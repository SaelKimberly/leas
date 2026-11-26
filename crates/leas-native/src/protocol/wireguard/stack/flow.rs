//! Flow types: a TCP stream and a UDP socket over the stack.
//!
//! Both are `tokio::io` types so the relay and the SOCKS inbound take them
//! unchanged. Backpressure is per flow: the driver hands out credit (bytes it
//! has written into the socket) and the writer parks when its outstanding
//! bytes reach [`WRITE_HIGH_WATER`]; the bounded command channel is the second
//! bound, and a full channel parks on the stack's shared `space` signal.
//!
//! Every command carries the flow's open `token`: smoltcp handles are bare
//! indices with slot reuse, so a command from a dropped flow must not touch a
//! socket that a new flow now owns.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use smoltcp::iface::SocketHandle;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

use super::StackError;
use super::net::{Command, StackHandle, WRITE_HIGH_WATER, WgStack};

/// Park on `notify`, retrying when it fires. `Ok(())` = retry now.
fn park(
    waiting: &mut Option<Pin<Box<tokio::sync::futures::OwnedNotified>>>,
    notify: &Arc<Notify>,
    cx: &mut Context<'_>,
) -> Poll<()> {
    if let Some(mut armed) = waiting.take() {
        if armed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(());
        }
        *waiting = Some(armed);
        return Poll::Pending;
    }
    let mut future = Box::pin(Arc::clone(notify).notified_owned());
    if future.as_mut().poll(cx).is_ready() {
        return Poll::Ready(());
    }
    *waiting = Some(future);
    Poll::Pending
}

/// A TCP connection through the tunnel.
pub struct TcpFlow {
    handle: StackHandle,
    socket: SocketHandle,
    /// The open's identity; a command for a reused handle is ignored.
    token: u64,
    /// Set when the socket is retired or the driver exits.
    dead: Arc<std::sync::atomic::AtomicBool>,
    rx: mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
    /// Bytes handed to the driver that it has not yet written into the socket.
    outstanding: Arc<AtomicUsize>,
    /// Per-flow credit signal (the driver decrements `outstanding` here).
    wake: Arc<Notify>,
    /// Shared command-channel space signal.
    space: Arc<Notify>,
    waiting: Option<Pin<Box<tokio::sync::futures::OwnedNotified>>>,
    closed: bool,
    /// Signalled after the flow consumed a chunk: the driver re-polls to move
    /// more socket bytes into the now-free channel.
    read_wake: Arc<Notify>,
    /// Keeps the stack (and its device) alive while the flow lives; the pool
    /// reads this strong count to decide an idle teardown.
    _guard: Option<Arc<WgStack>>,
}

impl std::fmt::Debug for TcpFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpFlow")
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl TcpFlow {
    pub(crate) fn new(
        handle: StackHandle,
        socket: SocketHandle,
        token: u64,
        dead: Arc<std::sync::atomic::AtomicBool>,
        wake: Arc<Notify>,
        rx: mpsc::Receiver<Vec<u8>>,
        read_wake: Arc<Notify>,
        guard: Option<Arc<WgStack>>,
    ) -> Self {
        Self {
            space: Arc::clone(&handle.space),
            handle,
            socket,
            token,
            dead,
            rx,
            current: Vec::new(),
            offset: 0,
            outstanding: Arc::new(AtomicUsize::new(0)),
            wake,
            waiting: None,
            closed: false,
            read_wake,
            _guard: guard,
        }
    }
}

impl AsyncRead for TcpFlow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.offset < self.current.len() {
                let n = (self.current.len() - self.offset).min(buf.remaining());
                buf.put_slice(&self.current[self.offset..self.offset + n]);
                self.offset += n;
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    self.current = chunk;
                    self.offset = 0;
                    // A slot just freed: let the driver refill it.
                    self.read_wake.notify_one();
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for TcpFlow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.closed || self.dead.load(Ordering::Relaxed) {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        loop {
            // Per-flow credit: the driver decrements this as it writes bytes
            // into the socket and notifies `wake`, so a stalled peer parks its
            // own writer without stopping the device.
            //
            // A single write larger than the cap is admitted when nothing is
            // outstanding: `write_all` hands over the whole slice and cannot
            // be split, so refusing it would park forever.
            let outstanding = self.outstanding.load(Ordering::Relaxed);
            if outstanding > 0 && outstanding + data.len() > WRITE_HIGH_WATER {
                let wake = Arc::clone(&self.wake);
                return match park(&mut self.waiting, &wake, cx) {
                    Poll::Ready(()) => continue,
                    Poll::Pending => Poll::Pending,
                };
            }
            // Reserve the credit BEFORE enqueueing: the driver may decrement
            // it the moment the command lands, and a later `fetch_add` would
            // resurrect it (and eventually wrap the counter).
            self.outstanding.fetch_add(data.len(), Ordering::Relaxed);
            let command = Command::TcpWrite {
                handle: self.socket,
                token: self.token,
                data: data.to_vec(),
                credit: Arc::clone(&self.outstanding),
                wake: Arc::clone(&self.wake),
            };
            match self.handle.cmd.try_send(command) {
                Ok(()) => return Poll::Ready(Ok(data.len())),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.outstanding.fetch_sub(data.len(), Ordering::Relaxed);
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.outstanding.fetch_sub(data.len(), Ordering::Relaxed);
                    let space = Arc::clone(&self.space);
                    return match park(&mut self.waiting, &space, cx) {
                        Poll::Ready(()) => continue,
                        Poll::Pending => Poll::Pending,
                    };
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // The driver writes as soon as the socket can take bytes; there is no
        // user-space buffer to force out here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // The FIN must be QUEUED, not offered once: a full command channel
        // parks on the shared `space` signal (the driver fires it after every
        // popped command) instead of dropping the shutdown.
        loop {
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            if self.dead.load(Ordering::Relaxed) {
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            match self.handle.cmd.try_send(Command::TcpShutdown {
                handle: self.socket,
                token: self.token,
            }) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    let space = Arc::clone(&self.space);
                    return match park(&mut self.waiting, &space, cx) {
                        Poll::Ready(()) => continue,
                        Poll::Pending => Poll::Pending,
                    };
                }
            }
        }
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        let _ = self.handle.cmd.try_send(Command::TcpClose {
            handle: self.socket,
            token: self.token,
        });
    }
}

/// A UDP socket through the tunnel, destination-locked by the caller.
pub struct UdpFlow {
    handle: StackHandle,
    socket: SocketHandle,
    token: u64,
    rx: mpsc::Receiver<(std::net::SocketAddr, Vec<u8>)>,
    closed: bool,
    read_wake: Arc<Notify>,
    guard: Option<Arc<WgStack>>,
}

impl std::fmt::Debug for UdpFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpFlow")
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl UdpFlow {
    #[allow(clippy::missing_const_for_fn)] // `mpsc::Receiver`/`Arc` are not const here
    pub(crate) fn new(
        handle: StackHandle,
        socket: SocketHandle,
        token: u64,
        rx: mpsc::Receiver<(std::net::SocketAddr, Vec<u8>)>,
        read_wake: Arc<Notify>,
        guard: Option<Arc<WgStack>>,
    ) -> Self {
        Self {
            handle,
            socket,
            token,
            rx,
            closed: false,
            read_wake,
            guard,
        }
    }

    /// Queue one datagram.
    ///
    /// # Errors
    ///
    /// Fails when the stack closed or its command queue is momentarily full.
    pub fn try_send_to(&self, to: std::net::SocketAddr, data: &[u8]) -> Result<(), StackError> {
        self.handle
            .cmd
            .try_send(Command::UdpSend {
                handle: self.socket,
                token: self.token,
                to,
                data: data.to_vec(),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Closed(_) => StackError::Closed,
                mpsc::error::TrySendError::Full(_) => {
                    StackError::RefusedRequest("command queue is full".into())
                }
            })
    }

    /// The next datagram the tunnel delivered.
    pub async fn recv_from(&mut self) -> Option<(std::net::SocketAddr, Vec<u8>)> {
        let datagram = self.rx.recv().await;
        if datagram.is_some() {
            self.read_wake.notify_one();
        }
        datagram
    }
}

impl UdpFlow {
    /// Split into a receive half and a send half.
    ///
    /// The UDP association relay needs both in separate tasks: `recv_from`
    /// holds `&mut self`, and cancelling it mid-datagram would lose the
    /// datagram. The send half owns the close: dropping it releases the
    /// socket.
    #[must_use]
    pub fn split(mut self) -> (UdpReader, UdpWriter) {
        self.closed = true; // the writer owns the close now
        let reader = UdpReader {
            rx: std::mem::replace(&mut self.rx, mpsc::channel(1).1),
            read_wake: Arc::clone(&self.read_wake),
            _guard: self.guard.take(),
        };
        let writer = UdpWriter {
            handle: self.handle.clone(),
            socket: self.socket,
            token: self.token,
        };
        (reader, writer)
    }
}

/// The receive half of a split [`UdpFlow`].
pub struct UdpReader {
    rx: mpsc::Receiver<(std::net::SocketAddr, Vec<u8>)>,
    read_wake: Arc<Notify>,
    _guard: Option<Arc<WgStack>>,
}

impl UdpReader {
    /// The next datagram the tunnel delivered.
    pub async fn recv(&mut self) -> Option<(std::net::SocketAddr, Vec<u8>)> {
        let datagram = self.rx.recv().await;
        if datagram.is_some() {
            // A slot just freed: the driver re-polls the socket's ring.
            self.read_wake.notify_one();
        }
        datagram
    }
}

/// The send half of a split [`UdpFlow`]; dropping it closes the socket.
pub struct UdpWriter {
    handle: StackHandle,
    socket: SocketHandle,
    token: u64,
}

impl UdpWriter {
    /// Queue one datagram.
    ///
    /// # Errors
    ///
    /// Fails when the stack closed or its command queue is momentarily full.
    pub fn send_to(&self, to: std::net::SocketAddr, data: &[u8]) -> Result<(), StackError> {
        self.handle
            .cmd
            .try_send(Command::UdpSend {
                handle: self.socket,
                token: self.token,
                to,
                data: data.to_vec(),
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Closed(_) => StackError::Closed,
                mpsc::error::TrySendError::Full(_) => {
                    StackError::RefusedRequest("command queue is full".into())
                }
            })
    }
}

impl Drop for UdpWriter {
    fn drop(&mut self) {
        let _ = self.handle.cmd.try_send(Command::UdpClose {
            handle: self.socket,
            token: self.token,
        });
    }
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.handle.cmd.try_send(Command::UdpClose {
                handle: self.socket,
                token: self.token,
            });
        }
    }
}

/// One SOCKS5 UDP association through a `WireGuard` device.
///
/// Every datagram is a full inner IP/UDP packet, so the destination is
/// mandatory (the relay never sends `None`) and a reply carries the source it
/// came from.
pub struct WgUdpConn {
    flow: UdpFlow,
    /// The profile's tunnel resolver, when it has one: a domain destination
    /// must be resolved through the tunnel, not by the host.
    dns: Option<Arc<leas_dns::DnsResolver>>,
}

impl std::fmt::Debug for WgUdpConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgUdpConn").finish_non_exhaustive()
    }
}

impl WgUdpConn {
    pub(crate) const fn new(flow: UdpFlow, dns: Option<Arc<leas_dns::DnsResolver>>) -> Self {
        Self { flow, dns }
    }

    /// Queue one datagram to `dest` (mandatory).
    ///
    /// # Errors
    ///
    /// `InvalidInput` without a destination; otherwise the stack's error.
    pub fn send(&self, dest: Option<std::net::SocketAddr>, payload: &[u8]) -> std::io::Result<()> {
        let dest = dest.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a wireguard datagram needs a destination",
            )
        })?;
        self.flow
            .try_send_to(dest, payload)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }

    /// The next reply, with the inner packet's source address.
    pub async fn recv(
        &mut self,
    ) -> std::io::Result<Option<(Option<std::net::SocketAddr>, bytes::Bytes)>> {
        Ok(self
            .flow
            .recv_from()
            .await
            .map(|(source, payload)| (Some(source), bytes::Bytes::from(payload))))
    }

    /// Halves for the relay: the reader owns `recv`, the writer owns the close.
    #[must_use]
    pub fn split(self) -> (WgUdpReader, WgUdpWriter) {
        let (reader, writer) = self.flow.split();
        (
            WgUdpReader { reader },
            WgUdpWriter {
                writer,
                dns: self.dns,
            },
        )
    }
}

/// The receive half of a [`WgUdpConn`].
pub struct WgUdpReader {
    reader: UdpReader,
}

impl WgUdpReader {
    /// The next reply, with its source address.
    pub async fn recv(
        &mut self,
    ) -> std::io::Result<Option<(Option<std::net::SocketAddr>, bytes::Bytes)>> {
        Ok(self
            .reader
            .recv()
            .await
            .map(|(source, payload)| (Some(source), bytes::Bytes::from(payload))))
    }
}

/// The send half of a [`WgUdpConn`]; dropping it closes the socket.
pub struct WgUdpWriter {
    writer: UdpWriter,
    dns: Option<Arc<leas_dns::DnsResolver>>,
}

impl WgUdpWriter {
    /// The profile's tunnel resolver, when the association has one.
    #[must_use]
    pub fn resolver(&self) -> Option<Arc<leas_dns::DnsResolver>> {
        self.dns.clone()
    }

    /// Queue one datagram (a destination is mandatory).
    ///
    /// # Errors
    ///
    /// `InvalidInput` without a destination; otherwise the stack's error.
    pub fn send(&self, dest: Option<std::net::SocketAddr>, payload: &[u8]) -> std::io::Result<()> {
        let dest = dest.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a wireguard datagram needs a destination",
            )
        })?;
        self.writer
            .send_to(dest, payload)
            .map_err(|error| std::io::Error::other(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dead() -> Arc<std::sync::atomic::AtomicBool> {
        Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    #[tokio::test]
    async fn reading_a_chunk_signals_the_driver() {
        let (cmd, _cmd_rx) = mpsc::channel(64);
        let space = Arc::new(Notify::new());
        let handle = StackHandle {
            cmd,
            space: Arc::clone(&space),
        };
        let (data_tx, data_rx) = mpsc::channel(2);
        let read_wake = Arc::new(Notify::new());
        data_tx.send(b"payload".to_vec()).await.expect("send");
        let mut flow = TcpFlow::new(
            handle,
            SocketHandle::default(),
            1,
            dead(),
            Arc::new(Notify::new()),
            data_rx,
            Arc::clone(&read_wake),
            None,
        );
        let mut buf = [0u8; 7];
        let mut read = ReadBuf::new(&mut buf);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(Pin::new(&mut flow).poll_read(&mut cx, &mut read).is_ready());
        assert_eq!(read.filled(), b"payload");

        let mut notified = Box::pin(read_wake.notified_owned());
        assert!(
            notified.as_mut().poll(&mut cx).is_ready(),
            "the driver must be woken for the freed slot"
        );
    }

    /// A full command channel parks the shutdown on the shared `space` signal,
    /// which the driver fires after every popped command.
    #[tokio::test]
    async fn shutdown_waits_for_command_space_instead_of_dropping_the_fin() {
        let (cmd, mut rx) = mpsc::channel(1);
        let space = Arc::new(Notify::new());
        let handle = StackHandle {
            cmd,
            space: Arc::clone(&space),
        };
        let (_data_tx, data_rx) = mpsc::channel(1);
        let mut flow = TcpFlow::new(
            handle,
            SocketHandle::default(),
            1,
            dead(),
            Arc::new(Notify::new()),
            data_rx,
            Arc::new(Notify::new()),
            None,
        );
        // Fill the one-slot command channel.
        assert!(
            flow.handle
                .cmd
                .try_send(Command::TcpClose {
                    handle: SocketHandle::default(),
                    token: 0,
                })
                .is_ok()
        );
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(
            Pin::new(&mut flow).poll_shutdown(&mut cx).is_pending(),
            "a full channel parks the shutdown instead of dropping it"
        );

        assert!(rx.try_recv().is_ok());
        space.notify_waiters();
        assert!(
            Pin::new(&mut flow).poll_shutdown(&mut cx).is_ready(),
            "with room the FIN is queued"
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(Command::TcpShutdown { token: 1, .. })
        ));
    }

    /// The writer parks on its own credit once the driver stops acknowledging.
    #[tokio::test]
    async fn a_write_parks_when_the_credit_is_exhausted() {
        let (cmd, mut rx) = mpsc::channel(64);
        let mut flow = TcpFlow::new(
            StackHandle {
                cmd,
                space: Arc::new(Notify::new()),
            },
            SocketHandle::default(),
            1,
            dead(),
            Arc::new(Notify::new()),
            mpsc::channel(1).1,
            Arc::new(Notify::new()),
            None,
        );
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let chunk = vec![0u8; WRITE_HIGH_WATER];
        assert!(Pin::new(&mut flow).poll_write(&mut cx, &chunk).is_ready());

        // No further credit: the next write parks.
        assert!(
            Pin::new(&mut flow).poll_write(&mut cx, b"x").is_pending(),
            "a flow with no outstanding credit must park"
        );

        // The driver writes the chunk and returns its credit: the flow's
        // outstanding count drops, and the wake unparks the writer.
        let Ok(Command::TcpWrite { credit, wake, .. }) = rx.try_recv() else {
            panic!("the write commands must be queued");
        };
        credit.fetch_sub(WRITE_HIGH_WATER, Ordering::Relaxed);
        wake.notify_one();
        assert!(Pin::new(&mut flow).poll_write(&mut cx, b"x").is_ready());
    }
}
