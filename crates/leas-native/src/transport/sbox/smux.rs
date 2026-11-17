//! `smux` (protocol version 1) — the `SagerNet` fork pinned in `thirdparty/smux`
//! at `v1.5.50-sing-box-mod.1`, which is what `sing-mux` configures
//! (`DefaultConfig`: version 1, 32 KiB frames, no keepalive).
//!
//! Wire (`frame.go`): every frame is
//! `[1B version][1B command][2B length LE][4B stream id LE][payload]`.
//! Commands: `SYN=0`, `FIN=1`, `PSH=2`, `NOP=3` (`UPD=4` is v2-only).
//!
//! Version 1 has no per-stream window-update frames; this client bounds its
//! own in-flight payload at the reference's session bucket (4 MiB) and relies
//! on the transport's backpressure beyond that.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use crate::BoxStream;

/// Version 1 (sing-mux's `smux.DefaultConfig().Version`).
pub const VERSION: u8 = 1;
/// Stream open.
pub const CMD_SYN: u8 = 0;
/// Stream half-close.
pub const CMD_FIN: u8 = 1;
/// Data frame.
pub const CMD_PSH: u8 = 2;
/// Keepalive (disabled here, like the reference).
pub const CMD_NOP: u8 = 3;
/// Version-2 window update (ignored by a v1 peer).
pub const CMD_UPD: u8 = 4;

/// `smux.DefaultConfig().MaxFrameSize`.
pub const MAX_FRAME: usize = 32 * 1024;
/// `smux.DefaultConfig().MaxReceiveBuffer`: this client's in-flight cap.
pub const MAX_INFLIGHT: usize = 4 * 1024 * 1024;
/// Per-stream receive queue depth (frames).
const STREAM_QUEUE: usize = 16;

/// One frame header's encoded size.
pub const HEADER: usize = 8;

/// Encode a frame header + payload.
#[must_use]
pub fn encode_frame(cmd: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.push(VERSION);
    out.push(cmd);
    out.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("frame ≤ 65535")
            .to_le_bytes(),
    );
    out.extend_from_slice(&sid.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode one header: `(cmd, sid, length)`.
#[must_use]
pub const fn decode_header(header: &[u8; HEADER]) -> Option<(u8, u32, u16)> {
    if header[0] != VERSION {
        return None;
    }
    let cmd = header[1];
    let len = u16::from_le_bytes([header[2], header[3]]);
    let sid = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    Some((cmd, sid, len))
}

/// An event delivered to a stream.
enum Event {
    Data(Bytes),
    End,
    Error(io::Error),
}

/// In-flight payload accounting shared by every stream of one session.
struct Inflight {
    bytes: AtomicUsize,
    waker: Mutex<Option<Waker>>,
}

impl Inflight {
    const fn new() -> Self {
        Self {
            bytes: AtomicUsize::new(0),
            waker: Mutex::new(None),
        }
    }

    /// Try to reserve `n` bytes; `false` when over the cap (waker kept).
    fn try_add(&self, n: usize, cx: &Context<'_>) -> bool {
        let current = self.bytes.load(Ordering::Acquire);
        if current + n > MAX_INFLIGHT {
            *self
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cx.waker().clone());
            return false;
        }
        self.bytes.fetch_add(n, Ordering::AcqRel);
        true
    }

    fn release(&self, n: usize) {
        self.bytes.fetch_sub(n, Ordering::AcqRel);
        let waker = self
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// A live smux session.
pub struct SmuxSession {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Event>>>>,
    next_id: AtomicU32,
    inflight: Arc<Inflight>,
    dead: Arc<AtomicBool>,
    /// Fires when the session handle is dropped: the reader must exit and
    /// release its half (otherwise an idle carrier would keep the transport
    /// alive forever once the pool evicts it).
    #[allow(dead_code)] // held so dropping the session closes the reader
    close: tokio::sync::watch::Sender<bool>,
}

impl SmuxSession {
    /// Split the carrier into reader/writer tasks.
    ///
    /// # Errors
    ///
    /// Never fails today (the session is lazy); chip errors surface on the
    /// first write/read.
    #[must_use]
    pub fn new(carrier: BoxStream) -> Self {
        let (mut read_half, mut write_half) = tokio::io::split(carrier);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let streams = Arc::new(Mutex::new(HashMap::<u32, mpsc::Sender<Event>>::new()));
        let dead = Arc::new(AtomicBool::new(false));
        let inflight = Arc::new(Inflight::new());
        let (close, close_rx) = tokio::sync::watch::channel(false);

        let write_inflight = Arc::clone(&inflight);
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if let Err(error) = write_half.write_all(&frame).await {
                    tracing::debug!(%error, "sbox smux writer stopped");
                    break;
                }
                if frame[1] == CMD_PSH {
                    let payload = usize::from(u16::from_le_bytes([frame[2], frame[3]]));
                    write_inflight.release(payload);
                }
            }
            let _ = write_half.shutdown().await;
        });

        let reader_tx = tx.clone();
        let read_streams = Arc::clone(&streams);
        let read_dead = Arc::clone(&dead);
        tokio::spawn(async move {
            let mut header = [0u8; HEADER];
            let mut close_rx = close_rx;
            loop {
                tokio::select! {
                    _ = close_rx.changed() => break,
                    read = read_half.read_exact(&mut header) => {
                        if let Err(error) = read {
                            tracing::debug!(%error, "sbox smux reader stopped");
                            break;
                        }
                    }
                }
                let Some((cmd, sid, len)) = decode_header(&header) else {
                    break;
                };
                let payload = if len == 0 {
                    Bytes::new()
                } else {
                    let mut buf = vec![0u8; usize::from(len)];
                    tokio::select! {
                        _ = close_rx.changed() => break,
                        read = read_half.read_exact(&mut buf) => {
                            if read.is_err() { break; }
                        }
                    }
                    Bytes::from(buf)
                };
                let delivered = {
                    let streams = read_streams
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    streams.get(&sid).cloned()
                };
                let Some(stream) = delivered else {
                    if cmd == CMD_SYN {
                        // We are a client: reject a server-initiated stream.
                        let _ = reader_tx.send(encode_frame(CMD_FIN, sid, &[]));
                    }
                    continue;
                };
                match cmd {
                    CMD_PSH => {
                        // The stream may have closed while this frame was in
                        // flight; dropping one frame is not a carrier failure.
                        let _ = stream.send(Event::Data(payload)).await;
                    }
                    CMD_FIN => {
                        let _ = stream.send(Event::End).await;
                    }
                    CMD_SYN | CMD_NOP | CMD_UPD => {}
                    _ => break,
                }
            }
            read_dead.store(true, Ordering::Release);
            let streams = read_streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for stream in streams.values() {
                let _ = stream.try_send(Event::Error(io::Error::other("sbox smux session closed")));
            }
        });

        Self {
            tx,
            streams,
            // The reference's client starts at 1 and pre-increments by 2, so
            // the first stream id is 3.
            next_id: AtomicU32::new(3),
            inflight,
            dead,
            close,
        }
    }

    /// Whether the reader task has exited.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire)
    }

    /// Open one stream.
    ///
    /// # Errors
    ///
    /// A dead session or an exhausted stream-id space.
    pub fn open(&self) -> io::Result<SmuxStream> {
        if self.is_dead() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sbox smux session is closed",
            ));
        }
        let id = self.next_id.fetch_add(2, Ordering::Relaxed);
        if id == 0 || id == u32::MAX {
            return Err(io::Error::other("sbox smux stream ids exhausted"));
        }
        let (data_tx, data_rx) = mpsc::channel(STREAM_QUEUE);
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, data_tx);
        if self.tx.send(encode_frame(CMD_SYN, id, &[])).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sbox smux session is closed",
            ));
        }
        Ok(SmuxStream {
            id,
            rx: data_rx,
            tx: self.tx.clone(),
            streams: Arc::clone(&self.streams),
            inflight: Arc::clone(&self.inflight),
            read_eof: false,
            fin_sent: false,
            pending: None,
        })
    }
}

/// One smux stream.
pub struct SmuxStream {
    id: u32,
    rx: mpsc::Receiver<Event>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Event>>>>,
    inflight: Arc<Inflight>,
    /// The peer half-closed (or the session died): reads return EOF.
    read_eof: bool,
    /// This side sent FIN (shutdown or drop).
    fin_sent: bool,
    /// The unread tail of a payload split by a short caller buffer.
    pending: Option<Bytes>,
}

impl Drop for SmuxStream {
    fn drop(&mut self) {
        if !self.fin_sent {
            let _ = self.tx.send(encode_frame(CMD_FIN, self.id, &[]));
        }
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(pending) = self.pending.as_mut() {
            let take = pending.len().min(buf.remaining());
            buf.put_slice(&pending[..take]);
            let rest = pending.slice(take..);
            self.pending = if rest.is_empty() { None } else { Some(rest) };
            return Poll::Ready(Ok(()));
        }
        if self.read_eof {
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Event::Data(bytes))) => {
                let take = bytes.len().min(buf.remaining());
                buf.put_slice(&bytes[..take]);
                if take < bytes.len() {
                    self.pending = Some(bytes.slice(take..));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Event::End) | None) => {
                self.read_eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Event::Error(error))) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = buf.len().min(MAX_FRAME);
        if !self.inflight.try_add(take, cx) {
            return Poll::Pending;
        }
        if self
            .tx
            .send(encode_frame(CMD_PSH, self.id, &buf[..take]))
            .is_err()
        {
            self.inflight.release(take);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sbox smux session is closed",
            )));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.fin_sent {
            self.fin_sent = true;
            let _ = self.tx.send(encode_frame(CMD_FIN, self.id, &[]));
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    #[test]
    fn frame_bytes_are_little_endian_and_ordered() {
        let frame = encode_frame(CMD_PSH, 3, b"hi");
        assert_eq!(
            frame,
            vec![1, 2, 2, 0, 3, 0, 0, 0, b'h', b'i'],
            "version, cmd, length LE, stream id LE, payload"
        );
        let header: [u8; HEADER] = frame[..HEADER].try_into().expect("header");
        assert_eq!(decode_header(&header), Some((CMD_PSH, 3, 2)));
    }

    /// A minimal smux server: echo every `PSH`, answer `FIN`.
    async fn serve(mut io: DuplexStream) {
        loop {
            let mut header = [0u8; HEADER];
            if io.read_exact(&mut header).await.is_err() {
                return;
            }
            let Some((cmd, sid, len)) = decode_header(&header) else {
                return;
            };
            let mut payload = vec![0u8; usize::from(len)];
            if !payload.is_empty() && io.read_exact(&mut payload).await.is_err() {
                return;
            }
            match cmd {
                CMD_PSH => {
                    if io
                        .write_all(&encode_frame(CMD_PSH, sid, &payload))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                CMD_FIN => {
                    let _ = io.write_all(&encode_frame(CMD_FIN, sid, &[])).await;
                    return;
                }
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn stream_round_trip_through_an_echo_peer() {
        let (client, server) = duplex(1 << 20);
        let server = tokio::spawn(serve(server));
        let session = SmuxSession::new(Box::new(client) as crate::BoxStream);
        let mut stream = session.open().expect("open");
        stream.write_all(b"hello").await.expect("write");
        stream.shutdown().await.expect("half-close");
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.expect("read");
        assert_eq!(got, b"hello");
        let _ = server.await;
    }

    #[tokio::test]
    async fn first_stream_id_is_three_and_ids_advance_by_two() {
        let (client, _server) = duplex(512);
        let session = SmuxSession::new(Box::new(client) as crate::BoxStream);
        let first = session.open().expect("first");
        let second = session.open().expect("second");
        assert_eq!(first.id, 3);
        assert_eq!(second.id, 5);
    }

    #[tokio::test]
    async fn a_bad_version_kills_the_session() {
        let (client, mut server) = duplex(512);
        server
            .write_all(&[2, CMD_NOP, 0, 0, 0, 0, 0, 0])
            .await
            .expect("bad version frame");
        let session = SmuxSession::new(Box::new(client) as crate::BoxStream);
        // The reader exits on the bad version; `open` then fails.
        for _ in 0..50 {
            if session.is_dead() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(session.is_dead(), "a wrong version must kill the session");
        assert!(session.open().is_err());
    }
}
