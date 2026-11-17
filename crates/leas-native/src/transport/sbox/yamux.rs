//! `yamux` (`hashicorp/yamux` v0.1.2, as `sing-mux` configures it).
//!
//! Wire (`spec.md`, `const.go`): a 12-byte big-endian header
//! `[version=0][type][flags][stream id][length]`, types
//! `Data=0`, `WindowUpdate=1`, `Ping=2`, `GoAway=3`, flags
//! `SYN=1`, `ACK=2`, `FIN=4`, `RST=8`.
//!
//! The client starts at stream id 1 and advances by 2. A stream opens with a
//! zero-delta `WindowUpdate` carrying SYN; each side starts with a 256 KiB
//! receive window, and a reader sends a `WindowUpdate` once it has consumed
//! half of that window. Control frames travel on the same ordered queue as
//! data, so a FIN can never overtake its payload.

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

/// Protocol version.
pub const VERSION: u8 = 0;
/// Data.
pub const TYPE_DATA: u8 = 0;
/// Window update.
pub const TYPE_WINDOW_UPDATE: u8 = 1;
/// Ping.
pub const TYPE_PING: u8 = 2;
/// Go away.
pub const TYPE_GO_AWAY: u8 = 3;

/// Open a stream.
pub const FLAG_SYN: u16 = 1;
/// Acknowledge an open.
pub const FLAG_ACK: u16 = 2;
/// Half-close.
pub const FLAG_FIN: u16 = 4;
/// Reset.
pub const FLAG_RST: u16 = 8;

/// `initialStreamWindow`.
pub const INITIAL_WINDOW: u32 = 256 * 1024;
/// A window update is sent after this much consumed data.
pub const WINDOW_UPDATE_AT: u32 = INITIAL_WINDOW / 2;
/// Header size.
pub const HEADER: usize = 12;
/// One data frame never exceeds this (caller buffers are 16–64 KiB).
const WRITE_CHUNK: usize = 32 * 1024;
/// Session-wide in-flight payload cap.
const MAX_INFLIGHT: usize = 4 * 1024 * 1024;
/// Per-stream receive queue depth.
const STREAM_QUEUE: usize = 16;

/// Encode one frame header, appending the payload when present.
#[must_use]
pub fn encode_frame(kind: u8, flags: u16, sid: u32, length: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + payload.len());
    out.push(VERSION);
    out.push(kind);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a header into `(type, flags, stream id, length)`.
#[must_use]
pub const fn decode_header(header: &[u8; HEADER]) -> Option<(u8, u16, u32, u32)> {
    if header[0] != VERSION {
        return None;
    }
    let kind = header[1];
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let sid = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    Some((kind, flags, sid, length))
}

enum Event {
    Data(Bytes),
    End,
    Error(io::Error),
}

/// Per-stream send-window credit plus a waker for a blocked writer.
struct Window {
    credit: Mutex<(u32, Option<Waker>, bool)>,
}

impl Window {
    const fn new() -> Self {
        Self {
            credit: Mutex::new((INITIAL_WINDOW, None, false)),
        }
    }

    fn take(&self, want: usize, cx: &Context<'_>) -> Option<usize> {
        let mut credit = self
            .credit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let taken = match (credit.2, credit.0) {
            (true, _) => None,
            (false, 0) => {
                credit.1 = Some(cx.waker().clone());
                None
            }
            (false, _) => {
                let take = want.min(usize::try_from(credit.0).unwrap_or(usize::MAX));
                credit.0 -= u32::try_from(take).expect("take ≤ credit");
                Some(take)
            }
        };
        drop(credit);
        taken
    }

    fn add(&self, delta: u32) {
        let waker = {
            let mut credit = self
                .credit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            credit.0 = credit.0.saturating_add(delta);
            credit.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn close(&self) {
        let waker = {
            let mut credit = self
                .credit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            credit.2 = true;
            credit.1.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// In-flight payload accounting (shared by the session's streams).
struct Inflight {
    bytes: AtomicUsize,
    wakers: Mutex<Vec<Waker>>,
}

impl Inflight {
    const fn new() -> Self {
        Self {
            bytes: AtomicUsize::new(0),
            wakers: Mutex::new(Vec::new()),
        }
    }

    fn try_add(&self, n: usize, cx: &Context<'_>) -> bool {
        if self.bytes.load(Ordering::Acquire) + n > MAX_INFLIGHT {
            self.wakers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(cx.waker().clone());
            return false;
        }
        self.bytes.fetch_add(n, Ordering::AcqRel);
        true
    }

    fn release(&self, n: usize) {
        self.bytes.fetch_sub(n, Ordering::AcqRel);
        let wakers = std::mem::take(
            &mut *self
                .wakers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for waker in wakers {
            waker.wake();
        }
    }
}

#[derive(Clone)]
struct StreamEntry {
    data: mpsc::Sender<Event>,
    window: Arc<Window>,
}

/// A live yamux session.
pub struct YamuxSession {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    streams: Arc<Mutex<HashMap<u32, StreamEntry>>>,
    next_id: AtomicU32,
    inflight: Arc<Inflight>,
    dead: Arc<AtomicBool>,
    /// Fires when the session handle is dropped: the reader exits and releases
    /// its half (idle carriers must not keep the transport alive).
    #[allow(dead_code)] // held so dropping the session closes the reader
    close: tokio::sync::watch::Sender<bool>,
}

impl YamuxSession {
    /// Split the carrier into reader/writer tasks.
    #[must_use]
    pub fn new(carrier: BoxStream) -> Self {
        let (mut read_half, mut write_half) = tokio::io::split(carrier);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let streams = Arc::new(Mutex::new(HashMap::<u32, StreamEntry>::new()));
        let dead = Arc::new(AtomicBool::new(false));
        let inflight = Arc::new(Inflight::new());
        let (close, close_rx) = tokio::sync::watch::channel(false);

        let write_inflight = Arc::clone(&inflight);
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if let Err(error) = write_half.write_all(&frame).await {
                    tracing::debug!(%error, "sbox yamux writer stopped");
                    break;
                }
                if frame[1] == TYPE_DATA {
                    let len = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
                    write_inflight.release(usize::try_from(len).unwrap_or(0));
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
                            tracing::debug!(%error, "sbox yamux reader stopped");
                            break;
                        }
                    }
                }
                let Some((kind, flags, sid, length)) = decode_header(&header) else {
                    break;
                };
                match kind {
                    TYPE_PING => {
                        // Echo, per spec: same id/length with ACK.
                        let _ = reader_tx.send(encode_frame(TYPE_PING, FLAG_ACK, sid, length, &[]));
                    }
                    TYPE_WINDOW_UPDATE => {
                        let entry = {
                            let streams = read_streams
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            streams.get(&sid).cloned()
                        };
                        if let Some(entry) = entry {
                            if flags & FLAG_RST != 0 {
                                entry.window.close();
                                let _ = entry
                                    .data
                                    .send(Event::Error(io::Error::other("sbox yamux stream reset")))
                                    .await;
                                continue;
                            }
                            if flags & FLAG_FIN != 0 {
                                let _ = entry.data.send(Event::End).await;
                            } else if length > 0 {
                                entry.window.add(length);
                            }
                        }
                    }
                    TYPE_DATA => {
                        let mut payload = vec![0u8; usize::try_from(length).unwrap_or(0)];
                        if !payload.is_empty() {
                            tokio::select! {
                                _ = close_rx.changed() => break,
                                read = read_half.read_exact(&mut payload) => {
                                    if read.is_err() { break; }
                                }
                            }
                        }
                        let entry = {
                            let streams = read_streams
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            streams.get(&sid).cloned()
                        };
                        let Some(entry) = entry else {
                            // A SYN from the server (we are a client): reset it.
                            if flags & FLAG_SYN != 0 {
                                let _ = reader_tx.send(encode_frame(
                                    TYPE_WINDOW_UPDATE,
                                    FLAG_RST,
                                    sid,
                                    0,
                                    &[],
                                ));
                            }
                            continue;
                        };
                        if flags & FLAG_SYN != 0 {
                            // Server-initiated stream on a client session.
                            entry.window.close();
                            let _ = reader_tx.send(encode_frame(
                                TYPE_WINDOW_UPDATE,
                                FLAG_RST,
                                sid,
                                0,
                                &[],
                            ));
                            continue;
                        }
                        if flags & FLAG_RST != 0 {
                            entry.window.close();
                            let _ = entry
                                .data
                                .send(Event::Error(io::Error::other("sbox yamux stream reset")))
                                .await;
                            continue;
                        }
                        // A stream that closed mid-flight must not kill the
                        // carrier: drop the frame and keep routing others.
                        let _ = entry.data.send(Event::Data(Bytes::from(payload))).await;
                        if flags & FLAG_FIN != 0 {
                            let _ = entry.data.send(Event::End).await;
                        }
                    }
                    _ => break,
                }
            }
            read_dead.store(true, Ordering::Release);
            let streams = read_streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for entry in streams.values() {
                entry.window.close();
                let _ = entry
                    .data
                    .try_send(Event::Error(io::Error::other("sbox yamux session closed")));
            }
        });

        Self {
            tx,
            streams,
            next_id: AtomicU32::new(1),
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
    /// A dead session or an exhausted id space.
    pub fn open(&self) -> io::Result<YamuxStream> {
        if self.is_dead() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sbox yamux session is closed",
            ));
        }
        let id = self.next_id.fetch_add(2, Ordering::Relaxed);
        if id == 0 || id >= u32::MAX - 1 {
            return Err(io::Error::other("sbox yamux stream ids exhausted"));
        }
        let (data_tx, data_rx) = mpsc::channel(STREAM_QUEUE);
        let window = Arc::new(Window::new());
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                id,
                StreamEntry {
                    data: data_tx,
                    window: Arc::clone(&window),
                },
            );
        // A zero-delta window update carrying SYN opens the stream.
        if self
            .tx
            .send(encode_frame(TYPE_WINDOW_UPDATE, FLAG_SYN, id, 0, &[]))
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sbox yamux session is closed",
            ));
        }
        Ok(YamuxStream {
            id,
            rx: data_rx,
            tx: self.tx.clone(),
            streams: Arc::clone(&self.streams),
            window,
            inflight: Arc::clone(&self.inflight),
            read_eof: false,
            fin_sent: false,
            consumed: 0,
            pending: None,
        })
    }
}

/// One yamux stream.
pub struct YamuxStream {
    id: u32,
    rx: mpsc::Receiver<Event>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    streams: Arc<Mutex<HashMap<u32, StreamEntry>>>,
    window: Arc<Window>,
    inflight: Arc<Inflight>,
    read_eof: bool,
    fin_sent: bool,
    /// Bytes handed to the caller since the last window update.
    consumed: u32,
    /// The unread tail of a payload split by a short caller buffer.
    pending: Option<Bytes>,
}

impl Drop for YamuxStream {
    fn drop(&mut self) {
        if !self.fin_sent {
            let _ = self
                .tx
                .send(encode_frame(TYPE_WINDOW_UPDATE, FLAG_FIN, self.id, 0, &[]));
        }
        self.window.close();
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl YamuxStream {
    /// Advertise consumed bytes so the peer's send window grows.
    fn credit_consumed(&mut self, bytes: u32) {
        self.consumed = self.consumed.saturating_add(bytes);
        if self.consumed >= WINDOW_UPDATE_AT {
            let delta = self.consumed;
            self.consumed = 0;
            let _ = self
                .tx
                .send(encode_frame(TYPE_WINDOW_UPDATE, 0, self.id, delta, &[]));
        }
    }
}

impl AsyncRead for YamuxStream {
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
            let take = u32::try_from(take).unwrap_or(u32::MAX);
            self.credit_consumed(take);
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
                let take = u32::try_from(take).unwrap_or(u32::MAX);
                self.credit_consumed(take);
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

impl AsyncWrite for YamuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let want = buf.len().min(WRITE_CHUNK);
        let Some(take) = self.window.take(want, cx) else {
            // Window exhausted (or the stream reset): the waker is registered.
            return Poll::Pending;
        };
        if !self.inflight.try_add(take, cx) {
            self.window.add(u32::try_from(take).expect("take ≤ credit"));
            return Poll::Pending;
        }
        if self
            .tx
            .send(encode_frame(
                TYPE_DATA,
                0,
                self.id,
                u32::try_from(take).expect("take ≤ 32 KiB"),
                &buf[..take],
            ))
            .is_err()
        {
            self.inflight.release(take);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sbox yamux session is closed",
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
            let _ = self
                .tx
                .send(encode_frame(TYPE_WINDOW_UPDATE, FLAG_FIN, self.id, 0, &[]));
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    #[test]
    fn header_is_big_endian_and_ordered() {
        let frame = encode_frame(TYPE_DATA, FLAG_SYN | FLAG_FIN, 3, 2, b"hi");
        assert_eq!(frame, vec![0, 0, 0, 5, 0, 0, 0, 3, 0, 0, 0, 2, b'h', b'i']);
        let header: [u8; HEADER] = frame[..HEADER].try_into().expect("header");
        assert_eq!(
            decode_header(&header),
            Some((TYPE_DATA, FLAG_SYN | FLAG_FIN, 3, 2))
        );
    }

    /// A minimal yamux server: ACK opens, echo data, answer FIN, count window
    /// updates.
    async fn serve(mut io: DuplexStream, updates: Arc<AtomicU32>) {
        loop {
            let mut header = [0u8; HEADER];
            if io.read_exact(&mut header).await.is_err() {
                return;
            }
            let Some((kind, flags, sid, length)) = decode_header(&header) else {
                return;
            };
            let mut payload = vec![0u8; usize::try_from(length).unwrap_or(0)];
            if kind == TYPE_DATA
                && !payload.is_empty()
                && io.read_exact(&mut payload).await.is_err()
            {
                return;
            }
            match kind {
                TYPE_WINDOW_UPDATE => {
                    if flags & FLAG_SYN != 0 {
                        let _ = io
                            .write_all(&encode_frame(TYPE_WINDOW_UPDATE, FLAG_ACK, sid, 0, &[]))
                            .await;
                    } else if flags & FLAG_FIN != 0 {
                        let _ = io
                            .write_all(&encode_frame(TYPE_WINDOW_UPDATE, FLAG_FIN, sid, 0, &[]))
                            .await;
                        return;
                    } else if length > 0 {
                        updates.fetch_add(length, Ordering::AcqRel);
                    }
                }
                TYPE_DATA => {
                    if io
                        .write_all(&encode_frame(TYPE_DATA, 0, sid, length, &payload))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                TYPE_PING => {
                    if io
                        .write_all(&encode_frame(TYPE_PING, FLAG_ACK, 0, length, &[]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                _ => return,
            }
        }
    }

    #[tokio::test]
    async fn stream_round_trip_through_an_echo_peer() {
        let (client, server) = duplex(1 << 20);
        let updates = Arc::new(AtomicU32::new(0));
        let server = tokio::spawn(serve(server, Arc::clone(&updates)));
        let session = YamuxSession::new(Box::new(client) as crate::BoxStream);
        let mut stream = session.open().expect("open");
        stream.write_all(b"hello").await.expect("write");
        stream.shutdown().await.expect("half-close");
        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.expect("read");
        assert_eq!(got, b"hello");
        let _ = server.await;
    }

    #[tokio::test]
    async fn first_stream_ids_are_odd() {
        let (client, _server) = duplex(512);
        let session = YamuxSession::new(Box::new(client) as crate::BoxStream);
        assert_eq!(session.open().expect("first").id, 1);
        assert_eq!(session.open().expect("second").id, 3);
    }

    #[tokio::test]
    async fn a_reader_sends_a_window_update_after_consuming_half() {
        // The peer sends 200 KiB; the client reads it and must advertise the
        // consumed credit back.
        let (client, mut server) = duplex(1 << 21);
        let session = YamuxSession::new(Box::new(client) as crate::BoxStream);
        let mut stream = session.open().expect("open");
        // Accept the SYN locally (the test peer is the writer below).
        tokio::spawn(async move {
            let mut header = [0u8; HEADER];
            server.read_exact(&mut header).await.expect("syn");
            let payload = vec![7u8; 200 * 1024];
            server
                .write_all(&encode_frame(TYPE_DATA, 0, 1, 200 * 1024, &payload))
                .await
                .expect("data");
            // Read the client's window update.
            let mut update = [0u8; HEADER];
            server.read_exact(&mut update).await.expect("update");
            let (kind, _flags, _sid, delta) = decode_header(&update).expect("update header");
            assert_eq!(kind, TYPE_WINDOW_UPDATE);
            assert!(delta >= WINDOW_UPDATE_AT, "delta {delta}");
        });
        let mut got = vec![0u8; 200 * 1024];
        stream.read_exact(&mut got).await.expect("read all");
        assert!(got.iter().all(|byte| *byte == 7));
    }
}
