//! One `AnyTLS` session: an authenticated TLS connection carrying many streams.
//!
//! Layering (spec `thirdparty/anytls-go/docs/protocol.md`):
//!
//! ```text
//! TCP proxy -> Stream -> Session -> TLS -> TCP
//! ```
//!
//! The session owns two tasks over the split TLS stream: a reader that routes
//! `cmdPSH` payloads into per-stream channels, and a writer that applies the
//! padding scheme to each write. Every stream is a `cmdSYN` + `cmdPSH`
//! (SOCKS5 address) opener and a `cmdFIN` terminator.
//!
//! Deliberately absent: the reference's 3-second "no `cmdSYNACK` yet" session
//! watchdog. A slow v2 server would lose a healthy session to it, and the
//! frames are already ordered by the TLS stream — `cmdSYNACK` with a payload
//! is still handled as the stream error it is.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use super::frame::{
    self, CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, HEADER_LEN, Header,
};
use super::padding::{PaddingScheme, Step};
use crate::BoxStream;
use crate::addr::{TargetAddr, encode_addr_port_last};
use crate::error::NativeError;
use crate::protocol::AuthAck;
use crate::protocol::AuthAckSlot;

/// Per-stream read queue capacity (frames).
const READ_CAPACITY: usize = 32;
/// Session write queue capacity (frame batches).
const WRITE_CAPACITY: usize = 64;

/// The client's `client=` settings value; the protocol asks third-party
/// implementations to identify themselves truthfully.
const CLIENT_NAME: &str = concat!("leas/", env!("CARGO_PKG_VERSION"));

/// Shared, server-updatable padding scheme (one per client object).
pub type Padding = RwLock<Arc<PaddingScheme>>;

/// A multiplexed `AnyTLS` session.
pub struct Session {
    /// Monotonic per-client sequence: the pool reuses the newest idle session.
    pub seq: u64,
    inner: Arc<Inner>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

/// State shared by the session tasks and every stream it carries.
struct Inner {
    dead: AtomicBool,
    active: AtomicUsize,
    next_id: AtomicU32,
    streams: Mutex<HashMap<u32, mpsc::Sender<Event>>>,
    /// `None` once the session is closing, so the writer task can end.
    writer: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    padding: Arc<Padding>,
    last_used: Mutex<Instant>,
}

/// One inbound session event delivered to a stream.
enum Event {
    Data(Bytes),
    End,
    Error(String),
}

impl Session {
    /// Authenticate on `stream` and start the session tasks.
    ///
    /// The authentication packet is `sha256(password) | u16 padding0 len |
    /// padding0` and must be the very first bytes on the TLS session.
    pub async fn start(
        stream: BoxStream,
        password: &str,
        padding: Arc<Padding>,
        ack: AuthAckSlot,
        seq: u64,
    ) -> Result<Self, NativeError> {
        let scheme = padding
            .read()
            .expect("anytls padding lock poisoned")
            .clone();
        let padding0 = scheme.padding0_len();
        let mut auth = Vec::with_capacity(32 + 2 + padding0);
        auth.extend_from_slice(&Sha256::digest(password.as_bytes()));
        auth.extend_from_slice(
            &u16::try_from(padding0)
                .expect("padding0 length fits u16")
                .to_be_bytes(),
        );
        auth.resize(auth.len() + padding0, 0);

        let (read_half, mut write_half) = tokio::io::split(stream);
        let timeout = crate::error::timeouts::PROTOCOL;
        // The authentication write is the one eager write on this protocol:
        // the server reads it before it will parse anything else.
        tokio::time::timeout(timeout, write_half.write_all(&auth))
            .await
            .map_err(|_| NativeError::Timeout {
                step: "anytls auth write",
                limit: timeout,
            })??;

        let inner = Arc::new(Inner {
            dead: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            next_id: AtomicU32::new(0),
            streams: Mutex::new(HashMap::new()),
            writer: Mutex::new(None),
            padding: padding.clone(),
            last_used: Mutex::new(Instant::now()),
        });
        let (write_tx, write_rx) = mpsc::channel(WRITE_CAPACITY);
        *inner.writer.lock().expect("anytls writer lock poisoned") = Some(write_tx);

        let settings = frame::frame(
            CMD_SETTINGS,
            0,
            format!(
                "v=2\nclient={CLIENT_NAME}\npadding-md5={}",
                scheme.md5_hex()
            )
            .as_bytes(),
        );
        let writer_task = tokio::spawn(write_loop(write_half, write_rx, inner.clone(), settings));
        let reader_task = tokio::spawn(read_loop(read_half, inner.clone(), ack));
        Ok(Self {
            seq,
            inner,
            tasks: Mutex::new(vec![writer_task, reader_task]),
        })
    }

    /// Reuse check: alive with no open streams.
    pub fn is_idle(&self) -> bool {
        !self.is_dead() && self.inner.active.load(Ordering::Relaxed) == 0
    }

    /// True once the session's read loop ended (EOF, alert, abort).
    pub fn is_dead(&self) -> bool {
        self.inner.dead.load(Ordering::Relaxed)
    }

    /// Mark the session as just used, so the reaper cannot pick it for
    /// eviction between the pool handing it out and its first stream opening.
    pub fn touch(&self) {
        *self
            .inner
            .last_used
            .lock()
            .expect("anytls used lock poisoned") = Instant::now();
    }

    /// Idle time for the reaper.
    pub fn idle_since(&self) -> Instant {
        *self
            .inner
            .last_used
            .lock()
            .expect("anytls used lock poisoned")
    }

    /// Open one stream to `target` (SYN + PSH with the SOCKS5 address).
    pub async fn open_stream(&self, target: &TargetAddr) -> Result<AnyTlsStream, NativeError> {
        if self.inner.dead.load(Ordering::Relaxed) {
            return Err(NativeError::Io(closed()));
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let addr = encode_addr_port_last(target)?;
        let mut batch = Vec::with_capacity(HEADER_LEN * 2 + addr.len());
        frame::push_frame(&mut batch, CMD_SYN, id, &[]);
        frame::push_frame(&mut batch, CMD_PSH, id, &addr);

        let (tx, rx) = mpsc::channel(READ_CAPACITY);
        self.inner
            .streams
            .lock()
            .expect("anytls streams lock poisoned")
            .insert(id, tx);
        self.inner.active.fetch_add(1, Ordering::Relaxed);
        *self
            .inner
            .last_used
            .lock()
            .expect("anytls used lock poisoned") = Instant::now();
        let writer = self
            .inner
            .writer
            .lock()
            .expect("anytls writer lock poisoned")
            .clone();
        let Some(writer) = writer else {
            self.unregister(id);
            self.inner.active.fetch_sub(1, Ordering::Relaxed);
            return Err(NativeError::Io(closed()));
        };
        if writer.send(batch).await.is_err() {
            self.unregister(id);
            self.inner.active.fetch_sub(1, Ordering::Relaxed);
            return Err(NativeError::Io(closed()));
        }
        Ok(AnyTlsStream::new(id, self.inner.clone(), rx))
    }

    /// Tear the session down: streams see EOF, tasks stop.
    pub fn close(&self) {
        self.inner.shutdown();
        for task in self
            .tasks
            .lock()
            .expect("anytls tasks lock poisoned")
            .drain(..)
        {
            task.abort();
        }
    }

    fn unregister(&self, id: u32) {
        self.inner
            .streams
            .lock()
            .expect("anytls streams lock poisoned")
            .remove(&id);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Dropping the JoinHandles would DETACH the tasks; the read loop would
        // then keep the TLS read half alive for the life of the process.
        self.close();
    }
}

impl Inner {
    fn shutdown(&self) {
        self.dead.store(true, Ordering::Relaxed);
        // Dropping the per-stream senders is the EOF every stream observes.
        self.streams
            .lock()
            .expect("anytls streams lock poisoned")
            .clear();
        self.writer
            .lock()
            .expect("anytls writer lock poisoned")
            .take();
    }

    async fn deliver(&self, id: u32, payload: Bytes) {
        let tx = self
            .streams
            .lock()
            .expect("anytls streams lock poisoned")
            .get(&id)
            .cloned();
        if let Some(tx) = tx {
            let _ = tx.send(Event::Data(payload)).await;
        }
    }

    async fn finish(&self, id: u32, error: Option<String>) {
        let tx = self
            .streams
            .lock()
            .expect("anytls streams lock poisoned")
            .remove(&id);
        if let Some(tx) = tx {
            let event = error.map_or(Event::End, Event::Error);
            let _ = tx.send(event).await;
        }
    }

    async fn send_control(&self, command: u8, stream_id: u32) {
        let writer = self
            .writer
            .lock()
            .expect("anytls writer lock poisoned")
            .clone();
        if let Some(writer) = writer {
            let _ = writer.send(frame::frame(command, stream_id, &[])).await;
        }
    }
}

/// Read the session frames and route them.
async fn read_loop(
    mut read_half: tokio::io::ReadHalf<BoxStream>,
    inner: Arc<Inner>,
    ack: AuthAckSlot,
) {
    let mut header = [0u8; HEADER_LEN];
    loop {
        if read_half.read_exact(&mut header).await.is_err() {
            break;
        }
        let header = Header::parse(header);
        let mut payload = vec![0u8; usize::from(header.len)];
        if header.len > 0 && read_half.read_exact(&mut payload).await.is_err() {
            break;
        }
        match header.command {
            CMD_PSH => {
                if !payload.is_empty() {
                    inner.deliver(header.stream_id, Bytes::from(payload)).await;
                }
            }
            CMD_FIN => inner.finish(header.stream_id, None).await,
            CMD_SYNACK => {
                if !payload.is_empty() {
                    inner
                        .finish(
                            header.stream_id,
                            Some(String::from_utf8_lossy(&payload).into_owned()),
                        )
                        .await;
                }
            }
            CMD_ALERT => {
                tracing::warn!(
                    alert = %String::from_utf8_lossy(&payload),
                    "anytls: server alert; closing session"
                );
                ack.set(AuthAck::Failed);
                break;
            }
            CMD_UPDATE_PADDING_SCHEME => {
                if let Some(scheme) = PaddingScheme::parse(&payload) {
                    *inner.padding.write().expect("anytls padding lock poisoned") =
                        Arc::new(scheme);
                } else {
                    tracing::warn!(
                        "anytls: server sent an unparseable padding scheme; keeping the current one"
                    );
                }
            }
            CMD_HEART_REQUEST => {
                inner
                    .send_control(CMD_HEART_RESPONSE, header.stream_id)
                    .await;
            }
            CMD_SERVER_SETTINGS => ack.set(AuthAck::Ok),
            // `cmdSettings`/`cmdSYN` are server-bound, `cmdHeartResponse` needs
            // no action; an unknown command carries data we already discarded.
            _ => {}
        }
    }
    inner.shutdown();
}

/// Write frames, applying the padding scheme to each write.
///
/// The first write is deferred so it leaves together with the first stream's
/// `cmdSYN`/`cmdPSH` — packet 1 of the scheme, exactly as the reference
/// describes.
async fn write_loop(
    mut write_half: tokio::io::WriteHalf<BoxStream>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    inner: Arc<Inner>,
    settings: Vec<u8>,
) {
    let mut pending = Some(settings);
    let mut counter = 0u32;
    while let Some(batch) = rx.recv().await {
        let data = match pending.take() {
            Some(mut settings) => {
                settings.extend_from_slice(&batch);
                settings
            }
            None => batch,
        };
        counter += 1;
        let scheme = inner
            .padding
            .read()
            .expect("anytls padding lock poisoned")
            .clone();
        if let Err(error) = write_padded(&mut write_half, &data, counter, &scheme).await {
            tracing::debug!(%error, "anytls: session write failed");
            break;
        }
    }
    inner.shutdown();
}

/// One padded write: split `data` per the packet's row and trailing
/// `cmdWaste` frames.
async fn write_padded<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    data: &[u8],
    packet: u32,
    scheme: &PaddingScheme,
) -> io::Result<()> {
    if packet >= scheme.stop() {
        write_half.write_all(data).await?;
        return write_half.flush().await;
    }
    let mut rest = data;
    for step in scheme.draw(packet) {
        match step {
            Step::Check => {
                if rest.is_empty() {
                    break;
                }
            }
            Step::Size(size) => {
                if rest.len() > size {
                    write_half.write_all(&rest[..size]).await?;
                    rest = &rest[size..];
                } else if rest.is_empty() {
                    let mut pad = Vec::with_capacity(HEADER_LEN + size);
                    frame::push_frame(&mut pad, CMD_WASTE, 0, &vec![0u8; size]);
                    write_half.write_all(&pad).await?;
                } else {
                    let mut buf = Vec::with_capacity(size);
                    buf.extend_from_slice(rest);
                    // `size` is the TLS plaintext size; the waste frame's own
                    // header is part of it.
                    if let Some(pad_len) = size.checked_sub(rest.len() + HEADER_LEN)
                        && pad_len > 0
                    {
                        frame::push_frame(&mut buf, CMD_WASTE, 0, &vec![0u8; pad_len]);
                    }
                    write_half.write_all(&buf).await?;
                    rest = &[];
                }
            }
        }
    }
    if !rest.is_empty() {
        write_half.write_all(rest).await?;
    }
    write_half.flush().await
}

/// A byte stream carried by one session stream id.
pub struct AnyTlsStream {
    id: u32,
    inner: Arc<Inner>,
    rx: mpsc::Receiver<Event>,
    read_pending: Option<Bytes>,
    read_end: Option<StreamEnd>,
    write_queue: VecDeque<Vec<u8>>,
    write_state: WriteState,
    fin_queued: bool,
}

#[derive(Clone, Copy)]
enum StreamEnd {
    Eof,
    Error,
}

type WriteFuture = Pin<
    Box<
        dyn Future<
                Output = Result<
                    tokio::sync::mpsc::OwnedPermit<Vec<u8>>,
                    mpsc::error::SendError<()>,
                >,
            > + Send,
    >,
>;

enum WriteState {
    Idle,
    Waiting(WriteFuture),
}

impl AnyTlsStream {
    const fn new(id: u32, inner: Arc<Inner>, rx: mpsc::Receiver<Event>) -> Self {
        Self {
            id,
            inner,
            rx,
            read_pending: None,
            read_end: None,
            write_queue: VecDeque::new(),
            write_state: WriteState::Idle,
            fin_queued: false,
        }
    }

    fn writer(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        self.inner
            .writer
            .lock()
            .expect("anytls writer lock poisoned")
            .clone()
    }

    /// Drive the queue front: `Ok(accepted payload bytes)` once it is handed
    /// to the writer task, `Pending` while a reservation is outstanding.
    fn poll_send_front(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        loop {
            match &mut self.write_state {
                WriteState::Idle => {
                    let Some(item) = self.write_queue.front() else {
                        return Poll::Ready(Ok(0));
                    };
                    let accepted = item.len().saturating_sub(HEADER_LEN);
                    let Some(writer) = self.writer() else {
                        return Poll::Ready(Err(closed()));
                    };
                    match writer.try_send(item.clone()) {
                        Ok(()) => {
                            self.write_queue.pop_front();
                            return Poll::Ready(Ok(accepted));
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            self.write_state =
                                WriteState::Waiting(Box::pin(writer.reserve_owned()));
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            return Poll::Ready(Err(closed()));
                        }
                    }
                }
                WriteState::Waiting(future) => match future.as_mut().poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        self.write_state = WriteState::Idle;
                        let item = self
                            .write_queue
                            .pop_front()
                            .expect("a reservation in flight has a front item");
                        let accepted = item.len().saturating_sub(HEADER_LEN);
                        permit.send(item);
                        return Poll::Ready(Ok(accepted));
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(Err(closed())),
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }

    fn unregister(&self) {
        self.inner
            .streams
            .lock()
            .expect("anytls streams lock poisoned")
            .remove(&self.id);
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(end) = self.read_end {
            return Poll::Ready(match end {
                StreamEnd::Eof => Ok(()),
                StreamEnd::Error => Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "anytls: stream closed by the server",
                )),
            });
        }
        loop {
            if let Some(pending) = self.read_pending.take() {
                let n = pending.len().min(buf.remaining());
                buf.put_slice(&pending[..n]);
                if n < pending.len() {
                    self.read_pending = Some(pending.slice(n..));
                }
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(Event::Data(data))) => {
                    if data.is_empty() {
                        continue;
                    }
                    self.read_pending = Some(data);
                }
                Poll::Ready(Some(Event::End) | None) => {
                    self.read_end = Some(StreamEnd::Eof);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Event::Error(message))) => {
                    tracing::debug!(%message, "anytls: stream aborted");
                    self.read_end = Some(StreamEnd::Error);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        message,
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fin_queued {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "anytls: write after shutdown",
            )));
        }
        let mut accepted = 0;
        loop {
            match self.poll_send_front(cx) {
                Poll::Ready(Ok(n)) => accepted += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return if accepted > 0 {
                        Poll::Ready(Ok(accepted))
                    } else {
                        Poll::Pending
                    };
                }
            }
            if self.write_queue.is_empty() {
                if accepted >= buf.len() {
                    return Poll::Ready(Ok(accepted));
                }
                let chunk = (buf.len() - accepted).min(frame::MAX_PAYLOAD);
                let mut encoded = Vec::with_capacity(HEADER_LEN + chunk);
                frame::push_frame(
                    &mut encoded,
                    CMD_PSH,
                    self.id,
                    &buf[accepted..accepted + chunk],
                );
                self.write_queue.push_back(encoded);
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_send_front(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.poll_send_front(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            if self.write_queue.is_empty() {
                break;
            }
        }
        if !self.fin_queued {
            self.fin_queued = true;
            let id = self.id;
            self.write_queue.push_back(frame::frame(CMD_FIN, id, &[]));
            self.unregister();
        }
        loop {
            match self.poll_send_front(cx) {
                Poll::Ready(Ok(_)) => {
                    if self.write_queue.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        self.inner.active.fetch_sub(1, Ordering::Relaxed);
        self.unregister();
        if self.fin_queued || self.inner.dead.load(Ordering::Relaxed) {
            return;
        }
        self.fin_queued = true;
        let Some(writer) = self.writer() else {
            return;
        };
        let mut queue: Vec<Vec<u8>> = self.write_queue.drain(..).collect();
        queue.push(frame::frame(CMD_FIN, self.id, &[]));
        // Parked reservation: hand the rest to a task so the FIN still leaves.
        drop(std::mem::replace(&mut self.write_state, WriteState::Idle));
        tokio::spawn(async move {
            for item in queue {
                if writer.send(item).await.is_err() {
                    break;
                }
            }
        });
    }
}

/// A dead session/stream error.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "anytls: session closed")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::frame::{
        self, CMD_FIN, CMD_PSH, CMD_SETTINGS, CMD_SYN, CMD_WASTE, HEADER_LEN, Header,
    };
    use super::*;
    use crate::addr::Host;

    fn padding() -> Arc<Padding> {
        Arc::new(RwLock::new(Arc::new(
            PaddingScheme::default_scheme().clone(),
        )))
    }

    /// Read frames until a non-waste one, returning `(header, data)`.
    async fn next_frame<S: tokio::io::AsyncRead + Unpin>(
        stream: &mut S,
    ) -> std::io::Result<(Header, Vec<u8>)> {
        loop {
            let mut raw = [0u8; HEADER_LEN];
            stream.read_exact(&mut raw).await?;
            let header = Header::parse(raw);
            let mut data = vec![0u8; usize::from(header.len)];
            stream.read_exact(&mut data).await?;
            if header.command != CMD_WASTE {
                return Ok((header, data));
            }
        }
    }

    /// Consume the auth packet (34 bytes + padding0).
    async fn consume_auth<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) {
        let mut auth = [0u8; 34];
        stream.read_exact(&mut auth).await.expect("auth");
        let padding0 = usize::from(u16::from_be_bytes([auth[32], auth[33]]));
        let mut zeros = vec![0u8; padding0];
        stream.read_exact(&mut zeros).await.expect("padding0");
    }

    #[tokio::test]
    async fn streams_are_independent_on_one_session() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(async move {
            let mut server = server;
            consume_auth(&mut server).await;
            let (settings, _) = next_frame(&mut server).await.expect("settings");
            assert_eq!(settings.command, CMD_SETTINGS);
            // Two stream opens, then echo each payload back on its own id.
            let mut opened = Vec::new();
            for _ in 0..2 {
                let (syn, _) = next_frame(&mut server).await.expect("syn");
                assert_eq!(syn.command, CMD_SYN);
                let (psh, _addr) = next_frame(&mut server).await.expect("target");
                assert_eq!(psh.stream_id, syn.stream_id);
                assert_eq!(psh.command, CMD_PSH);
                opened.push(syn.stream_id);
            }
            for _ in 0..2 {
                let (data, payload) = next_frame(&mut server).await.expect("data");
                assert_eq!(data.command, CMD_PSH);
                let reply = frame::frame(CMD_PSH, data.stream_id, &payload);
                server.write_all(&reply).await.expect("echo");
            }
            // Close the FIRST stream only.
            let fin = frame::frame(CMD_FIN, opened[0], &[]);
            server.write_all(&fin).await.expect("fin");
            // Hand the peer socket back: the session must not see EOF while
            // the sibling-stream assertion runs.
            (opened, server)
        });

        let session = Session::start(
            Box::new(client),
            "secret",
            padding(),
            AuthAckSlot::new(AuthAck::Unknown),
            1,
        )
        .await
        .expect("session");
        let target = TargetAddr::new(Host::Ip("127.0.0.1".parse().expect("ip")), 80);
        let mut first = session.open_stream(&target).await.expect("first");
        let mut second = session.open_stream(&target).await.expect("second");

        first.write_all(b"one").await.expect("write first");
        second.write_all(b"two").await.expect("write second");
        first.flush().await.expect("flush first");
        second.flush().await.expect("flush second");

        let mut buf = [0u8; 3];
        tokio::time::timeout(Duration::from_secs(5), first.read_exact(&mut buf))
            .await
            .expect("first echo timeout")
            .expect("first echo");
        assert_eq!(&buf, b"one");
        tokio::time::timeout(Duration::from_secs(5), second.read_exact(&mut buf))
            .await
            .expect("second echo timeout")
            .expect("second echo");
        assert_eq!(&buf, b"two");

        // The server closes stream 1: only that stream sees EOF.
        let mut eof = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), first.read(&mut eof))
            .await
            .expect("first eof timeout")
            .expect("first eof read");
        assert_eq!(read, 0, "the FIN'd stream must report EOF");
        let mut third = [0u8; 1];
        let still_open =
            tokio::time::timeout(Duration::from_millis(150), second.read(&mut third)).await;
        assert!(
            still_open.is_err(),
            "the sibling stream must stay open (got {still_open:?})"
        );

        let (ids, _server) = peer.await.expect("peer task");
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1], "each stream gets its own id");
        assert!(!session.is_idle(), "streams are still open");
    }
}
