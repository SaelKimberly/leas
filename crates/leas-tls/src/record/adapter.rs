//! Async adapter over the sans-I/O [`Engine`](super::engine::Engine).
//!
//! This is the public `TlsStream` production path: it moves bytes between the
//! transport and the engine and maps record events to `AsyncRead`/`AsyncWrite`.
//! No record parsing, AEAD or key rotation lives here.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::TlsError;

use super::MAX_RECORD_PAYLOAD;
use super::engine::Engine;
use super::stream::{AppKeys, AppSecrets};

/// A TLS application-data stream: decrypts records on read, encrypts and
/// frames plaintext on write.
///
/// # EOF semantics (deliberate deviation from RFC 8446 §6.1)
///
/// Transport EOF *without* `close_notify` is surfaced as a clean EOF
/// (`Ready(Ok(()))` with zero bytes), deliberately: this stream is a proxy
/// tunnel whose servers close with TCP FIN and do not guarantee
/// `close_notify` (RST arrives as an `io::Error` before the record layer
/// observes EOF). Truncation attacks per RFC 8446 §6.1 are out of scope for
/// this tunnel semantic; a `close_notify` is still honored as EOF when
/// present.
#[allow(
    clippy::struct_excessive_bools,
    reason = "direct read/write, negotiated hybrid/resumed and response flags are independent"
)]
pub struct TlsStream<S> {
    inner: S,
    engine: Engine,
    /// Exact current-record payload window, allocated once and reused.
    read_buf: Vec<u8>,
    /// Five-byte record header being filled.
    hdr: [u8; 5],
    hdr_filled: usize,
    /// Payload state: `Some((content_type, len, filled))` while reading one.
    payload: Option<(u8, usize, usize)>,
    /// Sealed bytes waiting for the transport (crate-visible for tests).
    pub(crate) pending: Vec<u8>,
    /// How much of `pending` has reached `inner` (a cursor, not a drain).
    pending_pos: usize,
    /// Write side switched to raw passthrough (`Vision`).
    write_direct: bool,
    /// Read side switched to raw passthrough (`Vision`).
    read_direct: bool,
    negotiated_hybrid: bool,
    negotiated_alpn: Option<Vec<u8>>,
    resumed: bool,
    /// Server name used to key received session tickets (set by the connect
    /// adapter right after the handshake).
    resumption_key: Option<String>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TlsStream<S> {
    /// Build the adapter around negotiated keys.
    #[must_use]
    pub fn new(inner: S, keys: AppKeys) -> Self {
        Self {
            inner,
            engine: Engine::new(keys),
            read_buf: vec![0; MAX_RECORD_PAYLOAD],
            hdr: [0; 5],
            hdr_filled: 0,
            payload: None,
            pending: Vec::new(),
            pending_pos: 0,
            write_direct: false,
            read_direct: false,
            negotiated_hybrid: false,
            negotiated_alpn: None,
            resumed: false,
            resumption_key: None,
        }
    }

    /// Whether the handshake negotiated a hybrid (post-quantum) key share.
    #[must_use]
    pub const fn negotiated_hybrid(&self) -> bool {
        self.negotiated_hybrid
    }

    /// Record the negotiated key-exchange shape (handshake internal).
    pub(crate) const fn set_negotiated_hybrid(&mut self, hybrid: bool) {
        self.negotiated_hybrid = hybrid;
    }

    /// Switch writes to the raw transport (the last record must be flushed).
    pub const fn set_write_direct(&mut self) {
        self.write_direct = true;
    }

    /// Switch reads to the raw transport (at a clean record boundary).
    pub const fn set_read_direct(&mut self) {
        self.read_direct = true;
    }

    /// The ALPN protocol the server selected.
    #[must_use]
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
    }

    /// Record the negotiated ALPN (handshake internal).
    pub(crate) fn set_negotiated_alpn(&mut self, alpn: Option<Vec<u8>>) {
        self.negotiated_alpn = alpn;
    }

    /// Whether the handshake resumed a cached PSK.
    #[must_use]
    pub const fn is_resumed(&self) -> bool {
        self.resumed
    }

    /// Record the resumption outcome (handshake internal).
    pub(crate) const fn set_resumed(&mut self, resumed: bool) {
        self.resumed = resumed;
    }

    /// Key received session tickets by this server name.
    pub(crate) fn set_resumption_key(&mut self, server: String) {
        self.resumption_key = Some(server);
    }

    /// Move newly received tickets into the bounded cache.
    fn drain_tickets(&mut self) {
        let Some(name) = self.resumption_key.as_deref() else {
            return;
        };
        let alpn = self.negotiated_alpn.clone().unwrap_or_default();
        while let Some(ticket) = self.engine.take_ticket() {
            crate::handshake::resume::store(name, &alpn, ticket);
        }
    }

    /// Install the application traffic secrets for `KeyUpdate`.
    pub(crate) fn set_app_secrets(&mut self, secrets: AppSecrets) {
        self.engine.set_app_secrets(secrets);
    }

    /// Test seam: put the write counter at a record limit.
    #[cfg(test)]
    pub(crate) const fn set_write_seq(&mut self, seq: u64) {
        self.engine.set_write_seq(seq);
    }

    /// Test seam: the current write counter.
    #[cfg(test)]
    pub(crate) const fn write_seq(&self) -> u64 {
        self.engine.write_seq()
    }

    /// Write as much of `pending` as possible.
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]) {
                Poll::Pending | Poll::Ready(Ok(0)) => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => self.pending_pos += n,
            }
        }
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }

    /// Drain engine output into the transport staging buffer.
    fn stage_output(&mut self) {
        self.engine.poll_transmit(&mut self.pending);
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_direct {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        loop {
            if let Some(data) = this.engine.poll_data() {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                this.engine.consume(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(event) = this.engine.poll_event() {
                return Poll::Ready(match event {
                    super::engine::RecordEvent::Closed => Ok(()),
                    super::engine::RecordEvent::Alert { level, description } => {
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            format!("TLS alert: level {level} description {description}"),
                        ))
                    }
                });
            }
            if this.engine.is_closed() {
                return Poll::Ready(Ok(()));
            }
            if let Some((content_type, len, filled)) = this.payload {
                let mut rb = ReadBuf::new(&mut this.read_buf[filled..len]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "truncated TLS record payload",
                            )));
                        }
                        let filled = filled + n;
                        if filled < len {
                            this.payload = Some((content_type, len, filled));
                        } else {
                            this.payload = None;
                            if let Err(e) = this
                                .engine
                                .feed_record(content_type, &mut this.read_buf[..len])
                            {
                                return Poll::Ready(Err(to_io_error(e)));
                            }
                            this.stage_output();
                            this.drain_tickets();
                        }
                    }
                }
                continue;
            }
            let mut rb = ReadBuf::new(&mut this.hdr[this.hdr_filled..]);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        if this.hdr_filled == 0 {
                            if let Err(e) = this.engine.feed_eof() {
                                return Poll::Ready(Err(to_io_error(e)));
                            }
                            this.stage_output();
                            continue;
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated TLS record header",
                        )));
                    }
                    this.hdr_filled += n;
                }
            }
            if this.hdr_filled < this.hdr.len() {
                continue;
            }
            this.hdr_filled = 0;
            let content_type = this.hdr[0];
            let len = usize::from(u16::from_be_bytes([this.hdr[3], this.hdr[4]]));
            if let Some(cleartext) = super::cleartext_hello_answer(this.hdr) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "peer does not speak TLS: it answered in cleartext ({cleartext:?}) — \
                         the endpoint's port or its `security` setting is wrong"
                    ),
                )));
            }
            if len > MAX_RECORD_PAYLOAD {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("TLS record too large: {len} bytes"),
                )));
            }
            if len == 0 {
                if let Err(e) = this.engine.feed_record(content_type, &mut []) {
                    return Poll::Ready(Err(to_io_error(e)));
                }
                this.stage_output();
            } else {
                this.payload = Some((content_type, len, 0));
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_direct {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if this.pending_pos < this.pending.len() {
            match this.flush_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let take = match this.engine.seal_batch(buf) {
            Ok(take) => take,
            Err(e) => return Poll::Ready(Err(to_io_error(e))),
        };
        this.stage_output();
        match this.flush_pending(cx) {
            Poll::Pending | Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_direct {
            return Pin::new(&mut this.inner).poll_flush(cx);
        }
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_direct {
            return Pin::new(&mut this.inner).poll_shutdown(cx);
        }
        if let Err(e) = this.engine.queue_close_notify() {
            return Poll::Ready(Err(to_io_error(e)));
        }
        this.stage_output();
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn to_io_error(e: TlsError) -> io::Error {
    match e {
        TlsError::Io(io) => io,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::crypto::{AeadKey, CipherSuiteId};
    use crate::record::stream::AppKeys;

    struct Counting<S> {
        inner: S,
        writes: Arc<AtomicUsize>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Counting<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Counting<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    fn keys() -> AppKeys {
        let key = AeadKey::from_key_bytes(CipherSuiteId::Aes128GcmSha256, &[0x11; 16]).unwrap();
        AppKeys::tls13(key.clone_key(), key)
    }

    /// A 64 KiB relay write leaves as two transport writes (two 32 KiB
    /// batches), not one per 16 KiB record.
    #[tokio::test]
    async fn sixty_four_kib_costs_two_transport_writes() {
        let (a, mut peer) = tokio::io::duplex(256 * 1024);
        let writes = Arc::new(AtomicUsize::new(0));
        let mut stream = TlsStream::new(
            Counting {
                inner: a,
                writes: Arc::clone(&writes),
            },
            keys(),
        );
        let drain = tokio::spawn(async move {
            let mut sink = vec![0u8; 16 * 1024];
            loop {
                match peer.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        let payload = vec![0xABu8; 64 * 1024];
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
        let _ = drain.await;
        assert!(
            writes.load(Ordering::Relaxed) <= 2,
            "expected <=2 transport writes, got {}",
            writes.load(Ordering::Relaxed)
        );
    }
}
