//! `obfs=http` framing: one HTTP request head, then raw bytes.
//!
//! The reference is `thirdparty/sing-box/transport/simple-obfs/http.go`:
//!
//! * **write** — the first write is replaced by a `GET http://<host>/ HTTP/1.1`
//!   request whose body is the payload: `Upgrade: websocket`,
//!   `Connection: Upgrade`, a 16-byte random `Sec-WebSocket-Key`,
//!   `Content-Length: <len>`, `User-Agent: curl/7.<r>.<r>`, and
//!   `Host: <host>[:<port unless 80>]`. It is a **disguise, not a WebSocket**:
//!   the server strips the head and pipes the rest to the SS server.
//! * **read** — everything through the first `\r\n\r\n` of the first server
//!   response is discarded, then bytes pass through untouched.
//!
//! The head is written lazily, on the first payload, because that is the moment
//! its `Content-Length` is known (the reference does the same: `http.go:63-83`).

use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;
use crate::context::LinkContext;
use crate::rand::fill_nonsecret;

use super::obfs_host_header;

/// The largest first-response head we buffer while looking for its end.
const MAX_HEAD: usize = 8 * 1024;

/// Wrap `inner` so the first write becomes an HTTP request head.
///
/// `host_header` is the value the `Host` header (and the request target) carry:
/// the plugin's host with its `:port` suffix, falling back to the server host.
pub(crate) fn wrap(inner: BoxStream, host_header: String) -> BoxStream {
    Box::new(HttpObfs {
        inner,
        host: host_header,
        head: Vec::new(),
        written: false,
        read_state: ReadState::BeforeHead,
        scan: Vec::new(),
        pending: Vec::new(),
    })
}

/// The `LinkContext`-driven entry the transport arm calls: resolve the `Host`
/// header value, then wrap.
pub(crate) fn wrap_for(
    ctx: &LinkContext,
    inner: BoxStream,
    spec: &leas_proto::proto_spec::PluginSpec,
) -> BoxStream {
    wrap(
        inner,
        obfs_host_header(
            spec.host.as_deref(),
            spec.port,
            ctx.params.server.host.as_str(),
        ),
    )
}

/// Where the read side is: still discarding the server's first response head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadState {
    /// Dropping bytes until the first `\r\n\r\n`.
    BeforeHead,
    /// The head is gone; bytes are the payload.
    Payload,
}

struct HttpObfs {
    inner: BoxStream,
    host: String,
    /// Bytes not yet handed to the socket (the head, then payload).
    head: Vec<u8>,
    written: bool,
    read_state: ReadState,
    /// First-response bytes seen so far, while looking for the head end.
    scan: Vec<u8>,
    /// Payload read past the head that did not fit the caller's buffer. Drained
    /// at the TOP of `poll_read`, before the payload passthrough — otherwise the
    /// leftover would be dropped the moment `read_state` becomes `Payload`.
    pending: Vec<u8>,
}

impl HttpObfs {
    /// The request head for a payload of `len` bytes.
    fn request_head(&self, len: usize) -> Vec<u8> {
        // A 16-byte random key, base64url without padding (`http.go:75`).
        let mut key = [0u8; 16];
        fill_nonsecret(&mut key);
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
        // The reference randomizes a curl version (`http.go:68`); both
        // components come from the CSPRNG pool, like every other draw here.
        let mut ua = [0u8; 2];
        fill_nonsecret(&mut ua);
        format!(
            "GET http://{host}/ HTTP/1.1\r\n\
             Host: {host}\r\n\
             User-Agent: curl/7.{major}.{minor}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Content-Length: {len}\r\n\r\n",
            host = self.host,
            major = ua[0] % 54,
            minor = ua[1] % 2,
        )
        .into_bytes()
    }
}

/// The index just past the first `\r\n\r\n`, if present.
fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

impl AsyncRead for HttpObfs {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Leftover payload from a previous read comes first, whatever the state.
        if !this.pending.is_empty() {
            let take = this.pending.len().min(buf.remaining());
            if take > 0 {
                buf.put_slice(&this.pending[..take]);
            }
            this.pending.drain(..take);
            return Poll::Ready(Ok(()));
        }
        if this.read_state == ReadState::Payload {
            return Pin::new(&mut *this.inner).poll_read(cx, buf);
        }
        let mut scratch = [0u8; 1024];
        loop {
            let mut read_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut *this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        // A clean EOF before any head end: there is nothing to
                        // strip, and the peer has nothing more to say.
                        this.read_state = ReadState::Payload;
                        return Poll::Ready(Ok(()));
                    }
                    this.scan.extend_from_slice(filled);
                    let end = find_head_end(&this.scan);
                    let keep = match end {
                        Some(at) => {
                            this.read_state = ReadState::Payload;
                            at + 4
                        }
                        None if this.scan.len() > MAX_HEAD => {
                            // A response with no head end is not this plugin's
                            // server: stop stripping and pass the bytes through.
                            this.read_state = ReadState::Payload;
                            this.scan.len()
                        }
                        None => continue,
                    };
                    // The remainder can be far larger than the caller's buffer —
                    // the first response after a small head is typically the whole
                    // body — so it goes through `pending`, never straight into
                    // `buf`: `ReadBuf::put_slice` panics when `len > remaining()`,
                    // which is how the 3b row caught this (a 226-byte remainder into
                    // a 32-byte buffer).
                    let mut rest = this.scan.split_off(keep);
                    // Deliver what the caller's buffer takes **in this call** — a
                    // 0-byte read reads as EOF to many callers — and keep only the
                    // overflow for the next poll.
                    let take = rest.len().min(buf.remaining());
                    if take > 0 {
                        buf.put_slice(&rest[..take]);
                        rest.drain(..take);
                    }
                    this.pending = rest;
                    this.read_state = ReadState::Payload;
                    if take == 0 && this.pending.is_empty() {
                        // The head ended exactly on the buffer boundary and the
                        // caller had no room: read more rather than report EOF.
                        continue;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for HttpObfs {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if !this.written {
            this.head.extend_from_slice(&this.request_head(buf.len()));
            this.written = true;
        }
        this.head.extend_from_slice(buf);
        // The bytes are buffered and flushed: the head must reach the socket
        // immediately, ahead of the payload, and `poll_write` returning before
        // the socket has taken them keeps the framing a single head.
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.head.is_empty() {
            return Pin::new(&mut *this.inner).poll_flush(cx);
        }
        let chunk = std::mem::take(&mut this.head);
        match Pin::new(&mut *this.inner).poll_write(cx, &chunk) {
            Poll::Pending => {
                this.head = chunk;
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                this.head = chunk;
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(n)) => {
                if n < chunk.len() {
                    this.head = chunk[n..].to_vec();
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self;
        if !this.head.is_empty() {
            {
                let _ = Pin::new(&mut *this).poll_flush(cx)?;
            }
        }
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    fn wrap_pair(host: &str) -> (HttpObfs, tokio::io::DuplexStream) {
        let (client, server) = duplex(64 * 1024);
        let obfs = HttpObfs {
            inner: Box::new(client),
            host: host.to_string(),
            head: Vec::new(),
            written: false,
            read_state: ReadState::BeforeHead,
            scan: Vec::new(),
            pending: Vec::new(),
        };
        (obfs, server)
    }

    /// The first write is a GET head whose body is the payload — the disguise
    /// the reference writes (`http.go:63-83`), byte for byte in shape.
    #[tokio::test]
    async fn the_first_write_becomes_a_get_head() {
        let (mut obfs, mut peer) = wrap_pair("cdn.example");
        obfs.write_all(b"HELLO-PAYLOAD").await.expect("write");
        obfs.flush().await.expect("flush");

        let mut wire = vec![0u8; 4096];
        let n = peer.read(&mut wire).await.expect("read");
        let text = String::from_utf8_lossy(&wire[..n]).into_owned();

        assert!(
            text.starts_with("GET http://cdn.example/ HTTP/1.1\r\n"),
            "{text}"
        );
        assert!(text.contains("\r\nHost: cdn.example\r\n"), "{text}");
        assert!(text.contains("\r\nConnection: Upgrade\r\n"), "{text}");
        assert!(text.contains("\r\nUpgrade: websocket\r\n"), "{text}");
        assert!(text.contains("\r\nContent-Length: 13\r\n"), "{text}");
        assert!(
            text.contains("Sec-WebSocket-Key: ") && text.contains("\r\nContent-Length"),
            "{text}"
        );
        // The key is 16 random bytes in base64url: 22 unpadded characters.
        let key = text
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .expect("a key header");
        assert_eq!(key.len(), 22, "{key}");
        assert!(text.contains("User-Agent: curl/7."), "{text}");
        assert!(text.ends_with("\r\n\r\nHELLO-PAYLOAD"), "{text}");
    }

    /// The `Host` header carries the stated `:port` verbatim — the port reaches
    /// the header and nothing else. (Port elision and the endpoint fallback are
    /// `super::obfs_host_header`'s rule, tested there.)
    #[tokio::test]
    async fn the_host_header_carries_the_stated_port() {
        let (mut obfs, mut peer) = wrap_pair("df1fab2.dl.nintendo.net:16569");
        obfs.write_all(b"x").await.expect("write");
        obfs.flush().await.expect("flush");
        let mut wire = vec![0u8; 512];
        let n = peer.read(&mut wire).await.expect("read");
        let text = String::from_utf8_lossy(&wire[..n]).into_owned();
        assert!(
            text.contains("Host: df1fab2.dl.nintendo.net:16569\r\n"),
            "{text}"
        );
    }
    #[tokio::test]
    async fn later_writes_are_raw() {
        let (mut obfs, mut peer) = wrap_pair("cdn.example");
        obfs.write_all(b"one").await.expect("write");
        obfs.flush().await.expect("flush");
        let mut first = vec![0u8; 512];
        let n = peer.read(&mut first).await.expect("read");
        obfs.write_all(b"two").await.expect("write");
        obfs.flush().await.expect("flush");
        let mut second = vec![0u8; 512];
        let m = peer.read(&mut second).await.expect("read");
        assert_eq!(&second[..m], b"two", "no second head");
        assert!(String::from_utf8_lossy(&first[..n]).ends_with("one"));
    }

    /// The read side drops the server's first response head and returns what
    /// follows it (`http.go:37-58`).
    #[tokio::test]
    async fn the_first_response_head_is_stripped() {
        let (mut obfs, mut peer) = wrap_pair("cdn.example");
        peer.write_all(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nPAYLOAD-AFTER")
            .await
            .expect("server writes");
        let mut got = vec![0u8; 64];
        let n = obfs.read(&mut got).await.expect("read");
        assert_eq!(&got[..n], b"PAYLOAD-AFTER");

        // And afterwards, raw.
        peer.write_all(b"MORE").await.expect("server writes");
        let mut got = vec![0u8; 16];
        let n = obfs.read(&mut got).await.expect("read");
        assert_eq!(&got[..n], b"MORE");
    }

    /// A caller buffer smaller than the response body must not panic, and no byte
    /// may be dropped. This is the case the hermetic tests missed and the 3b row
    /// caught: a 226-byte remainder went into a 32-byte `ReadBuf`.
    #[tokio::test]
    async fn a_small_read_buffer_still_receives_every_payload_byte() {
        let (mut obfs, mut peer) = wrap_pair("cdn.example");
        let body = vec![b'Z'; 300];
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 300\r\n\r\n".to_vec();
        response.extend_from_slice(&body);
        peer.write_all(&response).await.expect("server writes");

        let mut got = Vec::new();
        let mut chunk = [0u8; 32];
        while got.len() < body.len() {
            let n = obfs.read(&mut chunk).await.expect("read");
            assert!(n > 0, "no progress at {} bytes", got.len());
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got.len(), body.len(), "no padding, no truncation");
        assert!(got.iter().all(|b| *b == b'Z'), "payload survived intact");
    }

    /// A response split across reads must still be stripped: the head end can
    /// arrive one byte at a time.
    #[tokio::test]
    async fn a_split_response_head_is_still_stripped() {
        let (mut obfs, mut peer) = wrap_pair("cdn.example");
        for chunk in [&b"HTTP/1.1 200 OK"[..], b"\r\n", b"\r\nTAIL"] {
            peer.write_all(chunk).await.expect("server writes");
            obfs.flush().await.ok();
        }
        let mut got = vec![0u8; 64];
        let n = obfs.read(&mut got).await.expect("read");
        assert_eq!(&got[..n], b"TAIL", "only the payload survives");
    }
}
