//! WebSocket transport: RFC 6455 framing (tokio-tungstenite) over an
//! established stream — the engine TLS/REALITY session or raw TCP. The
//! transport never owns TLS; it consumes `AsyncRead + AsyncWrite`.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Context as TaskCx, Poll, ready};

use bytes::{Buf, Bytes};
use futures_core::Stream;
use futures_core::future::BoxFuture;
use futures_sink::Sink;
use leas_proto::proto_spec::common::WebSocketConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{CONNECTION, HOST, UPGRADE};
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, Request, StatusCode};

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};

/// Build the WS upgrade request. Pure, unit-testable.
pub fn ws_request(cfg: &WebSocketConfig, server_host: &str) -> Result<Request<()>, NativeError> {
    let path = super::request_target(cfg.path.as_deref().unwrap_or("/"));
    let host = super::host_or(cfg.host.as_deref(), server_host);
    let mut req = format!("ws://{host}{path}")
        .into_client_request()
        .map_err(|e| NativeError::Config(format!("ws request: {e}")))?;
    req.headers_mut().insert(
        HOST,
        HeaderValue::from_str(host).map_err(|e| NativeError::Config(format!("ws host: {e}")))?,
    );
    if let Some(headers) = &cfg.headers {
        for (k, v) in headers {
            let name = http_name(k);
            if let Ok(vv) = HeaderValue::from_str(v) {
                req.headers_mut().append(name, vv);
            }
        }
    }
    req.headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    req.headers_mut()
        .insert(UPGRADE, HeaderValue::from_static("websocket"));
    Ok(req)
}

fn http_name(k: &str) -> HeaderName {
    HeaderName::from_bytes(k.as_bytes())
        .unwrap_or_else(|_| HeaderName::from_static("x-v2ray-unknown"))
}

/// Run the WS upgrade over the established (secured) stream.
///
/// With `max_early_data` set (`?ed=N` in a share link), the upgrade is
/// DEFERRED to the first protocol write so those N bytes can ride the
/// `Sec-WebSocket-Protocol` header — Xray's early-data trick
/// (`transport/internet/websocket/dialer.go:143-145`). Deferring (instead of
/// prefetching from a pipe) keeps the upgrade in the caller's own future, so a
/// rejected handshake still surfaces as [`NativeError::TransportRejected`]
/// rather than as an anonymous EOF on a background task.
pub async fn connect(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let cfg = ctx.transport_ws().ok_or_else(|| {
        NativeError::Config("ws transport requested but config has no ws settings".into())
    })?;
    if let Some(max) = cfg.max_early_data.filter(|n| *n > 0) {
        return Ok(Box::new(EarlyDataDial::new(
            cfg.clone(),
            ctx.params.server.host.as_str().to_string(),
            stream,
            usize::try_from(max).unwrap_or(usize::MAX),
        )));
    }
    let req = ws_request(cfg, ctx.params.server.host.as_str())?;
    let ws = upgrade_with(req, stream, "ws").await?;
    Ok(Box::new(WsStream::new(ws)))
}

/// `Sec-WebSocket-Protocol` carrying URL-safe base64 of the first bytes.
///
/// Xray's server decodes it, feeds those bytes to the tunnel BEFORE the first
/// frame, and echoes the same header back. The bytes travel in the header and
/// NOWHERE else: any frame copy duplicates the first flight (issue 012).
fn early_data_request(
    cfg: &WebSocketConfig,
    host: &str,
    early: &[u8],
) -> Result<Request<()>, NativeError> {
    use base64::Engine as _;
    let mut req = ws_request(cfg, host)?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(early);
    req.headers_mut().insert(
        HeaderName::from_static("sec-websocket-protocol"),
        HeaderValue::from_str(&encoded)
            .map_err(|e| NativeError::Config(format!("ws early-data header: {e}")))?,
    );
    Ok(req)
}

/// The deferred-upgrade stream behind [`connect`] when early data is on.
pub struct EarlyDataDial {
    cfg: WebSocketConfig,
    host: String,
    /// The secured stream, consumed when the upgrade starts.
    stream: Option<BoxStream>,
    /// The upgrade future, created on the first write.
    upgrading: Option<
        BoxFuture<'static, Result<tokio_tungstenite::WebSocketStream<BoxStream>, NativeError>>,
    >,
    ws: Option<WsStream>,
    /// Bytes captured from the caller's first write. They travel in the
    /// `Sec-WebSocket-Protocol` header and nowhere else: the capture branch
    /// reports them consumed, so the buffer is only alive long enough to
    /// build the upgrade request.
    early: Vec<u8>,
    /// The reader parked before the first write started the upgrade: nothing
    /// would poll it again otherwise (the upgrade future is created by the
    /// writer).
    read_waker: Option<std::task::Waker>,
    max_early: usize,
}

impl EarlyDataDial {
    fn new(cfg: WebSocketConfig, host: String, stream: BoxStream, max_early: usize) -> Self {
        Self {
            cfg,
            host,
            stream: Some(stream),
            upgrading: None,
            ws: None,
            early: Vec::new(),
            read_waker: None,
            max_early,
        }
    }

    /// Drive a pending upgrade to completion. `Ready(Ok)` also means "there
    /// was none", so flush/shutdown can chain it unconditionally.
    fn poll_pending_upgrade(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.ws.is_some() {
            return Poll::Ready(Ok(()));
        }
        let Some(fut) = self.upgrading.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(ws)) => {
                self.ws = Some(WsStream::new(ws));
                self.upgrading = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.upgrading = None;
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for EarlyDataDial {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Reads cannot precede the upgrade: drive it first.
        if this.ws.is_none() {
            let Some(fut) = this.upgrading.as_mut() else {
                // No first write yet, and a read cannot start the upgrade:
                // the early bytes come from that write. Park WITH a waker so
                // the writer that starts the upgrade can wake this read.
                this.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            };
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(ws)) => {
                    this.ws = Some(WsStream::new(ws));
                    this.upgrading = None;
                }
                Poll::Ready(Err(e)) => {
                    // A finished future left in the slot is polled again by
                    // the next read (or the relay's half-close): resuming a
                    // completed `async fn` panics.
                    this.upgrading = None;
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let ws = this.ws.as_mut().expect("checked above");
        Pin::new(ws).poll_read(cx, buf)
    }
}

impl AsyncWrite for EarlyDataDial {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.ws.is_none() {
            if this.upgrading.is_none() {
                // First write: capture up to `max_early` bytes and start
                // the upgrade with them in the header. Reporting `take`
                // consumed is the whole contract: those bytes leave via the
                // header, so they must never be written again as a frame.
                let take = data.len().min(this.max_early.max(1));
                if take == 0 {
                    return Poll::Ready(Ok(0));
                }
                this.early.extend_from_slice(&data[..take]);
                let Some(stream) = this.stream.take() else {
                    return Poll::Ready(Err(io::Error::other("ws early-data: no stream")));
                };
                let req = match early_data_request(&this.cfg, &this.host, &this.early) {
                    Ok(req) => req,
                    Err(e) => return Poll::Ready(Err(io::Error::other(e))),
                };
                // The captured bytes live in the request now; the buffer is
                // dead weight past this point.
                this.early.clear();
                this.upgrading = Some(Box::pin(upgrade_with(req, stream, "ws")));
                if let Some(waker) = this.read_waker.take() {
                    waker.wake();
                }
                return Poll::Ready(Ok(take));
            }
            let Some(fut) = this.upgrading.as_mut() else {
                return Poll::Ready(Err(io::Error::other("ws early-data: no upgrade")));
            };
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(ws)) => {
                    this.ws = Some(WsStream::new(ws));
                    this.upgrading = None;
                }
                Poll::Ready(Err(e)) => {
                    // Finished: clearing the slot keeps a later flush or
                    // shutdown from resuming the completed `async fn`.
                    this.upgrading = None;
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        // The early prefix already left in the header; only the caller's
        // current buffer goes on the wire.
        let ws = this.ws.as_mut().expect("checked above");
        Pin::new(ws).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // The first flight rides the upgrade request: a flush must DRIVE a
        // pending upgrade, never report success for bytes still in the header
        // (the capture branch already reported them consumed).
        ready!(this.poll_pending_upgrade(cx))?;
        this.ws
            .as_mut()
            .map_or(Poll::Ready(Ok(())), |ws| Pin::new(ws).poll_flush(cx))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Same rule for close: dropping an unpolled upgrade future would lose
        // the request (and its early data) without a trace.
        ready!(this.poll_pending_upgrade(cx))?;
        this.ws
            .as_mut()
            .map_or(Poll::Ready(Ok(())), |ws| Pin::new(ws).poll_shutdown(cx))
    }
}

/// Run the WS upgrade for a caller-built request, and wrap the negotiated
/// connection as a byte stream.
///
/// **One owner for the exchange**: `step` names the caller's phase in the
/// timeout and transport errors, so a SIP003 plugin row reports "v2ray-plugin
/// ws upgrade" while a `TransportConfig` row reports "ws upgrade" — but the
/// handshake, the 101 requirement, and the binary-message wrapper are shared,
/// because a plugin row and a transport row are the same wire (spec §2.5, and
/// the only difference is where the request line and headers come from).
pub async fn upgrade_with(
    req: Request<()>,
    stream: BoxStream,
    step: &'static str,
) -> Result<WebSocketStream<BoxStream>, NativeError> {
    let handshake = tokio_tungstenite::client_async(req, stream);
    let (ws, resp) = tokio::time::timeout(timeouts::TRANSPORT, handshake)
        .await
        .map_err(|_| NativeError::Timeout {
            step,
            limit: timeouts::TRANSPORT,
        })?
        .map_err(|e| match e {
            // The server's own answer to the upgrade carries an HTTP status —
            // the typed signal the purge policy reads (`evidence`).
            tokio_tungstenite::tungstenite::Error::Http(resp) => NativeError::TransportRejected {
                detail: format!("{step}: HTTP error: {}", resp.status()),
                status: resp.status().as_u16(),
            },
            other => NativeError::Transport(format!("{step}: {other}")),
        })?;
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(NativeError::TransportRejected {
            detail: format!("{step} rejected: {}", resp.status()),
            status: resp.status().as_u16(),
        });
    }
    Ok(ws)
}

/// Binary-message byte stream: writes buffer into Binary frames (flushed on
/// `poll_flush`); reads drain Binary payloads (pong auto-replied by
/// tungstenite); Close/EOF surfaces as `UnexpectedEof`.
pub struct WsStream {
    inner: WebSocketStream<BoxStream>,
    /// Decoded Binary payloads awaiting the app: queued as `Bytes` chunks
    /// (zero-copy from tungstenite) and sliced on drain — no staging
    /// `BytesMut` copy per message.
    queued: VecDeque<Bytes>,
}

impl WsStream {
    #[must_use]
    pub fn new(inner: WebSocketStream<BoxStream>) -> Self {
        Self {
            inner,
            queued: VecDeque::new(),
        }
    }
}

/// Drain the front queued chunk into `buf`. Returns `true` when bytes were
/// delivered (the caller reports `Ready`).
fn drain_front(queued: &mut VecDeque<Bytes>, buf: &mut ReadBuf<'_>) -> bool {
    let Some(front) = queued.front_mut() else {
        return false;
    };
    let n = std::cmp::min(front.len(), buf.remaining());
    buf.put_slice(&front[..n]);
    front.advance(n);
    if front.is_empty() {
        queued.pop_front();
    }
    true
}

impl AsyncRead for WsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if drain_front(&mut self.queued, buf) {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(b)))) => {
                    if !b.is_empty() {
                        self.queued.push_back(b);
                    }
                }
                Poll::Ready(Some(Ok(Message::Close(_))) | None) => {
                    // Clean WS close: report EOF so `read_to_end` completes.
                    return Poll::Ready(Ok(()));
                }
                // Ping (pong auto-sent by tungstenite), Pong, Text, Frame: ignored.
                Poll::Ready(Some(Ok(_))) => {}
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Write-through (leaf's pattern): one Binary frame per write, best
        // effort flush so flush-less consumers (`write_all`-only) deliver.
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            Poll::Ready(Ok(())) => {}
        }
        // `Bytes::copy_from_slice` moves one copy straight into the frame
        // payload — no intermediate `Vec` allocation on the forward path.
        let msg = Message::Binary(Bytes::copy_from_slice(buf));
        if let Err(e) = Pin::new(&mut self.inner).start_send(msg) {
            return Poll::Ready(Err(io::Error::other(e)));
        }
        let _ = Pin::new(&mut self.inner).poll_flush(cx);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod early_data_tests {
    use super::*;

    fn cfg(max: Option<u32>) -> WebSocketConfig {
        WebSocketConfig {
            path: Some("/x".into()),
            max_early_data: max,
            ..WebSocketConfig::default()
        }
    }

    /// A rejected upgrade must not be polled a second time by the relay's
    /// half-close (`async fn resumed after completion` at `upgrade_with`).
    /// The error surfaces once, through the read; shutdown afterwards is a
    /// clean no-op because the capture consumed the header and the upgrade
    /// slot is cleared.
    #[tokio::test]
    async fn shutdown_after_a_rejected_upgrade_does_not_repoll_the_upgrade() {
        use crate::protocol::first_flight::HeaderFirst;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            let mut head = [0u8; 4096];
            let _ = server.read(&mut head).await;
            server
                .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let dial = EarlyDataDial::new(cfg(Some(64)), "example.com".into(), Box::new(client), 64);
        let mut stream = HeaderFirst::new(Box::new(dial), b"HEADER".to_vec());
        stream.write_all(b"PAYLOAD").await.unwrap();
        let err = stream.read(&mut [0u8; 1]).await.unwrap_err();
        assert!(err.to_string().contains("400"), "{err}");
        stream
            .shutdown()
            .await
            .expect("one terminal error, then a clean close");
        srv.await.unwrap();
    }

    /// A rejected upgrade must keep the typed `NativeError` inside the io
    /// error: the TLS layer's `map_tls_err` recovers it, and a formatted string
    /// classified 3 261 ws-status rows as TLS alerts on the 2026-11-20 run.
    #[tokio::test]
    async fn a_rejected_upgrade_keeps_the_typed_transport_error() {
        use crate::protocol::first_flight::HeaderFirst;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            let mut head = [0u8; 4096];
            let _ = server.read(&mut head).await;
            server
                .write_all(b"HTTP/1.1 409 Conflict\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let dial = EarlyDataDial::new(cfg(Some(64)), "example.com".into(), Box::new(client), 64);
        let mut stream = HeaderFirst::new(Box::new(dial), b"HEADER".to_vec());
        stream.write_all(b"PAYLOAD").await.unwrap();
        let err = stream.read(&mut [0u8; 1]).await.unwrap_err();
        let inner = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<crate::error::NativeError>());
        assert!(
            matches!(
                inner,
                Some(crate::error::NativeError::TransportRejected { status: 409, .. })
            ),
            "the io error boxes the typed transport error: {inner:?} / {err}"
        );
        srv.await.unwrap();
    }

    /// A read that arrives BEFORE the first write parks with a waker; the
    /// write that starts the upgrade must wake it, or a server-first peer
    /// deadlocks (the waker is the only channel between the two halves).
    #[tokio::test]
    async fn a_read_before_the_first_write_is_woken_by_it() {
        use futures_sink::Sink;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, server) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_hdr_async(server, echo_subprotocol)
                .await
                .unwrap();
            std::future::poll_fn(|cx| Pin::new(&mut ws).poll_ready(cx))
                .await
                .unwrap();
            Pin::new(&mut ws)
                .start_send(Message::Binary(Bytes::from_static(b"REPLY")))
                .unwrap();
            std::future::poll_fn(|cx| Pin::new(&mut ws).poll_flush(cx))
                .await
                .unwrap();
        });
        let dial = EarlyDataDial::new(cfg(Some(8)), "example.com".into(), Box::new(client), 8);
        let (mut reader, mut writer) = tokio::io::split(dial);
        // Poll the read first so it parks with the waker installed.
        let read = tokio::spawn(async move {
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf).await.map(|_| buf)
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        writer.write_all(b"PAYLOAD").await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), read)
            .await
            .expect("the first write must wake the parked read")
            .expect("read task")
            .expect("reply");
        assert_eq!(&got, b"REPLY");
        srv.await.unwrap();
    }

    /// A first write larger than the early window: the prefix rides the
    /// header, the remainder goes out as frames, each exactly once.
    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite's callback shape
    async fn a_partial_early_capture_sends_the_remainder_as_frames() {
        use base64::Engine as _;
        use futures_core::Stream;
        use std::sync::{Arc, Mutex};
        use tokio::io::AsyncWriteExt;

        let (client, server) = tokio::io::duplex(64 * 1024);
        let seen_header = Arc::new(Mutex::new(None::<String>));
        let capture = Arc::clone(&seen_header);
        let srv = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_hdr_async(
                server,
                move |req: &tokio_tungstenite::tungstenite::http::Request<()>,
                      resp: tokio_tungstenite::tungstenite::http::Response<()>| {
                    if let Some(v) = req.headers().get("sec-websocket-protocol") {
                        *capture.lock().expect("capture") = v.to_str().ok().map(str::to_owned);
                    }
                    echo_subprotocol(req, resp)
                },
            )
            .await
            .unwrap();
            let mut frames = Vec::new();
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(400);
            loop {
                let next = std::future::poll_fn(|cx| Pin::new(&mut ws).poll_next(cx));
                match tokio::time::timeout_at(deadline, next).await {
                    Ok(Some(Ok(Message::Binary(b)))) => frames.extend_from_slice(&b),
                    _ => break,
                }
            }
            frames
        });
        let dial = EarlyDataDial::new(cfg(Some(4)), "example.com".into(), Box::new(client), 4);
        let mut stream = dial;
        stream.write_all(b"0123456789").await.unwrap();
        // The upgrade still has to be driven: a flush does it (and is itself
        // the regression guard for the flush-before-upgrade path).
        stream.flush().await.unwrap();

        let header = seen_header
            .lock()
            .expect("capture")
            .clone()
            .expect("header sent");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header)
            .expect("base64url");
        assert_eq!(&decoded, b"0123", "the header carries exactly the window");
        let frames = srv.await.unwrap();
        assert_eq!(frames, b"456789", "the remainder goes out once");
    }

    /// The captured prefix travels in `Sec-WebSocket-Protocol` and nowhere
    /// else. Asserting only one half cannot tell "sent once, in the header"
    /// from "sent twice, once as a frame" (issue 012: 26 bytes off the socket
    /// for a 13-byte write).
    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite's callback shape
    async fn early_data_bytes_reach_the_carrier_once() {
        use crate::protocol::first_flight::HeaderFirst;
        use base64::Engine as _;
        use futures_core::Stream;
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, server) = tokio::io::duplex(64 * 1024);
        let seen_header = Arc::new(Mutex::new(None::<String>));
        let capture = Arc::clone(&seen_header);
        let srv = tokio::spawn(async move {
            let mut ws = tokio_tungstenite::accept_hdr_async(
                server,
                move |req: &tokio_tungstenite::tungstenite::http::Request<()>,
                      resp: tokio_tungstenite::tungstenite::http::Response<()>| {
                    if let Some(v) = req.headers().get("sec-websocket-protocol") {
                        *capture.lock().expect("capture") = v.to_str().ok().map(str::to_owned);
                    }
                    echo_subprotocol(req, resp)
                },
            )
            .await
            .unwrap();
            let mut got = Vec::new();
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(300);
            loop {
                let next = std::future::poll_fn(|cx| Pin::new(&mut ws).poll_next(cx));
                match tokio::time::timeout_at(deadline, next).await {
                    Ok(Some(Ok(Message::Binary(b)))) => got.extend_from_slice(&b),
                    _ => break,
                }
            }
            got
        });
        let dial = EarlyDataDial::new(cfg(Some(64)), "example.com".into(), Box::new(client), 64);
        let mut stream = HeaderFirst::new(Box::new(dial), b"HEADER".to_vec());
        stream.write_all(b"PAYLOAD").await.unwrap();
        // Drive the upgrade to completion: the carrier's echo arrives only
        // after both sides finished the handshake.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(800),
            stream.read(&mut [0u8; 1]),
        )
        .await;

        let header = seen_header
            .lock()
            .expect("capture")
            .clone()
            .expect("header sent");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header)
            .expect("base64url");
        assert_eq!(
            &decoded, b"HEADERPAYLOAD",
            "header must carry the whole buffer"
        );
        let got = srv.await.unwrap();
        assert!(
            got.is_empty(),
            "frames must carry nothing, saw {}",
            String::from_utf8_lossy(&got)
        );
    }

    /// Xray's hub echoes the requested subprotocol (`hub.go:55-59`), and
    /// tungstenite's client refuses an upgrade that drops it.
    #[allow(clippy::result_large_err, clippy::unnecessary_wraps)] // tungstenite's callback shape
    fn echo_subprotocol(
        req: &tokio_tungstenite::tungstenite::http::Request<()>,
        mut resp: tokio_tungstenite::tungstenite::http::Response<()>,
    ) -> Result<
        tokio_tungstenite::tungstenite::http::Response<()>,
        tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
    > {
        if let Some(v) = req.headers().get("sec-websocket-protocol") {
            resp.headers_mut()
                .insert("sec-websocket-protocol", v.clone());
        }
        Ok(resp)
    }

    /// The read that finishes the upgrade must hand up the data it came for,
    /// not park without a waker: the upgrade future is already gone from the
    /// runtime's point of view, so nothing would poll the read again.
    #[tokio::test]
    async fn early_data_upgrade_completes_on_the_read_path() {
        use crate::protocol::first_flight::HeaderFirst;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client, server) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            use futures_sink::Sink;
            let mut ws = tokio_tungstenite::accept_hdr_async(server, echo_subprotocol)
                .await
                .unwrap();
            std::future::poll_fn(|cx| Pin::new(&mut ws).poll_ready(cx))
                .await
                .unwrap();
            Pin::new(&mut ws)
                .start_send(Message::Binary(Bytes::from_static(b"REPLY")))
                .unwrap();
            std::future::poll_fn(|cx| Pin::new(&mut ws).poll_flush(cx))
                .await
                .unwrap();
        });
        let dial = EarlyDataDial::new(cfg(Some(64)), "example.com".into(), Box::new(client), 64);
        let mut stream = HeaderFirst::new(Box::new(dial), b"HEADER".to_vec());
        stream.write_all(b"PAYLOAD").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"REPLY");
        srv.await.unwrap();
    }

    /// Xray's rule: the header carries URL-safe base64 of the first bytes,
    /// and is absent when the knob is unset (a request that grew a header for
    /// no reason would be its own fingerprint).
    #[test]
    fn early_data_header_is_present_only_when_configured() {
        let early = b"GET / HTTP/1.1\r\n";
        let req = early_data_request(&cfg(Some(32)), "example.com", early).unwrap();
        assert_eq!(
            req.headers()
                .get("sec-websocket-protocol")
                .and_then(|v| v.to_str().ok()),
            Some("R0VUIC8gSFRUUC8xLjENCg")
        );
        let plain = ws_request(&cfg(None), "example.com").unwrap();
        assert!(plain.headers().get("sec-websocket-protocol").is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_proto::proto_spec::common::WebSocketConfig;

    #[test]
    fn request_headers_include_host_path_and_custom() {
        let cfg = WebSocketConfig {
            path: Some("/ws?ed=2048".into()),
            host: Some("cdn.example.com".into()),
            headers: Some([("X-Custom".to_string(), "v1".to_string())].into()),
            ..Default::default()
        };
        let req = ws_request(&cfg, "real-server.example").unwrap();
        assert_eq!(req.uri().path_and_query().unwrap().as_str(), "/ws?ed=2048");
        assert_eq!(req.headers().get("host").unwrap(), "cdn.example.com");
        assert_eq!(req.headers().get("x-custom").unwrap(), "v1");
        assert_eq!(req.headers().get("connection").unwrap(), "Upgrade");
        assert_eq!(req.headers().get("upgrade").unwrap(), "websocket");
    }

    #[test]
    fn space_and_unicode_path_are_percent_encoded() {
        let cfg = WebSocketConfig {
            path: Some("/?ed=2560 PuLaFreeBOT ü".into()),
            host: Some("cdn.example.com".into()),
            ..Default::default()
        };
        let req = ws_request(&cfg, "real-server.example").unwrap();
        assert_eq!(
            req.uri().path_and_query().unwrap().as_str(),
            "/?ed=2560%20PuLaFreeBOT%20%C3%BC"
        );
        assert!(req.uri().to_string().is_ascii());
        assert_eq!(req.headers().get("host").unwrap(), "cdn.example.com");
    }

    #[test]
    fn empty_host_falls_back_to_the_server() {
        let cfg = WebSocketConfig {
            path: Some("/x".into()),
            host: Some(String::new().into()),
            ..Default::default()
        };
        let req = ws_request(&cfg, "proxy.example.net").unwrap();
        assert_eq!(req.headers().get("host").unwrap(), "proxy.example.net");
    }

    #[test]
    fn fragment_in_path_is_sent_not_truncated() {
        let cfg = WebSocketConfig {
            path: Some("/x#frag".into()),
            ..Default::default()
        };
        let req = ws_request(&cfg, "proxy.example.net").unwrap();
        assert_eq!(req.uri().path_and_query().unwrap().as_str(), "/x%23frag");
    }

    #[test]
    fn host_defaults_to_server_host() {
        let cfg = WebSocketConfig {
            path: Some("/".into()),
            ..Default::default()
        };
        let req = ws_request(&cfg, "proxy.example.net").unwrap();
        assert_eq!(req.headers().get("host").unwrap(), "proxy.example.net");
        assert_eq!(req.uri().path(), "/");
    }
}
