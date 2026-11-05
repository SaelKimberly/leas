//! WebSocket transport: RFC 6455 framing (tokio-tungstenite) over an
//! established stream — the engine TLS/REALITY session or raw TCP. The
//! transport never owns TLS; it consumes `AsyncRead + AsyncWrite`.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Context as TaskCx, Poll};

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
    let path = cfg.path.as_deref().unwrap_or("/");
    let host = cfg.host.as_deref().unwrap_or(server_host);
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
/// frame, and echoes the same header back; we send them as the first binary
/// frame, which is equivalent on the wire (the server accepts both — see
/// `hub.go:55-59`).
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
    /// Bytes captured from the caller's first write, sent as the first frame
    /// once the upgrade lands.
    early: Vec<u8>,
    early_pos: usize,
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
            early_pos: 0,
            max_early,
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
            if let Some(fut) = this.upgrading.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(ws)) => this.ws = Some(WsStream::new(ws)),
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(io::Error::other(e.to_string())));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            return Poll::Pending;
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
                // the upgrade with them in the header.
                let take = data.len().min(this.max_early.max(1));
                this.early.extend_from_slice(&data[..take]);
                let Some(stream) = this.stream.take() else {
                    return Poll::Ready(Err(io::Error::other("ws early-data: no stream")));
                };
                let req = match early_data_request(&this.cfg, &this.host, &this.early) {
                    Ok(req) => req,
                    Err(e) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
                };
                this.upgrading = Some(Box::pin(upgrade_with(req, stream, "ws")));
                return Poll::Pending;
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
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        // Send the early bytes as the first frame, then the caller's.
        while this.early_pos < this.early.len() {
            let ws = this.ws.as_mut().expect("checked above");
            let remaining = &this.early[this.early_pos..];
            match Pin::new(ws).poll_write(cx, remaining) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => this.early_pos += n,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }
        }
        let ws = this.ws.as_mut().expect("checked above");
        match Pin::new(ws).poll_write(cx, data) {
            Poll::Ready(Ok(n)) => {
                let early_len = this.early.len();
                Poll::Ready(Ok(n.max(early_len.min(data.len()))))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ws
            .as_mut()
            .map_or(Poll::Ready(Ok(())), |ws| Pin::new(ws).poll_flush(cx))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ws
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
