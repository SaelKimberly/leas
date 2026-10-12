//! h2 transport ("v2rayhttp", sing-box `type: http`): a single HTTP/2
//! stream is the whole tunnel.
//!
//! The request body is the upload, the response body (200 required) the
//! download. Method defaults to PUT (v2fly-compatible); `:authority` = the
//! config `host` else `www.example.com`. ALPN `h2`. sing-box-only in modern
//! cores (xray-core removed the h2 transport in 26.x).
//!
//! h2-only: the sing-box no-TLS h1 arm is not reproducible with hyper (hyper
//! frames request bodies; sing-box's h1 server hijacks raw bytes) — deferred.
//!
//! Wire reference: `thirdparty/sing-box/transport/v2rayhttp/client.go`.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskCx, Poll};

use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};
use crate::transport::http::{IncomingReader, ReqBody, h2_client};

/// Write-side buffering cap before pushing into the upload pipe. The h2 DATA
/// frames flow continuously (no server-side chunk cap like xhttp packet-up);
/// this only bounds the local buffer while the pipe is wedged.
const MAX_PENDING: usize = 64 * 1024;

/// Normalize a path to start with `/`.
fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Resolve (method, authority, path) from the config — pure, unit-tested.
///
/// The v2rayhttp wire spec (sing-box `client.go` `dialHTTP2`): method
/// defaults to PUT; the `:authority` is the config `host`, else
/// `www.example.com`; the path is normalized to a leading `/`.
pub fn request_head(ctx: &LinkContext) -> Result<(String, String, String), NativeError> {
    let cfg = ctx
        .transport_http()
        .ok_or_else(|| NativeError::Config("http (v2rayhttp) transport config missing".into()))?;
    let method = cfg.method.as_deref().unwrap_or("PUT").to_string();
    let authority = cfg
        .host
        .as_deref()
        .map_or_else(|| "www.example.com".to_string(), str::to_string);
    let path = cfg
        .path
        .as_deref()
        .map_or_else(|| "/".to_string(), normalize_path);
    Ok((method, authority, path))
}

/// Run the v2rayhttp transport: h2 handshake, one full-duplex stream.
///
/// The request body (a live [`ReqBody::channel`] pipe) is the upload; the
/// 200 response body is the download. The h2 crate emits the `:authority`
/// pseudo-header only from the URI's authority component — a bare-path URI
/// plus a `host` header yields no pseudo-header, and sing-box's server
/// validates `request.Host` (the authority) against its host list — so the
/// authority goes in the URI, not a `host` header.
pub async fn connect(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let (method, authority, path) = request_head(ctx)?;
    let mut sender = h2_client(stream).await?;
    let (tx, body) = ReqBody::channel();

    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(&path)
        .build()
        .map_err(|e| NativeError::Config(format!("v2rayhttp uri build: {e}")))?;
    let req = http::Request::builder()
        .method(method.as_str())
        .uri(uri)
        .body(body)
        .map_err(|e| NativeError::Config(format!("v2rayhttp request build: {e}")))?;

    let limit = timeouts::TRANSPORT;
    let resp = tokio::time::timeout(limit, sender.send_request(req))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "v2rayhttp request",
            limit,
        })?
        .map_err(|e| NativeError::Transport(format!("v2rayhttp request: {e}")))?;
    if resp.status() != http::StatusCode::OK {
        return Err(NativeError::TransportRejected {
            detail: format!("v2rayhttp: expected 200, got {}", resp.status()),
            status: resp.status().as_u16(),
        });
    }
    let reader = IncomingReader::new(resp.into_body());

    let (wt, wrx) = mpsc::channel::<Bytes>(4);
    tokio::spawn(forward_pipe(tx, wrx));
    Ok(Box::new(V2rayStream::new(reader, wt)))
}

/// Forward tunnel writes into the request-body pipe.
///
/// `send_data` awaits pipe capacity (hyper drains it into h2 DATA frames),
/// so backpressure propagates without dropping bytes; `SendError` fires only
/// when the body is gone (stream reset) — the upload side is then broken.
async fn forward_pipe(
    mut pipe_tx: http_body_util::channel::Sender<Bytes>,
    mut wrx: mpsc::Receiver<Bytes>,
) {
    while let Some(b) = wrx.recv().await {
        if pipe_tx.send_data(b).await.is_err() {
            return;
        }
    }
}

/// An in-flight channel send (the channel was full when kicked) — a boxed
/// future keeps the type small.
type PendingSend = Pin<Box<dyn Future<Output = Result<(), ()>> + Send>>;

/// Full-duplex h2 stream: read side = the 200 response body (download);
/// write side = a buffered pipe into the request body (upload).
///
/// The write path mirrors [`crate::transport::xhttp::XhttpStream`]: accepted
/// bytes sit in `pending` until delivered — `poll_write` never returns
/// `WouldBlock` (the protocol write path treats it as fatal).
pub struct V2rayStream {
    reader: IncomingReader,
    tx: mpsc::Sender<Bytes>,
    /// Accepted-but-unsent bytes.
    pending: BytesMut,
    /// An in-flight channel send (the channel was full when kicked).
    flushing: Option<PendingSend>,
}

impl V2rayStream {
    #[must_use]
    pub fn new(reader: IncomingReader, tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            reader,
            tx,
            pending: BytesMut::new(),
            flushing: None,
        }
    }

    /// Push `pending` into the channel. Returns `false` when the forward
    /// task has gone (channel closed) — the write side is then broken.
    fn kick(&mut self) -> bool {
        if self.pending.is_empty() {
            return true;
        }
        let bytes = std::mem::take(&mut self.pending).freeze();
        match self.tx.try_send(bytes) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(bytes)) => {
                let tx = self.tx.clone();
                self.flushing = Some(Box::pin(
                    async move { tx.send(bytes).await.map_err(|_| ()) },
                ));
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Drive the in-flight send to completion. `Pending` = the channel is
    /// still full — the caller must not accept more bytes.
    fn poll_flushing(&mut self, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        while let Some(fut) = self.flushing.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => self.flushing = None,
                Poll::Ready(Err(())) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "v2rayhttp upload pipe closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncRead for V2rayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for V2rayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Backpressure: an in-flight channel send must complete before we
        // accept more bytes (Pending = nothing consumed, per the AsyncWrite
        // contract — the protocol retries the write).
        match self.poll_flushing(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let take = buf
            .len()
            .min(MAX_PENDING.saturating_sub(self.pending.len()));
        self.pending.extend_from_slice(&buf[..take]);
        // Deliver on every write: `AsyncWriteExt::write_all` never calls
        // `poll_flush`, so flush-only delivery would strand bytes (ws.rs
        // and xhttp.rs mirror this write-through choice).
        if !self.kick() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "v2rayhttp upload pipe closed",
            )));
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        if !self.kick() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "v2rayhttp upload pipe closed",
            )));
        }
        self.poll_flushing(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        // Flush the tail; dropping the stream then closes the channel (the
        // forward task exits, the request body ends, and hyper sends
        // END_STREAM — the upload half-close).
        if !self.kick() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "v2rayhttp upload pipe closed",
            )));
        }
        self.poll_flushing(cx)
    }
}

#[cfg(test)]
mod tests {
    use leas_proto::proto_spec::ProtocolConfig;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;

    use crate::addr::{Host, TargetAddr};
    use crate::context::{LinkContext, NativeConnectParams};
    use crate::transport::v2rayhttp::request_head;

    fn vless_http(method: Option<&str>, host: Option<&str>) -> ProtocolConfig {
        serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": {
                "type": "http",
                "path": "/h2",
                "host": host,
                "method": method
            }
        }))
        .expect("config parses")
    }

    fn ctx_at(addr: std::net::SocketAddr, cfg: ProtocolConfig) -> LinkContext {
        LinkContext::new(
            NativeConnectParams::new(
                cfg,
                EndpointEssentials::new(addr.ip().to_string(), addr.port()),
                TargetAddr::new(Host::Domain("dest.test".into()), 80),
            ),
            TargetAddr::new(Host::Domain("dest.test".into()), 80),
        )
    }

    #[test]
    fn method_defaults_to_put_and_authority_defaults_to_www_example_com() {
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ctx = ctx_at(addr, vless_http(None, None));
        let (method, authority, path) = request_head(&ctx).unwrap();
        assert_eq!(method, "PUT");
        assert_eq!(authority, "www.example.com");
        assert_eq!(path, "/h2");
    }

    #[test]
    fn method_and_host_override() {
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ctx = ctx_at(addr, vless_http(Some("POST"), Some("cdn.example")));
        let (method, authority, path) = request_head(&ctx).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(authority, "cdn.example");
        assert_eq!(path, "/h2");
    }

    #[test]
    fn path_normalizes_leading_slash() {
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let cfg = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "http", "path": "h2" }
        }))
        .unwrap();
        let ctx = ctx_at(addr, cfg);
        let (_, _, path) = request_head(&ctx).unwrap();
        assert_eq!(path, "/h2");
    }
}
