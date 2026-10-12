//! XHTTP transport (xray-core `splithttp`, v3 dialect — NO PDU framing, NO
//! X-TP-* headers).
//!
//! Session correlated by a uuid v4 in the URL path; download = a long-lived
//! GET response body; uploads = discrete POSTs of raw body bytes with a
//! decimal `seq` in the path. `auto`/default mode = packet-up.
//!
//! Wire reference: `thirdparty/Xray-core/transport/internet/splithttp/`
//! (dialer.go, client.go, config.go) — byte-identical to mihomo's xhttp
//! client.

use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskCx, Poll, ready};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use http::StatusCode;
use http::header::HOST;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::BoxStream;
use crate::context::{LinkContext, split_alpn};
use crate::error::{NativeError, timeouts};
use leas_proto::proto_spec::{SecurityConfig, TlsConfig};

use crate::transport::http::{IncomingReader, ReqBody, h1_client, h2_client};

/// packet-up chunk size (bytes) — xray default `scMaxEachPostBytes`.
const MAX_POST_BYTES: usize = 1_000_000;
/// minimum time between upload POSTs (ms) — xray default `scMinPostsIntervalMs`.
const POST_INTERVAL: Duration = Duration::from_millis(30);
/// `x_padding` length range (xray default `xPaddingBytes` 100..1000).
const PAD_MIN: usize = 100;
const PAD_MAX: usize = 1000;
/// Static `x_padding` alphabet: 1000 `X` characters (X/Z are 8-bit HPACK
/// huffman codes, so byte length == HPACK length — valid under every server
/// validation path, incl. the tokenish huffman-length check). Slicing this
/// per request replaces the per-request `"X".repeat(len)` allocation.
static X_PAD: [u8; PAD_MAX] = [b'X'; PAD_MAX];

/// Random `x_padding` value: a 100–1000 `X` slice of the static [`X_PAD`].
fn x_padding() -> &'static str {
    let mut buf = [0u8; 2];
    SystemRandom::new()
        .fill(&mut buf)
        .expect("ring CSPRNG fills");
    // `PAD_MAX - PAD_MIN + 1` keeps the inclusive [100, 1000] range (xray's
    // RangeConfig rand is inclusive).
    let len = PAD_MIN + usize::from(u16::from_be_bytes(buf)) % (PAD_MAX - PAD_MIN + 1);
    std::str::from_utf8(&X_PAD[..len]).expect("static pad is ASCII X")
}

/// Normalize a path to start with `/` and ensure a trailing `/` before
/// appending session/seq (xray `appendToPath`).
fn normalize_path(path: &str) -> String {
    let p = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if p.ends_with('/') { p } else { format!("{p}/") }
}

/// URL-safe session id (uuid v4).
fn session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Host for the HTTP requests: config `host` > endpoint host.
fn http_host(ctx: &LinkContext) -> String {
    ctx.transport_xhttp()
        .and_then(|c| c.host.as_deref())
        .map_or_else(|| ctx.params.server.host.clone(), str::to_string)
}

/// Base path without session (trailing slash).
fn base_path(ctx: &LinkContext) -> String {
    normalize_path(
        ctx.transport_xhttp()
            .and_then(|c| c.path.as_deref())
            .unwrap_or("/"),
    )
}

/// Path with optional session and seq appended (xray `appendToPath`).
fn path_with(ctx: &LinkContext, session: &str, seq: Option<&str>) -> String {
    let base = base_path(ctx);
    let mut p = format!("{base}{session}");
    if let Some(seq) = seq {
        p = format!("{p}/{seq}");
    }
    p
}

/// HTTP version for xhttp per xray `decideHTTPVersion` (spec §4.1) — a pure
/// mirror of the Go decision over the proto security config:
///
/// | condition | version |
/// |---|---|
/// | reality config present | `"2"` |
/// | no TLS config | `"1.1"` |
/// | TLS, exactly one ALPN `"http/1.1"` | `"1.1"` |
/// | TLS, exactly one ALPN `"h3"` | `"3"` (the QUIC path) |
/// | TLS, exactly one other ALPN | `"2"` |
/// | TLS, zero or 2+ ALPNs | `"2"` |
///
/// ALPN is the comma-separated `TlsOpts::alpn` string, split by the shared
/// [`crate::context::split_alpn`] (the one set of split rules the engine's
/// ALPN list uses too — they cannot drift).
#[must_use]
pub(crate) fn http_version(security: Option<&SecurityConfig>) -> &'static str {
    let Some(sec) = security else {
        return "1.1";
    };
    let alpn = match &sec.tls {
        None => return "1.1",
        Some(TlsConfig::Reality(_)) => return "2",
        Some(TlsConfig::Tls(opts)) => match &opts.alpn {
            Some(s) => s.as_str(),
            None => return "2",
        },
    };
    let mut protocols = split_alpn(alpn).into_iter();
    let Some(first) = protocols.next() else {
        return "2";
    };
    if protocols.next().is_some() {
        return "2";
    }
    match first {
        "http/1.1" => "1.1",
        "h3" => "3",
        _ => "2",
    }
}

/// Build a request with Host + config headers + Referer padding (shared by
/// the h1/h2 hyper arm and the h3 arm — the body is unit; callers map in
/// their transport's body type).
fn build_request(
    ctx: &LinkContext,
    method: &str,
    url_path: &str,
    host: &str,
) -> Result<http::Request<()>, NativeError> {
    let padding = x_padding();
    // xray captures `RawURL` *before* appending session/seq, so the Referer
    // carries the base URL (`{scheme}://{host}{path}`), not the session path.
    // One allocation for the whole value (`write!`, not chained `format!`).
    let scheme = if ctx.is_tls() { "https" } else { "http" };
    let mut referer_value = String::with_capacity(32 + host.len() + url_path.len());
    write!(
        referer_value,
        "{scheme}://{host}{}?x_padding={padding}",
        base_path(ctx)
    )
    .expect("write! to String cannot fail");
    let mut builder = http::Request::builder()
        .method(method)
        .uri(url_path)
        .header(HOST, host)
        .header("Referer", referer_value);
    if let Some(headers) = ctx.transport_xhttp().and_then(|c| c.headers.as_ref()) {
        for (k, v) in headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
    }
    builder
        .body(())
        .map_err(|e| NativeError::Config(format!("xhttp request build: {e}")))
}

/// Request body for the v3 protocol (transport-agnostic). The hyper arms
/// map it onto `ReqBody`; the h3 arm onto the request stream's send half.
enum V3Body {
    Empty,
    Full(Bytes),
    /// Stream-up: the upload body is a pipe fed by the tunnel writer
    /// (`wrx`); the seam forwards into the transport's body mechanism.
    Pipe(mpsc::Receiver<Bytes>),
    /// Stream-one: the single full-duplex request's body is a pipe fed by
    /// the tunnel writer, and the RESPONSE body becomes the tunnel's read
    /// side (no drain — unlike stream-up there is no separate GET).
    PipeFull(mpsc::Receiver<Bytes>),
}

/// A v3 response: status + the response body as an `AsyncRead`. For POSTs
/// the seam has already started draining the actual body (keepalive
/// X-blobs — xray hub.go) and the reader here is empty; GETs carry the
/// download body.
struct V3Response {
    status: StatusCode,
    reader: Box<dyn AsyncRead + Send + Unpin>,
}
trait V3Send {
    fn send_one(
        &mut self,
        req: http::Request<V3Body>,
        step: &'static str,
    ) -> impl Future<Output = Result<V3Response, NativeError>> + Send;
}

/// Drain a hyper response body to completion in a spawned task: the
/// stream-up server streams keepalive X-blobs into the upload response when
/// a Referer is present (xray hub.go) — the drain keeps the h1/h2 window
/// from stalling, so it must run concurrently with the tunnel.
fn drain_incoming(reader: IncomingReader) {
    tokio::spawn(async move {
        let mut reader = reader;
        if let Err(e) = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await {
            tracing::debug!(error = %e, "xhttp: drain failed on body read");
        }
    });
}

/// Forward tunnel writes into the stream-up upload pipe.
///
/// `send_data` awaits pipe capacity (hyper drains it into h1/h2 DATA
/// frames), so backpressure propagates without dropping bytes; `SendError`
/// fires only when the body is gone (stream reset) — the upload side is
/// then broken.
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

impl V3Send for hyper::client::conn::http1::SendRequest<ReqBody> {
    async fn send_one(
        &mut self,
        req: http::Request<V3Body>,
        step: &'static str,
    ) -> Result<V3Response, NativeError> {
        let (parts, body) = req.into_parts();
        let (pipe_rx, body) = match body {
            V3Body::Empty => (None, ReqBody::Empty),
            V3Body::Full(b) => (None, ReqBody::Full(b)),
            V3Body::Pipe(rx) => {
                let (tx, body) = ReqBody::channel();
                (Some((tx, rx, false)), body)
            }
            V3Body::PipeFull(rx) => {
                let (tx, body) = ReqBody::channel();
                (Some((tx, rx, true)), body)
            }
        };
        let req = http::Request::from_parts(parts, body);
        let resp = self
            .send_request(req)
            .await
            .map_err(|e| NativeError::Transport(format!("{step}: {e}")))?;
        let status = resp.status();
        let reader: Box<dyn AsyncRead + Send + Unpin> = match pipe_rx {
            Some((tx, rx, full)) => {
                tokio::spawn(forward_pipe(tx, rx));
                if full {
                    // Stream-one: the response body IS the tunnel's read
                    // side (no separate GET — dialer.go:453-458).
                    Box::new(IncomingReader::new(resp.into_body()))
                } else {
                    // The stream-up server 200s the POST immediately and
                    // streams keepalive X-blobs into the response (xray
                    // hub.go) — drain concurrently so the h1/h2 window
                    // doesn't stall.
                    drain_incoming(IncomingReader::new(resp.into_body()));
                    Box::new(tokio::io::empty())
                }
            }
            None => Box::new(IncomingReader::new(resp.into_body())),
        };
        Ok(V3Response { status, reader })
    }
}

impl V3Send for hyper::client::conn::http2::SendRequest<ReqBody> {
    async fn send_one(
        &mut self,
        req: http::Request<V3Body>,
        step: &'static str,
    ) -> Result<V3Response, NativeError> {
        let (parts, body) = req.into_parts();
        let (pipe_rx, body) = match body {
            V3Body::Empty => (None, ReqBody::Empty),
            V3Body::Full(b) => (None, ReqBody::Full(b)),
            V3Body::Pipe(rx) => {
                let (tx, body) = ReqBody::channel();
                (Some((tx, rx, false)), body)
            }
            V3Body::PipeFull(rx) => {
                let (tx, body) = ReqBody::channel();
                (Some((tx, rx, true)), body)
            }
        };
        let req = http::Request::from_parts(parts, body);
        let resp = self
            .send_request(req)
            .await
            .map_err(|e| NativeError::Transport(format!("{step}: {e}")))?;
        let status = resp.status();
        let reader: Box<dyn AsyncRead + Send + Unpin> = match pipe_rx {
            Some((tx, rx, full)) => {
                tokio::spawn(forward_pipe(tx, rx));
                if full {
                    // Stream-one: the response body IS the tunnel's read
                    // side (no separate GET — dialer.go:453-458).
                    Box::new(IncomingReader::new(resp.into_body()))
                } else {
                    drain_incoming(IncomingReader::new(resp.into_body()));
                    Box::new(tokio::io::empty())
                }
            }
            None => Box::new(IncomingReader::new(resp.into_body())),
        };
        Ok(V3Response { status, reader })
    }
}

/// Drain an h3 response body to completion in a spawned task: the stream-up
/// server streams keepalive X-blobs into the upload response (xray hub.go)
/// — Go's client does `io.Copy(io.Discard, resp.Body)`; the drain must run
/// concurrently with the tunnel.
fn drain_h3<S>(stream: h3::client::RequestStream<S, Bytes>)
where
    S: h3::quic::RecvStream + Send + 'static,
{
    tokio::spawn(async move {
        let mut stream = stream;
        while let Ok(Some(_)) = stream.recv_data().await {}
    });
}

/// Forward tunnel writes into the stream-up h3 upload pipe: each channel
/// item becomes a request-body DATA chunk; the body ends on channel close.
async fn forward_pipe_h3(
    mut send: h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
    mut wrx: mpsc::Receiver<Bytes>,
) {
    while let Some(b) = wrx.recv().await {
        if send.send_data(b).await.is_err() {
            return;
        }
    }
    let _ = send.finish().await;
}

/// The h3 request seam: one h3 request per call, over the shared QUIC
/// connection (h3 multiplexes bidirectional streams like h2).
impl V3Send for h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> {
    async fn send_one(
        &mut self,
        req: http::Request<V3Body>,
        step: &'static str,
    ) -> Result<V3Response, NativeError> {
        let (mut parts, body) = req.into_parts();
        // RFC 9114 §4.3.1: requests MUST carry `:scheme` + `:authority`.
        // The shared builder emits a path-only URI + Host header (correct
        // for h1/h2, where the engine sends Host separately) — but the h3
        // crate only translates URI scheme/authority into pseudo-headers,
        // so without this rewrite the request reaches quic-go's server
        // missing both and dies with H3_MESSAGE_ERROR (headers.go:
        // `hdr.Scheme == "" || hdr.Authority == ""`). h3 is always TLS.
        let Some(host) = parts
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
        else {
            return Err(NativeError::Transport(format!(
                "{step}: h3 absolute URI rewrite requires Host header"
            )));
        };
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        parts.uri = format!("https://{host}{path}")
            .parse()
            .map_err(|e| NativeError::Transport(format!("{step}: absolute h3 uri: {e}")))?;
        let req = http::Request::from_parts(parts, ());
        let err = |e: h3::error::StreamError| NativeError::Transport(format!("{step}: {e}"));
        let mut stream = self.send_request(req).await.map_err(err)?;
        match body {
            V3Body::Empty => {
                stream.finish().await.map_err(err)?;
                let resp = stream.recv_response().await.map_err(err)?;
                let status = resp.status();
                Ok(V3Response {
                    status,
                    reader: Box::new(H3Reader::new(stream)),
                })
            }
            V3Body::Full(payload) => {
                stream.send_data(payload).await.map_err(err)?;
                stream.finish().await.map_err(err)?;
                let resp = stream.recv_response().await.map_err(err)?;
                let status = resp.status();
                drain_h3(stream);
                Ok(V3Response {
                    status,
                    reader: Box::new(tokio::io::empty()),
                })
            }
            V3Body::Pipe(rx) => {
                let (send, mut recv) = stream.split();
                let resp = recv.recv_response().await.map_err(err)?;
                let status = resp.status();
                // The forward task outlives this call: it must keep a
                // `SendRequest` clone so the h3 connection stays open for
                // the tunnel's lifetime (dropping the last clone closes it
                // with H3_NO_ERROR).
                let keepalive = self.clone();
                tokio::spawn(async move {
                    let _keepalive = keepalive;
                    forward_pipe_h3(send, rx).await;
                });
                drain_h3(recv);
                Ok(V3Response {
                    status,
                    reader: Box::new(tokio::io::empty()),
                })
            }
            V3Body::PipeFull(rx) => {
                let (send, mut recv) = stream.split();
                let resp = recv.recv_response().await.map_err(err)?;
                let status = resp.status();
                // Stream-one: the response body is the tunnel's read side —
                // the forward task holds the send half + a `SendRequest`
                // clone so the h3 connection outlives this call.
                let keepalive = self.clone();
                tokio::spawn(async move {
                    let _keepalive = keepalive;
                    forward_pipe_h3(send, rx).await;
                });
                Ok(V3Response {
                    status,
                    reader: Box::new(H3Reader::new(recv)),
                })
            }
        }
    }
}

/// `AsyncRead` over an h3 response body: `recv_data` yields `Bytes` chunks
/// (h3-quinn's read-chunk adapter), copied into the pending buffer. `S` is
/// the recv-stream half: the full `BidiStream` (GET arm) or the split
/// `RecvStream` (stream-one arm).
struct H3Reader<S> {
    stream: Option<h3::client::RequestStream<S, Bytes>>,
    buf: Bytes,
}

impl<S: h3::quic::RecvStream> H3Reader<S> {
    const fn new(stream: h3::client::RequestStream<S, Bytes>) -> Self {
        Self {
            stream: Some(stream),
            buf: Bytes::new(),
        }
    }
}

impl<S: h3::quic::RecvStream> AsyncRead for H3Reader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.buf.is_empty() {
                let n = self.buf.len().min(buf.remaining());
                buf.put_slice(&self.buf[..n]);
                self.buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            let Some(stream) = self.stream.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match ready!(stream.poll_recv_data(cx)) {
                Ok(Some(mut data)) => {
                    self.buf = data.copy_to_bytes(data.remaining());
                }
                Ok(None) => {
                    self.stream = None;
                    return Poll::Ready(Ok(()));
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("xhttp h3 download: {e:?}"),
                    )));
                }
            }
        }
    }
}

/// Send a request, require 200, return the response.
async fn send_200<S: V3Send>(
    sender: &mut S,
    req: http::Request<V3Body>,
    step: &'static str,
) -> Result<V3Response, NativeError> {
    let limit = timeouts::TRANSPORT;
    let resp = tokio::time::timeout(limit, sender.send_one(req, step))
        .await
        .map_err(|_| NativeError::Timeout { step, limit })??;
    if resp.status != StatusCode::OK {
        return Err(NativeError::TransportRejected {
            detail: format!("{step}: expected 200, got {}", resp.status),
            status: resp.status.as_u16(),
        });
    }
    Ok(resp)
}

/// Send ONE packet-up POST: path `/x/{session}/{seq}`, raw body, 200
/// required. Shared by the h1, h2 and h3 upload tasks (the sender type is
/// the only difference).
async fn post_packet<S: V3Send>(
    sender: &mut S,
    ctx: &LinkContext,
    host: &str,
    url_path: &str,
    payload: Bytes,
) -> Result<(), NativeError> {
    let req = build_request(ctx, "POST", url_path, host)?.map(|()| V3Body::Full(payload));
    let _resp = send_200(sender, req, "xhttp upload").await?;
    Ok(())
}

/// Shared packet-up pacing/batching core. Drains `rx`, accumulates app
/// bytes, and POSTs chunks (≤ [`MAX_POST_BYTES`], ≥ [`POST_INTERVAL`] apart,
/// one in flight, via [`post_packet`]) in seq order. The h1/h2/h3 upload
/// tasks are thin wrappers over this core — they differ only in the sender
/// type.
async fn upload_loop_core<S: V3Send>(
    sender: &mut S,
    ctx: &LinkContext,
    session: &str,
    host: &str,
    mut rx: mpsc::Receiver<Bytes>,
) {
    let mut chunk = BytesMut::new();
    let mut seq: u64 = 0;
    let mut last = Instant::now();
    // The session-base path (`/x/{session}`) is built ONCE: every POST only
    // re-appends `/{seq}` into this buffer (`clear` + `write!`, no `format!`
    // and no `base_path` re-parse per request).
    let session_base = path_with(ctx, session, None);
    let mut url_path = String::with_capacity(session_base.len() + 20);
    loop {
        // Idle window: flush partial chunks on the timeout, or keep
        // accumulating until the size cap (xray `time.Sleep` before each
        // POST + `WithSizeLimit` batching).
        let mut closed = false;
        let mut filled = false;
        match tokio::time::timeout(POST_INTERVAL, rx.recv()).await {
            Ok(Some(data)) => {
                filled = true;
                chunk.extend_from_slice(&data);
            }
            Ok(None) => closed = true,
            Err(_) => {}
        }
        if filled && chunk.len() < MAX_POST_BYTES {
            continue;
        }
        if chunk.is_empty() {
            // Channel closed with nothing pending — done.
            if closed {
                break;
            }
            continue;
        }
        // Split at the size cap (xray `buf.SplitSize`): a single channel
        // item may push the accumulated chunk past `MAX_POST_BYTES`, and the
        // server 413s anything over `scMaxEachPostBytes`.
        loop {
            // The first POST is exempt from pacing: the 30 ms idle window
            // before it already spaced it from the GET.
            if seq > 0 {
                let since = last.elapsed();
                if since < POST_INTERVAL {
                    tokio::time::sleep(POST_INTERVAL.saturating_sub(since)).await;
                }
            }
            last = Instant::now();
            let take = chunk.len().min(MAX_POST_BYTES);
            let payload = chunk.split_to(take).freeze();
            url_path.clear();
            write!(url_path, "{session_base}/{seq}").expect("write! to String cannot fail");
            if post_packet(sender, ctx, host, &url_path, payload)
                .await
                .is_err()
            {
                return;
            }
            seq += 1;
            if chunk.is_empty() {
                break;
            }
        }
        if closed {
            // Channel closed: the final chunk was flushed above — stop.
            break;
        }
    }
}

/// packet-up uploads over the HTTP/1.1 POST connection (a second raw dial).
async fn upload_loop_h1(
    mut sender: hyper::client::conn::http1::SendRequest<ReqBody>,
    ctx: LinkContext,
    session: String,
    host: String,
    rx: mpsc::Receiver<Bytes>,
) {
    upload_loop_core(&mut sender, &ctx, &session, &host, rx).await;
}

/// packet-up uploads over the shared HTTP/2 connection (same conn as GET).
async fn upload_loop_h2(
    mut sender: hyper::client::conn::http2::SendRequest<ReqBody>,
    ctx: LinkContext,
    session: String,
    host: String,
    rx: mpsc::Receiver<Bytes>,
) {
    upload_loop_core(&mut sender, &ctx, &session, &host, rx).await;
}

/// packet-up uploads over the shared HTTP/3 connection (same QUIC conn as
/// the GET — h3 multiplexes streams like h2).
async fn upload_loop_h3(
    mut sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    ctx: LinkContext,
    session: String,
    host: String,
    rx: mpsc::Receiver<Bytes>,
) {
    upload_loop_core(&mut sender, &ctx, &session, &host, rx).await;
}

/// True when the security config is REALITY — the presence the
/// `http_version()` rule and xray's mode auto-selection read
/// (`realityConfig != nil`). Reuses the [`SecurityConfig`] accessors
/// `http_version()` already walks.
fn is_reality(ctx: &LinkContext) -> bool {
    matches!(
        ctx.security().and_then(|s| s.tls.as_ref()),
        Some(TlsConfig::Reality(_))
    )
}

/// True when the xhttp config carries a separate download dial — xray
/// `Config.DownloadSettings` (JSON `downloadSettings`, config.pb.go:175).
/// The native proto has no typed field (share links carry it in the raw
/// `extra` blob); the mode rule honors it for decision parity only (spec
/// §7.2 — the actual second dial is out of scope).
fn has_download_settings(ctx: &LinkContext) -> bool {
    ctx.transport_xhttp()
        .and_then(|c| c.extra.as_ref())
        .is_some_and(|v| v.get("downloadSettings").is_some())
}

/// The client-side xhttp dialect (config `mode`) — xray `dialer.go` mode
/// selection (spec §4.1): explicit modes honored; `auto`/empty →
/// packet-up (no reality) or stream-one (reality present), stream-up when
/// a download dial is also configured. Shared by the h1/h2 [`connect`]
/// dispatch and the h3 arm.
fn xhttp_mode(ctx: &LinkContext) -> Result<&'static str, NativeError> {
    let mode = ctx
        .transport_xhttp()
        .and_then(|c| c.mode.as_deref())
        .unwrap_or("auto");
    match mode {
        "packet-up" => Ok("packet-up"),
        "stream-up" => Ok("stream-up"),
        "stream-one" => Ok("stream-one"),
        "auto" | "" => {
            if is_reality(ctx) {
                Ok(if has_download_settings(ctx) {
                    "stream-up"
                } else {
                    "stream-one"
                })
            } else {
                Ok("packet-up")
            }
        }
        other => Err(NativeError::Config(format!("unknown xhttp mode: {other}"))),
    }
}

/// Run the XHTTP transport over the established (secured) stream.
///
/// The client-side mode (config `mode`) selects the dialect per
/// [`xhttp_mode`] (spec §4.1): `packet-up`, `stream-up`, `stream-one`
/// (legacy XHTTP v1 — a single full-duplex request, no session id), and
/// the `auto`/empty rules. HTTP version matches xray `decideHTTPVersion`:
/// no TLS → HTTP/1.1 (GET on the primary stream, POSTs on a second raw TCP
/// dial — Go h1 serializes responses in request order, so a long-lived GET
/// body would block POST responses on its own conn); TLS → HTTP/2 (one conn,
/// multiplexed streams). The h3 mode is NOT reached here: it is a different
/// dial ([`connect_quic`]) that replaces this upgrade step (spec §5.2).
pub async fn connect(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    match xhttp_mode(ctx)? {
        "stream-one" => {
            if ctx.is_tls() {
                stream_one_h2(ctx, stream).await
            } else {
                stream_one_h1(ctx, stream).await
            }
        }
        "stream-up" => {
            if ctx.is_tls() {
                stream_up_h2(ctx, stream).await
            } else {
                stream_up_h1(ctx, stream).await
            }
        }
        _ => {
            if ctx.is_tls() {
                packet_up_h2(ctx, stream).await
            } else {
                packet_up_h1(ctx, stream).await
            }
        }
    }
}

/// The HTTP/3 arm (xhttp + [`http_version`] == `"3"` → QUIC dial).
///
/// A quinn Endpoint over UDP with ALPN `h3`, replacing the dial + security +
/// upgrade chain (spec §5.2 — quinn's TLS is internal; the engine TLS never
/// wraps QUIC). The splithttp v3 protocol then runs over the h3 connection
/// (same session/GET/POST logic as the h1/h2 arms, via the [`V3Send`] seam).
/// 0-RTT: quinn early data is enabled; a fresh connection has no session
/// ticket and does the full handshake (xray `DialEarly` without a ticket —
/// spec §8.3).
pub async fn connect_quic(ctx: &LinkContext) -> Result<BoxStream, NativeError> {
    let mode = xhttp_mode(ctx)?;
    let server_addr = ctx.server_socket().await?;
    let endpoint = crate::transport::quic::client_endpoint(server_addr);
    let tls = crate::transport::quic::quic_tls_config(ctx, b"h3")?;
    let quic_config = crate::transport::quic::quinn_client_config(tls);
    let conn = crate::transport::quic::connect(
        &endpoint,
        quic_config,
        server_addr,
        &ctx.server_name(),
        "xhttp h3",
    )
    .await?;

    // The h3 connection driver owns the endpoint + quinn connection: it
    // polls the connection-level state (control frames, settings) and lives
    // exactly as long as the tunnel — when the last `SendRequest` clone
    // drops, the connection closes with H3_NO_ERROR, `poll_close` resolves,
    // and the endpoint goes with it.
    let h3_quic = h3_quinn::Connection::new(conn);
    let (mut h3_conn, send_request) = {
        let limit = timeouts::TRANSPORT;
        tokio::time::timeout(limit, h3::client::new(h3_quic))
            .await
            .map_err(|_| NativeError::Timeout {
                step: "xhttp h3 open",
                limit,
            })?
            .map_err(|e| NativeError::Transport(format!("xhttp h3 open: {e}")))?
    };
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
        drop(endpoint);
    });

    match mode {
        "packet-up" => packet_up_h3(ctx, send_request).await,
        "stream-one" => stream_one_h3(ctx, send_request).await,
        _ => stream_up_h3(ctx, send_request).await,
    }
}

/// packet-up over HTTP/1.1 (no TLS): GET on the primary stream, upload POSTs
/// on a second raw TCP dial.
async fn packet_up_h1(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let host = http_host(ctx);
    let session = session_id();
    let get_path = path_with(ctx, &session, None);
    let mut get_sender = h1_client(stream).await?;
    let get_req = build_request(ctx, "GET", &get_path, &host)?.map(|()| V3Body::Empty);
    let resp = send_200(&mut get_sender, get_req, "xhttp download GET").await?;
    let reader = resp.reader;

    // Second raw TCP dial for uploads.
    let post_stream = crate::transport::tcp::connect(ctx, None).await?;
    let post_sender = h1_client(post_stream).await?;

    let (tx, rx) = mpsc::channel::<Bytes>(16);
    let ctx = ctx.clone();
    let session_owned = session.clone();
    let host_owned = host.clone();
    tokio::spawn(upload_loop_h1(
        post_sender,
        ctx,
        session_owned,
        host_owned,
        rx,
    ));
    Ok(Box::new(XhttpStream::new(reader, tx)))
}

/// packet-up over HTTP/2 (TLS): one conn, GET stream + POST streams.
async fn packet_up_h2(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let host = http_host(ctx);
    let session = session_id();
    let get_path = path_with(ctx, &session, None);
    let mut sender = h2_client(stream).await?;
    let get_req = build_request(ctx, "GET", &get_path, &host)?.map(|()| V3Body::Empty);
    let resp = send_200(&mut sender, get_req, "xhttp download GET").await?;
    let reader = resp.reader;

    let (tx, rx) = mpsc::channel::<Bytes>(16);
    let ctx = ctx.clone();
    let session_owned = session.clone();
    let host_owned = host.clone();
    tokio::spawn(upload_loop_h2(sender, ctx, session_owned, host_owned, rx));
    Ok(Box::new(XhttpStream::new(reader, tx)))
}

/// packet-up over HTTP/3: one QUIC conn, GET stream + POST streams (h3
/// multiplexes like h2 — the upload task reuses the same [`V3Send`] loop).
async fn packet_up_h3(
    ctx: &LinkContext,
    mut sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
) -> Result<BoxStream, NativeError> {
    let host = http_host(ctx);
    let session = session_id();
    let get_path = path_with(ctx, &session, None);
    let get_req = build_request(ctx, "GET", &get_path, &host)?.map(|()| V3Body::Empty);
    let resp = send_200(&mut sender, get_req, "xhttp h3 download GET").await?;
    let reader = resp.reader;

    let (tx, rx) = mpsc::channel::<Bytes>(16);
    let ctx = ctx.clone();
    let session_owned = session.clone();
    let host_owned = host.clone();
    tokio::spawn(upload_loop_h3(sender, ctx, session_owned, host_owned, rx));
    Ok(Box::new(XhttpStream::new(reader, tx)))
}

/// stream-up: GET (download) + one long-lived POST (upload, pipe body,
/// `Content-Type: application/grpc`) on a second raw TCP dial. The server
/// 200s the POST immediately and streams keepalive X-blobs into the response
/// (drained by the seam).
async fn stream_up_h1(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let host = http_host(ctx);
    let session = session_id();
    let url = path_with(ctx, &session, None);
    let mut get_sender = h1_client(stream).await?;
    let get_req = build_request(ctx, "GET", &url, &host)?.map(|()| V3Body::Empty);
    let resp = send_200(&mut get_sender, get_req, "xhttp stream-up GET").await?;
    let reader = resp.reader;

    let post_stream = crate::transport::tcp::connect(ctx, None).await?;
    let mut post_sender = h1_client(post_stream).await?;
    let (wt, wrx) = mpsc::channel::<Bytes>(16);
    let mut req = build_request(ctx, "POST", &url, &host)?.map(|()| V3Body::Pipe(wrx));
    req.headers_mut().insert(
        "Content-Type",
        http::HeaderValue::from_static("application/grpc"),
    );
    let _resp = send_200(&mut post_sender, req, "xhttp stream-up POST").await?;
    Ok(Box::new(XhttpStream::new(reader, wt)))
}

/// stream-up over h2 (TLS): GET + POST streams on one h2 conn.
async fn stream_up_h2(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let host = http_host(ctx);
    let session = session_id();
    let url = path_with(ctx, &session, None);
    let mut sender = h2_client(stream).await?;
    let get_req = build_request(ctx, "GET", &url, &host)?.map(|()| V3Body::Empty);
    let resp = send_200(&mut sender, get_req, "xhttp stream-up GET").await?;
    let reader = resp.reader;

    let (wt, wrx) = mpsc::channel::<Bytes>(16);
    let mut req = build_request(ctx, "POST", &url, &host)?.map(|()| V3Body::Pipe(wrx));
    req.headers_mut().insert(
        "Content-Type",
        http::HeaderValue::from_static("application/grpc"),
    );
    let _resp = send_200(&mut sender, req, "xhttp stream-up POST").await?;
    Ok(Box::new(XhttpStream::new(reader, wt)))
}

/// stream-up over h3: GET + POST streams on the one QUIC conn (the pipe
/// body maps onto the h3 request stream's send half).
async fn stream_up_h3(
    ctx: &LinkContext,
    mut sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
) -> Result<BoxStream, NativeError> {
    let host = http_host(ctx);
    let session = session_id();
    let url = path_with(ctx, &session, None);
    let get_req = build_request(ctx, "GET", &url, &host)?.map(|()| V3Body::Empty);
    let resp = send_200(&mut sender, get_req, "xhttp h3 stream-up GET").await?;
    let reader = resp.reader;

    let (wt, wrx) = mpsc::channel::<Bytes>(16);
    let mut req = build_request(ctx, "POST", &url, &host)?.map(|()| V3Body::Pipe(wrx));
    req.headers_mut().insert(
        "Content-Type",
        http::HeaderValue::from_static("application/grpc"),
    );
    let _resp = send_200(&mut sender, req, "xhttp h3 stream-up POST").await?;
    Ok(Box::new(XhttpStream::new(reader, wt)))
}

/// stream-one (legacy XHTTP v1): ONE full-duplex request — no session id
/// (`sessionId = ""`, dialer.go:373-376), the request body carries
/// client→server, the 200 response body carries server→client
/// (dialer.go:453-458 → client.go `OpenStream`). Method = the uplink
/// method (default POST); headers = config headers + Referer `x_padding` +
/// `Content-Type: application/grpc` (config.go `FillStreamRequest`); with
/// an empty session/seq, `ApplyMetaToRequest` emits NO session/seq meta
/// (config.go:285,297 — the pinned meta set for stream-one is empty).
async fn stream_one_h1(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let host = http_host(ctx);
    // The base path only — no session, no seq (dialer.go:454).
    let url = base_path(ctx);
    let mut sender = h1_client(stream).await?;
    let (wt, wrx) = mpsc::channel::<Bytes>(16);
    let mut req = build_request(ctx, "POST", &url, &host)?.map(|()| V3Body::PipeFull(wrx));
    req.headers_mut().insert(
        "Content-Type",
        http::HeaderValue::from_static("application/grpc"),
    );
    let resp = send_200(&mut sender, req, "xhttp stream-one").await?;
    Ok(Box::new(XhttpStream::new(resp.reader, wt)))
}

/// stream-one over h2 (TLS): the single full-duplex request on the one h2
/// conn.
async fn stream_one_h2(ctx: &LinkContext, stream: BoxStream) -> Result<BoxStream, NativeError> {
    let host = http_host(ctx);
    let url = base_path(ctx);
    let mut sender = h2_client(stream).await?;
    let (wt, wrx) = mpsc::channel::<Bytes>(16);
    let mut req = build_request(ctx, "POST", &url, &host)?.map(|()| V3Body::PipeFull(wrx));
    req.headers_mut().insert(
        "Content-Type",
        http::HeaderValue::from_static("application/grpc"),
    );
    let resp = send_200(&mut sender, req, "xhttp stream-one").await?;
    Ok(Box::new(XhttpStream::new(resp.reader, wt)))
}

/// stream-one over h3: the single full-duplex request on one QUIC stream
/// (the response body is the read side — [`V3Body::PipeFull`]).
async fn stream_one_h3(
    ctx: &LinkContext,
    mut sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
) -> Result<BoxStream, NativeError> {
    let host = http_host(ctx);
    let url = base_path(ctx);
    let (wt, wrx) = mpsc::channel::<Bytes>(16);
    let mut req = build_request(ctx, "POST", &url, &host)?.map(|()| V3Body::PipeFull(wrx));
    req.headers_mut().insert(
        "Content-Type",
        http::HeaderValue::from_static("application/grpc"),
    );
    let resp = send_200(&mut sender, req, "xhttp h3 stream-one").await?;
    Ok(Box::new(XhttpStream::new(resp.reader, wt)))
}

/// An in-flight channel send (the channel was full when kicked) — a boxed
/// future keeps the type small.
type PendingSend = Pin<Box<dyn Future<Output = Result<(), ()>> + Send>>;

/// packet-up tunnel: read side = the GET download body; write side = a
/// buffered channel to the upload task.
///
/// The write path mirrors [`crate::transport::grpc::GrpcStream`]:
/// write-through — each accepted write moves one `Bytes` into the channel
/// (the depth-16 buffer absorbs bursts; the upload task batches the items
/// and paces the POSTs itself). There is no staging `BytesMut`: `poll_write`
/// never returns `WouldBlock` (the protocol write path treats it as fatal),
/// so a full channel parks the write as an in-flight send instead. `R` is
/// the download reader: `IncomingReader` on the h1/h2 arms, an h3 body
/// reader on the QUIC arm.
pub struct XhttpStream<R> {
    /// The GET download body (read side).
    reader: R,
    tx: mpsc::Sender<Bytes>,
    /// An in-flight channel send (the channel was full when kicked).
    flushing: Option<PendingSend>,
}

impl<R> XhttpStream<R> {
    #[must_use]
    pub fn new(reader: R, tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            reader,
            tx,
            flushing: None,
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
                        "xhttp uploader closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Move `bytes` into the upload channel, parking an in-flight send when
    /// the channel is full. Returns `false` when the uploader has gone
    /// (channel closed) — the write side is then broken.
    fn kick(&mut self, bytes: Bytes) -> bool {
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
}

impl<R: AsyncRead + Unpin + Send> AsyncRead for XhttpStream<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin + Send> AsyncWrite for XhttpStream<R> {
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
        // Write-through: one `Bytes` per write, delivered on every write
        // (`AsyncWriteExt::write_all` never calls `poll_flush`, so
        // flush-only delivery would strand bytes — ws.rs mirrors this
        // choice). No staging buffer: the single copy into `Bytes` is the
        // only per-write allocation.
        if !self.kick(Bytes::copy_from_slice(buf)) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp uploader closed",
            )));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        self.poll_flushing(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        // Nothing staged: dropping the stream closes the channel (the upload
        // task POSTs the tail and stops).
        self.poll_flushing(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use leas_proto::proto_spec::ProtocolConfig;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use leas_proto::proto_spec::{RealityOpts, TlsOpts};
    use leas_proto::urlx::TinyText;
    use rstest::rstest;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::addr::{Host, TargetAddr};
    use crate::context::{LinkContext, NativeConnectParams};

    fn vless_xhttp(mode: &str) -> ProtocolConfig {
        // The proto's `TransportConfig` serde tag is snake_case: the variant
        // serializes/parses as `x_http` (the wire/type_str name is `xhttp`).
        serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "x_http", "path": "/x", "host": "example.com", "mode": mode }
        }))
        .expect("config parses")
    }

    fn ctx_at(addr: SocketAddr, mode: &str) -> LinkContext {
        LinkContext::new(
            NativeConnectParams::new(
                vless_xhttp(mode),
                EndpointEssentials::new(addr.ip().to_string(), addr.port()),
                TargetAddr::new(Host::Domain("dest.test".into()), 80),
            ),
            TargetAddr::new(Host::Domain("dest.test".into()), 80),
        )
    }

    async fn read_head(sock: &mut tokio::net::TcpStream) -> String {
        let mut head = Vec::new();
        let mut buf = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            sock.read_exact(&mut buf).await.unwrap();
            head.push(buf[0]);
        }
        String::from_utf8(head).unwrap()
    }

    /// Decode the chunked POST body off the raw socket: parse size lines and
    /// payloads until `want` has arrived (the stream-up tunnel POST stays
    /// open, so the caller stops early) or the peer closes. Returns the
    /// de-chunked payload read so far.
    async fn read_chunked_until(sock: &mut tokio::net::TcpStream, want: &[u8]) -> Vec<u8> {
        let mut raw: Vec<u8> = Vec::new();
        let mut body: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 4096];
        let mut expect = 0usize; // payload bytes remaining in the current chunk
        loop {
            if expect == 0 {
                if let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") {
                    let size =
                        usize::from_str_radix(std::str::from_utf8(&raw[..pos]).unwrap().trim(), 16)
                            .unwrap();
                    raw.drain(..pos + 2);
                    if size == 0 {
                        return body; // terminating last-chunk
                    }
                    expect = size;
                } else {
                    let n = sock.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        return body;
                    }
                    raw.extend_from_slice(&tmp[..n]);
                    continue;
                }
            }
            if raw.len() < expect + 2 {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    return body;
                }
                raw.extend_from_slice(&tmp[..n]);
                continue;
            }
            body.extend_from_slice(&raw[..expect]);
            raw.drain(..expect + 2); // payload + trailing CRLF
            expect = 0;
            if body == want {
                return body;
            }
        }
    }

    /// Two connections: GET (download, session in path) + POSTs (upload, seq
    /// in path). Server responds 200 to both; GET body streams echoes.
    #[tokio::test]
    async fn packet_up_h1_get_and_post() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut get_sock, _) = listener.accept().await.unwrap();
            let get_head = read_head(&mut get_sock).await;
            assert!(get_head.starts_with("GET /x/"), "{get_head}");
            assert!(
                get_head
                    .to_lowercase()
                    .contains("referer: http://example.com/x/"),
                "{get_head}"
            );
            assert!(get_head.contains("x_padding="), "{get_head}");
            // 200 + SSE headers; body is the download stream.
            get_sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\nX-Accel-Buffering: no\r\nCache-Control: no-store\r\n\r\n",
                )
                .await
                .unwrap();
            // (upload comes on a second connection)
            let (mut up_sock, _) = listener.accept().await.unwrap();
            let up_head = read_head(&mut up_sock).await;
            assert!(up_head.starts_with("POST /x/"), "{up_head}");
            // hyper writes header names lowercase on the wire.
            assert!(
                up_head.to_lowercase().contains("content-length: 5"),
                "{up_head}"
            );
            // seq 0: the request-target is `/x/{session}/{seq}`.
            let target = up_head.split_whitespace().nth(1).unwrap();
            assert!(target.starts_with("/x/"), "{target}");
            assert!(target.ends_with("/0"), "{target}");
            let mut body = [0u8; 5];
            up_sock.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"hello");
            up_sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            // echo the downloaded bytes back through the GET chunked body
            get_sock
                .write_all(b"5\r\nworld\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ctx = ctx_at(addr, "packet-up");
        let mut t = connect(&ctx, Box::new(stream)).await.unwrap();
        t.write_all(b"hello").await.unwrap();
        let mut out = [0u8; 5];
        t.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"world");
        server.await.unwrap();
    }

    /// stream-up: GET (download, 200 + streaming body) + POST (upload, pipe
    /// body with application/grpc). The server 200s the POST immediately
    /// (xray hub.go) and streams echoes on the GET; the tunnel POST stays
    /// open for the connection's lifetime, so the server echoes as soon as
    /// the payload arrived (waiting for EOF would deadlock — xray streams
    /// continuously).
    #[tokio::test]
    async fn stream_up_h1_get_and_post() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut get_sock, _) = listener.accept().await.unwrap();
            let get_head = read_head(&mut get_sock).await;
            assert!(get_head.starts_with("GET /x/"), "{get_head}");
            get_sock
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n",
                )
                .await
                .unwrap();
            let (mut up_sock, _) = listener.accept().await.unwrap();
            let up_head = read_head(&mut up_sock).await;
            assert!(up_head.starts_with("POST /x/"), "{up_head}");
            // hyper writes header names lowercase on the wire.
            assert!(
                up_head
                    .to_lowercase()
                    .contains("content-type: application/grpc"),
                "{up_head}"
            );
            // xray hub.go 200s the upload POST immediately, then streams
            // keepalive X-blobs into the response body (drained client-side).
            up_sock
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            // POST body is chunked (unknown-length pipe); the tunnel stays
            // open — decode the framing and echo as soon as the payload
            // arrived (waiting for EOF would deadlock; xray streams echoes
            // continuously).
            let body = read_chunked_until(&mut up_sock, b"hello").await;
            assert_eq!(&body, b"hello");
            get_sock
                .write_all(b"6\r\nworld!\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ctx = ctx_at(addr, "stream-up");
        let mut t = connect(&ctx, Box::new(stream)).await.unwrap();
        t.write_all(b"hello").await.unwrap();
        let mut out = [0u8; 6];
        t.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"world!");
        server.await.unwrap();
    }

    /// stream-one (legacy XHTTP v1) over h1: ONE request — no session id,
    /// the POST body is the upload, the 200 response body the download. The
    /// server asserts the request-target is the base path only (no uuid, no
    /// seq), the Referer `x_padding`, `Content-Type: application/grpc`, and
    /// NO session/seq meta (`ApplyMetaToRequest` emits nothing for an empty
    /// session — config.go:285,297).
    #[tokio::test]
    async fn stream_one_h1_full_duplex() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let head = read_head(&mut sock).await;
            // request-target = the base path only — NO session/seq segment.
            let target = head.split_whitespace().nth(1).unwrap();
            assert_eq!(target, "/x/", "{head}");
            assert!(
                head.to_lowercase()
                    .contains("content-type: application/grpc"),
                "{head}"
            );
            assert!(
                head.to_lowercase()
                    .contains("referer: http://example.com/x/?x_padding="),
                "{head}"
            );
            assert!(!head.to_lowercase().contains("x-sid"), "{head}");
            assert!(!head.to_lowercase().contains("x-sq"), "{head}");
            // 200 immediately; body = the download stream.
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            // read the chunked upload until the payload arrived (the tunnel
            // POST stays open — no EOF; xray streams the download
            // continuously, so echoing as soon as the payload arrives
            // avoids the deadlock).
            let body = read_chunked_until(&mut sock, b"hello").await;
            assert_eq!(&body, b"hello");
            sock.write_all(b"6\r\nworld!\r\n0\r\n\r\n").await.unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ctx = ctx_at(addr, "stream-one");
        let mut t = connect(&ctx, Box::new(stream)).await.unwrap();
        t.write_all(b"hello").await.unwrap();
        let mut out = [0u8; 6];
        t.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"world!");
        server.await.unwrap();
    }

    /// Error path: a non-200 stream-one response must surface as a
    /// transport error (client.go `OpenStream`: non-200 → discard the
    /// body, close, error — the v3 contract requires 200).
    #[tokio::test]
    async fn stream_one_h1_non_200_surfaces_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let head = read_head(&mut sock).await;
            assert!(head.starts_with("POST /x/ "), "{head}");
            sock.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let ctx = ctx_at(addr, "stream-one");
        let Err(err) = connect(&ctx, Box::new(stream)).await else {
            panic!("a 500 stream-one response must fail connect")
        };
        assert!(
            matches!(err, NativeError::TransportRejected { status: 500, .. }),
            "the peer's status is the typed evidence: {err}"
        );
        server.await.unwrap();
    }

    /// stream-one over the h2 arm: hyper h2 client ↔ h2 crate server over a
    /// tokio duplex (h2c — the framing seam is the unit under test; the TLS
    /// layer is the e2e's job). One full-duplex request: POST `/x/` (no
    /// session), the response body is the download.
    ///
    /// The h2 crate's per-stream ops (`data()`, `send_response`) only touch
    /// stream state — the connection itself must be polled for bytes to
    /// flow, so the handler runs alongside an `accept()` driver (the h2
    /// docs pattern: spawn handlers and keep accepting). The driver exits
    /// when the handler completes; dropping the connection then closes it.
    #[tokio::test]
    async fn stream_one_h2_full_duplex() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io)
                .await
                .expect("h2 server handshake");
            let (req, mut respond) = conn.accept().await.expect("h2 accept").expect("h2 request");
            let handler = tokio::spawn(async move {
                let (parts, mut body) = req.into_parts();
                assert_eq!(parts.method, http::Method::POST);
                assert_eq!(parts.uri.path(), "/x/", "no session/seq in the path");
                let headers = &parts.headers;
                assert_eq!(
                    headers.get("content-type").and_then(|v| v.to_str().ok()),
                    Some("application/grpc")
                );
                let referer = headers
                    .get("referer")
                    .and_then(|v| v.to_str().ok())
                    .expect("referer");
                assert!(
                    referer.starts_with("https://localhost/x/?x_padding="),
                    "{referer}"
                );
                assert!(headers.get("x-sid").is_none(), "no session meta");
                assert!(headers.get("x-sq").is_none(), "no seq meta");
                // 200 immediately (xray hub.go 200s the upload POST before
                // reading the body — the client's forward task only starts
                // after the response headers resolve), then the download.
                let resp = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(resp, false).expect("send response");
                send.send_data(Bytes::from_static(b"world!"), false)
                    .expect("download data");
                send.send_data(Bytes::new(), true).expect("download end");
                // read the upload until the payload arrived (the tunnel POST
                // stays open — no EOF yet).
                let mut upload = Vec::new();
                while upload.len() < 5 {
                    let chunk = body
                        .data()
                        .await
                        .expect("upload chunk")
                        .expect("upload EOF before payload");
                    upload.extend_from_slice(&chunk[..]);
                }
                assert_eq!(&upload[..5], b"hello");
                // drain the rest of the upload (ends when the tunnel drops).
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.expect("upload data");
                    upload.extend_from_slice(&chunk[..]);
                }
            });
            let mut handler = handler;
            let done = loop {
                tokio::select! {
                    r = &mut handler => break Some(r),
                    next = conn.accept() => {
                        match next {
                            None | Some(Err(_)) => break None, // client closed / error
                            Some(Ok(_)) => {} // no second request expected
                        }
                    }
                }
            };
            drop(conn); // close the connection now that the handler is done
            match done {
                // The select branch already polled the handle to completion —
                // consuming the result here avoids re-polling it (tokio
                // panics on `JoinHandle` poll after completion).
                Some(r) => r.expect("h2 handler"),
                // The accept branch fired first (client closed early): the
                // handle was never polled, so awaiting it is safe.
                None => handler.await.expect("h2 handler"),
            }
        });
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "x_http", "path": "/x", "host": "localhost", "mode": "stream-one" },
            "security": { "type": "tls" }
        }))
        .expect("config parses");
        let ctx = LinkContext::new(
            NativeConnectParams::new(
                protocol,
                EndpointEssentials::new("127.0.0.1".to_string(), 1),
                TargetAddr::new(Host::Domain("dest.test".into()), 80),
            ),
            TargetAddr::new(Host::Domain("dest.test".into()), 80),
        );
        let mut t = connect(&ctx, Box::new(client_io))
            .await
            .expect("stream-one h2 connect");
        t.write_all(b"hello").await.unwrap();
        let mut out = [0u8; 6];
        t.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"world!");
        drop(t);
        server.await.unwrap();
    }

    #[test]
    fn padding_is_repeat_x_within_range() {
        for _ in 0..50 {
            let pad = x_padding();
            assert!(
                pad.len() >= PAD_MIN && pad.len() <= PAD_MAX,
                "len {}",
                pad.len()
            );
            assert!(pad.bytes().all(|b| b == b'X'), "repeat-X only");
        }
    }

    #[test]
    fn referer_appends_padding_query() {
        // The `referer()` helper is inlined into `build_request` (one
        // allocation via `write!`), so the wire shape is asserted on the
        // real path instead.
        let ctx = ctx_at("127.0.0.1:1".parse().unwrap(), "packet-up");
        let req = build_request(&ctx, "GET", "/x/sess", "example.com").unwrap();
        let referer = req.headers()["referer"].to_str().unwrap();
        let (url, pad) = referer.split_once("?x_padding=").unwrap();
        assert_eq!(url, "http://example.com/x/");
        assert!((100..=1000).contains(&pad.len()), "len {}", pad.len());
        assert!(pad.bytes().all(|b| b == b'X'), "repeat-X only");
    }

    #[test]
    fn paths_append_session_and_seq() {
        let ctx = ctx_at("127.0.0.1:1".parse().unwrap(), "packet-up");
        assert_eq!(path_with(&ctx, "sess", None), "/x/sess");
        assert_eq!(path_with(&ctx, "sess", Some("0")), "/x/sess/0");
        let no_slash = serde_json::from_value::<ProtocolConfig>(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "x_http", "path": "no-slash" }
        }))
        .expect("config parses");
        let ctx2 = LinkContext::new(
            NativeConnectParams::new(
                no_slash,
                EndpointEssentials::new("127.0.0.1", 1),
                TargetAddr::new(Host::Domain("dest.test".into()), 80),
            ),
            TargetAddr::new(Host::Domain("dest.test".into()), 80),
        );
        assert_eq!(base_path(&ctx2), "/no-slash/");
    }

    // --- decideHTTPVersion mirror (spec §4.1) -----------------------------

    fn tls(alpn: Option<&str>) -> SecurityConfig {
        SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                alpn: alpn.map(TinyText::from),
                ..TlsOpts::default()
            })),
            ..SecurityConfig::default()
        }
    }

    fn reality() -> SecurityConfig {
        SecurityConfig {
            tls: Some(TlsConfig::Reality(RealityOpts::default())),
            ..SecurityConfig::default()
        }
    }

    /// The `http_version` dispatch table (dialer.go `decideHTTPVersion`): one
    /// case per decision class, every input asserted here.
    #[rstest]
    #[case::no_security_none(None, "1.1")]
    #[case::no_security_default(Some(SecurityConfig::default()), "1.1")]
    #[case::reality(Some(reality()), "2")]
    #[case::http_1_1(Some(tls(Some("http/1.1"))), "1.1")]
    #[case::http_1_1_padded(Some(tls(Some(" http/1.1 "))), "1.1")]
    #[case::h3(Some(tls(Some("h3"))), "3")]
    #[case::h3_padded(Some(tls(Some(" h3 "))), "3")]
    #[case::other_single_h2(Some(tls(Some("h2"))), "2")]
    #[case::other_single_silly(Some(tls(Some("silly"))), "2")]
    #[case::zero_alpn_absent(Some(tls(None)), "2")]
    #[case::zero_alpn_empty(Some(tls(Some(""))), "2")]
    #[case::zero_alpn_commas(Some(tls(Some(" , "))), "2")]
    #[case::two_plus_h2_http_1_1(Some(tls(Some("h2,http/1.1"))), "2")]
    #[case::two_plus_h3_h2(Some(tls(Some("h3,h2"))), "2")]
    #[case::two_plus_three(Some(tls(Some("h2,http/1.1,h3"))), "2")]
    fn http_version_dispatch(#[case] security: Option<SecurityConfig>, #[case] expected: &str) {
        assert_eq!(http_version(security.as_ref()), expected);
    }

    #[test]
    fn dispatch_mirrors_decide_http_version_table() {
        // the full xray table in one sweep (dialer.go decideHTTPVersion)
        let cases: &[(Option<&SecurityConfig>, &str)] = &[
            (None, "1.1"),
            (Some(&reality()), "2"),
            (Some(&tls(None)), "2"),
            (Some(&tls(Some("http/1.1"))), "1.1"),
            (Some(&tls(Some("h3"))), "3"),
            (Some(&tls(Some("h2"))), "2"),
            (Some(&tls(Some("h2,http/1.1"))), "2"),
        ];
        for (sec, want) in cases {
            assert_eq!(http_version(*sec), *want);
        }
    }

    // --- mode selection mirror (spec §4.1, dialer.go:362-371) ------------

    /// An xhttp ctx with arbitrary mode/security/extra — the full §4.1
    /// input space (the [`ctx_at`] helper covers the plain h1 rows).
    fn ctx_mode(
        mode: &str,
        security: Option<serde_json::Value>,
        extra: Option<serde_json::Value>,
    ) -> LinkContext {
        let mut transport = serde_json::json!({
            "type": "x_http", "path": "/x", "host": "example.com"
        });
        transport["mode"] = serde_json::json!(mode);
        if let Some(extra) = extra {
            transport["extra"] = extra;
        }
        let mut protocol = serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": transport,
        });
        if let Some(security) = security {
            protocol["security"] = security;
        }
        let protocol: ProtocolConfig = serde_json::from_value(protocol).expect("config parses");
        LinkContext::new(
            NativeConnectParams::new(
                protocol,
                EndpointEssentials::new("127.0.0.1".to_string(), 1),
                TargetAddr::new(Host::Domain("dest.test".into()), 80),
            ),
            TargetAddr::new(Host::Domain("dest.test".into()), 80),
        )
    }

    /// Mode selection mirror (spec §4.1, dialer.go:362-371): explicit modes
    /// pass through; `auto`/empty resolves by the reality config and download
    /// settings. TLS (not reality) does NOT change the auto rule — xray only
    /// checks `realityConfig != nil`.
    #[rstest]
    #[case::explicit_packet_up("packet-up", None, false, "packet-up")]
    #[case::explicit_stream_up("stream-up", None, false, "stream-up")]
    #[case::explicit_stream_one("stream-one", None, false, "stream-one")]
    #[case::auto_without_reality("auto", None, false, "packet-up")]
    #[case::empty_without_reality("", None, false, "packet-up")]
    #[case::auto_with_plain_tls("auto", Some("tls"), false, "packet-up")]
    #[case::empty_with_plain_tls("", Some("tls"), false, "packet-up")]
    #[case::auto_with_reality("auto", Some("reality"), false, "stream-one")]
    #[case::empty_with_reality("", Some("reality"), false, "stream-one")]
    #[case::auto_with_reality_download("auto", Some("reality"), true, "stream-up")]
    #[case::empty_with_reality_download("", Some("reality"), true, "stream-up")]
    #[case::explicit_overrides_auto("packet-up", Some("reality"), false, "packet-up")]
    fn xhttp_mode_selection(
        #[case] mode: &str,
        #[case] security: Option<&str>,
        #[case] download: bool,
        #[case] expected: &str,
    ) {
        let security = security.map(|kind| serde_json::json!({ "type": kind }));
        let extra = if download {
            Some(serde_json::json!({ "downloadSettings": {} }))
        } else {
            None
        };
        assert_eq!(
            xhttp_mode(&ctx_mode(mode, security, extra)).unwrap(),
            expected,
            "{mode}"
        );
    }

    #[test]
    fn mode_unknown_is_config_error() {
        let err = xhttp_mode(&ctx_mode("bogus", None, None)).unwrap_err();
        assert!(matches!(err, NativeError::Config(_)), "{err}");
    }

    // --- SP5 T1 smoke: the quinn + h3 dep stack ---------------------------

    /// quinn server + client over loopback UDP, self-signed cert, the `h3`
    /// ALPN (spec §4.1): proves the stack compiles, negotiates TLS 1.3 +
    /// ALPN, and streams bytes. `h3`/`h3-quinn` compile as deps (the client
    /// arm consumes them in T2); this exercises the quinn transport their
    /// `h3-quinn` adapter wraps.
    #[tokio::test]
    async fn quic_loopback_smoke() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        let cert_der = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .expect("key der");

        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server tls");
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
                    .expect("quic server config"),
            )),
            "127.0.0.1:0".parse().expect("bind addr"),
        )
        .expect("quic server endpoint");
        let server_addr = server.local_addr().expect("server addr");

        let server_task = {
            let server = server.clone();
            tokio::spawn(async move {
                let conn = server
                    .accept()
                    .await
                    .expect("incoming conn")
                    .await
                    .expect("server handshake");
                let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
                let data = recv.read_to_end(usize::MAX).await.expect("read");
                send.write_all(&data).await.expect("echo write");
                send.finish().expect("finish");
                // Hold the connection until the client closes it: dropping it
                // here would abort the echoed stream before the client reads.
                conn.closed().await;
            })
        };

        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates({
                let mut roots = rustls::RootCertStore::empty();
                roots.add(cert_der).expect("root add");
                roots
            })
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client = quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind addr"))
            .expect("quic client endpoint");
        let conn = client
            .connect_with(
                quinn::ClientConfig::new(Arc::new(
                    quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
                        .expect("quic client config"),
                )),
                server_addr,
                "localhost",
            )
            .expect("connect")
            .await
            .expect("client handshake");

        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"hello quinn h3").await.expect("write");
        send.finish().expect("finish");
        let echoed = recv.read_to_end(usize::MAX).await.expect("echo read");
        assert_eq!(echoed, b"hello quinn h3");

        conn.close(0u32.into(), b"done");
        client.wait_idle().await;
        server_task.await.expect("server task");
        server.wait_idle().await;
    }

    // --- SP5 T2: the h3 client arm ----------------------------------------

    /// An xhttp ctx with the h3 ALPN (spec §4.1 trigger) + insecure TLS
    /// (the loopback server's cert is self-signed — verification is T3's
    /// e2e concern).
    fn ctx_h3(addr: SocketAddr, mode: &str) -> LinkContext {
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "x_http", "path": "/x", "host": "localhost", "mode": mode },
            "security": { "type": "tls", "alpn": "h3", "insecure": true }
        }))
        .expect("config parses");
        LinkContext::new(
            NativeConnectParams::new(
                protocol,
                EndpointEssentials::new(addr.ip().to_string(), addr.port()),
                TargetAddr::new(Host::Domain("dest.test".into()), 80),
            ),
            TargetAddr::new(Host::Domain("dest.test".into()), 80),
        )
    }

    // --- SP5 T3: the hermetic h3 server double (spec §7.2) ----------------

    /// Bounded server-side await: a hung client must fail the server task
    /// (and thus the test) instead of hanging forever.
    async fn bounded<T>(fut: impl Future<Output = T>, what: &'static str) -> T {
        tokio::time::timeout(H3_DEADLINE, fut)
            .await
            .unwrap_or_else(|_| panic!("fake h3 server: {what} timed out after {H3_DEADLINE:?}"))
    }

    /// Upper bound on every server-side await and the test-side observation
    /// wait (loopback QUIC round trips are sub-ms; 10 s is generous headroom
    /// for slow CI without letting a hung client hang the suite).
    const H3_DEADLINE: Duration = Duration::from_secs(10);

    /// The download body the fake streams on the session-open GET.
    const H3_DOWNLOAD: &[u8] = b"world";

    /// What the fake server observed, asserted on by the tests. Event-based:
    /// every record bumps [`H3Handle::changed`], and the tests wait on it
    /// under a deadline — never sleep-then-assert.
    #[derive(Debug, Default)]
    struct H3Obs {
        /// Session-open GETs: `(path, referer)` in arrival order.
        gets: Vec<(String, String)>,
        /// Packet-up POSTs: `(seq, body, referer, arrival)` in arrival order.
        posts: Vec<(u64, Bytes, String, Instant)>,
        /// Stream-up POSTs: `(referer, content-type)` in arrival order.
        stream_reqs: Vec<(String, String)>,
        /// Stream-up upload bodies (EOF is always observed — the fake reads
        /// each body to completion).
        stream_uploads: Vec<Bytes>,
        /// Stream-up X-blobs streamed by the server into the upload response
        /// (xray hub.go keepalive).
        stream_xblobs: Vec<Bytes>,
        /// Stream-one POSTs: `(referer, content-type)` in arrival order.
        stream_one_reqs: Vec<(String, String)>,
        /// Stream-one upload bodies (EOF is always observed).
        stream_one_uploads: Vec<Bytes>,
        /// The h3 connection closed (the client is gone).
        conn_closed: bool,
    }

    /// Shared handle: the observations + the event-based wait primitive.
    /// The Notify lives OUTSIDE the mutex so a waiter never holds the lock
    /// across an await — holding it there would deadlock the server's
    /// `record` against the test's wait.
    struct H3Handle {
        data: Mutex<H3Obs>,
        changed: Notify,
    }

    /// Record one observation and wake the test waiter.
    fn record(obs: &Arc<H3Handle>, f: impl FnOnce(&mut H3Obs)) {
        let mut o = obs.data.lock().expect("obs lock");
        f(&mut o);
        obs.changed.notify_one();
    }

    /// Wait until `pred` holds over the observations, under [`H3_DEADLINE`]
    /// (event-driven via the Notify — the permit model makes a record
    /// between the check and the wait unmissable).
    async fn wait_obs(obs: &Arc<H3Handle>, pred: impl Fn(&H3Obs) -> bool) {
        loop {
            if pred(&obs.data.lock().expect("obs lock")) {
                return;
            }
            let notified = obs.changed.notified();
            assert!(
                tokio::time::timeout(H3_DEADLINE, notified).await.is_ok(),
                "fake h3 server: expected observation missed: {:#?}",
                *obs.data.lock().expect("obs lock")
            );
        }
    }

    /// Referer = `{scheme}://{host}{base}?x_padding={X..}` — `X`s in the
    /// xray `xPaddingBytes` [100, 1000] range (the v3 padding the client
    /// sends on every request).
    fn assert_referer(referer: &str) {
        let (url, pad) = referer
            .split_once("?x_padding=")
            .expect("referer carries x_padding");
        assert_eq!(url, "https://localhost/x/", "{referer}");
        assert!(pad.bytes().all(|b| b == b'X'), "{referer}");
        assert!((PAD_MIN..=PAD_MAX).contains(&pad.len()), "{referer}");
    }

    /// Read an h3 request body to EOF, concatenated. The client always
    /// finishes its upload bodies (packet POSTs are finite; the stream-up
    /// pipe ends when the tunnel writer drops), so EOF is the expected
    /// outcome — a stalled peer trips the outer `bounded` deadline.
    async fn read_h3_body(
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ) -> Bytes {
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.expect("read request body") {
            body.extend_from_slice(chunk.chunk());
            chunk.advance(chunk.remaining());
        }
        Bytes::from(body)
    }

    /// Serve the v3 protocol over one h3 connection until the client closes
    /// it: session-open GETs, packet-up POSTs (seq in the path), stream-up
    /// POSTs (200 immediately — xray hub.go — then the piped body to EOF).
    async fn handle_h3_request(
        req: http::Request<()>,
        mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        obs: &Arc<H3Handle>,
        reject_get: bool,
    ) {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let referer = req
            .headers()
            .get("referer")
            .map(|v| v.to_str().unwrap_or_default().to_string())
            .unwrap_or_default();

        if method == http::Method::GET {
            // Session open: `{base}/{uuid}` — never a seq segment.
            let session = path.strip_prefix("/x/").expect("GET on session path");
            assert!(
                !session.contains('/'),
                "session-open GET must not carry a seq: {path}"
            );
            uuid::Uuid::parse_str(session).expect("session is a uuid v4");
            record(obs, |o| o.gets.push((path, referer)));
            let status = if reject_get {
                http::StatusCode::INTERNAL_SERVER_ERROR
            } else {
                http::StatusCode::OK
            };
            let resp = http::Response::builder().status(status).body(()).unwrap();
            bounded(stream.send_response(resp), "GET response")
                .await
                .expect("GET response");
            if !reject_get {
                bounded(
                    stream.send_data(Bytes::from_static(H3_DOWNLOAD)),
                    "GET body",
                )
                .await
                .expect("GET body");
            }
            bounded(stream.finish(), "GET finish")
                .await
                .expect("GET finish");
        } else if path == "/x/" {
            // Stream-one (legacy XHTTP v1): the single full-duplex request
            // on the base path — no session, no seq. 200 + the download
            // body (client.go OpenStream), then the piped upload to EOF.
            let content_type = req
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap_or_default().to_string())
                .unwrap_or_default();
            assert_eq!(
                req.headers().get("x-sid"),
                None,
                "no session meta for stream-one"
            );
            assert_eq!(
                req.headers().get("x-sq"),
                None,
                "no seq meta for stream-one"
            );
            record(obs, |o| o.stream_one_reqs.push((referer, content_type)));
            let resp = http::Response::builder()
                .status(http::StatusCode::OK)
                .body(())
                .unwrap();
            bounded(stream.send_response(resp), "stream-one 200")
                .await
                .expect("stream-one 200");
            bounded(
                stream.send_data(Bytes::from_static(H3_DOWNLOAD)),
                "stream-one body",
            )
            .await
            .expect("stream-one body");
            let body = bounded(read_h3_body(&mut stream), "stream-one upload").await;
            record(obs, |o| o.stream_one_uploads.push(body));
            // Teardown race: the client closes the h3 connection as soon as
            // the tunnel drops (the forward task's `SendRequest` clone goes
            // with it) — the server's finish may observe RemoteTerminate 0x0
            // (H3_NO_ERROR) instead of completing cleanly. The download +
            // upload bytes are already asserted; the finish is pure teardown.
            let _ = tokio::time::timeout(H3_DEADLINE, stream.finish()).await;
        } else if let Ok(seq) = path
            .rsplit('/')
            .next()
            .expect("POST path has a last segment")
            .parse::<u64>()
        {
            // Packet-up upload: `{base}/{uuid}/{seq}` — the raw body, 200.
            let body = bounded(read_h3_body(&mut stream), "upload body").await;
            record(obs, |o| o.posts.push((seq, body, referer, Instant::now())));
            let resp = http::Response::builder()
                .status(http::StatusCode::OK)
                .body(())
                .unwrap();
            bounded(stream.send_response(resp), "POST response")
                .await
                .expect("POST response");
            bounded(stream.finish(), "POST finish")
                .await
                .expect("POST finish");
        } else {
            // Stream-up upload: `{base}/{uuid}` — 200 immediately (xray
            // hub.go), then the piped body to EOF (the tunnel writer's
            // close ends it). The server streams keepalive X-blobs into
            // the response body (xray hub.go scStreamUpServerSecs) — the
            // client's drain_h3 task must consume them concurrently.
            let content_type = req
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap_or_default().to_string())
                .unwrap_or_default();
            record(obs, |o| o.stream_reqs.push((referer, content_type)));
            let resp = http::Response::builder()
                .status(http::StatusCode::OK)
                .body(())
                .unwrap();
            bounded(stream.send_response(resp), "stream-up 200")
                .await
                .expect("stream-up 200");
            // Stream keepalive X-blobs (xray hub.go style: periodic empty
            // DATA frames or small padding). The client's drain task must
            // consume these without blocking the tunnel.
            for _ in 0..3 {
                bounded(
                    stream.send_data(Bytes::from_static(b"X")),
                    "stream-up xblob",
                )
                .await
                .expect("stream-up xblob");
                record(obs, |o| o.stream_xblobs.push(Bytes::from_static(b"X")));
            }
            let body = bounded(read_h3_body(&mut stream), "stream-up body").await;
            record(obs, |o| o.stream_uploads.push(body));
            bounded(stream.finish(), "stream-up finish")
                .await
                .expect("stream-up finish");
        }
    }

    /// The fake server loop: one quinn connection (the tests open exactly
    /// one), the h3 server connection over it, and the request loop until
    /// the client closes. Every await is bounded.
    async fn serve_h3(server: quinn::Endpoint, obs: Arc<H3Handle>, reject_get: bool) {
        let incoming = bounded(server.accept(), "accept conn")
            .await
            .expect("incoming quinn conn");
        let conn = bounded(incoming.into_future(), "conn handshake")
            .await
            .expect("server handshake");
        let h3_quic = h3_quinn::Connection::new(conn);
        let mut h3_conn = bounded(h3::server::Connection::new(h3_quic), "h3 open")
            .await
            .expect("h3 server open");
        loop {
            // The client closes the h3 connection (H3_NO_ERROR after the
            // last request stream dropped) → accept yields `None`/`Err`.
            let Some(resolver) = bounded(h3_conn.accept(), "accept request")
                .await
                .ok()
                .flatten()
            else {
                record(&obs, |o| o.conn_closed = true);
                break;
            };
            let (req, stream) = bounded(resolver.resolve_request(), "resolve request")
                .await
                .expect("resolve request");
            handle_h3_request(req, stream, &obs, reject_get).await;
        }
    }

    /// Bind + spawn the fake h3 server (self-signed cert, `h3` ALPN —
    /// spec §4.1) over loopback QUIC, returning the socket address + the
    /// shared observations + the server task.
    ///
    /// Cert story: the client's `insecure` TLS mode (the `SkipServerVerify`
    /// seam — chain walk skipped, handshake signatures still verified)
    /// accepts the self-signed loopback cert in the hermetic tests; the
    /// webpki-roots path is the T4 e2e's job (the real xray server's own
    /// cert — there is no CA-injection hook in `quic_tls_config`).
    ///
    /// `reject_get` makes the server 500 the session-open GET (the error
    /// path test).
    fn spawn_h3_fake(reject_get: bool) -> (SocketAddr, Arc<H3Handle>, JoinHandle<()>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certified =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
        let cert_der = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(certified.signing_key.serialize_der())
                .expect("key der");
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server tls");
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
                    .expect("quic server config"),
            )),
            "127.0.0.1:0".parse().expect("bind addr"),
        )
        .expect("quic server endpoint");
        let addr = server.local_addr().expect("server addr");
        let obs = Arc::new(H3Handle {
            data: Mutex::new(H3Obs::default()),
            changed: Notify::new(),
        });
        let handle = tokio::spawn(serve_h3(server, obs.clone(), reject_get));
        (addr, obs, handle)
    }

    /// Assert the fake's observations for one full packet-up round trip:
    /// one session-open GET (uuid path, no seq, Referer) + one packet POST
    /// (seq 0, raw body, Referer). Sync helper — keeps the `MutexGuard` out
    /// of the async test bodies.
    fn assert_packet_roundtrip(o: &H3Obs) {
        assert_eq!(o.gets.len(), 1, "{o:#?}");
        let (get_path, get_referer) = &o.gets[0];
        assert!(get_path.starts_with("/x/"), "{get_path}");
        uuid::Uuid::parse_str(&get_path["/x/".len()..]).expect("GET session uuid");
        assert_referer(get_referer);
        assert_eq!(o.posts.len(), 1, "{o:#?}");
        let (seq, body, post_referer, _arrival) = &o.posts[0];
        assert_eq!(*seq, 0);
        assert_eq!(&body[..], &b"hello"[..]);
        assert_referer(post_referer);
    }

    /// Assert the chunked-upload observations: two packet POSTs, seqs 0 + 1
    /// in arrival order, each ≤ the 1 MB cap, concatenated == the payload,
    /// paced ≥ 25 ms apart, both carrying the Referer.
    fn assert_chunked_uploads(o: &H3Obs, payload: &[u8]) {
        assert_eq!(o.posts.len(), 2, "{o:#?}");
        let (s0, b0, r0, t0) = &o.posts[0];
        let (s1, b1, r1, t1) = &o.posts[1];
        assert_eq!(*s0, 0, "seq order");
        assert_eq!(*s1, 1, "seq order");
        assert_eq!(b0.len(), MAX_POST_BYTES, "first chunk = the size cap");
        assert_eq!(b1.len(), 200_000, "tail chunk");
        let mut joined = Vec::with_capacity(b0.len() + b1.len());
        joined.extend_from_slice(b0);
        joined.extend_from_slice(b1);
        assert_eq!(joined, payload, "no byte loss across the split");
        assert_referer(r0);
        assert_referer(r1);
        assert!(
            t1.duration_since(*t0) >= POST_INTERVAL.saturating_sub(Duration::from_millis(5)),
            "posts must be paced ≥ 25 ms apart: {t0:?} -> {t1:?}"
        );
    }

    /// Assert the stream-up observations: session-open GET with Referer, one
    /// pipe POST (application/grpc + Referer, body delivered intact).
    fn assert_stream_up_roundtrip(o: &H3Obs) {
        assert_eq!(o.gets.len(), 1, "{o:#?}");
        assert_referer(&o.gets[0].1);
        assert_eq!(o.stream_reqs.len(), 1, "{o:#?}");
        let (referer, content_type) = &o.stream_reqs[0];
        assert_eq!(content_type, "application/grpc");
        assert_referer(referer);
        assert_eq!(o.stream_uploads.len(), 1, "{o:#?}");
        assert_eq!(
            &o.stream_uploads[0][..],
            &b"hello"[..],
            "piped body delivered intact"
        );
    }

    /// Full packet-up round trip: `connect_quic` dials the loopback quinn
    /// server, negotiates TLS 1.3 + the h3 ALPN, opens the v3 session (GET
    /// `/{uuid}` → 200), uploads via the first packet POST (seq 0, raw
    /// body), and downloads from the GET body. The fake's observations pin
    /// the wire details: the session path is a uuid (no seq on the GET), the
    /// Referer carries the base URL + `x_padding`, and the client closes the
    /// h3 connection cleanly afterwards.
    #[tokio::test]
    async fn h3_loopback_get_and_post() {
        let (addr, obs, server_task) = spawn_h3_fake(false);
        let ctx = ctx_h3(addr, "packet-up");
        let mut t = connect_quic(&ctx).await.expect("h3 connect");
        t.write_all(b"hello").await.expect("upload write");
        let mut out = [0u8; H3_DOWNLOAD.len()];
        t.read_exact(&mut out).await.expect("download read");
        assert_eq!(&out[..], H3_DOWNLOAD);
        drop(t);

        wait_obs(&obs, |o| o.conn_closed).await;
        assert_packet_roundtrip(&obs.data.lock().expect("obs lock"));
        server_task.await.expect("server task");
    }

    /// Packet-up chunking + seq order + pacing: a > 1 MB tunnel write is
    /// split at `scMaxEachPostBytes` into consecutive seqs, each POST ≤
    /// 1 MB, paced ≥ `scMinPostsIntervalMs` apart (the first rides the idle
    /// window), in arrival order, each carrying the Referer. The split and
    /// the 30 ms sleep are client-side guarantees, so the assertions are
    /// lower bounds — deterministic, no flake.
    #[tokio::test]
    async fn h3_packet_up_seq_order_and_chunking() {
        let (addr, obs, server_task) = spawn_h3_fake(false);
        let ctx = ctx_h3(addr, "packet-up");
        let mut t = connect_quic(&ctx).await.expect("h3 connect");

        // 1.2 MB in one write: the upload loop splits it into a 1 MB +
        // 200 KB pair (the server 413s anything over the size cap).
        let payload = vec![0xABu8; MAX_POST_BYTES + 200_000];
        t.write_all(&payload).await.expect("upload write");
        let mut out = [0u8; H3_DOWNLOAD.len()];
        t.read_exact(&mut out).await.expect("download read");
        assert_eq!(&out[..], H3_DOWNLOAD);
        drop(t);

        // Both POSTs arrive (the channel-close flushes the tail after the
        // tunnel dropped), then the h3 connection closes.
        wait_obs(&obs, |o| o.posts.len() == 2 && o.conn_closed).await;
        assert_chunked_uploads(&obs.data.lock().expect("obs lock"), &payload);
        server_task.await.expect("server task");
    }

    /// The h3 stream-up path: session open (GET), one long-lived POST with
    /// a piped body — 200 immediately (xray hub.go), `Content-Type:
    /// application/grpc`, Referer present. The tunnel writer's drop ends
    /// the pipe: the fake reads the body to EOF, then the h3 connection
    /// closes.
    #[tokio::test]
    async fn h3_loopback_stream_up() {
        let (addr, obs, server_task) = spawn_h3_fake(false);
        let ctx = ctx_h3(addr, "stream-up");
        let mut t = connect_quic(&ctx).await.expect("h3 stream-up connect");
        t.write_all(b"hello").await.expect("upload write");
        let mut out = [0u8; H3_DOWNLOAD.len()];
        t.read_exact(&mut out).await.expect("download read");
        assert_eq!(&out[..], H3_DOWNLOAD);
        drop(t);

        wait_obs(&obs, |o| !o.stream_uploads.is_empty() && o.conn_closed).await;
        assert_stream_up_roundtrip(&obs.data.lock().expect("obs lock"));
        server_task.await.expect("server task");
    }

    /// Error path: a non-200 session-open GET must surface as a transport
    /// error from `connect_quic` (the v3 contract requires 200 everywhere),
    /// and the aborted session still closes the h3 connection.
    #[tokio::test]
    async fn h3_session_open_reject_surfaces_error() {
        let (addr, obs, server_task) = spawn_h3_fake(true);
        let ctx = ctx_h3(addr, "packet-up");
        let Err(err) = connect_quic(&ctx).await else {
            panic!("a 500 session open must fail connect_quic")
        };
        assert!(
            matches!(err, NativeError::TransportRejected { status: 500, .. }),
            "the peer's status is the typed evidence: {err}"
        );
        wait_obs(&obs, |o| o.conn_closed).await;
        server_task.await.expect("server task");
    }

    /// Assert the stream-one observations: ONE full-duplex request — no GET,
    /// no session — the POST carried the Referer + `application/grpc`, the
    /// upload arrived intact. Sync helper — keeps the `MutexGuard` out of
    /// the async test body.
    fn assert_stream_one_roundtrip(o: &H3Obs) {
        assert!(o.gets.is_empty(), "stream-one must not issue a GET: {o:#?}");
        assert_eq!(o.stream_one_reqs.len(), 1, "{o:#?}");
        let (referer, content_type) = &o.stream_one_reqs[0];
        assert_eq!(content_type, "application/grpc");
        assert_referer(referer);
        assert_eq!(o.stream_one_uploads.len(), 1, "{o:#?}");
        assert_eq!(&o.stream_one_uploads[0][..], &b"hello"[..]);
    }

    /// The h3 stream-one path: ONE full-duplex request (no GET, no
    /// session) — the POST body is the upload, the response body the
    /// download. The fake asserts the path is the base path only, the
    /// Referer, `application/grpc`, and no session/seq meta.
    #[tokio::test]
    async fn h3_loopback_stream_one() {
        let (addr, obs, server_task) = spawn_h3_fake(false);
        let ctx = ctx_h3(addr, "stream-one");
        let mut t = connect_quic(&ctx).await.expect("h3 stream-one connect");
        t.write_all(b"hello").await.expect("upload write");
        let mut out = [0u8; H3_DOWNLOAD.len()];
        t.read_exact(&mut out).await.expect("download read");
        assert_eq!(&out[..], H3_DOWNLOAD);
        drop(t);

        wait_obs(&obs, |o| !o.stream_one_uploads.is_empty() && o.conn_closed).await;
        assert_stream_one_roundtrip(&obs.data.lock().expect("obs lock"));
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn connect_quic_rejects_unknown_modes_before_dialing() {
        // The mode check precedes the quinn dial: unknown modes error
        // without any network step. stream-one is now a real mode — it
        // proceeds to the dial (a Dial error for the dead loopback port,
        // not a NotImplemented rejection).
        let ctx = ctx_h3("127.0.0.1:1".parse().unwrap(), "stream-one");
        let err = connect_quic(&ctx).await;
        // The quinn dial to the dead loopback port either refuses fast or
        // times out (a closed UDP port may drop packets silently) — both
        // prove stream-one proceeds to the network step instead of being
        // rejected as NotImplemented/Config.
        assert!(
            matches!(err, Err(NativeError::Dial(_) | NativeError::Timeout { .. })),
            "stream-one must dial, not be rejected"
        );
        let ctx = ctx_h3("127.0.0.1:1".parse().unwrap(), "bogus");
        let Err(err) = connect_quic(&ctx).await else {
            panic!("unknown mode must be rejected")
        };
        assert!(matches!(err, NativeError::Config(_)), "{err}");
    }

    #[tokio::test]
    async fn transport_connect_h3_with_base_is_config_error() {
        // xhttp+h3 as a later chain hop (base = Some) is forbidden: the
        // QUIC dial is a fresh connection that never reuses a base tunnel.
        let ctx = ctx_h3("127.0.0.1:1".parse().unwrap(), "packet-up");
        let Err(err) = crate::transport::connect(&ctx, Some(Box::new(tokio::io::empty()))).await
        else {
            panic!("base reuse must be rejected")
        };
        assert!(matches!(err, NativeError::Config(_)), "{err}");
    }

    #[test]
    fn self_contained_only_for_the_h3_arm() {
        let h3 = ctx_h3("127.0.0.1:1".parse().unwrap(), "packet-up");
        assert!(crate::transport::is_self_contained(&h3));
        let h1 = ctx_at("127.0.0.1:1".parse().unwrap(), "packet-up");
        assert!(!crate::transport::is_self_contained(&h1));
    }
    /// `H3Reader` borrow-slice + partial `ReadBuf` test: the reader consumes
    /// chunks without per-chunk allocation. We verify the reader assembles
    /// chunks correctly into the caller's buffer by reading in small chunks.
    #[tokio::test]
    async fn h3_reader_borrow_slice_partial_readbuf() {
        use tokio::io::AsyncReadExt;

        let (addr, obs, server_task) = spawn_h3_fake(false);
        let ctx = ctx_h3(addr, "packet-up");
        let mut t = connect_quic(&ctx).await.expect("h3 connect");

        t.write_all(b"hello").await.expect("upload write");
        let mut out = Vec::new();
        let mut buf = [0u8; 2]; // tiny buffer to force multiple poll_read calls
        loop {
            let n = t.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&out[..], H3_DOWNLOAD);
        drop(t);

        wait_obs(&obs, |o| o.conn_closed).await;
        assert_packet_roundtrip(&obs.data.lock().expect("obs lock"));
        server_task.await.expect("server task");
    }

    /// Stream-up X-blob drain hermetic test: the fake h3 server streams
    /// keepalive X-blobs into the upload response body (as xray hub.go does),
    /// and the client's `drain_h3` task must consume them without blocking the
    /// tunnel. We verify the fake sent X-blobs and the client finished cleanly.
    #[tokio::test]
    async fn h3_stream_up_xblob_drain() {
        let (addr, obs, server_task) = spawn_h3_fake(false);
        let ctx = ctx_h3(addr, "stream-up");
        let mut t = connect_quic(&ctx).await.expect("h3 stream-up connect");
        t.write_all(b"hello").await.expect("upload write");
        let mut out = [0u8; H3_DOWNLOAD.len()];
        t.read_exact(&mut out).await.expect("download read");
        assert_eq!(&out[..], H3_DOWNLOAD);
        drop(t);

        wait_obs(&obs, |o| !o.stream_uploads.is_empty() && o.conn_closed).await;
        let obs_data = {
            let o = obs.data.lock().expect("obs lock");
            assert_stream_up_roundtrip(&o);
            let xblobs_len = o.stream_xblobs.len();
            drop(o);
            xblobs_len
        };
        assert_eq!(obs_data, 3, "expected 3 X-blobs");
        server_task.await.expect("server task");
    }
}
