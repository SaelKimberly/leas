//! HTTP CONNECT proxy inbound: a local `CONNECT host:port` proxy that
//! accepts connections, routes them through the [`leas_route`] engine,
//! and forwards to direct / block / proxy outbounds.
//!
//! Composition mirrors [`super::Socks5Inbound`]: `inbound → router →
//! outbound`. The router is the compiled [`Engine`]; each
//! [`Decision::Route`] names an outbound tag resolved against
//! [`HttpInboundConfig::outbounds`]. The "proxy" outbound reuses
//! [`crate::connect`] via [`super::outbound::dial`].
//!
//! Scope (v1): `CONNECT` only, with optional `Basic` proxy authentication.
//! Any other method gets `501` (this proxy does not forward absolute-form
//! requests); a `CONNECT` without `host:port` gets `400`; an over-long head
//! gets `431`; a missing or wrong credential gets `407`; a blocked route gets
//! `403`; a failed outbound dial gets `502`; a routed connection gets `200
//! Connection Established` followed by a raw bidirectional relay.
//!
//! Every refusal is framed (`Content-Length` + `Connection: close`) and
//! carries a one-line reason, so a client can tell a PROXY refusal apart from
//! a destination failure.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use leas_route::engine::decide_async;
use leas_route::ir::NetworkMask;
use leas_route::{ConnMeta, Decision, Engine};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use super::outbound::{self, Outbound, OutboundKind};
use super::{
    DEFAULT_HTTP_INBOUND_TAG, TraceCtx, absorb_accept_error, net_to_target, target_to_net,
    traced_relay, warn_if_open_relay,
};
use crate::addr::TargetAddr;
use crate::error::{NativeError, timeouts};

/// Upper bound on the CONNECT request head (request line + headers).
/// CONNECT heads are tiny; anything larger is a slowloris / abuse.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// How long a refusal may spend discarding what the peer keeps sending before
/// the socket is closed. Short by design: the response and the FIN are already
/// out, and this is the abuse path.
const REFUSAL_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_millis(500);

/// How many further bytes a refusal discards. Comfortably above `MAX_HEAD_BYTES`,
/// because the point is to leave nothing unread at close, not to read the peer.
const REFUSAL_DRAIN_BYTES: usize = 64 * 1024;

/// Bytes of the previous chunk re-scanned for the head terminator, so a
/// terminator split across two reads is still found (`\r\n\r\n` minus one).
const HEAD_OVERLAP: usize = 3;

/// The `Basic` challenge sent with every `407`, already CRLF-terminated.
const PROXY_AUTHENTICATE: &str = "Proxy-Authenticate: Basic realm=\"leas\", charset=\"UTF-8\"\r\n";

/// Configuration for an [`HttpInbound`].
#[derive(Clone)]
pub struct HttpInboundConfig {
    /// Address to bind (e.g. `127.0.0.1:8080`).
    pub listen: SocketAddr,
    /// `Proxy-Authorization: Basic` credentials; `None` = no authentication.
    ///
    /// The native session ([`crate::server`]) has no credential source in the
    /// profile model, so it leaves this `None` and relies on the loopback
    /// bind; a non-loopback bind without credentials warns at bind time.
    pub auth: Option<(String, String)>,
    /// Inbound tag reported to the router (`ConnMeta.inbound_tag`).
    pub inbound_tag: String,
    /// Compiled routing engine.
    pub engine: Arc<Engine>,
    /// Tagged outbounds the router may select.
    pub outbounds: Vec<Outbound>,
    /// Per-connection telemetry (trace rows + byte counting); `None` off.
    pub trace: Option<TraceCtx>,
    /// When set, `serve` stops accepting and in-flight connections abort
    /// once the sender marks shutdown (`send(true)` or drop).
    pub shutdown: Option<watch::Receiver<bool>>,
}

impl HttpInboundConfig {
    /// Builds a config with the default inbound tag and no authentication.
    #[must_use]
    pub fn new(listen: SocketAddr, engine: Arc<Engine>, outbounds: Vec<Outbound>) -> Self {
        Self {
            listen,
            auth: None,
            inbound_tag: DEFAULT_HTTP_INBOUND_TAG.to_owned(),
            engine,
            outbounds,
            trace: None,
            shutdown: None,
        }
    }

    /// Requires `Basic` proxy authentication with these credentials.
    #[must_use]
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self
    }
}

impl fmt::Debug for HttpInboundConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpInboundConfig")
            .field("listen", &self.listen)
            .field("auth", &self.auth.as_ref().map(|_| "<redacted>"))
            .field("inbound_tag", &self.inbound_tag)
            .field("outbounds", &self.outbounds)
            .field("trace", &self.trace.is_some())
            .field("shutdown", &self.shutdown.is_some())
            .finish_non_exhaustive()
    }
}

/// A bound HTTP CONNECT proxy server.
pub struct HttpInbound {
    listener: TcpListener,
    config: Arc<HttpInboundConfig>,
}

impl HttpInbound {
    /// Binds the listener; call [`Self::serve`] to accept connections.
    ///
    /// # Errors
    /// Returns [`NativeError::Io`] when the listen address cannot be bound.
    pub async fn bind(config: HttpInboundConfig) -> Result<Self, NativeError> {
        let listener = TcpListener::bind(config.listen).await?;
        warn_if_open_relay(&listener, config.auth.is_some(), "http inbound");
        Ok(Self {
            listener,
            config: Arc::new(config),
        })
    }

    /// The bound local address (useful when listening on port 0).
    ///
    /// # Errors
    /// Returns [`NativeError::Io`] when the kernel reports no local address.
    pub fn local_addr(&self) -> Result<SocketAddr, NativeError> {
        self.listener.local_addr().map_err(NativeError::Io)
    }

    /// Runs the accept loop forever, spawning one task per connection.
    ///
    /// Returns when a configured `shutdown` receiver fires. When `shutdown` is
    /// set, in-flight connection tasks abort with it (the future drop closes
    /// their sockets).
    ///
    /// A failed `accept` never ends the loop: see [`absorb_accept_error`].
    ///
    /// # Errors
    /// Never fails today — every `accept` error is absorbed and retried, so the
    /// loop ends only on shutdown. The fallible signature stays for a listener
    /// fault a future revision cannot absorb.
    pub async fn serve(self) -> Result<(), NativeError> {
        loop {
            let accept = self.listener.accept();
            let accepted = match &self.config.shutdown {
                Some(rx) => {
                    let mut rx = rx.clone();
                    tokio::select! {
                        biased;
                        _ = rx.changed() => return Ok(()),
                        accepted = accept => accepted,
                    }
                }
                None => accept.await,
            };
            let (conn, peer) = match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    absorb_accept_error(&error, "http inbound").await;
                    continue;
                }
            };
            // Disable Nagle: interactive traffic through a local proxy should
            // not sit in the output buffer for up to 200ms (Go cores enable
            // TCP_NODELAY by default).
            if let Err(error) = conn.set_nodelay(true) {
                tracing::debug!(%peer, %error, "http inbound: set_nodelay failed");
            }
            let config = Arc::clone(&self.config);
            let shutdown = config.shutdown.clone();
            tokio::spawn(async move {
                let handle = handle_conn(config, conn, peer);
                match shutdown {
                    Some(rx) => {
                        let mut rx = rx;
                        tokio::select! {
                            biased;
                            _ = rx.changed() => {}
                            result = handle => {
                                if let Err(error) = result {
                                    tracing::debug!(%peer, %error, "http inbound: connection closed");
                                }
                            }
                        }
                    }
                    None => {
                        if let Err(error) = handle.await {
                            tracing::debug!(%peer, %error, "http inbound: connection closed");
                        }
                    }
                }
            });
        }
    }
}

/// One connection: read the CONNECT head, route, dial, relay.
async fn handle_conn(
    config: Arc<HttpInboundConfig>,
    conn: TcpStream,
    peer: SocketAddr,
) -> Result<(), NativeError> {
    let mut reader = BufReader::new(conn);

    let request = match tokio::time::timeout(
        timeouts::PROTOCOL,
        read_request(&mut reader, config.auth.as_ref()),
    )
    .await
    .map_err(|_| NativeError::Timeout {
        step: "http request",
        limit: timeouts::PROTOCOL,
    })? {
        Ok(request) => request,
        Err(refusal) => {
            // Best effort: a client that hung up mid-head cannot be told, and
            // that is its own fault, not a server failure.
            if let Err(error) = write_refusal(reader.into_inner(), refusal).await {
                tracing::debug!(%peer, %error, "http inbound: refusal not delivered");
            }
            return Ok(());
        }
    };

    handle_connect(&config, reader.into_inner(), peer, request).await
}

/// Handle a routed CONNECT: route the destination, dial the outbound, relay.
async fn handle_connect(
    config: &HttpInboundConfig,
    mut conn: TcpStream,
    peer: SocketAddr,
    request: ConnectRequest,
) -> Result<(), NativeError> {
    let ConnectRequest { target, pending } = request;

    // Route the destination.
    let mut meta = ConnMeta {
        target: target_to_net(&target),
        network: NetworkMask::TCP,
        inbound_tag: Some(config.inbound_tag.clone()),
        source: Some(peer),
        source_resolved_ips: Vec::new(),
        payload_prefix: None,
        sniffed: None,
        sni_host: None,
        resolved_host_ips: Vec::new(),
    };
    let decision = decide_async(&config.engine, &mut meta).await;

    match decision {
        Decision::Route { tag, override_addr } => {
            let Some(outbound) = config.outbounds.iter().find(|o| o.tag.as_str() == &*tag) else {
                tracing::warn!(%tag, "http inbound: routing decision named an unknown outbound");
                return write_refusal(&mut conn, Refusal::BadGateway).await;
            };
            match &outbound.kind {
                OutboundKind::Block => write_refusal(&mut conn, Refusal::Blocked).await,
                kind => {
                    let target = override_addr.map(|a| net_to_target(&a)).unwrap_or(target);
                    let mut upstream = match outbound::dial(kind, &target).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::warn!(
                                %tag,
                                ?target,
                                %error,
                                "http inbound: outbound dial failed"
                            );
                            return write_refusal(&mut conn, Refusal::BadGateway).await;
                        }
                    };
                    write_established(&mut conn).await?;
                    if let Some(trace) = &config.trace {
                        // The traced path replays `pending` inside its byte
                        // counters, so pipelined bytes are attributed `up`.
                        traced_relay(trace, conn, upstream, &target, &pending).await
                    } else {
                        if !pending.is_empty() {
                            upstream
                                .write_all(&pending)
                                .await
                                .map_err(NativeError::Io)?;
                        }
                        Box::pin(outbound::relay(conn, upstream)).await
                    }
                }
            }
        }
        // Rejections are policy refusals, not gateway failures.
        Decision::Reject { .. } | Decision::HijackDns => {
            if matches!(decision, Decision::HijackDns) {
                tracing::warn!("http inbound: HijackDns decision is not implemented; rejecting");
            }
            write_refusal(&mut conn, Refusal::Blocked).await
        }
    }
}

/// A parsed, authorised CONNECT request.
struct ConnectRequest {
    /// The tunnel destination from the request line.
    target: TargetAddr,
    /// Tunnel bytes the client pipelined behind the head — a TLS `ClientHello`
    /// written in the same `write` as the `CONNECT` line.
    ///
    /// They belong to the tunnel: dropping them (which is what handing the
    /// socket on without the parser's buffer does) truncates the stream, and
    /// the tunnel then stalls waiting for a handshake that was already sent.
    pending: Vec<u8>,
}

/// A CONNECT answered without routing: an HTTP status plus the one-line reason
/// the client is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// Malformed request line or head.
    BadRequest,
    /// The head exceeded [`MAX_HEAD_BYTES`].
    HeadTooLarge,
    /// A method other than `CONNECT`.
    MethodNotSupported,
    /// Missing, malformed, or wrong proxy credentials.
    AuthRequired,
    /// Policy refusal: a `Block` outbound or a `Reject` decision.
    Blocked,
    /// Unknown outbound tag, or the outbound could not dial.
    BadGateway,
}

impl Refusal {
    /// The status line text.
    const fn status(self) -> &'static str {
        match self {
            Self::BadRequest => "400 Bad Request",
            Self::HeadTooLarge => "431 Request Header Fields Too Large",
            Self::MethodNotSupported => "501 Not Implemented",
            Self::AuthRequired => "407 Proxy Authentication Required",
            Self::Blocked => "403 Forbidden",
            Self::BadGateway => "502 Bad Gateway",
        }
    }

    /// The plain-text body: one line naming what this proxy refused.
    const fn reason(self) -> &'static str {
        match self {
            Self::BadRequest => "malformed request: expected CONNECT host:port HTTP/1.1\n",
            Self::HeadTooLarge => "request head exceeds this proxy's head budget\n",
            Self::MethodNotSupported => {
                "this proxy implements CONNECT tunnelling only; \
                 plain (absolute-form) HTTP proxying is not supported\n"
            }
            Self::AuthRequired => "proxy credentials required\n",
            Self::Blocked => "destination refused by the routing policy\n",
            Self::BadGateway => "the outbound could not reach the destination\n",
        }
    }

    /// Extra header line this status requires, already CRLF-terminated.
    const fn extra_header(self) -> &'static str {
        match self {
            Self::AuthRequired => PROXY_AUTHENTICATE,
            _ => "",
        }
    }
}

/// Read and validate the request head: method, target, credentials.
async fn read_request<S>(
    stream: &mut BufReader<S>,
    auth: Option<&(String, String)>,
) -> Result<ConnectRequest, Refusal>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let (head, pending) = read_head(stream).await?;
    let mut lines = head.lines();
    let request_line = lines.next().ok_or(Refusal::BadRequest)?;
    let target = parse_request_line(request_line)?;
    if let Some(expected) = auth {
        authorize(lines, expected)?;
    }
    Ok(ConnectRequest { target, pending })
}

/// Read the request head, returning its text plus the bytes that arrived
/// after the blank line.
///
/// `read_line` cannot do this job twice over: it grows its `String` until a
/// newline arrives (a client that sends 4 GiB without one is a memory `DoS`),
/// and it hides the bytes already buffered past the head — which belong to the
/// TUNNEL. This scan copies nothing beyond the head, caps the bytes it will
/// buffer at [`MAX_HEAD_BYTES`], and hands the remainder back for replay.
async fn read_head<S>(stream: &mut BufReader<S>) -> Result<(String, Vec<u8>), Refusal>
where
    S: tokio::io::AsyncRead + Unpin,
{
    skip_leading_newlines(stream).await?;

    let mut head: Vec<u8> = Vec::new();
    loop {
        let available = stream.fill_buf().await.map_err(|_| Refusal::BadRequest)?;
        if available.is_empty() {
            // EOF before the blank line: there is no request to answer.
            return Err(Refusal::BadRequest);
        }
        let chunk_start = head.len();
        // Re-scan the tail of what we already have: the terminator may straddle
        // two reads.
        let scan_from = chunk_start.saturating_sub(HEAD_OVERLAP);
        head.extend_from_slice(available);
        let chunk_len = head.len() - chunk_start;

        if let Some(offset) = find_head_end(&head[scan_from..]) {
            let end = scan_from + offset;
            if end > MAX_HEAD_BYTES {
                return Err(Refusal::HeadTooLarge);
            }
            // Consume the head only; the rest stays buffered for the tunnel.
            debug_assert!(end > chunk_start, "the terminator ends in the new chunk");
            stream.consume(end.saturating_sub(chunk_start));
            head.truncate(end);
            return Ok((
                String::from_utf8_lossy(&head).into_owned(),
                stream.buffer().to_vec(),
            ));
        }

        stream.consume(chunk_len);
        if head.len() >= MAX_HEAD_BYTES {
            return Err(Refusal::HeadTooLarge);
        }
    }
}

/// Consume empty lines before the request line.
///
/// RFC 9112 §2.2: a server SHOULD ignore at least one empty line received
/// where a request line was expected (clients that reuse a connection may
/// prepend a stray CRLF). Bounded by the head budget, so this is not an
/// unlimited junk channel.
async fn skip_leading_newlines<S>(stream: &mut BufReader<S>) -> Result<(), Refusal>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut skipped = 0usize;
    loop {
        let available = stream.fill_buf().await.map_err(|_| Refusal::BadRequest)?;
        if available.is_empty() {
            return Err(Refusal::BadRequest);
        }
        let junk = available
            .iter()
            .take_while(|byte| matches!(**byte, b'\r' | b'\n'))
            .count();
        if junk == 0 {
            return Ok(());
        }
        stream.consume(junk);
        skipped += junk;
        if skipped >= MAX_HEAD_BYTES {
            return Err(Refusal::HeadTooLarge);
        }
    }
}

/// Index just past the blank line that ends a request head, if present.
///
/// Both terminators are accepted: `\r\n\r\n` per RFC 9112, and a bare `\n\n`
/// from a hand-rolled client (the previous `read_line` path tolerated lone
/// LFs, and silently dropping that tolerance would be a regression).
fn find_head_end(buf: &[u8]) -> Option<usize> {
    let crlf = find_subslice(buf, b"\r\n\r\n").map(|at| at + 4);
    let lf = find_subslice(buf, b"\n\n").map(|at| at + 2);
    match (crlf, lf) {
        (Some(crlf), Some(lf)) => Some(crlf.min(lf)),
        (found, None) | (None, found) => found,
    }
}

/// First index of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Check `Proxy-Authorization: Basic base64(user:pass)` against the configured
/// credentials.
///
/// The client's token is DECODED rather than the expected value encoded: the
/// decoded `user:pass` bytes compare equal whatever legal spelling the client
/// picked. Missing, malformed, and wrong credentials all answer the same 407,
/// so a prober learns nothing about which half was wrong. The header never
/// reaches the tunnel — only the bytes AFTER the blank line are replayed.
fn authorize<'a>(
    headers: impl Iterator<Item = &'a str>,
    expected: &(String, String),
) -> Result<(), Refusal> {
    let want = format!("{}:{}", expected.0, expected.1);
    for line in headers {
        // The blank line ends the head; nothing past it is a header.
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let Some((scheme, token)) = value.trim().split_once(' ') else {
            continue;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            continue;
        }
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token.trim()) else {
            continue;
        };
        if decoded == want.as_bytes() {
            return Ok(());
        }
    }
    Err(Refusal::AuthRequired)
}

/// Parse `CONNECT host:port HTTP/1.1` into a [`TargetAddr`].
///
/// [`Refusal::MethodNotSupported`] for another method (the client asked for
/// plain proxying, which this inbound does not implement — a 400 would claim
/// the request was malformed), [`Refusal::BadRequest`] for a malformed line or
/// target (missing port, unparseable port, empty host). IPv6 literals may be
/// bracketed (`[::1]:80`) or bare (`::1` is ambiguous — treated as host
/// without port, hence rejected unless it carries a port after `]:`).
fn parse_request_line(line: &str) -> Result<TargetAddr, Refusal> {
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or(Refusal::BadRequest)?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(Refusal::MethodNotSupported);
    }
    let authority = parts.next().ok_or(Refusal::BadRequest)?;
    let version = parts.next().ok_or(Refusal::BadRequest)?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return Err(Refusal::BadRequest);
    }
    parse_authority(authority).ok_or(Refusal::BadRequest)
}

/// Split `host:port` authority into a [`TargetAddr`].
fn parse_authority(authority: &str) -> Option<TargetAddr> {
    if authority.is_empty() {
        return None;
    }
    // Bracketed IPv6: [::1]:80.
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        if host.is_empty() || port.is_empty() {
            return None;
        }
        let port: u16 = port.parse().ok()?;
        return Some(TargetAddr::new(host, port));
    }
    // host:port — last colon separates the port (rejects bare IPv6).
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() {
        return None;
    }
    // A second colon means a bare IPv6 literal without brackets/port.
    if host.contains(':') {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    Some(TargetAddr::new(host, port))
}

/// The tunnel is open: a bare `200` with no body and no framing headers —
/// every byte after this belongs to the tunnel (RFC 9110 §9.3.6).
async fn write_established<S>(conn: &mut S) -> Result<(), NativeError>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(NativeError::Io)?;
    conn.flush().await.map_err(NativeError::Io)?;
    Ok(())
}

/// Answer a refusal: status line, framed one-line body, `Connection: close`.
///
/// One write, because `TCP_NODELAY` is on and a split head and body would cost
/// two packets. The body plus its `Content-Length` is what lets a client tell
/// that the PROXY refused rather than the destination, and `Connection: close`
/// says the socket is about to go — which it is, as the caller drops it.
///
/// The refusal has to actually arrive, and on Windows it did not: the caller
/// drops a socket whose receive queue still holds the oversized head the peer
/// is still sending, and closing with unread data makes the stack send an RST
/// that discards the response in flight (`oversized_head_is_refused` failed
/// with an empty read). So the close is sequenced instead: write, flush,
/// half-close our write side so the peer sees a FIN, then discard the rest of
/// what it keeps sending. Drained, the close is graceful and no RST is
/// generated.
async fn write_refusal<S>(mut conn: S, refusal: Refusal) -> Result<(), NativeError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let body = refusal.reason();
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         {extra}\r\n\
         {body}",
        status = refusal.status(),
        len = body.len(),
        extra = refusal.extra_header(),
    );
    conn.write_all(response.as_bytes())
        .await
        .map_err(NativeError::Io)?;
    conn.flush().await.map_err(NativeError::Io)?;
    conn.shutdown().await.map_err(NativeError::Io)?;
    drain_refused_head(&mut conn).await;
    Ok(())
}

/// Discard what a refused peer keeps sending, so the socket can be closed
/// without unread data and therefore without an RST.
///
/// Bounded twice on purpose: a peer that keeps pushing must not hold the
/// connection task open, and the budget has to be short because this is the
/// abuse path — a client that ignores the refusal does not get to keep a task
/// alive for `timeouts::PROTOCOL`'s ten seconds. Both limits are about
/// ordering, not about reading the peer: the response is already flushed and
/// the FIN already sent before this runs.
async fn drain_refused_head<S>(conn: &mut S)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let deadline = tokio::time::Instant::now() + REFUSAL_DRAIN_BUDGET;
    let mut scratch = [0u8; 4096];
    let mut discarded = 0usize;
    while discarded < REFUSAL_DRAIN_BYTES {
        match tokio::time::timeout_at(deadline, conn.read(&mut scratch)).await {
            // EOF, deadline, or a reset: there is nothing left to drain either way.
            Ok(Ok(0) | Err(_)) | Err(_) => break,
            Ok(Ok(read)) => discarded += read,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine as _;
    use leas_route::ir::{DefaultRoute, ResolveStrategy, RuleSet};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{MAX_HEAD_BYTES, PROXY_AUTHENTICATE, Refusal, parse_authority, parse_request_line};
    use crate::addr::TargetAddr;

    #[test]
    fn valid_connect_request_line_parses() {
        let target = parse_request_line("CONNECT example.com:443 HTTP/1.1").expect("parses");
        assert_eq!(target, TargetAddr::new("example.com", 443));
    }

    #[test]
    fn non_connect_method_is_not_implemented() {
        for line in [
            "GET http://example.com/ HTTP/1.1",
            "POST http://example.com/ HTTP/1.1",
            "HEAD example.com:80 HTTP/1.1",
        ] {
            assert_eq!(
                parse_request_line(line),
                Err(Refusal::MethodNotSupported),
                "{line}"
            );
        }
    }

    #[test]
    fn missing_port_rejected() {
        for authority in [
            "example.com",
            "example.com:",
            ":443",
            "",
            "127.0.0.1:notaport",
        ] {
            assert!(parse_authority(authority).is_none(), "{authority}");
        }
    }

    #[test]
    fn bracketed_ipv6_authority_parses() {
        let target = parse_authority("[::1]:8080").expect("parses");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn malformed_request_lines_rejected() {
        for line in [
            "",
            "CONNECT",
            "CONNECT example.com:443",
            "CONNECT example.com:443 HTTP/1.1 extra",
            "CONNECT example.com:443 FTP/1.0",
            "CONNECT example.com HTTP/1.1",
        ] {
            assert_eq!(
                parse_request_line(line),
                Err(Refusal::BadRequest),
                "{line:?}"
            );
        }
    }

    /// Hermetic end-to-end: CONNECT through a Direct outbound against a
    /// tiny TCP echo server (both bound to 127.0.0.1:0).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_direct_relays_to_echo() {
        let echo = spawn_echo().await;
        let (addr, handle) = spawn_inbound(direct_config()).await;

        let mut client = TcpStream::connect(addr).await.expect("connect inbound");
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            echo.port()
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("write CONNECT");
        let head = read_response_head(&mut client).await;
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "expected 200, got: {head}"
        );

        client.write_all(b"ping").await.expect("write payload");
        let mut echo_back = [0u8; 4];
        read_exact_within(&mut client, &mut echo_back).await;
        assert_eq!(&echo_back, b"ping");

        handle.abort();
    }

    /// The byte-loss regression: a client that writes its CONNECT head and its
    /// first tunnel bytes in ONE `write_all` must still see those bytes reach
    /// the destination. Handing the socket on without the parser's buffered
    /// remainder silently ate them, and the tunnel then stalled.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn payload_pipelined_with_the_head_is_replayed() {
        let echo = spawn_echo().await;
        let (addr, handle) = spawn_inbound(direct_config()).await;

        let mut client = TcpStream::connect(addr).await.expect("connect inbound");
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nhello-tunnel",
            echo.port()
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("write CONNECT + payload");

        let head = read_response_head(&mut client).await;
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "expected 200, got: {head}"
        );
        let mut echoed = [0u8; 12];
        read_exact_within(&mut client, &mut echoed).await;
        assert_eq!(&echoed, b"hello-tunnel", "pipelined bytes reached the echo");

        handle.abort();
    }

    /// The traced path replays the pipelined bytes THROUGH the byte counters,
    /// so they are attributed `up` instead of bypassing accounting entirely.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipelined_payload_is_counted_as_up() {
        use crate::telemetry::{Telemetry, TraceKind, TraceSecurity};

        let echo = spawn_echo().await;
        let (telemetry, _events) = Telemetry::new(64);
        let mut config = direct_config();
        config.trace = Some(super::TraceCtx {
            telemetry: telemetry.clone(),
            kind: TraceKind::Http,
            protocol: "direct".into(),
            transport: "-".into(),
            security: TraceSecurity::Plain,
        });
        let (addr, handle) = spawn_inbound(config).await;

        let mut client = TcpStream::connect(addr).await.expect("connect inbound");
        client
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\npipelined",
                    echo.port()
                )
                .as_bytes(),
            )
            .await
            .expect("write CONNECT + payload");

        let head = read_response_head(&mut client).await;
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "expected 200, got: {head}"
        );
        let mut echoed = [0u8; 9];
        read_exact_within(&mut client, &mut echoed).await;
        assert_eq!(&echoed, b"pipelined");

        assert_eq!(
            telemetry.drain_traffic(),
            (9, 9),
            "the replayed head payload counts as up, the echo as down"
        );

        handle.abort();
    }

    /// A non-CONNECT method is answered 501 (not 400: the request is
    /// well-formed, the proxy just does not implement plain proxying) with a
    /// framed body.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn non_connect_method_gets_501() {
        let (addr, handle) = spawn_inbound(direct_config()).await;

        let mut client = TcpStream::connect(addr).await.expect("connect inbound");
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .expect("write request");
        let response = read_to_end_within(&mut client).await;

        assert!(
            response.starts_with("HTTP/1.1 501 Not Implemented"),
            "expected 501: {response}"
        );
        assert!(
            response.contains("Connection: close") && response.contains("Content-Length: "),
            "refusal is framed and closes: {response}"
        );
        assert!(
            response.contains("CONNECT tunnelling only"),
            "body names the limitation: {response}"
        );
        handle.abort();
    }

    /// A `Block` outbound answers 403 — a policy refusal, not a gateway fault.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocked_route_gets_403() {
        let config = config_with(
            "block",
            vec![super::Outbound {
                tag: "block".to_owned(),
                kind: super::OutboundKind::Block,
            }],
        );
        let (addr, handle) = spawn_inbound(config).await;

        let response = connect_and_read(addr, "example.com:443", None).await;
        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden"),
            "expected 403: {response}"
        );
        assert!(
            response.contains("routing policy"),
            "body names the policy: {response}"
        );
        handle.abort();
    }

    /// A decision naming an outbound that does not exist is a gateway fault.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_outbound_tag_gets_502() {
        let config = config_with("ghost", Vec::new());
        let (addr, handle) = spawn_inbound(config).await;

        let response = connect_and_read(addr, "example.com:443", None).await;
        assert!(
            response.starts_with("HTTP/1.1 502 Bad Gateway"),
            "expected 502: {response}"
        );
        handle.abort();
    }

    /// A head that never ends must be refused, not buffered forever.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_head_is_refused() {
        let (addr, handle) = spawn_inbound(direct_config()).await;

        let client = TcpStream::connect(addr).await.expect("connect inbound");
        // Write and read concurrently: the proxy stops reading once the budget
        // is spent, and closing a socket with unread bytes queued can turn the
        // FIN into an RST that would discard the refusal in flight.
        let (mut read_half, mut write_half) = client.into_split();
        let writer = tokio::spawn(async move {
            // No newline, ever: the old `read_line` loop grew its String
            // without bound because the budget was only checked between lines.
            let mut junk = b"CONNECT example.com:443 HTTP/1.1\r\nX-Junk: ".to_vec();
            junk.extend(std::iter::repeat_n(b'j', MAX_HEAD_BYTES + 4096));
            let _ = write_half.write_all(&junk).await;
        });

        let response = read_line_within(&mut read_half).await;
        // A refusal must be the end of a *graceful* close. Closing with this
        // junk still unread makes the stack send an RST, which is how the
        // refusal got discarded on Windows — and here that shows up as a read
        // error where EOF is required.
        let mut rest = Vec::new();
        let after =
            tokio::time::timeout(Duration::from_secs(5), read_half.read_to_end(&mut rest)).await;
        assert!(
            matches!(after, Ok(Ok(_))),
            "refusal must be followed by a clean EOF, not a reset: {after:?}"
        );
        writer.abort();
        assert!(
            response.starts_with("HTTP/1.1 431"),
            "expected 431: {response}"
        );
        handle.abort();
    }

    /// With credentials configured, a CONNECT without them is 407 (and says
    /// how to authenticate), a wrong one is 407, and the right one tunnels.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxy_auth_gates_the_tunnel() {
        let echo = spawn_echo().await;
        let (addr, handle) = spawn_inbound(direct_config().with_auth("user", "pass")).await;
        let dest = format!("127.0.0.1:{}", echo.port());

        let response = connect_and_read(addr, &dest, None).await;
        assert!(
            response.starts_with("HTTP/1.1 407"),
            "missing credentials: {response}"
        );
        assert!(
            response.contains(PROXY_AUTHENTICATE.trim_end()),
            "407 offers Basic: {response}"
        );

        let wrong = base64::engine::general_purpose::STANDARD.encode("user:nope");
        let response = connect_and_read(addr, &dest, Some(&wrong)).await;
        assert!(
            response.starts_with("HTTP/1.1 407"),
            "wrong credentials: {response}"
        );

        let good = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut client = TcpStream::connect(addr).await.expect("connect inbound");
        client
            .write_all(
                format!("CONNECT {dest} HTTP/1.1\r\nProxy-Authorization: Basic {good}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("write CONNECT");
        let head = read_response_head(&mut client).await;
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "good credentials tunnel: {head}"
        );
        client.write_all(b"ping").await.expect("write payload");
        let mut echo_back = [0u8; 4];
        read_exact_within(&mut client, &mut echo_back).await;
        assert_eq!(&echo_back, b"ping");

        handle.abort();
    }

    // Helpers
    // *************************************************************************

    /// An engine whose default route names `tag`.
    fn engine_for(tag: &str) -> Arc<leas_route::Engine> {
        Arc::new(
            leas_route::Engine::build(RuleSet {
                rules: Vec::new(),
                default: DefaultRoute::Route {
                    tag: tag.to_owned(),
                },
                resolve_strategy: ResolveStrategy::AsIs,
                probes: Vec::new(),
            })
            .expect("engine builds"),
        )
    }

    /// A config on 127.0.0.1:0 routing everything to `tag`.
    fn config_with(tag: &str, outbounds: Vec<super::Outbound>) -> super::HttpInboundConfig {
        super::HttpInboundConfig::new(
            "127.0.0.1:0".parse().expect("listen addr"),
            engine_for(tag),
            outbounds,
        )
    }

    /// A config routing everything to a Direct outbound.
    fn direct_config() -> super::HttpInboundConfig {
        config_with(
            "direct",
            vec![super::Outbound {
                tag: "direct".to_owned(),
                kind: super::OutboundKind::Direct,
            }],
        )
    }

    /// Bind and serve `config`; returns its address and the serve task.
    async fn spawn_inbound(
        config: super::HttpInboundConfig,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let inbound = super::HttpInbound::bind(config)
            .await
            .expect("bind inbound");
        let addr = inbound.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let _ = inbound.serve().await;
        });
        (addr, handle)
    }

    /// Send one CONNECT (optionally with a `Basic` token) and read the whole
    /// refusal the proxy writes before closing.
    async fn connect_and_read(addr: SocketAddr, dest: &str, basic: Option<&str>) -> String {
        let mut client = TcpStream::connect(addr).await.expect("connect inbound");
        let auth = basic.map_or_else(String::new, |token| {
            format!("Proxy-Authorization: Basic {token}\r\n")
        });
        client
            .write_all(format!("CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n{auth}\r\n").as_bytes())
            .await
            .expect("write CONNECT");
        read_to_end_within(&mut client).await
    }

    /// Read up to the response head's blank line (the tunnel stays open, so
    /// reading to EOF would block).
    async fn read_response_head(client: &mut TcpStream) -> String {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            read_exact_within(client, &mut byte).await;
            head.extend_from_slice(&byte);
            assert!(head.len() < 4096, "response head bounded");
        }
        String::from_utf8(head).expect("head utf8")
    }

    /// Read until the proxy closes the connection, with a deadline so a
    /// regression fails the test instead of hanging it.
    async fn read_to_end_within(client: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut buf))
            .await
            .expect("response within 5s")
            .expect("read response");
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// `read_exact` with a deadline: a lost byte must fail, not hang.
    async fn read_exact_within(client: &mut TcpStream, buf: &mut [u8]) {
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(buf))
            .await
            .expect("bytes within 5s")
            .expect("read bytes");
    }

    /// Read one line with a deadline, tolerating the close that follows a
    /// refusal: the status line is all these cases assert on.
    async fn read_line_within<R>(reader: &mut R) -> String
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut line = Vec::new();
        while !line.ends_with(b"\n") {
            let mut byte = [0u8; 1];
            let read = tokio::time::timeout(Duration::from_secs(5), reader.read(&mut byte))
                .await
                .expect("status line within 5s");
            match read {
                Ok(0) | Err(_) => break,
                Ok(_) => line.extend_from_slice(&byte),
            }
        }
        String::from_utf8_lossy(&line).into_owned()
    }

    /// A TCP echo server; returns its bound address.
    async fn spawn_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind echo listener");
        let addr = listener.local_addr().expect("echo addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }
}
