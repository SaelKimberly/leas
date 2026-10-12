//! One HTTP request through a native tunnel — the real-ping primitive.
//!
//! `fetch` dials the proxy (the full dial → security → transport → protocol
//! chain) to the request's host:port and hands the tunnel to `fetch_over`;
//! `fetch_over` is the stream-level half (optional target TLS + one HTTP/1.1
//! request), so it is unit-testable over a plain socket without a proxy.
//!
//! The hyper glue is the crate's own (`transport::http::{conn, body}`) — the
//! same layer the xhttp/v2rayhttp transports use, so request framing, chunked
//! responses and the driver task are not re-implemented here.
//!
//! TLS to the destination verifies against the Mozilla root program
//! (`WebPkiVerifier::webpki_roots`) and NEVER falls back to `insecure`: this is
//! a real request to a real host, and a probe that cannot authenticate the
//! destination must fail loudly (decision 17 — no blanket skip).
//!
//! ALPN is pinned to `http/1.1` deliberately: leaving `TlsConfig::alpn` unset
//! offers the *profile's* own list (chrome_130 = h2 + http/1.1), the target
//! then negotiates h2, and a hyper http1 client over that stream breaks.

use std::sync::Arc;
use std::time::{Duration, Instant};

use http::header::{HOST, USER_AGENT};
use hyper::body::Incoming;
use leas_tls::client::{self, TlsConfig};
use leas_tls::error::TlsError;
use leas_tls::verify::WebPkiVerifier;

use crate::BoxStream;
use crate::addr::TargetAddr;
use crate::context::NativeConnectParams;
use crate::error::NativeError;
use crate::transport::http::body::{IncomingReader, ReqBody};
use crate::transport::http::conn::h1_client;

/// Request method for a probe. Deliberately not `hyper::Method`: the caller
/// (the TUI ops layer) does not depend on hyper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMethod {
    Get,
    Head,
}

/// One request to issue over a tunnel.
#[derive(Debug, Clone, Copy)]
pub struct ProbeRequest<'a> {
    /// Destination host (also the TLS server name when `https`).
    pub host: &'a str,
    pub port: u16,
    pub https: bool,
    pub method: ProbeMethod,
    /// Origin-form path, query string included (`/generate_204`, `/json/?x=1`).
    pub path: &'a str,
    /// Budget for the request (the body read is capped by the same value).
    pub timeout: Duration,
}

/// A completed probe: the response head plus the body (capped).
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Time from the start of the request to the response HEAD — the probe's
    /// latency (the body read is not part of it).
    pub elapsed: Duration,
}

/// Upper bound on a probe body. A probe reads a `generate_204` (empty) or a
/// small JSON document; anything larger is a failure, not a truncation.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Dial `req.host:req.port` through `params` and issue `req` over the tunnel.
///
/// The whole attempt runs under ONE deadline of `req.timeout` (the caller's
/// `real_ping_timeout_secs`): dial, security handshake, transport upgrade,
/// protocol handshake, target TLS and the request head. The engine's per-step
/// limits (`timeouts::DIAL`/`SECURITY`/… , 10 s each) are defence in depth, not
/// the contract — without this wrapper a 5 s setting let a probe spend 10 s in
/// the dial alone and report `timeout on tcp dial (limit 10s)`.
pub async fn fetch(
    mut params: NativeConnectParams,
    req: &ProbeRequest<'_>,
) -> Result<ProbeResponse, NativeError> {
    params.target = TargetAddr::new(req.host, req.port);
    let started = Instant::now();
    // Boxed: the wrapped attempt's state machine carries the dial, the engine
    // TLS handshake and the hyper request together, and every caller awaits it
    // inside its own function — one box per attempt keeps those futures small.
    let attempt = async move {
        // The SAME predicate the inbound dial uses: a link that resolved mux goes
        // through the mux protocol phase and one session, so the probe cannot
        // report a plugin row as "server unreachable" when the real cause is a
        // missing mux frame (v2ray-plugin's server mandates mux).
        let tunnel = if params.mux {
            // The session owns its tunnel here too, for the same keepalive
            // reason as the inbound dial.
            let mux = crate::connect_mux(&params).await?;
            crate::mux_session::open_session(mux, &params.target).await?
        } else {
            Box::new(crate::connect(params).await?)
        };
        fetch_over(tunnel, req).await
    };
    let response = Box::pin(tokio::time::timeout(req.timeout, attempt))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "probe attempt",
            limit: req.timeout,
        })??;
    // The probe's latency is the whole span, the dial included — the same span
    // the subprocess probe measured through its local SOCKS hop.
    Ok(ProbeResponse {
        elapsed: started.elapsed(),
        ..response
    })
}

/// Issue `req` over an already-connected stream (the target TLS wrap included
/// when `req.https`). Public so the HTTP half is testable over a plain socket.
pub async fn fetch_over<S: crate::Stream + 'static>(
    io: S,
    req: &ProbeRequest<'_>,
) -> Result<ProbeResponse, NativeError> {
    let start = Instant::now();
    let stream: BoxStream = if req.https {
        // The TARGET leg (the probe URL's host), not the proxy leg. It reports
        // plain `Tls` and must never carry the typed proxy causes: a target
        // certificate, or a target that answers cleartext, says nothing about
        // the config being probed. `target_leg_tls_failure_carries_no_evidence`
        // pins that — an "unify the two TLS mappings" refactor breaks the test
        // instead of purging healthy configs.
        let tls = client::connect(Box::new(io) as BoxStream, &tls_config(req.host))
            .await
            .map_err(target_leg_error)?;
        Box::new(tls)
    } else {
        Box::new(io)
    };

    let mut sender = h1_client(stream).await?;
    // Origin-form target (`/path?query`): an absolute URI would be written
    // verbatim into the request line, which is not what an origin server
    // expects (and `Host` is set explicitly below).
    let request = hyper::Request::builder()
        .method(method_of(req.method))
        .uri(req.path)
        .header(HOST, host_header(req))
        .header(USER_AGENT, "leas/probe")
        .body(ReqBody::Empty)
        .map_err(|e| NativeError::Transport(format!("probe request: {e}")))?;

    let response = tokio::time::timeout(req.timeout, sender.send_request(request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "probe request",
            limit: req.timeout,
        })?
        .map_err(|e| NativeError::Transport(format!("probe request: {e}")))?;

    // The head has arrived: this is the measurement point.
    let elapsed = start.elapsed();
    let status = response.status().as_u16();
    let body = read_body(response.into_body(), req.timeout).await?;
    Ok(ProbeResponse {
        status,
        body,
        elapsed,
    })
}

/// Classify a TARGET-leg TLS failure by the stage that actually failed.
///
/// The engine's record layer reads the tunnel with `read_exact`, so an EOF from
/// the stream underneath surfaces as `TlsError::Io` — and mapping that to
/// [`NativeError::Tls`] counted a PROTOCOL-stage EOF as a TLS problem (measured:
/// 151 rows of the 2026-09-21 run, e.g. `vless response header truncated
/// (EOF)`). An `UnexpectedEof` here means the tunnel ended before the peer
/// answered, which is [`NativeError::TunnelClosed`] → `ProbeClass::Protocol`.
///
/// Classified from the io error's KIND, never its message: re-parsing text is
/// what the class system exists to avoid.
///
/// The target leg must still never carry the typed PROXY causes (a target
/// certificate says nothing about the config) — `TunnelClosed` proves nothing
/// either, so `target_leg_tls_failure_carries_no_evidence` keeps holding.
fn target_leg_error(e: TlsError) -> NativeError {
    match e {
        TlsError::Io(io)
            if matches!(
                io.kind(),
                // A graceful close: `read_exact` sees 0 bytes.
                std::io::ErrorKind::UnexpectedEof
                    // An abrupt close (a reset, e.g. the peer closing with unread
                    // data pending). Measured: the probe's own test server produced
                    // this rather than an EOF, and the field data carries both
                    // (`early eof` and `Connection reset by peer`).
                    | std::io::ErrorKind::ConnectionReset
            ) =>
        {
            NativeError::TunnelClosed {
                detail: format!("the tunnel ended during the target handshake: {io}"),
            }
        }
        other => NativeError::Tls(other.to_string()),
    }
}

/// Plain TLS to the destination, WebPKI-verified, `http/1.1` only.
fn tls_config(host: &str) -> TlsConfig {
    let mut config = TlsConfig::plain(
        None,
        Arc::new(WebPkiVerifier::webpki_roots()),
        host.to_string(),
    );
    config.alpn = Some(vec![b"http/1.1".to_vec()]);
    config
}

const fn method_of(method: ProbeMethod) -> hyper::Method {
    match method {
        ProbeMethod::Get => hyper::Method::GET,
        ProbeMethod::Head => hyper::Method::HEAD,
    }
}

/// `Host` header: the bare host on the scheme's default port, else host:port.
fn host_header(req: &ProbeRequest<'_>) -> String {
    let default_port = if req.https { 443 } else { 80 };
    if req.port == default_port {
        req.host.to_string()
    } else {
        format!("{}:{}", req.host, req.port)
    }
}

/// Read the body under the request timeout, refusing anything over
/// [`MAX_BODY_BYTES`] (a silent truncation would turn a wrong response into a
/// plausible one).
async fn read_body(body: Incoming, timeout: Duration) -> Result<Vec<u8>, NativeError> {
    let mut reader = IncomingReader::new(body);
    let mut limited = tokio::io::AsyncReadExt::take(&mut reader, MAX_BODY_BYTES as u64 + 1);
    let mut out = Vec::new();
    tokio::time::timeout(
        timeout,
        tokio::io::AsyncReadExt::read_to_end(&mut limited, &mut out),
    )
    .await
    .map_err(|_| NativeError::Timeout {
        step: "probe body",
        limit: timeout,
    })?
    .map_err(|e| NativeError::Transport(format!("probe body: {e}")))?;
    if out.len() > MAX_BODY_BYTES {
        return Err(NativeError::Transport(format!(
            "probe body exceeds {MAX_BODY_BYTES} bytes"
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{ProbeMethod, ProbeRequest, fetch_over};

    /// A VLESS+TLS config as JSON — the proto's serde shape, the same one the
    /// other engine tests build.
    fn vless_tls() -> leas_proto::proto_spec::ProtocolConfig {
        serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "tcp" },
            "security": { "type": "tls", "sni": "dest.test", "insecure": true }
        }))
        .expect("config parses")
    }

    /// A whole probe attempt is bounded by the caller's budget, not by the
    /// engine's per-step limits: a peer that accepts the connection and then
    /// never answers the TLS handshake used to fail at `timeouts::SECURITY`
    /// (10 s) with `real_ping_timeout_secs` set to 5 s (or less).
    #[tokio::test]
    async fn a_stalled_handshake_is_bounded_by_the_attempt_budget() {
        use std::time::Instant;

        use leas_proto::proto_spec::endpoint::EndpointEssentials;

        use crate::addr::TargetAddr;
        use crate::context::NativeConnectParams;
        use crate::error::NativeError;
        use crate::probe::fetch;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Accept, then stay silent past every engine step limit.
            let (sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        });

        let params = NativeConnectParams::new(
            vless_tls(),
            EndpointEssentials::new(addr.ip().to_string(), addr.port()),
            TargetAddr::new("dest.test", 443),
        );
        let req = ProbeRequest {
            host: "dest.test",
            port: 443,
            https: false,
            method: ProbeMethod::Get,
            path: "/",
            timeout: Duration::from_millis(300),
        };
        let started = Instant::now();
        let err = fetch(params, &req)
            .await
            .expect_err("a silent peer must fail the probe");
        assert!(
            matches!(
                err,
                NativeError::Timeout {
                    step: "probe attempt",
                    ..
                }
            ),
            "expected the attempt deadline, got {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the attempt budget must bound the handshake: {:?}",
            started.elapsed()
        );
        server.abort();
    }

    /// Read a request head (bounded) so the test can assert on it.
    async fn read_head(sock: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
            match sock.read_exact(&mut byte).await {
                Ok(_) => head.push(byte[0]),
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&head).to_string()
    }

    fn request(method: ProbeMethod, path: &'static str) -> ProbeRequest<'static> {
        ProbeRequest {
            host: "127.0.0.1",
            port: 1, // replaced per test by the listener's real port
            https: false,
            method,
            path,
            timeout: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn head_request_reads_the_status_line() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let head = read_head(&mut sock).await;
            assert!(head.starts_with("HEAD /generate_204 "), "{head}");
            assert!(head.contains("host: 127.0.0.1:"), "{head}");
            sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut req = request(ProbeMethod::Head, "/generate_204");
        req.port = addr.port();
        let response = fetch_over(stream, &req).await.unwrap();
        assert_eq!(response.status, 204);
        assert!(response.body.is_empty());
        assert!(response.elapsed > Duration::ZERO);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn get_request_reads_the_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let head = read_head(&mut sock).await;
            assert!(head.starts_with("GET /json/ "), "{head}");
            let body = br#"{"query":"203.0.113.7"}"#;
            let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            sock.write_all(reply.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut req = request(ProbeMethod::Get, "/json/");
        req.port = addr.port();
        let response = fetch_over(stream, &req).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"query":"203.0.113.7"}"#);
        server.await.unwrap();
    }

    /// The probe's OWN target leg must not produce purge evidence: a target
    /// certificate — or a target that answers in cleartext — says nothing about
    /// the proxy config. The proxy leg types this exact failure as
    /// `CleartextPeer`; this leg reports plain `Tls`, and a later "unify the
    /// mappings" refactor must break THIS test rather than purge healthy
    /// configs.
    #[tokio::test]
    async fn target_leg_tls_failure_carries_no_evidence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Answer the ClientHello in cleartext, then hold the socket so the
            // failure is the cleartext diagnosis and not an EOF.
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut req = request(ProbeMethod::Head, "/generate_204");
        req.port = addr.port();
        req.https = true;
        req.timeout = Duration::from_millis(400);
        let err = fetch_over(stream, &req)
            .await
            .expect_err("a cleartext answer must fail the target TLS handshake");
        assert!(
            matches!(err, crate::error::NativeError::Tls(_)),
            "the target leg keeps the plain variant: {err:?}"
        );
        assert_eq!(
            err.evidence(),
            None,
            "a target-leg failure proves nothing about the config"
        );
        server.abort();
    }

    /// A tunnel that ENDS during the target handshake is a PROTOCOL-stage
    /// failure, not a TLS one. The engine's record layer reads the tunnel with
    /// `read_exact`, so the EOF arrives as `TlsError::Io` — and mapping that to
    /// `Tls` counted 151 rows of the 2026-09-21 run as TLS problems when the
    /// peer had simply closed the tunnel before answering (the VLESS
    /// response-header peel reports exactly this). The CLASS is asserted in
    /// `ops::ping_native`; this pins the variant that carries it.
    #[tokio::test]
    async fn a_tunnel_that_ends_during_the_target_handshake_is_not_a_tls_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Read the ClientHello, then close: the client sees a FIN (a clean
            // EOF) rather than a reset, which is the kind this case pins.
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; 512];
            let _ = sock.read(&mut hello).await;
            drop(sock);
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut req = request(ProbeMethod::Head, "/generate_204");
        req.port = addr.port();
        req.https = true;
        req.timeout = Duration::from_millis(400);
        let err = fetch_over(stream, &req)
            .await
            .expect_err("an immediate EOF must fail the target handshake");
        assert!(
            matches!(err, crate::error::NativeError::TunnelClosed { .. }),
            "an EOF from the tunnel is a protocol-stage failure, not TLS: {err:?}"
        );
        assert_eq!(
            err.evidence(),
            None,
            "and it still proves nothing about the config"
        );
        server.abort();
    }

    #[tokio::test]
    async fn silent_server_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // Hold the connection open without answering.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let mut req = request(ProbeMethod::Head, "/");
        req.port = addr.port();
        req.timeout = Duration::from_millis(200);
        let err = fetch_over(stream, &req).await.unwrap_err();
        assert!(
            matches!(err, crate::error::NativeError::Timeout { .. }),
            "{err:?}"
        );
        server.abort();
    }
}
