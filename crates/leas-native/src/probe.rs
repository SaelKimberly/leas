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
use crate::protocol::AuthAck;
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
    /// Budget for the PROTOCOL + PROBE stages (the body read is capped by the
    /// same value).
    pub timeout: Duration,
    /// Budget for the TRANSPORT stage alone — the time to establish the
    /// endpoint's transport (the dial to the proxy server's socket).
    ///
    /// **Independent** of `timeout`, not a split of it (spec
    /// `2026-10-21-merged-test-pipeline-design` D12): the transport span is
    /// the measurement that says "the server is alive", so it must never be
    /// truncated by the protocol stage's budget. The two budgets bound
    /// different stages, so a row's worst case is their SUM.
    pub transport_timeout: Duration,
}

/// A completed probe: the response head plus the body (capped).
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Time from the start of the request to the response HEAD — the probe's
    /// latency (the body read is not part of it).
    pub elapsed: Duration,
    /// The TRANSPORT span: the time to establish the endpoint's transport.
    ///
    /// `None` when the transport stage did not complete — the attempt never
    /// got past the dial, so there is no transport measurement to report.
    /// This is the Fast metric (spec D2): the same unit in the Fast Test
    /// (endpoint scope) and as stage 1 of the Real Test (link scope).
    pub transport_span: Option<Duration>,
    /// What the PROTOCOL stage saw of the server's authentication ack (spec
    /// D3). `NotApplicable` for a family with no server ack.
    pub auth_ack: AuthAck,
}

/// A failed probe: the engine's error PLUS the transport span the attempt
/// measured before it failed.
///
/// The span is the whole reason this type exists (spec D12). A plain
/// `NativeError` loses it: the failure path returns early, so the span the
/// dial produced never reaches the caller — and the row loses the fact that
/// separates "the server is dead" from "the server is up and the config is
/// not" (531 of 535 real-timeout rows on the 2026-09-21 run had a sub-second
/// transport span).
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct ProbeError {
    /// The engine's typed error — the class and the evidence come from it.
    pub error: NativeError,
    /// The TRANSPORT span, when the transport stage completed before the
    /// failure. `None` when the transport stage itself failed.
    pub transport_span: Option<Duration>,
    /// What the PROTOCOL stage saw of the server's ack (spec D3). A
    /// transport-stage failure never reached a protocol phase, so this is
    /// `NotApplicable` there.
    pub auth_ack: AuthAck,
}

impl ProbeError {
    /// A failure with no transport measurement and no ack (the transport
    /// stage failed, so no protocol phase ever ran).
    #[must_use]
    pub const fn new(error: NativeError) -> Self {
        Self {
            error,
            transport_span: None,
            auth_ack: AuthAck::NotApplicable,
        }
    }

    /// The engine's error, for the callers that classify it.
    #[must_use]
    pub const fn error(&self) -> &NativeError {
        &self.error
    }
}

/// Upper bound on a probe body. A probe reads a `generate_204` (empty) or a
/// small JSON document; anything larger is a failure, not a truncation.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Dial `req.host:req.port` through `params` and issue `req` over the tunnel.
///
/// The attempt runs in TWO stages with INDEPENDENT deadlines (spec
/// `2026-10-21-merged-test-pipeline-design` D12):
///
/// 1. **TRANSPORT** — the dial to the endpoint's IP+port, bounded by
///    `req.transport_timeout`. The span it produces is the Fast metric: the
///    time to establish the endpoint's transport.
/// 2. **PROTOCOL + PROBE** — the security handshake, the transport upgrade,
///    the protocol handshake, the target TLS and the request head, bounded by
///    `req.timeout`.
///
/// The budgets are NOT a split of one total: the transport span is the
/// measurement that separates "the server is alive" from "the server is dead",
/// so it must never be truncated by the protocol stage's budget. A row's worst
/// case is therefore their SUM (5 s + 5 s by default).
///
/// The engine's per-step limits (`timeouts::DIAL`/`SECURITY`/… , 10 s each)
/// are defence in depth, not the contract — without this wrapper a 5 s
/// setting let a probe spend 10 s in the dial alone and report `timeout on
/// tcp dial (limit 10s)`.
pub async fn fetch(
    mut params: NativeConnectParams,
    req: &ProbeRequest<'_>,
) -> Result<ProbeResponse, ProbeError> {
    params.target = TargetAddr::new(req.host, req.port);
    let started = Instant::now();
    // ── STAGE 1: TRANSPORT ──────────────────────────────────────────────
    // The DIAL alone: the TCP connection to the proxy server's IP+port (or
    // the QUIC handshake for a QUIC-family protocol). Nothing else — the
    // security handshake, the transport upgrade and the protocol phase all run
    // under the SECOND budget, so a slow handshake cannot eat the transport
    // measurement and a slow transport cannot eat the handshake's budget.
    let target = params.target.clone();
    let dial_params = params.clone();
    let dial_started = Instant::now();
    let dialed = Box::pin(tokio::time::timeout(
        req.transport_timeout,
        crate::chain::dial_transport(&dial_params, target),
    ))
    .await
    .map_err(|_| {
        ProbeError::new(NativeError::Timeout {
            step: "probe transport",
            limit: req.transport_timeout,
        })
    })?
    .map_err(ProbeError::new)?;
    // The transport span: the time to establish the endpoint's transport. It
    // is `Some` whenever the dial completed — including when the protocol
    // stage later failed, which is exactly the case the merged row reports as
    // "the transport was alive, the config was not".
    let transport_span = dial_started.elapsed();

    // ── STAGE 2: PROTOCOL + PROBE ───────────────────────────────────────
    // The security handshake, the transport upgrade, the protocol handshake,
    // the target TLS and the request head — all under `req.timeout`.
    //
    // The mux arm is here, not in stage 1: a mux row's protocol phase opens
    // the multiplexer over the dialed stream, so the mux handshake is the
    // PROTOCOL stage's work. The SAME predicate the inbound dial uses, so the
    // probe cannot report a plugin row as "server unreachable" when the real
    // cause is a missing mux frame (v2ray-plugin's server mandates mux).
    // The auth-ack slot: the tunnel's read path reports into it (spec D3).
    // It is cloned out of the context BEFORE the attempt moves it, so the
    // caller can read the observation after the attempt is over — including
    // on the failure paths, where the error type would otherwise lose it.
    let ctx = crate::context::LinkContext::with_auth_ack(params.clone(), params.target.clone());
    let ack_slot = ctx.ack.clone();
    let attempt = async move {
        let tunnel = if params.mux {
            // The mux multiplexer rides the DIAL the transport stage made —
            // one connection for the whole attempt, so the transport span
            // measures the connection the probe actually used (spec D2).
            let mux = crate::chain::finish_chain_mux(&ctx, dialed).await?;
            // The session owns its tunnel here too, for the same keepalive
            // reason as the inbound dial.
            crate::mux_session::open_session(mux, &params.target).await?
        } else {
            crate::chain::finish_chain(&ctx, dialed).await?
        };
        fetch_over(tunnel, req).await
    };
    let response = Box::pin(tokio::time::timeout(req.timeout, attempt))
        .await
        .map_err(|_| {
            // The transport span rides along with the failure: the transport
            // was alive, the protocol stage was not (spec D12). The ack is
            // whatever the tunnel saw — a timeout while the peel was pending
            // is the UNKNOWN state, not a rejection (spec D3).
            ProbeError {
                error: NativeError::Timeout {
                    step: "probe attempt",
                    limit: req.timeout,
                },
                transport_span: Some(transport_span),
                auth_ack: ack_slot.get(),
            }
        })?
        .map_err(|error| ProbeError {
            error,
            transport_span: Some(transport_span),
            auth_ack: ack_slot.get(),
        })?;
    // The probe's latency is the whole span, the dial included — the same span
    // the subprocess probe measured through its local SOCKS hop.
    Ok(ProbeResponse {
        elapsed: started.elapsed(),
        transport_span: Some(transport_span),
        auth_ack: ack_slot.get(),
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
        // The stream-level half has no transport stage or ack of its own: the
        // caller passes an ALREADY-connected stream. The dial's span belongs
        // to `fetch`, and the ack's slot is read there too.
        transport_span: None,
        auth_ack: AuthAck::NotApplicable,
    })
}

/// One download-speed request: the same two-stage shape as [`ProbeRequest`],
/// plus the streaming-stop policy.
///
/// `max_duration` bounds the whole download; `min_duration` + `min_bytes` are
/// the STOP gate (both must hold before the stream may end early): a number
/// taken from a fraction of a second of a slow link's trickle is noise, and a
/// fast link that finishes a small file in under `min_duration` has not shown
/// its steady-state rate either.
#[derive(Debug, Clone, Copy)]
pub struct SpeedRequest<'a> {
    /// Destination host (also the TLS server name when `https`).
    pub host: &'a str,
    pub port: u16,
    pub https: bool,
    /// Origin-form path, query string included.
    pub path: &'a str,
    /// Budget for the PROTOCOL stage (the handshake + the response HEAD).
    pub timeout: Duration,
    /// Budget for the TRANSPORT stage alone (the dial to the proxy server).
    pub transport_timeout: Duration,
    /// How long the download runs at most.
    pub max_duration: Duration,
    /// The minimum elapsed time before an early stop is allowed.
    pub min_duration: Duration,
    /// The minimum received bytes before an early stop is allowed.
    pub min_bytes: u64,
}

/// A completed download-speed probe: the PEAK 1-second-windowed bytes per
/// second.
///
/// Also the transport span (the Fast metric, spec D2) and the ack (spec D3) —
/// the same two facts [`ProbeResponse`] reports, so a speed result lands on
/// the row through the SAME columns a real probe fills.
#[derive(Debug, Clone)]
pub struct SpeedResponse {
    /// Peak of the 1-second sliding windows, in BYTES per second (the cell
    /// renders MiB/s; v2rayN reports the same statistic as MB/s).
    pub peak_bytes_per_sec: u64,
    /// The TRANSPORT span: the dial to the proxy server, the Fast metric.
    pub transport_span: Duration,
    /// What the PROTOCOL stage saw of the server's ack (spec D3).
    pub auth_ack: AuthAck,
}

/// Dial `req.host:req.port` through `params` and DOWNLOAD `req.path`, measuring
/// the peak 1-second-windowed throughput instead of buffering the body.
///
/// The same TWO-STAGE shape as [`fetch`] (spec D12): the TRANSPORT stage's
/// budget is independent of the download's, so a slow transport cannot eat the
/// measurement and the measurement cannot eat the dial. The streaming reads run
/// under the download's own `max_duration` deadline, not the probe budget.
pub async fn speed_fetch(
    mut params: NativeConnectParams,
    req: &SpeedRequest<'_>,
) -> Result<SpeedResponse, ProbeError> {
    params.target = TargetAddr::new(req.host, req.port);
    // ── STAGE 1: TRANSPORT ──────────────────────────────────────────────
    let target = params.target.clone();
    let dial_params = params.clone();
    let dial_started = Instant::now();
    let dialed = Box::pin(tokio::time::timeout(
        req.transport_timeout,
        crate::chain::dial_transport(&dial_params, target),
    ))
    .await
    .map_err(|_| {
        ProbeError::new(NativeError::Timeout {
            step: "probe transport",
            limit: req.transport_timeout,
        })
    })?
    .map_err(ProbeError::new)?;
    let transport_span = dial_started.elapsed();

    // ── STAGE 2: PROTOCOL + DOWNLOAD ────────────────────────────────────
    let ctx = crate::context::LinkContext::with_auth_ack(params.clone(), params.target.clone());
    let ack_slot = ctx.ack.clone();
    let attempt = async move {
        let tunnel = if params.mux {
            let mux = crate::chain::finish_chain_mux(&ctx, dialed).await?;
            crate::mux_session::open_session(mux, &params.target).await?
        } else {
            crate::chain::finish_chain(&ctx, dialed).await?
        };
        speed_over(tunnel, req).await
    };
    let peak = Box::pin(tokio::time::timeout(req.timeout, attempt))
        .await
        .map_err(|_| {
            // Same rule as `fetch`: the transport span rides the failure, and
            // a protocol-stage hang is NOT a transport failure.
            ProbeError {
                error: NativeError::Timeout {
                    step: "probe attempt",
                    limit: req.timeout,
                },
                transport_span: Some(transport_span),
                auth_ack: ack_slot.get(),
            }
        })?
        .map_err(|error| ProbeError {
            error,
            transport_span: Some(transport_span),
            auth_ack: ack_slot.get(),
        })?;
    Ok(SpeedResponse {
        peak_bytes_per_sec: peak,
        transport_span,
        auth_ack: ack_slot.get(),
    })
}

/// Stream the response body of one download and return the PEAK 1-second
/// windowed bytes-per-second.
///
/// The peak, not the average: v2rayN reports the fastest 1-second window
/// (`DownloaderHelper.DownloadDataAsync4Speed` keeps `maxSpeed`), and matching
/// that keeps a leas number comparable to the reference client's. The average
/// over a window that includes TCP slow-start understates every link.
///
/// The stream stops when the body ends OR when BOTH stop gates hold
/// (`min_duration` elapsed and `min_bytes` received) OR when `max_duration`
/// expires — the first of those that happens.
// Bytes-per-second math over u64 counters: the f64 round trip is exact at
// network scales and the result renders one-decimal, so the cast lints are
// deliberate here (the same allowance leas-core's throughput math carries).
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub async fn speed_over<S: crate::Stream + 'static>(
    io: S,
    req: &SpeedRequest<'_>,
) -> Result<u64, NativeError> {
    let stream: BoxStream = if req.https {
        let tls = client::connect(Box::new(io) as BoxStream, &tls_config(req.host))
            .await
            .map_err(target_leg_error)?;
        Box::new(tls)
    } else {
        Box::new(io)
    };
    let mut sender = h1_client(stream).await?;
    let request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(req.path)
        .header(HOST, host_header_of(req.host, req.port, req.https))
        .header(USER_AGENT, "leas/speedtest")
        .body(ReqBody::Empty)
        .map_err(|e| NativeError::Transport(format!("speed request: {e}")))?;
    // The response HEAD is under the PROTOCOL budget (it proves the tunnel
    // works); the BODY stream is under the download's own `max_duration`.
    let response = tokio::time::timeout(req.timeout, sender.send_request(request))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "speed request",
            limit: req.timeout,
        })?
        .map_err(|e| NativeError::Transport(format!("speed request: {e}")))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(NativeError::Transport(format!(
            "speed test target answered {status}"
        )));
    }
    let mut reader = tokio::io::BufReader::new(IncomingReader::new(response.into_body()));
    let mut buf = vec![0u8; SPEED_READ_CHUNK];
    // The peak of the 1-second windows.
    let mut peak: u64 = 0;
    // Bytes in the CURRENT (unsealed) window and the instant it opened.
    let mut window_bytes: u64 = 0;
    let started = Instant::now();
    let mut window_start = started;
    let deadline = started + req.max_duration;
    let mut total: u64 = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining == Duration::ZERO {
            break;
        }
        let n = tokio::select! {
            r = tokio::io::AsyncReadExt::read(&mut reader, &mut buf) => r,
            () = tokio::time::sleep(remaining) => break,
        };
        let n = match n {
            Ok(0) => break, // the body ended
            Ok(n) => n,
            Err(e) => {
                return Err(NativeError::Transport(format!("speed body: {e}")));
            }
        };
        total += n as u64;
        window_bytes += n as u64;
        let elapsed = window_start.elapsed();
        if elapsed >= Duration::from_secs(1) {
            // Seal the full second: the window's own bytes over the window's
            // own length, so a window the deadline cut short is not graded as
            // a whole one.
            let secs = elapsed.as_secs_f64().max(0.001);
            // Bytes/second over the sealed window; the f64 round trip is
            // exact enough at network scales and the result lands on the row
            // rounded to one decimal anyway.
            let bps = window_bytes as f64 / secs;
            if bps > peak as f64 {
                peak = bps as u64;
            }
            window_bytes = 0;
            window_start = Instant::now();
        }
        // The early-stop gate: BOTH the minimum time and the minimum bytes
        // must hold. A stop on time alone grades a trickle; a stop on bytes
        // alone grades a fast link on a small file.
        if started.elapsed() >= req.min_duration && total >= req.min_bytes {
            break;
        }
        if total >= SPEED_MAX_BYTES {
            break;
        }
    }
    // A short download (the file ended, or the gates fired inside the first
    // second) has no sealed window to report — grade the bytes it did deliver
    // over the time it took, so a fast link on a small file still gets a
    // number instead of a failure.
    if peak == 0 && total > 0 {
        let elapsed = started.elapsed().max(Duration::from_millis(1));
        peak = (total as f64 / elapsed.as_secs_f64().max(0.001)) as u64;
    }
    if peak == 0 {
        return Err(NativeError::Timeout {
            step: "speed body",
            limit: req.max_duration,
        });
    }
    Ok(peak)
}

/// How many bytes one download may read before it stops, however long that
/// took: a hard roof so a misconfigured `min_bytes` cannot stream a whole CDN
/// through one probe. Generous by design — the window gates do the real
/// stopping, this is the fence behind them.
const SPEED_MAX_BYTES: u64 = 1 << 30;

/// The body read chunk: 256 KiB, enough that one read fills a meaningful
/// fraction of a 1-second window even on a fast link (a 1 GiB/s stream
/// delivers ~1 MiB per read at this size, so the window still samples it).
const SPEED_READ_CHUNK: usize = 256 * 1024;

/// `Host` header for the speed request (the probe's own law, without the
/// borrowed struct).
fn host_header_of(host: &str, port: u16, https: bool) -> String {
    let default_port = if https { 443 } else { 80 };
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
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

    use super::{ProbeMethod, ProbeRequest, SpeedRequest, fetch_over, speed_over};

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
            // The transport budget is generous: the dial SUCCEEDS here, and
            // the protocol stage is what must fail.
            transport_timeout: Duration::from_secs(5),
        };
        let started = Instant::now();
        let err = fetch(params, &req)
            .await
            .expect_err("a silent peer must fail the probe");
        assert!(
            matches!(
                err.error,
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

    /// The TRANSPORT stage is bounded by its OWN budget, and the protocol
    /// stage by its own — they are INDEPENDENT, not a split of one total
    /// (spec `2026-10-21-merged-test-pipeline-design` D12).
    ///
    /// A peer that accepts the TCP connection and then never answers the TLS
    /// handshake: the transport stage SUCCEEDED (the socket is established), so
    /// the attempt fails in the PROTOCOL stage — and the transport span is
    /// still reported, because the transport was alive and the config was not
    /// (531 of 535 real-timeout rows on the 2026-09-21 run had a sub-second
    /// fast latency: the transport was alive, the timeout was spent later).
    #[tokio::test]
    async fn the_transport_stage_has_its_own_budget() {
        use std::time::Instant;

        use leas_proto::proto_spec::endpoint::EndpointEssentials;

        use crate::addr::TargetAddr;
        use crate::context::NativeConnectParams;
        use crate::error::NativeError;
        use crate::probe::fetch;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
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
            // The PROTOCOL budget is the short one: the dial succeeds, and
            // the protocol stage is what must run out.
            timeout: Duration::from_millis(300),
            // The transport budget is generous: the dial must SUCCEED.
            transport_timeout: Duration::from_secs(5),
        };
        let started = Instant::now();
        let err = fetch(params, &req)
            .await
            .expect_err("a silent peer must fail the probe");
        assert!(
            matches!(
                err.error,
                NativeError::Timeout {
                    step: "probe attempt",
                    ..
                }
            ),
            "expected the PROTOCOL stage's deadline, got {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the protocol stage is bounded by ITS budget, not the transport's: {:?}",
            started.elapsed()
        );
        // The transport span SURVIVES the protocol-stage failure: the dial
        // completed, so the transport was alive and the config was not (spec
        // D12). The merged row's whole value is this pair of facts.
        assert!(
            err.transport_span.is_some(),
            "a failure after the dial must still report the transport span"
        );
        server.abort();
    }

    /// A peer that never accepts the connection fails in the TRANSPORT stage,
    /// under the transport budget.
    #[tokio::test]
    async fn a_refused_transport_fails_under_the_transport_budget() {
        use std::time::Instant;

        use leas_proto::proto_spec::endpoint::EndpointEssentials;

        use crate::addr::TargetAddr;
        use crate::context::NativeConnectParams;
        use crate::error::NativeError;
        use crate::probe::fetch;

        // A listener that is dropped: the port is closed, so the dial is
        // refused immediately.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

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
            timeout: Duration::from_secs(5),
            transport_timeout: Duration::from_millis(300),
        };
        let started = Instant::now();
        let err = fetch(params, &req)
            .await
            .expect_err("a refused transport must fail the probe");
        // Windows does not refuse a closed port at once: the stack
        // retransmits SYN (the initial RTO, ~1 s on loopback) before it
        // surfaces the refuse, so this 300 ms transport budget can expire
        // while the dial is still inside that SYN-retry budget. Both outcomes
        // are transport-stage failures under the transport budget.
        #[cfg(windows)]
        assert!(
            !matches!(
                err.error,
                NativeError::Timeout {
                    step: "probe attempt",
                    ..
                }
            ),
            "a refused dial is a transport-stage failure, not a protocol-stage timeout: {err}"
        );
        #[cfg(not(windows))]
        assert!(
            !matches!(err.error, NativeError::Timeout { .. }),
            "a refused dial is a transport failure, not a timeout: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the transport stage is bounded by its own budget: {:?}",
            started.elapsed()
        );
    }

    /// A MUX row's probe costs ONE connection, not two.
    ///
    /// The mux multiplexer rides the transport stage's dial — the probe does
    /// not re-dial to open the mux session. The connection counter is the
    /// evidence: the claim "one connection" is not observable otherwise, and a
    /// re-dial would double the row's cost (and make the transport span
    /// measure a connection the probe then threw away — spec D2).
    #[tokio::test]
    async fn a_mux_row_probes_over_one_connection() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use leas_proto::proto_spec::ProtocolConfig;
        use leas_proto::proto_spec::endpoint::EndpointEssentials;

        use crate::addr::TargetAddr;
        use crate::context::NativeConnectParams;
        use crate::probe::fetch;

        // A VLESS+mux row. The peer accepts and then goes silent: the probe
        // fails in the PROTOCOL stage, which is all this test needs — the
        // connection COUNT is the evidence.
        let config: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "mux": { "limited": 8 },
            "transport": { "type": "tcp" },
            "security": { "type": "tls", "sni": "dest.test", "insecure": true }
        }))
        .expect("config parses");
        assert!(
            NativeConnectParams::resolved_mux(&config),
            "the row must resolve to mux, or the test proves nothing"
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        let server = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                // Each accepted socket is held by its OWN task: a sleep in the
                // accept loop would block the next accept, and the counter
                // would never see a second connection — the test would pass a
                // re-dial.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    drop(sock);
                });
            }
        });

        let params = NativeConnectParams::new(
            config,
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
            transport_timeout: Duration::from_secs(5),
        };
        let _ = fetch(params, &req)
            .await
            .expect_err("a silent peer must fail");

        // The accept counter is filled by the SERVER task, so it lags the
        // client by a scheduling quantum — a re-dial that the timeout cut
        // short would still be in flight when the probe returned. Give the
        // server task the chance to record it before asserting, or the test
        // would pass a re-dial.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The dial happened once. A re-dial for the mux session would make
        // this 2.
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "a mux row's probe must use ONE connection: the mux session rides the transport stage's dial"
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
            transport_timeout: Duration::from_secs(5),
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
        assert_eq!(response.body.len(), 0);
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

    /// A body that delivers bytes grades a rate; a short download falls back
    /// to the bytes it delivered over the time it took, not a zero.
    #[tokio::test]
    async fn a_short_download_still_grades_the_bytes_it_delivered() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = vec![0x41u8; 64 * 1024];
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = read_head(&mut sock).await;
            let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            sock.write_all(reply.as_bytes()).await.unwrap();
            sock.write_all(&body).await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let req = SpeedRequest {
            host: "127.0.0.1",
            port: addr.port(),
            https: false,
            path: "/50mb.test",
            timeout: Duration::from_secs(5),
            transport_timeout: Duration::from_secs(5),
            max_duration: Duration::from_secs(5),
            min_duration: Duration::from_secs(3),
            min_bytes: 1 << 20,
        };
        let rate = speed_over(stream, &req).await.unwrap();
        // The exact value depends on timing; the assertion is the SIGN — a
        // delivered body must grade a positive rate, not a failure.
        assert!(rate > 0, "a delivered body must grade a positive rate");
        server.await.unwrap();
    }

    /// A non-2xx answer is a download failure, not a zero rate.
    #[tokio::test]
    async fn a_non_2xx_target_fails_the_download() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = read_head(&mut sock).await;
            sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let req = SpeedRequest {
            host: "127.0.0.1",
            port: addr.port(),
            https: false,
            path: "/missing",
            timeout: Duration::from_secs(5),
            transport_timeout: Duration::from_secs(5),
            max_duration: Duration::from_secs(5),
            min_duration: Duration::from_secs(3),
            min_bytes: 1 << 20,
        };
        let err = speed_over(stream, &req).await.unwrap_err();
        assert!(
            matches!(err, crate::error::NativeError::Transport(_)),
            "a 404 must be a transport failure, not a rate: {err}"
        );
        server.await.unwrap();
    }

    /// A body that never arrives: the `max_duration` deadline cuts it short,
    /// and a zero-byte download is a timeout.
    #[tokio::test]
    async fn a_stalled_body_fails_under_max_duration() {
        use std::time::Instant;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = read_head(&mut sock).await;
            // A Content-Length that promises more than it will ever send.
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let req = SpeedRequest {
            host: "127.0.0.1",
            port: addr.port(),
            https: false,
            path: "/50mb.test",
            timeout: Duration::from_secs(5),
            transport_timeout: Duration::from_secs(5),
            max_duration: Duration::from_millis(300),
            min_duration: Duration::from_secs(3),
            min_bytes: 1 << 20,
        };
        let started = Instant::now();
        let err = speed_over(stream, &req).await.unwrap_err();
        assert!(
            matches!(err, crate::error::NativeError::Timeout { .. }),
            "a stalled body must be a timeout: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the download deadline must bound the wait: {:?}",
            started.elapsed()
        );
        server.abort();
    }
}
