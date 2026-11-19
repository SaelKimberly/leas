//! Native real-ping probe policy: one tunnel to the ping URL's host, one HTTP
//! request over it, then (on success) a second tunnel to fetch the exit IP.
//!
//! Transport, TLS and HTTP live in `leas_native::probe`; this module owns
//! only the policy around it (URL shape, retry fan-out, the latency span, the
//! exit-IP parse and the error strings the event path persists).
//!
//! Latency span: proxy dial → protocol handshake → target TCP + TLS → request →
//! response head. That is the same span the subprocess probe covered minus the
//! loopback SOCKS hop, so persisted delays stay comparable across the cutover.
//!
//! The engine is responsible for DNS of the proxy server (once per attempt,
//! bounded by its own DIAL deadline) and the target hostname travels in the
//! protocol header, so the remote side resolves it — exactly as before.

use std::time::Duration;

use leas_config::IpProvider;
use leas_db::models::Endpoint;
use leas_native::addr::TargetAddr;
use leas_native::context::NativeConnectParams;
use leas_native::error::{FailureEvidence, NativeError};
use leas_native::probe::{self, ProbeMethod, ProbeRequest};
use leas_proto::proto_spec::ProtocolConfig;

use crate::ops::native_connect::endpoint_essentials;

/// Exit-IP fetch budget (an `ip-api` JSON response, not a latency probe).
const IP_INFO_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a probe failed, at the granularity a batch reports.
///
/// The class is produced by the TYPED error where the failure happened (the
/// engine's [`NativeError`], or the fast adapter's `PingError`) and is never
/// re-parsed out of the user-facing text: the text is for the log and the DB,
/// the class is what a batch summary counts. Ordering is the summary's print
/// order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeClass {
    /// A deadline expired (the attempt budget or the engine's step timeout).
    Timeout,
    /// The server socket would not open.
    Dial,
    /// The server's name did not resolve.
    Dns,
    /// The peer refused the connection.
    Refused,
    /// No route to the peer.
    NoRoute,
    /// The local network had no path to the peer.
    Unreachable,
    /// The TLS (or REALITY) handshake failed.
    Tls,
    /// The REALITY provisioning/authentication step failed.
    Reality,
    /// A transport upgrade (ws/grpc/xhttp/httpupgrade/v2rayhttp) failed.
    Transport,
    /// The proxy protocol handshake or its response framing failed.
    Protocol,
    /// The tunnel worked but the probe's own HTTP exchange did not.
    Http,
    /// The link could not be probed as configured (missing row, refused by the
    /// capability gate, unparseable probe URL).
    Config,
    /// A local I/O failure.
    Io,
    Other,
}

/// The persisted `(stage, cause)` pair for one failure (spec
/// `2026-11-19-probe-truth-and-ingest-boundary` S1).
///
/// Stage = where the probe died; cause = what it met there. `transport_failed`
/// is the disambiguator the engine cannot give through `ProbeClass` alone: the
/// stage-1 deadline and a protocol-stage hang are both `Timeout`.
///
/// A real/name error keeps this pure — no text parsing — which is the point of
/// the pair: reports group by two closed columns instead of regexing prose.
#[must_use]
pub const fn failure_pair(
    class: ProbeClass,
    evidence: Option<leas_native::error::FailureEvidence>,
    transport_failed: bool,
) -> (leas_db::models::FailureStage, leas_db::models::FailureCause) {
    use leas_db::models::{FailureCause as C, FailureStage as S};
    use leas_native::error::FailureEvidence as E;
    match class {
        ProbeClass::Dns => (S::Dial, C::Nxdomain),
        ProbeClass::Refused => (S::Dial, C::Refused),
        ProbeClass::NoRoute | ProbeClass::Unreachable => (S::Dial, C::NoRoute),
        ProbeClass::Dial => (S::Dial, C::Io),
        ProbeClass::Timeout => {
            if transport_failed {
                (S::Dial, C::Timeout)
            } else {
                (S::Target, C::Timeout)
            }
        }
        ProbeClass::Tls => (S::Transport, C::Alert),
        ProbeClass::Reality => (S::Transport, C::Config),
        ProbeClass::Transport => {
            if matches!(evidence, Some(E::HttpRejected(_))) {
                (S::Transport, C::Status)
            } else {
                (S::Transport, C::Framing)
            }
        }
        // The protocol stage carries two different statements: the origin
        // rejecting the SECRET (or the config being undialable) is a config
        // fact, while bytes that do not parse are a framing fact.
        ProbeClass::Protocol => {
            if matches!(evidence, Some(E::CredentialsRejected | E::ConfigDefect)) {
                (S::Protocol, C::Config)
            } else {
                (S::Protocol, C::Framing)
            }
        }
        ProbeClass::Http => (S::Target, C::Status),
        ProbeClass::Config => (S::Protocol, C::Config),
        // A local I/O failure that never got past the dial is a DIAL failure;
        // the engine's `transport_failed` is the only signal that separates it
        // from a destination that hung.
        ProbeClass::Io | ProbeClass::Other => {
            if transport_failed {
                (S::Dial, C::Io)
            } else {
                (S::Target, C::Io)
            }
        }
    }
}

impl ProbeClass {
    /// The label the batch summary prints. Short: the line carries every class.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Dial => "dial",
            Self::Dns => "dns",
            Self::Refused => "refused",
            Self::NoRoute => "no-route",
            Self::Unreachable => "unreachable",
            Self::Tls => "tls",
            Self::Reality => "reality",
            Self::Transport => "transport",
            Self::Protocol => "protocol",
            Self::Http => "http",
            Self::Config => "config",
            Self::Io => "io",
            Self::Other => "other",
        }
    }
}

/// A failed real probe: the class a batch counts plus the text it persists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeFailure {
    pub class: ProbeClass,
    pub text: String,
    /// What the failure PROVES, when the engine reported it (spec §7). `None`
    /// for a failure this module raised itself — the probe-URL shape, the
    /// target request's own status — and for anything transient.
    pub evidence: Option<FailureEvidence>,
    /// The TRANSPORT span in ms, when the transport stage completed before the
    /// failure.
    ///
    /// This is the Fast metric carried through a FAILURE (spec D12): a row
    /// whose transport answered but whose config did not still reports the
    /// transport span, so the panel can say "the server is up, the config is
    /// not". `None` when the transport stage itself failed.
    pub transport_ms: Option<u64>,
    /// Whether the TRANSPORT stage itself failed — the connection never came
    /// up.
    ///
    /// This is an explicit flag, NOT a class test: the engine reports both
    /// `Timeout { step: "probe transport" }` (stage 1) and
    /// `Timeout { step: "probe attempt" }` (stage 2+) as the SAME class
    /// (`Timeout`), so a class test would call a protocol-stage hang a
    /// transport failure — and retire a working server as unreachable. That
    /// is the false negative the 2026-09-15 audit found.
    ///
    /// The merged pipeline's "not measurable" outcome (spec D1) reads THIS:
    /// the transport did not come up, so the probe cannot pass where the dial
    /// did not.
    pub transport_failed: bool,
    /// What the PROTOCOL stage saw of the server's ack (spec D3), when the
    /// stage ran. `NotApplicable` for a transport-stage failure (no protocol
    /// phase ever ran) and for a failure this module raised itself.
    pub auth_ack: leas_native::protocol::AuthAck,
    /// Whether a SECOND observation agreed with this failure (spec S2).
    /// Only a confirmed failure may sample the stability ring: one ambiguous
    /// deadline never demotes a link.
    pub confirmed: bool,
}

impl ProbeFailure {
    /// Classify the engine's typed error, keeping its rendered text.
    #[must_use]
    pub fn from_engine(err: &NativeError) -> Self {
        let class = match err {
            // The capability gate raises `NotImplemented` before the dial on a
            // probe path: both are "this row cannot be probed as configured".
            NativeError::Config(_) | NativeError::NotImplemented { .. } => ProbeClass::Config,
            NativeError::Dial(_) => ProbeClass::Dial,
            NativeError::Tls(_)
            | NativeError::CertNotValidForName(_)
            | NativeError::CertPinMismatch(_)
            | NativeError::CertExpired(_)
            | NativeError::CleartextPeer(_) => ProbeClass::Tls,
            NativeError::Reality(_) => ProbeClass::Reality,
            NativeError::Transport(_) | NativeError::TransportRejected { .. } => {
                ProbeClass::Transport
            }
            // `TunnelClosed`: the stage that failed is the tunnel under a later
            // phase, so the class is the protocol exchange that never completed
            // — not `Tls`, which is what the engine's `TlsError::Io` wrap used
            // to produce.
            NativeError::Protocol { .. }
            | NativeError::TunnelClosed { .. }
            | NativeError::AuthRejected { .. } => ProbeClass::Protocol,
            NativeError::Io(_) => ProbeClass::Io,
            NativeError::Timeout { .. } => ProbeClass::Timeout,
        };
        Self {
            class,
            text: err.to_string(),
            evidence: err.evidence(),
            transport_ms: None,
            transport_failed: is_transport_failure(err),
            auth_ack: leas_native::protocol::AuthAck::NotApplicable,
            confirmed: false,
        }
    }

    /// A failure this module raised itself (probe-URL shape, HTTP status).
    ///
    /// No evidence: the status of the probe's OWN target request says nothing
    /// about the config, and neither does a malformed probe URL.
    #[must_use]
    pub fn local(class: ProbeClass, text: impl Into<String>) -> Self {
        Self {
            class,
            text: text.into(),
            evidence: None,
            transport_ms: None,
            transport_failed: false,
            auth_ack: leas_native::protocol::AuthAck::NotApplicable,
            confirmed: false,
        }
    }
}

/// Whether the error means the TRANSPORT never came up.
///
/// The TRANSPORT stage's own failures, named by the engine's TYPED error:
/// the stage-1 deadline (`Timeout { step: "probe transport" }`), a refused
/// socket, a name that did not resolve, no route, an unreachable network, and
/// the dial itself.
///
/// The stage-2+ deadline (`Timeout { step: "probe attempt" }`) is NOT one: the
/// transport was up and the protocol stage hung, so the server is alive and
/// the config is what failed. The two share a class, so the STAGE is what
/// decides — a class test would retire a working server.
fn is_transport_failure(err: &NativeError) -> bool {
    match err {
        // The stage-1 deadline: the dial did not finish inside the transport
        // budget. The `step` is what distinguishes it from the stage-2
        // deadline, which shares the class.
        NativeError::Timeout {
            step: "probe transport",
            ..
        }
        | NativeError::Dial(_) => true,
        // A refused socket, a name that did not resolve, no route and an
        // unreachable network are all "the transport never came up". The
        // engine reports the first two as `Dial` and the OS code inside it;
        // the last two arrive as `Io` with the matching `ErrorKind`.
        NativeError::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::NetworkDown
                | std::io::ErrorKind::NotFound
                | std::io::ErrorKind::TimedOut
        ),
        _ => false,
    }
}

/// The ack→verdict bridge (spec amendment D8): a `Failed` ack on a FAILED
/// attempt is credential-grade evidence. It lives here, not in the engine,
/// because `AnyTLS` observes it inside its read task after the error was made —
/// the ack slot is the only channel that carries it out.
///
/// `Ok`/`Unknown`/`NotApplicable` prove nothing: a lazy response header, a
/// timeout and a family with no ack all look like those, and none names the
/// secret.
fn credential_evidence(ack: leas_native::protocol::AuthAck) -> Option<FailureEvidence> {
    (ack == leas_native::protocol::AuthAck::Failed).then_some(FailureEvidence::CredentialsRejected)
}

/// Parameters for one native real ping.
pub struct NativeProbeReq<'a> {
    pub ping_url: &'a str,
    /// Which exit-IP provider to ask first (the rest of the family-agnostic set
    /// is the fallback chain).
    pub ip_provider: IpProvider,
    /// Per-attempt budget for the PROTOCOL + PROBE stages.
    pub timeout: Duration,
    /// Per-attempt budget for the TRANSPORT stage alone — the time to
    /// establish the endpoint's transport.
    ///
    /// **Independent** of `timeout` (spec
    /// `2026-10-21-merged-test-pipeline-design` D12): the transport span is
    /// the measurement that says "the server is alive", so it must never be
    /// truncated by the protocol stage's budget.
    pub transport_timeout: Duration,
    /// Attempts per observation. The first failure buys ONE confirm
    /// observation (spec `2026-11-19-probe-truth` S2): the value is the total
    /// observation count, never a parallel fan-out.
    pub retries: u32,
    /// The fallback target (Cloudflare trace). It is the second observation's
    /// target ONLY when the first failure died at the destination — a dial or
    /// transport failure is re-observed on the same target (one extra dial,
    /// chosen by stage).
    pub fallback_url: Option<&'a str>,
}

/// A successful native real ping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeProbeResult {
    pub latency_ms: u64,
    /// The TRANSPORT span in ms: the time to establish the endpoint's
    /// transport. `None` when the transport stage did not complete.
    ///
    /// This is the Fast metric (spec D2) — the same unit in the Fast Test
    /// (endpoint scope) and as stage 1 of the Real Test (link scope).
    pub transport_ms: Option<u64>,
    /// What the PROTOCOL stage saw of the server's ack (spec D3).
    pub auth_ack: leas_native::protocol::AuthAck,
    /// `"<ip> | <country>"` when the winning observation was the fallback
    /// target and its body carried the trace fields — the exit IP costs no
    /// second tunnel in that case (spec S3).
    pub ip_info: Option<String>,
}

/// One parsed probe URL: the pieces `probe::fetch` needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeUrl {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Origin-form path, query string included.
    pub path: String,
}

/// Parse a probe URL into scheme/host/port/path.
///
/// Only `http`/`https` are accepted: the probe has no other transport, and a
/// wrong scheme must fail loudly instead of silently probing port 0.
pub fn parse_probe_url(url: &str) -> Result<ProbeUrl, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid URL {url:?}: {e}"))?;
    let https = match parsed.scheme() {
        "https" => true,
        "http" => false,
        other => return Err(format!("unsupported URL scheme {other:?} in {url:?}")),
    };
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("URL {url:?} has no host"))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("URL {url:?} has no port"))?;
    let mut path = parsed.path().to_string();
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(ProbeUrl {
        https,
        host,
        port,
        path,
    })
}

/// Run one native real ping for `endpoint` + the already-loaded protocol config.
///
/// `Err` carries the user-facing failure text the event path persists plus the
/// class a batch counts.
pub async fn real_ping(
    endpoint: &Endpoint,
    addresses: &[std::net::IpAddr],
    config: &ProtocolConfig,
    req: &NativeProbeReq<'_>,
) -> Result<NativeProbeResult, ProbeFailure> {
    let target =
        parse_probe_url(req.ping_url).map_err(|e| ProbeFailure::local(ProbeClass::Config, e))?;
    let fallback = req.fallback_url.and_then(|url| parse_probe_url(url).ok());

    let (latency_ms, transport_ms, auth_ack, ip_info) =
        probe_attempts(target, fallback.as_ref(), endpoint, addresses, config, req).await?;
    Ok(NativeProbeResult {
        latency_ms,
        transport_ms,
        auth_ack,
        ip_info,
    })
}

/// Parameters for one native download speed test.
pub struct NativeSpeedReq<'a> {
    pub speed_url: &'a str,
    /// Per-attempt budget for the PROTOCOL stage (handshake + response HEAD).
    pub timeout: Duration,
    /// Per-attempt budget for the TRANSPORT stage alone (spec D12).
    pub transport_timeout: Duration,
    /// How long the download may run at most.
    pub max_duration: Duration,
    /// The stop gate: elapsed time before an early stop is allowed.
    pub min_duration: Duration,
    /// The stop gate: received bytes before an early stop is allowed.
    pub min_bytes: u64,
    /// Whole-download retries before failure is reported.
    pub retries: u32,
}

/// A successful native download speed test: the peak 1-second-windowed bytes
/// per second plus the same two facts a real probe reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSpeedResult {
    /// Peak BYTES per second (the 1-second windowed maximum). The caller
    /// converts to the row's bits-per-second unit at the boundary.
    pub peak_bytes_per_sec: u64,
    /// The TRANSPORT span in ms (the Fast metric, spec D2).
    pub transport_ms: Option<u64>,
    /// What the PROTOCOL stage saw of the server's ack (spec D3).
    pub auth_ack: leas_native::protocol::AuthAck,
}

/// Run one native download speed test for `endpoint` + the already-loaded
/// protocol config, retrying the whole download on failure (`retries`).
///
/// A retry starts only after the previous attempt FAILED, so two attempts never
/// share the link's bandwidth (concurrent attempts halved each stream's rate
/// and provoked server-side resets).
///
/// The failure contract is the real probe's: the transport span survives a
/// failure, the class comes from the engine's typed error, and only the
/// transport stage's own failure sets `transport_failed` (spec D12/D1).
pub async fn speed_ping(
    endpoint: &Endpoint,
    addresses: &[std::net::IpAddr],
    config: &ProtocolConfig,
    req: &NativeSpeedReq<'_>,
) -> Result<NativeSpeedResult, ProbeFailure> {
    let target =
        parse_probe_url(req.speed_url).map_err(|e| ProbeFailure::local(ProbeClass::Config, e))?;
    let params = probe_params(endpoint, addresses, config, &target);
    let attempts = req.retries.max(1);
    let mut last_error: Option<ProbeFailure> = None;
    for _ in 0..attempts {
        let request = leas_native::probe::SpeedRequest {
            host: &target.host,
            port: target.port,
            https: target.https,
            path: &target.path,
            timeout: req.timeout,
            transport_timeout: req.transport_timeout,
            max_duration: req.max_duration,
            min_duration: req.min_duration,
            min_bytes: req.min_bytes,
        };
        match leas_native::probe::speed_fetch(params.clone(), &request).await {
            Ok(r) => {
                return Ok(NativeSpeedResult {
                    peak_bytes_per_sec: r.peak_bytes_per_sec,
                    transport_ms: Some(r.transport_span.as_millis() as u64),
                    auth_ack: r.auth_ack,
                });
            }
            Err(e) => {
                let mut failure = ProbeFailure::from_engine(e.error());
                failure.transport_ms = e.transport_span.map(|s| s.as_millis() as u64);
                failure.auth_ack = e.auth_ack;
                last_error = Some(failure);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        ProbeFailure::local(
            ProbeClass::Other,
            "all speed test attempts failed".to_string(),
        )
    }))
}

/// The connect parameters for a row's probe and for its exit-IP fetch.
///
/// Public because the exit-IP fetch is a SEPARATE phase (spec D10/D11) and
/// needs the same parameters: the caller builds them once and hands them to
/// both [`real_ping`] and [`fetch_exit_ip`].
#[must_use]
pub fn probe_params(
    endpoint: &Endpoint,
    addresses: &[std::net::IpAddr],
    config: &ProtocolConfig,
    target: &ProbeUrl,
) -> NativeConnectParams {
    NativeConnectParams::new(
        config.clone(),
        endpoint_essentials(endpoint, addresses),
        TargetAddr::new(target.host.as_str(), target.port),
    )
}

/// The exit IP for a row, fetched through its own tunnel.
///
/// A SEPARATE phase, not part of the probe (spec D10/D11): the exit IP is
/// its own fact, it ages on its own, and a missing IP is a missing fact — not
/// a config failure. The probe's verdict never depends on it, and the
/// `Fill Exit IPs` command calls this directly.
///
/// The fetch rides a SECOND tunnel through the same proxy: a tunnel is bound
/// to one target, so the exit-IP host needs its own connection. A mux row can
/// open a second SESSION on its live tunnel instead — that handover is the
/// caller's business (the worker owns the live connection), not this
/// function's.
pub async fn fetch_exit_ip(params: &NativeConnectParams, provider: IpProvider) -> Option<String> {
    fetch_ip_info(params, provider).await
}

/// The severity ladder for choosing which of two failed observations to
/// persist (spec `2026-11-19-probe-truth` S2). Higher is more informative: a
/// config/credential answer outranks a certificate verdict, which outranks a
/// front's status, a framing break, a TLS alert, a deadline, and finally a
/// dial error. Ties keep the EARLIER observation.
const fn failure_severity(failure: &ProbeFailure) -> u8 {
    use leas_native::error::FailureEvidence as E;
    match failure.evidence {
        Some(E::ConfigDefect) => 9,
        Some(E::CredentialsRejected) => 8,
        Some(E::RealityFallback | E::CertNotValidForName | E::CertExpired | E::CleartextPeer) => 7,
        Some(E::HttpRejected(_)) => 6,
        None => match failure.class {
            ProbeClass::Protocol | ProbeClass::Transport => 5,
            ProbeClass::Tls => 4,
            ProbeClass::Http => 6,
            ProbeClass::Timeout => 2,
            ProbeClass::Config => 9,
            ProbeClass::Dns
            | ProbeClass::Refused
            | ProbeClass::NoRoute
            | ProbeClass::Unreachable
            | ProbeClass::Dial => 1,
            ProbeClass::Reality => 7,
            ProbeClass::Io | ProbeClass::Other => 0,
        },
    }
}

/// True when the failure is the origin's own answer, so a second observation
/// would only repeat it (spec S2's "positive evidence stops here").
const fn is_positive(failure: &ProbeFailure) -> bool {
    matches!(
        failure.evidence,
        Some(
            leas_native::error::FailureEvidence::ConfigDefect
                | leas_native::error::FailureEvidence::CredentialsRejected
                | leas_native::error::FailureEvidence::RealityFallback
                | leas_native::error::FailureEvidence::CertNotValidForName
                | leas_native::error::FailureEvidence::CertExpired
                | leas_native::error::FailureEvidence::CleartextPeer
                | leas_native::error::FailureEvidence::HttpRejected(_)
        )
    )
}

/// `"<ip> | <loc>"` from a Cloudflare `cdn-cgi/trace` body, or `None` for any
/// other body. Shape: `key=value` lines, one per line (verified 2026-11-19:
/// 200, 221 B, `ip=`, `loc=`, `ts=`).
fn parse_trace_body(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let mut ip = None;
    let mut loc = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("ip=") {
            ip = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("loc=") {
            loc = Some(value.trim());
        }
    }
    let ip = ip.filter(|v| !v.is_empty())?;
    let loc = loc.unwrap_or("-");
    Some(format!("{ip} | {loc}"))
}

/// One observation: a single request on the given target, retried zero times.
async fn probe_once(
    params: &NativeConnectParams,
    target: &ProbeUrl,
    method: ProbeMethod,
    req: &NativeProbeReq<'_>,
) -> Result<
    (
        u64,
        Option<u64>,
        leas_native::protocol::AuthAck,
        Option<String>,
    ),
    ProbeFailure,
> {
    let request = ProbeRequest {
        host: &target.host,
        port: target.port,
        https: target.https,
        method,
        path: &target.path,
        timeout: req.timeout,
        transport_timeout: req.transport_timeout,
    };
    match probe::fetch(params.clone(), &request).await {
        Ok(r) => {
            if !(200..300).contains(&r.status) {
                // A non-2xx answer: the transport was alive (the probe reached
                // the target), so the span is kept on the failure. The ack is
                // the tunnel's own observation, and a non-2xx from the TARGET
                // says nothing about the config, so the flag still reports it.
                let mut failure = ProbeFailure::local(
                    ProbeClass::Http,
                    format!("unexpected status {}", r.status),
                );
                failure.transport_ms = r.transport_span.map(|s| s.as_millis() as u64);
                failure.auth_ack = r.auth_ack;
                return Err(failure);
            }
            let trace = parse_trace_body(&r.body);
            Ok((
                r.elapsed.as_millis() as u64,
                r.transport_span.map(|s| s.as_millis() as u64),
                r.auth_ack,
                trace,
            ))
        }
        Err(e) => {
            // The transport span and the ack ride along with the failure: the
            // transport was alive and the protocol stage SAW something
            // (spec D12, D3).
            let mut failure = ProbeFailure::from_engine(e.error());
            failure.transport_ms = e.transport_span.map(|s| s.as_millis() as u64);
            failure.auth_ack = e.auth_ack;
            // The ack overrides only when it IS credential evidence; otherwise
            // the engine's typed evidence stands.
            failure.evidence = credential_evidence(e.auth_ack).or(failure.evidence);
            Err(failure)
        }
    }
}

/// Observe the link once, and — only when the first failure is not the
/// origin's own answer — exactly once more, on the target its stage selects
/// (spec `2026-11-19-probe-truth` S2/S3).
///
/// One extra dial, never a fan-out: a destination-stage failure is re-observed
/// on the fallback target (it both confirms and tests the exit), a dial or
/// transport failure on the same target. The persisted failure is the more
/// informative of the two, by the severity ladder.
async fn probe_attempts(
    target: ProbeUrl,
    fallback: Option<&ProbeUrl>,
    endpoint: &Endpoint,
    addresses: &[std::net::IpAddr],
    config: &ProtocolConfig,
    req: &NativeProbeReq<'_>,
) -> Result<
    (
        u64,
        Option<u64>,
        leas_native::protocol::AuthAck,
        Option<String>,
    ),
    ProbeFailure,
> {
    let params = probe_params(endpoint, addresses, config, &target);
    // The primary observation is a HEAD (a 204 needs no body); the fallback is
    // a GET because its whole point is the trace BODY (spec S3).
    let first = probe_once(&params, &target, ProbeMethod::Head, req).await;
    let first_failure = match first {
        Ok(ok) => return Ok(ok),
        Err(failure) => failure,
    };
    // Positive evidence is the origin's answer: repeating it spends a dial to
    // learn nothing (spec S2).
    // `retries` is the observation budget: one attempt is the minimum, and a
    // configured 1 means "no confirm observation" (spec S2's default is 2).
    if req.retries.max(1) < 2 {
        return Err(first_failure);
    }
    if is_positive(&first_failure) {
        // The origin answered, so a second dial learns nothing — but one
        // observation is still ONE observation: it must not sample the ring
        // (spec S2: "a single failure never samples 0, whatever its stage").
        return Err(first_failure);
    }
    // The stage decides the second observation's target. The pair is the same
    // function the persisted row uses, so the choice cannot drift from the
    // classification.
    let (stage, _) = failure_pair(
        first_failure.class,
        first_failure.evidence,
        first_failure.transport_failed,
    );
    let second_target = if stage == leas_db::models::FailureStage::Target {
        fallback.unwrap_or(&target)
    } else {
        &target
    };
    let second_params = probe_params(endpoint, addresses, config, second_target);
    // Only the trace fallback needs a body; re-observing the primary target
    // stays a HEAD.
    let second_method = if stage == leas_db::models::FailureStage::Target && fallback.is_some() {
        ProbeMethod::Get
    } else {
        ProbeMethod::Head
    };
    match probe_once(&second_params, second_target, second_method, req).await {
        Ok(ok) => Ok(ok),
        Err(second_failure) => {
            // The more informative failure is persisted; a tie keeps the
            // earlier one (it was observed first and is not worse evidence).
            // Two observations: whichever is persisted is confirmed.
            let mut worse = if failure_severity(&second_failure) > failure_severity(&first_failure)
            {
                second_failure
            } else {
                first_failure
            };
            worse.confirmed = true;
            Err(worse)
        }
    }
}

/// Attempts at the exit-IP fetch. The fetch rides a SECOND tunnel through the
/// same proxy, so it can miss while the latency probe (which proves the config
/// works) succeeded — one retry covers a transient dial/TLS failure without
/// doubling the cost of every real ping.
const IP_INFO_ATTEMPTS: u32 = 2;

/// Space between the exit-IP attempts.
///
/// Every concurrent real probe fetches from the SAME IP API URL, so an immediate
/// retry doubles the request rate at exactly the moment that endpoint is most
/// likely to be rate-limiting — the failure shape a retry is supposed to rescue.
/// A short pause costs one sleep and lets a transient miss recover.
const IP_INFO_RETRY_DELAY: Duration = Duration::from_millis(250);

/// What one exit-IP attempt produced.
#[derive(Debug, PartialEq, Eq)]
enum IpInfoOutcome {
    /// The provider answered with the expected object.
    Answer(String),
    /// The provider REFUSED: a non-2xx status, or a body that is not the
    /// expected object (ip-api's `{"status":"fail","message":…}` — its HTTPS
    /// form, its rate limit, its quota). Deterministic for the provider that
    /// produced it, so a retry repeats it — the next provider is asked instead.
    Refused(String),
    /// The tunnel or the request failed — transient, worth the one retry.
    Transport(String),
}

/// What the fetch does after one attempt.
///
/// This IS the exit-IP policy, split out of the loop so it can be pinned by a
/// fake outcome sequence: a refusal is deterministic for the provider that
/// produced it (usually its rate limit, which every concurrent probe shares, so
/// retrying would double the request rate exactly when that limit is biting) and
/// hands over to the next provider at once; a transport miss is transient and
/// gets [`IP_INFO_ATTEMPTS`] tries first. At the last provider `NextProvider`
/// ends the fetch.
#[derive(Debug, PartialEq, Eq)]
enum IpInfoStep {
    /// The provider answered — the fetch is done.
    Answered(String),
    /// Ask the same provider again.
    Retry,
    /// This provider is spent; ask the next one.
    NextProvider,
}

fn next_step(outcome: IpInfoOutcome, attempt: u32) -> IpInfoStep {
    match outcome {
        IpInfoOutcome::Answer(info) => IpInfoStep::Answered(info),
        IpInfoOutcome::Transport(_) if attempt + 1 < IP_INFO_ATTEMPTS => IpInfoStep::Retry,
        IpInfoOutcome::Refused(_) | IpInfoOutcome::Transport(_) => IpInfoStep::NextProvider,
    }
}

/// Exit IP + country through a second tunnel; any failure is `None` (the
/// latency result stands on its own — parity with the old probe).
///
/// The providers of [`IpProvider::fallback_chain`] are asked in order until one
/// answers. The exit IP does not depend on which one does, so the chain is
/// capacity: the free tiers rate-limit (ip-api publishes ~45 requests/minute)
/// while one real probe issues one request, and a feed-wide real level (measured
/// 2.6 results/s ≈ 156/min on 2026-09-16) runs several times over that ceiling.
/// Every outcome is logged at `debug` (the Actions panel), so a row that renders
/// `—` has a stated reason instead of being silent.
async fn fetch_ip_info(params: &NativeConnectParams, provider: IpProvider) -> Option<String> {
    for provider in provider.fallback_chain() {
        if let Some(info) = fetch_ip_info_provider(params, provider).await {
            return Some(info);
        }
    }
    None
}

/// One provider: up to [`IP_INFO_ATTEMPTS`] requests, spaced by
/// [`IP_INFO_RETRY_DELAY`], stepping through [`next_step`].
async fn fetch_ip_info_provider(
    params: &NativeConnectParams,
    provider: IpProvider,
) -> Option<String> {
    // A provider URL is a constant pinned by its own test, so a parse failure
    // here is a bug — but a probe task must not panic on a shared worker.
    let Ok(target) = parse_probe_url(provider.url()) else {
        tracing::debug!(
            target: "tui::ops::ping_native",
            "exit-IP URL {} is unusable; skipping {provider}",
            provider.url()
        );
        return None;
    };
    for attempt in 0..IP_INFO_ATTEMPTS {
        let outcome = fetch_ip_info_once(params, provider, &target).await;
        match next_step(outcome, attempt) {
            IpInfoStep::Answered(info) => {
                tracing::debug!(
                    target: "tui::ops::ping_native",
                    "exit IP read from {provider}"
                );
                return Some(info);
            }
            IpInfoStep::Retry => tokio::time::sleep(IP_INFO_RETRY_DELAY).await,
            IpInfoStep::NextProvider => return None,
        }
    }
    None
}

/// The provider's own explanation for a body that carries no answer.
fn refusal_reason(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    v.get("status")
                        .and_then(serde_json::Value::as_str)
                        .map(|s| format!("status={s}"))
                })
        })
        .unwrap_or_else(|| "unexpected body".to_string())
}

/// One exit-IP fetch: a single HTTP request over a fresh tunnel, classified as
/// the provider's answer, a refusal, or a transport miss.
async fn fetch_ip_info_once(
    params: &NativeConnectParams,
    provider: IpProvider,
    target: &ProbeUrl,
) -> IpInfoOutcome {
    let request = ProbeRequest {
        host: &target.host,
        port: target.port,
        https: target.https,
        method: ProbeMethod::Get,
        path: &target.path,
        timeout: IP_INFO_TIMEOUT,
        transport_timeout: IP_INFO_TIMEOUT,
    };
    let outcome = match probe::fetch(params.clone(), &request).await {
        Ok(response) => {
            if (200..300).contains(&response.status) {
                match provider.parse(&response.body) {
                    Some(info) => IpInfoOutcome::Answer(info),
                    None => IpInfoOutcome::Refused(refusal_reason(&response.body)),
                }
            } else {
                IpInfoOutcome::Refused(format!("HTTP {}", response.status))
            }
        }
        Err(e) => IpInfoOutcome::Transport(e.to_string()),
    };
    match &outcome {
        IpInfoOutcome::Answer(_) => {}
        IpInfoOutcome::Refused(reason) => tracing::debug!(
            target: "tui::ops::ping_native",
            "exit-IP fetch refused by {provider}: {reason}"
        ),
        IpInfoOutcome::Transport(e) => tracing::debug!(
            target: "tui::ops::ping_native",
            "exit-IP fetch failed at {provider}: {e}"
        ),
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::{
        IP_INFO_ATTEMPTS, IpInfoOutcome, IpInfoStep, ProbeClass, ProbeFailure, credential_evidence,
        failure_pair, next_step, parse_probe_url, parse_trace_body, refusal_reason,
    };
    use leas_db::models::{FailureCause as C, FailureStage as S};
    use leas_native::error::FailureEvidence as E;
    use rstest::rstest;

    /// The fallback target answers liveness AND the exit IP in one body; any
    /// other body must not be mistaken for one (spec S3).
    #[rstest]
    #[case::trace(b"fl=1\nh=www.cloudflare.com\nip=203.0.113.7\nts=1\nloc=NL\n", Some("203.0.113.7 | NL".to_string()))]
    #[case::crlf(b"ip=203.0.113.7\r\nloc=NL\r\n", Some("203.0.113.7 | NL".to_string()))]
    #[case::missing_loc(b"ip=203.0.113.7\n", Some("203.0.113.7 | -".to_string()))]
    #[case::no_ip(b"loc=NL\n", None)]
    #[case::empty(b"", None)]
    #[case::junk(b"<html>403</html>", None)]
    fn the_trace_body_yields_the_exit_and_country(
        #[case] body: &[u8],
        #[case] want: Option<String>,
    ) {
        assert_eq!(parse_trace_body(body), want);
    }

    /// The persisted pair is computed from the class the engine reported plus
    /// the transport flag — never from prose. The timeout row is the reason the
    /// pair exists: the engine cannot say whether the deadline hit the dial or
    /// the destination, and only `transport_failed` separates them.
    #[rstest]
    #[case::dns(ProbeClass::Dns, None, false, (S::Dial, C::Nxdomain))]
    #[case::refused(ProbeClass::Refused, None, false, (S::Dial, C::Refused))]
    #[case::no_route(ProbeClass::NoRoute, None, false, (S::Dial, C::NoRoute))]
    #[case::unreachable(ProbeClass::Unreachable, None, false, (S::Dial, C::NoRoute))]
    #[case::dial_io(ProbeClass::Dial, None, false, (S::Dial, C::Io))]
    #[case::dial_timeout(ProbeClass::Timeout, None, true, (S::Dial, C::Timeout))]
    #[case::target_timeout(ProbeClass::Timeout, None, false, (S::Target, C::Timeout))]
    #[case::tls_alert(ProbeClass::Tls, Some(E::CertExpired), false, (S::Transport, C::Alert))]
    #[case::reality_wrong_keys(ProbeClass::Reality, Some(E::RealityFallback), false, (S::Transport, C::Config))]
    #[case::front_refused_the_upgrade(ProbeClass::Transport, Some(E::HttpRejected(403)), false, (S::Transport, C::Status))]
    #[case::upgrade_framing(ProbeClass::Transport, None, false, (S::Transport, C::Framing))]
    #[case::protocol_framing(ProbeClass::Protocol, None, false, (S::Protocol, C::Framing))]
    // The origin rejected the SECRET: a config fact, not a framing one.
    #[case::protocol_credentials(ProbeClass::Protocol, Some(E::CredentialsRejected), false, (S::Protocol, C::Config))]
    #[case::protocol_config_defect(ProbeClass::Protocol, Some(E::ConfigDefect), false, (S::Protocol, C::Config))]
    // A local I/O failure that never got past the dial is a DIAL failure.
    #[case::io_dial(ProbeClass::Io, None, true, (S::Dial, C::Io))]
    #[case::io_target(ProbeClass::Io, None, false, (S::Target, C::Io))]
    #[case::target_http(ProbeClass::Http, None, false, (S::Target, C::Status))]
    #[case::config(ProbeClass::Config, Some(E::ConfigDefect), false, (S::Protocol, C::Config))]
    #[case::io(ProbeClass::Io, None, false, (S::Target, C::Io))]
    fn failure_pair_is_class_plus_transport_flag(
        #[case] class: ProbeClass,
        #[case] evidence: Option<E>,
        #[case] transport_failed: bool,
        #[case] want: (S, C),
    ) {
        assert_eq!(failure_pair(class, evidence, transport_failed), want);
    }

    /// T6: the class names the STAGE that failed. A tunnel that ended under a
    /// later phase is a protocol-stage failure, and the engine now says so with
    /// a typed variant — the target leg's record layer reads the tunnel with
    /// `read_exact`, so the EOF used to arrive as `TlsError::Io` → `Tls`.
    /// Measured: 151 rows of the 2026-09-21 run (`vless response header
    /// truncated (EOF)`, `early eof`) were counted as TLS problems.
    #[test]
    fn a_tunnel_that_ended_is_classed_by_the_stage_not_by_its_wrapper() {
        for detail in [
            "the tunnel ended during the target handshake: early eof",
            "the tunnel ended during the target handshake: Connection reset by peer (os error 104)",
        ] {
            let err = leas_native::error::NativeError::TunnelClosed {
                detail: detail.to_owned(),
            };
            let failure = ProbeFailure::from_engine(&err);
            assert_eq!(
                failure.class,
                ProbeClass::Protocol,
                "a tunnel that ended must not be counted as a TLS failure: {err}"
            );
            assert_eq!(
                failure.evidence, None,
                "the class changed; the verdict must not: {err}"
            );
        }
        // And the TLS class still owns real TLS failures, so the fix cannot be
        // "send everything to Protocol".
        let tls = leas_native::error::NativeError::Tls("alert 2 40".into());
        assert_eq!(ProbeFailure::from_engine(&tls).class, ProbeClass::Tls);
    }

    /// The STAGE decides whether the transport failed — never the class.
    ///
    /// The engine reports the stage-1 deadline (`probe transport`) and the
    /// stage-2+ deadline (`probe attempt`) as the SAME class (`Timeout`), so a
    /// class test would call a protocol-stage hang a transport failure — and
    /// retire a working server as unreachable. That is the false negative the
    /// 2026-09-15 audit found.
    #[test]
    fn the_transport_failure_flag_reads_the_stage_not_the_class() {
        use leas_native::error::NativeError;
        // The stage-1 deadline: the dial did not finish. The transport failed.
        let stage1 = ProbeFailure::from_engine(&NativeError::Timeout {
            step: "probe transport",
            limit: std::time::Duration::from_secs(5),
        });
        assert!(
            stage1.transport_failed,
            "the transport stage's own deadline IS a transport failure"
        );
        // The stage-2 deadline: the transport was up, the protocol stage hung.
        let stage2 = ProbeFailure::from_engine(&NativeError::Timeout {
            step: "probe attempt",
            limit: std::time::Duration::from_secs(5),
        });
        assert!(
            !stage2.transport_failed,
            "a protocol-stage hang is NOT a transport failure — the server is up"
        );
        assert_eq!(
            stage1.class, stage2.class,
            "the two share a class, which is exactly why the flag exists"
        );
        // A refused socket IS a transport failure.
        let refused = ProbeFailure::from_engine(&NativeError::Dial("refused".into()));
        assert!(
            refused.transport_failed,
            "a refused socket is a transport failure"
        );
        // A TLS failure is NOT: the transport was up.
        let tls = ProbeFailure::from_engine(&NativeError::Tls("alert 2 40".into()));
        assert!(
            !tls.transport_failed,
            "a TLS failure is a CONFIG failure — the transport was up"
        );
    }

    /// A credential rejection is the PROXY's answer: a protocol-stage failure
    /// carrying the one evidence class that purges, and NOT a transport failure
    /// (which would write the `[fast]` "server unreachable" marker over a live
    /// server).
    #[test]
    fn a_credential_rejection_is_a_protocol_answer_with_credential_evidence() {
        use leas_native::error::{FailureEvidence, NativeError};
        let failure = ProbeFailure::from_engine(&NativeError::AuthRejected {
            detail: "authentication failed, status code: 404 Not Found".into(),
        });
        assert_eq!(failure.class, ProbeClass::Protocol);
        assert_eq!(failure.evidence, Some(FailureEvidence::CredentialsRejected));
        assert!(
            !failure.transport_failed,
            "the server answered; the transport was up"
        );
    }

    /// The ack→verdict bridge (D8): only `Failed` becomes credential
    /// evidence. `Ok` is an acceptance, `Unknown` is a possible-but-unobserved
    /// ack (a lazy sing-box header, a timeout) and `n-a` is a family with no
    /// ack — none of them names the secret.
    #[test]
    fn only_a_failed_ack_is_credential_evidence() {
        use leas_native::error::FailureEvidence;
        use leas_native::protocol::AuthAck;
        for ack in [AuthAck::Ok, AuthAck::Unknown, AuthAck::NotApplicable] {
            assert_eq!(credential_evidence(ack), None, "{ack:?} proves nothing");
        }
        assert_eq!(
            credential_evidence(AuthAck::Failed),
            Some(FailureEvidence::CredentialsRejected)
        );
    }

    /// A failure that happened AFTER the dial keeps the transport span
    /// (spec D12).
    ///
    /// The span is the fact that separates "the server is dead" from "the
    /// server is up and the config is not" (531 of 535 real-timeout rows on
    /// the 2026-09-21 run had a sub-second transport span). It reaches the
    /// caller on the FAILURE, so the batch path can produce the merged row's
    /// "the transport was alive" line.
    ///
    /// The regression this pins: the span used to live in a separate
    /// accumulator that only the non-2xx arm set, so every REAL engine
    /// failure (a timeout, a TLS error, a refusal) dropped it — and the
    /// merged row could never be produced by the batch.
    ///
    /// The peer here accepts the TCP connection and then goes silent: the
    /// dial succeeds (so a transport span exists) and the PROTOCOL stage
    /// times out (so the probe fails).
    #[tokio::test]
    async fn a_failed_probe_still_reports_the_transport_span() {
        use std::time::Duration;

        use leas_native::probe::{ProbeMethod, ProbeRequest, fetch};

        // A peer that accepts and never answers: the transport stage
        // completes, the protocol stage does not.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        });

        let config = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "tcp" },
            "security": { "type": "tls", "sni": "dest.test", "insecure": true }
        }))
        .expect("config parses");
        let params = leas_native::context::NativeConnectParams::new(
            config,
            leas_proto::proto_spec::endpoint::EndpointEssentials::new(
                addr.ip().to_string(),
                addr.port(),
            ),
            leas_native::addr::TargetAddr::new("dest.test", 443),
        );
        let req = ProbeRequest {
            host: "dest.test",
            port: 443,
            https: false,
            method: ProbeMethod::Head,
            path: "/",
            timeout: Duration::from_millis(300),
            transport_timeout: Duration::from_secs(5),
        };
        let err = fetch(params, &req)
            .await
            .expect_err("a silent peer must fail the probe");
        assert!(
            err.transport_span.is_some(),
            "the transport span survives the protocol-stage failure: {err}"
        );
        server.abort();
    }

    /// The provider's refusal shapes are what tell a rate limit (or a broken
    /// endpoint) apart from a dead tunnel — without this the row's `—` is
    /// silent, and a deterministic refusal would be retried like a transient
    /// miss.
    #[test]
    fn refusal_reason_names_the_providers_own_answer() {
        // The measured HTTPS answer (403 on ip-api's free tier).
        assert_eq!(
            refusal_reason(
                br#"{"status":"fail","message":"SSL unavailable for this endpoint, order a key at https://members.ip-api.com/"}"#
            ),
            "SSL unavailable for this endpoint, order a key at https://members.ip-api.com/"
        );
        // A rate-limit / quota answer carries a status but no message.
        assert_eq!(refusal_reason(br#"{"status":"fail"}"#), "status=fail");
        // Not the provider's object at all.
        assert_eq!(
            refusal_reason(b"<html>captive portal</html>"),
            "unexpected body"
        );
    }

    /// Expected shape of a parsed probe URL, for the url → expectation table.
    enum UrlExpect {
        Parsed {
            https: bool,
            host: &'static str,
            port: u16,
            path: &'static str,
        },
        Rejected,
    }

    /// The three probe-URL parsing cases folded into one url → expectation
    /// table: scheme-defaulted ports, an explicit port with a query, and the
    /// rejections (an unsupported scheme, and a bare host with no scheme).
    #[rstest]
    #[case::probe_url_defaults_the_port_per_scheme_https(
        "https://www.gstatic.com/generate_204",
        UrlExpect::Parsed {
            https: true,
            host: "www.gstatic.com",
            port: 443,
            path: "/generate_204",
        }
    )]
    #[case::probe_url_defaults_the_port_per_scheme_http(
        "http://example.com",
        UrlExpect::Parsed {
            https: false,
            host: "example.com",
            port: 80,
            path: "/",
        }
    )]
    #[case::probe_url_keeps_explicit_port_and_query(
        "https://ip-api.com:8443/json/?fields=query,country",
        UrlExpect::Parsed {
            https: true,
            host: "ip-api.com",
            port: 8443,
            path: "/json/?fields=query,country",
        }
    )]
    #[case::probe_url_rejects_unsupported_scheme("socks5://127.0.0.1:1080", UrlExpect::Rejected)]
    #[case::probe_url_rejects_garbage("www.gstatic.com/generate_204", UrlExpect::Rejected)]
    fn probe_url_parsing(#[case] url: &str, #[case] expect: UrlExpect) {
        match expect {
            UrlExpect::Parsed {
                https,
                host,
                port,
                path,
            } => {
                let got = parse_probe_url(url).unwrap_or_else(|e| panic!("{url:?}: {e}"));
                assert_eq!(got.https, https, "{url:?}");
                assert_eq!(got.host, host, "{url:?}");
                assert_eq!(got.port, port, "{url:?}");
                assert_eq!(got.path, path, "{url:?}");
            }
            UrlExpect::Rejected => {
                assert!(parse_probe_url(url).is_err(), "{url:?} must be rejected");
            }
        }
    }

    /// The exit-IP policy in one (outcome, attempt) → step table: this is the
    /// sequence that decides whether a rate-limited provider is ever left
    /// behind — a refusal is deterministic (ask the next provider at once — no
    /// retry can change a rate limit every concurrent probe shares), a transport
    /// miss is transient and gets the retries first, and an answer ends the
    /// fetch.
    #[rstest]
    #[case::refusal_is_fast_on_the_first_attempt(
        IpInfoOutcome::Refused("HTTP 429".into()),
        0,
        IpInfoStep::NextProvider
    )]
    #[case::refusal_is_fast_on_the_last_attempt(
        IpInfoOutcome::Refused("status=fail".into()),
        IP_INFO_ATTEMPTS - 1,
        IpInfoStep::NextProvider
    )]
    #[case::transport_miss_is_retried_while_attempts_remain(
        IpInfoOutcome::Transport("eof".into()),
        0,
        IpInfoStep::Retry
    )]
    #[case::transport_miss_steps_on_at_the_last_attempt(
        IpInfoOutcome::Transport("eof".into()),
        IP_INFO_ATTEMPTS - 1,
        IpInfoStep::NextProvider
    )]
    #[case::an_answer_ends_the_fetch(
        IpInfoOutcome::Answer("1.2.3.4 | X".into()),
        0,
        IpInfoStep::Answered("1.2.3.4 | X".into())
    )]
    fn next_step_over_outcomes(
        #[case] outcome: IpInfoOutcome,
        #[case] attempt: u32,
        #[case] expected: IpInfoStep,
    ) {
        assert_eq!(next_step(outcome, attempt), expected);
    }
}
