//! E2E pipeline: real-core server scenarios against the native client.
//!
//! Consumers implement [`E2eCase`] to describe one scenario (label, server
//! config, client params, expectations); a driver (Task 3) runs them against
//! resolved core binaries. Gated behind feature `native-e2e`.

pub mod case;
pub mod config;
pub mod core;
pub mod harness;
pub mod variant;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

pub use case::{AppKind, CaseSpec, Flow, ProtocolKind};
pub use core::{CoreKind, CoreUnderTest};
pub use harness::{
    Certs, EchoServer, InnerTlsEchoServer, MUX_SESSION_COUNT, TlsEchoServer, UDP_PROBE_COUNT,
    UDP_PROBE_PAYLOADS, UdpEchoServer, free_port, generate_certs, probe, probe_inner_tls,
    probe_mux, probe_udp, probe_udp_mux, spawn_core, spawn_echo, spawn_inner_tls_echo,
    spawn_tls_echo, spawn_udp_echo,
};
pub use variant::{
    Aes128GcmVariant, Chacha20Poly1305Variant, FingerprintTls, NoTls, PlainServerRealityClientTls,
    PqTls, RealityServerPlainClientTls, RealityTls, RealityWrongPbkTls, RealityWrongSidTls,
    SecurityVariant, StandardTls, TlsVariant,
};

use crate::{NativeConnectParams, NativeError};

/// Core version strings for the e2e sweep (single source of truth; tests
/// import these instead of duplicating constants).
pub const SINGBOX_VERSION: &str = "1.13.16";
pub const XRAY_VERSION: &str = "26.3.27";

/// The SECOND pinned peer: `thirdparty/Xray-core` built from source at HEAD.
///
/// A separate pin on purpose. Pointing `LEAS_CORE_BIN_DIR` at a HEAD build
/// would re-baseline every row in the suite and silently restate its
/// compatibility claim; this pin exists so one differential can target HEAD
/// while `XRAY_VERSION` stays the baseline. Only the pq-enc row uses it.
pub const XRAY_HEAD_VERSION: &str = "26.7.28";
/// Env var naming the directory that holds the HEAD-built `xray` binary.
pub const XRAY_HEAD_BIN_DIR: &str = "LEAS_CORE_HEAD_BIN_DIR";

/// Environment handed to an [`E2eCase`]'s `server_config` builder.
pub struct ServerEnv<'a> {
    pub port: u16,
    pub certs: &'a Certs,
    pub tmp: &'a Path,
    /// The local echo HTTP server (the probe's destination through the
    /// tunnel).
    pub echo: SocketAddr,
    /// The local TLS HTTP server: REALITY inbounds point their
    /// `dest`/`handshake` fallback here (xtls/reality borrows the dest's
    /// TLS `ServerHello` flight, so the fallback must be a real TLS server).
    pub tls_echo: SocketAddr,
    /// The rustls echo target for inner-TLS rows (the app wraps the tunnel
    /// in an engine TLS session to this server); `None` for plain rows.
    pub inner_tls_echo: Option<SocketAddr>,
    /// The UDP echo target for UDP rows (the probe's datagram destination
    /// through the tunnel); `None` for non-UDP rows.
    pub udp_echo: Option<SocketAddr>,
}

/// Expected outcome of the initial `connect()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectExpect {
    /// The tunnel establishes and the probe runs (status/body asserted).
    Ok,
    /// The REALITY client's auth is expected to fail against the server
    /// (wrong pbk/sid, or a non-REALITY server) — `connect()` must return
    /// `Err`, and the client's Spider-X session must reach the server's
    /// dest (its `h2` preface shows up in the `tls_echo` recording). The
    /// probe is skipped.
    ErrRealityFallback,
}

/// Expected probe outcome for an [`E2eCase`].
pub struct E2eExpect {
    /// Whether `connect()` succeeds or falls back.
    pub connect: ConnectExpect,
    pub status: u16,
    pub body: String,
}

impl Default for E2eExpect {
    fn default() -> Self {
        Self {
            connect: ConnectExpect::Ok,
            status: 200,
            body: crate::e2e::config::BODY.to_string(),
        }
    }
}

/// One end-to-end scenario: a core's server config, the native client params
/// that dial it, and the expected probe result.
pub trait E2eCase {
    /// Human-readable scenario name (test label).
    fn label(&self) -> String;
    /// JSON config to write for `core` and spawn on `env.port`.
    fn server_config(&self, core: CoreKind, env: &ServerEnv) -> String;
    /// Native client params dialing the core listener on `port` toward `target`.
    fn client_params(&self, port: u16, target: SocketAddr) -> NativeConnectParams;
    /// Expected probe (status, body) once the tunnel is live.
    fn expected(&self) -> E2eExpect;
    /// The tunnel's destination for this case: the plain echo by default,
    /// the TLS echo for cases whose probe must flow through a transparent
    /// proxy to the dest (a plain client through a REALITY server).
    fn probe_target(&self, env: &ServerEnv) -> SocketAddr {
        env.echo
    }
    /// True when a REALITY fallback's Spider-X session reaches the server's
    /// dest (the `tls_echo`) rather than terminating at the server itself.
    fn spider_reaches_dest(&self) -> bool {
        true
    }
    /// Optional hook to install harness-CA trust before dialing.
    fn client_trust(&self, _certs: &Certs) {}
}

// The flaky segment (core spawn + connect + probe) is retried with fresh
// resources. 5 attempts: the VLESS vision inner-TLS rows (spec §7.4) race a
// server-side teardown — both xray and sing-box occasionally truncate their
// downlink record write when the tunnel's Direct-splice handoff completes
// (the client's wire bytes are spec-correct; the server closes the conn
// mid-flight). The retry is the harness's designed mitigation for such
// flaky segments; the assertions are unchanged.
const ATTEMPTS: u32 = 5;

/// Run the fixed 7-step e2e lifecycle for `case` against `core`.
///
/// The flaky segment (core spawn + connect + probe) is retried with fresh
/// resources; `echo`/`certs`/`tls_echo`/`tempdir` are created once by the caller
/// (rstest fixtures) and shared across the retries.
pub async fn run_against(
    case: &CaseSpec,
    core: &CoreUnderTest,
    certs: &Certs,
    echo: &EchoServer,
    tls_echo: &TlsEchoServer,
) -> Result<(), String> {
    let expect = case.expected();
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    // Inner-TLS rows splice to a dedicated rustls echo target (created once
    // here, outliving the attempt loop like the caller's echo fixtures).
    let inner_tls_echo = if case.app() == AppKind::InnerTls {
        Some(spawn_inner_tls_echo())
    } else {
        None
    };
    // UDP rows echo datagrams to a dedicated UDP target (created once here,
    // outliving the attempt loop; mirror of `inner_tls_echo`).
    let udp_echo = if case.app() == AppKind::Udp {
        Some(spawn_udp_echo())
    } else {
        None
    };
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");
    std::fs::write(&cert_path, &certs.cert_pem).map_err(|e| format!("cert write: {e}"))?;
    std::fs::write(&key_path, &certs.key_pem).map_err(|e| format!("key write: {e}"))?;
    let config_path = dir.path().join("config.json");

    for attempt in 1..=ATTEMPTS {
        // Fresh recording per attempt: the tls_echo is created once before
        // the loop, so without a reset its buffer accumulates across
        // attempts — a preface that arrived just after attempt N's poll
        // expiry could satisfy attempt N+1 spuriously.
        tls_echo.reset_recording();
        let port = free_port();
        let env = ServerEnv {
            port,
            certs,
            tmp: dir.path(),
            echo: echo.addr,
            tls_echo: tls_echo.addr,
            inner_tls_echo: inner_tls_echo.as_ref().map(|s| s.addr),
            udp_echo: udp_echo.as_ref().map(|s| s.addr),
        };
        let config_json = case.server_config(core.kind, &env);
        if std::fs::write(&config_path, &config_json).is_err() {
            return Err(format!("attempt {attempt}: config write failed"));
        }
        // mKCP and xhttp/h3 listeners are datagram-only — the readiness
        // probe is UDP.
        let _core = spawn_core(
            &core.bin,
            core.kind,
            &config_path,
            port,
            matches!(case.network(), "kcp" | "xhttp3") || case.is_udp_listener(),
        );

        case.client_trust(certs);
        let params = case.client_params(port, case.probe_target(&env));
        if matches!(expect.connect, ConnectExpect::ErrRealityFallback) {
            // REALITY fallback scenario: the client's auth must fail. Assert
            // BOTH halves — the connect errors with a REALITY error
            // (RealityFallback), and the client's Spider-X session actually
            // reached the server's dest (its h2 preface shows up in the
            // tls_echo recording) — then skip the probe (there is no tunnel
            // to probe). Accepting *any* connect error here would let an
            // unrelated failure (server not up, timeout) pass the case.
            match crate::connect(params).await {
                Ok(_) => {
                    return Err(format!(
                        "{}: expected RealityFallback, got a connection",
                        case.label()
                    ));
                }
                Err(NativeError::Reality(_)) => {}
                Err(other) => {
                    return Err(format!(
                        "{}: expected RealityFallback (NativeError::Reality), got {other:?}",
                        case.label()
                    ));
                }
            }
            if !case.spider_reaches_dest() {
                // The fallback session terminates at the server itself
                // (plain TLS server) — the spider's bytes never reach the
                // tls_echo. The connect error alone proves the fallback.
                return Ok(());
            }
            // The spider sends its h2 preface right after the fallback
            // session is established; allow 5s for it to traverse the
            // transparent proxy to the dest.
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut saw = false;
            while std::time::Instant::now() < deadline {
                if tls_echo.saw_h2_preface() {
                    saw = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if saw {
                return Ok(());
            }
            eprintln!(
                "[e2e] {}: attempt {attempt}/{ATTEMPTS} fallback: no h2 preface on the dest within 5s",
                case.label()
            );
            continue;
        }
        if case.app() == AppKind::Udp {
            // UDP rows: the probe drives its own `connect_udp` (the tunnel
            // is a datagram tunnel, not a byte stream) and requires every
            // datagram's echo back. Mux+UDP rows probe through the mux
            // tunnel instead (`probe_udp_mux` — the udp443 flow forces the
            // same path, so `case.mux()` covers it).
            let (sent, received) = if case.mux() {
                probe_udp_mux(&params).await
            } else {
                probe_udp(&params).await
            };
            if sent == UDP_PROBE_COUNT && received == UDP_PROBE_COUNT {
                return Ok(());
            }
            eprintln!(
                "[e2e] {}: attempt {attempt}/{ATTEMPTS} udp probe sent {sent} received {received}",
                case.label()
            );
            continue;
        }
        if case.mux() {
            // Mux rows: the probe drives its own `connect_mux` (one tunnel,
            // N concurrent sessions) and requires every session's response
            // back — the single-stream `connect` never runs.
            let (opened, ok) = probe_mux(&params, case.probe_target(&env)).await;
            if opened == MUX_SESSION_COUNT && ok == MUX_SESSION_COUNT {
                return Ok(());
            }
            eprintln!(
                "[e2e] {}: attempt {attempt}/{ATTEMPTS} mux probe opened {opened} ok {ok}",
                case.label()
            );
            continue;
        }
        let mut tunnel = match crate::connect(params).await {
            Ok(t) => t,
            Err(e) => {
                eprintln!(
                    "[e2e] {}: attempt {attempt}/{ATTEMPTS} connect: {e}",
                    case.label()
                );
                continue;
            }
        };
        if case.pq_assert() && !outer_tls_negotiated_hybrid(tunnel.inner_stream()) {
            eprintln!(
                "[e2e] {}: attempt {attempt}/{ATTEMPTS} PQ assertion failed: the outer TLS \
                 handshake fell back to a classical key exchange",
                case.label()
            );
            continue;
        }
        let (status, body) = match case.app() {
            // Inner-TLS rows: the app establishes a real TLS 1.3 session
            // THROUGH the tunnel to the rustls echo target (Direct splice).
            AppKind::InnerTls => probe_inner_tls(tunnel).await,
            AppKind::Plain => probe(&mut tunnel).await,
            // UDP rows return above (before the TCP connect).
            AppKind::Udp => unreachable!("udp rows are handled before the TCP connect"),
        };
        if status == expect.status && body == expect.body {
            return Ok(());
        }
        eprintln!(
            "[e2e] {}: attempt {attempt}/{ATTEMPTS} probe status {status} body {body:?}",
            case.label()
        );
    }
    Err(format!(
        "{}: failed after {ATTEMPTS} attempts",
        case.label()
    ))
}

/// Whether the tunnel's OUTER TLS/REALITY handshake negotiated a hybrid
/// (post-quantum) key-share group — the PQ rows' honesty gate (spec §7.3:
/// a PQ row that silently fell back to classical must fail).
///
/// The engine `TlsStream` sits one or two wrappers down the boxed seam
/// (`VlessClientStream` / `VmessClientStream` response-header peel); the
/// walk recovers it through the `Any` supertrait like the vision splice.
fn outer_tls_negotiated_hybrid(stream: &crate::BoxStream) -> bool {
    use crate::protocol::vless::stream::VlessClientStream;
    use crate::protocol::vmess::stream::VmessClientStream;
    use leas_tls::record::stream::TlsStream;

    fn hybrid(s: &crate::BoxStream) -> bool {
        let any: &dyn std::any::Any = &**s;
        any.downcast_ref::<TlsStream<crate::BoxStream>>()
            .is_some_and(leas_tls::record::stream::TlsStream::negotiated_hybrid)
    }

    let any: &dyn std::any::Any = &**stream;
    if let Some(v) = any.downcast_ref::<VlessClientStream>() {
        return hybrid(v.inner());
    }
    if let Some(m) = any.downcast_ref::<VmessClientStream>() {
        return hybrid(m.inner());
    }
    hybrid(stream)
}
