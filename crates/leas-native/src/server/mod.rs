//! Server mode: the in-process equivalent of a spawned proxy core.
//!
//! [`NativeCoreServer`] binds a local SOCKS5 listener (plus an optional
//! HTTP CONNECT listener) whose routing engine defaults every connection to
//! a single proxy outbound dialing the connected profile through the native
//! client — the composition a TUI session needs (proxy-all, one profile),
//! layered on the same `inbound → router → outbound` machinery the
//! [`crate::inbound`] module provides.
//!
//! Shutdown is cooperative: [`NativeCoreServer::stop`] fires a watch signal
//! every listener and in-flight connection task selects on, so a disconnect
//! closes live sockets exactly like killing a subprocess core would.
//! [`NativeCoreServer::shutdown`] additionally awaits the accept loops and is
//! the ONLY teardown that guarantees the bound ports are free when it
//! returns; `Drop` signals and aborts the accept loops but cannot await them.

use std::net::SocketAddr;
use std::sync::Arc;

use leas_proto::proto_spec::common::TransportConfig;
use leas_proto::proto_spec::{ProtocolConfig, TlsConfig};
use leas_route::Engine;
use leas_route::ir::{DefaultRoute, ResolveStrategy, RuleSet};
use tokio::sync::watch;

use crate::error::NativeError;
use crate::inbound::http::{HttpInbound, HttpInboundConfig};
use crate::inbound::outbound::{Outbound, OutboundKind, ProxyOutbound};
use crate::inbound::{Socks5Inbound, Socks5InboundConfig, TraceCtx};
use crate::telemetry::{Telemetry, TraceKind, TraceSecurity};

/// Routing tag of the single proxy outbound.
const PROXY_TAG: &str = "proxy";

/// Configuration for a [`NativeCoreServer`] session.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Local SOCKS5 listener address.
    pub socks: SocketAddr,
    /// Optional local HTTP CONNECT listener address.
    pub http: Option<SocketAddr>,
    /// The proxy outbound: the profile's typed protocol config + server.
    pub proxy: ProxyOutbound,
    /// Telemetry sink; every accepted leg emits trace rows and byte counts.
    pub telemetry: Telemetry,
    /// Accept UDP ASSOCIATE on the SOCKS listener (defaults on).
    pub udp: bool,
}

impl ServerConfig {
    /// Proxy-all server: socks (UDP ASSOCIATE on) + optional http listener.
    #[must_use]
    pub const fn new(
        socks: SocketAddr,
        http: Option<SocketAddr>,
        proxy: ProxyOutbound,
        telemetry: Telemetry,
    ) -> Self {
        Self {
            socks,
            http,
            proxy,
            telemetry,
            udp: true,
        }
    }
}

/// A running native-core session: both listeners bound, accept loops live.
pub struct NativeCoreServer {
    shutdown_tx: watch::Sender<bool>,
    socks_addr: SocketAddr,
    http_addr: Option<SocketAddr>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl NativeCoreServer {
    /// Bind both listeners and spawn the accept loops.
    ///
    /// # Errors
    /// Returns [`NativeError::Io`] when a listener cannot bind or
    /// [`NativeError::Config`] when the routing engine cannot compile.
    pub async fn start(cfg: ServerConfig) -> Result<Self, NativeError> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Posture check, once per start: the listen addresses come from user
        // config, and NEITHER inbound authenticates a client — the SOCKS
        // listener is built through `Socks5InboundConfig::new`, which leaves
        // its RFC 1929 `auth` field `None` (there is no TUI surface for
        // credentials, and inventing one here is out of scope). A
        // non-loopback bind therefore publishes an open proxy to everything
        // that can route to this host.
        let exposed =
            !cfg.socks.ip().is_loopback() || cfg.http.is_some_and(|http| !http.ip().is_loopback());
        if exposed {
            tracing::warn!(
                socks = %cfg.socks,
                http = ?cfg.http,
                "native server: binding a non-loopback address — the proxy is \
                 reachable from the network and accepts every client unauthenticated"
            );
        }

        // Proxy-all engine: no rules, default route → the proxy outbound.
        let engine = Arc::new(
            Engine::build(RuleSet {
                rules: Vec::new(),
                default: DefaultRoute::Route {
                    tag: PROXY_TAG.to_owned(),
                },
                resolve_strategy: ResolveStrategy::AsIs,
                probes: Vec::new(),
            })
            .map_err(|error| NativeError::Config(error.to_string()))?,
        );
        let (protocol_name, transport, security) = trace_meta_of_protocol(&cfg.proxy.protocol);
        let outbounds = vec![Outbound {
            tag: PROXY_TAG.to_owned(),
            kind: OutboundKind::Proxy(Box::new(cfg.proxy)),
        }];

        let mut tasks = Vec::with_capacity(2);
        let mut http_addr = None;
        let socks_addr: SocketAddr;

        // SOCKS5 inbound.
        {
            let trace = TraceCtx {
                telemetry: cfg.telemetry.clone(),
                kind: TraceKind::Tcp,
                protocol: protocol_name.clone(),
                transport: transport.clone(),
                security,
            };
            let mut config = Socks5InboundConfig::new(cfg.socks, engine.clone(), outbounds.clone());
            config.udp = cfg.udp;
            config.trace = Some(trace);
            config.shutdown = Some(shutdown_rx.clone());
            let inbound = Socks5Inbound::bind(config).await?;
            socks_addr = inbound.local_addr()?;
            tasks.push(tokio::spawn(async move {
                if let Err(error) = inbound.serve().await {
                    tracing::warn!(%error, "native server: socks5 inbound ended");
                }
            }));
            tracing::info!(%socks_addr, "native server: socks5 inbound listening");
        }

        // Optional HTTP CONNECT inbound.
        if let Some(listen) = cfg.http {
            let trace = TraceCtx {
                telemetry: cfg.telemetry.clone(),
                kind: TraceKind::Http,
                protocol: protocol_name,
                transport,
                security,
            };
            let mut config = HttpInboundConfig::new(listen, engine, outbounds);
            config.trace = Some(trace);
            config.shutdown = Some(shutdown_rx);
            // Both fallible steps share ONE unwind: the SOCKS listener is
            // already bound with its accept loop spawned, so a bare `?` here
            // would return while that port stays held until the local
            // `shutdown_tx` happened to drop. Decision 3 (one core at a
            // time) makes that visible as an EADDRINUSE on the next start,
            // so the half-started server is torn down explicitly.
            let bound = async {
                let inbound = HttpInbound::bind(config).await?;
                let addr = inbound.local_addr()?;
                Ok::<_, NativeError>((inbound, addr))
            }
            .await;
            let (inbound, addr) = match bound {
                Ok(bound) => bound,
                Err(error) => {
                    let _ = shutdown_tx.send(true);
                    for task in std::mem::take(&mut tasks) {
                        task.abort();
                        let _ = task.await;
                    }
                    tracing::warn!(
                        %listen,
                        %error,
                        "native server: http listener failed to bind; socks listener unwound"
                    );
                    return Err(error);
                }
            };
            tasks.push(tokio::spawn(async move {
                if let Err(error) = inbound.serve().await {
                    tracing::warn!(%error, "native server: http inbound ended");
                }
            }));
            http_addr = Some(addr);
            tracing::info!(%addr, "native server: http inbound listening");
        }

        Ok(Self {
            shutdown_tx,
            socks_addr,
            http_addr,
            tasks,
        })
    }

    /// The bound SOCKS5 address (the real port when the config used 0).
    #[must_use]
    pub const fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    /// The bound HTTP CONNECT address, when enabled.
    #[must_use]
    pub const fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    /// Signal every listener and in-flight connection to close.
    ///
    /// Fire-and-forget: the listeners close on their own schedule, so the
    /// ports are NOT guaranteed free when this returns — that is
    /// [`Self::shutdown`]'s guarantee alone.
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Stop and await the accept loops (in-flight connections abort with
    /// the shutdown signal; their tasks are detached).
    ///
    /// The only teardown that guarantees the bound ports are released when it
    /// returns: [`Self::stop`] merely signals, and `Drop` aborts the accept
    /// loops but cannot await them. Decision 3 (one core at a time) makes
    /// that load-bearing — a core switch that skips this may race the next
    /// `start` into EADDRINUSE.
    pub async fn shutdown(mut self) {
        self.stop();
        for task in self.tasks.drain(..) {
            // Cancellation is a normal outcome (a previous `Drop` or unwind
            // may have aborted the task); a panic in an accept loop is not,
            // and swallowing the `JoinError` would hide it completely.
            if let Err(error) = task.await
                && !error.is_cancelled()
            {
                tracing::error!(%error, "native server: inbound accept task panicked");
            }
        }
    }
}

impl Drop for NativeCoreServer {
    /// Best-effort teardown. The watch signal fires FIRST — the detached
    /// per-connection tasks (which are not in `tasks`) only ever see that —
    /// and then the accept loops are aborted so their listeners drop without
    /// waiting to be polled again. Drop cannot await, so the release is not
    /// observable here; `shutdown().await` is the teardown that guarantees
    /// the ports are free on return.
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Trace-row labels for the session's outbound protocol config: the
/// protocol name, the transport tag, and the outer security layer.
///
/// Hysteria2 is a self-contained QUIC dial — no transport field; its TLS is
/// QUIC-internal (quinn), reported as the `Tls` layer for the badge.
fn trace_meta_of_protocol(cfg: &ProtocolConfig) -> (Arc<str>, Arc<str>, TraceSecurity) {
    let (name, transport, security) = match cfg {
        ProtocolConfig::Vless(c) => ("vless", Some(&c.transport), &c.security),
        ProtocolConfig::Vmess(c) => ("vmess", Some(&c.transport), &c.security),
        ProtocolConfig::Trojan(c) => ("trojan", Some(&c.transport), &c.security),
        ProtocolConfig::Hysteria2(c) => ("hysteria2", None, &c.security),
        _ => return ("unknown".into(), "-".into(), TraceSecurity::Plain),
    };
    let transport = match transport {
        Some(TransportConfig::Tcp) => "tcp",
        Some(TransportConfig::Ws(_)) => "ws",
        Some(TransportConfig::Grpc(_)) => "grpc",
        Some(TransportConfig::HttpUpgrade(_)) => "httpupgrade",
        Some(TransportConfig::XHttp(_)) => "xhttp",
        Some(TransportConfig::Http(_)) => "http",
        Some(TransportConfig::Kcp(_)) => "kcp",
        Some(TransportConfig::Quic) | None => "quic",
    };
    let security = match &security.tls {
        None => TraceSecurity::Plain,
        Some(TlsConfig::Tls(_)) => TraceSecurity::Tls,
        Some(TlsConfig::Reality(_)) => TraceSecurity::Reality,
    };
    (name.into(), transport.into(), security)
}

#[cfg(test)]
mod tests {
    use super::{NativeCoreServer, ServerConfig, trace_meta_of_protocol};
    use crate::inbound::ProxyOutbound;
    use crate::telemetry::{Telemetry, TraceSecurity};
    use leas_proto::proto_spec::common::TransportConfig;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use leas_proto::proto_spec::{
        Hysteria2Config, ProtocolConfig, SecurityConfig, TrojanConfig, VlessConfig,
    };

    #[test]
    fn trace_meta_vless_defaults() {
        let cfg = ProtocolConfig::Vless(VlessConfig {
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            uuid_origin: None,
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            encryption: None,
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        });
        let (name, transport, security) = trace_meta_of_protocol(&cfg);
        assert_eq!(&name[..], "vless");
        assert_eq!(&transport[..], "tcp");
        assert_eq!(security, TraceSecurity::Plain);
    }

    #[test]
    fn trace_meta_hysteria2_is_quic() {
        let cfg = ProtocolConfig::Hysteria2(Hysteria2Config {
            auth: "x".into(),
            security: SecurityConfig::default(),
            obfs: None,
            obfs_password: None,
            up: None,
            down: None,
            hop_interval: None,
            pin_sha256: None,
            remarks: None,
        });
        let (name, transport, security) = trace_meta_of_protocol(&cfg);
        assert_eq!(&name[..], "hysteria2");
        assert_eq!(&transport[..], "quic");
        assert_eq!(security, TraceSecurity::Plain);
    }

    #[test]
    fn trace_meta_unknown_kind() {
        let cfg = ProtocolConfig::Trojan(TrojanConfig {
            password: "pw".into(),
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            path: None,
            remarks: None,
        });
        let (name, transport, _) = trace_meta_of_protocol(&cfg);
        assert_eq!(&name[..], "trojan");
        assert_eq!(&transport[..], "tcp");
    }

    /// A server config for teardown tests: the proxy outbound's protocol
    /// config is never dialed — these tests only exercise bind + teardown.
    fn config_for(socks: std::net::SocketAddr, http: Option<std::net::SocketAddr>) -> ServerConfig {
        let (telemetry, _events) = Telemetry::new(16);
        ServerConfig::new(
            socks,
            http,
            ProxyOutbound {
                kind: leas_proto::proto_spec::ProtocolKind::Vless,
                protocol: ProtocolConfig::Vless(VlessConfig {
                    uuid: "00000000-0000-0000-0000-000000000000".into(),
                    uuid_origin: None,
                    security: SecurityConfig::default(),
                    transport: TransportConfig::Tcp,
                    encryption: None,
                    flow: None,
                    path: None,
                    splice: None,
                    remarks: None,
                    mux: None,
                }),
                server: EndpointEssentials::new("example.com", 443),
                resolved_ip: None,
            },
            telemetry,
        )
    }

    /// An ephemeral loopback address (a bound port released again — binding
    /// a `:0` listener and dropping it yields a port that is free right
    /// now, which is exactly what the under-test binds need).
    async fn ephemeral_addr() -> std::net::SocketAddr {
        let sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        sock.local_addr().unwrap()
    }

    /// Port `port` accepts a fresh TCP listener (with retries: an abort
    /// releases a port asynchronously, so a dropped server frees it one
    /// runtime poll later, not synchronously).
    async fn port_accepts(port: u16) -> bool {
        for _ in 0..200 {
            match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
                Ok(_) => return true,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
            }
        }
        false
    }

    #[tokio::test]
    async fn drop_releases_socks_port() {
        // Acceptance: Drop frees the bound port without awaiting shutdown.
        let socks = ephemeral_addr().await;
        let server = NativeCoreServer::start(config_for(socks, None))
            .await
            .unwrap();
        let bound = server.socks_addr();
        assert!(
            !port_accepts(bound.port()).await,
            "port held while server lives"
        );
        drop(server);
        assert!(
            port_accepts(bound.port()).await,
            "port {bound} still held after Drop"
        );
    }

    #[tokio::test]
    async fn shutdown_awaits_and_releases_ports() {
        let socks = ephemeral_addr().await;
        let http = ephemeral_addr().await;
        let server = NativeCoreServer::start(config_for(socks, Some(http)))
            .await
            .unwrap();
        let (socks_addr, http_addr) = (server.socks_addr(), server.http_addr().unwrap());
        server.shutdown().await;
        assert!(
            port_accepts(socks_addr.port()).await,
            "socks port {socks_addr} still held after shutdown"
        );
        assert!(
            port_accepts(http_addr.port()).await,
            "http port {http_addr} still held after shutdown"
        );
    }

    #[tokio::test]
    async fn http_bind_failure_unwinds_socks_listener() {
        // Acceptance: when the HTTP listener cannot bind (here: the port is
        // occupied), the already-bound and already-serving SOCKS listener is
        // torn down instead of leaking until the local `shutdown_tx` drops.
        let socks = ephemeral_addr().await;
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http = occupied.local_addr().unwrap();
        // `NativeCoreServer` derives no `Debug` (it is a handle: watch sender,
        // addresses, join handles), so `expect_err` is unavailable — destructure.
        let Err(error) = NativeCoreServer::start(config_for(socks, Some(http))).await else {
            panic!("http bind on an occupied port must fail");
        };
        assert!(
            matches!(error, crate::error::NativeError::Io(_)),
            "bind failure must surface as Io, got {error:?}"
        );
        assert!(
            port_accepts(socks.port()).await,
            "socks port {socks} leaked after http bind failure"
        );
    }
}
