//! Server mode: the in-process equivalent of a spawned proxy core.
//!
//! [`NativeCoreServer`] binds one local mixed listener (SOCKS5 + HTTP CONNECT
//! on the same port, selected by the first byte) whose routing engine defaults
//! every connection to a single proxy outbound dialing the connected profile
//! through the native client — the composition a TUI session needs
//! (proxy-all, one profile), layered on the same `inbound → router → outbound`
//! machinery the [`crate::inbound`] module provides.
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
use crate::inbound::http::HttpInboundConfig;
use crate::inbound::mixed::MixedInbound;
use crate::inbound::outbound::{Outbound, OutboundKind, ProxyOutbound};
use crate::inbound::{Socks5InboundConfig, TraceCtx};
use crate::telemetry::{Telemetry, TraceKind, TraceSecurity};

/// Routing tag of the single proxy outbound.
const PROXY_TAG: &str = "proxy";

/// Configuration for a [`NativeCoreServer`] session.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Local mixed (SOCKS5 + HTTP CONNECT) listener address.
    pub listen: SocketAddr,
    /// The proxy outbound: the profile's typed protocol config + server.
    pub proxy: ProxyOutbound,
    /// Telemetry sink; every accepted leg emits trace rows and byte counts.
    pub telemetry: Telemetry,
    /// Accept UDP ASSOCIATE on the mixed listener (defaults on).
    pub udp: bool,
}

impl ServerConfig {
    /// Proxy-all server: one mixed (SOCKS5 + HTTP CONNECT) listener with UDP
    /// ASSOCIATE on.
    #[must_use]
    pub const fn new(listen: SocketAddr, proxy: ProxyOutbound, telemetry: Telemetry) -> Self {
        Self {
            listen,
            proxy,
            telemetry,
            udp: true,
        }
    }
}

/// A running native-core session: the mixed listener bound, accept loop live.
pub struct NativeCoreServer {
    shutdown_tx: watch::Sender<bool>,
    listen_addr: SocketAddr,
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

        // Posture check, once per start: the listen address comes from user
        // config, and the mixed listener authenticates no client — its SOCKS
        // and HTTP configs are built with `auth: None` (there is no TUI
        // surface for credentials, and inventing one here is out of scope). A
        // non-loopback bind therefore publishes an open proxy to everything
        // that can route to this host.
        if !cfg.listen.ip().is_loopback() {
            tracing::warn!(
                listen = %cfg.listen,
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

        // One mixed listener: SOCKS5 and HTTP CONNECT share the port, chosen
        // by the first byte. Bind before spawning so a bind failure leaves
        // nothing running (Decision 3: a leaked port would EADDRINUSE the next
        // start). Each side carries its own trace kind so HTTP legs are not
        // reported as SOCKS.
        let mut socks_config =
            Socks5InboundConfig::new(cfg.listen, engine.clone(), outbounds.clone());
        socks_config.udp = cfg.udp;
        socks_config.trace = Some(TraceCtx {
            telemetry: cfg.telemetry.clone(),
            kind: TraceKind::Tcp,
            protocol: protocol_name.clone(),
            transport: transport.clone(),
            security,
        });
        socks_config.shutdown = Some(shutdown_rx.clone());
        let mut http_config = HttpInboundConfig::new(cfg.listen, engine, outbounds);
        http_config.trace = Some(TraceCtx {
            telemetry: cfg.telemetry.clone(),
            kind: TraceKind::Http,
            protocol: protocol_name,
            transport,
            security,
        });
        http_config.shutdown = Some(shutdown_rx);
        let inbound = MixedInbound::bind(socks_config, http_config).await?;
        let listen_addr = inbound.local_addr()?;
        let mut tasks = Vec::with_capacity(1);
        tasks.push(tokio::spawn(async move {
            if let Err(error) = inbound.serve().await {
                tracing::warn!(%error, "native server: mixed inbound ended");
            }
        }));
        tracing::info!(%listen_addr, "native server: mixed inbound listening");

        Ok(Self {
            shutdown_tx,
            listen_addr,
            tasks,
        })
    }

    /// The bound mixed address (the real port when the config used 0).
    #[must_use]
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
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
    fn config_for(listen: std::net::SocketAddr) -> ServerConfig {
        let (telemetry, _events) = Telemetry::new(16);
        ServerConfig::new(
            listen,
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
    async fn drop_releases_mixed_port() {
        // Acceptance: Drop frees the bound port without awaiting shutdown.
        let listen = ephemeral_addr().await;
        let server = NativeCoreServer::start(config_for(listen)).await.unwrap();
        let bound = server.listen_addr();
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
    async fn shutdown_awaits_and_releases_port() {
        let listen = ephemeral_addr().await;
        let server = NativeCoreServer::start(config_for(listen)).await.unwrap();
        let bound = server.listen_addr();
        server.shutdown().await;
        assert!(
            port_accepts(bound.port()).await,
            "mixed port {bound} still held after shutdown"
        );
    }
}
