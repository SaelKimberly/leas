//! SOCKS5 inbound: a local SOCKS5 server (RFC 1928/1929) that accepts
//! connections, routes them through the [`leas_route`] engine, and
//! forwards to direct / block / proxy outbounds.
//!
//! Composition mirrors xray/sing-box: `inbound → router → outbound`. The
//! router is the compiled [`Engine`]; each [`Decision::Route`] names an
//! outbound tag resolved against [`Socks5InboundConfig::outbounds`]. The
//! "proxy" outbound reuses [`crate::connect`] — see [`outbound`].
//!
//! Scope: TCP CONNECT plus UDP ASSOCIATE (when [`Socks5InboundConfig::udp`]
//! is enabled) — each datagram is routed through the engine with its own
//! destination, so a single association may reach direct, block, and proxy
//! outbounds. BIND is refused with `0x07 Command not supported`; a
//! `HijackDns` decision drops the datagram (the inbound has no built-in DNS
//! interceptor) and refuses TCP connections with `0x02`.

pub mod http;
pub mod outbound;
pub mod socks5;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::time::{Duration, Instant};

use leas_route::engine::decide_async;
use leas_route::ir::NetworkMask;
use leas_route::{ConnMeta, Decision, Engine, NetAddr, NetHost};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};

use crate::BoxStream;
use crate::addr::{Host, TargetAddr};
use crate::error::{NativeError, timeouts};
use crate::telemetry::{Counted, Telemetry, TraceGuard, TraceKind, TraceSecurity};

pub use http::{HttpInbound, HttpInboundConfig};
pub use outbound::{Outbound, OutboundKind, ProxyOutbound};
/// Inbound tag reported to the router when [`HttpInboundConfig`] doesn't
/// override it.
pub const DEFAULT_HTTP_INBOUND_TAG: &str = "http-in";
/// Inbound tag reported to the router when [`Socks5InboundConfig`] doesn't
/// override it.
pub const DEFAULT_INBOUND_TAG: &str = "socks-in";

/// The `BND.ADDR`/`BND.PORT` echoed in replies: this inbound reports a
/// zero address (the client already knows its peer; RFC 1928 allows it).
const BIND_ZERO: TargetAddr = TargetAddr {
    host: Host::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    port: 0,
};

/// Telemetry context threaded into an inbound by [`crate::server`] (the
/// connected-profile session). `None` on a config keeps the inbound
/// telemetry-free — existing consumers and tests are untouched.
#[derive(Clone)]
pub struct TraceCtx {
    /// Event sink.
    pub telemetry: Telemetry,
    /// Inbound leg kind stamped on every trace row.
    pub kind: TraceKind,
    /// Outbound protocol name (`"vless"`, …) — shared across every leg.
    pub protocol: Arc<str>,
    /// Outbound transport name (`"tcp"`, `"ws"`, …) — shared across legs.
    pub transport: Arc<str>,
    /// Outbound security layer.
    pub security: TraceSecurity,
}

/// Configuration for a [`Socks5Inbound`].
#[derive(Clone)]
pub struct Socks5InboundConfig {
    /// Address to bind (e.g. `127.0.0.1:1080`).
    pub listen: SocketAddr,
    /// RFC 1929 username/password; `None` = no-auth.
    pub auth: Option<(String, String)>,
    /// Inbound tag reported to the router (`ConnMeta.inbound_tag`).
    pub inbound_tag: String,
    /// Compiled routing engine.
    pub engine: Arc<Engine>,
    /// Tagged outbounds the router may select.
    pub outbounds: Vec<Outbound>,
    /// Accept UDP ASSOCIATE (relayed per datagram through the router). Off
    /// keeps the `0x07 Command not supported` refusal.
    pub udp: bool,
    /// Per-connection telemetry (trace rows + byte counting); `None` off.
    pub trace: Option<TraceCtx>,
    /// When set, `serve` stops accepting and in-flight connections abort
    /// once the sender marks shutdown (`send(true)` or drop).
    pub shutdown: Option<watch::Receiver<bool>>,
}

impl Socks5InboundConfig {
    /// Builds a config with no auth, the default inbound tag, and UDP
    /// ASSOCIATE enabled (sing-box socks inbounds default UDP on).
    #[must_use]
    pub fn new(listen: SocketAddr, engine: Arc<Engine>, outbounds: Vec<Outbound>) -> Self {
        Self {
            listen,
            auth: None,
            inbound_tag: DEFAULT_INBOUND_TAG.to_owned(),
            engine,
            outbounds,
            udp: true,
            trace: None,
            shutdown: None,
        }
    }

    /// Requires RFC 1929 username/password authentication.
    #[must_use]
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth = Some((username.into(), password.into()));
        self
    }
}

impl fmt::Debug for Socks5InboundConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5InboundConfig")
            .field("listen", &self.listen)
            .field("auth", &self.auth.as_ref().map(|_| "<redacted>"))
            .field("inbound_tag", &self.inbound_tag)
            .field("outbounds", &self.outbounds)
            .field("trace", &self.trace.is_some())
            .field("shutdown", &self.shutdown.is_some())
            .finish_non_exhaustive()
    }
}

/// A bound SOCKS5 server.
pub struct Socks5Inbound {
    listener: TcpListener,
    config: Arc<Socks5InboundConfig>,
}

impl Socks5Inbound {
    /// Binds the listener; call [`Self::serve`] to accept connections.
    ///
    /// # Errors
    /// Returns [`NativeError::Io`] when the listen address cannot be bound.
    pub async fn bind(config: Socks5InboundConfig) -> Result<Self, NativeError> {
        let listener = TcpListener::bind(config.listen).await?;
        warn_if_open_relay(&listener, config.auth.is_some(), "socks5 inbound");
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
                    absorb_accept_error(&error, "socks5 inbound").await;
                    continue;
                }
            };
            // Disable Nagle: interactive traffic through a local proxy should
            // not sit in the output buffer for up to 200ms (Go cores enable
            // TCP_NODELAY by default).
            if let Err(error) = conn.set_nodelay(true) {
                tracing::debug!(%peer, %error, "socks5 inbound: set_nodelay failed");
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
                                    tracing::debug!(%peer, %error, "socks5 inbound: connection closed");
                                }
                            }
                        }
                    }
                    None => {
                        if let Err(error) = handle.await {
                            tracing::debug!(%peer, %error, "socks5 inbound: connection closed");
                        }
                    }
                }
            });
        }
    }
}

/// Breather after an `accept` failure that is not the failed connection's own
/// fault: descriptor or buffer exhaustion clears when live connections close,
/// and spinning on it would burn a core for nothing.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(500);

/// Absorb an `accept` failure and keep the listener alive.
///
/// A dead accept loop is worse than a slow one: the TUI still reports
/// Connected while nothing is listening. A fault belonging to the connection
/// that failed (a client that vanished mid-handshake) retries immediately;
/// anything else — `EMFILE`, `ENOBUFS`, a transient kernel refusal — waits out
/// [`ACCEPT_BACKOFF`] first, because those clear only as live work drains.
async fn absorb_accept_error(error: &std::io::Error, who: &str) {
    use std::io::ErrorKind;

    if matches!(
        error.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
    ) {
        tracing::debug!(%error, "{who}: accept failed for one connection; continuing");
        return;
    }
    tracing::warn!(%error, "{who}: accept failed; retrying after {ACCEPT_BACKOFF:?}");
    tokio::time::sleep(ACCEPT_BACKOFF).await;
}

/// Warn once, at bind time, when an inbound is reachable beyond this host
/// without credentials.
///
/// An inbound on a non-loopback address with no authentication is an open
/// relay: every host that can route to it proxies through this profile, and
/// the TUI's "listening" line does not say so.
fn warn_if_open_relay(listener: &TcpListener, has_auth: bool, who: &str) {
    if has_auth {
        return;
    }
    let Ok(addr) = listener.local_addr() else {
        return;
    };
    if addr.ip().is_loopback() {
        return;
    }
    tracing::warn!(
        %addr,
        "{who}: listening on a non-loopback address with no authentication — \
         every host that can reach it can proxy through this profile"
    );
}

/// One connection: negotiate, then dispatch by command.
async fn handle_conn(
    config: Arc<Socks5InboundConfig>,
    mut conn: TcpStream,
    peer: SocketAddr,
) -> Result<(), NativeError> {
    // Method negotiation (greeting + optional RFC 1929 auth).
    let negotiated = tokio::time::timeout(
        timeouts::PROTOCOL,
        socks5::negotiate(&mut conn, config.auth.as_ref()),
    )
    .await;
    match negotiated {
        Err(_) => {
            return Err(NativeError::Timeout {
                step: "socks5 negotiate",
                limit: timeouts::PROTOCOL,
            });
        }
        Ok(Err(error)) => return Err(error.into()),
        Ok(Ok(())) => {}
    }

    // Request.
    let request = tokio::time::timeout(timeouts::PROTOCOL, socks5::read_request(&mut conn))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "socks5 request",
            limit: timeouts::PROTOCOL,
        })?
        .map_err(NativeError::from)?;

    match request.cmd {
        socks5::Command::Connect => handle_connect(&config, conn, peer, request).await,
        // UDP ASSOCIATE only when the gate is on.
        socks5::Command::UdpAssociate if config.udp => run_udp_associate(config, conn, peer).await,
        // BIND is never supported; UDP ASSOCIATE with the gate off.
        socks5::Command::Bind | socks5::Command::UdpAssociate => {
            socks5::write_reply(
                &mut conn,
                socks5::ReplyCode::CommandNotSupported,
                &BIND_ZERO,
            )
            .await?;
            Ok(())
        }
    }
}

/// Handle a TCP CONNECT: route the destination, dial the outbound, relay.
async fn handle_connect(
    config: &Socks5InboundConfig,
    mut conn: TcpStream,
    peer: SocketAddr,
    request: socks5::Socks5Request,
) -> Result<(), NativeError> {
    // Route the destination.
    let mut meta = ConnMeta {
        target: target_to_net(&request.target),
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
                tracing::warn!(%tag, "socks5 inbound: routing decision named an unknown outbound");
                socks5::write_reply(&mut conn, socks5::ReplyCode::GeneralFailure, &BIND_ZERO)
                    .await?;
                return Ok(());
            };
            match &outbound.kind {
                OutboundKind::Block => {
                    socks5::write_reply(
                        &mut conn,
                        socks5::ReplyCode::ConnectionNotAllowed,
                        &BIND_ZERO,
                    )
                    .await?;
                    Ok(())
                }
                kind => {
                    let target = override_addr
                        .map(|a| net_to_target(&a))
                        .unwrap_or(request.target);
                    let upstream = match outbound::dial(kind, &target).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::warn!(
                                %tag,
                                ?target,
                                %error,
                                "socks5 inbound: outbound dial failed"
                            );
                            socks5::write_reply(&mut conn, reply_for(&error), &BIND_ZERO).await?;
                            return Ok(());
                        }
                    };
                    socks5::write_reply(&mut conn, socks5::ReplyCode::Succeeded, &BIND_ZERO)
                        .await?;
                    match &config.trace {
                        Some(trace) => traced_relay(trace, conn, upstream, &target, &[]).await,
                        None => Box::pin(outbound::relay(conn, upstream)).await,
                    }
                }
            }
        }
        Decision::Reject { .. } => {
            socks5::write_reply(
                &mut conn,
                socks5::ReplyCode::ConnectionNotAllowed,
                &BIND_ZERO,
            )
            .await?;
            Ok(())
        }
        Decision::HijackDns => {
            // The inbound has no built-in DNS interceptor; refuse explicitly
            // (explicit absence beats silent fallthrough).
            tracing::warn!("socks5 inbound: HijackDns decision is not implemented; rejecting");
            socks5::write_reply(
                &mut conn,
                socks5::ReplyCode::ConnectionNotAllowed,
                &BIND_ZERO,
            )
            .await?;
            Ok(())
        }
    }
}

/// Relay a routed TCP leg with telemetry: per-connection up/down counters,
/// one trace open/close pair, and the shared poller traffic deltas.
///
/// The upstream is wrapped TWICE: the inner [`Counted`] feeds this leg's own
/// atomics (the totals the close row reports), the outer one feeds the shared
/// telemetry counters, so the 3 s delta poller sees bytes AS THEY FLOW instead
/// of one lump when the leg ends.
///
/// `prefix` is client payload that arrived together with the inbound's request
/// head (an HTTP `CONNECT` client that pipelines its first TLS record): it goes
/// upstream first, through the wrappers, so it is counted like every other
/// client byte instead of vanishing with the parser's buffer.
///
/// The close row belongs to a [`TraceGuard`], so it fires even when this future
/// is dropped mid-leg by the inbound's shutdown arm.
async fn traced_relay(
    trace: &TraceCtx,
    conn: TcpStream,
    upstream: BoxStream,
    target: &TargetAddr,
    prefix: &[u8],
) -> Result<(), NativeError> {
    let dest = dest_str(target);
    let peer = conn
        .peer_addr()
        .map_or_else(|_| "unknown".into(), |a| a.to_string());
    tracing::info!("accepted {:?} {peer} -> {dest}", trace.kind);
    let conn_id = trace.telemetry.opened(
        trace.kind,
        dest.as_str(),
        trace.protocol.clone(),
        trace.transport.clone(),
        trace.security,
    );
    let (up, down) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let mut guard: TraceGuard = trace
        .telemetry
        .guard(conn_id, Arc::clone(&up), Arc::clone(&down));
    let mut counted = trace.telemetry.counted(Counted::new(upstream, up, down));
    if !prefix.is_empty()
        && let Err(error) = counted.write_all(prefix).await
    {
        let error = NativeError::Io(error);
        tracing::debug!(%error, "{peer} -> {dest}: replaying the pipelined head payload failed");
        guard.finish(Some(error.to_string()));
        return Err(error);
    }
    let result = Box::pin(outbound::relay(conn, Box::new(counted))).await;
    let (up, down) = guard.bytes();
    let elapsed_ms = guard.elapsed_ms();
    if let Some(error) = result.as_ref().err() {
        tracing::info!("closed {peer} -> {dest} error={error} up={up} down={down} {elapsed_ms}ms");
    } else {
        tracing::info!("closed {peer} -> {dest} up={up} down={down} {elapsed_ms}ms");
    }
    guard.finish(result.as_ref().err().map(ToString::to_string));
    result
}

/// `host:port` display form for trace rows (IPv6 literals bracketed).
#[must_use]
fn dest_str(target: &TargetAddr) -> String {
    match &target.host {
        Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", target.port),
        Host::Ip(ip) => format!("{ip}:{}", target.port),
        Host::Domain(domain) => format!("{domain}:{}", target.port),
    }
}

/// How long an association may wait for its FIRST client datagram before the
/// relay gives up and releases its sockets. Once a datagram has arrived the
/// controlling TCP connection is the only lifetime authority (RFC 1928 §7).
const UDP_PIN_DEADLINE: Duration = Duration::from_secs(60);

/// Minimum spacing between retries of a failed per-association resource: the
/// proxy tunnel and the upstream socket binds. Without it a permanently
/// unavailable resource — a dead proxy, or `[::]:0` on a host with IPv6
/// disabled — is retried once per datagram, each costing a syscall and a
/// persisted debug event.
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Queue depth per proxy leg. UDP has no delivery guarantee: a full queue
/// drops the datagram rather than stalling the relay loop.
const PROXY_QUEUE_DEPTH: usize = 256;
/// Cap on queued (unsent) proxy-leg payload bytes per association: 256 queue
/// slots of 64 KiB datagrams could otherwise pin 16 MB behind a slow tunnel.
/// The gate below drops (not queues) past this — same drop-newest policy as
/// the existing `Full` arm, since tokio mpsc cannot drop-oldest.
const PROXY_QUEUE_BYTES: usize = 1_000_000;

/// Handle a UDP ASSOCIATE: reply with the bound client-facing UDP port, then
/// relay datagrams until the controlling TCP connection closes (RFC 1928 §7).
async fn run_udp_associate(
    config: Arc<Socks5InboundConfig>,
    mut conn: TcpStream,
    peer: SocketAddr,
) -> Result<(), NativeError> {
    // Bind the client-facing socket on the concrete address the client
    // reached (the accepted connection's local address), so replies are
    // routable back even when the listener is on a wildcard address. The
    // v4-mapped form of a dual-stack accept is unmapped first: an AF_INET
    // client cannot send to `::ffff:a.b.c.d`, and `BND.ADDR` must name an
    // address it can reach.
    let listen_ip = unmap_v6(conn.local_addr().map_err(NativeError::Io)?).ip();
    let client_udp = UdpSocket::bind(SocketAddr::new(listen_ip, 0)).await?;
    let bind_port = client_udp.local_addr().map_err(NativeError::Io)?.port();
    let bind = TargetAddr::new(Host::Ip(listen_ip), bind_port);
    socks5::write_reply(&mut conn, socks5::ReplyCode::Succeeded, &bind).await?;
    tracing::debug!(%peer, bind_port, "socks5 inbound: udp associate established");

    // The relay owns the TCP stream (its read half signals association end)
    // and the client-facing socket, so it outlives `handle_conn`.
    tokio::spawn(async move {
        if let Err(error) = run_udp_relay(config, conn, client_udp, peer).await {
            tracing::debug!(%error, "socks5 inbound: udp relay closed");
        }
    });
    Ok(())
}

/// Relay datagrams for one UDP ASSOCIATE until the controlling TCP connection
/// closes.
///
/// The control connection is watched from the first poll: a client that
/// associates and then disconnects without sending a datagram must not park
/// this task (and its two sockets) forever. An association that never
/// receives a datagram also expires after [`UDP_PIN_DEADLINE`].
///
/// The inbound's `shutdown` signal ends the association too: this task is
/// spawned by [`run_udp_associate`] and outlives the accept loop's
/// per-connection future, so without an arm of its own a live association would
/// keep forwarding datagrams through the PREVIOUS profile's tunnel after a
/// disconnect.
async fn run_udp_relay(
    config: Arc<Socks5InboundConfig>,
    conn: TcpStream,
    client_udp: UdpSocket,
    peer: SocketAddr,
) -> Result<(), NativeError> {
    // The write half stays alive so the control connection stays open; the
    // client signals the end by closing its side (read half → EOF).
    let (mut control, _control_w) = tokio::io::split(conn);

    // Cloned before `config` moves into the relay state below.
    let mut shutdown = config.shutdown.clone();

    let mut relay = UdpRelay {
        config,
        peer,
        source: None,
        client_udp: Arc::new(client_udp),
        out_v4: None,
        out_v6: None,
        dns_cache: Arc::new(DnsCache::default()),
        reply_buf: Vec::new(),
        proxy: None,
        proxy_retry_at: None,
        bind_retry_at: None,
        hijack_warned: false,
    };

    let mut client_buf = vec![0u8; 64 * 1024];
    let mut out4_buf = vec![0u8; 64 * 1024];
    let mut out6_buf = vec![0u8; 64 * 1024];
    let mut control_byte = [0u8; 1];
    let pin_deadline = tokio::time::sleep(UDP_PIN_DEADLINE);
    tokio::pin!(pin_deadline);

    loop {
        tokio::select! {
            // The session ended (disconnect, profile switch): the association
            // dies with it. Returning drops `relay`, which closes both sockets
            // and aborts the proxy leg — and the leg's reply task with it.
            () = shutdown_signal(shutdown.as_mut()) => {
                tracing::debug!(%peer, "socks5 inbound: udp association ending on shutdown");
                return Ok(());
            }
            // The controlling TCP connection closed or errored: the
            // association ends (a received byte is protocol garbage too).
            result = control.read(&mut control_byte) => {
                match result {
                    Ok(0) => tracing::trace!("socks5 inbound: udp control EOF"),
                    Ok(_) => tracing::debug!("socks5 inbound: udp control garbage, closing"),
                    Err(error) => tracing::debug!(%error, "socks5 inbound: udp control error"),
                }
                return Ok(());
            }
            // No client datagram ever arrived: release the association.
            () = &mut pin_deadline, if relay.source.is_none() => {
                tracing::debug!(
                    %peer,
                    "socks5 inbound: udp association expired before its first datagram"
                );
                return Ok(());
            }
            // A client datagram to forward.
            result = relay.client_udp.recv_from(&mut client_buf) => {
                let (len, from) = match result {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::debug!(%error, "socks5 inbound: udp client recv error");
                        return Ok(());
                    }
                };
                if !relay.accept_source(from) {
                    continue;
                }
                relay.forward_client(&client_buf[..len]).await;
            }
            // A direct-outbound reply (IPv4 upstream).
            result = recv_from_opt(relay.out_v4.as_deref(), &mut out4_buf),
                if relay.out_v4.is_some() =>
            {
                if !relay.reply_to_client(result, &out4_buf).await {
                    return Ok(());
                }
            }
            // A direct-outbound reply (IPv6 upstream).
            result = recv_from_opt(relay.out_v6.as_deref(), &mut out6_buf),
                if relay.out_v6.is_some() =>
            {
                if !relay.reply_to_client(result, &out6_buf).await {
                    return Ok(());
                }
            }
        }
    }
}

/// `recv_from` on an optional socket. The `None` arm never resolves, so the
/// branch is inert until its `if` guard sees a socket — no dead match arm and
/// no immediately-ready branch that could spin the relay loop.
async fn recv_from_opt(
    sock: Option<&UdpSocket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    match sock {
        Some(sock) => sock.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

/// Resolve when the inbound's shutdown signal fires (or its sender is dropped);
/// never resolve when the inbound has no shutdown wired.
///
/// `watch::Receiver::changed` is cancel-safe, so this may sit in a `select!`
/// arm inside a loop without missing a signal.
async fn shutdown_signal(rx: Option<&mut watch::Receiver<bool>>) {
    match rx {
        // `Err` means every sender is gone, which is a shutdown too.
        Some(rx) => {
            let _ = rx.changed().await;
        }
        None => std::future::pending().await,
    }
}

/// A datagram queued for the proxy leg. The destination is unresolved: the
/// leg owns resolution so the relay loop never waits on DNS.
struct ProxyDatagram {
    dest: TargetAddr,
    payload: Vec<u8>,
}

/// A spawned task aborted when this handle drops.
///
/// Dropping a bare [`tokio::task::JoinHandle`] only DETACHES its task, so a
/// cancelled association would leave its reply reader parked on a dead tunnel
/// forever, holding the tunnel half and the client socket. Every
/// per-association task therefore travels in this wrapper.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The proxy side of an association: a task owning the datagram tunnel, fed
/// over a queue.
///
/// The tunnel is NEVER read from the relay's `select!`: a stream carrier's
/// frame read spans several awaits, so a cancelled read would lose bytes and
/// desynchronise the tunnel. The leg splits the tunnel
/// ([`crate::PacketTunnel::split`]) and gives the reader its own task, where
/// its future is never cancelled.
struct ProxyLeg {
    /// Routing tag this leg serves; a datagram routed to another proxy tag is
    /// dropped (one association carries one tunnel).
    tag: String,
    queue: mpsc::Sender<ProxyDatagram>,
    /// Unsent payload bytes currently queued (sender + leg both hold this):
    /// the send gate refuses past [`PROXY_QUEUE_BYTES`], the leg releases on
    /// `recv`. Plain counter (not a semaphore): the leg never blocks the
    /// relay, it just stops receiving when slow.
    queued_bytes: Arc<AtomicUsize>,
    /// The leg task, aborted when the leg drops: an association that ends —
    /// control EOF, shutdown, relay error — must take its tunnel down instead
    /// of leaving it forwarding to the previous profile.
    _task: AbortOnDrop,
}

/// Per-association UDP relay state.
struct UdpRelay {
    config: Arc<Socks5InboundConfig>,
    /// Peer of the controlling TCP connection: the only host allowed to drive
    /// this association.
    peer: SocketAddr,
    /// Pinned client datagram source, set by the first accepted datagram.
    source: Option<SocketAddr>,
    /// Client-facing socket. Shared with the proxy leg, which writes replies
    /// straight to the client.
    client_udp: Arc<UdpSocket>,
    /// Direct-outbound sockets, one per address family, created on demand.
    out_v4: Option<Arc<UdpSocket>>,
    out_v6: Option<Arc<UdpSocket>>,
    /// Domain → address cache for the association lifetime, shared with the
    /// spawned resolve-and-send tasks.
    dns_cache: Arc<DnsCache>,
    /// Reply framing buffer, reused for every downlink datagram.
    reply_buf: Vec<u8>,
    /// The proxy leg, opened on the first proxy-routed datagram.
    proxy: Option<ProxyLeg>,
    /// Earliest instant a new proxy leg may be opened after a failure.
    proxy_retry_at: Option<Instant>,
    /// Earliest instant a failed upstream socket bind may be retried.
    bind_retry_at: Option<Instant>,
    hijack_warned: bool,
}

impl UdpRelay {
    /// Decide whether a datagram source may drive this association.
    ///
    /// The first datagram from the control connection's peer address pins the
    /// association (RFC 1928 §7 permits limiting it). Datagrams from any
    /// other host are dropped: without this check any local process — or any
    /// LAN host, for a non-loopback listener — could race the real client,
    /// have its traffic proxied under the client's routing identity, and
    /// silently take the association over.
    fn accept_source(&mut self, from: SocketAddr) -> bool {
        match self.source {
            Some(pinned) if pinned == from => true,
            Some(_) => {
                tracing::debug!(%from, "socks5 inbound: udp datagram from an unpinned source");
                false
            }
            None => {
                if from.ip() != self.peer.ip() {
                    tracing::debug!(
                        %from,
                        peer = %self.peer,
                        "socks5 inbound: udp datagram from a host other than the control peer"
                    );
                    return false;
                }
                tracing::debug!(%from, "socks5 inbound: udp association pinned");
                self.source = Some(from);
                true
            }
        }
    }

    /// Wrap an upstream reply and send it to the pinned client. Returns
    /// `false` when the association must end.
    async fn reply_to_client(
        &mut self,
        result: std::io::Result<(usize, SocketAddr)>,
        buf: &[u8],
    ) -> bool {
        let (len, src) = match result {
            Ok(pair) => pair,
            Err(error) => {
                tracing::debug!(%error, "socks5 inbound: udp upstream recv error");
                return false;
            }
        };
        let Some(source) = self.source else {
            // An upstream socket exists only after a client datagram, which
            // pins the source.
            return false;
        };
        write_reply(&mut self.reply_buf, src, &buf[..len]);
        match self.client_udp.send_to(&self.reply_buf, source).await {
            Ok(_) => {
                // Grow-only buffer would pin the association's high-water mark
                // forever; drop oversized capacity back once drained.
                if self.reply_buf.capacity() > 16384 {
                    self.reply_buf.shrink_to(2048);
                }
                true
            }
            Err(error) => {
                tracing::debug!(%error, "socks5 inbound: udp reply to client failed");
                false
            }
        }
    }

    /// Forward one client datagram (SOCKS UDP header included) to whichever
    /// outbound its destination routes to.
    ///
    /// Every per-datagram failure drops just that datagram: one unroutable
    /// destination must not tear down the flows multiplexed beside it.
    async fn forward_client(&mut self, datagram: &[u8]) {
        let (frag, target, payload) = match socks5::parse_udp_request(datagram) {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::debug!(%error, "socks5 inbound: malformed udp datagram dropped");
                return;
            }
        };
        if frag != 0 {
            tracing::trace!(frag, "socks5 inbound: dropping fragmented datagram");
            return;
        }

        // Route this datagram's destination. The sniffer needs the WHOLE
        // payload: a QUIC Initial is padded to ≥1200 bytes and the QUIC arm
        // rejects a truncated packet, so a prefix could never decrypt one.
        // The copy is skipped entirely when no rule sniffs.
        let payload_prefix = self
            .config
            .engine
            .needs_sniff()
            .then(|| bytes::Bytes::copy_from_slice(payload));
        let mut meta = ConnMeta {
            target: target_to_net(&target),
            network: NetworkMask::UDP,
            inbound_tag: Some(self.config.inbound_tag.clone()),
            source: self.source,
            source_resolved_ips: Vec::new(),
            payload_prefix,
            sniffed: None,
            sni_host: None,
            resolved_host_ips: Vec::new(),
        };
        let decision = decide_async(&self.config.engine, &mut meta).await;

        let (tag, override_addr) = match decision {
            Decision::Route { tag, override_addr } => (tag, override_addr),
            Decision::Reject { .. } => {
                tracing::debug!("socks5 inbound: udp datagram rejected");
                return;
            }
            Decision::HijackDns => {
                if !self.hijack_warned {
                    self.hijack_warned = true;
                    tracing::warn!(
                        "socks5 inbound: udp HijackDns decision drops datagram \
                         (no built-in DNS interceptor)"
                    );
                }
                return;
            }
        };

        // Clone the config handle so the outbound lookup does not borrow
        // `self` across the `&mut self` forwarding calls — no per-datagram
        // clone of the proxy config.
        let config = Arc::clone(&self.config);
        let Some(outbound) = config.outbounds.iter().find(|o| o.tag.as_str() == &*tag) else {
            tracing::debug!(%tag, "socks5 inbound: udp decision named an unknown outbound");
            return;
        };
        let dest = override_addr.map(|a| net_to_target(&a)).unwrap_or(target);

        match &outbound.kind {
            OutboundKind::Block => {}
            OutboundKind::Direct => self.forward_direct(dest, payload).await,
            OutboundKind::Proxy(proxy) => self.forward_proxy(&tag, proxy, dest, payload),
        }
    }

    /// Send a datagram straight to its destination.
    ///
    /// An IP destination is sent inline. A domain destination is resolved in a
    /// spawned task — a cache miss costs a full DNS lookup, which must not
    /// stall the other flows on this association — and that task receives BOTH
    /// family sockets, so an `AAAA`-only name is reachable (guessing the
    /// family before the lookup would drop every v6 answer).
    async fn forward_direct(&mut self, dest: TargetAddr, payload: &[u8]) {
        self.ensure_direct_sockets().await;
        match dest.host {
            Host::Ip(ip) => {
                let addr = SocketAddr::new(ip, dest.port);
                let Some(socket) = self.socket_for(addr) else {
                    tracing::debug!(%addr, "socks5 inbound: no upstream socket for family");
                    return;
                };
                if let Err(error) = socket.send_to(payload, addr).await {
                    tracing::debug!(%error, %addr, "socks5 inbound: direct udp send dropped");
                }
            }
            Host::Domain(domain) => {
                // Cache hit: send inline. Spawning first (as this used to)
                // meant a task and a payload copy for EVERY domain datagram,
                // including the ones whose address was already known.
                if let Some(addr) = cached_domain(&self.dns_cache, &domain, dest.port) {
                    let Some(socket) = self.socket_for(addr) else {
                        tracing::debug!(%addr, "socks5 inbound: no upstream socket for family");
                        return;
                    };
                    if let Err(error) = socket.send_to(payload, addr).await {
                        tracing::debug!(%error, %addr, "socks5 inbound: direct udp send dropped");
                    }
                    return;
                }
                // Miss: a full DNS lookup must not stall the other flows on
                // this association, so it runs in a task that receives BOTH
                // family sockets (guessing the family before the lookup would
                // drop every `AAAA`-only answer).
                let cache = Arc::clone(&self.dns_cache);
                let payload = payload.to_vec();
                let port = dest.port;
                let v4 = self.out_v4.clone();
                let v6 = self.out_v6.clone();
                tokio::spawn(async move {
                    let Some(addr) = resolve_domain(&cache, &domain, port).await else {
                        tracing::debug!(%domain, "socks5 inbound: direct udp dest unresolvable");
                        return;
                    };
                    let socket = if addr.is_ipv4() { v4 } else { v6 };
                    let Some(socket) = socket else {
                        tracing::debug!(%addr, "socks5 inbound: no upstream socket for family");
                        return;
                    };
                    if let Err(error) = socket.send_to(&payload, addr).await {
                        tracing::debug!(%error, %addr, "socks5 inbound: direct udp send dropped");
                    }
                });
            }
        }
    }

    /// Bind the upstream sockets for BOTH families, on the first direct
    /// datagram (a proxy-only association binds neither).
    ///
    /// A family whose bind fails stays `None`, which drops that family's
    /// datagrams but never the association — a host with IPv6 disabled cannot
    /// bind `[::]:0`. That failure is REMEMBERED for [`RETRY_BACKOFF`]:
    /// retrying per datagram would cost a doomed syscall and a persisted
    /// debug event on every packet an IPv4-only host sends.
    async fn ensure_direct_sockets(&mut self) {
        if self.out_v4.is_some() && self.out_v6.is_some() {
            return;
        }
        if self.bind_retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }
        let mut failed = false;
        for (slot, bind) in [
            (&mut self.out_v4, "0.0.0.0:0"),
            (&mut self.out_v6, "[::]:0"),
        ] {
            if slot.is_some() {
                continue;
            }
            match UdpSocket::bind(bind).await {
                Ok(socket) => *slot = Some(Arc::new(socket)),
                Err(error) => {
                    failed = true;
                    tracing::debug!(%error, bind, "socks5 inbound: upstream udp bind failed");
                }
            }
        }
        // A transient failure (fd pressure) still recovers on the next
        // datagram after the backoff; a permanent one costs one attempt per
        // second, not one per packet.
        self.bind_retry_at = failed.then(|| Instant::now() + RETRY_BACKOFF);
    }

    /// The upstream socket matching `addr`'s family.
    fn socket_for(&self, addr: SocketAddr) -> Option<Arc<UdpSocket>> {
        if addr.is_ipv4() {
            self.out_v4.clone()
        } else {
            self.out_v6.clone()
        }
    }

    /// Queue a datagram for the proxy leg, opening the leg on first use.
    ///
    /// The destination stays a [`TargetAddr`]: resolution happens inside the
    /// leg, so a cache miss cannot stall the relay loop (and thus control-EOF
    /// detection). The tunnel keeps the ORIGINAL target, so a domain stays a
    /// domain and the proxy resolves it.
    fn forward_proxy(
        &mut self,
        tag: &str,
        proxy: &ProxyOutbound,
        dest: TargetAddr,
        payload: &[u8],
    ) {
        if let Some(leg) = &self.proxy
            && leg.tag != tag
        {
            tracing::debug!(
                %tag,
                leg = %leg.tag,
                "socks5 inbound: one udp association carries one proxy tunnel; dropping"
            );
            return;
        }
        if self.proxy.is_none() {
            if self.proxy_retry_at.is_some_and(|at| Instant::now() < at) {
                return;
            }
            let Some(source) = self.source else {
                return;
            };
            let (queue, rx) = mpsc::channel(PROXY_QUEUE_DEPTH);
            let queued_bytes = Arc::new(AtomicUsize::new(0));
            let task = AbortOnDrop(tokio::spawn(run_proxy_leg(
                proxy.clone(),
                dest.clone(),
                Arc::clone(&self.client_udp),
                source,
                Arc::clone(&self.dns_cache),
                Arc::clone(&queued_bytes),
                rx,
            )));
            self.proxy = Some(ProxyLeg {
                tag: tag.to_owned(),
                queue,
                queued_bytes,
                _task: task,
            });
        }
        let leg = self.proxy.as_ref().expect("leg set above");
        // Byte gate ahead of the slot gate: 256 slots of 64 KiB datagrams
        // could pin 16 MB behind a slow tunnel. Over the cap the datagram is
        // dropped (same drop-newest policy as the `Full` arm — tokio mpsc
        // cannot drop-oldest).
        let len = payload.len();
        if leg.queued_bytes.load(std::sync::atomic::Ordering::Relaxed) + len > PROXY_QUEUE_BYTES {
            tracing::debug!("socks5 inbound: proxy udp byte cap reached; dropping datagram");
            return;
        }
        leg.queued_bytes
            .fetch_add(len, std::sync::atomic::Ordering::Relaxed);
        let datagram = ProxyDatagram {
            dest,
            payload: payload.to_vec(),
        };
        match leg.queue.try_send(datagram) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(dropped)) => {
                leg.queued_bytes
                    .fetch_sub(dropped.payload.len(), std::sync::atomic::Ordering::Relaxed);
                tracing::debug!("socks5 inbound: proxy udp queue full; dropping datagram");
            }
            Err(mpsc::error::TrySendError::Closed(dropped)) => {
                leg.queued_bytes
                    .fetch_sub(dropped.payload.len(), std::sync::atomic::Ordering::Relaxed);
                // The leg ended (tunnel open failed, or the tunnel closed).
                // Clear it so a later datagram re-opens, bounded by the
                // backoff — a transient proxy failure must not blackhole the
                // rest of the association.
                tracing::debug!("socks5 inbound: proxy udp leg closed; will re-open");
                self.proxy = None;
                self.proxy_retry_at = Some(Instant::now() + RETRY_BACKOFF);
            }
        }
    }
}

/// Run one association's proxy leg: open the datagram tunnel, split it, read
/// replies in a dedicated task, and write queued datagrams.
///
/// Returning drops the queue receiver, which is how the relay learns the leg
/// is gone and that the next datagram may re-open it.
async fn run_proxy_leg(
    proxy: ProxyOutbound,
    session_target: TargetAddr,
    client_udp: Arc<UdpSocket>,
    source: SocketAddr,
    dns_cache: Arc<DnsCache>,
    queued_bytes: Arc<AtomicUsize>,
    mut queue: mpsc::Receiver<ProxyDatagram>,
) {
    let params = outbound::proxy_params(&proxy, &session_target);
    let tunnel = match crate::connect_udp(&params).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            tracing::debug!(%error, "socks5 inbound: proxy udp tunnel open failed");
            return;
        }
    };
    let (mut reader, mut writer) = match tunnel.split() {
        Ok(halves) => halves,
        Err(error) => {
            tracing::debug!(%error, "socks5 inbound: proxy udp tunnel cannot be split");
            return;
        }
    };
    // Resolved once, for reply headers from a carrier that reports no
    // per-packet address. A domain that will not resolve costs only those
    // replies (the tunnel itself carries the domain).
    let session_addr = resolve_cached(&dns_cache, &session_target).await;

    // The reader owns its half, so its multi-await frame read is never
    // cancelled — the desync this split exists to prevent. The handle rides an
    // `AbortOnDrop`: the reader parks in `recv()` and would NOT wake when the
    // relay drops the queue, so a detached handle leaks a task plus a tunnel
    // per proxy association — including when THIS task is itself aborted.
    let _replies = AbortOnDrop(tokio::spawn(async move {
        // One framing buffer for the leg, like the direct path's.
        let mut packet = Vec::new();
        loop {
            match reader.recv().await {
                Ok(Some((dest, payload))) => {
                    // A carrier without per-packet addresses reports `None`:
                    // the datagram came from the session destination.
                    let Some(src) = dest.or(session_addr) else {
                        tracing::debug!(
                            "socks5 inbound: proxy reply has no address and the session \
                             destination did not resolve; dropping"
                        );
                        continue;
                    };
                    write_reply(&mut packet, src, &payload);
                    if let Err(error) = client_udp.send_to(&packet, source).await {
                        tracing::debug!(%error, "socks5 inbound: proxy reply to client failed");
                        return;
                    }
                }
                Ok(None) => {
                    tracing::debug!("socks5 inbound: proxy udp tunnel closed");
                    return;
                }
                Err(error) => {
                    tracing::debug!(%error, "socks5 inbound: proxy udp tunnel read failed");
                    return;
                }
            }
        }
    }));

    while let Some(datagram) = queue.recv().await {
        // Release this datagram's budget first: the bytes are now owned by
        // this task, not the queue.
        queued_bytes.fetch_sub(datagram.payload.len(), std::sync::atomic::Ordering::Relaxed);
        // The session destination needs no address on the wire — and no DNS:
        // comparing targets short-circuits the common single-destination case.
        // Every carrier accepts `None`; only a DIFFERENT destination needs an
        // explicit address, and the carriers without per-packet addresses
        // refuse those rather than mis-route them.
        let per_packet = if datagram.dest == session_target {
            None
        } else {
            let Some(addr) = resolve_cached(&dns_cache, &datagram.dest).await else {
                tracing::debug!(?datagram.dest, "socks5 inbound: proxy udp dest unresolvable");
                continue;
            };
            Some(addr)
        };
        match writer.send(per_packet, &datagram.payload).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                tracing::debug!(
                    %error,
                    "socks5 inbound: proxy carrier refuses this per-packet destination; dropping"
                );
            }
            Err(error) => {
                tracing::debug!(%error, "socks5 inbound: proxy udp send failed");
                break;
            }
        }
    }
}

/// The association's domain → address cache.
///
/// A short `Vec` rather than a `HashMap`: a probe borrows the domain instead
/// of allocating a `String` key for every datagram, and the cap bounds an
/// association that keeps naming new hosts (the map grew without limit).
type DnsCache = parking_lot::Mutex<Vec<(Box<str>, u16, SocketAddr)>>;

/// Cache entries kept per association; the oldest is dropped when full.
const DNS_CACHE_MAX: usize = 64;

/// Resolve a datagram destination. `None` = unresolvable.
async fn resolve_cached(cache: &DnsCache, target: &TargetAddr) -> Option<SocketAddr> {
    match &target.host {
        Host::Ip(ip) => Some(SocketAddr::new(*ip, target.port)),
        Host::Domain(domain) => resolve_domain(cache, domain, target.port).await,
    }
}

/// Look up `domain` in the association cache without allocating.
fn cached_domain(cache: &DnsCache, domain: &str, port: u16) -> Option<SocketAddr> {
    cache
        .lock()
        .iter()
        .find(|(d, p, _)| *p == port && &**d == domain)
        .map(|(_, _, addr)| *addr)
}

/// Resolve a domain, caching the answer for the association's lifetime.
async fn resolve_domain(cache: &DnsCache, domain: &str, port: u16) -> Option<SocketAddr> {
    if let Some(cached) = cached_domain(cache, domain, port) {
        return Some(cached);
    }
    let addrs = tokio::time::timeout(timeouts::DIAL, tokio::net::lookup_host((domain, port)))
        .await
        .ok()?
        .ok()?;
    let addr = addrs.into_iter().next()?;
    {
        let mut entries = cache.lock();
        if entries.len() >= DNS_CACHE_MAX {
            entries.remove(0);
        }
        entries.push((Box::from(domain), port, addr));
    }
    Some(addr)
}

/// Reverse an IPv4-mapped IPv6 address to plain IPv4 (clients do not expect
/// v6-mapped addresses when they reach v4 peers).
#[must_use]
const fn unmap_v6(src: SocketAddr) -> SocketAddr {
    match src {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), src.port()),
            None => src,
        },
        SocketAddr::V4(_) => src,
    }
}

/// Frame one reply datagram into `out`: a SOCKS UDP header naming `src`, then
/// `payload`. The buffer is cleared first, so callers may reuse it.
fn write_reply(out: &mut Vec<u8>, src: SocketAddr, payload: &[u8]) {
    let src = unmap_v6(src);
    let addr = TargetAddr::new(Host::Ip(src.ip()), src.port());
    out.clear();
    socks5::write_udp_header(out, &addr);
    out.extend_from_slice(payload);
}

/// Map an outbound dial error to a SOCKS5 reply code (RFC 1928 §6).
///
/// Only causes the client can act on are reported as such: `0x02` means "not
/// allowed by ruleset", so a local policy refusal maps there while a network
/// fault does not.
#[must_use]
fn reply_for(error: &NativeError) -> socks5::ReplyCode {
    match error {
        NativeError::Dial(_) | NativeError::Timeout { .. } => socks5::ReplyCode::HostUnreachable,
        NativeError::NotImplemented { .. } => socks5::ReplyCode::CommandNotSupported,
        NativeError::Io(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
                socks5::ReplyCode::ConnectionRefused
            }
            // EACCES/EPERM from a local firewall IS a policy refusal.
            std::io::ErrorKind::PermissionDenied => socks5::ReplyCode::ConnectionNotAllowed,
            std::io::ErrorKind::NetworkUnreachable => socks5::ReplyCode::NetworkUnreachable,
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::HostUnreachable => {
                socks5::ReplyCode::HostUnreachable
            }
            // `AddrNotAvailable`/`NotConnected` are local socket problems, not
            // routing verdicts: neither 0x02 nor 0x03 would be truthful.
            _ => socks5::ReplyCode::GeneralFailure,
        },
        NativeError::Config(_)
        | NativeError::Tls(_)
        | NativeError::CertNotValidForName(_)
        | NativeError::CertExpired(_)
        | NativeError::CleartextPeer(_)
        | NativeError::Reality(_)
        | NativeError::Transport(_)
        | NativeError::TransportRejected { .. }
        | NativeError::Protocol { .. }
        | NativeError::TunnelClosed { .. } => socks5::ReplyCode::GeneralFailure,
    }
}

/// Convert a native wire target into the router's [`NetAddr`].
#[must_use]
pub(crate) fn target_to_net(target: &TargetAddr) -> NetAddr {
    NetAddr {
        host: match &target.host {
            Host::Ip(ip) => NetHost::Ip(*ip),
            Host::Domain(domain) => NetHost::Domain(domain.clone()),
        },
        port: target.port,
    }
}

/// Convert a router rewrite ([`NetAddr`]) back into a native wire target.
///
/// Borrows the (possibly `Arc`-shared) decision address; the single
/// `Domain` copy here is per-connection dial setup, never the hot path.
#[must_use]
pub(crate) fn net_to_target(addr: &NetAddr) -> TargetAddr {
    TargetAddr {
        host: match &addr.host {
            NetHost::Ip(ip) => Host::Ip(*ip),
            NetHost::Domain(domain) => Host::Domain(domain.clone()),
        },
        port: addr.port,
    }
}

impl From<socks5::Socks5Error> for NativeError {
    fn from(error: socks5::Socks5Error) -> Self {
        match error {
            socks5::Socks5Error::Io(io) => Self::Io(io),
            other => Self::Config(format!("socks5: {other}")),
        }
    }
}

#[cfg(test)]
mod tests;
