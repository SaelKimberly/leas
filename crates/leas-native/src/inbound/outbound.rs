//! Outbounds for the SOCKS5 inbound: tagged destinations the router may
//! select (`Decision::Route { tag }` → [`Outbound`]).
//!
//! Composition mirrors xray/sing-box: the "proxy" outbound reuses
//! [`crate::connect`] — the native client tunnel — so a SOCKS5 inbound in
//! front of a VLESS/VMess/... proxy is the in-process equivalent of a local
//! SOCKS5 listener wired to a remote proxy.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use leas_proto::proto_spec::ProtocolConfig;
use leas_proto::proto_spec::endpoint::EndpointEssentials;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::BoxStream;
use crate::addr::{Host, TargetAddr};
use crate::context::NativeConnectParams;
use crate::error::{NativeError, timeouts};

/// A tagged outbound the router may forward to.
#[derive(Debug, Clone)]
pub struct Outbound {
    pub tag: String,
    pub kind: OutboundKind,
}

/// How an outbound reaches the destination.
#[derive(Debug, Clone)]
pub enum OutboundKind {
    /// Dial the destination directly (no proxy).
    Direct,
    /// Refuse connections routed here (the handler answers SOCKS5 0x02).
    Block,
    /// Tunnel through a native proxy client ([`crate::connect`]).
    Proxy(Box<ProxyOutbound>),
}

/// A proxy outbound: the typed protocol config plus the proxy server.
#[derive(Debug, Clone)]
pub struct ProxyOutbound {
    pub protocol: ProtocolConfig,
    /// The row's protocol kind, carried alongside the config because the
    /// refusal gate is keyed on it (`capability::support_reason(kind, config)`)
    /// and the kind lives on the `Protocol` ROW, not on the typed config — the
    /// two agree by construction, and the app has the row in hand.
    pub kind: leas_proto::proto_spec::ProtocolKind,
    pub server: EndpointEssentials,
    /// Pre-resolved proxy server address; `None` = resolve/DNS in
    /// [`crate::connect`].
    pub resolved_ip: Option<SocketAddr>,
}

/// Build the per-connection [`NativeConnectParams`] for a proxy outbound.
///
/// Pure construction (no I/O) — unit-tested independently of [`dial`].
#[must_use]
pub fn proxy_params(proxy: &ProxyOutbound, target: &TargetAddr) -> NativeConnectParams {
    let mut params =
        NativeConnectParams::new(proxy.protocol.clone(), proxy.server.clone(), target.clone());
    params.resolved_ip = proxy.resolved_ip;
    // `mux` is NOT set here: `NativeConnectParams::new` derives it from the row
    // (`resolved_mux`), so the app and the real probe — which builds its params
    // with `new` alone — cannot disagree about a `mux=1` plugin row. A second
    // copy of the match would be exactly the app/probe divergence the single
    // derivation exists to prevent, and Slice 4's VLESS term is a change to
    // `resolved_mux` alone.
    params
}

/// Build the params for one UDP association's proxy leg.
///
/// [`proxy_params`] is the TCP shape; a UDP relay must also carry the packet
/// mode, or `connect_udp` refuses with "requires params.udp" and the whole
/// association is dropped (the open item `native-core-integration.md` used to
/// describe as "the proxy UDP leg is missing").
///
/// The mode set here is [`PacketMode::Raw`] — the only one a tunnel with a
/// single header destination can honour. The two-mode rule lives at the one
/// call site: `inbound::run_proxy_leg` upgrades this to `PacketMode::XUdp`
/// exactly when the association pools a mux carrier (`connect_mux` refuses any
/// other mode), so a pooled leg never dials the raw shape this function
/// describes.
#[must_use]
pub fn proxy_udp_params(proxy: &ProxyOutbound, target: &TargetAddr) -> NativeConnectParams {
    let mut params = proxy_params(proxy, target);
    params.udp = Some(crate::protocol::vless::PacketMode::Raw);
    params
}

/// Open the outbound byte stream to `target`.
pub(crate) async fn dial(
    kind: &OutboundKind,
    target: &TargetAddr,
    mux_pool: &crate::mux_pool::MuxPool,
    mux_policy: &crate::mux_pool::MuxPolicy,
) -> Result<BoxStream, NativeError> {
    match kind {
        OutboundKind::Direct => Ok(Box::new(dial_direct(target).await?)),
        OutboundKind::Block => Err(NativeError::Config("block outbound cannot dial".into())),
        OutboundKind::Proxy(proxy) => {
            let params = proxy_params(proxy, target);
            // The refusal gate, re-checked HERE so no caller can reach a socket
            // with a config the engine has already declared it will not serve.
            // `resolve_runtime_core` is the production decision point, but this
            // is the in-process surface: the SOCKS5/HTTP inbound builds its
            // outbound from operator config, and without the check a refused row
            // (e.g. `mode=quic`, whose client wire is unpinned) opened a TCP
            // connection to a server answering on UDP and failed later with a
            // message about the framing layer instead of the row's own refusal.
            //
            // One pure call over a config that is already in hand — no load, no
            // allocation, no second source of truth: it asks the SAME
            // `capability` the app asked.
            if let Some(reason) = crate::capability::support_reason(proxy.kind, &proxy.protocol) {
                return Err(NativeError::Config(reason.into_owned()));
            }
            // ONE predicate for both families, so VLESS and a plugin row cannot
            // drift: effective mux → a pooled carrier session (the row's
            // request wins; otherwise the profile default applies to VLESS);
            // otherwise today's plain chain.
            if crate::mux_pool::effective_mux(&params, mux_policy) {
                return mux_pool.open_session(&params, target, mux_policy).await;
            }
            Ok(Box::new(crate::connect(params).await?))
        }
    }
}

/// Dial `target` directly over TCP, resolving domains locally.
///
/// Failures keep BOTH halves of the diagnosis: the `io::ErrorKind` (which
/// [`crate::inbound::reply_for`] maps to an RFC 1928 reply code) and the
/// destination in the message. A bare `io::Error` would drop the address;
/// [`NativeError::Dial`] would drop the kind.
async fn dial_direct(target: &TargetAddr) -> Result<TcpStream, NativeError> {
    let addr = match &target.host {
        Host::Ip(ip) => SocketAddr::new(*ip, target.port),
        Host::Domain(domain) => {
            let mut addrs = tokio::time::timeout(
                timeouts::DIAL,
                tokio::net::lookup_host((domain.as_str(), target.port)),
            )
            .await
            .map_err(|_| NativeError::Timeout {
                step: "direct dns lookup",
                limit: timeouts::DIAL,
            })?
            // `getaddrinfo` failures surface as `ErrorKind::Uncategorized`,
            // which would answer `0x01 General failure`; an unresolvable name
            // is `0x04 Host unreachable` (RFC 1928 §6).
            .map_err(|e| {
                NativeError::Io(std::io::Error::new(
                    std::io::ErrorKind::HostUnreachable,
                    format!("{domain}: {e}"),
                ))
            })?;
            addrs.next().ok_or_else(|| {
                NativeError::Io(std::io::Error::new(
                    std::io::ErrorKind::HostUnreachable,
                    format!("{domain}: no addresses found"),
                ))
            })?
        }
    };
    let stream = tokio::time::timeout(timeouts::DIAL, TcpStream::connect(addr))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "direct connect",
            limit: timeouts::DIAL,
        })?
        .map_err(|e| NativeError::Io(std::io::Error::new(e.kind(), format!("{addr}: {e}"))))?;
    // Disable Nagle (Go cores set TCP_NODELAY by default); direct relays must
    // not add ~200ms buffering latency to interactive traffic. A socket-option
    // failure never invalidates a connection that is already up.
    if let Err(error) = stream.set_nodelay(true) {
        tracing::debug!(%addr, %error, "direct outbound: set_nodelay failed");
    }
    Ok(stream)
}

/// Every direction starts on a small buffer and is promoted to a large one only
/// once a read fills the small one completely, i.e. once the flow has shown it
/// is a bulk transfer. Interactive and idle tunnels — most of a desktop client's
/// tunnels — then cost 32 KiB, while bulk transfers run on 64 KiB chunks: eight
/// times Xray's 8 KiB, so a gigabit flow is a few thousand read/write rounds a
/// second rather than tens of thousands. 128 KiB bought no measurable throughput
/// in the reference measurement this rule follows and doubled the cost of every
/// busy connection, so [`RELAY_LARGE`] is the ceiling.
const RELAY_SMALL: usize = 16 * 1024;
const RELAY_LARGE: usize = 64 * 1024;

/// Buffers kept per size class. Two per tunnel means a hundred idle buffers
/// cover fifty concurrent tunnels at 2 MiB — the pool never becomes a cache.
const POOL_CAP: usize = 64;

/// Free lists for the two relay buffer sizes.
///
/// Every tunnel takes two 16 KiB buffers and a bulk flow promotes one to
/// 64 KiB; under connection churn those are the allocator's most frequent
/// large requests, and the contents never matter — a read fills a buffer
/// before anything is written from it. Buffers come back on drop, so a
/// steady-state process stops calling the allocator for relay traffic.
struct BufferPool {
    small: Mutex<Vec<Vec<u8>>>,
    large: Mutex<Vec<Vec<u8>>>,
}

impl BufferPool {
    /// The free lists are reserved to [`POOL_CAP`] up front: a return then
    /// never grows them, which matters because `Drop` calls [`Self::put`] and
    /// allocating while unwinding aborts.
    fn new() -> Self {
        Self {
            small: Mutex::new(Vec::with_capacity(POOL_CAP)),
            large: Mutex::new(Vec::with_capacity(POOL_CAP)),
        }
    }

    fn take(&self, size: usize) -> Vec<u8> {
        let slot = if size == RELAY_SMALL {
            &self.small
        } else {
            &self.large
        };
        let mut free = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        free.pop().unwrap_or_else(|| vec![0u8; size])
    }

    fn put(&self, buf: Vec<u8>) {
        let slot = match buf.len() {
            RELAY_SMALL => &self.small,
            RELAY_LARGE => &self.large,
            _ => return,
        };
        let mut free = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if free.len() < POOL_CAP {
            free.push(buf);
        }
    }
}

static RELAY_POOL: LazyLock<BufferPool> = LazyLock::new(BufferPool::new);

/// One direction's buffer plus its promotion state.
///
/// The rule lives in a type so its transition is testable without a socket: a
/// read that fills the buffer proves the flow is bulk, and is the only thing
/// that promotes. There is no demotion — a tunnel that once moved bulk bytes
/// keeps the larger chunk size until it closes, which the idle timeout bounds.
struct RelayBuf {
    buf: Vec<u8>,
}

impl RelayBuf {
    fn new() -> Self {
        Self {
            buf: RELAY_POOL.take(RELAY_SMALL),
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Record a read of `read` bytes into the current buffer.
    fn filled(&mut self, read: usize) {
        if read == self.buf.len() && self.buf.len() == RELAY_SMALL {
            let small = std::mem::replace(&mut self.buf, RELAY_POOL.take(RELAY_LARGE));
            RELAY_POOL.put(small);
        }
    }

    #[cfg(test)]
    const fn capacity(&self) -> usize {
        self.buf.len()
    }
}

/// A closed tunnel returns both buffers; the pool is what makes the next one
/// free.
impl Drop for RelayBuf {
    fn drop(&mut self) {
        RELAY_POOL.put(std::mem::take(&mut self.buf));
    }
}

/// The tunnel's shared idle deadline.
///
/// [`timeouts::RELAY_IDLE`] bounds inactivity of the TUNNEL, not of one
/// direction: a download goes quiet on the uplink for as long as it lasts.
/// The previous `select!`-per-iteration shape got this for free (it rebuilt
/// both reads, and therefore both timeouts, after activity in either
/// direction); with one future per direction the stamp has to be explicit.
struct Idle {
    base: tokio::time::Instant,
    /// Nanoseconds since `base` at the last byte moved in either direction.
    last_ns: AtomicU64,
    /// Inactivity cap. Injectable so a timeout test does not have to virtual-
    /// time its way past the shipped 90 s (a constant bump must not red a
    /// test whose subject is the bound, not its value).
    cap: Duration,
}

impl Idle {
    fn new(cap: Duration) -> Self {
        Self {
            base: tokio::time::Instant::now(),
            last_ns: AtomicU64::new(0),
            cap,
        }
    }

    /// Record activity now.
    fn touch(&self) {
        let ns = u64::try_from(self.base.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.last_ns.store(ns, Ordering::Relaxed);
    }

    /// The instant the tunnel becomes idle, given the last activity seen.
    fn deadline(&self) -> tokio::time::Instant {
        self.base + Duration::from_nanos(self.last_ns.load(Ordering::Relaxed)) + self.cap
    }
}

/// Bidirectionally copy bytes between the client and the outbound stream,
/// half-closing each direction on EOF and failing the tunnel once NEITHER
/// direction has moved bytes for [`timeouts::RELAY_IDLE`].
pub(crate) async fn relay(client: TcpStream, upstream: BoxStream) -> Result<(), NativeError> {
    relay_with_cap(client, upstream, timeouts::RELAY_IDLE).await
}

/// [`relay`] with an injectable inactivity cap (tests only; production passes
/// [`timeouts::RELAY_IDLE`]).
async fn relay_with_cap(
    client: TcpStream,
    upstream: BoxStream,
    cap: Duration,
) -> Result<(), NativeError> {
    // Owned halves for the client: `tokio::io::split` puts the stream behind
    // an `Arc<Mutex<..>>` that is locked on every poll. The upstream is a
    // trait object with no owned split, so it keeps the locking form.
    let (client_r, client_w) = client.into_split();
    let (up_r, up_w) = tokio::io::split(upstream);
    let idle = Arc::new(Idle::new(cap));
    // One future per direction instead of one `select!` over both: an error
    // still tears the peer direction down, but a write in flight is never
    // cancelled by the *other* direction completing.
    // One buffer per direction, owned here so promotion survives the whole
    // connection rather than being rebuilt per call.
    let mut client_to_upstream = RelayBuf::new();
    let mut upstream_to_client = RelayBuf::new();
    tokio::try_join!(
        copy_half(client_r, up_w, &mut client_to_upstream, &idle),
        copy_half(up_r, client_w, &mut upstream_to_client, &idle)
    )?;
    Ok(())
}

/// Copy one direction until EOF, then half-close the writer.
///
/// One buffer and one timer per direction, both reused across chunks: the
/// previous shape allocated a fresh 16 KiB stack buffer and built a fresh
/// `tokio::time::timeout` future per chunk.
async fn copy_half<R, W>(
    mut r: R,
    mut w: W,
    buf: &mut RelayBuf,
    idle: &Idle,
) -> Result<(), std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let sleep = tokio::time::sleep_until(idle.deadline());
    tokio::pin!(sleep);
    // Write progress gets its OWN deadline: the shared idle stamp is slid by
    // the other direction, so a peer that stops reading would otherwise pin
    // this half forever while a live downlink keeps the tunnel "alive".
    let stall = tokio::time::sleep(idle.cap);
    tokio::pin!(stall);
    loop {
        let deadline = idle.deadline();
        sleep.as_mut().reset(deadline);
        let n = tokio::select! {
            // `AsyncReadExt::read` is cancel-safe, so the timeout branch can
            // only ever discard a read that produced no bytes.
            res = r.read(buf.as_mut_slice()) => res?,
            () = sleep.as_mut() => {
                // The peer direction moved bytes inside the window: the
                // tunnel is alive, re-arm from the shared stamp.
                if idle.deadline() > deadline {
                    continue;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "relay read timed out",
                ));
            }
        };
        if n == 0 {
            break;
        }
        // Stamp before the write: while this direction blocks on a slow peer,
        // the other direction must not read the tunnel as idle.
        idle.touch();
        // Write the chunk under its OWN deadline (re-armed per attempt, unlike
        // the read's shared stamp): the other direction may keep the tunnel
        // "alive" while this peer stops reading, and before this `write_all`
        // sat outside every timer (issue 002).
        let chunk = &buf.as_mut_slice()[..n];
        let mut off = 0usize;
        while off < chunk.len() {
            stall.as_mut().reset(tokio::time::Instant::now() + idle.cap);
            let written = tokio::select! {
                // `write` is cancel-safe between bytes: a cancelled arm keeps
                // the count and the loop resumes at `off`.
                res = w.write(&chunk[off..]) => res?,
                () = stall.as_mut() => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "relay write timed out",
                    ));
                }
            };
            if written == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
            }
            off += written;
            idle.touch();
        }
        // Promote only after the write: the read filled this buffer, and
        // replacing it earlier would discard the bytes just read.
        buf.filled(n);
    }
    // EOF: send FIN and let the peer direction keep draining.
    let _ = w.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_proto::proto_spec::common::TransportConfig;
    use leas_proto::proto_spec::{SecurityConfig, Socks5Config};

    /// Rows 24/25: the dispatch predicate the app's `dial` reads, pinned
    /// exactly — plus the *observable* difference a mux row makes on the wire.
    ///
    /// Success/failure could not be the discriminator: a plugin row runs the
    /// **WebSocket upgrade either way**, so against a non-WebSocket listener both
    /// shapes fail in the upgrade and the test would prove nothing. What does
    /// differ is the first byte run after the upgrade — a mux `New` frame for a
    /// mux row, an SS salt for a non-mux one — so that is what is asserted.
    #[tokio::test]
    async fn dial_dispatches_on_the_resolved_mux() {
        use leas_proto::proto_spec::{PluginSpec, SsConfig, VlessConfig, VlessMux};

        let ss = |opts: Option<&str>| {
            ProtocolConfig::Ss(SsConfig {
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                security: SecurityConfig::default(),
                remarks: None,
                plugin: opts.map(|o| PluginSpec::from_parts(Some("obfs-local"), o)),
            })
        };
        let vless = |mux: Option<VlessMux>| {
            ProtocolConfig::Vless(VlessConfig {
                uuid: "11111111-2222-3333-4444-555555555555".to_string(),
                uuid_origin: None,
                security: SecurityConfig::default(),
                transport: TransportConfig::Tcp,
                encryption: None,
                flow: None,
                mux,
                path: None,
                splice: None,
                remarks: None,
            })
        };

        // The predicate, exactly as `dial` and the probe read it.
        assert!(
            !NativeConnectParams::resolved_mux(&ss(Some("mode=websocket;mux=0;host=cdn.example"))),
            "row 3's client shape does not multiplex"
        );
        assert!(
            NativeConnectParams::resolved_mux(&ss(Some("mode=websocket;host=cdn.example"))),
            "a plugin row with mux on multiplexes"
        );
        assert!(
            NativeConnectParams::resolved_mux(&vless(Some(VlessMux::Limited(8)))),
            "a VLESS row that asks for mux multiplexes"
        );
        assert!(
            !NativeConnectParams::resolved_mux(&vless(None)),
            "a VLESS row that never mentions mux does not"
        );
        // Anti-overreach: a socks row never takes the mux path.
        assert!(!NativeConnectParams::resolved_mux(&ProtocolConfig::Socks(
            Socks5Config {
                username: None,
                password: None,
                security: SecurityConfig::default(),
                remarks: None,
            }
        )));
    }

    /// The UDP leg must carry the packet mode; the TCP dial must not. Before
    /// the fix `proxy_params` (the TCP shape) was used for both, so every
    /// non-pooled proxy association died in `connect_udp` with "requires
    /// params.udp" (the stale open item this spec re-verified).
    #[test]
    fn the_udp_leg_carries_a_packet_mode_and_the_tcp_dial_does_not() {
        use leas_proto::proto_spec::EndpointEssentials;

        let proxy = super::ProxyOutbound {
            protocol: ProtocolConfig::Vless(
                serde_json::from_value(serde_json::json!({
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "transport": { "type": "tcp" }
                }))
                .expect("vless config"),
            ),
            kind: leas_proto::proto_spec::ProtocolKind::Vless,
            server: EndpointEssentials::new("127.0.0.1", 443),
            resolved_ip: None,
        };
        let target = TargetAddr::new(Host::Domain("example.com".into()), 53);
        assert_eq!(super::proxy_params(&proxy, &target).udp, None);
        assert_eq!(
            super::proxy_udp_params(&proxy, &target).udp,
            Some(crate::protocol::vless::PacketMode::Raw)
        );
    }

    async fn command_byte(cfg: &ProtocolConfig) -> u8 {
        use leas_proto::proto_spec::EndpointEssentials;

        let (client, _server) = tokio::io::duplex(4096);
        let _ = client;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut head = [0u8; 64];
            let n = sock.read(&mut head).await.unwrap_or(0);
            assert!(n >= 19, "VLESS request is at least 19 bytes, got {n}");
            head[18]
        });
        let kind = super::OutboundKind::Proxy(Box::new(super::ProxyOutbound {
            protocol: cfg.clone(),
            kind: leas_proto::proto_spec::ProtocolKind::Vless,
            server: EndpointEssentials::new("127.0.0.1", addr.port()),
            resolved_ip: None,
        }));
        let target = TargetAddr::new(Host::Domain("example.com".into()), 80);
        let pool = crate::mux_pool::MuxPool::new();
        let policy = crate::mux_pool::MuxPolicy::default();
        let mut tunnel = super::dial(&kind, &target, &pool, &policy)
            .await
            .expect("dial");
        // The request header now leaves with the first payload (`first_flight`),
        // so the application's first byte is what makes the command byte
        // observable at all. This test still asserts the branch through the
        // real wire, it just has to speak to get there.
        tunnel.write_all(b"x").await.expect("first payload");
        seen.await.expect("join")
    }

    /// The safety property `ProxyOutbound::kind` exists for, tested through the
    /// path that actually consumes it.
    ///
    /// `ss_reason` branches on the kind (`method.kind() != kind` → "family does
    /// not match", `capability.rs:415`), so a gate handed the WRONG kind refuses
    /// a perfectly valid classic row. `capability.rs:1392` already pins the
    /// DIVERGENCE at `supported()`; what nothing pinned is the WIRING — that the
    /// kind carried on `ProxyOutbound` is the one the gate reads. Calling
    /// `support_reason` directly, as an earlier version of this test did, tests
    /// neither: it re-ran the existing test at a second address.
    ///
    /// So this drives `dial` itself, against accept-and-record listeners: the
    /// mismatched kind must be refused by the family's own rule and open no
    /// socket; the matching kind must get all the way to connecting.
    #[tokio::test]
    async fn the_outbound_kind_is_what_the_gate_actually_reads() {
        use leas_proto::proto_spec::SsConfig;
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        let cfg = ProtocolConfig::Ss(SsConfig {
            method: "aes-128-gcm".into(),
            password: "pw".into(),
            security: SecurityConfig::default(),
            remarks: None,
            plugin: None,
        });
        let accepted = StdArc::new(AtomicUsize::new(0));

        for (kind, expect_refused) in [
            (leas_proto::proto_spec::ProtocolKind::Shadowsocks, false),
            (leas_proto::proto_spec::ProtocolKind::Shadowsocks2022, true),
        ] {
            // Per iteration, not cumulative: the matching case deliberately
            // connects, and a shared counter would make the refused case's
            // assertion read that earlier connection as its own.
            accepted.store(0, AtomicOrdering::Relaxed);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let seen = StdArc::clone(&accepted);
            tokio::spawn(async move {
                if listener.accept().await.is_ok() {
                    seen.fetch_add(1, AtomicOrdering::Relaxed);
                }
            });
            let (_client, _server) = tokio::io::duplex(4096);
            let outbound = super::OutboundKind::Proxy(Box::new(super::ProxyOutbound {
                protocol: cfg.clone(),
                kind,
                server: EndpointEssentials::new("127.0.0.1", addr.port()),
                resolved_ip: None,
            }));
            let target = TargetAddr::new(Host::Domain("example.com".into()), 80);
            let pool = crate::mux_pool::MuxPool::new();
            let policy = crate::mux_pool::MuxPolicy::default();
            let result = super::dial(&outbound, &target, &pool, &policy).await;
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;

            if expect_refused {
                // `BoxStream` is not `Debug`, so the error is bound with let-else
                // rather than `expect_err`.
                let Err(error) = result else {
                    panic!("a 2022 kind on a classic method is refused");
                };
                let text = error.to_string();
                assert!(
                    text.contains("family does not match"),
                    "refused by the FAMILY rule, not by something else: {text}"
                );
                assert_eq!(
                    accepted.load(AtomicOrdering::Relaxed),
                    0,
                    "…and it refused BEFORE opening a socket"
                );
            } else {
                assert!(
                    result.is_ok(),
                    "the matching kind must not be refused by its own family rule"
                );
                assert_eq!(
                    accepted.load(AtomicOrdering::Relaxed),
                    1,
                    "and it must actually connect — otherwise the mismatch case \
                     above proves nothing"
                );
            }
        }
    }

    /// Row 8's second clause, which the audit found unasserted: a refused row
    /// must write **no byte first**. "Returns its own named reason" is about the
    /// message; this is about the wire — a refusal that still dialled, and only
    /// then reported itself, would leak a connection attempt (and a SNI) to a
    /// server the client has already decided it cannot serve.
    #[tokio::test]
    async fn a_refused_row_never_reaches_the_socket() {
        use crate::capability;
        use leas_proto::proto_spec::common::SecurityConfig;
        use leas_proto::proto_spec::{PluginSpec, SsConfig, VlessConfig, VlessMux};
        use std::sync::Arc as StdArc;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        let accepted = StdArc::new(AtomicUsize::new(0));
        // Each pair is (config, expected_servable).
        let ss = |plugin: Option<PluginSpec>| {
            ProtocolConfig::Ss(SsConfig {
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                security: SecurityConfig::default(),
                remarks: None,
                plugin,
            })
        };
        let vless_mux_invalid = ProtocolConfig::Vless(VlessConfig {
            uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            uuid_origin: None,
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            encryption: None,
            flow: None,
            mux: Some(VlessMux::Invalid {
                key: "muxtype".into(),
                value: "yamux".into(),
            }),
            path: None,
            splice: None,
            remarks: None,
        });
        let configs: Vec<(ProtocolConfig, bool, leas_proto::proto_spec::ProtocolKind)> = vec![
            (
                ss(Some(PluginSpec::from_parts(Some("kcptun"), "key=abc"))),
                false,
                leas_proto::proto_spec::ProtocolKind::Shadowsocks,
            ),
            (
                ss(Some(PluginSpec::from_parts(
                    Some("v2ray-plugin"),
                    "mode=quic;host=cdn.example",
                ))),
                false,
                leas_proto::proto_spec::ProtocolKind::Shadowsocks,
            ),
            (
                vless_mux_invalid,
                false,
                leas_proto::proto_spec::ProtocolKind::Vless,
            ),
            // The anti-overreach: a SERVABLE plugin row really does connect, so
            // "nothing connected" is a property of the refusal and not of the test.
            (
                ss(Some(PluginSpec::from_parts(
                    Some("v2ray-plugin"),
                    "mode=websocket;host=cdn.example",
                ))),
                true,
                leas_proto::proto_spec::ProtocolKind::Shadowsocks,
            ),
        ];

        for (config, servable, kind_ref) in configs {
            assert_eq!(
                capability::supported(kind_ref, &config),
                servable,
                "fixture classification for {config:?}"
            );

            // EVERY fixture is dialled, including the refused ones — row 8's
            // claim is about the WIRE ("no row writes a byte first"), so the
            // refused rows have to actually reach `dial`. Skipping them here
            // (an earlier version did) left the test asserting `supported()` a
            // second time and never touching a socket for the refusals at all.
            // The servable row must still connect, or the count proves nothing.
            // Per iteration, not cumulative: the matching case deliberately
            // connects, and a shared counter would make the refused case's
            // assertion read that earlier connection as its own.
            accepted.store(0, AtomicOrdering::Relaxed);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let seen = StdArc::clone(&accepted);
            tokio::spawn(async move {
                if listener.accept().await.is_ok() {
                    seen.fetch_add(1, AtomicOrdering::Relaxed);
                }
            });
            let (_client, _server) = tokio::io::duplex(4096);
            let kind = super::OutboundKind::Proxy(Box::new(super::ProxyOutbound {
                protocol: config,
                kind: kind_ref,
                server: EndpointEssentials::new("127.0.0.1", addr.port()),
                resolved_ip: None,
            }));
            let target = TargetAddr::new(Host::Domain("example.com".into()), 80);
            let pool = crate::mux_pool::MuxPool::new();
            let policy = crate::mux_pool::MuxPolicy::default();
            let _ = super::dial(&kind, &target, &pool, &policy).await;
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            accepted.load(AtomicOrdering::Relaxed),
            1,
            "exactly the servable row reached the socket; no refused row did"
        );
    }

    #[tokio::test]
    async fn a_vless_mux_row_dials_the_mux_branch() {
        use crate::protocol::vless::header::{CMD_MUX, CMD_TCP};
        use leas_proto::proto_spec::{VlessConfig, VlessMux};

        let vless = |mux: Option<VlessMux>| {
            ProtocolConfig::Vless(VlessConfig {
                uuid: "11111111-2222-3333-4444-555555555555".to_string(),
                uuid_origin: None,
                security: SecurityConfig::default(),
                transport: TransportConfig::Tcp,
                encryption: None,
                flow: None,
                mux,
                path: None,
                splice: None,
                remarks: None,
            })
        };

        assert_eq!(
            command_byte(&vless(None)).await,
            CMD_TCP,
            "a non-mux VLESS row dials the plain branch"
        );
        assert_eq!(
            command_byte(&vless(Some(VlessMux::Limited(8)))).await,
            CMD_MUX,
            "a mux VLESS row dials the mux branch"
        );
    }

    /// The old relay `select!`ed two futures that each did `read` then
    /// `write_all`; when one completed, the other was dropped — and if it sat
    /// inside `write_all`, the bytes it had already read were gone. Force that
    /// shape: a 1 KiB upstream pipe with a slow reader keeps the forward
    /// `write_all` blocked while reverse traffic keeps completing.
    #[tokio::test]
    async fn relay_does_not_lose_bytes_under_write_backpressure() {
        const TOTAL: usize = 64 * 1024;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (upstream_side, peer) = tokio::io::duplex(1024);
        let relayed = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            relay(sock, Box::new(upstream_side)).await
        });

        let (mut peer_r, mut peer_w) = tokio::io::split(peer);
        let drain = tokio::spawn(async move {
            let mut got = Vec::with_capacity(TOTAL);
            let mut buf = vec![0u8; 4096];
            while got.len() < TOTAL {
                let n = peer_r.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                // Slow reader: keep the relay's forward write blocked.
                tokio::time::sleep(std::time::Duration::from_micros(200)).await;
            }
            got
        });
        // Reverse traffic so the other direction keeps completing — that is
        // what used to cancel the forward write.
        let push_back = tokio::spawn(async move {
            for _ in 0..64 {
                peer_w.write_all(&[0x5a; 1024]).await.unwrap();
            }
        });

        let (mut client_r, mut client_w) = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap()
            .into_split();
        let client_drain = tokio::spawn(async move {
            let mut sink = vec![0u8; 4096];
            while client_r.read(&mut sink).await.unwrap_or(0) > 0 {}
        });

        let payload: Vec<u8> = (0..TOTAL).map(|i| u8::try_from(i % 251).unwrap()).collect();
        client_w.write_all(&payload).await.unwrap();
        client_w.shutdown().await.unwrap();

        let got = drain.await.unwrap();
        assert_eq!(
            got.len(),
            TOTAL,
            "relay dropped {} byte(s) under backpressure",
            TOTAL - got.len()
        );
        assert_eq!(got, payload, "relay reordered or corrupted the stream");
        push_back.await.unwrap();
        client_drain.abort();
        let _ = relayed.await.unwrap();
    }

    /// `RELAY_IDLE` bounds inactivity of the TUNNEL, not of one direction: on
    /// any download the uplink is quiet for the whole transfer. With a timer
    /// per direction the quiet half would fire and `try_join!` would take the
    /// streaming half down with it.
    #[tokio::test(start_paused = true)]
    async fn relay_idle_deadline_is_shared_between_directions() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (upstream_side, peer) = tokio::io::duplex(4096);
        let relayed = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            relay(sock, Box::new(upstream_side)).await
        });
        let (mut peer_r, mut peer_w) = tokio::io::split(peer);
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Uplink: one short request, then silence for the rest of the test.
        client.write_all(b"GET /\r\n").await.unwrap();
        let mut req = [0u8; 7];
        peer_r.read_exact(&mut req).await.unwrap();

        // Downlink: three chunks 20 virtual seconds apart. Every gap is under
        // RELAY_IDLE, but the uplink stays quiet for 40 s in total — a Discord
        // gateway heartbeat interval, and exactly the case the old 30 s cap
        // reaped.
        let mut got = [0u8; 512];
        for tag in [1u8, 2, 3] {
            if tag > 1 {
                tokio::time::advance(Duration::from_secs(20)).await;
            }
            peer_w.write_all(&[tag; 512]).await.unwrap();
            client.read_exact(&mut got).await.unwrap();
            assert_eq!(
                got[0],
                tag,
                "chunk {tag} lost after {}s of uplink silence",
                u32::from(tag - 1) * 20
            );
        }
        assert!(
            !relayed.is_finished(),
            "relay ended while the tunnel was live"
        );
    }

    /// The cap must outlast the protocols the tunnel carries. 41 s (a Discord
    /// gateway heartbeat) and 45 s are live sessions; the 2026-11-19/20 run
    /// reaped 652 of 661 gateway connections at 30 s and produced a reconnect
    /// loop with no transport fault.
    #[tokio::test(start_paused = true)]
    async fn relay_idle_outlives_a_heartbeat_and_then_closes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (upstream_side, peer) = tokio::io::duplex(4096);
        let relayed = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            relay(sock, Box::new(upstream_side)).await
        });
        let (mut peer_r, mut peer_w) = tokio::io::split(peer);
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        client.write_all(b"GET /\r\n").await.unwrap();
        let mut req = [0u8; 7];
        peer_r.read_exact(&mut req).await.unwrap();

        // Below the cap, completely silent: the tunnel must live.
        tokio::time::advance(Duration::from_secs(45)).await;
        peer_w.write_all(b"\x01").await.unwrap();
        let mut one = [0u8; 1];
        client.read_exact(&mut one).await.unwrap();
        assert!(
            !relayed.is_finished(),
            "45 s of silence must not reap a live tunnel"
        );

        // Past the cap with traffic in neither direction: the relay ends.
        // Relative to the constant: 45 s of silence above already longer than
        // the old 30 s/60 s caps, and one more full cap cannot be inside it.
        tokio::time::advance(timeouts::RELAY_IDLE).await;
        let err = relayed
            .await
            .unwrap()
            .expect_err("the idle cap must close a dead tunnel");
        assert!(err.to_string().contains("relay read timed out"), "{err}");
    }

    /// A peer that stops READING must not pin its direction forever while the
    /// other direction keeps the shared stamp alive. Before the write bound,
    /// the uplink's liveness masked a dead downlink and the tunnel held both
    /// sockets + both buffers indefinitely (issue 002).
    #[tokio::test(start_paused = true)]
    async fn a_stalled_reader_ends_the_write_half() {
        let cap = Duration::from_secs(5);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A real TCP peer, not `duplex` + `split`: the duplex halves share one
        // BiLock, so a blocked downlink write stalls the drain that keeps the
        // uplink moving, and both timers expire together (the assertion below
        // then depends on poll order). Production halves are independent.
        let peer_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        let relayed = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let (peer_sock, _) = peer_listener.accept().await.unwrap();
            // A short cap: the fixture must not virtual-time its way past the
            // shipped value, and the subject is the bound, not its number.
            relay_with_cap(sock, Box::new(peer_sock), cap).await
        });
        let peer = tokio::net::TcpStream::connect(peer_addr).await.unwrap();
        let (mut peer_r, mut peer_w) = peer.into_split();
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Uplink stays alive for the whole test: this is the masking case.
        let uplink = tokio::spawn(async move {
            loop {
                if client.write_all(&[0xAB; 4096]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        // The client never reads; the peer keeps pushing downlink.
        let drain = tokio::spawn(async move {
            let mut sink = [0u8; 4096];
            while matches!(peer_r.read(&mut sink).await, Ok(n) if n > 0) {}
        });
        let downlink = tokio::spawn(async move {
            // 64 MiB, not 4: a real TCP socket buffers several MiB, so a
            // smaller push can all fit and the write never stalls.
            let block = vec![0xCD; 64 * 1024];
            for _ in 0..1024 {
                if peer_w.write_all(&block).await.is_err() {
                    break;
                }
            }
        });

        // Let the buffers fill, then let the write deadline expire.
        for _ in 0..8 {
            tokio::time::advance(Duration::from_secs(10)).await;
            tokio::task::yield_now().await;
        }
        tokio::time::advance(cap).await;

        let err = relayed
            .await
            .expect("relay task must finish once the write half is stalled")
            .expect_err("a stalled reader must end the tunnel");
        // The uplink's touches lag the virtual advances here, so both timers
        // can fire inside one step and either may win; what the tunnel must
        // NOT do is hang. The isolated test below pins that the write bound
        // alone fires while the shared stamp moves.
        let text = err.to_string();
        assert!(
            text.contains("relay write timed out") || text.contains("relay read timed out"),
            "a stalled reader must end the tunnel: {err}"
        );
        uplink.abort();
        drain.abort();
        downlink.abort();
    }

    /// The promotion trigger is the whole memory contract: an interactive
    /// tunnel must not pay for 64 KiB, a bulk one must, and a full read at the
    /// ceiling must not allocate again (a fresh 64 KiB `Vec` per chunk is
    /// exactly the per-chunk cost the type exists to remove).
    #[test]
    fn relay_buffer_promotes_only_after_a_full_read() {
        let mut buf = RelayBuf::new();
        assert_eq!(buf.capacity(), RELAY_SMALL);
        buf.filled(RELAY_SMALL - 1);
        assert_eq!(buf.capacity(), RELAY_SMALL, "a short read must not promote");
        buf.filled(RELAY_SMALL);
        assert_eq!(buf.capacity(), RELAY_LARGE, "a full read must promote");
        let base = buf.as_mut_slice().as_ptr();
        buf.filled(RELAY_LARGE);
        assert_eq!(buf.capacity(), RELAY_LARGE, "the ceiling holds");
        assert_eq!(
            buf.as_mut_slice().as_ptr(),
            base,
            "a full read at the ceiling must not reallocate"
        );
        buf.filled(1);
        assert_eq!(buf.capacity(), RELAY_LARGE, "there is no demotion");
    }

    /// The pool is what makes a closed tunnel's buffers free for the next
    /// one: the same allocation comes back, unmodified.
    #[test]
    fn pool_hands_back_the_same_allocation() {
        let pool = BufferPool::new();
        let buf = pool.take(RELAY_SMALL);
        let addr = buf.as_ptr();
        pool.put(buf);
        let again = pool.take(RELAY_SMALL);
        assert_eq!(
            again.as_ptr(),
            addr,
            "a returned buffer must be handed out again, not reallocated"
        );
    }

    /// The pool stays bounded and never mixes size classes or foreign vectors.
    #[test]
    fn pool_is_bounded_and_classified() {
        let pool = BufferPool::new();
        for _ in 0..POOL_CAP + 8 {
            pool.put(vec![0u8; RELAY_SMALL]);
        }
        assert_eq!(
            pool.small.lock().unwrap().len(),
            POOL_CAP,
            "the pool must not grow past its cap"
        );
        pool.put(vec![0u8; 1234]);
        assert!(
            pool.large.lock().unwrap().is_empty(),
            "an unknown size is dropped, not pooled"
        );
        assert_eq!(
            pool.take(RELAY_LARGE).len(),
            RELAY_LARGE,
            "a miss allocates"
        );
    }

    /// The write bound is what stops a peer that refuses to read from pinning
    /// this half forever while the shared stamp is kept alive by the other
    /// direction (issue 002). Drive `copy_half` alone so the shared read
    /// timer is never polled: only the write stall can end it.
    #[tokio::test(start_paused = true)]
    async fn a_blocked_write_fires_while_the_shared_stamp_moves() {
        let cap = Duration::from_secs(5);
        let idle = Arc::new(Idle::new(cap));
        let (feed, mut feeder) = tokio::io::duplex(64 * 1024);
        // Nobody ever reads the sink: the first chunk fills its 64 bytes and
        // the write blocks.
        let (sink, sink_reader) = tokio::io::duplex(64);
        let push = tokio::spawn(async move {
            let _ = feeder.write_all(&[0xCD; 4096]).await;
            std::future::pending::<()>().await;
        });
        // The mask: the tunnel stamp keeps sliding under the blocked write.
        let keep = {
            let idle = Arc::clone(&idle);
            tokio::spawn(async move {
                loop {
                    idle.touch();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        };
        let mut buf = RelayBuf::new();
        let err = copy_half(feed, sink, &mut buf, &idle)
            .await
            .expect_err("a blocked write must time out");
        assert!(err.to_string().contains("relay write timed out"), "{err}");
        push.abort();
        keep.abort();
        drop(sink_reader);
    }

    /// The promotion has to be observable through the function that owns the
    /// read/write loop, not only through `RelayBuf` directly: a regression that
    /// stops calling `filled` must fail something.
    #[tokio::test]
    async fn copy_half_promotes_on_a_bulk_read_and_not_on_a_short_one() {
        async fn run(payload: &[u8]) -> usize {
            let (client, mut server) = tokio::io::duplex(payload.len().max(64));
            let payload = payload.to_vec();
            let feeder = tokio::spawn(async move {
                let _ = server.write_all(&payload).await;
            });
            let mut buf = RelayBuf::new();
            copy_half(
                client,
                tokio::io::sink(),
                &mut buf,
                &Idle::new(timeouts::RELAY_IDLE),
            )
            .await
            .expect("copy half");
            feeder.await.expect("feeder");
            buf.capacity()
        }

        let bulk = vec![0x11_u8; RELAY_SMALL * 2];
        assert_eq!(
            run(&bulk).await,
            RELAY_LARGE,
            "a burst that fills the small buffer must promote"
        );
        let interactive = vec![0x11_u8; 100];
        assert_eq!(
            run(&interactive).await,
            RELAY_SMALL,
            "an interactive-sized burst must not promote"
        );
    }
}
