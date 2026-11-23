//! Pooled mux carriers: one physical tunnel serves many sessions (spec
//! `docs/aegis/specs/2026-11-17-mux-carrier-reuse-design.md` §6).
//!
//! Before this module every SOCKS/HTTP leg dialled its own proxy carrier and
//! then used it for exactly one session — multiplexing cost framing and bought
//! nothing. The pool is keyed by the carrier identity (not the row and not the
//! target), picks the least-loaded live carrier under the stream cap, opens a
//! second carrier when all are full, and spills outside the pool once the
//! per-profile carrier cap is reached.
//!
//! Liveness and idle close are opportunistic: every acquire sweeps dead
//! carriers and carriers whose last session ended more than [`MuxPolicy::idle`]
//! ago. There is no background task — a pool with no traffic needs no timer.
//! The tunnel's own keepalive lives as long as this pool holds the
//! [`MuxTunnel`], which is exactly the lifetime the old per-session wrapper
//! could not give it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use leas_proto::proto_spec::ProtocolConfig;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;
use crate::addr::TargetAddr;
use crate::context::NativeConnectParams;
use crate::error::NativeError;
use crate::protocol::MuxTunnel;
use crate::transport::sbox::SboxSession;
use crate::transport::sbox::h2mux::H2Mux;
use crate::transport::sbox::padding::PaddingConn;
use crate::transport::sbox::protocol::{
    PROTOCOL_H2MUX, PROTOCOL_SMUX, PROTOCOL_YAMUX, Request, VERSION0, VERSION1,
};
use crate::transport::sbox::smux::SmuxSession;
use crate::transport::sbox::yamux::YamuxSession;

/// The per-profile mux policy: whether mux is the default, the stream and
/// carrier caps, the idle close window, and (from S2) the wire and padding.
#[derive(Debug, Clone)]
pub struct MuxPolicy {
    /// Default for rows that never spelled a mux key. A row's own request
    /// always wins (`mux=false` stays off).
    pub enabled: bool,
    /// Live sessions one carrier may carry before a second is dialled.
    pub cap: usize,
    /// Carriers one profile may keep; beyond this a session spills to a
    /// temporary carrier (bulk overflow, never queued).
    pub carriers: usize,
    /// A carrier with no live sessions is closed after this long.
    pub idle: Duration,
    /// The wire the profile defaults to for rows without `muxtype`.
    pub wire: MuxWire,
    /// Whether sbox carriers pad their handshake (S2+).
    pub padding: bool,
}

pub use leas_proto::proto_spec::MuxWire;

/// The stream cap a carrier for `params` may reach: the row's own magnitude
/// when it names a bounded one, the profile policy otherwise (issue 004).
#[must_use]
pub fn effective_cap(params: &NativeConnectParams, policy: &MuxPolicy) -> usize {
    params
        .mux_cap
        .filter(|cap| *cap > 0)
        .unwrap_or(policy.cap)
        .max(1)
}

impl Default for MuxPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            cap: 8,
            carriers: 8,
            idle: Duration::from_secs(16),
            wire: MuxWire::MuxCool,
            padding: false,
        }
    }
}

impl MuxPolicy {
    /// The shipped policy: mux is the default for families that have a wire
    /// (VLESS), 8 streams per carrier, 8 carriers.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            enabled: true,
            cap: 8,
            carriers: 8,
            idle: Duration::from_secs(16),
            wire: MuxWire::MuxCool,
            padding: false,
        }
    }
}

/// Whether this dial multiplexes, after row request and profile default.
///
/// The row's explicit spelling always wins (`Limited(0)`/`Invalid` is off); a
/// row with no mux key follows the profile default, and only for a family
/// with a wire — SS plugin rows keep their own `mux=` option (spec D8).
#[must_use]
pub const fn effective_mux(params: &NativeConnectParams, policy: &MuxPolicy) -> bool {
    match &params.protocol {
        // A flow (Vision) makes mux a server-conditional wire: Xray rejects TCP
        // mux under XRV, so the profile default must not silently move a Vision
        // row onto it. Such a row muxes only when it spells mux itself.
        ProtocolConfig::Vless(cfg) => {
            // Two server-conditional wires keep mux off unless the row asks:
            // a flow (Xray rejects TCP mux under XRV) and `xhttp` (prior art —
            // v2rayN/v2rayNG both force mux off for it; XHTTP multiplexes at
            // the transport layer instead).
            let risky = cfg.flow.is_some()
                || matches!(
                    cfg.transport,
                    leas_proto::proto_spec::common::TransportConfig::XHttp(_)
                );
            match params.mux_explicit {
                Some(explicit) => explicit,
                None if risky => false,
                None => policy.enabled,
            }
        }
        ProtocolConfig::Ss(_) => params.mux,
        _ => false,
    }
}

/// Whether this dial's UDP association rides a pooled mux carrier.
///
/// The TCP rule above plus the one flow that forces UDP onto the mux tunnel:
/// `xtls-rprx-vision-udp443` (the same predicate `connect_udp` dispatches on,
/// [`crate::protocol::vless::udp_uses_mux`]). Without it a udp443 row is
/// dialed as XUDP by the protocol phase but built as a per-association raw
/// tunnel by the inbound — the two owners disagreeing is what made
/// `case_37_vision_udp443` red.
#[must_use]
pub fn effective_udp_mux(params: &NativeConnectParams, policy: &MuxPolicy) -> bool {
    let ProtocolConfig::Vless(cfg) = &params.protocol else {
        return false;
    };
    effective_mux(params, policy)
        || crate::protocol::vless::udp_uses_mux(cfg.flow.as_deref(), false)
}

/// The wire this dial uses: the row's named multiplexer wins, a flow row is
/// pinned to MUX.Cool (Xray rejects TCP mux under XRV), otherwise the profile
/// default applies.
#[must_use]
pub fn effective_wire(params: &NativeConnectParams, policy: &MuxPolicy) -> MuxWire {
    match &params.protocol {
        ProtocolConfig::Vless(cfg) => cfg
            .mux
            .as_ref()
            .and_then(leas_proto::proto_spec::VlessMux::wire)
            .unwrap_or_else(|| {
                if cfg.flow.is_some() {
                    MuxWire::MuxCool
                } else {
                    policy.wire
                }
            }),
        // A plugin row's mux is the plugin's own wire, never an sbox one.
        _ => MuxWire::MuxCool,
    }
}

/// The wire-visible carrier identity. Built field-by-field: the row id,
/// remarks and the mux cap are policy, not identity, and a full
/// `ProtocolConfig` hash would split pools over them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MuxKey {
    kind: &'static str,
    credentials: String,
    server_host: String,
    server_port: u16,
    resolved_ip: Option<SocketAddr>,
    transport: String,
    security: String,
    flow: Option<String>,
    wire: MuxWire,
    padding: bool,
}

impl MuxKey {
    /// The identity of the carrier a `params` dial would use.
    #[must_use]
    pub fn of(params: &NativeConnectParams, policy: &MuxPolicy) -> Self {
        let (kind, credentials, transport, security, flow) = match &params.protocol {
            ProtocolConfig::Vless(cfg) => (
                "vless",
                format!(
                    "{}|enc:{:?}",
                    cfg.uuid,
                    cfg.encryption.as_ref().map(ToString::to_string)
                ),
                format!("{:?}", cfg.transport),
                format!("{:?}", cfg.security),
                cfg.flow.as_ref().map(ToString::to_string),
            ),
            ProtocolConfig::Ss(cfg) => (
                "ss",
                format!("{}|{:?}|cipher:{}", cfg.password, cfg.plugin, cfg.method),
                String::new(),
                format!("{:?}", cfg.security),
                None,
            ),
            other => (
                "other",
                format!("{other:?}"),
                String::new(),
                String::new(),
                None,
            ),
        };
        Self {
            kind,
            credentials,
            server_host: params.server.host.clone(),
            server_port: params.server.port,
            resolved_ip: params.resolved_ip,
            transport,
            security,
            flow,
            wire: effective_wire(params, policy),
            padding: policy.padding,
        }
    }
}

/// One physical carrier and its liveness.
struct Carrier {
    tunnel: MuxTunnel,
    live: AtomicUsize,
    last_used: Mutex<Instant>,
    dead: AtomicBool,
}

impl Carrier {
    fn new(tunnel: MuxTunnel) -> Self {
        Self {
            tunnel,
            live: AtomicUsize::new(0),
            last_used: Mutex::new(Instant::now()),
            dead: AtomicBool::new(false),
        }
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Acquire) || self.tunnel.is_dead()
    }

    fn touch(&self) {
        *self.last_used.lock() = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_used.lock().elapsed()
    }
}

/// The pool itself: one map per inbound session, so a profile switch drops
/// every carrier with the inbound that created it.
#[derive(Default)]
pub struct MuxPool {
    inner: Arc<PoolInner>,
}

#[derive(Default)]
struct PoolInner {
    entries: Mutex<HashMap<MuxKey, Vec<Arc<Carrier>>>>,
    /// The idle sweeper is armed once, on the first acquire.
    sweeper: AtomicBool,
    /// Serialises carrier builds: a cold burst must dial ONE carrier per cap
    /// step, not one per concurrent acquire.
    build_gate: tokio::sync::Mutex<()>,
}

/// What the acquire step decided under the lock.
enum Choice {
    Use(Arc<Carrier>),
    Build,
    Spill,
}

impl MuxPool {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire a session for `target`, reusing a carrier when the policy
    /// allows it. On a reused carrier the returned stream holds an `Arc`, so
    /// the carrier outlives the session and its live count drops on close.
    ///
    /// # Errors
    ///
    /// The carrier build failure (`connect_mux`) or the session-open failure
    /// after one retry on a fresh carrier.
    pub async fn open_session(
        &self,
        params: &NativeConnectParams,
        target: &TargetAddr,
        policy: &MuxPolicy,
    ) -> Result<BoxStream, NativeError> {
        self.ensure_sweeper(policy.idle);
        let (carrier, key) = self.acquire(params, policy).await?;
        let (carrier, stream) = if let Ok(stream) = carrier.tunnel.open_session(target).await {
            (carrier, stream)
        } else {
            // The reused carrier died between acquisition and the first
            // frame (h2mux has no liveness flag; smux/yamux can race a
            // close). Evict it and retry ONCE on a fresh carrier — the
            // pre-pool path dialled fresh on every attempt.
            carrier.dead.store(true, Ordering::Release);
            carrier.live.fetch_sub(1, Ordering::AcqRel);
            self.evict(&key, &carrier);
            let fresh = self.fresh_carrier(params, policy, &key).await?;
            match fresh.tunnel.open_session(target).await {
                Ok(stream) => (fresh, stream),
                Err(error) => {
                    fresh.live.fetch_sub(1, Ordering::AcqRel);
                    fresh.dead.store(true, Ordering::Release);
                    self.evict(&key, &fresh);
                    return Err(error);
                }
            }
        };
        carrier.touch();
        Ok(Box::new(PooledSession {
            inner: stream,
            carrier,
        }))
    }

    /// Build, register and reserve one fresh carrier (the retry path).
    async fn fresh_carrier(
        &self,
        params: &NativeConnectParams,
        policy: &MuxPolicy,
        key: &MuxKey,
    ) -> Result<Arc<Carrier>, NativeError> {
        let tunnel = build_tunnel(params, policy).await?;
        let carrier = Arc::new(Carrier::new(tunnel));
        self.register(key, &carrier, policy);
        carrier.live.fetch_add(1, Ordering::AcqRel);
        carrier.touch();
        Ok(carrier)
    }

    /// Acquire a carrier: a reusable one, a freshly built pooled one, or a
    /// spill outside the pool. The carrier's live count is NOT incremented
    /// here; the caller owns the lease.
    async fn acquire(
        &self,
        params: &NativeConnectParams,
        policy: &MuxPolicy,
    ) -> Result<(Arc<Carrier>, MuxKey), NativeError> {
        // Built ONCE here: the key is the caller's eviction handle too, so
        // neither `open_session` nor `open_udp` formats it a second time
        // (issue 005).
        let key = MuxKey::of(params, policy);
        let cap = effective_cap(params, policy);
        match self.choose(&key, policy, cap) {
            Choice::Use(carrier) => Ok((carrier, key)),
            // A spill is never shared, so there is nothing to coalesce and
            // nothing to pool: build it directly (issue 006).
            Choice::Spill => {
                let tunnel = build_tunnel(params, policy).await?;
                let carrier = Arc::new(Carrier::new(tunnel));
                carrier.live.fetch_add(1, Ordering::AcqRel);
                carrier.touch();
                Ok((carrier, key))
            }
            Choice::Build => {
                // Coalesce cold-start builds: without this every concurrent
                // acquire in a burst takes its own `Build` decision and dials
                // (12 CONNECTs → 12 handshakes). The gate is held across
                // choose+build+register; the next waiter re-chooses and finds
                // the carrier.
                //
                // The wait is bounded: a FAILING build holds the gate for the
                // whole CONNECT budget, and queueing behind it would turn a
                // burst against a dead server into N serial 15 s attempts.
                // After the wait, this leg builds unpooled and fails on its
                // own schedule.
                let Ok(_gate) = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    self.inner.build_gate.lock(),
                )
                .await
                else {
                    // The gate was busy for a whole second: build without
                    // waiting, but REGISTER the carrier anyway — a fallback
                    // nobody can reuse is one handshake per CONNECT, the waste
                    // this gate exists to prevent (issue 006).
                    let tunnel = build_tunnel(params, policy).await?;
                    let carrier = Arc::new(Carrier::new(tunnel));
                    self.register(&key, &carrier, policy);
                    carrier.live.fetch_add(1, Ordering::AcqRel);
                    carrier.touch();
                    return Ok((carrier, key));
                };
                match self.choose(&key, policy, cap) {
                    Choice::Use(carrier) => Ok((carrier, key)),
                    Choice::Build => {
                        let tunnel = build_tunnel(params, policy).await?;
                        let carrier = Arc::new(Carrier::new(tunnel));
                        self.register(&key, &carrier, policy);
                        carrier.live.fetch_add(1, Ordering::AcqRel);
                        carrier.touch();
                        Ok((carrier, key))
                    }
                    // Another waiter registered a carrier at the cap while we
                    // held the gate; build unpooled as before.
                    Choice::Spill => {
                        let tunnel = build_tunnel(params, policy).await?;
                        let carrier = Arc::new(Carrier::new(tunnel));
                        carrier.live.fetch_add(1, Ordering::AcqRel);
                        carrier.touch();
                        Ok((carrier, key))
                    }
                }
            }
        }
    }

    /// Acquire a datagram association on a pooled carrier (A12).
    ///
    /// mux.cool opens an XUDP session; an sbox carrier opens a UDP stream. The
    /// returned [`MuxLease`] holds the carrier for the association's lifetime
    /// (dropping it releases the live count and may idle-close the carrier).
    ///
    /// # Errors
    ///
    /// A carrier/session failure, or a family whose UDP path is not pooled
    /// (the SS plugin's TCP-only mux).
    pub(crate) async fn open_udp(
        &self,
        params: &NativeConnectParams,
        target: &TargetAddr,
        session: Option<std::net::SocketAddr>,
        policy: &MuxPolicy,
    ) -> Result<(crate::PacketTunnel, MuxLease), NativeError> {
        self.ensure_sweeper(policy.idle);
        let (carrier, key) = self.acquire(params, policy).await?;
        let (carrier, tunnel) = if let Ok(tunnel) = udp_tunnel(&carrier, target, session) {
            (carrier, tunnel)
        } else {
            carrier.dead.store(true, Ordering::Release);
            carrier.live.fetch_sub(1, Ordering::AcqRel);
            self.evict(&key, &carrier);
            let fresh = self.fresh_carrier(params, policy, &key).await?;
            match udp_tunnel(&fresh, target, session) {
                Ok(tunnel) => (fresh, tunnel),
                Err(error) => {
                    fresh.live.fetch_sub(1, Ordering::AcqRel);
                    fresh.dead.store(true, Ordering::Release);
                    self.evict(&key, &fresh);
                    return Err(error);
                }
            }
        };
        carrier.touch();
        Ok((tunnel, MuxLease { carrier }))
    }

    /// Pick, build or spill, and sweep dead/idle carriers on the way.
    fn choose(&self, key: &MuxKey, policy: &MuxPolicy, cap: usize) -> Choice {
        let mut entries = self.inner.entries.lock();
        sweep(&mut entries, policy.idle);
        let carriers = entries.entry(key.clone()).or_default();
        let pick = carriers
            .iter()
            .filter(|c| !c.is_dead() && c.live() < cap)
            .min_by_key(|c| c.live())
            .cloned();
        // Reserve the stream slot UNDER the lock: concurrent CONNECTs must see
        // each other's reservations, or the cap is bypassed by a burst.
        let grow = if carriers.len() < policy.carriers {
            Choice::Build
        } else {
            Choice::Spill
        };
        let choice = pick.map_or(grow, |carrier| {
            carrier.live.fetch_add(1, Ordering::AcqRel);
            carrier.touch();
            Choice::Use(carrier)
        });
        drop(entries);
        choice
    }

    /// The idle sweeper: one task per pool, armed on the first acquire, exits
    /// when the pool itself is dropped (`Weak` upgrade fails). Without it an
    /// idle carrier would live until unrelated traffic happened to sweep.
    fn ensure_sweeper(&self, idle: Duration) {
        if self.inner.sweeper.swap(true, Ordering::AcqRel) {
            return;
        }
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(idle).await;
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                sweep(&mut inner.entries.lock(), idle);
            }
        });
    }

    /// Remove one carrier from its profile list (eviction on failure).
    fn evict(&self, key: &MuxKey, carrier: &Arc<Carrier>) {
        let mut entries = self.inner.entries.lock();
        if let Some(carriers) = entries.get_mut(key) {
            carriers.retain(|c| !Arc::ptr_eq(c, carrier));
            if carriers.is_empty() {
                entries.remove(key);
            }
        }
        drop(entries);
    }

    /// Register a freshly built carrier, unless a concurrent acquire filled
    /// the profile in the meantime (then the caller's session still uses it;
    /// it simply is not pooled).
    fn register(&self, key: &MuxKey, carrier: &Arc<Carrier>, policy: &MuxPolicy) {
        let mut entries = self.inner.entries.lock();
        let carriers = entries.entry(key.clone()).or_default();
        if carriers.len() < policy.carriers {
            carriers.push(Arc::clone(carrier));
        }
        drop(entries);
    }

    /// Test-only: seed a carrier (the dial is not exercised).
    #[cfg(test)]
    fn seed(&self, key: MuxKey, carrier: Arc<Carrier>) {
        self.inner
            .entries
            .lock()
            .entry(key)
            .or_default()
            .push(carrier);
    }

    /// Test-only: live carrier count for a key.
    #[cfg(test)]
    fn carrier_count(&self, key: &MuxKey) -> usize {
        self.inner
            .entries
            .lock()
            .get(key)
            .map_or(0, std::vec::Vec::len)
    }

    /// Test-only: seed a tunnel without dialing (the inbound wiring tests use
    /// a carrier whose peer only drains frames).
    #[cfg(test)]
    pub(crate) fn seed_tunnel_for_test(&self, key: MuxKey, tunnel: MuxTunnel) {
        self.seed(key, Arc::new(Carrier::new(tunnel)));
    }

    /// Test-only: `(carriers, live_sessions)` for a key.
    #[cfg(test)]
    pub(crate) fn stats_for_test(&self, key: &MuxKey) -> (usize, usize) {
        let entries = self.inner.entries.lock();
        entries.get(key).map_or((0, 0), |carriers| {
            (
                carriers.len(),
                carriers.iter().map(|c| c.live()).sum::<usize>(),
            )
        })
    }
}

/// Open one datagram association on an acquired carrier.
fn udp_tunnel(
    carrier: &Arc<Carrier>,
    target: &TargetAddr,
    session: Option<std::net::SocketAddr>,
) -> Result<crate::PacketTunnel, NativeError> {
    match &carrier.tunnel {
        crate::protocol::MuxTunnel::Vless(client) => {
            let global_id = random_global_id();
            let session = client
                .open_udp_session(global_id)
                .map_err(|e| NativeError::Transport(format!("sbox mux: xudp session: {e}")))?;
            Ok(crate::PacketTunnel::Vless(
                crate::protocol::vless::PacketConn::xudp(session),
            ))
        }
        crate::protocol::MuxTunnel::Sbox(tunnel) => {
            let stream = tunnel.open_udp(target)?;
            Ok(crate::PacketTunnel::Sbox(
                crate::transport::sbox::udp::SboxUdpTunnel::new(stream, session),
            ))
        }
        crate::protocol::MuxTunnel::Ss(_) => Err(NativeError::Config(
            "the SS plugin mux is TCP-only; its UDP path is not pooled".into(),
        )),
    }
}

/// Build one carrier on the wire the profile/row selects.
async fn build_tunnel(
    params: &NativeConnectParams,
    policy: &MuxPolicy,
) -> Result<MuxTunnel, NativeError> {
    let wire = effective_wire(params, policy);
    if wire == MuxWire::MuxCool {
        return crate::connect_mux(params).await;
    }
    // The sbox mux is an INNER protocol: the proxy request must target the
    // server's mux endpoint (`sp.mux.sing-box.arpa:444`), exactly like
    // MUX.Cool's fixed destination. Running the session straight over TLS
    // would skip the proxy's request (and its authentication) entirely.
    let limit = crate::error::timeouts::CONNECT;
    tokio::time::timeout(limit, build_sbox(params, policy, wire))
        .await
        .map_err(|_| NativeError::Timeout {
            step: "sbox carrier",
            limit,
        })?
}

/// The sbox carrier build (dial → security → proxy request → handshake →
/// session), always under the aggregate carrier budget.
async fn build_sbox(
    params: &NativeConnectParams,
    policy: &MuxPolicy,
    wire: MuxWire,
) -> Result<MuxTunnel, NativeError> {
    let mux_target = crate::transport::sbox::protocol::mux_destination();
    let mut mux_params = params.clone();
    mux_params.target = mux_target.clone();
    let ctx = crate::context::LinkContext::new(mux_params, mux_target);
    let dialed = crate::transport::connect(&ctx, None).await?;
    let upgraded = crate::chain::secured_upgraded(&ctx, dialed).await?;
    let upgraded = crate::protocol::connect(&ctx, upgraded).await?;
    let protocol = match wire {
        MuxWire::H2Mux => PROTOCOL_H2MUX,
        MuxWire::Smux => PROTOCOL_SMUX,
        MuxWire::Yamux => PROTOCOL_YAMUX,
        MuxWire::MuxCool => unreachable!("handled above"),
    };
    let request = Request {
        version: if policy.padding { VERSION1 } else { VERSION0 },
        protocol,
        padding: policy.padding,
    };
    let mut stream: BoxStream = Box::new(crate::protocol::first_flight::HeaderFirst::new(
        upgraded,
        request.encode(),
    ));
    if policy.padding {
        stream = Box::new(PaddingConn::new(stream));
    }
    let session = match wire {
        MuxWire::H2Mux => SboxSession::H2(H2Mux::connect(stream).await?),
        MuxWire::Smux => SboxSession::Smux(SmuxSession::new(stream)),
        MuxWire::Yamux => SboxSession::Yamux(YamuxSession::new(stream)),
        MuxWire::MuxCool => unreachable!("handled above"),
    };
    Ok(MuxTunnel::Sbox(std::sync::Arc::new(
        crate::transport::sbox::SboxTunnel::new(session),
    )))
}

/// One datagram association's hold on a carrier: dropping it releases the
/// live count (the carrier may then idle-close).
pub(crate) struct MuxLease {
    carrier: Arc<Carrier>,
}

impl Drop for MuxLease {
    fn drop(&mut self) {
        self.carrier.live.fetch_sub(1, Ordering::AcqRel);
        self.carrier.touch();
    }
}

/// A fresh XUDP `GlobalID`.
fn random_global_id() -> [u8; 8] {
    let mut id = [0u8; 8];
    crate::rand::fill_nonsecret(&mut id);
    id
}

/// Drop dead carriers and carriers idle past the window.
fn sweep(entries: &mut HashMap<MuxKey, Vec<Arc<Carrier>>>, idle: Duration) {
    entries.retain(|_, carriers| {
        carriers.retain(|c| !c.is_dead() && (c.live() > 0 || c.idle_for() < idle));
        !carriers.is_empty()
    });
}

/// A session that keeps its carrier registered until the stream is dropped.
struct PooledSession {
    inner: BoxStream,
    carrier: Arc<Carrier>,
}

impl Drop for PooledSession {
    fn drop(&mut self) {
        self.carrier.live.fetch_sub(1, Ordering::AcqRel);
        self.carrier.touch();
    }
}

impl AsyncRead for PooledSession {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PooledSession {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use tokio::io::{AsyncReadExt, duplex};

    use super::*;
    use crate::addr::Host;
    use crate::context::NativeConnectParams;
    use crate::protocol::vless::MuxClient;

    fn vless(
        remarks: Option<&str>,
        mux: Option<leas_proto::proto_spec::VlessMux>,
    ) -> ProtocolConfig {
        let mut cfg: leas_proto::proto_spec::VlessConfig =
            serde_json::from_value(serde_json::json!({
                "uuid": "11111111-2222-3333-4444-555555555555",
                "transport": { "type": "tcp" }
            }))
            .expect("vless config");
        cfg.mux = mux;
        cfg.remarks = remarks.map(Into::into);
        ProtocolConfig::Vless(cfg)
    }

    fn vless_flow(flow: Option<&str>) -> ProtocolConfig {
        let mut cfg: leas_proto::proto_spec::VlessConfig =
            serde_json::from_value(serde_json::json!({
                "uuid": "11111111-2222-3333-4444-555555555555",
                "transport": { "type": "tcp" }
            }))
            .expect("vless config");
        cfg.flow = flow.map(Into::into);
        ProtocolConfig::Vless(cfg)
    }

    fn params(cfg: ProtocolConfig) -> NativeConnectParams {
        NativeConnectParams::new(
            cfg,
            EndpointEssentials::new("server.example", 443),
            TargetAddr::new(Host::Domain("target.example".into()), 443),
        )
    }

    fn policy() -> MuxPolicy {
        MuxPolicy::production()
    }

    /// A tunnel whose peer only drains frames: enough for `open_session`, which
    /// returns after the New frame is queued.
    fn fake_carrier() -> Arc<Carrier> {
        let (client, mut peer) = duplex(64 * 1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while peer.read(&mut buf).await.unwrap_or(0) > 0 {}
        });
        Arc::new(Carrier::new(MuxTunnel::Vless(Arc::new(MuxClient::new(
            Box::new(client) as BoxStream,
        )))))
    }

    /// The row's magnitude is the carrier's stream cap; the policy is only
    /// the default (issue 004: `mux=4` used to behave exactly like `mux=32`).
    #[test]
    fn a_rows_mux_cap_reaches_the_pool() {
        use leas_proto::proto_spec::VlessMux;
        let policy = policy();
        let limited = params(vless(None, Some(VlessMux::Limited(3))));
        assert_eq!(effective_cap(&limited, &policy), 3);
        let unlimited = params(vless(None, Some(VlessMux::Unlimited)));
        assert_eq!(
            effective_cap(&unlimited, &policy),
            policy.cap,
            "-1 means unlimited, which the pool caps at the policy"
        );
        let silent = params(vless(None, None));
        assert_eq!(effective_cap(&silent, &policy), policy.cap);
    }

    /// A carrier that reached the ROW's cap is not reused, even when the
    /// policy cap is larger: the row's value is the one that decides.
    #[tokio::test]
    async fn a_carrier_at_the_rows_cap_is_not_shared() {
        use leas_proto::proto_spec::VlessMux;
        let pool = MuxPool::new();
        let p = params(vless(None, Some(VlessMux::Limited(1))));
        let key = MuxKey::of(&p, &policy());
        let carrier = fake_carrier();
        carrier.live.fetch_add(1, Ordering::AcqRel);
        pool.seed(key.clone(), Arc::clone(&carrier));
        let policy = policy();
        let cap = effective_cap(&p, &policy);
        assert!(
            matches!(pool.choose(&key, &policy, cap), Choice::Build),
            "a full carrier must not take another session"
        );
        assert!(
            matches!(pool.choose(&key, &policy, 2), Choice::Use(_)),
            "the policy cap would reuse it — the row's cap must win"
        );
    }

    #[test]
    fn key_ignores_remarks_and_cap_but_not_identity() {
        let a = MuxKey::of(&params(vless(Some("one"), None)), &policy());
        let b = MuxKey::of(
            &params(vless(
                Some("two"),
                Some(leas_proto::proto_spec::VlessMux::Limited(4)),
            )),
            &policy(),
        );
        assert_eq!(a, b, "remarks and the cap are policy, not carrier identity");

        let mut other = params(vless(
            None,
            Some(leas_proto::proto_spec::VlessMux::Limited(4)),
        ));
        other.server = EndpointEssentials::new("other.example", 443);
        let c = MuxKey::of(&other, &policy());
        assert_ne!(a, c, "a different server is a different carrier");
    }

    #[test]
    fn effective_mux_follows_row_then_policy_and_spares_ss() {
        let default_row = params(vless(None, None));
        assert!(effective_mux(&default_row, &policy()), "policy default on");
        assert!(
            !effective_mux(&default_row, &MuxPolicy::default()),
            "config default off"
        );

        let off_row = params(vless(
            None,
            Some(leas_proto::proto_spec::VlessMux::Limited(0)),
        ));
        assert!(!effective_mux(&off_row, &policy()), "row off wins");

        let on_row = params(vless(
            None,
            Some(leas_proto::proto_spec::VlessMux::Limited(8)),
        ));
        assert!(effective_mux(&on_row, &MuxPolicy::default()), "row on wins");
    }

    /// The UDP pooling decision must agree with `connect_udp`'s rewrite: a
    /// udp443 row spells no mux key and the TCP rule keeps flow rows off, so
    /// without the flow term the leg is built as a raw tunnel for a config
    /// whose protocol phase only speaks XUDP (`case_37`/`case_38` in
    /// `leas-oracles` is the real-core guard).
    #[test]
    fn effective_udp_mux_honours_the_udp443_flow() {
        let udp443 = params(vless_flow(Some("xtls-rprx-vision-udp443")));
        assert!(
            !effective_mux(&udp443, &policy()),
            "TCP mux stays off for a flow row"
        );
        assert!(
            effective_udp_mux(&udp443, &policy()),
            "the flow is the UDP mux declaration"
        );

        let vision = params(vless_flow(Some("xtls-rprx-vision")));
        assert!(
            !effective_udp_mux(&vision, &policy()),
            "plain vision does not force UDP mux"
        );

        let on_row = params(vless(
            None,
            Some(leas_proto::proto_spec::VlessMux::Limited(8)),
        ));
        assert!(effective_udp_mux(&on_row, &policy()));
        let off_row = params(vless(
            None,
            Some(leas_proto::proto_spec::VlessMux::Limited(0)),
        ));
        assert!(!effective_udp_mux(&off_row, &policy()), "row off wins");
    }

    #[test]
    fn default_on_never_pulls_a_flow_or_xhttp_row_onto_mux() {
        let mut cfg = vless(None, None);
        let ProtocolConfig::Vless(vless_cfg) = &mut cfg else {
            unreachable!()
        };
        vless_cfg.flow = Some("xtls-rprx-vision".into());
        let flow_row = params(cfg);
        assert!(
            !effective_mux(&flow_row, &policy()),
            "a Vision row must not be muxed by the profile default (Xray rejects it)"
        );
        let mut explicit = vless(None, Some(leas_proto::proto_spec::VlessMux::Limited(8)));
        let ProtocolConfig::Vless(explicit_cfg) = &mut explicit else {
            unreachable!()
        };
        explicit_cfg.flow = Some("xtls-rprx-vision".into());
        assert!(
            effective_mux(&params(explicit), &policy()),
            "an explicit mux row still muxes under a flow"
        );

        let mut xhttp = vless(None, None);
        let ProtocolConfig::Vless(xhttp_cfg) = &mut xhttp else {
            unreachable!()
        };
        xhttp_cfg.transport = serde_json::from_value(serde_json::json!({
            "type": "x_http", "path": "/x"
        }))
        .expect("xhttp transport");
        assert!(
            !effective_mux(&params(xhttp), &policy()),
            "xhttp multiplexes at the transport layer; no mux nesting by default"
        );
    }

    #[tokio::test]
    async fn reuse_and_release_respect_the_cap() {
        let pool = MuxPool::new();
        let p = params(vless(
            None,
            Some(leas_proto::proto_spec::VlessMux::Limited(8)),
        ));
        let key = MuxKey::of(&p, &policy());
        let carrier = fake_carrier();
        pool.seed(key.clone(), Arc::clone(&carrier));

        let target = TargetAddr::new(Host::Domain("target.example".into()), 443);
        let s1 = pool.open_session(&p, &target, &policy()).await.unwrap();
        assert_eq!(carrier.live(), 1);
        let s2 = pool.open_session(&p, &target, &policy()).await.unwrap();
        assert_eq!(carrier.live(), 2);
        assert_eq!(pool.carrier_count(&key), 1, "one carrier, two sessions");

        drop(s1);
        assert_eq!(carrier.live(), 1);
        drop(s2);
        assert_eq!(carrier.live(), 0);
    }

    #[tokio::test]
    async fn sweep_drops_dead_and_idle_carriers() {
        let pool = MuxPool::new();
        let p = params(vless(
            None,
            Some(leas_proto::proto_spec::VlessMux::Limited(8)),
        ));
        let key = MuxKey::of(&p, &policy());
        let carrier = fake_carrier();
        pool.seed(key.clone(), Arc::clone(&carrier));

        carrier.dead.store(true, Ordering::Release);
        let mut policy = policy();
        policy.carriers = 0; // force the sweep to run without dialling
        let _ = pool.choose(&key, &policy, policy.cap);
        assert_eq!(pool.carrier_count(&key), 0, "dead carrier is evicted");

        let pool = MuxPool::new();
        let carrier = fake_carrier();
        pool.seed(key.clone(), Arc::clone(&carrier));
        *carrier.last_used.lock() = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .expect("now is after 60s ago");
        let _ = pool.choose(&key, &policy, policy.cap);
        assert_eq!(pool.carrier_count(&key), 0, "idle carrier is reaped");
    }

    #[test]
    fn effective_wire_prefers_the_row_and_pins_a_flow_to_muxcool() {
        let mut cfg = vless(None, None);
        let ProtocolConfig::Vless(vless_cfg) = &mut cfg else {
            unreachable!()
        };
        vless_cfg.mux = Some(leas_proto::proto_spec::VlessMux::Named {
            wire: MuxWire::Yamux,
            cap: 8,
        });
        let mut policy = policy();
        policy.wire = MuxWire::Smux;
        assert_eq!(
            effective_wire(&params(cfg), &policy),
            MuxWire::Yamux,
            "the row's wire wins over the profile default"
        );

        let plain = params(vless(None, None));
        assert_eq!(
            effective_wire(&plain, &policy),
            MuxWire::Smux,
            "a row with no wire takes the profile default"
        );

        let mut flow_cfg = vless(None, None);
        let ProtocolConfig::Vless(flow) = &mut flow_cfg else {
            unreachable!()
        };
        flow.flow = Some("xtls-rprx-vision".into());
        assert_eq!(
            effective_wire(&params(flow_cfg), &policy),
            MuxWire::MuxCool,
            "a flow row is pinned to MUX.Cool (Xray rejects sbox under XRV)"
        );
    }
}
