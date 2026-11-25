//! TUIC QUIC dial, exporter authentication, handshake phase, heartbeat.
//!
//! The dial owns `Connecting` and the `ZeroRttAccepted` future instead of
//! calling `transport::quic::connect`: quinn 0.11 exposes handshake completion
//! only through that future, and the TUIC token needs the TLS exporter after
//! the handshake. CONNECT/PACKET may use the 0-RTT lane; auth never does.

use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::Bytes;
use leas_proto::proto_spec::TuicConfig;
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use quinn::{Connection, Endpoint, IdleTimeout, TransportConfig, VarInt, ZeroRttAccepted};
use tokio::sync::oneshot;
use tokio::time::MissedTickBehavior;
use uuid::Uuid;

use crate::context::LinkContext;
use crate::error::{NativeError, timeouts};

use super::wire;

const ALPN_H3: &[u8] = b"h3";
#[cfg(any(test, feature = "e2e-support"))]
static EARLY_ATTEMPTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(any(test, feature = "e2e-support"))]
static EARLY_ACCEPTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(any(test, feature = "e2e-support"))]
static EARLY_REJECTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// `(attempts, accepted, rejected)` for the test/e2e harness. A retried dial
/// proves the 0-RTT lane only when the counters move.
#[cfg(any(test, feature = "e2e-support"))]
#[must_use]
pub fn early_stats() -> (usize, usize, usize) {
    use std::sync::atomic::Ordering;
    (
        EARLY_ATTEMPTS.load(Ordering::Relaxed),
        EARLY_ACCEPTED.load(Ordering::Relaxed),
        EARLY_REJECTED.load(Ordering::Relaxed),
    )
}

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const HEARTBEAT_FRAME: [u8; 2] = wire::heartbeat_frame();
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// The peer may open one PACKET reply stream per datagram in quic mode.
const MAX_INCOMING_UNI_STREAMS: u32 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Pending,
    Accepted,
    Rejected,
    Failed,
}

struct PhaseInner {
    phase: Phase,
    waker: Option<Waker>,
    error: Option<String>,
}

/// Handshake outcome shared by the auth task, the CONNECT stream, and the UDP
/// association. One lock keeps the phase, waker, and error consistent.
pub struct PhaseSlot {
    inner: Mutex<PhaseInner>,
}

impl PhaseSlot {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PhaseInner {
                phase: Phase::Pending,
                waker: None,
                error: None,
            }),
        })
    }

    #[cfg(test)]
    pub fn phase(&self) -> Phase {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .phase
    }

    pub fn error(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .error
            .clone()
    }

    pub fn poll(&self, cx: &Context<'_>) -> Poll<Phase> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if inner.phase == Phase::Pending {
            inner.waker = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(inner.phase)
        }
    }

    fn resolve(&self, phase: Phase) {
        let waker = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if inner.phase != Phase::Pending {
                return;
            }
            inner.phase = phase;
            inner.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn fail(&self, error: String) {
        let waker = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.phase = Phase::Failed;
            inner.error = Some(error);
            inner.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// Keeps the QUIC endpoint driver and the heartbeat task alive for exactly as
/// long as the tunnel that owns this guard.
pub struct ConnectionGuard {
    _endpoint: Endpoint,
    _shutdown: oneshot::Sender<()>,
}

pub struct Dialed {
    pub conn: Connection,
    pub phase: Arc<PhaseSlot>,
    pub guard: ConnectionGuard,
}

fn uuid_bytes(cfg: &TuicConfig) -> Result<[u8; 16], NativeError> {
    Uuid::parse_str(&cfg.uuid)
        .map(|uuid| *uuid.as_bytes())
        .map_err(|e| NativeError::Config(format!("tuic uuid is invalid: {e}")))
}

fn alpn(ctx: &LinkContext) -> Vec<Vec<u8>> {
    let explicit = ctx.alpn_vec();
    if explicit.is_empty() {
        vec![ALPN_H3.to_vec()]
    } else {
        explicit
    }
}

fn congestion_factory(config: Option<&str>) -> Arc<dyn ControllerFactory + Send + Sync> {
    match config.unwrap_or("cubic") {
        "new_reno" => Arc::new(NewRenoConfig::default()),
        "bbr" => Arc::new(BbrConfig::default()),
        _ => Arc::new(CubicConfig::default()),
    }
}

fn transport_config(cfg: &TuicConfig) -> Result<TransportConfig, NativeError> {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            IdleTimeout::try_from(IDLE_TIMEOUT)
                .map_err(|e| NativeError::Config(format!("tuic idle timeout: {e}")))?,
        ))
        .keep_alive_interval(None)
        .datagram_receive_buffer_size(Some(1 << 20))
        .max_concurrent_uni_streams(VarInt::from_u32(MAX_INCOMING_UNI_STREAMS))
        .congestion_controller_factory(congestion_factory(cfg.congestion_control.as_deref()));
    Ok(transport)
}

fn quic_client_config(
    tls: rustls::ClientConfig,
    transport: TransportConfig,
) -> Result<quinn::ClientConfig, NativeError> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| NativeError::Config(format!("tuic QUIC TLS: {e}")))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Dial the TUIC server. `allow_early` is true for TCP CONNECT (which can use
/// the 0-RTT lane); UDP waits for the handshake.
pub async fn dial(
    ctx: &LinkContext,
    cfg: &TuicConfig,
    allow_early: bool,
) -> Result<Dialed, NativeError> {
    let uuid = uuid_bytes(cfg)?;
    let server_addr = ctx.server_socket().await?;
    let endpoint = crate::transport::quic::client_endpoint(server_addr);
    let tls = crate::transport::quic::quic_tls_config_alpns(ctx, &alpn(ctx))?;
    let client_config = quic_client_config(tls, transport_config(cfg)?)?;
    let connecting = endpoint
        .connect_with(client_config, server_addr, &ctx.server_name())
        .map_err(|e| NativeError::Dial(format!("tuic connect: {e}")))?;

    let (conn, accepted) = if allow_early {
        match connecting.into_0rtt() {
            Ok((conn, accepted)) => {
                #[cfg(any(test, feature = "e2e-support"))]
                EARLY_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                (conn, Some(accepted))
            }
            Err(connecting) => (finish_handshake(connecting).await?, None),
        }
    } else {
        (finish_handshake(connecting).await?, None)
    };

    let phase = PhaseSlot::new();
    spawn_auth(
        conn.clone(),
        Arc::clone(&phase),
        uuid,
        cfg.password.clone(),
        accepted,
    );
    let guard = spawn_heartbeat(conn.clone(), endpoint);
    Ok(Dialed { conn, phase, guard })
}

async fn finish_handshake(connecting: quinn::Connecting) -> Result<Connection, NativeError> {
    let limit = timeouts::DIAL;
    tokio::time::timeout(limit, connecting)
        .await
        .map_err(|_| NativeError::Timeout {
            step: "tuic handshake",
            limit,
        })?
        .map_err(|e| NativeError::Dial(format!("tuic handshake: {e}")))
}

fn spawn_auth(
    conn: Connection,
    phase: Arc<PhaseSlot>,
    uuid: [u8; 16],
    password: String,
    accepted: Option<ZeroRttAccepted>,
) {
    tokio::spawn(async move {
        let early_phase = match accepted {
            Some(accepted) => {
                let limit = timeouts::DIAL;
                match tokio::time::timeout(limit, accepted).await {
                    Ok(true) => {
                        #[cfg(any(test, feature = "e2e-support"))]
                        EARLY_ACCEPTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Phase::Accepted
                    }
                    Ok(false) => {
                        #[cfg(any(test, feature = "e2e-support"))]
                        EARLY_REJECTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Phase::Rejected
                    }
                    Err(_) => {
                        phase.fail("tuic handshake timed out".into());
                        conn.close(0_u32.into(), b"tuic handshake timeout");
                        return;
                    }
                }
            }
            None => Phase::Accepted,
        };
        match write_auth(&conn, &uuid, &password).await {
            Ok(()) => phase.resolve(early_phase),
            Err(error) => {
                phase.fail(error.to_string());
                conn.close(0_u32.into(), b"tuic auth failed");
            }
        }
    });
}

async fn write_auth(conn: &Connection, uuid: &[u8; 16], password: &str) -> Result<(), NativeError> {
    let mut token = [0u8; wire::TOKEN_LEN];
    conn.export_keying_material(&mut token, uuid, password.as_bytes())
        .map_err(|e| NativeError::Protocol {
            kind: leas_proto::proto_spec::ProtocolKind::Tuic,
            detail: format!("tuic exporter: {e:?}"),
        })?;
    let frame = wire::auth_frame(uuid, &token);
    let limit = timeouts::PROTOCOL;
    let mut stream = tokio::time::timeout(limit, conn.open_uni())
        .await
        .map_err(|_| NativeError::Timeout {
            step: "tuic auth stream",
            limit,
        })?
        .map_err(|e| NativeError::Protocol {
            kind: leas_proto::proto_spec::ProtocolKind::Tuic,
            detail: format!("tuic auth stream: {e}"),
        })?;
    tokio::time::timeout(
        limit,
        tokio::io::AsyncWriteExt::write_all(&mut stream, &frame),
    )
    .await
    .map_err(|_| NativeError::Timeout {
        step: "tuic auth write",
        limit,
    })?
    .map_err(|e| NativeError::Protocol {
        kind: leas_proto::proto_spec::ProtocolKind::Tuic,
        detail: format!("tuic auth write: {e}"),
    })?;
    stream.finish().map_err(|e| NativeError::Protocol {
        kind: leas_proto::proto_spec::ProtocolKind::Tuic,
        detail: format!("tuic auth close: {e}"),
    })
}

fn spawn_heartbeat(conn: Connection, endpoint: Endpoint) -> ConnectionGuard {
    let (shutdown, mut receiver) = oneshot::channel();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut receiver => break,
                _ = conn.closed() => break,
                _ = ticker.tick() => {
                    if conn
                        .send_datagram(Bytes::from_static(&HEARTBEAT_FRAME))
                        .is_err()
                    {
                        conn.close(0_u32.into(), b"tuic heartbeat failed");
                        break;
                    }
                }
            }
        }
    });
    ConnectionGuard {
        _endpoint: endpoint,
        _shutdown: shutdown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn phase_resolves_and_wakes() {
        let phase = PhaseSlot::new();
        let waiting = phase.clone();
        let handle = tokio::spawn(async move { std::future::poll_fn(|cx| waiting.poll(cx)).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        phase.resolve(Phase::Accepted);
        assert_eq!(handle.await.expect("join"), Phase::Accepted);
    }

    #[tokio::test]
    async fn failure_carries_its_detail() {
        let phase = PhaseSlot::new();
        phase.fail("bad token".into());
        assert_eq!(phase.phase(), Phase::Failed);
        assert_eq!(phase.error().as_deref(), Some("bad token"));
    }
}
