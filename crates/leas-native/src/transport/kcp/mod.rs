//! mKCP transport: xray's fork of the KCP reliable-stream protocol over UDP
//! (SP4) — wire codec (Task 1), session (Task 2), dial + stream (Task 4).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use tokio::net::UdpSocket;

use crate::BoxStream;
use crate::context::LinkContext;
use crate::error::NativeError;

pub mod session;
pub mod stream;
pub mod wire;

pub use session::{KcpSession, KcpSettings, State};
pub use stream::KcpStream;
pub use wire::{Command, Segment, SegmentOption, encode_segment, parse_datagram};

/// Per-process conversation-id counter (spec §4.2): Go's
/// `globalConv = dice.RollUint16(); conv = ++globalConv`. Seeded once from
/// the wall clock (the `RollUint16` equivalent); `fetch_add(1)` per dial.
static GLOBAL_CONV: AtomicU16 = AtomicU16::new(0);

fn next_conv() -> u16 {
    static SEEDED: std::sync::Once = std::sync::Once::new();
    SEEDED.call_once(|| {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0x4b4b, |d| {
                u16::try_from(d.as_secs() ^ u64::from(d.subsec_nanos())).unwrap_or(0x4b4b)
            });
        GLOBAL_CONV.store(seed, Ordering::Relaxed);
    });
    GLOBAL_CONV.fetch_add(1, Ordering::Relaxed)
}

/// Dial the server's mKCP session over a fresh UDP socket (`base: None`).
///
/// `base: Some` is a config error — mKCP is always a fresh UDP dial (it
/// never tunnels over an existing stream; unlike TCP it is not an upgrade).
pub async fn connect(ctx: &LinkContext, base: Option<BoxStream>) -> Result<BoxStream, NativeError> {
    if base.is_some() {
        return Err(NativeError::Config(
            "kcp transport cannot run over an existing tunnel".into(),
        ));
    }
    let cfg = ctx
        .transport_kcp()
        .ok_or_else(|| NativeError::Config("kcp transport missing its transport config".into()))?;
    // Spec §4.5 defaults when the params omit mtu/tti.
    let settings = KcpSettings::new(
        usize::try_from(cfg.mtu.unwrap_or(1350)).unwrap_or(1350),
        cfg.tti.unwrap_or(50),
    );
    let addr = ctx.server_socket().await?;
    dial(addr, settings).await
}

/// Bind an ephemeral UDP socket, connect to the server, wire the session
/// (output closure → send task; recv task → `session.input`) and return the
/// stream adapter boxed. The socket error path follows spec §6: the input
/// task logs and stops; the session then EOFs via its own state machine.
async fn dial(addr: SocketAddr, settings: KcpSettings) -> Result<BoxStream, NativeError> {
    let sock = Arc::new(
        UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| NativeError::Dial(format!("kcp udp bind: {e}")))?,
    );
    sock.connect(addr)
        .await
        .map_err(|e| NativeError::Dial(format!("{addr}: {e}")))?;

    // The session's output closure is sync (called from the driver task), so
    // datagrams cross an unbounded channel to a task that awaits `send` (the
    // same wiring as the hermetic harness — the channel is drained promptly
    // and a dropped receiver surfaces as a send error, swallowed like Go's
    // ignored write errors).
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let session = Arc::new(KcpSession::new(
        next_conv(),
        settings,
        move |buf: &[u8]| {
            let _ = tx.send(buf.to_vec());
            Ok(())
        },
    ));

    let send_sock = Arc::clone(&sock);
    tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            if let Err(e) = send_sock.send(&buf).await {
                tracing::warn!(%e, "mKCP: udp send failed; stopping sender");
                break;
            }
        }
    });

    let recv_sock = Arc::clone(&sock);
    let recv_session = Arc::clone(&session);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match recv_sock.recv(&mut buf).await {
                Ok(n) => {
                    recv_session.input(&buf[..n]);
                    if recv_session.state() == State::Terminated {
                        break; // handshake done — no more datagrams matter
                    }
                }
                Err(e) => {
                    tracing::warn!(%e, "mKCP: udp recv failed; stopping input task");
                    break;
                }
            }
        }
    });

    Ok(Box::new(KcpStream::new(session)))
}

#[cfg(test)]
pub(crate) mod fake_peer;
