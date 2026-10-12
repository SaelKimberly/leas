//! A byte stream that **owns its mux tunnel**.
//!
//! `MuxClient::new` spawns the demux, writer and keepalive tasks but does not own the
//! tunnel: *"dropping the handle stops the keepalive, and the tunnel tears down once the last
//! session drops"* (`transport/mux.rs:500-503`). So a dial that returned the bare
//! `SessionStream` would drop the handle at return and silently kill the
//! 10-second [`KEEPALIVE_INTERVAL`](crate::transport::mux::KEEPALIVE_INTERVAL) while the
//! tunnel stayed up through the session's own `write_tx` clone — an idle plugin session
//! would look fine locally and be reaped server-side, a failure the 3b rows would only
//! catch intermittently.
//!
//! Holding the tunnel beside the session is the whole fix, and the shape is deliberately
//! small: a stream wrapper that owns both, forwards reads and writes, and drops the tunnel
//! only when the session does. A connection pool would be the larger change that makes
//! multiplexing *pay*; that is not this one (spec §5.2).

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxStream;
use crate::error::NativeError;
use crate::protocol::MuxTunnel;

/// Open one session on `tunnel` and return a stream that keeps `tunnel` alive for as
/// long as the session is usable.
///
/// The tunnel is taken **by value**: it is the session's to hold and to drop, and a
/// cloneable handle would be exactly the bug this file exists to prevent.
pub async fn open_session(
    tunnel: MuxTunnel,
    target: &crate::addr::TargetAddr,
) -> Result<BoxStream, NativeError> {
    let session = tunnel.open_session(target).await?;
    Ok(Box::new(Session { tunnel, session }))
}

/// A session plus the tunnel that carries it.
struct Session {
    /// Held, never read: the tunnel's lifetime IS the point. It is dropped with
    /// the session, so the keepalive stops exactly then — which is why this is a
    /// named field and not a `PhantomData`.
    #[allow(dead_code)]
    tunnel: MuxTunnel,
    session: BoxStream,
}

impl AsyncRead for Session {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().session).poll_read(cx, buf)
    }
}

impl AsyncWrite for Session {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().session).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().session).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().session).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The **behavioral** half: dropping the session tears the tunnel down, and
    /// the peer sees EOF. That is the semantics the module doc claims, and it
    /// is what returning a bare `SessionStream` would have broken (the keepalive
    /// would stop at return while the tunnel stayed up). The type-level check
    /// alone would not have caught it.
    #[tokio::test]
    async fn dropping_the_session_closes_the_tunnel() {
        use std::time::Duration;

        use tokio::io::AsyncReadExt;

        // One end of a pipe stands in for the server: the multiplexer reads
        // frames off it and writes them back, so EOF on this side is the
        // observable end of the tunnel.
        let (client, mut peer) = tokio::io::duplex(64 * 1024);
        let tunnel = MuxTunnel::Vless(std::sync::Arc::new(crate::transport::mux::MuxClient::new(
            Box::new(client),
        )));

        // A session that is never written to is enough: the tunnel's own tasks
        // are what must end.
        let session = match open_session(tunnel, &test_target()).await {
            Ok(session) => session,
            Err(e) => panic!("open_session: {e}"),
        };
        let mut byte = [0u8; 64];
        // While the session lives the tunnel is up. The read itself usually
        // returns the session's `New` frame, so the liveness claim is about EOF,
        // not about silence.
        let liveness = tokio::time::timeout(Duration::from_millis(150), peer.read(&mut byte)).await;
        if matches!(liveness, Ok(Ok(0))) {
            panic!("the tunnel closed while the session was still held");
        }

        // Verified non-vacuous: with this `drop` replaced by `mem::forget`, the test
        // FAILS (5 s, no EOF). That check matters because the teardown loop below was
        // rewritten several times to satisfy lints, and a rewrite that folds the
        // 200 ms timeout into the EOF arm would make the assertion true after 5 s
        // whatever happened — passing with the pin gone.
        drop(session);
        let mut saw_eof = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            // A clean EOF or a reset both mean the tunnel is gone; a timeout or
            // payload means it is still up, so keep waiting.
            let Ok(outcome) =
                tokio::time::timeout(Duration::from_millis(200), peer.read(&mut byte)).await
            else {
                continue;
            };
            // A clean EOF (0 bytes) or a reset means the tunnel is gone;
            // payload means it is still up, so keep waiting.
            // `Ok(0)` is the clean EOF, `Err(_)` a reset, `Ok(n > 0)` payload
            // (still up). The timeout already `continue`s above.
            let gone = outcome.map_or(true, |n| n == 0);
            if gone {
                saw_eof = true;
                break;
            }
        }
        assert!(
            saw_eof,
            "dropping the session must take the tunnel down with it"
        );
    }

    fn test_target() -> crate::addr::TargetAddr {
        crate::addr::TargetAddr::new(crate::addr::Host::Ip("127.0.0.1".parse().expect("ip")), 80)
    }
}
