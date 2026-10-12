//! The `AsyncRead`/`AsyncWrite` adapter over the mKCP session (spec §5.3).
//!
//! `KcpStream` is the byte stream the rest of the composition consumes:
//! `transport::connect` returns it boxed as a [`crate::BoxStream`], and
//! `security::wrap` (TLS/REALITY) wraps it exactly as it wraps the TCP
//! stream today (§5.4: kcp → security → upgrade passthrough → protocol).
//!
//! No extra buffering: reads drain the session's recv window and writes
//! push into its send window directly, with notifier-driven waiting. The
//! session's poll-style read/write register the task waker on the data
//! notifiers, so a dropped `KcpStream` (like a dropped TCP socket) closes
//! the session and lets the driver finish the terminate handshake.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskCx, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::KcpSession;

/// A reliable byte stream over the mKCP session (spec §5.3): `AsyncRead` +
/// `AsyncWrite` + `Send` + `Unpin` — the crate's [`crate::Stream`] seam, so
/// the security layer wraps it like TCP.
pub struct KcpStream {
    session: Arc<KcpSession>,
}

impl KcpStream {
    /// Wrap a session built by the dial side.
    #[must_use]
    pub const fn new(session: Arc<KcpSession>) -> Self {
        Self { session }
    }
}

impl Drop for KcpStream {
    fn drop(&mut self) {
        // TCP-drop semantics: dropping the stream closes the session (the
        // terminate handshake runs in the driver task). Idempotent.
        self.session.close();
    }
}

impl AsyncRead for KcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.session.poll_read(buf.initialize_unfilled(), cx) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for KcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskCx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.session.poll_write(buf, cx)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        // KCP has no explicit flush: writes land in the send window and the
        // driver flushes on its ticks/notifications. Nothing to do.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        self.session.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    use super::KcpStream;
    use crate::transport::kcp::State;
    use crate::transport::kcp::fake_peer::{PeerConfig, payload, spawn_harness};

    /// Read exactly `expected` bytes through the stream under `deadline`
    /// (EOF early-returns; the caller's equality assert then fails).
    async fn read_stream(stream: &mut KcpStream, expected: usize, deadline: Duration) -> Vec<u8> {
        let mut got = Vec::with_capacity(expected);
        let mut chunk = vec![0u8; 8192];
        loop {
            if got.len() >= expected {
                return got;
            }
            let n = timeout(deadline, stream.read(&mut chunk))
                .await
                .expect("read deadline exceeded")
                .expect("read error");
            if n == 0 {
                return got; // EOF
            }
            got.extend_from_slice(&chunk[..n]);
        }
    }

    /// Stream adapter over a real loopback session: `AsyncWrite` the payload,
    /// `AsyncRead` the peer's echo back — the exact shape the security layer
    /// consumes.
    #[tokio::test]
    async fn stream_echo_roundtrip() {
        let (client, _obs) = spawn_harness(PeerConfig::default()).await;
        let mut stream = KcpStream::new(client.session.clone());
        let data = payload(2); // crosses the mss boundary (2 × 1332)
        stream.write_all(&data).await.expect("write_all");
        let got = read_stream(&mut stream, data.len(), Duration::from_secs(5)).await;
        assert_eq!(got, data, "echoed payload must match, in order");
    }

    // ==== Driver timer regression (T3 ruling — the drive() flush fix is
    // KEPT; these pin the real-time behavior it fixed) ====
    //
    // Pre-fix, the driver's tokio::select! timer arms woke but never ran
    // flush() — only flush_seq notify wakeups did — so the RTO retransmit,
    // the 5s silence ping and the terminate-handshake state timers
    // (8s/4s/15s) never fired. T2's injected-clock unit tests could not see
    // it. Each test below pins ONE timer-driven behavior under real time
    // with no further session input after the setup step.

    /// The RTO retransmit fires from the driver's data tick alone: the
    /// first datagram is dropped, the write completes, and NOTHING else
    /// happens (no further writes, no further `session.input`). The echo
    /// can only arrive because the driver re-sends the segment when its
    /// RTO (100ms initial) expires. Pre-fix this test deadlocks on the read
    /// deadline.
    #[tokio::test]
    async fn driver_rto_retransmit_without_further_input() {
        let (client, obs) = spawn_harness(PeerConfig {
            drop_first: 1,
            ..PeerConfig::default()
        })
        .await;
        let mut stream = KcpStream::new(client.session.clone());
        let data = payload(1); // one mss segment
        stream.write_all(&data).await.expect("write_all");
        // No further input: only the driver's RTO tick runs now.
        let got = read_stream(&mut stream, data.len(), Duration::from_secs(5)).await;
        assert_eq!(got, data, "RTO retransmit must deliver the payload");
        // Exactly one Data segment reached the peer (the first try was
        // dropped before counting) — the timer-driven re-send, nothing
        // else. 0 would mean the driver never flushed on the timer wake.
        assert_eq!(
            obs.lock().data_segments,
            1,
            "exactly one timer-driven retransmit"
        );
    }

    /// The 5s silence ping fires from the driver's ping tick with zero
    /// traffic (no writes, no reads): the peer must observe the client's
    /// `CmdOnly` ping purely from the timer → flush. Pre-fix the peer never
    /// saw a ping.
    #[tokio::test]
    async fn driver_silence_ping_fires() {
        let (client, obs) = spawn_harness(PeerConfig::default()).await;
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        loop {
            if obs.lock().pings >= 1 {
                break;
            }
            let _ = tokio::select! {
                () = &mut deadline => panic!("silence ping never fired"),
                () = tokio::time::sleep(Duration::from_millis(20)) => 1u8,
            };
        }
        assert_eq!(
            client.state(),
            State::Active,
            "peer pings keep the session alive"
        );
    }

    /// The terminate-handshake state transition advances on the driver's
    /// timers with the peer IGNORING the Terminate: after shutdown the
    /// client sends one Terminate and, with no reply, reaches `Terminated`
    /// via the 8s terminating timer (the driver's 1s handshake ticks must
    /// keep flushing). Pre-fix the ticks woke but never flushed, so the
    /// state never advanced past `Terminating`.
    #[tokio::test]
    async fn driver_terminate_handshake_advances_unanswered() {
        let (client, obs) = spawn_harness(PeerConfig {
            ignore_terminate: true,
            ..PeerConfig::default()
        })
        .await;
        let mut stream = KcpStream::new(client.session.clone());
        stream.shutdown().await.expect("shutdown");
        let deadline = tokio::time::sleep(Duration::from_secs(15));
        tokio::pin!(deadline);
        loop {
            if client.state() == State::Terminated {
                break;
            }
            let _ = tokio::select! {
                () = &mut deadline => panic!(
                    "terminate handshake never reached Terminated: {:?}",
                    client.state()
                ),
                () = tokio::time::sleep(Duration::from_millis(20)) => 1u8,
            };
        }
        assert!(
            obs.lock().terminates >= 1,
            "client must have sent the Terminate"
        );
    }
}
