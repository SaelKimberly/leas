//! Native-core telemetry: log / traffic / per-connection trace events.
//!
//! TWO cheap, async-friendly feeds for the TUI adapter: log lines on one
//! bounded [`tokio::sync::mpsc`] channel, per-connection trace rows on their
//! own. The split is the point — every emit is a non-blocking `try_send`, so
//! a full channel drops the event, and a log burst sharing one queue would
//! evict the `Opened`/`Closed` pair of a live connection (leaving the TUI's
//! connection table holding a leg that already ended). [`NativeEvents::recv`]
//! drains traces first for the same reason.
//!
//! A drop is COUNTED, never logged inline: a `tracing::warn!` from here
//! re-enters the TUI's log layer, which emits another log event, which drops
//! again. The counts surface as one summary line per poll window, folded in
//! by [`Telemetry::drain_traffic`].
//!
//! Byte totals accumulate in shared atomics that the 3 s delta poller reads
//! with [`Telemetry::drain_traffic`].
//!
//! Connection ids come from a process-global [`AtomicU64`] counter and are
//! assigned inside [`Telemetry::opened`], which returns the fresh id for the
//! later [`Telemetry::closed`] call. [`TraceGuard`] ties the two together so
//! a cancelled relay still reports its close row. Byte accounting rides on
//! [`Counted`], a thin `AsyncRead`/`AsyncWrite` wrapper (writes count as up,
//! reads as down) sharing the telemetry atomics; create one per relayed
//! stream with [`Telemetry::counted`].

use std::{
    io::IoSlice,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};

/// Process-global connection-id source; [`Telemetry::opened`] bumps it.
/// Starts at 1 so `0` stays an obvious sentinel in logs.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

/// What kind of local inbound leg a traced connection arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceKind {
    /// SOCKS5 TCP CONNECT (or plain proxied TCP).
    Tcp,
    /// SOCKS5 UDP ASSOCIATE association.
    UdpAssoc,
    /// HTTP CONNECT.
    Http,
}

/// Security layer negotiated on the outbound leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceSecurity {
    /// No TLS/REALITY wrap.
    Plain,
    /// TLS.
    Tls,
    /// REALITY.
    Reality,
}

/// A connection started: emitted once per accepted inbound leg.
///
/// `dest`/`protocol`/`transport` are `Arc<str>`: the profile-level names are
/// shared across every leg of the session (one allocation per profile, not
/// per connection), and only the per-connection `dest` string allocates.
#[derive(Debug, Clone)]
pub struct TraceOpened {
    /// Id assigned by [`Telemetry::opened`]; match with [`TraceClosed`].
    pub conn_id: u64,
    /// Which inbound leg this is.
    pub kind: TraceKind,
    /// Destination as `host:port`.
    pub dest: Arc<str>,
    /// Outbound protocol name (e.g. `"vless"`).
    pub protocol: Arc<str>,
    /// Outbound transport name (e.g. `"tcp"`, `"ws"`).
    pub transport: Arc<str>,
    /// Outbound security layer.
    pub security: TraceSecurity,
}
#[derive(Debug, Clone)]
pub struct TraceClosed {
    /// Id from the matching [`TraceOpened`].
    pub conn_id: u64,
    /// Bytes written toward the remote (up direction).
    pub up_bytes: u64,
    /// Bytes read from the remote (down direction).
    pub down_bytes: u64,
    /// Whole-connection lifetime.
    pub duration_ms: u64,
    /// Failure reason, if the leg ended in error.
    pub error: Option<String>,
}

/// Per-connection realtime trace event.
#[derive(Debug, Clone)]
pub enum TraceEvent {
    /// A leg was accepted (and its outbound dialed).
    Opened(TraceOpened),
    /// A leg finished (ok or failed).
    Closed(TraceClosed),
}

/// The single native → TUI event feed.
#[derive(Debug, Clone)]
pub enum NativeEvent {
    /// Structured log line (no timestamp — the TUI stamps on receipt).
    Log {
        /// e.g. `"info"`, `"warn"`, `"error"`, `"debug"`.
        level: &'static str,
        /// e.g. `"leas_native::inbound"`.
        target: &'static str,
        /// The message body.
        message: String,
    },
    /// Poll-window byte delta (produced by the poller from [`Telemetry::drain_traffic`]).
    Traffic {
        /// Client → remote bytes since the last poll.
        up: u64,
        /// Remote → client bytes since the last poll.
        down: u64,
    },
    /// Per-connection open/close.
    Trace(TraceEvent),
}

/// Telemetry sink: one sender per event class plus shared traffic atomics.
///
/// Cheap to clone and to call from connection tasks: every emit is a
/// non-blocking `try_send`, and byte totals are lock-free counters that the
/// poller resets with [`Telemetry::drain_traffic`].
#[derive(Debug, Clone)]
pub struct Telemetry {
    logs: mpsc::Sender<NativeEvent>,
    traces: mpsc::Sender<NativeEvent>,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    dropped_logs: Arc<AtomicU64>,
    dropped_traces: Arc<AtomicU64>,
}

impl Telemetry {
    /// Create a sink whose log queue and trace queue each hold `cap` events.
    ///
    /// A `cap` of `0` is clamped to `1` (a zero-buffer `mpsc` panics).
    /// Returns the sink and the [`NativeEvents`] feed the TUI adapter drains.
    #[must_use]
    pub fn new(cap: usize) -> (Self, NativeEvents) {
        let cap = cap.max(1);
        let (logs, logs_rx) = mpsc::channel(cap);
        let (traces, traces_rx) = mpsc::channel(cap);
        (
            Self {
                logs,
                traces,
                up: Arc::new(AtomicU64::new(0)),
                down: Arc::new(AtomicU64::new(0)),
                dropped_logs: Arc::new(AtomicU64::new(0)),
                dropped_traces: Arc::new(AtomicU64::new(0)),
            },
            NativeEvents {
                logs: logs_rx,
                traces: traces_rx,
                logs_open: true,
                traces_open: true,
            },
        )
    }

    /// Emit a [`NativeEvent::Log`]; a full log queue drops it and counts it.
    pub fn log(&self, level: &'static str, target: &'static str, message: impl Into<String>) {
        Self::emit(
            &self.logs,
            &self.dropped_logs,
            NativeEvent::Log {
                level,
                target,
                message: message.into(),
            },
        );
    }

    /// Emit [`TraceEvent::Opened`] with a fresh process-global `conn_id`,
    /// returned for the matching [`Telemetry::closed`] call (or for
    /// [`Telemetry::guard`], which cannot forget it).
    pub fn opened(
        &self,
        kind: TraceKind,
        dest: impl Into<Arc<str>>,
        protocol: impl Into<Arc<str>>,
        transport: impl Into<Arc<str>>,
        security: TraceSecurity,
    ) -> u64 {
        let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        Self::emit(
            &self.traces,
            &self.dropped_traces,
            NativeEvent::Trace(TraceEvent::Opened(TraceOpened {
                conn_id,
                kind,
                dest: dest.into(),
                protocol: protocol.into(),
                transport: transport.into(),
                security,
            })),
        );
        conn_id
    }

    /// Emit [`TraceEvent::Closed`] for a leg previously opened with
    /// [`Telemetry::opened`].
    pub fn closed(
        &self,
        conn_id: u64,
        up_bytes: u64,
        down_bytes: u64,
        duration_ms: u64,
        error: Option<String>,
    ) {
        Self::emit(
            &self.traces,
            &self.dropped_traces,
            NativeEvent::Trace(TraceEvent::Closed(TraceClosed {
                conn_id,
                up_bytes,
                down_bytes,
                duration_ms,
                error,
            })),
        );
    }

    /// Own the [`TraceEvent::Closed`] row of the leg `conn_id`, reading its
    /// totals from the per-leg counters `up`/`down`.
    ///
    /// The guard emits the row even when the relay future is dropped mid-leg
    /// (an inbound shutdown, a cancelled task) — see [`TraceGuard`].
    #[must_use]
    pub fn guard(&self, conn_id: u64, up: Arc<AtomicU64>, down: Arc<AtomicU64>) -> TraceGuard {
        TraceGuard {
            telemetry: self.clone(),
            conn_id,
            up,
            down,
            started: Instant::now(),
            emitted: false,
        }
    }

    /// Add a traffic delta to the shared counters (called by [`Counted`]
    /// automatically; exposed for manual accounting such as UDP relays).
    pub fn add_traffic(&self, up: u64, down: u64) {
        self.up.fetch_add(up, Ordering::Relaxed);
        self.down.fetch_add(down, Ordering::Relaxed);
    }

    /// Read-and-reset both traffic counters for the 3 s delta poller, folding
    /// any events dropped since the previous drain into ONE summary log line.
    ///
    /// Returns `(up, down)` accumulated since the previous drain. Concurrent
    /// increments during the two swaps may land in either window — deltas
    /// stay exact over time, just possibly attributed to adjacent polls.
    #[must_use]
    pub fn drain_traffic(&self) -> (u64, u64) {
        self.flush_drops();
        (
            self.up.swap(0, Ordering::Relaxed),
            self.down.swap(0, Ordering::Relaxed),
        )
    }

    /// Wrap a relayed stream so its bytes feed the shared traffic counters:
    /// writes count as up, reads as down.
    #[must_use]
    pub fn counted<S>(&self, inner: S) -> Counted<S> {
        Counted {
            inner,
            up: Arc::clone(&self.up),
            down: Arc::clone(&self.down),
        }
    }

    /// Non-blocking emit; a full or closed queue drops the event and bumps
    /// `dropped`.
    ///
    /// NEVER logs the drop: `tracing` from here re-enters the TUI's log layer,
    /// which emits another log event — a saturated feed would amplify itself.
    /// [`Self::flush_drops`] reports the count once per poll window instead.
    fn emit(tx: &mpsc::Sender<NativeEvent>, dropped: &AtomicU64, event: NativeEvent) {
        if tx.try_send(event).is_err() {
            dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Fold the events dropped since the last window into one log line.
    ///
    /// When the log queue itself has no room the counts are put back, so the
    /// next window reports them: a summary must never evict a real event.
    fn flush_drops(&self) {
        let traces = self.dropped_traces.swap(0, Ordering::Relaxed);
        let logs = self.dropped_logs.swap(0, Ordering::Relaxed);
        if traces == 0 && logs == 0 {
            return;
        }
        let event = NativeEvent::Log {
            level: "warn",
            target: "leas_native::telemetry",
            message: format!(
                "telemetry feed saturated: dropped {traces} trace events and {logs} log events"
            ),
        };
        if self.logs.try_send(event).is_err() {
            self.dropped_traces.fetch_add(traces, Ordering::Relaxed);
            self.dropped_logs.fetch_add(logs, Ordering::Relaxed);
        }
    }
}

/// The TUI-side end of the feed: one queue for logs, one for traces.
///
/// Separate queues keep a log burst from evicting trace rows — an evicted
/// `Closed` leaves the TUI's connection table holding a leg that ended, and
/// an evicted `Opened` makes its `Closed` unmatched.
#[derive(Debug)]
pub struct NativeEvents {
    logs: mpsc::Receiver<NativeEvent>,
    traces: mpsc::Receiver<NativeEvent>,
    /// Cleared once the log queue is closed AND drained: a closed queue
    /// yields `None` immediately, which must not be mistaken for "the feed is
    /// over" while the other queue still holds buffered events.
    logs_open: bool,
    /// Cleared once the trace queue is closed and drained.
    traces_open: bool,
}

impl NativeEvents {
    /// The next event, traces first; `None` once every sender is gone and both
    /// queues are drained.
    ///
    /// Cancel-safe: the future never holds a received event, so losing a
    /// `select!` race cannot lose one.
    pub async fn recv(&mut self) -> Option<NativeEvent> {
        loop {
            match (self.traces_open, self.logs_open) {
                (true, true) => {
                    tokio::select! {
                        biased;
                        event = self.traces.recv() => match event {
                            Some(event) => return Some(event),
                            None => self.traces_open = false,
                        },
                        event = self.logs.recv() => match event {
                            Some(event) => return Some(event),
                            None => self.logs_open = false,
                        },
                    }
                }
                (true, false) => match self.traces.recv().await {
                    Some(event) => return Some(event),
                    None => self.traces_open = false,
                },
                (false, true) => match self.logs.recv().await {
                    Some(event) => return Some(event),
                    None => self.logs_open = false,
                },
                (false, false) => return None,
            }
        }
    }
}

/// Owns the [`TraceEvent::Closed`] row of one traced leg.
///
/// A relay future can be dropped mid-leg — the inbound's shutdown arm, a
/// cancelled connection task — and a close row written after the relay
/// returns then never fires, leaving the TUI's connection table holding an
/// `Opened` forever. The guard emits on `Drop` unless [`Self::finish`]
/// already emitted, so exactly one row reaches the TUI either way.
///
/// It deliberately does NOT touch the shared traffic counters: the relay wraps
/// its upstream with [`Telemetry::counted`], so those already saw every byte
/// as it flowed and adding the leg totals here would double-count them.
#[derive(Debug)]
pub struct TraceGuard {
    telemetry: Telemetry,
    conn_id: u64,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    started: Instant,
    emitted: bool,
}

impl TraceGuard {
    /// The leg's byte totals so far: `(up, down)`.
    #[must_use]
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }

    /// Milliseconds since the guard was created (the leg's lifetime).
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Emit the close row for a leg that ended on its own, carrying `error`
    /// when it ended badly. Later calls and the `Drop` emit nothing.
    pub fn finish(&mut self, error: Option<String>) {
        self.emit(error);
    }

    /// Emit once, whoever gets there first.
    fn emit(&mut self, error: Option<String>) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        let (up, down) = self.bytes();
        self.telemetry
            .closed(self.conn_id, up, down, self.elapsed_ms(), error);
    }
}

impl Drop for TraceGuard {
    fn drop(&mut self) {
        // Dropped without `finish`: the leg was cancelled (shutdown, task
        // abort). It still ended, so the row still belongs in the table.
        self.emit(Some("cancelled".to_owned()));
    }
}

/// Byte-counting stream wrapper: writes add to `up`, reads add to `down`.
///
/// Only successful polls count (0-byte reads and errors add nothing). The
/// counters are the shared telemetry atomics, so [`Telemetry::drain_traffic`]
/// picks the totals up with no extra plumbing.
#[derive(Debug)]
pub struct Counted<S> {
    inner: S,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

impl<S> Counted<S> {
    /// Wrap `inner`, counting into the given shared atomics.
    pub const fn new(inner: S, up: Arc<AtomicU64>, down: Arc<AtomicU64>) -> Self {
        Self { inner, up, down }
    }

    /// Recover the wrapped stream (counters stay shared elsewhere).
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Borrow the wrapped stream.
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// The shared counters this wrapper feeds.
    pub fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (Arc::clone(&self.up), Arc::clone(&self.down))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            ok @ Poll::Ready(Ok(())) => {
                let n = buf.filled().len() - before;
                if n > 0 {
                    this.down.fetch_add(n as u64, Ordering::Relaxed);
                }
                ok
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.up.fetch_add(n as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    /// Vectored writes are the relay's zero-copy path: without this the
    /// default `AsyncWrite` shim collapses the slices into one `poll_write`
    /// per call, so an upstream that gathers (TLS records, HTTP/2 frames)
    /// would silently lose that batching just because it is being counted.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.up.fetch_add(n as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    /// Report the wrapped stream's real capability: claiming `false` here
    /// would make callers serialise writes they could have gathered.
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn event_flow_through_channel() {
        let (tel, mut rx) = Telemetry::new(16);

        tel.log("info", "leas_native::test", "hello");
        let conn_id = tel.opened(
            TraceKind::Tcp,
            "example.com:443",
            "vless",
            "tcp",
            TraceSecurity::Tls,
        );
        tel.closed(conn_id, 10, 20, 5, None);
        tel.closed(conn_id + 1000, 0, 0, 1, Some("dial failed".to_owned()));

        let mut kinds = Vec::new();
        for _ in 0..4 {
            match rx.recv().await.expect("event") {
                NativeEvent::Log {
                    level,
                    target,
                    message,
                } => {
                    assert_eq!(level, "info");
                    assert_eq!(target, "leas_native::test");
                    assert_eq!(message, "hello");
                    kinds.push("log");
                }
                NativeEvent::Trace(TraceEvent::Opened(o)) => {
                    assert_eq!(o.conn_id, conn_id);
                    assert_eq!(o.kind, TraceKind::Tcp);
                    assert_eq!(&o.dest[..], "example.com:443");
                    assert_eq!(&o.protocol[..], "vless");
                    assert_eq!(&o.transport[..], "tcp");
                    assert_eq!(o.security, TraceSecurity::Tls);
                    kinds.push("opened");
                }
                NativeEvent::Trace(TraceEvent::Closed(c)) if c.error.is_none() => {
                    assert_eq!(
                        (c.conn_id, c.up_bytes, c.down_bytes, c.duration_ms),
                        (conn_id, 10, 20, 5)
                    );
                    kinds.push("closed-ok");
                }
                NativeEvent::Trace(TraceEvent::Closed(c)) => {
                    assert_eq!(c.error.as_deref(), Some("dial failed"));
                    kinds.push("closed-err");
                }
                NativeEvent::Traffic { .. } => kinds.push("traffic?"),
            }
        }
        // Traces drain before logs: the pair matters more than the line, and
        // `NativeEvents::recv` is biased toward the trace queue.
        assert_eq!(kinds, ["opened", "closed-ok", "closed-err", "log"]);

        // conn_ids are unique across opens.
        let a = tel.opened(
            TraceKind::Http,
            "h:80",
            "trojan",
            "tcp",
            TraceSecurity::Plain,
        );
        let b = tel.opened(
            TraceKind::UdpAssoc,
            "d:53",
            "vless",
            "tcp",
            TraceSecurity::Reality,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn drain_traffic_read_and_reset() {
        let (tel, _rx) = Telemetry::new(4);
        assert_eq!(tel.drain_traffic(), (0, 0));

        tel.add_traffic(100, 200);
        tel.add_traffic(50, 25);
        assert_eq!(tel.drain_traffic(), (150, 225));

        // Reset sticks: second drain is empty until new traffic arrives.
        assert_eq!(tel.drain_traffic(), (0, 0));
        tel.add_traffic(0, 7);
        assert_eq!(tel.drain_traffic(), (0, 7));
    }

    #[test]
    fn full_channel_drops_without_panicking() {
        // cap 1: more than 1 buffered event must not block or panic.
        let (tel, _rx) = Telemetry::new(1);
        for i in 0..100 {
            tel.log("debug", "leas_native::test", format!("line {i}"));
        }
        tel.add_traffic(1, 1);
        assert_eq!(tel.drain_traffic(), (1, 1));
    }

    #[tokio::test]
    async fn counted_wrapper_accounts_both_directions() {
        let (tel, _rx) = Telemetry::new(8);
        let (a, b) = duplex(64);
        let mut counted = tel.counted(a);
        let mut peer = b;

        // Write path counts up.
        counted.write_all(b"hello").await.expect("write");
        counted.flush().await.expect("flush");
        let mut buf = [0u8; 5];
        peer.read_exact(&mut buf).await.expect("peer read");
        assert_eq!(&buf, b"hello");

        // Read path counts down.
        peer.write_all(b"world!").await.expect("peer write");
        let mut back = [0u8; 6];
        counted.read_exact(&mut back).await.expect("read");
        assert_eq!(&back, b"world!");

        assert_eq!(tel.drain_traffic(), (5, 6));

        // into_inner hands the stream back untouched.
        let _ = counted.into_inner();
    }

    /// The reason the channels are split: a log burst that overflows its own
    /// queue must not cost the trace pair of a live connection.
    #[tokio::test]
    async fn log_burst_does_not_evict_trace_pairs() {
        let (tel, mut events) = Telemetry::new(4);
        for i in 0..100 {
            tel.log("debug", "leas_native::test", format!("line {i}"));
        }
        let conn_id = tel.opened(
            TraceKind::Tcp,
            "example.com:443",
            "vless",
            "tcp",
            TraceSecurity::Tls,
        );
        tel.closed(conn_id, 1, 2, 3, None);

        match events.recv().await.expect("opened survives the burst") {
            NativeEvent::Trace(TraceEvent::Opened(o)) => assert_eq!(o.conn_id, conn_id),
            other => panic!("expected the Opened row first: {other:?}"),
        }
        match events.recv().await.expect("closed survives the burst") {
            NativeEvent::Trace(TraceEvent::Closed(c)) => assert_eq!(c.conn_id, conn_id),
            other => panic!("expected the Closed row second: {other:?}"),
        }
    }

    /// Drops are counted and reported ONCE per poll window, not warned about
    /// per event (a warn from the sink re-enters the TUI log layer).
    #[tokio::test]
    async fn dropped_events_surface_as_one_summary_per_window() {
        let (tel, mut events) = Telemetry::new(2);
        for i in 0..10 {
            tel.log("debug", "leas_native::test", format!("line {i}"));
        }
        // Free the log queue so the summary has somewhere to land.
        for _ in 0..2 {
            events.recv().await.expect("buffered log");
        }

        assert_eq!(tel.drain_traffic(), (0, 0));
        match events.recv().await.expect("summary") {
            NativeEvent::Log { level, message, .. } => {
                assert_eq!(level, "warn");
                assert!(
                    message.contains("dropped 0 trace events and 8 log events"),
                    "summary names both counts: {message}"
                );
            }
            other => panic!("expected the drop summary: {other:?}"),
        }

        // The counters reset with the window: no second summary.
        assert_eq!(tel.drain_traffic(), (0, 0));
        let idle = tokio::time::timeout(std::time::Duration::from_millis(50), events.recv()).await;
        assert!(idle.is_err(), "one summary per window, got {idle:?}");
    }

    /// A cancelled leg still reports its close row — exactly once.
    #[tokio::test]
    async fn trace_guard_emits_closed_once() {
        let (tel, mut events) = Telemetry::new(8);
        let conn_id = tel.opened(TraceKind::Http, "h:443", "vless", "tcp", TraceSecurity::Tls);
        let up = Arc::new(AtomicU64::new(7));
        let down = Arc::new(AtomicU64::new(11));
        drop(tel.guard(conn_id, Arc::clone(&up), Arc::clone(&down)));

        assert!(matches!(
            events.recv().await.expect("opened"),
            NativeEvent::Trace(TraceEvent::Opened(_))
        ));
        match events.recv().await.expect("closed on drop") {
            NativeEvent::Trace(TraceEvent::Closed(c)) => {
                assert_eq!((c.conn_id, c.up_bytes, c.down_bytes), (conn_id, 7, 11));
                assert_eq!(c.error.as_deref(), Some("cancelled"));
            }
            other => panic!("expected the guard's Closed row: {other:?}"),
        }

        // A finished guard emits its own row and nothing on drop.
        let conn_id = tel.opened(TraceKind::Tcp, "h:80", "vless", "tcp", TraceSecurity::Plain);
        let mut guard = tel.guard(conn_id, Arc::clone(&up), Arc::clone(&down));
        guard.finish(None);
        drop(guard);
        assert!(matches!(
            events.recv().await.expect("opened"),
            NativeEvent::Trace(TraceEvent::Opened(_))
        ));
        match events.recv().await.expect("closed on finish") {
            NativeEvent::Trace(TraceEvent::Closed(c)) => {
                assert_eq!(c.conn_id, conn_id);
                assert!(c.error.is_none(), "finished cleanly: {:?}", c.error);
            }
            other => panic!("expected the finished Closed row: {other:?}"),
        }
        let idle = tokio::time::timeout(std::time::Duration::from_millis(50), events.recv()).await;
        assert!(idle.is_err(), "finish consumed the guard, got {idle:?}");
    }

    /// Vectored writes stay vectored and are accounted exactly once.
    #[tokio::test]
    async fn counted_delegates_vectored_writes() {
        let (tel, _rx) = Telemetry::new(8);
        let (a, mut peer) = duplex(64);
        let mut counted = tel.counted(a);
        assert_eq!(
            counted.is_write_vectored(),
            counted.inner().is_write_vectored(),
            "capability mirrors the wrapped stream"
        );

        let n = counted
            .write_vectored(&[IoSlice::new(b"ab"), IoSlice::new(b"cdef")])
            .await
            .expect("vectored write");
        assert!(n > 0, "wrote something");
        counted.flush().await.expect("flush");
        let mut buf = vec![0u8; n];
        peer.read_exact(&mut buf).await.expect("peer read");

        assert_eq!(
            tel.drain_traffic(),
            (n as u64, 0),
            "up counts exactly the bytes the vectored write reported"
        );
    }
}
