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

use compact_str::CompactString;
// Host/open/pending maps use rapidhash's FAST hasher (AVALANCHE/PROTECTED off,
// so only minimal HashDoS resistance). Host keys are attacker-influenced — any
// local client can name arbitrary domains — but the listener is
// loopback-trusted and the table is capped at 1000 rows; the per-datagram
// lookup wins are worth that accepted trade.
use rapidhash::RapidHashMap;
use smallvec::SmallVec;
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
    /// A leg was refused before it could reach a relay (no bytes, no close).
    Failed(TraceFailed),
}

/// Why a leg never reached the relay. Rendered by the Sniffer pane and
/// aggregated per host, so the set is closed rather than free-form text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TraceFailReason {
    /// Method/credential negotiation failed.
    Auth,
    /// The request head never parsed.
    Malformed,
    /// Routing chose a `Block` outbound.
    Blocked,
    /// Routing rejected the destination.
    Rejected,
    /// Routing asked for DNS interception, which this inbound does not do.
    HijackDns,
    /// The routing decision named a tag with no outbound.
    NoOutbound,
    /// The outbound dial failed.
    Dial,
}

impl TraceFailReason {
    /// Stable short label for logs and the Sniffer summary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Malformed => "malformed",
            Self::Blocked => "blocked",
            Self::Rejected => "rejected",
            Self::HijackDns => "hijack-dns",
            Self::NoOutbound => "no-outbound",
            Self::Dial => "dial",
        }
    }
}

/// A leg refused before the relay: no byte totals exist for it.
#[derive(Debug, Clone)]
pub struct TraceFailed {
    /// Inbound leg kind that refused it.
    pub kind: TraceKind,
    /// Destination host as sent; [`UNKNOWN_HOST`] when no target parsed.
    pub host: CompactString,
    /// Why it was refused.
    pub reason: TraceFailReason,
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

/// Placeholder host for a failure that never yielded a destination.
pub const UNKNOWN_HOST: &str = "(unknown)";

/// Hosts kept in the session table; the least recently active is evicted
/// past this. Bounds a browser session that keeps naming new hosts.
const HOST_TABLE_CAP: usize = 1000;

/// One host's session totals, as the Sniffer pane consumes them.
#[derive(Debug, Clone)]
pub struct HostStat {
    /// Host as the client sent it (domain or IP literal), port stripped.
    pub host: CompactString,
    /// Client → remote bytes.
    pub up: u64,
    /// Remote → client bytes.
    pub down: u64,
    /// Accepted legs plus UDP associations that touched this host.
    pub conns: u64,
    /// Refused or failed legs attributed to this host.
    pub failed: u64,
    /// Outbound tag the route named for this host's most recent routed event
    /// (a leg open, a refusal, or a UDP association); `None` until one names
    /// it. A later `Reject`/`HijackDns` does not clear it.
    pub outbound: Option<CompactString>,
}

/// One session's per-host accounting, sorted by total bytes descending.
#[derive(Debug, Clone, Default)]
pub struct SnifferSnapshot {
    /// Per-host rows; inline up to 16 hosts.
    pub hosts: SmallVec<[HostStat; 16]>,
    /// Undelivered UDP payload bytes.
    pub dropped_bytes: u64,
    /// Undelivered UDP datagrams.
    pub dropped_datagrams: u64,
    /// Every pre-relay refusal and failed leg this session.
    pub failed: u64,
}

/// Per-host cumulative totals; the map key is the host.
#[derive(Debug, Default)]
struct HostRow {
    up: u64,
    down: u64,
    conns: u64,
    failed: u64,
    last_seq: u64,
    /// Last-wins: the tag of the most recent routed event for the host (leg
    /// open, refusal, or association); never rewritten by a close.
    outbound: Option<CompactString>,
}

/// A relayed leg whose bytes are still in flight (folded into [`HostRow`] on
/// close, so a leg is either open or folded — never both).
#[derive(Debug)]
struct OpenLeg {
    host: CompactString,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

/// Strip the port from a traced destination (`host:port`, `[v6]:port`).
fn host_of(dest: &str) -> &str {
    if let Some(rest) = dest.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    dest.rsplit_once(':').map_or(dest, |(host, _)| host)
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
    /// Per-host session totals, keyed by the host as sent (no port).
    hosts: Arc<parking_lot::Mutex<RapidHashMap<CompactString, HostRow>>>,
    /// Legs whose bytes have not been folded into `hosts` yet.
    open: Arc<parking_lot::Mutex<RapidHashMap<u64, OpenLeg>>>,
    /// Host recorded by [`Telemetry::opened`] before its atomics exist.
    pending: Arc<parking_lot::Mutex<RapidHashMap<u64, CompactString>>>,
    /// Monotonic activity counter for LRU eviction (cheaper than `Instant`).
    seq: Arc<AtomicU64>,
    dropped_bytes: Arc<AtomicU64>,
    dropped_datagrams: Arc<AtomicU64>,
    failed_total: Arc<AtomicU64>,
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
                hosts: Arc::new(parking_lot::Mutex::new(RapidHashMap::default())),
                open: Arc::new(parking_lot::Mutex::new(RapidHashMap::default())),
                pending: Arc::new(parking_lot::Mutex::new(RapidHashMap::default())),
                seq: Arc::new(AtomicU64::new(0)),
                dropped_bytes: Arc::new(AtomicU64::new(0)),
                dropped_datagrams: Arc::new(AtomicU64::new(0)),
                failed_total: Arc::new(AtomicU64::new(0)),
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
        let dest: Arc<str> = dest.into();
        self.pending
            .lock()
            .insert(conn_id, CompactString::new(host_of(&dest)));
        Self::emit(
            &self.traces,
            &self.dropped_traces,
            NativeEvent::Trace(TraceEvent::Opened(TraceOpened {
                conn_id,
                kind,
                dest,
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
        self.fold_leg(conn_id, up_bytes, down_bytes);
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
    pub fn guard(
        &self,
        conn_id: u64,
        up: Arc<AtomicU64>,
        down: Arc<AtomicU64>,
        outbound: Option<&str>,
    ) -> TraceGuard {
        let host = self
            .pending
            .lock()
            .remove(&conn_id)
            .unwrap_or_else(|| CompactString::new(UNKNOWN_HOST));
        self.with_host(&host, |row| {
            row.conns = row.conns.saturating_add(1);
            if let Some(tag) = outbound {
                row.outbound = Some(CompactString::new(tag));
            }
        });
        self.open.lock().insert(
            conn_id,
            OpenLeg {
                host,
                up: Arc::clone(&up),
                down: Arc::clone(&down),
            },
        );
        TraceGuard {
            telemetry: self.clone(),
            conn_id,
            up,
            down,
            started: Instant::now(),
            emitted: false,
        }
    }

    /// Account one refused leg and emit [`TraceEvent::Failed`].
    ///
    /// `dest` is the destination as the client sent it; the port is stripped
    /// like every other host key. Bytes are never touched.
    pub fn failed(
        &self,
        kind: TraceKind,
        dest: &str,
        reason: TraceFailReason,
        outbound: Option<&str>,
    ) {
        let host = host_of(dest);
        // A failure that never parsed a destination has no host to attribute:
        // it counts in the session total only, never as a `(unknown)` row.
        if host != UNKNOWN_HOST {
            self.with_host(host, |row| {
                row.failed = row.failed.saturating_add(1);
                if let Some(tag) = outbound {
                    row.outbound = Some(CompactString::new(tag));
                }
            });
        }
        self.failed_total.fetch_add(1, Ordering::Relaxed);
        Self::emit(
            &self.traces,
            &self.dropped_traces,
            NativeEvent::Trace(TraceEvent::Failed(TraceFailed {
                kind,
                host: CompactString::new(host),
                reason,
            })),
        );
    }

    /// Fold one finished leg into its host row and drop it from the open map.
    ///
    /// The ledger is the only source of a leg's host, so a `Closed` for an id
    /// that was never opened (a dropped `Opened`, a test) folds nothing.
    fn fold_leg(&self, conn_id: u64, up: u64, down: u64) {
        let host = {
            let mut open = self.open.lock();
            match open.remove(&conn_id) {
                Some(leg) => Some(leg.host),
                None => self.pending.lock().remove(&conn_id),
            }
        };
        if let Some(host) = host {
            self.with_host(&host, |row| {
                row.up = row.up.saturating_add(up);
                row.down = row.down.saturating_add(down);
            });
        }
    }

    /// Run `f` with the row for `host`, creating it (and evicting the least
    /// recently active past [`HOST_TABLE_CAP`]) on first sight.
    fn with_host(&self, host: &str, f: impl FnOnce(&mut HostRow)) {
        let mut table = self.hosts.lock();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        if let Some(row) = table.get_mut(host) {
            row.last_seq = seq;
            f(row);
            return;
        }
        if table.len() >= HOST_TABLE_CAP
            && let Some(oldest) = table
                .iter()
                .min_by_key(|(_, row)| row.last_seq)
                .map(|(host, _)| host.clone())
        {
            table.remove(&oldest);
        }
        let mut row = HostRow {
            last_seq: seq,
            ..HostRow::default()
        };
        f(&mut row);
        table.insert(CompactString::new(host), row);
    }

    /// Account one forwarded UDP datagram (client → destination).
    pub fn udp_sent(&self, host: &str, bytes: u64) {
        self.with_host(host, |row| row.up = row.up.saturating_add(bytes));
    }

    /// Account one delivered UDP reply (destination → client).
    pub fn udp_received(&self, host: &str, bytes: u64) {
        self.with_host(host, |row| row.down = row.down.saturating_add(bytes));
    }

    /// Count one dropped datagram; `host` is `None` when the destination never
    /// parsed. Drop bytes are session-global, not per-host (spec §6).
    pub fn udp_dropped(&self, _host: Option<&str>, bytes: u64) {
        self.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
        self.dropped_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record that one UDP association exchanged traffic with `host`.
    pub fn udp_conn(&self, host: &str, outbound: &str) {
        self.with_host(host, |row| {
            row.conns = row.conns.saturating_add(1);
            row.outbound = Some(CompactString::new(outbound));
        });
    }

    /// Snapshot the session's per-host accounting for the Sniffer pane.
    ///
    /// Closed totals live in the table; still-open legs contribute their live
    /// atomics here, so a long transfer moves before it ends. Sorting is by
    /// total bytes descending, host ascending on ties.
    #[must_use]
    pub fn snapshot(&self) -> SnifferSnapshot {
        let mut hosts: SmallVec<[HostStat; 16]> = self
            .hosts
            .lock()
            .iter()
            .map(|(host, row)| HostStat {
                host: host.clone(),
                up: row.up,
                down: row.down,
                conns: row.conns,
                failed: row.failed,
                outbound: row.outbound.clone(),
            })
            .collect();

        // Sum each open host once (a browser keeps many legs on one host).
        let mut live: SmallVec<[(CompactString, u64, u64); 16]> = SmallVec::new();
        for leg in self.open.lock().values() {
            let (up, down) = (
                leg.up.load(Ordering::Relaxed),
                leg.down.load(Ordering::Relaxed),
            );
            if let Some(slot) = live.iter_mut().find(|(host, _, _)| *host == leg.host) {
                slot.1 = slot.1.saturating_add(up);
                slot.2 = slot.2.saturating_add(down);
            } else {
                live.push((leg.host.clone(), up, down));
            }
        }
        for (host, up, down) in live {
            match hosts.iter_mut().find(|row| row.host == host) {
                Some(row) => {
                    row.up = row.up.saturating_add(up);
                    row.down = row.down.saturating_add(down);
                }
                None => hosts.push(HostStat {
                    host,
                    up,
                    down,
                    conns: 0,
                    failed: 0,
                    outbound: None,
                }),
            }
        }

        hosts.sort_unstable_by(|a, b| {
            (b.up + b.down)
                .cmp(&(a.up + a.down))
                .then_with(|| a.host.cmp(&b.host))
        });

        SnifferSnapshot {
            hosts,
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
            dropped_datagrams: self.dropped_datagrams.load(Ordering::Relaxed),
            failed: self.failed_total.load(Ordering::Relaxed),
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
                NativeEvent::Trace(TraceEvent::Failed(_)) => kinds.push("failed?"),
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
    fn snapshot_sums_open_legs_and_does_not_double_count_after_close() {
        let (telemetry, _events) = Telemetry::new(16);
        let id = telemetry.opened(
            TraceKind::Tcp,
            "example.com:443",
            "vless",
            "tcp",
            TraceSecurity::Tls,
        );
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let mut guard = telemetry.guard(id, Arc::clone(&up), Arc::clone(&down), Some("proxy"));

        up.fetch_add(100, Ordering::Relaxed);
        down.fetch_add(250, Ordering::Relaxed);
        let live = telemetry.snapshot();
        assert_eq!(live.hosts.len(), 1);
        assert_eq!(
            (
                live.hosts[0].host.as_str(),
                live.hosts[0].up,
                live.hosts[0].down
            ),
            ("example.com", 100, 250)
        );

        guard.finish(None);
        let closed = telemetry.snapshot();
        assert_eq!(
            (closed.hosts[0].up, closed.hosts[0].down),
            (100, 250),
            "fold must not double count"
        );
        assert_eq!(closed.hosts[0].conns, 1);
        assert_eq!(
            closed.hosts[0].outbound.as_deref(),
            Some("proxy"),
            "the marker is set at open and survives the close fold"
        );
    }

    #[test]
    fn one_row_per_host_across_ports_and_kinds() {
        let (telemetry, _events) = Telemetry::new(16);
        for dest in ["example.com:443", "example.com:8443", "[2001:db8::1]:53"] {
            let id = telemetry.opened(TraceKind::Tcp, dest, "vless", "tcp", TraceSecurity::Plain);
            telemetry
                .guard(
                    id,
                    Arc::new(AtomicU64::new(10)),
                    Arc::new(AtomicU64::new(1)),
                    None,
                )
                .finish(None);
        }
        let snap = telemetry.snapshot();
        assert_eq!(snap.hosts.len(), 2, "ports merge, families do not");
        assert!(snap.hosts.iter().any(|h| h.host == "2001:db8::1"));
    }

    #[test]
    fn snapshot_sorts_by_total_desc_and_keeps_the_inline_buffer() {
        let (telemetry, _events) = Telemetry::new(16);
        for (dest, bytes) in [("a.example", 1_u64), ("b.example", 5)] {
            telemetry.udp_sent(dest, bytes);
        }
        let snap = telemetry.snapshot();
        assert_eq!(snap.hosts[0].host, "b.example");
        assert!(!snap.hosts.spilled(), "<=16 hosts must stay inline");
    }

    #[test]
    fn udp_bytes_and_drops_land_in_the_table() {
        let (telemetry, _events) = Telemetry::new(16);
        telemetry.udp_sent("dns.example", 40);
        telemetry.udp_received("dns.example", 120);
        telemetry.udp_dropped(Some("dns.example"), 40);
        telemetry.udp_dropped(None, 7);
        let snap = telemetry.snapshot();
        let row = snap
            .hosts
            .iter()
            .find(|h| h.host == "dns.example")
            .expect("row");
        assert_eq!((row.up, row.down), (40, 120));
        assert_eq!((snap.dropped_datagrams, snap.dropped_bytes), (2, 47));
    }

    /// A failure that never named a destination counts, but creates no row.
    #[test]
    fn an_unattributable_failure_counts_without_creating_a_row() {
        let (telemetry, _events) = Telemetry::new(16);
        telemetry.failed(
            TraceKind::Tcp,
            UNKNOWN_HOST,
            TraceFailReason::Malformed,
            None,
        );
        let snap = telemetry.snapshot();
        assert!(snap.hosts.is_empty(), "no (unknown) row: {snap:?}");
        assert_eq!(snap.failed, 1);
    }

    /// A blocked destination marks its row with the outbound the route chose.
    #[test]
    fn a_blocked_failure_marks_the_host_and_carries_no_bytes() {
        let (telemetry, _events) = Telemetry::new(16);
        telemetry.failed(
            TraceKind::Http,
            "x.example:443",
            TraceFailReason::Blocked,
            Some("block"),
        );
        let snap = telemetry.snapshot();
        let row = snap
            .hosts
            .iter()
            .find(|h| h.host == "x.example")
            .expect("row");
        assert_eq!(row.outbound.as_deref(), Some("block"));
        assert_eq!((row.up, row.down, row.conns, row.failed), (0, 0, 0, 1));
        assert_eq!(snap.failed, 1);
    }

    /// A later leg's outbound replaces the marker; the close fold does not.
    #[test]
    fn the_marker_is_last_wins_across_legs() {
        let (telemetry, _events) = Telemetry::new(16);
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        for tag in ["direct", "proxy"] {
            let id = telemetry.opened(
                TraceKind::Tcp,
                "cdn.example:443",
                "vless",
                "tcp",
                TraceSecurity::Plain,
            );
            let mut guard = telemetry.guard(id, Arc::clone(&up), Arc::clone(&down), Some(tag));
            guard.finish(None);
        }
        assert_eq!(
            telemetry.snapshot().hosts[0].outbound.as_deref(),
            Some("proxy")
        );
    }

    #[test]
    fn the_host_table_evicts_the_least_recently_active_past_the_cap() {
        let (telemetry, _events) = Telemetry::new(16);
        for i in 0..=HOST_TABLE_CAP {
            telemetry.udp_sent(&format!("h{i}.example"), 1);
        }
        let snap = telemetry.snapshot();
        assert_eq!(snap.hosts.len(), HOST_TABLE_CAP);
        assert!(snap.hosts.iter().all(|h| h.host != "h0.example"));
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
        drop(tel.guard(conn_id, Arc::clone(&up), Arc::clone(&down), None));

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
        let mut guard = tel.guard(conn_id, Arc::clone(&up), Arc::clone(&down), None);
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
