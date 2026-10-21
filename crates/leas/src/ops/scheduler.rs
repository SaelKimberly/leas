//! The per-(protocol, endpoint) task gate (design §6.2): at most one live
//! task per link.
//!
//! It provides a FIFO queue of waiting task ids and DNS-failure deferral so
//! endpoints with recent DNS failures are skipped. This module is pure
//! scheduling state — it decides *which* task id may run; it never executes
//! tests itself. The caller (the T19 batch pipeline) fires the actual probe
//! with the id it gets back.
//!
//! Task state is **runtime state**: it lives in this scheduler and is never
//! written to the database. A task id is only meaningful inside the process
//! that allocated it (the registry it points into dies with the process), so
//! persisting it could only ever produce a phantom id for the next launch to
//! reconcile away. That is the whole reason this file no longer needs a
//! persistence seam: the gate's state and the registry that validates it are
//! one map, updated under one mutex, so an orphan id is unrepresentable.
//!
//! ## Fire-handshake (contract with T19)
//!
//! There is no `CoreEvent::TaskFired` variant, so the fire signal is the
//! [`ScheduleOutcome`] the gate returns:
//!
//! - [`TaskScheduler::schedule`] returns [`ScheduleOutcome::Started(id)`] /
//!   [`ScheduleOutcome::Queued(id)`] — the caller fires `Started` immediately.
//! - [`TaskScheduler::complete`] retires the caller's id and advances the gate
//!   to the first LIVE queued id (whole-vec replace). The caller asks
//!   [`TaskScheduler::task_of`] for the new id and dispatches it, or stops
//!   when it is `None`.
//! - The id the caller passes to [`TaskScheduler::complete`] is checked
//!   against the gate: a stale completion (the gate advanced while the probe
//!   ran) is ignored, so a link can never advance twice.
//!
//! ## Concurrency
//!
//! Every gate transition ([`TaskScheduler::schedule`], `complete`,
//! `cancel_queued`) holds one internal async mutex for the whole check-then-act.
//! Concurrent callers on the same link therefore observe each other's
//! transitions: at most one `Started` outcome per gate-open, and a stale
//! completion can never double-advance the gate.

use std::sync::atomic::{AtomicI64, AtomicU16, Ordering};

use dashmap::DashMap;
use jiff::Timestamp;
use leas_db::models::{EndpointId, ProfileStats, ProtocolId, TaskKind};
use tracing::{debug, warn};

/// Outcomes of [`TaskScheduler::schedule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleOutcome {
    /// The gate was open: `id` is now the link's current task — fire the
    /// probe now.
    Started(u16),
    /// A live task holds the gate: `id` is appended to the link's queue —
    /// wait for the current task to complete.
    Queued(u16),
    /// The queue is at its limit (or queueing is disabled, `queue_limit ==
    /// 0`): nothing changed, the caller should skip this link this round.
    QueueFull,
    /// The endpoint's DNS failed within `dns_defer_secs`: nothing changed,
    /// re-schedule after the deferral window.
    DnsDeferred,
}

/// One link's gate state: the live task id and the ids waiting behind it.
/// `0` is never a valid task id.
#[derive(Debug, Clone, Default)]
pub struct LinkTasks {
    /// The task currently holding the gate, if any.
    pub task_id: Option<u16>,
    /// FIFO of ids waiting for the gate (all registered in `tasks`).
    pub queue: Vec<u16>,
}

/// In-memory scheduler state: the live task registry plus per-endpoint DNS
/// failure timestamps. `0` is never a valid task id.
pub struct TaskScheduler {
    /// Live task registry: every id here is either the current task of some
    /// link or queued in some link's queue.
    tasks: DashMap<u16, TaskKind>,
    /// Per-link gate state. Entries are dropped when a link's gate clears, so
    /// the map tracks the links this process is actively testing rather than
    /// every link it has ever seen.
    states: DashMap<(ProtocolId, EndpointId), LinkTasks>,
    /// Next candidate id; wraps around, skipping `0` and live ids.
    next_id: AtomicU16,
    /// Max queued tasks per link; `0` disables queueing (busy -> skipped).
    /// Runtime-settable via [`Self::set_limits`] (config load / settings
    /// save); every `schedule` reads it fresh.
    queue_limit: AtomicU16,
    /// DNS-failure deferral window in seconds (`<= 0` disables deferral).
    /// Runtime-settable via [`Self::set_limits`]; the deferral checks read
    /// it fresh.
    dns_defer_secs: AtomicI64,
    /// Endpoints whose DNS failed recently, by last failure time.
    dns_failures: DashMap<EndpointId, Timestamp>,
    /// Endpoints with a resolution lookup IN FLIGHT, by start time.
    ///
    /// Separate from `dns_failures` because the two windows are different
    /// questions. A failure is answered for `dns_defer_secs`; a lookup is
    /// answered by the lookup itself, so it needs no window at all — only a
    /// record that it has not answered yet.
    ///
    /// This is what makes the deferral able to help the run that asked for the
    /// resolution. `dispatch_page` issues the request and schedules the link in
    /// the same loop iteration, and the resolver's own deadline is 8s, so a
    /// link dispatched at `t` could not consult a failure report that arrives
    /// at `t+8s` — the gate reported `deferred=0` against 196 DNS failures for
    /// exactly this reason.
    dns_pending: DashMap<EndpointId, Timestamp>,
    /// Serializes every gate transition ([`Self::schedule`], [`Self::complete`],
    /// [`Self::cancel_queued`]).
    ///
    /// The check-then-act re-reads the persisted link inside the critical
    /// section, so concurrent callers on the same link observe each other's
    /// writes — at most one `Started` per gate-open. Contention is bounded:
    /// `SQLite` is single-writer anyway, so this adds no serialization the DB
    /// would not impose.
    gate: tokio::sync::Mutex<()>,
}

/// Smallest DNS-failure deferral window that can outlast one resolution.
///
/// A window shorter than [`crate::ops::enrich::DNS_LOOKUP_TIMEOUT`] is
/// self-defeating: the stamp is written when the lookup REPORTS, so a window
/// that has already elapsed by then never defers anything. The two were
/// unrelated constants and the window was the shorter — the shipped 5s against
/// an 8s deadline — which is one reason the 2026-09-27 run reported
/// `deferred=0` against 196 DNS failures.
///
/// The rule belongs to the CONFIG, not to this type: [`TaskScheduler`] holds
/// whatever window it is given, because the batch tests construct one directly
/// with a short window on purpose and there is no resolver deadline to outlive
/// in a test. `AppState::new` applies the floor to the user's setting.
pub const MIN_DNS_DEFER_SECS: i64 = 15;

impl TaskScheduler {
    /// Create a scheduler with the given queue limit and DNS deferral window.
    #[must_use]
    pub fn new(queue_limit: u16, dns_defer_secs: i64) -> Self {
        Self {
            tasks: DashMap::new(),
            states: DashMap::new(),
            next_id: AtomicU16::new(0),
            queue_limit: AtomicU16::new(queue_limit),
            // The raw value: this type holds whatever window it is given, and
            // the "must outlast a resolution" rule is a property of the CONFIG,
            // enforced where the setting enters (see `state.rs`). Tests and
            // single-ping paths construct one directly with a short window on
            // purpose, and there is no lookup deadline to outlive in a test.
            dns_defer_secs: AtomicI64::new(dns_defer_secs),
            dns_failures: DashMap::new(),
            dns_pending: DashMap::new(),
            gate: tokio::sync::Mutex::new(()),
        }
    }

    /// Update the queue limit and DNS-deferral window at runtime. Applied on
    /// config load and settings save; the next `schedule`/deferral check
    /// reads the new values — no re-construction needed.
    pub fn set_limits(&self, queue_limit: u16, dns_defer_secs: i64) {
        self.queue_limit.store(queue_limit, Ordering::Relaxed);
        self.dns_defer_secs.store(dns_defer_secs, Ordering::Relaxed);
    }

    /// Clear any DNS-failure marker for `endpoint` (e.g. a resolution that
    /// just succeeded). No-op when no marker exists.
    pub fn clear_dns_failure(&self, endpoint: EndpointId) {
        self.dns_failures.remove(&endpoint);
    }

    /// Decide whether a new task for `link` may run now. See the module docs
    /// for the fire-handshake.
    ///
    /// The caller's `link` is only an identity (its `(protocol_id,
    /// endpoint_id)`); the decision reads the gate's own state under the
    /// mutex, so a stale snapshot cannot produce two `Started` outcomes on the
    /// same link.
    pub async fn schedule(&self, link: &ProfileStats, kind: TaskKind) -> ScheduleOutcome {
        // DNS resolution state FIRST — nothing is touched. No gate needed:
        // both maps are DashMaps and the check mutates nothing but expired
        // entries.
        if self.is_dns_unresolved(link.endpoint_id, Timestamp::now()) {
            return ScheduleOutcome::DnsDeferred;
        }

        let key = (link.protocol_id, link.endpoint_id);
        let _guard = self.gate.lock().await;
        let state = self.state_of(key);

        match state.task_id {
            // A live task holds the gate: queue if there is room (the limit is
            // read per-schedule so `set_limits` takes effect at once).
            Some(current) if self.tasks.contains_key(&current) => {
                let queue_limit = self.queue_limit.load(Ordering::Relaxed);
                if queue_limit == 0 || state.queue.len() >= usize::from(queue_limit) {
                    warn!(
                        target: "tui::scheduler",
                        "Cannot schedule {kind:?} on leas://{:x}: queue full",
                        link.protocol_id.get(),
                    );
                    return ScheduleOutcome::QueueFull;
                }
                let id = self.alloc_id();
                self.tasks.insert(id, kind);
                let mut queue = state.queue;
                queue.push(id);
                self.store(key, Some(current), queue);
                ScheduleOutcome::Queued(id)
            }
            // Gate open: allocate, register, fire. Any queue left over belongs
            // to a task this process no longer knows (impossible: the registry
            // and the queue are updated together), so it is dropped rather
            // than carried.
            _ => {
                let id = self.alloc_id();
                self.tasks.insert(id, kind);
                self.store(key, Some(id), Vec::new());
                ScheduleOutcome::Started(id)
            }
        }
    }

    /// Retire `id` as the current task of `link` and advance the gate.
    ///
    /// Only a completion whose `id` is the link's CURRENT task and whose
    /// `kind` matches the live registry entry is honored (race guard);
    /// anything else is stale and leaves the gate untouched.
    ///
    /// FIFO pop: the gate advances to the first queued id still registered; if
    /// nothing live remains, the gate clears and the link leaves the state
    /// map. The caller asks [`Self::task_of`] for the new id (see module
    /// docs).
    pub async fn complete(&self, link: &ProfileStats, id: u16, kind: TaskKind) {
        let key = (link.protocol_id, link.endpoint_id);
        let _guard = self.gate.lock().await;
        let mut state = self.state_of(key);
        // Stale completion: the gate advanced since the caller read it, so
        // this task is no longer current — do not advance the gate twice.
        if state.task_id != Some(id) {
            debug!(
                target: "tui::scheduler",
                "complete: stale snapshot on leas://{:x} (task {id} is not current: {:?}) — ignored",
                link.protocol_id.get(),
                state.task_id,
            );
            return;
        }
        if self.tasks.get(&id).map(|k| *k) != Some(kind) {
            debug!(
                target: "tui::scheduler",
                "complete: task {id} on leas://{:x} is not {kind:?} — stale completion ignored",
                link.protocol_id.get(),
            );
            return;
        }
        self.tasks.remove(&id);

        // Pop FIFO, skipping ids that are no longer registered (a cancel
        // removed them from the registry but the queue is rewritten whole).
        let mut queue = state.queue;
        let mut next = None;
        while !queue.is_empty() {
            let candidate = queue.remove(0);
            if self.tasks.contains_key(&candidate) {
                next = Some(candidate);
                break;
            }
        }
        state.task_id = next;
        state.queue = queue;
        if next.is_some() {
            self.states.insert(key, state);
        } else {
            // The gate is clear: nothing about this link is live any more.
            self.states.remove(&key);
        }
    }

    /// The link's current task id, as the gate sees it.
    #[must_use]
    pub fn task_of(&self, link: &ProfileStats) -> Option<u16> {
        self.state_of((link.protocol_id, link.endpoint_id)).task_id
    }

    /// Drop every link's gate state (called when a batch starts: nothing from
    /// a previous batch is live).
    pub fn reset(&self) {
        self.states.clear();
    }

    /// Kind of a registered task id. `None` for unregistered / orphan ids.
    ///
    /// The batch pipeline uses this to dispatch a promoted task after
    /// [`Self::complete`] advanced the gate: the fire-handshake contract says
    /// the caller re-reads the link and fires the new `task_id`, and it must
    /// know which kind of probe to run.
    #[must_use]
    pub fn kind_of(&self, id: u16) -> Option<TaskKind> {
        self.tasks.get(&id).map(|k| *k)
    }

    /// The current DNS-deferral window (seconds). The batch pipeline sleeps
    /// this long before re-scheduling a `DnsDeferred` link; the value is
    /// runtime-settable via [`Self::set_limits`].
    #[must_use]
    pub fn dns_defer_secs(&self) -> i64 {
        self.dns_defer_secs.load(Ordering::Relaxed)
    }

    /// Sibling cancel: drop every queued id whose registry entry is `kind`
    /// (other kinds are preserved). Writes the filtered queue back against the
    /// CURRENT gate state; skips the write when nothing matched.
    pub async fn cancel_queued(&self, link: &ProfileStats, kind: TaskKind) {
        let key = (link.protocol_id, link.endpoint_id);
        let _guard = self.gate.lock().await;
        let state = self.state_of(key);
        let mut kept = Vec::with_capacity(state.queue.len());
        let mut changed = false;
        for id in &state.queue {
            if self.tasks.get(id).map(|k| *k) == Some(kind) {
                self.tasks.remove(id);
                changed = true;
            } else {
                kept.push(*id);
            }
        }
        if !changed {
            return;
        }
        self.store(key, state.task_id, kept);
    }

    /// Record a DNS failure for `endpoint`, sweeping expired entries so the
    /// map stays bounded.
    pub fn mark_dns_failure(&self, endpoint: EndpointId) {
        let now = Timestamp::now();
        self.dns_failures.insert(endpoint, now);
        self.sweep_dns_failures(now);
    }

    /// The link's gate state (the default when this process has never touched
    /// it).
    fn state_of(&self, key: (ProtocolId, EndpointId)) -> LinkTasks {
        self.states.get(&key).map(|s| s.clone()).unwrap_or_default()
    }

    /// Write a link's gate state. The registry and the state map are only ever
    /// touched under `gate`, so they cannot disagree.
    fn store(&self, key: (ProtocolId, EndpointId), task_id: Option<u16>, queue: Vec<u16>) {
        self.states.insert(key, LinkTasks { task_id, queue });
    }

    /// Allocate a fresh task id: never `0`, never a live id, wrapping.
    fn alloc_id(&self) -> u16 {
        loop {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 && !self.tasks.contains_key(&id) {
                return id;
            }
        }
    }

    /// Record that a resolution lookup for `endpoint` has started, so a link
    /// dispatched alongside it waits for the answer instead of racing it.
    ///
    /// The counterpart is [`Self::end_dns_lookup`], called when the lookup
    /// finishes — which is also when [`Self::mark_dns_failure`] or
    /// [`Self::clear_dns_failure`] decides the endpoint's DNS state.
    pub fn begin_dns_lookup(&self, endpoint: EndpointId) {
        self.dns_pending.insert(endpoint, Timestamp::now());
    }

    /// Clear the in-flight marker: the lookup has answered.
    pub fn end_dns_lookup(&self, endpoint: EndpointId) {
        self.dns_pending.remove(&endpoint);
    }

    /// Whether `endpoint` cannot be probed yet: a lookup for it is in flight,
    /// or it failed inside the deferral window. Expired failure entries are
    /// dropped lazily. `dns_defer_secs <= 0` disables the FAILURE window only —
    /// an in-flight lookup still defers, because the answer is coming and
    /// probing before it lands can only measure the wrong thing.
    fn is_dns_unresolved(&self, endpoint: EndpointId, now: Timestamp) -> bool {
        if self.dns_pending.contains_key(&endpoint) {
            return true;
        }
        let defer_secs = self.dns_defer_secs.load(Ordering::Relaxed);
        if defer_secs <= 0 {
            return false;
        }
        let Some(entry) = self.dns_failures.get(&endpoint) else {
            return false;
        };
        if now.as_second() - entry.as_second() < defer_secs {
            return true;
        }
        drop(entry);
        self.dns_failures.remove(&endpoint);
        false
    }

    /// A stamp that changes whenever this endpoint's DNS-deferral state is
    /// RE-ARMED — a lookup starts, or a fresh failure window opens.
    ///
    /// `defer_retry`'s budget is a wall clock from its first deferral, while
    /// the state it waits on is re-armed at report time. A stamp lets the retry
    /// restart that clock when the state moves, so a host that fails twice
    /// inside one batch is not booked unprobed by a clock that started before
    /// the second failure existed. `None` when the endpoint carries no DNS
    /// state at all (not deferred by DNS).
    pub fn dns_state_stamp(&self, endpoint: EndpointId) -> Option<i64> {
        if let Some(pending) = self.dns_pending.get(&endpoint) {
            return Some(pending.as_second());
        }
        self.dns_failures
            .get(&endpoint)
            .map(|entry| entry.as_second())
    }

    /// Drop all DNS-failure entries older than the deferral window.
    fn sweep_dns_failures(&self, now: Timestamp) {
        let defer_secs = self.dns_defer_secs.load(Ordering::Relaxed);
        if defer_secs <= 0 {
            self.dns_failures.clear();
            return;
        }
        self.dns_failures
            .retain(|_, ts| now.as_second() - ts.as_second() < defer_secs);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use leas_db::models::{EndpointId, Latency, ProfileStats, ProtocolId, TaskKind, TrafficStats};
    use toasty::Deferred;

    use super::MIN_DNS_DEFER_SECS;

    use super::{ScheduleOutcome, TaskScheduler};

    /// Epoch seconds — the storage unit of every timestamp column.
    fn ts(secs: i64) -> i64 {
        secs
    }

    fn link(pid: i64, eid: i64) -> ProfileStats {
        ProfileStats {
            protocol_id: ProtocolId::new(pid),
            endpoint_id: EndpointId::new(eid),
            last_used_at: None,
            last_seen_at: ts(0),
            latency: Latency::default(),
            speed_bps: None,
            error: None,
            purge_reason: None,
            stab_mask: 0,
            stab_len: 0,
            traffic: TrafficStats {
                today_up: 0,
                today_down: 0,
                total_up: 0,
                total_down: 0,
            },
            created_at: ts(0),
            updated_at: ts(0),
            version: 1,
            protocol: Deferred::default(),
            endpoint: Deferred::default(),
        }
    }

    fn sched() -> TaskScheduler {
        TaskScheduler::new(3, 5)
    }

    // ── gate ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn gate_none_starts_live_queue() {
        let s = sched();
        let l = link(1, 10);

        // None -> Started, and the gate now names that id.
        let id = match s.schedule(&l, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => id,
            other => panic!("expected Started, got {other:?}"),
        };
        assert_eq!(s.task_of(&l), Some(id));
        assert_eq!(s.kind_of(id), Some(TaskKind::FastPing));
    }

    #[tokio::test]
    async fn gate_queue_limit_full() {
        let s = sched();
        let l = link(1, 10);
        let first = match s.schedule(&l, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => id,
            other => panic!("expected Started, got {other:?}"),
        };
        // Fill the queue (limit 3).
        for _ in 0..3 {
            assert!(matches!(
                s.schedule(&l, TaskKind::FastPing).await,
                ScheduleOutcome::Queued(_)
            ));
        }
        // The fourth is refused and the gate is untouched.
        assert_eq!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::QueueFull
        );
        assert_eq!(s.task_of(&l), Some(first));
    }

    #[tokio::test]
    async fn concurrent_schedule_same_link_single_winner() {
        // The check-then-act is one critical section: only one caller may see
        // an open gate, whatever the interleaving.
        let s = Arc::new(sched());
        let l = Arc::new(link(1, 10));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&s);
            let l = Arc::clone(&l);
            handles.push(tokio::spawn(async move {
                s.schedule(&l, TaskKind::FastPing).await
            }));
        }
        let mut outcomes = Vec::new();
        for h in handles {
            outcomes.push(h.await.expect("join"));
        }
        let started = outcomes
            .iter()
            .filter(|o| matches!(o, ScheduleOutcome::Started(_)))
            .count();
        let queued = outcomes
            .iter()
            .filter(|o| matches!(o, ScheduleOutcome::Queued(_)))
            .count();
        let full = outcomes
            .iter()
            .filter(|o| **o == ScheduleOutcome::QueueFull)
            .count();
        assert_eq!(started, 1, "exactly one caller starts the link");
        assert_eq!(queued, 3, "the rest fill the queue");
        assert_eq!(full, 4, "and the overflow is refused");
    }

    #[tokio::test]
    async fn gate_state_is_per_link() {
        let s = sched();
        let a = link(1, 10);
        let b = link(2, 10);
        let id_a = match s.schedule(&a, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => id,
            other => panic!("expected Started, got {other:?}"),
        };
        // A different protocol on the same endpoint is a different link.
        assert!(matches!(
            s.schedule(&b, TaskKind::FastPing).await,
            ScheduleOutcome::Started(_)
        ));
        assert_eq!(s.task_of(&a), Some(id_a));
    }

    // ── complete ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn complete_pops_fifo() {
        let s = sched();
        let l = link(1, 10);
        let first = match s.schedule(&l, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => id,
            other => panic!("expected Started, got {other:?}"),
        };
        let second = match s.schedule(&l, TaskKind::RealPing).await {
            ScheduleOutcome::Queued(id) => id,
            other => panic!("expected Queued, got {other:?}"),
        };

        s.complete(&l, first, TaskKind::FastPing).await;
        assert_eq!(s.task_of(&l), Some(second), "the queued task is promoted");
        assert_eq!(s.kind_of(second), Some(TaskKind::RealPing));
        assert_eq!(s.kind_of(first), None, "the retired id is unregistered");
    }

    #[tokio::test]
    async fn complete_empty_queue_clears_the_link() {
        let s = sched();
        let l = link(1, 10);
        let id = match s.schedule(&l, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => id,
            other => panic!("expected Started, got {other:?}"),
        };
        s.complete(&l, id, TaskKind::FastPing).await;
        assert_eq!(s.task_of(&l), None, "gate clear");
        // And a fresh schedule starts again.
        assert!(matches!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::Started(_)
        ));
    }

    #[tokio::test]
    async fn complete_stale_snapshot_is_ignored() {
        let s = sched();
        let l = link(1, 10);
        let first = match s.schedule(&l, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => id,
            other => panic!("expected Started, got {other:?}"),
        };
        let second = match s.schedule(&l, TaskKind::RealPing).await {
            ScheduleOutcome::Queued(id) => id,
            other => panic!("expected Queued, got {other:?}"),
        };
        // The promotion already happened: completing the OLD id again must not
        // advance the gate a second time.
        s.complete(&l, first, TaskKind::FastPing).await;
        s.complete(&l, first, TaskKind::FastPing).await;
        assert_eq!(s.task_of(&l), Some(second));
    }

    #[tokio::test]
    async fn complete_kind_mismatch_is_stale_noop() {
        let s = sched();
        let l = link(1, 10);
        let id = match s.schedule(&l, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => id,
            other => panic!("expected Started, got {other:?}"),
        };
        // A completion claiming the wrong kind does not retire the task.
        s.complete(&l, id, TaskKind::RealPing).await;
        assert_eq!(s.task_of(&l), Some(id));
        assert_eq!(s.kind_of(id), Some(TaskKind::FastPing));
    }

    // ── cancel ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn cancel_queued_filters_kind_only() {
        let s = sched();
        let l = link(1, 10);
        let _live = match s.schedule(&l, TaskKind::FastPing).await {
            ScheduleOutcome::Started(id) => id,
            other => panic!("expected Started, got {other:?}"),
        };
        let fast = match s.schedule(&l, TaskKind::FastPing).await {
            ScheduleOutcome::Queued(id) => id,
            other => panic!("expected Queued, got {other:?}"),
        };
        let real = match s.schedule(&l, TaskKind::RealPing).await {
            ScheduleOutcome::Queued(id) => id,
            other => panic!("expected Queued, got {other:?}"),
        };

        s.cancel_queued(&l, TaskKind::FastPing).await;
        assert_eq!(s.kind_of(fast), None, "the queued fast task is gone");
        assert_eq!(
            s.kind_of(real),
            Some(TaskKind::RealPing),
            "other kinds stay"
        );

        // Completing the live task promotes the surviving real task.
        let Some(first) = s.task_of(&l) else {
            panic!("gate should still hold a task");
        };
        s.complete(&l, first, TaskKind::FastPing).await;
        assert_eq!(s.task_of(&l), Some(real));
    }

    // ── DNS deferral ───────────────────────────────────────────────────

    #[tokio::test]
    async fn dns_failure_defers_then_expires() {
        let s = TaskScheduler::new(3, 5);
        let l = link(1, 10);
        s.mark_dns_failure(l.endpoint_id);
        assert_eq!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::DnsDeferred
        );
        // A successful resolution clears the marker.
        s.clear_dns_failure(l.endpoint_id);
        assert!(matches!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::Started(_)
        ));
    }

    /// A link dispatched in the same breath as its resolution request must
    /// wait for the answer. This is the arm the 2026-09-27 run never reached:
    /// the request travelled a bounded channel to the UI task, so every link
    /// was scheduled first and the failure that would justify a deferral
    /// arrived 8s later — `deferred=0` against 196 DNS failures.
    #[tokio::test]
    async fn an_in_flight_lookup_defers_before_any_failure_is_known() {
        let s = TaskScheduler::new(3, 0);
        let l = link(1, 10);
        // No failure recorded: the resolver has not answered yet.
        s.begin_dns_lookup(l.endpoint_id);
        assert_eq!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::DnsDeferred
        );
        // The lookup answers; the link runs.
        s.end_dns_lookup(l.endpoint_id);
        assert!(matches!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::Started(_)
        ));
    }

    /// An in-flight lookup defers even with the failure window switched off:
    /// `dns_failure_defer_secs = 0` is a policy about REPEATED failures, not
    /// permission to probe a host whose answer is still outstanding.
    #[tokio::test]
    async fn an_in_flight_lookup_defers_with_deferral_disabled() {
        let s = TaskScheduler::new(3, 0);
        let l = link(1, 10);
        s.begin_dns_lookup(l.endpoint_id);
        assert_eq!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::DnsDeferred
        );
    }

    /// A marker belongs to one endpoint and cannot leak onto a sibling.
    #[tokio::test]
    async fn a_lookup_marker_is_scoped_to_its_endpoint() {
        let s = TaskScheduler::new(3, 0);
        let marked = link(1, 10);
        let other = link(2, 11);
        s.begin_dns_lookup(marked.endpoint_id);
        assert_eq!(
            s.schedule(&marked, TaskKind::FastPing).await,
            ScheduleOutcome::DnsDeferred
        );
        assert!(matches!(
            s.schedule(&other, TaskKind::FastPing).await,
            ScheduleOutcome::Started(_)
        ));
    }

    /// The scheduler holds whatever window it is given — the "must outlast a
    /// resolution" rule is enforced on the user's setting, where it belongs.
    /// This is what lets the batch tests below run a 2s window in a second
    /// instead of the configured floor.
    #[test]
    fn the_scheduler_takes_the_window_it_is_given() {
        assert_eq!(TaskScheduler::new(3, 2).dns_defer_secs(), 2);
        assert_eq!(TaskScheduler::new(3, 0).dns_defer_secs(), 0);
    }

    /// The floor the config boundary applies has to outlast the deadline it
    /// exists to protect — this is the invariant that was inverted (5s against
    /// 8s) when the 2026-09-27 run reported `deferred=0` against 196 failures.
    #[test]
    fn the_configured_floor_outlasts_one_resolution() {
        assert!(
            MIN_DNS_DEFER_SECS > crate::ops::enrich::DNS_LOOKUP_TIMEOUT.as_secs() as i64,
            "deferral floor {MIN_DNS_DEFER_SECS} must exceed the resolver deadline"
        );
    }

    /// The shipped default and the floor the config boundary enforces are two
    /// literals in two crates, and drift between them is silent — a default
    /// under the floor would mean every fresh install re-clamps and re-warns on
    /// first run.
    #[test]
    fn the_shipped_default_clears_the_floor() {
        let default = leas_config::app_config::SpeedTestConfig::default().dns_failure_defer_secs;
        assert!(
            default >= MIN_DNS_DEFER_SECS,
            "default {default} sits below the enforced floor {MIN_DNS_DEFER_SECS}"
        );
    }

    #[tokio::test]
    async fn dns_defer_secs_zero_disables_deferral() {
        let s = TaskScheduler::new(3, 0);
        let l = link(1, 10);
        s.mark_dns_failure(l.endpoint_id);
        assert!(matches!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::Started(_)
        ));
    }

    #[tokio::test]
    async fn set_limits_takes_effect_on_the_next_schedule() {
        let s = TaskScheduler::new(0, 5);
        let l = link(1, 10);
        assert!(matches!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::Started(_)
        ));
        // limit 0 = queueing disabled.
        assert_eq!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::QueueFull
        );
        // Raising the limit enables queueing without re-construction.
        s.set_limits(2, 5);
        assert!(matches!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::Queued(_)
        ));
    }

    #[tokio::test]
    async fn set_limits_changes_the_dns_window() {
        let s = TaskScheduler::new(3, 0);
        let l = link(1, 10);
        s.mark_dns_failure(l.endpoint_id);
        assert!(matches!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::Started(_)
        ));
        s.set_limits(3, 60);
        s.mark_dns_failure(l.endpoint_id);
        assert_eq!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::DnsDeferred
        );
    }

    /// A batch starts from a clean gate: nothing from a previous batch (or a
    /// previous process) can be considered live.
    #[tokio::test]
    async fn reset_drops_every_gate() {
        let s = sched();
        let l = link(1, 10);
        assert!(matches!(
            s.schedule(&l, TaskKind::FastPing).await,
            ScheduleOutcome::Started(_)
        ));
        s.reset();
        assert_eq!(s.task_of(&l), None);
    }
}
