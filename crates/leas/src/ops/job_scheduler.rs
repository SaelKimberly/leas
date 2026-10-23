//! The job scheduler: the **only** entry point for any long-running task.
//!
//! One queue, one running task, one paused flag. The UI enqueues; the event
//! loop drains. "One job at a time" is structural — there is no path that
//! starts a job outside [`enqueue`].
//!
//! Distinct from [`crate::ops::scheduler`], which is the PER-LINK ping gate
//! (`TaskScheduler`): that one decides whether a single link's probe may start
//! now, queued or deferred. This one decides which COMMAND runs, in order.
//!
//! The queue is a value type, not a handle: a `TaskSpec` freezes its
//! parameters at enqueue time (the selected endpoint, the scope), so a queued
//! task is unambiguous and re-enqueueing the same identity is a no-op.
//!
//! Design: spec `2026-10-22-details-metrics-tasks-design.md` §14.


use leas_db::models::PurgatoryView;
use leas_db::profiles_query::{PageRequest, PageSort, PlanScope};

use crate::AppState;

/// The kinds of job the scheduler can run. Each maps to one spawn path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    /// `Fast Test (All Profiles)` / `Fast Test (Selected)`.
    FastTest,
    /// `Real Test (All Profiles)` and every scoped variant.
    RealTest,
    /// `Speed Test (Selected)`.
    SpeedTest,
    /// `UDP Test (Selected)`.
    UdpTest,
    /// `Fill Exit IPs (Successful)`.
    FillExitIps,
    /// `Retry Failed DNS Lookups`.
    DnsRetry,
    /// `Compact Duplicate Endpoints`.
    Compact,
    /// `Fast Test (Selected)` over a MULTI-selection — every link of the
    /// selected endpoints. Distinct from [`TaskKind::FastTest`] so a
    /// multi-selection never dedups against the feed-wide batch.
    MultiFastTest,
    /// `Real Test (Selected)` over a multi-selection.
    MultiRealTest,
}

/// One queued task. A **value**: the parameters are frozen at enqueue time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSpec {
    pub kind: TaskKind,
    /// The plan scope for the batched variants. [`PlanScope::All`] for the
    /// `All Profiles` variants and for the non-probe jobs.
    pub scope: PlanScope,
    /// The selected endpoint for the `Selected` variants — `(endpoint_id,
    /// protocol_id)`. `None` for batched tasks.
    pub endpoint: Option<(i64, i64)>,
    /// The menu's own label, so the Tasks pane and the log read naturally.
    pub label: String,
}

impl TaskSpec {
    /// The dedup identity. Two specs with the same identity are the SAME task.
    ///
    /// `endpoint` participates: two different rows are two different tasks, so
    /// a per-row test never dedups against another row's.
    #[must_use]
    pub const fn identity(&self) -> (TaskKind, PlanScope, Option<(i64, i64)>) {
        (self.kind, self.scope, self.endpoint)
    }
}

/// Whether the scheduler is busy — the gate for the destructive one-shots.
///
/// `Remove Bad Servers` and `Clear All Stats` are disabled while anything is
/// running, queued, or the scheduler is paused (spec D45).
#[must_use]
pub fn is_busy(state: &AppState) -> bool {
    state.running_task.is_some() || !state.task_queue.is_empty() || state.scheduler_paused
}

/// Enqueue a task. A duplicate identity (queued or running) is ignored with a
/// log line — the queue never holds the same task twice, and a running task is
/// never re-armed.
pub fn enqueue(state: &mut AppState, spec: TaskSpec) {
    let identity = spec.identity();
    let duplicate = state.task_queue.iter().any(|queued| queued.identity() == identity)
        || state
            .running_task
            .as_ref()
            .is_some_and(|running| running.identity() == identity);
    if duplicate {
        state.log_trace(
            "info",
            "tui::ops::job_scheduler",
            &format!("task ignored — already queued or running: {}", spec.label),
        );
        return;
    }
    state.log_trace(
        "info",
        "tui::ops::job_scheduler",
        &format!("task queued: {}", spec.label),
    );
    state.task_queue.push_back(spec);
}

/// Cancel the running task and **pause** the queue (spec D40).
///
/// A stop is a pause, not a reset: the queue's contents survive for [`resume`].
pub fn stop(state: &mut AppState) {
    state.scheduler_paused = true;
    state
        .speed_test_stop
        .store(true, std::sync::atomic::Ordering::Relaxed);
    state.log_trace("info", "tui::ops::job_scheduler", "scheduler stopped (queue paused)");
}

/// Resume draining a paused queue (spec D40).
pub fn resume(state: &mut AppState) {
    state.scheduler_paused = false;
    state
        .speed_test_stop
        .store(false, std::sync::atomic::Ordering::Relaxed);
    state.log_trace("info", "tui::ops::job_scheduler", "scheduler resumed");
}

/// Delete a queued task by index (the Tasks pane's `d`).
///
/// No confirmation: it is a reversible queue edit (the task can be re-scheduled
/// from the menu), and a log line makes the removal visible (spec D39).
pub fn remove_queued(state: &mut AppState, index: usize) {
    let Some(removed) = state.task_queue.remove(index) else {
        return;
    };
    state.log_trace(
        "info",
        "tui::ops::job_scheduler",
        &format!("task removed from queue: {}", removed.label),
    );
}

/// Drain the queue: start the head if nothing is running and the scheduler is
/// not paused.
///
/// A head whose scope is now empty is **skipped** with a log line (spec D42) —
/// the scope was valid at enqueue time, but a queued `Real Test (New)` can be
/// pointless by the time it runs. A skipped head is dropped and the drain
/// continues to the next task.
pub async fn drain(state: &mut AppState) {
    loop {
        if state.running_task.is_some() || state.scheduler_paused {
            return;
        }
        let Some(spec) = state.task_queue.pop_front() else {
            return;
        };

        if scope_is_empty(state, &spec).await {
            state.log_trace(
                "info",
                "tui::ops::job_scheduler",
                &format!("task skipped — nothing to do: {}", spec.label),
            );
            continue; // the next head may still have work
        }

        // The probe spawns insert exactly one pair into `testing_profiles`; a
        // silent refusal leaves the length unchanged. Snapshot it so the
        // signal cannot be fooled by a pair that was already there.
        let testing_before = state.testing_profiles.len();
        state.running_task = Some(spec.clone());
        dispatch(state, &spec);
        if !started(state, &spec, testing_before) {
            // The spawn refused — its own guard saw the target already being
            // tested (`ping.rs:121`). Dropping the head here is what keeps the
            // scheduler from hanging: `running_task` would otherwise never
            // clear, because no terminal event is coming for a task that never
            // started.
            state.running_task = None;
            state.log_trace(
                "warn",
                "tui::ops::job_scheduler",
                &format!("task skipped — target already being tested: {}", spec.label),
            );
            continue;
        }
        return; // a task started; the queue waits for its terminal event
    }
}

/// Whether the spawn actually took effect.
///
/// Every spawn sets a progress slot; a silent return (the per-link guards)
/// leaves them all clear. Read the slot the task's own kind sets.
fn started(state: &AppState, spec: &TaskSpec, testing_before: usize) -> bool {
    let single_probe = matches!(
        spec.kind,
        TaskKind::FastTest | TaskKind::RealTest | TaskKind::SpeedTest | TaskKind::UdpTest
    );
    if single_probe && spec.endpoint.is_some() {
        // The spawn inserted the pair: the set grew.
        return state.testing_profiles.len() > testing_before;
    }
    match spec.kind {
        TaskKind::FastTest
        | TaskKind::RealTest
        | TaskKind::MultiFastTest
        | TaskKind::MultiRealTest => state.batch_progress.is_some(),
        TaskKind::SpeedTest | TaskKind::UdpTest => {
            // A Selected speed/UDP task with no endpoint cannot start.
            spec.endpoint.is_some()
        }
        TaskKind::FillExitIps => state.fill_progress.is_some(),
        TaskKind::Compact | TaskKind::DnsRetry => state.maint_progress.is_some(),
    }
}

/// Whether a task's scope has nothing left to work on.
async fn scope_is_empty(state: &AppState, spec: &TaskSpec) -> bool {
    // The Selected variants and the non-probe jobs have no plan scope to go
    // stale: a selected endpoint is a concrete target, and Compact/DNS-retry
    // derive their own work from the table.
    if spec.endpoint.is_some() || matches!(spec.kind, TaskKind::DnsRetry | TaskKind::Compact) {
        return false;
    }
    let req = PageRequest {
        view: PurgatoryView::All,
        active_threshold: 0,
        search: None,
        group_id: None,
        scope: spec.scope,
        sort: PageSort::Test,
        ascending: true,
        offset: 0,
        limit: 1,
    };
    match state.db.profiles_page(&req).await {
        Ok(meta) => meta.total == 0,
        Err(_) => false, // an unreadable scope is not an empty one
    }
}

/// Start a task. The scheduler's ONLY path into the spawn functions.
fn dispatch(state: &mut AppState, spec: &TaskSpec) {
    match spec.kind {
        TaskKind::FastTest => match spec.endpoint {
            Some((ep, proto)) => state.start_tcp_ping(ep, proto),
            None => state.start_batch_ping(),
        },
        TaskKind::RealTest => match spec.endpoint {
            Some((ep, proto)) => state.start_real_ping(ep, proto),
            None => match spec.scope {
                PlanScope::All => state.start_batch_then_real_ping(),
                scope => state.start_batch_then_real_ping_scoped(scope),
            },
        },
        TaskKind::SpeedTest => {
            if let Some((ep, proto)) = spec.endpoint {
                state.start_speed_test(ep, proto);
            }
        }
        TaskKind::UdpTest => {
            if let Some((ep, proto)) = spec.endpoint {
                state.start_udp_test(ep, proto);
            }
        }
        TaskKind::FillExitIps => state.start_fill_exit_ips(spec.scope),
        TaskKind::DnsRetry => state.retry_failed_dns(),
        TaskKind::Compact => state.compact_duplicate_endpoints(),
        TaskKind::MultiFastTest => state.start_endpoint_batch_ping(),
        TaskKind::MultiRealTest => state.start_endpoint_batch_real_ping(),
    }
}

/// The terminal events the scheduler observes.
///
/// The batch and the `Fill Exit IPs` command share `CoreEvent::BatchEnded`
/// (`ops/events.rs:1118-1130`), so the event alone does not name the task —
/// the running task's kind must be one the event can end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalEvent {
    BatchEnded,
    CompactFinished,
    MaintenanceDone,
}

/// The task kinds each terminal event can end.
const fn expected_kinds(event: TerminalEvent) -> &'static [TaskKind] {
    match event {
        TerminalEvent::BatchEnded => &[
            TaskKind::FastTest,
            TaskKind::RealTest,
            TaskKind::SpeedTest,
            TaskKind::UdpTest,
            TaskKind::FillExitIps,
            TaskKind::MultiFastTest,
            TaskKind::MultiRealTest,
        ],
        TerminalEvent::CompactFinished => &[TaskKind::Compact],
        TerminalEvent::MaintenanceDone => &[TaskKind::DnsRetry],
    }
}

/// A task ended. The running task's kind must be one this event can end;
/// otherwise it is a **stray event** — logged, and the running task is left
/// untouched (spec D43).
///
/// The meter clearing stays in the event handler (`ops/events.rs`): it is
/// per-event and shared between the batch and the fill, and clearing it here
/// on a stray event would leave the status bar stuck. The scheduler owns the
/// QUEUE — the running task, the history, and the drain.
pub fn handle_terminal(state: &mut AppState, event: TerminalEvent) {
    let Some(running) = state.running_task.take() else {
        state.log_trace(
            "warn",
            "tui::ops::job_scheduler",
            &format!("stray {event:?} — nothing running"),
        );
        return;
    };
    if !expected_kinds(event).contains(&running.kind) {
        state.running_task = Some(running);
        state.log_trace(
            "warn",
            "tui::ops::job_scheduler",
            &format!("stray {event:?} while a task is running"),
        );
        return;
    }
    state.log_trace(
        "info",
        "tui::ops::job_scheduler",
        &format!("task finished: {}", running.label),
    );
    state.task_history.push(running);
    // The counts changed: the next tick refreshes the cache (spec D21).
    state.aggregates_dirty.set(true);
}

/// Discard the queue on quit, logging each task that never ran (spec D48).
pub fn discard_queue_on_quit(state: &mut AppState) {
    // Take the queue first: `drain` borrows it for the loop, and the log call
    // needs all of `state` — holding both is a double mutable borrow.
    let queued = std::mem::take(&mut state.task_queue);
    for task in queued {
        state.log_trace(
            "info",
            "tui::ops::job_scheduler",
            &format!("task cancelled — never ran: {}", task.label),
        );
    }
    state.running_task = None;
    state.scheduler_paused = false;
}


#[cfg(test)]
mod tests {
    use super::*;
    use leas_db::profiles_query::PlanScope;

    fn spec(kind: TaskKind, scope: PlanScope, label: &str) -> TaskSpec {
        TaskSpec {
            kind,
            scope,
            endpoint: None,
            label: label.to_string(),
        }
    }

    fn selected(kind: TaskKind, label: &str) -> TaskSpec {
        TaskSpec {
            kind,
            scope: PlanScope::All,
            endpoint: Some((1, 2)),
            label: label.to_string(),
        }
    }

    async fn sched_state() -> AppState {
        crate::ops::profiles::test_support::test_state(Vec::new()).await
    }

    /// A duplicate identity — queued OR running — is ignored. The queue never
    /// holds the same task twice (spec D33).
    #[tokio::test]
    async fn enqueue_ignores_a_duplicate_identity() {
        let mut state = sched_state().await;
        enqueue(&mut state, spec(TaskKind::RealTest, PlanScope::New, "Real Test (New)"));
        assert_eq!(state.task_queue.len(), 1, "the first enqueue lands");

        enqueue(&mut state, spec(TaskKind::RealTest, PlanScope::New, "Real Test (New)"));
        assert_eq!(state.task_queue.len(), 1, "a queued duplicate is ignored");

        // A DIFFERENT scope is a different task — it must not be deduped.
        enqueue(&mut state, spec(TaskKind::RealTest, PlanScope::Failed, "Real Test (Failed)"));
        assert_eq!(state.task_queue.len(), 2, "a different scope is a distinct task");
    }

    /// A running task is never re-armed (spec D33).
    #[tokio::test]
    async fn enqueue_ignores_a_task_that_is_already_running() {
        let mut state = sched_state().await;
        let running = spec(TaskKind::RealTest, PlanScope::Successful, "Real Test (Successful)");
        state.running_task = Some(running.clone());

        enqueue(&mut state, running);
        assert_eq!(
            state.task_queue.len(),
            0,
            "a running duplicate must not re-queue"
        );
        assert!(state.running_task.is_some(), "the running task is untouched");
    }

    /// Two different rows are two different tasks — the endpoint is part of the
    /// identity, so a per-row test never dedups against another row's (D32).
    #[tokio::test]
    async fn enqueue_distinguishes_two_selected_endpoints() {
        let mut state = sched_state().await;
        enqueue(&mut state, selected(TaskKind::FastTest, "Fast Test (Selected)"));
        let mut other = selected(TaskKind::FastTest, "Fast Test (Selected)");
        other.endpoint = Some((3, 4));
        enqueue(&mut state, other);
        assert_eq!(state.task_queue.len(), 2, "different endpoints are different tasks");
    }

    /// `d` removes a queued task by index (spec D39).
    #[tokio::test]
    async fn remove_queued_deletes_by_index() {
        let mut state = sched_state().await;
        enqueue(&mut state, spec(TaskKind::RealTest, PlanScope::New, "first"));
        enqueue(&mut state, spec(TaskKind::RealTest, PlanScope::Failed, "second"));

        remove_queued(&mut state, 0);
        assert_eq!(state.task_queue.len(), 1);
        assert_eq!(state.task_queue[0].label, "second");

        // Out of range is a no-op.
        remove_queued(&mut state, 9);
        assert_eq!(state.task_queue.len(), 1);
    }

    /// The busy predicate gates the destructive one-shots (spec D45).
    #[tokio::test]
    async fn is_busy_covers_running_queued_and_paused() {
        let mut state = sched_state().await;
        assert!(!is_busy(&state), "idle is not busy");

        enqueue(&mut state, spec(TaskKind::RealTest, PlanScope::New, "queued"));
        assert!(is_busy(&state), "a queued task makes the scheduler busy");

        state.task_queue.clear();
        state.running_task = Some(spec(TaskKind::RealTest, PlanScope::New, "running"));
        assert!(is_busy(&state), "a running task makes the scheduler busy");

        state.running_task = None;
        state.scheduler_paused = true;
        assert!(is_busy(&state), "a paused scheduler is still busy");
    }

    /// A head whose scope is empty is SKIPPED and the drain moves on (D42).
    ///
    /// The test DB is empty, so a scoped task has nothing to work on.
    #[tokio::test]
    async fn drain_skips_a_stale_scope_and_keeps_the_scheduler_idle() {
        let mut state = sched_state().await;
        enqueue(&mut state, spec(TaskKind::RealTest, PlanScope::New, "Real Test (New)"));

        drain(&mut state).await;
        assert!(
            state.task_queue.is_empty(),
            "the skipped head is dropped, not re-queued"
        );
        assert!(
            state.running_task.is_none(),
            "an empty scope starts nothing"
        );
    }

    /// A paused scheduler drains nothing (D40).
    #[tokio::test]
    async fn drain_does_nothing_while_paused() {
        let mut state = sched_state().await;
        enqueue(&mut state, spec(TaskKind::RealTest, PlanScope::New, "queued"));
        stop(&mut state);

        drain(&mut state).await;
        assert_eq!(state.task_queue.len(), 1, "the queue survives the pause");
        assert!(state.running_task.is_none());

        resume(&mut state);
        assert!(!state.scheduler_paused);
    }

    /// The terminal event is matched to the running task: a match finishes it,
    /// a mismatch is a stray event that clears nothing (D43).
    #[tokio::test]
    async fn terminal_events_match_the_running_task() {
        let mut state = sched_state().await;

        // Nothing running: a stray event.
        handle_terminal(&mut state, TerminalEvent::BatchEnded);
        assert!(state.task_history.is_empty(), "a stray event records nothing");

        // A match finishes the task.
        let running = spec(TaskKind::RealTest, PlanScope::New, "Real Test (New)");
        state.running_task = Some(running);
        handle_terminal(&mut state, TerminalEvent::BatchEnded);
        assert!(state.running_task.is_none(), "the match clears the running task");
        assert_eq!(state.task_history.len(), 1, "the match records the outcome");
        assert_eq!(state.task_history[0].label, "Real Test (New)");

        // A mismatch is a stray event: the running task is untouched. A batch
        // event cannot end a Compact — the two are different jobs.
        let running = spec(TaskKind::Compact, PlanScope::All, "Compact");
        state.running_task = Some(running);
        handle_terminal(&mut state, TerminalEvent::BatchEnded);
        assert!(
            state.running_task.is_some(),
            "a batch event must not clear a Compact's state"
        );
        assert_eq!(state.task_history.len(), 1, "a mismatch records nothing");

        // A Compact's own event finishes it.
        handle_terminal(&mut state, TerminalEvent::CompactFinished);
        assert!(state.running_task.is_none());
        assert_eq!(state.task_history.len(), 2);
    }

    /// Quitting cancels the running task and discards the queue (D48).
    #[tokio::test]
    async fn discard_queue_on_quit_empties_everything() {
        let mut state = sched_state().await;
        enqueue(&mut state, spec(TaskKind::RealTest, PlanScope::New, "queued"));
        state.running_task = Some(spec(TaskKind::Compact, PlanScope::All, "Compact"));
        state.scheduler_paused = true;

        discard_queue_on_quit(&mut state);
        assert!(state.task_queue.is_empty());
        assert!(state.running_task.is_none());
        assert!(!state.scheduler_paused);
    }

    /// A Selected task whose target is already being tested must NOT hang the
    /// scheduler.
    ///
    /// `start_tcp_ping` silently returns when the pair is already in
    /// `testing_profiles` (`ping.rs:121`). Before the `started` check, the
    /// scheduler would keep `running_task` set forever — no terminal event is
    /// coming for a task that never started — so the queue would never drain
    /// and the destructive one-shots would stay disabled.
    #[tokio::test]
    async fn a_refused_spawn_does_not_hang_the_scheduler() {
        let mut state = sched_state().await;
        // The target is already being tested, so `start_tcp_ping` will refuse.
        state.testing_profiles.insert((7, 9));

        let target = TaskSpec {
            kind: TaskKind::FastTest,
            scope: PlanScope::All,
            endpoint: Some((7, 9)),
            label: "Fast Test (Selected)".to_string(),
        };
        enqueue(&mut state, target);
        // A SECOND task behind it, to prove the drain moves past the refusal.
        enqueue(
            &mut state,
            spec(TaskKind::RealTest, PlanScope::New, "Real Test (New)"),
        );

        drain(&mut state).await;

        assert!(
            state.running_task.is_none(),
            "the refused head is dropped, not left running forever"
        );
        assert!(
            state.task_queue.is_empty(),
            "the drain continued past the refusal to the next head"
        );
    }

    /// A multi-selection over an endpoint with no testable links must not hang
    /// either: `start_batch` returns early on an empty `PlanSource::Links` plan
    /// (`ping.rs:3317-3330`) without setting `batch_progress`.
    #[tokio::test]
    async fn an_empty_multi_selection_does_not_hang_the_scheduler() {
        let mut state = sched_state().await;
        enqueue(
            &mut state,
            TaskSpec {
                kind: TaskKind::MultiFastTest,
                scope: PlanScope::All,
                endpoint: None,
                label: "Fast Test (Selected)".to_string(),
            },
        );

        drain(&mut state).await;

        assert!(
            state.running_task.is_none(),
            "the empty plan set no meters, so the head must be dropped"
        );
    }

    /// The aggregate key tracks the filter scope, so a filter change is
    /// detectable by comparison (spec D21).
    #[tokio::test]
    async fn aggregate_key_tracks_the_filter_scope() {
        let mut state = sched_state().await;
        let key = state.aggregate_key();
        assert!(key.search.is_none(), "no search yet");
        assert!(key.group_id.is_none(), "the tab never narrows by group");

        state.search_query = "example".to_string();
        let key2 = state.aggregate_key();
        assert_eq!(key2.search.as_deref(), Some("example"));
        assert_ne!(key, key2, "a search change must change the key");

        state.purgatory_view = leas_db::models::PurgatoryView::Purgatory;
        assert_ne!(
            state.aggregate_key(),
            key2,
            "a view change must change the key"
        );
    }

    /// The refresh populates the cache, and the partition sums to the total.
    #[tokio::test]
    async fn refresh_aggregates_populates_the_cache() {
        let mut state = sched_state().await;
        assert!(state.aggregates.is_none(), "cold cache");

        state.refresh_aggregates().await;
        let cache = state.aggregates.expect("the refresh populates the cache");
        assert_eq!(
            cache.counts.proven
                + cache.counts.untested
                + cache.counts.failed
                + cache.counts.other,
            cache.counts.total,
            "the partition sums to the total even on an empty db"
        );
    }

    /// A finished task sets the dirty flag, so the next tick refreshes.
    #[tokio::test]
    async fn a_finished_task_marks_the_aggregates_dirty() {
        let mut state = sched_state().await;
        assert!(!state.aggregates_dirty.get());

        state.running_task = Some(spec(TaskKind::Compact, PlanScope::All, "Compact"));
        handle_terminal(&mut state, TerminalEvent::CompactFinished);

        assert!(
            state.aggregates_dirty.get(),
            "a job event must schedule a refresh"
        );
    }
}
