# 021 — A DNS-retry scan failure reports `CompactFinished`, which cannot end a `DnsRetry` task, so the job queue wedges for the rest of the session

- **Location**: `crates/leas/src/ops/compact.rs:431` (the emit on the scan's
  error path), `crates/leas/src/ops/job_scheduler.rs:335-336`
  (`expected_kinds`), `:348-362` (the stray branch that restores
  `running_task`), `crates/leas/src/ops/events.rs:719-731` (the mapping from
  the core event to the terminal event)
- **Severity**: medium
- **Status**: theory (code-proven: the producer's kind and the event's
  accepted-kind list are disjoint)

## Hypothesis

The job scheduler pairs each terminal event with the task kinds it may end
(`expected_kinds`, `job_scheduler.rs:322-338`):

| `TerminalEvent` | kinds it ends |
| --- | --- |
| `BatchEnded` | the nine probe/fill kinds |
| `CompactFinished` | `Compact` |
| `MaintenanceDone` | `DnsRetry` |

`handle_terminal` is strict by design (spec D43): a mismatched event is a
**stray**, logged, and `running_task` is put back (`:348-362`). The only other
clear in the process is `drain`'s refused-spawn path (`:198`), which cannot run
while `running_task` is set (`:170`), and the quit path (`:394`). So a task that
ends without a matching event is **running forever** as far as the queue is
concerned: `drain` returns on its first check (`:170`), `is_busy` stays true, so
every later enqueue is accepted into `task_queue` and never starts, and the
destructive one-shots (`Remove Bad Servers`, `Clear All Stats`) stay disabled.
Neither `stop` nor `resume` touches `running_task`, so there is no UI path out.

The exact sequence matters for the symptom, because the event itself is
partly handled: `CompactFinished` sets `maint_progress = None`
(`events.rs:721`) *before* forwarding to `handle_terminal`, so the progress
surface comes down normally and only `running_task` survives. Two visible
consequences:

- `running_task_meters` (`ui/status_bar.rs:27-48`) then finds no slot and
  returns `(0, 0)`, so the status bar hits its `total == 0` arm and renders
  `" <label> …"` (`:78-84`) — a permanent spinner naming a task that has
  already exited.
- `set_resolve_progress(None)` is called only by the `MaintenanceDone` handler
  (`events.rs:753`), never by this path, so the run's resolve meter stays
  installed in the process-global `RESOLVE_PROGRESS` (`enrich.rs:425`) and every
  later lookup keeps bumping it. Nothing renders it once `maint_progress` is
  `None`, so this is a leaked `Arc`, not a stuck bar — but it is why the failure
  path should clear the slot it installed.

`spawn_dns_retry` has two exits, and they disagree:

- success → `CoreEvent::MaintenanceDone` (`compact.rs:473`) — the right event
  for `TaskKind::DnsRetry`;
- **`load_all_rows` failure → `CoreEvent::CompactFinished`**
  (`compact.rs:428-437`, text `"DNS retry scan failed: {e}"`) — the event whose
  only accepted kind is `Compact`.

The event handler forwards the core event to the scheduler unconditionally
(`events.rs:719-731` → `handle_terminal(TerminalEvent::CompactFinished)`), so
the failed retry resolves to a stray: `running_task` is restored, and the queue
is dead for the session.

`spawn_compact` gets this right on both of its exits (`compact.rs:288`,
`:431` is the retry's), which is what makes the single wrong line visible: the
taxonomy is keyed on the *event*, and one producer emits the other task's
event.

## Evidence

```rust
// compact.rs:420-438 — the DNS-retry scan and its failure report
let rows = match load_all_rows(&db, purgatory_ttl_secs, error_ttl_hours, Some(scan.as_ref())).await {
    Ok(rows) => rows,
    Err(e) => {
        if let Some(tx) = &tx {
            let _ = tx.try_send(crate::types::CoreEvent::CompactFinished {
                merged: 0,
                text: format!("DNS retry scan failed: {e}"),
            });
        }
        return;                     // no `MaintenanceDone` is ever sent
    }
};
```

```rust
// job_scheduler.rs:335-336
TerminalEvent::CompactFinished => &[TaskKind::Compact],
TerminalEvent::MaintenanceDone => &[TaskKind::DnsRetry],
```

The failing path is the first statement of the task, so it triggers on any read
error — the driver's 5 s `busy_timeout` under a concurrent writer, an IO error,
a corrupt page — and also on a panic in the spawned task, which likewise sends
no event. `TaskKind::DnsRetry` is reached from the Tasks menu, so this is one
user command away.

The scheduler-level behaviour is *pinned* as intentional:
`terminal_events_match_the_running_task` (`job_scheduler.rs:618-655`) asserts a
mismatched event must not clear a running task, and the retry's **success** exit
is pinned by `retry_targets_only_unresolved_dns_hosts`
(`compact.rs:708-762`, asserting the `"DNS retry: complete"` log line only the
`MaintenanceDone` handler writes). What is not pinned is the **failure** exit —
which is exactly the seam this bug slips through.

## Reproducer

Not run: `crates/leas` is bin-only and a `leas-db`/`leas` test build is a cold
multi-minute compile, and the failing branch needs a `load_all_rows` error
injected through the global `Database`. The claim is static — two disjoint
lists, one emit site, one unconditional forward.

The nearest test is `retry_targets_only_unresolved_dns_hosts`
(`compact.rs:708-762`): it drives `spawn_dns_retry`, pumps
`poll_core_events`, and waits for the log line `"DNS retry: complete"` — which
only the `MaintenanceDone` handler writes (`events.rs:751`). That pins the
**success** exit's pairing. The failure exit is untested, and the two halves of
what a seam test needs are:

```rust
// The pairing table — passes today. It is the contract the producer must obey.
assert_eq!(expected_kinds(TerminalEvent::MaintenanceDone), &[TaskKind::DnsRetry]);
assert_eq!(expected_kinds(TerminalEvent::CompactFinished), &[TaskKind::Compact]);

// The producer half — nothing covers it. Every exit of `spawn_dns_retry`
// must emit `MaintenanceDone`; the error exit emits `CompactFinished`.
```

## Fix options

1. **Send the task's own event.** The sweep's error path emits
   `CoreEvent::MaintenanceDone` after logging the failure text — but
   `MaintenanceDone` carries no message, and the handler logs `"DNS retry:
   complete"`, which would be a lie. Smallest honest shape: give the retry its
   own terminal core event (`CoreEvent::MaintenanceFailed { text }`) mapped to
   `MaintenanceDone` by the handler, or add a `text` field to `MaintenanceDone`
   the way `CompactFinished` already carries one. Whichever shape, the handler
   must also `set_resolve_progress(None)` — that clear lives only in the
   `MaintenanceDone` arm today (`events.rs:753`), which is why the failure path
   leaves the meter installed.
2. **Make the mismatch recoverable.** Treat a terminal event as ending the
   running task whenever no *other* running task could own it — i.e. fall back
   to clearing when the event's kind set and the running kind cannot both be
   live. That deletes the D43 guard that keeps a late batch event from ending a
   just-started task, so it trades one bug for a worse class of races.
3. **Add the seam test.** A `#[rstest]` over `(TaskKind, TerminalEvent)` pairs
   asserting every kind's expected event is the one its producer emits, plus a
   per-producer test that each exit path emits it. This does not fix the bug on
   its own; it is what makes the next one impossible.

Option 1 plus the retry half of option 3: the mismatch is a taxonomy mistake,
and the reason it survived is that nothing tests producers against the
taxonomy.

## Related

- **019:** 019's scan (`profiles_page` → `profiles_count_with` per page) is one
  of the reads the retry's scan sits on, so a slow scan widens the window in
  which this issue's error can arrive. It is not the trigger — the trigger is
  any `load_all_rows` error.
- **022:** the failure bookkeeping the retry consumes. 022 makes the marks
  quadratic; 021 stops the run that reads them from ever handing its slot back.
  Only 021 wedges the queue — 022 costs CPU and lock hold time.
