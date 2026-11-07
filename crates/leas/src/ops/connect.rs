use std::time::Duration;

use leas_db::models::EndpointId;
use leas_native::capability;

use super::native_connect;

use crate::AppState;
use crate::try_send_or_warn;
use crate::types::CoreEvent;

/// How long a new session waits for the previous session task to finish its
/// teardown before it binds its own listeners.
///
/// AGENTS.md decision 3 — one core at a time, the in-process server included:
/// the stop signal only *asks* the previous session to stop, so a new session
/// that does not wait binds onto still-held ports (EADDRINUSE) and races the
/// old task's closing `Disconnected`.
const PREV_SESSION_TEARDOWN: Duration = Duration::from_secs(5);

/// How long `disconnect` lets the session task run its own teardown
/// (`server.shutdown()` + `Disconnected`) before aborting it.
const DISCONNECT_TEARDOWN: Duration = Duration::from_secs(3);

/// Connect to a profile by starting the appropriate core (xray-core or sing-box).
pub fn connect_to_profile(state: &mut AppState, endpoint_id: i64) {
    if state.connecting {
        return;
    }

    let (endpoint, addresses, protocol_id, proto_kind) = {
        let Some(row) = state
            .endpoints
            .iter()
            .find(|r| r.endpoint.id.get() == endpoint_id)
        else {
            state.log_trace(
                "error",
                "tui::ops::connect",
                "Profile not found for connection",
            );
            return;
        };
        let Some((link, protocol)) = row.active_protocol() else {
            // T8+9: linkless endpoints are valid rows — nothing to connect.
            state.log_trace(
                "error",
                "tui::ops::connect",
                "Endpoint has no protocol links to connect",
            );
            return;
        };
        (
            row.endpoint.clone(),
            row.resolved_ips.clone(),
            link.protocol_id,
            protocol.proto_kind,
        )
    };

    // If already connected/disconnecting, send stop signal first
    if let Some(tx) = state.disconnect_tx.take() {
        let _ = tx.send(());
    }

    // Create disconnect signal channel
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    state.disconnect_tx = Some(stop_tx);
    state.connecting = true;
    state.connected_protocol_id = Some(endpoint_id);
    state.connection_error = None;

    // Deferred-resolution trigger: connect does real networking, so resolve
    // the inbound host now (force — bypasses the TTL cache).
    crate::ops::enrich::spawn_dns_resolve(state, endpoint.id.get(), true);

    // "Last Used" = connect initiation: DB write + in-memory row so the
    // sub-table refreshes without a reload. `update_last_used` sets both
    // `last_used_at` and `last_seen_at` to the same ts (old semantics).
    let now = leas_db::models::now_epoch();
    let lu_endpoint_id = EndpointId::new(endpoint.id.get());
    let lu_db = state.db.clone();
    tokio::spawn(async move {
        if let Err(e) = lu_db
            .update_last_used(protocol_id, lu_endpoint_id, now)
            .await
        {
            tracing::warn!(target: "tui::ops::connect", "update_last_used failed: {e}");
        }
    });
    if let Some(r) = state
        .endpoints
        .iter_mut()
        .find(|r| r.endpoint.id == endpoint.id)
        && let Some(link) = r.links.iter_mut().find(|l| l.protocol_id == protocol_id)
    {
        link.last_used_at = Some(now);
        // Mirror the DB write so the sub-table's displayed last_seen matches
        // the DB staleness classification between reloads.
        link.last_seen_at = now;
    }
    let tx = if let Some(tx) = &state.core_event_tx {
        tx.clone()
    } else {
        state.connecting = false;
        state.log_trace(
            "error",
            "tui::ops::connect",
            "Core event channel not initialized",
        );
        return;
    };

    // The native session binds the configured mixed inbound.
    let param_listen = state.config.inbound.listen.clone();
    let param_local_port = state.config.inbound.local_port();

    // Session log sink (native telemetry writes the heed store).
    let state_log_sender = state.log_sender_tx.clone();

    // One core at a time: hand the previous session's task to the new one so it
    // can wait out that teardown before binding its own listeners.
    let db = state.db.clone();
    let prev_task = state.core_task_handle.take();
    let handle = tokio::spawn(async move {
        // 0a. Wait out the previous session's teardown — the stop signal above
        //     only asked it to stop. A wedged task is aborted so its listeners
        //     are released either way.
        if let Some(mut prev) = prev_task
            && tokio::time::timeout(PREV_SESSION_TEARDOWN, &mut prev)
                .await
                .is_err()
        {
            tracing::warn!(
                target: "tui::ops::connect",
                secs = PREV_SESSION_TEARDOWN.as_secs(),
                "previous core session did not finish teardown; aborting it"
            );
            prev.abort();
        }
        // Cancelled while waiting (disconnect, or another connect took over):
        // bind nothing. This session never emitted `Connected`, so it must not
        // emit `Disconnected` either.
        if stop_rx.try_recv().is_ok() {
            return;
        }

        // 0b. Load the Protocol row with config included (the EndpointRow
        //     list ships unloaded deferred JSON).
        let protocol = match crate::state::load_protocol_with_config(&db, protocol_id).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                try_send_or_warn(
                    &tx,
                    CoreEvent::Error("Protocol row not found for connection".to_string()),
                    "protocol_not_found",
                );
                return;
            }
            Err(e) => {
                try_send_or_warn(
                    &tx,
                    CoreEvent::Error(format!("Failed to load protocol: {e}")),
                    "protocol_load_error",
                );
                return;
            }
        };
        // Unsupported rows stay visible and refuse with the capability
        // reason (D16) instead of falling back to a subprocess core.
        if let Some(reason) = capability::support_reason(proto_kind, &protocol.config.get().0) {
            try_send_or_warn(
                &tx,
                CoreEvent::Error(reason.into_owned()),
                "unsupported_profile",
            );
            return;
        }

        native_connect::run_native_session(
            &param_listen,
            param_local_port,
            &endpoint,
            &addresses,
            &protocol,
            &tx,
            &state_log_sender,
            stop_rx,
            protocol_id.get(),
        )
        .await;
    });
    state.core_task_handle = Some(handle);
}

/// Disconnect the currently running core.
pub fn disconnect(state: &mut AppState) {
    // Flush the final traffic delta: a poller tick landing just before the
    // stop can still sit in the event channel, unprocessed (the event loop
    // drains once per frame). Accumulate those deltas into the owning link
    // and persist the final row state once. Traffic since the last poll tick
    // (≤ one native poll interval) was never captured as an
    // event and is dropped by design; the T21 handler already persisted
    // every processed tick, so the row is current as of the last tick.
    let flushed = crate::ops::events::drain_pending_stats_updates(state);
    if !flushed.is_empty() {
        // Stage, don't commit: the traffic group is written by the flush task
        // (one transaction per window), and the UI task never waits on it.
        for link in &flushed {
            state.link_stage.stage(link, leas_db::LinkGroups::TRAFFIC);
        }
        // `disconnect` is synchronous, so the flush is spawned (as the old
        // per-row writes were) — but it is now one transaction, not N.
        let writer = std::sync::Arc::clone(&state.link_stage);
        tokio::spawn(async move {
            if let Err(e) = writer.flush().await {
                tracing::warn!(target: "tui::ops::connect", "final stats flush failed: {e}");
            }
        });
    }
    if let Some(tx) = state.disconnect_tx.take() {
        let _ = tx.send(());
    }
    if let Some(mut handle) = state.core_task_handle.take() {
        // Let the session task run its own teardown — the native core's
        // `server.shutdown()` and the closing `Disconnected` live there — and
        // abort only a wedged one. The waiter replaces the handle so a
        // following connect still serializes on this teardown (those listeners
        // must be gone before new ones bind), while the UI thread returns now.
        state.core_task_handle = Some(tokio::spawn(async move {
            if tokio::time::timeout(DISCONNECT_TEARDOWN, &mut handle)
                .await
                .is_err()
            {
                tracing::warn!(
                    target: "tui::ops::connect",
                    secs = DISCONNECT_TEARDOWN.as_secs(),
                    "core session did not stop in time; aborting it"
                );
                handle.abort();
            }
        }));
    }
    state.connected = false;
    state.live_proxy.clear();
    state.connected_protocol_id = None;
    state.connecting = false;
    // Session state: drop the error marker and the actions-log traffic
    // deltas so a disconnected session renders as "Disconnected", never as a
    // stale error or a frozen traffic segment.
    state.connection_error = None;
    state.current_traffic_up = 0;
    state.current_traffic_down = 0;
    state.log_trace("info", "core::process", "Disconnected");
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use leas_config::AppConfig;
    use leas_db::models::{
        ErrorInfo, Latency, ProfileErr, ProfileStats, ProtocolId, Security, Transport,
    };
    use leas_proto::proto_spec::{
        PlaceholderConfig, ProtocolConfig, ProtocolKind, SecurityType, TransportType,
    };
    use toasty::{Deferred, Json};

    use crate::ops::profiles::test_support::fake_row;

    use super::*;

    /// A `Protocol` row whose config is a placeholder (`Redirect`): the
    /// `ConfigBuilder::build` outbound injection errors on BOTH cores, so a
    /// connect attempt fails deterministically at config build — before any
    /// binary lookup or core start.
    fn placeholder_protocol(id: i64) -> leas_db::models::Protocol {
        let settings = serde_json::json!({
            "protocol_settings": {"password": "sekrit"},
            "stream_settings": {},
        });
        leas_db::models::Protocol {
            id: ProtocolId::new(id),
            sig: id,
            proto_kind: ProtocolKind::Redirect,
            transport: Transport {
                r#type: TransportType::Tcp,
            },
            security: Security {
                r#type: SecurityType::None,
                sni: None,
                fp: None,
                insecure: None,
            },
            config: Deferred::from(Json(ProtocolConfig::Redirect(PlaceholderConfig::new(
                "redirect".to_string(),
                serde_json::to_vec(&settings).unwrap(),
            )))),
            created_at: 0,
            links: Deferred::default(),
        }
    }

    async fn read_link(
        db: &leas_db::Database,
        protocol_id: i64,
        endpoint_id: i64,
    ) -> Option<ProfileStats> {
        let mut conn = db.connection().await.unwrap();
        ProfileStats::filter_by_protocol_id_and_endpoint_id(
            ProtocolId::new(protocol_id),
            leas_db::models::EndpointId::new(endpoint_id),
        )
        .first()
        .exec(&mut conn)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn connect_failure_placeholder_errors_without_touching_markers() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        // Endpoint row with one link (protocol id 100); its protocol config
        // is a placeholder so `ConfigBuilder::build` errors on either core.
        let mut row = fake_row(100, "h100.example", 1);
        let pid = row.links[0].protocol_id;
        row.protocols.insert(pid, placeholder_protocol(pid.get()));
        // Pre-existing latency + error markers must survive a connect
        // failure (a failed connect is NOT a ping — no markers written).
        let link = &mut row.links[0];
        link.latency = Latency::fast(42);
        link.error = Some(ErrorInfo {
            kind: ProfileErr::Fast,
            text: "previous failure".to_string(),
        });
        let traffic_before = link.traffic;
        // Persist rows: the connect task's `load_protocol_with_config` reads
        // the Protocol row (with config) from the DB.
        db.upsert_endpoint(&row.endpoint).await.unwrap();
        db.upsert_protocol(row.protocols.get(&pid).unwrap())
            .await
            .unwrap();
        db.upsert_link(&row.links[0]).await.unwrap();

        // AppState over the SAME database the rows were persisted to (the
        // connect task reads the Protocol row back from `state.db`).
        let mut state = crate::AppState::new(db, AppConfig::default()).await;
        state.endpoints = vec![row];
        state.filter_cache_valid.set(false);
        state.selected_index = 0;
        state.connect_to_profile(100);

        // Connect initiation bookkeeping: `connecting` in flight, the
        // connected endpoint registered, and last_used/last_seen patched
        // in-memory (mirrors the persisted write).
        assert!(state.connecting, "connecting flag set during connect");
        assert_eq!(state.connected_protocol_id, Some(100));
        let link = &state.endpoints[0].links[0];
        let used_at = link
            .last_used_at
            .expect("in-memory last_used_at set at initiation");
        assert_eq!(
            link.last_seen_at, used_at,
            "last_used mirrors last_seen (old semantics)"
        );

        // Drain until the connect task's error event lands (config build
        // fails on the placeholder before any binary lookup or core start).
        for _ in 0..200 {
            let _ = state.poll_core_events().await;
            if state.connection_error.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let err = state
            .connection_error
            .clone()
            .expect("connect failure surfaced as an event");
        assert!(
            err.contains("no native implementation for this protocol kind"),
            "got: {err}"
        );
        assert!(!state.connecting, "connecting cleared by the error event");
        assert!(!state.connected);
        assert_eq!(state.connected_protocol_id, None);

        // Failure surfaced as an event ONLY: latency/error markers and the
        // traffic counters are untouched.
        let link = &state.endpoints[0].links[0];
        assert!(
            link.latency.is_measured(),
            "pre-existing latency marker preserved"
        );
        assert!(link.error.is_some(), "pre-existing error marker preserved");
        assert_eq!(
            link.traffic, traffic_before,
            "connect failure writes no traffic"
        );

        // Persisted consistency: the spawned update_last_used write lands
        // with the same timestamp the in-memory patch used.
        let mut stored = None;
        for _ in 0..100 {
            stored = read_link(&state.db, pid.get(), 100).await;
            if stored.as_ref().is_some_and(|l| l.last_used_at.is_some()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stored = stored.expect("link persisted");
        let stored_used = stored.last_used_at.expect("last_used_at persisted");
        assert_eq!(
            stored.last_seen_at, stored_used,
            "DB write sets both columns"
        );
        assert_eq!(
            state.endpoints[0].links[0].last_used_at,
            Some(stored_used),
            "in-memory and persisted timestamps agree"
        );
    }

    #[tokio::test]
    async fn disconnect_flushes_pending_stats_and_clears_session_state() {
        let mut state =
            crate::ops::profiles::test_support::test_state(vec![fake_row(100, "h100.example", 1)])
                .await;
        // Isolate from the startup channels (whitelist load, auto-update):
        // replace the rx so only this test can feed events — deterministic.
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        state.core_event_rx = Some(rx);
        state.connected = true;
        state.connected_protocol_id = Some(100);
        state.current_traffic_up = 42;
        state.current_traffic_down = 84;
        state.connection_error = Some("stale error".to_string());

        // A poller tick in flight when disconnect is pressed: the delta must
        // be flushed into the link (in-memory + persisted), not lost with
        // the task abort. fake_row's link protocol id is id*100 = 10_000.
        tx.send(CoreEvent::StatsUpdate {
            protocol_id: 10_000,
            today_up: 10,
            today_down: 20,
            total_up: 10,
            total_down: 20,
        })
        .await
        .unwrap();

        state.disconnect();

        // Pollers stopped: the stop signal was consumed. No session task was
        // registered in this test, so there is nothing left to wait on.
        assert!(state.disconnect_tx.is_none(), "stop signal consumed");
        assert!(
            state.core_task_handle.is_none(),
            "no session task to tear down"
        );
        // Session state cleared.
        assert!(!state.connected);
        assert_eq!(state.connected_protocol_id, None);
        assert!(!state.connecting);
        assert_eq!(state.connection_error, None, "stale error cleared");
        assert_eq!(state.current_traffic_up, 0, "actions-log traffic reset");
        assert_eq!(state.current_traffic_down, 0);
        // The in-flight delta was flushed into the link in-memory.
        let link = &state.endpoints[0].links[0];
        assert_eq!(link.traffic.today_up, 10);
        assert_eq!(link.traffic.today_down, 20);
        assert_eq!(link.traffic.total_up, 10);
        assert_eq!(link.traffic.total_down, 20);
        // ... and persisted by the spawned flush.
        let mut stored = None;
        for _ in 0..100 {
            stored = read_link(&state.db, 10_000, 100).await;
            if stored.as_ref().is_some_and(|l| l.traffic.total_up >= 10) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let stored = stored.expect("link persisted");
        assert_eq!(stored.traffic.total_up, 10);
        assert_eq!(stored.traffic.total_down, 20);
        // Disconnect left no stragglers: draining the channel post-disconnect
        // finds nothing (the flush consumed the pending tick).
        assert!(!state.poll_core_events().await);
    }

    /// `disconnect` fires the stop signal and then lets the session task run
    /// its own teardown (for the native core, `server.shutdown()` and the
    /// closing `Disconnected` live there) — never an immediate abort, and never
    /// a blocked UI thread. The bounded waiter it leaves behind is what the
    /// next connect serializes on.
    #[tokio::test]
    async fn disconnect_lets_the_session_task_run_its_own_teardown() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut state =
            crate::ops::profiles::test_support::test_state(vec![fake_row(100, "h100.example", 1)])
                .await;
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        // `release` stands in for a teardown that takes a while: the task
        // cannot finish until this test allows it, so "did the tail run?" is
        // decided by ordering instead of by a sleep.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let torn_down = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&torn_down);
        state.disconnect_tx = Some(stop_tx);
        state.core_task_handle = Some(tokio::spawn(async move {
            stop_rx.await.expect("stop signal delivered by disconnect");
            let _ = release_rx.await;
            flag.store(true, Ordering::SeqCst);
        }));

        state.disconnect();

        assert!(
            !torn_down.load(Ordering::SeqCst),
            "disconnect returns before the teardown finishes (the UI thread never blocks)"
        );
        let waiter = state
            .core_task_handle
            .take()
            .expect("the bounded teardown waiter is kept for the next session");
        release_tx
            .send(())
            .expect("teardown still running, not aborted");
        waiter.await.expect("waiter joins cleanly");
        assert!(
            torn_down.load(Ordering::SeqCst),
            "the session task ran its own tail instead of being aborted"
        );
    }
}
