use anyhow::Result;
use leas::{AppState, CoreEvent};
use leas_config::AppConfig;
use leas_core::log_heed::HeedLogStorage;
use leas_db::Database;
use std::path::Path;
use std::sync::Arc;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::Layer as _;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
// ── Custom tracing layer that forwards events to the TUI event loop ──

/// Non-blocking tracing layer that sends log events through a channel
/// instead of writing to heed synchronously under the subscriber lock.
/// Optionally writes to a file when `log_to_file` is enabled.
struct TuiLogLayer {
    core_event_tx: tokio::sync::mpsc::Sender<leas::CoreEvent>,
    log_sender: std::sync::mpsc::SyncSender<leas_core::log_heed::LogMessage>,
    log_file: Option<std::sync::Mutex<std::fs::File>>,
    /// Messages dropped when the bounded log queue is full (writer stalled on
    /// LMDB resize). Folded into the writer's poll summary, never logged here
    /// (a warn! would re-enter this layer).
    dropped_logs: Arc<std::sync::atomic::AtomicU64>,
}

/// Captures the `message` field, plus the `toasty::query` structured fields, and
/// renders them into TWO strings with different destinations.
///
/// * `message` — what heed PERSISTS. Carries the timing and the statement text,
///   which is what the Logs tab reads back after a restart.
/// * `detail` — what only the SESSION sees (the Logs panel, this run). Every
///   other field lands here, including `db.params`.
///
/// The split is a SECURITY boundary, not a convenience. Enabling toasty's
/// `.log_statement_params(true)` makes bind values appear on the `toasty::query`
/// event, and one of our binds is `protocols.config` — the parsed protocol
/// config, which carries UUIDs and passwords. toasty's own docstring says
/// parameter values "may contain secrets" and to enable them "only when the log
/// destination is trusted"; heed is not that destination. So params must never
/// enter `LogMessage`. This is the same reason `specs/2026-09-24-db-query-
/// monitoring-design.md` §10 non-goal 10 forbids persisting monitoring detail.
///
/// Before this, every other field hit `_ => {}` and was lost: the stuck-deferral
/// warning at `ops/ping.rs` carries `endpoint_id`, `half` and `waited_ms`, and
/// the 2026-10-01 run left 12 such warnings in heed that named no row.
/// Report lines the BOUNDED log channel dropped. Written to stderr, not
/// through the channel that dropped them.
fn report_dropped_logs(counter: &std::sync::atomic::AtomicU64) {
    let dropped = counter.load(std::sync::atomic::Ordering::Relaxed);
    if dropped > 0 {
        eprintln!(
            "[leas] {dropped} log line(s) were dropped: the writer channel (capacity 4096) was full",
        );
    }
}

#[derive(Default)]
struct LogVisitor {
    message: String,
    duration_ms: Option<f64>,
    statement: Option<String>,
    /// Every non-message field, rendered. SESSION-ONLY.
    detail: Vec<String>,
}

impl LogVisitor {
    /// Split into the persisted message and the session-only `detail`.
    ///
    /// The message half is what heed stores and deliberately excludes `detail`.
    fn split(self) -> (String, Option<String>) {
        let Self {
            message,
            duration_ms,
            statement,
            detail,
        } = self;
        let detail = if detail.is_empty() {
            None
        } else {
            Some(detail.join(" "))
        };
        let message = match (duration_ms, statement) {
            (Some(ms), Some(sql)) => format!("{message} [{ms:.1}ms]: {sql}"),
            (Some(ms), None) => format!("{message} [{ms:.1}ms]"),
            _ => message,
        };
        (message, detail)
    }

    fn push_detail(&mut self, name: &str, rendered: &str) {
        self.detail.push(format!("{name}={rendered}"));
    }
}

impl Visit for LogVisitor {
    fn record_f64(&mut self, field: &Field, value: f64) {
        if field.name() == "duration_ms" {
            self.duration_ms = Some(value);
        } else {
            self.push_detail(field.name(), &value.to_string());
        }
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push_detail(field.name(), &value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push_detail(field.name(), &value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push_detail(field.name(), &value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "db.statement" => self.statement = Some(format!("{value:?}")),
            other => self.detail.push(format!("{other}={value:?}")),
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "message" => self.message = value.to_string(),
            "db.statement" => self.statement = Some(value.to_string()),
            other => self.detail.push(format!("{other}={value}")),
        }
    }
}

impl<S> tracing_subscriber::Layer<S> for TuiLogLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        use std::time::SystemTime;

        // Static level, no `to_string().to_lowercase()` alloc pair. Trace and
        // debug are filtered here (too verbose for the heed store).
        let level: &'static str = match *event.metadata().level() {
            tracing::Level::ERROR => "error",
            tracing::Level::WARN => "warn",
            tracing::Level::INFO => "info",
            tracing::Level::DEBUG | tracing::Level::TRACE => return,
        };

        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);
        // Split BEFORE either consumer: `message` is persisted, `detail` is
        // session-only and is where `db.params` lands (see `LogVisitor`).
        let (message, detail) = visitor.split();
        let target = event.metadata().target();

        let timestamp_nanos = u64::try_from(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        )
        .unwrap_or(u64::MAX);

        // Optional file log — write JSON line when enabled
        if let Some(ref file_mutex) = self.log_file {
            use std::io::Write;
            if let Ok(mut file) = file_mutex.lock() {
                let escaped_msg = serde_json::to_string(&message).unwrap_or_else(|_| "null".into());
                let _ = writeln!(
                    file,
                    r#"{{"ts":{timestamp_nanos},"level":"{level}","target":"{target}","msg":{escaped_msg}}}"#,
                );
            }
        }

        // Bounded non-blocking send (never blocks under the tracing lock). On a
        // full queue the message is dropped and counted — the writer folds the
        // count into its poll summary instead of warn!-ing (which re-enters).
        if self
            .log_sender
            .try_send(leas_core::log_heed::LogMessage {
                level: level.to_owned(),
                target: target.to_owned(),
                message: message.clone(),
                timestamp_nanos,
            })
            .is_err()
        {
            self.dropped_logs
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Send lightweight notification to TUI for the actions panel. The
        // timestamp is the one this event was created with — the same value the
        // heed copy is keyed by, because the Logs tab reconciles the two
        // deliveries through a single watermark (`last_seen_log_ns`).
        let _ = self.core_event_tx.try_send(leas::CoreEvent::TuiLog {
            target: target.to_owned(),
            level: level.to_owned(),
            message,
            // `i64` nanos, saturating: a clock past 2262 would otherwise wrap
            // to a negative stamp and sort ahead of every real line.
            timestamp_nanos: i64::try_from(timestamp_nanos).unwrap_or(i64::MAX),
            // Session-only. Never reaches `LogMessage`, so `db.params` cannot
            // be persisted by way of this line.
            detail,
            // The heed copy is written above; the watermark may pass it.
            persisted: true,
        });
    }
}

// ── Application entry point ──

/// Install the process-level rustls `CryptoProvider` before anything can
/// build TLS. reqwest 0.13 is built with `rustls-no-provider` (workspace
/// standard: ring backend) and panics at `Client::build` unless a provider is
/// installed process-wide. Idempotent: a second call returns `Err` from
/// `install_default` and is ignored. rustls 0.23 also auto-selects when the
/// crate features name exactly one backend — the workspace pins ring only —
/// but reqwest checks `get_default()` explicitly and never auto-installs.
fn install_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Whether the `LEAS_STDERR_LOG` value enables the stderr log mirror.
///
/// Being set is the switch; an inherited `0`, `false` or empty value reads as
/// off so the mirror can be disabled without unsetting the variable.
fn stderr_mirror_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "" | "0" | "false"))
}

#[tokio::main]
async fn main() -> Result<()> {
    // 0. Install rustls CryptoProvider first — every later TLS consumer
    //    (reqwest, QUIC ping adapter, hickory DoH) needs it.
    install_tls_provider();
    // 1. Load app config (~/.config/leas/config.json) — returns Default on missing
    let config = AppConfig::load()?;

    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join("leas");
    // Bounded (4096) so a stalled LMDB writer caps retention instead of growing
    // without bound; `on_event`/`log_trace`/forwarder all `try_send` + drop.
    // The 200ms `recv_timeout` poll below stays: the global subscriber holds a
    // `Sender` forever, so a blocking `recv()` would park at quit; the timeout
    // lets the loop notice `shutdown_token`.
    let (log_sender_tx, log_rx) =
        std::sync::mpsc::sync_channel::<leas_core::log_heed::LogMessage>(4096);
    let dropped_logs = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // 2. Open database (~/.config/leas/data.db)
    // The directory holds the profile credential store (data.db) and the log
    // store: make it owner-only so it is not traversable by other local users.
    // `AppConfig::save` already creates it 0700 on a fresh install; this
    // tightens an install created by an older build.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::create_dir_all(&config_dir);
        let _ = std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o700));
    }
    let db_path = config_dir.join("data.db");
    // The store holds every stored profile's proxy credentials: create it
    // owner-only before the driver touches it, and tighten an existing store.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&db_path);
        let _ = std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600));
    }
    let db = Database::open(&db_path).await?;
    // The driver creates data.db-wal (and data.db-shm) with its own open,
    // which passes no create-time mode, so they inherit the umask and land
    // 0644 at umask 022 unless tightened here, after the driver has created
    // them. They hold the same cleartext credentials as data.db.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for sidecar in ["data.db-wal", "data.db-shm"] {
            let _ = std::fs::set_permissions(
                config_dir.join(sidecar),
                std::fs::Permissions::from_mode(0o600),
            );
        }
    }
    // 3. Open heed log storage (~/.config/leas/logs.lmdb)
    let log_path = config_dir.join("logs.lmdb");
    let heed = Arc::new(HeedLogStorage::new(&log_path)?);

    // 3b. Batched writer over the bounded channel created above (4096): batches
    //     up to 100 messages per heed write_transaction on the blocking pool.

    // The writer cannot rely on the channel closing to exit: `TuiLogLayer` holds a
    // `Sender` clone inside the GLOBAL tracing subscriber, which is never dropped, so
    // a blocking `recv()` would park forever — and `Runtime::drop` waits for in-flight
    // `spawn_blocking` work, which used to hang the process at quit. It polls the
    // canonical shutdown flag instead (the same `AppState::shutdown_token` every other
    // background loop checks — installed on the state below, so there is one owner).
    let shutdown_token = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let writer_shutdown = shutdown_token.clone();
    let writer_heed = heed.clone();
    // The channel is BOUNDED (4096), so a burst can drop lines. The counter was
    // incremented but never reported anywhere; this task owns the writer's
    // lifetime, so it is where the total becomes visible.
    let writer_drops = dropped_logs.clone();
    let _writer_handle = tokio::task::spawn_blocking(move || {
        /// Idle poll slice: the quit path waits at most this long for the writer.
        const IDLE_POLL: std::time::Duration = std::time::Duration::from_millis(200);
        let mut batch: Vec<leas_core::log_heed::LogMessage> = Vec::with_capacity(100);
        loop {
            // Wait for at least one message, waking often enough to notice shutdown.
            let msg = match log_rx.recv_timeout(IDLE_POLL) {
                Ok(msg) => msg,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if writer_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                        // Flush before leaving. This branch used to `return`
                        // WITHOUT flushing, so a quit inside the 500 ms batch
                        // deadline silently lost up to 100 lines.
                        if !batch.is_empty() {
                            let _ = writer_heed.write_log_batch(&batch);
                        }
                        report_dropped_logs(&writer_drops);
                        return;
                    }
                    continue;
                }
                // Channel closed (every sender dropped) — flush and exit.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    if !batch.is_empty() {
                        let _ = writer_heed.write_log_batch(&batch);
                    }
                    report_dropped_logs(&writer_drops);
                    return;
                }
            };
            let batch_deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
            batch.push(msg);
            // Drain until deadline or 100 entries
            while batch.len() < 100 {
                let remaining = batch_deadline.saturating_duration_since(std::time::Instant::now());
                match log_rx.recv_timeout(remaining) {
                    Ok(msg) => batch.push(msg),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        let _ = writer_heed.write_log_batch(&batch);
                        return;
                    }
                }
            }
            let _ = writer_heed.write_log_batch(&batch);
            batch.clear();
        }
    });
    // 3c. Capture log config before moving config into AppState
    let log_to_file = config.logging.log_to_file;
    let log_file_path = config.logging.log_file_path.clone();

    // Canonicalize log file path to prevent path traversal
    let log_file_path = if log_to_file {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| std::path::Path::new(".").to_path_buf())
            .join("leas");
        let p = Path::new(&log_file_path);
        // Reject any path with parent-dir traversal (`..`)
        if p.components().any(|c| c == std::path::Component::ParentDir) {
            tracing::warn!("log file path contains '..', falling back to default");
            config_dir.join("leas.log")
        } else if p.is_relative() {
            config_dir.join(&log_file_path)
        } else {
            p.to_path_buf()
        }
    } else {
        Path::new(&log_file_path).to_path_buf()
    };

    let mut state = AppState::new(Arc::new(db), config).await;
    // One shutdown owner: the log writer above already holds a clone, and every
    // background loop reads it off the state (`spawn_auto_update` and friends are
    // started later, from `ui::run`, so this replacement is not racing them).
    state.shutdown_token = shutdown_token;
    // Write-behind flush loop: result/stats/scheduler writes are staged and
    // flushed from here, never on the UI task.
    let _flush_task = state.link_stage.spawn_flush_task();
    state.heed_storage = Some(heed.clone());
    state.log_sender_tx = Some(log_sender_tx.clone());
    // Create core process log channel (stdout/stderr lines from xray-core/sing-box subprocesses).
    let (core_log_tx, mut core_log_rx) = tokio::sync::mpsc::channel::<String>(512);
    state.core_log_tx = Some(core_log_tx);
    {
        let log_sender = log_sender_tx.clone();
        tokio::spawn(async move {
            while let Some(line) = core_log_rx.recv().await {
                let (target, level, message, _ts) =
                    leas::parse_core_log_line(&line, leas_core::CoreType::Auto);
                let msg = leas_core::log_heed::LogMessage {
                    timestamp_nanos: u64::try_from(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos(),
                    )
                    .unwrap_or(u64::MAX),
                    level,
                    target,
                    message,
                };
                // `try_send`: a blocking `send` on the full bounded queue would
                // stall the async executor; drop instead (counted on the layer).
                let _ = log_sender.try_send(msg);
            }
        });
    }
    // 4. Install tracing subscriber with TuiLogLayer (non-blocking channel send).
    //    Do not crash if global subscriber was already set (e.g., in tests)
    let log_file = if log_to_file {
        Some(std::sync::Mutex::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file_path)
                .expect("failed to open log file for appending"),
        ))
    } else {
        None
    };
    // The stderr mirror is opt-in via `LEAS_STDERR_LOG`, never `RUST_LOG`
    // alone: an exported `RUST_LOG=debug` meant for some other tool would
    // both switch this layer on and widen its filter, and unguarded stderr
    // writes corrupt the alternate-screen TUI. The Logs tab and the log file
    // (TuiLogLayer below) capture everything regardless, so terminal
    // debugging is `LEAS_STDERR_LOG=1 leas 2>stderr.log`. `RUST_LOG`
    // still supplies this layer's directives when it is set.
    let stderr_var = std::env::var("LEAS_STDERR_LOG").ok();
    let stderr_log = stderr_mirror_enabled(stderr_var.as_deref()).then(|| {
        let filter = std::env::var("RUST_LOG")
            .ok()
            .filter(|directives| !directives.trim().is_empty())
            .map_or_else(
                || tracing_subscriber::EnvFilter::new("leas=info"),
                tracing_subscriber::EnvFilter::new,
            );
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(filter)
    });
    // DB query monitor: aggregates toasty's `toasty::query` events with our
    // `retry_on_busy` retry counts, keyed by `Database` method span.
    let db_monitor = leas::ops::db_monitor::DbMonitor::new();
    leas::ops::db_monitor::install(db_monitor.clone());
    let db_monitor_layer = leas::ops::db_monitor::DbMonitorLayer::new(db_monitor)
        // Only the per-query events and the method-attribution spans; nothing
        // else reaches this layer.
        .with_filter(tracing_subscriber::EnvFilter::new(
            "off,toasty::query=debug,db_method=trace",
        ));
    if tracing_subscriber::registry()
        .with(stderr_log)
        .with(
            TuiLogLayer {
                core_event_tx: state
                    .core_event_tx
                    .clone()
                    .expect("core_event_tx must be set before tracing init"),
                log_sender: log_sender_tx,
                log_file,
                dropped_logs: dropped_logs.clone(),
            }
            // Logs tab stays unfiltered (trace+) except hickory's DoH h2
            // transport chatter — those connections retry transparently and
            // spammed the dump (391 lines of "peer closed connection").
            .with_filter(tracing_subscriber::EnvFilter::new(
                "trace,hickory_net::h2=error",
            )),
        )
        .with(db_monitor_layer)
        .try_init()
        .is_err()
    {
        eprintln!("leas: tracing subscriber already set — skipping TUI log layer");
    }

    // 5. Spawn TTL maintenance task for old logs (uses heed directly — infrequent)
    let ttl_heed = heed.clone();
    let ttl_dur = state.config.logging.ttl_secs.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_mins(10)); // 10 min
        interval.tick().await; // skip first tick
        loop {
            interval.tick().await;
            if ttl_dur.is_zero() {
                continue; // 0 = keep forever
            }
            let now_nanos = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos(),
            )
            .unwrap_or(u64::MAX);
            let cutoff = now_nanos.saturating_sub(u64::try_from(ttl_dur.as_nanos()).unwrap_or(0));
            // Spawn_blocking for heed delete operation
            let h = ttl_heed.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = h.delete_older_than(cutoff) {
                    // Can't use tracing inside spawn_blocking from a tokio task without
                    // the right context — but eprintln! is safe here (TTL runs rarely)
                    eprintln!("leas: TTL cleanup error: {e}");
                }
            })
            .await
            .ok();
        }
    });
    // 5b. Retention maintenance: endpoints whose NEWEST link has aged past the
    //     purgatory retention window are reclaimed. `purge_expired` had no
    //     production caller before this — the Stale view showed rows that were
    //     never reclaimed. Best-effort: a failed pass logs and the next one
    //     retries.
    {
        let purge_db = Arc::clone(&state.db);
        let purge_tx = state.core_event_tx.clone();
        let purge_retention_secs = state.purgatory_retention_secs;
        let purge_shutdown = state.shutdown_token.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_mins(10));
            interval.tick().await; // skip first tick
            loop {
                interval.tick().await;
                if purge_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                // Demote endpoints that aged out of the Active window since the
                // last tick (band 0 → 1) — a cheap directional index sweep, run
                // every tick even when retention is disabled.
                if let Err(e) = purge_db.reband_expired().await {
                    tracing::warn!(target: "tui::main", "reband sweep failed: {e}");
                }
                if purge_retention_secs <= 0 {
                    continue; // 0 or negative = keep forever
                }
                // Stored timestamps are epoch seconds, so is the cutoff.
                let cutoff = leas_db::models::now_epoch() - purge_retention_secs;
                match purge_db.purge_expired(cutoff).await {
                    Ok(0) => {}
                    Ok(count) => {
                        if let Some(tx) = &purge_tx {
                            let _ = tx.try_send(CoreEvent::RetentionPurged { count });
                        }
                    }
                    Err(e) => {
                        tracing::warn!(target: "tui::main", "retention purge failed: {e}");
                    }
                }
            }
        });
    }

    // Panic hook to restore terminal on unexpected crashes
    let prev_hook = std::panic::take_hook();
    // A panic unwinds past the store below (the workspace has no
    // `panic = "abort"`), so the hook has to release the blocking terminal
    // reader and log writer too — otherwise the message prints, the terminal
    // is restored, and the runtime drop then parks on them forever.
    let panic_shutdown = state.shutdown_token.clone();
    std::panic::set_hook(Box::new(move |panic_info| {
        panic_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = std::panic::catch_unwind(|| {
            let _ = crossterm::terminal::disable_raw_mode();
        });
        let _ = std::panic::catch_unwind(|| {
            let _ =
                crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
        });
        prev_hook(panic_info);
    }));

    // 6. Enter ratatui event loop
    let outcome = leas::ui::run(&mut state).await;
    // Unconditional: `run` also exits through `?` (a failed draw, a failed
    // terminal restore), and the blocking terminal reader + heed log writer only
    // stop on this flag. Missing it parks them forever and the tokio runtime
    // drop below never returns — the process would hang instead of reporting the
    // error.
    state
        .shutdown_token
        .store(true, std::sync::atomic::Ordering::Relaxed);
    outcome?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LogVisitor, install_tls_provider, stderr_mirror_enabled};

    /// Regression: release panic "Could not automatically determine the
    /// process-level `CryptoProvider` from Rustls crate" on Fast+Real ping.
    /// rustls is single-backend ring, but reqwest 0.13 `rustls-no-provider`
    /// requires an installed default before `Client::build`.
    #[test]
    fn tls_provider_installed_before_any_use() {
        install_tls_provider();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "startup install_tls_provider() must leave a default CryptoProvider installed"
        );
        // The exact panic site from the report must no longer fire.
        let _builder = rustls::ClientConfig::builder();
        // Idempotent: a second install returns Err, never panics.
        install_tls_provider();
    }

    /// The stderr mirror must never ride on `RUST_LOG` alone (it garbles the
    /// alternate screen), and an inherited falsy value must read as off.
    #[test]
    fn stderr_mirror_gate_is_the_dedicated_variable() {
        assert!(stderr_mirror_enabled(Some("1")));
        assert!(stderr_mirror_enabled(Some("true")));
        assert!(stderr_mirror_enabled(Some("leas=debug")));
        assert!(!stderr_mirror_enabled(None));
        assert!(!stderr_mirror_enabled(Some("")));
        assert!(!stderr_mirror_enabled(Some(" ")));
        assert!(!stderr_mirror_enabled(Some("0")));
        assert!(!stderr_mirror_enabled(Some("False")));
    }

    /// The visitor splits a line into a PERSISTED message and a SESSION-ONLY
    /// detail. This is the security property T1 exists for: with toasty's
    /// `.log_statement_params(true)` wired, `db.params` lands on the
    /// `toasty::query` event, and one of our binds (`protocols.config`) carries
    /// UUIDs and passwords. The persisted half must never see it.
    #[test]
    fn structured_fields_split_between_persisted_and_session_only() {
        let mut v = LogVisitor {
            message: "slow query".to_string(),
            duration_ms: Some(312.4),
            statement: Some("SELECT * FROM profile_stats".to_string()),
            detail: Vec::new(),
        };
        v.push_detail("db.params", "[1000, secret-uuid]");
        let (message, detail) = v.split();
        let detail = detail.expect("detail");
        assert!(
            message.contains("312.4ms") && message.contains("profile_stats"),
            "the persisted line keeps timing and statement: {message}",
        );
        assert!(
            !message.contains("secret-uuid"),
            "bind values must NEVER reach the persisted line: {message}",
        );
        assert!(
            detail.contains("secret-uuid"),
            "the session-only detail must carry them: {detail}",
        );
    }

    /// Duration without a statement still gets the timing, and a line with no
    /// structured fields produces NO detail at all.
    #[test]
    fn log_visitor_still_enriches_timing() {
        let v = LogVisitor {
            message: "slow query".to_string(),
            duration_ms: Some(5.0),
            statement: None,
            detail: Vec::new(),
        };
        let (message, detail) = v.split();
        assert_eq!(message, "slow query [5.0ms]");
        assert_eq!(detail, None, "no extra fields, no detail");

        let v = LogVisitor {
            message: "plain log".to_string(),
            duration_ms: None,
            statement: None,
            detail: Vec::new(),
        };
        assert_eq!(v.split().0, "plain log");
    }
}
