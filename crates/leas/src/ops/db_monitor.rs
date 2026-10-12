//! In-process database query monitoring.
//!
//! Aggregates toasty's per-query `toasty::query` tracing events (statement,
//! duration, rows, outcome) with our own `retry_on_busy` retry counts, keyed
//! by the enclosing [`Database`] method name. Session-only, in-memory; dumped
//! on demand to the Logs tab.
//!
//! This module has two halves:
//! - the pure [`Registry`] fold/rank math (unit-tested here), and
//! - the `tracing` [`DbMonitorLayer`] two-source consumer (`on_event` folds
//!   query metrics, `on_close` folds the method's final retry count).
//!
//! See `docs/aegis/specs/2026-09-24-db-query-monitoring-design.md`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Bucket key for statements not enclosed by a named `Database`-method span.
pub const UNATTRIBUTED: &str = "unattributed";

/// Retained duration samples per method. A circular window: once full, the
/// oldest sample is overwritten, so percentiles reflect recent behavior and
/// memory stays bounded — ~32 KiB per method, ~1.3 MiB across the ~40
/// methods. The monitor is ALWAYS-ON (the goal is to have bottleneck data
/// ready the instant `d` is pressed, not to enable-then-reproduce); the cost
/// is a ~ns lock per physical statement (negligible beside the µs–ms
/// statement itself) plus this bounded memory. If the per-statement lock ever
/// shows in a profile, replace the ring with an atomic log-scale histogram.
const SAMPLE_CAP: usize = 4096;

/// Aggregated statistics for one `Database` method (or the unattributed
/// bucket).
#[derive(Debug, Default, Clone)]
pub struct MethodStat {
    /// Physical `toasty::query` events attributed to this method.
    pub query_count: u64,
    /// Events whose result was an error.
    pub fail_count: u64,
    /// Sum of final retry counts across method invocations.
    pub retries: u64,
    /// Method-close count (distinct invocations).
    pub invocations: u64,
    /// Sum of measured query durations (ms).
    total_ms: f64,
    /// Bounded circular window of duration samples (ms) for percentiles.
    samples: Vec<f64>,
    /// Next write position in the circular sample window.
    next: usize,
    /// Slowest statement seen: (`duration_ms`, statement text).
    pub slowest: Option<(f64, String)>,
}

impl MethodStat {
    fn record_query(&mut self, duration_ms: f64, is_err: bool, statement: Option<&str>) {
        self.query_count += 1;
        if is_err {
            self.fail_count += 1;
        }
        self.total_ms += duration_ms;

        if self.samples.len() < SAMPLE_CAP {
            self.samples.push(duration_ms);
        } else {
            self.samples[self.next] = duration_ms;
            self.next = (self.next + 1) % SAMPLE_CAP;
        }

        if self.slowest.as_ref().is_none_or(|(d, _)| duration_ms > *d) {
            self.slowest = Some((duration_ms, statement.unwrap_or("").to_owned()));
        }
    }

    /// Percentile (0..=100) over the retained sample window, in ms.
    #[must_use]
    pub fn percentile(&self, p: f64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_by(f64::total_cmp);
        let idx =
            (((p / 100.0) * ((sorted.len() - 1) as f64)).round() as usize).min(sorted.len() - 1);
        sorted[idx]
    }

    /// Mean query duration (ms).
    #[must_use]
    pub fn mean_ms(&self) -> f64 {
        if self.query_count == 0 {
            0.0
        } else {
            self.total_ms / self.query_count as f64
        }
    }
}

/// The per-method aggregation registry.
#[derive(Debug, Default)]
pub struct Registry {
    methods: HashMap<String, MethodStat>,
}

impl Registry {
    /// Fold one `toasty::query` event into `method`'s bucket.
    pub fn fold_query(
        &mut self,
        method: &str,
        duration_ms: f64,
        is_err: bool,
        statement: Option<&str>,
    ) {
        self.methods
            .entry(method.to_owned())
            .or_default()
            .record_query(duration_ms, is_err, statement);
    }

    /// Fold a method's completion: one invocation plus its final retry count.
    pub fn fold_close(&mut self, method: &str, retries: u64) {
        let stat = self.methods.entry(method.to_owned()).or_default();
        stat.invocations += 1;
        stat.retries += retries;
    }

    /// Ranked dump lines, hottest method (by p99) first, capped to `top_n`.
    #[must_use]
    pub fn ranked(&self, top_n: usize) -> Vec<String> {
        let mut rows: Vec<(&String, &MethodStat)> = self.methods.iter().collect();
        rows.sort_by(|a, b| b.1.percentile(99.0).total_cmp(&a.1.percentile(99.0)));

        let mut out = Vec::with_capacity(rows.len().min(top_n) + 1);
        out.push(format!(
            "db-monitor: top {} methods by p99 (queries / p50 / p99 / mean ms, invocations, retries, fails)",
            top_n.min(rows.len())
        ));
        for (method, s) in rows.into_iter().take(top_n) {
            let slow = s
                .slowest
                .as_ref()
                .map(|(d, sql)| format!("  slowest {d:.1}ms: {}", truncate(sql, 160)))
                .unwrap_or_default();
            out.push(format!(
                "  {method}: n={} p50={:.1} p99={:.1} mean={:.1} inv={} retries={} fails={}{}",
                s.query_count,
                s.percentile(50.0),
                s.percentile(99.0),
                s.mean_ms(),
                s.invocations,
                s.retries,
                s.fail_count,
                if slow.is_empty() {
                    String::new()
                } else {
                    format!("\n{slow}")
                },
            ));
        }
        out
    }

    /// True when nothing has been recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let head: String = s.chars().take(max).collect();
        format!("{head}…")
    }
}

/// Shared, cloneable handle to the registry.
#[derive(Clone, Default)]
pub struct DbMonitor(Arc<Mutex<Registry>>);

impl DbMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fold_query(
        &self,
        method: &str,
        duration_ms: f64,
        is_err: bool,
        statement: Option<&str>,
    ) {
        if let Ok(mut reg) = self.0.lock() {
            reg.fold_query(method, duration_ms, is_err, statement);
        }
    }

    pub fn fold_close(&self, method: &str, retries: u64) {
        if let Ok(mut reg) = self.0.lock() {
            reg.fold_close(method, retries);
        }
    }

    /// Ranked dump lines (see [`Registry::ranked`]).
    #[must_use]
    pub fn dump(&self, top_n: usize) -> Vec<String> {
        self.0.lock().map_or_else(
            |_| vec!["db-monitor: registry lock poisoned".to_owned()],
            |reg| {
                if reg.is_empty() {
                    vec!["db-monitor: no queries recorded this session".to_owned()]
                } else {
                    reg.ranked(top_n)
                }
            },
        )
    }
}

/// Process-global monitor handle, installed at subscriber init.
static GLOBAL: OnceLock<DbMonitor> = OnceLock::new();

/// Install the process-global monitor. Idempotent: a second call is ignored.
pub fn install(monitor: DbMonitor) {
    let _ = GLOBAL.set(monitor);
}

/// The process-global monitor, if installed.
#[must_use]
pub fn global() -> Option<&'static DbMonitor> {
    GLOBAL.get()
}

// ── tracing Layer (two-source: on_event query metrics, on_close retries) ──

use tracing::field::{Field, Visit};
use tracing::span;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Target set on the `#[instrument]` attribute of every `Database` method so
/// the Layer recognizes attribution spans without a magic field.
pub const METHOD_TARGET: &str = "db_method";

/// The `toasty::query` per-statement event target (from toasty-core).
const QUERY_TARGET: &str = "toasty::query";

/// Per-method span state stored in span extensions.
#[derive(Debug)]
struct MethodSpan {
    name: &'static str,
    retries: u64,
}

/// Extracts the final `retries` field from a method span record.
struct RetryVisitor(Option<u64>);
impl Visit for RetryVisitor {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "retries" {
            self.0 = Some(value);
        }
    }
    #[allow(clippy::cast_sign_loss)]
    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "retries" {
            self.0 = Some(value.max(0) as u64);
        }
    }
    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

/// Extracts query metrics from a `toasty::query` event.
#[derive(Default)]
struct QueryVisitor {
    duration_ms: f64,
    is_err: bool,
    statement: Option<String>,
}
impl Visit for QueryVisitor {
    fn record_f64(&mut self, field: &Field, value: f64) {
        if field.name() == "duration_ms" {
            self.duration_ms = value;
        }
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "db.statement" {
            self.statement = Some(value.to_owned());
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // toasty records `db.statement` and `error` through `field::display`,
        // which arrives here as `format_args!` (the bare Display string).
        match field.name() {
            "db.statement" => self.statement = Some(format!("{value:?}")),
            "error" => self.is_err = true,
            _ => {}
        }
    }
}

/// The two-source aggregating layer (see module docs).
pub struct DbMonitorLayer {
    monitor: DbMonitor,
}

impl DbMonitorLayer {
    #[must_use]
    pub const fn new(monitor: DbMonitor) -> Self {
        Self { monitor }
    }
}

impl<S> tracing_subscriber::Layer<S> for DbMonitorLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    // NOTE (no `register_callsite` override): an earlier revision overrode it
    // to return `Interest::always()`. That was reverted — it buys nothing and
    // the rationale was wrong:
    //
    // * In production it is inert. `main.rs` wraps this layer in
    //   `.with_filter(EnvFilter::…)`; `Filtered::register_callsite`
    //   (tracing-subscriber `filter/layer_filters/mod.rs`) calls the inner
    //   layer only for side effects and DISCARDS its `Interest`, returning
    //   `Interest::always()` itself — so the override could not change
    //   production behavior either way.
    // * The premise ("`never` is the default") was also wrong: `Layer::
    //   register_callsite` defaults to `Interest::always()` when `enabled()`
    //   is true (tracing-subscriber `layer/mod.rs`), and `enabled` defaults
    //   true. The `never` a test can observe comes from tracing-core's
    //   no-subscriber path, not from this layer.
    //
    // What actually protects the span is the DISPATCHER, not this layer's
    // interest: production installs the global subscriber before any callsite
    // is evaluated, so the verdict is always taken against the real filter
    // stack. A test that installs a thread-local subscriber AFTER the callsite
    // was first seen must re-arm the process-global interest cache with
    // `tracing::callsite::rebuild_interest_cache()` — see the attribution test
    // below.
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if attrs.metadata().target() != METHOD_TARGET {
            return;
        }
        if let Some(span) = ctx.span(id) {
            let name = span.metadata().name();
            span.extensions_mut()
                .insert(MethodSpan { name, retries: 0 });
        }
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        if let Some(ms) = ext.get_mut::<MethodSpan>() {
            let mut v = RetryVisitor(None);
            values.record(&mut v);
            if let Some(r) = v.0 {
                ms.retries = r;
            }
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() != QUERY_TARGET {
            return;
        }
        let mut v = QueryVisitor::default();
        event.record(&mut v);

        let method: &str = ctx
            .event_scope(event)
            .and_then(|mut scope| {
                scope.find_map(|s| s.extensions().get::<MethodSpan>().map(|m| m.name))
            })
            .unwrap_or(UNATTRIBUTED);

        self.monitor
            .fold_query(method, v.duration_ms, v.is_err, v.statement.as_deref());
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let ext = span.extensions();
        if let Some(ms) = ext.get::<MethodSpan>() {
            self.monitor.fold_close(ms.name, ms.retries);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_over_recorded_samples() {
        let mut r = Registry::default();
        for ms in 1..=100 {
            r.fold_query("load_page_rows", f64::from(ms), false, Some("SELECT 1"));
        }
        let s = &r.methods["load_page_rows"];
        assert_eq!(s.query_count, 100);
        // p50 of 1..=100 → index round(0.5*99)=50 → value 51.
        assert!((s.percentile(50.0) - 51.0).abs() < f64::EPSILON);
        // p99 → index round(0.99*99)=98 → value 99.
        assert!((s.percentile(99.0) - 99.0).abs() < f64::EPSILON);
    }

    #[test]
    fn counts_failures_and_keeps_slowest_sample() {
        let mut r = Registry::default();
        r.fold_query("upsert_link", 5.0, false, Some("INSERT a"));
        r.fold_query("upsert_link", 200.0, true, Some("INSERT slow"));
        r.fold_query("upsert_link", 10.0, false, Some("INSERT b"));
        let s = &r.methods["upsert_link"];
        assert_eq!(s.query_count, 3);
        assert_eq!(s.fail_count, 1);
        assert!((s.slowest.as_ref().unwrap().0 - 200.0).abs() < f64::EPSILON);
        assert_eq!(s.slowest.as_ref().unwrap().1, "INSERT slow");
    }

    #[test]
    fn fold_close_accumulates_invocations_and_retries() {
        let mut r = Registry::default();
        r.fold_close("apply_link_patches", 0);
        r.fold_close("apply_link_patches", 3);
        r.fold_close("apply_link_patches", 1);
        let s = &r.methods["apply_link_patches"];
        assert_eq!(s.invocations, 3);
        assert_eq!(s.retries, 4);
    }

    #[test]
    fn unattributed_bucket_aggregates_never_keys_by_text() {
        let mut r = Registry::default();
        r.fold_query(UNATTRIBUTED, 1.0, false, Some("PRAGMA busy_timeout=5000"));
        r.fold_query(UNATTRIBUTED, 2.0, false, Some("PRAGMA synchronous=NORMAL"));
        assert_eq!(r.methods.len(), 1);
        assert_eq!(r.methods[UNATTRIBUTED].query_count, 2);
    }

    #[test]
    fn sample_window_is_bounded() {
        let mut r = Registry::default();
        for _ in 0..(SAMPLE_CAP + 1000) {
            r.fold_query("hot", 7.0, false, None);
        }
        let s = &r.methods["hot"];
        assert_eq!(s.query_count as usize, SAMPLE_CAP + 1000);
        assert_eq!(s.samples.len(), SAMPLE_CAP);
    }

    #[test]
    fn ranked_orders_by_p99_desc() {
        let mut r = Registry::default();
        r.fold_query("fast", 1.0, false, None);
        r.fold_query("slow", 500.0, false, None);
        let lines = r.ranked(10);
        // header + 2 rows; first row after header is the slow method.
        assert!(lines[1].contains("slow"));
    }

    #[tracing::instrument(
        target = "db_method",
        name = "test_method",
        skip_all,
        fields(retries = tracing::field::Empty)
    )]
    async fn instrumented_op() {
        // Force the span to span an await point, mirroring toasty's async
        // driver: attribution must survive it.
        tokio::task::yield_now().await;
        tracing::debug!(
            target: "toasty::query",
            duration_ms = 42.0f64,
            db.statement = "SELECT * FROM profile_stats",
            "query executed"
        );
        tokio::task::yield_now().await;
        tracing::Span::current().record("retries", 2u64);
    }

    #[tokio::test]
    async fn attributes_query_events_across_await_and_folds_retries() {
        use tracing_subscriber::layer::SubscriberExt;
        let monitor = DbMonitor::new();
        let subscriber = tracing_subscriber::registry().with(DbMonitorLayer::new(monitor.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);

        instrumented_op().await;
        // An event outside any method span lands in the unattributed bucket.
        tracing::debug!(
            target: "toasty::query",
            duration_ms = 1.0f64,
            db.statement = "PRAGMA busy_timeout=5000",
            "query executed"
        );

        let dump = monitor.dump(10).join("\n");
        assert!(dump.contains("test_method"), "attributed to method: {dump}");
        assert!(
            dump.contains("retries=2"),
            "final retry count folded: {dump}"
        );
        assert!(
            dump.contains(UNATTRIBUTED),
            "unattributed bucket present: {dump}"
        );
    }

    #[tokio::test]
    async fn real_toasty_query_events_attribute_to_the_database_method() {
        use tracing_subscriber::layer::SubscriberExt;
        // Build the DB BEFORE installing the subscriber so schema-push
        // statements are not counted.
        let db = leas_db::Database::in_memory().await.expect("in-memory db");

        let monitor = DbMonitor::new();
        let subscriber = tracing_subscriber::registry().with(DbMonitorLayer::new(monitor.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);

        // A real instrumented `Database` method issues real `toasty::query`
        // events; they must land under the method, never `unattributed`.
        let _ = db.get_all_groups().await.expect("query");

        let dump = monitor.dump(10).join("\n");
        assert!(
            dump.contains("get_all_groups"),
            "real query attributed to method: {dump}"
        );
        assert!(
            !dump.contains(UNATTRIBUTED),
            "no leakage to unattributed: {dump}"
        );
    }

    /// F1 (final review 2026-10-05): the write-behind driver's flush is a
    /// `db_method` span, so its statements attribute to `write_behind_flush`
    /// rather than falling into the `unattributed` bucket.
    ///
    /// The tx-scoped callees carry no span by design, and the flush runs on a
    /// background task with no enclosing `Database` method — before the span
    /// this dump named only `unattributed`.
    #[tokio::test]
    async fn write_behind_flush_statements_attribute_to_the_flush_span() {
        // Attempts before giving up on the callsite registering at all.
        const ATTEMPTS: usize = 200;
        use tracing_subscriber::layer::SubscriberExt;
        // Build the DB BEFORE installing the subscriber so schema-push
        // statements are not counted.
        let db = std::sync::Arc::new(leas_db::Database::in_memory().await.expect("in-memory db"));

        let monitor = DbMonitor::new();
        let subscriber = tracing_subscriber::registry().with(DbMonitorLayer::new(monitor.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);
        // Re-arm the global interest cache before every attempt. The
        // `write_behind_flush` callsite's interest verdict is cached
        // process-globally and `DbMonitorLayer` no longer overrides
        // `register_callsite`; this thread-local subscriber must be the one the
        // next `Span::new` decides against.
        tracing::callsite::rebuild_interest_cache();

        // An endpoint to hang the resolved address off: `endpoint_ip` rows
        // carry a foreign key to it.
        let endpoint_id = leas_db::models::EndpointId::new(1);
        db.upsert_endpoint(&leas_db::models::Endpoint {
            id: endpoint_id,
            domain: String::new(),
            sub_domain: String::new(),
            port: 443,
            ports: Vec::new(),
            last_source: None,
            manual_protocol_override: None,
            resolved_at: None,
            created_at: leas_db::models::now_epoch(),
            links: toasty::Deferred::default(),
            group_links: toasty::Deferred::default(),
        })
        .await
        .expect("endpoint");

        let driver = leas_db::WriteBehind::<leas_db::CountrySpec>::new(
            std::sync::Arc::clone(&db),
            256,
            std::time::Duration::from_secs(5),
        );
        // Retry the flush until the span registers. The code under test is
        // deterministic; what is not is WHEN the `write_behind_flush`
        // callsite is first evaluated, because that verdict is cached
        // process-globally and other tests in this binary call
        // `WriteBehind::flush` from threads with no subscriber (the geo drain,
        // ping batches, import barriers). Re-arming the cache immediately
        // before each attempt makes the next `Span::new` decide against THIS
        // thread's dispatcher; the loop exists only because a concurrent
        // thread can re-poison the cache between the re-arm and the call. A
        // fresh row per attempt keeps every attempt a real write.
        let mut dump = String::new();
        for attempt in 0..ATTEMPTS {
            driver.push(leas_db::CountryRow {
                endpoint_id,
                ip: "198.51.100.7".parse().expect("ip"),
                iso: "US".to_owned(),
            });
            tracing::callsite::rebuild_interest_cache();
            driver.flush().await.expect("flush");
            dump = monitor.dump(10).join("\n");
            if dump.contains("write_behind_flush") {
                break;
            }
            assert!(
                attempt + 1 < ATTEMPTS,
                "the flush span never registered after {ATTEMPTS} attempts: {dump}"
            );
            // Yield so a competing thread's cached verdict can settle before
            // the next re-arm.
            tokio::task::yield_now().await;
        }

        assert!(
            dump.contains("write_behind_flush"),
            "flush statements attributed to the flush span: {dump}"
        );
        assert!(
            !dump.contains(UNATTRIBUTED),
            "no leakage to unattributed: {dump}"
        );
    }
}
