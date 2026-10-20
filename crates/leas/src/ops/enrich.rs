//! Background enrichment of endpoint display data.
//!
//! All network- and IO-bound work (DNS resolution, `GeoIP` mmdb lookups,
//! whitelist checks) runs in spawned tokio tasks that report back through
//! `CoreEvent::EndpointInfoUpdated`. The UI thread never blocks on them.
//! Every failure degrades to defaults (no flag / `🏴`) with a `tracing::warn!`.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
#[cfg(test)]
use std::time::Duration;

use leas_db::models::{EndpointId, HostType, Protocol};
use leas_host_features::HostFeatures;
use tokio::sync::Semaphore;

use crate::AppState;
use crate::ops::profiles::PROFILES_PAGE_SIZE;
use crate::types::{CoreEvent, EndpointInfo};

/// The SNI a link actually presents, for the whitelist/`🏳️` verdict.
///
/// **One owner with the engine:** [`leas_proto::proto_spec::ss_plugin::link_sni`],
/// so the name the whitelist judges is the name the handshake sends. It matters for plugin
/// rows, whose SNI is the plugin's `host` (or the endpoint host) rather than a stated
/// `security.sni` — and it returns `None` for a row with no TLS session at all, so an
/// `obfs=http`/`obfs=tls` row never gets a verdict computed from a fake name.
///
/// When the deferred config is not loaded, the `security.sni` **column** answers: it is
/// written at row-build time from `config.security().sni()` and is queryable without the
/// JSON. A plugin row has no stated SNI, so the column is `None` there — correct, because a
/// plugin row's SNI needs the config.
pub(crate) fn extract_sni(protocol: &Protocol, endpoint_host: &str) -> Option<String> {
    use leas_proto::proto_spec::ss_plugin::link_sni;
    if !protocol.config.is_unloaded() {
        return link_sni(&protocol.config.get().0, endpoint_host);
    }
    protocol.security.sni.clone()
}

/// Overall deadline for one resolution: resolver init (the `DNSCrypt` list
/// download) plus lookups across many name servers, which can otherwise stall
/// indefinitely.
///
/// Public because it is the other half of a relationship the settings have to
/// respect: the batch's DNS-failure deferral window must outlast this, or a
/// deferral expires before the lookup it defers can report. The two were
/// independent constants — 8s here against a 5s `default_dns_failure_defer_secs`
/// — and the window was the shorter of the pair.
pub const DNS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// The tick interval of the country driver's flush task.
///
/// NOT the loss window. Results are not lost on a crash, only delayed, and the
/// ceiling on that delay is `GEO_MAX_STAGED_AGE` (15 s) — the tick is only how
/// often the deadline is checked, in the same spirit as the link writer's
/// `max_staged_age`. The driver also writes well before the tick, as soon as
/// `GEO_FLUSH_AT` rows are staged.
pub const GEO_DRAIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Rows a flush window carries, and so the occupancy that forces a write
/// without waiting for the tick.
const GEO_FLUSH_AT: usize = 256;

/// Ceiling on how long a staged country may sit unpersisted.
///
/// NOT the drain interval: the driver's default deadline is 75 ticks, which at
/// a 5 s tick is 375 s — sixty-odd times the hard 5 s ceiling the hand-rolled
/// loop had, and far outside the seconds-long loss window the enrichment path
/// is allowed. The deadline is therefore named here, at 3 ticks.
const GEO_MAX_STAGED_AGE: std::time::Duration = std::time::Duration::from_secs(15);

/// The country driver, installed by [`spawn_geo_drain`] at the top of
/// `ui::run` — before any resolution task exists, so every
/// [`queue_country`] call finds it.
static GEO_DRIVER: std::sync::OnceLock<std::sync::Arc<leas_db::WriteBehind<leas_db::CountrySpec>>> =
    std::sync::OnceLock::new();

/// Warned once, not per row: a queue call with no driver is a lifecycle bug
/// (the UI was torn down), not a per-row condition worth a log line each.
static GEO_DRIVER_MISSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Queue one resolved country for the next batched write. Non-blocking: the
/// resolution task must not await a database write, or a fan-out of a few
/// thousand hosts would serialise behind it.
pub(crate) fn queue_country(endpoint_id: EndpointId, ip: std::net::IpAddr, iso: String) {
    let Some(driver) = GEO_DRIVER.get() else {
        if !GEO_DRIVER_MISSED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::warn!(
                target: "tui::ops::enrich",
                "country queued before the drain driver was installed — dropped",
            );
        }
        return;
    };
    driver.push(leas_db::CountryRow {
        endpoint_id,
        ip,
        iso,
    });
}

/// Install the country driver and run it until shutdown.
///
/// The driver owns the whole cadence — the `GEO_FLUSH_AT` window, the
/// `GEO_DRAIN_INTERVAL` tick, the [`GEO_MAX_STAGED_AGE`] deadline, and the
/// re-stage of a failed write — so this only supplies the database and the
/// shutdown edge. The final `flush` before the flush task is aborted is
/// today's "one last drain": a quit must not strand what is staged.
pub(crate) fn spawn_geo_drain(
    db: std::sync::Arc<leas_db::Database>,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let driver = leas_db::WriteBehind::<leas_db::CountrySpec>::new_with_deadline(
        db,
        GEO_FLUSH_AT,
        GEO_DRAIN_INTERVAL,
        GEO_MAX_STAGED_AGE,
    );
    if GEO_DRIVER.set(std::sync::Arc::clone(&driver)).is_err() {
        tracing::warn!(
            target: "tui::ops::enrich",
            "country drain driver already installed — keeping the first",
        );
    }
    let flush_task = driver.spawn_flush_task();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(GEO_DRAIN_INTERVAL).await;
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
        }
        // One last flush so a quit does not strand what is queued.
        if let Err(e) = driver.flush().await {
            tracing::warn!(
                target: "tui::ops::enrich",
                "final country flush failed: {e}",
            );
        }
        flush_task.abort();
    });
}

/// True when a resolution must run: no entry, no address and no attempt, or a
/// DNS entry older than the TTL, or `force`.
///
/// An entry with an empty address set AND no attempt timestamp is not an
/// IP-host entry and carries no resolution information: `spawn_outbound_enrich`
/// materializes exactly that shape (it knows the endpoint's exit IP, not its
/// inbound address). Treating it as "already resolved" is what made `[name]`
/// terminal for a DNS host whose first real ping landed before its first
/// resolution attempt.
const fn should_resolve(
    entry: Option<&EndpointInfo>,
    force: bool,
    ttl_secs: i64,
    now_secs: i64,
) -> bool {
    let Some(e) = entry else {
        return true;
    };
    // No address and no attempt is not a resolution — see the note above.
    if e.resolved_ips.is_empty() && e.resolved_at_secs.is_none() {
        return true;
    }
    // An IP host carries its own address and no attempt stamp: its address IS
    // the resolution, so it never re-resolves.
    let Some(ts) = e.resolved_at_secs else {
        return false;
    };
    force || now_secs - ts >= ttl_secs
}

/// A DNS hostname safe to hand to the resolver: ASCII letters/digits/hyphens
/// in dot-separated labels. Rejects plugin URLs (`host:port?plugin=...`),
/// underscores (Telegram-channel names), spaces and non-ASCII — hickory
/// errors on those ("Label contains invalid characters") and the failure is
/// pure log noise.
pub(crate) fn is_resolvable_hostname(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.contains("..") {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// `"{ip} | {country}"` (real-ping `ip_info` format) → `(ip, country-hint)`.
fn parse_ip_info(ip_info: &str) -> Option<(IpAddr, Option<String>)> {
    let (ip_part, country) = ip_info
        .split_once('|')
        .map_or((ip_info, None), |(a, b)| (a, Some(b.trim().to_string())));
    let ip = ip_part.trim().parse::<IpAddr>().ok()?;
    Some((ip, country))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Fill `country` (mmdb) and `host_features`/`sni_whitelisted` (whitelist
/// checker) for an entry. Selected IP = first IPv4, else first entry.
///
/// Returns the `(address, ISO)` the mmdb just produced, `None` when the
/// country was already known or no database is loaded. The caller persists
/// it — this function never writes, so the two call sites (the DNS resolve
/// and the page seed) own their own durability.
async fn fill_features(
    info: &mut EndpointInfo,
    geo: Option<&Arc<leas_geoip::GeoIp>>,
    checker: Option<&Arc<leas_host_features::HostFeaturesChecker>>,
    sni: Option<&str>,
) -> Option<(IpAddr, String)> {
    let selected = info
        .resolved_ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| info.resolved_ips.first())
        .copied();
    let mut fresh = None;
    if let Some(ip) = selected {
        // A country that came from `endpoint_ip` (or from this session's
        // earlier lookup) needs no mmdb walk — the store is the cache.
        if info.country.is_none()
            && let Some(geo) = geo
        {
            match geo.location_by_ip(ip).await {
                Ok(Some(loc)) => {
                    let iso = loc.country.to_string();
                    info.country = Some(iso.clone());
                    fresh = Some((ip, iso));
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(target: "tui::ops::enrich", "geo lookup failed: {e}"),
            }
        }
        if let Some(checker) = checker {
            info.host_features = checker.ip_features(ip);
        }
    }
    if let Some(checker) = checker
        && let Some(sni_str) = sni
    {
        info.sni_whitelisted = checker.sni_features(sni_str);
    }
    fresh
}

/// The stored country a feature pass would use for an endpoint: the
/// selection rule [`fill_features`] applies (first IPv4, else the first
/// entry), with the country that address carries.
fn stored_country(addrs: &[(IpAddr, Option<String>)]) -> Option<String> {
    addrs
        .iter()
        .find(|(ip, _)| ip.is_ipv4())
        .or_else(|| addrs.first())
        .and_then(|(_, country)| country.clone())
}

/// Resolve (or re-resolve) one endpoint's inbound host in the background.
///
/// TTL gate: fresh DNS entries are skipped (no network) unless `force`.
/// Results arrive via `CoreEvent::EndpointInfoUpdated`; DNS-host results are
/// persisted by the event handler so they survive launches.
///
/// Page-scoped: the row must be in the loaded page. A batch plans the whole
/// feed, so it sends [`CoreEvent::DnsResolveRequest`] and the handler calls
/// [`spawn_dns_resolve_host`] with the facts instead.
pub fn spawn_dns_resolve(state: &mut AppState, endpoint_id: i64, force: bool) {
    let Some(row) = state
        .endpoints
        .iter()
        .find(|r| r.endpoint.id.get() == endpoint_id)
    else {
        return;
    };
    let host = row.endpoint.dns_name();
    let host_type = leas_db::models::HostType::Dns;
    let sni = row
        .active_protocol()
        .and_then(|(_, p)| extract_sni(p, &row.endpoint.dns_name()));
    let trigger = if force {
        ResolveTrigger::Forced
    } else {
        ResolveTrigger::Routine
    };
    spawn_dns_resolve_host(state, endpoint_id, host, host_type, sni, trigger);
}

/// Bound on concurrent inbound resolutions.
///
/// A feed-wide batch asks for one resolution per DNS endpoint — ~18k on the
/// reference feed — and the trigger it replaces was bounded by
/// `real_ping_concurrency`. Every in-flight lookup holds a permit and one shared
/// hickory resolver's sockets, so without this the whole fan-out opens at once.
/// Acquired INSIDE the spawned task: taking a permit in `poll_core_events` would
/// stall the UI tick on DNS.
static RESOLVE_SEM: std::sync::LazyLock<Arc<Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(Semaphore::new(64)));

/// Who asked for a lookup — the three knobs (`TTL` gate, `RESOLVE_SEM`
/// permit, per-host waiter dedup) never vary independently:
///
/// - [`Routine`]: TTL-gated, bounded, deduped — background enrichment.
/// - [`Maintenance`]: TTL BYPASSED (the command re-asks failed names), but
///   still bounded and deduped — a feed-wide retry is exactly the fan-out the
///   semaphore exists to bound; unbounded it would open one socket per
///   unresolved endpoint at once.
/// - [`Forced`]: single-endpoint user action (the `x` key, the connect path)
///   — bypasses TTL and the bound (a fair queue behind a feed's fan-out would
///   look dead), and no per-host dedup: the user pressed the key on purpose.
///
/// [`Routine`]: ResolveTrigger::Routine
/// [`Maintenance`]: ResolveTrigger::Maintenance
/// [`Forced`]: ResolveTrigger::Forced
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveTrigger {
    Routine,
    Maintenance,
    Forced,
}

/// Optional completion meter for in-flight lookups, installed by the DNS
/// retry (its `Name` bar). Swap-able: the retry installs a fresh meter, and
/// every completed lookup — whatever its trigger — bumps `done`, so the bar
/// tracks the fleet while the meter exists.
static RESOLVE_PROGRESS: std::sync::RwLock<Option<Arc<crate::types::PhaseMeters>>> =
    std::sync::RwLock::new(None);

/// Install (or clear, `None`) the DNS-retry completion meter.
pub(crate) fn set_resolve_progress(meter: Option<Arc<crate::types::PhaseMeters>>) {
    let mut guard = RESOLVE_PROGRESS.write().expect("resolve meter lock");
    *guard = meter;
}

fn bump_resolve_progress() {
    let meter = RESOLVE_PROGRESS.read().ok().and_then(|guard| guard.clone());
    if let Some(meter) = meter {
        meter.done.fetch_add(1, Ordering::Relaxed);
    }
}

/// Endpoint ids waiting on the lookup currently running for each host.
///
/// Keyed by the HOST, not the endpoint: a feed routinely carries one hostname
/// on many rows (different ports, different protocols), and the old
/// per-endpoint dedup — [`should_resolve`] against each endpoint's own
/// `endpoint_info` entry, which a failed lookup cannot write — asked the
/// resolver the same question once per row. The 2026-09-27 run logged 19
/// lookups for a single dead hostname inside one TTL window, and the network
/// work is the expensive part: each costs an 8s deadline and a `RESOLVE_SEM`
/// permit.
///
/// A waiter still gets its OWN `EndpointInfoUpdated`: the answer is fanned out
/// to every id registered here, because the result is per-endpoint state (an
/// `endpoint_info` entry, a `profile_stats` refresh) even though the query is
/// per-host. Sharing the query without fanning the answer would leave the
/// siblings `[name]` forever — the regression this replaces.
static LOOKUP_WAITERS: std::sync::LazyLock<dashmap::DashMap<String, Vec<i64>>> =
    std::sync::LazyLock::new(dashmap::DashMap::new);

/// The key a host is deduplicated under: case-insensitive, trailing dot
/// dropped, so `Example.COM` and `example.com.` share one lookup.
pub(crate) fn lookup_key(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Resolve one endpoint's inbound host from facts the caller already holds.
///
/// The TTL gate ([`should_resolve`]) is evaluated here, against the session's
/// `endpoint_info`, so repeated requests for the same endpoint collapse to one
/// lookup and a fresh resolution is never repeated. Requests for DIFFERENT
/// endpoints sharing a host collapse too, one level up: the first caller runs
/// the query and later callers register as waiters on [`LOOKUP_WAITERS`], and
/// the answer is fanned out to all of them.
pub fn spawn_dns_resolve_host(
    state: &mut AppState,
    endpoint_id: i64,
    host: String,
    host_type: HostType,
    sni: Option<String>,
    trigger: ResolveTrigger,
) {
    let scheduler = state.scheduler.clone();
    if !should_resolve(
        state.endpoint_info.get(&endpoint_id),
        trigger != ResolveTrigger::Routine,
        state.dns_cache_ttl_secs,
        unix_now(),
    ) {
        // The SESSION says this host was resolved recently, so no lookup runs.
        // The batch may still have marked the endpoint in flight — it gates on
        // the PERSISTED attempt, which is a different fact and can be stale
        // while the session entry is fresh. The two gates disagree exactly
        // there, and the marker is cleared by the only code that runs on this
        // path; without this the endpoint's links defer forever and the batch's
        // self-looping retry never ends.
        scheduler.end_dns_lookup(EndpointId::new(endpoint_id));
        return;
    }

    let dns = state.dns_resolver.clone();
    let geo = state.geo_ip.clone();
    let checker = state.host_features.clone();
    // No `db` clone: the country write is QUEUED (see `queue_country`), so this
    // task no longer opens a transaction of its own.
    let tx = state.core_event_tx.clone();

    // The endpoint is now waiting on an answer that does not exist yet, so the
    // batch's gate must not schedule it: a link dispatched in the same
    // iteration as the request would otherwise be probed before the resolver
    // has been asked, and could only measure the wrong thing.
    scheduler.begin_dns_lookup(EndpointId::new(endpoint_id));

    // An IP host is parsed, not queried, and a forced lookup is a user action
    // on one specific endpoint — neither shares a per-host query.
    let key = (host_type == HostType::Dns && trigger != ResolveTrigger::Forced)
        .then(|| lookup_key(&host));
    if let Some(key) = &key
        && let Some(mut waiters) = LOOKUP_WAITERS.get_mut(key)
    {
        if !waiters.contains(&endpoint_id) {
            waiters.push(endpoint_id);
        }
        return;
    }
    if let Some(key) = &key {
        LOOKUP_WAITERS.insert(key.clone(), vec![endpoint_id]);
    }
    let waiters_key = key;

    tokio::spawn(async move {
        let now = unix_now();
        // Whether the resolution produced a usable answer; `false` feeds the
        // scheduler's DNS-failure gate below. IP hosts and hosts without a
        // resolver configured count as fine.
        let mut resolved_ok = true;
        // DNS lookup or direct IP parse
        let (ips, resolved_at) = match host_type {
            HostType::Ipv4 | HostType::Ipv6 => (
                host.parse::<IpAddr>()
                    .map(|ip| vec![ip])
                    .unwrap_or_default(),
                None,
            ),
            HostType::Undefined => {
                resolved_ok = false;
                (Vec::new(), Some(now))
            }
            HostType::Dns => {
                if is_resolvable_hostname(&host) {
                    match &dns {
                        Some(r) => {
                            // Overall deadline: resolver init (DNSCrypt list
                            // download) plus lookups over many name servers
                            // can otherwise stall indefinitely.
                            //
                            // The semaphore permit is acquired INSIDE this
                            // deadline, deliberately — one permit per in-flight
                            // lookup ([`RESOLVE_SEM`]). A FORCED lookup (the `x`
                            // key, the connect path) bypasses the bound: the
                            // semaphore is fair, so a user-triggered resolve
                            // would otherwise queue behind a whole feed's
                            // fan-out and look dead, and one request cannot
                            // flood anything.
                            //
                            // Acquiring it OUTSIDE (as this did) left the queue
                            // wait unbounded and uncounted, so request→report was
                            // unbounded — and that is what broke the batch's
                            // deferral. `defer_retry` measures its budget from
                            // the FIRST deferral while `mark_dns_failure` arms
                            // its 15 s window at REPORT time, so a tail lookup
                            // that queued past the budget armed a window the
                            // budget could never outlast; the 2026-10-01 run
                            // booked 12 halves unprobed that way. Bounding the
                            // wait to `DNS_LOOKUP_TIMEOUT` makes report time a
                            // function of the timeout alone.
                            let bounded = async {
                                let _permit = if trigger == ResolveTrigger::Forced {
                                    None
                                } else {
                                    let permit =
                                        Arc::clone(&RESOLVE_SEM).acquire_owned().await.ok()?;
                                    Some(permit)
                                };
                                Some(r.lookup_ip(&host, true).await)
                            };
                            match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, bounded).await {
                                // `Some(...)` means the permit was taken and the
                                // lookup ran inside the deadline.
                                Ok(Some(Ok(ips))) => {
                                    // SESSION-ONLY, deliberately. This was `info`,
                                    // and the 2026-10-01 run showed it was **933 of
                                    // the 1,313 persisted entries (79%)** — one
                                    // LMDB row per resolved host, kept forever.
                                    // The information is already durable in
                                    // `endpoint_ip` and `endpoints.resolved_at`,
                                    // and `ping.rs` made its per-result lines
                                    // session-only for the same reason. The same
                                    // flood is what filled the 10,000-row
                                    // `log_cache` cap that truncated the export.
                                    tracing::debug!(
                                        target: "tui::ops::enrich",
                                        "Resolved {host}: {} IP(s)",
                                        ips.len()
                                    );
                                    // `Box<[IpAddr]>` → `Vec`: reuses the
                                    // allocation, no copy.
                                    (Vec::from(ips), Some(now))
                                }
                                Ok(Some(Err(e))) => {
                                    resolved_ok = false;
                                    if e.to_string().contains("no records found") {
                                        // Host without any DNS record — the
                                        // UI flag carries the signal; don't
                                        // warn per host per TTL.
                                        tracing::debug!(
                                            target: "tui::ops::enrich",
                                            "DNS lookup of {host} found no records"
                                        );
                                    } else {
                                        tracing::warn!(
                                            target: "tui::ops::enrich",
                                            "DNS lookup of {host} failed: {e}"
                                        );
                                    }
                                    (Vec::new(), Some(now))
                                }
                                // `None` means the permit was never taken: the
                                // semaphore closed (the runtime is going away).
                                // Release the waiters so their endpoints do not
                                // defer forever — the old `acquire_owned`
                                // failure path did exactly this.
                                Ok(None) => {
                                    release_waiters(waiters_key.as_ref(), endpoint_id, &scheduler);
                                    return;
                                }
                                Err(_) => {
                                    resolved_ok = false;
                                    tracing::warn!(
                                        target: "tui::ops::enrich",
                                        "DNS lookup of {host} timed out"
                                    );
                                    (Vec::new(), Some(now))
                                }
                            }
                        }
                        None => (Vec::new(), None),
                    }
                } else {
                    // Plugin URLs / garbage hostnames can never resolve;
                    // record a failed attempt (TTL-gated) instead of firing
                    // hickory parse errors on every refresh.
                    resolved_ok = false;
                    tracing::debug!(
                        target: "tui::ops::enrich",
                        "Skipping DNS lookup for invalid hostname: {host}"
                    );
                    (Vec::new(), Some(now))
                }
            }
        };

        // The lookup (or its failure) has an answer now: the maintenance
        // retry's Name bar counts completions, not dispatches.
        bump_resolve_progress();

        // Every endpoint waiting on this host shares the answer, so the whole
        // set is settled here: the per-host registry is released (a later
        // request must be able to start a fresh lookup), the batch's gate is
        // told the answer is in, and each id gets its own event.
        let waiters = take_waiters(waiters_key.as_ref(), endpoint_id);
        for id in &waiters {
            let endpoint = EndpointId::new(*id);
            scheduler.end_dns_lookup(endpoint);
            if resolved_ok {
                scheduler.clear_dns_failure(endpoint);
            } else {
                scheduler.mark_dns_failure(endpoint);
            }
        }

        let mut info = EndpointInfo {
            resolved_ips: ips,
            country: None,
            host_features: HostFeatures::default(),
            sni_whitelisted: None,
            outbound_ip: None,
            outbound_country: None,
            resolved_at_secs: resolved_at,
        };
        // Phase 1: deliver the resolution immediately — the UI must never
        // wait on geo/whitelist work (the mmdb can download on first use).
        if let Some(t) = tx.as_ref() {
            for id in &waiters {
                let _ = t.try_send(CoreEvent::EndpointInfoUpdated {
                    endpoint_id: *id,
                    info: info.clone(),
                });
            }
        }
        // Phase 2: country + whitelist features. Bounded by the geo crate's
        // own download deadline; a timeout here still degrades to `🏴`.
        // A country the mmdb just produced is written to `endpoint_ip` (the
        // table owns the address's flag; `replace` keeps it across
        // re-resolutions), so the next launch renders it without a lookup.
        //
        // QUEUED, not written here. This used to call the per-address writer once
        // per waiter — its own connection, transaction and commit — and `break` on
        // the first error, abandoning the rest. The 2026-10-01 run measured that
        // as **790 invocations / 8,608 statements / 88 aborts** at a p99 of
        // 1,051 ms against an isolated 108 µs: the cost was contention from
        // concurrent single-row transactions, not the writes themselves. Rows now
        // accumulate ACROSS hosts and leave in one transaction (see
        // `WriteBehind<CountrySpec>`).
        if let Some((ip, iso)) =
            fill_features(&mut info, geo.as_ref(), checker.as_ref(), sni.as_deref()).await
        {
            for id in &waiters {
                queue_country(EndpointId::new(*id), ip, iso.clone());
            }
        }
        if let Some(t) = tx {
            for id in &waiters {
                let _ = t.try_send(CoreEvent::EndpointInfoUpdated {
                    endpoint_id: *id,
                    info: info.clone(),
                });
            }
        }
    });
}

/// Take the waiters registered for `key`. A non-DNS or forced lookup never
/// registers — an IP host is parsed and a forced lookup is one user action on
/// one endpoint — so it serves only `fallback`, its own id. Without that
/// fallback those lookups would emit no event at all and would leave a
/// permanent in-flight marker, deferring their links forever.
fn take_waiters(key: Option<&String>, fallback: i64) -> Vec<i64> {
    key.and_then(|k| LOOKUP_WAITERS.remove(k).map(|(_, ids)| ids))
        .filter(|ids| !ids.is_empty())
        .unwrap_or_else(|| vec![fallback])
}

/// Release the waiters a lookup will never answer (the runtime shut down
/// between registering them and acquiring a permit). Their in-flight markers
/// go with them, for the same reason as the fallback above.
fn release_waiters(
    key: Option<&String>,
    fallback: i64,
    scheduler: &crate::ops::scheduler::TaskScheduler,
) {
    for id in take_waiters(key, fallback) {
        scheduler.end_dns_lookup(EndpointId::new(id));
    }
}

/// One enrichment target: endpoint id, its persisted `endpoint_ip` address set,
/// the persisted `resolved_at` (unix secs), and the SNI of its active protocol
/// (None for linkless endpoints). An IP-literal endpoint's address is IN the
/// set (db-rewamp D10) — `is_dns()` distinguishes a DNS host without one.
type EnrichTarget = (i64, Vec<IpAddr>, Option<i64>, Option<String>);

/// Startup/refresh pass: seed `endpoint_info` for every endpoint that has no
///
/// entry yet — IP hosts (parse host, no DNS) and DNS hosts with a persisted
/// `endpoint_ip` address set (no network). Geo + whitelist
/// features are filled in the same task.
pub fn spawn_enrich_ip_hosts(state: &mut AppState) {
    let targets: Vec<EnrichTarget> = state
        .endpoints
        .iter()
        .filter(|r| (!r.endpoint.is_dns()) || !r.resolved_ips.is_empty())
        // An entry with no address and no attempt timestamp carries no
        // resolution information (an outbound-only event materializes one), so
        // it must still be seeded rather than treated as already resolved.
        .filter(|r| {
            state
                .endpoint_info
                .get(&r.endpoint.id.get())
                .is_none_or(|e| e.resolved_ips.is_empty() && e.resolved_at_secs.is_none())
        })
        .map(|r| {
            (
                r.endpoint.id.get(),
                r.resolved_ips.clone(),
                r.endpoint.resolved_at,
                r.active_protocol()
                    .and_then(|(_, p)| extract_sni(p, &r.endpoint.dns_name())),
            )
        })
        .collect();
    if targets.is_empty() {
        return;
    }

    // Phase 1 runs SYNCHRONOUSLY here: insert the cached resolution directly
    // into `endpoint_info` instead of round-tripping an event. The old
    // phase-1 `EndpointInfoUpdated` events looked identical to real DNS
    // resolutions to the event handler, which re-persisted
    // `update_endpoint_resolution` + `upsert_resolved_ip_children` for EVERY
    // already-resolved endpoint on every reload (7000 redundant write pairs
    // after a 7000-URL import).
    let mut feature_targets: Vec<(i64, EndpointInfo, Option<String>)> =
        Vec::with_capacity(targets.len());
    for (endpoint_id, cached_as, cached_at, sni) in targets {
        let mut info = if cached_as.is_empty() {
            // No `endpoint_ip` row: an exotic host with no literal to carry.
            // The seed filter admitted it, so it stays explicit (the
            // unspecified address is a placeholder, never dialed) rather than
            // silently empty.
            EndpointInfo {
                resolved_ips: vec![
                    cached_as
                        .first()
                        .copied()
                        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                ],
                country: None,
                host_features: HostFeatures::default(),
                sni_whitelisted: None,
                outbound_ip: None,
                outbound_country: None,
                resolved_at_secs: None,
            }
        } else {
            // DNS host with a persisted resolution — reuse it, no network and
            // no text parse: the stored form is the address itself.
            EndpointInfo {
                resolved_ips: cached_as,
                country: None,
                host_features: HostFeatures::default(),
                sni_whitelisted: None,
                outbound_ip: None,
                outbound_country: None,
                resolved_at_secs: cached_at,
            }
        };
        // An entry the seed is allowed to replace may still carry the exit-IP
        // fields an outbound-only event wrote (that event knows the endpoint's
        // outbound IP, never its inbound address, so it cannot fill
        // `resolved_ips`). Those fields are not the seed's to drop.
        if let Some(existing) = state.endpoint_info.get(&endpoint_id) {
            info.outbound_ip = existing.outbound_ip;
            info.outbound_country.clone_from(&existing.outbound_country);
        }
        state.endpoint_info.insert(endpoint_id, info.clone());
        feature_targets.push((endpoint_id, info, sni));
    }
    state.mark_rows_dirty(crate::ui::profiles::ROWS_DIRTY_COUNTRY);

    // Phase 2 stays in the background: mmdb may download on first use and
    // must never stall the UI task. Feature fields only — the handler's
    // persist branch stays silent because the seeded `resolved_at_secs` now
    // equals the incoming value.
    let geo = state.geo_ip.clone();
    let checker = state.host_features.clone();
    let db = state.db.clone();
    let tx = state.core_event_tx.clone();

    tokio::spawn(async move {
        // Countries land one transaction per page, not one commit per address:
        // `set_endpoint_ip_country` paid a full commit each (~4.2 ms,
        // `docs/database.md`) and those commits contended with the import's
        // 500-URL chunk transactions (`database is locked`). A failed batch
        // logs once and the pass carries on — the next page still writes.
        async fn flush_countries(
            db: &leas_db::Database,
            pending: &mut Vec<(EndpointId, IpAddr, String)>,
            flushes: &mut usize,
        ) {
            let rows = std::mem::take(pending);
            if rows.is_empty() {
                return; // the tail call is unconditional; an empty one writes nothing
            }
            *flushes += 1;
            if let Err(e) = db.set_endpoint_ip_countries(&rows).await {
                tracing::warn!(
                    target: "tui::ops::enrich",
                    "country persist failed for {} rows: {e}",
                    rows.len()
                );
            }
        }

        // The countries already stored for this page's addresses: one read,
        // and every address that has one skips the mmdb entirely (a second
        // launch needs no `geo_ip` at all). Read here rather than in the
        // synchronous seed above so the seed stays callable from a
        // non-async caller.
        let ids: Vec<EndpointId> = feature_targets
            .iter()
            .map(|(id, ..)| EndpointId::new(*id))
            .collect();
        let stored = match db.endpoint_resolutions(&ids).await {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(target: "tui::ops::enrich", "stored countries read failed: {e}");
                std::collections::HashMap::new()
            }
        };
        let mut pending: Vec<(EndpointId, IpAddr, String)> = Vec::with_capacity(PROFILES_PAGE_SIZE);
        let mut scanned = 0usize;
        let mut countries = 0usize;
        let mut flushes = 0usize;
        for (endpoint_id, mut info, sni) in feature_targets {
            scanned += 1;
            if info.country.is_none() {
                info.country = stored
                    .get(&EndpointId::new(endpoint_id))
                    .and_then(|addrs| stored_country(addrs));
            }
            let fresh =
                fill_features(&mut info, geo.as_ref(), checker.as_ref(), sni.as_deref()).await;
            if let Some((ip, iso)) = fresh {
                countries += 1;
                pending.push((EndpointId::new(endpoint_id), ip, iso));
            }
            if let Some(t) = tx.as_ref() {
                let _ = t.try_send(CoreEvent::EndpointInfoUpdated { endpoint_id, info });
            }
            if pending.len() >= PROFILES_PAGE_SIZE {
                flush_countries(&db, &mut pending, &mut flushes).await;
            }
        }
        // The tail: the last partial page still has to land.
        flush_countries(&db, &mut pending, &mut flushes).await;
        tracing::debug!(
            target: "tui::ops::enrich",
            "geo seed: scanned={scanned} countries={countries} flushes={flushes}"
        );
    });
}

/// Refresh whitelist features (ip/cidr + SNI) for every endpoint once the
///
/// checker has loaded. Runs on every launch — features are never persisted, so
/// cached entries get fresh membership. Sends a full copy of each entry.
pub fn spawn_whitelist_pass(state: &mut AppState) {
    let Some(checker) = state.host_features.clone() else {
        return;
    };
    let targets: Vec<(i64, Option<String>, EndpointInfo)> = state
        .endpoints
        .iter()
        .map(|r| {
            (
                r.endpoint.id.get(),
                r.active_protocol()
                    .and_then(|(_, p)| extract_sni(p, &r.endpoint.dns_name())),
                state
                    .endpoint_info
                    .get(&r.endpoint.id.get())
                    .cloned()
                    .unwrap_or_default(),
            )
        })
        .collect();
    if targets.is_empty() {
        return;
    }
    let tx = state.core_event_tx.clone();

    tokio::spawn(async move {
        for (endpoint_id, sni, mut info) in targets {
            let selected = info
                .resolved_ips
                .iter()
                .find(|ip| ip.is_ipv4())
                .or_else(|| info.resolved_ips.first())
                .copied();
            if let Some(ip) = selected {
                info.host_features = checker.ip_features(ip);
            }
            info.sni_whitelisted = sni.as_deref().and_then(|s| checker.sni_features(s));

            if let Some(t) = tx.clone() {
                let _ = t.try_send(CoreEvent::EndpointInfoUpdated { endpoint_id, info });
            }
        }
    });
}

/// Seed the outbound-IP country cache at profile load.
///
/// Collects the distinct exit IPs persisted on links (`Latency::Real.ip`),
/// looks each up in mmdb and fills `state.outbound_country_cache` — async, so
/// IPs render immediately and flags a moment later. Survives reruns: the
/// source IPs are persisted and this re-runs at every load.
pub fn spawn_outbound_countries(state: &mut AppState) {
    let mut ips = std::collections::HashSet::new();
    for row in &state.endpoints {
        for link in &row.links {
            if let Some(leas_db::models::Latency::Real { ip: Some(ip), .. }) = &link.latency {
                ips.insert(ip.clone());
            }
        }
    }
    if ips.is_empty() {
        return;
    }
    let geo = state.geo_ip.clone();
    let cache = state.outbound_country_cache.clone();
    tokio::spawn(async move {
        let Some(geo) = geo else { return };
        for ip in ips {
            let Ok(ipaddr) = ip.parse::<std::net::IpAddr>() else {
                continue;
            };
            let country = match geo.location_by_ip(ipaddr).await {
                Ok(Some(loc)) => Some(loc.country.to_string()),
                _ => None,
            };
            cache.lock().push(ip, country);
        }
    });
}

/// Record the exit (egress) IP + country of a real ping on the endpoint that
///
/// owns `protocol_id`. The IP is parsed from real-ping `ip_info`
/// (`"{ip} | {country}"`); the country hint string is replaced by the mmdb ISO
/// code. Sends a full copy of the entry with outbound fields set.
pub fn spawn_outbound_enrich(state: &mut AppState, endpoint_id: i64, ip_info: Option<String>) {
    let Some(ip_info) = ip_info else {
        return;
    };
    let Some((outbound_ip, _hint)) = parse_ip_info(&ip_info) else {
        return;
    };
    // The caller knows the endpoint that ran the probe (the SpeedTestResult
    // event carries it). Never resolve by protocol: shared `Protocol` rows
    // would point the exit IP at the first owner's endpoint.
    if !state
        .endpoints
        .iter()
        .any(|r| r.endpoint.id.get() == endpoint_id)
    {
        return;
    }

    let geo = state.geo_ip.clone();
    let mut info = state
        .endpoint_info
        .get(&endpoint_id)
        .cloned()
        .unwrap_or_default();
    info.outbound_ip = Some(outbound_ip);
    let cache = state.outbound_country_cache.clone();
    let tx = state.core_event_tx.clone();

    tokio::spawn(async move {
        // Phase 1: show the exit IP immediately; the country lookup follows
        // (mmdb may download on first use — must not delay the IP).
        if let Some(t) = tx.as_ref() {
            let _ = t.try_send(CoreEvent::EndpointInfoUpdated {
                endpoint_id,
                info: info.clone(),
            });
        }
        if let Some(geo) = &geo {
            match geo.location_by_ip(outbound_ip).await {
                Ok(Some(loc)) => {
                    info.outbound_country = Some(loc.country.to_string());
                    cache
                        .lock()
                        .push(outbound_ip.to_string(), Some(loc.country.to_string()));
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(target: "tui::ops::enrich", "outbound geo lookup failed: {e}");
                }
            }
        }
        if let Some(t) = tx {
            let _ = t.try_send(CoreEvent::EndpointInfoUpdated { endpoint_id, info });
        }
    });
}

/// Drain everything the country driver has staged for `ids` — the merge's
/// anti-resurrection guard. A `CountrySpec` patch flushing after the endpoint
/// delete would silently re-create an orphan `endpoint_ip` row (no FKs,
/// ADR 0011), so the maintenance command discards by absorbed id first.
/// Returns the number of discarded entries.
pub(crate) fn discard_country_for(ids: &[i64]) -> usize {
    GEO_DRIVER
        .get()
        .map_or(0, |driver| driver.discard_where(|k| ids.contains(&k.get())))
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    /// The flag a DNS endpoint shows must come from `endpoint_ip` when it is
    /// already stored: the seed reads it back and the mmdb is never asked.
    /// (The state's `geo_ip` is whatever the fixture config built — the
    /// assertion holds because the stored country short-circuits the
    /// lookup, not because a database happened to be present.)
    #[tokio::test]
    async fn stored_country_reaches_the_ui_without_the_mmdb() {
        use crate::ops::profiles::test_support::{fake_row, test_state};
        let mut row = fake_row(7, "dns.example", 1);
        row.endpoint.domain = "dns.example".to_string();
        row.endpoint.sub_domain = String::new();
        row.endpoint.resolved_at = Some(60);
        row.resolved_ips = vec!["1.1.1.1".parse().expect("ip")];
        let mut state = test_state(vec![row]).await;
        state
            .db
            .set_endpoint_ip_country(EndpointId::new(7), "1.1.1.1".parse().expect("ip"), "US")
            .await
            .expect("stored country");

        spawn_enrich_ip_hosts(&mut state);
        for _ in 0..100 {
            let _ = state.poll_core_events().await;
            if state
                .endpoint_info
                .get(&7)
                .and_then(|i| i.country.clone())
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            state
                .endpoint_info
                .get(&7)
                .and_then(|i| i.country.clone())
                .as_deref(),
            Some("US"),
            "the stored country is the one the row renders"
        );
    }

    /// One host → resolvable table: the valid-domain set and the garbage set
    /// (plugin URLs, port suffixes, Telegram-channel names with underscores,
    /// spaces and non-ASCII — all hickory errors) as named rows.
    #[rstest]
    #[case::accepts_example_com("example.com", true)]
    #[case::accepts_cdn_subdomain("cdn.example.com", true)]
    #[case::accepts_deeply_nested_subdomain("like.myolddomain.kesug.com", true)]
    #[case::accepts_short_two_label("x.com", true)]
    #[case::accepts_hyphenated_label("a-b.example.com", true)]
    #[case::accepts_trailing_dot_fqdn("example.com.", true)]
    #[case::rejects_empty("", false)]
    #[case::rejects_plugin_url("1.2.3.4:8388?plugin=obfs-local;obfs=tls;obfs-host=x", false)]
    #[case::rejects_underscore_channel_name("v2ray_configs_poolsTELEGRAM.kesug.com", false)]
    #[case::rejects_space("foo bar.com", false)]
    #[case::rejects_empty_label("foo..com", false)]
    #[case::rejects_leading_dot(".foo.com", false)]
    #[case::rejects_leading_hyphen("-foo.com", false)]
    #[case::rejects_trailing_hyphen("foo-.com", false)]
    #[case::rejects_at_sign("foo@bar.com", false)]
    #[case::rejects_non_ascii("exämple.com", false)]
    #[case::rejects_underscore("foo_com.com", false)]
    fn is_resolvable_hostname_over_inputs(#[case] host: &str, #[case] expected: bool) {
        assert_eq!(is_resolvable_hostname(host), expected, "{host:?}");
    }

    #[test]
    fn test_iso_to_flag() {
        assert_eq!(crate::iso_to_flag("US"), "\u{1F1FA}\u{1F1F8}");
        assert_eq!(crate::iso_to_flag("USA"), "\u{1F3F4}");
        assert_eq!(crate::iso_to_flag(""), "\u{1F3F4}");
        assert_eq!(crate::iso_to_flag("U1"), "\u{1F3F4}");
    }

    #[test]
    fn test_should_resolve() {
        let now = 1_000_000i64;
        let ttl = 300;
        // No entry → resolve
        assert!(should_resolve(None, false, ttl, now));
        // Fresh DNS entry → skip
        let fresh = EndpointInfo {
            resolved_ips: vec!["1.2.3.4".parse().unwrap()],
            resolved_at_secs: Some(now),
            ..Default::default()
        };
        assert!(!should_resolve(Some(&fresh), false, ttl, now));
        // Stale → resolve
        let stale = EndpointInfo {
            resolved_at_secs: Some(now - ttl - 1),
            ..fresh.clone()
        };
        assert!(should_resolve(Some(&stale), false, ttl, now));
        // force → resolve regardless
        assert!(should_resolve(Some(&fresh), true, ttl, now));
        // An outbound-only entry (no address, no attempt) carries no resolution
        // information, so it must NOT read as "already resolved": treating it
        // that way is what made `[name]` terminal for a DNS host whose first
        // real ping landed before its first resolution attempt.
        let outbound_only = EndpointInfo {
            outbound_ip: Some("5.6.7.8".parse().unwrap()),
            ..Default::default()
        };
        assert!(should_resolve(Some(&outbound_only), false, ttl, now));
        // ...but an entry whose address set is non-empty with no attempt stamp
        // is an IP host, and never re-resolves.
        let ip_host = EndpointInfo {
            resolved_at_secs: None,
            ..fresh
        };
        assert!(!should_resolve(Some(&ip_host), false, ttl, now));
        assert!(!should_resolve(Some(&ip_host), true, ttl, now));
    }

    #[test]
    fn test_parse_ip_info() {
        assert_eq!(
            parse_ip_info("1.2.3.4 | Germany").map(|(ip, _)| ip),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            parse_ip_info("1.2.3.4 | Germany").map(|(_, c)| c),
            Some(Some("Germany".to_string()))
        );
        assert!(parse_ip_info("not-an-ip | x").is_none());
    }

    #[test]
    fn test_extract_sni() {
        // Real vless+reality URL → typed rows → Security embed sni column
        let parsed = leas_config::import_export::parse_share_url(
            "vless://550e8400-e29b-41d4-a716-446655440000@example.com:443?security=reality&sni=chat.example.com&encryption=none&type=tcp",
            &leas_config::import_export::ValidationSettings::default(),
        )
        .expect("parse vless url");
        let protocol = crate::state::protocol_from_parsed(&parsed.parsed);
        assert_eq!(
            extract_sni(&protocol, "server.example").as_deref(),
            Some("chat.example.com")
        );
    }

    /// Row 16, the half that was missing. The test above calls `link_sni`
    /// DIRECTLY, which cannot fail when the two CALLERS drift apart: one of them
    /// could stop routing through the shared resolver and this would still pass,
    /// while the engine dialled with one SNI and enrichment recorded another —
    /// the exact split §5.1 exists to prevent.
    ///
    /// So this drives BOTH public callers on the same stored row and compares
    /// their answers, on the two shapes that matter: a row that STATES a host,
    /// and a host-less row that falls back to the endpoint.
    #[test]
    fn the_engine_and_enrichment_cannot_disagree_on_a_plugin_sni() {
        use leas_native::context::{LinkContext, NativeConnectParams};
        use leas_proto::proto_spec::common::SecurityConfig;
        use leas_proto::proto_spec::{EndpointEssentials, PluginSpec, ProtocolConfig, SsConfig};

        for (opts, expect) in [
            ("host=cdn.example;tls", "cdn.example"),
            ("tls", "fallback.example"),
        ] {
            let config = ProtocolConfig::Ss(SsConfig {
                method: "aes-256-gcm".into(),
                password: "pw".into(),
                security: SecurityConfig::default(),
                remarks: None,
                plugin: Some(PluginSpec::from_parts(Some("v2ray-plugin"), opts)),
            });
            let host = if expect == "fallback.example" {
                "fallback.example"
            } else {
                "server.example"
            };

            // Caller 1: the engine, through LinkContext.
            let params = NativeConnectParams::new(
                config.clone(),
                EndpointEssentials::new(host, 443),
                leas_native::addr::TargetAddr::new(
                    leas_native::addr::Host::Domain("example.com".into()),
                    80,
                ),
            );
            let engine = LinkContext::new(
                params,
                leas_native::addr::TargetAddr::new(
                    leas_native::addr::Host::Domain("example.com".into()),
                    80,
                ),
            )
            .server_name();

            // Caller 2: enrichment, through the persisted Protocol row.
            let protocol = leas_db::models::Protocol {
                id: leas_db::models::ProtocolId::new(1),
                sig: 1,
                proto_kind: leas_proto::proto_spec::ProtocolKind::Shadowsocks,
                transport: leas_db::models::Transport {
                    r#type: leas_proto::proto_spec::TransportType::Tcp,
                },
                security: leas_db::models::Security {
                    r#type: leas_proto::proto_spec::SecurityType::None,
                    sni: None,
                    fp: None,
                    insecure: None,
                },
                config: toasty::Deferred::from(toasty::Json(config)),
                created_at: 0,
                links: toasty::Deferred::default(),
            };
            let enrich = super::extract_sni(&protocol, host);

            assert_eq!(
                engine.as_str(),
                enrich.as_deref().unwrap_or(engine.as_str()),
                "the engine and enrichment must answer identically for `{opts}`"
            );
            assert_eq!(engine, expect, "…and both must be the expected SNI");
        }
    }

    /// The plugin path: a TLS-bearing plugin row's SNI is the plugin's `host`,
    /// a host-less one falls back to the endpoint, and a row with no TLS
    /// session has **no** SNI — so a whitelist verdict is never computed from
    /// the obfs `Host` (which is a disguise, not a name any certificate
    /// carries). Spec §5.1; the engine reads the same function.

    #[test]
    fn plugin_rows_resolve_the_sni_the_engine_sends() {
        use leas_proto::proto_spec::common::SecurityConfig;
        use leas_proto::proto_spec::ss_plugin::link_sni;
        use leas_proto::proto_spec::{PluginSpec, ProtocolConfig, SsConfig};

        let row = |opts: Option<&str>| {
            let plugin = opts.map(|o| PluginSpec::from_parts(Some("v2ray-plugin"), o));
            ProtocolConfig::Ss(SsConfig {
                method: "aes-128-gcm".into(),
                password: "pw".into(),
                security: SecurityConfig::default(),
                remarks: None,
                plugin,
            })
        };
        assert_eq!(
            link_sni(&row(Some("host=cdn.example;tls")), "server.example").as_deref(),
            Some("cdn.example"),
            "a stated host is the SNI"
        );
        assert_eq!(
            link_sni(&row(Some("tls")), "server.example").as_deref(),
            Some("server.example"),
            "a host-less TLS row falls back to the endpoint"
        );
        assert_eq!(
            link_sni(&row(Some("host=cdn.example")), "server.example").as_deref(),
            None,
            "a plaintext ws row has no SNI at all"
        );
    }

    /// A driver over an in-memory database, sized like production so the
    /// window behaviour under test is the shipped one.
    async fn country_driver() -> (
        std::sync::Arc<leas_db::Database>,
        std::sync::Arc<leas_db::WriteBehind<leas_db::CountrySpec>>,
    ) {
        let db = std::sync::Arc::new(leas_db::Database::in_memory().await.expect("db"));
        let driver = leas_db::WriteBehind::<leas_db::CountrySpec>::new(
            std::sync::Arc::clone(&db),
            GEO_FLUSH_AT,
            Duration::from_millis(50),
        );
        (db, driver)
    }

    fn stage(driver: &leas_db::WriteBehind<leas_db::CountrySpec>, id: i64, iso: &str) {
        driver.push(leas_db::CountryRow {
            endpoint_id: EndpointId::new(id),
            // Keep the octet in range: these ids are row numbers, not addresses.
            ip: format!("1.2.3.{}", id % 250).parse().expect("ip"),
            iso: iso.to_owned(),
        });
    }

    /// The whole point of T7: N resolutions across N DIFFERENT hosts must leave
    /// as ONE batched write. Per-host batching could not do this — the
    /// 2026-10-01 run had `waiters.len() ≈ 1` (933 lookups, 790 per-address
    /// invocations), so only cross-host accumulation reduces the count.
    #[tokio::test]
    async fn countries_from_many_hosts_coalesce_into_one_write() {
        let (db, driver) = country_driver().await;
        for i in 1..=500i64 {
            stage(&driver, i, "ZZ");
        }
        assert_eq!(driver.staged_len(), 500, "all hosts staged");

        assert_eq!(driver.flush().await.expect("flush"), 500);

        assert_eq!(
            driver.staged_len(),
            0,
            "a successful flush empties the buffer in ONE write"
        );
        let stored = db
            .endpoint_resolutions(&[EndpointId::new(1), EndpointId::new(250)])
            .await
            .expect("read back");
        assert!(
            stored
                .values()
                .flatten()
                .any(|(_, iso)| iso.as_deref() == Some("ZZ")),
            "the batched rows must be PERSISTED, not merely dropped from the buffer",
        );
    }

    /// Two resolutions of the SAME endpoint collapse to the last writer — the
    /// queue's `DashMap` insert overwrote, and so does the coalesce rule.
    #[tokio::test]
    async fn two_resolutions_of_one_endpoint_write_only_the_last() {
        let (db, driver) = country_driver().await;
        stage(&driver, 1, "US");
        stage(&driver, 1, "DE");
        assert_eq!(driver.staged_len(), 1, "one endpoint, one staged row");

        driver.flush().await.expect("flush");

        let stored = db
            .endpoint_resolutions(&[EndpointId::new(1)])
            .await
            .expect("read back");
        let iso = stored
            .values()
            .flatten()
            .find_map(|(_, iso)| iso.as_deref());
        assert_eq!(iso, Some("DE"), "the LAST resolution wins");
    }

    /// A FAILED flush must RE-STAGE, not abandon. The old per-address loop
    /// `break`ed on the first error and lost the remaining waiters — the 88
    /// `country persist failed` aborts of the 2026-10-01 run.
    #[tokio::test]
    async fn a_failed_flush_restages_rather_than_abandoning() {
        let (db, driver) = country_driver().await;
        // A SECOND connection holding the write lock makes every write attempt
        // fail — the same injection the link-writer tests use.
        let mut blocker = db.connection().await.expect("blocker");
        let mut lock = blocker.transaction().await.expect("lock");
        toasty::sql::statement("UPDATE endpoint_ip SET country = country")
            .exec(&mut lock)
            .await
            .expect("take the write lock");

        for i in 1..=5i64 {
            stage(&driver, i, "ZZ");
        }
        driver.flush().await.expect_err("the write lock is held");
        assert_eq!(
            driver.staged_len(),
            5,
            "a failed flush must put every row back, not abandon it",
        );

        lock.rollback().await.expect("release the lock");
        driver.flush().await.expect("flush after unlock");
        assert_eq!(
            driver.staged_len(),
            0,
            "the re-staged rows must land on the next flush",
        );
    }
}
