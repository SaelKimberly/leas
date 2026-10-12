//! Resolver seam: DNS sink trait, TTL result cache, probe streak tracker.
//!
//! Pure bookkeeping only — no network I/O here. The caller (engine) invokes
//! the [`DnsSink`] and feeds outcomes to [`ProbeTracker`]/[`ResolvedCache`].

use std::{collections::HashMap, future::Future, net::IpAddr, pin::Pin, sync::Arc};

use crate::{error::RouteError, events::RouteEvent};

/// Async DNS resolution seam, consumed by the routing engine.
///
/// Object-safe: the engine stores `Arc<dyn DnsSink>`. The host arrives
/// borrowed; implementations copy only what their transport actually needs
/// (the boxed future may hold the `&str`, so callers await it within the
/// borrow's scope).
pub trait DnsSink: Send + Sync {
    /// Resolves `host`, returning all addresses or a [`RouteError::Resolve`].
    fn lookup_ip<'a>(
        &self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RouteError>> + Send + 'a>>;
}

/// TTL-keyed DNS resolution cache, bounded by LRU eviction.
///
/// Expiry is by [`jiff::Timestamp`] comparison: an entry is fresh while
/// `now < stored + ttl`, stale from `now >= stored + ttl` (inclusive).
/// Capacity is [`RESOLVED_CACHE_CAP`]: distinct-host growth (e.g. subscription
/// churn) evicts cold entries instead of growing without bound.
const RESOLVED_CACHE_CAP: usize = 2048;

#[derive(Debug)]
pub struct ResolvedCache {
    entries: lru::LruCache<String, (Vec<IpAddr>, jiff::Timestamp)>,
    ttl_secs: i64,
}

impl Default for ResolvedCache {
    fn default() -> Self {
        Self {
            entries: lru::LruCache::new(
                std::num::NonZeroUsize::new(RESOLVED_CACHE_CAP).expect("cache cap is nonzero"),
            ),
            ttl_secs: 300,
        }
    }
}

impl ResolvedCache {
    /// Creates a cache whose entries live `ttl_secs` past their store time.
    #[must_use]
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            entries: lru::LruCache::new(
                std::num::NonZeroUsize::new(RESOLVED_CACHE_CAP).expect("cache cap is nonzero"),
            ),
            ttl_secs,
        }
    }

    /// Returns the cached addresses for `host` when `now` is before expiry.
    /// `peek` (no recency bump): a freshness check must not keep entries
    /// alive past their TTL intent.
    #[must_use]
    pub fn get_fresh(&self, host: &str, now: jiff::Timestamp) -> Option<&[IpAddr]> {
        let (ips, stored) = self.entries.peek(host)?;
        if now >= *stored + jiff::Span::new().seconds(self.ttl_secs) {
            None
        } else {
            Some(ips)
        }
    }

    /// Stores `ips` for `host`, stamped at `now`. The owned `host` key moves
    /// into the cache — no key clone; an existing entry is re-stamped in
    /// place (`get_mut` also refreshes recency); overflow evicts the
    /// least-recently-used entry.
    pub fn put(&mut self, host: String, ips: Vec<IpAddr>, now: jiff::Timestamp) {
        if let Some((slot, stored)) = self.entries.get_mut(host.as_str()) {
            *slot = ips;
            *stored = now;
        } else {
            self.entries.push(host, (ips, now));
        }
    }
}

/// Consecutive-failure streak tracker for probe targets.
///
/// Zero-cost no-op while the probes list is empty. Streaks are keyed per
/// probe (`Arc<str>`, shared with the emitted events — one alloc per
/// streak, bumps thereafter); entering failure emits
/// [`RouteEvent::NetworkBreakdown`] exactly once per streak, and the next
/// success emits [`RouteEvent::ProbeRecovered`] exactly once and resets the
/// streak (the removed `Arc` is reused for the event — no realloc).
#[derive(Debug, Default)]
pub struct ProbeTracker {
    streaks: HashMap<Arc<str>, u32>,
}

impl ProbeTracker {
    /// Applies one probe cycle.
    ///
    /// `sink_probe_result` is `Some((failed, Some(probe)))` for a per-probe
    /// outcome; probes not in `probes` are ignored. `any_failed_this_cycle`
    /// is informational only — the per-probe streak model is authoritative.
    /// Events go to `tx` when `Some`.
    pub fn update(
        &mut self,
        probes: &[String],
        _any_failed_this_cycle: bool,
        sink_probe_result: Option<(bool, Option<&str>)>,
        tx: &Option<tokio::sync::mpsc::UnboundedSender<RouteEvent>>,
    ) {
        let Some((failed, which)) = sink_probe_result else {
            return;
        };
        let Some(probe) = which else { return };
        if !probes.iter().any(|p| p == probe) {
            return;
        }
        if failed {
            // Borrow-first: repeat failures for a tracked probe cost no
            // alloc; only a genuinely new streak allocates its key `Arc`
            // (whose refcount the Breakdown event then shares — no realloc).
            if let Some(count) = self.streaks.get_mut(probe) {
                *count += 1;
                if *count == 1
                    && let Some((event_key, _)) = self.streaks.get_key_value(probe)
                {
                    let event_key = event_key.clone();
                    emit(
                        tx.as_ref(),
                        RouteEvent::NetworkBreakdown {
                            failed_probe: event_key,
                            at: jiff::Timestamp::now(),
                        },
                    );
                }
            } else {
                let event_key: Arc<str> = Arc::from(probe);
                self.streaks.insert(event_key.clone(), 1);
                emit(
                    tx.as_ref(),
                    RouteEvent::NetworkBreakdown {
                        failed_probe: event_key,
                        at: jiff::Timestamp::now(),
                    },
                );
            }
        } else if let Some((key, _)) = self.streaks.remove_entry(probe) {
            emit(
                tx.as_ref(),
                RouteEvent::ProbeRecovered {
                    // Reuse the removed key — no realloc.
                    probe: key,
                    at: jiff::Timestamp::now(),
                },
            );
        }
    }
}

/// Sends `event` when the channel exists; drops it otherwise.
fn emit(tx: Option<&tokio::sync::mpsc::UnboundedSender<RouteEvent>>, event: RouteEvent) {
    if let Some(tx) = tx {
        let _ = tx.send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use rstest::rstest;
    use tokio::sync::mpsc;

    fn probes(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[tokio::test]
    async fn cache_ttl_expiry_forces_refetch() {
        let mut cache = ResolvedCache::new(60);
        let t0 = jiff::Timestamp::now();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        cache.put("h".into(), vec![ip], t0);
        assert_eq!(cache.get_fresh("h", t0), Some(&[ip][..]));
        // Boundary: now == stored+ttl is stale (inclusive).
        let expired = t0 + Duration::from_secs(60);
        assert_eq!(cache.get_fresh("h", expired), None);
        // Just before expiry is fresh.
        assert_eq!(
            cache.get_fresh("h", expired - Duration::from_nanos(1)),
            Some(&[ip][..])
        );
        // After a refetch (put again), fresh again.
        cache.put("h".into(), vec![ip], expired);
        assert_eq!(cache.get_fresh("h", expired), Some(&[ip][..]));
    }

    #[tokio::test]
    async fn probe_streak_fail_then_recover_emits_exactly_once_each() {
        let mut tracker = ProbeTracker::default();
        let list = probes(&["p1", "p2"]);
        let (tx, mut rx) = mpsc::unbounded_channel();

        // Two consecutive failures: one Breakdown, streak continues.
        tracker.update(&list, true, Some((true, Some("p1"))), &Some(tx.clone()));
        tracker.update(&list, true, Some((true, Some("p1"))), &Some(tx.clone()));
        tracker.update(&list, true, Some((true, Some("p2"))), &Some(tx.clone()));
        // Successes: one Recovered each, streaks reset.
        tracker.update(&list, false, Some((false, Some("p1"))), &Some(tx.clone()));
        tracker.update(&list, false, Some((false, Some("p2"))), &Some(tx.clone()));

        let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(
            matches!(events[0], RouteEvent::NetworkBreakdown { ref failed_probe, .. } if &**failed_probe == "p1")
        );
        assert!(
            matches!(events[1], RouteEvent::NetworkBreakdown { ref failed_probe, .. } if &**failed_probe == "p2")
        );
        assert!(
            matches!(events[2], RouteEvent::ProbeRecovered { ref probe, .. } if &**probe == "p1")
        );
        assert!(
            matches!(events[3], RouteEvent::ProbeRecovered { ref probe, .. } if &**probe == "p2")
        );
        assert_eq!(events.len(), 4);
        // Steady state: further successes emit nothing.
        tracker.update(&list, false, Some((false, Some("p1"))), &Some(tx));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn streak_reset_on_success_between_failures() {
        let mut tracker = ProbeTracker::default();
        let list = probes(&["p1"]);
        let (tx, mut rx) = mpsc::unbounded_channel();

        tracker.update(&list, true, Some((true, Some("p1"))), &Some(tx.clone()));
        tracker.update(&list, false, Some((false, Some("p1"))), &Some(tx.clone()));
        tracker.update(&list, true, Some((true, Some("p1"))), &Some(tx));

        let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(matches!(events[0], RouteEvent::NetworkBreakdown { .. }));
        assert!(matches!(events[1], RouteEvent::ProbeRecovered { .. }));
        assert!(matches!(events[2], RouteEvent::NetworkBreakdown { .. }));
        assert_eq!(events.len(), 3);
    }

    // Every no-op input (untracked list, out-of-list probe, absent sink
    // result) must leave the tracker silent.
    #[rstest]
    #[case::empty_list(&[], Some("p1"))]
    #[case::probe_not_in_list(&["p1"], Some("other"))]
    #[case::sink_no_result(&["p1"], None)]
    #[tokio::test]
    async fn no_op_updates_emit_no_events(#[case] list: &[&str], #[case] probe: Option<&str>) {
        let mut tracker = ProbeTracker::default();
        let list = probes(list);
        let (tx, mut rx) = mpsc::unbounded_channel();

        match probe {
            Some(p) => {
                tracker.update(&list, true, Some((true, Some(p))), &Some(tx.clone()));
                tracker.update(&list, false, Some((false, Some(p))), &Some(tx));
            }
            None => tracker.update(&list, true, None, &Some(tx)),
        }
        assert!(rx.try_recv().is_err());
    }
}

/// IP-literal passthrough needs no network; runtime resolves locally.
#[cfg(feature = "dns")]
#[tokio::test]
async fn dns_adapter_ip_literal_passthrough() {
    let adapter = crate::dns_adapter::DnsSinkAdapter {
        resolver: std::sync::Arc::new(leas_dns::DnsResolver::new("/tmp")),
    };
    let ips = adapter.lookup_ip("127.0.0.1").await.unwrap();
    assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
}
