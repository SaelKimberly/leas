//! Geo data acquisition and the shared routing-engine lifecycle.
//!
//! One compiled [`Engine`] is the routing source of truth: native connects and
//! subscription-source fetches read it from [`EngineCell`]. It is rebuilt when
//! the DB rules, the geo settings, or the downloaded datasets change.
//!
//! Downloads happen only for assets the current rules actually reference
//! (`scan_rules`), so a rule set without geo tokens never touches the network.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use leas_config::app_config::{AppConfig, GeoIpMode};
use leas_db::models::RoutingRule;
use leas_route::Engine;
use leas_route::geo::{CountryLookup, GeoSource};
use leas_route::ir::{DefaultRoute, PROXY_TAG, ResolveStrategy, RuleSet};
use parking_lot::RwLock;

use crate::state::AppState;

/// Compiled engine plus the last build error, shared by every routing
/// consumer.
#[derive(Default)]
pub struct EngineSlot {
    /// The compiled engine (`None` until a build succeeds or after a failure).
    pub engine: Option<Arc<Engine>>,
    /// The last build failure; `Some` means routing must fail closed.
    pub error: Option<String>,
    /// Snapshot id of the inputs this engine was built from.
    pub generation: u64,
}

/// Shared handle to the routing engine.
pub type EngineCell = Arc<RwLock<EngineSlot>>;

/// An empty engine slot.
#[must_use]
pub fn new_cell() -> EngineCell {
    Arc::new(RwLock::new(EngineSlot::default()))
}

/// The app's config directory (`dirs::config_dir()/leas`).
#[must_use]
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join("leas")
}

/// Assets referenced by the current rule rows.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GeoNeeds {
    /// A `geosite:<code>` token exists.
    pub geosite: bool,
    /// A non-private `geoip:<code>` token exists.
    pub geoip: bool,
    /// Local rule-set paths (`rule_set_file`).
    pub rule_files: Vec<String>,
    /// Remote rule-set URLs (`rule_set_url`).
    pub rule_urls: Vec<String>,
}

/// Scans the rows for the datasets they reference.
#[must_use]
pub fn scan_rules(rules: &[RoutingRule]) -> GeoNeeds {
    let mut needs = GeoNeeds::default();
    for row in rules {
        if row
            .domains
            .iter()
            .any(|domain| domain.starts_with("geosite:"))
        {
            needs.geosite = true;
        }
        if row.ips.iter().any(|ip| {
            let (_, rest) = strip_reverse(ip);
            rest.strip_prefix("geoip:")
                .is_some_and(|code| !code.eq_ignore_ascii_case("private"))
        }) {
            needs.geoip = true;
        }
        if let Some(file) = &row.rule_set_file {
            needs.rule_files.push(file.clone());
        }
        if let Some(url) = &row.rule_set_url {
            needs.rule_urls.push(url.clone());
        }
    }
    needs
}

fn strip_reverse(raw: &str) -> (bool, &str) {
    let mut reverse = false;
    let mut rest = raw;
    while let Some(stripped) = rest.strip_prefix('!') {
        reverse = !reverse;
        rest = stripped;
    }
    (reverse, rest)
}

/// Everything one engine build needs. Cloned into the spawned rebuild tasks.
#[derive(Clone)]
pub struct RouteInputs {
    /// Shared engine slot.
    pub cell: EngineCell,
    /// Serializes rebuilds (config dir writes + engine swap).
    pub lock: Arc<tokio::sync::Mutex<()>>,
    /// App config (geo URLs, mode, update cadence).
    pub cfg: AppConfig,
    /// Current DB rows, in `sort_order`.
    pub rules: Vec<RoutingRule>,
    /// `GeoLite2` handle for mmdb mode (shared with endpoint enrichment).
    pub geo_ip: Option<Arc<leas_geoip::GeoIp>>,
    /// Resolver installed on the engine for `IfNonMatch`.
    pub dns: Option<Arc<leas_dns::DnsResolver>>,
    /// Config directory that owns the downloaded assets.
    pub dir: PathBuf,
    /// Monotonic snapshot id (older rebuilds never overwrite newer ones).
    pub generation: u64,
}

impl RouteInputs {
    /// Snapshot the inputs from the current app state.
    #[must_use]
    pub fn from_state(state: &AppState) -> Self {
        Self {
            cell: Arc::clone(&state.routing_engine),
            lock: Arc::clone(&state.routing_rebuild),
            cfg: state.config.clone(),
            rules: state.routing_rules.clone(),
            geo_ip: state.geo_ip.clone(),
            dns: state.dns_resolver.clone(),
            dir: config_dir(),
            generation: state
                .routing_generation
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1),
        }
    }
}

/// Rebuilds the slot from the DB rows, downloading referenced assets.
///
/// A failure installs `error` and clears `engine`, so consumers fail closed
/// instead of routing with a stale or empty rule set.
pub async fn rebuild(inputs: &RouteInputs, force_refresh: bool) {
    let _guard = inputs.lock.lock().await;
    match compile_routing_engine(inputs, force_refresh).await {
        Ok(engine) => {
            // An out-of-order older rebuild must not resurrect old rules.
            if inputs.generation < inputs.cell.read().generation {
                tracing::debug!(
                    target: "tui::ops::geodata",
                    "dropping stale routing engine snapshot {} (installed {})",
                    inputs.generation,
                    inputs.cell.read().generation
                );
                return;
            }
            *inputs.cell.write() = EngineSlot {
                engine: Some(engine),
                error: None,
                generation: inputs.generation,
            };
            tracing::info!(
                target: "tui::ops::geodata",
                "routing engine compiled from {} rule row(s)",
                inputs.rules.len()
            );
        }
        Err(error) => {
            let message = format!("{error:#}");
            if inputs.generation < inputs.cell.read().generation {
                return;
            }
            *inputs.cell.write() = EngineSlot {
                engine: None,
                error: Some(message.clone()),
                generation: inputs.generation,
            };
            tracing::error!(
                target: "tui::ops::geodata",
                "routing engine build failed: {message}"
            );
        }
    }
}

/// Returns the compiled engine, rebuilding when the slot is empty.
///
/// # Errors
/// The last build error (or "still compiling") — never a silent fallback.
pub async fn engine_for_connect(inputs: &RouteInputs) -> anyhow::Result<Arc<Engine>> {
    let cached = {
        let slot = inputs.cell.read();
        slot.engine.clone()
    };
    if let Some(engine) = cached {
        return Ok(engine);
    }
    rebuild(inputs, false).await;
    let (engine, error) = {
        let slot = inputs.cell.read();
        (slot.engine.clone(), slot.error.clone())
    };
    match (engine, error) {
        (Some(engine), _) => Ok(engine),
        (None, Some(error)) => Err(anyhow!("{error}")),
        (None, None) => Err(anyhow!("routing engine is still compiling")),
    }
}

/// Forces a download of every referenced asset, then rebuilds.
pub fn refresh_geo(state: &AppState) {
    let inputs = RouteInputs::from_state(state);
    // Fail closed while the refreshed artifacts compile.
    *inputs.cell.write() = EngineSlot::default();
    tokio::spawn(async move {
        rebuild(&inputs, true).await;
    });
}

/// Auto-update loop: re-downloads referenced assets every configured interval.
pub fn spawn_auto_update(
    inputs: RouteInputs,
    db: Arc<leas_db::Database>,
    shutdown: Arc<AtomicBool>,
) {
    let hours = inputs.cfg.geo.update_interval_hours.max(1);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(hours.saturating_mul(3600)));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = async {
                    while !shutdown.load(Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                } => return,
            }
            let mut inputs = inputs.clone();
            match db.get_all_routing_rules().await {
                Ok(rules) => inputs.rules = rules,
                Err(error) => {
                    tracing::warn!(
                        target: "tui::ops::geodata",
                        "geo auto-update: rules unavailable ({error}); keeping the previous snapshot"
                    );
                }
            }
            rebuild(&inputs, true).await;
        }
    });
}

async fn compile_routing_engine(
    inputs: &RouteInputs,
    force_refresh: bool,
) -> anyhow::Result<Arc<Engine>> {
    let needs = scan_rules(&inputs.rules);
    let mut source = GeoSource::default();

    if needs.geosite {
        let path = inputs.dir.join("geosite.dat");
        ensure_download(
            &inputs.cfg.geo.geosite_url,
            &path,
            force_refresh,
            leas_geoip::MAX_GEO_DAT_BYTES,
            |tmp| leas_geoip::geodata::validate(tmp).map(drop),
        )
        .await?;
        source.geosite = Some(path);
    }

    if needs.geoip {
        match inputs.cfg.geo.geoip_mode {
            GeoIpMode::Dat => {
                let path = inputs.dir.join("geoip.dat");
                ensure_download(
                    &inputs.cfg.geo.geoip_url,
                    &path,
                    force_refresh,
                    leas_geoip::MAX_GEO_DAT_BYTES,
                    |tmp| leas_geoip::geodata::validate(tmp).map(drop),
                )
                .await?;
                source.geoip = Some(path);
            }
            GeoIpMode::Mmdb => {
                let db = inputs
                    .geo_ip
                    .as_ref()
                    .ok_or_else(|| anyhow!("geoip_mode=mmdb needs the GeoLite2 database handle"))?;
                db.ensure_loaded().await.context("GeoLite2 database")?;
                source.country = Some(Arc::clone(db) as Arc<dyn CountryLookup>);
            }
        }
    }

    for url in &needs.rule_urls {
        let path = inputs
            .dir
            .join("rule-sets")
            .join(format!("{}.srs", leas_geoip::url_cache_key(url)));
        ensure_download(
            url,
            &path,
            force_refresh,
            leas_geoip::MAX_RULE_SET_BYTES,
            |tmp| leas_geoip::geodata::srs::load_rule_set(tmp).map(drop),
        )
        .await?;
        source.rule_sets.insert(url.clone(), path);
    }
    for file in &needs.rule_files {
        source.rule_sets.insert(file.clone(), PathBuf::from(file));
    }

    let mut compiled = Vec::with_capacity(inputs.rules.len());
    for (index, row) in inputs.rules.iter().enumerate() {
        for warning in crate::route_compile::warnings_from_row(row) {
            tracing::warn!(
                target: "tui::ops::geodata",
                "routing rule {index}: {warning}"
            );
        }
        match crate::route_compile::rule_from_row(row, index) {
            Ok(rule) => compiled.push(rule),
            Err(error) => tracing::warn!(
                target: "tui::ops::geodata",
                "routing rule {index} skipped: {error}"
            ),
        }
    }

    let ruleset = RuleSet {
        rules: compiled,
        default: DefaultRoute::Route {
            tag: PROXY_TAG.to_owned(),
        },
        resolve_strategy: ResolveStrategy::IfNonMatch,
        probes: Vec::new(),
    };
    let geo_source = source.clone();
    let engine = tokio::task::spawn_blocking(move || Engine::build_with_geo(ruleset, &geo_source))
        .await
        .map_err(|error| anyhow!("routing engine build thread panicked: {error}"))??;
    let engine = if let Some(dns) = &inputs.dns {
        engine.with_resolver(Arc::new(leas_route::dns_adapter::DnsSinkAdapter {
            resolver: Arc::clone(dns),
        }))
    } else {
        engine
    };
    Ok(Arc::new(engine))
}

async fn ensure_download<F>(
    url: &str,
    path: &Path,
    force_refresh: bool,
    max_bytes: u64,
    validate: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&Path) -> anyhow::Result<()> + Send + 'static,
{
    if !force_refresh && path.is_file() {
        return Ok(());
    }
    if url.trim().is_empty() {
        anyhow::bail!("no download URL configured for {}", path.display());
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    match leas_geoip::fetch_validated(url, path, max_bytes, validate).await {
        Ok(()) => Ok(()),
        // A failed refresh must not strand routing on a working artifact:
        // fetch_validated never replaces the old file, so keep using it.
        Err(error) if force_refresh && path.is_file() => {
            tracing::warn!(
                target: "tui::ops::geodata",
                "refresh of {} failed ({error:#}); keeping the existing file",
                path.display()
            );
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("download {url}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> RoutingRule {
        RoutingRule {
            id: "r".into(),
            group_id: None,
            r#type: 0,
            domain_matcher: None,
            domains: Vec::new(),
            ips: Vec::new(),
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            network: None,
            protocols: Vec::new(),
            domain_strategy: None,
            outbound_tag: Some("proxy".into()),
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: None,
        }
    }

    #[test]
    fn scan_detects_only_referenced_assets() {
        let plain = row();
        assert_eq!(scan_rules(&[plain]), GeoNeeds::default());

        let mut geo = row();
        geo.domains = vec!["geosite:cn".into(), "plain.test".into()];
        geo.ips = vec![
            "geoip:private".into(),
            "geoip:cn".into(),
            "!geoip:!de".into(),
        ];
        geo.rule_set_file = Some("/tmp/x.srs".into());
        geo.rule_set_url = Some("https://example.com/y.srs".into());
        let needs = scan_rules(&[geo]);
        assert!(needs.geosite && needs.geoip);
        assert_eq!(needs.rule_files, ["/tmp/x.srs"]);
        assert_eq!(needs.rule_urls, ["https://example.com/y.srs"]);

        let mut private_only = row();
        private_only.ips = vec!["geoip:private".into()];
        assert!(!scan_rules(&[private_only]).geoip);
    }

    #[tokio::test]
    async fn empty_rules_build_a_proxy_all_engine_without_downloads() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = RouteInputs {
            cell: new_cell(),
            lock: Arc::new(tokio::sync::Mutex::new(())),
            cfg: AppConfig::default(),
            rules: Vec::new(),
            geo_ip: None,
            dns: None,
            dir: dir.path().to_path_buf(),
            generation: 0,
        };
        rebuild(&inputs, false).await;
        let (engine, error) = {
            let slot = inputs.cell.read();
            (slot.engine.clone(), slot.error.clone())
        };
        assert!(error.is_none(), "{error:?}");
        assert!(engine.is_some());
    }

    #[tokio::test]
    async fn an_older_snapshot_cannot_replace_a_newer_engine() {
        let dir = tempfile::tempdir().unwrap();
        let cell = new_cell();
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        let inputs = |generation: u64| RouteInputs {
            cell: Arc::clone(&cell),
            lock: Arc::clone(&lock),
            cfg: AppConfig::default(),
            rules: Vec::new(),
            geo_ip: None,
            dns: None,
            dir: dir.path().to_path_buf(),
            generation,
        };
        rebuild(&inputs(2), false).await;
        assert_eq!(cell.read().generation, 2);
        rebuild(&inputs(1), false).await;
        assert_eq!(
            cell.read().generation,
            2,
            "an out-of-order rebuild must not resurrect older rules"
        );
    }

    #[tokio::test]
    async fn failed_forced_refresh_keeps_a_working_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("geo.dat");
        std::fs::write(&path, b"old").unwrap();
        ensure_download("http://127.0.0.1:1/unreachable", &path, true, 1024, |_| {
            Ok(())
        })
        .await
        .expect("a failed refresh keeps the old file");
        assert_eq!(std::fs::read(&path).unwrap(), b"old");

        let absent = dir.path().join("absent.dat");
        assert!(
            ensure_download(
                "http://127.0.0.1:1/unreachable",
                &absent,
                true,
                1024,
                |_| Ok(())
            )
            .await
            .is_err(),
            "no artifact to keep => the refresh error surfaces"
        );
    }

    #[tokio::test]
    async fn missing_rule_set_url_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut row = row();
        row.rule_set_url = Some("http://127.0.0.1:1/never.srs".into());
        let inputs = RouteInputs {
            cell: new_cell(),
            lock: Arc::new(tokio::sync::Mutex::new(())),
            cfg: AppConfig::default(),
            rules: vec![row],
            geo_ip: None,
            dns: None,
            dir: dir.path().to_path_buf(),
            generation: 0,
        };
        rebuild(&inputs, false).await;
        let (engine, error) = {
            let slot = inputs.cell.read();
            (slot.engine.clone(), slot.error.clone())
        };
        assert!(engine.is_none());
        assert!(error.as_deref().is_some_and(|e| e.contains("never.srs")));
    }
}

#[cfg(test)]
mod real_engine_tests {
    use super::*;
    use leas_route::Decision;

    fn meta(host: &str) -> leas_route::ConnMeta {
        leas_route::ConnMeta {
            target: leas_route::NetAddr {
                host: leas_route::NetHost::new(host),
                port: 443,
            },
            network: leas_route::ir::NetworkMask::TCP,
            inbound_tag: None,
            source: None,
            source_resolved_ips: Vec::new(),
            payload_prefix: None,
            sniffed: None,
            sni_host: None,
            resolved_host_ips: Vec::new(),
        }
    }

    fn routed(engine: &Engine, host: &str, tag: &str) -> bool {
        matches!(engine.decide(&meta(host)), Decision::Route { tag: t, .. } if t.as_ref() == tag)
    }

    fn row(domains: Vec<String>, ips: Vec<String>, tag: &str) -> RoutingRule {
        RoutingRule {
            id: "r".into(),
            group_id: None,
            r#type: 0,
            domain_matcher: None,
            domains,
            ips,
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            network: None,
            protocols: Vec::new(),
            domain_strategy: None,
            outbound_tag: Some(tag.into()),
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: None,
        }
    }

    #[tokio::test]
    #[ignore = "downloads the default geo assets and runs the real engine"]
    async fn geosite_cn_routes_direct() {
        let dir = tempfile::tempdir().unwrap();
        let inputs = RouteInputs {
            cell: new_cell(),
            lock: Arc::new(tokio::sync::Mutex::new(())),
            cfg: AppConfig::default(),
            rules: vec![
                row(vec!["geosite:cn".into()], Vec::new(), "direct"),
                row(Vec::new(), vec!["geoip:cn".into()], "direct"),
            ],
            geo_ip: None,
            dns: None,
            dir: dir.path().to_path_buf(),
            generation: 0,
        };
        rebuild(&inputs, false).await;
        let engine = {
            let slot = inputs.cell.read();
            slot.engine
                .clone()
                .unwrap_or_else(|| panic!("engine build failed: {:?}", slot.error))
        };
        assert!(routed(&engine, "www.baidu.com", "direct"));
        assert!(routed(&engine, "1.0.1.1", "direct"));
        assert!(!routed(&engine, "www.google.com", "direct"));
        assert!(!routed(&engine, "8.8.8.8", "direct"));

        let mut typo = inputs.clone();
        typo.cell = new_cell();
        typo.rules = vec![row(
            vec!["geosite:not-a-real-code".into()],
            Vec::new(),
            "direct",
        )];
        rebuild(&typo, false).await;
        let error = {
            let slot = typo.cell.read();
            assert!(slot.engine.is_none());
            slot.error.clone()
        };
        assert!(
            error
                .as_deref()
                .is_some_and(|e| e.contains("not-a-real-code")),
            "{error:?}"
        );
    }
}
