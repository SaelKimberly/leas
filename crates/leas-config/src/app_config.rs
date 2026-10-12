use ratatui_themes::ThemeName;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub core: CoreConfig,
    #[serde(default)]
    pub gui: GuiConfig,
    #[serde(default)]
    pub inbound: InboundConfig,
    #[serde(default)]
    pub tun: TunConfig,
    #[serde(default)]
    pub mux: MuxConfig,
    #[serde(default)]
    pub system_proxy: SystemProxyConfig,
    #[serde(default)]
    pub statistics: StatisticsConfig,
    #[serde(default)]
    pub updates: UpdateConfig,
    #[serde(default)]
    pub speed_test: SpeedTestConfig,
    #[serde(default)]
    pub logging: LogConfig,
    #[serde(default)]
    pub parsing: ParsingSettings,
    #[serde(default)]
    pub geo: GeoConfig,
    #[serde(default)]
    pub theme_name: ThemeName,
    pub clash_api_port: Option<u16>,
    #[serde(default)]
    pub clash_mixin: Option<String>,
    #[serde(default)]
    pub purgatory: PurgatoryConfig,
    #[serde(default)]
    pub import: ImportConfig,
}

/// Ceilings on ONE subscription feed.
///
/// These were two function-local `const`s in `run_streaming_import`, invisible
/// and unchangeable: on 2026-10-01 a 90,688-profile feed hit the byte budget and
/// was cut off with the reason reachable only from the activity log.
/// `specs/2026-10-02-import-budget-design.md` owns this.
///
/// The DEFAULTS are the values that were hard-coded, so adding the section
/// changes no behaviour at all — that is the compatibility boundary the spec
/// requires. Raising the byte ceiling is a one-line edit below, and once
/// surfaced in Settings it is a runtime change, not a rebuild.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ImportConfig {
    /// Decoded-feed ceiling in bytes; `0` disables it. 64 MiB is the value that
    /// was hard-coded, and it is MARGINAL: the 2026-10-01 feed decoded to just
    /// over it (67,112,960 bytes) and was truncated.
    #[serde(default = "default_max_feed_bytes")]
    pub max_feed_bytes: u64,
    /// Stored-link ceiling; `0` disables it. A runaway guard, not a real limit —
    /// 90,688 links fit comfortably.
    #[serde(default = "default_max_feed_links")]
    pub max_feed_links: usize,
}

const fn default_max_feed_bytes() -> u64 {
    64 * 1024 * 1024
}

const fn default_max_feed_links() -> usize {
    200_000
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            max_feed_bytes: default_max_feed_bytes(),
            max_feed_links: default_max_feed_links(),
        }
    }
}

/// The Purgatory windows: `ttl_days` is the Active/Purgatory bound a reload
/// computes from now, `retention_days` the cutoff the sweep reclaims at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgatoryConfig {
    #[serde(default = "default_purgatory_ttl_days")]
    pub ttl_days: u64,
    #[serde(default = "default_purgatory_retention_days")]
    pub retention_days: u64,
}

const fn default_purgatory_ttl_days() -> u64 {
    7
}
const fn default_purgatory_retention_days() -> u64 {
    30
}
impl Default for PurgatoryConfig {
    fn default() -> Self {
        Self {
            ttl_days: default_purgatory_ttl_days(),
            retention_days: default_purgatory_retention_days(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    pub xray_path: Option<String>,
    pub sing_box_path: Option<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub protocol_core_overrides: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub skip_cert_verify: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            xray_path: None,
            sing_box_path: None,
            log_level: default_log_level(),
            protocol_core_overrides: std::collections::HashMap::new(),
            skip_cert_verify: false,
        }
    }
}

fn default_log_level() -> String {
    "warning".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiConfig {
    #[serde(default = "default_language")]
    pub language: String,
    pub theme: Option<String>,
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: crate::DurationOrSecs,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            language: default_language(),
            theme: None,
            refresh_interval_secs: default_refresh_interval(),
        }
    }
}

fn default_language() -> String {
    "en".to_owned()
}

fn default_refresh_interval() -> crate::DurationOrSecs {
    crate::DurationOrSecs::from(std::time::Duration::from_secs(5))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundConfig {
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    pub http_port: Option<u16>,
    pub mixed_port: Option<u16>,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub sniffing: bool,
}

impl Default for InboundConfig {
    fn default() -> Self {
        Self {
            socks_port: default_socks_port(),
            http_port: None,
            mixed_port: None,
            listen: default_listen(),
            sniffing: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunConfig {
    #[serde(default)]
    pub enabled: bool,
    pub interface_name: Option<String>,
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuxConfig {
    #[serde(default)]
    pub enabled: bool,
    pub concurrency: Option<u8>,
    #[serde(default = "default_mux_protocol")]
    pub protocol: String,
    pub max_connections: Option<u8>,
    pub min_streams: Option<u8>,
    pub max_streams: Option<u16>,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub fragment_enabled: bool,
    pub fragment_packets: Option<String>,
    pub fragment_length: Option<String>,
    pub fragment_interval: Option<String>,
}

fn default_mux_protocol() -> String {
    "smux".to_owned()
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            concurrency: None,
            protocol: default_mux_protocol(),
            max_connections: None,
            min_streams: None,
            max_streams: None,
            padding: false,
            fragment_enabled: false,
            fragment_packets: None,
            fragment_length: None,
            fragment_interval: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemProxyConfig {
    #[serde(default)]
    pub enabled: bool,
    pub http_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub bypass: Option<String>,
}

const fn default_clash_api_port() -> u16 {
    9090
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticsConfig {
    #[serde(default = "default_stats_enabled")]
    pub enabled: bool,
    #[serde(default = "default_clash_api_port")]
    pub clash_api_port: u16,
}

const fn default_stats_enabled() -> bool {
    true
}

impl Default for StatisticsConfig {
    fn default() -> Self {
        Self {
            enabled: default_stats_enabled(),
            clash_api_port: default_clash_api_port(),
        }
    }
}

const fn default_socks_port() -> u16 {
    10808
}

fn default_listen() -> String {
    "127.0.0.1".to_owned()
}

pub type Result<T, E = ConfigError> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let path = default_config_path();
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let mut config: Self = serde_json::from_str(&content)?;
            // Normalize old protocol Display strings in protocol_core_overrides keys.
            // The Display impl was changed to short forms ("ss", "hy", etc.)
            // which broke backward-compat with configs saved using the old
            // kebab-case Debug forms ("shadowsocks", "hysteria", etc.).
            config.core.protocol_core_overrides = config
                .core
                .protocol_core_overrides
                .into_iter()
                .map(|(k, v)| (normalize_protocol_key(&k), v))
                .collect();
            Ok(config)
        } else {
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = default_config_path();
        if let Some(parent) = path.parent() {
            // Owner-only: this directory also holds data.db, the profile
            // credential store, so it must not be traversable by other users.
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }
}

fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("leas")
        .join("config.json")
}

/// Normalize old protocol (Display) key names to current short forms.
/// The `Protocol::Display` impl was changed from kebab-case Debug-derived
/// names to short forms (e.g. "shadowsocks" → "ss", "hysteria" → "hy").
/// This maps old config-file keys to their current equivalents.
fn normalize_protocol_key(key: &str) -> String {
    match key {
        "shadowsocks" => "ss",
        "shadowsocks-2022" => "ss-2022",
        "shadowsocks-r" => "ssr",
        "hysteria" => "hy",
        "hysteria-2" => "hy2",
        "dokodemo-door" => "dokodemo",
        "wire-guard" => "wireguard",
        other => other,
    }
    .to_owned()
}

/// An EXISTING `config.json` must load unchanged: the `import` section is
/// `#[serde(default)]`, so a file written before this change still parses
/// and still gets the values that were hard-coded. This is the spec's
/// compatibility boundary, and it is the whole reason the section is additive.
#[test]
fn a_config_without_an_import_section_loads_with_the_previous_defaults() {
    let cfg: AppConfig = serde_json::from_str("{}").expect("empty config must load");
    assert_eq!(cfg.import.max_feed_bytes, 64 * 1024 * 1024);
    assert_eq!(cfg.import.max_feed_links, 200_000);
}

/// Overrides must survive a round trip, including `0` meaning "unbounded".
#[test]
fn import_budget_overrides_round_trip_and_zero_disables() {
    let cfg: AppConfig =
        serde_json::from_str(r#"{"import":{"max_feed_bytes":0,"max_feed_links":1234}}"#)
            .expect("override must load");
    assert_eq!(cfg.import.max_feed_bytes, 0, "0 must mean unbounded");
    assert_eq!(cfg.import.max_feed_links, 1234);
    let back = serde_json::to_string(&cfg.import).expect("serialize");
    let again: ImportConfig = serde_json::from_str(&back).expect("reparse");
    assert_eq!(again.max_feed_bytes, 0);
    assert_eq!(again.max_feed_links, 1234);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_round_trips() {
        let original = AppConfig::default();
        let json = serde_json::to_string_pretty(&original).unwrap();
        let restored: AppConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.core.log_level, "warning");
        assert_eq!(restored.gui.language, "en");
        assert_eq!(
            *restored.gui.refresh_interval_secs,
            std::time::Duration::from_secs(5)
        );
        assert_eq!(restored.inbound.socks_port, 10808);
        assert_eq!(restored.inbound.listen, "127.0.0.1");
        assert!(!restored.inbound.sniffing);
    }

    #[test]
    fn speed_test_error_ttl_defaults_none_and_round_trips() {
        // Default: None — errors survive until the next test overwrites them.
        let original = AppConfig::default();
        assert!(original.speed_test.error_ttl_hours.is_none());
        let json = serde_json::to_string(&original).unwrap();
        let restored: AppConfig = serde_json::from_str(&json).unwrap();
        assert!(restored.speed_test.error_ttl_hours.is_none());

        // Explicit value round-trips through the speed-test section.
        let json = r#"{"core":{},"gui":{},"inbound":{},"speed_test":{"error_ttl_hours":168}}"#;
        let config: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.speed_test.error_ttl_hours, Some(168));
    }

    #[test]
    fn speed_test_queue_and_dns_defer_defaults_and_round_trip() {
        // Defaults: queue limit 3, deferral 15s. The deferral has to outlast
        // one resolution (8s) — the failure stamp is written when the lookup
        // reports, so the old 5s default expired before there was anything to
        // defer.
        let original = AppConfig::default();
        assert_eq!(original.speed_test.task_queue_limit, 3);
        assert_eq!(original.speed_test.dns_failure_defer_secs, 15);
        let json = serde_json::to_string(&original).unwrap();
        let restored: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.speed_test.task_queue_limit, 3);
        assert_eq!(restored.speed_test.dns_failure_defer_secs, 15);

        // Explicit values round-trip through the speed-test section; absent
        // fields fall back to the defaults.
        let json = r#"{"core":{},"gui":{},"inbound":{},"speed_test":{"task_queue_limit":1,"dns_failure_defer_secs":30}}"#;
        let config: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.speed_test.task_queue_limit, 1);
        assert_eq!(config.speed_test.dns_failure_defer_secs, 30);

        // 0 queue limit = no queueing; 0 deferral = no DNS deferral.
        let json = r#"{"core":{},"gui":{},"inbound":{},"speed_test":{"task_queue_limit":0,"dns_failure_defer_secs":0}}"#;
        let config: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.speed_test.task_queue_limit, 0);
        assert_eq!(config.speed_test.dns_failure_defer_secs, 0);
    }

    #[test]
    fn normalize_protocol_key_known_pairs() {
        // Each known old Display string → current short form
        let cases = [
            ("shadowsocks", "ss"),
            ("shadowsocks-2022", "ss-2022"),
            ("shadowsocks-r", "ssr"),
            ("hysteria", "hy"),
            ("hysteria-2", "hy2"),
            ("dokodemo-door", "dokodemo"),
            ("wire-guard", "wireguard"),
        ];
        for (old, expected) in &cases {
            assert_eq!(normalize_protocol_key(old), *expected, "failed for {old}");
        }
    }

    #[test]
    fn normalize_protocol_key_passes_through_unknown() {
        // Already-short or unknown keys pass through unchanged
        let passthrough = [
            "vmess",
            "vless",
            "ss",
            "ss-2022",
            "ssr",
            "hy",
            "hy2",
            "trojan",
            "socks",
            "http",
            "dokodemo",
            "wireguard",
            "tuic",
            "naive",
            "any-tls",
            "shadow-tls",
            "tor",
            "ssh",
            "redirect",
            "t-proxy",
            "mixed",
            "tailscale",
        ];
        for key in &passthrough {
            assert_eq!(
                normalize_protocol_key(key),
                *key,
                "passthrough failed for {key}"
            );
        }
    }

    #[test]
    fn normalise_protocol_key_round_trips_config() {
        // Simulate loading a config with old keys — they should survive
        // normalization and be usable at runtime.
        let old_config_json = r#"{
            "core": {
                "protocol_core_overrides": {
                    "shadowsocks-2022": "xray",
                    "wire-guard": "sing-box",
                    "dokodemo-door": "xray"
                }
            },
            "gui": {},
            "inbound": {}
        }"#;
        let mut config: AppConfig = serde_json::from_str(old_config_json).unwrap();
        // Apply normalization (same as AppConfig::load() does)
        config.core.protocol_core_overrides = config
            .core
            .protocol_core_overrides
            .into_iter()
            .map(|(k, v)| (normalize_protocol_key(&k), v))
            .collect();
        let overrides = &config.core.protocol_core_overrides;
        assert_eq!(overrides.get("ss-2022").map(String::as_str), Some("xray"));
        assert_eq!(
            overrides.get("wireguard").map(String::as_str),
            Some("sing-box")
        );
        assert_eq!(overrides.get("dokodemo").map(String::as_str), Some("xray"));
        // Old keys should no longer exist
        assert!(overrides.get("shadowsocks-2022").is_none());
        assert!(overrides.get("wire-guard").is_none());
        assert!(overrides.get("dokodemo-door").is_none());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    #[serde(default = "default_update_check_enabled")]
    pub check_on_startup: bool,
    #[serde(default)]
    pub last_check: Option<String>,
    #[serde(default)]
    pub xray_latest_known: Option<String>,
    #[serde(default)]
    pub sing_box_latest_known: Option<String>,
}

const fn default_update_check_enabled() -> bool {
    true
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            check_on_startup: true,
            last_check: None,
            xray_latest_known: None,
            sing_box_latest_known: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestConfig {
    #[serde(default = "default_ping_url")]
    pub ping_url: String,
    /// Exit-IP lookup endpoint, fetched through the probe's own tunnel. The
    /// family-agnostic providers are also the automatic fallback order: the
    /// exit IP does not depend on which one answers, so a rate-limited free
    /// tier just hands over to the next.
    #[serde(default)]
    pub ip_provider: crate::IpProvider,
    #[serde(default = "default_tcp_timeout_secs")]
    pub tcp_timeout_secs: crate::DurationOrSecs,
    #[serde(default = "default_real_ping_timeout_secs")]
    pub real_ping_timeout_secs: crate::DurationOrSecs,
    #[serde(default = "default_real_ping_retries")]
    pub real_ping_retries: u32,
    #[serde(default = "default_real_ping_concurrency")]
    pub real_ping_concurrency: usize,
    #[serde(default = "default_fast_ping_concurrency")]
    pub fast_ping_concurrency: usize,
    #[serde(default = "default_real_ping_test_all_protocols")]
    pub real_ping_test_all_protocols: bool,
    /// "Clear error after": persisted failure markers (`ProfileStats.error`)
    /// older than this many hours are swept, anchored on `updated_at`.
    /// `None` (the default) = errors survive until the next test overwrites
    /// them. The TUI sweeps on profile reload and after batch completion;
    /// the settings form edits this.
    #[serde(default)]
    pub error_ttl_hours: Option<i64>,
    /// Max queued tasks per link for the batch scheduler; `0` disables
    /// queueing (busy links are skipped this round). Applied to the runtime
    /// scheduler on config load and settings save.
    #[serde(default = "default_task_queue_limit")]
    pub task_queue_limit: u16,
    /// DNS-failure deferral window in seconds: endpoints whose DNS failed
    /// recently are skipped by the batch scheduler for this long
    /// (`<= 0` disables deferral). Applied to the runtime scheduler on
    /// config load and settings save.
    #[serde(default = "default_dns_failure_defer_secs")]
    pub dns_failure_defer_secs: i64,
}

fn default_ping_url() -> String {
    "https://www.gstatic.com/generate_204".to_string()
}

fn default_tcp_timeout_secs() -> crate::DurationOrSecs {
    crate::DurationOrSecs::from(std::time::Duration::from_secs(5))
}

fn default_real_ping_timeout_secs() -> crate::DurationOrSecs {
    crate::DurationOrSecs::from(std::time::Duration::from_secs(5))
}

const fn default_real_ping_retries() -> u32 {
    2
}

const fn default_real_ping_concurrency() -> usize {
    100
}

const fn default_fast_ping_concurrency() -> usize {
    200
}

const fn default_real_ping_test_all_protocols() -> bool {
    false
}

const fn default_task_queue_limit() -> u16 {
    3
}

const fn default_dns_failure_defer_secs() -> i64 {
    // Must outlast one resolution (`enrich::DNS_LOOKUP_TIMEOUT`, 8s): the
    // failure stamp is written when the lookup reports, so a shorter window
    // has already expired by the time there is anything to defer. The
    // scheduler clamps to the same floor, so a hand-edited config.json cannot
    // reinstall the inverted pair.
    15
}

impl Default for SpeedTestConfig {
    fn default() -> Self {
        Self {
            ping_url: default_ping_url(),
            ip_provider: crate::IpProvider::default(),
            tcp_timeout_secs: default_tcp_timeout_secs(),
            real_ping_timeout_secs: default_real_ping_timeout_secs(),
            real_ping_retries: default_real_ping_retries(),
            real_ping_concurrency: default_real_ping_concurrency(),
            fast_ping_concurrency: default_fast_ping_concurrency(),
            real_ping_test_all_protocols: default_real_ping_test_all_protocols(),
            error_ttl_hours: None,
            task_queue_limit: default_task_queue_limit(),
            dns_failure_defer_secs: default_dns_failure_defer_secs(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParsingSettings {
    #[serde(default)]
    pub allow_private_ips: bool,
    #[serde(default)]
    pub reject_insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_ttl_secs")]
    pub ttl_secs: crate::DurationOrSecs,
    #[serde(default)]
    pub log_to_file: bool,
    #[serde(default = "default_log_file_path")]
    pub log_file_path: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_log_ttl_secs(),
            log_to_file: false,
            log_file_path: default_log_file_path(),
        }
    }
}

fn default_log_ttl_secs() -> crate::DurationOrSecs {
    crate::DurationOrSecs::from(std::time::Duration::from_hours(72))
}

fn default_log_file_path() -> String {
    "leas.log".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoConfig {
    #[serde(default = "default_geoip_url")]
    pub geoip_url: String,
    #[serde(default = "default_geosite_url")]
    pub geosite_url: String,
    #[serde(default)]
    pub auto_update: bool,
    #[serde(default = "default_geo_update_interval")]
    pub update_interval_hours: u64,
}

impl Default for GeoConfig {
    fn default() -> Self {
        Self {
            geoip_url: default_geoip_url(),
            geosite_url: default_geosite_url(),
            auto_update: false,
            update_interval_hours: 24,
        }
    }
}

fn default_geoip_url() -> String {
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat".into()
}

fn default_geosite_url() -> String {
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat".into()
}

const fn default_geo_update_interval() -> u64 {
    24
}
