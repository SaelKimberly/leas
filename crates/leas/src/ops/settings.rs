use std::collections::HashMap;

use leas_config::IpProvider;
use leas_db::models::RoutingRule;

use crate::AppState;
use crate::types::{AppMode, SettingsMode, SettingsSection, SplitFocus, SplitRightPane};

pub fn cancel_form(state: &mut AppState) {
    state.mode = AppMode::List;
}

/// One settings field: the key the form saves under, its label, the input
/// type the form dispatches on, and the one-line description the help band
/// shows. ONE table per section — the form defs, the value builder and the
/// defaults all walk it, so label/type/order/description cannot drift apart
/// (the `SpeedTest` table and builder used to disagree past
/// `dns_failure_defer_secs`, mislabeling nine rows).
pub(crate) struct FieldDef {
    pub key: &'static str,
    pub label: &'static str,
    pub ftype: &'static str,
    pub description: &'static str,
}

const GUI_DEFS: &[FieldDef] = &[
    FieldDef {
        key: "language",
        label: "Language",
        ftype: "Select:en,zh",
        description: "UI language",
    },
    FieldDef {
        key: "theme",
        label: "Theme",
        ftype: "SelectThemes",
        description: "Colour theme, applied live on save",
    },
    FieldDef {
        key: "refresh_interval",
        label: "Refresh Interval",
        ftype: "Text",
        description: "How often the feed re-queries the DB",
    },
];

const INBOUND_DEFS: &[FieldDef] = &[
    FieldDef {
        key: "socks_port",
        label: "SOCKS Port",
        ftype: "Number",
        description: "Local SOCKS5 listen port",
    },
    FieldDef {
        key: "http_port",
        label: "HTTP Port",
        ftype: "Number",
        description: "Local HTTP listen port, empty = off",
    },
    FieldDef {
        key: "mixed_port",
        label: "Mixed Port",
        ftype: "Number",
        description: "Local mixed (SOCKS+HTTP) port, empty = off",
    },
    FieldDef {
        key: "listen",
        label: "Listen Address",
        ftype: "Text",
        description: "Bind address for the local inbound",
    },
    FieldDef {
        key: "sniffing",
        label: "Sniffing",
        ftype: "Boolean",
        description: "Sniff destination domains for routing",
    },
];

const SYSTEM_PROXY_DEFS: &[FieldDef] = &[
    FieldDef {
        key: "enabled",
        label: "Enabled",
        ftype: "Boolean",
        description: "Set the OS proxy to leas's inbound",
    },
    FieldDef {
        key: "http_port",
        label: "HTTP Port",
        ftype: "Number",
        description: "OS proxy HTTP port",
    },
    FieldDef {
        key: "socks_port",
        label: "SOCKS Port",
        ftype: "Number",
        description: "OS proxy SOCKS port",
    },
    FieldDef {
        key: "bypass",
        label: "Bypass",
        ftype: "Text",
        description: "Hosts the OS proxy must not capture",
    },
];

const TUN_DEFS: &[FieldDef] = &[
    FieldDef {
        key: "enabled",
        label: "Enabled",
        ftype: "Boolean",
        description: "TUN device capture (needs privileges)",
    },
    FieldDef {
        key: "interface_name",
        label: "Interface Name",
        ftype: "Text",
        description: "TUN interface name",
    },
    FieldDef {
        key: "mtu",
        label: "MTU",
        ftype: "Number",
        description: "TUN interface MTU, empty = default",
    },
];

const MUX_DEFS: &[FieldDef] = &[
    FieldDef {
        key: "enabled",
        label: "Enabled",
        ftype: "Boolean",
        description: "Multiplex links over one connection",
    },
    FieldDef {
        key: "concurrency",
        label: "Concurrency",
        ftype: "Number",
        description: "Streams per connection, empty = auto",
    },
    FieldDef {
        key: "protocol",
        label: "Protocol",
        ftype: "Select:smux,yamux,h2mux",
        description: "Mux protocol the core speaks",
    },
    FieldDef {
        key: "max_connections",
        label: "Max Connections",
        ftype: "Number",
        description: "Connection pool cap",
    },
    FieldDef {
        key: "min_streams",
        label: "Min Streams",
        ftype: "Number",
        description: "Min streams before a new connection",
    },
    FieldDef {
        key: "max_streams",
        label: "Max Streams",
        ftype: "Number",
        description: "Max streams per connection",
    },
    FieldDef {
        key: "padding",
        label: "Padding",
        ftype: "Boolean",
        description: "Pad mux frames",
    },
    FieldDef {
        key: "fragment_enabled",
        label: "Fragment Enabled",
        ftype: "Boolean",
        description: "Split TLS ClientHello into fragments",
    },
    FieldDef {
        key: "fragment_packets",
        label: "Fragment Packets",
        ftype: "Text",
        description: "Fragment sizes, e.g. 10-20,30-50",
    },
    FieldDef {
        key: "fragment_length",
        label: "Fragment Length",
        ftype: "Text",
        description: "Fragment byte lengths",
    },
    FieldDef {
        key: "fragment_interval",
        label: "Fragment Interval",
        ftype: "Text",
        description: "Delay between fragments (ms)",
    },
];

const SPEED_TEST_DEFS: &[FieldDef] = &[
    FieldDef {
        key: "ping_url",
        label: "Ping Test URL",
        ftype: "Url",
        description: "URL the real probe fetches",
    },
    FieldDef {
        key: "ip_provider",
        label: "IP Provider",
        ftype: leas_config::ip_provider::SELECT_CELL,
        description: "Service that reports the exit IP",
    },
    FieldDef {
        key: "tcp_timeout_secs",
        label: "TCP Timeout",
        ftype: "Duration",
        description: "Transport stage timeout",
    },
    FieldDef {
        key: "real_ping_timeout_secs",
        label: "Real Ping Timeout",
        ftype: "Duration",
        description: "Real probe timeout",
    },
    FieldDef {
        key: "real_ping_retries",
        label: "Real Ping Retries",
        ftype: "Number",
        description: "Retries per real probe",
    },
    FieldDef {
        key: "real_ping_concurrency",
        label: "Real Ping Concurrency",
        ftype: "Number",
        description: "Parallel real probes",
    },
    FieldDef {
        key: "real_ping_test_all_protocols",
        label: "Real Ping Test All Protocols",
        ftype: "Boolean",
        description: "Probe every link of an endpoint, not the best",
    },
    FieldDef {
        key: "task_queue_limit",
        label: "Task Queue Limit (0=no queue)",
        ftype: "Number",
        description: "Queued-test cap, 0 = unlimited",
    },
    FieldDef {
        key: "dns_failure_defer_secs",
        label: "DNS Failure Defer (secs)",
        ftype: "Number",
        description: "Window a DNS failure defers a re-test",
    },
    // Was missing from the defs while the builder produced it: the rows from
    // `speed_test_url` on showed wrong label/value pairs.
    FieldDef {
        key: "error_ttl_hours",
        label: "Error TTL Hours",
        ftype: "Number",
        description: "Hours a failure marker stays believable, empty = never",
    },
    FieldDef {
        key: "speed_test_url",
        label: "Speed Test URL",
        ftype: "Url",
        description: "File downloaded for the speed test",
    },
    FieldDef {
        key: "speed_test_concurrency",
        label: "Speed Test Concurrency",
        ftype: "Number",
        description: "Parallel speed tests",
    },
    FieldDef {
        key: "speed_test_retries",
        label: "Speed Test Retries",
        ftype: "Number",
        description: "Retries per speed test",
    },
    FieldDef {
        key: "speed_test_min_duration",
        label: "Speed Test Min Duration",
        ftype: "Duration",
        description: "Min run length per download",
    },
    FieldDef {
        key: "speed_test_min_bytes",
        label: "Speed Test Min Bytes",
        ftype: "Number",
        description: "Min bytes per download",
    },
    FieldDef {
        key: "speed_test_max_duration",
        label: "Speed Test Max Duration",
        ftype: "Duration",
        description: "Max run length per download",
    },
    FieldDef {
        key: "geoip_mode",
        label: "GeoIP Mode",
        ftype: "Select:dat,mmdb",
        description: "GeoIP artifact format",
    },
    FieldDef {
        key: "geo_auto_update",
        label: "Geo Auto Update",
        ftype: "Boolean",
        description: "Re-download geo artifacts on a timer",
    },
    FieldDef {
        key: "geo_update_interval",
        label: "Geo Update Interval Hours",
        ftype: "Number",
        description: "Geo artifact re-download interval (hours)",
    },
];

const LOGGING_DEFS: &[FieldDef] = &[
    FieldDef {
        key: "log_ttl_secs",
        label: "Log Retention",
        ftype: "Duration",
        description: "How long core logs stay stored",
    },
    FieldDef {
        key: "log_to_file",
        label: "Log to File",
        ftype: "Boolean",
        description: "Also write core logs to a file",
    },
    FieldDef {
        key: "log_file_path",
        label: "Log File Path",
        ftype: "Text",
        description: "Log file path",
    },
];

const DNS_DEFS: &[FieldDef] = &[
    FieldDef {
        key: "servers",
        label: "Servers (JSON)",
        ftype: "Text",
        description: "DNS servers the core queries (comma-sep)",
    },
    FieldDef {
        key: "hosts",
        label: "Hosts (JSON)",
        ftype: "Text",
        description: "Static host mappings (comma-sep)",
    },
    FieldDef {
        key: "query_strategy",
        label: "Query Strategy",
        ftype: "Select:,,UseIP,UseIPv4,UseIPv6",
        description: "A/AAAA preference",
    },
    FieldDef {
        key: "disable_cache",
        label: "Disable Cache",
        ftype: "Boolean",
        description: "Disable the core's DNS cache",
    },
    FieldDef {
        key: "disable_fallback",
        label: "Disable Fallback",
        ftype: "Boolean",
        description: "Disable fallback servers",
    },
    FieldDef {
        key: "client_ip",
        label: "Client IP",
        ftype: "Text",
        description: "Reported client IP for EDNS",
    },
    FieldDef {
        key: "cache_ttl_secs",
        label: "DNS Cache TTL (secs)",
        ftype: "Number",
        description: "TUI DNS cache TTL, empty = 300",
    },
];

const ROUTE_PROBES_DEFS: &[FieldDef] = &[FieldDef {
    key: "probes",
    label: "Probes (comma-sep)",
    ftype: "Text",
    description: "Hostnames that must resolve for the routing probe",
}];

/// The field table a section's form shows, in row order. `Routing` is a list
/// pane (no fields); `Subscriptions` rows belong to the group form.
pub(crate) const fn field_defs(section: SettingsSection) -> &'static [FieldDef] {
    match section {
        SettingsSection::Gui => GUI_DEFS,
        SettingsSection::Inbound => INBOUND_DEFS,
        SettingsSection::SystemProxy => SYSTEM_PROXY_DEFS,
        SettingsSection::Tun => TUN_DEFS,
        SettingsSection::Mux => MUX_DEFS,
        SettingsSection::SpeedTest => SPEED_TEST_DEFS,
        SettingsSection::Logging => LOGGING_DEFS,
        SettingsSection::Dns => DNS_DEFS,
        SettingsSection::RouteProbes => ROUTE_PROBES_DEFS,
        SettingsSection::Routing => &[],
    }
}

/// Open the Settings popup with the first section selected and its settings
/// already on screen (R1).
///
/// There is no "nothing selected" state: the right pane is never empty while
/// the popup is open, so a user cannot land on a blank form and have to
/// discover the `Enter` that fills it.
pub async fn enter_settings(state: &mut AppState) {
    // Selection starts on the first leaf and all groups are expanded. The
    // list, the search bar and the status message are session state and never
    // resume stale values.
    state.settings_sections = crate::types::SectionList::default();
    state.settings_search = crate::types::SettingsSearch::default();
    state.settings_notice = None;
    state.settings_form_snapshot = None;
    state.settings_form_defaults = None;
    let section = crate::SettingsSection::Gui;
    let right = state.build_right_pane(section).await;
    state.mode = AppMode::Settings {
        mode: SettingsMode::Split {
            focus: SplitFocus::Tree,
            right,
        },
    };
}

pub async fn build_settings_fields(
    state: &AppState,
    section: SettingsSection,
) -> Vec<(String, String)> {
    match section {
        SettingsSection::Dns => match state.db.get_dns_settings().await {
            Ok(Some(dns)) => vec![
                // Vec fields render comma-joined in the form; split back
                // on save (join/split at the form boundary).
                ("servers".into(), dns.servers.join(",")),
                ("hosts".into(), dns.hosts.join(",")),
                (
                    "query_strategy".into(),
                    match dns.query_strategy {
                        Some(leas_db::models::QueryStrategy::UseIp) => "UseIP".into(),
                        Some(leas_db::models::QueryStrategy::UseIpv4) => "UseIPv4".into(),
                        Some(leas_db::models::QueryStrategy::UseIpv6) => "UseIPv6".into(),
                        None => String::new(),
                    },
                ),
                ("disable_cache".into(), dns.disable_cache.to_string()),
                ("disable_fallback".into(), dns.disable_fallback.to_string()),
                ("client_ip".into(), dns.client_ip.unwrap_or_default()),
                (
                    "cache_ttl_secs".into(),
                    dns.cache_ttl_secs
                        .map_or_else(String::new, |t| t.to_string()),
                ),
            ],
            _ => dns_fresh_fields(),
        },
        // Routing/Subscriptions list panes build their own state; RouteProbes
        // loads in build_right_pane (async db read can't live here).
        _ => build_config_fields(&state.config, section),
    }
}

/// The fresh-install Dns form: no DB row means nothing is configured; the
/// empty fields ARE the defaults (the cache TTL's 300 lives in the app, not
/// the row).
fn dns_fresh_fields() -> Vec<(String, String)> {
    field_defs(SettingsSection::Dns)
        .iter()
        .map(|def| (def.key.to_owned(), String::new()))
        .collect()
}

/// The values a section's form shows, straight from `config`. Key order is
/// the `field_defs` table's — the two cannot drift.
fn build_config_fields(
    config: &leas_config::AppConfig,
    section: SettingsSection,
) -> Vec<(String, String)> {
    match section {
        SettingsSection::Dns | SettingsSection::RouteProbes => {
            // DB-backed; `build_settings_fields` owns them.
            Vec::new()
        }
        SettingsSection::Routing => Vec::new(),
        _ => field_defs(section)
            .iter()
            .map(|def| (def.key.to_owned(), config_value(config, section, def.key)))
            .collect(),
    }
}

/// One field's value off a config, formatted exactly as the form always
/// showed it (humantime durations, empty string for `None`).
fn config_value(config: &leas_config::AppConfig, section: SettingsSection, key: &str) -> String {
    use crate::SettingsSection::{Gui, Inbound, Logging, Mux, SpeedTest, SystemProxy, Tun};
    match (section, key) {
        (Gui, "language") => config.gui.language.clone(),
        (Gui, "theme") => config.theme_name.clone(),
        (Gui, "refresh_interval") => {
            humantime::format_duration(*config.gui.refresh_interval_secs).to_string()
        }
        (Inbound, "socks_port") => config.inbound.socks_port.to_string(),
        (Inbound, "http_port") => config.inbound.http_port.map_or_default(|p| p.to_string()),
        (Inbound, "mixed_port") => config.inbound.mixed_port.map_or_default(|p| p.to_string()),
        (Inbound, "listen") => config.inbound.listen.clone(),
        (Inbound, "sniffing") => config.inbound.sniffing.to_string(),
        (SystemProxy, "enabled") => config.system_proxy.enabled.to_string(),
        (SystemProxy, "http_port") => config
            .system_proxy
            .http_port
            .map_or_default(|p| p.to_string()),
        (SystemProxy, "socks_port") => config
            .system_proxy
            .socks_port
            .map_or_default(|p| p.to_string()),
        (SystemProxy, "bypass") => config.system_proxy.bypass.clone().unwrap_or_default(),
        (Tun, "enabled") => config.tun.enabled.to_string(),
        (Tun, "interface_name") => config.tun.interface_name.clone().unwrap_or_default(),
        (Tun, "mtu") => config.tun.mtu.map_or_default(|m| m.to_string()),
        (Mux, "enabled") => config.mux.enabled.to_string(),
        (Mux, "concurrency") => config.mux.concurrency.map_or_default(|c| c.to_string()),
        (Mux, "protocol") => config.mux.protocol.clone(),
        (Mux, "max_connections") => config.mux.max_connections.map_or_default(|c| c.to_string()),
        (Mux, "min_streams") => config.mux.min_streams.map_or_default(|c| c.to_string()),
        (Mux, "max_streams") => config.mux.max_streams.map_or_default(|c| c.to_string()),
        (Mux, "padding") => config.mux.padding.to_string(),
        (Mux, "fragment_enabled") => config.mux.fragment_enabled.to_string(),
        (Mux, "fragment_packets") => config.mux.fragment_packets.clone().unwrap_or_default(),
        (Mux, "fragment_length") => config.mux.fragment_length.clone().unwrap_or_default(),
        (Mux, "fragment_interval") => config.mux.fragment_interval.clone().unwrap_or_default(),
        (SpeedTest, "ping_url") => config.speed_test.ping_url.clone(),
        (SpeedTest, "ip_provider") => config.speed_test.ip_provider.to_string(),
        (SpeedTest, "tcp_timeout_secs") => {
            humantime::format_duration(*config.speed_test.tcp_timeout_secs).to_string()
        }
        (SpeedTest, "real_ping_timeout_secs") => {
            humantime::format_duration(*config.speed_test.real_ping_timeout_secs).to_string()
        }
        (SpeedTest, "real_ping_retries") => config.speed_test.real_ping_retries.to_string(),
        (SpeedTest, "real_ping_concurrency") => config.speed_test.real_ping_concurrency.to_string(),
        (SpeedTest, "real_ping_test_all_protocols") => {
            config.speed_test.real_ping_test_all_protocols.to_string()
        }
        (SpeedTest, "task_queue_limit") => config.speed_test.task_queue_limit.to_string(),
        (SpeedTest, "dns_failure_defer_secs") => {
            config.speed_test.dns_failure_defer_secs.to_string()
        }
        (SpeedTest, "error_ttl_hours") => config
            .speed_test
            .error_ttl_hours
            .map_or_else(String::new, |h| h.to_string()),
        (SpeedTest, "speed_test_url") => config.speed_test.speed_test_url.clone(),
        (SpeedTest, "speed_test_concurrency") => {
            config.speed_test.speed_test_concurrency.to_string()
        }
        (SpeedTest, "speed_test_retries") => config.speed_test.speed_test_retries.to_string(),
        (SpeedTest, "speed_test_min_duration") => {
            humantime::format_duration(*config.speed_test.speed_test_min_duration).to_string()
        }
        (SpeedTest, "speed_test_min_bytes") => config.speed_test.speed_test_min_bytes.to_string(),
        (SpeedTest, "speed_test_max_duration") => {
            humantime::format_duration(*config.speed_test.speed_test_max_duration).to_string()
        }
        (SpeedTest, "geoip_mode") => match config.geo.geoip_mode {
            leas_config::app_config::GeoIpMode::Dat => "dat",
            leas_config::app_config::GeoIpMode::Mmdb => "mmdb",
        }
        .to_string(),
        (SpeedTest, "geo_auto_update") => config.geo.auto_update.to_string(),
        (SpeedTest, "geo_update_interval") => config.geo.update_interval_hours.to_string(),
        (Logging, "log_ttl_secs") => {
            humantime::format_duration(*config.logging.ttl_secs).to_string()
        }
        (Logging, "log_to_file") => config.logging.log_to_file.to_string(),
        (Logging, "log_file_path") => config.logging.log_file_path.clone(),
        _ => String::new(),
    }
}

/// What a fresh install would load into `section`'s form.
///
/// This is the value of `r` (reset) and the `○`-at-default comparison.
/// Config-backed sections read `AppConfig::default()` through the SAME
/// formatter as the live builder, so reset and load cannot disagree.
#[must_use]
pub fn default_fields(section: SettingsSection) -> Vec<(String, String)> {
    match section {
        SettingsSection::Dns => dns_fresh_fields(),
        SettingsSection::RouteProbes => vec![("probes".into(), String::new())],
        _ => build_config_fields(&leas_config::AppConfig::default(), section),
    }
}

fn apply_settings_fields(
    state: &mut AppState,
    section: SettingsSection,
    fields: &[(String, String)],
) {
    use crate::SettingsSection::{
        Dns, Gui, Inbound, Logging, Mux, Routing, SpeedTest, SystemProxy, Tun,
    };
    let get_str = |key: &str| -> &str {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map_or("", |(_, v)| v.as_str())
    };
    let get = |key: &str| get_str(key).to_owned();
    let get_opt = |key: &str| {
        let v = get_str(key);
        if v.is_empty() {
            None
        } else {
            Some(v.to_owned())
        }
    };
    match section {
        Gui => {
            state.config.gui.language = get("language");
            let theme_slug = get_str("theme");
            if !theme_slug.is_empty() && state.config.theme_name != theme_slug {
                // Apply live, so the popup (and everything behind it) re-renders
                // in the theme the user just picked.
                match crate::ui::theme::load(theme_slug) {
                    Ok(theme) => {
                        theme_slug.clone_into(&mut state.config.theme_name);
                        state.theme = theme;
                    }
                    Err(error) => state.log_trace(
                        "error",
                        "tui::ops::settings",
                        &format!("theme `{theme_slug}` rejected: {error}"),
                    ),
                }
            }
            if let Ok(d) = humantime::parse_duration(get_str("refresh_interval")) {
                *state.config.gui.refresh_interval_secs = d;
            }
        }
        Inbound => {
            if let Ok(v) = get_str("socks_port").parse::<u16>() {
                state.config.inbound.socks_port = v;
            }
            state.config.inbound.http_port = get_str("http_port").parse::<u16>().ok();
            state.config.inbound.mixed_port = get_str("mixed_port").parse::<u16>().ok();
            if !get_str("listen").is_empty() {
                state.config.inbound.listen = get("listen");
            }
            state.config.inbound.sniffing = get_str("sniffing") == "true";
        }
        SystemProxy => {
            state.config.system_proxy.enabled = get_str("enabled") == "true";
            state.config.system_proxy.http_port = get_str("http_port").parse::<u16>().ok();
            state.config.system_proxy.socks_port = get_str("socks_port").parse::<u16>().ok();
            state.config.system_proxy.bypass = get_opt("bypass");
        }
        Tun => {
            state.config.tun.enabled = get_str("enabled") == "true";
            state.config.tun.interface_name = get_opt("interface_name");
            state.config.tun.mtu = get_str("mtu").parse::<u16>().ok();
        }
        Mux => {
            state.config.mux.enabled = get_str("enabled") == "true";
            state.config.mux.concurrency = get_str("concurrency").parse::<u8>().ok();
            if !get_str("protocol").is_empty() {
                state.config.mux.protocol = get("protocol");
            }
            state.config.mux.max_connections = get_str("max_connections").parse::<u8>().ok();
            state.config.mux.min_streams = get_str("min_streams").parse::<u8>().ok();
            state.config.mux.max_streams = get_str("max_streams").parse::<u16>().ok();
            state.config.mux.padding = get_str("padding") == "true";
            state.config.mux.fragment_enabled = get_str("fragment_enabled") == "true";
            state.config.mux.fragment_packets = get_opt("fragment_packets");
            state.config.mux.fragment_length = get_opt("fragment_length");
            state.config.mux.fragment_interval = get_opt("fragment_interval");
        }

        SpeedTest => {
            if !get_str("ping_url").is_empty() {
                state.config.speed_test.ping_url = get("ping_url");
            }
            if let Ok(p) = get_str("ip_provider").parse::<IpProvider>() {
                state.config.speed_test.ip_provider = p;
            }
            if let Ok(d) = humantime::parse_duration(get_str("tcp_timeout_secs")) {
                *state.config.speed_test.tcp_timeout_secs = d;
            }
            if let Ok(d) = humantime::parse_duration(get_str("real_ping_timeout_secs")) {
                *state.config.speed_test.real_ping_timeout_secs = d;
            }
            if let Ok(v) = get_str("real_ping_retries").parse::<u32>() {
                state.config.speed_test.real_ping_retries = v;
            }
            if let Ok(v) = get_str("real_ping_concurrency").parse::<usize>() {
                state.config.speed_test.real_ping_concurrency = v;
            }
            state.config.speed_test.real_ping_test_all_protocols =
                get_str("real_ping_test_all_protocols") == "true";
            if let Ok(v) = get_str("task_queue_limit").parse::<u16>() {
                state.config.speed_test.task_queue_limit = v;
            }
            if let Ok(v) = get_str("dns_failure_defer_secs").parse::<i64>() {
                state.config.speed_test.dns_failure_defer_secs = v;
            }
            // Empty = never (None); a non-empty field must parse as hours.
            state.config.speed_test.error_ttl_hours =
                get_opt("error_ttl_hours").and_then(|s| s.parse::<i64>().ok());
            if !get_str("speed_test_url").is_empty() {
                state.config.speed_test.speed_test_url = get("speed_test_url");
            }
            if let Ok(v) = get_str("speed_test_concurrency").parse::<usize>() {
                state.config.speed_test.speed_test_concurrency = v;
            }
            if let Ok(v) = get_str("speed_test_retries").parse::<u32>() {
                state.config.speed_test.speed_test_retries = v;
            }
            if let Ok(d) = humantime::parse_duration(get_str("speed_test_min_duration")) {
                *state.config.speed_test.speed_test_min_duration = d;
            }
            if let Ok(v) = get_str("speed_test_min_bytes").parse::<u64>() {
                state.config.speed_test.speed_test_min_bytes = v;
            }
            if let Ok(d) = humantime::parse_duration(get_str("speed_test_max_duration")) {
                *state.config.speed_test.speed_test_max_duration = d;
            }
            let old_geoip_mode = state.config.geo.geoip_mode;
            state.config.geo.geoip_mode = if get_str("geoip_mode").eq_ignore_ascii_case("mmdb") {
                leas_config::app_config::GeoIpMode::Mmdb
            } else {
                leas_config::app_config::GeoIpMode::Dat
            };
            state.config.geo.auto_update = get_str("geo_auto_update") == "true";
            if let Ok(v) = get_str("geo_update_interval").parse::<u64>() {
                state.config.geo.update_interval_hours = v;
            }
            // A mode change must fetch the new artifact; an unrelated save
            // only recompiles. The dataset itself is chosen in the Routing
            // pane's header, which refreshes on its own.
            if state.config.geo.geoip_mode == old_geoip_mode {
                state.spawn_routing_engine_rebuild();
            } else {
                crate::ops::geodata::refresh_geo(state);
            }
        }
        // Dns, Routing and RouteProbes are handled separately (DB-backed)
        Dns | Routing | crate::SettingsSection::RouteProbes => {}
        Logging => {
            if let Ok(d) = humantime::parse_duration(get_str("log_ttl_secs")) {
                *state.config.logging.ttl_secs = d;
            }
            state.config.logging.log_to_file = get_str("log_to_file") == "true";
            if !get_str("log_file_path").is_empty() {
                state.config.logging.log_file_path = get("log_file_path");
            }
        }
    }
}

pub async fn build_right_pane(state: &mut AppState, section: SettingsSection) -> SplitRightPane {
    let fields = build_settings_fields(state, section).await;
    // Dirty-tracking snapshot (spec P3): Esc on a form compares live fields
    // against what was loaded. The defaults snapshot (fresh-install values)
    // is what `r` writes and `○` compares against; a list pane has neither.
    state.settings_form_snapshot = None;
    state.settings_form_defaults = None;
    match section {
        SettingsSection::Routing => {
            state.reload_routing_rules().await;
            SplitRightPane::RoutingList { selected: 0 }
        }

        SettingsSection::RouteProbes => {
            let hosts = state.db.get_route_probes().await.unwrap_or_default();
            state.settings_form_snapshot = Some(vec![("probes".into(), hosts.join(", "))]);
            state.settings_form_defaults = Some(default_fields(section));
            SplitRightPane::Form {
                section,
                fields: vec![("probes".into(), hosts.join(", "))],
                focus_index: 0,
                form_errors: HashMap::new(),
            }
        }
        _ => {
            state.settings_form_snapshot = Some(fields.clone());
            state.settings_form_defaults = Some(default_fields(section));
            SplitRightPane::Form {
                section,
                fields,
                focus_index: 0,
                form_errors: HashMap::new(),
            }
        }
    }
}

pub fn save_settings_form(
    state: &mut AppState,
    section: SettingsSection,
    fields: &[(String, String)],
) {
    apply_settings_fields(state, section, fields);
    state.settings_form_snapshot = None;
    // The scheduler limits are runtime-settable: apply the persisted values
    // so the next batch honors them without a restart. The DNS window goes
    // through the same clamp as config load — it is the same user setting, and
    // a value below one resolution's deadline defers nothing.
    //
    // The RAISED value is written back, not just passed to `set_limits`:
    // otherwise the form keeps showing the user's 5, the file persists 5, the
    // runtime uses 15, and every save re-clamps and re-warns. One number,
    // everywhere the setting is read.
    let dns_defer_secs =
        crate::state::clamp_dns_defer_secs(state.config.speed_test.dns_failure_defer_secs);
    state.config.speed_test.dns_failure_defer_secs = dns_defer_secs;
    state
        .scheduler
        .set_limits(state.config.speed_test.task_queue_limit, dns_defer_secs);
    if let Err(e) = state.config.save() {
        state.log_trace(
            "error",
            "tui::ops::settings",
            &format!("Failed to save config: {e}"),
        );
    } else {
        state.log_trace("info", "tui::ops::settings", "Settings saved");
    }
}

pub async fn save_routing_rule(
    state: &mut AppState,
    rule_id: Option<String>,
    fields: &[(String, String)],
) {
    let id = rule_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let get_str = |key: &str| -> &str {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map_or("", |(_, v)| v.as_str())
    };
    let get_opt = |key: &str| {
        let v = get_str(key);
        if v.is_empty() {
            None
        } else {
            Some(v.to_owned())
        }
    };
    // Vec fields are comma-joined in the form; split at the form boundary.
    // `ports`/`source_ports` are u16 lists; the other lists are strings.
    let split = |v: &str| -> Vec<String> {
        v.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    let split_u16 = |v: &str| -> Vec<u16> {
        v.split(',')
            .filter_map(|t| t.trim().parse::<u16>().ok())
            .collect()
    };
    let ports = split_u16(get_str("ports"));
    let source_ports = split_u16(get_str("source_ports"));
    let active_ruleset = state.config.geo.country.key();
    let rule = RoutingRule {
        id,
        group_id: None,
        ruleset: Some(active_ruleset.to_string()),
        r#type: get_str("type").parse::<i32>().unwrap_or(0),
        domain_matcher: get_opt("domain_matcher"),
        domains: split(get_str("domains")),
        ips: split(get_str("ips")),
        inbound_tags: split(get_str("inbound_tags")),
        ports,
        source_ports,
        network: get_opt("network"),
        protocols: split(get_str("protocols")),
        domain_strategy: get_opt("domain_strategy"),
        outbound_tag: get_opt("outbound_tag"),
        balancer_tag: get_opt("balancer_tag"),
        rule_set_file: get_opt("rule_set_file"),
        rule_set_url: get_opt("rule_set_url"),
        sort_order: None,
    };
    // rule_set_file/rule_set_url count as match conditions at save time, but
    // neither core builder emits them yet (xray has no rule-set support;
    // sing-box rule_set emission is intentionally out of scope for now). The
    // fields remain persisted for future sing-box rule-set support.
    let has_matcher = !rule.domains.is_empty()
        || !rule.ips.is_empty()
        || !rule.inbound_tags.is_empty()
        || !rule.ports.is_empty()
        || !rule.source_ports.is_empty()
        || rule.network.is_some()
        || !rule.protocols.is_empty()
        || rule.rule_set_file.is_some()
        || rule.rule_set_url.is_some();
    if !has_matcher {
        state.log_trace(
            "error",
            "tui::ops::settings",
            "Routing rule needs at least one match condition",
        );
        return;
    }
    // The typed model has no dedicated routing-rule write; upsert through the
    // pooled connection (upsert is idempotent for add and edit alike).
    let result = upsert_rule(&state.db, &rule).await;
    match result {
        Ok(()) => state.log_trace("info", "tui::ops::settings", "Routing rule saved"),
        Err(e) => state.log_trace(
            "error",
            "tui::ops::settings",
            &format!("Failed to save routing rule: {e}"),
        ),
    }
    state.reload_routing_rules().await;
}

/// Insert or update one routing row. Shared by the form save and the
/// default-table seed so the two cannot drift on the column set.
pub(crate) async fn upsert_rule(db: &leas_db::Database, rule: &RoutingRule) -> Result<(), String> {
    let mut conn = db.connection().await.map_err(|e| e.to_string())?;
    leas_db::models::RoutingRule::upsert_by_id(rule.id.clone())
        .group_id(rule.group_id.clone())
        .ruleset(rule.ruleset.clone())
        .r#type(rule.r#type)
        .domain_matcher(rule.domain_matcher.clone())
        .domains(rule.domains.clone())
        .ips(rule.ips.clone())
        .inbound_tags(rule.inbound_tags.clone())
        .ports(rule.ports.clone())
        .source_ports(rule.source_ports.clone())
        .network(rule.network.clone())
        .protocols(rule.protocols.clone())
        .domain_strategy(rule.domain_strategy.clone())
        .outbound_tag(rule.outbound_tag.clone())
        .balancer_tag(rule.balancer_tag.clone())
        .rule_set_file(rule.rule_set_file.clone())
        .rule_set_url(rule.rule_set_url.clone())
        .sort_order(rule.sort_order)
        .exec(&mut conn)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Seed the active country's custom set from its shipped table, when the
/// country has no custom rows yet. Called when the mode flips to `custom`, so
/// "custom" starts identical to "default".
pub async fn seed_custom_rules(state: &mut AppState) {
    let country = state.config.geo.country;
    let key = country.key();
    // NULL rows are this country's custom rows too (`active_rules` selects
    // them), so seeding on top of them would duplicate the user's set.
    if state
        .routing_rules
        .iter()
        .any(|rule| rule.ruleset.as_deref().is_none_or(|value| value == key))
    {
        return;
    }
    let start = state
        .routing_rules
        .iter()
        .filter_map(|rule| rule.sort_order)
        .max()
        .map_or(0, |order| order.saturating_add(1));
    for rule in crate::ops::routing_defaults::default_rules(country, start) {
        if let Err(error) = upsert_rule(&state.db, &rule).await {
            state.log_trace(
                "error",
                "tui::ops::settings",
                &format!("Failed to seed the default ruleset: {error}"),
            );
            return;
        }
    }
    state.reload_routing_rules().await;
    state.log_trace(
        "info",
        "tui::ops::settings",
        "Custom ruleset seeded from the shipped default",
    );
}

/// Persist the probes editor: split the comma-separated field, drop empties,
/// and wholesale-replace the singleton row (the db dedupes).
pub async fn save_route_probes(state: &mut AppState, fields: &[(String, String)]) {
    let raw = fields
        .iter()
        .find(|(k, _)| k == "probes")
        .map_or("", |(_, v)| v.as_str());
    let hosts: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    match state.db.upsert_route_probes(hosts).await {
        Ok(()) => state.log_trace("info", "tui::ops::settings", "Probe hosts saved"),
        Err(e) => state.log_trace(
            "error",
            "tui::ops::settings",
            &format!("Failed to save probe hosts: {e}"),
        ),
    }
}

pub async fn save_dns_settings(state: &mut AppState, fields: &[(String, String)]) {
    let id = state
        .db
        .get_dns_settings()
        .await
        .ok()
        .flatten()
        .map_or_else(|| uuid::Uuid::new_v4().to_string(), |d| d.id);
    let get_str = |key: &str| -> &str {
        fields
            .iter()
            .find(|(k, _)| k == key)
            .map_or("", |(_, v)| v.as_str())
    };
    let get_opt = |key: &str| {
        let v = get_str(key);
        if v.is_empty() {
            None
        } else {
            Some(v.to_owned())
        }
    };
    let split = |v: &str| -> Vec<String> {
        v.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    let query_strategy = match get_str("query_strategy") {
        "UseIP" => Some(leas_db::models::QueryStrategy::UseIp),
        "UseIPv4" => Some(leas_db::models::QueryStrategy::UseIpv4),
        "UseIPv6" => Some(leas_db::models::QueryStrategy::UseIpv6),
        _ => None,
    };
    let dns = leas_db::models::DnsSetting {
        id,
        name: None,
        servers: split(get_str("servers")),
        hosts: split(get_str("hosts")),
        query_strategy,
        disable_cache: get_str("disable_cache") == "true",
        disable_fallback: get_str("disable_fallback") == "true",
        client_ip: get_opt("client_ip"),
        cache_ttl_secs: get_opt("cache_ttl_secs").and_then(|s| s.parse().ok()),
    };
    let result: Result<(), String> = async {
        let mut conn = state.db.connection().await.map_err(|e| e.to_string())?;
        leas_db::models::DnsSetting::upsert_by_id(dns.id.clone())
            .name(dns.name.clone())
            .servers(dns.servers.clone())
            .hosts(dns.hosts.clone())
            .query_strategy(dns.query_strategy)
            .disable_cache(dns.disable_cache)
            .disable_fallback(dns.disable_fallback)
            .client_ip(dns.client_ip.clone())
            .cache_ttl_secs(dns.cache_ttl_secs)
            .exec(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            // Apply immediately: TTL gate reads this on the next resolve.
            if let Some(ttl) = dns.cache_ttl_secs {
                state.dns_cache_ttl_secs = ttl;
            }
            state.log_trace("info", "tui::ops::settings", "DNS settings saved");
        }
        Err(e) => state.log_trace(
            "error",
            "tui::ops::settings",
            &format!("Failed to save DNS settings: {e}"),
        ),
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;
    use crate::SettingsSection;

    /// Reset ground truth: what `r` writes and what a fresh install loads
    /// must be the same vector, section by section.
    #[tokio::test]
    async fn default_fields_equal_build_over_a_fresh_config() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("defaults.db"))
                .await
                .unwrap(),
        );
        let state = AppState::new(db, leas_config::AppConfig::default()).await;
        for section in [
            SettingsSection::Gui,
            SettingsSection::Inbound,
            SettingsSection::SystemProxy,
            SettingsSection::Tun,
            SettingsSection::Mux,
            SettingsSection::SpeedTest,
            SettingsSection::Logging,
        ] {
            let built = build_settings_fields(&state, section).await;
            let defaults = default_fields(section);
            assert_eq!(
                built, defaults,
                "{section}: reset must write what a fresh config loads"
            );
        }
    }

    /// The defs table and the builder share one key order; when this test
    /// was written, `SpeedTest`'s builder emitted `error_ttl_hours` while the
    /// defs did not, so every row from `speed_test_url` on showed the wrong
    /// label/value pair. DB-backed sections are checked against their own
    /// builder branch (`build_config_fields` deliberately skips them).
    #[test]
    fn every_section_def_matches_the_builder_key_order() {
        // Config-backed: the table IS the builder's key source.
        for section in [
            SettingsSection::Gui,
            SettingsSection::Inbound,
            SettingsSection::SystemProxy,
            SettingsSection::Tun,
            SettingsSection::Mux,
            SettingsSection::SpeedTest,
            SettingsSection::Logging,
        ] {
            let def_keys: Vec<_> = field_defs(section).iter().map(|def| def.key).collect();
            let built = build_config_fields(&leas_config::AppConfig::default(), section);
            let built_keys: Vec<_> = built.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(def_keys, built_keys, "{section}: defs and builder drifted");
        }
        // DB-backed Dns: the table must match the builder's fresh-DB branch.
        let dns_fresh: Vec<String> = dns_fresh_fields().into_iter().map(|(k, _)| k).collect();
        let dns_keys = field_defs(SettingsSection::Dns)
            .iter()
            .map(|def| def.key.to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            dns_keys, dns_fresh,
            "Dns: defs and the fresh-DB branch drifted"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::apply_settings_fields;
    use super::build_settings_fields;
    use super::save_route_probes;
    use super::seed_custom_rules;
    use super::upsert_rule;
    use crate::AppState;
    use crate::types::SettingsSection;
    use leas_db::models::RoutingRule;

    /// The exit-IP provider crosses three representations on one save: the
    /// Select's option string, the stored field value, and the enum the apply
    /// parses. A mismatch anywhere leaves the setting silently at its default
    /// (the apply keeps the old value when the string does not parse), which no
    /// compiler and no render check would catch.
    #[tokio::test]
    async fn speed_test_provider_survives_the_form_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, leas_config::AppConfig::default()).await;
        let names: Vec<String> = leas_config::ip_provider::SELECT_CELL
            .strip_prefix("Select:")
            .expect("the cell must declare its options")
            .split(',')
            .map(str::to_string)
            .collect();

        for name in &names {
            let provider: leas_config::IpProvider = name
                .parse()
                .unwrap_or_else(|_| panic!("the select offers {name}, which does not parse"));
            state.config.speed_test.ip_provider = provider;
            let fields = build_settings_fields(&state, SettingsSection::SpeedTest).await;
            let saved = fields
                .iter()
                .find(|(k, _)| k == "ip_provider")
                .unwrap_or_else(|| panic!("the form must carry ip_provider, got {fields:?}"));
            assert_eq!(&saved.1, name, "the snapshot must emit the selectable name");

            // Clobber, then replay the save: the value must come back.
            state.config.speed_test.ip_provider = leas_config::IpProvider::default();
            apply_settings_fields(&mut state, SettingsSection::SpeedTest, &fields);
            assert_eq!(
                state.config.speed_test.ip_provider, provider,
                "{name} did not survive the round trip"
            );
        }
    }

    /// The active ruleset is exclusive and country-scoped: the shipped table
    /// in `default` mode, the country's custom rows (plus pre-ruleset NULL
    /// rows) in `custom` mode, and nothing from another country.
    #[tokio::test]
    async fn active_rules_follow_the_mode_and_the_country() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, leas_config::AppConfig::default()).await;
        state.config.geo.country = leas_config::GeoCountry::Ru;
        state.config.geo.ruleset = Some(leas_config::RulesetMode::Default);

        let shipped = state.active_rules();
        assert_eq!(
            shipped.len(),
            crate::ops::routing_defaults::default_rules(leas_config::GeoCountry::Ru, 0).len()
        );
        assert!(shipped.iter().all(|r| r.ruleset.as_deref() == Some("ru")));

        // Custom rows for two countries plus a pre-ruleset NULL row.
        for (id, ruleset) in [("a", Some("ru")), ("b", Some("cn")), ("legacy", None)] {
            let mut rule = RoutingRule {
                id: id.to_string(),
                group_id: None,
                ruleset: ruleset.map(str::to_string),
                r#type: 0,
                domain_matcher: None,
                domains: vec!["example.com".to_string()],
                ips: Vec::new(),
                inbound_tags: Vec::new(),
                ports: Vec::new(),
                source_ports: Vec::new(),
                network: None,
                protocols: Vec::new(),
                domain_strategy: None,
                outbound_tag: Some("direct".to_string()),
                balancer_tag: None,
                rule_set_file: None,
                rule_set_url: None,
                sort_order: Some(0),
            };
            rule.sort_order = Some(rule.sort_order.unwrap_or(0));
            upsert_rule(&state.db, &rule).await.unwrap();
        }
        state.reload_routing_rules().await;
        state.config.geo.ruleset = Some(leas_config::RulesetMode::Custom);

        let ids: Vec<String> = state.active_rules().into_iter().map(|r| r.id).collect();
        assert!(ids.contains(&"a".to_string()));
        assert!(ids.contains(&"legacy".to_string()));
        assert!(
            !ids.contains(&"b".to_string()),
            "another country's rows stay inactive"
        );
    }

    /// A rules read failure keeps the previous snapshot and must NOT flip the
    /// effective mode to the shipped table: that would reroute traffic on a
    /// transient DB error.
    #[tokio::test]
    async fn a_rules_read_failure_pins_the_custom_ruleset() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, leas_config::AppConfig::default()).await;
        assert_eq!(
            state.ruleset_mode(),
            leas_config::RulesetMode::Default,
            "an empty table resolves to the shipped default"
        );
        state.routing_rules_load_failed = true;
        assert_eq!(
            state.ruleset_mode(),
            leas_config::RulesetMode::Custom,
            "a failed read must not substitute the shipped table"
        );
        assert!(
            state.active_rules().is_empty(),
            "the snapshot is kept as-is"
        );
    }

    /// A pre-ruleset NULL row IS the country's custom set: seeding on top of
    /// it would duplicate the user's rules.
    #[tokio::test]
    async fn seeding_skips_a_table_that_already_has_legacy_rows() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, leas_config::AppConfig::default()).await;
        state.config.geo.country = leas_config::GeoCountry::Ru;
        let mut legacy = RoutingRule {
            id: "legacy".to_string(),
            group_id: None,
            ruleset: None,
            r#type: 0,
            domain_matcher: None,
            domains: vec!["example.com".to_string()],
            ips: Vec::new(),
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            network: None,
            protocols: Vec::new(),
            domain_strategy: None,
            outbound_tag: Some("direct".to_string()),
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: Some(0),
        };
        legacy.sort_order = Some(0);
        upsert_rule(&state.db, &legacy).await.unwrap();
        state.reload_routing_rules().await;

        seed_custom_rules(&mut state).await;
        assert_eq!(state.routing_rules.len(), 1, "no shipped rows were added");
        assert_eq!(state.routing_rules[0].id, "legacy");
    }

    /// Flipping to custom seeds the shipped table once; a second flip must not
    /// duplicate it, or every mode toggle would grow the table.
    #[tokio::test]
    async fn seed_custom_rules_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, leas_config::AppConfig::default()).await;
        state.config.geo.country = leas_config::GeoCountry::Cn;

        seed_custom_rules(&mut state).await;
        let first = state.routing_rules.len();
        assert_eq!(
            first,
            crate::ops::routing_defaults::default_rules(leas_config::GeoCountry::Cn, 0).len()
        );
        seed_custom_rules(&mut state).await;
        assert_eq!(state.routing_rules.len(), first, "seed must be idempotent");
        assert!(
            state
                .routing_rules
                .iter()
                .all(|r| r.ruleset.as_deref() == Some("cn"))
        );
    }

    #[tokio::test]
    async fn save_route_probes_splits_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, leas_config::AppConfig::default()).await;
        let fields = vec![(
            "probes".to_string(),
            " a.example.com , b.example.com ,, ".to_string(),
        )];
        save_route_probes(&mut state, &fields).await;
        let hosts = state.db.get_route_probes().await.unwrap();
        assert_eq!(
            hosts,
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
    }
}
