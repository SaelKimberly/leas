//! The shipped per-country rulesets: `default` tables for `cn`, `ir` and `ru`.
//!
//! Sources: RU is the `RoscomVPN` reference profile
//! (`thirdparty/roscomvpn-routing/HAPP/DEFAULT.JSON`, `RouteOrder:
//! block-proxy-direct`) with `torrent` routed `direct` (their MIHOMO profile).
//! CN is v2rayN's built-in whitelist (`ServiceLib/Sample/custom_routing_white`:
//! mainland direct, LAN direct, ads blocked) reduced to what our three
//! outbounds can express. IR follows the same shape with the v2fly
//! `category-ir` list; v2rayN ships no IR ruleset, only
//! `ExpectedIPs = ["geoip:cn","geoip:ir","geoip:ru"]`.
//!
//! Compatibility is the dataset's job, not this table's: a code the selected
//! dataset cannot serve is marked disabled in the pane and skipped at compile.
//! Under `Loyalsoldier` the RU table loses its service categories; under
//! `RoscomVPN` the CN and IR tables lose `cn`/`category-ir` but keep
//! `geoip:<cc>` through the `GeoLite2` fallback.

use leas_config::GeoCountry;
use leas_db::models::RoutingRule;
use leas_route::ir::{BLOCK_TAG, DIRECT_TAG, PROXY_TAG};

/// Prefix of every shipped row id: `preset:<country>:<nn>`.
pub const ID_PREFIX: &str = "preset:";

/// One row of a shipped table.
struct Row {
    domains: &'static [&'static str],
    ips: &'static [&'static str],
    outbound: &'static str,
}

const fn sites(domains: &'static [&'static str], outbound: &'static str) -> Row {
    Row {
        domains,
        ips: &[],
        outbound,
    }
}

/// Declaration order is evaluation order (block, then proxy, then direct; the
/// engine is first-match and the default route is `proxy`).
const RU: &[Row] = &[
    sites(&["geosite:win-spy"], BLOCK_TAG),
    sites(&["geosite:category-ads"], BLOCK_TAG),
    sites(&["geosite:google-play"], PROXY_TAG),
    sites(&["geosite:github"], PROXY_TAG),
    sites(&["geosite:twitch-ads"], PROXY_TAG),
    sites(&["geosite:youtube"], PROXY_TAG),
    sites(&["geosite:telegram"], PROXY_TAG),
    sites(&["geosite:private"], DIRECT_TAG),
    sites(&["geosite:torrent"], DIRECT_TAG),
    sites(&["geosite:category-ru"], DIRECT_TAG),
    sites(&["geosite:whitelist"], DIRECT_TAG),
    sites(&["geosite:microsoft"], DIRECT_TAG),
    sites(&["geosite:apple"], DIRECT_TAG),
    sites(&["geosite:epicgames"], DIRECT_TAG),
    sites(&["geosite:riot"], DIRECT_TAG),
    sites(&["geosite:escapefromtarkov"], DIRECT_TAG),
    sites(&["geosite:steam"], DIRECT_TAG),
    sites(&["geosite:twitch"], DIRECT_TAG),
    sites(&["geosite:pinterest"], DIRECT_TAG),
    sites(&["geosite:faceit"], DIRECT_TAG),
    // Two rows, not one: `geoip:direct` is a RoscomVPN-only category, and the
    // gate drops a whole row when any token is unservable — sharing the row
    // would take the built-in `private` match down with it under Loyalsoldier.
    Row {
        domains: &[],
        ips: &["geoip:private"],
        outbound: DIRECT_TAG,
    },
    Row {
        domains: &[],
        ips: &["geoip:direct"],
        outbound: DIRECT_TAG,
    },
];

const CN: &[Row] = &[
    sites(&["geosite:category-ads"], BLOCK_TAG),
    sites(&["geosite:private"], DIRECT_TAG),
    sites(&["geosite:cn"], DIRECT_TAG),
    Row {
        domains: &[],
        ips: &["geoip:private", "geoip:cn"],
        outbound: DIRECT_TAG,
    },
];

const IR: &[Row] = &[
    sites(&["geosite:category-ads"], BLOCK_TAG),
    sites(&["geosite:private"], DIRECT_TAG),
    sites(&["geosite:category-ir"], DIRECT_TAG),
    Row {
        domains: &[],
        ips: &["geoip:private", "geoip:ir"],
        outbound: DIRECT_TAG,
    },
];

/// The rows of one country's shipped table.
const fn table(country: GeoCountry) -> &'static [Row] {
    match country {
        GeoCountry::Ru => RU,
        GeoCountry::Cn => CN,
        GeoCountry::Ir => IR,
    }
}

/// The shipped table as `RoutingRule` rows, ids and `sort_order` assigned in
/// declaration order.
///
/// `start` is the first free sort order: the caller passes one past the user's
/// last row so the table appends BELOW them. Explicit orders, never `None` —
/// SQLite sorts NULL first, so a NULL would put the table above user rows.
#[must_use]
pub fn default_rules(country: GeoCountry, start: i32) -> Vec<RoutingRule> {
    let key = country.key();
    table(country)
        .iter()
        .enumerate()
        .map(|(index, row)| RoutingRule {
            id: format!("{ID_PREFIX}{key}:{index:02}"),
            group_id: None,
            ruleset: Some(key.to_string()),
            r#type: 0,
            domain_matcher: None,
            domains: row.domains.iter().map(|d| (*d).to_string()).collect(),
            ips: row.ips.iter().map(|ip| (*ip).to_string()).collect(),
            inbound_tags: Vec::new(),
            ports: Vec::new(),
            source_ports: Vec::new(),
            network: None,
            protocols: Vec::new(),
            domain_strategy: None,
            outbound_tag: Some(row.outbound.to_string()),
            balancer_tag: None,
            rule_set_file: None,
            rule_set_url: None,
            sort_order: Some(start.saturating_add(i32::try_from(index).unwrap_or(i32::MAX))),
        })
        .collect()
}

/// The ruleset mode in effect: the explicit choice, or — when the config has
/// never chosen — `custom` if the database holds rows, `default` if empty.
#[must_use]
pub fn effective_mode(
    cfg: &leas_config::AppConfig,
    db_rows: &[RoutingRule],
) -> leas_config::RulesetMode {
    cfg.geo.ruleset.unwrap_or(if db_rows.is_empty() {
        leas_config::RulesetMode::Default
    } else {
        leas_config::RulesetMode::Custom
    })
}

/// The rows the engine and the pane use for the active ruleset.
///
/// One predicate for the interactive rebuild AND the geo auto-update loop: an
/// auto-update must never recompile another country's rows.
#[must_use]
pub fn effective_rules(cfg: &leas_config::AppConfig, db_rows: &[RoutingRule]) -> Vec<RoutingRule> {
    effective_rules_for(cfg, db_rows, effective_mode(cfg, db_rows))
}

/// [`effective_rules`] with the mode supplied by the caller — the pane pins
/// `custom` after a failed read, which the pure resolution cannot see.
#[must_use]
pub fn effective_rules_for(
    cfg: &leas_config::AppConfig,
    db_rows: &[RoutingRule],
    mode: leas_config::RulesetMode,
) -> Vec<RoutingRule> {
    let country = cfg.geo.country;
    match mode {
        leas_config::RulesetMode::Default => default_rules(country, 0),
        leas_config::RulesetMode::Custom => {
            let key = country.key();
            db_rows
                .iter()
                .filter(|rule| rule.ruleset.as_deref().is_none_or(|value| value == key))
                .cloned()
                .collect()
        }
    }
}

/// Whether `id` names a shipped row (any country).
#[must_use]
pub fn is_shipped(id: &str) -> bool {
    id.starts_with(ID_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row must survive the compiler the engine build uses: an empty row
    /// or an unknown outbound tag is a table that half-applies and then takes
    /// routing down on the next rebuild.
    #[test]
    fn every_default_row_compiles() {
        for country in [GeoCountry::Ru, GeoCountry::Cn, GeoCountry::Ir] {
            for (index, rule) in default_rules(country, 0).iter().enumerate() {
                crate::route_compile::rule_from_row(rule, index)
                    .unwrap_or_else(|e| panic!("{country:?} row {index} does not compile: {e}"));
            }
        }
    }

    /// Ids are unique, start with the country they belong to, and carry the
    /// `ruleset` value the pane filters on.
    #[test]
    fn ids_and_rulesets_are_country_scoped() {
        let mut seen = std::collections::HashSet::new();
        for country in [GeoCountry::Ru, GeoCountry::Cn, GeoCountry::Ir] {
            for rule in default_rules(country, 0) {
                let key = country.key();
                assert!(
                    rule.id.starts_with(&format!("{ID_PREFIX}{key}:")),
                    "{}",
                    rule.id
                );
                assert_eq!(rule.ruleset.as_deref(), Some(key));
                assert!(is_shipped(&rule.id));
                assert!(seen.insert(rule.id), "duplicate id");
            }
        }
    }

    /// The reference profile's `RouteOrder: block-proxy-direct` is the only
    /// thing keeping `twitch-ads` (proxy) ahead of `twitch` (direct) and the
    /// ads blocks ahead of everything.
    #[test]
    fn rows_follow_block_then_proxy_then_direct() {
        let rank = |tag: Option<&str>| match tag {
            Some(BLOCK_TAG) => 0,
            Some(PROXY_TAG) => 1,
            Some(DIRECT_TAG) => 2,
            other => panic!("unexpected outbound {other:?}"),
        };
        for country in [GeoCountry::Ru, GeoCountry::Cn, GeoCountry::Ir] {
            let ranks: Vec<usize> = default_rules(country, 0)
                .iter()
                .map(|r| rank(r.outbound_tag.as_deref()))
                .collect();
            assert!(
                ranks.windows(2).all(|w| w[0] <= w[1]),
                "{country:?} rows are out of order: {ranks:?}"
            );
        }
    }

    fn cfg(country: GeoCountry, mode: Option<leas_config::RulesetMode>) -> leas_config::AppConfig {
        let mut cfg = leas_config::AppConfig::default();
        cfg.geo.country = country;
        cfg.geo.ruleset = mode;
        cfg
    }

    fn retagged(id: &str, ruleset: Option<&str>) -> RoutingRule {
        let mut rule = default_rules(GeoCountry::Ru, 0).remove(0);
        rule.id = id.to_string();
        rule.ruleset = ruleset.map(str::to_string);
        rule
    }

    /// Exclusive selection: the shipped table in `default` mode (DB rows
    /// ignored), the country's custom rows plus pre-ruleset NULL rows in
    /// `custom` mode, and never another country's rows.
    #[test]
    fn effective_rules_select_exactly_one_ruleset() {
        let rows = [
            retagged("ru-row", Some("ru")),
            retagged("cn-row", Some("cn")),
            retagged("legacy", None),
        ];
        let shipped = effective_rules(
            &cfg(GeoCountry::Ru, Some(leas_config::RulesetMode::Default)),
            &rows,
        );
        assert!(
            shipped.iter().all(|r| r.id.starts_with("preset:ru:")),
            "default mode ignores the DB"
        );

        let ids: Vec<String> = effective_rules(
            &cfg(GeoCountry::Ru, Some(leas_config::RulesetMode::Custom)),
            &rows,
        )
        .into_iter()
        .map(|r| r.id)
        .collect();
        assert!(ids.contains(&"ru-row".to_string()));
        assert!(
            ids.contains(&"legacy".to_string()),
            "NULL rows are reachable"
        );
        assert!(
            !ids.contains(&"cn-row".to_string()),
            "another country stays out"
        );
    }

    /// A config that never chose resolves from the data: custom when rows
    /// exist (an upgrade must not ignore them), default when the table is
    /// empty.
    #[test]
    fn an_unchosen_mode_follows_the_database() {
        let rows = [retagged("x", Some("ru"))];
        let cfg = cfg(GeoCountry::Ru, None);
        assert_eq!(
            effective_mode(&cfg, &rows),
            leas_config::RulesetMode::Custom
        );
        assert_eq!(effective_mode(&cfg, &[]), leas_config::RulesetMode::Default);
    }

    /// The one shadowing pair the RU table needs, plus the CN/IR tables'
    /// direct-country rows.
    #[test]
    fn the_ru_table_keeps_its_shadowing_pair() {
        let rules = default_rules(GeoCountry::Ru, 0);
        let pos = |needle: &str| {
            rules
                .iter()
                .position(|r| r.domains.iter().any(|d| d == needle))
                .unwrap_or_else(|| panic!("missing {needle}"))
        };
        assert!(pos("geosite:twitch-ads") < pos("geosite:twitch"));
        assert!(pos("geosite:category-ads") < pos("geosite:google-play"));
    }

    /// The shipped tables append below the user's rows with explicit ascending
    /// orders (`None` would sort first in SQLite).
    #[test]
    fn default_orders_append_after_the_users_last_row() {
        let rules = default_rules(GeoCountry::Cn, 7);
        let orders: Vec<i32> = rules.iter().filter_map(|r| r.sort_order).collect();
        assert_eq!(orders.len(), rules.len());
        assert_eq!(orders.first(), Some(&7));
        assert!(orders.windows(2).all(|w| w[0] < w[1]), "{orders:?}");
    }
}
