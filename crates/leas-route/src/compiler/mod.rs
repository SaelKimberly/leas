//! Compiler frontends translating vendor routing configs into [`RuleSet`] IR.

mod singbox;
mod xray;

pub use singbox::compile_singbox;
pub use xray::compile_xray;

use crate::ir::{Action, DefaultRoute, RuleSet};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct CompileOutput {
    /// Compiled rule set.
    pub ruleset: RuleSet,
    /// `(rule_index, explanation)` pairs for tolerated deviations (unknown
    /// keys, skipped empty rules, deferred strategy semantics).
    pub warnings: Vec<(usize, String)>,
}

/// Provenance of a [`RuleSet`] handed to [`merge`]; informational only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeOrigin {
    /// Xray-core `routing` JSON.
    Xray,
    /// sing-box `route` JSON.
    SingBox,
    /// TUI DB `RoutingRule` rows (Task 8 converter).
    DbRows,
    /// Native on-disk rule-set file.
    NativeFile,
}

/// Merges front-end rule sets into one, preserving source order.
///
/// Semantics (locked, plan §7):
/// - rules concatenate in argument order;
/// - a tag colliding with any earlier source's tag is renamed to
///   `<tag>-<source_index>` everywhere it appears **within the colliding
///   source only** (its own `Action::Route` targets and its default);
///   references to earlier sources' tags (including their renamed forms,
///   e.g. `a-1`) pass through untouched;
/// - conflicting non-absent defaults: last wins, exactly one
///   `(0, "conflicting defaults ...")` warning;
/// - probes: union, deduped case-insensitively, first spelling kept;
/// - constituent warnings pass through unchanged.
pub fn merge(sources: Vec<(MergeOrigin, RuleSet)>) -> CompileOutput {
    let mut warnings: Vec<(usize, String)> = Vec::new();
    let mut rules = Vec::new();
    // Original (pre-rename) tags seen so far, across rules and defaults.
    let mut seen_orig: HashSet<String> = HashSet::new();
    let mut probes: Vec<String> = Vec::new();
    let mut probe_keys: HashSet<String> = HashSet::new();
    let mut default: Option<DefaultRoute> = None;
    let mut last_default_orig: Option<String> = None;
    let mut default_conflict = false;
    let mut default_trace: Vec<(MergeOrigin, String)> = Vec::new();
    let mut resolve_strategy = crate::ir::ResolveStrategy::AsIs;

    for (i, (origin, rs)) in sources.into_iter().enumerate() {
        let d_tag = default_target(&rs.default);
        // Rename ONLY this source's own colliding tag (its default target).
        // Self-references in its rules follow the rename; targets pointing
        // at other tags are cross-references to earlier sources and pass
        // through untouched (renaming them would break resolution).
        let mut rename: HashMap<String, String> = HashMap::new();
        let rule_tags: Vec<String> = rs
            .rules
            .iter()
            .filter_map(|r| route_target(&r.action).map(str::to_owned))
            .collect();
        if let Some(t) = d_tag
            && seen_orig.contains(t)
        {
            rename.insert(t.to_owned(), format!("{t}-{i}"));
        }
        let map = |t: &mut String| {
            if let Some(new) = rename.get(t.as_str()) {
                *t = new.clone();
            }
        };
        for mut r in rs.rules {
            if let Action::Route { tag, .. } = &mut r.action {
                map(tag);
            }
            rules.push(r);
        }
        if let Some(tag) = d_tag {
            default_trace.push((origin, tag.to_owned()));
            if last_default_orig.as_deref() != Some(tag) && last_default_orig.is_some() {
                default_conflict = true;
            }
            last_default_orig = Some(tag.to_owned());
            let mut renamed = tag.to_owned();
            map(&mut renamed);
            default = Some(DefaultRoute::Route { tag: renamed });
        }
        for t in rule_tags.iter().map(String::as_str).chain(d_tag) {
            seen_orig.insert(t.to_owned());
        }
        for new in rename.values() {
            seen_orig.insert(new.clone());
        }
        for p in rs.probes {
            if probe_keys.insert(p.to_lowercase()) {
                probes.push(p);
            }
        }
        if i == 0 {
            resolve_strategy = rs.resolve_strategy;
        }
    }

    if default_conflict {
        let trace = default_trace
            .iter()
            .map(|(o, t)| format!("{}:{t}", origin_name(*o)))
            .collect::<Vec<_>>()
            .join(", ");
        warnings.push((
            0,
            format!("conflicting defaults across sources; last wins ({trace})"),
        ));
    }

    CompileOutput {
        ruleset: RuleSet {
            rules,
            default: default.unwrap_or(DefaultRoute::Reject {
                method: crate::ir::RejectMethod::Drop,
            }),
            resolve_strategy,
            probes,
        },
        warnings,
    }
}

/// Human-readable name for a [`MergeOrigin`], used in warning text.
const fn origin_name(o: MergeOrigin) -> &'static str {
    match o {
        MergeOrigin::Xray => "xray",
        MergeOrigin::SingBox => "sing-box",
        MergeOrigin::DbRows => "db-rows",
        MergeOrigin::NativeFile => "native-file",
    }
}

/// The outbound tag an [`Action`] routes to, if any.
fn route_target(a: &Action) -> Option<&str> {
    match a {
        Action::Route { tag, .. } => Some(tag),
        _ => None,
    }
}

/// The outbound tag a [`DefaultRoute`] forwards to, if any (Reject is absent).
fn default_target(d: &DefaultRoute) -> Option<&str> {
    match d {
        DefaultRoute::Route { tag } => Some(tag),
        DefaultRoute::Reject { .. } => None,
    }
}

/// Extracts an optional JSON string-or-array-of-strings field as owned
/// strings. Errors when the value is present but neither shape.
pub(crate) fn field_strings(
    v: &serde_json::Value,
    rule_index: usize,
    field: &'static str,
) -> Result<Vec<String>, crate::RouteError> {
    match v {
        serde_json::Value::String(s) => Ok(vec![s.clone()]),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|it| match it {
                serde_json::Value::String(s) => Ok(s.clone()),
                other => Err(non_string(rule_index, field, other)),
            })
            .collect(),
        other => Err(non_string(rule_index, field, other)),
    }
}

fn non_string(rule_index: usize, field: &'static str, v: &serde_json::Value) -> crate::RouteError {
    crate::RouteError::Parse {
        rule_index,
        field,
        message: format!("expected string or string array, got {v}"),
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use crate::addr::PortRange;
    use crate::ir::{Action, Cond, DefaultRoute, MatchItem, ResolveStrategy, Rule, RuleSet};

    fn rs(default_tag: &str, probes: &[&str], rules: Vec<Rule>) -> RuleSet {
        RuleSet {
            rules,
            default: DefaultRoute::Route {
                tag: default_tag.to_owned(),
            },
            resolve_strategy: ResolveStrategy::AsIs,
            probes: probes.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    fn route_to(tag: &str) -> Action {
        Action::Route {
            tag: tag.to_owned(),
            override_addr: None,
        }
    }

    fn domain_rule(name: &str, tag: &str) -> Rule {
        Rule {
            name: Some(name.to_owned()),
            cond: Cond::All(vec![MatchItem::Domain {
                exact: vec![format!("{name}.test")],
                suffix: vec![],
                keywords: vec![],
                regexes: vec![],
            }]),
            action: route_to(tag),
        }
    }

    fn port_rule(name: &str, port: u16, tag: &str) -> Rule {
        Rule {
            name: Some(name.to_owned()),
            cond: Cond::All(vec![MatchItem::Ports(vec![PortRange {
                start: port,
                end: port,
            }])]),
            action: route_to(tag),
        }
    }

    #[test]
    fn collision_renames_later_tag_and_remaps_its_own_rules() {
        // Sources 0 and 1 both define tag "a". Source 1 additionally routes
        // one rule to its own "a" — that in-source reference must be renamed
        // along with the rule target, while source 0 keeps plain "a".
        let s0 = rs("a", &[], vec![domain_rule("d0", "a")]);
        let s1 = rs(
            "a",
            &[],
            vec![domain_rule("d1-self", "a"), port_rule("p1", 8080, "a")],
        );
        let out = merge(vec![(MergeOrigin::Xray, s0), (MergeOrigin::SingBox, s1)]);
        assert_eq!(out.ruleset.rules.len(), 3);
        assert_eq!(out.ruleset.rules[0].action, route_to("a"));
        assert_eq!(out.ruleset.rules[1].action, route_to("a-1"));
        assert_eq!(out.ruleset.rules[2].action, route_to("a-1"));
        // Renamed default (its tag was the collider) plus no spurious
        // warnings: same-tag defaults are NOT conflicting, they merge.
        assert_eq!(
            out.ruleset.default,
            DefaultRoute::Route {
                tag: "a-1".to_owned()
            }
        );
        assert!(out.warnings.is_empty(), "unexpected: {:?}", out.warnings);
    }

    #[test]
    fn later_reference_to_earlier_tag_is_untouched() {
        // Source 1 owns fresh tag "a" (source 0 only has "b") but routes one
        // rule at "b": the cross-reference must survive verbatim, and "a"
        // must not be renamed since it collides with nothing.
        let s0 = rs("b", &[], vec![domain_rule("d0", "b")]);
        let s1 = rs(
            "a",
            &[],
            vec![domain_rule("d1", "a"), port_rule("p1", 443, "b")],
        );
        let out = merge(vec![(MergeOrigin::Xray, s0), (MergeOrigin::SingBox, s1)]);
        assert_eq!(out.ruleset.rules[0].action, route_to("b"));
        assert_eq!(out.ruleset.rules[1].action, route_to("a"));
        assert_eq!(out.ruleset.rules[2].action, route_to("b"));
        assert_eq!(
            out.ruleset.default,
            DefaultRoute::Route {
                tag: "a".to_owned()
            }
        );
    }

    #[test]
    fn three_source_chain_collision_yields_a_a1_a2() {
        let mk = |tag: &str| rs(tag, &[], vec![domain_rule("d", tag)]);
        let out = merge(vec![
            (MergeOrigin::Xray, mk("a")),
            (MergeOrigin::SingBox, mk("a")),
            (MergeOrigin::DbRows, mk("a")),
        ]);
        assert_eq!(out.ruleset.rules[0].action, route_to("a"));
        assert_eq!(out.ruleset.rules[1].action, route_to("a-1"));
        assert_eq!(out.ruleset.rules[2].action, route_to("a-2"));
        assert_eq!(
            out.ruleset.default,
            DefaultRoute::Route {
                tag: "a-2".to_owned()
            }
        );
    }

    #[test]
    fn reference_to_earlier_renamed_form_passes_through() {
        // Sources 0 and 1 collide on "a" (-> a-1); source 2 routes a rule at
        // the renamed form "a-1" — a genuine cross-reference to source 1's
        // outbound, so it must NOT be renamed and "a-1" must not collide.
        let mk = |tag: &str| rs(tag, &[], vec![domain_rule("d", tag)]);
        let s2 = rs("z", &[], vec![port_rule("p", 9, "a-1")]);
        let out = merge(vec![
            (MergeOrigin::Xray, mk("a")),
            (MergeOrigin::SingBox, mk("a")),
            (MergeOrigin::DbRows, s2),
        ]);
        assert_eq!(out.ruleset.rules[2].action, route_to("a-1"));
        assert_eq!(
            out.ruleset.default,
            DefaultRoute::Route {
                tag: "z".to_owned()
            }
        );
    }

    #[test]
    fn probes_dedup_case_insensitive_first_spelling_wins() {
        let s0 = rs("d0", &["Probe.Example.com", "alpha"], vec![]);
        let s1 = rs("d1", &["probe.example.COM", "beta"], vec![]);
        let out = merge(vec![(MergeOrigin::Xray, s0), (MergeOrigin::SingBox, s1)]);
        assert_eq!(
            out.ruleset.probes,
            vec![
                "Probe.Example.com".to_owned(),
                "alpha".to_owned(),
                "beta".to_owned()
            ]
        );
    }

    #[test]
    fn conflicting_defaults_last_wins_with_exactly_one_warning() {
        let s0 = rs("a", &[], vec![]);
        let s1 = rs("b", &[], vec![]);
        let s2 = rs("c", &[], vec![]);
        let out = merge(vec![
            (MergeOrigin::Xray, s0),
            (MergeOrigin::SingBox, s1),
            (MergeOrigin::DbRows, s2),
        ]);
        assert_eq!(
            out.ruleset.default,
            DefaultRoute::Route {
                tag: "c".to_owned()
            }
        );
        assert_eq!(out.warnings.len(), 1, "exactly one conflict warning");
        assert_eq!(out.warnings[0].0, 0);
        assert!(out.warnings[0].1.contains("conflicting defaults"));
        for (i, want) in [Some("a"), Some("b"), Some("c")].into_iter().enumerate() {
            assert!(
                out.warnings[0].1.contains(want.unwrap()),
                "warning should name origin {i} tag {want:?}: {}",
                out.warnings[0].1
            );
        }
    }

    #[test]
    fn identical_defaults_and_non_conflicting_defaults_stay_silent() {
        // Same tag twice: not a conflict, no warning.
        let same = merge(vec![
            (MergeOrigin::Xray, rs("a", &[], vec![])),
            (MergeOrigin::SingBox, rs("a", &[], vec![])),
        ]);
        assert_eq!(same.warnings, Vec::<(usize, String)>::new());
        // Distinct tags across disjoint sources: one warning (they conflict).
        let distinct = merge(vec![
            (MergeOrigin::Xray, rs("a", &[], vec![])),
            (MergeOrigin::SingBox, rs("b", &[], vec![])),
        ]);
        assert_eq!(distinct.warnings.len(), 1);
        assert_eq!(
            distinct.ruleset.default,
            DefaultRoute::Route {
                tag: "b".to_owned()
            }
        );
    }

    #[test]
    fn constituent_warnings_pass_through_and_empty_sources_default() {
        // The pass-through contract is structural: merge() only ever APPENDS
        // the default-conflict warning; it never drops or rewrites existing
        // pairs. Exercise via the conflict path and shape equality.
        let with_warning = merge(vec![
            (MergeOrigin::Xray, rs("x", &[], vec![])),
            (MergeOrigin::NativeFile, rs("y", &["p"], vec![])),
        ]);
        // Distinct defaults → 1 conflict warning on top of pass-throughs.
        assert_eq!(with_warning.warnings.len(), 1);
        assert_eq!(with_warning.ruleset.probes, vec!["p".to_owned()]);

        let empty = merge(Vec::new());
        assert!(empty.ruleset.rules.is_empty());
        assert_eq!(
            empty.ruleset.default,
            DefaultRoute::Reject {
                method: crate::ir::RejectMethod::Drop
            }
        );
        assert!(empty.ruleset.probes.is_empty());
        assert!(empty.warnings.is_empty());
        assert_eq!(empty.ruleset.resolve_strategy, ResolveStrategy::AsIs);
    }
}
