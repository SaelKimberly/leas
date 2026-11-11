//! Country rulesets and their mode for the routing pane.
//!
//! A ruleset is per COUNTRY, not per dataset: `cn`, `ir` and `ru` each carry a
//! shipped `default` table (in `leas::ops::routing_defaults`) and a `custom`
//! table stored in `routing_rules`. The geo dataset only decides which rows in
//! the active ruleset are compatible — an incompatible code marks its row
//! disabled and is skipped at compile, never a build failure.
//!
//! Exactly ONE ruleset is active: the country plus the mode. The other
//! countries' custom rows stay stored and inactive.

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString};

/// The country rulesets the app ships.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    Serialize,
    Deserialize,
    Display,
    EnumIter,
    EnumString,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum GeoCountry {
    /// Russia/Belarus: direct RU, selected services proxied.
    #[default]
    Ru,
    /// China: direct mainland, selected services proxied.
    Cn,
    /// Iran: direct IR, everything else proxied.
    Ir,
}

/// Which of a country's two tables is active.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, EnumString,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum RulesetMode {
    /// The shipped table for the active country, generated from code.
    Default,
    /// The `routing_rules` rows for the active country, seeded from the
    /// default on the first edit.
    Custom,
}

impl GeoCountry {
    /// The stored `ruleset` value in `routing_rules`.
    ///
    /// A `&'static str` rather than `Display`: the routing pane compares it
    /// against every custom row on each render.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Ru => "ru",
            Self::Cn => "cn",
            Self::Ir => "ir",
        }
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::{GeoCountry, RulesetMode};

    /// `Display`, serde and `FromStr` are three spellings of one name; the
    /// routing pane stores the `FromStr` form and the header prints `Display`.
    #[test]
    fn every_country_has_one_name_across_strum_serde_and_parse() {
        for country in GeoCountry::iter() {
            let name = country.to_string();
            assert_eq!(
                serde_json::to_value(country).unwrap().as_str(),
                Some(name.as_str()),
                "{country:?}: strum and serde disagree"
            );
            assert_eq!(name.parse::<GeoCountry>().ok(), Some(country));
        }
    }

    #[test]
    fn every_mode_has_one_name_across_strum_serde_and_parse() {
        for mode in RulesetMode::iter() {
            let name = mode.to_string();
            assert_eq!(
                serde_json::to_value(mode).unwrap().as_str(),
                Some(name.as_str()),
                "{mode:?}: strum and serde disagree"
            );
            assert_eq!(name.parse::<RulesetMode>().ok(), Some(mode));
        }
    }

    /// `key()` is the stored `ruleset` value; it must equal the `Display` name
    /// or a saved row stops matching the active country.
    #[test]
    fn every_country_key_matches_its_display_name() {
        for country in GeoCountry::iter() {
            assert_eq!(country.key(), country.to_string());
        }
    }
}
