//! Geo dataset sources for `geoip:` / `geosite:` resolution.
//!
//! One owner for the fixed dataset set: a variant knows the two release URLs it
//! resolves from, so `config.json` stores a name instead of two URLs that can
//! drift apart. The set is closed rather than free text because a code absent
//! from the selected dataset fails the whole engine build (fail closed): the
//! `RoscomVPN` `geoip.dat` carries only `direct` / `private` / `whitelist`, so a
//! rule written against `geoip:RU` would take routing down under it.
//!
//! `Loyalsoldier` stays the default: configs written before the selector have
//! no `dataset` key, and their rules use `geoip:<cc>` country codes.

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, EnumString};

/// The geo datasets a rule set can resolve from.
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
pub enum GeoDataset {
    /// `Loyalsoldier/v2ray-rules-dat`: per-country `geoip` codes plus the
    /// v2fly geosite categories.
    #[default]
    Loyalsoldier,
    /// `hydraponique/roscomvpn-*`: Russia/Belarus-tuned lists — `geoip:direct`
    /// (RU+BY minus RKN/blocked ranges), `geosite:whitelist`, `category-ru`,
    /// and the service categories the `RoscomVPN` routing profile names. Carries
    /// no per-country geoip codes.
    Roscomvpn,
}

impl GeoDataset {
    /// The `geosite.dat` release URL.
    #[must_use]
    pub const fn geosite_url(self) -> &'static str {
        match self {
            Self::Loyalsoldier => {
                "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
            }
            Self::Roscomvpn => {
                "https://github.com/hydraponique/roscomvpn-geosite/releases/latest/download/geosite.dat"
            }
        }
    }

    /// The `geoip.dat` release URL.
    #[must_use]
    pub const fn geoip_url(self) -> &'static str {
        match self {
            Self::Loyalsoldier => {
                "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
            }
            Self::Roscomvpn => {
                "https://github.com/hydraponique/roscomvpn-geoip/releases/latest/download/geoip.dat"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::GeoDataset;

    /// The settings form writes `Display` into a `Select:` cell and reads it
    /// back with `FromStr`, and `config.json` round-trips through serde — three
    /// spellings of the same name that nothing else keeps aligned.
    #[test]
    fn every_variant_has_one_name_across_strum_and_serde() {
        for dataset in GeoDataset::iter() {
            let name = dataset.to_string();
            assert_eq!(
                serde_json::to_value(dataset).unwrap().as_str(),
                Some(name.as_str()),
                "{dataset:?}: strum and serde disagree"
            );
            assert_eq!(
                name.parse::<GeoDataset>().ok(),
                Some(dataset),
                "{dataset:?}: {name} does not parse back"
            );
        }
    }

    /// Both artifacts are fetched as-is, so a typo is a dataset that never
    /// arrives (and, with `auto_update` on, a rebuild that fails closed).
    #[test]
    fn every_url_is_an_absolute_https_url() {
        for dataset in GeoDataset::iter() {
            for url in [dataset.geosite_url(), dataset.geoip_url()] {
                let parsed = url::Url::parse(url)
                    .unwrap_or_else(|e| panic!("{dataset:?}: {url} is not a URL: {e}"));
                assert_eq!(parsed.scheme(), "https", "{dataset:?}: {url}");
                assert!(parsed.host_str().is_some(), "{dataset:?}: no host");
                assert!(
                    parsed.path().to_ascii_lowercase().ends_with(".dat"),
                    "{dataset:?}: {url} does not name a .dat artifact"
                );
            }
        }
    }
}
