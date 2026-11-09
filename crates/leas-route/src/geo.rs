//! Geo data seam for engine builds.
//!
//! The engine itself owns no I/O: callers resolve datasets to local paths (and
//! rule-set keys to cached files) and hand them over in a [`GeoSource`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

/// Country lookup seam, so the engine's mmdb mode does not depend on the
/// concrete database wrapper and tests can inject a map.
pub trait CountryLookup: Send + Sync {
    /// Lowercase ISO-3166 alpha-2 country code for `ip`, when known.
    fn country(&self, ip: IpAddr) -> Option<Arc<str>>;
}

/// Local paths and handles for one engine build.
#[derive(Clone, Default)]
pub struct GeoSource {
    /// `geoip.dat` (CIDR mode).
    pub geoip: Option<PathBuf>,
    /// `geosite.dat`.
    pub geosite: Option<PathBuf>,
    /// Country database (mmdb mode); the engine never opens it itself.
    pub country: Option<Arc<dyn CountryLookup>>,
    /// Rule-set key (raw `file`/`url` from the IR) → prepared local path.
    pub rule_sets: HashMap<String, PathBuf>,
}

impl GeoSource {
    /// Whether no dataset/handle is available.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.geoip.is_none()
            && self.geosite.is_none()
            && self.country.is_none()
            && self.rule_sets.is_empty()
    }
}

#[cfg(feature = "geoip")]
impl CountryLookup for leas_geoip::GeoIp {
    fn country(&self, ip: IpAddr) -> Option<Arc<str>> {
        self.country_sync(ip)
    }
}
