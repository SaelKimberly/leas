//! Geo data files consumed by the routing engine.
//!
//! Two on-disk formats plus the `MaxMind` database (handled by the crate root):
//!
//! - [`dat`] — Xray/v2ray `geoip.dat` / `geosite.dat` protobuf lists, the
//!   format Xray, mihomo's geodata mode, and sing-box's legacy geosite reader
//!   consume.
//! - [`srs`] — sing-box binary rule-sets (`.srs`).
//!
//! Parsers return neutral shapes (`GeoDomains`, `GeoNet`, ranges) so this
//! crate stays independent of `leas-route`'s matcher types.

pub mod dat;
pub mod srs;

pub use dat::{GeoDomains, GeoNet, load_geoip, load_geosite, validate};
