#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    reason = "TUI display domain: ports validated to u16, timestamps fit i64, list indices bounded by rendered rows; converting each cast adds unwrap noise with no correctness gain"
)]
#![allow(
    clippy::future_not_send,
    reason = "single-threaded TUI: futures are spawned onto one local runtime and never cross threads"
)]

pub mod ops;
pub mod route_compile;
pub mod state;
mod types;
pub mod ui;

// Re-exports
pub use state::AppState;
pub use types::*;

// ── Helper functions ───────────────────────────────────────────────────

use tokio::sync::mpsc;
use tracing::warn;

use leas_proto::proto_spec::{ProtoSpec, ProtocolConfig};

/// Helper to send a `CoreEvent` with a warning on channel full.
/// Prevents silent event loss.
pub(crate) fn try_send_or_warn(
    tx: &mpsc::Sender<CoreEvent>,
    event: CoreEvent,
    label: &'static str,
) {
    if let Err(_e) = tx.try_send(event) {
        warn!(target: "tui::events", "try_send dropped {label}: channel full");
    }
}

fn common_field_defaults() -> Vec<(String, String)> {
    vec![
        ("address".to_string(), String::new()),
        ("port".to_string(), "443".to_string()),
        ("core_type".to_string(), "auto".to_string()),
    ]
}

/// Populate the add/edit-server form fields from a typed [`Protocol`] row and
/// its endpoint.
///
/// The `Protocol` must be loaded with its deferred `config` JSON included
/// (edit flow reads via `.include(Protocol::fields().config())`); the
/// [`leas_db::Database::upsert_protocol`] write has the same requirement.
/// `core_type` is seeded "auto" by [`common_field_defaults`] — the caller
/// post-sets it from the link's `core_type` (the per-pair override), which
/// this function does not receive.
pub(crate) fn profile_to_fields(
    protocol: &leas_db::models::Protocol,
    endpoint: &leas_db::models::Endpoint,
    addresses: &[std::net::IpAddr],
) -> Vec<(String, String)> {
    let mut fields = common_field_defaults();
    if !protocol.config.is_unloaded() {
        let config = &protocol.config.get().0;
        if let Some(v) = leas_config::import_export::profile_user_id(config) {
            set_field(&mut fields, "user_id", &v);
        }
        if let Some(v) = config.security_type() {
            set_field(&mut fields, "security", v);
        }
        if let Some(v) = config.transport_type() {
            set_field(&mut fields, "network", v);
        }
        // Stream-settings fields for the edit form: typed protocols expose
        // their flat `network`/`security` keys via the accessors above;
        // placeholder protocols (Redirect/TProxy/Mixed) carry their stream
        // settings as an opaque blob — pass those through unchanged.
        if let ProtocolConfig::Redirect(c) | ProtocolConfig::TProxy(c) | ProtocolConfig::Mixed(c) =
            config
            && let Ok(blob) = serde_json::from_slice::<serde_json::Value>(&c.settings_json)
            && let Some(ss) = blob.get("stream_settings")
        {
            flatten_json_to_fields(ss, &mut fields);
        }
    }
    // The `address` field is the DIAL host, not the DNS name: an IP-literal
    // endpoint's `dns_name()` is empty, so the form would open blank and its
    // re-submit would fail validation (~75% of a real feed).
    let address = endpoint.display_host(addresses);
    if !address.is_empty() {
        set_field(&mut fields, "address", &address);
    }
    if endpoint.port > 0 {
        set_field(&mut fields, "port", &endpoint.port.to_string());
    }
    fields
}

/// Flatten a settings JSON object into `(key, value)` form fields (ported from
/// the removed `leas_config::import_export::flatten_json_to_fields`).
/// String/bool/number leaf values are kept; nested objects and arrays are
/// skipped — the form fields are flat keys.
fn flatten_json_to_fields(json: &serde_json::Value, fields: &mut Vec<(String, String)>) {
    if let serde_json::Value::Object(obj) = json {
        for (k, v) in obj {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Number(n) => n.to_string(),
                _ => continue,
            };
            fields.push((k.clone(), val));
        }
    }
}

fn set_field(fields: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some((_, existing)) = fields.iter_mut().find(|(k, _)| k == key) {
        *existing = value.to_string();
    } else {
        fields.push((key.to_string(), value.to_string()));
    }
}

/// Get a value from a form field list, returning None if empty or missing.
#[must_use]
pub fn get_field(fields: &[(String, String)], key: &str) -> Option<String> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty())
}

/// `Timestamp` → "YYYY-MM-DD HH:MM:SS" in the system local time zone.
/// Callers render "—" for `None`.
#[must_use]
pub fn format_ts(secs: i64) -> String {
    leas_db::models::from_epoch(secs)
        .to_zoned(jiff::tz::TimeZone::system())
        .strftime("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// Compact relative time for the panel "last used" column: "2d ago", "5h
/// ago", "3m ago", "now" for under a minute. Callers render "never" for
/// `None`.
#[must_use]
pub fn format_relative_ts(secs: i64) -> String {
    let span = jiff::Timestamp::now()
        .since(leas_db::models::from_epoch(secs))
        .unwrap_or_default();
    let (n, unit) = if span.get_weeks() > 0 {
        (span.get_weeks() as u64, "w")
    } else if span.get_days() > 0 {
        (span.get_days() as u64, "d")
    } else if span.get_hours() > 0 {
        (span.get_hours() as u64, "h")
    } else if span.get_minutes() > 0 {
        (span.get_minutes() as u64, "m")
    } else {
        return "now".to_string();
    };
    format!("{n}{unit} ago")
}

/// "US" → "🇺🇸"; anything not exactly 2 ASCII alpha chars → "🏴" (U+1F3F4).
#[must_use]
pub fn iso_to_flag(iso: &str) -> String {
    let b = iso.as_bytes();
    if b.len() == 2 && b[0].is_ascii_alphabetic() && b[1].is_ascii_alphabetic() {
        let mut s = String::with_capacity(8);
        for c in iso.chars() {
            let regional = u32::from(c) - u32::from('A') + 0x1F1E6;
            s.push(char::from_u32(regional).unwrap_or('\u{1F3F4}'));
        }
        s
    } else {
        "\u{1F3F4}".to_string()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_field_defaults() {
        let fields = common_field_defaults();
        assert_ne!(fields.len(), 0);
        assert!(fields.iter().any(|(k, _)| k == "address"));
        assert!(fields.iter().any(|(k, _)| k == "port"));
        assert!(!fields.iter().any(|(k, _)| k == "remarks"));
        assert!(fields.iter().any(|(k, _)| k == "core_type"));
    }

    #[test]
    fn test_set_field() {
        let mut fields = common_field_defaults();
        set_field(&mut fields, "port", "8443");
        assert_eq!(
            fields
                .iter()
                .find(|(k, _)| k == "port")
                .map(|(_, v)| v.as_str()),
            Some("8443")
        );
        set_field(&mut fields, "new_key", "value");
        assert!(fields.iter().any(|(k, _)| k == "new_key"));
    }

    #[test]
    fn test_get_field() {
        let mut fields = common_field_defaults();
        set_field(&mut fields, "port", "8443");
        assert_eq!(get_field(&fields, "port"), Some("8443".to_string()));
        // Empty value should return None
        assert_eq!(get_field(&fields, "nonexistent"), None);
    }

    #[test]
    fn format_ts_renders_local_yyyymmdd_hhmmss() {
        // The agreed shape is "YYYY-MM-DD HH:MM:SS" in the system local
        // zone. The output is TZ-dependent by design, so the shape is pinned
        // and correctness is verified by a round-trip: parsing the rendered
        // local civil time in the system zone must recover the exact instant
        // (a UTC-only formatter would fail this whenever TZ != UTC).
        let ts = jiff::Timestamp::from_second(1_752_595_200).expect("valid ts");
        let s = format_ts(leas_db::models::to_epoch(ts));
        assert_eq!(s.len(), 19, "YYYY-MM-DD HH:MM:SS is 19 chars");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], " ");
        assert_eq!(&s[13..14], ":");
        assert_eq!(&s[16..17], ":");
        let parsed = jiff::civil::DateTime::strptime("%Y-%m-%d %H:%M:%S", &s)
            .expect("parse format_ts output")
            .to_zoned(jiff::tz::TimeZone::system())
            .expect("local zoned conversion")
            .timestamp();
        assert_eq!(
            parsed, ts,
            "rendered local time must round-trip to the same instant"
        );
    }
}
