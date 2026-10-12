//! Identity hashing: allocation-free, per-kind, binary.
//!
//! [`ProtocolId`](crate::proto_spec::ProtocolEssentials) is `uid`, the persisted
//! dedup key. It is derived from two independent rapidhash streams fed in a
//! single traversal:
//!
//! * the **sig** stream sees only non-credential, non-default fields, so two
//!   configs that differ only in credentials share a `sig` (grouping "same way
//!   configured servers");
//! * the **credential** stream sees credentials only (and is domain-separated
//!   from the sig stream), producing `cred_hash = 0` when there are none.
//!
//! `uid = sig ^ cred_hash`, and `uid == sig` structurally when a config has no
//! credentials.
//!
//! # Framing (load-bearing)
//!
//! Every field is written as `tag: u8` followed by an explicit little-endian
//! length or a fixed-width encoding. Raw concatenation is forbidden: without
//! framing, `flow="ab", sni="c"` and `flow="a", sni="bc"` produce identical
//! byte streams and silently merge two distinct configs into one `Protocol`
//! row. No escape hatch writing raw bytes exists on this type.
//!
//! # Ordering (frozen wire format)
//!
//! The order in which a config's writer emits fields is part of the identity
//! format. Reordering or removing a field re-keys every stored row. Adding a
//! field is safe for existing rows only when it is absent/default there, i.e.
//! when it is written through an eliding helper. [`IDENTITY_VERSION`] is
//! written first so a deliberate format change is explicit.
//!
//! Tag ranges: `0x01..=0x3F` are shared structural fields (written by
//! [`super::common`] helpers and the [`ProtocolEssentials`] wrapper);
//! `0x40..=0xFF` are per-kind local fields.
//!
//! [`ProtocolEssentials`]: super::endpoint::ProtocolEssentials

use std::collections::HashMap;

use rapidhash::v3::{DEFAULT_RAPID_SECRETS, RapidStreamHasherV3};
use serde_json::Value;
use smallvec::SmallVec;

/// Identity format version, written first into both streams. A bump is a
/// deliberate, global re-key.
///
/// **3** — the `config_type` (`ShareUrl` vs `Form`) discriminator left the
/// identity (db-rewamp D9): the origin of a config does not change what it is,
/// so a form config and an identical share URL now share one `Protocol` row.
/// Every stored uid changes, so the schema tag moves with it (a wipe, the
/// accepted pre-alpha cost, `AGENTS.md` decision 4/11).
///
/// **2** — the SIP003 plugin field became a typed, lossless `PluginSpec`.
pub const IDENTITY_VERSION: u8 = 3;

/// Domain separator for the credential stream: credential bytes are hashed
/// with a different prefix than sig bytes, so a byte slice moved between the
/// credential and non-credential classes cannot cancel in the `sig ^ cred_hash`
/// fold.
const CRED_DOMAIN: &[u8] = b"\x00cred\x00";

/// Reserved tags for shared structural fields (never used by per-kind fields).
pub mod tag {
    pub const PROTO_KIND: u8 = 0x01;
    // 0x02 was CONFIG_TYPE, dropped with IDENTITY_VERSION 3 (db-rewamp D9).
    pub const CORE_TYPE: u8 = 0x03;

    // ── SecurityConfig ──
    /// TLS vs REALITY discriminator; written only when TLS/REALITY is present.
    pub const SEC_KIND: u8 = 0x10;
    pub const SEC_SNI: u8 = 0x11;
    pub const SEC_ALPN: u8 = 0x12;
    pub const SEC_FP: u8 = 0x13;
    /// Written only when `true` (`None`/`Some(false)` are the default).
    pub const SEC_INSECURE: u8 = 0x14;
    pub const SEC_CURVES: u8 = 0x15;
    pub const SEC_PQV: u8 = 0x16;
    pub const SEC_ECH: u8 = 0x17;
    pub const SEC_VCN: u8 = 0x18;
    pub const SEC_PCS: u8 = 0x19;
    pub const SEC_PIN_SHA256: u8 = 0x1A;
    /// REALITY public key — a public server parameter, so it belongs to `sig`.
    pub const SEC_PBK: u8 = 0x1B;
    pub const SEC_SID: u8 = 0x1C;
    pub const SEC_SPX: u8 = 0x1D;
    /// Extra security string (`SecurityConfig::enc`).
    pub const SEC_ENC: u8 = 0x1E;

    // ── TransportConfig ──
    /// Transport discriminator; written only for non-`tcp` transports.
    pub const TR_KIND: u8 = 0x28;
    pub const TR_PATH: u8 = 0x29;
    pub const TR_HOST: u8 = 0x2A;
    pub const TR_HEADERS: u8 = 0x2B;
    pub const TR_METHOD: u8 = 0x2C;
    pub const TR_IDLE_TIMEOUT: u8 = 0x2D;
    pub const TR_PING_TIMEOUT: u8 = 0x2E;
    pub const TR_SERVICE_NAME: u8 = 0x2F;
    pub const TR_AUTHORITY: u8 = 0x30;
    pub const TR_MODE: u8 = 0x31;
    pub const TR_USER_AGENT: u8 = 0x32;
    pub const TR_PING_INTERVAL: u8 = 0x33;
    pub const TR_MAX_EARLY_DATA: u8 = 0x34;
    pub const TR_EARLY_DATA_HEADER: u8 = 0x35;
    pub const TR_V2RAY_UPGRADE: u8 = 0x36;
    pub const TR_V2RAY_UPGRADE_FAST_OPEN: u8 = 0x37;
    pub const TR_ED: u8 = 0x38;
    pub const TR_EXTRA: u8 = 0x39;
    pub const TR_MTU: u8 = 0x3A;
    pub const TR_TTI: u8 = 0x3B;
    pub const TR_UPLINK_CAPACITY: u8 = 0x3C;
    pub const TR_DOWNLINK_CAPACITY: u8 = 0x3D;
    pub const TR_CONGESTION: u8 = 0x3E;
    pub const TR_READ_BUFFER: u8 = 0x3F;
    pub const TR_WRITE_BUFFER: u8 = 0x40;
    pub const TR_SEED: u8 = 0x41;
    pub const TR_HEADER_TYPE: u8 = 0x42;
}

/// Materialized identity: `uid = sig ^ cred_hash`, `sig != 0`, `uid != 0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub sig: u64,
    pub cred_hash: u64,
    pub uid: u64,
}

/// Single-pass identity writer over two framed rapidhash streams.
pub struct IdentityWriter {
    sig: RapidStreamHasherV3<'static>,
    cred: RapidStreamHasherV3<'static>,
    has_cred: bool,
}

/// Frame `bytes` with its tag and length. The ONLY write primitive: no method
/// exposes an unframed write.
fn frame(out: &mut RapidStreamHasherV3<'static>, field: u8, bytes: &[u8]) {
    out.write(&[field]);
    out.write(&len_u32(bytes.len()).to_le_bytes());
    out.write(bytes);
}

/// Element count as a framing width. Saturating (never truncating): a count
/// above `u32::MAX` is unreachable for a config field, and clamping keeps the
/// framing deterministic instead of silently wrapping.
fn len_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Frame a fixed-width little-endian scalar.
fn frame_le(out: &mut RapidStreamHasherV3<'static>, field: u8, bytes: &[u8]) {
    out.write(&[field]);
    out.write(bytes);
}

/// Canonical recursive JSON writer (object keys sorted; no allocation for
/// small maps). `serde_json::Map` is a `BTreeMap` in this workspace, but the
/// keys are sorted explicitly so a future `preserve_order` feature cannot
/// silently change identity.
fn write_json(out: &mut RapidStreamHasherV3<'static>, value: &Value) {
    match value {
        Value::Null => out.write(&[0x00]),
        Value::Bool(b) => out.write(&[0x01, u8::from(*b)]),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.write(&[0x02]);
                out.write(&u.to_le_bytes());
            } else if let Some(i) = n.as_i64() {
                out.write(&[0x03]);
                out.write(&i.to_le_bytes());
            } else {
                out.write(&[0x04]);
                out.write(&n.as_f64().unwrap_or_default().to_bits().to_le_bytes());
            }
        }
        Value::String(s) => {
            out.write(&[0x05]);
            frame(out, 0x00, s.as_bytes());
        }
        Value::Array(items) => {
            out.write(&[0x06]);
            out.write(&len_u32(items.len()).to_le_bytes());
            for item in items {
                write_json(out, item);
            }
        }
        Value::Object(map) => {
            out.write(&[0x07]);
            out.write(&len_u32(map.len()).to_le_bytes());
            let mut entries: SmallVec<[(&str, &Value); 8]> =
                map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            entries.sort_unstable_by_key(|(k, _)| *k);
            for (k, v) in entries {
                frame(out, 0x08, k.as_bytes());
                write_json(out, v);
            }
        }
    }
}

impl IdentityWriter {
    #[must_use]
    pub fn new() -> Self {
        let mut sig = RapidStreamHasherV3::new(&DEFAULT_RAPID_SECRETS);
        let mut cred = RapidStreamHasherV3::new(&DEFAULT_RAPID_SECRETS);
        sig.write(&[IDENTITY_VERSION]);
        cred.write(&[IDENTITY_VERSION]);
        cred.write(CRED_DOMAIN);
        Self {
            sig,
            cred,
            has_cred: false,
        }
    }

    /// Kind discriminator. MUST be the first per-config write; it separates
    /// kinds in both streams (so credentials of different kinds never share a
    /// `cred_hash`).
    pub fn kind(&mut self, kind: &str) {
        frame(&mut self.sig, 0x00, kind.as_bytes());
        frame(&mut self.cred, 0x00, kind.as_bytes());
    }

    /// Non-credential string, always written (caller decided it is non-default).
    pub fn str(&mut self, field: u8, value: &str) {
        frame(&mut self.sig, field, value.as_bytes());
    }

    /// Non-credential string, written only when present and different from the
    /// builder's default.
    pub fn opt_str(&mut self, field: u8, value: Option<&str>, default: &str) {
        if let Some(v) = value
            && v != default
        {
            self.str(field, v);
        }
    }

    /// Non-credential string, written whenever present (no known default).
    pub fn present_str(&mut self, field: u8, value: Option<&str>) {
        if let Some(v) = value {
            self.str(field, v);
        }
    }

    /// Non-credential string, written whenever present and non-empty (the
    /// builders drop empty strings, so `Some("")` and `None` build alike).
    pub fn nonempty_str(&mut self, field: u8, value: Option<&str>) {
        if let Some(v) = value
            && !v.is_empty()
        {
            self.str(field, v);
        }
    }

    /// Unsigned scalar, written only when present and different from default.
    pub fn opt_u64(&mut self, field: u8, value: Option<u64>, default: u64) {
        if let Some(v) = value
            && v != default
        {
            frame_le(&mut self.sig, field, &v.to_le_bytes());
        }
    }

    /// Unsigned scalar, written whenever present (no known default).
    pub fn present_u64(&mut self, field: u8, value: Option<u64>) {
        if let Some(v) = value {
            frame_le(&mut self.sig, field, &v.to_le_bytes());
        }
    }

    /// Optional flag whose default is `false`: `Some(false)`/`None` are equal.
    pub fn opt_flag(&mut self, field: u8, value: Option<bool>) {
        if value == Some(true) {
            frame(&mut self.sig, field, &[]);
        }
    }

    /// Ordered string list (`Vec` order is semantic).
    pub fn list_str(&mut self, field: u8, items: &[String]) {
        if items.is_empty() {
            return;
        }
        frame(&mut self.sig, field, &len_u32(items.len()).to_le_bytes());
        for item in items {
            frame(&mut self.sig, 0x00, item.as_bytes());
        }
    }

    /// String map, written with keys sorted (`HashMap` order must never reach
    /// the hasher).
    pub fn map_str(&mut self, field: u8, map: &HashMap<String, String>) {
        if map.is_empty() {
            return;
        }
        frame(&mut self.sig, field, &len_u32(map.len()).to_le_bytes());
        let mut entries: SmallVec<[(&str, &str); 8]> =
            map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
        for (k, v) in entries {
            frame(&mut self.sig, 0x00, k.as_bytes());
            frame(&mut self.sig, 0x01, v.as_bytes());
        }
    }

    /// Arbitrary JSON (XHTTP `extra`), canonicalized.
    pub fn json(&mut self, field: u8, value: &Value) {
        self.sig.write(&[field]);
        write_json(&mut self.sig, value);
    }

    /// Opaque framed bytes (only for blobs with no decomposable fields, e.g.
    /// `PlaceholderConfig::settings_json`).
    pub fn bytes(&mut self, field: u8, value: &[u8]) {
        frame(&mut self.sig, field, value);
    }

    /// Credential scalar. Empty values are dropped: a config whose credentials
    /// are all empty gets `cred_hash == 0` and `uid == sig`.
    pub fn cred(&mut self, key: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        self.has_cred = true;
        frame(&mut self.cred, 0x01, key.as_bytes());
        frame(&mut self.cred, 0x02, value.as_bytes());
    }

    #[must_use]
    pub fn finish(self) -> Identity {
        let sig = self.sig.finish();
        let sig = if sig == 0 { 1 } else { sig };
        let cred_hash = if self.has_cred { self.cred.finish() } else { 0 };
        let uid = sig ^ cred_hash;
        let uid = if uid == 0 { 1 } else { uid };
        Identity {
            sig,
            cred_hash,
            uid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig_of(f: impl FnOnce(&mut IdentityWriter)) -> u64 {
        let mut w = IdentityWriter::new();
        w.kind("test");
        f(&mut w);
        w.finish().sig
    }

    #[test]
    fn adjacent_string_fields_are_frame_separated() {
        let a = sig_of(|w| {
            w.str(0x50, "ab");
            w.str(0x51, "c");
        });
        let b = sig_of(|w| {
            w.str(0x50, "a");
            w.str(0x51, "bc");
        });
        assert_ne!(a, b, "unframed concatenation would collide");
    }

    #[test]
    fn empty_credentials_yield_uid_equal_to_sig() {
        let mut w = IdentityWriter::new();
        w.kind("test");
        w.cred("uuid", "");
        let id = w.finish();
        assert_eq!(id.cred_hash, 0);
        assert_eq!(id.uid, id.sig);
    }

    #[test]
    fn map_order_does_not_reach_the_hasher() {
        let mk = |pairs: &[(&str, &str)]| {
            let map: HashMap<String, String> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            sig_of(|w| w.map_str(0x52, &map))
        };
        assert_eq!(mk(&[("a", "1"), ("b", "2")]), mk(&[("b", "2"), ("a", "1")]));
    }

    #[test]
    fn credentials_do_not_move_the_sig() {
        let a = sig_of(|w| w.cred("uuid", "one"));
        let b = sig_of(|w| w.cred("uuid", "two"));
        assert_eq!(a, b, "sig ignores credentials");
    }

    #[test]
    fn identity_is_never_zero() {
        let id = IdentityWriter::new().finish();
        assert_ne!(id.sig, 0);
        assert_ne!(id.uid, 0);
    }
}
