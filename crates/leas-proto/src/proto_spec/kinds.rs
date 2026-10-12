use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Protocol kinds.
///
/// Variants mirror the (being-replaced) `Protocol` enum from
/// `crates/leas-core/src/protocol.rs` — 27 variants incl. the 7 outbound-only
/// form types (`DokodemoDoor`, Freedom, Blackhole, Dns, Loopback, Custom) and the
/// separate Shadowsocks2022. `as_str()` MUST equal `Protocol::Display` outputs
/// VERBATIM ("hy", "hy2", "any-tls", "shadow-tls", "t-proxy", "ss-2022",
/// "dokodemo", ...). `FromStr` additionally accepts the legacy hyphen-less
/// aliases ("hysteria", "hysteria2", "anytls", "shadowtls", "tproxy",
/// "hysteria1") that proto identity hashing, `security_rank` and
/// `fields_to_profile` historically wrote.
///
/// Serde serializes via [`as_str`](Self::as_str) and deserializes via
/// [`FromStr`], so the JSON form is the protocol dialect ("vmess", "ss-2022",
/// ...) — never the Rust variant names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum ProtocolKind {
    Vmess,
    Vless,
    Shadowsocks,
    Shadowsocks2022,
    Socks,
    Http,
    Trojan,
    WireGuard,
    Hysteria2,
    DokodemoDoor,
    Freedom,
    Blackhole,
    Dns,
    Loopback,
    Custom,
    Tuic,
    Hysteria,
    Naive,
    AnyTls,
    ShadowTls,
    Tor,
    Ssh,
    Tailscale,
    ShadowsocksR,
    Redirect,
    TProxy,
    Mixed,
}

impl ProtocolKind {
    /// Maps v2rayN `EConfigType` integer values to protocol kinds (the legacy
    /// `config_type` column of the removed core `Protocol` enum, moved here in
    /// T23 so `ProfileKey`/fast-ping dispatch stay i32-based).
    #[must_use]
    pub const fn try_from_i32(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::Vmess),
            2 => Some(Self::Custom),
            3 => Some(Self::Shadowsocks),
            4 => Some(Self::Socks),
            5 => Some(Self::Vless),
            6 => Some(Self::Trojan),
            7 => Some(Self::Hysteria2),
            8 => Some(Self::Tuic),
            9 => Some(Self::WireGuard),
            10 => Some(Self::Http),
            11 => Some(Self::AnyTls),
            12 => Some(Self::Naive),
            13 => Some(Self::ShadowsocksR),
            14 => Some(Self::Hysteria),
            15 => Some(Self::ShadowTls),
            16 => Some(Self::Tor),
            17 => Some(Self::Ssh),
            18 => Some(Self::Tailscale),
            19 => Some(Self::Redirect),
            20 => Some(Self::TProxy),
            21 => Some(Self::Mixed),
            22 => Some(Self::DokodemoDoor),
            23 => Some(Self::Freedom),
            24 => Some(Self::Blackhole),
            25 => Some(Self::Dns),
            26 => Some(Self::Loopback),
            27 => Some(Self::Shadowsocks2022),
            _ => None,
        }
    }

    /// Inverse of [`Self::try_from_i32`] — the legacy `config_type` integer
    /// for a protocol kind (used by `ProfileKey` and the fast-ping adapters).
    #[must_use]
    pub const fn to_i32(self) -> i32 {
        match self {
            Self::Vmess => 1,
            Self::Custom => 2,
            Self::Shadowsocks => 3,
            Self::Socks => 4,
            Self::Vless => 5,
            Self::Trojan => 6,
            Self::Hysteria2 => 7,
            Self::Tuic => 8,
            Self::WireGuard => 9,
            Self::Http => 10,
            Self::AnyTls => 11,
            Self::Naive => 12,
            Self::ShadowsocksR => 13,
            Self::Hysteria => 14,
            Self::ShadowTls => 15,
            Self::Tor => 16,
            Self::Ssh => 17,
            Self::Tailscale => 18,
            Self::Redirect => 19,
            Self::TProxy => 20,
            Self::Mixed => 21,
            Self::DokodemoDoor => 22,
            Self::Freedom => 23,
            Self::Blackhole => 24,
            Self::Dns => 25,
            Self::Loopback => 26,
            Self::Shadowsocks2022 => 27,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Shadowsocks => "ss",
            Self::Shadowsocks2022 => "ss-2022",
            Self::Socks => "socks",
            Self::Http => "http",
            Self::Trojan => "trojan",
            Self::WireGuard => "wireguard",
            Self::Hysteria2 => "hy2",
            Self::DokodemoDoor => "dokodemo",
            Self::Freedom => "freedom",
            Self::Blackhole => "blackhole",
            Self::Dns => "dns",
            Self::Loopback => "loopback",
            Self::Custom => "custom",
            Self::Tuic => "tuic",
            Self::Hysteria => "hy",
            Self::Naive => "naive",
            Self::AnyTls => "any-tls",
            Self::ShadowTls => "shadow-tls",
            Self::Tor => "tor",
            Self::Ssh => "ssh",
            Self::Tailscale => "tailscale",
            Self::ShadowsocksR => "ssr",
            Self::Redirect => "redirect",
            Self::TProxy => "t-proxy",
            Self::Mixed => "mixed",
        }
    }
}

impl std::fmt::Display for ProtocolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ProtocolKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProtocolKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Error returned when a [`ProtocolKind`] string cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid protocol kind: '{0}'")]
pub struct ParseProtocolKindError(String);

impl std::str::FromStr for ProtocolKind {
    type Err = ParseProtocolKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Same normalization as `Protocol::from_str` in leas-core:
        // lowercase, `-` → `_`, then match canonical `as_str` spellings plus
        // the legacy hyphen-less aliases written by proto identity hashing,
        // security_rank, fields_to_profile and normalize_protocol_key.
        let normalized = s.to_lowercase().replace('-', "_");
        let kind = match normalized.as_str() {
            // Canonical (`as_str`) spellings, plus the legacy hyphen-less
            // aliases historically written/parsed elsewhere in the codebase.
            "vmess" => Self::Vmess,
            "vless" => Self::Vless,
            "ss" | "shadowsocks" => Self::Shadowsocks,
            "ss_2022" | "shadowsocks_2022" | "shadowsocks2022" => Self::Shadowsocks2022,
            "socks" | "socks5" => Self::Socks,
            "http" => Self::Http,
            "trojan" => Self::Trojan,
            "wireguard" | "wire_guard" => Self::WireGuard,
            "hy2" | "hysteria2" | "hysteria_2" => Self::Hysteria2,
            "dokodemo" | "dokodemo_door" => Self::DokodemoDoor,
            "freedom" => Self::Freedom,
            "blackhole" => Self::Blackhole,
            "dns" => Self::Dns,
            "loopback" => Self::Loopback,
            "custom" => Self::Custom,
            "tuic" => Self::Tuic,
            "hy" | "hysteria" | "hysteria1" => Self::Hysteria,
            "naive" | "naive+https" | "naive+quic" => Self::Naive,
            "any_tls" | "anytls" => Self::AnyTls,
            "shadow_tls" | "shadowtls" => Self::ShadowTls,
            "tor" => Self::Tor,
            "ssh" => Self::Ssh,
            "tailscale" => Self::Tailscale,
            "ssr" | "shadowsocks_r" | "shadowsocksr" => Self::ShadowsocksR,
            "redirect" => Self::Redirect,
            "t_proxy" | "tproxy" => Self::TProxy,
            "mixed" => Self::Mixed,
            _ => return Err(ParseProtocolKindError(s.to_owned())),
        };
        Ok(kind)
    }
}

/// Transport kinds. Mirrors the `type_str()` outputs of [`TransportConfig`]
/// for every transport that exists today (incl. `Quic`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum TransportType {
    Tcp,
    Ws,
    Grpc,
    Http,
    Quic,
    Kcp,
    HttpUpgrade,
    XHttp,
}

impl TransportType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws => "ws",
            Self::Grpc => "grpc",
            Self::Http => "http",
            Self::Quic => "quic",
            Self::Kcp => "kcp",
            Self::HttpUpgrade => "httpupgrade",
            Self::XHttp => "xhttp",
        }
    }
}

impl std::fmt::Display for TransportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for TransportType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TransportType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s)
            .map_err(|()| serde::de::Error::custom(format_args!("invalid transport type: '{s}'")))
    }
}

impl TransportType {
    /// Parse the label `toasty` WRITES for an embedded enum column.
    ///
    /// NOT the same as `FromStr`: the embed derive stores its own `snake_case`
    /// label derived from the Rust ident, so the database holds `http_upgrade`
    /// and `x_http` where the wire form (`as_str()`, and every share URL) says
    /// `httpupgrade` / `xhttp`. Verified against a real feed (2026-10-01:
    /// 145 `http_upgrade` + 169 `x_http` rows). A caller that reads the column
    /// back as text and parses it with `FromStr` silently gets `Err` for those
    /// two transports — which, in the ordering law, means a stored zero weight
    /// and a page sorted differently from the in-memory comparator.
    ///
    /// Accepts both spellings; the wire form stays the canonical output.
    #[must_use]
    pub fn from_db_label(label: &str) -> Option<Self> {
        match label.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "ws" => Some(Self::Ws),
            "grpc" => Some(Self::Grpc),
            "http" => Some(Self::Http),
            "quic" => Some(Self::Quic),
            "kcp" => Some(Self::Kcp),
            "httpupgrade" | "http_upgrade" => Some(Self::HttpUpgrade),
            "xhttp" | "x_http" => Some(Self::XHttp),
            _ => None,
        }
    }
}

impl std::str::FromStr for TransportType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The wire spellings only — a share URL is never `x_http`.
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "ws" => Ok(Self::Ws),
            "grpc" => Ok(Self::Grpc),
            "http" => Ok(Self::Http),
            "quic" => Ok(Self::Quic),
            "kcp" => Ok(Self::Kcp),
            "httpupgrade" => Ok(Self::HttpUpgrade),
            "xhttp" => Ok(Self::XHttp),
            _ => Err(()),
        }
    }
}

/// Security kinds. Mirrors the `type_str()` outputs of [`SecurityConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum SecurityType {
    None,
    Tls,
    Reality,
}

impl SecurityType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::Reality => "reality",
        }
    }
}

impl std::fmt::Display for SecurityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for SecurityType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SecurityType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s)
            .map_err(|()| serde::de::Error::custom(format_args!("invalid security type: '{s}'")))
    }
}

impl std::str::FromStr for SecurityType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "tls" => Ok(Self::Tls),
            "reality" => Ok(Self::Reality),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KINDS: [ProtocolKind; 27] = [
        ProtocolKind::Vmess,
        ProtocolKind::Vless,
        ProtocolKind::Shadowsocks,
        ProtocolKind::Shadowsocks2022,
        ProtocolKind::Socks,
        ProtocolKind::Http,
        ProtocolKind::Trojan,
        ProtocolKind::WireGuard,
        ProtocolKind::Hysteria2,
        ProtocolKind::DokodemoDoor,
        ProtocolKind::Freedom,
        ProtocolKind::Blackhole,
        ProtocolKind::Dns,
        ProtocolKind::Loopback,
        ProtocolKind::Custom,
        ProtocolKind::Tuic,
        ProtocolKind::Hysteria,
        ProtocolKind::Naive,
        ProtocolKind::AnyTls,
        ProtocolKind::ShadowTls,
        ProtocolKind::Tor,
        ProtocolKind::Ssh,
        ProtocolKind::Tailscale,
        ProtocolKind::ShadowsocksR,
        ProtocolKind::Redirect,
        ProtocolKind::TProxy,
        ProtocolKind::Mixed,
    ];

    const ALL_TRANSPORTS: [TransportType; 8] = [
        TransportType::Tcp,
        TransportType::Ws,
        TransportType::Grpc,
        TransportType::Http,
        TransportType::Quic,
        TransportType::Kcp,
        TransportType::HttpUpgrade,
        TransportType::XHttp,
    ];

    const ALL_SECURITIES: [SecurityType; 3] =
        [SecurityType::None, SecurityType::Tls, SecurityType::Reality];

    #[test]
    fn display_from_str_round_trip_all_variants() {
        for kind in ALL_KINDS {
            assert_eq!(kind.as_str(), kind.to_string(), "mismatch for {kind:?}");
            let parsed: ProtocolKind = kind.to_string().parse().expect("parse as_str output");
            assert_eq!(parsed, kind, "round-trip failed for {kind:?}");
        }
        for transport in ALL_TRANSPORTS {
            assert_eq!(transport.as_str(), transport.to_string());
            let parsed: TransportType = transport.to_string().parse().expect("parse as_str output");
            assert_eq!(parsed, transport, "round-trip failed for {transport:?}");
        }
        for security in ALL_SECURITIES {
            assert_eq!(security.as_str(), security.to_string());
            let parsed: SecurityType = security.to_string().parse().expect("parse as_str output");
            assert_eq!(parsed, security, "round-trip failed for {security:?}");
        }
    }

    /// `ProtocolKind::as_str()` must equal the `Display` output of the
    /// (being-replaced) `Protocol` enum in `leas-core`. Core is not a
    /// dependency of this crate, so the expected strings are hard-coded from
    /// the current `Protocol::Display` impl (verified 2026-08-05 — no deltas;
    /// see task report).
    #[test]
    fn as_str_equals_protocol_display_strings() {
        let cases = [
            (ProtocolKind::Vmess, "vmess"),
            (ProtocolKind::Vless, "vless"),
            (ProtocolKind::Shadowsocks, "ss"),
            (ProtocolKind::Shadowsocks2022, "ss-2022"),
            (ProtocolKind::Socks, "socks"),
            (ProtocolKind::Http, "http"),
            (ProtocolKind::Trojan, "trojan"),
            (ProtocolKind::WireGuard, "wireguard"),
            (ProtocolKind::Hysteria2, "hy2"),
            (ProtocolKind::DokodemoDoor, "dokodemo"),
            (ProtocolKind::Freedom, "freedom"),
            (ProtocolKind::Blackhole, "blackhole"),
            (ProtocolKind::Dns, "dns"),
            (ProtocolKind::Loopback, "loopback"),
            (ProtocolKind::Custom, "custom"),
            (ProtocolKind::Tuic, "tuic"),
            (ProtocolKind::Hysteria, "hy"),
            (ProtocolKind::Naive, "naive"),
            (ProtocolKind::AnyTls, "any-tls"),
            (ProtocolKind::ShadowTls, "shadow-tls"),
            (ProtocolKind::Tor, "tor"),
            (ProtocolKind::Ssh, "ssh"),
            (ProtocolKind::Tailscale, "tailscale"),
            (ProtocolKind::ShadowsocksR, "ssr"),
            (ProtocolKind::Redirect, "redirect"),
            (ProtocolKind::TProxy, "t-proxy"),
            (ProtocolKind::Mixed, "mixed"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.as_str(), expected, "as_str mismatch for {kind:?}");
            assert_eq!(kind.to_string(), expected, "Display mismatch for {kind:?}");
        }
    }

    #[test]
    fn legacy_aliases_parse() {
        let cases = [
            ("hysteria", ProtocolKind::Hysteria),
            ("hysteria1", ProtocolKind::Hysteria),
            ("hysteria2", ProtocolKind::Hysteria2),
            ("anytls", ProtocolKind::AnyTls),
            ("shadowtls", ProtocolKind::ShadowTls),
            ("tproxy", ProtocolKind::TProxy),
            ("shadowsocks", ProtocolKind::Shadowsocks),
            ("ss", ProtocolKind::Shadowsocks),
            ("ss-2022", ProtocolKind::Shadowsocks2022),
            ("shadowsocks2022", ProtocolKind::Shadowsocks2022),
            ("shadowsocks-r", ProtocolKind::ShadowsocksR),
            ("ssr", ProtocolKind::ShadowsocksR),
            ("dokodemo-door", ProtocolKind::DokodemoDoor),
            ("dokodemo", ProtocolKind::DokodemoDoor),
            ("wire-guard", ProtocolKind::WireGuard),
            ("socks5", ProtocolKind::Socks),
            ("naive+https", ProtocolKind::Naive),
            ("naive+quic", ProtocolKind::Naive),
            // Case-insensitive.
            ("VMESS", ProtocolKind::Vmess),
            ("AnyTLS", ProtocolKind::AnyTls),
            ("Shadowsocks-2022", ProtocolKind::Shadowsocks2022),
            ("Naive+HTTPS", ProtocolKind::Naive),
            ("T-PROXY", ProtocolKind::TProxy),
        ];
        for (input, expected) in cases {
            assert_eq!(
                input.parse::<ProtocolKind>().expect("parse alias"),
                expected,
                "failed for {input:?}"
            );
        }
        // Unknown strings must error.
        assert!("bogus".parse::<ProtocolKind>().is_err());
        assert!("".parse::<ProtocolKind>().is_err());
        assert!("vmess-extra".parse::<ProtocolKind>().is_err());
    }

    #[test]
    fn serde_json_round_trip() {
        for kind in ALL_KINDS {
            let json = serde_json::to_string(&kind).expect("serialize");
            let back: ProtocolKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, kind, "serde round-trip failed for {kind:?}");
        }
        for transport in ALL_TRANSPORTS {
            let json = serde_json::to_string(&transport).expect("serialize");
            let back: TransportType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, transport, "serde round-trip failed for {transport:?}");
        }
        for security in ALL_SECURITIES {
            let json = serde_json::to_string(&security).expect("serialize");
            let back: SecurityType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, security, "serde round-trip failed for {security:?}");
        }
    }

    /// Pin the serde representation: the JSON form must equal the protocol
    /// dialect (`as_str()`), never the Rust variant names — Task 3 hashes
    /// serialized `ProtocolEssentials` for identity, so a second dialect
    /// would drift identity hashing.
    #[test]
    fn serde_representation_is_stable() {
        assert_eq!(
            serde_json::to_string(&ProtocolKind::Vmess).expect("serialize"),
            "\"vmess\""
        );
        assert_eq!(
            serde_json::to_string(&ProtocolKind::Shadowsocks2022).expect("serialize"),
            "\"ss-2022\""
        );
        assert_eq!(
            serde_json::to_string(&ProtocolKind::Hysteria2).expect("serialize"),
            "\"hy2\""
        );
        assert_eq!(
            serde_json::to_string(&TransportType::HttpUpgrade).expect("serialize"),
            "\"httpupgrade\""
        );
        assert_eq!(
            serde_json::to_string(&TransportType::XHttp).expect("serialize"),
            "\"xhttp\""
        );
        assert_eq!(
            serde_json::to_string(&SecurityType::None).expect("serialize"),
            "\"none\""
        );
    }

    #[test]
    fn transport_as_str_matches_type_str() {
        use super::super::common::{
            GrpcConfig, HttpConfig, HttpUpgradeConfig, KcpConfig, TransportConfig, WebSocketConfig,
            XHttpConfig,
        };
        let cases = [
            (TransportType::Tcp, TransportConfig::Tcp),
            (
                TransportType::Ws,
                TransportConfig::Ws(WebSocketConfig::default()),
            ),
            (
                TransportType::Grpc,
                TransportConfig::Grpc(GrpcConfig::default()),
            ),
            (
                TransportType::Http,
                TransportConfig::Http(HttpConfig::default()),
            ),
            (TransportType::Quic, TransportConfig::Quic),
            (
                TransportType::Kcp,
                TransportConfig::Kcp(KcpConfig::default()),
            ),
            (
                TransportType::HttpUpgrade,
                TransportConfig::HttpUpgrade(HttpUpgradeConfig::default()),
            ),
            (
                TransportType::XHttp,
                TransportConfig::XHttp(XHttpConfig::default()),
            ),
        ];
        for (transport, config) in cases {
            assert_eq!(
                transport.as_str(),
                config.type_str(),
                "mismatch for {transport:?}"
            );
        }
    }

    #[test]
    fn security_as_str_matches_type_str() {
        use super::super::common::{RealityOpts, SecurityConfig, TlsConfig, TlsOpts};
        let cases = [
            // `SecurityConfig::default()` has no TLS; `type_str()` is `None`
            // while `SecurityType::None::as_str()` is "none".
            (SecurityType::None, SecurityConfig::default()),
            (
                SecurityType::Tls,
                SecurityConfig {
                    tls: Some(TlsConfig::Tls(TlsOpts::default())),
                    ..SecurityConfig::default()
                },
            ),
            (
                SecurityType::Reality,
                SecurityConfig {
                    tls: Some(TlsConfig::Reality(RealityOpts::default())),
                    ..SecurityConfig::default()
                },
            ),
        ];
        for (security, config) in cases {
            match config.type_str() {
                Some(s) => assert_eq!(security.as_str(), s, "mismatch for {security:?}"),
                None => assert_eq!(security.as_str(), "none", "mismatch for {security:?}"),
            }
        }
    }
}
