use std::borrow::Cow;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use smallvec::SmallVec;

use crate::clash::ClashProxy;
use crate::urlx::{HostSpec, RawUrlX, SchemeX};

pub mod common;
pub mod core_mapping;
pub mod endpoint;
pub(crate) mod identity;
pub mod utils;

use identity::IdentityWriter;

mod anytls;
mod error;
mod http_client;
mod hysteria1;
mod hysteria2;
mod kinds;
mod naive;
pub mod security_rank;
mod shadowtls;
mod socks;
mod ss;
pub mod ss_plugin;
mod ssh;
mod ssr;
mod tailscale;
mod tor;
mod trojan;
mod tuic;
mod vless;
mod vmess;
pub mod weight;
mod wireguard;
pub use anytls::AnyTlsConfig;
pub use common::{
    HttpUpgradeConfig, RealityOpts, SecurityConfig, TlsConfig, TlsOpts, XHttpConfig, curve_id,
    parse_curve_names,
};
pub use endpoint::{EndpointEssentials, HostKind, ParsedProto, ProtocolEssentials};
pub use error::SupportError;
pub use http_client::HttpClientConfig;
pub use hysteria1::Hysteria1Config;
pub use hysteria2::Hysteria2Config;
pub use kinds::{ParseProtocolKindError, ProtocolKind, SecurityType, TransportType};
pub use naive::NaiveConfig;
pub use security_rank::protocol_security_rank;
pub use shadowtls::ShadowTlsConfig;
pub use socks::Socks5Config;
pub use ss::SsConfig;
pub use ss_plugin::{MuxSetting, PluginFamily, PluginMode, PluginSpec, TlsSetting};
pub use ssh::SshConfig;
pub use ssr::SsrConfig;
pub use tailscale::TailscaleConfig;
pub use tor::TorConfig;
pub use trojan::TrojanConfig;
pub use tuic::TuicConfig;
pub use vless::VlessMux;
pub use vless::{MlkemEncryption, MlkemMode, VlessConfig, parse_mlkem_encryption};
pub use vmess::VmessConfig;
pub use wireguard::WireguardConfig;
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("invalid host: {0}")]
    InvalidHost(Cow<'static, str>),
    #[error("invalid port: {0}")]
    InvalidPort(Cow<'static, str>),
    #[error("missing host")]
    MissingHost,
    #[error("missing port")]
    MissingPort,
    #[error("invalid userinfo: {0}")]
    InvalidUserInfo(Cow<'static, str>),
    #[error("invalid hostport: {0}")]
    InvalidHostPort(Cow<'static, str>),
    #[error("missing conf: {0}")]
    MissingConf(Cow<'static, str>),
    #[error("invalid conf: {0}: {1}")]
    InvalidConf(Cow<'static, str>, Cow<'static, str>),
    #[error("unknown error: {0}")]
    Unknown(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("invalid structure for {0}")]
    InvalidStructure(SchemeX),
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(SchemeX),
    #[error("not a proxy config URL (promotion or navigation link)")]
    PromotionUrl,
    /// The protocol is recognized but not yet implemented as a placeholder.
    #[error("protocol not yet implemented: {0}")]
    Unimplemented(&'static str),
}

/// Which proxy core to target for JSON config generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, toasty::Embed)]
pub enum CoreType {
    Xray,
    SingBox,
}

impl CoreType {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::SingBox => "sing-box",
        }
    }
}

impl std::str::FromStr for CoreType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "xray" | "xray-core" => Ok(Self::Xray),
            "sing-box" | "singbox" | "sing_box" => Ok(Self::SingBox),
            _ => Err(()),
        }
    }
}

impl std::fmt::Display for CoreType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// Serde for `CoreType` follows the same as_str dialect as the kind enums in
// `kinds.rs` ("xray" / "sing-box") — required so `ProtocolEssentials` can
// derive `Serialize`/`Deserialize` (T3 parse boundary).
impl Serialize for CoreType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CoreType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s)
            .map_err(|()| serde::de::Error::custom(format_args!("invalid core type: '{s}'")))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoSpecError {
    #[error("invalid config: {0}")]
    Invalid(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("unsupported protocol for {0}")]
    Unsupported(String),
}

macro_rules! dispatch {
    ($self:expr, $method:ident $(, $arg:expr)*) => {
        match $self {
            ProtocolConfig::Vless(c) => c.$method($($arg),*),
            ProtocolConfig::Vmess(c) => c.$method($($arg),*),
            ProtocolConfig::Trojan(c) => c.$method($($arg),*),
            ProtocolConfig::Hysteria2(c) => c.$method($($arg),*),
            ProtocolConfig::Ss(c) => c.$method($($arg),*),
            ProtocolConfig::Ssr(c) => c.$method($($arg),*),
            ProtocolConfig::Tuic(c) => c.$method($($arg),*),
            ProtocolConfig::Wireguard(c) => c.$method($($arg),*),
            ProtocolConfig::Socks(c) => c.$method($($arg),*),
            ProtocolConfig::Http(c) => c.$method($($arg),*),
            ProtocolConfig::Naive(c) => c.$method($($arg),*),
            ProtocolConfig::AnyTls(c) => c.$method($($arg),*),
            ProtocolConfig::ShadowTls(c) => c.$method($($arg),*),
            ProtocolConfig::Tor(c) => c.$method($($arg),*),
            ProtocolConfig::Ssh(c) => c.$method($($arg),*),
            ProtocolConfig::Tailscale(c) => c.$method($($arg),*),
            ProtocolConfig::Hysteria1(c) => c.$method($($arg),*),
            ProtocolConfig::Redirect(c) => c.$method($($arg),*),
            ProtocolConfig::TProxy(c) => c.$method($($arg),*),
            ProtocolConfig::Mixed(c) => c.$method($($arg),*),
        }
    };
}

impl ProtocolConfig {
    /// Normalize the transport into its stored form.
    ///
    /// Two normalizations, both mirroring the reference: the URI paths (the
    /// transport's and the config's `path` mirror) become canonical
    /// request-targets, and the legacy `?ed=NNNN` query is hoisted into the
    /// typed early-data field.
    ///
    /// Called from the single row-build owner (`state::protocol_from_parsed`),
    /// before the identity is computed and before the stored columns are built,
    /// so a non-canonical stored path can neither break the dial nor split one
    /// logical path into two uids. Idempotent.
    ///
    /// See `docs/aegis/specs/2026-09-23-ws-path-canonicalization-design.md`.
    pub fn normalize_transport(&mut self) {
        // These three carry the path TWICE: the transport's (hashed into the
        // identity) and a top-level mirror (`write_identity` excludes it,
        // `reconstruct_proto` emits it) — they travel together, under the
        // transport's own match.
        let (transport, mirror) = match self {
            Self::Vless(c) => (&mut c.transport, &mut c.path),
            Self::Vmess(c) => (&mut c.transport, &mut c.path),
            Self::Trojan(c) => (&mut c.transport, &mut c.path),
            // Every other kind is transport-less: only vless/vmess/trojan carry
            // a `TransportConfig`.
            _ => return,
        };
        common::hoist_early_data(transport);
        common::canonicalize_config_paths(transport, mirror);
    }

    /// Full parse boundary: scheme dispatch + fallback chain, returning the
    /// complete [`ParsedProto`] (endpoints + protocol essentials) of the
    /// FIRST parser that succeeds.
    ///
    /// The scheme-mapped parser runs first; when it fails with a recoverable
    /// structural error (missing/malformed host, port, userinfo, or unknown),
    /// the chain falls back through `Ss → Ssr → Vmess → Vless → Trojan →
    /// Hysteria2 → Hysteria1`. Unrecoverable errors (unsupported scheme,
    /// promotion/navigation URLs, invalid conf) abort immediately.
    ///
    /// Supersedes the removed `try_parse_detailed`/`ParseResult` (T11): the
    /// endpoints are no longer discarded — callers get them on the returned
    /// [`ParsedProto`].
    ///
    /// # Errors
    ///
    /// If the URL is not a valid proxy URL for any supported protocol.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        // Every arm goes through the config's `try_parse_proto` (the parse
        // boundary entry — T4/T5) and keeps the full ParsedProto (endpoints
        // + protocol essentials).
        let r = match raw.schema {
            SchemeX::Vless => VlessConfig::try_parse_proto(raw),
            SchemeX::Trojan => TrojanConfig::try_parse_proto(raw),
            SchemeX::Vmess => VmessConfig::try_parse_proto(raw),
            SchemeX::Hysteria => Hysteria1Config::try_parse_proto(raw),
            SchemeX::Hysteria2 => Hysteria2Config::try_parse_proto(raw),
            SchemeX::SS => SsConfig::try_parse_proto(raw),
            SchemeX::SSR => SsrConfig::try_parse_proto(raw),
            SchemeX::TUIC => TuicConfig::try_parse_proto(raw),
            SchemeX::WireGuard => WireguardConfig::try_parse_proto(raw),
            SchemeX::ShadowTls => ShadowTlsConfig::try_parse_proto(raw),
            SchemeX::Socks => Socks5Config::try_parse_proto(raw),
            SchemeX::Http => HttpClientConfig::try_parse_proto(raw),
            SchemeX::Naive => NaiveConfig::try_parse_proto(raw),
            SchemeX::AnyTLS => AnyTlsConfig::try_parse_proto(raw),
            SchemeX::Warp => {
                // Warp is not directly URL-parsable — no fallback applies.
                Err(ParseError::UnsupportedScheme(raw.schema.clone()))
            }
            SchemeX::Undefined | SchemeX::Https => return Err(ParseError::PromotionUrl),
            ref other => return Err(ParseError::UnsupportedScheme(other.clone())),
        };

        let original_err = match r {
            Ok(parsed) => return Ok(parsed),
            Err(
                e @ (ParseError::InvalidStructure(_)
                | ParseError::MissingHost
                | ParseError::MissingPort
                | ParseError::InvalidUserInfo(_)
                | ParseError::InvalidHostPort(_)
                | ParseError::InvalidHost(_)
                | ParseError::Unknown(_)),
            ) => e,
            unrecoverable @ Err(_) => return Err(unrecoverable.unwrap_err()),
        };
        SsConfig::try_parse_proto(raw)
            .or_else(|_| SsrConfig::try_parse_proto(raw))
            .or_else(|_| VmessConfig::try_parse_proto(raw))
            .or_else(|_| VlessConfig::try_parse_proto(raw))
            .or_else(|_| TrojanConfig::try_parse_proto(raw))
            .or_else(|_| Hysteria2Config::try_parse_proto(raw))
            .or_else(|_| Hysteria1Config::try_parse_proto(raw))
            .or(Err(original_err))
    }

    /// Reconstruct the share URL for this config given its endpoint.
    ///
    /// Dispatches to the per-config `reconstruct_proto`; placeholder
    /// protocols (no URL format) return
    /// [`ParseError::Unimplemented`].
    ///
    /// # Errors
    ///
    /// If this protocol has no URL format, or the endpoint/config cannot be
    /// rendered.
    pub fn reconstruct_proto(&self, endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        dispatch!(self, reconstruct_proto, endpoint)
    }
}

/// Identity computation for protocol configs: pure, deterministic, stateless.
///
/// Crate-private (plain `trait`, no `pub`). The [`ProtoSpec`] trait is sealed
/// through this supertrait — only config types inside this crate implement it.
///
/// One traversal feeds both identity streams: non-credential, non-default
/// fields go to the `sig` stream, credentials to the domain-separated
/// credential stream. `uid = sig ^ cred_hash`. See [`identity`].
trait ProtoIdentity {
    /// Write this config's kind tag, non-default non-credential fields, and
    /// credentials into `w`. The call order is the frozen identity format.
    fn write_identity(&self, w: &mut IdentityWriter);
}

/// Behavioral protocol spec, sealed to this crate via the private
/// [`ProtoIdentity`] supertrait.
///
/// PARSE-CONTRACT MIGRATION (phase A): the parse contract lives on the
/// `*_proto` inherent methods of every config type (`try_parse_proto` /
/// `try_from_clash_proto` / `to_clash_proto` / `reconstruct_proto`), which
/// produce/consume [`ParsedProto`] with the endpoint ([`EndpointEssentials`])
/// split out and [`ProtocolEssentials::config`] carrying only endpoint-free
/// protocol parameters (host-free parse mandate). T4 converted vless/vmess;
/// T4 converted vless/vmess; T5 converted all remaining configs (no config struct carries host/port
/// anymore). This legacy trait is kept as a bridge so `ProtocolConfig`
/// dispatch and the legacy `*_proto` consumers keep compiling:
/// `try_parse`/`try_from_clash` still work by delegating to the `*_proto`
/// variants and discarding the endpoints; `to_clash`/`reconstruct` return
/// errors because host/port are no longer stored on the config. T11 rewired
/// import/export to the `*_proto` variants (phase D builders take the
/// endpoint separately); the trait itself is slated for removal in T23.
#[allow(private_bounds)] // edition 2024 denies private bounds; deliberate seal
pub trait ProtoSpec: ProtoIdentity {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError>
    where
        Self: Sized;
    /// # Errors
    ///
    /// If internal configuration is invalid.
    fn reconstruct(&self) -> Result<String, ParseError>;
    fn schema(&self) -> SchemeX;
    fn host(&self) -> Option<&HostSpec>;
    fn port(&self) -> Option<u16>;
    fn remarks(&self) -> Option<&str>;
    fn security(&self) -> Option<&SecurityConfig> {
        None
    }
    fn transport_type(&self) -> Option<&str>;
    fn security_type(&self) -> Option<&str> {
        self.security().and_then(SecurityConfig::type_str)
    }
    /// Extract country flag emojis detected in this server's remarks string.
    /// Returns deduplicated flag emojis in order of detection.
    fn country_flags(&self) -> SmallVec<[crate::urlx::TinyText; 4]> {
        self.remarks().map(|_| SmallVec::new()).unwrap_or_default()
    }
    /// Generate JSON config for the specified proxy core.
    ///
    /// # Errors
    ///
    /// Returns [`ProtoSpecError`] if the config cannot be serialized.
    fn to_json_config(&self, _core: CoreType) -> Result<serde_json::Value, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "json config not implemented for this protocol".into(),
        ))
    }

    /// Parse this protocol from a Clash YAML proxy entry.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] if the Clash proxy doesn't match this protocol type
    /// or contains invalid/missing fields.
    fn try_from_clash(proxy: &ClashProxy) -> Result<Self, ParseError>
    where
        Self: Sized,
    {
        let _ = proxy;
        Err(ParseError::Unknown(
            "clash parsing not implemented for this protocol".into(),
        ))
    }

    /// Serialize this protocol to a Clash YAML proxy entry.
    ///
    /// # Errors
    ///
    /// Returns [`ProtoSpecError`] if the config cannot be converted.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "clash serialization not implemented for this protocol".into(),
        ))
    }
}

/// Build-time overrides applied by config builders at inject time.
///
/// Carries user-facing settings that are not part of the protocol config
/// itself but must be honored when the outbound block is materialized (e.g.
/// the TUI's "skip cert verify" toggle → `tls.insecure`). Tasks 14/15 impls
/// MUST honor [`InjectOptions::skip_cert_verify`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InjectOptions {
    pub skip_cert_verify: bool,
}

/// A protocol config injects its outbound block + stream settings into a core
/// JSON config.
///
/// `endpoint` supplies host/port for transport/sni fields left
/// unset by the host-free parse mandate (Task 4/5) — impls apply
/// `transport.with_host(endpoint.host)` / sni defaults at build time, NEVER at
/// parse time. `opts` carries build-time overrides (see [`InjectOptions`])
/// applied at inject time.
///
/// Standalone by design: deliberately NOT a supertrait of [`ProtoSpec`] (no
/// coupling). Task 6 adds the trait plus the [`ProtocolConfig`] dispatch; the
/// per-config implementations land in Tasks 14/15 (the interim stub impls
/// errored with [`SupportError::UnsupportedProtocol`] until then).
pub trait InjectToCoreConf {
    /// # Errors
    ///
    /// If this protocol cannot be injected into the requested core (or, today,
    /// until Tasks 14/15 land the real impls — always).
    fn inject_to(
        &self,
        core_conf: &mut serde_json::Value,
        core_type: CoreType,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(tag = "schema")]
pub enum ProtocolConfig {
    Vless(VlessConfig),
    Vmess(VmessConfig),
    Trojan(TrojanConfig),
    Hysteria2(Hysteria2Config),
    Ss(SsConfig),
    Ssr(SsrConfig),
    Tuic(TuicConfig),
    Wireguard(WireguardConfig),
    // ── Typed protocol configs ──
    Socks(Socks5Config),
    Http(HttpClientConfig),
    Naive(NaiveConfig),
    AnyTls(AnyTlsConfig),
    ShadowTls(ShadowTlsConfig),
    Tor(TorConfig),
    Ssh(SshConfig),
    Tailscale(TailscaleConfig),
    Hysteria1(Hysteria1Config),
    // ── Legacy placeholder protocols (no URL format) ──
    Redirect(PlaceholderConfig),
    TProxy(PlaceholderConfig),
    Mixed(PlaceholderConfig),
}

impl ProtoIdentity for ProtocolConfig {
    fn write_identity(&self, w: &mut IdentityWriter) {
        dispatch!(self, write_identity, w);
    }
}

impl ProtoSpec for ProtocolConfig {
    fn reconstruct(&self) -> Result<String, ParseError> {
        dispatch!(self, reconstruct)
    }
    fn schema(&self) -> SchemeX {
        dispatch!(self, schema)
    }
    fn host(&self) -> Option<&HostSpec> {
        dispatch!(self, host)
    }
    fn port(&self) -> Option<u16> {
        dispatch!(self, port)
    }
    fn remarks(&self) -> Option<&str> {
        dispatch!(self, remarks)
    }
    fn security(&self) -> Option<&SecurityConfig> {
        dispatch!(self, security)
    }
    fn transport_type(&self) -> Option<&str> {
        dispatch!(self, transport_type)
    }
    fn security_type(&self) -> Option<&str> {
        dispatch!(self, security_type)
    }
    fn country_flags(&self) -> SmallVec<[crate::urlx::TinyText; 4]> {
        dispatch!(self, country_flags)
    }
    fn to_json_config(&self, core: CoreType) -> Result<serde_json::Value, ProtoSpecError> {
        dispatch!(self, to_json_config, core)
    }

    fn try_from_clash(proxy: &ClashProxy) -> Result<Self, ParseError> {
        match proxy {
            ClashProxy::Vmess(_) => VmessConfig::try_from_clash(proxy).map(Self::Vmess),
            ClashProxy::Vless(_) => VlessConfig::try_from_clash(proxy).map(Self::Vless),
            ClashProxy::Trojan(_) => TrojanConfig::try_from_clash(proxy).map(Self::Trojan),
            ClashProxy::Shadowsocks(_) => SsConfig::try_from_clash(proxy).map(Self::Ss),
            ClashProxy::ShadowsocksR(_) => SsrConfig::try_from_clash(proxy).map(Self::Ssr),
            ClashProxy::Socks5(_) => Socks5Config::try_from_clash(proxy).map(Self::Socks),
            ClashProxy::Http(_) => HttpClientConfig::try_from_clash(proxy).map(Self::Http),
            ClashProxy::Tuic(_) => TuicConfig::try_from_clash(proxy).map(Self::Tuic),
            ClashProxy::Hysteria2(_) => Hysteria2Config::try_from_clash(proxy).map(Self::Hysteria2),
            ClashProxy::Hysteria(_) => Hysteria1Config::try_from_clash(proxy).map(Self::Hysteria1),
            ClashProxy::Wireguard(_) => WireguardConfig::try_from_clash(proxy).map(Self::Wireguard),
            ClashProxy::Naive(_) => NaiveConfig::try_from_clash(proxy).map(Self::Naive),
            ClashProxy::Anytls(_) => AnyTlsConfig::try_from_clash(proxy).map(Self::AnyTls),
            ClashProxy::Shadowtls(_) => ShadowTlsConfig::try_from_clash(proxy).map(Self::ShadowTls),
            ClashProxy::Tor(_) => TorConfig::try_from_clash(proxy).map(Self::Tor),
            ClashProxy::Ssh(_) => SshConfig::try_from_clash(proxy).map(Self::Ssh),
            ClashProxy::Tailscale(_) => TailscaleConfig::try_from_clash(proxy).map(Self::Tailscale),
            ClashProxy::Snell(_)
            | ClashProxy::Direct(_)
            | ClashProxy::Dns(_)
            | ClashProxy::Reject(_) => Err(ParseError::Unknown(
                "cannot convert clash proxy type to outbound protocol".into(),
            )),
        }
    }

    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        dispatch!(self, to_clash)
    }

    /// # Errors
    ///
    /// If the URL is not a valid proxy URL for any supported protocol.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        // T11: the full parse boundary is `try_parse_proto`; this legacy
        // config-only bridge discards the parsed endpoints.
        Self::try_parse_proto(raw).map(|p| p.protocol.config)
    }
}

impl InjectToCoreConf for ProtocolConfig {
    fn inject_to(
        &self,
        core_conf: &mut serde_json::Value,
        core_type: CoreType,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        // Reuses the existing `dispatch!` macro — it already forwards extra
        // arguments (`core_conf`, `core_type`, `endpoint`, `opts`) to each
        // variant.
        dispatch!(self, inject_to, core_conf, core_type, endpoint, opts)
    }
}

impl ProtocolConfig {
    /// Mutable security view for export-time defaulting. The exhaustive match
    /// makes a new protocol variant fail to compile until its security owner is
    /// classified.
    pub const fn security_mut(&mut self) -> Option<&mut SecurityConfig> {
        match self {
            Self::Vless(config) => Some(&mut config.security),
            Self::Vmess(config) => Some(&mut config.security),
            Self::Trojan(config) => Some(&mut config.security),
            Self::Hysteria2(config) => Some(&mut config.security),
            Self::Ss(config) => Some(&mut config.security),
            Self::Ssr(config) => Some(&mut config.security),
            Self::Tuic(config) => Some(&mut config.security),
            Self::Wireguard(config) => Some(&mut config.security),
            Self::Socks(config) => Some(&mut config.security),
            Self::Http(config) => Some(&mut config.security),
            Self::Naive(config) => Some(&mut config.security),
            Self::AnyTls(config) => Some(&mut config.security),
            Self::ShadowTls(config) => Some(&mut config.security),
            Self::Tor(config) => Some(&mut config.security),
            Self::Ssh(config) => Some(&mut config.security),
            Self::Tailscale(config) => Some(&mut config.security),
            Self::Hysteria1(config) => Some(&mut config.security),
            Self::Redirect(_) | Self::TProxy(_) | Self::Mixed(_) => None,
        }
    }

    /// Mutable transport view for export-time defaulting. Only protocols with
    /// a transport own one; all other variants are explicitly classified.
    pub const fn transport_mut(&mut self) -> Option<&mut common::TransportConfig> {
        match self {
            Self::Vless(config) => Some(&mut config.transport),
            Self::Vmess(config) => Some(&mut config.transport),
            Self::Trojan(config) => Some(&mut config.transport),
            Self::Hysteria2(_)
            | Self::Ss(_)
            | Self::Ssr(_)
            | Self::Tuic(_)
            | Self::Wireguard(_)
            | Self::Socks(_)
            | Self::Http(_)
            | Self::Naive(_)
            | Self::AnyTls(_)
            | Self::ShadowTls(_)
            | Self::Tor(_)
            | Self::Ssh(_)
            | Self::Tailscale(_)
            | Self::Hysteria1(_)
            | Self::Redirect(_)
            | Self::TProxy(_)
            | Self::Mixed(_) => None,
        }
    }

    /// Apply Resolved-export defaults to a cloned config. Explicit SNI and
    /// transport authority remain untouched.
    pub fn set_export_defaults(&mut self, dns: &str) {
        if let Some(security) = self.security_mut() {
            security.set_default_sni(dns);
        }
        if let Some(transport) = self.transport_mut() {
            transport.set_default_authority(dns);
        }
    }
}
// ── Placeholder config type ─────────────────────────────────────────────

/// Stub config for protocols not yet implemented.
/// All `ProtoSpec` methods return errors or defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PlaceholderConfig {
    pub proto_name: String,
    /// Opaque JSON blob containing `protocol_settings/stream_settings` from legacy parsing.
    /// Stored as `{"protocol_settings": {...}, "stream_settings": {...}}` JSON.
    pub settings_json: Vec<u8>,
}

impl ProtoSpec for PlaceholderConfig {
    fn try_parse(_raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        Err(ParseError::Unimplemented("placeholder protocol"))
    }
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::Unimplemented("placeholder protocol"))
    }
    fn schema(&self) -> SchemeX {
        SchemeX::Undefined
    }
    fn host(&self) -> Option<&HostSpec> {
        None
    }
    fn port(&self) -> Option<u16> {
        None
    }
    fn remarks(&self) -> Option<&str> {
        None
    }
    fn transport_type(&self) -> Option<&str> {
        None
    }
    fn to_json_config(&self, _core: CoreType) -> Result<serde_json::Value, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(self.proto_name.clone()))
    }
}

impl InjectToCoreConf for PlaceholderConfig {
    fn inject_to(
        &self,
        _core_conf: &mut Value,
        core_type: CoreType,
        _endpoint: Option<&EndpointEssentials>,
        _opts: InjectOptions,
    ) -> Result<(), SupportError> {
        // Redirect / TProxy / Mixed share this one type; the variant is carried
        // in `proto_name` ("redirect" / "tproxy" / "mixed" as written by
        // `PlaceholderConfig::new` and `try_parse_proto`), so it is the kind string.
        //
        // Both cores error: sing-box has NO redirect/tproxy/mixed OUTBOUND
        // type (option/redir.go is inbound-only; the design doc §7 raw
        // settings_json injection predates the runtime contract and would
        // yield an outbound without a `type` key that sing-box rejects at
        // config load — "unknown outbound type"). Config validity is enforced
        // at build time (AGENTS.md decision 2): no raw body can ever be a
        // valid outbound, so these stay unsupported until a real shape exists.
        Err(SupportError::UnsupportedProtocol(
            self.proto_name.clone(),
            core_type,
        ))
    }
}

impl PlaceholderConfig {
    /// Construct a placeholder wrapping an opaque legacy JSON body.
    #[must_use]
    pub const fn new(proto_name: String, settings_json: Vec<u8>) -> Self {
        Self {
            proto_name,
            settings_json,
        }
    }

    /// Wrap this placeholder as an endpoint-less [`ParsedProto`] — the parse
    /// boundary entry for orphan protocols (Redirect/TProxy/Mixed) that have
    /// no URL format and no endpoint. `endpoints` EMPTY is legal for these.
    ///
    /// The kind is derived from `proto_name`; unknown names fall back to
    /// [`ProtocolKind::Mixed`], the same backward-compat rule the legacy
    /// parser passthrough used.
    #[must_use]
    pub fn try_parse_proto(&self) -> ParsedProto {
        let (proto_kind, config) = match self.proto_name.to_lowercase().as_str() {
            "redirect" => (
                ProtocolKind::Redirect,
                ProtocolConfig::Redirect(self.clone()),
            ),
            "tproxy" => (ProtocolKind::TProxy, ProtocolConfig::TProxy(self.clone())),
            _ => (ProtocolKind::Mixed, ProtocolConfig::Mixed(self.clone())),
        };
        ParsedProto {
            endpoints: vec![],
            protocol: ProtocolEssentials {
                proto_kind,
                core_type: core_mapping::resolve_core(proto_kind, None, None),
                config,
            },
        }
    }

    /// Placeholder protocols have no Clash representation — always an error
    /// (mirrors the legacy trait default).
    ///
    /// # Errors
    ///
    /// Always — placeholder protocols have no Clash format.
    pub fn try_from_clash_proto(_proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        Err(ParseError::Unknown(
            "clash parsing not implemented for this protocol".into(),
        ))
    }

    /// Placeholder protocols have no Clash representation — always an error
    /// (mirrors the legacy trait default).
    ///
    /// # Errors
    ///
    /// Always — placeholder protocols have no Clash format.
    pub fn to_clash_proto(
        &self,
        _endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "clash serialization not implemented for this protocol".into(),
        ))
    }

    /// Placeholder protocols have no URL format — always an error (mirrors
    /// the legacy [`Self::reconstruct`]).
    ///
    /// # Errors
    ///
    /// Always — placeholder protocols have no URL format.
    pub const fn reconstruct_proto(
        &self,
        _endpoint: &EndpointEssentials,
    ) -> Result<String, ParseError> {
        Err(ParseError::Unimplemented("placeholder protocol"))
    }
}

impl ProtoIdentity for PlaceholderConfig {
    /// Opaque legacy blob: the semantic fields cannot be decomposed reliably,
    /// so the whole body (`proto_name` + `settings_json`) is hashed as framed
    /// bytes.
    ///
    /// The variant (`Redirect` / `TProxy` / `Mixed`) is NOT part of this writer —
    /// all three share this one type. It is covered by the `proto_kind`
    /// discriminator that [`ProtocolEssentials::write_identity`] writes before
    /// delegating here.
    ///
    /// NOTE: the hashed body INCLUDES the volatile `remarks` field for
    /// placeholder-scheme profiles (`set_legacy_fields` writes it into the
    /// settings JSON). Renaming a profile's remark therefore changes its uid,
    /// so a subscription refresh treats the row as new and duplicates it. This
    /// is the mandated whole-body-hash design for opaque configs — the remark
    /// is intentionally part of the identity; do NOT special-case it out of
    /// the hash here. There are no extractable credentials, so `cred_hash`
    /// stays 0 and `uid == sig`.
    fn write_identity(&self, w: &mut IdentityWriter) {
        const ID_PROTO_NAME: u8 = 0x50;
        const ID_SETTINGS_JSON: u8 = 0x51;
        w.kind("placeholder");
        w.str(ID_PROTO_NAME, &self.proto_name);
        w.bytes(ID_SETTINGS_JSON, &self.settings_json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn placeholder_try_parse_proto_emits_endpointless_parsed_proto() {
        // Placeholder configs wrap into the parse boundary as orphan
        // protocols: empty endpoints, kind derived from proto_name.
        let blob = serde_json::json!({
            "protocol_settings": {"password": "sekrit"},
            "stream_settings": {}
        });
        let json = serde_json::to_vec(&blob).unwrap();

        let redirect = PlaceholderConfig::new("redirect".into(), json.clone());
        let parsed = redirect.try_parse_proto();
        assert!(parsed.endpoints.is_empty(), "orphan protocol: no endpoint");
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Redirect);
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        assert_eq!(
            parsed.protocol.config,
            ProtocolConfig::Redirect(redirect.clone())
        );

        let tproxy = PlaceholderConfig::new("tproxy".into(), json.clone());
        let parsed = tproxy.try_parse_proto();
        assert!(parsed.endpoints.is_empty());
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::TProxy);
        assert_eq!(parsed.protocol.config, ProtocolConfig::TProxy(tproxy));

        // Unknown proto_name falls back to Mixed (legacy passthrough rule).
        let mixed = PlaceholderConfig::new("wireguard".into(), json);
        let parsed = mixed.try_parse_proto();
        assert!(parsed.endpoints.is_empty());
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Mixed);
        assert_eq!(parsed.protocol.config, ProtocolConfig::Mixed(mixed));

        // The *_proto clash/reconstruct paths mirror the legacy errors.
        assert!(
            PlaceholderConfig::try_from_clash_proto(&ClashProxy::Direct(
                crate::clash::ClashDirect {
                    name: "d".into(),
                    udp: None
                }
            ))
            .is_err()
        );
        assert!(
            redirect
                .to_clash_proto(&EndpointEssentials::new("x", 1))
                .is_err()
        );
        assert!(
            redirect
                .reconstruct_proto(&EndpointEssentials::new("x", 1))
                .is_err()
        );
    }

    #[test]
    fn placeholder_config_sig_is_deterministic_nonzero_body_hash() {
        let blob = serde_json::json!({
            "protocol_settings": {"password": "sekrit"},
            "stream_settings": {}
        });
        let json = serde_json::to_vec(&blob).unwrap();
        let a = PlaceholderConfig::new("wireguard".into(), json.clone())
            .try_parse_proto()
            .identity_once();
        let b = PlaceholderConfig::new("wireguard".into(), json)
            .try_parse_proto()
            .identity_once();
        let c = PlaceholderConfig::new(
            "wireguard".into(),
            serde_json::to_vec(&serde_json::json!({
                "protocol_settings": {"password": "other"},
                "stream_settings": {}
            }))
            .unwrap(),
        )
        .try_parse_proto()
        .identity_once();
        assert_ne!(a.0, 0, "sig must never be zero");
        assert_eq!(a, b, "same body -> same identity (dedup)");
        assert_ne!(a.0, c.0, "different body -> different sig");
        assert_eq!(a.1, 0, "opaque blob has no extractable credentials");
        assert_eq!(a.2, a.0, "uid == sig when cred_hash is 0");
    }

    #[test]
    fn placeholder_kind_discriminates_redirect_tproxy_mixed() {
        // All three share one PlaceholderConfig type; the identity can only
        // tell them apart through the parse-boundary proto_kind.
        let body = serde_json::to_vec(&json!({})).unwrap();
        let of = |name: &str| {
            PlaceholderConfig::new(name.to_string(), body.clone())
                .try_parse_proto()
                .uid()
        };
        let (redirect, tproxy, mixed) = (of("redirect"), of("tproxy"), of("mixed"));
        assert_ne!(redirect, tproxy);
        assert_ne!(tproxy, mixed);
        assert_ne!(redirect, mixed);
    }

    #[test]
    fn identity_is_stable_across_calls() {
        let url = "ss://Y2xlb2Y6cGFzc3dvcmQ@1.2.3.4:8080";
        let config = ProtocolConfig::try_parse(&RawUrlX::from(url)).unwrap();
        let parsed = ParsedProto {
            endpoints: vec![],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::Shadowsocks,
                core_type: CoreType::Xray,
                config,
            },
        };
        let (sig, cred_hash, uid) = parsed.identity_once();
        assert_ne!(sig, 0, "sig must never be zero");
        assert_eq!(uid, sig ^ cred_hash, "uid == sig ^ cred_hash");
        assert_eq!(parsed.sig(), sig, "sig is stable across calls");
        assert_eq!(parsed.cred_hash(), cred_hash, "cred_hash is stable");
        assert_eq!(parsed.uid(), uid, "uid is stable across calls");
    }

    #[test]
    fn core_type_display_matches_as_str() {
        assert_eq!(CoreType::Xray.to_string(), "xray");
        assert_eq!(CoreType::SingBox.to_string(), "sing-box");
        assert_eq!(CoreType::Xray.as_str(), "xray");
        assert_eq!(CoreType::SingBox.as_str(), "sing-box");
    }

    #[test]
    fn core_type_from_str_round_trip() {
        for original in [CoreType::Xray, CoreType::SingBox] {
            let parsed: CoreType = original.to_string().parse().expect("round-trip parse");
            assert_eq!(parsed, original);
        }
        // Accepted aliases.
        assert_eq!("xray-core".parse::<CoreType>(), Ok(CoreType::Xray));
        assert_eq!("singbox".parse::<CoreType>(), Ok(CoreType::SingBox));
        assert_eq!("sing_box".parse::<CoreType>(), Ok(CoreType::SingBox));
        assert_eq!("SING-BOX".parse::<CoreType>(), Ok(CoreType::SingBox));
        // Unknown strings must error.
        assert!("auto".parse::<CoreType>().is_err());
        assert!("".parse::<CoreType>().is_err());
    }

    // ── InjectToCoreConf dispatch (Task 6) ────────────────────────────────
    // NOTE: these stub-behavior tests are replaced in T14/T15 when the real
    // per-config `inject_to` impls land.

    fn vless_config() -> VlessConfig {
        let url = "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws";
        let parsed = VlessConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"));
        match parsed.protocol.config {
            ProtocolConfig::Vless(c) => c,
            other => panic!("expected VlessConfig, got {other:?}"),
        }
    }

    /// Parse a share URL into its `ProtocolConfig` (endpoints discarded).
    fn config_from_url(url: &str) -> ProtocolConfig {
        ProtocolConfig::try_parse(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    /// One `ProtocolConfig` per dispatch variant, paired with the kind string
    /// its dispatch arm must route to.
    fn all_variants_with_kinds() -> Vec<(ProtocolConfig, &'static str)> {
        use crate::clash::{ClashProxy, ClashSsh, ClashTailscale, ClashTor};

        let placeholder = |name: &str| {
            let body = serde_json::to_vec(&json!({})).unwrap();
            let pc = PlaceholderConfig::new(name.to_string(), body);
            match name {
                "redirect" => ProtocolConfig::Redirect(pc),
                "tproxy" => ProtocolConfig::TProxy(pc),
                _ => ProtocolConfig::Mixed(pc),
            }
        };
        let tor = TorConfig::try_from_clash_proto(&ClashProxy::Tor(ClashTor {
            name: "tor-node".into(),
            server: "127.0.0.1".into(),
            port: 9050,
        }))
        .expect("tor clash parse")
        .protocol
        .config;
        let ssh = SshConfig::try_from_clash_proto(&ClashProxy::Ssh(ClashSsh {
            name: "ssh-box".into(),
            server: "example.com".into(),
            port: 22,
            user: "root".into(),
            password: Some("sekrit".into()),
            private_key: None,
            private_key_path: Some("/home/user/.ssh/id_ed25519".into()),
            host_key: Some(vec!["ssh-ed25519 AAA".into()]),
            host_key_algorithms: Some(vec!["ssh-ed25519".into()]),
            client_version: Some("SSH-2.0-myclient".into()),
        }))
        .expect("ssh clash parse")
        .protocol
        .config;
        let tailscale =
            TailscaleConfig::try_from_clash_proto(&ClashProxy::Tailscale(ClashTailscale {
                name: "ts-node".into(),
                server: "100.64.0.1".into(),
                port: 100,
                hostname: "node1".into(),
                auth_key: Some("tskey-auth-abc".into()),
                control_url: Some("https://control.example.com".into()),
                state_dir: Some("/var/lib/tailscale".into()),
                ephemeral: true,
                accept_routes: true,
                exit_node: Some("100.64.0.2".into()),
                exit_node_allow_lan_access: Some(true),
            }))
            .expect("tailscale clash parse")
            .protocol
            .config;

        vec![
            (
                config_from_url(
                    "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@159.223.24.65:443?path=/?ed=2560&security=tls&encryption=none&sni=test.ir&type=ws",
                ),
                "vless",
            ),
            (
                config_from_url(
                    "vmess://eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJpbnNlY3VyZSI6IjEiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6IkBDbG91ZENpdHl5Iiwic2N5IjoiYXV0byIsInNuaSI6InN0ZWFtLmF2YWFhYWwuaXIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiLS0tIiwidiI6IjIifQ==",
                ),
                "vmess",
            ),
            (
                config_from_url(
                    "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org",
                ),
                "trojan",
            ),
            (
                config_from_url(
                    "hy2://linux.do@[2a01:4f9:4b:f378::1]:13599?security=tls&insecure=1&sni=www.bing.com",
                ),
                "hy2",
            ),
            (
                // AEAD cipher so the xray arm's build-time validation passes.
                config_from_url("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388"),
                "ss",
            ),
            (
                config_from_url(
                    "ssr://ZXhhbXBsZS5jb206NDQzOm9yaWdpbjpyYzQtbWQ1OnBsYWluOmNHRnpjM2R2Y21RLz9ncm91cD1WR1Z6ZEVkeWIzVncmcmVtYXJrcz1WR1Z6ZEZObGNuWmxjZw",
                ),
                "ssr",
            ),
            (
                config_from_url(
                    "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3",
                ),
                "tuic",
            ),
            (
                config_from_url(
                    "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&presharedkey=&reserved=236%2C163%2C162&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280",
                ),
                "wireguard",
            ),
            (config_from_url("socks://user:pass@1.2.3.4:1080"), "socks"),
            (config_from_url("http://user:pass@1.2.3.4:8080"), "http"),
            (
                config_from_url("naive+https://user:pass@example.com:443"),
                "naive",
            ),
            (
                config_from_url("anytls://1.2.3.4:8080?password=secret"),
                "any-tls",
            ),
            (
                config_from_url(
                    "shadowtls://1.2.3.4:443?password=pass123&version=1&sni=example.com",
                ),
                "shadow-tls",
            ),
            (tor, "tor"),
            (ssh, "ssh"),
            (tailscale, "tailscale"),
            (
                config_from_url(
                    "hysteria://example.com:443?protocol=udp&obfs=xplus&up_mbps=200&down_mbps=200&insecure=1&sni=real.example.com",
                ),
                "hy",
            ),
            (placeholder("redirect"), "redirect"),
            (placeholder("tproxy"), "tproxy"),
            (placeholder("mixed"), "mixed"),
        ]
    }

    /// Cores that can build an outbound for the variant (T14 xray + T15
    /// sing-box for the shared set; sing-box only for the sing-box-native set).
    fn supported_core(config: &ProtocolConfig) -> CoreType {
        match config {
            ProtocolConfig::Vless(_)
            | ProtocolConfig::Vmess(_)
            | ProtocolConfig::Trojan(_)
            | ProtocolConfig::Hysteria2(_)
            | ProtocolConfig::Ss(_)
            | ProtocolConfig::Wireguard(_)
            | ProtocolConfig::Socks(_)
            | ProtocolConfig::Http(_) => CoreType::Xray,
            _ => CoreType::SingBox,
        }
    }

    #[test]
    fn dispatch_routes_to_variant() {
        // vless: both the Xray (T14) and sing-box (T15) arms land.
        let vless = ProtocolConfig::Vless(vless_config());
        let endpoint = EndpointEssentials::new("1.2.3.4", 443);
        vless
            .inject_to(
                &mut json!({}),
                CoreType::Xray,
                Some(&endpoint),
                InjectOptions::default(),
            )
            .expect("xray inject must succeed in T14");
        vless
            .inject_to(
                &mut json!({}),
                CoreType::SingBox,
                Some(&endpoint),
                InjectOptions::default(),
            )
            .expect("sing-box inject must succeed in T15");

        // tuic: real sing-box shape since T15; an orphan (no endpoint) is
        // rejected with the missing-server error, not UnsupportedProtocol.
        let tuic = config_from_url(
            "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3",
        );
        let err = tuic
            .inject_to(
                &mut json!({}),
                CoreType::SingBox,
                None,
                InjectOptions::default(),
            )
            .expect_err("orphan tuic must be rejected by the real impl");
        assert!(
            matches!(err, SupportError::MissingField("server", "tuic")),
            "expected MissingField(server), got {err:?}"
        );
    }

    #[test]
    fn endpoint_param_accepted() {
        // Orphan configs (no endpoint) cannot build an xray outbound that
        // needs a server — the impl must reject, never panic.
        let vless = ProtocolConfig::Vless(vless_config());
        let endpoint = EndpointEssentials::new("1.2.3.4", 443);
        vless
            .inject_to(
                &mut json!({}),
                CoreType::Xray,
                Some(&endpoint),
                InjectOptions::default(),
            )
            .expect("endpoint-bearing inject must succeed");
        let err = vless
            .inject_to(
                &mut json!({}),
                CoreType::Xray,
                None,
                InjectOptions::default(),
            )
            .expect_err("orphan inject must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "vless")));
    }

    #[test]
    fn placeholder_rejected_on_both_cores() {
        // sing-box has no redirect/tproxy/mixed OUTBOUND type, so the raw
        // settings_json can never be a valid outbound — both cores refuse at
        // build time (config validity enforced, AGENTS.md decision 2).
        let raw = json!({
            "protocol_settings": { "redirect_address": "1.2.3.4" },
            "stream_settings": {},
        });
        let placeholder = PlaceholderConfig::new(
            "redirect".into(),
            serde_json::to_vec(&raw).expect("serialize"),
        );
        for core in [CoreType::SingBox, CoreType::Xray] {
            let mut conf = json!({});
            let err = placeholder
                .inject_to(&mut conf, core, None, InjectOptions::default())
                .expect_err("placeholder must be rejected on both cores");
            assert!(matches!(
                &err,
                SupportError::UnsupportedProtocol(kind, got) if kind == "redirect" && *got == core
            ));
        }
    }

    #[test]
    fn all_variants_route_to_their_kind_string() {
        let variants = all_variants_with_kinds();
        assert_eq!(variants.len(), 20, "all 20 dispatch arms must be covered");
        let endpoint = EndpointEssentials::new("1.2.3.4", 443);
        // Since T15 every non-placeholder variant has a real sing-box shape:
        // with an endpoint, dispatch must succeed for all 17 (tor/tailscale
        // ignore the endpoint). The redirect/tproxy/mixed placeholders have
        // NO outbound shape on either core (sing-box has no such outbound
        // type) and are rejected at build time.
        for (config, expected) in &variants {
            if matches!(*expected, "redirect" | "tproxy" | "mixed") {
                continue;
            }
            let core = supported_core(config);
            config
                .inject_to(
                    &mut json!({}),
                    core,
                    Some(&endpoint),
                    InjectOptions::default(),
                )
                .unwrap_or_else(|e| panic!("{expected:?} must build via {core:?}, got {e:?}"));
        }
        // The sing-box-only variants still report their kind string via the
        // Xray arm (no Xray shape, permanently).
        let mut kinds = Vec::new();
        for (config, expected) in &variants {
            if supported_core(config) == CoreType::SingBox {
                match config.inject_to(
                    &mut json!({}),
                    CoreType::Xray,
                    Some(&endpoint),
                    InjectOptions::default(),
                ) {
                    Err(SupportError::UnsupportedProtocol(kind, _)) => {
                        assert_eq!(
                            kind.as_str(),
                            *expected,
                            "dispatch arm for {config:?} must report kind {expected:?}"
                        );
                        kinds.push(kind);
                    }
                    other => panic!(
                        "expected UnsupportedProtocol for {config:?} via Xray, got {other:?}"
                    ),
                }
            }
        }
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(
            kinds.len(),
            12,
            "the 12 sing-box-only variants must report distinct kind strings"
        );
    }
    #[test]
    fn export_defaults_preserve_explicit_values() {
        let mut config = ProtocolConfig::Vless(VlessConfig {
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            uuid_origin: None,
            security: SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts {
                    sni: Some("explicit.example".into()),
                    ..TlsOpts::default()
                })),
                enc: None,
            },
            transport: common::TransportConfig::Ws(common::WebSocketConfig {
                host: Some("explicit.example".into()),
                ..common::WebSocketConfig::default()
            }),
            encryption: None,
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        });
        config.set_export_defaults("fallback.example");
        let ProtocolConfig::Vless(vless) = config else {
            panic!("vless")
        };
        assert_eq!(vless.security.sni(), Some("explicit.example"));
        let common::TransportConfig::Ws(ws) = vless.transport else {
            panic!("ws")
        };
        assert_eq!(ws.host.as_deref(), Some("explicit.example"));
    }

    #[test]
    fn export_defaults_fill_absent_vless_values() {
        let mut config = ProtocolConfig::Vless(VlessConfig {
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            uuid_origin: None,
            security: SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts::default())),
                enc: None,
            },
            transport: common::TransportConfig::Ws(common::WebSocketConfig::default()),
            encryption: None,
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        });
        config.set_export_defaults("fallback.example");
        let ProtocolConfig::Vless(vless) = config else {
            panic!("vless")
        };
        assert_eq!(vless.security.sni(), Some("fallback.example"));
        let common::TransportConfig::Ws(ws) = vless.transport else {
            panic!("ws")
        };
        assert_eq!(ws.host.as_deref(), Some("fallback.example"));
    }
    #[test]
    fn resolved_vless_reconstruct_uses_ip_authority_and_dns_sni() {
        let mut config = ProtocolConfig::Vless(VlessConfig {
            uuid: "00000000-0000-0000-0000-000000000001".into(),
            uuid_origin: None,
            security: SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts::default())),
                enc: None,
            },
            transport: common::TransportConfig::Ws(common::WebSocketConfig::default()),
            encryption: Some("none".into()),
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        });
        config.set_export_defaults("origin.example");
        let endpoint = EndpointEssentials {
            host: "1.1.1.1".into(),
            host_type: HostKind::Ipv4,
            port: 443,
            ports: Vec::new(),
        };
        let url = config.reconstruct_proto(&endpoint).expect("url");
        assert!(url.contains("@1.1.1.1:443"));
        assert!(url.contains("sni=origin.example"));
        assert!(url.contains("host=origin.example"));
    }
}
