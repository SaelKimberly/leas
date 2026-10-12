//! Shadowsocks (`ss://`) URL parsing.
//!
//! # Format (SIP002 — Modern Standard)
//! ```text
//! ss://<base64url_no_pad(method:password)>@<host>:<port>#<remarks>?plugin=...
//! ```
//!
//! # Legacy `QRCode` Format (also accepted)
//! ```text
//! ss://<base64(method:password@host:port)>
//! ```
//! Detected by presence/absence of `@` in the base64-decoded userinfo.
//!
//! # Plain Format (go-shadowsocks2 compatibility)
//! ```text
//! ss://<method>:<password>@<host>:<port>
//! ```
//!
//! # Fields
//!
//! | Component     | Source              | Purpose                         |
//! |---------------|----------------------|---------------------------------|
//! | `method`      | userinfo (method:password) | Encryption cipher         |
//! | `password`    | userinfo (method:password) | Shared secret             |
//! | `host`        | hostport             | Server address                  |
//! | `port`        | hostport             | Server port                     |
//! | `remarks`     | fragment (#)         | Display name (URL-decoded)      |
//! | `plugin`      | query `plugin`       | SIP003 plugin (e.g., obfs-local)|
//!
//! # Valid Ciphers
//! - Legacy: `rc4-md5`, `aes-256-cfb`, `chacha20`, `salsa20`, etc.
//! - AEAD: `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`
//! - AEAD-2022: `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`
//!
//! # Edge Cases
//! - Base64 can be URL-safe (`-`/`_`) or standard (`+`/`/`), with/without padding
//! - Legacy format: whole `method:password@host:port` base64-encoded (no `@` in URL)
//! - AEAD-2022 passwords are already base64, not double-encoded
//! - Port defaults to 8388 if missing (shadowsocks-rust convention)
//! - IPv6 addresses must be bracketed
//!
//! # References
//! - shadowsocks-rust: `src/config.rs` SIP002 `from_url()`/`to_url()`
//! - SIP002 spec: <https://github.com/shadowsocks/shadowsocks-org/issues/27>
//! - subconverter: `subparser.cpp` `explodeSS()`
//! - go-shadowsocks2: `parseURL()` (plain format)

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

use super::ProtoIdentity;
use super::ss_plugin::{MuxSetting, PluginFamily, PluginMode, PluginSpec, TlsSetting};

use super::common::{
    SecurityConfig, TransportConfig, security_force_insecure, to_xray_stream_settings,
};
use super::core_mapping;
use super::identity::IdentityWriter;
use super::utils;
use super::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::clash::{ClashProxy, ClashSS};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{clash_to_endpoint, host_kind_for};

/// Shadowsocks protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct SsConfig {
    pub method: TinyText,
    pub password: String,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
    /// The SIP003 plugin row, in the total lossless form (spec §3). `None` when
    /// the URL carried no plugin at all; `Some` — even with an empty `name` —
    /// whenever options were present, so a spelling can never fall through to a
    /// plugin-less row that dials the bare server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<PluginSpec>,
}

impl SsConfig {
    /// Parse a Shadowsocks URL into the parse boundary: [`ParsedProto`] with
    /// the endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// Supports three formats:
    /// 1. SIP002: `base64url(method:password)@host:port` (has `@`, hostport present)
    /// 2. Legacy QR: `base64(method:password@host:port)` (no `@` in URL, hostport absent)
    /// 3. Plain: `method:password@host:port` (base64 decode fails but `@` present)
    ///
    /// `decode_base64` tolerates trailing annotation text/emoji (Telegram pattern)
    /// and accepts both URL-safe and standard base64 alphabets.
    ///
    /// The protocol kind is cipher-aware: `2022-blake3-*` methods route to
    /// [`ProtocolKind::Shadowsocks2022`] and the core is resolved with the
    /// method ([`core_mapping::resolve_core`]) so legacy ciphers route to
    /// sing-box and AEAD/2022 ciphers to xray-core.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        let (userinfo, hostport) = if let Some(hostport) = raw.hostport {
            // SIP002 format: base64(method:password)@host:port
            let decoded = utils::decode_base64(raw.userinfo).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            let text = String::from_utf8(decoded).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            (text, hostport.to_string())
        } else {
            // Legacy QR format: base64(method:password@host:port) — no @ in URL
            let decoded = utils::decode_base64(raw.userinfo).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            let text = String::from_utf8(decoded).map_err(|e| {
                ParseError::InvalidUserInfo(format!("{}: {e}", raw.userinfo).into())
            })?;
            let (ui, hp) = text.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{}: missing hostport", raw.userinfo).into())
            })?;
            (ui.to_string(), hp.to_string())
        };

        let (parsed_host, parsed_port_spec) = utils::parse_hostport(&hostport)?;
        let parsed_port = parsed_port_spec
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;

        // Endpoint essentials: host/port live here, never in the config payload.
        let mut endpoint = EndpointEssentials::new(parsed_host.to_str().into_owned(), parsed_port);
        endpoint.host_type = host_kind_for(&parsed_host);
        if parsed_port_spec.length() > 1 {
            endpoint.ports = parsed_port_spec.iter().collect();
        }

        // Split at first ':' to get method:password
        let (method, password) = userinfo.split_once(':').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{}: missing password", raw.userinfo).into())
        })?;

        let remarks = utils::decode_fragment(raw)?;

        let query = utils::parse_query(raw.query);
        // The single constructor: glued name+options, a separate `plugin_opts`,
        // and the base64-JSON spelling all resolve here (spec §3.2), and it
        // never refuses — a row we cannot serve still stores, so it can be
        // exported, re-imported, and reported by `capability` at connect.
        let plugin = PluginSpec::from_query(&query);

        // Cipher-aware kind + core: the one config where resolve_core's
        // ss_method argument matters.
        let proto_kind = proto_kind_for_method(method);
        let config = Self {
            method: TinyText::from(method),
            password: password.to_string(),
            security: SecurityConfig::default(),
            remarks,
            plugin,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind,
                core_type: core_mapping::resolve_core(proto_kind, None, Some(method)),
                config: ProtocolConfig::Ss(config),
            },
        })
    }

    /// Rebuild the share URL from this endpoint-free config plus the endpoint
    /// essentials. Endpoint host/port come from `endpoint`.
    pub fn reconstruct_proto(&self, endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        let userinfo = format!("{}:{}", self.method, self.password);
        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(userinfo.as_bytes());
        let host = endpoint.host.as_str();
        let hostport = if host.contains(':') {
            format!("[{host}]:{}", endpoint.port)
        } else {
            format!("{host}:{}", endpoint.port)
        };
        let mut query_parts: Vec<String> = Vec::new();
        if let Some(plugin) = &self.plugin {
            // Canonical form: the bare name, then every non-default typed field
            // and every preserved extra key, sorted. The typed fields are
            // re-derived into the option string here — echoing only the name
            // would silently drop `mode`/`host`/`tls`/`mux` and re-import as a
            // different row (spec §3.1 rule 2).
            query_parts.push(format!("plugin={}", urlencoding::encode(&plugin.name)));
            let opts = plugin.render_opts();
            if !opts.is_empty() {
                query_parts.push(format!("plugin_opts={}", urlencoding::encode(&opts)));
            }
        }
        let query_string = if query_parts.is_empty() {
            String::new()
        } else {
            format!("?{}", query_parts.join("&"))
        };
        let fragment = self
            .remarks
            .as_ref()
            .map(|f| format!("#{}", urlencoding::encode(f)))
            .unwrap_or_default();
        Ok(format!("ss://{encoded}@{hostport}{query_string}{fragment}"))
    }
}

impl SsConfig {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        Ok(ClashProxy::Shadowsocks(ClashSS {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            cipher: self.method.to_string(),
            password: self.password.clone(),
            udp: None,
            udp_over_tcp: None,
            plugin: self.plugin.as_ref().map(|spec| spec.name.to_string()),
            plugin_opts: self
                .plugin
                .as_ref()
                .map(super::ss_plugin::PluginSpec::render_opts)
                .filter(|opts| !opts.is_empty()),
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    /// The kind is derived from the Clash `cipher` method (cipher-aware).
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Shadowsocks(c) => {
                let method = TinyText::from(c.cipher.as_str());
                let proto_kind = proto_kind_for_method(&method);
                let config = Self {
                    method,
                    password: c.password.clone(),
                    security: SecurityConfig::default(),
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                    // The same constructor the URL path uses, so a Clash YAML
                    // with only `plugin-opts` (no `plugin`) stores an empty name
                    // rather than losing the options.
                    plugin: match (&c.plugin, &c.plugin_opts) {
                        (name, opts) if name.is_some() || opts.is_some() => {
                            Some(PluginSpec::from_parts(
                                name.as_deref(),
                                opts.as_deref().unwrap_or_default(),
                            ))
                        }
                        _ => None,
                    },
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind,
                        core_type: core_mapping::resolve_core(proto_kind, None, Some(&c.cipher)),
                        config: ProtocolConfig::Ss(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown(
                "expected shadowsocks clash proxy".into(),
            )),
        }
    }
}

/// Cipher-aware Shadowsocks kind: `2022-blake3-*` methods are
/// [`ProtocolKind::Shadowsocks2022`], everything else is
/// [`ProtocolKind::Shadowsocks`].
fn proto_kind_for_method(method: &str) -> ProtocolKind {
    if method.starts_with("2022-blake3-") {
        ProtocolKind::Shadowsocks2022
    } else {
        ProtocolKind::Shadowsocks
    }
}

/// Legacy [`ProtoSpec`] bridge — kept so `ProtocolConfig` dispatch (and the
/// `Proto` consumer in leas-core) compile unchanged.
///
/// DEGRADED PATH (documented): `try_parse`/`try_from_clash` still work by
/// delegating to the `*_proto` variants and discarding the parsed endpoints;
/// `to_clash`/`reconstruct` return errors because the config no longer stores
/// host/port. Import/export rewires to the `*_proto` variants in T11 (phase D
/// builders take the endpoint separately).
impl ProtoSpec for SsConfig {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::Ss(config) => Ok(config),
            // Parser invariant: an ss URL always yields an SsConfig.
            _ => Err(ParseError::Unknown(
                "ss URL parsed to a non-ss config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "ss config no longer stores host/port; use SsConfig::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::SS
    }

    /// `None` — the endpoint host moved to [`EndpointEssentials`] (T5).
    fn host(&self) -> Option<&HostSpec> {
        None
    }

    /// `None` — the endpoint port moved to [`EndpointEssentials`] (T5).
    fn port(&self) -> Option<u16> {
        None
    }

    fn remarks(&self) -> Option<&str> {
        self.remarks.as_deref()
    }

    fn transport_type(&self) -> Option<&str> {
        None
    }

    /// The row's TLS/REALITY layer — an SS row rides plain TCP plus the
    /// optional `security` the chain applies outside the protocol. Omitting
    /// this accessor leaves the trait default (`None`), which silently drops
    /// a requested TLS/REALITY layer (the client would write the SS
    /// handshake in the clear to a TLS listener).
    fn security(&self) -> Option<&SecurityConfig> {
        Some(&self.security)
    }

    /// # Errors
    ///
    /// If the Clash proxy doesn't match this protocol type.
    fn try_from_clash(proxy: &ClashProxy) -> Result<Self, ParseError> {
        let parsed = Self::try_from_clash_proto(proxy)?;
        match parsed.protocol.config {
            ProtocolConfig::Ss(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "ss clash proxy parsed to a non-ss config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "ss config no longer stores host/port; use SsConfig::to_clash_proto(endpoint)".into(),
        ))
    }
}

/// Per-kind identity tags (see [`super::identity`] for the reserved ranges).
///
/// The SIP003 plugin tags replace the old `ID_PLUGIN` / `ID_PLUGIN_OPTS` pair
/// (spec §4), so the spec is written field by field, in this frozen order.
const ID_PLUGIN_NAME: u8 = 0x50;
const ID_PLUGIN_FAMILY: u8 = 0x51;
const ID_PLUGIN_MODE: u8 = 0x52;
const ID_PLUGIN_HOST: u8 = 0x53;
const ID_PLUGIN_PORT: u8 = 0x54;
const ID_PLUGIN_PATH: u8 = 0x55;
const ID_PLUGIN_TLS: u8 = 0x56;
const ID_PLUGIN_MUX: u8 = 0x57;
const ID_PLUGIN_EXTRA: u8 = 0x58;

impl ProtoIdentity for SsConfig {
    /// Identity fields: everything that reaches a builder.
    ///
    /// The SIP003 plugin spec reaches both cores and is identity, written
    /// field by field. Defaults are **elided** (identity rule (c)) so an absent
    /// key and an explicit default are one row — with one deliberate exception:
    /// `host` is written whenever present, *including* when its value is the
    /// `cloudfront.com` default, because sing-box's SNI rule is gated on the
    /// key's **presence** (spec §4, §5.1). Collapsing those two forms would
    /// silently change which name a server is dialed with.
    ///
    /// `Invalid(_)` values and `extra` entries are always written: neither is
    /// ever a default, and dropping them would merge two rows that differ.
    ///
    /// Excluded on purpose: `remarks` (display). Credentials: `method` and
    /// `password` (the 2022-blake3 PSK).
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("ss");
        super::common::write_security(w, &self.security);
        // Endpoint (host/port) intentionally absent from the identity — it
        // lives on the ParsedProto boundary, never in the config payload (T5).
        if let Some(plugin) = &self.plugin {
            // The EFFECTIVE family, not the stored field: vocabulary presence
            // is not recoverable from the wire form. `?plugin=v2ray-plugin`
            // (name only) stores `Unknown` but resolves to V2Ray, and the
            // canonical export renders it as the bare name — so hashing the
            // stored field would give those two spellings different uids and
            // row 20's fixed point could never pass. Rule (c) says they are
            // one row: both put the same bytes on the wire.
            let family = plugin.effective_family();
            w.present_str(ID_PLUGIN_NAME, Some(plugin.name.as_str()));
            w.present_str(ID_PLUGIN_FAMILY, Some(family_tag(family)));
            // The mode, elided against the SAME effective family's default so
            // an absent key and an explicit default are one row. An `Invalid`
            // value is never a default, so it always writes — dropping it
            // would merge two rows that refuse for different reasons.
            match &plugin.mode {
                PluginMode::Unset => {}
                PluginMode::Invalid(value) => w.str(ID_PLUGIN_MODE, value),
                mode => {
                    // The elision is conditioned on `name_agrees` for the same
                    // reason the renderer conditions it there: a name that
                    // disagrees with its keys must keep the key, or the name
                    // alone re-derives the other family on the next import.
                    if *mode != PluginMode::default_for(family) || !plugin.name_agrees() {
                        w.str(ID_PLUGIN_MODE, mode.as_str());
                    }
                }
            }
            // Presence-gated, so NEVER elided against a default.
            w.present_str(ID_PLUGIN_HOST, plugin.host.as_deref());
            w.present_u64(ID_PLUGIN_PORT, plugin.port.map(u64::from));
            w.opt_str(ID_PLUGIN_PATH, plugin.path.as_deref(), "/");
            match &plugin.tls {
                TlsSetting::Unset | TlsSetting::Off => {}
                TlsSetting::On => w.str(ID_PLUGIN_TLS, "1"),
                TlsSetting::Invalid(value) => w.str(ID_PLUGIN_TLS, value),
            }
            match &plugin.mux {
                MuxSetting::Unset | MuxSetting::On(1) => {}
                MuxSetting::Off => w.str(ID_PLUGIN_MUX, "0"),
                MuxSetting::On(n) => w.str(ID_PLUGIN_MUX, &n.to_string()),
                MuxSetting::Invalid(value) => w.str(ID_PLUGIN_MUX, value),
            }
            // Sorted by key: `extra` is a `BTreeMap`, so the write order is
            // deterministic (a raw `HashMap` here was a live nondeterminism bug).
            for (key, value) in &plugin.extra {
                w.str(ID_PLUGIN_EXTRA, key);
                w.str(ID_PLUGIN_EXTRA, value);
            }
        }
        w.cred("method", self.method.as_str());
        w.cred("password", &self.password);
    }
}

/// The family tag written to identity — stable text, not a `Debug` rendering.
const fn family_tag(family: PluginFamily) -> &'static str {
    match family {
        PluginFamily::Obfs => "obfs",
        PluginFamily::V2Ray => "v2ray",
        PluginFamily::Unknown => "unknown",
    }
}

impl InjectToCoreConf for SsConfig {
    fn inject_to(
        &self,
        core_conf: &mut Value,
        core_type: CoreType,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        match core_type {
            CoreType::Xray => self.inject_xray(core_conf, endpoint, opts),
            CoreType::SingBox => self.inject_singbox(core_conf, endpoint, opts),
        }
    }
}

impl SsConfig {
    /// xray-core outbound for this config, ported field-by-field from the old
    /// xray builder's `Protocol::Shadowsocks | Protocol::Shadowsocks2022` arm.
    /// xray-core's `CipherType` enum only covers AEAD + 2022-blake3; refusing
    /// here prevents the core from dying on startup with "unknown cipher
    /// method" (build-time validation).
    fn inject_xray(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "ss"));
        };
        if !core_mapping::xray_supports_ss_method(self.method.as_str()) {
            return Err(SupportError::Config(format!(
                "Shadowsocks cipher '{}' is not supported by xray-core; \
                 supported: aes-128-gcm, aes-256-gcm, chacha20-poly1305, \
                 xchacha20-poly1305, 2022-blake3-*",
                self.method.as_str()
            )));
        }
        // xray-core has NO SIP003 support at all (no `plugin` field anywhere
        // under `thirdparty/Xray-core/proxy/shadowsocks/`), so a plugin row
        // used to be emitted WITHOUT its obfuscation wrapper — a config that
        // dials the bare server and reports a dead endpoint, i.e. a client
        // defect that reads as a server verdict. Refuse it instead (decision
        // 2's rule, the same one the cipher check above uses).
        if let Some(plugin) = &self.plugin {
            return Err(SupportError::Config(format!(
                "Shadowsocks plugin `{}` cannot be built for xray-core: it has no SIP003 support",
                plugin.name
            )));
        }
        let security = security_force_insecure(&self.security, opts.skip_cert_verify);
        let stream = to_xray_stream_settings(&security, &TransportConfig::Tcp);
        *core_conf = json!({
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": ep.host,
                    "port": ep.port,
                    "method": self.method.as_str(),
                    "password": self.password
                }]
            },
        });
        if let Some(ss) = stream {
            core_conf["streamSettings"] = ss;
        }
        Ok(())
    }

    /// sing-box outbound for this config, ported field-by-field from the old
    /// builder's `Protocol::Shadowsocks | Protocol::Shadowsocks2022` arm
    /// (`method`/`password` with build-time cipher validation via
    /// `core_mapping::singbox_supports_ss_method` — legacy cfb/ctr/rc4-md5/
    /// none methods build on sing-box, unknown ones are refused so the config
    /// is never written invalid), plus the typed `plugin`/`plugin_opts`
    /// (sing-box `ShadowsocksOutboundOptions` keys the old builder dropped).
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        _opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "ss"));
        };
        if !core_mapping::singbox_supports_ss_method(self.method.as_str()) {
            return Err(SupportError::Config(format!(
                "Shadowsocks cipher '{}' is not supported by sing-box; \
                 supported: modern AEAD/2022-blake3 + legacy cfb/ctr/rc4-md5 \
                 methods",
                self.method.as_str()
            )));
        }
        let mut out = json!({
            "tag": "proxy",
            "type": "shadowsocks",
            "server": ep.host,
            "server_port": ep.port,
            "method": self.method,
            "password": self.password,
        });
        if let Some(plugin) = &self.plugin {
            // sing-box looks the plugin up by name in a registry
            // (`transport/sip003/plugin.go:28-37` — `v2ray-plugin` and
            // `obfs-local` are built in), so the name and a canonical option
            // string are the whole contract. `render_opts` is sorted, which is
            // what kept the emitted config from differing between runs.
            out["plugin"] = json!(plugin.name.as_str());
            let opts = plugin.render_opts();
            if !opts.is_empty() {
                out["plugin_opts"] = json!(opts);
            }
        }
        *core_conf = out;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::super::{
        CoreType, HostKind, ParsedProto, ProtoSpec, ProtocolConfig, ProtocolKind, SecurityConfig,
        TlsConfig, TlsOpts,
    };
    use super::SsConfig;
    use crate::proto_spec::ss_plugin::{PluginFamily, PluginMode};
    use crate::urlx::{RawUrlX, SchemeX};

    fn parse(url: &str) -> ParsedProto {
        SsConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> SsConfig {
        match parsed.protocol.config {
            ProtocolConfig::Ss(c) => c,
            other => panic!("expected SsConfig, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &SsConfig) {
        let json = serde_json::to_value(cfg).expect("serialize");
        let obj = json.as_object().expect("config is an object");
        assert!(
            !obj.contains_key("host"),
            "config payload must not carry a top-level host key: {json}"
        );
        assert!(
            !obj.contains_key("port"),
            "config payload must not carry a top-level port key: {json}"
        );
    }

    /// Reconstruct round-trip via the endpoint: parse → `reconstruct_proto(endpoint)`
    /// → re-parse must reproduce the same `ParsedProto` (endpoints + config).
    fn assert_reconstruct_roundtrip(url: &str) {
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed.clone());
        let out = cfg
            .reconstruct_proto(&endpoint)
            .unwrap_or_else(|e| panic!("reconstruct failed for {url}: {e}"));
        let reparsed = parse(&out);
        assert_eq!(parsed, reparsed, "reconstruct round-trip failed for: {url}");
    }

    // ── URL parse: endpoints + config ─────────────────────────────────────

    #[test]
    fn test_ss_basic() {
        // aes-256-gcm:password — a real AEAD cipher (xray-core supports it).
        let url = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8080";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 8080);
        assert_eq!(ep.ports, vec![8080]);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Shadowsocks);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let cfg = config(parsed);
        assert_eq!(cfg.method, "aes-256-gcm");
        assert_eq!(cfg.password, "password");
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_ss_legacy_qr_format() {
        // Legacy QR: whole method:password@host:port base64-encoded, no `@` in URL.
        let b64 =
            base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(b"aes-256-gcm:sekrit@example.com:443");
        let parsed = parse(&format!("ss://{b64}"));
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].port, 443);
        let cfg = config(parsed);
        assert_eq!(cfg.method, "aes-256-gcm");
        assert_eq!(cfg.password, "sekrit");
    }

    // ── ss cipher routing: kind + core ────────────────────────────────────

    #[test]
    fn ss_cipher_routes_kind_and_core() {
        // 2022-blake3 method -> Shadowsocks2022 + Xray (xray supports the family).
        let parsed = parse("ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388");
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Shadowsocks2022);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);

        // Legacy method -> Shadowsocks + SingBox (xray has no cfb/ctr/rc4).
        let parsed = parse("ss://YWVzLTI1Ni1jZmI6cGFzcw@1.2.3.4:8388");
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Shadowsocks);
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);

        // AEAD (non-2022) -> Shadowsocks + Xray.
        let parsed = parse("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388");
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Shadowsocks);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
    }

    /// `ProtoSpec::security()` must hand back the row's TLS/REALITY layer: the
    /// trait default is `None`, which silently drops a requested layer (the
    /// client would write the SS handshake in the clear to a TLS listener).
    /// Like vless/trojan the accessor is never `None`, so a defaulted config
    /// returns `Some` wrapping an empty layer.
    #[test]
    fn security_accessor_exposes_the_rows_layer() {
        let mut cfg = config(parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8080"));
        assert!(
            cfg.security().is_some_and(SecurityConfig::is_empty),
            "a defaulted SS config still exposes an (empty) layer"
        );

        cfg.security = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts::default())),
            enc: None,
        };
        assert_eq!(
            cfg.security().and_then(SecurityConfig::type_str),
            Some("tls"),
            "a TLS layer must reach the chain"
        );
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_methods() {
        let url_a = "ss://Y2xlb2Y6cGFzc3dvcmQ@a.example.com:8080"; // cleof:password
        let url_b = "ss://Y2xlb2Y6cGFzc3dvcmQ@b.example.com:8081"; // cleof:password
        let url_c = "ss://Y2xlb2Y6cGFzczEyMw==@a.example.com:8080"; // cleof:pass123
        let a = parse(url_a);
        let b = parse(url_b);
        let c = parse(url_c);
        assert_eq!(
            a.uid(),
            b.uid(),
            "same protocol on different servers must dedup to one uid"
        );
        assert_ne!(a.uid(), c.uid(), "different password -> different uid");
        assert_ne!(a.sig(), 0);
    }

    #[test]
    fn ss_password_is_credential_not_sig() {
        let url_a = "ss://Y2xlb2Y6cGFzc3dvcmQ@1.2.3.4:8080"; // cleof:password
        let url_b = "ss://Y2xlb2Y6cGFzczEyMw==@1.2.3.4:8080"; // cleof:pass123
        let a = parse(url_a);
        let b = parse(url_b);
        assert_eq!(a.sig(), b.sig(), "password must not change sig");
        assert_ne!(a.cred_hash(), b.cred_hash());
    }

    // ── Reconstruct round-trip via endpoint ───────────────────────────────

    #[test]
    fn reconstruct_roundtrip_via_endpoint() {
        assert_reconstruct_roundtrip("ss://Y2xlb2Y6cGFzc3dvcmQ@1.2.3.4:8080");
        assert_reconstruct_roundtrip("ss://Y2xlb2Y6cGFzc3dvcmQ@example.com:443#my-server");
        assert_reconstruct_roundtrip(
            "ss://YWVzLTI1Ni1nY206cGFzcw@[2001:db8::1]:8388?plugin=obfs-local%3Bobfs%3Dhttp",
        );
    }

    #[test]
    fn ss_reconstruct_with_remarks() {
        let url = "ss://Y2xlb2Y6cGFzc3dvcmQ@example.com:443#my-server";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        assert_eq!(cfg.remarks.as_deref(), Some("my-server"));
        let rebuilt = cfg.reconstruct_proto(&endpoint).unwrap();
        assert!(
            rebuilt.contains("#my-server"),
            "reconstruct should preserve fragment: {rebuilt}"
        );
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let url = "ss://Y2xlb2Y6cGFzc3dvcmQ@1.2.3.4:8080";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = SsConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Ss(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashProxy, ClashSS};

        let proxy = ClashProxy::Shadowsocks(ClashSS {
            name: "test".into(),
            server: "1.2.3.4".into(),
            port: 8080,
            cipher: "aes-256-gcm".into(),
            password: "sekrit".into(),
            udp: None,
            udp_over_tcp: None,
            plugin: Some("obfs-local".into()),
            plugin_opts: Some("obfs=http".into()),
        });
        let parsed = SsConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "1.2.3.4");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Ipv4);
        assert_eq!(parsed.endpoints[0].port, 8080);
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Shadowsocks);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Ss(c) => c,
            other => panic!("expected SsConfig, got {other:?}"),
        };
        assert_eq!(cfg.method, "aes-256-gcm");
        let plugin = cfg.plugin.as_ref().expect("the plugin row is stored");
        assert_eq!(plugin.name.as_str(), "obfs-local");
        assert_eq!(
            plugin.mode,
            PluginMode::Http,
            "an absent key normalizes to the default"
        );
        assert!(
            plugin.host.is_none(),
            "this entry states no host — one must not be invented"
        );
        assert_no_top_level_host_port(cfg);
        // The canonical export elides a default, so the emitted TEXT differs
        // from the input (`obfs=http` becomes absent). What must hold is that
        // re-parsing it yields the same row: the Clash round trip is a parse
        // fixed point, not a text round trip.
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        let round_tripped = SsConfig::try_from_clash_proto(&out).expect("clash re-parse");
        match (round_tripped.protocol.config, parsed.protocol.config) {
            (ProtocolConfig::Ss(first), ProtocolConfig::Ss(second)) => {
                assert_eq!(
                    first.plugin, second.plugin,
                    "the plugin row survives the round trip"
                );
                assert_eq!(first.method, second.method);
                assert_eq!(first.password, second.password);
            }
            _ => panic!("expected shadowsocks on both sides"),
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip() {
        let url = "ss://Y2xlb2Y6cGFzc3dvcmQ@1.2.3.4:8080";
        let cfg = config(parse(url));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: SsConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let url = "ss://Y2xlb2Y6cGFzc3dvcmQ@1.2.3.4:8080";
        let bridged = SsConfig::try_parse(&RawUrlX::from(url)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::SS);
        assert_eq!(bridged.method, "cleof");
        // host/port accessors are gone — the endpoint lives on ParsedProto.
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        // Degraded legacy paths error instead of fabricating a host.
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    // ── Xray inject_to (Task 14) ──────────────────────────────────────────

    use super::super::{EndpointEssentials, InjectOptions, InjectToCoreConf, SupportError};

    fn ss_aead() -> SsConfig {
        config(parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8080"))
    }

    #[test]
    fn xray_inject_writes_proxy_outbound() {
        let cfg = ss_aead();
        let ep = EndpointEssentials::new("1.2.3.4", 8080);
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&ep),
            InjectOptions::default(),
        )
        .expect("ss inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["protocol"], "shadowsocks");
        let server = &conf["settings"]["servers"][0];
        assert_eq!(server["address"], "1.2.3.4");
        assert_eq!(server["port"], 8080);
        assert_eq!(server["method"], "aes-256-gcm");
        assert_eq!(server["password"], "password");
        // No TLS/transport → no streamSettings
        assert!(conf.get("streamSettings").is_none());
    }

    #[test]
    fn xray_inject_2022_blake3_method_builds() {
        let cfg = config(parse(
            "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206cGFzc3dvcmQ@1.2.3.4:8080",
        ));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("1.2.3.4", 8080)),
            InjectOptions::default(),
        )
        .expect("2022-blake3 inject");
        assert_eq!(
            conf["settings"]["servers"][0]["method"],
            "2022-blake3-aes-128-gcm"
        );
    }

    #[test]
    fn xray_inject_rejects_legacy_cipher() {
        // aes-256-cfb is not in xray-core's CipherType enum; the build must
        // refuse instead of the core dying on startup.
        let cfg = config(parse("ss://YWVzLTI1Ni1jZmI6cGFzc3dvcmQ@1.2.3.4:8080"));
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(
                &mut conf,
                CoreType::Xray,
                Some(&EndpointEssentials::new("1.2.3.4", 8080)),
                InjectOptions::default(),
            )
            .expect_err("aes-256-cfb must be rejected for xray");
        assert!(
            err.to_string().contains("aes-256-cfb"),
            "error must name the cipher: {err}"
        );
    }

    #[test]
    fn xray_inject_without_endpoint_is_rejected() {
        let cfg = ss_aead();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::Xray, None, InjectOptions::default())
            .expect_err("orphan ss must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "ss")));
    }

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = ss_aead();
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 8080)),
            InjectOptions::default(),
        )
        .expect("ss sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "shadowsocks");
        assert_eq!(conf["server"], "1.2.3.4");
        assert_eq!(conf["server_port"], 8080);
        assert_eq!(conf["method"], "aes-256-gcm");
        assert_eq!(conf["password"], "password");
    }

    #[test]
    fn singbox_inject_legacy_cipher_builds_ok() {
        // aes-256-cfb is legacy — sing-box builds it, xray-core cannot.
        let cfg = config(parse("ss://YWVzLTI1Ni1jZmI6cGFzcw@1.2.3.4:8388"));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 8388)),
            InjectOptions::default(),
        )
        .expect("legacy cipher must build on sing-box");
        assert_eq!(conf["type"], "shadowsocks");
        assert_eq!(conf["method"], "aes-256-cfb");
    }

    #[test]
    fn singbox_inject_unknown_cipher_is_rejected() {
        // salsa20 is supported by neither core — refuse at build time.
        let cfg = SsConfig {
            method: "salsa20".into(),
            password: "password".into(),
            security: super::super::common::SecurityConfig::default(),
            remarks: None,
            plugin: None,
        };
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(
                &mut conf,
                CoreType::SingBox,
                Some(&EndpointEssentials::new("1.2.3.4", 8388)),
                InjectOptions::default(),
            )
            .expect_err("unknown cipher must be rejected");
        assert!(
            err.to_string().contains("salsa20"),
            "error must name the cipher: {err}"
        );
    }

    // ── Plugin identity (spec §4) ────────────────────────────────────────

    /// The uid of a row carrying `?plugin=<opts>`. The option string is
    /// inserted **raw**: `parse_query` percent-decodes, so encoding here would
    /// store the escape instead of the value.
    fn uid_of(opts: &str) -> i64 {
        let url = format!("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388?plugin={opts}");
        parse(&url).identity_once().2
    }

    /// An absent key and an explicit default are ONE row: the canonical export
    /// elides defaults, so if the two hashed differently the export fixed point
    /// (`uid(parse(u)) == uid(parse(export(parse(u))))`) could not hold.
    #[test]
    fn plugin_defaults_elide_to_one_protocol_row() {
        for (absent, explicit) in [
            ("v2ray-plugin", "v2ray-plugin;mode=websocket"),
            ("v2ray-plugin;host=h", "v2ray-plugin;mode=websocket;host=h"),
            ("obfs-local;obfs-host=h", "obfs-local;obfs=http;obfs-host=h"),
            ("v2ray-plugin", "v2ray-plugin;path=%2F"),
            ("v2ray-plugin", "v2ray-plugin;tls=0"),
            // Row 13's `mux` pair: `write_identity` elides `MuxSetting::Unset`
            // against `On(1)`, because a v2ray-plugin row's default IS mux-on for
            // the websocket and unset modes (`active_for`), so the two spellings
            // are the same configured behaviour and therefore one row.
            (
                "v2ray-plugin;mode=websocket",
                "v2ray-plugin;mode=websocket;mux=1",
            ),
            ("v2ray-plugin", "v2ray-plugin;mux=1"),
        ] {
            assert_eq!(
                uid_of(absent),
                uid_of(explicit),
                "{absent} and {explicit} must be one row"
            );
        }

        // The anti-overreach: `mux=0` really does turn mux OFF for a websocket
        // row (`active_for`: `Off` → false), so it is a DIFFERENT stored config
        // and must be a different row. Eliding it the way `mux=1` is elided
        // would merge a multiplexed row with a plain one — and whichever
        // imported first would supply the config for both.
        assert_ne!(
            uid_of("v2ray-plugin;mode=websocket"),
            uid_of("v2ray-plugin;mode=websocket;mux=0"),
            "`mux=0` disables the websocket default and is its own row"
        );
    }

    /// The one deliberate exception: the plugin `host` is **never** elided,
    /// because sing-box's SNI rule is gated on the key's presence. A row that
    /// spells `host=cloudfront.com` and one that spells nothing dial different
    /// names, so merging them would change which name a server is reached by.
    #[test]
    fn plugin_host_is_never_elided_because_its_presence_gates_the_sni() {
        assert_ne!(
            uid_of("v2ray-plugin;tls"),
            uid_of("v2ray-plugin;host=cloudfront.com;tls"),
            "a stated host and an absent one are different rows"
        );
        assert_ne!(uid_of("v2ray-plugin;host=a"), uid_of("v2ray-plugin;host=b"));
    }

    /// Everything that is not a default IS identity: an invalid value, a
    /// preserved extra key, a mode, a port, a path, a non-default cap.
    #[test]
    fn plugin_non_defaults_are_all_identity() {
        let base = uid_of("v2ray-plugin;host=h");
        for opts in [
            "v2ray-plugin;host=h;mode=quic",
            "v2ray-plugin;host=h;path=%2Fp",
            "v2ray-plugin;host=h;obfs-uri=%2F",
            "v2ray-plugin;host=h;zz=1",
            "v2ray-plugin;host=h;mux=8",
            "v2ray-plugin;host=h;tls=1",
        ] {
            assert_ne!(uid_of(opts), base, "{opts} must differ from the bare row");
        }
        assert_ne!(
            uid_of("obfs-local;obfs-host=h"),
            uid_of("obfs-local;obfs-host=h:8080"),
            "the obfs port reaches the Host header, so it is part of the row"
        );
        assert_ne!(
            uid_of("obfs-local;obfs=http"),
            uid_of("obfs-local;obfs=tls"),
            "the obfs mode is a different wire"
        );
    }

    /// A row with NO plugin and a row with one are different rows, and the
    /// endpoint still plays no part: the same plugin row on two servers is one
    /// `Protocol` (decision 11(f)).
    #[test]
    fn plugin_presence_is_identity_and_the_endpoint_is_not() {
        assert_ne!(
            uid_of("v2ray-plugin;host=h"),
            parse("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388")
                .identity_once()
                .2
        );
        let other = "ss://YWVzLTI1Ni1nY206cGFzcw@9.9.9.9:8388?plugin=v2ray-plugin%3Bhost%3Dh";
        assert_eq!(
            uid_of("v2ray-plugin;host=h"),
            parse(other).identity_once().2
        );
    }

    #[test]
    fn singbox_inject_without_endpoint_is_rejected() {
        let cfg = ss_aead();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect_err("orphan ss must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "ss")));
    }

    // ── Injectors (T5) ──────────────────────────────────────────────────

    /// xray-core has no SIP003 support, so a plugin row must be a BUILD
    /// refusal — never a config that silently dials the bare server.
    #[test]
    fn xray_inject_refuses_a_plugin_row_instead_of_dropping_it() {
        let url = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp";
        let parsed = parse(url);
        let mut conf = serde_json::json!({});
        let err = config(parsed.clone())
            .inject_to(
                &mut conf,
                CoreType::Xray,
                Some(&parsed.endpoints[0]),
                InjectOptions::default(),
            )
            .expect_err("xray-core cannot carry a plugin");
        let text = err.to_string();
        assert!(text.contains("obfs-local"), "{text} must name the plugin");
        assert!(text.contains("SIP003"), "{text} must say why");
    }

    /// sing-box DOES carry the plugin (it registers `v2ray-plugin` and
    /// `obfs-local` in-process), so the row builds there with the canonical
    /// option string.
    #[test]
    fn singbox_inject_emits_the_plugin_name_and_canonical_opts() {
        let url = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388?plugin=v2ray-plugin%3Bhost%3Dcdn.example%3Btls";
        let parsed = parse(url);
        let mut conf = serde_json::json!({});
        config(parsed.clone())
            .inject_to(
                &mut conf,
                CoreType::SingBox,
                Some(&parsed.endpoints[0]),
                InjectOptions::default(),
            )
            .expect("sing-box has the plugin in-process");
        assert_eq!(conf["plugin"], "v2ray-plugin");
        assert_eq!(conf["plugin_opts"], "host=cdn.example;tls=1");
    }

    // ── The stored-form fixed point (T4, acceptance row 20) ──────────────

    /// `uid(parse(export(row))) == uid(row)` for a STORED row — the Ctrl+E
    /// path. A corpus URL cannot prove this on its own: SS export emits no
    /// `security` field, so the invariant is only testable through the plugin
    /// spec the export does re-derive.
    #[test]
    fn export_reimport_is_uid_stable_for_a_stored_row() {
        for opts in [
            // A v2ray-plugin row whose typed fields are ALL defaults: the
            // export carries only `plugin=<name>`, and the name alone must
            // reproduce the same stored row.
            "v2ray-plugin",
            // …and one that states a host, which SS export does emit.
            "v2ray-plugin;host=cdn.example;tls",
            "obfs-local;obfs=tls;obfs-host=example.com:8080",
            "obfs-local",
            "kcptun;key=abc",
        ] {
            let url = format!("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388?plugin={opts}");
            let parsed = parse(&url);
            let exported = config(parsed.clone())
                .reconstruct_proto(&parsed.endpoints[0])
                .expect("reconstruct");
            let reparsed = parse(&exported);
            assert_eq!(
                config(reparsed.clone()).plugin,
                config(parsed.clone()).plugin,
                "{opts} → {exported} must re-parse to the same spec"
            );
            assert_eq!(
                reparsed.identity_once(),
                parsed.identity_once(),
                "{opts} → {exported} must re-import as the SAME row"
            );
        }
    }

    // ── The captured feeds (tier 1b) ─────────────────────────────────────

    /// Every plugin-bearing `ss://` line in the captured feeds
    /// (`tests/fixtures/m1n1-5ub-*.txt`) parses, is stored losslessly, and
    /// survives export → re-import as the SAME row.
    ///
    /// The corpus is the only source of the real spellings: glued name+opts,
    /// percent-encoded, base64-JSON under a key named after the plugin, an obfs
    /// name with v2ray vocabulary, `host:port`, a name with no options, and the
    /// nested-`ss://` junk. No crate consumed these files before this test.
    #[test]
    fn corpus_plugin_rows_parse_and_round_trip() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.to_string_lossy().contains("m1n1-5ub"))
            .collect();
        files.sort();
        assert!(files.len() >= 30, "the corpus is {} files", files.len());

        // Markers taken from the corpus itself, in the exact spelling the files
        // carry (most rows percent-encode the option string; a few do not).
        // Each is a shape the spec's §2.7 table names.
        let expected: &[(&str, PluginFamily, PluginMode)] = &[
            // unencoded, carrying the `obfs-uri` the reference ignores
            ("obfs-local;obfs-uri", PluginFamily::Obfs, PluginMode::Tls),
            // percent-encoded option strings
            (
                "obfs-local%3Bobfs%3Dtls",
                PluginFamily::Obfs,
                PluginMode::Tls,
            ),
            (
                "obfs-local%3Bobfs%3Dhttp%3Bobfs-host",
                PluginFamily::Obfs,
                PluginMode::Http,
            ),
            (
                "simple-obfs%3Bobfs%3Dtls",
                PluginFamily::Obfs,
                PluginMode::Tls,
            ),
            (
                "simple-obfs%3Bobfs-host%3D51.38.112.84",
                PluginFamily::Obfs,
                PluginMode::Http,
            ),
            // an obfs NAME with the v2ray vocabulary (the keys win)
            (
                "obfs-local%3Bmode%3Dwebsocket",
                PluginFamily::V2Ray,
                PluginMode::Websocket,
            ),
            // v2ray-plugin: glued, and the base64-JSON key form
            (
                "plugin=v2ray-plugin%3B",
                PluginFamily::V2Ray,
                PluginMode::Websocket,
            ),
            (
                "v2ray-plugin=ey",
                PluginFamily::V2Ray,
                PluginMode::Websocket,
            ),
        ];
        let mut seen_marker = [false; 8];
        let mut plugin_rows = 0usize;
        let mut nested = 0usize;
        let mut unparsed_userinfo = 0usize;

        for path in &files {
            let text = std::fs::read_to_string(path).expect("read corpus file");
            for line in text.lines() {
                if !line.starts_with("ss://") {
                    continue;
                }
                if !line.contains("plugin") {
                    continue;
                }
                let parsed = match SsConfig::try_parse_proto(&RawUrlX::from(line)) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        // Two pre-existing failure shapes reach here, both
                        // BEFORE any plugin branch runs — the userinfo layer
                        // either sees a nested `ss://` or a base64 payload that
                        // a feed percent-encoded mid-string. Neither is a
                        // plugin regression; both must be NAMED errors rather
                        // than a panic, and neither may reach a dial.
                        assert!(
                            !err.to_string().is_empty(),
                            "{}: a parse failure must carry a reason",
                            path.display()
                        );
                        if line.contains("@ss://") {
                            nested += 1;
                        } else {
                            unparsed_userinfo += 1;
                        }
                        continue;
                    }
                };
                plugin_rows += 1;
                let cfg = config(parsed.clone());
                let plugin = cfg
                    .plugin
                    .as_ref()
                    .unwrap_or_else(|| panic!("{}: {line} stored no plugin", path.display()));
                assert!(!plugin.name.is_empty(), "{}: {line}", path.display());

                for (index, (marker, family, mode)) in expected.iter().enumerate() {
                    if line.contains(marker) {
                        assert_eq!(plugin.family, *family, "{line}");
                        assert_eq!(plugin.mode, *mode, "{line}");
                        seen_marker[index] = true;
                    }
                }
                // The export fixed point, on real rows.
                let exported = cfg
                    .reconstruct_proto(&parsed.endpoints[0])
                    .expect("reconstruct a corpus row");
                let reparsed = match SsConfig::try_parse_proto(&RawUrlX::from(exported.as_str())) {
                    Ok(reparsed) => reparsed,
                    Err(e) => panic!("{line} → {exported} failed to re-parse: {e}"),
                };
                assert_eq!(
                    reparsed.identity_once(),
                    parsed.identity_once(),
                    "{line} → {exported} must re-import as the same row"
                );
            }
        }

        assert!(
            plugin_rows >= 20,
            "only {plugin_rows} plugin rows in the corpus"
        );
        assert!(
            nested >= 1,
            "the nested-ss:// rows are missing from the corpus"
        );
        // Feeds also carry rows whose base64 userinfo is percent-encoded
        // mid-string; those fail at the userinfo layer, before any plugin
        // branch, and are counted rather than fixed here — a userinfo-layer
        // change is a separate concern from SIP003.
        assert!(
            unparsed_userinfo >= 1,
            "the percent-encoded-userinfo rows vanished from the corpus"
        );
        for (index, hit) in seen_marker.iter().enumerate() {
            assert!(
                *hit,
                "no corpus row matched the expected shape {}",
                expected[index].0
            );
        }
    }
}
