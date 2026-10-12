//! Hysteria2 (`hysteria2://` / `hy2://`) URL parsing.
//!
//! # Format
//! ```text
//! hysteria2://<auth>@<host>:<port>/?<query_params>#<remarks>
//! hy2://<auth>@<host>:<port>/?<query_params>#<remarks>
//! ```
//!
//! Canonical reference: `thirdparty/hysteria/app/cmd/client.go` `parseURI()`.
//! Both `hysteria2://` and `hy2://` schemes are accepted.
//!
//! # Fields
//!
//! | Component     | Source       | Purpose                         |
//! |---------------|--------------|---------------------------------|
//! | `auth`        | userinfo     | Authentication token/password   |
//! | `host`        | host         | Server address                  |
//! | `port`        | port         | Port (supports port hopping)    |
//! | `remarks`     | fragment (#) | Display name                    |
//!
//! # Query Parameters
//!
//! | Key            | Values                    | Purpose                          | Default   |
//! |----------------|---------------------------|----------------------------------|-----------|
//! | `obfs`         | salamander                | Obfuscation type                 | —         |
//! | `obfs-password`| string (min 4 bytes)      | Obfuscation pre-shared key       | —         |
//! | `insecure`     | 1/0, true/false           | Skip TLS verification            | `false`   |
//! | `sni`          | domain                    | TLS SNI override                 | hostname  |
//! | `up`           | bandwidth string          | Upload speed limit               | —         |
//! | `down`         | bandwidth string          | Download speed limit             | —         |
//! | `mportHopInt`  | integer (seconds)         | Port hopping interval            | —         |
//! | `pinSHA256`    | SHA-256 base64 string     | Certificate SHA-256 pin          | —         |
//!
//! # Port Hopping
//! Port supports special syntax from Hysteria's URL parser fork:
//! - Single: `:443`
//! - List: `:443,7788,9999`
//! - Range: `:8888-9999`
//! - Mixed: `:443,7788-8899,10010`
//!
//! # Edge Cases
//! - Auth can be single token (`auth@`) or `user:pass` pair (concatenated to `user:pass`)
//! - No auth → empty auth token (unusual, server may reject)
//! - Port defaults to 443
//! - Default port `"443"` when no port specified
//! - Salamander obfuscation uses BLAKE2b-256 with 8-byte random salt
//! - IPv6 addresses must be bracketed `[::1]`
//!
//! # References
//! - Hysteria2: `app/cmd/client.go` `parseURI()`, `app/internal/url/url.go`
//! - sing-box: `protocol/hysteria2/outbound.go`, `option/hysteria2.go`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

use super::ProtoIdentity;
use super::common::{
    SecurityConfig, TlsConfig, TlsOpts, TransportConfig, security_force_insecure,
    should_skip_endpoint_param, to_singbox_tls_or_default, to_xray_stream_settings,
};
use super::core_mapping;
use super::identity::IdentityWriter;
use super::utils;
use super::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::clash::{ClashHysteria2, ClashProxy};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{clash_tls_to_security, clash_to_endpoint, host_kind_for};

/// Hysteria2 protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity. A multi-port hop spec is flattened onto `endpoint.ports`
/// (endpoints[0] carries the primary port plus the full list).
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct Hysteria2Config {
    pub auth: String,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub obfs: Option<TinyText>,
    pub obfs_password: Option<TinyText>,
    pub up: Option<TinyText>,
    pub down: Option<TinyText>,
    pub hop_interval: Option<u32>,
    pub pin_sha256: Option<TinyText>,
    pub remarks: Option<TinyText>,
}

impl Hysteria2Config {
    /// Parse a Hysteria2 URL into the parse boundary: [`ParsedProto`] with the
    /// endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// Auth token is the userinfo (single token or user:pass pair).
    /// Port supports Hysteria's extended `PortSpec` (ranges, lists, mixed) —
    /// the primary port lands in `endpoints[0].port` and the full flattened
    /// hop list in `endpoints[0].ports`.
    /// Security defaults to "tls" (QUIC always uses TLS).
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        let (auth, hostport) = if let Some(hostport) = raw.hostport {
            (raw.userinfo, hostport)
        } else {
            let userinfo = raw.userinfo;
            let (auth, hostport) = userinfo.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{userinfo}: missing hostport").into())
            })?;
            (auth, hostport)
        };

        let (parsed_host, parsed_port) = utils::parse_hostport(hostport)?;

        // Endpoint essentials: host/port live here, never in the config payload.
        let parsed_port_first = parsed_port
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;
        let mut endpoint =
            EndpointEssentials::new(parsed_host.to_str().into_owned(), parsed_port_first);
        endpoint.host_type = host_kind_for(&parsed_host);
        if parsed_port.length() > 1 {
            // Multi-port hop spec: endpoints[0] carries the primary port plus
            // the full flattened list.
            endpoint.ports = parsed_port.iter().collect();
        }

        let query = utils::parse_query(raw.query);

        // obfs: obfuscation type (e.g., "salamander")
        let obfs = utils::query_get(&query, "obfs").map(TinyText::from);
        // obfs-password: pre-shared key for salamander obfuscation
        let obfs_password = utils::query_get(&query, "obfs-password").map(TinyText::from);
        // up/down: bandwidth limits (canonical impl doesn't parse these from URL)
        let up = utils::query_get(&query, "up").map(TinyText::from);
        // pin_sha256: certificate SHA-256 pin (keys: pinSHA256, pin_sha256)
        let pin_sha256 =
            utils::query_get_multi(&query, &["pinSHA256", "pin_sha256"]).map(TinyText::from);
        let security = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                pin_sha256: pin_sha256.clone(),
                sni: utils::query_get(&query, "sni").map(TinyText::from),
                alpn: None,
                fp: None,
                insecure: utils::query_get(&query, "insecure").and_then(|v| match v {
                    "1" | "true" | "yes" => Some(true),
                    "0" | "false" | "no" => Some(false),
                    _ => None,
                }),
                ..Default::default()
            })),
            enc: None,
        };
        let down = utils::query_get(&query, "down").map(TinyText::from);
        // hop_interval: port hopping interval in seconds (keys: mportHopInt, hop_interval)
        let hop_interval = utils::query_get_multi(&query, &["mportHopInt", "hop_interval"])
            .and_then(|v| v.parse().ok());
        let remarks = utils::decode_fragment(raw)?;

        let config = Self {
            auth: auth.to_string(),
            security,
            obfs,
            obfs_password,
            up,
            down,
            hop_interval,
            pin_sha256,
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::Hysteria2,
                core_type: core_mapping::resolve_core(ProtocolKind::Hysteria2, None, None),
                config: ProtocolConfig::Hysteria2(config),
            },
        })
    }

    /// Rebuild the share URL from this endpoint-free config plus the endpoint
    /// essentials. Endpoint host comes from `endpoint`; the port spec is the
    /// primary port, or the full flattened list when the endpoint carries a
    /// multi-port hop spec.
    pub fn reconstruct_proto(&self, endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        let host = endpoint.host.as_str();
        let port_str = if endpoint.ports.len() > 1 {
            endpoint
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        } else {
            endpoint.port.to_string()
        };
        let hostport = if host.contains(':') {
            format!("[{host}]:{port_str}")
        } else {
            format!("{host}:{port_str}")
        };

        let query_string = {
            let mut parts: Vec<String> = Vec::new();
            // Security config (always Tls for Hysteria2)
            if self.security.tls.is_some() {
                if self.security.insecure() == Some(true) {
                    parts.push("insecure=1".to_string());
                }
                if let Some(v) = self.security.sni()
                    && !should_skip_endpoint_param(host, v)
                {
                    parts.push(format!("sni={}", urlencoding::encode(v)));
                }
            }
            if let Some(v) = &self.obfs {
                parts.push(format!("obfs={}", urlencoding::encode(v)));
            }
            if let Some(v) = &self.obfs_password {
                parts.push(format!("obfs-password={}", urlencoding::encode(v)));
            }
            if let Some(v) = &self.up {
                parts.push(format!("up={}", urlencoding::encode(v)));
            }
            if let Some(v) = &self.down {
                parts.push(format!("down={}", urlencoding::encode(v)));
            }
            if let Some(v) = &self.hop_interval {
                parts.push(format!("mportHopInt={v}"));
            }
            if let Some(v) = &self.pin_sha256 {
                parts.push(format!("pinSHA256={}", urlencoding::encode(v)));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!("?{}", parts.join("&"))
            }
        };

        let fragment = self
            .remarks
            .as_ref()
            .map(|f| format!("#{}", urlencoding::encode(f)))
            .unwrap_or_default();

        Ok(format!(
            "hysteria2://{auth}@{hostport}{query_string}{fragment}",
            auth = self.auth,
        ))
    }
}

impl Hysteria2Config {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint` (primary port).
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        let alpn_str = self.security.alpn();
        Ok(ClashProxy::Hysteria2(ClashHysteria2 {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            password: self.auth.clone(),
            ports: None,
            hop_interval: self.hop_interval,
            up: self.up.as_ref().and_then(|v| v.parse().ok()),
            down: self.down.as_ref().and_then(|v| v.parse().ok()),
            obfs: self.obfs.as_ref().map(std::string::ToString::to_string),
            obfs_password: self
                .obfs_password
                .as_ref()
                .map(std::string::ToString::to_string),
            skip_cert_verify: self.security.insecure(),
            servername: self.security.sni().map(std::string::ToString::to_string),
            alpn: alpn_str.map(|s| vec![s.to_string()]),
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Hysteria2(c) => {
                let config = Self {
                    auth: c.password.clone(),
                    hop_interval: c.hop_interval,
                    up: c.up.clone().map(TinyText::from),
                    down: c.down.clone().map(TinyText::from),
                    obfs: c.obfs.clone().map(TinyText::from),
                    obfs_password: c.obfs_password.clone().map(TinyText::from),
                    security: clash_tls_to_security(
                        Some(true),
                        c.servername.as_deref(),
                        c.skip_cert_verify,
                        c.alpn
                            .as_deref()
                            .and_then(|v| v.first().map(std::string::String::as_str)),
                        None,
                        None,
                    ),
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                    pin_sha256: None,
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind: ProtocolKind::Hysteria2,
                        core_type: core_mapping::resolve_core(ProtocolKind::Hysteria2, None, None),
                        config: ProtocolConfig::Hysteria2(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected hysteria2 clash proxy".into())),
        }
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
impl ProtoSpec for Hysteria2Config {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::Hysteria2(config) => Ok(config),
            // Parser invariant: a hysteria2 URL always yields a Hysteria2Config.
            _ => Err(ParseError::Unknown(
                "hysteria2 URL parsed to a non-hysteria2 config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "hysteria2 config no longer stores host/port; use Hysteria2Config::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Hysteria2
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
        Some("quic")
    }

    fn security(&self) -> Option<&SecurityConfig> {
        Some(&self.security)
    }

    /// # Errors
    ///
    /// If the Clash proxy doesn't match this protocol type.
    fn try_from_clash(proxy: &ClashProxy) -> Result<Self, ParseError> {
        let parsed = Self::try_from_clash_proto(proxy)?;
        match parsed.protocol.config {
            ProtocolConfig::Hysteria2(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "hysteria2 clash proxy parsed to a non-hysteria2 config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "hysteria2 config no longer stores host/port; use Hysteria2Config::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

/// Per-kind identity tags (see [`super::identity`] for the reserved ranges).
const ID_OBFS: u8 = 0x50;
const ID_UP_MBPS: u8 = 0x51;
const ID_DOWN_MBPS: u8 = 0x52;

/// Numeric Mbps prefix of a Hysteria bandwidth string, exactly as the
/// sing-box builder reads it (`up`/`down` default to 100 Mbps when the prefix
/// is absent or unparseable — see `inject_singbox`).
fn bandwidth_mbps(value: &str) -> u64 {
    let digits = value
        .as_bytes()
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    value[..digits].parse().unwrap_or(100)
}

impl ProtoIdentity for Hysteria2Config {
    /// Identity fields: everything that reaches a builder or the native core.
    ///
    /// `up`/`down` hash as the numeric Mbps the builders emit (sing-box
    /// `up_mbps`/`down_mbps`, native `hysteria-cc-rx`), so `100mbps`, `100`
    /// and an absent value (the builder's 100 Mbps default) share one
    /// identity.
    ///
    /// Excluded on purpose: `remarks` (display), `hop_interval` (dropped by
    /// every builder and ignored by native — no port hopping) and `pin_sha256`
    /// (a mirror of `security.tls.pin_sha256`, which `write_security` already
    /// covers). Credentials: `auth`, `obfs_password`.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("hysteria2");
        super::common::write_security_mandatory(w, &self.security);
        w.present_str(ID_OBFS, self.obfs.as_deref());
        w.opt_u64(ID_UP_MBPS, self.up.as_deref().map(bandwidth_mbps), 100);
        w.opt_u64(ID_DOWN_MBPS, self.down.as_deref().map(bandwidth_mbps), 100);
        w.cred("auth", &self.auth);
        w.cred("obfs_password", self.obfs_password.as_deref().unwrap_or(""));
    }
}

impl InjectToCoreConf for Hysteria2Config {
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

impl Hysteria2Config {
    /// xray-core outbound for this config.
    ///
    /// Vendored xray-core (v26.7.28) registers the UNIFIED `"hysteria"`
    /// outbound (`infra/conf/xray.go` → `HysteriaClientConfig`) — there is no
    /// "hysteria2" protocol name; "hysteria" with version 2 IS hysteria2.
    /// `settings` is exactly `{version, address, port}` (hysteria.go); `auth`
    /// is silently dropped there and must live in
    /// `streamSettings.hysteriaSettings.auth` (`transport_method.go`)
    /// `HysteriaConfig`; emitted as transport `ProtocolName` "hysteria" by
    /// `transport_internet.go` — `proxy/hysteria/client.go` hard-errors "not
    /// hysteria transport" without it). TLS stays in streamSettings
    /// security/tlsSettings (the Task 16 TLS ruling; the settings block has
    /// no TLS keys).
    fn inject_xray(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "hy2"));
        };
        let security = security_force_insecure(&self.security, opts.skip_cert_verify);
        *core_conf = json!({
            "tag": "proxy",
            "protocol": "hysteria",
            "settings": {
                "version": 2,
                "address": ep.host,
                "port": ep.port
            },
        });
        // TLS block (security/tlsSettings) from the typed security, merged
        // with the mandatory hysteria transport (network + hysteriaSettings).
        let mut ss = to_xray_stream_settings(&security, &TransportConfig::Tcp)
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        ss.insert("network".into(), json!("hysteria"));
        ss.insert(
            "hysteriaSettings".into(),
            json!({ "version": 2, "auth": self.auth }),
        );
        core_conf["streamSettings"] = Value::Object(ss);
        Ok(())
    }

    /// sing-box outbound for this config, ported from the old builder's
    /// `Protocol::Hysteria2` arm against the vendored sing-box
    /// `Hysteria2OutboundOptions`: `password` (typed `auth`), `up_mbps`/
    /// `down_mbps` (numeric prefix of the typed `up`/`down` strings, default
    /// 100 — always emitted like the old builder), `obfs` object
    /// (`{type, password}`) when the typed obfs is set (sing-box key the old
    /// builder dropped), and the mandatory TLS block. `hop_interval`/
    /// `server_ports` are dropped (typed `hop_interval` is a raw int with
    /// ambiguous Duration semantics; the old builder dropped it too).
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "hy2"));
        };
        let mbps = |v: &Option<TinyText>, default: i64| -> i64 {
            v.as_ref()
                .and_then(|s| {
                    s.as_str()
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect::<String>()
                        .parse::<i64>()
                        .ok()
                })
                .unwrap_or(default)
        };
        let mut out = json!({
            "tag": "proxy",
            "type": "hysteria2",
            "server": ep.host,
            "server_port": ep.port,
            "password": self.auth,
            "up_mbps": mbps(&self.up, 100),
            "down_mbps": mbps(&self.down, 100),
        });
        if let Some(obfs) = &self.obfs {
            let mut obfs_json = serde_json::Map::new();
            obfs_json.insert("type".into(), json!(obfs));
            if let Some(pw) = &self.obfs_password {
                obfs_json.insert("password".into(), json!(pw));
            }
            out["obfs"] = json!(obfs_json);
        }
        out["tls"] = to_singbox_tls_or_default(&self.security, ep, opts.skip_cert_verify);
        *core_conf = out;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::TlsConfig;
    use super::super::{CoreType, HostKind, ParsedProto, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::Hysteria2Config;
    use crate::urlx::{RawUrlX, SchemeX};

    fn parse(url: &str) -> ParsedProto {
        Hysteria2Config::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> Hysteria2Config {
        match parsed.protocol.config {
            ProtocolConfig::Hysteria2(c) => c,
            other => panic!("expected Hysteria2Config, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &Hysteria2Config) {
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
    fn test_hysteria2_basic() {
        let url = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "206.71.158.41");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 35000);
        assert_eq!(ep.ports, vec![35000]);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Hysteria2);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let cfg = config(parsed);
        assert_eq!(cfg.obfs.as_deref(), Some("salamander"));
        assert_eq!(cfg.security.insecure(), Some(true));
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_hy2_ipv6() {
        let url =
            "hy2://linux.do@[2a01:4f9:4b:f378::1]:13599?security=tls&insecure=1&sni=www.bing.com";
        let parsed = parse(url);
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Hysteria2);
        assert_eq!(parsed.endpoints[0].host, "2a01:4f9:4b:f378::1");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Ipv6);
    }

    #[test]
    fn test_hysteria2_full() {
        let url = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com&up=50mbps&down=100mbps&mportHopInt=10&pinSHA256=abc123deadbeef";
        let parsed = parse(url);
        let cfg = config(parsed);
        assert_eq!(cfg.obfs.as_deref(), Some("salamander"));
        assert_eq!(cfg.obfs_password.as_deref(), Some("password123"));
        assert_eq!(cfg.security.insecure(), Some(true));
        assert_eq!(cfg.security.sni(), Some("jnir.pichondan.com"));
        assert_eq!(cfg.up.as_deref(), Some("50mbps"));
        assert_eq!(cfg.down.as_deref(), Some("100mbps"));
        assert_eq!(cfg.hop_interval, Some(10));
        assert_eq!(cfg.pin_sha256.as_deref(), Some("abc123deadbeef"));
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_pin_sha256_lands_in_tls_opts() {
        let url = "hysteria2://secret@host:443/?pinSHA256=abc123deadbeef&sni=host#r";
        let cfg = config(parse(url));
        let Some(TlsConfig::Tls(opts)) = cfg.security.tls else {
            panic!("expected Tls opts");
        };
        assert_eq!(opts.pin_sha256.as_deref(), Some("abc123deadbeef"));
    }

    #[test]
    fn test_hysteria2_multi_port_endpoint() {
        // Port-hopping spec: primary port + full flattened list on endpoints[0];
        // the config payload carries no port at all.
        let parsed = parse("hysteria2://secret@example.com:443,7788,9999?insecure=1");
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.port, 443, "primary port first");
        assert_eq!(ep.ports, vec![443, 7788, 9999]);
        assert_no_top_level_host_port(&config(parsed));
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_auth() {
        let url_a = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@a.example.com:35000?obfs=salamander&insecure=1&sni=jnir.pichondan.com";
        let url_b = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@b.example.com:443?obfs=salamander&insecure=1&sni=jnir.pichondan.com";
        let url_c = "hysteria2://othertoken@a.example.com:35000?obfs=salamander&insecure=1&sni=jnir.pichondan.com";
        let a = parse(url_a);
        let b = parse(url_b);
        let c = parse(url_c);
        assert_eq!(
            a.uid(),
            b.uid(),
            "same protocol on different servers must dedup to one uid"
        );
        assert_ne!(a.uid(), c.uid(), "different auth -> different uid");
        assert_ne!(a.sig(), 0);
    }

    // ── Reconstruct round-trip via endpoint ───────────────────────────────

    #[test]
    fn reconstruct_roundtrip_via_endpoint() {
        assert_reconstruct_roundtrip(
            "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com",
        );
        assert_reconstruct_roundtrip(
            "hy2://linux.do@[2a01:4f9:4b:f378::1]:13599?security=tls&insecure=1&sni=www.bing.com",
        );
        assert_reconstruct_roundtrip("hysteria2://secret@example.com:443,7788,9999?insecure=1");
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let url = "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = Hysteria2Config::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Hysteria2(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashHysteria2, ClashProxy};

        let proxy = ClashProxy::Hysteria2(ClashHysteria2 {
            name: "test".into(),
            server: "example.com".into(),
            port: 443,
            password: "token".into(),
            ports: None,
            hop_interval: Some(10),
            up: Some("50".into()),
            down: Some("100".into()),
            obfs: Some("salamander".into()),
            obfs_password: Some("password123".into()),
            skip_cert_verify: Some(true),
            servername: Some("jnir.pichondan.com".into()),
            alpn: None,
        });
        let parsed = Hysteria2Config::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 443);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Hysteria2(c) => c,
            other => panic!("expected Hysteria2Config, got {other:?}"),
        };
        assert_eq!(cfg.auth, "token");
        assert_eq!(cfg.hop_interval, Some(10));
        assert_eq!(cfg.obfs.as_deref(), Some("salamander"));
        assert_eq!(cfg.security.insecure(), Some(true));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Hysteria2(out), ClashProxy::Hysteria2(orig)) => assert_eq!(out, orig),
            _ => panic!("expected hysteria2 clash proxy"),
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip() {
        let cfg = config(parse(
            "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&insecure=1&sni=jnir.pichondan.com",
        ));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: Hysteria2Config = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let url = "hysteria2://token@example.com:443?obfs=salamander";
        let bridged = Hysteria2Config::try_parse(&RawUrlX::from(url)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::Hysteria2);
        assert_eq!(bridged.auth, "token");
        // host/port accessors are gone — the endpoint lives on ParsedProto.
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        // Degraded legacy paths error instead of fabricating a host.
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    // ── Xray inject_to (Task 14) ──────────────────────────────────────────

    use super::super::{EndpointEssentials, InjectOptions, InjectToCoreConf, SupportError};

    fn hy2_tls() -> Hysteria2Config {
        config(parse(
            "hy2://linux.do@[2a01:4f9:4b:f378::1]:13599?security=tls&insecure=1&sni=www.bing.com",
        ))
    }

    #[test]
    fn xray_inject_writes_proxy_outbound() {
        let cfg = hy2_tls();
        let ep = EndpointEssentials::new("2a01:4f9:4b:f378::1", 13599);
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&ep),
            InjectOptions::default(),
        )
        .expect("hy2 inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["protocol"], "hysteria");
        assert_eq!(conf["settings"]["version"], 2);
        assert_eq!(conf["settings"]["address"], "2a01:4f9:4b:f378::1");
        assert_eq!(conf["settings"]["port"], 13599);
        // settings is exactly {version, address, port} — auth silently drops
        // there and must live in streamSettings.hysteriaSettings.auth
        // (vendored HysteriaClientConfig + HysteriaConfig).
        assert!(
            conf["settings"].get("auth").is_none(),
            "auth must not leak into settings: {}",
            conf["settings"]
        );
        // TLS placement (Task 16 verification): TLS is uniformly a
        // streamSettings concern (security + tlsSettings per StreamConfig.
        // Build); the hysteria transport carries auth.
        assert_eq!(conf["streamSettings"]["network"], "hysteria");
        assert_eq!(conf["streamSettings"]["hysteriaSettings"]["version"], 2);
        assert_eq!(
            conf["streamSettings"]["hysteriaSettings"]["auth"],
            "linux.do"
        );
        assert_eq!(conf["streamSettings"]["security"], "tls");
        assert_eq!(
            conf["streamSettings"]["tlsSettings"]["serverName"],
            "www.bing.com"
        );
        assert_eq!(conf["streamSettings"]["tlsSettings"]["allowInsecure"], true);
        assert!(
            conf["settings"].get("tls").is_none(),
            "TLS must not leak into settings: {}",
            conf["settings"]
        );
    }

    #[test]
    fn xray_inject_skip_cert_verify_forces_allow_insecure() {
        let cfg = config(parse(
            "hy2://linux.do@example.com:13599?security=tls&sni=x.com",
        ));
        assert_eq!(cfg.security.insecure(), None);
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("example.com", 13599)),
            InjectOptions {
                skip_cert_verify: true,
            },
        )
        .expect("hy2 inject");
        assert_eq!(conf["streamSettings"]["tlsSettings"]["allowInsecure"], true);
    }

    #[test]
    fn xray_inject_without_endpoint_is_rejected() {
        let cfg = hy2_tls();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::Xray, None, InjectOptions::default())
            .expect_err("orphan hy2 must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "hy2")));
    }

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = hy2_tls();
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("2a01:4f9:4b:f378::1", 13599)),
            InjectOptions::default(),
        )
        .expect("hy2 sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "hysteria2");
        assert_eq!(conf["server"], "2a01:4f9:4b:f378::1");
        assert_eq!(conf["server_port"], 13599);
        assert_eq!(conf["password"], "linux.do");
        assert_eq!(conf["up_mbps"], 100, "no up -> default 100");
        assert_eq!(conf["down_mbps"], 100, "no down -> default 100");
        assert!(conf.get("obfs").is_none(), "no obfs -> key omitted");
        assert_eq!(conf["tls"]["enabled"], true);
        assert_eq!(conf["tls"]["server_name"], "www.bing.com");
        assert_eq!(conf["tls"]["insecure"], true, "config insecure=1");
    }

    #[test]
    fn singbox_inject_obfs_up_down_and_skip_cert_verify() {
        let cfg = config(parse(
            "hysteria2://b4bd0613-ff7c-4f2f-954d-185915e6ddad@206.71.158.41:35000?security=tls&obfs=salamander&obfs-password=password123&up=50mbps&down=100mbps",
        ));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("206.71.158.41", 35000)),
            InjectOptions {
                skip_cert_verify: true,
            },
        )
        .expect("hy2 sing-box inject");
        assert_eq!(conf["up_mbps"], 50, "numeric prefix of '50mbps'");
        assert_eq!(conf["down_mbps"], 100, "numeric prefix of '100mbps'");
        assert_eq!(conf["obfs"]["type"], "salamander");
        assert_eq!(conf["obfs"]["password"], "password123");
        assert_eq!(conf["tls"]["insecure"], true, "skip_cert_verify forces it");
    }

    #[test]
    fn singbox_inject_without_endpoint_is_rejected() {
        let cfg = hy2_tls();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect_err("orphan hy2 must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "hy2")));
    }
}
