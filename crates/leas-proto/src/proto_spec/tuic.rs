//! TUIC (`tuic://`) URL parsing.
//!
//! # Format
//! ```text
//! tuic://<uuid>:<password>@<host>:<port>?<query_params>#<remarks>
//! ```
//!
//! Standard URI format. UUID and password in userinfo separated by colon.
//! Configuration in query parameters, remarks in fragment.
//!
//! # Query Parameters
//!
//! | Key                  | Values                       | Purpose                          | Default   |
//! |----------------------|------------------------------|----------------------------------|-----------|
//! | `congestion_control` | cubic, bbr, `new_reno`, bbr3  | QUIC congestion control          | `"bbr"`   |
//! | `udp_relay_mode`     | native, quic                 | UDP relay transport              | `"native"`|
//! | `alpn`               | comma-separated (h3,h2)      | TLS ALPN negotiation             | `"h3"`    |
//! | `sni`                | domain                       | TLS SNI override                 | hostname  |
//! | `allow_insecure`     | 1/0                          | Skip TLS cert verification       | `"0"`     |
//!
//! # Edge Cases
//! - `allow_insecure` accepts 3 aliases: `allow_insecure`, `allowInsecure`, `insecure`
//! - ALPN is comma-separated and URL-decoded
//! - Default congestion control is `bbr` (from tuic-client/src/config.rs)
//! - Default ALPN is `h3`
//! - IPv6 addresses must be bracketed
//! - UUID validated via `uuid::Uuid::parse_str`
//!
//! # References
//! - TUIC: `tuic-client/src/config.rs`, `tuic-core/src/utils.rs`
//! - v2rayN: `TuicFmt.cs`, `BaseFmt.cs`
//! - sing-box: `option/tuic.go`

use std::fmt::Write;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

use super::ProtoIdentity;
use super::common::{
    SecurityConfig, TlsConfig, TlsOpts, should_skip_endpoint_param, to_singbox_tls_or_default,
};
use super::core_mapping;
use super::identity::IdentityWriter;
use super::utils;
use super::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::clash::{ClashProxy, ClashTuic};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{
    clash_alpn_as_str, clash_tls_to_security, clash_to_endpoint, host_kind_for,
};

/// TUIC protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct TuicConfig {
    pub uuid: String,
    pub password: String,
    pub congestion_control: Option<TinyText>,
    pub udp_relay_mode: Option<TinyText>,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl TuicConfig {
    /// Parse a TUIC URL into the parse boundary: [`ParsedProto`] with the
    /// endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// Userinfo is `uuid:password` (colon-separated). UUID validated via
    /// `uuid::Uuid::parse_str`. Server address and port from hostport.
    /// `allow_insecure` accepts 3 alias variants for compatibility.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        let (userinfo, hostport) = if let Some(hostport) = raw.hostport {
            (raw.userinfo, hostport)
        } else {
            let userinfo = raw.userinfo;
            let (ui, hp) = userinfo.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{userinfo}: missing hostport").into())
            })?;
            (ui, hp)
        };

        let (uuid, password) = userinfo.split_once(':').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{userinfo}: expected uuid:password").into())
        })?;

        uuid::Uuid::parse_str(uuid)
            .map_err(|_| ParseError::InvalidUserInfo(format!("invalid UUID: {uuid}").into()))?;

        let (parsed_host, parsed_port_spec) = utils::parse_hostport(hostport)?;
        let parsed_port = parsed_port_spec
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;

        // Endpoint essentials: host/port live here, never in the config payload.
        let mut endpoint = EndpointEssentials::new(parsed_host.to_str().into_owned(), parsed_port);
        endpoint.host_type = host_kind_for(&parsed_host);
        if parsed_port_spec.length() > 1 {
            endpoint.ports = parsed_port_spec.iter().collect();
        }

        let query = utils::parse_query(raw.query);

        // congestion_control: cubic/bbr/new_reno/bbr3. Defaults to bbr.
        let congestion_control = utils::query_get(&query, "congestion_control").map(TinyText::from);
        // udp_relay_mode: native/quic. Defaults to native.
        let udp_relay_mode = utils::query_get(&query, "udp_relay_mode").map(TinyText::from);
        let security = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                pin_sha256: None,
                sni: utils::query_get(&query, "sni").map(TinyText::from),
                alpn: utils::query_get(&query, "alpn").map(TinyText::from),
                fp: None,
                insecure: utils::query_get_multi(
                    &query,
                    &["allow_insecure", "insecure", "allowInsecure"],
                )
                .and_then(|v| match v {
                    "1" | "true" => Some(true),
                    "0" | "false" => Some(false),
                    _ => None,
                }),
                ..Default::default()
            })),
            enc: None,
        };
        let remarks = utils::decode_fragment(raw)?;

        let config = Self {
            uuid: uuid.to_string(),
            password: password.to_string(),
            congestion_control,
            udp_relay_mode,
            security,
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::Tuic,
                core_type: core_mapping::resolve_core(ProtocolKind::Tuic, None, None),
                config: ProtocolConfig::Tuic(config),
            },
        })
    }

    /// Rebuild the share URL from this endpoint-free config plus the endpoint
    /// essentials. Endpoint host/port come from `endpoint`.
    pub fn reconstruct_proto(&self, endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        let endpoint_host = endpoint.host.as_str();
        let hostport = if endpoint_host.contains(':') {
            format!("[{endpoint_host}]:{}", endpoint.port)
        } else {
            format!("{endpoint_host}:{}", endpoint.port)
        };

        let mut base = format!("tuic://{}:{}@{}", self.uuid, self.password, hostport);

        let query_string = {
            let mut parts: Vec<String> = Vec::new();
            if let Some(v) = &self.congestion_control {
                parts.push(format!("congestion_control={}", urlencoding::encode(v)));
            }
            if let Some(v) = &self.udp_relay_mode {
                parts.push(format!("udp_relay_mode={}", urlencoding::encode(v)));
            }
            // Security config (TUIC always uses TLS)
            if let Some(v) = self.security.alpn() {
                parts.push(format!("alpn={}", urlencoding::encode(v)));
            }
            if let Some(v) = self.security.insecure() {
                parts.push(format!("allow_insecure={}", if v { "1" } else { "0" }));
            }
            if let Some(v) = self.security.sni()
                && !should_skip_endpoint_param(endpoint_host, v)
            {
                parts.push(format!("sni={}", urlencoding::encode(v)));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!("?{}", parts.join("&"))
            }
        };
        base.push_str(&query_string);

        if let Some(remarks) = &self.remarks {
            let frag = urlencoding::decode(remarks).unwrap_or(std::borrow::Cow::Borrowed(remarks));
            let frag = frag.trim();
            if !frag.is_empty() {
                _ = write!(base, "#{}", urlencoding::encode(frag));
            }
        }

        Ok(base)
    }
}

impl TuicConfig {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        let alpn_str = self.security.alpn();
        let token = if self.password.is_empty() {
            self.uuid.clone()
        } else {
            format!("{}:{}", self.uuid, self.password)
        };
        Ok(ClashProxy::Tuic(ClashTuic {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            token,
            ip: None,
            heartbeat_interval: None,
            reduce_rtt: None,
            request_timeout: None,
            udp_relay_mode: self
                .udp_relay_mode
                .as_ref()
                .map(std::string::ToString::to_string),
            congestion_controller: self
                .congestion_control
                .as_ref()
                .map(std::string::ToString::to_string),
            skip_cert_verify: self.security.insecure(),
            servername: self.security.sni().map(std::string::ToString::to_string),
            alpn: alpn_str.map(|s| vec![s.to_string()]),
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    /// Explicit Clash `servername` stays in the config (protocol parameter).
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Tuic(c) => {
                let (uuid, password) = match c.token.split_once(':') {
                    Some((u, p)) if !u.is_empty() => (u.to_string(), p.to_string()),
                    _ => (c.token.clone(), String::new()),
                };
                let config = Self {
                    uuid,
                    password,
                    congestion_control: c.congestion_controller.clone().map(TinyText::from),
                    udp_relay_mode: c.udp_relay_mode.clone().map(TinyText::from),
                    security: clash_tls_to_security(
                        Some(true),
                        c.servername.as_deref(),
                        c.skip_cert_verify,
                        clash_alpn_as_str(c.alpn.as_ref()),
                        None,
                        None,
                    ),
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind: ProtocolKind::Tuic,
                        core_type: core_mapping::resolve_core(ProtocolKind::Tuic, None, None),
                        config: ProtocolConfig::Tuic(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected tuic clash proxy".into())),
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
impl ProtoSpec for TuicConfig {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::Tuic(config) => Ok(config),
            // Parser invariant: a tuic URL always yields a TuicConfig.
            _ => Err(ParseError::Unknown(
                "tuic URL parsed to a non-tuic config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "tuic config no longer stores host/port; use TuicConfig::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::TUIC
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
            ProtocolConfig::Tuic(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "tuic clash proxy parsed to a non-tuic config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "tuic config no longer stores host/port; use TuicConfig::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

/// Per-kind identity tags (see [`super::identity`] for the reserved ranges).
const ID_CONGESTION_CONTROL: u8 = 0x50;
const ID_UDP_RELAY_MODE: u8 = 0x51;

impl ProtoIdentity for TuicConfig {
    /// Identity fields: everything that reaches the sing-box builder.
    ///
    /// `congestion_control`/`udp_relay_mode` are elided at the sing-box
    /// defaults (`bbr`/`native`), which the builder leaves to the core. ALPN
    /// is written by the shared TLS helper, but sing-box's TUIC outbound
    /// defaults it to `h3` too, so an explicit `h3` is normalized away first —
    /// otherwise a URL spelling out the parser's default would split the
    /// identity from one that omits it.
    ///
    /// Excluded on purpose: `remarks` (display). Credentials: `uuid`,
    /// `password`.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("tuic");
        // ALPN `h3` == the sing-box TUIC default (see `to_singbox_tls`).
        let normalized = (self.security.alpn() == Some("h3")).then(|| {
            let mut security = self.security.clone();
            if let Some(TlsConfig::Tls(opts)) = &mut security.tls {
                opts.alpn = None;
            }
            security
        });
        super::common::write_security_mandatory(w, normalized.as_ref().unwrap_or(&self.security));
        w.opt_str(
            ID_CONGESTION_CONTROL,
            self.congestion_control.as_deref(),
            "bbr",
        );
        w.opt_str(ID_UDP_RELAY_MODE, self.udp_relay_mode.as_deref(), "native");
        w.cred("uuid", &self.uuid);
        w.cred("password", &self.password);
    }
}

impl InjectToCoreConf for TuicConfig {
    fn inject_to(
        &self,
        core_conf: &mut Value,
        core_type: CoreType,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        match core_type {
            CoreType::SingBox => self.inject_singbox(core_conf, endpoint, opts),
            other @ CoreType::Xray => Err(SupportError::UnsupportedProtocol("tuic".into(), other)),
        }
    }
}

impl TuicConfig {
    /// sing-box outbound for this config, ported field-by-field from the old
    /// builder's `Protocol::Tuic` arm (`uuid`/`password`/`server`/`server_port`
    /// + mandatory `tls`), plus the typed `congestion_control`/`udp_relay_mode`
    ///   fields (sing-box `TUICOutboundOptions` keys the old builder dropped).
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "tuic"));
        };
        let mut out = json!({
            "tag": "proxy",
            "type": "tuic",
            "server": ep.host,
            "server_port": ep.port,
            "uuid": self.uuid,
            "password": self.password,
        });
        if let Some(cc) = &self.congestion_control {
            out["congestion_control"] = json!(cc);
        }
        if let Some(urm) = &self.udp_relay_mode {
            out["udp_relay_mode"] = json!(urm);
        }
        // TUIC always uses TLS (QUIC) — old builder emitted the block
        // unconditionally.
        out["tls"] = to_singbox_tls_or_default(&self.security, ep, opts.skip_cert_verify);
        *core_conf = out;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CoreType, HostKind, ParsedProto, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::TuicConfig;
    use crate::urlx::{RawUrlX, SchemeX};

    const TUIC_URL: &str = "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3";

    fn parse(url: &str) -> ParsedProto {
        TuicConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> TuicConfig {
        match parsed.protocol.config {
            ProtocolConfig::Tuic(c) => c,
            other => panic!("expected TuicConfig, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &TuicConfig) {
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
    fn test_tuic_basic() {
        let parsed = parse(TUIC_URL);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "5.178.101.117");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 30006);
        assert_eq!(ep.ports, vec![30006]);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Tuic);
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        let cfg = config(parsed);
        assert_eq!(cfg.uuid, "36106e0f-4d9a-470b-a3fd-535f3b7a1e92");
        assert_eq!(cfg.password, "dongtaiwang.com");
        assert_eq!(cfg.congestion_control.as_deref(), Some("cubic"));
        assert_eq!(cfg.udp_relay_mode.as_deref(), Some("native"));
        assert_eq!(cfg.security.alpn(), Some("h3"));
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_tuic_allow_insecure_and_sni() {
        let url = "tuic://9bbd1f42-7ae7-4239-bd10-a68de95e3295:dongtaiwang.com@ip1.758733.xyz:10088?allow_insecure=0&alpn=h3&congestion_control=bbr&sni=apple.com";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints[0].host, "ip1.758733.xyz");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        let cfg = config(parsed);
        assert_eq!(cfg.security.insecure(), Some(false));
        assert_eq!(cfg.security.sni(), Some("apple.com"));
        assert_eq!(cfg.congestion_control.as_deref(), Some("bbr"));
    }

    #[test]
    fn test_tuic_endpoint_host_kinds() {
        let v6 = parse("tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:pw@[2001:db8::1]:443");
        assert_eq!(v6.endpoints[0].host, "2001:db8::1");
        assert_eq!(v6.endpoints[0].host_type, HostKind::Ipv6);
        assert_eq!(v6.endpoints[0].port, 443);
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_uuids() {
        let url_a = TUIC_URL;
        let url_b = "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@other.example.com:443?congestion_control=cubic&udp_relay_mode=native&alpn=h3";
        let url_c = "tuic://22222222-3333-4444-5555-666666666666:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3";
        let a = parse(url_a);
        let b = parse(url_b);
        let c = parse(url_c);
        assert_eq!(
            a.uid(),
            b.uid(),
            "same protocol on different servers must dedup to one uid"
        );
        assert_ne!(a.uid(), c.uid(), "different uuid -> different uid");
        assert_ne!(a.sig(), 0);
    }

    // ── Reconstruct round-trip via endpoint ───────────────────────────────

    #[test]
    fn reconstruct_roundtrip_via_endpoint() {
        assert_reconstruct_roundtrip(TUIC_URL);
        assert_reconstruct_roundtrip(
            "tuic://36106e0f-4d9a-470b-a3fd-535f3b7a1e92:dongtaiwang.com@5.178.101.117:30006?congestion_control=cubic&udp_relay_mode=native&alpn=h3#DE",
        );
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let parsed = parse(TUIC_URL);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = TuicConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Tuic(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashProxy, ClashTuic};

        let proxy = ClashProxy::Tuic(ClashTuic {
            name: "test".into(),
            server: "example.com".into(),
            port: 30006,
            token: "36106e0f-4d9a-470b-a3fd-535f3b7a1e92:pw".into(),
            ip: None,
            heartbeat_interval: None,
            reduce_rtt: None,
            request_timeout: None,
            udp_relay_mode: Some("native".into()),
            congestion_controller: Some("bbr".into()),
            skip_cert_verify: None,
            servername: Some("cdn.example.com".into()),
            alpn: Some(vec!["h3".into()]),
        });
        let parsed = TuicConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 30006);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Tuic(c) => c,
            other => panic!("expected TuicConfig, got {other:?}"),
        };
        assert_eq!(cfg.uuid, "36106e0f-4d9a-470b-a3fd-535f3b7a1e92");
        assert_eq!(cfg.password, "pw");
        // Explicit Clash servername stays in the config (host-free mandate).
        assert_eq!(cfg.security.sni(), Some("cdn.example.com"));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Tuic(out), ClashProxy::Tuic(orig)) => assert_eq!(out, orig),
            _ => panic!("expected tuic clash proxy"),
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tuic_serde_roundtrip() {
        let cfg = config(parse(TUIC_URL));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: TuicConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let bridged = TuicConfig::try_parse(&RawUrlX::from(TUIC_URL)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::TUIC);
        assert_eq!(bridged.uuid, "36106e0f-4d9a-470b-a3fd-535f3b7a1e92");
        // host/port accessors are gone — the endpoint lives on ParsedProto.
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        // Degraded legacy paths error instead of fabricating a host.
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    // ── Sing-box inject_to (Task 15) ──────────────────────────────────────

    use super::super::{EndpointEssentials, InjectOptions, InjectToCoreConf, SupportError};

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = config(parse(TUIC_URL));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("5.178.101.117", 30006)),
            InjectOptions::default(),
        )
        .expect("tuic sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "tuic");
        assert_eq!(conf["server"], "5.178.101.117");
        assert_eq!(conf["server_port"], 30006);
        assert_eq!(conf["uuid"], "36106e0f-4d9a-470b-a3fd-535f3b7a1e92");
        assert_eq!(conf["password"], "dongtaiwang.com");
        assert_eq!(conf["congestion_control"], "cubic");
        assert_eq!(conf["udp_relay_mode"], "native");
        // tls via the shared helper: enabled + server_name from endpoint host
        // (no explicit sni) + alpn from the typed config.
        assert_eq!(conf["tls"]["enabled"], true);
        assert_eq!(conf["tls"]["server_name"], "5.178.101.117");
        assert_eq!(conf["tls"]["alpn"], serde_json::json!(["h3"]));
        assert!(conf["tls"].get("insecure").is_none());
    }

    #[test]
    fn singbox_inject_sni_and_skip_cert_verify() {
        let cfg = config(parse(
            "tuic://9bbd1f42-7ae7-4239-bd10-a68de95e3295:pw@ip1.758733.xyz:10088?sni=apple.com&alpn=h3",
        ));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("ip1.758733.xyz", 10088)),
            InjectOptions {
                skip_cert_verify: true,
            },
        )
        .expect("tuic sing-box inject");
        assert_eq!(conf["tls"]["server_name"], "apple.com");
        assert_eq!(conf["tls"]["insecure"], true);
    }

    #[test]
    fn singbox_inject_without_endpoint_is_rejected() {
        let cfg = config(parse(TUIC_URL));
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect_err("orphan tuic must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "tuic")));
    }

    #[test]
    fn xray_core_is_rejected() {
        let cfg = config(parse(TUIC_URL));
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(
                &mut conf,
                CoreType::Xray,
                Some(&EndpointEssentials::new("5.178.101.117", 30006)),
                InjectOptions::default(),
            )
            .expect_err("tuic has no xray shape");
        assert!(matches!(
            &err,
            SupportError::UnsupportedProtocol(kind, CoreType::Xray) if kind == "tuic"
        ));
    }
}
