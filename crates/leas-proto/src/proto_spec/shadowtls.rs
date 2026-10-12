//! `ShadowTLS` (`shadowtls://`) URL parsing.
//!
//! # Format
//! ```text
//! shadowtls://<host>:<port>?password=xxx&version=1&sni=xxx#<remarks>
//! ```
//!
//! No userinfo — password is a query parameter.
//! The `sni` field populates TLS server name indication.
//!
//! # Query Parameters
//!
//! | Key       | Type     | Required | Default | Description          |
//! |-----------|----------|----------|---------|----------------------|
//! | `password`| `String` | ❌       | —       | `ShadowTLS` password   |
//! | `version` | `String` | ❌       | —       | Protocol version     |
//! | `sni`     | `String` | ❌       | —       | TLS SNI              |
//!
//! # References
//! - sing-box: `option/shadowtls.go` — `ShadowTLSOutboundOptions`
//! - `thirdparty/sing-box/docs/configuration/outbound/shadowtls.md`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

use super::ProtoIdentity;
use super::common::{
    SecurityConfig, TlsConfig, TlsOpts, should_skip_endpoint_param, to_singbox_tls,
};
use super::core_mapping;
use super::identity::IdentityWriter;
use super::utils;
use super::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::clash::{ClashProxy, ClashShadowTls};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{
    clash_tls_to_security, clash_to_endpoint, host_kind_for, security_to_clash_tls,
};

/// `ShadowTLS` protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct ShadowTlsConfig {
    pub password: Option<String>,
    pub version: Option<TinyText>,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl ShadowTlsConfig {
    /// Parse a `ShadowTLS` URL into the parse boundary: [`ParsedProto`] with
    /// the endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// `ShadowTLS` uses standard `host:port` with config in query params.
    /// No userinfo — password is extracted from query.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        let hostport = raw.hostport.ok_or_else(|| {
            ParseError::InvalidHostPort("missing hostport in shadowtls URL".into())
        })?;

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
        let remarks = utils::decode_fragment(raw)?;

        let password = utils::query_get(&query, "password").map(str::to_string);
        let version = utils::query_get(&query, "version").map(TinyText::from);

        // Build security config with SNI if present
        let security =
            utils::query_get(&query, "sni").map_or_else(SecurityConfig::default, |sni| {
                SecurityConfig {
                    tls: Some(TlsConfig::Tls(TlsOpts {
                        pin_sha256: None,
                        sni: Some(TinyText::from(sni)),
                        ..Default::default()
                    })),
                    enc: None,
                }
            });

        let config = Self {
            password,
            version,
            security,
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::ShadowTls,
                core_type: core_mapping::resolve_core(ProtocolKind::ShadowTls, None, None),
                config: ProtocolConfig::ShadowTls(config),
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

        let mut query_parts: Vec<String> = Vec::new();
        if let Some(password) = &self.password {
            query_parts.push(format!("password={}", urlencoding::encode(password)));
        }
        if let Some(version) = &self.version {
            query_parts.push(format!("version={}", urlencoding::encode(version)));
        }
        // Emit sni when it differs from host or is explicitly set
        if let Some(sni) = self.security.sni()
            && !should_skip_endpoint_param(endpoint_host, sni)
        {
            query_parts.push(format!("sni={}", urlencoding::encode(sni)));
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

        Ok(format!("shadowtls://{hostport}{query_string}{fragment}"))
    }
}

impl ShadowTlsConfig {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        let (tls, servername, skip_cert_verify, _alpn, _fingerprint) =
            security_to_clash_tls(&self.security);
        Ok(ClashProxy::Shadowtls(ClashShadowTls {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            password: self.password.clone().unwrap_or_default(),
            version: self.version.as_ref().and_then(|v| v.parse::<u32>().ok()),
            tls,
            servername,
            skip_cert_verify,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    /// Explicit Clash `servername` stays in the config (protocol parameter).
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Shadowtls(c) => {
                let config = Self {
                    password: Some(c.password.clone()),
                    version: c.version.map(|v| TinyText::from(v.to_string())),
                    security: clash_tls_to_security(
                        c.tls,
                        c.servername.as_deref(),
                        c.skip_cert_verify,
                        None,
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
                        proto_kind: ProtocolKind::ShadowTls,
                        core_type: core_mapping::resolve_core(ProtocolKind::ShadowTls, None, None),
                        config: ProtocolConfig::ShadowTls(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected shadowtls clash proxy".into())),
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
impl ProtoSpec for ShadowTlsConfig {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::ShadowTls(config) => Ok(config),
            // Parser invariant: a shadowtls URL always yields a ShadowTlsConfig.
            _ => Err(ParseError::Unknown(
                "shadowtls URL parsed to a non-shadowtls config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "shadowtls config no longer stores host/port; use ShadowTlsConfig::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::ShadowTls
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

    fn security(&self) -> Option<&SecurityConfig> {
        Some(&self.security)
    }

    /// # Errors
    ///
    /// If the Clash proxy doesn't match this protocol type.
    fn try_from_clash(proxy: &ClashProxy) -> Result<Self, ParseError> {
        let parsed = Self::try_from_clash_proto(proxy)?;
        match parsed.protocol.config {
            ProtocolConfig::ShadowTls(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "shadowtls clash proxy parsed to a non-shadowtls config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "shadowtls config no longer stores host/port; use ShadowTlsConfig::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

/// Per-kind identity tags (see [`super::identity`] for the reserved ranges).
const ID_VERSION: u8 = 0x50;

impl ProtoIdentity for ShadowTlsConfig {
    /// Identity fields: everything that reaches the sing-box builder.
    ///
    /// Excluded on purpose: `remarks` (display). `version` elides the builder
    /// default of `3` (absent and an unparseable value both build as 3).
    /// `security` carries every TLS parameter the builder emits (`server_name`,
    /// `insecure`, `alpn`, `fp`, …). Credential: `password`.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("shadowtls");
        // Endpoint (host/port) intentionally absent from the identity — it
        // lives on the ParsedProto boundary, never in the config payload (T5).
        super::common::write_security_mandatory(w, &self.security);
        let version = self
            .version
            .as_ref()
            .and_then(|v| v.as_str().parse::<u64>().ok());
        w.opt_u64(ID_VERSION, version, 3);
        w.cred("password", self.password.as_deref().unwrap_or(""));
    }
}

impl InjectToCoreConf for ShadowTlsConfig {
    fn inject_to(
        &self,
        core_conf: &mut Value,
        core_type: CoreType,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        match core_type {
            CoreType::SingBox => self.inject_singbox(core_conf, endpoint, opts),
            other @ CoreType::Xray => Err(SupportError::UnsupportedProtocol(
                "shadow-tls".into(),
                other,
            )),
        }
    }
}

impl ShadowTlsConfig {
    /// sing-box outbound for this config, ported field-by-field from the old
    /// builder's `Protocol::ShadowTls` arm (`password`/`version` defaulting to
    /// 3 + TLS via the shared helper — emitted only when the config carries
    /// TLS material, exactly like the old `build_tls` enabled check).
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "shadow-tls"));
        };
        let version = self
            .version
            .as_ref()
            .and_then(|v| v.as_str().parse::<i64>().ok())
            .unwrap_or(3);
        let mut out = json!({
            "tag": "proxy",
            "type": "shadowtls",
            "server": ep.host,
            "server_port": ep.port,
            "version": version,
        });
        if let Some(password) = &self.password {
            out["password"] = json!(password);
        }
        if let Some(tls) = to_singbox_tls(&self.security, ep, opts.skip_cert_verify) {
            out["tls"] = tls;
        }
        *core_conf = out;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CoreType, HostKind, ParsedProto, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::ShadowTlsConfig;
    use crate::urlx::{RawUrlX, SchemeX};

    fn parse(url: &str) -> ParsedProto {
        ShadowTlsConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> ShadowTlsConfig {
        match parsed.protocol.config {
            ProtocolConfig::ShadowTls(c) => c,
            other => panic!("expected ShadowTlsConfig, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &ShadowTlsConfig) {
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
    fn test_shadowtls_basic() {
        let url = "shadowtls://1.2.3.4:443?password=pass123&version=1&sni=example.com";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 443);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::ShadowTls);
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        let cfg = config(parsed);
        assert_eq!(cfg.password.as_deref(), Some("pass123"));
        assert_eq!(cfg.version.as_deref(), Some("1"));
        assert_eq!(cfg.security.sni(), Some("example.com"));
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_shadowtls_no_auth() {
        let parsed = parse("shadowtls://1.2.3.4:443");
        assert_eq!(parsed.endpoints[0].port, 443);
        let cfg = config(parsed);
        assert_eq!(cfg.password, None);
        assert_eq!(cfg.version, None);
        assert!(cfg.security.tls.is_none());
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_passwords() {
        let url_a = "shadowtls://a.example.com:443?password=pass123&version=1&sni=example.com";
        let url_b = "shadowtls://b.example.com:8443?password=pass123&version=1&sni=example.com";
        let url_c = "shadowtls://a.example.com:443?password=other&version=1&sni=example.com";
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

    // ── Reconstruct round-trip via endpoint ───────────────────────────────

    #[test]
    fn reconstruct_roundtrip_via_endpoint() {
        assert_reconstruct_roundtrip(
            "shadowtls://1.2.3.4:443?password=pass123&version=1&sni=example.com",
        );
        assert_reconstruct_roundtrip("shadowtls://1.2.3.4:443");
        assert_reconstruct_roundtrip("shadowtls://[2001:db8::1]:443?password=pass123");
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let url = "shadowtls://1.2.3.4:443?password=pass123&version=1&sni=example.com";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = ShadowTlsConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::ShadowTls(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashProxy, ClashShadowTls};

        let proxy = ClashProxy::Shadowtls(ClashShadowTls {
            name: "test".into(),
            server: "example.com".into(),
            port: 443,
            password: "pass123".into(),
            version: Some(1),
            tls: Some(true),
            servername: Some("real-target.com".into()),
            skip_cert_verify: Some(true),
        });
        let parsed = ShadowTlsConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 443);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::ShadowTls(c) => c,
            other => panic!("expected ShadowTlsConfig, got {other:?}"),
        };
        assert_eq!(cfg.password.as_deref(), Some("pass123"));
        assert_eq!(cfg.version.as_deref(), Some("1"));
        // Explicit Clash servername stays in the config (host-free mandate).
        assert_eq!(cfg.security.sni(), Some("real-target.com"));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Shadowtls(out), ClashProxy::Shadowtls(orig)) => assert_eq!(out, orig),
            _ => panic!("expected shadowtls clash proxy"),
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_shadowtls_serde_roundtrip() {
        let cfg = config(parse(
            "shadowtls://1.2.3.4:443?password=pass123&version=1&sni=example.com",
        ));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: ShadowTlsConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let url = "shadowtls://1.2.3.4:443?password=pass123";
        let bridged = ShadowTlsConfig::try_parse(&RawUrlX::from(url)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::ShadowTls);
        assert_eq!(bridged.password.as_deref(), Some("pass123"));
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
        let cfg = config(parse(
            "shadowtls://1.2.3.4:443?password=pass123&version=1&sni=example.com",
        ));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 443)),
            InjectOptions::default(),
        )
        .expect("shadowtls sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "shadowtls");
        assert_eq!(conf["server"], "1.2.3.4");
        assert_eq!(conf["server_port"], 443);
        assert_eq!(conf["password"], "pass123");
        assert_eq!(conf["version"], 1);
        assert_eq!(conf["tls"]["enabled"], true);
        assert_eq!(conf["tls"]["server_name"], "example.com");
    }

    #[test]
    fn singbox_inject_version_defaults_to_three() {
        // No version in the URL -> old builder default 3.
        let cfg = config(parse("shadowtls://1.2.3.4:443?password=pass123"));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 443)),
            InjectOptions::default(),
        )
        .expect("shadowtls sing-box inject");
        assert_eq!(conf["version"], 3);
        // No TLS material -> no tls block (old build_tls enabled check).
        assert!(conf.get("tls").is_none());
    }

    #[test]
    fn singbox_inject_without_endpoint_is_rejected() {
        let cfg = config(parse("shadowtls://1.2.3.4:443?password=pass123"));
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect_err("orphan shadowtls must be rejected");
        assert!(matches!(
            err,
            SupportError::MissingField("server", "shadow-tls")
        ));
    }
}
