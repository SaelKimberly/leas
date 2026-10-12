//! `AnyTLS` (`anytls://`) URL parsing.
//!
//! # Format
//! ```text
//! anytls://<host>:<port>?password=<password>&sni=<sni>#<remarks>
//! ```
//!
//! Password is in query params (not userinfo). TLS is always used.
//! Userinfo portion is always ignored — no auth in userinfo.
//!
//! # Query Parameters
//!
//! | Key              | Values                                       | Purpose                     | Default   |
//! |------------------|----------------------------------------------|-----------------------------|-----------|
//! | `password`       | string                                       | Authentication password     | —         |
//! | `auth`           | string                                       | Password alias              | —         |
//! | `sni`            | domain                                       | TLS SNI override            | hostname  |
//! | `alpn`           | comma-separated (h2,http/1.1)                | ALPN list                   | —         |
//! | `insecure`       | 1/0, true/false                              | Skip TLS cert verification  | `"0"`     |
//! | `allow_insecure` | 1/0, true/false                              | Skip TLS cert verification  | `"0"`     |
//!
//! # Edge Cases
//! - Userinfo is always ignored (no auth in userinfo)
//! - Password is optional (`Option<String>`)
//! - TLS is always on (no `security=none`)
//! - No transport config (raw TCP only)
//!
//! # References
//! - sing-box: `option/anytls.go` — `AnyTLSOutboundOptions`
//! - mihomo: `adapter/outbound/anytls.go` — `AnyTlsOption`
//! - subconverter: `subparser.cpp` `explodeAnyTLS()`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::core_mapping;
use super::identity::IdentityWriter;
use super::utils;
use super::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoIdentity, ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::clash::{ClashAnyTls, ClashProxy};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{
    SecurityConfig, TlsConfig, TlsOpts, clash_tls_to_security, clash_to_endpoint, host_kind_for,
    should_skip_endpoint_param, to_singbox_tls_or_default,
};
use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

/// `AnyTLS` protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct AnyTlsConfig {
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl AnyTlsConfig {
    /// Parse an `AnyTLS` URL into the parse boundary: [`ParsedProto`] with the
    /// endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// Userinfo is ignored (no auth in userinfo). Password comes from query params.
    /// TLS is always used, configured via sni/alpn/insecure query params.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        let hostport = raw
            .hostport
            .ok_or_else(|| ParseError::InvalidUserInfo("anytls: missing hostport".into()))?;

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

        // Password from query: password or auth alias
        let password = utils::query_get_multi(&query, &["password", "auth"]).map(str::to_string);

        // TLS config (AnyTLS always uses TLS)
        let insecure = utils::query_get_multi(
            &query,
            &["insecure", "allow_insecure", "allowinsecure", "skipVerify"],
        )
        .and_then(|v| match v {
            "1" | "true" | "True" => Some(true),
            "0" | "false" | "False" => Some(false),
            _ => None,
        });

        let sni = utils::query_get(&query, "sni").map(TinyText::from);
        let alpn = utils::query_get(&query, "alpn").map(TinyText::from);

        let security = if sni.is_some() || alpn.is_some() || insecure.is_some() {
            SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts {
                    pin_sha256: None,
                    sni,
                    alpn,
                    fp: None,
                    insecure,
                    ..Default::default()
                })),
                enc: None,
            }
        } else {
            SecurityConfig::default()
        };

        let remarks = utils::decode_fragment(raw)?;

        let config = Self {
            password,
            security,
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::AnyTls,
                core_type: core_mapping::resolve_core(ProtocolKind::AnyTls, None, None),
                config: ProtocolConfig::AnyTls(config),
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

        let mut parts: Vec<String> = Vec::new();
        if let Some(password) = &self.password {
            parts.push(format!("password={}", urlencoding::encode(password)));
        }
        if let Some(TlsConfig::Tls(opts)) = &self.security.tls {
            if let Some(sni) = &opts.sni
                && !should_skip_endpoint_param(endpoint_host, sni)
            {
                parts.push(format!("sni={}", urlencoding::encode(sni)));
            }
            if let Some(alpn) = &opts.alpn {
                parts.push(format!("alpn={}", urlencoding::encode(alpn)));
            }
            if opts.insecure == Some(true) {
                parts.push("insecure=1".to_string());
            }
        }

        let query_string = if parts.is_empty() {
            String::new()
        } else {
            format!("?{}", parts.join("&"))
        };

        let fragment = self
            .remarks
            .as_ref()
            .map(|f| format!("#{}", urlencoding::encode(f)))
            .unwrap_or_default();

        Ok(format!("anytls://{hostport}{query_string}{fragment}"))
    }
}

impl AnyTlsConfig {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        Ok(ClashProxy::Anytls(ClashAnyTls {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            password: self.password.clone().unwrap_or_default(),
            tls: Some(true),
            servername: self.security.sni().map(std::string::ToString::to_string),
            skip_cert_verify: self.security.insecure(),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    /// Explicit Clash `servername` stays in the config (protocol parameter).
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Anytls(c) => {
                let mut security = clash_tls_to_security(
                    c.tls,
                    c.servername.as_deref(),
                    c.skip_cert_verify,
                    None,
                    None,
                    None,
                );
                // AnyTLS always uses TLS at the protocol level, so the config
                // payload stores only EXPLICIT TLS parameters. An all-empty
                // Tls (exported `tls: true` with no sni/insecure/alpn/fp)
                // collapses to default — the canonical host-free form — so the
                // clash cycle is identity-stable.
                if matches!(
                    &security.tls,
                    Some(TlsConfig::Tls(opts))
                        if opts.sni.is_none()
                            && opts.insecure.is_none()
                            && opts.alpn.is_none()
                            && opts.fp.is_none()
                ) {
                    security = SecurityConfig::default();
                }
                let config = Self {
                    password: Some(c.password.clone()),
                    security,
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind: ProtocolKind::AnyTls,
                        core_type: core_mapping::resolve_core(ProtocolKind::AnyTls, None, None),
                        config: ProtocolConfig::AnyTls(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected anytls clash proxy".into())),
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
impl ProtoSpec for AnyTlsConfig {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::AnyTls(config) => Ok(config),
            // Parser invariant: an anytls URL always yields an AnyTlsConfig.
            _ => Err(ParseError::Unknown(
                "anytls URL parsed to a non-anytls config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "anytls config no longer stores host/port; use AnyTlsConfig::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::AnyTLS
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

    /// # Errors
    ///
    /// If the Clash proxy doesn't match this protocol type.
    fn try_from_clash(proxy: &ClashProxy) -> Result<Self, ParseError> {
        let parsed = Self::try_from_clash_proto(proxy)?;
        match parsed.protocol.config {
            ProtocolConfig::AnyTls(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "anytls clash proxy parsed to a non-anytls config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "anytls config no longer stores host/port; use AnyTlsConfig::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

impl ProtoIdentity for AnyTlsConfig {
    /// Identity fields: everything that reaches the sing-box builder.
    ///
    /// Excluded on purpose: `remarks` (display). `security` carries every TLS
    /// parameter the builder emits (`server_name`, `insecure`, `alpn`, `fp`,
    /// …). Credential: `password`.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("anytls");
        // Endpoint (host/port) intentionally absent from the identity — it
        // lives on the ParsedProto boundary, never in the config payload (T5).
        super::common::write_security_mandatory(w, &self.security);
        w.cred("password", self.password.as_deref().unwrap_or(""));
    }
}

impl InjectToCoreConf for AnyTlsConfig {
    fn inject_to(
        &self,
        core_conf: &mut Value,
        core_type: CoreType,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        match core_type {
            CoreType::SingBox => self.inject_singbox(core_conf, endpoint, opts),
            other @ CoreType::Xray => {
                Err(SupportError::UnsupportedProtocol("any-tls".into(), other))
            }
        }
    }
}

impl AnyTlsConfig {
    /// sing-box outbound for this config, ported field-by-field from the old
    /// builder's `Protocol::AnyTls` arm (`password` + TLS via the shared
    /// helper). `AnyTLS` always uses TLS, so an empty typed security still
    /// yields a block with the endpoint-host `server_name`.
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "any-tls"));
        };
        let mut out = json!({
            "tag": "proxy",
            "type": "anytls",
            "server": ep.host,
            "server_port": ep.port,
        });
        if let Some(password) = &self.password {
            out["password"] = json!(password);
        }
        out["tls"] = to_singbox_tls_or_default(&self.security, ep, opts.skip_cert_verify);
        *core_conf = out;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CoreType, HostKind, ParsedProto, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::AnyTlsConfig;
    use crate::urlx::{RawUrlX, SchemeX};

    fn parse(url: &str) -> ParsedProto {
        AnyTlsConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> AnyTlsConfig {
        match parsed.protocol.config {
            ProtocolConfig::AnyTls(c) => c,
            other => panic!("expected AnyTlsConfig, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &AnyTlsConfig) {
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
    fn test_anytls_basic() {
        let url = "anytls://1.2.3.4:8080?password=secret";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 8080);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::AnyTls);
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        let cfg = config(parsed);
        assert_eq!(cfg.password.as_deref(), Some("secret"));
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_anytls_no_auth() {
        let parsed = parse("anytls://1.2.3.4:8080");
        assert_eq!(parsed.endpoints[0].host, "1.2.3.4");
        assert_eq!(parsed.endpoints[0].port, 8080);
        assert!(config(parsed).password.is_none());
    }

    #[test]
    fn test_anytls_with_sni() {
        let url = "anytls://example.com:443?password=secret&sni=real-target.com&insecure=1";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        let cfg = config(parsed);
        assert_eq!(cfg.password.as_deref(), Some("secret"));
        assert_eq!(cfg.security.sni(), Some("real-target.com"));
        assert_eq!(cfg.security.insecure(), Some(true));
    }

    #[test]
    fn test_anytls_auth_alias() {
        let cfg = config(parse("anytls://1.2.3.4:8080?auth=mysecret"));
        assert_eq!(cfg.password.as_deref(), Some("mysecret"));
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_passwords() {
        let url_a = "anytls://a.example.com:443?password=secret&sni=real-target.com";
        let url_b = "anytls://b.example.com:8443?password=secret&sni=real-target.com";
        let url_c = "anytls://a.example.com:443?password=other&sni=real-target.com";
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
        assert_reconstruct_roundtrip("anytls://1.2.3.4:8080?password=secret");
        assert_reconstruct_roundtrip("anytls://1.2.3.4:8080");
        assert_reconstruct_roundtrip(
            "anytls://1.2.3.4:8080?password=secret&sni=real.com&insecure=1#my-server",
        );
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let url = "anytls://1.2.3.4:8080?password=secret";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = AnyTlsConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::AnyTls(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashAnyTls, ClashProxy};

        let proxy = ClashProxy::Anytls(ClashAnyTls {
            name: "test".into(),
            server: "example.com".into(),
            port: 443,
            password: "secret".into(),
            tls: Some(true),
            servername: Some("real-target.com".into()),
            skip_cert_verify: Some(true),
            idle_session_check_interval: None,
            idle_session_timeout: None,
            min_idle_session: None,
        });
        let parsed = AnyTlsConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 443);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::AnyTls(c) => c,
            other => panic!("expected AnyTlsConfig, got {other:?}"),
        };
        assert_eq!(cfg.password.as_deref(), Some("secret"));
        // Explicit Clash servername stays in the config (host-free mandate).
        assert_eq!(cfg.security.sni(), Some("real-target.com"));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Anytls(out), ClashProxy::Anytls(orig)) => assert_eq!(out, orig),
            _ => panic!("expected anytls clash proxy"),
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_anytls_serde_roundtrip() {
        let cfg = config(parse("anytls://1.2.3.4:8080?password=secret"));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: AnyTlsConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let url = "anytls://1.2.3.4:8080?password=secret";
        let bridged = AnyTlsConfig::try_parse(&RawUrlX::from(url)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::AnyTLS);
        assert_eq!(bridged.password.as_deref(), Some("secret"));
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
        let cfg = config(parse("anytls://1.2.3.4:8080?password=secret"));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 8080)),
            InjectOptions::default(),
        )
        .expect("anytls sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "anytls");
        assert_eq!(conf["server"], "1.2.3.4");
        assert_eq!(conf["server_port"], 8080);
        assert_eq!(conf["password"], "secret");
        // anytls always uses TLS; server_name falls back to endpoint host.
        assert_eq!(conf["tls"]["enabled"], true);
        assert_eq!(conf["tls"]["server_name"], "1.2.3.4");
    }

    #[test]
    fn singbox_inject_without_password_and_endpoint() {
        let cfg = config(parse("anytls://1.2.3.4:8080"));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 8080)),
            InjectOptions::default(),
        )
        .expect("anytls sing-box inject");
        assert!(
            conf.get("password").is_none(),
            "password omitted when unset"
        );

        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect_err("orphan anytls must be rejected");
        assert!(matches!(
            err,
            SupportError::MissingField("server", "any-tls")
        ));
    }
}
