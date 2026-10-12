//! HTTP Client (`http://`) URL parsing.
//!
//! # Format
//! ```text
//! http://[user:pass@]<host>:<port>[#remarks]
//! ```
//!
//! # Query Parameters
//!
//! | Key       | Values                   | Purpose                     | Default   |
//! |-----------|--------------------------|-----------------------------|-----------|
//! | `security`| tls                      | Enable TLS (HTTPS)          | none      |
//! | `sni`     | domain                   | TLS SNI                     | hostname  |
//! | `alpn`    | comma-separated          | ALPN list                   | —         |
//! | `fp`      | chrome, firefox, safari  | uTLS fingerprint            | —         |
//!
//! # Edge Cases
//! - Userinfo is optional (plain HTTP proxy, no auth)
//! - Default port is 80 when omitted
//! - `security=tls` enables TLS (HTTPS) wrapping
//! - IPv6 addresses must be bracketed
//!
//! # References
//! - sing-box: `option/simple.go` — `HTTPOutboundOptions`
//! - mihomo: `adapter/outbound/http.go` — `HttpOption`
//! - Xray-core: `proxy/http/config.proto`
//! - subconverter: `subparser.cpp` `explodeHTTP()`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

use super::ProtoIdentity;
use super::common::{
    SecurityConfig, TlsConfig, TlsOpts, TransportConfig, security_force_insecure,
    should_skip_endpoint_param, to_singbox_tls, to_xray_stream_settings,
};
use super::core_mapping;
use super::identity::IdentityWriter;
use super::utils;
use super::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::clash::{ClashHttp, ClashProxy};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{
    clash_tls_to_security, clash_to_endpoint, host_kind_for, security_to_clash_tls,
};

/// HTTP client protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct HttpClientConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl HttpClientConfig {
    /// Parse an HTTP proxy URL into the parse boundary: [`ParsedProto`] with
    /// the endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        // Userinfo is optional for HTTP.
        // When present (URL has `@`): raw.userinfo = "user:pass", raw.hostport = "host:port"
        // When absent (no `@`): raw.userinfo == raw.hostport (both are "host:port")
        let has_userinfo = raw.hostport.is_some_and(|hp| raw.userinfo != hp);
        let (username, password) = if has_userinfo && !raw.userinfo.is_empty() {
            if let Some((u, p)) = raw.userinfo.split_once(':') {
                (Some(u.to_string()), Some(p.to_string()))
            } else {
                (Some(raw.userinfo.to_string()), None)
            }
        } else {
            (None, None)
        };

        let hostport = raw
            .hostport
            .ok_or_else(|| ParseError::InvalidHostPort("missing hostport in http URL".into()))?;

        let (parsed_host, parsed_port) = if hostport.contains(':') {
            let (h, p) = utils::parse_hostport(hostport)?;
            (h, p.first().unwrap_or(80))
        } else {
            // No port in URL — parse as host only, default to HTTP port
            let host = utils::parse_host(hostport)?;
            (host, 80)
        };

        // Endpoint essentials: host/port live here, never in the config payload.
        let mut endpoint = EndpointEssentials::new(parsed_host.to_str().into_owned(), parsed_port);
        endpoint.host_type = host_kind_for(&parsed_host);

        let query = utils::parse_query(raw.query);

        // Security mode: tls (HTTPS) or none (default plain HTTP)
        let security = match utils::query_get(&query, "security") {
            Some("tls") => {
                let insecure = utils::query_get_multi(
                    &query,
                    &[
                        "allowInsecure",
                        "allow_insecure",
                        "allowinsecure",
                        "skipVerify",
                    ],
                )
                .and_then(|v| match v {
                    "1" | "true" | "True" => Some(true),
                    "0" | "false" | "False" => Some(false),
                    _ => None,
                });
                SecurityConfig {
                    tls: Some(TlsConfig::Tls(TlsOpts {
                        pin_sha256: None,
                        sni: utils::query_get(&query, "sni").map(TinyText::from),
                        alpn: utils::query_get(&query, "alpn").map(TinyText::from),
                        fp: utils::query_get(&query, "fp").map(TinyText::from),
                        insecure,
                        ..Default::default()
                    })),
                    enc: None,
                }
            }
            _ => SecurityConfig::default(),
        };

        let remarks = utils::decode_fragment(raw)?;

        let config = Self {
            username,
            password,
            security,
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::Http,
                core_type: core_mapping::resolve_core(ProtocolKind::Http, None, None),
                config: ProtocolConfig::Http(config),
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

        let auth = match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("{u}:{p}@"),
            (Some(u), None) => format!("{u}@"),
            _ => String::new(),
        };

        let query_string = {
            let mut parts: Vec<String> = Vec::new();
            if let Some(tls_config) = &self.security.tls
                && let TlsConfig::Tls(opts) = tls_config
            {
                if opts.sni.is_some() || opts.alpn.is_some() || opts.fp.is_some() {
                    parts.push("security=tls".to_string());
                }
                if let Some(v) = &opts.sni
                    && !should_skip_endpoint_param(endpoint_host, v)
                {
                    parts.push(format!("sni={}", urlencoding::encode(v)));
                }
                if let Some(v) = &opts.alpn {
                    parts.push(format!("alpn={}", urlencoding::encode(v)));
                }
                if let Some(v) = &opts.fp {
                    parts.push(format!("fp={}", urlencoding::encode(v)));
                }
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

        Ok(format!("http://{auth}{hostport}{query_string}{fragment}"))
    }
}

impl HttpClientConfig {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        let (tls, servername, skip_cert_verify, _, _) = security_to_clash_tls(&self.security);
        Ok(ClashProxy::Http(ClashHttp {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            username: self.username.clone(),
            password: self.password.clone(),
            tls,
            servername,
            skip_cert_verify,
            headers: None,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Http(c) => {
                let config = Self {
                    username: c.username.clone(),
                    password: c.password.clone(),
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
                        proto_kind: ProtocolKind::Http,
                        core_type: core_mapping::resolve_core(ProtocolKind::Http, None, None),
                        config: ProtocolConfig::Http(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected http clash proxy".into())),
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
impl ProtoSpec for HttpClientConfig {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::Http(config) => Ok(config),
            // Parser invariant: an http URL always yields an HttpClientConfig.
            _ => Err(ParseError::Unknown(
                "http URL parsed to a non-http config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "http config no longer stores host/port; use HttpClientConfig::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Http
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
        if self.security.is_empty() {
            None
        } else {
            Some(&self.security)
        }
    }

    /// # Errors
    ///
    /// If the Clash proxy doesn't match this protocol type.
    fn try_from_clash(proxy: &ClashProxy) -> Result<Self, ParseError> {
        let parsed = Self::try_from_clash_proto(proxy)?;
        match parsed.protocol.config {
            ProtocolConfig::Http(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "http clash proxy parsed to a non-http config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "http config no longer stores host/port; use HttpClientConfig::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

impl ProtoIdentity for HttpClientConfig {
    /// Identity fields: everything that reaches a builder.
    ///
    /// `security` carries the TLS layer both cores emit (xray
    /// `streamSettings`, sing-box `tls`). Excluded on purpose: `remarks`
    /// (display). Credentials: `username` and `password` (emitted only when
    /// both are non-empty).
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("http");
        super::common::write_security(w, &self.security);
        // Endpoint (host/port) intentionally absent from the identity — it
        // lives on the ParsedProto boundary, never in the config payload (T5).
        w.cred("username", self.username.as_deref().unwrap_or(""));
        w.cred("password", self.password.as_deref().unwrap_or(""));
    }
}

impl InjectToCoreConf for HttpClientConfig {
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

impl HttpClientConfig {
    /// xray-core outbound for this config, ported field-by-field from the old
    /// xray builder's `Protocol::Http` arm (including `add_user_if_present`:
    /// users emitted only when both username and password are non-empty).
    fn inject_xray(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "http"));
        };
        let security = security_force_insecure(&self.security, opts.skip_cert_verify);
        let stream = to_xray_stream_settings(&security, &TransportConfig::Tcp);
        let mut server = json!({
            "address": ep.host,
            "port": ep.port,
        });
        if let (Some(u), Some(p)) = (&self.username, &self.password)
            && !u.is_empty()
            && !p.is_empty()
        {
            server["users"] = json!([{ "user": u, "pass": p }]);
        }
        *core_conf = json!({
            "tag": "proxy",
            "protocol": "http",
            "settings": { "servers": [server] },
        });
        if let Some(ss) = stream {
            core_conf["streamSettings"] = ss;
        }
        Ok(())
    }

    /// sing-box outbound for this config, ported field-by-field from the old
    /// builder's `Protocol::Http` arm: `username`/`password` only when BOTH
    /// are non-empty (the old `add_user_if_present` semantics). The typed
    /// TLS is emitted when the security carries it (`HTTPOutboundOptions`
    /// embeds `OutboundTLSOptionsContainer` — an http-over-TLS profile must
    /// not dial a TLS port in plaintext), via the shared helper.
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "http"));
        };
        let mut out = json!({
            "tag": "proxy",
            "type": "http",
            "server": ep.host,
            "server_port": ep.port,
        });
        if let (Some(u), Some(p)) = (&self.username, &self.password)
            && !u.is_empty()
            && !p.is_empty()
        {
            out["username"] = json!(u);
            out["password"] = json!(p);
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
    use super::HttpClientConfig;
    use crate::urlx::{RawUrlX, SchemeX};

    fn parse(url: &str) -> ParsedProto {
        HttpClientConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> HttpClientConfig {
        match parsed.protocol.config {
            ProtocolConfig::Http(c) => c,
            other => panic!("expected HttpClientConfig, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &HttpClientConfig) {
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
    fn test_http_basic() {
        let url = "http://user:pass@1.2.3.4:8080";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 8080);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Http);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let cfg = config(parsed);
        assert_eq!(cfg.username.as_deref(), Some("user"));
        assert_eq!(cfg.password.as_deref(), Some("pass"));
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_http_no_auth() {
        let url = "http://1.2.3.4:8080";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints[0].host, "1.2.3.4");
        assert_eq!(parsed.endpoints[0].port, 8080);
        let cfg = config(parsed);
        assert!(cfg.username.is_none());
        assert!(cfg.password.is_none());
    }

    #[test]
    fn test_http_default_port() {
        let url = "http://user:pass@1.2.3.4";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints[0].port, 80);
    }

    #[test]
    fn test_http_username_only() {
        let url = "http://user@1.2.3.4:8080";
        let cfg = config(parse(url));
        assert_eq!(cfg.username.as_deref(), Some("user"));
        assert!(cfg.password.is_none());
    }

    #[test]
    fn test_http_tls_security() {
        let url = "http://user:pass@example.com:443?security=tls&sni=cdn.example.com";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        let cfg = config(parsed);
        assert_eq!(cfg.security.type_str(), Some("tls"));
        assert_eq!(cfg.security.sni(), Some("cdn.example.com"));
        assert_no_top_level_host_port(&cfg);
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_credentials() {
        let url_a = "http://user:pass@a.example.com:8080";
        let url_b = "http://user:pass@b.example.com:8081";
        let url_c = "http://other:pass@a.example.com:8080";
        let a = parse(url_a);
        let b = parse(url_b);
        let c = parse(url_c);
        assert_eq!(
            a.uid(),
            b.uid(),
            "same protocol on different servers must dedup to one uid"
        );
        assert_ne!(a.uid(), c.uid(), "different credentials -> different uid");
        assert_ne!(a.sig(), 0);
    }

    // ── Reconstruct round-trip via endpoint ───────────────────────────────

    #[test]
    fn reconstruct_roundtrip_via_endpoint() {
        assert_reconstruct_roundtrip("http://user:pass@1.2.3.4:8080");
        assert_reconstruct_roundtrip("http://1.2.3.4:8080");
        assert_reconstruct_roundtrip("http://user@example.com:80#my-server");
        assert_reconstruct_roundtrip(
            "http://user:pass@example.com:443?security=tls&sni=cdn.example.com",
        );
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let url = "http://user:pass@1.2.3.4:8080";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = HttpClientConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Http(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashHttp, ClashProxy};

        let proxy = ClashProxy::Http(ClashHttp {
            name: "test".into(),
            server: "example.com".into(),
            port: 8080,
            username: Some("user".into()),
            password: Some("pass".into()),
            tls: Some(true),
            servername: Some("cdn.example.com".into()),
            skip_cert_verify: None,
            headers: None,
        });
        let parsed = HttpClientConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 8080);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Http(c) => c,
            other => panic!("expected HttpClientConfig, got {other:?}"),
        };
        assert_eq!(cfg.username.as_deref(), Some("user"));
        assert_eq!(cfg.password.as_deref(), Some("pass"));
        // Explicit Clash servername stays in the config (host-free mandate).
        assert_eq!(cfg.security.sni(), Some("cdn.example.com"));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Http(out), ClashProxy::Http(orig)) => assert_eq!(out, orig),
            _ => panic!("expected http clash proxy"),
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip() {
        let cfg = config(parse("http://user:pass@1.2.3.4:8080"));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: HttpClientConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let url = "http://user:pass@1.2.3.4:8080";
        let bridged = HttpClientConfig::try_parse(&RawUrlX::from(url)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::Http);
        assert_eq!(bridged.username.as_deref(), Some("user"));
        // host/port accessors are gone — the endpoint lives on ParsedProto.
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        // Degraded legacy paths error instead of fabricating a host.
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    // ── Xray inject_to (Task 14) ──────────────────────────────────────────

    use super::super::{EndpointEssentials, InjectOptions, InjectToCoreConf, SupportError};

    fn http_auth() -> HttpClientConfig {
        config(parse("http://user:pass@1.2.3.4:8080"))
    }

    #[test]
    fn xray_inject_writes_proxy_outbound_with_users() {
        let cfg = http_auth();
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("1.2.3.4", 8080)),
            InjectOptions::default(),
        )
        .expect("http inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["protocol"], "http");
        let server = &conf["settings"]["servers"][0];
        assert_eq!(server["address"], "1.2.3.4");
        assert_eq!(server["port"], 8080);
        assert_eq!(server["users"][0]["user"], "user");
        assert_eq!(server["users"][0]["pass"], "pass");
        assert!(conf.get("streamSettings").is_none());
    }

    #[test]
    fn xray_inject_https_tls_stream_settings() {
        let cfg = config(parse(
            "http://user:pass@example.com:8443?security=tls&sni=cdn.example.com",
        ));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("example.com", 8443)),
            InjectOptions::default(),
        )
        .expect("http inject");
        assert_eq!(conf["streamSettings"]["security"], "tls");
        assert_eq!(
            conf["streamSettings"]["tlsSettings"]["serverName"],
            "cdn.example.com"
        );
    }

    #[test]
    fn xray_inject_without_endpoint_is_rejected() {
        let cfg = http_auth();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::Xray, None, InjectOptions::default())
            .expect_err("orphan http must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "http")));
    }

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = http_auth();
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 8080)),
            InjectOptions::default(),
        )
        .expect("http sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "http");
        assert_eq!(conf["server"], "1.2.3.4");
        assert_eq!(conf["server_port"], 8080);
        assert_eq!(conf["username"], "user");
        assert_eq!(conf["password"], "pass");
    }

    #[test]
    fn singbox_inject_emits_tls_from_security() {
        // http-over-TLS profile: security=tls + sni -> tls block emitted.
        let cfg = config(parse(
            "http://user:pass@1.2.3.4:8443?security=tls&sni=cdn.example.com",
        ));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 8443)),
            InjectOptions {
                skip_cert_verify: true,
            },
        )
        .expect("http sing-box inject");
        assert_eq!(conf["type"], "http");
        assert_eq!(conf["tls"]["enabled"], true);
        assert_eq!(conf["tls"]["server_name"], "cdn.example.com");
        assert_eq!(conf["tls"]["insecure"], true, "skip_cert_verify forces it");
    }

    #[test]
    fn singbox_inject_without_endpoint_is_rejected() {
        let cfg = http_auth();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect_err("orphan http must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "http")));
    }
}
