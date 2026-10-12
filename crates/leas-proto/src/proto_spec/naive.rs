//! Naïve (`naive+https://`) URL parsing.
//!
//! # Format
//! ```text
//! naive+https://<username>:<password>@<host>:<port>#<remarks>
//! ```
//!
//! Standard URI format. Username/password in userinfo, server in host:port,
//! remarks in fragment.
//!
//! # Fields
//!
//! | Component     | Source              | Purpose                         |
//! |---------------|---------------------|---------------------------------|
//! | `username`    | userinfo            | Basic auth username              |
//! | `password`    | userinfo            | Basic auth password              |
//! | `host`        | hostport            | Server address                   |
//! | `port`        | hostport            | Server port (default 443)        |
//! | `remarks`     | fragment (#)        | Display name (URL-decoded)       |
//!
//! # Upstream References
//!
//! - sing-box: `option/naive.go` — `NaiveOutboundOptions`
use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::ProtoIdentity;
use super::common::{SecurityConfig, TlsConfig, TlsOpts, to_singbox_tls};
use super::core_mapping;
use super::identity::IdentityWriter;
use super::utils;
use super::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::clash::{ClashNaive, ClashProxy};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{
    clash_tls_to_security, clash_to_endpoint, host_kind_for, security_to_clash_tls,
};

/// Naïve protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct NaiveConfig {
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl NaiveConfig {
    /// Parse a Naïve URL into the parse boundary: [`ParsedProto`] with the
    /// endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// Format: `naive+https://<username>:<password>@<host>:<port>#<remarks>`
    /// Userinfo and hostport are always present.
    /// Default port is 443.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        let hostport = raw.hostport.ok_or_else(|| {
            ParseError::InvalidHost(format!("missing host:port in {}", raw.raw).into())
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

        let (username, password) = raw.userinfo.split_once(':').ok_or_else(|| {
            ParseError::InvalidUserInfo(format!("{}: missing password", raw.userinfo).into())
        })?;

        let remarks = utils::decode_fragment(raw)?;

        let config = Self {
            username: username.to_string(),
            password: password.to_string(),
            security: SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts::default())),
                enc: None,
            },
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::Naive,
                core_type: core_mapping::resolve_core(ProtocolKind::Naive, None, None),
                config: ProtocolConfig::Naive(config),
            },
        })
    }

    /// Rebuild the share URL from this endpoint-free config plus the endpoint
    /// essentials. Endpoint host/port come from `endpoint`.
    pub fn reconstruct_proto(&self, endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        let host = endpoint.host.as_str();
        let hostport = if host.contains(':') {
            format!("[{host}]:{}", endpoint.port)
        } else {
            format!("{host}:{}", endpoint.port)
        };
        let fragment = self
            .remarks
            .as_ref()
            .map(|f| format!("#{}", urlencoding::encode(f)))
            .unwrap_or_default();
        Ok(format!(
            "naive+https://{}:{}@{hostport}{fragment}",
            urlencoding::encode(&self.username),
            urlencoding::encode(&self.password),
        ))
    }
}

impl NaiveConfig {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        let (tls, servername, skip_cert_verify, _, _) = security_to_clash_tls(&self.security);
        Ok(ClashProxy::Naive(ClashNaive {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            username: self.username.clone(),
            password: self.password.clone(),
            tls,
            servername,
            skip_cert_verify,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Naive(c) => {
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
                        proto_kind: ProtocolKind::Naive,
                        core_type: core_mapping::resolve_core(ProtocolKind::Naive, None, None),
                        config: ProtocolConfig::Naive(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected naive clash proxy".into())),
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
impl ProtoSpec for NaiveConfig {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::Naive(config) => Ok(config),
            // Parser invariant: a naive URL always yields a NaiveConfig.
            _ => Err(ParseError::Unknown(
                "naive URL parsed to a non-naive config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "naive config no longer stores host/port; use NaiveConfig::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Naive
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

    fn security(&self) -> Option<&SecurityConfig> {
        Some(&self.security)
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
            ProtocolConfig::Naive(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "naive clash proxy parsed to a non-naive config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "naive config no longer stores host/port; use NaiveConfig::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

impl ProtoIdentity for NaiveConfig {
    /// Identity fields: everything that reaches the sing-box builder.
    ///
    /// Excluded on purpose: `remarks` (display). `security` carries every TLS
    /// parameter the builder emits (`server_name`, `insecure`, `alpn`, `fp`,
    /// …). Credentials: `username` and `password`.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("naive");
        // Endpoint (host/port) intentionally absent from the identity — it
        // lives on the ParsedProto boundary, never in the config payload (T5).
        super::common::write_security_mandatory(w, &self.security);
        w.cred("username", &self.username);
        w.cred("password", &self.password);
    }
}

impl InjectToCoreConf for NaiveConfig {
    fn inject_to(
        &self,
        core_conf: &mut Value,
        core_type: CoreType,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        match core_type {
            CoreType::SingBox => self.inject_singbox(core_conf, endpoint, opts),
            other @ CoreType::Xray => Err(SupportError::UnsupportedProtocol("naive".into(), other)),
        }
    }
}

impl NaiveConfig {
    /// sing-box outbound for this config, ported field-by-field from the old
    /// builder's `Protocol::Naive` arm (`password` always, `username` when
    /// non-empty, TLS via the shared helper — the parse always sets
    /// `security.tls`, so the block is effectively mandatory).
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "naive"));
        };
        let mut out = json!({
            "tag": "proxy",
            "type": "naive",
            "server": ep.host,
            "server_port": ep.port,
            "password": self.password,
        });
        if !self.username.is_empty() {
            out["username"] = json!(self.username);
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
    use super::NaiveConfig;
    use crate::urlx::{RawUrlX, SchemeX};

    fn parse(url: &str) -> ParsedProto {
        NaiveConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> NaiveConfig {
        match parsed.protocol.config {
            ProtocolConfig::Naive(c) => c,
            other => panic!("expected NaiveConfig, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &NaiveConfig) {
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
    fn test_naive_basic() {
        let url = "naive+https://user:pass@example.com:443";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "example.com");
        assert_eq!(ep.host_type, HostKind::Dns);
        assert_eq!(ep.port, 443);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Naive);
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        let cfg = config(parsed);
        assert_eq!(cfg.username, "user");
        assert_eq!(cfg.password, "pass");
        assert_no_top_level_host_port(&cfg);
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_passwords() {
        let url_a = "naive+https://user:pass@a.example.com:443";
        let url_b = "naive+https://user:pass@b.example.com:8443";
        let url_c = "naive+https://user:other@a.example.com:443";
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
        assert_reconstruct_roundtrip("naive+https://user:pass@example.com:443");
        assert_reconstruct_roundtrip("naive+https://user:pass@example.com:443#my-server");
        assert_reconstruct_roundtrip("naive+https://user:pass@[2001:db8::1]:443");
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let url = "naive+https://user:pass@example.com:443";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = NaiveConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Naive(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashNaive, ClashProxy};

        let proxy = ClashProxy::Naive(ClashNaive {
            name: "test".into(),
            server: "example.com".into(),
            port: 443,
            username: "user".into(),
            password: "pass".into(),
            tls: Some(true),
            servername: Some("cdn.example.com".into()),
            skip_cert_verify: Some(true),
        });
        let parsed = NaiveConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 443);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Naive(c) => c,
            other => panic!("expected NaiveConfig, got {other:?}"),
        };
        assert_eq!(cfg.username, "user");
        // Explicit Clash servername stays in the config (host-free mandate).
        assert_eq!(cfg.security.sni(), Some("cdn.example.com"));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Naive(out), ClashProxy::Naive(orig)) => assert_eq!(out, orig),
            _ => panic!("expected naive clash proxy"),
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip() {
        let cfg = config(parse("naive+https://user:pass@example.com:443"));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: NaiveConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let url = "naive+https://user:pass@example.com:443";
        let bridged = NaiveConfig::try_parse(&RawUrlX::from(url)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::Naive);
        assert_eq!(bridged.username, "user");
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
        let cfg = config(parse("naive+https://user:pass@example.com:443"));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("example.com", 443)),
            InjectOptions::default(),
        )
        .expect("naive sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "naive");
        assert_eq!(conf["server"], "example.com");
        assert_eq!(conf["server_port"], 443);
        assert_eq!(conf["username"], "user");
        assert_eq!(conf["password"], "pass");
        // naive always has a tls block; server_name falls back to the
        // endpoint host at build time (never stored).
        assert_eq!(conf["tls"]["enabled"], true);
        assert_eq!(conf["tls"]["server_name"], "example.com");
    }

    #[test]
    fn singbox_inject_skip_cert_verify_forces_insecure() {
        let cfg = config(parse("naive+https://user:pass@example.com:443"));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("example.com", 443)),
            InjectOptions {
                skip_cert_verify: true,
            },
        )
        .expect("naive sing-box inject");
        assert_eq!(conf["tls"]["insecure"], true);
    }

    #[test]
    fn singbox_inject_without_endpoint_is_rejected() {
        let cfg = config(parse("naive+https://user:pass@example.com:443"));
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect_err("orphan naive must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "naive")));
    }
}
