//! SOCKS5 (`socks://`) URL parsing.
//!
//! # Format
//! ```text
//! socks://[user:pass@]host:port[#remarks]
//! ```
//!
//! Standard URI format with optional username/password authentication.
//! Server address and port in hostport. Username and password (optional) in userinfo.
//! Remarks in fragment.
//!
//! # Fields
//!
//! | Component     | Source              | Purpose                         |
//! |---------------|----------------------|---------------------------------|
//! | `host`        | hostport             | Server address                  |
//! | `port`        | hostport             | Server port (default 1080)      |
//! | `username`    | userinfo (optional)  | SOCKS5 username                 |
//! | `password`    | userinfo (optional)  | SOCKS5 password                 |
//! | `remarks`     | fragment (#)         | Display name (URL-decoded)      |
//!
//! # Edge Cases
//! - Auth is optional; userinfo may contain username only (no colon) or username:password
//! - When no auth is present, `raw.userinfo` equals `raw.hostport` — checked to avoid
//!   misinterpreting the hostport string as a username
//! - IPv6 addresses must be bracketed in the URL
//! - Default port is 1080 if not specified (parse error if unparseable)
//!
//! # References
//! - sing-box: `option/simple.go` — `SOCKSOutboundOptions`
//! - mihomo: `adapter/outbound/socks5.go` — `Socks5Option`
//! - Xray-core: `proxy/socks/config.proto`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

use super::ProtoIdentity;
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
use crate::clash::{ClashProxy, ClashSocks5};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{
    clash_tls_to_security, clash_to_endpoint, host_kind_for, security_to_clash_tls,
};

/// SOCKS5 protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct Socks5Config {
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub remarks: Option<TinyText>,
}

impl Socks5Config {
    /// Parse a SOCKS5 URL into the parse boundary: [`ParsedProto`] with the
    /// endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// Two code paths:
    /// 1. Hostport present (standard): userinfo from `raw.userinfo` (may be empty/
    ///    equal to hostport = no auth, or contain `user:pass`).
    /// 2. Hostport absent (fallback): split `raw.userinfo` at `@` to extract
    ///    auth and hostport.
    ///
    /// Userinfo is split at the first `:` for username:password. A lone username
    /// (no colon) is stored with password = `None`.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        let (userinfo, hostport_str) = if let Some(hostport) = raw.hostport {
            // Standard: socks://[user:pass@]host:port[#remarks]
            (raw.userinfo, hostport)
        } else {
            // Fallback: socks://user:pass@host:port collapsed into userinfo
            let (ui, hp) = raw.userinfo.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{}: missing hostport", raw.userinfo).into())
            })?;
            (ui, hp)
        };

        // Parse userinfo at first ':' for username:password (or just username)
        let (username, password) = {
            // When no auth is present, raw.userinfo == raw.hostport (same string).
            // Treat empty or hostport-identical userinfo as "no auth".
            let has_auth = !userinfo.is_empty() && userinfo != hostport_str;
            if has_auth {
                match userinfo.split_once(':') {
                    Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
                    None => (Some(userinfo.to_string()), None),
                }
            } else {
                (None, None)
            }
        };

        let (parsed_host, parsed_port_spec) = utils::parse_hostport(hostport_str)?;
        let parsed_port = parsed_port_spec
            .first()
            .ok_or_else(|| ParseError::InvalidPort("empty port spec".into()))?;

        // Endpoint essentials: host/port live here, never in the config payload.
        let mut endpoint = EndpointEssentials::new(parsed_host.to_str().into_owned(), parsed_port);
        endpoint.host_type = host_kind_for(&parsed_host);
        if parsed_port_spec.length() > 1 {
            endpoint.ports = parsed_port_spec.iter().collect();
        }

        let remarks = utils::decode_fragment(raw)?;

        let config = Self {
            username,
            password,
            security: SecurityConfig::default(),
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::Socks,
                core_type: core_mapping::resolve_core(ProtocolKind::Socks, None, None),
                config: ProtocolConfig::Socks(config),
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

        let auth = match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!("{u}:{p}@"),
            (Some(u), None) => format!("{u}@"),
            _ => String::new(),
        };

        let fragment = self
            .remarks
            .as_ref()
            .map(|f| format!("#{}", urlencoding::encode(f)))
            .unwrap_or_default();

        Ok(format!("socks://{auth}{hostport}{fragment}"))
    }
}

impl Socks5Config {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        let (tls, servername, skip_cert_verify, _, _) = security_to_clash_tls(&self.security);
        Ok(ClashProxy::Socks5(ClashSocks5 {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            username: self.username.clone(),
            password: self.password.clone(),
            tls,
            servername,
            skip_cert_verify,
            udp: None,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Socks5(c) => {
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
                        proto_kind: ProtocolKind::Socks,
                        core_type: core_mapping::resolve_core(ProtocolKind::Socks, None, None),
                        config: ProtocolConfig::Socks(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected socks5 clash proxy".into())),
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
impl ProtoSpec for Socks5Config {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::Socks(config) => Ok(config),
            // Parser invariant: a socks URL always yields a Socks5Config.
            _ => Err(ParseError::Unknown(
                "socks URL parsed to a non-socks config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "socks config no longer stores host/port; use Socks5Config::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Socks
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
            ProtocolConfig::Socks(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "socks clash proxy parsed to a non-socks config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "socks config no longer stores host/port; use Socks5Config::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

impl ProtoIdentity for Socks5Config {
    /// Identity fields: everything that reaches a builder.
    ///
    /// `security` carries the TLS layer xray-core emits as `streamSettings`
    /// (sing-box's socks outbound has no TLS field, so it ignores the layer).
    /// Excluded on purpose: `remarks` (display). Credentials: `username` and
    /// `password` (emitted only when both are non-empty).
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("socks");
        super::common::write_security(w, &self.security);
        // Endpoint (host/port) intentionally absent from the identity — it
        // lives on the ParsedProto boundary, never in the config payload (T5).
        w.cred("username", self.username.as_deref().unwrap_or(""));
        w.cred("password", self.password.as_deref().unwrap_or(""));
    }
}

impl InjectToCoreConf for Socks5Config {
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

impl Socks5Config {
    /// xray-core outbound for this config, ported field-by-field from the old
    /// xray builder's `Protocol::Socks` arm (including `add_user_if_present`:
    /// users emitted only when both username and password are non-empty).
    fn inject_xray(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "socks"));
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
            "protocol": "socks",
            "settings": { "servers": [server] },
        });
        if let Some(ss) = stream {
            core_conf["streamSettings"] = ss;
        }
        Ok(())
    }

    /// sing-box outbound for this config, ported field-by-field from the old
    /// builder's `Protocol::Socks` arm: `username`/`password` only when BOTH
    /// are non-empty (the old `add_user_if_present` semantics). sing-box
    /// `socks` has no TLS field, so the typed security is not emitted.
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        _opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "socks"));
        };
        let mut out = json!({
            "tag": "proxy",
            "type": "socks",
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
        *core_conf = out;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CoreType, HostKind, ParsedProto, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::Socks5Config;
    use crate::urlx::{RawUrlX, SchemeX};

    fn parse(url: &str) -> ParsedProto {
        Socks5Config::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> Socks5Config {
        match parsed.protocol.config {
            ProtocolConfig::Socks(c) => c,
            other => panic!("expected Socks5Config, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &Socks5Config) {
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
    fn test_basic() {
        let url = "socks://user:pass@1.2.3.4:1080";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "1.2.3.4");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 1080);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Socks);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let cfg = config(parsed);
        assert_eq!(cfg.username.as_deref(), Some("user"));
        assert_eq!(cfg.password.as_deref(), Some("pass"));
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_no_auth() {
        let url = "socks://1.2.3.4:1080";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints[0].host, "1.2.3.4");
        assert_eq!(parsed.endpoints[0].port, 1080);
        let cfg = config(parsed);
        assert!(cfg.username.is_none());
        assert!(cfg.password.is_none());
    }

    #[test]
    fn test_ipv6() {
        let url = "socks://[2001:db8::1]:1080";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints[0].host, "2001:db8::1");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Ipv6);
        assert_eq!(parsed.endpoints[0].port, 1080);
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_credentials() {
        let url_a = "socks://user:pass@a.example.com:1080";
        let url_b = "socks://user:pass@b.example.com:1081";
        let url_c = "socks://other:pass@a.example.com:1080";
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

    #[test]
    fn socks_credentials_change_cred_hash_not_sig() {
        let noauth = parse("socks://1.2.3.4:1080");
        let auth = parse("socks://user:pass@1.2.3.4:1080");
        assert_eq!(noauth.sig(), auth.sig(), "creds are not part of sig");
        assert_ne!(noauth.cred_hash(), auth.cred_hash());
    }

    // ── Reconstruct round-trip via endpoint ───────────────────────────────

    #[test]
    fn reconstruct_roundtrip_via_endpoint() {
        assert_reconstruct_roundtrip("socks://user:pass@1.2.3.4:1080");
        assert_reconstruct_roundtrip("socks://1.2.3.4:1080");
        assert_reconstruct_roundtrip("socks://user@example.com:1080#my-server");
        assert_reconstruct_roundtrip("socks://[2001:db8::1]:1080");
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let url = "socks://user:pass@1.2.3.4:1080";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = Socks5Config::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Socks(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashProxy, ClashSocks5};

        let proxy = ClashProxy::Socks5(ClashSocks5 {
            name: "test".into(),
            server: "1.2.3.4".into(),
            port: 1080,
            username: Some("user".into()),
            password: Some("pass".into()),
            tls: None,
            servername: None,
            skip_cert_verify: None,
            udp: None,
        });
        let parsed = Socks5Config::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "1.2.3.4");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Ipv4);
        assert_eq!(parsed.endpoints[0].port, 1080);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Socks(c) => c,
            other => panic!("expected Socks5Config, got {other:?}"),
        };
        assert_eq!(cfg.username.as_deref(), Some("user"));
        assert_eq!(cfg.password.as_deref(), Some("pass"));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Socks5(out), ClashProxy::Socks5(orig)) => assert_eq!(out, orig),
            _ => panic!("expected socks5 clash proxy"),
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip() {
        let cfg = config(parse("socks://user:pass@1.2.3.4:1080"));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: Socks5Config = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let url = "socks://user:pass@1.2.3.4:1080";
        let bridged = Socks5Config::try_parse(&RawUrlX::from(url)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::Socks);
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

    fn socks_auth() -> Socks5Config {
        config(parse("socks://user:pass@1.2.3.4:1080"))
    }

    #[test]
    fn xray_inject_writes_proxy_outbound_with_users() {
        let cfg = socks_auth();
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("1.2.3.4", 1080)),
            InjectOptions::default(),
        )
        .expect("socks inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["protocol"], "socks");
        let server = &conf["settings"]["servers"][0];
        assert_eq!(server["address"], "1.2.3.4");
        assert_eq!(server["port"], 1080);
        assert_eq!(server["users"][0]["user"], "user");
        assert_eq!(server["users"][0]["pass"], "pass");
        assert!(conf.get("streamSettings").is_none());
    }

    #[test]
    fn xray_inject_no_auth_omits_users() {
        let cfg = config(parse("socks://1.2.3.4:1080"));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("1.2.3.4", 1080)),
            InjectOptions::default(),
        )
        .expect("socks inject");
        let server = &conf["settings"]["servers"][0];
        assert!(server.get("users").is_none());
    }

    #[test]
    fn xray_inject_without_endpoint_is_rejected() {
        let cfg = socks_auth();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::Xray, None, InjectOptions::default())
            .expect_err("orphan socks must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "socks")));
    }

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = socks_auth();
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 1080)),
            InjectOptions::default(),
        )
        .expect("socks sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "socks");
        assert_eq!(conf["server"], "1.2.3.4");
        assert_eq!(conf["server_port"], 1080);
        assert_eq!(conf["username"], "user");
        assert_eq!(conf["password"], "pass");
    }

    #[test]
    fn singbox_inject_auth_omitted_when_password_missing() {
        // Lone username (no password) -> no auth block (old builder rule).
        let cfg = config(parse("socks://user@1.2.3.4:1080"));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("1.2.3.4", 1080)),
            InjectOptions::default(),
        )
        .expect("socks sing-box inject");
        assert!(conf.get("username").is_none());
        assert!(conf.get("password").is_none());
    }

    #[test]
    fn singbox_inject_without_endpoint_is_rejected() {
        let cfg = socks_auth();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, CoreType::SingBox, None, InjectOptions::default())
            .expect_err("orphan socks must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "socks")));
    }
}
