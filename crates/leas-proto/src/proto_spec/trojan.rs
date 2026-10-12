//! Trojan (`trojan://`) URL parsing.
//!
//! # Format
//! ```text
//! trojan://<password>@<host>:<port>?<query_params>#<remarks>
//! ```
//!
//! Standard URI format. Password in userinfo, query params for transport
//! and TLS configuration, fragment for remarks.
//!
//! # Query Parameters
//!
//! | Key       | Values                                    | Purpose                     | Default   |
//! |-----------|--------------------------------------------|-----------------------------|-----------|
//! | `security`| tls, none, reality                          | TLS/security mode           | `"tls"`   |
//! | `type`    | tcp, ws, grpc, http, kcp, quic             | Transport type              | `"tcp"`   |
//! | `path`    | URL path                                   | WS path / gRPC serviceName  | —         |
//! | `sni`     | domain                                     | TLS SNI (folllowed by host) | hostname  |
//! | `alpn`    | comma-separated (h2,http/1.1)              | ALPN list                   | —         |
//! | `fp`      | chrome, firefox, safari, randomized        | uTLS fingerprint            | —         |
//! | `allowInsecure` | 1/0, true/false                    | Skip TLS cert verification  | `"0"`     |
//! | `encryption` | ss;method;password                       | Trojan-Go SS layer          | —         |
//!
//! # Edge Cases
//! - Security defaults to **`"tls"`** (not `"none"` — unlike VLESS)
//! - `allowInsecure` accepts 4 aliases: `allowInsecure`, `allow_insecure`,
//!   `allowinsecure`, `skipVerify` (outbound/dialer compat)
//! - `sni` fallback: `peer` query param → `sni` → URL hostname
//! - Legacy format: `ws=1` + `wspath=` instead of `type=ws` + `path=`
//! - Wire protocol uses SHA-224(password) → 56-byte hex for auth
//!
//! # References
//! - trojan-gfw C++: `src/core/config.h`
//! - outbound: `dialer/trojan/trojan.go`
//! - Xray-core: `proxy/trojan/protocol.go`
//! - sing-box: `option/trojan.go`
//! - subconverter: `subparser.cpp` `explodeTrojan()`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

use super::ProtoIdentity;
use super::common::{
    RealityOpts, SecurityConfig, TlsConfig, TlsOpts, TransportConfig, security_force_insecure,
    should_skip_endpoint_param, to_singbox_tls, to_singbox_transport, to_xray_stream_settings,
    validate_xray_reality, validate_xray_transport,
};
use super::core_mapping;
use super::identity::IdentityWriter;
use super::utils;
use super::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::clash::{ClashProxy, ClashTrojan};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{
    clash_alpn_as_str, clash_tls_to_security, clash_to_endpoint, clash_transport_to_transport,
    host_kind_for, security_to_clash_tls, transport_to_clash,
};

/// Trojan protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity. Host-bearing fields on transports/security hold only EXPLICIT
/// protocol parameters (the host-free parse mandate) — never the endpoint.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct TrojanConfig {
    pub password: String,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub transport: TransportConfig,
    pub path: Option<TinyText>,
    pub remarks: Option<TinyText>,
}

impl TrojanConfig {
    /// Parse a Trojan URL into the parse boundary: [`ParsedProto`] with the
    /// endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// Trojan uses standard URI: password in userinfo, server in host:port,
    /// config in query params, remarks in fragment.
    /// Security defaults to "tls" (Trojan always uses TLS by default).
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        let (username, hostport) = if let Some(hostport) = raw.hostport {
            (raw.userinfo, hostport)
        } else {
            let userinfo = raw.userinfo;
            let (username, hostport) = userinfo.split_once('@').ok_or_else(|| {
                ParseError::InvalidUserInfo(format!("{userinfo}: missing hostport").into())
            })?;
            (username, hostport)
        };

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

        // Security mode: tls (default), none, or reality
        let security = match utils::query_get(&query, "security") {
            Some("tls") | None => {
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
            Some("reality") => SecurityConfig {
                tls: Some(TlsConfig::Reality(RealityOpts {
                    sni: utils::query_get(&query, "sni").map(TinyText::from),
                    fp: utils::query_get(&query, "fp").map(TinyText::from),
                    pbk: utils::query_get(&query, "pbk").map(str::to_string),
                    sid: utils::query_get(&query, "sid").map(TinyText::from),
                    spx: utils::query_get(&query, "spx").map(TinyText::from),
                })),
                enc: None,
            },
            _ => SecurityConfig::default(),
        };
        // Transport type: tcp (default), ws, grpc, http, quic, kcp
        let transport_type = utils::query_get(&query, "type")
            .unwrap_or("tcp")
            .to_string();
        let path = utils::query_get(&query, "path").map(TinyText::from);

        let remarks = utils::decode_fragment(raw)?;

        // HOST-FREE PARSE MANDATE (identity invariant): the endpoint host must
        // never leak into the config payload. Only EXPLICIT query params
        // (`host=`, `sni=`) are protocol parameters and are stored; `with_host`
        // is called with `None` as the server address, so absent params leave
        // the ws/grpc/http host fields unset (the builder injects the endpoint
        // host at build time in phase D).
        let host = utils::query_get(&query, "host").map(str::to_string);
        let sni_from_query = utils::query_get(&query, "sni").map(str::to_string);

        let mut transport =
            TransportConfig::from_type_and_path(Some(&transport_type), path.as_deref())?
                .unwrap_or(TransportConfig::Tcp);
        transport = transport.with_host(host, sni_from_query, None);

        let path = match &transport {
            TransportConfig::Ws(ws) => ws.path.clone(),
            TransportConfig::Grpc(g) => g.path.clone(),
            TransportConfig::Http(h) => h.path.clone(),
            TransportConfig::HttpUpgrade(cfg) => cfg.path.clone(),
            TransportConfig::XHttp(cfg) => cfg.path.clone(),
            _ => path,
        };

        let config = Self {
            password: username.to_string(),
            transport,
            security,
            path,
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::Trojan,
                core_type: core_mapping::resolve_core(ProtocolKind::Trojan, None, None),
                config: ProtocolConfig::Trojan(config),
            },
        })
    }

    /// Rebuild the share URL from this endpoint-free config plus the endpoint
    /// essentials. Endpoint host/port come from `endpoint`; every protocol
    /// parameter (including explicit transport/security host fields) is taken
    /// from the config.
    pub fn reconstruct_proto(&self, endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        let endpoint_host = endpoint.host.as_str();
        let hostport = if endpoint_host.contains(':') {
            format!("[{endpoint_host}]:{}", endpoint.port)
        } else {
            format!("{endpoint_host}:{}", endpoint.port)
        };

        let query_string = {
            let mut parts: Vec<String> = Vec::new();
            // Security config. TLS is the default — only emit when reality or sni/alpn/fp set.
            if let Some(tls_config) = &self.security.tls {
                match tls_config {
                    TlsConfig::Tls(opts) => {
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
                        if opts.insecure == Some(true) {
                            parts.push("allowInsecure=1".to_string());
                        }
                    }
                    TlsConfig::Reality(opts) => {
                        parts.push("security=reality".to_string());
                        if let Some(v) = &opts.sni
                            && !should_skip_endpoint_param(endpoint_host, v)
                        {
                            parts.push(format!("sni={}", urlencoding::encode(v)));
                        }
                        if let Some(v) = &opts.fp {
                            parts.push(format!("fp={}", urlencoding::encode(v)));
                        }
                        if let Some(v) = &opts.pbk {
                            parts.push(format!("pbk={}", urlencoding::encode(v)));
                        }
                        if let Some(v) = &opts.sid {
                            parts.push(format!("sid={}", urlencoding::encode(v)));
                        }
                        if let Some(v) = &opts.spx {
                            parts.push(format!("spx={}", urlencoding::encode(v)));
                        }
                    }
                }
            }
            if self.security.tls.is_none() {
                parts.push("security=none".to_string());
            }
            if self.transport.type_str() != "tcp" {
                parts.push(format!("type={}", self.transport.type_str()));
            }
            // Explicit transport host params round-trip for every host-bearing
            // transport (T4 widening, consistent with vless/vmess).
            match &self.transport {
                TransportConfig::Ws(cfg) => {
                    if let Some(host) = &cfg.host
                        && !should_skip_endpoint_param(endpoint_host, host)
                    {
                        parts.push(format!("host={}", urlencoding::encode(host)));
                    }
                }
                TransportConfig::Grpc(cfg) => {
                    if let Some(auth) = &cfg.authority
                        && !should_skip_endpoint_param(endpoint_host, auth)
                    {
                        parts.push(format!("host={}", urlencoding::encode(auth)));
                    }
                }
                TransportConfig::Http(cfg) => {
                    if let Some(host) = &cfg.host
                        && !should_skip_endpoint_param(endpoint_host, host)
                    {
                        parts.push(format!("host={}", urlencoding::encode(host)));
                    }
                }
                TransportConfig::HttpUpgrade(cfg) => {
                    if let Some(host) = &cfg.host
                        && !should_skip_endpoint_param(endpoint_host, host)
                    {
                        parts.push(format!("host={}", urlencoding::encode(host)));
                    }
                }
                TransportConfig::XHttp(cfg) => {
                    if let Some(host) = &cfg.host
                        && !should_skip_endpoint_param(endpoint_host, host)
                    {
                        parts.push(format!("host={}", urlencoding::encode(host)));
                    }
                }
                _ => {}
            }
            if let Some(path) = &self.path {
                parts.push(format!("path={}", urlencoding::encode(path)));
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
            "trojan://{password}@{hostport}{query_string}{fragment}",
            password = self.password,
        ))
    }
}

impl TrojanConfig {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint` (identity is not
    /// involved in this direction).
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        let server = endpoint.host.clone();
        let (tls, servername, skip_cert_verify, alpn_str, fingerprint) =
            security_to_clash_tls(&self.security);
        // HOST-FREE: `None` — the endpoint host must never fall back into
        // Clash h2 `host` (which re-imports into the identity config).
        let (_, ws_opts, grpc_opts, _, _, _) = transport_to_clash(&self.transport, None);
        Ok(ClashProxy::Trojan(ClashTrojan {
            name,
            server,
            port: endpoint.port,
            password: self.password.clone(),
            udp: None,
            tfo: None,
            flow: None,
            flow_show: None,
            tls: tls.unwrap_or(true),
            servername,
            skip_cert_verify,
            alpn: alpn_str.map(|s| vec![s]),
            fingerprint,
            ws_opts,
            grpc_opts,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    /// Explicit Clash TLS `servername` and ws `Host` header fields are
    /// protocol parameters and stay in the config.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Trojan(c) => {
                let security = clash_tls_to_security(
                    Some(c.tls),
                    c.servername.as_deref(),
                    c.skip_cert_verify,
                    clash_alpn_as_str(c.alpn.as_ref()),
                    c.fingerprint.as_deref(),
                    None,
                );
                // Infer network from available transport opts (ClashTrojan has no network field)
                let network = if c.ws_opts.is_some() {
                    Some("ws")
                } else if c.grpc_opts.is_some() {
                    Some("grpc")
                } else {
                    None
                };
                // HOST-FREE: the endpoint server is never copied into
                // transport host fields (`server = None`).
                let transport = clash_transport_to_transport(
                    network,
                    c.ws_opts.as_ref(),
                    c.grpc_opts.as_ref(),
                    None,
                    None,
                    None,
                    None,
                );
                // Derive path from transport (same pattern as try_parse_proto)
                let path = match &transport {
                    TransportConfig::Ws(ws) => ws.path.clone(),
                    TransportConfig::Grpc(g) => g.path.clone(),
                    TransportConfig::Http(h) => h.path.clone(),
                    TransportConfig::HttpUpgrade(cfg) => cfg.path.clone(),
                    TransportConfig::XHttp(cfg) => cfg.path.clone(),
                    _ => None,
                };
                let config = Self {
                    password: c.password.clone(),
                    security,
                    transport,
                    path,
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind: ProtocolKind::Trojan,
                        core_type: core_mapping::resolve_core(ProtocolKind::Trojan, None, None),
                        config: ProtocolConfig::Trojan(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected trojan clash proxy".into())),
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
impl ProtoSpec for TrojanConfig {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::Trojan(config) => Ok(config),
            // Parser invariant: a trojan URL always yields a TrojanConfig.
            _ => Err(ParseError::Unknown(
                "trojan URL parsed to a non-trojan config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "trojan config no longer stores host/port; use TrojanConfig::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Trojan
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
        Some(self.transport.type_str())
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
            ProtocolConfig::Trojan(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "trojan clash proxy parsed to a non-trojan config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "trojan config no longer stores host/port; use TrojanConfig::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

impl ProtoIdentity for TrojanConfig {
    /// Identity fields: everything a builder or the native client reads.
    ///
    /// Excluded on purpose: `remarks` (display) and `path` (a mirror of the
    /// transport's own path, which `write_transport` already covers).
    /// Credential: `password`.
    ///
    /// REALITY `pbk`/`sid`/`spx` and TLS `insecure` reach the builders through
    /// the shared `write_security` helper (they were missing from both old
    /// streams).
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("trojan");
        super::common::write_security(w, &self.security);
        super::common::write_transport(w, &self.transport);
        w.cred("password", &self.password);
    }
}

impl InjectToCoreConf for TrojanConfig {
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

impl TrojanConfig {
    /// xray-core outbound for this config, ported field-by-field from the old
    /// xray builder's `Protocol::Trojan` arm. Transport host left unset by the
    /// host-free parse mandate is filled at build time via
    /// `TransportConfig::with_host` (never mutating the stored config).
    fn inject_xray(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "trojan"));
        };
        validate_xray_reality(&self.security)?;
        let transport = self
            .transport
            .clone()
            .with_host(Some(ep.host.clone()), None, None);
        // An `http`/`quic` transport would emit a config xray-core refuses to
        // load (a removed feature, not a warning) — refuse the BUILD instead.
        validate_xray_transport(&transport)?;
        let security = security_force_insecure(&self.security, opts.skip_cert_verify);
        let stream = to_xray_stream_settings(&security, &transport);
        *core_conf = json!({
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": ep.host,
                    "port": ep.port,
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
    /// builder's `Protocol::Trojan` arm (`password` + TLS via the shared
    /// helper) plus the typed `transport` (sing-box `V2RayTransportOptions`;
    /// `kcp`/`xhttp` refuse at build time).
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "trojan"));
        };
        // Transport host left unset by the host-free parse mandate is filled
        // at build time (never mutating the stored config) — same rule as the
        // xray arm.
        let transport = self
            .transport
            .clone()
            .with_host(Some(ep.host.clone()), None, None);
        let mut out = json!({
            "tag": "proxy",
            "type": "trojan",
            "server": ep.host,
            "server_port": ep.port,
            "password": self.password,
        });
        if let Some(tls) = to_singbox_tls(&self.security, ep, opts.skip_cert_verify) {
            out["tls"] = tls;
        }
        if let Some(transport) = to_singbox_transport(&transport)? {
            out["transport"] = transport;
        }
        *core_conf = out;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CoreType, HostKind, ParsedProto, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::TrojanConfig;
    use crate::proto_spec::common::TransportConfig;
    use crate::urlx::{RawUrlX, SchemeX};
    use rstest::rstest;

    fn parse(url: &str) -> ParsedProto {
        TrojanConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> TrojanConfig {
        match parsed.protocol.config {
            ProtocolConfig::Trojan(c) => c,
            other => panic!("expected TrojanConfig, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &TrojanConfig) {
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
    fn test_trojan_basic() {
        let url = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "172.64.152.23");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 443);
        assert_eq!(ep.ports, vec![443]);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Trojan);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let cfg = config(parsed);
        assert_eq!(cfg.password, "humanity");
        assert_eq!(cfg.transport.type_str(), "ws");
        assert_eq!(cfg.security.type_str(), Some("tls"));
        assert_eq!(cfg.security.sni(), Some("www.creationlong.org"));
        if let TransportConfig::Ws(ws) = &cfg.transport {
            assert_eq!(ws.path.as_deref(), Some("/assignment"));
        } else {
            panic!("expected ws transport");
        }
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_trojan_endpoint_host_kinds() {
        let dns = parse("trojan://pass@example.com:443?type=tcp");
        assert_eq!(dns.endpoints[0].host, "example.com");
        assert_eq!(dns.endpoints[0].host_type, HostKind::Dns);

        let v6 = parse("trojan://pass@[2001:db8::1]:8443?type=tcp");
        assert_eq!(v6.endpoints[0].host, "2001:db8::1");
        assert_eq!(v6.endpoints[0].host_type, HostKind::Ipv6);
        assert_eq!(v6.endpoints[0].port, 8443);
    }

    #[test]
    fn trojan_security_none_is_stored() {
        let cfg = config(parse("trojan://pass@example.com:443?security=none"));
        assert!(cfg.security.tls.is_none());
        assert_no_top_level_host_port(&cfg);
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_passwords() {
        let url_a = "trojan://humanity@a.example.com:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let url_b = "trojan://humanity@b.example.com:8443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let url_c = "trojan://otherpass@a.example.com:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
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
            "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org",
        );
        assert_reconstruct_roundtrip("trojan://pass@example.com:443?security=none");
        assert_reconstruct_roundtrip("trojan://pass@[2001:db8::1]:443?type=tcp");
        assert_reconstruct_roundtrip(
            "trojan://pass@example.com:443?type=ws&path=%2F&host=cdn.example.com",
        );
    }

    #[test]
    fn explicit_host_param_survives_roundtrip() {
        let url =
            "trojan://pass@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws#r";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let out = cfg.reconstruct_proto(&endpoint).expect("reconstruct");
        assert!(
            out.contains("host=cdn.example.com"),
            "roundtrip keeps host for {url}: {out}"
        );
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let url = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = TrojanConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Trojan(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashProxy, ClashTrojan, ClashWSOpts};

        let proxy = ClashProxy::Trojan(ClashTrojan {
            name: "test".into(),
            server: "example.com".into(),
            port: 443,
            password: "humanity".into(),
            udp: None,
            tfo: None,
            flow: None,
            flow_show: None,
            tls: true,
            servername: Some("www.creationlong.org".into()),
            skip_cert_verify: None,
            alpn: None,
            fingerprint: None,
            ws_opts: Some(ClashWSOpts {
                path: Some("/ws".into()),
                headers: Some(std::collections::HashMap::from([(
                    "Host".to_string(),
                    "cdn.example.com".to_string(),
                )])),
                ..Default::default()
            }),
            grpc_opts: None,
        });
        let parsed = TrojanConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 443);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Trojan(c) => c,
            other => panic!("expected TrojanConfig, got {other:?}"),
        };
        // Explicit Clash ws Host header stays in the config (host-free mandate).
        if let TransportConfig::Ws(ws) = &cfg.transport {
            assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
            assert_eq!(ws.path.as_deref(), Some("/ws"));
        } else {
            panic!("expected ws transport");
        }
        assert_eq!(cfg.security.sni(), Some("www.creationlong.org"));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Trojan(out), ClashProxy::Trojan(orig)) => assert_eq!(out, orig),
            _ => panic!("expected trojan clash proxy"),
        }
    }

    // ── HOST-FREE PARSE MANDATE: no server-address fallback ───────────────

    #[test]
    fn ws_host_param_stored_but_absent_param_stays_unset() {
        // Explicit `host=` is a protocol parameter and IS stored.
        let url =
            "trojan://pass@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws";
        let cfg = config(parse(url));
        if let TransportConfig::Ws(ws) = &cfg.transport {
            assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
        } else {
            panic!("expected ws transport");
        }

        // Without `host=`, the ws host field must be UNSET — never the server.
        let url = "trojan://pass@example.com:443?security=tls&type=ws&path=%2Fws";
        let parsed = parse(url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        if let TransportConfig::Ws(ws) = &cfg.transport {
            assert_eq!(ws.host, None, "ws host must not fall back to the server");
        } else {
            panic!("expected ws transport");
        }
        // Reconstruct must not invent a `host=` param for the absent one.
        let out = cfg.reconstruct_proto(&endpoint).expect("reconstruct");
        assert!(!out.contains("host="), "no host param emitted: {out}");
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn sni_param_stored_but_absent_sni_stays_unset() {
        // Explicit `sni=` is a protocol parameter and IS stored.
        let url = "trojan://pass@example.com:443?security=tls&type=tcp&sni=cdn.example.com";
        let cfg = config(parse(url));
        assert_eq!(cfg.security.sni(), Some("cdn.example.com"));

        // No `sni=` param: security must not carry the server as sni.
        let url = "trojan://pass@example.com:443?security=tls&type=tcp";
        let cfg = config(parse(url));
        assert_eq!(
            cfg.security.sni(),
            None,
            "sni must not fall back to the server"
        );
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_trojan_serde_roundtrip() {
        let url = "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org";
        let cfg = config(parse(url));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: TrojanConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let url = "trojan://humanity@172.64.152.23:443?type=tcp";
        // try_parse still extracts the config (endpoints discarded).
        let bridged = TrojanConfig::try_parse(&RawUrlX::from(url)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::Trojan);
        assert_eq!(bridged.password, "humanity");
        // host/port accessors are gone — the endpoint lives on ParsedProto.
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        // Degraded legacy paths error instead of fabricating a host.
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    // ── Xray inject_to (Task 14) ──────────────────────────────────────────

    use super::super::{EndpointEssentials, InjectOptions, InjectToCoreConf, SupportError};

    fn trojan_ws_tls() -> TrojanConfig {
        config(parse(
            "trojan://humanity@172.64.152.23:443?security=tls&type=ws&path=/assignment&sni=www.creationlong.org",
        ))
    }

    #[test]
    fn xray_inject_writes_proxy_outbound() {
        let cfg = trojan_ws_tls();
        let ep = EndpointEssentials::new("172.64.152.23", 443);
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&ep),
            InjectOptions::default(),
        )
        .expect("trojan inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["protocol"], "trojan");
        let server = &conf["settings"]["servers"][0];
        assert_eq!(server["address"], "172.64.152.23");
        assert_eq!(server["port"], 443);
        assert_eq!(server["password"], "humanity");
        let expected = crate::proto_spec::common::to_xray_stream_settings(
            &cfg.security,
            &cfg.transport
                .clone()
                .with_host(Some("172.64.152.23".into()), None, None),
        )
        .expect("ws+tls stream settings");
        assert_eq!(conf["streamSettings"], expected);
    }

    #[test]
    fn xray_inject_security_none_no_stream_settings() {
        // Trojan defaults to TLS; security=none yields a bare tcp outbound.
        let cfg = config(parse(
            "trojan://humanity@example.com:443?type=tcp&security=none",
        ));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("example.com", 443)),
            InjectOptions::default(),
        )
        .expect("trojan inject");
        assert!(conf.get("streamSettings").is_none());
    }

    #[test]
    fn xray_inject_skip_cert_verify_forces_allow_insecure() {
        let cfg = config(parse(
            "trojan://humanity@example.com:443?security=tls&type=tcp&allowInsecure=0",
        ));
        assert_eq!(cfg.security.insecure(), Some(false));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("example.com", 443)),
            InjectOptions {
                skip_cert_verify: true,
            },
        )
        .expect("trojan inject");
        assert_eq!(conf["streamSettings"]["tlsSettings"]["allowInsecure"], true);
    }

    #[rstest]
    #[case::xray(CoreType::Xray)]
    #[case::singbox(CoreType::SingBox)]
    fn inject_without_endpoint_is_rejected(#[case] core: CoreType) {
        let cfg = trojan_ws_tls();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, core, None, InjectOptions::default())
            .expect_err("orphan trojan must be rejected");
        assert!(matches!(
            err,
            SupportError::MissingField("server", "trojan")
        ));
    }

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = trojan_ws_tls();
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("172.64.152.23", 443)),
            InjectOptions::default(),
        )
        .expect("trojan sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "trojan");
        assert_eq!(conf["server"], "172.64.152.23");
        assert_eq!(conf["server_port"], 443);
        assert_eq!(conf["password"], "humanity");
        assert_eq!(conf["tls"]["enabled"], true);
        assert_eq!(conf["tls"]["server_name"], "www.creationlong.org");
    }

    #[test]
    fn singbox_inject_skip_cert_verify_forces_insecure() {
        let cfg = trojan_ws_tls();
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("172.64.152.23", 443)),
            InjectOptions {
                skip_cert_verify: true,
            },
        )
        .expect("trojan sing-box inject");
        assert_eq!(conf["tls"]["insecure"], true);
    }

    #[test]
    fn singbox_inject_tcp_omits_transport() {
        // Plain TCP is the sing-box default — no transport key, even when a
        // TLS block is present.
        let cfg = config(parse(
            "trojan://humanity@172.64.152.23:443?security=tls&type=tcp&sni=www.creationlong.org",
        ));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("172.64.152.23", 443)),
            InjectOptions::default(),
        )
        .expect("trojan tcp sing-box inject");
        assert_eq!(conf["type"], "trojan");
        assert_eq!(conf["tls"]["enabled"], true);
        assert!(
            conf.get("transport").is_none(),
            "tcp must not emit a transport key: {conf}"
        );
    }
}
