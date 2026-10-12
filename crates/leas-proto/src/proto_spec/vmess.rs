//! `VMess` (`vmess://`) URL parsing.
//!
//! # Format
//! ```text
//! vmess://<base64_urlsafe_no_pad(JSON)>
//! ```
//!
//! The base64-decoded payload is JSON with abbreviated 2–3 char field names
//! (v2rayN `VmessQRCode` format). Canonical reference:
//! `thirdparty/v2rayN/ServiceLib/Models/Dto/VmessQRCode.cs`
//!
//! # JSON Fields
//!
//! | Field | Key | Type    | Purpose                         | Default        |
//! |-------|-----|---------|---------------------------------|----------------|
//! | `v`   | `v` | string  | Config version                  | `"2"`          |
//! | `ps`  | `ps`| string  | Remarks (friendly name)         | `""`           |
//! | `add` | `add`| string | Server address (IP or domain)   | — (required)   |
//! | `port`| `port`| int   | Server port                     | — (required)   |
//! | `id`  | `id` | string  | User UUID                       | — (required)   |
//! | `aid` | `aid`| string  | `AlterId` (additional IDs)        | `"0"`          |
//! | `scy` | `scy`| string  | Encryption method               | `"auto"`       |
//! | `net` | `net`| string  | Transport type                  | `"tcp"`        |
//! | `type`| `type`| string | TCP/KCP header / gRPC mode      | `"none"`       |
//! | `host`| `host`| string | Host header / gRPC authority    | `""`           |
//! | `path`| `path`| string | WS path / gRPC serviceName / KCP seed | `""`     |
//! | `tls` | `tls`| string  | TLS: `"tls"` or `""`            | `""`           |
//! | `sni` | `sni`| string  | TLS SNI override                | `""`           |
//! | `alpn`| `alpn`| string | ALPN (comma-separated)          | `""`           |
//! | `fp`  | `fp` | string  | uTLS Client Hello fingerprint   | `""`           |
//!
//! # Security (`scy`)
//! - `auto` — auto-select AES-128-GCM or ChaCha20-Poly1305
//! - `aes-128-gcm`, `chacha20-poly1305`, `none` (deprecated), `zero`
//!
//! # Transport (`net`)
//! `tcp`, `ws`, `kcp`, `grpc`, `http` (→ `h2`), `quic`, `httpupgrade`,
//! `splithttp`/`xhttp`
//!
//! # Edge Cases
//! - Port is stored as string in JSON, coerced to u16
//! - Empty/null fields filtered (scy=auto, net stripped if `"null"`)
//! - Trailing Telegram annotation text/emoji after base64 is stripped
//! - `host` starting with `/` treated as path when path empty (v2rayN compat)
//! - Base64 can be URL-safe or standard, with or without padding
//!
//! # References
//! - Xray-core: `proxy/vmess/`
//! - v2rayN: `VmessQRCode.cs`, `VmessFmt.cs`
//! - sing-box: `option/vmess.go`
//! - outbound: `dialer/v2ray/v2ray.go`
//! - subconverter: `subparser.cpp` `explodeVmessConf()`

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::urlx::{HostSpec, RawUrlX, SchemeX, TinyText};

use super::ProtoIdentity;
use super::common::{
    SecurityConfig, TlsConfig, TlsOpts, TransportConfig, security_force_insecure, to_singbox_tls,
    to_singbox_transport, to_xray_stream_settings, validate_xray_reality, validate_xray_transport,
};
use super::core_mapping;
use super::identity::IdentityWriter;
use super::utils;
use super::{
    CoreType, EndpointEssentials, InjectOptions, InjectToCoreConf, ParseError, ParsedProto,
    ProtoSpec, ProtocolConfig, ProtocolEssentials, ProtocolKind, SupportError,
};
use crate::clash::{ClashProxy, ClashVmess};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{
    clash_alpn_as_str, clash_tls_to_security, clash_to_endpoint, clash_transport_to_transport,
    host_kind_for, security_to_clash_tls, should_skip_endpoint_param, transport_to_clash,
};

/// `VMess` protocol configuration — the identity payload (sans host/port).
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
pub struct VmessConfig {
    pub uuid: String,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub transport: TransportConfig,
    pub alter_id: Option<TinyText>,
    pub path: Option<TinyText>,
    pub remarks: Option<TinyText>,
}

impl VmessConfig {
    /// Parse a `VMess` URL into the parse boundary: [`ParsedProto`] with the
    /// endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// Decodes the base64 userinfo → parses lenient JSON with abbreviated v2rayN keys.
    /// Trailing non-base64 annotation (Telegram emoji, Persian text, etc.) is stripped
    /// by `decode_base64` before JSON parsing. Empty/null string fields are filtered.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        // VMess userinfo is base64-encoded JSON (v2rayN VmessQRCode format).
        // decode_base64 handles trailing annotation text/emoji and stray backticks.
        let decoded = utils::decode_base64(raw.userinfo)
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Vmess))?;

        // Permissive JSON parser handles single-quoted keys, trailing commas, etc.
        let json: serde_json::Value = serde_json::from_slice(decoded.as_slice())
            .map_err(|_| ParseError::InvalidStructure(SchemeX::Vmess))?;

        // "add" — server address (IP or domain), required
        let host_str = json
            .get("add")
            .and_then(|v| v.as_str())
            .ok_or(ParseError::MissingHost)?;
        let host_str = host_str.trim();
        let parsed_host = utils::parse_host(host_str)?;

        // "port" — can be string or number, coerce via coerce_u16
        let port_val = json
            .get("port")
            .ok_or(ParseError::MissingPort)
            .and_then(|v| {
                utils::coerce_u16(v)
                    .ok_or_else(|| ParseError::InvalidPort(format!("cannot parse: {v}").into()))
            })?;

        // Endpoint essentials: host/port live here, never in the config payload.
        let endpoint = EndpointEssentials {
            host: parsed_host.to_str().into_owned(),
            host_type: host_kind_for(&parsed_host),
            port: port_val,
            ports: vec![port_val],
        };

        // "id" — UUID v4 string, required
        let uuid = json
            .get("id")
            .ok_or_else(|| ParseError::MissingConf("id".into()))?
            .as_str()
            .ok_or_else(|| ParseError::InvalidConf("id".into(), "not a string".into()))?
            .to_owned();

        // "net" — transport network type (tcp, ws, kcp, grpc, http/h2, quic, httpupgrade, xhttp/splithttp)
        // Filters empty/null/"null" — absence means tcp
        let net_str = json
            .get("net")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"null")
            .map(String::from);

        // "path" — transport-specific path
        let path = json
            .get("path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(TinyText::from);

        let sni = json
            .get("sni")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(TinyText::from);
        let alpn = json
            .get("alpn")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"\"\"")
            .map(TinyText::from);
        let fp = json
            .get("fp")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(TinyText::from);
        let insecure = json
            .get("insecure")
            .and_then(|v| v.as_str())
            .and_then(|s| match s {
                "1" | "true" | "True" => Some(true),
                "0" | "false" | "False" => Some(false),
                _ => None,
            });
        let tls_str = json
            .get("tls")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"\"\"");

        // scy → security.enc (encryption method)
        let scy = json
            .get("scy")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"null")
            .or(Some("auto"))
            .map(String::from);

        let security = SecurityConfig {
            tls: tls_str.map(|_| {
                TlsConfig::Tls(TlsOpts {
                    pin_sha256: None,
                    sni: sni.clone(),
                    alpn,
                    fp,
                    insecure,
                    ..Default::default()
                })
            }),
            enc: scy.map(|s| crate::urlx::TinyText::from(s.as_str())),
        };

        // "aid" — AlterId (additional IDs), must be 0 for AEAD-only clients
        // Filters empty/escaped-empty/"0" since 0 is the modern AEAD default
        let alter_id = json
            .get("aid")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s != &"\"\"" && s != &"0")
            .map(TinyText::from);

        // "ps" — remarks/friendly name, also strips wrapping quotes
        let remarks = json
            .get("ps")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| TinyText::from(s.trim_matches(['"', '\''])));
        // Build typed TransportConfig from net field
        let mut transport =
            TransportConfig::from_type_and_path(net_str.as_deref(), path.as_deref())?
                .unwrap_or(TransportConfig::Tcp);

        // HOST-FREE PARSE MANDATE (identity invariant): the endpoint host must
        // never leak into the config payload. Only EXPLICIT `host`/`sni` JSON
        // fields are protocol parameters and are stored; `with_host` is called
        // with `None` as the server address, so absent fields leave the
        // ws/grpc/http host fields unset (the builder injects the endpoint
        // host at build time in phase D).
        let vmess_host = json
            .get("host")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from);
        transport = transport.with_host(vmess_host, sni.map(|s| s.to_string()), None);

        // For XHttp: mode comes from VMess JSON `type` field
        if let TransportConfig::XHttp(ref mut xcfg) = transport
            && let Some(mode) = json.get("type").and_then(|v| v.as_str())
        {
            match mode {
                "auto" | "none" | "packet-up" | "stream-up" | "stream-one" => {
                    xcfg.mode = Some(TinyText::from(mode));
                }
                other => {
                    return Err(ParseError::InvalidConf(
                        "type".into(),
                        other.to_string().into(),
                    ));
                }
            }
        }

        // Post-process path: if host starts with "/" and path is empty (v2rayN compat)
        let path = if path.is_none() {
            json.get("host")
                .and_then(|v| v.as_str())
                .filter(|s| s.starts_with('/'))
                .map(TinyText::from)
        } else {
            path
        };

        let config = Self {
            uuid,
            security,
            transport,
            alter_id,
            path,
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::Vmess,
                core_type: core_mapping::resolve_core(ProtocolKind::Vmess, None, None),
                config: ProtocolConfig::Vmess(config),
            },
        })
    }

    /// Rebuild the share URL from this endpoint-free config plus the endpoint
    /// essentials. Endpoint host/port come from `endpoint`; every protocol
    /// parameter (including explicit transport/security host fields) is taken
    /// from the config.
    pub fn reconstruct_proto(&self, endpoint: &EndpointEssentials) -> Result<String, ParseError> {
        use base64::Engine as _;

        let endpoint_host = endpoint.host.as_str();
        let mut map = serde_json::Map::new();
        map.insert(
            "add".into(),
            serde_json::Value::String(endpoint_host.to_string()),
        );
        map.insert(
            "port".into(),
            serde_json::Value::String(endpoint.port.to_string()),
        );
        map.insert("id".into(), serde_json::Value::String(self.uuid.clone()));

        if let Some(TlsConfig::Tls(opts)) = &self.security.tls {
            map.insert("tls".into(), serde_json::Value::String("tls".into()));
            if let Some(ref v) = opts.sni
                && !should_skip_endpoint_param(endpoint_host, v)
            {
                map.insert("sni".into(), serde_json::Value::String(v.to_string()));
            }
            if let Some(ref v) = opts.alpn {
                map.insert("alpn".into(), serde_json::Value::String(v.to_string()));
            }
            if let Some(ref v) = opts.fp {
                map.insert("fp".into(), serde_json::Value::String(v.to_string()));
            }
            if opts.insecure == Some(true) {
                map.insert("insecure".into(), serde_json::Value::String("1".into()));
            }
        }
        if let Some(ref v) = self.security.enc {
            map.insert("scy".into(), serde_json::Value::String(v.to_string()));
        }
        if self.transport.type_str() != "tcp" {
            map.insert(
                "net".into(),
                serde_json::Value::String(self.transport.type_str().to_string()),
            );
        }
        // Emit XHttp/SplitHTTP mode
        if let TransportConfig::XHttp(xcfg) = &self.transport
            && let Some(ref mode) = xcfg.mode
        {
            map.insert("type".into(), serde_json::Value::String(mode.to_string()));
        }
        // Emit transport Host/vhost for CDN-hosted ws/grpc/http transports
        match &self.transport {
            TransportConfig::Ws(cfg) => {
                if let Some(host) = &cfg.host
                    && !should_skip_endpoint_param(endpoint_host, host)
                {
                    map.insert("host".into(), serde_json::Value::String(host.to_string()));
                }
            }
            TransportConfig::Grpc(cfg) => {
                if let Some(auth) = &cfg.authority
                    && !should_skip_endpoint_param(endpoint_host, auth)
                {
                    map.insert("host".into(), serde_json::Value::String(auth.to_string()));
                }
            }
            TransportConfig::Http(cfg) => {
                if let Some(host) = &cfg.host
                    && !should_skip_endpoint_param(endpoint_host, host)
                {
                    map.insert("host".into(), serde_json::Value::String(host.to_string()));
                }
            }
            TransportConfig::HttpUpgrade(cfg) => {
                if let Some(host) = &cfg.host
                    && !should_skip_endpoint_param(endpoint_host, host)
                {
                    map.insert("host".into(), serde_json::Value::String(host.to_string()));
                }
            }
            TransportConfig::XHttp(cfg) => {
                if let Some(host) = &cfg.host
                    && !should_skip_endpoint_param(endpoint_host, host)
                {
                    map.insert("host".into(), serde_json::Value::String(host.to_string()));
                }
            }
            _ => {}
        }
        if let Some(ref v) = self.path {
            map.insert("path".into(), serde_json::Value::String(v.to_string()));
        }
        if let Some(ref v) = self.alter_id {
            map.insert("aid".into(), serde_json::Value::String(v.to_string()));
        }
        if let Some(ref v) = self.remarks {
            map.insert("ps".into(), serde_json::Value::String(v.to_string()));
        }

        let json = serde_json::Value::Object(map);
        let json_str = serde_json::to_string(&json).map_err(|e| ParseError::Unknown(e.into()))?;
        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(json_str.as_bytes());
        Ok(format!("vmess://{encoded}"))
    }
}

impl VmessConfig {
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
        let (network, ws_opts, grpc_opts, h2_opts, http_opts, mkcp_opts) =
            transport_to_clash(&self.transport, None);
        Ok(ClashProxy::Vmess(ClashVmess {
            name,
            server,
            port: endpoint.port,
            uuid: self.uuid.clone(),
            cipher: self
                .security
                .enc
                .as_ref()
                .map_or_else(|| "auto".to_string(), std::string::ToString::to_string),
            alter_id: self.alter_id.as_ref().and_then(|v| v.parse::<u32>().ok()),
            udp: None,
            tfo: None,
            network,
            tls,
            servername,
            skip_cert_verify,
            alpn: alpn_str.map(|s| vec![s]),
            fingerprint,
            ws_opts,
            grpc_opts,
            h2_opts,
            http_opts,
            mkcp_opts,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    /// Explicit Clash TLS `servername` and ws `Host` header fields are
    /// protocol parameters and stay in the config.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Vmess(c) => {
                let security = {
                    let mut s = clash_tls_to_security(
                        c.tls,
                        c.servername.as_deref(),
                        c.skip_cert_verify,
                        clash_alpn_as_str(c.alpn.as_ref()),
                        c.fingerprint.as_deref(),
                        None,
                    );
                    s.enc = Some(TinyText::from(c.cipher.as_str()));
                    s
                };
                // HOST-FREE: the endpoint server is never copied into
                // transport host fields (`server = None`).
                let transport = clash_transport_to_transport(
                    c.network.as_deref(),
                    c.ws_opts.as_ref(),
                    c.grpc_opts.as_ref(),
                    c.h2_opts.as_ref(),
                    c.http_opts.as_ref(),
                    c.mkcp_opts.as_ref(),
                    None,
                );
                let path = match &transport {
                    TransportConfig::Ws(ws) => ws.path.clone(),
                    TransportConfig::Grpc(g) => g.path.clone(),
                    TransportConfig::Http(h) => h.path.clone(),
                    TransportConfig::HttpUpgrade(cfg) => cfg.path.clone(),
                    TransportConfig::XHttp(cfg) => cfg.path.clone(),
                    _ => None,
                };
                let config = Self {
                    uuid: c.uuid.clone(),
                    security,
                    transport,
                    alter_id: c.alter_id.map(|v| TinyText::from(v.to_string())),
                    path,
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind: ProtocolKind::Vmess,
                        core_type: core_mapping::resolve_core(ProtocolKind::Vmess, None, None),
                        config: ProtocolConfig::Vmess(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected vmess clash proxy".into())),
        }
    }
}

/// Legacy [`ProtoSpec`] bridge — kept so `ProtocolConfig` dispatch (and the
/// other 18 configs) compile unchanged.
///
/// DEGRADED PATH (documented): `try_parse`/`try_from_clash` still work by
/// delegating to the `*_proto` variants and discarding the parsed endpoints;
/// `to_clash`/`reconstruct` return errors because the config no longer stores
/// host/port. Import/export rewires to the `*_proto` variants in T11 (phase D
/// builders take the endpoint separately).
impl ProtoSpec for VmessConfig {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::Vmess(config) => Ok(config),
            // Parser invariant: a vmess URL always yields a VmessConfig.
            _ => Err(ParseError::Unknown(
                "vmess URL parsed to a non-vmess config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "vmess config no longer stores host/port; use VmessConfig::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::Vmess
    }

    /// `None` — the endpoint host moved to [`EndpointEssentials`] (T4).
    fn host(&self) -> Option<&HostSpec> {
        None
    }

    /// `None` — the endpoint port moved to [`EndpointEssentials`] (T4).
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
            ProtocolConfig::Vmess(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "vmess clash proxy parsed to a non-vmess config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "vmess config no longer stores host/port; use VmessConfig::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

/// Per-kind identity tags (see [`super::identity`] for the reserved ranges).
const ID_ALTER_ID: u8 = 0x50;

impl ProtoIdentity for VmessConfig {
    /// Identity fields: everything a builder or the native client reads.
    ///
    /// Excluded on purpose: `remarks` (display) and `path` (a mirror of the
    /// transport's own path, which `write_transport` already covers).
    /// Credential: `uuid`.
    ///
    /// `security.enc` is the payload-security method (`scy`). Both cores fall
    /// back to `"auto"` when it is absent and the parser always materializes
    /// it, so the default is normalized away before `write_security` — an
    /// explicit `scy=auto` must not split from the absent form.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("vmess");
        let normalized;
        let security = if self.security.enc.as_deref() == Some("auto") {
            normalized = SecurityConfig {
                tls: self.security.tls.clone(),
                enc: None,
            };
            &normalized
        } else {
            &self.security
        };
        super::common::write_security(w, security);
        super::common::write_transport(w, &self.transport);
        // A non-zero `alter_id` selects the legacy pre-AEAD session scheme the
        // native client never implemented, so it changes what a consumer does;
        // absent, empty and `"0"` are all the AEAD default.
        w.opt_str(
            ID_ALTER_ID,
            self.alter_id.as_deref().filter(|v| !v.is_empty()),
            "0",
        );
        w.cred("uuid", &self.uuid);
    }
}

impl InjectToCoreConf for VmessConfig {
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

impl VmessConfig {
    /// xray-core outbound for this config, ported field-by-field from the old
    /// xray builder's `Protocol::Vmess` arm. The user's `security` is the
    /// vmess encryption method (`scy`, default "auto"); transport host left
    /// unset by the host-free parse mandate is filled at build time via
    /// `TransportConfig::with_host` (never mutating the stored config).
    fn inject_xray(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "vmess"));
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
        let enc = self.security.enc.as_deref().unwrap_or("auto");
        *core_conf = json!({
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": ep.host,
                    "port": ep.port,
                    "users": [{
                        "id": self.uuid,
                        "security": enc
                    }]
                }]
            },
        });
        if let Some(ss) = stream {
            core_conf["streamSettings"] = ss;
        }
        Ok(())
    }

    /// sing-box outbound for this config, ported field-by-field from the old
    /// builder's `Protocol::Vmess` arm (`uuid` + hard-coded `security`
    /// "auto" — here sourced from the typed `enc`, which the old builder
    /// TODO'd — plus TLS via the shared helper) and the typed `transport`
    /// (sing-box `V2RayTransportOptions`; `kcp`/`xhttp` refuse at build
    /// time). `alter_id` has no sing-box emission (the old builder dropped
    /// it).
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "vmess"));
        };
        let enc = self.security.enc.as_deref().unwrap_or("auto");
        // Transport host left unset by the host-free parse mandate is filled
        // at build time (never mutating the stored config) — same rule as the
        // xray arm.
        let transport = self
            .transport
            .clone()
            .with_host(Some(ep.host.clone()), None, None);
        let mut out = json!({
            "tag": "proxy",
            "type": "vmess",
            "server": ep.host,
            "server_port": ep.port,
            "uuid": self.uuid,
            "security": enc,
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
    use base64::Engine as _;

    use super::super::{CoreType, HostKind, ParsedProto, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::VmessConfig;
    use crate::proto_spec::common::TransportConfig;
    use crate::urlx::{RawUrlX, SchemeX};
    use rstest::rstest;

    const UUID: &str = "9b4c2eda-341e-488f-a3b2-1dc716b9f36a";
    const BASIC_B64: &str = "eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJpbnNlY3VyZSI6IjEiLCJuZXQiOiJ3cyIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6IkBDbG91ZENpdHl5Iiwic2N5IjoiYXV0byIsInNuaSI6InN0ZWFtLmF2YWFhYWwuaXIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiLS0tIiwidiI6IjIifQ==";

    fn vmess_url(server: &str, port: u16, id: &str, extra: &[(&str, &str)]) -> String {
        use base64::Engine as _;
        let mut map = serde_json::Map::new();
        map.insert("v".into(), serde_json::json!("2"));
        map.insert("add".into(), serde_json::json!(server));
        map.insert("port".into(), serde_json::json!(port.to_string()));
        map.insert("id".into(), serde_json::json!(id));
        map.insert("aid".into(), serde_json::json!("0"));
        map.insert("scy".into(), serde_json::json!("auto"));
        map.insert("net".into(), serde_json::json!("ws"));
        map.insert("path".into(), serde_json::json!("/"));
        map.insert("tls".into(), serde_json::json!("tls"));
        map.insert("sni".into(), serde_json::json!("test.ir"));
        for (k, v) in extra {
            map.insert((*k).into(), serde_json::json!(v));
        }
        let json = serde_json::Value::Object(map);
        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(json.to_string().as_bytes());
        format!("vmess://{encoded}")
    }

    fn parse(url: &str) -> ParsedProto {
        VmessConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> VmessConfig {
        match parsed.protocol.config {
            ProtocolConfig::Vmess(c) => c,
            other => panic!("expected VmessConfig, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &VmessConfig) {
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
    fn test_vmess_basic() {
        let url = format!("vmess://{BASIC_B64}");
        let parsed = parse(&url);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "192.200.160.16");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 8443);
        assert_eq!(ep.ports, vec![8443]);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Vmess);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let cfg = config(parsed);
        assert_eq!(cfg.uuid, UUID);
        assert_eq!(cfg.transport.type_str(), "ws");
        assert_eq!(cfg.security.type_str(), Some("tls"));
        assert_eq!(cfg.security.sni(), Some("steam.avaaaal.ir"));
        assert_eq!(cfg.security.insecure(), Some(true));
        assert_eq!(cfg.remarks.as_deref(), Some("@CloudCityy"));
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_vmess_endpoint_host_kinds() {
        let dns = parse(&vmess_url("example.com", 443, UUID, &[]));
        assert_eq!(dns.endpoints[0].host, "example.com");
        assert_eq!(dns.endpoints[0].host_type, HostKind::Dns);

        let v6 = parse(&vmess_url("2001:db8::1", 8443, UUID, &[]));
        assert_eq!(v6.endpoints[0].host, "2001:db8::1");
        assert_eq!(v6.endpoints[0].host_type, HostKind::Ipv6);
        assert_eq!(v6.endpoints[0].port, 8443);
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_uuids() {
        let url_a = vmess_url("a.example.com", 443, UUID, &[]);
        let url_b = vmess_url("b.example.com", 8443, UUID, &[]);
        let url_c = vmess_url(
            "a.example.com",
            443,
            "22222222-3333-4444-5555-666666666666",
            &[],
        );
        let a = parse(&url_a);
        let b = parse(&url_b);
        let c = parse(&url_c);
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
        assert_reconstruct_roundtrip(&format!("vmess://{BASIC_B64}"));
        assert_reconstruct_roundtrip(&vmess_url("example.com", 443, UUID, &[]));
        assert_reconstruct_roundtrip(&vmess_url(
            "example.com",
            443,
            UUID,
            &[("host", "cdn.example.com"), ("path", "/ws")],
        ));
    }

    #[test]
    fn explicit_host_param_survives_roundtrip() {
        let url = vmess_url("example.com", 443, UUID, &[("host", "cdn.example.com")]);
        let parsed = parse(&url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        if let TransportConfig::Ws(ws) = &cfg.transport {
            assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
        } else {
            panic!("expected ws transport");
        }
        let out = cfg.reconstruct_proto(&endpoint).expect("reconstruct");
        // The payload is base64 — decode it to inspect the JSON body.
        let payload = out.strip_prefix("vmess://").expect("vmess scheme");
        let decoded = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .expect("decode vmess payload");
        let json: serde_json::Value = serde_json::from_slice(&decoded).expect("vmess json");
        assert_eq!(
            json["host"], "cdn.example.com",
            "reconstruct keeps ws host in: {out}"
        );
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let url = format!("vmess://{BASIC_B64}");
        let parsed = parse(&url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = VmessConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Vmess(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashProxy, ClashVmess, ClashWSOpts};

        let proxy = ClashProxy::Vmess(ClashVmess {
            name: "test".into(),
            server: "example.com".into(),
            port: 443,
            uuid: UUID.into(),
            cipher: "auto".into(),
            alter_id: None,
            udp: None,
            tfo: None,
            network: Some("ws".into()),
            tls: Some(true),
            servername: Some("test.ir".into()),
            skip_cert_verify: Some(true),
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
            h2_opts: None,
            http_opts: None,
            mkcp_opts: None,
        });
        let parsed = VmessConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 443);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Vmess(c) => c,
            other => panic!("expected VmessConfig, got {other:?}"),
        };
        // Explicit Clash ws Host header stays in the config (host-free mandate).
        if let TransportConfig::Ws(ws) = &cfg.transport {
            assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
            assert_eq!(ws.path.as_deref(), Some("/ws"));
        } else {
            panic!("expected ws transport");
        }
        assert_eq!(cfg.security.sni(), Some("test.ir"));
        assert_eq!(cfg.security.insecure(), Some(true));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Vmess(out), ClashProxy::Vmess(orig)) => assert_eq!(out, orig),
            _ => panic!("expected vmess clash proxy"),
        }
    }

    #[test]
    fn clash_roundtrip_via_proto_h2_keeps_config_host_free() {
        use crate::clash::ClashProxy;

        // Regression (F1): the endpoint host must never leak into the identity
        // config via the Clash h2 `host` fallback on export. With no explicit
        // host, the export must not synthesize an h2 host from the endpoint —
        // but a non-empty path must survive the cycle (F3).
        let url = vmess_url(
            "example.com",
            443,
            UUID,
            &[("net", "h2"), ("path", "/foo"), ("sni", "")],
        );
        let parsed = parse(&url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        if let TransportConfig::Http(h) = &cfg.transport {
            assert_eq!(h.host, None, "no explicit host -> config host unset");
            assert_eq!(h.path.as_deref(), Some("/foo"));
        } else {
            panic!("expected http transport");
        }
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        match &proxy {
            ClashProxy::Vmess(v) => match &v.h2_opts {
                Some(opts) => {
                    assert_eq!(
                        opts.host, None,
                        "export must not synthesize an h2 host from the endpoint: {proxy:?}"
                    );
                    assert_eq!(
                        opts.path.as_deref(),
                        Some("/foo"),
                        "h2 path survives export"
                    );
                }
                None => panic!("h2 opts must be emitted for a path-bearing h2 config: {proxy:?}"),
            },
            other => panic!("expected vmess proxy, got {other:?}"),
        }
        let reparsed = VmessConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Vmess(cfg),
            "config must stay endpoint-free through the clash cycle"
        );
    }

    // ── HOST-FREE PARSE MANDATE: no server-address fallback ───────────────

    #[test]
    fn ws_host_param_stored_but_absent_param_stays_unset() {
        // Explicit `host` JSON field is a protocol parameter and IS stored.
        let url = vmess_url("example.com", 443, UUID, &[("host", "cdn.example.com")]);
        let parsed = parse(&url);
        let cfg = config(parsed);
        if let TransportConfig::Ws(ws) = &cfg.transport {
            assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
        } else {
            panic!("expected ws transport");
        }

        // Without `host`/`sni`, the ws host field must be UNSET — never the
        // server (the explicit `sni` param would be stored, but an absent one
        // must not fall back to the endpoint).
        let url = vmess_url("example.com", 443, UUID, &[("sni", "")]);
        let parsed = parse(&url);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        if let TransportConfig::Ws(ws) = &cfg.transport {
            assert_eq!(ws.host, None, "ws host must not fall back to the server");
        } else {
            panic!("expected ws transport");
        }
        // Reconstruct must not invent a `host` field for the absent one.
        let out = cfg.reconstruct_proto(&endpoint).expect("reconstruct");
        let payload = out.strip_prefix("vmess://").expect("vmess scheme");
        let decoded = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .expect("decode vmess payload");
        let json: serde_json::Value = serde_json::from_slice(&decoded).expect("vmess json");
        assert!(
            json.get("host").is_none(),
            "no host field emitted for absent param: {json}"
        );
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn sni_param_stored_but_absent_sni_stays_unset() {
        // Explicit `sni` is a protocol parameter and IS stored.
        let url = vmess_url("example.com", 443, UUID, &[("sni", "cdn.example.com")]);
        let cfg = config(parse(&url));
        assert_eq!(cfg.security.sni(), Some("cdn.example.com"));

        // No `sni`: security must not carry the server as sni.
        let url = vmess_url("example.com", 443, UUID, &[("sni", "")]);
        let cfg = config(parse(&url));
        assert_eq!(
            cfg.security.sni(),
            None,
            "sni must not fall back to the server"
        );
    }

    // ── Transport edge cases ──────────────────────────────────────────────

    #[test]
    fn test_vmess_httpupgrade() {
        let b64 = "eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJob3N0Ijoid3MuZXhhbXBsZS5jb20iLCJpZCI6Ijk5OTk5OTk5LTk5OTktOTk5OS05OTk5LTk5OTk5OTk5OTk5OSIsIm5ldCI6Imh0dHB1cGdyYWRlIiwicGF0aCI6Ii92MnJheSIsInBvcnQiOiI4NDQzIiwicHMiOiJ0ZXN0aHR0cHVwZ3JhZGUiLCJzY3kiOiJhdXRvIiwic25pIjoiIiwidGxzIjoidGxzIiwidHlwZSI6IiIsInYiOiIyIn0=";
        let url = format!("vmess://{b64}");
        let parsed = parse(&url);
        let cfg = config(parsed);
        assert_eq!(cfg.transport.type_str(), "httpupgrade");
        if let TransportConfig::HttpUpgrade(h) = &cfg.transport {
            assert_eq!(h.host.as_deref(), Some("ws.example.com"));
        } else {
            panic!("expected httpupgrade transport");
        }
        assert_reconstruct_roundtrip(&url);
    }

    #[test]
    fn test_vmess_splithttp() {
        let b64 = "eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJob3N0IjoieGh0dHAuZXhhbXBsZS5jb20iLCJpZCI6Ijk5OTk5OTk5LTk5OTktOTk5OS05OTk5LTk5OTk5OTk5OTk5OSIsIm5ldCI6InNwbGl0aHR0cCIsInBhdGgiOiIvIiwicG9ydCI6Ijg0NDMiLCJwcyI6InRlc3R4aHR0cCIsInNjeSI6ImF1dG8iLCJzbmkiOiIiLCJ0bHMiOiJ0bHMiLCJ0eXBlIjoiYXV0byIsInYiOiIyIn0=";
        let url = format!("vmess://{b64}");
        let parsed = parse(&url);
        let cfg = config(parsed);
        assert_eq!(cfg.transport.type_str(), "xhttp");
        if let TransportConfig::XHttp(x) = &cfg.transport {
            assert_eq!(x.mode.as_deref(), Some("auto"));
            assert_eq!(x.host.as_deref(), Some("xhttp.example.com"));
        } else {
            panic!("expected xhttp transport");
        }
        assert_reconstruct_roundtrip(&url);
    }

    #[test]
    fn test_vmess_trailing_annotations() {
        let tcp_b64 = "eyJhZGQiOiIxOTIuMjAwLjE2MC4xNiIsImFpZCI6IjAiLCJob3N0IjoiIiwiaWQiOiI5YjRjMmVkYS0zNDFlLTQ4OGYtYTNiMi0xZGM3MTZiOWYzNmEiLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiLyIsInBvcnQiOiI4NDQzIiwicHMiOiJ0ZXN0Iiwic2N5IjoiYXV0byIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiIiLCJ2IjoiMiJ9";
        // The `Irancell&Mci...` suffix is itself valid base64 text, so it is
        // only stripped when padding marks the end of the real payload.
        let padded = format!("{tcp_b64}=");
        for (b64, suffix) in [
            (tcp_b64, "💛💜test"),
            (tcp_b64, "سرور آلمان"),
            (padded.as_str(), "Irancell&Mciفوروارد فراموش نشه📌"),
        ] {
            let url = format!("vmess://{b64}{suffix}");
            let parsed = parse(&url);
            assert_eq!(parsed.endpoints[0].host, "192.200.160.16");
            assert_eq!(parsed.endpoints[0].port, 8443);
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_vmess_serde_roundtrip() {
        let url = format!("vmess://{BASIC_B64}");
        let parsed = parse(&url);
        let cfg = config(parsed);
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: VmessConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let url = vmess_url("example.com", 443, UUID, &[]);
        // try_parse still extracts the config (endpoints discarded).
        let bridged = VmessConfig::try_parse(&RawUrlX::from(url.as_str())).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::Vmess);
        assert_eq!(bridged.uuid, UUID);
        // host/port accessors are gone — the endpoint lives on ParsedProto.
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        // Degraded legacy paths error instead of fabricating a host.
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    #[test]
    fn legacy_bridge_try_from_clash_extracts_config() {
        use crate::clash::{ClashProxy, ClashVmess};

        let proxy = ClashProxy::Vmess(ClashVmess {
            name: "test".into(),
            server: "example.com".into(),
            port: 443,
            uuid: UUID.into(),
            cipher: "auto".into(),
            alter_id: None,
            udp: None,
            tfo: None,
            network: Some("ws".into()),
            tls: Some(true),
            servername: Some("test.ir".into()),
            skip_cert_verify: None,
            alpn: None,
            fingerprint: None,
            ws_opts: None,
            grpc_opts: None,
            h2_opts: None,
            http_opts: None,
            mkcp_opts: None,
        });
        // try_from_clash delegates to try_from_clash_proto and extracts the
        // config (endpoints discarded).
        let bridged = VmessConfig::try_from_clash(&proxy).expect("bridged clash parse");
        assert_eq!(bridged.uuid, UUID);
        assert_eq!(bridged.security.sni(), Some("test.ir"));
        // host/port accessors are gone even via the bridge.
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
    }

    #[test]
    fn serialized_config_has_no_host_or_port_keys() {
        for url in [
            format!("vmess://{BASIC_B64}"),
            vmess_url("example.com", 443, UUID, &[("host", "cdn.example.com")]),
            vmess_url(
                "example.com",
                443,
                UUID,
                &[("net", "grpc"), ("path", "svc")],
            ),
        ] {
            let cfg = config(parse(&url));
            assert_no_top_level_host_port(&cfg);
        }
    }

    // ── Xray inject_to (Task 14) ──────────────────────────────────────────

    use super::super::{EndpointEssentials, InjectOptions, InjectToCoreConf, SupportError};

    #[test]
    fn xray_inject_writes_proxy_outbound() {
        let cfg = config(parse(&format!("vmess://{BASIC_B64}")));
        let ep = EndpointEssentials::new("192.200.160.16", 8443);
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&ep),
            InjectOptions::default(),
        )
        .expect("vmess inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["protocol"], "vmess");
        let users = &conf["settings"]["vnext"][0]["users"][0];
        assert_eq!(users["id"], UUID);
        // scy=auto → vmess encryption method
        assert_eq!(users["security"], "auto");
        assert_eq!(conf["settings"]["vnext"][0]["address"], "192.200.160.16");
        assert_eq!(conf["settings"]["vnext"][0]["port"], 8443);
        // streamSettings == to_xray_stream_settings output
        let expected = crate::proto_spec::common::to_xray_stream_settings(
            &cfg.security,
            &cfg.transport
                .clone()
                .with_host(Some("192.200.160.16".into()), None, None),
        )
        .expect("ws+tls stream settings");
        assert_eq!(conf["streamSettings"], expected);
        assert_eq!(conf["streamSettings"]["network"], "ws");
        assert_eq!(conf["streamSettings"]["security"], "tls");
    }

    #[test]
    fn xray_inject_explicit_scy_is_emitted() {
        let cfg = config(parse(&vmess_url(
            "example.com",
            443,
            UUID,
            &[("scy", "chacha20-poly1305")],
        )));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("example.com", 443)),
            InjectOptions::default(),
        )
        .expect("vmess inject");
        assert_eq!(
            conf["settings"]["vnext"][0]["users"][0]["security"],
            "chacha20-poly1305"
        );
    }

    #[test]
    fn xray_inject_skip_cert_verify_forces_allow_insecure() {
        let cfg = config(parse(&format!("vmess://{BASIC_B64}")));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("192.200.160.16", 8443)),
            InjectOptions {
                skip_cert_verify: true,
            },
        )
        .expect("vmess inject");
        assert_eq!(conf["streamSettings"]["tlsSettings"]["allowInsecure"], true);
    }

    #[rstest]
    #[case::xray(CoreType::Xray)]
    #[case::singbox(CoreType::SingBox)]
    fn inject_without_endpoint_is_rejected(#[case] core: CoreType) {
        let cfg = config(parse(&format!("vmess://{BASIC_B64}")));
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, core, None, InjectOptions::default())
            .expect_err("orphan vmess must be rejected");
        assert!(matches!(err, SupportError::MissingField("server", "vmess")));
    }

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = config(parse(&format!("vmess://{BASIC_B64}")));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("192.200.160.16", 8443)),
            InjectOptions::default(),
        )
        .expect("vmess sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "vmess");
        assert_eq!(conf["server"], "192.200.160.16");
        assert_eq!(conf["server_port"], 8443);
        assert_eq!(conf["uuid"], UUID);
        // security = typed scy (default "auto").
        assert_eq!(conf["security"], "auto");
        assert_eq!(conf["tls"]["enabled"], true);
        assert_eq!(conf["tls"]["server_name"], "steam.avaaaal.ir");
    }

    #[test]
    fn singbox_inject_skip_cert_verify_forces_insecure() {
        let cfg = config(parse(&format!("vmess://{BASIC_B64}")));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("192.200.160.16", 8443)),
            InjectOptions {
                skip_cert_verify: true,
            },
        )
        .expect("vmess sing-box inject");
        assert_eq!(conf["tls"]["insecure"], true);
    }

    #[test]
    fn singbox_inject_grpc_transport() {
        // grpc service name rides in the share-link `path`; the mapper emits
        // the sing-box V2RayGRPCOptions.service_name.
        let cfg = config(parse(&vmess_url(
            "example.com",
            443,
            UUID,
            &[("net", "grpc"), ("path", "svc")],
        )));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("example.com", 443)),
            InjectOptions::default(),
        )
        .expect("vmess grpc sing-box inject");
        let transport = &conf["transport"];
        assert_eq!(transport["type"], "grpc");
        assert_eq!(transport["service_name"], "svc");
    }
}
