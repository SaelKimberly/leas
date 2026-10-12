//! `WireGuard` (`wireguard://`) URL parsing.
//!
//! # Format
//! ```text
//! wireguard://<percent-encoded(private_key)>@<host>:<port>?<query_params>#<remarks>
//! ```
//!
//! Private key is percent-encoded in userinfo. Server endpoint in host:port.
//! Interface and peer configuration in query parameters.
//!
//! # Query Parameters
//!
//! | Key          | Values              | Purpose                          | Required |
//! |--------------|---------------------|----------------------------------|----------|
//! | `address`    | CIDR notation       | Interface address (e.g., 10.0.0.2/32) | Yes |
//! | `publickey`  | base64 key          | Peer's public key                | Yes      |
//! | `presharedkey`| base64 key         | Pre-shared key                   | No       |
//! | `reserved`   | comma-separated bytes| Reserved bytes (exactly 3)      | No       |
//! | `mtu`        | integer             | Interface MTU                    | No       |
//!
//! # Edge Cases
//! - `publickey` also accepted as `public_key`
//! - `presharedkey` also accepted as `psk`
//! - `reserved` accepts both comma-separated decimals and base64-encoded bytes
//! - All query values are percent-decoded
//! - Default MTU: 1420 (Xray-core)
//! - Default port: 2408 (v2rayN parser), 51820 (`WireGuard` native)
//!
//! # References
//! - v2rayN: `WireguardFmt.cs`
//! - Xray-core: `proxy/wireguard/config.proto`
//! - sing-box: `option/wireguard.go`
//! - wireguard-go: `device/uapi.go`

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
use crate::clash::{ClashProxy, ClashWireGuard};
use crate::proto_spec::ProtoSpecError;
use crate::proto_spec::common::{clash_to_endpoint, host_kind_for};

/// `WireGuard` protocol configuration — the identity payload (sans host/port).
///
/// The endpoint (server host/port) lives in [`EndpointEssentials`] on the
/// [`ParsedProto`] boundary; this struct only carries endpoint-free protocol
/// parameters, so the same config pointed at different servers shares one
/// identity.
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[serde(rename_all = "snake_case")]
pub struct WireguardConfig {
    pub private_key: String,
    #[serde(default, skip_serializing_if = "SecurityConfig::is_empty")]
    pub security: SecurityConfig,
    pub address: TinyText,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub reserved: Option<TinyText>,
    pub mtu: Option<TinyText>,
    /// Persistent keepalive interval in seconds (from Clash format)
    pub persistent_keepalive: Option<u32>,
    /// DNS servers (from Clash format)
    pub dns: Option<Vec<String>>,
    /// Force remote DNS resolution (from Clash format)
    pub remote_dns_resolve: Option<bool>,
    pub remarks: Option<TinyText>,
}

impl WireguardConfig {
    /// Parse a `WireGuard` URL into the parse boundary: [`ParsedProto`] with
    /// the endpoint essentials (host/port) split out and the identity payload
    /// ([`ProtocolEssentials::config`]) holding only endpoint-free protocol
    /// parameters.
    ///
    /// Private key is percent-encoded in userinfo (may contain `+`, `/`, `=`).
    /// `address` and `publickey`/`public_key` are required; `presharedkey`/`psk`
    /// and `reserved` are optional. All query values are percent-decoded.
    pub fn try_parse_proto(raw: &RawUrlX<'_>) -> Result<ParsedProto, ParseError> {
        let private_key = urlencoding::decode(raw.userinfo)
            .map_err(|_| {
                ParseError::InvalidUserInfo("invalid percent-encoding in private_key".into())
            })?
            .into_owned();

        let hostport = raw.hostport.ok_or(ParseError::MissingHost)?;
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

        // address: interface address in CIDR notation (required)
        let address = utils::query_get(&query, "address")
            .ok_or_else(|| ParseError::MissingConf("address".into()))
            .map(TinyText::from)?;

        // publickey/public_key: peer's base64-encoded public key (required)
        let public_key = utils::query_get_multi(&query, &["publickey", "public_key"])
            .ok_or_else(|| ParseError::MissingConf("publickey".into()))
            .map(str::to_string)?;

        // presharedkey/psk: optional pre-shared key
        let preshared_key = utils::query_get_multi(&query, &["presharedkey", "psk"])
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // reserved: 3 bytes, comma-separated decimal or base64
        let reserved = utils::query_get(&query, "reserved").map(TinyText::from);

        // mtu: interface MTU (defaults vary: 1420 Xray, 1280 WireGuard-go)
        let mtu = utils::query_get(&query, "mtu").map(TinyText::from);

        // persistent_keepalive/keepalive: optional keepalive interval
        let persistent_keepalive =
            utils::query_get_multi(&query, &["persistent_keepalive", "keepalive"])
                .and_then(|s| s.parse::<u32>().ok());

        // dns: comma-separated DNS servers
        let dns = utils::query_get(&query, "dns")
            .map(|s| {
                s.split(',')
                    .map(|part| part.trim().to_string())
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<String>>()
            })
            .filter(|v| !v.is_empty());

        // remote_dns_resolve/remote_dns: force remote DNS resolution
        let remote_dns_resolve =
            utils::query_get_multi(&query, &["remote_dns_resolve", "remote_dns"]).and_then(|s| {
                match s.to_lowercase().as_str() {
                    "true" | "1" | "yes" => Some(true),
                    "false" | "0" | "no" => Some(false),
                    _ => None,
                }
            });

        let remarks = utils::decode_fragment(raw)?;

        let config = Self {
            private_key,
            security: SecurityConfig::default(),
            address,
            public_key,
            preshared_key,
            reserved,
            mtu,
            persistent_keepalive,
            dns,
            remote_dns_resolve,
            remarks,
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: ProtocolKind::WireGuard,
                core_type: core_mapping::resolve_core(ProtocolKind::WireGuard, None, None),
                config: ProtocolConfig::Wireguard(config),
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

        let mut parts: Vec<String> = Vec::new();
        parts.push(format!("address={}", urlencoding::encode(&self.address)));
        parts.push(format!(
            "publickey={}",
            urlencoding::encode(&self.public_key)
        ));
        if let Some(v) = &self.preshared_key
            && !v.is_empty()
        {
            parts.push(format!("presharedkey={}", urlencoding::encode(v)));
        }
        if let Some(v) = &self.reserved {
            parts.push(format!("reserved={}", urlencoding::encode(v)));
        }
        if let Some(v) = &self.mtu {
            parts.push(format!("mtu={}", urlencoding::encode(v)));
        }
        if let Some(v) = &self.persistent_keepalive {
            parts.push(format!("persistent_keepalive={v}"));
        }
        if let Some(v) = &self.dns {
            parts.push(format!("dns={}", urlencoding::encode(&v.join(","))));
        }
        if let Some(v) = &self.remote_dns_resolve {
            parts.push(format!("remote_dns_resolve={v}"));
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

        Ok(format!(
            "wireguard://{private_key}@{hostport}{query_string}{fragment}",
            private_key = urlencoding::encode(&self.private_key),
        ))
    }
}

impl WireguardConfig {
    /// Serialize this endpoint-free config plus the endpoint to a Clash proxy
    /// entry. Endpoint host/port are taken from `endpoint`.
    pub fn to_clash_proto(
        &self,
        endpoint: &EndpointEssentials,
    ) -> Result<ClashProxy, ProtoSpecError> {
        let name = self.remarks.as_deref().unwrap_or("").to_string();
        Ok(ClashProxy::Wireguard(ClashWireGuard {
            name,
            server: endpoint.host.clone(),
            port: endpoint.port,
            private_key: self.private_key.clone(),
            public_key: self.public_key.clone(),
            ip: Some(
                self.address
                    .split('/')
                    .next()
                    .unwrap_or(&self.address)
                    .to_string(),
            ),
            ipv6: None,
            pre_shared_key: self.preshared_key.clone(),
            reserved: self.reserved.as_ref().map(std::string::ToString::to_string),
            mtu: self.mtu.as_ref().and_then(|v| v.parse::<u32>().ok()),
            dns: self.dns.clone(),
            persistent_keepalive: self.persistent_keepalive,
        }))
    }

    /// Parse a Clash proxy entry into the parse boundary: `server`/`port`
    /// become the endpoint essentials; the config payload is endpoint-free.
    pub fn try_from_clash_proto(proxy: &ClashProxy) -> Result<ParsedProto, ParseError> {
        match proxy {
            ClashProxy::Wireguard(c) => {
                // ClashWireGuard.ip may not have CIDR suffix; add /32 if missing
                let address =
                    c.ip.as_deref()
                        .map(|ip| {
                            if ip.contains('/') {
                                TinyText::from(ip)
                            } else {
                                TinyText::from(format!("{ip}/32"))
                            }
                        })
                        .unwrap_or_default();

                let config = Self {
                    private_key: c.private_key.clone(),
                    security: SecurityConfig::default(),
                    address,
                    public_key: c.public_key.clone(),
                    preshared_key: c.pre_shared_key.clone(),
                    reserved: c.reserved.clone().map(TinyText::from),
                    mtu: c.mtu.map(|v| TinyText::from(v.to_string())),
                    persistent_keepalive: c.persistent_keepalive,
                    dns: c.dns.clone(),
                    remote_dns_resolve: None,
                    remarks: match c.name.as_str() {
                        "" => None,
                        s => Some(TinyText::from(s)),
                    },
                };
                Ok(ParsedProto {
                    endpoints: vec![clash_to_endpoint(&c.server, c.port)],
                    protocol: ProtocolEssentials {
                        proto_kind: ProtocolKind::WireGuard,
                        core_type: core_mapping::resolve_core(ProtocolKind::WireGuard, None, None),
                        config: ProtocolConfig::Wireguard(config),
                    },
                })
            }
            _ => Err(ParseError::Unknown("expected wireguard clash proxy".into())),
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
impl ProtoSpec for WireguardConfig {
    /// # Errors
    ///
    /// If either the URL is invalid or the external configuration is invalid.
    fn try_parse(raw: &RawUrlX<'_>) -> Result<Self, ParseError> {
        let parsed = Self::try_parse_proto(raw)?;
        match parsed.protocol.config {
            ProtocolConfig::Wireguard(config) => Ok(config),
            // Parser invariant: a wireguard URL always yields a WireguardConfig.
            _ => Err(ParseError::Unknown(
                "wireguard URL parsed to a non-wireguard config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::reconstruct_proto`] with the endpoint.
    fn reconstruct(&self) -> Result<String, ParseError> {
        Err(ParseError::InvalidHost(
            "wireguard config no longer stores host/port; use WireguardConfig::reconstruct_proto(endpoint)"
                .into(),
        ))
    }

    fn schema(&self) -> SchemeX {
        SchemeX::WireGuard
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
            ProtocolConfig::Wireguard(config) => Ok(config),
            _ => Err(ParseError::Unknown(
                "wireguard clash proxy parsed to a non-wireguard config".into(),
            )),
        }
    }

    /// # Errors
    ///
    /// Always — host/port are no longer stored on the config; use
    /// [`Self::to_clash_proto`] with the endpoint.
    fn to_clash(&self) -> Result<ClashProxy, ProtoSpecError> {
        Err(ProtoSpecError::Unsupported(
            "wireguard config no longer stores host/port; use WireguardConfig::to_clash_proto(endpoint)"
                .into(),
        ))
    }
}

/// Per-kind identity tags (see [`super::identity`] for the reserved ranges).
const ID_ADDRESS: u8 = 0x50;
const ID_PUBLIC_KEY: u8 = 0x51;
const ID_RESERVED: u8 = 0x52;
const ID_MTU: u8 = 0x53;
const ID_PERSISTENT_KEEPALIVE: u8 = 0x54;

impl ProtoIdentity for WireguardConfig {
    /// Identity fields: everything that reaches a builder.
    ///
    /// Excluded on purpose: `remarks` (display) and `dns`/`remote_dns_resolve`
    /// (neither core emits a key for them — sing-box-only concepts dropped by
    /// both builders). `reserved` is hashed as its decoded byte form, the only
    /// shape a builder emits (a non-3-byte value is dropped by both cores, so
    /// it is not identity), which also collapses textual aliases. `mtu` elides
    /// the sing-box 1420 default. Credentials: `private_key` and
    /// `preshared_key`; the peer `public_key` is a public server parameter, so
    /// it is a `sig` field.
    fn write_identity(&self, w: &mut IdentityWriter) {
        w.kind("wireguard");
        super::common::write_security(w, &self.security);
        // Endpoint (host/port) intentionally absent from the identity — it
        // lives on the ParsedProto boundary, never in the config payload (T5).
        w.str(ID_ADDRESS, self.address.as_str());
        w.str(ID_PUBLIC_KEY, &self.public_key);
        if let Some(reserved) = &self.reserved
            && let Some(bytes) = parse_reserved_bytes(reserved.as_str())
        {
            w.bytes(ID_RESERVED, &bytes);
        }
        let mtu = self
            .mtu
            .as_ref()
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .map(u64::from);
        w.opt_u64(ID_MTU, mtu, 1420);
        w.present_u64(
            ID_PERSISTENT_KEEPALIVE,
            self.persistent_keepalive.map(u64::from),
        );
        w.cred("private_key", &self.private_key);
        w.cred("preshared_key", self.preshared_key.as_deref().unwrap_or(""));
    }
}

impl InjectToCoreConf for WireguardConfig {
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

impl WireguardConfig {
    /// xray-core outbound for this config. The old builder never constructed
    /// wireguard (it errored as unsupported), so this follows xray-core's
    /// `proxy/wireguard/config.proto` shape: `secretKey`/`address`/`reserved`/
    /// `peers` (+ optional `mtu`). The peer endpoint is `host:port` from
    /// `endpoint` (IPv6 hosts bracketed — xray-core cannot split an
    /// unbracketed `2606:...:2408`).
    ///
    /// `address` (T12 F5: no form source — URL imports always carry it) is
    /// emitted as-is, possibly empty. `reserved` (comma-separated decimals or
    /// base64 in the typed config) is decoded to the byte array xray expects
    /// (required for Cloudflare WARP endpoints) — emitted only when exactly 3
    /// bytes, since xray-core rejects other lengths at config load.
    /// `dns`/`remote_dns_resolve` have no xray outbound key and are dropped
    /// (sing-box-only concepts).
    fn inject_xray(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "wireguard"));
        };
        if self.private_key.trim().is_empty() {
            return Err(SupportError::Config(
                "WireGuard private key is empty; xray-core cannot build the outbound \
                 without a secret key"
                    .to_string(),
            ));
        }
        let security = security_force_insecure(&self.security, opts.skip_cert_verify);
        let stream = to_xray_stream_settings(&security, &TransportConfig::Tcp);
        let mut peer = json!({
            "publicKey": self.public_key,
            "endpoint": wg_endpoint(&ep.host, ep.port),
            "allowedIPs": ["0.0.0.0/0", "::/0"],
        });
        if let Some(psk) = &self.preshared_key {
            peer["preSharedKey"] = json!(psk);
        }
        if let Some(ka) = self.persistent_keepalive {
            peer["keepAlive"] = json!(ka);
        }
        let mut settings = json!({
            "secretKey": self.private_key,
            "address": [self.address.as_str()],
            "peers": [peer],
        });
        if let Some(reserved) = &self.reserved
            && let Some(bytes) = parse_reserved_bytes(reserved.as_str())
        {
            settings["reserved"] = json!(bytes);
        }
        if let Some(mtu) = &self.mtu
            && let Ok(v) = mtu.as_str().parse::<u32>()
        {
            settings["mtu"] = json!(v);
        }
        *core_conf = json!({
            "tag": "proxy",
            "protocol": "wireguard",
            "settings": settings,
        });
        if let Some(ss) = stream {
            core_conf["streamSettings"] = ss;
        }
        Ok(())
    }

    /// sing-box outbound for this config, ported from the old builder's
    /// `Protocol::WireGuard` arm against the vendored sing-box
    /// `WireGuardEndpointOptions`/`WireGuardPeer` structs: `server`/
    /// `server_port` from the endpoint, `address` (interface CIDR list),
    /// `mtu` (typed value or the old 1420 default), `private_key`, one peer
    /// with `address`/`port`/`public_key`/`allowed_ips` (`0.0.0.0/0`),
    /// `pre_shared_key`/`persistent_keepalive_interval` when set. `reserved`
    /// follows the T14 3-byte rule: decoded (comma decimals or base64) and
    /// emitted as the byte array only when EXACTLY 3 bytes — sing-box's
    /// `WireGuardPeer.Reserved []uint8` rejects other lengths. `dns`/
    /// `remote_dns_resolve`/`workers`/`udp_timeout`/`system` have no typed
    /// source or sing-box key here and are dropped.
    fn inject_singbox(
        &self,
        core_conf: &mut Value,
        endpoint: Option<&EndpointEssentials>,
        _opts: InjectOptions,
    ) -> Result<(), SupportError> {
        let Some(ep) = endpoint else {
            return Err(SupportError::MissingField("server", "wireguard"));
        };
        let mtu = self
            .mtu
            .as_ref()
            .and_then(|m| m.as_str().parse::<u32>().ok())
            .unwrap_or(1420);
        let mut peer = json!({
            "address": ep.host,
            "port": ep.port,
            "public_key": self.public_key,
            "allowed_ips": ["0.0.0.0/0"],
        });
        if let Some(psk) = self.preshared_key.as_deref().filter(|s| !s.is_empty()) {
            peer["pre_shared_key"] = json!(psk);
        }
        if let Some(reserved) = &self.reserved
            && let Some(bytes) = parse_reserved_bytes(reserved.as_str())
        {
            peer["reserved"] = json!(bytes);
        }
        if let Some(ka) = self.persistent_keepalive {
            peer["persistent_keepalive_interval"] = json!(ka);
        }
        let out = json!({
            "tag": "proxy",
            "type": "wireguard",
            "server": ep.host,
            "server_port": ep.port,
            "address": self
                .address
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>(),
            "mtu": mtu,
            "private_key": self.private_key,
            "peers": [peer],
        });
        *core_conf = out;
        Ok(())
    }
}

/// Peer endpoint as `host:port`, with IPv6 hosts bracketed (`[2606:...]:2408`)
/// so xray-core's endpoint parser can split them.
fn wg_endpoint(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Decode the typed `reserved` field (comma-separated decimals or base64 per
/// the module doc) into the byte array xray-core's wireguard config expects.
///
/// Returns `None` unless the decoded value is EXACTLY 3 bytes — xray-core
/// rejects any other length at config load
/// (`infra/conf/wireguard.go`: `"reserved" should be empty or 3 bytes`), so a
/// malformed value is skipped rather than hard-failing the whole outbound.
fn parse_reserved_bytes(raw: &str) -> Option<Vec<u8>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // Comma-separated decimals: "236,163,162"
    let bytes = if raw.contains(',') {
        let mut bytes = Vec::new();
        for part in raw.split(',') {
            bytes.push(part.trim().parse::<u8>().ok()?);
        }
        bytes
    } else {
        // Base64-encoded bytes (URL-safe or standard, padded or not)
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(raw)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(raw))
            .ok()?
    };
    (bytes.len() == 3).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::{CoreType, HostKind, ParsedProto, ProtoSpec, ProtocolConfig, ProtocolKind};
    use super::{WireguardConfig, parse_reserved_bytes};
    use crate::urlx::{RawUrlX, SchemeX};
    use rstest::rstest;
    use serde_json::json;

    const WG_URL: &str = "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&presharedkey=&reserved=236%2C163%2C162&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280";

    fn parse(url: &str) -> ParsedProto {
        WireguardConfig::try_parse_proto(&RawUrlX::from(url))
            .unwrap_or_else(|e| panic!("parse failed for {url}: {e}"))
    }

    fn config(parsed: ParsedProto) -> WireguardConfig {
        match parsed.protocol.config {
            ProtocolConfig::Wireguard(c) => c,
            other => panic!("expected WireguardConfig, got {other:?}"),
        }
    }

    /// The identity payload must be endpoint-free: no top-level `host`/`port`
    /// keys in the serialized config.
    fn assert_no_top_level_host_port(cfg: &WireguardConfig) {
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
    fn test_wireguard_basic() {
        let parsed = parse(WG_URL);
        assert_eq!(parsed.endpoints.len(), 1);
        let ep = &parsed.endpoints[0];
        assert_eq!(ep.host, "162.159.192.1");
        assert_eq!(ep.host_type, HostKind::Ipv4);
        assert_eq!(ep.port, 2408);
        assert_eq!(ep.ports, vec![2408]);

        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::WireGuard);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let cfg = config(parsed);
        assert_eq!(cfg.address, "172.16.0.2/32");
        assert_eq!(cfg.mtu.as_deref(), Some("1280"));
        assert_eq!(cfg.remarks, None);
        assert_no_top_level_host_port(&cfg);
    }

    #[test]
    fn test_wireguard_hostname() {
        let url = "wireguard://privatekey==@wg.example.com:51820?address=10.0.0.2%2F32&publickey=serverpubkey==";
        let parsed = parse(url);
        assert_eq!(parsed.endpoints[0].host, "wg.example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 51820);
        let cfg = config(parsed);
        assert_eq!(cfg.address, "10.0.0.2/32");
    }

    #[test]
    fn test_wireguard_missing_address() {
        let url = "wireguard://key@1.2.3.4:51820?publickey=pubkey";
        assert!(WireguardConfig::try_parse_proto(&RawUrlX::from(url)).is_err());
    }

    #[test]
    fn test_wireguard_missing_publickey() {
        let url = "wireguard://key@1.2.3.4:51820?address=10.0.0.1%2F32";
        assert!(WireguardConfig::try_parse_proto(&RawUrlX::from(url)).is_err());
    }

    #[test]
    fn test_wireguard_full() {
        // Full WireGuard with all new fields in query params
        let url = "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&persistent_keepalive=25&dns=1.1.1.1%2C8.8.8.8&remote_dns_resolve=true&presharedkey=psk123&mtu=1280";
        let parsed = parse(url);
        let cfg = config(parsed);
        assert_eq!(cfg.persistent_keepalive, Some(25));
        assert_eq!(
            cfg.dns.as_deref(),
            Some(&["1.1.1.1".to_string(), "8.8.8.8".to_string()][..])
        );
        assert_eq!(cfg.remote_dns_resolve, Some(true));
        assert_eq!(cfg.mtu.as_deref(), Some("1280"));
        assert_eq!(cfg.preshared_key.as_deref(), Some("psk123"));
        assert_no_top_level_host_port(&cfg);
    }

    // ── Identity: endpoint-free uid ───────────────────────────────────────

    #[test]
    fn uid_identical_across_servers_different_across_keys() {
        let url_b = "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@wg.example.com:51820?address=172.16.0.2%2F32&presharedkey=&reserved=236%2C163%2C162&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280";
        let url_c = "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&presharedkey=BBB&reserved=236%2C163%2C162&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280";
        let a = parse(WG_URL);
        let b = parse(url_b);
        let c = parse(url_c);
        assert_eq!(
            a.uid(),
            b.uid(),
            "same protocol on different servers must dedup to one uid"
        );
        assert_ne!(a.uid(), c.uid(), "different preshared_key -> different uid");
        assert_ne!(a.sig(), 0);
    }

    // ── Reconstruct round-trip via endpoint ───────────────────────────────

    #[test]
    fn reconstruct_roundtrip_via_endpoint() {
        assert_reconstruct_roundtrip(WG_URL);
        assert_reconstruct_roundtrip(
            "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&mtu=1280#%40V2rayBaaz",
        );
        assert_reconstruct_roundtrip(
            "wireguard://privatekey==@wg.example.com:51820?address=10.0.0.2%2F32&publickey=serverpubkey==",
        );
    }

    // ── Clash round-trip via *_proto ──────────────────────────────────────

    #[test]
    fn clash_roundtrip_from_url_via_proto() {
        let parsed = parse(WG_URL);
        let endpoint = parsed.endpoints[0].clone();
        let cfg = config(parsed);
        let proxy = cfg.to_clash_proto(&endpoint).expect("to clash");
        let reparsed = WireguardConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(
            reparsed.endpoints[0], endpoint,
            "endpoint round-trips through clash"
        );
        assert_eq!(
            reparsed.protocol.config,
            ProtocolConfig::Wireguard(cfg),
            "config round-trips through clash"
        );
    }

    #[test]
    fn clash_proxy_roundtrip_via_proto() {
        use crate::clash::{ClashProxy, ClashWireGuard};

        let proxy = ClashProxy::Wireguard(ClashWireGuard {
            name: "test".into(),
            server: "wg.example.com".into(),
            port: 51820,
            private_key: "privkey".into(),
            public_key: "pubkey".into(),
            ip: Some("10.0.0.2".into()),
            ipv6: None,
            pre_shared_key: Some("psk".into()),
            reserved: Some("236,163,162".into()),
            mtu: Some(1280),
            dns: Some(vec!["1.1.1.1".into()]),
            persistent_keepalive: Some(25),
        });
        let parsed = WireguardConfig::try_from_clash_proto(&proxy).expect("clash parse");
        assert_eq!(parsed.endpoints[0].host, "wg.example.com");
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Dns);
        assert_eq!(parsed.endpoints[0].port, 51820);
        let cfg = match &parsed.protocol.config {
            ProtocolConfig::Wireguard(c) => c,
            other => panic!("expected WireguardConfig, got {other:?}"),
        };
        // Bare Clash ip without CIDR gets /32 appended.
        assert_eq!(cfg.address, "10.0.0.2/32");
        assert_eq!(cfg.mtu.as_deref(), Some("1280"));
        assert_no_top_level_host_port(cfg);
        let out = cfg.to_clash_proto(&parsed.endpoints[0]).expect("to clash");
        match (out, proxy) {
            (ClashProxy::Wireguard(out), ClashProxy::Wireguard(orig)) => assert_eq!(out, orig),
            _ => panic!("expected wireguard clash proxy"),
        }
    }

    // ── Serde ─────────────────────────────────────────────────────────────

    #[test]
    fn test_serde_roundtrip() {
        let cfg = config(parse(WG_URL));
        let json = serde_json::to_string(&cfg).expect("serialize");
        let deserialized: WireguardConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cfg, deserialized);
        assert_no_top_level_host_port(&deserialized);
    }

    // ── Legacy trait bridge ───────────────────────────────────────────────

    #[test]
    fn legacy_bridge_parse_works_but_reconstruct_to_clash_error() {
        let bridged = WireguardConfig::try_parse(&RawUrlX::from(WG_URL)).expect("bridged parse");
        assert_eq!(bridged.schema(), SchemeX::WireGuard);
        assert_eq!(bridged.address, "172.16.0.2/32");
        // host/port accessors are gone — the endpoint lives on ParsedProto.
        assert_eq!(bridged.host(), None);
        assert_eq!(bridged.port(), None);
        // Degraded legacy paths error instead of fabricating a host.
        assert!(bridged.reconstruct().is_err());
        assert!(bridged.to_clash().is_err());
    }

    // ── Xray inject_to (Task 14) ──────────────────────────────────────────

    use super::super::{EndpointEssentials, InjectOptions, InjectToCoreConf, SupportError};

    #[test]
    fn xray_inject_writes_proxy_outbound() {
        let cfg = config(parse(WG_URL));
        let ep = EndpointEssentials::new("162.159.192.1", 2408);
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&ep),
            InjectOptions::default(),
        )
        .expect("wireguard inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["protocol"], "wireguard");
        let settings = &conf["settings"];
        // secretKey = private key from userinfo
        assert_eq!(
            settings["secretKey"],
            "eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j+wAPSEH4="
        );
        // interface address emitted as-is (URL import carries it)
        assert_eq!(settings["address"], json!(["172.16.0.2/32"]));
        assert_eq!(settings["mtu"], 1280);
        // WARP endpoint — reserved bytes decoded to the array xray needs
        assert_eq!(settings["reserved"], json!([236, 163, 162]));
        let peer = &settings["peers"][0];
        assert_eq!(
            peer["publicKey"],
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        );
        assert_eq!(peer["endpoint"], "162.159.192.1:2408");
        assert_eq!(peer["allowedIPs"], json!(["0.0.0.0/0", "::/0"]));
        // empty presharedkey → preSharedKey omitted
        assert!(peer.get("preSharedKey").is_none());
        assert!(conf.get("streamSettings").is_none());
    }

    #[test]
    fn xray_inject_ipv6_peer_endpoint_is_bracketed() {
        let url =
            "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@[2606:4700:d0::a29f:c001]:2408?address=172.16.0.2%2F32&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D"
                .to_string();
        let cfg = config(parse(&url));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("2606:4700:d0::a29f:c001", 2408)),
            InjectOptions::default(),
        )
        .expect("wireguard inject");
        assert_eq!(
            conf["settings"]["peers"][0]["endpoint"],
            "[2606:4700:d0::a29f:c001]:2408"
        );
    }

    #[test]
    fn parse_reserved_bytes_accepts_decimals_and_base64() {
        assert_eq!(
            parse_reserved_bytes("236,163,162"),
            Some(vec![236, 163, 162])
        );
        assert_eq!(
            parse_reserved_bytes("236, 163, 162"),
            Some(vec![236, 163, 162])
        );
        // base64 of 236,163,162
        assert_eq!(parse_reserved_bytes("7KOi"), Some(vec![236, 163, 162]));
        assert_eq!(parse_reserved_bytes(""), None);
        assert_eq!(parse_reserved_bytes("999"), None);
    }

    #[test]
    fn parse_reserved_bytes_rejects_non_three_byte_values() {
        // xray-core refuses any length other than 0 or 3 at config load
        // ("reserved" should be empty or 3 bytes) — malformed values must be
        // skipped, not emitted.
        assert_eq!(parse_reserved_bytes("1,2"), None);
        assert_eq!(parse_reserved_bytes("1,2,3,4"), None);
        // base64 of [1,2,3,4] (4 bytes)
        assert_eq!(parse_reserved_bytes("AQIDBA"), None);
        // base64 of [1,2] (2 bytes)
        assert_eq!(parse_reserved_bytes("AQI"), None);
    }

    #[test]
    fn xray_inject_skips_malformed_reserved() {
        let url =
            "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&reserved=1%2C2"
                .to_string();
        let cfg = config(parse(&url));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::Xray,
            Some(&EndpointEssentials::new("162.159.192.1", 2408)),
            InjectOptions::default(),
        )
        .expect("wireguard inject");
        assert!(
            conf["settings"].get("reserved").is_none(),
            "2-byte reserved must not be emitted: {}",
            conf["settings"]
        );
    }

    #[test]
    fn xray_inject_without_private_key_is_rejected() {
        let mut cfg = config(parse(WG_URL));
        cfg.private_key = String::new();
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(
                &mut conf,
                CoreType::Xray,
                Some(&EndpointEssentials::new("162.159.192.1", 2408)),
                InjectOptions::default(),
            )
            .expect_err("empty private key must be rejected");
        assert!(
            err.to_string().contains("private key"),
            "error must mention the private key: {err}"
        );
    }

    #[rstest]
    #[case::xray(CoreType::Xray)]
    #[case::singbox(CoreType::SingBox)]
    fn inject_without_endpoint_is_rejected(#[case] core: CoreType) {
        let cfg = config(parse(WG_URL));
        let mut conf = serde_json::json!({});
        let err = cfg
            .inject_to(&mut conf, core, None, InjectOptions::default())
            .expect_err("orphan wireguard must be rejected");
        assert!(matches!(
            err,
            SupportError::MissingField("server", "wireguard")
        ));
    }

    #[test]
    fn singbox_inject_writes_proxy_outbound() {
        let cfg = config(parse(WG_URL));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("162.159.192.1", 2408)),
            InjectOptions::default(),
        )
        .expect("wireguard sing-box inject");
        assert_eq!(conf["tag"], "proxy");
        assert_eq!(conf["type"], "wireguard");
        assert_eq!(conf["server"], "162.159.192.1");
        assert_eq!(conf["server_port"], 2408);
        assert_eq!(
            conf["address"],
            serde_json::json!(["172.16.0.2/32"]),
            "interface address list"
        );
        assert_eq!(conf["mtu"], 1280);
        assert_eq!(
            conf["private_key"],
            "eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j+wAPSEH4="
        );
        let peer = &conf["peers"][0];
        assert_eq!(peer["address"], "162.159.192.1");
        assert_eq!(peer["port"], 2408);
        assert_eq!(
            peer["public_key"],
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        );
        assert_eq!(peer["allowed_ips"], serde_json::json!(["0.0.0.0/0"]));
        // reserved: decoded from "236,163,162" to the 3-byte array.
        assert_eq!(peer["reserved"], serde_json::json!([236, 163, 162]));
    }

    #[test]
    fn singbox_inject_skips_malformed_reserved() {
        // 2-byte reserved -> no reserved key (sing-box rejects non-3-byte).
        let cfg = config(parse(
            "wireguard://eERuOncn22jnY3uYp8WLcy0SCuOkEbSDa0j%2BwAPSEH4%3D@162.159.192.1:2408?address=172.16.0.2%2F32&reserved=1%2C2&publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D",
        ));
        let mut conf = serde_json::json!({});
        cfg.inject_to(
            &mut conf,
            CoreType::SingBox,
            Some(&EndpointEssentials::new("162.159.192.1", 2408)),
            InjectOptions::default(),
        )
        .expect("wireguard sing-box inject");
        assert!(
            conf["peers"][0].get("reserved").is_none(),
            "malformed reserved must be skipped: {conf}"
        );
        assert_eq!(conf["mtu"], 1420, "mtu defaults to 1420 when unset");
    }
}
