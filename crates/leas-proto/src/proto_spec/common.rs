use crate::clash::{
    ClashGrpcOpts, ClashH2Opts, ClashHttpOpts, ClashKcpOpts, ClashRealityOpts, ClashWSOpts,
};
use crate::proto_spec::{EndpointEssentials, HostKind, ParseError, SupportError};
use serde::{Deserialize, Serialize};

use serde_json::Value;

use crate::urlx::{HostSpec, TinyText};

use super::identity::{IdentityWriter, tag};

/// Clash TLS fields as returned by `security_to_clash_tls`.
type SecurityClashTls = (
    Option<bool>,
    Option<String>,
    Option<bool>,
    Option<String>,
    Option<String>,
);

/// Clash transport fields as returned by `transport_to_clash`.
type TransportClash = (
    Option<String>,
    Option<ClashWSOpts>,
    Option<ClashGrpcOpts>,
    Option<ClashH2Opts>,
    Option<ClashHttpOpts>,
    Option<ClashKcpOpts>,
);

// ========================================
// Transport Configurations
// ========================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportConfig {
    Tcp,
    Ws(WebSocketConfig),
    Grpc(GrpcConfig),
    Http(HttpConfig),
    Quic,
    Kcp(KcpConfig),
    HttpUpgrade(HttpUpgradeConfig),
    XHttp(XHttpConfig),
}

impl TransportConfig {
    #[must_use]
    pub const fn type_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws(_) => "ws",
            Self::Grpc(_) => "grpc",
            Self::Http(_) => "http",
            Self::Quic => "quic",
            Self::Kcp(_) => "kcp",
            Self::HttpUpgrade(_) => "httpupgrade",
            Self::XHttp(_) => "xhttp",
        }
    }

    /// The URI-path field of a transport whose `path` is a request-target, if
    /// any.
    ///
    /// **The one place that decides which transports carry a URI path.**
    /// `Grpc`'s `path` is a service name, and the pathless kinds have none.
    /// Everything that needs that decision goes through here — including the
    /// config-level `path` mirror, which is a URI path exactly when the
    /// transport is one.
    const fn uri_path_mut(&mut self) -> Option<&mut Option<TinyText>> {
        match self {
            Self::Ws(c) => Some(&mut c.path),
            Self::Http(c) => Some(&mut c.path),
            Self::HttpUpgrade(c) => Some(&mut c.path),
            Self::XHttp(c) => Some(&mut c.path),
            Self::Tcp | Self::Grpc(_) | Self::Quic | Self::Kcp(_) => None,
        }
    }

    fn recover_transport_type(input: &str) -> Option<&'static str> {
        // Sorted by length descending, so longest prefix matches first
        const KNOWN: &[&str] = &[
            "httpupgrade",
            "splithttp",
            "websocket",
            "https",
            "xhttp",
            "grpc",
            "http",
            "mkcp",
            "quic",
            "kcp",
            "raw",
            "tcp",
            "h2",
            "ws",
        ];
        let lower = input.to_ascii_lowercase();
        // Exact match (case-insensitive) via eq_ignore_ascii_case
        for &known in KNOWN {
            if known.eq_ignore_ascii_case(input) {
                return Some(known);
            }
        }
        // Longest prefix match
        KNOWN
            .iter()
            .find(|&&known| lower.starts_with(known))
            .copied()
            .map(|v| v as _)
    }

    /// # Errors
    ///
    /// Return `ParseError`, if `protocol_type` is invalid and could not be recovered.
    pub fn from_type_and_path(
        protocol_type: Option<&str>,
        path: Option<&str>,
    ) -> Result<Option<Self>, ParseError> {
        match protocol_type {
            None | Some("") => Ok(None),
            // "auto"/"none" on `net` field are common mistakes from share link
            // generators confusing `net` (transport) with `scy` (security) or
            // `type` (header type). Default to TCP like mihomo does.
            Some("tcp" | "raw" | "auto" | "none") => Ok(Some(Self::Tcp)),
            Some("ws" | "websocket") => Ok(Some(Self::Ws(WebSocketConfig {
                path: path.map(TinyText::from),
                ..WebSocketConfig::default()
            }))),
            Some("grpc") => Ok(Some(Self::Grpc(GrpcConfig {
                path: path.map(TinyText::from),
                ..GrpcConfig::default()
            }))),
            Some("http" | "h2" | "https") => Ok(Some(Self::Http(HttpConfig {
                path: path.map(TinyText::from),
                ..HttpConfig::default()
            }))),
            Some("quic") => Ok(Some(Self::Quic)),
            Some("kcp" | "mkcp") => Ok(Some(Self::Kcp(KcpConfig::default()))),
            Some("httpupgrade") => Ok(Some(Self::HttpUpgrade(HttpUpgradeConfig {
                path: Some(TinyText::from(path.unwrap_or("/"))),
                ..HttpUpgradeConfig::default()
            }))),
            Some("xhttp" | "splithttp") => Ok(Some(Self::XHttp(XHttpConfig {
                path: Some(TinyText::from(path.unwrap_or("/"))),
                mode: Some(TinyText::from("auto")),
                ..XHttpConfig::default()
            }))),

            Some(other) =>  Self::recover_transport_type(other).map_or_else(
                ||Err(ParseError::InvalidConf(
                    "type".into(),
                    other.to_string().into(),
                )), |recovered| {
                    // Per-row parse noise, not a user-visible fault: a
                    // subscription of 25k rows wrote 739 of these lines in one
                    // import (2026-09-15). The recovered value is in the event.
                    tracing::debug!(target: "proto_spec::common", transport = %other, recovered = %recovered, "Recovered transport type");
                    Self::from_type_and_path(Some(recovered), path)
                })

        }
    }

    #[must_use]
    pub fn with_host(
        self,
        host: Option<String>,
        sni: Option<String>,
        server_addr: Option<String>,
    ) -> Self {
        let resolved: Option<TinyText> = host.or(sni).or(server_addr).map(TinyText::from);
        match self {
            Self::Ws(cfg) => Self::Ws(WebSocketConfig {
                host: cfg.host.or(resolved),
                ..cfg
            }),
            Self::Grpc(cfg) => Self::Grpc(GrpcConfig {
                authority: cfg.authority.or(resolved),
                ..cfg
            }),
            Self::Http(cfg) => Self::Http(HttpConfig {
                host: cfg.host.or(resolved),
                ..cfg
            }),
            Self::HttpUpgrade(cfg) => Self::HttpUpgrade(HttpUpgradeConfig {
                host: cfg.host.or(resolved),
                ..cfg
            }),
            Self::XHttp(cfg) => Self::XHttp(XHttpConfig {
                host: cfg.host.or(resolved),
                ..cfg
            }),
            other => other,
        }
    }
    /// Set an HTTP/WS/gRPC authority fallback without replacing an explicit
    /// stored value.
    pub fn set_default_authority(&mut self, value: &str) {
        let value = || Some(TinyText::from(value));
        match self {
            Self::Ws(config) => config.host = config.host.clone().or_else(value),
            Self::Grpc(config) => config.authority = config.authority.clone().or_else(value),
            Self::Http(config) => config.host = config.host.clone().or_else(value),
            Self::HttpUpgrade(config) => config.host = config.host.clone().or_else(value),
            Self::XHttp(config) => config.host = config.host.clone().or_else(value),
            Self::Tcp | Self::Quic | Self::Kcp(_) => {}
        }
    }
}

/// Returns `true` when `value` equals the endpoint host's DNS name
/// (case-insensitive). When the endpoint is an IP address, always returns
/// `false` — sni/host must be emitted because the IP address cannot serve as
/// a TLS SNI/HTTP Host value. Takes the endpoint host *string*, which is all
/// the `*_proto` reconstruct path has (`EndpointEssentials::host`).
pub(crate) fn should_skip_endpoint_param(endpoint_host: &str, value: &str) -> bool {
    if endpoint_host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    endpoint_host.eq_ignore_ascii_case(value)
}

/// Endpoint host kind for a parsed [`HostSpec`] — the rule every URL parser
/// uses: Ipv4/Ipv6 when the host parses as an IP address, Dns otherwise
/// (`Undefined` only when there is no host at all, which vless/vmess never
/// hit).
pub(crate) const fn host_kind_for(host: &HostSpec) -> HostKind {
    match host {
        HostSpec::IpAddress(rustls::pki_types::IpAddr::V4(_)) => HostKind::Ipv4,
        HostSpec::IpAddress(rustls::pki_types::IpAddr::V6(_)) => HostKind::Ipv6,
        _ => HostKind::Dns,
    }
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct WebSocketConfig {
    pub path: Option<TinyText>,
    pub host: Option<TinyText>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub max_early_data: Option<u32>,
    pub early_data_header_name: Option<TinyText>,
    pub v2ray_http_upgrade: Option<bool>,
    pub v2ray_http_upgrade_fast_open: Option<bool>,
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct GrpcConfig {
    pub path: Option<TinyText>,
    pub authority: Option<TinyText>,
    pub service_name: Option<TinyText>,
    pub mode: Option<TinyText>,
    pub user_agent: Option<TinyText>,
    pub ping_interval: Option<u32>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct HttpConfig {
    pub path: Option<TinyText>,
    pub host: Option<TinyText>,
    pub method: Option<TinyText>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub idle_timeout: Option<u32>,
    pub ping_timeout: Option<u32>,
}
/// `HTTPUpgrade` transport config (fake WebSocket upgrade).
///
/// Sends HTTP GET with `Upgrade: websocket` → `101 Switching Protocols`,
/// then pipes raw bytes. No actual WebSocket framing.
///
/// Reference: `thirdparty/Xray-core/transport/internet/httpupgrade/config.proto`
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct HttpUpgradeConfig {
    pub path: Option<TinyText>,
    pub host: Option<TinyText>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub ed: Option<u32>,
}
/// SplitHTTP/XHTTP transport config — full HTTP-based transport.
///
/// Supports 4 modes (`auto`, `packet-up`, `stream-up`, `stream-one`),
/// session-based multiplexing, `XPadding` obfuscation, separate download paths.
/// Extra fields from share link `extra=` JSON blob are stored raw.
///
/// Reference config proto: `thirdparty/Xray-core/transport/internet/splithttp/config.proto`
/// Reference client config: `thirdparty/mihomo/transport/xhttp/config.go`
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct XHttpConfig {
    pub path: Option<TinyText>,
    pub host: Option<TinyText>,
    pub mode: Option<TinyText>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub extra: Option<Value>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct KcpConfig {
    pub mtu: Option<u32>,
    pub tti: Option<u32>,
    pub uplink_capacity: Option<u32>,
    pub downlink_capacity: Option<u32>,
    pub congestion: Option<bool>,
    pub read_buffer: Option<u32>,
    pub write_buffer: Option<u32>,
    pub seed: Option<TinyText>,
    pub header_type: Option<TinyText>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct QuicOpts {
    pub security: Option<TinyText>,
    pub key: Option<TinyText>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    #[serde(flatten)]
    pub tls: Option<TlsConfig>,
    pub enc: Option<TinyText>,
}

impl SecurityConfig {
    #[must_use]
    pub const fn type_str(&self) -> Option<&'static str> {
        match self.tls {
            None => None,
            Some(ref c @ (TlsConfig::Reality(_) | TlsConfig::Tls(_))) => Some(c.type_str()),
        }
    }
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        match self.tls {
            Some(
                TlsConfig::Tls(TlsOpts {
                    sni: Some(ref sni), ..
                })
                | TlsConfig::Reality(RealityOpts {
                    sni: Some(ref sni), ..
                }),
            ) => Some(sni.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub fn alpn(&self) -> Option<&str> {
        if let Some(TlsConfig::Tls(TlsOpts {
            alpn: Some(ref alpn),
            ..
        })) = self.tls
        {
            Some(alpn.as_str())
        } else {
            None
        }
    }

    #[must_use]
    pub fn fp(&self) -> Option<&str> {
        match self.tls {
            Some(
                TlsConfig::Tls(TlsOpts {
                    fp: Some(ref fp), ..
                })
                | TlsConfig::Reality(RealityOpts {
                    fp: Some(ref fp), ..
                }),
            ) => Some(fp.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub const fn insecure(&self) -> Option<bool> {
        if let Some(TlsConfig::Tls(TlsOpts { insecure, .. })) = self.tls {
            insecure
        } else {
            None
        }
    }

    #[must_use]
    pub const fn pbk(&self) -> Option<&str> {
        if let Some(TlsConfig::Reality(RealityOpts {
            pbk: Some(ref pbk), ..
        })) = self.tls
        {
            Some(pbk.as_str())
        } else {
            None
        }
    }

    #[must_use]
    pub fn sid(&self) -> Option<&str> {
        if let Some(TlsConfig::Reality(RealityOpts {
            sid: Some(ref sid), ..
        })) = self.tls
        {
            Some(sid.as_str())
        } else {
            None
        }
    }
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.tls.is_none() && self.enc.is_none()
    }
    /// Set an SNI fallback without replacing an explicitly stored value.
    pub fn set_default_sni(&mut self, value: &str) {
        match &mut self.tls {
            Some(TlsConfig::Tls(opts)) => {
                opts.sni.get_or_insert_with(|| TinyText::from(value));
            }
            Some(TlsConfig::Reality(opts)) => {
                opts.sni.get_or_insert_with(|| TinyText::from(value));
            }
            None => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TlsConfig {
    Tls(TlsOpts),
    Reality(RealityOpts),
}

impl TlsConfig {
    #[must_use]
    pub const fn type_str(&self) -> &'static str {
        match self {
            Self::Tls(_) => "tls",
            Self::Reality(_) => "reality",
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct TlsOpts {
    pub sni: Option<TinyText>,
    pub alpn: Option<TinyText>,
    /// Comma-separated TLS curve preferences (`curvePreferences` mirror);
    /// parsed by [`parse_curve_names`].
    pub curves: Option<TinyText>,
    pub fp: Option<TinyText>,
    pub insecure: Option<bool>,
    pub pqv: Option<TinyText>,
    pub ech: Option<TinyText>,
    pub vcn: Option<bool>,
    pub pcs: Option<TinyText>,
    pub pin_sha256: Option<TinyText>,
}

/// TLS curve IDs (Go `tls.CurveID` / utls hybrid groups) — the wire values
/// the native TLS engine advertises in `supported_groups` / `key_share`.
pub mod curve_id {
    pub const P256: u16 = 23;
    pub const P384: u16 = 24;
    pub const P521: u16 = 25;
    pub const X25519: u16 = 29;
    /// `SecP256r1MLKEM768` hybrid (0x11EB).
    pub const SECP256R1_MLKEM768: u16 = 4587;
    /// `X25519MLKEM768` hybrid (0x11EC) — xray's primary hybrid group.
    pub const X25519_MLKEM768: u16 = 4588;
    /// `SecP384r1MLKEM1024` hybrid (0x11ED).
    pub const SECP384R1_MLKEM1024: u16 = 4589;
}

/// Parse a comma-separated curve-preference list into wire curve IDs — a
/// mirror of xray's `ParseCurveName` (`transport/internet/tls/config.go`).
///
/// The seven known names are matched case-insensitively (`strings.ToLower`);
/// unsupported names are skipped with a warning, never an error.
#[must_use]
pub fn parse_curve_names(names: &str) -> Vec<u16> {
    use curve_id::{
        P256, P384, P521, SECP256R1_MLKEM768, SECP384R1_MLKEM1024, X25519, X25519_MLKEM768,
    };
    names
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|name| {
            let id = match name.to_ascii_lowercase().as_str() {
                "curvep256" => P256,
                "curvep384" => P384,
                "curvep521" => P521,
                "x25519" => X25519,
                "x25519mlkem768" => X25519_MLKEM768,
                "secp256r1mlkem768" => SECP256R1_MLKEM768,
                "secp384r1mlkem1024" => SECP384R1_MLKEM1024,
                other => {
                    tracing::warn!(target: "proto_spec::common", curve = %other, "unsupported curve name");
                    return None;
                }
            };
            Some(id)
        })
        .collect()
}
#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct RealityOpts {
    pub sni: Option<TinyText>,
    pub fp: Option<TinyText>,
    pub pbk: Option<String>,
    pub sid: Option<TinyText>,
    pub spx: Option<TinyText>,
}

/// Convert Clash TLS fields to a `SecurityConfig`.
pub(crate) fn clash_tls_to_security(
    tls: Option<bool>,
    servername: Option<&str>,
    skip_cert_verify: Option<bool>,
    alpn: Option<&str>,
    fingerprint: Option<&str>,
    reality_opts: Option<&ClashRealityOpts>,
) -> SecurityConfig {
    if tls.is_none() || tls == Some(false) {
        return SecurityConfig::default();
    }
    if let Some(r) = reality_opts {
        return SecurityConfig {
            tls: Some(TlsConfig::Reality(RealityOpts {
                sni: servername.map(TinyText::from),
                pbk: r.public_key.clone(),
                sid: r.short_id.clone().map(TinyText::from),
                fp: fingerprint.map(TinyText::from),
                ..RealityOpts::default()
            })),
            enc: None,
        };
    }
    SecurityConfig {
        tls: Some(TlsConfig::Tls(TlsOpts {
            sni: servername.map(TinyText::from),
            insecure: skip_cert_verify,
            alpn: alpn.map(TinyText::from),
            fp: fingerprint.map(TinyText::from),
            ..TlsOpts::default()
        })),
        enc: None,
    }
}

/// Reject a transport xray-core has REMOVED.
///
/// `TransportConfig::Http` reaches `to_xray_stream_settings` as
/// `network: "http"` and `Quic` as `"network": "quic"`, and xray-core 26
/// refuses BOTH at config load — `PrintRemovedFeatureError` returns an error,
/// not a warning (`thirdparty/Xray-core/common/errors/feature_errors.go:25-27`).
/// Verified against the pinned binary:
///
/// ```text
/// network: "http" -> Failed to start: … The feature HTTP transport (without
///                    header padding, etc.) has been removed and migrated to
///                    XHTTP stream-one H2 & H3.
/// network: "quic" -> Failed to start: … The feature QUIC transport (without
///                    web service, etc.) has been removed and migrated to
///                    XHTTP stream-one H3.
/// ```
///
/// So emitting one produced a config the core will not start, for a reason
/// unrelated to the link's quality. Refusing here fails the BUILD with a named
/// reason instead, and the caller can route the link to the native engine
/// (which serves both transports) or sing-box.
///
/// Returns [`SupportError::Config`], the same shape [`validate_xray_reality`]
/// uses for a build-time refusal.
pub(crate) fn validate_xray_transport(transport: &TransportConfig) -> Result<(), SupportError> {
    match transport {
        TransportConfig::Http(_) => Err(SupportError::Config(
            "http/h2 transport has been removed from xray-core (migrated to XHTTP stream-one); \
             this link needs the native engine or sing-box"
                .into(),
        )),
        TransportConfig::Quic => Err(SupportError::Config(
            "quic transport has been removed from xray-core (migrated to XHTTP stream-one H3); \
             this link needs the native engine or sing-box"
                .into(),
        )),
        _ => Ok(()),
    }
}

/// Convert a `SecurityConfig` back to Clash TLS fields.
pub(crate) fn security_to_clash_tls(security: &SecurityConfig) -> SecurityClashTls {
    match &security.tls {
        Some(TlsConfig::Tls(opts)) => (
            Some(true),
            opts.sni.as_ref().map(std::string::ToString::to_string),
            opts.insecure,
            opts.alpn.as_ref().map(std::string::ToString::to_string),
            opts.fp.as_ref().map(std::string::ToString::to_string),
        ),
        Some(TlsConfig::Reality(opts)) => (
            None,
            opts.sni.as_ref().map(std::string::ToString::to_string),
            None,
            None,
            opts.fp.as_ref().map(std::string::ToString::to_string),
        ),
        None => (None, None, None, None, None),
    }
}

/// Convert a `SecurityConfig` to Clash `reality_opts`.
pub(crate) fn security_to_clash_reality(security: &SecurityConfig) -> Option<ClashRealityOpts> {
    match &security.tls {
        Some(TlsConfig::Reality(opts)) => Some(ClashRealityOpts {
            public_key: opts.pbk.clone(),
            short_id: opts.sid.as_ref().map(std::string::ToString::to_string),
            support_x25519mlkem768: None,
        }),
        _ => None,
    }
}

/// Clash `server` string + `port` → [`EndpointEssentials`], using the same
/// host-kind rule as the URL parsers ([`host_kind_for`]). The raw server
/// string is stored verbatim so `to_clash_proto` round-trips it unchanged.
pub(crate) fn clash_to_endpoint(server: &str, port: u16) -> EndpointEssentials {
    let host_type = match server.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => HostKind::Ipv4,
        Ok(std::net::IpAddr::V6(_)) => HostKind::Ipv6,
        Err(_) => HostKind::Dns,
    };
    EndpointEssentials {
        host: server.to_string(),
        host_type,
        port,
        ports: vec![port],
    }
}

/// Convert Clash transport fields to a `TransportConfig`.
pub(crate) fn clash_transport_to_transport(
    network: Option<&str>,
    ws_opts: Option<&ClashWSOpts>,
    grpc_opts: Option<&ClashGrpcOpts>,
    h2_opts: Option<&ClashH2Opts>,
    _http_opts: Option<&ClashHttpOpts>,
    mkcp_opts: Option<&ClashKcpOpts>,
    server: Option<&str>,
) -> TransportConfig {
    match network {
        Some("ws" | "websocket") => {
            let Some(w) = ws_opts else {
                return TransportConfig::Tcp;
            };
            let headers = w.headers.as_ref().and_then(|h| {
                let mut headers = h.clone();
                headers.retain(|key, _| !key.eq_ignore_ascii_case("host"));
                (!headers.is_empty()).then_some(headers)
            });
            TransportConfig::Ws(WebSocketConfig {
                path: w.path.clone().map(TinyText::from),
                // Match the strip above case-insensitively, so a lowercase
                // `host` header key still restores the vhost.
                host: w
                    .headers
                    .as_ref()
                    .and_then(|h| {
                        h.iter()
                            .find(|(key, _)| key.eq_ignore_ascii_case("host"))
                            .map(|(_, value)| value.clone())
                    })
                    .map(TinyText::from),
                headers,
                max_early_data: w.max_early_data,
                early_data_header_name: w.early_data_header_name.clone().map(TinyText::from),
                v2ray_http_upgrade: w.v2ray_http_upgrade,
                v2ray_http_upgrade_fast_open: w.v2ray_http_upgrade_fast_open,
            })
        }
        Some("grpc") => TransportConfig::Grpc(GrpcConfig {
            path: grpc_opts
                .as_ref()
                .and_then(|g| g.grpc_service_name.clone())
                .map(TinyText::from),
            authority: None,
            service_name: grpc_opts
                .as_ref()
                .and_then(|g| g.grpc_service_name.clone())
                .map(TinyText::from),
            mode: None,
            user_agent: grpc_opts
                .as_ref()
                .and_then(|g| g.grpc_user_agent.clone())
                .map(TinyText::from),
            ping_interval: grpc_opts.and_then(|g| g.ping_interval),
        }),
        Some("h2" | "http") => {
            let h = h2_opts;
            TransportConfig::Http(HttpConfig {
                path: h.and_then(|h| h.path.clone()).map(TinyText::from),
                host: h
                    .and_then(|h| {
                        h.host
                            .as_ref()
                            .and_then(|v| v.first())
                            .map(std::string::String::as_str)
                    })
                    .or(server)
                    .map(|s| TinyText::from(s.to_string())),
                method: None,
                headers: None,
                idle_timeout: None,
                ping_timeout: None,
            })
        }
        Some("kcp" | "mkcp") => {
            let Some(k) = mkcp_opts else {
                return TransportConfig::Tcp;
            };
            TransportConfig::Kcp(KcpConfig {
                mtu: k.mtu,
                tti: k.tti,
                uplink_capacity: k.uplink_capacity,
                downlink_capacity: k.downlink_capacity,
                congestion: k.congestion,
                read_buffer: k.read_buffer,
                write_buffer: k.write_buffer,
                seed: k.seed.clone().map(TinyText::from),
                header_type: k.header.clone().map(TinyText::from),
            })
        }
        _ => TransportConfig::Tcp,
    }
}

/// Convert a `TransportConfig` back to Clash transport fields.
///
/// `server` is the OPT-IN fallback for the HTTP/h2 transport's `host` when the
/// config carries no explicit host. The `*_proto` export path passes `None` —
/// the endpoint host must never leak into Clash fields that re-import into the
/// identity-hashed config (host-free parse mandate). Legacy `to_clash` impls
/// (config still stores its host) pass `Some(config_host)` to preserve the
/// historical fallback.
pub(crate) fn transport_to_clash(
    transport: &TransportConfig,
    server: Option<&str>,
) -> TransportClash {
    match transport {
        TransportConfig::Ws(w) => {
            // Clash carries the WS vhost in `headers.Host`; forward `host` so the
            // Clash -> TransportConfig conversion can restore it.
            let mut headers = w.headers.clone().unwrap_or_default();
            if let Some(host) = &w.host {
                headers.insert("Host".to_string(), host.to_string());
            }
            let headers = (!headers.is_empty()).then_some(headers);
            (
                Some("ws".to_string()),
                Some(ClashWSOpts {
                    path: w.path.as_ref().map(std::string::ToString::to_string),
                    headers,
                    max_early_data: w.max_early_data,
                    early_data_header_name: w
                        .early_data_header_name
                        .as_ref()
                        .map(std::string::ToString::to_string),
                    v2ray_http_upgrade: w.v2ray_http_upgrade,
                    v2ray_http_upgrade_fast_open: w.v2ray_http_upgrade_fast_open,
                }),
                None,
                None,
                None,
                None,
            )
        }
        TransportConfig::Grpc(g) => (
            Some("grpc".to_string()),
            None,
            Some(ClashGrpcOpts {
                grpc_service_name: g
                    .service_name
                    .as_ref()
                    .or(g.path.as_ref())
                    .map(std::string::ToString::to_string),
                grpc_user_agent: g.user_agent.as_ref().map(std::string::ToString::to_string),
                ping_interval: g.ping_interval,
                max_concurrent_streams: None,
            }),
            None,
            None,
            None,
        ),
        TransportConfig::Http(h) => {
            // h2 host is emitted ONLY from the config's explicit host, or from
            // the opt-in `server` fallback when the config host is unset. The
            // `*_proto` export path passes `None`, so an unset host stays unset
            // (never the endpoint). The opts block is emitted when either host
            // or path is present, so a host-free h2 config keeps its path.
            let host = h
                .host
                .as_ref()
                .map(std::string::ToString::to_string)
                .or_else(|| server.map(str::to_string));
            let h2_opts = (h.host.is_some() || h.path.is_some()).then(|| ClashH2Opts {
                host: host.map(|host| vec![host]),
                path: h.path.as_ref().map(std::string::ToString::to_string),
            });
            (Some("http".to_string()), None, None, h2_opts, None, None)
        }
        TransportConfig::Kcp(k) => (
            Some("kcp".to_string()),
            None,
            None,
            None,
            None,
            Some(ClashKcpOpts {
                mtu: k.mtu,
                tti: k.tti,
                uplink_capacity: k.uplink_capacity,
                downlink_capacity: k.downlink_capacity,
                congestion: k.congestion,
                write_buffer: k.write_buffer,
                read_buffer: k.read_buffer,
                seed: k.seed.as_ref().map(std::string::ToString::to_string),
                header: k.header_type.as_ref().map(std::string::ToString::to_string),
            }),
        ),
        _ => (None, None, None, None, None, None),
    }
}

/// Write the identity of a [`SecurityConfig`]: TLS/REALITY discriminator (only
/// when present — `security: none` is the default), then each explicit
/// non-default field.
///
/// REALITY `pbk`/`sid`/`spx` are PUBLIC server parameters, so they belong to
/// `sig` (they distinguish servers, not credentials).
pub(crate) fn write_security(w: &mut IdentityWriter, security: &SecurityConfig) {
    #[allow(
        clippy::wildcard_imports,
        reason = "the tag namespace is a flat field-id table; a wildcard keeps the field list readable"
    )]
    use tag::*;
    match &security.tls {
        Some(TlsConfig::Tls(opts)) => {
            w.str(SEC_KIND, "tls");
            w.nonempty_str(SEC_SNI, opts.sni.as_deref());
            w.nonempty_str(SEC_ALPN, opts.alpn.as_deref());
            w.nonempty_str(SEC_FP, opts.fp.as_deref());
            w.opt_flag(SEC_INSECURE, opts.insecure);
            w.nonempty_str(SEC_CURVES, opts.curves.as_deref());
            w.nonempty_str(SEC_PQV, opts.pqv.as_deref());
            w.nonempty_str(SEC_ECH, opts.ech.as_deref());
            w.opt_flag(SEC_VCN, opts.vcn);
            w.nonempty_str(SEC_PCS, opts.pcs.as_deref());
            w.nonempty_str(SEC_PIN_SHA256, opts.pin_sha256.as_deref());
        }
        Some(TlsConfig::Reality(opts)) => {
            w.str(SEC_KIND, "reality");
            w.nonempty_str(SEC_SNI, opts.sni.as_deref());
            w.nonempty_str(SEC_FP, opts.fp.as_deref());
            w.nonempty_str(SEC_PBK, opts.pbk.as_deref());
            w.nonempty_str(SEC_SID, opts.sid.as_deref());
            w.nonempty_str(SEC_SPX, opts.spx.as_deref());
        }
        None => {}
    }
    w.nonempty_str(SEC_ENC, security.enc.as_deref());
}

/// True when a TLS block carries nothing a builder acts on: `None`, or a
/// `Tls` whose optional fields are all absent and whose `insecure` is not
/// forced true. REALITY is never inert.
///
/// The distinction matters only for protocols whose TLS is MANDATORY: their
/// builder emits the same `tls` block for `None` and for such an inert block,
/// so identity must not split `security=tls` from an absent `security=`.
#[must_use]
pub(crate) fn tls_block_is_inert(security: &SecurityConfig) -> bool {
    match &security.tls {
        None => true,
        Some(TlsConfig::Tls(o)) => {
            o.sni.is_none()
                && o.alpn.is_none()
                && o.curves.is_none()
                && o.fp.is_none()
                && o.insecure != Some(true)
                && o.pqv.is_none()
                && o.ech.is_none()
                && o.vcn != Some(true)
                && o.pcs.is_none()
                && o.pin_sha256.is_none()
        }
        Some(TlsConfig::Reality(_)) => false,
    }
}

/// [`write_security`] for protocols whose builder ALWAYS emits a TLS block
/// (`tuic`/`hysteria1`/`hysteria2`/`naive`/`anytls`/`shadowtls`): an inert TLS
/// block is elided entirely, so the two spellings of the same mandatory-TLS
/// config share one identity.
pub(crate) fn write_security_mandatory(w: &mut IdentityWriter, security: &SecurityConfig) {
    if tls_block_is_inert(security) {
        w.nonempty_str(tag::SEC_ENC, security.enc.as_deref());
        return;
    }
    write_security(w, security);
}

/// Write the identity of a [`TransportConfig`]: the transport discriminator
/// (only for non-`tcp` — `tcp` is the default) followed by every explicit
/// field of that variant.
///
/// The field set mirrors what the builders can emit (`to_xray_stream_settings`
/// / `to_singbox_transport`): a field no builder reads is not identity.
pub(crate) fn write_transport(w: &mut IdentityWriter, transport: &TransportConfig) {
    #[allow(
        clippy::wildcard_imports,
        reason = "the tag namespace is a flat field-id table; a wildcard keeps the field list readable"
    )]
    use tag::*;
    match transport {
        TransportConfig::Tcp => {}
        TransportConfig::Ws(cfg) => {
            w.str(TR_KIND, "ws");
            w.opt_str(TR_PATH, cfg.path.as_deref(), "/");
            w.nonempty_str(TR_HOST, cfg.host.as_deref());
            if let Some(headers) = &cfg.headers {
                w.map_str(TR_HEADERS, headers);
            }
            w.present_u64(TR_MAX_EARLY_DATA, cfg.max_early_data.map(u64::from));
            w.nonempty_str(TR_EARLY_DATA_HEADER, cfg.early_data_header_name.as_deref());
            w.opt_flag(TR_V2RAY_UPGRADE, cfg.v2ray_http_upgrade);
            w.opt_flag(TR_V2RAY_UPGRADE_FAST_OPEN, cfg.v2ray_http_upgrade_fast_open);
        }
        TransportConfig::Grpc(cfg) => {
            w.str(TR_KIND, "grpc");
            w.present_str(TR_PATH, cfg.path.as_deref());
            w.nonempty_str(TR_AUTHORITY, cfg.authority.as_deref());
            w.nonempty_str(TR_SERVICE_NAME, cfg.service_name.as_deref());
            w.nonempty_str(TR_MODE, cfg.mode.as_deref());
            w.nonempty_str(TR_USER_AGENT, cfg.user_agent.as_deref());
            w.present_u64(TR_PING_INTERVAL, cfg.ping_interval.map(u64::from));
        }
        TransportConfig::Http(cfg) => {
            w.str(TR_KIND, "http");
            w.present_str(TR_PATH, cfg.path.as_deref());
            w.nonempty_str(TR_HOST, cfg.host.as_deref());
            w.nonempty_str(TR_METHOD, cfg.method.as_deref());
            if let Some(headers) = &cfg.headers {
                w.map_str(TR_HEADERS, headers);
            }
            w.present_u64(TR_IDLE_TIMEOUT, cfg.idle_timeout.map(u64::from));
            w.present_u64(TR_PING_TIMEOUT, cfg.ping_timeout.map(u64::from));
        }
        TransportConfig::HttpUpgrade(cfg) => {
            w.str(TR_KIND, "httpupgrade");
            w.present_str(TR_PATH, cfg.path.as_deref());
            w.nonempty_str(TR_HOST, cfg.host.as_deref());
            if let Some(headers) = &cfg.headers {
                w.map_str(TR_HEADERS, headers);
            }
            w.present_u64(TR_ED, cfg.ed.map(u64::from));
        }
        TransportConfig::XHttp(cfg) => {
            w.str(TR_KIND, "xhttp");
            w.present_str(TR_PATH, cfg.path.as_deref());
            w.nonempty_str(TR_HOST, cfg.host.as_deref());
            w.nonempty_str(TR_MODE, cfg.mode.as_deref());
            if let Some(headers) = &cfg.headers {
                w.map_str(TR_HEADERS, headers);
            }
            if let Some(extra) = &cfg.extra {
                w.json(TR_EXTRA, extra);
            }
        }
        TransportConfig::Kcp(cfg) => {
            w.str(TR_KIND, "kcp");
            w.opt_u64(TR_MTU, cfg.mtu.map(u64::from), 1350);
            w.opt_u64(TR_TTI, cfg.tti.map(u64::from), 20);
            w.present_u64(TR_UPLINK_CAPACITY, cfg.uplink_capacity.map(u64::from));
            w.present_u64(TR_DOWNLINK_CAPACITY, cfg.downlink_capacity.map(u64::from));
            w.opt_flag(TR_CONGESTION, cfg.congestion);
            w.present_u64(TR_READ_BUFFER, cfg.read_buffer.map(u64::from));
            w.present_u64(TR_WRITE_BUFFER, cfg.write_buffer.map(u64::from));
            w.nonempty_str(TR_SEED, cfg.seed.as_deref());
            w.opt_str(TR_HEADER_TYPE, cfg.header_type.as_deref(), "none");
        }
        TransportConfig::Quic => w.str(TR_KIND, "quic"),
    }
}

/// Convert a Clash ALPN (Option<Vec<String>>) to Option<&str> for `clash_tls_to_security`.
pub(crate) fn clash_alpn_as_str(alpn: Option<&Vec<String>>) -> Option<&str> {
    alpn.and_then(|v| v.first())
        .map(std::string::String::as_str)
}

/// Build xray-core `streamSettings` JSON from typed security + transport.
/// Returns `None` when there is nothing to emit (tcp + no TLS).
pub fn to_xray_stream_settings(
    security: &SecurityConfig,
    transport: &TransportConfig,
) -> Option<serde_json::Value> {
    let mut ss = serde_json::Map::new();
    // Xray-core calls the XHttp transport "splithttp" (its proto/config name);
    // `type_str()` returns "xhttp" which xray-core does not recognize as a
    // network.
    let network = if matches!(transport, TransportConfig::XHttp(_)) {
        "splithttp"
    } else {
        transport.type_str()
    };
    if network != "tcp" {
        ss.insert(
            "network".into(),
            serde_json::Value::String(network.to_string()),
        );
    }
    match &security.tls {
        Some(TlsConfig::Tls(opts)) => {
            ss.insert("security".into(), serde_json::json!("tls"));
            let mut t = serde_json::Map::new();
            if let Some(sni) = &opts.sni {
                t.insert("serverName".into(), serde_json::json!(sni.as_str()));
            }
            if let Some(insecure) = opts.insecure {
                t.insert("allowInsecure".into(), serde_json::json!(insecure));
            }
            if let Some(fp) = &opts.fp {
                t.insert("fingerprint".into(), serde_json::json!(fp.as_str()));
            }
            if let Some(alpn) = &opts.alpn {
                let list: Vec<&str> = alpn.split(',').map(str::trim).collect();
                t.insert("alpn".into(), serde_json::json!(list));
            }
            if !t.is_empty() {
                ss.insert("tlsSettings".into(), serde_json::Value::Object(t));
            }
        }
        Some(TlsConfig::Reality(opts)) => {
            ss.insert("security".into(), serde_json::json!("reality"));
            let mut r = serde_json::Map::new();
            if let Some(sni) = &opts.sni {
                r.insert("serverName".into(), serde_json::json!(sni.as_str()));
            }
            if let Some(pbk) = &opts.pbk {
                r.insert("publicKey".into(), serde_json::json!(pbk));
            }
            if let Some(sid) = &opts.sid {
                r.insert("shortId".into(), serde_json::json!(sid.as_str()));
            }
            if let Some(spx) = &opts.spx {
                r.insert("spiderX".into(), serde_json::json!(spx.as_str()));
            }
            if let Some(fp) = &opts.fp {
                r.insert("fingerprint".into(), serde_json::json!(fp.as_str()));
            }
            ss.insert("realitySettings".into(), serde_json::Value::Object(r));
        }
        None => {}
    }
    match transport {
        TransportConfig::Ws(cfg) => {
            let mut w = serde_json::Map::new();
            if let Some(p) = &cfg.path {
                // xray's JSON has no `maxEarlyData` key, so the typed size is
                // expressed as the `?ed=NNNN` query its `Build()` reads — a
                // no-op when the path already carries it.
                w.insert(
                    "path".into(),
                    serde_json::json!(ws_path_for_xray(p, cfg.max_early_data)),
                );
            }
            if let Some(h) = &cfg.host {
                // Top-level `host` — xray-core deprecates `headers.Host`
                // ("will be removed soon").
                w.insert("host".into(), serde_json::json!(h.as_str()));
            }
            if !w.is_empty() {
                ss.insert("wsSettings".into(), serde_json::Value::Object(w));
            }
        }
        TransportConfig::Grpc(cfg) => {
            let mut g = serde_json::Map::new();
            if let Some(sn) = &cfg.service_name {
                g.insert("serviceName".into(), serde_json::json!(sn.as_str()));
            }
            if !g.is_empty() {
                ss.insert("grpcSettings".into(), serde_json::Value::Object(g));
            }
        }
        TransportConfig::Http(cfg) => {
            let mut h = serde_json::Map::new();
            if let Some(p) = &cfg.path {
                h.insert("path".into(), serde_json::json!(p.as_str()));
            }
            if let Some(host) = &cfg.host {
                h.insert("host".into(), serde_json::json!([host.as_str()]));
            }
            if !h.is_empty() {
                ss.insert("httpSettings".into(), serde_json::Value::Object(h));
            }
        }
        TransportConfig::HttpUpgrade(cfg) => {
            let mut u = serde_json::Map::new();
            if let Some(p) = &cfg.path {
                u.insert("path".into(), serde_json::json!(p.as_str()));
            }
            if let Some(host) = &cfg.host {
                // httpupgradeSettings.host is a single string (unlike
                // httpSettings.host which is an array).
                u.insert("host".into(), serde_json::json!(host.as_str()));
            }
            if !u.is_empty() {
                ss.insert("httpupgradeSettings".into(), serde_json::Value::Object(u));
            }
        }
        TransportConfig::XHttp(cfg) => {
            let mut x = serde_json::Map::new();
            if let Some(p) = &cfg.path {
                x.insert("path".into(), serde_json::json!(p.as_str()));
            }
            if let Some(host) = &cfg.host {
                x.insert("host".into(), serde_json::json!(host.as_str()));
            }
            if !x.is_empty() {
                ss.insert("splithttpSettings".into(), serde_json::Value::Object(x));
            }
        }
        TransportConfig::Tcp | TransportConfig::Quic | TransportConfig::Kcp(_) => {}
    }
    if ss.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(ss))
    }
}

/// Build-time override copy of `security` for the xray `inject_to` impls:
/// when `skip_cert_verify` is set, TLS `insecure` is forced on (the TUI's
/// "skip cert verify" toggle → `tlsSettings.allowInsecure`). Reality has no
/// insecure knob and is returned unchanged. Never mutates the stored config.
#[must_use]
pub(crate) fn security_force_insecure(
    security: &SecurityConfig,
    skip_cert_verify: bool,
) -> SecurityConfig {
    if !skip_cert_verify {
        return security.clone();
    }
    let mut sec = security.clone();
    if let Some(TlsConfig::Tls(opts)) = &mut sec.tls {
        opts.insecure = Some(true);
    }
    sec
}

/// Build-time reality validation, ported from the old xray builder: a
/// `security: "reality"` stream setting without a usable realitySettings
/// kills the core at startup ("REALITY: Empty \"realitySettings\"" when the
/// object is absent, `empty "password"` when publicKey is missing). Realities
/// need at least the server's public key and an SNI; both are unrecoverable
/// if absent from the profile.
///
/// # Errors
///
/// Returns [`SupportError::Config`] when the security is reality but the
/// reality settings are incomplete.
pub(crate) fn validate_xray_reality(security: &SecurityConfig) -> Result<(), SupportError> {
    if let Some(TlsConfig::Reality(opts)) = &security.tls {
        let has = |v: Option<&str>| v.is_some_and(|s| !s.is_empty());
        if !has(opts.pbk.as_deref()) || !has(opts.sni.as_deref()) {
            return Err(SupportError::Config(
                "REALITY profile is missing required stream settings \
                 (realitySettings.publicKey / serverName); \
                 security is 'reality' but the reality settings are incomplete"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// Build the sing-box `tls` block shared by every TLS-capable outbound,
/// ported field-by-field from the old sing-box builder's `build_tls` onto the
/// typed configs. Returns `None` when the config carries no TLS at all (e.g.
/// `security=none` vless/vmess/trojan, empty shadowtls) — the caller then
/// emits no `tls` key, exactly like the old builder.
///
/// Shape: `{ "enabled": true, "server_name", "insecure"?, "alpn"?,
/// "utls"?, "reality"? }` (sing-box `OutboundTLSOptions`).
///
/// - `server_name` = explicit config sni, falling back to the endpoint host
///   at BUILD time — never stored in the config (host-free parse mandate).
/// - `skip_cert_verify` forces `insecure: true` (old builder:
///   `params.skip_cert_verify || p_settings.insecure`).
/// - `alpn` is the comma-separated list string → array.
/// - `utls` from the config fingerprint.
/// - reality emits `public_key`/`short_id` only when present; the block is
///   dropped when it would carry nothing beyond `enabled`. `spider_x` is
///   deliberately NOT emitted — sing-box's `OutboundRealityOptions` has no
///   such field (xray-only; it must never leak into `short_id`).
#[must_use]
pub(crate) fn to_singbox_tls(
    security: &SecurityConfig,
    endpoint: &EndpointEssentials,
    skip_cert_verify: bool,
) -> Option<serde_json::Value> {
    let tls = security.tls.as_ref()?;
    let mut tls_json = serde_json::Map::new();
    tls_json.insert("enabled".into(), serde_json::json!(true));

    let sni = security.sni().filter(|s| !s.is_empty());
    tls_json.insert(
        "server_name".into(),
        serde_json::json!(sni.unwrap_or(endpoint.host.as_str())),
    );

    let insecure = skip_cert_verify || security.insecure() == Some(true);
    if insecure {
        tls_json.insert("insecure".into(), serde_json::json!(true));
    }

    if let Some(alpn) = security.alpn().filter(|s| !s.is_empty()) {
        let parts: Vec<&str> = alpn
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if !parts.is_empty() {
            tls_json.insert("alpn".into(), serde_json::json!(parts));
        }
    }

    if let Some(fp) = security.fp().filter(|s| !s.is_empty()) {
        tls_json.insert(
            "utls".into(),
            serde_json::json!({ "enabled": true, "fingerprint": fp }),
        );
    }

    if let TlsConfig::Reality(reality) = tls {
        let mut r = serde_json::Map::new();
        r.insert("enabled".into(), serde_json::json!(true));
        if let Some(pbk) = reality.pbk.as_deref().filter(|s| !s.is_empty()) {
            r.insert("public_key".into(), serde_json::json!(pbk));
        }
        if let Some(sid) = reality.sid.as_deref().filter(|s| !s.is_empty()) {
            r.insert("short_id".into(), serde_json::json!(sid));
        }
        // Only add the reality block if it has meaningful content beyond
        // "enabled" (old builder: `if reality.len() > 1`).
        if r.len() > 1 {
            tls_json.insert("reality".into(), serde_json::json!(r));
        }
    }

    Some(serde_json::Value::Object(tls_json))
}

/// Like [`to_singbox_tls`] but always returns a block: for protocols where
/// TLS is mandatory (tuic/hysteria1/hysteria2/naive/anytls) the old builder
/// unconditionally emitted `tls.enabled`, so an empty typed security still
/// yields `{ enabled: true, server_name: <sni or endpoint host> }` (plus any
/// insecure/alpn/utls the config does carry).
#[must_use]
pub(crate) fn to_singbox_tls_or_default(
    security: &SecurityConfig,
    endpoint: &EndpointEssentials,
    skip_cert_verify: bool,
) -> serde_json::Value {
    to_singbox_tls(security, endpoint, skip_cert_verify).unwrap_or_else(|| {
        serde_json::json!({
            "enabled": true,
            "server_name": security
                .sni()
                .filter(|s| !s.is_empty())
                .unwrap_or(endpoint.host.as_str()),
        })
    })
}

/// Build the sing-box `transport` block (`V2RayTransportOptions`) for the
/// vless/vmess/trojan outbounds.
///
/// Shape per `thirdparty/sing-box/option/v2ray_transport.go` +
/// `docs/configuration/shared/v2ray-transport.md`:
///
/// | Typed transport | sing-box emission |
/// |-----------------|--------------------|
/// | `Tcp`           | `None` — tcp is the sing-box default, no `transport` key |
/// | `Ws`            | `{ type: "ws", path, headers: { Host, … }, max_early_data, early_data_header_name }` |
/// | `Grpc`          | `{ type: "grpc", service_name }` (share-link convention: the typed `path` doubles as the service name) |
/// | `Http`          | `{ type: "http", host: [...], path, method, headers }` |
/// | `HttpUpgrade`   | `{ type: "httpupgrade", host, path, headers }` |
/// | `Quic`          | `{ type: "quic" }` |
/// | `Kcp`/`XHttp`   | build-time refusal — not in the vendored sing-box transport set |
///
/// Host-bearing fields come from the (host-injected) transport; callers apply
/// `TransportConfig::with_host(endpoint.host, …)` first so unset host fields
/// filled from the endpoint at build time (host-free parse mandate).
///
/// # Errors
///
/// Returns [`SupportError::Config`] when the transport cannot be mapped to
/// the vendored sing-box transport set (`kcp`/`xhttp`).
pub(crate) fn to_singbox_transport(
    transport: &TransportConfig,
) -> Result<Option<serde_json::Value>, SupportError> {
    let mut obj = serde_json::Map::new();
    match transport {
        TransportConfig::Tcp => return Ok(None),
        TransportConfig::Ws(cfg) => {
            obj.insert("type".into(), serde_json::json!("ws"));
            if let Some(p) = &cfg.path {
                obj.insert("path".into(), serde_json::json!(p.as_str()));
            }
            // sing-box has no top-level ws host field — the vhost goes into
            // the `headers` map (Host header), merged over any extra headers.
            let mut headers = cfg.headers.clone().unwrap_or_default();
            if let Some(h) = &cfg.host {
                headers.insert("Host".to_string(), h.to_string());
            }
            if !headers.is_empty() {
                obj.insert("headers".into(), serde_json::json!(headers));
            }
            if let Some(med) = cfg.max_early_data {
                obj.insert("max_early_data".into(), serde_json::json!(med));
                // The header route is not optional here, and defaulting it in
                // the EMITTER (not only in the hoist) is what covers every
                // source — a Clash import or the Add/Edit form sets the size
                // without a name. Our field is `Option`, so `None` means
                // "unset" and never "explicitly empty": no caller can want the
                // path-append route.
                obj.insert(
                    "early_data_header_name".into(),
                    serde_json::json!(
                        cfg.early_data_header_name
                            .as_deref()
                            .unwrap_or(EARLY_DATA_HEADER)
                    ),
                );
            } else if let Some(name) = &cfg.early_data_header_name {
                obj.insert(
                    "early_data_header_name".into(),
                    serde_json::json!(name.as_str()),
                );
            }
        }
        TransportConfig::Grpc(cfg) => {
            obj.insert("type".into(), serde_json::json!("grpc"));
            // `service_name` for forms-built configs; URL share links carry
            // the service name in `path` (share-link convention).
            if let Some(sn) = cfg.service_name.as_ref().or(cfg.path.as_ref()) {
                obj.insert("service_name".into(), serde_json::json!(sn.as_str()));
            }
        }
        TransportConfig::Http(cfg) => {
            obj.insert("type".into(), serde_json::json!("http"));
            if let Some(host) = &cfg.host {
                obj.insert("host".into(), serde_json::json!([host.as_str()]));
            }
            if let Some(p) = &cfg.path {
                obj.insert("path".into(), serde_json::json!(p.as_str()));
            }
            if let Some(m) = &cfg.method {
                obj.insert("method".into(), serde_json::json!(m.as_str()));
            }
            if let Some(headers) = &cfg.headers
                && !headers.is_empty()
            {
                obj.insert("headers".into(), serde_json::json!(headers));
            }
        }
        TransportConfig::HttpUpgrade(cfg) => {
            obj.insert("type".into(), serde_json::json!("httpupgrade"));
            if let Some(host) = &cfg.host {
                obj.insert("host".into(), serde_json::json!(host.as_str()));
            }
            if let Some(p) = &cfg.path {
                obj.insert("path".into(), serde_json::json!(p.as_str()));
            }
            if let Some(headers) = &cfg.headers
                && !headers.is_empty()
            {
                obj.insert("headers".into(), serde_json::json!(headers));
            }
        }
        TransportConfig::Quic => {
            obj.insert("type".into(), serde_json::json!("quic"));
        }
        TransportConfig::Kcp(_) => {
            return Err(SupportError::Config(
                "kcp transport is not supported by sing-box (no mKCP in the vendored transport set)"
                    .into(),
            ));
        }
        TransportConfig::XHttp(_) => {
            return Err(SupportError::Config(
                "xhttp/splithttp transport is not supported by sing-box (no XHTTP in the vendored transport set)"
                    .into(),
            ));
        }
    }
    Ok(Some(serde_json::Value::Object(obj)))
}

/// The early-data header xray's client sends (`websocket/dialer.go:153`) and the
/// only one its hub reads back (`hub.go:55-58`).
///
/// Pinned rather than left to sing-box's default, which **appends** the payload
/// to the request path (`transport/v2raywebsocket/conn.go:170-175`) — a
/// convention only a sing-box server configured the same way understands, so
/// every other peer sees a mutated path and 404s.
pub(crate) const EARLY_DATA_HEADER: &str = "Sec-WebSocket-Protocol";

/// The `ed` value in a request-target's query, if any.
///
/// xray reads the FIRST `ed` (`url.Values.Get`), so this does too.
fn early_data_from_path(path: &str) -> Option<u32> {
    let (_, query) = path.split_once('?')?;
    query
        .split('&')
        .filter_map(|pair| pair.strip_prefix("ed="))
        .find_map(|v| v.parse::<u32>().ok())
}

/// Hoist the legacy `?ed=NNNN` ws-path query into the typed early-data field.
///
/// Mirrors xray's own `WebSocketConfig::Build`
/// (`thirdparty/Xray-core/infra/conf/transport_method.go:622-651`), which reads
/// `ed` out of the path query into `Config.Ed`.
///
/// **The path is left byte-identical, and the path's query is authoritative.**
/// xray's JSON `WebSocketConfig` (`transport_method.go:611-617`) has exactly
/// five keys — `host`, `path`, `headers`, `acceptProxyProtocol`,
/// `heartbeatPeriod` — and **no `maxEarlyData`**: the query is its only carrier,
/// so removing it would silently drop early data for the xray subprocess. The
/// typed field is the derived mirror: it is what sing-box reads
/// (`max_early_data`), what the native ws will read, and what
/// [`ws_path_for_xray`] re-derives the query from when the path carries none.
///
/// Reading the path rather than only filling an empty field is what keeps the
/// two consistent in every flow: a form that sets both gets the path's value
/// (the one xray honours), and a form that sets only the field keeps it.
pub(crate) fn hoist_early_data(transport: &mut TransportConfig) {
    let TransportConfig::Ws(cfg) = transport else {
        return;
    };
    let Some(path) = cfg.path.as_deref() else {
        return;
    };
    if let Some(ed) = early_data_from_path(path) {
        cfg.max_early_data = Some(ed);
        // Pin the header route. `ed` is xray's convention and xray delivers the
        // payload in `Sec-WebSocket-Protocol` (`websocket/dialer.go:153`),
        // never by rewriting the path. With the name unset, sing-box instead
        // APPENDS the base64 payload to the request path
        // (`transport/v2raywebsocket/conn.go:170-175`) — a convention private to
        // a sing-box server configured the same way (`server.go:75-96`); every
        // other peer sees a mutated path and 404s. Setting the name makes
        // sing-box take its header branch (`conn.go:176-179`, moved into the WS
        // subprotocol at `client.go:92-96`), which is byte-identical to what
        // xray's hub reads.
        if cfg.early_data_header_name.is_none() {
            cfg.early_data_header_name = Some(TinyText::from(EARLY_DATA_HEADER));
        }
    }
}

/// The ws path to **emit to xray**, with the typed early-data size re-derived as
/// the `?ed=NNNN` query its config builder reads.
///
/// A share-URL config already carries the query, so this is a no-op for it. It
/// exists for the cases where `max_early_data` was set with no query to match —
/// a Clash import or the Add/Edit form — which xray's JSON has no other way to
/// express.
fn ws_path_for_xray(path: &str, ed: Option<u32>) -> String {
    let Some(n) = ed else {
        return path.to_owned();
    };
    if early_data_from_path(path).is_some() {
        // The path already carries the carrier xray reads; leave it untouched.
        return path.to_owned();
    }
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}ed={n}")
}

/// Canonicalize a transport's URI path **and** a config's top-level `path`
/// mirror, under the transport's own match.
///
/// vless/vmess/trojan carry the path twice — the transport's (which
/// `write_transport` hashes into the identity) and a top-level mirror
/// (`write_identity` deliberately excludes it, `reconstruct_proto` emits it) —
/// so the two must be canonicalized together or the stored config, its exported
/// share URL and its uid describe different paths.
///
/// The mirror is a URI path exactly when the transport is one, and that is
/// decided by [`TransportConfig::uri_path_mut`] — the single match. A mirror
/// that travelled on its own is how a grpc service name got a leading `/`.
///
/// Idempotent: a canonical path is recognized without allocating.
pub(crate) fn canonicalize_config_paths(
    transport: &mut TransportConfig,
    mirror: &mut Option<TinyText>,
) {
    let Some(path) = transport.uri_path_mut() else {
        return;
    };
    canonicalize_target_opt(path);
    canonicalize_target_opt(mirror);
}

/// Canonicalize an optional stored request-target in place.
///
/// The fast path is the point: a canonical value (`/ws`, `/?ed=2560`, …) is
/// recognized without allocating, so an import pays nothing for the common
/// case. Shared by the transport path AND the config's top-level `path` mirror
/// (vless/vmess/trojan) so the two can never disagree.
pub(crate) fn canonicalize_target_opt(path: &mut Option<TinyText>) {
    let Some(stored) = path.as_deref() else {
        return;
    };
    if is_canonical_request_target(stored) {
        return;
    }
    let canonical = canonical_request_target(stored);
    if canonical != stored {
        *path = Some(TinyText::from(canonical.as_str()));
    }
}

/// True when `stored` is already a canonical request-target, so the caller can
/// skip the decode/encode pass — and its allocations — entirely.
///
/// The rule preserves the query verbatim, so only the path part is inspected.
/// `%` is not a `pchar`, so any escape forces the full pass; likewise a missing
/// leading `/` and any `#`.
fn is_canonical_request_target(stored: &str) -> bool {
    if stored.contains('#') {
        return false;
    }
    let path = stored.split_once('?').map_or(stored, |(p, _)| p);
    path.starts_with('/') && path.bytes().all(is_pchar)
}

/// Canonicalize one stored request-target (spec §4.1).
///
/// The value is a request-target — `path ["?" query]` — so it is split at the
/// FIRST `?` before anything else; everything from a `#` is a fragment, which
/// is not sent (`into_client_request` already behaves this way). The path part
/// gets one extra percent-decode (`RawUrlX::query` already decoded once, so a
/// double-encoded source still carries its escapes here), a leading `/` when
/// missing, and a re-encode to `pchar`. The query rides through verbatim.
fn canonical_request_target(stored: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let target = stored.split('#').next().unwrap_or_default();
    let (path_part, query_part) = target
        .split_once('?')
        .map_or((target, None), |(p, q)| (p, Some(q)));
    // Malformed escapes stay as stored; the encode pass below normalizes them
    // (`%` is not a pchar).
    let path = urlencoding::decode(path_part).map_or_else(|_| path_part.to_owned(), Into::into);
    let mut wire = String::with_capacity(path.len() + 8);
    if !path.starts_with('/') {
        wire.push('/');
    }
    for &b in path.as_bytes() {
        if is_pchar(b) {
            wire.push(char::from(b));
        } else {
            wire.push('%');
            wire.push(char::from(HEX[usize::from(b >> 4)]));
            wire.push(char::from(HEX[usize::from(b & 0x0F)]));
        }
    }
    if let Some(q) = query_part {
        wire.push('?');
        wire.push_str(q);
    }
    wire
}

/// RFC 3986 `pchar`: `unreserved` / `sub-delims` / `:` / `@` / `/`.
const fn is_pchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto_spec::{ProtoSpec, ProtocolConfig, SecurityConfig, VlessConfig};
    use crate::urlx::RawUrlX;

    /// vless/vmess/trojan carry the ws path **twice**: the transport's (which
    /// `write_transport` hashes into the identity) and a top-level mirror that
    /// `reconstruct_proto` EMITS while `write_identity` deliberately excludes.
    /// Canonicalizing one without the other would leave the stored config, its
    /// exported share URL and its uid describing different paths.
    #[test]
    fn canonicalize_transport_paths_covers_the_top_level_mirror() {
        let raw = "%2Ftr%20x";
        let mut config = ProtocolConfig::Vless(VlessConfig {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            uuid_origin: None,
            security: SecurityConfig::default(),
            transport: TransportConfig::Ws(WebSocketConfig {
                path: Some(TinyText::from(raw)),
                ..Default::default()
            }),
            path: Some(TinyText::from(raw)),
            encryption: None,
            flow: None,
            splice: None,
            remarks: None,
            mux: None,
        });
        config.normalize_transport();
        let ProtocolConfig::Vless(c) = &config else {
            unreachable!("built a vless config");
        };
        let transport_path = match &c.transport {
            TransportConfig::Ws(ws) => ws.path.as_deref(),
            other => panic!("expected ws transport, got {other:?}"),
        };
        assert_eq!(transport_path, Some("/tr%20x"));
        assert_eq!(
            c.path.as_deref(),
            Some("/tr%20x"),
            "the mirror must agree with the transport path"
        );
    }

    /// The mirror is a URI path ONLY when the transport is a URI-path kind.
    /// For `Grpc` the top-level `path` is the SERVICE NAME (a real share link
    /// is `?type=grpc&path=svc`, no leading slash), and `reconstruct_proto`
    /// emits `path=` from this mirror — so canonicalizing it would export
    /// `/svc`, and reimporting that hands the transport a different grpc path,
    /// which `write_transport` hashes into a different uid.
    #[test]
    fn canonicalize_transport_paths_leaves_a_non_uri_transport_mirror_alone() {
        let vless = |transport: TransportConfig, mirror: &str| {
            ProtocolConfig::Vless(VlessConfig {
                uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
                uuid_origin: None,
                security: SecurityConfig::default(),
                transport,
                path: Some(TinyText::from(mirror)),
                encryption: None,
                flow: None,
                splice: None,
                remarks: None,
                mux: None,
            })
        };

        // grpc: the mirror IS the service name.
        let mut grpc = vless(
            TransportConfig::Grpc(GrpcConfig {
                service_name: Some(TinyText::from("svc")),
                path: Some(TinyText::from("svc")),
                ..Default::default()
            }),
            "svc",
        );
        let before = grpc.clone();
        grpc.normalize_transport();
        assert_eq!(grpc, before, "a grpc service name must not move");
        // The export shape, pinned: `reconstruct_proto` emits `path=` from the
        // mirror, so an unchanged mirror is what keeps export → reimport
        // identity-stable.
        let endpoint = EndpointEssentials::new("example.com", 443);
        let ProtocolConfig::Vless(c) = &grpc else {
            unreachable!("built a vless config");
        };
        let url = c
            .reconstruct_proto(&endpoint)
            .expect("grpc config reconstructs");
        assert!(url.contains("path=svc"), "exported mirror stays raw: {url}");
        assert!(!url.contains("%2Fsvc"), "no leading slash was added: {url}");

        // A pathless transport with a mirror (vmess's legacy host-as-path form):
        // not a URI path either, so it is left as stored.
        let mut tcp = vless(TransportConfig::Tcp, "foo");
        tcp.normalize_transport();
        let ProtocolConfig::Vless(c) = &tcp else {
            unreachable!("built a vless config");
        };
        assert_eq!(c.path.as_deref(), Some("foo"));
    }

    /// A `#` begins a fragment: it is not part of a request-target and is
    /// dropped by the rule, exactly as `into_client_request` does today.
    #[test]
    fn ws_path_canonicalization_drops_a_fragment() {
        assert_eq!(canon("/a#frag").as_deref(), Some("/a"));
        assert_eq!(canon("/a/b#f").as_deref(), Some("/a/b"));
        assert_eq!(canon("/a?x=1#f").as_deref(), Some("/a?x=1"));
    }

    /// The legacy `?ed=NNNN` ws-path query is hoisted into the typed field
    /// (xray's own `WebSocketConfig::Build` shape) — and the path stays
    /// **byte-identical**, because xray's JSON has no `maxEarlyData` key and the
    /// query is its only carrier.
    #[test]
    fn hoist_early_data_fills_the_field_and_leaves_the_path_alone() {
        let mut t = TransportConfig::Ws(WebSocketConfig {
            path: Some(TinyText::from("/ws?ed=2560")),
            ..Default::default()
        });
        hoist_early_data(&mut t);
        let TransportConfig::Ws(c) = &t else {
            unreachable!("built a ws transport");
        };
        assert_eq!(c.max_early_data, Some(2560));
        assert_eq!(
            c.early_data_header_name.as_deref(),
            Some("Sec-WebSocket-Protocol"),
            "the header route is pinned, so sing-box does not rewrite the path"
        );
        assert_eq!(
            c.path.as_deref(),
            Some("/ws?ed=2560"),
            "the path keeps the carrier xray reads"
        );

        // An explicit header name is respected (the Clash/form case).
        let mut t = TransportConfig::Ws(WebSocketConfig {
            path: Some(TinyText::from("/ws?ed=2560")),
            early_data_header_name: Some(TinyText::from("X-Custom-Early")),
            ..Default::default()
        });
        hoist_early_data(&mut t);
        let TransportConfig::Ws(c) = &t else {
            unreachable!("built a ws transport");
        };
        assert_eq!(c.early_data_header_name.as_deref(), Some("X-Custom-Early"));

        // The path's query is authoritative when present: it is what xray's
        // `Build()` reads, so a form that sets both cannot make them disagree.
        let mut t = TransportConfig::Ws(WebSocketConfig {
            path: Some(TinyText::from("/ws?ed=2048")),
            max_early_data: Some(9999),
            ..Default::default()
        });
        hoist_early_data(&mut t);
        let TransportConfig::Ws(c) = &t else {
            unreachable!("built a ws transport");
        };
        assert_eq!(c.max_early_data, Some(2048));

        // No query: an explicit field is kept as-is (the Clash/form case).
        let mut t = TransportConfig::Ws(WebSocketConfig {
            path: Some(TinyText::from("/ws")),
            max_early_data: Some(512),
            ..Default::default()
        });
        hoist_early_data(&mut t);
        let TransportConfig::Ws(c) = &t else {
            unreachable!("built a ws transport");
        };
        assert_eq!(c.max_early_data, Some(512));

        // Not a ws transport: untouched.
        let mut t = TransportConfig::Tcp;
        hoist_early_data(&mut t);
        assert_eq!(t, TransportConfig::Tcp);
    }

    /// The xray emitter re-derives the carrier **only** when the path has none,
    /// so a share-URL config's path comes back byte-identical (no double `ed`).
    #[test]
    fn xray_ws_path_carries_the_early_data_only_when_it_must() {
        assert_eq!(ws_path_for_xray("/ws?ed=2560", Some(2560)), "/ws?ed=2560");
        assert_eq!(ws_path_for_xray("/ws", Some(2048)), "/ws?ed=2048");
        assert_eq!(ws_path_for_xray("/ws?a=1", Some(2048)), "/ws?a=1&ed=2048");
        assert_eq!(ws_path_for_xray("/ws", None), "/ws");
    }

    /// End to end through the emitters, on the shape production builds: a
    /// share-URL path carrying `ed`, put through the hoist.
    #[test]
    fn the_early_data_size_reaches_both_core_configs() {
        let mut transport = TransportConfig::Ws(WebSocketConfig {
            path: Some(TinyText::from("/ws?ed=2048")),
            ..Default::default()
        });
        hoist_early_data(&mut transport);

        // xray: the path keeps the carrier its `Build()` hoists; there is no
        // `maxEarlyData` key to emit.
        let ss = to_xray_stream_settings(&SecurityConfig::default(), &transport)
            .expect("a ws transport emits streamSettings");
        assert_eq!(ss["wsSettings"]["path"], "/ws?ed=2048");

        // sing-box: the typed fields, on the HEADER route — not its
        // path-append default, which only a sing-box server would understand.
        let sb = to_singbox_transport(&transport)
            .expect("ws is in the vendored set")
            .expect("a ws transport emits a transport object");
        assert_eq!(sb["max_early_data"], 2048);
        assert_eq!(
            sb["early_data_header_name"], "Sec-WebSocket-Protocol",
            "the header route, not sing-box's path-append default"
        );

        // Every source, not just the hoisted one: a Clash import or the Add/Edit
        // form sets the size with no name, and the emitter must still pin the
        // route — the hoist never ran on this shape.
        let from_clash = TransportConfig::Ws(WebSocketConfig {
            path: Some(TinyText::from("/ws")),
            max_early_data: Some(2048),
            ..Default::default()
        });
        let sb = to_singbox_transport(&from_clash)
            .expect("ws is in the vendored set")
            .expect("a ws transport emits a transport object");
        assert_eq!(sb["max_early_data"], 2048);
        assert_eq!(
            sb["early_data_header_name"], "Sec-WebSocket-Protocol",
            "a field-set source must not fall back to the path-append route"
        );
    }

    fn ws_path(t: &TransportConfig) -> Option<&str> {
        match t {
            TransportConfig::Ws(c) => c.path.as_deref(),
            other => panic!("expected ws transport, got {other:?}"),
        }
    }

    fn canon(input: &str) -> Option<String> {
        let mut t = TransportConfig::Ws(WebSocketConfig {
            path: Some(TinyText::from(input)),
            ..Default::default()
        });
        canonicalize_config_paths(&mut t, &mut None);
        ws_path(&t).map(str::to_owned)
    }

    /// The two measured spellings of ONE logical path (spec §2 rows 2 and 4)
    /// must canonicalize to the same request-target — that is the dedup, since
    /// the ws path is identity-bearing (`write_transport`).
    #[test]
    fn ws_path_canonicalization_merges_the_two_spellings_of_one_path() {
        // row 2: what a single-encoded source leaves after RawUrlX's one decode
        let single = canon("/trTelegram🇨🇳 @WangCai2");
        // row 4: what a double-encoded source leaves
        let doubled = canon("%2FtrTelegram%F0%9F%87%A8%F0%9F%87%B3%20%40WangCai2");
        assert_eq!(single, doubled);
        // `@` is an RFC 3986 pchar, so it stays bare — Go's EscapedPath does
        // the same, and leaving it is what keeps the target decodable.
        assert_eq!(
            single.as_deref(),
            Some("/trTelegram%F0%9F%87%A8%F0%9F%87%B3%20@WangCai2")
        );
        // The invariant: the target decodes server-side to the configured path.
        let decoded = urlencoding::decode(single.as_deref().unwrap()).unwrap();
        assert_eq!(decoded.as_ref(), "/trTelegram🇨🇳 @WangCai2");
    }

    /// Distinct logical paths must NOT be merged — a merge-happy canonicalizer
    /// would be as wrong as today's behaviour, in the other direction
    /// (spec §2 rows 1 and 3 are genuinely different channels).
    #[test]
    fn ws_path_canonicalization_does_not_merge_distinct_paths() {
        let no_emoji = canon("/trTelegram @WangCai2");
        let plus = canon("%2FtrTelegram%F0%9F%87%A8%F0%9F%87%B3%2B%40WangCai2");
        let emoji = canon("/trTelegram🇨🇳 @WangCai2");
        assert_ne!(no_emoji, emoji);
        assert_ne!(plus, emoji);
        assert_ne!(no_emoji, plus);
    }

    /// The early-data form is stored INSIDE `path`; its query must ride
    /// through verbatim or a config that dials today would move and re-key
    /// (spec §4.1 — `vless.rs` pins `/?ed=2560`).
    #[test]
    fn ws_path_canonicalization_preserves_the_query() {
        for same in ["/?ed=2560", "/?ed=2048", "/ws", "/", "/a/b?x=1&y=2", "/x?a"] {
            assert_eq!(canon(same).as_deref(), Some(same), "moved: {same}");
        }
    }

    /// Idempotent: re-canonicalizing a canonical path changes nothing.
    #[test]
    fn ws_path_canonicalization_is_idempotent() {
        for input in [
            "/trTelegram🇨🇳 @WangCai2",
            "%2FtrTelegram%F0%9F%87%A8%F0%9F%87%B3%20%40WangCai2",
            "/?ed=2560",
        ] {
            let once = canon(input).unwrap();
            assert_eq!(canon(&once).as_deref(), Some(once.as_str()), "{input}");
        }
        // An absent path stays absent.
        let mut t = TransportConfig::Ws(WebSocketConfig::default());
        canonicalize_config_paths(&mut t, &mut None);
        assert_eq!(ws_path(&t), None);
    }

    #[test]
    fn ws_path_canonicalization_prepends_the_leading_slash() {
        for (input, expected) in [
            ("trTelegram x", "/trTelegram%20x"),
            ("/trTelegram x", "/trTelegram%20x"),
            // `%2F` decodes to `/`, so the slash is already there
            ("%2Ftr", "/tr"),
        ] {
            assert_eq!(canon(input).as_deref(), Some(expected), "{input}");
        }
    }

    /// `Grpc`'s `path` is a service name, not a URI path — it must not move.
    #[test]
    fn grpc_service_name_is_not_a_path() {
        let mut t = TransportConfig::Grpc(GrpcConfig {
            path: Some(TinyText::from("my.Service")),
            ..Default::default()
        });
        canonicalize_config_paths(&mut t, &mut None);
        match t {
            TransportConfig::Grpc(c) => assert_eq!(c.path.as_deref(), Some("my.Service")),
            other => panic!("expected grpc, got {other:?}"),
        }
    }
    #[test]
    fn parse_curve_names_maps_all_seven_xray_names() {
        use super::curve_id::{
            P256, P384, P521, SECP256R1_MLKEM768, SECP384R1_MLKEM1024, X25519, X25519_MLKEM768,
        };
        assert_eq!(parse_curve_names("curvep256"), vec![P256]);
        assert_eq!(parse_curve_names("curvep384"), vec![P384]);
        assert_eq!(parse_curve_names("curvep521"), vec![P521]);
        assert_eq!(parse_curve_names("x25519"), vec![X25519]);
        assert_eq!(parse_curve_names("x25519mlkem768"), vec![X25519_MLKEM768]);
        assert_eq!(
            parse_curve_names("secp256r1mlkem768"),
            vec![SECP256R1_MLKEM768]
        );
        assert_eq!(
            parse_curve_names("secp384r1mlkem1024"),
            vec![SECP384R1_MLKEM1024]
        );
    }

    #[test]
    fn parse_curve_names_is_case_insensitive_and_skips_unknown() {
        // xray lowercases via strings.ToLower before the map lookup.
        assert_eq!(
            parse_curve_names("X25519MLKEM768, CurveP256"),
            vec![4588, 23]
        );
        // Unknown names warn + skip (never error) — ParseCurveName mirror.
        assert_eq!(parse_curve_names("bogus,x25519,p521x"), vec![29]);
        assert!(parse_curve_names("").is_empty());
        assert!(parse_curve_names(" , ").is_empty());
    }

    #[test]
    fn tls_opts_curves_serde_roundtrip() {
        let opts: TlsOpts = serde_json::from_str(r#"{"curves":"x25519mlkem768"}"#).unwrap();
        assert_eq!(opts.curves.as_deref(), Some("x25519mlkem768"));
        // Absent field stays None — identity configs are unchanged.
        assert_eq!(TlsOpts::default().curves, None);
    }

    #[test]
    fn vless_stream_settings_emits_xray_stream_settings() {
        let raw = RawUrlX::from(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@cdn.example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com#r",
        );
        let config = VlessConfig::try_parse(&raw).expect("parse vless URL");
        let ss = to_xray_stream_settings(&config.security, &config.transport)
            .expect("streamSettings present");
        assert_eq!(ss["network"], "ws");
        assert_eq!(ss["security"], "tls");
        assert_eq!(ss["wsSettings"]["path"], "/ws");
        // The WS vhost goes in the top-level `host` field — xray-core
        // deprecates `headers.Host` ("will be removed soon").
        assert_eq!(ss["wsSettings"]["host"], "cdn.example.com");
        assert!(
            ss["wsSettings"].get("headers").is_none(),
            "headers.Host must not be emitted"
        );
    }

    /// The coupling `validate_xray_transport` exists for.
    ///
    /// These two transports reach xray as `network: "http"` / `"quic"`, and
    /// xray-core 26 refuses BOTH at config load (`PrintRemovedFeatureError`
    /// returns an error, not a warning — verified against the pinned binary).
    /// `ws`, `httpupgrade` and `splithttp` were already pinned by tests; these
    /// two were the unpinned pair, which is exactly why nothing failed when the
    /// transports were removed upstream. Pinned here so a change to the emitted
    /// name cannot silently re-open the hole the validator closes.
    #[test]
    fn the_removed_transports_emit_the_names_xray_refuses() {
        for (transport, expected) in [
            (TransportConfig::Http(HttpConfig::default()), "http"),
            (TransportConfig::Quic, "quic"),
        ] {
            let ss = to_xray_stream_settings(&SecurityConfig::default(), &transport)
                .expect("a non-tcp transport emits streamSettings");
            assert_eq!(ss["network"], expected, "{transport:?}");
            // And the validator refuses exactly the ones that emit those names.
            assert!(
                validate_xray_transport(&transport).is_err(),
                "{transport:?} emits a name xray-core removed, so the build must refuse it"
            );
        }
        // The transports xray still implements stay buildable.
        for transport in [
            TransportConfig::Tcp,
            TransportConfig::Ws(WebSocketConfig::default()),
            TransportConfig::Grpc(GrpcConfig::default()),
            TransportConfig::HttpUpgrade(HttpUpgradeConfig::default()),
            TransportConfig::XHttp(XHttpConfig::default()),
        ] {
            assert!(
                validate_xray_transport(&transport).is_ok(),
                "{transport:?} is still implemented by xray-core"
            );
        }
    }

    #[test]
    fn vless_stream_settings_emits_splithttp_network() {
        let raw = RawUrlX::from(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@cdn.example.com:443?security=tls&type=splithttp&path=%2Fs#r",
        );
        let config = VlessConfig::try_parse(&raw).expect("parse vless URL");
        let ss = to_xray_stream_settings(&config.security, &config.transport)
            .expect("streamSettings present");
        // xray-core only recognizes "splithttp" as the network name.
        assert_eq!(ss["network"], "splithttp");
        assert_eq!(ss["splithttpSettings"]["path"], "/s");
    }

    #[test]
    fn vless_stream_settings_emits_httpupgrade_host_string() {
        let raw = RawUrlX::from(
            "vless://6202b230-417c-4d8e-b624-0f71afa9c75d@cdn.example.com:443?type=httpupgrade&path=%2Fup&host=cdn.example.com#r",
        );
        let config = VlessConfig::try_parse(&raw).expect("parse vless URL");
        let ss = to_xray_stream_settings(&config.security, &config.transport)
            .expect("streamSettings present");
        assert_eq!(ss["network"], "httpupgrade");
        let host = &ss["httpupgradeSettings"]["host"];
        assert!(
            host.is_string(),
            "httpupgradeSettings.host must be a string, got {host}"
        );
        assert_eq!(host, "cdn.example.com");
    }

    #[test]
    fn security_config_default_is_empty() {
        let sc = SecurityConfig::default();
        assert!(sc.tls.is_none());
        assert!(sc.enc.is_none());
    }

    #[test]
    fn security_config_type_str() {
        let tls = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts::default())),
            enc: None,
        };
        assert_eq!(tls.type_str(), Some("tls"));

        let reality = SecurityConfig {
            tls: Some(TlsConfig::Reality(RealityOpts::default())),
            enc: None,
        };
        assert_eq!(reality.type_str(), Some("reality"));

        let none = SecurityConfig::default();
        assert_eq!(none.type_str(), None);
    }

    #[test]
    fn security_config_serde_empty() {
        let sc = SecurityConfig::default();
        let json = serde_json::to_string(&sc).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn security_config_serde_tls() {
        let sc = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: Some("example.com".into()),
                ..TlsOpts::default()
            })),
            enc: None,
        };
        let json = serde_json::to_string(&sc).unwrap();
        assert!(json.contains("\"tls\""));
        assert!(json.contains("\"sni\""));
        assert!(json.contains("\"example.com\""));
        assert!(!json.contains("\"enc\""));
    }

    #[test]
    fn should_skip_endpoint_param_skips_matching_dns() {
        assert!(should_skip_endpoint_param("example.com", "example.com"));
        assert!(should_skip_endpoint_param("example.com", "EXAMPLE.COM"));
        assert!(!should_skip_endpoint_param("example.com", "other.com"));
        assert!(!should_skip_endpoint_param("example.com", "example.org"));
    }

    #[test]
    fn should_skip_endpoint_param_never_skips_for_ip() {
        assert!(!should_skip_endpoint_param("1.2.3.4", "anything"));
        assert!(!should_skip_endpoint_param("1.2.3.4", "1.2.3.4"));

        assert!(!should_skip_endpoint_param("::1", "::1"));
        assert!(!should_skip_endpoint_param("::1", "anything"));
    }

    #[test]
    fn clash_ws_lowercase_host_header_restores_vhost() {
        let ws = ClashWSOpts {
            path: Some("/ws".into()),
            headers: Some(std::collections::HashMap::from([
                ("host".to_string(), "cdn.example.com".to_string()),
                ("X-Test".to_string(), "1".to_string()),
            ])),
            ..ClashWSOpts::default()
        };
        let t = clash_transport_to_transport(Some("ws"), Some(&ws), None, None, None, None, None);
        match t {
            TransportConfig::Ws(w) => {
                assert_eq!(w.host.as_deref(), Some("cdn.example.com"));
                let headers = w.headers.expect("non-host headers survive");
                assert!(
                    !headers.keys().any(|k| k.eq_ignore_ascii_case("host")),
                    "host must not be double-represented: {headers:?}"
                );
                assert_eq!(headers.get("X-Test").map(String::as_str), Some("1"));
            }
            other => panic!("expected Ws transport, got {other:?}"),
        }
    }

    #[test]
    fn with_host_forwards_host_to_ws_grpc_http() {
        let cases = vec![
            TransportConfig::Ws(WebSocketConfig::default()),
            TransportConfig::Grpc(GrpcConfig::default()),
            TransportConfig::Http(HttpConfig::default()),
        ];
        for t in cases {
            let t = t.with_host(Some("cdn.example.com".into()), None, None);
            let host = match &t {
                TransportConfig::Ws(c) => c.host.as_deref(),
                TransportConfig::Grpc(c) => c.authority.as_deref(),
                TransportConfig::Http(c) => c.host.as_deref(),
                _ => None,
            };
            assert_eq!(host, Some("cdn.example.com"), "{t:?} keeps host");
        }
    }
}
