//! Clash/mihomo YAML proxy format.
//!
//! Per-protocol structs with kebab-case serde. Conversion to/from `ProtocolConfig`
//! lives in each protocol's implementation.
//! Only mihomo/meta-v1 (`proxies:` array entries).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Single proxy entry in Clash YAML `proxies:` array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ClashProxy {
    Vmess(ClashVmess),
    Vless(ClashVless),
    Trojan(ClashTrojan),
    #[serde(rename = "ss")]
    Shadowsocks(ClashSS),
    #[serde(rename = "ssr")]
    ShadowsocksR(ClashSSR),
    Socks5(ClashSocks5),
    Http(ClashHttp),
    Tuic(ClashTuic),
    Hysteria2(ClashHysteria2),
    Hysteria(ClashHysteria1),
    Wireguard(ClashWireGuard),
    Naive(ClashNaive),
    Anytls(ClashAnyTls),
    Shadowtls(ClashShadowTls),
    Tor(ClashTor),
    Ssh(ClashSsh),
    Tailscale(ClashTailscale),
    Snell(ClashSnell),
    #[serde(rename = "direct")]
    Direct(ClashDirect),
    #[serde(rename = "dns")]
    Dns(ClashDns),
    Reject(ClashReject),
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashVmess {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default = "default_cipher")]
    pub cipher: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alter_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tfo")]
    pub tfo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<ClashWSOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<ClashGrpcOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h2_opts: Option<ClashH2Opts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_opts: Option<ClashHttpOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mkcp_opts: Option<ClashKcpOpts>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashVless {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tfo")]
    pub tfo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// Clash states mux as a **bool** (`mux: true`); a true row asks for the
    /// default cap. This is the Clash shape, not ours — `VlessMux` carries the
    /// cap and the unlimited case that a bool cannot express.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_opts: Option<ClashRealityOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<ClashWSOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<ClashGrpcOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xhttp_opts: Option<ClashXHttpOpts>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashTrojan {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "tfo")]
    pub tfo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_show: Option<bool>,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<ClashWSOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<ClashGrpcOpts>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashSS {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_over_tcp: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashSSR {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
    pub protocol: String,
    pub obfs: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_param: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashSocks5 {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashHttp {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashTuic {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduce_rtt: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_relay_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion_controller: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashHysteria2 {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_interval: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashHysteria1 {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub auth_str: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashWireGuard {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub private_key: String,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_shared_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u32>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashNaive {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashAnyTls {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_session_check_interval: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_session_timeout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_idle_session: Option<u32>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashShadowTls {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashTor {
    pub name: String,
    pub server: String,
    pub port: u16,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashSsh {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashTailscale {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub ephemeral: bool,
    #[serde(default)]
    pub accept_routes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_node_allow_lan_access: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashSnell {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub psk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_opts: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashDirect {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashDns {
    pub name: String,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClashReject {
    pub name: String,
}

// ── Transport sub-option structs ──

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashWSOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_early_data: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data_header_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2ray_http_upgrade: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2ray_http_upgrade_fast_open: Option<bool>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashGrpcOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc_user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_interval: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_streams: Option<u32>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashH2Opts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashHttpOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, Vec<String>>>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashKcpOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tti: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_capacity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downlink_capacity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub congestion: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_buffer: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_buffer: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashXHttpOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_download_size: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data_header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reuse: Option<ClashReuseOpts>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashReuseOpts {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_path: Option<String>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashRealityOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_x25519mlkem768: Option<bool>,
}

fn default_cipher() -> String {
    "auto".to_string()
}

const fn default_true() -> bool {
    true
}
