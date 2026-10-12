use leas_proto::proto_spec::common::{GrpcConfig, TransportConfig, WebSocketConfig};
use leas_proto::proto_spec::core_mapping;
use leas_proto::proto_spec::{
    AnyTlsConfig, EndpointEssentials, HostKind, HttpClientConfig, Hysteria1Config, Hysteria2Config,
    NaiveConfig, ParsedProto, PlaceholderConfig, PluginSpec, ProtocolConfig, ProtocolEssentials,
    ProtocolKind, SecurityConfig, ShadowTlsConfig, Socks5Config, SsConfig, SshConfig, SsrConfig,
    TailscaleConfig, TlsConfig, TlsOpts, TorConfig, TrojanConfig, TuicConfig, VlessConfig,
    VlessMux, VmessConfig, WireguardConfig,
};
use leas_proto::urlx::TinyText;
use serde_json::{Map, Value};

/// A single input field in a protocol form.
#[derive(Debug, Clone)]
pub enum FormFieldType {
    Text,
    Number,
    Select(&'static [&'static str]),
    Boolean,
    Password,
}

#[derive(Debug, Clone)]
pub struct FormField {
    pub key: &'static str,
    pub label: &'static str,
    pub field_type: FormFieldType,
    pub default: &'static str,
    pub required: bool,
    pub section: FieldSection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSection {
    /// Stored directly as Profile fields (remarks, address, port, etc.)
    Common,
    /// Serialized to `Profile.stream_settings` JSON blob
    StreamSetting,
    /// Serialized to `Profile.protocol_settings` JSON blob
    ProtocolSetting,
}

/// Returns the form fields for a given protocol.
#[must_use]
pub fn form_fields_for(protocol: ProtocolKind) -> Vec<FormField> {
    let mut fields = common_fields();
    fields.extend(protocol_specific_fields(protocol));
    fields
}

fn common_fields() -> Vec<FormField> {
    vec![
        FormField {
            key: "address",
            label: "Address",
            field_type: FormFieldType::Text,
            default: "",
            required: true,
            section: FieldSection::Common,
        },
        FormField {
            key: "port",
            label: "Port",
            field_type: FormFieldType::Number,
            default: "443",
            required: true,
            section: FieldSection::Common,
        },
        FormField {
            key: "core_type",
            label: "Core",
            field_type: FormFieldType::Select(&["auto", "xray", "sing-box"]),
            default: "auto",
            required: false,
            section: FieldSection::Common,
        },
    ]
}

fn protocol_specific_fields(protocol: ProtocolKind) -> Vec<FormField> {
    match protocol {
        ProtocolKind::Vmess => vec![
            field(
                "user_id",
                "User ID",
                FormFieldType::Text,
                "",
                true,
                FieldSection::Common,
            ),
            field(
                "security",
                "Encryption",
                FormFieldType::Select(&["auto", "aes-128-gcm", "chacha20-poly1305", "none"]),
                "auto",
                false,
                FieldSection::Common,
            ),
            field(
                "network",
                "Network",
                FormFieldType::Select(&["tcp", "kcp", "ws", "http", "h2", "grpc", "quic"]),
                "tcp",
                false,
                FieldSection::Common,
            ),
            field(
                "tls.enable",
                "TLS",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "fingerprint",
                "Fingerprint",
                FormFieldType::Select(&[
                    "", "chrome", "firefox", "safari", "edge", "random", "ios", "android", "qq",
                ]),
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "alpn",
                "ALPN",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "pin_sha256",
                "Pin SHA256",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "sni",
                "SNI",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "allow_insecure",
                "Allow Insecure",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "ech.enable",
                "ECH",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "ech.config",
                "ECH Config",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "fragment.enable",
                "Fragment",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "fragment.packets",
                "Frag Packets",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "fragment.length",
                "Frag Length",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "fragment.interval",
                "Frag Interval",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "reality.show",
                "Reality",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "ws.path",
                "WebSocket Path",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "ws.host",
                "WebSocket Host",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "grpc.serviceName",
                "gRPC Service",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "tcp.headerType",
                "TCP Header",
                FormFieldType::Select(&["none", "http"]),
                "none",
                false,
                FieldSection::StreamSetting,
            ),
        ],
        ProtocolKind::Vless => vec![
            field(
                "user_id",
                "User ID",
                FormFieldType::Text,
                "",
                true,
                FieldSection::Common,
            ),
            field(
                "flow",
                "Flow",
                FormFieldType::Select(&["", "xtls-rprx-vision", "xtls-rprx-vision-udp443"]),
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            // Default ABSENT, not "false": `fields_to_parsed` skips only EMPTY
            // values, so a "false" default would make every untouched form row
            // store the stated "no" (`Limited(0)`) — a different uid from the
            // imported row for the same server, which stores `None`. The two
            // would duplicate into two `Protocol` rows, which is the form/import
            // disagreement this mapper exists to prevent. A Boolean renders
            // `[ ]` when empty and toggles to "true"; un-toggling gives the
            // stated "false", which IS a distinct stored state (spec §5.2 item 9).
            field(
                "mux",
                "Mux",
                FormFieldType::Boolean,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "mux_concurrency",
                "Mux Concurrency",
                FormFieldType::Text,
                "8",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "network",
                "Network",
                FormFieldType::Select(&["tcp", "kcp", "ws", "http", "h2", "grpc", "quic"]),
                "tcp",
                false,
                FieldSection::Common,
            ),
            field(
                "fingerprint",
                "Fingerprint",
                FormFieldType::Select(&[
                    "", "chrome", "firefox", "safari", "edge", "random", "ios", "android", "qq",
                ]),
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "alpn",
                "ALPN",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "pin_sha256",
                "Pin SHA256",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "sni",
                "SNI",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "allow_insecure",
                "Allow Insecure",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "ech.enable",
                "ECH",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "ech.config",
                "ECH Config",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "fragment.enable",
                "Fragment",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "fragment.packets",
                "Frag Packets",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "fragment.length",
                "Frag Length",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "fragment.interval",
                "Frag Interval",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "tls.enable",
                "TLS",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "ws.path",
                "WebSocket Path",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "ws.host",
                "WebSocket Host",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "grpc.serviceName",
                "gRPC Service",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
        ],
        ProtocolKind::Shadowsocks | ProtocolKind::Shadowsocks2022 => vec![
            field(
                "method",
                "Method",
                FormFieldType::Select(match protocol {
                    ProtocolKind::Shadowsocks => &[
                        "aes-256-gcm",
                        "aes-128-gcm",
                        "chacha20-ietf-poly1305",
                        "xchacha20-ietf-poly1305",
                        "none",
                    ],
                    ProtocolKind::Shadowsocks2022 => {
                        // 2022-blake3 only — no "none" (neither core has a
                        // plain 2022 mode; the 2022 spec requires a key).
                        &[
                            "2022-blake3-aes-128-gcm",
                            "2022-blake3-aes-256-gcm",
                            "2022-blake3-chacha20-poly1305",
                        ]
                    }
                    _ => unreachable!(),
                }),
                "aes-256-gcm",
                true,
                FieldSection::ProtocolSetting,
            ),
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                true,
                FieldSection::Common,
            ),
            field(
                "plugin",
                "Plugin",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
            field(
                "plugin_opts",
                "Plugin Opts",
                FormFieldType::Text,
                "",
                false,
                FieldSection::StreamSetting,
            ),
        ],
        ProtocolKind::Socks => vec![
            field(
                "username",
                "Username",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "udp",
                "UDP",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Http => vec![
            field(
                "username",
                "Username",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "tls",
                "TLS",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "path",
                "Path",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Trojan => vec![
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                true,
                FieldSection::Common,
            ),
            field(
                "flow",
                "Flow",
                FormFieldType::Select(&["", "xtls-rprx-vision"]),
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "sni",
                "SNI",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "alpn",
                "ALPN",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "fingerprint",
                "Fingerprint",
                FormFieldType::Select(&[
                    "", "chrome", "firefox", "safari", "edge", "random", "ios", "android", "qq",
                ]),
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "allow_insecure",
                "Allow Insecure",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "pin_sha256",
                "Pin SHA256",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "ech.enable",
                "ECH",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "ech.config",
                "ECH Config",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "fragment.enable",
                "Fragment",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "fragment.packets",
                "Frag Packets",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "fragment.length",
                "Frag Length",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "fragment.interval",
                "Frag Interval",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::WireGuard => vec![
            field(
                "private_key",
                "Private Key",
                FormFieldType::Password,
                "",
                true,
                FieldSection::ProtocolSetting,
            ),
            field(
                "public_key",
                "Public Key",
                FormFieldType::Text,
                "",
                true,
                FieldSection::ProtocolSetting,
            ),
            field(
                "endpoint",
                "Endpoint",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "allowed_ips",
                "Allowed IPs",
                FormFieldType::Text,
                "0.0.0.0/0",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "dns",
                "DNS",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "mtu",
                "MTU",
                FormFieldType::Number,
                "1420",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "workers",
                "Workers",
                FormFieldType::Number,
                "4",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "preshared_key",
                "Pre-Shared Key",
                FormFieldType::Password,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "reserved",
                "Reserved",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "persistent_keepalive",
                "Keepalive",
                FormFieldType::Number,
                "0",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "udp_timeout",
                "UDP Timeout",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "system",
                "System",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "peers",
                "Peers (JSON)",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Hysteria2 => vec![
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                false,
                FieldSection::Common,
            ),
            field(
                "ports",
                "Ports",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "hop",
                "Hop Interval",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "obfs",
                "Obfs",
                FormFieldType::Select(&["", "salamander", "other"]),
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "obfs_password",
                "Obfs Password",
                FormFieldType::Password,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "sni",
                "SNI",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "insecure",
                "Insecure",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Hysteria => vec![
            field(
                "protocol",
                "Protocol",
                FormFieldType::Select(&["udp", "faketcp", "wechat-video"]),
                "udp",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "auth",
                "Auth",
                FormFieldType::Password,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "obfs",
                "Obfs",
                FormFieldType::Select(&["", "salamander", "other"]),
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "up_mbps",
                "Upload Mbps",
                FormFieldType::Number,
                "100",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "down_mbps",
                "Download Mbps",
                FormFieldType::Number,
                "100",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "sni",
                "SNI",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "insecure",
                "Insecure",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Tuic => vec![
            field(
                "uuid",
                "UUID",
                FormFieldType::Text,
                "",
                true,
                FieldSection::Common,
            ),
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "congestion_control",
                "Congestion Ctrl",
                FormFieldType::Select(&["bbr", "cubic", "new_reno"]),
                "bbr",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "udp_relay_mode",
                "UDP Relay",
                FormFieldType::Select(&["native", "quic"]),
                "native",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "sni",
                "SNI",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "alpn",
                "ALPN",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "insecure",
                "Insecure",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Naive => vec![
            field(
                "user",
                "User",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                true,
                FieldSection::ProtocolSetting,
            ),
            field(
                "extra_headers",
                "Extra Headers",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "padding",
                "Padding",
                FormFieldType::Boolean,
                "true",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::AnyTls => vec![
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                true,
                FieldSection::ProtocolSetting,
            ),
            field(
                "sni",
                "SNI",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "alpn",
                "ALPN",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "insecure",
                "Insecure",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::ShadowTls => vec![
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                true,
                FieldSection::ProtocolSetting,
            ),
            field(
                "version",
                "Version",
                FormFieldType::Number,
                "3",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "sni",
                "SNI",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Tor => vec![
            field(
                "socks_port",
                "SOCKS Port",
                FormFieldType::Number,
                "9050",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "control_port",
                "Control Port",
                FormFieldType::Number,
                "9051",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "control_password",
                "Control Password",
                FormFieldType::Password,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "data_dir",
                "Data Dir",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Ssh => vec![
            field(
                "host",
                "SSH Host",
                FormFieldType::Text,
                "",
                true,
                FieldSection::ProtocolSetting,
            ),
            field(
                "ssh_port",
                "SSH Port",
                FormFieldType::Number,
                "22",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "username",
                "Username",
                FormFieldType::Text,
                "",
                true,
                FieldSection::ProtocolSetting,
            ),
            field(
                "private_key",
                "Private Key",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "auth_method",
                "Auth Method",
                FormFieldType::Select(&["password", "key"]),
                "password",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Tailscale => vec![
            field(
                "auth_key",
                "Auth Key",
                FormFieldType::Password,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "control_url",
                "Control URL",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "ephemeral",
                "Ephemeral",
                FormFieldType::Boolean,
                "false",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::ShadowsocksR => vec![
            field(
                "method",
                "Method",
                FormFieldType::Select(&[
                    "aes-256-cfb",
                    "aes-128-cfb",
                    "rc4-md5",
                    "chacha20",
                    "none",
                ]),
                "aes-256-cfb",
                true,
                FieldSection::ProtocolSetting,
            ),
            field(
                "password",
                "Password",
                FormFieldType::Password,
                "",
                true,
                FieldSection::Common,
            ),
            field(
                "obfs",
                "Obfs",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "obfs_param",
                "Obfs Param",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "protocol",
                "Protocol",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "protocol_param",
                "Protocol Param",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::DokodemoDoor => vec![
            field(
                "doko_address",
                "Target Address",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "doko_port",
                "Target Port",
                FormFieldType::Number,
                "0",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "network",
                "Network",
                FormFieldType::Select(&["tcp", "udp", "tcp,udp"]),
                "tcp",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Freedom => vec![
            field(
                "domain_strategy",
                "Domain Strategy",
                FormFieldType::Select(&["AsIs", "UseIP", "UseIPv4", "UseIPv6"]),
                "AsIs",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "redirect",
                "Redirect",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Blackhole => vec![field(
            "response_type",
            "Response",
            FormFieldType::Select(&["none", "http"]),
            "none",
            false,
            FieldSection::ProtocolSetting,
        )],
        ProtocolKind::Loopback => vec![field(
            "proxy_tag",
            "Proxy Tag",
            FormFieldType::Text,
            "",
            false,
            FieldSection::ProtocolSetting,
        )],
        ProtocolKind::Dns => vec![
            field(
                "network",
                "Network",
                FormFieldType::Select(&["tcp", "udp"]),
                "tcp",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "dns_address",
                "Address",
                FormFieldType::Text,
                "",
                true,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Redirect => vec![
            field(
                "redirect_address",
                "Address",
                FormFieldType::Text,
                "",
                false,
                FieldSection::ProtocolSetting,
            ),
            field(
                "redirect_port",
                "Port",
                FormFieldType::Number,
                "0",
                false,
                FieldSection::ProtocolSetting,
            ),
        ],
        ProtocolKind::Custom => vec![field(
            "config_json",
            "Config JSON",
            FormFieldType::Text,
            "",
            true,
            FieldSection::ProtocolSetting,
        )],
        ProtocolKind::TProxy | ProtocolKind::Mixed => {
            // Inbound-only protocols — no outbound form
            vec![]
        }
    }
}

const fn field(
    key: &'static str,
    label: &'static str,
    field_type: FormFieldType,
    default: &'static str,
    required: bool,
    section: FieldSection,
) -> FormField {
    FormField {
        key,
        label,
        field_type,
        default,
        required,
        section,
    }
}

/// URL scheme prefix for each protocol's share link.
#[must_use]
pub const fn url_scheme_for(protocol: ProtocolKind) -> &'static str {
    match protocol {
        ProtocolKind::Vmess => "vmess://",
        ProtocolKind::Vless => "vless://",
        ProtocolKind::Shadowsocks | ProtocolKind::Shadowsocks2022 => "ss://",
        ProtocolKind::Trojan => "trojan://",
        ProtocolKind::Socks => "socks://",
        ProtocolKind::Hysteria2 => "hysteria2://",
        ProtocolKind::Hysteria => "hysteria://",
        ProtocolKind::Tuic => "tuic://",
        ProtocolKind::Naive => "naive+https://",
        ProtocolKind::AnyTls => "anytls://",
        ProtocolKind::ShadowTls => "shadowtls://",
        ProtocolKind::WireGuard => "wireguard://",
        _ => "",
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Typed config builders (T12) — form field JSON → ParsedProto
//
// The TUI's `fields_to_profile` (ops/profiles.rs, READ-ONLY) produces the
// settings JSON consumed here: `{ "user_id"?, "protocol_settings": {…},
// "stream_settings": {…} }` — `user_id` is the credential form field
// (`user_id`/`uuid`/`password`), which `fields_to_profile` keeps OUT of the
// two settings maps. These builders are the reverse of the typed config
// structs' parse boundaries, and wrap
// outbound-only kinds in a `PlaceholderConfig`.
//
// HOST-FREE rule: the endpoint `address` never enters transport/security
// config fields — only explicit form override keys (`sni`, `ws.host`, …) do.
// ═══════════════════════════════════════════════════════════════════════

type SettingsMap = Map<String, Value>;

/// Build a typed [`ParsedProto`] from form field JSON.
///
/// `address`/`port` are the endpoint essentials the form collected; `settings`
/// is the form's `{ "user_id"?, "protocol_settings": …, "stream_settings": … }`
/// JSON (the shape `fields_to_profile` produces — T17 passes its `extra` object
/// verbatim; no wrapper helper is needed). Unknown settings keys -> Err.
pub fn build_typed_config(
    proto_kind: ProtocolKind,
    address: &str,
    port: u16,
    settings: &Value,
) -> Result<ParsedProto, String> {
    let proto = proto_kind.as_str();
    let obj = settings
        .as_object()
        .ok_or_else(|| format!("settings must be a JSON object for {proto}"))?;
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "user_id" | "protocol_settings" | "stream_settings"
        ) {
            return Err(format!("unknown setting {key} for {proto}"));
        }
    }
    let user_id = obj.get("user_id").and_then(Value::as_str);
    let ps = settings_map(obj.get("protocol_settings"), "protocol_settings", proto)?;
    let ss = settings_map(obj.get("stream_settings"), "stream_settings", proto)?;

    let config = match proto_kind {
        // Shadowsocks: kind and core are cipher-aware (mirrors
        // `SsConfig::try_parse_proto` — 2022-blake3 methods are
        // Shadowsocks2022), so the whole ParsedProto is built here.
        ProtocolKind::Shadowsocks | ProtocolKind::Shadowsocks2022 => {
            let cfg = ss_from_form(user_id, ps, ss)?;
            let kind = kind_for_ss_method(cfg.method.as_str());
            return Ok(ParsedProto {
                endpoints: vec![endpoint_from(address, port)],
                protocol: ProtocolEssentials {
                    proto_kind: kind,
                    core_type: core_mapping::resolve_core(kind, None, Some(cfg.method.as_str())),
                    config: ProtocolConfig::Ss(cfg),
                },
            });
        }
        ProtocolKind::Vless => ProtocolConfig::Vless(vless_from_form(user_id, ps, ss)?),
        ProtocolKind::Vmess => ProtocolConfig::Vmess(vmess_from_form(user_id, ps, ss)?),
        ProtocolKind::Trojan => ProtocolConfig::Trojan(trojan_from_form(user_id, ps, ss)?),
        ProtocolKind::Hysteria2 => ProtocolConfig::Hysteria2(hysteria2_from_form(user_id, ps, ss)?),
        ProtocolKind::Socks => ProtocolConfig::Socks(socks_from_form(user_id, ps, ss)?),
        ProtocolKind::Http => ProtocolConfig::Http(http_from_form(user_id, ps, ss)?),
        ProtocolKind::Tuic => ProtocolConfig::Tuic(tuic_from_form(user_id, ps, ss)?),
        ProtocolKind::WireGuard => ProtocolConfig::Wireguard(wireguard_from_form(user_id, ps, ss)?),
        ProtocolKind::Naive => ProtocolConfig::Naive(naive_from_form(user_id, ps, ss)?),
        ProtocolKind::AnyTls => ProtocolConfig::AnyTls(anytls_from_form(user_id, ps, ss)?),
        ProtocolKind::ShadowTls => ProtocolConfig::ShadowTls(shadowtls_from_form(user_id, ps, ss)?),
        ProtocolKind::Tor => ProtocolConfig::Tor(tor_from_form(ps, ss)?),
        ProtocolKind::Ssh => ProtocolConfig::Ssh(ssh_from_form(ps, ss)?),
        ProtocolKind::Tailscale => ProtocolConfig::Tailscale(tailscale_from_form(ps, ss)?),
        ProtocolKind::Hysteria => ProtocolConfig::Hysteria1(hysteria1_from_form(ps, ss)?),
        ProtocolKind::ShadowsocksR => ProtocolConfig::Ssr(ssr_from_form(user_id, ps, ss)?),
        // Outbound-only kinds (no URL, no typed config) + Redirect/TProxy/
        // Mixed: raw settings passthrough in a PlaceholderConfig.
        ProtocolKind::DokodemoDoor
        | ProtocolKind::Freedom
        | ProtocolKind::Blackhole
        | ProtocolKind::Dns
        | ProtocolKind::Loopback
        | ProtocolKind::Custom
        | ProtocolKind::Redirect
        | ProtocolKind::TProxy
        | ProtocolKind::Mixed => {
            return placeholder_parsed(proto_kind, address, port, settings);
        }
    };

    let mut endpoint = endpoint_from(address, port);
    // Hysteria2: the form's `ports` hop spec flattens onto endpoints[0]
    // (primary port + full list), same as the URL parser's multi-port path.
    if proto_kind == ProtocolKind::Hysteria2
        && let Some(ports) = ps.get("ports").and_then(value_string)
        && !ports.is_empty()
    {
        let spec = parse_port_spec(proto, &ports)?;
        if !spec.is_empty() {
            endpoint.port = spec[0];
            endpoint.ports = spec;
        }
    }

    Ok(ParsedProto {
        endpoints: vec![endpoint],
        protocol: ProtocolEssentials {
            proto_kind,
            core_type: core_mapping::resolve_core(proto_kind, None, None),
            config,
        },
    })
}

// ── shared helpers ──────────────────────────────────────────────────────

/// Extract a named sub-object; missing → empty map, non-object → Err.
fn settings_map<'a>(
    v: Option<&'a Value>,
    what: &str,
    proto: &str,
) -> Result<&'a SettingsMap, String> {
    match v {
        None => Ok(&EMPTY_SETTINGS),
        Some(Value::Object(m)) => Ok(m),
        Some(_) => Err(format!("{what} must be a JSON object for {proto}")),
    }
}

static EMPTY_SETTINGS: std::sync::LazyLock<SettingsMap> = std::sync::LazyLock::new(Map::new);

/// JSON value → string (numbers accepted: `fields_to_profile` converts
/// numeric-looking form values to JSON numbers).
fn value_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn opt_string(v: Option<&Value>) -> Option<String> {
    v.and_then(value_string).filter(|s| !s.is_empty())
}

fn opt_str(v: Option<&str>) -> Option<String> {
    v.filter(|s| !s.is_empty()).map(str::to_string)
}

fn opt_text(v: Option<&Value>) -> Option<TinyText> {
    opt_string(v).map(TinyText::from)
}

fn req_string(proto: &str, key: &str, v: Option<&str>) -> Result<String, String> {
    opt_str(v).ok_or_else(|| format!("missing required field {key} for {proto}"))
}

fn opt_bool(v: Option<&Value>) -> Option<bool> {
    v.and_then(Value::as_bool)
}

fn opt_u32(proto: &str, key: &str, v: Option<&Value>) -> Result<Option<u32>, String> {
    match v {
        None => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|u| u32::try_from(u).ok())
            .map(Some)
            .ok_or_else(|| format!("invalid setting {key} for {proto}: expected u32")),
        Some(Value::String(s)) => s
            .parse::<u32>()
            .map(Some)
            .map_err(|_| format!("invalid setting {key} for {proto}: {s}")),
        Some(_) => Err(format!("invalid setting {key} for {proto}: expected u32")),
    }
}

/// Reject settings keys the form does not emit for `proto` — catches
/// form/builder drift (a new form field T17 emits without a mapper here).
fn check_keys(proto: &str, map: &SettingsMap, allowed: &[&str]) -> Result<(), String> {
    let mut unknown: Option<&str> = None;
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            unknown = Some(key.as_str());
            break;
        }
    }
    unknown.map_or(Ok(()), |key| {
        Err(format!("unknown setting {key} for {proto}"))
    })
}

/// TLS options from the shared stream keys (`sni`/`alpn`/`fingerprint`/
/// `allow_insecure` — all in `stream_settings`) plus `pin_sha256` (routed to
/// `protocol_settings` by `fields_to_profile`). Explicit form overrides only.
fn tls_opts_stream(ps: &SettingsMap, ss: &SettingsMap) -> TlsOpts {
    TlsOpts {
        sni: opt_text(ss.get("sni")),
        alpn: opt_text(ss.get("alpn")),
        fp: opt_text(ss.get("fingerprint")),
        insecure: opt_bool(ss.get("allow_insecure")),
        pin_sha256: opt_text(ps.get("pin_sha256")),
        ..Default::default()
    }
}

/// TLS options for the always-TLS protocols. The producer routes `sni`/`alpn`
/// into `stream_settings` (exact-match arm) while `insecure` stays in
/// `protocol_settings` (no stream prefix/exact match).
fn tls_opts_always_tls(ps: &SettingsMap, ss: &SettingsMap, with_alpn: bool) -> TlsOpts {
    TlsOpts {
        sni: opt_text(ss.get("sni")),
        alpn: with_alpn.then(|| opt_text(ss.get("alpn"))).flatten(),
        insecure: opt_bool(ps.get("insecure")),
        ..Default::default()
    }
}

/// The add/edit form always emits the `network` select (default "tcp") and
/// renders the ws/grpc stream fields unconditionally. A submission that fills
/// WebSocket/gRPC fields while leaving the select on tcp would otherwise
/// silently drop them (`transport_and_path` treats network=tcp as
/// authoritative — the I1 P2 regression). Reject the mismatch loudly for both
/// add and edit. Absent `network` (legacy producers) is untouched: key
/// presence still infers the transport.
fn validate_network_vs_transport_fields(
    proto: &str,
    ps: &SettingsMap,
    ss: &SettingsMap,
) -> Result<(), String> {
    let network = ps.get("network").and_then(value_string);
    if !network
        .as_deref()
        .is_some_and(|n| n == "tcp" || n.is_empty())
    {
        return Ok(());
    }
    let ws_set = opt_string(ss.get("ws.path")).is_some() || opt_string(ss.get("ws.host")).is_some();
    let grpc_set = opt_string(ss.get("grpc.serviceName")).is_some();
    if ws_set || grpc_set {
        return Err(format!(
            "network must be ws/grpc when WebSocket/gRPC fields are set for {proto}"
        ));
    }
    Ok(())
}

/// Transport from the form's stream keys and `network` select. The form's
/// `network` select is routed by `fields_to_parsed` into
/// `protocol_settings.network` and is authoritative when present: network=kcp
/// selects `Kcp`, network=tcp overrides leftover `ws.*`/`grpc.*` keys, and
/// the `ws.*`/`grpc.*` payload keys still fill their configs. When `network`
/// is absent (legacy producers) transport is inferred from key presence;
/// defaults to Tcp. Returns the top-level `path` the vless/vmess configs
/// carry for reconstruct parity (ws path / grpc serviceName).
fn transport_and_path(ps: &SettingsMap, ss: &SettingsMap) -> (TransportConfig, Option<TinyText>) {
    let ws_payload = || {
        TransportConfig::Ws(WebSocketConfig {
            path: opt_text(ss.get("ws.path")),
            host: opt_text(ss.get("ws.host")),
            ..Default::default()
        })
    };
    let grpc_payload = || {
        // serviceName doubles as the gRPC path (share-link convention) so
        // reconstruct emits `path=` while the builders emit `serviceName`.
        let sn = opt_string(ss.get("grpc.serviceName"));
        TransportConfig::Grpc(GrpcConfig {
            service_name: sn.clone().map(TinyText::from),
            path: sn.map(TinyText::from),
            ..Default::default()
        })
    };
    let transport = match opt_string(ps.get("network")).as_deref() {
        // Explicit form selection — authoritative over key presence.
        Some("ws" | "websocket") => ws_payload(),
        Some("grpc") => grpc_payload(),
        // kcp/http/h2/quic (and httpupgrade) map to their typed variants via
        // the parser's transport mapping; unknown values degrade to Tcp.
        Some(other) => TransportConfig::from_type_and_path(Some(other), None)
            .ok()
            .flatten()
            .unwrap_or(TransportConfig::Tcp),
        // No `network` key (legacy producers): infer from ws/grpc keys.
        None if ss.contains_key("ws.path") || ss.contains_key("ws.host") => ws_payload(),
        None if opt_string(ss.get("grpc.serviceName")).is_some() => grpc_payload(),
        None => TransportConfig::Tcp,
    };
    let path = match &transport {
        TransportConfig::Ws(ws) => ws.path.clone(),
        TransportConfig::Grpc(g) => g.path.clone(),
        _ => None,
    };
    (transport, path)
}

/// Endpoint essentials from the form's address/port — host-kind detection
/// follows the URL parsers (Ipv4/Ipv6 literal vs Dns).
fn endpoint_from(address: &str, port: u16) -> EndpointEssentials {
    let host_type = match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => HostKind::Ipv4,
        Ok(std::net::IpAddr::V6(_)) => HostKind::Ipv6,
        Err(_) => HostKind::Dns,
    };
    EndpointEssentials {
        host: address.to_string(),
        host_type,
        port,
        ports: vec![port],
    }
}
/// Parse a port spec ("443", "1000-2000,3000") into a flattened list.
///
/// A single range may not exceed [`MAX_PORT_RANGE`] ports, and the flattened
/// total may not exceed [`MAX_PORT_TOTAL`]: an unbounded `lo..=hi` extend is
/// a trivial heap-exhaustion vector through a pasted form value (u16 space
/// tops out at 65535 entries, ~128 KiB — the caps below keep pathological
/// specs cheap while real hop lists stay far under them).
fn parse_port_spec(proto: &str, spec: &str) -> Result<Vec<u16>, String> {
    const MAX_PORT_RANGE: u32 = 4096;
    const MAX_PORT_TOTAL: usize = 8192;
    let invalid = |part: &str| format!("invalid setting ports for {proto}: {part}");
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo = lo.trim().parse::<u16>().map_err(|_| invalid(part))?;
            let hi = hi.trim().parse::<u16>().map_err(|_| invalid(part))?;
            if lo > hi {
                return Err(invalid(part));
            }
            let span = u32::from(hi) - u32::from(lo) + 1;
            if span > MAX_PORT_RANGE || out.len() + span as usize > MAX_PORT_TOTAL {
                return Err(invalid(part));
            }
            out.extend(lo..=hi);
        } else {
            if out.len() >= MAX_PORT_TOTAL {
                return Err(invalid(part));
            }
            out.push(part.parse::<u16>().map_err(|_| invalid(part))?);
        }
    }
    Ok(out)
}

/// Cipher-aware kind routing, mirroring `SsConfig::try_parse_proto`.
fn kind_for_ss_method(method: &str) -> ProtocolKind {
    if method.starts_with("2022-blake3-") {
        ProtocolKind::Shadowsocks2022
    } else {
        ProtocolKind::Shadowsocks
    }
}

/// Outbound-only / non-URL kinds: raw settings passthrough in a
/// [`PlaceholderConfig`] (the legacy raw-settings passthrough), endpoints
/// from address/port. Redirect/TProxy/Mixed get their
/// dedicated [`ProtocolConfig`] variants; the other outbound-only kinds share
/// the Mixed placeholder variant (the only one that can carry them — the
/// `proto_kind` stays the real kind).
fn placeholder_parsed(
    proto_kind: ProtocolKind,
    address: &str,
    port: u16,
    settings: &Value,
) -> Result<ParsedProto, String> {
    let settings_json = serde_json::to_vec(settings).map_err(|e| {
        format!(
            "failed to serialize settings for {}: {e}",
            proto_kind.as_str()
        )
    })?;
    let placeholder = PlaceholderConfig::new(proto_kind.as_str().to_string(), settings_json);
    let config = match proto_kind {
        ProtocolKind::Redirect => ProtocolConfig::Redirect(placeholder),
        ProtocolKind::TProxy => ProtocolConfig::TProxy(placeholder),
        _ => ProtocolConfig::Mixed(placeholder),
    };
    Ok(ParsedProto {
        endpoints: vec![endpoint_from(address, port)],
        protocol: ProtocolEssentials {
            proto_kind,
            core_type: core_mapping::resolve_core(proto_kind, None, None),
            config,
        },
    })
}

// ── per-protocol mappers ────────────────────────────────────────────────

fn vless_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    ss: &SettingsMap,
) -> Result<VlessConfig, String> {
    check_keys(
        "vless",
        ps,
        &[
            // The producer routes the form's `network` select here (I1).
            "network",
            "flow",
            "mux",
            "mux_concurrency",
            "pin_sha256",
            "ech.enable",
            "ech.config",
            "fragment.enable",
            "fragment.packets",
            "fragment.length",
            "fragment.interval",
        ],
    )?;
    check_keys(
        "vless",
        ss,
        &[
            "fingerprint",
            "alpn",
            "sni",
            "allow_insecure",
            "tls.enable",
            "ws.path",
            "ws.host",
            "grpc.serviceName",
        ],
    )?;
    validate_network_vs_transport_fields("vless", ps, ss)?;
    let uuid = req_string("vless", "user_id", user_id)?;
    let (transport, path) = transport_and_path(ps, ss);
    let security = tls_security_from_stream(ps, ss);
    Ok(VlessConfig {
        uuid,
        uuid_origin: None,
        security,
        transport,
        // The form has no encryption field; None is the parser default
        // ("none").
        encryption: None,
        flow: opt_text(ps.get("flow")),
        // The form states mux as a bool plus an optional cap: the same shape the
        // share links carry, so a form row and an imported row of the same
        // server agree (an absent cap means the ecosystem default).
        mux: opt_bool(ps.get("mux")).map(|on| {
            let cap = opt_string(ps.get("mux_concurrency"))
                .and_then(|c| c.parse::<i64>().ok())
                .unwrap_or(8);
            VlessMux::from_i64(if on { cap } else { 0 })
        }),
        path,
        splice: None,
        remarks: None,
    })
}

/// TLS security for vless/vmess: enabled only by the explicit `tls.enable`
/// form flag; `ech.*` (when enabled) maps to `TlsOpts::ech`. `reality.show`,
/// `fragment.*` and `tcp.headerType` have no typed fields — accepted and
/// ignored (see the T12 report for T17).
fn tls_security_from_stream(ps: &SettingsMap, ss: &SettingsMap) -> SecurityConfig {
    if opt_bool(ss.get("tls.enable")).unwrap_or(false) {
        let mut opts = tls_opts_stream(ps, ss);
        if opt_bool(ps.get("ech.enable")).unwrap_or(false) {
            opts.ech = opt_text(ps.get("ech.config"));
        }
        SecurityConfig {
            tls: Some(TlsConfig::Tls(opts)),
            enc: None,
        }
    } else {
        SecurityConfig::default()
    }
}

fn vmess_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    ss: &SettingsMap,
) -> Result<VmessConfig, String> {
    check_keys(
        "vmess",
        ps,
        &[
            // The producer routes the form's `network` select here (I1).
            "network",
            "pin_sha256",
            "ech.enable",
            "ech.config",
            "fragment.enable",
            "fragment.packets",
            "fragment.length",
            "fragment.interval",
        ],
    )?;
    check_keys(
        "vmess",
        ss,
        &[
            "tls.enable",
            "fingerprint",
            "alpn",
            "sni",
            "allow_insecure",
            "ws.path",
            "ws.host",
            "grpc.serviceName",
            "tcp.headerType",
            // Producer routes every `reality.*` key to stream_settings; the
            // form always emits `reality.show=false` (non-empty default).
            // Accepted decoration key — no typed Reality fields exist on the
            // form (no pbk/sid), so it is deliberately dropped.
            "reality.show",
        ],
    )?;
    validate_network_vs_transport_fields("vmess", ps, ss)?;
    let uuid = req_string("vmess", "user_id", user_id)?;
    let (transport, path) = transport_and_path(ps, ss);
    let mut security = tls_security_from_stream(ps, ss);
    // Encryption is a Profile column in fields_to_profile (never lands in the
    // settings JSON); "auto" is the parser default and what the vmess builder
    // emits.
    security.enc = Some(TinyText::from("auto"));
    Ok(VmessConfig {
        uuid,
        security,
        transport,
        alter_id: None,
        path,
        remarks: None,
    })
}

fn trojan_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    ss: &SettingsMap,
) -> Result<TrojanConfig, String> {
    check_keys(
        "trojan",
        ps,
        &[
            "flow",
            "pin_sha256",
            "ech.enable",
            "ech.config",
            "fragment.enable",
            "fragment.packets",
            "fragment.length",
            "fragment.interval",
        ],
    )?;
    check_keys(
        "trojan",
        ss,
        &["sni", "alpn", "fingerprint", "allow_insecure"],
    )?;
    let password = req_string("trojan", "password", user_id)?;
    // Trojan always uses TLS (parser default); sni/alpn/fp/insecure/pin_sha256
    // from the form go into the TlsOpts.
    let mut opts = tls_opts_stream(ps, ss);
    if opt_bool(ps.get("ech.enable")).unwrap_or(false) {
        opts.ech = opt_text(ps.get("ech.config"));
    }
    Ok(TrojanConfig {
        password,
        security: SecurityConfig {
            tls: Some(TlsConfig::Tls(opts)),
            enc: None,
        },
        transport: TransportConfig::Tcp,
        path: None,
        remarks: None,
    })
}

fn ss_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    _ss: &SettingsMap,
) -> Result<SsConfig, String> {
    check_keys("ss", ps, &["method", "plugin", "plugin_opts"])?;
    let method = req_string("ss", "method", opt_string(ps.get("method")).as_deref())?;
    let password = req_string("ss", "password", user_id)?;
    // The SAME constructor the share-link and Clash paths use, so the form is
    // not a second dialect — and a `plugin_opts` with no `plugin` stores an
    // empty name instead of losing the options.
    let plugin_name = opt_string(ps.get("plugin"));
    let plugin_opts = opt_string(ps.get("plugin_opts")).unwrap_or_default();
    let plugin = (plugin_name.is_some() || !plugin_opts.is_empty())
        .then(|| PluginSpec::from_parts(plugin_name.as_deref(), &plugin_opts));
    Ok(SsConfig {
        method: TinyText::from(method),
        password,
        security: SecurityConfig::default(),
        remarks: None,
        plugin,
    })
}

fn socks_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    _ss: &SettingsMap,
) -> Result<Socks5Config, String> {
    check_keys("socks", ps, &["username", "udp"])?;
    Ok(Socks5Config {
        username: opt_string(ps.get("username")),
        // The form's `password` routes to the top-level `user_id`.
        password: opt_str(user_id),
        security: SecurityConfig::default(),
        remarks: None,
    })
}

fn http_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    _ss: &SettingsMap,
) -> Result<HttpClientConfig, String> {
    check_keys("http", ps, &["username", "tls", "path"])?;
    let security = if opt_bool(ps.get("tls")).unwrap_or(false) {
        SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts::default())),
            enc: None,
        }
    } else {
        SecurityConfig::default()
    };
    Ok(HttpClientConfig {
        username: opt_string(ps.get("username")),
        password: opt_str(user_id),
        security,
        remarks: None,
    })
}

fn tuic_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    ss: &SettingsMap,
) -> Result<TuicConfig, String> {
    check_keys(
        "tuic",
        ps,
        &[
            "password",
            "congestion_control",
            "udp_relay_mode",
            "insecure",
        ],
    )?;
    // sni/alpn route to stream_settings (producer exact-match arm).
    check_keys("tuic", ss, &["sni", "alpn"])?;
    let uuid = req_string("tuic", "uuid", user_id)?;
    Ok(TuicConfig {
        uuid,
        password: opt_string(ps.get("password")).unwrap_or_default(),
        congestion_control: opt_text(ps.get("congestion_control")),
        udp_relay_mode: opt_text(ps.get("udp_relay_mode")),
        // Tuic always uses TLS (parser default).
        security: SecurityConfig {
            tls: Some(TlsConfig::Tls(tls_opts_always_tls(ps, ss, true))),
            enc: None,
        },
        remarks: None,
    })
}

fn wireguard_from_form(
    _user_id: Option<&str>,
    ps: &SettingsMap,
    _ss: &SettingsMap,
) -> Result<WireguardConfig, String> {
    check_keys(
        "wireguard",
        ps,
        &[
            "private_key",
            "public_key",
            "endpoint",
            "allowed_ips",
            "dns",
            "mtu",
            "workers",
            "preshared_key",
            "reserved",
            "persistent_keepalive",
            "udp_timeout",
            "system",
            "peers",
        ],
    )?;
    let private_key = req_string(
        "wireguard",
        "private_key",
        opt_string(ps.get("private_key")).as_deref(),
    )?;
    let public_key = req_string(
        "wireguard",
        "public_key",
        opt_string(ps.get("public_key")).as_deref(),
    )?;
    let dns = opt_string(ps.get("dns"))
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect::<Vec<String>>()
        })
        .filter(|v| !v.is_empty());
    let persistent_keepalive = opt_u32(
        "wireguard",
        "persistent_keepalive",
        ps.get("persistent_keepalive"),
    )?;
    Ok(WireguardConfig {
        private_key,
        security: SecurityConfig::default(),
        // The interface CIDR has no form field (the form's `address` is the
        // server endpoint, which lands in EndpointEssentials) — default empty.
        address: TinyText::default(),
        public_key,
        preshared_key: opt_string(ps.get("preshared_key")),
        reserved: opt_text(ps.get("reserved")),
        mtu: opt_text(ps.get("mtu")),
        persistent_keepalive,
        dns,
        remote_dns_resolve: None,
        remarks: None,
    })
}

fn hysteria2_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    ss: &SettingsMap,
) -> Result<Hysteria2Config, String> {
    check_keys(
        "hysteria2",
        ps,
        &["ports", "hop", "obfs", "obfs_password", "insecure"],
    )?;
    // sni routes to stream_settings (producer exact-match arm).
    check_keys("hysteria2", ss, &["sni"])?;
    let hop_interval = opt_u32("hysteria2", "hop", ps.get("hop"))?;
    Ok(Hysteria2Config {
        // The form's `password` routes to the top-level `user_id`.
        auth: opt_str(user_id).unwrap_or_default(),
        // Hysteria2 always uses TLS (parser default).
        security: SecurityConfig {
            tls: Some(TlsConfig::Tls(tls_opts_always_tls(ps, ss, false))),
            enc: None,
        },
        obfs: opt_text(ps.get("obfs")),
        obfs_password: opt_text(ps.get("obfs_password")),
        up: None,
        down: None,
        hop_interval,
        pin_sha256: None,
        remarks: None,
    })
}

fn hysteria1_from_form(ps: &SettingsMap, ss: &SettingsMap) -> Result<Hysteria1Config, String> {
    check_keys(
        "hysteria",
        ps,
        &[
            "protocol",
            "auth",
            "obfs",
            "up_mbps",
            "down_mbps",
            "insecure",
        ],
    )?;
    // sni routes to stream_settings (producer exact-match arm).
    check_keys("hysteria", ss, &["sni"])?;
    Ok(Hysteria1Config {
        auth: opt_string(ps.get("auth")),
        protocol: opt_text(ps.get("protocol")),
        obfs: opt_text(ps.get("obfs")),
        up_mbps: opt_u32("hysteria", "up_mbps", ps.get("up_mbps"))?,
        down_mbps: opt_u32("hysteria", "down_mbps", ps.get("down_mbps"))?,
        // Hysteria always uses TLS (parser default).
        security: SecurityConfig {
            tls: Some(TlsConfig::Tls(tls_opts_always_tls(ps, ss, false))),
            enc: None,
        },
        remarks: None,
    })
}

fn naive_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    _ss: &SettingsMap,
) -> Result<NaiveConfig, String> {
    check_keys("naive", ps, &["user", "extra_headers", "padding"])?;
    let password = req_string("naive", "password", user_id)?;
    Ok(NaiveConfig {
        username: opt_string(ps.get("user")).unwrap_or_default(),
        password,
        // Naive is always TLS (parser default).
        security: SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts::default())),
            enc: None,
        },
        remarks: None,
    })
}

fn anytls_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    ss: &SettingsMap,
) -> Result<AnyTlsConfig, String> {
    check_keys("anytls", ps, &["insecure"])?;
    // sni/alpn route to stream_settings (producer exact-match arm).
    check_keys("anytls", ss, &["sni", "alpn"])?;
    Ok(AnyTlsConfig {
        password: opt_str(user_id),
        // AnyTLS always uses TLS (parser default).
        security: SecurityConfig {
            tls: Some(TlsConfig::Tls(tls_opts_always_tls(ps, ss, true))),
            enc: None,
        },
        remarks: None,
    })
}

fn shadowtls_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    ss: &SettingsMap,
) -> Result<ShadowTlsConfig, String> {
    check_keys("shadowtls", ps, &["version"])?;
    // sni routes to stream_settings (producer exact-match arm) — it is the
    // TLS trigger for ShadowTLS (the disguise host).
    check_keys("shadowtls", ss, &["sni"])?;
    let security =
        opt_text(ss.get("sni")).map_or_else(SecurityConfig::default, |sni| SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: Some(sni),
                ..Default::default()
            })),
            enc: None,
        });
    Ok(ShadowTlsConfig {
        password: opt_str(user_id),
        version: opt_text(ps.get("version")),
        security,
        remarks: None,
    })
}

fn tor_from_form(ps: &SettingsMap, _ss: &SettingsMap) -> Result<TorConfig, String> {
    check_keys(
        "tor",
        ps,
        &["socks_port", "control_port", "control_password", "data_dir"],
    )?;
    Ok(TorConfig {
        executable_path: None,
        extra_args: None,
        data_directory: opt_string(ps.get("data_dir")),
        torrc: None,
        security: SecurityConfig::default(),
        remarks: None,
    })
}

fn ssh_from_form(ps: &SettingsMap, _ss: &SettingsMap) -> Result<SshConfig, String> {
    check_keys(
        "ssh",
        ps,
        &["host", "ssh_port", "username", "private_key", "auth_method"],
    )?;
    Ok(SshConfig {
        user: opt_string(ps.get("username")),
        password: None,
        private_key: opt_string(ps.get("private_key")),
        private_key_path: None,
        private_key_passphrase: None,
        host_key: None,
        host_key_algorithms: None,
        client_version: None,
        security: SecurityConfig::default(),
        remarks: None,
    })
}

fn tailscale_from_form(ps: &SettingsMap, _ss: &SettingsMap) -> Result<TailscaleConfig, String> {
    check_keys("tailscale", ps, &["auth_key", "control_url", "ephemeral"])?;
    Ok(TailscaleConfig {
        hostname: None,
        auth_key: opt_string(ps.get("auth_key")),
        control_url: opt_string(ps.get("control_url")),
        state_directory: None,
        ephemeral: opt_bool(ps.get("ephemeral")),
        accept_routes: None,
        exit_node: None,
        exit_node_allow_lan_access: None,
        advertise_routes: None,
        security: SecurityConfig::default(),
        remarks: None,
    })
}

fn ssr_from_form(
    user_id: Option<&str>,
    ps: &SettingsMap,
    _ss: &SettingsMap,
) -> Result<SsrConfig, String> {
    check_keys(
        "ssr",
        ps,
        &["method", "obfs", "obfs_param", "protocol", "protocol_param"],
    )?;
    let password = req_string("ssr", "password", user_id)?;
    let protocol = opt_text(ps.get("protocol")).unwrap_or_default();
    let method = opt_text(ps.get("method")).unwrap_or_default();
    let obfs = opt_text(ps.get("obfs")).unwrap_or_default();
    // Mirror the SSR parser: protocol/obfs live in both the fields and params
    // (reconstruct skips them in the query string).
    let mut params = std::collections::HashMap::new();
    params.insert("protocol".to_string(), protocol.to_string());
    params.insert("obfs".to_string(), obfs.to_string());
    if let Some(v) = opt_string(ps.get("protocol_param")) {
        params.insert("protocol_param".to_string(), v);
    }
    if let Some(v) = opt_string(ps.get("obfs_param")) {
        params.insert("obfs_param".to_string(), v);
    }
    Ok(SsrConfig {
        security: SecurityConfig::default(),
        protocol,
        method,
        obfs,
        password,
        params,
        remarks: None,
    })
}

#[cfg(test)]
mod tests {
    use leas_proto::urlx::RawUrlX;

    use super::*;
    use leas_proto::proto_spec::CoreType;
    use rstest::rstest;

    /// Row 31's form half, and the guard for the arm that was unreachable:
    /// `vless_from_form` read `mux`/`mux_concurrency` while NO field emitted
    /// them and `check_keys` rejected them as unknown — so the mapper arm could
    /// never run. This test walks the real producer path (the declared fields,
    /// through `check_keys`, into the mapper) rather than calling the mapper
    /// directly, which is exactly how the gap survived.
    /// An UNTOUCHED form row must store no mux at all. With a `"false"` default
    /// the producer would send `mux=false` for every VLESS row the user never
    /// toggled, storing the stated "no" — a different uid from the imported row
    /// for the same server, which stores `None`. The two then duplicate into two
    /// `Protocol` rows, defeating the form/import agreement the mapper's own
    /// comment claims.
    #[test]
    fn an_untouched_vless_form_row_stores_no_mux() {
        let declared = form_fields_for(ProtocolKind::Vless);
        let mux = declared
            .iter()
            .find(|f| f.key == "mux")
            .expect("the VLESS form declares a mux field");
        assert_eq!(
            mux.default, "",
            "the mux field's default must be absent, not a stated \"false\""
        );

        // Exactly what the producer does with untouched fields: skip empties, and
        // route only `ProtocolSetting` fields into `protocol_settings` (the
        // Common/StreamSetting ones go to other maps, so passing them here would
        // be rejected by `check_keys` as unknown settings).
        let mut ps = SettingsMap::new();
        for f in &declared {
            if f.default.is_empty() || f.section != FieldSection::ProtocolSetting {
                continue;
            }
            let value = if f.default == "true" {
                Value::Bool(true)
            } else if f.default == "false" {
                Value::Bool(false)
            } else if let Ok(n) = f.default.parse::<i64>() {
                Value::Number(n.into())
            } else {
                Value::String(f.default.to_string())
            };
            ps.insert(f.key.to_string(), value);
        }
        let cfg = vless_from_form(
            Some("11111111-2222-3333-4444-555555555555"),
            &ps,
            &SettingsMap::new(),
        )
        .expect("defaults-only form row");
        assert_eq!(
            cfg.mux, None,
            "an untouched form row stores no mux, matching an imported row"
        );

        // Non-vacuity: the SAME producer path with the old `"false"` default is
        // the duplicate this guards against, so assert it really does store one.
        let mut regressed = SettingsMap::new();
        regressed.insert("mux".into(), Value::Bool(false));
        let cfg = vless_from_form(
            Some("11111111-2222-3333-4444-555555555555"),
            &regressed,
            &SettingsMap::new(),
        )
        .expect("accepted");
        assert_eq!(
            cfg.mux,
            Some(VlessMux::Limited(0)),
            "a stated \"false\" IS stored — which is why the default must be absent"
        );
    }

    #[test]
    fn the_vless_mux_fields_reach_the_mapper() {
        let fields = form_fields_for(ProtocolKind::Vless);
        let names: Vec<&str> = fields.iter().map(|f| f.key).collect();
        for key in ["mux", "mux_concurrency"] {
            assert!(
                names.contains(&key),
                "the VLESS form declares no `{key}` field, so the mapper can never see it"
            );
        }

        // Exactly what the UI sends: `ops/profiles.rs:656-664` turns the field
        // buffers into typed values — "true"/"false" become `Value::Bool` and a
        // numeric buffer becomes `Value::Number`, NOT a string. (That conversion
        // is inline in the TUI crate, so it is replicated here rather than
        // called; a string here would silently read as "absent".)
        let mut ps = SettingsMap::new();
        ps.insert("mux".into(), Value::Bool(true));
        ps.insert("mux_concurrency".into(), Value::Number(16.into()));
        let cfg = vless_from_form(
            Some("11111111-2222-3333-4444-555555555555"),
            &ps,
            &SettingsMap::new(),
        )
        .expect("the producer's own keys are accepted");
        assert_eq!(
            cfg.mux,
            Some(VlessMux::Limited(16)),
            "the form's bool+cap reaches the stored mux"
        );
        // And the stated "no" is a stored state, not an absent one (spec §5.2 item 9).
        let mut off = SettingsMap::new();
        off.insert("mux".into(), Value::Bool(false));
        let cfg = vless_from_form(
            Some("11111111-2222-3333-4444-555555555555"),
            &off,
            &SettingsMap::new(),
        )
        .expect("accepted");
        assert_eq!(cfg.mux, Some(VlessMux::Limited(0)));

        // The rest of row 31's claim: the form's mux survives the EXPORT, i.e.
        // a form row and an imported row of the same server agree. Without this
        // leg the test only proved the mapper reads its own keys.
        let exported = cfg
            .reconstruct_proto(&EndpointEssentials::new("example.com", 443))
            .expect("reconstruct");
        assert!(
            exported.contains("mux="),
            "the form's mux request is exported, got {exported}"
        );
        let reimported =
            ProtocolConfig::try_parse_proto(&RawUrlX::from(exported.as_str())).expect("re-import");
        let ProtocolConfig::Vless(back) = reimported.protocol.config else {
            panic!("expected vless");
        };
        assert_eq!(
            back.mux, cfg.mux,
            "the form's mux survives form → export → import"
        );
    }

    #[test]
    fn form_fields_all_protocols() {
        for proto in &[
            ProtocolKind::Vmess,
            ProtocolKind::Vless,
            ProtocolKind::Shadowsocks,
            ProtocolKind::Shadowsocks2022,
            ProtocolKind::Socks,
            ProtocolKind::Http,
            ProtocolKind::Trojan,
            ProtocolKind::WireGuard,
            ProtocolKind::Hysteria2,
            ProtocolKind::Hysteria,
            ProtocolKind::Tuic,
            ProtocolKind::Naive,
            ProtocolKind::AnyTls,
            ProtocolKind::ShadowTls,
            ProtocolKind::Tor,
            ProtocolKind::Ssh,
            ProtocolKind::Tailscale,
            ProtocolKind::ShadowsocksR,
            ProtocolKind::DokodemoDoor,
            ProtocolKind::Freedom,
            ProtocolKind::Blackhole,
            ProtocolKind::Loopback,
            ProtocolKind::Dns,
            ProtocolKind::Redirect,
            ProtocolKind::Custom,
        ] {
            let fields = form_fields_for(*proto);
            assert!(!fields.is_empty(), "{proto} should have fields");
            // Common fields always present
            assert!(
                !fields.iter().any(|f| f.key == "remarks"),
                "{proto} should not have remarks"
            );
            assert!(
                fields.iter().any(|f| f.key == "address"),
                "{proto} missing address"
            );
            assert!(
                fields.iter().any(|f| f.key == "port"),
                "{proto} missing port"
            );
            assert!(
                fields.iter().any(|f| f.key == "core_type"),
                "{proto} missing core_type"
            );
            // No duplicate keys
            let mut keys = std::collections::HashSet::new();
            for f in &fields {
                assert!(keys.insert(f.key), "duplicate key '{}' in {}", f.key, proto);
            }
        }
    }

    #[test]
    fn form_fields_inbound_only_have_common() {
        let tproxy = form_fields_for(ProtocolKind::TProxy);
        assert_eq!(tproxy.len(), 3); // common fields (remarks removed)
        assert!(tproxy.iter().all(|f| f.section == FieldSection::Common));
        let mixed = form_fields_for(ProtocolKind::Mixed);
        assert_eq!(mixed.len(), 3);
        assert!(mixed.iter().all(|f| f.section == FieldSection::Common));
    }

    #[test]
    fn vmess_required_fields() {
        let fields = form_fields_for(ProtocolKind::Vmess);
        let user_id = fields.iter().find(|f| f.key == "user_id").unwrap();
        assert!(user_id.required);
        assert!(matches!(user_id.field_type, FormFieldType::Text));
        let addr = fields.iter().find(|f| f.key == "address").unwrap();
        assert!(addr.required);
    }

    #[test]
    fn url_scheme_mapping() {
        assert_eq!(url_scheme_for(ProtocolKind::Vmess), "vmess://");
        assert_eq!(url_scheme_for(ProtocolKind::Vless), "vless://");
        assert_eq!(url_scheme_for(ProtocolKind::Shadowsocks), "ss://");
        assert_eq!(url_scheme_for(ProtocolKind::Trojan), "trojan://");
        assert_eq!(url_scheme_for(ProtocolKind::WireGuard), "wireguard://");
        assert_eq!(url_scheme_for(ProtocolKind::Freedom), "");
    }

    // ── T12: typed config builders ────────────────────────────────────

    /// Replicates `fields_to_parsed` (crates/leas/src/ops/profiles.rs)
    /// EXACTLY: empty values skipped; `user_id`/`password`/`uuid` → top-level
    /// `user_id`; `network` → `protocol_settings` (the vmess/vless transport
    /// select; placeholder kinds accept any key in their raw passthrough, so
    /// the unconditional routing is equivalent for them — the real producer
    /// gates it to Vless/Vmess); `address`/`port`/`core_type`/`security` are
    /// profile columns (never in the maps); `tls.`/`ws.`/`grpc.`/`reality.`/
    /// `tcp.` prefixes + exact `sni`/`alpn`/`fingerprint`/`allow_insecure` →
    /// `stream_settings`; everything else → `protocol_settings`. "true"/
    /// "false" → bool, integers → number.
    fn producer_settings(fields: &[(&str, &str)]) -> Value {
        let mut proto_map = Map::new();
        let mut stream_map = Map::new();
        let mut user_id: Option<String> = None;
        for &(key, value) in fields {
            if value.is_empty() {
                continue;
            }
            let json_val = if value == "true" {
                Value::Bool(true)
            } else if value == "false" {
                Value::Bool(false)
            } else if let Ok(n) = value.parse::<i64>() {
                Value::Number(n.into())
            } else {
                Value::String(value.to_string())
            };
            match key {
                "user_id" | "password" | "uuid" => user_id = Some(value.to_string()),
                "network" => {
                    proto_map.insert(key.to_string(), json_val);
                }
                "address" | "port" | "core_type" | "security" => {}
                _ if key.starts_with("tls.")
                    || key.starts_with("ws.")
                    || key.starts_with("grpc.")
                    || key.starts_with("reality.")
                    || key.starts_with("tcp.")
                    || key == "sni"
                    || key == "alpn"
                    || key == "fingerprint"
                    || key == "allow_insecure" =>
                {
                    stream_map.insert(key.to_string(), json_val);
                }
                _ => {
                    proto_map.insert(key.to_string(), json_val);
                }
            }
        }
        let mut obj = Map::new();
        if let Some(u) = user_id {
            obj.insert("user_id".into(), Value::String(u));
        }
        if !proto_map.is_empty() {
            obj.insert("protocol_settings".into(), Value::Object(proto_map));
        }
        if !stream_map.is_empty() {
            obj.insert("stream_settings".into(), Value::Object(stream_map));
        }
        Value::Object(obj)
    }

    /// Direct settings construction for negative tests (unknown-key
    /// rejection) where producer routing cannot express the bad key.
    fn raw_settings(user_id: Option<&str>, ps: &[(&str, Value)], ss: &[(&str, Value)]) -> Value {
        let mut obj = Map::new();
        if let Some(u) = user_id {
            obj.insert("user_id".into(), Value::String(u.to_string()));
        }
        if !ps.is_empty() {
            obj.insert(
                "protocol_settings".into(),
                Value::Object(ps.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()),
            );
        }
        if !ss.is_empty() {
            obj.insert(
                "stream_settings".into(),
                Value::Object(ss.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()),
            );
        }
        Value::Object(obj)
    }

    fn built(kind: ProtocolKind, settings: &Value) -> ParsedProto {
        build_typed_config(kind, "1.2.3.4", 443, settings).expect("build_typed_config")
    }

    fn config_json(parsed: &ParsedProto) -> Value {
        serde_json::to_value(&parsed.protocol.config).expect("config serializable")
    }

    #[test]
    fn build_vless_ws_tls() {
        let parsed = built(
            ProtocolKind::Vless,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("flow", "xtls-rprx-vision"),
                ("tls.enable", "true"),
                ("sni", "real.example.com"),
                ("alpn", "h2,http/1.1"),
                ("fingerprint", "chrome"),
                ("allow_insecure", "false"),
                ("ws.path", "/ws"),
                ("ws.host", "cdn.example.com"),
            ]),
        );
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Vless);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let ProtocolConfig::Vless(c) = &parsed.protocol.config else {
            panic!("expected Vless config");
        };
        assert_eq!(c.uuid, "6202b230-417c-4d8e-b624-0f71afa9c75d");
        assert_eq!(c.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(c.encryption, None);
        let TransportConfig::Ws(ws) = &c.transport else {
            panic!("expected ws transport");
        };
        assert_eq!(ws.path.as_deref(), Some("/ws"));
        // Explicit form override host — host-free rule allows it.
        assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
        let Some(TlsConfig::Tls(tls)) = &c.security.tls else {
            panic!("expected tls security");
        };
        assert_eq!(tls.sni.as_deref(), Some("real.example.com"));
        assert_eq!(tls.alpn.as_deref(), Some("h2,http/1.1"));
        assert_eq!(tls.fp.as_deref(), Some("chrome"));
        assert_eq!(tls.insecure, Some(false));
        assert_eq!(parsed.endpoints.len(), 1);
        assert_eq!(parsed.endpoints[0].host, "1.2.3.4");
        assert_eq!(parsed.endpoints[0].port, 443);
        assert_eq!(parsed.endpoints[0].host_type, HostKind::Ipv4);
    }

    #[test]
    fn build_vmess_ws_tls_enc_auto() {
        // Producer routes reality.show AND tcp.headerType to stream_settings;
        // both must be accepted (decoration keys), not rejected.
        let parsed = built(
            ProtocolKind::Vmess,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("reality.show", "false"),
                ("fragment.enable", "false"),
                ("tls.enable", "true"),
                ("sni", "real.example.com"),
                ("ws.path", "/ws"),
                ("tcp.headerType", "none"),
            ]),
        );
        let ProtocolConfig::Vmess(c) = &parsed.protocol.config else {
            panic!("expected Vmess config");
        };
        assert_eq!(c.uuid, "6202b230-417c-4d8e-b624-0f71afa9c75d");
        // Encryption is a Profile column in fields_to_profile; mapper defaults
        // to the parser's "auto".
        assert_eq!(c.security.enc.as_deref(), Some("auto"));
        let TransportConfig::Ws(ws) = &c.transport else {
            panic!("expected ws transport (ws.path present)");
        };
        assert_eq!(ws.path.as_deref(), Some("/ws"));
        assert!(c.security.tls.is_some());
    }

    #[test]
    fn build_vless_defaults_tcp_no_tls() {
        let parsed = built(
            ProtocolKind::Vless,
            &producer_settings(&[("user_id", "uuid-here")]),
        );
        let ProtocolConfig::Vless(c) = &parsed.protocol.config else {
            panic!("expected Vless config");
        };
        assert!(matches!(c.transport, TransportConfig::Tcp));
        assert!(c.security.is_empty());
    }

    #[test]
    fn build_vless_grpc_service_name() {
        let parsed = built(
            ProtocolKind::Vless,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("grpc.serviceName", "myservice"),
            ]),
        );
        let ProtocolConfig::Vless(c) = &parsed.protocol.config else {
            panic!("expected Vless config");
        };
        let TransportConfig::Grpc(g) = &c.transport else {
            panic!("expected grpc transport");
        };
        assert_eq!(g.service_name.as_deref(), Some("myservice"));
        // path doubles as serviceName (share-link convention).
        assert_eq!(c.path.as_deref(), Some("myservice"));
    }

    #[test]
    fn build_vless_network_ws_with_path() {
        // The form's `network` select routes to protocol_settings.network
        // (I1); network=ws selects Ws even though ws.* keys also present.
        let parsed = built(
            ProtocolKind::Vless,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("network", "ws"),
                ("ws.path", "/ws"),
                ("ws.host", "cdn.example.com"),
            ]),
        );
        let ProtocolConfig::Vless(c) = &parsed.protocol.config else {
            panic!("expected Vless config");
        };
        let TransportConfig::Ws(ws) = &c.transport else {
            panic!("expected ws transport (network=ws)");
        };
        assert_eq!(ws.path.as_deref(), Some("/ws"));
        assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(c.path.as_deref(), Some("/ws"));
    }

    #[test]
    fn build_vless_network_tcp_with_ws_path_errors() {
        // The add form initializes `network` to "tcp" (default select) and
        // renders ws.path unconditionally, so a user who fills WebSocket
        // Path but leaves the Network select untouched would silently get a
        // Tcp transport with the path discarded. Validation must reject the
        // mismatch loudly; selecting ws builds the Ws transport with the
        // path.
        let settings = producer_settings(&[
            ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
            ("network", "tcp"),
            ("ws.path", "/x"),
        ]);
        let err = build_typed_config(ProtocolKind::Vless, "1.2.3.4", 443, &settings)
            .expect_err("network=tcp with ws.path must be rejected");
        assert_eq!(
            err,
            "network must be ws/grpc when WebSocket/gRPC fields are set for vless"
        );

        let parsed = built(
            ProtocolKind::Vless,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("network", "ws"),
                ("ws.path", "/x"),
            ]),
        );
        let ProtocolConfig::Vless(c) = &parsed.protocol.config else {
            panic!("expected Vless config");
        };
        let TransportConfig::Ws(ws) = &c.transport else {
            panic!("expected ws transport (network=ws)");
        };
        assert_eq!(ws.path.as_deref(), Some("/x"));
        assert_eq!(c.path.as_deref(), Some("/x"));
    }

    #[test]
    fn build_vless_network_kcp() {
        // network=kcp selects the Kcp variant (no ws/grpc keys involved).
        let parsed = built(
            ProtocolKind::Vless,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("network", "kcp"),
            ]),
        );
        let ProtocolConfig::Vless(c) = &parsed.protocol.config else {
            panic!("expected Vless config");
        };
        assert!(matches!(c.transport, TransportConfig::Kcp(_)));
        assert_eq!(c.path, None);
    }

    #[test]
    fn build_vmess_network_tcp_with_ws_fields_errors() {
        // network=tcp is authoritative in transport_and_path, but the form
        // defaults the select to "tcp" while rendering ws fields
        // unconditionally — a submission with both must fail loudly instead
        // of silently discarding the ws values (the I1 P2 add-flow
        // regression).
        let settings = producer_settings(&[
            ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
            ("network", "tcp"),
            ("ws.path", "/stale"),
            ("ws.host", "old.example.com"),
        ]);
        let err = build_typed_config(ProtocolKind::Vmess, "1.2.3.4", 443, &settings)
            .expect_err("network=tcp with ws fields must be rejected");
        assert_eq!(
            err,
            "network must be ws/grpc when WebSocket/gRPC fields are set for vmess"
        );
    }

    #[test]
    fn build_vless_network_h2_maps_http() {
        // h2 has no dedicated TransportConfig variant — maps to Http (the
        // closest real variant, same as the parser's from_type_and_path).
        let parsed = built(
            ProtocolKind::Vless,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("network", "h2"),
            ]),
        );
        let ProtocolConfig::Vless(c) = &parsed.protocol.config else {
            panic!("expected Vless config");
        };
        assert!(matches!(c.transport, TransportConfig::Http(_)));
    }

    #[test]
    fn build_vless_network_quic() {
        let parsed = built(
            ProtocolKind::Vless,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("network", "quic"),
            ]),
        );
        let ProtocolConfig::Vless(c) = &parsed.protocol.config else {
            panic!("expected Vless config");
        };
        assert!(matches!(c.transport, TransportConfig::Quic));
    }

    #[test]
    fn build_vless_network_unknown_falls_back_tcp() {
        // A raw (non-producer) settings payload with an unknown network value
        // degrades to Tcp instead of erroring — same policy as the parser.
        let raw = raw_settings(
            Some("uuid"),
            &[("network", Value::String("bogus".into()))],
            &[],
        );
        let parsed = built(ProtocolKind::Vless, &raw);
        let ProtocolConfig::Vless(c) = &parsed.protocol.config else {
            panic!("expected Vless config");
        };
        assert!(matches!(c.transport, TransportConfig::Tcp));
    }

    #[test]
    fn build_ss_aead_resolves_xray() {
        let parsed = built(
            ProtocolKind::Shadowsocks,
            &producer_settings(&[
                ("user_id", "passw0rd"),
                ("method", "aes-256-gcm"),
                ("plugin", "obfs-local"),
                ("plugin_opts", "obfs=http;obfs-host=example.com"),
            ]),
        );
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Shadowsocks);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let ProtocolConfig::Ss(c) = &parsed.protocol.config else {
            panic!("expected Ss config");
        };
        assert_eq!(c.method.as_str(), "aes-256-gcm");
        assert_eq!(c.password, "passw0rd");
        let plugin = c
            .plugin
            .as_ref()
            .expect("the form's plugin fields are stored");
        assert_eq!(plugin.name.as_str(), "obfs-local");
        assert_eq!(plugin.mode, leas_proto::proto_spec::PluginMode::Http);
        assert_eq!(plugin.host.as_deref(), Some("example.com"));
        // The form goes through the SAME constructor as the share-link path, so
        // this row is byte-identical to the imported form of the same options.
        let imported = leas_proto::proto_spec::SsConfig::try_parse_proto(
            &leas_proto::urlx::RawUrlX::from(
                "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@h:1?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com",
            ),
        )
        .expect("parse the equivalent URL");
        let ProtocolConfig::Ss(imported) = imported.protocol.config else {
            panic!("expected Ss config");
        };
        assert_eq!(
            imported.plugin.as_ref(),
            c.plugin.as_ref(),
            "form and URL rows must be one row"
        );
    }

    #[test]
    fn build_ss_2022_method_kind_and_core() {
        let parsed = built(
            ProtocolKind::Shadowsocks,
            &producer_settings(&[
                ("user_id", "passw0rd"),
                ("method", "2022-blake3-aes-128-gcm"),
            ]),
        );
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Shadowsocks2022);
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
    }

    #[test]
    fn build_ss_legacy_method_resolves_singbox() {
        let parsed = built(
            ProtocolKind::Shadowsocks,
            &producer_settings(&[("user_id", "passw0rd"), ("method", "aes-256-cfb")]),
        );
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        assert_eq!(parsed.protocol.proto_kind, ProtocolKind::Shadowsocks);
    }

    #[test]
    fn build_trojan_tls() {
        let parsed = built(
            ProtocolKind::Trojan,
            &producer_settings(&[
                ("user_id", "humanity"),
                ("flow", "xtls-rprx-vision"),
                ("sni", "real.example.com"),
                ("alpn", "h2"),
                ("fingerprint", "chrome"),
                ("allow_insecure", "true"),
            ]),
        );
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let ProtocolConfig::Trojan(c) = &parsed.protocol.config else {
            panic!("expected Trojan config");
        };
        assert_eq!(c.password, "humanity");
        assert!(matches!(c.transport, TransportConfig::Tcp));
        // Trojan always uses TLS.
        let Some(TlsConfig::Tls(tls)) = &c.security.tls else {
            panic!("expected tls security");
        };
        assert_eq!(tls.sni.as_deref(), Some("real.example.com"));
        assert_eq!(tls.insecure, Some(true));
    }

    #[test]
    fn build_socks() {
        let parsed = built(
            ProtocolKind::Socks,
            &producer_settings(&[
                ("user_id", "secret"),
                ("username", "alice"),
                ("udp", "true"),
            ]),
        );
        let ProtocolConfig::Socks(c) = &parsed.protocol.config else {
            panic!("expected Socks config");
        };
        assert_eq!(c.username.as_deref(), Some("alice"));
        // The form's `password` routes to top-level `user_id`.
        assert_eq!(c.password.as_deref(), Some("secret"));
    }

    #[test]
    fn build_http_tls() {
        let parsed = built(
            ProtocolKind::Http,
            &producer_settings(&[
                ("user_id", "secret"),
                ("username", "alice"),
                ("tls", "true"),
                ("path", "/proxy"),
            ]),
        );
        let ProtocolConfig::Http(c) = &parsed.protocol.config else {
            panic!("expected Http config");
        };
        assert_eq!(c.username.as_deref(), Some("alice"));
        assert_eq!(c.password.as_deref(), Some("secret"));
        assert!(c.security.tls.is_some());
    }

    #[test]
    fn build_wireguard() {
        let parsed = built(
            ProtocolKind::WireGuard,
            &producer_settings(&[
                ("private_key", "aGVsbG8="),
                ("public_key", "d29ybGQ="),
                ("preshared_key", "cHNr"),
                ("reserved", "0,1,2"),
                ("mtu", "1420"),
                ("dns", "1.1.1.1,8.8.8.8"),
                ("persistent_keepalive", "25"),
            ]),
        );
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let ProtocolConfig::Wireguard(c) = &parsed.protocol.config else {
            panic!("expected Wireguard config");
        };
        assert_eq!(c.private_key, "aGVsbG8=");
        assert_eq!(c.public_key, "d29ybGQ=");
        assert_eq!(c.preshared_key.as_deref(), Some("cHNr"));
        assert_eq!(c.reserved.as_deref(), Some("0,1,2"));
        assert_eq!(c.mtu.as_deref(), Some("1420"));
        assert_eq!(c.persistent_keepalive, Some(25));
        assert_eq!(
            c.dns.as_deref(),
            Some(&["1.1.1.1".to_string(), "8.8.8.8".to_string()][..])
        );
    }

    #[test]
    fn build_hysteria2_with_ports() {
        let parsed = built(
            ProtocolKind::Hysteria2,
            &producer_settings(&[
                ("user_id", "token"),
                ("ports", "1000-1002,2000"),
                ("hop", "5"),
                ("obfs", "salamander"),
                ("obfs_password", "obfs-secret"),
                ("sni", "real.example.com"),
                ("insecure", "true"),
            ]),
        );
        assert_eq!(parsed.protocol.core_type, CoreType::Xray);
        let ProtocolConfig::Hysteria2(c) = &parsed.protocol.config else {
            panic!("expected Hysteria2 config");
        };
        assert_eq!(c.auth, "token");
        assert_eq!(c.obfs.as_deref(), Some("salamander"));
        assert_eq!(c.obfs_password.as_deref(), Some("obfs-secret"));
        assert_eq!(c.hop_interval, Some(5));
        let Some(TlsConfig::Tls(tls)) = &c.security.tls else {
            panic!("expected tls security");
        };
        assert_eq!(tls.sni.as_deref(), Some("real.example.com"));
        assert_eq!(tls.insecure, Some(true));
        // The form's `ports` hop spec flattens onto endpoints[0].
        assert_eq!(parsed.endpoints[0].port, 1000);
        assert_eq!(parsed.endpoints[0].ports, vec![1000, 1001, 1002, 2000]);
    }

    #[test]
    fn build_hysteria1() {
        let parsed = built(
            ProtocolKind::Hysteria,
            &producer_settings(&[
                ("auth", "token"),
                ("protocol", "udp"),
                ("obfs", "salamander"),
                ("up_mbps", "100"),
                ("down_mbps", "200"),
                ("sni", "real.example.com"),
            ]),
        );
        let ProtocolConfig::Hysteria1(c) = &parsed.protocol.config else {
            panic!("expected Hysteria1 config");
        };
        assert_eq!(c.auth.as_deref(), Some("token"));
        assert_eq!(c.protocol.as_deref(), Some("udp"));
        assert_eq!(c.up_mbps, Some(100));
        assert_eq!(c.down_mbps, Some(200));
        assert!(c.security.tls.is_some());
    }

    #[test]
    fn build_tuic() {
        // NOTE: no `password` field here — the producer routes a key literally
        // named `password` to the top-level `user_id` (clobbering `uuid`; see
        // tuic_password_collides_with_uuid / F6 in the T12 report).
        let parsed = built(
            ProtocolKind::Tuic,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("congestion_control", "bbr"),
                ("udp_relay_mode", "native"),
                ("sni", "real.example.com"),
                ("alpn", "h3"),
                ("insecure", "false"),
            ]),
        );
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        let ProtocolConfig::Tuic(c) = &parsed.protocol.config else {
            panic!("expected Tuic config");
        };
        assert_eq!(c.uuid, "6202b230-417c-4d8e-b624-0f71afa9c75d");
        assert_eq!(c.password, "");
        assert_eq!(c.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(c.udp_relay_mode.as_deref(), Some("native"));
        let Some(TlsConfig::Tls(tls)) = &c.security.tls else {
            panic!("expected tls security");
        };
        assert_eq!(tls.sni.as_deref(), Some("real.example.com"));
        assert_eq!(tls.alpn.as_deref(), Some("h3"));
        assert_eq!(tls.insecure, Some(false));
    }

    #[test]
    fn tuic_password_collides_with_uuid() {
        // F6 (T17 producer fix): fields_to_profile routes BOTH `uuid` and
        // `password` (exact key names) to the top-level `user_id`; the later
        // field in form order (`password`) wins. The mapper reads `user_id`
        // into the config's `uuid` field per the settings contract — the
        // collision is upstream and must be fixed in the producer. Pinned
        // here so the behavior is explicit.
        let settings = producer_settings(&[
            ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
            ("password", "pw"),
        ]);
        let parsed = built(ProtocolKind::Tuic, &settings);
        let ProtocolConfig::Tuic(c) = &parsed.protocol.config else {
            panic!("expected Tuic config");
        };
        assert_eq!(c.uuid, "pw", "last field wins in the producer's user_id");
        assert_eq!(c.password, "");
    }

    #[test]
    fn build_naive() {
        let parsed = built(
            ProtocolKind::Naive,
            &producer_settings(&[
                ("user_id", "secret"),
                ("user", "alice"),
                ("padding", "true"),
            ]),
        );
        let ProtocolConfig::Naive(c) = &parsed.protocol.config else {
            panic!("expected Naive config");
        };
        assert_eq!(c.username, "alice");
        assert_eq!(c.password, "secret");
        assert!(c.security.tls.is_some());
    }

    #[test]
    fn build_anytls() {
        let parsed = built(
            ProtocolKind::AnyTls,
            &producer_settings(&[
                ("user_id", "secret"),
                ("sni", "real.example.com"),
                ("alpn", "h2"),
                ("insecure", "true"),
            ]),
        );
        let ProtocolConfig::AnyTls(c) = &parsed.protocol.config else {
            panic!("expected AnyTls config");
        };
        assert_eq!(c.password.as_deref(), Some("secret"));
        let Some(TlsConfig::Tls(tls)) = &c.security.tls else {
            panic!("expected tls security");
        };
        assert_eq!(tls.sni.as_deref(), Some("real.example.com"));
        assert_eq!(tls.insecure, Some(true));
    }

    #[test]
    fn build_shadowtls() {
        let parsed = built(
            ProtocolKind::ShadowTls,
            &producer_settings(&[
                ("user_id", "secret"),
                ("version", "3"),
                ("sni", "real.example.com"),
            ]),
        );
        let ProtocolConfig::ShadowTls(c) = &parsed.protocol.config else {
            panic!("expected ShadowTls config");
        };
        assert_eq!(c.password.as_deref(), Some("secret"));
        assert_eq!(c.version.as_deref(), Some("3"));
        let Some(TlsConfig::Tls(tls)) = &c.security.tls else {
            panic!("expected tls security from sni");
        };
        assert_eq!(tls.sni.as_deref(), Some("real.example.com"));
    }

    #[test]
    fn build_tor() {
        let tor = built(
            ProtocolKind::Tor,
            &producer_settings(&[
                ("socks_port", "9050"),
                ("control_port", "9051"),
                ("control_password", "pw"),
                ("data_dir", "/tmp/tor"),
            ]),
        );
        let ProtocolConfig::Tor(c) = &tor.protocol.config else {
            panic!("expected Tor config");
        };
        assert_eq!(c.data_directory.as_deref(), Some("/tmp/tor"));
    }

    #[test]
    fn build_ssh() {
        let ssh = built(
            ProtocolKind::Ssh,
            &producer_settings(&[
                ("host", "ssh.example.com"),
                ("ssh_port", "22"),
                ("username", "root"),
                ("private_key", "key"),
                ("auth_method", "key"),
            ]),
        );
        let ProtocolConfig::Ssh(c) = &ssh.protocol.config else {
            panic!("expected Ssh config");
        };
        assert_eq!(c.user.as_deref(), Some("root"));
        assert_eq!(c.private_key.as_deref(), Some("key"));
    }

    #[test]
    fn build_tailscale() {
        let ts = built(
            ProtocolKind::Tailscale,
            &producer_settings(&[
                ("auth_key", "tskey-abc"),
                ("control_url", "https://control.example.com"),
                ("ephemeral", "true"),
            ]),
        );
        let ProtocolConfig::Tailscale(c) = &ts.protocol.config else {
            panic!("expected Tailscale config");
        };
        assert_eq!(c.auth_key.as_deref(), Some("tskey-abc"));
        assert_eq!(
            c.control_url.as_deref(),
            Some("https://control.example.com")
        );
        assert_eq!(c.ephemeral, Some(true));
    }

    #[test]
    fn build_ssr() {
        let parsed = built(
            ProtocolKind::ShadowsocksR,
            &producer_settings(&[
                ("user_id", "secret"),
                ("method", "aes-256-cfb"),
                ("protocol", "auth_sha1_v4"),
                ("obfs", "tls1.2_ticket_auth"),
                ("protocol_param", "#1"),
                ("obfs_param", "example.com"),
            ]),
        );
        assert_eq!(parsed.protocol.core_type, CoreType::SingBox);
        let ProtocolConfig::Ssr(c) = &parsed.protocol.config else {
            panic!("expected Ssr config");
        };
        assert_eq!(c.password, "secret");
        assert_eq!(c.method.as_str(), "aes-256-cfb");
        assert_eq!(c.protocol.as_str(), "auth_sha1_v4");
        assert_eq!(c.obfs.as_str(), "tls1.2_ticket_auth");
        assert_eq!(
            c.params.get("protocol_param").map(String::as_str),
            Some("#1")
        );
        assert_eq!(
            c.params.get("obfs_param").map(String::as_str),
            Some("example.com")
        );
    }

    #[test]
    fn build_rejects_unknown_protocol_settings_key() {
        let settings = raw_settings(Some("uuid"), &[("bogus", Value::String("x".into()))], &[]);
        let err = build_typed_config(ProtocolKind::Vless, "1.2.3.4", 443, &settings)
            .expect_err("unknown key must error");
        assert_eq!(err, "unknown setting bogus for vless");
    }

    #[test]
    fn build_rejects_unknown_stream_settings_key() {
        let settings = raw_settings(Some("uuid"), &[], &[("ws.foo", Value::String("x".into()))]);
        let err = build_typed_config(ProtocolKind::Vless, "1.2.3.4", 443, &settings)
            .expect_err("unknown key must error");
        assert_eq!(err, "unknown setting ws.foo for vless");
    }

    #[test]
    fn build_rejects_unknown_top_level_key() {
        let mut obj = Map::new();
        obj.insert("user_id".into(), Value::String("uuid".into()));
        obj.insert("protocol_settings".into(), Value::Object(Map::new()));
        obj.insert("extra".into(), Value::Bool(true));
        let err = build_typed_config(ProtocolKind::Vless, "1.2.3.4", 443, &Value::Object(obj))
            .expect_err("unknown top-level key must error");
        assert_eq!(err, "unknown setting extra for vless");
    }

    #[test]
    fn build_rejects_missing_required_credential() {
        let raw = raw_settings(None, &[], &[]);
        let err = build_typed_config(ProtocolKind::Vless, "1.2.3.4", 443, &raw)
            .expect_err("missing user_id must error");
        assert_eq!(err, "missing required field user_id for vless");
        let err = build_typed_config(
            ProtocolKind::Shadowsocks,
            "1.2.3.4",
            443,
            &raw_settings(Some("pw"), &[], &[]),
        )
        .expect_err("missing method must error");
        assert_eq!(err, "missing required field method for ss");
    }

    #[test]
    fn build_rejects_non_object_settings() {
        let err = build_typed_config(ProtocolKind::Vless, "1.2.3.4", 443, &Value::Null)
            .expect_err("non-object settings must error");
        assert_eq!(err, "settings must be a JSON object for vless");
    }

    #[test]
    fn outbound_only_kinds_build_placeholder() {
        for kind in [
            ProtocolKind::DokodemoDoor,
            ProtocolKind::Freedom,
            ProtocolKind::Blackhole,
            ProtocolKind::Dns,
            ProtocolKind::Loopback,
            ProtocolKind::Custom,
        ] {
            let raw = producer_settings(&[("network", "tcp"), ("doko_address", "10.0.0.1")]);
            let parsed = built(kind, &raw);
            assert_eq!(parsed.protocol.proto_kind, kind);
            let ProtocolConfig::Mixed(p) = &parsed.protocol.config else {
                panic!("{kind:?} must be a Mixed placeholder");
            };
            assert_eq!(p.proto_name, kind.as_str());
            // Raw settings JSON preserved verbatim.
            let back: Value = serde_json::from_slice(&p.settings_json).expect("settings JSON");
            assert_eq!(back, raw);
            assert_eq!(parsed.endpoints.len(), 1);
            assert_eq!(parsed.endpoints[0].host, "1.2.3.4");
            assert_eq!(parsed.endpoints[0].port, 443);
        }
    }

    #[test]
    fn redirect_tproxy_mixed_build_placeholder() {
        for (kind, expect) in [
            (ProtocolKind::Redirect, "Redirect"),
            (ProtocolKind::TProxy, "TProxy"),
            (ProtocolKind::Mixed, "Mixed"),
        ] {
            let raw = producer_settings(&[]);
            let parsed = built(kind, &raw);
            assert_eq!(parsed.protocol.proto_kind, kind);
            let config = &parsed.protocol.config;
            let variant = match config {
                ProtocolConfig::Redirect(_) => "Redirect",
                ProtocolConfig::TProxy(_) => "TProxy",
                ProtocolConfig::Mixed(_) => "Mixed",
                _ => panic!("{kind:?} must be a placeholder variant"),
            };
            assert_eq!(variant, expect);
        }
    }

    #[test]
    fn serialized_config_has_no_address_bytes() {
        for (kind, fields) in [
            (
                ProtocolKind::Vless,
                vec![
                    ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                    ("flow", "xtls-rprx-vision"),
                    ("tls.enable", "true"),
                    ("sni", "real.example.com"),
                    ("ws.path", "/ws"),
                ],
            ),
            (
                ProtocolKind::Vmess,
                vec![
                    ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                    ("tls.enable", "true"),
                    ("ws.host", "cdn.example.com"),
                ],
            ),
            (
                ProtocolKind::Trojan,
                vec![("user_id", "humanity"), ("sni", "real.example.com")],
            ),
            (
                ProtocolKind::Hysteria2,
                vec![("user_id", "token"), ("sni", "real.example.com")],
            ),
        ] {
            let parsed = built(kind, &producer_settings(&fields));
            let json = serde_json::to_string(&parsed.protocol.config).expect("serialize");
            assert!(
                !json.contains("1.2.3.4"),
                "{kind:?} config must not contain the endpoint address: {json}"
            );
        }
    }

    #[test]
    fn endpoint_host_kind_detection() {
        let ipv4 = built(
            ProtocolKind::Vless,
            &producer_settings(&[("user_id", "uuid")]),
        );
        assert_eq!(ipv4.endpoints[0].host_type, HostKind::Ipv4);

        let ipv6 = build_typed_config(
            ProtocolKind::Vless,
            "2001:db8::1",
            443,
            &producer_settings(&[("user_id", "uuid")]),
        )
        .expect("ipv6 build");
        assert_eq!(ipv6.endpoints[0].host_type, HostKind::Ipv6);
        assert_eq!(ipv6.endpoints[0].host, "2001:db8::1");

        let dns = build_typed_config(
            ProtocolKind::Vless,
            "example.com",
            443,
            &producer_settings(&[("user_id", "uuid")]),
        )
        .expect("dns build");
        assert_eq!(dns.endpoints[0].host_type, HostKind::Dns);
    }

    /// Reconstruct the built config via the endpoint and re-parse — the
    /// config payload must survive the round trip (JSON equality, since
    /// proto config structs derive `PartialEq` only inside the proto crate).
    fn assert_reconstruct_roundtrip(parsed: &ParsedProto) {
        let endpoint = &parsed.endpoints[0];
        let url = parsed
            .protocol
            .config
            .reconstruct_proto(endpoint)
            .expect("reconstruct_proto");
        let reparsed =
            ProtocolConfig::try_parse_proto(&leas_proto::urlx::RawUrlX::from(url.as_str()))
                .expect("re-parse reconstructed URL");
        assert_eq!(config_json(parsed), config_json(&reparsed));
    }

    #[rstest]
    #[case::vless_ws_tls(ProtocolKind::Vless, &[
        ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
        ("flow", "xtls-rprx-vision"),
        ("tls.enable", "true"),
        ("sni", "real.example.com"),
        ("fingerprint", "chrome"),
        ("ws.path", "/ws"),
        ("ws.host", "cdn.example.com"),
    ])]
    #[case::trojan(ProtocolKind::Trojan, &[
        ("user_id", "humanity"),
        ("sni", "real.example.com"),
        ("alpn", "h2"),
        ("fingerprint", "chrome"),
    ])]
    #[case::shadowsocks(ProtocolKind::Shadowsocks, &[
        ("user_id", "passw0rd"),
        ("method", "aes-256-gcm"),
        ("plugin", "obfs-local"),
        ("plugin_opts", "obfs=http;obfs-host=example.com"),
    ])]
    #[case::shadowsocks2022(ProtocolKind::Shadowsocks2022, &[
        ("user_id", "0123456789abcdef0123456789abcdef"),
        ("method", "2022-blake3-aes-128-gcm"),
    ])]
    fn reconstruct_roundtrip_cases(#[case] kind: ProtocolKind, #[case] settings: &[(&str, &str)]) {
        let parsed = built(kind, &producer_settings(settings));
        assert_eq!(parsed.protocol.proto_kind, kind);
        assert_reconstruct_roundtrip(&parsed);
    }

    #[test]
    fn reconstruct_roundtrip_grpc_reformatable() {
        // gRPC service_name has no URL query slot (share links carry it as
        // `path`), so strict config equality is not expected — the URL must
        // still reconstruct and re-parse.
        let parsed = built(
            ProtocolKind::Vless,
            &producer_settings(&[
                ("user_id", "6202b230-417c-4d8e-b624-0f71afa9c75d"),
                ("grpc.serviceName", "myservice"),
            ]),
        );
        let url = parsed
            .protocol
            .config
            .reconstruct_proto(&parsed.endpoints[0])
            .expect("reconstruct_proto");
        assert!(
            url.contains("type=grpc") && url.contains("path=myservice"),
            "grpc URL should carry type and path: {url}"
        );
        ProtocolConfig::try_parse_proto(&leas_proto::urlx::RawUrlX::from(url.as_str()))
            .expect("re-parse reconstructed URL");
    }

    #[test]
    fn hy2_ports_roundtrip_flattens_endpoint() {
        let parsed = built(
            ProtocolKind::Hysteria2,
            &producer_settings(&[
                ("user_id", "token"),
                ("ports", "1000-1002,2000"),
                ("sni", "real.example.com"),
            ]),
        );
        let url = parsed
            .protocol
            .config
            .reconstruct_proto(&parsed.endpoints[0])
            .expect("reconstruct_proto");
        // The multi-port hop spec must reconstruct (endpoint.ports drives it).
        assert!(url.contains("1000"), "reconstructed URL: {url}");
        let reparsed =
            ProtocolConfig::try_parse_proto(&leas_proto::urlx::RawUrlX::from(url.as_str()))
                .expect("re-parse reconstructed URL");
        assert_eq!(reparsed.endpoints[0].ports, parsed.endpoints[0].ports);
    }

    // ── producer-accurate end-to-end: real form defaults must build ─────

    /// The form's own default field values, with empty-default REQUIRED
    /// fields filled so the builder's required-credential backstop does not
    /// trip (the TUI validates required fields before submission).
    fn form_default_fields(proto: ProtocolKind) -> Vec<(&'static str, String)> {
        let mut fields: Vec<(&'static str, String)> = form_fields_for(proto)
            .iter()
            .map(|f| (f.key, f.default.to_string()))
            .collect();
        for (key, value) in &mut fields {
            match (proto, *key) {
                (
                    ProtocolKind::Vmess | ProtocolKind::Vless | ProtocolKind::Tuic,
                    "user_id" | "uuid",
                ) => {
                    *value = "6202b230-417c-4d8e-b624-0f71afa9c75d".into();
                }
                (
                    ProtocolKind::Shadowsocks
                    | ProtocolKind::Shadowsocks2022
                    | ProtocolKind::ShadowsocksR
                    | ProtocolKind::Trojan
                    | ProtocolKind::Naive
                    | ProtocolKind::AnyTls
                    | ProtocolKind::ShadowTls,
                    "password",
                ) => {
                    *value = "secret".into();
                }
                (ProtocolKind::Ssh, "host") => *value = "ssh.example.com".into(),
                (ProtocolKind::Ssh, "username") => *value = "root".into(),
                (ProtocolKind::WireGuard, "private_key") => *value = "aGVsbG8=".into(),
                (ProtocolKind::WireGuard, "public_key") => *value = "d29ybGQ=".into(),
                (ProtocolKind::Dns, "dns_address") => *value = "1.1.1.1".into(),
                (ProtocolKind::Custom, "config_json") => *value = "{}".into(),
                _ => {}
            }
        }
        fields
    }

    /// Every protocol's REAL form-default key set (default values routed
    /// through the exact `fields_to_profile` logic) must build without error
    /// — regression net for the producer-routing contract (F1/F2 class bugs:
    /// a default-emitted key must never be rejected as unknown, and
    /// stream-routed keys must never be silently dropped).
    #[test]
    fn form_defaults_build_cleanly_for_all_protocols() {
        for proto in [
            ProtocolKind::Vmess,
            ProtocolKind::Vless,
            ProtocolKind::Shadowsocks,
            ProtocolKind::Shadowsocks2022,
            ProtocolKind::Socks,
            ProtocolKind::Http,
            ProtocolKind::Trojan,
            ProtocolKind::WireGuard,
            ProtocolKind::Hysteria2,
            ProtocolKind::Hysteria,
            ProtocolKind::Tuic,
            ProtocolKind::Naive,
            ProtocolKind::AnyTls,
            ProtocolKind::ShadowTls,
            ProtocolKind::Tor,
            ProtocolKind::Ssh,
            ProtocolKind::Tailscale,
            ProtocolKind::ShadowsocksR,
            ProtocolKind::DokodemoDoor,
            ProtocolKind::Freedom,
            ProtocolKind::Blackhole,
            ProtocolKind::Loopback,
            ProtocolKind::Dns,
            ProtocolKind::Redirect,
            ProtocolKind::Custom,
            ProtocolKind::TProxy,
            ProtocolKind::Mixed,
        ] {
            let fields = form_default_fields(proto);
            let pairs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let settings = producer_settings(&pairs);
            let result = build_typed_config(proto, "1.2.3.4", 443, &settings);
            assert!(
                result.is_ok(),
                "{proto:?} default form must build without error: {:?}",
                result.err()
            );
        }
    }

    /// The reviewer-flagged vmess case, pinned explicitly: the real vmess
    /// form-default key set (incl. `reality.show=false` in `stream_settings` and
    /// `tcp.headerType=none`) builds, and sni/tls still map.
    #[test]
    fn vmess_form_defaults_build() {
        let fields = form_default_fields(ProtocolKind::Vmess);
        let pairs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let settings = producer_settings(&pairs);
        let parsed = build_typed_config(ProtocolKind::Vmess, "1.2.3.4", 443, &settings)
            .expect("vmess default form builds");
        let ProtocolConfig::Vmess(c) = &parsed.protocol.config else {
            panic!("expected Vmess config");
        };
        // Defaults: no TLS, no ws/grpc keys → Tcp transport, no TLS, enc auto
        // (the parser default; the form's encryption select is a Profile
        // column dropped by fields_to_profile).
        assert!(matches!(c.transport, TransportConfig::Tcp));
        assert!(c.security.tls.is_none());
        assert_eq!(c.security.enc.as_deref(), Some("auto"));
    }
}
