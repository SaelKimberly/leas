use std::net::SocketAddr;

use leas_proto::proto_spec::VlessMux;
use leas_proto::proto_spec::common::{
    GrpcConfig, HttpConfig, HttpUpgradeConfig, KcpConfig, TransportConfig, WebSocketConfig,
    XHttpConfig,
};
use leas_proto::proto_spec::endpoint::EndpointEssentials;
use leas_proto::proto_spec::ss_plugin::{PluginSpec, link_sni};
use leas_proto::proto_spec::{
    ProtoSpec, ProtocolConfig, SecurityConfig, TlsConfig, TlsOpts, parse_curve_names,
};

use crate::addr::Host;
use crate::error::{NativeError, timeouts};
use crate::protocol::vless::PacketMode;
use crate::security::reality::HelloProvisionerChoice;

/// Per-connect parameters: the typed proto config plus the dial address.
///
/// `server` is the proxy server (host/port); `target` is the destination the
/// proxy should reach. `resolved_ip` lets callers inject a pre-resolved
/// address (one of the enrichment pipeline's resolved addresses) and skip DNS.
#[derive(Debug, Clone)]
pub struct NativeConnectParams {
    pub protocol: ProtocolConfig,
    pub server: EndpointEssentials,
    pub target: crate::addr::TargetAddr,
    pub resolved_ip: Option<SocketAddr>,
    /// REALITY provisioner for the security phase: which fingerprint shapes
    /// the `ClientHello`. Defaults to
    /// [`HelloProvisionerChoice::FixedChrome133`].
    pub reality_provisioner: HelloProvisionerChoice,
    /// UDP packet mode: `None` = the TCP path (default; [`crate::connect`]);
    /// `Some(mode)` selects the VLESS UDP datagram tunnel ([`crate::connect_udp`],
    /// command 0x02) with `Raw` (header-dest) or `PacketAddr` (per-packet
    /// magic-address destinations) framing.
    pub udp: Option<PacketMode>,
    /// Mux tunnel request for this link, for BOTH phases:
    ///
    /// - **UDP**: `true` routes [`crate::connect_udp`] through the VLESS mux
    ///   tunnel (XUDP — `connect_mux` → `open_udp_session` → [`PacketMode::XUdp`])
    ///   instead of the raw `command=0x02` tunnel, and
    ///   `xtls-rprx-vision-udp443` forces it (spec §4.3);
    /// - **TCP**: `true` routes the dial through the mux protocol phase
    ///   ([`crate::connect_mux`]) and opens one session on the tunnel.
    ///
    /// The TCP half is what the SIP003 plugin rows need: a v2ray-plugin server
    /// *mandates* mux (it dispatches every stream to `v1.mux.cool` and parses
    /// frames unconditionally), so a row that stored `mux=1` and resolved it
    /// off would be dialled without frames and rejected (spec §2.3). The value
    /// is the row's **resolved** mux — `PluginSpec::mux_active()` for a plugin
    /// row — never the stored key, and never for a QUIC mode, which replaces the
    /// dial entirely.
    pub mux: bool,
}

impl NativeConnectParams {
    #[must_use]
    pub fn new(
        protocol: ProtocolConfig,
        server: EndpointEssentials,
        target: crate::addr::TargetAddr,
    ) -> Self {
        let mux = Self::resolved_mux(&protocol);
        Self {
            protocol,
            server,
            target,
            resolved_ip: None,
            reality_provisioner: HelloProvisionerChoice::FixedChrome133,
            udp: None,
            // **Derived here, once.** The mux decision is the row's RESOLVED
            // plugin mux (`PluginSpec::mux_active`: the resolved value, never the
            // stored key, and never a QUIC mode), so the app's `proxy_params`, the
            // real probe and any future caller cannot disagree — a hand-written
            // assignment per site is exactly the drift the §5.2 predicate exists
            // to prevent. VLESS now has a `mux` field, so this predicate covers
            // both families — still a change to THIS function alone.
            mux,
        }
    }

    /// The link's mux request, from the row itself.
    #[must_use]
    pub fn resolved_mux(protocol: &ProtocolConfig) -> bool {
        match protocol {
            ProtocolConfig::Ss(cfg) => cfg.plugin.as_ref().is_some_and(PluginSpec::mux_active),
            // VLESS: the row's own request. `is_active` rather than a magnitude
            // test, so `mux=-1` (unlimited) is mux ON — a `u32`/`> 0` reading would
            // silently dial an unlimited row without frames.
            ProtocolConfig::Vless(cfg) => cfg.mux.as_ref().is_some_and(VlessMux::is_active),
            _ => false,
        }
    }
}

/// Per-link state in the connect pipeline (a chain has one context per link).
#[derive(Debug, Clone)]
pub struct LinkContext {
    pub params: NativeConnectParams,
    pub target: crate::addr::TargetAddr,
}

impl LinkContext {
    #[must_use]
    pub const fn new(params: NativeConnectParams, target: crate::addr::TargetAddr) -> Self {
        Self { params, target }
    }

    /// The proxy server's socket address: `resolved_ip` override, else the
    /// parsed host IP, else DNS resolution via `tokio::net::lookup_host`.
    ///
    /// DNS lookup is a network step: bounded by [`timeouts::DIAL`].
    pub async fn server_socket(&self) -> Result<SocketAddr, NativeError> {
        if let Some(addr) = self.params.resolved_ip {
            return Ok(addr);
        }
        match Host::new(&self.params.server.host) {
            Host::Ip(ip) => Ok(SocketAddr::new(ip, self.params.server.port)),
            Host::Domain(domain) => {
                let (host, port) = (domain.as_str(), self.params.server.port);
                let timeout = timeouts::DIAL;
                let mut addrs =
                    tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
                        .await
                        .map_err(|_| NativeError::Timeout {
                            step: "dns lookup",
                            limit: timeout,
                        })?
                        .map_err(|e| NativeError::Dial(format!("{host}: {e}")))?;
                addrs
                    .next()
                    .ok_or_else(|| NativeError::Dial(format!("{host}: no addresses found")))
            }
        }
    }

    /// True when the link actually runs TLS or REALITY: `sec.tls.is_some()`.
    ///
    /// The one predicate every phase uses — `security::wrap` (skip the
    /// handshake), the xhttp scheme/HTTP-version decision, and the VLESS
    /// vision/mux guards — collapsing the three historical re-derivations
    /// (`sec.is_empty()` and two byte-identical `has_tls()` copies) onto
    /// this single decision surface.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        // A plugin row's TLS is the plugin's `tls` key, not the row's
        // `security` — which is exactly why this edit is necessary: without it
        // `security::wrap` returns at its own `is_tls()` guard and a
        // `mode=websocket;tls` row performs a **plaintext** upgrade against a
        // TLS port (the corpus's most common plugin shape, 20:8014).
        self.security().is_some_and(|s| s.tls.is_some())
            || self.plugin_spec().is_some_and(PluginSpec::needs_tls)
    }

    /// The TLS server name (SNI): explicit `sni` option — plain TLS or the
    /// REALITY steal target — else the endpoint host.
    ///
    /// Unifies the two historical SNI paths (`ctx.sni()` routed through
    /// `tls_opts()`, which rejected Reality configs and fell back to the
    /// often-IP server host; `sec.sni()` read the steal target) into one
    /// decision. `SecurityConfig::sni()` reads `RealityOpts.sni`, so a
    /// REALITY link never leaks the endpoint host as its steal target.
    ///
    /// [`super::link_sni`] — the one SNI owner — with the endpoint host as the
    /// final fallback. For a plugin row the middle term is the plugin's `host`
    /// (only when the row states one); for every other row this is the
    /// historical `security.sni()` → endpoint-host behaviour, unchanged.
    #[must_use]
    pub fn server_name(&self) -> String {
        link_sni(&self.params.protocol, &self.params.server.host)
            .unwrap_or_else(|| self.params.server.host.clone())
    }

    /// Canonical split of the explicit `alpn` option — the ONE place the
    /// `split(',') → trim → drop-empty` rules live (shared with the xhttp
    /// transport's `http_version` decision). Empty when no explicit ALPN;
    /// the transport-implied fallback is `alpn_vec`'s job, not this.
    #[must_use]
    pub fn alpn_tokens(&self) -> Vec<&str> {
        self.tls_opts()
            .ok()
            .flatten()
            .and_then(|o| o.alpn.as_deref())
            .map(split_alpn)
            .unwrap_or_default()
    }

    /// TLS ALPN list: explicit `alpn` tokens (via [`Self::alpn_tokens`]),
    /// else transport-implied ALPN — grpc/xhttp/http ride HTTP/2 (xhttp
    /// falls back to HTTP/1.1 only when there is no TLS at all — no ALPN
    /// then), ws/httpupgrade are HTTP/1.1 exchanges. (Reality forces
    /// h2+http/1.1 server-side; an explicit `alpn` option wins above.)
    #[must_use]
    pub fn alpn_vec(&self) -> Vec<Vec<u8>> {
        let explicit: Vec<Vec<u8>> = self
            .alpn_tokens()
            .into_iter()
            .map(str::as_bytes)
            .map(<[u8]>::to_vec)
            .collect();
        if !explicit.is_empty() {
            return explicit;
        }
        match self.transport_type() {
            Some("grpc" | "xhttp" | "http") => vec![b"h2".to_vec()],
            Some("ws" | "httpupgrade") => vec![b"http/1.1".to_vec()],
            // A plugin row has no `TransportConfig`, so the transport-implied
            // arm above cannot see it. Both references send `http/1.1` for the
            // v2ray websocket transport (v2ray-core's ws dialer passes
            // `OptionWithALPN{ALPNs: ["http/1.1"]}`; sing-box sets
            // `NextProtos` to `["http/1.1"]` when the caller left it empty), so
            // the plugin's TLS session advertises the same.
            _ if self.plugin_spec().is_some_and(PluginSpec::needs_tls) => {
                vec![b"http/1.1".to_vec()]
            }
            _ => vec![],
        }
    }

    /// TLS curve preferences: the `curves` option parsed to wire curve IDs
    /// via the proto's `parse_curve_names` (xray `ParseCurveName` mirror —
    /// unknown names skipped). Empty when unset or security is REALITY.
    #[must_use]
    pub fn curve_ids(&self) -> Vec<u16> {
        self.tls_opts()
            .ok()
            .flatten()
            .and_then(|o| o.curves.as_ref())
            .map_or_else(Vec::new, |c| parse_curve_names(c.as_str()))
    }

    /// The typed TLS options when security is plain TLS (not Reality).
    pub fn tls_opts(&self) -> Result<Option<&TlsOpts>, NativeError> {
        match self.security() {
            Some(SecurityConfig {
                tls: Some(TlsConfig::Tls(opts)),
                ..
            }) => Ok(Some(opts)),
            Some(SecurityConfig {
                tls: Some(TlsConfig::Reality(_)),
                ..
            }) => Err(NativeError::Reality(
                "plain-TLS opts requested for a REALITY config".into(),
            )),
            _ => Ok(None),
        }
    }

    /// Security config from the protocol payload (typed, via the proto trait).
    #[must_use]
    pub fn security(&self) -> Option<&SecurityConfig> {
        self.params.protocol.security()
    }

    /// Transport name ("tcp", "ws", ...) from the protocol payload.
    #[must_use]
    pub fn transport_type(&self) -> Option<&str> {
        self.params.protocol.transport_type()
    }

    /// Typed transport config (vless/vmess/trojan carry `transport`).
    #[must_use]
    pub const fn transport_config(&self) -> Option<&TransportConfig> {
        use leas_proto::proto_spec::ProtocolConfig as PC;
        match &self.params.protocol {
            PC::Vless(c) => Some(&c.transport),
            PC::Vmess(c) => Some(&c.transport),
            PC::Trojan(c) => Some(&c.transport),
            _ => None,
        }
    }

    /// The SIP003 plugin spec, when the link is a Shadowsocks row carrying one.
    ///
    /// The SS arm of the typed-accessor family (`transport_ws`, `transport_grpc`,
    /// …): an `SsConfig` carries **no transport field**, so this is the only
    /// input the transport phase has for selecting the plugin framing — and the
    /// reason `transport::upgrade` dispatches on it before any
    /// `TransportConfig` match (§5 items 1–2).
    #[must_use]
    pub const fn plugin_spec(&self) -> Option<&leas_proto::proto_spec::PluginSpec> {
        use leas_proto::proto_spec::ProtocolConfig as PC;
        match &self.params.protocol {
            PC::Ss(config) => config.plugin.as_ref(),
            _ => None,
        }
    }

    /// WebSocket transport config, when the link uses `ws`.
    #[must_use]
    pub fn transport_ws(&self) -> Option<&WebSocketConfig> {
        match self.transport_config()? {
            TransportConfig::Ws(c) => Some(c),
            _ => None,
        }
    }

    /// gRPC transport config, when the link uses `grpc`.
    #[must_use]
    pub fn transport_grpc(&self) -> Option<&GrpcConfig> {
        match self.transport_config()? {
            TransportConfig::Grpc(c) => Some(c),
            _ => None,
        }
    }

    /// `HTTPUpgrade` transport config, when the link uses `httpupgrade`.
    #[must_use]
    pub fn transport_httpupgrade(&self) -> Option<&HttpUpgradeConfig> {
        match self.transport_config()? {
            TransportConfig::HttpUpgrade(c) => Some(c),
            _ => None,
        }
    }

    /// XHTTP transport config, when the link uses `xhttp`.
    #[must_use]
    pub fn transport_xhttp(&self) -> Option<&XHttpConfig> {
        match self.transport_config()? {
            TransportConfig::XHttp(c) => Some(c),
            _ => None,
        }
    }

    /// h2 (v2rayhttp) transport config, when the link uses `http`.
    #[must_use]
    pub fn transport_http(&self) -> Option<&HttpConfig> {
        match self.transport_config()? {
            TransportConfig::Http(c) => Some(c),
            _ => None,
        }
    }

    /// mKCP transport config, when the link uses `kcp` (the native params
    /// expose only mtu/tti; everything else derives, spec §4.5).
    #[must_use]
    pub fn transport_kcp(&self) -> Option<&KcpConfig> {
        match self.transport_config()? {
            TransportConfig::Kcp(c) => Some(c),
            _ => None,
        }
    }
}

/// Split a comma-separated ALPN string — `split(',')`, trim, drop empties.
/// The canonical rules shared by [`LinkContext::alpn_tokens`] and the xhttp
/// transport's `http_version` decision, so neither can drift from the other.
pub(crate) fn split_alpn(s: &str) -> Vec<&str> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Host, TargetAddr};

    fn vless_empty() -> ProtocolConfig {
        // VlessConfig has no Default; build through the serde schema.
        // ProtocolConfig is `#[serde(tag = "schema")]` with no rename: the
        // tag value is the PascalCase variant name ("Vless").
        serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "tcp" }
        }))
        .expect("vless config parses")
    }

    fn target(host: &str) -> TargetAddr {
        TargetAddr::new(Host::Domain(host.into()), 80)
    }

    #[test]
    fn server_socket_uses_ip_host_without_dns() {
        let params = NativeConnectParams::new(
            vless_empty(),
            EndpointEssentials::new("127.0.0.1", 4430),
            target("example.com"),
        );
        let ctx = LinkContext::new(params, target("example.com"));
        let sock = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(ctx.server_socket())
            .unwrap();
        assert_eq!(sock, SocketAddr::from(([127, 0, 0, 1], 4430)));
    }

    #[test]
    fn resolved_ip_overrides_host() {
        let mut params = NativeConnectParams::new(
            vless_empty(),
            EndpointEssentials::new("server.example", 4430),
            target("example.com"),
        );
        params.resolved_ip = Some(SocketAddr::from(([127, 0, 0, 1], 9999)));
        let ctx = LinkContext::new(params, target("example.com"));
        let sock = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(ctx.server_socket())
            .unwrap();
        assert_eq!(sock, SocketAddr::from(([127, 0, 0, 1], 9999)));
    }

    #[test]
    fn alpn_splits_on_comma() {
        let params = NativeConnectParams::new(
            vless_empty(),
            EndpointEssentials::new("127.0.0.1", 4430),
            target("example.com"),
        );
        let ctx = LinkContext::new(params, target("example.com"));
        assert_eq!(ctx.alpn_vec().len(), 0);
    }

    #[test]
    fn curve_ids_parse_curves_option() {
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "security": {
                "type": "tls", "sni": "sni.example",
                "curves": "X25519MLKEM768, x25519, bogus"
            },
            "transport": { "type": "tcp" }
        }))
        .expect("vless tls+curves config parses");
        let ctx = LinkContext::new(
            NativeConnectParams::new(
                protocol,
                EndpointEssentials::new("127.0.0.1", 4430),
                target("example.com"),
            ),
            target("example.com"),
        );
        // Case-insensitive; unknown names skipped (ParseCurveName mirror).
        assert_eq!(ctx.curve_ids(), vec![4588, 29]);
    }

    #[test]
    fn curve_ids_empty_without_curves_option() {
        let ctx = LinkContext::new(
            NativeConnectParams::new(
                vless_empty(),
                EndpointEssentials::new("127.0.0.1", 4430),
                target("example.com"),
            ),
            target("example.com"),
        );
        assert_eq!(ctx.curve_ids().len(), 0);
    }

    /// The full plumbing: config string → proto parse → native params →
    /// the TLS spec's `supported_groups`/`key_share` extensions.
    #[test]
    fn curves_config_flows_to_tls_spec_extensions() {
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "security": {
                "type": "tls", "sni": "sni.example",
                "curves": "x25519mlkem768,x25519"
            },
            "transport": { "type": "tcp" }
        }))
        .expect("vless tls+curves config parses");
        let ctx = LinkContext::new(
            NativeConnectParams::new(
                protocol,
                EndpointEssentials::new("127.0.0.1", 4430),
                target("example.com"),
            ),
            target("example.com"),
        );
        let ids = ctx.curve_ids();
        assert_eq!(ids, vec![4588, 29]);

        let spec = leas_tls::spec::apply_curve_preferences(
            &leas_tls::fingerprints::Fingerprint::new(
                leas_tls::fingerprints::query::Browser::Chrome,
            )
            .with_version(130)
            .resolve()
            .expect("chrome_130 must resolve")
            .spec,
            &ids,
        );
        let groups = spec.extensions.iter().find_map(|e| match e {
            leas_tls::spec::ExtensionSpec::SupportedGroups(g) => Some(g.clone()),
            _ => None,
        });
        assert_eq!(groups, Some(vec![4588, 29]));
        let key_shares = spec.extensions.iter().find_map(|e| match e {
            leas_tls::spec::ExtensionSpec::KeyShare(g) => Some(g.clone()),
            _ => None,
        });
        assert!(matches!(
            key_shares.as_deref(),
            Some([
                leas_tls::spec::KeyShareGroup::Grease,
                leas_tls::spec::KeyShareGroup::X25519Mlkem768,
                leas_tls::spec::KeyShareGroup::X25519
            ])
        ));
    }

    #[test]
    fn alpn_defaults_per_transport() {
        let grpc: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "grpc", "service_name": "gun" }
        }))
        .expect("vless grpc config parses");
        let ctx = LinkContext::new(
            NativeConnectParams::new(
                grpc,
                EndpointEssentials::new("127.0.0.1", 4430),
                target("x"),
            ),
            target("x"),
        );
        assert_eq!(ctx.alpn_vec(), vec![b"h2".to_vec()]);

        let ws: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "ws", "path": "/ws" }
        }))
        .expect("vless ws config parses");
        let ctx = LinkContext::new(
            NativeConnectParams::new(ws, EndpointEssentials::new("127.0.0.1", 4430), target("x")),
            target("x"),
        );
        assert_eq!(ctx.alpn_vec(), vec![b"http/1.1".to_vec()]);

        // v2rayhttp rides HTTP/2 like grpc.
        let http: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "transport": { "type": "http", "path": "/h2" }
        }))
        .expect("vless http config parses");
        let ctx = LinkContext::new(
            NativeConnectParams::new(
                http,
                EndpointEssentials::new("127.0.0.1", 4430),
                target("x"),
            ),
            target("x"),
        );
        assert_eq!(ctx.alpn_vec(), vec![b"h2".to_vec()]);
    }

    #[test]
    fn explicit_alpn_wins_over_transport() {
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "security": { "type": "tls", "sni": "sni.example", "alpn": "h2,http/1.1" },
            "transport": { "type": "grpc", "service_name": "gun" }
        }))
        .expect("vless grpc+tls config parses");
        let ctx = LinkContext::new(
            NativeConnectParams::new(
                protocol,
                EndpointEssentials::new("127.0.0.1", 4430),
                target("x"),
            ),
            target("x"),
        );
        assert_eq!(ctx.alpn_vec(), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn tls_config_yields_sni_and_alpn() {
        // `SecurityConfig.tls` is `#[serde(flatten)]` — the TlsConfig internal
        // tag sits directly under `security`.
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "security": { "type": "tls", "sni": "sni.example", "alpn": "h2,http/1.1" },
            "transport": { "type": "tcp" }
        }))
        .expect("vless tls config parses");
        let params = NativeConnectParams::new(
            protocol,
            EndpointEssentials::new("127.0.0.1", 4430),
            target("example.com"),
        );
        let ctx = LinkContext::new(params, target("example.com"));
        assert_eq!(ctx.server_name(), "sni.example");
        assert_eq!(ctx.alpn_vec(), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    // ---- policy decision surface --------------------------------------

    /// Build a link with the given `security` JSON value (None = the field
    /// omitted entirely; the proto still yields an empty `SecurityConfig`).
    fn ctx_with_sec(security: Option<serde_json::Value>) -> LinkContext {
        let sec = security.unwrap_or_else(|| serde_json::json!({}));
        let protocol: ProtocolConfig = serde_json::from_value(serde_json::json!({
            "schema": "Vless",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "security": sec,
            "transport": { "type": "tcp" }
        }))
        .expect("vless config parses");
        LinkContext::new(
            NativeConnectParams::new(
                protocol,
                EndpointEssentials::new("my.server.test", 4430),
                target("example.com"),
            ),
            target("example.com"),
        )
    }

    #[test]
    fn is_tls_false_without_tls() {
        // Omitted security → empty SecurityConfig → not TLS.
        assert!(!ctx_with_sec(None).is_tls());
        // Explicit empty security object → not TLS either.
        assert!(!ctx_with_sec(Some(serde_json::json!({}))).is_tls());
    }

    #[test]
    fn is_tls_true_for_plain_tls_and_reality() {
        assert!(ctx_with_sec(Some(serde_json::json!({ "type": "tls" }))).is_tls());
        assert!(
            ctx_with_sec(Some(serde_json::json!({
                "type": "reality", "pbk": "x", "sid": "y"
            })))
            .is_tls()
        );
    }

    #[test]
    fn server_name_plain_sni_wins_over_host() {
        let ctx = ctx_with_sec(Some(serde_json::json!({
            "type": "tls", "sni": "sni.example"
        })));
        assert_eq!(ctx.server_name(), "sni.example");
    }

    #[test]
    fn server_name_reality_steal_sni_wins_over_host() {
        // REALITY's `RealityOpts.sni` is the steal target — the endpoint
        // host (often an IP literal) must NOT leak through.
        let ctx = ctx_with_sec(Some(serde_json::json!({
            "type": "reality", "sni": "steal.target", "pbk": "x", "sid": "y"
        })));
        assert_eq!(ctx.server_name(), "steal.target");
    }

    #[test]
    fn server_name_falls_back_to_host() {
        // No security, and TLS without an explicit sni, both fall back to
        // the endpoint host.
        assert_eq!(ctx_with_sec(None).server_name(), "my.server.test");
        assert_eq!(
            ctx_with_sec(Some(serde_json::json!({ "type": "tls" }))).server_name(),
            "my.server.test"
        );
        assert_eq!(
            ctx_with_sec(Some(serde_json::json!({
                "type": "reality", "pbk": "x", "sid": "y"
            })))
            .server_name(),
            "my.server.test"
        );
    }

    #[test]
    fn alpn_tokens_split_trims_drops_empty() {
        let ctx = ctx_with_sec(Some(serde_json::json!({
            "type": "tls", "alpn": " h2 , ,http/1.1 "
        })));
        assert_eq!(ctx.alpn_tokens(), vec!["h2", "http/1.1"]);
        assert_eq!(ctx.alpn_vec(), vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn alpn_tokens_empty_without_explicit_alpn() {
        // No explicit ALPN → no tokens (the transport-implied fallback lives
        // only in `alpn_vec`, never in the tokens).
        assert_eq!(ctx_with_sec(None).alpn_tokens().len(), 0);
        assert_eq!(
            ctx_with_sec(Some(serde_json::json!({ "type": "tls" })))
                .alpn_tokens()
                .len(),
            0
        );
    }
}
