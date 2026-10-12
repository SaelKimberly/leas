//! Data-driven e2e case: protocol + optional payload-security variant.
//!
//! The `E2eCase` impl derives the server config, client params, expectations
//! and label from these parts — adding a variant is a new `SecurityVariant`
//! impl, not a new case struct.

use std::net::SocketAddr;

use super::{
    Certs, ConnectExpect, CoreKind, E2eCase, E2eExpect, SecurityVariant, ServerEnv, StandardTls,
    TlsVariant, config,
};
use crate::NativeConnectParams;
use crate::protocol::vless::PacketMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Vless,
    Vmess,
    Trojan,
    Hysteria2,
    Shadowsocks,
}

/// VLESS flow control: `xtls-rprx-vision` (`Vision`) or the XUDP variant
/// `xtls-rprx-vision-udp443` (`Udp443`).
///
/// The udp443 suffix is client-side only: UDP rides the mux tunnel, the
/// addon truncates to `xtls-rprx-vision` on the wire (spec §4.3), and the
/// server validates against that truncated name (see [`Flow::server_str`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Vision,
    Udp443,
}

impl Flow {
    /// The client-facing flow name — what the native client's
    /// `VlessConfig.flow` carries (the udp443 suffix selects the XUDP
    /// path client-side: mux-forced, guard lifted, addon truncated).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Vision => "xtls-rprx-vision",
            Self::Udp443 => "xtls-rprx-vision-udp443",
        }
    }

    /// The flow the SERVER config must carry: the udp443 suffix is
    /// truncated away at encode time (spec §4.3), so the wire addon is
    /// always `xtls-rprx-vision` — and both cores reject a server user
    /// whose flow differs from the request's (xray inbound
    /// `account.Flow == requestAddons.Flow`; sing-vmess `service.go`
    /// flow-mismatch / unknown-flow). The server config therefore emits
    /// `xtls-rprx-vision` for both variants.
    #[must_use]
    pub const fn server_str(&self) -> &'static str {
        match self {
            Self::Vision | Self::Udp443 => "xtls-rprx-vision",
        }
    }
}

/// The app-side probe kind: how the client's application data is carried
/// through the tunnel (spec §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKind {
    /// Plain HTTP over the raw tunnel (the End path for non-TLS traffic).
    Plain,
    /// A real TLS 1.3 session THROUGH the tunnel: the app wraps the tunnel
    /// in the engine TLS client to a rustls echo target (the vision
    /// Direct-splice path).
    InnerTls,
    /// UDP datagrams through the tunnel (VLESS command 0x02): the probe
    /// sends datagrams to the UDP echo target and matches echoes by
    /// payload. The packet mode (`Raw` / `PacketAddr`) lives in
    /// [`CaseSpec::udp`].
    Udp,
}

/// One e2e scenario described as data.
///
/// Construct via [`CaseSpec::vless`] / [`CaseSpec::vmess`]; `protocol` and
/// `security` are private invariants (a vmess case always carries a variant).
/// `tls` defaults to [`StandardTls`]; add fingerprint/REALITY variants with
/// [`CaseSpec::with_tls`].
pub struct CaseSpec {
    protocol: ProtocolKind,
    security: Option<Box<dyn SecurityVariant>>,
    tls: Option<Box<dyn TlsVariant>>,
    network: &'static str,
    /// Client-side xhttp dialect ("packet-up" default, "stream-up"). The
    /// client's mode selects the dialect on the wire; `None` for non-xhttp
    /// networks.
    xhttp_mode: Option<&'static str>,
    /// VLESS flow control; `None` = no flow. Only `Flow::Vision`
    /// (`xtls-rprx-vision`) exists; it is emitted in the server's
    /// clients/users and the client outbound (vmess cases never carry one).
    flow: Option<Flow>,
    /// App-side probe kind: plain HTTP over the tunnel, an inner TLS
    /// session THROUGH the tunnel to a rustls echo target, or UDP
    /// datagrams to the UDP echo target.
    app: AppKind,
    /// VLESS mux path: `true` routes the row through
    /// [`super::harness::probe_mux`] — one `connect_mux` tunnel carrying
    /// [`super::harness::MUX_SESSION_COUNT`] concurrent sessions to the
    /// echo target instead of the single-stream probe. The row's `app`
    /// stays [`AppKind::Plain`] (the probe sends HTTP over the sessions).
    mux: bool,
    /// UDP packet mode for UDP rows: `None` = the TCP path (default);
    /// `Some(mode)` selects the VLESS UDP datagram tunnel ([`PacketMode`]
    /// `Raw` = header-dest, `PacketAddr` = per-packet address header
    /// (`atyp|addr|port`) — the magic fqdn is header-dest only, never in
    /// the frame). Ignored unless `app` is [`AppKind::Udp`]; drives
    /// `NativeConnectParams.udp` for the probe's `connect_udp`.
    udp: Option<PacketMode>,
    /// VLESS `mlkem768x25519plus` account encryption: `(client encryption,
    /// server decryption)` strings sharing one generated keypair set
    /// ([`config::mlkem_enc_pair`]). `Some` wires the client outbound's
    /// `encryption` and the xray inbound's `settings.decryption` (xray-only
    /// — sing-box has no VLESS account encryption).
    vless_enc: Option<(String, String)>,
    /// Assert that the tunnel's outer TLS handshake negotiated a hybrid
    /// (post-quantum) key share — a PQ row that silently fell back to
    /// classical fails instead of passing.
    pq_assert: bool,
    /// Hysteria2 Salamander obfuscation PSK (`Some` enables it).
    obfs: Option<&'static str>,
    /// Single-core gate: `Some(kind)` restricts the row to that core only
    /// (hysteria2 is sing-box-only — xray-core has no hysteria2 inbound; the
    /// SS TLS row is xray-only — sing-box's shadowsocks inbound has no `tls`
    /// field). Set via [`CaseSpec::with_single_core`].
    single_core: Option<CoreKind>,
    /// Shadowsocks cipher method (`None` for every other protocol); selects
    /// the codec family and the server config's method/password.
    ss_method: Option<&'static str>,
}

impl CaseSpec {
    #[must_use]
    pub fn vless() -> Self {
        Self {
            protocol: ProtocolKind::Vless,
            security: None,
            tls: None,
            network: "tcp",
            xhttp_mode: None,
            flow: None,
            app: AppKind::Plain,
            mux: false,
            udp: None,
            vless_enc: None,
            pq_assert: false,
            obfs: None,
            single_core: None,
            ss_method: None,
        }
    }

    #[must_use]
    pub fn vmess(variant: impl SecurityVariant + 'static) -> Self {
        Self {
            protocol: ProtocolKind::Vmess,
            security: Some(Box::new(variant)),
            tls: None,
            network: "tcp",
            xhttp_mode: None,
            flow: None,
            app: AppKind::Plain,
            mux: false,
            udp: None,
            vless_enc: None,
            pq_assert: false,
            obfs: None,
            single_core: None,
            ss_method: None,
        }
    }

    /// A trojan case: password + transport, cert-TLS or fingerprint
    /// security via [`CaseSpec::with_tls`].
    #[must_use]
    pub fn trojan() -> Self {
        Self {
            protocol: ProtocolKind::Trojan,
            security: None,
            tls: None,
            network: "tcp",
            xhttp_mode: None,
            flow: None,
            app: AppKind::Plain,
            mux: false,
            udp: None,
            vless_enc: None,
            pq_assert: false,
            obfs: None,
            single_core: None,
            ss_method: None,
        }
    }

    /// A hysteria2 case (QUIC dial): always single-core sing-box (xray-core
    /// has no hysteria2 inbound). `obfs` enables Salamander obfuscation.
    #[must_use]
    pub fn hysteria2(obfs: Option<&'static str>) -> Self {
        Self {
            protocol: ProtocolKind::Hysteria2,
            security: None,
            tls: None,
            network: "tcp",
            xhttp_mode: None,
            flow: None,
            app: AppKind::Plain,
            mux: false,
            udp: None,
            vless_enc: None,
            pq_assert: false,
            obfs,
            single_core: Some(CoreKind::SingBox),
            ss_method: None,
        }
    }

    /// A Shadowsocks case: `method` selects the cipher family
    /// (`aes-128-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`,
    /// `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`,
    /// `2022-blake3-chacha20-poly1305`).
    ///
    /// `SsConfig` has no transport field, so the row is a plain TCP dial —
    /// cert/fingerprint TLS via [`CaseSpec::with_tls`], or `NoTls` for the
    /// genuinely plain rows (the `ss(...)` helpers in `tests/shadowsocks.rs`).
    #[must_use]
    pub fn shadowsocks(method: &'static str) -> Self {
        Self {
            protocol: ProtocolKind::Shadowsocks,
            security: None,
            tls: None,
            network: "tcp",
            xhttp_mode: None,
            flow: None,
            app: AppKind::Plain,
            mux: false,
            udp: None,
            vless_enc: None,
            pq_assert: false,
            obfs: None,
            single_core: None,
            ss_method: Some(method),
        }
    }

    /// Wire VLESS `mlkem768x25519plus` account encryption: generates a
    /// fresh keypair set and carries `(client encryption, server
    /// decryption)` in the case. The row is xray-single-core.
    #[must_use]
    pub fn with_pq_enc(mut self) -> Self {
        self.vless_enc = Some(config::mlkem_enc_pair());
        self
    }

    /// [`Self::with_pq_enc`], but with a pair the CALLER supplies.
    ///
    /// Exists to run the pq-enc row against a keypair the REFERENCE generated
    /// (`xray vlessenc`), which is the one experiment that separates "our
    /// client's wire is wrong" from "our test's key generator is wrong": the
    /// reference pair is self-consistent on the server side, so a red row with
    /// it indicts the client, and a green one indicts [`config::mlkem_enc_pair`].
    #[must_use]
    pub fn with_pq_enc_pair(mut self, client: String, server: String) -> Self {
        self.vless_enc = Some((client, server));
        self
    }

    /// Assert PQ negotiation: the runner requires the outer TLS handshake's
    /// `ServerHello` to have selected a hybrid key-share group.
    #[must_use]
    pub const fn with_pq_assert(mut self) -> Self {
        self.pq_assert = true;
        self
    }

    /// Whether the row asserts hybrid (PQ) negotiation.
    #[must_use]
    pub const fn pq_assert(&self) -> bool {
        self.pq_assert
    }

    /// Select the transport ("tcp", "ws", "grpc").
    #[must_use]
    pub const fn with_network(mut self, network: &'static str) -> Self {
        self.network = network;
        self
    }

    #[must_use]
    pub const fn network(&self) -> &'static str {
        self.network
    }

    /// Select the client-side xhttp dialect ("stream-up"; packet-up is the
    /// default). Ignored for non-xhttp networks.
    #[must_use]
    pub const fn with_xhttp_mode(mut self, mode: &'static str) -> Self {
        self.xhttp_mode = Some(mode);
        self
    }

    /// Select the VLESS flow control ("vision"; the default is no flow).
    #[must_use]
    pub const fn with_flow(mut self, flow: Flow) -> Self {
        self.flow = Some(flow);
        self
    }

    /// Select the app-side probe kind: plain HTTP over the tunnel (default),
    /// an inner TLS session through the tunnel to a rustls echo target, or
    /// UDP datagrams to the UDP echo target.
    #[must_use]
    pub const fn with_app(mut self, app: AppKind) -> Self {
        self.app = app;
        self
    }

    /// Select the UDP packet mode (`Raw` / `PacketAddr`); the row's `app`
    /// must be [`AppKind::Udp`] (the mode drives the probe's `connect_udp`).
    #[must_use]
    pub const fn with_udp(mut self, mode: PacketMode) -> Self {
        self.udp = Some(mode);
        self
    }

    /// Restrict a row to one core (used when the server side genuinely cannot
    /// serve the config — e.g. sing-box 1.13's shadowsocks inbound has no
    /// `tls` field, so the SS TLS row is xray-only).
    #[must_use]
    pub const fn with_single_core(mut self, kind: CoreKind) -> Self {
        self.single_core = Some(kind);
        self
    }

    /// The app-side probe kind.
    #[must_use]
    pub const fn app(&self) -> AppKind {
        self.app
    }

    /// Select the VLESS mux probe: `run_against` establishes one
    /// `connect_mux` tunnel and opens [`super::harness::MUX_SESSION_COUNT`]
    /// concurrent sessions to the echo target (default `false` = the
    /// single-stream probe). The label gains `/mux`.
    #[must_use]
    pub const fn with_mux(mut self, mux: bool) -> Self {
        self.mux = mux;
        self
    }

    /// Whether the row probes the VLESS mux path (`run_against` routes it
    /// to [`super::harness::probe_mux`] / [`super::harness::probe_udp_mux`]).
    /// The `xtls-rprx-vision-udp443` flow forces the mux tunnel regardless
    /// of the flag (spec §4.3 — `connect_udp` rewrites UDP to XUDP under
    /// the udp443 flow).
    #[must_use]
    pub const fn mux(&self) -> bool {
        self.mux || matches!(self.flow, Some(Flow::Udp443))
    }

    /// Select the TLS transport variant (fingerprint engine or REALITY).
    #[must_use]
    pub fn with_tls(mut self, tls: Box<dyn TlsVariant>) -> Self {
        self.tls = Some(tls);
        self
    }

    /// The TLS variant, defaulting to stock rustls.
    fn tls(&self) -> &dyn TlsVariant {
        self.tls.as_deref().unwrap_or(&StandardTls)
    }

    /// Cores this case runs against (variant gate; no security → both).
    #[must_use]
    pub fn cores(&self) -> &'static [CoreKind] {
        if let Some(kind) = self.single_core {
            return match kind {
                CoreKind::Xray => &[CoreKind::Xray],
                CoreKind::SingBox => &[CoreKind::SingBox],
            };
        }
        if self.vless_enc.is_some() {
            // VLESS account encryption: sing-box has no decryption support.
            return &[CoreKind::Xray];
        }
        self.security
            .as_ref()
            .map_or(&[CoreKind::Xray, CoreKind::SingBox], |s| s.cores())
    }

    /// True when the row's server must be probed over UDP at readiness time:
    /// a QUIC/QUIC-family listener (hysteria2 — UDP-only) or an SS row whose
    /// `app` is [`AppKind::Udp`].
    ///
    /// `harness::spawn_core`'s UDP probe binds an EPHEMERAL socket and sends
    /// a datagram at the server's port — it never binds that port — so it is
    /// safe for SS's dual TCP+UDP listener: it only proves the server's UDP
    /// socket is bound. A TCP accept alone can win the race against xray's
    /// UDP bind (the client only ever uses the server's UDP port), losing the
    /// first datagram and burning the full probe deadline. SS TCP rows stay
    /// `false` (their client never touches UDP).
    #[must_use]
    pub const fn is_udp_listener(&self) -> bool {
        match self.protocol {
            ProtocolKind::Hysteria2 => true,
            ProtocolKind::Shadowsocks => matches!(self.app, AppKind::Udp),
            _ => false,
        }
    }
}

impl E2eCase for CaseSpec {
    fn label(&self) -> String {
        let proto = match self.protocol {
            ProtocolKind::Vless => "vless",
            ProtocolKind::Vmess => "vmess",
            ProtocolKind::Trojan => "trojan",
            ProtocolKind::Hysteria2 => "hysteria2",
            ProtocolKind::Shadowsocks => "ss",
        };
        // The SS method is the row's identity: two SS rows differ only by it.
        let meth = self.ss_method.map_or(String::new(), |m| format!("/{m}"));
        let flow = self
            .flow
            .map_or_else(String::new, |flow| format!("{}/", flow.as_str()));
        let tls = self.tls.as_deref().map_or("tls", TlsVariant::name);
        let sec = self
            .security
            .as_ref()
            .map_or(String::new(), |s| format!("/{}", s.name()));
        let app = match self.app {
            AppKind::Plain => String::new(),
            AppKind::InnerTls => "/inner-tls".to_string(),
            AppKind::Udp => format!(
                "/udp-{}",
                self.udp.map_or("raw", |m| match m {
                    PacketMode::Raw => "raw",
                    PacketMode::PacketAddr => "packetaddr",
                    PacketMode::XUdp => "xudp",
                })
            ),
        };
        let mux = if self.mux() { "/mux" } else { "" };
        let obfs = if self.obfs.is_some() {
            "/obfs-salamander"
        } else {
            ""
        };
        let pq = if self.pq_assert { "/pq" } else { "" };
        let enc = if self.vless_enc.is_some() {
            "/pq-enc"
        } else {
            ""
        };
        format!(
            "{proto}{meth}/{flow}{}/{tls}{sec}{app}{mux}{obfs}{pq}{enc}",
            self.network
        )
    }

    fn server_config(&self, core: CoreKind, env: &ServerEnv) -> String {
        match self.protocol {
            ProtocolKind::Vless => config::vless_inbound(
                core,
                env,
                self.flow,
                self.tls(),
                self.network,
                self.vless_enc.as_ref().map(|(_, server)| server.as_str()),
            ),
            ProtocolKind::Vmess => {
                let security = self.security.as_ref().and_then(|s| s.server_security(core));
                config::vmess_inbound(core, env, security, self.tls(), self.network)
            }
            ProtocolKind::Trojan => config::trojan_inbound(core, env, self.network),
            ProtocolKind::Hysteria2 => config::hysteria2_inbound(env, self.obfs),
            ProtocolKind::Shadowsocks => config::ss_inbound(
                core,
                env,
                self.tls(),
                self.network,
                self.ss_method.expect("shadowsocks case requires a method"),
                self.app == AppKind::Udp,
            ),
        }
    }

    fn client_params(&self, port: u16, target: SocketAddr) -> NativeConnectParams {
        let mut params = match self.protocol {
            ProtocolKind::Vless => config::client_params_vless(
                port,
                target,
                self.flow,
                self.tls(),
                self.network,
                self.xhttp_mode,
            ),
            ProtocolKind::Vmess => {
                let enc = self
                    .security
                    .as_ref()
                    .expect("vmess case requires a security variant")
                    .client_security();
                config::client_params_vmess(
                    enc,
                    port,
                    target,
                    self.tls(),
                    self.network,
                    self.xhttp_mode,
                )
            }
            ProtocolKind::Trojan => {
                config::client_params_trojan(port, target, self.tls(), self.network)
            }
            ProtocolKind::Hysteria2 => config::client_params_hysteria2(port, target, self.obfs),
            ProtocolKind::Shadowsocks => config::client_params_ss(
                port,
                target,
                self.tls(),
                self.network,
                self.ss_method.expect("shadowsocks case requires a method"),
            ),
        };
        // pq-enc rows: the VLESS outbound carries the mlkem768x25519plus
        // account `encryption` (the client-side PUBLIC key segments).
        if let Some((client, _)) = &self.vless_enc
            && let leas_proto::proto_spec::ProtocolConfig::Vless(cfg) = &mut params.protocol
        {
            cfg.encryption = Some(client.as_str().into());
        }
        // UDP rows: the VLESS UDP datagram tunnel dispatches on the params'
        // packet mode (`connect_udp` requires it; the proto has no
        // `packet_encoding` field — spec §4.3, no proto changes allowed).
        params.udp = self.udp;
        // Mux rows (incl. the udp443 flow, which forces the mux path):
        // the probe's `connect_udp` dispatches XUDP on `params.mux`
        // (connect_mux ignores it, so the TCP mux rows are unaffected).
        params.mux = self.mux();
        params
    }

    fn expected(&self) -> E2eExpect {
        let connect = if self.tls().expect_fallback() {
            ConnectExpect::ErrRealityFallback
        } else {
            ConnectExpect::Ok
        };
        E2eExpect {
            connect,
            ..Default::default()
        }
    }

    fn probe_target(&self, env: &ServerEnv) -> SocketAddr {
        // UDP rows echo datagrams to the dedicated UDP target (the probe's
        // `connect_udp` header destination). Inner-TLS rows splice to a
        // rustls echo target (the vision Direct path); a plain client
        // through a REALITY server is transparently proxied and terminates
        // at the server's dest — probe that instead of the plain echo.
        if self.app == AppKind::Udp {
            env.udp_echo.expect("udp rows spawn the UDP echo target")
        } else if self.app == AppKind::InnerTls {
            env.inner_tls_echo
                .expect("inner-tls rows spawn the inner TLS echo target")
        } else if self.tls().probe_dest() {
            env.tls_echo
        } else {
            env.echo
        }
    }

    fn spider_reaches_dest(&self) -> bool {
        self.tls().spider_reaches_dest()
    }

    fn client_trust(&self, certs: &Certs) {
        self.tls().client_trust(certs);
    }
}

#[cfg(test)]
mod tests {
    use super::super::variant::{
        Aes128GcmVariant, Chacha20Poly1305Variant, FingerprintTls, NoTls, RealityTls, StandardTls,
    };
    use super::*;

    #[test]
    fn derived_labels() {
        assert_eq!(CaseSpec::vless().label(), "vless/tcp/tls");
        assert_eq!(
            CaseSpec::vmess(Aes128GcmVariant).label(),
            "vmess/tcp/tls/aes-128-gcm"
        );
        assert_eq!(
            CaseSpec::vmess(Chacha20Poly1305Variant).label(),
            "vmess/tcp/tls/chacha20-poly1305"
        );
        assert_eq!(
            CaseSpec::vless().with_tls(Box::new(StandardTls)).label(),
            "vless/tcp/tls-standard"
        );
        assert_eq!(
            CaseSpec::vless()
                .with_tls(Box::new(FingerprintTls("chrome")))
                .label(),
            "vless/tcp/tls-chrome"
        );
        // The genuinely plain (no-TLS) row labels with the variant name.
        assert_eq!(
            CaseSpec::vless()
                .with_network("kcp")
                .with_tls(Box::new(NoTls))
                .label(),
            "vless/kcp/plain"
        );
        assert_eq!(
            CaseSpec::vmess(Aes128GcmVariant)
                .with_tls(Box::new(RealityTls::fresh()))
                .label(),
            "vmess/tcp/reality/aes-128-gcm"
        );
        assert_eq!(
            CaseSpec::vless().with_flow(Flow::Vision).label(),
            "vless/xtls-rprx-vision/tcp/tls"
        );
        assert_eq!(
            CaseSpec::vless()
                .with_flow(Flow::Vision)
                .with_tls(Box::new(RealityTls::fresh()))
                .label(),
            "vless/xtls-rprx-vision/tcp/reality"
        );
        assert_eq!(
            CaseSpec::vless()
                .with_flow(Flow::Vision)
                .with_tls(Box::new(RealityTls::fresh()))
                .with_app(AppKind::InnerTls)
                .label(),
            "vless/xtls-rprx-vision/tcp/reality/inner-tls"
        );
        // UDP rows carry the packet mode in the label (Raw vs PacketAddr).
        assert_eq!(
            CaseSpec::vless()
                .with_app(AppKind::Udp)
                .with_udp(PacketMode::Raw)
                .label(),
            "vless/tcp/tls/udp-raw"
        );
        assert_eq!(
            CaseSpec::vless()
                .with_tls(Box::new(RealityTls::fresh()))
                .with_app(AppKind::Udp)
                .with_udp(PacketMode::PacketAddr)
                .label(),
            "vless/tcp/reality/udp-packetaddr"
        );
        // Mux rows: the client-side probe axis gains `/mux`; the app stays
        // plain (HTTP over the sessions).
        assert_eq!(
            CaseSpec::vless().with_mux(true).label(),
            "vless/tcp/tls/mux"
        );
        assert_eq!(
            CaseSpec::vless()
                .with_tls(Box::new(RealityTls::fresh()))
                .with_mux(true)
                .label(),
            "vless/tcp/reality/mux"
        );
        // XUDP rows: the udp443 flow (client-facing name in the label)
        // forces the `/mux` suffix — the flow implies the mux path.
        assert_eq!(
            CaseSpec::vless()
                .with_flow(Flow::Udp443)
                .with_app(AppKind::Udp)
                .with_udp(PacketMode::XUdp)
                .label(),
            "vless/xtls-rprx-vision-udp443/tcp/tls/udp-xudp/mux"
        );
        // SS rows: the method is part of the name (two SS rows differ only
        // by it); the tls segment still names the variant, and there is no
        // transport dimension.
        assert_eq!(
            CaseSpec::shadowsocks("aes-128-gcm")
                .with_tls(Box::new(NoTls))
                .label(),
            "ss/aes-128-gcm/tcp/plain"
        );
        assert_eq!(
            CaseSpec::shadowsocks("2022-blake3-chacha20-poly1305")
                .with_app(AppKind::Udp)
                .with_udp(PacketMode::Raw)
                .label(),
            "ss/2022-blake3-chacha20-poly1305/tcp/tls/udp-raw"
        );
    }

    #[test]
    fn mux_defaults_off_and_plumbs() {
        // Default rows keep the single-stream probe.
        assert!(!CaseSpec::vless().mux());
        assert!(!CaseSpec::vmess(Aes128GcmVariant).mux());
        // The axis is sticky once selected.
        assert!(CaseSpec::vless().with_mux(true).mux());
        // The udp443 flow forces the mux path even without the flag (spec
        // §4.3 — connect_udp rewrites UDP to XUDP under the udp443 flow);
        // the plain vision flow does not.
        assert!(CaseSpec::vless().with_flow(Flow::Udp443).mux());
        assert!(!CaseSpec::vless().with_flow(Flow::Vision).mux());
        // Mux rows keep `params.udp` unset — the TCP mux probe (XUDP rows
        // set both, via the Task 4 harness plumbing).
        let params = CaseSpec::vless()
            .with_mux(true)
            .client_params(12345, "127.0.0.1:9999".parse().unwrap());
        assert_eq!(params.udp, None);
        // The probe's `connect_udp` dispatches XUDP on `params.mux`, so the
        // params carry it: the explicit flag and the udp443 flow both.
        assert!(params.mux);
        let params = CaseSpec::vless()
            .with_flow(Flow::Udp443)
            .client_params(12345, "127.0.0.1:9999".parse().unwrap());
        assert!(params.mux);
        // Non-mux rows leave the params' default false.
        let params = CaseSpec::vless().client_params(12345, "127.0.0.1:9999".parse().unwrap());
        assert!(!params.mux);
    }

    #[test]
    fn flow_server_string_truncates_udp443() {
        // The udp443 suffix is client-side only: the wire addon truncates
        // to `xtls-rprx-vision` (spec §4.3) and the server validates
        // against that — both flows emit the same server string.
        assert_eq!(Flow::Vision.as_str(), "xtls-rprx-vision");
        assert_eq!(Flow::Udp443.as_str(), "xtls-rprx-vision-udp443");
        assert_eq!(Flow::Vision.server_str(), "xtls-rprx-vision");
        assert_eq!(Flow::Udp443.server_str(), "xtls-rprx-vision");
    }

    #[test]
    fn udp_readiness_gate() {
        // A UDP row's client only ever uses the server's UDP port, so the
        // readiness probe must be the UDP one (a TCP accept can win the race
        // against the server's UDP bind and lose the first datagram).
        assert!(
            CaseSpec::shadowsocks("aes-128-gcm")
                .with_app(AppKind::Udp)
                .with_udp(PacketMode::Raw)
                .is_udp_listener()
        );
        // SS TCP rows never touch UDP: the readiness probe stays a TCP accept.
        assert!(!CaseSpec::shadowsocks("aes-128-gcm").is_udp_listener());
        // hysteria2 is a QUIC (UDP-only) listener regardless of `app`.
        assert!(CaseSpec::hysteria2(None).is_udp_listener());
        // The other protocols' listeners are TCP.
        assert!(!CaseSpec::trojan().is_udp_listener());
        assert!(
            !CaseSpec::vless()
                .with_app(AppKind::Udp)
                .with_udp(PacketMode::Raw)
                .is_udp_listener()
        );
    }

    #[test]
    fn cores_gate_defaults_to_both() {
        assert_eq!(
            CaseSpec::vless().cores(),
            &[CoreKind::Xray, CoreKind::SingBox]
        );
        assert_eq!(
            CaseSpec::vmess(Chacha20Poly1305Variant).cores(),
            &[CoreKind::Xray, CoreKind::SingBox]
        );
        // SS rows default to both cores; `with_single_core` narrows exactly
        // the TLS row (sing-box 1.13's shadowsocks inbound has no `tls`).
        assert_eq!(
            CaseSpec::shadowsocks("aes-128-gcm").cores(),
            &[CoreKind::Xray, CoreKind::SingBox]
        );
        assert_eq!(
            CaseSpec::shadowsocks("aes-128-gcm")
                .with_single_core(CoreKind::Xray)
                .cores(),
            &[CoreKind::Xray]
        );
    }
}
