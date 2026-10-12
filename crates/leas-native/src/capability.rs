//! Native-capability predicate: which protocol+config rows the in-process
//! core may serve (spec brief §2).
//!
//! [`kind_supported`] is the cheap kind-only gate (display/sort paths that
//! cannot load the full config); [`support_reason`] is the config-aware
//! runtime gate (connect/ping paths) and [`supported`] its bool form, so the
//! reason it returns doubles as the user-visible `[real]` marker text. A row
//! native serves *worse* than a subprocess is refused so Auto resolution falls
//! back to the subprocess. VLESS `mlkem768x25519plus` account encryption was
//! such a row until 2026-09-23; it is now supported and gated on the connect
//! path's own parser (`mlkem_encryption_supported`), which refuses only a
//! value that is not that scheme or that the codec would reject at dial time.
//!
//! The predicate mirrors the native dispatch arms, not xray's feature set:
//! [`crate::protocol`], [`crate::transport`], and [`crate::security`]. A
//! combo both cores reject (equal-failure) stays `true` per brief D5; only
//! native-worse/deferred markers return `false`.
//!
//! Unknown values fail CLOSED. A row carrying a field native cannot parse (an
//! mKCP seed, an unimplemented transport) returns `false`: a false positive is
//! a connection that dies (or worse, hangs) where the subprocess would have
//! worked, while a false negative costs only the in-process fast path.
//!
//! A TLS fingerprint id is **no longer a refusal**: an id with no roster row is
//! probed with the engine default and marked approximated
//! (`security::fingerprint::resolve_fingerprint`, read by `security::wrap`
//! where the substitution happens), so this gate does not consult one.

use std::borrow::Cow;

use leas_proto::proto_spec::common::{KcpConfig, TransportConfig};
use leas_proto::proto_spec::{
    Hysteria2Config, MuxSetting, PluginFamily, PluginMode, PluginSpec, ProtocolConfig,
    ProtocolKind, SsConfig, TlsSetting, TrojanConfig, VlessConfig, VlessMux, VmessConfig,
};
use leas_proto::proto_spec::{
    SecurityConfig, TlsConfig,
    ss_plugin::{OBFS_KEYS, V2RAY_KEYS},
};

use crate::protocol::ss::method::password_key;
use crate::protocol::ss::resolve_method;
use crate::protocol::vless::encryption::EncryptionConfig;

/// The protocols with a native implementation, in canonical order.
///
/// Must stay exactly `[Vless, Vmess, Trojan, Hysteria2, Shadowsocks,
/// Shadowsocks2022]` — the e2e-verified protocols the TUI may Auto-resolve
/// onto native. The two Shadowsocks kinds are separate entries because the
/// typed kind carries the cipher family (`2022-blake3-*` → `Shadowsocks2022`)
/// even though both share one [`SsConfig`].
pub const NATIVE_KINDS: &[ProtocolKind] = &[
    ProtocolKind::Vless,
    ProtocolKind::Vmess,
    ProtocolKind::Trojan,
    ProtocolKind::Hysteria2,
    ProtocolKind::Shadowsocks,
    ProtocolKind::Shadowsocks2022,
];

/// True when the protocol kind has a native implementation at all.
///
/// Config-blind: used where the loaded [`ProtocolConfig`] is unavailable
/// (display/sort). Connect-time may still downgrade on a
/// capability-deferred config (see [`supported`]).
#[must_use]
pub const fn kind_supported(kind: ProtocolKind) -> bool {
    matches!(
        kind,
        ProtocolKind::Vless
            | ProtocolKind::Vmess
            | ProtocolKind::Trojan
            | ProtocolKind::Hysteria2
            | ProtocolKind::Shadowsocks
            | ProtocolKind::Shadowsocks2022
    )
}

/// The reason a protocol kind has no native implementation at all.
///
/// Public because the ping gate decides this level WITHOUT a loaded config and
/// must not duplicate the text.
pub const KIND_UNSUPPORTED_REASON: &str = "no native implementation for this protocol kind";

/// Why native refuses this exact protocol+config row, or [`None`] when it
/// serves it.
///
/// The reason is the persisted, user-visible `[real]` marker text, so these
/// strings are an interface, not log prose. `support_reason(kind,
/// config).is_none()` is exactly [`supported`]. A row is refused when
/// `kind_supported(kind)` is false (`"no native implementation for this
/// protocol kind"`), when the config variant does not match `kind`
/// (`"protocol kind and config type do not match"`), or when the config
/// requests a native-worse/deferred feature — each predicate below documents
/// its own string.
///
/// The verdict is TCP-truthful — it covers the byte-stream path only.
/// SOCKS5 UDP ASSOCIATE through the native proxy outbound is not
/// implemented: `inbound::outbound::proxy_params` never sets `params.udp`,
/// and `protocol::vless::connect_udp` rejects `params.udp == None` as a
/// config error, so a native session drops the proxy UDP leg (debug-logged)
/// no matter what this predicate answers. Gating UDP-capable shapes off
/// that gap would cost them their native TCP path for a UDP leg no config
/// can reach today — see `vless_reason` for the vision flows.
///
/// The Shadowsocks row is the sharpest case of that stance: `SsConfig` has no
/// transport field at all, so the verdict covers the plain-TCP dial plus
/// optional `security` and nothing else — the UDP dial-end refuses a
/// non-empty `security` inside `ss::udp::connect_udp`, and refuses a chain in
/// `chain.rs::ss_udp_guard`, which is where both refusals belong.
#[must_use]
pub fn support_reason(kind: ProtocolKind, config: &ProtocolConfig) -> Option<Cow<'static, str>> {
    if !kind_supported(kind) {
        return Some(Cow::Borrowed(KIND_UNSUPPORTED_REASON));
    }
    // The Shadowsocks arm is dispatched first, and apart from ordering it is
    // also the one that can name a VALUE from the row (a plugin option), which
    // needs an owned string rather than a `&'static` reason.
    if let (ProtocolKind::Shadowsocks | ProtocolKind::Shadowsocks2022, ProtocolConfig::Ss(cfg)) =
        (kind, config)
    {
        return ss_reason(kind, cfg);
    }
    match (kind, config) {
        // VLESS first: its mux refusals are value-bearing (an unusable option
        // names the option), so it already returns `Cow`.
        (ProtocolKind::Vless, ProtocolConfig::Vless(cfg)) => vless_reason(cfg),
        (ProtocolKind::Vmess, ProtocolConfig::Vmess(cfg)) => vmess_reason(cfg).map(Cow::Borrowed),
        (ProtocolKind::Trojan, ProtocolConfig::Trojan(cfg)) => {
            trojan_reason(cfg).map(Cow::Borrowed)
        }
        (ProtocolKind::Hysteria2, ProtocolConfig::Hysteria2(cfg)) => {
            hysteria2_reason(cfg).map(Cow::Borrowed)
        }
        _ => Some(Cow::Borrowed("protocol kind and config type do not match")),
    }
}

/// True when native should serve this exact protocol+config row.
///
/// The bool form of [`support_reason`], which documents the predicate
/// itself.
#[must_use]
pub fn supported(kind: ProtocolKind, config: &ProtocolConfig) -> bool {
    support_reason(kind, config).is_none()
}

/// Why the transport is not buildable, or [`None`] — the transports native
/// can build are a POSITIVE match of the arms `transport::connect` /
/// `transport::upgrade` actually dispatch: tcp/ws/grpc/httpupgrade/xhttp/http
/// (v2rayhttp) ride the dial + upgrade chain, xhttp+h3 replaces the dial with
/// its own QUIC one, and kcp is a fresh UDP dial.
///
/// Bare `TransportConfig::Quic` has no arm (`NotImplemented("transport
/// quic")`) — xray-only, so deferred: `"transport is not implemented"`. The
/// match is deliberately exhaustive (no wildcard): a variant added to
/// `TransportConfig` breaks THIS function at compile time rather than
/// inheriting `true`, which is the strongest fail-closed shape available —
/// nothing new can pass unreviewed.
///
/// `path` is the protocol row's own `path` field, forwarded for the mKCP
/// seed check ([`kcp_reason`]); every other arm ignores it (their path
/// lives inside the transport config).
fn transport_reason(transport: &TransportConfig, path: Option<&str>) -> Option<&'static str> {
    match transport {
        TransportConfig::Tcp
        | TransportConfig::Ws(_)
        | TransportConfig::Grpc(_)
        | TransportConfig::Http(_)
        | TransportConfig::HttpUpgrade(_)
        | TransportConfig::XHttp(_) => None,
        TransportConfig::Kcp(cfg) => kcp_reason(cfg, path),
        TransportConfig::Quic => Some("transport is not implemented"),
    }
}

/// Bool form of [`transport_reason`] — the shape the direct dispatch-table
/// test asserts on.
#[cfg(test)]
fn transport_supported(transport: &TransportConfig, path: Option<&str>) -> bool {
    transport_reason(transport, path).is_none()
}

/// mKCP row: only the settings the native dial actually reads.
///
/// `transport::kcp::connect` reads `mtu` + `tti` and nothing else (spec §4.5
/// defaults otherwise). Capacity/congestion/buffer fields are local pacing
/// knobs — ignoring them still interoperates. Two fields are not knobs but
/// WIRE FORMAT, so ignoring them frames every datagram differently than the
/// server expects: the packets are dropped and the dial hangs instead of
/// failing loudly, the worst failure shape there is. Either of them is
/// refused as `"mKCP seed or header_type is not implemented"`.
///
/// - `seed`: mKCP's global obfuscation key. Clash configs carry it in
///   `KcpConfig::seed`; share links carry it in the protocol row's `path`
///   (`vless://…?type=kcp&path=<seed>`), which is why `path` is checked here
///   too. Native has no obfuscator at all.
/// - `header_type`: the packet camouflage header (`srtp`, `utp`,
///   `wechat-video`, `dtls`, `wireguard`, `dns`). Only the default `none`
///   is a bare mKCP datagram.
fn kcp_reason(cfg: &KcpConfig, path: Option<&str>) -> Option<&'static str> {
    let seeded =
        cfg.seed.as_deref().is_some_and(|s| !s.is_empty()) || path.is_some_and(|s| !s.is_empty());
    let camouflaged = cfg
        .header_type
        .as_deref()
        .is_some_and(|h| !(h.is_empty() || h == "none"));
    (seeded || camouflaged).then_some("mKCP seed or header_type is not implemented")
}

// The fingerprint refusal gate is retired: an id with no engine hello is now
// probed with the engine default and marked approximated
// (`security::fingerprint::resolve_fingerprint`) rather than refused, so a
// subscription carrying `qq`/`android`/`360` no longer defers to the
// subprocess. It was removed rather than left returning `None`, so no caller
// can quietly re-introduce a divergence between this gate and
// `security::wrap`: both now read the same resolver.

/// VLESS row: implemented account encryption and flow, implemented transport.
///
/// Account encryption: any non-empty `encryption` other than `"none"` must be
/// an `mlkem768x25519plus` value the CONNECT PATH can actually dial
/// ([`mlkem_encryption_supported`] runs the codec's own parser, so the gate
/// cannot drift from it) — anything else is refused as `"vless account
/// encryption is not implemented"`. Flows are limited to the vision pair native
/// encodes (`connect_vision`); any other non-empty flow is a `NotImplemented`
/// guard, refused as `"vless flow is not implemented"`. A transport refusal
/// appends the [`transport_reason`] string.
///
/// Both vision flows stay supported even though a native session cannot
/// carry their UDP leg (`xtls-rprx-vision-udp443` forces XUDP, and the proxy
/// leg never sets `params.udp` — see [`supported`]): vision over REALITY is
/// the most common native shape and its TCP path is fully implemented, so
/// deferring it would trade a live fast path for a UDP leg that is dead on
/// both sides of the decision.
fn vless_reason(cfg: &VlessConfig) -> Option<Cow<'static, str>> {
    if let Some(enc) = cfg.encryption.as_deref()
        && !enc.is_empty()
        && enc != "none"
        && !mlkem_encryption_supported(enc)
    {
        return Some(Cow::Borrowed("vless account encryption is not implemented"));
    }
    if let Some(flow) = cfg.flow.as_deref()
        && !(flow.is_empty() || flow == "xtls-rprx-vision" || flow == "xtls-rprx-vision-udp443")
    {
        return Some(Cow::Borrowed("vless flow is not implemented"));
    }
    // A mux spelling we cannot serve, refused HERE rather than at parse so the
    // row stays importable, exportable and correctly marked untestable — the same
    // two-layer rule the plugin family follows with `MuxSetting::Invalid`.
    if let Some(VlessMux::Invalid { key, value }) = &cfg.mux {
        return Some(match key.as_str() {
            // Named WITH its value: §8 requires every refusal to name the row's
            // own key/value, and the plugin family already interpolates the same
            // way (`ss_reason`).
            "muxtype" => Cow::Owned(format!(
                "vless multiplexer `{key}={value}` is not implemented — only the default \
                 v1.mux.cool codec"
            )),
            // An unusable value: named, because "the row asked for mux and we
            // cannot honour it" is the diagnosis, and silently treating it as "no
            // mux" would dial without frames while looking as if it had asked.
            // The value is named, not just the key: "the row asked for mux and
            // we cannot honour it" needs the spelling to be actionable.
            _ => {
                return Some(Cow::Owned(format!(
                    "vless mux option `{key}={value}` is not a supported cap"
                )));
            }
        });
    }
    // Vision × mux: the row is refused rather than dialed, because a vision
    // account may only carry XUDP mux (Xray's `command=Mux` with port 666), and
    // we send the plain `v1.mux.cool` form, which Xray's inbound rejects
    // (`isMuxAndNotXUDP`, `thirdparty/Xray-core/proxy/vless/inbound/inbound.go:180-184`).
    if cfg.mux.as_ref().is_some_and(VlessMux::is_active)
        && let Some(flow) = cfg.flow.as_deref()
        && flow.starts_with("xtls-rprx-vision")
    {
        // Named with its value, like every other refusal here (§8): "your
        // `flow` was X" is what a row needs to say to be actionable.
        return Some(Cow::Owned(format!(
            "vless flow `{flow}` with plain mux is not implemented — a vision account may only \
             carry XUDP mux (port 666)"
        )));
    }
    transport_reason(&cfg.transport, cfg.path.as_deref()).map(Cow::Borrowed)
}

/// Whether a non-`none` VLESS `encryption` value is one native can serve.
///
/// `mlkem768x25519plus` IS implemented (`protocol/vless/encryption`), so the
/// only refusal left is a value that is not that scheme at all. The check runs
/// the CONNECT PATH'S OWN PARSER (`parse_mlkem_encryption` then
/// [`EncryptionConfig::try_from_parsed`]) rather than a string test, so the
/// gate and the codec cannot drift: anything the codec would reject at dial
/// time (a malformed base64 key segment, an out-of-range padding spec, an
/// unknown mode/window) is refused here, and anything it accepts is offered to
/// the fast path. Fails closed — a lowercased or otherwise unrecognised scheme
/// yields `Ok(None)` and is refused.
fn mlkem_encryption_supported(enc: &str) -> bool {
    leas_proto::proto_spec::parse_mlkem_encryption(enc)
        .ok()
        .flatten()
        .is_some_and(|parsed| EncryptionConfig::try_from_parsed(&parsed).is_ok())
}

/// `VMess` row: modern AEAD payload security only, implemented transport.
///
/// Native maps `security.enc` to the header security byte
/// (`protocol::vmess::security_byte`): absent/`auto`/`aes-128-gcm`/
/// `chacha20-poly1305` only. Legacy `none`/`zero`/`aes-128-cfb`/bare
/// `chacha20` are xray-only (rejected server-side by xray 26.x too, but
/// native has no arm at all), refused as `"legacy vmess payload security is
/// not implemented"`. A non-zero `alter_id` selects the legacy pre-AEAD
/// session scheme native never implemented, refused as `"vmess alter_id is
/// not implemented"`. A transport refusal appends the
/// [`transport_reason`] string.
fn vmess_reason(cfg: &VmessConfig) -> Option<&'static str> {
    if let Some(enc) = cfg.security.enc.as_deref()
        && !(enc.is_empty() || enc == "auto" || enc == "aes-128-gcm" || enc == "chacha20-poly1305")
    {
        return Some("legacy vmess payload security is not implemented");
    }
    if let Some(aid) = cfg.alter_id.as_deref()
        && !(aid.is_empty() || aid == "0")
    {
        return Some("vmess alter_id is not implemented");
    }
    transport_reason(&cfg.transport, cfg.path.as_deref())
}

/// Trojan row: implemented transport.
///
/// Trojan has no account-level encryption/flow variants in the typed config;
/// security is none/tls/reality, all of which `security::wrap` implements, and
/// every fingerprint id now resolves (an id with no roster row is approximated,
/// never refused). So the only refusal left is the transport.
fn trojan_reason(cfg: &TrojanConfig) -> Option<&'static str> {
    transport_reason(&cfg.transport, cfg.path.as_deref())
}

/// Hysteria2 row: never refused — and it MUST stay that way.
///
/// It is a self-contained QUIC dial (`protocol::hysteria2`, quinn's internal
/// rustls), so there is no transport matrix and no fingerprint gate: the TLS
/// side comes from `transport::quic::quic_tls_config`, which reads only
/// `insecure` and never looks at `fp`, so an xray-only fingerprint id on a
/// hysteria2 row is inert rather than fatal.
///
/// A refusal here would not be fatal — xray-core DOES have a hysteria2
/// outbound (`protocol: "hysteria"`, `version: 2`; see
/// `Hysteria2Config::inject_xray` in leas-proto, unit-tested there), so a
/// downgrade would serve the profile. The predicate stays reason-free because
/// nothing in the typed config requests a feature native lacks:
///
/// Fields native reads: `auth`, `obfs_password` (Salamander — keyed off the
/// password alone; the `obfs` TYPE string is never read), `down`
/// (→ the `hysteria-cc-rx` auth header) and `security`'s `insecure`. Fields
/// native ignores: `up` (the client advertises no send cap), `hop_interval`
/// (no port hopping — the dial pins to the endpoint's base port) and
/// `pin_sha256` (the QUIC dial carries no SPKI pin; only the plain-TLS path
/// honours one). All of those are refinements: ignoring them still
/// interoperates, so none of them gates. If a future config field DOES
/// require xray semantics native lacks, return a reason for it — the Auto
/// downgrade lands on xray-core, which can build the row.
const fn hysteria2_reason(_cfg: &Hysteria2Config) -> Option<&'static str> {
    None
}

/// Shadowsocks row (both kinds share this payload type): a native method
/// family matching `kind`, no SIP003 plugin, a key the connect path can
/// derive.
///
/// SS has no transport dimension — `SsConfig` carries no transport field, so
/// the row always rides a plain TCP dial, plus optional `security` applied by
/// the chain. The UDP dial-end's own refusals (a non-empty `security` on the
/// UDP path, chaining) live in `ss::udp::connect_udp`/`chain`, not here: this
/// predicate stays TCP-truthful, exactly as [`supported`] documents.
///
/// Refusals, in check order: `"shadowsocks method is not implemented"`,
/// `"shadowsocks method family does not match the protocol kind"`,
/// `"shadowsocks SIP003 plugin is not implemented"`, `"shadowsocks 2022
/// password key is malformed"`.
///
/// Every refusal below is a dead native dial the subprocess would have
/// served:
///
/// - [`resolve_method`] is the connect path's ONE config entry point
///   (`ss::connect` calls it before dispatching to a family codec), so the
///   gate and the codec cannot drift: routing through the same function
///   rejects exactly what the dial would reject — legacy stream ciphers
///   (`aes-*-cfb/ctr`, `rc4-md5`, `chacha20-ietf`, `none`, …) and unknown
///   names — and keeps those rows on sing-box. Should `resolve_method` ever
///   grow a check, this gate inherits it.
/// - Method family vs `kind`: the two kinds share `SsConfig`, and
///   `2022-blake3-*` selects the BLAKE3 schedule while everything else uses
///   HKDF-SHA1, so a mismatch means the wrong KDF, not a fallback.
/// - The SIP003 **plugin spec**, one verdict per shape, each naming the key or
///   value that caused it. This is the single validation owner for plugin rows
///   (spec §8): the parse/store layer never refuses, so every verdict lives here
///   and reaches the row as the `[untestable]` marker — which is also what keeps
///   `remove_failed_servers` from deleting a row we merely cannot serve.
/// - `password_key`: a malformed 2022 PSK (not base64, or the wrong length
///   for the method) is a fatal `NativeError::Config` in the connect path, so
///   refusing at gate time keeps Auto resolution on the subprocess.
///
/// A fingerprint id is no longer a refusal here: `security::wrap` resolves
/// every id, approximating one with no roster row rather than failing.
fn ss_reason(kind: ProtocolKind, cfg: &SsConfig) -> Option<Cow<'static, str>> {
    let Ok(method) = resolve_method(cfg) else {
        return Some(Cow::Borrowed("shadowsocks method is not implemented"));
    };
    if method.kind() != kind {
        return Some(Cow::Borrowed(
            "shadowsocks method family does not match the protocol kind",
        ));
    }
    if let Some(plugin) = &cfg.plugin
        && let Some(reason) = plugin_reason(plugin, &cfg.security)
    {
        return Some(reason);
    }
    if password_key(method, &cfg.password).is_err() {
        return Some(Cow::Borrowed("shadowsocks 2022 password key is malformed"));
    }
    None
}

/// The plugin verdicts — one per shape, each naming the key or value that
/// caused it (spec §8).
///
/// This is the only place a plugin row is judged: the parse layer never refuses
/// (it preserves what it cannot interpret in `extra`), so a row we cannot serve
/// still imports, exports and round-trips — it just carries this reason as its
/// `[untestable]` marker, which is also what keeps `remove_failed_servers` from
/// deleting it.
/// `mode=quic`: named, deliberately not served, and not because it is hard.
/// The full evidence is in the comment at the refusal site; the short form is
/// what a row's marker has to say.
const QUIC_WIRE_UNPINNED: &str = "shadowsocks plugin mode `quic` is not implemented — its client wire could not be pinned \
     from evidence (v2ray-plugin embeds V2Ray 4.38.3, whose source is not in-tree)";

fn plugin_reason(spec: &PluginSpec, security: &SecurityConfig) -> Option<Cow<'static, str>> {
    // A row that speaks both vocabularies is not decidable: the two describe
    // different wire framings, and guessing would dial a server neither spells.
    if spec.family == PluginFamily::Unknown
        && !spec.extra.is_empty()
        && (spec.extra.keys().any(|k| OBFS_KEYS.contains(&k.as_str()))
            || spec.extra.keys().any(|k| V2RAY_KEYS.contains(&k.as_str())))
    {
        return Some(Cow::Borrowed(
            "shadowsocks plugin carries both option vocabularies (obfs/obfs-host and mode/mux/tls/path/host); which one is on the wire is not decidable",
        ));
    }
    if spec.name.is_empty() {
        return Some(Cow::Borrowed(
            "shadowsocks plugin options arrived with no plugin name",
        ));
    }
    let family = spec.effective_family();
    if family == PluginFamily::Unknown {
        return Some(Cow::Owned(format!(
            "shadowsocks plugin `{}` is not implemented",
            spec.name
        )));
    }
    // A mode the row states that we do not implement — named, never rewritten
    // to a default (that would dial a server neither spelling describes).
    if let PluginMode::Invalid(value) = &spec.mode {
        if family == PluginFamily::Obfs && value.eq_ignore_ascii_case("websocket") {
            return Some(Cow::Borrowed(
                "shadowsocks plugin `obfs=websocket` is the legacy smux dialect, not the v2ray-plugin websocket framing",
            ));
        }
        return Some(Cow::Owned(format!(
            "shadowsocks plugin mode `{value}` is not implemented for `{name}`",
            name = spec.name
        )));
    }
    // `mode=quic` is a mode we name but do NOT serve, and the reason is a
    // recorded evidence gap rather than a missing snippet: v2ray-plugin v1.3.2
    // embeds V2Ray **4.38.3**, and that tree's source is not in the repo. Three
    // divergent QUIC wires ARE in it — v2ray-core v5.53.0 (`KeepAlivePeriod`
    // 15 s), v2ray-core v4.31.0 legacy (`HandshakeTimeout`, quic-go 0.18.1) and
    // sing-box's own `v2rayquic` (which sing-box's own docs state is *not*
    // v2ray-core-compatible here) — so picking any of them would be a guess
    // about the peer's wire, and a wrong QUIC wire fails as an opaque handshake
    // timeout. Xray-core is no help: it removed its QUIC transport outright and
    // has no SIP003 surface at all. So the row is refused BY NAME here and the
    // dial never happens: without this it would open a TCP connection to a
    // server that answers on UDP/443 and fail in the framing layer with a
    // message that describes neither the mode nor the reason.
    if spec.resolved_mode() == leas_proto::proto_spec::PluginMode::Quic {
        return Some(Cow::Borrowed(QUIC_WIRE_UNPINNED));
    }
    if let MuxSetting::Invalid(value) = &spec.mux {
        return Some(Cow::Owned(format!(
            "shadowsocks plugin option `mux={value}` is not a number we can use"
        )));
    }
    if let TlsSetting::Invalid(value) = &spec.tls {
        return Some(Cow::Owned(format!(
            "shadowsocks plugin option `tls={value}` is not a boolean we can use"
        )));
    }
    // A client CA pin is never silently ignored: ignoring a pin is the one
    // failure mode this change refuses to ship. Matched lowercased, because the
    // parser lowercases option keys (feeds spell these both ways).
    for key in ["cert", "certraw"] {
        if spec.extra.contains_key(key) {
            let spelled = if key == "certraw" { "certRaw" } else { "cert" };
            return Some(Cow::Owned(format!(
                "shadowsocks plugin option `{spelled}` pins a client CA, which the native engine does not implement"
            )));
        }
    }
    // The `security` layer: on a TLS-bearing plugin mode it is the *supported*
    // case (it supplies the SNI/fingerprint/insecure the plugin's own `tls` key
    // turns on). REALITY never is — a steal target around an obfs stream is a
    // construct no server has — and the obfs modes cannot carry one at all,
    // because their server expects the plugin's first bytes on a plain socket.
    if let Some(layer) = security_layer(security) {
        if layer == SecurityLayer::Reality {
            return Some(Cow::Borrowed(
                "shadowsocks plugin row carries a REALITY layer; a steal target cannot wrap an obfuscated stream",
            ));
        }
        if family == PluginFamily::Obfs {
            return Some(Cow::Borrowed(
                "shadowsocks obfs plugin row also requests a TLS layer; the plugin's framing is what its server parses first",
            ));
        }
    }
    None
}

/// The `security` layer a row states, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityLayer {
    Tls,
    Reality,
}

const fn security_layer(security: &SecurityConfig) -> Option<SecurityLayer> {
    match &security.tls {
        Some(TlsConfig::Reality(_)) => Some(SecurityLayer::Reality),
        Some(TlsConfig::Tls(_)) => Some(SecurityLayer::Tls),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leas_proto::proto_spec::common::{
        GrpcConfig, HttpConfig, KcpConfig, TransportConfig, WebSocketConfig,
    };
    use leas_proto::proto_spec::{
        HttpUpgradeConfig, RealityOpts, SecurityConfig, TlsConfig, TlsOpts, XHttpConfig,
    };
    use leas_proto::urlx::TinyText;

    fn vless_cfg() -> VlessConfig {
        VlessConfig {
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            uuid_origin: None,
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            encryption: None,
            flow: None,
            path: None,
            splice: None,
            remarks: None,
            mux: None,
        }
    }

    fn vmess_cfg() -> VmessConfig {
        VmessConfig {
            uuid: "00000000-0000-0000-0000-000000000000".into(),
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            alter_id: None,
            path: None,
            remarks: None,
        }
    }

    fn trojan_cfg() -> TrojanConfig {
        TrojanConfig {
            password: "secret".into(),
            security: SecurityConfig::default(),
            transport: TransportConfig::Tcp,
            path: None,
            remarks: None,
        }
    }

    fn hysteria2_cfg() -> Hysteria2Config {
        Hysteria2Config {
            auth: "secret".into(),
            security: SecurityConfig::default(),
            obfs: None,
            obfs_password: None,
            up: None,
            down: None,
            hop_interval: None,
            pin_sha256: None,
            remarks: None,
        }
    }

    /// A plain-TLS security config carrying the `fp` id.
    fn tls_fp(fp: &str) -> SecurityConfig {
        SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: Some(TinyText::from("example.com")),
                fp: Some(TinyText::from(fp)),
                ..TlsOpts::default()
            })),
            enc: None,
        }
    }

    /// A REALITY security config carrying the `fp` id (the other arm of
    /// `security::wrap` that parses it).
    fn reality_fp(fp: &str) -> SecurityConfig {
        SecurityConfig {
            tls: Some(TlsConfig::Reality(RealityOpts {
                sni: Some(TinyText::from("example.com")),
                fp: Some(TinyText::from(fp)),
                pbk: Some("cHVibGljLWtleS0zMi1ieXRlcy1iYXNlNjR1cmw".to_owned()),
                ..RealityOpts::default()
            })),
            enc: None,
        }
    }

    /// A shadowsocks row with no plugin and default (no-op) security.
    fn ss_cfg(method: &str, password: &str) -> SsConfig {
        SsConfig {
            method: method.into(),
            password: password.into(),
            security: SecurityConfig::default(),
            remarks: None,
            plugin: None,
        }
    }

    /// A plugin spec built through the ONE constructor the parse path uses.
    fn plugin(name: &str, opts: &str) -> PluginSpec {
        PluginSpec::from_parts(if name.is_empty() { None } else { Some(name) }, opts)
    }

    fn ss_with_plugin(method: &str, name: &str, opts: &str) -> SsConfig {
        SsConfig {
            plugin: Some(plugin(name, opts)),
            ..ss_cfg(method, "pw")
        }
    }

    /// The verdict text for a plugin row, or `""` when it is accepted.
    fn ss_reason_text(method: &str, name: &str, opts: &str) -> String {
        support_reason(
            ProtocolKind::Shadowsocks,
            &ProtocolConfig::Ss(ss_with_plugin(method, name, opts)),
        )
        .map_or_else(String::new, std::borrow::Cow::into_owned)
    }

    /// A plain-TLS security config with an optional SNI.
    fn tls_security(sni: Option<&str>) -> SecurityConfig {
        SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: sni.map(TinyText::from),
                ..TlsOpts::default()
            })),
            enc: None,
        }
    }

    fn reality_security() -> SecurityConfig {
        SecurityConfig {
            tls: Some(TlsConfig::Reality(RealityOpts {
                sni: Some(TinyText::from("example.com")),
                pbk: Some("cHVibGljLWtleS0zMi1ieXRlcy1iYXNlNjR1cmw".to_owned()),
                ..RealityOpts::default()
            })),
            enc: None,
        }
    }

    /// `supported` for an SS row (both kinds share the payload type).
    fn ss_row(kind: ProtocolKind, cfg: SsConfig) -> bool {
        supported(kind, &ProtocolConfig::Ss(cfg))
    }

    /// `supported` for a vless row whose security is `security`.
    fn vless_with(security: SecurityConfig) -> bool {
        let mut cfg = vless_cfg();
        cfg.security = security;
        supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg))
    }

    /// `supported` for a kcp-transport row of every stream protocol, with
    /// `path` on the protocol row (the share-link seed carrier).
    fn kcp_rows_supported(kcp: &KcpConfig, path: Option<&str>) -> [bool; 3] {
        let transport = TransportConfig::Kcp(kcp.clone());
        let path = path.map(TinyText::from);
        [
            supported(
                ProtocolKind::Vless,
                &ProtocolConfig::Vless(VlessConfig {
                    transport: transport.clone(),
                    path: path.clone(),
                    ..vless_cfg()
                }),
            ),
            supported(
                ProtocolKind::Vmess,
                &ProtocolConfig::Vmess(VmessConfig {
                    transport: transport.clone(),
                    path: path.clone(),
                    ..vmess_cfg()
                }),
            ),
            supported(
                ProtocolKind::Trojan,
                &ProtocolConfig::Trojan(TrojanConfig {
                    transport,
                    path,
                    ..trojan_cfg()
                }),
            ),
        ]
    }

    #[test]
    fn native_kinds_exact_order() {
        assert_eq!(
            NATIVE_KINDS,
            &[
                ProtocolKind::Vless,
                ProtocolKind::Vmess,
                ProtocolKind::Trojan,
                ProtocolKind::Hysteria2,
                ProtocolKind::Shadowsocks,
                ProtocolKind::Shadowsocks2022,
            ]
        );
    }

    #[test]
    fn plain_defaults_supported() {
        assert!(supported(
            ProtocolKind::Vless,
            &ProtocolConfig::Vless(vless_cfg())
        ));
        assert!(supported(
            ProtocolKind::Vmess,
            &ProtocolConfig::Vmess(vmess_cfg())
        ));
        assert!(supported(
            ProtocolKind::Trojan,
            &ProtocolConfig::Trojan(trojan_cfg())
        ));
        assert!(supported(
            ProtocolKind::Hysteria2,
            &ProtocolConfig::Hysteria2(hysteria2_cfg())
        ));
    }

    /// `mlkem768x25519plus` IS served natively (the record-layer EOF
    /// classification was the bug, fixed 2026-09-23 — see `encryption/mlkem.rs`
    /// `poll_read`). The gate now accepts every value the CONNECT PATH accepts.
    #[test]
    fn pq_enc_vless_supported() {
        // A valid 32-byte X25519 key segment (base64url, raw) — a `<20`-char
        // segment would be parsed as padding, not a key.
        const KEY32: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
        for enc in [
            format!("mlkem768x25519plus.native.1rtt.{KEY32}"),
            // Padding + key (the shape a padded account carries).
            format!("mlkem768x25519plus.native.1rtt.100-35-70.0-0-0.{KEY32}"),
            // Every mode is implemented.
            format!("mlkem768x25519plus.xorpub.1rtt.{KEY32}"),
            format!("mlkem768x25519plus.random.1rtt.{KEY32}"),
        ] {
            let mut cfg = vless_cfg();
            cfg.encryption = Some(TinyText::from(enc.as_str()));
            assert!(
                supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)),
                "must be served natively: {enc}"
            );
        }
    }

    /// A malformed `mlkem768x25519plus` value stays REFUSED — the gate runs the
    /// connect path's own parser, so anything the codec would reject at dial
    /// time never reaches the native fast path.
    #[test]
    fn malformed_pq_enc_vless_deferred() {
        let mut cfg = vless_cfg();
        cfg.encryption = Some(TinyText::from("mlkem768x25519plus.xor.1rtt.a2V5"));
        assert!(!supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)));
    }

    #[test]
    fn unknown_vless_encryption_deferred() {
        let mut cfg = vless_cfg();
        cfg.encryption = Some(TinyText::from("some-future-scheme"));
        assert!(!supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)));
    }

    #[test]
    fn unknown_vless_flow_deferred() {
        let mut cfg = vless_cfg();
        cfg.flow = Some(TinyText::from("xtls-rprx-splice"));
        assert!(!supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)));
    }

    #[test]
    fn vision_flows_supported() {
        for flow in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"] {
            let mut cfg = vless_cfg();
            cfg.flow = Some(TinyText::from(flow));
            assert!(
                supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)),
                "{flow}"
            );
        }
    }

    /// The refusal the parse-time check used to be: vision + plain mux is Xray's
    /// `isMuxAndNotXUDP` rejection (its inbound refuses it; its XRV outbound
    /// turns vision UDP into `command=Mux` with port 666 — an XUDP path this
    /// change explicitly leaves out of scope). It lives HERE, not at parse, so
    /// the row imports, exports, carries `[untestable]` and is purge-safe.
    #[test]
    fn vision_with_mux_is_refused_by_name() {
        for flow in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"] {
            let mut cfg = vless_cfg();
            cfg.flow = Some(TinyText::from(flow));
            cfg.mux = Some(VlessMux::Limited(8));
            assert!(
                !supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)),
                "{flow} + plain mux must not be served"
            );
            let mut cfg = vless_cfg();
            cfg.flow = Some(TinyText::from(flow));
            cfg.mux = Some(VlessMux::Limited(8));
            let reason = support_reason(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg))
                .unwrap_or_else(|| panic!("{flow} + mux must be refused"));
            assert!(
                reason.contains("mux") && reason.contains(flow),
                "the refusal names the row's own combination, got {reason}"
            );
            // And the row itself is NOT refused — only the combination is.
            let mut cfg = vless_cfg();
            cfg.flow = Some(TinyText::from(flow));
            cfg.mux = None;
            assert!(
                supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)),
                "vision alone still works"
            );
        }
    }

    /// §8: every refusal names the row's OWN key/value, so the row reads as
    /// "this spelling", not as a generic "mux is unsupported".
    #[test]
    fn an_unusable_mux_spelling_is_named_in_its_refusal() {
        // Row 29 names smux/yamux/h2mux, so ALL THREE are driven: a refusal
        // covering only `smux` would pass while a `yamux` row was handed
        // mux.cool frames — which is a different wire format, not a different
        // cap. (An earlier version of this test covered `smux` alone while the
        // plan claimed three; the claim was wrong, not the code.)
        for multiplexer in ["smux", "yamux", "h2mux"] {
            let mut cfg = vless_cfg();
            cfg.mux = Some(VlessMux::Invalid {
                key: "muxtype".into(),
                value: multiplexer.into(),
            });
            assert!(
                !supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg.clone())),
                "muxtype={multiplexer} must not be served"
            );
            let reason =
                support_reason(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)).expect("refused");
            assert!(
                reason.contains(&format!("muxtype={multiplexer}")),
                "the refusal names the offending spelling, got {reason}"
            );
            // An `Invalid` row must NOT be refused for something else, and must
            // not be "supported" either — it is stored, importable and marked
            // untestable, which is what keeps it purge-safe.
            assert!(!reason.contains("vision"), "no unrelated reason leaks in");
        }
    }

    /// T22's disposition, made executable: `mode=quic` is STORED (parse never
    /// refuses it) and refused HERE, by name, so the row stays importable,
    /// exportable and `[untestable]` — and, the point of the refusal, is never
    /// dialled. Without it the row opened a TCP connection to a server that
    /// answers on UDP and failed downstream with a message describing neither the
    /// mode nor the reason.
    ///
    /// It is NOT `PluginMode::Invalid`: the mode is well-formed and sing-box
    /// serves it. The reason is recorded in the message.
    #[test]
    fn a_quic_plugin_row_is_refused_by_name_and_never_dialled() {
        let mut cfg = ss_cfg("aes-256-gcm", "pw");
        cfg.plugin = Some(PluginSpec::from_parts(
            Some("v2ray-plugin"),
            "mode=quic;host=cdn.example",
        ));
        assert!(
            !supported(ProtocolKind::Shadowsocks, &ProtocolConfig::Ss(cfg.clone())),
            "a quic plugin row is not served by the native engine"
        );
        let reason =
            support_reason(ProtocolKind::Shadowsocks, &ProtocolConfig::Ss(cfg)).expect("refused");
        assert!(
            reason.contains("quic"),
            "the refusal names the mode, got {reason}"
        );
        assert!(
            reason.contains("4.38.3"),
            "and says WHY it is not implemented rather than implying it is hard, got {reason}"
        );
        // The mode is well-formed, so it must NOT read as an invalid spelling —
        // that would tell a user their URL is malformed when it is not.
        assert!(
            !reason.contains("is not implemented for"),
            "a valid mode is refused as unpinned, not as malformed, got {reason}"
        );
        // Anti-overreach: the modes we DO serve are untouched by this.
        for (opts, served) in [
            ("mode=websocket;host=cdn.example", true),
            ("obfs=http;obfs-host=cdn.example", true),
            ("mode=gun;host=cdn.example", false), // gun is a framing we do not own
        ] {
            let mut cfg = ss_cfg("aes-256-gcm", "pw");
            cfg.plugin = Some(PluginSpec::from_parts(Some("v2ray-plugin"), opts));
            assert_eq!(
                supported(ProtocolKind::Shadowsocks, &ProtocolConfig::Ss(cfg)),
                served,
                "{opts}"
            );
        }
    }

    #[test]
    fn legacy_vmess_ciphers_deferred() {
        for enc in ["none", "zero", "aes-128-cfb", "chacha20"] {
            let mut cfg = vmess_cfg();
            cfg.security.enc = Some(TinyText::from(enc));
            assert!(
                !supported(ProtocolKind::Vmess, &ProtocolConfig::Vmess(cfg)),
                "{enc}"
            );
        }
    }

    #[test]
    fn modern_vmess_ciphers_supported() {
        for enc in ["auto", "aes-128-gcm", "chacha20-poly1305"] {
            let mut cfg = vmess_cfg();
            cfg.security.enc = Some(TinyText::from(enc));
            assert!(
                supported(ProtocolKind::Vmess, &ProtocolConfig::Vmess(cfg)),
                "{enc}"
            );
        }
    }

    #[test]
    fn nonzero_alter_id_deferred() {
        let mut cfg = vmess_cfg();
        cfg.alter_id = Some(TinyText::from("4"));
        assert!(!supported(ProtocolKind::Vmess, &ProtocolConfig::Vmess(cfg)));
    }

    #[test]
    fn bare_quic_transport_deferred() {
        let mut cfg = vless_cfg();
        cfg.transport = TransportConfig::Quic;
        assert!(!supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)));
    }

    #[test]
    fn kind_config_mismatch_deferred() {
        // Right kind, wrong payload — never servable.
        assert!(!supported(
            ProtocolKind::Vless,
            &ProtocolConfig::Vmess(vmess_cfg())
        ));
    }

    #[test]
    fn support_reason_agrees_with_supported() {
        // One row per refusal class plus an accepted row per native kind: the
        // two entry points must never disagree, so the marker text can never
        // describe a row `supported` accepts (or the reverse).
        let mut vless_enc = vless_cfg();
        vless_enc.encryption = Some("mlkem768x25519plus.native.0rtt".into());
        let mut vless_flow = vless_cfg();
        vless_flow.flow = Some("xtls-rprx-direct".into());
        let mut vless_kcp = vless_cfg();
        vless_kcp.transport = TransportConfig::Kcp(KcpConfig {
            seed: Some("obfs".into()),
            ..KcpConfig::default()
        });
        let mut vless_quic = vless_cfg();
        vless_quic.transport = TransportConfig::Quic;
        let mut vmess_sec = vmess_cfg();
        vmess_sec.security.enc = Some("aes-128-cfb".into());
        let mut vmess_alter = vmess_cfg();
        vmess_alter.alter_id = Some("1".into());
        let mut ss_legacy = ss_cfg("aes-128-cfb", "secret");
        ss_legacy.method = "aes-128-cfb".into();
        let mut ss_family = ss_cfg("2022-blake3-aes-128-gcm", "secret");
        ss_family.method = "2022-blake3-aes-128-gcm".into();
        let mut ss_plugin = ss_cfg("aes-256-gcm", "secret");
        ss_plugin.plugin = Some(plugin("v2ray-plugin", "host=cdn.example;tls"));

        let rows: Vec<(ProtocolKind, ProtocolConfig)> = vec![
            // Refusals.
            (ProtocolKind::Tuic, ProtocolConfig::Vless(vless_cfg())),
            (ProtocolKind::Vless, ProtocolConfig::Vmess(vmess_cfg())),
            (ProtocolKind::Vless, ProtocolConfig::Vless(vless_enc)),
            (ProtocolKind::Vless, ProtocolConfig::Vless(vless_flow)),
            (ProtocolKind::Vless, ProtocolConfig::Vless(vless_kcp)),
            (ProtocolKind::Vless, ProtocolConfig::Vless(vless_quic)),
            (ProtocolKind::Vmess, ProtocolConfig::Vmess(vmess_sec)),
            (ProtocolKind::Vmess, ProtocolConfig::Vmess(vmess_alter)),
            (ProtocolKind::Shadowsocks, ProtocolConfig::Ss(ss_legacy)),
            (ProtocolKind::Shadowsocks, ProtocolConfig::Ss(ss_family)),
            (ProtocolKind::Shadowsocks, ProtocolConfig::Ss(ss_plugin)),
            (
                ProtocolKind::Shadowsocks,
                ProtocolConfig::Ss(ss_with_plugin(
                    "aes-256-gcm",
                    "obfs-local",
                    "obfs=websocket",
                )),
            ),
            (
                ProtocolKind::Shadowsocks,
                ProtocolConfig::Ss(ss_with_plugin("aes-256-gcm", "kcptun", "key=x")),
            ),
            // Accepted rows.
            (ProtocolKind::Vless, ProtocolConfig::Vless(vless_cfg())),
            (ProtocolKind::Vmess, ProtocolConfig::Vmess(vmess_cfg())),
            (ProtocolKind::Trojan, ProtocolConfig::Trojan(trojan_cfg())),
            (
                ProtocolKind::Hysteria2,
                ProtocolConfig::Hysteria2(hysteria2_cfg()),
            ),
            (
                ProtocolKind::Shadowsocks,
                ProtocolConfig::Ss(ss_cfg("aes-256-gcm", "secret")),
            ),
        ];

        let mut refusals = 0;
        for (kind, config) in rows {
            let reason = support_reason(kind, &config);
            assert_eq!(
                reason.is_none(),
                supported(kind, &config),
                "support_reason/supported disagree for {kind:?}"
            );
            if reason.is_some() {
                refusals += 1;
            }
        }
        assert!(
            refusals >= 11,
            "the table must exercise every refusal class"
        );
    }

    #[test]
    fn non_native_kinds_unsupported() {
        let non_native = [
            ProtocolKind::Socks,
            ProtocolKind::Http,
            ProtocolKind::WireGuard,
            ProtocolKind::DokodemoDoor,
            ProtocolKind::Freedom,
            ProtocolKind::Blackhole,
            ProtocolKind::Dns,
            ProtocolKind::Loopback,
            ProtocolKind::Custom,
            ProtocolKind::Tuic,
            ProtocolKind::Hysteria,
            ProtocolKind::Naive,
            ProtocolKind::AnyTls,
            ProtocolKind::ShadowTls,
            ProtocolKind::Tor,
            ProtocolKind::Ssh,
            ProtocolKind::Tailscale,
            ProtocolKind::ShadowsocksR,
            ProtocolKind::Redirect,
            ProtocolKind::TProxy,
            ProtocolKind::Mixed,
        ];
        assert_eq!(non_native.len(), 21);
        let fallback = ProtocolConfig::Vless(vless_cfg());
        for kind in non_native {
            assert!(!kind_supported(kind), "{kind:?}");
            assert!(!supported(kind, &fallback), "{kind:?}");
        }
    }

    #[test]
    fn unrosterable_fingerprints_probed_with_the_default_not_refused() {
        // An id with no engine hello used to defer the row to the subprocess.
        // It is now probed with the engine default hello and MARKED
        // approximated (`security::fingerprint::resolve_fingerprint`), which is
        // the whole point of the policy: refusing a config the engine can dial
        // costs a testable link, and the marker keeps the substitution visible.
        // `""` and `unsafe` are not in this set — they mean "no fingerprint
        // requested", so the default IS the requested shape.
        for fp in ["android", "360", "qq", "randomizednoalpn", "chrome-130"] {
            assert!(vless_with(tls_fp(fp)), "vless tls fp={fp:?}");
            assert!(vless_with(reality_fp(fp)), "vless reality fp={fp:?}");

            let mut vmess = vmess_cfg();
            vmess.security = tls_fp(fp);
            assert!(
                supported(ProtocolKind::Vmess, &ProtocolConfig::Vmess(vmess)),
                "vmess fp={fp:?}"
            );

            let mut trojan = trojan_cfg();
            trojan.security = tls_fp(fp);
            assert!(
                supported(ProtocolKind::Trojan, &ProtocolConfig::Trojan(trojan)),
                "trojan fp={fp:?}"
            );
        }
    }

    #[test]
    fn no_fingerprint_request_is_supported_and_unmarked() {
        // The three spellings of "no fingerprint requested" reach the gate as
        // a supported row: absent, empty, and xray's `unsafe` sentinel.
        for security in [
            tls_fp(""),
            tls_fp("unsafe"),
            reality_fp(""),
            reality_fp("unsafe"),
        ] {
            assert!(vless_with(security));
        }
    }

    #[test]
    fn native_fingerprints_supported() {
        // Exactly the ids the parser accepts — the gate must not narrow it.
        // `randomized` is xray's alias for randomized Chrome; `edge` and `ios`
        // are presets the roster carries (edge_106, Safari-on-iOS), so they
        // are probed rather than marked untestable (2026-09-16: ~19 links per
        // subscription fell into that marker for no reason).
        for fp in [
            "chrome",
            "chrome-randomized",
            "randomized",
            "firefox",
            "safari",
            "edge",
            "ios",
            "random",
        ] {
            assert!(vless_with(tls_fp(fp)), "vless tls fp={fp:?}");
            assert!(vless_with(reality_fp(fp)), "vless reality fp={fp:?}");

            let mut vmess = vmess_cfg();
            vmess.security = tls_fp(fp);
            assert!(
                supported(ProtocolKind::Vmess, &ProtocolConfig::Vmess(vmess)),
                "vmess fp={fp:?}"
            );

            let mut trojan = trojan_cfg();
            trojan.security = tls_fp(fp);
            assert!(
                supported(ProtocolKind::Trojan, &ProtocolConfig::Trojan(trojan)),
                "trojan fp={fp:?}"
            );
        }
    }

    #[test]
    fn tls_without_fingerprint_supported() {
        // No `fp`: plain TLS uses the engine default, REALITY the fixed
        // chrome spec — nothing is parsed, nothing defers.
        assert!(vless_with(SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: Some(TinyText::from("example.com")),
                ..TlsOpts::default()
            })),
            enc: None,
        }));
        assert!(vless_with(SecurityConfig {
            tls: Some(TlsConfig::Reality(RealityOpts {
                sni: Some(TinyText::from("example.com")),
                pbk: Some("cHVibGljLWtleS0zMi1ieXRlcy1iYXNlNjR1cmw".to_owned()),
                ..RealityOpts::default()
            })),
            enc: None,
        }));
    }

    #[test]
    fn hysteria2_ignores_fingerprint_and_stays_supported() {
        // quinn's internal rustls never reads `fp` (`quic_tls_config` looks
        // at `insecure` only), so an xray-only id is inert here — the test
        // pins that no fingerprint handling over-reaches onto the QUIC dial. (A `false` here WOULD downgrade to xray-core, which builds
        // hysteria2 outbounds — the gate is simply never triggered.)
        let mut cfg = hysteria2_cfg();
        cfg.security = tls_fp("ios");
        cfg.obfs = Some(TinyText::from("salamander"));
        cfg.obfs_password = Some(TinyText::from("obfs-shared-secret"));
        cfg.up = Some(TinyText::from("100 mbps"));
        cfg.down = Some(TinyText::from("200 mbps"));
        cfg.hop_interval = Some(30);
        cfg.pin_sha256 = Some(TinyText::from("YmFzZTY0LXBpbg"));
        assert!(supported(
            ProtocolKind::Hysteria2,
            &ProtocolConfig::Hysteria2(cfg)
        ));
    }

    #[test]
    fn plain_kcp_supported() {
        // `mtu`/`tti` are the two fields the native dial reads; the pacing
        // knobs it ignores do not change the wire format, and an explicit
        // `none`/empty header is the bare-datagram default.
        for kcp in [
            KcpConfig::default(),
            KcpConfig {
                mtu: Some(1350),
                tti: Some(50),
                ..KcpConfig::default()
            },
            KcpConfig {
                header_type: Some(TinyText::from("none")),
                ..KcpConfig::default()
            },
            KcpConfig {
                header_type: Some(TinyText::from("")),
                seed: Some(TinyText::from("")),
                ..KcpConfig::default()
            },
            KcpConfig {
                uplink_capacity: Some(50),
                downlink_capacity: Some(100),
                congestion: Some(true),
                read_buffer: Some(2),
                write_buffer: Some(2),
                ..KcpConfig::default()
            },
        ] {
            assert_eq!(kcp_rows_supported(&kcp, None), [true; 3], "{kcp:?}");
        }
    }

    #[test]
    fn kcp_seed_deferred() {
        // Clash carrier: `mkcp-opts.seed` → `KcpConfig::seed`. Native has no
        // obfuscator, so it would frame every datagram unmasked and the
        // server would silently drop them.
        let kcp = KcpConfig {
            seed: Some(TinyText::from("hunter2")),
            ..KcpConfig::default()
        };
        assert_eq!(kcp_rows_supported(&kcp, None), [false; 3]);
    }

    #[test]
    fn kcp_share_link_seed_path_deferred() {
        // Share-link carrier: `?type=kcp&path=<seed>` lands in the protocol
        // row's `path`, never in `KcpConfig`.
        assert_eq!(
            kcp_rows_supported(&KcpConfig::default(), Some("hunter2")),
            [false; 3]
        );
        // An empty path is no seed at all.
        assert_eq!(
            kcp_rows_supported(&KcpConfig::default(), Some("")),
            [true; 3]
        );
    }

    #[test]
    fn kcp_header_type_deferred() {
        // Packet camouflage: native writes bare mKCP datagrams, so any
        // header type frames the packets differently than the server reads
        // them — a silent drop + hang, not an error.
        for header in ["srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"] {
            let kcp = KcpConfig {
                header_type: Some(TinyText::from(header)),
                ..KcpConfig::default()
            };
            assert_eq!(kcp_rows_supported(&kcp, None), [false; 3], "{header}");
        }
    }

    #[test]
    fn non_kcp_path_is_not_a_seed() {
        // The `path` gate is kcp-only: a ws/grpc row's path is its transport
        // path, not an obfuscation seed.
        for transport in [
            TransportConfig::Ws(WebSocketConfig::default()),
            TransportConfig::Grpc(GrpcConfig::default()),
            TransportConfig::HttpUpgrade(HttpUpgradeConfig::default()),
        ] {
            let mut cfg = vless_cfg();
            cfg.transport = transport.clone();
            cfg.path = Some(TinyText::from("/ws"));
            assert!(
                supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)),
                "{transport:?}"
            );
        }
    }

    #[test]
    fn transport_positive_match_known_set() {
        // The dispatch set of `transport::{connect, upgrade}` — bare quic has
        // no arm. `transport_supported` matches exhaustively, so a variant
        // added to `TransportConfig` fails to compile there instead of
        // silently inheriting `true`; this pins the known answers.
        for (transport, want) in [
            (TransportConfig::Tcp, true),
            (TransportConfig::Ws(WebSocketConfig::default()), true),
            (TransportConfig::Grpc(GrpcConfig::default()), true),
            (TransportConfig::Http(HttpConfig::default()), true),
            (
                TransportConfig::HttpUpgrade(HttpUpgradeConfig::default()),
                true,
            ),
            (TransportConfig::XHttp(XHttpConfig::default()), true),
            (TransportConfig::Kcp(KcpConfig::default()), true),
            (TransportConfig::Quic, false),
        ] {
            assert_eq!(
                transport_supported(&transport, None),
                want,
                "{transport:?} direct"
            );
            let mut cfg = vless_cfg();
            cfg.transport = transport.clone();
            assert_eq!(
                supported(ProtocolKind::Vless, &ProtocolConfig::Vless(cfg)),
                want,
                "{transport:?} via supported"
            );
        }
    }

    #[test]
    fn ss_kinds_are_native_and_legacy_methods_defer() {
        assert!(kind_supported(ProtocolKind::Shadowsocks));
        assert!(kind_supported(ProtocolKind::Shadowsocks2022));
        assert!(ss_row(
            ProtocolKind::Shadowsocks,
            ss_cfg("aes-128-gcm", "pw")
        ));
        assert!(ss_row(
            ProtocolKind::Shadowsocks2022,
            ss_cfg(
                "2022-blake3-aes-256-gcm",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            )
        ));
        // legacy + unknown methods stay on sing-box
        for method in ["aes-256-cfb", "none", "rc4-md5", "chacha20-ietf"] {
            assert!(
                !ss_row(ProtocolKind::Shadowsocks, ss_cfg(method, "pw")),
                "{method}"
            );
        }
    }

    #[test]
    fn ss_kind_and_method_family_must_agree() {
        // A 2022 method on the classic kind (and vice versa) would pick the
        // wrong KDF, so mismatched rows defer.
        assert!(!ss_row(
            ProtocolKind::Shadowsocks,
            ss_cfg("2022-blake3-aes-256-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")
        ));
        assert!(!ss_row(
            ProtocolKind::Shadowsocks2022,
            ss_cfg("aes-128-gcm", "pw")
        ));
    }

    /// Every plugin shape gets its OWN named verdict (spec §8), and the shapes
    /// we do implement are accepted.
    #[test]
    fn ss_plugin_rows_are_judged_one_verdict_per_shape() {
        for (name, opts) in [
            ("obfs-local", "obfs=http"),
            ("obfs-local", "obfs=tls;obfs-host=example.com"),
            ("simple-obfs", "obfs=http;obfs-host=example.com:8080"),
            ("v2ray-plugin", "host=cdn.example"),
            ("v2ray-plugin", "mode=websocket;host=cdn.example;mux=0"),
            ("v2ray-plugin", "host=cdn.example;tls"),
        ] {
            assert!(
                ss_row(
                    ProtocolKind::Shadowsocks,
                    ss_with_plugin("aes-128-gcm", name, opts)
                ),
                "{name};{opts} must be servable natively"
            );
        }

        let cases: &[(&str, &str, &str)] = &[
            // Row 14's wording is "refused at connect **naming the name**", so
            // the expectation is the plugin's own name, not a generic phrase —
            // a refusal that said only "is not implemented" would leave the user
            // with nothing to act on.
            ("kcptun", "key=abc", "kcptun"),
            ("obfs", "", "obfs"),
            (
                "obfs-local",
                "obfs=websocket;obfs-host=h",
                "legacy smux dialect",
            ),
            ("v2ray-plugin", "host=h;mux=many", "mux=many"),
            ("v2ray-plugin", "host=h;tls=maybe", "tls=maybe"),
            (
                "v2ray-plugin",
                "host=h;cert=/tmp/ca.pem",
                "pins a client CA",
            ),
            ("v2ray-plugin", "host=h;certRaw=PEM", "pins a client CA"),
            (
                "obfs-local",
                "obfs=http;obfs-host=h;mode=websocket",
                "both option vocabularies",
            ),
            ("", "obfs=http;obfs-host=h", "no plugin name"),
        ];
        for (name, opts, expect) in cases {
            let reason = ss_reason_text("aes-128-gcm", name, opts);
            assert!(
                reason.contains(expect),
                "{name};{opts} → {reason:?} must mention {expect:?}"
            );
        }
    }

    /// A `wss` row that also states a `security` layer is the SUPPORTED case
    /// (it supplies the SNI/fingerprint/insecure for the plugin's `tls`), REALITY
    /// never is, and the obfs modes cannot carry one at all.
    #[test]
    fn ss_plugin_security_is_refused_only_where_it_is_meaningless() {
        let mut cfg = ss_with_plugin("aes-128-gcm", "v2ray-plugin", "host=cdn.example;tls");
        cfg.security = tls_security(Some("cdn.example"));
        assert!(
            ss_row(ProtocolKind::Shadowsocks, cfg),
            "wss + security is supported"
        );

        let mut reality = ss_with_plugin("aes-128-gcm", "v2ray-plugin", "host=cdn.example;tls");
        reality.security = reality_security();
        assert!(
            !ss_row(ProtocolKind::Shadowsocks, reality),
            "REALITY wraps no obfs stream"
        );

        let mut obfs = ss_with_plugin("aes-128-gcm", "obfs-local", "obfs=http");
        obfs.security = tls_security(None);
        assert!(
            !ss_row(ProtocolKind::Shadowsocks, obfs),
            "the obfs server parses the head first"
        );
    }

    #[test]
    fn ss2022_password_length_is_validated_at_gate_time() {
        // A wrong-length or non-base64 PSK is a config error in
        // `password_key`, not a fallback: refusing here keeps Auto
        // resolution on the subprocess instead of a dead native dial.
        assert!(!ss_row(
            ProtocolKind::Shadowsocks2022,
            ss_cfg("2022-blake3-aes-128-gcm", "c2hvcnQ=")
        ));
        assert!(!ss_row(
            ProtocolKind::Shadowsocks2022,
            ss_cfg("2022-blake3-aes-128-gcm", "!!!")
        ));
        // The classic KDF accepts any password, so an SS AEAD row with an
        // arbitrary password stays supported.
        assert!(ss_row(
            ProtocolKind::Shadowsocks,
            ss_cfg("chacha20-ietf-poly1305", "")
        ));
    }

    #[test]
    fn ss_unrosterable_fingerprint_probed_with_the_default() {
        // `security::wrap` resolves `fp` on the SS TCP path too, so an id with
        // no engine hello is approximated there exactly as on
        // vless/vmess/trojan — it is no longer a reason to defer the row.
        let mut cfg = ss_cfg("aes-128-gcm", "pw");
        cfg.security = tls_fp("qq");
        assert!(ss_row(ProtocolKind::Shadowsocks, cfg));

        let mut cfg = ss_cfg(
            "2022-blake3-aes-256-gcm",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        );
        cfg.security = reality_fp("android");
        assert!(ss_row(ProtocolKind::Shadowsocks2022, cfg));
    }

    #[test]
    fn ss_native_fingerprint_and_plain_tls_supported() {
        for security in [tls_fp("chrome"), reality_fp("firefox")] {
            let mut cfg = ss_cfg("aes-192-gcm", "pw");
            cfg.security = security.clone();
            assert!(ss_row(ProtocolKind::Shadowsocks, cfg), "{security:?}");
        }
    }
}
