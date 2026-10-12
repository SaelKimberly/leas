//! Payload-security variants for the e2e pipeline. A variant names itself,
//! gates which cores support it, and supplies the security strings for the
//! server config and client params.

use super::{Certs, CoreKind, config};

/// TLS transport variant: stock rustls, the fingerprint engine, or REALITY.
///
/// Supplies the security-relevant strings for the server config and client
/// params, plus the harness-CA trust hook for the client path. A `CaseSpec`
/// without an explicit variant is `StandardTls`.
pub trait TlsVariant: Sync {
    /// Short variant name used in case labels ("tls-standard", "tls-chrome",
    /// "reality").
    fn name(&self) -> &'static str;
    /// The SNI the client offers (and the core's `serverNames` for REALITY).
    fn sni(&self) -> &'static str;
    /// Fingerprint id for the client TLS config ("chrome", "firefox", ...);
    /// `None` = stock rustls. A fingerprint id routes `wrap()` through the
    /// fingerprint engine AND selects a `Custom` provider in the client
    /// params.
    fn fingerprint(&self) -> Option<&'static str> {
        None
    }
    /// TLS curve preferences (`curves` client option / server
    /// `curvePreferences`): `Some("x25519mlkem768")` pins the hybrid PQ
    /// curve on BOTH ends — the server then cannot pick anything else, so a
    /// green row proves PQ negotiation. `None` = the core defaults.
    fn curves(&self) -> Option<&'static str> {
        None
    }
    /// REALITY server private key (base64url); `None` = certificate TLS.
    fn reality_private_key(&self) -> Option<&str> {
        None
    }
    /// REALITY client public key (base64url).
    fn reality_pbk(&self) -> Option<&str> {
        None
    }
    /// REALITY short id (hex).
    fn reality_sid(&self) -> Option<&str> {
        None
    }
    /// REALITY short id the *client* presents (hex); `None` = the server's
    /// `reality_sid()`. Overridden to a wrong value to drive the
    /// wrong-sid fallback scenario.
    fn reality_client_sid(&self) -> Option<&str> {
        None
    }
    /// True when the case expects `connect()` to fail with the engine's
    /// `RealityFallback` (wrong pbk/sid, or a REALITY client against a
    /// plain-TLS server) instead of establishing a tunnel.
    fn expect_fallback(&self) -> bool {
        false
    }
    /// True when a fallback's Spider-X session terminates at the server's
    /// dest (a REALITY server transparently proxies the fallback there, so
    /// the spider's `h2` preface shows up in the `tls_echo` recording).
    /// False when the fallback session terminates at the server itself (a
    /// plain-TLS server) — the spider's bytes never reach the `tls_echo`.
    fn spider_reaches_dest(&self) -> bool {
        true
    }
    /// True when the probe must target the TLS echo (the transparent
    /// proxy's dest) instead of the plain echo — a plain client through a
    /// REALITY server terminates at the dest.
    fn probe_dest(&self) -> bool {
        false
    }
    /// Install the harness-CA trust this variant's client path needs. Both
    /// certificate-TLS variants (stock and fingerprint) install the engine's
    /// test CA; REALITY needs none (its auth key, not a PKI chain,
    /// authenticates the server).
    fn client_trust(&self, _certs: &Certs) {}

    /// True when the row carries a TLS/REALITY security layer over the
    /// transport at all. `false` = genuinely no security: the server config
    /// emits `streamSettings` WITHOUT `tlsSettings` (xray) / no `tls`
    /// object (sing-box), and the client params omit the `security` key —
    /// the native `wrap` passthrough (`None => Ok(stream)`) leaves the raw
    /// transport stream.
    fn tls_enabled(&self) -> bool {
        true
    }
}

/// No TLS at all — the raw transport stream end to end.
///
/// The e2e suite's first genuinely plain row (`kcp_plain`): the server
/// config emits `streamSettings` without `tlsSettings` (xray) / no `tls`
/// object (sing-box); the client params omit the `security` key so the
/// native `wrap` passthrough (`None => Ok(stream)`) leaves the transport
/// stream unsecured. Vless rows only — the vmess config builders always
/// emit a security layer (no plain vmess row exists).
pub struct NoTls;

impl TlsVariant for NoTls {
    fn name(&self) -> &'static str {
        "plain"
    }
    fn sni(&self) -> &'static str {
        "" // no TLS handshake — nothing to name
    }
    fn tls_enabled(&self) -> bool {
        false
    }
}

/// Stock rustls (the tier-1 behavior; no fingerprint, no REALITY).
pub struct StandardTls;

impl TlsVariant for StandardTls {
    fn name(&self) -> &'static str {
        "tls-standard"
    }
    fn sni(&self) -> &'static str {
        "localhost"
    }
    fn client_trust(&self, certs: &Certs) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::security::fingerprint::set_test_ca(&certs.ca_der);
        // The h3 (QUIC) arm's rustls is quinn-internal — the engine verifier
        // never sees it, so the harness CA needs its own hook (SP5 T4).
        crate::transport::quic::set_test_ca(&certs.ca_der);
    }
}

/// Stock rustls with the hybrid PQ curve pinned on both ends.
///
/// `x25519mlkem768`: the client offers ONLY the X25519MLKEM768 key share
/// (the engine's `curves` option) and the server's `curvePreferences`
/// accepts nothing else — a green row is a negotiated ML-KEM-768 exchange,
/// never a classical fallback.
pub struct PqTls;

impl TlsVariant for PqTls {
    fn name(&self) -> &'static str {
        "tls-pq"
    }
    fn sni(&self) -> &'static str {
        "localhost"
    }
    fn curves(&self) -> Option<&'static str> {
        Some("x25519mlkem768")
    }
    fn client_trust(&self, certs: &Certs) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        crate::security::fingerprint::set_test_ca(&certs.ca_der);
        crate::transport::quic::set_test_ca(&certs.ca_der);
    }
}

/// The fingerprint engine with a named browser profile (`fp` id).
pub struct FingerprintTls(pub &'static str);

impl TlsVariant for FingerprintTls {
    fn name(&self) -> &'static str {
        match self.0 {
            "chrome" => "tls-chrome",
            "firefox" => "tls-firefox",
            other => other,
        }
    }
    fn sni(&self) -> &'static str {
        "localhost"
    }
    fn fingerprint(&self) -> Option<&'static str> {
        Some(self.0)
    }
    fn client_trust(&self, certs: &Certs) {
        crate::security::fingerprint::set_test_ca(&certs.ca_der);
    }
}

/// REALITY with a fresh keypair + short id (see [`RealityTls::fresh`]).
///
/// The private half is stored alongside `pbk` because the xray/sing-box
/// inbound needs it and a public key cannot be inverted; the brief's visible
/// `pbk`/`sid` pair is what the client consumes.
pub struct RealityTls {
    /// Client public key (base64url).
    pub pbk: String,
    /// Shared short id (8 hex chars).
    pub sid: String,
    /// Server private key (base64url) — the matching private half of `pbk`.
    private_key: String,
}

impl RealityTls {
    /// Generate a fresh REALITY keypair and short id for one e2e run.
    #[must_use]
    pub fn fresh() -> Self {
        let (private_key, pbk) = config::reality_keypair();
        Self {
            pbk,
            sid: config::reality_sid(),
            private_key,
        }
    }
}

impl TlsVariant for RealityTls {
    fn name(&self) -> &'static str {
        "reality"
    }
    fn sni(&self) -> &'static str {
        "localhost"
    }
    fn reality_private_key(&self) -> Option<&str> {
        Some(&self.private_key)
    }
    fn reality_pbk(&self) -> Option<&str> {
        Some(&self.pbk)
    }
    fn reality_sid(&self) -> Option<&str> {
        Some(&self.sid)
    }
    // `client_trust`: none — REALITY authenticates via the auth key.
}

/// REALITY server with the real keypair but the client given a *wrong*
/// public key (valid 32-byte key, not the server's). Server transparently
/// proxies → client's auth fails → `RealityFallback`.
pub struct RealityWrongPbkTls(RealityTls);

impl RealityWrongPbkTls {
    /// A wrong but well-formed pbk: a fresh keypair whose private half is
    /// kept only on the client side (never the server's private key).
    #[must_use]
    pub fn fresh() -> Self {
        let inner = RealityTls::fresh();
        let (wrong_private, wrong_pbk) = config::reality_keypair();
        let _ = wrong_private;
        Self(RealityTls {
            pbk: wrong_pbk,
            ..inner
        })
    }
}

impl TlsVariant for RealityWrongPbkTls {
    fn name(&self) -> &'static str {
        "reality-wrong-pbk"
    }
    fn sni(&self) -> &'static str {
        "localhost"
    }
    fn reality_private_key(&self) -> Option<&str> {
        self.0.reality_private_key()
    }
    fn reality_pbk(&self) -> Option<&str> {
        Some(&self.0.pbk) // wrong pbk
    }
    fn reality_sid(&self) -> Option<&str> {
        self.0.reality_sid()
    }
    fn expect_fallback(&self) -> bool {
        true
    }
}

/// REALITY with the server's short id *different* from the client's.
/// Server decrypts the session id (right pbk) but the sid inside doesn't
/// match its own → transparent proxy → fallback.
pub struct RealityWrongSidTls(RealityTls, String); // (real server, wrong client sid)

impl RealityWrongSidTls {
    #[must_use]
    pub fn fresh() -> Self {
        Self(RealityTls::fresh(), config::reality_sid())
    }
}

impl TlsVariant for RealityWrongSidTls {
    fn name(&self) -> &'static str {
        "reality-wrong-sid"
    }
    fn sni(&self) -> &'static str {
        "localhost"
    }
    fn reality_private_key(&self) -> Option<&str> {
        self.0.reality_private_key()
    }
    fn reality_pbk(&self) -> Option<&str> {
        Some(&self.0.pbk)
    }
    fn reality_sid(&self) -> Option<&str> {
        self.0.reality_sid()
    }
    fn reality_client_sid(&self) -> Option<&str> {
        Some(&self.1) // wrong client sid
    }
    fn expect_fallback(&self) -> bool {
        true
    }
}

/// REALITY server (real key) with a plain-fingerprint client — the "active
/// probing without REALITY" case: the probe client is transparently proxied
/// and completes standard TLS to the dest (stealth).
///
/// Probe target = `tls_echo`.
pub struct RealityServerPlainClientTls(RealityTls);

impl RealityServerPlainClientTls {
    #[must_use]
    pub fn fresh() -> Self {
        Self(RealityTls::fresh())
    }
}

impl TlsVariant for RealityServerPlainClientTls {
    fn name(&self) -> &'static str {
        "reality-server-plain-client"
    }
    fn sni(&self) -> &'static str {
        "localhost"
    }
    fn fingerprint(&self) -> Option<&'static str> {
        Some("chrome")
    }
    fn reality_private_key(&self) -> Option<&str> {
        self.0.reality_private_key()
    }
    // No `reality_pbk`: the client is a plain (fingerprint) TLS client, so
    // its ClientHello carries no valid REALITY session id and the server
    // transparently proxies it to the dest (stealth). A pbk here would make
    // the client an auth'd REALITY client instead.
    fn reality_pbk(&self) -> Option<&str> {
        None
    }
    fn reality_sid(&self) -> Option<&str> {
        self.0.reality_sid()
    }
    fn client_trust(&self, certs: &Certs) {
        crate::security::fingerprint::set_test_ca(&certs.ca_der);
    }
    fn probe_dest(&self) -> bool {
        true
    }
}

/// Plain-TLS VLESS server (harness-CA cert) but a REALITY client — the
/// client's auth fails against a non-REALITY server → `RealityFallback`.
pub struct PlainServerRealityClientTls(RealityTls);

impl PlainServerRealityClientTls {
    #[must_use]
    pub fn fresh() -> Self {
        Self(RealityTls::fresh())
    }
}

impl TlsVariant for PlainServerRealityClientTls {
    fn name(&self) -> &'static str {
        "plain-server-reality-client"
    }
    fn sni(&self) -> &'static str {
        "localhost"
    }
    fn reality_private_key(&self) -> Option<&str> {
        None // server = cert TLS
    }
    fn reality_pbk(&self) -> Option<&str> {
        Some(&self.0.pbk)
    }
    fn reality_sid(&self) -> Option<&str> {
        self.0.reality_sid()
    }
    fn expect_fallback(&self) -> bool {
        true
    }
    // The fallback session terminates at the plain server itself (the
    // server's TLS inbound, not a transparent proxy) — the spider's bytes
    // go there, never to the tls_echo dest.
    fn spider_reaches_dest(&self) -> bool {
        false
    }
}

/// Payload-security variant: names itself, gates which cores support it, and
/// supplies the security strings for the server config and client params.
pub trait SecurityVariant: Sync {
    fn name(&self) -> &'static str;
    fn cores(&self) -> &'static [CoreKind];
    fn server_security(&self, core: CoreKind) -> Option<&'static str>;
    fn client_security(&self) -> &'static str;
}

/// `VMess` payload security: AES-128-GCM (xray header security byte 3).
pub struct Aes128GcmVariant;

impl SecurityVariant for Aes128GcmVariant {
    fn name(&self) -> &'static str {
        "aes-128-gcm"
    }
    fn cores(&self) -> &'static [CoreKind] {
        &[CoreKind::Xray, CoreKind::SingBox]
    }
    fn server_security(&self, core: CoreKind) -> Option<&'static str> {
        match core {
            // xray inbound user security mirrors intent; sing-box rejects
            // the field outright (`json: unknown field "security"`).
            CoreKind::Xray => Some("aes-128-gcm"),
            CoreKind::SingBox => None,
        }
    }
    fn client_security(&self) -> &'static str {
        "aes-128-gcm"
    }
}

/// `VMess` payload security: chacha20-poly1305 (header security byte 4).
pub struct Chacha20Poly1305Variant;

impl SecurityVariant for Chacha20Poly1305Variant {
    fn name(&self) -> &'static str {
        "chacha20-poly1305"
    }
    fn cores(&self) -> &'static [CoreKind] {
        &[CoreKind::Xray, CoreKind::SingBox]
    }
    fn server_security(&self, core: CoreKind) -> Option<&'static str> {
        match core {
            CoreKind::Xray => Some("chacha20-poly1305"),
            CoreKind::SingBox => None,
        }
    }
    fn client_security(&self) -> &'static str {
        "chacha20-poly1305"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha_variant_supports_both_cores() {
        let v = Chacha20Poly1305Variant;
        assert_eq!(v.name(), "chacha20-poly1305");
        assert_eq!(v.cores(), &[CoreKind::Xray, CoreKind::SingBox]);
        assert_eq!(v.server_security(CoreKind::Xray), Some("chacha20-poly1305"));
        assert_eq!(v.server_security(CoreKind::SingBox), None); // sing-box: no field
        assert_eq!(v.client_security(), "chacha20-poly1305");
    }
}
