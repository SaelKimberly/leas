//! Shared rstest fixtures for the e2e integration tests (feature `native-e2e`).
#![cfg(feature = "native-e2e")]

use leas_native::e2e::{
    Certs, CoreKind, CoreUnderTest, EchoServer, FingerprintTls, NoTls, PlainServerRealityClientTls,
    PqTls, RealityServerPlainClientTls, RealityTls, RealityWrongPbkTls, RealityWrongSidTls,
    SINGBOX_VERSION, TlsEchoServer, TlsVariant, XRAY_VERSION, generate_certs, spawn_echo,
    spawn_tls_echo,
};
use rstest::fixture;

/// Resolved core binaries, once per test binary (hard-fails when
/// `LEAS_CORE_BIN_DIR` is missing/unversioned).
#[fixture]
#[once]
pub fn cores() -> (CoreUnderTest, CoreUnderTest) {
    let xray = CoreUnderTest::resolve(CoreKind::Xray, XRAY_VERSION).expect("resolve xray-core");
    let singbox =
        CoreUnderTest::resolve(CoreKind::SingBox, SINGBOX_VERSION).expect("resolve sing-box");
    (xray, singbox)
}

/// Harness CA (cert/key), generated once per test binary.
#[fixture]
#[once]
pub fn certs() -> Certs {
    generate_certs()
}

/// Plain HTTP echo; `per-test` (`tiny_http` owns a thread; Drop unblocks it).
#[fixture]
pub fn echo() -> EchoServer {
    spawn_echo()
}

/// TLS HTTP echo with the harness CA; per-test — `reset_recording`/
/// `saw_h2_preface` is mutable fallback-case state, so sharing would race.
#[fixture]
pub fn tls_echo(certs: &Certs) -> TlsEchoServer {
    spawn_tls_echo(certs)
}

/// Select the resolved core for a `CoreKind` case value.
#[must_use]
pub const fn pick(cores: &(CoreUnderTest, CoreUnderTest), kind: CoreKind) -> &CoreUnderTest {
    match kind {
        CoreKind::Xray => &cores.0,
        CoreKind::SingBox => &cores.1,
    }
}

/// TLS-variant builders — keep the `#[case]` rows one-liners (shared by the
/// vless + vmess matrices; `StandardTls` is `CaseSpec`'s default, no builder).
#[must_use]
#[allow(dead_code)] // shared across test binaries; each uses a subset
pub fn fp(id: &'static str) -> Box<dyn TlsVariant> {
    Box::new(FingerprintTls(id))
}

#[must_use]
#[allow(dead_code)] // shared across test binaries; each uses a subset
pub fn reality() -> Box<dyn TlsVariant> {
    Box::new(RealityTls::fresh())
}

/// Hybrid PQ curve pinned on both ends (`x25519mlkem768`): the client offers
/// only the X25519MLKEM768 key share and the server's `curvePreferences`
/// accepts nothing else — a green row is a negotiated ML-KEM-768 exchange
/// (SP7 spec §7.3).
#[must_use]
#[allow(dead_code)] // shared across test binaries; each uses a subset
pub fn pq_tls() -> Box<dyn TlsVariant> {
    Box::new(PqTls)
}

/// Genuinely no TLS: the raw transport stream end to end (server
/// streamSettings without tlsSettings, client security none — the `kcp_plain`
/// row). Vless-only (vmess rows always carry a security layer).
#[must_use]
#[allow(dead_code)] // vless-only variant (unused in the vmess test binary)
pub fn no_tls() -> Box<dyn TlsVariant> {
    Box::new(NoTls)
}

// vless-only variant (unused in the vmess test binary, which shares this module).
#[must_use]
#[allow(dead_code)]
pub fn reality_wrong_pbk() -> Box<dyn TlsVariant> {
    Box::new(RealityWrongPbkTls::fresh())
}

// vless-only variant (unused in the vmess test binary, which shares this module).
#[must_use]
#[allow(dead_code)]
pub fn reality_wrong_sid() -> Box<dyn TlsVariant> {
    Box::new(RealityWrongSidTls::fresh())
}

// vless-only variant (unused in the vmess test binary, which shares this module).
#[must_use]
#[allow(dead_code)]
pub fn reality_server_plain_client() -> Box<dyn TlsVariant> {
    Box::new(RealityServerPlainClientTls::fresh())
}

// vless-only variant (unused in the vmess test binary, which shares this module).
#[must_use]
#[allow(dead_code)]
pub fn plain_server_reality_client() -> Box<dyn TlsVariant> {
    Box::new(PlainServerRealityClientTls::fresh())
}
