//! Tier-2 verification against a **strict** peer (network).
//!
//! Ignored by default so `cargo test` needs no network; run with
//! `cargo test -p leas-tls --test strict_peer_presets -- --ignored`.
//!
//! The offline roster gate (`tests/generated_ja4_gate.rs`) checks the wire
//! against this crate's own parser and the JA4 id/hash projection; the
//! `tls_peet.ws` grader checks it against a **lenient** Go peer. Neither can
//! see a malformed extension *body*, which is how the 2026-09-17 run shipped
//! two of them: `encrypted_client_hello` with a 0-byte body (36 generated
//! rows) and `compress_certificate` with an empty algorithm list (28 rows).
//! `BoringSSL` — Cloudflare, Google — answers `alert 2 50 (decode_error)` to
//! both, so every affected preset failed to connect or probe at all.
//!
//! This test dials a `BoringSSL` front with each preset the app hands out and
//! asserts the handshake completes. A verification failure is not the
//! subject: the question is whether the peer accepted the **hello**, so the
//! probe runs insecure (the same convention as `examples/probe_host.rs`) and
//! a completed handshake is the pass condition.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;

use leas_tls::client::{TlsConfig, connect};
use leas_tls::fingerprints::{Browser, Device, Fingerprint, Os};
use leas_tls::verify::WebPkiVerifier;

/// A Cloudflare-fronted name: `BoringSSL` parses `encrypted_client_hello`,
/// `compress_certificate` and `delegated_credentials` here, and a bad body
/// is rejected before any application data is exchanged.
const HOST: &str = "www.cloudflare.com";
const PORT: u16 = 443;
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);

/// Every fingerprint preset the native path resolves — one per
/// `FingerprintId` in `leas-native`'s `profile_for`. The three
/// generated-tier presets (firefox, safari, ios) are the ones the
/// 2026-09-17 defect killed; chrome/edge are the hand-declared tier and act
/// as the control.
fn presets() -> Vec<(&'static str, Fingerprint)> {
    vec![
        (
            "chrome",
            Fingerprint::new(Browser::Chrome).with_version(130),
        ),
        (
            "firefox",
            Fingerprint::new(Browser::Firefox)
                .with_version(128)
                .with_os(Os::Linux),
        ),
        (
            "safari",
            Fingerprint::new(Browser::Safari)
                .with_version(17)
                .with_os(Os::MacOs),
        ),
        (
            "ios",
            Fingerprint::new(Browser::Safari)
                .with_version(26)
                .with_os(Os::Ios)
                .with_device(Device::Phone),
        ),
        (
            "edge",
            Fingerprint::new(Browser::Edge)
                .with_version(106)
                .with_os(Os::Windows)
                .with_device(Device::Desktop),
        ),
    ]
}

#[tokio::test]
#[ignore = "network"]
async fn every_preset_hello_is_accepted_by_a_strict_peer() {
    let mut failures = Vec::new();
    for (name, fingerprint) in presets() {
        let stream = match TcpStream::connect((HOST, PORT)).await {
            Ok(stream) => stream,
            Err(e) => panic!("{HOST}:{PORT} dial failed: {e}"),
        };
        let verifier = Arc::new(WebPkiVerifier::webpki_roots().with_insecure(true));
        let mut config = TlsConfig::plain(Some(fingerprint), verifier, HOST.to_string());
        config.alpn = Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        match tokio::time::timeout(ATTEMPT_TIMEOUT, connect(stream, &config)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => failures.push(format!("{name}: {e}")),
            Err(_) => failures.push(format!("{name}: timed out")),
        }
    }
    assert!(
        failures.is_empty(),
        "a strict peer rejected these preset hellos:\n  {}",
        failures.join("\n  ")
    );
}
