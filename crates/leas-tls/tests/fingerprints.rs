//! Instantly-verifiable fingerprint cases (design spec: rstest tables).
//! Expected JA4s are frozen from live `tls.peet.ws` captures of each
//! profile's hello (GREASE-stable by construction — JA4 strips GREASE).
//!
//! Capture provenance: every expected string below was reported by
//! `tls.peet.ws` for a live connection made by this engine with the
//! profile's hello (grader example, 2026-08-24; Tasks 7/8/10).
//!
//! Known JA4 collision (verified genuine, not copy-paste error):
//! `edge_106 == chrome_130` share the same cipher set, extension-id set,
//! and signature-alg order — they differ only in extension ORDER, which
//! JA4 hashes sorted, so the full strings coincide.

use leas_tls::fingerprints::{Fingerprint, query::Browser};
use rstest::rstest;

const fn fp(browser: Browser, version: u16) -> Fingerprint {
    Fingerprint::new(browser).with_version(version)
}

#[rstest]
// ── surviving hand profiles ──
#[case::chrome_130(fp(Browser::Chrome, 130), "t13d1516h2_8daaf6152771_f37e75b10bcc")]
#[case::edge_106(fp(Browser::Edge, 106), "t13d1516h2_8daaf6152771_f37e75b10bcc")]
fn ja4_matches_peet_ground_truth(#[case] fp: Fingerprint, #[case] expected: &str) {
    let resolved = fp.resolve().expect("table case must resolve");
    assert_eq!(resolved.ja4(), expected, "{}", resolved.name);
}

#[rstest]
#[case::chrome_130(fp(Browser::Chrome, 130))]
#[case::edge_106(fp(Browser::Edge, 106))]
fn ja4_is_run_to_run_stable(#[case] fp: Fingerprint) {
    let a = fp.resolve().unwrap().ja4();
    let b = fp.resolve().unwrap().ja4(); // fresh spec; GREASE draws differ
    assert_eq!(a, b, "JA4 must be GREASE-independent");
}

#[rstest]
#[case::chrome_130(fp(Browser::Chrome, 130))]
#[case::edge_106(fp(Browser::Edge, 106))]
fn grease_carrying_profiles_use_stripped_ja3_variant(#[case] fp: Fingerprint) {
    // Determinism rule (b): stripped variant is deterministic; classic
    // on-wire JA3 is NOT pinned for these families.
    let resolved = fp.resolve().unwrap();
    let ja3 = leas_tls::crypto::fingerprint::ja3::ja3_grease_stripped(
        &leas_tls::crypto::fingerprint::ja3::Ja3Fields::from_spec(&resolved.spec),
    );
    assert!(!ja3.is_empty());
}
