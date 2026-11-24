//! Roster-wide signature-scheme boundary gate.
//!
//! Every scheme a profile advertises is either verifiable by the ring-backed
//! engine (TLS 1.3 or TLS 1.2 only) or an explicitly documented failure. A
//! new profile that introduces an unclassified code point fails here, so the
//! boundary cannot drift into a silent handshake failure.

use leas_tls::profiles::generated::GENERATED;
use leas_tls::profiles::hand_selected::{chrome_130, edge_106};
use leas_tls::spec::{ClientHelloSpec, ExtensionSpec};
use leas_tls::verify::{
    SchemeSupport, scheme_support, tls12_verifier_available, tls13_verifier_available,
};

fn advertised_schemes(spec: &ClientHelloSpec) -> Option<&[u16]> {
    spec.extensions.iter().find_map(|ext| match ext {
        ExtensionSpec::SignatureAlgorithms(schemes) => Some(schemes.as_slice()),
        _ => None,
    })
}

fn check(name: &str, spec: &ClientHelloSpec, counts: &mut [usize; 3]) {
    let schemes =
        advertised_schemes(spec).unwrap_or_else(|| panic!("{name}: no signature_algorithms"));
    for &scheme in schemes {
        let class = scheme_support(scheme)
            .unwrap_or_else(|| panic!("{name}: scheme 0x{scheme:04X} is not classified"));
        let idx = match class {
            SchemeSupport::Tls13 => {
                assert!(
                    tls13_verifier_available(scheme),
                    "{name}: TLS 1.3 class without a verifier for 0x{scheme:04X}"
                );
                assert!(
                    tls12_verifier_available(scheme),
                    "{name}: TLS 1.3 class without a TLS 1.2 verifier for 0x{scheme:04X}"
                );
                0
            }
            SchemeSupport::Tls12Only => {
                assert!(
                    !tls13_verifier_available(scheme),
                    "{name}: TLS 1.2-only scheme has a TLS 1.3 verifier: 0x{scheme:04X}"
                );
                assert!(
                    tls12_verifier_available(scheme),
                    "{name}: TLS 1.2-only scheme has no TLS 1.2 verifier: 0x{scheme:04X}"
                );
                1
            }
            SchemeSupport::DocumentedUnverifiable => {
                assert!(
                    !tls13_verifier_available(scheme),
                    "{name}: documented-unverifiable 0x{scheme:04X} has a TLS 1.3 verifier"
                );
                assert!(
                    !tls12_verifier_available(scheme),
                    "{name}: documented-unverifiable 0x{scheme:04X} has a TLS 1.2 verifier"
                );
                2
            }
        };
        counts[idx] += 1;
    }
}

#[test]
fn every_advertised_scheme_is_classified() {
    let mut counts = [0usize; 3];
    for entry in GENERATED {
        check(entry.name, &(entry.spec_fn)(), &mut counts);
    }
    check("chrome_130", &chrome_130(), &mut counts);
    check("edge_106", &edge_106(), &mut counts);

    // The roster really exercises all three classes; otherwise this gate
    // could pass vacuously after a generator change.
    assert!(counts[0] > 0, "no TLS 1.3-verifiable scheme in the roster");
    assert!(counts[1] > 0, "no TLS 1.2-only scheme in the roster");
    assert!(
        counts[2] > 0,
        "no documented-unverifiable scheme in the roster"
    );
}
