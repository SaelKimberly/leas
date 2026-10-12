//! Fingerprint parsing + verifier building for the `leas-tls` engine.
//!
//! `wrap()` routes every TLS connect through the engine
//! (`leas_tls::client::connect`); this module supplies the engine-side
//! pieces: the URL `fp` id parser, the id → [`Fingerprint`] identity mapping, and
//! the [`WebPkiVerifier`] builder — harness CA (test/e2e), `webpki-roots`
//! (production), `allowInsecure`, or a `pinSHA256` SPKI pin.

use base64::Engine as _;
use leas_tls::fingerprints::{Browser, Device, Fingerprint, Os};
use leas_tls::verify::WebPkiVerifier;

use crate::error::NativeError;

/// Browser fingerprint id, mirrored from the URL `fp` parameter.
///
/// The accepted set is xray's `PresetFingerprints` minus the ids this engine
/// has no hello for (`360`, `qq`, `android`, `randomizednoalpn`). A
/// subscription carrying one of those is **probed with the engine default and
/// marked approximated** by [`resolve_fingerprint`], never refused and never
/// silently substituted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintId {
    Chrome,
    ChromeRandomized,
    Firefox,
    Safari,
    Edge,
    /// `ios` — uTLS `HelloIOS_Auto`; the engine's Safari-on-iOS identity.
    Ios,
    Random,
}

impl std::fmt::Display for FingerprintId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Chrome => "chrome",
            Self::ChromeRandomized => "chrome-randomized",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
            Self::Edge => "edge",
            Self::Ios => "ios",
            Self::Random => "random",
        };
        f.write_str(s)
    }
}

/// Parse a URL `fp` value into the engine's fingerprint id.
///
/// `randomized` is xray's alias for the randomized-Chrome hello
/// (`HelloRandomized`), and `edge`/`ios` are presets the roster carries
/// (`edge_106`, Safari-on-iOS) — three ids that used to be refused although a
/// profile existed, which marked ~19 links per subscription "not testable by
/// the native engine". `360`, `qq`, `android` and `randomizednoalpn` have no
/// engine hello and are **approximated** by [`resolve_fingerprint`] rather than
/// refused; `unsafe` means "no fingerprint requested" and resolves to the
/// engine default.
pub fn parse_fingerprint_id(s: &str) -> Result<FingerprintId, NativeError> {
    match s {
        "chrome" => Ok(FingerprintId::Chrome),
        "chrome-randomized" | "randomized" => Ok(FingerprintId::ChromeRandomized),
        "firefox" => Ok(FingerprintId::Firefox),
        "safari" => Ok(FingerprintId::Safari),
        "edge" => Ok(FingerprintId::Edge),
        "ios" => Ok(FingerprintId::Ios),
        "random" => Ok(FingerprintId::Random),
        other => Err(NativeError::Config(format!(
            "unknown fingerprint id {other:?} (expected chrome, chrome-randomized, \
             randomized, firefox, safari, edge, ios or random)"
        ))),
    }
}

/// Resolve a URL `fp` value to the identity the engine probes with, plus
/// whether the requested shape was honoured.
///
/// This is the single decision point for the fingerprint policy, so the
/// capability gate and the row label cannot drift: both read this function.
///
/// - `None`, `""` and `unsafe` all mean *no fingerprint requested*. The engine
///   default IS the requested shape, so they resolve to `None` with
///   `approximated = false` — the same shape an absent `fp` has always taken.
///   An empty string reaches here as `Some("")` for a present-but-empty field,
///   which is why it must be handled explicitly rather than left to the parser.
/// - A known id resolves to its own profile.
/// - An id with no roster row (an xray-only uTLS preset, or a future one)
///   resolves to the engine default with `approximated = true`: probing with a
///   shape the link did not ask for is a decision the row must carry visibly.
///
/// `Option<FingerprintId>` (`None` = engine default) is the shape both call
/// sites need: plain TLS passes it through, REALITY maps `None` to its fixed
/// provisioner.
#[must_use]
pub fn resolve_fingerprint(s: Option<&str>) -> (Option<FingerprintId>, bool) {
    match s {
        None | Some("" | "unsafe") => (None, false),
        Some(id) => parse_fingerprint_id(id).map_or((None, true), |fp| (Some(fp), false)),
    }
}

/// Resolve a fingerprint id to the engine's [`Fingerprint`] identity.
///
/// `Random` maps to the Chrome-130 capture, matching the engine's
/// "generic Chrome" convention. The concrete versions are the roster rows the
/// resolution table carries (`edge_106`, Safari-on-iOS 26) — pinned by
/// `every_fingerprint_id_resolves_to_a_roster_row`, so a roster change fails
/// the test instead of silently probing with a shape the link did not ask for.
pub const fn profile_for(fp: FingerprintId) -> Result<Fingerprint, NativeError> {
    Ok(match fp {
        FingerprintId::Chrome | FingerprintId::ChromeRandomized | FingerprintId::Random => {
            Fingerprint::new(Browser::Chrome).with_version(130)
        }
        FingerprintId::Firefox => Fingerprint::new(Browser::Firefox)
            .with_version(128)
            .with_os(Os::Linux),
        FingerprintId::Safari => Fingerprint::new(Browser::Safari)
            .with_version(17)
            .with_os(Os::MacOs),
        FingerprintId::Edge => Fingerprint::new(Browser::Edge)
            .with_version(106)
            .with_os(Os::Windows)
            .with_device(Device::Desktop),
        FingerprintId::Ios => Fingerprint::new(Browser::Safari)
            .with_version(26)
            .with_os(Os::Ios)
            .with_device(Device::Phone),
    })
}

// Test/e2e override: a verifier trusting exactly one CA (the harness CA).
// Thread-local: each `#[tokio::test]` runs on its own OS thread with its own
// harness CA, so parallel e2e cases can't clobber each other's trust store.
// Production builds use webpki-roots and carry no test state.
#[cfg(any(test, feature = "native-e2e"))]
std::thread_local! {
    static TEST_CA: std::cell::RefCell<Option<WebPkiVerifier>> =
        const { std::cell::RefCell::new(None) };
}

/// Install a test-only verifier trusting exactly `ca_der` (test/e2e harness).
#[doc(hidden)]
#[cfg(any(test, feature = "native-e2e"))]
pub fn set_test_ca(ca_der: &[u8]) {
    let verifier = WebPkiVerifier::from_ca_der(ca_der).expect("harness CA der is a valid cert");
    TEST_CA.with(|c| *c.borrow_mut() = Some(verifier));
}

/// Build the verifier for a connect: test CA (harness) else webpki-roots,
/// then `insecure` / `pin_sha256` overrides from the TLS opts.
pub(crate) fn verifier_for(insecure: bool, pin: Option<[u8; 32]>) -> WebPkiVerifier {
    #[cfg(any(test, feature = "native-e2e"))]
    let verifier = TEST_CA
        .with(|c| c.borrow().clone())
        .unwrap_or_else(WebPkiVerifier::webpki_roots);
    #[cfg(not(any(test, feature = "native-e2e")))]
    let verifier = WebPkiVerifier::webpki_roots();
    let verifier = verifier.with_insecure(insecure);
    match pin {
        Some(pin) => verifier.with_pin(pin),
        None => verifier,
    }
}

/// Decode a `pinSHA256` value (base64, standard or URL-safe) to its 32 bytes.
pub(crate) fn decode_pin_sha256(s: Option<&str>) -> Result<Option<[u8; 32]>, NativeError> {
    let Some(s) = s else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| NativeError::Tls(format!("invalid pinSHA256 base64: {e}")))?;
    let pin: [u8; 32] = bytes
        .try_into()
        .map_err(|_| NativeError::Tls("pinSHA256 must decode to 32 bytes".into()))?;
    Ok(Some(pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every id the parser accepts must resolve to a row the roster actually
    /// carries: `profile_for` pins concrete versions, and a roster change
    /// (a renamed/removed row) would otherwise surface as a handshake error on
    /// a live link instead of a test failure.
    #[test]
    fn every_fingerprint_id_resolves_to_a_roster_row() {
        for id in [
            FingerprintId::Chrome,
            FingerprintId::ChromeRandomized,
            FingerprintId::Firefox,
            FingerprintId::Safari,
            FingerprintId::Edge,
            FingerprintId::Ios,
            FingerprintId::Random,
        ] {
            let fp = profile_for(id).expect("profile_for is total");
            let resolved = fp
                .resolve()
                .unwrap_or_else(|e| panic!("{id} ({}) has no roster row: {e}", fp.render()));
            assert_eq!(resolved.fingerprint.browser, fp.browser, "{id}");
        }
    }

    /// xray's own preset ids: `parse_fingerprint_id` accepts exactly the ids
    /// the roster carries a row for.
    #[test]
    fn parser_accepts_exactly_the_roster_ids() {
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
            assert!(parse_fingerprint_id(fp).is_ok(), "{fp} should be served");
        }
        for fp in ["android", "360", "qq", "randomizednoalpn", "unsafe", ""] {
            assert!(
                parse_fingerprint_id(fp).is_err(),
                "{fp} has no engine hello"
            );
        }
    }

    /// The policy: only an id that WAS requested and has no roster row is an
    /// approximation. The three spellings of "no fingerprint requested" are
    /// not — the engine default is the shape they asked for.
    #[test]
    fn resolve_marks_only_unrosterable_ids_as_approximated() {
        for fp in [None, Some(""), Some("unsafe")] {
            assert_eq!(resolve_fingerprint(fp), (None, false), "{fp:?}");
        }
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
            let (id, approximated) = resolve_fingerprint(Some(fp));
            assert_eq!(id, Some(parse_fingerprint_id(fp).unwrap()), "{fp}");
            assert!(!approximated, "{fp} has a roster row and is honoured");
        }
        for fp in ["android", "360", "qq", "randomizednoalpn", "chrome-130"] {
            assert_eq!(
                resolve_fingerprint(Some(fp)),
                (None, true),
                "{fp} must resolve to the engine default, marked approximated"
            );
        }
    }

    /// "Approximated" means the same identity an absent `fp` produces, so the
    /// resolver cannot silently invent a third shape. The flag is the only
    /// difference — that is what makes the marker meaningful.
    #[test]
    fn approximated_and_absent_resolve_to_the_same_identity() {
        let (absent_id, absent_marked) = resolve_fingerprint(None);
        assert!(!absent_marked, "an absent fp is not an approximation");
        for fp in ["android", "360", "qq", "randomizednoalpn", "chrome-130"] {
            let (id, approximated) = resolve_fingerprint(Some(fp));
            assert_eq!(id, absent_id, "{fp} must probe the absent-fp identity");
            assert!(approximated, "{fp} differs only by the marker");
        }
    }
}
