//! Identity → concrete hello resolution over a two-tier table.
//!
//! Resolution is **next-modern**: a query version `v` resolves to the
//! smallest kept major `>= v` within the os/device-compatible identity
//! group; versions above the group's newest row, or below its oldest kept
//! major (era mismatch), refuse.
//!
//! When the query's exact `(browser, os, device)` triple has no rows, the
//! query retries with the os dropped (same browser+device over any-os
//! rows): desktop hellos are OS-independent within a family, so e.g.
//! `chrome/linux` serves the family's `windows/macos` chrome rows.
//!
//! Strict per the design spec: unknown combinations error with the list
//! of what IS resolvable. Never silently substitute a different browser,
//! and never serve a hello older than the requested version.

use crate::fingerprints::error::FingerprintError;
use crate::fingerprints::query::{Browser, Device, Fingerprint, Os};
use crate::profiles::generated::{GENERATED, GenEntry};
use crate::spec::ClientHelloSpec;
use std::sync::LazyLock;

/// One resolvable identity row.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Row {
    /// Stable spec name (`chrome_130`) — appears in errors and UI.
    pub name: &'static str,
    pub browser: Browser,
    /// `None` = row serves any OS (desktop hellos are largely OS-independent
    /// within a browser family).
    pub os: Option<Os>,
    pub device: Device,
    /// Inclusive maximum requested major this row answers.
    pub max_version: u16,
    /// Inclusive minimum requested major this row answers (`0` =
    /// unbounded below). Hand rows set this to `0` — their band absorbs
    /// every version up to `max_version`. Generated rows set it to their
    /// own major; the chooser refuses queries below the group's oldest
    /// kept major (its smallest `min_version`).
    pub min_version: u16,
    pub spec: fn() -> ClientHelloSpec,
}

use crate::profiles::hand_selected;

/// The hand-written wire-exact tier. Ordered ascending by `max_version`
/// within each `(browser, os, device)`.
static HAND_ROWS: &[Row] = &[
    Row {
        name: "chrome_130",
        browser: Browser::Chrome,
        os: Some(Os::Windows),
        device: Device::Desktop,
        max_version: 130,
        min_version: 0,
        spec: hand_selected::chrome_130,
    },
    Row {
        name: "edge_106",
        browser: Browser::Edge,
        os: Some(Os::Windows),
        device: Device::Desktop,
        max_version: 106,
        min_version: 0,
        spec: hand_selected::edge_106,
    },
];
/// The merged resolution table: [`HAND_ROWS`] then the derived generated
/// bands ([`generated_rows`]). Built once on first use.
static TABLE: LazyLock<Vec<Row>> = LazyLock::new(|| {
    let mut rows = Vec::with_capacity(HAND_ROWS.len() + GENERATED.len());
    rows.extend(HAND_ROWS.iter().copied());
    rows.extend(generated_rows());
    rows
});

/// The merged resolution table (see [`TABLE`]).
pub(crate) fn table() -> &'static [Row] {
    &TABLE
}

/// The generated-tier slice of [`table`]: derived rows only.
fn generated_rows_slice() -> &'static [Row] {
    &table()[HAND_ROWS.len()..]
}

/// Derives the generated-tier rows from the roster: one [`Row`] per kept
/// entry, so every kept identity stays individually resolvable — next-modern
/// must answer `v` with the smallest *kept major* `>= v`, which per-major
/// rows preserve exactly (band merging would collapse e.g. the firefox
/// macOS majors 148/149/150 into one row and mis-serve 148/149). Rows are
/// ordered by `(browser, os, device)` — the same deterministic group order
/// the roster's band construction used — so ties (rows sharing a
/// `max_version`, and variant fingerprints sharing a
/// `(browser, os, device, major)` — distinct JA4s, never deduped) resolve
/// to the first-declared row (stable sort keeps [`GENERATED`] order).
fn generated_rows() -> Vec<Row> {
    let mut entries: Vec<&GenEntry> = GENERATED.iter().collect();
    entries.sort_by_key(|e| (e.browser.name(), e.os.map(Os::name), e.device.name()));
    entries
        .into_iter()
        .map(|e| Row {
            name: e.name,
            browser: e.browser,
            os: e.os,
            device: e.device,
            max_version: e.major,
            min_version: e.major,
            spec: e.spec_fn,
        })
        .collect()
}

/// Greatest `max_version` row (ties → first declared).
fn greatest_row<'a>(rows: impl Iterator<Item = &'a Row>) -> Option<&'a Row> {
    rows.reduce(|best, r| {
        if r.max_version > best.max_version {
            r
        } else {
            best
        }
    })
}

/// Next-modern chooser, shared by both tiers: among the
/// os/device-compatible rows of the group, pick the row with the smallest
/// `max_version >= v` (first-declared on ties). Refuse when `v` sits above
/// the group's newest row (no `max_version >= v`) or below its oldest kept
/// major (era mismatch — never serve a hello from a wildly different era
/// than asked for). Version-unset queries take the greatest `max_version`
/// row, ties → first declared ([`greatest_row`]).
fn choose_next_modern<'b>(candidates: &[&'b Row], version: Option<u16>) -> Option<&'b Row> {
    version.map_or_else(
        || greatest_row(candidates.iter().copied()),
        |v| {
            let oldest_kept_major = candidates.iter().map(|r| r.min_version).min()?;
            if v < oldest_kept_major {
                return None;
            }
            candidates
                .iter()
                .filter(|r| v <= r.max_version)
                .min_by_key(|r| r.max_version)
                .copied()
        },
    )
}

impl Row {
    /// Identity/os/device compatibility with a query. Version gating
    /// lives in [`choose_next_modern`], not here: rows above `v` are
    /// valid next-modern candidates.
    fn matches(&self, q_os: Option<Os>, q_device: Option<Device>) -> bool {
        if let Some(d) = q_device {
            if d != self.device {
                return false;
            }
        } else if self.device != Device::Desktop {
            return false; // unspecified device defaults to desktop rows
        }
        // Os-unpinned rows serve any os; an unspecified query os accepts
        // pinned-os rows.
        match (q_os, self.os) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
    }
}

/// The table row answering `browser` at its greatest `max_version`.
/// Hand-tier rows win: the wire-exact tier holds the authoritative
/// latest-known identities. Generated bands answer only browsers with no
/// hand rows (e.g. Samsung Internet). Ties resolve to the first
/// (earliest-declared) row.
pub(crate) fn latest_row(browser: Browser) -> Option<&'static Row> {
    greatest_row(HAND_ROWS.iter().filter(|r| r.browser == browser)).or_else(|| {
        greatest_row(
            generated_rows_slice()
                .iter()
                .filter(|r| r.browser == browser),
        )
    })
}

/// Every resolvable identity name, sorted (error payloads, UI pickers).
#[must_use]
pub fn available_identities() -> Vec<String> {
    let mut names: Vec<String> = table().iter().map(|r| r.name.to_string()).collect();
    names.sort();
    names
}

impl Fingerprint {
    /// Rows in `rows` that could answer this query (same browser, and
    /// os/device compat against `q_os`), in declaration order. Version is
    /// not filtered here: next-modern candidates may sit above `v`.
    fn matching<'a>(&self, rows: &'a [Row], q_os: Option<Os>) -> Vec<&'a Row> {
        rows.iter()
            .filter(|r| r.browser == self.browser && r.matches(q_os, self.device))
            .collect()
    }

    /// Resolves to a concrete hello in two passes, hand tier first in
    /// both (wire-exact precedence): the query's exact
    /// `(browser, os, device)` triple, then — when that yields no row —
    /// the same browser+device over any-os rows (cross-triple os-drop:
    /// desktop hellos are OS-independent within a family, so e.g.
    /// `chrome/linux` serves the family's `windows/macos` chrome rows).
    ///
    /// Within a pass both tiers apply next-modern: query `v` resolves to
    /// the smallest kept major `>= v` in the os/device-compatible group,
    /// refusing versions above the group's newest row or below its oldest
    /// kept major (era mismatch).
    ///
    /// # Errors
    /// [`FingerprintError::Unknown`] when neither pass finds a row.
    pub fn resolve(&self) -> Result<Resolved, FingerprintError> {
        let chosen = if self.os.is_some() {
            self.resolve_in_pass(self.os)
                .or_else(|| self.resolve_in_pass(None))
        } else {
            self.resolve_in_pass(None)
        };
        let Some(row) = chosen else {
            return Err(FingerprintError::Unknown {
                query: self.render(),
                available: available_identities(),
            });
        };
        Ok(Resolved {
            name: row.name,
            fingerprint: Self {
                browser: row.browser,
                version: Some(self.version.unwrap_or(row.max_version)),
                os: self.os.or(row.os),
                device: Some(self.device.unwrap_or(row.device)),
            },
            spec: (row.spec)(),
        })
    }

    /// One resolution pass over both tiers for a fixed query os: hand
    /// tier first (wire-exact wins over generated rows), then the
    /// generated tier; both next-modern.
    fn resolve_in_pass(&self, q_os: Option<Os>) -> Option<&'static Row> {
        let hand_candidates = self.matching(HAND_ROWS, q_os);
        let generated_candidates = self.matching(generated_rows_slice(), q_os);
        let hand = choose_next_modern(&hand_candidates, self.version);
        hand.or_else(|| choose_next_modern(&generated_candidates, self.version))
    }
}

/// A successfully resolved fingerprint: identity + concrete hello.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// Resolution-table name (`chrome_130`).
    pub name: &'static str,
    /// Fully concretized identity (unset query fields filled from the row).
    pub fingerprint: Fingerprint,
    /// The hello specification.
    pub spec: ClientHelloSpec,
}

impl Resolved {
    /// The full JA4 of this resolved hello (computed, not looked up).
    #[must_use]
    pub fn ja4(&self) -> String {
        crate::crypto::fingerprint::ja4::full_ja4(
            &crate::crypto::fingerprint::ja3::Ja3Fields::from_spec(&self.spec),
        )
    }

    /// True when this resolved hello's JA4 was observed in the wild for
    /// its claimed browser identity (catalog evidence). Version is passed
    /// as `None`: recall over precision — evidence-only check, so catalog
    /// rows without a recorded browser major still count.
    ///
    /// Honest caveat: the hand-transcribed rows (`chrome_130`, `edge_106`)
    /// were captured outside the observed corpus, so their JA4s are absent
    /// from the catalog and this returns `false` for them; every kept
    /// generated row, however, IS a catalog observation
    /// (`manifest-derived`) and returns `true`. The check distinguishes
    /// wire-captured evidence from hand-written transcriptions.
    #[must_use]
    pub fn in_catalog(&self) -> bool {
        super::catalog::contains(self.fingerprint.browser.name(), None, &self.ja4())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fingerprint with an optional os.
    fn fp(browser: Browser, version: u16, os: Option<Os>, device: Device) -> Fingerprint {
        let mut fp = Fingerprint::new(browser)
            .with_version(version)
            .with_device(device);
        fp.os = os;
        fp
    }

    /// Next-modern fallback: a version between kept majors resolves to the
    /// smallest kept major `>= v`. The hand `chrome_130` band `(0, 130]`
    /// absorbs every version up to 130 (hand precedence); above it the
    /// generated tier answers next-modern; above the newest row refuses.
    /// Cross-triple os-drop covers linux/os-less chrome desktop queries.
    #[rstest::rstest]
    #[case::chrome_windows_50_hand_band(
        fp(Browser::Chrome, 50, Some(Os::Windows), Device::Desktop),
        Ok("chrome_130")
    )]
    #[case::chrome_windows_93_hand_band(
        fp(Browser::Chrome, 93, Some(Os::Windows), Device::Desktop),
        Ok("chrome_130")
    )]
    #[case::chrome_windows_115_hand_band(
        fp(Browser::Chrome, 115, Some(Os::Windows), Device::Desktop),
        Ok("chrome_130")
    )]
    #[case::chrome_windows_140_next_modern(
        fp(Browser::Chrome, 140, Some(Os::Windows), Device::Desktop),
        Ok("chrome_143_windows_desktop")
    )]
    #[case::chrome_windows_200_refuses(fp(Browser::Chrome, 200, Some(Os::Windows), Device::Desktop), Err(()))]
    #[case::chrome_linux_115_cross_triple(
        fp(Browser::Chrome, 115, Some(Os::Linux), Device::Desktop),
        Ok("chrome_130")
    )]
    #[case::chrome_osless_115_any_os(
        fp(Browser::Chrome, 115, None, Device::Desktop),
        Ok("chrome_130")
    )]
    fn resolves_under_reduced_roster(
        #[case] fp: Fingerprint,
        #[case] expected: Result<&'static str, ()>,
    ) {
        match expected {
            Ok(name) => {
                let r = fp.resolve().unwrap();
                assert_eq!(r.name, name);
            }
            Err(()) => assert!(fp.resolve().is_err()),
        }
    }

    #[test]
    fn resolves_exact_query() {
        let fp = Fingerprint::new(Browser::Chrome)
            .with_version(143)
            .with_os(Os::Windows)
            .with_device(Device::Desktop);
        let r = fp.resolve().unwrap();
        assert_eq!(r.name, "chrome_143_windows_desktop");
        assert!(!r.spec.cipher_suites.is_empty());
    }

    #[test]
    fn falls_forward_to_next_modern_major_same_platform() {
        let fp = Fingerprint::new(Browser::Chrome)
            .with_version(132)
            .with_os(Os::Windows)
            .with_device(Device::Desktop);
        let r = fp.resolve().unwrap();
        // The hand chrome_130 band caps at 130; the smallest kept chrome
        // windows major >= 132 is 143.
        assert_eq!(r.name, "chrome_143_windows_desktop");
        assert_eq!(r.fingerprint.version, Some(132));
    }

    #[test]
    fn unset_fields_default_to_desktop_rows() {
        // Bare Firefox query lands on the newest desktop row: the Android
        // desktop band [149, 150], served by firefox_150_android_desktop
        // (greatest max_version; first-declared group wins ties). The
        // resolved os fills from the row.
        let r = Fingerprint::new(Browser::Firefox).resolve().unwrap();
        assert_eq!(r.name, "firefox_150_android_desktop");
        assert_eq!(r.fingerprint.os, Some(Os::Android));
        assert_eq!(r.fingerprint.device, Some(Device::Desktop));
    }

    #[test]
    fn pinned_os_fills_from_row_when_query_unspecified() {
        // Safari v17 with no os/device: next-modern picks the smallest
        // kept macOS desktop major >= 17 (26); the row pins os macOS.
        let r = Fingerprint::new(Browser::Safari)
            .with_version(17)
            .resolve()
            .unwrap();
        assert_eq!(r.name, "safari_26_macos_desktop");
        assert_eq!(r.fingerprint.os, Some(Os::MacOs));
        assert_eq!(r.fingerprint.device, Some(Device::Desktop));
    }

    #[test]
    fn version_inside_hand_band_picks_hand_row() {
        // 125 sits inside the hand chrome_130 band (0, 130].
        let r = Fingerprint::new(Browser::Chrome)
            .with_version(125)
            .resolve()
            .unwrap();
        assert_eq!(r.name, "chrome_130");
    }

    #[test]
    fn hand_row_wins_over_generated_band_overlap() {
        // Chrome 125 Windows desktop: the hand chrome_130 row's band
        // (0, 130] claims it even though generated chrome windows rows
        // (93, 143) carry different majors. Wire-exact precedence: the
        // query resolves to the hand-written row, never the generated one.
        let r = Fingerprint::new(Browser::Chrome)
            .with_version(125)
            .with_os(Os::Windows)
            .with_device(Device::Desktop)
            .resolve()
            .unwrap();
        assert_eq!(r.name, "chrome_130");
    }

    #[test]
    fn generated_only_identity_resolves_to_registered_ja4() {
        // chrome_148_android_desktop is a kept generated-roster identity
        // with no hand row. It must resolve, and the resolved hello must
        // hash to the roster's registered source JA4 for that identity.
        let registered = GENERATED
            .iter()
            .find(|e| e.name == "chrome_148_android_desktop")
            .expect("roster pins chrome_148_android_desktop");
        let r = Fingerprint::new(Browser::Chrome)
            .with_version(148)
            .with_os(Os::Android)
            .with_device(Device::Desktop)
            .resolve()
            .unwrap();
        assert_eq!(r.name, registered.name);
        assert_eq!(r.fingerprint.version, Some(148));
        assert_eq!(r.ja4(), registered.ja4, "JA4 fidelity for {}", r.name);
    }

    #[test]
    fn error_listing_caps_at_eight_with_total_suffix() {
        let available: Vec<String> = (0..20).map(|i| format!("alt_{i}")).collect();
        let err = FingerprintError::Unknown {
            query: "chrome/999/-/-".to_string(),
            available,
        };
        let msg = err.to_string();
        for i in 0..8 {
            assert!(msg.contains(&format!("alt_{i}")), "missing alt_{i}: {msg}");
        }
        assert!(
            !msg.contains("alt_8"),
            "9th alternative must be hidden: {msg}"
        );
        assert!(msg.ends_with("… and 12 more"), "{msg}");
    }

    #[test]
    fn unresolvable_query_message_is_capped() {
        // Chrome 200 sits above the newest chrome row in both tiers; the
        // 71-name alternatives list must render capped, not verbatim.
        let err = Fingerprint::new(Browser::Chrome)
            .with_version(200)
            .with_os(Os::Windows)
            .with_device(Device::Desktop)
            .resolve()
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("… and "), "truncation suffix missing: {msg}");
        assert!(msg.ends_with(" more"), "{msg}");
    }

    #[test]
    fn hand_band_absorbs_old_versions_generated_refuses_below_oldest() {
        // Chrome/Windows 93 sits inside the hand chrome_130 band (0, 130]:
        // the wire-exact row answers, never the generated single-major band.
        let hand = Fingerprint::new(Browser::Chrome)
            .with_version(93)
            .with_os(Os::Windows)
            .with_device(Device::Desktop)
            .resolve()
            .unwrap();
        assert_eq!(hand.name, "chrome_130");
        assert_eq!(hand.fingerprint.version, Some(93));
        // Firefox has no hand rows; 50 sits below its oldest kept desktop
        // major (125): era mismatch, strict error.
        let err = Fingerprint::new(Browser::Firefox)
            .with_version(50)
            .with_os(Os::Windows)
            .with_device(Device::Desktop)
            .resolve()
            .unwrap_err();
        assert!(matches!(err, FingerprintError::Unknown { .. }));
    }

    #[test]
    fn version_above_every_row_errors_with_available_list() {
        // 200 is above every chrome row in both tiers: strict error.
        let fp = Fingerprint::new(Browser::Chrome).with_version(200);
        let err = fp.resolve().unwrap_err();
        let FingerprintError::Unknown { query, available } = err else {
            panic!("wrong variant")
        };
        assert_eq!(query, "chrome/200/-/-");
        assert!(available.iter().any(|a| a.starts_with("chrome")));
    }

    #[test]
    fn mobile_query_lands_on_mobile_row_via_cross_triple() {
        // Chrome/Android/Phone has no kept rows; the exact triple pass
        // fails and the os drops: any-os chrome phone rows answer,
        // greatest major (no version) = 144.
        let fp = Fingerprint::new(Browser::Chrome)
            .with_os(Os::Android)
            .with_device(Device::Phone);
        let r = fp.resolve().unwrap();
        assert_eq!(r.name, "chrome_144_ios_phone_2");
        assert_eq!(r.fingerprint.version, Some(144));
    }

    #[test]
    fn mobile_versions_below_oldest_refuse_and_between_majors_go_next_modern() {
        // The oldest kept chrome phone major is 133 (iOS phone); 100 is
        // below it: era mismatch even through the os-drop pass.
        let err = Fingerprint::new(Browser::Chrome)
            .with_version(100)
            .with_os(Os::Android)
            .with_device(Device::Phone)
            .resolve()
            .unwrap_err();
        assert!(matches!(err, FingerprintError::Unknown { .. }));
        // 140 sits between the kept phone majors 133 and 143: next-modern
        // serves the smallest kept major >= 140, cross-triple (os dropped).
        let modern = Fingerprint::new(Browser::Chrome)
            .with_version(140)
            .with_os(Os::Android)
            .with_device(Device::Phone)
            .resolve()
            .unwrap();
        assert_eq!(modern.name, "chrome_143_ios_phone");
        assert_eq!(modern.fingerprint.version, Some(140));
    }

    #[test]
    fn ios_versions_resolve_next_modern_to_kept_ios_rows() {
        // Safari/iOS 14: the smallest kept iOS phone major >= 14 is 18;
        // 18 itself stays on the same row.
        let old = Fingerprint::new(Browser::Safari)
            .with_version(14)
            .with_os(Os::Ios)
            .with_device(Device::Phone)
            .resolve()
            .unwrap();
        assert_eq!(old.name, "safari_18_ios_phone");
        let exact = Fingerprint::new(Browser::Safari)
            .with_version(18)
            .with_os(Os::Ios)
            .with_device(Device::Phone)
            .resolve()
            .unwrap();
        assert_eq!(exact.name, "safari_18_ios_phone");
    }

    #[test]
    fn os_dropped_when_exact_triple_absent_but_still_refuses_no_rows() {
        // Safari/Android/Phone has no kept rows; the os drops and any-os
        // Safari phone rows answer (greatest major 26).
        let dropped = Fingerprint::new(Browser::Safari)
            .with_os(Os::Android)
            .with_device(Device::Phone)
            .resolve()
            .unwrap();
        assert_eq!(dropped.name, "safari_26_ios_phone");
        // Brave has no phone rows at all: neither pass finds anything.
        let err = Fingerprint::new(Browser::Brave)
            .with_os(Os::Ios)
            .with_device(Device::Phone)
            .resolve()
            .unwrap_err();
        assert!(matches!(err, FingerprintError::Unknown { .. }));
    }

    #[test]
    fn tablet_queries_resolve_via_generated_rows() {
        // No hand row is a tablet; the generated roster carries Chrome
        // Android/iOS tablet identities. A bare tablet query lands on the
        // newest band (greatest max_version): the iOS tablet major 148.
        let r = Fingerprint::new(Browser::Chrome)
            .with_device(Device::Tablet)
            .resolve()
            .unwrap();
        assert_eq!(r.name, "chrome_148_ios_tablet");
        assert_eq!(r.fingerprint.os, Some(Os::Ios));
        assert_eq!(r.fingerprint.device, Some(Device::Tablet));
        assert_eq!(r.fingerprint.version, Some(148));
    }

    #[test]
    fn every_table_row_targets_existing_profile_fn() {
        // Compile-time completeness: building each row's spec proves the fn exists.
        for entry in table() {
            let _ = (entry.spec)();
        }
    }

    #[test]
    fn firefox_below_oldest_kept_major_refuses() {
        // Firefox 120 sits below the oldest kept firefox desktop major
        // (125): era mismatch — strict error, no substitution.
        let err = Fingerprint::new(Browser::Firefox)
            .with_version(120)
            .resolve()
            .unwrap_err();
        assert!(matches!(err, FingerprintError::Unknown { .. }));
    }

    #[test]
    fn firefox_125_exact_and_126_next_modern() {
        let exact = Fingerprint::new(Browser::Firefox)
            .with_version(125)
            .with_os(Os::Windows)
            .with_device(Device::Desktop)
            .resolve()
            .unwrap();
        assert_eq!(exact.name, "firefox_125_windows_desktop");
        // 126 sits between the kept firefox windows majors 125 and 139.
        let modern = Fingerprint::new(Browser::Firefox)
            .with_version(126)
            .with_os(Os::Windows)
            .with_device(Device::Desktop)
            .resolve()
            .unwrap();
        assert_eq!(modern.name, "firefox_139_windows_desktop");
    }

    #[test]
    fn safari_16_query_hits_safari_16_macos_row() {
        let r = Fingerprint::new(Browser::Safari)
            .with_version(16)
            .resolve()
            .unwrap();
        assert_eq!(r.name, "safari_16_macos_desktop");
    }

    #[test]
    fn available_identities_sorted_and_complete() {
        let names = available_identities();
        assert_eq!(names.len(), table().len());
        assert_eq!(names.len(), HAND_ROWS.len() + GENERATED.len());
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(names.contains(&"chrome_130".to_string()));
        assert!(names.contains(&"edge_106".to_string()));
    }

    #[test]
    fn latest_row_finds_greatest_max_version() {
        // Hand-tier rows win: chrome_130 (wire-exact) beats every
        // generated chrome major, 149 included.
        assert_eq!(latest_row(Browser::Chrome).unwrap().name, "chrome_130");
        assert_eq!(
            latest_row(Browser::Firefox).unwrap().name,
            "firefox_150_android_desktop"
        );
        // Samsung Internet has no hand rows; the generated roster answers.
        assert_eq!(
            latest_row(Browser::SamsungInternet).unwrap().name,
            "samsung_29_android_desktop"
        );
    }

    #[test]
    fn resolved_computes_full_ja4() {
        let r = Fingerprint::new(Browser::Chrome)
            .with_version(130)
            .with_os(Os::Windows)
            .with_device(Device::Desktop)
            .resolve()
            .unwrap();
        let ja4 = r.ja4();
        assert!(ja4.starts_with("t13d"), "{ja4}");
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 3, "A_hash1_hash2");
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);
    }

    #[test]
    fn in_catalog_evidence_marks_generated_rows_live() {
        // Hand-transcribed hellos (chrome_130, edge_106) were captured
        // outside the observed corpus: their JA4s are NOT catalog evidence.
        for fp in [
            Fingerprint::new(Browser::Chrome)
                .with_version(130)
                .with_os(Os::Windows),
            Fingerprint::new(Browser::Edge)
                .with_version(106)
                .with_os(Os::Windows),
        ] {
            let r = fp.resolve().unwrap();
            assert!(!r.in_catalog(), "{} must not be catalog evidence", r.name);
        }
        // Kept generated rows ARE catalog observations (manifest-derived).
        let generated_row = Fingerprint::new(Browser::Firefox)
            .with_version(150)
            .with_os(Os::MacOs)
            .resolve()
            .unwrap();
        assert!(
            generated_row.in_catalog(),
            "{} must be catalog evidence",
            generated_row.name
        );
    }

    #[test]
    fn in_catalog_wiring_matches_contains() {
        // Wiring proof (not hello fidelity): a real CATALOG entry fed
        // through the same contains() call in_catalog() makes.
        use crate::fingerprints::catalog;
        let entry = catalog::CATALOG
            .iter()
            .find(|e| e.application == "chrome")
            .expect("catalog has chrome rows");
        assert!(catalog::contains("chrome", None, entry.ja4));
        // ...and a fabricated JA4 is correctly rejected.
        assert!(!catalog::contains(
            "chrome",
            None,
            "t13d9999zzzz_zzzzzzzzzzzz_zzzzzzzzzzzz"
        ));
    }
}
