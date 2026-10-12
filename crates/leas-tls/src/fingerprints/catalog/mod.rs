//! Generated real-world JA4 catalog (identity evidence only — never used
//! to synthesize hello bytes).

mod catalog_data;

pub use catalog_data::{CATALOG, CatalogEntry};

/// All catalog entries observed for a browser name (e.g. `"chrome"`),
/// optionally filtered to an exact major version.
///
/// Entries with an unknown browser version (`browser_major == 0`) are only
/// matched by the unversioned query.
#[must_use]
pub fn entries_for(application: &str, version: Option<u16>) -> Vec<&'static CatalogEntry> {
    CATALOG
        .iter()
        .filter(|e| {
            e.application == application && version.is_none_or(|v| v != 0 && e.browser_major == v)
        })
        .collect()
}

/// True when `ja4` was observed in the wild for this browser (+version).
#[must_use]
pub fn contains(application: &str, version: Option<u16>, ja4: &str) -> bool {
    entries_for(application, version)
        .iter()
        .any(|e| e.ja4 == ja4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_nonempty_and_wellformed() {
        assert!(
            CATALOG.len() > 500,
            "catalog suspiciously small: {}",
            CATALOG.len()
        );
        for e in CATALOG.iter().take(100) {
            assert!(e.ja4.starts_with("t1"), "{}", e.ja4);
            assert!(
                e.ja4.split('_').count() == 3 || e.ja4.split('_').count() == 2,
                "unexpected ja4 shape: {}",
                e.ja4
            );
            assert!(!e.application.is_empty());
        }
    }

    #[test]
    fn chrome_entries_exist() {
        assert!(!entries_for("chrome", None).is_empty());
    }

    #[test]
    fn versioned_query_matches_exact_major() {
        let known = CATALOG
            .iter()
            .find(|e| e.application == "chrome" && e.browser_major > 0)
            .expect("catalog has chrome rows with a parsed major");
        let hits = entries_for("chrome", Some(known.browser_major));
        assert!(!hits.is_empty());
        assert!(hits.iter().any(|e| std::ptr::eq(*e, known)));
        for e in &hits {
            assert_eq!(e.browser_major, known.browser_major);
        }
    }

    #[test]
    fn zero_major_excluded_from_versioned_included_in_unversioned() {
        if let Some(e) = CATALOG.iter().find(|e| e.browser_major == 0) {
            let app = e.application;
            assert!(entries_for(app, Some(0)).is_empty());
            assert!(
                entries_for(app, Some(u16::MAX))
                    .iter()
                    .all(|h| h.browser_major != 0)
            );
            assert!(entries_for(app, None).iter().any(|h| std::ptr::eq(*h, e)));
        }
    }
}
