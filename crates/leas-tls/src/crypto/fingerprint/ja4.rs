//! JA4 fingerprint encoder (offline).
//!
//! Two variants exist in the wild and this crate implements both
//! explicitly rather than picking one silently:
//!
//! - [`Ja4Variant::Foxio`] (the default): the published `FoxIO` scheme —
//!   `hash2` excludes only SNI (`0000`) and ALPN (`0010`), so padding
//!   (`0015`) stays in the hashed list, and GREASE is ignored everywhere,
//!   including the signature-algorithm segment.
//! - [`Ja4Variant::PeetWs`]: the `tls.peet.ws` rendering the crate was
//!   originally pinned against — `hash2` additionally excludes padding and
//!   appends sig-algs unfiltered.
//!
//! The two disagree on `0x0015`, which is why the variant is a parameter and
//! not a comment: the local `ja4db` corpus keeps padding, the old pinned
//! vector did not.
//!
//! A-part `{t}{version}{d|i}{cipher_count}{ext_count}{alpn}`:
//!
//! - `version` comes from `supported_versions` when present (highest
//!   non-GREASE value), else from the legacy version field.
//! - `d`/`i` is SNI presence.
//! - counts EXCLUDE GREASE but INCLUDE SNI, ALPN and padding, clamped at 99.
//! - ALPN renders the first protocol's first+last ASCII-alphanumeric
//!   character; when either byte is not alphanumeric the first and last
//!   characters of the two bytes' hex rendering are used instead.
//!
//! Both hashes render `000000000000` for an empty list instead of hashing
//! the empty string, per the spec.

use sha2::{Digest, Sha256};

use crate::spec::grease::is_grease;

use super::ja3::Ja3Fields;

/// Extension ids excluded from the `hash2` list under `PeetWs` semantics
/// (but still counted in the A-part).
const PEET_HASH2_EXCLUDED: [u16; 3] = [0x0000, 0x0010, 0x0015];
/// Extension ids excluded from `hash2` under `FoxIO` semantics.
const FOXIO_HASH2_EXCLUDED: [u16; 2] = [0x0000, 0x0010];
/// Sentinel for an empty hashed list.
const EMPTY_HASH: &str = "000000000000";

/// Which JA4 rendering to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ja4Variant {
    /// The published `FoxIO` scheme (padding kept, GREASE ignored in sig-algs).
    #[default]
    Foxio,
    /// The `tls.peet.ws` rendering this crate was first pinned against.
    PeetWs,
}

/// The JA4-A part: `t13d{cipher_count:02}{ext_count:02}{alpn}` shape.
#[must_use]
pub fn ja4_a(f: &Ja3Fields) -> String {
    // Clamped at 99 per the FoxIO spec (`99` renders as-is): a >99-element
    // list must not overflow into a malformed 3-digit segment.
    let cipher_count = f.ciphers.iter().filter(|&&c| !is_grease(c)).count().min(99);
    let ext_count = f
        .extensions
        .iter()
        .filter(|&&e| !is_grease(e))
        .count()
        .min(99);
    let version = version_segment(f);
    let sni = if f.sni { 'd' } else { 'i' };
    let alpn = alpn_segment(&f.alpn);
    format!("t{version}{sni}{cipher_count:02}{ext_count:02}{alpn}")
}

/// `13`/`12`/`11`/`10`/`s3`/`s2` from the highest offered TLS version, or
/// from the legacy field when `supported_versions` is absent.
fn version_segment(f: &Ja3Fields) -> &'static str {
    let highest = f
        .supported_versions
        .iter()
        .copied()
        .filter(|&v| !is_grease(v))
        .max()
        .unwrap_or(f.version);
    match highest {
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        // TLS 1.3 and any later 0x03xx minor version.
        0x0304..=0x03ff => "13",
        _ => "00",
    }
}

/// First ALPN value → its two-character A-part segment.
fn alpn_segment(alpn: &[String]) -> String {
    alpn.first().map_or_else(
        || "00".to_string(),
        |first| alpn_segment_bytes(first.as_bytes()),
    )
}

/// Byte-level ALPN segment rule (also used by tests with non-UTF-8 bytes).
fn alpn_segment_bytes(bytes: &[u8]) -> String {
    match (bytes.first(), bytes.last()) {
        (None, _) | (_, None) => "00".to_string(),
        (Some(&a), Some(&b)) => {
            if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() {
                format!("{}{}", a as char, b as char)
            } else {
                // Both bytes rendered as hex, then its first and last char.
                let hex = format!("{a:02x}{b:02x}");
                let mut chars = hex.chars();
                let first_c = chars.next().unwrap_or('0');
                let last_c = chars.next_back().unwrap_or('0');
                format!("{first_c}{last_c}")
            }
        }
    }
}

/// hash1: sha256[:12] over sorted non-GREASE ciphers (4-hex, comma-joined).
#[must_use]
pub fn hash1(f: &Ja3Fields) -> String {
    let mut ciphers: Vec<String> = f
        .ciphers
        .iter()
        .filter(|&&c| !is_grease(c))
        .map(|c| format!("{c:04x}"))
        .collect();
    if ciphers.is_empty() {
        return EMPTY_HASH.to_string();
    }
    ciphers.sort_unstable();
    sha12(&ciphers.join(","))
}

/// hash2 under the default (`FoxIO`) semantics.
#[must_use]
pub fn hash2(f: &Ja3Fields) -> String {
    hash2_variant(f, Ja4Variant::Foxio)
}

/// hash2: sha256[:12] over sorted extensions (minus the variant's
/// exclusions and GREASE) + `_` + sig algs in hello order.
#[must_use]
pub fn hash2_variant(f: &Ja3Fields, variant: Ja4Variant) -> String {
    let excluded: &[u16] = match variant {
        Ja4Variant::Foxio => &FOXIO_HASH2_EXCLUDED,
        Ja4Variant::PeetWs => &PEET_HASH2_EXCLUDED,
    };
    let mut exts: Vec<String> = f
        .extensions
        .iter()
        .copied()
        .filter(|&e| !is_grease(e) && !excluded.contains(&e))
        .map(|e| format!("{e:04x}"))
        .collect();
    let sigs: Vec<String> = match variant {
        Ja4Variant::Foxio => f
            .signature_algorithms
            .iter()
            .copied()
            .filter(|&s| !is_grease(s))
            .map(|s| format!("{s:04x}"))
            .collect(),
        Ja4Variant::PeetWs => f
            .signature_algorithms
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect(),
    };
    if exts.is_empty() && sigs.is_empty() {
        return EMPTY_HASH.to_string();
    }
    exts.sort_unstable();
    let mut payload = exts.join(",");
    if !sigs.is_empty() {
        payload.push('_');
        payload.push_str(&sigs.join(","));
    }
    sha12(&payload)
}

/// The full JA4 fingerprint under the default (`FoxIO`) semantics.
#[must_use]
pub fn full_ja4(f: &Ja3Fields) -> String {
    full_ja4_variant(f, Ja4Variant::Foxio)
}

/// The full JA4 fingerprint under an explicit variant.
#[must_use]
pub fn full_ja4_variant(f: &Ja3Fields, variant: Ja4Variant) -> String {
    format!("{}_{}_{}", ja4_a(f), hash1(f), hash2_variant(f, variant))
}

fn sha12(payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..6])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::fingerprint::ja3::Ja3Fields;

    /// Ground truth: the `ClientHello` of a `curl` request, reported by
    /// `tls.peet.ws`. Lists verbatim from its `ja4_r` rendering; extension
    /// order reconstructed from its ja3 field.
    fn peet_vector() -> Ja3Fields {
        let ciphers: Vec<u16> = [
            "002f", "0033", "0035", "0039", "003c", "003d", "0067", "006b", "009c", "009d", "009e",
            "009f", "00ff", "1301", "1302", "1303", "c009", "c00a", "c013", "c014", "c023", "c024",
            "c027", "c028", "c02b", "c02c", "c02f", "c030", "cca8", "cca9", "ccaa",
        ]
        .iter()
        .map(|s| u16::from_str_radix(s, 16).unwrap())
        .collect();
        let extensions: Vec<u16> = [
            0x0000, 0x000b, 0x000a, 0x3374, 0x0010, 0x0016, 0x0017, 0x0031, 0x000d, 0x002b, 0x002d,
            0x0033, 0x0015,
        ]
        .to_vec();
        let signature_algorithms: Vec<u16> = [
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602,
        ]
        .to_vec();
        Ja3Fields {
            version: 771,
            ciphers,
            extensions,
            curves: vec![29, 23, 30, 25, 24, 256, 257, 258, 259, 260],
            point_formats: vec![0, 1, 2],
            signature_algorithms,
            alpn: vec!["h2".into()],
            supported_versions: vec![0x0304, 0x0303],
            sni: true,
        }
    }

    #[test]
    fn peet_variant_reproduces_the_pinned_vector() {
        assert_eq!(
            full_ja4_variant(&peet_vector(), Ja4Variant::PeetWs),
            "t13d3113h2_e8f1e7e78f70_db572f7c111e"
        );
    }

    /// The published `FoxIO` example, lists verbatim from the spec
    /// (`t13d1516h2_8daaf6152771_e5627efa2ab1`). It keeps padding
    /// (`0015`) in hash2 — the axis where the two variants diverge.
    fn foxio_vector() -> Ja3Fields {
        let ciphers: Vec<u16> = [
            "1301", "1302", "1303", "c02b", "c02f", "c02c", "c030", "cca9", "cca8", "c013", "c014",
            "009c", "009d", "002f", "0035",
        ]
        .iter()
        .map(|s| u16::from_str_radix(s, 16).unwrap())
        .collect();
        let extensions: Vec<u16> = [
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ]
        .to_vec();
        let signature_algorithms: Vec<u16> = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]
        .to_vec();
        Ja3Fields {
            version: 771,
            ciphers,
            extensions,
            curves: vec![],
            point_formats: vec![],
            signature_algorithms,
            alpn: vec!["h2".into()],
            supported_versions: vec![0x0304, 0x0303],
            sni: true,
        }
    }

    #[test]
    fn foxio_variant_matches_the_published_example() {
        assert_eq!(
            full_ja4(&foxio_vector()),
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        );
        // Same hello under peet semantics drops padding → a different hash2.
        assert_eq!(
            hash2_variant(&foxio_vector(), Ja4Variant::PeetWs),
            "f37e75b10bcc"
        );
    }

    #[test]
    fn foxio_spec_example_without_sig_algs() {
        let mut f = foxio_vector();
        f.signature_algorithms.clear();
        assert_eq!(hash2(&f), "6d807ffa2a79");
    }

    #[test]
    fn ext_count_includes_sni_alpn_padding_but_hash_excludes_them() {
        assert_eq!(ja4_a(&peet_vector()), "t13d3113h2");
    }

    #[test]
    fn grease_removed_from_counts_and_hashes() {
        let mut f = foxio_vector();
        f.ciphers.insert(0, 0xCACA);
        f.extensions.insert(0, 0x0A0A);
        f.signature_algorithms.insert(0, 0xDADA);
        f.supported_versions.insert(0, 0x3A3A);
        assert_eq!(ja4_a(&f), "t13d1516h2");
        assert_eq!(hash1(&f), "8daaf6152771");
        assert_eq!(hash2(&f), "e5627efa2ab1");
        assert_eq!(full_ja4(&f), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn alpn_rendering_follows_the_spec_table() {
        // (input, expected segment) rows from the FoxIO ALPN table.
        let rows: [(&[u8], &str); 8] = [
            (b"h2", "h2"),
            (b"http/1.1", "h1"),
            (&[0xAB], "ab"),
            (&[0xAB, 0xCD], "ad"),
            (&[0x20, 0x61], "21"),
            (&[0x30, 0xAB], "3b"),
            (&[0x61, 0x20], "60"),
            (b"a", "aa"),
        ];
        for (bytes, want) in rows {
            assert_eq!(
                alpn_segment_bytes(bytes),
                want,
                "ALPN {bytes:?} must render {want}"
            );
        }
        let mut f = peet_vector();
        f.alpn.clear();
        assert!(ja4_a(&f).ends_with("00"));
    }

    #[test]
    fn version_and_sni_segments_come_from_the_hello() {
        let mut f = peet_vector();
        f.supported_versions = vec![0x0303];
        assert!(ja4_a(&f).starts_with("t12d"));
        f.supported_versions.clear();
        f.version = 0x0303;
        assert!(ja4_a(&f).starts_with("t12d"));
        f.sni = false;
        assert!(ja4_a(&f).starts_with("t12i"));
    }

    #[test]
    fn empty_lists_render_the_sentinel() {
        let f = Ja3Fields::default();
        assert_eq!(hash1(&f), EMPTY_HASH);
        assert_eq!(hash2(&f), EMPTY_HASH);
    }

    #[test]
    fn counts_clamp_at_99() {
        let mut f = peet_vector();
        f.ciphers.extend(std::iter::repeat_n(0x009c, 80));
        f.extensions.extend(std::iter::repeat_n(0x000b, 100));
        let a = ja4_a(&f);
        let counts = &a[4..8]; // after `t13d`
        assert_eq!(&counts[..2], "99");
        assert_eq!(&counts[2..], "99");
    }
}
