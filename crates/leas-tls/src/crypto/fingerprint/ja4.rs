//! JA4 fingerprint encoder (final `FoxIO` scheme, offline).
//!
//! Validated byte-for-byte against a live `tls.peet.ws` capture (see
//! tests). Semantics:
//!
//! - A-part `{t|q}{version}{d|i}{cipher_count}{ext_count}{alpn}`: counts
//!   EXCLUDE GREASE entirely but INCLUDE SNI (`0000`), ALPN (`0010`) and
//!   padding (`0015`). ALPN renders first protocol's first+last char
//!   (`h2`, `http/1.1` → `h1`), `00` when absent, `99` when non-ASCII.
//! - hash1: sha256 of sorted non-GREASE cipher ids (lowercase 4-hex,
//!   comma-joined), truncated to 12 hex chars.
//! - hash2: sha256 of sorted non-GREASE extension ids EXCLUDING SNI,
//!   ALPN and padding, joined `,`, then `_` then sig-alg ids in HELLO
//!   ORDER joined `,`; truncated to 12 hex chars. (Padding exclusion =
//!   peet.ws semantics; pinned by the known-vector test.)

use sha2::{Digest, Sha256};

use crate::spec::grease::is_grease;

use super::ja3::Ja3Fields;

/// Extension ids excluded from the hash2 list (but still counted).
const HASH2_EXCLUDED: [u16; 3] = [0x0000, 0x0010, 0x0015];

/// The JA4-A part: `t13d{cipher_count:02}{ext_count:02}{alpn}` shape.
///
/// The version segment is hardcoded `t13d`: every profile in this crate
/// offers TLS 1.3 via `supported_versions`.
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
    let alpn = match f.alpn.first() {
        None => "00".to_string(),
        Some(p) if p.bytes().all(|b| b.is_ascii()) => {
            let bytes = p.as_bytes();
            if bytes.len() > 2 {
                format!("{}{}", bytes[0] as char, bytes[bytes.len() - 1] as char)
            } else {
                p.clone()
            }
        }
        Some(_) => "99".to_string(),
    };
    format!("t13d{cipher_count:02}{ext_count:02}{alpn}")
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
    ciphers.sort_unstable();
    sha12(&ciphers.join(","))
}

/// hash2: sha256[:12] over sorted extensions (minus SNI/ALPN/padding/GREASE)
/// + `_` + sig algs in hello order.
#[must_use]
pub fn hash2(f: &Ja3Fields) -> String {
    let mut exts: Vec<String> = f
        .extensions
        .iter()
        .copied()
        .filter(|&e| !is_grease(e) && !HASH2_EXCLUDED.contains(&e))
        .map(|e| format!("{e:04x}"))
        .collect();
    exts.sort_unstable();
    let mut payload = exts.join(",");
    if !f.signature_algorithms.is_empty() {
        payload.push('_');
        payload.push_str(
            &f.signature_algorithms
                .iter()
                .map(|s| format!("{s:04x}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    sha12(&payload)
}

/// The full JA4 fingerprint: `{ja4_a}_{hash1}_{hash2}`.
#[must_use]
pub fn full_ja4(f: &Ja3Fields) -> String {
    format!("{}_{}_{}", ja4_a(f), hash1(f), hash2(f))
}

fn sha12(payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(12);
    for b in &digest[..6] {
        use core::fmt::Write as _;
        out.write_fmt(format_args!("{b:02x}"))
            .expect("string write");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::fingerprint::ja3::Ja3Fields;

    /// Ground truth: the `ClientHello` of a `curl` request, reported by
    /// `tls.peet.ws` (`t13d3113h2_e8f1e7e78f70_db572f7c111e`). Lists verbatim from its
    /// `ja4_r` rendering; extension order reconstructed from its ja3 field.
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
        }
    }

    #[test]
    fn full_ja4_peet_ws_known_vector() {
        let f = peet_vector();
        assert_eq!(full_ja4(&f), "t13d3113h2_e8f1e7e78f70_db572f7c111e");
    }

    #[test]
    fn ext_count_includes_sni_alpn_padding_but_hash_excludes_them() {
        // 13 extensions counted (incl. 0000/0010/0015); hash2 list excludes them.
        assert_eq!(ja4_a(&peet_vector()), "t13d3113h2");
    }

    #[test]
    fn grease_removed_from_counts_and_hashes() {
        let mut f = peet_vector();
        f.ciphers.insert(0, 0xCACA);
        f.extensions.insert(0, 0x0A0A);
        assert_eq!(full_ja4(&f), "t13d3113h2_e8f1e7e78f70_db572f7c111e");
    }

    #[test]
    fn alpn_short_form_and_none() {
        let mut f = peet_vector();
        f.alpn = vec!["http/1.1".into()];
        assert!(ja4_a(&f).ends_with("h1"));
        f.alpn.clear();
        assert!(ja4_a(&f).ends_with("00"));
    }

    #[test]
    fn no_sig_algs_drops_trailing_segment() {
        let mut f = peet_vector();
        f.signature_algorithms.clear();
        // Ext-only payload: sorted non-GREASE extensions minus SNI/ALPN/
        // padding, comma-joined, NO sig segment and no trailing underscore:
        // `000a,000b,000d,0016,0017,002b,002d,0031,0033,3374`
        assert_eq!(hash2(&f), "619e7cdd0224");
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
