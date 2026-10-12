//! Offline JA4 oracle gate over the generated kept roster.
//!
//! Every entry of [`generated::GENERATED`] (69 kept profiles, the
//! `select_roster` subset of the 1825-entry manifest) is built into a
//! `ClientHello` with a fixed-seed RNG (all-`0x5A` fixture, the same
//! pattern as the `profiles/mod.rs` tests), parsed back, and its JA4 is
//! recomputed with the crate's own `full_ja4` codec. The registered
//! `GenEntry.ja4` is the corpus truth (ja4db export); any spec/emitter
//! drift that changes the wire shape fails here. The RNG cannot flip the
//! result: GREASE ids are excluded from every JA4 segment and SNI value /
//! random bytes / padding length are JA4-invisible.
//!
//! Corpus-vs-codec semantics gaps prevent byte-exact `full_ja4` equality
//! for part of the kept roster; each is classified and asserted to its
//! fully verifiable components (failures on anything else):
//!
//! - **padding-in-hello**: `ja4.rs` hash2 excludes padding (`peet.ws`
//!   semantics) but the corpus keeps `0015` (original `FoxIO` rule). When
//!   the built hello carries a padding extension the full hash cannot
//!   match; the corpus-rule hash2 (padding kept) is asserted instead.
//! - **padding-omitted**: the builder's 512-byte target rule drops the
//!   padding extension when the record already reaches the target (the
//!   large ML-KEM-768 key share on Chromium-family specs), while the
//!   corpus counted it. Asserted: A-part with the padding id re-added to
//!   the extension count, hash1, and corpus-rule hash2 with `0015` forced
//!   back into the extension list.
//! - **`ht` ALPN letter** (orthogonal): the corpus renders `http/1.1` as
//!   `ht` (first-two-chars) while `ja4.rs` renders `h1` (first+last); the
//!   A-part counts and every hash are still asserted exactly.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

use leas_tls::SecureRandom;
use leas_tls::crypto::fingerprint::ja3::Ja3Fields;
use leas_tls::crypto::fingerprint::ja4::{full_ja4, hash1, ja4_a};
use leas_tls::hello::parse::parse_hello;
use leas_tls::hello::{BuildParams, build_hello};
use leas_tls::profiles::generated::GENERATED;
use leas_tls::spec::grease::is_grease;

/// Fixed-seed RNG feeding back a fixed byte sequence (verbatim fixture
/// from the `profiles/mod.rs` tests; `AtomicUsize` keeps it `Sync` for
/// the `SecureRandom` supertrait).
struct FixedRandom {
    bytes: Vec<u8>,
    pos: AtomicUsize,
}

impl SecureRandom for FixedRandom {
    fn fill(&self, dest: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        let mut pos = self.pos.load(Ordering::Relaxed);
        for b in dest.iter_mut() {
            *b = *self.bytes.get(pos).ok_or(ring::error::Unspecified)?;
            pos += 1;
        }
        self.pos.store(pos, Ordering::Relaxed);
        Ok(())
    }
}

const SNI: u16 = 0x0000;
const ALPN: u16 = 0x0010;

/// sha256[:12] lowercase hex, byte-identical to `ja4.rs::sha12`.
fn sha12(payload: &str) -> String {
    let digest = Sha256::digest(payload.as_bytes());
    let mut out = String::with_capacity(12);
    for b in &digest[..6] {
        write!(out, "{b:02x}").expect("infallible string write");
    }
    out
}

/// Corpus-rule hash2 (original FoxIO/ja4db semantics): sorted non-GREASE
/// extension ids minus SNI (`0000`) and ALPN (`0010`), padding (`0015`)
/// kept in the list — and forced back in when `force_padding` even if the
/// built hello omitted it (the 512-byte target rule) — then `_` + sig
/// algs in hello order when `with_sigs`.
fn corpus_hash2(f: &Ja3Fields, force_padding: bool, with_sigs: bool) -> String {
    let mut exts: Vec<String> = f
        .extensions
        .iter()
        .copied()
        .filter(|&e| !is_grease(e) && e != SNI && e != ALPN)
        .map(|e| format!("{e:04x}"))
        .collect();
    if force_padding && !exts.iter().any(|e| e == "0015") {
        exts.push("0015".to_string());
    }
    exts.sort_unstable();
    let mut payload = exts.join(",");
    if with_sigs && !f.signature_algorithms.is_empty() {
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

/// A-part equality, allowing the two documented renderings:
/// - the corpus `ht` letter (first-two-chars) vs the codec `h1`
///   (first+last) for `http/1.1`;
/// - `ext_delta` extra extension ids counted by the corpus that the built
///   hello legitimately omitted (the padding extension under the
///   512-byte target rule).
fn a_part_ok(computed: &str, registered: &str, ext_delta: u8) -> bool {
    let letter_ok = |c: &str, r: &str| c == r || (r.ends_with("ht") && c.ends_with("h1"));
    computed.len() == 10
        && registered.len() == 10
        && computed[..4] == registered[..4]
        && computed[4..6] == registered[4..6]
        && computed[6..8]
            .parse::<u8>()
            .ok()
            .zip(registered[6..8].parse::<u8>().ok())
            .is_some_and(|(c, r)| c + ext_delta == r)
        && letter_ok(&computed[8..], &registered[8..])
}

#[test]
fn every_generated_entry_hashes_to_source_ja4() {
    // One ML-KEM-768 keypair serves every spec (the key-share BODY is
    // JA4-invisible; only the group ids count), same as the profiles tests.
    let (mlkem_pk, _) = leas_tls::crypto::mlkem::Mlkem768::generate_keypair();

    let mut full = 0u32;
    let mut padding_in_hello = 0u32;
    let mut padding_omitted = 0u32;
    let mut no_sig = 0u32;
    let mut ht_letter = 0u32;

    for entry in GENERATED {
        let spec = (entry.spec_fn)();
        let rng = FixedRandom {
            bytes: vec![0x5A; 256],
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(
            &spec,
            &BuildParams {
                server_name: "example.org",
                alpn: None, // use the spec's ALPN list
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: Some(mlkem_pk.as_bytes()),
                rng: &rng,
            },
        )
        .unwrap_or_else(|e| panic!("entry {}: build_hello failed: {e}", entry.name));
        let parsed = parse_hello(&hello.handshake_bytes)
            .unwrap_or_else(|e| panic!("entry {}: parse_hello failed: {e}", entry.name));
        let fields = Ja3Fields::from(&parsed);

        if full_ja4(&fields) == entry.ja4 {
            full += 1;
            continue;
        }

        // Not byte-identical: classify the discrepancy against the three
        // documented corpus/codec semantics gaps; anything else is a
        // real roster regression and fails the gate.
        let parts: Vec<&str> = entry.ja4.split('_').collect();
        assert_eq!(
            parts.len(),
            3,
            "entry {}: malformed registered JA4 `{}`",
            entry.name,
            entry.ja4
        );
        let (a_r, h1_r, h2_r) = (parts[0], parts[1], parts[2]);
        let a_c = ja4_a(&fields);
        if a_r.ends_with("ht") && a_c.ends_with("h1") {
            ht_letter += 1;
        }

        assert_eq!(
            hash1(&fields),
            h1_r,
            "entry {}: cipher hash1 mismatch (computed {} vs registered {})",
            entry.name,
            hash1(&fields),
            h1_r
        );

        // hash2 under the corpus rule; first match classifies the entry.
        let (class, ext_delta): (&str, u8) = if corpus_hash2(&fields, false, true) == h2_r {
            ("padding-in-hello", 0)
        } else if corpus_hash2(&fields, true, true) == h2_r {
            ("padding-omitted", 1)
        } else if corpus_hash2(&fields, false, false) == h2_r {
            ("no-sig", 0)
        } else if corpus_hash2(&fields, true, false) == h2_r {
            ("no-sig", 1)
        } else {
            panic!(
                "entry {}: computed full_ja4 {} does not reproduce registered JA4 {} \
                     under any documented semantics",
                entry.name,
                full_ja4(&fields),
                entry.ja4
            );
        };
        match class {
            "padding-in-hello" => padding_in_hello += 1,
            "padding-omitted" => padding_omitted += 1,
            "no-sig" => no_sig += 1,
            _ => unreachable!(),
        }

        assert!(
            a_part_ok(&a_c, a_r, ext_delta),
            "entry {}: A-part mismatch (computed {a_c} vs registered {a_r})",
            entry.name
        );
    }

    let total = GENERATED.len();
    eprintln!(
        "JA4 gate: total={total} full-hash={full} padding-in-hello={padding_in_hello} \
         padding-omitted={padding_omitted} no-sig={no_sig} ht-letter={ht_letter} failures=0"
    );
    assert_eq!(
        full + padding_in_hello + padding_omitted + no_sig,
        u32::try_from(total).expect("roster fits in u32"),
        "classification must cover the whole roster"
    );
    // Kept-roster classification contract (recomputed over the 69 kept
    // entries after the roster reduction; a drift in any class means the
    // emitted roster's semantics changed and the counts are re-derived
    // from the manifest before updating these).
    assert_eq!(total, 69, "kept roster drifted from 69 entries");
    assert_eq!(
        full, 49,
        "full-hash (byte-exact) entries drifted from the kept-roster 49"
    );
    assert_eq!(
        padding_in_hello, 16,
        "padding-in-hello entries drifted from the kept-roster 16"
    );
    assert_eq!(
        padding_omitted, 4,
        "padding-omitted entries drifted from the kept-roster 4"
    );
    // The no-sig class (raw strings without a signature-algorithm segment;
    // 102 across the full 1825-entry manifest) is absent from the kept
    // roster: no kept entry's registered hash2 lacks the sig segment.
    assert_eq!(
        no_sig, 0,
        "no-sig entries appeared in the kept roster; expected none"
    );
    assert_eq!(
        ht_letter, 3,
        "ht-letter entries drifted from the kept-roster 3"
    );
}
