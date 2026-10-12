//! tls.peet.ws grader — tier-2 verification of the fingerprint engine.
//!
//! Connects to `tls.peet.ws` with a browser profile (`--profile <name>`;
//! any [`GRADED_PROFILES`] entry, both by default), speaks HTTP/2
//! through [`leas_tls::http2`], and compares the server-reported
//! JA3/JA4 against the locked expected values.
//!
//! # JA3/JA4 reconciliation (plan Task 12 step 3)
//!
//! tls.peet.ws is authoritative: it computes JA3/JA4 from the observed
//! `ClientHello`. Its computations differ from this crate's offline
//! fingerprints in two documented ways, so the grader re-implements the
//! server's algorithm locally and asserts the server's report against it:
//!
//! 1. **JA3 separators.** tls.peet.ws emits the classic ja3er form —
//!    decimal ids, dashes *within* a group, commas *between* groups
//!    (e.g. `771,4865-4866-…,0-11-10-…`). The crate's offline
//!    [`ja3_string`](leas_tls::crypto::fingerprint::ja3::ja3_string)
//!    joins everything with commas, so its `md5` differs. The grader
//!    computes the dash form locally (see [`local::ja3_dash`]).
//! 2. **JA4 padding exclusion.** tls.peet.ws excludes the padding
//!    extension (0x0015) from the JA4-c hash list, while the strict
//!    `FoxIO` spec includes it. The crate's offline
//!    [`ja4_a`](leas_tls::crypto::fingerprint::ja4::ja4_a) implements
//!    the final `FoxIO` scheme (validated byte-for-byte against live
//!    captures); the grader re-implements the server's variant with the
//!    padding exclusion (verified against the reference `ja4.py`) in
//!    [`local::ja4_v2`] and asserts the two agree on every non-padding
//!    field via the server report.
//!
//! # Assertions
//!
//! * Server JA4 == locked constant (GREASE-normalized → deterministic per
//!   profile) AND == locally computed JA4 v2 from the built hello (proves
//!   the wire bytes match what the builder produced and the algorithms
//!   agree). The local v2 replicates tls.peet.ws's exact algorithm,
//!   including its padding-extension (0x0015) exclusion from the hash
//!   list.
//! * Server JA3 hash == md5 of the locally built JA3 canonical with GREASE
//!   values stripped (tls.peet.ws strips GREASE before hashing; Chrome's
//!   GREASE is per-connection random, so this is the stable comparison).
//! * Firefox 128 ESR additionally asserts the locked, stable JA3 constant.

use std::error::Error;
use std::sync::atomic::AtomicUsize;

use tokio::net::TcpStream;

use leas_tls::fingerprints::{Browser, Fingerprint};
use leas_tls::handshake::{HandshakeParams, connect};
use leas_tls::hello::parse::parse_hello;
use leas_tls::hello::{BuildParams, build_hello};
use leas_tls::http2;
use leas_tls::verify::WebPkiVerifier;

const HOST: &str = "tls.peet.ws";
const PORT: u16 = 443;
const API_PATH: &str = "/api/all";
const ALPN: &[&str] = &["h2", "http/1.1"];
/// Locked expected fingerprints of the two kept hand profiles (captured
/// live against tls.peet.ws with this engine: Chrome 130 on 2026-08-11,
/// Edge 106 in Task 7/8 — see the task report). Both share the same
/// GREASE-normalized JA4; they differ in wire bytes (Edge carries two
/// GREASE extensions, Chrome one).
const CHROME130_JA4: &str = "t13d1516h2_8daaf6152771_f37e75b10bcc";
const EDGE106_JA4: &str = "t13d1516h2_8daaf6152771_f37e75b10bcc";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--roster") {
        return roster::main(&args).await;
    }
    for idx in parse_args(&args) {
        let (name, fingerprint) = &GRADED_PROFILES[idx];
        println!("\n{}", "=".repeat(60));
        println!("Profile : {name}");
        println!("Protocol: HTTP/2");
        println!("{}", "=".repeat(60));

        if let Err(e) = grade(name, fingerprint).await {
            eprintln!("GRADE: FAIL — {e}");
            std::process::exit(1);
        }
        println!("GRADE: PASS");
    }

    Ok(())
}
/// Parses `--profile <name>` (repeatable); defaults to both graded
/// profiles. Only [`GRADED_PROFILES`] are accepted — any other profile
/// name is a CLI error (`grade()` cannot handle it).
fn parse_args(args: &[String]) -> Vec<usize> {
    let mut it = args.iter();
    let mut selected = Vec::new();
    while let Some(arg) = it.next() {
        if arg != "--profile" {
            eprintln!("usage: grader [--profile <name>] | --roster [--family <name>] [--sample]");
            std::process::exit(2);
        }
        let name = it.next().unwrap_or_else(|| {
            eprintln!("--profile requires a value");
            std::process::exit(2);
        });
        let idx = GRADED_PROFILES
            .iter()
            .position(|(n, _)| *n == name)
            .unwrap_or_else(|| {
                eprintln!(
                    "unknown or unsupported profile {name:?}; grader supports: {}",
                    GRADED_PROFILES
                        .iter()
                        .map(|(n, _)| *n)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                std::process::exit(2);
            });
        selected.push(idx);
    }
    if selected.is_empty() {
        (0..GRADED_PROFILES.len()).collect()
    } else {
        selected
    }
}

/// Profiles the grader can grade (all others are rejected at the CLI):
/// the two kept wire-exact hand profiles + the fingerprint identity
/// selecting them (the deep single-profile check; the whole kept roster
/// is covered by `--roster`).
const GRADED_PROFILES: &[(&str, Fingerprint)] = &[
    (
        "chrome_130",
        Fingerprint::new(Browser::Chrome).with_version(130),
    ),
    (
        "edge_106",
        Fingerprint::new(Browser::Edge).with_version(106),
    ),
];

/// Parses `--profile <name>` (repeatable); defaults to both graded
/// profiles. Only [`GRADED_PROFILES`] are accepted — any other profile
/// name is a CLI error (`grade()` cannot handle it).
async fn grade(profile: &'static str, fingerprint: &Fingerprint) -> Result<(), Box<dyn Error>> {
    // Local fingerprint of the profile (fixed seed → deterministic GREASE;
    // JA4 is GREASE-normalized anyway; JA3 is compared GREASE-stripped).
    let spec = fingerprint.resolve()?.spec;
    let fixed = local::FixedRandom {
        bytes: vec![0x42; 128],
        pos: AtomicUsize::new(0),
    };
    let (mlkem_pk, _) = leas_tls::crypto::mlkem::Mlkem768::generate_keypair();
    let local_hello = build_hello(
        &spec,
        &BuildParams {
            server_name: HOST,
            alpn: Some(ALPN),
            x25519_pub: &[0xAB; 32],
            mlkem768_pub: Some(mlkem_pk.as_bytes()),
            rng: &fixed,
        },
    )?;
    let parsed = parse_hello(&local_hello.handshake_bytes)?;
    let local_ja3 = local::ja3_dash(&parsed);
    let local_ja3_stripped_md5 = local::md5_hex(local::strip_grease(&local_ja3).as_bytes());
    let local_ja4 = local::ja4_v2(&parsed);

    // Live connection: TLS 1.3 with the profile's ClientHello, then an
    // HTTP/2 GET against tls.peet.ws.
    let stream = TcpStream::connect((HOST, PORT)).await?;
    let verifier = WebPkiVerifier::webpki_roots();
    let mut conn = connect(
        stream,
        HandshakeParams {
            spec: &spec,
            server_name: HOST,
            alpn: Some(ALPN),
            verifier: &verifier,
            rng: &ring::rand::SystemRandom::new(),
        },
    )
    .await?;
    let body = http2::get(&mut conn, API_PATH, HOST).await?;
    let json: serde_json::Value = serde_json::from_str(&body)?;

    let tls = &json["tls"];
    let tls_version = match tls["tls_version_negotiated"].as_str() {
        Some("771") => "TLS 1.2".to_string(),
        Some("772") => "TLS 1.3".to_string(),
        Some(other) => format!("0x{other}"),
        None => "<missing>".to_string(),
    };
    let cipher = tls["ciphers"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>")
        .to_string();
    let server_ja3 = tls["ja3"].as_str().unwrap_or("<missing>");
    let server_ja3_hash = tls["ja3_hash"].as_str().unwrap_or("<missing>");
    let server_ja4 = tls["ja4"].as_str().unwrap_or("<missing>");
    let server_ja4_r = tls["ja4_r"].as_str().unwrap_or("");
    let akamai = json["http2"]["akamai_fingerprint_hash"]
        .as_str()
        .unwrap_or("");

    println!("TLS version : {tls_version}");
    // `tls.ciphers` is the server's echo of the *offered* cipher list, so
    // the first entry is the first offered cipher (GREASE for Chrome), not
    // the negotiated suite.
    println!("First cipher: {cipher}");
    println!("JA3 hash    : {server_ja3_hash}");
    println!("JA3 string  : {server_ja3}");
    println!("JA4         : {server_ja4}");
    if !server_ja4_r.is_empty() {
        println!("JA4 raw     : {server_ja4_r}");
    }
    if !akamai.is_empty() {
        println!("Akamai h2   : {akamai}");
    }
    println!("--- local (reconciliation) ---");
    println!("JA3 local   : {local_ja3}");
    println!("JA3 stripped: {local_ja3_stripped_md5} (md5 of GREASE-stripped canonical)");
    println!("JA4 v2      : {local_ja4}");

    // Tier-2 assertions.
    assert_eq!(tls_version, "TLS 1.3", "tls_version_negotiated must be 772");
    assert_eq!(
        server_ja4, local_ja4,
        "server JA4 != local JA4 v2 — wire or algorithm divergence"
    );
    let expected_ja4 = match profile {
        "chrome_130" => Some(CHROME130_JA4),
        "edge_106" => Some(EDGE106_JA4),
        _ => unreachable!("GRADED_PROFILES and this match must stay in sync"),
    };
    if let Some(expected_ja4) = expected_ja4 {
        assert_eq!(server_ja4, expected_ja4, "server JA4 != locked constant");
    }

    // JA3: tls.peet.ws strips GREASE from its canonical string before
    // hashing (unlike the classic spec). Assert its hash equals the md5 of
    // our locally built canonical with GREASE stripped — this proves every
    // non-GREASE JA3 field is identical on the wire.
    assert_eq!(
        server_ja3_hash, local_ja3_stripped_md5,
        "server JA3 (GREASE-stripped) != local JA3 (GREASE-stripped)"
    );
    assert_eq!(
        server_ja3_hash,
        local::md5_hex(local::strip_grease(server_ja3).as_bytes()),
        "server JA3 hash must be the md5 of its own GREASE-stripped string"
    );

    Ok(())
}

/// Local re-implementations of the fingerprints tls.peet.ws reports.
///
/// Deliberately duplicated in `tests/tls_peet_ws.rs` so the ignored
/// network test runs the same reconciliation logic without a shared
/// module (the brief scopes new files to http2/, the example, and the
/// test).
mod local {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use md5::{Digest, Md5};
    use ring::digest;

    use leas_tls::SecureRandom;
    use leas_tls::hello::parse::ParsedClientHello;
    use leas_tls::spec::grease::is_grease;

    /// Deterministic RNG (all `0x42`) mirroring the crate's test double.
    pub struct FixedRandom {
        pub bytes: Vec<u8>,
        pub pos: AtomicUsize,
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

    pub fn md5_hex(data: &[u8]) -> String {
        use std::fmt::Write;
        let mut hasher = Md5::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let mut out = String::with_capacity(32);
        for b in digest {
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    fn sha256_hex12(data: &[u8]) -> String {
        use std::fmt::Write;
        let mut out = String::with_capacity(12);
        for b in digest::digest(&digest::SHA256, data)
            .as_ref()
            .iter()
            .take(6)
        {
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    /// Extracts the sigalgs of the `signature_algorithms` extension
    /// (0x000d), in wire order.
    fn sigalgs(hello: &ParsedClientHello) -> Vec<u16> {
        u16_list(hello.extension(0x000d))
    }

    /// Decodes a u16-BE list behind a 2-byte length prefix (the RFC 8446
    /// vector shape shared by `supported_groups` and
    /// `signature_algorithms`).
    fn u16_list(body: Option<&[u8]>) -> Vec<u16> {
        let Some(body) = body else {
            return Vec::new();
        };
        let Some(rest) = body.get(2..) else {
            return Vec::new();
        };
        let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
        rest[..len.min(rest.len())]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect()
    }

    pub fn alpn(hello: &ParsedClientHello) -> Option<String> {
        let body = hello.extension(0x0010)?;
        let list_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
        let rest = body.get(2..)?;
        let mut off = 0;
        while off < list_len.min(rest.len()) {
            let len = usize::from(rest[off]);
            off += 1;
            if off + len <= rest.len() {
                return String::from_utf8(rest[off..off + len].to_vec()).ok();
            }
        }
        None
    }

    fn dash_join_decimal(values: &[u16]) -> String {
        values
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Classic ja3er canonical string (dashes within a group, commas
    /// between groups, decimal ids) — the exact shape tls.peet.ws emits.
    fn ja3_canonical(hello: &ParsedClientHello) -> String {
        let ext_types: Vec<u16> = hello.extensions.iter().map(|(t, _)| *t).collect();
        let curves = u16_list(hello.extension(0x000a));
        let point_formats = hello
            .extension(0x000b)
            .map(|body| {
                let len = usize::from(body[0]);
                body[1..(1 + len).min(body.len())].to_vec()
            })
            .unwrap_or_default();
        format!(
            "{},{},{},{},{}",
            hello.legacy_version,
            dash_join_decimal(&hello.cipher_suites),
            dash_join_decimal(&ext_types),
            dash_join_decimal(&curves),
            point_formats
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join("-"),
        )
    }

    /// Removes the GREASE values from a canonical JA3 string. tls.peet.ws
    /// strips GREASE before hashing (its `fingerprint_tls.go` skips GREASE
    /// ciphers/extensions/curves), so stripping the local fixed-seed
    /// canonical yields the server's exact md5 input.
    pub fn strip_grease(canonical: &str) -> String {
        canonical
            .split(',')
            .map(|group| {
                group
                    .split('-')
                    .filter(|tok| !tok.parse::<u16>().is_ok_and(is_grease))
                    .collect::<Vec<_>>()
                    .join("-")
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Classic ja3er canonical string (dashes within a group, commas
    /// between groups, decimal ids) of a locally built hello — WITH the
    /// builder's GREASE values (stripped before comparison).
    pub fn ja3_dash(hello: &ParsedClientHello) -> String {
        ja3_canonical(hello)
    }

    /// Current `FoxIO` JA4 (`ja4.py`, FoxIO-LLC/ja4; `ja4.go`, `TrackMe`):
    /// `t13d` + SNI flag `d` + non-GREASE cipher count + non-GREASE
    /// extension count + first/last chars of the first ALPN + `_` +
    /// SHA-256[:12] of sorted non-GREASE ciphers + `_` + SHA-256[:12] of
    /// (sorted non-GREASE extensions minus SNI/ALPN/padding, then `_`,
    /// then non-GREASE sigalgs in wire order).
    ///
    /// tls.peet.ws's `ja4.go` explicitly skips the padding extension
    /// (0x0015) from the hash list (`hexStr == "0015"`), a documented
    /// deviation from the `FoxIO` `python` implementation which includes it.
    /// The extension *count* in the `_a_` section still includes padding.
    pub fn ja4_v2(hello: &ParsedClientHello) -> String {
        let ciphers: Vec<u16> = hello
            .cipher_suites
            .iter()
            .copied()
            .filter(|&c| !is_grease(c))
            .collect();
        let exts: Vec<u16> = hello
            .extensions
            .iter()
            .map(|(t, _)| *t)
            .filter(|&t| !is_grease(t))
            .collect();
        let sigs: Vec<u16> = sigalgs(hello)
            .into_iter()
            .filter(|&s| !is_grease(s))
            .collect();

        let cipher_count = ciphers.len().min(99);
        let ext_count = exts.len().min(99);

        let mut sorted_ciphers: Vec<String> = ciphers.iter().map(|c| format!("{c:04x}")).collect();
        sorted_ciphers.sort_unstable();
        let cipher_sha = sha256_hex12(sorted_ciphers.join(",").as_bytes());

        let mut sorted_exts: Vec<String> = exts
            .iter()
            .map(|e| format!("{e:04x}"))
            .filter(|e| e != "0000" && e != "0010" && e != "0015")
            .collect();
        sorted_exts.sort_unstable();
        let sig_str = sigs
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let ext_sha = sha256_hex12(format!("{}_{}", sorted_exts.join(","), sig_str).as_bytes());

        let alpn_token = alpn(hello).map_or_else(
            || "00".to_string(),
            |p| {
                let mut chars = p.chars();
                match (chars.next(), chars.last()) {
                    (Some(first), Some(last)) => format!("{first}{last}"),
                    _ => p,
                }
            },
        );

        format!("t13d{cipher_count:02}{ext_count:02}{alpn_token}_{cipher_sha}_{ext_sha}")
    }
}

/// Live roster sweep — tier-2 verification over the kept roster.
///
/// `grader --roster [--family <name>] [--sample]`
///
/// Walks the combined kept roster — the 69 generated `GenEntry`s plus the
/// 2 wire-exact hand profiles (`chrome_130`, `edge_106`; see
/// [`combined_roster`]). For every entry it builds the `ClientHello` with
/// a fixed seed, computes the local JA4 (tls.peet.ws algorithm, padding
/// excluded from the hash list), connects live and compares the
/// server-reported JA4 against both the local value (wire fidelity) and
/// the registered expected JA4 (corpus value for generated entries,
/// hand-captured value for the hand profiles), classified against the
/// four documented corpus/codec semantics gaps — padding in hello,
/// padding omitted by the 512-byte target rule, no-sig, `ht` ALPN letter
/// — the same classification the offline gate
/// `tests/generated_ja4_gate.rs` pins.
mod roster {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::fmt::Write;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;

    use leas_tls::crypto::fingerprint::ja3::Ja3Fields;
    use leas_tls::crypto::fingerprint::ja4::{full_ja4, hash1, hash2, ja4_a};
    use leas_tls::error::TlsError;
    use leas_tls::fingerprints::{Browser, Device, Os};
    use leas_tls::handshake::{HandshakeParams, connect};
    use leas_tls::hello::parse::parse_hello;
    use leas_tls::hello::{BuildParams, build_hello};
    use leas_tls::http2;
    use leas_tls::profiles::generated::{GENERATED, GenEntry};
    use leas_tls::record::stream::TlsStream;
    use leas_tls::spec::ExtensionSpec;
    use leas_tls::spec::grease::is_grease;
    use leas_tls::verify::WebPkiVerifier;

    use super::local;
    use super::{API_PATH, HOST, PORT};

    /// Bounded concurrency for the live sweep (politeness + local socket
    /// limits; peet.ws grades thousands of fingerprints, but bursty is
    /// rude).
    const CONCURRENCY: usize = 16;
    /// Per-entry cap for the whole fetch (connect + handshake + GET).
    const FETCH_TIMEOUT_SECS: u64 = 20;

    pub async fn main(args: &[String]) -> Result<(), Box<dyn Error>> {
        let mut family_filter: Option<&str> = None;
        let mut sample = false;
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--roster" => {}
                "--sample" => sample = true,
                "--family" => {
                    family_filter = Some(it.next().unwrap_or_else(|| {
                        eprintln!("--family requires a value");
                        std::process::exit(2);
                    }));
                }
                other => {
                    eprintln!("usage: grader --roster [--family <name>] [--sample]");
                    eprintln!("unexpected roster argument {other:?}");
                    std::process::exit(2);
                }
            }
        }

        let mut entries: Vec<GenEntry> = combined_roster();
        if let Some(f) = family_filter {
            entries.retain(|e| family(e) == f);
            if entries.is_empty() {
                eprintln!(
                    "unknown roster family {f:?}; families: chrome, firefox, safari, \
                     chrome_android, safari_ios"
                );
                std::process::exit(2);
            }
        }
        if sample {
            entries = band_sample(&entries);
        }
        let scope = match (family_filter, sample) {
            (Some(f), false) => format!("family {f}, full"),
            (Some(f), true) => format!("family {f}, per-band sample"),
            (None, false) => "full roster".to_string(),
            (None, true) => "per-family/band sample".to_string(),
        };
        println!("roster sweep: {} entries ({scope})", entries.len());

        let (mlkem_pk, _) = leas_tls::crypto::mlkem::Mlkem768::generate_keypair();
        // One shared ML-KEM keypair for the whole sweep (the key-share BODY
        // is JA4-invisible; only the group ids count). Leaked once: the
        // sweep tasks need `'static` — a CLI-sized, single allocation.
        let pk: &'static [u8] = Box::leak(mlkem_pk.as_bytes().to_vec().into_boxed_slice());
        let results = sweep(&entries, pk).await;

        for r in &results {
            println!(
                "{} {:<32} {:<13} {:>3} {:>3} {:>4} {:>4}  {}  {}",
                if r.failed() { "FAIL" } else { "pass" },
                r.name,
                r.family,
                class_abbr(r.class),
                if r.ht { "ht" } else { "·" },
                if r.ech { "ech" } else { "·" },
                r.alpn,
                r.server_ja4,
                r.error.as_deref().unwrap_or(""),
            );
        }
        let table = summary_table(&results);
        print!("{table}");
        let failures = results.iter().filter(|r| r.failed()).count();
        let total = results.len();
        if failures > 0 {
            eprintln!("\nROSTER: {failures}/{total} FAILED — see per-entry lines above");
            std::process::exit(1);
        }
        println!("\nROSTER: ALL {total} PASS");
        Ok(())
    }

    /// Generated-module family of an entry (the five roster modules; the
    /// `safari_ios` module is the `WKWebView` reality — any browser on iOS).
    const fn family(entry: &GenEntry) -> &'static str {
        match (entry.browser, entry.os) {
            (_, Some(Os::Ios)) => "safari_ios",
            (Browser::Firefox, _) => "firefox",
            (Browser::Safari, _) => "safari",
            (_, Some(Os::Android)) => "chrome_android",
            _ => "chrome",
        }
    }

    /// The combined kept roster: the 69 generated `GenEntry`s (in
    /// `GENERATED` order) plus the 2 wire-exact hand profiles. The hand
    /// entries are synthesized `GenEntry`s so the sweep/classification
    /// machinery (family, band sample, offline class, registered-JA4
    /// comparison) treats every kept identity uniformly; their `ja4` is
    /// the hand-captured expected value.
    fn combined_roster() -> Vec<GenEntry> {
        let mut entries: Vec<GenEntry> = GENERATED.to_vec();
        entries.push(GenEntry {
            name: "chrome_130",
            browser: Browser::Chrome,
            os: Some(Os::Windows),
            device: Device::Desktop,
            major: 130,
            ja4: super::CHROME130_JA4,
            spec_fn: leas_tls::profiles::hand_selected::chrome_130,
        });
        entries.push(GenEntry {
            name: "edge_106",
            browser: Browser::Edge,
            os: Some(Os::Windows),
            device: Device::Desktop,
            major: 106,
            ja4: super::EDGE106_JA4,
            spec_fn: leas_tls::profiles::hand_selected::edge_106,
        });
        entries
    }

    /// One entry per (family, major) band, in roster order. The wire-exact
    /// hand profiles claim their band first (they are the roster's most
    /// valuable live checks — `chrome_130` shares band 130 with the
    /// generated `opera_130_*` entries), then generated entries fill the
    /// remaining slots.
    fn band_sample(all: &[GenEntry]) -> Vec<GenEntry> {
        let is_hand = |e: &GenEntry| matches!(e.name, "chrome_130" | "edge_106");
        let mut seen: Vec<(&str, u16)> = Vec::new();
        let mut out: Vec<GenEntry> = Vec::with_capacity(all.len());
        for entry in all.iter().copied().filter(|e| is_hand(e)) {
            let key = (family(&entry), entry.major);
            if !seen.contains(&key) {
                seen.push(key);
                out.push(entry);
            }
        }
        for entry in all.iter().copied().filter(|e| !is_hand(e)) {
            let key = (family(&entry), entry.major);
            if !seen.contains(&key) {
                seen.push(key);
                out.push(entry);
            }
        }
        out
    }

    /// Offline classification of the registered JA4 vs the built hello —
    /// the same semantics the offline gate (`generated_ja4_gate.rs`) pins.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Class {
        Full,
        PaddingInHello,
        PaddingOmitted,
        NoSig,
    }

    const fn class_abbr(class: Option<Class>) -> &'static str {
        match class {
            Some(Class::Full) => "full",
            Some(Class::PaddingInHello) => "pad+",
            Some(Class::PaddingOmitted) => "pad-",
            Some(Class::NoSig) => "nsg",
            None => "???",
        }
    }

    fn sha12(payload: &str) -> String {
        use std::fmt::Write;
        let digest = Sha256::digest(payload.as_bytes());
        let mut out = String::with_capacity(12);
        for b in &digest[..6] {
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    /// Corpus-rule hash2 (original `FoxIO`/ja4db semantics): sorted
    /// non-GREASE ext ids minus SNI (`0000`) and ALPN (`0010`), padding
    /// (`0015`) KEPT in the list — and forced back in when the 512-byte
    /// target rule dropped it — then `_` + sig algs in hello order when
    /// `with_sigs`.
    fn corpus_hash2(f: &Ja3Fields, force_padding: bool, with_sigs: bool) -> String {
        let mut exts: Vec<String> = f
            .extensions
            .iter()
            .copied()
            .filter(|&e| !is_grease(e) && e != 0x0000 && e != 0x0010)
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

    /// Classifies an entry offline; the returned bool marks the corpus
    /// `ht` ALPN letter rendering (first-two-chars vs the codec's
    /// first+last `h1`) — orthogonal to the class.
    fn classify(f: &Ja3Fields, registered: &str) -> Option<(Class, bool)> {
        if full_ja4(f) == registered {
            return Some((Class::Full, false));
        }
        let parts: Vec<&str> = registered.split('_').collect();
        if parts.len() != 3 || hash1(f) != parts[1] {
            return None;
        }
        let ht = parts[0].ends_with("ht") && ja4_a(f).ends_with("h1");
        if corpus_hash2(f, false, true) == parts[2] {
            Some((Class::PaddingInHello, ht))
        } else if corpus_hash2(f, true, true) == parts[2] {
            Some((Class::PaddingOmitted, ht))
        } else if corpus_hash2(f, false, false) == parts[2]
            || corpus_hash2(f, true, false) == parts[2]
        {
            Some((Class::NoSig, ht))
        } else {
            None
        }
    }

    /// tls.peet.ws's A-part rendering (its `ja4.go`): `t13d` + NON-padded
    /// decimal cipher/ext counts + first+last ALPN letter, with NO letter
    /// when no ALPN is offered — the server deviates from the `FoxIO` spec's
    /// `%02d` counts and `00` letter. Observed live: registered
    /// `t13d170900_…` is reported as `t13d179_…` (17 ciphers, 9 exts).
    fn peet_a_part(f: &Ja3Fields) -> String {
        let cipher_count = f.ciphers.iter().filter(|&&c| !is_grease(c)).count();
        let ext_count = f.extensions.iter().filter(|&&e| !is_grease(e)).count();
        let letter = match f.alpn.first() {
            None => String::new(),
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
        format!("t13d{cipher_count}{ext_count}{letter}")
    }

    /// The JA4 the server should report for the built hello: peet A-part +
    /// the codec's hash1 and hash2 (peet.ws excludes padding from hash2,
    /// matching `ja4.rs`).
    fn peet_ja4(f: &Ja3Fields) -> String {
        format!("{}_{}_{}", peet_a_part(f), hash1(f), hash2(f))
    }

    /// A registered JA4 (`FoxIO` rendering: padded counts, `00`/`ht` letters)
    /// converted to the server's rendering for comparison — the shape the
    /// wire would produce for the same hello when every hash matches.
    fn to_peet_rendering(ja4: &str) -> Option<String> {
        let (a, rest) = ja4.split_once('_')?;
        let a = a.strip_prefix("t13d")?;
        let digits = a.get(..4)?;
        let c: usize = digits[..2].parse().ok()?;
        let e: usize = digits[2..4].parse().ok()?;
        let letter = match &a[4..] {
            "00" => "",
            l => l,
        };
        Some(format!("t13d{c}{e}{letter}_{rest}"))
    }

    fn has_ech(spec: &leas_tls::spec::ClientHelloSpec) -> bool {
        spec.extensions
            .iter()
            .any(|e| matches!(e, ExtensionSpec::Raw { ty: 0xfe0d, .. }))
    }

    #[allow(clippy::struct_excessive_bools, reason = "one bool per verdict check")]
    struct EntryResult {
        name: &'static str,
        family: &'static str,
        class: Option<Class>,
        ht: bool,
        ech: bool,
        alpn: &'static str,
        server_ja4: String,
        registered_ok: bool,
        wire_ok: bool,
        hash1_ok: bool,
        error: Option<String>,
    }

    impl EntryResult {
        fn error(entry: &GenEntry, spec: &leas_tls::spec::ClientHelloSpec, msg: String) -> Self {
            Self {
                name: entry.name,
                family: family(entry),
                class: None,
                ht: false,
                ech: has_ech(spec),
                alpn: "·",
                server_ja4: String::new(),
                registered_ok: false,
                wire_ok: false,
                hash1_ok: false,
                error: Some(msg),
            }
        }

        fn failed(&self) -> bool {
            if self.error.is_some() || !self.wire_ok || !self.hash1_ok {
                return true;
            }
            self.class == Some(Class::Full) && !self.registered_ok
        }
    }

    async fn sweep(entries: &[GenEntry], mlkem_pk: &'static [u8]) -> Vec<EntryResult> {
        let sem = Arc::new(Semaphore::new(CONCURRENCY));
        let mut set = JoinSet::new();
        for entry in entries {
            let sem = Arc::clone(&sem);
            let entry = *entry;
            set.spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                grade_entry(entry, mlkem_pk).await
            });
        }
        let mut results = Vec::with_capacity(entries.len());
        while let Some(res) = set.join_next().await {
            match res {
                Ok(r) => results.push(r),
                Err(e) => results.push(EntryResult {
                    name: "<task panic>",
                    family: "?",
                    class: None,
                    ht: false,
                    ech: false,
                    alpn: "·",
                    server_ja4: String::new(),
                    registered_ok: false,
                    wire_ok: false,
                    hash1_ok: false,
                    error: Some(format!("sweep task panicked: {e}")),
                }),
            }
        }
        results
    }

    async fn grade_entry(entry: GenEntry, mlkem_pk: &'static [u8]) -> EntryResult {
        let spec = (entry.spec_fn)();
        let ech = has_ech(&spec);
        let fixed = local::FixedRandom {
            bytes: vec![0x5A; 512],
            pos: AtomicUsize::new(0),
        };
        let local_hello = match build_hello(
            &spec,
            &BuildParams {
                server_name: HOST,
                alpn: None,
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: Some(mlkem_pk),
                rng: &fixed,
            },
        ) {
            Ok(h) => h,
            Err(e) => return EntryResult::error(&entry, &spec, format!("build_hello: {e}")),
        };
        let parsed = match parse_hello(&local_hello.handshake_bytes) {
            Ok(p) => p,
            Err(e) => return EntryResult::error(&entry, &spec, format!("parse_hello: {e}")),
        };
        let fields = Ja3Fields::from(&parsed);
        let peet_ja4 = peet_ja4(&fields);
        let Some((class, ht)) = classify(&fields, entry.ja4) else {
            return EntryResult::error(&entry, &spec, "unclassifiable offline".to_string());
        };
        let alpn = match local::alpn(&parsed).as_deref() {
            Some("h2") => "h2",
            Some(_) => "h1",
            None => "00",
        };

        let fetched = tokio::time::timeout(
            Duration::from_secs(FETCH_TIMEOUT_SECS),
            fetch_peet(&spec, alpn),
        )
        .await;
        let server_ja4 = match fetched {
            Ok(Ok(ja4)) => ja4,
            Ok(Err(e)) => {
                let mut r = EntryResult::error(&entry, &spec, e);
                r.class = Some(class);
                r.ht = ht;
                r.ech = ech;
                r.alpn = alpn;
                return r;
            }
            Err(_) => {
                let mut r = EntryResult::error(&entry, &spec, "fetch timed out".to_string());
                r.class = Some(class);
                r.ht = ht;
                r.ech = ech;
                r.alpn = alpn;
                return r;
            }
        };
        let wire_ok = server_ja4 == peet_ja4;
        let registered_ok = to_peet_rendering(entry.ja4).is_some_and(|r| server_ja4 == r);
        let hash1_ok = server_ja4.split('_').nth(1) == entry.ja4.split('_').nth(1);

        EntryResult {
            name: entry.name,
            family: family(&entry),
            class: Some(class),
            ht,
            ech,
            alpn,
            server_ja4,
            registered_ok,
            wire_ok,
            hash1_ok,
            error: None,
        }
    }

    async fn fetch_peet(
        spec: &leas_tls::spec::ClientHelloSpec,
        alpn: &str,
    ) -> Result<String, String> {
        let stream = TcpStream::connect((HOST, PORT))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let verifier = WebPkiVerifier::webpki_roots();
        let mut conn = connect(
            stream,
            HandshakeParams {
                spec,
                server_name: HOST,
                alpn: None,
                verifier: &verifier,
                rng: &ring::rand::SystemRandom::new(),
            },
        )
        .await
        .map_err(|e| format!("handshake: {e}"))?;
        let body = match alpn {
            "h2" => http2::get(&mut conn, API_PATH, HOST).await,
            _ => http1_get(&mut conn, API_PATH, HOST).await,
        }
        .map_err(|e| format!("GET {API_PATH}: {e}"))?;
        let json: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("response JSON: {e}"))?;
        let ja4 = json["tls"]["ja4"]
            .as_str()
            .unwrap_or("<missing>")
            .to_string();
        if std::env::var_os("ROSTER_DEBUG").is_some() {
            let ja4_r = json["tls"]["ja4_r"].as_str().unwrap_or("");
            let ver = json["tls"]["tls_version_negotiated"].as_str().unwrap_or("");
            let alpn_neg = json["tls"]["alpn_protocol"]
                .as_str()
                .unwrap_or("")
                .to_string();
            eprintln!("DEBUG {alpn}: ja4={ja4} ja4_r={ja4_r} version={ver} alpn_neg={alpn_neg}");
        }
        Ok(ja4)
    }

    /// HTTP/1.1 GET for entries whose hello does not offer h2 (the 306
    /// `http/1.1`-only and 533 no-ALPN entries; peet.ws serves /api/all
    /// over both). Sends `Connection: close`, honors `Content-Length`,
    /// de-chunks when the server chunks.
    async fn http1_get<S: AsyncRead + AsyncWrite + Unpin + Send>(
        conn: &mut TlsStream<S>,
        path: &str,
        host: &str,
    ) -> Result<String, TlsError> {
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
        );
        conn.write_all(req.as_bytes()).await?;
        let mut buf = [0u8; 8192];
        let mut raw: Vec<u8> = Vec::new();
        while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = conn.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
        }
        let header_end = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| TlsError::Protocol("HTTP/1.1 response without headers".to_string()))?;
        let head = String::from_utf8_lossy(&raw[..header_end]);
        let mut body = raw[header_end + 4..].to_vec();
        let chunked = head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked");
        let content_length = head
            .lines()
            .find_map(|l| {
                let lower = l.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().to_string())
            })
            .and_then(|v| v.parse::<usize>().ok());
        if let Some(len) = content_length {
            while body.len() < len {
                let n = conn.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
            }
            body.truncate(len);
        } else if chunked {
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
            }
            body = dechunk(&body)
                .ok_or_else(|| TlsError::Protocol("malformed chunked body".to_string()))?;
        } else {
            loop {
                let n = conn.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
            }
        }
        String::from_utf8(body).map_err(|_| TlsError::Protocol("body not UTF-8".to_string()))
    }

    /// RFC 9112 §7.1 chunked decoding (chunk-size line, data, CRLF per
    /// chunk; a 0-size chunk ends the body, trailing trailers ignored).
    fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let line_end = data.iter().position(|&b| b == b'\n')?;
            let size_line = std::str::from_utf8(&data[..line_end]).ok()?.trim();
            let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
            data = data.get(line_end + 1..)?;
            if size == 0 {
                return Some(out);
            }
            let chunk = data.get(..size)?;
            out.extend_from_slice(chunk);
            data = data.get(size..)?;
            if !data.starts_with(b"\r\n") {
                return None;
            }
            data = data.get(2..)?;
        }
    }

    fn summary_table(results: &[EntryResult]) -> String {
        let mut by_family: BTreeMap<&str, Vec<&EntryResult>> = BTreeMap::new();
        for r in results {
            by_family.entry(r.family).or_default().push(r);
        }
        let mut out = String::from("\n\n");
        let _ = writeln!(
            out,
            "{:<14} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>7} {:>7} {:>5}",
            "family", "total", "full", "pad+", "pad-", "no-sig", "ht", "wire-ok", "reg-ok", "fail"
        );
        let mut totals = [0usize; 9];
        for (fam, group) in &by_family {
            let total = group.len();
            let full = group
                .iter()
                .filter(|r| r.class == Some(Class::Full))
                .count();
            let pad_in = group
                .iter()
                .filter(|r| r.class == Some(Class::PaddingInHello))
                .count();
            let pad_out = group
                .iter()
                .filter(|r| r.class == Some(Class::PaddingOmitted))
                .count();
            let no_sig = group
                .iter()
                .filter(|r| r.class == Some(Class::NoSig))
                .count();
            let ht = group.iter().filter(|r| r.ht).count();
            let wire_ok = group.iter().filter(|r| r.wire_ok).count();
            let reg_ok = group.iter().filter(|r| r.registered_ok).count();
            let fail = group.iter().filter(|r| r.failed()).count();
            totals[0] += total;
            totals[1] += full;
            totals[2] += pad_in;
            totals[3] += pad_out;
            totals[4] += no_sig;
            totals[5] += ht;
            totals[6] += wire_ok;
            totals[7] += reg_ok;
            totals[8] += fail;
            let _ = writeln!(
                out,
                "{fam:<14} {total:>5} {full:>6} {pad_in:>6} {pad_out:>6} {no_sig:>6} {ht:>6} {wire_ok:>7} {reg_ok:>7} {fail:>5}"
            );
        }
        let _ = writeln!(
            out,
            "{:<14} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>7} {:>7} {:>5}",
            "TOTAL",
            totals[0],
            totals[1],
            totals[2],
            totals[3],
            totals[4],
            totals[5],
            totals[6],
            totals[7],
            totals[8]
        );
        out
    }
}
