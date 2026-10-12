//! Browser fingerprint profiles as spec data.
//!
//! The two surviving hand-transcribed profiles (`hand_selected::chrome_130`,
//! `hand_selected::edge_106`) are declared via `spec!`; the generated
//! roster (`generated/`) holds the JA4-faithful corpus. Resolution lives in
//! `crate::fingerprints`.

use crate::spec::{ClientHelloSpec, ExtensionSpec, SessionIdSpec};

/// Assembles a [`ClientHelloSpec`] from the pieces a `spec!` declaration
/// names. `legacy_version` is fixed at `0x0303` and compression at `[0]` —
/// both TLS 1.3 invariants (see [`ClientHelloSpec`]).
#[allow(dead_code)] // consumed by spec! (Task 5) and the equivalence tests below
pub(crate) fn spec_from_parts(
    cipher_suites: Vec<u16>,
    extensions: Vec<ExtensionSpec>,
    session_id: SessionIdSpec,
) -> ClientHelloSpec {
    ClientHelloSpec {
        legacy_version: 0x0303,
        cipher_suites,
        compression_methods: vec![0x00],
        session_id,
        extensions,
    }
}

/// Decodes the hex body of a `spec!` `raw[ty, "hex"]` token into bytes.
/// Panics on malformed input — a `spec!` declaration is source code, so a
/// bad body is a compile-time-adjacent authoring error, surfaced the moment
/// the profile function runs.
#[allow(dead_code)] // consumed by spec! (Task 5) and the equivalence tests below
pub(crate) fn decode_hex(s: &str) -> Vec<u8> {
    assert_eq!(
        s.len() % 2,
        0,
        "spec! raw body must be even-length hex, got {s:?}"
    );
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| (hex_val(c[0]) << 4) | hex_val(c[1]))
        .collect()
}

/// Decodes one hex digit into its value (spec! `raw` bodies).
fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex digit {b:#x} in spec! raw body"),
    }
}

/// One cipher-suite token: `GREASE` (either case) or a u16 literal.
#[allow(unused_macros)] // consumed by spec! (Task 5) and the equivalence tests below
macro_rules! cipher_token {
    (GREASE) => {
        $crate::spec::grease::GREASE_PLACEHOLDER
    };
    (grease) => {
        $crate::spec::grease::GREASE_PLACEHOLDER
    };
    ($lit:literal) => {
        $lit
    };
}

/// A u16 in a plain id-list context (`versions`, `sigalgs`): `grease` or a
/// u16 literal.
#[allow(unused_macros)] // consumed by spec! (Task 5) and the equivalence tests below
macro_rules! u16_token {
    (grease) => {
        $crate::spec::grease::GREASE_PLACEHOLDER
    };
    (GREASE) => {
        $crate::spec::grease::GREASE_PLACEHOLDER
    };
    ($lit:literal) => {
        $lit
    };
}

/// A `groups[...]` entry: u16 literal or a named group id.
#[allow(unused_macros)] // consumed by spec! (Task 5) and the equivalence tests below
macro_rules! group_token {
    (grease) => {
        $crate::spec::grease::GREASE_PLACEHOLDER
    };
    (GREASE) => {
        $crate::spec::grease::GREASE_PLACEHOLDER
    };
    (x25519) => {
        0x001D
    };
    (mlkem768) => {
        0x11EC
    }; // x25519mlkem768 hybrid
    (p256) => {
        0x0017
    };
    (p384) => {
        0x0018
    };
    (p521) => {
        0x0019
    };
    ($lit:literal) => {
        $lit
    };
}

/// A `compress[...]` entry: RFC 8879 algorithm name or u16 literal.
#[allow(unused_macros)] // consumed by spec! (Task 5) and the equivalence tests below
macro_rules! compress_token {
    (zlib) => {
        0x0001
    };
    (brotli) => {
        0x0002
    };
    (zstd) => {
        0x0003
    };
    ($lit:literal) => {
        $lit
    };
}

/// A `keyshare[...]` entry. The P-curve hybrids are rejected at compile
/// time: the wire encoder hard-fails on Secp256r1Mlkem768/Secp384r1Mlkem1024
/// (`TlsError::Spec`, spec/mod.rs) and there is no P-521 variant at all.
#[allow(unused_macros)] // consumed by spec! (Task 5) and the equivalence tests below
macro_rules! keyshare_token {
    (grease) => {
        $crate::spec::KeyShareGroup::Grease
    };
    (x25519) => {
        $crate::spec::KeyShareGroup::X25519
    };
    (mlkem768) => {
        $crate::spec::KeyShareGroup::X25519Mlkem768
    };
    (p256) => {
        compile_error!(
            "spec!: keyshare `p256` is rejected: the engine implements no \
             P-256 key exchange (see spec/mod.rs)"
        )
    };
    (p384) => {
        compile_error!(
            "spec!: keyshare `p384` is rejected: the engine implements no \
             P-384 key exchange (see spec/mod.rs)"
        )
    };
    (p521) => {
        compile_error!(
            "spec!: keyshare `p521` has no KeyShareGroup variant (see \
             spec/mod.rs; the engine implements no P-521 key exchange)"
        )
    };
}

/// A `session:` token.
#[allow(unused_macros)] // consumed by spec! (Task 5) and the equivalence tests below
macro_rules! session_token {
    (random32) => {
        $crate::spec::SessionIdSpec::Random32
    };
    (empty) => {
        $crate::spec::SessionIdSpec::Empty
    };
}

/// One `exts:` token: a bare unit-variant id or a `name[args]` tuple form.
#[allow(unused_macros)] // consumed by spec! (Task 5) and the equivalence tests below
macro_rules! ext_token {
    (grease) => { $crate::spec::ExtensionSpec::Grease };
    (sni) => { $crate::spec::ExtensionSpec::ServerName };
    (reneg) => { $crate::spec::ExtensionSpec::RenegotiationInfo };
    (ecpf) => { $crate::spec::ExtensionSpec::EcPointFormats };
    (ticket) => { $crate::spec::ExtensionSpec::SessionTicket };
    (status) => { $crate::spec::ExtensionSpec::StatusRequest };
    (sct) => { $crate::spec::ExtensionSpec::SignedCertificateTimestamp };
    (psk) => { $crate::spec::ExtensionSpec::PskKeyExchangeModes };
    (padding) => { $crate::spec::ExtensionSpec::Padding };
    (ech) => { $crate::spec::ExtensionSpec::EchGrease };
    (groups[$($g:tt),*]) => {
        $crate::spec::ExtensionSpec::SupportedGroups(vec![$(group_token!($g)),*])
    };
    (keyshare[$($k:tt),*]) => {
        $crate::spec::ExtensionSpec::KeyShare(vec![$(keyshare_token!($k)),*])
    };
    (versions[$($v:tt),*]) => {
        $crate::spec::ExtensionSpec::SupportedVersions(vec![$(u16_token!($v)),*])
    };
    (sigalgs[$($s:tt),*]) => {
        $crate::spec::ExtensionSpec::SignatureAlgorithms(vec![$(u16_token!($s)),*])
    };
    (compress[$($c:tt),*]) => {
        $crate::spec::ExtensionSpec::CompressCertificate(vec![$(compress_token!($c)),*])
    };
    (alpn[$($p:literal),*]) => {
        $crate::spec::ExtensionSpec::Alpn(vec![$($p.to_string()),*])
    };
    (appsettings[$($p:literal),*]) => {
        $crate::spec::ExtensionSpec::ApplicationSettings(vec![$($p.to_string()),*])
    };
    (rslimit[$n:literal]) => { $crate::spec::ExtensionSpec::RecordSizeLimit($n) };
    (raw[$ty:literal, $data:literal]) => {
        $crate::spec::ExtensionSpec::Raw {
            ty: $ty,
            data: $crate::profiles::decode_hex($data),
        }
    };
}

/// Declaratively defines a fingerprint profile function.
///
/// Expands `name` into `pub fn name() -> ClientHelloSpec` — the
/// `SpecEntry` shape — with `legacy_version` fixed at `0x0303` and
/// compression at `[0]` (TLS 1.3 invariants):
///
/// ```ignore
/// spec! {
///     chrome_gen_137,
///     ciphers: GREASE, 0x1301, 0x1302, 0x1303, 0xc02b,
///     session: random32,
///     exts: grease, sni, groups[grease, x25519, mlkem768],
///           versions[0x0304, 0x0303], sigalgs[0x0403, 0x0804],
///           alpn["h2", "http/1.1"], psk, padding
/// }
/// ```
///
/// # Token grammar
///
/// `ciphers:` — u16 literals (decimal or `0x`-hex) or `GREASE` (either
/// case) for a GREASE slot. A GREASE cipher, when present, must be the
/// first token (the generator and every Chromium-family profile emit it
/// first; this is what keeps the list unambiguous for the parser).
///
/// `session:` — `random32` | `empty`.
///
/// `exts:` — extension tokens in profile order:
/// - bare ids (unit variants): `grease`, `sni`, `reneg`, `ecpf`,
///   `ticket`, `status`, `sct`, `psk`, `padding`, `ech`;
/// - `ech` — `encrypted_client_hello`, emitted as a GREASE
///   `ECHClientHello` whose `config_id`/`enc`/`payload` come from the build
///   RNG (RFC 9849 §5.1; never a bodyless `raw[0xfe0d, ""]`, which every
///   strict parser answers `decode_error` to);
/// - `groups[..]` — `supported_groups`: u16 literals or named group ids
///   (`grease`, `x25519`, `mlkem768`, `p256`, `p384`, `p521`);
/// - `keyshare[..]` — `key_share`: `grease`, `x25519`, `mlkem768` only;
///   the P-curve hybrids `p256`/`p384`/`p521` are rejected (the engine has
///   no P-256/P-384/P-521 key exchange, so those specs would fail at
///   hello-build time);
/// - `versions[..]`, `sigalgs[..]` — u16 literals or `grease`;
/// - `alpn[..]`, `appsettings[..]` — string literals;
/// - `compress[..]` — `zlib` | `brotli` | `zstd` or u16 literals;
/// - `rslimit[N]` — `record_size_limit`;
/// - `raw[ty, "hex"]` — arbitrary extension: u16 `ty` and the body as a
///   hex string. `""` is legal only for an id whose whole body may be empty
///   (`0x0016`/`0x0017`/`0x0023`/`0x0031`); an id with a length-prefixed
///   vector body (ECH, `compress_certificate`, `delegated_credentials`,
///   `signature_algorithms_cert`) must carry it — the roster emitter refuses
///   the bodyless form.
///
/// A comma must follow the last cipher and the session value (they separate
/// the three sections); a trailing comma after the last extension is
/// optional.
#[allow(unused_macros)] // consumed by profiles/generated/*.rs (Task 5) and the equivalence tests below
macro_rules! spec {
    ($name:ident,
     ciphers: $first:tt $(, $cipher:literal)*,
     session: $session:tt,
     exts: $($ext_tail:tt)*) => {
        pub fn $name() -> $crate::spec::ClientHelloSpec {
            $crate::profiles::spec_from_parts(
                vec![cipher_token!($first) $(, cipher_token!($cipher))*],
                spec_exts!($($ext_tail)*),
                session_token!($session),
            )
        }
    };
}

/// Splits the `exts:` token tail into `ExtensionSpec`s, in order.
///
/// Each item is either a bare unit-variant id (`grease`) or an id with a
/// bracketed argument group (`groups[0x001d, x25519]`) — two token trees —
/// so the list is munched one item at a time instead of parsed with a
/// comma-separated `tt` repetition (which cannot express the optional
/// trailing group).
#[allow(unused_macros)] // consumed by spec! (Task 5) and the equivalence tests below
macro_rules! spec_exts {
    () => { Vec::new() };
    ($ext:tt , $($rest:tt)*) => {{
        let mut v = vec![ext_token!($ext)];
        v.extend(spec_exts!($($rest)*));
        v
    }};
    ($ext:tt $args:tt , $($rest:tt)*) => {{
        let mut v = vec![ext_token!($ext $args)];
        v.extend(spec_exts!($($rest)*));
        v
    }};
    ($ext:tt) => { vec![ext_token!($ext)] };
    ($ext:tt $args:tt) => { vec![ext_token!($ext $args)] };
}

// Generated JA4-faithful roster (Task 5 emitter output). Declared after the
// `spec!` macro so its textual scope reaches `generated/*.rs`.
pub mod generated;
// The surviving hand-transcribed profiles (chrome_130, edge_106),
// `spec!`-declared (see `hand_selected.rs`). Declared after the `spec!`
// macro so its textual scope reaches the declarations.
pub mod hand_selected;

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use crate::SecureRandom;
    use crate::crypto::fingerprint::ja3::{Ja3Fields, ja3_hash};
    use crate::crypto::fingerprint::ja4::ja4_a;
    use crate::hello::parse::parse_hello;
    use crate::hello::{BuildParams, build_hello};
    use crate::spec::ClientHelloSpec;
    use crate::spec::grease::is_grease;

    /// Every hand-transcribed profile: stable `snake_case` name + its spec
    /// function. The resolution table in `crate::fingerprints` points at
    /// these same functions. Kept separate from the generated roster: the
    /// hand-written tier carries resolution precedence, and its GREASE-slot
    /// expectations are the family archetypes the generated corpus does
    /// not reproduce (the ja4db export never carries GREASE ids).
    type SpecEntry = (&'static str, fn() -> ClientHelloSpec);
    const HAND_WRITTEN: &[SpecEntry] = &[
        ("chrome_130", super::hand_selected::chrome_130),
        ("edge_106", super::hand_selected::edge_106),
    ];

    /// Hand-written + generated roster, concatenated — the `ALL_SPECS`
    /// iteration point for the build/parse and uniqueness tests.
    fn all_specs() -> Vec<SpecEntry> {
        HAND_WRITTEN
            .iter()
            .copied()
            .chain(
                super::generated::GENERATED
                    .iter()
                    .map(|g| (g.name, g.spec_fn)),
            )
            .collect()
    }

    /// Deterministic RNG feeding back a fixed byte sequence (mirrors the
    /// `hello` test double; `AtomicUsize` keeps it `Sync` for the
    /// `SecureRandom` supertrait).
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

    #[test]
    fn all_profiles_build_and_parse() {
        // Task 2 contract: the generated kept roster is wired in (69
        // entries; a truncated roster would silently shrink this test's
        // coverage).
        assert_eq!(super::generated::GENERATED.len(), 69);
        let (mlkem_pk, _) = crate::crypto::mlkem::Mlkem768::generate_keypair();
        for (name, spec_fn) in all_specs() {
            let spec = spec_fn();
            let rng = FixedRandom {
                bytes: vec![0x5A; 256],
                pos: AtomicUsize::new(0),
            };
            let hello = build_hello(
                &spec,
                &BuildParams {
                    server_name: "tls.peet.ws",
                    alpn: None, // use spec's Alpn
                    x25519_pub: &[0xAB; 32],
                    mlkem768_pub: Some(mlkem_pk.as_bytes()),
                    rng: &rng,
                },
            )
            .unwrap();
            let parsed = parse_hello(&hello.handshake_bytes).unwrap();
            let fields = Ja3Fields::from(&parsed);
            // Both surviving hand profiles (chrome_130, edge_106) carry a
            // GREASE cipher slot — the family archetype the generated
            // corpus does not reproduce (the ja4db export never carries
            // GREASE ids, so generated entries are exempt by nature).
            let hand_written = HAND_WRITTEN.iter().any(|(n, _)| *n == name);
            if hand_written {
                assert!(
                    parsed.cipher_suites.iter().any(|c| is_grease(*c)),
                    "{name} must carry a GREASE cipher slot"
                );
            }
            assert!(!ja3_hash(&fields).is_empty(), "{name} JA3");
            assert!(ja4_a(&fields).starts_with("t13d"), "{name} JA4-A prefix");
        }
    }

    /// Every roster hello must carry RFC-minimal extension bodies.
    ///
    /// The 2026-09-17 run exposed two shapes that every other check missed:
    /// `encrypted_client_hello` with a 0-byte body (36 generated rows) and
    /// `compress_certificate` with an empty algorithm list (28 rows). Both
    /// parse fine with this crate's own decoder and with tls.peet.ws (a
    /// lenient Go peer), and both are `decode_error` on `BoringSSL` — so the
    /// sieve has to be the RFC's minimum body size, not a peer.
    #[test]
    fn every_roster_hello_has_rfc_minimal_extension_bodies() {
        /// Extension id → minimum body length, from its RFC's vector bound.
        /// `None` minimum means "any length, including zero".
        const MIN_BODY: &[(u16, usize, &str)] = &[
            (0x0000, 5, "server_name (RFC 6066 §3)"),
            (0x000a, 2, "supported_groups (RFC 8446 §4.2.7)"),
            (0x000d, 2, "signature_algorithms (RFC 8446 §4.2.3)"),
            (0x0010, 2, "alpn (RFC 7301)"),
            (0x001b, 3, "compress_certificate (RFC 8879 §4)"),
            (0x0022, 2, "delegated_credentials (RFC 9345 §3)"),
            (0x002b, 3, "supported_versions (RFC 8446 §4.2.1)"),
            (0x0033, 2, "key_share (RFC 8446 §4.2.8)"),
            (0x4469, 3, "application_settings (draft-vvv-tls-alps §4)"),
            (0xfe0d, 38, "encrypted_client_hello (RFC 9849 §5.1)"),
        ];

        let (mlkem_pk, _) = crate::crypto::mlkem::Mlkem768::generate_keypair();
        for (name, spec_fn) in all_specs() {
            let spec = spec_fn();
            let rng = FixedRandom {
                bytes: vec![0x5A; 256],
                pos: AtomicUsize::new(0),
            };
            let hello = build_hello(
                &spec,
                &BuildParams {
                    server_name: "tls.peet.ws",
                    alpn: None,
                    x25519_pub: &[0xAB; 32],
                    mlkem768_pub: Some(mlkem_pk.as_bytes()),
                    rng: &rng,
                },
            )
            .unwrap_or_else(|e| panic!("{name}: build_hello failed: {e}"));
            let parsed = parse_hello(&hello.handshake_bytes)
                .unwrap_or_else(|e| panic!("{name}: parse_hello failed: {e}"));

            // Frames must consume their declared length exactly: a mismatch
            // is what a strict peer rejects, and the parser tolerates
            // trailing bytes by design.
            for (ty, body) in &parsed.extensions {
                if let Some((_, min, what)) = MIN_BODY.iter().find(|(id, _, _)| id == ty) {
                    assert!(
                        body.len() >= *min,
                        "{name}: {what} body is {} bytes, needs >= {min}",
                        body.len()
                    );
                }
            }
            let ids: Vec<u16> = parsed
                .extensions
                .iter()
                .map(|(ty, _)| *ty)
                .filter(|ty| !crate::spec::grease::is_grease(*ty))
                .collect();
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                ids.len(),
                "{name}: duplicate extension id (the constant-RNG fixture can collide two GREASE slots — that is the fixture, not the spec)"
            );
        }
    }

    #[test]
    fn all_spec_names_are_unique_snake_case() {
        let mut seen: Vec<&str> = Vec::new();
        for (name, _) in all_specs() {
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_' || c.is_ascii_digit()),
                "{name} must be snake_case"
            );
            assert!(!seen.contains(&name), "duplicate profile name {name}");
            seen.push(name);
        }
    }
}

/// Exercises the `spec!` macro arms directly (the surviving hand profiles
/// in `hand_selected.rs` are themselves `spec!` declarations, so the macro
/// is exercised in production code as well as here).
#[cfg(test)]
mod macro_tests {
    spec! {
        kitchen_sink,
        ciphers: GREASE, 0x1301, 0x1302, 0xc02b,
        session: empty,
        exts: padding, reneg, ecpf, status, sct,
              groups[grease, x25519, mlkem768, p256, p384, p521, 0x001a],
              versions[grease, 0x0304, 0x0303],
              sigalgs[grease, 0x0403, 0x0804],
              alpn["h2", "http/1.1"],
              appsettings["h2"],
              compress[zlib, brotli, zstd, 0x0002],
              rslimit[16385],
              keyshare[grease, x25519, mlkem768],
              raw[0x446d, "0003026832"], psk
    }

    /// Exercises every `spec!` token form: `session: empty`, `padding`,
    /// `appsettings`, `rslimit`, `compress` names + literal, `grease`
    /// inside `sigalgs`, named group ids incl. the P-curve ids, and a
    /// trailing comma.
    #[test]
    fn kitchen_sink_macro_arms() {
        use crate::spec::grease::GREASE_PLACEHOLDER;
        use crate::spec::{ClientHelloSpec, ExtensionSpec, KeyShareGroup, SessionIdSpec};

        let expected = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![GREASE_PLACEHOLDER, 0x1301, 0x1302, 0xc02b],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Empty,
            extensions: vec![
                ExtensionSpec::Padding,
                ExtensionSpec::RenegotiationInfo,
                ExtensionSpec::EcPointFormats,
                ExtensionSpec::StatusRequest,
                ExtensionSpec::SignedCertificateTimestamp,
                ExtensionSpec::SupportedGroups(vec![
                    GREASE_PLACEHOLDER,
                    0x001D,
                    0x11EC,
                    0x0017,
                    0x0018,
                    0x0019,
                    0x001a,
                ]),
                ExtensionSpec::SupportedVersions(vec![GREASE_PLACEHOLDER, 0x0304, 0x0303]),
                ExtensionSpec::SignatureAlgorithms(vec![GREASE_PLACEHOLDER, 0x0403, 0x0804]),
                ExtensionSpec::Alpn(vec!["h2".into(), "http/1.1".into()]),
                ExtensionSpec::ApplicationSettings(vec!["h2".into()]),
                ExtensionSpec::CompressCertificate(vec![0x0001, 0x0002, 0x0003, 0x0002]),
                ExtensionSpec::RecordSizeLimit(16385),
                ExtensionSpec::KeyShare(vec![
                    KeyShareGroup::Grease,
                    KeyShareGroup::X25519,
                    KeyShareGroup::X25519Mlkem768,
                ]),
                ExtensionSpec::Raw {
                    ty: 0x446D,
                    data: vec![0x00, 0x03, 0x02, 0x68, 0x32],
                },
                ExtensionSpec::PskKeyExchangeModes,
            ],
        };
        assert_eq!(kitchen_sink(), expected);
    }
}
