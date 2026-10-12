//! `ClientHello` builder: turns a [`ClientHelloSpec`] into wire bytes.
//!
//! The builder draws GREASE values and random material from a
//! [`SecureRandom`], substitutes GREASE placeholders per the Chrome-family
//! pairing rule (one value across the four slot-A positions, a second for
//! the standalone GREASE extension), and wraps the result in a TLS
//! handshake message and record.

use std::ops::Range;

use crate::error::TlsError;
use crate::spec::grease::GREASE_PLACEHOLDER;
use crate::spec::{
    ClientHelloSpec, EchGrease, ExtensionSpec, KeyShareGroup, RuntimeValues, SessionIdSpec,
    encode_alpn_override_into, encode_supported_groups_into, encode_supported_versions_into,
};

pub mod parse;
pub use crate::SecureRandom;

/// Runtime inputs for a single `ClientHello` build.
pub struct BuildParams<'a> {
    pub server_name: &'a str,
    /// `None` → use the spec's ALPN list.
    pub alpn: Option<&'a [&'a str]>,
    pub x25519_pub: &'a [u8; 32],
    /// ML-KEM-768 encapsulation key (1184 bytes) for a hybrid key-share
    /// entry; required iff the spec's `key_share` contains one.
    pub mlkem768_pub: Option<&'a [u8]>,
    pub rng: &'a dyn SecureRandom,
}

/// The built `ClientHello`.
pub struct BuiltHello {
    /// type `0x01` + 3-byte length + body.
    pub handshake_bytes: Vec<u8>,
    /// handshake record: `0x16 0x0301 <len u16>` + handshake.
    pub record_bytes: Vec<u8>,
    /// Byte range of the session id inside `handshake_bytes`; `Some` only
    /// for [`SessionIdSpec::AuthPayload`] (a REALITY auth payload slot).
    pub session_id_range: Option<Range<usize>>,
}

impl BuiltHello {
    /// The legacy session id carried by the hello, read from the wire
    /// layout: handshake header (4) + `legacy_version` (2) + random (32) +
    /// `sid_len(1) + sid` (RFC 8446 §4.1.2). The server's `ServerHello` must
    /// echo these exact bytes (RFC 8446 §4.1.3).
    #[must_use]
    pub fn session_id(&self) -> &[u8] {
        let sid_len = usize::from(self.handshake_bytes[38]);
        &self.handshake_bytes[39..39 + sid_len]
    }
}

/// Target total record size for the padding extension, matching the
/// reference (`tls-fingerprint` `profiles/chrome.rs`): the padding data
/// length is `512 - (unpadded record + 4)`, so the final record is exactly
/// 512 bytes; no padding is added when the unpadded record already reaches
/// the target.
const PADDING_TARGET: usize = 512;

/// Builds a `ClientHello` handshake message and record from a spec.
pub fn build_hello(spec: &ClientHelloSpec, params: &BuildParams) -> Result<BuiltHello, TlsError> {
    // GREASE pairing (Chrome family): the first placeholder in each of
    // {cipher_suites, supported_groups, supported_versions, key_share} is
    // replaced with `grease_a`; the first standalone GREASE extension uses
    // `grease_b` (a separate draw — values and extension types are
    // independent namespaces). Each further placeholder in a namespace
    // draws a fresh value, kept distinct from the ones already used there
    // (Go's TLS parser rejects duplicate extension types). Specs without
    // placeholders (Firefox family) skip the draws entirely.
    let (grease_a, grease_b) = if spec_has_grease(spec) {
        (draw_grease(params.rng)?, draw_grease(params.rng)?)
    } else {
        (0x0A0A, 0x1A1A)
    };

    let mut rt = RuntimeValues {
        server_name: params.server_name.to_string(),
        x25519_pub: *params.x25519_pub,
        mlkem768_pub: params.mlkem768_pub.unwrap_or(&[]).to_vec(),
        grease_a,
        grease_b,
        padding_len: 0,
        ech: EchGrease::default(),
    };

    // GREASE ECH material, drawn only when the spec asks for it (a spec
    // without `EchGrease` must not consume RNG bytes — the fixtures in the
    // hello tests and the JA4 gate pin the draw sequence).
    if spec
        .extensions
        .iter()
        .any(|e| matches!(e, ExtensionSpec::EchGrease))
    {
        params
            .rng
            .fill(core::slice::from_mut(&mut rt.ech.config_id))
            .map_err(|_| TlsError::Crypto("ECH config id failed".to_string()))?;
        params
            .rng
            .fill(&mut rt.ech.enc)
            .map_err(|_| TlsError::Crypto("ECH enc failed".to_string()))?;
        params
            .rng
            .fill(&mut rt.ech.payload)
            .map_err(|_| TlsError::Crypto("ECH payload failed".to_string()))?;
    }

    // Client random (RFC 8446 §4.1.2).
    let mut random = [0u8; 32];
    params
        .rng
        .fill(&mut random)
        .map_err(|_| TlsError::Crypto("client random failed".to_string()))?;

    // Legacy session id: 32 random bytes (TLS 1.3 default) or the REALITY
    let (session_id, session_id_range) = match &spec.session_id {
        SessionIdSpec::Random32 => {
            let mut sid = [0u8; 32];
            params
                .rng
                .fill(&mut sid)
                .map_err(|_| TlsError::Crypto("session id random failed".to_string()))?;
            (sid.to_vec(), None)
        }
        SessionIdSpec::Empty => (Vec::new(), None),
        SessionIdSpec::AuthPayload { len } => {
            // handshake header (4) + legacy_version (2) + random (32) +
            // session id length byte (1).
            let start = 4 + 2 + 32 + 1;
            (vec![0u8; *len], Some(start..start + len))
        }
    };
    let sid_len = u8::try_from(session_id.len())
        .map_err(|_| TlsError::Spec("session id exceeds 255 bytes".to_string()))?;
    let comp_len = u8::try_from(spec.compression_methods.len())
        .map_err(|_| TlsError::Spec("compression methods exceed 255 bytes".to_string()))?;

    let mut body = Vec::with_capacity(
        2 + 32
            + 1
            + session_id.len()
            + 2
            + spec.cipher_suites.len() * 2
            + 1
            + spec.compression_methods.len()
            + 2
            + spec.extensions.len() * 8,
    );
    body.extend_from_slice(&spec.legacy_version.to_be_bytes());
    body.extend_from_slice(&random);
    body.push(sid_len);
    body.extend_from_slice(&session_id);

    // Cipher suites: first placeholder → grease_a, later ones → fresh
    // values distinct from every value already used in the list.
    let cs_len = u16::try_from(spec.cipher_suites.len() * 2)
        .map_err(|_| TlsError::Spec("cipher suites exceed u16 length".to_string()))?;
    body.extend_from_slice(&cs_len.to_be_bytes());
    let mut first_cs_grease = true;
    let mut used_cs = [0u16; 16];
    used_cs[0] = grease_a;
    let mut used_cs_len = 1usize;
    for &cs in &spec.cipher_suites {
        let v = if cs == GREASE_PLACEHOLDER {
            if first_cs_grease {
                first_cs_grease = false;
                grease_a
            } else {
                draw_grease_distinct(params.rng, &mut used_cs, &mut used_cs_len)?
            }
        } else {
            cs
        };
        body.extend_from_slice(&v.to_be_bytes());
    }

    body.push(comp_len);
    body.extend_from_slice(&spec.compression_methods);

    // Extensions in spec order.
    let mut ext_bytes = Vec::with_capacity(spec.extensions.len() * 8);
    let mut first_grease_ext = true;
    let mut used_ext = [0u16; 16];
    used_ext[0] = rt.grease_b;
    let mut used_ext_len = 1usize;
    for ext in &spec.extensions {
        match ext {
            ExtensionSpec::Alpn(_) => {
                match params.alpn {
                    // The override encodes straight from `&[&str]` — no
                    // `Vec<String>` staging.
                    Some(protos) => encode_alpn_override_into(protos, &mut ext_bytes)?,
                    None => ext.encode_body_into(&rt, &mut ext_bytes)?,
                }
            }
            ExtensionSpec::Grease => {
                // Standalone GREASE extensions must carry DISTINCT values:
                // real browsers draw each slot independently, and Go's TLS
                // parser rejects a ClientHello with duplicate extension
                // types (the Edge 106 profile carries two — see
                // `profiles/hand_selected.rs`). The first slot uses `grease_b`;
                // later slots draw fresh values distinct from every
                // extension type already used.
                let value = if first_grease_ext {
                    first_grease_ext = false;
                    rt.grease_b
                } else {
                    draw_grease_distinct(params.rng, &mut used_ext, &mut used_ext_len)?
                };
                // len 1, body [0x00] — framed straight into the list buffer.
                ext_bytes.extend_from_slice(&value.to_be_bytes());
                ext_bytes.extend_from_slice(&[0x00, 0x01, 0x00]);
            }
            ExtensionSpec::SupportedGroups(groups) => {
                if groups.contains(&GREASE_PLACEHOLDER) {
                    // GREASE-fill a stack array instead of cloning the Vec.
                    let mut tmp = [0u16; 32];
                    if groups.len() > tmp.len() {
                        return Err(TlsError::Spec(
                            "supported_groups exceeds 32 entries".to_string(),
                        ));
                    }
                    tmp[..groups.len()].copy_from_slice(groups);
                    fill_grease(&mut tmp[..groups.len()], grease_a, params.rng)?;
                    encode_supported_groups_into(&tmp[..groups.len()], &mut ext_bytes)?;
                } else {
                    ext.encode_body_into(&rt, &mut ext_bytes)?;
                }
            }
            ExtensionSpec::SupportedVersions(versions) => {
                if versions.contains(&GREASE_PLACEHOLDER) {
                    let mut tmp = [0u16; 32];
                    if versions.len() > tmp.len() {
                        return Err(TlsError::Spec(
                            "supported_versions exceeds 32 entries".to_string(),
                        ));
                    }
                    tmp[..versions.len()].copy_from_slice(versions);
                    fill_grease(&mut tmp[..versions.len()], grease_a, params.rng)?;
                    encode_supported_versions_into(&tmp[..versions.len()], &mut ext_bytes)?;
                } else {
                    ext.encode_body_into(&rt, &mut ext_bytes)?;
                }
            }
            ExtensionSpec::Padding => {
                // Accumulated RECORD size without the padding extension:
                // record header (5) + handshake header (4) + version (2) +
                // random (32) + sid (1 + len) + cipher suites (2 + bytes) +
                // compression (1 + len) + extension total length field (2)
                // + already-encoded extensions. Padding data length =
                // PADDING_TARGET − (accumulated + 4) with the 4 bytes being
                // the padding extension's type+length overhead; a zero
                // result omits the extension (matches the reference).
                let acc_record = 5
                    + 4
                    + 2
                    + 32
                    + 1
                    + usize::from(sid_len)
                    + 2
                    + spec.cipher_suites.len() * 2
                    + 1
                    + usize::from(comp_len)
                    + 2
                    + ext_bytes.len();
                let padding_len = PADDING_TARGET.saturating_sub(acc_record + 4);
                if padding_len > 0 {
                    rt.padding_len = padding_len;
                    ext.encode_body_into(&rt, &mut ext_bytes)?;
                }
            }
            _ => ext.encode_body_into(&rt, &mut ext_bytes)?,
        }
    }

    let ext_len = u16::try_from(ext_bytes.len())
        .map_err(|_| TlsError::Spec("extensions exceed u16 length".to_string()))?;
    body.extend_from_slice(&ext_len.to_be_bytes());
    body.extend_from_slice(&ext_bytes);

    // Handshake message: type 0x01 + 3-byte length + body.
    let body_len = u32::try_from(body.len())
        .map_err(|_| TlsError::Spec("client hello body exceeds u32 length".to_string()))?;
    if body_len > 0xFF_FFFF {
        return Err(TlsError::Spec(
            "client hello body exceeds 16 MiB".to_string(),
        ));
    }
    let mut handshake_bytes = Vec::with_capacity(4 + body.len());
    handshake_bytes.push(0x01);
    handshake_bytes.extend_from_slice(&body_len.to_be_bytes()[1..]);
    handshake_bytes.extend_from_slice(&body);

    // A TLS record's length field is uint16 (RFC 8446 §5.1): a handshake
    // message larger than 64 KiB cannot be framed in a single record, so
    // reject it here — `to_record`'s defensive saturation of the u16 length
    // stays unreachable for every hello this builder emits.
    if handshake_bytes.len() > usize::from(u16::MAX) {
        return Err(TlsError::Spec(
            "client hello handshake exceeds 64 KiB record limit".to_string(),
        ));
    }

    let record_bytes = to_record(&handshake_bytes);
    Ok(BuiltHello {
        handshake_bytes,
        record_bytes,
        session_id_range,
    })
}

/// Wraps a handshake message in a TLS handshake record:
/// `0x16 0x0301 <len u16 BE> <handshake>`.
#[must_use]
pub fn to_record(handshake_bytes: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + handshake_bytes.len());
    to_record_into(handshake_bytes, &mut record);
    record
}

/// Appends a TLS handshake record framing of `handshake_bytes` to `out`:
/// `0x16 0x0301 <len u16 BE> <handshake>`.
///
/// The allocation-free counterpart of [`to_record`]: drivers framing into
/// a send buffer skip the dedicated record allocation.
pub fn to_record_into(handshake_bytes: &[u8], out: &mut Vec<u8>) {
    out.push(0x16); // ContentType: handshake
    out.extend_from_slice(&0x0301u16.to_be_bytes()); // legacy record version
    // A ClientHello never approaches the u16 record length limit; saturate
    // defensively rather than panic on a pathological spec.
    let len = u16::try_from(handshake_bytes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(handshake_bytes);
}

/// Returns `true` if the spec contains any GREASE placeholder slot.
fn spec_has_grease(spec: &ClientHelloSpec) -> bool {
    spec.cipher_suites.contains(&GREASE_PLACEHOLDER)
        || spec.extensions.iter().any(|e| match e {
            ExtensionSpec::SupportedGroups(groups) => groups.contains(&GREASE_PLACEHOLDER),
            ExtensionSpec::SupportedVersions(versions) => versions.contains(&GREASE_PLACEHOLDER),
            ExtensionSpec::KeyShare(groups) => {
                groups.iter().any(|g| matches!(g, KeyShareGroup::Grease))
            }
            ExtensionSpec::Grease => true,
            _ => false,
        })
}

/// Replaces `GREASE_PLACEHOLDER` slots in `values`: the first becomes
/// `grease_a`, later ones get freshly drawn GREASE values, each distinct
/// from every value already used in this namespace.
fn fill_grease(values: &mut [u16], grease_a: u16, rng: &dyn SecureRandom) -> Result<(), TlsError> {
    let mut first = true;
    let mut used = [0u16; 16];
    used[0] = grease_a;
    let mut used_len = 1usize;
    for v in values.iter_mut() {
        if *v == GREASE_PLACEHOLDER {
            *v = if first {
                first = false;
                grease_a
            } else {
                draw_grease_distinct(rng, &mut used, &mut used_len)?
            };
        }
    }
    Ok(())
}
///
/// Mirrors `spec::grease::random_grease`, which is bounded to ring's sealed
/// `SecureRandom` and therefore unusable through the crate-local seam.
fn draw_grease(rng: &dyn SecureRandom) -> Result<u16, TlsError> {
    let mut byte = [0u8; 1];
    rng.fill(&mut byte)
        .map_err(|_| TlsError::Crypto("random grease failed".to_string()))?;
    // The low nibble indexes the 16 GREASE byte values 0x0A..0xFA.
    let b = 0x0A + (byte[0] & 0x0F) * 0x10;
    Ok((u16::from(b) << 8) | u16::from(b))
}

/// Draws a GREASE value not already recorded in `used`, recording it before
/// returning.
///
/// GREASE placeholders within one namespace (extension types, cipher
/// suites, groups, versions) should be pairwise distinct: BoringSSL/Chrome
/// draw each GREASE index independently (`ssl_grease_extension1` never
/// equals `ssl_grease_extension2`), Go's TLS parser rejects a `ClientHello`
/// with a duplicated extension type, and the reference profiles (e.g.
/// Chrome 133) carry two standalone GREASE extensions. Re-draws are bounded:
/// with real randomness the chance of 8 consecutive collisions is
/// (1/16)^8, while a degenerate fixed-seed RNG (tests, golden vectors)
/// falls back to the reference's all-equal output instead of failing.
fn draw_grease_distinct(
    rng: &dyn SecureRandom,
    used: &mut [u16; 16],
    used_len: &mut usize,
) -> Result<u16, TlsError> {
    const ATTEMPTS: usize = 8;
    let mut last = 0;
    for _ in 0..ATTEMPTS {
        last = draw_grease(rng)?;
        if !used[..*used_len].contains(&last) {
            if *used_len < used.len() {
                used[*used_len] = last;
                *used_len += 1;
            }
            return Ok(last);
        }
    }
    Ok(last)
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{BuildParams, SecureRandom, build_hello, to_record};
    use crate::hello::parse::parse_hello;
    use crate::spec::grease::GREASE_PLACEHOLDER;
    use crate::spec::{ClientHelloSpec, ExtensionSpec, KeyShareGroup, SessionIdSpec};

    /// Deterministic RNG feeding back a fixed byte sequence.
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

    /// Decodes a hex digit into its value (test helper).
    fn hex_val(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("invalid hex digit: {b:#x}"),
        }
    }

    /// Decodes a hex string into bytes (test helper).
    fn decode_hex(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "hex string must have even length");
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| (hex_val(c[0]) << 4) | hex_val(c[1]))
            .collect()
    }

    /// Golden Chrome 130 `ClientHello` captured from the reference
    /// implementation (`tls-fingerprint` crate, same profile + fixed seed):
    /// RNG bytes all `0x42` (so every GREASE value is `0x2A2A`), X25519
    /// public key `[0xAB; 32]`, and the real `chrome::spec()` — which ends
    /// with a Padding extension the builder uses to hit a 512-byte record
    /// (the reference `profiles/chrome.rs` computes the same target).
    const EXPECTED_HELLO_HEX: &str = "010001f70303424242424242424242424242424242424242424242424242424242424242424220424242424242424242424242424242424242424242424242424242424242424200202a2a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f00350100018e2a2a00010000000010000e00000b746c732e706565742e777300170000ff01000100000a000a00082a2a001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000001200000033002b00292a2a000100001d0020abababababababababababababababababababababababababababababababab002d00020101002b0007062a2a03040303001b00050400020003446900050003026832000d0012001004030804040105030805050108060601001500c9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    /// Same hello wrapped in a handshake record (`0x16 0x0301` + length).
    const EXPECTED_RECORD_HEX: &str = "16030101fb010001f70303424242424242424242424242424242424242424242424242424242424242424220424242424242424242424242424242424242424242424242424242424242424200202a2a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f00350100018e2a2a00010000000010000e00000b746c732e706565742e777300170000ff01000100000a000a00082a2a001d00170018000b00020100002300000010000e000c02683208687474702f312e31000500050100000000001200000033002b00292a2a000100001d0020abababababababababababababababababababababababababababababababab002d00020101002b0007062a2a03040303001b00050400020003446900050003026832000d0012001004030804040105030805050108060601001500c9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn chrome130_golden_hello_with_fixed_seed() {
        // Reference capture (run the CURRENT tls-fingerprint example with
        // the same fixed seed): RNG all 0x42 → every GREASE value 0x2A2A,
        // random and session id all 0x42, X25519 public key [0xAB; 32].
        // The real chrome_130 spec ends with a Padding extension, so the
        // record is padded to exactly 512 bytes (same target as the
        // reference `profiles/chrome.rs`). The ported builder must produce
        // byte-identical output.
        let spec = crate::profiles::hand_selected::chrome_130();
        // 2 GREASE bytes + 32 random + 32 session id = 66 bytes needed; give
        // the fixed RNG headroom so exhaustion is never the failure mode.
        let rng = FixedRandom {
            bytes: vec![0x42; 128],
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(
            &spec,
            &BuildParams {
                server_name: "tls.peet.ws",
                alpn: Some(&["h2", "http/1.1"]),
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .unwrap();

        assert_eq!(hello.handshake_bytes, decode_hex(EXPECTED_HELLO_HEX));
        assert_eq!(hello.record_bytes, decode_hex(EXPECTED_RECORD_HEX));
        assert_eq!(hello.record_bytes, to_record(&hello.handshake_bytes));
        assert!(hello.session_id_range.is_none());
        // grease_a + grease_b + random + session id all came from the RNG.
        assert_eq!(rng.pos.load(Ordering::Relaxed), 66);
    }

    #[test]
    fn grease_pairing_uses_a_for_slots_and_b_for_standalone_ext() {
        // Byte 0x00 → GREASE 0x0A0A (slot A), byte 0x01 → GREASE 0x1A1A
        // (slot B, standalone extension type). Distinct values prove the
        // pairing rule, not just equal-value GREASE everywhere.
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![GREASE_PLACEHOLDER, 0x1301, 0x1302],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::Grease,
                ExtensionSpec::SupportedGroups(vec![GREASE_PLACEHOLDER, 0x001D]),
                ExtensionSpec::KeyShare(vec![KeyShareGroup::Grease, KeyShareGroup::X25519]),
                ExtensionSpec::SupportedVersions(vec![GREASE_PLACEHOLDER, 0x0304]),
            ],
        };
        let mut bytes = vec![0x00, 0x01];
        bytes.extend_from_slice(&[0x42; 64]);
        let rng = FixedRandom {
            bytes,
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(
            &spec,
            &BuildParams {
                server_name: "example.com",
                alpn: None,
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .unwrap();

        let parsed = parse_hello(&hello.handshake_bytes).unwrap();
        // cipher_suites[0] is the first slot-A placeholder.
        assert_eq!(parsed.cipher_suites[0], 0x0A0A);
        assert_eq!(parsed.cipher_suites[1], 0x1301);
        // The standalone GREASE extension carries grease_b as its type.
        assert!(parsed.extensions.iter().any(|(ty, _)| *ty == 0x1A1A));
        // supported_groups[0] → grease_a (skip the u16 byte-length prefix).
        let groups = parsed.extension(0x000A).expect("supported_groups");
        let groups: Vec<u16> = groups[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(groups[0], 0x0A0A);
        // key_share first entry group → grease_a (skip the u16 list-length
        // prefix).
        let key_share = parsed.extension(0x0033).expect("key_share");
        let ks_groups: Vec<u16> = key_share[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(ks_groups[0], 0x0A0A);
        // supported_versions[0] → grease_a.
        let versions = parsed.extension(0x002B).expect("supported_versions");
        assert_eq!(u16::from_be_bytes([versions[1], versions[2]]), 0x0A0A);
    }

    #[test]
    fn additional_placeholders_get_fresh_grease_values() {
        // The second cipher-suite placeholder must not reuse grease_a: the
        // fresh draw (rng byte 66, all 0x42 → 0x2A2A) lands in its slot.
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![GREASE_PLACEHOLDER, GREASE_PLACEHOLDER, 0x1301],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![],
        };
        let mut bytes = vec![0x00, 0x01];
        bytes.extend_from_slice(&[0x42; 66]);
        let rng = FixedRandom {
            bytes,
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(
            &spec,
            &BuildParams {
                server_name: "example.com",
                alpn: None,
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .unwrap();

        let parsed = parse_hello(&hello.handshake_bytes).unwrap();
        assert_eq!(parsed.cipher_suites[0], 0x0A0A);
        assert_eq!(parsed.cipher_suites[1], 0x2A2A);
        assert_eq!(parsed.cipher_suites[2], 0x1301);
    }

    #[test]
    fn padding_reaches_512_byte_record() {
        // Full Chrome 130 layout + padding, per the reference
        // (`chrome.rs:125-139`): the padding data length is
        // `512 - (unpadded record + 4)`, so the record is exactly 512 bytes.
        let spec = crate::profiles::hand_selected::chrome_130();
        let rng = FixedRandom {
            bytes: vec![0x42; 128],
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(
            &spec,
            &BuildParams {
                server_name: "tls.peet.ws",
                alpn: Some(&["h2", "http/1.1"]),
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .unwrap();

        assert_eq!(hello.record_bytes.len(), 512);
        assert_eq!(hello.handshake_bytes.len(), 507);
        let parsed = parse_hello(&hello.handshake_bytes).unwrap();
        let padding = parsed.extension(0x0015).expect("padding extension");
        // The exact padding length follows from the 512-byte target (and
        // shifts with any hello change); the invariants are the record size
        // above and a zero-filled padding body.
        assert!(!padding.is_empty());
        assert!(padding.iter().all(|&b| b == 0));

        // An unpadded record already >= 512 bytes → no padding extension.
        let big = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::Raw {
                    ty: 0x1234,
                    data: vec![0xEE; 600],
                },
                ExtensionSpec::Padding,
            ],
        };
        let rng = FixedRandom {
            bytes: vec![0x42; 64],
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(
            &big,
            &BuildParams {
                server_name: "example.com",
                alpn: None,
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .unwrap();
        assert!(hello.record_bytes.len() > 512);
        let parsed = parse_hello(&hello.handshake_bytes).unwrap();
        assert!(
            parsed.extension(0x0015).is_none(),
            "no padding when already >= 512"
        );
    }

    #[test]
    fn auth_payload_session_id_is_zeroed_and_ranged() {
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::AuthPayload { len: 42 },
            extensions: vec![],
        };
        let rng = FixedRandom {
            bytes: vec![0x42; 64],
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(
            &spec,
            &BuildParams {
                server_name: "example.com",
                alpn: None,
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .unwrap();

        let range = hello.session_id_range.expect("auth payload range");
        assert_eq!(range, 39..81);
        let sid = &hello.handshake_bytes[range];
        assert_eq!(sid.len(), 42);
        assert!(sid.iter().all(|&b| b == 0));
        // No GREASE in this spec → the RNG only fed the 32-byte random.
        assert_eq!(rng.pos.load(Ordering::Relaxed), 32);
    }

    #[test]
    fn alpn_param_overrides_spec_list() {
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![ExtensionSpec::Alpn(vec!["spec-only".into()])],
        };
        let build = |alpn: Option<&[&str]>| {
            let rng = FixedRandom {
                bytes: vec![0x42; 64],
                pos: AtomicUsize::new(0),
            };
            build_hello(
                &spec,
                &BuildParams {
                    server_name: "example.com",
                    alpn,
                    x25519_pub: &[0xAB; 32],
                    mlkem768_pub: None,
                    rng: &rng,
                },
            )
            .unwrap()
        };

        // Some(...) replaces the spec's ALPN list.
        let overridden = build(Some(&["h2"]));
        let parsed = parse_hello(&overridden.handshake_bytes).unwrap();
        let alpn = parsed.extension(0x0010).expect("alpn");
        assert!(alpn.windows(2).any(|w| w == b"h2".as_slice()));
        assert!(!alpn.windows(2).any(|w| w == b"sp".as_slice()));

        // None keeps the spec's list.
        let spec_alpn = build(None);
        let parsed = parse_hello(&spec_alpn.handshake_bytes).unwrap();
        let alpn = parsed.extension(0x0010).expect("alpn");
        assert!(alpn.windows(9).any(|w| w == b"spec-only".as_slice()));
    }

    #[test]
    fn duplicate_grease_extension_draws_are_retried() {
        // Two standalone GREASE extensions must carry DISTINCT types: the
        // fresh draw (rng byte 66, 0x01 → 0x1A1A) collides with grease_b
        // (0x1A1A), so the builder must re-draw (byte 67, 0x02 → 0x2A2A).
        // Without the retry the hello would carry the extension type 0x1A1A
        // twice — rejected by Go's TLS parser and rustls.
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![GREASE_PLACEHOLDER, 0x1301],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![
                ExtensionSpec::Grease,
                ExtensionSpec::Grease,
                ExtensionSpec::SupportedVersions(vec![GREASE_PLACEHOLDER, 0x0304]),
            ],
        };
        let mut bytes = vec![0x00, 0x01];
        bytes.extend_from_slice(&[0x42; 64]);
        bytes.extend_from_slice(&[0x01, 0x02]);
        let rng = FixedRandom {
            bytes,
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(
            &spec,
            &BuildParams {
                server_name: "example.com",
                alpn: None,
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .unwrap();

        let parsed = parse_hello(&hello.handshake_bytes).unwrap();
        let types: Vec<u16> = parsed.extensions.iter().map(|(ty, _)| *ty).collect();
        // The first standalone ext carries grease_b; the second got the
        // re-drawn value — distinct.
        assert!(types.contains(&0x1A1A));
        assert!(types.contains(&0x2A2A));
        let mut sorted = types.clone();
        sorted.sort_unstable();
        assert!(
            !sorted.windows(2).any(|w| w[0] == w[1]),
            "extension types must be pairwise distinct, got {types:?}"
        );
    }

    #[test]
    fn no_grease_spec_does_not_consume_grease_bytes() {
        // Firefox-family specs contain no placeholders: the RNG must only
        // feed random + session id (64 bytes).
        let spec = ClientHelloSpec {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301, 0x1302],
            compression_methods: vec![0x00],
            session_id: SessionIdSpec::Random32,
            extensions: vec![ExtensionSpec::SupportedGroups(vec![0x001D])],
        };
        let rng = FixedRandom {
            bytes: vec![0x42; 64],
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(
            &spec,
            &BuildParams {
                server_name: "example.com",
                alpn: None,
                x25519_pub: &[0xAB; 32],
                mlkem768_pub: None,
                rng: &rng,
            },
        )
        .unwrap();
        assert_eq!(rng.pos.load(Ordering::Relaxed), 64);
        assert!(hello.session_id_range.is_none());
    }

    /// Fixed `BuildParams` for the round-trip test (Chrome 130 profile
    /// inputs, deterministic RNG).
    fn params_fixed(rng: &FixedRandom) -> BuildParams<'_> {
        BuildParams {
            server_name: "tls.peet.ws",
            alpn: Some(&["h2", "http/1.1"]),
            x25519_pub: &[0xAB; 32],
            mlkem768_pub: None,
            rng,
        }
    }

    #[test]
    fn parse_roundtrip_of_built_hello() {
        let spec = crate::profiles::hand_selected::chrome_130();
        let rng = FixedRandom {
            bytes: vec![0x42; 128],
            pos: AtomicUsize::new(0),
        };
        let hello = build_hello(&spec, &params_fixed(&rng)).unwrap();
        let parsed = parse_hello(&hello.handshake_bytes).unwrap();
        assert_eq!(parsed.legacy_version, 0x0303);
        assert_eq!(parsed.cipher_suites.len(), spec.cipher_suites.len());
        assert!(parsed.extensions.iter().any(|(t, _)| *t == 0x0000)); // SNI present
        assert!(parsed.extension(0x0010).is_some(), "ALPN present");
    }
}
