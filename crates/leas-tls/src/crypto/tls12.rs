//! TLS 1.2 cipher suites and the TLS 1.2 PRF.
//!
//! The TLS 1.2 key schedule (RFC 5246 §6.3, §8.1) is a single PRF — unlike
//! TLS 1.3's HKDF chain — so it needs no incremental schedule object: the
//! master secret and key block are one-shot derivations from the ECDHE
//! premaster secret and the two randoms. Only the AEAD suites are
//! implemented (ECDHE + AES-GCM/ChaCha20-Poly1305): TLS 1.2 CBC suites use
//! HMAC-SHA1 MAC-then-encrypt, which ring does not expose and which is
//! unsafe to hand-roll; a legacy server selecting one is refused with a
//! clear error rather than silently degraded.

use ring::{digest, hmac};
use zeroize::Zeroizing;

/// The TLS 1.2 AEAD cipher suites this engine can speak.
///
/// `EcdheRsa*` vs `EcdheEcdsa*` mirrors the *server's* certificate key type
/// (a TLS 1.2 server picks the suite matching its cert); both are needed to
/// interoperate with RSA- and ECDSA-cert legacy servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls12Suite {
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F).
    EcdheRsaAes128GcmSha256,
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (0xC030).
    EcdheRsaAes256GcmSha384,
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` (0xCCA8, RFC 7905 §2).
    EcdheRsaChacha20Poly1305Sha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (0xC02B).
    EcdheEcdsaAes128GcmSha256,
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (0xC02C).
    EcdheEcdsaAes256GcmSha384,
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` (0xCCA9, RFC 7905 §2).
    EcdheEcdsaChacha20Poly1305Sha256,
}

impl Tls12Suite {
    /// Maps a wire cipher-suite value to a variant.
    #[must_use]
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            0xc02f => Some(Self::EcdheRsaAes128GcmSha256),
            0xc030 => Some(Self::EcdheRsaAes256GcmSha384),
            0xcca8 => Some(Self::EcdheRsaChacha20Poly1305Sha256),
            0xc02b => Some(Self::EcdheEcdsaAes128GcmSha256),
            0xc02c => Some(Self::EcdheEcdsaAes256GcmSha384),
            0xcca9 => Some(Self::EcdheEcdsaChacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// The wire value of this cipher suite.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        match self {
            Self::EcdheRsaAes128GcmSha256 => 0xc02f,
            Self::EcdheRsaAes256GcmSha384 => 0xc030,
            Self::EcdheRsaChacha20Poly1305Sha256 => 0xcca8,
            Self::EcdheEcdsaAes128GcmSha256 => 0xc02b,
            Self::EcdheEcdsaAes256GcmSha384 => 0xc02c,
            Self::EcdheEcdsaChacha20Poly1305Sha256 => 0xcca9,
        }
    }

    /// The PRF hash algorithm for this suite (RFC 5246 §5).
    #[must_use]
    pub const fn prf_digest(self) -> &'static digest::Algorithm {
        match self {
            Self::EcdheRsaAes128GcmSha256
            | Self::EcdheRsaChacha20Poly1305Sha256
            | Self::EcdheEcdsaAes128GcmSha256
            | Self::EcdheEcdsaChacha20Poly1305Sha256 => &digest::SHA256,
            Self::EcdheRsaAes256GcmSha384 | Self::EcdheEcdsaAes256GcmSha384 => &digest::SHA384,
        }
    }

    /// The PRF HMAC algorithm for this suite.
    #[must_use]
    pub const fn prf_alg(self) -> hmac::Algorithm {
        match self {
            Self::EcdheRsaAes128GcmSha256
            | Self::EcdheRsaChacha20Poly1305Sha256
            | Self::EcdheEcdsaAes128GcmSha256
            | Self::EcdheEcdsaChacha20Poly1305Sha256 => hmac::HMAC_SHA256,
            Self::EcdheRsaAes256GcmSha384 | Self::EcdheEcdsaAes256GcmSha384 => hmac::HMAC_SHA384,
        }
    }

    /// PRF hash output length in bytes (sizes `P_hash` scratch buffers).
    #[must_use]
    pub const fn prf_len(self) -> usize {
        match self {
            Self::EcdheRsaAes128GcmSha256
            | Self::EcdheRsaChacha20Poly1305Sha256
            | Self::EcdheEcdsaAes128GcmSha256
            | Self::EcdheEcdsaChacha20Poly1305Sha256 => 32,
            Self::EcdheRsaAes256GcmSha384 | Self::EcdheEcdsaAes256GcmSha384 => 48,
        }
    }

    /// AEAD key length in bytes.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::EcdheRsaAes128GcmSha256 | Self::EcdheEcdsaAes128GcmSha256 => 16,
            _ => 32,
        }
    }

    /// Fixed (implicit) IV length in bytes: 4 for AES-GCM, which carries an
    /// 8-byte explicit nonce per record (RFC 5288 §3), and 12 for
    /// ChaCha20-Poly1305, which carries none — its nonce is the fixed IV
    /// XOR the padded sequence number (RFC 7905 §2, `record_iv_length = 0`).
    #[must_use]
    pub const fn fixed_iv_len(self) -> usize {
        match self {
            Self::EcdheRsaAes128GcmSha256
            | Self::EcdheRsaAes256GcmSha384
            | Self::EcdheEcdsaAes128GcmSha256
            | Self::EcdheEcdsaAes256GcmSha384 => 4,
            Self::EcdheRsaChacha20Poly1305Sha256 | Self::EcdheEcdsaChacha20Poly1305Sha256 => 12,
        }
    }
}

fn hmac_sign(suite: Tls12Suite, key_bytes: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let key = hmac::Key::new(suite.prf_alg(), key_bytes);
    Zeroizing::new(hmac::sign(&key, data).as_ref().to_vec())
}

/// `P_hash(secret, seed)` (RFC 5246 §5): iterated HMAC expansion.
///
/// Every intermediate (`A(i)`, each block) and the output wipe on drop: this
/// is the only expansion function in TLS 1.2, so it produces the master
/// secret and the whole key block.
fn p_hash(suite: Tls12Suite, secret: &[u8], seed: &[u8], out_len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(out_len));
    // A(0) = seed.
    let mut a = Zeroizing::new(seed.to_vec());
    // `A(i) || seed` scratch, hoisted out of the loop: every iteration
    // refills the same allocation instead of building a fresh `Vec`.
    let mut block_in = Zeroizing::new(Vec::with_capacity(suite.prf_len() + seed.len()));
    while out.len() < out_len {
        // A(i) = HMAC(secret, A(i-1)).
        a = hmac_sign(suite, secret, &a);
        // Block = HMAC(secret, A(i) || seed).
        block_in.clear();
        block_in.extend_from_slice(&a);
        block_in.extend_from_slice(seed);
        let block = hmac_sign(suite, secret, &block_in);
        let take = (out_len - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
    }
    out
}

/// The TLS 1.2 PRF (RFC 5246 §5): `P_hash(secret, label || seed)`.
#[must_use]
pub fn prf(
    suite: Tls12Suite,
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
    out_len: usize,
) -> Zeroizing<Vec<u8>> {
    let mut s = Vec::with_capacity(label.len() + seed.len());
    s.extend_from_slice(label);
    s.extend_from_slice(seed);
    p_hash(suite, secret, &s, out_len)
}

/// The 48-byte master secret (RFC 5246 §8.1):
/// `PRF(premaster, "master secret", client_random + server_random)`.
#[must_use]
pub fn master_secret(
    suite: Tls12Suite,
    premaster: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut seed = Vec::with_capacity(client_random.len() + server_random.len());
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    prf(suite, premaster, b"master secret", &seed, 48)
}

/// The 48-byte master secret under `extended_master_secret` (RFC 7627).
///
/// `PRF(premaster, "extended master secret", session_hash)`, where
/// `session_hash` is the hash of the handshake messages from `ClientHello`
/// through `ClientKeyExchange`.
#[must_use]
pub fn master_secret_ems(
    suite: Tls12Suite,
    premaster: &[u8],
    session_hash: &[u8],
) -> Zeroizing<Vec<u8>> {
    prf(
        suite,
        premaster,
        b"extended master secret",
        session_hash,
        48,
    )
}

/// The key block (RFC 5246 §6.3).
///
/// `PRF(master, "key expansion", server_random + client_random)` — note the
/// server random comes FIRST in TLS 1.2 (unlike TLS 1.3). Laid out as
/// `client_write_key || server_write_key || client_write_IV || server_write_IV`.
#[must_use]
pub fn key_block(
    suite: Tls12Suite,
    master: &[u8],
    server_random: &[u8],
    client_random: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut seed = Vec::with_capacity(server_random.len() + client_random.len());
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let len = 2 * suite.key_len() + 2 * suite.fixed_iv_len();
    prf(suite, master, b"key expansion", &seed, len)
}

/// The 12-byte `Finished` `verify_data` (RFC 5246 §7.4.9):
/// `PRF(master, finished_label, Hash(handshake_messages))[0..12]`.
#[must_use]
pub fn finished_verify_data(
    suite: Tls12Suite,
    master: &[u8],
    label: &[u8],
    handshake_hash: &[u8],
) -> Zeroizing<Vec<u8>> {
    prf(suite, master, label, handshake_hash, 12)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Golden vector computed independently (Python `hashlib.hmac`) for
    /// `PRF(SHA256, secret=b"\x01\x02\x03", "master secret",
    /// seed=b"\xaa\xbb\xcc", 48)`.
    #[test]
    fn prf_sha256_golden_vector() {
        let suite = Tls12Suite::EcdheRsaAes128GcmSha256;
        let secret = [0x01u8, 0x02, 0x03];
        let seed = [0xaa, 0xbb, 0xcc];
        let out = prf(suite, &secret, b"master secret", &seed, 48);
        assert_eq!(
            hex(&out),
            "4442b311e2b342a483f52718ea543816b9c8c8db915cacbe87b29d9139f18104d40b988fc0b23fe81aa11dcaf01a6b89"
        );
    }

    #[test]
    fn prf_output_lengths() {
        let suite = Tls12Suite::EcdheRsaAes256GcmSha384;
        assert_eq!(prf(suite, &[1u8; 4], b"x", &[2u8; 4], 48).len(), 48);
        assert_eq!(
            key_block(suite, &[1u8; 48], &[2u8; 32], &[3u8; 32]).len(),
            2 * 32 + 2 * 4
        );
        // RFC 7905: ChaCha20-Poly1305 has a 12-byte fixed IV per direction
        // and no explicit per-record nonce.
        assert_eq!(
            key_block(
                Tls12Suite::EcdheRsaChacha20Poly1305Sha256,
                &[1u8; 48],
                &[2u8; 32],
                &[3u8; 32]
            )
            .len(),
            2 * 32 + 2 * 12
        );
    }

    #[test]
    fn suite_wire_mapping() {
        for s in [
            Tls12Suite::EcdheRsaAes128GcmSha256,
            Tls12Suite::EcdheRsaAes256GcmSha384,
            Tls12Suite::EcdheRsaChacha20Poly1305Sha256,
            Tls12Suite::EcdheEcdsaAes128GcmSha256,
            Tls12Suite::EcdheEcdsaAes256GcmSha384,
            Tls12Suite::EcdheEcdsaChacha20Poly1305Sha256,
        ] {
            assert_eq!(Tls12Suite::from_u16(s.to_u16()), Some(s));
        }
        assert_eq!(Tls12Suite::from_u16(0xc013), None); // CBC: unsupported
        assert_eq!(Tls12Suite::from_u16(0x1301), None); // TLS 1.3 suite
        assert_eq!(Tls12Suite::EcdheRsaAes128GcmSha256.fixed_iv_len(), 4);
        assert_eq!(
            Tls12Suite::EcdheRsaChacha20Poly1305Sha256.fixed_iv_len(),
            12
        );
    }

    #[test]
    fn split_key_block_layout() {
        // GCM: client_key || server_key || client_iv(4) || server_iv(4).
        let suite = Tls12Suite::EcdheRsaAes128GcmSha256;
        let kb = key_block(suite, &[0x5a; 48], &[0x10; 32], &[0x20; 32]);
        let k = suite.key_len();
        let client_key = &kb[..k];
        let server_key = &kb[k..2 * k];
        let client_iv = &kb[2 * k..2 * k + 4];
        let server_iv = &kb[2 * k + 4..];
        assert_ne!(client_key, server_key);
        assert_eq!(client_iv.len(), 4);
        assert_eq!(server_iv.len(), 4);
        assert_eq!(kb.len(), 2 * k + 8);
        let _ = (client_key, server_key, client_iv, server_iv);
    }
}
