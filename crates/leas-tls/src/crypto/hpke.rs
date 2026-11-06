//! HPKE base mode (RFC 9180), the cipher ECH seals `ClientHelloInner` with.
//!
//! Only the profile ECH requires is implemented: DHKEM(X25519, HKDF-SHA256)
//! (KEM id 0x0020), HKDF-SHA256 (KDF id 0x0001) and AES-128-GCM (AEAD id
//! 0x0001). Ring supplies X25519, HKDF and the AEAD; the `HPKE-v1` label
//! plumbing is what the RFC pins and the A.1 vectors below check.
//!
//! Sender and recipient contexts are one-shot sequences (`seal`/`open` with a
//! running sequence number), and the exporter secret is exposed because ECH
//! derives its accept confirmation from it.
//!
//! Reference: RFC 9180 §5.1 (base mode), §4 (DHKEM), §5.3 (exporters).

use ring::aead::{Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hmac;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Result, TlsError};

/// DHKEM(X25519, HKDF-SHA256).
pub const KEM_X25519_HKDF_SHA256: u16 = 0x0020;
/// HKDF-SHA256.
pub const KDF_HKDF_SHA256: u16 = 0x0001;
/// AES-128-GCM.
pub const AEAD_AES128GCM: u16 = 0x0001;
/// X25519 public keys, DKEM shared secrets and the derived key material widths.
const X25519_LEN: usize = 32;
const NH: usize = 32;
const NK: usize = 16;
const NN: usize = NONCE_LEN;

/// `suite_id` for the key schedule (RFC 9180 §5.1): the whole ciphersuite.
fn hpke_suite_id() -> [u8; 10] {
    let mut id = [0u8; 10];
    id[..4].copy_from_slice(b"HPKE");
    id[4..6].copy_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    id[6..8].copy_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    id[8..10].copy_from_slice(&AEAD_AES128GCM.to_be_bytes());
    id
}

/// `suite_id` INSIDE a KEM (RFC 9180 §4: it "MUST start with `KEM`" and
/// identify the KEM alone) — mixing the two produces a plausible but wrong
/// shared secret.
fn kem_suite_id() -> [u8; 5] {
    let mut id = [0u8; 5];
    id[..3].copy_from_slice(b"KEM");
    id[3..5].copy_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    id
}

/// HKDF-Extract (RFC 5869 §2.2) = HMAC(salt, ikm).
///
/// Spelled out rather than taken from `ring::hkdf` because the RFC pins the
/// raw Extract OUTPUT as part of `key_schedule_context`, and `ring::hkdf::Prk`
/// does not expose its bytes.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let tag = hmac::sign(&key, ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(tag.as_ref());
    out
}

/// HKDF-Expand (RFC 5869 §2.3).
fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let mut block = Zeroizing::new(Vec::new());
    let mut counter = 1u8;
    while out.len() < len {
        let mut message = Zeroizing::new(block.to_vec());
        message.extend_from_slice(info);
        message.push(counter);
        let tag = hmac::sign(&key, &message);
        *block = tag.as_ref().to_vec();
        out.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// `LabeledExtract(salt, label, ikm)` — Extract over the labelled IKM.
fn labeled_extract(salt: &[u8], suite: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut prefixed = Zeroizing::new(Vec::with_capacity(
        7 + suite.len() + label.len() + ikm.len(),
    ));
    prefixed.extend_from_slice(b"HPKE-v1");
    prefixed.extend_from_slice(suite);
    prefixed.extend_from_slice(label);
    prefixed.extend_from_slice(ikm);
    hkdf_extract(salt, &prefixed)
}

/// `LabeledExpand(prk, label, info, L)`: Expand over
/// `I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`.
fn labeled_expand(
    prk: &[u8],
    suite: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let len_bytes = u16::try_from(len)
        .expect("HPKE output length fits u16")
        .to_be_bytes();
    let mut full_info = Zeroizing::new(Vec::with_capacity(
        2 + 7 + suite.len() + label.len() + info.len(),
    ));
    full_info.extend_from_slice(&len_bytes);
    full_info.extend_from_slice(b"HPKE-v1");
    full_info.extend_from_slice(suite);
    full_info.extend_from_slice(label);
    full_info.extend_from_slice(info);
    hkdf_expand(prk, &full_info, len)
}

/// DHKEM(X25519, HKDF-SHA256) encapsulation: `(enc, shared_secret)`.
fn encap(pk_r: &[u8; X25519_LEN], sk_e: &StaticSecret) -> ([u8; X25519_LEN], Zeroizing<Vec<u8>>) {
    let pk_e = PublicKey::from(sk_e);
    let enc = pk_e.to_bytes();
    let dh = Zeroizing::new(sk_e.diffie_hellman(&PublicKey::from(*pk_r)).to_bytes());
    let eae_prk = labeled_extract(&[], &kem_suite_id(), b"eae_prk", dh.as_ref());
    let mut kem_context = Vec::with_capacity(2 * X25519_LEN);
    kem_context.extend_from_slice(&enc);
    kem_context.extend_from_slice(pk_r);
    let shared = labeled_expand(
        eae_prk.as_ref(),
        &kem_suite_id(),
        b"shared_secret",
        &kem_context,
        NH,
    );
    (enc, shared)
}

/// DHKEM decapsulation: the recipient half of [`encap`].
fn decap(enc: &[u8; X25519_LEN], sk_r: &StaticSecret) -> Result<Zeroizing<Vec<u8>>> {
    let pk_r = PublicKey::from(sk_r).to_bytes();
    let dh = Zeroizing::new(sk_r.diffie_hellman(&PublicKey::from(*enc)).to_bytes());
    if dh.iter().all(|&b| b == 0) {
        // RFC 9180 §7.1.2: a low-order point must not be accepted.
        return Err(TlsError::Crypto("HPKE: X25519 low-order point".into()));
    }
    let eae_prk = labeled_extract(&[], &kem_suite_id(), b"eae_prk", dh.as_ref());
    let mut kem_context = Vec::with_capacity(2 * X25519_LEN);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(&pk_r);
    Ok(labeled_expand(
        eae_prk.as_ref(),
        &kem_suite_id(),
        b"shared_secret",
        &kem_context,
        NH,
    ))
}

/// The AEAD key and starting nonce plus the exporter secret — what base mode
/// derives from a shared secret (RFC 9180 §5.1, mode 0x00).
pub struct Context {
    key: LessSafeKey,
    base_nonce: [u8; NN],
    sequence: u64,
    exporter_secret: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("hpke::Context")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl Context {
    fn key_schedule(shared_secret: &[u8], info: &[u8]) -> Result<Self> {
        // The Extract OUTPUTS are the context fields, not their expansions.
        let psk_id_hash = labeled_extract(&[], &hpke_suite_id(), b"psk_id_hash", &[]);
        let info_hash = labeled_extract(&[], &hpke_suite_id(), b"info_hash", info);
        let mut ks_context = Zeroizing::new(Vec::with_capacity(1 + 2 * NH));
        ks_context.push(0x00); // mode_base
        ks_context.extend_from_slice(psk_id_hash.as_ref());
        ks_context.extend_from_slice(info_hash.as_ref());
        let secret = labeled_extract(shared_secret, &hpke_suite_id(), b"secret", &[]);
        let key = labeled_expand(secret.as_ref(), &hpke_suite_id(), b"key", &ks_context, NK);
        let base_nonce = labeled_expand(
            secret.as_ref(),
            &hpke_suite_id(),
            b"base_nonce",
            &ks_context,
            NN,
        );
        let exporter_secret =
            labeled_expand(secret.as_ref(), &hpke_suite_id(), b"exp", &ks_context, NH);
        let unbound = UnboundKey::new(&ring::aead::AES_128_GCM, &key)
            .map_err(|_| TlsError::Crypto("HPKE: bad AES-128-GCM key".into()))?;
        let mut nonce = [0u8; NN];
        nonce.copy_from_slice(&base_nonce);
        Ok(Self {
            key: LessSafeKey::new(unbound),
            base_nonce: nonce,
            sequence: 0,
            exporter_secret,
        })
    }

    /// `base_nonce XOR seq` (RFC 9180 §5.2).
    fn nonce(&self, sequence: u64) -> [u8; NN] {
        let mut nonce = self.base_nonce;
        let seq = sequence.to_be_bytes();
        // RFC 9180 §5.2: the sequence is XORed into the LAST 8 bytes.
        for (n, s) in nonce.iter_mut().skip(NN - seq.len()).zip(seq.iter()) {
            *n ^= *s;
        }
        nonce
    }

    /// Seal one message, advancing the sequence number.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce(self.sequence);
        let mut out = plaintext.to_vec();
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut out,
            )
            .map_err(|_| TlsError::Crypto("HPKE: seal failed".into()))?;
        out.extend_from_slice(tag.as_ref());
        self.sequence = self.sequence.saturating_add(1);
        Ok(out)
    }

    /// Open one message, advancing the sequence number.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce(self.sequence);
        let mut out = ciphertext.to_vec();
        let plain = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut out,
            )
            .map_err(|_| TlsError::Crypto("HPKE: open failed (tampered or wrong key)".into()))?;
        let len = plain.len();
        out.truncate(len);
        self.sequence = self.sequence.saturating_add(1);
        Ok(out)
    }

    /// RFC 9180 §5.3 `Context.Export`: `LabeledExpand(exporter_secret,
    /// "sec", exporter_context, L)` — the context is used as the info string
    /// verbatim and the exporter secret is already the PRK.
    #[must_use]
    pub fn export(&self, context: &[u8], len: usize) -> Vec<u8> {
        labeled_expand(
            self.exporter_secret.as_ref(),
            &hpke_suite_id(),
            b"sec",
            context,
            len,
        )
        .to_vec()
    }

    /// The raw exporter secret (ECH derives its accept confirmation from it).
    #[must_use]
    pub fn exporter_secret(&self) -> &[u8] {
        &self.exporter_secret
    }
}

/// A base-mode sender whose `enc` is known BEFORE sealing.
///
/// ECH needs that order: the encapsulated key rides in the `ClientHelloOuter`
/// whose payload is then zeroed to form the AEAD's associated data, so the
/// ciphertext cannot exist yet.
#[derive(Debug)]
pub struct Sender {
    enc: [u8; X25519_LEN],
    ctx: Context,
}

impl Sender {
    /// Draw an ephemeral key and derive the sender context.
    pub fn new(pk_r: &[u8], info: &[u8]) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; X25519_LEN]);
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), seed.as_mut())
            .map_err(|_| TlsError::Crypto("HPKE: ephemeral key draw failed".into()))?;
        Self::with_secret(&StaticSecret::from(*seed), pk_r, info)
    }

    /// As [`Self::new`], with a caller-supplied ephemeral secret (the RFC
    /// vector entry point).
    pub fn with_secret(sk_e: &StaticSecret, pk_r: &[u8], info: &[u8]) -> Result<Self> {
        let pk_r: [u8; X25519_LEN] = pk_r
            .try_into()
            .map_err(|_| TlsError::Crypto("HPKE: recipient key is not 32 bytes".into()))?;
        let (enc, shared) = encap(&pk_r, sk_e);
        Ok(Self {
            enc,
            ctx: Context::key_schedule(&shared, info)?,
        })
    }

    /// The encapsulated key (`enc`) the peer needs to decapsulate.
    #[must_use]
    pub const fn enc(&self) -> &[u8] {
        &self.enc
    }

    /// Seal one message under `aad`, advancing the sequence.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.ctx.seal(aad, plaintext)
    }
}

/// Base-mode seal: `(enc, ciphertext)` for `plaintext` under the recipient key.
///
/// The ephemeral key is drawn from the system CSPRNG; [`seal_base_with`] takes
/// one, which is what the RFC vectors pin.
pub fn seal_base(
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut seed = Zeroizing::new([0u8; X25519_LEN]);
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), seed.as_mut())
        .map_err(|_| TlsError::Crypto("HPKE: ephemeral key draw failed".into()))?;
    seal_base_with(&StaticSecret::from(*seed), pk_r, info, aad, plaintext)
}

/// Base-mode seal with a caller-supplied ephemeral secret (the RFC vector
/// entry point, and what a deterministic test needs).
pub fn seal_base_with(
    sk_e: &StaticSecret,
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut sender = Sender::with_secret(sk_e, pk_r, info)?;
    let ct = sender.seal(aad, plaintext)?;
    Ok((sender.enc().to_vec(), ct))
}

/// Base-mode open: the recipient half, from the sender's `enc`.
pub fn open_base(
    sk_r: &[u8; X25519_LEN],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let enc: [u8; X25519_LEN] = enc
        .try_into()
        .map_err(|_| TlsError::Crypto("HPKE: enc is not 32 bytes".into()))?;
    let shared = decap(&enc, &StaticSecret::from(*sk_r))?;
    let mut ctx = Context::key_schedule(&shared, info)?;
    ctx.open(aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 9180 A.1 (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM),
    /// base mode: the full key schedule, both nonces and every ciphertext.
    #[test]
    fn rfc9180_a1_base_vectors() {
        let info = unhex("4f6465206f6e2061204772656369616e2055726e");
        let sk_e: [u8; 32] =
            unhex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
                .try_into()
                .unwrap();
        let pk_r = unhex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let sk_r: [u8; 32] =
            unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
                .try_into()
                .unwrap();

        let (enc, shared) = encap(&pk_r.try_into().unwrap(), &StaticSecret::from(sk_e));
        assert_eq!(
            hex(&enc),
            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
        );
        assert_eq!(
            hex(&shared),
            "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"
        );

        let ctx = Context::key_schedule(&shared, &info).unwrap();
        assert_eq!(hex(&ctx.base_nonce), "56d890e5accaaf011cff4b7d");
        assert_eq!(
            hex(&ctx.exporter_secret),
            "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8"
        );

        // Sequence numbers 0, 1, 2, 4, 255, 256 (A.1.1.1); the nonce XOR and
        // the AEAD output are both pinned.
        let pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
        let cases: [(u64, &str, &str); 6] = [
            (
                0,
                "436f756e742d30",
                "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
            ),
            (
                1,
                "436f756e742d31",
                "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84",
            ),
            (
                2,
                "436f756e742d32",
                "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180",
            ),
            (
                4,
                "436f756e742d34",
                "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d",
            ),
            (
                255,
                "436f756e742d323535",
                "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a",
            ),
            (
                256,
                "436f756e742d323536",
                "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2",
            ),
        ];
        for (seq, aad, want) in cases {
            let mut ctx = Context::key_schedule(&shared, &info).unwrap();
            ctx.sequence = seq;
            let ct = ctx.seal(&unhex(aad), &pt).unwrap();
            assert_eq!(hex(&ct), want, "sequence {seq}");
        }

        // And the recipient half recovers the plaintext from the sender's enc.
        let ct = {
            let mut fresh = Context::key_schedule(&shared, &info).unwrap();
            fresh.seal(b"436f756e742d30", &pt).unwrap()
        };
        let opened = {
            let shared_r = decap(&enc, &StaticSecret::from(sk_r)).unwrap();
            let mut ctx = Context::key_schedule(&shared_r, &info).unwrap();
            ctx.open(b"436f756e742d30", &ct).unwrap()
        };
        assert_eq!(opened, pt);

        // The exporter (A.1.1.2).
        assert_eq!(
            hex(&ctx.export(&[], 32)),
            "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"
        );
    }

    /// `seal_base`/`open_base` agree, and a tampered ciphertext is rejected.
    #[test]
    fn seal_open_round_trip() {
        let sk_r = StaticSecret::from([7u8; 32]);
        let pk_r = PublicKey::from(&sk_r).to_bytes();
        let (enc, ct) = seal_base(&pk_r, b"tls ech\x00", b"aad", b"inner hello").unwrap();
        let opened = open_base(&sk_r.to_bytes(), &enc, b"tls ech\x00", b"aad", &ct).unwrap();
        assert_eq!(opened, b"inner hello");
        let mut bad = ct;
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open_base(&sk_r.to_bytes(), &enc, b"tls ech\x00", b"aad", &bad).is_err());
    }
}
