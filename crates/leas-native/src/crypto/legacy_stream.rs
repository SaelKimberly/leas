//! Legacy (pre-AEAD) stream ciphers: the algorithms only.
//!
//! Owners: `protocol/vmess/legacy.rs` (AES-128-CFB request header) and
//! `protocol/ss/stream_legacy.rs` (the Shadowsocks legacy method set —
//! `aes-*-cfb`, `aes-*-ctr`, `rc4-md5`, `chacha20-ietf`, `xchacha20`, `none`).
//!
//! `RustCrypto` ships no CFB mode and no RC4, and both are five-line
//! constructions over primitives the workspace already carries, so they live
//! here (see the hazmat rows in `docs/reference/crypto-dependencies.md`).
//! AES-CTR and ChaCha20/XChaCha20 are *not* re-implemented: their codecs stay
//! in the crates (`ctr`, `chacha20`) and the protocol layer composes them.

use aes::cipher::{BlockCipherEncrypt, BlockSizeUser, KeyInit, consts::U16};

/// AES-CFB (CFB-128) stream state — one direction, one key.
///
/// Generic over the AES key size so the three Shadowsocks CFB methods and the
/// `VMess` AES-128 header share one implementation.
pub struct Cfb<C> {
    cipher: C,
    /// The last FULL ciphertext block: CFB's feedback register.
    feedback: [u8; 16],
    /// Position inside the current keystream block.
    used: usize,
    /// Keystream for the current block.
    keystream: [u8; 16],
}

/// `aes-128-cfb` / the `VMess` legacy header.
pub type Aes128Cfb = Cfb<aes::Aes128>;
/// `aes-192-cfb`.
pub type Aes192Cfb = Cfb<aes::Aes192>;
/// `aes-256-cfb`.
pub type Aes256Cfb = Cfb<aes::Aes256>;

impl<C: BlockCipherEncrypt + KeyInit + BlockSizeUser<BlockSize = U16>> Cfb<C> {
    /// `key` must be a valid AES key length for `C` (16/24/32 bytes).
    #[must_use]
    pub fn new(key: &[u8], iv: &[u8; 16]) -> Self {
        Self {
            cipher: C::new_from_slice(key).expect("valid AES key length"),
            feedback: *iv,
            used: 16,
            keystream: [0u8; 16],
        }
    }

    /// XOR `data` in place, feeding back `ciphertext` (encrypt) or the input
    /// itself (decrypt, which IS ciphertext). One refill per 16-byte block; a
    /// partial block never advances the feedback register, matching CFB's
    /// "hold the last full block" rule.
    fn apply(&mut self, data: &mut [u8], decrypting: bool) {
        for byte in data.iter_mut() {
            if self.used == 16 {
                let mut block = [0u8; 16];
                self.cipher
                    .encrypt_block_b2b((&self.feedback).into(), (&mut block).into());
                self.keystream = block;
                self.used = 0;
            }
            let k = self.keystream[self.used];
            let input = *byte;
            *byte = input ^ k;
            // Feedback is the CIPHERTEXT byte in both directions.
            let cipher_byte = if decrypting { input } else { *byte };
            self.feedback[self.used] = cipher_byte;
            self.used += 1;
        }
    }

    /// Encrypt in place (plaintext → ciphertext).
    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.apply(data, false);
    }

    /// Decrypt in place (ciphertext → plaintext).
    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.apply(data, true);
    }
}

/// RC4 keystream state (`rc4-md5`'s primitive).
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Key setup (RFC 6229 §2: key length 1..=256 bytes).
    ///
    /// # Panics
    ///
    /// On an empty key. `rc4-md5` always keys with an MD5 digest (16 bytes).
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "RC4 requires a non-empty key");
        let mut s = [0u8; 256];
        for (i, byte) in s.iter_mut().enumerate() {
            *byte = u8::try_from(i).expect("0..256 fits a byte");
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, usize::from(j));
        }
        Self { s, i: 0, j: 0 }
    }

    /// XOR `data` in place with the next keystream bytes (PRGA).
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[usize::from(self.i)]);
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.s[usize::from(
                self.s[usize::from(self.i)].wrapping_add(self.s[usize::from(self.j)]),
            )];
            *byte ^= k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// NIST SP 800-38A F.3.13 (CFB128-AES128.Encrypt): the published vector,
    /// not a round trip.
    #[test]
    fn cfb128_aes128_matches_nist_sp800_38a() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let plain = hex("6bc1bee22e409f96e93d7e117393172a");
        let expect = hex("3b3fd92eb72dad20333449f8e83cfb4a");
        let mut buf = plain.clone();
        Cfb::<aes::Aes128>::new(&key, &iv).encrypt(&mut buf);
        assert_eq!(buf, expect, "CFB128-AES128 encryption");
        let mut back = expect;
        Cfb::<aes::Aes128>::new(&key, &iv).decrypt(&mut back);
        assert_eq!(back, plain);
    }

    /// NIST SP 800-38A F.3.17 (CFB128-AES256.Encrypt) — proves the generic
    /// key-size path the `aes-256-cfb` method relies on.
    #[test]
    fn cfb128_aes256_matches_nist_sp800_38a() {
        let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let plain = hex("6bc1bee22e409f96e93d7e117393172a");
        let expect = hex("dc7e84bfda79164b7ecd8486985d3860");
        let mut buf = plain.clone();
        Cfb::<aes::Aes256>::new(&key, &iv).encrypt(&mut buf);
        assert_eq!(buf, expect, "CFB128-AES256 encryption");
        let mut back = expect;
        Cfb::<aes::Aes256>::new(&key, &iv).decrypt(&mut back);
        assert_eq!(back, plain);
    }

    /// Uneven writes must produce the same keystream as one call: the feedback
    /// register advances per BLOCK, not per call (Go's `cipher.Stream`).
    #[test]
    fn cfb_is_chunking_invariant() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let data: Vec<u8> = (0..71u8).collect();
        let mut one = data.clone();
        Cfb::<aes::Aes128>::new(&key, &iv).encrypt(&mut one);
        let mut split = data.clone();
        let mut cfb = Cfb::<aes::Aes128>::new(&key, &iv);
        for chunk in split.chunks_mut(7) {
            cfb.encrypt(chunk);
        }
        assert_eq!(one, split, "one call and many calls must agree");
        let mut dec = one;
        let mut cfb = Cfb::<aes::Aes128>::new(&key, &iv);
        for chunk in dec.chunks_mut(5) {
            cfb.decrypt(chunk);
        }
        assert_eq!(dec, data);
    }

    /// RFC 6229 §2: key `0102030405`, the first 16 keystream bytes.
    #[test]
    fn rc4_matches_rfc_6229_vectors() {
        let mut rc4 = Rc4::new(&hex("0102030405"));
        let mut buf = [0u8; 16];
        rc4.apply(&mut buf);
        assert_eq!(buf.to_vec(), hex("b2396305f03dc027ccc3524a0a1118a8"));

        // A second key whose bytes are not sequential: `833222772a` (§2), the
        // full 16-byte block.
        let mut rc4 = Rc4::new(&hex("833222772a"));
        let mut buf = [0u8; 16];
        rc4.apply(&mut buf);
        assert_eq!(buf.to_vec(), hex("80ad97bdc973df8a2e879e92a497efda"));

        // ...and a chunked caller sees the same keystream.
        let mut rc4 = Rc4::new(&hex("0102030405"));
        let mut split = [0u8; 16];
        for chunk in split.chunks_mut(3) {
            rc4.apply(chunk);
        }
        assert_eq!(split.to_vec(), hex("b2396305f03dc027ccc3524a0a1118a8"));
    }

    /// RC4 is its own inverse: the composition with the ciphertext returns
    /// the plaintext only when the SAME state continues (a fresh state would
    /// produce a different keystream offset).
    #[test]
    fn rc4_round_trips_only_with_continuing_state() {
        let key = [0x5au8; 16];
        let data = b"shadowsocks rc4-md5 payload".to_vec();
        let mut rc4 = Rc4::new(&key);
        let mut buf = data.clone();
        rc4.apply(&mut buf);
        assert_ne!(buf, data);
        let mut rc4 = Rc4::new(&key);
        rc4.apply(&mut buf);
        assert_eq!(buf, data);
    }
}
