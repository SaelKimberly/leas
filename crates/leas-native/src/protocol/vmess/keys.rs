//! `VMess` key derivation (v2ray `proxy/vmess/aead` + `common/protocol/id.go`).
use md5::Md5;
use md5::digest::Digest as _;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const VMESS_SALT: &str = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_ROOT: &str = "VMess AEAD KDF";
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// cmdKey = `md5(uuid_bytes ‖ VMESS_SALT)` — Go `protocol.NewID`.
///
/// Wipes on drop: every request-header key and the auth ID derive from it,
/// so it is the account's long-term secret in derived form.
#[must_use]
pub fn cmd_key(uuid_bytes: &[u8; 16]) -> Zeroizing<[u8; 16]> {
    let mut m = Md5::new();
    m.update(uuid_bytes);
    m.update(VMESS_SALT.as_bytes());
    Zeroizing::new(m.finalize().into())
}

/// 32-byte `chacha20poly1305` key for a 16-byte `VMess` session body key.
///
/// Mirrors Go `GenerateChacha20Poly1305Key` (xray
/// `proxy/vmess/encoding/auth.go`, sing-vmess `protocol.go`):
/// `md5(k) ‖ md5(md5(k))` — chained double md5, never zeros.
#[must_use]
pub fn chacha20_key_32(body_key: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let first: [u8; 16] = Md5::digest(body_key).into();
    key[..16].copy_from_slice(&first);
    let second: [u8; 16] = Md5::digest(&key[..16]).into();
    key[16..].copy_from_slice(&second);
    key
}

/// `VMess` AEAD KDF — Go `aead.KDF`.
///
/// Go builds a chain of HMAC-SHA256 objects
/// where each path element keys the next HMAC whose *underlying hash* is the
/// previous HMAC (`hmac.New(parent.Create, v)`), then writes the original key
/// as the innermost message. Unrolled, one path element is:
///
/// ```text
/// kdf(key, [p]) = HMAC(root, opad(p) ‖ HMAC(root, ipad(p) ‖ key))
/// ```
///
/// and each additional element wraps the previous result the same way
/// (`kdf(key, p..) = kdf'(opad(pn) ‖ kdf'(ipad(pn) ‖ key, p..n-1), p..n-1)`).
/// All `VMess` keys and path entries are ≤ 64 bytes, so the long-key hashing
/// branch never applies. Path entries are RAW BYTES — Go passes the 16-byte
/// authID / 8-byte nonce through `string(...)`.
///
/// Verified byte-for-byte against Xray-core (hash2 form), v2ray-core v5 and
/// mihomo and sing-vmess (`hMacCreator` form), and the leaf/shoes Rust ports.
#[must_use]
pub fn kdf_bytes_path(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    /// Scratch bound. Each level prepends a 64-byte HMAC pad block to the
    /// message it recurses on, so the deepest message is
    /// `64 * path.len() + key.len()`: `VMess` uses at most 3 path elements
    /// (`kdf16_bytes_path(cmd_key, [salt, authid, nonce])`) with keys ≤ 64
    /// bytes, i.e. 3 * 64 + 64 = 256.
    const SCRATCH: usize = 256;

    fn go(id: &[u8], path: &[&[u8]]) -> [u8; 32] {
        match path {
            [] => hmac_sha256(KDF_ROOT.as_bytes(), id),
            [rest @ .., p] => {
                // `ipad(p) ‖ id` then `opad(p) ‖ inner`, both built in one
                // stack buffer that is wiped when the recursion unwinds —
                // the previous shape allocated two heap Vecs per level, i.e.
                // 28 allocations for a 3-element path.
                let mut msg = Zeroizing::new([0u8; SCRATCH]);
                let end = 64 + id.len();
                msg[..64].copy_from_slice(pad_key(p, IPAD).as_slice());
                msg[64..end].copy_from_slice(id);
                let inner = go(&msg[..end], rest);
                msg[..64].copy_from_slice(pad_key(p, OPAD).as_slice());
                let end = 64 + inner.len();
                msg[64..end].copy_from_slice(&inner);
                go(&msg[..end], rest)
            }
        }
    }
    // A deeper path or a longer key would overflow the scratch: assert here,
    // once per KDF, rather than panicking inside the recursion on a slice
    // range — a silently truncated message would derive the wrong key.
    assert!(
        64 * path.len() + key.len() <= SCRATCH,
        "vmess kdf path too deep: 64 * {} + {} > {SCRATCH}",
        path.len(),
        key.len()
    );
    go(key, path)
}

/// String-path form of [`kdf_bytes_path`] (ASCII salts — e.g. the authID
/// encryption key salt and the response-header salts).
#[must_use]
pub fn kdf(key: &[u8], path: &[&str]) -> [u8; 32] {
    let bytes: Vec<&[u8]> = path.iter().map(|s| s.as_bytes()).collect();
    kdf_bytes_path(key, &bytes)
}

/// 16-byte prefix of [`kdf`].
#[must_use]
pub fn kdf16(key: &[u8], path: &[&str]) -> [u8; 16] {
    let full = kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// 16-byte prefix of [`kdf_bytes_path`].
#[must_use]
pub fn kdf16_bytes_path(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = kdf_bytes_path(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// 64-byte ipad/opad padding of an HMAC key (`VMess` keys are ≤ 64 bytes, so no
/// long-key pre-hashing is needed — matches Go's `hmac.New` for short keys).
fn pad_key(key: &[u8], xor: u8) -> Zeroizing<[u8; 64]> {
    let mut out = Zeroizing::new([xor; 64]);
    for (o, &b) in out.iter_mut().zip(key) {
        *o ^= b;
    }
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac key any size");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// FNV-1a 32-bit (Go `hash/fnv`).
#[must_use]
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// CRC-32 IEEE (Go `hash/crc32`).
#[must_use]
pub fn crc32_ieee(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Request `AuthID`: AES-128-ECB(key = KDF16(cmdKey, "AES Auth ID Encryption"),
/// block = [`ts_be`] [rand4] [`crc32(ts_be ‖ rand4)`]). Go `aead.CreateAuthID`.
#[must_use]
pub fn auth_id(cmd_key: &[u8; 16], ts_secs: i64, rand4: &[u8; 4]) -> [u8; 16] {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let key = kdf16(cmd_key, &["AES Auth ID Encryption"]);
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&ts_secs.to_be_bytes());
    block[8..12].copy_from_slice(rand4);
    let crc = crc32_ieee(&block[..12]);
    block[12..].copy_from_slice(&crc.to_be_bytes());
    let cipher = aes::Aes128::new_from_slice(&key).expect("16-byte key");
    let mut out = [0u8; 16];
    cipher.encrypt_block_b2b((&block).into(), (&mut out).into());
    out
}

/// sha256(data)[..16] — responseBodyKey/IV derivation (Go `crypto/sha256`).
#[must_use]
pub fn sha256_first16(data: &[u8]) -> [u8; 16] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_UUID: [u8; 16] = [0; 16];

    #[test]
    fn cmd_key_matches_go_id_new() {
        // Go: NewID(uuid.Zero) cmdKey (computed via md5(uuid ‖ const))
        assert_eq!(
            hex(cmd_key(&ZERO_UUID).as_slice()),
            "5e20f3239545e3f48e0ff445aa7c4c3b"
        );
    }

    #[test]
    fn kdf_matches_go_hmac_chain() {
        let ck = cmd_key(&ZERO_UUID);
        // Go aead.KDF16(ck, "AES Auth ID Encryption") — verified against the
        // vendored Xray-core proxy/vmess/aead package.
        assert_eq!(
            hex(&kdf16(ck.as_slice(), &["AES Auth ID Encryption"])),
            "b39f4051224a1a3ce8aa8b1a2ab9f5ca"
        );
        // Go aead.KDF16(ck, "AEAD Resp Header Len Key")
        assert_eq!(
            hex(&kdf16(ck.as_slice(), &["AEAD Resp Header Len Key"])),
            "e784d53ee0d812cd04762ebe91cab8d4"
        );
    }

    #[test]
    fn kdf_bytes_path_three_level_matches_go_seal_key() {
        // 3-level byte-path KDF, exactly as used to seal the request header:
        // Go KDF16(ck, "VMess Header AEAD Key_Length", authID(ts=42), nonce=0xABx8).
        // authID/ts=42 from the vendored Go run (fixed rand aabbccdd).
        let ck = cmd_key(&ZERO_UUID);
        let auth_id = hex_decode("79d348cf6b4707cf6acbb494bf257f1d");
        let nonce = [0xab; 8];
        let got = kdf16_bytes_path(
            ck.as_slice(),
            &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
        );
        assert_eq!(hex(&got), "f6ce8d31a534f597ab191a35a335f27e");
    }

    #[test]
    fn fnv1a32_matches_go() {
        // Real request-body prefix (wire layout, Go-verified): version | iv | key |
        // resp | opt | security 3 | reserved | cmd | PORT FIRST | addrType | addr.
        // fnv = 0x273bd20a (computed by the vendored Xray-core seal for this body).
        let mut body = vec![1u8];
        body.extend_from_slice(&[0x11; 16]);
        body.extend_from_slice(&[0x22; 16]);
        body.extend_from_slice(&[0x33, 0x00, 0x03, 0x00, 0x01]);
        body.extend_from_slice(&80u16.to_be_bytes()); // port 80 (0x0050), FIRST
        body.extend_from_slice(&[0x01, 127, 0, 0, 1]); // addrType IPv4 + 127.0.0.1
        assert_eq!(fnv1a32(&body), 0x273b_d20a);
    }

    #[test]
    fn auth_id_encrypts_ecb_golden() {
        let ck = cmd_key(&ZERO_UUID);
        // ts=0x6000000000000000, rand=0xaabbccdd -> crc32 0x277774dc; key =
        // KDF16(ck, "AES Auth ID Encryption") = b39f4051224a1a3ce8aa8b1a2ab9f5ca.
        // Golden ciphertext (openssl aes-128-ecb + vendored Xray-core aead):
        // 9becfee74d1a702389bc60e9f200e6de
        let id = auth_id(&ck, 0x6000_0000_0000_0000, &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(hex(&id), "9becfee74d1a702389bc60e9f200e6de");
    }

    #[test]
    fn kdf_bytes_path_matches_string_path_for_ascii() {
        let ck = cmd_key(&ZERO_UUID);
        let str_path = ["AES Auth ID Encryption", "aead", "salt"];
        let bytes_path: [&[u8]; 3] = [b"AES Auth ID Encryption", b"aead", b"salt"];
        assert_eq!(
            kdf_bytes_path(ck.as_slice(), &bytes_path),
            kdf(ck.as_slice(), &str_path)
        );
        assert_eq!(
            kdf16_bytes_path(ck.as_slice(), &bytes_path),
            kdf16(ck.as_slice(), &str_path)
        );
    }

    #[test]
    fn chacha20_key_is_double_md5_of_body_key() {
        let k = [0x22u8; 16];
        let key = chacha20_key_32(&k);
        assert_eq!(
            hex(key.as_slice()),
            "fbc3cf71d993ca7bec2664357ccdac2bb270c6d264a3bfeab7ceea80762a13cc"
        );
    }

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    }

    fn hex_decode(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }
}
