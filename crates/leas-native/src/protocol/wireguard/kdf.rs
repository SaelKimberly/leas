//! KDF over BLAKE2s — the `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` hash chain.
//!
//! Every derivation in the handshake is RFC 2104 HMAC keyed by the chaining
//! key, over the *unkeyed* BLAKE2s-256 hash. The reference (`wireguard-go`
//! `device/noise-protocol.go` + `kdf.go`) emits up to three 32-byte outputs in
//! one pass:
//!
//! ```text
//! t0 = HMAC(key, input)
//! t1 = HMAC(t0, 0x01)
//! t2 = HMAC(t0, t1 || 0x02)
//! t3 = HMAC(t0, t2 || 0x03)
//! ```
//!
//! `KDF2` returns `(t1, t2)` and `KDF3` returns `(t1, t2, t3)`; nothing else
//! about the chain is adjustable, which is why the vectors from
//! `thirdparty/wireguard-go/device/kdf_test.go` are the whole contract.

use blake2::Blake2s256;
use hmac::{KeyInit, Mac, SimpleHmac};

/// The `mac1` label, hashed with the receiver's static public key.
pub const LABEL_MAC1: &[u8] = b"mac1----";
/// The `cookie--` label, hashed with the receiver's static public key.
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// `HMAC-BLAKE2s(key, data)`. BLAKE2s-256's block size is 64 bytes, which is
/// what Go's `hmac.New(blake2s.New256, key)` uses. `SimpleHmac` is the digest
/// 0.11 spelling for a hash whose buffer is not "eager" (`Blake2s`).
type HmacBlake2s = SimpleHmac<Blake2s256>;

#[must_use]
pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = <HmacBlake2s as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    h.update(data);
    h.finalize().into_bytes().into()
}

/// First KDF output: the new chaining key.
#[must_use]
pub fn kdf1(key: &[u8], input: &[u8]) -> [u8; 32] {
    kdf2(key, input).0
}

/// Two outputs: `(new chaining key, key)`.
#[must_use]
pub fn kdf2(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t0 = mac(key, input);
    let t1 = mac(&t0, &[0x01]);
    let mut second = [0u8; 33];
    second[..32].copy_from_slice(&t1);
    second[32] = 0x02;
    let t2 = mac(&t0, &second);
    (t1, t2)
}

/// Three outputs: `(new chaining key, tau, key)`. `tau` is mixed into the
/// transcript; the caller must zero it when done.
#[must_use]
pub fn kdf3(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let t0 = mac(key, input);
    let t1 = mac(&t0, &[0x01]);
    let mut second = [0u8; 33];
    second[..32].copy_from_slice(&t1);
    second[32] = 0x02;
    let t2 = mac(&t0, &second);
    let mut third = [0u8; 33];
    third[..32].copy_from_slice(&t2);
    third[32] = 0x03;
    let t3 = mac(&t0, &third);
    (t1, t2, t3)
}

#[cfg(test)]
mod tests {
    use super::{kdf1, kdf2, kdf3};
    use rstest::rstest;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        s.as_bytes()
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(64);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// `thirdparty/wireguard-go/device/kdf_test.go` — three (key, input) rows
    /// with their three outputs. The first row is the RFC-style ASCII pair,
    /// the last is two empty inputs.
    #[rstest]
    #[case::ascii(
        "746573742d6b6579",
        "746573742d696e707574",
        "6f0e5ad38daba1bea8a0d213688736f19763239305e0f58aba697f9ffc41c633",
        "df1194df20802a4fe594cde27e92991c8cae66c366e8106aaa937a55fa371e8a",
        "fac6e2745a325f5dc5d11a5b165aad08b0ada28e7b4e666b7c077934a4d76c24"
    )]
    #[case::wireguard(
        "776972656775617264",
        "776972656775617264",
        "491d43bbfdaa8750aaf535e334ecbfe5129967cd64635101c566d4caefda96e8",
        "1e71a379baefd8a79aa4662212fcafe19a23e2b609a3db7d6bcba8f560e3d25f",
        "31e1ae48bddfbe5de38f295e5452b1909a1b4e38e183926af3780b0c1e1f0160"
    )]
    #[case::empty(
        "",
        "",
        "8387b46bf43eccfcf349552a095d8315c4055beb90208fb1be23b894bc2ed5d0",
        "58a0e5f6faefccf4807bff1f05fa8a9217945762040bcec2f4b4a62bdfe0e86e",
        "0ce6ea98ec548f8e281e93e32db65621c45eb18dc6f0a7ad94178610a2f7338e"
    )]
    fn kdf_matches_the_reference(
        #[case] key: &str,
        #[case] input: &str,
        #[case] t1: &str,
        #[case] t2: &str,
        #[case] t3: &str,
    ) {
        // The reference keys are `[u8; 32]` only by type; the first two rows
        // are shorter, so the chaining key is the HMAC key bytes as given.
        let key = unhex(key);
        let input = unhex(input);
        let (one, two, three) = kdf3(&key, &input);
        assert_eq!(hex32(&one), t1, "t1");
        assert_eq!(hex32(&two), t2, "t2");
        assert_eq!(hex32(&three), t3, "t3");

        let (a, b) = kdf2(&key, &input);
        assert_eq!(hex32(&a), t1, "kdf2 first");
        assert_eq!(hex32(&b), t2, "kdf2 second");
        assert_eq!(hex32(&kdf1(&key, &input)), t1, "kdf1");
    }
}
