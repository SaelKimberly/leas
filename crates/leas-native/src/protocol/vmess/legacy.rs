//! Legacy (pre-AEAD) `VMess`: the `alterId > 0` wire that Xray-core dropped
//! but v2ray-core 4.x and sing-box still speak.
//!
//! Authority: `thirdparty/v2ray-core-legacy/proxy/vmess/encoding/client.go`
//! (`EncodeRequestHeader` / `DecodeResponseHeader`), `common/protocol/id.go`.
//!
//! The delta against the AEAD wire is small and entirely in the two headers:
//!
//! * the request header is `idHash` (16 bytes, PLAINTEXT) followed by the same
//!   49+-byte body, encrypted with **AES-128-CFB** under `cmdKey` with the IV
//!   `md5(timestamp_be8 × 4)`;
//! * the response header is **4 plaintext bytes** read from the same CFB
//!   stream the response body uses (`responseBodyKey`/`responseBodyIV`):
//!   `[echo][option][0][0]`.
//!
//! Body records are unchanged AEAD chunks. The option byte carries
//! `RequestOptionChunkStream` (`0x01`) — the legacy framing bit that the AEAD
//! era deprecated — so the chunk layer is the plain 2-byte size + AEAD body
//! the modern path already implements.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use md5::Md5;
use md5::digest::Digest as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// `RequestOptionChunkStream` — `[DEPRECATED 2023-06]` on the AEAD wire, but
/// the *only* framing bit the legacy wire understands.
pub const OPTION_CHUNK_STREAM: u8 = 0x01;

/// Go `hashTimestamp(h, t)`: the timestamp is written into the hash FOUR
/// times, then the digest is taken (`encoding/client.go:29-35`). This is the
/// CFB IV, not a MAC.
#[must_use]
pub fn hash_timestamp(ts: i64) -> [u8; 16] {
    let mut h = Md5::new();
    for _ in 0..4 {
        h.update(ts.to_be_bytes());
    }
    h.finalize().into()
}

/// The 16-byte plaintext prefix that precedes the CFB-encrypted header:
/// `md5(uuid ‖ timestamp_be8)` (Go `idHash.Sum(nil)` after
/// `serial.WriteUint64(idHash, ts)`).
#[must_use]
pub fn id_hash(uuid: &[u8; 16], ts: i64) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid);
    h.update(ts.to_be_bytes());
    h.finalize().into()
}

/// AES-128-CFB (CFB-128) stream state — one direction.
///
/// `RustCrypto` ships no CFB mode and the construction is a five-line feedback
/// loop over the block cipher, so it lives here (see the hazmat row in
/// `docs/reference/crypto-dependencies.md`).
pub struct Cfb {
    cipher: Aes128,
    /// The last FULL ciphertext block: CFB's feedback register.
    feedback: [u8; 16],
    /// Position inside the current keystream block.
    used: usize,
    /// Keystream for the current block.
    keystream: [u8; 16],
}

impl Cfb {
    #[must_use]
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new_from_slice(key).expect("16-byte AES key"),
            feedback: *iv,
            used: 16,
            keystream: [0u8; 16],
        }
    }

    /// XOR `data` in place, feeding back `ciphertext` (encrypt) or the input
    /// itself (decrypt, which IS ciphertext). One `refill` per 16-byte block;
    /// a partial block never advances the feedback register, matching CFB's
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

/// Read wrapper: decrypts every byte the peer sends after the CFB prefix.
///
/// The write half is untouched — the request body is NOT CFB-framed, only the
/// request header was, and it is written before this wrapper exists.
pub struct CfbReader<S> {
    inner: S,
    cfb: Cfb,
}

impl<S> CfbReader<S> {
    #[must_use]
    pub fn new(inner: S, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        Self {
            inner,
            cfb: Cfb::new(key, iv),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CfbReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        let filled = buf.filled().len();
        if filled > filled_before {
            let this = &mut *self;
            this.cfb
                .decrypt(&mut buf.filled_mut()[filled_before..filled]);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CfbReader<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST SP 800-38A F.3.13 (CFB128-AES128.Encrypt): the published vector,
    /// not a round trip.
    #[test]
    fn cfb128_aes128_matches_nist_sp800_38a() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plain: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expect: [u8; 16] = [
            0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c,
            0xfb, 0x4a,
        ];
        let mut buf = plain;
        Cfb::new(&key, &iv).encrypt(&mut buf);
        assert_eq!(buf, expect, "CFB128-AES128 encryption");
        // And the inverse over the published ciphertext.
        let mut back = expect;
        Cfb::new(&key, &iv).decrypt(&mut back);
        assert_eq!(back, plain);
    }

    /// Uneven chunks must produce the same keystream as one call: the feedback
    /// register advances per BLOCK, not per call (Go's `cipher.Stream`).
    #[test]
    fn cfb_is_chunking_invariant() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let data: Vec<u8> = (0..71u8).collect();
        let mut one = data.clone();
        Cfb::new(&key, &iv).encrypt(&mut one);
        let mut split = data.clone();
        let mut cfb = Cfb::new(&key, &iv);
        for chunk in split.chunks_mut(7) {
            cfb.encrypt(chunk);
        }
        assert_eq!(one, split, "one call and many calls must agree");
        let mut dec = one;
        let mut cfb = Cfb::new(&key, &iv);
        for chunk in dec.chunks_mut(5) {
            cfb.decrypt(chunk);
        }
        assert_eq!(dec, data);
    }

    /// Independent oracle: `python3 -c "hashlib.md5(...)"`. The prefix is
    /// `md5(uuid ‖ ts_be8)`; the CFB IV is `md5(ts_be8 × 4)`.
    #[test]
    fn id_hash_and_iv_match_go_helpers() {
        assert_eq!(
            hex(&id_hash(&[0u8; 16], 0x6000_0000_0000_0000)),
            "8624959d45c80fecd9bef2113b47e849"
        );
        assert_eq!(
            hex(&hash_timestamp(0x6000_0000_0000_0000)),
            "9ae35f9fa5bca3fa101e510a5d4402e9"
        );
    }

    fn hex(b: &[u8]) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(out, "{x:02x}");
        }
        out
    }
}
