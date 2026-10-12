//! VLESS `mlkem768x25519plus` payload encryption (xray
//! `proxy/vless/encryption` — the client side of the ML-KEM-768 + X25519
//! PFS handshake).
//!
//! Wire summary (client → server):
//! - `ClientHello`: `[16B random IV][relays][pfs key exchange][padding]`.
//!   One relay block per configured server key, in order: an ephemeral
//!   X25519 public key (32 B) or an ML-KEM-768 ciphertext (1088 B). With
//!   `xorpub`/`random` each relay block is XOR-masked with AES-256-CTR
//!   keyed by the server's own key material (`blake3.DeriveKey("VLESS",
//!   key)`); consecutive blocks are chained by XOR-masking a 32-byte
//!   blake3 hash of the next server key with a CTR stream keyed by the
//!   previous shared secret. The pfs exchange is NFS-AEAD-sealed
//!   (`[2B BE len][ephemeral ML-KEM pk 1184 || ephemeral X25519 pk 32]`),
//!   followed by sealed padding fragments sent with configurable delays.
//! - `ServerHello` (read): `[NFS-AEAD(MaxNonce) server pfs material
//!   1088+32+16][AEAD ticket 32][AEAD [2B padding length]]` then the
//!   padding itself.
//! - **Post-handshake records** both ways: `[23 03 03 len_hi len_lo]
//!   [AEAD(payload ≤8192)]`, nonce auto-incrementing from zero; the two
//!   directions use different AEAD contexts (each side's PFS public
//!   material). `random` mode additionally XOR-masks ONLY the 5-byte record
//!   headers (per-direction CTR streams in `CommonConn`); the AEAD payloads
//!   travel clear and the keystream advances 5 bytes per record
//!   (xray `XorConn`).
//!
//! Deviations from upstream (documented in the task report): no 0-RTT
//! ticket resume — `0rtt` accounts still run the full 1-RTT handshake
//! (wire-valid; the server issues tickets that we never replay); AES-GCM
//! is never selected — the client always seals with ChaCha20-Poly1305 and
//! the server accepts either.

use super::b3;

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, AeadInOut};
use ctr::cipher::{KeyIvInit, StreamCipher};
use ring::rand::SecureRandom;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use aes::Aes256;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce as ChachaNonce};
use ctr::Ctr128BE;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use leas_proto::proto_spec::MlkemEncryption;
use leas_proto::proto_spec::MlkemMode;
use leas_tls::crypto::X25519KeyPair;
use leas_tls::crypto::mlkem::{Ciphertext, Mlkem768, PublicKey};

use crate::BoxStream;
use crate::error::{NativeError, timeouts};

/// ML-KEM-768 encapsulation-key / ciphertext length (FIPS 203).
pub const MLKEM_CT_LEN: usize = 1088;
/// X25519 public-key length.
const X25519_LEN: usize = 32;
/// AEAD tag length (Poly1305).
const TAG_LEN: usize = 16;
/// Record header length (`23 03 03 len_hi len_lo`).
const HEADER_LEN: usize = 5;
/// Maximum plaintext chunk per record (xray `CommonConn.Write`).
const MAX_CHUNK: usize = 8192;
/// Record-length bounds (xray `DecodeHeader`: TLS 1.3 max record + tag).
const MIN_RECORD: usize = 17;
const MAX_RECORD: usize = 16_640;
/// The all-ones nonce used for the fixed-context NFS seal of the server's
/// PFS material (xray `MaxNonce`).
const MAX_NONCE: [u8; 12] = [0xff; 12];
/// `ClientHello` layout constants (xray `ClientInstance.Handshake`).
const IV_LEN: usize = 16;
/// `18 + 1184 + 32 + 16`: sealed length prefix + client PFS public keys +
/// tags.
const PFS_EXCHANGE_LEN: usize = 18 + 1184 + X25519_LEN + TAG_LEN;

// ── wire helpers ───────────────────────────────────────────────────────────

/// Big-endian u16 into two bytes (xray `EncodeLength`).
#[allow(
    clippy::cast_possible_truncation,
    reason = "ML-KEM length fields are < 2^16 by protocol construction"
)]
const fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}

/// Big-endian two bytes into u16 (xray `DecodeLength`).
const fn decode_length(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | (b[1] as usize)
}

/// The AEAD cipher both directions use (xray `NewAEAD`): a ChaCha20-Poly1305
/// instance keyed by `blake3.DeriveKey(ctx, united_key)` with an
/// auto-incrementing 12-byte counter nonce starting at zero.
struct WireAead {
    cipher: ChaCha20Poly1305,
    nonce: [u8; 12],
}

impl WireAead {
    fn new(ctx: &[u8], key: &[u8]) -> Self {
        let derived = b3::derive_key_bytes(ctx, key);
        Self {
            cipher: ChaCha20Poly1305::new((&derived).into()),
            nonce: [0; 12],
        }
    }

    /// xray `IncreaseNonce`: little-endian increment from the last byte.
    fn increase_nonce(&mut self) -> [u8; 12] {
        for i in 0..12 {
            self.nonce[11 - i] += 1;
            if self.nonce[11 - i] != 0 {
                break;
            }
        }
        self.nonce
    }

    /// Test-only allocating seal: production seals via [`Self::seal_into`]
    /// / [`Self::seal_append`] / [`Self::seal_zeros_in_place`].
    #[cfg(test)]
    fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let n = self.increase_nonce();
        let nonce = ChachaNonce::from(n);
        let nonce = &nonce;
        self.cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("chacha20poly1305 seal cannot fail")
    }

    /// Seal `plaintext` into `out` (`out.len() == plaintext.len() + TAG_LEN`).
    ///
    /// The allocation-free counterpart of [`Self::seal`]: handshake code
    /// sealing straight into the flight buffer skips the temp `Vec`.
    fn seal_into(&mut self, out: &mut [u8], plaintext: &[u8], aad: &[u8]) {
        use inout::InOutBuf;
        debug_assert_eq!(out.len(), plaintext.len() + TAG_LEN);
        let n = self.increase_nonce();
        let (msg, tag_out) = out.split_at_mut(plaintext.len());
        msg.copy_from_slice(plaintext);
        let tag = self
            .cipher
            .encrypt_inout_detached(&ChachaNonce::from(n), aad, InOutBuf::from(msg))
            .expect("chacha20poly1305 seal cannot fail");
        tag_out.copy_from_slice(tag.as_slice());
    }

    fn seal_append(&mut self, buf: &mut Vec<u8>, body_start: usize, aad: &[u8]) {
        use inout::InOutBuf;
        let n = self.increase_nonce();
        let tag = self
            .cipher
            .encrypt_inout_detached(
                &ChachaNonce::from(n),
                aad,
                InOutBuf::from(&mut buf[body_start..]),
            )
            .expect("chacha20poly1305 seal cannot fail");
        buf.extend_from_slice(tag.as_slice());
    }

    /// Open `buf` (`ciphertext || tag`) in place, returning the plaintext
    /// length: the plaintext occupies `buf[..len]`.
    ///
    /// The allocation-free counterpart of [`Self::open`]: the record
    /// reader decrypts inside its reused read buffer.
    fn open_in_place(&mut self, buf: &mut [u8], aad: &[u8]) -> Result<usize, io::Error> {
        use inout::InOutBuf;
        if buf.len() < TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "aead open failed",
            ));
        }
        let split = buf.len() - TAG_LEN;
        let (msg, tag_bytes) = buf.split_at_mut(split);
        let tag: [u8; TAG_LEN] = tag_bytes
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aead open failed"))?;
        let n = self.increase_nonce();
        let msg_len = msg.len();
        self.cipher
            .decrypt_inout_detached(
                &ChachaNonce::from(n),
                aad,
                InOutBuf::from(msg),
                (&tag).into(),
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aead open failed"))?;
        Ok(msg_len)
    }

    /// Seal an all-zeros `buf` in place, returning the tag: for padding
    /// bodies that are already zeroed in the flight buffer (no staging).
    fn seal_zeros_in_place(&mut self, buf: &mut [u8]) -> [u8; TAG_LEN] {
        use inout::InOutBuf;
        let n = self.increase_nonce();
        debug_assert!(buf.iter().all(|&b| b == 0));
        let tag = self
            .cipher
            .encrypt_inout_detached(&ChachaNonce::from(n), &[], InOutBuf::from(buf))
            .expect("chacha20poly1305 seal cannot fail");
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_slice());
        out
    }

    /// Test-only allocating open: production decrypts via
    /// [`Self::open_in_place`].
    #[cfg(test)]
    fn open(&mut self, buf: &[u8], aad: &[u8]) -> Result<Vec<u8>, io::Error> {
        let n = self.increase_nonce();
        self.cipher
            .decrypt(
                &ChachaNonce::from(n),
                chacha20poly1305::aead::Payload { msg: buf, aad },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aead open failed"))
    }

    /// Seal under an explicit nonce — the fake-server tests' `MaxNonce`
    /// PFS seal (server.go `nfsAEAD.Seal(serverHello[:0], MaxNonce, ..)`).
    #[cfg(test)]
    fn seal_with(&self, nonce: [u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        self.cipher
            .encrypt(
                &ChachaNonce::from(nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("chacha20poly1305 seal cannot fail")
    }

    fn open_with(
        &self,
        nonce: [u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, io::Error> {
        self.cipher
            .decrypt(
                &ChachaNonce::from(nonce),
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "aead open failed"))
    }
}

/// AES-256-CTR keystream keyed like xray's `NewCTR`: the raw key material is
/// first run through `blake3.DeriveKey("VLESS", ..)`. Go's `cipher.NewCTR`
/// treats the full 16-byte IV as the initial big-endian counter block —
/// `Ctr128BE`.
///
/// Hazmat assessment (`ctr`'s crate banner warns that ciphertexts are
/// unauthenticated, and that warning is about *encryption*): this is a
/// keystream MASK, not an encryption scheme. It hides relay blocks
/// (`xorpub`/`random`) and, in `random` mode, the 5-byte record headers, on
/// exactly the bytes xray masks; the bytes that carry user data are sealed by
/// the NFS AEAD (`WireAead`, ChaCha20-Poly1305) and the relay chain is
/// authenticated by `b3::hash32`. No `RustCrypto` API provides raw AES-CTR
/// other than this crate, and xray's wire format fixes the construction, so
/// the crate stays; the wire bytes are pinned against Go by the KAT tests at
/// the bottom of this file. Recorded in `docs/crypto-dependencies.md`.
fn new_ctr(key: &[u8], iv: &[u8; 16]) -> Ctr128BE<Aes256> {
    let derived = b3::derive_key_bytes(b"VLESS", key);
    Ctr128BE::<Aes256>::new(&derived.into(), iv.into())
}

/// Uniform random integer in `[lo, hi]` (xray `crypto.RandBetween`).
#[allow(
    clippy::cast_possible_truncation,
    reason = "usize is at least u64-wide on all supported targets"
)]
fn rand_between(lo: usize, hi: usize, rng: &ring::rand::SystemRandom) -> usize {
    debug_assert!(hi >= lo);
    let span = (hi - lo + 1) as u64;
    // Rejection sampling: no modulo bias (traffic-shaping only, but free).
    let zone = u64::MAX / span * span;
    loop {
        let mut buf = [0u8; 8];
        rng.fill(&mut buf).expect("ring CSPRNG fills");
        let v = u64::from_be_bytes(buf);
        if v < zone {
            return lo + (v % span) as usize;
        }
    }
}

// ── config ─────────────────────────────────────────────────────────────────

/// A configured server authentication key: X25519 (32 bytes) or ML-KEM-768
/// encapsulation key (1184 bytes).
#[derive(Debug, Clone)]
pub enum ServerKey {
    X25519([u8; X25519_LEN]),
    Mlkem(Vec<u8>),
}

impl ServerKey {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::X25519(k) => k.as_slice(),
            Self::Mlkem(k) => k,
        }
    }
}

/// Ready-to-use encryption parameters (parsed string + decoded keys +
/// parsed padding).
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    pub mode: MlkemMode,
    /// xray `account.Seconds` — `1` for `0rtt` accounts. Ticket-based
    /// resume is not implemented (deviation); every dial runs the full
    /// handshake.
    pub seconds: u32,
    pub padding_lens: Vec<[usize; 3]>,
    pub padding_gaps: Vec<[usize; 3]>,
    pub keys: Vec<ServerKey>,
}

impl EncryptionConfig {
    /// Build from the proto-parsed value: decodes the base64url key
    /// segments and parses the padding spec (xray `ParsePadding` rules).
    pub fn try_from_parsed(parsed: &MlkemEncryption) -> Result<Self, NativeError> {
        let invalid = |what: String| NativeError::Config(format!("vless mlkem encryption: {what}"));
        let mut keys = Vec::new();
        for seg in parsed.keys.split('.') {
            if seg.is_empty() {
                return Err(invalid("empty key segment".into()));
            }
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(seg)
                .map_err(|_| invalid("invalid base64url key segment".into()))?;
            match decoded.len() {
                32 => {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&decoded);
                    keys.push(ServerKey::X25519(k));
                }
                1184 => keys.push(ServerKey::Mlkem(decoded)),
                other => {
                    return Err(invalid(format!(
                        "key segment must be 32 or 1184 bytes, got {other}"
                    )));
                }
            }
        }
        if keys.is_empty() {
            return Err(invalid("no server keys".into()));
        }
        let (padding_lens, padding_gaps) = parse_padding(&parsed.padding)?;
        Ok(Self {
            mode: parsed.mode,
            seconds: parsed.seconds,
            padding_lens,
            padding_gaps,
            keys,
        })
    }
}

/// Parse the padding spec (xray `ParsePadding`): dot-separated
/// `probability-min-max` triples, alternating length/delay blocks starting
/// with a length block. The first block requires probability ≥100 and
/// min ≥35; total max padding ≤65553.
/// One `probability-min-max` padding block (xray `[3]int`).
type PaddingSpec = [usize; 3];

fn parse_padding(padding: &str) -> Result<(Vec<PaddingSpec>, Vec<PaddingSpec>), NativeError> {
    let invalid = |s: &str| NativeError::Config(format!("vless mlkem padding parameter: {s}"));
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    if padding.is_empty() {
        return Ok((lens, gaps));
    }
    let mut max_len = 0usize;
    for (i, s) in padding.split('.').enumerate() {
        let x: Vec<&str> = s.split('-').collect();
        if x.len() < 3 || x.iter().any(|p| p.is_empty()) {
            return Err(invalid(s));
        }
        let mut y = [0usize; 3];
        for (slot, part) in y.iter_mut().zip(x) {
            *slot = part.parse().map_err(|_| invalid(s))?;
        }
        if i == 0 && (y[0] < 100 || y[1] < 18 + 17 || y[2] < 18 + 17) {
            return Err(NativeError::Config(
                "vless mlkem padding: first padding length must not be smaller than 35".into(),
            ));
        }
        if i % 2 == 0 {
            max_len += y[1].max(y[2]);
            lens.push(y);
        } else {
            gaps.push(y);
        }
    }
    if max_len > 18 + 65_535 {
        return Err(NativeError::Config(
            "vless mlkem padding: total padding length must not be larger than 65553".into(),
        ));
    }
    Ok((lens, gaps))
}

/// Draw one padded fragment plan (xray `CreatPadding`): each block fires
/// with its probability, producing a length/gap in `[min, max]`; empty
/// specs fall back to the documented defaults.
fn create_padding(
    lens: &[[usize; 3]],
    gaps: &[[usize; 3]],
    rng: &ring::rand::SystemRandom,
) -> (Vec<usize>, Vec<usize>) {
    let default_lens: [[usize; 3]; 2] = [[100, 111, 1111], [50, 0, 3333]];
    let default_gaps: [[usize; 3]; 1] = [[75, 0, 111]];
    let (lens, gaps) = if lens.is_empty() {
        (default_lens.as_slice(), default_gaps.as_slice())
    } else {
        (lens, gaps)
    };
    let draw = |y: [usize; 3]| {
        if y[0] >= rand_between(0, 100, rng) {
            rand_between(y[1], y[2], rng)
        } else {
            0
        }
    };
    let frag_lens: Vec<usize> = lens.iter().copied().map(draw).collect();
    let gap_ms: Vec<usize> = gaps.iter().copied().map(draw).collect();
    (frag_lens, gap_ms)
}

// ── handshake ──────────────────────────────────────────────────────────────

/// Sealed session ticket length in the server flight.
const TICKET_LEN: usize = 32;
/// Sealed padding-length field in the server flight.
const LENGTH_LEN: usize = 18;

/// Run the client handshake over the secured stream and return the encrypted
/// tunnel (xray `ClientInstance.Handshake`). On success the VLESS request
/// header is written through the returned connection.
pub async fn handshake(
    stream: BoxStream,
    cfg: &EncryptionConfig,
) -> Result<CommonConn, NativeError> {
    let mut stream = stream;
    let rng = ring::rand::SystemRandom::new();

    // Relay blocks: one per server key, chained by hash32 + CTR streams.
    let relays_len: usize = cfg
        .keys
        .iter()
        .map(|k| match k {
            ServerKey::X25519(_) => 32 + 32,
            ServerKey::Mlkem(_) => MLKEM_CT_LEN + 32,
        })
        .sum::<usize>()
        - 32;

    // Padding plan (drawn before the buffer so its length is known).
    let (mut frag_lens, gap_ms) = create_padding(&cfg.padding_lens, &cfg.padding_gaps, &rng);
    let padding_len: usize = frag_lens.iter().sum();

    let mut hello = vec![0u8; IV_LEN + relays_len + PFS_EXCHANGE_LEN + padding_len];
    rng.fill(&mut hello[..IV_LEN])
        .map_err(|_| NativeError::Config("rng failure".into()))?;
    let iv: [u8; 16] = hello[..IV_LEN].try_into().expect("iv slice");

    // Every hop's shared secret lands here; the last one keys the NFS AEAD
    // and is folded into `united`, so it must not outlive the handshake.
    let mut nfs_key = Zeroizing::new(Vec::new());
    let mut last_ctr: Option<Ctr128BE<Aes256>> = None;
    let mut off = IV_LEN;
    for (j, key) in cfg.keys.iter().enumerate() {
        let index = match key {
            ServerKey::X25519(pk) => {
                let eph =
                    X25519KeyPair::generate(&rng).map_err(|e| NativeError::Tls(e.to_string()))?;
                hello[off..off + X25519_LEN].copy_from_slice(&eph.public_key());
                nfs_key = Zeroizing::new(
                    eph.agree(pk)
                        .map_err(|e| NativeError::Tls(e.to_string()))?
                        .to_vec(),
                );
                X25519_LEN
            }
            ServerKey::Mlkem(ek) => {
                let pk = PublicKey::from_bytes(ek).map_err(|e| NativeError::Tls(e.to_string()))?;
                // Encapsulate straight into the hello relay slot and a
                // stack secret — no `Ciphertext`/`Vec` temps.
                let mut ss = [0u8; 32];
                let slot: &mut [u8; MLKEM_CT_LEN] = (&mut hello[off..off + MLKEM_CT_LEN])
                    .try_into()
                    .expect("relay slot");
                Mlkem768::encapsulate_into(&pk, slot, &mut ss)
                    .map_err(|e| NativeError::Tls(e.to_string()))?;
                // Wrap before copying: the stack array itself has no wipe
                // hook, so it must die inside `Zeroizing`.
                let ss = Zeroizing::new(ss);
                nfs_key = Zeroizing::new(ss.to_vec());
                MLKEM_CT_LEN
            }
        };
        if cfg.mode != MlkemMode::Native {
            // xorpub/random: mask this relay block with a CTR stream keyed
            // by the server's own key material (recoverable by the server).
            new_ctr(key.bytes(), &iv).apply_keystream(&mut hello[off..off + index]);
        }
        if let Some(c) = last_ctr.as_mut() {
            // Make this relay irreplaceable: unmask the previous hop's
            // hash32 check region.
            c.apply_keystream(&mut hello[off..off + 32]);
        }
        if j == cfg.keys.len() - 1 {
            break;
        }
        // Chain to the next key: write blake3(next server key) masked by a
        // CTR stream keyed by THIS hop's shared secret.
        let mut c = new_ctr(&nfs_key, &iv);
        let hash = b3::hash32(cfg.keys[j + 1].bytes());
        hello[off + index..off + index + 32].copy_from_slice(&hash);
        c.apply_keystream(&mut hello[off + index..off + index + 32]);
        last_ctr = Some(c);
        off += index + 32;
    }

    // NFS AEAD over the IV context.
    let mut nfs_aead = WireAead::new(&iv, &nfs_key);

    // Client PFS key exchange: ephemeral ML-KEM-768 + ephemeral X25519.
    // The public material is staged in a stack array and sealed straight
    // into the hello — no `pfs_public` Vec, no seal temp `Vec`s.
    let (mlkem_pk, mlkem_dsk) = Mlkem768::generate_keypair();
    let x25519_eph = X25519KeyPair::generate(&rng).map_err(|e| NativeError::Tls(e.to_string()))?;
    let mut pfs_public = [0u8; 1184 + X25519_LEN];
    pfs_public[..1184].copy_from_slice(mlkem_pk.as_bytes());
    pfs_public[1184..].copy_from_slice(&x25519_eph.public_key());

    let pfs_off = IV_LEN + relays_len;
    let len_prefix = encode_length(PFS_EXCHANGE_LEN - 18);
    nfs_aead.seal_into(&mut hello[pfs_off..pfs_off + 18], &len_prefix, &[]);
    nfs_aead.seal_into(
        &mut hello[pfs_off + 18..pfs_off + PFS_EXCHANGE_LEN],
        &pfs_public,
        &[],
    );

    // Padding: a sealed [2B len] prefix, then the zero body sealed so the
    // ciphertext (body + tag) fills the remainder exactly (xray seals
    // `padding[18:paddingLength-16]` — zeros at that point — into the tail).
    // The body region is already zeroed (fresh `vec![0u8; ..]` hello), so
    // it seals in place with no staging `Vec`.
    debug_assert!(padding_len >= 34, "padding first block min is 35");
    let pad_off = pfs_off + PFS_EXCHANGE_LEN;
    let pad_len_prefix = encode_length(padding_len - 18);
    nfs_aead.seal_into(&mut hello[pad_off..pad_off + 18], &pad_len_prefix, &[]);
    let pad_body_end = pad_off + padding_len - TAG_LEN;
    let pad_tag = nfs_aead.seal_zeros_in_place(&mut hello[pad_off + 18..pad_body_end]);
    hello[pad_body_end..pad_off + padding_len].copy_from_slice(&pad_tag);

    // Fragmented send: the first fragment carries the whole pre-padding
    // prefix (xray folds it into paddingLens[0]); gaps between fragments
    // shape the traffic pattern.
    frag_lens[0] += pfs_off + PFS_EXCHANGE_LEN;
    let mut sent = 0usize;
    for (i, l) in frag_lens.into_iter().enumerate() {
        if l > 0 {
            write_all_timeout(
                &mut stream,
                &hello[sent..sent + l],
                "vless mlkem hello fragment",
            )
            .await?;
            sent += l;
        }
        if gap_ms.len() > i && gap_ms[i] > 0 {
            tokio::time::sleep(Duration::from_millis(gap_ms[i] as u64)).await;
        }
    }

    // ── ServerHello ──
    //
    // One read for the entire fixed-size server flight: the encrypted PFS
    // share, the ticket and the padding length arrive back to back (no client
    // write sits between them), so three sequential `read_exact`s bought only
    // extra syscalls and timers. The AEAD open order below is unchanged, so
    // the nonce sequence is identical on the wire.
    let pfs_len = MLKEM_CT_LEN + X25519_LEN + TAG_LEN;
    let flight = read_exact_timeout(
        &mut stream,
        pfs_len + TICKET_LEN + LENGTH_LEN,
        "vless mlkem server flight",
    )
    .await?;
    let encrypted_pfs = &flight[..pfs_len];
    let server_pfs = nfs_aead.open_with(MAX_NONCE, encrypted_pfs, &[])?;
    let mlkem_ct = Ciphertext::from_bytes(&server_pfs[..MLKEM_CT_LEN])
        .map_err(|e| NativeError::Tls(e.to_string()))?;
    let mlkem_key = Mlkem768::decapsulate(&mlkem_dsk, &mlkem_ct);
    let mut peer_x25519 = [0u8; X25519_LEN];
    peer_x25519.copy_from_slice(&server_pfs[MLKEM_CT_LEN..MLKEM_CT_LEN + X25519_LEN]);
    let x25519_key = x25519_eph
        .agree(&peer_x25519)
        .map_err(|e| NativeError::Tls(e.to_string()))?;

    // united = pfs(64) || nfs(32); direction-specific AEAD contexts.
    let mut united = Zeroizing::new(Vec::with_capacity(96));
    united.extend_from_slice(mlkem_key.as_bytes());
    united.extend_from_slice(x25519_key.as_slice());
    united.extend_from_slice(&nfs_key);

    let self_aead = WireAead::new(&pfs_public, &united);
    let mut peer_aead = WireAead::new(&server_pfs, &united);

    // xray opens the ticket IN PLACE and reuses its first 16 bytes
    // (plaintext) as the random-mode inbound CTR IV. Both fields are
    // opened inside the flight buffer — no temp `Vec`s.
    let mut flight = flight;
    let ticket_len = peer_aead.open_in_place(&mut flight[pfs_len..pfs_len + TICKET_LEN], &[])?;
    debug_assert_eq!(ticket_len, 16, "ticket plaintext is 16 bytes");
    let length_len = peer_aead.open_in_place(&mut flight[pfs_len + TICKET_LEN..], &[])?;
    let peer_padding_len = decode_length(&flight[pfs_len + TICKET_LEN..][..length_len]);

    // random mode: XOR-mask everything past the handshake except record
    // headers. The server's Hello tail (the padding still unread below) was
    // written before its masking layer engaged, so the inbound side skips
    // exactly those bytes (xray `NewXorConn(.., 0, peerPaddingLen)`).
    let (out_xor, in_xor) = if cfg.mode == MlkemMode::Random {
        let ticket_iv: [u8; 16] = flight[pfs_len..pfs_len + 16]
            .try_into()
            .expect("ticket slice");
        (
            Some(new_ctr(&united, &iv)),
            Some(new_ctr(&united, &ticket_iv)),
        )
    } else {
        (None, None)
    };

    Ok(CommonConn {
        inner: stream,
        aead: self_aead,
        peer_aead,
        peer_padding: Some(vec![0u8; peer_padding_len]),
        pad_pos: 0,
        in_buf: Vec::new(),
        in_pos: 0,
        phase: ReadPhase::Padding,
        header: [0; HEADER_LEN],
        header_pos: 0,
        payload: Vec::new(),
        payload_pos: 0,
        out_pending: Vec::new(),
        out_pos: 0,
        out_xor,
        in_xor,
    })
}

// ── timeout helpers ────────────────────────────────────────────────────────

async fn write_all_timeout(
    stream: &mut BoxStream,
    data: &[u8],
    step: &'static str,
) -> Result<(), NativeError> {
    use tokio::io::AsyncWriteExt;
    let timeout = timeouts::PROTOCOL;
    tokio::time::timeout(timeout, stream.write_all(data))
        .await
        .map_err(|_| NativeError::Timeout {
            step,
            limit: timeout,
        })?
        .map_err(NativeError::from)
}

async fn read_exact_timeout(
    stream: &mut BoxStream,
    len: usize,
    step: &'static str,
) -> Result<Vec<u8>, NativeError> {
    use tokio::io::AsyncReadExt;
    let timeout = timeouts::PROTOCOL;
    let mut buf = vec![0u8; len];
    tokio::time::timeout(timeout, stream.read_exact(&mut buf))
        .await
        .map_err(|_| NativeError::Timeout {
            step,
            limit: timeout,
        })?
        .map_err(NativeError::from)?;
    Ok(buf)
}

// ── post-handshake record connection ───────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadPhase {
    /// Draining the sealed server-hello padding (raw — written before the
    /// random-mode masking engaged).
    Padding,
    /// Collecting the 5-byte record header (never masked).
    Header,
    /// Collecting the record payload (masked under `random`).
    Payload,
}

/// The encrypted tunnel (xray `CommonConn`).
///
/// Outbound writes are chunked to ≤8192 bytes and sealed as
/// `[23 03 03 len_hi len_lo][AEAD(chunk, aad=header)]` with an
/// auto-incrementing nonce; inbound reads mirror the framing after draining
/// the server padding. `random` mode XOR-masks ONLY the 5-byte record
/// headers (per-direction CTR streams keyed with the united key); the AEAD
/// payloads travel clear and each CTR advances 5 bytes per record (xray
/// `XorConn`).
///
/// Deviation from upstream: the `MaxNonce` re-key branch (xray re-derives the
/// AEAD from the record bytes after 2⁹⁶ records) is not implemented — it is
/// unreachable at any realistic traffic volume.
pub struct CommonConn {
    inner: BoxStream,
    aead: WireAead,
    peer_aead: WireAead,
    peer_padding: Option<Vec<u8>>,
    pad_pos: usize,
    in_buf: Vec<u8>,
    in_pos: usize,
    phase: ReadPhase,
    header: [u8; HEADER_LEN],
    header_pos: usize,
    payload: Vec<u8>,
    payload_pos: usize,
    out_pending: Vec<u8>,
    out_pos: usize,
    out_xor: Option<Ctr128BE<Aes256>>,
    in_xor: Option<Ctr128BE<Aes256>>,
}

impl AsyncRead for CommonConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let Self {
            inner,
            peer_aead,
            peer_padding,
            pad_pos,
            in_buf,
            in_pos,
            phase,
            header,
            header_pos,
            payload,
            payload_pos,
            in_xor,
            ..
        } = this;
        loop {
            // Leftover decrypted payload first: never lose a filled record.
            if *in_pos < in_buf.len() {
                let n = std::cmp::min(in_buf.len() - *in_pos, buf.remaining());
                let end = *in_pos + n;
                buf.put_slice(&in_buf[*in_pos..end]);
                *in_pos = end;
                return Poll::Ready(Ok(()));
            }
            match phase {
                ReadPhase::Padding => {
                    let Some(mut padding) = peer_padding.take() else {
                        *phase = ReadPhase::Header;
                        continue;
                    };
                    while *pad_pos < padding.len() {
                        let mut slice = ReadBuf::new(&mut padding[*pad_pos..]);
                        match Pin::new(&mut **inner).poll_read(cx, &mut slice)? {
                            Poll::Ready(()) if slice.filled().is_empty() => {
                                // EOF at a field boundary is a CLEAN end of
                                // stream, not a truncation: Go's
                                // `io.ReadFull` (xray's padding drain) yields
                                // bare `io.EOF` when zero bytes were read and
                                // `ErrUnexpectedEOF` only mid-field. Raising
                                // here made `read_to_end` discard an
                                // already-complete response.
                                *peer_padding = Some(padding);
                                return if *pad_pos == 0 {
                                    Poll::Ready(Ok(()))
                                } else {
                                    Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "vless mlkem: eof in server padding",
                                    )))
                                };
                            }
                            Poll::Ready(()) => *pad_pos += slice.filled().len(),
                            Poll::Pending => {
                                *peer_padding = Some(padding);
                                return Poll::Pending;
                            }
                        }
                    }
                    peer_aead.open_in_place(&mut padding, &[])?;
                    *pad_pos = 0;
                    *header_pos = 0;
                    *phase = ReadPhase::Header;
                }
                ReadPhase::Header => {
                    while *header_pos < HEADER_LEN {
                        let mut byte = [0u8; 1];
                        let mut slice = ReadBuf::new(&mut byte);
                        match Pin::new(&mut **inner).poll_read(cx, &mut slice)? {
                            Poll::Ready(()) if slice.filled().is_empty() => {
                                // Clean end of stream when no header byte has
                                // been read yet (Go `io.ReadFull` semantics);
                                // a partial header is genuine truncation.
                                return if *header_pos == 0 {
                                    Poll::Ready(Ok(()))
                                } else {
                                    Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "vless mlkem: eof in record header",
                                    )))
                                };
                            }
                            Poll::Ready(()) => {
                                header[*header_pos] = byte[0];
                                *header_pos += 1;
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    // random mode: unmask the 5-byte header (xray `XorConn`
                    // masks ONLY headers; payloads stay clear). Applied once
                    // per complete header so the keystream advances exactly
                    // 5 bytes per record.
                    if let Some(ctr) = in_xor {
                        ctr.apply_keystream(header);
                    }
                    let l = decode_length(&header[3..]);
                    if header[0] != 23
                        || header[1] != 3
                        || header[2] != 3
                        || !(MIN_RECORD..=MAX_RECORD).contains(&l)
                    {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vless mlkem: invalid record header",
                        )));
                    }
                    // Reuse the payload allocation across records: `resize`
                    // only allocates when a larger record arrives.
                    payload.clear();
                    payload.resize(l, 0);
                    *payload_pos = 0;
                    *phase = ReadPhase::Payload;
                }
                ReadPhase::Payload => {
                    while *payload_pos < payload.len() {
                        let mut slice = ReadBuf::new(&mut payload[*payload_pos..]);
                        match Pin::new(&mut **inner).poll_read(cx, &mut slice)? {
                            Poll::Ready(()) if slice.filled().is_empty() => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "vless mlkem: eof in record payload",
                                )));
                            }
                            Poll::Ready(()) => *payload_pos += slice.filled().len(),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let plain_len = peer_aead.open_in_place(payload, header)?;
                    payload.truncate(plain_len);
                    // Ping-pong the buffers so both keep their capacity:
                    // `payload` becomes the next record's scratch.
                    std::mem::swap(payload, in_buf);
                    *in_pos = 0;
                    *header_pos = 0;
                    *phase = ReadPhase::Header;
                }
            }
        }
    }
}

impl AsyncWrite for CommonConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let Self {
            inner,
            aead,
            out_pending,
            out_pos,
            out_xor,
            ..
        } = this;
        let mut accepted = 0usize;
        loop {
            // Drive any parked record first; its bytes are this buf's prefix.
            while *out_pos < out_pending.len() {
                match Pin::new(&mut **inner).poll_write(cx, &out_pending[*out_pos..]) {
                    Poll::Ready(Ok(n)) => *out_pos += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        return if accepted > 0 {
                            Poll::Ready(Ok(accepted))
                        } else {
                            Poll::Pending
                        };
                    }
                }
            }
            out_pending.clear();
            *out_pos = 0;
            if accepted >= buf.len() {
                return Poll::Ready(Ok(accepted));
            }
            // Seal the next ≤8192-byte chunk as one record, framed and
            // sealed inside `out_pending` — one copy of the chunk, no
            // `seal` temp, no `record` temp.
            let end = std::cmp::min(buf.len(), accepted + MAX_CHUNK);
            let chunk = &buf[accepted..end];
            let hdr = encode_length_header(chunk.len() + TAG_LEN);
            // random mode masks ONLY the wire header (xray `XorConn`); the
            // AEAD AAD stays the clear header.
            let mut wire_hdr = hdr;
            if let Some(ctr) = out_xor {
                ctr.apply_keystream(&mut wire_hdr);
            }
            out_pending.extend_from_slice(&wire_hdr);
            out_pending.extend_from_slice(chunk);
            aead.seal_append(out_pending, HEADER_LEN, &hdr);
            accepted = end;
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self {
            inner,
            out_pending,
            out_pos,
            ..
        } = &mut *self;
        while *out_pos < out_pending.len() {
            match Pin::new(&mut **inner).poll_write(cx, &out_pending[*out_pos..]) {
                Poll::Ready(Ok(n)) => *out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        out_pending.clear();
        *out_pos = 0;
        Pin::new(&mut **inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self {
            inner,
            out_pending,
            out_pos,
            ..
        } = &mut *self;
        while *out_pos < out_pending.len() {
            match Pin::new(&mut **inner).poll_write(cx, &out_pending[*out_pos..]) {
                Poll::Ready(Ok(n)) => *out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        out_pending.clear();
        *out_pos = 0;
        Pin::new(&mut **inner).poll_shutdown(cx)
    }
}

/// Record header: `23 03 03` + big-endian u16 length (xray `EncodeHeader`).
const fn encode_length_header(l: usize) -> [u8; HEADER_LEN] {
    let [hi, lo] = encode_length(l);
    [23, 3, 3, hi, lo]
}

#[cfg(test)]
mod tests {
    use super::b3;
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    /// [`fake_server`] with an echo limit: after `max_echoes` records the
    /// server returns (dropping the socket), so the peer's close lands exactly
    /// on a record boundary — the shape the clean-EOF test needs.
    async fn fake_server_bounded(
        conn: DuplexStream,
        keys: Vec<ServerKey>,
        x25519_sk: std::sync::Arc<X25519KeyPair>,
        mlkem_sk: leas_tls::crypto::mlkem::SecretKey,
    ) -> std::io::Result<usize> {
        fake_server_limited(conn, keys, x25519_sk, mlkem_sk, MlkemMode::Native, 1).await
    }

    /// An independent server-side implementation of xray
    /// `ServerInstance.Handshake` + the record layer (server.go semantics,
    /// NOT a `CommonConn` twin — the framing is re-derived from the Go
    /// source so symmetric bugs surface). Echoes every received record
    /// back until the client disconnects.
    async fn fake_server(
        conn: DuplexStream,
        keys: Vec<ServerKey>,
        x25519_sk: std::sync::Arc<X25519KeyPair>,
        mlkem_sk: leas_tls::crypto::mlkem::SecretKey,
        mode: MlkemMode,
    ) -> std::io::Result<usize> {
        fake_server_limited(conn, keys, x25519_sk, mlkem_sk, mode, usize::MAX).await
    }

    /// The shared body of [`fake_server`]/[`fake_server_bounded`].
    async fn fake_server_limited(
        mut conn: DuplexStream,
        keys: Vec<ServerKey>,
        x25519_sk: std::sync::Arc<X25519KeyPair>,
        mlkem_sk: leas_tls::crypto::mlkem::SecretKey,
        mode: MlkemMode,
        max_echoes: usize,
    ) -> std::io::Result<usize> {
        let relays_len: usize = keys
            .iter()
            .map(|k| match k {
                ServerKey::X25519(_) => 64,
                ServerKey::Mlkem(_) => MLKEM_CT_LEN + 32,
            })
            .sum::<usize>()
            - 32;

        // ── ClientHello: iv + relays ──
        let mut buf = vec![0u8; IV_LEN + relays_len];
        conn.read_exact(&mut buf).await?;
        let iv: [u8; IV_LEN] = buf[..IV_LEN].try_into().expect("iv");
        let mut relays = buf[IV_LEN..].to_vec();
        let mut nfs_key = Vec::new();
        let mut last_ctr: Option<Ctr128BE<Aes256>> = None;
        let mut off = 0usize;
        for (j, key) in keys.iter().enumerate() {
            if let Some(c) = &mut last_ctr {
                c.apply_keystream(&mut relays[off..off + 32]); // recover this relay
            }
            let index = match key {
                ServerKey::X25519(_) => X25519_LEN,
                ServerKey::Mlkem(_) => MLKEM_CT_LEN,
            };
            if mode != MlkemMode::Native {
                new_ctr(key.bytes(), &iv).apply_keystream(&mut relays[off..off + index]);
            }
            match key {
                ServerKey::X25519(_) => {
                    let mut peer = [0u8; X25519_LEN];
                    peer.copy_from_slice(&relays[off..off + X25519_LEN]);
                    nfs_key = x25519_sk.agree(&peer).expect("agree").to_vec();
                }
                ServerKey::Mlkem(_) => {
                    let ct = leas_tls::crypto::mlkem::Ciphertext::from_bytes(
                        &relays[off..off + MLKEM_CT_LEN],
                    )
                    .expect("ct");
                    nfs_key = Mlkem768::decapsulate(&mlkem_sk, &ct).as_bytes().to_vec();
                }
            }
            if j == keys.len() - 1 {
                break;
            }
            // hash32 chain check (server.go: unexpected hash32 → error). The
            // SAME CTR instance continues into the next hop's unmask.
            let mut c = new_ctr(&nfs_key, &iv);
            let mut got = relays[off + index..off + index + 32].to_vec();
            c.apply_keystream(&mut got);
            assert_eq!(got, b3::hash32(keys[j + 1].bytes()), "hash32 chain");
            last_ctr = Some(c);
            off += index + 32;
        }

        let mut nfs_aead = WireAead::new(&iv, &nfs_key);

        // ── sealed pfs key-exchange length + body ──
        let mut enc_len = [0u8; 18];
        conn.read_exact(&mut enc_len).await?;
        let length = decode_length(&nfs_aead.open(&enc_len, &[])?);
        let mut enc_pfs = vec![0u8; length];
        conn.read_exact(&mut enc_pfs).await?;
        let client_pfs_public = nfs_aead.open(&enc_pfs, &[])?;

        // ── server pfs: encapsulate + ephemeral X25519 ──
        let client_mlkem_pk =
            leas_tls::crypto::mlkem::PublicKey::from_bytes(&client_pfs_public[..1184]).expect("pk");
        let (server_ct, server_ss) = Mlkem768::encapsulate(&client_mlkem_pk).expect("encapsulate");
        let server_x = X25519KeyPair::generate(&ring::rand::SystemRandom::new()).expect("x");
        let mut peer = [0u8; X25519_LEN];
        peer.copy_from_slice(&client_pfs_public[1184..]);
        let x_key = server_x.agree(&peer).expect("agree");
        let mut united = Vec::with_capacity(96);
        united.extend_from_slice(server_ss.as_bytes());
        united.extend_from_slice(x_key.as_slice());
        united.extend_from_slice(&nfs_key);

        let mut server_pfs_public = Vec::with_capacity(MLKEM_CT_LEN + X25519_LEN);
        server_pfs_public.extend_from_slice(server_ct.as_bytes());
        server_pfs_public.extend_from_slice(&server_x.public_key());

        let mut self_aead = WireAead::new(&server_pfs_public, &united);
        let mut peer_aead = WireAead::new(&client_pfs_public, &united);

        // ── ServerHello: [MaxNonce pfs 1136][ticket 32][padlen 18][padding] ──
        let mut ticket_plain = [0u8; 16];
        ring::rand::SystemRandom::new()
            .fill(&mut ticket_plain)
            .expect("rng");
        ticket_plain[..2].copy_from_slice(&encode_length(0)); // seconds = 0

        let mut hello = Vec::new();
        hello.extend(nfs_aead.seal_with(MAX_NONCE, &server_pfs_public, &[]));
        hello.extend(self_aead.seal(&ticket_plain, &[]));
        let pad_len = 40usize;
        hello.extend(self_aead.seal(&encode_length(pad_len - 18), &[]));
        hello.extend(self_aead.seal(&vec![0u8; pad_len - 34], &[]));
        conn.write_all(&hello).await?;

        // ── client padding (nfs-sealed) ──
        let mut enc_len = [0u8; 18];
        conn.read_exact(&mut enc_len).await?;
        // The decoded length is the body CIPHERTEXT length (plaintext + tag).
        let ct_len = decode_length(&nfs_aead.open(&enc_len, &[])?);
        let mut enc_pad = vec![0u8; ct_len];
        conn.read_exact(&mut enc_pad).await?;
        nfs_aead.open(&enc_pad, &[])?;

        // ── record echo loop (random mode masks ONLY the 5-byte headers,
        // xray `XorConn`; payloads clear, keystream +5 B/record) ──
        let mut out_ctr = (mode == MlkemMode::Random).then(|| new_ctr(&united, &ticket_plain));
        let mut in_ctr = (mode == MlkemMode::Random).then(|| new_ctr(&united, &iv));
        let mut echoes = 0usize;
        loop {
            if echoes >= max_echoes {
                // Deliberate close on a record boundary (the clean-EOF test).
                return Ok(length);
            }
            let mut hdr = [0u8; HEADER_LEN];
            if let Err(e) = conn.read_exact(&mut hdr).await {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    // The first flight's sealed pfs length, for the caller to
                    // assert on (a fresh dial must never send the ticket form).
                    return Ok(length);
                }
                return Err(e);
            }
            if let Some(c) = &mut in_ctr {
                c.apply_keystream(&mut hdr);
            }
            let l = decode_length(&hdr[3..]);
            let mut payload = vec![0u8; l];
            conn.read_exact(&mut payload).await?;
            let plain = peer_aead.open(&payload, &hdr)?;
            let sealed = self_aead.seal(&plain, &hdr);
            let mut wire_hdr = hdr;
            if let Some(c) = &mut out_ctr {
                c.apply_keystream(&mut wire_hdr);
            }
            let mut record = Vec::with_capacity(HEADER_LEN + l);
            record.extend_from_slice(&wire_hdr);
            record.extend_from_slice(&sealed);
            conn.write_all(&record).await?;
            echoes += 1;
        }
    }

    fn test_keys() -> (
        Vec<ServerKey>,
        std::sync::Arc<X25519KeyPair>,
        leas_tls::crypto::mlkem::SecretKey,
    ) {
        let x = X25519KeyPair::generate(&ring::rand::SystemRandom::new()).expect("x25519");
        let (pk, sk) = Mlkem768::generate_keypair();
        (
            vec![
                ServerKey::X25519(x.public_key()),
                ServerKey::Mlkem(pk.as_bytes().to_vec()),
            ],
            std::sync::Arc::new(x),
            sk,
        )
    }

    /// Returns the FIRST FLIGHT's sealed pfs length as the fake server read it,
    /// so a caller can assert on the wire shape rather than on bytes (which are
    /// randomised per connection).
    async fn roundtrip(mode: MlkemMode, padding: &str, payload_len: usize, seconds: u32) -> usize {
        let (keys, x_sk, mlkem_sk) = test_keys();
        let cfg = EncryptionConfig {
            mode,
            seconds,
            padding_lens: parse_padding(padding).expect("padding").0,
            padding_gaps: parse_padding(padding).expect("padding").1,
            keys: keys.clone(),
        };
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(async move {
            match fake_server(
                server_side,
                keys.clone(),
                std::sync::Arc::clone(&x_sk),
                mlkem_sk,
                mode,
            )
            .await
            {
                Ok(len) => len,
                Err(e) => {
                    eprintln!("FAKE SERVER ERR: {e}");
                    0
                }
            }
        });

        let mut conn = handshake(Box::new(client_side), &cfg)
            .await
            .expect("handshake");

        // Exercise the record layer: a payload larger than MAX_CHUNK forces
        // multi-record writes; read it back through the echo server.
        let payload: Vec<u8> = (0..payload_len)
            .map(|i| u8::try_from(i % 251).expect("in range"))
            .collect();
        conn.write_all(&payload).await.expect("write");
        conn.flush().await.expect("flush");

        let mut got = Vec::new();
        let mut chunk = vec![0u8; 4096];
        while got.len() < payload.len() {
            let n = tokio::time::timeout(std::time::Duration::from_secs(5), conn.read(&mut chunk))
                .await
                .expect("read timeout")
                .expect("read");
            assert!(n > 0);
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got, payload, "roundtrip payload");

        drop(conn);
        server.await.expect("server task")
    }

    #[tokio::test]
    async fn roundtrip_native_default_padding() {
        roundtrip(MlkemMode::Native, "", 10_000, 0).await;
    }

    #[tokio::test]
    async fn roundtrip_xorpub_custom_padding() {
        roundtrip(
            MlkemMode::XorPub,
            "100-35-70.0-0-0.50-100-200.0-0-0",
            5_000,
            0,
        )
        .await;
    }

    #[tokio::test]
    async fn roundtrip_random_default_padding() {
        roundtrip(MlkemMode::Random, "", 17_345, 0).await;
    }

    #[tokio::test]
    async fn roundtrip_random_custom_padding() {
        roundtrip(MlkemMode::Random, "100-35-111.0-0-0", 100, 0).await;
    }

    /// A peer that EOFs at a RECORD BOUNDARY is a clean end of stream, not a
    /// truncation.
    ///
    /// The reference frames with `io.ReadFull`, which returns bare `io.EOF`
    /// when zero bytes were read into a field and `ErrUnexpectedEOF` only
    /// mid-field. Our reader used to raise `UnexpectedEof` in both cases, so a
    /// caller doing `read_to_end` (the probe; any collect-the-body consumer)
    /// threw away an ALREADY COMPLETE response — the pq-enc e2e row's
    /// `status 0 body ""` for a tunnel that had delivered `HTTP/1.1 200 OK`.
    ///
    /// The fake server echoes ONE record and closes; the client must read the
    /// payload back and then see a clean EOF that loses nothing.
    #[tokio::test]
    async fn eof_at_a_record_boundary_is_clean() {
        let (keys, x_sk, mlkem_sk) = test_keys();
        let cfg = EncryptionConfig {
            mode: MlkemMode::Native,
            seconds: 0,
            padding_lens: Vec::new(),
            padding_gaps: Vec::new(),
            keys: keys.clone(),
        };
        let (client_side, server_side) = tokio::io::duplex(1 << 16);
        // The stock fake server loops until the CLIENT closes. This variant
        // stops right after the first echo, so the close lands on a record
        // boundary — exactly the shape a real core produces when it finishes
        // a response and tears the tunnel down.
        let server = tokio::spawn(fake_server_bounded(server_side, keys, x_sk, mlkem_sk));

        let mut conn = handshake(Box::new(client_side), &cfg)
            .await
            .expect("handshake");
        let payload = b"clean-eof-body".to_vec();
        conn.write_all(&payload).await.expect("write");
        conn.flush().await.expect("flush");

        // `read_to_end` MUST return the payload rather than an error.
        let mut got = Vec::new();
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read_to_end(&mut got),
        )
        .await
        .expect("read_to_end timeout");
        assert!(res.is_ok(), "clean EOF must not error: {res:?}");
        assert_eq!(got, payload, "the complete body must survive the EOF");
        server.abort();
    }

    /// A FRESH dial never takes the 0-RTT (ticket) path — for EITHER mode.
    ///
    /// The reference sends the ticket form only while it holds a live ticket
    /// from a *previous* connection (`encryption/client.go:113-121`: `Seconds >
    /// 0 && time.Now().Before(i.Expire) && i.Ticket`, and `i.Expire`/`i.Ticket`
    /// are set at `:188-193` from the server's own hello). A probe dials once
    /// per attempt, so `0rtt` and `1rtt` accounts are indistinguishable on a
    /// fresh dial — which is why the mode is not a differential for the pq-enc
    /// interop, and why §5.8's "they behave identically" needed a vehicle that
    /// is not byte equality (the first flight is randomised: a per-connection
    /// IV and a fresh ML-KEM encapsulation, so two connects can never match).
    ///
    /// The RNG-independent vehicle is STRUCTURAL: the sealed first-flight length
    /// is the 1-RTT pfs length in both cases, never the ticket form's 32. A
    /// future change that lets the mode affect the first flight fails here.
    #[tokio::test]
    async fn a_fresh_dial_never_takes_the_zero_rtt_path() {
        // The sealed length field carries the CIPHERTEXT length, i.e. the pfs
        // plaintext (1184-B ML-KEM pk + 32-B X25519 pk) plus the 16-byte tag —
        // `PFS_EXCHANGE_LEN` minus its own 18-byte sealed length field.
        const PFS_SEALED_LEN: usize = PFS_EXCHANGE_LEN - 18;
        // The ticket form seals `EncodeLength(32)` and the server reads exactly
        // 32 bytes and `Open`s them, so 32 IS ciphertext-plus-tag: the sealed
        // ticket already contains it (`TICKET_LEN`, the server flight's own
        // constant). Not `32 + TAG_LEN` — that double-counts.
        const TICKET_FORM_LEN: usize = TICKET_LEN;
        assert_ne!(PFS_SEALED_LEN, TICKET_FORM_LEN, "the two forms differ");
        for (seconds, label) in [(0_u32, "1rtt"), (1, "0rtt")] {
            let observed = roundtrip(MlkemMode::Native, "", 64, seconds).await;
            assert_eq!(
                observed, PFS_SEALED_LEN,
                "{label} must send the 1-RTT pfs form on a fresh dial, not the ticket form"
            );
        }
    }

    /// Does our ML-KEM keypair expansion match Go's?
    ///
    /// `mlkem_enc_pair` derives the account keypair from a 64-byte FIPS 203 seed
    /// (`d || z`) through OUR `keypair_from_seed`, while the server's decryption
    /// string carries that same seed for Go's `mlkem.NewDecapsulationKey768` to
    /// expand. If the two expansions differ, the client's `ek` targets a key the
    /// server never holds — and the symptom would be exactly the one the pq-enc
    /// row shows: the handshake appears to complete one way, then the tunnel
    /// EOFs before the response header.
    ///
    /// The constants are ONE MATCHED PAIR from the reference's own generator
    /// (`xray vlessenc`), so they are fixed evidence rather than anything we
    /// produced: `decryption` carries the 64-byte seed, `encryption` the
    /// 1184-byte encapsulation key expanded from it. Equal means our expansion
    /// agrees with Go's and the pq-enc divergence is in the client's sealing or
    /// framing; unequal means `keypair_from_seed` itself is the bug — and that
    /// would also explain why `mlkem_enc_pair`'s own server string never matches
    /// the `ek` its client string carries.
    ///
    /// Hermetic: no cores, no e2e case, no network.
    #[test]
    fn keypair_from_seed_matches_the_reference_expansion() {
        const SEED_HEX: &str = concat!(
            "5c3f1db5c450330cc7cf63372b58aa3b3f774d741d837410fa82e906e48645caf9efa7611e4fe60becd1e9caffb2bda4",
            "b9c7ae9bf6f7204153155c0b01345a80"
        );
        const EK_HEX: &str = concat!(
            "01275a02ec24b4133372859569fa6058d2350c5252cca6640ecc6c10663f148577f21b66c4a230ec78b38db737c9d1a5",
            "c5fb3d28f095b8b0a726b377bde9433bd3c7960274d873507d53763b8b8c850b938ac3235510394ca37c99d2ba1beb09",
            "b1d2c5eb32986df658eefb32f0048556a2c70af59dd4034784eba7b6a4b9412a100aac2aebb347100a88ea7baf098849",
            "fd63b0870ac332e52d98ab51cdf5a0a571530c41a65919965e66862bd693e0964341857ab6413d58b7459c206969aa5f",
            "9f558bc17a806927c7690205e8063b9ee477baeba6fef06f1f4c361e261a9f69ab8670a425b0b5a99025f2d86ea8a03b",
            "55e330bd0086cfb65147452aa6877625e527de2995e6559262aa167f520df26156569893ed34cdd266554df11f26bb28",
            "3242cb89e95cd393964b74cf85d7589a40c999e233c558862a043e83e601e3f3ce98f81ec587ba8ddb387a727064202c",
            "af32abad338535d78a59a362c30c72da5933189c15df778f7e41159951bb74e38a15e91c7c36646fd84cbe95156d333c",
            "194a61bd4940fcc4a4d5700bd9050b7037b2f65b16d97b9de0b89a040102223b899e32aa31c857aa8684694530126244",
            "1a3bc7496648b40589df76083c49cb2767469ac84e9403497dc33c4e43b5e3ba09f2db200e22bd2411c9893c298ff437",
            "6b22b77fc765b8b85386e653700055ae56bfe8dc06bd8229830bc83c36c4abb6ba3377997c94a2790ccbe3081a68a850",
            "d093aa8812c933672c3f20b0299930a40b22f57694f40870d9746867ba1dbe0c69821ac275c52898d9cb5171a9c5ca91",
            "7f9308b0541bfb19ba667959ca21236c81cb0a681c84db490a3a69469a7745a5afca28951e561b8a009f21009a5bfacd",
            "fca87335b9cfa5bb50727bb029f294460b16c8b0328e927fb1419252f924b8bbaf4a8cc16e809cf825c5fea3bbedf2c4",
            "2820a249e22b6373c4a6026bb157507866002e21388660613080707be12abf27111cd5c3e6ecba84314f90216877e18c",
            "e62c38c77157d7b0bbe917c4d3502e0839590f9b99be877f5276bfcaa8a4d7082a4502850ea50abd4290de35ac600870",
            "641ac39c71699a3a003a63b161965e3c6a2d50cb0f17c125a0748af3023c040466aa86159570a755128289f66dcd6278",
            "055109bb267c1a82106b922759b015debcbc1012aec76c770c16cf8aec4c2619bbfbb244bb55a124b435f9420c0b25c5",
            "f644500e71a0a5c3097cc10bfc3c8870e49f4355c9e32bca88147575258fdeb316b6728c3fbc74706ab0697c5bfcf124",
            "53d9a3ac2ba634f56d3509510d06b6bbf15ddbe1cf87610a56c1471b217d0ca7c7668a81c8541c697283547b15dda342",
            "2e6c7c8fd992597741c3881683aaacd4bb670bb804701bcdd5c414dab75dcc928aecd0a89ff0b22d95b0c4356a04560e",
            "657645ee26877a98882a137b9972ca5a739c161790ef87ce9e00b0cd449f877651e083234cb3009b3a4ec0eb06534422",
            "e15b621b06a9eb152eec61624fe3a390e41fec371477c3b7fb993c05711d455640ed544d2891c3d2e51ebc216e3b8579",
            "3f6a0ecccc1b36c44cf01745d8d32fb04a67d32820d3aa7f93b9aea46b257fc11d488124e7187535d353b01a28ab9991",
            "f8e12c49e76b73553c000e9104c0a1aa49ae7cb2e57a9b516359706772bc9e4f"
        );
        let seed: [u8; 64] = unhex(SEED_HEX).try_into().expect("64-byte FIPS 203 seed");
        let expected = unhex(EK_HEX);
        assert_eq!(expected.len(), 1184, "ML-KEM-768 ek length");
        let (ek, _) = Mlkem768::keypair_from_seed(&seed);
        assert_eq!(
            ek.as_bytes(),
            expected.as_slice(),
            "our keypair_from_seed must expand the reference's seed to the reference's ek"
        );
    }

    // ── Go-pinned keystream vectors (2026-09-18) ─────────────────────────
    //
    // The `roundtrip_*` tests and `random_mode_masks_headers_only` compare
    // this implementation against itself (our own server double, our own
    // `new_ctr`), so a wrong mask passes on both ends. These constants come
    // from Go 1.27.1 using xray's own libraries — `lukechampine.com/blake3`
    // `DeriveKey("VLESS", key)` plus `crypto/aes` under `cipher.NewCTR` — and
    // are what makes the mask wire-compatible with the peer rather than
    // merely self-consistent. Generator: derive `k = DeriveKey("VLESS", key)`
    // then `cipher.NewCTR(aes.NewCipher(k), iv).XORKeyStream(out, out)` over
    // zeros; inputs are `iv = 0..15`, keys/secret = `[n + 0..31]`.

    /// Decode a hex string (KAT constants stay readable and copy-pasteable
    /// from their sources).
    fn unhex(s: &str) -> Vec<u8> {
        assert!(
            s.len().is_multiple_of(2),
            "hex string must have an even length"
        );
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(out, "{b:02x}").expect("string write");
        }
        out
    }

    fn ramp(len: usize, base: u8) -> Vec<u8> {
        (0..len)
            .map(|i| base.wrapping_add(u8::try_from(i).expect("small len")))
            .collect()
    }

    /// The raw counter-mode primitive against the published vector: NIST SP
    /// 800-38A F.5.5 (CTR-AES256.Encrypt, block 1). Pins `Ctr128BE`'s
    /// semantics — the 16-byte IV is the initial big-endian counter block,
    /// which is exactly what makes this equal to Go's `cipher.NewCTR`.
    #[test]
    fn nist_sp800_38a_aes256_ctr_matches_the_published_vector() {
        let key: [u8; 32] =
            unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
                .try_into()
                .expect("32-byte key");
        let iv: [u8; 16] = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
            .try_into()
            .expect("16-byte counter block");
        let mut buf = unhex("6bc1bee22e409f96e93d7e117393172a");
        Ctr128BE::<Aes256>::new(&key.into(), (&iv).into()).apply_keystream(&mut buf);
        assert_eq!(hex(&buf), "601ec313775789a5b7a7f504bbf3d228");
    }

    /// `new_ctr`'s composition (blake3 `DeriveKey("VLESS", ..)` then AES-256
    /// CTR) against Go/xray bytes.
    #[test]
    fn xray_new_ctr_keystream_matches_go() {
        let iv: [u8; 16] = ramp(16, 0).try_into().expect("16 bytes");
        let key: [u8; 32] = ramp(32, 0x40).try_into().expect("32 bytes");
        let mut ks = [0u8; 32];
        new_ctr(&key, &iv).apply_keystream(&mut ks);
        assert_eq!(
            hex(&ks),
            "c7dc79c22501a8db2f0c846f64e623c6ddf364bce1581b178a78a7bcb5f3c16d"
        );
    }

    /// The relay-chain masking order against Go bytes: (a) `hash32` of the
    /// next server key masked by THIS hop's shared secret, and (b) the next
    /// block, where that same CTR instance CONTINUES from the `hash32` region
    /// into the block (offset 32) while the block's own server-key stream
    /// starts at 0. Restarting the stream per block — a plausible
    /// "simplification" — breaks (b) and the peer rejects the chain.
    #[test]
    fn xray_relay_chain_masking_matches_go() {
        let iv: [u8; 16] = ramp(16, 0).try_into().expect("16 bytes");
        let k1: [u8; 32] = ramp(32, 0x80).try_into().expect("32 bytes");
        let s0: [u8; 32] = ramp(32, 0xa0).try_into().expect("32 bytes");

        let mut hash_region = b3::hash32(&k1);
        new_ctr(&s0, &iv).apply_keystream(&mut hash_region);
        assert_eq!(
            hex(&hash_region),
            "087f1ddc1f178975c335512d7de1e7c6dd0029ba66d549cd226806003de2a45e"
        );

        let mut block1 = [0u8; 64];
        new_ctr(&k1, &iv).apply_keystream(&mut block1);
        let mut continuing = new_ctr(&s0, &iv);
        let mut consumed = [0u8; 32];
        continuing.apply_keystream(&mut consumed);
        continuing.apply_keystream(&mut block1[..32]);
        assert_eq!(
            hex(&block1),
            "b817a575de017b6239fcf7e718acf8ef813d0ae423115721d061300e56c6130ad3a01296603a8af67680d643656e443edb29a859441774f29daa327c664440db"
        );
    }

    /// Pins the random-mode masking semantics against xray `XorConn`
    /// (xor.go): ONLY the 5-byte record headers are masked on the wire, the
    /// AEAD payloads travel clear (AAD = the CLEAR header), and the
    /// keystream advances exactly 5 bytes per record.
    #[tokio::test]
    async fn random_mode_masks_headers_only() {
        let key = [7u8; 32];
        let iv = [9u8; 16];
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let mut conn = CommonConn {
            inner: Box::new(client),
            aead: WireAead::new(&iv, &key),
            peer_aead: WireAead::new(&iv, &key),
            peer_padding: None,
            pad_pos: 0,
            in_buf: Vec::new(),
            in_pos: 0,
            phase: ReadPhase::Header,
            header: [0u8; HEADER_LEN],
            header_pos: 0,
            payload: Vec::new(),
            payload_pos: 0,
            out_pending: Vec::new(),
            out_pos: 0,
            out_xor: Some(new_ctr(&key, &iv)),
            in_xor: None,
        };

        let payload: Vec<u8> = (0u8..100).collect();
        let clear_hdr = encode_length_header(payload.len() + TAG_LEN);
        let wire_len = HEADER_LEN + payload.len() + TAG_LEN;

        for rec in 0..2usize {
            conn.write_all(&payload).await.expect("write");
            conn.flush().await.expect("flush");

            // Independent reference seal: fresh AEAD pre-advanced to the
            // same nonce sequence number (`rec`).
            let mut reference = WireAead::new(&iv, &key);
            for _ in 0..rec {
                reference.seal(&[], &[]);
            }
            let expect_payload = reference.seal(&payload, &clear_hdr);

            // Keystream window at byte offset 5*rec — proves the CTR
            // advanced by exactly one header per record.
            let mut ctr = new_ctr(&key, &iv);
            let mut skip = vec![0u8; HEADER_LEN * rec];
            ctr.apply_keystream(&mut skip);
            let mut ks = [0u8; HEADER_LEN];
            ctr.apply_keystream(&mut ks);
            let masked_hdr: Vec<u8> = clear_hdr.iter().zip(ks).map(|(a, b)| a ^ b).collect();

            let mut wire = vec![0u8; wire_len];
            server.read_exact(&mut wire).await.expect("wire read");
            assert_ne!(&wire[..HEADER_LEN], &clear_hdr[..], "header masked");
            assert_eq!(&wire[..HEADER_LEN], &masked_hdr[..], "rec {rec} header");
            assert_eq!(
                &wire[HEADER_LEN..],
                &expect_payload[..],
                "rec {rec} payload clear"
            );
        }
    }

    /// The config builder decodes base64url keys and rejects bad segments.
    #[test]
    fn config_from_parsed_string() {
        use base64::Engine as _;
        let x = X25519KeyPair::generate(&ring::rand::SystemRandom::new()).expect("x");
        let key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x.public_key());
        let value = format!("mlkem768x25519plus.native.1rtt.100-35-70.0-0-0.{key_b64}");
        let parsed = leas_proto::proto_spec::parse_mlkem_encryption(&value)
            .expect("parse")
            .expect("is mlkem");
        let cfg = EncryptionConfig::try_from_parsed(&parsed).expect("config");
        assert_eq!(cfg.mode, MlkemMode::Native);
        assert_eq!(cfg.seconds, 0); // 1rtt → xray Seconds=0 (no 0-RTT resume)
        assert_eq!(cfg.keys.len(), 1);
        assert_eq!(cfg.keys[0].bytes(), x.public_key().as_slice());

        // A malformed key segment is rejected at parse time.
        let bad = format!("mlkem768x25519plus.native.0rtt.{key_b64}!!!");
        assert!(leas_proto::proto_spec::parse_mlkem_encryption(&bad).is_err());
    }

    /// Padding validation mirrors xray `ParsePadding` bounds.
    #[test]
    fn padding_validation() {
        assert!(parse_padding("100-35-70.0-0-0").is_ok());
        assert!(parse_padding("50-35-70").is_err()); // first probability < 100
        assert!(parse_padding("100-34-70").is_err()); // first min < 35
        assert!(parse_padding("100-35-70.0-0").is_err()); // missing slot
        let big = "100-35-65535.".repeat(3);
        assert!(parse_padding(big.trim_end_matches('.')).is_err()); // total > 65553
    }
}
