//! mKCP datagram masks — Xray's `finalmask` `header-*` / `mkcp-original` /
//! `mkcp-aes128gcm` family.
//!
//! A mKCP share link carries two obfuscation knobs, and Xray 26 turns them
//! into a mask chain with a fixed wire shape:
//!
//! - `header_type` → a camouflage prefix: `srtp`, `utp`, `wechat` /
//!   `wechat-video`, `dtls`, `wireguard`, `dns`.
//! - `seed` → an AES-128-GCM envelope, key `SHA-256(seed)[..16]`, a random
//!   12-byte nonce ahead of the ciphertext and the 16-byte tag behind it.
//! - no seed → Xray's "original" envelope: a 4-byte FNV-1a hash over the
//!   length-prefixed payload, the 2-byte length, then a running XOR.
//!
//! The envelope is OUTERMOST and the camouflage prefix rides INSIDE it
//! (`envelope(prefix || payload)`). That is what the released core
//! (26.3.27, `finalmask.NewUdpmaskManager`) produces for a config whose
//! `finalmask.udp` array lists the envelope before the header — the order
//! v2rayN emits for a kcp outbound. Header state — the srtp/utp/wechat
//! counters, the dtls epoch/sequence/length walk — is per-connection, so a
//! chain belongs to exactly one dial.
//!
//! Reference: `thirdparty/Xray-core` at tag `v26.3.27`,
//! `transport/internet/finalmask/{mkcp,header}/**`. The vectors in the tests
//! below were produced by that Go implementation (or by its fixed constants),
//! not by this module.

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{AeadInOut as _, KeyInit as _, Nonce};
use sha2::{Digest as _, Sha256};

/// Xray `simple.Overhead`: 4-byte hash + 2-byte length.
const FNV_ENVELOPE: usize = 6;
/// AES-GCM explicit nonce ahead of the ciphertext.
const AES_NONCE: usize = 12;
/// AES-GCM tag behind the ciphertext.
const AES_TAG: usize = 16;
/// FNV-1a/32 offset basis and prime (the hash `original` uses).
const FNV_OFFSET: u32 = 2_166_136_261;
const FNV_PRIME: u32 = 16_777_619;
/// Xray's `mkcp-legacy` default DNS domain (`MkcpLegacy.Build`, empty value).
const DNS_DEFAULT_DOMAIN: &str = "www.baidu.com";
/// `header/srtp`: the fixed SRTP version/flags word (the counter follows it).
const SRTP_HEADER: u16 = 0xB5E8;
/// `header/utp`: the fixed header/extension bytes of a STUN-like packet.
const UTP_HEADER: u8 = 1;

/// Why a datagram was not unmasked. Both error variants mean "drop it": a
/// masked datagram that fails validation is indistinguishable from a stray
/// packet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MaskError {
    /// Fewer bytes than the mask's own overhead.
    #[error("mKCP mask: datagram shorter than the mask overhead")]
    Short,
    /// The envelope did not authenticate (wrong key/seed, or not a mask
    /// datagram at all).
    #[error("mKCP mask: datagram did not authenticate")]
    Auth,
    /// `header_type` names a camouflage header this build does not implement.
    /// Refused rather than ignored: the peer would drop every datagram and the
    /// dial would hang instead of failing loudly.
    #[error("mKCP mask: unsupported header_type {0:?}")]
    UnknownHeader(String),
    /// A DNS camouflage domain is not representable as a DNS name.
    #[error("mKCP mask: invalid dns domain {0:?}")]
    BadDomain(String),
}

/// Whether `header_type` names a camouflage prefix this build implements.
///
/// The capability gate calls this instead of matching the names itself, so the
/// accepted set cannot drift from what the dial can actually frame.
#[must_use]
pub fn header_supported(name: &str) -> bool {
    Header::parse(name).is_ok()
}

/// One mask chain. `None` from [`MaskChain::from_settings`] means bare mKCP.
#[derive(Debug)]
pub struct MaskChain {
    header: Option<Header>,
    inner: Inner,
}

#[derive(Debug)]
enum Inner {
    /// Xray `mkcp-original` (`simple` in Go).
    Fnv,
    /// `mkcp-aes128gcm`: the seed is the password, `SHA-256(seed)[..16]` the key.
    Aes(Box<Aes128Gcm>),
}

impl MaskChain {
    /// Build the chain a link's obfuscation knobs describe.
    ///
    /// `None` when neither knob is set: a bare mKCP datagram, which is what a
    /// server with no `finalmask` expects (the legacy-core shape the e2e rows
    /// pin). v2rayN always emits an `original` entry for kcp — a share link
    /// cannot say that, so a v2rayN-configured server without `headerType` or
    /// `seed` is not dialable from a link and is not guessed at here.
    pub fn from_settings(
        header_type: Option<&str>,
        seed: Option<&str>,
    ) -> Result<Option<Self>, MaskError> {
        let seed = seed.filter(|s| !s.is_empty());
        let header = header_type.map(Header::parse).transpose()?.flatten();
        if header.is_none() && seed.is_none() {
            return Ok(None);
        }
        let inner = match seed {
            Some(seed) => {
                let mut digest = Sha256::new();
                digest.update(seed.as_bytes());
                let key = digest.finalize();
                Inner::Aes(Box::new(
                    Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| MaskError::Auth)?,
                ))
            }
            None => Inner::Fnv,
        };
        Ok(Some(Self { header, inner }))
    }

    /// Bytes the mask adds to every datagram (for MTU budgeting).
    #[must_use]
    pub fn overhead(&self) -> usize {
        let inner = match &self.inner {
            Inner::Fnv => FNV_ENVELOPE,
            Inner::Aes(_) => AES_NONCE + AES_TAG,
        };
        self.header.as_ref().map_or(inner, |h| h.size() + inner)
    }

    /// Wrap one KCP datagram. Header counters advance here, once per packet.
    #[must_use]
    pub fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(self.overhead() + payload.len());
        match &mut self.header {
            Some(header) => header.write(&mut framed, payload),
            None => framed.extend_from_slice(payload),
        }
        match &self.inner {
            Inner::Fnv => fnv_seal(&framed),
            Inner::Aes(cipher) => aes_seal(cipher, &framed),
        }
    }

    /// Unwrap one datagram in place, returning the KCP payload.
    ///
    /// Takes `&self`: the receive direction carries no state (the envelopes are
    /// stateless and a prefix is skipped by length), so the reader half needs
    /// no lock shared with the writer's counters.
    pub fn open<'a>(&self, datagram: &'a mut [u8]) -> Result<&'a mut [u8], MaskError> {
        let body = match &self.inner {
            Inner::Fnv => fnv_open(datagram)?,
            Inner::Aes(cipher) => aes_open(cipher, datagram)?,
        };
        match &self.header {
            Some(header) => {
                let skip = header.size();
                if body.len() <= skip {
                    return Err(MaskError::Short);
                }
                Ok(&mut body[skip..])
            }
            None => Ok(body),
        }
    }
}

/// Camouflage prefix. Sizes, fixed bytes and counter starts mirror
/// `finalmask/header/*/conn.go` at v26.3.27; the SEO-randomised fields (srtp
/// number, wechat sn, utp connection id, dtls epoch, dns txid) start from the
/// CSPRNG like `dice.RollUint16`.
#[derive(Debug)]
enum Header {
    Dns {
        base: Vec<u8>,
    },
    Dtls {
        epoch: u16,
        length: u16,
        sequence: u32,
    },
    Srtp {
        number: u16,
    },
    Utp {
        connection_id: u16,
    },
    Wechat {
        sn: u32,
    },
    Wireguard,
}

impl Header {
    /// `Ok(None)` for the two spellings of "no camouflage"; `Err` for a name
    /// nothing frames.
    fn parse(name: &str) -> Result<Option<Self>, MaskError> {
        Ok(Some(match name {
            "" | "none" => return Ok(None),
            // `wechat-video` is the share-link spelling, `wechat` the finalmask
            // one (v2rayN's `KcpHeaderMaskMap`).
            "wechat" | "wechat-video" => Self::Wechat {
                sn: u32::from(roll_u16()),
            },
            "srtp" => Self::Srtp { number: roll_u16() },
            "utp" => Self::Utp {
                connection_id: roll_u16(),
            },
            "dtls" => Self::Dtls {
                epoch: roll_u16(),
                length: 17,
                sequence: 0,
            },
            "wireguard" => Self::Wireguard,
            "dns" => Self::Dns {
                base: dns_base(DNS_DEFAULT_DOMAIN)?,
            },
            other => return Err(MaskError::UnknownHeader(other.to_owned())),
        }))
    }

    const fn size(&self) -> usize {
        match self {
            Self::Dns { base } => base.len(),
            Self::Dtls { .. } | Self::Wechat { .. } => 13,
            Self::Srtp { .. } | Self::Utp { .. } | Self::Wireguard => 4,
        }
    }

    /// Append this packet's prefix and then `payload`, advancing the
    /// per-connection counters.
    fn write(&mut self, out: &mut Vec<u8>, payload: &[u8]) {
        match self {
            Self::Dns { base } => {
                let start = out.len();
                out.extend_from_slice(base);
                // Transaction id: fresh random per packet, like `dice.RollUint16`.
                let txid = roll_u16().to_be_bytes();
                out[start..start + 2].copy_from_slice(&txid);
            }
            Self::Dtls {
                epoch,
                length,
                sequence,
            } => {
                out.extend_from_slice(&[23, 254, 253]);
                out.extend_from_slice(&epoch.to_be_bytes());
                out.extend_from_slice(&[0, 0]);
                out.extend_from_slice(&sequence.to_be_bytes());
                out.extend_from_slice(&length.to_be_bytes());
                *sequence = sequence.wrapping_add(1);
                *length = length.wrapping_add(17);
                if *length > 100 {
                    *length -= 50;
                }
            }
            Self::Srtp { number } => {
                *number = number.wrapping_add(1);
                out.extend_from_slice(&SRTP_HEADER.to_be_bytes());
                out.extend_from_slice(&number.to_be_bytes());
            }
            Self::Utp { connection_id } => {
                out.extend_from_slice(&connection_id.to_be_bytes());
                out.extend_from_slice(&[UTP_HEADER, 0]);
            }
            Self::Wechat { sn } => {
                *sn = sn.wrapping_add(1);
                out.extend_from_slice(&[0xa1, 0x08]);
                out.extend_from_slice(&sn.to_be_bytes());
                out.extend_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            }
            Self::Wireguard => out.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]),
        }
        out.extend_from_slice(payload);
    }
}

/// `dice.RollUint16` — the per-connection counter seeds.
fn roll_u16() -> u16 {
    let mut bytes = [0u8; 2];
    crate::rand::fill_nonsecret(&mut bytes);
    u16::from_be_bytes(bytes)
}

/// `mkcp-original` envelope: `fnv32a(len16 || body) || len16 || body`, then
/// the running `x[i] ^= x[i-4]` XOR forwards.
///
/// Go pads the buffer to a 4-byte multiple before the XOR and truncates the
/// padding afterwards. Those trailing bytes are only ever written, never read
/// by a lower index, so the XOR is identical without them.
fn fnv_seal(payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(FNV_ENVELOPE + payload.len());
    out.extend_from_slice(&[0u8; FNV_ENVELOPE]);
    out.extend_from_slice(payload);
    out[4..6].copy_from_slice(&len.to_be_bytes());
    let hash = fnv32a(&out[4..]);
    out[..4].copy_from_slice(&hash.to_be_bytes());
    for i in 4..out.len() {
        out[i] ^= out[i - 4];
    }
    out
}

fn fnv_open(datagram: &mut [u8]) -> Result<&mut [u8], MaskError> {
    if datagram.len() <= FNV_ENVELOPE {
        return Err(MaskError::Short);
    }
    for i in (4..datagram.len()).rev() {
        datagram[i] ^= datagram[i - 4];
    }
    let want = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    if want != fnv32a(&datagram[4..]) {
        return Err(MaskError::Auth);
    }
    let len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    if len != datagram.len() - FNV_ENVELOPE {
        return Err(MaskError::Auth);
    }
    Ok(&mut datagram[FNV_ENVELOPE..])
}

fn aes_seal(cipher: &Aes128Gcm, payload: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; AES_NONCE];
    crate::rand::fill_nonsecret(&mut nonce);
    let mut out = Vec::with_capacity(AES_NONCE + payload.len() + AES_TAG);
    out.extend_from_slice(&nonce);
    let start = out.len();
    out.extend_from_slice(payload);
    // Infallible for a 12-byte nonce and an empty AAD; the tag is appended by
    // hand so the envelope stays `nonce || ciphertext || tag`.
    let nonce: &Nonce<Aes128Gcm> = (&nonce[..]).try_into().expect("12-byte nonce");
    let tag = cipher
        .encrypt_inout_detached(nonce, b"", (&mut out[start..]).into())
        .expect("AES-128-GCM seal cannot fail");
    out.extend_from_slice(tag.as_slice());
    out
}

fn aes_open<'a>(cipher: &Aes128Gcm, datagram: &'a mut [u8]) -> Result<&'a mut [u8], MaskError> {
    if datagram.len() < AES_NONCE + AES_TAG {
        return Err(MaskError::Short);
    }
    let mut nonce = [0u8; AES_NONCE];
    nonce.copy_from_slice(&datagram[..AES_NONCE]);
    let (_, rest) = datagram.split_at_mut(AES_NONCE);
    let (body, tag) = rest.split_at_mut(rest.len() - AES_TAG);
    let tag: &[u8] = tag;
    let tag: &aes_gcm::aead::Tag<Aes128Gcm> = tag.try_into().map_err(|_| MaskError::Auth)?;
    let nonce: &Nonce<Aes128Gcm> = (&nonce[..]).try_into().map_err(|_| MaskError::Auth)?;
    cipher
        .decrypt_inout_detached(nonce, b"", (&mut body[..]).into(), tag)
        .map_err(|_| MaskError::Auth)?;
    Ok(body)
}

/// FNV-1a/32, the hash `mkcp-original` authenticates with.
fn fnv32a(bytes: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The DNS query prefix: fixed header (txid zeroed, filled per packet), the
/// domain as labels, `A`/`IN`.
fn dns_base(domain: &str) -> Result<Vec<u8>, MaskError> {
    let mut base = Vec::with_capacity(32);
    // Transaction ID (randomised per packet), flags "standard query", one
    // question, no answers/authority/additional records.
    base.extend_from_slice(&[0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in domain.split('.') {
        // A label is at most 63 bytes, and the length byte shares its top bits
        // with the compression markers (RFC 1035 §4.1.4).
        let len = u8::try_from(label.len())
            .ok()
            .filter(|&len| len < 64 && !label.contains('\\'))
            .ok_or_else(|| MaskError::BadDomain(domain.to_owned()))?;
        base.push(len);
        base.extend_from_slice(label.as_bytes());
    }
    base.push(0);
    base.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
    Ok(base)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    fn chain(header: Option<&str>, seed: Option<&str>) -> MaskChain {
        MaskChain::from_settings(header, seed)
            .expect("valid settings")
            .expect("a chain")
    }

    /// The bare `original` envelope: no knob sets it from a link (see
    /// `from_settings`), so the envelope vectors build the chain directly.
    fn envelope_only() -> MaskChain {
        MaskChain {
            header: None,
            inner: Inner::Fnv,
        }
    }

    /// Build a chain whose header starts from fixed counters, so the prefix
    /// bytes are deterministic (the released core seeds them from
    /// `dice.RollUint16`).
    fn with_fixed_header(header: Header) -> MaskChain {
        MaskChain {
            header: Some(header),
            inner: Inner::Fnv,
        }
    }

    /// The `original` envelope is deterministic, so the vector pins the hash,
    /// the length prefix and the XOR direction.
    #[test]
    fn original_envelope_matches_xray() {
        let mut mask = envelope_only();
        assert_eq!(hex(&mask.seal(&[0, 0])), "cdc88e7fcdca8e7f");
        assert_eq!(hex(&mask.seal(&[1, 1])), "a8c615a9a8c414a8");
        assert_eq!(hex(&mask.seal(&[2, 2])), "7fc396877fc19485");
    }

    #[test]
    fn original_envelope_round_trips_and_rejects_tampering() {
        let mut mask = envelope_only();
        let mut wire = mask.seal(b"hello mKCP");
        assert_eq!(mask.open(&mut wire).unwrap(), b"hello mKCP");
        let mut wire = mask.seal(b"hello mKCP");
        let last = wire.len() - 1;
        wire[last] ^= 0x40;
        assert_eq!(mask.open(&mut wire), Err(MaskError::Auth));
    }

    /// The camouflage prefix rides INSIDE the envelope: unwrapping yields
    /// `prefix || payload`. Wireguard's prefix is fully fixed, so the whole
    /// datagram is pinned.
    #[test]
    fn prefix_rides_inside_the_envelope() {
        let mut mask = with_fixed_header(Header::Wireguard);
        let wire = mask.seal(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(hex(&wire), "6a95fe556a99fa556a99fb57699dfe516e95");
        let mut wire = wire;
        assert_eq!(mask.open(&mut wire).unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// Write one framed datagram body (`prefix || payload`) through a header.
    fn framed(header: &mut Header, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        header.write(&mut out, payload);
        out
    }

    /// Each prefix's fixed bytes, and the counters that advance per packet.
    /// The randomised counter starts are checked for shape, not pinned.
    #[test]
    fn header_prefixes_match_xray() {
        let mut srtp = Header::Srtp { number: 0 };
        assert_eq!(hex(&framed(&mut srtp, &[0xAA])[..4]), "b5e80001", "srtp");

        let mut wechat = Header::Wechat { sn: 0 };
        let first = framed(&mut wechat, &[0xAA]);
        let second = framed(&mut wechat, &[0xAA]);
        assert_eq!(hex(&first[..6]), "a10800000001", "wechat: magic + sn 1");
        assert_eq!(hex(&second[..6]), "a10800000002", "wechat: sn advances");
        assert_eq!(hex(&first[6..13]), "00101118302230", "wechat: fixed tail");

        let mut utp = Header::Utp {
            connection_id: 0x1234,
        };
        assert_eq!(hex(&framed(&mut utp, &[0xAA])[..4]), "12340100", "utp");

        let mut dtls = Header::Dtls {
            epoch: 0,
            length: 17,
            sequence: 0,
        };
        assert_eq!(
            hex(&framed(&mut dtls, &[0xAA])[..13]),
            "17fefd00000000000000000011",
            "dtls: epoch 0, seq 0, length 17"
        );
        assert_eq!(
            hex(&framed(&mut dtls, &[0xAA])[..13]),
            "17fefd00000000000000010022",
            "dtls: length walks by 17"
        );
        assert_eq!(
            hex(&framed(&mut dtls, &[0xAA])[..13]),
            "17fefd00000000000000020033",
            "dtls: third length"
        );

        let mut wireguard = Header::Wireguard;
        assert_eq!(hex(&framed(&mut wireguard, &[0xAA])[..4]), "04000000");
    }

    /// The `dns` prefix is a syntactically valid query: fixed header, labels,
    /// root, `A`/`IN`. The transaction id is random, so it is checked, not pinned.
    #[test]
    fn dns_header_is_a_valid_query() {
        let mut header = Header::parse("dns").unwrap().unwrap();
        let base = dns_base(DNS_DEFAULT_DOMAIN).unwrap();
        let first = framed(&mut header, &[9, 9]);
        assert_eq!(first.len(), base.len() + 2);
        // Everything behind the transaction id is byte-identical to the base.
        assert_eq!(&first[2..base.len()], &base[2..]);
        let second = framed(&mut header, &[9, 9]);
        assert_ne!(first[..2], second[..2], "transaction id varies per packet");
        // And the prefix survives the envelope both ways.
        let mut mask = chain(Some("dns"), None);
        let mut wire = mask.seal(&[9, 9]);
        assert_eq!(mask.open(&mut wire).unwrap(), [9, 9]);
    }

    #[test]
    fn dns_base_encodes_the_default_domain() {
        // `www.baidu.com` as length-prefixed labels: the exact bytes Xray's
        // `packDomainName` emits (note the 5-byte `baidu` label).
        assert_eq!(
            hex(&dns_base("www.baidu.com").unwrap()),
            "0000010000010000000000000377777705626169647503636f6d0000010001"
        );
        let long = "a".repeat(64);
        assert_eq!(dns_base(&long).unwrap_err(), MaskError::BadDomain(long));
    }

    /// `seed` selects AES-128-GCM keyed by `SHA-256(seed)[..16]`: 12-byte
    /// nonce, ciphertext, 16-byte tag, and the bytes round-trip.
    #[test]
    fn seed_uses_aes_gcm_envelope() {
        let mut mask = chain(None, Some("secret"));
        let mut wire = mask.seal(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(wire.len(), AES_NONCE + 8 + AES_TAG);
        assert_eq!(mask.open(&mut wire).unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);
        // The nonce varies per datagram, so two seals of one payload differ.
        let again = mask.seal(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_ne!(wire[..AES_NONCE], again[..AES_NONCE]);
        // A wrong seed must not authenticate.
        let other = chain(None, Some("other"));
        let mut wire = mask.seal(b"payload");
        assert_eq!(other.open(&mut wire), Err(MaskError::Auth));
    }

    #[test]
    fn unknown_header_is_refused() {
        assert_eq!(
            MaskChain::from_settings(Some("mux.cool"), None).unwrap_err(),
            MaskError::UnknownHeader("mux.cool".into())
        );
        assert!(
            MaskChain::from_settings(Some("none"), None)
                .unwrap()
                .is_none()
        );
        assert!(MaskChain::from_settings(None, Some("")).unwrap().is_none());
        assert!(
            MaskChain::from_settings(Some(""), Some(""))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn overhead_covers_the_prefix_and_envelope() {
        assert_eq!(envelope_only().overhead(), 6);
        assert!(MaskChain::from_settings(None, None).unwrap().is_none());
        assert_eq!(chain(None, Some("s")).overhead(), 28);
        assert_eq!(chain(Some("srtp"), None).overhead(), 10);
        assert_eq!(chain(Some("dtls"), Some("s")).overhead(), 41);
        assert_eq!(
            chain(Some("dns"), None).overhead(),
            dns_base(DNS_DEFAULT_DOMAIN).unwrap().len() + 6
        );
    }
}
