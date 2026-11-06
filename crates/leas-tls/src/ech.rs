//! `Encrypted ClientHello` (RFC 9849) client side.
//!
//! The client splits its hello in two. `ClientHelloOuter` carries the public
//! name and an `encrypted_client_hello` extension; `ClientHelloInner` carries
//! the real SNI and is sealed with HPKE ([`crate::crypto::hpke`]) under the
//! config the server published in its HTTPS RR. The server answers in the
//! outer hello; acceptance is confirmed by the last 8 bytes of
//! `ServerHello.random` ([`accept_confirmation`]).
//!
//! Only the profile every deployed peer speaks is implemented:
//! `DHKEM(X25519, HKDF-SHA256)` with `HKDF-SHA256` + `AES-128-GCM`, which is what
//! Cloudflare, Fastly and the browsers negotiate. A config list with no such
//! suite is refused by name, never silently downgraded.

use ring::digest;
use ring::hkdf;
use zeroize::Zeroizing;

use crate::crypto::hpke;
use crate::error::{Result, TlsError};

/// `encrypted_client_hello` extension type (RFC 9849 §11.1).
pub const ECH_EXTENSION_TYPE: u16 = 0xfe0d;
/// The HPKE `info` prefix (RFC 9849 §6.1): `"tls ech" || 0x00 || ECHConfig`.
const ECH_INFO_PREFIX: &[u8] = b"tls ech\x00";
/// RFC 9849 §6.1.3: `ClientHelloInner` is padded in 32-byte units.
const PADDING_UNIT: usize = 32;

/// One `ECHConfig` (RFC 9849 §4) with the fields this client reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfig {
    /// Key id the client echoes in the extension.
    pub config_id: u8,
    /// HPKE KEM id (0x0020 for X25519).
    pub kem_id: u16,
    /// HPKE public key for `kem_id`.
    pub public_key: Vec<u8>,
    /// Accepted `(kdf_id, aead_id)` pairs.
    pub cipher_suites: Vec<(u16, u16)>,
    /// Longest name the server will accept in the inner hello.
    pub max_name_length: u8,
    /// Name the server will accept in the outer hello (its public name).
    pub public_name: String,
    /// The `ECHConfig` serialized verbatim — part of the HPKE `info` string,
    /// so it must be preserved byte for byte.
    pub raw: Vec<u8>,
}

/// A decoded `ECHConfigList`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchConfigList {
    pub configs: Vec<EchConfig>,
}

impl EchConfigList {
    /// Parse the link's `ech=` value: a base64 (standard alphabet) encoded
    /// `ECHConfigList`, as v2rayN/v2rayNG emit it from the HTTPS RR.
    pub fn from_base64(value: &str) -> Result<Self> {
        let bytes = base64_decode(value)?;
        Self::parse(&bytes)
    }

    /// Parse the wire form (`ECHConfigList`, RFC 9849 §4.1).
    ///
    /// Each entry is `version(u16) || length(u16) || contents` — the length is
    /// part of the config, and `raw` keeps all four header bytes because the
    /// HPKE `info` string embeds the config verbatim. Unknown versions are
    /// skipped, like a browser does; a list that leaves nothing usable is an
    /// error at [`Self::select`], not here.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let body = read_vec_u16(bytes, "ECHConfigList")?;
        let mut configs = Vec::new();
        let mut rest = body;
        while !rest.is_empty() {
            if rest.len() < 4 {
                return Err(TlsError::Spec("ECHConfig: truncated header".into()));
            }
            let version = u16::from_be_bytes([rest[0], rest[1]]);
            let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            let raw = rest
                .get(..4 + len)
                .ok_or_else(|| TlsError::Spec("ECHConfig: truncated body".into()))?;
            let (entry, tail) = (raw, &rest[4 + len..]);
            rest = tail;
            if version != 0xfe0d {
                continue;
            }
            if let Some(config) = EchConfig::parse_contents(entry) {
                configs.push(config);
            }
        }
        if configs.is_empty() {
            return Err(TlsError::Spec(
                "ECHConfigList carries no usable config".into(),
            ));
        }
        Ok(Self { configs })
    }

    /// The first config this client can actually use.
    pub fn select(&self) -> Result<&EchConfig> {
        self.configs.iter().find(|c| c.supported()).ok_or_else(|| {
            TlsError::Spec(
                "ECHConfigList offers no DHKEM(X25519)/HKDF-SHA256/AES-128-GCM config".into(),
            )
        })
    }
}

impl EchConfig {
    /// Decode one `ECHConfig` from its `version || length || contents` bytes.
    /// `None` for a shape this client cannot use.
    fn parse_contents(raw: &[u8]) -> Option<Self> {
        let mut rest = raw.get(4..)?;
        let config_id = *rest.first()?;
        rest = &rest[1..];
        let kem_id = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
        let public_key = read_vec_u16(&rest[2..], "public_key").ok()?;
        let after_key = 2 + 2 + public_key.len();
        let suites_body = read_vec_u16(rest.get(after_key..)?, "cipher_suites").ok()?;
        let mut cipher_suites = Vec::new();
        let (suites, remainder) = suites_body.as_chunks::<4>();
        if !remainder.is_empty() {
            return None;
        }
        for chunk in suites {
            cipher_suites.push((
                u16::from_be_bytes([chunk[0], chunk[1]]),
                u16::from_be_bytes([chunk[2], chunk[3]]),
            ));
        }
        let tail = rest.get(after_key + 2 + suites_body.len()..)?;
        let max_name_length = *tail.first()?;
        let name_bytes = read_vec_u8(&tail[1..], "public_name").ok()?;
        let public_name = String::from_utf8(name_bytes.to_vec()).ok()?;
        Some(Self {
            config_id,
            kem_id,
            public_key: public_key.to_vec(),
            cipher_suites,
            max_name_length,
            public_name,
            raw: raw.to_vec(),
        })
    }

    /// Whether this config matches the one HPKE profile implemented here.
    fn supported(&self) -> bool {
        matches!(self.kem_id, hpke::KEM_X25519_HKDF_SHA256)
            && self.public_key.len() == 32
            && has_suite(&self.cipher_suites)
    }
}

fn has_suite(suites: &[(u16, u16)]) -> bool {
    suites.contains(&(hpke::KDF_HKDF_SHA256, hpke::AEAD_AES128GCM))
}

/// What the client needs after sealing the inner hello.
#[derive(Debug)]
pub struct SealedEch {
    /// `ECHClientHello.enc` — the HPKE encapsulated key.
    pub enc: Vec<u8>,
    /// `ECHClientHello.payload` — the sealed `ClientHelloInner`.
    pub payload: Vec<u8>,
    /// The inner hello's random, the acceptance confirmation's HKDF salt.
    pub inner_random: [u8; 32],
}

/// Seal a padded `ClientHelloInner` for `config`.
///
/// `outer_aad` is the serialized `ClientHelloOuter` with the ECH payload
/// zeroed (RFC 9849 §6.1.2); it must already have a payload slot of
/// `sealed_len(inner_body.len())` bytes. `inner_body` is the hello WITHOUT
/// its handshake header (RFC 9849 §6.1.3: "the `ClientHelloInner` structure …
/// omitting the Handshake header").
pub fn seal_inner(config: &EchConfig, outer_aad: &[u8], inner_body: &[u8]) -> Result<SealedEch> {
    let mut sender = hpke::Sender::new(&config.public_key, &hpke_info(config))?;
    seal_with(&mut sender, outer_aad, inner_body)
}

/// The HPKE `info` string: `"tls ech" || 0x00 || ECHConfig`.
fn hpke_info(config: &EchConfig) -> Zeroizing<Vec<u8>> {
    let mut info = Zeroizing::new(Vec::with_capacity(ECH_INFO_PREFIX.len() + config.raw.len()));
    info.extend_from_slice(ECH_INFO_PREFIX);
    info.extend_from_slice(&config.raw);
    info
}

/// Seal `inner_body` with a sender whose `enc` is already fixed — what
/// [`build_hellos`] needs, since `enc` goes into the AAD's hello first.
fn seal_with(sender: &mut hpke::Sender, outer_aad: &[u8], inner_body: &[u8]) -> Result<SealedEch> {
    let (padded, inner_random) = pad_inner(inner_body)?;
    let payload = sender.seal(outer_aad, &padded)?;
    Ok(SealedEch {
        enc: sender.enc().to_vec(),
        payload,
        inner_random,
    })
}

/// Sealed length for an inner hello of `inner_len` bytes: the AEAD tag plus
/// the padding to the next 32-byte unit.
#[must_use]
pub const fn sealed_len(inner_len: usize) -> usize {
    let padded = inner_len + (PADDING_UNIT - (inner_len % PADDING_UNIT)) % PADDING_UNIT;
    padded + 16
}

/// Pad a headerless `ClientHelloInner` body to a 32-byte unit (RFC 9849
/// §6.1.3), returning the padded bytes and the inner hello's random.
///
/// The sealed body is `legacy_version || random || sid_len(0) || …` — no
/// handshake header and NO session id: the server fills the session id from
/// the outer hello (uTLS `decodeInnerClientHello` refuses a non-empty one).
fn pad_inner(body: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
    let random = body
        .get(2..34)
        .ok_or_else(|| TlsError::Spec("ClientHelloInner is too short".into()))?;
    let mut inner_random = [0u8; 32];
    inner_random.copy_from_slice(random);
    let mut padded = body.to_vec();
    let rem = padded.len() % PADDING_UNIT;
    let pad = if rem == 0 { 0 } else { PADDING_UNIT - rem };
    padded.resize(padded.len() + pad, 0);
    Ok((padded, inner_random))
}

/// Build the pair of hellos and seal the inner one.
///
/// Returns `(outer, inner, state)`: `outer` is the message that goes on the
/// wire (public name, ECH extension carrying the sealed inner hello), `inner`
/// is the transcript the handshake uses when the server accepts.
///
/// The outer hello is built TWICE-consistent by construction: the first build
/// carries a zeroed payload of exactly the sealed length and is the HPKE AAD
/// (RFC 9849 §6.1.2), then the sealed `enc`/`payload` are written into the
/// same offsets — same lengths, so every other byte (and the transcript
/// layout the server sees) is unchanged.
pub fn build_hellos(
    spec: &crate::spec::ClientHelloSpec,
    params: &crate::hello::BuildParams<'_>,
    config: &EchConfig,
    permute: bool,
) -> Result<(crate::hello::BuiltHello, crate::hello::BuiltHello, EchState)> {
    use crate::hello::build_hello_ordered;

    // RFC 9849 §6.1.1.1: the INNER hello's `encrypted_client_hello` extension
    // carries the inner variant marker (a single 0x01 byte), not a payload —
    // the server rejects an inner hello that repeats the outer's GREASE body.
    let mut inner_spec = spec.clone();
    // RFC 9849 §6.1.3: the inner hello offers TLS 1.3 and nothing older — the
    // server rejects an inner hello that still advertises TLS 1.2 (uTLS
    // `unmarshalInner`: "unsupported versions").
    for ext in &mut inner_spec.extensions {
        if matches!(ext, crate::spec::ExtensionSpec::SupportedVersions(_)) {
            *ext = crate::spec::ExtensionSpec::SupportedVersions(vec![0x0304]);
        }
    }
    let mut inner_marked = false;
    for ext in &mut inner_spec.extensions {
        if matches!(ext, crate::spec::ExtensionSpec::EchGrease { .. }) {
            *ext = crate::spec::ExtensionSpec::Raw {
                ty: ECH_EXTENSION_TYPE,
                data: vec![0x01],
            };
            inner_marked = true;
            break;
        }
    }
    if !inner_marked {
        inner_spec.extensions.push(crate::spec::ExtensionSpec::Raw {
            ty: ECH_EXTENSION_TYPE,
            data: vec![0x01],
        });
    }
    let inner = build_hello_ordered(&inner_spec, params, permute)?;
    // `legacy_version || random` then an EMPTY session id, then the rest of the
    // body (cipher suites, compression, extensions) — the handshake header and
    // the session id both drop out of the sealed form (RFC 9849 §6.1.3).
    let sid_len = usize::from(inner.handshake_bytes[38]);
    let mut inner_body = Vec::with_capacity(inner.handshake_bytes.len() - 4 - sid_len + 1);
    inner_body.extend_from_slice(&inner.handshake_bytes[4..38]);
    inner_body.push(0x00);
    inner_body.extend_from_slice(&inner.handshake_bytes[39 + sid_len..]);

    // `enc` exists before sealing, and the AAD is the outer hello carrying the
    // REAL `enc` with only the payload zeroed (RFC 9849 §6.1.2).
    let mut sender = crate::crypto::hpke::Sender::new(&config.public_key, &hpke_info(config))?;
    let enc = sender.enc().to_vec();
    let mut body = Vec::with_capacity(42 + sealed_len(inner_body.len()));
    body.push(0x00); // ClientHelloOuter
    body.extend_from_slice(&hpke::KDF_HKDF_SHA256.to_be_bytes());
    body.extend_from_slice(&hpke::AEAD_AES128GCM.to_be_bytes());
    body.push(config.config_id);
    body.extend_from_slice(&32u16.to_be_bytes());
    body.extend_from_slice(&enc);
    body.extend_from_slice(
        &u16::try_from(sealed_len(inner_body.len()))
            .map_err(|_| TlsError::Spec("ECH payload exceeds u16".into()))?
            .to_be_bytes(),
    );
    body.resize(body.len() + sealed_len(inner_body.len()), 0); // payload slot

    let mut outer_spec = spec.clone();
    // The public name is what the outer hello claims; the extension list keeps
    // every other entry (and its order) so the fingerprint does not move.
    outer_spec
        .extensions
        .retain(|e| !matches!(e, crate::spec::ExtensionSpec::EchGrease { .. }));
    outer_spec.extensions.push(crate::spec::ExtensionSpec::Raw {
        ty: ECH_EXTENSION_TYPE,
        data: body.clone(),
    });
    let outer_params = crate::hello::BuildParams {
        server_name: &config.public_name,
        alpn: params.alpn,
        x25519_pub: params.x25519_pub,
        mlkem768_pub: params.mlkem768_pub,
        rng: params.rng,
    };
    let mut outer = build_hello_ordered(&outer_spec, &outer_params, permute)?;

    // RFC 9849 §6.1.1: both hellos carry the SAME legacy session id.
    let sid_len = usize::from(inner.handshake_bytes[38]);
    let sid = 39..39 + sid_len;
    outer.handshake_bytes[sid.clone()].copy_from_slice(&inner.handshake_bytes[sid]);

    // Locate the extension body by its exact 4-byte header: a structural
    // search cannot drift with an owned copy, unlike a pointer into a parse.
    let mut header = Vec::with_capacity(4);
    header.extend_from_slice(&ECH_EXTENSION_TYPE.to_be_bytes());
    header.extend_from_slice(
        &u16::try_from(body.len())
            .map_err(|_| TlsError::Spec("ECH extension exceeds u16".into()))?
            .to_be_bytes(),
    );
    let start = outer
        .handshake_bytes
        .windows(header.len())
        .position(|w| w == header.as_slice())
        .ok_or_else(|| TlsError::Spec("built outer hello lost its ECH extension".into()))?
        + header.len();

    // The associated data is the outer hello WITHOUT its handshake header.
    let sealed = seal_with(&mut sender, &outer.handshake_bytes[4..], &inner_body)?;
    outer.handshake_bytes[start + 42..start + 42 + sealed.payload.len()]
        .copy_from_slice(&sealed.payload);
    outer.record_bytes = crate::hello::to_record(&outer.handshake_bytes);

    let state = EchState {
        inner_random: sealed.inner_random,
        inner_hello: inner.handshake_bytes.clone(),
    };
    Ok((outer, inner, state))
}

/// The client-side ECH state a handshake carries after sealing.
#[derive(Debug, Clone)]
pub struct EchState {
    /// The inner hello's random: the confirmation's HKDF salt.
    pub inner_random: [u8; 32],
    /// The inner hello as it entered the transcript.
    pub inner_hello: Vec<u8>,
}

impl EchState {
    /// The confirmation the server must have put in the last 8 bytes of its
    /// `ServerHello.random`.
    pub fn confirm(
        &self,
        hash: &'static digest::Algorithm,
        server_hello: &[u8],
    ) -> Result<[u8; 8]> {
        accept_confirmation(hash, &self.inner_random, &self.inner_hello, server_hello)
    }
}

/// RFC 9849 §7.2.1 acceptance confirmation: the client recomputes the
/// server's 8-byte value from the inner transcript and the outer hello.
///
/// `transcript` is the running hash over `ClientHelloInner` (and any earlier
/// messages); `server_hello` is the received `ServerHello` message with its
/// 4-byte handshake header, whose last 8 random bytes the server replaced.
pub fn accept_confirmation(
    hash: &'static digest::Algorithm,
    inner_random: &[u8; 32],
    inner_hello: &[u8],
    server_hello: &[u8],
) -> Result<[u8; 8]> {
    // The confirmation covers the ServerHello with its trailing 8 random
    // bytes ZEROED (RFC 9849 §7.2.1).
    // Handshake header (4) + legacy_version (2) + random (32) = 38 bytes; the
    // server overwrites the LAST 8 BYTES OF THE RANDOM, not of the message.
    if server_hello.len() < 38 {
        return Err(TlsError::Spec("ServerHello is too short for ECH".into()));
    }
    // ONE hash stream: ClientHelloInner then the zeroed ServerHello. Feeding
    // a digest of the first message and re-hashing would give
    // `Hash(Hash(inner) || sh)`, which is not the transcript.
    let mut sh = server_hello.to_vec();
    sh[30..38].fill(0);
    let mut hasher = digest::Context::new(hash);
    hasher.update(inner_hello);
    hasher.update(&sh);
    let covered = hasher.finish();

    // RFC 9849 §7.2.1: HKDF-Extract(salt = empty, IKM = ClientHelloInner.random).
    let prk = hkdf_extract(hash, &[], inner_random);
    Ok(
        hkdf_expand_label(hash, &prk, b"ech accept confirmation", covered.as_ref(), 8)?
            .try_into()
            .expect("8 bytes requested"),
    )
}

/// `HKDF-Extract(hash, salt = inner random, ikm = nil)`.
fn hkdf_extract(hash: &'static digest::Algorithm, salt: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    use ring::hmac;
    let alg = match hash {
        a if a == &digest::SHA256 => hmac::HMAC_SHA256,
        a if a == &digest::SHA384 => hmac::HMAC_SHA384,
        _ => hmac::HMAC_SHA256,
    };
    let key = hmac::Key::new(alg, salt);
    let tag = hmac::sign(&key, ikm);
    Zeroizing::new(tag.as_ref().to_vec())
}

/// `HKDF-Expand-Label(prk, label, context, len)` (RFC 8446 §7.1).
fn hkdf_expand_label(
    hash: &'static digest::Algorithm,
    prk: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    let hkdf_alg = match hash {
        a if a == &digest::SHA256 => hkdf::HKDF_SHA256,
        a if a == &digest::SHA384 => hkdf::HKDF_SHA384,
        _ => hkdf::HKDF_SHA256,
    };
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(
        &u16::try_from(len)
            .map_err(|_| TlsError::Spec("hkdf label length overflow".into()))?
            .to_be_bytes(),
    );
    info.push(u8::try_from(6 + label.len()).map_err(|_| TlsError::Spec("label too long".into()))?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(u8::try_from(context.len()).map_err(|_| TlsError::Spec("context too long".into()))?);
    info.extend_from_slice(context);
    // ring's `hkdf::Prk` is opaque and its bytes are already in hand, so the
    // expansion runs over the PRK as an HMAC key.
    hmac_expand(prk, &info, len, hkdf_alg)
}

/// HKDF-Expand over raw PRK bytes.
fn hmac_expand(prk: &[u8], info: &[u8], len: usize, alg: hkdf::Algorithm) -> Result<Vec<u8>> {
    let (hmac_alg, hash_len) = if alg == hkdf::HKDF_SHA384 {
        (ring::hmac::HMAC_SHA384, 48)
    } else {
        (ring::hmac::HMAC_SHA256, 32)
    };
    if len > 255 * hash_len {
        return Err(TlsError::Spec("hkdf expand length out of range".into()));
    }
    let key = ring::hmac::Key::new(hmac_alg, prk);
    let mut out = Vec::with_capacity(len);
    let mut block = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut message = Zeroizing::new(block.clone());
        message.extend_from_slice(info);
        message.push(counter);
        block = ring::hmac::sign(&key, &message).as_ref().to_vec();
        out.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    Ok(out)
}

/// Strict base64 (standard alphabet, `=` padding) decoding.
fn base64_decode(value: &str) -> Result<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let stripped: Vec<u8> = value.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let unpadded = stripped.strip_suffix(b"=").unwrap_or(&stripped);
    let unpadded = unpadded.strip_suffix(b"=").unwrap_or(unpadded);
    let rem = unpadded.len() % 4;
    if rem == 1 {
        return Err(TlsError::Spec("ech: malformed base64 length".into()));
    }
    let mut out = Vec::with_capacity(unpadded.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in unpadded {
        let v =
            sextet(c).ok_or_else(|| TlsError::Spec(format!("ech: not base64: {:?}", c as char)))?;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).expect("masked to a byte"));
        }
    }
    Ok(out)
}

/// `opaque<len u16>`: the body plus its 2-byte length prefix.
fn read_vec_u16<'a>(bytes: &'a [u8], what: &str) -> Result<&'a [u8]> {
    let len = bytes
        .get(..2)
        .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
        .ok_or_else(|| TlsError::Spec(format!("ECH {what}: truncated length")))?;
    bytes
        .get(2..2 + len)
        .ok_or_else(|| TlsError::Spec(format!("ECH {what}: truncated body")))
}

/// `opaque<len u8>`.
fn read_vec_u8<'a>(bytes: &'a [u8], what: &str) -> Result<&'a [u8]> {
    let len = usize::from(
        *bytes
            .first()
            .ok_or_else(|| TlsError::Spec(format!("ECH {what}: truncated length")))?,
    );
    bytes
        .get(1..1 + len)
        .ok_or_else(|| TlsError::Spec(format!("ECH {what}: truncated body")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full split, checked the way a server checks it: seal the inner body,
    /// open it with the config's private key, then walk the structure uTLS's
    /// `decodeInnerClientHello` requires (no handshake header, empty session
    /// id, zero padding) and look for the real SNI in the extensions.
    #[test]
    fn built_hellos_round_trip_through_a_server_style_decode() {
        use crate::fingerprints::{Browser, Fingerprint};
        use crate::hello::BuildParams;

        let sk = x25519_dalek::StaticSecret::from([11u8; 32]);
        let pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
        let mut raw = Vec::new();
        raw.extend_from_slice(&0xfe0du16.to_be_bytes());
        raw.extend_from_slice(&0u16.to_be_bytes());
        raw.push(0x42); // config id
        raw.extend_from_slice(&hpke::KEM_X25519_HKDF_SHA256.to_be_bytes());
        raw.extend_from_slice(&32u16.to_be_bytes());
        raw.extend_from_slice(&pk);
        raw.extend_from_slice(&4u16.to_be_bytes());
        raw.extend_from_slice(&[0, 1, 0, 1]);
        raw.push(32);
        raw.push(4);
        raw.extend_from_slice(b"pub1");
        raw.extend_from_slice(&0u16.to_be_bytes());
        let config = EchConfig {
            config_id: 0x42,
            kem_id: hpke::KEM_X25519_HKDF_SHA256,
            public_key: pk.to_vec(),
            cipher_suites: vec![(1, 1)],
            max_name_length: 32,
            public_name: "pub.example".into(),
            raw,
        };

        let rng = ring::rand::SystemRandom::new();
        let spec = Fingerprint::default_for(Browser::Chrome)
            .resolve()
            .unwrap()
            .spec;
        let x = [9u8; 32];
        let params = BuildParams {
            server_name: "secret.example",
            alpn: None,
            x25519_pub: &x,
            mlkem768_pub: None,
            rng: &rng,
        };
        let (outer, inner, state) = build_hellos(&spec, &params, &config, false).unwrap();

        // Both hellos carry the REAL name where they should: the OUTER the
        // public name, the inner (sealed) the real one.
        let outer_view = crate::hello::parse::parse_hello(&outer.handshake_bytes).unwrap();
        let inner_view = crate::hello::parse::parse_hello(&inner.handshake_bytes).unwrap();
        assert_eq!(sni_bytes(&outer_view), b"pub.example");
        assert_eq!(sni_bytes(&inner_view), b"secret.example");
        // …and the same legacy session id (RFC 9849 §6.1.1).
        assert_eq!(outer_view.session_id, inner_view.session_id);

        // The inner offers TLS 1.3 only (uTLS refuses an inner with 1.2) and
        // marks itself with the inner variant.
        let versions = inner_view.extension(0x002b).expect("supported_versions");
        assert!(
            !versions.windows(2).any(|w| w == [0x03, 0x03]),
            "inner hello must not advertise TLS 1.2"
        );
        assert_eq!(
            inner_view.extension(ECH_EXTENSION_TYPE),
            Some(&[0x01u8][..])
        );

        // Server half: open the sealed body and check the framing.
        let ext = outer_view.extension(ECH_EXTENSION_TYPE).expect("ECH ext");
        assert_eq!(ext[0], 0x00, "outer variant");
        let enc = &ext[8..40];
        let payload_len = usize::from(u16::from_be_bytes([ext[40], ext[41]]));
        let payload = &ext[42..42 + payload_len];

        // The AAD is the outer hello as sent, with the payload zeroed.
        let mut aad = outer.handshake_bytes[4..].to_vec();
        let mut header = vec![0xfe, 0x0d];
        header.extend_from_slice(&u16::try_from(42 + payload_len).unwrap().to_be_bytes());
        let start = outer
            .handshake_bytes
            .windows(header.len())
            .position(|w| w == header.as_slice())
            .expect("ECH extension header")
            + header.len();
        aad[start - 4 + 42..start - 4 + 42 + payload_len].fill(0);

        let info = [ECH_INFO_PREFIX, &config.raw].concat();
        let body = hpke::open_base(&sk.to_bytes(), enc, &info, &aad, payload).expect("opens");

        // `legacy_version || random || sid_len(0) || …` — no handshake header.
        assert_eq!(body[0], 0x03);
        assert_eq!(body[1], 0x03);
        assert_eq!(&body[2..34], &state.inner_random);
        assert_eq!(body[34], 0x00, "the sealed inner carries no session id");
        let unpadded = body.iter().rposition(|&b| b != 0).unwrap() + 1;
        assert_eq!(body.len() % PADDING_UNIT, 0, "padded to a 32-byte unit");
        assert!(
            body[unpadded..].iter().all(|&b| b == 0),
            "trailing padding is zeros"
        );

        // And the confirmation the server would compute is reproducible.
        let mut sh = vec![0x02u8, 0, 0, 40, 0x03, 0x03];
        sh.extend_from_slice(&[0x77u8; 32]);
        sh.extend_from_slice(&[0x13, 0x01, 0x00, 0x00, 0x00]);
        let confirm = state.confirm(&digest::SHA256, &sh).unwrap();
        let mut confirmed = sh.clone();
        confirmed[30..38].copy_from_slice(&confirm);
        assert_eq!(state.confirm(&digest::SHA256, &confirmed).unwrap(), confirm);
    }

    /// The `server_name` extension's host bytes, from a parsed hello.
    fn sni_bytes(hello: &crate::hello::parse::ParsedClientHello) -> Vec<u8> {
        let body = hello.extension(0x0000).expect("SNI extension");
        // server_name_list<u16> { name_type(u8)=0, name<u16> }
        let len = usize::from(u16::from_be_bytes([body[3], body[4]]));
        body[5..5 + len].to_vec()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A real `ECHConfigList` published by `crypto.cloudflare.com` (HTTPS RR,
    /// fetched 2026-11-06): the parse must land on the public name and the
    /// X25519/AES-128-GCM suite the client implements.
    #[test]
    fn parses_a_deployed_cloudflare_config() {
        let list = EchConfigList::from_base64(
            "AEX+DQBBlwAgACD5y8b2ysonYsAe68O0szS1iyyKWjiOA8gN1ZFyYLh7aQAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=",
        )
        .expect("parses");
        let config = list.select().expect("selects");
        assert_eq!(config.config_id, 0x97);
        assert_eq!(config.kem_id, hpke::KEM_X25519_HKDF_SHA256);
        assert_eq!(config.public_key.len(), 32);
        assert_eq!(config.cipher_suites, vec![(1, 1)]);
        assert_eq!(config.public_name, "cloudflare-ech.com");
        assert_eq!(config.max_name_length, 0);
        // The `info` string embeds the config verbatim.
        let info = [ECH_INFO_PREFIX, &config.raw].concat();
        assert_eq!(&info[..8], b"tls ech\x00");
        assert_eq!(info.len(), 8 + config.raw.len());
    }

    #[test]
    fn skips_a_config_with_an_unsupported_suite() {
        // One config whose only suite is AES-256-GCM (kdf 1, aead 2) must not
        // be selected: sealing under it would be an unnegotiable offer.
        let mut contents = Vec::new();
        contents.push(0x01); // config id
        contents.extend_from_slice(&0x0020u16.to_be_bytes()); // kem
        contents.extend_from_slice(&32u16.to_be_bytes());
        contents.extend_from_slice(&[7u8; 32]);
        contents.extend_from_slice(&4u16.to_be_bytes());
        contents.extend_from_slice(&[0, 1, 0, 2]); // kdf 1, aead 2
        contents.push(0);
        contents.push(1);
        contents.push(b'x'); // public name "x"
        contents.extend_from_slice(&0u16.to_be_bytes()); // extensions
        let mut entry = Vec::new();
        entry.extend_from_slice(&0xfe0du16.to_be_bytes());
        entry.extend_from_slice(&u16::try_from(contents.len()).unwrap().to_be_bytes());
        entry.extend_from_slice(&contents);
        let mut list = Vec::new();
        list.extend_from_slice(&u16::try_from(entry.len()).unwrap().to_be_bytes());
        list.extend_from_slice(&entry);
        let parsed = EchConfigList::parse(&list).expect("parses");
        assert_eq!(parsed.configs.len(), 1);
        assert!(parsed.select().is_err(), "no usable suite");
    }

    /// Acceptance confirmation over a known transcript: the value is a pure
    /// function of the inner random, the hello and the `ServerHello`, so a
    /// hash mistake shows up here rather than as a silent ECH rejection.
    #[test]
    fn acceptance_confirmation_binds_all_three_inputs() {
        let inner_random = [0x11u8; 32];
        let transcript = vec![0x22u8; 32];
        let mut sh = vec![0x02u8, 0, 0, 36, 0x03, 0x03];
        sh.extend_from_slice(&[0x33u8; 32]);
        sh.extend_from_slice(&[0x13, 0x01, 0x00, 0x00, 0x00]); // suite + no ext
        let a = accept_confirmation(&digest::SHA256, &inner_random, &transcript, &sh).unwrap();
        // Deterministic for the same inputs...
        let b = accept_confirmation(&digest::SHA256, &inner_random, &transcript, &sh).unwrap();
        assert_eq!(a, b);
        // ...and different for each of the three inputs.
        let mut other_random = inner_random;
        other_random[0] ^= 1;
        assert_ne!(
            a,
            accept_confirmation(&digest::SHA256, &other_random, &transcript, &sh).unwrap()
        );
        let mut other_transcript = transcript.clone();
        other_transcript[0] ^= 1;
        assert_ne!(
            a,
            accept_confirmation(&digest::SHA256, &inner_random, &other_transcript, &sh).unwrap()
        );
        let mut other_sh = sh.clone();
        other_sh[10] ^= 1; // inside the random, before the confirmation tail
        assert_ne!(
            a,
            accept_confirmation(&digest::SHA256, &inner_random, &transcript, &other_sh).unwrap()
        );
        // The trailing 8 random bytes are the ones the server overwrites: a
        // change there must NOT change the confirmation.
        let mut confirmed_sh = sh.clone();
        confirmed_sh[30..38].copy_from_slice(&a);
        assert_eq!(
            a,
            accept_confirmation(&digest::SHA256, &inner_random, &transcript, &confirmed_sh)
                .unwrap()
        );
    }

    #[test]
    fn sealed_length_rounds_to_the_padding_unit() {
        assert_eq!(sealed_len(1), 32 + 16);
        assert_eq!(sealed_len(31), 32 + 16);
        assert_eq!(sealed_len(32), 32 + 16);
        assert_eq!(sealed_len(33), 64 + 16);
    }

    #[test]
    fn sealed_body_drops_the_header_and_the_session_id() {
        let sk = x25519_dalek::StaticSecret::from([5u8; 32]);
        let pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
        let config = EchConfig {
            config_id: 1,
            kem_id: hpke::KEM_X25519_HKDF_SHA256,
            public_key: pk.to_vec(),
            cipher_suites: vec![(1, 1)],
            max_name_length: 0,
            public_name: "public.example".into(),
            raw: vec![0u8; 4],
        };
        // Headerless body: legacy_version, random, empty sid, then junk.
        let mut body = vec![0x03u8, 0x03];
        body.extend_from_slice(&[0x44u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x55u8; 8]);
        let sealed = seal_inner(&config, b"aad", &body).expect("seals");
        assert_eq!(sealed.inner_random, [0x44u8; 32]);
        let info = [ECH_INFO_PREFIX, &config.raw].concat();
        let opened = hpke::open_base(&sk.to_bytes(), &sealed.enc, &info, b"aad", &sealed.payload)
            .expect("opens");
        assert_eq!(&opened[..body.len()], &body[..]);
        assert!(opened[body.len()..].iter().all(|&b| b == 0), "zero padding");
        // A body too short to carry a random is refused, not sealed blindly.
        assert!(seal_inner(&config, b"aad", &[0x03, 0x03]).is_err());
    }

    #[test]
    fn seal_and_open_round_trip_under_hpke() {
        let sk = x25519_dalek::StaticSecret::from([3u8; 32]);
        let pk = x25519_dalek::PublicKey::from(&sk).to_bytes();
        let config = EchConfig {
            config_id: 7,
            kem_id: hpke::KEM_X25519_HKDF_SHA256,
            public_key: pk.to_vec(),
            cipher_suites: vec![(1, 1)],
            max_name_length: 0,
            public_name: "public.example".into(),
            raw: unhex("0102030405"),
        };
        let mut body = vec![0x03u8, 0x03];
        body.extend_from_slice(&[0x44u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x55u8; 40]); // cipher suites/compression/exts
        let aad = b"outer hello aad";
        let sealed = seal_inner(&config, aad, &body).expect("seals");
        assert_eq!(sealed.enc.len(), 32);
        assert_eq!(sealed.payload.len(), 16 + body.len().div_ceil(32) * 32);
        assert_eq!(sealed.inner_random, [0x44u8; 32]);

        let info = [ECH_INFO_PREFIX, &config.raw].concat();
        let opened = hpke::open_base(&sk.to_bytes(), &sealed.enc, &info, aad, &sealed.payload)
            .expect("the server half opens it");
        assert_eq!(&opened[..body.len()], &body[..]);
        assert!(opened[body.len()..].iter().all(|&b| b == 0), "zero padding");
    }
}
