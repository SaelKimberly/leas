//! `NapsterV` Tunnel `.npvt` / `.npvs` exchange formats.
//!
//! The wire format is specified in `docs/reference/npvt.md`; this module is the
//! executable form of that document. It does not convert profiles to share
//! URLs: it stops at the JSON payload, so the caller owns the mapping onto
//! `ParsedProto`.
//!
//! Key material:
//! - legacy `NPVT1`/`NPVTSUB1`: embedded whitebox tables, no user secret;
//! - `NPVO1`: no key;
//! - sealed `NPVS`: passphrase, app key, or a recipient private key. Recipient
//!   envelopes need a per-device key the client does not export, so they are
//!   reported as unsupported rather than guessed.
//!
//! Version 5 app-key envelopes need the client's gen2 whitebox walker, which is
//! not implemented here; they are reported as unsupported. The derivation is
//! documented in the reference so a clean-room implementation can be added
//! without inventing the format.

use std::sync::LazyLock;

use base64_simd::STANDARD_NO_PAD;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::base64_util::decode_base64;
use leas_proto::HostKind;
use leas_proto::proto_spec::common::{
    GrpcConfig, HttpConfig, HttpUpgradeConfig, KcpConfig, RealityOpts, SecurityConfig, TlsConfig,
    TlsOpts, TransportConfig, WebSocketConfig, XHttpConfig,
};
use leas_proto::proto_spec::{
    EndpointEssentials, Hysteria2Config, ParsedProto, ProtocolConfig, ProtocolEssentials,
    ProtocolKind, SsConfig, TrojanConfig, VlessConfig, VmessConfig,
};
use leas_proto::urlx::TinyText;

const LEGACY: &str = "NPVT1";
const LEGACY_SUB: &str = "NPVTSUB1";
const OPEN: &str = "NPVO1";
const SEALED: &[u8] = b"NPVS";
const SEALED_V5: u8 = 5;
const SEALED_V5_HEADER_FIXED: usize = 53;
const SEALED_V5_RECIPIENT_SIZE: usize = 32 + 93;
const SEALED_V5_METHOD_PASS: u8 = 1;
const SEALED_V5_METHOD_APPKEY: u8 = 2;
const SEALED_V5_SENTINEL_SEQ: u16 = 0xFFFF;
const V1_WRAP_LEN: usize = 60;
const V1_APP_KEY_LABEL: &[u8] = b"npvtunnel/appkey/v1 ";
const V5_METADATA_INFO: &[u8] = b"NPVS-v5/metadata";
const V5_FIELD_KEY_INFO: &[u8] = b"NPV-fields-v1/field/";
const V5_RECORD_AAD_INFO: &[u8] = b"NPV-fields-v1/record/";

/// One decoded exchange container.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Container schema version. Legacy files carry it in segment 0; sealed
    /// envelopes use the envelope version byte (1 or 5).
    pub version: u32,
    /// Configuration objects (`Config` / `ConfigBody`).
    pub configs: Vec<Value>,
    /// Legacy user info / `LockConfig`, or sealed policy metadata.
    pub user_info: Option<Value>,
    /// Creator message extracted from sealed metadata, when present.
    pub creator_message: Option<String>,
    /// Non-JSON sealed payload (sentinel-encoded), when the body is not JSON.
    pub payload: Option<String>,
    /// Version-5 sentinel table that describes a subscription instead of a
    /// config list (`{ "kind": 1, "name": ..., "url": ..., "autoUpdateHours": ... }`).
    pub subscription: Option<Value>,
}

#[derive(Debug, Error)]
pub enum NpvtError {
    #[error("not an NPVT/NPVS container")]
    NotNpvt,
    #[error("malformed NPVT container: {0}")]
    Malformed(&'static str),
    #[error("base64 decode failed")]
    Base64,
    #[error("JSON parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cryptographic open failed (wrong key, passphrase, or corrupted file)")]
    Crypt,
    #[error("passphrase required to open this sealed config")]
    PassphraseRequired,
    #[error("this envelope is sealed to a recipient private key; it cannot be opened here")]
    RecipientKeyRequired,
    #[error("unsupported NPVT feature: {0}")]
    Unsupported(&'static str),
    #[error("unsupported NPVS envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("config requires a newer app version")]
    NewerVersion,
}

/// Container kind, without decrypting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Legacy,
    Open,
    /// Sealed envelope, carrying its version byte (`1` or `5`).
    Sealed(u8),
}

/// Detect the container without decrypting it.
#[must_use]
pub fn detect(data: &[u8]) -> Option<Format> {
    if data.starts_with(SEALED) && data.len() >= 5 {
        return Some(Format::Sealed(data[4]));
    }
    let text = leading_text(data);
    if text.starts_with(OPEN) {
        return Some(Format::Open);
    }
    if text.starts_with(LEGACY) || text.starts_with(LEGACY_SUB) {
        return Some(Format::Legacy);
    }
    None
}

/// Decode a container.
///
/// `passphrase` is used only for sealed envelopes that carry a passphrase
/// block. Legacy and open containers ignore it.
///
/// # Errors
///
/// Returns [`NpvtError::NotNpvt`] when the marker is absent, or a container-
/// specific error when the payload is malformed or cannot be opened.
pub fn decode(data: &[u8], passphrase: Option<&str>) -> Result<Bundle, NpvtError> {
    if data.starts_with(SEALED) {
        return decode_sealed(data, passphrase);
    }
    let text = std::str::from_utf8(data).map_err(|_| NpvtError::NotNpvt)?;
    let text = text.trim_start();
    if text.starts_with(OPEN) {
        return decode_open(text);
    }
    if text.starts_with(LEGACY) || text.starts_with(LEGACY_SUB) {
        return decode_legacy(text);
    }
    Err(NpvtError::NotNpvt)
}

fn leading_text(data: &[u8]) -> &str {
    let start = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(data.len());
    std::str::from_utf8(&data[start..]).unwrap_or("")
}

fn decode_legacy(text: &str) -> Result<Bundle, NpvtError> {
    let mut body = text;
    for marker in [LEGACY_SUB, LEGACY] {
        body = body
            .strip_prefix(marker)
            .map_or(body, |rest| rest.strip_prefix('\n').unwrap_or(rest));
    }
    let body = body.trim();
    let mut parts = body.split(',');
    let (Some(v), Some(configs), Some(info), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(NpvtError::Malformed("expected three comma-separated parts"));
    };

    let version_text = decrypt_segment(v)?;
    let version: u32 = std::str::from_utf8(&version_text)
        .map_err(|_| NpvtError::Malformed("version is not UTF-8"))?
        .trim()
        .parse()
        .map_err(|_| NpvtError::Malformed("version is not a number"))?;
    if version > 1 {
        return Err(NpvtError::NewerVersion);
    }

    let configs: Value = serde_json::from_slice(&decrypt_segment(configs)?)?;
    let Value::Array(configs) = configs else {
        return Err(NpvtError::Malformed("config segment is not an array"));
    };
    let info: Value = serde_json::from_slice(&decrypt_segment(info)?)?;

    Ok(Bundle {
        version,
        configs,
        user_info: Some(info),
        creator_message: None,
        payload: None,
        subscription: None,
    })
}

fn decrypt_segment(segment: &str) -> Result<Vec<u8>, NpvtError> {
    let raw = decode_base64(segment).map_err(|_| NpvtError::Base64)?;
    legacy_ctr_crypt(&raw)
}

fn decode_open(text: &str) -> Result<Bundle, NpvtError> {
    let body = text
        .strip_prefix(OPEN)
        .map_or(text, |rest| rest.strip_prefix('\n').unwrap_or(rest))
        .trim();
    let value: Value = serde_json::from_str(body)?;
    let configs = value
        .get("configs")
        .and_then(Value::as_array)
        .ok_or(NpvtError::Malformed("open payload has no configs array"))?
        .iter()
        .cloned()
        .map(decode_sentinels_value)
        .collect();
    Ok(Bundle {
        version: 1,
        configs,
        user_info: None,
        creator_message: None,
        payload: None,
        subscription: None,
    })
}

fn decode_sealed(data: &[u8], passphrase: Option<&str>) -> Result<Bundle, NpvtError> {
    let version = data
        .get(4)
        .copied()
        .ok_or(NpvtError::Malformed("missing envelope version"))?;
    match version {
        1 => decode_sealed_v1(data, passphrase),
        SEALED_V5 => decode_sealed_v5(data, passphrase),
        other => Err(NpvtError::UnsupportedVersion(other)),
    }
}

// ── Sealed v1 ──────────────────────────────────────────────────────────

fn decode_sealed_v1(data: &[u8], passphrase: Option<&str>) -> Result<Bundle, NpvtError> {
    if data.len() < 89 {
        return Err(NpvtError::Malformed("sealed envelope is too short"));
    }
    let header_len = be_u32(data, 5)?;
    let header_end = 9usize
        .checked_add(header_len as usize)
        .ok_or(NpvtError::Malformed("header length overflow"))?;
    if header_end > data.len() {
        return Err(NpvtError::Malformed("header length exceeds file"));
    }
    let header_raw = &data[9..header_end];
    let header: Value = serde_json::from_slice(header_raw)?;
    let nonce_start = header_end;
    let nonce_end = nonce_start + 12;
    let len_at = nonce_end;
    let body_len = be_u32(data, len_at)? as usize;
    let body_start = len_at + 4;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or(NpvtError::Malformed("body length overflow"))?;
    if body_end + 64 != data.len() {
        return Err(NpvtError::Malformed("trailing or missing signature"));
    }

    let cek = unwrap_v1_key(&header, passphrase)?;
    let plaintext = chacha_open(
        &cek,
        &data[nonce_start..nonce_end],
        &data[body_start..body_end],
        header_raw,
    )?;
    let text =
        String::from_utf8(plaintext).map_err(|_| NpvtError::Malformed("body is not UTF-8"))?;
    let decoded = decode_sentinels(&text);
    let (configs, user_info, payload) = split_payload(&decoded);

    Ok(Bundle {
        version: 1,
        configs,
        user_info,
        creator_message: creator_message(&header),
        payload,
        subscription: None,
    })
}

fn unwrap_v1_key(
    header: &Value,
    passphrase: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, NpvtError> {
    if let Some(app_key) = header.get("appKey") {
        let kdf = app_key
            .get("kdf")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if kdf != "wbaes-ctr-sha256" {
            return Err(NpvtError::Malformed("unsupported app-key KDF"));
        }
        let key_id = app_key.get("keyId").and_then(Value::as_i64).unwrap_or(0);
        if key_id != 1 {
            return Err(NpvtError::Malformed("unsupported app-key generation"));
        }
        let salt = b64_field(app_key, "salt")?;
        if salt.len() != 16 {
            return Err(NpvtError::Malformed("app-key salt is not 16 bytes"));
        }
        let wrap = b64_field(app_key, "wrap")?;
        if wrap.len() != V1_WRAP_LEN {
            return Err(NpvtError::Malformed("app-key wrap is not 60 bytes"));
        }
        let kdk = v1_app_key_kdk(&salt);
        return chacha_open(&*kdk, &wrap[..12], &wrap[12..], &salt).map(Zeroizing::new);
    }

    if let Some(pass) = header.get("passphrase") {
        let kdf = pass.get("kdf").and_then(Value::as_str).unwrap_or_default();
        if kdf != "pbkdf2-hmac-sha256" {
            return Err(NpvtError::Malformed("unsupported passphrase KDF"));
        }
        let passphrase = passphrase.ok_or(NpvtError::PassphraseRequired)?;
        let salt = b64_field(pass, "salt")?;
        let wrap = b64_field(pass, "wrap")?;
        if wrap.len() != V1_WRAP_LEN {
            return Err(NpvtError::Malformed("passphrase wrap is not 60 bytes"));
        }
        let iters = pass
            .get("iters")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| (1..=10_000_000).contains(v))
            .ok_or(NpvtError::Malformed("bad passphrase iteration count"))?;
        let mut derived = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, iters, &mut *derived);
        return chacha_open(&*derived, &wrap[..12], &wrap[12..], &salt).map(Zeroizing::new);
    }

    if header
        .get("recipients")
        .and_then(Value::as_array)
        .is_some_and(|recipients| !recipients.is_empty())
    {
        return Err(NpvtError::RecipientKeyRequired);
    }
    Err(NpvtError::PassphraseRequired)
}

fn v1_app_key_kdk(salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut material = Zeroizing::new([0u8; 32]);
    material[..16].copy_from_slice(salt);
    let stream = Zeroizing::new(legacy_ctr_crypt(&*material).unwrap_or_default());
    let mut hasher = Sha256::new();
    hasher.update(V1_APP_KEY_LABEL);
    hasher.update(&*stream);
    Zeroizing::new(hasher.finalize().into())
}

// ── Sealed v5 ──────────────────────────────────────────────────────────

fn decode_sealed_v5(data: &[u8], passphrase: Option<&str>) -> Result<Bundle, NpvtError> {
    if data.len() < 89 {
        return Err(NpvtError::Malformed("sealed envelope is too short"));
    }
    let header_len = be_u32(data, 5)?;
    let header_end = 9usize
        .checked_add(header_len as usize)
        .ok_or(NpvtError::Malformed("header length overflow"))?;
    if header_end > data.len() {
        return Err(NpvtError::Malformed("header length exceeds file"));
    }
    let header = &data[9..header_end];
    if header.first().copied() != Some(1) {
        return Err(NpvtError::Malformed("unsupported compact header version"));
    }
    if header.len() < SEALED_V5_HEADER_FIXED {
        return Err(NpvtError::Malformed("compact header is too short"));
    }
    let nonce_start = header_end;
    let body_len_at = nonce_start + 12;
    let body_start = body_len_at + 4;
    let body_len = be_u32(data, body_len_at)? as usize;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or(NpvtError::Malformed("body length overflow"))?;
    if body_end + 64 != data.len() {
        return Err(NpvtError::Malformed("trailing or missing signature"));
    }
    let nonce = data
        .get(nonce_start..nonce_start + 12)
        .ok_or(NpvtError::Malformed("truncated body nonce"))?;

    let method = header[50];
    let recipients = u16::from_be_bytes([header[51], header[52]]) as usize;
    let mut off = SEALED_V5_HEADER_FIXED
        .checked_add(recipients * SEALED_V5_RECIPIENT_SIZE)
        .ok_or(NpvtError::Malformed("recipient count overflow"))?;
    if off > header.len() {
        return Err(NpvtError::Malformed("recipient table exceeds header"));
    }

    let (cek, prefix_end) = match method {
        SEALED_V5_METHOD_PASS => {
            if off + 4 + 16 + 60 > header.len() {
                return Err(NpvtError::Malformed("truncated passphrase block"));
            }
            let iters = be_u32(header, off)?;
            if !(1..=10_000_000).contains(&iters) {
                return Err(NpvtError::Malformed("bad passphrase iteration count"));
            }
            let salt = &header[off + 4..off + 20];
            let wrap = &header[off + 20..off + 80];
            off += 80;
            let passphrase = passphrase.ok_or(NpvtError::PassphraseRequired)?;
            let mut derived = Zeroizing::new([0u8; 32]);
            pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iters, &mut *derived);
            let cek = chacha_open(&*derived, &wrap[..12], &wrap[12..], salt)?;
            (Zeroizing::new(cek), off)
        }
        SEALED_V5_METHOD_APPKEY => {
            if off + 2 + 16 + 60 > header.len() {
                return Err(NpvtError::Malformed("truncated app-key block"));
            }
            if header[off..off + 2] != [0, 2] {
                return Err(NpvtError::Malformed("missing app-key block marker"));
            }
            return Err(NpvtError::Unsupported(
                "version-5 app-key envelopes are not implemented",
            ));
        }
        0 => return Err(NpvtError::RecipientKeyRequired),
        _ => return Err(NpvtError::Malformed("unknown unlock method")),
    };

    let meta_len = be_u32(header, off)? as usize;
    let meta_start = off + 4;
    let meta_end = meta_start
        .checked_add(meta_len)
        .ok_or(NpvtError::Malformed("metadata length overflow"))?;
    if meta_end > header.len() {
        return Err(NpvtError::Malformed("metadata length exceeds header"));
    }
    let meta_key = hkdf(&cek, nonce, V5_METADATA_INFO)?;
    let meta_plain = chacha_open(
        &*meta_key,
        nonce,
        &header[meta_start..meta_end],
        &header[..prefix_end],
    )?;
    let metadata: Value = serde_json::from_slice(&meta_plain)?;

    let body = &data[body_start..body_end];
    if body.len() < 38 || body[..4] != [b'N', b'P', b'F', 1] {
        return Err(NpvtError::Malformed("bad NPF body"));
    }
    let content_id = &body[4..36];
    let count = usize::from(u16::from_be_bytes([body[36], body[37]]));
    let mut at = 38usize;
    let mut fields = std::collections::HashMap::with_capacity(count);
    for _ in 0..count {
        let seq = u16::from_be_bytes([
            *body
                .get(at)
                .ok_or(NpvtError::Malformed("truncated field header"))?,
            *body
                .get(at + 1)
                .ok_or(NpvtError::Malformed("truncated field header"))?,
        ]);
        let blob_len = usize::from(u16::from_be_bytes([
            *body
                .get(at + 4)
                .ok_or(NpvtError::Malformed("truncated field header"))?,
            *body
                .get(at + 5)
                .ok_or(NpvtError::Malformed("truncated field header"))?,
        ]));
        let blob_start = at + 6;
        let blob_end = blob_start
            .checked_add(blob_len)
            .ok_or(NpvtError::Malformed("field length overflow"))?;
        let blob = body
            .get(blob_start..blob_end)
            .ok_or(NpvtError::Malformed("truncated field blob"))?;
        if blob.len() < 16 {
            return Err(NpvtError::Malformed("field blob is shorter than its tag"));
        }
        let mut info = Vec::with_capacity(V5_FIELD_KEY_INFO.len() + 2);
        info.extend_from_slice(V5_FIELD_KEY_INFO);
        info.extend_from_slice(&seq.to_be_bytes());
        let key = hkdf(&cek, content_id, &info)?;
        let plain_len = u32::try_from(blob.len() - 16)
            .map_err(|_| NpvtError::Malformed("field length exceeds u32"))?;
        let mut aad = Vec::with_capacity(V5_RECORD_AAD_INFO.len() + 32 + 2 + 4);
        aad.extend_from_slice(V5_RECORD_AAD_INFO);
        aad.extend_from_slice(content_id);
        aad.extend_from_slice(&seq.to_be_bytes());
        aad.extend_from_slice(&plain_len.to_be_bytes());
        let plaintext = chacha_open(&*key, &[0u8; 12], blob, &aad)?;
        fields.insert(seq, field_text(&plaintext));
        at = blob_end;
    }

    let sentinel = fields
        .get(&SEALED_V5_SENTINEL_SEQ)
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .map(|value| substitute(value, &fields));
    let configs = sentinel
        .as_ref()
        .and_then(|value| value.get("configs"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let subscription = sentinel.filter(|value| value.get("configs").is_none());

    Ok(Bundle {
        version: 5,
        configs,
        user_info: Some(metadata.clone()),
        creator_message: creator_message(&metadata),
        payload: None,
        subscription,
    })
}

fn field_text(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let text = text.trim();
    let text = if text.starts_with('"') && text.ends_with('"') {
        serde_json::from_str::<String>(text).unwrap_or_else(|_| text.to_owned())
    } else {
        text.to_owned()
    };
    decode_sentinels(&text)
}

fn substitute(value: Value, fields: &std::collections::HashMap<u16, String>) -> Value {
    match value {
        Value::Number(number) => {
            let Some(seq) = number.as_u64().and_then(|n| u16::try_from(n).ok()) else {
                return Value::Number(number);
            };
            if seq == 0 {
                return Value::String(String::new());
            }
            if seq == SEALED_V5_SENTINEL_SEQ {
                return Value::Null;
            }
            fields
                .get(&seq)
                .map_or_else(|| Value::Null, |text| Value::String(text.clone()))
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| substitute(item, fields))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, substitute(value, fields)))
                .collect(),
        ),
        other => other,
    }
}

// ── payload helpers ────────────────────────────────────────────────────

fn split_payload(text: &str) -> (Vec<Value>, Option<Value>, Option<String>) {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(items)) => (items, None, None),
        Ok(Value::Object(mut map)) => {
            if let Some(Value::Array(items)) = map.remove("configs") {
                let user_info = map
                    .remove("lockConfig")
                    .or_else(|| map.remove("userInfo"))
                    .or_else(|| {
                        if map.is_empty() {
                            None
                        } else {
                            Some(Value::Object(map))
                        }
                    });
                return (items, user_info, None);
            }
            (Vec::new(), Some(Value::Object(map)), None)
        }
        Ok(other) => (Vec::new(), Some(other), None),
        Err(_) => (Vec::new(), None, Some(text.to_owned())),
    }
}

fn creator_message(header: &Value) -> Option<String> {
    let policy = header.get("policy")?;
    let mut parts = Vec::new();
    for key in ["displayMessage", "customServerMessage"] {
        if let Some(value) = policy.get(key).and_then(Value::as_str) {
            let value = value.trim();
            if !value.is_empty() {
                parts.push(value);
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join("\n"))
}

fn b64_field(value: &Value, key: &str) -> Result<Vec<u8>, NpvtError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(NpvtError::Malformed("missing base64 field"))
        .and_then(|s| decode_base64(s).map_err(|_| NpvtError::Base64))
}

fn be_u32(data: &[u8], at: usize) -> Result<u32, NpvtError> {
    let bytes = data
        .get(at..at + 4)
        .ok_or(NpvtError::Malformed("truncated integer"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

// ── crypto ─────────────────────────────────────────────────────────────

fn chacha_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, NpvtError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| NpvtError::Crypt)?;
    let nonce: &Nonce = nonce.try_into().map_err(|_| NpvtError::Crypt)?;
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| NpvtError::Crypt)
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, NpvtError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *out).map_err(|_| NpvtError::Crypt)?;
    Ok(out)
}

// ── legacy whitebox ────────────────────────────────────────────────────

const PERM: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

static V1_XOR: &[u8; 24_576] = include_bytes!("npvt/tables/v1_xor.bin");
static V1_TY: &[u8; 16_384] = include_bytes!("npvt/tables/v1_ty.bin");
static V1_MBL: &[u8; 16_384] = include_bytes!("npvt/tables/v1_mbl.bin");
static V1_LAST: &[u8; 4_096] = include_bytes!("npvt/tables/v1_last.bin");

struct Whitebox {
    ty: [u32; 4_096],
    mbl: [u32; 4_096],
}

fn whitebox() -> &'static Whitebox {
    static TABLES: LazyLock<Whitebox> = LazyLock::new(|| {
        let mut ty = [0u32; 4_096];
        let mut mbl = [0u32; 4_096];
        for (i, chunk) in V1_TY.as_chunks::<4>().0.iter().enumerate() {
            ty[i] = u32::from_le_bytes(*chunk);
        }
        for (i, chunk) in V1_MBL.as_chunks::<4>().0.iter().enumerate() {
            mbl[i] = u32::from_le_bytes(*chunk);
        }
        Whitebox { ty, mbl }
    });
    &TABLES
}

fn legacy_ctr_crypt(data: &[u8]) -> Result<Vec<u8>, NpvtError> {
    if data.len() < 16 {
        return Err(NpvtError::Malformed("ciphertext is shorter than the nonce"));
    }
    let mut counter = [0u8; 16];
    counter.copy_from_slice(&data[..16]);
    let mut out = Vec::with_capacity(data.len() - 16);
    for block in data[16..].chunks(16) {
        let mut ks = counter;
        whitebox_block(&mut ks);
        for (i, byte) in block.iter().enumerate() {
            out.push(byte ^ ks[i]);
        }
        increment_be(&mut counter);
    }
    Ok(out)
}

fn whitebox_block(state: &mut [u8; 16]) {
    let tables = whitebox();
    permute(state);
    for group in 0..4 {
        whitebox_group(state, group, &tables.ty);
        whitebox_group(state, group, &tables.mbl);
    }
    permute(state);
    for i in 0..16 {
        state[i] = V1_LAST[i * 256 + usize::from(state[i])];
    }
}

fn whitebox_group(state: &mut [u8; 16], group: usize, table: &[u32; 4_096]) {
    let base = group * 4;
    let q0 = table[base * 256 + usize::from(state[base])];
    let q1 = table[(base + 1) * 256 + usize::from(state[base + 1])];
    let q2 = table[(base + 2) * 256 + usize::from(state[base + 2])];
    let q3 = table[(base + 3) * 256 + usize::from(state[base + 3])];
    for k in 0..4 {
        let t = group * 24 + k * 6;
        let high = 28 - k * 8;
        let low = 24 - k * 8;
        let p1 = xor_at(t, q0 >> high, q1 >> high);
        let p2 = xor_at(t + 1, q2 >> high, q3 >> high);
        let p3 = xor_at(t + 2, q0 >> low, q1 >> low);
        let p4 = xor_at(t + 3, q2 >> low, q3 >> low);
        let high_nibble = xor_at(t + 4, u32::from(p1), u32::from(p2));
        let low_nibble = xor_at(t + 5, u32::from(p3), u32::from(p4));
        state[base + k] = (high_nibble << 4) | low_nibble;
    }
}

fn xor_at(table: usize, a: u32, b: u32) -> u8 {
    let a = (a & 0x0f) as usize;
    let b = (b & 0x0f) as usize;
    V1_XOR[table * 256 + a * 16 + b]
}

fn permute(state: &mut [u8; 16]) {
    let copy = *state;
    for i in 0..16 {
        state[i] = copy[PERM[i]];
    }
}

fn increment_be(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

// ── sentinel encoding ──────────────────────────────────────────────────

fn decode_sentinels(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find("npvs1:") {
        out.push_str(&rest[..pos]);
        let mut token_start = pos + "npvs1:".len();
        let mut end = token_start;
        while let Some(byte) = rest.as_bytes().get(end) {
            if is_sentinel_byte(*byte) {
                end += 1;
            } else {
                break;
            }
        }
        let token = &rest[token_start..end];
        if let Some(decoded) = decode_sentinel_token(token) {
            out.push_str(&String::from_utf8_lossy(&decoded));
        } else {
            out.push_str("npvs1:");
            out.push_str(token);
        }
        token_start = end;
        rest = &rest[token_start..];
    }
    out.push_str(rest);
    out
}

const fn is_sentinel_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn decode_sentinel_token(token: &str) -> Option<Vec<u8>> {
    if let Ok(decoded) = STANDARD_NO_PAD.decode_to_vec(token.as_bytes()) {
        return Some(decoded);
    }
    decode_base64(token).ok()
}

fn decode_sentinels_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(decode_sentinels(&text)),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(decode_sentinels_value).collect())
        }
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, decode_sentinels_value(value)))
                .collect(),
        ),
        other => other,
    }
}

// ── typed NP VT configs and direct mapping ─────────────────────────────

/// Typed view of one NP VT `Config` entry. `raw` keeps every field the typed
/// view does not use, so the caller can still inspect or migrate it.
#[derive(Debug, Clone)]
pub struct NpvtConfig {
    pub name: String,
    pub address: String,
    pub kind: String,
    pub profile: Option<NpvtProfile>,
    pub raw: Value,
}

/// Typed view of `v2rayProfile`, the fields needed to build a `ParsedProto`.
#[derive(Debug, Clone, Default)]
pub struct NpvtProfile {
    pub config_type: i32,
    pub server: String,
    pub server_port: u16,
    pub password: String,
    pub method: String,
    pub flow: String,
    pub network: String,
    pub header_type: String,
    pub host: String,
    pub path: String,
    pub seed: String,
    pub mode: String,
    pub service_name: String,
    pub authority: String,
    pub xhttp_mode: String,
    pub xhttp_extra: String,
    pub security: String,
    pub sni: String,
    pub alpn: String,
    pub fingerprint: String,
    pub insecure: bool,
    pub pinned_sha256: String,
    pub public_key: String,
    pub short_id: String,
    pub spider_x: String,
    pub mldsa65_verify: String,
    pub obfs_password: String,
    pub up_mbps: Option<i64>,
    pub down_mbps: Option<i64>,
    pub port_hopping: Option<u32>,
    pub pin_sha256: String,
    pub v2ray_json: Option<Value>,
}

impl Bundle {
    /// Typed view of every config object, in wire order.
    #[must_use]
    pub fn typed_configs(&self) -> Vec<NpvtConfig> {
        self.configs
            .iter()
            .cloned()
            .map(NpvtConfig::from_json)
            .collect()
    }
}

impl NpvtConfig {
    fn from_json(raw: Value) -> Self {
        let name = text(&raw, "name");
        let address = text(&raw, "address");
        let kind = text(&raw, "type");
        let profile = raw.get("v2rayProfile").map(NpvtProfile::from_json);
        Self {
            name,
            address,
            kind,
            profile,
            raw,
        }
    }

    /// Map this config directly onto the internal parse boundary.
    ///
    /// Structured NP VT profiles map first. `CUSTOM` (`configType == 2`)
    /// profiles map their first supported Xray outbound. SSH, issuer-backed,
    /// SOCKS, HTTP, `WireGuard` and unknown outbounds return
    /// [`NpvtError::Unsupported`] rather than a half-built row.
    ///
    /// # Errors
    ///
    /// Returns [`NpvtError::Unsupported`] for a config shape this mapper does
    /// not own, or [`NpvtError::Malformed`] when required fields are missing or
    /// unparseable.
    pub fn to_parsed_proto(&self) -> Result<ParsedProto, NpvtError> {
        let profile = self
            .profile
            .as_ref()
            .ok_or(NpvtError::Unsupported("NP VT config has no v2rayProfile"))?;
        let view = if profile.config_type == 2 {
            let json = profile
                .v2ray_json
                .as_ref()
                .ok_or(NpvtError::Malformed("CUSTOM config has no v2rayJson"))?;
            view_from_xray(json, &self.name)?
        } else {
            profile.to_view(&self.address, &self.name)?
        };
        view.into_parsed_proto()
    }
}

impl NpvtProfile {
    fn from_json(raw: &Value) -> Self {
        Self {
            config_type: i32::try_from(int(raw, "configType").unwrap_or(2)).unwrap_or(2),
            server: text(raw, "server"),
            server_port: u16::try_from(int(raw, "serverPort").unwrap_or(0)).unwrap_or(0),
            password: text(raw, "password"),
            method: text(raw, "method"),
            flow: text(raw, "flow"),
            network: text(raw, "network"),
            header_type: text(raw, "headerType"),
            host: text(raw, "host"),
            path: text(raw, "path"),
            seed: text(raw, "seed"),
            mode: text(raw, "mode"),
            service_name: text(raw, "serviceName"),
            authority: text(raw, "authority"),
            xhttp_mode: text(raw, "xhttpMode"),
            xhttp_extra: text(raw, "xhttpExtra"),
            security: text(raw, "security"),
            sni: text(raw, "sni"),
            alpn: text(raw, "alpn"),
            fingerprint: text(raw, "fingerPrint"),
            insecure: truthy(raw, "insecure") || truthy(raw, "tlsAllowInsecure"),
            pinned_sha256: text(raw, "pinnedPeerCertSha256"),
            public_key: text(raw, "publicKey"),
            short_id: text(raw, "shortId"),
            spider_x: text(raw, "spiderX"),
            mldsa65_verify: text(raw, "mldsa65Verify"),
            obfs_password: text(raw, "obfsPassword"),
            up_mbps: int(raw, "uploadMbps"),
            down_mbps: int(raw, "downloadMbps"),
            port_hopping: int(raw, "portHopping").and_then(|v| u32::try_from(v).ok()),
            pin_sha256: text(raw, "pinSHA256"),
            v2ray_json: raw.get("v2rayJson").map(|value| match value {
                Value::String(text) => serde_json::from_str(text).unwrap_or_else(|_| value.clone()),
                _ => value.clone(),
            }),
        }
    }

    fn to_view(&self, address: &str, remarks: &str) -> Result<View, NpvtError> {
        let host = if self.server.is_empty() {
            host_from_address(address)
        } else {
            self.server.clone()
        };
        let port = if self.server_port != 0 {
            self.server_port
        } else {
            port_from_address(address)
        };
        if host.is_empty() || port == 0 {
            return Err(NpvtError::Malformed("profile has no server:port"));
        }
        let security = if self.config_type == 9 && self.security.is_empty() {
            SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts {
                    sni: text_opt(&self.sni),
                    insecure: Some(self.insecure),
                    pin_sha256: text_opt(&self.pin_sha256),
                    ..TlsOpts::default()
                })),
                enc: None,
            }
        } else {
            security_from_profile(self)
        };
        let transport = transport_from_profile(self);
        let common = |kind, secret| View {
            kind,
            host,
            port,
            secret,
            alter_id: None,
            method: None,
            encryption: None,
            flow: text_opt(&self.flow),
            security,
            transport,
            remarks: Some(TinyText::from(remarks)),
            path: text_opt(&self.path),
            obfs: None,
            obfs_password: None,
            up: None,
            down: None,
            hop_interval: self.port_hopping,
            pin_sha256: text_opt(&self.pin_sha256),
        };
        match self.config_type {
            1 => Ok(View {
                alter_id: text_opt(&self.method).or_else(|| Some(TinyText::from("auto"))),
                method: None,
                ..common(ProtocolKind::Vmess, self.password.clone())
            }),
            3 => Ok(View {
                kind: ProtocolKind::Shadowsocks,
                method: text_opt(&self.method),
                ..common(ProtocolKind::Shadowsocks, self.password.clone())
            }),
            5 => Ok(View {
                encryption: text_opt(if self.method.is_empty() {
                    "none"
                } else {
                    &self.method
                }),
                ..common(ProtocolKind::Vless, self.password.clone())
            }),
            6 => Ok(common(ProtocolKind::Trojan, self.password.clone())),
            9 => Ok(View {
                kind: ProtocolKind::Hysteria2,
                obfs: text_opt(&self.obfs_password).map(|_| TinyText::from("salamander")),
                obfs_password: text_opt(&self.obfs_password),
                up: self.up_mbps.map(|v| TinyText::from(v.to_string())),
                down: self.down_mbps.map(|v| TinyText::from(v.to_string())),
                pin_sha256: text_opt(&self.pin_sha256),
                ..common(ProtocolKind::Hysteria2, self.password.clone())
            }),
            2 => Err(NpvtError::Malformed(
                "CUSTOM profile reached the structured mapper",
            )),
            7 | 8 => Err(NpvtError::Unsupported(
                "NP VT WireGuard/HTTP configs are not mapped",
            )),
            4 => Err(NpvtError::Unsupported("NP VT SOCKS configs are not mapped")),
            _ => Err(NpvtError::Unsupported("unknown NP VT configType")),
        }
    }
}

#[derive(Debug)]
struct View {
    kind: ProtocolKind,
    host: String,
    port: u16,
    secret: String,
    alter_id: Option<TinyText>,
    method: Option<TinyText>,
    encryption: Option<TinyText>,
    flow: Option<TinyText>,
    security: SecurityConfig,
    transport: TransportConfig,
    remarks: Option<TinyText>,
    path: Option<TinyText>,
    obfs: Option<TinyText>,
    obfs_password: Option<TinyText>,
    up: Option<TinyText>,
    down: Option<TinyText>,
    hop_interval: Option<u32>,
    pin_sha256: Option<TinyText>,
}

impl View {
    fn into_parsed_proto(self) -> Result<ParsedProto, NpvtError> {
        let endpoint = endpoint(&self.host, self.port);
        let config = match self.kind {
            ProtocolKind::Vless => ProtocolConfig::Vless(VlessConfig {
                uuid: self.secret,
                uuid_origin: None,
                security: self.security,
                transport: self.transport,
                encryption: self.encryption,
                flow: self.flow,
                mux: None,
                path: self.path,
                splice: None,
                remarks: self.remarks,
            }),
            ProtocolKind::Vmess => ProtocolConfig::Vmess(VmessConfig {
                uuid: self.secret,
                security: self.security,
                transport: self.transport,
                alter_id: self.alter_id,
                path: self.path,
                remarks: self.remarks,
            }),
            ProtocolKind::Trojan => ProtocolConfig::Trojan(TrojanConfig {
                password: self.secret,
                security: self.security,
                transport: self.transport,
                path: self.path,
                remarks: self.remarks,
            }),
            ProtocolKind::Shadowsocks => ProtocolConfig::Ss(SsConfig {
                method: self
                    .method
                    .ok_or(NpvtError::Malformed("shadowsocks method is empty"))?,
                password: self.secret,
                security: self.security,
                remarks: self.remarks,
                plugin: None,
            }),
            ProtocolKind::Hysteria2 => ProtocolConfig::Hysteria2(Hysteria2Config {
                auth: self.secret,
                security: self.security,
                obfs: self.obfs,
                obfs_password: self.obfs_password,
                up: self.up,
                down: self.down,
                hop_interval: self.hop_interval,
                pin_sha256: self.pin_sha256,
                remarks: self.remarks,
            }),
            _ => return Err(NpvtError::Unsupported("protocol is not mapped")),
        };
        Ok(ParsedProto {
            endpoints: vec![endpoint],
            protocol: ProtocolEssentials {
                proto_kind: self.kind,
                config,
            },
        })
    }
}

fn view_from_xray(config: &Value, remarks: &str) -> Result<View, NpvtError> {
    let outbounds = config
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or(NpvtError::Malformed("v2rayJson has no outbounds"))?;
    for outbound in outbounds {
        let protocol = text(outbound, "protocol");
        let settings = outbound.get("settings").unwrap_or(&Value::Null);
        let stream = outbound.get("streamSettings").unwrap_or(&Value::Null);
        let view = match protocol.as_str() {
            "vless" | "vmess" => {
                let vnext = settings
                    .get("vnext")
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .ok_or(NpvtError::Malformed("outbound has no vnext"))?;
                let user = vnext
                    .get("users")
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .ok_or(NpvtError::Malformed("outbound has no user"))?;
                let kind = if protocol == "vless" {
                    ProtocolKind::Vless
                } else {
                    ProtocolKind::Vmess
                };
                let alter_id = (protocol == "vmess").then(|| TinyText::from(text(user, "alterId")));
                View {
                    kind,
                    host: text(vnext, "address"),
                    port: u16::try_from(int(vnext, "port").unwrap_or(0)).unwrap_or(0),
                    secret: text(user, "id"),
                    alter_id,
                    method: None,
                    encryption: text_opt(&text(user, "encryption")),
                    flow: text_opt(&text(user, "flow")),
                    security: security_from_xray(stream),
                    transport: transport_from_xray(stream),
                    remarks: Some(TinyText::from(remarks)),
                    path: transport_path_from_xray(stream),
                    obfs: None,
                    obfs_password: None,
                    up: None,
                    down: None,
                    hop_interval: None,
                    pin_sha256: None,
                }
            }
            "trojan" | "shadowsocks" => {
                let server = settings
                    .get("servers")
                    .and_then(Value::as_array)
                    .and_then(|items| items.first())
                    .ok_or(NpvtError::Malformed("outbound has no servers"))?;
                let kind = if protocol == "trojan" {
                    ProtocolKind::Trojan
                } else {
                    ProtocolKind::Shadowsocks
                };
                View {
                    kind,
                    host: text(server, "address"),
                    port: u16::try_from(int(server, "port").unwrap_or(0)).unwrap_or(0),
                    secret: text(server, "password"),
                    alter_id: None,
                    method: text_opt(&text(server, "method")),
                    encryption: None,
                    flow: None,
                    security: security_from_xray(stream),
                    transport: transport_from_xray(stream),
                    remarks: Some(TinyText::from(remarks)),
                    path: transport_path_from_xray(stream),
                    obfs: None,
                    obfs_password: None,
                    up: None,
                    down: None,
                    hop_interval: None,
                    pin_sha256: None,
                }
            }
            _ => continue,
        };
        if view.host.is_empty() || view.port == 0 {
            return Err(NpvtError::Malformed("outbound has no address:port"));
        }
        return Ok(view);
    }
    Err(NpvtError::Unsupported(
        "v2rayJson has no supported proxy outbound",
    ))
}

fn transport_path_from_xray(stream: &Value) -> Option<TinyText> {
    let network = text(stream, "network");
    let settings = match network.to_ascii_lowercase().as_str() {
        "ws" | "websocket" => stream.get("wsSettings"),
        "xhttp" | "splithttp" => stream.get("xhttpSettings"),
        "http" | "h2" | "https" => stream.get("httpSettings"),
        "httpupgrade" => stream.get("httpupgradeSettings"),
        _ => None,
    };
    settings.and_then(|settings| text_opt(&text(settings, "path")))
}

fn security_from_profile(profile: &NpvtProfile) -> SecurityConfig {
    match profile.security.as_str() {
        "tls" => SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: text_opt(&profile.sni),
                alpn: text_opt(&profile.alpn),
                fp: text_opt(&profile.fingerprint),
                insecure: Some(profile.insecure),
                pcs: text_opt(&profile.pinned_sha256),
                ..TlsOpts::default()
            })),
            enc: None,
        },
        "reality" => SecurityConfig {
            tls: Some(TlsConfig::Reality(RealityOpts {
                sni: text_opt(&profile.sni),
                fp: text_opt(&profile.fingerprint),
                pbk: text_opt(&profile.public_key).map(String::from),
                sid: text_opt(&profile.short_id),
                spx: text_opt(&profile.spider_x),
                mldsa65_verify: text_opt(&profile.mldsa65_verify).map(String::from),
            })),
            enc: None,
        },
        _ => SecurityConfig::default(),
    }
}

fn security_from_xray(stream: &Value) -> SecurityConfig {
    match text(stream, "security").as_str() {
        "tls" => {
            let tls = stream.get("tlsSettings").unwrap_or(&Value::Null);
            SecurityConfig {
                tls: Some(TlsConfig::Tls(TlsOpts {
                    sni: text_opt(&text(tls, "serverName")),
                    alpn: array_join(tls, "alpn"),
                    fp: text_opt(&text(tls, "fingerprint")),
                    insecure: Some(truthy(tls, "allowInsecure")),
                    pcs: text_opt(&text(tls, "pinnedPeerCertSha256")),
                    ..TlsOpts::default()
                })),
                enc: None,
            }
        }
        "reality" => {
            let reality = stream.get("realitySettings").unwrap_or(&Value::Null);
            SecurityConfig {
                tls: Some(TlsConfig::Reality(RealityOpts {
                    sni: text_opt(&text(reality, "serverName")),
                    fp: text_opt(&text(reality, "fingerprint")),
                    pbk: text_opt(&text(reality, "publicKey")).map(String::from),
                    sid: text_opt(&text(reality, "shortId")),
                    spx: text_opt(&text(reality, "spiderX")),
                    mldsa65_verify: text_opt(&text(reality, "mldsa65Verify")).map(String::from),
                })),
                enc: None,
            }
        }
        _ => SecurityConfig::default(),
    }
}

fn transport_from_profile(profile: &NpvtProfile) -> TransportConfig {
    transport(
        &profile.network,
        &profile.path,
        &profile.host,
        &profile.header_type,
        &profile.seed,
        &profile.mode,
        &profile.service_name,
        &profile.authority,
        &profile.xhttp_mode,
        &profile.xhttp_extra,
    )
}

fn transport_from_xray(stream: &Value) -> TransportConfig {
    let network = text(stream, "network");
    let settings = match network.to_ascii_lowercase().as_str() {
        "ws" | "websocket" => stream.get("wsSettings"),
        "grpc" => stream.get("grpcSettings"),
        "xhttp" | "splithttp" => stream.get("xhttpSettings"),
        "kcp" | "mkcp" => stream.get("kcpSettings"),
        "http" | "h2" | "https" => stream.get("httpSettings"),
        "httpupgrade" => stream.get("httpupgradeSettings"),
        _ => None,
    }
    .unwrap_or(&Value::Null);
    let header_type = text(settings.get("header").unwrap_or(&Value::Null), "type");
    transport(
        &network,
        &text(settings, "path"),
        &text(settings, "host"),
        &header_type,
        &text(settings, "seed"),
        &text(settings, "mode"),
        &text(settings, "serviceName"),
        &text(settings, "authority"),
        &text(settings, "mode"),
        &settings
            .get("extra")
            .map_or_else(String::new, ToString::to_string),
    )
}

fn transport(
    network: &str,
    path: &str,
    host: &str,
    header_type: &str,
    seed: &str,
    mode: &str,
    service_name: &str,
    authority: &str,
    xhttp_mode: &str,
    xhttp_extra: &str,
) -> TransportConfig {
    let path = text_opt(path);
    let host = text_opt(host);
    match network.to_ascii_lowercase().as_str() {
        "ws" | "websocket" => TransportConfig::Ws(WebSocketConfig {
            path,
            host,
            ..WebSocketConfig::default()
        }),
        "grpc" => TransportConfig::Grpc(GrpcConfig {
            service_name: text_opt(service_name),
            authority: text_opt(authority),
            mode: text_opt(mode),
            ..GrpcConfig::default()
        }),
        "http" | "h2" | "https" => TransportConfig::Http(HttpConfig {
            path,
            host,
            ..HttpConfig::default()
        }),
        "kcp" | "mkcp" => TransportConfig::Kcp(KcpConfig {
            seed: text_opt(seed),
            header_type: text_opt(header_type),
            ..KcpConfig::default()
        }),
        "httpupgrade" => TransportConfig::HttpUpgrade(HttpUpgradeConfig {
            path: path.or_else(|| Some(TinyText::from("/"))),
            host,
            ..HttpUpgradeConfig::default()
        }),
        "xhttp" | "splithttp" => TransportConfig::XHttp(XHttpConfig {
            path: path.or_else(|| Some(TinyText::from("/"))),
            host,
            mode: text_opt(xhttp_mode),
            extra: serde_json::from_str::<Value>(xhttp_extra).ok(),
            ..XHttpConfig::default()
        }),
        "quic" => TransportConfig::Quic,
        _ => TransportConfig::Tcp,
    }
}

fn endpoint(host: &str, port: u16) -> EndpointEssentials {
    let host = host.trim_matches(['[', ']']);
    let host_type = host
        .parse::<std::net::IpAddr>()
        .map_or(HostKind::Dns, |ip| match ip {
            std::net::IpAddr::V4(_) => HostKind::Ipv4,
            std::net::IpAddr::V6(_) => HostKind::Ipv6,
        });
    EndpointEssentials {
        host: host.to_owned(),
        host_type,
        port,
        ports: vec![port],
    }
}

fn text(value: &Value, key: &str) -> String {
    value.get(key).map_or_else(String::new, |v| match v {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Null | Value::Array(_) | Value::Object(_) => String::new(),
    })
}

fn text_opt(value: &str) -> Option<TinyText> {
    (!value.is_empty()).then(|| TinyText::from(value))
}

fn int(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(|v| match v {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    })
}

fn truthy(value: &Value, key: &str) -> bool {
    value.get(key).is_some_and(|v| match v {
        Value::Bool(flag) => *flag,
        Value::String(text) => matches!(text.trim(), "true" | "1" | "yes"),
        Value::Number(number) => number.as_i64() == Some(1),
        _ => false,
    })
}

fn array_join(value: &Value, key: &str) -> Option<TinyText> {
    let items = value.get(key)?.as_array()?;
    let joined = items
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(",");
    (!joined.is_empty()).then(|| TinyText::from(joined))
}

fn host_from_address(address: &str) -> String {
    address
        .rsplit_once(':')
        .map_or_else(String::new, |(host, _)| {
            host.trim_matches(['[', ']']).to_owned()
        })
}

fn port_from_address(address: &str) -> u16 {
    address
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_all_markers() {
        assert_eq!(detect(b"NPVT1\nAAAA"), Some(Format::Legacy));
        assert_eq!(detect(b"  NPVTSUB1\nAAAA"), Some(Format::Legacy));
        assert_eq!(detect(b"NPVO1\n{}"), Some(Format::Open));
        assert_eq!(detect(b"NPVS\x01\x00\x00\x00\x00"), Some(Format::Sealed(1)));
        assert_eq!(detect(b"NPVS\x05\x00\x00\x00\x00"), Some(Format::Sealed(5)));
        assert_eq!(detect(b"vmess://x"), None);
    }

    #[test]
    fn open_bundle_schema() {
        let data = br#"NPVO1
{"configs":[{"name":"a","address":"h:1","type":"v2ray","message":"npvs1:aGk="}]}"#;
        let bundle = decode(data, None).unwrap();
        assert_eq!(bundle.configs.len(), 1);
        assert_eq!(bundle.configs[0]["message"], "hi");
    }

    fn seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
        let nonce: &Nonce = nonce.try_into().unwrap();
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap()
    }

    fn b64(bytes: &[u8]) -> String {
        STANDARD_NO_PAD.encode_to_string(bytes)
    }

    /// Synthetic round trip: it proves the parser wires the v1 app-key path
    /// together, not that the KDK derivation matches the client. A wrong
    /// label/table variant would still pass this test; only a real sealed app
    /// export can pin that. The two-table variant rule from the reference is
    /// likewise untested here.
    #[test]
    fn v1_app_key_envelope_opens() {
        let salt = [7u8; 16];
        let cek = [9u8; 32];
        let wrap_nonce = [1u8; 12];
        let kdk = v1_app_key_kdk(&salt);
        let mut wrap = wrap_nonce.to_vec();
        wrap.extend(seal(&*kdk, &wrap_nonce, &cek, &salt));

        let header = serde_json::json!({
            "v": 1,
            "configId": b64(&[0u8; 16]),
            "issuedAt": "2026-01-01T00:00:00Z",
            "creator": {"fp": b64(&[1u8; 32]), "pk": b64(&[2u8; 33])},
            "policy": {},
            "recipients": [],
            "appKey": {"kdf": "wbaes-ctr-sha256", "keyId": 1, "salt": b64(&salt), "wrap": b64(&wrap)}
        });
        let header_raw = serde_json::to_vec(&header).unwrap();
        let body_nonce = [2u8; 12];
        let body = seal(
            &cek,
            &body_nonce,
            br#"{"configs":[{"name":"x"}]}"#,
            &header_raw,
        );

        let mut envelope = b"NPVS\x01".to_vec();
        envelope.extend(u32::try_from(header_raw.len()).unwrap().to_be_bytes());
        envelope.extend(&header_raw);
        envelope.extend(body_nonce);
        envelope.extend(u32::try_from(body.len()).unwrap().to_be_bytes());
        envelope.extend(&body);
        envelope.extend([0u8; 64]);

        let bundle = decode(&envelope, None).unwrap();
        assert_eq!(bundle.version, 1);
        assert_eq!(bundle.configs[0]["name"], "x");
    }

    #[test]
    fn v5_app_key_envelope_is_reported_unsupported() {
        let mut header = vec![1u8];
        header.extend([0u8; 16]);
        header.extend([0u8; 33]);
        header.push(SEALED_V5_METHOD_APPKEY);
        header.extend(0u16.to_be_bytes());
        header.extend([0u8, SEALED_V5_METHOD_APPKEY]);
        header.extend([3u8; 16]);
        header.extend([4u8; 60]);
        header.extend(0u32.to_be_bytes());

        let mut envelope = b"NPVS".to_vec();
        envelope.push(SEALED_V5);
        envelope.extend(u32::try_from(header.len()).unwrap().to_be_bytes());
        envelope.extend(&header);
        envelope.extend([0u8; 12]);
        envelope.extend(0u32.to_be_bytes());
        envelope.extend([0u8; 64]);

        assert!(matches!(
            decode(&envelope, None),
            Err(NpvtError::Unsupported(
                "version-5 app-key envelopes are not implemented"
            ))
        ));
    }
}
