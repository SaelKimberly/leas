//! `VMess` AEAD request header codec (v2ray `proxy/vmess/encoding/client.go`
//! + `proxy/vmess/aead/encrypt.go`).

use aes::cipher::KeyInit;
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, Payload};

use crate::addr::{TargetAddr, encode_addr};
use crate::error::NativeError;
use crate::protocol::vmess::keys;

pub const VERSION: u8 = 1;
pub const SECURITY_AES128_GCM: u8 = 3;
pub const SECURITY_CHACHA20_POLY1305: u8 = 4;
pub const COMMAND_TCP: u8 = 1;
/// UDP command byte (`RequestCommandUDP`).
pub const COMMAND_UDP: u8 = 2;

/// Per-connection `VMess` session material (mirrors Go `ClientSession`).
///
/// Wipes every field on drop: the request/response body keys protect the
/// whole tunnel, and the struct lives as long as the connection does.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct Session {
    pub request_body_iv: [u8; 16],
    pub request_body_key: [u8; 16],
    pub response_header: u8,
    pub response_body_key: [u8; 16],
    pub response_body_iv: [u8; 16],
    /// Payload security byte (header body byte 35): 3 = AES-128-GCM,
    /// 4 = chacha20-poly1305. `connect` sets it from the config.
    pub security: u8,
}

impl Session {
    /// CSPRNG request IV/key/response header; response keys are the first 16
    /// bytes of sha256(request key/iv) — Go `NewClientSession`.
    #[must_use]
    pub fn new() -> Self {
        let mut iv = [0u8; 16];
        let mut key = [0u8; 16];
        let mut resp_header = [0u8; 1];
        rand_bytes(&mut iv);
        rand_bytes(&mut key);
        rand_bytes(&mut resp_header);
        Self {
            request_body_iv: iv,
            request_body_key: key,
            response_header: resp_header[0],
            response_body_key: keys::sha256_first16(&key),
            response_body_iv: keys::sha256_first16(&iv),
            security: SECURITY_AES128_GCM,
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// CSPRNG fill for per-connection session randomness (ring, same provider
/// rustls uses).
fn rand_bytes(out: &mut [u8]) {
    use ring::rand::{SecureRandom, SystemRandom};
    SystemRandom::new().fill(out).expect("rng failure");
}

/// Encode the sealed AEAD request header for `command` (1 = TCP, 2 = UDP).
///
/// `entropy` supplies the 4-byte auth-rand and 8-byte connection nonce (fixed
/// for tests). The header body (Go `EncodeRequestHeader`):
/// version | IV | key | respHeader | option=0 | security={session.security} | 0 | cmd |
/// port BE2 | addrType | addr | fnv1a32. Wire (Go `SealVMessAEADHeader`):
/// authID(16) | lenAEAD(18) | nonce(8) | payloadAEAD.
///
/// NOTE on address order: `VMess` uses the same `PortThenAddress()` parser as
/// VLESS in both Xray-core and v2ray-core (proxy/vmess/encoding/encoding.go),
/// mihomo, and sing-vmess — the port comes FIRST, then the address type byte
/// and bytes. The crate's [`encode_addr`] already emits exactly that order.
pub fn encode_request(
    cmd_key: &[u8; 16],
    session: &Session,
    target: &TargetAddr,
    command: u8,
    auth_ts: i64,
    entropy: &mut impl FnMut(&mut [u8]),
) -> Result<Vec<u8>, NativeError> {
    // --- plaintext header body (49 bytes for the minimal TCP/IPv4 form) ---
    let mut body = Vec::with_capacity(49);
    body.push(VERSION);
    body.extend_from_slice(&session.request_body_iv);
    body.extend_from_slice(&session.request_body_key);
    body.push(session.response_header);
    body.push(0); // option (basic format; chunk-stream option is Task 6)
    body.push(session.security); // padding nibble 0 | security byte
    body.push(0); // reserved
    body.push(command);
    encode_address_port(&mut body, target)?;
    // padding: length 0 (we send the minimal body)
    let fnv = keys::fnv1a32(&body);
    body.extend_from_slice(&fnv.to_be_bytes());

    // --- randomness for the seal ---
    let mut auth_rand = [0u8; 4];
    entropy(&mut auth_rand);
    let auth_id = keys::auth_id(cmd_key, auth_ts, &auth_rand);
    let mut conn_nonce = [0u8; 8];
    entropy(&mut conn_nonce);

    // --- length AEAD (seals the 2-byte BE body length) ---
    let len_key = keys::kdf16_bytes_path(
        cmd_key,
        &[b"VMess Header AEAD Key_Length", &auth_id, &conn_nonce],
    );
    let len_nonce = keys::kdf_bytes_path(
        cmd_key,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &conn_nonce],
    );
    let len_cipher = {
        let len_aead = Aes128Gcm::new_from_slice(&len_key).expect("16-byte key");
        let plain = u16::try_from(body.len()).expect("vmess body length fits u16");
        len_aead
            .encrypt(
                (&len_nonce[..12]).try_into().unwrap(),
                Payload {
                    msg: &plain.to_be_bytes(),
                    aad: &auth_id,
                },
            )
            .expect("aes-gcm seal infallible for 16-byte key")
    };

    // --- payload AEAD (seals the header body) ---
    let body_key =
        keys::kdf16_bytes_path(cmd_key, &[b"VMess Header AEAD Key", &auth_id, &conn_nonce]);
    let body_nonce = keys::kdf_bytes_path(
        cmd_key,
        &[b"VMess Header AEAD Nonce", &auth_id, &conn_nonce],
    );
    let body_cipher = {
        let body_aead = Aes128Gcm::new_from_slice(&body_key).expect("16-byte key");
        body_aead
            .encrypt(
                (&body_nonce[..12]).try_into().unwrap(),
                Payload {
                    msg: &body,
                    aad: &auth_id,
                },
            )
            .expect("aes-gcm seal infallible for 16-byte key")
    };

    // --- wire: authID | lenAEAD | nonce | payloadAEAD ---
    let mut out = Vec::with_capacity(peek_seal_len(body.len()));
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&len_cipher);
    out.extend_from_slice(&conn_nonce);
    out.extend_from_slice(&body_cipher);
    Ok(out)
}

/// Wire length of a sealed request given the plaintext header body length:
/// authID(16) + lenAEAD(18) + nonce(8) + body + GCM tag(16).
#[must_use]
pub const fn peek_seal_len(body_len: usize) -> usize {
    16 + 18 + 8 + body_len + 16
}

/// Append the `VMess` target address to `body`: port BE2 first, then the
/// address (type byte + payload). `VMess` uses the same port-first
/// `PortThenAddress()` order as VLESS — Go `encoding.go` address parser —
/// which is exactly what [`encode_addr`] emits.
fn encode_address_port(body: &mut Vec<u8>, target: &TargetAddr) -> Result<(), NativeError> {
    body.extend_from_slice(&encode_addr(target)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Host, TargetAddr};
    use crate::protocol::vmess::keys::cmd_key;

    fn fixed_session() -> Session {
        let mut s = Session::new();
        s.request_body_iv = [0x11; 16];
        s.request_body_key = [0x22; 16];
        s.response_header = 0x33;
        s.response_body_key = [0x44; 16];
        s.response_body_iv = [0x55; 16];
        s
    }

    /// Deterministic entropy: the 4-byte auth-rand must be aabbccdd for the
    /// authID golden; the 8-byte connection nonce and anything else = 0xAB.
    fn fixed_entropy(out: &mut [u8]) {
        if out.len() == 4 {
            out.copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        } else {
            out.fill(0xAB);
        }
    }

    #[test]
    fn request_wire_lengths() {
        let ck = cmd_key(&[0; 16]);
        let tgt = TargetAddr::new(Host::Ip("127.0.0.1".parse().unwrap()), 80);
        let s = fixed_session();
        let wire = encode_request(
            &ck,
            &s,
            &tgt,
            COMMAND_TCP,
            0x6000_0000_0000_0000,
            &mut fixed_entropy,
        )
        .unwrap();
        // body = 38 fixed + port 2 + addr(1+4) + fnv 4 = 49; payloadAEAD = 49+16; lenAEAD 18; authID 16; nonce 8
        assert_eq!(wire.len(), 16 + 18 + 8 + 49 + 16);
        // authID golden (ts=0x6000000000000000, rand=aabbccdd, fixed cmdKey) —
        // verified against the vendored Xray-core aead package + openssl.
        assert_eq!(&wire[..16], &hex_decode("9becfee74d1a702389bc60e9f200e6de"));
    }

    #[test]
    fn request_contains_session_material() {
        // bytes after the 16-byte authID are ciphertext — session IV/key never
        // appear in plaintext anywhere on the wire (wire[42..] is sealed).
        let ck = cmd_key(&[0; 16]);
        let tgt = TargetAddr::new(Host::Ip("127.0.0.1".parse().unwrap()), 80);
        let s = fixed_session();
        let wire = encode_request(&ck, &s, &tgt, COMMAND_TCP, 42, &mut fixed_entropy).unwrap();
        assert!(!wire[..16].iter().any(|b| *b == 0x11 || *b == 0x22)); // authID is ciphertext
        assert_eq!(wire.len(), 16 + 18 + 8 + 49 + 16);
    }

    /// Unseal a request's payload AEAD and return the plaintext header body,
    /// checking that the lenAEAD announces exactly that body. The key/nonce
    /// derivation depends only on `ck`, the authID and the connection nonce —
    /// all on the wire — so a test needs no session material to read a
    /// sealed body back.
    fn unseal_request_body(ck: &[u8; 16], wire: &[u8]) -> Vec<u8> {
        let auth_id = &wire[..16];
        let len_cipher = &wire[16..34];
        let nonce = &wire[34..42];
        let body_cipher = &wire[42..];

        let len_key =
            keys::kdf16_bytes_path(ck, &[b"VMess Header AEAD Key_Length", auth_id, nonce]);
        let len_nonce =
            keys::kdf_bytes_path(ck, &[b"VMess Header AEAD Nonce_Length", auth_id, nonce]);
        let len_plain = Aes128Gcm::new_from_slice(&len_key)
            .unwrap()
            .decrypt(
                (&len_nonce[..12]).try_into().unwrap(),
                Payload {
                    msg: len_cipher,
                    aad: auth_id,
                },
            )
            .unwrap();

        let body_key = keys::kdf16_bytes_path(ck, &[b"VMess Header AEAD Key", auth_id, nonce]);
        let body_nonce = keys::kdf_bytes_path(ck, &[b"VMess Header AEAD Nonce", auth_id, nonce]);
        let body = Aes128Gcm::new_from_slice(&body_key)
            .unwrap()
            .decrypt(
                (&body_nonce[..12]).try_into().unwrap(),
                Payload {
                    msg: body_cipher,
                    aad: auth_id,
                },
            )
            .unwrap();

        assert_eq!(
            len_plain,
            u16::try_from(body.len()).unwrap().to_be_bytes(),
            "the lenAEAD must announce the body it seals"
        );
        body
    }

    #[test]
    fn request_plaintext_body_layout_is_port_first() {
        // Wire authority: VMess uses the same PortThenAddress() parser as
        // VLESS (Xray-core + v2ray-core proxy/vmess/encoding/encoding.go,
        // mihomo transport/vmess/conn.go, sing-vmess protocol.go) — the
        // header address is PORT FIRST, then type byte + bytes. Unseal the
        // payload AEAD and pin the exact plaintext layout, including the FNV
        // checksum over the port-first body.
        //
        // Both commands are pinned: the UDP path turns exactly one body byte
        // on, and the FNV checksum runs over the body, so each command has
        // its own golden — a wrong `COMMAND_UDP` (3, trojan's value) fails
        // here instead of only against a live core. Upstream values:
        // `RequestCommandTCP = 0x01`, `RequestCommandUDP = 0x02`
        // (Xray-core `common/protocol/headers.go:15-16`).
        let ck = cmd_key(&[0; 16]);
        let tgt = TargetAddr::new(Host::Ip("127.0.0.1".parse().unwrap()), 80);
        let s = fixed_session();
        for (command, fnv) in [
            (COMMAND_TCP, 0x273b_d20a_u32),
            (COMMAND_UDP, 0x2139_6fa9_u32),
        ] {
            let wire = encode_request(&ck, &s, &tgt, command, 42, &mut fixed_entropy).unwrap();
            let body = unseal_request_body(&ck, &wire);

            // 49 bytes: 38 fixed + 2 port + 5 addr + 4 fnv.
            let mut expect = vec![VERSION];
            expect.extend_from_slice(&[0x11; 16]);
            expect.extend_from_slice(&[0x22; 16]);
            expect.extend_from_slice(&[0x33, 0x00, 0x03, 0x00, command]);
            expect.extend_from_slice(&80u16.to_be_bytes()); // port FIRST
            expect.extend_from_slice(&[0x01, 127, 0, 0, 1]); // addrType IPv4 + 127.0.0.1
            expect.extend_from_slice(&fnv.to_be_bytes()); // fnv1a32(port-first body)
            assert_eq!(body, expect, "command {command}");
        }
    }

    #[test]
    fn request_wire_matches_go_xray_aead() {
        // Full-wire golden, cross-verified against the vendored Xray-core
        // proxy/vmess/aead package (kdf.go + consts.go) with the same fixed
        // inputs: cmdKey zero-UUID, ts=42, auth-rand aabbccdd, nonce 0xAB x8.
        // The Go seal (identical bytes) was produced by:
        //   aead.KDF16/aead.KDF with string(authID)/string(nonce) byte paths
        //   + AES-128-GCM with AAD = authID, output authID|lenAEAD|nonce|bodyAEAD.
        let ck = cmd_key(&[0; 16]);
        let tgt = TargetAddr::new(Host::Ip("127.0.0.1".parse().unwrap()), 80);
        let s = fixed_session();
        let wire = encode_request(&ck, &s, &tgt, COMMAND_TCP, 42, &mut fixed_entropy).unwrap();
        assert_eq!(
            hex_encode(&wire),
            "79d348cf6b4707cf6acbb494bf257f1de2d3f7fed70400fdc38997b98856e876eea6abababababababab988161deb14ca4eb23a17a1a8bef86e406b8fd0192d050514be96e66e75ebc4ac82dbbbe0fa3ef08d80e26f393f4dea4c96aee6878ba3a7d22cceba18a67028d7e"
        );
    }

    #[test]
    fn request_security_byte_is_writable() {
        // Body layout: version(1) IV(16) key(16) respHdr(1) option(1) = 35, so
        // the security byte sits at body index 35.
        let ck = [0x55u8; 16];
        let mut session = Session::new();
        session.request_body_iv = [0x11; 16];
        session.request_body_key = [0x22; 16];
        session.security = SECURITY_CHACHA20_POLY1305;
        let mut entropy = |out: &mut [u8]| out.fill(0x77);
        let target = TargetAddr::new(Host::Ip("127.0.0.1".parse().unwrap()), 8080);
        let wire = encode_request(
            &ck,
            &session,
            &target,
            COMMAND_TCP,
            0x6000_0000_0000_0000,
            &mut entropy,
        )
        .unwrap();
        assert_eq!(wire.len(), peek_seal_len(49));

        // This test pins the task's central contract: `encode_request` must
        // write `session.security` (4 = chacha20-poly1305) at plaintext body
        // index 35 — NOT a hardcoded default. The security byte is inside the
        // sealed payload, so unseal the body AEAD (the shared
        // `unseal_request_body` helper).
        let body = unseal_request_body(&ck, &wire);

        // 35 = version(1) IV(16) key(16) respHdr(1) option(1).
        assert_eq!(body[35], SECURITY_CHACHA20_POLY1305);
        // chacha20-poly1305 security byte = 4 (RFC 7905 / xray common).
        assert_eq!(SECURITY_CHACHA20_POLY1305, 4);
    }

    fn hex_encode(b: &[u8]) -> String {
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
