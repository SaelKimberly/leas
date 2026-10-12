//! Shadowsocks UDP relay: the classic-AEAD datagram codec, the 2022-blake3
//! session codec, and the dial-end carrier that speaks both.
//!
//! Shadowsocks' UDP relay is a **dial-end**, not a stream carrier: the client
//! sends datagrams to the SS server's own UDP port ([`connect_udp`] binds a
//! fresh `UdpSocket` and connects it), so one SS packet is exactly one UDP
//! datagram — no length prefix, no in-tunnel framing, and no room for a chain
//! (`chain.rs::ss_udp_guard` refuses one).
//!
//! Classic AEAD (mihomo `shadowaead/packet.go` [`Pack`]/[`Unpack`]):
//!
//! ```text
//! packet = [salt][seal(all-zero nonce, ATYP|addr|port ‖ payload)]
//! ```
//!
//! A fresh salt — and therefore subkey — per datagram. The address is ALWAYS
//! on the wire, so `send(None)` means the session target. 2022-blake3 (2022
//! edition spec §3.2/§4.1, shadowsocks-rust `relay/udprelay/aead_2022.rs`):
//! the AES methods carry an AES-ECB separate header (`[session_id u64be ‖
//! packet_id u64be]`) and seal the body with the per-session subkey under the
//! **plaintext** header's `[4..16]` nonce; the `ChaCha` method prepends a
//! 24-byte random nonce and seals the merged
//! `[client_session_id ‖ packet_id ‖ body]` with the PSK directly.
//!
//! [`Pack`]: thirdparty/mihomo/transport/shadowsocks/shadowaead/packet.go
//! [`Unpack`]: thirdparty/mihomo/transport/shadowsocks/shadowaead/packet.go
//!
//! Both families use the SOCKS5 port-last address family
//! ([`crate::addr::encode_addr_port_last`] /
//! [`crate::addr::decode_addr_port_last`]): an IPv4 address is 7 bytes in
//! either family, so a wrong-family test would still pass while the wire was
//! wrong.

use std::borrow::Cow;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use leas_proto::proto_spec::{ProtocolKind, SsConfig};
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

use crate::addr::{Host, TargetAddr, decode_addr_port_last, write_addr_port_last};
use crate::context::LinkContext;
use crate::crypto::aead::SsAead;
use crate::error::NativeError;
use crate::protocol::ss::consts::{
    MAX_PADDING, TIMESTAMP_TOLERANCE_SECS, now_unix_secs, s2022_error,
};
use crate::protocol::ss::method::{
    SsFamily, SsMethod, password_key, stream_subkey, stream_subkey_into,
};
use crate::rand::{fill_nonsecret, u32_below};

/// Largest datagram this carrier reads into its scratch buffer — one UDP
/// datagram can never exceed it (mihomo's `maxPacketSize`, 64 KiB).
const MAX_DATAGRAM: usize = 64 * 1024;

/// Largest payload one SS datagram may carry.
///
/// The cap bounds the SEALED datagram, not just the plaintext: the
/// worst-case overhead a method can add is 326 bytes (2022 `ChaCha`: a 24-byte
/// nonce, the 16-byte merged id pair, the 11-byte main header, the 259-byte
/// encoded 255-byte domain address and the 16-byte tag), so
/// `MAX_PAYLOAD + 326 = 65326` stays under the 65507 bytes an IPv4 UDP payload
/// can hold. A bigger payload would be refused by the kernel with `EMSGSIZE`
/// instead of a clean error.
const MAX_PAYLOAD: usize = 65_000;

/// Spec §3.2.4's rotation gate: keeping one old and one current server session
/// is only allowed while the client "reject[s] newer server sessions when the
/// last packet received from the old session is less than 1 minute old".
///
/// Without it, a replayed capture whose timestamp is still inside the ±30 s
/// window could rotate the table away from a live session — replaying a dead
/// session must not disturb the one that is actually delivering.
const ROTATION_QUIET: Duration = Duration::from_secs(60);

/// 2022 separate header: `session_id u64be ‖ packet_id u64be` — exactly one
/// AES block, so the ECB call needs no padding.
const SEPARATE_HEADER_LEN: usize = 16;

/// 2022 `ChaCha` UDP leading nonce length (spec §4.1: XChaCha20-Poly1305).
const CHACHA_NONCE_LEN: usize = 24;

/// Client→server message type (spec §3.2.3).
const HEADER_TYPE_CLIENT_PACKET: u8 = 0;

/// Server→client message type (spec §3.2.3).
const HEADER_TYPE_SERVER_PACKET: u8 = 1;

/// A decoded datagram: the origin address the reply header carried (`None`
/// when that origin is a domain — a `TargetAddr` domain has no `SocketAddr`),
/// plus the payload.
type Datagram = (Option<SocketAddr>, Vec<u8>);

/// The reusable send scratch of one direction: the sealed packet, the
/// plaintext body it is sealed from, and the classic subkey (a fresh one per
/// datagram).
///
/// Both buffers keep their capacity across datagrams, so the steady-state
/// send path allocates nothing; the subkey buffer is wiped by `Zeroizing`.
#[derive(Default)]
struct SendBuf {
    packet: Vec<u8>,
    body: Vec<u8>,
    subkey: Zeroizing<Vec<u8>>,
}

impl SendBuf {
    /// Start a datagram: both buffers are emptied, their capacity kept.
    fn begin(&mut self) {
        self.packet.clear();
        self.body.clear();
    }
}

/// A wire failure in the classic codec (`NativeError::Protocol` with the
/// classic kind).
fn datagram_error(detail: &str) -> NativeError {
    NativeError::Protocol {
        kind: ProtocolKind::Shadowsocks,
        detail: detail.to_owned(),
    }
}

/// A `SocketAddr` destination as a wire `TargetAddr` (the IP families only —
/// a `SocketAddr` cannot carry a domain).
fn target_from_socket(address: SocketAddr) -> TargetAddr {
    TargetAddr::new(Host::Ip(address.ip()), address.port())
}

/// A decoded origin as a `SocketAddr`; `None` for a domain origin, which has
/// no `SocketAddr` form.
const fn socket_addr(origin: &TargetAddr) -> Option<SocketAddr> {
    match &origin.host {
        Host::Ip(ip) => Some(SocketAddr::new(*ip, origin.port)),
        Host::Domain(_) => None,
    }
}

/// Read one big-endian `u64`, returning it with the unconsumed tail.
fn read_u64(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (head, tail) = bytes.split_at_checked(8)?;
    Some((u64::from_be_bytes(head.try_into().ok()?), tail))
}

/// Read one big-endian `u16`, returning it with the unconsumed tail.
fn read_u16(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let (head, tail) = bytes.split_at_checked(2)?;
    Some((u16::from_be_bytes(head.try_into().ok()?), tail))
}

/// One classic-AEAD datagram INTO `buf`: `[salt][seal(all-zero nonce,
/// addr ‖ payload)]`.
///
/// A fresh random salt (and therefore subkey) per call — a server-side replay
/// cache keyed on the salt must never see the same one twice. The address is
/// written straight into the body scratch, so nothing is allocated per
/// datagram in steady state.
fn seal_datagram_into(
    method: SsMethod,
    key: &[u8],
    dest: &TargetAddr,
    payload: &[u8],
    buf: &mut SendBuf,
) -> Result<(), NativeError> {
    let salt_len = method.aead.salt_len();
    let mut salt = [0u8; 32];
    let salt = &mut salt[..salt_len];
    fill_nonsecret(salt);
    buf.begin();
    if buf.subkey.len() != method.key_len() {
        buf.subkey.resize(method.key_len(), 0);
    }
    stream_subkey_into(method, key, salt, &mut buf.subkey);
    buf.packet.extend_from_slice(salt);
    write_addr_port_last(&mut buf.body, dest)?;
    buf.body.extend_from_slice(payload);
    // The classic codec seals under the all-zero nonce (`mihomo` `_zerononce`);
    // one datagram per seal is what makes that safe.
    let zero_nonce = [0u8; CHACHA_NONCE_LEN];
    method.aead.seal_into(
        &buf.subkey,
        &zero_nonce[..method.aead.nonce_len()],
        b"",
        &buf.body,
        &mut buf.packet,
    )
}

/// [`seal_datagram_into`] with a fresh buffer: the test/lookup-facing form.
#[cfg(test)]
fn seal_datagram(
    method: SsMethod,
    key: &[u8],
    dest: &TargetAddr,
    payload: &[u8],
) -> Result<Vec<u8>, NativeError> {
    let mut buf = SendBuf::default();
    seal_datagram_into(method, key, dest, payload, &mut buf)?;
    Ok(buf.packet)
}

/// One received classic-AEAD datagram: salt → subkey → open → address/payload.
fn open_datagram(
    method: SsMethod,
    key: &[u8],
    packet: &[u8],
) -> Result<(TargetAddr, Vec<u8>), NativeError> {
    let salt_len = method.aead.salt_len();
    if packet.len() < salt_len + method.aead.tag_len() {
        return Err(datagram_error("short datagram"));
    }
    let subkey = stream_subkey(method, key, &packet[..salt_len]);
    let zero_nonce = [0u8; CHACHA_NONCE_LEN];
    let body = method.aead.open(
        &subkey,
        &zero_nonce[..method.aead.nonce_len()],
        b"",
        &packet[salt_len..],
    )?;
    let Some((dest, payload)) = decode_addr_port_last(&body) else {
        return Err(datagram_error("undecodable address in datagram"));
    };
    Ok((dest, payload.to_vec()))
}

/// AES-ECB encrypt one 16-byte block under the PSK — the 2022 separate
/// header's cipher (spec §3.2.1).
///
/// 2022 has no AES-192 method, so any other cipher never reaches a separate
/// header and is a config error, not a silent fallback.
fn aes_ecb_encrypt(aead: SsAead, psk: &[u8], block: &mut [u8; 16]) -> Result<(), NativeError> {
    let out = match aead {
        SsAead::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(psk)
                .map_err(|_| NativeError::Config("AES-128 PSK must be 16 bytes".into()))?;
            let mut out = [0u8; 16];
            cipher.encrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        SsAead::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(psk)
                .map_err(|_| NativeError::Config("AES-256 PSK must be 32 bytes".into()))?;
            let mut out = [0u8; 16];
            cipher.encrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        other => {
            return Err(NativeError::Config(format!(
                "{other:?} has no Shadowsocks-2022 separate header (AES methods only)"
            )));
        }
    };
    *block = out;
    Ok(())
}

/// [`aes_ecb_encrypt`]'s inverse — used only by tests and by the reader.
fn aes_ecb_decrypt(aead: SsAead, psk: &[u8], block: &mut [u8; 16]) -> Result<(), NativeError> {
    let out = match aead {
        SsAead::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(psk)
                .map_err(|_| NativeError::Config("AES-128 PSK must be 16 bytes".into()))?;
            let mut out = [0u8; 16];
            cipher.decrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        SsAead::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(psk)
                .map_err(|_| NativeError::Config("AES-256 PSK must be 32 bytes".into()))?;
            let mut out = [0u8; 16];
            cipher.decrypt_block_b2b((&*block).into(), (&mut out).into());
            out
        }
        other => {
            return Err(NativeError::Config(format!(
                "{other:?} has no Shadowsocks-2022 separate header (AES methods only)"
            )));
        }
    };
    *block = out;
    Ok(())
}

/// The wire separate header: `AES-ECB(psk, session_id BE8 ‖ packet_id BE8)`.
fn separate_header_aes(
    aead: SsAead,
    psk: &[u8],
    session_id: u64,
    packet_id: u64,
) -> Result<[u8; SEPARATE_HEADER_LEN], NativeError> {
    let mut header = [0u8; SEPARATE_HEADER_LEN];
    header[..8].copy_from_slice(&session_id.to_be_bytes());
    header[8..].copy_from_slice(&packet_id.to_be_bytes());
    aes_ecb_encrypt(aead, psk, &mut header)?;
    Ok(header)
}

/// The body AEAD nonce: the **plaintext** separate header's `[4..16]`, i.e.
/// the low 4 bytes of the session id followed by all 8 bytes of the packet id
/// (spec §3.2.1).
///
/// Never the wire ciphertext at `packet[4..16]` — the sender encrypts the ids
/// with AES-ECB *after* choosing this nonce, so reading it off the wire would
/// hand the receiver a value the sender never sealed with.
fn separate_header_nonce(session_id: u64, packet_id: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&session_id.to_be_bytes()[4..]);
    nonce[4..].copy_from_slice(&packet_id.to_be_bytes());
    nonce
}

/// The 2022 session subkey: BLAKE3 derive-key over `psk ‖ session_id BE8`,
/// truncated to the method's key length.
///
/// The session id is the salt exactly as the TCP handshake uses it, so this
/// delegates to the ONE owner of that derivation ([`stream_subkey`]) — the
/// 32-byte XOF root is wrong for `2022-blake3-aes-128-gcm`, whose body AEAD
/// takes 16 bytes.
fn udp_session_subkey(method: SsMethod, key: &[u8], session_id: u64) -> Zeroizing<Vec<u8>> {
    stream_subkey(method, key, &session_id.to_be_bytes())
}

/// The AEAD body cipher of a 2022 UDP datagram.
///
/// The `ChaCha` method uses XChaCha20-Poly1305 here (24-byte random nonce) even
/// though its TCP stream uses plain ChaCha20-Poly1305 — spec §4.1: "For TCP,
/// AES-GCM is simply replaced by ChaCha-Poly1305. For UDP, a slightly
/// different construction is used."
const fn udp_cipher(method: SsMethod) -> SsAead {
    match method.family {
        SsFamily::Blake3_2022 => match method.aead {
            SsAead::ChaCha20Poly1305 => SsAead::XChaCha20Poly1305,
            other => other,
        },
        SsFamily::Classic => method.aead,
    }
}

/// Append the client→server main header to the body scratch:
/// `type=0 | ts u64be | pad_len u16be | padding | ATYP|addr|port | payload`.
///
/// Padding is added only to a payload-less datagram (a UDP keep-alive), as
/// shadowsocks-rust's `get_aead_2022_padding_size` does, so real traffic never
/// pays for it. The caller owns `body`: the 2022 `ChaCha` method writes the
/// merged id pair in front of it first.
fn client_body(buf: &mut SendBuf, dest: &TargetAddr, payload: &[u8]) -> Result<(), NativeError> {
    let pad_len = if payload.is_empty() {
        u32_below(MAX_PADDING + 1) as usize
    } else {
        0
    };
    buf.body.push(HEADER_TYPE_CLIENT_PACKET);
    buf.body.extend_from_slice(&now_unix_secs()?.to_be_bytes());
    buf.body.extend_from_slice(
        &u16::try_from(pad_len)
            .expect("padding <= 900")
            .to_be_bytes(),
    );
    let pad_start = buf.body.len();
    buf.body.resize(pad_start + pad_len, 0);
    fill_nonsecret(&mut buf.body[pad_start..]);
    write_addr_port_last(&mut buf.body, dest)?;
    buf.body.extend_from_slice(payload);
    Ok(())
}

/// Parse and validate a server main header
/// (`type=1 | ts u64be | client_session_id BE8 | pad_len u16be | padding |
/// ATYP|addr|port | payload`) out of an authenticated body.
///
/// `None` for every semantic failure: a wrong direction byte, a timestamp
/// outside the ±30 s window (spec §3.2.3), a body echoed for a different
/// client session, or a truncated padding/address run.
fn parse_server_body(body: &[u8], expected_client: u64, now: u64) -> Option<(TargetAddr, Vec<u8>)> {
    let (&kind, rest) = body.split_first()?;
    if kind != HEADER_TYPE_SERVER_PACKET {
        return None;
    }
    let (timestamp, rest) = read_u64(rest)?;
    if timestamp.abs_diff(now) > TIMESTAMP_TOLERANCE_SECS {
        return None;
    }
    let (client_session_id, rest) = read_u64(rest)?;
    if client_session_id != expected_client {
        return None;
    }
    let (pad_len, rest) = read_u16(rest)?;
    let (origin, payload) = decode_addr_port_last(rest.get(usize::from(pad_len)..)?)?;
    Some((origin, payload.to_vec()))
}

/// A packet-id replay window anchored at the highest committed id (spec
/// §3.2.4; WireGuard-style). 1024 ids wide — UDP replies reorder, and a 64-id
/// window would silently drop anything more than 64 packets behind the newest.
struct SlidingWindow {
    /// Highest committed packet id; `None` until the first commit, so a fresh
    /// session slot accepts any first id (a server session always starts at 0
    /// after a restart).
    highest: Option<u64>,
    /// Bit `d` of word `d / 64` = "id `highest - d` was committed". Only the
    /// [`Self::WIDTH`] ids below `highest` are remembered; anything older is
    /// out of window.
    bitmap: [u64; Self::WORDS],
}

impl SlidingWindow {
    /// Window width in packet ids — one bit per id in `bitmap`.
    const WIDTH: u64 = 1024;
    /// `bitmap` words (`WIDTH / 64`).
    const WORDS: usize = (Self::WIDTH / 64) as usize;

    const fn new() -> Self {
        Self {
            highest: None,
            bitmap: [0; Self::WORDS],
        }
    }

    /// Would [`Self::accept`] take `id`? Pure — the check half of the
    /// check/commit split, which must never mutate the window.
    const fn will_accept(&self, id: u64) -> bool {
        match self.highest {
            None => true,
            Some(highest) if id > highest => true,
            Some(highest) => {
                let distance = highest - id;
                distance < Self::WIDTH
                    && self.bitmap[(distance / 64) as usize] & (1u64 << (distance % 64)) == 0
            }
        }
    }

    /// Take `id` if it is in-window and unseen, marking it committed.
    ///
    /// `false` for a duplicate or an id that fell out of the window behind
    /// `highest`.
    const fn accept(&mut self, id: u64) -> bool {
        if !self.will_accept(id) {
            return false;
        }
        match self.highest {
            None => {
                self.highest = Some(id);
                self.bitmap[0] = 1;
            }
            Some(highest) if id > highest => {
                self.slide(id - highest);
                self.bitmap[0] |= 1;
                self.highest = Some(id);
            }
            Some(highest) => {
                let distance = highest - id;
                self.bitmap[(distance / 64) as usize] |= 1u64 << (distance % 64);
            }
        }
        true
    }

    /// Slide the window `shift` ids forward, dropping whatever leaves it.
    const fn slide(&mut self, shift: u64) {
        if shift >= Self::WIDTH {
            self.bitmap = [0; Self::WORDS];
            return;
        }
        let words = (shift / 64) as usize;
        let bits = (shift % 64) as u32;
        let mut i = Self::WORDS;
        while i > 0 {
            i -= 1;
            let low = if i >= words {
                self.bitmap[i - words] << bits
            } else {
                0
            };
            let high = if i > words && bits > 0 {
                self.bitmap[i - words - 1] >> (64 - bits)
            } else {
                0
            };
            self.bitmap[i] = low | high;
        }
    }
}

/// One learned server session: its replay window, its body subkey (AES
/// methods) and when it was last heard from.
struct ServerSlot {
    server_id: u64,
    window: SlidingWindow,
    /// `blake3(psk ‖ server_id BE8)` truncated to the method's key length.
    /// `None` for the `ChaCha` method, which seals with the PSK directly.
    body_subkey: Option<Zeroizing<Vec<u8>>>,
    /// When the last VALIDATED datagram for this session arrived. The current
    /// slot's is the clock §3.2.4's rotation gate reads.
    last_seen: Instant,
}

impl ServerSlot {
    fn new(method: SsMethod, key: &[u8], server_id: u64, now: Instant) -> Self {
        let body_subkey = match method.aead {
            SsAead::Aes128Gcm | SsAead::Aes256Gcm => {
                Some(udp_session_subkey(method, key, server_id))
            }
            _ => None,
        };
        Self {
            server_id,
            window: SlidingWindow::new(),
            body_subkey,
            last_seen: now,
        }
    }
}

/// The client's server-session table: at most one current session and one
/// previous one (spec §3.2.4 — a restarted server issues a new session whose
/// packet ids restart at 0, so the window belongs to the session, not the
/// tunnel).
///
/// The check/commit split is what keeps a spoofed datagram from desyncing the
/// window: [`Self::check`] may run as soon as the separate header decrypts,
/// but it only *tests* membership — [`Self::commit`] advances the window, and
/// the reader calls it only after the body authenticated and the header
/// validated.
struct ServerSessions {
    /// The single local client session (single-user PSK).
    client_session_id: u64,
    method: SsMethod,
    key: Arc<Zeroizing<Vec<u8>>>,
    /// Most recently learned server session.
    current: Option<ServerSlot>,
    /// The one session retained behind `current`.
    previous: Option<ServerSlot>,
}

impl ServerSessions {
    const fn new(client_session_id: u64, method: SsMethod, key: Arc<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            client_session_id,
            method,
            key,
            current: None,
            previous: None,
        }
    }

    /// The slot already tracking `server_id`, if any.
    fn slot(&self, server_id: u64) -> Option<&ServerSlot> {
        [self.current.as_ref(), self.previous.as_ref()]
            .into_iter()
            .flatten()
            .find(|slot| slot.server_id == server_id)
    }

    /// Mutable [`Self::slot`].
    fn slot_mut(&mut self, server_id: u64) -> Option<&mut ServerSlot> {
        [self.current.as_mut(), self.previous.as_mut()]
            .into_iter()
            .flatten()
            .find(|slot| slot.server_id == server_id)
    }

    /// The client session id this table belongs to (single-user PSK: one id).
    const fn client_session_id(&self) -> u64 {
        self.client_session_id
    }

    /// Is `server_id` already tracked? PURE, and separate from [`Self::check`]
    /// because the two `None` cases need opposite handling: a *candidate*
    /// (unknown session) is opened and learned, while a *known* session whose
    /// id is out-of-window is a replay and is dropped outright.
    fn is_known(&self, server_id: u64) -> bool {
        self.slot(server_id).is_some()
    }

    /// The client session id when `server_id` is a known slot with
    /// `packet_id` in-window.
    ///
    /// PURE: no window mutation and no table mutation — a datagram that has
    /// not authenticated yet must not be able to move or evict a session (that
    /// is the whole point of the check/commit split, spec §3.2.4).
    fn check(&self, server_id: u64, packet_id: u64) -> Option<u64> {
        let slot = self.slot(server_id)?;
        slot.window
            .will_accept(packet_id)
            .then_some(self.client_session_id)
    }

    /// The cached body subkey for `server_id` (AES methods only).
    fn body_subkey(&self, server_id: u64) -> Option<&[u8]> {
        self.slot(server_id)?
            .body_subkey
            .as_deref()
            .map(Vec::as_slice)
    }

    /// A CANDIDATE session's body subkey, derived on the fly — opening a
    /// candidate inserts nothing into the table.
    fn candidate_subkey(&self, server_id: u64) -> Zeroizing<Vec<u8>> {
        udp_session_subkey(self.method, &self.key, server_id)
    }

    /// Advance a known `server_id`'s window — called only once the body
    /// authenticated and the header validated (spec §3.2.4). Also refreshes
    /// that slot's `last_seen`.
    fn commit(&mut self, server_id: u64, packet_id: u64, now: Instant) {
        if let Some(slot) = self.slot_mut(server_id) {
            // `check` already proved the id in-window; accepting cannot fail.
            slot.window.accept(packet_id);
            slot.last_seen = now;
        }
    }

    /// May a NEWER server session replace the current one now?
    ///
    /// Spec §3.2.4: while the client keeps one old and one current session it
    /// must "reject newer server sessions when the last packet received from
    /// the old session is less than 1 minute old" — otherwise a replayed
    /// capture whose timestamp still fits the ±30 s window could rotate a live
    /// session out. No current slot means there is nothing to protect.
    fn rotation_allowed(&self, now: Instant) -> bool {
        self.current
            .as_ref()
            .is_none_or(|slot| now.saturating_duration_since(slot.last_seen) >= ROTATION_QUIET)
    }

    /// Learn a validated candidate session: it becomes current, the previous
    /// current slides back, and the one before it is dropped (spec §3.2.4's
    /// "one old, one current").
    ///
    /// Called only after the body opened AND the type, timestamp and echoed
    /// client session id all validated — never for a datagram whose id was
    /// merely decrypted — and only when [`Self::rotation_allowed`] says the
    /// current session has gone quiet.
    fn learn(&mut self, server_id: u64, packet_id: u64, now: Instant) {
        let mut slot = ServerSlot::new(self.method, &self.key, server_id, now);
        slot.window.accept(packet_id);
        self.previous = self.current.take();
        self.current = Some(slot);
    }
}

/// The 2022 send direction: the client session id, its packet counter, and
/// the cached session subkey. Moved wholesale into the writer half by
/// [`SsUdpTunnel::split`].
struct Ss2022WriterState {
    /// UDP body cipher ([`udp_cipher`]).
    aead: SsAead,
    /// The PSK: the AES-ECB key for the separate header, and the AEAD key for
    /// the `ChaCha` method (which uses the PSK directly).
    key: Arc<Zeroizing<Vec<u8>>>,
    client_session_id: u64,
    packet_id: u64,
    subkey: Zeroizing<Vec<u8>>,
}

impl Ss2022WriterState {
    fn new(method: SsMethod, key: Arc<Zeroizing<Vec<u8>>>) -> Self {
        let mut id = [0u8; 8];
        fill_nonsecret(&mut id);
        let client_session_id = u64::from_be_bytes(id);
        let subkey = udp_session_subkey(method, &key, client_session_id);
        Self {
            aead: udp_cipher(method),
            key,
            client_session_id,
            packet_id: 0,
            subkey,
        }
    }

    /// Seal one client→server 2022 datagram for `dest` into `buf`.
    fn seal(
        &mut self,
        dest: &TargetAddr,
        payload: &[u8],
        buf: &mut SendBuf,
    ) -> Result<(), NativeError> {
        let packet_id = self.packet_id;
        buf.begin();
        match self.aead {
            SsAead::Aes128Gcm | SsAead::Aes256Gcm => {
                // The nonce comes from the PLAINTEXT separate header; the
                // wire block is that header encrypted afterwards.
                let nonce = separate_header_nonce(self.client_session_id, packet_id);
                let header =
                    separate_header_aes(self.aead, &self.key, self.client_session_id, packet_id)?;
                buf.packet.extend_from_slice(&header);
                client_body(buf, dest, payload)?;
                self.aead
                    .seal_into(&self.subkey, &nonce, b"", &buf.body, &mut buf.packet)?;
            }
            SsAead::XChaCha20Poly1305 => {
                let mut nonce = [0u8; CHACHA_NONCE_LEN];
                fill_nonsecret(&mut nonce);
                buf.packet.extend_from_slice(&nonce);
                // The merged main header: the id pair travels INSIDE the
                // sealed body, in front of the client header.
                buf.body
                    .extend_from_slice(&self.client_session_id.to_be_bytes());
                buf.body.extend_from_slice(&packet_id.to_be_bytes());
                client_body(buf, dest, payload)?;
                self.aead
                    .seal_into(&self.key, &nonce, b"", &buf.body, &mut buf.packet)?;
            }
            other => {
                return Err(NativeError::Config(format!(
                    "{other:?} is not a Shadowsocks-2022 UDP cipher"
                )));
            }
        }
        self.packet_id = self.packet_id.wrapping_add(1);
        Ok(())
    }
}

/// The 2022 receive direction: the PSK (for the `ChaCha` method and the AES-ECB
/// separate header) plus the server-session table. Moved wholesale into the
/// reader half by [`SsUdpTunnel::split`].
struct Ss2022ReaderState {
    aead: SsAead,
    key: Arc<Zeroizing<Vec<u8>>>,
    sessions: ServerSessions,
}

impl Ss2022ReaderState {
    fn new(method: SsMethod, key: Arc<Zeroizing<Vec<u8>>>, client_session_id: u64) -> Self {
        Self {
            aead: udp_cipher(method),
            key: Arc::clone(&key),
            sessions: ServerSessions::new(client_session_id, method, key),
        }
    }

    /// Decode one server→client datagram.
    ///
    /// `Ok(None)` drops the datagram without ending anything: a replay, a
    /// candidate whose body failed to authenticate, a newer server session
    /// arriving before the current one went quiet (§3.2.4's rotation gate), or
    /// a header/timestamp/client-session that did not validate. The session
    /// table only moves in [`Self::finish`], and only for a fully validated
    /// datagram.
    fn open(&mut self, packet: &[u8]) -> Result<Option<(TargetAddr, Vec<u8>)>, NativeError> {
        self.open_at(packet, Instant::now())
    }

    /// [`Self::open`] with the rotation gate's clock injected: the §3.2.4
    /// 60-second boundary is testable without sleeping.
    fn open_at(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<(TargetAddr, Vec<u8>)>, NativeError> {
        match self.aead {
            SsAead::Aes128Gcm | SsAead::Aes256Gcm => self.open_aes(packet, now),
            SsAead::XChaCha20Poly1305 => self.open_chacha(packet, now),
            other => Err(NativeError::Config(format!(
                "{other:?} is not a Shadowsocks-2022 UDP cipher"
            ))),
        }
    }

    fn open_aes(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<(TargetAddr, Vec<u8>)>, NativeError> {
        // A datagram too short to hold the separate header and a tag is a
        // wire failure, exactly as the classic codec's short-datagram error is.
        if packet.len() < SEPARATE_HEADER_LEN + self.aead.tag_len() {
            return Err(s2022_error("short datagram"));
        }
        let mut header: [u8; SEPARATE_HEADER_LEN] = packet[..SEPARATE_HEADER_LEN]
            .try_into()
            .expect("the length was checked above");
        aes_ecb_decrypt(self.aead, &self.key, &mut header)?;
        let (server_id, _) = read_u64(&header).expect("the header is 16 bytes");
        let (packet_id, _) = read_u64(&header[8..]).expect("the header is 16 bytes");

        // PURE resolution: the table may not move on a datagram that has not
        // authenticated yet (spec §3.2.4).
        let known = self.sessions.check(server_id, packet_id);
        let nonce = separate_header_nonce(server_id, packet_id);
        let sealed = &packet[SEPARATE_HEADER_LEN..];
        let body = if known.is_some() {
            // A known session: its cached subkey. `check` already proved the
            // id in-window, so a failure here is a tampered body.
            let Some(subkey) = self.sessions.body_subkey(server_id) else {
                return Ok(None);
            };
            let Ok(body) = self.aead.open(subkey, &nonce, b"", sealed) else {
                return Ok(None);
            };
            body
        } else {
            if self.sessions.is_known(server_id) {
                // A known session whose id is out of window: a replay. Drop it
                // without opening anything.
                return Ok(None);
            }
            // A candidate: subkey derived on the fly, table untouched until
            // the body AND the main header validate.
            let subkey = self.sessions.candidate_subkey(server_id);
            let Ok(body) = self.aead.open(&subkey, &nonce, b"", sealed) else {
                return Ok(None);
            };
            body
        };
        Ok(self.finish(server_id, packet_id, known.is_some(), &body, now))
    }

    fn open_chacha(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<(TargetAddr, Vec<u8>)>, NativeError> {
        // A datagram too short to hold the nonce and a tag is a wire failure,
        // exactly as the classic codec's short-datagram error is.
        if packet.len() < CHACHA_NONCE_LEN + self.aead.tag_len() {
            return Err(s2022_error("short datagram"));
        }
        let (nonce, sealed) = packet.split_at(CHACHA_NONCE_LEN);
        let Ok(plain) = self.aead.open(&self.key, nonce, b"", sealed) else {
            return Ok(None);
        };
        // `ChaCha` merges the ids into the body, so they are only known after
        // the AEAD authenticates — the table is still only read here.
        let Some((server_id, rest)) = read_u64(&plain) else {
            return Err(s2022_error("truncated datagram header"));
        };
        let Some((packet_id, body)) = read_u64(rest) else {
            return Err(s2022_error("truncated datagram header"));
        };
        let known = self.sessions.check(server_id, packet_id);
        if known.is_none() && self.sessions.is_known(server_id) {
            // A known session whose id is out of window: a replay.
            return Ok(None);
        }
        Ok(self.finish(server_id, packet_id, known.is_some(), body, now))
    }

    /// Validate an authenticated body and land the packet id.
    ///
    /// Only here — after the body opened AND the type, the timestamp and the
    /// echoed client session id all validated — does the table move: a known
    /// session commits its id (always), a candidate is learned only once the
    /// current session has been quiet for [`ROTATION_QUIET`] (spec §3.2.4's
    /// rotation gate). `None` drops the datagram and touches neither.
    fn finish(
        &mut self,
        server_id: u64,
        packet_id: u64,
        known: bool,
        body: &[u8],
        now: Instant,
    ) -> Option<(TargetAddr, Vec<u8>)> {
        let timestamp_now = now_unix_secs().ok()?;
        let opened = parse_server_body(body, self.sessions.client_session_id(), timestamp_now)?;
        if known {
            self.sessions.commit(server_id, packet_id, now);
        } else {
            if !self.sessions.rotation_allowed(now) {
                // A NEWER session while the current one is still live: refused
                // (spec §3.2.4) — the live session keeps the table.
                return None;
            }
            self.sessions.learn(server_id, packet_id, now);
        }
        Some(opened)
    }
}

/// Seal one datagram for the carrier INTO `buf` — classic fresh-salt or 2022
/// session — shared by [`SsUdpTunnel::send`] and `SsUdpWriter::send`.
fn seal_packet(
    method: SsMethod,
    key: &[u8],
    target: &TargetAddr,
    s2022: Option<&mut Ss2022WriterState>,
    dest: Option<SocketAddr>,
    payload: &[u8],
    buf: &mut SendBuf,
) -> Result<(), NativeError> {
    // `None` names the session destination, never "no address": every SS
    // datagram carries one. Borrowed for the common `None` case, so a domain
    // target is not cloned per datagram.
    let dest = dest.map_or(Cow::Borrowed(target), |socket| {
        Cow::Owned(target_from_socket(socket))
    });
    // Early return, not `map_or_else`: both branches need the same `&mut
    // SendBuf`, which two closures could not share.
    if let Some(state) = s2022 {
        return state.seal(&dest, payload, buf);
    }
    seal_datagram_into(method, key, &dest, payload, buf)
}

/// Receive one SS datagram, looping over datagrams that do not decode.
///
/// A UDP relay has no error channel back to the peer, so an undecodable
/// datagram — another session's, a replay, tampered ciphertext, a malformed
/// header — is dropped and the loop keeps reading. Only a socket error
/// surfaces.
async fn recv_packet(
    socket: &UdpSocket,
    buf: &mut [u8],
    method: SsMethod,
    key: &[u8],
    mut s2022: Option<&mut Ss2022ReaderState>,
) -> io::Result<Option<Datagram>> {
    loop {
        let read = socket.recv(buf).await?;
        let decoded = s2022.as_deref_mut().map_or_else(
            || open_datagram(method, key, &buf[..read]).map(Some),
            |state| state.open(&buf[..read]),
        );
        if let Ok(Some((origin, payload))) = decoded {
            return Ok(Some((socket_addr(&origin), payload)));
        }
    }
}

/// Map a codec failure onto the datagram seam's `io::Result`.
fn carrier_error(error: NativeError) -> io::Error {
    match error {
        NativeError::Config(message) => io::Error::new(io::ErrorKind::InvalidInput, message),
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

/// Refuse an oversized datagram before it reaches the socket.
fn oversize(len: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("shadowsocks udp payload too large ({len} bytes, max {MAX_PAYLOAD})"),
    )
}

/// The SS UDP carrier: the connected socket to the SS server, the codec key,
/// the session destination, and the 2022 send/receive states.
///
/// The 2022 state is split by direction (writer: client session id + packet
/// counter + subkey; reader: server-session table + windows + body subkeys),
/// so [`Self::split`] hands each half its own state with no lock. Classic
/// rows leave both states `None` — every datagram stands alone.
pub struct SsUdpTunnel {
    socket: Arc<UdpSocket>,
    method: SsMethod,
    key: Arc<Zeroizing<Vec<u8>>>,
    /// `ctx.target`: the destination a `send(None)` carries (the chain's
    /// per-link target, not the profile's `params.target`).
    target: TargetAddr,
    s2022_writer: Option<Ss2022WriterState>,
    s2022_reader: Option<Ss2022ReaderState>,
    /// Reused read scratch — one allocation per tunnel instead of one per
    /// datagram.
    recv_buf: Vec<u8>,
    /// Reused send scratch; moves to the writer half on [`Self::split`].
    send_buf: SendBuf,
}

impl SsUdpTunnel {
    /// Send one datagram. `dest = None` means the session `target`. Both codecs
    /// take a `TargetAddr`, and the address travels INSIDE the sealed body,
    /// so a domain destination is legal on the wire.
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD {
            return Err(oversize(payload.len()));
        }
        seal_packet(
            self.method,
            &self.key,
            &self.target,
            self.s2022_writer.as_mut(),
            dest,
            payload,
            &mut self.send_buf,
        )
        .map_err(carrier_error)?;
        self.socket.send(&self.send_buf.packet).await.map(|_| ())
    }

    /// Receive one datagram; `Some(addr)` is the origin the reply header
    /// carried (`None` when that origin is a domain name). Undecodable
    /// datagrams are dropped, never fatal.
    ///
    /// Cancellation-safe: [`tokio::net::UdpSocket::recv`] keeps no partial
    /// datagram, so a dropped future loses nothing.
    pub async fn recv(&mut self) -> io::Result<Option<Datagram>> {
        recv_packet(
            &self.socket,
            &mut self.recv_buf,
            self.method,
            &self.key,
            self.s2022_reader.as_mut(),
        )
        .await
    }

    /// Split the carrier into halves usable from separate tasks.
    ///
    /// The socket is shared through `Arc` (a UDP datagram send and receive
    /// are independent syscalls, so neither half needs a lock) and each 2022
    /// state moves to its own direction. Classic rows split into two stateless
    /// halves.
    // Infallible for this carrier; the `io::Result` is the shared split
    // contract (`PacketTunnel::split`).
    pub fn split(self) -> io::Result<(SsUdpReader, SsUdpWriter)> {
        let Self {
            socket,
            method,
            key,
            target,
            s2022_writer,
            s2022_reader,
            recv_buf,
            send_buf,
        } = self;
        Ok((
            SsUdpReader {
                socket: Arc::clone(&socket),
                method,
                key: Arc::clone(&key),
                s2022_reader,
                recv_buf,
            },
            SsUdpWriter {
                socket,
                method,
                key,
                target,
                s2022_writer,
                send_buf,
            },
        ))
    }
}

/// The read half of a [`split`](SsUdpTunnel::split) SS UDP carrier: the shared
/// socket, the codec key, the 2022 server-session table and the read scratch.
pub struct SsUdpReader {
    socket: Arc<UdpSocket>,
    method: SsMethod,
    key: Arc<Zeroizing<Vec<u8>>>,
    s2022_reader: Option<Ss2022ReaderState>,
    recv_buf: Vec<u8>,
}

impl SsUdpReader {
    /// Receive one datagram — exactly [`SsUdpTunnel::recv`], via the same
    /// routine, with the same drop-what-does-not-decode contract.
    pub async fn recv(&mut self) -> io::Result<Option<Datagram>> {
        recv_packet(
            &self.socket,
            &mut self.recv_buf,
            self.method,
            &self.key,
            self.s2022_reader.as_mut(),
        )
        .await
    }
}

/// The write half of a [`split`](SsUdpTunnel::split) SS UDP carrier: the
/// shared socket, the codec key, the session destination and the 2022 client
/// session state.
pub struct SsUdpWriter {
    socket: Arc<UdpSocket>,
    method: SsMethod,
    key: Arc<Zeroizing<Vec<u8>>>,
    target: TargetAddr,
    s2022_writer: Option<Ss2022WriterState>,
    /// Reused send scratch — the halves never share it, so no lock.
    send_buf: SendBuf,
}

impl SsUdpWriter {
    /// Send one datagram — exactly [`SsUdpTunnel::send`], via the same
    /// routine, with the same `dest: None` = session-destination meaning.
    pub async fn send(&mut self, dest: Option<SocketAddr>, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD {
            return Err(oversize(payload.len()));
        }
        seal_packet(
            self.method,
            &self.key,
            &self.target,
            self.s2022_writer.as_mut(),
            dest,
            payload,
            &mut self.send_buf,
        )
        .map_err(carrier_error)?;
        self.socket.send(&self.send_buf.packet).await.map(|_| ())
    }
}

/// Dial the SS server's UDP relay and return the datagram carrier.
///
/// The whole dial is `bind` + `connect`: an SS UDP link has no security
/// layer, no transport upgrade and no base tunnel — the server's UDP relay IS
/// its own endpoint. A row whose `security` is set is therefore refused
/// ([`NativeError::Config`]): there is nowhere to put the TLS/REALITY
/// handshake, and dialing anyway would send it in the clear. The server
/// address goes through [`LinkContext::server_socket`], which honours
/// `params.resolved_ip` and bounds DNS with [`crate::error::timeouts::DIAL`].
pub async fn connect_udp(
    ctx: &LinkContext,
    method: SsMethod,
    cfg: &SsConfig,
) -> Result<SsUdpTunnel, NativeError> {
    // The UDP dial replaces dial + security + transport, so there is no layer
    // to put a TLS/REALITY handshake in. Dialing anyway would send a row that
    // asked for TLS in the clear — refuse it instead.
    if !cfg.security.is_empty() {
        return Err(NativeError::Config(
            "shadowsocks UDP cannot carry a TLS/REALITY layer (the UDP relay dials the server's \
             UDP port directly); use TCP for this profile"
                .into(),
        ));
    }
    // SIP003 has no datagram path (the plugin is a stream transformer and the
    // SS server's UDP relay is a separate endpoint), so a plugin row's UDP leg
    // cannot be carried at all.
    //
    // This refusal is RUNTIME-scoped and cannot announce itself: RFC 1928 gives
    // a SOCKS5 client no channel to report a failure after the ASSOCIATE
    // reply, and the inbound drops per-datagram failures without ending the
    // association — so the row would look perfectly healthy (its TCP probes
    // are green) while every datagram vanished. The `warn!` is the only
    // diagnosability this has, which is why it names the row and the reason
    // and why it is emitted ONCE per association: a per-datagram warn on a
    // busy association is itself a log flood.
    if let Some(plugin) = &cfg.plugin {
        tracing::warn!(
            target: "leas_native::protocol::ss::udp",
            protocol = ?method.kind(),
            server = %ctx.params.server.host,
            port = ctx.params.server.port,
            plugin = %plugin.name,
            mode = plugin.mode.as_str(),
            "dropping UDP for a shadowsocks plugin row: SIP003 has no datagram path, \
             and the SOCKS5 UDP association cannot report the failure",
        );
        return Err(NativeError::Config(format!(
            "shadowsocks plugin `{}` cannot carry UDP (SIP003 has no datagram path)",
            plugin.name
        )));
    }
    let key = Arc::new(password_key(method, &cfg.password)?);
    let server = ctx.server_socket().await?;
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .expect("a literal socket address");
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| NativeError::Dial(format!("shadowsocks udp bind: {e}")))?;
    socket
        .connect(server)
        .await
        .map_err(|e| NativeError::Dial(format!("shadowsocks udp connect: {e}")))?;
    let (s2022_writer, s2022_reader) = match method.family {
        SsFamily::Classic => (None, None),
        SsFamily::Blake3_2022 => {
            let writer = Ss2022WriterState::new(method, Arc::clone(&key));
            let reader = Ss2022ReaderState::new(method, Arc::clone(&key), writer.client_session_id);
            (Some(writer), Some(reader))
        }
    };
    Ok(SsUdpTunnel {
        socket: Arc::new(socket),
        method,
        key,
        target: ctx.target.clone(),
        s2022_writer,
        s2022_reader,
        recv_buf: vec![0u8; MAX_DATAGRAM],
        send_buf: SendBuf::default(),
    })
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use base64::Engine as _;
    use leas_proto::proto_spec::endpoint::EndpointEssentials;
    use leas_proto::proto_spec::{
        PluginSpec, ProtocolConfig, ProtocolKind, SecurityConfig, TlsConfig, TlsOpts,
    };
    use leas_proto::urlx::TinyText;

    use super::*;
    use crate::addr::encode_addr_port_last;
    use crate::context::NativeConnectParams;
    use crate::protocol::ss::resolve_method;
    use crate::protocol::vless::encryption::derive_key_bytes;

    /// Seal one datagram through the writer state with a scratch buffer.
    fn seal_with(writer: &mut Ss2022WriterState, dest: &TargetAddr, payload: &[u8]) -> Vec<u8> {
        let mut buf = SendBuf::default();
        writer.seal(dest, payload, &mut buf).unwrap();
        buf.packet
    }

    /// The client main header ahead of the address, for the hand-written
    /// parsers: `type | ts u64be | pad_len u16be`.
    const CLIENT_BODY_PREFIX: usize = 1 + 8 + 2;

    fn ss_cfg(method: &str, password: &str) -> SsConfig {
        SsConfig {
            method: method.into(),
            password: password.into(),
            security: SecurityConfig::default(),
            remarks: None,
            plugin: None,
        }
    }

    fn base64(data: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    /// A `LinkContext` whose server is `server` (via `resolved_ip`, so the
    /// dial does no DNS) and whose per-link target is `target`.
    fn ctx_for(cfg: &SsConfig, server: SocketAddr, target: TargetAddr) -> LinkContext {
        let mut params = NativeConnectParams::new(
            ProtocolConfig::Ss(cfg.clone()),
            EndpointEssentials::new(server.ip().to_string(), server.port()),
            target.clone(),
        );
        params.resolved_ip = Some(server);
        LinkContext::new(params, target)
    }

    /// A plugin row cannot carry UDP, and the refusal is the ONLY diagnosability
    /// the user gets: RFC 1928 gives a SOCKS5 client no channel to report a
    /// failure after ASSOCIATE, and the inbound drops per-datagram failures
    /// without ending the association. So the error must name the plugin, and
    /// the row's TCP path must be untouched.
    #[tokio::test]
    async fn a_plugin_row_refuses_udp_by_name() {
        let cfg = SsConfig {
            plugin: Some(PluginSpec::from_parts(
                Some("obfs-local"),
                "obfs=http;obfs-host=example.com",
            )),
            ..ss_cfg("aes-128-gcm", "pw")
        };
        let server: SocketAddr = "127.0.0.1:1".parse().expect("literal");
        let ctx = ctx_for(&cfg, server, TargetAddr::new(Host::new("example.org"), 53));
        let method = resolve_method(&cfg).expect("aead method");
        // `SsUdpTunnel` is not `Debug`, so the error is bound with `let-else`
        // rather than `expect_err`.
        let Err(err) = connect_udp(&ctx, method, &cfg).await else {
            panic!("SIP003 has no datagram path, so this must be refused");
        };
        let text = err.to_string();
        assert!(text.contains("obfs-local"), "{text} must name the plugin");
        assert!(text.contains("no datagram path"), "{text} must say why");

        // The same row's TCP leg is unaffected: it must not be gated here, or
        // the refusal would disable the feature's main benefit.
        assert!(
            crate::capability::supported(ProtocolKind::Shadowsocks, &ProtocolConfig::Ss(cfg)),
            "a plugin row's TCP path is still native-servable"
        );
    }

    /// A dependency-free `Subscriber` that counts events on one target. The
    /// crate deliberately has no `tracing-subscriber` dependency, and asserting
    /// "exactly one warn" needs a real subscriber — the previous test only
    /// called `connect_udp` twice and asserted the same error both times, which
    /// passes whether the code logs once or a hundred times.
    struct WarnCounter {
        target: &'static str,
        count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl tracing::Subscriber for WarnCounter {
        fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
            meta.target() == self.target
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Row 22's unasserted fact: the warn fires **exactly once per association**.
    ///
    /// The seam matters and is easy to get wrong: `connect_udp` IS the
    /// association-level dial (`inbound/mod.rs` calls it once per SOCKS5 UDP
    /// ASSOCIATE, before the datagram loop), so "once per association" means
    /// once per CALL to this function — not once per datagram, which never
    /// reaches here at all. A test that called it N times and expected one warn
    /// would be asserting that N associations produce one warning, which is the
    /// opposite of the contract.
    #[test]
    fn a_plugin_association_warns_exactly_once() {
        let cfg = SsConfig {
            plugin: Some(PluginSpec::from_parts(
                Some("v2ray-plugin"),
                "host=cdn.example",
            )),
            ..ss_cfg("aes-128-gcm", "pw")
        };
        let server: SocketAddr = "127.0.0.1:1".parse().expect("literal");
        let ctx = ctx_for(&cfg, server, TargetAddr::new(Host::new("example.org"), 53));
        let method = resolve_method(&cfg).expect("aead method");
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let subscriber = WarnCounter {
            target: "leas_native::protocol::ss::udp",
            count: std::sync::Arc::clone(&count),
        };

        let mut refusal = String::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        tracing::subscriber::with_default(subscriber, || {
            rt.block_on(async {
                let Err(err) = connect_udp(&ctx, method, &cfg).await else {
                    panic!("a plugin row's UDP leg must be refused");
                };
                refusal = err.to_string();
            });
        });

        assert!(
            refusal.contains("v2ray-plugin"),
            "the refusal names the row's own plugin: {refusal}"
        );
        assert!(
            refusal.contains("no datagram path"),
            "and says why: {refusal}"
        );
        assert_eq!(
            count.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one association dial warns exactly once, even though the refusal is \
             what the association is built from"
        );
    }

    /// A refusal that fires on EVERY datagram would flood the log; the guard
    /// runs once per association dial, so the warn is emitted once.
    #[tokio::test]
    async fn the_plugin_udp_refusal_is_a_dial_time_decision() {
        let cfg = SsConfig {
            plugin: Some(PluginSpec::from_parts(
                Some("v2ray-plugin"),
                "host=cdn.example",
            )),
            ..ss_cfg("aes-256-gcm", "pw")
        };
        let server: SocketAddr = "127.0.0.1:1".parse().expect("literal");
        let ctx = ctx_for(&cfg, server, TargetAddr::new(Host::new("example.org"), 53));
        let method = resolve_method(&cfg).expect("aead method");
        // The refusal happens before any socket is bound, so it costs no I/O
        // and repeats identically for a second datagram on the same link.
        for _ in 0..2 {
            let Err(err) = connect_udp(&ctx, method, &cfg).await else {
                panic!("a plugin row's UDP leg must be refused");
            };
            assert!(err.to_string().contains("v2ray-plugin"));
        }
    }

    /// The independent 2022 subkey the tests pin against: the hand-rolled
    /// BLAKE3 in `protocol/vless/encryption`, not the `blake3` crate the
    /// production helper delegates to.
    fn reference_subkey(method: SsMethod, psk: &[u8], session_id: u64) -> Vec<u8> {
        let material = [psk, &session_id.to_be_bytes()].concat();
        derive_key_bytes(b"shadowsocks 2022 session subkey", &material)[..method.key_len()].to_vec()
    }

    /// A hand-written server→client AES datagram (spec §3.2.2/§3.2.3): the
    /// ECB id block, then the sealed body
    /// `type=1 | ts | client_session_id | pad_len | padding | addr | port |
    /// payload`.
    fn aes_server_datagram(
        method: SsMethod,
        psk: &[u8],
        server_id: u64,
        packet_id: u64,
        client_id: u64,
        origin: &TargetAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        aes_server_datagram_at(
            method,
            psk,
            server_id,
            packet_id,
            client_id,
            now_unix_secs().unwrap().to_be_bytes(),
            origin,
            payload,
        )
    }

    /// [`aes_server_datagram`] with the timestamp SEALED INTO the plaintext —
    /// the only way to exercise the body's timestamp validation (patching
    /// ciphertext would fail the tag first, which is a different drop).
    fn aes_server_datagram_at(
        method: SsMethod,
        psk: &[u8],
        server_id: u64,
        packet_id: u64,
        client_id: u64,
        timestamp: [u8; 8],
        origin: &TargetAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let header = separate_header_aes(method.aead, psk, server_id, packet_id).unwrap();
        let mut body = vec![HEADER_TYPE_SERVER_PACKET];
        body.extend_from_slice(&timestamp);
        body.extend_from_slice(&client_id.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&encode_addr_port_last(origin).unwrap());
        body.extend_from_slice(payload);
        let mut out = header.to_vec();
        method
            .aead
            .seal_into(
                &udp_session_subkey(method, psk, server_id),
                &separate_header_nonce(server_id, packet_id),
                b"",
                &body,
                &mut out,
            )
            .unwrap();
        out
    }

    /// A hand-written server→client `ChaCha` datagram: the random nonce, then
    /// the sealed merged header
    /// `server_session_id ‖ server_packet_id ‖ type=1 ‖ ts ‖ client_session_id
    /// ‖ pad_len ‖ padding ‖ addr ‖ port ‖ payload` (spec §4.1). The cipher is
    /// XChaCha20-Poly1305 by construction — the independent side of the
    /// reader's `udp_cipher` mapping.
    fn chacha_server_datagram(
        psk: &[u8],
        server_id: u64,
        packet_id: u64,
        client_id: u64,
        origin: &TargetAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let cipher = SsAead::XChaCha20Poly1305;
        let nonce = [0x5Au8; CHACHA_NONCE_LEN];
        let mut plain = Vec::new();
        plain.extend_from_slice(&server_id.to_be_bytes());
        plain.extend_from_slice(&packet_id.to_be_bytes());
        plain.push(HEADER_TYPE_SERVER_PACKET);
        plain.extend_from_slice(&now_unix_secs().unwrap().to_be_bytes());
        plain.extend_from_slice(&client_id.to_be_bytes());
        plain.extend_from_slice(&0u16.to_be_bytes());
        plain.extend_from_slice(&encode_addr_port_last(origin).unwrap());
        plain.extend_from_slice(payload);
        let mut out = nonce.to_vec();
        cipher
            .seal_into(psk, &nonce, b"", &plain, &mut out)
            .unwrap();
        out
    }

    /// The hand-written server-side parser of a client AES datagram: decrypt
    /// the id block, derive the subkey independently, open the body and read
    /// the client main header field by field. The client writer is checked
    /// against THIS, not against its own reader.
    fn open_client_aes_datagram(
        method: SsMethod,
        psk: &[u8],
        wire: &[u8],
    ) -> Option<(u64, u64, TargetAddr, Vec<u8>)> {
        let mut header =
            <[u8; SEPARATE_HEADER_LEN]>::try_from(wire.get(..SEPARATE_HEADER_LEN)?).ok()?;
        aes_ecb_decrypt(method.aead, psk, &mut header).ok()?;
        let (session_id, _) = read_u64(&header)?;
        let (packet_id, _) = read_u64(&header[8..])?;
        let subkey = reference_subkey(method, psk, session_id);
        let body = method
            .aead
            .open(
                &subkey,
                &separate_header_nonce(session_id, packet_id),
                b"",
                &wire[SEPARATE_HEADER_LEN..],
            )
            .ok()?;
        let (&kind, rest) = body.split_first()?;
        if kind != HEADER_TYPE_CLIENT_PACKET {
            return None;
        }
        let (timestamp, rest) = read_u64(rest)?;
        if timestamp.abs_diff(now_unix_secs().ok()?) > TIMESTAMP_TOLERANCE_SECS {
            return None;
        }
        let (pad_len, rest) = read_u16(rest)?;
        let (dest, payload) = decode_addr_port_last(rest.get(usize::from(pad_len)..)?)?;
        Some((session_id, packet_id, dest, payload.to_vec()))
    }

    /// A loopback "server" that decodes one classic datagram with the codec
    /// primitives (not the tunnel) and echoes a reply sealed the same way.
    async fn classic_echo(server: UdpSocket, key: Zeroizing<Vec<u8>>, method: SsMethod) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (read, from) = server.recv_from(&mut buf).await.unwrap();
        let (dest, payload) = open_datagram(method, &key, &buf[..read]).unwrap();
        assert_eq!(payload, b"query");
        let reply = seal_datagram(method, &key, &dest, b"answer").unwrap();
        server.send_to(&reply, from).await.unwrap();
    }

    #[test]
    fn classic_udp_packet_is_salt_then_sealed_address_payload() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let key = Zeroizing::new(vec![0x11u8; 16]);
        let dest = TargetAddr::new(Host::Ip(IpAddr::from([1, 2, 3, 4])), 53);
        let packet = seal_datagram(method, &key, &dest, b"query").unwrap();
        assert_eq!(packet.len(), 16 + 7 + 5 + 16);
        let subkey = stream_subkey(method, &key, &packet[..16]);
        let body = method
            .aead
            .open(&subkey, &[0u8; 12], b"", &packet[16..])
            .unwrap();
        assert_eq!(&body[..7], &encode_addr_port_last(&dest).unwrap()[..]);
        assert_eq!(&body[7..], b"query");
        // And the decoder reads back exactly that address + payload.
        let (decoded, payload) = open_datagram(method, &key, &packet).unwrap();
        assert_eq!(decoded, dest);
        assert_eq!(payload, b"query");
    }

    /// Two datagrams to the same destination must use different salts (so a
    /// server-side replay cache never rejects the second one).
    #[test]
    fn classic_udp_salts_are_fresh_per_datagram() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let key = Zeroizing::new(vec![0x33u8; 16]);
        let dest = TargetAddr::new(Host::Ip(IpAddr::from([10, 0, 0, 7])), 5353);
        let a = seal_datagram(method, &key, &dest, b"ping").unwrap();
        let b = seal_datagram(method, &key, &dest, b"ping").unwrap();
        assert_ne!(&a[..16], &b[..16]);
    }

    /// The address always travels inside the sealed body, so the same
    /// destination can be reached through a domain target (`send(None)`) and
    /// a per-packet IP (`send(Some)`) alike; the decoder reads both back.
    #[test]
    fn classic_udp_round_trips_ipv6_and_domain_addresses() {
        let method = SsMethod::from_method("chacha20-ietf-poly1305").unwrap();
        let key = Zeroizing::new(vec![0x44u8; 32]);
        for dest in [
            TargetAddr::new(
                Host::Ip(IpAddr::from([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ])),
                443,
            ),
            TargetAddr::new(Host::Domain("example.com".into()), 853),
        ] {
            let packet = seal_datagram(method, &key, &dest, b"payload").unwrap();
            let (decoded, payload) = open_datagram(method, &key, &packet).unwrap();
            assert_eq!(decoded, dest);
            assert_eq!(payload, b"payload");
        }
    }

    #[tokio::test]
    async fn ss_udp_tunnel_round_trips_against_a_loopback_echo() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let cfg = ss_cfg("aes-128-gcm", "hunter2");
        let target = TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 53);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let ctx = ctx_for(&cfg, server_addr, target);
        let mut tunnel = connect_udp(&ctx, method, &cfg).await.unwrap();
        // The echo side uses the codec primitives, not the tunnel, so both
        // the send and the receive path cross a real UDP datagram.
        let key = password_key(method, &cfg.password).unwrap();

        let echo = tokio::spawn(classic_echo(server, key, method));
        tunnel.send(None, b"query").await.unwrap();
        let (origin, payload) = tunnel.recv().await.unwrap().expect("one reply");
        echo.await.unwrap();

        assert_eq!(payload, b"answer");
        assert_eq!(origin, Some(SocketAddr::from(([127, 0, 0, 1], 53))));
    }

    /// The send cap bounds the SEALED datagram, not just the plaintext: the
    /// largest allowed payload to a worst-case 255-byte domain destination
    /// still fits the UDP ceiling and reaches the peer, while one byte more is
    /// a clean refusal — never the kernel's `EMSGSIZE`.
    #[tokio::test]
    async fn the_send_cap_bounds_the_sealed_datagram() {
        // 2022 `ChaCha` carries the largest per-packet overhead: a 24-byte
        // nonce, the 16-byte merged id pair, the 11-byte client header, the
        // 259-byte encoded 255-byte domain address and the 16-byte tag.
        let method = SsMethod::from_method("2022-blake3-chacha20-poly1305").unwrap();
        let psk = [0x66u8; 32];
        let cfg = ss_cfg("2022-blake3-chacha20-poly1305", &base64(&psk));
        let target = TargetAddr::new(Host::Domain("a".repeat(255)), 1);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let ctx = ctx_for(&cfg, server_addr, target);
        let mut tunnel = connect_udp(&ctx, method, &cfg).await.unwrap();

        let echo = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            let (read, _from) = server.recv_from(&mut buf).await.unwrap();
            read
        });
        tunnel.send(None, &vec![0u8; MAX_PAYLOAD]).await.unwrap();
        let sealed = echo.await.unwrap();
        assert_eq!(sealed, MAX_PAYLOAD + 326);
        assert!(
            sealed <= 65_507,
            "the sealed datagram must fit an IPv4 UDP payload"
        );

        let err = tunnel
            .send(None, &vec![0u8; MAX_PAYLOAD + 1])
            .await
            .expect_err("one byte over the cap");
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidInput,
            "a clean refusal, not an OS EMSGSIZE"
        );
    }

    /// The steady-state send path reuses its scratch: a second datagram of the
    /// same size neither reallocates the wire packet nor the body it is sealed
    /// from (hysteria2's `WriteState` precedent).
    #[tokio::test]
    async fn the_send_path_reuses_its_scratch() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let cfg = ss_cfg("aes-128-gcm", "reuse");
        let target = TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 9);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ctx = ctx_for(&cfg, server.local_addr().unwrap(), target);
        let mut tunnel = connect_udp(&ctx, method, &cfg).await.unwrap();

        tunnel.send(None, b"one").await.unwrap();
        let packet = (
            tunnel.send_buf.packet.as_ptr(),
            tunnel.send_buf.packet.capacity(),
        );
        let body = tunnel.send_buf.body.as_ptr();
        tunnel.send(None, b"two").await.unwrap();
        assert_eq!(
            (
                tunnel.send_buf.packet.as_ptr(),
                tunnel.send_buf.packet.capacity()
            ),
            packet,
            "the wire packet is reused, not reallocated"
        );
        assert_eq!(
            tunnel.send_buf.body.as_ptr(),
            body,
            "the body scratch is reused, not reallocated"
        );
    }

    /// An SS UDP row that asked for TLS/REALITY is refused before any dial:
    /// the dial is a plain UDP socket to the relay, so dialing would send the
    /// row in the clear. The server host is unresolvable on purpose — a
    /// `Config` error (never a dial/DNS error) is what proves no socket was
    /// created.
    #[tokio::test]
    async fn connect_udp_refuses_a_tls_security_layer_before_dialing() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let mut cfg = ss_cfg("aes-128-gcm", "hunter2");
        cfg.security = SecurityConfig {
            tls: Some(TlsConfig::Tls(TlsOpts {
                sni: Some(TinyText::from("example.com")),
                ..TlsOpts::default()
            })),
            enc: None,
        };
        let target = TargetAddr::new(Host::Ip(IpAddr::from([1, 2, 3, 4])), 53);
        let params = NativeConnectParams::new(
            ProtocolConfig::Ss(cfg.clone()),
            EndpointEssentials::new("ss.invalid", 8388),
            target.clone(),
        );
        let ctx = LinkContext::new(params, target);

        let Err(err) = connect_udp(&ctx, method, &cfg).await else {
            panic!("a TLS-carrying SS UDP row must be refused");
        };
        assert!(
            matches!(&err, NativeError::Config(msg) if msg.contains("TLS/REALITY")),
            "got {err:?}"
        );
    }

    /// The split halves share the socket with no lock and carry both
    /// directions: the writer seals, the reader opens, each with its own
    /// state. Also proves the carrier is `Send + 'static` for the chain.
    #[tokio::test]
    async fn split_halves_carry_both_directions() {
        fn assert_send_static<T: Send + 'static>(_: &T) {}

        let method = SsMethod::from_method("aes-256-gcm").unwrap();
        let cfg = ss_cfg("aes-256-gcm", "split-secret");
        let target = TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 7);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let ctx = ctx_for(&cfg, server_addr, target);
        let tunnel = connect_udp(&ctx, method, &cfg).await.unwrap();
        assert_send_static(&tunnel);
        let (mut reader, mut writer) = tunnel.split().unwrap();
        let key = password_key(method, &cfg.password).unwrap();

        let echo = tokio::spawn(classic_echo(server, key, method));
        writer.send(None, b"query").await.unwrap();
        let (origin, payload) = reader.recv().await.unwrap().expect("one reply");
        echo.await.unwrap();

        assert_eq!(payload, b"answer");
        assert_eq!(origin, Some(SocketAddr::from(([127, 0, 0, 1], 7))));
    }

    /// A datagram that does not decode is dropped and the loop keeps reading:
    /// a short datagram and a broken tag ahead of the real reply must not kill
    /// the tunnel (UDP has no error channel back to the peer).
    #[tokio::test]
    async fn undecodable_datagrams_are_dropped_and_the_next_one_is_delivered() {
        let method = SsMethod::from_method("aes-128-gcm").unwrap();
        let cfg = ss_cfg("aes-128-gcm", "garbage-proof");
        let target = TargetAddr::new(Host::Ip(IpAddr::from([127, 0, 0, 1])), 9);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let ctx = ctx_for(&cfg, server_addr, target);
        let mut tunnel = connect_udp(&ctx, method, &cfg).await.unwrap();
        let key = password_key(method, &cfg.password).unwrap();

        let echo = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            let (read, from) = server.recv_from(&mut buf).await.unwrap();
            let (dest, _) = open_datagram(method, &key, &buf[..read]).unwrap();
            server.send_to(b"nope", from).await.unwrap();
            let mut broken = seal_datagram(method, &key, &dest, b"broken").unwrap();
            let last = broken.len() - 1;
            broken[last] ^= 0xFF;
            server.send_to(&broken, from).await.unwrap();
            let reply = seal_datagram(method, &key, &dest, b"answer").unwrap();
            server.send_to(&reply, from).await.unwrap();
        });

        tunnel.send(None, b"query").await.unwrap();
        let (_, payload) = tunnel.recv().await.unwrap().expect("the reply");
        echo.await.unwrap();
        assert_eq!(payload, b"answer");
    }

    #[test]
    fn separate_header_is_aes_ecb_of_ids_with_the_psk() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x03u8; 32];
        let ids = 0x0102_0304_0506_0708u64;
        let header = separate_header_aes(method.aead, &psk, ids, 0x11).unwrap();
        // AES-ECB is a permutation, not the identity.
        assert_ne!(&header[..8], &ids.to_be_bytes());
        let mut plain = header;
        aes_ecb_decrypt(method.aead, &psk, &mut plain).unwrap();
        assert_eq!(&plain[..8], &ids.to_be_bytes());
        assert_eq!(&plain[8..], &0x11u64.to_be_bytes());
    }

    /// The body nonce is the PLAINTEXT header's `[4..16]`, never the wire
    /// block: the two differ, and the sender seals with the former.
    #[test]
    fn separate_header_nonce_is_the_plaintext_id_slice() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x07u8; 32];
        let (session_id, packet_id) = (0x0102_0304_0506_0708u64, 0x11u64);
        let expected = {
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&[0x05, 0x06, 0x07, 0x08]);
            nonce[4..].copy_from_slice(&packet_id.to_be_bytes());
            nonce
        };
        assert_eq!(separate_header_nonce(session_id, packet_id), expected);
        let wire = separate_header_aes(method.aead, &psk, session_id, packet_id).unwrap();
        assert_ne!(
            expected,
            wire[4..16],
            "the wire block is the ECB ciphertext, not the nonce"
        );
    }

    #[test]
    fn udp_session_subkey_uses_the_session_id_and_the_method_key_length() {
        let method = SsMethod::from_method("2022-blake3-aes-128-gcm").unwrap();
        let psk = [0x04u8; 16];
        let k1 = udp_session_subkey(method, &psk, 1);
        let k2 = udp_session_subkey(method, &psk, 2);
        // The 128-bit method's body AEAD takes 16 bytes, not the XOF root's 32.
        assert_eq!(k1.len(), 16);
        assert_ne!(&*k1, &*k2);
        assert_eq!(&*k1, &reference_subkey(method, &psk, 1)[..]);
    }

    /// The 1024-bit window slides whole words: bits must carry across a 64-id
    /// boundary — a partial-word slide, a slide that carries from a SECOND
    /// source word, and an exact-word slide — and an id that falls off the far
    /// end must be rejected.
    #[test]
    fn sliding_window_slides_across_word_boundaries() {
        let mut w = SlidingWindow::new();
        assert!(w.accept(63));
        assert!(w.accept(100)); // slide(37): no whole word, the old bit moves 37 places
        assert!(w.accept(80)); // unseen, 20 behind the top
        assert!(!w.accept(80), "duplicate");
        assert!(
            !w.accept(63),
            "the 63 bit moved 37 places and is still tracked"
        );
        assert!(w.accept(4000)); // a 3900-id jump drops every word
        assert!(!w.accept(4000), "duplicate at the top");
        assert!(
            !w.accept(2900),
            "1100 behind the top: outside the 1024-id window"
        );
        assert!(w.accept(3900), "100 behind the top: inside");

        // A partial-word slide that also carries from a second source word:
        // shift 100 = one whole word + 36 bits, with a bit 36 places from the
        // old top so the `old[i - words - 1] >> (64 - bits)` term is non-zero.
        let mut w = SlidingWindow::new();
        assert!(w.accept(27));
        assert!(w.accept(63)); // 36 places behind the new top
        assert!(w.accept(163)); // slide(100): words 1, bits 36
        assert!(!w.accept(27), "carried two words out: 136 behind the top");
        assert!(!w.accept(63), "carried one word + 36 bits: 100 behind");
        assert!(w.accept(100), "unseen, 63 behind the top");

        // An exact word slide (`shift % 64 == 0`) takes the other branch.
        let mut w = SlidingWindow::new();
        assert!(w.accept(0));
        assert!(w.accept(64));
        assert!(!w.accept(0), "the shifted word carried over intact");
        assert!(!w.accept(64));
    }

    #[test]
    fn sliding_window_rejects_duplicates_and_old_packets() {
        let mut w = SlidingWindow::new();
        assert!(w.accept(0));
        assert!(!w.accept(0)); // duplicate
        assert!(w.accept(1));
        assert!(w.accept(63));
        assert!(w.accept(64));
        assert!(w.accept(65));
        assert!(!w.accept(64)); // duplicate inside the window
        assert!(w.accept(2000)); // jump forward
        // The window is 1024 ids wide: an unseen id 1000 behind the top is
        // still taken (and is then a duplicate), while 1998 behind has fallen
        // out — a 64-id window would have dropped both.
        assert!(w.accept(1000));
        assert!(!w.accept(1000));
        assert!(!w.accept(2)); // fell out of the 1024-packet window
        assert!(!w.accept(2000)); // the top is still a duplicate
    }

    /// The window is PER relay session: after a server restart the new
    /// session's ids restart at 0 and must be accepted (a global window would
    /// reject every reply — spec §3.2.4's old/current association exists for
    /// this). Only a fully validated datagram may move the table, so a session
    /// is `learn`ed into existence, never `check`ed into it, and §3.2.4's
    /// rotation gate makes the client wait out the current session's 60 s of
    /// silence before a different one replaces it.
    #[test]
    fn each_server_session_has_its_own_window_and_one_old_slot_is_kept() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let key = Arc::new(Zeroizing::new(vec![0x09u8; 32]));
        let mut s = ServerSessions::new(7, method, key);
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        // An unknown session is a candidate, not a check hit.
        assert_eq!(s.check(100, 0), None);
        assert!(!s.is_known(100), "check never learns a session");
        s.learn(100, 0, at(0));
        assert_eq!(s.check(100, 0), None, "the committed id is a duplicate");
        assert_eq!(s.check(100, 1), Some(7));
        s.commit(100, 1, at(0));
        // A newer session arrives while 100 is fresh: refused.
        assert!(!s.rotation_allowed(at(59)));
        assert!(s.rotation_allowed(at(60)));
        // Once it is quiet, the newer session rotates in: it becomes current,
        // 100 slides back to previous.
        assert_eq!(s.check(200, 0), None);
        s.learn(200, 0, at(61));
        assert_eq!(s.check(200, 0), None, "duplicate on the new session");
        assert_eq!(s.check(100, 2), Some(7), "one old association stays valid");
        s.commit(100, 2, at(61));
        // A third session evicts the oldest (100) after another quiet period.
        s.learn(300, 0, at(122));
        assert!(!s.is_known(100), "only one old association is retained");
        assert_eq!(s.check(100, 3), None, "evicted: no window hit");
        assert_eq!(s.check(200, 3), Some(7));
    }

    /// The check/commit split holds for the TABLE, not just the window: a
    /// spoofed high-id datagram is checked, its body never opens, and the
    /// caller never learns it — so the real reply that follows is still a
    /// fresh candidate (spec §3.2.4 forbids moving session state before
    /// validation).
    #[test]
    fn check_without_commit_does_not_advance_the_window() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let key = Arc::new(Zeroizing::new(vec![0x0Au8; 32]));
        let mut s = ServerSessions::new(7, method, key);
        let now = Instant::now();
        assert_eq!(s.check(100, 5000), None); // spoofed: no hit…
        assert!(!s.is_known(100), "…and no slot either");
        assert_eq!(s.body_subkey(100), None, "no slot, no cached subkey");
        // The real first datagram of that session is still a candidate.
        assert_eq!(s.check(100, 0), None);
        s.learn(100, 0, now);
        assert_eq!(s.check(100, 0), None, "committed id is a duplicate");
        assert_eq!(s.check(100, 1), Some(7));
    }

    /// The writer's AES datagram, parsed by the hand-written spec decoder:
    /// the ECB id block, the plaintext-header nonce, the per-session subkey
    /// and the client main header all have to line up.
    #[test]
    fn aes_2022_writer_datagram_matches_the_spec_layout() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x5Bu8; 32];
        let mut writer = Ss2022WriterState::new(method, Arc::new(Zeroizing::new(psk.to_vec())));
        let dest = TargetAddr::new(Host::Ip(IpAddr::from([203, 0, 113, 5])), 443);
        let wire = seal_with(&mut writer, &dest, b"ping");
        let (session_id, packet_id, decoded, payload) =
            open_client_aes_datagram(method, &psk, &wire).unwrap();
        assert_eq!(session_id, writer.client_session_id);
        assert_eq!(packet_id, 0);
        assert_eq!(decoded, dest);
        assert_eq!(payload, b"ping");

        // The packet counter advances per datagram, and each gets a new ECB
        // block for the new id.
        let second = seal_with(&mut writer, &dest, b"ping");
        let (_, packet_id, _, _) = open_client_aes_datagram(method, &psk, &second).unwrap();
        assert_eq!(packet_id, 1);
        assert_ne!(&wire[..SEPARATE_HEADER_LEN], &second[..SEPARATE_HEADER_LEN]);
    }

    #[test]
    fn aes_2022_reader_opens_a_hand_built_server_datagram() {
        let method = SsMethod::from_method("2022-blake3-aes-128-gcm").unwrap();
        let psk = [0x0Cu8; 16];
        let origin = TargetAddr::new(Host::Ip(IpAddr::from([198, 51, 100, 9])), 5353);
        let mut reader =
            Ss2022ReaderState::new(method, Arc::new(Zeroizing::new(psk.to_vec())), 0xABCD_1234);
        let wire = aes_server_datagram(
            method,
            &psk,
            0x0102_0304_0506_0708,
            0,
            0xABCD_1234,
            &origin,
            b"reply",
        );

        let (decoded, payload) = reader.open(&wire).unwrap().expect("one datagram");
        assert_eq!(decoded, origin);
        assert_eq!(payload, b"reply");
        // A replay of the same datagram is a duplicate packet id.
        assert!(reader.open(&wire).unwrap().is_none());
    }

    /// Spec §3.2.4's rotation gate and the no-blackhole rule, both through the
    /// reader: while the live session is fresh, a NEWER session's authentic
    /// datagram is refused (even with a valid timestamp — a replayed capture
    /// must not rotate a live session away); it IS learned once the current
    /// slot has been quiet for 60 s; a validated datagram for a session the
    /// table already tracks is never gated; and a session is learned from any
    /// packet id, so a lost first reply cannot blackhole the return path.
    #[test]
    fn a_replay_cannot_displace_the_live_session_and_any_id_can_learn() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x0Du8; 32];
        let origin = TargetAddr::new(Host::Ip(IpAddr::from([192, 0, 2, 44])), 53);
        let client_id = 0x1111_2222_3333_4444;
        let mut reader =
            Ss2022ReaderState::new(method, Arc::new(Zeroizing::new(psk.to_vec())), client_id);
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);

        // The live session 0xAA, established and delivering.
        let live = aes_server_datagram(method, &psk, 0xAA, 0, client_id, &origin, b"one");
        assert_eq!(reader.open_at(&live, at(0)).unwrap().unwrap().1, b"one");
        let live2 = aes_server_datagram(method, &psk, 0xAA, 1, client_id, &origin, b"two");
        assert_eq!(reader.open_at(&live2, at(1)).unwrap().unwrap().1, b"two");

        // 0xBB's authentic, freshly-timestamped datagram arrives while 0xAA is
        // live: refused, and it does not even enter the table.
        let newer = aes_server_datagram(method, &psk, 0xBB, 0, client_id, &origin, b"three");
        assert!(
            reader.open_at(&newer, at(59)).unwrap().is_none(),
            "the current session is still fresh"
        );
        assert!(!reader.sessions.is_known(0xBB));
        // …and the live session keeps delivering, gate or no gate.
        let live3 = aes_server_datagram(method, &psk, 0xAA, 2, client_id, &origin, b"four");
        assert_eq!(reader.open_at(&live3, at(59)).unwrap().unwrap().1, b"four");

        // Once the current slot has been quiet >= 60 s the same datagram is
        // learned: it becomes current and 0xAA slides back to previous.
        assert_eq!(
            reader.open_at(&newer, at(119)).unwrap().unwrap().1,
            b"three"
        );
        assert!(reader.sessions.is_known(0xBB));
        assert_eq!(reader.sessions.check(0xAA, 3), Some(client_id));
        // A datagram for a session we already track is committed immediately —
        // the gate only ever guards learning a DIFFERENT session.
        let bb2 = aes_server_datagram(method, &psk, 0xBB, 1, client_id, &origin, b"five");
        assert_eq!(reader.open_at(&bb2, at(119)).unwrap().unwrap().1, b"five");
        let aa3 = aes_server_datagram(method, &psk, 0xAA, 3, client_id, &origin, b"six");
        assert_eq!(reader.open_at(&aa3, at(119)).unwrap().unwrap().1, b"six");

        // A new session is learned from ANY validated packet id (0xDD's first
        // replies were lost) once the current slot is quiet again.
        let late = aes_server_datagram(method, &psk, 0xDD, 9, client_id, &origin, b"seven");
        assert_eq!(reader.open_at(&late, at(180)).unwrap().unwrap().1, b"seven");
        assert!(reader.sessions.is_known(0xDD));
        // An evicted session coming back is re-learned the same way, so the
        // return path can never be permanently blackholed.
        let revived = aes_server_datagram(method, &psk, 0xAA, 7, client_id, &origin, b"eight");
        assert_eq!(
            reader.open_at(&revived, at(240)).unwrap().unwrap().1,
            b"eight"
        );
    }

    /// A tampered body must not advance the window: the spoofed high id is
    /// checked but never committed, so the honest reply (id 0) still opens.
    #[test]
    fn tampered_high_id_does_not_advance_the_window() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x0Eu8; 32];
        let origin = TargetAddr::new(Host::Ip(IpAddr::from([192, 0, 2, 7])), 53);
        let client_id = 0x5555_6666_7777_8888;
        let mut reader =
            Ss2022ReaderState::new(method, Arc::new(Zeroizing::new(psk.to_vec())), client_id);

        let mut spoofed = aes_server_datagram(method, &psk, 0x01, 5000, client_id, &origin, b"x");
        let last = spoofed.len() - 1;
        spoofed[last] ^= 0x01;
        assert!(
            reader.open(&spoofed).unwrap().is_none(),
            "the body must not open"
        );
        assert!(
            !reader.sessions.is_known(0x01),
            "an unauthenticated datagram must not even create the slot"
        );

        let honest = aes_server_datagram(method, &psk, 0x01, 0, client_id, &origin, b"reply");
        assert_eq!(reader.open(&honest).unwrap().unwrap().1, b"reply");
    }

    /// Every semantic header failure drops the datagram without committing:
    /// a genuinely stale timestamp (sealed INTO the plaintext, so it reaches
    /// the validation branch rather than failing the tag first) and a body
    /// echoed for another client session both leave the table untouched for
    /// the honest datagram that follows.
    #[test]
    fn stale_timestamp_and_foreign_client_session_are_dropped() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x0Fu8; 32];
        let origin = TargetAddr::new(Host::Ip(IpAddr::from([192, 0, 2, 8])), 53);
        let client_id = 0x9999_AAAA_BBBB_CCCC;
        let mut reader =
            Ss2022ReaderState::new(method, Arc::new(Zeroizing::new(psk.to_vec())), client_id);

        let stale_at = (now_unix_secs().unwrap() - TIMESTAMP_TOLERANCE_SECS - 1).to_be_bytes();
        let stale = aes_server_datagram_at(
            method, &psk, 0x02, 0, client_id, stale_at, &origin, b"stale",
        );
        assert!(reader.open(&stale).unwrap().is_none(), "stale timestamp");
        assert!(
            !reader.sessions.is_known(0x02),
            "a stale body learns nothing"
        );

        let foreign = aes_server_datagram(method, &psk, 0x02, 0, client_id ^ 0xFFFF, &origin, b"x");
        assert!(
            reader.open(&foreign).unwrap().is_none(),
            "foreign client session"
        );
        assert!(
            !reader.sessions.is_known(0x02),
            "a foreign client session learns nothing"
        );

        let honest = aes_server_datagram(method, &psk, 0x02, 0, client_id, &origin, b"reply");
        assert_eq!(reader.open(&honest).unwrap().unwrap().1, b"reply");
    }

    /// The `pad_len` inside an authenticated server body is skipped before the
    /// address, and an empty client payload (the only case this client pads)
    /// round-trips through the pad path both ways.
    #[test]
    fn padding_is_skipped_before_the_address_in_both_directions() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x10u8; 32];
        let origin = TargetAddr::new(Host::Ip(IpAddr::from([203, 0, 113, 77])), 53);
        let client_id = 0x0F0F_0F0F_0F0F_0F0F;
        let mut reader =
            Ss2022ReaderState::new(method, Arc::new(Zeroizing::new(psk.to_vec())), client_id);

        // Hand-built server datagram with five bytes of padding.
        let (server_id, packet_id) = (0x0A0Bu64, 0u64);
        let mut body = vec![HEADER_TYPE_SERVER_PACKET];
        body.extend_from_slice(&now_unix_secs().unwrap().to_be_bytes());
        body.extend_from_slice(&client_id.to_be_bytes());
        body.extend_from_slice(&5u16.to_be_bytes());
        body.extend_from_slice(&[0xEEu8; 5]);
        body.extend_from_slice(&encode_addr_port_last(&origin).unwrap());
        body.extend_from_slice(b"reply");
        let mut wire = separate_header_aes(method.aead, &psk, server_id, packet_id)
            .unwrap()
            .to_vec();
        method
            .aead
            .seal_into(
                &udp_session_subkey(method, &psk, server_id),
                &separate_header_nonce(server_id, packet_id),
                b"",
                &body,
                &mut wire,
            )
            .unwrap();
        let (decoded, payload) = reader.open(&wire).unwrap().expect("one datagram");
        assert_eq!(decoded, origin);
        assert_eq!(payload, b"reply");

        // A padded client datagram: an empty payload makes `client_body` add
        // 0..=900 bytes, and the hand-written parser has to skip them.
        let mut writer = Ss2022WriterState::new(method, Arc::new(Zeroizing::new(psk.to_vec())));
        let dest = TargetAddr::new(Host::Domain("empty.example".into()), 443);
        let wire = seal_with(&mut writer, &dest, b"");
        let (_, packet_id, decoded, payload) =
            open_client_aes_datagram(method, &psk, &wire).unwrap();
        assert_eq!(packet_id, 0);
        assert_eq!(decoded, dest);
        assert!(payload.is_empty());
    }

    #[test]
    fn chacha_2022_writer_merges_the_ids_into_the_sealed_body() {
        let method = SsMethod::from_method("2022-blake3-chacha20-poly1305").unwrap();
        let psk = [0x61u8; 32];
        let mut writer = Ss2022WriterState::new(method, Arc::new(Zeroizing::new(psk.to_vec())));
        let dest = TargetAddr::new(Host::Domain("example.com".into()), 443);
        let wire = seal_with(&mut writer, &dest, b"ping");
        let addr = encode_addr_port_last(&dest).unwrap();
        // 24B nonce + ids(16) + type(1) + ts(8) + pad_len(2) + addr + payload
        // + tag, with no padding for a non-empty payload.
        let body_len = 16 + CLIENT_BODY_PREFIX + addr.len() + 4;
        assert_eq!(
            wire.len(),
            CHACHA_NONCE_LEN + body_len + SsAead::XChaCha20Poly1305.tag_len()
        );
        let plain = SsAead::XChaCha20Poly1305
            .open(
                &psk,
                &wire[..CHACHA_NONCE_LEN],
                b"",
                &wire[CHACHA_NONCE_LEN..],
            )
            .unwrap();
        assert_eq!(&plain[..8], &writer.client_session_id.to_be_bytes());
        assert_eq!(&plain[8..16], &0u64.to_be_bytes());
        assert_eq!(plain[16], HEADER_TYPE_CLIENT_PACKET);
        assert_eq!(
            &plain[16 + CLIENT_BODY_PREFIX..],
            &[addr.as_slice(), b"ping"].concat()[..]
        );

        // A second datagram: packet id 1 and a fresh random nonce.
        let second = seal_with(&mut writer, &dest, b"ping");
        assert_ne!(&wire[..CHACHA_NONCE_LEN], &second[..CHACHA_NONCE_LEN]);
        let plain = SsAead::XChaCha20Poly1305
            .open(
                &psk,
                &second[..CHACHA_NONCE_LEN],
                b"",
                &second[CHACHA_NONCE_LEN..],
            )
            .unwrap();
        assert_eq!(&plain[8..16], &1u64.to_be_bytes());
    }

    #[test]
    fn chacha_2022_reader_opens_a_hand_built_server_datagram() {
        let method = SsMethod::from_method("2022-blake3-chacha20-poly1305").unwrap();
        let psk = [0x62u8; 32];
        let origin = TargetAddr::new(Host::Ip(IpAddr::from([198, 18, 0, 3])), 853);
        let client_id = 0xDEAD_BEEF_CAFE_F00D;
        let mut reader =
            Ss2022ReaderState::new(method, Arc::new(Zeroizing::new(psk.to_vec())), client_id);
        let wire = chacha_server_datagram(&psk, 0x77, 0, client_id, &origin, b"reply");

        let (decoded, payload) = reader.open(&wire).unwrap().expect("one datagram");
        assert_eq!(decoded, origin);
        assert_eq!(payload, b"reply");
        assert!(reader.open(&wire).unwrap().is_none(), "replayed datagram");
    }

    /// A domain origin comes back as `None` (no `SocketAddr` form), and the
    /// session that carried it is learned like any other.
    #[test]
    fn a_domain_reply_origin_surfaces_as_no_socket_addr() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x63u8; 32];
        let domain = TargetAddr::new(Host::Domain("dns.example".into()), 53);
        let client_id = 0x1234_5678_9ABC_DEF0;
        let mut reader =
            Ss2022ReaderState::new(method, Arc::new(Zeroizing::new(psk.to_vec())), client_id);
        let wire = aes_server_datagram(method, &psk, 0x99, 0, client_id, &domain, b"a");
        let (origin, _) = reader.open(&wire).unwrap().expect("one datagram");
        assert_eq!(origin, domain);
        assert_eq!(socket_addr(&origin), None, "a domain has no SocketAddr");
        assert!(reader.sessions.is_known(0x99));
    }

    /// Four 2022 datagrams for one link: the whole exchange through the
    /// carrier's real socket, split into halves, with the server double
    /// parsing the client's wire and answering with a hand-built datagram.
    #[tokio::test]
    async fn aes_2022_tunnel_round_trips_after_split() {
        let method = SsMethod::from_method("2022-blake3-aes-256-gcm").unwrap();
        let psk = [0x64u8; 32];
        let cfg = ss_cfg("2022-blake3-aes-256-gcm", &base64(&psk));
        let target = TargetAddr::new(Host::Ip(IpAddr::from([10, 1, 2, 3])), 5353);
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let ctx = ctx_for(&cfg, server_addr, target.clone());
        let tunnel = connect_udp(&ctx, method, &cfg).await.unwrap();
        let (mut reader, mut writer) = tunnel.split().unwrap();

        let echo = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            let (read, from) = server.recv_from(&mut buf).await.unwrap();
            let (client_id, packet_id, dest, payload) =
                open_client_aes_datagram(method, &psk, &buf[..read]).unwrap();
            assert_eq!(packet_id, 0);
            assert_eq!(dest, target);
            assert_eq!(payload, b"query");
            let reply =
                aes_server_datagram(method, &psk, 0x0BAD_C0DE, 0, client_id, &dest, b"answer");
            server.send_to(&reply, from).await.unwrap();
        });

        writer.send(None, b"query").await.unwrap();
        let (origin, payload) = reader.recv().await.unwrap().expect("one reply");
        echo.await.unwrap();

        assert_eq!(payload, b"answer");
        assert_eq!(origin, Some(SocketAddr::from(([10, 1, 2, 3], 5353))));
    }
}
