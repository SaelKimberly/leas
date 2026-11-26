//! The record layer and the outer MACs.
//!
//! A transport message is `type(u32 LE) | receiver(u32) | counter(u64 LE) |
//! ciphertext | tag(16)`; the type word's upper three bytes are the `reserved`
//! field (WARP). The reference computes both handshake MACs over those bytes
//! as **zero** and stamps `reserved` afterwards, so a receiver must copy the
//! three bytes off, zero them, verify, and only then trust the type byte
//! (`ferrox-core/src/wireguard/transport.rs:62-130`).
//!
//! Nonces are `00 00 00 00 ‖ counter(u64 LE)`; content is padded to a multiple
//! of 16 and never past the interface MTU. The replay window is RFC 6479 with
//! the reference's 127 × 64 = 8128 counters (`wireguard-go/replay/replay.go`).

use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, AeadInOut, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce};
use zeroize::Zeroize;

use crate::protocol::wireguard::kdf::{LABEL_COOKIE, LABEL_MAC1};

/// Message type words, little-endian in the first four bytes.
pub const TYPE_INITIATION: u32 = 1;
pub const TYPE_RESPONSE: u32 = 2;
pub const TYPE_COOKIE_REPLY: u32 = 3;
pub const TYPE_TRANSPORT: u32 = 4;

/// Handshake message sizes (the reference's marshal checks are exact).
pub const INITIATION_SIZE: usize = 148;
pub const RESPONSE_SIZE: usize = 92;
pub const COOKIE_REPLY_SIZE: usize = 64;
/// Transport header and Poly1305 tag.
pub const HEADER_SIZE: usize = 16;
pub const TAG_SIZE: usize = 16;
/// An empty transport message (a keepalive) is header + tag.
pub const MIN_SIZE: usize = HEADER_SIZE + TAG_SIZE;
/// Transport content is padded to this multiple, capped at the MTU.
pub const PADDING_MULTIPLE: usize = 16;
/// Replay window: 127 usable blocks of 64 counters (`windowSize` in the
/// reference).
pub const REPLAY_WINDOW: u64 = 127 * 64;

/// The three reserved bytes now in `buf[1..4]`, written over the type word's
/// upper bytes. A buffer shorter than four bytes is left alone.
pub fn set_reserved(buf: &mut [u8], reserved: [u8; 3]) {
    if buf.len() >= 4 {
        buf[1..4].copy_from_slice(&reserved);
    }
}

/// Zero the reserved bytes before parsing a message whose MACs were computed
/// over zeros.
pub fn clear_reserved(buf: &mut [u8]) {
    if buf.len() >= 4 {
        buf[1..4].fill(0);
    }
}

/// The message type from a zeroed type word.
#[must_use]
pub fn message_type(buf: &[u8]) -> Option<u32> {
    let word = u32::from_le_bytes(buf.get(..4)?.try_into().ok()?);
    Some(word & 0xff)
}

/// `BLAKE2s256("mac1----" ‖ peer_static_public)` — the `mac1` key.
#[must_use]
pub fn mac1_key(peer_static: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(LABEL_MAC1);
    h.update(peer_static);
    h.finalize().into()
}

/// `BLAKE2s256("cookie--" ‖ peer_static_public)` — the cookie-encryption key.
#[must_use]
pub fn cookie_key(peer_static: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(LABEL_COOKIE);
    h.update(peer_static);
    h.finalize().into()
}

/// Keyed BLAKE2s-128 over `data`.
#[must_use]
pub fn keyed_mac(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <blake2::Blake2sMac<blake2::digest::consts::U16> as KeyInit>::new_from_slice(key)
        .expect("BLAKE2s MAC accepts a key up to 32 bytes");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Fill `msg`'s last 32 bytes: `mac1` over everything before it.
pub fn set_mac1(msg: &mut [u8], peer_static: &[u8; 32]) {
    let key = mac1_key(peer_static);
    let split = msg.len() - 32;
    let mac = keyed_mac(&key, &msg[..split]);
    msg[split..split + 16].copy_from_slice(&mac);
    msg[split + 16..].fill(0);
}

/// Verify `mac1` of a handshake message whose reserved bytes are already
/// zeroed.
#[must_use]
pub fn check_mac1(msg: &[u8], peer_static: &[u8; 32]) -> bool {
    if msg.len() < 32 {
        return false;
    }
    let key = mac1_key(peer_static);
    let split = msg.len() - 32;
    let mac = keyed_mac(&key, &msg[..split]);
    mac[..] == msg[split..split + 16]
}

/// Fill `msg`'s last 16 bytes with `mac2`, keyed by a cookie the peer issued.
/// `mac2` covers everything before it (which includes `mac1`).
pub fn set_mac2(msg: &mut [u8], cookie: &[u8; 16]) {
    if msg.len() < 16 {
        return;
    }
    let split = msg.len() - 16;
    let mac = keyed_mac(cookie, &msg[..split]);
    msg[split..].copy_from_slice(&mac);
}

/// Verify `mac2` under `cookie` (the receiver's `CheckMAC2`).
#[must_use]
pub fn check_mac2(msg: &[u8], cookie: &[u8; 16]) -> bool {
    if msg.len() < 16 {
        return false;
    }
    let split = msg.len() - 16;
    let mac = keyed_mac(cookie, &msg[..split]);
    mac[..] == msg[split..]
}

/// Decrypt a cookie reply (`type 3`). `own_mac1` is the `mac1` of the message
/// the peer refused: it is the AEAD's associated data, so a reply for another
/// message cannot be replayed at us.
#[must_use]
pub fn consume_cookie_reply(
    cookie_key: &[u8; 32],
    own_mac1: &[u8; 16],
    msg: &[u8; COOKIE_REPLY_SIZE],
) -> Option<[u8; 16]> {
    if message_type(msg)? != TYPE_COOKIE_REPLY {
        return None;
    }
    let cipher = XChaCha20Poly1305::new(cookie_key.into());
    let nonce_bytes: [u8; 24] = msg[8..32].try_into().ok()?;
    let nonce = &XNonce::from(nonce_bytes);
    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &msg[32..64],
                aad: own_mac1,
            },
        )
        .ok()?;
    plain.try_into().ok()
}

/// Build a cookie reply for a handshake message that failed `mac1` under load.
///
/// `nonce` and `cookie` are the caller's, so the responder stays deterministic
/// in tests. The cookie itself is `BLAKE2s128_keyed(secret, source_address)`.
#[must_use]
pub fn cookie_reply(
    cookie_key: &[u8; 32],
    receiver_index: u32,
    nonce: [u8; 24],
    cookie: [u8; 16],
    refused_mac1: &[u8; 16],
) -> [u8; COOKIE_REPLY_SIZE] {
    let mut out = [0u8; COOKIE_REPLY_SIZE];
    out[..4].copy_from_slice(&TYPE_COOKIE_REPLY.to_le_bytes());
    out[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    out[8..32].copy_from_slice(&nonce);
    let cipher = XChaCha20Poly1305::new(cookie_key.into());
    let sealed = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &cookie,
                aad: refused_mac1,
            },
        )
        .expect("XChaCha20-Poly1305 seal cannot fail");
    out[32..].copy_from_slice(&sealed);
    out
}

/// A counter the sender must never reach (`RejectAfterMessages`).
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
/// The sender starts a new handshake at this counter while the old session
/// keeps carrying traffic (`RekeyAfterMessages`).
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

/// The padded length of one transport payload at the interface MTU.
///
/// Rounded up to a multiple of 16, but never past `mtu`
/// (`wireguard-go/device/send.go:419-432`): the MTU bounds the *inner* IP
/// packet, so padding only fills the slack below it. There is deliberately no
/// header subtraction: the sealed record is `content + 16 header + 16 tag`,
/// larger than the MTU by the `WireGuard` overhead — capping at `mtu − 32` would
/// refuse every full-sized segment.
#[must_use]
pub const fn padded_len(content: usize, mtu: usize) -> usize {
    if content > mtu {
        return content;
    }
    let padded = content.next_multiple_of(PADDING_MULTIPLE);
    if padded > mtu { mtu } else { padded }
}

/// Seal one transport record whose plaintext is **already** at
/// `out[HEADER_SIZE..HEADER_SIZE + len]` (padding included), writing the header
/// and the tag around it. Returns the record length.
pub fn seal_in_place(
    key: &[u8; 32],
    counter: u64,
    receiver: u32,
    reserved: [u8; 3],
    len: usize,
    out: &mut [u8],
) -> usize {
    let total = HEADER_SIZE + len + TAG_SIZE;
    assert!(out.len() >= total, "output buffer too small for a record");
    let mut word = TYPE_TRANSPORT.to_le_bytes();
    word[1..4].copy_from_slice(&reserved);
    out[..4].copy_from_slice(&word);
    out[4..8].copy_from_slice(&receiver.to_le_bytes());
    out[8..16].copy_from_slice(&counter.to_le_bytes());
    let nonce = transport_nonce(counter);
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(
            &Nonce::from(nonce),
            &[],
            (&mut out[HEADER_SIZE..HEADER_SIZE + len]).into(),
        )
        .expect("ChaCha20-Poly1305 seal cannot fail");
    out[HEADER_SIZE + len..total].copy_from_slice(tag.as_slice());
    total
}

/// Seal one transport record into `out` (which must hold
/// `HEADER_SIZE + plaintext.len() + TAG_SIZE` bytes), returning its length.
///
/// The ciphertext is the plaintext plus its padding, so the caller pads
/// `plaintext` itself via [`padded_len`] before calling.
pub fn seal(
    key: &[u8; 32],
    counter: u64,
    receiver: u32,
    reserved: [u8; 3],
    plaintext: &[u8],
    out: &mut [u8],
) -> usize {
    let total = HEADER_SIZE + plaintext.len() + TAG_SIZE;
    assert!(out.len() >= total, "output buffer too small for a record");
    out[HEADER_SIZE..HEADER_SIZE + plaintext.len()].copy_from_slice(plaintext);
    seal_in_place(key, counter, receiver, reserved, plaintext.len(), out)
}

fn transport_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Open one transport record in place: `buf[..total]`, with the plaintext
/// left at `buf[HEADER_SIZE..HEADER_SIZE + len]`. Returns
/// `(receiver, counter, plaintext_len)`.
///
/// The reserved bytes are cleared before decryption — they are not part of
/// what the sender's tag covers only because the reference clears them too —
/// and restored after, so a failed open leaves `buf` exactly as it arrived.
pub fn open(key: &[u8; 32], buf: &mut [u8], total: usize) -> Option<(u32, u64, usize)> {
    if total < MIN_SIZE || buf.len() < total {
        return None;
    }
    let reserved = [buf[1], buf[2], buf[3]];
    clear_reserved(buf);
    let receiver = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    let counter = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = transport_nonce(counter);
    let body_len = total - HEADER_SIZE - TAG_SIZE;
    let (message, tag_bytes) = buf[HEADER_SIZE..total].split_at_mut(body_len);
    let Ok(tag) = chacha20poly1305::aead::Tag::<ChaCha20Poly1305>::try_from(&tag_bytes[..]) else {
        set_reserved(buf, reserved);
        return None;
    };
    if cipher
        .decrypt_inout_detached(&Nonce::from(nonce), &[], message.into(), &tag)
        .is_err()
    {
        set_reserved(buf, reserved);
        return None;
    }
    set_reserved(buf, reserved);
    Some((receiver, counter, body_len))
}

/// The RFC 6479 anti-replay window the reference uses: 127 blocks of 64 bits.
///
/// `check` answers whether a counter could be accepted; the record must only be
/// committed after its tag verified, so a forged counter cannot advance it.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    last: u64,
    ring: [u64; 128],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            last: 0,
            ring: [0u64; 128],
        }
    }
}

impl ReplayWindow {
    /// A fresh window.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: 0,
            ring: [0u64; 128],
        }
    }

    /// Forget every counter (a new session).
    pub const fn reset(&mut self) {
        self.last = 0;
        let mut i = 0;
        while i < 128 {
            self.ring[i] = 0;
            i += 1;
        }
    }
    /// Would `counter` be accepted now? Counters at or past
    /// [`REJECT_AFTER_MESSAGES`] are always refused, and so is anything older
    /// than [`REPLAY_WINDOW`] behind the newest accepted counter (`replay.go:52`).
    #[must_use]
    pub const fn check(&self, counter: u64) -> bool {
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        if counter > self.last {
            return true;
        }
        // `replay.go:52`: rejected when more than `windowSize` (8128) COUNTERS
        // behind the newest accepted value.
        if self.last.saturating_sub(counter) > REPLAY_WINDOW {
            return false;
        }
        let index = ((counter / 64) % 128) as usize;
        let bit = 1u64 << (counter % 64);
        self.ring[index] & bit == 0
    }

    /// Record a counter that was accepted (call after the tag verified, and
    /// only when `check` returned true).
    ///
    /// The clear loop is capped at one ring: a far-ahead counter must reset the
    /// window, not spin 2^58 times inside the single driver task.
    pub const fn commit(&mut self, counter: u64) {
        if counter > self.last {
            let end = counter / 64;
            let oldest = end.saturating_sub(127);
            let first = self.last / 64 + 1;
            let start = if first > oldest { first } else { oldest };
            let mut block = start;
            let mut index = (block % 128) as usize;
            while block <= end {
                self.ring[index] = 0;
                index = (index + 1) % 128;
                block += 1;
            }
            self.last = counter;
        }
        let index = ((counter / 64) % 128) as usize;
        self.ring[index] |= 1u64 << (counter % 64);
    }
}

impl Drop for ReplayWindow {
    fn drop(&mut self) {
        self.ring.zeroize();
    }
}

/// A session's send state: key, counter, reserved bytes, and the peer's index.
pub struct SendKey {
    key: [u8; 32],
    counter: u64,
    pub receiver: u32,
    pub reserved: [u8; 3],
}

impl SendKey {
    /// A fresh send direction.
    #[must_use]
    pub const fn new(key: [u8; 32], receiver: u32, reserved: [u8; 3]) -> Self {
        Self {
            key,
            counter: 0,
            receiver,
            reserved,
        }
    }

    /// The next counter, or `None` when the session must stop sending.
    pub const fn next_counter(&mut self) -> Option<u64> {
        if self.counter >= REJECT_AFTER_MESSAGES {
            return None;
        }
        let counter = self.counter;
        self.counter += 1;
        Some(counter)
    }

    /// Whether the session has sent enough records that a new handshake must
    /// start while it keeps carrying traffic (`RekeyAfterMessages = 1<<60`).
    #[must_use]
    pub const fn needs_rekey(&self) -> bool {
        self.counter >= REKEY_AFTER_MESSAGES
    }

    /// Move the counter for a boundary test (never for production use).
    #[cfg(test)]
    pub(crate) const fn force_counter(&mut self, counter: u64) {
        self.counter = counter;
    }

    /// Seal `plaintext` (already padded) into `out`.
    pub fn seal_into(&self, counter: u64, plaintext: &[u8], out: &mut [u8]) -> usize {
        seal(
            &self.key,
            counter,
            self.receiver,
            self.reserved,
            plaintext,
            out,
        )
    }

    /// Seal a record whose plaintext is already at `out[16..16 + len]`.
    pub fn seal_in_place(&self, counter: u64, len: usize, out: &mut [u8]) -> usize {
        seal_in_place(&self.key, counter, self.receiver, self.reserved, len, out)
    }
}

impl Drop for SendKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// A session's receive state: key, replay window, peer index.
pub struct ReceiveKey {
    key: [u8; 32],
    pub receiver: u32,
    window: ReplayWindow,
}

impl ReceiveKey {
    /// A fresh receive direction.
    #[must_use]
    pub const fn new(key: [u8; 32], receiver: u32) -> Self {
        Self {
            key,
            receiver,
            window: ReplayWindow::new(),
        }
    }

    /// Check-then-open: the window is advanced only after the tag verified.
    pub fn open_in_place(&mut self, buf: &mut [u8], total: usize) -> Option<usize> {
        let receiver = u32::from_le_bytes(buf.get(4..8)?.try_into().ok()?);
        if receiver != self.receiver {
            return None;
        }
        let counter = u64::from_le_bytes(buf.get(8..16)?.try_into().ok()?);
        if !self.window.check(counter) {
            return None;
        }
        let (_, got_counter, len) = open(&self.key, buf, total)?;
        debug_assert_eq!(counter, got_counter);
        self.window.commit(counter);
        Some(len)
    }
}

impl Drop for ReceiveKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn seal_open_round_trip_and_nonce_layout() {
        let mut record = [0u8; 128];
        let payload = [0xABu8; 40];
        let n = seal(&KEY, 5, 0x1122_3344, [0, 0, 0], &payload, &mut record);
        assert_eq!(n, HEADER_SIZE + 40 + TAG_SIZE);
        assert_eq!(
            u32::from_le_bytes(record[..4].try_into().unwrap()),
            TYPE_TRANSPORT
        );
        assert_eq!(
            u32::from_le_bytes(record[4..8].try_into().unwrap()),
            0x1122_3344
        );
        assert_eq!(u64::from_le_bytes(record[8..16].try_into().unwrap()), 5);

        let (receiver, counter, len) = open(&KEY, &mut record, n).expect("opens");
        assert_eq!((receiver, counter, len), (0x1122_3344, 5, 40));
        assert_eq!(&record[HEADER_SIZE..HEADER_SIZE + 40], &payload);
    }

    #[test]
    fn a_flipped_tag_is_refused_and_the_buffer_is_untouched() {
        let mut record = [0u8; 64];
        let n = seal(&KEY, 1, 9, [1, 2, 3], &[0u8; 8], &mut record);
        let before = record;
        record[n - 1] ^= 0xff;
        assert!(open(&KEY, &mut record, n).is_none());
        record[n - 1] ^= 0xff;
        // Restored bytes still open (reserved put back on the failure path).
        assert!(open(&KEY, &mut record, n).is_some());
        assert_eq!(before[1..4], [1, 2, 3]);
    }

    #[test]
    fn reserved_bytes_are_carried_but_do_not_break_the_tag() {
        let mut record = [0u8; 64];
        let n = seal(&KEY, 3, 1, [0xAA, 0xBB, 0xCC], &[0u8; 4], &mut record);
        assert_eq!(&record[1..4], &[0xAA, 0xBB, 0xCC]);
        let (_, _, _) = open(&KEY, &mut record, n).expect("opens");
        // After a successful open the reserved bytes are back in place.
        assert_eq!(&record[1..4], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(message_type(&record), Some(TYPE_TRANSPORT));
    }

    #[test]
    fn replay_window_accepts_out_of_order_once_and_refuses_the_ceiling() {
        let mut w = ReplayWindow::new();
        w.commit(0);
        assert!(w.check(1));
        w.commit(1);
        assert!(!w.check(1), "duplicate refused");
        assert!(!w.check(0), "older counter already seen");
        w.commit(8120);
        assert!(w.check(8119), "inside the window, unseen");
        assert!(w.check(7000), "still inside the 8128 window, unseen");
        assert!(
            !w.check(0),
            "a message seen before the window slid stays seen"
        );
        assert!(!w.check(REJECT_AFTER_MESSAGES));
        assert!(w.check(REJECT_AFTER_MESSAGES - 1));
    }

    #[test]
    fn replay_window_boundary_is_measured_in_counters() {
        // Exactly `windowSize` behind: examined (`replay.go:52` uses `>`).
        let mut w = ReplayWindow::new();
        w.commit(REPLAY_WINDOW);
        assert!(w.check(0));
        // One counter further: behind the window, refused.
        let mut w = ReplayWindow::new();
        w.commit(REPLAY_WINDOW + 1);
        assert!(!w.check(0));
    }

    #[test]
    fn replay_window_slides_by_blocks() {
        let mut w = ReplayWindow::new();
        w.commit(64 * 128);
        // Everything older than the window is gone.
        assert!(!w.check(0));
        assert!(w.check(64 * 128 + 1));
    }

    #[test]
    fn counters_flag_the_rekey_threshold_and_stop_at_the_reject_ceiling() {
        let mut key = SendKey::new([1u8; 32], 3, [0, 0, 0]);
        key.force_counter(REKEY_AFTER_MESSAGES - 1);
        assert!(!key.needs_rekey());
        key.force_counter(REKEY_AFTER_MESSAGES);
        assert!(key.needs_rekey(), "1<<60 must start a new handshake");
        assert!(
            key.next_counter().is_some(),
            "the old session keeps carrying traffic while it rekeys"
        );
        key.force_counter(REJECT_AFTER_MESSAGES - 1);
        assert_eq!(key.next_counter(), Some(REJECT_AFTER_MESSAGES - 1));
        key.force_counter(REJECT_AFTER_MESSAGES);
        assert_eq!(key.next_counter(), None, "the ceiling refuses to send");
    }

    #[test]
    fn send_and_receive_keys_agree_and_receive_advances_the_window() {
        let mut send = SendKey::new(KEY, 77, [0, 0, 0]);
        let mut recv = ReceiveKey::new(KEY, 77);
        let mut record = [0u8; 96];
        let c0 = send.next_counter().unwrap();
        let n = send.seal_into(c0, &[1u8; 16], &mut record);
        assert_eq!(recv.open_in_place(&mut record, n), Some(16));
        // Replaying the same record is refused.
        assert_eq!(recv.open_in_place(&mut record, n), None);
    }

    #[test]
    fn mac1_keys_are_labelled_and_verify() {
        let peer = [3u8; 32];
        let mut msg = [0u8; INITIATION_SIZE];
        msg[..4].copy_from_slice(&TYPE_INITIATION.to_le_bytes());
        set_mac1(&mut msg, &peer);
        assert!(check_mac1(&msg, &peer));
        msg[8] ^= 1;
        assert!(!check_mac1(&msg, &peer));
    }

    #[test]
    fn a_cookie_reply_round_trips_only_for_its_own_mac1() {
        let key = cookie_key(&[9u8; 32]);
        let mac1 = [5u8; 16];
        let reply = cookie_reply(&key, 42, [1u8; 24], [0xCD; 16], &mac1);
        assert_eq!(message_type(&reply), Some(TYPE_COOKIE_REPLY));
        assert_eq!(consume_cookie_reply(&key, &mac1, &reply), Some([0xCD; 16]));
        // A different mac1 (another refused message) does not open it.
        assert_eq!(consume_cookie_reply(&key, &[6u8; 16], &reply), None);
    }

    #[test]
    fn mac2_is_keyed_by_the_cookie() {
        let mut msg = [0u8; RESPONSE_SIZE];
        set_mac1(&mut msg, &[4u8; 32]);
        set_mac2(&mut msg, &[0x11; 16]);
        assert!(check_mac2(&msg, &[0x11; 16]));
        assert!(!check_mac2(&msg, &[0x12; 16]));
    }

    #[test]
    fn padding_rounds_up_but_never_past_the_mtu() {
        assert_eq!(padded_len(1, 1420), 16);
        assert_eq!(padded_len(32, 1420), 32);
        // A full interface-MTU packet is not padded at all; the record still
        // grows past the MTU by the 16-byte header and 16-byte tag.
        assert_eq!(padded_len(1420, 1420), 1420);
        // Near the MTU the reference pads *to* the MTU, never past it.
        assert_eq!(padded_len(1409, 1420), 1420);
        assert_eq!(padded_len(1419, 1420), 1420);
        assert_eq!(padded_len(1388, 1420), 1392);
        assert_eq!(
            padded_len(1424, 1420),
            1424,
            "content above the MTU is the caller's bug, not truncation"
        );
    }
}
