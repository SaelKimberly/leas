//! One peer's tunnel: session rotation, the payload queue, and the message
//! timers.
//!
//! Sans-I/O contract: `now` is Unix seconds supplied by the caller, nothing
//! here reads a clock or opens a socket, and every output is an [`Event`]. The
//! timer values are the reference's (`wireguard-go/device/constants.go`), and
//! the state machine mirrors `device/timers.go`'s observable behaviour rather
//! than its goroutines.

use std::collections::VecDeque;

use super::handshake::{Handshake, SessionKeys, tai64n};
use super::transport::{
    self, COOKIE_REPLY_SIZE, HEADER_SIZE, MIN_SIZE, RESPONSE_SIZE, ReceiveKey, SendKey,
    TYPE_COOKIE_REPLY, TYPE_RESPONSE, TYPE_TRANSPORT, padded_len,
};
use crate::protocol::wireguard::keys::{KeyError, Secret, fill_secret, public_key};

/// Rekey while the old session still carries traffic.
pub const REKEY_AFTER_TIME: u64 = 120;
/// Stop using (and stop accepting) a session this old.
pub const REJECT_AFTER_TIME: u64 = 180;
/// Retransmit the initiation this often.
pub const REKEY_TIMEOUT: u64 = 5;
/// Give up on a handshake after this long.
pub const REKEY_ATTEMPT_TIME: u64 = 90;
/// Send a keepalive this long after receiving data, if nothing was sent.
pub const KEEPALIVE_TIMEOUT: u64 = 10;
/// A stored cookie is stale after this long.
pub const COOKIE_REFRESH_TIME: u64 = 120;
/// Sending data with nothing authenticated received for this long starts a
/// fresh handshake (`timersDataSent`: `KeepaliveTimeout + RekeyTimeout`).
pub const NEW_HANDSHAKE_AFTER: u64 = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
/// Payloads held while no session exists.
pub const MAX_STAGED: usize = 64;

/// What the tunnel produced for the driver to act on.
#[derive(Debug)]
pub enum Event {
    /// One datagram for the connected UDP socket.
    Send(Vec<u8>),
    /// A decrypted inner IP packet.
    Inbound(Vec<u8>),
    /// A session exists from now on.
    Established,
    /// A rekey attempt gave up; the live session keeps carrying traffic.
    Failed,
    /// The handshake gave up with no session at all: the peer is unreachable
    /// and every flow on this device must fail.
    Dead,
}

struct Session {
    send: SendKey,
    recv: ReceiveKey,
    established: u64,
}

struct State {
    session: Option<Session>,
    previous: Option<Session>,
}

/// The driver's per-peer state machine.
pub struct Tunnel {
    secret: Secret,
    peer_public: [u8; 32],
    psk: Option<Secret>,
    mtu: usize,
    reserved: [u8; 3],
    local_index: u32,
    /// `persistent_keepalive`: send an empty record this often on an idle
    /// session. `0` = off.
    keepalive_interval: u64,
    handshake: Option<Handshake>,
    state: State,
    staged: VecDeque<Vec<u8>>,
    attempts: u32,
    last_handshake_at: Option<u64>,
    handshake_started_at: Option<u64>,
    keepalive_at: Option<u64>,
    need_another_keepalive: bool,
    periodic_keepalive_at: Option<u64>,
    last_received_at: Option<u64>,
    cookie: Option<([u8; 16], u64)>,
    last_mac1: [u8; 16],
    /// Last second a timestamp was issued, and the sub-second value used, so
    /// two initiations inside one second still differ (the peer rejects a
    /// non-increasing TAI64N).
    timestamp_secs: u64,
    timestamp_nanos: u32,
    dead: bool,
    rng: fn(&mut [u8; 32]),
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("established", &self.state.session.is_some())
            .field("staged", &self.staged.len())
            .field("attempts", &self.attempts)
            .field("dead", &self.dead)
            .finish_non_exhaustive()
    }
}

impl Tunnel {
    /// Build the peer. Rejects a zero/low-order peer public key up front.
    ///
    /// `keepalive_interval` is the profile's `persistent_keepalive` in seconds
    /// (`0` = off); `mtu` is the interface MTU, which bounds the padding.
    pub fn new(
        secret: Secret,
        peer_public: [u8; 32],
        psk: Option<Secret>,
        mtu: usize,
        reserved: [u8; 3],
        local_index: u32,
        keepalive_interval: u16,
    ) -> Result<Self, KeyError> {
        // Validating here means `initiate` cannot fail later on a bad key.
        let handshake = Handshake::new(secret.clone(), peer_public, psk.clone(), local_index)?;
        Ok(Self {
            secret,
            peer_public,
            psk,
            mtu,
            reserved,
            local_index,
            keepalive_interval: u64::from(keepalive_interval),
            handshake: Some(handshake),
            state: State {
                session: None,
                previous: None,
            },
            staged: VecDeque::new(),
            attempts: 0,
            last_handshake_at: None,
            handshake_started_at: None,
            keepalive_at: None,
            need_another_keepalive: false,
            periodic_keepalive_at: None,
            last_received_at: None,
            cookie: None,
            last_mac1: [0u8; 16],
            timestamp_secs: 0,
            timestamp_nanos: 0,
            dead: false,
            rng: fill_secret,
        })
    }

    /// Replace the ephemeral source (tests only).
    #[cfg(test)]
    pub(crate) fn set_rng(&mut self, rng: fn(&mut [u8; 32])) {
        self.rng = rng;
    }

    /// Install a cookie as if a reply had been consumed (tests only).
    #[cfg(test)]
    pub(crate) const fn force_cookie(&mut self, cookie: [u8; 16], now: u64) {
        self.cookie = Some((cookie, now));
    }

    /// Move the live session's send counter (tests only).
    #[cfg(test)]
    #[allow(clippy::missing_const_for_fn)] // `Option::as_mut` is not const here
    pub(crate) fn force_send_counter(&mut self, counter: u64) {
        if let Some(session) = self.state.session.as_mut() {
            session.send.force_counter(counter);
        }
    }

    /// The local static public key.
    #[must_use]
    pub fn public(&self) -> [u8; 32] {
        public_key(&self.secret)
    }

    /// The local handshake index.
    #[must_use]
    pub const fn local_index(&self) -> u32 {
        self.local_index
    }

    /// Whether a usable session exists at `now`.
    #[must_use]
    pub fn established(&self, now: u64) -> bool {
        self.state
            .session
            .as_ref()
            .is_some_and(|s| now.saturating_sub(s.established) < REJECT_AFTER_TIME)
    }

    /// Whether the handshake failed with no session (the device is unusable).
    #[must_use]
    pub const fn is_dead(&self) -> bool {
        self.dead
    }

    /// Queue one inner IP packet for the tunnel. A session seals it now;
    /// otherwise it waits for the handshake and starts one.
    pub fn send(&mut self, now: u64, payload: &[u8], out: &mut Vec<Event>) {
        if self.dead {
            return;
        }
        self.expire(now);
        if let Some(session) = self.state.session.as_mut() {
            let age = now.saturating_sub(session.established);
            let silent = self
                .last_received_at
                .is_some_and(|at| now.saturating_sub(at) >= NEW_HANDSHAKE_AFTER);
            Self::seal_record(session, payload, self.mtu, out);
            // A send cancels a pending keepalive (`timersAnyAuthenticatedPacketSent`).
            self.keepalive_at = None;
            self.need_another_keepalive = false;
            if (age >= REKEY_AFTER_TIME || session.send.needs_rekey() || silent)
                && self.handshake_started_at.is_none()
                // One initiation per retry interval, so a failed rekey cannot
                // turn every packet into a handshake.
                && self
                    .last_handshake_at
                    .is_none_or(|at| now.saturating_sub(at) >= REKEY_TIMEOUT)
            {
                self.initiate(now, out);
            }
            return;
        }
        if self.staged.len() < MAX_STAGED {
            self.staged.push_back(payload.to_vec());
        }
        if self.handshake_started_at.is_none()
            || self
                .last_handshake_at
                .is_some_and(|at| now.saturating_sub(at) >= REKEY_TIMEOUT)
        {
            self.initiate(now, out);
        }
    }

    /// Feed one datagram from the UDP socket.
    pub fn receive(&mut self, now: u64, datagram: &mut [u8], out: &mut Vec<Event>) {
        let Some(kind) = transport::message_type(datagram).filter(|_| datagram.len() >= 4) else {
            return;
        };
        match kind {
            TYPE_RESPONSE if datagram.len() == RESPONSE_SIZE => {
                let msg: &[u8; RESPONSE_SIZE] = datagram[..].try_into().expect("length checked");
                let keys = self
                    .handshake
                    .as_mut()
                    .and_then(|hs| hs.consume_response(msg));
                if let Some(keys) = keys {
                    self.install(&keys, now);
                    self.handshake = Handshake::new(
                        self.secret.clone(),
                        self.peer_public,
                        self.psk.clone(),
                        self.next_index(),
                    )
                    .ok();
                    self.attempts = 0;
                    self.handshake_started_at = None;
                    self.last_received_at = Some(now);
                    self.arm_keepalive(now);
                    out.push(Event::Established);
                    self.flush_staged(now, out);
                }
            }
            TYPE_COOKIE_REPLY if datagram.len() == COOKIE_REPLY_SIZE => {
                let msg: &[u8; COOKIE_REPLY_SIZE] =
                    datagram[..].try_into().expect("length checked");
                let key = transport::cookie_key(&self.peer_public);
                if let Some(cookie) = transport::consume_cookie_reply(&key, &self.last_mac1, msg) {
                    self.cookie = Some((cookie, now));
                }
            }
            TYPE_TRANSPORT if datagram.len() >= MIN_SIZE => {
                let total = datagram.len();
                if let Some(len) = self.open_inbound(now, datagram, total) {
                    self.last_received_at = Some(now);
                    // `timersDataReceived`: re-arm rather than ignore.
                    if self.keepalive_at.is_some() {
                        self.need_another_keepalive = true;
                    } else {
                        self.arm_keepalive(now);
                    }
                    if len == 0 {
                        return;
                    }
                    out.push(Event::Inbound(
                        datagram[HEADER_SIZE..HEADER_SIZE + len].to_vec(),
                    ));
                }
            }
            _ => {}
        }
    }

    /// Run the timers.
    pub fn poll(&mut self, now: u64, out: &mut Vec<Event>) {
        self.expire(now);

        if self.keepalive_interval > 0
            && self.state.session.is_some()
            && self.periodic_keepalive_at.is_some_and(|at| now >= at)
        {
            self.send_empty(now, out);
            self.periodic_keepalive_at = Some(now + self.keepalive_interval);
        }

        if self.keepalive_at.is_some_and(|at| now >= at) {
            self.keepalive_at = None;
            self.send_empty(now, out);
            if self.need_another_keepalive {
                self.need_another_keepalive = false;
                self.keepalive_at = Some(now + KEEPALIVE_TIMEOUT);
            }
        }

        let Some(started) = self.handshake_started_at else {
            return;
        };
        // A live session does NOT cancel a pending handshake: during a rekey
        // the old session keeps carrying traffic while the initiation retries
        // every `REKEY_TIMEOUT` (clearing the marker here re-armed `send`,
        // which then emitted a fresh initiation for every packet — a storm).
        if now.saturating_sub(started) >= REKEY_ATTEMPT_TIME {
            self.handshake_started_at = None;
            self.attempts = 0;
            if self.state.session.is_some() {
                out.push(Event::Failed);
            } else {
                self.staged.clear();
                self.dead = true;
                out.push(Event::Dead);
            }
            return;
        }
        if self
            .last_handshake_at
            .is_some_and(|at| now.saturating_sub(at) >= REKEY_TIMEOUT)
        {
            self.attempts += 1;
            self.initiate(now, out);
        }
    }

    /// The next moment [`Tunnel::poll`] has work, if any.
    ///
    /// A running minimum, not a collected `Vec`: the driver asks this every
    /// loop iteration.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        let mut next: Option<u64> = None;
        let mut take = |deadline: u64| {
            next = Some(next.map_or(deadline, |current| current.min(deadline)));
        };
        if let Some(at) = self.keepalive_at {
            take(at);
        }
        if self.keepalive_interval > 0
            && self.state.session.is_some()
            && let Some(at) = self.periodic_keepalive_at
        {
            take(at);
        }
        match (self.handshake_started_at, self.last_handshake_at) {
            (Some(started), Some(last)) => {
                take((last + REKEY_TIMEOUT).min(started + REKEY_ATTEMPT_TIME));
            }
            (Some(started), None) => take(started + REKEY_ATTEMPT_TIME),
            _ => {}
        }
        next
    }

    /// Drop sessions past `REJECT_AFTER_TIME` (send **and** receive).
    fn expire(&mut self, now: u64) {
        if self
            .state
            .session
            .as_ref()
            .is_some_and(|s| now.saturating_sub(s.established) >= REJECT_AFTER_TIME)
        {
            self.state.session = None;
        }
        if self
            .state
            .previous
            .as_ref()
            .is_some_and(|s| now.saturating_sub(s.established) >= REJECT_AFTER_TIME)
        {
            self.state.previous = None;
        }
    }

    const fn arm_keepalive(&mut self, now: u64) {
        if self.keepalive_at.is_none() {
            self.keepalive_at = Some(now + KEEPALIVE_TIMEOUT);
        }
    }

    fn send_empty(&mut self, now: u64, out: &mut Vec<Event>) {
        if let Some(session) = self.state.session.as_mut() {
            let Some(counter) = session.send.next_counter() else {
                return;
            };
            let mut record = vec![0u8; MIN_SIZE];
            let n = session.send.seal_in_place(counter, 0, &mut record);
            record.truncate(n);
            let _ = now;
            out.push(Event::Send(record));
        }
    }

    const fn next_index(&mut self) -> u32 {
        self.local_index = self.local_index.wrapping_add(1);
        self.local_index
    }

    fn timestamp(&mut self, now: u64) -> [u8; 12] {
        if now == self.timestamp_secs {
            self.timestamp_nanos = self.timestamp_nanos.saturating_add(1);
        } else {
            self.timestamp_secs = now;
            self.timestamp_nanos = 0;
        }
        tai64n(now, self.timestamp_nanos)
    }

    fn initiate(&mut self, now: u64, out: &mut Vec<Event>) {
        let timestamp = self.timestamp(now);
        let Some(handshake) = self.handshake.as_mut() else {
            return;
        };
        let mut ephemeral = [0u8; 32];
        (self.rng)(&mut ephemeral);
        let mut msg = handshake.create_initiation(timestamp, &ephemeral);
        // Both MACs are computed over the bytes with the reserved field ZERO
        // (`ferrox-core/src/wireguard/device.rs:265`: stamp reserved last, and
        // a receiver zeroes the field before verifying). mac2 therefore goes
        // in before the stamp, or it would cover bytes the peer clears.
        if let Some((cookie, at)) = self.cookie
            && now.saturating_sub(at) < COOKIE_REFRESH_TIME
        {
            transport::set_mac2(&mut msg, &cookie);
        }
        transport::set_reserved(&mut msg, self.reserved);
        self.last_mac1
            .copy_from_slice(&msg[msg.len() - 32..msg.len() - 16]);
        self.last_handshake_at = Some(now);
        if self.handshake_started_at.is_none() {
            self.handshake_started_at = Some(now);
        }
        out.push(Event::Send(msg.to_vec()));
    }

    fn install(&mut self, keys: &SessionKeys, now: u64) {
        let remote = self
            .handshake
            .as_ref()
            .map_or(0, super::handshake::Handshake::remote_index);
        let session = Session {
            send: SendKey::new(keys.send, remote, self.reserved),
            recv: ReceiveKey::new(keys.recv, self.local_index),
            established: now,
        };
        if let Some(old) = self.state.session.replace(session) {
            self.state.previous = Some(old);
        }
        if self.keepalive_interval > 0 {
            self.periodic_keepalive_at = Some(now + self.keepalive_interval);
        }
    }

    fn flush_staged(&mut self, _now: u64, out: &mut Vec<Event>) {
        let mtu = self.mtu;
        let staged: Vec<Vec<u8>> = self.staged.drain(..).collect();
        if let Some(session) = self.state.session.as_mut() {
            for payload in staged {
                Self::seal_record(session, &payload, mtu, out);
            }
        }
    }

    fn seal_record(session: &mut Session, payload: &[u8], mtu: usize, out: &mut Vec<Event>) {
        let content = padded_len(payload.len(), mtu);
        let Some(counter) = session.send.next_counter() else {
            return;
        };
        let mut record = vec![0u8; HEADER_SIZE + content + transport::TAG_SIZE];
        record[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);
        debug_assert!(content >= payload.len() && content <= mtu.max(payload.len()));
        let n = session.send.seal_in_place(counter, content, &mut record);
        record.truncate(n);
        out.push(Event::Send(record));
    }

    fn open_inbound(&mut self, now: u64, datagram: &mut [u8], total: usize) -> Option<usize> {
        if let Some(session) = self.state.session.as_mut()
            && now.saturating_sub(session.established) < REJECT_AFTER_TIME
            && let Some(len) = session.recv.open_in_place(datagram, total)
        {
            return Some(len);
        }
        if let Some(previous) = self.state.previous.as_mut()
            && now.saturating_sub(previous.established) < REJECT_AFTER_TIME
            && let Some(len) = previous.recv.open_in_place(datagram, total)
        {
            return Some(len);
        }
        None
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.last_mac1.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::wireguard::core::handshake::test_responder::Responder;
    use crate::protocol::wireguard::keys::{decode_private, public_key};

    fn alice() -> Secret {
        decode_private("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap()
    }

    fn bob() -> Secret {
        decode_private("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").unwrap()
    }

    fn rng_fn() -> fn(&mut [u8; 32]) {
        fn next(out: &mut [u8; 32]) {
            static COUNTER: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
            let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            *out = [n; 32];
        }
        next
    }

    fn tunnel_with(rng: fn(&mut [u8; 32]), keepalive: u16) -> Tunnel {
        let mut t = Tunnel::new(
            alice(),
            public_key(&bob()),
            None,
            1420,
            [0, 0, 0],
            7,
            keepalive,
        )
        .unwrap();
        t.set_rng(rng);
        t
    }

    fn tunnel(rng: fn(&mut [u8; 32])) -> Tunnel {
        tunnel_with(rng, 0)
    }

    /// Run the initiator half against a fresh responder and install a session.
    fn establish(t: &mut Tunnel, now: u64, responder_index: u32) -> Responder {
        let mut out = Vec::new();
        t.send(now, &[1u8; 8], &mut out);
        let Event::Send(initiation) = out.remove(0) else {
            unreachable!()
        };
        let mut responder = Responder::new(bob(), public_key(&alice()), None, responder_index);
        responder
            .consume_initiation(
                initiation
                    .get(..148)
                    .expect("an initiation")
                    .try_into()
                    .unwrap(),
            )
            .expect("authenticates");
        let response = responder.create_response(now, &[8u8; 32]);
        let mut response = response.to_vec();
        let mut events = Vec::new();
        t.receive(now, &mut response, &mut events);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Established)),
            "the session installs"
        );
        responder
    }

    /// The initiation is emitted and the payload waits; the response completes
    /// the session and flushes the staged payload.
    #[test]
    fn staged_payload_flushes_on_the_response() {
        let mut t = tunnel(rng_fn());
        let mut out = Vec::new();
        t.send(100, &[9u8; 20], &mut out);
        assert!(matches!(out[0], Event::Send(_)), "initiation first");
        let Event::Send(initiation) = &out[0] else {
            unreachable!()
        };
        let mut responder = Responder::new(bob(), public_key(&alice()), None, 0x55);
        responder
            .consume_initiation(initiation.as_slice().try_into().unwrap())
            .expect("authenticates");
        let response = responder.create_response(100, &[0x33; 32]);

        out.clear();
        let mut datagram = response.to_vec();
        t.receive(101, &mut datagram, &mut out);
        assert!(matches!(out[0], Event::Established), "session installed");
        assert!(matches!(out[1], Event::Send(_)), "staged payload flushed");
        assert!(t.established(101));
    }

    /// Five seconds without a response retransmits; ninety seconds gives up and
    /// reports the device dead (there was never a session).
    #[test]
    fn handshake_retransmits_then_declares_the_device_dead() {
        let mut t = tunnel(rng_fn());
        let mut out = Vec::new();
        t.send(0, &[1u8; 8], &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(t.next_deadline(), Some(REKEY_TIMEOUT));

        out.clear();
        t.poll(REKEY_TIMEOUT, &mut out);
        assert!(matches!(out[0], Event::Send(_)), "retransmit at 5 s");

        out.clear();
        t.poll(REKEY_ATTEMPT_TIME, &mut out);
        assert!(matches!(out.last(), Some(Event::Dead)), "gave up at 90 s");
        assert!(t.is_dead());
        assert!(t.staged.is_empty(), "staged payloads dropped");
        assert_eq!(t.next_deadline(), None);
    }

    /// A session older than the rekey time starts a new handshake while it is
    /// still used for the payload; older than the reject time it is dropped.
    #[test]
    fn rekey_and_reject_are_time_driven() {
        let mut t = tunnel(rng_fn());
        establish(&mut t, 0, 0x9);

        let mut out = Vec::new();
        t.send(REKEY_AFTER_TIME, &[2u8; 8], &mut out);
        assert!(
            out.iter()
                .any(|e| matches!(e, Event::Send(b) if b.len() == 148)),
            "a rekey initiation is emitted beside the data"
        );

        out.clear();
        t.send(REJECT_AFTER_TIME, &[3u8; 8], &mut out);
        assert!(
            !out.iter()
                .any(|e| matches!(e, Event::Send(b) if b.len() != 148 && b.len() != 92)),
            "the expired session no longer carries data"
        );
    }

    /// A rekey initiation past the age threshold retries on the timer, never
    /// per packet, and gives up without touching the live session.
    #[test]
    fn a_rekey_retries_on_a_timer_instead_of_per_packet() {
        use crate::protocol::wireguard::core::transport::REKEY_AFTER_MESSAGES;
        let mut t = tunnel(rng_fn());
        establish(&mut t, 0, 0x21);
        // The message-count trigger starts a rekey well before the age one, so
        // the attempt can give up while the session (reject at 180 s) is alive.
        t.force_send_counter(REKEY_AFTER_MESSAGES);

        let initiations = |out: &[Event]| {
            out.iter()
                .filter(|event| matches!(event, Event::Send(bytes) if bytes.len() == 148))
                .count()
        };

        let mut out = Vec::new();
        t.send(REKEY_TIMEOUT + 1, &[2u8; 8], &mut out);
        assert_eq!(initiations(&out), 1, "the threshold packet starts a rekey");

        out.clear();
        t.send(REKEY_TIMEOUT + 2, &[3u8; 8], &mut out);
        assert_eq!(initiations(&out), 0, "the next packet must not restart it");

        out.clear();
        t.poll(REKEY_TIMEOUT + REKEY_TIMEOUT + 1, &mut out);
        assert_eq!(initiations(&out), 1, "the timer retransmits it once");

        out.clear();
        t.poll(REKEY_TIMEOUT + 1 + REKEY_ATTEMPT_TIME, &mut out);
        assert!(
            out.iter().any(|event| matches!(event, Event::Failed)),
            "the attempt gives up after 90 s"
        );
        assert!(
            t.state.session.is_some(),
            "a failed rekey must not drop the live session"
        );
        assert!(!t.is_dead(), "a failed rekey is not fatal");
    }

    /// The 1<<60 counter threshold starts a handshake while the session keeps
    /// sending (`RekeyAfterMessages`).
    #[test]
    fn the_message_threshold_starts_a_handshake() {
        use crate::protocol::wireguard::core::transport::REKEY_AFTER_MESSAGES;
        let mut t = tunnel(rng_fn());
        establish(&mut t, 0, 0x31);

        t.force_send_counter(REKEY_AFTER_MESSAGES);
        let mut out = Vec::new();
        // Past the retry cooldown: the previous initiation went out at t = 0.
        t.send(REKEY_TIMEOUT + 1, &[2u8; 8], &mut out);
        assert!(
            out.iter()
                .any(|e| matches!(e, Event::Send(b) if b.len() == 148)),
            "an initiation is emitted at the threshold"
        );
    }

    /// Receiving data arms a keepalive ten seconds later; the keepalive is an
    /// empty (32-byte) transport record, and a send cancels it.
    #[test]
    fn a_keepalive_is_armed_by_a_received_record() {
        let mut t = tunnel(rng_fn());
        let responder = establish(&mut t, 0, 0x77);
        let (_, send_key) = responder.session_keys();
        let send = SendKey::new(send_key, 7, [0, 0, 0]);
        let mut record = vec![0u8; HEADER_SIZE + 16 + transport::TAG_SIZE];
        let n = send.seal_into(0, &[0u8; 16], &mut record);
        record.truncate(n);
        let mut out = Vec::new();
        t.receive(1, &mut record, &mut out);
        assert!(matches!(out[0], Event::Inbound(_)));

        out.clear();
        t.poll(1 + KEEPALIVE_TIMEOUT, &mut out);
        match &out[0] {
            Event::Send(bytes) => assert_eq!(bytes.len(), MIN_SIZE, "empty keepalive"),
            other => panic!("expected a keepalive, got {other:?}"),
        }

        // A send before the deadline cancels it.
        let mut record = vec![0u8; HEADER_SIZE + 16 + transport::TAG_SIZE];
        let n = send.seal_into(1, &[0u8; 16], &mut record);
        record.truncate(n);
        out.clear();
        t.receive(2, &mut record, &mut out);
        out.clear();
        t.send(3, &[1u8; 8], &mut out);
        out.clear();
        t.poll(3 + KEEPALIVE_TIMEOUT, &mut out);
        assert!(
            !out.iter()
                .any(|e| matches!(e, Event::Send(b) if b.len() == MIN_SIZE)),
            "a send cancels the pending keepalive"
        );
    }

    /// Data sent with nothing authenticated received for 15 s starts a fresh
    /// handshake (`timersDataSent`), so a restarted peer is noticed long before
    /// the 120 s rekey age.
    #[test]
    fn a_silent_peer_starts_a_new_handshake_after_fifteen_seconds() {
        let mut t = tunnel(rng_fn());
        let responder = establish(&mut t, 0, 0x41);
        let (_, send_key) = responder.session_keys();
        let send = SendKey::new(send_key, 7, [0, 0, 0]);
        let mut record = vec![0u8; HEADER_SIZE + 16 + transport::TAG_SIZE];
        let n = send.seal_into(0, &[0u8; 16], &mut record);
        record.truncate(n);
        let mut out = Vec::new();
        t.receive(0, &mut record, &mut out);

        out.clear();
        t.send(NEW_HANDSHAKE_AFTER, &[1u8; 8], &mut out);
        assert!(
            out.iter()
                .any(|e| matches!(e, Event::Send(b) if b.len() == 148)),
            "silence for 15 s starts a handshake on the next send"
        );
    }

    /// `persistent_keepalive` keeps an idle session alive on its own interval.
    #[test]
    fn persistent_keepalive_fires_on_an_idle_session() {
        let mut t = tunnel_with(rng_fn(), 25);
        establish(&mut t, 0, 0x51);
        let mut out = Vec::new();
        t.poll(25, &mut out);
        match out.first() {
            Some(Event::Send(bytes)) => assert_eq!(bytes.len(), MIN_SIZE, "empty keepalive"),
            other => panic!("expected the periodic keepalive, got {other:?}"),
        }
        out.clear();
        t.poll(49, &mut out);
        assert!(
            !out.iter()
                .any(|e| matches!(e, Event::Send(b) if b.len() == MIN_SIZE)),
            "not before the next interval"
        );
        out.clear();
        t.poll(50, &mut out);
        assert!(
            out.iter()
                .any(|e| matches!(e, Event::Send(b) if b.len() == MIN_SIZE))
        );
    }

    /// A record from a session past `REJECT_AFTER_TIME` is refused, even though
    /// its key and counter would still open it.
    #[test]
    fn an_expired_session_no_longer_accepts_records() {
        let mut t = tunnel(rng_fn());
        let responder = establish(&mut t, 0, 0x61);
        let (_, send_key) = responder.session_keys();
        let send = SendKey::new(send_key, 7, [0, 0, 0]);
        let mut record = vec![0u8; HEADER_SIZE + 16 + transport::TAG_SIZE];
        let n = send.seal_into(0, &[0u8; 16], &mut record);
        record.truncate(n);

        let mut out = Vec::new();
        t.receive(REJECT_AFTER_TIME, &mut record, &mut out);
        assert!(out.is_empty(), "the expired session is not used");
        assert!(!t.established(REJECT_AFTER_TIME));
    }

    /// The reserved bytes travel in the initiation's type word, stamped after
    /// the MACs, and the peer accepts it after zeroing them.
    /// With a cookie installed, mac2 must verify AFTER the receiver zeroes the
    /// reserved field: it is computed before the stamp.
    #[test]
    fn mac2_is_computed_before_the_reserved_stamp() {
        use crate::protocol::wireguard::core::transport::{check_mac2, clear_reserved};
        let mut t = Tunnel::new(alice(), public_key(&bob()), None, 1420, [1, 2, 3], 7, 0).unwrap();
        t.set_rng(rng_fn());
        let cookie = [0x5Au8; 16];
        t.force_cookie(cookie, 0);
        let mut out = Vec::new();
        t.send(0, &[1u8; 8], &mut out);
        let Event::Send(mut initiation) = out.remove(0) else {
            unreachable!()
        };
        assert_eq!(&initiation[1..4], &[1, 2, 3]);
        clear_reserved(&mut initiation);
        assert!(
            check_mac2(&initiation, &cookie),
            "mac2 covers the zeroed reserved bytes, not the stamped ones"
        );
    }

    #[test]
    fn an_initiation_carries_the_reserved_bytes() {
        let mut t = Tunnel::new(alice(), public_key(&bob()), None, 1420, [1, 2, 3], 7, 0).unwrap();
        t.set_rng(rng_fn());
        let mut out = Vec::new();
        t.send(0, &[1u8; 8], &mut out);
        let Event::Send(initiation) = out.remove(0) else {
            unreachable!()
        };
        assert_eq!(&initiation[1..4], &[1, 2, 3], "reserved in the type word");

        let mut responder = Responder::new(bob(), public_key(&alice()), None, 0x71);
        let message: &[u8; 148] = initiation[..148].try_into().unwrap();
        responder
            .consume_initiation(message)
            .expect("mac1 was computed over zeroed reserved bytes");
    }
}
