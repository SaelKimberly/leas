//! The `Noise_IKpsk2` handshake: initiation creation and response consumption.
//!
//! The transcript and every offset follow `wireguard-go/device/noise-protocol.go`
//! exactly; the constants are the same strings, and the message bodies are the
//! reference's fixed-size arrays rather than a variable codec, because every
//! field has one place and one meaning.
//!
//! The client is an **initiator** only. A responder exists under `#[cfg(test)]`
//! so the exchange can be driven end to end without a socket or a peer binary;
//! production interop is proven against sing-box/boringtun in `leas-oracles`.

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{AeadInOut, KeyInit as _};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroize;

use super::transport;
use super::transport::{
    INITIATION_SIZE, RESPONSE_SIZE, TYPE_INITIATION, TYPE_RESPONSE, check_mac1, set_mac1,
};
use crate::protocol::wireguard::kdf;
use crate::protocol::wireguard::keys::{KeyError, Secret, public_key, shared};

/// The Noise protocol name (also the initial chaining key's preimage).
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// The identifier mixed into the initial hash.
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// `H = BLAKE2s256(H ‖ data)`.
fn mix_hash(state: &mut [u8; 32], data: &[u8]) {
    let mut h = Blake2s256::new();
    h.update(&state[..]);
    h.update(data);
    *state = h.finalize().into();
}

/// `(chain, _) = KDF2(chain, data)`.
fn mix_key(chain: &mut [u8; 32], data: &[u8]) {
    let (next, _) = kdf::kdf2(chain, data);
    *chain = next;
}

fn initial_state() -> ([u8; 32], [u8; 32]) {
    let mut h = Blake2s256::new();
    h.update(CONSTRUCTION);
    let chain: [u8; 32] = h.finalize().into();
    let mut hash = chain;
    mix_hash(&mut hash, IDENTIFIER);
    (chain, hash)
}

/// TAI64 for `unix_secs`, the reference's base (`0x400000000000000A` = the
/// TAI64 epoch plus the leap-second offset) — **not** `1 << 62`.
#[must_use]
pub const fn tai64n_base(unix_secs: u64) -> u64 {
    0x4000_0000_0000_000A + unix_secs
}

/// TAI64N for an initiation's timestamp: the TAI64 label, big-endian, then
/// nanoseconds big-endian.
///
/// The reference's `timestamp.After(lastTimestamp)` check rejects a repeat, so
/// two initiations inside one second must still differ: the caller supplies
/// `nanos` (one per attempt is enough; it is not a clock).
#[must_use]
pub fn tai64n(unix_secs: u64, nanos: u32) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&tai64n_base(unix_secs).to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    out
}

/// Session keys derived from a completed handshake, both directions.
#[derive(Clone)]
pub struct SessionKeys {
    /// Key for records we send.
    pub send: [u8; 32],
    /// Key for records we receive.
    pub recv: [u8; 32],
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.send.zeroize();
        self.recv.zeroize();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Zeroed,
    InitiationCreated,
    ResponseConsumed,
}

/// The initiator's half of one handshake attempt.
pub struct Handshake {
    secret: Secret,
    public: [u8; 32],
    peer: [u8; 32],
    psk: Secret,
    precomputed_ss: [u8; 32],
    state: State,
    chain: [u8; 32],
    hash: [u8; 32],
    ephemeral: Secret,
    ephemeral_public: [u8; 32],
    local_index: u32,
    remote_index: u32,
    last_timestamp: [u8; 12],
}

impl std::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshake")
            .field("state", &self.state)
            .field("local_index", &self.local_index)
            .finish_non_exhaustive()
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.chain.zeroize();
        self.hash.zeroize();
        self.precomputed_ss.zeroize();
        self.last_timestamp.zeroize();
    }
}

impl Handshake {
    /// Build one peer's handshake state. Rejects a zero static-static secret,
    /// which is what a zero or low-order peer public key produces.
    pub fn new(
        secret: Secret,
        peer_public: [u8; 32],
        psk: Option<Secret>,
        local_index: u32,
    ) -> Result<Self, KeyError> {
        let precomputed_ss = shared(&secret, &peer_public)?;
        let (chain, hash) = initial_state();
        Ok(Self {
            public: public_key(&secret),
            secret,
            peer: peer_public,
            psk: psk.unwrap_or_else(|| zeroize::Zeroizing::new([0u8; 32])),
            precomputed_ss,
            state: State::Zeroed,
            chain,
            hash,
            ephemeral: zeroize::Zeroizing::new([0u8; 32]),
            ephemeral_public: [0u8; 32],
            local_index,
            remote_index: 0,
            last_timestamp: [0u8; 12],
        })
    }

    /// The local static public key (the key a `mac1` addressed to us is keyed
    /// by).
    #[must_use]
    pub const fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The local 32-bit handshake index the peer must echo.
    #[must_use]
    pub const fn local_index(&self) -> u32 {
        self.local_index
    }

    /// Create the initiation for `timestamp`, using a caller-supplied ephemeral
    /// secret so tests are deterministic.
    pub fn create_initiation(
        &mut self,
        timestamp: [u8; 12],
        ephemeral: &[u8; 32],
    ) -> [u8; INITIATION_SIZE] {
        let (mut chain, mut hash) = initial_state();
        mix_hash(&mut hash, &self.peer);

        let eph = zeroize::Zeroizing::new(crate::protocol::wireguard::keys::clamp(*ephemeral));
        self.ephemeral_public = public_key(&eph);

        let mut msg = [0u8; INITIATION_SIZE];
        msg[..4].copy_from_slice(&TYPE_INITIATION.to_le_bytes());
        msg[4..8].copy_from_slice(&self.local_index.to_le_bytes());
        msg[8..40].copy_from_slice(&self.ephemeral_public);

        mix_key(&mut chain, &self.ephemeral_public);
        mix_hash(&mut hash, &self.ephemeral_public);

        // static key, sealed under DH(e, S_peer)
        let ss = shared(&eph, &self.peer).expect("peer public key was validated in new()");
        let (next, key) = kdf::kdf2(&chain, &ss);
        chain = next;
        seal_into(&key, &hash, &self.public, &mut msg[40..88]);
        mix_hash(&mut hash, &msg[40..88]);

        // timestamp, sealed under the precomputed DH(s, S_peer)
        let (next, key) = kdf::kdf2(&chain, &self.precomputed_ss);
        chain = next;
        seal_into(&key, &hash, &timestamp, &mut msg[88..116]);
        mix_hash(&mut hash, &msg[88..116]);

        self.chain = chain;
        self.hash = hash;
        self.ephemeral = eph;
        self.state = State::InitiationCreated;
        // mac1 is keyed by the RECEIVER's static public key.
        set_mac1(&mut msg, &self.peer);
        msg
    }

    /// Consume the peer's response, yielding both transport keys.
    pub fn consume_response(&mut self, msg: &[u8; RESPONSE_SIZE]) -> Option<SessionKeys> {
        if self.state != State::InitiationCreated {
            return None;
        }
        if u32::from_le_bytes(msg[..4].try_into().ok()?) & 0xff != TYPE_RESPONSE {
            return None;
        }
        // The response is addressed to us: mac1 is keyed by OUR public key.
        let mut zeroed = *msg;
        transport::clear_reserved(&mut zeroed);
        if !check_mac1(&zeroed, &self.public) {
            return None;
        }
        let receiver = u32::from_le_bytes(zeroed[8..12].try_into().ok()?);
        if receiver != self.local_index {
            return None;
        }

        let mut hash = self.hash;
        let mut chain = self.chain;
        let ephemeral_peer: &[u8; 32] = zeroed[12..44].try_into().ok()?;
        mix_hash(&mut hash, ephemeral_peer);
        mix_key(&mut chain, ephemeral_peer);

        let ss = shared(&self.ephemeral, ephemeral_peer).ok()?;
        mix_key(&mut chain, &ss);
        let ss = shared(&self.secret, ephemeral_peer).ok()?;
        mix_key(&mut chain, &ss);

        let (next, tau, key) = kdf::kdf3(&chain, &self.psk[..]);
        chain = next;
        mix_hash(&mut hash, &tau);

        if !open_empty(&key, &hash, &zeroed[44..60]) {
            return None;
        }
        mix_hash(&mut hash, &zeroed[44..60]);

        let (send, recv) = kdf::kdf2(&chain, &[]);
        self.remote_index = u32::from_le_bytes(zeroed[4..8].try_into().ok()?);
        self.state = State::ResponseConsumed;
        self.hash = hash;
        self.chain = chain;
        Some(SessionKeys { send, recv })
    }

    /// The peer's handshake index, available after a response was consumed.
    #[must_use]
    pub const fn remote_index(&self) -> u32 {
        self.remote_index
    }

    /// Whether a session exists for this handshake attempt.
    #[must_use]
    pub fn completed(&self) -> bool {
        self.state == State::ResponseConsumed
    }
}

fn seal_into(key: &[u8; 32], aad: &[u8; 32], plaintext: &[u8], out: &mut [u8]) {
    out[..plaintext.len()].copy_from_slice(plaintext);
    let total = plaintext.len() + 16;
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(
            &Nonce::from([0u8; 12]),
            aad,
            (&mut out[..plaintext.len()]).into(),
        )
        .expect("seal of a handshake field cannot fail");
    out[plaintext.len()..total].copy_from_slice(tag.as_slice());
}

#[cfg(test)]
fn open_in_place(key: &[u8; 32], aad: &[u8; 32], sealed: &mut [u8]) -> Result<(), ()> {
    let tag_len = 16;
    if sealed.len() < tag_len {
        return Err(());
    }
    let split = sealed.len() - tag_len;
    let (message, tag_bytes) = sealed.split_at_mut(split);
    let tag =
        chacha20poly1305::aead::Tag::<ChaCha20Poly1305>::try_from(&*tag_bytes).map_err(|_| ())?;
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_inout_detached(&Nonce::from([0u8; 12]), aad, message.into(), &tag)
        .map_err(|_| ())
}

/// Open a 16-byte sealed empty payload (`msg.Empty`); the plaintext is empty,
/// so only the tag is checked.
fn open_empty(key: &[u8; 32], aad: &[u8; 32], sealed: &[u8]) -> bool {
    let cipher = ChaCha20Poly1305::new(key.into());
    let Ok(tag) = chacha20poly1305::aead::Tag::<ChaCha20Poly1305>::try_from(sealed) else {
        return false;
    };
    cipher
        .decrypt_inout_detached(&Nonce::from([0u8; 12]), aad, (&mut [][..]).into(), &tag)
        .is_ok()
}

/// A minimal responder used by the unit tests to drive a full exchange with no
/// socket. Production never constructs one (the client is an initiator).
#[cfg(test)]
#[allow(clippy::result_unit_err, clippy::ignored_unit_patterns)]
pub mod test_responder {
    use super::{IDENTIFIER, mix_hash, mix_key, open_in_place, seal_into};
    use crate::protocol::wireguard::core::transport::{
        RESPONSE_SIZE, TYPE_INITIATION, TYPE_RESPONSE, check_mac1, set_mac1,
    };
    use crate::protocol::wireguard::kdf;
    use crate::protocol::wireguard::keys::{Secret, public_key, shared};
    use blake2::{Blake2s256, Digest};
    use zeroize::Zeroize;

    /// The responder half, deliberately written against the same spec text as
    /// the initiator so an asymmetric mistake shows up as a key mismatch.
    pub struct Responder {
        secret: Secret,
        public: [u8; 32],
        peer: [u8; 32],
        psk: Secret,
        chain: [u8; 32],
        hash: [u8; 32],
        remote_index: u32,
        local_index: u32,
        peer_ephemeral: [u8; 32],
    }

    impl Responder {
        /// Build a responder that expects `peer_public` as its only peer.
        #[must_use]
        pub fn new(
            secret: Secret,
            peer_public: [u8; 32],
            psk: Option<Secret>,
            local_index: u32,
        ) -> Self {
            let mut h = Blake2s256::new();
            h.update(super::CONSTRUCTION);
            let chain: [u8; 32] = h.finalize().into();
            let mut hash = chain;
            mix_hash(&mut hash, IDENTIFIER);
            let public = public_key(&secret);
            Self {
                secret,
                public,
                peer: peer_public,
                psk: psk.unwrap_or_else(|| zeroize::Zeroizing::new([0u8; 32])),
                chain,
                hash,
                remote_index: 0,
                local_index,
                peer_ephemeral: [0u8; 32],
            }
        }

        /// Consume the initiator's message; `Ok` means it authenticated.
        pub fn consume_initiation(&mut self, msg: &[u8; 148]) -> Result<(), ()> {
            let mut msg = *msg;
            crate::protocol::wireguard::core::transport::clear_reserved(&mut msg);
            if u32::from_le_bytes(msg[..4].try_into().unwrap()) & 0xff != TYPE_INITIATION {
                return Err(());
            }
            if !check_mac1(&msg, &self.public) {
                return Err(());
            }
            let mut hash = {
                let mut h = self.hash;
                mix_hash(&mut h, &self.public);
                h
            };
            let eph: &[u8; 32] = msg[8..40].try_into().map_err(|_| ())?;
            mix_hash(&mut hash, eph);
            let mut chain = self.chain;
            mix_key(&mut chain, eph);

            let ss = shared(&self.secret, eph).map_err(|_| ())?;
            let (next, key) = kdf::kdf2(&chain, &ss);
            chain = next;
            let mut static_key = msg[40..88].to_vec();
            open_in_place(&key, &hash, &mut static_key).map_err(|_| ())?;
            let peer_static: [u8; 32] = static_key[..32].try_into().map_err(|_| ())?;
            if peer_static != self.peer {
                return Err(());
            }
            mix_hash(&mut hash, &msg[40..88]);

            let ss = shared(&self.secret, &peer_static).map_err(|_| ())?;
            let (next, key) = kdf::kdf2(&chain, &ss);
            chain = next;
            let mut timestamp = msg[88..116].to_vec();
            open_in_place(&key, &hash, &mut timestamp).map_err(|_| ())?;
            mix_hash(&mut hash, &msg[88..116]);

            self.remote_index = u32::from_le_bytes(msg[4..8].try_into().unwrap());
            self.peer_ephemeral.copy_from_slice(eph);
            self.chain = chain;
            self.hash = hash;
            Ok(())
        }

        /// Create the response for `now` with a caller-supplied ephemeral.
        pub fn create_response(&mut self, _now: u64, ephemeral: &[u8; 32]) -> [u8; RESPONSE_SIZE] {
            let eph = zeroize::Zeroizing::new(crate::protocol::wireguard::keys::clamp(*ephemeral));
            let eph_public = public_key(&eph);
            let mut msg = [0u8; RESPONSE_SIZE];
            msg[..4].copy_from_slice(&TYPE_RESPONSE.to_le_bytes());
            msg[4..8].copy_from_slice(&self.local_index.to_le_bytes());
            msg[8..12].copy_from_slice(&self.remote_index.to_le_bytes());
            msg[12..44].copy_from_slice(&eph_public);

            let mut hash = self.hash;
            let mut chain = self.chain;
            mix_hash(&mut hash, &eph_public);
            mix_key(&mut chain, &eph_public);
            // Three-way DH: e_resp·e_init, then e_resp·s_init.
            let ss = shared(&eph, &self.peer_ephemeral).unwrap();
            mix_key(&mut chain, &ss);
            let ss = shared(&eph, &self.peer).unwrap();
            mix_key(&mut chain, &ss);

            let (next, tau, key) = kdf::kdf3(&chain, &self.psk[..]);
            chain = next;
            mix_hash(&mut hash, &tau);
            seal_into(&key, &hash, &[], &mut msg[44..60]);
            mix_hash(&mut hash, &msg[44..60]);

            self.chain = chain;
            self.hash = hash;
            set_mac1(&mut msg, &self.peer);
            msg
        }

        /// `(recv, send)` for the responder: the initiator's send key is the
        /// responder's receive key.
        #[must_use]
        pub fn session_keys(&self) -> ([u8; 32], [u8; 32]) {
            kdf::kdf2(&self.chain, &[])
        }
    }

    impl Drop for Responder {
        fn drop(&mut self) {
            self.chain.zeroize();
            self.hash.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_responder::Responder;
    use super::*;
    use crate::protocol::wireguard::keys::{decode_private, public_key};

    /// A fixed key pair pair so the test is deterministic; RFC 7748 §6.1 keys.
    fn alice() -> Secret {
        decode_private("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap()
    }

    fn bob() -> Secret {
        decode_private("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").unwrap()
    }

    #[test]
    fn tai64n_carries_the_reference_label_and_nanos() {
        let t = tai64n(1_700_000_000, 7);
        assert_eq!(
            u64::from_be_bytes(t[..8].try_into().unwrap()),
            0x4000_0000_0000_000A + 1_700_000_000,
            "the base is the reference's TAI64 offset, not 1<<62"
        );
        assert_eq!(u32::from_be_bytes(t[8..].try_into().unwrap()), 7);
        assert_ne!(t, tai64n(1_700_000_000, 0), "same second, different nanos");
    }

    /// The initiation's fixed fields: type, sender index, and sizes the
    /// reference's marshal asserts (148 bytes, static at 40..88).
    #[test]
    fn initiation_layout_is_the_references() {
        let mut hs = Handshake::new(alice(), public_key(&bob()), None, 0x1234_5678).unwrap();
        let msg = hs.create_initiation(tai64n(10, 0), &[0x42; 32]);
        assert_eq!(msg.len(), 148);
        assert_eq!(
            u32::from_le_bytes(msg[..4].try_into().unwrap()),
            TYPE_INITIATION
        );
        assert_eq!(
            u32::from_le_bytes(msg[4..8].try_into().unwrap()),
            0x1234_5678
        );
        assert_eq!(&msg[8..40], &public_key(&[0x42; 32]));
        // mac1 is keyed by the peer's static public key.
        assert!(check_mac1(&msg, &public_key(&bob())));
        assert!(!check_mac1(&msg, &public_key(&alice())));
    }

    /// A tampered byte in the static field fails the tag before the transcript
    /// is touched.
    #[test]
    fn a_tampered_static_field_is_refused() {
        let mut hs = Handshake::new(alice(), public_key(&bob()), None, 1).unwrap();
        let mut msg = hs.create_initiation(tai64n(10, 0), &[7; 32]);
        let mut responder = Responder::new(bob(), public_key(&alice()), None, 9);
        msg[40] ^= 1;
        assert!(responder.consume_initiation(&msg).is_err());
    }
}
