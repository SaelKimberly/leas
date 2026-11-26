//! `WireGuard` core as a whole: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.
//!
//! Everything here is sans-I/O. The pieces are
//! [`handshake`] (message encode/decode and the Noise transcript),
//! [`transport`] (the record layer: seal/open, reserved bytes, MACs, cookies,
//! replay window) and [`device`] (one peer's tunnel: timers, session rotation,
//! the payload queue). `device` is the only stateful entry point and it takes
//! `now: u64` on every call; nothing reads a clock or opens a socket.

pub mod device;
pub mod handshake;
pub mod transport;
