//! TLS 1.3 client engine with browser fingerprint mimicry and REALITY support.
//!
//! This crate provides a ring-based TLS 1.3 client that emulates real browsers,
//! including JA3 fingerprinting, TLS record and handshake handling, certificate
//! verification, and REALITY protocol integration.

// The crypto/TLS engine holds no `unsafe`: every primitive is ring/RustCrypto,
// and the engine owns no raw-pointer or FFI surface. Forbidding it here keeps
// that true — a future edit cannot add hand-rolled unsafe to the crypto core
// silently (a genuine need would move the code out of this crate instead).
#![forbid(unsafe_code)]

pub mod fingerprints;
pub mod profiles;
pub mod spec;
pub use fingerprints::{
    Browser, Device, Fingerprint, FingerprintBuilder, FingerprintError, GreasePolicy, Os, Resolved,
};
pub mod client;
pub mod crypto;
pub mod handshake;
pub mod hello;
pub mod http2;
pub mod reality;
pub mod record;
pub mod verify;

pub mod error;

/// Byte-stream seam: everything the engine touches is generic over this.
pub trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}

/// Random-byte source for the engine.
///
/// ring's `SecureRandom` is a sealed trait (ring 0.17.13+), so a
/// deterministic test double cannot implement it. This crate-local seam
/// mirrors ring's shape and is blanket-implemented for everything ring's
/// `SecureRandom` accepts: production passes `ring::rand::SystemRandom`,
/// tests pass fixed-seed RNGs. All engine code that draws randomness takes
/// `&dyn SecureRandom`.
pub trait SecureRandom: Send + Sync {
    /// Fills `dest` with random bytes.
    fn fill(&self, dest: &mut [u8]) -> Result<(), ring::error::Unspecified>;
}

impl<T> SecureRandom for T
where
    T: ring::rand::SecureRandom + Send + Sync,
{
    fn fill(&self, dest: &mut [u8]) -> Result<(), ring::error::Unspecified> {
        ring::rand::SecureRandom::fill(self, dest)
    }
}
