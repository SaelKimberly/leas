//! Offline TLS fingerprint encoders (JA3/JA4).
//!
//! JA3 and JA4 are computed purely from `ClientHello` fields — no network
//! needed. They tripwire extension-order drift on every commit. The
//! authoritative grader check (tier 2, tls.peet.ws) ships with the
//! fingerprint engine milestone M2.

pub mod ja3;
pub mod ja4;

/// Draw 8 random bytes from `rng` as a little-endian `u64`.
///
/// Used for jitter values (e.g. the spider's padding-cookie size) where a
/// failed draw is indistinguishable from a zero: `rng.fill` only fails for
/// exotic RNG implementations, and callers modulo the result anyway.
#[must_use]
pub(crate) fn rand_u64(rng: &dyn crate::SecureRandom) -> u64 {
    let mut buf = [0u8; 8];
    if rng.fill(&mut buf).is_err() {
        return 0;
    }
    u64::from_le_bytes(buf)
}
