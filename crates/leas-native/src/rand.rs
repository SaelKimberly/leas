//! Buffered CSPRNG for non-secret randomness.
//!
//! The entropy source is unchanged — ring's [`SystemRandom`], i.e. one
//! `getrandom(2)` per fill — but a thread-local pool amortizes that syscall
//! over many draws. The hot consumers are per-packet, not per-connection:
//! hysteria2 draws an 8-byte Salamander salt for EVERY outbound datagram and
//! vision draws a padding length for every frame, so an unbuffered draw puts a
//! syscall on the datagram path.
//!
//! NEVER use this for key material. Key draws stay on a direct
//! `SystemRandom::fill` (VMess IV/body keys, the mlkem IV and X25519 seeds,
//! everything in `leas-tls`) so no key byte ever sits in a
//! process-lifetime buffer. What belongs here is wire-visible filler:
//! padding lengths and bytes, datagram salts, session/global ids.

use std::cell::RefCell;

use ring::rand::{SecureRandom, SystemRandom};

/// Pool size: 4 KiB is 512 hysteria2 salts, or ~1000 padding draws, per
/// `getrandom(2)`.
const POOL_LEN: usize = 4096;

thread_local! {
    /// `(pool, used)`: `pool[used..]` is CSPRNG output nobody has read yet.
    /// Starts fully consumed so the first draw refills. Boxed to keep 4 KiB
    /// out of the thread-local block itself.
    static POOL: RefCell<(Box<[u8; POOL_LEN]>, usize)> =
        RefCell::new((Box::new([0u8; POOL_LEN]), POOL_LEN));
}

/// Fill `out` with non-secret CSPRNG bytes.
///
/// # Panics
///
/// Panics if the system CSPRNG fails — the same contract every other draw in
/// this crate has: without `getrandom(2)` the process cannot produce padding,
/// salts or ids at all, and continuing with predictable filler is worse.
pub fn fill_nonsecret(out: &mut [u8]) {
    if out.len() >= POOL_LEN {
        // A draw at least as large as the pool would refill for nothing.
        SystemRandom::new().fill(out).expect("system rng failure");
        return;
    }
    POOL.with_borrow_mut(|(pool, used)| {
        if *used + out.len() > POOL_LEN {
            SystemRandom::new()
                .fill(pool.as_mut_slice())
                .expect("system rng failure");
            *used = 0;
        }
        out.copy_from_slice(&pool[*used..*used + out.len()]);
        *used += out.len();
    });
}

/// Rejection-sample `[0, bound)` from the pool — no modulo bias.
///
/// `bound` must be > 0 (debug-asserted; a zero bound would divide by zero).
pub fn u32_below(bound: u32) -> u32 {
    debug_assert!(bound > 0);
    // 2^32 % bound: samples below this threshold are rejected.
    let threshold = bound.wrapping_neg() % bound;
    loop {
        let mut buf = [0u8; 4];
        fill_nonsecret(&mut buf);
        let v = u32::from_le_bytes(buf);
        if v >= threshold {
            return v % bound;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{POOL_LEN, fill_nonsecret, u32_below};

    #[test]
    fn pool_refills_without_repeating() {
        // 1200 8-byte salts = 9600 bytes, more than two pool fills: a wrap
        // that forgets to refill would hand the same bytes out again.
        const DRAWS: usize = 1200;
        const { assert!(DRAWS * 8 > POOL_LEN * 2, "must cross two refills") };
        let mut seen = HashSet::new();
        for _ in 0..DRAWS {
            let mut salt = [0u8; 8];
            fill_nonsecret(&mut salt);
            assert!(seen.insert(salt), "repeated draw {salt:?}");
        }
    }

    #[test]
    fn draw_at_least_pool_sized_bypasses_the_pool() {
        let mut big = vec![0u8; POOL_LEN + 64];
        fill_nonsecret(&mut big);
        assert!(big.iter().any(|&b| b != 0), "buffer left untouched");
        // The pool must still work afterwards.
        let mut small = [0u8; 8];
        fill_nonsecret(&mut small);
        assert_ne!(small, [0u8; 8]);
    }

    #[test]
    fn u32_below_stays_in_range() {
        // bound = 1 is the edge case: threshold is 0, every sample accepted.
        for bound in [1u32, 2, 256, 500, 0xffff_ffff] {
            for _ in 0..256 {
                assert!(u32_below(bound) < bound, "bound {bound}");
            }
        }
    }
}
