//! Automatic TCP segment size for the proxy's own outbound connections.
//!
//! Iranian paths commonly carry less than 1500 bytes (PPPoE at 1492, mobile GTP
//! tunnels near 1400) while dropping the ICMP "fragmentation needed" replies
//! that path-MTU discovery depends on. The result is a black hole: the SYN and
//! the small ClientHello pass, the server's full-size certificate flight never
//! arrives, and the handshake times out with nothing to diagnose.
//!
//! Setting `TCP_MAXSEG` before connect lowers the MSS we advertise, so the
//! server never sends a segment larger than we can take. That costs a few bytes
//! of header per packet — 40 in 1360, under 3% — and nothing else: no probe
//! traffic, no allocation, one `setsockopt` per connection.
//!
//! The policy is two steps and only goes down:
//!
//! * [`SAFE_MSS`] from the start, which fits a 1400-byte path;
//! * [`FLOOR_MSS`] after [`STALLS_TO_DESCEND`] handshake stalls in a row with
//!   no useful connection between them, which fits a 1280-byte path (the IPv6
//!   minimum, which no working network goes below).
//!
//! There is no ascent within a process: leas has no network-change monitor to
//! hang one on, and a wrong ascent costs a dead handshake class while a wrong
//! descent costs about 1% header overhead. A restart is the re-arm.

use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

use crate::error::NativeError;

/// MSS for a 1400-byte path: 1400 minus 40 bytes of IPv4 and TCP header.
pub const SAFE_MSS: u16 = 1360;
/// MSS for a 1280-byte path under IPv6's 60 bytes of header, so one value fits
/// both families.
pub const FLOOR_MSS: u16 = 1220;
/// Consecutive handshake stalls, with no success between, before descending.
pub const STALLS_TO_DESCEND: u32 = 3;

static MSS: AtomicU16 = AtomicU16::new(SAFE_MSS);
static STALLS: AtomicU32 = AtomicU32::new(0);

/// The MSS new proxy connections advertise.
#[must_use]
pub fn current() -> u16 {
    MSS.load(Ordering::Relaxed)
}

/// A handshake stalled after the server was reached. Returns `true` when this
/// call lowered the advertised MSS.
pub fn note_stall() -> bool {
    let stalls = STALLS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    if stalls < STALLS_TO_DESCEND {
        return false;
    }
    MSS.try_update(Ordering::Relaxed, Ordering::Relaxed, |mss| {
        (mss > FLOOR_MSS).then_some(FLOOR_MSS)
    })
    .is_ok()
}

/// A handshake reached the other side: the current MSS works on this network,
/// so the stall run restarts.
pub fn note_success() {
    STALLS.store(0, Ordering::Relaxed);
}

/// Feed one connect attempt's handshake outcome to the policy.
///
/// Only a timeout counts as a stall: a refused or reset connection says nothing
/// about segment size, and counting it would descend on a server that is simply
/// down. The dial's own timeout is excluded upstream — the caller only reports
/// the stages after a dial succeeded.
pub fn note_outcome<T>(result: &Result<T, NativeError>) {
    match result {
        Ok(_) => note_success(),
        Err(NativeError::Timeout { .. }) => {
            note_stall();
        }
        Err(_) => {}
    }
}

#[cfg(test)]
pub fn reset_for_tests() {
    MSS.store(SAFE_MSS, Ordering::Relaxed);
    STALLS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn timeout() -> NativeError {
        NativeError::Timeout {
            step: "tls handshake",
            limit: Duration::from_secs(10),
        }
    }

    #[test]
    fn starts_at_the_safe_mss() {
        reset_for_tests();
        assert_eq!(current(), SAFE_MSS);
    }

    #[test]
    fn three_stalls_descend_and_the_floor_holds() {
        reset_for_tests();
        assert!(!note_stall(), "one stall is not enough");
        assert!(!note_stall(), "two stalls are not enough");
        assert!(note_stall(), "the third stall descends");
        assert_eq!(current(), FLOOR_MSS);
        assert!(!note_stall(), "already at the floor");
        assert_eq!(current(), FLOOR_MSS);
    }

    #[test]
    fn a_success_restarts_the_run() {
        reset_for_tests();
        note_stall();
        note_stall();
        note_success();
        assert!(
            !note_stall(),
            "the run restarted, so this is the first stall"
        );
        assert_eq!(current(), SAFE_MSS);
    }

    #[test]
    fn only_timeouts_count_as_stalls() {
        reset_for_tests();
        note_outcome(&Err::<(), _>(timeout()));
        note_outcome(&Err::<(), _>(timeout()));
        // A refused connection says nothing about segment size. If it counted,
        // the next timeout would be the third event and would descend; it must
        // leave the run at two.
        note_outcome(&Err::<(), _>(NativeError::Dial("refused".into())));
        assert_eq!(current(), SAFE_MSS);
        note_outcome(&Err::<(), _>(timeout()));
        assert_eq!(current(), FLOOR_MSS);
    }

    #[test]
    fn an_ok_outcome_resets() {
        reset_for_tests();
        note_outcome(&Err::<(), _>(timeout()));
        note_outcome(&Err::<(), _>(timeout()));
        note_outcome(&Ok::<(), NativeError>(()));
        note_outcome(&Err::<(), _>(timeout()));
        assert_eq!(current(), SAFE_MSS);
    }
}
