//! mKCP session core: windows, RTO/RTT, timers, state machine (spec
//! §4.2-§4.5, §5.2).
//!
//! Authority: `thirdparty/Xray-core/transport/internet/kcp/` — `connection.go`
//! (states + `flush` + `Input` + updaters), `sending.go` (send window,
//! RTO-driven retransmit, fast-resend, congestion), `receiving.go` (recv
//! window + ack list), `config.go` (window-size formulas). All wraparound
//! arithmetic is `u32` wrapping with the Go `0x7FFFFFFF` signed checks —
//! interop-critical.
//!
//! Design notes (documented decisions):
//! - Time is injected: every state-machine method takes `current` — elapsed
//!   milliseconds since session creation (Go `Elapsed()`). The machine is
//!   pure and fully deterministic under test; only the async driver
//!   ([`drive`]) reads the real clock.
//! - The two Go updater goroutines collapse into one task ([`drive`], spec
//!   §8 deviation 2) with the same wake/stop conditions: an immediate first
//!   flush (Go's `pingUpdater.WakeUp()` at connect), then a ping tick every
//!   5s (1s during the terminate handshake) and a `tti` data tick while the
//!   send window or ack list is nonempty. Flush wakeups from
//!   write/input/close arrive via a `Notify` plus a sequence counter that
//!   closes the lost-wakeup race (notify while the driver is not waiting).
//! - `dataInput`/`dataOutput` use `notify_one`, whose stored-notification
//!   latch prevents the classic check-then-wait lost wakeup for the single
//!   reader/writer (Go's notifier drops signals with no waiter and recovers
//!   by re-checking after its 16s timer; the latch makes the Rust wait
//!   strict).
//! - The send window is an insertion-ordered deque of `(sn, entry)` (Go's
//!   `container/list`) — insertion order == transmission order, which
//!   survives u32 wraparound that an ordered map would misorder.
//! - Go's `fastResend` field (set to 2) is never read — dead in upstream;
//!   the fast-resend threshold is `rto / 3` (`HandleFastAck`). Not ported.
//! - `cwnd_multiplier` is fixed at 1 (xray default; the native params expose
//!   only mtu/tti, spec §4.5), so the ×multiplier step is a no-op.
//! - Output write errors during `flush` are swallowed, exactly like Go (the
//!   workers ignore `writer.Write` errors); socket failures surface through
//!   the recv side (spec §6).
//! - `close()` wakes the driver, so the terminate handshake starts
//!   immediately; Go relies on the ping updater's next tick (≤5s). Same wire
//!   sequence, tighter teardown.
//! - A session abandoned without `close()` self-terminates: the 30s idle
//!   guard closes it, and the terminate handshake reaches `Terminated` ~8s
//!   later, where the driver exits.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskCx, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::{Mutex, MutexGuard};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::wire::{
    Command, DATA_SEGMENT_OVERHEAD, Segment, SegmentOption, encode_segment, parse_datagram,
};

/// mKCP connection state (Go `State`, connection.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// Connection is active.
    Active = 0,
    /// Connection is closed locally.
    ReadyToClose = 1,
    /// Connection is closed on remote.
    PeerClosed = 2,
    /// Connection is ready to be destroyed locally.
    Terminating = 3,
    /// Connection is ready to be destroyed on remote.
    PeerTerminating = 4,
    /// Connection is destroyed.
    Terminated = 5,
}

impl State {
    /// Read returns EOF immediately in these states, BEFORE draining the
    /// receive window (Go `Connection.Read` checks first) — buffered data is
    /// discarded on a local close.
    const fn read_eof_immediate(self) -> bool {
        matches!(
            self,
            Self::ReadyToClose | Self::Terminating | Self::Terminated
        )
    }

    /// The ping tick runs at 1s during the terminate handshake (Go
    /// `SetState` shortens the ping updater interval).
    const fn is_terminating(self) -> bool {
        matches!(self, Self::Terminating | Self::PeerTerminating)
    }
}

const UPLINK_MBPS: u32 = 5;
const DOWNLINK_MBPS: u32 = 20;
const MAX_SENDING_WINDOW: u32 = 2 * 1024 * 1024;
/// Go `ackNumberLimit`: the ack count is a single wire byte, and the
/// per-ack list is additionally capped at 128 numbers.
const ACK_NUMBER_LIMIT: usize = 128;
/// Go `NewConnection`: the first ping fires after this many ms of silence.
const PING_INTERVAL_MS: u32 = 3000;
/// Go `flush`: the idle guard — no incoming datagram for 30s closes the
/// session (matches xray; the e2e timeout is shorter anyway).
const IDLE_CLOSE_MS: u32 = 30_000;
/// Go `flush` state timers.
const TERMINATING_MS: u32 = 8000;
const PEER_TERMINATING_MS: u32 = 4000;
const READY_TO_CLOSE_MS: u32 = 15_000;
/// Go `ProcessSegment`: an ack echo older than this is not an RTT sample.
const RTT_SAMPLE_MS: u32 = 10_000;

/// mKCP settings derived from mtu/tti per spec §4.5 (Go config.go formulas).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KcpSettings {
    /// UDP payload size bound for one datagram (default 1350).
    pub mtu: usize,
    /// Data-tick interval in ms (default 50).
    pub tti: u32,
    /// Sending in-flight size (uplink-derived), Go `GetSendingInFlightSize`.
    pub snd_inflight: u32,
    /// Receiving in-flight size (downlink-derived), Go `GetReceivingInFlightSize`.
    pub rcv_inflight: u32,
    /// Send-window capacity (`max_sending_window / mtu`), Go `GetSendingBufferSize`.
    pub snd_buf: u32,
    /// Max payload per Data segment (`mtu - 18`).
    pub mss: usize,
}

impl KcpSettings {
    /// Defaults (spec §4.5): uplink 5 Mbps, downlink 20 Mbps,
    /// `cwnd_multiplier` 1, `max_sending_window` 2 MiB.
    ///
    /// Note: the Go formulas yield `rcv_inflight = 776` for the defaults
    /// (20 MiB/s ÷ 1350 B ÷ 20 ticks/s), not the spec text's 777 — the Go
    /// formula is authoritative here.
    #[must_use]
    pub fn new(mtu: usize, tti: u32) -> Self {
        let mtu = mtu.max(DATA_SEGMENT_OVERHEAD + 1);
        let mtu_u32 = u32::try_from(mtu).unwrap_or(u32::MAX);
        let ticks = (1000 / tti.max(1)).max(1);
        let snd_inflight = (UPLINK_MBPS * 1024 * 1024 / mtu_u32 / ticks).max(8);
        let rcv_inflight = (DOWNLINK_MBPS * 1024 * 1024 / mtu_u32 / ticks).max(8);
        let snd_buf = MAX_SENDING_WINDOW / mtu_u32;
        Self {
            mtu,
            tti,
            snd_inflight,
            rcv_inflight,
            snd_buf,
            mss: mtu - DATA_SEGMENT_OVERHEAD,
        }
    }
}

/// RFC 6298-style RTT estimator (Go `RoundTripInfo`, connection.go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoundTripInfo {
    variation: u32,
    srtt: u32,
    rto: u32,
    min_rtt: u32,
    updated_ts: u32,
}

impl RoundTripInfo {
    /// New estimator: `rto = 100`, `min_rtt = tti` (Go `NewConnection`).
    const fn new(min_rtt: u32) -> Self {
        Self {
            variation: 0,
            srtt: 0,
            rto: 100,
            min_rtt,
            updated_ts: 0,
        }
    }

    /// Adopt the peer's RTO when at least 3000ms since the last RTO update
    /// (Go `UpdatePeerRTO`; `updatedTimestamp` is shared with [`Self::update`]).
    const fn update_peer_rto(&mut self, rto: u32, current: u32) {
        if current.wrapping_sub(self.updated_ts) < 3000 {
            return;
        }
        self.updated_ts = current;
        self.rto = rto;
    }

    /// RFC 6298 sample (Go `Update`): first sample sets `srtt = rtt`,
    /// `variation = rtt / 2`; later samples smooth both, clamp `srtt` up to
    /// `min_rtt`, then `rto = srtt + 4v` (or `+v` when `4v <= min_rtt`),
    /// capped at 10000 and scaled `×5/4`. Samples above `0x7FFFFFFF` are
    /// rejected (Go's signed check).
    fn update(&mut self, rtt: u32, current: u32) {
        if rtt > 0x7FFF_FFFF {
            return;
        }
        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            let delta = self.srtt.abs_diff(rtt);
            // Go's plain uint32 arithmetic wraps here (RFC 6298 assumes no
            // overflow; pathological RTTs must not panic in Rust debug).
            self.variation = self.variation.wrapping_mul(3).wrapping_add(delta) / 4;
            self.srtt = self.srtt.wrapping_mul(7).wrapping_add(rtt) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }
        let rto = if self.min_rtt < 4 * self.variation {
            self.srtt.wrapping_add(4 * self.variation)
        } else {
            self.srtt.wrapping_add(self.variation)
        };
        let rto = rto.min(10_000);
        self.rto = rto * 5 / 4;
        self.updated_ts = current;
    }

    /// The current retransmit timeout (Go `Timeout`).
    #[must_use]
    const fn timeout(&self) -> u32 {
        self.rto
    }
}

/// One queued Data segment in the send window (Go `DataSegment`'s
/// timeout/transmit/timestamp bookkeeping).
#[derive(Debug)]
struct SendEntry {
    payload: Bytes,
    timeout: u32,
    transmit: u32,
    ts: u32,
}

/// A Data segment to write; the session injects conv/opt/una.
#[derive(Debug)]
struct OutData {
    sn: u32,
    ts: u32,
    payload: Bytes,
}

/// Send window: insertion-ordered `sn → entry` (Go `SendingWindow`'s
/// `container/list`). Insertion order == transmission order, which survives
/// u32 wraparound that an ordered map would misorder.
#[derive(Debug, Default)]
struct SendWindow {
    entries: VecDeque<(u32, SendEntry)>,
    total_in_flight: u32,
}

impl SendWindow {
    #[must_use]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Go `FirstNumber` (callers guarantee a non-empty window).
    #[must_use]
    fn first_number(&self) -> u32 {
        self.entries.front().map_or(0, |(sn, _)| *sn)
    }

    fn push_back(&mut self, sn: u32, entry: SendEntry) {
        self.entries.push_back((sn, entry));
    }

    /// Go `Clear`: drop segments from the front while `number < una`
    /// (plain comparison, replicated — Go stops at the first `>= una`).
    fn clear(&mut self, una: u32) {
        while let Some((sn, _)) = self.entries.front() {
            if *sn >= una {
                break;
            }
            self.entries.pop_front();
        }
    }

    /// Go `Remove`: walk from the front, stop at the first `sn > number`.
    /// Returns whether the segment was found and removed.
    fn remove(&mut self, number: u32) -> bool {
        for (i, (sn, _)) in self.entries.iter().enumerate() {
            if *sn > number {
                return false;
            }
            if *sn == number {
                self.entries.remove(i);
                if self.total_in_flight > 0 {
                    self.total_in_flight -= 1;
                }
                return true;
            }
        }
        false
    }

    /// Go `HandleFastAck`: for every segment with `sn < number` (wrap-correct)
    /// that has been transmitted, pull its timeout forward by `rto / 3`.
    fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        if self.entries.is_empty() {
            return;
        }
        let threshold = rto / 3;
        for (sn, entry) in &mut self.entries {
            if number == *sn || number.wrapping_sub(*sn) > 0x7FFF_FFFF {
                break;
            }
            if entry.transmit > 0 && entry.timeout > threshold {
                entry.timeout -= threshold;
            }
        }
    }

    /// Go `SendingWindow.Flush`: (re)transmit due segments in order, at most
    /// `cwnd` of them; a segment is due when `current - timeout` did not
    /// wrap (i.e. its timeout has passed — `>= 0x7FFFFFFF` means the timeout
    /// is still in the future and the segment is skipped). Returns the
    /// segments to send plus the retransmit accounting.
    fn flush(&mut self, current: u32, rto: u32, cwnd: u32) -> (Vec<OutData>, u32, u32) {
        if self.entries.is_empty() {
            return (Vec::new(), 0, 0);
        }
        let mut out = Vec::new();
        let mut lost = 0u32;
        let mut in_flight = 0u32;
        for (sn, entry) in &mut self.entries {
            if current.wrapping_sub(entry.timeout) >= 0x7FFF_FFFF {
                continue; // not yet due
            }
            if entry.transmit == 0 {
                // First transmission.
                self.total_in_flight += 1;
            } else {
                lost += 1;
            }
            entry.timeout = current.wrapping_add(rto);
            entry.ts = current;
            entry.transmit += 1;
            out.push(OutData {
                sn: *sn,
                ts: current,
                payload: entry.payload.clone(), // Bytes: cheap refcount bump
            });
            in_flight += 1;
            if in_flight >= cwnd {
                break;
            }
        }
        (out, lost, in_flight)
    }
}

/// Send half: window + congestion + ack processing (Go `SendingWorker`).
#[derive(Debug)]
pub(crate) struct SendingWorker {
    window: SendWindow,
    first_unacked: u32,
    next_sn: u32,
    /// Peer's advertised receive window edge (`remoteNextNumber`, init 32).
    remote_rcv_nxt: u32,
    control_window: u32,
    window_size: u32,
    snd_inflight: u32,
    first_unacked_updated: bool,
}

impl SendingWorker {
    fn new(settings: &KcpSettings) -> Self {
        Self {
            window: SendWindow::default(),
            first_unacked: 0,
            next_sn: 0,
            remote_rcv_nxt: 32,
            control_window: settings.snd_inflight,
            window_size: settings.snd_buf,
            snd_inflight: settings.snd_inflight,
            first_unacked_updated: false,
        }
    }

    #[must_use]
    fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    #[must_use]
    const fn first_unacked(&self) -> u32 {
        self.first_unacked
    }

    /// Go `Push`: queue one segment. Rejects when the window already holds
    /// more than `window_size` entries (Go's `Len() > windowSize` quirk lets
    /// the window transiently hold `window_size + 1`). Empty payloads are
    /// accepted as a no-op success — the Go write path can never push one
    /// (its reader hits EOF first), and an empty Data segment is rejected on
    /// the wire (T1, Go quirk).
    fn push(&mut self, payload: Bytes) -> bool {
        if payload.is_empty() {
            return true;
        }
        if u32::try_from(self.window.len()).unwrap_or(u32::MAX) > self.window_size {
            return false;
        }
        let sn = self.next_sn;
        self.window.push_back(
            sn,
            SendEntry {
                payload,
                timeout: 0,
                transmit: 0,
                ts: 0,
            },
        );
        self.next_sn = self.next_sn.wrapping_add(1);
        true
    }

    /// Go `ProcessReceivingNext`: clear everything below the peer's
    /// `rcv_nxt` and recompute the first unacknowledged number.
    fn clear_up_to(&mut self, una: u32) {
        self.window.clear(una);
        self.find_first_unacked();
    }

    fn find_first_unacked(&mut self) {
        let first = self.first_unacked;
        self.first_unacked = if self.window.is_empty() {
            self.next_sn
        } else {
            self.window.first_number()
        };
        if first != self.first_unacked {
            self.first_unacked_updated = true;
        }
    }

    /// Go `processAck`: valid iff `number ∈ [first_unacked, next_sn)` in
    /// wrap terms; removes the segment and updates `first_unacked`.
    fn process_ack(&mut self, number: u32) -> bool {
        if number.wrapping_sub(self.first_unacked) > 0x7FFF_FFFF {
            return false;
        }
        if number.wrapping_sub(self.next_sn) < 0x7FFF_FFFF {
            return false;
        }
        if self.window.remove(number) {
            self.find_first_unacked();
            return true;
        }
        false
    }

    /// Go `ProcessSegment` on an Ack segment: advance the remote window and
    /// clear below `rcv_nxt`, then process each acked number. When the max
    /// acked number was actually removed: fast-resend (`HandleFastAck`) and,
    /// if the echo is fresh (`current - ack.ts < 10000`), return the RTT
    /// sample for the session's estimator.
    fn process_ack_segment(
        &mut self,
        current: u32,
        ack_rcv_wnd: u32,
        ack_rcv_nxt: u32,
        numbers: &[u32],
        ack_ts: u32,
        rto: u32,
    ) -> Option<u32> {
        if self.remote_rcv_nxt < ack_rcv_wnd {
            self.remote_rcv_nxt = ack_rcv_wnd;
        }
        self.clear_up_to(ack_rcv_nxt);
        if numbers.is_empty() {
            return None;
        }
        let mut maxack = 0u32;
        let mut maxack_removed = false;
        for &number in numbers {
            let removed = self.process_ack(number);
            if maxack < number {
                maxack = number;
                maxack_removed = removed;
            }
        }
        if !maxack_removed {
            return None;
        }
        self.window.handle_fast_ack(maxack, rto);
        let rtt = current.wrapping_sub(ack_ts);
        (rtt < RTT_SAMPLE_MS).then_some(rtt)
    }

    /// Go `SendingWorker.Flush`: `cwnd = min(snd_inflight,
    /// remote_rcv_nxt - first_unacked, control_window)` (the
    /// `cwnd_multiplier` of 1 is a no-op), then flush the window. Returns
    /// whether `first_unacked` moved (the session then sends a Ping so the
    /// peer learns the new `una` promptly).
    fn flush(&mut self, current: u32, rto: u32) -> (Vec<OutData>, bool) {
        let avail = self.remote_rcv_nxt.wrapping_sub(self.first_unacked);
        let cwnd = self.snd_inflight.min(avail).min(self.control_window);
        let (out, lost, in_flight) = self.window.flush(current, rto, cwnd);
        if in_flight > 0 && self.window.total_in_flight != 0 {
            let rate = lost * 100 / self.window.total_in_flight;
            self.on_packet_loss(rate, rto);
        }
        let updated = self.first_unacked_updated;
        self.first_unacked_updated = false;
        (out, updated)
    }

    /// Go `OnPacketLoss`: loss rate ≥15% shrinks the control window ×3/4,
    /// ≤5% grows it +1/4; floor 16, cap `snd_inflight`. A zero RTO skips the
    /// adjustment (Go checks `roundTrip.Timeout() == 0`).
    const fn on_packet_loss(&mut self, rate: u32, rto: u32) {
        if rto == 0 {
            return;
        }
        if rate >= 15 {
            self.control_window = 3 * self.control_window / 4;
        }
        if rate <= 5 {
            self.control_window += self.control_window / 4;
        }
        if self.control_window < 16 {
            self.control_window = 16;
        }
        if self.control_window > self.snd_inflight {
            self.control_window = self.snd_inflight;
        }
    }

    /// Go `CloseWrite`: discard every queued segment (state leaves Active).
    fn close_write(&mut self) {
        self.window.entries.clear();
    }
}

/// An Ack segment to write; the session injects `conv`/`opt`/`rcv_wnd`/
/// `rcv_nxt`.
#[derive(Debug)]
struct OutAck {
    numbers: Vec<u32>,
    /// The latest (wrap-forward) timestamp echo among the batch — Go
    /// `AckSegment.PutTimestamp` keeps the max.
    ts: u32,
}

/// Ack list: per-number due times + flush candidates (Go `AckList`).
#[derive(Debug)]
pub(crate) struct AckList {
    numbers: VecDeque<u32>,
    timestamps: VecDeque<u32>,
    next_flush: VecDeque<u32>,
    dirty: bool,
    limit: usize,
}

impl AckList {
    const fn new(limit: usize) -> Self {
        Self {
            numbers: VecDeque::new(),
            timestamps: VecDeque::new(),
            next_flush: VecDeque::new(),
            dirty: false,
            limit,
        }
    }

    #[must_use]
    fn is_empty(&self) -> bool {
        self.numbers.is_empty()
    }

    /// Go `Add`, but bounded and duplicate-free.
    ///
    /// Go pushes unconditionally, so a peer that replays one in-window Data
    /// segment grows the list by one entry per datagram and the `clear` scan
    /// runs over the whole list each time — quadratic total, attacker-chosen
    /// memory (finding f7). The receive window already dedups the same `sn`
    /// (`window.entry(sn).or_insert`), so an `sn` already queued for
    /// acknowledgement is skipped, and the list is capped at the receive
    /// window size (`cap = rcv_inflight`).
    fn add(&mut self, number: u32, timestamp: u32, cap: usize) {
        if self.numbers.contains(&number) {
            return; // this sn is already queued for acknowledgement
        }
        while self.numbers.len() >= cap.max(1) {
            self.numbers.pop_front();
            self.timestamps.pop_front();
            self.next_flush.pop_front();
        }
        self.numbers.push_back(number);
        self.timestamps.push_back(timestamp);
        self.next_flush.push_back(0);
        self.dirty = true;
    }

    /// Go `Clear`: drop numbers `< una` (plain comparison, replicated).
    fn clear(&mut self, una: u32) {
        let mut count = 0;
        for i in 0..self.numbers.len() {
            if self.numbers[i] < una {
                continue;
            }
            if i != count {
                self.numbers[count] = self.numbers[i];
                self.timestamps[count] = self.timestamps[i];
                self.next_flush[count] = self.next_flush[i];
            }
            count += 1;
        }
        if count < self.numbers.len() {
            self.numbers.truncate(count);
            self.timestamps.truncate(count);
            self.next_flush.truncate(count);
            self.dirty = true;
        }
    }

    /// Go `AckList.Flush`: batch due numbers into acks of up to `limit`
    /// (128), advancing each due number's next flush to
    /// `current + max(rto/2, 20)`; not-yet-due numbers become flush
    /// candidates that ride along when the final batch is written for
    /// another reason. A batch is written when it is nonempty OR the list
    /// is dirty — the latter reproduces Go's header-only ack.
    fn flush(&mut self, current: u32, rto: u32) -> Vec<OutAck> {
        let mut candidates: Vec<u32> = Vec::new();
        let mut out: Vec<OutAck> = Vec::new();
        let mut batch: Vec<u32> = Vec::with_capacity(self.limit);
        let mut batch_ts = 0u32;
        for i in 0..self.numbers.len() {
            if self.next_flush[i] > current {
                if candidates.len() < self.limit {
                    candidates.push(self.numbers[i]);
                }
                continue;
            }
            batch.push(self.numbers[i]);
            let ts = self.timestamps[i];
            if ts.wrapping_sub(batch_ts) < 0x7FFF_FFFF {
                batch_ts = ts;
            }
            let timeout = (rto / 2).max(20);
            self.next_flush[i] = current.wrapping_add(timeout);
            if batch.len() >= self.limit {
                out.push(OutAck {
                    numbers: std::mem::take(&mut batch),
                    ts: batch_ts,
                });
                batch_ts = 0;
                self.dirty = false;
            }
        }
        if self.dirty || !batch.is_empty() {
            for &number in &candidates {
                if batch.len() >= self.limit {
                    break;
                }
                batch.push(number);
            }
            out.push(OutAck {
                numbers: batch,
                ts: batch_ts,
            });
            self.dirty = false;
        }
        out
    }
}

/// Receive half: window + reassembly + ack list (Go `ReceivingWorker`).
#[derive(Debug)]
pub(crate) struct ReceivingWorker {
    window: HashMap<u32, Bytes>,
    acklist: AckList,
    next_number: u32,
    window_size: u32,
    left_over: Option<Bytes>,
}

impl ReceivingWorker {
    fn new(settings: &KcpSettings) -> Self {
        // Go NewAckList receives `kcp.mss + DataSegmentOverhead` = mtu, so
        // the batch limit is `(mtu - 17) / 4`, capped by ackNumberLimit 128.
        let limit = (settings.mtu.saturating_sub(17) / 4).clamp(1, ACK_NUMBER_LIMIT);
        Self {
            window: HashMap::new(),
            acklist: AckList::new(limit),
            next_number: 0,
            window_size: settings.rcv_inflight,
            left_over: None,
        }
    }

    #[must_use]
    const fn next_number(&self) -> u32 {
        self.next_number
    }

    #[must_use]
    const fn window_size(&self) -> u32 {
        self.window_size
    }

    #[must_use]
    fn is_data_available(&self) -> bool {
        self.window.contains_key(&self.next_number)
    }

    #[must_use]
    fn acklist_nonempty(&self) -> bool {
        !self.acklist.is_empty()
    }

    /// Go `ProcessSendingNext`: drop acked numbers from the ack list.
    fn clear_acklist(&mut self, una: u32) {
        self.acklist.clear(una);
    }

    /// Go `ProcessSegment` on a Data segment: drop when
    /// `sn - next_number` (wrapping) is at or beyond the window; otherwise
    /// clear the ack list below `una`, record (sn, ts), and store the
    /// payload — the first copy wins, a duplicate drops the incoming bytes.
    fn process_data(&mut self, sn: u32, ts: u32, una: u32, payload: Bytes) {
        let idx = sn.wrapping_sub(self.next_number);
        if idx >= self.window_size {
            return; // out of window → drop (never acked, like Go)
        }
        self.acklist.clear(una);
        // Cap the ack list by the receive window (rcv_inflight): state derived
        // from received segments must be bounded by the window, not the peer's
        // cumulative datagram count (finding f7).
        let cap = usize::try_from(self.window_size).unwrap_or(usize::MAX);
        self.acklist.add(sn, ts, cap);
        self.window.entry(sn).or_insert(payload);
    }

    /// Drain consecutive payloads into `buf` (Go `ReadMultiBuffer` + `Read`):
    /// leftover from a previous short read first, then window segments from
    /// `next_number` upward. Returns bytes copied; 0 = nothing ready.
    fn read_available(&mut self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        let mut used = 0;
        if let Some(lo) = self.left_over.take() {
            let take = lo.len().min(buf.len());
            buf[..take].copy_from_slice(&lo[..take]);
            used += take;
            if take < lo.len() {
                self.left_over = Some(Bytes::copy_from_slice(&lo[take..]));
                return used;
            }
        }
        while used < buf.len() {
            let Some(payload) = self.window.remove(&self.next_number) else {
                break;
            };
            self.next_number = self.next_number.wrapping_add(1);
            let take = payload.len().min(buf.len() - used);
            buf[used..used + take].copy_from_slice(&payload[..take]);
            used += take;
            if take < payload.len() {
                self.left_over = Some(Bytes::copy_from_slice(&payload[take..]));
                break;
            }
        }
        used
    }

    /// Go `ReceivingWorker.Flush`: flush the ack list.
    fn flush(&mut self, current: u32, rto: u32) -> Vec<OutAck> {
        self.acklist.flush(current, rto)
    }
}

/// The UDP send path: one call per datagram (injected by the dialer, T4).
type OutputSender = Box<dyn FnMut(&[u8]) -> io::Result<()> + Send>;

/// The mKCP session state machine (Go `Connection`, minus the updater
/// goroutines — those collapse into one async driver, spec §8 deviation 2).
///
/// Every time-sensitive method takes `current`: elapsed milliseconds since
/// session creation (Go `Elapsed()`), so the machine is fully deterministic
/// under test.
pub(crate) struct SessionCore {
    conv: u16,
    state: State,
    state_begin: u32,
    last_incoming: u32,
    last_ping: u32,
    tti: u32,
    mss: usize,
    round_trip: RoundTripInfo,
    sending: SendingWorker,
    receiving: ReceivingWorker,
    output: OutputSender,
    since: Instant,
    data_input: Arc<Notify>,
    data_output: Arc<Notify>,
    /// Waker registered by the stream adapter's `poll_read` when no data is
    /// available; woken alongside `data_input` (T4 stream adapter).
    read_waker: Option<Waker>,
    /// Waker registered by the stream adapter's `poll_write` when the send
    /// window is full; woken alongside `data_output` (T4 stream adapter).
    write_waker: Option<Waker>,
    flush_seq: AtomicU64,
    flush_wake: Arc<Notify>,
}

impl SessionCore {
    fn new(conv: u16, settings: KcpSettings, output: OutputSender) -> Self {
        Self {
            conv,
            state: State::Active,
            state_begin: 0,
            last_incoming: 0,
            last_ping: 0,
            tti: settings.tti,
            mss: settings.mss,
            round_trip: RoundTripInfo::new(settings.tti),
            sending: SendingWorker::new(&settings),
            receiving: ReceivingWorker::new(&settings),
            output,
            since: Instant::now(),
            data_input: Arc::new(Notify::new()),
            data_output: Arc::new(Notify::new()),
            read_waker: None,
            write_waker: None,
            flush_seq: AtomicU64::new(0),
            flush_wake: Arc::new(Notify::new()),
        }
    }

    /// Real elapsed milliseconds (used by the driver; tests pass synthetic
    /// `current` values directly).
    #[must_use]
    fn elapsed(&self) -> u32 {
        u32::try_from(self.since.elapsed().as_millis()).unwrap_or(u32::MAX)
    }

    #[must_use]
    const fn state(&self) -> State {
        self.state
    }

    #[must_use]
    const fn is_terminated(&self) -> bool {
        matches!(self.state, State::Terminated)
    }

    /// Ping tick interval: 5s normally, 1s during the terminate handshake
    /// (Go `SetState` shortens the ping updater interval).
    #[must_use]
    const fn ping_interval(&self) -> Duration {
        if self.state.is_terminating() {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(5)
        }
    }

    /// The data tick runs while the send window or the ack list is nonempty
    /// (Go `dataUpdater.shouldContinue`).
    #[must_use]
    fn data_work_needed(&self) -> bool {
        !self.sending.is_empty() || self.receiving.acklist_nonempty()
    }

    /// Read EOFs immediately in these states, BEFORE draining (Go order).
    #[must_use]
    const fn read_eof(&self) -> bool {
        self.state.read_eof_immediate()
    }

    #[must_use]
    const fn peer_terminating(&self) -> bool {
        matches!(self.state, State::PeerTerminating)
    }

    /// Go `SetState`: record the state + its begin time; leaving `Active`
    /// for `PeerClosed`/`Terminating`/`PeerTerminating`/`Terminated`
    /// discards the pending send window (`CloseWrite`) — `ReadyToClose`
    /// keeps it (graceful close flushes in-flight data with the Close
    /// option).
    fn set_state(&mut self, current: u32, state: State) {
        self.state = state;
        self.state_begin = current;
        if matches!(
            state,
            State::PeerClosed | State::Terminating | State::PeerTerminating | State::Terminated
        ) {
            self.sending.close_write();
        }
        if state == State::Terminated {
            self.signal_input();
            self.signal_output();
        }
    }

    /// Signal the read side: wake the async `read` waiter (stored
    /// notification latch) AND the stream adapter's poll-registered waker.
    fn signal_input(&mut self) {
        self.data_input.notify_one();
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
    }

    /// Signal the write side: wake the async `write` waiter AND the stream
    /// adapter's poll-registered waker.
    fn signal_output(&mut self) {
        self.data_output.notify_one();
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }

    /// Go `Close`: signal the notifiers, then transition per state.
    /// `Active` → `ReadyToClose`, `PeerClosed` → `Terminating`,
    /// `PeerTerminating` → `Terminated`. Errors on an already-closed session
    /// (Go returns `ErrClosedConnection`).
    ///
    /// # Errors
    ///
    /// `ConnectionAborted` when already in ReadyToClose/Terminating/Terminated.
    fn close(&mut self, current: u32) -> io::Result<()> {
        self.signal_input();
        self.signal_output();
        match self.state {
            State::ReadyToClose | State::Terminating | State::Terminated => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "kcp connection already closed",
                ));
            }
            State::Active => {
                self.set_state(current, State::ReadyToClose);
            }
            State::PeerClosed => {
                self.set_state(current, State::Terminating);
            }
            State::PeerTerminating => {
                self.set_state(current, State::Terminated);
            }
        }
        Ok(())
    }

    /// Go `OnPeerClosed`: the peer sent the Close option.
    fn on_peer_closed(&mut self, current: u32) {
        if self.state == State::ReadyToClose {
            self.set_state(current, State::Terminating);
        } else if self.state == State::Active {
            self.set_state(current, State::PeerClosed);
        }
    }

    fn handle_option(&mut self, current: u32, opt: SegmentOption) {
        if opt.is_close() {
            self.on_peer_closed(current);
        }
    }

    /// Ask the driver to flush now (Go `dataUpdater.WakeUp`): bump the
    /// sequence counter BEFORE the notify so a notify that races the
    /// driver's wait is not lost.
    fn wake_flush(&self) {
        self.flush_seq.fetch_add(1, Ordering::Relaxed);
        self.flush_wake.notify_waiters();
    }

    fn close_opt(&self) -> SegmentOption {
        if self.state == State::ReadyToClose {
            SegmentOption::CLOSE
        } else {
            SegmentOption::from_u8(0)
        }
    }

    /// Serialize and send one segment. Send errors are logged and swallowed,
    /// exactly like Go (the workers ignore `writer.Write` errors); the UDP
    /// recv side surfaces socket failures (spec §6).
    fn write_seg(&mut self, seg: &Segment) -> io::Result<()> {
        let mut buf = Vec::with_capacity(1400);
        encode_segment(seg, &mut buf);
        (self.output)(&buf)
    }

    /// Go `Ping`: a `CmdOnly` segment with our receiving next / sending
    /// first unacked / RTO; carries the `Close` option only in
    /// `ReadyToClose`. Updates `lastPingTime`.
    fn ping_segment(&self, cmd: Command) -> Segment {
        Segment::CmdOnly {
            conv: self.conv,
            cmd,
            opt: self.close_opt(),
            snd_nxt: self.sending.first_unacked(),
            rcv_nxt: self.receiving.next_number(),
            peer_rto: self.round_trip.timeout(),
        }
    }

    fn ping(&mut self, current: u32, cmd: Command) {
        let seg = self.ping_segment(cmd);
        let _ = self.write_seg(&seg);
        self.last_ping = current;
    }

    /// Go `flush()`: the per-tick state machine, then the window flushes.
    fn flush(&mut self, current: u32) {
        if self.state == State::Terminated {
            return;
        }
        if self.state == State::Active && current.wrapping_sub(self.last_incoming) >= IDLE_CLOSE_MS
        {
            let _ = self.close(current);
        }
        if self.state == State::ReadyToClose && self.sending.is_empty() {
            self.set_state(current, State::Terminating);
        }
        if self.state == State::Terminating {
            // Send one Terminate per tick; after 8s in this state, die.
            self.ping(current, Command::Terminate);
            if current.wrapping_sub(self.state_begin) > TERMINATING_MS {
                self.set_state(current, State::Terminated);
            }
            return;
        }
        if self.state == State::PeerTerminating
            && current.wrapping_sub(self.state_begin) > PEER_TERMINATING_MS
        {
            self.set_state(current, State::Terminating);
        }
        if self.state == State::ReadyToClose
            && current.wrapping_sub(self.state_begin) > READY_TO_CLOSE_MS
        {
            self.set_state(current, State::Terminating);
        }

        let rto = self.round_trip.timeout();
        let acks = self.receiving.flush(current, rto);
        let (data, first_unacked_updated) = self.sending.flush(current, rto);

        // Emit acks, then data, then at most one ping — Go's wire order.
        for a in acks {
            let seg = Segment::Ack {
                conv: self.conv,
                opt: self.close_opt(),
                rcv_wnd: self
                    .receiving
                    .next_number()
                    .wrapping_add(self.receiving.window_size()),
                rcv_nxt: self.receiving.next_number(),
                ts: a.ts,
                numbers: a.numbers,
            };
            let _ = self.write_seg(&seg);
        }
        for d in data {
            let seg = Segment::Data {
                conv: self.conv,
                opt: self.close_opt(),
                ts: d.ts,
                sn: d.sn,
                una: self.sending.first_unacked(),
                payload: d.payload,
            };
            let _ = self.write_seg(&seg);
        }
        if first_unacked_updated || current.wrapping_sub(self.last_ping) >= PING_INTERVAL_MS {
            self.ping(current, Command::Ping);
        }
    }

    /// Go `Input`: parse + dispatch one datagram. A malformed datagram is
    /// dropped with a debug log (spec §6); a conv mismatch is dropped after
    /// counting as incoming (Go sets `lastIncomingTime` before the conv
    /// check).
    fn input(&mut self, current: u32, datagram: &[u8]) {
        let Some(seg) = parse_datagram(datagram) else {
            tracing::debug!(conv = self.conv, "mKCP: dropping malformed datagram");
            return;
        };
        self.last_incoming = current;
        match seg {
            Segment::Data {
                conv,
                opt,
                ts,
                sn,
                una,
                payload,
            } => {
                if conv != self.conv {
                    return;
                }
                self.handle_option(current, opt);
                self.receiving.process_data(sn, ts, una, payload);
                if self.receiving.is_data_available() {
                    self.signal_input();
                }
                self.wake_flush();
            }
            Segment::Ack {
                conv,
                opt,
                rcv_wnd,
                rcv_nxt,
                ts,
                numbers,
            } => {
                if conv != self.conv {
                    return;
                }
                self.handle_option(current, opt);
                let rtt = self.sending.process_ack_segment(
                    current,
                    rcv_wnd,
                    rcv_nxt,
                    &numbers,
                    ts,
                    self.round_trip.timeout(),
                );
                if let Some(rtt) = rtt {
                    self.round_trip.update(rtt, current);
                }
                self.signal_output();
                self.wake_flush();
            }
            Segment::CmdOnly {
                conv,
                cmd,
                opt,
                snd_nxt,
                rcv_nxt,
                peer_rto,
            } => {
                if conv != self.conv {
                    return;
                }
                self.handle_option(current, opt);
                if cmd == Command::Terminate {
                    match self.state {
                        State::Active | State::PeerClosed => {
                            self.set_state(current, State::PeerTerminating);
                        }
                        State::ReadyToClose => {
                            self.set_state(current, State::Terminating);
                        }
                        State::Terminating => {
                            self.set_state(current, State::Terminated);
                        }
                        _ => {}
                    }
                }
                if opt.is_close() || cmd == Command::Terminate {
                    self.signal_input();
                    self.signal_output();
                }
                self.sending.clear_up_to(rcv_nxt);
                self.receiving.clear_acklist(snd_nxt);
                self.round_trip.update_peer_rto(peer_rto, current);
            }
        }
    }

    /// Drain available bytes into `buf`; 0 = nothing ready (the async
    /// facade waits on the data notifier). Non-blocking.
    fn try_read(&mut self, buf: &mut [u8]) -> usize {
        self.receiving.read_available(buf)
    }

    /// Go `writeMultiBufferInternal`'s inner loop: push mss-chunked slices
    /// while the window accepts. Returns the bytes pushed (the remainder
    /// stays in the caller's buffer — the facade waits on the data-output
    /// notifier and retries). The state check mirrors Go's ordering: an
    /// exhausted input returns success before the state check, so a fully
    /// pushed write succeeds even if the state flips right after.
    ///
    /// # Errors
    ///
    /// `BrokenPipe` when the state leaves `Active` while bytes remain.
    fn push_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut pushed = 0;
        let mut rest = buf;
        loop {
            if rest.is_empty() {
                return Ok(pushed);
            }
            if self.state != State::Active {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "kcp connection closed",
                ));
            }
            let take = rest.len().min(self.mss);
            if !self.sending.push(Bytes::copy_from_slice(&rest[..take])) {
                // Window full: stop; the facade waits for window space.
                return Ok(pushed);
            }
            pushed += take;
            rest = &rest[take..];
        }
    }
}

fn lock(core: &Mutex<SessionCore>) -> MutexGuard<'_, SessionCore> {
    core.lock()
}

/// The per-session driver task (spec §4.4 + §8 deviation 2): the ping
/// updater (immediate first flush, then every 5s — 1s during the terminate
/// handshake) and the data updater (every `tti` while the send window or
/// ack list is nonempty) collapse into one loop; every wake runs `flush()`.
async fn drive(core: Arc<Mutex<SessionCore>>) {
    let flush_wake = lock(&core).flush_wake.clone();
    let tti = Duration::from_millis(u64::from(lock(&core).tti));
    // Ping updater: immediate first wake (Go NewConnection →
    // pingUpdater.WakeUp()). Sends nothing: empty windows + last_ping ≈ 0.
    {
        let mut core = lock(&core);
        let current = core.elapsed();
        core.flush(current);
    }
    let mut last_seq = lock(&core).flush_seq.load(Ordering::Relaxed);
    loop {
        // Drain any flush requests that arrived since the last flush.
        loop {
            let seq = lock(&core).flush_seq.load(Ordering::Relaxed);
            if seq == last_seq {
                break;
            }
            last_seq = seq;
            let mut core = lock(&core);
            if core.is_terminated() {
                return;
            }
            let current = core.elapsed();
            core.flush(current);
        }
        let (ping_delay, data_work, terminated) = {
            let core = lock(&core);
            (
                core.ping_interval(),
                core.data_work_needed(),
                core.is_terminated(),
            )
        };
        if terminated {
            return;
        }
        tokio::select! {
            () = tokio::time::sleep(ping_delay) => 0u8,
            () = flush_wake.notified() => 1u8,
            () = tokio::time::sleep(tti), if data_work => 2u8,
        };
        // Every wake runs flush() — timer ticks included (Go's updaters
        // call flush on each tick): the silence ping cadence, the RTO
        // retransmit (via the data tti while the send window is nonempty),
        // the idle guard and the terminate-handshake state transitions all
        // live inside flush. Without this, only write/input/close wakeups
        // flushed, so a stalled window never retransmitted and the 5s ping
        // tick never fired. (A wakeup that raced the drain loop above makes
        // this flush redundant — flushing twice is a no-op for empty
        // windows/ack lists.)
        {
            let mut core = lock(&core);
            if core.is_terminated() {
                return;
            }
            let current = core.elapsed();
            core.flush(current);
        }
    }
}

/// An mKCP session: a reliable byte stream over UDP (xray's KCP fork).
///
/// Owns the state machine ([`SessionCore`]) plus the driver task ([`drive`])
/// running the §4.4 timers. The UDP send path is injected as a closure; the
/// recv side is fed by [`KcpSession::input`] (the transport's recv task,
/// wired in T4). Exposes async [`read`](Self::read)/[`write`](Self::write)
/// with notifier-driven waiting.
pub struct KcpSession {
    core: Arc<Mutex<SessionCore>>,
    _driver: Arc<JoinHandle<()>>,
}

impl KcpSession {
    /// Create a session for `conv` with `settings`; `output` sends one UDP
    /// datagram per call (the dial side injects it in T4). Spawns the flush
    /// driver task.
    pub fn new(
        conv: u16,
        settings: KcpSettings,
        output: impl FnMut(&[u8]) -> io::Result<()> + Send + 'static,
    ) -> Self {
        let core = Arc::new(Mutex::new(SessionCore::new(
            conv,
            settings,
            Box::new(output),
        )));
        let driver = tokio::spawn(drive(Arc::clone(&core)));
        Self {
            core,
            _driver: Arc::new(driver),
        }
    }

    /// Feed one received UDP datagram (spec §5.2 Input). Malformed or
    /// conv-mismatched datagrams are dropped; never fails.
    pub fn input(&self, datagram: &[u8]) {
        let mut core = lock(&self.core);
        let current = core.elapsed();
        core.input(current, datagram);
    }

    /// Read up to `buf.len()` bytes; `Ok(0)` = EOF. EOF states are checked
    /// before draining (Go `Connection.Read` order): `ReadyToClose` /
    /// `Terminating` / `Terminated` EOF immediately, `PeerTerminating`
    /// drains then EOFs. Waits on the data notifier when nothing is
    /// available.
    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            {
                let mut core = lock(&self.core);
                if core.read_eof() {
                    return Ok(0);
                }
                let n = core.try_read(buf);
                if n > 0 {
                    core.wake_flush();
                    return Ok(n);
                }
                if core.peer_terminating() {
                    return Ok(0);
                }
            }
            let notifier = lock(&self.core).data_input.clone();
            notifier.notified().await;
        }
    }

    /// Write the whole buffer with backpressure: mss-chunked pushes, waiting
    /// on the data-output notifier when the send window is full.
    ///
    /// # Errors
    ///
    /// `BrokenPipe` when the state leaves `Active` before all bytes are
    /// pushed (spec §4.3 Write).
    pub async fn write(&self, buf: &[u8]) -> io::Result<()> {
        let mut rest = buf;
        loop {
            let pushed = lock(&self.core).push_write(rest)?;
            if pushed > 0 {
                lock(&self.core).wake_flush();
                rest = &rest[pushed..];
            }
            if rest.is_empty() {
                return Ok(());
            }
            let notifier = lock(&self.core).data_output.clone();
            notifier.notified().await;
        }
    }

    /// Poll-style read for the stream adapter (spec §5.3): same semantics
    /// as [`read`] (EOF states resolve first, then a synchronous drain of
    /// the recv window), but the wait registers the caller's waker on the
    /// data notifier instead of parking an async `read`. The drain and the
    /// waker registration happen under one core-lock hold, and every
    /// data-input signal wakes the stored waker — check-then-wait is
    /// race-free, no lost wakeups.
    pub(crate) fn poll_read(&self, buf: &mut [u8], cx: &TaskCx<'_>) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut core = lock(&self.core);
        if core.read_eof() {
            return Poll::Ready(Ok(0));
        }
        let n = core.try_read(buf);
        if n > 0 {
            core.wake_flush();
            return Poll::Ready(Ok(n));
        }
        if core.peer_terminating() {
            return Poll::Ready(Ok(0));
        }
        core.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Poll-style write for the stream adapter (spec §5.3): push as much of
    /// `buf` as the send window accepts (partial writes are valid
    /// `AsyncWrite`), and when the window is full register the caller's
    /// waker on the data-output notifier (woken by every ack signal).
    pub(crate) fn poll_write(&self, buf: &[u8], cx: &TaskCx<'_>) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut core = lock(&self.core);
        let pushed = core.push_write(buf)?;
        if pushed > 0 {
            core.wake_flush();
            return Poll::Ready(Ok(pushed));
        }
        core.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Close the session (spec §4.3 Close). Idempotent; the terminate
    /// handshake runs in the driver task.
    pub fn close(&self) {
        let mut core = lock(&self.core);
        let current = core.elapsed();
        let _ = core.close(current);
        core.wake_flush();
    }

    /// The current session state (for the stream adapter's EOF logic).
    #[must_use]
    pub fn state(&self) -> State {
        lock(&self.core).state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> KcpSettings {
        KcpSettings::new(1350, 50)
    }

    fn sent_collector() -> (Sent, impl FnMut(&[u8]) -> io::Result<()>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let s = Arc::clone(&sent);
        (sent, move |buf: &[u8]| {
            s.lock().push(buf.to_vec());
            Ok(())
        })
    }

    /// Datagrams captured by [`sent_collector`].
    type Sent = Arc<Mutex<Vec<Vec<u8>>>>;

    fn parse_sent(sent: &[Vec<u8>]) -> Vec<Segment> {
        sent.iter().filter_map(|d| parse_datagram(d)).collect()
    }

    fn core_with_sent() -> (SessionCore, Arc<Mutex<Vec<Vec<u8>>>>) {
        let (sent, out) = sent_collector();
        (SessionCore::new(7, settings(), Box::new(out)), sent)
    }

    fn data_seg(conv: u16, opt: u8, ts: u32, sn: u32, una: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_segment(
            &Segment::Data {
                conv,
                opt: SegmentOption::from_u8(opt),
                ts,
                sn,
                una,
                payload: Bytes::copy_from_slice(payload),
            },
            &mut out,
        );
        out
    }

    fn ack_seg(conv: u16, rcv_wnd: u32, rcv_nxt: u32, ts: u32, numbers: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_segment(
            &Segment::Ack {
                conv,
                opt: SegmentOption::from_u8(0),
                rcv_wnd,
                rcv_nxt,
                ts,
                numbers: numbers.to_vec(),
            },
            &mut out,
        );
        out
    }

    fn cmd_seg(
        conv: u16,
        cmd: Command,
        opt: u8,
        snd_nxt: u32,
        rcv_nxt: u32,
        peer_rto: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        encode_segment(
            &Segment::CmdOnly {
                conv,
                cmd,
                opt: SegmentOption::from_u8(opt),
                snd_nxt,
                rcv_nxt,
                peer_rto,
            },
            &mut out,
        );
        out
    }

    // --- RTO/RTT arithmetic (Go RoundTripInfo) ---

    #[test]
    fn rto_first_sample() {
        // First sample: srtt = rtt, variation = rtt/2; min_rtt(50) < 4v(400)
        // → rto = srtt + 4v = 600 → ×5/4 = 750.
        let mut rt = RoundTripInfo::new(50);
        assert_eq!(rt.timeout(), 100); // init rto
        rt.update(200, 1000);
        assert_eq!(rt.srtt, 200);
        assert_eq!(rt.variation, 100);
        assert_eq!(rt.timeout(), 750);
        assert_eq!(rt.updated_ts, 1000);
    }

    #[test]
    fn rto_smoothing() {
        let mut rt = RoundTripInfo::new(50);
        rt.update(200, 0);
        rt.update(220, 100); // delta 20: v = (3*100+20)/4 = 80; srtt = (7*200+220)/8 = 202
        assert_eq!(rt.variation, 80);
        assert_eq!(rt.srtt, 202);
        // min_rtt(50) < 4v(320) → rto = 202 + 320 = 522 → ×5/4 = 652.
        assert_eq!(rt.timeout(), 522 * 5 / 4);
        assert_eq!(rt.updated_ts, 100);
    }

    #[test]
    fn rto_srtt_clamped_to_min_rtt() {
        // (7*30+10)/8 = 27 < min_rtt 50 → clamped to 50.
        let mut rt = RoundTripInfo {
            variation: 10,
            srtt: 30,
            rto: 100,
            min_rtt: 50,
            updated_ts: 0,
        };
        rt.update(10, 100);
        assert_eq!(rt.srtt, 50);
    }

    #[test]
    fn rto_capped_then_scaled() {
        // srtt + 4v = 9000 + 4*375 = 10500 → capped to 10000 → ×5/4 = 12500.
        let mut rt = RoundTripInfo {
            variation: 500,
            srtt: 9000,
            rto: 100,
            min_rtt: 50,
            updated_ts: 0,
        };
        rt.update(9000, 0); // delta 0: v = 375, srtt = 9000
        assert_eq!(rt.variation, 375);
        assert_eq!(rt.timeout(), 12_500);
    }

    #[test]
    fn rto_rejects_rtt_over_i32_max() {
        let mut rt = RoundTripInfo::new(50);
        rt.update(200, 0);
        let before = rt.timeout();
        rt.update(0x8000_0000, 100); // > 0x7FFFFFFF → ignored
        assert_eq!(rt.timeout(), before);
        assert_eq!(rt.updated_ts, 0);
    }

    #[test]
    fn rto_smoothing_wraps_like_go() {
        // Pathological samples must wrap like Go's plain uint32 math, not
        // panic in Rust debug builds.
        let mut rt = RoundTripInfo {
            variation: 0x3FFF_FFFF,
            srtt: 0x7FFF_FFFF,
            rto: 100,
            min_rtt: 50,
            updated_ts: 0,
        };
        rt.update(0x7FFF_FFFF, 0);
        // srtt = (7*0x7FFFFFFF wraps to 0x7FFFFFFF + 0x7FFFFFFF)/8 = 0x1FFFFFFF;
        // variation = (3*0x3FFFFFFF + 0)/4 = 0x2FFFFFFF.
        assert_eq!(rt.srtt, 0x1FFF_FFFF);
        assert_eq!(rt.variation, 0x2FFF_FFFF);
        // rto > 10000 → capped to 10000 → ×5/4.
        assert_eq!(rt.timeout(), 12_500);
    }

    #[test]
    fn rto_plus_v_when_small_variation() {
        // min_rtt(50) >= 4v(8) → rto = srtt + v = 100 + 2 = 102 → ×5/4 = 127.
        let mut rt = RoundTripInfo::new(50);
        rt.update(100, 0); // srtt 100, v 50 → rto (100+4*50=300)*5/4 = 375
        assert_eq!(rt.timeout(), 375);
        // Force tiny variation via a direct construction.
        let mut rt = RoundTripInfo {
            variation: 2,
            srtt: 100,
            rto: 100,
            min_rtt: 50,
            updated_ts: 0,
        };
        rt.update(100, 0); // delta 0: v = (6+0)/4 = 1; srtt = 100; 50 >= 4 → rto = 101 → 126
        assert_eq!(rt.variation, 1);
        assert_eq!(rt.timeout(), 101 * 5 / 4);
    }

    #[test]
    fn peer_rto_adoption_gate() {
        let mut rt = RoundTripInfo::new(50);
        rt.update(200, 1000); // updated_ts = 1000
        rt.update_peer_rto(321, 2500); // 2500-1000 = 1500 < 3000 → ignored
        assert_eq!(rt.timeout(), 750);
        rt.update_peer_rto(321, 4000); // 4000-1000 = 3000 ≥ 3000 → adopted
        assert_eq!(rt.timeout(), 321);
        assert_eq!(rt.updated_ts, 4000);
    }

    // --- send window (Go SendingWorker) ---

    #[test]
    fn send_flush_in_order_and_cwnd_stop() {
        let mut w = SendingWorker::new(&settings());
        // cwnd = min(snd_inflight 194, remote_rcv_nxt 32 - first 0, control 194) = 32.
        for _ in 0..40 {
            assert!(w.push(Bytes::from(vec![0x41u8; 8])));
        }
        let (out, updated) = w.flush(1000, 100);
        assert_eq!(out.len(), 32); // cwnd stop
        assert_eq!(out[0].sn, 0);
        assert_eq!(out[31].sn, 31);
        assert!(out.iter().all(|d| d.ts == 1000));
        assert!(!updated); // nothing acked → first_unacked untouched
        // Nothing due on an immediate re-flush: timeouts = 1100, now 1000.
        let (out, _) = w.flush(1000, 100);
        assert!(!out.is_empty());
        // Re-flush at the same current: the 32 sent entries are not due yet
        // (timeouts 1100 in the future → wrapped → skipped), but the 8
        // never-sent tail (timeout 0 → always due) goes out.
        let sns: Vec<u32> = out.iter().map(|d| d.sn).collect();
        assert_eq!(sns, (32..40).collect::<Vec<u32>>());
    }

    #[test]
    fn send_retransmit_on_timeout() {
        let mut w = SendingWorker::new(&settings());
        assert!(w.push(Bytes::from_static(b"hello")));
        let (out, _) = w.flush(1000, 100);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sn, 0);
        // Not yet due (timeout 1100 is in the future) → skipped.
        let (out, _) = w.flush(1050, 100);
        assert!(out.is_empty());
        // Due now (1200 - 1100 = 100, no wrap) → retransmit.
        let (out, _) = w.flush(1200, 100);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sn, 0);
        assert_eq!(w.window.entries[0].1.transmit, 2);
    }

    #[test]
    fn ack_fast_resend_and_rtt_sample() {
        let mut w = SendingWorker::new(&settings());
        for _ in 0..4 {
            assert!(w.push(Bytes::from(vec![0x41u8; 4])));
        }
        w.flush(1000, 300); // timeouts 1300, transmit 1
        // Ack sn 2: maxack removed → fast-resend pulls 0/1's timeouts forward
        // by rto/3 = 100; RTT = 1100 - 1050 = 50 < 10000 → sample.
        let rtt = w.process_ack_segment(1100, 200, 0, &[2], 1050, 300);
        assert_eq!(rtt, Some(50));
        // sn 2 was removed; fast-ack visited 0/1 (reduced by 100) and broke
        // at 3 (wrap-ahead of maxack 2) → the window holds 0, 1, 3.
        let timeouts: Vec<u32> = w.window.entries.iter().map(|(_, e)| e.timeout).collect();
        assert_eq!(timeouts, vec![1200, 1200, 1300]);
        assert_eq!(w.window.entries.len(), 3);
        assert_eq!(w.window.entries[2].0, 3);
        // Flush at 1250: 0/1 due (1250-1200 = 50), 3 not (1250-1300 wraps).
        let (out, _) = w.flush(1250, 300);
        let sns: Vec<u32> = out.iter().map(|d| d.sn).collect();
        assert_eq!(sns, vec![0, 1]);
    }

    #[test]
    fn ack_removes_segments_and_advances_first_unacked() {
        let mut w = SendingWorker::new(&settings());
        for _ in 0..5 {
            assert!(w.push(Bytes::from(vec![0x41u8; 4])));
        }
        w.flush(1000, 100);
        assert_eq!(w.first_unacked, 0);
        // rcv_nxt 0: the numbers are still in the window, so they remove
        // and the max (2) triggers fast-ack + the RTT sample.
        let rtt = w.process_ack_segment(1100, 64, 0, &[0, 1, 2], 1000, 100);
        assert_eq!(rtt, Some(100));
        assert_eq!(w.first_unacked, 3);
        assert_eq!(w.remote_rcv_nxt, 64); // rcv_wnd 64 > 32 → adopted
        assert_eq!(w.window.entries.len(), 2); // sn 3, 4 remain
        // Out-of-range acks are ignored: 3 == next_sn... no: next_sn = 5,
        // so 3 is valid but absent → not removed; 5 == next_sn → ignored.
        assert!(!w.process_ack(5));
    }

    #[test]
    fn process_ack_wrap_range() {
        let mut w = SendingWorker::new(&settings());
        w.push(Bytes::from_static(b"a"));
        w.push(Bytes::from_static(b"b"));
        w.push(Bytes::from_static(b"c"));
        assert!(!w.process_ack(3)); // == next_sn → out of [first, next)
        assert!(!w.process_ack(u32::MAX)); // wrap-behind first_unacked
        assert!(w.process_ack(1));
        assert_eq!(w.first_unacked, 0); // sn 0 still queued at the front
        assert!(w.process_ack(0));
        assert_eq!(w.first_unacked, 2); // sn 2 is now the front
        assert!(!w.process_ack(1)); // wrap-behind the new first_unacked
        assert!(w.process_ack(2)); // last in-window segment (sn 2, next_sn 3)
        assert!(w.is_empty());
        assert_eq!(w.first_unacked, 3);
    }

    #[test]
    fn fast_ack_wrap_break() {
        let mut w = SendingWorker::new(&settings());
        for _ in 0..4 {
            assert!(w.push(Bytes::from_static(b"x")));
        }
        w.flush(1000, 300);
        // A maxack of 0: breaks immediately (number == 0), nothing reduced.
        w.window.handle_fast_ack(0, 300);
        let timeouts: Vec<u32> = w.window.entries.iter().map(|(_, e)| e.timeout).collect();
        assert_eq!(timeouts, vec![1300, 1300, 1300, 1300]);
        // maxack 2: 0/1 reduced, 2 breaks the visit, 3 untouched.
        w.window.handle_fast_ack(2, 300);
        let timeouts: Vec<u32> = w.window.entries.iter().map(|(_, e)| e.timeout).collect();
        assert_eq!(timeouts, vec![1200, 1200, 1300, 1300]);
    }

    #[test]
    fn loss_rate_cwnd_adjustment() {
        let mut w = SendingWorker::new(&settings());
        for _ in 0..4 {
            assert!(w.push(Bytes::from(vec![0x41u8; 4])));
        }
        w.flush(1000, 100);
        // 4 retransmits → lost 4/4 = 100% → ×3/4.
        w.flush(1200, 100);
        assert_eq!(w.control_window, 194 * 3 / 4); // 145
        // 0 loss (fresh first-transmits) → +1/4.
        w.clear_up_to(4); // ack everything
        assert_eq!(w.first_unacked, 4);
        for _ in 0..4 {
            assert!(w.push(Bytes::from(vec![0x41u8; 4])));
        }
        w.flush(1400, 100);
        assert_eq!(w.control_window, 145 + 145 / 4); // 181
        // Floor 16.
        w.control_window = 8;
        w.on_packet_loss(30, 100); // 8*3/4 = 6 → 16
        assert_eq!(w.control_window, 16);
        // Cap at snd_inflight.
        w.control_window = 1000;
        w.on_packet_loss(0, 100); // 1250 → capped at 194
        assert_eq!(w.control_window, 194);
        // Zero RTO skips the adjustment (Go checks Timeout() == 0).
        w.control_window = 100;
        w.on_packet_loss(50, 0);
        assert_eq!(w.control_window, 100);
    }

    #[test]
    fn push_rejects_beyond_window_size() {
        let s = settings();
        let mut w = SendingWorker::new(&s);
        let cap = s.snd_buf as usize; // 1553
        for i in 0..=cap {
            assert!(w.push(Bytes::from(vec![0x41u8; 1])), "push {i}");
        }
        // Go quirk: Push accepts while Len() <= windowSize → cap+1 entries.
        assert!(!w.push(Bytes::from_static(b"x")));
        assert_eq!(w.window.len(), cap + 1);
        // Empty payloads are no-op successes (never pushed on the wire).
        assert!(w.push(Bytes::new()));
        assert_eq!(w.window.len(), cap + 1);
    }

    #[test]
    fn close_write_discards_window() {
        let mut w = SendingWorker::new(&settings());
        for i in 0..3 {
            assert!(w.push(Bytes::from(vec![i; 1])));
        }
        w.close_write();
        assert!(w.is_empty());
    }

    // --- receive window (Go ReceivingWorker) ---

    #[test]
    fn recv_in_order_and_gap_fill() {
        let mut r = ReceivingWorker::new(&settings());
        r.process_data(1, 10, 0, Bytes::from_static(b"b")); // gap
        assert!(!r.is_data_available());
        let mut buf = [0u8; 16];
        assert_eq!(r.read_available(&mut buf), 0);
        r.process_data(0, 5, 0, Bytes::from_static(b"a")); // fills the gap
        assert!(r.is_data_available());
        let n = r.read_available(&mut buf);
        assert_eq!(&buf[..n], b"ab");
        assert_eq!(r.next_number, 2);
    }

    #[test]
    fn recv_duplicate_dropped() {
        let mut r = ReceivingWorker::new(&settings());
        r.process_data(0, 5, 0, Bytes::from_static(b"first"));
        r.process_data(0, 6, 0, Bytes::from_static(b"second")); // duplicate
        let mut buf = [0u8; 16];
        let n = r.read_available(&mut buf);
        assert_eq!(&buf[..n], b"first"); // first copy wins
    }

    #[test]
    fn recv_out_of_window_dropped() {
        let mut r = ReceivingWorker::new(&settings());
        r.process_data(settings().rcv_inflight, 1, 0, Bytes::from_static(b"x"));
        assert!(!r.is_data_available());
        assert!(r.acklist.is_empty()); // dropped before the ack list
        // Boundary: sn = window_size - 1 is accepted.
        r.process_data(settings().rcv_inflight - 1, 1, 0, Bytes::from_static(b"y"));
        assert!(r.window.contains_key(&(settings().rcv_inflight - 1)));
    }

    #[test]
    fn recv_wrap_arithmetic() {
        let mut r = ReceivingWorker::new(&settings());
        r.next_number = 0xFFFF_FFF0;
        // Ahead within the window, wrap-correct.
        r.process_data(0xFFFF_FFF2, 1, 0, Bytes::from_static(b"a"));
        assert!(r.window.contains_key(&0xFFFF_FFF2));
        let mut buf = [0u8; 16];
        assert_eq!(r.read_available(&mut buf), 0); // next FFF0 still missing
        r.process_data(0xFFFF_FFF0, 1, 0, Bytes::from_static(b"x"));
        r.process_data(0xFFFF_FFF1, 1, 0, Bytes::from_static(b"y"));
        let n = r.read_available(&mut buf);
        assert_eq!(&buf[..n], b"xya"); // FFF2 was queued earlier and is now consecutive
        assert_eq!(r.next_number, 0xFFFF_FFF3);
        // Beyond the window after wrap: idx = 1904 ≥ 776 → dropped.
        let far = 0xFFFF_FFF3u32.wrapping_add(settings().rcv_inflight);
        r.process_data(far, 1, 0, Bytes::from_static(b"z"));
        assert!(!r.window.contains_key(&far));
    }

    #[test]
    fn recv_read_leftover() {
        let mut r = ReceivingWorker::new(&settings());
        r.process_data(0, 1, 0, Bytes::from_static(b"abcdef"));
        let mut buf = [0u8; 4];
        let n = r.read_available(&mut buf);
        assert_eq!(&buf[..n], b"abcd");
        // The remainder is served from leftover on the next read.
        let mut buf2 = [0u8; 8];
        let n = r.read_available(&mut buf2);
        assert_eq!(&buf2[..n], b"ef");
        assert_eq!(r.next_number, 1); // consumed once, split across reads
    }

    // --- ack list (Go AckList) ---

    #[test]
    fn acklist_batching_and_due_times() {
        let mut l = AckList::new(128);
        for i in 0..300 {
            l.add(i, i * 10, 1024);
        }
        let out = l.flush(1000, 100);
        assert_eq!(out.len(), 3); // 128 + 128 + 44
        assert_eq!(out[0].numbers.len(), 128);
        assert_eq!(out[1].numbers.len(), 128);
        assert_eq!(out[2].numbers.len(), 44);
        // ts = the latest echo in each batch (Go PutTimestamp keeps max).
        assert_eq!(out[0].ts, 127 * 10);
        assert_eq!(out[1].ts, 255 * 10);
        // Nothing due on an immediate re-flush (nextFlush = 1050): dirty
        // false and batch empty → no write.
        assert!(l.flush(1000, 100).is_empty());
    }

    #[test]
    fn acklist_candidates_ride_along() {
        let mut l = AckList::new(128);
        for i in 0..6 {
            l.add(i, 1, 1024);
        }
        assert_eq!(l.flush(1000, 100).len(), 1); // all due; nextFlush = 1050
        for i in 6..10 {
            l.add(i, 1, 1024);
        }
        // 0..5 not yet due → candidates; 6..9 due → batch; the final write
        // (dirty from the adds) appends the candidates.
        let out = l.flush(1020, 100);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].numbers, vec![6, 7, 8, 9, 0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn acklist_clear_drops_acked() {
        let mut l = AckList::new(128);
        l.add(3, 1, 1024);
        l.add(7, 1, 1024);
        l.add(9, 1, 1024);
        l.clear(8); // drops 3 and 7
        assert_eq!(l.numbers.iter().copied().collect::<Vec<_>>(), vec![9]);
        assert!(l.dirty);
    }

    #[test]
    fn acklist_dirty_writes_header_only_ack() {
        // Go writes a header-only ack when the list is dirty but empty.
        let mut l = AckList::new(128);
        l.add(5, 1, 1024);
        l.clear(6); // drops 5 → dirty, empty
        let out = l.flush(1000, 100);
        assert_eq!(out.len(), 1);
        assert!(out[0].numbers.is_empty());
    }

    #[test]
    fn acklist_ts_wrap_keeps_latest() {
        // PutTimestamp replaces only when the new ts is wrap-ahead.
        let mut l = AckList::new(128);
        l.add(0, 0xFFFF_FFFF, 1024);
        l.add(1, 100, 1024);
        let out = l.flush(1000, 100);
        assert_eq!(out[0].ts, 100); // 100 is wrap-ahead of 0xFFFFFFFF? No —
        // 100 - 0xFFFFFFFF wraps to 101 < 0x7FFFFFFF → replaced. Yes.
    }

    /// A peer replaying one in-window Data segment must not grow the ack list:
    /// duplicates are skipped and the list is capped at the receive window
    /// (finding f7 — the unbounded, quadratic-growth case).
    #[test]
    fn acklist_dedups_and_caps_at_receive_window() {
        let cap = 776_u32; // rcv_inflight at the defaults
        let cap_usize = usize::try_from(cap).unwrap();
        let mut l = AckList::new(128);
        // Replay the SAME sn 10_000 times: one entry, not 10_000.
        for _ in 0..10_000 {
            l.add(0, 1, cap_usize);
        }
        assert_eq!(l.numbers.len(), 1, "replays must not enqueue duplicates");
        // Distinct sns beyond the cap evict the oldest, never exceed `cap`.
        for i in 0..(cap + 500) {
            l.add(i, 1, cap_usize);
        }
        assert_eq!(
            l.numbers.len(),
            cap_usize,
            "the list must be capped at the window"
        );
        // Oldest entries evicted: the front is the oldest survivor.
        assert_eq!(l.numbers.front().copied(), Some(500));
        assert_eq!(l.numbers.back().copied(), Some(cap + 499));
    }

    // --- state machine (Go Connection) ---

    #[test]
    fn close_to_terminate_to_terminated() {
        let (mut c, sent) = core_with_sent();
        assert!(c.close(100).is_ok());
        assert_eq!(c.state, State::ReadyToClose);
        // ReadyToClose + empty window → Terminating, Terminate sent in the
        // same flush.
        c.flush(100);
        assert_eq!(c.state, State::Terminating);
        let segs = parse_sent(&sent.lock());
        assert_eq!(segs.len(), 1);
        assert!(matches!(
            &segs[0],
            Segment::CmdOnly {
                cmd: Command::Terminate,
                opt,
                ..
            } if !opt.is_close() // Terminating is not ReadyToClose
        ));
        // 8000ms is NOT > 8000ms.
        c.flush(8100);
        assert_eq!(c.state, State::Terminating);
        c.flush(8101);
        assert_eq!(c.state, State::Terminated);
        // Terminated: flush is a no-op.
        let before = sent.lock().len();
        c.flush(9000);
        assert_eq!(sent.lock().len(), before);
    }

    #[test]
    fn ready_to_close_flushes_data_with_close_opt() {
        let (mut c, sent) = core_with_sent();
        assert_eq!(c.push_write(b"payload").unwrap(), 7);
        let _ = c.close(100);
        c.flush(100); // window nonempty → stays ReadyToClose; data with Close opt
        let segs = parse_sent(&sent.lock());
        assert_eq!(segs.len(), 1);
        match &segs[0] {
            Segment::Data {
                opt,
                ts,
                sn,
                una,
                payload,
                ..
            } => {
                assert!(opt.is_close());
                assert_eq!(*ts, 100);
                assert_eq!(*sn, 0);
                assert_eq!(*una, 0);
                assert_eq!(&payload[..], b"payload");
            }
            _ => panic!("expected Data"),
        }
        assert_eq!(c.state, State::ReadyToClose);
    }

    #[test]
    fn peer_close_opt() {
        let (mut c, _sent) = core_with_sent();
        c.input(100, &data_seg(7, 1, 10, 0, 0, b"hi")); // Close option
        assert_eq!(c.state, State::PeerClosed);
        // Data still deliverable in PeerClosed.
        let mut buf = [0u8; 8];
        let n = c.try_read(&mut buf);
        assert_eq!(&buf[..n], b"hi");
        // Write fails (state != Active).
        assert!(c.push_write(b"x").is_err());
        // Our close: PeerClosed → Terminating.
        assert!(c.close(200).is_ok());
        assert_eq!(c.state, State::Terminating);
        // Second close errors.
        assert!(c.close(201).is_err());
    }

    #[test]
    fn peer_terminate_handshake() {
        let (mut c, _sent) = core_with_sent();
        c.input(1000, &cmd_seg(7, Command::Terminate, 0, 0, 0, 100));
        assert_eq!(c.state, State::PeerTerminating);
        assert!(!c.read_eof()); // drains buffered data before EOF
        assert!(c.peer_terminating());
        c.flush(5000); // 5000-1000 = 4000, not > 4000
        assert_eq!(c.state, State::PeerTerminating);
        c.flush(5001); // > 4000 → Terminating
        assert_eq!(c.state, State::Terminating);
        c.flush(13_001); // 13001-5001 = 8000, not > 8000
        assert_eq!(c.state, State::Terminating);
        c.flush(13_002);
        assert_eq!(c.state, State::Terminated);
    }

    #[test]
    fn idle_30s_closes() {
        let (mut c, sent) = core_with_sent();
        c.flush(29_999);
        assert_eq!(c.state, State::Active);
        // 29999 ≥ 3000 → a Ping went out; the close happens at 30000.
        let segs = parse_sent(&sent.lock());
        assert!(matches!(
            &segs[0],
            Segment::CmdOnly {
                cmd: Command::Ping,
                ..
            }
        ));
        c.flush(30_000);
        // Idle guard closes → ReadyToClose; empty window → Terminating;
        // Terminate sent in the same flush.
        assert_eq!(c.state, State::Terminating);
        let segs = parse_sent(&sent.lock());
        assert!(matches!(
            segs.last().unwrap(),
            Segment::CmdOnly {
                cmd: Command::Terminate,
                ..
            }
        ));
    }

    #[test]
    fn incoming_updates_idle_timer() {
        let (mut c, _sent) = core_with_sent();
        c.input(20_000, &cmd_seg(7, Command::Ping, 0, 0, 0, 100));
        c.flush(40_000); // 40000 - 20000 = 20000 < 30000 → still active
        assert_eq!(c.state, State::Active);
        c.flush(50_001); // 50001 - 20000 = 30001 ≥ 30000 → closes
        assert_eq!(c.state, State::Terminating);
    }

    #[test]
    fn ping_cadence() {
        let (mut c, sent) = core_with_sent();
        c.flush(0); // initial — nothing (0 - last_ping 0 < 3000)
        assert!(sent.lock().is_empty());
        c.flush(2999);
        assert!(sent.lock().is_empty());
        c.flush(3000);
        let segs = parse_sent(&sent.lock());
        assert_eq!(segs.len(), 1);
        assert!(matches!(
            &segs[0],
            Segment::CmdOnly {
                cmd: Command::Ping,
                ..
            }
        ));
        match &segs[0] {
            Segment::CmdOnly {
                opt,
                snd_nxt,
                rcv_nxt,
                peer_rto,
                ..
            } => {
                assert!(!opt.is_close());
                assert_eq!(snd_nxt, &0);
                assert_eq!(rcv_nxt, &0);
                assert_eq!(peer_rto, &100); // initial RTO
            }
            _ => panic!("expected Ping"),
        }
        c.flush(5999); // 5999 - 3000 = 2999 < 3000 → nothing
        assert_eq!(sent.lock().len(), 1);
        c.flush(6000);
        assert_eq!(sent.lock().len(), 2);
    }

    #[test]
    fn ack_advance_pings() {
        let (mut c, sent) = core_with_sent();
        assert_eq!(c.push_write(b"data").unwrap(), 4);
        c.flush(1000);
        c.input(1100, &ack_seg(7, 100, 1, 990, &[0]));
        // first_unacked moved 0 → 1 → the next flush pings.
        c.flush(1100);
        let segs = parse_sent(&sent.lock());
        let pings = segs
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    Segment::CmdOnly {
                        cmd: Command::Ping,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(pings, 1);
    }

    #[test]
    fn ack_advances_rtt_and_remote_window() {
        let (mut c, _sent) = core_with_sent();
        assert_eq!(c.push_write(&[0xAB; 3000]).unwrap(), 3000); // 3 mss chunks
        c.flush(1000);
        // rcv_nxt 0 keeps the segments in the window so the acks remove
        // them; maxack must be > 0 for the RTT sample (Go's `maxack` starts
        // at 0, so acking only sn 0 yields no sample).
        c.input(1100, &ack_seg(7, 1000, 0, 1000, &[0, 1]));
        // rtt = 1100 - 1000 = 100 → srtt 100, v 50, min_rtt 50 < 200 →
        // rto = (100 + 200) * 5/4 = 375.
        assert_eq!(c.round_trip.timeout(), 375);
        assert_eq!(c.sending.window.entries.len(), 1); // sn 2 still queued
        assert_eq!(c.sending.first_unacked(), 2);
        assert_eq!(c.sending.remote_rcv_nxt, 1000); // rcv_wnd 1000 > 32
    }

    #[test]
    fn ack_segment_rcv_wnd_and_nxt() {
        let (mut c, sent) = core_with_sent();
        c.input(100, &data_seg(7, 0, 10, 5, 0, b"z")); // gap → acklist entry
        c.flush(100);
        let segs = parse_sent(&sent.lock());
        match &segs[0] {
            Segment::Ack {
                numbers,
                rcv_wnd,
                rcv_nxt,
                ts,
                ..
            } => {
                assert_eq!(numbers, &vec![5]);
                assert_eq!(*rcv_nxt, 0);
                assert_eq!(*rcv_wnd, settings().rcv_inflight);
                assert_eq!(*ts, 10);
            }
            _ => panic!("expected Ack"),
        }
    }

    #[test]
    fn conv_mismatch_dropped() {
        let (mut c, sent) = core_with_sent();
        c.input(100, &data_seg(99, 0, 10, 0, 0, b"x")); // wrong conv
        assert!(!c.receiving.is_data_available());
        assert_eq!(c.last_incoming, 100); // still counts as incoming
        c.flush(100);
        assert!(sent.lock().is_empty()); // nothing acked
    }

    #[test]
    fn malformed_datagram_dropped() {
        let (mut c, _sent) = core_with_sent();
        c.input(100, &[0x00, 0x07, 0x01]); // 3-byte prefix
        assert_eq!(c.last_incoming, 0); // not incoming (Go parses first)
    }

    #[test]
    fn cmd_only_updates_peer_rto_and_windows() {
        let (mut c, _sent) = core_with_sent();
        assert_eq!(c.push_write(b"abcd").unwrap(), 4);
        c.flush(1000);
        c.input(4000, &cmd_seg(7, Command::Ping, 0, 5, 1, 1234));
        // snd_nxt 5 → acklist cleared (empty anyway); rcv_nxt 1 → send
        // window cleared below 1 → first_unacked 1; peer_rto adopted
        // (4000 - 0 = 4000 ≥ 3000).
        assert_eq!(c.sending.first_unacked(), 1);
        assert_eq!(c.round_trip.timeout(), 1234);
    }

    // --- async facade ---

    #[tokio::test]
    async fn facade_write_read_roundtrip() {
        let (sent, out) = sent_collector();
        let session = KcpSession::new(7, settings(), out);
        session.write(b"hello kcp").await.unwrap();
        // The driver (woken by the push) flushes the Data segment out.
        let deadline = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(deadline);
        loop {
            if !sent.lock().is_empty() {
                break;
            }
            let _ = tokio::select! {
                () = &mut deadline => panic!("no datagram sent"),
                () = tokio::time::sleep(Duration::from_millis(5)) => 1u8,
            };
        }
        let segs = parse_sent(&sent.lock());
        match &segs[0] {
            Segment::Data { sn, payload, .. } => {
                assert_eq!(sn, &0);
                assert_eq!(&payload[..], b"hello kcp");
            }
            _ => panic!("expected Data"),
        }
        // Peer acks + echoes the data back.
        session.input(&ack_seg(7, 1000, 1, 1000, &[0]));
        session.input(&data_seg(7, 0, 1500, 0, 0, b"echo"));
        let mut buf = [0u8; 32];
        let n = tokio::time::timeout(Duration::from_secs(2), session.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"echo");
    }

    #[tokio::test]
    async fn facade_read_eof_after_close() {
        let (_sent, out) = sent_collector();
        let session = KcpSession::new(7, settings(), out);
        session.close();
        let mut buf = [0u8; 4];
        let n = session.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF
        let err = session.write(b"x").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        // Empty-buffer read returns immediately (AsyncRead contract).
        let n = session.read(&mut []).await.unwrap();
        assert_eq!(n, 0);
    }
}
