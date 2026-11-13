//! The tracing allocator itself.
//!
//! Every block carries one 8-byte header immediately before the payload:
//! `tag | payload_offset << 32`. That single word is the whole reason a free is
//! cheap — the symbol id is read back from the block, so there is no
//! `pointer → symbol` map to lock, hash or grow.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr;
use std::sync::atomic::Ordering::Relaxed;

use crate::attrib;
use crate::table::{ALLOCS, DEALLOCS, LIVE_BYTES, NO_TAG, PEAK_LIVE_BYTES};

/// The header word: low 32 bits the row tag, high 32 the payload offset.
const HEADER: usize = size_of::<u64>();

/// A `#[global_allocator]` that charges every allocation to a workspace module.
///
/// Install it as the process allocator, call [`crate::start`] and take
/// [`crate::snapshot`]s; before `start` it behaves like `System` and records
/// nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingAllocator;

impl TracingAllocator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// The payload's offset into the block: the user's alignment, never less than
/// the header word. Block alignment equals the offset, so the payload lands on
/// the requested boundary and the header stays 8-byte aligned.
const fn offset_for(align: usize) -> usize {
    if align > HEADER { align } else { HEADER }
}

/// The wrapper layout for `size` payload bytes, or `None` on overflow.
fn block(size: usize, offset: usize) -> Option<Layout> {
    Layout::from_size_align(size.checked_add(offset)?, offset).ok()
}

// SAFETY: `payload` was returned by `alloc`/`realloc` of this allocator, so the
// eight bytes below it belong to this allocator's block.
unsafe fn store_header(payload: *mut u8, tag: u32, offset: usize) {
    let word = (u64::try_from(offset).unwrap_or(0) << 32) | u64::from(tag);
    // SAFETY: the caller guarantees the block layout; unaligned writes need none.
    unsafe { payload.sub(HEADER).cast::<u64>().write_unaligned(word) };
}

// SAFETY: `payload` was returned by this allocator, so `payload - 8` is inside
// its block.
unsafe fn read_header(payload: *mut u8) -> (u32, usize) {
    // SAFETY: see above; an unaligned read is always sound for `u64`.
    let word = unsafe { payload.sub(HEADER).cast::<u64>().read_unaligned() };
    let tag = u32::try_from(word & u64::from(u32::MAX)).unwrap_or(NO_TAG);
    let offset = usize::try_from(word >> 32).unwrap_or(HEADER);
    (tag, offset)
}

fn record_alloc(tag: u32, bytes: usize) {
    if tag == NO_TAG {
        return;
    }
    ALLOCS.fetch_add(1, Relaxed);
    let live = LIVE_BYTES.fetch_add(bytes, Relaxed) + bytes;
    PEAK_LIVE_BYTES.fetch_max(live, Relaxed);
    if let Some(stats) = attrib::state().and_then(|state| state.stats(tag)) {
        stats.alloc(bytes);
    }
}

fn record_dealloc(tag: u32, bytes: usize) {
    if tag == NO_TAG {
        return;
    }
    DEALLOCS.fetch_add(1, Relaxed);
    let _ = LIVE_BYTES.try_update(Relaxed, Relaxed, |live| Some(live.saturating_sub(bytes)));
    if let Some(stats) = attrib::state().and_then(|state| state.stats(tag)) {
        stats.dealloc(bytes);
    }
}

fn record_grow(tag: u32, old: usize, new: usize) {
    if tag == NO_TAG || old == new {
        return;
    }
    if new > old {
        let delta = new - old;
        let live = LIVE_BYTES.fetch_add(delta, Relaxed) + delta;
        PEAK_LIVE_BYTES.fetch_max(live, Relaxed);
    } else {
        let delta = old - new;
        let _ = LIVE_BYTES.try_update(Relaxed, Relaxed, |live| Some(live.saturating_sub(delta)));
    }
    if let Some(stats) = attrib::state().and_then(|state| state.stats(tag)) {
        stats.grow(old, new);
    }
}

// SAFETY: every method forwards a correctly offset `Layout` to `System` and
// returns the shifted payload pointer; the header is written inside the block
// this allocator owns.
unsafe impl GlobalAlloc for TracingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let offset = offset_for(layout.align());
        let Some(block) = block(layout.size(), offset) else {
            return ptr::null_mut();
        };
        // SAFETY: `block` covers the payload plus the header; `System` is the
        // allocator the linker installed for this process.
        let base = unsafe { System.alloc(block) };
        if base.is_null() {
            return base;
        }
        // SAFETY: `offset < block.size()` by construction.
        let payload = unsafe { base.add(offset) };
        // Already inside the tracer: forward the memory, charge it to no row.
        let tag = attrib::enter().map_or(NO_TAG, |_guard| {
            let tag = attrib::attribute(layout.size());
            record_alloc(tag, layout.size());
            tag
        });
        // SAFETY: `payload` is inside the block this allocator owns.
        unsafe { store_header(payload, tag, offset) };
        payload
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let offset = offset_for(layout.align());
        let Some(block) = block(layout.size(), offset) else {
            return ptr::null_mut();
        };
        // SAFETY: as in `alloc`; the whole block — header included — comes back
        // zeroed, and the header is overwritten below.
        let base = unsafe { System.alloc_zeroed(block) };
        if base.is_null() {
            return base;
        }
        // SAFETY: `offset < block.size()` by construction.
        let payload = unsafe { base.add(offset) };
        // Already inside the tracer: forward the memory, charge it to no row.
        let tag = attrib::enter().map_or(NO_TAG, |_guard| {
            let tag = attrib::attribute(layout.size());
            record_alloc(tag, layout.size());
            tag
        });
        // SAFETY: `payload` is inside the block this allocator owns.
        unsafe { store_header(payload, tag, offset) };
        payload
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: `ptr` came from this allocator.
        let (tag, offset) = unsafe { read_header(ptr) };
        let Some(old_block) = block(layout.size(), offset) else {
            return ptr::null_mut();
        };
        let Some(new_block) = block(new_size, offset) else {
            return ptr::null_mut();
        };
        // SAFETY: `ptr - offset` is the block base this allocator allocated, and
        // `new_block` keeps the offset (hence the payload alignment) intact. The
        // header sits inside the block, so a move carries it along.
        let base = unsafe { System.realloc(ptr.sub(offset), old_block, new_block.size()) };
        if base.is_null() {
            return base;
        }
        // SAFETY: `offset < block.size()` by construction.
        let payload = unsafe { base.add(offset) };
        if let Some(_guard) = attrib::enter() {
            record_grow(tag, layout.size(), new_size);
        }
        payload
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator.
        let (tag, offset) = unsafe { read_header(ptr) };
        if let Some(_guard) = attrib::enter() {
            record_dealloc(tag, layout.size());
        }
        // The stored offset, not `layout.align()`, is the block's alignment:
        // an 8-byte-aligned payload may have come from a 1-byte-aligned request.
        let Some(block) = block(layout.size(), offset) else {
            debug_assert!(false, "dealloc with an overflowing layout");
            return;
        };
        // SAFETY: `ptr - offset` is the base this allocator allocated.
        unsafe { System.dealloc(ptr.sub(offset), block) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_offset_never_undercuts_the_header() {
        assert_eq!(offset_for(1), HEADER);
        assert_eq!(offset_for(8), HEADER);
        assert_eq!(offset_for(16), 16);
        assert_eq!(offset_for(4096), 4096);
    }

    /// The whole design rests on this: the shifted payload keeps the alignment
    /// the caller asked for, and the header word reads back unchanged.
    #[test]
    fn header_round_trips_and_payload_stays_aligned() {
        for align in [1_usize, 8, 16, 64, 4096] {
            let layout = Layout::from_size_align(64, align).expect("layout");
            let offset = offset_for(layout.align());
            let block = block(layout.size(), offset).expect("block");
            // SAFETY: a test-local block allocated and freed here.
            let base = unsafe { System.alloc(block) };
            assert!(!base.is_null());
            // SAFETY: `offset < block.size()`.
            let payload = unsafe { base.add(offset) };
            assert_eq!(
                payload as usize % align,
                0,
                "align {align} lost through the header"
            );
            // SAFETY: `payload` is inside the block.
            unsafe { store_header(payload, 42, offset) };
            // SAFETY: as above.
            assert_eq!(unsafe { read_header(payload) }, (42, offset));
            // SAFETY: the block this test allocated.
            unsafe { System.dealloc(base, block) };
        }
    }

    #[test]
    fn the_largest_tag_survives_the_round_trip() {
        let layout = Layout::from_size_align(8, 8).expect("layout");
        let offset = offset_for(layout.align());
        let block = block(layout.size(), offset).expect("block");
        // SAFETY: a test-local block allocated and freed here.
        let base = unsafe { System.alloc(block) };
        // SAFETY: `offset < block.size()`.
        let payload = unsafe { base.add(offset) };
        // SAFETY: `payload` is inside the block.
        unsafe { store_header(payload, u32::MAX - 1, offset) };
        // SAFETY: as above.
        assert_eq!(unsafe { read_header(payload) }.0, u32::MAX - 1);
        // SAFETY: the block this test allocated.
        unsafe { System.dealloc(base, block) };
    }
}
