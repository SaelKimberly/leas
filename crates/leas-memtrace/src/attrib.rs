//! Attribution: walk the stack, resolve a frame's module once, remember it.
//!
//! The hot path captures up to [`MAX_FRAMES`] instruction pointers with
//! `backtrace::trace` (frame pointers only — no symbolization) and asks the
//! cache about each one. Symbolization happens on a cache miss only, and the
//! cache is keyed by the frame's instruction pointer, which is the call site's
//! return address: stable for the life of the process, so a warm run resolves a
//! few dozen addresses in total.

use std::cell::Cell;
use std::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::Ordering::Relaxed;

use crate::table::{
    ATTRIBUTED, CACHE_HITS, CACHE_RESOLVES, Cached, FRAMES_WALKED, LIVE_BYTES, NO_TAG, OVERFLOWED,
    State, UNTRACED,
};

/// Bounded capture: enough to cross the `std` allocation shims and the tracer's
/// own frames and still reach the caller's module, cheap enough to be on every
/// allocation.
const MAX_FRAMES: usize = 32;

/// Innermost workspace modules kept per symbol for the folded-stack artifact.
const MAX_FOLD_DEPTH: usize = 8;

static STATE: OnceLock<State> = OnceLock::new();

thread_local! {
    /// Set while this thread is inside the tracer. An allocation made from the
    /// tracer's own bookkeeping (a `String`, the unwinder's internals) forwards
    /// straight to `System` and is charged to no row.
    static IN_TRACER: Cell<bool> = const { Cell::new(false) };
}

/// Held for the length of one traced allocation; clearing on `Drop` keeps a
/// panic from permanently disabling tracing on that thread.
pub struct Reentry;

impl Drop for Reentry {
    fn drop(&mut self) {
        IN_TRACER.with(|cell| cell.set(false));
    }
}

/// Enter the tracer, or `None` when this thread is already inside it.
pub fn enter() -> Option<Reentry> {
    IN_TRACER.with(|cell| {
        if cell.get() {
            return None;
        }
        cell.set(true);
        Some(Reentry)
    })
}

/// Start a trace window. Idempotent: returns `false` when one already runs.
///
/// `roots` are crate-name prefixes whose modules are attributed; `min_bytes`
/// sends smaller allocations to the `<untraced>` row (0 traces everything).
#[must_use]
pub fn start(roots: &'static [&'static str], min_bytes: usize) -> bool {
    start_with(roots, min_bytes, &[])
}

/// Like [`start`], with metadata the artifacts echo: feature set, binary name,
/// dataset — whatever makes two runs distinguishable without a transcript.
#[must_use]
pub fn start_with(
    roots: &'static [&'static str],
    min_bytes: usize,
    metadata: &'static [(&'static str, &'static str)],
) -> bool {
    STATE.set(State::new(roots, min_bytes, metadata)).is_ok()
}

/// The metadata the running window was started with (empty when not started).
#[must_use]
pub fn metadata() -> &'static [(&'static str, &'static str)] {
    STATE.get().map_or(&[], |state| state.metadata)
}

/// Whether a trace window is running.
#[must_use]
pub fn is_started() -> bool {
    STATE.get().is_some()
}

/// Bytes allocated and still live, across every row including `<untraced>`.
#[must_use]
pub fn live_bytes() -> usize {
    LIVE_BYTES.load(Relaxed)
}

pub fn state() -> Option<&'static State> {
    STATE.get()
}

/// The row this allocation belongs to, or [`NO_TAG`] when the tracer must not
/// account for it at all.
pub fn attribute(size: usize) -> u32 {
    let Some(state) = STATE.get() else {
        return NO_TAG;
    };
    if size < state.min_bytes {
        return UNTRACED;
    }
    ATTRIBUTED.fetch_add(1, Relaxed);
    // Probe while capturing: the walk stops at the first frame that already
    // resolves, so a repeated allocation pays the depth to its row instead of
    // `MAX_FRAMES`. A row's *first* sight still needs the callers, because the
    // folded path is the one output that depends on stack depth — that cold
    // path walks again below, once per instruction pointer (~5 700 per run).
    let mut frames = [0_usize; MAX_FRAMES];
    let mut walked = 0_usize;
    let mut resolved: Option<u32> = None;
    let mut fresh: Option<(usize, String)> = None;
    backtrace::trace(|frame| {
        let ip = frame.ip() as usize;
        if walked < MAX_FRAMES {
            frames[walked] = ip;
        }
        walked += 1;
        match state.cache_get(ip) {
            Some(Cached::Row(id)) => {
                CACHE_HITS.fetch_add(1, Relaxed);
                resolved = Some(id);
                return false;
            }
            Some(Cached::Foreign) => {
                CACHE_HITS.fetch_add(1, Relaxed);
            }
            None => {
                CACHE_RESOLVES.fetch_add(1, Relaxed);
                match key_of(ip, state.roots, state.rows == "symbol") {
                    Some(module) => {
                        fresh = Some((ip, module));
                        return false;
                    }
                    None => state.cache_put(ip, Cached::Foreign),
                }
            }
        }
        walked < MAX_FRAMES
    });
    if let Some(id) = resolved {
        FRAMES_WALKED.fetch_add(walked, Relaxed);
        return id;
    }
    let Some((ip, module)) = fresh else {
        FRAMES_WALKED.fetch_add(walked, Relaxed);
        return UNTRACED;
    };
    let mut full = [0_usize; MAX_FRAMES];
    let captured = capture(&mut full);
    FRAMES_WALKED.fetch_add(walked + captured, Relaxed);
    // The folded path must describe the stack that produced the row. Both walks
    // sample the same call site on the same thread, but if the second did not
    // contain the frame the first resolved on (a signal handler interrupting the
    // stack between passes), fall back to the frames the first pass captured.
    let path_frames = if full[..captured].contains(&ip) {
        &full[..captured]
    } else {
        &frames[..walked.min(MAX_FRAMES)]
    };
    let id = row_for(state, &module, path_frames);
    state.cache_put(ip, Cached::Row(id));
    id
}

/// Frame pointers only: no symbolization, no allocation for the common case.
fn capture(buf: &mut [usize]) -> usize {
    let mut count = 0;
    // `backtrace::trace`'s callback returns `false` to stop the walk.
    backtrace::trace(|frame| {
        if count == buf.len() {
            return false;
        }
        buf[count] = frame.ip() as usize;
        count += 1;
        true
    });
    count
}

/// The row for `module`, created on first sight, with its folded path recorded.
fn row_for(state: &State, module: &str, frames: &[usize]) -> u32 {
    // A poisoned registry still holds the rows — a panic somewhere else must
    // not silently turn every later allocation into `<untraced>`.
    let mut registry = state
        .registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(id) = registry.row(module) else {
        OVERFLOWED.fetch_add(1, Relaxed);
        return UNTRACED;
    };
    if !registry.folded().contains_key(&id) {
        let path = folded_path(frames, state.roots);
        registry.set_folded(id, path);
    }
    id
}

/// The innermost ≤[`MAX_FOLD_DEPTH`] workspace modules on the captured stack,
/// innermost first. Resolved once per symbol, never per allocation.
fn folded_path(frames: &[usize], roots: &'static [&'static str]) -> Vec<String> {
    let mut path: Vec<String> = Vec::new();
    for &ip in frames {
        if let Some(module) = module_of(ip, roots) {
            // Nested calls inside one module are one folded frame, not five.
            if path.last() == Some(&module) {
                continue;
            }
            path.push(module);
            if path.len() == MAX_FOLD_DEPTH {
                break;
            }
        }
    }
    path
}

/// The workspace module a frame belongs to, if any.
fn module_of(ip: usize, roots: &'static [&'static str]) -> Option<String> {
    // The captured address is a return address, which can sit one byte past the
    // call instruction — probing `ip - 1` resolves the call, not its caller.
    let probe = ip.wrapping_sub(1) as *mut c_void;
    let mut found = None;
    backtrace::resolve(probe, |symbol| {
        if found.is_some() {
            return;
        }
        if let Some(name) = symbol.name()
            && let Some(module) = module_path(&name.to_string(), roots)
        {
            found = Some(module);
        }
    });
    found
}

/// `leas_native::protocol::vless::header::encode_request::h1f2…` →
/// `leas_native::protocol::vless::header`, but only when it sits under `roots`.
///
/// A demangled Rust name ends in noise: the hash, then any generic arguments,
/// then closure shims. Peel those, then drop the function itself — what remains
/// is the module that owns it.
pub fn module_path(name: &str, roots: &'static [&'static str]) -> Option<String> {
    path_parts(name, roots).map(|(module, _)| module)
}

/// `(module, function)` for a demangled workspace symbol, or `None` when the
/// symbol belongs to no root.
fn path_parts(name: &str, roots: &'static [&'static str]) -> Option<(String, String)> {
    let cleaned = without_disambiguators(name);
    let mut segments = top_level_segments(&cleaned);
    while segments.last().is_some_and(|segment| is_noise(segment)) {
        segments.pop();
    }
    // A frame that is itself a `<Type as Trait>` has no module of its own; a
    // generic on top here is not the function, so there is nothing to strip.
    if segments.last().is_some_and(|segment| is_generic(segment)) {
        return None;
    }
    // The function: `encode_request`, `batch`, `{{closure}}` already peeled.
    let function = segments.pop()?.to_owned();
    let module = segments.join("::");
    roots
        .iter()
        .any(|root| under_root(&module, root))
        .then_some((module, function))
}

/// The row key for a demangled symbol: the module, or `module::function` when
/// the window asked for symbol rows (`LEAS_MEM_TRACE_ROWS=symbol`).
fn row_key(name: &str, roots: &'static [&'static str], by_symbol: bool) -> Option<String> {
    if by_symbol {
        path_parts(name, roots).map(|(module, function)| format!("{module}::{function}"))
    } else {
        module_path(name, roots)
    }
}

/// The row key for a frame, resolved once per instruction pointer.
fn key_of(ip: usize, roots: &'static [&'static str], by_symbol: bool) -> Option<String> {
    let probe = ip.wrapping_sub(1) as *mut c_void;
    let mut found = None;
    backtrace::resolve(probe, |symbol| {
        if found.is_some() {
            return;
        }
        let Some(name) = symbol.name() else {
            return;
        };
        found = row_key(&name.to_string(), roots, by_symbol);
    });
    found
}

/// Demangled names carry the crate's disambiguator, `leas_memtrace[23d599d2ee…]`.
/// It is not part of the path and would defeat the root prefix; drop it.
///
/// Only a bracketed run of exactly sixteen hex digits is removed, so array
/// types (`[u8; 4]`) and index expressions survive untouched.
fn without_disambiguators(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = String::with_capacity(name.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'['
            && let Some(close) = name[i + 1..].find(']')
        {
            let end = i + 1 + close;
            let inner = &name[i + 1..end];
            if inner.len() == 16 && inner.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                out.push_str(&name[copied..i]);
                copied = end + 1;
                i = copied;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&name[copied..]);
    out
}

/// `module` sits under `root` on a segment boundary, so `leas_native` matches
/// its root but `leasthing` matches nothing.
fn under_root(module: &str, root: &str) -> bool {
    module
        .strip_prefix(root)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
}

/// Split on `::` at angle-bracket depth zero, so a generic argument's own path
/// stays inside one segment.
fn top_level_segments(name: &str) -> Vec<&str> {
    let bytes = name.as_bytes();
    let mut segments = Vec::new();
    let mut depth = 0_i32;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => depth += 1,
            b'>' if i == 0 || bytes[i - 1] != b'-' => depth -= 1,
            b':' if depth == 0 && i + 1 < bytes.len() && bytes[i + 1] == b':' => {
                segments.push(&name[start..i]);
                i += 2;
                start = i;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    segments.push(&name[start..]);
    segments
}

/// Segments that are not part of the path: the trailing hash, generic
/// arguments, and closure shims.
fn is_noise(segment: &str) -> bool {
    segment.starts_with('{') || is_generic(segment) || is_hash(segment)
}

/// `<...>`: generic arguments, or a `<Type as Trait>` frame — never a module.
fn is_generic(segment: &str) -> bool {
    segment.starts_with('<') && segment.ends_with('>')
}

/// Rust's instantiating hash: `h` followed by 16 lowercase hex digits.
fn is_hash(segment: &str) -> bool {
    let Some(rest) = segment.strip_prefix('h') else {
        return false;
    };
    (16..=20).contains(&rest.len()) && rest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repeated site must stop the walk at its row: the fusion is the point
    /// of the change, and a regression that restores the full capture fails
    /// here (the artifact diff alone cannot see a walk that is merely slow).
    #[test]
    fn a_repeated_site_walks_one_frame_after_the_first() {
        assert!(
            start(&["leas_memtrace"], 0),
            "the tracer starts once per process"
        );
        let _warm = attribute(64);
        let before = FRAMES_WALKED.load(Relaxed);
        let _hit = attribute(64);
        let walked = FRAMES_WALKED.load(Relaxed) - before;
        // The first frames are `backtrace`/`std` shims, cached as foreign; the
        // hit follows within a few. Far below `MAX_FRAMES` is the point.
        assert!(
            walked <= 4,
            "a cache hit must stop the walk at the resolving frame, walked {walked}"
        );
    }

    const ROOTS: &[&str] = &["leas", "leas_native"];

    /// The grain switch itself: module rows collapse two functions of one module
    /// into one row, symbol rows keep them apart. A regression that inverted the
    /// flag or compared it against the wrong string fails here.
    #[test]
    fn row_grain_separates_functions_of_one_module() {
        let render = "leas::ui::render::h1f2e3d4c5b6a7988";
        let run = "leas::ui::run::{{closure}}";
        assert_eq!(row_key(render, ROOTS, false).as_deref(), Some("leas::ui"));
        assert_eq!(row_key(run, ROOTS, false).as_deref(), Some("leas::ui"));
        assert_eq!(
            row_key(render, ROOTS, true).as_deref(),
            Some("leas::ui::render")
        );
        assert_eq!(row_key(run, ROOTS, true).as_deref(), Some("leas::ui::run"));
        // A crate outside the roots stays unattributed under either grain.
        assert_eq!(row_key("core::mem::drop::h1234", ROOTS, true), None);
    }

    #[test]
    fn module_is_the_path_above_the_function() {
        assert_eq!(
            module_path(
                "leas_native::protocol::vless::header::encode_request::h1f2e3d4c5b6a7988",
                ROOTS
            )
            .as_deref(),
            Some("leas_native::protocol::vless::header")
        );
    }

    #[test]
    fn closure_shims_are_peeled() {
        assert_eq!(
            module_path(
                "leas::ops::ping::batch::{{closure}}::h1234567890abcdef",
                ROOTS
            )
            .as_deref(),
            Some("leas::ops::ping")
        );
        assert_eq!(
            module_path(
                "leas::ops::ping::batch::{{closure}}::{{closure}}::h1234567890abcdef",
                ROOTS
            )
            .as_deref(),
            Some("leas::ops::ping")
        );
    }

    /// Generics are their own segment; peeling them still leaves the function,
    /// so the module cannot stop at `spawn`.
    #[test]
    fn generic_arguments_do_not_shorten_the_path() {
        assert_eq!(
            module_path(
                "leas::ops::ping::spawn::<leas_native::client::Client>::h1234567890abcdef",
                ROOTS
            )
            .as_deref(),
            Some("leas::ops::ping")
        );
    }

    /// Symbolization appends the crate's disambiguating hash in brackets; the
    /// root prefix must still see `leas_memtrace::…` underneath it.
    #[test]
    fn crate_disambiguators_are_not_part_of_the_path() {
        assert_eq!(
            module_path(
                "leas_native[23d599d2ee5a0763]::protocol::vless::header::encode_request::h1f2e3d4c5b6a7988",
                ROOTS
            )
            .as_deref(),
            Some("leas_native::protocol::vless::header")
        );
        // An array type is not a disambiguator.
        assert_eq!(
            without_disambiguators("std::vec::IntoIter<[u8; 4]>::next"),
            "std::vec::IntoIter<[u8; 4]>::next"
        );
    }

    #[test]
    fn frames_outside_the_roots_are_not_attributed() {
        assert_eq!(
            module_path("std::vec::Vec<u8>::push::h1234567890abcdef", ROOTS),
            None
        );
        assert_eq!(
            module_path("tokio::runtime::task::run::h1234567890abcdef", ROOTS),
            None
        );
        // `leasthing` is not `leas`.
        assert_eq!(
            module_path("leasthing::inner::f::h1234567890abcdef", ROOTS),
            None
        );
    }

    #[test]
    fn a_name_without_a_hash_still_resolves() {
        assert_eq!(
            module_path("leas::ops::ping::batch", ROOTS).as_deref(),
            Some("leas::ops::ping")
        );
    }

    /// The real thing: capture this thread's stack and find this crate's module
    /// through the same path the allocator uses.
    #[test]
    fn a_captured_stack_resolves_to_this_module() {
        fn allocate_here() -> (usize, [usize; MAX_FRAMES]) {
            let mut frames = [0_usize; MAX_FRAMES];
            let captured = capture(&mut frames);
            (captured, frames)
        }
        let (captured, frames) = allocate_here();
        assert!(captured > 0, "no frames captured");
        let modules: Vec<String> = frames[..captured]
            .iter()
            .filter_map(|&ip| module_of(ip, &["leas_memtrace"]))
            .collect();
        assert!(
            modules
                .iter()
                .any(|module| module.starts_with("leas_memtrace::")),
            "no frame attributed to this crate: {modules:?}"
        );
    }
}
