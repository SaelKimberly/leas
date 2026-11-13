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
    CACHE_HITS, CACHE_RESOLVES, Cached, LIVE_BYTES, NO_TAG, OVERFLOWED, State, UNTRACED,
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
pub fn start(roots: &'static [&'static str], min_bytes: usize) -> bool {
    STATE.set(State::new(roots, min_bytes)).is_ok()
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
    let mut frames = [0_usize; MAX_FRAMES];
    let captured = capture(&mut frames);
    for &ip in &frames[..captured] {
        match state.cache_get(ip) {
            Some(Cached::Row(id)) => {
                CACHE_HITS.fetch_add(1, Relaxed);
                return id;
            }
            Some(Cached::Foreign) => {
                CACHE_HITS.fetch_add(1, Relaxed);
            }
            None => {
                CACHE_RESOLVES.fetch_add(1, Relaxed);
                match module_of(ip, state.roots) {
                    Some(module) => {
                        let id = row_for(state, &module, &frames[..captured]);
                        state.cache_put(ip, Cached::Row(id));
                        return id;
                    }
                    None => state.cache_put(ip, Cached::Foreign),
                }
            }
        }
    }
    UNTRACED
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
        OVERFLOWED.store(true, Relaxed);
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
    segments.pop()?;
    let module = segments.join("::");
    roots
        .iter()
        .any(|root| under_root(&module, root))
        .then_some(module)
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

    const ROOTS: &[&str] = &["leas", "leas_native"];

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
