//! Process-wide clipboard owner.
//!
//! `arboard::Clipboard` is not a plain setter on Linux: the handle *is* the X11
//! selection owner. Dropping it destroys the serving window and joins the
//! request thread (`arboard` x11.rs `Drop`, `strong_count == MIN_OWNERS`), so
//! a create-set-drop call only leaves the payload readable when a clipboard
//! manager wins the 100 ms handover race inside `Drop`. On a desktop with no
//! clipboard manager — or headless, or over SSH — the text is gone the instant
//! the handle drops, while `set_text` has already returned `Ok`.
//!
//! So the handle is created on first use and kept for the process lifetime;
//! every writer goes through [`set_text`]. Nothing here holds the payload: X11
//! pulls it from the serving thread on demand. An environment with no display
//! at all gets an error per call, never a panic — see [`CLIPBOARD`].

// The test seam's `thread_local!` initializer is already a `const` block whose
// `RefCell::new` is const-qualifiable, so `missing_const_for_thread_local` fires
// on it anyway — the false positive in clippy#17566 (the repo's three
// `leas-native` warnings are the same lint). An `allow` on the macro invocation
// itself is ignored (it produces its own `unused_attributes` warning), so the
// suppression sits at module level, where it reaches the expansion.
#![allow(
    clippy::missing_const_for_thread_local,
    reason = "false positive on an already-const initializer: clippy#17566"
)]

#[cfg(test)]
use std::cell::RefCell;
use std::sync::{LazyLock, Mutex};

// Test seam for `get_text`: a headless test host has no clipboard, so the paste
// path is driven by installing a payload here.
//
// Strict and thread-local on purpose. An installed payload is authoritative; an
// empty one reports "no clipboard" instead of falling through to a real handle.
// Falling through let a test read whatever happened to be on the developer's
// clipboard. Thread-local, because the slot used to be process-global: tests run
// in parallel, so two of them raced on one payload and a passing test failed
// whenever the other happened to run alongside it.
#[cfg(test)]
std::thread_local! {
    static TEST_CLIPBOARD: RefCell<String> = const { RefCell::new(String::new()) };
}

/// The one handle, created on first use and kept for the process lifetime —
/// the selection owner must outlive every individual copy.
///
/// The cell holds an `Option` and initializes infallibly on purpose: a
/// headless / SSH / no-display session has no clipboard at all, and
/// `arboard::Clipboard::new()` fails there. Panicking (or panicking inside a
/// `LazyLock`, which poisons it for the rest of the process) would turn one
/// unavailable clipboard into every later copy and export panicking too. So a
/// failed attempt stores `None`, reports the error to this one caller, and is
/// retried on the next call — a display that appears later recovers.
static CLIPBOARD: LazyLock<Mutex<Option<arboard::Clipboard>>> = LazyLock::new(|| Mutex::new(None));

// `set_text`/`get_text` need `&mut`, so the guard necessarily spans the
// call — it cannot be dropped before `f`. The section is still bounded to one
// call and never held across an await, so a slow or dead clipboard cannot
// block the UI task behind it.
#[allow(
    clippy::significant_drop_tightening,
    reason = "the guard must outlive the &mut borrow passed to `f`"
)]
fn with_clipboard<T>(
    f: impl FnOnce(&mut arboard::Clipboard) -> Result<T, String>,
) -> Result<T, String> {
    let mut slot = CLIPBOARD
        .lock()
        .map_err(|_| "clipboard lock poisoned".to_string())?;
    let clipboard = match slot.as_mut() {
        Some(clipboard) => clipboard,
        None => slot.insert(
            arboard::Clipboard::new().map_err(|error| format!("clipboard unavailable: {error}"))?,
        ),
    };
    f(clipboard)
}

/// Copy `text` to the system clipboard, keeping ownership alive afterwards.
///
/// Errors are returned so callers can surface them; the previous behaviour of
/// swallowing them is what made a silent no-op indistinguishable from success.
pub fn set_text(text: String) -> Result<(), String> {
    with_clipboard(|clipboard| {
        clipboard
            .set_text(text)
            .map_err(|error| format!("clipboard set failed: {error}"))
    })
}

/// Read the current clipboard text. Used by the paste path.
///
/// The test seam is authoritative: an installed payload is returned as-is, and
/// an empty one means "no clipboard" — never a fall-through to a real handle,
/// which would read whatever happened to be on the developer's clipboard.
pub fn get_text() -> Result<String, String> {
    #[cfg(test)]
    {
        test_clipboard()
    }
    #[cfg(not(test))]
    {
        with_clipboard(|clipboard| {
            clipboard
                .get_text()
                .map_err(|error| format!("clipboard get failed: {error}"))
        })
    }
}

/// The test-only clipboard reader (see [`get_text`]).
#[cfg(test)]
fn test_clipboard() -> Result<String, String> {
    TEST_CLIPBOARD.with(|slot| Ok(slot.borrow().clone()))
}

/// Install `payload` as the test clipboard and return a guard that clears it.
#[cfg(test)]
#[must_use]
pub fn set_test_clipboard(payload: &str) -> TestClipboardGuard {
    TEST_CLIPBOARD.with(|slot| *slot.borrow_mut() = payload.to_string());
    TestClipboardGuard
}

/// Clears the test clipboard on drop, so a payload cannot leak into the next
/// test on the same worker thread. The cell returns to its empty state, which
/// the strict reader reports as "no clipboard".
#[cfg(test)]
pub struct TestClipboardGuard;

#[cfg(test)]
impl Drop for TestClipboardGuard {
    fn drop(&mut self) {
        TEST_CLIPBOARD.with(|slot| slot.borrow_mut().clear());
    }
}
