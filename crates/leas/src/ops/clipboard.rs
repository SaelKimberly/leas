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

use std::sync::{LazyLock, Mutex};

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
pub fn get_text() -> Result<String, String> {
    with_clipboard(|clipboard| {
        clipboard
            .get_text()
            .map_err(|error| format!("clipboard get failed: {error}"))
    })
}
