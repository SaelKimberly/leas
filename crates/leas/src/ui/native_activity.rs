use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};

use crossterm::event::{KeyCode, KeyEvent};
use leas_core::format_bytes;
use leas_native::telemetry::{TraceKind, TraceSecurity};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::AppState;
use crate::NativeActivityEntry;
use crate::ui::theme::ThemeStyles;

/// Scroll offset from the bottom of the entry list (0 = newest visible),
/// mirroring the Logs tab conventions (`Up` = older, `Down` = newer,
/// `Home` = oldest, `End` = newest).
///
/// Module-local because `AppState` is owned by the state slice: the
/// cross-file contract only provides `state.native_activity` plus
/// `record_native_trace`, so per-screen view state lives here.
static SCROLL: AtomicUsize = AtomicUsize::new(0);

/// Drop the scroll offset: a new native session replaced the ring, so an
/// offset measured against the previous session's rows means nothing.
pub fn reset_scroll() {
    SCROLL.store(0, Ordering::Relaxed);
}

/// The current scroll offset, clamped to a ring of `len` rows and stored back
/// clamped, so the next key press starts from a row that exists.
///
/// The offset counts rows back from the newest, so `len - 1` (the oldest row
/// on screen) is the deepest meaningful value. Storing anything larger — the
/// old `Home` sentinel `usize::MAX` — stalls `Down`/`PageDown`: they
/// subtract from an offset the view never actually reached, so the window
/// does not budge until the subtraction crosses `len`.
fn clamp_scroll(len: usize) -> usize {
    // Clamp and read in one RMW: this runs on every frame.
    let max = len.saturating_sub(1);
    SCROLL.fetch_min(max, Ordering::Relaxed).min(max)
}

/// Render the `NativeActivity` tab: session totals plus one line per connection.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let block = Block::default()
        .title(" Native Activity ")
        .borders(Borders::ALL)
        .border_style(ThemeStyles::container_border(theme))
        .title_style(ThemeStyles::container_title(theme));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Only the in-process native core emits trace events.
    if state.connected_core != Some(leas_core::CoreType::Native) {
        let paragraph = Paragraph::new(
            " No native session — connect with the native core to see live connections ",
        )
        .style(ThemeStyles::hint(theme))
        .alignment(Alignment::Center);
        frame.render_widget(paragraph, inner);
        return;
    }

    let log = &state.native_activity;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(inner);

    let header = vec![
        Line::from(vec![
            Span::raw(" Session "),
            Span::raw(format!("↑{} ", format_bytes(saturating_i64(log.total_up)))),
            Span::raw(format!("↓{}", format_bytes(saturating_i64(log.total_down)))),
        ]),
        Line::from(format!(
            " open {} · failed {} · {} connections",
            log.open_count,
            log.fail_count,
            log.entries.len(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(header).style(ThemeStyles::hint(theme)),
        chunks[0],
    );

    if log.entries.is_empty() {
        let paragraph =
            Paragraph::new(" No connections recorded yet. ").style(ThemeStyles::hint(theme));
        frame.render_widget(paragraph, chunks[1]);
        return;
    }

    // Window first, format second: the ring holds up to 2000 rows, of which
    // only the visible slice is worth a `Line`.
    let height = chunks[1].height as usize;
    let total = log.entries.len();
    let start = total.saturating_sub(height.saturating_add(clamp_scroll(total)));
    let visible: Vec<Line> = log
        .entries
        .range(start..)
        .take(height)
        .map(|entry| render_entry(entry, theme))
        .collect();
    frame.render_widget(Paragraph::new(visible), chunks[1]);
}

/// Handle key events for the `NativeActivity` tab (scrolling only).
pub fn handle_key(state: &mut AppState, key: &KeyEvent) {
    // A short terminal still pages by one row: the documented keys must move.
    let page = (state.term_height.get().saturating_sub(5) as usize).max(1);
    let max = state.native_activity.entries.len().saturating_sub(1);
    let scroll = SCROLL.load(Ordering::Relaxed).min(max);
    if let Some(next) = next_scroll(key.code, scroll, page, max) {
        SCROLL.store(next, Ordering::Relaxed);
    }
}

/// The offset `code` scrolls to from `scroll`, or `None` when the key is not
/// one of the six scroll keys. `max` is the deepest reachable offset
/// (`entries.len() - 1`); every result is clamped into `0..=max`.
fn next_scroll(code: KeyCode, scroll: usize, page: usize, max: usize) -> Option<usize> {
    let next = match code {
        KeyCode::Up => scroll.saturating_add(1),
        KeyCode::Down => scroll.saturating_sub(1),
        KeyCode::PageUp => scroll.saturating_add(page),
        KeyCode::PageDown => scroll.saturating_sub(page),
        KeyCode::Home => max,
        KeyCode::End => 0,
        _ => return None,
    };
    Some(next.min(max))
}

/// One line per connection:
/// `[id] kind dest [protocol/transport] [security] up↑ down↓ dur err`.
fn render_entry(entry: &NativeActivityEntry, theme: &opaline::Theme) -> Line<'static> {
    let mut text = format!(
        "[{}] {} {} [{}/{}] [{}] ↑{} ↓{} {}ms",
        entry.conn_id,
        kind_label(entry.kind),
        entry.dest,
        entry.protocol,
        entry.transport,
        security_label(entry.security),
        format_bytes(saturating_i64(entry.up)),
        format_bytes(saturating_i64(entry.down)),
        entry.duration_ms,
    );
    if let Some(err) = entry.error.as_deref() {
        let _ = write!(text, " err: {err}");
    }
    let style = if entry.closed {
        if entry.error.is_some() {
            ThemeStyles::error(theme)
        } else {
            ThemeStyles::hint(theme)
        }
    } else {
        ThemeStyles::table_row_normal(theme)
    };
    Line::from(Span::styled(text, style))
}

/// Short kind label for the per-connection line.
const fn kind_label(kind: TraceKind) -> &'static str {
    match kind {
        TraceKind::Tcp => "TCP",
        TraceKind::UdpAssoc => "UDP",
        TraceKind::Http => "HTTP",
    }
}

/// Short security label for the per-connection line.
const fn security_label(security: TraceSecurity) -> &'static str {
    match security {
        TraceSecurity::Plain => "plain",
        TraceSecurity::Tls => "tls",
        TraceSecurity::Reality => "reality",
    }
}

/// `u64` counters into `format_bytes(i64)` without wrapping on huge values.
fn saturating_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_keys_always_move_inside_the_ring() {
        // Ten recorded rows: offsets 0..=9 are reachable.
        let max = 9;
        // `Home` lands on the oldest row instead of a `usize::MAX` sentinel,
        // so the next `Down` immediately walks back toward the newest row.
        let home = next_scroll(KeyCode::Home, 0, 5, max).expect("Home scrolls");
        assert_eq!(home, max);
        assert_eq!(next_scroll(KeyCode::Down, home, 5, max), Some(max - 1));
        assert_eq!(next_scroll(KeyCode::End, home, 5, max), Some(0));
        // Up/PageUp stop at the oldest row, PageDown steps a page toward new.
        assert_eq!(next_scroll(KeyCode::Up, max, 5, max), Some(max));
        assert_eq!(next_scroll(KeyCode::PageUp, 7, 5, max), Some(max));
        assert_eq!(next_scroll(KeyCode::PageDown, 7, 5, max), Some(2));
        assert_eq!(next_scroll(KeyCode::Down, 0, 5, max), Some(0));
        // Everything else belongs to the global handler.
        assert_eq!(next_scroll(KeyCode::Char('q'), 0, 5, max), None);
    }

    #[test]
    fn empty_ring_pins_every_key_to_zero() {
        assert_eq!(next_scroll(KeyCode::Home, 0, 5, 0), Some(0));
        assert_eq!(next_scroll(KeyCode::Up, 0, 5, 0), Some(0));
        assert_eq!(next_scroll(KeyCode::PageUp, 0, 5, 0), Some(0));
    }
}
