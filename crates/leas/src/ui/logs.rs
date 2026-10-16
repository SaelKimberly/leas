use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use std::collections::{HashSet, VecDeque};

use crate::AppState;
use crate::ui::render_confirmation_overlay;
use crate::ui::theme::ThemeStyles;
use crate::ui::widgets::{Column, ColumnWidth, DataTable, DataTableRow, DataTableState};
use tui_popup::{KnownSizeWrapper, Popup};

// ── DataTable row type ────────────────────────────────────────────────

/// Pre-computed log row data for `DataTable` rendering. `target`/`level`/`msg`
/// borrow the cached [`crate::LogLine`] — the render pass must not clone a
/// String per row per frame; only the formatted `ts` is owned (one per
/// *visible* row, see [`build_rows_viewport`]).
struct LogRow<'a> {
    ts: String,
    target: &'a str,
    target_style: Style,
    level: &'a str,
    level_style: Style,
    msg: &'a str,
}

impl DataTableRow for LogRow<'_> {
    fn render(
        &self,
        col_xs: &[u16],
        col_widths: &[u16],
        _col_order: &[usize],
        buf: &mut ratatui::buffer::Buffer,
        y: u16,
        clip_bottom: u16,
    ) {
        if col_xs.len() < 4 {
            return;
        }
        // A multi-line log row may start below the clip line; its first
        // visible line would be past the frame, so draw nothing.
        if y >= clip_bottom {
            return;
        }
        buf.set_stringn(
            col_xs[0],
            y,
            &self.ts,
            col_widths[0] as usize,
            self.target_style,
        );
        buf.set_stringn(
            col_xs[1],
            y,
            self.target,
            col_widths[1] as usize,
            self.target_style,
        );
        buf.set_stringn(
            col_xs[2],
            y,
            self.level,
            col_widths[2] as usize,
            self.level_style,
        );
        buf.set_stringn(
            col_xs[3],
            y,
            self.msg,
            col_widths[3] as usize,
            Style::default(),
        );
    }

    fn height(&self, available_width: u16) -> u16 {
        let text_width = unicode_width::UnicodeWidthStr::width(self.msg);
        let msg_width = available_width.saturating_sub(25).max(1);
        1 + (text_width as u16).saturating_sub(1) / msg_width
    }
}

/// Narrow a [`crate::LogLine`] to its [`LogRow`] display form (borrows the
/// line; allocates only the formatted timestamp).
fn log_row_from<'a>(log: &'a crate::LogLine, theme: &opaline::Theme) -> LogRow<'a> {
    let target_style = if log.target.starts_with("xray") {
        ThemeStyles::log_info(theme)
    } else if log.target.starts_with("sing") {
        ThemeStyles::success(theme)
    } else if log.target == "tui" {
        ThemeStyles::log_warning(theme)
    } else {
        ThemeStyles::log_debug(theme)
    };
    let level_style = match log.level.as_str() {
        "error" | "fatal" | "panic" => ThemeStyles::error(theme),
        "warning" | "warn" => ThemeStyles::warning(theme),
        "debug" | "trace" => ThemeStyles::hint(theme),
        _ => Style::default(),
    };
    LogRow {
        ts: fmt_ts(log.timestamp_nanos),
        target: &log.target,
        target_style,
        level: &log.level,
        level_style,
        msg: &log.message,
    }
}

/// Materialize row data only for `cache[offset..offset + visible]` — the old
/// shape built one `LogRow` per filtered entry (up to 10k Strings per
/// frame); the render pass now passes just the visible window.
#[cfg(test)]
fn build_rows_viewport(cache: &[crate::LogLine], offset: usize, visible: usize) -> Vec<LogRow<'_>> {
    let theme = crate::ui::theme::load("tokyo-night").unwrap();
    let end = offset.saturating_add(visible).min(cache.len());
    cache
        .get(offset..end)
        .unwrap_or(&[])
        .iter()
        .map(|log| log_row_from(log, &theme))
        .collect()
}

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    render_inner(frame, area, state);
}

/// Pane-1 content: the pane frame supplies the border, so the log viewer
/// renders frameless (spec §6 — no nested boxes).
pub fn render_inner(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();

    // Filter bar (1 line)
    let (filter_area, log_area) = {
        let rects = Layout::default()
            .direction(ratatui::layout::Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(area);
        (rects[0], rects[1])
    };

    let active_count = state.selected_targets.len();
    let sel_active = state.log_select_anchor.is_some();
    let filter_label = if active_count > 0 {
        format!("({active_count} active)")
    } else {
        "(all)".into()
    };
    let filter_text = if sel_active {
        format!(
            " [T] Filter {filter_label}  \u{2191}\u{2193} Select  y Copy  Y All  PgUp/PgDn  Home/End  Esc done",
        )
    } else {
        format!(
            " [T] Filter {filter_label}  \u{2191}\u{2193} Scroll  y Copy  Shift+\u{2191}\u{2193} Select  PgUp/PgDn  Home/End",
        )
    };
    let bar = Line::from(Span::styled(filter_text, ThemeStyles::hint(theme)));
    frame.render_widget(Paragraph::new(bar), filter_area);

    let log_count = state.log_cache.len();
    if log_count == 0 {
        let empty_msg = if state.log_has_older {
            " Loading logs..."
        } else {
            " No logs yet. Run a profile or wait for core output."
        };
        let paragraph = Paragraph::new(Line::from(empty_msg)).style(ThemeStyles::hint(theme));
        frame.render_widget(paragraph, log_area);
        return;
    }

    // Filter cache by target — count only (no per-frame 10k-entry index
    // Vec): the window below streams the cache once and keeps just the rows
    // the viewport can show.
    let filtered_count = if state.selected_targets.is_empty() {
        log_count
    } else {
        state
            .log_cache
            .iter()
            .filter(|l| state.selected_targets.contains(&l.target))
            .count()
    };
    if filtered_count == 0 {
        let paragraph = Paragraph::new(Line::from(" No logs match current filter"))
            .style(ThemeStyles::hint(theme));
        frame.render_widget(paragraph, log_area);
        return;
    }

    let columns = vec![
        Column::new("Time", ColumnWidth::Fixed(25)),
        Column::new("Target", ColumnWidth::Ratio(1)),
        Column::new("Lvl", ColumnWidth::Fixed(5)),
        Column::new("Message", ColumnWidth::Ratio(4)),
    ];

    // Compute offset — during selection, pin viewport so entire range is visible
    let approx_visible = (log_area.height as usize).saturating_sub(2);
    // Publish the viewport so the key handler pages by what is actually on
    // screen. Pane 1 is a fraction of the terminal (pane 2 + status bar sit
    // below it), so the old terminal-height estimate paged roughly double.
    state.log_viewport_rows.set(approx_visible);
    let offset = state.log_select_anchor.map_or_else(
        || filtered_count.saturating_sub(state.log_scroll + approx_visible),
        |anchor| {
            let oldest_row = filtered_count.saturating_sub(state.log_scroll.max(anchor) + 1);
            let newest_row = filtered_count.saturating_sub(state.log_scroll.min(anchor) + 1);
            let range_height = newest_row.saturating_sub(oldest_row).saturating_add(1);
            if range_height <= approx_visible {
                oldest_row
            } else {
                filtered_count.saturating_sub(state.log_scroll + approx_visible)
            }
        },
    );
    // The DataTable receives ONLY the visible slice with offset 0; a window
    // starting past the last row would render an empty table (the old full-
    // slice path clamped internally). Clamp here so at least one row shows.
    let offset = offset.min(filtered_count.saturating_sub(1));

    // Materialize ONLY the visible window of the filtered stream: rows borrow
    // the cache lines, and the pass stops as soon as the window is filled.
    // Multi-line (wrapped) rows can exceed the area height, so build one row
    // of slack; the DataTable clips whatever overflows.
    let visible = approx_visible.saturating_add(1);
    let no_filter = state.selected_targets.is_empty();
    let mut log_rows: Vec<LogRow> = Vec::with_capacity(visible);
    let mut rank = 0usize;
    for log in &state.log_cache {
        if !no_filter && !state.selected_targets.contains(&log.target) {
            continue;
        }
        if rank >= offset {
            log_rows.push(log_row_from(log, theme));
            if log_rows.len() >= visible {
                break;
            }
        }
        rank += 1;
    }

    // Build multi-selection set from anchor range (offset-from-bottom),
    // translated into visible-window row indices (the slice starts at `offset`
    // in filtered space).
    let mut multi_selected = HashSet::new();
    if let Some(anchor) = state.log_select_anchor {
        let lo = state.log_scroll.min(anchor);
        let hi = state.log_scroll.max(anchor);
        // Convert offset-from-bottom to row indices (0 = oldest)
        let lo_row = filtered_count.saturating_sub(hi + 1);
        let hi_row = filtered_count.saturating_sub(lo + 1);
        let win_end = offset.saturating_add(log_rows.len());
        for i in lo_row..=hi_row {
            if i >= offset && i < win_end {
                multi_selected.insert(i - offset);
            }
        }
    }

    // Cursor row in filtered index space → visible-window selection
    let cursor_row = filtered_count.saturating_sub(state.log_scroll + 1);
    let selected = cursor_row
        .checked_sub(offset)
        .filter(|&s| s < log_rows.len());

    let data_table = DataTable::new(columns, &log_rows)
        .column_spacing(1)
        .selection_style(ThemeStyles::table_row_selected(theme))
        // The slice is the visible window; the scrollbar still reports the
        // full filtered length and the true offset.
        .total_rows(Some(filtered_count))
        .scrollbar_offset(Some(offset))
        .scrollbar(
            ThemeStyles::scrollbar_thumb(theme),
            ThemeStyles::scrollbar_track(theme),
        );
    let mut dt_state = DataTableState {
        offset: 0,
        selected,
        multi_selected,
    };
    frame.render_stateful_widget(data_table, log_area, &mut dt_state);

    if matches!(state.confirmation, Some(crate::ConfirmAction::ClearLogs)) {
        render_confirmation_overlay(frame, area, " Clear all logs? (y/N) ", state.theme());
    }
    if matches!(
        state.confirmation,
        Some(crate::ConfirmAction::PurgeLogsDatabase)
    ) {
        render_confirmation_overlay(
            frame,
            area,
            " Purge entire log database? (y/N) ",
            state.theme(),
        );
    }
}

/// Handle key events for the Logs tab.
pub async fn handle_key(state: &mut AppState, key: &KeyEvent) {
    // Page by what the viewport can actually show. `log_viewport_rows` is
    // published by the render pass; the fallback covers the first keypress
    // before any frame has drawn.
    let height = state.log_viewport_rows.get().max(1);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    match key.code {
        KeyCode::Up if shift => {
            state.log_select_anchor.get_or_insert(state.log_scroll);
            state.log_scroll = state.log_scroll.saturating_add(1);
            try_load_older(state).await;
            clamp_log_scroll(state);
        }
        KeyCode::Down if shift => {
            state.log_select_anchor.get_or_insert(state.log_scroll);
            state.log_scroll = state.log_scroll.saturating_sub(1);
            clamp_log_scroll(state);
        }
        KeyCode::Up => {
            state.log_scroll = state.log_scroll.saturating_add(1);
            try_load_older(state).await;
            clamp_log_scroll(state);
        }
        KeyCode::Down => {
            state.log_scroll = state.log_scroll.saturating_sub(1);
            clamp_log_scroll(state);
        }
        KeyCode::PageUp => {
            state.log_scroll = state.log_scroll.saturating_add(height);
            try_load_older(state).await;
            clamp_log_scroll(state);
        }
        KeyCode::PageDown => {
            state.log_scroll = state.log_scroll.saturating_sub(height);
            clamp_log_scroll(state);
        }
        KeyCode::Home => {
            // Oldest loaded row, not `usize::MAX`: the seek path in
            // `ui::run` walks the buffer to the true top and rewrites this,
            // and the sentinel only ever needed clamping on the way back.
            state.log_scroll = max_log_scroll(state);
            state.log_seek_home = state.log_has_older;
        }
        KeyCode::End => {
            state.log_scroll = 0;
        }
        KeyCode::Char('t' | 'T') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.mode = crate::AppMode::TargetPicker { selected: 0 };
        }
        KeyCode::Char('c') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.confirmation = Some(crate::ConfirmAction::ClearLogs);
        }
        KeyCode::Char('d') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(monitor) = crate::ops::db_monitor::global() {
                for line in monitor.dump(20) {
                    for l in line.split('\n') {
                        tracing::info!(target: "tui::db_monitor", "{l}");
                    }
                }
            }
        }
        KeyCode::Delete => {
            state.confirmation = Some(crate::ConfirmAction::PurgeLogsDatabase);
        }
        KeyCode::Char('y') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if state.log_select_anchor.is_some() {
                copy_selection(state);
            } else {
                copy_cursor_line(state);
            }
        }
        KeyCode::Char('Y') => {
            copy_all_filtered(state).await;
        }
        KeyCode::Esc => {
            state.log_select_anchor = None;
        }
        _ => {}
    }
}

/// Largest scroll offset the loaded buffer can express.
///
/// The viewport is bottom-anchored: the render places `approx_visible` rows
/// ABOVE the cursor, so the deepest legal position keeps the oldest visible
/// row at the TOP of the window — `filtered_count - viewport` when the buffer
/// is longer than a page. Bound at `filtered_count - 1` (one past the oldest
/// row) would let the cursor sit below the whole buffer, which pins the render
/// at row 0 and leaves a nearly blank pane — the "only a few lines on top"
/// symptom a user sees after repeated `PageUp`.
fn max_log_scroll(state: &AppState) -> usize {
    let filtered = count_filtered(state);
    let viewport = state.log_viewport_rows.get().max(1);
    filtered.saturating_sub(viewport.saturating_sub(1))
}

/// Pull `log_scroll` (and a live selection anchor) back inside the loaded
/// buffer.
///
/// This is the single owner of the bound. `log_scroll` used to grow without
/// limit: `Up` past the oldest row kept incrementing while the render's
/// `saturating_sub` pinned the viewport at row 0, so the screen looked frozen
/// and `Down` had to walk back through the whole surplus one row per press.
/// `Home` compounded it by writing `usize::MAX`.
fn clamp_log_scroll(state: &mut AppState) {
    let max = max_log_scroll(state);
    state.log_scroll = state.log_scroll.min(max);
    if let Some(anchor) = state.log_select_anchor {
        state.log_select_anchor = Some(anchor.min(max));
    }
}

/// Load older log entries from heed when scrolled near the top (async).
pub(super) async fn try_load_older(state: &mut AppState) {
    if !state.log_has_older {
        return;
    }
    if state.log_cache.is_empty() {
        state.log_has_older = false;
        return;
    }
    let filtered_count = count_filtered(state);
    let height = state.log_viewport_rows.get().max(1);
    // `log_scroll` is offset FROM BOTTOM: the viewport covers rows
    // `filtered_count - (log_scroll + viewport)` .. `filtered_count - log_scroll`.
    // The user is at the top when `log_scroll + viewport >= filtered_count`,
    // so the old `filtered_count - height` threshold had the comparison
    // backwards and fired one full page before reaching the top (or never, once
    // the viewport was already capping the screen) — repeated PageUp did
    // nothing visible because has_older stayed false.
    if !state.log_has_older || state.log_scroll + height < filtered_count {
        return;
    }
    let heed = match &state.heed_storage {
        Some(h) => h.clone(),
        None => return,
    };
    let oldest_ts = state.log_cache[0].timestamp_nanos;
    let entries = heed.read_older_than_async(oldest_ts as u64, 500).await;

    match entries {
        Ok(entries) => {
            if entries.is_empty() {
                state.log_has_older = false;
                return;
            }
            if entries.len() < 500 {
                state.log_has_older = false;
            }
            let mut new_lines: VecDeque<crate::LogLine> = entries
                .into_iter()
                .rev()
                .map(|e| crate::LogLine {
                    level: e.level,
                    target: e.target,
                    message: e.message,
                    // Recovered from heed, so there is no `detail`: it is
                    // session-only and was never persisted.
                    detail: None,
                    timestamp_nanos: e.timestamp_nanos as i64,
                })
                .collect();
            let n = new_lines.len();
            state.log_scroll = state.log_scroll.saturating_add(n);
            if let Some(a) = &mut state.log_select_anchor {
                *a = a.saturating_add(n);
            }
            new_lines.append(&mut state.log_cache);
            state.log_cache = new_lines;
            let before = state.log_cache.len();
            while state.log_cache.len() > 10_000 {
                state.log_cache.pop_front();
            }
            let popped = before - state.log_cache.len();
            state.log_scroll = state.log_scroll.saturating_sub(popped);
            if let Some(a) = &mut state.log_select_anchor {
                *a = a.saturating_sub(popped);
            }
            // NO clamp on the normal path. The prepend grew `filtered_count`
            // and `log_scroll` by the same `n`, so the view is unchanged and
            // the offset is already legal. The caller clamps once after this
            // returns; doing it here as well would let the bound
            // (`filtered_count - viewport + 1`) bite before the key's own
            // `+= height` is accounted for, undoing the page.
            //
            // A drain is the exception: rows the cursor pointed at are gone,
            // so the offset can now exceed the buffer and must be pulled back.
            if popped > 0 {
                clamp_log_scroll(state);
            }
        }
        Err(e) => {
            state.log_has_older = false;
            tracing::error!(target: "tui::ui::logs::load", "Failed to load older logs: {e}");
        }
    }
}

/// Entries read per `read_newer_than` call.
const POLL_PAGE: usize = 500;

/// Ceiling on entries drained in one poll, so a burst cannot monopolize the UI
/// task. Reading stops here with the watermark where it got to, and the next
/// tick continues — the backlog is never skipped, only deferred.
const POLL_MAX_PER_TICK: usize = 5_000;

/// Poll heed for new log entries newer than `last_seen_log_ns` (async).
pub(super) async fn poll_new_logs(state: &mut AppState) {
    let heed = match &state.heed_storage {
        Some(h) => h.clone(),
        None => return,
    };

    // Drained page by page, and the watermark advanced by the OLDEST entry of
    // each page rather than the newest. A single capped read that then set the
    // watermark to the newest entry SILENTLY DROPPED everything between the
    // previous watermark and that window: a batch emits hundreds of warn-level
    // lines per tick, and the 2026-09-27 Windows dump shows the effect — the
    // same target at the same level rendered twice for some lines and once for
    // others, because one of the two delivery paths had lost its copy.
    let mut drained: Vec<leas_core::log_heed::LogMessage> = Vec::new();
    let mut watermark = state.last_seen_log_ns;
    loop {
        let page = match heed.read_newer_than_async(watermark, POLL_PAGE).await {
            Ok(e) => e,
            Err(e) => {
                tracing::error!(target: "tui::ui::logs::poll", "Failed to poll new logs: {e}");
                break;
            }
        };
        if page.is_empty() {
            break;
        }
        // `page` is newest-first, so the last element is the oldest of the
        // window — that is the point the next read must resume from.
        let Some(oldest) = page.last() else {
            break;
        };
        watermark = oldest.timestamp_nanos;
        let full = page.len() == POLL_PAGE;
        drained.extend(page);
        if !full || drained.len() >= POLL_MAX_PER_TICK {
            break;
        }
    }

    if drained.is_empty() {
        return;
    }
    state.last_seen_log_ns = watermark;

    // Newest-first from heed, so reverse to append in chronological order.
    let new_count = drained.len();
    for entry in drained.into_iter().rev() {
        state.log_cache.push_back(crate::LogLine {
            level: entry.level,
            target: entry.target,
            message: entry.message,
            // Poll-recovered from heed: no `detail`.
            detail: None,
            timestamp_nanos: entry.timestamp_nanos as i64,
        });
    }
    // Follow the tail only while the user is already at the bottom; otherwise
    // hold the viewport still by pushing the offset forward by the arrival
    // count, so new lines do not yank the reader's position.
    if state.log_scroll != 0 {
        state.log_scroll = state.log_scroll.saturating_add(new_count);
        if let Some(a) = &mut state.log_select_anchor {
            *a = a.saturating_add(new_count);
        }
    }
    let excess = state.log_cache.len().saturating_sub(10_000);
    if excess > 0 {
        state.log_cache.drain(0..excess);
        if state.log_scroll > 0 {
            state.log_scroll = state.log_scroll.saturating_sub(excess);
            if let Some(a) = &mut state.log_select_anchor {
                *a = a.saturating_sub(excess);
            }
        }
        // The drain can pass the cursor's row; re-apply the bound.
        clamp_log_scroll(state);
    }
}

/// Count how many log entries match the current target filter.
pub(super) fn count_filtered(state: &AppState) -> usize {
    if state.selected_targets.is_empty() {
        state.log_cache.len()
    } else {
        state
            .log_cache
            .iter()
            .filter(|l| state.selected_targets.contains(&l.target))
            .count()
    }
}

// ── Target Picker ────────────────────────────────────────────────────

/// Render the target picker overlay as centered popup.
pub fn render_target_picker(frame: &mut Frame, area: Rect, state: &AppState) {
    let selected = match &state.mode {
        crate::AppMode::TargetPicker { selected } => *selected,
        _ => return,
    };
    let theme = state.theme();

    // Empty state: small centered popup
    if state.known_targets.is_empty() {
        let text = Paragraph::new(Line::from(" No targets available"))
            .style(ThemeStyles::hint(theme))
            .alignment(Alignment::Center);
        let sized = KnownSizeWrapper::new(text, 30, 3);
        let popup = Popup::new(sized)
            .title(" Select Targets (t=done, Enter=toggle) ")
            .border_set(ratatui::symbols::border::ROUNDED)
            .style(ThemeStyles::dialog(theme));
        frame.render_widget(popup, area);
        return;
    }

    let max_target_width = state
        .known_targets
        .iter()
        .map(std::string::String::len)
        .max()
        .unwrap_or(0);
    let popup_width = (max_target_width + 8).max(36) as u16;
    let popup_height = (state.known_targets.len() + 2).min(20) as u16;

    let items: Vec<Line> = state
        .known_targets
        .iter()
        .enumerate()
        .map(|(i, target)| {
            let checked = if state.selected_targets.contains(target) {
                "[\u{2713}]" // [✓]
            } else {
                "[ ]"
            };
            let prefix = if i == selected { " > " } else { "   " };
            Line::from(Span::styled(
                format!("{prefix}{checked} {target}"),
                if i == selected {
                    ThemeStyles::log_warning(theme)
                } else {
                    Style::default()
                },
            ))
        })
        .collect();

    let para = Paragraph::new(items).scroll((selected.saturating_sub(5) as u16, 0));
    let sized = KnownSizeWrapper::new(para, popup_width as usize, popup_height as usize);
    let popup = Popup::new(sized)
        .title(" Select Targets (t=done, Enter=toggle) ")
        .border_set(ratatui::symbols::border::ROUNDED)
        .style(ThemeStyles::dialog(theme));
    frame.render_widget(popup, area);
}

/// Handle key events for the target picker overlay.
pub fn handle_target_picker_key(state: &mut AppState, key: &KeyEvent) {
    let selected = match &state.mode {
        crate::AppMode::TargetPicker { selected } => *selected,
        _ => return,
    };

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            let new_sel = selected.saturating_sub(1);
            state.mode = crate::AppMode::TargetPicker { selected: new_sel };
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let new_sel = if state.known_targets.is_empty() {
                0
            } else {
                (selected + 1).min(state.known_targets.len() - 1)
            };
            state.mode = crate::AppMode::TargetPicker { selected: new_sel };
        }
        KeyCode::Enter => {
            // Toggle the selected target
            if let Some(target) = state.known_targets.get(selected).cloned()
                && !state.selected_targets.remove(&target)
            {
                state.selected_targets.insert(target);
            }
        }
        KeyCode::Char('t' | 'T' | 'q' | 'Q') | KeyCode::Esc => {
            state.mode = crate::AppMode::List;
        }
        _ => {}
    }
}

// ── Copy —───────────────────────────────────────────────────────────

/// Format one log entry for the system clipboard, stripping terminal control
/// bytes from the message.
///
/// The on-screen render path filters control bytes; the clipboard path must
/// too. A log line is remote-controlled (the core's stdout/stderr), and a
/// pasted raw `ESC` (`ESC[201~`, cursor moves, SGR) can forge terminal
/// output. `\n` is kept: entries are joined with it.
/// Same rendering as [`clipboard_line`], for a row read back from heed. It has
/// no `detail`: that is session-only and was never persisted.
fn heed_line(msg: &leas_core::log_heed::LogMessage) -> String {
    let message: String = msg
        .message
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    format!(
        "{} [{}] [{}] {}",
        fmt_ts(i64::try_from(msg.timestamp_nanos).unwrap_or(i64::MAX)),
        msg.level,
        msg.target,
        message,
    )
}

fn clipboard_line(log: &crate::LogLine) -> String {
    let message: String = log
        .message
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    format!(
        "{} [{}] [{}] {}",
        fmt_ts(log.timestamp_nanos),
        log.level,
        log.target,
        message,
    )
}

/// Copy the selected log range to the system clipboard.
fn copy_selection(state: &mut AppState) {
    let Some(anchor) = state.log_select_anchor else {
        return copy_cursor_line(state);
    };
    if state.log_cache.is_empty() {
        return;
    }
    let filtered_indices: Vec<usize> = state
        .log_cache
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            if state.selected_targets.is_empty() || state.selected_targets.contains(&l.target) {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    let filtered_count = filtered_indices.len();
    if filtered_count == 0 {
        return;
    }
    let lo = state.log_scroll.min(anchor);
    let hi = state.log_scroll.max(anchor);
    // Convert offset-from-bottom to filtered indices
    let lo_fi = filtered_count.saturating_sub(hi + 1);
    let hi_fi = filtered_count.saturating_sub(lo + 1);
    if lo_fi > hi_fi || lo_fi >= filtered_count {
        return;
    }
    let hi_fi = hi_fi.min(filtered_count - 1);
    let lines: Vec<String> = filtered_indices[lo_fi..=hi_fi]
        .iter()
        .filter_map(|&ci| state.log_cache.get(ci))
        .map(clipboard_line)
        .collect();
    if lines.is_empty() {
        return;
    }
    let text = lines.join("\n");
    copy_to_clipboard(state, text);
}

/// Copy the log line under the cursor to the system clipboard.
fn copy_cursor_line(state: &mut AppState) {
    if state.log_cache.is_empty() {
        return;
    }
    let filtered_indices: Vec<usize> = state
        .log_cache
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            if state.selected_targets.is_empty() || state.selected_targets.contains(&l.target) {
                Some(i)
            } else {
                None
            }
        })
        .collect();
    let filtered_count = filtered_indices.len();
    if filtered_count == 0 {
        return;
    }
    let cursor_idx = filtered_count.saturating_sub(state.log_scroll + 1);
    let Some(&cache_idx) = filtered_indices.get(cursor_idx) else {
        return;
    };
    let Some(log) = state.log_cache.get(cache_idx) else {
        return;
    };
    let text = clipboard_line(log);
    copy_to_clipboard(state, text);
}

/// Ceiling on one export, so a multi-gigabyte store cannot wedge the UI task
/// on a single keypress. 200k lines is far past any real session.
const EXPORT_MAX_LINES: usize = 200_000;

/// Page of lines read per `read_older_than_async` round trip.
const EXPORT_PAGE: usize = 5_000;

/// Copy ALL filtered log entries to the system clipboard.
///
/// Pages **heed**, not `log_cache`. The cache is seeded with the 500 NEWEST
/// entries (`AppState::load_initial_logs`) and only ever grows forward, so an
/// export built from it silently truncates whatever is older: the 2026-10-01
/// dump held **575 of the store's 1,313 lines (44%)** and said nothing about
/// it. `read_all_from` walks backwards from the newest key to the start of the
/// store, so what is copied is what is stored.
async fn copy_all_filtered(state: &mut AppState) {
    let Some(heed) = state.heed_storage.clone() else {
        return;
    };
    let targets = state.selected_targets.clone();
    let keep =
        |l: &leas_core::log_heed::LogMessage| targets.is_empty() || targets.contains(&l.target);
    let lines: Vec<String> = match heed
        .read_all_older_than_async(u64::MAX, EXPORT_PAGE, EXPORT_MAX_LINES)
        .await
    {
        Ok(all) => all.iter().filter(|l| keep(l)).map(heed_line).collect(),
        Err(e) => {
            state.log_activity(
                "error",
                "tui::ui::logs",
                &format!("log export read failed: {e}"),
            );
            return;
        }
    };
    if lines.is_empty() {
        return;
    }
    if lines.len() >= EXPORT_MAX_LINES {
        state.log_activity(
            "warn",
            "tui::ui::logs",
            &format!(
                "log export truncated at {EXPORT_MAX_LINES} lines — the store is larger than one clipboard copy",
            ),
        );
    }
    let text = lines.join("\n");
    copy_to_clipboard(state, text);
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Write to the shared clipboard handle and surface a failure. Copy failures
/// used to be dropped here, so a broken clipboard looked identical to a
/// successful copy.
fn copy_to_clipboard(state: &mut AppState, text: String) {
    if let Err(error) = crate::ops::clipboard::set_text(text) {
        state.log_trace("error", "tui::ui::logs", &format!("Copy failed: {error}"));
    }
}

fn fmt_ts(ts_nanos: i64) -> String {
    let secs = if ts_nanos >= 0 {
        ts_nanos / 1_000_000_000
    } else {
        (ts_nanos - 999_999_999) / 1_000_000_000
    };
    let sub_nanos = ts_nanos.rem_euclid(1_000_000_000) as u32;
    chrono::DateTime::from_timestamp(secs, sub_nanos).map_or_else(
        || format!("{}s", ts_nanos / 1_000_000_000),
        |dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use leas_config::AppConfig;

    fn make_line(s: &str) -> crate::LogLine {
        crate::LogLine {
            level: "info".to_string(),
            target: "tui".to_string(),
            message: s.to_string(),
            detail: None,
            timestamp_nanos: 0,
        }
    }

    /// A state with just enough to exercise the scroll bound; the log buffer
    /// is the only thing these tests touch.
    async fn scroll_state() -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        AppState::new(db, AppConfig::default()).await
    }

    fn filled(state: &mut AppState, n: usize) {
        state.log_cache = (0..n).map(|i| make_line(&format!("m{i}"))).collect();
    }

    /// A scroll offset past the loaded buffer must be pulled back, or the
    /// viewport saturates at row 0 while `Down` walks the surplus away one row
    /// per press — the frozen log pane.
    #[tokio::test]
    async fn scroll_clamps_to_loaded_buffer() {
        let mut state = scroll_state().await;
        filled(&mut state, 10);
        state.log_viewport_rows.set(5);

        state.log_scroll = 3;
        clamp_log_scroll(&mut state);
        assert_eq!(state.log_scroll, 3, "an in-range offset is untouched");

        // What unbounded `Up` accumulation produced.
        state.log_scroll = 10_000;
        clamp_log_scroll(&mut state);
        assert_eq!(
            state.log_scroll, 6,
            "clamped so the oldest row is at the top of a 5-row viewport"
        );
    }

    /// `Home` lands on the oldest LOADED row, not a sentinel only the seek
    /// path could recover from — and `Down` from there must return to the
    /// bottom in one press, not thousands.
    #[tokio::test]
    async fn home_lands_on_oldest_row_and_returns_in_one_press() {
        let mut state = scroll_state().await;
        filled(&mut state, 10);
        state.log_viewport_rows.set(5);
        state.log_scroll = max_log_scroll(&state);
        assert_eq!(state.log_scroll, 6, "no usize::MAX sentinel survives");
        state.log_scroll = state.log_scroll.saturating_sub(1);
        clamp_log_scroll(&mut state);
        assert_eq!(state.log_scroll, 5);
    }

    /// A live selection anchor addresses a row, so it is bound by the same
    /// rule and cannot outlive the buffer.
    #[tokio::test]
    async fn selection_anchor_clamps_with_the_buffer() {
        let mut state = scroll_state().await;
        filled(&mut state, 10);
        state.log_viewport_rows.set(5);
        state.log_select_anchor = Some(usize::MAX);
        clamp_log_scroll(&mut state);
        assert_eq!(state.log_select_anchor, Some(6));
    }

    /// The target filter narrows the buffer, so the deepest legal offset
    /// shrinks with it: an offset valid before filtering is not valid after.
    #[tokio::test]
    async fn filter_narrowing_tightens_the_bound() {
        let mut state = scroll_state().await;
        filled(&mut state, 20);
        for (i, line) in state.log_cache.iter_mut().enumerate() {
            line.target = if i % 2 == 0 { "xray" } else { "other" }.to_string();
        }
        state.log_viewport_rows.set(5);
        state.log_scroll = 19;
        state.selected_targets.insert("xray".to_string());
        clamp_log_scroll(&mut state);
        assert_eq!(state.log_scroll, 6, "10 of 20 entries match the filter");
    }

    /// A page up near the top loads 500 older rows and shifts `log_scroll`
    /// forward by the same count. Every consumer reads `log_scroll` as
    /// offset-from-bottom, so the two adjustments cancel and the viewport must
    /// NOT move — but only if the clamp permits the full shift.
    ///
    /// It did not: `clamp_log_scroll` capped the shift at `filtered_count - 1`
    /// of the PREPENDED buffer, so a load at the top pushed the cursor far
    /// below the oldest row and the render pinned the window at the bottom —
    /// repeated `PageUp` then did nothing visible.
    #[tokio::test]
    async fn loading_older_rows_keeps_the_viewport_still() {
        let mut state = scroll_state().await;
        filled(&mut state, 500);
        state.log_viewport_rows.set(20);

        // Sit one viewport from the top, as a `PageUp` would.
        state.log_scroll = 480;
        clamp_log_scroll(&mut state);
        assert_eq!(state.log_scroll, 480);

        // Simulate a 500-row older prepend, which is what `try_load_older` does.
        for i in (0..500).rev() {
            state.log_cache.push_front(make_line(&format!("old{i}")));
        }
        state.log_scroll = state.log_scroll.saturating_add(500);
        clamp_log_scroll(&mut state);

        assert_eq!(
            state.log_scroll, 980,
            "the shift must survive the clamp, or the page is undone"
        );
    }

    /// The render window must stay inside the buffer at the deepest legal
    /// offset: the cursor sits `viewport - 1` rows above the oldest row, so
    /// `filtered_count - (log_scroll + viewport)` reaches 0 and the whole
    /// window is addressable. A tighter bound strands the cursor below the
    /// oldest row, blanks the pane, and freezes `PageUp`.
    #[tokio::test]
    async fn deepest_offset_keeps_the_window_inside_the_buffer() {
        let mut state = scroll_state().await;
        filled(&mut state, 500);
        state.log_viewport_rows.set(20);
        state.log_scroll = max_log_scroll(&state);
        assert_eq!(state.log_scroll, 481, "oldest row at the top of the pane");
        assert!(
            state.log_scroll + 20 >= 500,
            "the render window must reach the top of the buffer"
        );
        assert!(
            state.log_scroll < 500,
            "the cursor must stay inside the buffer"
        );
    }

    #[test]
    fn log_rows_build_viewport_only() {
        let cache = vec![make_line("a"); 10000];
        let rows = build_rows_viewport(&cache, 0, 30);
        assert_eq!(rows.len(), 30);
    }

    /// A remote-controlled log message must not put terminal control bytes on
    /// the clipboard (finding f16: raw `ESC` / `ESC[201~`).
    #[test]
    fn clipboard_line_strips_control_bytes() {
        let mut log = make_line("plain");
        log.message = "before\u{1b}[201~after\u{7}\u{9b}31m".to_string();
        let out = clipboard_line(&log);
        assert!(
            !out.chars().any(char::is_control),
            "no control bytes may survive: {out:?}"
        );
        assert!(out.ends_with("before[201~after31m"), "text kept: {out:?}");
        // A newline is preserved (entries are joined with it).
        let mut multi = make_line("a");
        multi.message = "line1\nline2".to_string();
        assert!(clipboard_line(&multi).contains("line1\nline2"));
    }
}
