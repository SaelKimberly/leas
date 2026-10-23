//! Pane-2 `Tasks` tab (spec §14).
//!
//! The job queue: the running task's progress bar on top, the queued tasks
//! below (earliest first). The running task is the bar's label, NOT a list row
//! — so its progress is never drawn twice (spec D38).

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{LineGauge, Paragraph};

use crate::AppState;
use crate::ui::theme::ThemeStyles;

/// The bar's label column, so the bar starts at a fixed x.
const LABEL_WIDTH: usize = 24;

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    if area.height < 3 || area.width < 20 {
        // Too small for a bar + a queue: show the bar's state as a hint.
        let theme = state.theme();
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                bar_idle_label(state),
                ThemeStyles::hint(theme),
            ))),
            area,
        );
        return;
    }
    let theme = state.theme();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(1)])
        .split(area);
    render_bar(frame, rows[0], state, theme);
    render_queue(frame, rows[1], state, theme);
}

/// The bar row: a `LineGauge` with a manual thumb overlay (spec D30).
///
/// `tui-slider` was rejected (it pulls `tui-nuances`, a second theme engine,
/// and its `SliderStyle` is `Color`-based with no theme trait). The thumb is
/// one cell at `floor(width * done/total)` — the same math `LineGauge` uses
/// internally, so the thumb and the bar cannot disagree.
fn render_bar(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let (label, ratio) = bar_label(state);
    let label = truncate(&label, LABEL_WIDTH);

    let gauge = LineGauge::default()
        .ratio(ratio.clamp(0.0, 1.0))
        .label(Line::from(Span::styled(
            label,
            ThemeStyles::footer_value(theme),
        )))
        .filled_symbol("━")
        .unfilled_symbol("─")
        .filled_style(ThemeStyles::progress_fill(theme))
        .unfilled_style(ThemeStyles::progress_bar(theme));
    frame.render_widget(gauge, area);

    // The thumb: one cell at the fill boundary. `LineGauge` fills up to
    // `floor(width * ratio)`, so the thumb sits on the first unfilled cell.
    let fill = (f64::from(area.width) * ratio).floor() as u16;
    let thumb_x = area.x + (LABEL_WIDTH as u16).min(area.width.saturating_sub(1)) + fill;
    if thumb_x < area.x + area.width && ratio > 0.0 && ratio < 1.0 {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "●",
                ThemeStyles::progress_fill(theme),
            ))),
            Rect::new(thumb_x, area.y, 1, 1),
        );
    }
}

/// The bar's label and ratio.
fn bar_label(state: &AppState) -> (String, f64) {
    let Some(spec) = &state.running_task else {
        return (bar_idle_label(state), 0.0);
    };
    let (done, total, rate_milli) = running_meters(state);
    let eta = match (total, done, rate_milli) {
        (0, _, _) => String::new(),
        (_, d, _) if d >= total => String::new(),
        (_, _, 0) => String::new(),
        _ => {
            let remaining = u64::from(total - done) * 1000 / u64::from(rate_milli);
            format!(
                " {}",
                crate::ui::widgets::progress::format_eta(Some(remaining))
            )
        }
    };
    let label = match total {
        0 => format!("{} …", spec.label),
        _ => format!("{} {done}/{total}{eta}", spec.label),
    };
    let ratio = if total == 0 {
        0.0
    } else {
        f64::from(done.min(total)) / f64::from(total)
    };
    (label, ratio)
}

/// The bar's label when nothing is running (spec D47).
fn bar_idle_label(state: &AppState) -> String {
    if state.scheduler_paused {
        format!(
            "paused — {} queued, press r to resume",
            state.task_queue.len()
        )
    } else if state.task_queue.is_empty() {
        "no tasks — pick one from the Speed Test menu".to_string()
    } else {
        "queued: ".to_string()
    }
}

/// The running task's `(done, total, rate_milli)`, read from the slot its kind
/// sets.
fn running_meters(state: &AppState) -> (u32, u32, u32) {
    use std::sync::atomic::Ordering::Relaxed;
    if let Some(m) = &state.batch_progress {
        return (
            m.main.done.load(Relaxed),
            m.main.total.load(Relaxed),
            m.main.rate_milli.load(Relaxed),
        );
    }
    if let Some(m) = &state.fill_progress {
        return (
            m.look.done.load(Relaxed),
            m.look.total.load(Relaxed),
            m.look.rate_milli.load(Relaxed),
        );
    }
    if let Some(m) = &state.maint_progress {
        let name = (
            m.name.done.load(Relaxed),
            m.name.total.load(Relaxed),
            m.name.rate_milli.load(Relaxed),
        );
        let comp = (
            m.comp.done.load(Relaxed),
            m.comp.total.load(Relaxed),
            m.comp.rate_milli.load(Relaxed),
        );
        return match (name.1, comp.1) {
            (0, 0) => name,
            (0, _) => comp,
            _ => name,
        };
    }
    (0, 0, 0)
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// The queue list: the queued tasks only, earliest first.
///
/// The cursor moves with `↑↓` and the list scrolls to keep it visible (the
/// Profiles-table convention). The running task is NOT a row.
fn render_queue(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let total = state.task_queue.len();
    let cursor = state.tasks_cursor.min(total.saturating_sub(1));

    // Scroll so the cursor is visible.
    let visible_rows = area.height as usize;
    let offset = if total <= visible_rows {
        0
    } else if cursor >= visible_rows {
        cursor + 1 - visible_rows
    } else {
        0
    };

    let mut lines: Vec<Line> = Vec::new();
    if total == 0 {
        lines.push(Line::from(Span::styled(
            "  queue empty",
            ThemeStyles::hint(theme),
        )));
    }
    for (i, task) in state
        .task_queue
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible_rows)
    {
        let marker = if i == cursor { "► " } else { "  " };
        let style = if i == cursor {
            ThemeStyles::table_row_selected(theme)
        } else {
            ThemeStyles::footer_value(theme)
        };
        lines.push(Line::from(Span::styled(
            format!("{marker}{}", task.label),
            style,
        )));
    }
    if total > visible_rows {
        lines.push(Line::from(Span::styled(
            format!(
                "  ↑↓ scroll — rows {}-{} of {total}",
                offset + 1,
                (offset + visible_rows).min(total)
            ),
            ThemeStyles::hint(theme),
        )));
    }
    frame.render_widget(Paragraph::new(lines), area);
}
