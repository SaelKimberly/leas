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

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    if area.height < 4 || area.width < 20 {
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
        .constraints([
            Constraint::Length(1), // metrics line
            Constraint::Length(1), // gauge line
            Constraint::Min(1),    // queue
        ])
        .split(area);
    render_metrics(frame, rows[0], state, theme);
    render_gauge(frame, rows[1], state, theme);
    render_queue(frame, rows[2], state, theme);
}

/// Metrics line: task name, counters, ETA — full width, never overlapped by
/// the gauge below it.
fn render_metrics(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let text = metrics_text(state);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            text,
            ThemeStyles::footer_value(theme),
        ))),
        area,
    );
}

/// Gauge line: bare bar + thumb, full width, no label.
fn render_gauge(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let ratio = gauge_ratio(state);
    let gauge = LineGauge::default()
        .ratio(ratio.clamp(0.0, 1.0))
        .label(Line::from(""))
        .filled_symbol("━")
        .unfilled_symbol("─")
        .filled_style(ThemeStyles::progress_fill(theme))
        .unfilled_style(ThemeStyles::progress_bar(theme));
    frame.render_widget(gauge, area);

    let fill = (f64::from(area.width) * ratio).floor() as u16;
    let thumb_x = area.x + fill;
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

/// The metrics line text: `<label> <done>/<total> <eta>` or the idle/paused hint.
fn metrics_text(state: &AppState) -> String {
    let Some(spec) = &state.running_task else {
        return bar_idle_label(state);
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
    match total {
        0 => format!("{} …", spec.label),
        _ => format!("{} {done}/{total}{eta}", spec.label),
    }
}

/// Fill ratio for the gauge (0.0–1.0).
fn gauge_ratio(state: &AppState) -> f64 {
    if state.running_task.is_none() {
        return 0.0;
    }
    let (done, total, _) = running_meters(state);
    if total == 0 {
        0.0
    } else {
        f64::from(done.min(total)) / f64::from(total)
    }
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
