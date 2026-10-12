use ratatui::text::{Line, Span};
use ratatui_cheese::theme::Palette;

use crate::ui::theme::ThemeStyles;

// ── Width ladder ────────────────────────────────────────────────────────

/// Below this the right region renders nothing (the status bar keeps the numbers).
const MIN_REGION_WIDTH: usize = 18;
/// Below this the glyphs go: label, counters and ETA only.
const MIN_BAR_WIDTH: usize = 30;
/// At or above this the bar keeps its full cell budget.
const FULL_SHAPE_WIDTH: usize = 44;
/// The bar's cell budget in the full shape.
const FULL_BAR_CELLS: usize = 20;
/// A shortened bar never shrinks past this, even if the text then overflows.
const MIN_SHORT_BAR_CELLS: usize = 6;
/// The cells the shape spends outside the bar: two separators around the
/// counters/ETA text, the brackets, the `>` head, and the separator `bar_cells`
/// puts between the bar and the percent.
const LADDER_FRAME: usize = 6;

// ── Glyphs ──────────────────────────────────────────────────────────────

/// The fill and track runs of one bar — the crate's only glyph producer.
fn runs(done: u64, total: u64, width: usize) -> (String, String) {
    let filled = if total == 0 {
        0
    } else {
        // Integer math keeps an exact fill exact (`done == total` → full bar).
        let cells = u128::from(done.min(total)) * width as u128 / u128::from(total);
        usize::try_from(cells).unwrap_or(width)
    };
    ("█".repeat(filled), "░".repeat(width - filled))
}

/// The ` 42%` suffix; empty while the total is unknown.
fn pct_text(done: u64, total: u64) -> String {
    // `None` covers both an unknown total (0) and an impossible one.
    done.min(total)
        .checked_mul(100)
        .and_then(|n| n.checked_div(total))
        .map_or_else(String::new, |pct| format!(" {pct}%"))
}

/// The bar cells for a counter pair, width-adapted: `[███>░░] 42%`.
///
/// The single owner of the glyph rendering (the Settings download bar and the
/// batch ping bars share it). `width` is the *bar* cell budget (the brackets
/// and counters are extra).
#[must_use]
pub(crate) fn bar_cells(done: u64, total: u64, width: usize) -> String {
    let (fill, track) = runs(done, total, width);
    format!("[{fill}>{track}]{}", pct_text(done, total))
}

/// `~12m` / `~40s` / `~1h05m`; `--` when the estimate is unknown.
#[must_use]
pub fn format_eta(secs: Option<u64>) -> String {
    let Some(secs) = secs else {
        return "--".to_string();
    };
    if secs >= 3600 {
        format!("~{}h{:02}m", secs / 3600, secs % 3600 / 60)
    } else if secs >= 60 {
        format!("~{}m", secs / 60)
    } else {
        format!("~{secs}s")
    }
}

/// One Actions-Log row's right region: label, bar, counters, ETA, styled from
/// the palette and degrading with the available width.
#[must_use]
pub fn bar_line(
    label: &str,
    done: u32,
    total: u32,
    eta: Option<u64>,
    width: usize,
    palette: &Palette,
) -> Line<'static> {
    if width < MIN_REGION_WIDTH {
        return Line::default();
    }
    let (done, total) = (u64::from(done), u64::from(total));
    let counters = format!("{done}/{total}");
    let eta = format_eta(eta);
    let pct = pct_text(done, total);
    let muted = ThemeStyles::footer_label(palette);
    if width < MIN_BAR_WIDTH {
        return Line::from(vec![
            Span::styled(format!("{label} "), muted),
            Span::styled(format!("{counters} {eta}"), muted),
        ]);
    }
    // A narrow region shortens the bar; the text is never dropped before it.
    let bar_width = if width >= FULL_SHAPE_WIDTH {
        FULL_BAR_CELLS
    } else {
        let fixed = label.chars().count()
            + counters.chars().count()
            + eta.chars().count()
            + pct.chars().count()
            + LADDER_FRAME;
        width.saturating_sub(fixed).max(MIN_SHORT_BAR_CELLS)
    };
    let (fill, track) = runs(done, total, bar_width);
    let fill_style = ThemeStyles::progress_fill(palette);
    let track_style = ThemeStyles::progress_bar(palette);
    Line::from(vec![
        Span::styled(format!("{label} "), track_style),
        Span::styled("[", track_style),
        Span::styled(fill, fill_style),
        Span::styled(">", fill_style),
        Span::styled(track, track_style),
        Span::styled("]", track_style),
        Span::styled(format!("{pct} {counters} {eta}"), muted),
    ])
}

#[cfg(test)]
mod tests {
    use super::{bar_cells, bar_line, format_eta};
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use ratatui::text::Line;
    use ratatui::widgets::Widget;
    use ratatui_cheese::theme::Palette;

    /// The rendered text of a line — what the terminal actually shows.
    fn plain(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn bar_cells_matches_the_settings_shape() {
        let empty = format!("[>{}]", "░".repeat(20));
        assert_eq!(
            bar_cells(0, 0, 20),
            empty,
            "no total: empty bar, no percent"
        );
        assert_eq!(
            bar_cells(1, 2, 20),
            format!("[{}>{}] 50%", "█".repeat(10), "░".repeat(10))
        );
        assert_eq!(
            bar_cells(1, 4, 8),
            format!("[{}>{}] 25%", "█".repeat(2), "░".repeat(6))
        );
        assert_eq!(
            bar_cells(2, 2, 20),
            format!("[{}>] 100%", "█".repeat(20)),
            "an exact fill keeps the > head"
        );
        assert_eq!(
            bar_cells(3, 2, 20),
            format!("[{}>] 100%", "█".repeat(20)),
            "a done past total clamps to a full bar"
        );
    }

    #[test]
    fn eta_formats_by_magnitude() {
        assert_eq!(format_eta(None), "--");
        assert_eq!(format_eta(Some(0)), "~0s");
        assert_eq!(format_eta(Some(45)), "~45s");
        assert_eq!(format_eta(Some(59)), "~59s");
        assert_eq!(format_eta(Some(60)), "~1m");
        assert_eq!(format_eta(Some(720)), "~12m");
        assert_eq!(format_eta(Some(3599)), "~59m");
        assert_eq!(format_eta(Some(3600)), "~1h00m");
        assert_eq!(format_eta(Some(11_400)), "~3h10m");
    }

    #[test]
    fn ladder_degrades_with_the_right_region_width() {
        let palette = Palette::default();
        let row = |width| plain(&bar_line("Fast", 1234, 34562, Some(180), width, &palette));
        assert_eq!(row(17), "", "below 18 there is no right region");
        assert_eq!(row(18), "Fast 1234/34562 ~3m", "18..=29 is numbers and ETA");
        assert_eq!(row(29), "Fast 1234/34562 ~3m");
        assert_eq!(
            row(30),
            "Fast [>░░░░░░] 3% 1234/34562 ~3m",
            "30..=43 shrinks the bar"
        );
        assert_eq!(row(43), "Fast [>░░░░░░░░░░░░░░░░░] 3% 1234/34562 ~3m");
        assert_eq!(
            row(44),
            "Fast [>░░░░░░░░░░░░░░░░░░░░] 3% 1234/34562 ~3m",
            "44 and up get the full 20-cell bar"
        );
        assert_eq!(row(60), "Fast [>░░░░░░░░░░░░░░░░░░░░] 3% 1234/34562 ~3m");
        assert_eq!(row(16), "", "16 columns is under the floor too");
    }

    #[test]
    fn bar_glyphs_are_painted_from_the_palette() {
        let palette = Palette::default();
        let line = bar_line("Fast", 1, 2, None, 60, &palette);
        let area = Rect::new(0, 0, u16::try_from(line.width()).unwrap(), 1);
        let mut buf = Buffer::empty(area);
        (&line).render(area, &mut buf);
        // Glyphs are multi-byte, so a match's offset is counted in characters.
        let col = |needle: &str| {
            let text = plain(&line);
            let idx = text.find(needle).unwrap();
            u16::try_from(text[..idx].chars().count()).unwrap()
        };
        let fill = &buf[(col("█"), 0)];
        assert_eq!((fill.fg, fill.bg), (palette.primary, palette.primary));
        let head = &buf[(col(">"), 0)];
        assert_eq!(
            (head.fg, head.bg),
            (palette.primary, palette.primary),
            "the head belongs to the fill"
        );
        let bracket = &buf[(col("["), 0)];
        assert_eq!(
            (bracket.fg, bracket.bg),
            (palette.foreground, palette.surface)
        );
        let track = &buf[(col("░"), 0)];
        assert_eq!((track.fg, track.bg), (palette.foreground, palette.surface));
        let counters = &buf[(col("1/2"), 0)];
        assert_eq!(counters.fg, palette.muted);
    }
}
