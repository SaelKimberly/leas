use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, StatefulWidget, Widget};
use std::collections::HashSet;
use tui_scrollbar::{GlyphSet, ScrollBar, ScrollLengths};

// ── Width strategy ──────────────────────────────────────────────────────

/// How a column's width is determined.
#[derive(Debug, Clone)]
pub enum ColumnWidth {
    /// Exact pixel width.
    Fixed(u16),
    /// Proportional weight for distributing remaining space (e.g. `Ratio(3)`).
    Ratio(u16),
    /// Content-based with a minimum pixel width.
    Min(u16),
}

// ── Sort ────────────────────────────────────────────────────────────────

/// Sort direction indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

// ── Column ──────────────────────────────────────────────────────────────

/// A single column definition.
#[derive(Debug, Clone)]
pub struct Column<'a> {
    pub header: Line<'a>,
    pub width: ColumnWidth,
    pub alignment: Alignment,
    pub style: Style,
}

impl<'a> Column<'a> {
    #[must_use]
    pub fn new(header: impl Into<Line<'a>>, width: ColumnWidth) -> Self {
        Self {
            header: header.into(),
            width,
            alignment: Alignment::Left,
            style: Style::default(),
        }
    }

    #[must_use]
    pub const fn alignment(mut self, alignment: Alignment) -> Self {
        self.alignment = alignment;
        self
    }

    #[must_use]
    pub const fn style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }
}

// ── Row trait ───────────────────────────────────────────────────────────

/// A row that can be rendered into pre-computed column slots.
pub trait DataTableRow {
    /// Render row content into the buffer at the given y position.
    /// `col_xs` gives the starting x coordinate of each column.
    /// `col_widths` gives the pixel width of each column.
    /// `clip_bottom` is the first line below the visible area; rows taller
    /// than the viewport MUST NOT write at `y_line >= clip_bottom`.
    fn render(
        &self,
        col_xs: &[u16],
        col_widths: &[u16],
        buf: &mut Buffer,
        y: u16,
        clip_bottom: u16,
    );

    /// Row height in lines (default 1).
    /// Override for wrapping/multi-line rows such as log messages.
    fn height(&self, _available_width: u16) -> u16 {
        1
    }
}

// ── Widget ──────────────────────────────────────────────────────────────

/// A stateful data table widget similar to a spreadsheet or list view.
///
/// Columns are defined with a width strategy. Rows implement [`DataTableRow`]
/// to control per-cell rendering. Supports single-selection, multi-selection,
/// column sorting indicators, a header row with optional divider, and an
/// optional block border.
pub struct DataTable<'a, R: DataTableRow> {
    pub columns: Vec<Column<'a>>,
    pub rows: &'a [R],
    pub highlight_style: Style,
    pub selection_style: Style,
    pub sort_column: Option<usize>,
    pub sort_direction: SortDirection,
    pub column_spacing: u16,
    pub block: Option<Block<'a>>,
    pub header_divider: Option<char>,
    pub show_scrollbar: bool,
    pub scrollbar_thumb_style: Style,
    pub scrollbar_track_style: Style,
    /// When the caller passes a WINDOWED row slice (viewport virtualization),
    /// the scrollbar's content length comes from here instead of `rows.len()`.
    pub total_rows: Option<usize>,
    /// True scroll position when the slice starts at a non-zero offset.
    pub scrollbar_offset: Option<usize>,
}

impl<R: DataTableRow> Default for DataTable<'_, R> {
    fn default() -> Self {
        Self {
            columns: Vec::new(),
            rows: &[],
            highlight_style: Style::default().add_modifier(Modifier::REVERSED),
            selection_style: Style::default(),
            sort_column: None,
            sort_direction: SortDirection::Ascending,
            column_spacing: 1,
            block: None,
            header_divider: None,
            show_scrollbar: false,
            scrollbar_thumb_style: Style::default(),
            scrollbar_track_style: Style::default(),
            total_rows: None,
            scrollbar_offset: None,
        }
    }
}

impl<'a, R: DataTableRow> DataTable<'a, R> {
    #[must_use]
    pub fn new(columns: Vec<Column<'a>>, rows: &'a [R]) -> Self {
        Self {
            columns,
            rows,
            ..Self::default()
        }
    }

    #[must_use]
    pub const fn highlight_style(mut self, style: Style) -> Self {
        self.highlight_style = style;
        self
    }

    #[must_use]
    pub const fn selection_style(mut self, style: Style) -> Self {
        self.selection_style = style;
        self
    }

    #[must_use]
    pub const fn sort_column(mut self, col: Option<usize>, dir: SortDirection) -> Self {
        self.sort_column = col;
        self.sort_direction = dir;
        self
    }

    #[must_use]
    pub const fn column_spacing(mut self, spacing: u16) -> Self {
        self.column_spacing = spacing;
        self
    }

    #[must_use]
    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    #[must_use]
    pub const fn header_divider(mut self, ch: char) -> Self {
        self.header_divider = Some(ch);
        self
    }

    #[must_use]
    pub const fn scrollbar(mut self, thumb_style: Style, track_style: Style) -> Self {
        self.show_scrollbar = true;
        self.scrollbar_thumb_style = thumb_style;
        self.scrollbar_track_style = track_style;
        self
    }

    /// Scrollbar content length when `rows` is a windowed (viewport) slice:
    /// the full filtered row count the thumb size/proportion use.
    /// `None` (default) uses `rows.len()`.
    #[must_use]
    pub const fn total_rows(mut self, total: Option<usize>) -> Self {
        self.total_rows = total;
        self
    }

    /// True scroll position when a windowed slice starts past row 0: the
    /// scrollbar thumb uses this instead of `state.offset`.
    /// `None` (default) uses `state.offset`.
    #[must_use]
    pub const fn scrollbar_offset(mut self, offset: Option<usize>) -> Self {
        self.scrollbar_offset = offset;
        self
    }
}

// ── State ───────────────────────────────────────────────────────────────

/// Mutable state for [`DataTable`].
#[derive(Debug, Clone)]
pub struct DataTableState {
    /// Scroll offset (index of first visible row).
    pub offset: usize,
    /// Currently selected row index (global).
    pub selected: Option<usize>,
    /// Multi-selected row indices (global).
    pub multi_selected: HashSet<usize>,
}

impl Default for DataTableState {
    fn default() -> Self {
        Self {
            offset: 0,
            selected: Some(0),
            multi_selected: HashSet::new(),
        }
    }
}

// ── Width computation ───────────────────────────────────────────────────

/// Maximum supported column count; the widest caller has 16 (profiles).
/// Stack-resident so the per-frame render never touches the allocator.
const MAX_COLS: usize = 32;

/// Compute pixel widths for each column given the available inner width.
/// Writes into `out`, returning the number of columns filled (columns beyond
/// [`MAX_COLS`] are ignored — no caller is near it).
fn compute_widths(
    columns: &[Column],
    available: u16,
    spacing: u16,
    out: &mut [u16; MAX_COLS],
) -> usize {
    let n = columns.len().min(MAX_COLS);
    if n == 0 {
        return 0;
    }

    let total_spacing = n.saturating_sub(1) as u16 * spacing;
    let available = available.saturating_sub(total_spacing);

    let widths = &mut out[..n];
    widths.fill(0);
    let mut remaining = available;

    // 1. Assign Fixed widths
    for (i, col) in columns.iter().take(n).enumerate() {
        if let ColumnWidth::Fixed(w) = col.width {
            let w = w.min(remaining);
            widths[i] = w;
            remaining = remaining.saturating_sub(w);
        }
    }

    // 2. Assign Min widths
    for (i, col) in columns.iter().take(n).enumerate() {
        if let ColumnWidth::Min(min) = col.width {
            let w = min.min(remaining);
            widths[i] = w;
            remaining = remaining.saturating_sub(w);
        }
    }

    // 3. Distribute remaining to Ratio columns
    let ratio_total: u16 = columns
        .iter()
        .take(n)
        .filter_map(|c| match c.width {
            ColumnWidth::Ratio(r) => Some(r),
            _ => None,
        })
        .sum();

    if ratio_total > 0 && remaining > 0 {
        let remaining_before_ratio = remaining;
        let mut assigned = 0u16;
        for (i, col) in columns.iter().take(n).enumerate() {
            if let ColumnWidth::Ratio(r) = col.width {
                let share = remaining_before_ratio * r / ratio_total;
                widths[i] = share;
                assigned += share;
            }
        }
        // Give any leftover pixels to the last ratio column
        if let Some(ratio_idx) = columns
            .iter()
            .take(n)
            .enumerate()
            .rev()
            .find(|(_, c)| matches!(c.width, ColumnWidth::Ratio(_)))
            .map(|(i, _)| i)
        {
            widths[ratio_idx] += remaining - assigned;
        }
    }

    n
}

impl<R: DataTableRow> StatefulWidget for DataTable<'_, R> {
    type State = DataTableState;

    fn render(self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let inner = self.block.as_ref().map_or(area, |block| {
            let cloned_block = block.clone();
            cloned_block.render(area, buf);
            block.inner(area)
        });

        if inner.width == 0 || inner.height == 0 {
            return;
        }
        if self.columns.is_empty() || self.rows.is_empty() {
            return;
        }

        // Compute content area and scrollbar column
        let (content_inner, scrollbar_area) = if self.show_scrollbar && inner.width >= 2 {
            let halves =
                Layout::horizontal([Constraint::Min(1), Constraint::Length(1)]).split(inner);
            (halves[0], halves[1])
        } else {
            (inner, Rect::default())
        };

        // Compute column pixel widths (stack arrays — no per-frame heap).
        let mut widths_buf = [0u16; MAX_COLS];
        let ncols = compute_widths(
            &self.columns,
            content_inner.width,
            self.column_spacing,
            &mut widths_buf,
        );
        let col_widths = &widths_buf[..ncols];
        let mut xs_buf = [0u16; MAX_COLS];
        let col_xs = {
            let xs = &mut xs_buf[..ncols];
            let mut x = content_inner.x;
            for (i, w) in col_widths.iter().enumerate() {
                xs[i] = x;
                x += w;
                if i < col_widths.len() - 1 {
                    x += self.column_spacing;
                }
            }
            &xs_buf[..ncols]
        };

        // Header row. The header line is rendered borrowed (no spans clone);
        // the sort arrow overwrites the column's trailing cells with a second
        // `set_stringn` instead of a re-allocated header string.
        let mut header_y = inner.y;
        for (i, col) in self.columns.iter().take(ncols).enumerate() {
            let w = col_widths[i];
            if w == 0 {
                continue;
            }
            buf.set_line(col_xs[i], header_y, &col.header, w);
            if self.sort_column == Some(i) {
                // The old shape appended " ↑"/" ↓" to the header text (a
                // spans clone + format! per frame). Draw the same suffix with
                // a second `set_stringn` right after the header's own width.
                let arrow = match self.sort_direction {
                    SortDirection::Ascending => " ↑",
                    SortDirection::Descending => " ↓",
                };
                let ax = col_xs[i] + (col.header.width() as u16).min(w.saturating_sub(2));
                let aw = w.saturating_sub(ax - col_xs[i]) as usize;
                if aw > 0 {
                    buf.set_stringn(ax, header_y, arrow, aw, self.columns[i].style);
                }
            }
        }

        header_y += 1;

        // Divider
        if let Some(ch) = self.header_divider
            && header_y < content_inner.bottom()
        {
            for x in content_inner.x..content_inner.right() {
                buf[(x, header_y)].set_char(ch);
                buf[(x, header_y)].set_style(self.columns[0].style); // use first col style
            }
            header_y += 1;
        }

        // Compute row heights
        let row_heights: Vec<u16> = self
            .rows
            .iter()
            .map(|row| row.height(content_inner.width))
            .collect();

        // Clamp offset — count rows from the end so max_offset is the
        // earliest visible row that still fills the viewport.
        let total_rows = self.rows.len();
        let visible_height = content_inner.bottom().saturating_sub(header_y);
        let mut rows_from_end = 0usize;
        let mut h_sum = 0u16;
        for h in row_heights.iter().rev() {
            if h_sum + h > visible_height {
                break;
            }
            h_sum += h;
            rows_from_end += 1;
        }
        let max_offset = total_rows.saturating_sub(rows_from_end);
        if state.offset > max_offset {
            state.offset = max_offset;
        }

        // Render visible rows. Rows taller than the viewport are clipped at
        // `bottom` (clip_bottom) instead of being skipped entirely, so a
        // partially-visible row still draws and never writes past the frame.
        let bottom = content_inner.bottom();
        let mut y = header_y;
        let mut row_idx = state.offset;
        while y < bottom && row_idx < total_rows {
            let rh = row_heights[row_idx];
            if rh == 0 {
                row_idx += 1;
                continue;
            }

            let is_selected = state.selected == Some(row_idx);
            let is_multi = state.multi_selected.contains(&row_idx);
            // Highlight only the visible part of the row.
            let row_bottom = y.saturating_add(rh).min(bottom);

            // Apply selection/highlight styles via buffer background
            if is_selected {
                for row_y in y..row_bottom {
                    for x in content_inner.x..content_inner.right() {
                        buf[(x, row_y)].set_style(self.highlight_style);
                    }
                }
            } else if is_multi {
                for row_y in y..row_bottom {
                    for x in content_inner.x..content_inner.right() {
                        buf[(x, row_y)].set_style(self.selection_style);
                    }
                }
            }

            self.rows[row_idx].render(col_xs, col_widths, buf, y, bottom);

            y += rh;
            row_idx += 1;
        }

        // Render vertical scrollbar. With a windowed (viewport) slice the
        // content length and the true offset are supplied by the caller —
        // the slice length alone would pin the thumb at full-track.
        if self.show_scrollbar && scrollbar_area.width > 0 && total_rows > 0 {
            let visible_rows = rows_from_end.max(1);
            let lengths = ScrollLengths {
                content_len: self.total_rows.unwrap_or(total_rows).max(1),
                viewport_len: visible_rows.max(1),
            };
            let scrollbar = ScrollBar::vertical(lengths)
                .offset(self.scrollbar_offset.unwrap_or(state.offset))
                .thumb_style(self.scrollbar_thumb_style)
                .track_style(self.scrollbar_track_style)
                .glyph_set(GlyphSet::minimal());
            scrollbar.render(scrollbar_area, buf);
        }

        // Update selected within bounds
        if let Some(sel) = state.selected {
            if sel >= total_rows {
                state.selected = if total_rows > 0 { Some(0) } else { None };
            }
        } else if total_rows > 0 {
            state.selected = Some(0);
        }
    }
}

impl<R: DataTableRow> Widget for DataTable<'_, R> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let mut state = DataTableState::default();
        StatefulWidget::render(self, area, buf, &mut state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test row that records the `clip_bottom` it received and writes a
    /// marker cell at its start line, obeying the same no-write-past-
    /// `clip_bottom` invariant the real row types must follow.
    struct ClipRow {
        height: u16,
        marker: char,
        clip_seen: std::cell::Cell<u16>,
    }

    impl DataTableRow for ClipRow {
        fn render(
            &self,
            col_xs: &[u16],
            col_widths: &[u16],
            buf: &mut Buffer,
            y: u16,
            clip_bottom: u16,
        ) {
            self.clip_seen.set(clip_bottom);
            if y >= clip_bottom {
                return;
            }
            let x = col_xs.first().copied().unwrap_or(0);
            let w = col_widths.first().copied().unwrap_or(1) as usize;
            buf.set_stringn(x, y, self.marker.to_string(), w, Style::default());
        }

        fn height(&self, _available_width: u16) -> u16 {
            self.height
        }
    }

    fn one_column_table(rows: &[ClipRow]) -> DataTable<'_, ClipRow> {
        DataTable::new(vec![Column::new("h", ColumnWidth::Fixed(10))], rows)
    }

    #[test]
    fn rows_taller_than_viewport_are_clipped_not_blank() {
        // A single expanded-style row (height 10) in a 4-line area: the old
        // render loop broke out and rendered nothing at all.
        let rows = vec![ClipRow {
            height: 10,
            marker: 'A',
            clip_seen: std::cell::Cell::new(0),
        }];
        let area = Rect::new(0, 0, 20, 4);
        let mut buf = Buffer::empty(area);
        let mut state = DataTableState {
            offset: 0,
            selected: Some(0),
            multi_selected: HashSet::new(),
        };
        StatefulWidget::render(one_column_table(&rows), area, &mut buf, &mut state);

        // The row must have been told to clip exactly at the area bottom…
        assert_eq!(
            rows[0].clip_seen.get(),
            4,
            "clip_bottom must be the area bottom"
        );
        // …and must have rendered something (no blank table).
        assert_eq!(buf[(0, 1)].symbol(), "A");
        // Nothing may be written at or past the clip line.
        assert_eq!(buf[(0, 3)].symbol(), " ");
    }

    #[test]
    fn rows_taller_than_viewport_never_exceed_area_bottom() {
        // Every row that renders must receive a clip_bottom at or below the
        // area bottom — never above it.
        let rows: Vec<ClipRow> = (0..3)
            .map(|i| ClipRow {
                height: 10,
                marker: char::from(b'A' + i),
                clip_seen: std::cell::Cell::new(0),
            })
            .collect();
        let area = Rect::new(0, 0, 20, 6);
        let mut buf = Buffer::empty(area);
        let mut state = DataTableState {
            offset: 0,
            selected: None,
            multi_selected: HashSet::new(),
        };
        StatefulWidget::render(one_column_table(&rows), area, &mut buf, &mut state);

        assert!(
            rows.iter().all(|r| r.clip_seen.get() <= 6),
            "clip_bottom must never exceed the area bottom"
        );
        // First row rendered at y=1; the area below it stays empty.
        assert_eq!(buf[(0, 1)].symbol(), "A");
        assert_eq!(buf[(0, 5)].symbol(), " ");
    }
}
