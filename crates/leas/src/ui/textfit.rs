//! Display-width text fitting for the Settings popup and Sources tab.
//!
//! Every helper measures **terminal cells** (unicode-width), never `char`
//! count — `{:<width$}` padding and `chars().count()` truncation misalign on
//! CJK text, which the settings forms already render (subscription names).
//!
//! Limitation (named): ZWJ emoji sequences are walked per char and can
//! over-count by one cell per joiner; acceptable for labels/values the popup
//! carries today.

use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Display width of `s` in terminal cells.
#[must_use]
pub fn width(s: &str) -> usize {
    s.width()
}

/// Exactly `width` cells: truncate (with `…`) then pad with spaces.
#[must_use]
pub fn pad(s: &str, width: usize) -> String {
    let mut out = truncate(s, width);
    let shown = out.width();
    out.extend(std::iter::repeat_n(' ', width.saturating_sub(shown)));
    out
}

/// At most `width` cells; a truncation ends with `…` inside the budget.
#[must_use]
pub fn truncate(s: &str, width: usize) -> String {
    if s.width() <= width {
        return s.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let budget = width - 1; // one cell for the ellipsis
    let mut out = String::new();
    let mut cells = 0;
    for c in s.chars() {
        let w = c.width().unwrap_or(0);
        if cells + w > budget {
            break;
        }
        out.push(c);
        cells += w;
    }
    out.push('…');
    out
}

/// At most `width` cells, dropping the HEAD: a leading `…` followed by the
/// last `width - 1` cells of `s`. For a value being edited the freshest part
/// is at the end (typing appends), so the tail survives and the ellipsis
/// marks what was cut. Callers reserve the cursor cell in `width` and append
/// `█` themselves.
///
/// A string that already fits is returned unchanged.
#[must_use]
pub fn truncate_head(s: &str, width: usize) -> String {
    if s.width() <= width {
        return s.to_owned();
    }
    if width <= 1 {
        return (width == 1).then(|| "…".to_owned()).unwrap_or_default();
    }
    let keep = width - 1; // one cell for the ellipsis
    let kept: String = s
        .chars()
        .rev()
        .scan(0, |acc, c| {
            let w = c.width().unwrap_or(0);
            if *acc + w > keep {
                None
            } else {
                *acc += w;
                Some(c)
            }
        })
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{kept}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_measures_display_width_not_chars() {
        // "配置" is 2 chars but 4 cells.
        assert_eq!(width("配置"), 4);
        assert_eq!(pad("ab", 5), "ab   ");
        // 7 cells of content in 6: the first 5 cells + the ellipsis cell.
        assert_eq!(pad("配置xyz", 6), "配置x…");
        // ASCII labels keep their old column alignment.
        assert_eq!(pad("SOCKS Port", 12), "SOCKS Port  ");
    }

    #[test]
    fn truncate_reserves_the_ellipsis_cell() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
        assert_eq!(truncate("abcdefg", 6), "abcde…");
        assert_eq!(truncate("配置配置", 5), "配置…"); // 4 + 1 = 5 cells
        assert_eq!(truncate("", 0), "");
        assert_eq!(truncate("ab", 1), "…");
        assert_eq!(truncate("abc", 0), "");
    }

    #[test]
    fn truncate_head_keeps_the_cursor_cell() {
        // Head-drop: the value's end survives (typing appends); the caller
        // reserves one cell of the budget and appends the █ Span itself.
        assert_eq!(truncate_head("abcdefg", 5), "…defg"); // … + last 4 cells
        assert_eq!(truncate_head("ab", 5), "ab");
        assert_eq!(truncate_head("配置xyz", 4), "…xyz"); // … + last 3 cells
        assert_eq!(truncate_head("abcdefg", 7), "abcdefg");
        assert_eq!(truncate_head("abcdef", 1), "…");
        assert_eq!(truncate_head("abcdef", 0), "");
    }
}
