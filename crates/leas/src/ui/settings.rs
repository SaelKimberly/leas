use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui_cheese::field::ValidationKind;
use ratatui_cheese::input::{Input, InputState};
use ratatui_cheese::list::{List, ListItem, ListItemContext, ListState};
use std::collections::{HashMap, HashSet};

use crate::ui::theme::ThemeStyles;
use crate::ui::widgets::progress::bar_cells;
use crate::{
    AppMode, AppState, BackendUpdateStatus, SectionList, SettingsMode, SettingsSection, SplitFocus,
    SplitRightPane,
};
use leas_core::CoreType;
// ── Settings section data — the source of the left list and its filter ──

struct SettingsTreeNode {
    name: &'static str,
    section: Option<SettingsSection>,
}

struct SettingsTreeGroup {
    name: &'static str,
    items: &'static [SettingsTreeNode],
}

const SETTINGS_TREE: &[SettingsTreeGroup] = &[
    SettingsTreeGroup {
        name: "Core",
        items: &[
            SettingsTreeNode {
                name: "Core Settings",
                section: Some(SettingsSection::Core),
            },
            SettingsTreeNode {
                name: "Protocol Core",
                section: Some(SettingsSection::ProtocolCore),
            },
        ],
    },
    SettingsTreeGroup {
        name: "Connection",
        items: &[
            SettingsTreeNode {
                name: "Inbound",
                section: Some(SettingsSection::Inbound),
            },
            SettingsTreeNode {
                name: "System Proxy",
                section: Some(SettingsSection::SystemProxy),
            },
            SettingsTreeNode {
                name: "TUN",
                section: Some(SettingsSection::Tun),
            },
            SettingsTreeNode {
                name: "Mux",
                section: Some(SettingsSection::Mux),
            },
        ],
    },
    SettingsTreeGroup {
        name: "Routing",
        items: &[
            SettingsTreeNode {
                name: "Routing Rules",
                section: Some(SettingsSection::Routing),
            },
            SettingsTreeNode {
                name: "Probe Hosts",
                section: Some(SettingsSection::RouteProbes),
            },
            SettingsTreeNode {
                name: "DNS",
                section: Some(SettingsSection::Dns),
            },
        ],
    },
    SettingsTreeGroup {
        name: "GUI",
        items: &[SettingsTreeNode {
            name: "GUI Settings",
            section: Some(SettingsSection::Gui),
        }],
    },
    SettingsTreeGroup {
        name: "Advanced",
        items: &[
            SettingsTreeNode {
                name: "Statistics",
                section: Some(SettingsSection::Stats),
            },
            SettingsTreeNode {
                name: "Updates",
                section: Some(SettingsSection::Updates),
            },
            SettingsTreeNode {
                name: "Speed Test",
                section: Some(SettingsSection::SpeedTest),
            },
            SettingsTreeNode {
                name: "Logging",
                section: Some(SettingsSection::Logging),
            },
            SettingsTreeNode {
                name: "Subscriptions",
                section: Some(SettingsSection::Subscriptions),
            },
        ],
    },
];

/// Leaves of `SETTINGS_TREE` in document order: the index space that
/// `SectionList::selected` lives in, so filtering or collapsing the list never
/// moves the selection onto a different section (spec D2/D4).
fn leaf_count() -> usize {
    SETTINGS_TREE.iter().map(|g| g.items.len()).sum()
}

/// Flat leaf index of `(group, child)`.
fn leaf_index(group: usize, child: usize) -> usize {
    SETTINGS_TREE
        .iter()
        .take(group)
        .map(|g| g.items.len())
        .sum::<usize>()
        + child
}

/// `(group, child)` of a flat leaf index.
fn leaf_position(leaf: usize) -> Option<(usize, usize)> {
    let mut start = 0usize;
    for (group, g) in SETTINGS_TREE.iter().enumerate() {
        if leaf < start + g.items.len() {
            return Some((group, leaf - start));
        }
        start += g.items.len();
    }
    None
}

fn leaf_section(leaf: usize) -> Option<SettingsSection> {
    let (group, child) = leaf_position(leaf)?;
    SETTINGS_TREE[group].items[child].section
}

/// The leaf index a section sits at, so an entry point that jumps to a
/// section (`g` -> Subscriptions) can move the selection with it.
#[must_use]
pub fn section_leaf_index(section: SettingsSection) -> usize {
    (0..leaf_count())
        .find(|leaf| leaf_section(*leaf) == Some(section))
        .unwrap_or(0)
}

fn leaf_group(leaf: usize) -> Option<usize> {
    leaf_position(leaf).map(|(group, _)| group)
}

fn leaf_name(leaf: usize) -> Option<&'static str> {
    let (group, child) = leaf_position(leaf)?;
    Some(SETTINGS_TREE[group].items[child].name)
}

/// Case-insensitive substring match; an empty query matches everything.
fn matches_filter(query: &str, text: &str) -> bool {
    query.is_empty() || text.to_lowercase().contains(&query.to_lowercase())
}

/// A leaf matches on its own name or on its group's name (spec D7).
fn leaf_matches(leaf: usize, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let Some(group) = leaf_group(leaf) else {
        return false;
    };
    matches_filter(query, SETTINGS_TREE[group].name)
        || leaf_name(leaf).is_some_and(|name| matches_filter(query, name))
}

/// Leaves the list shows, in document order: filtered, and hidden by collapse
/// unless a filter is active (a search always reveals its own matches).
fn visible_leaves(query: &str, sections: &SectionList) -> Vec<usize> {
    (0..leaf_count())
        .filter(|leaf| {
            leaf_matches(*leaf, query)
                && (!query.is_empty() || leaf_group(*leaf).is_some_and(|g| sections.is_expanded(g)))
        })
        .collect()
}

/// One display row of the sections pane.
enum SectionRow {
    /// A group header. When the selected leaf is hidden inside a collapsed
    /// group, the header's row carries the highlight instead.
    Group {
        group: usize,
        collapsed: bool,
    },
    Leaf {
        leaf: usize,
    },
}

/// Build the sections pane's rows plus the row index that carries the
/// highlight (spec D2/D4).
fn section_rows(query: &str, sections: &SectionList) -> (Vec<SectionRow>, Option<usize>) {
    let visible: HashSet<usize> = visible_leaves(query, sections).into_iter().collect();
    let selected_group = leaf_group(sections.selected);
    let mut rows = Vec::new();
    let mut selected_row = None;
    for (group, g) in SETTINGS_TREE.iter().enumerate() {
        let collapsed = query.is_empty() && !sections.is_expanded(group);
        let holds_selection = collapsed && selected_group == Some(group);
        let children: Vec<usize> = (0..g.items.len())
            .map(|child| leaf_index(group, child))
            .filter(|leaf| visible.contains(leaf))
            .collect();
        if children.is_empty() && !holds_selection {
            continue;
        }
        rows.push(SectionRow::Group { group, collapsed });
        if holds_selection {
            selected_row = Some(rows.len() - 1);
        }
        if collapsed {
            continue;
        }
        for leaf in children {
            if leaf == sections.selected {
                selected_row = Some(rows.len());
            }
            rows.push(SectionRow::Leaf { leaf });
        }
    }
    (rows, selected_row)
}

/// `n/N` for a pane title: 1-based, clamped, `0/0` when the pane is empty
/// (spec D3).
fn counter_label(row: usize, total: usize) -> String {
    if total == 0 {
        return "0/0".to_string();
    }
    format!("{}/{}", (row + 1).min(total), total)
}

/// The options a selector offers, in cycle order (spec R2).
///
/// `Select:a,b,c` is the static list; `SelectThemes` resolves the builtin
/// opaline slugs at runtime, so the theme setting cannot name a theme the app
/// cannot load — and the list grows with opaline instead of drifting from it.
pub fn select_options(field_type: &str) -> Option<Vec<String>> {
    if let Some(options) = field_type.strip_prefix("Select:") {
        return Some(options.split(',').map(str::to_string).collect());
    }
    match field_type {
        "SelectThemes" => {
            let mut ids: Vec<String> = opaline::builtins::builtin_names()
                .iter()
                .map(|(id, _)| (*id).to_string())
                .collect();
            ids.sort_unstable();
            Some(ids)
        }
        _ => None,
    }
}

/// Whether the focused field of `section`'s form accepts pasted free text.
///
/// A selector and a boolean have no free text: pasting into one would replace a
/// value the user chose with Space, so the payload is dropped. An index past
/// the declared fields (the form was opened with no data) takes nothing either.
#[must_use]
pub fn field_accepts_paste(section: SettingsSection, focus_index: usize) -> bool {
    let defs = form_field_defs_for_section(section);
    match defs.get(focus_index) {
        Some((_key, _label, field_type)) => {
            select_options(field_type).is_none() && *field_type != "Boolean"
        }
        None => false,
    }
}

/// One step along a selector, wrapping past the last option back to the first
/// (spec R2).
///
/// A stored value that is no longer offered (a theme removed from opaline, a
/// config written by a newer build) lands on the first option going forward,
/// the last going back — stepping "one past where it claims to be" would show
/// the user the second option and look like a skip.
fn cycle_select(current: &str, options: &[String], forward: bool) -> String {
    if options.is_empty() {
        return current.to_string();
    }
    let Some(index) = options.iter().position(|o| o == current) else {
        return options[if forward { 0 } else { options.len() - 1 }].clone();
    };
    let next = if forward {
        index + 1
    } else {
        (index + options.len() - 1) % options.len()
    };
    options[next % options.len()].clone()
}

/// One step along a boolean, in either direction: `Space`/`Enter`/any printable
/// key and `←`/`→` all land on the opposite value.
///
/// Read the stored value BEFORE overwriting it. The previous arm cleared the
/// buffer first and then asked whether it read `"true"`, so the comparison
/// always saw an empty string and every edit wrote `"true"` — a boolean could
/// be set but never unset.
const fn toggle_bool(current: &str) -> &'static str {
    if current.eq_ignore_ascii_case("true") {
        "false"
    } else {
        "true"
    }
}

/// How a field's value renders in the list (spec D5).
fn value_display(field_type: &str, value: &str) -> String {
    if field_type == "Boolean" {
        return if value == "true" { "✓" } else { "✗" }.to_string();
    }
    if value.is_empty() {
        return "—".to_string();
    }
    if select_options(field_type).is_some() {
        return format!("< {value} >");
    }
    value.to_string()
}

/// Provenance marker: `*` when the field differs from the values the pane was
/// built with, `·` otherwise (spec D4).
fn provenance_marker(snapshot: Option<&str>, current: &str) -> char {
    match snapshot {
        Some(base) if base != current => '*',
        _ => '·',
    }
}

/// What the field accepts, for the help box (spec D10).
fn field_accepts(field_type: &str) -> String {
    match field_type {
        "Boolean" => "true / false".to_string(),
        "Number" => "digits".to_string(),
        "Url" => "a URL".to_string(),
        "Duration" => "a duration, e.g. 5s, 1h30m".to_string(),
        // A 39-slug list is noise in a one-line box; the value already names
        // the slug, so the box states the rule and the count.
        "SelectThemes" => format!(
            "a builtin theme slug ({} available)",
            opaline::builtins::builtin_names().len()
        ),
        _ => select_options(field_type)
            .map_or_else(|| "free text".to_string(), |options| options.join(", ")),
    }
}

/// The type as a word, for the help box.
fn field_type_label(field_type: &str) -> &'static str {
    match field_type {
        "Boolean" => "Boolean",
        "Number" => "Number",
        "Url" => "URL",
        "Duration" => "Duration",
        "SelectThemes" => "Select",
        _ if select_options(field_type).is_some() => "Select",
        _ => "Text",
    }
}

const fn section_name(section: SettingsSection) -> &'static str {
    match section {
        SettingsSection::Core => "Core",
        SettingsSection::Gui => "GUI",
        SettingsSection::Inbound => "Inbound",
        SettingsSection::Routing => "Routing",
        SettingsSection::Dns => "DNS",
        SettingsSection::SystemProxy => "System Proxy",
        SettingsSection::Tun => "TUN",
        SettingsSection::Mux => "Mux",
        SettingsSection::Stats => "Statistics",
        SettingsSection::Subscriptions => "Subscriptions",
        SettingsSection::ProtocolCore => "Protocol Core",
        SettingsSection::SpeedTest => "Speed Test",
        SettingsSection::Logging => "Logging",
        SettingsSection::Updates => "Updates",
        SettingsSection::RouteProbes => "Probe Hosts",
    }
}

// ── Public entry points ─────────────────────────────────────────────────

/// True when the open settings form differs from the snapshot taken when the
/// pane was built (spec P3 — drives the popup title's `*` and the Esc guard).
pub fn form_is_dirty(state: &AppState) -> bool {
    match &state.mode {
        AppMode::Settings {
            mode:
                SettingsMode::Split {
                    right: SplitRightPane::Form { fields, .. },
                    ..
                },
            ..
        } => state
            .settings_form_snapshot
            .as_ref()
            .is_some_and(|snap| *snap != *fields),
        _ => false,
    }
}

/// Four bands, as in the reference (spec §4): bar / split / help / status.
///
/// The footer hints live in the popup's bottom border (spec D9), so
/// `ui::status_bar` drops its own settings hints while this popup is open.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let AppMode::Settings {
        mode: SettingsMode::Split { focus, right },
    } = &state.mode
    else {
        return;
    };
    let theme = state.theme();
    let status_rows = u16::from(settings_status(state).is_some());
    // The help band yields before the sections/values split does, so a short
    // terminal loses help rows rather than the list itself (spec §4).
    let help_rows = 10u16.min(area.height.saturating_sub(3 + 7 + status_rows));
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(7),
            Constraint::Length(help_rows),
            Constraint::Length(status_rows),
        ])
        .split(area);
    render_input_bar(frame, rows[0], state, theme);
    let left_pct = if rows[1].width < 80 { 0.35 } else { 0.30 };
    let left_w = (f64::from(rows[1].width) * left_pct) as u16;
    let (left_area, right_area) = split_rect(rows[1], left_w);
    render_sections(frame, left_area, state, theme, *focus);
    render_right_pane(frame, right_area, state, theme, right, *focus);
    render_help(frame, rows[2], theme, right);
    if status_rows > 0 {
        render_status(frame, rows[3], state, theme);
    }
}

/// The input bar: the filter while it is active, what is being edited
/// otherwise (spec §4 band 0).
fn render_input_bar(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let editing = match &state.mode {
        AppMode::Settings {
            mode:
                SettingsMode::Split {
                    right:
                        SplitRightPane::Form {
                            section,
                            focus_index,
                            ..
                        },
                    ..
                },
        } => form_field_defs_for_section(*section)
            .get(*focus_index)
            .copied(),
        _ => None,
    };
    let active = state.settings_search.active;
    // The bar names the field you are editing only while the Values pane has
    // focus; with Sections focused there is no cursor in a field.
    let editing = if matches!(
        &state.mode,
        AppMode::Settings {
            mode: SettingsMode::Split {
                focus: SplitFocus::Right,
                ..
            },
        }
    ) {
        editing
    } else {
        None
    };
    let (title, body, body_style) = if active {
        let body = if state.settings_search.query.is_empty() {
            "Press / to filter settings".to_string()
        } else {
            format!("{}█", state.settings_search.query)
        };
        (
            " Filter ".to_string(),
            body,
            ThemeStyles::footer_value(theme),
        )
    } else if let Some((_, label, field_type)) = editing {
        let how = if select_options(field_type).is_some() {
            "[Space]/[Enter] next value · [←→] step · [Tab] next field"
        } else if field_type == "Boolean" {
            "any key toggles · [Tab] next field"
        } else {
            "type to change · [Backspace] erase · [Tab] next field"
        };
        (
            format!(" Edit {label} · {} ", field_type_label(field_type)),
            how.to_string(),
            ThemeStyles::footer_label(theme),
        )
    } else {
        (
            " Search ".to_string(),
            "Press / to filter settings".to_string(),
            ThemeStyles::hint(theme),
        )
    };
    let border = if active || editing.is_some() {
        ThemeStyles::container_border_focused(theme)
    } else {
        ThemeStyles::container_border(theme)
    };
    let bar = Paragraph::new(Line::styled(body, body_style)).block(
        Block::default()
            .title(title)
            .title_style(ThemeStyles::container_title(theme))
            .borders(Borders::ALL)
            .border_style(border),
    );
    frame.render_widget(bar, area);
}

/// The sections list (spec D2): group headers with `▾`/`▸`, leaves indented,
/// the selected row marked `›`, counters in the title (spec D3).
fn render_sections(
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    theme: &opaline::Theme,
    focus: SplitFocus,
) {
    let query = state.settings_search.query.as_str();
    let (rows, selected_row) = section_rows(query, &state.settings_sections);
    // A counter that does not fit is clipped mid-number ("2/" at 50 cols),
    // which reads as a broken value; drop it on a narrow pane instead.
    let title = if area.width >= 18 {
        format!(
            " Sections · {} ",
            counter_label(selected_row.unwrap_or(0), rows.len())
        )
    } else {
        " Sections ".to_string()
    };
    let block = Block::default()
        .title(title)
        .title_style(ThemeStyles::container_title(theme))
        .borders(Borders::ALL)
        .border_style(if focus == SplitFocus::Tree {
            ThemeStyles::container_border_focused(theme)
        } else {
            ThemeStyles::container_border(theme)
        });
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let height = inner.height as usize;
    // Keep the highlighted row on screen; the list is short, so this is the
    // only scroll that matters (no stored offset to keep in step).
    let start = selected_row
        .unwrap_or(0)
        .saturating_sub(height.saturating_sub(1))
        .min(rows.len().saturating_sub(height));
    let lines: Vec<Line> = rows
        .iter()
        .skip(start)
        .take(height)
        .enumerate()
        .map(|(offset, row)| {
            let selected = Some(start + offset) == selected_row;
            let marker = if selected { "› " } else { "  " };
            let style = if selected {
                ThemeStyles::table_row_selected(theme).add_modifier(Modifier::BOLD)
            } else {
                match row {
                    SectionRow::Group { .. } => {
                        ThemeStyles::footer_label(theme).add_modifier(Modifier::BOLD)
                    }
                    SectionRow::Leaf { .. } => ThemeStyles::table_row_normal(theme),
                }
            };
            let text = match row {
                SectionRow::Group {
                    group, collapsed, ..
                } => {
                    let chevron = if *collapsed { "▸" } else { "▾" };
                    format!("{marker}{chevron} {}", SETTINGS_TREE[*group].name)
                }
                SectionRow::Leaf { leaf } => {
                    format!("{marker}   {}", leaf_name(*leaf).unwrap_or_default())
                }
            };
            Line::styled(text, style)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The help band (spec D10): what the focused field is, and the marker legend.
fn render_help(frame: &mut Frame, area: Rect, theme: &opaline::Theme, right: &SplitRightPane) {
    let (title, lines) = help_content(theme, right);
    let block = Block::default()
        .title(title)
        .title_style(ThemeStyles::container_title(theme))
        .borders(Borders::ALL)
        .border_style(ThemeStyles::container_border(theme));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn help_content(theme: &opaline::Theme, right: &SplitRightPane) -> (String, Vec<Line<'static>>) {
    let label = ThemeStyles::footer_label(theme).add_modifier(Modifier::BOLD);
    let value = ThemeStyles::footer_value(theme);
    let row = |name: &str, text: String| {
        Line::from(vec![
            Span::styled(format!("{name:<9}"), label),
            Span::styled(text, value),
        ])
    };
    let legend = "· saved   * unsaved   › selected".to_string();
    match right {
        SplitRightPane::Form {
            section,
            fields,
            focus_index,
            ..
        } => {
            let defs = form_field_defs_for_section(*section);
            let Some((_, field_label, field_type)) = defs.get(*focus_index).copied() else {
                return (
                    format!(" Help · {} ", section_name(*section)),
                    vec![Line::styled(
                        " No field selected — [Tab] moves between fields.".to_string(),
                        ThemeStyles::hint(theme),
                    )],
                );
            };
            let current = fields
                .get(*focus_index)
                .map_or("", |(_, v)| v.as_str())
                .to_string();
            (
                format!(" Help · {} ", section_name(*section)),
                vec![
                    row("Field", (*field_label).to_string()),
                    row("Type", field_type_label(field_type).to_string()),
                    row("Accepts", field_accepts(field_type)),
                    row("Current", value_display(field_type, &current)),
                    row("Keys", legend),
                ],
            )
        }
        _ => (
            " Help ".to_string(),
            vec![
                row(
                    "Keys",
                    "[/] filter this pane   [Tab] focus   [Esc] back".to_string(),
                ),
                row("Legend", legend),
            ],
        ),
    }
}

/// What the status band shows (spec A7).
enum SettingsStatus {
    Error(String),
    Notice(String),
    Hint(String),
}

/// The status band (spec A7): a validation error, the filter-miss line, or the
/// last notice. `None` collapses the band.
fn settings_status(state: &AppState) -> Option<SettingsStatus> {
    if let AppMode::Settings {
        mode:
            SettingsMode::Split {
                right: SplitRightPane::Form { form_errors, .. },
                ..
            },
    } = &state.mode
        && let Some(message) = form_errors.values().next()
    {
        let count = form_errors.len();
        let prefix = if count > 1 {
            format!("{count} fields need attention — ")
        } else {
            String::new()
        };
        return Some(SettingsStatus::Error(format!("⚠ {prefix}{message}")));
    }
    let query = state.settings_search.query.as_str();
    if !query.is_empty() && visible_leaves(query, &state.settings_sections).is_empty() {
        return Some(SettingsStatus::Hint(format!(
            "No settings match \"{query}\" — [Ctrl+U] clear  [Esc] cancel"
        )));
    }
    state.settings_notice.clone().map(SettingsStatus::Notice)
}

fn render_status(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let Some(status) = settings_status(state) else {
        return;
    };
    let (text, style) = match status {
        SettingsStatus::Error(text) => (text, ThemeStyles::error(theme)),
        SettingsStatus::Notice(text) => (text, ThemeStyles::success(theme)),
        SettingsStatus::Hint(text) => (text, ThemeStyles::warning(theme)),
    };
    frame.render_widget(Paragraph::new(Line::styled(text, style)), area);
}

/// The popup's footer hints (spec D9), owned by `ui::status_bar` so the modal
/// border and the app status bar can never drift apart.
pub fn footer_hints(state: &AppState, popup_width: u16) -> String {
    crate::ui::status_bar::fit_hints(
        crate::ui::status_bar::settings_hints(state),
        popup_width.saturating_sub(2).max(20) as usize,
    )
}
pub async fn handle_key(state: &mut AppState, key: &KeyEvent) {
    handle_split_key(state, key).await;
}

// ── Split view ──────────────────────────────────────────────────────────

fn split_rect(area: Rect, left_w: u16) -> (Rect, Rect) {
    let gap = 1u16;
    let left = Rect {
        width: left_w.min(area.width.saturating_sub(gap)),
        ..area
    };
    let right_x = left.width.saturating_add(gap);
    let right = Rect {
        x: area.x.saturating_add(right_x),
        width: area.width.saturating_sub(right_x),
        ..area
    };
    (left, right)
}
fn render_right_pane(
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    theme: &opaline::Theme,
    right: &SplitRightPane,
    _focus: SplitFocus,
) {
    // Form panes get the `Values · i/n` title of the reference (spec A2); the
    // routing/update panes keep their own names.
    let title = match right {
        SplitRightPane::Form {
            section,
            focus_index,
            ..
        } => {
            let rows = visible_field_rows(*section);
            let position = (*focus_index).min(rows.len().saturating_sub(1));
            if area.width >= 18 {
                format!(" Values · {} ", counter_label(position, rows.len()))
            } else {
                " Values ".to_string()
            }
        }
        SplitRightPane::GroupForm { focus_index, .. } => {
            let rows = visible_field_rows(SettingsSection::Subscriptions);
            let position = (*focus_index).min(rows.len().saturating_sub(1));
            if area.width >= 18 {
                format!(" Values · {} ", counter_label(position, rows.len()))
            } else {
                " Values ".to_string()
            }
        }
        SplitRightPane::RoutingList { .. } => " Routing Rules ".to_string(),
        SplitRightPane::RoutingForm { .. } => " Routing Rule ".to_string(),
        SplitRightPane::UpdateForm { .. } => " Updates ".to_string(),
        SplitRightPane::GroupList { .. } => " Subscriptions ".to_string(),
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(ThemeStyles::container_border(theme));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // Render form content inside the block
    match right {
        SplitRightPane::Form {
            section,
            fields,
            focus_index,
            form_errors,
        } => {
            render_form_with_area(
                frame,
                inner,
                theme,
                *section,
                fields.as_slice(),
                *focus_index,
                form_errors,
                state.settings_form_snapshot.as_ref(),
            );
        }
        SplitRightPane::RoutingList { selected } => {
            render_routing_list_inner(frame, inner, state, theme, *selected);
        }
        SplitRightPane::RoutingForm {
            fields,
            focus_index,
            form_errors,
            ..
        } => {
            render_routing_form_inner(
                frame,
                inner,
                theme,
                fields.as_slice(),
                *focus_index,
                form_errors,
            );
        }
        SplitRightPane::UpdateForm {
            status_xray,
            status_singbox,
        } => {
            render_update_form_inner(frame, inner, theme, status_xray, status_singbox);
        }
        SplitRightPane::GroupList {
            selected,
            selected_mask,
        } => {
            render_group_list_inner(frame, inner, state, theme, *selected, selected_mask);
        }
        SplitRightPane::GroupForm {
            fields,
            focus_index,
            form_errors,
            ..
        } => {
            render_form_with_area(
                frame,
                inner,
                theme,
                SettingsSection::Subscriptions,
                fields.as_slice(),
                *focus_index,
                form_errors,
                None,
            );
        }
    }
}

const fn toggle_split_focus(state: &mut AppState) {
    if let AppMode::Settings {
        mode: SettingsMode::Split { focus, .. },
    } = &mut state.mode
    {
        *focus = match focus {
            SplitFocus::Tree => SplitFocus::Right,
            SplitFocus::Right => SplitFocus::Tree,
        };
    }
}

async fn handle_split_key(state: &mut AppState, key: &KeyEvent) {
    // The filter bar owns the keyboard while it is active (spec §5).
    if state.settings_search.active {
        handle_search_key(state, key).await;
        return;
    }
    // `/` opens the filter. It is only claimed where it cannot be text: a
    // text field on the right pane keeps its own slash.
    if key.code == KeyCode::Char('/')
        && !key.modifiers.contains(KeyModifiers::CONTROL)
        && search_available(state)
    {
        state.settings_search.active = true;
        return;
    }
    // Ctrl+W toggles focus between tree and right pane
    if key.code == KeyCode::Char('w') && key.modifiers.contains(KeyModifiers::CONTROL) {
        toggle_split_focus(state);
        return;
    }

    // Determine focus and right pane type without holding a borrow
    let focus = match &state.mode {
        AppMode::Settings {
            mode: SettingsMode::Split { focus, .. },
        } => *focus,
        _ => return,
    };

    match focus {
        SplitFocus::Tree => handle_sections_key(state, key).await,
        SplitFocus::Right => {
            let pane_type = match &state.mode {
                AppMode::Settings {
                    mode: SettingsMode::Split { right, .. },
                } => match right {
                    SplitRightPane::Form { .. } => 1,
                    SplitRightPane::RoutingList { .. } => 2,
                    SplitRightPane::RoutingForm { .. } => 3,
                    SplitRightPane::UpdateForm { .. } => 4,
                    SplitRightPane::GroupList { .. } => 5,
                    SplitRightPane::GroupForm { .. } => 6,
                },
                _ => return,
            };
            match pane_type {
                1 => handle_form_key(state, key).await,
                2 => handle_routing_list_key(state, key).await,
                3 => handle_routing_form_key(state, key).await,
                4 => handle_update_form_key(state, key),
                5 => handle_group_list_key(state, key).await,
                6 => handle_group_form_key(state, key).await,
                _ => {}
            }
        }
    }
}

/// True where `/` cannot collide with text entry (spec §5): the sections
/// pane, an empty right pane, or one of the right pane's list modes.
fn search_available(state: &AppState) -> bool {
    match &state.mode {
        AppMode::Settings {
            mode: SettingsMode::Split { focus, right },
        } => {
            *focus == SplitFocus::Tree
                || matches!(
                    right,
                    SplitRightPane::RoutingList { .. } | SplitRightPane::GroupList { .. }
                )
        }
        _ => false,
    }
}

/// Keys while the filter bar is active: it consumes printable input, and
/// `Enter` applies while `Esc` cancels (spec §5).
async fn handle_search_key(state: &mut AppState, key: &KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            state.settings_search.query.clear();
            state.settings_search.active = false;
        }
        KeyCode::Enter => {
            state.settings_search.active = false;
        }
        KeyCode::Backspace => {
            state.settings_search.query.pop();
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.settings_search.query.clear();
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.settings_search.query.push(c);
        }
        _ => return,
    }
    // A filter can move the selection (R1), so the pane follows it — otherwise
    // the highlight names one section while the fields show another.
    if snap_selection_to_filter(state) {
        load_selected_section(state).await;
    }
}

/// Keep the selection on a row the filter actually shows (spec D7). Returns
/// whether the selection moved.
fn snap_selection_to_filter(state: &mut AppState) -> bool {
    let query = state.settings_search.query.clone();
    let visible = visible_leaves(&query, &state.settings_sections);
    if let Some(first) = visible.first()
        && !visible.contains(&state.settings_sections.selected)
    {
        state.settings_sections.selected = *first;
        return true;
    }
    false
}

/// Load the selected section's pane into the Values side. Focus is untouched:
/// moving the selection shows the settings, it does not jump the cursor there.
async fn load_selected_section(state: &mut AppState) {
    let Some(section) = leaf_section(state.settings_sections.selected) else {
        return;
    };
    // A stale "Saved X" from the previous section would read as if the new one
    // were saved.
    state.settings_notice = None;
    let pane = state.build_right_pane(section).await;
    if let AppMode::Settings {
        mode: SettingsMode::Split { right, .. },
    } = &mut state.mode
    {
        *right = pane;
    }
}

/// Move the selection by one visible row, in either direction, clamping at
/// the ends (spec D2).
fn step_selection(state: &mut AppState, forward: bool) {
    let query = state.settings_search.query.clone();
    let visible = visible_leaves(&query, &state.settings_sections);
    let Some(last) = visible.len().checked_sub(1) else {
        return;
    };
    let current = state.settings_sections.selected;
    let next = match visible.iter().position(|leaf| *leaf == current) {
        Some(position) if forward => visible[(position + 1).min(last)],
        Some(position) => visible[position.saturating_sub(1)],
        None if forward => visible
            .iter()
            .find(|leaf| **leaf > current)
            .copied()
            .unwrap_or(visible[last]),
        None => visible
            .iter()
            .rev()
            .find(|leaf| **leaf < current)
            .copied()
            .unwrap_or(visible[0]),
    };
    state.settings_sections.selected = next;
}

async fn handle_sections_key(state: &mut AppState, key: &KeyEvent) {
    // Esc exits Settings mode — the help overlay advertises "Esc — Close
    // settings", and previously Esc was a dead key while the list had focus.
    if key.code == KeyCode::Esc {
        state.mode = AppMode::List;
        return;
    }

    if key.code == KeyCode::Enter {
        let selected = state.settings_sections.selected;
        // A collapsed group holds the highlight: the first `Enter` expands it
        // rather than opening a section the user cannot see (spec D4).
        if let Some(group) = leaf_group(selected)
            && !state.settings_sections.is_expanded(group)
        {
            state.settings_sections.toggle_expanded(group);
            return;
        }
        load_selected_section(state).await;
        if let AppMode::Settings {
            mode: SettingsMode::Split { focus, .. },
        } = &mut state.mode
        {
            // `Enter` is the only key that moves focus into the pane.
            *focus = SplitFocus::Right;
        }
        return;
    }

    // Tab moves focus into the Values pane (spec §5): a key that silently
    // closed the popup was a trap — nothing on screen said so — and the pane
    // pair is what Tab means everywhere else in the shell. `Ctrl+W` keeps
    // toggling, so the two agree.
    if key.code == KeyCode::Tab || key.code == KeyCode::BackTab {
        if let AppMode::Settings {
            mode: SettingsMode::Split { focus, .. },
        } = &mut state.mode
        {
            *focus = SplitFocus::Right;
        }
        return;
    }

    match key.code {
        // The selection's pane is loaded as it moves (spec R1): the reference
        // shows a section's settings the moment you move onto it, so nothing
        // waits for `Enter` and no two-step "move, then open" exists.
        KeyCode::Up => {
            step_selection(state, false);
            load_selected_section(state).await;
        }
        KeyCode::Down => {
            step_selection(state, true);
            load_selected_section(state).await;
        }
        KeyCode::Left => {
            // Collapse the group that owns the selection.
            if let Some(group) = leaf_group(state.settings_sections.selected) {
                state.settings_sections.toggle_expanded(group);
            }
        }
        // `→` is the way right: it expands a collapsed group first (there is
        // nothing to show yet), then moves focus into the Values pane. Values
        // keeps `←`/`→` for stepping a selector, which is what the cursor is
        // doing there.
        KeyCode::Right => {
            let collapsed = leaf_group(state.settings_sections.selected)
                .is_some_and(|group| !state.settings_sections.is_expanded(group));
            if collapsed {
                state
                    .settings_sections
                    .toggle_expanded(leaf_group(state.settings_sections.selected).unwrap_or(0));
            } else {
                toggle_split_focus(state);
            }
        }
        _ => {}
    }
}

pub static PROTOCOL_CORE_DEFS: &[(&str, &str, &str)] = &[
    ("vmess", "VMess", "Select:Auto,Xray,SingBox"),
    ("vless", "VLESS", "Select:Auto,Xray,SingBox"),
    ("ss", "Shadowsocks", "Select:Auto,Xray,SingBox"),
    ("ss-2022", "SS-2022", "Select:Auto,Xray,SingBox"),
    ("socks", "SOCKS", "Select:Auto,Xray,SingBox"),
    ("http", "HTTP", "Select:Auto,Xray,SingBox"),
    ("trojan", "Trojan", "Select:Auto,Xray,SingBox"),
    ("wireguard", "WireGuard", "Select:Auto,Xray,SingBox"),
    ("hy2", "Hysteria2", "Select:Auto,Xray,SingBox"),
    ("hy", "Hysteria", "Select:Auto,Xray,SingBox"),
    ("tuic", "TUIC", "Select:Auto,Xray,SingBox"),
    ("naive", "Naïve", "Select:Auto,Xray,SingBox"),
    ("any-tls", "AnyTLS", "Select:Auto,Xray,SingBox"),
    ("shadow-tls", "ShadowTLS", "Select:Auto,Xray,SingBox"),
    ("tor", "Tor", "Select:Auto,Xray,SingBox"),
    ("ssh", "SSH", "Select:Auto,Xray,SingBox"),
    ("ssr", "ShadowsocksR", "Select:Auto,Xray,SingBox"),
    ("redirect", "Redirect", "Select:Auto,Xray,SingBox"),
    ("dokodemo", "Dokodemo-door", "Select:Auto,Xray,SingBox"),
    ("t-proxy", "TProxy", "Select:Auto,Xray,SingBox"),
    ("mixed", "Mixed", "Select:Auto,Xray,SingBox"),
    ("tailscale", "Tailscale", "Select:Auto,Xray,SingBox"),
];
fn form_field_defs(mode: &SettingsMode) -> &'static [(&'static str, &'static str, &'static str)] {
    // &[(key, label, field_type)]
    // field_type: "Text", "Number", "Url", "Duration", "Boolean", "Select" (comma-separated)
    match mode {
        SettingsMode::Split {
            right: SplitRightPane::Form { section, .. },
            ..
        } => form_field_defs_for_section(*section),
        SettingsMode::Split { .. } => &[],
    }
}

fn form_field_defs_for_section(
    section: SettingsSection,
) -> &'static [(&'static str, &'static str, &'static str)] {
    match section {
        SettingsSection::Core => &[
            ("xray_path", "Xray Path", "Text"),
            ("sing_box_path", "Sing-Box Path", "Text"),
            ("log_level", "Log Level", "Select:debug,info,warning,error"),
            ("skip_cert_verify", "Skip Cert Verify", "Boolean"),
            ("clash_mixin", "Clash Mixin (JSON/YAML)", "Text"),
        ],
        SettingsSection::Gui => &[
            ("language", "Language", "Select:en,zh"),
            // A selector over opaline's builtin slugs: as free text it could
            // name a theme that does not exist, and `AppState::new` panics on
            // an unknown `theme_name` at the NEXT launch.
            ("theme", "Theme", "SelectThemes"),
            ("refresh_interval", "Refresh Interval", "Text"),
        ],
        SettingsSection::Inbound => &[
            ("socks_port", "SOCKS Port", "Number"),
            ("http_port", "HTTP Port", "Number"),
            ("mixed_port", "Mixed Port", "Number"),
            ("listen", "Listen Address", "Text"),
            ("sniffing", "Sniffing", "Boolean"),
        ],
        SettingsSection::Dns => &[
            ("servers", "Servers (JSON)", "Text"),
            ("hosts", "Hosts (JSON)", "Text"),
            (
                "query_strategy",
                "Query Strategy",
                "Select:,,UseIP,UseIPv4,UseIPv6",
            ),
            ("disable_cache", "Disable Cache", "Boolean"),
            ("disable_fallback", "Disable Fallback", "Boolean"),
            ("client_ip", "Client IP", "Text"),
            ("cache_ttl_secs", "DNS Cache TTL (secs)", "Number"),
        ],
        SettingsSection::SystemProxy => &[
            ("enabled", "Enabled", "Boolean"),
            ("http_port", "HTTP Port", "Number"),
            ("socks_port", "SOCKS Port", "Number"),
            ("bypass", "Bypass", "Text"),
        ],
        SettingsSection::Tun => &[
            ("enabled", "Enabled", "Boolean"),
            ("interface_name", "Interface Name", "Text"),
            ("mtu", "MTU", "Number"),
        ],
        SettingsSection::Mux => &[
            ("enabled", "Enabled", "Boolean"),
            ("concurrency", "Concurrency", "Number"),
            ("protocol", "Protocol", "Select:smux,yamux,h2mux"),
            ("max_connections", "Max Connections", "Number"),
            ("min_streams", "Min Streams", "Number"),
            ("max_streams", "Max Streams", "Number"),
            ("padding", "Padding", "Boolean"),
            ("fragment_enabled", "Fragment Enabled", "Boolean"),
            ("fragment_packets", "Fragment Packets", "Text"),
            ("fragment_length", "Fragment Length", "Text"),
            ("fragment_interval", "Fragment Interval", "Text"),
        ],
        SettingsSection::ProtocolCore => PROTOCOL_CORE_DEFS,
        SettingsSection::SpeedTest => &[
            ("ping_url", "Ping Test URL", "Url"),
            (
                "ip_provider",
                "IP Provider",
                leas_config::ip_provider::SELECT_CELL,
            ),
            ("tcp_timeout_secs", "TCP Timeout", "Duration"),
            ("real_ping_timeout_secs", "Real Ping Timeout", "Duration"),
            ("real_ping_retries", "Real Ping Retries", "Number"),
            ("real_ping_concurrency", "Real Ping Concurrency", "Number"),
            (
                "real_ping_test_all_protocols",
                "Real Ping Test All Protocols",
                "Boolean",
            ),
            (
                "task_queue_limit",
                "Task Queue Limit (0=no queue)",
                "Number",
            ),
            (
                "dns_failure_defer_secs",
                "DNS Failure Defer (secs)",
                "Number",
            ),
            ("error_ttl_hours", "Error TTL Hours (empty=never)", "Number"),
            ("geoip_url", "GeoIP URL", "Url"),
            ("geosite_url", "GeoSite URL", "Url"),
            ("geo_auto_update", "Geo Auto Update", "Boolean"),
            ("geo_update_interval", "Geo Update Interval Hours", "Number"),
        ],
        SettingsSection::Logging => &[
            ("log_ttl_secs", "Log Retention", "Duration"),
            ("log_to_file", "Log to File", "Boolean"),
            ("log_file_path", "Log File Path", "Text"),
        ],
        SettingsSection::Stats => &[("enabled", "Enabled", "Boolean")],
        SettingsSection::Subscriptions => &[
            ("name", "Name", "Text"),
            ("subscription_url", "Subscription URL", "Url"),
            ("user_agent", "User Agent", "Text"),
            ("update_interval", "Update Interval", "Duration"),
        ],
        SettingsSection::Updates | SettingsSection::Routing => &[],
        SettingsSection::RouteProbes => &[("probes", "Probes (comma-sep)", "Text")],
    }
}
const fn section_from_mode(mode: &SettingsMode) -> Option<SettingsSection> {
    match mode {
        SettingsMode::Split {
            right: SplitRightPane::Form { section, .. },
            ..
        } => Some(*section),
        SettingsMode::Split { .. } => None,
    }
}

/// Render form fields in horizontal layout (label left, value right).
/// Used by both the Split right pane and the old full-screen form path.
/// One row per field, as in the reference (spec D4/D5): `›` on the focused
/// row, the provenance marker, the label in its own column, then the value.
/// The caller provides the inner area (this draws no outer block).
/// Field rows a section shows: **all of them**. The `/` filter narrows the
/// sections list only (R1) — the Values pane never hides part of the section the
/// user is looking at, so `i/n` is a plain position within the section.
fn visible_field_rows(section: SettingsSection) -> Vec<usize> {
    (0..form_field_defs_for_section(section).len()).collect()
}

fn render_form_with_area(
    frame: &mut Frame,
    area: Rect,
    theme: &opaline::Theme,
    section: SettingsSection,
    fields: &[(String, String)],
    focus_index: usize,
    form_errors: &HashMap<String, String>,
    snapshot: Option<&Vec<(String, String)>>,
) {
    let field_defs = form_field_defs_for_section(section);
    let visible = visible_field_rows(section);
    let focused_row = visible.iter().position(|i| *i == focus_index);
    let height = area.height as usize;
    let start = focused_row
        .unwrap_or(0)
        .saturating_sub(height.saturating_sub(1))
        .min(visible.len().saturating_sub(height.max(1)));

    let label_w = area.width.saturating_sub(14).clamp(12, 24);
    for (y, (offset, index)) in
        (area.y..area.bottom()).zip(visible.iter().skip(start).take(height).enumerate())
    {
        let focused = Some(start + offset) == focused_row;
        let (key, label, field_type) = field_defs[*index];
        let current = fields.get(*index).map_or("", |(_, v)| v.as_str());
        let base = snapshot
            .and_then(|snap| snap.get(*index))
            .map(|(_, v)| v.as_str());
        let marker = provenance_marker(base, current);
        let marker_style = if marker == '*' {
            ThemeStyles::warning(theme)
        } else {
            ThemeStyles::hint(theme)
        };
        let label_style = if focused {
            ThemeStyles::table_row_selected(theme).add_modifier(Modifier::BOLD)
        } else {
            ThemeStyles::table_row_normal(theme)
        };
        let value_style = if focused {
            ThemeStyles::footer_value(theme)
        } else {
            ThemeStyles::hint(theme)
        };
        let mut spans = vec![
            Span::styled(if focused { "›" } else { " " }, label_style),
            Span::styled(format!("{marker} "), marker_style),
            // A label longer than the column still gets one separating space,
            // or the value collides with it at the narrow minimum
            // (`Sing-Box Path—` at 54 columns).
            Span::styled(
                if label.chars().count() >= label_w as usize {
                    format!("{label} ")
                } else {
                    format!("{label:<label_w$}", label_w = label_w as usize)
                },
                label_style,
            ),
        ];
        let mut value = value_display(field_type, current);
        if focused {
            value.push('█');
        }
        spans.push(Span::styled(value, value_style));
        if let Some(error) = form_errors.get(key) {
            spans.push(Span::styled(
                format!("  ⚠ {error}"),
                ThemeStyles::error(theme),
            ));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(area.x, y, area.width, 1),
        );
    }
}

async fn handle_form_key(state: &mut AppState, key: &KeyEvent) {
    // Borrow mode to extract data, then work through mutable state
    let AppMode::Settings { mode } = &state.mode else {
        return;
    };
    let Some(section) = section_from_mode(mode) else {
        return;
    };

    // Get field defs
    let field_defs = form_field_defs(mode);
    if field_defs.is_empty() {
        return;
    }
    let max_idx = field_defs.len().saturating_sub(1);
    // Extract current fields, focus_index, and form_errors from mutable state
    let AppMode::Settings {
        mode:
            SettingsMode::Split {
                right:
                    SplitRightPane::Form {
                        fields,
                        focus_index,
                        form_errors,
                        ..
                    },
                ..
            },
    } = &mut state.mode
    else {
        return;
    };

    // A selector advances on Space/Enter and wraps past its last option
    // (spec R2); `Ctrl+S` is the save key for every field type, since Enter no
    // longer reaches the save on a selector or a boolean. Enter still saves
    // everywhere else.
    let save_requested = if matches!(key.code, KeyCode::Char(' ') | KeyCode::Enter) {
        let field_type = field_defs.get(*focus_index).map_or("", |def| def.2);
        if select_options(field_type).is_some() {
            if let Some(options) = select_options(field_type)
                && let Some((_, value)) = fields.get_mut(*focus_index)
            {
                *value = cycle_select(value, &options, key.code == KeyCode::Enter);
            }
            return;
        }
        // A boolean is a two-value selector: `Space`/`Enter` toggle it, the
        // same gesture a select field uses to advance. `Enter` therefore must
        // NOT also reach the save here, or one press would both flip the value
        // and commit the form — the opposite of a toggle. `Ctrl+S` saves.
        if field_type == "Boolean" {
            if let Some((_, value)) = fields.get_mut(*focus_index) {
                *value = toggle_bool(value).to_string();
            }
            return;
        }
        // Enter still saves on every field type that is neither.
        key.code == KeyCode::Enter
    } else {
        key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL)
    };

    match key.code {
        KeyCode::Tab if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            *focus_index = if *focus_index >= max_idx {
                0
            } else {
                *focus_index + 1
            };
        }
        KeyCode::BackTab | KeyCode::Tab => {
            *focus_index = if *focus_index == 0 {
                max_idx
            } else {
                *focus_index - 1
            };
        }
        KeyCode::Up => {
            *focus_index = focus_index.saturating_sub(1);
        }
        KeyCode::Down => {
            if *focus_index < max_idx {
                *focus_index += 1;
            }
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if *focus_index >= fields.len() {
                return;
            }
            let def = field_defs[*focus_index];
            let (_, ref mut val) = fields[*focus_index];

            let field_type = def.2;
            if select_options(field_type).is_some() {
                // A selector has no free text: Space/Enter/←→/→ move it.
            } else if field_type == "Boolean" {
                // Any printable key toggles, reading the OLD value first: the
                // previous `clear()`-then-compare order could only ever write
                // `"true"`, so a `true` boolean was impossible to unset.
                *val = toggle_bool(val).to_string();
            } else if field_type == "Number" {
                if c.is_ascii_digit() || c == '-' {
                    val.push(c);
                }
            } else {
                val.push(c);
            }
        }
        // `←`/`→` step a selector or toggle a boolean in place; that dispatch
        // lives in the arm below, which already owned these keys.
        KeyCode::Backspace => {
            if *focus_index < fields.len() {
                let field_type = field_defs[*focus_index].2;
                let (_, ref mut val) = fields[*focus_index];
                // Backspace erases text. On a boolean it used to `pop()` the
                // literal, turning `true` into the invalid `tru`; a two-value
                // field has no tail to erase, so toggle it instead — the same
                // gesture as `Space`, and the inverse of what it did before.
                if field_type == "Boolean" {
                    *val = toggle_bool(val).to_string();
                } else if select_options(field_type).is_none() {
                    val.pop();
                }
            }
        }
        KeyCode::Enter | KeyCode::Char('s') if save_requested => {
            form_errors.clear();

            // Validate each field based on its declared type
            for (i, (_key, _label, field_type)) in field_defs.iter().enumerate() {
                let val = fields.get(i).map_or("", |(_, v)| v.as_str());
                if val.is_empty() {
                    continue;
                }
                match *field_type {
                    "Url" => {
                        if url::Url::parse(val).is_err() {
                            form_errors
                                .insert(field_defs[i].0.to_string(), "Invalid URL".to_string());
                        }
                    }
                    "Duration" if humantime::parse_duration(val).is_err() => {
                        form_errors.insert(
                            field_defs[i].0.to_string(),
                            "Invalid duration — use e.g. '5s', '1h30m'".to_string(),
                        );
                    }
                    field_type
                        if select_options(field_type)
                            .is_some_and(|options| !options.iter().any(|o| o == val)) =>
                    {
                        form_errors.insert(
                            field_defs[i].0.to_string(),
                            format!("`{val}` is not one of this field's options"),
                        );
                    }
                    _ => {}
                }
            }

            if form_errors.is_empty() {
                let saved_fields = fields.clone();
                if section == SettingsSection::RouteProbes {
                    crate::ops::settings::save_route_probes(state, &saved_fields).await;
                } else {
                    state.save_settings_form(section, &saved_fields);
                }
                // The status band reports the save, not just failures (spec A7).
                state.settings_notice = Some(format!("Saved {}", section_name(section)));
                // Focus goes back to Sections; the pane stays on the section that
                // was just saved, rebuilt so it shows the stored values (R1).
                let pane = state.build_right_pane(section).await;
                if let AppMode::Settings {
                    mode: SettingsMode::Split { right, focus },
                } = &mut state.mode
                {
                    *right = pane;
                    *focus = SplitFocus::Tree;
                }
            }
            // If errors, stay on form with errors displayed
        }
        // Guard both lengths: the Char handler already does
        // `if *focus_index >= fields.len() { return; }`; without the fields
        // check here, a form whose stored fields are shorter than its defs
        // (e.g. Protocol Core with no saved overrides) panics on
        // `fields[*focus_index]`.
        KeyCode::Left | KeyCode::Right
            if *focus_index < field_defs.len() && *focus_index < fields.len() =>
        {
            let field_type = field_defs[*focus_index].2;
            let (_, ref mut val) = fields[*focus_index];
            if let Some(options) = select_options(field_type) {
                *val = cycle_select(val, &options, key.code == KeyCode::Right);
            } else if field_type == "Boolean" {
                // A boolean has exactly two values, so stepping either
                // direction is the same toggle.
                *val = toggle_bool(val).to_string();
            }
        }
        KeyCode::Esc => {
            // Dirty form (spec P3): leaving without saving asks first.
            if form_is_dirty(state) {
                state.confirmation = Some(crate::ConfirmAction::DiscardSettings);
                return;
            }
            state.settings_form_snapshot = None;
            if let AppMode::Settings {
                mode: SettingsMode::Split { focus, .. },
            } = &mut state.mode
            {
                *focus = SplitFocus::Tree;
            }
        }
        _ => {}
    }
}
fn handle_update_form_key(state: &mut AppState, key: &KeyEvent) {
    match key.code {
        KeyCode::Char('c' | 'C') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            state.spawn_update_check();
            // Refresh the form with current status
            let status_xray = state
                .update_status
                .get(&CoreType::Xray)
                .cloned()
                .unwrap_or_default();
            let status_singbox = state
                .update_status
                .get(&CoreType::SingBox)
                .cloned()
                .unwrap_or_default();
            if let AppMode::Settings {
                mode: SettingsMode::Split { right, .. },
            } = &mut state.mode
            {
                *right = SplitRightPane::UpdateForm {
                    status_xray,
                    status_singbox,
                };
            }
        }
        KeyCode::Char('d' | 'D') => {
            // Download updates for all cores that have them available
            let any_updates = state.update_status.values().any(|s| s.update_available);
            if !any_updates {
                return;
            }
            // Check each core and trigger download if available
            let xray_avail = state
                .update_status
                .get(&CoreType::Xray)
                .is_some_and(|s| s.update_available);
            let singbox_avail = state
                .update_status
                .get(&CoreType::SingBox)
                .is_some_and(|s| s.update_available);

            if xray_avail {
                state.spawn_update_download(CoreType::Xray);
            }
            if singbox_avail {
                state.spawn_update_download(CoreType::SingBox);
            }
            // Refresh the form with current status
            let status_xray = state
                .update_status
                .get(&CoreType::Xray)
                .cloned()
                .unwrap_or_default();
            let status_singbox = state
                .update_status
                .get(&CoreType::SingBox)
                .cloned()
                .unwrap_or_default();
            if let AppMode::Settings {
                mode: SettingsMode::Split { right, .. },
            } = &mut state.mode
            {
                *right = SplitRightPane::UpdateForm {
                    status_xray,
                    status_singbox,
                };
            }
        }
        KeyCode::Esc => {
            if let AppMode::Settings {
                mode: SettingsMode::Split { focus, .. },
            } = &mut state.mode
            {
                *focus = SplitFocus::Tree;
            }
        }
        _ => {}
    }
}

// ── Routing list ────────────────────────────────────────────────────────

/// Persist a full sort-order pass: each rule's `sort_order` is the index in
/// `ids`. One transaction for the whole pass — the typed model has no bulk
/// reorder, and per-rule autocommit meant one commit per keystroke-visible
/// move (a partial pass could also leave two rules sharing a sort order).
/// Best-effort: failures log via tracing and roll the pass back.
async fn reorder_routing_rules(state: &AppState, ids: &[(String, i32)]) {
    let mut conn = match state.db.connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(target: "tui::ui::settings", "Failed to open DB for reorder: {e}");
            return;
        }
    };
    let mut tx = match conn.transaction().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(target: "tui::ui::settings", "Failed to open reorder transaction: {e}");
            return;
        }
    };
    for (id, order) in ids {
        if let Err(e) = leas_db::models::RoutingRule::filter_by_id(id.clone())
            .update()
            .sort_order(Some(*order))
            .exec(&mut tx)
            .await
        {
            // Dropping the transaction rolls the pass back.
            tracing::warn!(target: "tui::ui::settings", "Failed to reorder rule {id}: {e}");
            return;
        }
    }
    if let Err(e) = tx.commit().await {
        tracing::warn!(target: "tui::ui::settings", "Failed to commit reorder: {e}");
    }
}

/// Delete one routing rule by id through the pooled connection.
async fn delete_routing_rule(state: &AppState, id: &str) {
    let mut conn = match state.db.connection().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(target: "tui::ui::settings", "Failed to open DB for delete: {e}");
            return;
        }
    };
    if let Err(e) = leas_db::models::RoutingRule::filter_by_id(id.to_string())
        .delete()
        .exec(&mut conn)
        .await
    {
        tracing::warn!(target: "tui::ui::settings", "Failed to delete routing rule: {e}");
    }
}

async fn handle_routing_list_key(state: &mut AppState, key: &KeyEvent) {
    let selected = match &state.mode {
        AppMode::Settings {
            mode:
                SettingsMode::Split {
                    right: SplitRightPane::RoutingList { selected },
                    ..
                },
        } => *selected,
        _ => return,
    };

    let rules = &state.routing_rules;
    let max = rules.len().saturating_sub(1);

    match key.code {
        KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if selected > 0 && selected <= rules.len() {
                let mut ids: Vec<(String, i32)> = rules
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        (
                            r.id.clone(),
                            if i == selected {
                                i as i32 - 1
                            } else if i == selected - 1 {
                                i as i32 + 1
                            } else {
                                i as i32
                            },
                        )
                    })
                    .collect();
                for (idx, (_, order)) in ids.iter_mut().enumerate() {
                    *order = idx as i32;
                }
                reorder_routing_rules(state, &ids).await;
                if let AppMode::Settings {
                    mode:
                        SettingsMode::Split {
                            right: SplitRightPane::RoutingList { ref mut selected },
                            ..
                        },
                } = state.mode
                {
                    *selected = selected.saturating_sub(1);
                }
                state.reload_routing_rules().await;
            }
        }
        KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if selected < max {
                let mut ids: Vec<(String, i32)> = rules
                    .iter()
                    .enumerate()
                    .map(|(i, r)| {
                        (
                            r.id.clone(),
                            if i == selected {
                                i as i32 + 1
                            } else if i == selected + 1 {
                                i as i32 - 1
                            } else {
                                i as i32
                            },
                        )
                    })
                    .collect();
                for (idx, (_, order)) in ids.iter_mut().enumerate() {
                    *order = idx as i32;
                }
                reorder_routing_rules(state, &ids).await;
                if let AppMode::Settings {
                    mode:
                        SettingsMode::Split {
                            right: SplitRightPane::RoutingList { ref mut selected },
                            ..
                        },
                } = state.mode
                {
                    *selected += 1;
                }
                state.reload_routing_rules().await;
            }
        }
        KeyCode::Up => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right: SplitRightPane::RoutingList { ref mut selected },
                        ..
                    },
            } = state.mode
            {
                *selected = selected.saturating_sub(1);
            }
        }
        KeyCode::Down => {
            if selected < max
                && let AppMode::Settings {
                    mode:
                        SettingsMode::Split {
                            right: SplitRightPane::RoutingList { ref mut selected },
                            ..
                        },
                } = state.mode
            {
                *selected += 1;
            }
        }
        KeyCode::Char('a' | 'A') => {
            let fields = routing_rule_fields(None);
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        ref mut right,
                        ref mut focus,
                        ..
                    },
            } = state.mode
            {
                *right = SplitRightPane::RoutingForm {
                    rule_id: None,
                    fields,
                    focus_index: 0,
                    form_errors: HashMap::new(),
                };
                *focus = SplitFocus::Right;
            }
        }
        KeyCode::Char('e' | 'E') => {
            if !rules.is_empty() && selected < rules.len() {
                let fields = routing_rule_fields(Some(&rules[selected]));
                if let AppMode::Settings {
                    mode:
                        SettingsMode::Split {
                            ref mut right,
                            ref mut focus,
                            ..
                        },
                } = state.mode
                {
                    *right = SplitRightPane::RoutingForm {
                        rule_id: Some(rules[selected].id.clone()),
                        fields,
                        focus_index: 0,
                        form_errors: HashMap::new(),
                    };
                    *focus = SplitFocus::Right;
                }
            }
        }
        KeyCode::Char('d' | 'D') => {
            let (rule_id, list_len) = if !rules.is_empty() && selected < rules.len() {
                (Some(rules[selected].id.clone()), rules.len())
            } else {
                (None, 0)
            };
            if let Some(id) = rule_id {
                delete_routing_rule(state, &id).await;
                state.log_trace("info", "tui::ui::settings", "Routing rule deleted");
                let new_max = list_len.saturating_sub(2);
                if let AppMode::Settings {
                    mode:
                        SettingsMode::Split {
                            right: SplitRightPane::RoutingList { ref mut selected },
                            ..
                        },
                } = state.mode
                    && *selected > new_max
                    && new_max > 0
                {
                    *selected = new_max;
                }
                state.reload_routing_rules().await;
            }
        }
        KeyCode::Esc => {
            if let AppMode::Settings {
                mode: SettingsMode::Split { ref mut focus, .. },
            } = state.mode
            {
                *focus = SplitFocus::Tree;
            }
        }
        _ => {}
    }
}

// ── Routing form ────────────────────────────────────────────────────────

fn routing_rule_fields(rule: Option<&leas_db::models::RoutingRule>) -> Vec<(String, String)> {
    let keys = [
        "type",
        "domain_matcher",
        "domains",
        "ips",
        "inbound_tags",
        "ports",
        "source_ports",
        "network",
        "protocols",
        "domain_strategy",
        "outbound_tag",
        "balancer_tag",
        "rule_set_file",
        "rule_set_url",
    ];
    keys.iter()
        .map(|k| {
            let val = rule.map_or_else(String::new, |r| match *k {
                "type" => r.r#type.to_string(),
                "domain_matcher" => r.domain_matcher.as_deref().unwrap_or("").to_string(),
                // Vec fields render comma-joined in the form; split back on save.
                "domains" => r.domains.join(","),
                "ips" => r.ips.join(","),
                "inbound_tags" => r.inbound_tags.join(","),
                "ports" => r
                    .ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                "source_ports" => r
                    .source_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                "network" => r.network.as_deref().unwrap_or("").to_string(),
                "protocols" => r.protocols.join(","),
                "domain_strategy" => r.domain_strategy.as_deref().unwrap_or("").to_string(),
                "outbound_tag" => r.outbound_tag.as_deref().unwrap_or("").to_string(),
                "balancer_tag" => r.balancer_tag.as_deref().unwrap_or("").to_string(),
                "rule_set_file" => r.rule_set_file.as_deref().unwrap_or("").to_string(),
                "rule_set_url" => r.rule_set_url.as_deref().unwrap_or("").to_string(),
                _ => String::new(),
            });
            (k.to_string(), val)
        })
        .collect()
}

const ROUTING_FIELD_DEFS: &[(&str, &str, &str)] = &[
    ("type", "Type", "Number"),
    ("domain_matcher", "Domain Matcher", "Text"),
    ("domains", "Domains (comma-sep)", "Text"),
    ("ips", "IPs (comma-sep)", "Text"),
    ("inbound_tags", "Inbound Tags (comma-sep)", "Text"),
    ("ports", "Ports (comma-sep)", "Text"),
    ("source_ports", "Source Ports (comma-sep)", "Text"),
    ("network", "Network", "Text"),
    ("protocols", "Protocols (comma-sep)", "Text"),
    ("domain_strategy", "Domain Strategy", "Text"),
    ("outbound_tag", "Outbound Tag", "Text"),
    ("balancer_tag", "Balancer Tag", "Text"),
    ("rule_set_file", "Rule Set (File)", "Text"),
    ("rule_set_url", "Rule Set (URL)", "Text"),
];

async fn handle_routing_form_key(state: &mut AppState, key: &KeyEvent) {
    let (rule_id, fields, focus_index) = match &mut state.mode {
        AppMode::Settings {
            mode:
                SettingsMode::Split {
                    right:
                        SplitRightPane::RoutingForm {
                            rule_id,
                            fields,
                            focus_index,
                            ..
                        },
                    ..
                },
        } => (rule_id.clone(), fields, focus_index),
        _ => return,
    };

    let max_idx = ROUTING_FIELD_DEFS.len().saturating_sub(1);

    match key.code {
        KeyCode::Tab if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            *focus_index = if *focus_index >= max_idx {
                0
            } else {
                *focus_index + 1
            };
        }
        KeyCode::BackTab | KeyCode::Tab => {
            *focus_index = if *focus_index == 0 {
                max_idx
            } else {
                *focus_index - 1
            };
        }
        KeyCode::Up => {
            *focus_index = focus_index.saturating_sub(1);
        }
        KeyCode::Down => {
            if *focus_index < max_idx {
                *focus_index += 1;
            }
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if *focus_index >= fields.len() {
                return;
            }
            let def = ROUTING_FIELD_DEFS[*focus_index];
            let (_, ref mut val) = fields[*focus_index];
            let field_type = def.2;

            if field_type == "Boolean" {
                // Same owner-level fix as the settings form: read the old value
                // before overwriting, or a `true` boolean can never be unset.
                *val = toggle_bool(val).to_string();
            } else if field_type == "Number" {
                if c.is_ascii_digit() || c == '-' {
                    val.push(c);
                }
            } else {
                val.push(c);
            }
        }
        KeyCode::Backspace => {
            if *focus_index < fields.len() {
                let field_type = ROUTING_FIELD_DEFS[*focus_index].2;
                let (_, ref mut val) = fields[*focus_index];
                if field_type == "Boolean" {
                    *val = toggle_bool(val).to_string();
                } else {
                    val.pop();
                }
            }
        }
        KeyCode::Enter => {
            let saved_fields = fields.clone();
            state
                .save_routing_rule(rule_id.clone(), &saved_fields)
                .await;
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        ref mut right,
                        ref mut focus,
                        ..
                    },
            } = state.mode
            {
                *right = SplitRightPane::RoutingList { selected: 0 };
                *focus = SplitFocus::Tree;
            }
        }
        KeyCode::Esc => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        ref mut right,
                        ref mut focus,
                        ..
                    },
            } = state.mode
            {
                *right = SplitRightPane::RoutingList { selected: 0 };
                *focus = SplitFocus::Tree;
            }
        }
        _ => {}
    }
}

// ── Render: Update Form ─────────────────────────────────────────────────

fn render_update_form_inner(
    frame: &mut Frame,
    area: Rect,
    theme: &opaline::Theme,
    status_xray: &BackendUpdateStatus,
    status_singbox: &BackendUpdateStatus,
) {
    let label_style = Style::default()
        .fg(theme.color("text.primary").into())
        .add_modifier(Modifier::BOLD);
    let header_style = Style::default()
        .fg(theme.color("accent.primary").into())
        .add_modifier(Modifier::BOLD);
    let avail_style = Style::default()
        .fg(theme.color("success").into())
        .add_modifier(Modifier::BOLD);
    let error_style = Style::default().fg(theme.color("error").into());
    let hint_style = Style::default().fg(theme.color("text.muted").into());

    let mut lines: Vec<Line> = Vec::new();

    // ── Xray-core ──
    lines.push(Line::from(Span::styled("  Xray-core", header_style)));
    if let Some(ver) = &status_xray.current_version {
        lines.push(Line::from(format!("    Current: {ver}")));
    } else {
        lines.push(Line::from(Span::styled(
            "    Current: not installed",
            label_style,
        )));
    }
    if let Some(ver) = &status_xray.latest_version {
        lines.push(Line::from(format!("    Latest:  {ver}")));
    } else if status_xray.error.is_some() {
        lines.push(Line::from(Span::styled(
            "    Latest:  (check failed)",
            error_style,
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "    Latest:  (checking...)",
            hint_style,
        )));
    }
    if status_xray.update_available {
        lines.push(Line::from(Span::styled(
            "    [Update available!]",
            avail_style,
        )));
    }
    if let Some((downloaded, total)) = status_xray.download_progress {
        lines.push(progress_bar_line(downloaded, total, &hint_style));
    } else if status_xray.downloading {
        lines.push(Line::from(Span::styled("    Downloading...", hint_style)));
    }
    if let Some(err) = &status_xray.error {
        lines.push(Line::from(Span::styled(
            format!("    Error: {err}"),
            error_style,
        )));
    }

    // ── Sing-box ──
    lines.push(Line::from(Span::styled("  Sing-box", header_style)));
    if let Some(ver) = &status_singbox.current_version {
        lines.push(Line::from(format!("    Current: {ver}")));
    } else {
        lines.push(Line::from(Span::styled(
            "    Current: not installed",
            label_style,
        )));
    }
    if let Some(ver) = &status_singbox.latest_version {
        lines.push(Line::from(format!("    Latest:  {ver}")));
    } else if status_singbox.error.is_some() {
        lines.push(Line::from(Span::styled(
            "    Latest:  (check failed)",
            error_style,
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "    Latest:  (checking...)",
            hint_style,
        )));
    }
    if status_singbox.update_available {
        lines.push(Line::from(Span::styled(
            "    [Update available!]",
            avail_style,
        )));
    }
    if let Some((downloaded, total)) = status_singbox.download_progress {
        lines.push(progress_bar_line(downloaded, total, &hint_style));
    } else if status_singbox.downloading {
        lines.push(Line::from(Span::styled("    Downloading...", hint_style)));
    }
    if let Some(err) = &status_singbox.error {
        lines.push(Line::from(Span::styled(
            format!("    Error: {err}"),
            error_style,
        )));
    }

    // Action hints
    lines.push(Line::from(""));
    let any_updates = status_xray.update_available || status_singbox.update_available;
    let help = if any_updates {
        " [C] Check for Updates  [D] Download & Install  [Esc] Back "
    } else {
        " [C] Check for Updates  [Esc] Back "
    };
    lines.push(Line::from(Span::styled(help, hint_style)));

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, area);
}

// ── Render: Routing List ────────────────────────────────────────────────

struct RoutingRuleItem {
    index: usize,
    rule_type: String,
    targets: String,
    outbound: String,
}

impl ListItem for RoutingRuleItem {
    fn height(&self) -> u16 {
        1
    }

    fn render(&self, area: Rect, buf: &mut Buffer, ctx: &ListItemContext) {
        let is_selected = ctx.selected;
        let nums = format!(" {:>2} ", self.index);
        let type_str = format!(" {} ", self.rule_type);
        let target_str = format!(" {:<30} ", self.targets);
        let out_str = format!(" {} ", self.outbound);
        let line = format!("{nums}{type_str}{target_str}{out_str}");
        let style = if is_selected {
            Style::default()
                .fg(ctx.palette.primary)
                .bg(ctx.palette.surface)
                .add_modifier(Modifier::REVERSED)
        } else {
            Style::default().fg(ctx.palette.foreground)
        };
        buf.set_string(area.x + 1, area.y, &line, style);
    }
}

fn render_routing_list_inner(
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    theme: &opaline::Theme,
    selected: usize,
) {
    let rules = &state.routing_rules;
    let list_area = area;

    // Build list items
    let items: Vec<RoutingRuleItem> = rules
        .iter()
        .enumerate()
        .map(|(i, rule)| {
            let domains = rule.domains.join(",");
            let ips = rule.ips.join(",");
            let targets = if !domains.is_empty() && !ips.is_empty() {
                format!("{domains}, {ips}")
            } else if !domains.is_empty() {
                domains
            } else {
                ips
            };
            RoutingRuleItem {
                index: i + 1,
                rule_type: rule.r#type.to_string(),
                targets,
                outbound: rule.outbound_tag.as_deref().unwrap_or("-").to_string(),
            }
        })
        .collect();

    // Render list widget
    let list = List::new(&items)
        .palette(crate::ui::theme::widget_palette(theme))
        // The widget's default `│` gutter drew a second bar right after the
        // pane's own border (`││  Default`); the selected row is marked by
        // `sel_mark` inside the item instead.
        .selection_indicator(" ")
        .show_paginator(false);
    let mut list_state = ListState::new(items.len());
    list_state.select(selected, items.len());
    frame.render_stateful_widget(list, list_area, &mut list_state);

    // No hint line of its own: the modal's bottom border already carries this
    // pane's keys (`status_bar::settings_hints`), and printing them twice also
    // overflowed the pane — the routing footer overwrote its right border.
}

// ── Render: Routing Form ────────────────────────────────────────────────

fn render_routing_form_inner(
    frame: &mut Frame,
    area: Rect,
    theme: &opaline::Theme,
    fields: &[(String, String)],
    focus_index: usize,
    form_errors: &HashMap<String, String>,
) {
    // Render each field as an Input widget with y-coordinate tracking
    let mut y = area.y;
    let max_y = area.bottom();

    for (i, (key, label, _field_type)) in ROUTING_FIELD_DEFS.iter().enumerate() {
        if y >= max_y {
            break;
        }

        let is_focused = i == focus_index;
        let val = fields.get(i).map_or("", |(_, v)| v.as_str());

        // Compute display value
        let display_val = if val.is_empty() {
            "(empty)".into()
        } else {
            val.to_string()
        };

        let input = Input::new(label).palette(&crate::ui::theme::widget_palette(theme));
        let mut input_state = InputState::new();
        input_state.set_value(display_val);
        input_state.set_focused(is_focused);

        // Show validation error if present
        if let Some(error) = form_errors.get(*key) {
            input_state.set_validation(Some((ValidationKind::Error, error.clone())));
        }

        let has_error = u16::from(input_state.validation().is_some());
        let field_height = 2 + has_error;
        let field_area = Rect::new(area.x, y, area.width, field_height.min(max_y - y));
        frame.render_stateful_widget(&input, field_area, &mut input_state);
        y += field_height;
    }

    // Help text at the bottom
    if y < max_y {
        let help = " [Tab] Next  [Shift+Tab] Prev  [Enter] Save  [Esc] Cancel ";
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(help, ThemeStyles::hint(theme)))),
            Rect::new(area.x, y, area.width, 1),
        );
    }
}
// ── Group List (Subscriptions) ───────────────────────────────────────────

struct GroupListItem {
    name: String,
    url: String,
    status: String,
    selected: bool,
}

impl ListItem for GroupListItem {
    fn height(&self) -> u16 {
        1
    }

    fn render(&self, area: Rect, buf: &mut Buffer, ctx: &ListItemContext) {
        let is_focused = ctx.selected;
        let sel_mark = if self.selected { " \u{2713} " } else { "   " };
        // Columns sized from the pane, not from a wide-terminal guess: a fixed
        // 20/40/10 split elided the status (`nev…`) in a normal popup while
        // overrunning the pane in a narrow one.
        let status_w = 10usize;
        let name_w = ((area.width as usize) * 2 / 10).clamp(8, 20);
        let url_w = (area.width as usize)
            .saturating_sub(3 + name_w + status_w)
            .max(8);
        let name_str = format!(" {:<name_w$}", self.name, name_w = name_w);
        let url_str = format!(" {:<url_w$}", self.url, url_w = url_w);
        let status_str = format!(" {:<status_w$}", self.status, status_w = status_w);
        let line = format!("{sel_mark}{name_str}{url_str}{status_str}");
        // The columns are padded for a wide pane; without a clamp the tail runs
        // past the pane and paints over its right border.
        let line = if unicode_width::UnicodeWidthStr::width(line.as_str()) > usize::from(area.width)
        {
            let keep = (area.width as usize).saturating_sub(1);
            let mut trimmed = line;
            while unicode_width::UnicodeWidthStr::width(trimmed.as_str()) > keep {
                trimmed.pop();
            }
            format!("{trimmed}…")
        } else {
            line
        };
        let style = if is_focused {
            Style::default()
                .fg(ctx.palette.primary)
                .bg(ctx.palette.surface)
                .add_modifier(Modifier::REVERSED)
        } else {
            Style::default().fg(ctx.palette.foreground)
        };
        buf.set_string(area.x + 1, area.y, &line, style);
    }
}

fn render_group_list_inner(
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    theme: &opaline::Theme,
    selected: usize,
    selected_mask: &[bool],
) {
    let groups = &state.groups;
    let list_area = area;

    // Build list items
    let items: Vec<GroupListItem> = groups
        .iter()
        .enumerate()
        .map(|(i, g)| {
            use leas_db::models::GroupStatus;
            let status = match g.status {
                Some(GroupStatus::Ok) => "ok",
                Some(GroupStatus::Error) => "error",
                Some(GroupStatus::Never) | None => "never",
            };
            let url = g.url.as_deref().unwrap_or("");
            // Truncate long URLs for display
            let url_display = if url.len() > 38 {
                format!("{}…", &url[..37])
            } else {
                url.to_string()
            };
            GroupListItem {
                name: g.name.clone().unwrap_or_else(|| "Unnamed".to_string()),
                url: url_display,
                // On an error, show WHY. The bare word "error" is what left the
                // 2026-10-01 truncated import undiagnosable — the reason was in
                // the activity log, which the user has to know to look in.
                // `specs/2026-10-02-import-budget-design.md` §5.
                status: match (&g.status, g.error_message.as_deref()) {
                    (Some(GroupStatus::Error), Some(reason)) if !reason.is_empty() => {
                        let reason = reason.trim();
                        let tail: String = reason.chars().take(60).collect();
                        format!("error: {tail}")
                    }
                    _ => status.to_string(),
                },
                selected: selected_mask.get(i).copied().unwrap_or(false),
            }
        })
        .collect();

    // Render list widget
    let list = List::new(&items)
        .palette(crate::ui::theme::widget_palette(theme))
        // The widget's default `│` gutter drew a second bar right after the
        // pane's own border (`││  Default`); the selected row is marked by
        // `sel_mark` inside the item instead.
        .selection_indicator(" ")
        .show_paginator(false);
    let mut list_state = ListState::new(items.len());
    list_state.select(selected, items.len());
    frame.render_stateful_widget(list, list_area, &mut list_state);

    // Footer with action hints
    // Keys live in the modal's bottom border (see the routing list).
}

async fn handle_group_list_key(state: &mut AppState, key: &KeyEvent) {
    // Extract current selection state (read-only, copies usize)
    let (selected, max) = match &state.mode {
        AppMode::Settings {
            mode:
                SettingsMode::Split {
                    right: SplitRightPane::GroupList { selected, .. },
                    ..
                },
        } => (*selected, state.groups.len().saturating_sub(1)),
        _ => return,
    };

    match key.code {
        KeyCode::Up => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right:
                            SplitRightPane::GroupList {
                                ref mut selected, ..
                            },
                        ..
                    },
            } = state.mode
            {
                *selected = selected.saturating_sub(1);
            }
        }
        KeyCode::Down => {
            if selected < max
                && let AppMode::Settings {
                    mode:
                        SettingsMode::Split {
                            right:
                                SplitRightPane::GroupList {
                                    ref mut selected, ..
                                },
                            ..
                        },
                } = state.mode
            {
                *selected += 1;
            }
        }
        KeyCode::Char(' ') => {
            // Toggle selection for the current row
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right:
                            SplitRightPane::GroupList {
                                ref mut selected,
                                ref mut selected_mask,
                                ..
                            },
                        ..
                    },
            } = state.mode
                && *selected < selected_mask.len()
            {
                selected_mask[*selected] = !selected_mask[*selected];
            }
        }
        KeyCode::Char('a' | 'A') => {
            crate::ops::subscriptions::start_add_group(state);
        }
        KeyCode::Char('e' | 'E') => {
            if !state.groups.is_empty() && selected < state.groups.len() {
                let group_id = state.groups[selected].id.clone();
                crate::ops::subscriptions::start_edit_group(state, &group_id);
            }
        }
        KeyCode::Char('d' | 'D') => {
            // Read selection state without borrow conflict
            let ids_from_mask: Vec<String> = match &state.mode {
                AppMode::Settings {
                    mode:
                        SettingsMode::Split {
                            right:
                                SplitRightPane::GroupList {
                                    selected,
                                    selected_mask,
                                },
                            ..
                        },
                } => {
                    let ids: Vec<String> = selected_mask
                        .iter()
                        .enumerate()
                        .filter(|&(_, m)| *m)
                        .filter_map(|(i, _)| state.groups.get(i).map(|g| g.id.clone()))
                        .collect();
                    let sel = *selected;
                    if ids.is_empty() {
                        // Fall back to current selection
                        state
                            .groups
                            .get(sel)
                            .map(|g| vec![g.id.clone()])
                            .unwrap_or_default()
                    } else {
                        ids
                    }
                }
                _ => return,
            };
            for group_id in ids_from_mask {
                crate::ops::subscriptions::delete_group(state, &group_id).await;
            }
            // Clamp selected after deletion
            let new_max = state.groups.len().saturating_sub(1);
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right:
                            SplitRightPane::GroupList {
                                ref mut selected, ..
                            },
                        ..
                    },
            } = state.mode
            {
                if *selected > new_max && new_max > 0 {
                    *selected = new_max;
                } else if new_max == 0 {
                    *selected = 0;
                }
            }
        }
        KeyCode::Char('u' | 'U') => {
            crate::ops::subscriptions::update_all_subscriptions(state);
        }
        KeyCode::Esc => {
            if let AppMode::Settings {
                mode: SettingsMode::Split { ref mut focus, .. },
            } = state.mode
            {
                *focus = SplitFocus::Tree;
            }
        }
        _ => {}
    }
}

async fn handle_group_form_key(state: &mut AppState, key: &KeyEvent) {
    let (group_id, _focus_index, max_index) = match &state.mode {
        AppMode::Settings {
            mode:
                SettingsMode::Split {
                    right:
                        SplitRightPane::GroupForm {
                            group_id,
                            focus_index,
                            fields,
                            ..
                        },
                    ..
                },
        } => (
            group_id.clone(),
            *focus_index,
            fields.len().saturating_sub(1),
        ),
        _ => return,
    };

    match key.code {
        KeyCode::Tab => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right:
                            SplitRightPane::GroupForm {
                                ref mut focus_index,
                                ..
                            },
                        ..
                    },
            } = state.mode
                && *focus_index < max_index
            {
                *focus_index += 1;
            }
        }
        KeyCode::BackTab => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right:
                            SplitRightPane::GroupForm {
                                ref mut focus_index,
                                ..
                            },
                        ..
                    },
            } = state.mode
                && *focus_index > 0
            {
                *focus_index -= 1;
            }
        }
        KeyCode::Enter => {
            // Save the form
            if group_id.is_some() {
                crate::ops::subscriptions::confirm_edit_group(state).await;
            } else {
                crate::ops::subscriptions::confirm_add_group(state).await;
            }
        }
        KeyCode::Esc => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        ref mut right,
                        ref mut focus,
                        ..
                    },
            } = state.mode
            {
                *right = SplitRightPane::GroupList {
                    selected: 0,
                    selected_mask: vec![false; state.groups.len()],
                };
                *focus = SplitFocus::Right;
            }
        }
        KeyCode::Up => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right:
                            SplitRightPane::GroupForm {
                                ref mut focus_index,
                                ..
                            },
                        ..
                    },
            } = state.mode
                && *focus_index > 0
            {
                *focus_index -= 1;
            }
        }
        KeyCode::Down => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right:
                            SplitRightPane::GroupForm {
                                ref mut focus_index,
                                ..
                            },
                        ..
                    },
            } = state.mode
                && *focus_index < max_index
            {
                *focus_index += 1;
            }
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right:
                            SplitRightPane::GroupForm {
                                ref mut fields,
                                ref mut focus_index,
                                ..
                            },
                        ..
                    },
            } = state.mode
            {
                if *focus_index >= fields.len() {
                    return;
                }
                let (_, ref mut val) = fields[*focus_index];
                val.push(c);
            }
        }
        KeyCode::Backspace => {
            if let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        right:
                            SplitRightPane::GroupForm {
                                ref mut fields,
                                ref mut focus_index,
                                ..
                            },
                        ..
                    },
            } = state.mode
                && *focus_index < fields.len()
            {
                let (_, ref mut val) = fields[*focus_index];
                val.pop();
            }
        }
        // Right/Left are deliberately inert here (the form's own key path owns
        // caret movement), so they fall through with everything else.
        _ => {}
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Format byte count to a human-readable string (KB/MB).
fn format_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    if n >= MB {
        format!("{:.1}MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.1}KB", n as f64 / KB as f64)
    } else {
        format!("{n}B")
    }
}

/// Build a text-based progress bar line for download progress.
fn progress_bar_line(downloaded: u64, total: u64, style: &Style) -> Line<'static> {
    let bar = bar_cells(downloaded, total, 20);
    let sizes = format!(
        " ({}/{})",
        format_bytes(downloaded),
        if total > 0 {
            format_bytes(total)
        } else {
            "?".to_string()
        }
    );
    Line::from(Span::styled(format!("    {bar}{sizes}"), *style))
}

#[cfg(test)]
mod section_list_tests {
    use super::{
        SectionRow, counter_label, field_accepts, leaf_matches, provenance_marker, section_rows,
        value_display, visible_field_rows, visible_leaves,
    };
    use crate::types::{SectionList, SettingsSection};
    use rstest::rstest;

    #[rstest]
    #[case::empty_pane(0, 0, "0/0")]
    #[case::first_row(0, 20, "1/20")]
    #[case::last_row(19, 20, "20/20")]
    #[case::out_of_range_clamps(25, 20, "20/20")]
    fn counter_labels_are_one_based_and_clamped(
        #[case] row: usize,
        #[case] total: usize,
        #[case] expected: &str,
    ) {
        assert_eq!(counter_label(row, total), expected);
    }

    #[rstest]
    #[case::bool_true("Boolean", "true", "✓")]
    #[case::bool_false("Boolean", "false", "✗")]
    #[case::empty_text("Text", "", "—")]
    #[case::select_keeps_angle_brackets("Select:debug,info", "info", "< info >")]
    #[case::text_verbatim("Number", "443", "443")]
    fn values_render_per_field_type(
        #[case] field_type: &str,
        #[case] value: &str,
        #[case] expected: &str,
    ) {
        assert_eq!(value_display(field_type, value), expected);
    }

    #[rstest]
    #[case::no_snapshot(None, "x", '·')]
    #[case::unchanged(Some("x"), "x", '·')]
    #[case::changed(Some("x"), "xy", '*')]
    fn provenance_marks_only_unsaved_edits(
        #[case] snapshot: Option<&str>,
        #[case] current: &str,
        #[case] expected: char,
    ) {
        assert_eq!(provenance_marker(snapshot, current), expected);
    }

    #[test]
    fn filter_matches_leaf_or_its_group_name() {
        // Leaf 8 is DNS; leaf 0 is Core Settings (group "Core").
        assert!(leaf_matches(8, "dns"));
        assert!(leaf_matches(0, "core"));
        assert!(leaf_matches(7, "probe"));
        assert!(!leaf_matches(8, "zszs"));
        // An empty query keeps every leaf.
        assert!(leaf_matches(0, ""));
    }

    #[test]
    fn collapsed_group_hides_its_leaves_but_a_filter_reveals_them() {
        // 15 leaves, all visible with no filter.
        let list = SectionList::default();
        assert_eq!(visible_leaves("", &list).len(), 15);
        let mut collapsed = SectionList::default();
        collapsed.toggle_expanded(0);
        assert_eq!(visible_leaves("", &collapsed).len(), 13);
        // A filter always shows what it matched, collapse or not.
        assert_eq!(visible_leaves("core settings", &collapsed).len(), 1);
    }

    #[test]
    fn collapsed_group_holds_the_highlight() {
        let mut list = SectionList::default();
        list.toggle_expanded(0);
        let (rows, selected) = section_rows("", &list);
        assert!(matches!(
            rows[selected.expect("the collapsed group carries the highlight")],
            SectionRow::Group {
                collapsed: true,
                ..
            }
        ));
    }

    #[test]
    fn the_values_pane_never_hides_part_of_the_selected_section() {
        // The `/` filter narrows sections only (R1): Core's five fields are all
        // listed whatever the query is.
        assert_eq!(visible_field_rows(SettingsSection::Core).len(), 5);
        assert_eq!(visible_field_rows(SettingsSection::Dns).len(), 7);
    }

    #[rstest]
    #[case::static_list_has_two_options("Select:en,zh", Some(vec!["en", "zh"]))]
    #[case::selector_is_none_for_text("Text", None)]
    fn static_option_lists_come_from_the_field_type(
        #[case] field_type: &str,
        #[case] expected: Option<Vec<&'static str>>,
    ) {
        assert_eq!(
            super::select_options(field_type),
            expected.map(|v| v.into_iter().map(str::to_string).collect::<Vec<_>>())
        );
    }

    #[test]
    fn theme_selector_offers_every_builtin_slug() {
        let options = super::select_options("SelectThemes").expect("theme options");
        assert_eq!(options.len(), opaline::builtins::builtin_names().len());
        // Sorted and loadable: a theme the field offers is a theme the app can
        // start with (`AppState::new` panics on an unknown `theme_name`).
        let mut sorted = options.clone();
        sorted.sort();
        assert_eq!(options, sorted);
        for slug in &options {
            assert!(
                crate::ui::theme::load(slug).is_ok(),
                "selector offers `{slug}` but it does not load"
            );
        }
    }

    #[rstest]
    #[case::forward_wraps("zh", true, "en")]
    #[case::backward_wraps("en", false, "zh")]
    #[case::forward_steps("en", true, "zh")]
    #[case::backward_steps("zh", false, "en")]
    fn cycling_wraps_past_the_last_option(
        #[case] current: &str,
        #[case] forward: bool,
        #[case] expected: &str,
    ) {
        let options = vec!["en".to_string(), "zh".to_string()];
        assert_eq!(super::cycle_select(current, &options, forward), expected);
    }

    #[test]
    fn cycling_an_unknown_value_starts_at_the_first_option() {
        let options = vec!["en".to_string(), "zh".to_string()];
        assert_eq!(super::cycle_select("klingon", &options, true), "en");
    }

    /// The regression that made booleans one-way: the toggle arm cleared the
    /// buffer BEFORE reading it, so the comparison always saw `""` and every
    /// edit wrote `"true"`. A stored `true` could not be turned back off by
    /// any gesture.
    #[rstest]
    #[case::true_to_false("true", "false")]
    #[case::false_to_true("false", "true")]
    #[case::uppercase_true("TRUE", "false")]
    #[case::empty_becomes_true("", "true")]
    #[case::garbage_becomes_true("tru", "true")]
    fn toggling_a_boolean_reaches_both_values(#[case] current: &str, #[case] expected: &str) {
        assert_eq!(super::toggle_bool(current), expected);
    }

    /// Toggling twice returns to the start, and round-tripping a real stored
    /// value must be lossless — the invariant a one-way toggle breaks.
    #[rstest]
    #[case::stored_true("true")]
    #[case::stored_false("false")]
    fn boolean_toggle_round_trips(#[case] stored: &str) {
        let once = super::toggle_bool(stored);
        assert_ne!(once, stored, "one press must change the value");
        assert_eq!(super::toggle_bool(once), stored, "two presses restore it");
    }

    #[test]
    fn select_accepts_lists_its_options_without_the_empty_one() {
        assert_eq!(
            field_accepts("Select:debug,info,warning,error"),
            "debug, info, warning, error"
        );
        assert_eq!(field_accepts("Boolean"), "true / false");
        assert_eq!(field_accepts("Text"), "free text");
    }
}

#[cfg(test)]
mod navigation_tests {
    use super::{snap_selection_to_filter, step_selection};
    use crate::AppState;

    async fn state() -> AppState {
        let dir = tempfile::tempdir().expect("temp dir");
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("nav.db"))
                .await
                .expect("database"),
        );
        AppState::new(db, leas_config::AppConfig::default()).await
    }

    #[tokio::test]
    async fn selection_walks_visible_rows_and_clamps_at_the_ends() {
        let mut app = state().await;
        // 15 leaves, all visible.
        assert_eq!(app.settings_sections.selected, 0);
        step_selection(&mut app, false);
        assert_eq!(app.settings_sections.selected, 0, "clamps at the first row");
        step_selection(&mut app, true);
        assert_eq!(app.settings_sections.selected, 1);
        for _ in 0..40 {
            step_selection(&mut app, true);
        }
        assert_eq!(app.settings_sections.selected, 14, "clamps at the last row");
    }

    #[tokio::test]
    async fn collapsed_group_is_skipped_and_a_filter_snaps_the_selection() {
        let mut app = state().await;
        // Collapsing "Core" hides leaves 0 and 1.
        app.settings_sections.toggle_expanded(0);
        app.settings_sections.selected = 0;
        step_selection(&mut app, true);
        assert_eq!(
            app.settings_sections.selected, 2,
            "a hidden leaf is skipped, not selected"
        );
        // A filter that hides the selection moves it to the first match.
        app.settings_search.query = "dns".to_string();
        snap_selection_to_filter(&mut app);
        assert_eq!(app.settings_sections.selected, 8, "DNS is the only match");
    }
}

#[cfg(test)]
mod tests {
    use super::handle_form_key;
    use crate::AppState;
    use crate::types::{AppMode, SettingsMode, SettingsSection, SplitFocus, SplitRightPane};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::collections::HashMap;

    /// Regression: pressing Right on the Protocol Core form panicked
    /// ("index out of bounds: the len is 0 but the index is 0" at
    /// settings.rs, the Select Left/Right arm) because the stored form fields
    /// were empty when no overrides were saved, while the field defs (22
    /// protocols) were not. The handler must no-op instead of indexing.
    #[tokio::test]
    async fn form_left_right_no_panic_with_empty_fields() {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, leas_config::AppConfig::default()).await;
        // Pre-fix failure state: Protocol Core form with empty stored fields.
        state.mode = AppMode::Settings {
            mode: SettingsMode::Split {
                focus: SplitFocus::Right,
                right: SplitRightPane::Form {
                    section: SettingsSection::ProtocolCore,
                    fields: Vec::new(),
                    focus_index: 0,
                    form_errors: HashMap::new(),
                },
            },
        };

        // Must not panic; fields stay empty (no field to cycle).
        handle_form_key(
            &mut state,
            &KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
        )
        .await;
        handle_form_key(
            &mut state,
            &KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
        )
        .await;
    }
}
