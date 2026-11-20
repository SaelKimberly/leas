//! Sources (pane 1): the subscription groups as a table.
//!
//! The group list and form left the Settings popup (spec §1) for a first-class
//! tab: same keys (`a` add, `e` edit, `d` delete, `u` update all, `Space`
//! toggle), table-shaped with human-readable columns, and the group form is a
//! full screen (`AppMode::GroupForm`) like add/edit-server.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::ui::theme::ThemeStyles;
use crate::ui::widgets::{Column, ColumnWidth, DataTable, DataTableRow, DataTableState};
use leas_db::models::GroupStatus;

use crate::{AppMode, AppState};

/// Group table columns, widest set first: `Name · Enabled · Status ·
/// Updated · Endpoints · URL`. Narrow panes shed whole columns from the
/// right (never half-drawn) at the thresholds in [`columns_for`].
fn columns_for(width: u16) -> Vec<Column<'static>> {
    // Name shares two tenths of the pane, clamped so a narrow table keeps at
    // least a usable name column.
    let mut cols = vec![
        Column::new("Kind", ColumnWidth::Fixed(6)),
        Column::new(
            "Name",
            ColumnWidth::Fixed((width.saturating_sub(4) as usize * 2 / 10).clamp(8, 20) as u16),
        ),
        Column::new("Enabled", ColumnWidth::Fixed(7)),
    ];
    if width >= 52 {
        // An error row puts its REASON here (`error: <reason>`), and 20 cells
        // shows about a twelfth of one. 40 fits only once the fixed columns
        // plus the remaining URL minimum stop overflowing, hence the tier.
        let status = if width >= 90 { 40 } else { 20 };
        cols.push(Column::new(
            "Status",
            ColumnWidth::Fixed(status.min(width.saturating_sub(40))),
        ));
    }
    if width >= 64 {
        cols.push(Column::new("Updated", ColumnWidth::Fixed(10)));
    }
    if width >= 80 {
        cols.push(Column::new("Endpoints", ColumnWidth::Fixed(9)));
    }
    if width >= 100 {
        cols.push(Column::new(
            "URL",
            ColumnWidth::Min(width.saturating_sub(60).max(10)),
        ));
    }
    cols
}

/// Rows of the sources table: the same facts the old group list rendered,
/// plus the per-group endpoint count. Styles are precomputed where the theme
/// is available (`render`); the [`DataTableRow`] impl only draws.
struct SourceRow {
    kind: String,
    name: String,
    enabled: String,
    status: String,
    updated: String,
    endpoints: usize,
    url: String,
    updating: bool,
    name_style: Style,
    enabled_style: Style,
    status_style: Style,
    updated_style: Style,
    url_style: Style,
}

impl DataTableRow for SourceRow {
    fn render(
        &self,
        col_xs: &[u16],
        col_widths: &[u16],
        col_order: &[usize],
        buf: &mut Buffer,
        y: u16,
        clip_bottom: u16,
        content_right: u16,
    ) {
        // A row that starts past the clip line has nothing visible to draw.
        if y >= clip_bottom {
            return;
        }
        let enabled = if self.enabled == "true" { "✓" } else { "✗" };
        let enabled_suffix = if self.updating { " ⟳" } else { "" };
        for (i, &x) in col_xs.iter().enumerate() {
            // Match by LOGICAL column id: width-aware drops hide trailing
            // columns without shifting another column's meaning.
            let logical = col_order.get(i).copied().unwrap_or(i);
            let max_w = usize::from(col_widths.get(i).copied().unwrap_or(0))
                .min(usize::from(content_right.saturating_sub(x)));
            if max_w == 0 {
                continue;
            }
            let (text, style) = match logical {
                0 => (self.kind.clone(), self.url_style),
                1 => (self.name.clone(), self.name_style),
                2 => (format!("{enabled}{enabled_suffix}"), self.enabled_style),
                3 => (self.status.clone(), self.status_style),
                4 => (self.updated.clone(), self.updated_style),
                5 => (self.endpoints.to_string(), self.name_style),
                6 => (self.url.clone(), self.url_style),
                _ => (String::new(), self.name_style),
            };
            buf.set_stringn(
                x,
                y,
                crate::ui::textfit::truncate(&text, max_w),
                max_w,
                style,
            );
        }
    }

    fn height(&self, _available_width: u16) -> u16 {
        1
    }
}

/// `last_refreshed` is unix seconds.
///
/// A rough "days ago" is what a table cell can afford (the Details pane holds
/// the precise facts).
fn format_updated(last_refreshed: Option<i64>) -> String {
    last_refreshed.map_or_else(
        || "—".to_string(),
        |secs| {
            let days = (secs.max(0) as u64) / 86_400;
            if days == 0 {
                "today".to_string()
            } else {
                format!("{days}d ago")
            }
        },
    )
}

struct SourceRowFields<'a> {
    kind: &'static str,
    name: String,
    enabled: bool,
    status_text: String,
    updated: String,
    endpoints: usize,
    url: &'a str,
    updating: bool,
    width: u16,
}

fn build_row(theme: &opaline::Theme, selected: bool, f: SourceRowFields<'_>) -> SourceRow {
    let base = if selected {
        ThemeStyles::table_row_selected(theme)
    } else {
        ThemeStyles::table_row_normal(theme)
    };
    let url_width = usize::from(f.width.max(100).saturating_sub(60)).max(10);
    let status_style = if f.status_text.starts_with("error") {
        ThemeStyles::error(theme)
    } else {
        ThemeStyles::hint(theme)
    };
    SourceRow {
        kind: f.kind.to_string(),
        name: f.name,
        enabled: if f.enabled { "true" } else { "false" }.to_string(),
        status: f.status_text,
        updated: f.updated,
        endpoints: f.endpoints,
        url: crate::ui::textfit::truncate(f.url, url_width),
        updating: f.updating,
        name_style: base,
        enabled_style: if f.enabled {
            ThemeStyles::success(theme)
        } else {
            ThemeStyles::hint(theme)
        },
        status_style,
        updated_style: ThemeStyles::hint(theme),
        url_style: ThemeStyles::hint(theme),
    }
}

fn group_status_text(status: Option<GroupStatus>, error: Option<&str>) -> String {
    let name = match status {
        Some(GroupStatus::Ok) => "ok",
        Some(GroupStatus::Error) => "error",
        Some(GroupStatus::Never) | None => "never",
    };
    let reason = error
        .map(str::trim)
        .filter(|reason| !reason.is_empty())
        .map_or_default(|reason| crate::ui::textfit::truncate(reason, 60));
    if name == "error" && !reason.is_empty() {
        format!("error: {reason}")
    } else {
        name.to_string()
    }
}

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let selected_index = state.sources_selected;
    let mut rows: Vec<SourceRow> = Vec::with_capacity(state.groups.len() + state.dns_sources.len());
    for (index, group) in state.groups.iter().enumerate() {
        let selected = index == selected_index
            || state
                .sources_selected_mask
                .get(index)
                .copied()
                .unwrap_or(false);
        rows.push(build_row(
            theme,
            selected,
            SourceRowFields {
                kind: "proxy",
                name: group.name.clone().unwrap_or_else(|| "Unnamed".to_string()),
                enabled: group.enabled,
                status_text: group_status_text(group.status, group.error_message.as_deref()),
                updated: format_updated(group.last_refreshed),
                endpoints: state.sources_counts.get(&group.id).copied().unwrap_or(0),
                url: group.url.as_deref().unwrap_or(""),
                updating: state.updating_groups.contains(&group.id),
                width: area.width,
            },
        ));
    }
    for (offset, source) in state.dns_sources.iter().enumerate() {
        let index = state.groups.len() + offset;
        let selected = index == selected_index
            || state
                .sources_selected_mask
                .get(index)
                .copied()
                .unwrap_or(false);
        rows.push(build_row(
            theme,
            selected,
            SourceRowFields {
                kind: "dns",
                name: source
                    .name
                    .clone()
                    .unwrap_or_else(|| "Unnamed DNS".to_string()),
                enabled: source.enabled,
                status_text: group_status_text(source.status, source.error_message.as_deref()),
                updated: format_updated(source.last_refreshed),
                endpoints: 0,
                url: &source.url,
                updating: false,
                width: area.width,
            },
        ));
    }
    let columns = columns_for(area.width);
    let table = DataTable::new(&columns, &rows)
        .highlight_style(ThemeStyles::table_row_selected(theme).add_modifier(Modifier::BOLD));
    let mut table_state = DataTableState {
        offset: state.sources_selected.saturating_sub(1),
        ..DataTableState::default()
    };
    frame.render_stateful_widget(table, area, &mut table_state);
}

/// Tab-entry setup for Sources (spec §1): reset the selection, size the
/// enabled mask to the groups, refresh the member counts.
///
/// Every route into the tab (`g`, `[`/`]`) goes through this — a skipped
/// entry leaves an empty mask (Space dead) and zero counts.
pub async fn enter_sources_if_selected(state: &mut AppState) {
    if !matches!(state.pane1_tab, crate::types::Pane1Tab::Sources) {
        return;
    }
    state.sources_selected = 0;
    state.sources_selected_mask = vec![false; state.groups.len() + state.dns_sources.len()];
    crate::ops::subscriptions::reload_sources_counts(state).await;
}

pub fn handle_key(state: &mut AppState, key: &KeyEvent) {
    let selected = state.sources_selected;
    let group_count = state.groups.len();
    let max = group_count
        .saturating_add(state.dns_sources.len())
        .saturating_sub(1);
    match key.code {
        KeyCode::Up => {
            state.sources_selected = selected.saturating_sub(1);
        }
        KeyCode::Down => {
            if selected < max {
                state.sources_selected += 1;
            }
        }
        KeyCode::Char(' ') => {
            if let Some(flag) = state.sources_selected_mask.get_mut(state.sources_selected) {
                *flag = !*flag;
            }
        }
        // `a` adds a proxy subscription, `A` a DNS source: one form, two kinds.
        KeyCode::Char('a') => crate::ops::subscriptions::start_add_group(state),
        KeyCode::Char('A') => crate::ops::dns::start_add_source(state),
        KeyCode::Char('e' | 'E') => {
            if selected < group_count {
                if let Some(group) = state.groups.get(selected) {
                    let group_id = group.id.clone();
                    crate::ops::subscriptions::start_edit_group(state, &group_id);
                }
            } else if let Some(source) = state.dns_sources.get(selected - group_count) {
                let source_id = source.id.clone();
                crate::ops::dns::start_edit_source(state, &source_id);
            }
        }
        KeyCode::Char('d' | 'D') => {
            // Masked groups win; otherwise the cursor row, whichever kind.
            let masked: Vec<String> = state
                .sources_selected_mask
                .iter()
                .enumerate()
                .filter(|&(_, m)| *m)
                .filter_map(|(i, _)| state.groups.get(i).map(|g| g.id.clone()))
                .collect();
            if let Some(id) = masked.first() {
                state.confirmation = Some(crate::ConfirmAction::DeleteGroup(id.clone()));
            } else if selected < group_count {
                if let Some(group) = state.groups.get(selected) {
                    state.confirmation = Some(crate::ConfirmAction::DeleteGroup(group.id.clone()));
                }
            } else if let Some(source) = state.dns_sources.get(selected - group_count) {
                state.confirmation = Some(crate::ConfirmAction::DeleteDnsSource(source.id.clone()));
            }
        }
        KeyCode::Char('u' | 'U') => {
            crate::ops::subscriptions::update_all_subscriptions(state);
            crate::ops::dns::refresh_all(state);
        }
        _ => {}
    }
}

/// Full-screen group form (add/edit): one row per field, `›` focus marker,
/// `█` cursor. Four text fields; no selectors or booleans.
const GROUP_FIELD_DEFS: &[(&str, &str)] = &[
    ("name", "Name"),
    ("subscription_url", "Subscription URL / Channel"),
    ("user_agent", "User Agent"),
    ("update_interval", "Update Interval"),
];

pub fn render_group_form(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let AppMode::GroupForm {
        group_id,
        kind,
        fields,
        focus_index,
        ..
    } = &state.mode
    else {
        return;
    };
    let title = match (kind, group_id) {
        (crate::types::SourceFormKind::Dns, Some(_)) => " Edit DNS Source ",
        (crate::types::SourceFormKind::Dns, None) => " Add DNS Source ",
        (crate::types::SourceFormKind::Subscription, Some(_)) => " Edit Source ",
        (crate::types::SourceFormKind::Subscription, None) => " Add Source ",
    };
    let block = Block::default()
        .title(title)
        .title_style(ThemeStyles::container_title(theme))
        .borders(Borders::ALL)
        .border_style(ThemeStyles::container_border_focused(theme));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let prefix_cells = 3usize;
    let label_w = (inner.width.saturating_sub(14).clamp(12, 24) as usize)
        .min((inner.width as usize).saturating_sub(prefix_cells + 1));
    let budget = (inner.width as usize).saturating_sub(prefix_cells + label_w);

    for (y, (i, (key, label))) in (inner.y..inner.bottom()).zip(GROUP_FIELD_DEFS.iter().enumerate())
    {
        let focused = i == *focus_index;
        let value = fields
            .iter()
            .find(|(k, _)| k == *key)
            .map_or_else(String::new, |(_, v)| v.clone());
        let display = if value.is_empty() {
            "—".to_string()
        } else {
            value
        };
        let text = if focused {
            let trimmed = crate::ui::textfit::truncate_head(&display, budget.saturating_sub(1));
            format!("{trimmed}█")
        } else {
            crate::ui::textfit::truncate(&display, budget)
        };
        let label_style = if focused {
            ThemeStyles::table_row_selected(theme).add_modifier(Modifier::BOLD)
        } else {
            ThemeStyles::table_row_normal(theme)
        };
        let spans = vec![
            Span::styled(if focused { "›" } else { " " }, label_style),
            Span::styled("· ", ThemeStyles::hint(theme)),
            Span::styled(crate::ui::textfit::pad(label, label_w), label_style),
            Span::styled(text, ThemeStyles::footer_value(theme)),
        ];
        frame.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(inner.x, y, inner.width, 1),
        );
    }
}

pub async fn handle_group_form_key(state: &mut AppState, key: &KeyEvent) {
    let (group_id, _focus_index, field_count) = match &state.mode {
        AppMode::GroupForm {
            group_id,
            focus_index,
            fields,
            ..
        } => (group_id.clone(), *focus_index, fields.len()),
        _ => return,
    };
    let max_index = field_count.saturating_sub(1);
    match key.code {
        KeyCode::Tab => {
            if let AppMode::GroupForm { focus_index, .. } = &mut state.mode
                && *focus_index < max_index
            {
                *focus_index += 1;
            }
        }
        KeyCode::BackTab | KeyCode::Up => {
            if let AppMode::GroupForm { focus_index, .. } = &mut state.mode {
                *focus_index = focus_index.saturating_sub(1);
            }
        }
        KeyCode::Down => {
            if let AppMode::GroupForm { focus_index, .. } = &mut state.mode
                && *focus_index < max_index
            {
                *focus_index += 1;
            }
        }
        KeyCode::Enter => {
            if group_id.is_some() {
                crate::ops::subscriptions::confirm_edit_group(state).await;
            } else {
                crate::ops::subscriptions::confirm_add_group(state).await;
            }
        }
        KeyCode::Esc => {
            state.mode = AppMode::List;
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let AppMode::GroupForm {
                fields,
                focus_index,
                ..
            } = &mut state.mode
                && *focus_index < fields.len()
            {
                let (_, val) = &mut fields[*focus_index];
                val.push(c);
            }
        }
        KeyCode::Backspace => {
            if let AppMode::GroupForm {
                fields,
                focus_index,
                ..
            } = &mut state.mode
                && *focus_index < fields.len()
            {
                let (_, val) = &mut fields[*focus_index];
                val.pop();
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Pane1Tab;

    /// Column shedding thresholds (spec §1): full set at ≥100, URL first to
    /// go, then Endpoints, then Updated, then Status; none half-drawn.
    #[test]
    fn sources_columns_shed_by_width_thresholds() {
        let count = |w: u16| columns_for(w).len();
        assert_eq!(count(120), 7);
        assert_eq!(count(100), 7);
        assert_eq!(count(99), 6, "URL sheds first");
        assert_eq!(count(80), 6);
        assert_eq!(count(79), 5, "Endpoints sheds second");
        assert_eq!(count(64), 5);
        assert_eq!(count(63), 4, "Updated sheds third");
        assert_eq!(count(52), 4);
        assert_eq!(count(51), 3, "Status sheds fourth");
        assert_eq!(count(40), 3, "Kind, Name and Enabled always stay");
    }

    /// The tab is part of the cycle, between DNS and Logs.
    #[test]
    fn sources_sits_between_dns_and_logs() {
        assert_eq!(Pane1Tab::Dns.next(), Pane1Tab::Sources);
        assert_eq!(Pane1Tab::Sources.next(), Pane1Tab::Logs);
        assert_eq!(Pane1Tab::Sources.prev(), Pane1Tab::Dns);
        assert_eq!(Pane1Tab::Logs.prev(), Pane1Tab::Sources);
    }
}

#[cfg(test)]
mod flow_tests {
    use super::*;
    use crate::types::Pane1Tab;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    async fn state_with_groups(count: usize) -> (tempfile::TempDir, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, leas_config::AppConfig::default()).await;
        for i in 0..count {
            let group = leas_db::models::Group {
                id: format!("g{i}"),
                name: Some(format!("Group {i}")),
                url: Some("https://example.com/feed".into()),
                enabled: true,
                user_agent: None,
                convert_target: None,
                sort_order: Some(i as i32),
                refresh_interval: Some(60),
                last_refreshed: None,
                status: None,
                error_message: None,
            };
            state.db.upsert_group(&group).await.unwrap();
        }
        state.reload_groups().await;
        state.pane1_tab = Pane1Tab::Sources;
        state.sources_selected_mask = vec![false; state.groups.len() + state.dns_sources.len()];
        (dir, state)
    }

    /// `a` opens `AppMode::GroupForm` with the four default fields; `Enter`
    /// saves and returns to `AppMode::List` with the group present.
    #[tokio::test]
    async fn add_group_flows_through_group_form_mode() {
        let (dir, mut state) = state_with_groups(0).await;
        handle_key(
            &mut state,
            &KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
        );
        assert!(
            matches!(state.mode, AppMode::GroupForm { group_id: None, .. }),
            "a must open the add form"
        );
        for c in "TestFeed".chars() {
            handle_group_form_key(
                &mut state,
                &KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE),
            )
            .await;
        }
        handle_group_form_key(
            &mut state,
            &KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        )
        .await;
        assert!(matches!(state.mode, AppMode::List), "save returns to List");
        assert!(
            state
                .groups
                .iter()
                .any(|g| g.name.as_deref() == Some("TestFeed")),
            "the group was saved"
        );
        drop(dir);
    }

    /// `e` edits the selected group; the form carries its id.
    #[tokio::test]
    async fn edit_group_carries_the_selected_id() {
        let (dir, mut state) = state_with_groups(1).await;
        // The app seeds a "Default" group at startup; select the upserted one.
        state.sources_selected = state
            .groups
            .iter()
            .position(|g| g.name.as_deref() == Some("Group 0"))
            .expect("the seeded default must not swallow the upserted group");
        handle_key(
            &mut state,
            &KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE),
        );
        let AppMode::GroupForm {
            group_id, fields, ..
        } = &state.mode
        else {
            panic!("e must open the edit form");
        };
        let expected = state.groups[state.sources_selected].id.clone();
        assert_eq!(group_id.as_deref(), Some(expected.as_str()));
        assert_eq!(
            fields
                .iter()
                .find(|(k, _)| k == "name")
                .map(|(_, v)| v.as_str()),
            Some("Group 0"),
            "the form preloads the group's values"
        );
        drop(dir);
    }

    /// `d` queues `ConfirmAction::DeleteGroup` for the masked rows, falling
    /// back to the cursor row.
    #[tokio::test]
    async fn delete_queues_the_confirmation() {
        let (dir, mut state) = state_with_groups(2).await;
        handle_key(
            &mut state,
            &KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        );
        let expected = state.groups[0].id.clone();
        let expected2 = state.groups[1].id.clone();
        assert!(
            matches!(
                state.confirmation,
                Some(crate::ConfirmAction::DeleteGroup(ref id)) if *id == expected
            ),
            "the cursor row is the fallback"
        );
        state.confirmation = None;
        state.sources_selected_mask[1] = true;
        handle_key(
            &mut state,
            &KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
        );
        assert!(
            matches!(
                state.confirmation,
                Some(crate::ConfirmAction::DeleteGroup(ref id)) if *id == expected2
            ),
            "the mask wins over the cursor"
        );
        drop(dir);
    }

    /// A truncated import's reason must be legible in the row, not just the
    /// word `error`: the Status column is what clips it, so at a wide pane the
    /// text after `error: ` has to survive to the reason's words. Before the
    /// 40-cell tier this row showed `error: 256 MiB byt` and nothing else.
    #[tokio::test]
    async fn an_error_row_shows_its_reason_words() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let (dir, mut state) = state_with_groups(1).await;
        let mut group = state.groups[0].clone();
        group.status = Some(leas_db::models::GroupStatus::Error);
        group.error_message = Some(
            "256 MiB byte budget — raise import.max_feed_bytes — subscription import ended \
             early after 12 link(s) stored; the feed is incomplete, stored rows were kept"
                .into(),
        );
        state.db.upsert_group(&group).await.unwrap();
        state.reload_groups().await;

        let mut terminal = Terminal::new(TestBackend::new(120, 10)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &state))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let area = *buffer.area();
        let painted: String = (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            painted.contains("byte budget"),
            "the reason must reach the row, not stop at `error:`: {painted}"
        );
        assert!(
            painted.contains("raise"),
            "the action the user has to take must be visible too: {painted}"
        );
        drop(dir);
    }

    /// `Space` toggles the mask at the cursor; the table keeps the widest
    /// column set at 120 columns with no column past the pane.
    #[tokio::test]
    async fn space_toggles_and_the_table_fits_the_pane() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let (dir, mut state) = state_with_groups(1).await;
        state.sources_selected = 0;
        handle_key(
            &mut state,
            &KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
        );
        assert!(state.sources_selected_mask[0], "space toggles the mask");

        let mut terminal = Terminal::new(TestBackend::new(120, 10)).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &state))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let area = *buffer.area();
        // Every painted cell sits inside the pane; the URL column is the
        // widest and must not run past the right edge.
        for y in 0..area.height {
            for x in 0..area.width {
                let cell = &buffer[(x, y)];
                assert!(
                    cell.symbol().trim().is_empty() || usize::from(x) < 120,
                    "cell outside the pane at ({x},{y})"
                );
            }
        }
        drop(dir);
    }
}
