use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use leas_config::forms::{FieldSection, FormFieldType, form_fields_for};
use leas_core::SINGBOX_ONLY_KINDS;
use leas_proto::proto_spec::ProtocolKind;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use std::collections::HashMap;

use crate::ui::theme::ThemeStyles;
use crate::{AppMode, AppState};
use ratatui_cheese::field::ValidationKind;
use ratatui_cheese::fieldset::{Fieldset, FieldsetFill};
use ratatui_cheese::input::{Input, InputState};
use ratatui_cheese::select::{Select, SelectOption, SelectState};
use tui_popup::{KnownSizeWrapper, Popup};

/// Protocol picker layout groups
const XRAY_PROTOCOLS: &[ProtocolKind] = &[
    ProtocolKind::Vmess,
    ProtocolKind::Vless,
    ProtocolKind::Shadowsocks,
    ProtocolKind::Shadowsocks2022,
    ProtocolKind::Socks,
    ProtocolKind::Http,
    ProtocolKind::Trojan,
    ProtocolKind::WireGuard,
    ProtocolKind::Hysteria2,
    ProtocolKind::DokodemoDoor,
    ProtocolKind::Freedom,
    ProtocolKind::Blackhole,
    ProtocolKind::Dns,
    ProtocolKind::Loopback,
    ProtocolKind::Custom,
];

fn singbox_protocols() -> Vec<ProtocolKind> {
    SINGBOX_ONLY_KINDS
        .iter()
        .filter(|p| !matches!(p, ProtocolKind::TProxy | ProtocolKind::Mixed))
        .copied()
        .collect()
}

const ALL_PICKER_PROTOCOLS: &[ProtocolKind] = &[
    ProtocolKind::Vmess,
    ProtocolKind::Vless,
    ProtocolKind::Shadowsocks,
    ProtocolKind::Shadowsocks2022,
    ProtocolKind::Socks,
    ProtocolKind::Http,
    ProtocolKind::Trojan,
    ProtocolKind::WireGuard,
    ProtocolKind::Hysteria2,
    ProtocolKind::DokodemoDoor,
    ProtocolKind::Freedom,
    ProtocolKind::Blackhole,
    ProtocolKind::Dns,
    ProtocolKind::Loopback,
    ProtocolKind::Custom,
    ProtocolKind::Tuic,
    ProtocolKind::Hysteria,
    ProtocolKind::Naive,
    ProtocolKind::AnyTls,
    ProtocolKind::ShadowTls,
    ProtocolKind::Tor,
    ProtocolKind::Ssh,
    ProtocolKind::Tailscale,
    ProtocolKind::ShadowsocksR,
    ProtocolKind::Redirect,
];

// ── Render dispatch ──────────────────────────────────────────────────────

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    match &state.mode {
        AppMode::AddServer { protocol: None, .. } => {
            render_protocol_picker(frame, area, state);
        }
        AppMode::AddServer {
            protocol: Some(p),
            fields,
            focus_index,
            form_errors,
        } => {
            render_form(
                frame,
                area,
                *p,
                fields,
                *focus_index,
                form_errors,
                false,
                theme,
            );
        }
        AppMode::EditServer {
            fields,
            focus_index,
            form_errors,
            ..
        } => {
            let proto = crate::get_field(fields, "config_type")
                .and_then(|v| v.parse::<i32>().ok())
                .and_then(ProtocolKind::try_from_i32)
                .unwrap_or(ProtocolKind::Custom);
            render_form(
                frame,
                area,
                proto,
                fields,
                *focus_index,
                form_errors,
                true,
                theme,
            );
        }
        _ => {}
    }
}

pub fn render_import_url(frame: &mut Frame, area: Rect, state: &AppState) {
    let AppMode::ImportUrl { input, error } = &state.mode else {
        return;
    };
    let theme = state.theme();

    let display_text = if input.is_empty() {
        "(paste URL here)".to_string()
    } else {
        input.clone()
    };

    let mut lines = vec![Line::from(Span::raw(&display_text))];
    if let Some(err) = error {
        lines.push(Line::from(Span::styled(
            format!("Error: {err}"),
            ThemeStyles::error(theme),
        )));
    }
    let para = Paragraph::new(lines);
    let width = area.width.saturating_sub(4).max(20) as usize;
    let height = 3usize;
    let sized = KnownSizeWrapper {
        inner: para,
        width,
        height,
    };
    let popup = Popup::new(sized)
        .title(" Import URL — Ctrl+V paste, Enter parse, Esc cancel ")
        .borders(Borders::ALL)
        .border_style(ThemeStyles::container_border(theme))
        .style(ThemeStyles::dialog(theme));
    frame.render_widget(popup, area);
}

// ── Protocol picker ──────────────────────────────────────────────────────

fn render_protocol_picker(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();

    // Build options with disabled separators for section headers
    let mut item_labels: Vec<String> = Vec::new();
    item_labels.push("=== Xray-core ===".to_string());
    for proto in XRAY_PROTOCOLS {
        item_labels.push(format!("  {proto}"));
    }
    item_labels.push("=== Sing-box ===".to_string());
    for proto in singbox_protocols() {
        item_labels.push(format!("  {proto}"));
    }
    let opts: Vec<SelectOption> = item_labels
        .iter()
        .map(|s| {
            if s.starts_with("===") {
                SelectOption::new(s).enabled(false)
            } else {
                SelectOption::new(s)
            }
        })
        .collect();
    // Map AppState.selected_index (protocol-only index) to Select cursor position
    let xray_count = XRAY_PROTOCOLS.len();
    let cursor_pos = if state.selected_index < xray_count {
        1 + state.selected_index
    } else {
        1 + xray_count + 1 + (state.selected_index - xray_count)
    };

    let select =
        Select::new("Select Protocol", &opts).palette(&crate::ui::theme::widget_palette(theme));
    let mut select_state = SelectState::from_options(&opts);
    select_state.set_cursor(cursor_pos);
    select_state.set_focused(true);
    frame.render_stateful_widget(select, area, &mut select_state);
}

// ── Form render ──────────────────────────────────────────────────────────

// TODO 3.3: Add scroll_offset: usize to AddServer/EditServer variants + scroll
// indicators when fields exceed visible height.
fn render_form(
    frame: &mut Frame,
    area: Rect,
    protocol: ProtocolKind,
    fields: &[(String, String)],
    focus_index: usize,
    form_errors: &HashMap<String, String>,
    _is_edit: bool,
    theme: &opaline::Theme,
) {
    let title = format!(" {protocol} ");
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(ThemeStyles::container_border(theme))
        .title_style(ThemeStyles::container_title(theme));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let form_fields = form_fields_for(protocol);

    // Group fields by section
    let sections: &[(&str, FieldSection)] = &[
        ("General", FieldSection::Common),
        ("Stream Settings", FieldSection::StreamSetting),
        ("Protocol Settings", FieldSection::ProtocolSetting),
    ];

    let mut y = inner.y;
    let max_y = inner.y + inner.height;

    for (sec_name, sec_key) in sections {
        // Collect fields in this section
        let sec_fields: Vec<(usize, &leas_config::forms::FormField)> = form_fields
            .iter()
            .enumerate()
            .filter(|(_, ff)| ff.section == *sec_key)
            .collect();

        if sec_fields.is_empty() {
            continue;
        }

        // Fieldset section header (1 line)
        if y >= max_y {
            break;
        }
        let fs_area = Rect::new(inner.x, y, inner.width, 1);
        let fieldset = Fieldset::new()
            .title(sec_name)
            .fill(FieldsetFill::Dash)
            .palette(&crate::ui::theme::widget_palette(theme));
        frame.render_widget(&fieldset, fs_area);
        y += 1;

        // Render each field in this section as an Input widget
        for (i, ff) in &sec_fields {
            if y >= max_y {
                break;
            }

            let is_focused = *i == focus_index;
            let val = fields.get(*i).map_or("", |(_, v)| v.as_str());

            // Compute display value based on field type
            let display_val = match ff.field_type {
                FormFieldType::Password => {
                    if val.is_empty() {
                        String::new()
                    } else {
                        "••••••".into()
                    }
                }
                FormFieldType::Boolean => {
                    if val == "true" {
                        "[X]".into()
                    } else {
                        "[ ]".into()
                    }
                }
                FormFieldType::Select(_) => {
                    format!("< {val} >")
                }
                _ => val.to_string(),
            };

            // Build Input widget
            let input = if matches!(ff.field_type, FormFieldType::Password) {
                Input::new(ff.label)
                    .palette(&crate::ui::theme::widget_palette(theme))
                    .password_mode(true)
            } else {
                Input::new(ff.label).palette(&crate::ui::theme::widget_palette(theme))
            };

            let mut input_state = InputState::new();
            input_state.set_value(display_val);
            input_state.set_focused(is_focused);

            // Set validation error if present
            if let Some(error) = form_errors.get(ff.key) {
                input_state.set_validation(Some((ValidationKind::Error, error.clone())));
            }

            // Height: title line + prompt/value line + optional error line
            let has_error = u16::from(input_state.validation().is_some());
            let field_height = 2 + has_error;
            let field_area = Rect::new(inner.x, y, inner.width, field_height.min(max_y - y));
            frame.render_stateful_widget(&input, field_area, &mut input_state);
            y += field_height;
        }
    }

    // Help text at the bottom
    if y < max_y {
        let help = " Tab/Shift+Tab focus  ↵ Enter save  Esc cancel  Ctrl+S save";
        let hint_style = ThemeStyles::hint(theme);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(help, hint_style))),
            Rect::new(inner.x, y, inner.width, 1),
        );
    }
}

// ── Key handler ──────────────────────────────────────────────────────────

pub async fn handle_key(state: &mut AppState, key: &KeyEvent) {
    // Determine mode type first without borrowing state.mode deeply
    let is_picker = matches!(&state.mode, AppMode::AddServer { protocol: None, .. });
    let is_import = matches!(&state.mode, AppMode::ImportUrl { .. });
    let is_form = matches!(
        &state.mode,
        AppMode::AddServer {
            protocol: Some(_),
            ..
        } | AppMode::EditServer { .. }
    );

    if is_picker {
        handle_picker_key(state, key);
        return;
    }

    if is_import {
        handle_import_key(state, key);
        return;
    }

    if is_form {
        handle_form_key(state, key).await;
    }
}

fn handle_picker_key(state: &mut AppState, key: &KeyEvent) {
    let protocol_count = XRAY_PROTOCOLS.len() + singbox_protocols().len();
    if protocol_count == 0 {
        return;
    }

    match key.code {
        KeyCode::Up => {
            state.selected_index = state.selected_index.saturating_sub(1);
        }
        KeyCode::Down => {
            if state.selected_index < protocol_count - 1 {
                state.selected_index += 1;
            }
        }
        KeyCode::Enter => {
            if state.selected_index < ALL_PICKER_PROTOCOLS.len() {
                let proto = ALL_PICKER_PROTOCOLS[state.selected_index];
                let fields = form_fields_for(proto)
                    .iter()
                    .map(|f| (f.key.to_string(), f.default.to_string()))
                    .collect::<Vec<_>>();
                state.mode = AppMode::AddServer {
                    protocol: Some(proto),
                    fields,
                    focus_index: 0,
                    form_errors: HashMap::new(),
                };
            }
        }
        KeyCode::Esc => state.cancel_form(),
        _ => {}
    }
}
fn handle_import_key(state: &mut AppState, key: &KeyEvent) {
    let (url_to_import, should_import) = match &mut state.mode {
        AppMode::ImportUrl { input, error: _ } => match key.code {
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                input.push(c);
                (None, false)
            }
            KeyCode::Backspace => {
                input.pop();
                (None, false)
            }
            KeyCode::Enter => (Some(input.clone()), true),
            KeyCode::Esc => {
                state.cancel_form();
                return;
            }
            _ => (None, false),
        },
        _ => (None, false),
    };

    if should_import && let Some(url) = url_to_import {
        state.import_url(&url);
    }
}

async fn handle_form_key(state: &mut AppState, key: &KeyEvent) {
    // Extract protocol from current mode
    let protocol = match &state.mode {
        AppMode::AddServer {
            protocol: Some(p), ..
        } => Some(*p),
        AppMode::EditServer { proto_kind, .. } => Some(*proto_kind),
        _ => None,
    };

    let Some(p) = protocol else {
        return;
    };

    // Now match on mode again to get mutable refs to fields
    let field_data = match &mut state.mode {
        AppMode::AddServer {
            protocol: Some(_),
            fields,
            focus_index,
            ..
        } => Some((p, fields, focus_index, false)),
        AppMode::EditServer {
            fields,
            focus_index,
            ..
        } => Some((p, fields, focus_index, true)),
        _ => None,
    };

    let Some((protocol, fields, focus_index, is_edit)) = field_data else {
        return;
    };

    let form_fields = form_fields_for(protocol);
    if form_fields.is_empty() {
        return;
    }
    let max_idx = form_fields.len().saturating_sub(1);

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
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if is_edit {
                state.confirm_edit_server().await;
            } else {
                state.confirm_add_server().await;
            }
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            if *focus_index >= fields.len() {
                return;
            }
            let ff = &form_fields[*focus_index];
            let (_, ref mut val) = fields[*focus_index];

            match ff.field_type {
                FormFieldType::Select(options) => {
                    let current_idx = options.iter().position(|o| *o == val.as_str()).unwrap_or(0);
                    let new_idx = (current_idx + 1) % options.len();
                    val.clear();
                    val.push_str(options[new_idx]);
                }
                FormFieldType::Boolean => {
                    val.clear();
                    val.push_str(if val == "true" { "false" } else { "true" });
                }
                FormFieldType::Number => {
                    if c.is_ascii_digit() || c == '-' {
                        val.push(c);
                    }
                }
                _ => {
                    val.push(c);
                }
            }
        }
        KeyCode::Backspace => {
            if *focus_index < fields.len() {
                let (_, ref mut val) = fields[*focus_index];
                val.pop();
            }
        }
        KeyCode::Enter => {
            if is_edit {
                state.confirm_edit_server().await;
            } else {
                state.confirm_add_server().await;
            }
        }
        KeyCode::Esc => state.cancel_form(),
        KeyCode::Left | KeyCode::Right if *focus_index < form_fields.len() => {
            let ff = &form_fields[*focus_index];
            if let FormFieldType::Select(options) = ff.field_type {
                let (_, ref mut val) = fields[*focus_index];
                let current_idx = options.iter().position(|o| *o == val.as_str()).unwrap_or(0);
                let new_idx = if key.code == KeyCode::Right {
                    (current_idx + 1) % options.len()
                } else if current_idx == 0 {
                    options.len() - 1
                } else {
                    current_idx - 1
                };
                val.clear();
                val.push_str(options[new_idx]);
            }
        }
        _ => {}
    }
}

pub fn render_batch_import(frame: &mut Frame, area: Rect, state: &AppState) {
    let AppMode::BatchImport { results, scroll } = &state.mode else {
        return;
    };
    let theme = state.theme();

    let total = results.len();
    let scroll = *scroll;

    // Build content lines
    let mut lines: Vec<Line> = Vec::new();

    // Status header
    let ok_count = results.iter().filter(|r| r.profile.is_some()).count();
    let err_count = results.iter().filter(|r| r.profile.is_none()).count();
    let header =
        format!(" {ok_count} valid, {err_count} invalid — Enter to import, Esc to cancel ");
    lines.push(Line::from(Span::styled(
        header,
        Style::default().fg(theme.color("accent.primary").into()),
    )));
    lines.push(Line::from(""));

    // URL list
    let popup_width = area.width.saturating_sub(4) as usize;
    let max_visible = 15usize;
    let list_height = max_visible.min(total.saturating_sub(scroll));
    for i in 0..list_height {
        let idx = scroll + i;
        if idx >= total {
            break;
        }
        let item = &results[idx];

        // Status icon
        let (icon, icon_style) = if item.profile.is_some() {
            (" ✓", ThemeStyles::success(theme))
        } else {
            (" ✗", ThemeStyles::error(theme))
        };

        // URL display (truncate to fit)
        let max_url_len = popup_width.saturating_sub(5);
        let display = if item.url.len() > max_url_len {
            format!("{}…", &item.url[..max_url_len.saturating_sub(1)])
        } else {
            item.url.clone()
        };

        let icon_span = Span::styled(icon, icon_style);
        let url_span = Span::raw(display);
        lines.push(Line::from(vec![icon_span, Span::raw(" "), url_span]));
    }

    // Scroll indicator
    if total > max_visible {
        let scroll_text = format!(
            " [{}-{}/{}] ",
            scroll + 1,
            (scroll + max_visible).min(total),
            total
        );
        lines.push(Line::from(Span::styled(
            scroll_text,
            Style::default().fg(theme.color("text.muted").into()),
        )));
    }

    let total_lines = lines.len() as u16;
    let para = Paragraph::new(lines);

    let popup_w = area.width.saturating_sub(4).max(30) as usize;
    let popup_h = (total_lines + 2).min(area.height.saturating_sub(2)).max(5) as usize;
    let sized = KnownSizeWrapper {
        inner: para,
        width: popup_w,
        height: popup_h,
    };
    let popup = Popup::new(sized)
        .title(" Batch Import ")
        .borders(Borders::ALL)
        .border_style(ThemeStyles::container_border(theme))
        .style(ThemeStyles::dialog(theme));
    frame.render_widget(popup, area);
}

pub async fn handle_batch_import_key(state: &mut AppState, key: &KeyEvent) {
    let results_len = match &state.mode {
        AppMode::BatchImport { results, .. } => results.len(),
        _ => return,
    };
    let scroll = match &state.mode {
        AppMode::BatchImport { scroll, .. } => *scroll,
        _ => return,
    };
    match key.code {
        KeyCode::Down => {
            let new_scroll = (scroll + 1).min(results_len.saturating_sub(1));
            if let AppMode::BatchImport { ref mut scroll, .. } = state.mode {
                *scroll = new_scroll;
            }
        }
        KeyCode::Up => {
            let new_scroll = scroll.saturating_sub(1);
            if let AppMode::BatchImport { ref mut scroll, .. } = state.mode {
                *scroll = new_scroll;
            }
        }
        KeyCode::Enter => {
            state.confirm_batch_import().await;
        }
        KeyCode::Esc => {
            state.mode = AppMode::List;
        }
        _ => {}
    }
}
