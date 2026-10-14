use crate::AppState;
use crate::SettingsSection;
use crate::ui::theme::ThemeStyles;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use std::sync::atomic::{AtomicU16, Ordering};

const SPINNER_CHARS: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
static SPINNER_TICK: AtomicU16 = AtomicU16::new(0);

fn spinner_char() -> char {
    let tick = SPINNER_TICK.fetch_add(1, Ordering::Relaxed);
    SPINNER_CHARS[tick as usize % SPINNER_CHARS.len()]
}

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let (left_text, left_style) = if state.connecting {
        (
            format!(" {} Connecting... ", spinner_char()),
            ThemeStyles::spinner(theme),
        )
    } else if state.speed_test_stop.load(Ordering::Relaxed) {
        (" ■ Stopping...".to_string(), ThemeStyles::error(theme))
    } else if state.batch_progress.is_some() || !state.testing_profiles.is_empty() {
        let progress_text = state.batch_progress.as_ref().map_or_else(
            || " Testing...".to_string(),
            |m| {
                let fast_done = m.fast.done.load(Ordering::Relaxed);
                let fast_total = m.fast.total.load(Ordering::Relaxed);
                let real_done = m.real.done.load(Ordering::Relaxed);
                let real_total = m.real.total.load(Ordering::Relaxed);
                match (fast_total, real_total) {
                    (0, _) => " Testing...".to_string(),
                    // Both levels, the fast one first: they run at the same time,
                    // so the pair is `F done/total · R done/total`. The compact
                    // panel bar and the Actions Log bars carry the ETAs.
                    (fast_total, real_total) if real_total > 0 => {
                        format!(" Testing: F {fast_done}/{fast_total} · R {real_done}/{real_total}")
                    }
                    (fast_total, _) => format!(" Testing: F {fast_done}/{fast_total}"),
                }
            },
        );
        (progress_text, ThemeStyles::warning(theme))
    } else if let Some(err) = &state.connection_error {
        (format!(" Error: {err}"), ThemeStyles::error(theme))
    } else {
        state.connected_core.as_ref().map_or_else(
            || (" Disconnected".to_string(), ThemeStyles::error(theme)),
            |core| (format!(" Connected [{core}]"), ThemeStyles::success(theme)),
        )
    };

    // Append update indicator if any backend has an update available
    let update_indicator_span = if state.update_status.values().any(|s| s.update_available) {
        let cores: Vec<&str> = state
            .update_status
            .iter()
            .filter(|(_, s)| s.update_available)
            .map(|(ct, _)| match ct {
                leas_core::CoreType::Xray => "xray",
                leas_core::CoreType::SingBox => "sing-box",
                // Auto never has a pending update row; native is in-process.
                leas_core::CoreType::Auto | leas_core::CoreType::Native => "",
            })
            .filter(|s| !s.is_empty())
            .collect();
        if cores.is_empty() {
            Span::raw("")
        } else {
            Span::styled(
                format!(" ⇧Update:{} ", cores.join(",")),
                ThemeStyles::warning(theme).add_modifier(Modifier::BOLD),
            )
        }
    } else {
        Span::raw("")
    };
    // Download progress indicator while updating backends
    let download_span = {
        let parts: Vec<String> = state
            .update_status
            .iter()
            .filter(|(_, s)| s.downloading)
            .map(|(ct, s)| {
                let name = match ct {
                    leas_core::CoreType::Xray => "x",
                    leas_core::CoreType::SingBox => "sb",
                    leas_core::CoreType::Auto | leas_core::CoreType::Native => "",
                };
                if let Some((done, total)) = s.download_progress {
                    let pct = if total > 0 {
                        format!("{}%", (done as f64 / total as f64 * 100.0) as u64)
                    } else {
                        "??".to_string()
                    };
                    format!(" ⇩{name} {pct}")
                } else {
                    format!(" ⇩{name}")
                }
            })
            .collect();
        if parts.is_empty() {
            Span::raw("")
        } else {
            Span::styled(parts.join(" "), ThemeStyles::spinner(theme))
        }
    };
    // Mode indicator prefix
    let mode_prefix = match &state.mode {
        crate::AppMode::Settings { mode } => match mode {
            crate::SettingsMode::Split { right, .. } => match right {
                crate::SplitRightPane::Empty => " Settings",
                crate::SplitRightPane::Form { section, .. } => status_bar_section_label(*section),
                crate::SplitRightPane::RoutingList { .. }
                | crate::SplitRightPane::RoutingForm { .. } => " Settings > Routing",
                crate::SplitRightPane::UpdateForm { .. } => " Settings > Updates",
                crate::SplitRightPane::GroupList { .. }
                | crate::SplitRightPane::GroupForm { .. } => " Settings > Subscriptions",
            },
        },
        crate::AppMode::AddServer { .. } => " Add Server",
        crate::AppMode::EditServer { .. } => " Edit Server",
        crate::AppMode::SpeedTestMenu { .. } => " Server Tools",
        crate::AppMode::ExportScope { .. } | crate::AppMode::ExportDestination { .. } => " Export",
        crate::AppMode::ExportPath { .. } => " Export File",
        crate::AppMode::BatchImport { .. } => " Batch Import",
        crate::AppMode::Help => " Help",
        _ => "",
    };

    let left_text = format!("{mode_prefix}{left_text}");

    // Dynamic right-side hints
    let right_text = build_hints(state);
    let right_style = ThemeStyles::status_bar_hint(theme);

    let width = area.width as usize;
    let left_len = left_text.len();
    let padding = width.saturating_sub(left_len + right_text.len());

    let mut spans = vec![
        Span::styled(left_text, left_style),
        Span::raw(" ".repeat(padding)),
        Span::styled(right_text, right_style),
    ];
    // Insert indicators between left text and padding
    let mut insert_pos = 1;
    if !download_span.content.is_empty() {
        spans.insert(insert_pos, Span::raw(" "));
        insert_pos += 1;
        spans.insert(insert_pos, download_span);
        insert_pos += 1;
    }
    if !update_indicator_span.content.is_empty() {
        spans.insert(insert_pos, Span::raw(" "));
        insert_pos += 1;
        spans.insert(insert_pos, update_indicator_span);
    }

    let line = Line::from(spans);

    let bg = ThemeStyles::status_bar_bg(theme);

    let paragraph = Paragraph::new(line).style(bg);
    frame.render_widget(paragraph, area);
}

/// Build context-sensitive keyboard hints for the right side of the status bar.
/// The one owner of the right-hand hint set: every key it names is live in the
/// state the screen is in.
///
/// It used to be a per-tab constant, so a confirmation dialog kept advertising
/// `[→] Expand` (and `q` there *cancels*, it does not quit), a filtered-empty
/// list still offered `Expand`, and the Settings tree never mentioned that `Tab`
/// leaves the screen. All four are asserted by
/// `docs/guides/tui/2026-10-14-132534-scenario-profiles-menus-states.md`.
fn build_hints(state: &AppState) -> String {
    // A modal owns the keyboard: its own keys, nothing else.
    if state.confirmation.is_some() {
        return " [y] Confirm  [n/Esc] Cancel ".to_string();
    }
    if matches!(&state.mode, crate::AppMode::Help) {
        return " [Esc] Close help ".to_string();
    }
    match &state.mode {
        // One string for every list-shaped overlay: the keys are the same, so
        // splitting them into arms only invites the two copies to drift.
        crate::AppMode::SpeedTestMenu { .. }
        | crate::AppMode::ExportScope { .. }
        | crate::AppMode::ExportDestination { .. } => {
            " [↑↓] Navigate  [Enter] Select  [Esc] Close ".to_string()
        }
        crate::AppMode::ExportPath {
            overwrite: true, ..
        } => " [Y] Overwrite  [N] Cancel ".to_string(),
        crate::AppMode::ExportPath { .. } => " [Enter] Write  [Esc] Cancel ".to_string(),
        crate::AppMode::Settings { mode } => match mode {
            crate::SettingsMode::Split { focus, right, .. } => match focus {
                crate::SplitFocus::Tree => {
                    " [↑↓] Navigate  [←→] Collapse  [Enter] Open  [Tab] Next tab  [Ctrl+W] Focus Form  [Esc] Close "
                        .to_string()
                }
                crate::SplitFocus::Right => match right {
                    crate::SplitRightPane::Empty => " [Ctrl+W] Focus Tree ".to_string(),
                    crate::SplitRightPane::Form { .. }
                    | crate::SplitRightPane::GroupForm { .. } => {
                        " [Tab/Shift+Tab] Focus  [Enter] Save  [Ctrl+W] Focus Tree  [Esc] Back ".to_string()
                    }
                    crate::SplitRightPane::RoutingList { .. } => {
                        " [↑/↓] Navigate  [A] Add  [E] Edit  [D] Delete  [Ctrl+W] Focus Tree  [Esc] Back ".to_string()
                    }
                    crate::SplitRightPane::RoutingForm { .. } => {
                        " [Enter] Save  [Ctrl+W] Focus Tree  [Esc] Back ".to_string()
                    }
                    crate::SplitRightPane::UpdateForm { .. } => {
                        " [C] Check  [D] Download  [Ctrl+W] Focus Tree  [Esc] Back ".to_string()
                    }
                    crate::SplitRightPane::GroupList { .. } => {
                        " [↑↓] Navigate  [Space] Select  [A] Add  [E] Edit  [D] Delete  [U] Update  [Ctrl+W] Focus Tree  [Esc] Back ".to_string()
                    }
                },
            },
        },
        _ => {
            // Default tab-based hints for non-Settings modes
            match state.current_tab {
                crate::Tab::Profiles => {
                    if state.connected_core.is_some() {
                        " [Ctrl+D] Disconnect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit ".to_string()
                    } else if state.connecting {
                        " [Tab] Next  [?] Help  [q/Ctrl+C] Quit ".to_string()
                    } else if state.search_focused || !state.search_query.is_empty() {
                        // A prefix filter that matched nothing is not an empty
                        // store: say what filtered it out, and how to undo it.
                        if state.endpoints.is_empty() {
                            format!(
                                " No match for \"{}\"  [Esc] Clear  [q/Ctrl+C] Quit ",
                                state.search_query
                            )
                        } else {
                            " [Esc] Clear filter  [Tab] Next  [?] Help  [q/Ctrl+C] Quit "
                                .to_string()
                        }
                    } else if state.endpoints.is_empty() {
                        // Nothing loaded: the row keys have nothing to act on.
                        " [a] Add  [Ctrl+V] Import  [Tab] Next  [?] Help  [q/Ctrl+C] Quit ".to_string()
                    } else {
                        " [→] Expand  [↑↓] Variant  [Ctrl+Enter/Ctrl+G] Connect  [Tab] Next  [?] Help  [q/Ctrl+C] Quit ".to_string()
                    }
                }
                // The tab's own keys are the six scroll keys (documented in
                // its manual section); the hints name what else is live here.
                crate::Tab::NativeActivity => {
                        " [F1] Actions Log  [?] Help  [q/Ctrl+C] Quit ".to_string()
                    }
                _ => " [q/Ctrl+C] Quit ".to_string(),
            }
        }
    }
}

const fn status_bar_section_label(section: SettingsSection) -> &'static str {
    match section {
        SettingsSection::Core => " Settings > Core",
        SettingsSection::Gui => " Settings > GUI",
        SettingsSection::Inbound => " Settings > Inbound",
        SettingsSection::Dns => " Settings > DNS",
        SettingsSection::SystemProxy => " Settings > System Proxy",
        SettingsSection::Tun => " Settings > TUN",
        SettingsSection::Mux => " Settings > Mux",
        SettingsSection::Stats => " Settings > Statistics",
        SettingsSection::ProtocolCore => " Settings > Protocol Core",
        SettingsSection::SpeedTest => " Settings > Speed Test",
        SettingsSection::Logging => " Settings > Logging",
        SettingsSection::Updates => " Settings > Updates",
        SettingsSection::Routing => " Settings > Routing",
        SettingsSection::Subscriptions => " Settings > Subscriptions",
        SettingsSection::RouteProbes => " Settings > Route Probes",
    }
}
