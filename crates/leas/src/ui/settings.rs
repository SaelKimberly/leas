use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui_cheese::field::ValidationKind;
use ratatui_cheese::input::{Input, InputState};
use ratatui_cheese::list::{List, ListItem, ListItemContext, ListState};
use std::cell::RefCell;
use std::collections::HashMap;

use crate::ui::theme::ThemeStyles;
use crate::ui::widgets::progress::bar_cells;
use crate::{
    AppMode, AppState, BackendUpdateStatus, SettingsMode, SettingsSection, SplitFocus,
    SplitRightPane,
};
use leas_core::CoreType;
use ratatui_cheese::tree::{Tree, TreeState, TreeStyles};
// ── Settings tree — data source for the left panel tree ─────────────────

use ratatui_cheese::tree as cheese_tree;

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

fn build_tree_groups() -> Vec<cheese_tree::TreeGroup> {
    SETTINGS_TREE
        .iter()
        .map(|g| {
            cheese_tree::TreeGroup::new(cheese_tree::TreeItem::new(g.name)).children(
                g.items
                    .iter()
                    .map(|item| cheese_tree::TreeItem::new(item.name))
                    .collect(),
            )
        })
        .collect()
}

fn section_from_selection(g: usize, child: Option<usize>) -> Option<SettingsSection> {
    let group = SETTINGS_TREE.get(g)?;
    let item = group.items.get(child?)?;
    item.section
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

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    if let AppMode::Settings {
        mode: SettingsMode::Split { tree, focus, right },
    } = &state.mode
    {
        let theme = state.theme();
        let left_pct = if area.width < 80 { 0.35 } else { 0.30 };
        let left_w = (f64::from(area.width) * left_pct) as u16;
        let (left_area, right_area) = split_rect(area, left_w);
        render_tree(frame, left_area, theme, tree, *focus);
        render_right_pane(frame, right_area, state, theme, right, *focus);
    }
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
fn render_tree(
    frame: &mut Frame,
    area: Rect,
    theme: &opaline::Theme,
    tree_state: &RefCell<TreeState>,
    focus: SplitFocus,
) {
    let block = Block::default()
        .title(" Settings ")
        .borders(Borders::ALL)
        .border_style(ThemeStyles::container_border(theme));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut styles = TreeStyles {
        parent: ThemeStyles::table_row_normal(theme),
        child: ThemeStyles::hint(theme),
        selected: Style::default()
            .fg(theme.color("bg.selection").into())
            .bg(theme.color("accent.primary").into())
            .add_modifier(Modifier::BOLD),
        chevron: ThemeStyles::hint(theme),
        chevron_active: ThemeStyles::spinner(theme),
        chevron_dim: ThemeStyles::hint(theme),
        count: ThemeStyles::footer_label(theme),
        icon: Style::default(),
    };

    // Dim selection when focus is on right pane
    if focus == SplitFocus::Right {
        styles.selected = ThemeStyles::hint(theme);
    }

    let groups = build_tree_groups();
    let tree = Tree::default()
        .groups(groups)
        .styles(styles)
        .chevron_collapsed("▸")
        .chevron_expanded("▾")
        .highlight_full_row(true);

    // Borrow mutably for render_stateful_widget (updates scroll offset)
    frame.render_stateful_widget(tree, inner, &mut tree_state.borrow_mut());
}
fn render_right_pane(
    frame: &mut Frame,
    area: Rect,
    state: &AppState,
    theme: &opaline::Theme,
    right: &SplitRightPane,
    _focus: SplitFocus,
) {
    let title = match right {
        SplitRightPane::Empty => " Select a section ",
        SplitRightPane::Form { section, .. } => form_title_for_section(*section),
        SplitRightPane::RoutingList { .. } => " Routing Rules ",
        SplitRightPane::RoutingForm { .. } => " Routing Rule ",
        SplitRightPane::UpdateForm { .. } => " Updates ",
        SplitRightPane::GroupList { .. } => " Subscriptions ",
        SplitRightPane::GroupForm { .. } => " Edit Group ",
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
            );
        }
        SplitRightPane::Empty => {}
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
        SplitFocus::Tree => handle_tree_key(state, key).await,
        SplitFocus::Right => {
            let pane_type = match &state.mode {
                AppMode::Settings {
                    mode: SettingsMode::Split { right, .. },
                } => match right {
                    SplitRightPane::Empty => 0u8,
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

const fn form_title_for_section(section: SettingsSection) -> &'static str {
    match section {
        SettingsSection::Core => " Core Settings ",
        SettingsSection::Gui => " GUI Settings ",
        SettingsSection::Inbound => " Inbound Settings ",
        SettingsSection::Dns => " DNS Settings ",
        SettingsSection::SystemProxy => " System Proxy ",
        SettingsSection::Tun => " TUN Mode ",
        SettingsSection::Mux => " Mux / Fragment ",
        SettingsSection::Stats => " Statistics ",
        SettingsSection::Subscriptions => " Subscriptions ",
        SettingsSection::ProtocolCore => " Protocol Core ",
        SettingsSection::SpeedTest => " Speed Test Settings ",
        SettingsSection::Logging => " Logging ",
        SettingsSection::Updates => " Updates ",
        SettingsSection::Routing => " Routing Rules ",
        SettingsSection::RouteProbes => " Probe Hosts ",
    }
}

async fn handle_tree_key(state: &mut AppState, key: &KeyEvent) {
    // Esc exits Settings mode — the help overlay advertises "Esc — Close settings",
    // and previously Esc was a dead key while the tree had focus.
    if key.code == KeyCode::Esc {
        state.mode = AppMode::List;
        return;
    }

    let groups = build_tree_groups();

    // Handle Enter separately — needs to release borrow before async call
    if key.code == KeyCode::Enter {
        let (g, child) = {
            let AppMode::Settings {
                mode:
                    SettingsMode::Split {
                        tree: tree_state, ..
                    },
            } = &mut state.mode
            else {
                return;
            };

            tree_state.borrow().selected()
        };
        if let Some(section) = section_from_selection(g, child) {
            let pane = state.build_right_pane(section).await;
            if let AppMode::Settings {
                mode: SettingsMode::Split { right, focus, .. },
            } = &mut state.mode
            {
                *right = pane;
                *focus = SplitFocus::Right;
            }
        } else {
            // Group header selected — toggle expand/collapse
            if let AppMode::Settings {
                mode: SettingsMode::Split { tree, .. },
            } = &mut state.mode
            {
                tree.borrow_mut().toggle_selected();
            }
        }
        return;
    }

    // Tab/BackTab leave Settings. The tab cycle is gone (spec D2: Tab now
    // moves pane focus, which is meaningless behind this screen), so the
    // legacy "cycle tabs" behaviour collapses to closing settings.
    if key.code == KeyCode::Tab || key.code == KeyCode::BackTab {
        state.mode = AppMode::List;
        return;
    }

    // Handle navigation keys — brief borrow
    if let AppMode::Settings {
        mode: SettingsMode::Split { tree, .. },
    } = &mut state.mode
    {
        let mut ts = tree.borrow_mut();
        match key.code {
            KeyCode::Up => ts.select_prev(&groups),
            KeyCode::Down => ts.select_next(&groups),
            KeyCode::Left | KeyCode::Right => {
                let (_, child) = ts.selected();
                if child.is_none() {
                    ts.toggle_selected();
                }
            }
            _ => {}
        }
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
            ("theme", "Theme", "Text"),
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
            ("fast_ping_concurrency", "Fast Ping Concurrency", "Number"),
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
/// Does NOT draw an outer block — the caller provides the inner area.
fn render_form_with_area(
    frame: &mut Frame,
    area: Rect,
    theme: &opaline::Theme,
    section: SettingsSection,
    fields: &[(String, String)],
    focus_index: usize,
    form_errors: &HashMap<String, String>,
) {
    let field_defs = form_field_defs_for_section(section);
    let mut y = area.y;
    let max_y = area.bottom();

    let label_w = ((f64::from(area.width) * 0.30) as u16).clamp(15, 25);
    let value_x = area.x + label_w + 2;
    let value_w = area.width.saturating_sub(label_w + 2);

    for (i, (key, label, field_type)) in field_defs.iter().enumerate() {
        if y >= max_y {
            break;
        }

        let is_focused = i == focus_index;
        let val = fields.get(i).map_or("", |(_, v)| v.as_str());

        // Label style
        let label_style = if is_focused {
            Style::default()
                .fg(theme.color("accent.primary").into())
                .bg(theme.color("bg.selection").into())
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.color("text.primary").into())
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(*label, label_style))),
            Rect::new(area.x, y, label_w, 1),
        );

        // Separator
        frame.render_widget(
            Paragraph::new(Line::from(Span::raw(":"))),
            Rect::new(area.x + label_w, y, 1, 1),
        );

        // Value display
        let display_val = field_type.strip_prefix("Select:").map_or_else(
            || {
                if *field_type == "Boolean" {
                    if val == "true" {
                        "[X]".into()
                    } else {
                        "[ ]".into()
                    }
                } else if val.is_empty() {
                    "(empty)".into()
                } else {
                    val.to_string()
                }
            },
            |_options_csv| format!("< {val} >"),
        );

        let input = Input::new("");
        let mut input_state = InputState::new();
        input_state.set_value(display_val);
        input_state.set_focused(is_focused);

        if let Some(error) = form_errors.get(*key) {
            input_state.set_validation(Some((ValidationKind::Error, error.clone())));
        }

        let has_error = u16::from(input_state.validation().is_some());
        let field_height = 2 + has_error;
        let field_area = Rect::new(value_x, y, value_w, field_height.min(max_y - y));
        frame.render_stateful_widget(&input, field_area, &mut input_state);
        y += field_height;
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
            if field_type.starts_with("Select:") {
                // Select types only respond to Left/Right, not character input
            } else if field_type == "Boolean" {
                val.clear();
                val.push_str(if val == "true" { "false" } else { "true" });
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
                let (_, ref mut val) = fields[*focus_index];
                val.pop();
            }
        }
        KeyCode::Enter => {
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
                // In Split mode, return focus to tree after saving
                if let AppMode::Settings {
                    mode: SettingsMode::Split { right, focus, .. },
                } = &mut state.mode
                {
                    *right = SplitRightPane::Empty;
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
            let def = field_defs[*focus_index];
            let field_type = def.2;
            if let Some(options_csv) = field_type.strip_prefix("Select:") {
                let options: Vec<&str> = options_csv.split(',').collect();
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
        KeyCode::Esc => {
            // Dirty form (spec P3): leaving without saving asks first.
            if form_is_dirty(state) {
                state.confirmation = Some(crate::ConfirmAction::DiscardSettings);
                return;
            }
            state.settings_form_snapshot = None;
            if let AppMode::Settings {
                mode: SettingsMode::Split { right, focus, .. },
            } = &mut state.mode
            {
                *right = SplitRightPane::Empty;
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
                mode: SettingsMode::Split { right, focus, .. },
            } = &mut state.mode
            {
                *right = SplitRightPane::Empty;
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
                mode:
                    SettingsMode::Split {
                        ref mut right,
                        ref mut focus,
                        ..
                    },
            } = state.mode
            {
                *right = SplitRightPane::Empty;
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
                val.clear();
                val.push_str(if val == "true" { "false" } else { "true" });
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
                let (_, ref mut val) = fields[*focus_index];
                val.pop();
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
    let list_area = Rect::new(area.x, area.y, area.width, area.height.saturating_sub(1));

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
        .show_paginator(false);
    let mut list_state = ListState::new(items.len());
    list_state.select(selected, items.len());
    frame.render_stateful_widget(list, list_area, &mut list_state);

    // Footer with action hints
    let footer_y = area.bottom().saturating_sub(1);
    let footer = Paragraph::new(Line::from(Span::styled(
        " [a] Add  [e] Edit  [d] Delete  [Ctrl+↑/↓] Reorder  [Esc] Back ",
        Style::default().fg(theme.color("text.muted").into()),
    )));
    frame.render_widget(footer, Rect::new(area.x, footer_y, area.width, 1));
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
        let name_str = format!(" {:<20}", self.name);
        let url_str = format!(" {:<40}", self.url);
        let status_str = format!(" {:<10}", self.status);
        let line = format!("{sel_mark}{name_str}{url_str}{status_str}");
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
    let list_area = Rect::new(area.x, area.y, area.width, area.height.saturating_sub(1));

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
        .show_paginator(false);
    let mut list_state = ListState::new(items.len());
    list_state.select(selected, items.len());
    frame.render_stateful_widget(list, list_area, &mut list_state);

    // Footer with action hints
    let footer_y = area.bottom().saturating_sub(1);
    let footer = Paragraph::new(Line::from(Span::styled(
        " [Space] Toggle select  [a] Add  [e] Edit  [d] Delete selected  [u] Update  [Esc] Back ",
        Style::default().fg(theme.color("text.muted").into()),
    )));
    frame.render_widget(footer, Rect::new(area.x, footer_y, area.width, 1));
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
                mode:
                    SettingsMode::Split {
                        ref mut right,
                        ref mut focus,
                        ..
                    },
            } = state.mode
            {
                *right = SplitRightPane::Empty;
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
mod tests {
    use super::handle_form_key;
    use crate::AppState;
    use crate::types::{AppMode, SettingsMode, SettingsSection, SplitFocus, SplitRightPane};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui_cheese::tree::TreeState;
    use std::cell::RefCell;
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
                tree: RefCell::new(TreeState::all_expanded(5)),
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
