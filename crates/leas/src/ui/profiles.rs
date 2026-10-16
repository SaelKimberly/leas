use leas_core::speed_test::TestType;
use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Widget};

use crate::ui::render_confirmation_overlay;
use crate::ui::theme::ThemeStyles;
use crate::ui::widgets::data_table::{
    Column, ColumnWidth, DataTable, DataTableRow, DataTableState, SortDirection,
};
use crate::{AppState, ConfirmAction, EndpointRow, format_relative_ts, format_ts, iso_to_flag};

// ── Display-row cache (part-2 runtime bounds) ────────────────────────────
//
// `build_display_rows` rebuilds a `Vec<DisplayRowData>` for the visible
// endpoint list every frame. Most frames' inputs are unchanged, so the rows
// are cached behind a fingerprint: structural `endpoints_gen`, the selection
// (`selected`/`selected_sub`), the connected protocol, the multi-select
// membership, each row's `expanded` flag — all cheap to compare — plus a
// dirty bitmask for the async inputs that mutate WITHOUT touching any of
// those. The bits are set by the mutation sites (`ops::events` handlers, the
// ping entry points); `build_display_rows` clears them on rebuild.

/// Rebuild because link traffic changed (a `StatsUpdate` delta landed).
pub(crate) const ROWS_DIRTY_TRAFFIC: u8 = 1 << 0;
/// Rebuild because test state changed (a `SpeedTestResult`/`TestTypeUpdate`
/// landed, or a single-ping entry point seeded `testing_details`).
pub(crate) const ROWS_DIRTY_TEST: u8 = 1 << 1;
/// Rebuild because enrichment changed (an `EndpointInfoUpdated` merge landed:
/// resolved IPs, country, outbound fields).
pub(crate) const ROWS_DIRTY_COUNTRY: u8 = 1 << 2;

/// One entry of the profiles display-row cache.
///
/// `Default` forces the first build: `gen` starts at `u64::MAX` so no real
/// `endpoints_gen` matches, and `rows` starts empty. The `expanded` vector is
/// per filtered row, compared membership-wise against the row list so a
/// single toggle invalidates without a per-row key.
pub struct DisplayRowsCache {
    pub gen_id: u64,
    pub selected_index: usize,
    pub selected_sub: Option<usize>,
    pub connected_protocol_id: Option<i64>,
    /// Sorted multi-select ids, compared membership-wise against the live set.
    pub multi_select: Vec<i64>,
    /// `expanded` flag per filtered row, in row order.
    pub expanded: Vec<bool>,
    /// Pending rebuild reasons (see `ROWS_DIRTY_*`).
    pub dirty: u8,
    /// The built rows. Behind an `Rc` so the per-frame hand-off to the
    /// renderer is a refcount bump, not a deep clone of every row's strings
    /// and sub-rows (`Rc::make_mut` still gives the selection patch its
    /// in-place path — it only copies when a previous frame's handle is
    /// somehow still alive).
    pub rows: std::rc::Rc<Vec<DisplayRowData>>,
}

impl Default for DisplayRowsCache {
    fn default() -> Self {
        Self {
            gen_id: u64::MAX,
            selected_index: usize::MAX,
            selected_sub: Some(usize::MAX),
            connected_protocol_id: Some(i64::MIN),
            multi_select: Vec::new(),
            expanded: Vec::new(),
            dirty: 0,
            rows: std::rc::Rc::new(Vec::new()),
        }
    }
}

/// Visible sub-rows inside an expanded endpoint panel. Longer variant lists
/// are windowed — the panel scrolls to follow the selected sub-row instead of
/// growing the row past the viewport (a 100-protocol endpoint used to blank
/// itself: its row was taller than the whole table).
const PANEL_MAX_ROWS: usize = 8;

/// Width of the single-row Protocol Info cell (`protocol/transport/security`).
const PROTOCOL_INFO_WIDTH: usize = 24;

/// Column the fixed sort arrow points at (D13): the page request orders by
/// `PageSort::Test`, which is column 7 in the §7 grid. Derived from the sort
/// the page asks for — not a second magic number.
const PROFILES_SORT_COLUMN: usize = 7;

/// One row of the expanded per-protocol sub-table inside an endpoint panel.
#[derive(Clone)]
struct PanelRow {
    /// "●" for the active protocol, "○" otherwise.
    marker: String,
    proto_id_hex: String,
    last_seen: String,
    last_used: String,
    /// Protocol kind (vmess, vless, …) — the endpoint-level Type column's
    /// value, which belongs to each protocol row.
    protocol_type: String,
    config_type: String,
    delay: String,
    speed: String,
    traffic: String,
    outbound: String,
    outbound_country: String,
    /// The stability ring as `successes/attempts` ("12/16"), or `—` when the
    /// link has no samples yet (spec `2026-10-09-stab-bin-design` §8). The
    /// ratio is the readable form of the ordering's `stab_bin`: it must be
    /// checkable against where the row sits, which a glyph would not be.
    stab: String,
}

/// A single-line endpoint row.
///
/// The expanded sub-table is drawn inside the row's own height
/// (`1 + panel_rows + 4`) by `render_expansion_panel`. `Clone` backs the
/// display-row cache's hit path. `pub` because the cache (and thus this row
/// type) lives on the crate-`pub` `AppState`.
#[derive(Clone)]
pub struct DisplayRowData {
    indicator: String,
    indicator_fg: Style,
    /// `{:08x}` of the representative link's protocol id; `*` when the row is
    /// multi-selected (D9/D10 — the marker replaces the id, both padded to 8).
    id_hex: String,
    /// Inbound flag cell: `<flag>-<ISO>` or bare `<ISO>`, `—` unknown (D14).
    inbound_flag: String,
    /// Host only (elided when the subdomain overflows); the port moved to its
    /// own column (spec §7).
    address_str: String,
    /// Right-aligned port (spec §7 col 5).
    port_str: String,
    /// Whitelist tokens `SNI` / `CIDR` / `SNI+CIDR` / `—` (9 cells).
    white_str: String,
    /// `protocol/transport/security` single-row cell (the braces around it
    /// come from the neighbouring decoration columns).
    protocol_info_str: String,
    /// `[ 12 ]`-style Test cell: `[value]` where value is 4 cells wide,
    /// or the red `[name]`/`[fast]`/`[real]` problem labels, or blank.
    test_str: String,
    test_style: Style,
    outbound_addr: String,
    /// Exit flag cell (D14): `<flag>-<ISO>` or bare `<ISO>`, `—` unknown.
    outbound_flag: String,
    /// `+` collapsed / `-` expanded, drawn accent-bold one cell before the
    /// host (D11); `' '` when the endpoint has no variants. Carries the
    /// expandability fact that used to live in a separate `has_sub_rows` flag.
    expand_prefix: char,
    expanded: bool,
    row_style: Style,
    /// Per-column colour map (spec D12): one style per styled column.
    id_style: Style,
    address_style: Style,
    port_style: Style,
    white_style: Style,
    protocol_style: Style,
    prefix_style: Style,
    panel_selected_style: Style,
    panel_selected: Option<usize>,
    panel_ips: String,
    panel_resolve_hint: bool,
    panel_rows: Vec<PanelRow>,
}

impl DataTableRow for DisplayRowData {
    fn render(
        &self,
        col_xs: &[u16],
        col_widths: &[u16],
        col_order: &[usize],
        buf: &mut Buffer,
        y: u16,
        clip_bottom: u16,
    ) {
        // A row that starts past the clip line has nothing visible to draw.
        if y >= clip_bottom {
            return;
        }
        for (i, &x) in col_xs.iter().enumerate() {
            // Match by LOGICAL column id: width-aware drops hide trailing
            // columns without shifting another column's meaning.
            let logical = col_order.get(i).copied().unwrap_or(i);
            let (text, style) = match logical {
                0 => (self.indicator.as_str(), self.indicator_fg),
                1 => (self.id_hex.as_str(), self.id_style),
                2 => (self.inbound_flag.as_str(), self.row_style),
                3 => (self.address_str.as_str(), self.address_style),
                4 => (self.port_str.as_str(), self.port_style),
                5 => (self.white_str.as_str(), self.white_style),
                6 => (self.protocol_info_str.as_str(), self.protocol_style),
                7 => (self.test_str.as_str(), self.test_style),
                8 => (self.outbound_flag.as_str(), self.row_style),
                9 => (self.outbound_addr.as_str(), self.address_style),
                _ => ("", self.row_style),
            };
            let max_w = col_widths.get(i).copied().unwrap_or(0) as usize;
            if logical == 3 {
                // The `+`/`-` marker takes the first cell; the host starts one
                // cell in and is one cell narrower (D11), elided by §8.
                if self.expand_prefix != ' ' {
                    buf.set_stringn(
                        x,
                        y,
                        self.expand_prefix.encode_utf8(&mut [0u8; 4]),
                        1,
                        self.prefix_style,
                    );
                }
                let host_w = max_w.saturating_sub(1);
                let host = truncate_host(text, host_w);
                buf.set_stringn(x + 1, y, &host, host_w, style);
            } else {
                buf.set_stringn(x, y, text, max_w, style);
            }
        }

        if self.expanded {
            let total_w: u16 = col_widths.iter().sum();
            // Panel is 2 lines shorter than the row: it starts one line below
            // the endpoint and leaves one blank line (gap) after its bottom
            // border so it never touches the next row.
            self.render_expansion_panel(
                buf,
                col_xs[0],
                y + 1,
                self.height(0) - 2,
                total_w,
                self.row_style,
                clip_bottom,
            );
        }
    }

    fn height(&self, _available_width: u16) -> u16 {
        if self.expanded {
            // 1 endpoint line + panel (top border + IPs + separator + up to
            // PANEL_MAX_ROWS sub rows + bottom border) + 1 gap line after the
            // panel. The cap keeps a long variant list from growing the row
            // past the viewport.
            1 + self.panel_rows.len().min(PANEL_MAX_ROWS) as u16 + 4 + 1
        } else {
            1
        }
    }
}

impl DisplayRowData {
    /// Rounded panel under the endpoint line: IPs line, separator, sub-table.
    /// `panel_w` is the table's actual rendered width (viewport-capped) so the
    /// panel never exceeds the buffer. The panel is clipped to `clip_bottom`:
    /// an expanded row taller than the viewport must not write past it.
    fn render_expansion_panel(
        &self,
        buf: &mut Buffer,
        x0: u16,
        y0: u16,
        panel_height: u16,
        panel_w: u16,
        row_style: Style,
        clip_bottom: u16,
    ) {
        let visible_h = clip_bottom.saturating_sub(y0);
        if visible_h == 0 {
            return;
        }
        let panel_height = panel_height.min(visible_h);
        let rect = Rect {
            x: x0,
            y: y0,
            width: panel_w,
            height: panel_height,
        };
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .render(rect, buf);

        let inner_x = x0 + 1;
        let inner_w = (panel_w - 2) as usize;

        // IPs line (y0+1 is inside the top border)
        if y0 + 1 < clip_bottom {
            let ips_text = format!(" IPs: {}", self.panel_ips);
            buf.set_stringn(inner_x, y0 + 1, &ips_text, inner_w, row_style);
            if self.panel_resolve_hint {
                let hint = "(x resolve)";
                let hx = inner_x + (inner_w.saturating_sub(hint.len())) as u16;
                buf.set_stringn(hx, y0 + 1, hint, hint.len(), row_style);
            }
        }

        // Sub-table geometry: window the variant list to PANEL_MAX_ROWS and
        // follow the selected sub-row, so a long list scrolls instead of
        // growing the panel past the viewport.
        let total = self.panel_rows.len();
        let visible = total.min(PANEL_MAX_ROWS);
        let win = panel_window(total, self.panel_selected, PANEL_MAX_ROWS);

        // Separator
        if y0 + 2 < clip_bottom {
            let sep_x = inner_x;
            let sep_y = y0 + 2;
            let sep_line = "─".repeat(inner_w);
            buf.set_stringn(sep_x, sep_y, &sep_line, inner_w, Style::default());
            if total > visible {
                // Windowed: the separator carries the visible range (rows N-M
                // of T) so the panel signals the rows scrolled out of view.
                let label = format!(" {}-{}/{} ", win + 1, win + visible, total);
                let lx = inner_x + (inner_w.saturating_sub(label.len())) as u16;
                buf.set_stringn(lx, sep_y, &label, label.len(), row_style);
            }
        }

        // Sub-table rows. last_used is relative ("2d ago"/"never"); the
        // protocol-type column precedes config (transport/security). Offsets
        // are absolute within the panel interior — the untouched cell after
        // config (68) and the one in outbound's 16th cell are deliberate gaps
        // so a clipped/full-width value never blends into the next column.
        let cols: [(usize, usize); 12] = [
            (0, 3),   // marker
            (3, 9),   // id
            (12, 20), // last_seen
            (32, 11), // last_used (relative)
            (43, 11), // protocol type
            (54, 14), // config (transport/security)
            (69, 8),  // delay (1-cell gap after config)
            (77, 7),  // speed
            (84, 10), // traffic
            (94, 16), // outbound (1-cell gap before country)
            (110, 5), // country
            (115, 7), // stability (successes/attempts)
        ];
        for n in 0..visible {
            let pr = &self.panel_rows[win + n];
            let selected = self.panel_selected == Some(win + n);
            let y = y0 + 3 + n as u16;
            if y >= clip_bottom {
                break;
            }
            let style = if selected {
                self.panel_selected_style
            } else {
                row_style
            };
            if selected {
                // Reverse highlight across the ENTIRE sub-row width: replace
                // the panel's highlight background (painted by the DataTable
                // over the selected endpoint row) with the common background,
                // not just over written glyphs — column gaps would keep the
                // highlight otherwise.
                for x in inner_x..(inner_x + inner_w as u16) {
                    buf[(x, y)].set_style(style);
                }
            }
            let cell_texts = [
                pr.marker.as_str(),
                pr.proto_id_hex.as_str(),
                pr.last_seen.as_str(),
                pr.last_used.as_str(),
                pr.protocol_type.as_str(),
                pr.config_type.as_str(),
                pr.delay.as_str(),
                pr.speed.as_str(),
                pr.traffic.as_str(),
                pr.outbound.as_str(),
                pr.outbound_country.as_str(),
                pr.stab.as_str(),
            ];
            for ((off, w), text) in cols.iter().zip(cell_texts.iter()) {
                buf.set_stringn(inner_x + *off as u16, y, text, *w, style);
            }
        }
    }
}

pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let rows: Vec<&EndpointRow> = state.filtered_profiles().collect();
    let selected = state.selected_index;
    let theme = state.theme();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    render_filter_strip(frame, chunks[0], state, theme);

    // Empty state guidance
    if rows.is_empty() {
        let msg = if state.filtered_len() == 0 && state.endpoints.is_empty() {
            " No profiles — press 'a' to add one "
        } else if state.filtered_len() == 0 {
            " No profiles match the current filter "
        } else {
            unreachable!()
        };
        let paragraph = Paragraph::new(msg)
            .style(ThemeStyles::hint(theme))
            .alignment(Alignment::Center);
        frame.render_widget(paragraph, chunks[1]);
        render_footer(frame, chunks[2], state, theme);
        return;
    }

    // One display row per endpoint; the expanded panel lives inside the row.
    let display_rows = build_display_rows(&rows, selected, state, theme);

    render_data_grid(frame, chunks[1], &display_rows, selected, state, theme);
    render_footer(frame, chunks[2], state, theme);
    render_confirmation_overlays(frame, area, &rows, state);
}

const fn test_glyph(test_type: TestType) -> &'static str {
    match test_type {
        TestType::TcpPing => "↔",
        TestType::RealPing => "◎",
        TestType::SpeedTest => "⇩",
        TestType::UdpTest => "↗",
    }
}

/// Latency thresholds for the Test column: green below the warning threshold,
/// yellow at/above it, red at/above the error threshold.
const TEST_WARN_MS: i32 = 500;
const TEST_BAD_MS: i32 = 1000;

/// Compute the Test cell for one endpoint row: `[value]` with the last
/// measured delay, colored by magnitude, or the red problem labels — `[name]`
/// when the DNS name could not be resolved, `[real]`/`[fast]` when the link has
/// no clean measurement left.
///
/// The cell describes the endpoint's REPRESENTATIVE link
/// ([`EndpointRow::representative_link_index`] — the minimum of the
/// decision-16 key, the same link `compute_rank` stores the endpoint's stored
/// tier from). Selecting by `active_link()` instead (the lowest-delay MEASURED
/// link, error-blind) let a marker render on a row the ordering law had placed
/// in a measurement band: for a link with a fast latency plus a real failure
/// beside a sibling still measured clean, the cell showed `[real]` while the
/// endpoint's own tier was 1. With the representative link the cell's content
/// and the row's tier band come from one fact, so they cannot disagree.
///
/// Precedence follows the tier model (decision 16): real-err (3) ranks above
/// fast-err (4) — when both marker classes are present the deeper real check
/// wins — and DNS-unresolved (5) is the deepest, so `[name]` beats both.
fn compute_test_cell(row: &EndpointRow, resolved: bool, theme: &opaline::Theme) -> (String, Style) {
    use leas_db::models::ProfileErr;
    let representative = row
        .representative_link_index(!resolved)
        .and_then(|i| row.links.get(i));
    let representative_error = representative.and_then(|l| l.error.as_ref());
    // A "not testable by the native engine" marker is a STATUS, not a failed
    // measurement, so it outranks a stored delay (see `test_cell_content`).
    let untestable = representative_error.is_some_and(crate::ops::ping::is_untestable_marker);
    // A purge verdict is a STATUS too, and the same precedence applies: the
    // delay a purged link still carries is the phase-1 result of a row the
    // classifier has already judged (spec §9). Reachable only when every link
    // is purged — the representative of an endpoint that still has a live link
    // is that live link, because tier 6 sits below every live band.
    let purged = representative.and_then(|l| l.purge_reason).map(purge_label);
    let failure = match representative_error.map(|e| e.kind) {
        Some(ProfileErr::Real | ProfileErr::Name) => Some(TestFailure::Real),
        Some(ProfileErr::Fast) => Some(TestFailure::Fast),
        None => None,
    };
    let delay = representative.and_then(|l| match l.latency {
        Some(
            leas_db::models::Latency::Real { delay, .. } | leas_db::models::Latency::Fast { delay },
        ) => Some(delay),
        None => None,
    });
    // The approximation marker: `~` says the verdict beside it was produced by a
    // SUBSTITUTED ClientHello — the link asked for a fingerprint with no roster
    // row, so the engine probed with its default. It is a provenance note about
    // the measurement, so it appends to whatever the cell already shows instead
    // of displacing it.
    //
    // Scoped to the REPRESENTATIVE link's own protocol, never "the endpoint has
    // an unrosterable `fp` somewhere": a `Protocol` row is shared across
    // endpoints (identity excludes host/port) and an endpoint carries several
    // links, so an endpoint-level predicate would mark a verdict that came from
    // a roster-mapped sibling — destroying the one thing the marker means.
    let approximated = representative
        .and_then(|l| row.protocols.get(&l.protocol_id))
        .is_some_and(|p| {
            // The `security_fp` COLUMN, not the deferred config: the column is
            // what the page query projects, so the label needs no config load.
            leas_native::security::fingerprint::resolve_fingerprint(p.security.fp.as_deref()).1
        });
    let (mut text, style) = test_cell_content(
        row.endpoint.is_dns(),
        resolved,
        untestable,
        purged,
        failure,
        delay,
        theme,
    );
    if approximated {
        text.push('~');
    }
    (text, style)
}

/// The short name a purged link shows in place of its Test-cell content.
///
/// A purge is a statement about the row, so it outranks the delay the link
/// still carries from phase 1 — exactly as the untestable marker does. Exact
/// strings are presentation; the precedence rule is not.
#[must_use]
const fn purge_label(reason: leas_db::models::PurgeReason) -> &'static str {
    use leas_db::models::PurgeReason;
    match reason {
        PurgeReason::RealityFallback => "mitm",
        PurgeReason::CertificateMismatch => "cert",
        PurgeReason::CertificateExpired => "expired",
        PurgeReason::NotTls => "notls",
        PurgeReason::ConfigInvalid => "cfg",
        PurgeReason::TransportRejected => "http",
        PurgeReason::OriginUnreachable => "origin",
    }
}

/// Test-failure tier for one row. Real outranks fast in the label
/// precedence (decision 16), so the two failure markers collapse into a
/// single value — `Real` when the real check failed, else `Fast`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TestFailure {
    Real,
    Fast,
}

/// Pure Test-cell logic (no `AppState`) so the label precedence and color
/// thresholds are unit-testable.
fn test_cell_content(
    host_is_dns: bool,
    resolved: bool,
    untestable: bool,
    purged: Option<&str>,
    failure: Option<TestFailure>,
    active_delay: Option<i32>,
    theme: &opaline::Theme,
) -> (String, Style) {
    let bad = ThemeStyles::test_delay_bad(theme);
    if host_is_dns && !resolved {
        return (format!("[{}]", center_cell("name", 4)), bad);
    }
    if untestable {
        // The native engine cannot test this row: the marker is a status about
        // the row, not a failed attempt, so it outranks a stored delay the same
        // way `[name]` does. It renders as `[real]` (the persisted kind is
        // `ProfileErr::Real` — the frozen `error_kind` CHECK leaves no other
        // kind to store).
        return (format!("[{}]", center_cell("real", 4)), bad);
    }
    if let Some(label) = purged {
        // Only reachable when every link of the endpoint is purged (the Active
        // view does not load a purged link beside a live one), so this is the
        // Purgatory/All row: the verdict is what the row IS.
        return (format!("[{}]", center_cell(label, 4)), bad);
    }
    // A failure marker outranks the link's OWN measurement. A failed real
    // probe keeps its fast latency in `profile_stats` (`apply_test_result`
    // preserves the measurement when it writes a marker), so rendering that
    // delay would present a failed profile as a working one — and the
    // ordering law already ranks the same link in an error tier
    // (`RankLink::key` lets `error_kind` force tier 3/4), so a delay here
    // made the cell and the sort key two different laws. Tier ordering
    // (decision 16): real-err ranks above fast-err — the real check is the
    // deeper probe, so when both classes failed `[real]` wins.
    let failure_label = match failure {
        Some(TestFailure::Real) => Some("real"),
        Some(TestFailure::Fast) => Some("fast"),
        None => None,
    };
    if let Some(label) = failure_label {
        return (format!("[{}]", center_cell(label, 4)), bad);
    }
    match active_delay {
        Some(d) if d >= 0 => {
            let style = if d >= TEST_BAD_MS {
                bad
            } else if d >= TEST_WARN_MS {
                ThemeStyles::test_delay_warn(theme)
            } else {
                ThemeStyles::test_delay_ok(theme)
            };
            (format!("[{}]", center_cell(&d.to_string(), 4)), style)
        }
        _ => (" ".repeat(6), Style::default()),
    }
}

/// The panel's stability cell: `successes/attempts` from the link's ring, or
/// `—` when it has no samples yet (spec `2026-10-09-stab-bin-design` §8).
///
/// Numeric, not a glyph: the ratio is the readable form of the ordering's
/// `stab_bin` and must be checkable against where the row sits. The neutral
/// "no data" marker is deliberately not `0/0` — that reads as a measured zero.
fn stability_ratio(link: &leas_db::models::ProfileStats) -> String {
    let len = u8::try_from(
        link.stab_len
            .clamp(0, i64::from(leas_db::endpoint_rank::STAB_WINDOW)),
    )
    .unwrap_or(0);
    if len == 0 {
        return "—".to_string();
    }
    let successes = leas_db::endpoint_rank::stab_successes(link.stab_mask.cast_unsigned(), len);
    format!("{successes}/{len}")
}

/// Row-number cell: a 6-cell right-aligned slot plus a trailing gap cell
/// (carrying the multi-select `*`) — room for 100000+ profiles without the
/// number bleeding into the next column.
/// Row id cell (D9/D10): `{:08x}` of the representative link's protocol id —
/// the same link the Test cell describes, so ID and Test never disagree.
/// Multi-selected rows print `*` instead, mirroring `index_cell`'s old law
/// (marker replaces the number, widths equal).
fn link_id_cell(row: &EndpointRow, dns_unresolved: bool, is_multi: bool) -> String {
    if is_multi {
        // The marker replaces the id, both padded to 8 — the same equal-width
        // law `index_cell` used for the number slot.
        return format!("{:>8}", "*");
    }
    row.representative_link_index(dns_unresolved)
        .and_then(|idx| row.links.get(idx))
        .map_or_else(String::new, |l| {
            format!("{:08x}", l.protocol_id.get() as u32)
        })
}

/// Flag cell (D14): `<flag emoji>-<ISO>` (5 cells) when the terminal renders
/// regional-indicator emoji, bare `<ISO>` (2) when it does not. Unknown
/// country = `—`.
fn flag_cell(iso: Option<&str>, flags_ok: bool) -> String {
    match iso {
        Some(iso) if flags_ok => truncate_pad(&format!("{}-{iso}", iso_to_flag(iso)), 5),
        Some(iso) => truncate_pad(iso, 5),
        None => "—".to_string(),
    }
}

/// Whitelist token cell (spec §7 col 6): `SNI` / `CIDR` / `SNI+CIDR` / `—`,
/// 9 cells — the longest token sets the width (D8). The DNS-unresolved flag
/// is gone: the Test cell's `[name]` marker already carries that fact.
fn white_cell(cidr: bool, sni: bool) -> String {
    let token = match (sni, cidr) {
        (true, true) => "SNI+CIDR",
        (true, false) => "SNI",
        (false, true) => "CIDR",
        (false, false) => "—",
    };
    truncate_pad(token, 9)
}

/// Host cell (spec §8): a DNS name whose subdomain overflows keeps the
/// registrable domain intact and elides the subdomain's tail
/// (`verylongsub….example.com`). IP literals and overflowed hosts plain
/// right-truncate with a trailing `…`.
fn truncate_host(host: &str, width: usize) -> String {
    use unicode_width::UnicodeWidthStr;
    if host.width() <= width {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').collect();
    let dns_name = labels.len() > 2 && labels.iter().all(|l| !l.is_empty());
    if dns_name {
        let domain = labels[labels.len() - 2..].join(".");
        let suffix = format!("….{domain}");
        let budget = width.saturating_sub(suffix.width());
        if budget >= 1 {
            let mut out: String = host.chars().take(budget).collect();
            out.push_str(&suffix);
            return out;
        }
    }
    // IP literal (or a pathological name): right-truncate with an ellipsis.
    let mut out: String = host.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Does this terminal render regional-indicator (flag) emoji? Probed once:
/// `LEAS_NO_FLAGS`/`NO_EMOJI` force the bare-ISO fallback, a UTF-8 locale gets
/// the emoji form, anything else (ASCII locale, dumb term) gets bare ISO.
fn flags_supported() -> bool {
    use std::sync::OnceLock;
    static FLAGS: OnceLock<bool> = OnceLock::new();
    *FLAGS.get_or_init(|| {
        let disabled =
            std::env::var_os("LEAS_NO_FLAGS").is_some() || std::env::var_os("NO_EMOJI").is_some();
        if disabled {
            return false;
        }
        ["LC_ALL", "LANG", "LC_CTYPE"]
            .iter()
            .filter_map(|k| std::env::var(k).ok())
            .any(|v| v.to_ascii_uppercase().contains("UTF-8"))
    })
}

/// Single-row Protocol Info cell: `protocol/transport/security` (e.g.
/// `vless/tcp/reality`), centered in the fixed-width slot. A row without an
/// active protocol renders the `-` placeholder.
fn protocol_info_cell(row: &EndpointRow) -> String {
    let info = row.active_protocol().map_or_else(
        || "-".to_string(),
        |(_, p)| {
            format!(
                "{}/{}/{}",
                p.proto_kind,
                p.transport.r#type.as_str(),
                p.security.r#type.as_str()
            )
        },
    );
    center_pad(&info, PROTOCOL_INFO_WIDTH)
}

/// Recompute the selection-dependent fields of one cached display row.
///
/// Everything else in [`DisplayRowData`] is independent of the selection, which
/// is what lets a selection move patch two rows instead of rebuilding the list.
fn restyle_row(
    row: &mut DisplayRowData,
    index: usize,
    selected: usize,
    state: &AppState,
    theme: &opaline::Theme,
    source: &EndpointRow,
) {
    let is_connected = state.connected_protocol_id.as_ref() == Some(&source.endpoint.id.get());
    row.row_style = match (index == selected, is_connected) {
        (true, true) => ThemeStyles::table_row_connected(theme)
            .add_modifier(ratatui::style::Modifier::UNDERLINED),
        (false, true) => ThemeStyles::table_row_connected(theme),
        (true, false) => ThemeStyles::table_row_selected(theme),
        (false, false) => ThemeStyles::table_row_normal(theme),
    };
    row.panel_selected = if index == selected {
        state.selected_sub
    } else {
        None
    };
}

fn build_display_rows(
    rows: &[&EndpointRow],
    selected: usize,
    state: &AppState,
    theme: &opaline::Theme,
) -> std::rc::Rc<Vec<DisplayRowData>> {
    // Cache check (part-2 runtime bounds): reuse the previous frame's rows
    // when every input is unchanged — structural gen, the selection,
    // connection, multi-select membership, per-row expansion, and the async
    // dirty bits. All comparisons are reference/flag reads; the only per-row
    // work on a hit is the `expanded` zip.
    let mut cache = state.display_rows_cache.borrow_mut();
    // The cache key deliberately EXCLUDES the selection: only the selected row
    // and the previously selected one carry selection-dependent styling, so a
    // PgUp/PgDn/Home/End move patches two rows instead of rebuilding 40k of
    // them (~160 ms per keypress at the reported scale).
    let structurally_cached = !cache.rows.is_empty()
        && cache.gen_id == state.endpoints_gen
        && cache.connected_protocol_id == state.connected_protocol_id
        && cache.dirty == 0
        && cache.multi_select.len() == state.multi_select.len()
        && cache
            .multi_select
            .iter()
            .all(|id| state.multi_select.contains(id))
        && cache.expanded.len() == rows.len()
        && cache
            .expanded
            .iter()
            .zip(rows.iter())
            .all(|(c, r)| *c == r.expanded);
    if structurally_cached {
        let selection_changed =
            cache.selected_index != selected || cache.selected_sub != state.selected_sub;
        if selection_changed {
            let previous = cache.selected_index;
            let cached_rows = std::rc::Rc::make_mut(&mut cache.rows);
            for index in [previous, selected] {
                if index < rows.len()
                    && let Some(row) = cached_rows.get_mut(index)
                {
                    restyle_row(row, index, selected, state, theme, rows[index]);
                }
            }
            cache.selected_index = selected;
            cache.selected_sub = state.selected_sub;
        }
        return cache.rows.clone();
    }

    let mut result = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let is_connected = state.connected_protocol_id.as_ref() == Some(&row.endpoint.id.get());
        let base_style = match (i == selected, is_connected) {
            (true, true) => ThemeStyles::table_row_connected(theme)
                .add_modifier(ratatui::style::Modifier::UNDERLINED),
            (false, true) => ThemeStyles::table_row_connected(theme),
            (true, false) => ThemeStyles::table_row_selected(theme),
            (false, false) => ThemeStyles::table_row_normal(theme),
        };

        // Indicator: connected → ●; else active protocol's test glyph; else the
        // first protocol under test.
        let (indicator, indicator_fg) = if is_connected {
            ("●".to_string(), ThemeStyles::success(theme))
        } else {
            let active_id = row.active_link().map(|l| l.protocol_id.get());
            let glyph = active_id
                .and_then(|id| {
                    state
                        .testing_details
                        .get(&(row.endpoint.id.get(), id))
                        .copied()
                        .map(test_glyph)
                })
                .or_else(|| {
                    row.links.iter().find_map(|l| {
                        state
                            .testing_details
                            .get(&(row.endpoint.id.get(), l.protocol_id.get()))
                            .copied()
                            .map(test_glyph)
                    })
                });
            glyph.map_or_else(
                || (String::new(), Style::default()),
                |g| (g.to_string(), Style::default()),
            )
        };

        let is_multi = state.multi_select.contains(&row.endpoint.id.get());

        // Row id: the representative link's hex id, or `*` under multi-select
        // (D9/D10).
        let dns_unresolved = crate::ops::profiles::endpoint_dns_unresolved(state, row);
        let id_hex = link_id_cell(row, dns_unresolved, is_multi);

        let info = state.endpoint_info.get(&row.endpoint.id.get());
        // One resolution source: the loaded row's persisted addresses — the
        // same fact the ordering law's DNS band is computed from
        // (`endpoint_rank::dns_unresolved`). Reading the in-memory cache here
        // made `[name]` and the tier-5 band two different answers for the same
        // endpoint, which is what let a row show `[name]` beside a live exit IP.
        let resolved = !crate::ops::profiles::endpoint_dns_unresolved(state, row);

        let inbound_flag = flag_cell(info.and_then(|i| i.country.as_deref()), flags_supported());
        // Host (raw): the Address column truncates at draw time (§8) so a
        // width-shrunk column still elides the subdomain instead of
        // hard-clipping through the domain.
        let address_str = row.endpoint.display_host(&row.resolved_ips);
        let port_str = format!("{:>6}", row.endpoint.port);
        // Whitelist tokens (spec §7 col 6); the DNS-unresolved flag moved to
        // the Test cell's `[name]` marker, which already carried it.
        let white_str = white_cell(
            info.is_some_and(|i| {
                i.host_features.ip_whitelisted || i.host_features.cidr_whitelisted
            }),
            info.and_then(|i| i.sni_whitelisted).unwrap_or(false),
        );
        let (test_str, test_style) = compute_test_cell(row, resolved, theme);

        let protocol_info_str = protocol_info_cell(row);

        // Exit IP: the ACTIVE link's persisted real-ping IP wins (survives
        // reruns); endpoint_info is the live-enrich fallback. Country comes
        // from the per-IP mmdb cache (seeded at load + on ping).
        //
        // Both columns are gated on the endpoint being RESOLVED: the exit IP is
        // evidence that a tunnel to this endpoint worked, and a DNS host whose
        // name has never resolved — or whose resolution failed — must not
        // assert one. Without the gate a feed batch (which persists `latency_ip`
        // for every planned link) rendered `[name]` beside a live exit IP for
        // every endpoint outside the loaded page.
        let active_outbound_ip = row.active_link().and_then(|l| match &l.latency {
            Some(leas_db::models::Latency::Real { ip: Some(ip), .. }) => Some(ip.clone()),
            _ => None,
        });
        let persisted_outbound = active_outbound_ip
            .clone()
            .or_else(|| info.and_then(|i| i.outbound_ip.map(|ip| ip.to_string())));
        let enriched_country = active_outbound_ip
            .as_deref()
            .and_then(|ip| state.outbound_country_for(ip))
            .or_else(|| info.and_then(|i| i.outbound_country.clone()));
        // The gate: an unresolved endpoint asserts no exit IP.
        let (persisted_outbound, enriched_country) = if resolved {
            (persisted_outbound, enriched_country)
        } else {
            (None, None)
        };
        let outbound_addr =
            truncate_pad(&persisted_outbound.unwrap_or_else(|| "—".to_string()), 14);
        let outbound_flag = flag_cell(enriched_country.as_deref(), flags_supported());

        // Panel content
        let panel_ips = info
            .map(|i| {
                i.resolved_ips
                    .iter()
                    .map(|ip| format!("[{ip}]"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let (panel_ips, panel_resolve_hint) = if panel_ips.is_empty() {
            if row.endpoint.is_dns() {
                ("[?]".to_string(), true)
            } else {
                (panel_ips, false)
            }
        } else {
            (panel_ips, false)
        };

        let panel_rows: Vec<PanelRow> = if row.expanded {
            let active_id = row.active_link().map(|l| l.protocol_id);
            row.links
                .iter()
                .map(|link| {
                    let proto = row.protocols.get(&link.protocol_id);
                    let delay = match (link.purge_reason, &link.latency) {
                        // The verdict replaces the numbers: the delay is
                        // phase 1's, on a link the classifier has retired.
                        (Some(reason), _) => format!("[{}]", purge_label(reason)),
                        (
                            None,
                            Some(
                                leas_db::models::Latency::Real { delay, .. }
                                | leas_db::models::Latency::Fast { delay },
                            ),
                        ) => format!("{delay}ms"),
                        (None, None) => "-".to_string(),
                    };
                    let speed = link
                        .speed_bps
                        .map_or_else(|| "-".to_string(), |s| format_traffic(s as u64));
                    let traffic = {
                        let total = link.traffic.total_down + link.traffic.total_up;
                        if total == 0 {
                            "-".to_string()
                        } else {
                            format_traffic(total as u64)
                        }
                    };
                    let (outbound, outbound_country) = link
                        .latency
                        .as_ref()
                        .and_then(|l| match l {
                            // Latency::Real.ip is the persisted exit IP
                            // (events.rs stores the bare IP; country comes
                            // from the mmdb cache seeded at load + on ping).
                            leas_db::models::Latency::Real { ip, .. } => ip.clone(),
                            leas_db::models::Latency::Fast { .. } => None,
                        })
                        .map_or_else(
                            || ("—".to_string(), "—".to_string()),
                            |ip| {
                                let country = state.outbound_country_for(&ip).map_or_else(
                                    || "—".to_string(),
                                    |iso| format!("{} {iso}", iso_to_flag(&iso)),
                                );
                                (ip, country)
                            },
                        );
                    let (t, s) = proto.map_or((None, None), |p| {
                        (
                            Some(p.transport.r#type.as_str()),
                            Some(p.security.r#type.as_str()),
                        )
                    });
                    let config_type = match (t, s) {
                        (None, None) => "-".to_string(),
                        (t, s) => {
                            let base = format!("{}/{}", t.unwrap_or("-"), s.unwrap_or("-"));
                            // `~` marks a substituted ClientHello. The panel row
                            // IS one link, so this is per-link by construction —
                            // the same predicate the endpoint Test cell applies to
                            // its representative, so the two surfaces cannot
                            // disagree about what "approximated" means.
                            if proto.is_some_and(|p| {
                                leas_native::security::fingerprint::resolve_fingerprint(
                                    p.security.fp.as_deref(),
                                )
                                .1
                            }) {
                                format!("{base}~")
                            } else {
                                base
                            }
                        }
                    };
                    let protocol_type =
                        proto.map_or_else(|| "-".to_string(), |p| p.proto_kind.to_string());
                    PanelRow {
                        marker: if Some(link.protocol_id) == active_id {
                            "●".to_string()
                        } else {
                            "○".to_string()
                        },
                        proto_id_hex: format!("{:08x}", link.protocol_id.get() as u32),
                        last_seen: format_ts(link.last_seen_at),
                        last_used: link
                            .last_used_at
                            .map_or_else(|| "never".to_string(), format_relative_ts),
                        protocol_type,
                        config_type,
                        delay,
                        speed,
                        traffic,
                        outbound,
                        outbound_country,
                        stab: stability_ratio(link),
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        result.push(DisplayRowData {
            indicator,
            indicator_fg,
            id_hex,
            inbound_flag,
            address_str,
            port_str,
            white_str,
            protocol_info_str,
            test_str,
            test_style,
            outbound_addr,
            outbound_flag,
            expand_prefix: if row.links.len() > 1 {
                if row.expanded { '-' } else { '+' }
            } else {
                ' '
            },
            expanded: row.expanded,
            row_style: base_style,
            id_style: ThemeStyles::hint(theme),
            address_style: ThemeStyles::footer_value(theme),
            port_style: ThemeStyles::hint(theme),
            white_style: ThemeStyles::hint(theme),
            protocol_style: ThemeStyles::footer_value(theme),
            prefix_style: ThemeStyles::container_title(theme).add_modifier(Modifier::BOLD),
            panel_selected_style: ThemeStyles::panel_row_selected(theme),
            panel_selected: if i == selected {
                state.selected_sub
            } else {
                None
            },
            panel_ips,
            panel_resolve_hint,
            panel_rows,
        });
    }
    // Store the rebuild: fingerprint + rows. The dirty bits are cleared here
    // (a rebuild is the reset point; mutation sites re-set them on the next
    // change). The multi-select projection is sorted for cheap membership
    // comparison on the next frame.
    cache.gen_id = state.endpoints_gen;
    cache.selected_index = selected;
    cache.selected_sub = state.selected_sub;
    cache.connected_protocol_id = state.connected_protocol_id;
    cache.multi_select = state.multi_select.iter().copied().collect();
    cache.multi_select.sort_unstable();
    cache.expanded = rows.iter().map(|r| r.expanded).collect();
    cache.dirty = 0;
    cache.rows = std::rc::Rc::new(result);
    std::rc::Rc::clone(&cache.rows)
}

fn render_data_grid(
    frame: &mut Frame,
    area: Rect,
    display_rows: &[DisplayRowData],
    selected_display_idx: usize,
    state: &AppState,
    theme: &opaline::Theme,
) {
    // Pane 1 supplies the frame (spec §6): the table renders frameless, inset
    // one cell per side to preserve the geometry the old Block's border gave.

    // 10 columns (spec §7): status, ID, Flag, Address, Port, White, Protocol,
    // Test, Out, Exit. No decorative bracket or glyph cells; every label
    // carries the header role.
    let header_style = ThemeStyles::table_header(theme);
    // Width-aware drop (tui-polish D7, re-derived for the §7 grid): the inner
    // width decides which columns survive. `Test` is protected — a row without
    // its verdict is useless. Drop order: Exit, Out, White; then Address
    // shrinks toward a 12-cell floor. Surviving columns carry their LOGICAL id
    // through `order`, so a drop never shifts another column's meaning.
    let logical: [(usize, &str, u16); 10] = [
        (0, "", 2),         // status
        (1, "ID", 8),       // link id hex
        (2, "Flag", 5),     // inbound flag
        (3, "Address", 29), // host (+ `+`/`-` prefix cell)
        (4, "Port", 6),     // port
        (5, "White", 9),    // whitelist tokens
        (6, "Protocol", 24),
        (7, "Test", 7),  // + fixed sort arrow
        (8, "Out", 5),   // exit flag
        (9, "Exit", 14), // exit IP
    ];
    let mut widths: Vec<u16> = logical.iter().map(|(_, _, w)| *w).collect();
    let inner_w = area.width.saturating_sub(2); // frameless inset
    for &drop in &[9usize, 8, 5] {
        if widths.iter().sum::<u16>() > inner_w {
            widths[drop] = 0;
        }
    }
    let excess = widths.iter().sum::<u16>().saturating_sub(inner_w);
    if excess > 0 {
        // Address shrinks toward a 12-cell floor; anything still over clips.
        let shrink = excess.min(widths[3].saturating_sub(12));
        widths[3] -= shrink;
    }
    let order: Vec<usize> = widths
        .iter()
        .enumerate()
        .filter(|(_, w)| **w > 0)
        .map(|(i, _)| i)
        .collect();
    let columns: Vec<Column> = order
        .iter()
        .map(|&l| {
            let (_, label, _) = logical[l];
            if label.is_empty() {
                Column::new(Line::raw(""), ColumnWidth::Fixed(widths[l]))
            } else {
                Column::new(
                    Line::from(Span::styled(label, header_style)),
                    ColumnWidth::Fixed(widths[l]),
                )
            }
        })
        .collect();

    // The arrow follows the Test column's POSITION in the visible grid — a
    // width-aware drop moves it (e.g. `Test ↑` once White drops).
    let sort_column = order.iter().position(|&l| l == PROFILES_SORT_COLUMN);
    let sort_direction = SortDirection::Ascending;

    // Scroll offset: keep the selected row roughly centered, in line units —
    // expanded rows are taller than 1, so row-index math would strand the
    // last rows below the viewport.
    let heights: Vec<u16> = display_rows
        .iter()
        .map(|r| r.height(area.width.saturating_sub(2)))
        .collect();
    let data_offset = compute_scroll_offset(&heights, selected_display_idx, area.height);
    let scrollbar_total = usize::try_from(state.page_total).unwrap_or(usize::MAX);
    let scrollbar_offset = state.page_offset.saturating_add(data_offset);
    let data_table = DataTable::new(columns, display_rows)
        .highlight_style(ThemeStyles::table_row_selected(theme))
        .column_spacing(1)
        .column_order(order)
        .sort_column(sort_column, sort_direction)
        .total_rows(Some(scrollbar_total))
        .scrollbar_offset(Some(scrollbar_offset))
        .scrollbar(
            ThemeStyles::scrollbar_thumb(theme),
            ThemeStyles::scrollbar_track(theme),
        );

    let mut table_state = DataTableState {
        offset: data_offset,
        selected: Some(selected_display_idx),
        multi_selected: std::collections::HashSet::new(),
    };

    let inner = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    };
    frame.render_stateful_widget(data_table, inner, &mut table_state);
}

/// First visible sub-row of a windowed panel: keeps the selected sub-row near
/// the middle of the `max_visible`-row window, clamped so the window always
/// shows `max_visible` rows when the list is that long.
fn panel_window(total: usize, selected: Option<usize>, max_visible: usize) -> usize {
    if total <= max_visible || max_visible == 0 {
        return 0;
    }
    let sel = selected.unwrap_or(0).min(total - 1);
    sel.saturating_sub(max_visible / 2).min(total - max_visible)
}

/// First visible row index that keeps the selected row roughly centered.
/// `heights[i]` is row i's height (expanded rows are taller than 1). The
/// return value is a row index because [`DataTableState::offset`] indexes
/// `DataTable::rows`, even though vertical positioning uses line heights.
fn compute_scroll_offset(heights: &[u16], selected: usize, viewport_height: u16) -> usize {
    let inner_height = viewport_height.saturating_sub(3) as usize;
    let Some(selected_height) = heights.get(selected).copied() else {
        return 0;
    };
    if selected_height as usize >= inner_height {
        return selected.min(heights.len().saturating_sub(1));
    }

    let selected_start: usize = heights[..selected].iter().map(|h| *h as usize).sum();
    let ideal_line =
        selected_start.saturating_sub(inner_height.saturating_sub(selected_height as usize) / 2);

    // Earliest row that still shows the selected row's last line. For a
    // selected row taller than the viewport, this is the selected row itself.
    let minimum_line = selected_start
        .saturating_add(selected_height as usize)
        .saturating_sub(inner_height);
    let mut line = 0usize;
    let mut minimum_offset = selected;
    for (index, height) in heights.iter().enumerate() {
        if line >= minimum_line {
            minimum_offset = index;
            break;
        }
        line += *height as usize;
    }

    // Latest row offset that still fills the viewport from the end. A row
    // taller than the viewport remains partially visible at the last index.
    let mut rows_from_end = 0usize;
    let mut height_from_end = 0usize;
    for height in heights.iter().rev() {
        let height = *height as usize;
        if height_from_end + height > inner_height {
            break;
        }
        height_from_end += height;
        rows_from_end += 1;
    }
    let maximum_offset = heights
        .len()
        .saturating_sub(rows_from_end)
        .min(heights.len().saturating_sub(1));
    let minimum_offset = minimum_offset.min(maximum_offset);

    // Convert the ideal LINE position to the closest actual ROW start.
    let mut best = minimum_offset;
    let mut best_distance = usize::MAX;
    line = 0;
    for (index, height) in heights.iter().enumerate().take(maximum_offset + 1) {
        if index >= minimum_offset {
            let distance = line.abs_diff(ideal_line);
            if distance < best_distance {
                best = index;
                best_distance = distance;
            }
        }
        line += *height as usize;
    }
    best
}

fn format_traffic(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:>4.1}GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:>4.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:>4.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes:>4}B ")
    }
}

/// Truncate to `width` (unicode-aware) with space padding, no ellipsis.
pub(crate) fn truncate_pad(s: &str, width: usize) -> String {
    if unicode_width::UnicodeWidthStr::width(s) > width {
        let mut char_w = 0usize;
        let mut end = 0usize;
        for (i, c) in s.char_indices() {
            let cw = unicode_width::UnicodeWidthChar::width(c).unwrap_or(1);
            if char_w + cw > width.saturating_sub(1) {
                break;
            }
            char_w += cw;
            end = i + c.len_utf8();
        }
        format!("{:width$}", &s[..end], width = width)
    } else {
        format!("{s:width$}")
    }
}

/// Center `s` inside a `width`-wide cell with the extra space on the LEFT for
/// odd widths: `[ 12 ]`, `[ 123]`, `[1234]` (Test column look). Truncates
/// when wider.
fn center_cell(s: &str, width: usize) -> String {
    let w = unicode_width::UnicodeWidthStr::width(s);
    if w >= width {
        return truncate_pad(s, width);
    }
    let left = (width - w).div_ceil(2);
    let right = width - w - left;
    format!("{}{}{}", " ".repeat(left), s, " ".repeat(right))
}

/// Center `s` inside a `width`-wide cell (unicode-aware); truncates when wider.
fn center_pad(s: &str, width: usize) -> String {
    let w = unicode_width::UnicodeWidthStr::width(s);
    if w >= width {
        return truncate_pad(s, width);
    }
    let left = (width - w) / 2;
    let right = width - w - left;
    format!("{}{}{}", " ".repeat(left), s, " ".repeat(right))
}

/// The row the footer describes: the FILTERED row at `selected_index`.
/// With a search filter active, `selected_index` indexes the filtered list,
/// not `state.endpoints` — resolving through `filtered_profiles()` keeps the
/// footer in sync with the highlighted row (and the none-selected branch).
pub(crate) fn footer_row(state: &AppState) -> Option<&EndpointRow> {
    state.filtered_profiles().nth(state.selected_index)
}

fn render_footer(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    if area.height < 1 {
        return;
    }

    let line = footer_row(state).map_or_else(
        || {
            Line::from(Span::styled(
                " Server: (none selected)",
                ThemeStyles::footer_label(theme),
            ))
        },
        |row| {
            let core = state.resolved_core(row);

            let host = row.endpoint.display_host(&row.resolved_ips);
            let addr = if host.is_empty() {
                "-".to_string()
            } else {
                host
            };
            let port = row.endpoint.port.to_string();
            Line::from(vec![
                Span::styled(" Server: ", ThemeStyles::footer_label(theme)),
                Span::styled(format!("{addr}:{port}  "), ThemeStyles::footer_value(theme)),
                Span::styled(format!("[{core}] "), ThemeStyles::footer_value(theme)),
            ])
        },
    );
    // Page position: a 200-row window must not look like a 200-entry feed.
    let line = line.patch_style(ThemeStyles::status_footer(theme));
    let mut spans = line.spans;
    if state.profiles_total() > 0 {
        let first = state.page_offset as u64 + 1;
        let last = state.page_offset as u64 + state.endpoints.len() as u64;
        spans.push(Span::styled(" ", ThemeStyles::footer_label(theme)));
        spans.push(Span::styled(
            format!("rows {first}-{last} of {}", state.profiles_total()),
            ThemeStyles::footer_label(theme),
        ));
    }
    let line = Line::from(spans);
    let footer = Paragraph::new(line).style(ThemeStyles::status_footer(theme));
    frame.render_widget(footer, area);
}

fn render_filter_strip(frame: &mut Frame, area: Rect, state: &AppState, theme: &opaline::Theme) {
    let view_label = match state.purgatory_view {
        leas_db::models::PurgatoryView::Active => "Active",
        leas_db::models::PurgatoryView::Purgatory => "Purgatory",
        leas_db::models::PurgatoryView::All => "All",
    };
    let view_text = format!(" View: {view_label} [P]");
    let view_span = Span::styled(view_text, ThemeStyles::container_title(theme));
    let search_text = if state.search_focused {
        format!("/ {}▉", state.search_query)
    } else if state.search_query.is_empty() {
        " /  (press / to search)".to_string()
    } else {
        format!("/ {}", state.search_query)
    };
    let search_span = Span::styled(search_text, ThemeStyles::warning(theme));

    let line = Line::from(vec![view_span, Span::raw("  "), search_span]);
    let paragraph = Paragraph::new(line);
    frame.render_widget(paragraph, area);
}

fn render_confirmation_overlays(
    frame: &mut Frame,
    area: Rect,
    rows: &[&EndpointRow],
    state: &AppState,
) {
    match state.confirmation {
        Some(ConfirmAction::DeleteProfile(ref delete_id)) => {
            let profile_name = rows
                .iter()
                .find(|r| r.endpoint.id.get() == *delete_id)
                .map(|r| {
                    format!(
                        "{}:{}",
                        r.endpoint.display_host(&r.resolved_ips),
                        r.endpoint.port
                    )
                })
                .unwrap_or_default();
            render_confirmation_overlay(
                frame,
                area,
                &format!(" Delete \"{profile_name}\"? (y/N) "),
                state.theme(),
            );
        }
        Some(ConfirmAction::DeleteProfiles(ref ids)) => {
            render_confirmation_overlay(
                frame,
                area,
                &format!(" Delete {} profiles? (y/N) ", ids.len()),
                state.theme(),
            );
        }
        Some(ConfirmAction::ClearGroup(ref group_id)) => {
            let group_name = state
                .groups
                .iter()
                .find(|g| g.id == *group_id)
                .and_then(|g| g.name.as_deref())
                .unwrap_or("unknown");
            render_confirmation_overlay(
                frame,
                area,
                &format!(" Clear all profiles in \"{group_name}\"? (y/N) "),
                state.theme(),
            );
        }
        _ => {}
    }
}

#[cfg(test)]
mod page_window_tests {
    use std::sync::Arc;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn scrollbar_thumb_row(state: &AppState, rows: &[DisplayRowData]) -> usize {
        let area = Rect::new(0, 0, 125, 10);
        let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
        terminal
            .draw(|frame| {
                render_data_grid(
                    frame,
                    area,
                    rows,
                    state.selected_index,
                    state,
                    state.theme(),
                );
            })
            .unwrap();
        let symbols: String = (1..area.height)
            .map(|y| terminal.backend().buffer()[(area.width - 2, y)].symbol())
            .collect();
        symbols
            .char_indices()
            .find(|(_, symbol)| matches!(*symbol, '█' | '▄' | '▀'))
            .map_or_else(
                || panic!("scrollbar glyphs: {symbols:?}"),
                |(index, _)| index,
            )
    }

    #[tokio::test]
    async fn rendered_scrollbar_moves_across_full_feed() {
        let mut state = two_page_state().await;
        let first_page = display(&state);
        let first_thumb = scrollbar_thumb_row(&state, &first_page);

        state.selected_index = PROFILES_PAGE_SIZE - 1;
        move_selection(&mut state, 1).await;
        let second_page = display(&state);
        let second_thumb = scrollbar_thumb_row(&state, &second_page);

        assert!(
            second_thumb > first_thumb,
            "page 2 thumb ({second_thumb}) must follow page 1 ({first_thumb})"
        );
    }
    use super::*;
    use crate::ops::profiles::{PROFILES_PAGE_SIZE, move_selection, reload_profiles, test_support};

    /// Two FULL pages of endpoints, loaded through the real query path — a
    /// short second page would let the display cache miss on row count alone
    /// and mask a stale page.
    async fn two_page_state() -> AppState {
        let db = Arc::new(leas_db::Database::in_memory().await.unwrap());
        let count = PROFILES_PAGE_SIZE * 2;
        for i in 1..=count as i64 {
            let row = test_support::fake_row(i, &format!("h{i:05}.example"), 1);
            db.upsert_endpoint(&row.endpoint).await.unwrap();
            for link in &row.links {
                db.upsert_link(link).await.unwrap();
                if let Some(proto) = row.protocols.get(&link.protocol_id) {
                    db.upsert_protocol(proto).await.unwrap();
                }
            }
        }
        let mut state = test_support::test_state(Vec::new()).await;
        state.db = db;
        state.purgatory_view = leas_db::models::PurgatoryView::All;
        reload_profiles(&mut state).await;
        state
    }

    /// The whole chain: a link's RING reaches the panel cell. `stability_ratio`
    /// is correct in isolation (the test above) and the panel draws whatever
    /// `PanelRow.stab` holds (the render test) — this pins the one line between
    /// them, reading a real `ProfileStats` through `build_display_rows`.
    #[tokio::test]
    async fn a_links_ring_reaches_the_panel_cell() {
        let mut row = crate::ops::profiles::test_support::fake_row(1, "10.0.0.1", 2);
        // Link 0: 12 successes out of 16. Link 1: never sampled.
        row.links[0].stab_mask = (1 << 12) - 1;
        row.links[0].stab_len = 16;
        // Only an EXPANDED row builds its panel.
        row.expanded = true;
        let mut state = crate::ops::profiles::test_support::test_state(vec![row]).await;
        state.endpoints[0].expanded = true;
        let rows = display(&state);
        let panel = &rows[0].panel_rows;
        assert_eq!(panel.len(), 2, "both links render a sub-row");
        assert_eq!(panel[0].stab, "12/16", "the ring, as a ratio");
        assert_eq!(panel[1].stab, "—", "an unsampled link says so, not 0/0");
    }

    fn display(state: &AppState) -> Vec<DisplayRowData> {
        let rows: Vec<&EndpointRow> = state.endpoints.iter().collect();
        let theme = state.theme();
        (*build_display_rows(&rows, state.selected_index, state, theme)).clone()
    }

    /// Paging back onto a page whose rows are all already enriched (so the
    /// enrichment seeding marks nothing dirty) must still render that page.
    #[tokio::test]
    async fn returning_to_an_enriched_page_renders_it() {
        let mut state = two_page_state().await;
        let first_address = display(&state)[0].address_str.trim().to_string();

        state.selected_index = PROFILES_PAGE_SIZE - 1;
        move_selection(&mut state, 1).await; // page 2
        let second_address = display(&state)[0].address_str.trim().to_string();
        assert_ne!(first_address, second_address);

        state.selected_index = 0;
        move_selection(&mut state, -1).await; // back to page 1
        assert_ne!(first_address, second_address);
        assert_eq!(state.page_offset, 0);
        assert_eq!(
            display(&state)[0].address_str.trim(),
            first_address,
            "page 1 must render again"
        );
    }

    /// A page change must show the new page's rows: the display cache key has
    /// to see the page, not just the loaded row count.
    #[tokio::test]
    async fn page_change_refreshes_the_display_rows() {
        let mut state = two_page_state().await;
        let before = display(&state);
        let before_addr = before[0].address_str.clone();

        state.selected_index = PROFILES_PAGE_SIZE - 1;
        move_selection(&mut state, 1).await;

        let after = display(&state);
        assert_ne!(
            after[0].address_str, before_addr,
            "page 2's first row must not be page 1's cached row"
        );
        assert_eq!(
            after[0].address_str.trim(),
            state.endpoints[0]
                .endpoint
                .display_host(&state.endpoints[0].resolved_ips),
            "the Address column carries the host only; port is its own column"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The panel's stability cell (spec §8): a ratio when the link has samples,
    /// and the neutral marker — never a fake `0/0` — when it has none.
    #[test]
    fn the_stability_cell_shows_the_ratio_or_a_dash() {
        let mut link = crate::ops::profiles::test_support::fake_row(1, "10.0.0.1", 1)
            .links
            .remove(0);
        assert_eq!(stability_ratio(&link), "—", "no samples is not 0/0");

        link.stab_mask = 0b1011;
        link.stab_len = 4;
        assert_eq!(stability_ratio(&link), "3/4");

        link.stab_mask = (1 << 16) - 1;
        link.stab_len = 16;
        assert_eq!(stability_ratio(&link), "16/16");

        // A corrupt stored len is clamped, not panicked on.
        link.stab_len = 999;
        assert_eq!(stability_ratio(&link), "16/16");
    }

    fn sample_panel_row(marker: &str) -> PanelRow {
        PanelRow {
            marker: marker.to_string(),
            proto_id_hex: String::new(),
            stab: String::new(),
            last_seen: String::new(),
            last_used: String::new(),
            protocol_type: String::new(),
            config_type: String::new(),
            delay: String::new(),
            speed: String::new(),
            traffic: String::new(),
            outbound: String::new(),
            outbound_country: String::new(),
        }
    }

    fn sample_row(expanded: bool, panel_rows: Vec<PanelRow>, idx: &str) -> DisplayRowData {
        DisplayRowData {
            indicator: String::new(),
            indicator_fg: Style::default(),
            id_hex: idx.to_string(),
            inbound_flag: String::new(),
            address_str: String::new(),
            port_str: String::new(),
            white_str: String::new(),
            protocol_info_str: String::new(),
            test_str: String::new(),
            test_style: Style::default(),
            outbound_addr: String::new(),
            outbound_flag: String::new(),
            expand_prefix: if panel_rows.is_empty() {
                ' '
            } else if expanded {
                '-'
            } else {
                '+'
            },
            expanded,
            row_style: Style::default(),
            id_style: Style::default(),
            address_style: Style::default(),
            port_style: Style::default(),
            white_style: Style::default(),
            protocol_style: Style::default(),
            prefix_style: Style::default(),
            panel_selected_style: Style::default(),
            panel_selected: None,
            panel_ips: String::new(),
            panel_resolve_hint: false,
            panel_rows,
        }
    }

    /// The approximation marker is scoped to the REPRESENTATIVE link's own
    /// protocol — the same link the cell describes (decision 16). A `Protocol`
    /// row is shared across endpoints (identity excludes host/port) and an
    /// endpoint carries several links, so "the endpoint has an unrosterable `fp`
    /// somewhere" would mark a verdict that came from a roster-mapped sibling —
    /// which is the one thing the marker must never mean.
    #[test]
    fn approximation_marker_follows_the_representative_link() {
        use crate::ops::profiles::test_support::fake_row;
        let theme = crate::ui::theme::load("tokyo-night").unwrap();
        let mut row = fake_row(1, "1.2.3.4", 3); // p100, p101, p102
        let rep = row
            .representative_link_index(true)
            .expect("a representative");
        let rep_id = row.links[rep].protocol_id;
        let sibling_id = row.links[(rep + 1) % row.links.len()].protocol_id;

        // A sibling carrying an unrosterable id must NOT mark the row.
        row.protocols
            .get_mut(&sibling_id)
            .expect("sibling")
            .security
            .fp = Some(String::from("qq"));
        let (text, _) = compute_test_cell(&row, true, &theme);
        assert!(!text.contains('~'), "sibling-only: {text:?}");

        // The representative's own protocol carrying it MUST.
        row.protocols.get_mut(&rep_id).expect("rep").security.fp = Some(String::from("qq"));
        let (text, _) = compute_test_cell(&row, true, &theme);
        assert!(text.ends_with('~'), "representative: {text:?}");

        // A roster id, and the two spellings of "no fingerprint requested", are
        // honoured as specified and unmarked.
        for fp in ["chrome", "firefox", "", "unsafe"] {
            row.protocols.get_mut(&rep_id).expect("rep").security.fp = Some(String::from(fp));
            let (text, _) = compute_test_cell(&row, true, &theme);
            assert!(!text.contains('~'), "fp={fp:?} honoured: {text:?}");
        }
    }

    /// The marker appends to whatever the cell already shows — it is a
    /// provenance note about the measurement, never a replacement for it.
    #[test]
    fn approximation_marker_composes_with_the_verdict() {
        use crate::ops::profiles::test_support::fake_row;
        use leas_db::models::Latency;
        let theme = crate::ui::theme::load("tokyo-night").unwrap();
        let mut row = fake_row(1, "1.2.3.4", 1);
        let rep_id = row.links[0].protocol_id;
        row.links[0].latency = Some(Latency::Fast { delay: 42 });
        row.protocols.get_mut(&rep_id).expect("rep").security.fp = Some(String::from("qq"));
        let (text, _) = compute_test_cell(&row, true, &theme);
        assert!(text.contains("42"), "the measurement survives: {text:?}");
        assert!(text.ends_with('~'), "and carries the marker: {text:?}");
    }

    /// Regression: multi-protocol endpoint — the cell describes the
    /// REPRESENTATIVE link (the minimum of the decision-16 key), never the raw
    /// `selected_protocol` and never "any link". A failed sibling must not paint
    /// the row red while the endpoint's own tier is a success band, and the
    /// marker must appear once no link has a clean measurement left.
    #[test]
    fn test_cell_follows_the_representative_link() {
        use crate::ops::profiles::test_support::fake_row;
        use leas_db::models::{ErrorInfo, Latency, ProfileErr};
        let theme = crate::ui::theme::load("tokyo-night").unwrap();
        let mut row = fake_row(1, "1.2.3.4", 3); // p100, p101, p102
        row.links[0].error = Some(ErrorInfo {
            kind: ProfileErr::Real,
            text: "timeout".into(),
        });
        row.links[1].latency = Some(Latency::Real {
            delay: 40,
            ip: None,
        });
        // p102 stays untested.

        // The representative is p101 (tier 0), so its delay is what the row
        // shows — whatever the selection is.
        for selected in [0, 1, 2] {
            row.selected_protocol = selected;
            let (text, _) = compute_test_cell(&row, true, &theme);
            assert!(text.contains("40"), "representative delay: {text:?}");
            assert!(!text.contains("real"), "no marker: {text:?}");
        }

        // Every link failed → no clean measurement remains → the marker, from
        // the representative's kind (real ranks above fast).
        row.links[1].latency = None;
        row.links[1].error = Some(ErrorInfo {
            kind: ProfileErr::Fast,
            text: "timeout".into(),
        });
        row.links[2].error = Some(ErrorInfo {
            kind: ProfileErr::Real,
            text: "timeout".into(),
        });
        row.selected_protocol = 1;
        let (text, _) = compute_test_cell(&row, true, &theme);
        assert_eq!(text, "[real]");
    }

    /// A link carrying BOTH a fast measurement and a real failure (tier 3)
    /// beside a sibling whose fast measurement is clean (tier 1): the endpoint's
    /// tier is 1, so the cell must show the clean measurement. Selecting by
    /// lowest-delay MEASURED (error-blind) picked the failing link — whose delay
    /// is lower — and rendered its marker on a row the ordering law had placed in
    /// the measurement band. This state is routine mid-batch: the failing link is
    /// a previous run's result, the clean one landed seconds ago.
    #[test]
    fn test_cell_ignores_a_marker_on_a_link_worse_than_the_endpoints_tier() {
        use crate::ops::profiles::test_support::fake_row;
        use leas_db::models::{ErrorInfo, Latency, ProfileErr};
        let theme = crate::ui::theme::load("tokyo-night").unwrap();
        let mut row = fake_row(1, "1.2.3.4", 2);
        row.links[0].latency = Some(Latency::Fast { delay: 12 });
        row.links[0].error = Some(ErrorInfo {
            kind: ProfileErr::Real,
            text: "timeout".into(),
        });
        row.links[1].latency = Some(Latency::Fast { delay: 20 });

        // `select_best_measured_link` would pick links[0] (12 < 20) — the cell
        // must not follow it.
        let mut probing = row.clone();
        probing.select_best_measured_link();
        assert_eq!(probing.selected_protocol, 0, "the error-blind rule picks A");

        let (text, _) = compute_test_cell(&row, true, &theme);
        assert_eq!(
            text, "[ 20 ]",
            "the endpoint's tier is 1, so its clean measurement shows"
        );
    }

    /// A link that carries both a measurement and a failure marker shows the
    /// MARKER. A failed real probe keeps its fast latency in `profile_stats`
    /// (`apply_test_result` preserves the measurement when it writes the
    /// marker), so rendering that delay would present a failed profile as a
    /// working one — and the ordering law already ranks the same link in an
    /// error tier, so a delay here made the cell and the sort key two
    /// different laws.
    #[test]
    fn test_cell_failure_marker_beats_the_links_own_delay() {
        use crate::ops::profiles::test_support::fake_row;
        use leas_db::models::{ErrorInfo, Latency, ProfileErr};
        let theme = crate::ui::theme::load("tokyo-night").unwrap();
        let mut row = fake_row(1, "1.2.3.4", 1);
        row.links[0].latency = Some(Latency::Fast { delay: 44 });
        row.links[0].error = Some(ErrorInfo {
            kind: ProfileErr::Fast,
            text: "timeout".into(),
        });
        let (text, _style) = compute_test_cell(&row, true, &theme);
        assert_eq!(text, "[fast]", "the marker must win over a stale delay");
        assert!(!text.contains("44"), "no delay over a marker: {text:?}");

        // The delay is displayable again once the marker is gone — the TTL
        // sweep is the only remover.
        row.links[0].error = None;
        let (text, _style) = compute_test_cell(&row, true, &theme);
        assert!(
            text.contains("44"),
            "a clean measurement still shows: {text:?}"
        );
    }

    #[test]
    fn expanded_row_height_includes_gap() {
        let row = sample_row(
            true,
            vec![sample_panel_row("●"), sample_panel_row("○")],
            "00",
        );
        // 1 endpoint + panel (2 rows + 4 border/IPs/sep lines) + 1 gap
        assert_eq!(row.height(0), 8);
        let collapsed = sample_row(false, vec![], "11");
        assert_eq!(collapsed.height(0), 1);
    }

    #[test]
    fn link_id_cell_prints_hex_or_marker() {
        use crate::ops::profiles::test_support::fake_row;
        let row = fake_row(42, "1.2.3.4", 1);
        // The representative link's protocol id, 8 lowercase hex.
        let expected = format!("{:08x}", row.links[0].protocol_id.get() as u32);
        assert_eq!(link_id_cell(&row, false, false), expected);
        // Multi-select: the marker replaces the id, both padded to 8 (D10).
        assert_eq!(link_id_cell(&row, false, true), "       *");
        assert_eq!(
            link_id_cell(&row, false, true).len(),
            link_id_cell(&row, false, false).len()
        );
    }

    #[test]
    fn truncate_host_keeps_the_domain() {
        // A long subdomain elides its tail; the registrable domain survives.
        // 36-cell host, 33-cell column: 20 subdomain cells + `….example.com`.
        assert_eq!(
            truncate_host("abcdefghijklmnopqrstuvwxyz.example.com", 33),
            "abcdefghijklmnopqrst….example.com"
        );
        // Fits: verbatim.
        assert_eq!(truncate_host("edge-a.example", 33), "edge-a.example");
        // IP literals right-truncate with an ellipsis.
        assert_eq!(truncate_host("2001:db8::dead:beef", 10), "2001:db8:…");
    }

    #[test]
    fn flag_cell_pins_both_capability_forms() {
        // Emoji form: `<flag>-<ISO>`, 5 cells (D14). Fallback: bare ISO.
        assert_eq!(flag_cell(Some("NL"), true), "🇳🇱-NL");
        assert_eq!(flag_cell(Some("NL"), false), "NL   ");
        // Unknown country is the neutral glyph in both forms.
        assert_eq!(flag_cell(None, true), "—");
        assert_eq!(flag_cell(None, false), "—");
    }

    #[test]
    fn white_cell_spells_the_whitelist_tokens() {
        assert_eq!(white_cell(false, false).trim(), "—");
        assert_eq!(white_cell(true, false).trim(), "CIDR");
        assert_eq!(white_cell(false, true).trim(), "SNI");
        assert_eq!(white_cell(true, true).trim(), "SNI+CIDR");
        // 9 cells: the longest token must fit unabbreviated.
        assert_eq!(white_cell(true, true).len(), 9);
    }

    #[test]
    fn protocol_info_cell_merges_kind_transport_security() {
        use crate::ops::profiles::test_support::fake_row;
        let row = fake_row(1, "1.2.3.4", 1);
        // The test row is a vless protocol over tcp with no security layer.
        assert_eq!(protocol_info_cell(&row).trim(), "vless/tcp/none");
        assert_eq!(protocol_info_cell(&row).len(), PROTOCOL_INFO_WIDTH);
        // A row without an active protocol keeps the placeholder.
        let linkless = fake_row(2, "5.6.7.8", 0);
        assert_eq!(protocol_info_cell(&linkless).trim(), "-");
    }

    #[test]
    fn panel_window_follows_selected_sub_row() {
        // Lists that fit are never windowed.
        assert_eq!(panel_window(3, Some(2), 8), 0);
        assert_eq!(panel_window(8, Some(7), 8), 0);
        // A 23-row list centers the selection and clamps at both ends.
        assert_eq!(panel_window(23, Some(0), 8), 0);
        assert_eq!(panel_window(23, Some(9), 8), 5);
        assert_eq!(panel_window(23, Some(22), 8), 15);
        // No selection (endpoint row focused) shows the top of the list.
        assert_eq!(panel_window(23, None, 8), 0);
    }

    #[test]
    fn panel_height_is_capped_at_eight_sub_rows() {
        let capped = sample_row(true, (0..20).map(|_| sample_panel_row("○")).collect(), "00");
        // 1 + PANEL_MAX_ROWS + 4 + 1 — the row can no longer grow past the
        // viewport, which used to blank the table when expanded.
        assert_eq!(capped.height(0), 14);
        // Shorter lists keep their exact panel height.
        let short = sample_row(true, (0..7).map(|_| sample_panel_row("○")).collect(), "00");
        assert_eq!(short.height(0), 13);
    }

    #[test]
    fn panel_config_and_delay_keep_a_gap() {
        let theme = crate::ui::theme::load("tokyo-night").unwrap();
        let mut pr = sample_panel_row("●");
        // A config value wider than its 14-cell column (the cell clips it):
        // without the deliberate 1-cell gap the latency text would run into
        // the clipped config.
        pr.config_type = "splithttp/reality".to_string();
        pr.delay = "1234ms".to_string();
        let mut row = sample_row(true, vec![pr], "00");
        row.row_style = ThemeStyles::table_row_normal(&theme);
        let col_widths = vec![1u16, 2, 7, 1, 4, 34, 2, 4, 4, 24, 3, 7, 1, 16, 7, 1];
        let mut col_xs = Vec::with_capacity(col_widths.len());
        let mut x = 0u16;
        for w in &col_widths {
            col_xs.push(x);
            x += w;
        }
        let mut buf = Buffer::empty(Rect::new(0, 0, 120, 20));

        row.render(
            &col_xs,
            &col_widths,
            &(0..col_xs.len()).collect::<Vec<_>>(),
            &mut buf,
            0,
            20,
        );

        let line: String = (0..120).map(|x| buf[(x, 4)].symbol()).collect();
        assert!(
            line.contains("splithttp/real 1234ms"),
            "config must not blend into the latency cell: {line:?}"
        );
    }

    #[test]
    fn windowed_panel_renders_selected_window_and_range() {
        let theme = crate::ui::theme::load("tokyo-night").unwrap();
        let mut row = sample_row(
            true,
            (0..23)
                .map(|i| {
                    let mut pr = sample_panel_row("●");
                    pr.proto_id_hex = format!("{i:08x}");
                    pr
                })
                .collect(),
            "00",
        );
        row.row_style = ThemeStyles::table_row_normal(&theme);
        row.panel_selected_style = ThemeStyles::panel_row_selected(&theme);
        row.panel_selected = Some(9);
        // Real column geometry (118 cells) so the panel draws at its
        // production width. Keep in step with the `Column::new` widths in
        // `columns()` — this literal is a copy, so a width change there must
        // change it here too (the Test column is 7: 6 for `[value]` plus the
        // `~` approximation marker).
        let col_widths = vec![1u16, 2, 7, 1, 4, 34, 2, 4, 4, 24, 3, 7, 1, 16, 7, 1];
        let mut col_xs = Vec::with_capacity(col_widths.len());
        let mut x = 0u16;
        for w in &col_widths {
            col_xs.push(x);
            x += w;
        }
        let mut buf = Buffer::empty(Rect::new(0, 0, 120, 20));

        row.render(
            &col_xs,
            &col_widths,
            &(0..col_xs.len()).collect::<Vec<_>>(),
            &mut buf,
            0,
            20,
        );

        // Window = panel rows 5..13 (centered on the selected 9): the first
        // visible sub-row line carries row 5's id, not row 0's.
        let first_line: String = (0..120).map(|x| buf[(x, 4)].symbol()).collect();
        assert!(
            first_line.contains("00000005"),
            "window must start at the selected window: {first_line:?}"
        );
        assert!(
            !first_line.contains("00000000"),
            "row 0 must be scrolled out of view: {first_line:?}"
        );
        // The separator (y0+2 = 3) carries the visible range + total.
        let separator: String = (0..120).map(|x| buf[(x, 3)].symbol()).collect();
        assert!(
            separator.contains("6-13/23"),
            "range label missing: {separator:?}"
        );
        // The selected sub-row (global 9 → local 4 → y = 8) keeps the reverse
        // highlight.
        assert_eq!(buf[(1, 8)].style().bg, Some(ratatui::style::Color::Reset));
        // Nothing is written at or past the clip line.
        for x in 0..120u16 {
            assert_eq!(buf[(x, 19)].symbol(), " ");
        }
    }

    #[test]
    fn selected_sub_row_reverse_highlights_full_width() {
        let theme = crate::ui::theme::load("tokyo-night").unwrap();
        let mut row = sample_row(
            true,
            vec![sample_panel_row("●"), sample_panel_row("○")],
            "00",
        );
        row.row_style = ThemeStyles::table_row_normal(&theme);
        row.panel_selected_style = ThemeStyles::panel_row_selected(&theme);
        row.panel_selected = Some(0);
        let col_xs: Vec<u16> = (0..17).collect();
        let col_widths = vec![1u16; 17];
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 20));

        // Simulate the DataTable's endpoint-row highlight: the whole row
        // (including the expanded panel area) sits on `surface`.
        for x in 0..17u16 {
            for y in 0..8u16 {
                buf[(x, y)].set_style(ThemeStyles::table_row_selected(&theme));
            }
        }

        row.render(
            &col_xs,
            &col_widths,
            &(0..col_xs.len()).collect::<Vec<_>>(),
            &mut buf,
            0,
            20,
        );

        // Panel starts at y=1; sub-rows at y0+3 → sub-row 0 at y=4, sub-row 1
        // at y=5. x=1 is the panel's first inner cell.
        // Selected sub-row drops back to the common (terminal-default)
        // background…
        assert_eq!(
            buf[(1, 4)].style().bg,
            Some(ratatui::style::Color::Reset),
            "selected sub-row must use the common background (reverse highlight)"
        );
        // …across the ENTIRE row width, not just written glyphs.
        assert_eq!(
            buf[(13, 4)].style().bg,
            Some(ratatui::style::Color::Reset),
            "reverse highlight must span the full sub-row width"
        );
        // …the unselected sub-row keeps the panel's highlight background.
        assert_eq!(
            buf[(1, 5)].style().bg,
            Some(theme.color("bg.highlight").into()),
            "unselected sub-row keeps the endpoint highlight background"
        );
    }

    #[test]
    fn panel_bottom_border_does_not_touch_next_row() {
        let row0 = sample_row(
            true,
            vec![sample_panel_row("●"), sample_panel_row("○")],
            "00",
        );
        let row1 = sample_row(false, vec![], "11");
        let col_xs: Vec<u16> = (0..17).collect();
        let col_widths = vec![1u16; 17];
        let mut buf = Buffer::empty(Rect::new(0, 0, 40, 20));

        row0.render(
            &col_xs,
            &col_widths,
            &(0..col_xs.len()).collect::<Vec<_>>(),
            &mut buf,
            0,
            20,
        );
        row1.render(
            &col_xs,
            &col_widths,
            &(0..col_xs.len()).collect::<Vec<_>>(),
            &mut buf,
            8,
            20,
        );

        // Panel (height 6) sits at y=1..6: bottom-left corner at y=6.
        assert_eq!(buf[(0, 6)].symbol(), "\u{2570}"); // ╰
        // y=7 is the blank gap line — the next row must not start there.
        assert_eq!(buf[(0, 7)].symbol(), " ");
        // Next row's content starts at y=8, untouched by the panel. The row id
        // lives in column 1 now (the `#` slot was replaced by the hex id).
        assert_eq!(buf[(1, 8)].symbol(), "1");
    }

    #[test]
    fn scroll_offset_reaches_last_row_when_tail_expanded() {
        // 30 collapsed + 10 expanded (6 lines), 40-line viewport (37 inner).
        let mut heights = vec![1u16; 40];
        for h in heights.iter_mut().skip(30) {
            *h = 6;
        }
        let offset = compute_scroll_offset(&heights, 39, 40);
        // Rows from the offset must fit the viewport…
        let fit: u16 = heights[offset..].iter().sum();
        assert!(fit <= 37);
        // …and the selected (last) row must be inside it.
        let sel_start: u16 = heights[offset..39].iter().sum();
        assert!(sel_start + 6 <= 37);
    }

    #[test]
    fn scroll_offset_small_list_stays_top() {
        let heights = vec![1u16; 5];
        assert_eq!(compute_scroll_offset(&heights, 4, 40), 0);
    }

    #[test]
    fn scroll_offset_centers_mid_list() {
        // 100 one-line rows, 21-line viewport (18 inner) → row 50 centered
        // at line 8 → offset 42.
        let heights = vec![1u16; 100];
        assert_eq!(compute_scroll_offset(&heights, 50, 21), 42);
    }

    #[test]
    fn scroll_offset_does_not_push_selection_offscreen() {
        // Selection in the middle of a tall list must stay visible.
        let heights = vec![1u16; 40];
        let offset = compute_scroll_offset(&heights, 20, 21);
        assert!(offset <= 20);
        let sel_start: u16 = heights[offset..20].iter().sum();
        assert!(sel_start < 18);
    }

    #[test]
    fn rows_taller_than_viewport_do_not_blank_table() {
        // heights where the selected (tall) row exceeds the viewport:
        // old code produced offset == len → nothing rendered.
        let heights = vec![1u16, 1, 1, 1, 1, 10];
        let offset = compute_scroll_offset(&heights, 5, 8);
        assert!(
            offset < heights.len(),
            "offset must stay inside the row list"
        );
    }

    #[test]
    fn scroll_offset_tall_selected_row_mid_list_stays_inside() {
        // Expanded row in the middle of the list: the offset must never
        // escape the row list even though the row is taller than the viewport.
        let heights = vec![1u16, 1, 10, 1, 1];
        let offset = compute_scroll_offset(&heights, 2, 8);
        assert_eq!(offset, 2, "offset must select the tall row, not exceed it");
    }

    #[test]
    fn scroll_offset_returns_row_index_for_mixed_heights() {
        let heights = [3, 10, 8, 8, 8];
        assert_eq!(compute_scroll_offset(&heights, 1, 14), 1);
    }

    #[test]
    fn scroll_offset_converts_line_position_after_expanded_prefix() {
        let heights = [8, 8, 8, 1, 1, 1, 1, 1];
        assert_eq!(compute_scroll_offset(&heights, 5, 8), 3);
    }

    /// A selection move patches only the two affected rows: the rest of the
    /// cached list must be identical (same allocation content), and the styles
    /// must swap.
    #[tokio::test]
    async fn selection_move_patches_styles_without_rebuilding_the_list() {
        use crate::ops::profiles::test_support::test_state;
        let rows = vec![
            endpoint_row(1, "a.example", 443),
            endpoint_row(2, "b.example", 443),
            endpoint_row(3, "c.example", 443),
        ];
        let state = test_state(rows).await;
        let theme = state.theme();
        let refs: Vec<&leas_db::models::EndpointRow> = state.endpoints.iter().collect();

        let first = build_display_rows(&refs, 0, &state, theme);
        assert_eq!(first[0].row_style, ThemeStyles::table_row_selected(theme));
        assert_eq!(first[1].row_style, ThemeStyles::table_row_normal(theme));

        // Move the selection: row 0 and row 1 restyle, row 2 is untouched.
        let moved = build_display_rows(&refs, 1, &state, theme);
        assert_eq!(moved[0].row_style, ThemeStyles::table_row_normal(theme));
        assert_eq!(moved[1].row_style, ThemeStyles::table_row_selected(theme));
        assert_eq!(moved[2].row_style, ThemeStyles::table_row_normal(theme));
        assert_eq!(moved.len(), 3);

        // Same selection again: still consistent (cache hit).
        let again = build_display_rows(&refs, 1, &state, theme);
        assert_eq!(again[1].row_style, ThemeStyles::table_row_selected(theme));
        assert_eq!(again[0].row_style, ThemeStyles::table_row_normal(theme));
    }

    /// Minimal `EndpointRow` with just enough to be filtered and described:
    /// host + port drive the search filter; no links (linkless endpoints must
    /// render without sub-rows and without an active protocol).
    fn endpoint_row(id: i64, host: &str, port: i32) -> EndpointRow {
        use leas_db::models::Endpoint;
        EndpointRow {
            endpoint: Endpoint {
                id: leas_db::models::EndpointId::new(id),
                domain: host.to_string(),
                sub_domain: String::new(),
                port: port as u16,
                ports: Vec::new(),
                last_source: None,
                manual_protocol_override: None,
                resolved_at: None,
                created_at: crate::ops::profiles::test_support::ts(0),
                links: toasty::Deferred::default(),
                group_links: toasty::Deferred::default(),
            },
            resolved_ips: Vec::new(),
            links: Vec::new(),
            protocols: std::collections::HashMap::new(),
            selected_protocol: 0,
            expanded: false,
        }
    }

    #[tokio::test]
    async fn footer_row_resolves_within_the_loaded_page() {
        // `selected_index` indexes the PAGE (the query applied the filter), so
        // the footer must describe that row — never `endpoints[selected_index]`
        // resolved against a different list, which would name another server.
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(
            leas_db::Database::open(dir.path().join("t.db"))
                .await
                .unwrap(),
        );
        let mut state = AppState::new(db, leas_config::AppConfig::default()).await;
        state.endpoints = vec![
            endpoint_row(1, "alpha.example", 443),
            endpoint_row(2, "beta.example", 8443),
            endpoint_row(3, "gamma.example", 443),
        ];
        state.page_total = 3;
        state.selected_index = 1;

        let row = footer_row(&state).expect("row should exist");
        assert_eq!(row.endpoint.id.get(), 2);
    }

    fn test_theme() -> opaline::Theme {
        crate::ui::theme::load("tokyo-night").unwrap()
    }

    /// The purge verdict outranks the delay the link still carries from phase 1
    /// — the row is retired, and its only reachable position is Purgatory/All.
    #[test]
    fn test_cell_shows_the_purge_label_over_a_delay() {
        let theme = crate::ui::theme::load("tokyo-night").unwrap();
        let (text, _) = test_cell_content(false, true, false, Some("mitm"), None, Some(12), &theme);
        assert_eq!(text, "[mitm]", "the verdict replaces the delay");

        // A row with no verdict is unchanged by the new slot.
        let (text, _) = test_cell_content(false, true, false, None, None, Some(12), &theme);
        assert_eq!(text, "[ 12 ]");
    }

    #[test]
    fn test_cell_colors_delay_by_threshold() {
        let theme = test_theme();
        let (t, s) = test_cell_content(false, true, false, None, None, Some(12), &theme);
        assert_eq!(t, "[ 12 ]");
        assert_eq!(s.fg, Some(theme.color("success").into()));
        let (t, s) = test_cell_content(false, true, false, None, None, Some(612), &theme);
        assert_eq!(t, "[ 612]");
        assert_eq!(s.fg, Some(theme.color("warning").into()));
        let (t, s) = test_cell_content(false, true, false, None, None, Some(1234), &theme);
        assert_eq!(t, "[1234]");
        assert_eq!(s.fg, Some(theme.color("error").into()));
    }

    #[test]
    fn test_cell_blank_without_measurement() {
        let theme = test_theme();
        let (t, _) = test_cell_content(false, true, false, None, None, None, &theme);
        assert_eq!(t, "      ");
    }

    #[test]
    fn test_cell_shows_name_when_dns_unresolved() {
        let theme = test_theme();
        let (t, s) = test_cell_content(true, false, false, None, None, Some(12), &theme);
        assert_eq!(t, "[name]");
        assert_eq!(s.fg, Some(theme.color("error").into()));
        // Resolved DNS name behaves like a normal host.
        let (t, _) = test_cell_content(true, true, false, None, None, Some(12), &theme);
        assert_eq!(t, "[ 12 ]");
    }

    #[test]
    fn test_cell_labels_persisted_failure_markers() {
        let theme = test_theme();
        // A failure marker outranks the link's OWN measurement: a failed probe
        // keeps its latency stored, and rendering it would hide a failure the
        // ordering law already ranks in an error tier.
        let (t, _) = test_cell_content(
            false,
            true,
            false,
            None,
            Some(TestFailure::Real),
            Some(12),
            &theme,
        );
        assert_eq!(t, "[real]");
        let (t, _) = test_cell_content(
            false,
            true,
            false,
            None,
            Some(TestFailure::Fast),
            Some(12),
            &theme,
        );
        assert_eq!(t, "[fast]");
        // Both marker classes present with no delay → [real]: real-err
        // (tier 3) ranks above fast-err (tier 4), the real check being the
        // deeper probe (T20 flip).
        let (t, s) = test_cell_content(
            false,
            true,
            false,
            None,
            Some(TestFailure::Real),
            None,
            &theme,
        );
        assert_eq!(t, "[real]");
        assert_eq!(s.fg, Some(theme.color("error").into()));
        // Only a fast-class failure marker with no delay → [fast].
        let (t, _) = test_cell_content(
            false,
            true,
            false,
            None,
            Some(TestFailure::Fast),
            None,
            &theme,
        );
        assert_eq!(t, "[fast]");
        // No failure markers → the delay shows even when untested links exist.
        let (t, _) = test_cell_content(false, true, false, None, None, Some(30), &theme);
        assert_eq!(t, "[ 30 ]");
    }

    #[test]
    fn untestable_marker_outranks_a_measured_delay() {
        let theme = test_theme();
        // A stored (fast) delay must not hide the "cannot be tested" status —
        // that is the whole point of the marker.
        let (t, s) = test_cell_content(false, true, true, None, None, Some(12), &theme);
        assert_eq!(t, "[real]");
        assert_eq!(s.fg, Some(theme.color("error").into()));
        // A genuine failure marker outranks a measured delay too — the marker
        // is the later, deeper statement about the link.
        let (t, _) = test_cell_content(
            false,
            true,
            false,
            None,
            Some(TestFailure::Real),
            Some(12),
            &theme,
        );
        assert_eq!(t, "[real]");
        // DNS-unresolved stays the deepest state.
        let (t, _) = test_cell_content(true, false, true, None, None, None, &theme);
        assert_eq!(t, "[name]");
    }
}
