//! The app's colour vocabulary, backed by opaline tokens.
//!
//! Every style the UI draws is named here once and resolved from the loaded
//! [`Theme`](opaline::Theme) — no hex, no `Color::*` literal, and no theme
//! bridge. The 28 core tokens and 14 styles opaline's contract guarantees in
//! every theme cover most roles directly; the roles it does not name
//! (`table.header`, `statusbar`, the progress bar) are **registered** on the
//! theme at load time with [`Theme::register_default_token`] /
//! [`Theme::register_default_style`], so a user TOML can still override them.
//!
//! Why registration rather than literals: the earlier `Color::Gray` status-bar
//! hint was unreadable on a light theme (≈1.2:1 — measured, see
//! `docs/guides/tui/`). A token resolves per theme, so the same role is legible
//! on both.

use opaline::style::OpalineStyle;
use opaline::{OpalineColor, Theme};
use ratatui::style::{Color, Modifier, Style};

/// Register the app's own tokens and styles on a freshly loaded theme.
///
/// `register_default_*` only fills gaps, so a theme (or a user TOML that
/// already defines `table.header`) wins over the derivation.
#[must_use]
pub fn with_app_roles(mut theme: Theme) -> Theme {
    // Roles opaline's 14 core styles do not name.
    theme.register_default_style(
        "app.table_header",
        OpalineStyle::fg(theme.color("text.primary"))
            .with_bg(theme.color("bg.selection"))
            .bold(),
    );
    theme.register_default_style(
        "app.statusbar",
        OpalineStyle::fg(theme.color("text.primary")).with_bg(theme.color("bg.selection")),
    );
    theme.register_default_style(
        "app.progress_bar",
        OpalineStyle::fg(theme.color("text.primary")).with_bg(theme.color("bg.selection")),
    );
    theme.register_default_style(
        "app.progress_fill",
        OpalineStyle::fg(theme.color("accent.primary")).with_bg(theme.color("accent.primary")),
    );
    theme.register_default_style(
        "app.dialog",
        OpalineStyle::fg(theme.color("text.primary")).with_bg(theme.color("bg.elevated")),
    );
    theme.register_default_style(
        "app.table_row_alt",
        OpalineStyle::fg(theme.color("text.primary")).with_bg(theme.color("bg.panel")),
    );
    theme.register_default_style(
        "app.badge",
        OpalineStyle::fg(theme.color("error")).with_bg(theme.color("bg.elevated")),
    );
    theme
}

/// Load a theme by its kebab-case slug, with the app's roles registered.
///
/// An unknown slug is an error, not a silent fallback: the earlier bridge
/// defaulted quietly, which is how a walkthrough once measured the wrong theme
/// (`docs/guides/tui/2026-10-14-144700-scenario-colour-focus-audit.md`).
pub fn load(slug: &str) -> Result<Theme, String> {
    opaline::load_by_name(slug)
        .map(with_app_roles)
        .ok_or_else(|| format!("unknown theme `{slug}` — run `just themes` to list the builtins"))
}

/// The style names the UI refers to, in one place.
///
/// The old `ThemeStyles` took a `&Palette`; these take the theme itself, so a
/// call site reads `ThemeStyles::hint(state.theme())`.
pub struct ThemeStyles;

impl ThemeStyles {
    // ── Tab bar ─────────────────────────────────────────────────────────
    #[must_use]
    pub fn tab_selected(theme: &Theme) -> Style {
        theme.style("active_selected").into()
    }
    #[must_use]
    pub fn tab_deselected(theme: &Theme) -> Style {
        theme.style("muted").into()
    }

    // ── Table / profile grid ────────────────────────────────────────────
    #[must_use]
    pub fn table_header(theme: &Theme) -> Style {
        theme.style("app.table_header").into()
    }
    #[must_use]
    pub fn table_row_selected(theme: &Theme) -> Style {
        theme.style("selected").into()
    }
    #[must_use]
    pub fn table_row_normal(theme: &Theme) -> Style {
        Style::default().fg(theme.color("text.primary").into())
    }
    #[must_use]
    pub fn table_row_alt(theme: &Theme) -> Style {
        theme.style("app.table_row_alt").into()
    }
    #[must_use]
    pub fn table_row_connected(theme: &Theme) -> Style {
        theme.style("active_selected").into()
    }
    /// The notch inside an expanded endpoint. opaline has no "Reset" colour, and
    /// this is the one place that needs it: the expanded panel sits on the row's
    /// `surface` fill, so the selected sub-row has to *clear* the inherited
    /// background rather than leave it (`Cell::set_style` merges), otherwise the
    /// whole block reads as one highlight with no notch for the active variant.
    #[must_use]
    pub fn panel_row_selected(theme: &Theme) -> Style {
        Style::default()
            .fg(theme.color("text.primary").into())
            .bg(Color::Reset)
            .add_modifier(Modifier::BOLD)
    }

    // ── Profiles Test column ────────────────────────────────────────────
    #[must_use]
    pub fn test_delay_ok(theme: &Theme) -> Style {
        theme.style("success_style").into()
    }
    #[must_use]
    pub fn test_delay_warn(theme: &Theme) -> Style {
        theme.style("warning_style").into()
    }
    #[must_use]
    pub fn test_delay_bad(theme: &Theme) -> Style {
        theme.style("error_style").into()
    }

    // ── Containers / borders ────────────────────────────────────────────
    #[must_use]
    pub fn container_border(theme: &Theme) -> Style {
        theme.style("unfocused_border").into()
    }
    #[must_use]
    pub fn container_border_focused(theme: &Theme) -> Style {
        theme.style("focused_border").into()
    }
    #[must_use]
    pub fn container_title(theme: &Theme) -> Style {
        theme.style("keyword").into()
    }

    // ── Status bar ──────────────────────────────────────────────────────
    #[must_use]
    pub fn status_bar_bg(theme: &Theme) -> Style {
        theme.style("app.statusbar").into()
    }
    #[must_use]
    pub fn status_bar_mode(theme: &Theme) -> Style {
        theme.style("active_selected").into()
    }
    #[must_use]
    pub fn status_bar_hint(theme: &Theme) -> Style {
        theme.style("muted").into()
    }

    // ── Feedback / progress ─────────────────────────────────────────────
    #[must_use]
    pub fn progress_bar(theme: &Theme) -> Style {
        theme.style("app.progress_bar").into()
    }
    #[must_use]
    pub fn progress_fill(theme: &Theme) -> Style {
        theme.style("app.progress_fill").into()
    }
    #[must_use]
    pub fn spinner(theme: &Theme) -> Style {
        theme.style("keyword").into()
    }

    // ── Semantic ───────────────────────────────────────────────────────
    #[must_use]
    pub fn error(theme: &Theme) -> Style {
        theme.style("error_style").into()
    }
    #[must_use]
    pub fn warning(theme: &Theme) -> Style {
        theme.style("warning_style").into()
    }
    #[must_use]
    pub fn success(theme: &Theme) -> Style {
        theme.style("success_style").into()
    }
    #[must_use]
    pub fn hint(theme: &Theme) -> Style {
        theme.style("muted").into()
    }
    #[must_use]
    pub fn badge(theme: &Theme) -> Style {
        theme.style("app.badge").into()
    }

    // ── Dialogs ─────────────────────────────────────────────────────────
    /// The dialog's fill and text. The red *border* stays semantic and is
    /// applied by the caller with [`Self::error`].
    #[must_use]
    pub fn dialog(theme: &Theme) -> Style {
        theme.style("app.dialog").into()
    }

    // ── Footer ──────────────────────────────────────────────────────────
    #[must_use]
    pub fn status_footer(theme: &Theme) -> Style {
        theme.style("app.statusbar").into()
    }
    #[must_use]
    pub fn footer_label(theme: &Theme) -> Style {
        theme.style("muted").into()
    }
    #[must_use]
    pub fn footer_value(theme: &Theme) -> Style {
        Style::default().fg(theme.color("text.primary").into())
    }

    // ── Log levels ──────────────────────────────────────────────────────
    #[must_use]
    pub fn log_error(theme: &Theme) -> Style {
        Style::from(theme.style("error_style")).add_modifier(Modifier::BOLD)
    }
    #[must_use]
    pub fn log_warning(theme: &Theme) -> Style {
        theme.style("warning_style").into()
    }
    #[must_use]
    pub fn log_info(theme: &Theme) -> Style {
        Style::default().fg(theme.color("text.primary").into())
    }
    #[must_use]
    pub fn log_debug(theme: &Theme) -> Style {
        theme.style("muted").into()
    }

    // ── Scrollbar ───────────────────────────────────────────────────────
    #[must_use]
    pub fn scrollbar_thumb(theme: &Theme) -> Style {
        Style::default()
            .fg(theme.color("accent.primary").into())
            .bg(theme.color("bg.selection").into())
    }
    #[must_use]
    pub fn scrollbar_track(theme: &Theme) -> Style {
        Style::default().bg(theme.color("bg.selection").into())
    }
}

/// Convert an opaline colour straight to a ratatui colour.
#[must_use]
pub fn color_of(c: OpalineColor) -> ratatui::style::Color {
    c.into()
}

/// cheese's own `Palette`, derived from the opaline theme.
///
/// ratatui-cheese survives only as a widget toolkit (`Tree`, `List`, `Input`,
/// `Select`) and those widgets take its `Palette`; this is the **only** place
/// that shape appears, so a widget never introduces a colour the theme does
/// not define.
#[must_use]
pub fn widget_palette(theme: &Theme) -> ratatui_cheese::theme::Palette {
    use ratatui_cheese::theme::Palette;
    Palette {
        foreground: theme.color("text.primary").into(),
        muted: theme.color("text.muted").into(),
        faint: theme.color("text.dim").into(),
        primary: theme.color("accent.primary").into(),
        secondary: theme.color("accent.secondary").into(),
        surface: theme.color("bg.selection").into(),
        border: theme.color("border.unfocused").into(),
        highlight: theme.color("bg.active").into(),
        on_highlight: theme.color("text.primary").into(),
        error: theme.color("error").into(),
        success: theme.color("success").into(),
    }
}
