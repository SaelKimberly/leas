use ratatui_cheese::theme::Palette;
use ratatui_themes::ThemePalette;

/// Map ratatui-themes `ThemePalette` → ratatui-cheese `Palette`.
///
/// `ThemePalette` has 10 semantic colors; `Palette` defines 11 roles.
/// This function maps each `ThemePalette` color to its closest `Palette` role.
#[must_use]
pub const fn from_theme_palette(p: &ThemePalette) -> Palette {
    Palette {
        foreground: p.fg,
        muted: p.muted,
        faint: p.muted, // ThemePalette has no third-tier color; muted is closest
        primary: p.accent,
        secondary: p.secondary,
        surface: p.selection,
        border: p.secondary,
        highlight: p.accent,
        on_highlight: p.fg,
        error: p.error,
        success: p.success,
    }
}

/// Get current ratatui-cheese `Palette` from a ratatui-themes `Theme`.
#[must_use]
pub const fn current_palette(theme: &ratatui_themes::Theme) -> Palette {
    from_theme_palette(&theme.palette())
}

/// Convenience — build a `cheese::Palette` from a `ThemeName` directly.
#[must_use]
pub const fn palette_from_name(name: &ratatui_themes::ThemeName) -> Palette {
    from_theme_palette(&name.palette())
}
