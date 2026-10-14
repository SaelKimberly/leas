//! Profiles export popup and dispatch.

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use leas_db::export::ExportScope;
use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use tui_popup::{KnownSizeWrapper, Popup};

use crate::ops::export::{self, ExportDestination};
use crate::ui::theme::ThemeStyles;
use crate::{AppMode, AppState, CoreEvent};

const SCOPES: [ExportScope; 4] = [
    ExportScope::Alive,
    ExportScope::Resolved,
    ExportScope::Active,
    ExportScope::Full,
];

const fn scope_label(scope: ExportScope) -> &'static str {
    match scope {
        ExportScope::Alive => "Only Alive",
        ExportScope::Resolved => "Only Resolved",
        ExportScope::Active => "Only Active",
        ExportScope::Full => "All Valid",
    }
}

pub async fn handle_key(key: &KeyEvent, state: &mut AppState) {
    match state.mode.clone() {
        AppMode::ExportScope { selected } => match key.code {
            KeyCode::Up => {
                if let AppMode::ExportScope { selected } = &mut state.mode {
                    *selected = selected.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                if let AppMode::ExportScope { selected } = &mut state.mode {
                    *selected = (*selected + 1).min(SCOPES.len() - 1);
                }
            }
            KeyCode::Enter => {
                state.mode = AppMode::ExportDestination {
                    scope: SCOPES[selected],
                    selected: 0,
                };
            }
            KeyCode::Esc => state.mode = AppMode::List,
            _ => {}
        },
        AppMode::ExportDestination { scope, selected } => match key.code {
            KeyCode::Up => {
                if let AppMode::ExportDestination { selected, .. } = &mut state.mode {
                    *selected = selected.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                if let AppMode::ExportDestination { selected, .. } = &mut state.mode {
                    *selected = (*selected + 1).min(1);
                }
            }
            KeyCode::Enter if selected == 0 => {
                dispatch(state, scope, ExportDestination::Clipboard, None);
            }
            KeyCode::Enter => {
                state.mode = AppMode::ExportPath {
                    scope,
                    input: export::default_export_path(scope)
                        .to_string_lossy()
                        .into_owned(),
                    overwrite: false,
                    error: None,
                };
            }
            KeyCode::Esc => state.mode = AppMode::List,
            _ => {}
        },
        AppMode::ExportPath {
            scope,
            input,
            overwrite,
            ..
        } => {
            if overwrite {
                match key.code {
                    KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                        dispatch(
                            state,
                            scope,
                            ExportDestination::File,
                            Some(PathBuf::from(input)),
                        );
                    }
                    KeyCode::Char('n' | 'N') | KeyCode::Esc => {
                        if let AppMode::ExportPath { overwrite, .. } = &mut state.mode {
                            *overwrite = false;
                        }
                    }
                    _ => {}
                }
                return;
            }
            match key.code {
                KeyCode::Char(c) => {
                    if let AppMode::ExportPath { input, .. } = &mut state.mode {
                        input.push(c);
                    }
                }
                KeyCode::Backspace => {
                    if let AppMode::ExportPath { input, .. } = &mut state.mode {
                        input.pop();
                    }
                }
                KeyCode::Enter => {
                    let path = PathBuf::from(input);
                    match tokio::fs::metadata(&path).await {
                        Ok(_) => {
                            if let AppMode::ExportPath { overwrite, .. } = &mut state.mode {
                                *overwrite = true;
                            }
                        }
                        Err(metadata_error)
                            if metadata_error.kind() == std::io::ErrorKind::NotFound =>
                        {
                            if let AppMode::ExportPath { error, .. } = &mut state.mode {
                                *error = None;
                            }
                            dispatch(state, scope, ExportDestination::File, Some(path));
                        }
                        Err(metadata_error) => {
                            if let AppMode::ExportPath { error, .. } = &mut state.mode {
                                *error = Some(metadata_error.to_string());
                            }
                        }
                    }
                }
                KeyCode::Esc => state.mode = AppMode::List,
                _ => {}
            }
        }
        _ => {}
    }
}

fn dispatch(
    state: &mut AppState,
    scope: ExportScope,
    destination: ExportDestination,
    path: Option<PathBuf>,
) {
    let db = state.db.clone();
    let tx = state.core_event_tx.clone();
    state.mode = AppMode::List;
    tokio::spawn(async move {
        let result = export::run_export(db, scope, destination, path.as_deref()).await;
        let event = match result {
            Ok(report) => CoreEvent::ExportFinished {
                report: Some(report),
                error: None,
            },
            Err(error) => CoreEvent::ExportFinished {
                report: None,
                error: Some(error.to_string()),
            },
        };
        if let Some(tx) = tx {
            let _ = tx.send(event).await;
        }
    });
}

pub fn render(frame: &mut Frame, area: ratatui::layout::Rect, state: &AppState) {
    let theme = state.theme();
    let lines = match &state.mode {
        AppMode::ExportScope { selected } => SCOPES
            .iter()
            .enumerate()
            .map(|(index, scope)| {
                let prefix = if index == *selected { "► " } else { "  " };
                menu_line(
                    format!("{prefix}{}", scope_label(*scope)),
                    index == *selected,
                    theme,
                )
            })
            .collect(),
        AppMode::ExportDestination { selected, .. } => ["Clipboard", "File"]
            .iter()
            .enumerate()
            .map(|(index, label)| {
                let prefix = if index == *selected { "► " } else { "  " };
                menu_line(format!("{prefix}{label}"), index == *selected, theme)
            })
            .collect(),
        AppMode::ExportPath {
            input,
            overwrite,
            error,
            ..
        } => {
            let mut lines = vec![Line::from(Span::raw(format!(" Path: {input}")))];
            if *overwrite {
                lines.push(Line::from(Span::styled(
                    " File exists. Overwrite? (y/N)",
                    ThemeStyles::error(theme),
                )));
            } else if let Some(error) = error {
                lines.push(Line::from(Span::styled(
                    format!(" Error: {error}"),
                    ThemeStyles::error(theme),
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    " Enter write  Esc cancel",
                    ThemeStyles::hint(theme),
                )));
            }
            lines
        }
        _ => return,
    };
    let title = match state.mode {
        AppMode::ExportScope { .. } => " Export Scope ",
        AppMode::ExportDestination { .. } => " Export Destination ",
        AppMode::ExportPath { .. } => " Export File ",
        _ => " Export ",
    };
    let height = (lines.len() as u16 + 2).min(area.height.saturating_sub(4));
    let width = 52.min(area.width.saturating_sub(4));
    let paragraph = Paragraph::new(lines).alignment(Alignment::Left);
    let popup = Popup::new(KnownSizeWrapper::new(
        paragraph,
        width as usize,
        height as usize,
    ))
    .title(title)
    .border_set(ratatui::symbols::border::ROUNDED)
    .style(ThemeStyles::dialog(theme));
    frame.render_widget(popup, area);
}

fn menu_line(text: String, selected: bool, theme: &opaline::Theme) -> Line<'static> {
    Line::from(Span::styled(
        text,
        if selected {
            ThemeStyles::table_row_selected(theme)
        } else {
            ThemeStyles::footer_value(theme)
        },
    ))
}
