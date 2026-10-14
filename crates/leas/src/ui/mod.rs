pub mod actions_log;
pub mod add_server;
pub mod export;
pub mod logs;
pub mod native_activity;
pub mod profiles;
pub mod settings;
pub mod statistics;
pub mod status_bar;
pub mod theme;
pub mod widgets;
use crate::ui::theme::ThemeStyles;
use crate::{AppMode, AppState, ConfirmAction, Tab};
use crossterm::cursor::SetCursorStyle;
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent, MouseEventKind,
};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use leas_config::subscription::subscription_url_split;
use leas_db::profiles_query::PlanScope;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs};
use ratatui::{Frame, Terminal};
use std::io;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tui_popup::{KnownSizeWrapper, Popup};

pub fn render_confirmation_overlay(
    frame: &mut Frame,
    area: Rect,
    text: &str,
    theme: &opaline::Theme,
) {
    use unicode_width::UnicodeWidthStr;
    let width = text.width() as u16 + 2;
    let height = 3u16;

    if area.width < width + 2 || area.height < height + 2 {
        return;
    }

    let para = Paragraph::new(text.to_string())
        .style(ThemeStyles::container_title(theme))
        .alignment(Alignment::Center);
    let sized = KnownSizeWrapper::new(para, width as usize, height as usize);
    let popup = Popup::new(sized)
        .title(" Confirm ")
        .border_set(ratatui::symbols::border::ROUNDED)
        .border_style(ThemeStyles::error(theme))
        .style(ThemeStyles::dialog(theme));
    frame.render_widget(popup, area);
}

/// Render the correct confirmation text for any `ConfirmAction` variant.
/// Call once per render path instead of duplicating per-variant checks.
pub fn render_any_confirmation(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let text = match state.confirmation {
        Some(crate::ConfirmAction::Quit) => " Quit? (y/N) ",
        Some(crate::ConfirmAction::ClearStats) => " Clear all stats? (y/N) ",
        Some(crate::ConfirmAction::ClearLogs) => " Clear logs? (y/N) ",
        Some(crate::ConfirmAction::PurgeLogsDatabase) => " Purge logs database? (y/N) ",
        _ => return,
    };
    render_confirmation_overlay(frame, area, text, theme);
}
// ── Entry point ───────────────────────────────────────────────────────

pub async fn run(state: &mut AppState) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let ts = terminal.size().unwrap_or_default();
    state.actions_compact = ts.height < 20;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(64);
    // Terminal input runs on the blocking pool, and `Runtime::drop` (in `main`)
    // waits for in-flight blocking work — a bare `event::read()` parks until the
    // next keypress, which is why quitting used to leave the process alive with
    // the runtime waiting on a reader nobody would ever feed again. Poll in
    // slices and exit on the shutdown flag instead.
    let reader_shutdown = state.shutdown_token.clone();

    // The country drain: one owner for every `(endpoint, address, country)`
    // write the enrichment fan-out produces. Without it each row opened its own
    // transaction inside the resolution task (T7).
    crate::ops::enrich::spawn_geo_drain(state.db.clone(), state.shutdown_token.clone());

    // PSL-version guard (db-rewamp D2): the DNS-name split, and therefore every
    // endpoint's identity, is a function of the `psl2` Public Suffix List the
    // build embedded. A `cargo update` that moves it can re-key or reject hosts
    // with no code change, so a mismatch is surfaced (re-import) rather than
    // allowed to shift silently.
    let psl = leas_config::domain::psl_version();
    match state.db.meta_get("psl_version").await {
        Ok(Some(stored)) if stored != psl => {
            state.log_trace(
                "warn",
                "tui::state",
                &format!(
                    "public-suffix list changed ({stored} -> {psl}); stored endpoint \
                     identities may be stale — re-import the feed"
                ),
            );
        }
        Ok(_) => {
            if let Err(e) = state.db.meta_set("psl_version", psl).await {
                tracing::warn!(target: "tui::state", "psl_version stamp failed: {e}");
            }
        }
        Err(e) => tracing::warn!(target: "tui::state", "psl_version read failed: {e}"),
    }

    tokio::task::spawn_blocking(move || {
        /// Idle poll slice: the quit path waits at most this long for the reader.
        const IDLE_POLL: Duration = Duration::from_millis(200);
        loop {
            match event::poll(IDLE_POLL) {
                Ok(true) => match event::read() {
                    Ok(ev) => {
                        if tx.blocking_send(ev).is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                },
                // Idle slice elapsed: the only chance to notice the quit.
                Ok(false) => {
                    if reader_shutdown.load(Ordering::Relaxed) {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    // The startup envelope is logged once the first page has landed: it names
    // the loaded page size, which is zero while the tab is still loading.
    let mut envelope_logged = false;
    let refresh_interval = *state.config.gui.refresh_interval_secs;
    let mut last_tick = std::time::Instant::now();
    // Set when a Resize event is drained; forces the next loop iteration to redraw.
    let mut resize_seen = false;
    // Set when any other event was handled; renders input changes promptly.
    let mut events_seen = false;

    // (channels already created in AppState::new)

    // Trigger startup version check if enabled
    if state.config.updates.check_on_startup {
        state.spawn_update_check();
    }

    // Initial logs no longer loaded here — deferred to first Logs tab access (lazy loading).
    // Draw the first frame now; the gate below would otherwise wait a full
    // refresh_interval before anything appears on screen.
    state.term_height.set(ts.height);
    terminal.draw(|f| render(f, &*state))?;
    while !state.should_quit {
        // Process up to N events per frame to prevent input lag under held keys
        const MAX_EVENTS_PER_FRAME: usize = 100;
        for i in 0..MAX_EVENTS_PER_FRAME {
            match rx.try_recv() {
                Ok(ev) => {
                    if matches!(&ev, Event::Resize(_, _)) {
                        // Process resize immediately — keep draining for more
                        resize_seen = true;
                        handle_event(&ev, state).await;
                        continue;
                    }
                    handle_event(&ev, state).await;
                    // Non-resize: stop after this event so the events_seen draw fires promptly
                    events_seen = true;
                    if i < MAX_EVENTS_PER_FRAME - 1 {
                        continue;
                    }
                    break;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    state.should_quit = true;
                    break;
                }
            }
        }

        // Process core process events (connect/disconnect/error). When any
        // event was handled, mark the frame dirty so async state changes
        // (ping results, connect/disconnect, stats, logs, batch progress)
        // render immediately instead of waiting for the idle refresh cadence.
        if state.poll_core_events().await {
            events_seen = true;
        }

        // Refetch the Profiles page when something invalidated it: a ping
        // result (the row must move to its new place), a search keystroke, a
        // sort or view change, a delete. The reload preserves the selection by
        // endpoint id and re-anchors the window on it, so a reorder never
        // scrolls the user away. One reload per tick, at most.
        if !state.filter_cache_valid.get() {
            state.filter_cache_valid.set(true);
            crate::ops::profiles::reload_profiles_preserving_selection(state).await;
            events_seen = true;
        }

        // Lazy-load initial logs on first Logs tab access
        if !state.logs_loaded && state.current_tab == Tab::Logs {
            state.load_initial_logs().await;
            state.logs_loaded = true;
        }

        // Progressive log loading: one batch per frame for Home key
        if state.log_seek_home {
            crate::ui::logs::try_load_older(state).await;
            if !state.log_has_older {
                let filtered = crate::ui::logs::count_filtered(state);
                state.log_scroll = filtered.saturating_sub(1);
                state.log_seek_home = false;
            }
        }

        if state.current_tab == Tab::Logs && state.log_scroll == 0 {
            let now = std::time::Instant::now();
            if now.duration_since(state.last_heed_poll) >= std::time::Duration::from_millis(100) {
                state.last_heed_poll = now;
                crate::ui::logs::poll_new_logs(state).await;
            }
        }

        let ts = terminal.size().unwrap_or_default();
        state.term_height.set(ts.height);
        // Draw when events were handled (input stays responsive), when a resize was
        // seen (immediate redraw), or at the refresh cadence while idle (default 5s —
        // previously the draw ran every 16ms frame at 60fps).
        if !envelope_logged && !state.endpoints.is_empty() {
            crate::ops::ping::log_startup_envelope(state);
            envelope_logged = true;
        }
        if resize_seen || events_seen || last_tick.elapsed() >= refresh_interval {
            last_tick = std::time::Instant::now();
            resize_seen = false;
            events_seen = false;
            terminal.draw(|f| render(f, &*state))?;
        }
        // Keep the cheap 16ms wakeup so events are serviced promptly.
        tokio::time::sleep(Duration::from_millis(16)).await;
    }
    // Signal background tasks to stop and disconnect core. `disconnect()`
    // stores its bounded teardown waiter in `core_task_handle`; await it here
    // (bounded, UI thread idle at exit) so the native core's graceful
    // shutdown — `server.shutdown()`, the `Disconnected` event — runs before
    // the process leaves the alternate screen. Unbounded wait would hang a
    // wedged core, so the 3 s cap aborts instead.
    state.disconnect();
    if let Some(handle) = state.core_task_handle.take() {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
    }
    // Stops the background loops, INCLUDING the blocking heed log writer — the
    // tokio runtime drop in `main` waits for in-flight `spawn_blocking` work, so
    // a writer that never noticed shutdown would hang the process at exit.
    state.shutdown_token.store(true, Ordering::Relaxed);

    // Persist anything still staged (ping results, scheduler transitions)
    // before the runtime goes away.
    if let Err(e) = state.link_stage.flush().await {
        tracing::warn!(target: "tui::ui", "final link flush failed: {e}");
    }

    // A batch that was still running when the user quit never reaches its own
    // `batch summary` line (the runtime drop cancels the task), which is how
    // the 2026-09-16 run left 31k persisted results with no record of the run
    // in the log — and the per-class histograms only the summary carries were
    // lost with it. The handle published at batch start is reachable here, so
    // the interrupted run reports the SAME line a completed run writes, plus
    // what has settled and what is still in flight. The meters alone cannot:
    // they are a live view, not a record, so the fallback names only what is
    // known without the handle.
    if let Some(meters) = &state.batch_progress {
        if let Some(shared) = state.batch.as_ref().and_then(|slot| slot.get()) {
            tracing::info!(
                target: "tui::ops::ping",
                "{}",
                crate::ops::ping::interrupted_summary_line(shared),
            );
        } else {
            let (fast_done, fast_total) = (
                meters.fast.done.load(Ordering::Relaxed),
                meters.fast.total.load(Ordering::Relaxed),
            );
            let (real_done, real_total) = (
                meters.real.done.load(Ordering::Relaxed),
                meters.real.total.load(Ordering::Relaxed),
            );
            tracing::info!(
                target: "tui::ops::ping",
                "batch interrupted at quit: fast {fast_done}/{fast_total} probe(s), real {real_done}/{real_total} probe(s) reported, no batch summary; staged writes flushed, {} left staged",
                state.link_stage.staged_len(),
            );
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), DisableMouseCapture)?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    Ok(())
}

// ── Event handling ────────────────────────────────────────────────────

async fn handle_event(ev: &Event, state: &mut AppState) {
    match ev {
        // Only a key-DOWN is an action. A Windows console delivers a key-up
        // record for every keypress and crossterm maps it to
        // `KeyEventKind::Release` (`event/sys/windows/parse.rs`), so acting on
        // every `Event::Key` applied each press twice there — and doubled every
        // pasted character too, since the terminal injects a paste as key
        // records. Unix terminals report only `Press`, which is why the defect
        // was Windows-only.
        Event::Key(key) if key.kind == KeyEventKind::Press => handle_key(key, state).await,
        Event::Mouse(mouse) => handle_mouse(mouse, state).await,
        _ => {}
    }
}

async fn handle_mouse(mouse: &MouseEvent, state: &mut AppState) {
    match mouse.kind {
        MouseEventKind::ScrollUp => {
            let key = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
            handle_key(&key, state).await;
        }
        MouseEventKind::ScrollDown => {
            let key = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
            handle_key(&key, state).await;
        }
        MouseEventKind::ScrollLeft => {
            let key = KeyEvent::new(KeyCode::Left, KeyModifiers::NONE);
            handle_key(&key, state).await;
        }
        MouseEventKind::ScrollRight => {
            let key = KeyEvent::new(KeyCode::Right, KeyModifiers::NONE);
            handle_key(&key, state).await;
        }
        _ => {}
    }
}
async fn handle_key(key: &KeyEvent, state: &mut AppState) {
    // Delete confirmation: only y/n/esc — check before mode dispatch so
    // confirmation is handled even when inside a sub-mode like settings.
    if state.confirmation.is_some() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => match state.confirmation.take() {
                Some(ConfirmAction::DeleteProfile(id)) => state.delete_profile(id).await,
                Some(ConfirmAction::DeleteGroup(id)) => state.delete_group(&id).await,
                Some(ConfirmAction::DeleteProfiles(ids)) => {
                    for id in &ids {
                        state.delete_profile(*id).await;
                    }
                    state.multi_select.clear();
                }
                Some(ConfirmAction::ClearGroup(id)) => state.clear_group(&id).await,
                Some(ConfirmAction::Quit) => {
                    state.disconnect();
                    state.should_quit = true;
                }
                Some(ConfirmAction::ClearLogs) => state.clear_logs(),
                Some(ConfirmAction::PurgeLogsDatabase) => state.purge_logs_database(),
                Some(ConfirmAction::ClearStats) => state.clear_all_stats().await,
                None => {}
            },
            KeyCode::Char('n' | 'N' | 'q' | 'Q') | KeyCode::Esc => {
                state.confirmation = None;
            }
            _ => {}
        }
        return;
    }

    // F1 toggles actions panel compact/full — works across all modes
    if matches!(key.code, KeyCode::F(1)) {
        state.actions_compact = !state.actions_compact;
        return;
    }

    // Settings mode: route to settings handler (with Ctrl+C quit)
    if matches!(&state.mode, crate::AppMode::Settings { .. }) {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if state.connected_core.is_some() && state.confirmation.is_none() {
                    state.confirmation = Some(ConfirmAction::Quit);
                } else {
                    state.should_quit = true;
                }
            }
            _ => settings::handle_key(state, key).await,
        }
        return;
    }

    // BatchImport: route all keys to batch import handler
    if matches!(&state.mode, crate::AppMode::BatchImport { .. }) {
        add_server::handle_batch_import_key(state, key).await;
        return;
    }

    // Form mode: route all keys to add_server handler (except Ctrl+C quit, SpeedTestMenu, BatchImport, TargetPicker)
    if !matches!(state.mode, crate::AppMode::List)
        && !matches!(&state.mode, crate::AppMode::Help)
        && !matches!(
            &state.mode,
            crate::AppMode::SpeedTestMenu { .. }
                | crate::AppMode::ExportScope { .. }
                | crate::AppMode::ExportDestination { .. }
                | crate::AppMode::ExportPath { .. }
                | crate::AppMode::BatchImport { .. }
                | crate::AppMode::TargetPicker { .. }
        )
    {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if state.connected_core.is_some() && state.confirmation.is_none() {
                    state.confirmation = Some(ConfirmAction::Quit);
                } else {
                    state.should_quit = true;
                }
            }
            _ => add_server::handle_key(state, key).await,
        }
        return;
    }

    // Search mode captures all alphanumeric input
    if state.search_focused {
        match key.code {
            KeyCode::Char(c) => {
                state.search_query.push(c);
                state.filter_cache_valid.set(false);
            }
            KeyCode::Backspace => {
                state.search_query.pop();
                state.filter_cache_valid.set(false);
            }
            KeyCode::Esc => {
                state.search_focused = false;
                state.search_query.clear();
                state.filter_cache_valid.set(false);
                let _ = execute!(std::io::stdout(), SetCursorStyle::DefaultUserShape);
            }
            _ => {}
        }
        return;
    }

    // Export popup mode
    if matches!(
        &state.mode,
        crate::AppMode::ExportScope { .. }
            | crate::AppMode::ExportDestination { .. }
            | crate::AppMode::ExportPath { .. }
    ) {
        export::handle_key(key, state).await;
        return;
    }

    // Speed test menu mode
    if matches!(&state.mode, crate::AppMode::SpeedTestMenu { .. }) {
        let sep_idx = SPEED_TEST_MENU_ITEMS
            .iter()
            .position(|item| matches!(item, SpeedTestMenuItem::Separator));
        let max = SPEED_TEST_MENU_ITEMS.len().saturating_sub(1);
        match key.code {
            KeyCode::Up => {
                if let crate::AppMode::SpeedTestMenu { ref mut selected } = state.mode {
                    *selected = selected.saturating_sub(1);
                    // Skip the separator using typed check
                    if let Some(sep) = sep_idx
                        && *selected == sep
                    {
                        *selected = sep.saturating_sub(1);
                    }
                }
            }
            KeyCode::Down => {
                if let crate::AppMode::SpeedTestMenu { ref mut selected } = state.mode {
                    if *selected < max {
                        *selected += 1;
                    }
                    // Skip the separator using typed check
                    if let Some(sep) = sep_idx
                        && *selected == sep
                    {
                        *selected = sep.saturating_add(1);
                    }
                }
            }
            KeyCode::Enter => {
                let selected = match &state.mode {
                    crate::AppMode::SpeedTestMenu { selected } => *selected,
                    _ => 0,
                };
                state.mode = crate::AppMode::List;
                // Resolve the target protocol id + row shape before dispatch.
                // Collapsed endpoint rows with >1 protocols run an
                // endpoint-scoped batch; sub-rows ping the exact protocol.
                let on_sub = state.is_on_sub_row();
                let ep_id = state.selected_profile_id();
                let (proto_id, multi) = {
                    let row = ep_id
                        .and_then(|id| state.endpoints.iter().find(|r| r.endpoint.id.get() == id));
                    let multi = row.is_some_and(|r| r.protocols.len() > 1);
                    let pid = if on_sub {
                        state.selected_sub_protocol_id()
                    } else {
                        row.and_then(|r| r.active_protocol().map(|(_, p)| p.id.get()))
                    };
                    (pid, multi)
                };
                match selected {
                    0 => {
                        if on_sub || !multi {
                            if let Some(id) = proto_id {
                                state.start_tcp_ping(ep_id.unwrap_or_default(), id);
                            }
                        } else {
                            state.start_endpoint_batch_ping();
                        }
                    }
                    1 => {
                        if on_sub || !multi {
                            if let Some(id) = proto_id {
                                state.start_real_ping(ep_id.unwrap_or_default(), id);
                            }
                        } else {
                            state.start_endpoint_batch_real_ping();
                        }
                    }
                    2 => {
                        if let Some(id) = proto_id {
                            state.start_speed_test(ep_id.unwrap_or_default(), id);
                        }
                    }
                    3 => {
                        if let Some(id) = proto_id {
                            state.start_udp_test(ep_id.unwrap_or_default(), id);
                        }
                    }
                    5 => {
                        state.start_batch_ping();
                    }
                    6 => {
                        state.start_batch_then_real_ping();
                    }
                    7 => {
                        state.start_batch_then_real_ping_scoped(PlanScope::Successful);
                    }
                    8 => {
                        state.start_batch_then_real_ping_scoped(PlanScope::New);
                    }
                    9 => {
                        state.start_batch_then_real_ping_scoped(PlanScope::SuccessfulAndNew);
                    }
                    10 => {
                        state.start_batch_then_real_ping_scoped(PlanScope::Failed);
                    }
                    12 => {
                        state.remove_failed_servers().await;
                    }
                    14 => {
                        state.stop_speed_test();
                    }
                    16 => {
                        state.confirmation = Some(crate::ConfirmAction::ClearStats);
                    }
                    _ => {}
                }
            }

            KeyCode::Esc => {
                state.mode = crate::AppMode::List;
            }
            KeyCode::Char('?') => {
                state.mode = crate::AppMode::Help;
            }
            _ => {}
        }
        return;
    }

    // Logs tab: route logs-specific keys (scroll, filter, copy, selection)
    if state.current_tab == crate::Tab::Logs && matches!(state.mode, crate::AppMode::List) {
        let is_logs_key = matches!(
            key.code,
            KeyCode::Up
                | KeyCode::Down
                | KeyCode::PageUp
                | KeyCode::PageDown
                | KeyCode::Home
                | KeyCode::End
                | KeyCode::Delete
                | KeyCode::Esc
                | KeyCode::Char('c' | 'd' | 't' | 'T' | 'y' | 'Y')
        ) && !key.modifiers.contains(KeyModifiers::CONTROL);
        if is_logs_key {
            logs::handle_key(state, key).await;
            return;
        }
        // else: fall through to main handler for quit/tab/help/etc.
    }

    // NativeActivity tab: route scroll keys to the screen handler
    if state.current_tab == crate::Tab::NativeActivity && matches!(state.mode, crate::AppMode::List)
    {
        let is_native_activity_key = matches!(
            key.code,
            KeyCode::Up
                | KeyCode::Down
                | KeyCode::PageUp
                | KeyCode::PageDown
                | KeyCode::Home
                | KeyCode::End
        ) && !key.modifiers.contains(KeyModifiers::CONTROL);
        if is_native_activity_key {
            native_activity::handle_key(state, key);
            return;
        }
        // else: fall through to main handler for quit/tab/help/etc.
    }

    // TargetPicker mode: route to target picker handler
    if matches!(&state.mode, crate::AppMode::TargetPicker { .. }) {
        logs::handle_target_picker_key(state, key);
        return;
    }

    match key.code {
        // Help mode: Esc or ? to close, ignore other keys
        KeyCode::Char('?') | KeyCode::Esc if matches!(&state.mode, crate::AppMode::Help) => {
            state.mode = *state
                .previous_mode
                .take()
                .unwrap_or_else(|| Box::new(crate::AppMode::List));
        }
        // Open help overlay from List mode
        KeyCode::Char('?') if !matches!(&state.mode, crate::AppMode::Help) => {
            state.previous_mode = Some(Box::new(state.mode.clone()));
            state.mode = crate::AppMode::Help;
        }
        KeyCode::Char('q' | 'Q') => {
            if state.connected_core.is_some() && state.confirmation.is_none() {
                state.confirmation = Some(ConfirmAction::Quit);
            } else {
                state.should_quit = true;
            }
        }
        KeyCode::Char('d')
            if key.modifiers.contains(KeyModifiers::CONTROL) && state.connected_core.is_some() =>
        {
            state.disconnect();
        }

        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if state.connected_core.is_some() && state.confirmation.is_none() {
                state.confirmation = Some(ConfirmAction::Quit);
            } else {
                state.should_quit = true;
            }
        }
        KeyCode::Tab => {
            let idx = Tab::ALL
                .iter()
                .position(|t| *t == state.current_tab)
                .unwrap_or(0);
            state.current_tab = Tab::ALL[(idx + 1) % Tab::ALL.len()];
            if state.current_tab == Tab::Settings && matches!(state.mode, AppMode::List) {
                state.enter_settings();
            }
        }
        KeyCode::BackTab => {
            let idx = Tab::ALL
                .iter()
                .position(|t| *t == state.current_tab)
                .unwrap_or(0);
            state.current_tab = if idx == 0 {
                Tab::ALL[Tab::ALL.len() - 1]
            } else {
                Tab::ALL[idx - 1]
            };
            if state.current_tab == Tab::Settings && matches!(state.mode, AppMode::List) {
                state.enter_settings();
            }
        }
        KeyCode::Up if state.current_tab == Tab::Profiles => {
            if !state.nav_protocol_up() {
                crate::ops::profiles::move_selection(state, -1).await;
            }
        }
        KeyCode::Down if state.current_tab == Tab::Profiles => {
            if !state.nav_protocol_down() {
                crate::ops::profiles::move_selection(state, 1).await;
            }
        }
        KeyCode::Home if state.current_tab == Tab::Profiles => {
            crate::ops::profiles::goto_first(state).await;
        }
        KeyCode::End if state.current_tab == Tab::Profiles => {
            crate::ops::profiles::goto_last(state).await;
        }
        KeyCode::PageUp if state.current_tab == Tab::Profiles => {
            let page = state.term_height.get().saturating_sub(5) as isize;
            state.selected_sub = None;
            crate::ops::profiles::move_selection(state, -page).await;
        }
        KeyCode::PageDown if state.current_tab == Tab::Profiles => {
            let page = state.term_height.get().saturating_sub(5) as isize;
            state.selected_sub = None;
            crate::ops::profiles::move_selection(state, page).await;
        }
        KeyCode::Up
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && state.current_tab == Tab::Profiles =>
        {
            state.move_profile_up();
        }
        KeyCode::Down
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && state.current_tab == Tab::Profiles =>
        {
            state.move_profile_down();
        }
        KeyCode::Enter | KeyCode::Char('g')
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && state.current_tab == Tab::Profiles =>
        {
            if let Some(id) = state.selected_profile_id() {
                state.connect_to_profile(id);
            }
        }
        KeyCode::Right if state.current_tab == Tab::Profiles => {
            state.toggle_expand();
        }
        KeyCode::Left if state.current_tab == Tab::Profiles => {
            state.collapse_expand();
        }
        KeyCode::Enter if state.current_tab == Tab::Profiles => {
            if state.is_on_sub_row() {
                // Pin the selected protocol as the endpoint's default.
                let ep_id = state.selected_profile_id();
                let proto_id = state.selected_sub_protocol_id();
                if let (Some(ep), Some(p)) = (ep_id, proto_id) {
                    state.set_protocol_default(ep, p).await;
                }
            } else if let Some(id) = state.selected_profile_id() {
                state.set_active(&id.to_string()).await;
            }
        }
        KeyCode::Enter if state.current_tab == Tab::Settings => {
            state.enter_settings();
        }
        KeyCode::Char(' ') if state.current_tab == Tab::Profiles => {
            if let Some(id) = state.selected_profile_id() {
                state.toggle_multi_select(id);
            }
        }
        // Ctrl+A: select all filtered profiles
        KeyCode::Char('a')
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && state.current_tab == Tab::Profiles =>
        {
            let ids: Vec<i64> = state
                .filtered_profiles()
                .map(|r| r.endpoint.id.get())
                .collect();
            for id in ids {
                state.multi_select.insert(id);
            }
        }
        // Ctrl+G: deselect all (Ctrl+Shift+A is the same as Ctrl+A on most terminals)
        KeyCode::Char('g')
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && state.current_tab == Tab::Profiles =>
        {
            state.multi_select.clear();
        }
        KeyCode::Char('/') if state.current_tab == Tab::Profiles => {
            state.search_focused = true;
            state.search_query.clear();
            state.filter_cache_valid.set(false);
            let _ = execute!(std::io::stdout(), SetCursorStyle::BlinkingBlock);
        }
        KeyCode::Char('e')
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && state.current_tab == Tab::Profiles =>
        {
            state.mode = crate::AppMode::ExportScope { selected: 0 };
        }
        // Speed test menu
        KeyCode::Char('t' | 'T') if state.current_tab == Tab::Profiles => {
            state.mode = crate::AppMode::SpeedTestMenu { selected: 0 };
        }
        // Stop current speed test
        KeyCode::Char('s' | 'S')
            if state.current_tab == Tab::Profiles && !state.testing_profiles.is_empty() =>
        {
            state.stop_speed_test();
            state.log_trace("info", "tui::ui", "Speed test stopped by user");
        }
        // CRUD shortcuts (profiles tab)
        KeyCode::Char('a' | 'A') if state.current_tab == Tab::Profiles => {
            state.start_add_server();
        }
        KeyCode::Char('e' | 'E')
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && state.current_tab == Tab::Profiles =>
        {
            if let Some(id) = state.selected_profile_id() {
                state.start_edit_profile(&id.to_string()).await;
            }
        }
        KeyCode::Char('g' | 'G') if state.current_tab == Tab::Profiles => {
            state.enter_settings();
            let pane = state
                .build_right_pane(crate::SettingsSection::Subscriptions)
                .await;
            if let crate::AppMode::Settings {
                mode: crate::SettingsMode::Split { right, focus, .. },
            } = &mut state.mode
            {
                *right = pane;
                *focus = crate::SplitFocus::Right;
            }
        }
        KeyCode::Char('p' | 'P') if state.current_tab == Tab::Profiles => {
            state.cycle_purgatory_view();
            state.reload_profiles().await;
        }
        KeyCode::Char('r' | 'R') if state.current_tab == Tab::Profiles => {
            if matches!(
                state.purgatory_view,
                leas_db::models::PurgatoryView::Purgatory
            ) && let Some(id) = state.selected_profile_id()
            {
                state
                    .db
                    .restore_endpoint(crate::ops::profiles::endpoint_id_from_raw(id))
                    .await
                    .unwrap_or_default();
                state.reload_profiles().await;
            }
        }
        KeyCode::Char('x' | 'X') if state.current_tab == Tab::Profiles => {
            // Manual DNS resolve (force — bypasses the TTL cache). No-op for
            // IP hosts (their address is already resolved).
            if let Some(ep_id) = state.selected_profile_id() {
                let host = state
                    .endpoints
                    .iter()
                    .find(|r| r.endpoint.id.get() == ep_id)
                    .map(|r| r.endpoint.display_host(&r.resolved_ips))
                    .unwrap_or_default();
                crate::ops::enrich::spawn_dns_resolve(state, ep_id, true);
                state.log_trace("info", "tui::ui", &format!("Resolving {host} …"));
            }
        }
        KeyCode::Char('d' | 'D') if state.current_tab == Tab::Profiles => {
            if state.multi_select.len() >= 2 {
                let ids: Vec<i64> = state.multi_select.iter().copied().collect();
                state.confirmation = Some(ConfirmAction::DeleteProfiles(ids));
            } else if let Some(id) = state.selected_profile_id() {
                state.confirmation = Some(ConfirmAction::DeleteProfile(id));
            }
        }
        KeyCode::Char('c' | 'C')
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && state.current_tab == Tab::Profiles =>
        {
            if let Some(id) = state.selected_profile_id() {
                state.clone_profile(id);
            }
        }
        KeyCode::Char('v')
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && state.current_tab == Tab::Profiles =>
        {
            let clipboard_text = crate::ops::clipboard::get_text().unwrap_or_default();

            let urls = subscription_url_split(&clipboard_text);
            match urls.len() {
                0 => {
                    state.mode = crate::AppMode::ImportUrl {
                        input: clipboard_text,
                        error: Some("No valid share URLs found".into()),
                    };
                }
                1 => {
                    state.mode = crate::AppMode::ImportUrl {
                        input: clipboard_text,
                        error: None,
                    };
                }
                _ => {
                    state.start_batch_import(&urls);
                }
            }
        }
        KeyCode::Char('S')
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && key.modifiers.contains(KeyModifiers::SHIFT)
                && state.current_tab == Tab::Profiles =>
        {
            // Copy the active protocol's share URL. The typed
            // `format_share_url(&ParsedProto, &EndpointEssentials)` equivalent
            // is `ProtocolConfig::reconstruct_proto(&endpoint_essentials)` —
            // the config must be loaded WITH its deferred data included.
            let Some((endpoint, addresses, pid)) = state.selected_profile_id().and_then(|id| {
                let row = state
                    .filtered_profiles()
                    .find(|r| r.endpoint.id.get() == id)?;
                let (_, protocol) = row.active_protocol()?;
                Some((row.endpoint.clone(), row.resolved_ips.clone(), protocol.id))
            }) else {
                state.log_trace("warn", "tui::ui", "No active protocol to copy");
                return;
            };
            let essentials = leas_core::config_builder::endpoint_essentials(&endpoint, &addresses);
            let url = match crate::state::load_protocol_with_config(&state.db, pid).await {
                Ok(Some(p)) if !p.config.is_unloaded() => {
                    p.config.get().0.reconstruct_proto(&essentials).ok()
                }
                _ => None,
            };
            match url {
                Some(url) => {
                    if let Err(error) = crate::ops::clipboard::set_text(url) {
                        state.log_trace("error", "tui::ui", &format!("Copy failed: {error}"));
                    }
                }
                None => state.log_trace(
                    "error",
                    "tui::ui",
                    "Failed to reconstruct share URL for this profile",
                ),
            }
        }
        KeyCode::Esc => {
            if !state.actions_compact && state.term_height.get() < 20 {
                state.actions_compact = true; // close overlay in small terminal
            } else if state.confirmation.is_some() {
                state.confirmation = None;
            } else {
                state.filter_cache_valid.set(false);
            }
        }
        _ => {}
    }
}

fn render(frame: &mut Frame, state: &AppState) {
    const FULL_PANEL_HEIGHT: u16 = 8;
    const SMALL_THRESH: u16 = 20;

    let is_small = frame.area().height < SMALL_THRESH;
    let overlay = !state.actions_compact && is_small;
    let ph = if overlay {
        0 // actions panel only useful on Profiles tab
    } else if state.actions_compact {
        1
    } else {
        FULL_PANEL_HEIGHT
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // 0: tabs
            Constraint::Min(3),     // 1: content
            Constraint::Length(ph), // 2: actions panel
            Constraint::Length(1),  // 3: status bar
        ])
        .split(frame.area());

    // Overlay mode: full panel replaces content area in small terminals
    if overlay {
        render_tabs(frame, chunks[0], state);
        actions_log::render_full(frame, chunks[1], state);
        render_any_confirmation(frame, chunks[1], state);
        status_bar::render(frame, chunks[3], state);
        return;
    }

    // Inline: render actions panel at bottom (chunks[2])
    if state.actions_compact {
        actions_log::render_compact(frame, chunks[2], state);
    } else {
        actions_log::render_full(frame, chunks[2], state);
    }
    let is_form_mode = matches!(
        &state.mode,
        crate::AppMode::AddServer { .. }
            | crate::AppMode::EditServer { .. }
            | crate::AppMode::ImportUrl { .. }
            | crate::AppMode::BatchImport { .. }
            | crate::AppMode::ExportScope { .. }
            | crate::AppMode::ExportDestination { .. }
            | crate::AppMode::ExportPath { .. }
    );
    if !is_form_mode {
        render_tabs(frame, chunks[0], state);
    }
    if !matches!(state.mode, crate::AppMode::List)
        && matches!(
            &state.mode,
            crate::AppMode::ExportScope { .. }
                | crate::AppMode::ExportDestination { .. }
                | crate::AppMode::ExportPath { .. }
        )
    {
        profiles::render(frame, chunks[1], state);
        export::render(frame, chunks[1], state);
        status_bar::render(frame, chunks[3], state);
        return;
    }
    if !matches!(state.mode, crate::AppMode::List) {
        if matches!(&state.mode, crate::AppMode::SpeedTestMenu { .. }) {
            profiles::render(frame, chunks[1], state);
            render_speed_test_menu(frame, chunks[1], state);
            render_any_confirmation(frame, chunks[1], state);
            status_bar::render(frame, chunks[3], state);
            return;
        }

        if matches!(&state.mode, crate::AppMode::TargetPicker { .. }) {
            logs::render(frame, chunks[1], state);
            logs::render_target_picker(frame, chunks[1], state);
            render_any_confirmation(frame, chunks[1], state);
            status_bar::render(frame, chunks[3], state);
            return;
        }

        if matches!(&state.mode, crate::AppMode::Help) {
            match state.current_tab {
                Tab::Profiles => profiles::render(frame, chunks[1], state),
                Tab::Settings => settings::render(frame, chunks[1], state),
                Tab::Logs => logs::render(frame, chunks[1], state),
                Tab::Statistics => statistics::render(frame, chunks[1], state),
                Tab::NativeActivity => native_activity::render(frame, chunks[1], state),
                Tab::Actions => crate::ui::actions_log::render(frame, chunks[1], state),
            }
            render_help_overlay(frame, chunks[1], state);
            render_any_confirmation(frame, chunks[1], state);
            status_bar::render(frame, chunks[3], state);
            return;
        }

        match &state.mode {
            crate::AppMode::AddServer { .. } | crate::AppMode::EditServer { .. } => {
                add_server::render(frame, chunks[1], state);
            }
            crate::AppMode::ImportUrl { .. } => {
                add_server::render_import_url(frame, chunks[1], state);
            }
            crate::AppMode::BatchImport { .. } => {
                add_server::render_batch_import(frame, chunks[1], state);
            }
            crate::AppMode::Settings { .. } => {
                settings::render(frame, chunks[1], state);
            }
            _ => {}
        }
        render_any_confirmation(frame, chunks[1], state);
        status_bar::render(frame, chunks[3], state);
        return;
    }
    match state.current_tab {
        Tab::Profiles => profiles::render(frame, chunks[1], state),
        Tab::Settings => settings::render(frame, chunks[1], state),
        Tab::Logs => logs::render(frame, chunks[1], state),
        Tab::Statistics => statistics::render(frame, chunks[1], state),
        Tab::NativeActivity => native_activity::render(frame, chunks[1], state),
        Tab::Actions => crate::ui::actions_log::render(frame, chunks[1], state),
    }
    render_any_confirmation(frame, chunks[1], state);
    status_bar::render(frame, chunks[3], state);
}
fn help_content(state: &AppState) -> Vec<(&'static str, &'static str)> {
    match &state.mode {
        crate::AppMode::Help => match state
            .previous_mode
            .as_deref()
            .cloned()
            .unwrap_or(AppMode::List)
        {
            AppMode::List => match state.current_tab {
                Tab::Profiles => vec![
                    ("↑↓ / PgUp PgDn", "Navigate profiles"),
                    ("← →", "Expand / collapse endpoint"),
                    ("↑↓ (expanded)", "Navigate protocol variants (panel)"),
                    ("Enter", "Set as active server / Activate variant"),
                    ("Ctrl+Enter", "Connect to selected server"),
                    ("Ctrl+G", "Connect to selected server"),
                    ("Space", "Toggle multi-select"),
                    ("x", "Resolve DNS of selected endpoint"),
                    ("a", "Add new server"),
                    ("e", "Edit selected server"),
                    ("d", "Delete selected server(s)"),
                    ("g", "Open subscriptions settings"),
                    ("t", "Open speed test menu (endpoint row = batch)"),
                    ("o", "Cycle sort column"),
                    ("/", "Search/filter"),
                    ("Ctrl+V", "Import share URL"),
                    ("Ctrl+Shift+S", "Copy share URL"),
                    ("Tab / Shift+Tab", "Cycle tabs"),
                    ("Ctrl+D", "Disconnect"),
                    ("?", "Toggle this help"),
                    ("q / Ctrl+C", "Quit"),
                ],
                Tab::Settings => vec![
                    ("↑↓", "Navigate settings menu"),
                    ("Enter", "Open selected section"),
                    ("Esc", "Close settings"),
                    ("Tab / Shift+Tab", "Cycle tabs"),
                    ("?", "Toggle this help"),
                    ("q / Ctrl+C", "Quit"),
                ],
                Tab::Logs => vec![
                    ("↑↓", "Scroll logs"),
                    ("PgUp / PgDn", "Page up/down"),
                    ("Home / End", "Jump to oldest/newest"),
                    ("c", "Clear log cache"),
                    ("Del", "Purge all logs from database"),
                    ("t", "Open target filter"),
                    ("d", "Dump DB query monitor"),
                    ("Tab / Shift+Tab", "Cycle tabs"),
                    ("?", "Toggle this help"),
                    ("q / Ctrl+C", "Quit"),
                ],
                Tab::Statistics | Tab::Actions => vec![
                    ("Tab / Shift+Tab", "Cycle tabs"),
                    ("?", "Toggle this help"),
                    ("q / Ctrl+C", "Quit"),
                ],
                Tab::NativeActivity => vec![
                    ("↑↓", "Scroll connections"),
                    ("PgUp / PgDn", "Page up/down"),
                    ("Home / End", "Jump to oldest/newest"),
                    ("Tab / Shift+Tab", "Cycle tabs"),
                    ("?", "Toggle this help"),
                    ("q / Ctrl+C", "Quit"),
                ],
            },
            _ => vec![
                ("Tab / Shift+Tab", "Cycle tabs"),
                ("?", "Toggle this help"),
                ("q / Ctrl+C", "Quit"),
            ],
        },
        _ => Vec::new(),
    }
}

fn render_help_overlay(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let content = help_content(state);
    let lines: Vec<Line> = content
        .iter()
        .map(|(key, desc)| {
            Line::from(vec![
                Span::styled(
                    format!(" {key:<20}"),
                    crate::ui::theme::ThemeStyles::hint(theme),
                ),
                Span::raw("  "),
                Span::styled(*desc, ThemeStyles::footer_value(theme)),
            ])
        })
        .collect();

    let popup_width = 52u16.min(area.width.saturating_sub(4));
    let popup_height = (content.len() as u16 + 2).min(area.height.saturating_sub(4));

    let para = Paragraph::new(lines).alignment(Alignment::Left);
    let sized = KnownSizeWrapper::new(para, popup_width as usize, popup_height as usize);
    let popup = Popup::new(sized)
        .title(" Keyboard Shortcuts ")
        .border_set(ratatui::symbols::border::ROUNDED)
        .style(ThemeStyles::dialog(theme));
    frame.render_widget(popup, area);
}

/// A typed item in the speed test menu.
enum SpeedTestMenuItem {
    Item(&'static str),
    Separator,
}

const SPEED_TEST_MENU_ITEMS: &[SpeedTestMenuItem] = &[
    SpeedTestMenuItem::Item("Fast Ping (Selected)"),
    SpeedTestMenuItem::Item("Real Ping (Selected)"),
    SpeedTestMenuItem::Item("Speed Test (Selected)"),
    SpeedTestMenuItem::Item("UDP Test (Selected)"),
    SpeedTestMenuItem::Separator,
    SpeedTestMenuItem::Item("Fast Ping (All Profiles)"),
    SpeedTestMenuItem::Item("Fast + Real Ping (All Profiles)"),
    SpeedTestMenuItem::Item("Fast + Real Ping (Successful)"),
    SpeedTestMenuItem::Item("Fast + Real Ping (New)"),
    SpeedTestMenuItem::Item("Fast + Real Ping (Successful + New)"),
    SpeedTestMenuItem::Item("Fast + Real Ping (Failed)"),
    SpeedTestMenuItem::Item("Sort by Test"),
    SpeedTestMenuItem::Item("Remove Bad Servers"),
    SpeedTestMenuItem::Separator,
    SpeedTestMenuItem::Item("Stop Testing"),
    SpeedTestMenuItem::Separator,
    SpeedTestMenuItem::Item("Clear All Stats"),
];

fn render_speed_test_menu(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    let selected = match &state.mode {
        crate::AppMode::SpeedTestMenu { selected } => *selected,
        _ => return,
    };

    let mut lines: Vec<Line> = Vec::new();
    for (i, item) in SPEED_TEST_MENU_ITEMS.iter().enumerate() {
        if matches!(item, SpeedTestMenuItem::Separator) {
            lines.push(Line::from(Span::raw(" ─────")));
            continue;
        }
        let label = match item {
            SpeedTestMenuItem::Item(label) => label,
            SpeedTestMenuItem::Separator => unreachable!(),
        };
        let prefix = if i == selected { "► " } else { "  " };
        let is_stop_item = *label == "Stop Testing";
        let is_disabled = is_stop_item && state.testing_profiles.is_empty();
        let style = if is_disabled {
            ThemeStyles::hint(theme)
        } else if i == selected {
            ThemeStyles::table_row_selected(theme)
        } else {
            ThemeStyles::footer_value(theme)
        };
        lines.push(Line::from(Span::styled(format!("{prefix}{label}"), style)));
    }

    let popup_width = 40u16.min(area.width.saturating_sub(4));
    let popup_height = (SPEED_TEST_MENU_ITEMS.len() as u16 + 2).min(area.height.saturating_sub(4));

    let para = Paragraph::new(lines).alignment(Alignment::Left);
    let sized = KnownSizeWrapper::new(para, popup_width as usize, popup_height as usize);
    let popup = Popup::new(sized)
        .title(" Server Tools ")
        .border_set(ratatui::symbols::border::ROUNDED)
        .style(ThemeStyles::dialog(theme));
    frame.render_widget(popup, area);
}
fn render_tabs(frame: &mut Frame, area: Rect, state: &AppState) {
    let theme = state.theme();
    // Split area into [indicator(3) | tabs]
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);
    // Connection indicator
    let indicator = if state.connecting {
        Span::styled(" ⟳", crate::ui::theme::ThemeStyles::spinner(theme))
    } else if state.connected_core.is_some() {
        Span::styled(" ●", crate::ui::theme::ThemeStyles::success(theme))
    } else {
        Span::styled(" ○", crate::ui::theme::ThemeStyles::hint(theme))
    };
    let indicator_para = Paragraph::new(Line::from(indicator));
    frame.render_widget(indicator_para, chunks[0]);

    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|tab| {
            let name = match tab {
                Tab::Profiles => " Profiles ",
                Tab::Settings => " Settings ",
                Tab::Logs => " Logs ",
                Tab::Statistics => " Statistics ",
                Tab::NativeActivity => " Native Activity ",
                Tab::Actions => " Actions ",
            };
            Line::from(Span::styled(
                name,
                crate::ui::theme::ThemeStyles::tab_deselected(theme),
            ))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .select(
            Tab::ALL
                .iter()
                .position(|t| *t == state.current_tab)
                .unwrap_or(0),
        )
        .highlight_style(crate::ui::theme::ThemeStyles::tab_selected(theme))
        .divider(Span::raw(""));
    frame.render_widget(tabs, chunks[1]);
}

pub fn render_placeholder_screen(
    frame: &mut Frame,
    area: Rect,
    name: &str,
    theme: &opaline::Theme,
) {
    let text = format!("{name} — Coming Soon");
    let paragraph = Paragraph::new(text)
        .style(ThemeStyles::hint(theme))
        .block(Block::default().title(name).borders(Borders::ALL));
    frame.render_widget(paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Windows console reports a key-up record for every keypress, and
    /// crossterm maps it to `KeyEventKind::Release` — dispatching every
    /// `Event::Key` applied each press twice there, and doubled every character
    /// of a paste (injected as key records). Unix terminals report only
    /// `Press`.
    #[tokio::test]
    async fn a_key_up_record_does_not_repeat_the_action() {
        let mut state = crate::ops::profiles::test_support::test_state(Vec::new()).await;
        let f1 = |kind| {
            Event::Key(KeyEvent::new_with_kind(
                KeyCode::F(1),
                KeyModifiers::NONE,
                kind,
            ))
        };

        // One keypress is one action, whatever the platform reports around it.
        assert!(!state.actions_compact);
        handle_event(&f1(KeyEventKind::Press), &mut state).await;
        handle_event(&f1(KeyEventKind::Release), &mut state).await;
        assert!(state.actions_compact, "key-up must not undo the press");

        // …and two presses are still two actions.
        handle_event(&f1(KeyEventKind::Press), &mut state).await;
        handle_event(&f1(KeyEventKind::Release), &mut state).await;
        assert!(!state.actions_compact);
    }
}
