use std::sync::{Arc, Mutex};

use leas_core::CoreType;

use crate::AppState;
use crate::try_send_or_warn;
use crate::types::CoreEvent;

/// Spawn async task to check for backend updates on startup or manual trigger.
pub fn spawn_update_check(state: &mut AppState) {
    let Some(tx) = state.core_event_tx.clone() else {
        return;
    };
    let bin_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::Path::new(".").to_path_buf())
        .join("leas/bin");
    for &core_type in &[CoreType::Xray, CoreType::SingBox] {
        let tx = tx.clone();
        let bin_dir = bin_dir.clone();
        tokio::spawn(async move {
            let current = leas_core::updater::get_current_version(core_type, &bin_dir).await;
            let latest = leas_core::updater::get_latest_version(core_type).await;
            let error = if current.is_none() && latest.is_none() {
                Some("binary not found and check failed".into())
            } else if latest.is_none() {
                Some("failed to check latest version".into())
            } else {
                None
            };
            try_send_or_warn(
                &tx,
                CoreEvent::UpdateCheckResult {
                    core_type,
                    current_version: current,
                    latest_version: latest,
                    error,
                },
                "update_check_result",
            );
        });
    }
}

/// Spawn async task to download and install an update for the given core.
pub fn spawn_update_download(state: &mut AppState, core_type: CoreType) {
    // Guard: don't download if already downloading
    if state
        .update_status
        .get(&core_type)
        .is_some_and(|s| s.downloading)
    {
        return;
    }
    // Guard: don't download if core is currently running
    if state.connected_core == Some(core_type) {
        state.log_trace(
            "warn",
            "tui::ops::updates",
            &format!("Cannot update {core_type} while it's running. Disconnect first."),
        );
        return;
    }

    let Some(latest) = state
        .update_status
        .get(&core_type)
        .and_then(|s| s.latest_version.clone())
    else {
        return;
    };
    let old_version = state
        .update_status
        .get(&core_type)
        .and_then(|s| s.current_version.clone());
    let Some(tx) = state.core_event_tx.clone() else {
        return;
    };
    let bin_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::Path::new(".").to_path_buf())
        .join("leas/bin");
    let client = leas_core::updater::update_client();
    let temp_dir = std::env::temp_dir().join(format!("leas-update-{core_type}"));

    state
        .update_status
        .entry(core_type)
        .or_default()
        .downloading = true;

    let last_report = Arc::new(Mutex::new(std::time::Instant::now()));
    let core_type_progress = core_type;

    let progress_cb = {
        let tx_progress = tx.clone();
        move |downloaded: u64, total: u64| {
            let should_send = {
                let mut last = last_report.lock().unwrap();
                if last.elapsed() >= std::time::Duration::from_millis(100) {
                    *last = std::time::Instant::now();
                    true
                } else {
                    false
                }
            };
            if should_send {
                let _ = tx_progress.try_send(CoreEvent::UpdateDownloadProgress {
                    core_type: core_type_progress,
                    downloaded,
                    total,
                });
            }
        }
    };

    tokio::spawn(async move {
        // Download
        let archive = match leas_core::updater::download_release(
            &client,
            core_type,
            &latest,
            &temp_dir,
            Some(progress_cb),
        )
        .await
        {
            Ok(path) => path,
            Err(e) => {
                try_send_or_warn(
                    &tx,
                    CoreEvent::UpdateCompleted {
                        core_type,
                        old_version: old_version.clone(),
                        new_version: latest,
                        success: false,
                        error: Some(e.to_string()),
                    },
                    "update_completed_err",
                );
                return;
            }
        };
        // Install
        let result = leas_core::updater::install_binary(&archive, core_type, &bin_dir).await;
        let (success, error) = match result {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };
        // Clean up temp file
        let _ = std::fs::remove_file(&archive);
        let _ = std::fs::remove_dir_all(&temp_dir);

        try_send_or_warn(
            &tx,
            CoreEvent::UpdateCompleted {
                core_type,
                old_version,
                new_version: latest,
                success,
                error,
            },
            "update_completed",
        );
    });
}
