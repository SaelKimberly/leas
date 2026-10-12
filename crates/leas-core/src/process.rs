use tracing::warn;

use crate::bin_manager::{BinError, get_core_info};
use crate::config_builder::BackendConfig;
use crate::core_type::CoreType;
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::io::AsyncBufReadExt;
use tokio::process::{Child, Command};
use tokio::sync::mpsc::Sender;

/// Abstract interface for core process lifecycle.
#[async_trait]
pub trait CoreManager: Send + Sync {
    /// Start the core process with the given config and binary.
    async fn start(
        &mut self,
        core_type: CoreType,
        config: &BackendConfig,
        binary_path: &Path,
        clash_mixin: Option<&serde_json::Value>,
    ) -> Result<(), ProcessError>;

    /// Gracefully stop the running core process.
    async fn stop(&mut self) -> Result<(), ProcessError>;

    /// Check if a core process is currently running.
    fn is_running(&self) -> bool;

    /// Get the type of the currently running core.
    fn running_core_type(&self) -> Option<CoreType>;

    /// Send SIGHUP to reload config (sing-box only).
    fn sighup_reload(&self) -> Result<u32, ProcessError>;

    /// Rewrite config file and reload.
    async fn rewrite_config(
        &self,
        config: &BackendConfig,
        clash_mixin: Option<&serde_json::Value>,
    ) -> Result<(), ProcessError>;
}

/// Status of a running core process.
pub struct CoreProcess {
    child: Option<Child>,
    config_path: PathBuf,
    pub core_type: CoreType,
}

impl CoreProcess {
    const fn new(child: Child, config_path: PathBuf, core_type: CoreType) -> Self {
        Self {
            child: Some(child),
            config_path,
            core_type,
        }
    }

    /// Gracefully stop the process: SIGTERM, wait 5s, then SIGKILL.
    async fn graceful_stop(&mut self) -> Result<(), ProcessError> {
        if let Some(child) = self.child.as_mut() {
            // Only try graceful stop on unix
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                // Send SIGTERM for graceful shutdown
                let _ = unsafe { libc::kill(pid.cast_signed(), libc::SIGTERM) };
            }
            #[cfg(not(unix))]
            {
                // Windows: TerminateProcess (like SIGKILL)
                let _ = child.kill().await;
            }

            // Wait up to 5s for graceful exit
            let start = std::time::Instant::now();
            loop {
                if let Some(_exit) = child.try_wait().map_err(ProcessError::Io)? {
                    break; // Exited gracefully
                }
                if start.elapsed() > std::time::Duration::from_secs(5) {
                    // Timeout — SIGKILL
                    child.kill().await?;
                    child.wait().await?;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
        // Clean up config file
        let _ = std::fs::remove_file(&self.config_path);
        Ok(())
    }
}

impl Drop for CoreProcess {
    fn drop(&mut self) {
        if let Some(_child) = self.child.take() {
            // kill_on_drop handles the child process
        }
        let _ = std::fs::remove_file(&self.config_path);
    }
}

/// Helper to write config files with owner-only permissions (0600 on Unix).
async fn write_config_file(path: &Path, content: &str) -> Result<(), std::io::Error> {
    // Write config with owner-only permissions (0600 on Unix).
    // The file contains proxy credentials (passwords, UUIDs, etc.).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        opts.open(path)?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        tokio::fs::write(path, content).await
    }
    #[cfg(not(unix))]
    tokio::fs::write(path, content).await
}

/// Manages a single core process lifecycle.
pub struct RealCoreManager {
    config_dir: tempfile::TempDir,
    current: Option<CoreProcess>,
    log_tx: Sender<String>,
}

impl RealCoreManager {
    /// Create a new `CoreManager` with a temporary config directory and log channel.
    /// Falls back to `config_dir` if tempdir creation fails.
    // Public API takes an owned `PathBuf`; the signature is not narrowed for a lint.
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn new(fallback_config_dir: PathBuf, log_tx: Sender<String>) -> Self {
        let config_dir = tempfile::Builder::new()
            .prefix("leas-config-")
            .tempdir_in(&fallback_config_dir)
            .unwrap_or_else(|_| tempfile::TempDir::new().expect("tempdir creation failed"));
        // The tempdir holds config.json with proxy credentials. `tempfile`
        // creates it 0700 on Unix; enforce it explicitly so the
        // credential-bearing directory is never traversable, whatever the
        // creation path. Do NOT touch the parent: on the `TempDir::new()`
        // fallback that parent is the shared `/tmp` (1777) and chmodding it
        // would break the host.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ =
                std::fs::set_permissions(config_dir.path(), std::fs::Permissions::from_mode(0o700));
        }
        Self {
            config_dir,
            current: None,
            log_tx,
        }
    }
    /// Start a core process with the given config and binary path.
    pub async fn start(
        &mut self,
        core_type: CoreType,
        config: &BackendConfig,
        binary_path: &Path,
        clash_mixin: Option<&serde_json::Value>,
    ) -> Result<(), ProcessError> {
        // Stop any running core of a different type
        if let Some(running) = &self.current
            && running.core_type != core_type
        {
            self.stop().await?;
        }

        let info = get_core_info(core_type)
            .ok_or_else(|| ProcessError::Startup("Unknown core type".to_string()))?;

        // Write config JSON
        let config_path = self.config_dir.path().join("config.json");
        let json = match config {
            BackendConfig::Xray(c) => serde_json::to_string_pretty(c)?,
            BackendConfig::SingBox(c) => serde_json::to_string_pretty(c)?,
        };
        // Apply clash mixin: parse the serialized JSON, merge mixin fields, re-serialize
        let json = if let Some(mixin_value) = clash_mixin
            && let Some(mixin_obj) = mixin_value.as_object()
            && !mixin_obj.is_empty()
        {
            let mut root: serde_json::Value = serde_json::from_str(&json)?;
            if let Some(obj) = root.as_object_mut() {
                for (key, val) in mixin_obj {
                    obj.insert(key.clone(), val.clone());
                }
            }
            serde_json::to_string_pretty(&root)?
        } else {
            json
        };
        write_config_file(&config_path, &json).await?;

        // Build args from template: "run -c {0}" → ["run", "-c", config_path]
        let config_str = config_path.to_string_lossy().to_string();
        let args: Vec<String> = info
            .args_template
            .split(' ')
            .map(|part| {
                if part == "{0}" {
                    config_str.clone()
                } else {
                    part.to_string()
                }
            })
            .collect();

        // Spawn process
        let mut child = Command::new(binary_path)
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        // Read stderr for logs
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ProcessError::Startup("Failed to capture stderr".to_string()))?;
        let log_tx = self.log_tx.clone();
        tokio::spawn(async move {
            let reader = tokio::io::BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if log_tx.try_send(line).is_err() {
                    warn!(target: "core::process::reader", "reader channel full, dropping log line");
                    // Don't exit — keep reading and drop stale lines
                }
            }
        });

        // Read stdout for logs (xray-core logs to stdout by default)
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProcessError::Startup("Failed to capture stdout".to_string()))?;
        let log_tx = self.log_tx.clone();
        tokio::spawn(async move {
            let reader = tokio::io::BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if log_tx.try_send(line).is_err() {
                    warn!(target: "core::process::reader", "reader channel full, dropping log line");
                    // Don't exit — keep reading and drop stale lines
                }
            }
        });
        // Poll for readiness (check process hasn't exited early)
        let max_retries = 20; // 500ms * 20 = 10s
        for _ in 0..max_retries {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(ProcessError::Startup(format!(
                        "Process exited early with status: {status}"
                    )));
                }
                Ok(None) => {
                    // Process still running
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                Err(e) => {
                    return Err(ProcessError::Io(e));
                }
            }
        }

        // Check one more time after polling
        if let Some(status) = child.try_wait()? {
            return Err(ProcessError::Startup(format!(
                "Process exited during startup with status: {status}"
            )));
        }

        self.current = Some(CoreProcess::new(child, config_path, core_type));

        Ok(())
    }

    /// Gracefully stop the running core process.
    pub async fn stop(&mut self) -> Result<(), ProcessError> {
        if let Some(mut proc) = self.current.take() {
            proc.graceful_stop().await?;
        }
        Ok(())
    }

    /// Check if a core process is currently running.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        self.current.is_some()
    }

    /// Get the type of the currently running core.
    #[must_use]
    pub fn running_core_type(&self) -> Option<CoreType> {
        self.current.as_ref().map(|p| p.core_type)
    }

    /// Get a reference to the log sender.
    #[must_use]
    pub fn log_tx(&self) -> Sender<String> {
        self.log_tx.clone()
    }

    /// Send SIGHUP to the running core (sing-box only — xray-core ignores it).
    /// The config file must already be rewritten before calling this.
    /// sing-box handles SIGHUP as a config reload: validate → shutdown → restart.
    /// Returns the process PID for external readiness polling.
    pub fn sighup_reload(&self) -> Result<u32, ProcessError> {
        let proc = self
            .current
            .as_ref()
            .ok_or_else(|| ProcessError::Startup("No running process".into()))?;
        let pid = proc
            .child
            .as_ref()
            .and_then(tokio::process::Child::id)
            .ok_or_else(|| ProcessError::Startup("No child PID".into()))?;
        // No SIGHUP on Windows — the caller stops and restarts instead. The
        // success path lives inside the unix block: a `return` in the non-unix
        // arm would leave a trailing `Ok(pid)` unreachable there.
        #[cfg(unix)]
        {
            unsafe {
                if libc::kill(pid.cast_signed(), libc::SIGHUP) != 0 {
                    let err = std::io::Error::last_os_error();
                    return Err(ProcessError::Startup(format!("SIGHUP failed: {err}")));
                }
            }
            Ok(pid)
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            Err(ProcessError::Startup(
                "SIGHUP not supported on Windows".into(),
            ))
        }
    }

    /// Write config to the existing temp directory without restarting.
    pub async fn rewrite_config(
        &self,
        config: &BackendConfig,
        clash_mixin: Option<&serde_json::Value>,
    ) -> Result<(), ProcessError> {
        let config_path = self.config_dir.path().join("config.json");
        let json = match config {
            BackendConfig::Xray(c) => serde_json::to_string_pretty(c)?,
            BackendConfig::SingBox(c) => serde_json::to_string_pretty(c)?,
        };
        let json = if let Some(mixin_value) = clash_mixin
            && let Some(mixin_obj) = mixin_value.as_object()
            && !mixin_obj.is_empty()
        {
            let mut root: serde_json::Value = serde_json::from_str(&json)?;
            if let Some(obj) = root.as_object_mut() {
                for (key, val) in mixin_obj {
                    obj.insert(key.clone(), val.clone());
                }
            }
            serde_json::to_string_pretty(&root)?
        } else {
            json
        };
        write_config_file(&config_path, &json).await?;
        Ok(())
    }

    /// Get the config directory path (for multi-inbound config writes).
    #[must_use]
    pub fn config_dir(&self) -> &std::path::Path {
        self.config_dir.path()
    }
}

impl Drop for RealCoreManager {
    fn drop(&mut self) {
        // Dropping CoreProcess kills child via kill_on_drop + start_kill
        let _ = self.current.take();
    }
}

#[async_trait]
impl CoreManager for RealCoreManager {
    async fn start(
        &mut self,
        core_type: CoreType,
        config: &BackendConfig,
        binary_path: &Path,
        clash_mixin: Option<&serde_json::Value>,
    ) -> Result<(), ProcessError> {
        Self::start(self, core_type, config, binary_path, clash_mixin).await
    }

    async fn stop(&mut self) -> Result<(), ProcessError> {
        Self::stop(self).await
    }

    fn is_running(&self) -> bool {
        Self::is_running(self)
    }

    fn running_core_type(&self) -> Option<CoreType> {
        Self::running_core_type(self)
    }

    fn sighup_reload(&self) -> Result<u32, ProcessError> {
        Self::sighup_reload(self)
    }

    async fn rewrite_config(
        &self,
        config: &BackendConfig,
        clash_mixin: Option<&serde_json::Value>,
    ) -> Result<(), ProcessError> {
        Self::rewrite_config(self, config, clash_mixin).await
    }
}

/// Mock `CoreManager` for testing — simulates process lifecycle without real subprocess.
#[derive(Debug)]
pub struct MockCoreManager {
    pub start_error: Option<String>,
    pub stop_error: Option<String>,
    pub is_running: bool,
    pub running_core_type: Option<CoreType>,
    pub sighup_error: Option<String>,
    pub rewrite_error: Option<String>,
    pub call_count: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>,
}

impl MockCoreManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_error: None,
            stop_error: None,
            is_running: false,
            running_core_type: None,
            sighup_error: None,
            rewrite_error: None,
            call_count: std::sync::Arc::new(
                std::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        }
    }

    fn record_call(&self, name: &str) {
        if let Ok(mut count) = self.call_count.lock() {
            *count.entry(name.to_string()).or_insert(0) += 1;
        }
    }
}

impl Default for MockCoreManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CoreManager for MockCoreManager {
    async fn start(
        &mut self,
        _core_type: CoreType,
        _config: &BackendConfig,
        _binary_path: &Path,
        _clash_mixin: Option<&serde_json::Value>,
    ) -> Result<(), ProcessError> {
        self.record_call("start");
        self.start_error
            .as_ref()
            .map_or(Ok(()), |msg| Err(ProcessError::Startup(msg.clone())))
    }

    async fn stop(&mut self) -> Result<(), ProcessError> {
        self.record_call("stop");
        self.stop_error
            .as_ref()
            .map_or(Ok(()), |msg| Err(ProcessError::Startup(msg.clone())))
    }

    fn is_running(&self) -> bool {
        self.is_running
    }

    fn running_core_type(&self) -> Option<CoreType> {
        self.running_core_type
    }

    fn sighup_reload(&self) -> Result<u32, ProcessError> {
        self.record_call("sighup_reload");
        self.sighup_error
            .as_ref()
            .map_or(Ok(0), |msg| Err(ProcessError::Startup(msg.clone())))
    }

    async fn rewrite_config(
        &self,
        _config: &BackendConfig,
        _clash_mixin: Option<&serde_json::Value>,
    ) -> Result<(), ProcessError> {
        self.record_call("rewrite_config");
        self.rewrite_error
            .as_ref()
            .map_or(Ok(()), |msg| Err(ProcessError::Startup(msg.clone())))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("Startup failed: {0}")]
    Startup(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Binary error: {0}")]
    Bin(#[from] BinError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_manager_is_not_running() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mgr = RealCoreManager::new(PathBuf::from("/tmp"), tx);
        assert!(!mgr.is_running());
        assert!(mgr.running_core_type().is_none());
    }

    /// The credentials-bearing core config and its directory must be owner
    /// only, independent of the caller's umask (finding f3).
    #[cfg(unix)]
    #[tokio::test]
    async fn written_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = tempfile::tempdir().unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mgr = RealCoreManager::new(base.path().to_path_buf(), tx);
        assert_eq!(
            std::fs::metadata(mgr.config_dir())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0,
            "config tempdir must not be group/other accessible"
        );
        let path = mgr.config_dir().join("config.json");
        super::write_config_file(&path, r#"{"password":"secret"}"#)
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
            0,
            "config.json must not be group/other readable"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"password":"secret"}"#
        );
    }

    #[tokio::test]
    async fn start_does_not_panic_without_log_consumer() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let mut mgr = RealCoreManager::new(PathBuf::from("/tmp"), tx);
        let result = mgr
            .start(
                CoreType::Xray,
                &BackendConfig::Xray(crate::config_builder::xray::XrayConfig::default()),
                Path::new("/nonexistent/binary"),
                None,
            )
            .await;
        assert!(result.is_err());
    }
}
