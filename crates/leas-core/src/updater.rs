use crate::core_type::CoreType;
use futures_util::StreamExt;
use semver::Version;
use std::path::{Path, PathBuf};
use thiserror::Error;
/// Shared HTTP client for update checks/downloads: one connection pool per
/// process instead of one `Client::new()` per check.
static UPDATE_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    crate::ensure_tls_provider();
    reqwest::Client::builder()
        .redirect(safe_redirect_policy(false))
        .build()
        .expect("update HTTP client build must succeed")
});

/// Whether a redirect target is an interior/local address or a local name.
/// A fetch whose response is adopted (an update, a geo file, a subscription
/// feed) must not be movable onto a loopback/LAN/metadata endpoint by the
/// origin that answers it (findings f10/f11).
#[allow(clippy::case_sensitive_file_extension_comparisons)] // `lower` is already ASCII-lowercased, so this comparison is case-insensitive
fn redirect_target_is_local(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
        return true;
    }
    // `Url::host_str` keeps the brackets around an IPv6 literal.
    let bare = lower
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&lower);
    let Ok(ip) = bare.parse::<std::net::IpAddr>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
        }
    }
}

/// Redirect policy for fetch clients whose body is adopted (updates, geo
/// files, subscription feeds).
///
/// Rejects a plaintext downgrade, refuses to land
/// on a local-use host, and caps the chain. `require_https` forces every hop
/// to HTTPS (pass `false` for feeds whose provider may legitimately be http —
/// a downgrade from https is still always refused).
#[must_use]
pub fn safe_redirect_policy(require_https: bool) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many redirects");
        }
        let target = attempt.url();
        let downgrade = attempt
            .previous()
            .last()
            .is_some_and(|prev| prev.scheme() == "https" && target.scheme() != "https");
        if downgrade
            || (require_https && target.scheme() != "https")
            || redirect_target_is_local(target)
        {
            return attempt.stop();
        }
        attempt.follow()
    })
}

/// Clone the shared update HTTP client (`Client::clone` is an `Arc` bump).
#[must_use]
pub fn update_client() -> reqwest::Client {
    UPDATE_CLIENT.clone()
}
#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("Unsupported platform: {0} {1}")]
    UnsupportedPlatform(&'static str, &'static str),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Download failed: {0}")]
    Download(String),
    #[error("Archive error: {0}")]
    Archive(String),
    #[error("Binary not found in archive: {0}")]
    BinaryNotFound(String),
    #[error("Installation failed: {0}")]
    Install(String),
    #[error("Cannot install for Auto core type")]
    AutoCore,
}

/// Parse a version tag (strip leading 'v') as `semver::Version`.
#[must_use]
pub fn parse_version(tag: &str) -> Option<Version> {
    let stripped = tag.strip_prefix('v').unwrap_or(tag);
    Version::parse(stripped).ok()
}

/// Compare two versions. Returns true if `latest > current` per semver precedence.
#[must_use]
pub fn is_newer(current: &Version, latest: &Version) -> bool {
    *latest > *current
}

/// Run `{core_type} version` and parse the first version-like token from stdout.
pub async fn get_current_version(core_type: CoreType, bin_dir: &Path) -> Option<String> {
    let exe = match core_type {
        CoreType::Xray => "xray",
        CoreType::SingBox => "sing-box",
        CoreType::Auto | CoreType::Native => return None,
    };

    // Try managed bin_dir first (inside per-core subdirectory), then PATH
    let bin_path = bin_dir.join(core_type.to_string()).join(exe);
    let cmd: std::borrow::Cow<'_, std::ffi::OsStr> = if bin_path.is_file() {
        bin_path.as_os_str().into()
    } else {
        std::ffi::OsStr::new(exe).into()
    };

    let output = tokio::process::Command::new(&cmd)
        .arg("version")
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Extract the first version-like token (e.g., "1.8.4" from "xray 1.8.4 ...")
    let version_str = stdout.split_whitespace().find(|token| {
        let stripped = token.strip_prefix('v').unwrap_or(token);
        stripped.chars().next().is_some_and(|c| c.is_ascii_digit())
            && stripped.chars().any(|c| c == '.')
    })?;

    let stripped = version_str.strip_prefix('v').unwrap_or(version_str);
    if Version::parse(stripped).is_ok() {
        Some(version_str.to_string())
    } else {
        None
    }
}

/// GitHub API endpoints and asset naming for each core type.
const XRAY_OWNER: &str = "XTLS";
const XRAY_REPO: &str = "Xray-core";
const SINGBOX_OWNER: &str = "SagerNet";
const SINGBOX_REPO: &str = "sing-box";

/// GET latest release from GitHub API and return the `tag_name`.
pub async fn get_latest_version(core_type: CoreType) -> Option<String> {
    let (owner, repo) = match core_type {
        CoreType::Xray => (XRAY_OWNER, XRAY_REPO),
        CoreType::SingBox => (SINGBOX_OWNER, SINGBOX_REPO),
        CoreType::Auto | CoreType::Native => return None,
    };

    let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
    let client = update_client();
    let resp = client
        .get(&url)
        .header("User-Agent", "leas")
        .header("Accept", "application/json")
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body: serde_json::Value = resp.json().await.ok()?;
    let tag_name = body.get("tag_name")?.as_str()?;
    Some(tag_name.to_string())
}

/// Download the release asset for the current platform.
/// Download the release asset for the current platform.
/// `progress` is an optional callback invoked with (`downloaded_bytes`, `total_bytes`).
pub async fn download_release<F: Fn(u64, u64) + Send + 'static>(
    client: &reqwest::Client,
    core_type: CoreType,
    version: &str,
    dest_dir: &Path,
    progress: Option<F>,
) -> Result<PathBuf, UpdateError> {
    let url = release_asset_url(core_type, version)?;

    let filename = url.rsplit('/').next().unwrap_or("archive.tar.gz");
    let dest = dest_dir.join(filename);

    std::fs::create_dir_all(dest_dir)?;

    // Stream download
    let resp = client
        .get(&url)
        .header("User-Agent", "leas")
        .header("Accept", "application/octet-stream")
        .send()
        .await
        .map_err(|e| UpdateError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(UpdateError::Download(format!("HTTP {}", resp.status())));
    }

    let total_size = resp.content_length().unwrap_or(0);
    let mut file = tokio::fs::File::create(&dest).await?;

    let mut stream = resp.bytes_stream();
    let mut downloaded: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| UpdateError::Download(e.to_string()))?;
        downloaded += chunk.len() as u64;
        if let Some(ref cb) = progress {
            cb(downloaded, total_size);
        }
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
    }

    Ok(dest)
}

/// Download a geo file (geoip.dat or geosite.dat) from URL to `dest_dir`.
pub async fn download_geo_file(
    client: &reqwest::Client,
    url: &str,
    dest_dir: &Path,
) -> Result<PathBuf, UpdateError> {
    let filename = url.rsplit('/').next().unwrap_or("geo.dat");
    let dest = dest_dir.join(filename);

    std::fs::create_dir_all(dest_dir)?;

    let resp = client
        .get(url)
        .header("User-Agent", "leas")
        .header("Accept", "application/octet-stream")
        .send()
        .await
        .map_err(|e| UpdateError::Http(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(UpdateError::Download(format!("HTTP {}", resp.status())));
    }

    let mut file = tokio::fs::File::create(&dest).await?;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| UpdateError::Download(e.to_string()))?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
    }

    Ok(dest)
}
/// Extract archive, verify binary, install all files to `bin_dir`.
/// Uses `spawn_blocking` for synchronous archive extraction and file copy.
pub async fn install_binary(
    archive: &Path,
    core_type: CoreType,
    bin_dir: &Path,
) -> Result<(), UpdateError> {
    let _suffix = match core_type {
        CoreType::Xray => "xray",
        CoreType::SingBox => "sing-box",
        CoreType::Auto | CoreType::Native => return Err(UpdateError::AutoCore),
    };
    let bin_owned = bin_dir.to_path_buf();
    let archive_owned = archive.to_path_buf();
    let temp_dir = tempfile::tempdir()
        .map_err(|e| UpdateError::Install(format!("failed to create temp dir: {e}")))?
        .keep();
    let temp_dir_clone = temp_dir.clone();

    // Extract archive to temp dir (sync — wrap in spawn_blocking)
    let binary = tokio::task::spawn_blocking(move || {
        let _ = std::fs::remove_dir_all(&temp_dir_clone);
        std::fs::create_dir_all(&temp_dir_clone)?;

        // 1. Extract archive to temp dir
        crate::bin_manager::extract_archive(&archive_owned, core_type, &temp_dir_clone)
            .map_err(|e| UpdateError::Archive(e.to_string()))?;

        // 2. Find extracted binary — through the same platform-spelled
        // candidate list `find_binary` uses, so `xray` vs `xray.exe` has one
        // owner instead of a second hardcoded match here.
        let exe_names = crate::bin_manager::exe_names(core_type).ok_or(UpdateError::AutoCore)?;
        let binary = find_binary_in_dir(&temp_dir_clone, &exe_names)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&binary)?;
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() | 0o111);
            std::fs::set_permissions(&binary, perms)?;
        }

        Ok::<PathBuf, UpdateError>(binary)
    })
    .await
    .map_err(|e| UpdateError::Install(e.to_string()))??;

    // 3. Verify binary runs (async — tokio::process::Command)
    let output = tokio::process::Command::new(&binary)
        .arg("version")
        .output()
        .await
        .map_err(|e| UpdateError::Install(e.to_string()))?;

    if !output.status.success() {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(UpdateError::Install(
            "extracted binary returned non-zero exit code".into(),
        ));
    }

    let version_output = String::from_utf8_lossy(&output.stdout);
    if version_output.is_empty() {
        return Err(UpdateError::Install(
            "extracted binary produced no version output".into(),
        ));
    }

    // 4. Install to bin_dir (sync — wrap in spawn_blocking)
    let core_bin_dir = bin_owned.join(match core_type {
        CoreType::Xray => "xray",
        CoreType::SingBox => "sing-box",
        CoreType::Auto | CoreType::Native => return Err(UpdateError::AutoCore),
    });

    tokio::task::spawn_blocking(move || {
        // Remove old .bak if present
        let bak_dir = bin_owned.join(format!(
            "{}.bak",
            core_bin_dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ));
        let _ = std::fs::remove_dir_all(&bak_dir);

        // Rename existing directory to .bak
        if core_bin_dir.exists() {
            std::fs::rename(&core_bin_dir, &bak_dir)?;
        }

        // Copy all extracted files
        std::fs::create_dir_all(&core_bin_dir)?;

        if let Err(e) = copy_recursively(&temp_dir, &core_bin_dir) {
            // Restore from backup
            let _ = std::fs::remove_dir_all(&core_bin_dir);
            if bak_dir.exists() {
                let _ = std::fs::rename(&bak_dir, &core_bin_dir);
            }
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(UpdateError::Install(format!("failed to copy files: {e}")));
        }

        // Remove .bak on success
        let _ = std::fs::remove_dir_all(&bak_dir);
        let _ = std::fs::remove_dir_all(&temp_dir);

        Ok(())
    })
    .await
    .map_err(|e| UpdateError::Install(e.to_string()))??;

    Ok(())
}

/// Build the GitHub release asset URL for the current OS/arch.
pub fn release_asset_url(core_type: CoreType, version: &str) -> Result<String, UpdateError> {
    let version = version.strip_prefix('v').unwrap_or(version);
    let name = asset_name(
        core_type,
        version,
        std::env::consts::OS,
        std::env::consts::ARCH,
    )?;

    let repo = match core_type {
        CoreType::Xray => "https://github.com/XTLS/Xray-core/releases/download",
        CoreType::SingBox => "https://github.com/SagerNet/sing-box/releases/download",
        CoreType::Auto | CoreType::Native => return Err(UpdateError::AutoCore),
    };

    Ok(format!("{repo}/v{version}/{name}"))
}

/// Build the upstream release-archive filename for a core, version and target.
///
/// The OS and arch are **inputs**, not environment reads, so every platform's
/// naming is checkable from any host — reading `std::env` in here is what made
/// the previous version untestable off Linux and turned its Linux-only support
/// into a silent Windows failure.
///
/// The names come from upstream, not from memory: Xray-core publishes
/// `Xray-<friendly>.zip` with the friendly names in
/// `.github/build/friendly-filenames.json` (`windows-64`, `linux-arm64-v8a`),
/// and sing-box packages `sing-box-<version>-<os>-<arch>` — a `.zip` through
/// `Compress-Archive` on Windows, a `.tar.gz` through `tar` on Linux.
///
/// `linux`/`windows` × `x86_64`/`aarch64` are the combinations named here.
/// Anything else is refused rather than guessed: macOS publishes
/// `macos-64`/`darwin-arm64` upstream, but no macOS target is claimed.
fn asset_name(
    core_type: CoreType,
    version: &str,
    os: &'static str,
    arch: &'static str,
) -> Result<String, UpdateError> {
    let version = version.strip_prefix('v').unwrap_or(version);
    let suffix = match arch {
        "x86_64" => match core_type {
            CoreType::Xray => "64",
            CoreType::SingBox => "amd64",
            CoreType::Auto | CoreType::Native => return Err(UpdateError::AutoCore),
        },
        "aarch64" => match core_type {
            CoreType::Xray => "arm64-v8a", // XTLS publishes arm64-v8a, not arm64
            CoreType::SingBox => "arm64",
            CoreType::Auto | CoreType::Native => return Err(UpdateError::AutoCore),
        },
        _ => {
            return Err(UpdateError::UnsupportedPlatform(arch, os));
        }
    };
    let name = match (os, core_type) {
        ("linux", CoreType::Xray) => format!("Xray-linux-{suffix}.zip"),
        ("windows", CoreType::Xray) => format!("Xray-windows-{suffix}.zip"),
        ("linux", CoreType::SingBox) => format!("sing-box-{version}-linux-{suffix}.tar.gz"),
        ("windows", CoreType::SingBox) => format!("sing-box-{version}-windows-{suffix}.zip"),
        (_, CoreType::Auto | CoreType::Native) => return Err(UpdateError::AutoCore),
        _ => {
            return Err(UpdateError::UnsupportedPlatform(arch, os));
        }
    };
    Ok(name)
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Recursively copy a directory.
fn copy_recursively(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let file_name = entry.file_name();
        let dst_path = dst.join(&file_name);

        if file_type.is_dir() {
            copy_recursively(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Find a binary in a directory tree (searching recursively), by any of the
/// platform-spelled candidate names.
fn find_binary_in_dir(dir: &Path, exe_names: &[String]) -> Result<PathBuf, UpdateError> {
    let mut found = None;
    let mut entries: Vec<_> = vec![dir.to_path_buf()];

    while let Some(current) = entries.pop() {
        if let Ok(read_dir) = std::fs::read_dir(&current) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    entries.push(path);
                } else if let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && exe_names.iter().any(|candidate| candidate == name)
                {
                    found = Some(path);
                    break;
                }
            }
        }
        if found.is_some() {
            break;
        }
    }

    found.ok_or_else(|| UpdateError::BinaryNotFound(exe_names.join(", ")))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("v1.8.4"), Some(Version::new(1, 8, 4)));
        assert_eq!(parse_version("1.8.4"), Some(Version::new(1, 8, 4)));
        assert!(parse_version("v1.9.0-rc1").is_some());
        assert_eq!(parse_version("invalid"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn test_is_newer() {
        assert!(is_newer(&Version::new(1, 8, 4), &Version::new(1, 8, 10)));
        assert!(!is_newer(&Version::new(1, 8, 10), &Version::new(1, 8, 4)));
        assert!(!is_newer(&Version::new(1, 8, 4), &Version::new(1, 8, 4)));
        // Pre-release: 1.9.0-rc1 < 1.9.0, so 1.9.0 IS newer than rc1
        assert!(is_newer(
            &Version::parse("1.9.0-rc1").unwrap(),
            &Version::new(1, 9, 0)
        ));
        assert!(!is_newer(
            &Version::new(1, 9, 0),
            &Version::parse("1.9.0-rc1").unwrap()
        ));
    }

    #[test]
    fn release_asset_url_points_at_the_hosts_own_archive() {
        // The URL the host actually fetches. The naming itself is the table
        // below's job; what this pins is the URL shape around it, per host —
        // it failed on `windows` while `asset_name` refused every non-Linux OS.
        let xray = release_asset_url(CoreType::Xray, "v1.8.10").unwrap();
        let singbox = release_asset_url(CoreType::SingBox, "v1.10.3").unwrap();
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;
        assert_eq!(
            xray,
            format!(
                "https://github.com/XTLS/Xray-core/releases/download/v1.8.10/{}",
                asset_name(CoreType::Xray, "1.8.10", os, arch).unwrap()
            )
        );
        assert_eq!(
            singbox,
            format!(
                "https://github.com/SagerNet/sing-box/releases/download/v1.10.3/{}",
                asset_name(CoreType::SingBox, "1.10.3", os, arch).unwrap()
            )
        );
    }

    /// Upstream archive naming is a table over (os, arch). Because the OS is an
    /// input, every platform is checked from every host — which is what makes
    /// the Windows rows a local regression test rather than a CI-only one.
    #[rstest]
    #[case::xray_linux_x86_64("linux", "x86_64", "1.8.0", CoreType::Xray, "Xray-linux-64.zip")]
    #[case::xray_linux_aarch64(
        "linux",
        "aarch64",
        "1.8.0",
        CoreType::Xray,
        "Xray-linux-arm64-v8a.zip"
    )]
    #[case::singbox_linux_x86_64(
        "linux",
        "x86_64",
        "1.8.0",
        CoreType::SingBox,
        "sing-box-1.8.0-linux-amd64.tar.gz"
    )]
    #[case::singbox_linux_aarch64(
        "linux",
        "aarch64",
        "1.8.0",
        CoreType::SingBox,
        "sing-box-1.8.0-linux-arm64.tar.gz"
    )]
    #[case::xray_windows_x86_64(
        "windows",
        "x86_64",
        "1.8.0",
        CoreType::Xray,
        "Xray-windows-64.zip"
    )]
    #[case::xray_windows_aarch64(
        "windows",
        "aarch64",
        "1.8.0",
        CoreType::Xray,
        "Xray-windows-arm64-v8a.zip"
    )]
    #[case::singbox_windows_x86_64(
        "windows",
        "x86_64",
        "1.8.0",
        CoreType::SingBox,
        "sing-box-1.8.0-windows-amd64.zip"
    )]
    #[case::singbox_windows_aarch64(
        "windows",
        "aarch64",
        "1.8.0",
        CoreType::SingBox,
        "sing-box-1.8.0-windows-arm64.zip"
    )]
    #[case::version_prefix_is_stripped(
        "linux",
        "x86_64",
        "v1.8.0",
        CoreType::Xray,
        "Xray-linux-64.zip"
    )]
    fn asset_name_follows_the_upstream_archive_tables(
        #[case] os: &'static str,
        #[case] arch: &'static str,
        #[case] version: &str,
        #[case] core: CoreType,
        #[case] expected: &str,
    ) {
        assert_eq!(asset_name(core, version, os, arch).unwrap(), expected);
    }

    /// The refusals are part of the contract: no guess for a platform the
    /// project does not target, and no asset at all for the pseudo-cores.
    #[test]
    fn asset_name_refuses_undeclared_platforms_and_pseudo_cores() {
        assert!(matches!(
            asset_name(CoreType::Xray, "1.8.0", "macos", "aarch64"),
            Err(UpdateError::UnsupportedPlatform("aarch64", "macos"))
        ));
        assert!(matches!(
            asset_name(CoreType::SingBox, "1.8.0", "linux", "riscv64"),
            Err(UpdateError::UnsupportedPlatform("riscv64", "linux"))
        ));
        for core in [CoreType::Auto, CoreType::Native] {
            assert!(matches!(
                asset_name(core, "1.8.0", "linux", "aarch64"),
                Err(UpdateError::AutoCore)
            ));
            assert!(matches!(
                release_asset_url(core, "v1.8.10"),
                Err(UpdateError::AutoCore)
            ));
        }
    }

    /// The redirect guard must recognise the local-use targets a malicious
    /// origin could move a fetch to (findings f10/f11).
    #[test]
    fn redirect_target_is_local_matches_local_use_hosts() {
        for local in [
            "http://127.0.0.1/x",
            "http://10.0.0.1/x",
            "http://192.168.1.1/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/x",
            "http://localhost/x",
            "http://foo.localhost/x",
            "http://printer.local/x",
        ] {
            assert!(
                redirect_target_is_local(&reqwest::Url::parse(local).unwrap()),
                "{local} must be refused as a redirect target"
            );
        }
        for public in [
            "https://example.com/x",
            "http://8.8.8.8/x",
            "https://github.com/x",
        ] {
            assert!(
                !redirect_target_is_local(&reqwest::Url::parse(public).unwrap()),
                "{public} must be allowed"
            );
        }
    }

    #[cfg(unix)]
    #[rstest]
    #[case::xray_managed_binary(
        CoreType::Xray,
        "leas-test-updater-xray",
        "xray 1.8.4",
        "1.8.4",
        false
    )]
    #[case::singbox_managed_binary(
        CoreType::SingBox,
        "leas-test-updater-singbox",
        "sing-box 1.10.3",
        "1.10.3",
        false
    )]
    #[case::find_binary_and_version_combined(
        CoreType::Xray,
        "leas-test-updater-combined",
        "xray 2.0.0",
        "2.0.0",
        true
    )]
    fn get_current_version_from_managed_binary(
        #[case] core_type: CoreType,
        #[case] tmp_name: &str,
        #[case] script_body: &str,
        #[case] expected: &str,
        #[case] assert_find_binary: bool,
    ) {
        use std::os::unix::fs::PermissionsExt;

        let tmp = std::env::temp_dir().join(tmp_name);
        let _ = std::fs::remove_dir_all(&tmp);
        let core_subdir = core_type.to_string();
        std::fs::create_dir_all(tmp.join(&core_subdir)).unwrap();

        let binary = tmp.join(&core_subdir).join(&core_subdir);
        std::fs::write(&binary, format!("#!/bin/sh\necho \"{script_body}\"\n")).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();

        if assert_find_binary {
            let found = crate::bin_manager::find_binary(core_type, &tmp);
            assert!(
                found.is_some(),
                "find_binary should find managed {core_subdir}"
            );
            assert_eq!(
                found.unwrap(),
                binary,
                "find_binary should return the managed path"
            );
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let version = rt.block_on(get_current_version(core_type, &tmp));
        assert_eq!(version, Some(expected.to_string()));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn get_current_version_returns_none_when_binary_missing() {
        let tmp = std::env::temp_dir().join("leas-test-updater-missing");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let version = rt.block_on(get_current_version(CoreType::Xray, &tmp));
        // Should be None since no binary exists in managed dir and likely not in PATH
        assert!(version.is_none(), "should return None when no binary found");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
