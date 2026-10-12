use crate::core_type::CoreType;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct CoreBinInfo {
    pub exe_names: &'static [&'static str],
    pub args_template: &'static str,
}

#[must_use]
pub const fn get_core_info(core_type: CoreType) -> Option<CoreBinInfo> {
    match core_type {
        CoreType::Xray => Some(CoreBinInfo {
            exe_names: &["xray"],
            args_template: "run -c {0}",
        }),
        CoreType::SingBox => Some(CoreBinInfo {
            exe_names: &["sing-box-client", "sing-box"],
            args_template: "run -c {0}",
        }),
        CoreType::Auto | CoreType::Native => None,
    }
}

/// Find a core binary by checking the managed directory first, then PATH.
#[must_use]
pub fn find_binary(core_type: CoreType, bin_dir: &Path) -> Option<PathBuf> {
    let info = get_core_info(core_type)?;

    // 1. Check managed binary directory (inside per-core subdirectory)
    let core_dir = bin_dir.join(core_type.to_string());
    if core_dir.is_dir() {
        for exe in info.exe_names {
            let managed = core_dir.join(exe);
            if managed.is_file() {
                // Check if executable (on Unix, file must be executable)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = managed.metadata()
                        && meta.permissions().mode() & 0o111 != 0
                    {
                        return Some(managed);
                    }
                }
                #[cfg(not(unix))]
                {
                    return Some(managed);
                }
            }
        }
    }

    // 1b. If flat check failed, search recursively inside core_dir
    if let Some(path) = find_binary_recursive(&core_dir, info.exe_names) {
        return Some(path);
    }

    // 2. Check PATH via `which` command
    for exe in info.exe_names {
        if let Ok(path) = std::process::Command::new("which").arg(exe).output()
            && path.status.success()
        {
            let path_str = String::from_utf8_lossy(&path.stdout);
            let trimmed = path_str.trim();
            if !trimmed.is_empty() {
                let p = PathBuf::from(trimmed);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }

    None
}

/// Search recursively for any of the given executable names in `dir`.
/// Returns the first match that passes the executable check (Unix).
fn find_binary_recursive(dir: &Path, exe_names: &[&str]) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&current) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && exe_names.contains(&name)
                {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(meta) = path.metadata()
                            && meta.permissions().mode() & 0o111 != 0
                        {
                            return Some(path);
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        return Some(path);
                    }
                }
            }
        }
    }
    None
}

/// Extract a core binary archive (zip or tar.gz) into the target directory.
pub fn extract_archive(
    archive: &Path,
    _core_type: CoreType,
    target_dir: &Path,
) -> Result<(), BinError> {
    let ext = archive.extension().and_then(|e| e.to_str()).unwrap_or("");

    let stem = archive.file_stem().and_then(|s| s.to_str()).unwrap_or("");

    // Create target dir
    std::fs::create_dir_all(target_dir)?;

    match ext {
        "zip" => extract_zip(archive, target_dir)?,
        "gz" | "tgz"
            if std::path::Path::new(stem)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tar"))
                || ext == "tgz" =>
        {
            extract_tar_gz(archive, target_dir)?;
        }
        _ => {
            return Err(BinError::ExtractionFailed(format!(
                "Unsupported archive format: .{ext}"
            )));
        }
    }

    Ok(())
}

fn extract_zip(archive: &Path, target_dir: &Path) -> Result<(), BinError> {
    let file = std::fs::File::open(archive)?;
    let mut archive_zip = zip::ZipArchive::new(file)?;

    for i in 0..archive_zip.len() {
        let mut entry = archive_zip.by_index(i)?;
        if let Some(name) = entry.enclosed_name() {
            let target_path = target_dir.join(name);
            if entry.is_dir() {
                std::fs::create_dir_all(&target_path)?;
            } else {
                if let Some(parent) = target_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut outfile = std::fs::File::create(&target_path)?;
                std::io::copy(&mut entry, &mut outfile)?;
            }
        }
    }

    Ok(())
}

fn extract_tar_gz(archive: &Path, target_dir: &Path) -> Result<(), BinError> {
    let file = std::fs::File::open(archive)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive_tar = tar::Archive::new(decoder);

    for entry in archive_tar.entries()? {
        let mut entry = entry?;
        if let Some(path) = entry.path()?.parent() {
            std::fs::create_dir_all(target_dir.join(path))?;
        }
        entry.unpack_in(target_dir)?;
    }

    flatten_single_top_dir(target_dir);
    Ok(())
}

/// If `dir` contains only a single subdirectory (no standalone files at top level),
/// move all contents of that subdirectory up one level and remove the subdirectory.
///
/// Handles archives that wrap their payload in a versioned directory
/// (e.g., `sing-box-X.Y.Z-linux-amd64/sing-box`).
pub(crate) fn flatten_single_top_dir(dir: &Path) {
    let entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(std::result::Result::ok).collect(),
        Err(_) => return,
    };

    let mut subdirs = Vec::new();
    let mut have_file = false;
    for entry in &entries {
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            subdirs.push(entry.path());
        } else {
            have_file = true;
        }
    }

    if subdirs.len() != 1 || have_file {
        return; // nothing to flatten
    }

    let top_dir = &subdirs[0];
    if let Ok(rd) = std::fs::read_dir(top_dir) {
        for entry in rd.flatten() {
            let name = entry.file_name();
            let dst = dir.join(&name);
            let src = entry.path();
            // Try rename (fast, same filesystem) then fall back to copy+delete
            if let Err(e) = std::fs::rename(&src, &dst)
                && e.kind() == std::io::ErrorKind::CrossesDevices
            {
                let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
                if is_dir {
                    let _ = copy_dir_contents(&src, &dst).map(|()| {
                        let _ = std::fs::remove_dir_all(&src);
                    });
                } else if std::fs::copy(&src, &dst).is_ok() {
                    let _ = std::fs::remove_file(&src);
                }
                // else: permission denied, etc. — skip this entry
            }
        }
    }
    let _ = std::fs::remove_dir_all(top_dir);
}

/// Recursively copy all entries from `src_dir` into `dst_dir`.
fn copy_dir_contents(src_dir: &Path, dst_dir: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dst_dir)?;
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let src = entry.path();
        let dst = dst_dir.join(&name);
        if entry.file_type()?.is_dir() {
            copy_dir_contents(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// Find archives in the current directory and extract them to the bin dir.
pub fn find_and_extract_archives(bin_dir: &Path) -> Result<(), BinError> {
    let cwd = std::env::current_dir()?;

    // Xray zip
    for entry in std::fs::read_dir(&cwd)? {
        let entry = entry?;
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        if name.starts_with("xray")
            && std::path::Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
        {
            let xray_dir = bin_dir.join("xray");
            extract_archive(&path, CoreType::Xray, &xray_dir)?;
        }

        if name.starts_with("sing-box") && name.ends_with(".tar.gz") {
            let singbox_dir = bin_dir.join("sing-box");
            extract_archive(&path, CoreType::SingBox, &singbox_dir)?;
        }
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum BinError {
    #[error("Binary not found: {0}")]
    NotFound(String),
    #[error("Archive extraction failed: {0}")]
    ExtractionFailed(String),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Zip error: {0}")]
    ZipError(#[from] zip::result::ZipError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_core_info_xray() {
        let info = get_core_info(CoreType::Xray).unwrap();
        assert!(info.exe_names.contains(&"xray"));
        assert_eq!(info.args_template, "run -c {0}");
    }

    #[test]
    fn get_core_info_singbox() {
        let info = get_core_info(CoreType::SingBox).unwrap();
        assert!(info.exe_names.contains(&"sing-box"));
        assert_eq!(info.args_template, "run -c {0}");
    }

    #[test]
    fn get_core_info_auto_is_none() {
        assert!(get_core_info(CoreType::Auto).is_none());
    }

    #[test]
    fn get_core_info_native_is_none() {
        assert!(get_core_info(CoreType::Native).is_none());
    }

    #[test]
    fn find_binary_managed_path_resolution() {
        let tmp = std::env::temp_dir().join("leas-test-find-binary");
        let _ = std::fs::remove_dir_all(&tmp);

        std::fs::create_dir_all(&tmp).unwrap();

        // Create managed binary at tmp/xray/xray
        let core_dir = tmp.join("xray");
        std::fs::create_dir_all(&core_dir).unwrap();
        let binary = core_dir.join("xray");
        std::fs::write(&binary, "fake binary content").unwrap();
        // Mark executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Should find binary at tmp/xray/xray (managed path)
        let found = find_binary(CoreType::Xray, &tmp);
        assert!(found.is_some(), "should find managed binary");
        assert_eq!(
            found.unwrap(),
            binary,
            "should return managed path, not PATH"
        );

        // Binary outside core subdir should NOT be found by managed-path check
        // (it would only be found via which/PATH if xray is in PATH)
        let wrong_binary = tmp.join("xray_bad");
        std::fs::write(&wrong_binary, "wrong location").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrong_binary, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let found2 = find_binary(CoreType::Xray, &tmp);
        // Should still find the correct managed one, not wrong_binary
        assert_eq!(found2, Some(binary));

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn find_binary_singbox_managed_path() {
        let tmp = std::env::temp_dir().join("leas-test-find-singbox");
        let _ = std::fs::remove_dir_all(&tmp);

        let core_dir = tmp.join("sing-box");
        std::fs::create_dir_all(&core_dir).unwrap();
        let binary = core_dir.join("sing-box");
        std::fs::write(&binary, "fake sing-box").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let found = find_binary(CoreType::SingBox, &tmp);
        assert!(found.is_some(), "should find managed sing-box binary");
        assert_eq!(found.unwrap(), binary);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    #[cfg(unix)]
    fn find_binary_skips_non_executable_in_managed_dir() {
        let tmp = std::env::temp_dir().join("leas-test-find-non-exec");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Create managed binary at tmp/xray/xray WITHOUT executable bit
        let core_dir = tmp.join("xray");
        std::fs::create_dir_all(&core_dir).unwrap();
        let binary = core_dir.join("xray");
        std::fs::write(&binary, "fake non-executable binary").unwrap();
        // Intentionally NOT setting executable permissions

        // Non-executable file in managed dir must be skipped.
        // Falls through to which(PATH). If xray is in PATH, returns that;
        // otherwise returns None. Either way, the managed-dir path is not returned.
        let found = find_binary(CoreType::Xray, &tmp);
        assert_ne!(
            found.as_deref(),
            Some(binary.as_path()),
            "non-executable managed file must be skipped"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn find_binary_recursive_singbox_versioned_dir() {
        let tmp = std::env::temp_dir().join("leas-test-find-recursive-singbox");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Create versioned subdirectory like sing-box-1.13.13-linux-amd64/sing-box
        let version_dir = tmp.join("sing-box/sing-box-1.13.13-linux-amd64");
        std::fs::create_dir_all(&version_dir).unwrap();
        let binary = version_dir.join("sing-box");
        std::fs::write(&binary, "fake sing-box").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let found = find_binary(CoreType::SingBox, &tmp);
        assert!(found.is_some(), "should find sing-box via recursive search");
        assert!(
            found
                .as_deref()
                .unwrap()
                .to_string_lossy()
                .contains("sing-box-1.13.13-linux-amd64/sing-box"),
            "should find binary inside versioned subdirectory"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn find_binary_flat_wins_over_recursive() {
        let tmp = std::env::temp_dir().join("leas-test-flat-wins");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Create flat binary at tmp/sing-box/sing-box
        let core_dir = tmp.join("sing-box");
        std::fs::create_dir_all(&core_dir).unwrap();
        let flat_binary = core_dir.join("sing-box");
        std::fs::write(&flat_binary, "flat sing-box").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&flat_binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Create nested binary too
        let version_dir = core_dir.join("sing-box-1.13.13-linux-amd64");
        std::fs::create_dir_all(&version_dir).unwrap();
        let nested_binary = version_dir.join("sing-box");
        std::fs::write(&nested_binary, "nested sing-box").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&nested_binary, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }

        let found = find_binary(CoreType::SingBox, &tmp);
        assert_eq!(
            found.as_deref(),
            Some(flat_binary.as_path()),
            "flat binary should win over nested"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn flatten_single_top_dir_moves_contents_up() {
        let tmp = std::env::temp_dir().join("leas-test-flatten");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("version-dir")).unwrap();

        std::fs::write(tmp.join("version-dir/binary"), "binary_content").unwrap();
        std::fs::write(tmp.join("version-dir/config.json"), r#"{"key":"value"}"#).unwrap();

        flatten_single_top_dir(&tmp);

        assert!(tmp.join("binary").exists(), "binary should be at top level");
        assert!(
            tmp.join("config.json").exists(),
            "config should be at top level"
        );
        assert!(
            !tmp.join("version-dir").exists(),
            "version dir should be removed"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.join("binary")).unwrap(),
            "binary_content"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn flatten_single_top_dir_noop_when_files_present() {
        let tmp = std::env::temp_dir().join("leas-test-flatten-noop");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("subdir")).unwrap();
        std::fs::write(tmp.join("top_file"), "top").unwrap();

        flatten_single_top_dir(&tmp);

        assert!(tmp.join("subdir").exists(), "subdir should remain");
        assert!(tmp.join("top_file").exists(), "top file should remain");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn flatten_single_top_dir_noop_multiple_dirs() {
        let tmp = std::env::temp_dir().join("leas-test-flatten-multi");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("dir1")).unwrap();
        std::fs::create_dir_all(tmp.join("dir2")).unwrap();

        flatten_single_top_dir(&tmp);

        assert!(tmp.join("dir1").exists(), "dir1 should remain");
        assert!(tmp.join("dir2").exists(), "dir2 should remain");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn flatten_single_top_dir_empty_dir() {
        let tmp = std::env::temp_dir().join("leas-test-flatten-empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir(&tmp).unwrap();

        flatten_single_top_dir(&tmp);
        assert!(tmp.exists());

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
