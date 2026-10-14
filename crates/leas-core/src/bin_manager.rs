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

/// The candidate executable names for `core_type` **as the running platform
/// spells them**: `["sing-box-client.exe", "sing-box.exe"]` on Windows,
/// `["sing-box-client", "sing-box"]` elsewhere.
///
/// This is the single owner of that spelling. `find_binary` walks the managed
/// directory and PATH with these names, and the updater uses the same list to
/// find the binary inside a freshly extracted upstream archive. The old
/// extensionless list could never match the real Windows case (upstream ships
/// `xray.exe`/`sing-box.exe`), and PATH was searched through `which`, which
/// Windows does not have — the two defects recorded at `roadmap.md:358`.
#[must_use]
pub fn exe_names(core_type: CoreType) -> Option<Vec<String>> {
    let info = get_core_info(core_type)?;
    Some(
        info.exe_names
            .iter()
            .map(|name| format!("{name}{}", std::env::consts::EXE_SUFFIX))
            .collect(),
    )
}

/// Find a core binary by checking the managed directory first, then PATH.
#[must_use]
pub fn find_binary(core_type: CoreType, bin_dir: &Path) -> Option<PathBuf> {
    let names = exe_names(core_type)?;

    // 1. Check managed binary directory (inside per-core subdirectory)
    let core_dir = bin_dir.join(core_type.to_string());
    if core_dir.is_dir() {
        for exe in &names {
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
    if let Some(path) = find_binary_recursive(&core_dir, &names) {
        return Some(path);
    }

    // 2. Check PATH with the platform's lookup tool: `where` on Windows,
    //    `which` elsewhere (`which` does not exist on Windows).
    let lookup = if cfg!(windows) { "where" } else { "which" };
    for exe in &names {
        if let Ok(out) = std::process::Command::new(lookup).arg(exe).output()
            && out.status.success()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // `where` lists every match, one per line; the first is the one it
            // would run.
            if let Some(first) = stdout.lines().map(str::trim).find(|line| !line.is_empty()) {
                let p = PathBuf::from(first);
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
fn find_binary_recursive(dir: &Path, exe_names: &[String]) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&current) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Some(name) = path.file_name().and_then(|n| n.to_str())
                    && exe_names.iter().any(|candidate| candidate == name)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Packaging {
    Zip,
    TarGz,
}

/// Which packaging a filename names, or `None` if it is not an archive this
/// module extracts. The single owner of that shape test, used both to choose an
/// extractor and to recognise a dropped-in download.
///
/// `.tar.gz` is two extensions, so it is matched the way `extract_archive`
/// always did: a `.gz` whose stem ends in `.tar`.
fn packaging(path: &Path) -> Option<Packaging> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("zip") => Some(Packaging::Zip),
        Some("gz")
            if path
                .file_stem()
                .and_then(|stem| Path::new(stem).extension())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tar")) =>
        {
            Some(Packaging::TarGz)
        }
        Some("tgz") => Some(Packaging::TarGz),
        _ => None,
    }
}

/// Extract a core binary archive (zip or tar.gz) into the target directory.
pub fn extract_archive(
    archive: &Path,
    _core_type: CoreType,
    target_dir: &Path,
) -> Result<(), BinError> {
    let ext = archive.extension().and_then(|e| e.to_str()).unwrap_or("");

    // Create target dir
    std::fs::create_dir_all(target_dir)?;

    match packaging(archive) {
        Some(Packaging::Zip) => extract_zip(archive, target_dir)?,
        Some(Packaging::TarGz) => extract_tar_gz(archive, target_dir)?,
        None => {
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

/// Which core an archive belongs to, and the per-core directory it extracts
/// into, or `None` for a file this path does not claim.
///
/// The names are the upstream ones and platform-shaped, which is why the match
/// is on the filename rather than on extensions alone: Xray ships
/// `Xray-<os>-<arch>.zip` everywhere, while sing-box ships
/// `sing-box-<version>-linux-<arch>.tar.gz` on Linux and
/// `sing-box-<version>-windows-<arch>.zip` on Windows (`Compress-Archive`).
/// Matching only `.tar.gz` ignored every sing-box download on Windows.
fn archive_core(name: &str) -> Option<(CoreType, &'static str)> {
    // Lowercased first: upstream builds the names from the target triple, but a
    // download keeps whatever case the filesystem had.
    let lower = name.to_lowercase();
    let packaging = packaging(Path::new(&lower))?;
    if lower.starts_with("xray") && packaging == Packaging::Zip {
        return Some((CoreType::Xray, "xray"));
    }
    if lower.starts_with("sing-box") {
        return Some((CoreType::SingBox, "sing-box"));
    }
    None
}

/// Find archives in the current directory and extract them to the bin dir.
pub fn find_and_extract_archives(bin_dir: &Path) -> Result<(), BinError> {
    let cwd = std::env::current_dir()?;

    for entry in std::fs::read_dir(&cwd)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Some((core_type, core_dir)) = archive_core(name) else {
            continue;
        };
        extract_archive(&path, core_type, &bin_dir.join(core_dir))?;
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
    use rstest::rstest;

    /// A fixture binary's name as THIS platform spells an executable. The
    /// fixture and the product have to agree, and on Windows that means `.exe`
    /// — the mismatch is exactly the shipped defect, so the tests must not
    /// hardcode the extensionless spelling the product used to look for.
    fn exe(name: &str) -> String {
        format!("{name}{}", std::env::consts::EXE_SUFFIX)
    }

    /// A versioned sing-box release directory, named the way upstream does
    /// (`sing-box-<version>-<os>-<arch>`), so a fixture never hardcodes a Linux
    /// spelling next to a platform-spelled binary.
    fn version_dir(root: &Path) -> PathBuf {
        root.join(format!(
            "sing-box-1.13.13-{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
    }

    /// The platform spelling is one owner: `find_binary` walks the managed
    /// directory and PATH with these names, and the updater looks inside an
    /// extracted archive with the same list.
    #[test]
    fn exe_names_carry_the_platform_suffix() {
        let suffix = std::env::consts::EXE_SUFFIX;
        assert_eq!(
            exe_names(CoreType::Xray).unwrap(),
            vec![format!("xray{suffix}")]
        );
        assert_eq!(
            exe_names(CoreType::SingBox).unwrap(),
            vec![
                format!("sing-box-client{suffix}"),
                format!("sing-box{suffix}")
            ]
        );
        // The base table stays extensionless: it is the source the suffix is
        // applied to, not the lookup list.
        assert_eq!(get_core_info(CoreType::Xray).unwrap().exe_names, &["xray"]);
        assert_eq!(exe_names(CoreType::Auto), None);
        assert_eq!(exe_names(CoreType::Native), None);
    }

    /// The drop-in path must recognise the platform packagings, not only the
    /// Linux ones: matching `.tar.gz` alone ignored every sing-box archive a
    /// Windows user could download.
    #[rstest]
    #[case::xray_linux_zip("Xray-linux-64.zip", Some((CoreType::Xray, "xray")))]
    #[case::xray_windows_zip("Xray-windows-64.zip", Some((CoreType::Xray, "xray")))]
    #[case::singbox_linux_tarball(
        "sing-box-1.13.13-linux-amd64.tar.gz",
        Some((CoreType::SingBox, "sing-box"))
    )]
    #[case::singbox_windows_zip(
        "sing-box-1.13.13-windows-amd64.zip",
        Some((CoreType::SingBox, "sing-box"))
    )]
    #[case::uppercase_is_matched("XRAY-WINDOWS-64.ZIP", Some((CoreType::Xray, "xray")))]
    #[case::unrelated_zip("geoip.zip", None)]
    #[case::unrelated_tarball("geosite.tar.gz", None)]
    #[case::xray_only_ships_zips("xray.tar.gz", None)]
    fn archive_core_matches_the_upstream_packagings(
        #[case] name: &str,
        #[case] expected: Option<(CoreType, &'static str)>,
    ) {
        assert_eq!(archive_core(name), expected);
    }

    #[rstest]
    #[case::xray(CoreType::Xray, Some(&["xray"][..]))]
    #[case::singbox(CoreType::SingBox, Some(&["sing-box"][..]))]
    #[case::auto_is_none(CoreType::Auto, None)]
    #[case::native_is_none(CoreType::Native, None)]
    fn get_core_info_table(
        #[case] core_type: CoreType,
        #[case] expected_exe_names: Option<&[&str]>,
    ) {
        match (get_core_info(core_type), expected_exe_names) {
            (Some(info), Some(names)) => {
                for name in names {
                    assert!(
                        info.exe_names.contains(name),
                        "{core_type:?} must expose {name}"
                    );
                }
                assert_eq!(info.args_template, "run -c {0}");
            }
            (None, None) => {}
            (info, names) => panic!("unexpected info for {core_type:?}: {info:?}/{names:?}"),
        }
    }

    #[test]
    fn find_binary_managed_path_resolution() {
        let tmp = std::env::temp_dir().join("leas-test-find-binary");
        let _ = std::fs::remove_dir_all(&tmp);

        std::fs::create_dir_all(&tmp).unwrap();

        // Create managed binary at tmp/xray/xray
        let core_dir = tmp.join("xray");
        std::fs::create_dir_all(&core_dir).unwrap();
        let binary = core_dir.join(exe("xray"));
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
        let binary = core_dir.join(exe("sing-box"));
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
        let binary = core_dir.join(exe("xray"));
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

        // Create versioned subdirectory like sing-box-1.13.13-<os>-<arch>/sing-box<exe>
        let version_dir = version_dir(&tmp.join("sing-box"));
        std::fs::create_dir_all(&version_dir).unwrap();
        let binary = version_dir.join(exe("sing-box"));
        std::fs::write(&binary, "fake sing-box").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let found = find_binary(CoreType::SingBox, &tmp);
        let found = found.expect("should find sing-box via recursive search");
        // Compare path COMPONENTS: a string compare would bake in `/` and fail
        // on Windows, whose separator is `\` — which is what this assertion did.
        assert!(
            found.ends_with(version_dir.join(exe("sing-box"))),
            "should find binary inside versioned subdirectory, got {}",
            found.display()
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
        let flat_binary = core_dir.join(exe("sing-box"));
        std::fs::write(&flat_binary, "flat sing-box").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&flat_binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Create nested binary too
        let version_dir = version_dir(&core_dir);
        std::fs::create_dir_all(&version_dir).unwrap();
        let nested_binary = version_dir.join(exe("sing-box"));
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

    #[rstest]
    #[case::files_present(
        "leas-test-flatten-noop",
        &[("subdir", true), ("top_file", false)],
        &["subdir", "top_file"]
    )]
    #[case::multiple_dirs(
        "leas-test-flatten-multi",
        &[("dir1", true), ("dir2", true)],
        &["dir1", "dir2"]
    )]
    fn flatten_single_top_dir_noop_unless_exactly_one_subdir(
        #[case] tmp_name: &str,
        #[case] entries: &[(&str, bool)],
        #[case] expected_remaining: &[&str],
    ) {
        let tmp = std::env::temp_dir().join(tmp_name);
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        for (name, is_dir) in entries {
            if *is_dir {
                std::fs::create_dir_all(tmp.join(name)).unwrap();
            } else {
                std::fs::write(tmp.join(name), "top").unwrap();
            }
        }

        flatten_single_top_dir(&tmp);

        for name in expected_remaining {
            assert!(tmp.join(name).exists(), "{name} should remain");
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
