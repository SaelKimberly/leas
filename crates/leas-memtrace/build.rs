//! Stamps the short git revision into the artifacts, so two runs are
//! distinguishable without a transcript. Best effort: a packaged source tree or
//! a checkout without git reports `unknown`.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    let rev = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|rev| rev.trim().to_owned())
        .filter(|rev| !rev.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    // A working tree with edits is not the commit it claims to be.
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .is_ok_and(|out| out.status.success() && !out.stdout.is_empty());
    if dirty && rev != "unknown" {
        println!("cargo:rustc-env=LEAS_GIT_REV={rev}-dirty");
    } else {
        println!("cargo:rustc-env=LEAS_GIT_REV={rev}");
    }
}
