//! **The previous published release's `vox`**, downloaded and checked as `vox update` checks it:
//! the release named by `VOX_UPGRADE_FROM` (a version, `0.4.0`), or the newest stable one, its
//! size and SHA-256 against its release record (ADR-026 F-3, ADR-011 requirement 14). The proofs
//! that run a person's previous release beside this build use it. Every failure here is the
//! network's or the release's, `APPARATUS:`, never this build's.
//!
//! Included with `#[path]` by a proof, which is why not every item is used by every includer.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository whose releases are the upgrade's source.
const REPO: &str = "robertelee78/vox";

/// This build's target, as the release names its assets.
pub fn target_triple() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else {
        panic!("APPARATUS: no release asset is published for this target")
    }
}

/// `url` fetched to `out` by curl (https only); `Err` says what went wrong. Every failure here is
/// the network's or the release's, never this build's.
fn fetch(url: &str, out: &Path) -> Result<(), String> {
    let o = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "10",
            "--max-time",
            "300",
            "--output",
        ])
        .arg(out)
        .arg(url)
        .output()
        .map_err(|e| format!("curl could not be run: {e}"))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(format!(
            "curl {url}: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ))
    }
}

/// The string value of `key` in a flat JSON record.
fn field(json: &str, key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    match &v[key] {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// **The published release a person upgrades from**: `VOX_UPGRADE_FROM` (a version, `0.4.0`), or
/// the newest stable release. Its binary is downloaded into `dir` and checked against the size and
/// SHA-256 its release record gives, as `vox update` checks it. `(version, path)`.
pub fn previous_release(dir: &Path) -> (String, PathBuf) {
    use sha2::Digest as _;
    let triple = target_triple();
    let record_path = dir.join("record.json");
    let version = match std::env::var("VOX_UPGRADE_FROM") {
        Ok(v) if !v.trim().is_empty() => v.trim().trim_start_matches('v').to_owned(),
        _ => {
            let url =
                format!("https://github.com/{REPO}/releases/latest/download/stable-{triple}.json");
            fetch(&url, &record_path)
                .unwrap_or_else(|e| panic!("APPARATUS: the newest release's record: {e}"));
            let json = std::fs::read_to_string(&record_path).unwrap_or_default();
            field(&json, "version").unwrap_or_else(|| {
                panic!("APPARATUS: the newest release's record names no version: {json:?}")
            })
        }
    };
    let base = format!("https://github.com/{REPO}/releases/download/v{version}");
    fetch(&format!("{base}/stable-{triple}.json"), &record_path)
        .unwrap_or_else(|e| panic!("APPARATUS: v{version}'s release record: {e}"));
    let record = std::fs::read_to_string(&record_path).unwrap_or_default();
    let (Some(size), Some(sha)) = (field(&record, "size"), field(&record, "sha256")) else {
        panic!("APPARATUS: v{version}'s release record gives no size and digest: {record:?}")
    };
    let bin = dir.join(format!("vox-{version}"));
    fetch(&format!("{base}/vox-{triple}"), &bin)
        .unwrap_or_else(|e| panic!("APPARATUS: v{version}'s vox: {e}"));
    let bytes = std::fs::read(&bin).expect("APPARATUS: reading the downloaded vox");
    let got = format!("{:x}", sha2::Sha256::digest(&bytes));
    assert!(
        bytes.len().to_string() == size && got == sha,
        "APPARATUS: the vox downloaded for v{version} is not the published one: {} bytes, sha256 \
         {got}; the record says {size} bytes, sha256 {sha}",
        bytes.len()
    );
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
            .expect("APPARATUS: making the downloaded vox executable");
    }
    let said = Command::new(&bin)
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    assert!(
        said.contains(&version),
        "APPARATUS: the downloaded vox does not say it is v{version}: {said:?}"
    );
    println!(
        "[proof] the previous release, v{version}: {} ({size} bytes, sha256 {sha})",
        bin.display()
    );
    (version, bin)
}
