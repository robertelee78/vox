//! The previous release's `vox` binary, fetched once per target directory and checked against its
//! published SHA-256: what a person upgrading from it has on disk is what it wrote, not what this
//! build's code thinks it wrote. Included with `#[path]` by the proofs that start from it.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

/// The release the migration arm starts from, and its binaries' published SHA-256.
pub const PREVIOUS: &str = "v0.2.9";
pub const PREVIOUS_SHA256: &[(&str, &str)] = &[
    (
        "aarch64-apple-darwin",
        "1015a3296541e94bc18ec92af43badc0eeabf98db99a92b4b88553fbea79bd31",
    ),
    (
        "x86_64-apple-darwin",
        "5efb392656f7e87bfbb726167408eca75fa96b49ff572deb25a698fb84388b73",
    ),
    (
        "x86_64-unknown-linux-gnu",
        "7b622d32cffa14eb18cc0471b31b6b85d7da487adb4786016ab42577d9924b3d",
    ),
];

/// The released binary for this platform, fetched once per target directory and checked against
/// its published SHA-256.
pub fn previous_release() -> PathBuf {
    let triple = match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        other => panic!("CANNOT MEASURE: {PREVIOUS} was not released for {other:?}"),
    };
    let want = PREVIOUS_SHA256
        .iter()
        .find(|(t, _)| *t == triple)
        .map(|(_, h)| *h)
        .unwrap_or_else(|| panic!("APPARATUS: no published SHA-256 for {triple} in this proof"));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("vox-{PREVIOUS}"));
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", dir.display()));
    let exe = dir.join(format!("vox-{triple}"));
    let digest = |p: &Path| hex(&Sha256::digest(std::fs::read(p).unwrap_or_default()));
    if !exe.is_file() || digest(&exe) != want {
        let url = format!(
            "https://github.com/robertelee78/vox/releases/download/{PREVIOUS}/vox-{triple}"
        );
        let part = dir.join("download.part");
        let fetched = Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o"])
            .arg(&part)
            .arg(&url)
            .status()
            .is_ok_and(|s| s.success());
        assert!(fetched, "CANNOT MEASURE: could not fetch {url}");
        let got = digest(&part);
        assert!(
            got == want,
            "CANNOT MEASURE: {url} does not match its published SHA-256 (got {got}, want {want}) — \
             the download, or the published artifact, is not the {PREVIOUS} this proof starts from"
        );
        std::fs::rename(&part, &exe).unwrap_or_else(|e| {
            panic!(
                "APPARATUS: could not move {} into place: {e}",
                exe.display()
            )
        });
    }
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not make {} executable: {e}",
            exe.display()
        )
    });
    exe
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
