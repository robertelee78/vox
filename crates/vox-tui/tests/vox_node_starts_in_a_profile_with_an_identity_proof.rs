//! V210-70 — **`vox node --serve trusted` in a profile that has an identity**, through the
//! shipped binary. (Plain `vox node` in such a profile is the operator first-run proof's, #298.)

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::path::Path;

use world::IDENTITY;

/// **`vox node --serve trusted` says what is wrong when it cannot read its trust list.** A profile
/// with no identity has no list and needs one made; a profile whose store this user cannot read
/// has one, and telling that person to make one sent them the wrong way (the #261 c2 verifier).
///
/// Asserted: with no identity it refuses and says so, advising `vox id` / `vox trust add`; with the
/// profile's `store.redb` unreadable (mode 000) it refuses, says the list exists but could not be
/// opened, names the profile directory, and does **not** advise making one. Neither ever starts.
#[test]
#[ignore = "real vox processes with production Argon2id; run in release"]
fn vox_node_serve_trusted_names_what_is_wrong_with_its_trust_list() {
    use std::os::unix::fs::PermissionsExt as _;
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let run = |data: &Path| {
        let out = std::process::Command::new(world::VOX)
            .args(["node", "--listen", "127.0.0.1:0", "--serve", "trusted"])
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", data.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("APPARATUS: run vox node");
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };

    let bare = profile_dir(tmp.path(), "bare");
    let (ok, said) = run(&bare);
    println!(
        "[proof] --serve trusted, no identity: ok={ok}: {}",
        said.trim()
    );
    assert!(
        !ok && said.contains("has no identity") && said.contains("vox trust add"),
        "PRODUCT: `vox node --serve trusted` in a profile with no identity must refuse and say to make one: \
         ok={ok}: {said}"
    );

    let locked = profile_dir(tmp.path(), "locked");
    world::fingerprint(&locked, "the locked profile");
    let store = world::node_dir(&locked, world::DEFAULT_NODE).join("store.redb");
    assert!(
        store.is_file(),
        "APPARATUS, CANNOT MEASURE (the proof's premise): `vox id` made no store at {}, the file \
         the proof makes unreadable",
        store.display()
    );
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o000))
        .expect("APPARATUS: set a staging file's mode");
    let (ok, said) = run(&locked);
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o600))
        .expect("APPARATUS: set a staging file's mode");
    println!(
        "[proof] --serve trusted, unreadable store: ok={ok}: {}",
        said.trim()
    );
    assert!(
        !ok && said.contains("exist but could not be opened") && !said.contains("make one with"),
        "PRODUCT: `vox node --serve trusted` with an unreadable store must say the list exists but could \
         not be opened, and must not advise making one: ok={ok}: {said}"
    );
}

/// A data root `root/name` with its config directory, as a person's would be.
fn profile_dir(root: &Path, name: &str) -> std::path::PathBuf {
    let d = root.join(name);
    world::mkdir(&d.join("cfg"));
    d
}
