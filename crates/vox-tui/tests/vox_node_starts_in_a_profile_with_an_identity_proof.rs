//! V210-70 — **`vox node --serve trusted` starts in a profile that has an identity**, and leaves
//! neither the identity passphrase nor the trust list readable, through the shipped binary. (Plain
//! `vox node` in such a profile is the operator first-run proof's, #298.)
//!
//! `--serve trusted` keeps the anchor's trust list in its own profile, which means the profile
//! has an identity (`vox id`). A person who did that saw `vox node` refuse to start:
//!
//! ```text
//! vox node: node: another vox already has this profile open
//! ```
//!
//! The headless node opened the profile's vault — whose store it then held — and then opened
//! the same store again for its anchored logs. A headless node networks as its key file and
//! holds no room, so it never needs the vault.
//!
//! **Staging.** One profile, `vox id` in it, `vox trust add` of one fingerprint, then
//! `vox node --serve trusted`.
//!
//! **Asserted.**
//! 1. It prints its `--anchor` spec within 120 s (it fails the proof if it exits first), never
//!    says the profile is already open, and says it serves only the 1 trusted identity's rooms.
//! 2. With `--serve trusted` running, neither the identity passphrase nor the trusted
//!    fingerprint (as text or as its 32 bytes) appears in anything the anchor printed or in any
//!    file under the profile's data or config directory, and the passphrase is not on its
//!    command line.
//!
//! **Mutation that must turn it red.** In `node::actor`'s `spawn_config`, open the profile's
//! vault for a headless node again (`Profile::exists` without the `headless.is_none()` guard).
//! The start fails with "another vox already has this profile open".

#![cfg(unix)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::path::Path;
use std::time::Duration;

use world::{args, vox_once, VoxProc, IDENTITY};

/// How long `vox node` may take to print its spec. A start takes seconds; the defect exits at
/// once.
const START_BOUND: Duration = Duration::from_secs(120);

/// Every file under `dir`, recursively.
fn files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Start `vox node` with `extra` and wait for its spec. A node that exits first fails here,
/// with everything it said.
fn start(data: &Path, extra: &[&str]) -> VoxProc {
    let mut argv = vec!["node", "--listen", "127.0.0.1:0"];
    argv.extend_from_slice(extra);
    let mut p = VoxProc::spawn("anchor", data, &args(&argv));
    p.expect_within(START_BOUND, "its --anchor spec", |l| {
        l.contains("@/ip4/127.0.0.1/udp/")
    });
    p
}

#[test]
#[ignore = "real vox processes with production Argon2id; run in release"]
fn vox_node_starts_in_a_profile_with_an_identity_and_keeps_its_trust_list_sealed() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let data = hostile::profile_dir(tmp.path(), "anchor");
    hostile::fingerprint(&data);
    let trusted = hostile::stranger(0x71);
    let trusted_fp = vox_core::identity::composite::RootSigner::fingerprint(&trusted);
    let trusted_b32 = vox_core::node::link::b32_encode(&trusted_fp);
    let (ok, out, err) = vox_once(
        &data,
        &args(&["trust", "add", &trusted_b32, "--name", "friend"]),
    );
    assert!(
        ok,
        "PRODUCT (staging): vox trust add in the anchor's profile: {out}{err}"
    );

    // ---- 1. the start --------------------------------------------------------------------------
    {
        let mut node = start(&data, &["--serve", "trusted"]);
        let said = node.transcript();
        println!("[proof] vox node --serve trusted in a profile with an identity: started");
        assert!(
            !said.contains("already has this profile open"),
            "PRODUCT: `vox node --serve trusted` said the profile is already open:\n{said}"
        );
        assert!(
            said.contains("serving only rooms made by the 1 identity this profile trusts"),
            "PRODUCT: `vox node --serve trusted` did not say it serves only the trusted identity's rooms:\n{said}"
        );

        // ---- 2. nothing readable, while it runs ----------------------------------------------
        let pid = node.child.id();
        let argv = std::process::Command::new("ps")
            .args(["-o", "command=", "-p", &pid.to_string()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        assert!(
            !argv.trim().is_empty(),
            "CANNOT MEASURE: could not read the anchor's command line"
        );
        let mut all = Vec::new();
        files(&data, &mut all);
        let mut leaks = Vec::new();
        for f in &all {
            let Ok(bytes) = std::fs::read(f) else {
                continue;
            };
            for (what, needle) in [
                ("the identity passphrase", IDENTITY.as_bytes()),
                ("the trusted fingerprint", trusted_b32.as_bytes()),
                ("the trusted fingerprint's bytes", &trusted_fp[..]),
            ] {
                if contains(&bytes, needle) {
                    leaks.push(format!("{what} in {}", f.display()));
                }
            }
        }
        for (what, needle) in [
            ("the identity passphrase", IDENTITY),
            ("the trusted fingerprint", trusted_b32.as_str()),
        ] {
            if said.contains(needle) {
                leaks.push(format!("{what} in what the anchor printed"));
            }
            if argv.contains(needle) {
                leaks.push(format!("{what} on the anchor's command line"));
            }
        }
        println!(
            "[proof] --serve trusted: {} file(s) under the profile checked, {} leak(s)",
            all.len(),
            leaks.len()
        );
        assert!(
            all.len() >= 3,
            "CANNOT MEASURE: only {} file(s) under the anchor's profile",
            all.len()
        );
        assert!(
            leaks.is_empty(),
            "PRODUCT: `vox node --serve trusted` left its secrets readable: {leaks:?}"
        );
        drop(node);
    }
}

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

    let bare = hostile::profile_dir(tmp.path(), "bare");
    let (ok, said) = run(&bare);
    println!(
        "[proof] --serve trusted, no identity: ok={ok}: {}",
        said.trim()
    );
    assert!(
        !ok && said.contains("has no identity") && said.contains("vox trust add"),
        "`vox node --serve trusted` in a profile with no identity must refuse and say to make one: \
         ok={ok}: {said}"
    );

    let locked = hostile::profile_dir(tmp.path(), "locked");
    hostile::fingerprint(&locked);
    let store = locked.join("default").join("store.redb");
    assert!(
        store.is_file(),
        "CANNOT MEASURE: no store at {}",
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
        "`vox node --serve trusted` with an unreadable store must say the list exists but could \
         not be opened, and must not advise making one: ok={ok}: {said}"
    );
}
