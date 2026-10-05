//! V210-55 (#241) — **a file whose loss loses the identity is written durably**, through the
//! shipped binary.
//!
//! `vault.cbor` (the identity, sealed under its passphrase) and a headless node's
//! `node-identity.key` (its seeds, in the clear by design) are published by writing a temporary
//! file and renaming it over the old one. Before V210-55 the temporary file was renamed without
//! being flushed, and the directory was not flushed after: a power loss could leave the new name
//! on an empty file, and the identity gone with it. And it was created at the umask's mode and
//! `chmod`ed to `0600` after, leaving a headless node's seeds readable by other local users for a
//! moment.
//!
//! A power loss cannot be staged from userspace, and a `SIGKILL` keeps the page cache, so the
//! order of the binary's own calls is observed instead: the unmodified binary runs with
//! `crates/vox-test-interpose` loaded (`support/syscalls.rs`), and each publication must be
//! created `O_CREAT | O_EXCL` with mode `0600` and never `chmod`ed, flushed before its rename,
//! and its directory flushed after.
//!
//! 1. A new identity's vault (`vox id`).
//! 2. A headless node's identity file (`vox node`).
//!
//! (The arms that rewrote an earlier release's vault went with that migration, #423: Vox carries
//! no code for data from earlier releases.)
//!
//! Mutations: the temporary file not flushed, the directory not flushed, or the file created at
//! the umask's mode and `chmod`ed after, each breaks both.

#![cfg(target_os = "macos")]

#[path = "support/world.rs"]
mod world;

#[path = "support/syscalls.rs"]
mod syscalls;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::{Path, PathBuf};

use syscalls::{assert_the_recorder_saw_vox, interposer, parse, published_durably, recorded};
use world::{args, node_dir, VoxProc, DEFAULT_NODE, IDENTITY, VOX};

/// The default node's vault where this build keeps it (`<data>/nodes/default/`).
fn vault_of(data: &Path) -> PathBuf {
    node_dir(data, DEFAULT_NODE).join("vault.cbor")
}

fn verdict(what: &str, result: &Result<(), String>) {
    println!(
        "[proof] {what}: {}",
        match result {
            Ok(()) => "created 0600 with O_EXCL, flushed, renamed, directory flushed".to_owned(),
            Err(e) => format!("NOT durable: {e}"),
        }
    );
}

#[test]
#[ignore = "real vox with production Argon2id under DYLD_INSERT_LIBRARIES; run in release"]
fn a_file_that_holds_the_identity_is_published_durably() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a profile directory");
        d
    };
    let new = PathBuf::from(VOX);

    // ---- 1. a new identity's vault ------------------------------------------------------------
    let alice = dir("alice");
    let (made, out, err, events) = recorded(&new, &alice, &["id"], None, IDENTITY);
    assert!(made, "PRODUCT (staging): `vox id` failed: {out}{err}");
    let fresh = published_durably(&events, &vault_of(&alice));
    verdict("a new identity's vault.cbor", &fresh);

    // ---- 2. a headless node's identity file --------------------------------------------------
    let node = dir("node");
    let log = node.join("interpose.tsv");
    let (dylib, log_s) = (
        interposer()
            .to_str()
            .expect("APPARATUS: a UTF-8 path")
            .to_owned(),
        log.to_str().expect("APPARATUS: a UTF-8 path").to_owned(),
    );
    {
        let mut p = VoxProc::spawn_exe(
            &new,
            "node",
            &node,
            &args(&["node", "--listen", "127.0.0.1:0"]),
            &[
                ("DYLD_INSERT_LIBRARIES", &dylib),
                ("VOX_INTERPOSE_LOG", &log_s),
            ],
        );
        p.expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        });
    }
    let events = parse(&std::fs::read_to_string(&log).unwrap_or_default());
    assert_the_recorder_saw_vox(&events, "a headless `vox node`");
    let headless = published_durably(
        &events,
        &node_dir(&node, DEFAULT_NODE).join("node-identity.key"),
    );
    verdict("a headless node's node-identity.key", &headless);

    for (what, r) in [
        ("a new identity's vault.cbor", fresh),
        ("a headless node's node-identity.key", headless),
    ] {
        if let Err(e) = r {
            panic!("PRODUCT: {what} was not published durably: {e}");
        }
    }
}
