//! V210-55 (#241) — **a file whose loss loses the identity is written durably**, through the
//! shipped binary.
//!
//! `vault.cbor` (the identity, sealed under its passphrase) and a headless node's
//! `node-identity.key` (its seeds, in the clear by design) are replaced by writing a temporary
//! file and renaming it over the old one. Before V210-55 the temporary file was renamed without
//! being flushed, and the directory was not flushed after: a power loss could leave the new name
//! on an empty file, and the identity gone with it. Every person upgrading from v0.2.9 rewrites
//! their vault once (#214). And it was created at the umask's mode and `chmod`ed to `0600` after,
//! leaving a headless node's seeds readable by other local users for a moment.
//!
//! A power loss cannot be staged from userspace, and a `SIGKILL` keeps the page cache, so the
//! order of the binary's own calls is observed instead: the unmodified binary runs with
//! `crates/vox-test-interpose` loaded (`support/syscalls.rs`), and each publication must be
//! created `O_CREAT | O_EXCL` with mode `0600` and never `chmod`ed, flushed before its rename,
//! and its directory flushed after.
//!
//! 1. A new identity's vault (`vox id`).
//! 2. A v0.2.9 vault rewritten by the migration (#214), from the **released v0.2.9 binary**.
//! 3. A headless node's identity file (`vox node`).
//! 4. A vault write that fails leaves the old vault in place and readable, and the next unlock
//!    completes the migration.
//!
//! Mutations: the temporary file not flushed, the directory not flushed, or the file created at
//! the umask's mode and `chmod`ed after, each breaks 1–3.

#![cfg(target_os = "macos")]

#[path = "support/world.rs"]
mod world;

#[path = "support/syscalls.rs"]
mod syscalls;

#[path = "support/previous_release.rs"]
mod previous_release;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::atrest::vault::IdentityVault;

use previous_release::previous_release;
use syscalls::{assert_the_recorder_saw_vox, interposer, parse, published_durably, recorded};
use world::{args, node_dir, VoxProc, DEFAULT_NODE, IDENTITY, VOX};

const TIMEOUT: Duration = Duration::from_secs(90);

fn vox_with(exe: &Path, data: &Path, argv: &[&str]) -> (bool, String, String) {
    let out = Command::new(exe)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {}: {e}", exe.display()));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn ok(exe: &Path, data: &Path, argv: &[&str]) -> String {
    let (good, out, err) = vox_with(exe, data, argv);
    assert!(good, "PRODUCT (staging): `vox {argv:?}` failed: {out}{err}");
    out
}

/// The default node's vault where this build keeps it (`<data>/nodes/default/`).
fn vault_of(data: &Path) -> PathBuf {
    node_dir(data, DEFAULT_NODE).join("vault.cbor")
}

/// The vault where v0.2.9 keeps it (`<data>/default/`), before this build's first run moves the
/// profile into `nodes/` (ADR-026 F-3).
fn old_vault_of(data: &Path) -> PathBuf {
    data.join(DEFAULT_NODE).join("vault.cbor")
}

fn vault_version(path: &Path) -> u64 {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| panic!("APPARATUS: could not read {}: {e}", path.display()));
    IdentityVault::from_canonical_slice(&bytes)
        .unwrap_or_else(|e| panic!("PRODUCT: vox left {} undecodable: {e:?}", path.display()))
        .version
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
#[ignore = "real vox with production Argon2id under DYLD_INSERT_LIBRARIES, and the v0.2.9 release; run in release"]
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

    // ---- 2. a v0.2.9 vault rewritten by the migration ---------------------------------------
    let old = previous_release();
    let (carol, dave) = (dir("carol"), dir("dave"));
    let dave_fp = ok(&old, &dave, &["id"]).trim().to_owned();
    ok(&old, &carol, &["id"]);
    ok(&old, &carol, &["trust", "add", &dave_fp, "--name", "dave"]);
    assert_eq!(
        vault_version(&old_vault_of(&carol)),
        1,
        "APPARATUS (precondition not met): v0.2.9 wrote no version-1 vault"
    );
    let (migrated, out, err, events) = recorded(&new, &carol, &["trust", "list"], None, IDENTITY);
    assert!(
        migrated && out.contains("dave") && vault_version(&vault_of(&carol)) == 2,
        "PRODUCT (staging): the v0.2.9 profile did not migrate: {out}{err}"
    );
    let migration = published_durably(&events, &vault_of(&carol));
    verdict("a v0.2.9 vault.cbor rewritten by the migration", &migration);

    // ---- 3. a headless node's identity file --------------------------------------------------
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
    let headless = published_durably(&events, &node_dir(&node, DEFAULT_NODE).join("node-identity.key"));
    verdict("a headless node's node-identity.key", &headless);

    // ---- 4. a vault write that fails leaves the old vault --------------------------------------
    let (erin, frank) = (dir("erin"), dir("frank"));
    let frank_fp = ok(&old, &frank, &["id"]).trim().to_owned();
    ok(&old, &erin, &["id"]);
    ok(&old, &erin, &["trust", "add", &frank_fp, "--name", "frank"]);
    let before = std::fs::read(old_vault_of(&erin)).expect("APPARATUS: read erin's v0.2.9 vault");
    // A directory where the temporary file must be created: the write cannot happen. Staged in
    // v0.2.9's profile directory; this build's first run moves it, blocker and all, into `nodes/`.
    let blocker = erin.join(DEFAULT_NODE).join("vault.tmp");
    std::fs::create_dir(&blocker).expect("APPARATUS: create the blocking directory");
    std::fs::write(
        blocker.join("keep"),
        b"the vault's temporary file cannot go here",
    )
    .expect("APPARATUS: fill the blocking directory");
    let (wrote, out, err) = vox_with(&new, &erin, &["trust", "list"]);
    let kept = std::fs::read(vault_of(&erin)).unwrap_or_else(|e| {
        panic!(
            "PRODUCT: after this build's first run erin's vault is not at {}: {e}: {out}{err}",
            vault_of(&erin).display()
        )
    }) == before;
    let opens = IdentityVault::from_canonical_slice(&before)
        .and_then(|v| v.unlock_signer(IDENTITY.as_bytes()))
        .is_ok();
    println!(
        "[proof] a vault write that cannot happen: the unlock succeeded = {wrote}; the v1 vault \
         kept byte for byte = {kept}; it still opens = {opens}"
    );
    assert!(
        !wrote,
        "PRODUCT (staging): the blocked vault write was not staged — the unlock succeeded with the \
         temporary file's path occupied: {out}{err}"
    );
    assert!(
        kept && opens,
        "PRODUCT: a failed vault write lost or changed the old vault (kept byte for byte = \
         {kept}, still opens = {opens}): {out}{err}"
    );
    std::fs::remove_dir_all(node_dir(&erin, DEFAULT_NODE).join("vault.tmp"))
        .expect("APPARATUS: remove the blocking directory from where the migration moved it");
    let deadline = Instant::now() + TIMEOUT;
    let listed = loop {
        let (good, out, _) = vox_with(&new, &erin, &["trust", "list"]);
        if good || Instant::now() > deadline {
            break out;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    println!(
        "[proof] with the obstacle gone: vault v{}, `trust list` names frank = {}",
        vault_version(&vault_of(&erin)),
        listed.contains("frank")
    );
    assert!(
        vault_version(&vault_of(&erin)) == 2 && listed.contains("frank"),
        "PRODUCT: the migration did not complete once the vault could be written: {listed}"
    );

    for (what, r) in [
        ("a new identity's vault.cbor", fresh),
        ("a v0.2.9 vault.cbor rewritten by the migration", migration),
        ("a headless node's node-identity.key", headless),
    ] {
        if let Err(e) = r {
            panic!("PRODUCT: {what} was not published durably: {e}");
        }
    }
}
