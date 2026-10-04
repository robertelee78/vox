//! ADR-026 F-3 (#399) — **every verb moves a data root of the layout before v0.3.0 before it
//! resolves its node**, driven through the shipped binaries.
//!
//! [`PREVIOUS`] (v0.2.9, its published binary checked against its SHA-256) makes an identity in a
//! data root as a person did (`vox id`), which leaves it at `<data>/default/`. Then this build's
//! commands meet it, each in a fresh copy of that data root:
//! - a one-shot verb (`vox room list`): it must move the profile to `nodes/default/`, say so, and
//!   then refuse as a one-shot verb refuses an unattached node (L-2) — never "there is no node in
//!   <data> yet", which is what it said when it looked for nodes before moving them;
//! - `vox node list`: it must list `default`;
//! - an agent's hook (`vox agent hook --node default`): it must find the moved node.
//!
//! Mutant: the migration taken out of the client's entry point (`NodeArgs::account`): the one-shot
//! verb says there is no node, red.
//!
//! The previous release failing to stage the scene is `CANNOT MEASURE`.

#![cfg(unix)]

#[path = "support/previous_release.rs"]
mod previous_release;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use previous_release::{previous_release, PREVIOUS};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase for the migration proof";

fn vox(exe: &Path, data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(exe)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_NODE")
        .env_remove("VOX_PROFILE")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env("VOX_LISTEN", "127.0.0.1:0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not start {}: {e}", exe.display()));
    let _ = child
        .stdin
        .take()
        .expect("APPARATUS: stdin")
        .write_all(stdin.as_bytes());
    let out = child.wait_with_output().expect("APPARATUS: vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A data root at `data` holding one v0.2.9 identity at `<data>/default/`.
fn old_root(old: &Path, data: &Path) {
    std::fs::create_dir_all(data.join("cfg")).expect("APPARATUS: data root");
    let (ok, out, err) = vox(old, data, &["id"], "");
    assert!(
        ok && data.join("default").join("vault.cbor").exists(),
        "CANNOT MEASURE: {PREVIOUS}'s `vox id` made no profile at {}/default: {out}{err}",
        data.display()
    );
}

/// Stop any daemon a verb started in `data`, by the PID in its lock.
fn reap(data: &Path) {
    if let Some(pid) = std::fs::read_to_string(data.join(".daemon/lock"))
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
    {
        let _ = Command::new("kill").arg(pid.to_string()).status();
    }
}

#[test]
#[ignore = "the previous release and production Argon2id; run in release"]
fn every_verb_moves_an_old_layout_before_it_resolves_its_node() {
    watchdog::arm();
    let old = previous_release();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");

    // A one-shot verb.
    let a = tmp.path().join("a");
    old_root(&old, &a);
    let (ok, out, err) = vox(Path::new(VOX), &a, &["room", "list"], "");
    eprintln!("[proof] `vox room list` on a {PREVIOUS} data root: ok={ok}\n{err}");
    assert!(
        !err.contains("there is no node in"),
        "PRODUCT: a one-shot verb on a {PREVIOUS} data root looked for nodes before moving them: \
         {out}{err}"
    );
    assert!(
        a.join("nodes").join("default").join("vault.cbor").exists() && !a.join("default").exists(),
        "PRODUCT: `vox room list` did not move the {PREVIOUS} profile to nodes/default: {out}{err}"
    );
    assert!(
        err.contains("moved ") && err.contains("node default is not attached"),
        "PRODUCT: `vox room list` must say it moved the profile, then refuse as a one-shot verb on \
         an unattached node: ok={ok}: {out}{err}"
    );

    // `vox node list`.
    let b = tmp.path().join("b");
    old_root(&old, &b);
    let (ok, out, err) = vox(Path::new(VOX), &b, &["node", "list"], "");
    eprintln!("[proof] `vox node list` on a {PREVIOUS} data root: ok={ok}\n{out}{err}");
    assert!(
        ok && out
            .lines()
            .any(|l| l.split_whitespace().next() == Some("default")),
        "PRODUCT: `vox node list` on a {PREVIOUS} data root did not list node default: {out}{err}"
    );

    // An agent's hook.
    let c = tmp.path().join("c");
    old_root(&old, &c);
    let (ok, out, err) = vox(
        Path::new(VOX),
        &c,
        &["agent", "hook", "--node", "default"],
        r#"{"hook_event_name":"UserPromptSubmit","session_id":"s-1"}"#,
    );
    reap(&c);
    eprintln!("[proof] `vox agent hook --node default` on a {PREVIOUS} data root: ok={ok}\n{err}");
    assert!(
        c.join("nodes").join("default").join("vault.cbor").exists() && !c.join("default").exists(),
        "PRODUCT: the hook did not move the {PREVIOUS} profile to nodes/default: ok={ok}: {out}{err}"
    );
}
