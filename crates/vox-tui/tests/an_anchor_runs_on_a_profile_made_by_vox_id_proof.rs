//! V210-103 (#298) — **`vox node` runs on a profile made by `vox id`**, and serves, through the
//! shipped binary.
//!
//! An anchor's first run: `vox id`, then `vox node`. The node refused at once with
//!
//! ```text
//! vox node: node: another vox already has this profile open
//! ```
//!
//! and no other vox was running. A headless node opened the profile's vault, which held its store
//! read-only, and then opened the same store writable for the anchor's own logs; redb refused the
//! second open as a profile held by someone else. A profile with no vault started, which is why
//! nothing proved it: every proof's anchor runs in a profile nobody gave an identity (`World`
//! among them, and it stays that way — that path is the other half of what an anchor must do).
//!
//! **Staging.** A fresh anchor profile, `vox id` in it, then `vox node --listen 127.0.0.1:0`. A
//! host profile `vox serve`s a loopback echo service through that anchor, and a guest profile
//! `vox connect`s to the host's room through it. Then the anchor is stopped and started again in
//! the same profile.
//!
//! **Asserted** — every red says whether it is the product's verdict (`PRODUCT:`, quoting what the
//! product said), a vox step that stages it failing (`PRODUCT (staging):`), or this proof's own
//! machinery (`APPARATUS:`).
//! 1. `vox node` prints its `--anchor` spec within [`START_BOUND`] and has not exited, and it never
//!    says the profile is already open.
//! 2. It serves: a guest joins the host's room through it, and the anchor reports the room on its
//!    board.
//! 3. Started again in the same profile (an anchor restarting), it comes up again the same way.
//!
//! **Mutation that must turn it red.** In `node::actor`'s `spawn_config`, open the profile's vault
//! for a headless node again (`Profile::exists` without the `headless.is_none()` guard): the node
//! exits at once with "another vox already has this profile open", a `PRODUCT:` red on assertion 1.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use world::{after_label, args, echo_service, room_pass_file, vox_once, VoxProc};

/// How long `vox node` may take to print its spec. A start takes seconds; the defect exits at
/// once.
const START_BOUND: Duration = Duration::from_secs(120);
/// How long the host may take to print its room's address and passphrase.
const SERVE_BOUND: Duration = Duration::from_secs(180);
/// How long the anchor may take to report the room on its board once the guest has joined.
const BOARD_BOUND: Duration = Duration::from_secs(60);
/// What the defect said.
const BUSY: &str = "already has this profile open";

/// Why a wait ended without the line it wanted.
#[derive(Debug)]
enum Missed {
    Exited,
    TimedOut,
}

/// Wait up to `within` for a line of `proc`'s matching `pred`, keeping every line seen. A process
/// that exits or stays silent is returned to the caller, which says whose fault that is.
fn wait_for(
    proc: &mut VoxProc,
    within: Duration,
    pred: impl Fn(&str) -> bool,
) -> Result<String, Missed> {
    if let Some(line) = proc.seen.iter().find(|l| pred(l)) {
        return Ok(line.clone());
    }
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Missed::TimedOut);
        }
        match proc.lines.recv_timeout(left.min(Duration::from_secs(5))) {
            Ok(line) => {
                eprintln!("[{}] {line}", proc.name);
                proc.seen.push(line.clone());
                if pred(&line) {
                    return Ok(line);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Missed::Exited),
        }
    }
}

/// Start `vox node` in `data` and assert it comes up: its spec printed, still running, and no
/// claim that the profile is open elsewhere. Returns the node and its spec.
fn start_anchor(data: &Path, run: &str) -> (VoxProc, String) {
    let mut node = VoxProc::spawn("anchor", data, &args(&["node", "--listen", "127.0.0.1:0"]));
    let spec = wait_for(&mut node, START_BOUND, |l| {
        !l.starts_with("! ") && l.contains("@/ip4/127.0.0.1/udp/")
    });
    let exited = node.child.try_wait().ok().flatten();
    let said = node.transcript();
    assert!(
        !said.contains(BUSY),
        "PRODUCT: `vox node` ({run}) on a profile made by `vox id` said the profile is already \
         open, with no other vox running (exit status {exited:?}). It said:\n{said}"
    );
    let spec = match spec {
        Ok(spec) if exited.is_none() => spec.trim().to_owned(),
        other => panic!(
            "PRODUCT: `vox node` ({run}) on a profile made by `vox id` did not come up: {other:?} \
             within {START_BOUND:?}, exit status {exited:?}. It said:\n{said}"
        ),
    };
    println!("[proof] vox node ({run}) on a profile made by vox id: up, spec printed");
    (node, spec)
}

/// A labelled line the host printed, e.g. `address …`. The host is staging: a host that never
/// says it is the product's fault (staging), shown with what the anchor said in case the anchor
/// is why.
fn host_says(host: &mut VoxProc, anchor: &mut VoxProc, label: &str) -> String {
    match wait_for(host, SERVE_BOUND, |l| l.starts_with(&format!("{label} "))) {
        Ok(line) => after_label(&line, label),
        Err(missed) => panic!(
            "PRODUCT (staging): the host's `vox serve` never printed its {label} \
             ({missed:?} within {SERVE_BOUND:?}).\nthe host said:\n{}\nthe anchor said:\n{}",
            host.transcript(),
            anchor.transcript()
        ),
    }
}

#[test]
#[ignore = "real vox processes with production Argon2id; run in release"]
fn an_anchor_runs_and_serves_on_a_profile_made_by_vox_id() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: a profile directory");
    }

    // ---- staging: the anchor's identity --------------------------------------------------------
    let (ok, fp, err) = vox_once(&anchor_dir, &args(&["id"]));
    assert!(
        ok,
        "PRODUCT (staging): `vox id` in the anchor's profile failed: {err}"
    );
    let vault = world::node_dir(&anchor_dir, world::DEFAULT_NODE).join("vault.cbor");
    assert!(
        vault.is_file(),
        "PRODUCT (staging): `vox id` printed {fp:?} but left no vault at {}",
        vault.display()
    );
    println!("[proof] vox id made the anchor profile's identity");

    // ---- 1. vox node comes up ------------------------------------------------------------------
    let (mut anchor, spec) = start_anchor(&anchor_dir, "first run");

    // ---- 2. it serves: a guest joins a host's room through it --------------------------------
    for (who, dir) in [("host", &host_dir), ("guest", &guest_dir)] {
        let (ok, _, err) = vox_once(dir, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): `vox id` ({who}) failed: {err}");
    }
    let port = echo_service();
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &format!("{port}={port}"),
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let address = host_says(&mut host, &mut anchor, "address");
    let passphrase = host_says(&mut host, &mut anchor, "passphrase");
    let pass_file = room_pass_file(tmp.path(), &passphrase);
    let (joined, out, err) = vox_once(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &pass_file,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    assert!(
        joined,
        "PRODUCT: a guest did not join the host's room through the anchor made by `vox id`.\n\
         `vox connect` stdout:\n{out}\nstderr:\n{err}\nthe anchor said:\n{}",
        anchor.transcript()
    );
    println!("[proof] a guest joined the host's room through the anchor");
    let board = wait_for(&mut anchor, BOARD_BOUND, |l| {
        l.contains("room(s) on the board") && !l.contains(" 0 room(s)")
    })
    .unwrap_or_else(|missed| {
        panic!(
            "PRODUCT: the anchor never reported the room on its board ({missed:?} within \
             {BOARD_BOUND:?}). It said:\n{}",
            anchor.transcript()
        )
    });
    println!("[proof] the anchor reports: {}", board.trim());
    assert!(
        anchor.child.try_wait().ok().flatten().is_none(),
        "PRODUCT: the anchor exited while serving. It said:\n{}",
        anchor.transcript()
    );
    drop(host);
    drop(anchor);

    // ---- 3. restarted in the same profile ----------------------------------------------------
    let (again, _) = start_anchor(&anchor_dir, "restart");
    drop(again);
    println!("[proof] 3 of 3 assertions held");
}
