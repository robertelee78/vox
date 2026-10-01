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
//! nothing proved it: every proof's anchor ran in a profile nobody had given an identity.
//!
//! **Staging.** A fresh anchor profile, `vox id` in it, then `vox node --listen 127.0.0.1:0`. A
//! host profile `vox serve`s a loopback echo service through that anchor, and a guest profile
//! `vox connect`s to the host's room through it. Then the anchor is stopped and started again in
//! the same profile.
//!
//! **Asserted.**
//! 1. `vox id` made the anchor profile's identity (its vault is there) — else CANNOT MEASURE.
//! 2. `vox node` prints its `--anchor` spec within [`START_BOUND`] and has not exited, and it never
//!    says the profile is already open.
//! 3. It serves: a guest joins the host's room through it, and the anchor reports the room on its
//!    board.
//! 4. Started again in the same profile (an anchor restarting), it prints its spec again and never
//!    says the profile is already open.
//! 5. (macOS) The first run, under the syscall recorder (`support/syscalls.rs`), opened the
//!    profile's `store.redb` exactly once. A second open in one process is the defect's mechanism,
//!    and this catches it even if a later redb stopped refusing it.
//!
//! **Mutation that must turn it red.** In `node::actor`'s `spawn_config`, open the profile's vault
//! for a headless node again (`Profile::exists` without the `headless.is_none()` guard): the node
//! exits at once with "another vox already has this profile open", red on assertion 2, and the
//! recorder counts two opens of `store.redb` (printed before the assertions).

#![cfg(unix)]

#[cfg(target_os = "macos")]
#[path = "support/syscalls.rs"]
mod syscalls;
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
/// How long the anchor may take to report the room on its board once the guest has joined.
const BOARD_BOUND: Duration = Duration::from_secs(60);
/// What the defect said.
const BUSY: &str = "already has this profile open";

/// Wait up to `within` for the node's `--anchor` spec. `None` if it exited first — the defect —
/// so the caller asserts on it, with everything the node said.
fn spec_or_exit(node: &mut VoxProc, within: Duration) -> Option<String> {
    let deadline = Instant::now() + within;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        match node.lines.recv_timeout(left.min(Duration::from_secs(5))) {
            Ok(line) => {
                eprintln!("[{}] {line}", node.name);
                node.seen.push(line.clone());
                if !line.starts_with("! ") && line.contains("@/ip4/127.0.0.1/udp/") {
                    return Some(line.trim().to_owned());
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

/// Start `vox node` in `data`, with `env`, and assert it comes up: its spec printed, still
/// running, and no claim that the profile is open elsewhere. `measured` runs once the node has
/// come up or exited, before anything is asserted, so what it prints is there in a red too.
/// Returns the node and its spec.
fn start_anchor(
    data: &Path,
    run: &str,
    env: &[(&str, &str)],
    measured: impl FnOnce(u32),
) -> (VoxProc, String) {
    let mut node = VoxProc::spawn_env(
        "anchor",
        data,
        &args(&["node", "--listen", "127.0.0.1:0"]),
        env,
    );
    let spec = spec_or_exit(&mut node, START_BOUND);
    measured(node.child.id());
    let exited = node.child.try_wait().ok().flatten();
    let said = node.transcript();
    assert!(
        spec.is_some() && exited.is_none(),
        "`vox node` ({run}) on a profile made by `vox id` did not come up within {START_BOUND:?} \
         (exit status {exited:?}). It said:\n{said}"
    );
    assert!(
        !said.contains(BUSY),
        "`vox node` ({run}) said the profile is already open, with no other vox running:\n{said}"
    );
    println!("[proof] vox node ({run}) on a profile made by vox id: up, spec printed");
    (node, spec.unwrap())
}

/// How many times process `pid` opened the profile's `store.redb`, from the recorder's log.
#[cfg(target_os = "macos")]
fn store_opens(log: &Path, data: &Path, pid: u32) -> usize {
    let store = std::fs::canonicalize(data.join("default"))
        .expect("the anchor's profile directory")
        .join("store.redb");
    let events = syscalls::parse(&std::fs::read_to_string(log).unwrap_or_default());
    assert!(
        !events.is_empty(),
        "CANNOT MEASURE: the syscall recorder logged nothing for `vox node`"
    );
    events
        .iter()
        .filter(|e| {
            e.pid == pid
                && e.ret >= 0
                && matches!(&e.call, syscalls::Call::Open { path, .. } if syscalls::norm(path) == store)
        })
        .count()
}

#[test]
#[ignore = "real vox processes with production Argon2id; run in release"]
fn an_anchor_runs_and_serves_on_a_profile_made_by_vox_id() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }

    // ---- 1. the anchor's identity ------------------------------------------------------------
    let (ok, fp, err) = vox_once(&anchor_dir, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id in the anchor's profile: {err}");
    let vault = anchor_dir.join("default").join("vault.cbor");
    assert!(
        vault.is_file(),
        "CANNOT MEASURE: vox id printed {fp:?} but left no vault at {}",
        vault.display()
    );
    println!("[proof] vox id made the anchor profile's identity");

    // ---- 2. vox node comes up, (macOS) under the syscall recorder -------------------------------
    #[cfg(target_os = "macos")]
    let log = tmp.path().join("interpose-node.tsv");
    #[cfg(target_os = "macos")]
    let recording = [
        (
            "DYLD_INSERT_LIBRARIES",
            syscalls::interposer().to_str().unwrap(),
        ),
        ("VOX_INTERPOSE_LOG", log.to_str().unwrap()),
    ];
    #[cfg(not(target_os = "macos"))]
    let recording: [(&str, &str); 0] = [];
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut opens = None::<usize>;
    let (mut anchor, spec) = start_anchor(&anchor_dir, "first run", &recording, |_pid| {
        #[cfg(target_os = "macos")]
        {
            let n = store_opens(&log, &anchor_dir, _pid);
            println!("[proof] the first run opened store.redb {n} time(s)");
            opens = Some(n);
        }
    });

    // ---- 3. it serves: a guest joins a host's room through it --------------------------------
    let (ok, _, err) = vox_once(&host_dir, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id (host): {err}");
    let (ok, _, err) = vox_once(&guest_dir, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id (guest): {err}");
    let port = echo_service();
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &port.to_string(),
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let address = after_label(
        &host.expect_line("address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
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
        "a guest did not join the host's room through the anchor made by `vox id`.\n\
         stdout:\n{out}\nstderr:\n{err}\nthe anchor said:\n{}",
        anchor.transcript()
    );
    println!("[proof] a guest joined the host's room through the anchor");
    let board = anchor.expect_within(BOARD_BOUND, "the room on its board", |l| {
        l.contains("room(s) on the board") && !l.contains(" 0 room(s)")
    });
    println!("[proof] the anchor reports: {}", board.trim());
    assert!(
        anchor.child.try_wait().ok().flatten().is_none(),
        "the anchor exited while serving. It said:\n{}",
        anchor.transcript()
    );
    drop(host);
    drop(anchor);

    // ---- 4. restarted in the same profile ----------------------------------------------------
    let (again, _) = start_anchor(&anchor_dir, "restart", &[], |_| {});
    drop(again);

    // ---- 5. (macOS) one open of the store -------------------------------------------------------
    #[cfg(target_os = "macos")]
    assert_eq!(
        opens,
        Some(1),
        "one `vox node` opened its profile's store.redb more than once (or never)"
    );
    #[cfg(target_os = "macos")]
    println!("[proof] 5 of 5 assertions held");
    #[cfg(not(target_os = "macos"))]
    {
        let _ = opens;
        println!("[proof] 4 of 4 assertions held (the open count is recorded on macOS only)");
    }
}
