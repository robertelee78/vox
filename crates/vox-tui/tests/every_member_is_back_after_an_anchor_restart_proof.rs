//! V210-86 (#278) — **after an anchor restarts, every member is back promptly**, and the anchor's
//! cap on concurrent handshakes still holds, through the shipped binary.
//!
//! An anchor runs at most 64 inbound handshakes at once. An attempt past that cap whose address
//! was validated used to be refused on the spot. Its dialler cannot tell that from a failed dial,
//! so it backed off like one — 1, 2, 4… seconds, doubling to 30 — and after an anchor restart every
//! member redials within the same second or two. Measured by fix-v210-70 against the shipped
//! `vox node`: 300 identities dialling at once got 107–188 in, and all 511 failures were
//! `CONNECTION_REFUSED`. Now such an attempt waits for a slot (bounded in time and number) instead.
//!
//! **The scene:** one anchor (`vox node`) on a fixed port and [`MEMBERS`] real `vox daemon`s, each
//! its own identity made by `vox id`, all pointed at it with `--anchor`. The daemons are started a
//! few at a time, so their first connections are not the burst being measured, and the anchor must
//! report all of them connected. Then the anchor is **stopped** (SIGINT, as a person stops it: it
//! closes every connection, so every member learns at once and redials together), kept down for
//! [`DOWN`], and brought back **on the same port** from the same profile.
//!
//! **Asserted:**
//! - the restarted anchor reports all [`MEMBERS`] peers connected within [`BACK_WITHIN`] of its
//!   return — its own `N peer(s) connected` line, read as it is printed;
//! - the burst reached the cap (the anchor says attempts waited for a handshake slot — otherwise
//!   the run measured nothing and says CANNOT MEASURE), never more than [`CAP`] handshakes ran at
//!   once while they waited, and none was refused.
//!
//! The in-flight count is the anchor's own report ([`NodeEvent::HandshakesQueued`]); nothing
//! outside the process can see a handshake slot. The bound is observed from outside.
//!
//! **Why the bound separates the two:** with refusals, the members past the cap each wait a backoff
//! step, then meet the cap again with the next ones, and the last of them come back on a doubling
//! backoff many seconds later (the old code measured below); waiting for a slot brings every one in
//! within the same burst.
//!
//! Mutations (each must go red):
//! - validated attempts past the cap refused again (`HANDSHAKES_WAITING` = 0, the old behaviour)
//!   → red on the bound;
//! - the cap raised (`HANDSHAKES_IN_FLIGHT` = 100) → red on the cap.
//!
//! [`NodeEvent::HandshakesQueued`]: vox_core::node::api::NodeEvent::HandshakesQueued

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY};

/// How many members redial the restarted anchor.
const MEMBERS: usize = 300;
/// The anchor's handshake cap, restated rather than read, so a changed cap goes red.
const CAP: usize = 64;
/// How long the anchor stays down.
const DOWN: Duration = Duration::from_secs(3);
/// How soon after the anchor is back every member must be connected to it again.
const BACK_WITHIN: Duration = Duration::from_secs(10);
/// How long the members get to connect the first time, before anything is measured.
const SETTLE: Duration = Duration::from_secs(300);
/// What the anchor says when a burst waited for handshake slots.
const WAITED: &str = "connection attempt(s) waited for a handshake slot";

#[test]
#[ignore = "real binaries, 300 daemons and production Argon2id; CI runs it in release"]
fn every_member_is_back_after_an_anchor_restart() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).unwrap();
    let port = free_udp_port();
    let listen = format!("127.0.0.1:{port}");
    let mut anchor = VoxProc::spawn("anchor", &anchor_dir, &args(&["node", "--listen", &listen]));
    let spec = anchor
        .expect_line("the anchor's --anchor spec", |l| {
            l.contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    // ---- MEMBERS identities, a few at a time (each is a production Argon2id) --------------------
    let lanes = std::thread::available_parallelism().map_or(4, |n| n.get().min(12));
    let dirs: Vec<PathBuf> = (0..MEMBERS)
        .map(|i| tmp.path().join(format!("m{i:03}")))
        .collect();
    let made = Instant::now();
    for batch in dirs.chunks(lanes) {
        let handles: Vec<_> = batch
            .iter()
            .map(|dir| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    std::fs::create_dir_all(dir.join("cfg")).unwrap();
                    let (ok, _, err) = vox_once(&dir, &args(&["id"]));
                    assert!(ok, "CANNOT MEASURE: vox id failed: {err}");
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
    eprintln!("[proof] {MEMBERS} identities made in {:?}", made.elapsed());

    // ---- MEMBERS daemons, started a few at a time, all connected --------------------------------
    let pass_file = tmp.path().join("identity-passphrase");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();
    let started = Instant::now();
    let mut daemons: Vec<VoxProc> = Vec::with_capacity(MEMBERS);
    for batch in dirs.chunks(lanes) {
        for dir in batch {
            daemons.push(daemon(dir, &spec, &pass_file));
        }
        // Past its unlock (a production Argon2id) before the next batch starts its own.
        for d in daemons.iter_mut().rev().take(batch.len()) {
            d.expect_line("the daemon's control socket", |l| {
                l.starts_with("vox daemon: control socket")
            });
        }
    }
    let (first, _) = wait_for_peers(&mut anchor, MEMBERS, Instant::now(), SETTLE);
    assert!(
        first >= MEMBERS,
        "CANNOT MEASURE: only {first} of {MEMBERS} members connected to the anchor within \
         {SETTLE:?} of starting, before any restart\n{}",
        anchor.transcript()
    );
    eprintln!(
        "[proof] all {MEMBERS} members connected to the anchor {:?} after the first started",
        started.elapsed()
    );

    // ---- the anchor is stopped, and comes back on the same port ---------------------------------
    let _ = std::process::Command::new("kill")
        .args(["-INT", &anchor.child.id().to_string()])
        .status();
    let stopping = Instant::now();
    while anchor.child.try_wait().ok().flatten().is_none() {
        assert!(
            stopping.elapsed() < Duration::from_secs(10),
            "CANNOT MEASURE: the anchor did not stop within 10 s of SIGINT"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(anchor);
    std::thread::sleep(DOWN);
    let mut anchor = VoxProc::spawn(
        "anchor (restarted)",
        &anchor_dir,
        &args(&["node", "--listen", &listen]),
    );
    let back = Instant::now();

    // ---- every member is connected again within BACK_WITHIN ------------------------------------
    let (most, at) = wait_for_peers(
        &mut anchor,
        MEMBERS,
        back,
        BACK_WITHIN + Duration::from_secs(50),
    );
    eprintln!(
        "[proof] after the restart: {most}/{MEMBERS} members connected, the last {at:?} after the \
         anchor was back (bound {BACK_WITHIN:?})"
    );
    // The burst's report comes when none is left waiting, which may be a moment after the count.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut said = None;
    while said.is_none() && Instant::now() < deadline {
        anchor.transcript();
        said = anchor.seen.iter().find(|l| l.contains(WAITED)).cloned();
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("[proof] the anchor said: {said:?}");
    assert!(
        most >= MEMBERS,
        "only {most} of {MEMBERS} members were connected again within {:?} of the anchor's \
         return\n---- the anchor ----\n{}",
        BACK_WITHIN + Duration::from_secs(50),
        anchor.transcript()
    );
    assert!(
        at < BACK_WITHIN,
        "every member was back only {at:?} after the anchor's return, over {BACK_WITHIN:?}: \
         members turned away at the cap waited out a backoff\n---- the anchor ----\n{}",
        anchor.transcript()
    );

    // ---- the cap held ---------------------------------------------------------------------------
    let said = said.unwrap_or_else(|| {
        panic!(
            "CANNOT MEASURE: the anchor never said attempts waited for a handshake slot, so the \
             burst never reached the cap of {CAP}\n{}",
            anchor.transcript()
        )
    });
    let number = |after: &str| -> usize {
        said.split(after)
            .nth(1)
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| {
                n.trim_end_matches(|c: char| !c.is_ascii_digit())
                    .parse()
                    .ok()
            })
            .unwrap_or_else(|| panic!("no number after {after:?} in {said:?}"))
    };
    let (waited, running, refused) = (number("vox node: "), number("while at most "), number("; "));
    eprintln!(
        "[proof] {waited} attempts waited, at most {running} handshakes ran at once (cap {CAP}), \
         {refused} refused"
    );
    assert!(
        running <= CAP,
        "{running} handshakes ran at once, over the cap of {CAP}: {said}"
    );
    assert_eq!(refused, 0, "attempts were refused at the cap: {said}");
}

/// A `vox daemon` for the profile at `dir`, pointed at the anchor `spec`.
fn daemon(dir: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    VoxProc::spawn(
        &dir.file_name().unwrap().to_string_lossy(),
        dir,
        &args(&[
            "daemon",
            "--passphrase-file",
            pass_file.to_str().unwrap(),
            "--anchor",
            spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    )
}

/// Read the anchor's `N peer(s) connected` reports until one says `want`, or `within` passes.
/// Returns the most it reported and when, since `t0`, it first reported that many.
fn wait_for_peers(
    anchor: &mut VoxProc,
    want: usize,
    t0: Instant,
    within: Duration,
) -> (usize, Duration) {
    let (mut most, mut at) = (0, Duration::ZERO);
    while most < want {
        let left = within.saturating_sub(t0.elapsed());
        if left.is_zero() {
            break;
        }
        match anchor
            .lines
            .recv_timeout(left.min(Duration::from_millis(500)))
        {
            Ok(line) => {
                if let Some(n) = line
                    .strip_prefix("vox node: ")
                    .and_then(|r| r.split_once(" peer(s) connected"))
                    .and_then(|(n, _)| n.parse::<usize>().ok())
                {
                    if n > most {
                        (most, at) = (n, t0.elapsed());
                    }
                }
                anchor.seen.push(line);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
                "CANNOT MEASURE: the anchor exited\n{}",
                anchor.seen.join("\n")
            ),
        }
    }
    (most, at)
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
