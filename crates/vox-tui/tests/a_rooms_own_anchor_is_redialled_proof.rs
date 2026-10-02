//! V210-75 (#266) — **a room's own anchor is redialled after it goes, like a configured one**,
//! through the shipped binary.
//!
//! A node keeps two kinds of anchor: the ones it is configured with (`--anchor`, the anchors
//! file), and the ones a room recorded when it was created or joined — for a member who joined
//! from an invite, often the only anchor it has. Only the configured set was redialled. A room's
//! own anchor was dialled once, when the room opened, and never again: the first time it
//! restarted, the member lost its board and its relay for as long as the process ran.
//!
//! **The scene** (`support/relay.rs`, `Split::Families`, so the only path between host and guest
//! is a circuit through the anchor): the guest joins, and then runs `vox forward` **with no
//! `--anchor` and no anchors file**, so the one anchor that process knows is the one its room
//! recorded at the join. (The join itself names the anchor by its IPv6 address with `--anchor`,
//! because the guest listens on `[::1]` and the invite names the anchor as the IPv4 host reached
//! it; the join is where the room records it.) The echo carries over the circuit, the anchor is
//! stopped with SIGINT and brought back [`DOWN`] later on the same port, and the forward must
//! carry an echo again within [`BACK_WITHIN`] of its return, and say it saw its anchor go.
//!
//! **And the node republishes to it.** The anchor comes back having **lost its board** (its
//! `store.redb` is removed while it is down, as a disk replaced or a store reset would leave it;
//! its identity file is kept, so it is the same anchor), and the host is **paused** (SIGSTOP by
//! its PID) meanwhile, so the host cannot restore anything itself. A member republishes the
//! room's genesis, its own records, and every other member's record its board holds (it vouches
//! for them, M15.2a). So the only node that can put the **host's** record back on the wiped
//! board is the guest, on reconnecting, and the restarted anchor must say, within
//! [`REPUBLISHED_WITHIN`] of its return, that it holds the host's record again. (The guest's
//! *own* bundle is not the observable: a board admits a member's own bundle only once another
//! member has vouched for it, and the only other member is paused.) Then the host resumes and
//! the echo is checked.
//!
//! **Asserted:** the forward process has no configured anchor (else CANNOT MEASURE); the path is
//! relayed (the guest's `still relayed`); before the restart the anchor held both members'
//! records (else PRODUCT (staging)); after the restart the echo carries again within
//! [`BACK_WITHIN`]; the forward said the connection to its anchor was gone; and the restarted
//! anchor, with the host paused, holds the host's record again within [`REPUBLISHED_WITHIN`].
//!
//! **Which side a red is on.** A red that names the product begins `PRODUCT:` and quotes what
//! vox said; a step of the setup the product did not do (a join, an echo before the restart, a
//! record the anchor never held) begins `PRODUCT (staging):`; a precondition that was not met (an
//! anchors file, the store's place) begins `CANNOT MEASURE:`; a fault of this proof's own (a signal that did not take,
//! a `vox` that cannot be started) begins `APPARATUS:`. The host's pause is confirmed, not
//! assumed: `ps` must show it stopped after SIGSTOP and running after SIGCONT, or a host that was
//! never paused could restore its own record and pass the republish claim for it. The two bounds
//! are read against an **apparatus clock** on the same timeline: how long this machine takes to
//! start a `vox --version`, and the republish poll's slowest turn. A bound missed while the
//! apparatus was over [`APPARATUS_BUDGET`] is CANNOT MEASURE; otherwise it is the product's.
//!
//! **Mutations that must turn it red:**
//! - Redial only the configured set (`kept_anchors` in `actor.rs` returns `self.anchors` alone,
//!   the code before V210-75): the forward never redials the room's anchor, the host can reach
//!   it only through that anchor, and no echo carries again.
//! - Redial it but republish nothing to it (`NetEvent::AnchorConnected` skips
//!   `publish_channel_to_anchor` for an anchor that is not configured): the restarted anchor
//!   holds no record while the host is paused.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::path::Path;
use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::{args, round_trip, vox_once, VoxProc};

/// How long after the forward starts the anchor is stopped.
const KILL_AFTER: Duration = Duration::from_secs(4);
/// How long the anchor stays down.
const DOWN: Duration = Duration::from_secs(3);
/// How soon after the anchor is back the forward must carry an echo again: a tick, a dial, and
/// the host's own redial of its configured anchor.
const BACK_WITHIN: Duration = Duration::from_secs(15);
/// How long to keep trying after that, so a red says how late (or never) it came back.
const PATIENCE: Duration = Duration::from_secs(45);
/// How soon after the anchor is back it must hold the host's record again, put there by the guest.
const REPUBLISHED_WITHIN: Duration = Duration::from_secs(20);
/// What a node says when its anchor connection goes.
const GONE: &str = "the connection to this anchor is gone";
/// The most the apparatus may take, on the same timeline as a bound, for a missed bound to be the
/// product's: starting a `vox` that does nothing, or one turn of a poll loop past its sleep.
const APPARATUS_BUDGET: Duration = Duration::from_secs(2);

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_rooms_own_anchor_is_redialled_after_it_restarts() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "PRODUCT (staging): the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );

    // ---- the forward: no --anchor, no anchors file; its only anchor is the room's -------------
    let anchors_file = w.guest_dir.join("cfg").join("anchors");
    assert!(
        !anchors_file.exists(),
        "CANNOT MEASURE: the guest has an anchors file ({}), so its anchor would be configured",
        anchors_file.display()
    );
    let pass_file = w.passphrase_file();
    let started = Instant::now();
    let mut fwd = VoxProc::spawn(
        "forward",
        &w.guest_dir,
        &args(&[
            "forward",
            &w.room,
            &w.host_fp,
            &w.service,
            "127.0.0.1:0",
            "--passphrase-file",
            &pass_file,
            "--listen",
            Split::Families.guest_listen(),
        ]),
    );
    let line = fwd.expect_line("the forward's bound address", |l| {
        l.starts_with("vox: 127.0.0.1:") && l.contains('→')
    });
    let at: std::net::SocketAddr = line
        .split_whitespace()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| {
            panic!("PRODUCT: the forward's address line names no address: {line:?}")
        });
    w.fwd = Some(fwd);
    let first = round_trip(at, b"before", Duration::from_secs(30));
    assert!(
        first.as_deref().is_ok_and(|b| b == b"before"),
        "PRODUCT (staging): no echo through the forward before the anchor went: {first:?}\n{}",
        w.fwd.as_mut().unwrap().transcript()
    );
    w.expect_still_relayed();
    std::thread::sleep(KILL_AFTER.saturating_sub(started.elapsed()));

    // ---- whose records the anchor holds before it goes -----------------------------------------
    let host_author: String = w.host_fp.chars().take(8).collect();
    let held_before = held_authors(&w.anchor.proc.transcript(), false);
    let host_held = held_before
        .iter()
        .find(|a| w.host_fp.starts_with(a.as_str()))
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): before the restart the anchor held no record for the host \
                 ({host_author}…): {held_before:?}\n{}",
                w.anchor.proc.transcript()
            )
        });
    println!("[proof] before the restart the anchor held records for {held_before:?}");

    // ---- the host is paused, so the guest is the only one who can restore its record ----------
    // A member publishes every record its board holds, the other members' too, so the host
    // reconnecting to its (configured) anchor would put the guest's record back by itself and
    // hide whether the guest republished. Paused by its PID (SIGSTOP), and resumed below.
    let host_pid = w
        .host
        .as_ref()
        .expect("APPARATUS: the relay world has no host process")
        .child
        .id()
        .to_string();
    signal_and_confirm(&host_pid, "-STOP");

    // ---- the anchor is stopped, and comes back on the same port, without its board -------------
    let anchor_dir = w.tmp.path().join("anchor");
    let killed = Instant::now();
    let sent = std::process::Command::new("kill")
        .args(["-INT", &w.anchor.proc.child.id().to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(sent, "APPARATUS: SIGINT could not be sent to the anchor");
    while w.anchor.proc.child.try_wait().ok().flatten().is_none() {
        assert!(
            killed.elapsed() < Duration::from_secs(10),
            "PRODUCT: the anchor (`vox node`) did not stop within 10 s of SIGINT\n{}",
            w.anchor.proc.transcript()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // Its board goes with its store; its identity file stays, so it is the same anchor.
    let store = anchor_dir.join("default").join("store.redb");
    assert!(
        std::fs::remove_file(&store).is_ok(),
        "CANNOT MEASURE: the anchor's store is not at {}",
        store.display()
    );
    std::thread::sleep(DOWN);
    w.anchor.restart(&anchor_dir);
    let back = Instant::now();
    println!(
        "[proof] the anchor was stopped {:?} after the forward started, and is back {:?} later",
        killed.duration_since(started),
        back.duration_since(killed)
    );

    // ---- the guest put the room back on the board the anchor lost -----------------------------
    let left = REPUBLISHED_WITHIN.saturating_sub(back.elapsed());
    let deadline = Instant::now() + left;
    let (mut turn, mut slowest_turn) = (Instant::now(), Duration::ZERO);
    let republished = loop {
        let now_held = held_authors(&w.anchor.proc.transcript(), true);
        if now_held.contains(&host_held) {
            break Some(back.elapsed());
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(200));
        slowest_turn = slowest_turn.max(turn.elapsed().saturating_sub(Duration::from_millis(200)));
        turn = Instant::now();
    };
    let apparatus = slowest_turn.max(apparatus_spawn(&w.guest_dir));
    println!(
        "[proof] with the host paused, the restarted anchor holds the host's record \
         ({host_held}) again, put there by the guest: {republished:?} after its return (bound \
         {REPUBLISHED_WITHIN:?}); it now holds {:?}",
        held_authors(&w.anchor.proc.transcript(), true)
    );
    if republished.is_none() {
        assert!(
            apparatus <= APPARATUS_BUDGET,
            "CANNOT MEASURE: apparatus took {apparatus:?} (budget {APPARATUS_BUDGET:?}) while the \
             republish was timed, so a missed {REPUBLISHED_WITHIN:?} may be this machine's"
        );
        panic!(
            "PRODUCT: the anchor came back without its board, the host was paused, and the guest, \
             whose only anchor it is, never put the room's records back on it within \
             {REPUBLISHED_WITHIN:?} (apparatus {apparatus:?}): a reconnect to a room's own anchor \
             did not republish\n---- the anchor ----\n{}\n---- the forward ----\n{}",
            w.anchor.proc.transcript(),
            w.fwd.as_mut().map(|f| f.transcript()).unwrap_or_default()
        );
    }
    // ---- the host resumes, and the forward carries again ----------------------------------------
    signal_and_confirm(&host_pid, "-CONT");
    let mut carried = None;
    let mut tries = 0u32;
    while back.elapsed() < PATIENCE {
        tries += 1;
        if round_trip(at, b"after", Duration::from_secs(2)).is_ok_and(|b| b == b"after") {
            carried = Some(back.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let said = w.fwd.as_mut().map(|f| f.transcript()).unwrap_or_default();
    let saw_it_go = said.lines().any(|l| l.contains(GONE));
    let apparatus = apparatus_spawn(&w.guest_dir);
    println!(
        "[proof] the forward carried again {carried:?} after the anchor was back, {tries} echo \
         tries (bound {BACK_WITHIN:?}, apparatus {apparatus:?}); it said its room's anchor went: \
         {saw_it_go}"
    );
    let carried = carried.unwrap_or_else(|| {
        panic!(
            "PRODUCT: the forward, whose only anchor is its room's, never carried again within \
             {PATIENCE:?} \
             of the anchor's return: a room's own anchor was not redialled\n---- the forward \
             ----\n{said}\n---- the anchor ----\n{}\n---- the host ----\n{}",
            w.anchor.proc.transcript(),
            w.host.as_mut().map(|h| h.transcript()).unwrap_or_default()
        )
    });
    if carried >= BACK_WITHIN {
        assert!(
            apparatus <= APPARATUS_BUDGET,
            "CANNOT MEASURE: apparatus took {apparatus:?} (budget {APPARATUS_BUDGET:?}) while the \
             forward carried again only {carried:?} after its anchor's return"
        );
        panic!(
            "PRODUCT: the forward carried again only {carried:?} after its room's anchor was back, \
             over {BACK_WITHIN:?} (apparatus {apparatus:?})\n---- the forward ----\n{said}"
        );
    }
    assert!(
        saw_it_go,
        "PRODUCT: the forward did not say its room's anchor connection went ({GONE:?}); in a \
         debug build this is #287 (V210-93), a stopping anchor's closes lost as it exits\n{said}"
    );
}

/// Send `sig` (`-STOP` or `-CONT`) to the process `pid` and confirm it took: `ps` must show the
/// process stopped (state `T`) after `-STOP`, and not stopped after `-CONT`.
fn signal_and_confirm(pid: &str, sig: &str) {
    let sent = std::process::Command::new("kill")
        .args([sig, pid])
        .status()
        .is_ok_and(|s| s.success());
    assert!(sent, "APPARATUS: `kill {sig} {pid}` failed");
    let want_stopped = sig == "-STOP";
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = std::process::Command::new("ps")
            .args(["-o", "state=", "-p", pid])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        if state.starts_with('T') == want_stopped && !state.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: {sig} did not take on PID {pid}: `ps` says its state is {state:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The apparatus clock: how long this machine takes, now, to start a `vox` that does nothing
/// (`vox --version`, against the profile at `dir`). A stalled runner stalls this too.
fn apparatus_spawn(dir: &Path) -> Duration {
    let t = Instant::now();
    let (ok, out, err) = vox_once(dir, &args(&["--version"]));
    assert!(
        ok,
        "APPARATUS: `vox --version` failed, so the apparatus clock cannot be read: {out}{err}"
    );
    t.elapsed()
}

/// The members whose records an anchor says its board holds (`vox node: board — <room> holding
/// <addrs> for <author>`), from after its last restart only when `after_restart`.
fn held_authors(transcript: &str, after_restart: bool) -> Vec<String> {
    let mut out: Vec<String> = transcript
        .lines()
        .filter(|l| !(after_restart && l.starts_with("(before the restart)")))
        .filter(|l| l.contains("vox node: board — ") && l.contains(" holding "))
        .filter_map(|l| l.rsplit(" for ").next())
        .map(|a| a.trim().to_owned())
        .collect();
    out.sort();
    out.dedup();
    out
}
