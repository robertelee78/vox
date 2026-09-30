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
//! [`DOWN`], and brought back **on the same port** from the same profile. Once it is listening it
//! is held for [`HELD`] (SIGSTOP, then SIGCONT, by its PID), as an anchor busy starting up is: the
//! members' redials queue in its socket and it meets them all at once. The bound runs from SIGCONT.
//!
//! **Why the hold.** Without it, on an 18-core machine, the redials arrive spread over each
//! member's tick and QUIC retransmit schedule, and each handshake ends in milliseconds: measured,
//! the burst never reached the cap, and the old code and the new both had all 300 back 4.03 s after
//! the restart. The run measured nothing, and said CANNOT MEASURE. The defect needs the redials to
//! meet the anchor together, which is what fix-v210-70's 300 simultaneous dials did, and what a
//! slower anchor, or one that takes a moment to start, sees.
//!
//! **Asserted:**
//! - the restarted anchor reports all [`MEMBERS`] peers connected within [`BACK_WITHIN`] of
//!   SIGCONT — its own `N peer(s) connected` line, read as it is printed;
//! - the burst reached the cap (the anchor says attempts waited for a handshake slot, or were
//!   refused — otherwise the run measured nothing and says CANNOT MEASURE), never more than [`CAP`]
//!   handshakes ran at once meanwhile, and **none was refused**.
//!
//! The in-flight and refused counts are the anchor's own report ([`NodeEvent::HandshakesQueued`],
//! said once a burst has nobody left waiting; a refusal with nobody waiting is a burst of its own,
//! so no refusal goes unsaid). Nothing outside the process can see a handshake slot. The bound is
//! observed from outside; what each member said about its anchor is printed for the last to return.
//!
//! **What the first bound does not separate, stated:** on this machine the old code met it too.
//! Measured with the hold, the old code had all 300 back 2.47 s after SIGCONT, the new 0.95 s: a
//! refused member's first backoff is a single second, and on 18 cores the next wave fits under the
//! cap. What separates the two is the refusals, so the old code goes red on those. The bound stays,
//! as the acceptance's "within a hard-coded bound".
//!
//! **Then a long outage.** A member whose dial to its anchor fails waits before the next, and that
//! wait used to double to 30 s. Measured with the restart above, one run in eight had 94 of 300
//! members back only 5–25 s after SIGCONT with none refused, which the cap cannot explain and a
//! backoff can. To stage failed dials every time, the anchor is stopped again (past the 10 s in
//! which a lost connection counts as a flap) and kept away for [`OUTAGE`] while **another node**
//! holds its port, as a stale address held by somebody else is (V210-17's trigger): every dial
//! reaches a node that is not the anchor and fails as soon as it answers, so every member's backoff
//! grows as far as it can. Then the anchor comes back on its port. **Asserted:** every member's
//! dials failed at least 3 times while it was away (else CANNOT MEASURE), and all [`MEMBERS`] are
//! connected again within [`BACK_WITHIN`] of the anchor listening — its own count, as above.
//!
//! Mutations (each must go red):
//! - validated attempts past the cap refused again (`HANDSHAKES_WAITING` = 0, the old behaviour)
//!   → red on the refusals;
//! - the cap raised (`HANDSHAKES_IN_FLIGHT` = 100) → red on the cap;
//! - a failed anchor dial backed off to 30 s again (`ANCHOR_UNREACHED_REDIAL_SECS` = 30) → red on
//!   the bound after the outage.
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
/// How long the restarted anchor is held (SIGSTOP) once it is listening, so the redials meet it at once.
const HELD: Duration = Duration::from_secs(3);
/// How long the anchor is away in the second outage, its port answered by another node meanwhile.
const OUTAGE: Duration = Duration::from_secs(40);
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
    let stopped = Instant::now();
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
    anchor.expect_line("the restarted anchor's --anchor spec", |l| {
        l.contains("@/ip4/127.0.0.1/udp/")
    });
    // Held as a slow start holds it: bound, and reading nothing. The members' redials queue in
    // its socket and reach it together when it goes on (see the header).
    let pid = anchor.child.id().to_string();
    let _ = std::process::Command::new("kill")
        .args(["-STOP", &pid])
        .status();
    std::thread::sleep(HELD);
    let _ = std::process::Command::new("kill")
        .args(["-CONT", &pid])
        .status();
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
    // A burst's report comes once none is left waiting, which may be a moment after the count.
    std::thread::sleep(Duration::from_secs(8));
    anchor.transcript();
    let said: Vec<String> = anchor
        .seen
        .iter()
        .filter(|l| l.contains(WAITED))
        .cloned()
        .collect();
    eprintln!("[proof] the anchor said, {} report(s):", said.len());
    for l in said.iter().take(5) {
        eprintln!("[proof]   {l}");
    }
    // What the members said about their anchor after the restart: the anchor sees only who got
    // in, so a member that was late says why (a failed dial and its backoff, or a flap).
    let mut back_at: Vec<(Duration, usize)> = Vec::new();
    for (i, d) in daemons.iter().enumerate() {
        let lines = d.timed.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((t, _)) = lines
            .iter()
            .find(|(t, l)| *t >= stopped && l.contains("connected to this anchor"))
        {
            back_at.push((t.saturating_duration_since(back), i));
        }
    }
    back_at.sort();
    eprintln!(
        "[proof] {} member(s) said they were connected to the anchor again; the last:",
        back_at.len()
    );
    for (at, i) in back_at.iter().rev().take(3) {
        eprintln!(
            "[proof]   {} at {at:?} after SIGCONT, having said:",
            daemons[*i].name
        );
        let lines = daemons[*i].timed.lock().unwrap_or_else(|e| e.into_inner());
        for (t, l) in lines.iter().filter(|(t, _)| *t >= stopped) {
            let when = if *t >= back {
                format!("+{:?}", t.duration_since(back))
            } else {
                format!("-{:?}", back.duration_since(*t))
            };
            eprintln!("[proof]     {when} {l}");
        }
    }
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

    // ---- the cap held, and nobody was refused ---------------------------------------------------
    let number = |line: &str, after: &str| -> usize {
        line.split(after)
            .nth(1)
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| {
                n.trim_end_matches(|c: char| !c.is_ascii_digit())
                    .parse()
                    .ok()
            })
            .unwrap_or_else(|| panic!("no number after {after:?} in {line:?}"))
    };
    let (mut waited, mut running, mut refused) = (0, 0, 0);
    for l in &said {
        waited += number(l, "vox node: ");
        running = running.max(number(l, "while at most "));
        refused += number(l, "; ");
    }
    eprintln!(
        "[proof] {waited} attempts waited, at most {running} handshakes ran at once (cap {CAP}), \
         {refused} refused, over {} report(s)",
        said.len()
    );
    assert!(
        waited + refused > 0,
        "CANNOT MEASURE: the anchor never said attempts waited for a handshake slot or were \
         refused, so the burst never reached the cap of {CAP}\n{}",
        anchor.transcript()
    );
    assert!(
        running <= CAP,
        "{running} handshakes ran at once, over the cap of {CAP}: {said:#?}"
    );
    assert_eq!(
        refused, 0,
        "{refused} attempts were refused at the cap instead of waiting for a slot: {said:#?}"
    );

    // ---- a long outage: the anchor is away OUTAGE, its port answered by another node -----------
    // Past a flap first: a connection lost within ANCHOR_FLAP_SECS (10 s) of being made is
    // backed off as a flap, which is not what this measures.
    std::thread::sleep(Duration::from_secs(12));
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
    let away = Instant::now();
    let stranger_dir = tmp.path().join("stranger");
    std::fs::create_dir_all(stranger_dir.join("cfg")).unwrap();
    let mut stranger = VoxProc::spawn(
        "stranger",
        &stranger_dir,
        &args(&["node", "--listen", &listen]),
    );
    stranger.expect_line("the stranger's --anchor spec", |l| {
        l.contains("@/ip4/127.0.0.1/udp/")
    });
    std::thread::sleep(OUTAGE.saturating_sub(away.elapsed()));
    let _ = std::process::Command::new("kill")
        .args(["-INT", &stranger.child.id().to_string()])
        .status();
    let stopping = Instant::now();
    while stranger.child.try_wait().ok().flatten().is_none() {
        assert!(
            stopping.elapsed() < Duration::from_secs(10),
            "CANNOT MEASURE: the stranger did not stop within 10 s of SIGINT"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(stranger);
    let mut anchor = VoxProc::spawn(
        "anchor (back after the outage)",
        &anchor_dir,
        &args(&["node", "--listen", &listen]),
    );
    anchor.expect_line("the returned anchor's --anchor spec", |l| {
        l.contains("@/ip4/127.0.0.1/udp/")
    });
    let back = Instant::now();
    let (most, at) = wait_for_peers(
        &mut anchor,
        MEMBERS,
        back,
        BACK_WITHIN + Duration::from_secs(50),
    );
    eprintln!(
        "[proof] after the outage: {most}/{MEMBERS} members connected, the last {at:?} after the \
         anchor was listening again (bound {BACK_WITHIN:?})"
    );
    // The staging is that every member's dials failed while it was away, several times over.
    let failed: Vec<usize> = daemons
        .iter()
        .map(|d| {
            d.timed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(t, l)| {
                    *t >= away && *t < back && l.contains("dialling this anchor failed")
                })
                .count()
        })
        .collect();
    let fewest = failed.iter().copied().min().unwrap_or(0);
    eprintln!(
        "[proof] while it was away, each member's dials to it failed {fewest} to {} time(s), {} in \
         all",
        failed.iter().copied().max().unwrap_or(0),
        failed.iter().sum::<usize>()
    );
    let mut late: Vec<(Duration, usize)> = Vec::new();
    for (i, d) in daemons.iter().enumerate() {
        let lines = d.timed.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((t, _)) = lines
            .iter()
            .find(|(t, l)| *t >= back && l.contains("connected to this anchor"))
        {
            late.push((t.saturating_duration_since(back), i));
        }
    }
    late.sort();
    for (at, i) in late.iter().rev().take(2) {
        eprintln!(
            "[proof]   {} was back {at:?} after it, having said:",
            daemons[*i].name
        );
        let lines = daemons[*i].timed.lock().unwrap_or_else(|e| e.into_inner());
        for (t, l) in lines.iter().filter(|(t, _)| *t >= away).rev().take(4).rev() {
            eprintln!("[proof]     +{:?} {l}", t.duration_since(away));
        }
    }
    assert!(
        fewest >= 3,
        "CANNOT MEASURE: a member's dials failed only {fewest} time(s) while its anchor was away, \
         so its backoff never grew"
    );
    assert!(
        most >= MEMBERS && at <= BACK_WITHIN,
        "{most}/{MEMBERS} members were back after the outage, the last {at:?} after the anchor was \
         listening again, over {BACK_WITHIN:?}: a member whose dials failed while it was away waits \
         out its backoff"
    );
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
                        eprintln!("[proof]   {n} peer(s) connected at {at:?}");
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
