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
//! - **no member was turned away**: none says its dial to the anchor failed after the restart (a
//!   member the anchor refuses says so, with the reason and its next try).
//!
//! The staging — that the burst met the anchor's cap of 64 handshakes — is something only the
//! anchor can see, and it says so to its operator: "N connection attempt(s) waited for a handshake
//! slot … M refused". A run where it never says so measured nothing, and says PRODUCT (staging). The
//! cap itself is unchanged and rests on review: how many handshakes run at once is not something a
//! user sees. What each member said about its anchor is printed for the last to return.
//!
//! **A stop must be said to every member** for the first bound to hold: a member that misses its
//! anchor's close learns it is gone only from its silence (30 s). In a debug build the anchor's
//! closes were lost as it exited (#287, V210-93, measured here: 300 members back up to 26 s after
//! the restart); that is #287's to fix, and until it lands this arm is red in debug.
//!
//! **What the first bound does not separate, stated:** on this machine, in release, the old
//! queueing code met it too: the old code had all 300 back 2.47 s after SIGCONT, the new 0.95 s. A
//! refused member's first backoff is a single second, and on 18 cores the next wave fits under the
//! cap. What separates the two is what the members were told, so the old code goes red on that.
//!
//! **Then a long outage.** A member whose dial to its anchor fails waits before the next, and that
//! wait used to double to 30 s. Measured with the restart above, one run in eight had 94 of 300
//! members back only 5–25 s after SIGCONT with none refused, which the cap cannot explain and a
//! backoff can. To stage failed dials every time, the anchor is stopped again (past the 10 s in
//! which a lost connection counts as a flap) and kept away for [`OUTAGE`] while **another node**
//! holds its port, as a stale address held by somebody else is (V210-17's trigger): every dial
//! reaches a node that is not the anchor and fails as soon as it answers, so every member's backoff
//! grows as far as it can. Then the anchor comes back on its port. **Asserted:** every member's
//! dials failed at least 3 times while it was away (else PRODUCT (staging)), and all [`MEMBERS`] are
//! connected again within [`BACK_WITHIN`] of the anchor listening — its own count, as above.
//!
//! **Then a busy anchor.** Waiting is bounded (5 s), so an anchor whose every slot is held still
//! refuses, and a refused member used to be told "signature verification failed": every failed
//! handshake was reported as one. To stage refusals, the anchor is restarted with [`STALLED`]
//! members' dials queued in its socket, and those members are frozen (SIGSTOP) before it goes on,
//! as members whose machines froze mid-handshake: each attempt it takes from them holds a slot until
//! it gives up on it (30 s). The other members are frozen while it restarts and let go a second
//! after it goes on, so every slot is held when they dial. **Asserted:** the anchor refused some
//! (its own report; else PRODUCT (staging)); no refused member was told of a bad signature; at least
//! one was told the anchor is busy ([`BUSY`]); every refused member retried and was connected within
//! [`BUSY_BACK_WITHIN`] of the anchor going on; and once the frozen members go on, all [`MEMBERS`]
//! are connected within [`BACK_WITHIN`].
//!
//! **Optional** (300 daemons, a few minutes in release): it runs only with the `optional-proofs`
//! feature and blocks nothing. Run it with
//! `cargo test --release -p vox-tui --features optional-proofs --test every_member_is_back_after_an_anchor_restart_proof -- --ignored --nocapture`.
//! Without the feature a stand-in, `optional_proof_not_run::every_member_is_back_after_an_anchor_restart`,
//! takes its place, so a run is never silent about it: a listing shows it, a run shows it ignored
//! with the reason, and a run of the ignored tests prints that the proof did not run, and passes.
//!
//! Every red says which it is: `PRODUCT:` quotes what the product said or did, `PRODUCT (staging):`
//! names staging that was not achieved, `APPARATUS:` names a fault of the proof's own; the
//! watchdog says it is the watchdog.
//!
//! Mutations (each must go red):
//! - validated attempts past the cap refused again (`HANDSHAKES_WAITING` = 0, the old behaviour)
//!   → red on the members turned away;
//! - a refused dial reported as a bad signature again (the dial's `map_err` back to
//!   `Error::SignatureInvalid`) → red on what the refused members were told;
//! - a failed anchor dial backed off to 30 s again (`ANCHOR_UNREACHED_REDIAL_SECS` = 30) → red on
//!   the bound after the outage;
//!

#![cfg(unix)]
// Without the feature only the stand-in below runs; the proof's code still compiles, unused.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(every_member_is_back_after_an_anchor_restart);

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
/// How many members are frozen mid-handshake to make the anchor busy: more than its cap.
const STALLED: usize = 100;
/// How long the busy anchor is held so the stalled members' dials queue in its socket.
const STALL_QUEUED: Duration = Duration::from_secs(5);
/// How soon after the busy anchor goes on every member it refused must be connected: the
/// anchor's 30 s for a handshake that never finishes, then a retry and a handshake.
const BUSY_BACK_WITHIN: Duration = Duration::from_secs(40);
/// What a member refused by a busy anchor is told.
const BUSY: &str = "the peer is busy";

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real binaries, 300 daemons and production Argon2id; run by hand, never in CI"]
fn every_member_is_back_after_an_anchor_restart() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg"))
        .expect("APPARATUS: cannot make a profile directory");
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
                    std::fs::create_dir_all(dir.join("cfg"))
                        .expect("APPARATUS: cannot make a profile directory");
                    let (ok, _, err) = vox_once(&dir, &args(&["id"]));
                    assert!(ok, "PRODUCT (staging): vox id (staging) failed: {err}");
                })
            })
            .collect();
        for h in handles {
            h.join().expect("APPARATUS: a vox id thread panicked");
        }
    }
    eprintln!("[proof] {MEMBERS} identities made in {:?}", made.elapsed());

    // ---- MEMBERS daemons, started a few at a time, all connected --------------------------------
    let pass_file = tmp.path().join("identity-passphrase");
    std::fs::write(&pass_file, format!("{IDENTITY}\n"))
        .expect("APPARATUS: cannot write the passphrase file");
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
        "PRODUCT (staging): only {first} of {MEMBERS} members connected to the anchor within \
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
            "PRODUCT: the anchor did not stop within 10 s of SIGINT"
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
        "PRODUCT: only {most} of {MEMBERS} members were connected again within {:?} of the anchor's \
         return\n---- the anchor ----\n{}",
        BACK_WITHIN + Duration::from_secs(50),
        anchor.transcript()
    );
    assert!(
        at < BACK_WITHIN,
        "PRODUCT: every member was back only {at:?} after the anchor's return, over \
         {BACK_WITHIN:?}\n---- the anchor ----\n{}",
        anchor.transcript()
    );

    // ---- nobody was turned away ------------------------------------------------------------------
    // The staging: the burst met the cap, which only the anchor can see. Its report is what it
    // tells its operator.
    let number = |line: &str, after: &str| -> usize {
        line.split(after)
            .nth(1)
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| {
                n.trim_end_matches(|c: char| !c.is_ascii_digit())
                    .parse()
                    .ok()
            })
            .unwrap_or_else(|| {
                panic!("APPARATUS: the proof cannot read a number after {after:?} in {line:?}")
            })
    };
    let (mut waited, mut refused) = (0, 0);
    for l in &said {
        waited += number(l, "vox node: ");
        refused += number(l, "; ");
    }
    eprintln!(
        "[proof] the anchor says {waited} attempts waited for a handshake slot and {refused} were \
         refused, over {} report(s)",
        said.len()
    );
    assert!(
        waited + refused > 0,
        "PRODUCT (staging): the anchor never said attempts waited for a handshake slot or were \
         refused, so the burst never reached its cap\n{}",
        anchor.transcript()
    );
    // What the members saw: a member the anchor turned away says its dial failed.
    let turned_away: Vec<String> = daemons
        .iter()
        .flat_map(|d| {
            d.timed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(t, l)| *t >= back && l.contains("dialling this anchor failed"))
                .map(|(_, l)| format!("{}: {l}", d.name))
                .collect::<Vec<_>>()
        })
        .collect();
    eprintln!(
        "[proof] {} dial(s) to the restarted anchor failed, as the members said",
        turned_away.len()
    );
    assert!(
        turned_away.is_empty(),
        "PRODUCT: the restarted anchor turned members away instead of letting them wait for a \
         handshake slot; {} failed dial(s), the first: {:#?}",
        turned_away.len(),
        &turned_away[..turned_away.len().min(3)]
    );

    // ---- a busy anchor: its slots held by members frozen mid-handshake, the rest refused --------
    // Past a flap first, as below.
    std::thread::sleep(Duration::from_secs(12));
    let (stalled, refused_ones) = daemons.split_at(STALLED);
    // The refused ones send nothing until the slots are taken: frozen before the anchor stops.
    for d in refused_ones {
        signal("-STOP", d);
    }
    let _ = std::process::Command::new("kill")
        .args(["-INT", &anchor.child.id().to_string()])
        .status();
    let stopping = Instant::now();
    while anchor.child.try_wait().ok().flatten().is_none() {
        assert!(
            stopping.elapsed() < Duration::from_secs(10),
            "PRODUCT: the anchor did not stop within 10 s of SIGINT"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(anchor);
    std::thread::sleep(DOWN);
    let mut anchor = VoxProc::spawn(
        "anchor (busy)",
        &anchor_dir,
        &args(&["node", "--listen", &listen]),
    );
    anchor.expect_line("the busy anchor's --anchor spec", |l| {
        l.contains("@/ip4/127.0.0.1/udp/")
    });
    // Held while the stalled members' dials queue in its socket, then the stalled members are
    // frozen: each attempt the anchor takes from them holds a handshake slot until the anchor
    // gives up on it (30 s), as a member whose machine froze mid-handshake does.
    let pid = anchor.child.id().to_string();
    let _ = std::process::Command::new("kill")
        .args(["-STOP", &pid])
        .status();
    std::thread::sleep(STALL_QUEUED);
    for d in stalled {
        signal("-STOP", d);
    }
    let _ = std::process::Command::new("kill")
        .args(["-CONT", &pid])
        .status();
    let busy = Instant::now();
    std::thread::sleep(Duration::from_secs(1));
    for d in refused_ones {
        signal("-CONT", d);
    }
    let want = MEMBERS - STALLED;
    let (most, at) = wait_for_peers(&mut anchor, want, busy, Duration::from_secs(90));
    eprintln!(
        "[proof] busy anchor: {most}/{want} members it refused connected, the last {at:?} after it \
         went on (bound {BUSY_BACK_WITHIN:?})"
    );
    let said_failed: Vec<(usize, String)> = refused_ones
        .iter()
        .enumerate()
        .flat_map(|(i, d)| {
            d.timed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(t, l)| *t >= busy && l.contains("dialling this anchor failed"))
                .map(|(_, l)| (i, l.clone()))
                .collect::<Vec<_>>()
        })
        .collect();
    let told_busy = said_failed.iter().filter(|(_, l)| l.contains(BUSY)).count();
    let told_bad_signature: Vec<&String> = said_failed
        .iter()
        .map(|(_, l)| l)
        .filter(|l| l.contains("signature"))
        .collect();
    let mut who: Vec<usize> = said_failed
        .iter()
        .filter(|(_, l)| l.contains(BUSY))
        .map(|(i, _)| *i)
        .collect();
    who.dedup();
    eprintln!(
        "[proof] busy anchor: {} failed dial(s) said by the refused members, {told_busy} told \
         busy ({} member(s)), {} told of a bad signature",
        said_failed.len(),
        who.len(),
        told_bad_signature.len()
    );
    for (_, l) in said_failed.iter().take(3) {
        eprintln!("[proof]   {l}");
    }
    std::thread::sleep(Duration::from_secs(2));
    anchor.transcript();
    let refused: usize = anchor
        .seen
        .iter()
        .filter(|l| l.contains(WAITED))
        .map(|l| {
            l.split("; ")
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0)
        })
        .sum();
    eprintln!("[proof] busy anchor: it says it refused {refused} attempt(s)");
    assert!(
        refused > 0,
        "PRODUCT (staging): the busy anchor refused nobody, so no member could be told why\n{}",
        anchor.transcript()
    );
    assert!(
        told_bad_signature.is_empty(),
        "PRODUCT: a member refused by a busy anchor was told of a bad signature: {told_bad_signature:#?}"
    );
    assert!(
        told_busy > 0,
        "PRODUCT: the anchor refused {refused} attempt(s) and no refused member was told it was busy: \
         {said_failed:#?}"
    );
    assert!(
        most >= want && at < BUSY_BACK_WITHIN,
        "PRODUCT: {most}/{want} refused members were back, the last {at:?} after the busy anchor went on, \
         over {BUSY_BACK_WITHIN:?}: a refused member did not retry once a slot was free"
    );
    // The frozen members come back too.
    for d in stalled {
        signal("-CONT", d);
    }
    let thawed = Instant::now();
    let (most, at) = wait_for_peers(&mut anchor, MEMBERS, thawed, Duration::from_secs(60));
    eprintln!(
        "[proof] busy anchor: {most}/{MEMBERS} members connected, the last {at:?} after the \
         stalled ones went on (bound {BACK_WITHIN:?})"
    );
    assert!(
        most >= MEMBERS && at < BACK_WITHIN,
        "PRODUCT: {most}/{MEMBERS} members were back, the last {at:?} after the stalled ones went on, over \
         {BACK_WITHIN:?}"
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
            "PRODUCT: the anchor did not stop within 10 s of SIGINT"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(anchor);
    let away = Instant::now();
    let stranger_dir = tmp.path().join("stranger");
    std::fs::create_dir_all(stranger_dir.join("cfg"))
        .expect("APPARATUS: cannot make a profile directory");
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
            "PRODUCT: the stranger (a vox node) did not stop within 10 s of SIGINT"
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
        let since: Vec<_> = lines.iter().filter(|(t, _)| *t >= away).collect();
        for (t, l) in &since[since.len().saturating_sub(4)..] {
            eprintln!("[proof]     +{:?} {l}", t.duration_since(away));
        }
    }
    assert!(
        fewest >= 3,
        "PRODUCT (staging): a member's dials failed only {fewest} time(s) while its anchor was away, \
         so its backoff never grew"
    );
    assert!(
        most >= MEMBERS && at <= BACK_WITHIN,
        "PRODUCT: {most}/{MEMBERS} members were back after the outage, the last {at:?} after the anchor was \
         listening again, over {BACK_WITHIN:?}: a member whose dials failed while it was away waits \
         out its backoff"
    );
}

/// Send `sig` (`-STOP` or `-CONT`) to the process `p`, by its PID.
fn signal(sig: &str, p: &VoxProc) {
    let _ = std::process::Command::new("kill")
        .args([sig, &p.child.id().to_string()])
        .status();
}

/// A `vox daemon` for the profile at `dir`, pointed at the anchor `spec`.
fn daemon(dir: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    VoxProc::spawn(
        &dir.file_name()
            .expect("APPARATUS: a path with no file name")
            .to_string_lossy(),
        dir,
        &args(&[
            "daemon",
            "--passphrase-file",
            pass_file
                .to_str()
                .expect("APPARATUS: a path that is not UTF-8"),
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
                "PRODUCT: the anchor exited by itself\n{}",
                anchor.seen.join("\n")
            ),
        }
    }
    (most, at)
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("APPARATUS: bind a socket")
        .local_addr()
        .expect("APPARATUS: read a socket the proof bound")
        .port()
}
