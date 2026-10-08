//! V210-86 (#278) — **after an anchor restarts, every member is back promptly**, through the
//! shipped binary.
//!
//! **The scene:** one anchor (`vox node`) on a fixed port of `[::]`, and [`MEMBERS`] real
//! `vox daemon`s, each its own identity made by `vox id`, all pointed at it with `--anchor`: half
//! of them dial it from `127.0.0.1`, half from `::1`. The daemons are started a few at a time, so
//! their first connections are not the burst being measured, and the anchor must report all of
//! them connected. Then the anchor is **stopped** (SIGINT, as a person stops it: it closes every
//! connection, so every member learns at once and redials together), kept down for [`DOWN`], and
//! brought back **on the same port** from the same profile, held for [`STARTING`] between
//! binding the port and attaching its node (a start slowed by its unlock), so every member's
//! redial reaches it in that gap. **Asserted:** none of them is refused ("nothing … answers as" the
//! anchor): an anchor that answered before its node was attached refused its own members. Once it
//! is listening it is held for
//! [`HELD`] (SIGSTOP, then SIGCONT, by its PID), as an anchor busy starting up is: the members'
//! redials queue in its socket and it meets them all at once. The bound runs from SIGCONT.
//!
//! **Why [`MEMBERS_PER_SOURCE`] members per source address, not 300 from one.** A listener admits
//! at most 8 identity requests a second from one source IP address, with a burst of 16 (ADR-011
//! requirement 34); over that, a request is refused and its dialler retries later. 300 members on
//! one machine all dial from `127.0.0.1`, so after a restart they came back at 8 a second: the last
//! about 36 s after the anchor's return. The decider ruled on 2026-10-04 that the shared-IP budget
//! stays as it is, with no exemption, so this proof stages what that budget allows from one
//! machine without sudo: 16 members from each of the two loopback addresses, both within their
//! burst. The handshake cap (64 in flight) is not reached by 32 members; it is unchanged, and
//! rests on review.
//!
//! **Asserted after the restart:** the restarted anchor reports all [`MEMBERS`] peers connected
//! within [`BACK_WITHIN`] of SIGCONT — its own `N peer(s) connected` line, read as it is printed;
//! and **no member was turned away**: none says its dial to the anchor failed after the restart,
//! save a dial begun before the hold, which may time out across it within the exchange's bound
//! and must then say it did not answer in time, not "answers as" (ADR-011 38a).
//!
//! **A stop must be said to every member** for that bound to hold: a member that misses its
//! anchor's close learns it is gone only from its silence (30 s).
//!
//! **Then a long outage.** A member whose dial to its anchor fails waits before the next, and that
//! wait used to double to 30 s. To stage failed dials every time, the anchor is stopped again (past
//! the 10 s in which a lost connection counts as a flap) and kept away for [`OUTAGE`] while
//! **another node** holds its port, as a stale address held by somebody else is (V210-17's
//! trigger): every dial reaches a node that is not the anchor and fails as soon as it answers, so
//! every member's backoff grows as far as it can. Then the anchor comes back on its port.
//! **Asserted:** every member's dials failed at least twice while it was away (else PRODUCT
//! (staging)), and all [`MEMBERS`] are connected again within [`BACK_WITHIN`] of the anchor
//! listening — its own count, as above.
//!
//! **Optional** (a minute or two in release): it runs only with the `optional-proofs` feature and
//! blocks nothing. Run it with
//! `cargo test --release -p vox-tui --features optional-proofs --test every_member_is_back_after_an_anchor_restart_proof -- --ignored --nocapture`.
//! Without the feature a stand-in, `optional_proof_not_run::every_member_is_back_after_an_anchor_restart`,
//! takes its place, so a run is never silent about it.
//!
//! Every red says which it is: `PRODUCT:` quotes what the product said or did, `PRODUCT (staging):`
//! names staging that was not achieved, `APPARATUS:` names a fault of the proof's own; the
//! watchdog says it is the watchdog.
//!
//! Mutations (each must go red):
//! - a member's redial after its anchor's close stretched (the first wait after a lost anchor
//!   connection 30 s instead of 1) → red on the bound after the restart (22.98 s, 2026-10-04);
//! - a member's redial after a failed anchor dial stretched (the first wait 30 s instead of 1) →
//!   red on the bound after the outage. Doubling the cap alone (`ANCHOR_UNREACHED_REDIAL_SECS` =
//!   30) does not go red with 32 members: their waits never grow past a few seconds in 40 s.
//! - the presence's accept loop started when its port is bound, not with the first attach
//!   (`NetPresence::start` spawning it) → red on the refusals while the anchor started.
//!
//! **Needs a `test-knobs` build** (`VOX_TEST_DAEMON_SERVE_DELAY_MS`); run it with
//! `--features test-knobs,optional-proofs`.

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

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY};

/// How many members dial the anchor from each of its two loopback addresses: the burst one source
/// may spend (ADR-011 requirement 34).
const MEMBERS_PER_SOURCE: usize = 16;
/// How many members redial the restarted anchor: [`MEMBERS_PER_SOURCE`] from `127.0.0.1`, as many
/// from `::1`.
const MEMBERS: usize = 2 * MEMBERS_PER_SOURCE;
/// How long the anchor stays down.
const DOWN: Duration = Duration::from_secs(3);
/// How long the restarted anchor is held (SIGSTOP) once it is listening, so the redials meet it at once.
const HELD: Duration = Duration::from_secs(3);
/// How long the restarted anchor is held between binding its port and attaching its node
/// (`VOX_TEST_DAEMON_SERVE_DELAY_MS`, test-knobs builds): every member redials at least once in it.
const STARTING: Duration = Duration::from_secs(2);
/// How long the anchor is away in the second outage, its port answered by another node meanwhile.
const OUTAGE: Duration = Duration::from_secs(40);
/// How soon after the anchor is back every member must be connected to it again.
const BACK_WITHIN: Duration = Duration::from_secs(10);
/// How long the members get to connect the first time, before anything is measured.
const SETTLE: Duration = Duration::from_secs(300);

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real binaries, 32 daemons and production Argon2id; run by hand, never in CI"]
fn every_member_is_back_after_an_anchor_restart() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_DAEMON_SERVE_DELAY_MS"]);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg"))
        .expect("APPARATUS: cannot make a profile directory");
    // On a port of its own choosing, read back from its spec (#410); it comes back on that port.
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "[::]:0"]),
    );
    let spec = anchor
        .expect_line("the anchor's --anchor spec", |l| {
            l.contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();
    let port = world::spec_addr(&spec).port();
    let listen = format!("[::]:{port}");
    // The same anchor, dialled from each loopback address (each its own source, ADR-011 req 34).
    let specs = [
        world::respec(
            &spec,
            format!("127.0.0.1:{port}")
                .parse()
                .expect("APPARATUS: an address"),
        ),
        world::respec(
            &spec,
            format!("[::1]:{port}")
                .parse()
                .expect("APPARATUS: an address"),
        ),
    ];

    // ---- MEMBERS identities, a few at a time (each is a production Argon2id) --------------------
    let at_once = std::thread::available_parallelism().map_or(4, |n| n.get().min(12));
    let dirs: Vec<PathBuf> = (0..MEMBERS)
        .map(|i| tmp.path().join(format!("m{i:03}")))
        .collect();
    let made = Instant::now();
    for batch in dirs.chunks(at_once) {
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
    for batch in dirs.chunks(at_once) {
        for dir in batch {
            // Even members from 127.0.0.1, odd ones from ::1.
            let i = daemons.len();
            daemons.push(daemon(dir, &specs[i % 2], &pass_file, i % 2 == 1));
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
    // Held between binding its port and attaching its node for STARTING, as a start slowed by its
    // unlock is: the members' redials reach it in that gap.
    let restarted = Instant::now();
    let mut anchor = VoxProc::spawn_env(
        "anchor (restarted)",
        &anchor_dir,
        &args(&["node", "--listen", &listen]),
        &[(
            "VOX_TEST_DAEMON_SERVE_DELAY_MS",
            &STARTING.as_millis().to_string(),
        )],
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

    // ---- nobody was turned away while the anchor started ------------------------------------------
    // Bound and not yet attached, the anchor has nobody to answer for: a dial then must wait to be
    // answered, not be refused as if the anchor were not there.
    let while_starting: Vec<String> = daemons
        .iter()
        .flat_map(|d| {
            d.timed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(t, l)| {
                    *t >= restarted
                        && *t < back
                        && l.contains("dialling this anchor failed")
                        && l.contains("answers as")
                })
                .map(|(_, l)| format!("{}: {l}", d.name))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        while_starting.is_empty(),
        "PRODUCT: the restarted anchor refused its own members while it started; {} refusal(s), \
         the first: {:#?}",
        while_starting.len(),
        &while_starting[..while_starting.len().min(3)]
    );

    // ---- nobody was turned away ------------------------------------------------------------------
    // What the members saw: a member the anchor turned away says its dial failed. One exception,
    // the staging's own: a dial whose exchange began before SIGSTOP and was not answered by then
    // times out across the hold, within EXCHANGE_TIMEOUT of SIGCONT, and must say it timed out —
    // never "answers as" or "did not prove", which read as a refusal or an impostor (ADR-011 38a).
    let exchange = vox_core::transport::identity::EXCHANGE_TIMEOUT;
    let mut across_hold = Vec::new();
    let turned_away: Vec<String> = daemons
        .iter()
        .flat_map(|d| {
            d.timed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|(t, l)| *t >= back && l.contains("dialling this anchor failed"))
                .filter(|(t, l)| {
                    let held = *t < back + exchange
                        && l.contains(&format!("did not answer within {} s", exchange.as_secs()))
                        && !l.contains("answers as")
                        && !l.contains("did not prove");
                    if held {
                        across_hold.push(format!("{}: {l}", d.name));
                    }
                    !held
                })
                .map(|(_, l)| format!("{}: {l}", d.name))
                .collect::<Vec<_>>()
        })
        .collect();
    eprintln!(
        "[proof] {} dial(s) begun before the hold timed out across it, as they said: {across_hold:#?}",
        across_hold.len()
    );
    eprintln!(
        "[proof] {} dial(s) to the restarted anchor failed, as the members said",
        turned_away.len()
    );
    assert!(
        turned_away.is_empty(),
        "PRODUCT: the restarted anchor turned members away, each within its source's budget; {} \
         failed dial(s), the first: {:#?}",
        turned_away.len(),
        &turned_away[..turned_away.len().min(3)]
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
    // **A member that never came back is the product's red, whatever its dials did** (the full
    // pass of 75c22d4f: 27 of 32 back after a minute, and the staging line, read first, called it
    // a staging miss). Each one is named, with what it said since the anchor went away.
    let missing: Vec<String> = daemons
        .iter()
        .filter(|d| {
            !d.timed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|(t, l)| *t >= back && l.contains("connected to this anchor"))
        })
        .map(|d| {
            let lines = d.timed.lock().unwrap_or_else(|e| e.into_inner());
            let said: Vec<String> = lines
                .iter()
                .filter(|(t, _)| *t >= away)
                .map(|(t, l)| format!("    +{:?} {l}", t.duration_since(away)))
                .collect();
            format!("  {}:\n{}", d.name, said.join("\n"))
        })
        .collect();
    assert!(
        most >= MEMBERS,
        "PRODUCT: only {most}/{MEMBERS} members were connected to the anchor again within {:?} of it \
         listening after the outage; those that did not say they were:\n{}",
        BACK_WITHIN + Duration::from_secs(50),
        missing.join("\n")
    );
    // Which members, and what they said while it was away: a staging miss names its cause.
    let short: Vec<String> = daemons
        .iter()
        .zip(&failed)
        .filter(|(_, n)| **n < 2)
        .map(|(d, n)| {
            let lines = d.timed.lock().unwrap_or_else(|e| e.into_inner());
            let said: Vec<String> = lines
                .iter()
                .filter(|(t, _)| *t >= away)
                .map(|(t, l)| format!("    +{:?} {l}", t.duration_since(away)))
                .collect();
            format!("  {} ({n} failed dial(s)):\n{}", d.name, said.join("\n"))
        })
        .collect();
    assert!(
        fewest >= 2,
        "PRODUCT (staging): a member's dials failed only {fewest} time(s) while its anchor was away, \
         so its backoff never grew; {most}/{MEMBERS} were back. The members short of two:\n{}",
        short.join("\n")
    );
    assert!(
        most >= MEMBERS && at <= BACK_WITHIN,
        "PRODUCT: {most}/{MEMBERS} members were back after the outage, the last {at:?} after the anchor was \
         listening again, over {BACK_WITHIN:?}: a member whose dials failed while it was away waits \
         out its backoff"
    );
}

/// A `vox daemon` for the profile at `dir`, pointed at the anchor `spec`, listening on IPv6
/// loopback when `v6`, else IPv4.
fn daemon(dir: &Path, spec: &str, pass_file: &Path, v6: bool) -> VoxProc {
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
            if v6 { "[::1]:0" } else { "127.0.0.1:0" },
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
