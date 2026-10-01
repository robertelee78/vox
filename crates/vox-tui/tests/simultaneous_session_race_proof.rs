//! **V210-27 — two members who open their pairwise session to each other at once converge on
//! one, and read each other**, forced on every run, through the shipped `vox` binary.
//!
//! Two members who trust each other auto-consent: each finds no pairwise session, opens one,
//! and sends its hello and sender key over it. If both do it before either has the other's
//! hello, each holds a session the other did not accept. Before `56f9763`, each kept its own,
//! ignored the other's hello, and could not open the key sealed under it: neither ever read the
//! other (ADR-021 F12). The fix has both ends keep the session the lower fingerprint opened.
//!
//! That race used to be caught by chance: about one run in three. Here it is forced. bob and
//! carol reach each other only through the anchor's relay (bob on `127.0.0.1`, carol on `[::1]`,
//! the anchor on `[::]`), so **freezing the anchor** (SIGSTOP) holds everything between them.
//! Both then trust each other at once: each opens its session and sends its hello into the
//! frozen relay. When the anchor is released, the two hellos cross, and each end receives the
//! other's only after it has opened its own. That is the race, on every run.
//!
//! What it asserts: before the trust, bob cannot read carol (so the keys come from this
//! exchange and nothing earlier); after it, each comes to read the other. Each keeps posting a
//! fresh probe until the other reads one, so what is measured is whether the two sessions
//! converged, not whether one particular post fell inside the window before a key arrived.
//! A consent that could not be delivered while the relay was frozen releases its key from the
//! chain's position when it IS delivered, so a post made in between is never readable to that
//! member (a separate defect, V210-29); a probe made after delivery is.
//!
//! **V210-89 — a hello lost after it was written.** The freeze makes both members' first dials
//! fail together, so both redial at the same moment, 30 s later, and each writes its hello and
//! key over the connection it dialled. About one run in nine both streams came back `connection
//! lost`: each member then held its own session, counted its hello delivered, and sent every
//! later key without one, and the other refused each with "the key did not open under the session
//! it holds" — for good (seen in the daemons' own record of the reds). The fix counts a hello as
//! delivered only once the peer has taken a key sealed under its session, never once it is
//! written, so every key until then carries the hello again and the lower fingerprint's rule
//! settles the pair.
//!
//! The second test forces that interleaving on every run: `VOX_TEST_LOSE_HELLOS=1` (a test-only
//! knob, inert when unset) makes bob and carol each lose the first hello they receive, unread,
//! as a stream lost with its connection is. It asserts both daemons said they lost one (else
//! CANNOT MEASURE), and that the two still come to read each other. With a hello counted as
//! delivered once written again, it is red on every run: each keeps its own session and neither
//! reads the other.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use relay::{Anchor, Split};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "room passphrase";
/// How long the relay is held frozen while both members open their sessions.
const FREEZE: Duration = Duration::from_secs(4);
/// The test-only knob that makes a daemon lose the first N hellos it receives, and what it says
/// then.
const LOSE_HELLOS: &str = "VOX_TEST_LOSE_HELLOS";
/// How many of the winner's hellos the losing member loses in the backoff case.
const LOSER_LOSES: usize = 4;
/// The losing member's post is read by the winner within this of the relay's release.
const BOUND: Duration = Duration::from_secs(8);
const LOST_SAID: &str = "VOX_TEST_LOSE_HELLOS: an inbound hello was lost";

fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(text.as_bytes()).expect("write");
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn reads(dir: &std::path::Path, room: &str, text: &str) -> bool {
    vox(dir, &["room", "read", room], None).1.contains(text)
}

fn until(what: &str, secs: u64, ok: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("[proof] {what}: not within {secs} s");
    false
}

/// A daemon, killed by its own PID however the test ends, its output kept.
struct Daemon(Child, Arc<Mutex<String>>);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn daemon(dir: &std::path::Path, listen: &str, anchor: &str, lose_hellos: usize) -> Daemon {
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", listen, "--anchor", anchor])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .env_remove(LOSE_HELLOS);
    if lose_hellos > 0 {
        cmd.env(LOSE_HELLOS, lose_hellos.to_string());
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn a daemon");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(format!("{IDPASS}\n").as_bytes()).unwrap();
    drop(pipe);
    let said = Arc::new(Mutex::new(String::new()));
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let sink = Arc::clone(&said);
        let mut stream = stream;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink
                        .lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }
    let d = Daemon(child, said);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !d.1.lock().unwrap().contains("control socket") {
        assert!(
            Instant::now() < deadline,
            "a daemon never served its socket:\n{}",
            d.1.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "kill {sig} {pid}");
}

#[test]
#[ignore = "three daemons and a relay anchor with production Argon2id; CI runs it in release"]
fn two_members_who_open_sessions_at_once_converge_and_read_each_other() {
    race(Lose::None);
}

#[test]
#[ignore = "three daemons and a relay anchor with production Argon2id; CI runs it in release"]
fn two_members_whose_hellos_are_both_lost_still_converge_and_read_each_other() {
    race(Lose::FirstAtBoth);
}

/// **Simultaneous trust does not stall on a doubling backoff** (V210-80, #271).
///
/// The member whose session loses the race has its key refused ("its hello was not accepted")
/// until it adopts the winner's session, which arrives with the winner's next hello. That refusal
/// set the key backoff, 2 s and doubling, and the backoff still held after the adoption. So when a
/// winner's hello was lost after it was written (a connection retired by a tie-break, seen through
/// the shipped binary, 7.56 s), the loser's retries waited 2, then 4, then 8 s.
///
/// **Staging, forced on every run.** The same race as above, and the losing member (the higher
/// fingerprint, since both ends keep the session the lower one opened) loses the first
/// [`LOSER_LOSES`] hellos it receives (`VOX_TEST_LOSE_HELLOS`, a test-only knob, inert unset). The
/// run is `CANNOT MEASURE` unless it said it lost exactly that many and nothing else lost any.
///
/// **Asserted, as the members see it:** the winner reads a post of the loser's within [`BOUND`] of
/// the relay's release. The loser's refusals are printed with when each was seen.
///
/// **Mutation that must turn it red:** the key backoff as before V210-80, doubling on every
/// refusal and kept after the loser adopts the winner's session.
#[test]
#[ignore = "three daemons and a relay anchor with production Argon2id; CI runs it in release"]
fn a_member_whose_session_lost_the_race_is_read_promptly_after_lost_hellos() {
    race(Lose::WinnersAtLoser);
}

/// Which hellos the race loses (V210-89, V210-80).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Lose {
    None,
    /// bob and carol each lose the first hello they receive.
    FirstAtBoth,
    /// The member whose session loses loses the first [`LOSER_LOSES`] hellos it receives.
    WinnersAtLoser,
}

/// A fingerprint as `vox id` prints it (unpadded lowercase base32) decoded to its 5-bit digits,
/// which order the same way as the digest's bytes do.
fn digits(fp: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    fp.bytes()
        .map(|c| {
            ALPHABET
                .iter()
                .position(|&a| a == c)
                .unwrap_or_else(|| panic!("CANNOT MEASURE: `vox id` printed {fp:?}, not base32"))
                as u8
        })
        .collect()
}

/// The race, losing the hellos `lose` names.
fn race(lose: Lose) {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs: Vec<std::path::PathBuf> = ["alice", "bob", "carol"]
        .iter()
        .map(|n| tmp.path().join(n))
        .collect();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (alice_dir, bob_dir, carol_dir) = (&dirs[0], &dirs[1], &dirs[2]);
    let anchor = Anchor::start(&tmp.path().join("anchor"));
    let mut fps = Vec::new();
    for d in &dirs {
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    // alice and bob on IPv4, carol on IPv6: bob and carol reach each other only through
    // the anchor's relay.
    // Both ends keep the session the lower fingerprint opened, so the higher one's loses.
    let bob_loses = digits(&fps[1]) > digits(&fps[2]);
    let (bob_knob, carol_knob) = match lose {
        Lose::None => (0, 0),
        Lose::FirstAtBoth => (1, 1),
        Lose::WinnersAtLoser if bob_loses => (LOSER_LOSES, 0),
        Lose::WinnersAtLoser => (0, LOSER_LOSES),
    };
    let _alice = daemon(alice_dir, "127.0.0.1:0", &anchor.v4_spec, 0);
    let bob = daemon(bob_dir, "127.0.0.1:0", &anchor.v4_spec, bob_knob);
    let carol_spec = Split::Families.guest_spec(&anchor).to_owned();
    let carol = daemon(
        carol_dir,
        Split::Families.guest_listen(),
        &carol_spec,
        carol_knob,
    );

    // alice's room; alice and each joiner trust each other. bob and carol do NOT, yet.
    for (i, name) in [(1usize, "bob"), (2, "carol")] {
        let (ok, _, err) = vox(alice_dir, &["trust", "add", &fps[i], "--name", name], None);
        assert!(ok, "alice trusts {name}: {err}");
        let (ok, _, err) = vox(
            &dirs[i],
            &["trust", "add", &fps[0], "--name", "alice"],
            None,
        );
        assert!(ok, "{name} trusts alice: {err}");
    }
    let (ok, _, err) = vox(
        alice_dir,
        &["room", "create", "--name", "race"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "room create: {err}");
    let listed = vox(alice_dir, &["room", "list"], None).1;
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("a room id in `room list`")
        .to_owned();
    let (ok, link, err) = vox(alice_dir, &["room", "invite", &room], None);
    assert!(ok, "invite: {err}");
    for d in [bob_dir, carol_dir] {
        let (ok, _, err) = vox(
            d,
            &["room", "join", link.trim(), "--name", "race"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "CANNOT MEASURE: a join failed: {err}");
    }

    // ---- precondition: bob and carol cannot read each other yet ----
    let (ok, _, _) = vox(carol_dir, &["room", "post", &room, "CAROL-BEFORE"], None);
    assert!(ok);
    assert!(
        until("alice reads carol", 60, || reads(
            alice_dir,
            &room,
            "CAROL-BEFORE"
        )),
        "CANNOT MEASURE: carol's post never reached alice"
    );
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !reads(bob_dir, &room, "CAROL-BEFORE"),
        "CANNOT MEASURE: bob already reads carol before either trusts the other, so this \
         run's keys did not come from the exchange it means to race"
    );

    // ---- the race: both open their sessions while the relay between them is frozen ----
    let anchor_pid = anchor.proc.child.id();
    signal(anchor_pid, "-STOP");
    let frozen = Instant::now();
    let (b, c) = std::thread::scope(|s| {
        let b = s.spawn(|| vox(bob_dir, &["trust", "add", &fps[2], "--name", "carol"], None));
        let c = s.spawn(|| vox(carol_dir, &["trust", "add", &fps[1], "--name", "bob"], None));
        (b.join().unwrap(), c.join().unwrap())
    });
    assert!(b.0, "bob trusts carol: {}", b.2);
    assert!(c.0, "carol trusts bob: {}", c.2);
    std::thread::sleep(FREEZE.saturating_sub(frozen.elapsed()));
    signal(anchor_pid, "-CONT");
    let released = Instant::now();
    eprintln!(
        "[proof] relay frozen {:?} while both trusted",
        frozen.elapsed()
    );

    // ---- they converge and read each other ----
    // **Two cures hold this, so this proof cannot see either regress alone** (V210-89, V210-71).
    // A hello counts as delivered only once a key sealed under its session is taken (#281); and a
    // key refused as not opening under the session the peer holds marks that session dead, so the
    // retry offers a fresh hello (#262, finding A). With both in, counting a hello on write stays
    // green here (A heals the pair), and so does removing A (the hello rule does). Whoever removes
    // either must know the other is then this race's only guard.
    // Each posts a fresh probe every round until the other reads one of them.
    let deadline = Instant::now() + Duration::from_secs(90);
    let (mut bob_reads_carol, mut carol_reads_bob) = (false, false);
    let (mut bob_read_at, mut carol_read_at) = (None, None);
    let refused = |d: &Daemon| d.1.lock().unwrap().matches("did not take our key").count();
    let mut refusals_seen: Vec<(Duration, &str)> = Vec::new();
    let mut n = 0;
    while !(bob_reads_carol && carol_reads_bob) && Instant::now() < deadline {
        let (ok, _, _) = vox(
            bob_dir,
            &["room", "post", &room, &format!("BOB-PROBE-{n:02}")],
            None,
        );
        assert!(ok);
        let (ok, _, _) = vox(
            carol_dir,
            &["room", "post", &room, &format!("CAROL-PROBE-{n:02}")],
            None,
        );
        assert!(ok);
        std::thread::sleep(Duration::from_millis(500));
        if !carol_reads_bob && reads(carol_dir, &room, "BOB-PROBE-") {
            carol_reads_bob = true;
            carol_read_at = Some(released.elapsed());
        }
        if !bob_reads_carol && reads(bob_dir, &room, "CAROL-PROBE-") {
            bob_reads_carol = true;
            bob_read_at = Some(released.elapsed());
        }
        for (who, d) in [("bob", &bob), ("carol", &carol)] {
            let seen = refusals_seen.iter().filter(|(_, w)| *w == who).count();
            for _ in seen..refused(d) {
                refusals_seen.push((released.elapsed(), who));
            }
        }
        n += 1;
    }
    let lost = |d: &Daemon| d.1.lock().unwrap().matches(LOST_SAID).count();
    let (bob_lost, carol_lost) = (lost(&bob), lost(&carol));
    eprintln!(
        "[proof] release={} lose={lose:?}: after the race ({n} probe rounds, watched {:.1?} of \
         90s): bob reads carol at {bob_read_at:?}, carol reads bob at {carol_read_at:?} after the \
         relay's release; hellos lost: bob {bob_lost}, carol {carol_lost}; bob's session loses: \
         {bob_loses}",
        !cfg!(debug_assertions),
        released.elapsed()
    );
    for (at, who) in &refusals_seen {
        eprintln!("[proof] {who}'s key refused, seen at {at:?} after the release");
    }
    if lose == Lose::WinnersAtLoser {
        assert!(
            (bob_lost, carol_lost) == (bob_knob, carol_knob),
            "CANNOT MEASURE: the knob did not lose {LOSER_LOSES} of the winner's hellos at the \
             loser and none at the winner (bob lost {bob_lost} of {bob_knob}, carol {carol_lost} \
             of {carol_knob}), so this run did not force the case"
        );
    } else if lose == Lose::FirstAtBoth {
        assert!(
            bob_lost == 1 && carol_lost == 1,
            "CANNOT MEASURE: the knob did not lose one hello at each end (bob {bob_lost}, carol \
             {carol_lost}), so this run did not force the split"
        );
    } else {
        assert_eq!(
            (bob_lost, carol_lost),
            (0, 0),
            "a daemon lost a hello with {LOSE_HELLOS} unset"
        );
    }
    // A red names its mechanism from the daemons' own record: every key the other end did not
    // take, and why.
    let record = |d: &Daemon| {
        let said = d.1.lock().unwrap();
        let lines: Vec<&str> = said
            .lines()
            .filter(|l| l.contains("did not take our key") || l.contains(LOST_SAID))
            .collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    };
    if lose == Lose::WinnersAtLoser {
        let (reading, loser_read) = if bob_loses {
            (
                "carol reads bob, whose session lost the race,",
                carol_read_at,
            )
        } else {
            ("bob reads carol, whose session lost the race,", bob_read_at)
        };
        assert!(
            loser_read.is_some_and(|t| t < BOUND),
            "PRODUCT: {reading} at {loser_read:?} after the \
             release, over {BOUND:?}: a key refused in the race waited out its backoff\n--- bob's \
             daemon:\n{}\n--- carol's daemon:\n{}",
            record(&bob),
            record(&carol)
        );
    }
    assert!(
        bob_reads_carol && carol_reads_bob,
        "PRODUCT: two members who opened their sessions at once did not converge: bob reads carol = \
         {bob_reads_carol}, carol reads bob = {carol_reads_bob}\n--- bob's daemon:\n{}\n--- \
         carol's daemon:\n{}",
        record(&bob),
        record(&carol)
    );
}
