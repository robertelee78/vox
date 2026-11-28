//! ADR-023 R14 / PRD-001 R14, design-4 R6 — **an author keeps a superseded generation of its
//! sender key only while a member still entitled to it has not acknowledged it**, driven through
//! the **shipped `vox` binary**. (Formerly `history_grant_proof`; its `--history full` arm is gone
//! with the option, by the owner's ruling of 2026-11-27: nobody is given older history.)
//!
//! What runs: alice's room, with bob, carol and dave. Bob and dave trust alice and she trusts
//! all three. Carol does not trust alice, so she never takes alice's key and is owed it.
//!
//! - Alice posts under generation 0 and bob reads it; then bob's node stops.
//! - **Stage 1, two rotations back to back.** Alice's re-grant to bob is held
//!   (`VOX_TEST_HOLD_REGRANT_FILE` names bob on alice's node): every rotation's own Presence
//!   resets her grants until they are issued again, and none is issued to bob between these
//!   two. Alice stops trusting dave, which rotates her key (generation 1), and posts; carol
//!   leaves the room (`vox room leave`); once a re-grant to bob was held, alice trusts dave again,
//!   posts, stops trusting him again (generation 2) and posts. Then the re-grant goes.
//! - **Stage 2, a rotation while a delivery is on its way.** Bob's node starts again. The keys he
//!   is owed go to him directly, and are held on their way (`VOX_TEST_HOLD_PAIRWISE_KEY_FILE`
//!   names bob on alice's node) while alice trusts and stops trusting dave twice more
//!   (generations 3 and 4), posting under each; then the keys go.
//! - **Stage 3, a package settles nothing.** Bob's node stops; alice rotates twice more
//!   (generations 5 and 6) and her keys for bob go into the room's log as packages; dave relays
//!   the log. Alice's node stops and bob's starts: he reads those posts from the packages. Bob's
//!   node stops, alice's starts, then bob's.
//! - **Stage 4, an own-history recovery that jumps the generation.** Alice's data directory is
//!   copied with her daemon stopped; she starts and rotates twice more (bob, online, reads it);
//!   both stop and the copy is put back. Alice starts from it with her re-grant to bob held: she
//!   is behind her own history, recovers it from dave, and her recovery mints a generation
//!   above every one her feed shows (not one above the live one of the copy). She posts under
//!   it and rotates once more (she stops trusting dave), and posts. The re-grant goes once her
//!   origin prune has decided with that last generation minted. Bob's node starts.
//!
//! **PRODUCT:** bob, trusted before all of it, reads every post written after his trust: those
//! of the generations minted while his grant read false (stage 1), those of the generations
//! minted while his keys were on their way (stage 2), those whose keys reached him only as
//! packages while alice was stopped (stage 3), and those of the generation her recovery minted
//! while he was offline (stage 4). Alice's `vox status --json` reports **one** generation held
//! (`key_generations`) once bob has acknowledged his keys, and more while he has not: after
//! stage 3 she still holds the retired generation until they are online together. Carol, who
//! left, pins nothing.
//!
//! Mutations (red), each on its own assertion: `VOX_TEST_FWD_MUTANT=rotation-readers` (a
//! rotation owes nothing to a member whose grant reads false, `rotation_debt`) → bob never reads
//! p1; `VOX_TEST_FWD_MUTANT=settle-whole` (an answer settles the member's whole set,
//! `prepare_pending_consent_delivery`) → bob never reads p3; `VOX_TEST_FWD_MUTANT=departed-pins`
//! (a departed member's set pins origins, `origins_needed`) → "alice still holds 3 generations".
//! Stage 4 has no switch: with the defect it guards (a recovery's debt owing one above the
//! copy's live generation instead of the one it mints), alice's prune deletes the recovered
//! generation and bob never reads p9 1.

#![cfg(unix)]

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "support/typed.rs"]
mod typed;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: vox stdin")
            .write_all(text.as_bytes())
            .expect("APPARATUS: write vox stdin");
        drop(child.stdin.take());
    }
    // Bounded: a node that stops answering must fail this proof by name, not hang it.
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().expect("APPARATUS: try_wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "PRODUCT: `vox {}` got no answer in 120 s — the node stopped answering",
                args.join(" ")
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn daemon(dir: &Path, tag: &str) -> Daemon {
    daemon_with(dir, tag, None)
}

/// [`daemon`], holding its direct room-key writes to the peer named in `holds.0`, and its
/// consents to the peer named in `holds.1`, while those files exist.
fn daemon_with(dir: &Path, tag: &str, holds: Option<(&Path, &Path)>) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out")))
        .expect("APPARATUS: daemon stdout file");
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: daemon stderr file");
    let mut cmd = Command::new(VOX);
    // The run's mutant selector reaches the daemon only by name: a proof process keeps no
    // `VOX_TEST_*` of the shell that runs it (`temp_home.rs`).
    if let Some(mutant) = std::env::var_os("VOX_MUTANT_FWD") {
        cmd.env("VOX_TEST_FWD_MUTANT", mutant);
    }
    if let Some((keys, regrant)) = holds {
        cmd.env("VOX_TEST_HOLD_PAIRWISE_KEY_FILE", keys);
        cmd.env("VOX_TEST_HOLD_REGRANT_FILE", regrant);
    }
    let mut child = cmd
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let mut pipe = child.stdin.take().expect("APPARATUS: daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes())
        .expect("APPARATUS: write daemon stdin");
    drop(pipe);
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if vox(dir, &["room", "list"], None).0 {
            return d;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): {tag}'s daemon never answered: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn identity(tmp: &Path, name: &str) -> (PathBuf, String) {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: profile directory");
    let (ok, out, err) = vox(&dir, &["id"], None);
    assert!(ok, "PRODUCT (staging): vox id {name}: {err}");
    (dir, out.trim().to_owned())
}

/// The texts `vox room read` returns.
fn read(dir: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "PRODUCT: vox room read: {err}");
    out.lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

fn count(texts: &[String], prefix: &str) -> usize {
    texts.iter().filter(|t| t.starts_with(prefix)).count()
}

/// Read `room` on `dir` until `done`, for at most `secs`; the last read either way.
fn read_until(
    dir: &Path,
    room: &str,
    secs: u64,
    done: impl Fn(&[String]) -> bool,
) -> (bool, Vec<String>) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let last = read(dir, room);
        if done(&last) {
            return (true, last);
        }
        if Instant::now() >= deadline {
            return (false, last);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(ok, "PRODUCT (staging): vox room post {text:?}: {err}");
}

fn trust(dir: &Path, fp: &str, name: &str) {
    let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
    assert!(ok, "PRODUCT (staging): vox trust add {name}: {err}");
}

fn untrust(dir: &Path, fp: &str) {
    let (ok, _, err) = vox(dir, &["trust", "remove", fp], None);
    assert!(ok, "PRODUCT (staging): vox trust remove: {err}");
}

/// `key_generations` for the room, from `vox status --json`.
fn generations(dir: &Path) -> Option<u64> {
    let (ok, out, _) = vox(dir, &["status", "--json"], None);
    if !ok {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&out).ok()?;
    v["rooms"][0]["key_generations"].as_u64()
}

/// Poll alice's generations until `want`, for at most `secs`; the last reading either way.
fn until_generations(dir: &Path, want: u64, secs: u64) -> Option<u64> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last = generations(dir);
    while last != Some(want) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        last = generations(dir);
    }
    last
}

fn join(creator: &Path, joiner: &Path, room: &str) {
    let (ok, link, err) = vox(creator, &["room", "link", room], None);
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let (ok, _, err) = vox(
        joiner,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room join: {err}");
}

/// Whether `vox room read` answers for `room` on `dir` within `secs`: a reopened room is
/// prepared before it is published.
fn room_answers(dir: &Path, room: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if vox(dir, &["room", "read", room], None).0 {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The highest generation alice's origin prune has decided with so far (the `test-knobs` line
/// `origin prune of room … keeps generations […] of […]`, said once per new decision).
fn decided_up_to(text: &str) -> Option<u64> {
    text.lines()
        .filter(|line| line.contains("test-knobs: origin prune of room"))
        .filter_map(|line| line.rsplit(" of [").next())
        .flat_map(|held| {
            held.trim_end_matches(']')
                .split(", ")
                .filter_map(|g| g.parse::<u64>().ok())
                .collect::<Vec<_>>()
        })
        .max()
}

/// A stopped member's whole data directory, copied, each directory with its own permissions (a
/// node refuses a management directory that is not private): the backup stage 4 restores from.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make {}: {e}", to.display()));
    let mode = std::fs::metadata(from)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot stat {}: {e}", from.display()))
        .permissions();
    std::fs::set_permissions(to, mode)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot set the mode of {}: {e}", to.display()));
    for e in std::fs::read_dir(from)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot list {}: {e}", from.display()))
    {
        let e = e.expect("APPARATUS: cannot read a stopped profile's entry");
        let target = to.join(e.file_name());
        let kind = e
            .file_type()
            .expect("APPARATUS: cannot read a stopped profile entry's type");
        if kind.is_dir() {
            copy_dir(&e.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(e.path(), &target).unwrap_or_else(|err| {
                panic!("APPARATUS: cannot copy {}: {err}", e.path().display())
            });
        }
        // A socket of the stopped process is not part of the profile.
    }
}

#[test]
#[ignore = "four real vox daemons and production Argon2id; CI runs it in release"]
fn an_author_keeps_a_key_only_while_a_member_still_needs_it() {
    test_knobs::require(&[
        "VOX_TEST_HOLD_PAIRWISE_KEY_FILE",
        "VOX_TEST_HOLD_REGRANT_FILE",
    ]);
    watchdog::arm();
    let mut tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
        tmp.disable_cleanup(true);
        println!("[proof] daemon dirs kept under {}", tmp.path().display());
    }
    let tmp = tmp.path();
    let (alice, alice_fp) = identity(tmp, "alice");
    let (bob, bob_fp) = identity(tmp, "bob");
    let (carol, carol_fp) = identity(tmp, "carol");
    let (dave, dave_fp) = identity(tmp, "dave");
    let hold = tmp.join("hold-keys-to-bob");
    let regrant = tmp.join("hold-regrant-to-bob");
    let a = daemon_with(&alice, "alice", Some((&hold, &regrant)));
    let b = daemon(&bob, "bob");
    let _c = daemon(&carol, "carol");
    let _d = daemon(&dave, "dave");

    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let (_, listed, _) = vox(&alice, &["room", "list"], None);
    let room = listed
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): `vox room list` shows no room")
        .to_owned();
    for who in [&bob, &carol, &dave] {
        join(&alice, who, &room);
    }
    // Trust runs one way: bob and dave take alice's key once they trust her; carol never does,
    // so whatever alice owes carol stays owed.
    trust(&bob, &alice_fp, "alice");
    trust(&dave, &alice_fp, "alice");
    trust(&alice, &bob_fp, "bob");
    trust(&alice, &carol_fp, "carol");
    trust(&alice, &dave_fp, "dave");

    post(&alice, &room, "p0 1");
    for (who, name) in [(&bob, "bob"), (&dave, "dave")] {
        let (ok, t) = read_until(who, &room, 90, |t| count(t, "p0 1") == 1);
        assert!(
            ok,
            "PRODUCT (staging): {name}, trusted, never read alice's first post in 90 s: {t:?}"
        );
    }
    // Bob's node stops: he stays a member, entitled, and is owed every later generation.
    drop(b);

    // Stage 1: no consent goes to bob from here until both rotations are done.
    std::fs::write(&regrant, &bob_fp).expect("APPARATUS: write the re-grant hold file");
    // Rotation 1: dave held alice's generation 0.
    untrust(&alice, &dave_fp);
    post(&alice, &room, "p1 1");
    // Carol leaves after it: she is owed alice's key from generation 0 and never took it.
    let (ok, _, err) = vox(&carol, &["room", "leave", &room], None);
    assert!(
        ok,
        "PRODUCT (staging): carol's `vox room leave` failed: {err}"
    );
    let short = &carol_fp[..carol_fp.len().min(16)];
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (ok, roster, _) = vox(&alice, &["room", "roster", &room], None);
        if ok && !roster.contains(short) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): alice's roster still lists carol 90 s after she left: {roster}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Rotation 2: dave, trusted again, takes the live generation; removing him again rotates.
    trust(&alice, &dave_fp, "dave");
    post(&alice, &room, "p1 2");
    let (ok, t) = read_until(&dave, &room, 90, |t| count(t, "p1 2") == 1);
    assert!(
        ok,
        "PRODUCT (staging): dave, trusted again, never read alice's next post in 90 s: {t:?}"
    );
    // The watchdog owns a re-grant that is never wanted.
    while !regrant.with_extension("engaged").is_file() {
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("[proof] alice's re-grant to bob is held after rotation 1");
    untrust(&alice, &dave_fp);
    post(&alice, &room, "p2 1");
    // The re-grant goes only once alice's origin prune has decided with generation 2 minted
    // (said once per new decision): what the two rotations left owed is what it keeps. The
    // watchdog owns a decision that is never made.
    let decided = |text: &str| {
        text.lines().any(|line| {
            line.contains("test-knobs: origin prune of room")
                && line
                    .rsplit(" of [")
                    .next()
                    .is_some_and(|held| held.trim_end_matches(']').split(", ").any(|g| g == "2"))
        })
    };
    while !decided(&std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default()) {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::fs::remove_file(&regrant).expect("APPARATUS: release the re-grant hold");
    let offline = generations(&alice);
    println!("[proof] with bob offline and carol gone, alice holds {offline:?} generation(s)");

    // Stage 2: bob comes back. Alice's keys for him are held on their way while she rotates
    // twice more.
    std::fs::write(&hold, &bob_fp).expect("APPARATUS: write the key hold file");
    let b = daemon(&bob, "bob-back");
    // The watchdog owns a delivery that never starts.
    while !hold.with_extension("engaged").is_file() {
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("[proof] alice's history keys for bob are held on their way");
    for generation in [3, 4] {
        trust(&alice, &dave_fp, "dave");
        let seen = format!("p{} 2", generation - 1);
        post(&alice, &room, &seen);
        let (ok, t) = read_until(&dave, &room, 90, |t| count(t, &seen) == 1);
        assert!(
            ok,
            "PRODUCT (staging): dave, trusted again, never read alice's {seen:?} in 90 s: {t:?}"
        );
        untrust(&alice, &dave_fp);
        post(&alice, &room, &format!("p{generation} 1"));
    }
    std::fs::remove_file(&hold).expect("APPARATUS: release the key hold");
    let (ok, t) = read_until(&bob, &room, 120, |t| {
        count(t, "p0 1") == 1 && count(t, "p1 ") == 2 && count(t, "p2 ") == 2
    });
    println!("[proof] bob, back, shows {t:?}");
    assert!(
        ok,
        "PRODUCT: bob, trusted before and offline across two rotations made back to back while \
         his grant read false, never read post p1 1, p1 2, p2 1 or p2 2 in 120 s: {t:?}"
    );
    let (ok, t) = read_until(&bob, &room, 120, |t| {
        count(t, "p3 ") == 2 && count(t, "p4 1") == 1
    });
    println!("[proof] bob, back, shows {t:?}");
    assert!(
        ok,
        "PRODUCT: bob, his keys held on their way across two rotations, never read post p3 1, \
         p3 2 or p4 1 in 120 s: {t:?}"
    );
    let held = until_generations(&alice, 1, 60);
    println!("[proof] once bob took his keys, alice holds {held:?} generation(s)");
    assert_eq!(
        held,
        Some(1),
        "PRODUCT: alice still holds {held:?} generations 60 s after bob took every key he was \
         owed: carol, who left, must pin nothing (alice still holds 3 generations when she does)"
    );

    // Stage 3: a package settles nothing. Bob is away while alice rotates twice more; her keys
    // for him go into the room's log, and dave, trusted at the end, holds that log.
    drop(b);
    for generation in [5, 6] {
        trust(&alice, &dave_fp, "dave");
        let seen = format!("p{} 2", generation - 1);
        post(&alice, &room, &seen);
        let (ok, t) = read_until(&dave, &room, 90, |t| count(t, &seen) == 1);
        assert!(
            ok,
            "PRODUCT (staging): dave, trusted again, never read alice's {seen:?} in 90 s: {t:?}"
        );
        untrust(&alice, &dave_fp);
        post(&alice, &room, &format!("p{generation} 1"));
    }
    // The watchdog owns a log route that never ends.
    let in_log = format!("every key owed to {bob_fp} is in the log");
    let posted = |text: &str| {
        text.lines().any(|line| {
            line.contains(&in_log)
                && line.rsplit('{').next().is_some_and(|set| {
                    let set: Vec<&str> = set.trim_end_matches('}').split(", ").collect();
                    set.contains(&"5") && set.contains(&"6")
                })
        })
    };
    while !posted(&std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default()) {
        std::thread::sleep(Duration::from_millis(100));
    }
    trust(&alice, &dave_fp, "dave");
    post(&alice, &room, "p6 2");
    let (ok, t) = read_until(&dave, &room, 90, |t| count(t, "p6 2") == 1);
    assert!(
        ok,
        "PRODUCT (staging): dave, trusted again, never read alice's \"p6 2\" in 90 s: {t:?}"
    );
    println!(
        "[proof] bob away, his keys in the log as packages: alice holds {:?}",
        generations(&alice)
    );
    drop(a);
    let b = daemon(&bob, "bob-packages");
    let (ok, t) = read_until(&bob, &room, 120, |t| {
        count(t, "p5 ") == 2 && count(t, "p6 ") == 2
    });
    println!("[proof] bob, back while alice is stopped, shows {t:?}");
    assert!(
        ok,
        "PRODUCT: bob, back while alice is stopped, never read post p5 1, p5 2, p6 1 or p6 2 \
         from the key packages in the room's log in 120 s: {t:?}"
    );
    drop(b);
    let a = daemon(&alice, "alice-again");
    // Its room is read from the store after the daemon first answers: a reading, not a number.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut unsettled = generations(&alice);
    while unsettled.is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        unsettled = generations(&alice);
    }
    println!("[proof] alice, started again before bob is back, holds {unsettled:?}");
    assert!(
        unsettled.is_some_and(|held| held > 1),
        "PRODUCT: alice, started again, holds {unsettled:?} generation(s) before bob, who took \
         his keys only from the log, has been online with her: a package settled his debt"
    );
    let b = daemon(&bob, "bob-again");
    let held = until_generations(&alice, 1, 120);
    println!("[proof] once bob and alice were online together, alice holds {held:?}");
    assert_eq!(
        held,
        Some(1),
        "PRODUCT: alice still holds {held:?} generations 120 s after bob, who took his keys from \
         the log, came online with her: his direct answers never settled them"
    );

    // Stage 4: a copy of alice's data directory, taken with her daemon stopped.
    drop(a);
    let backup = tmp.join("alice-backup");
    copy_dir(&alice, &backup);
    println!("[proof] alice's data directory copied with her daemon stopped");
    // She goes on from the original: two more rotations, read by bob and dave.
    let a = daemon(&alice, "alice-gap");
    assert!(
        room_answers(&alice, &room, 120),
        "PRODUCT (staging): alice's reopened room did not answer `vox room read` in 120 s"
    );
    for generation in [7, 8] {
        untrust(&alice, &dave_fp);
        post(&alice, &room, &format!("p{generation} 1"));
        trust(&alice, &dave_fp, "dave");
        let seen = format!("p{generation} 2");
        post(&alice, &room, &seen);
        let (ok, t) = read_until(&dave, &room, 90, |t| count(t, &seen) == 1);
        assert!(
            ok,
            "PRODUCT (staging): dave, trusted again, never read alice's {seen:?} in 90 s: {t:?}"
        );
    }
    let (ok, t) = read_until(&bob, &room, 120, |t| {
        count(t, "p7 ") == 2 && count(t, "p8 ") == 2
    });
    assert!(
        ok,
        "PRODUCT (staging): bob, online, never read alice's p7 1, p7 2, p8 1 and p8 2 in 120 s: \
         {t:?}"
    );
    // Bob stops; alice is put back to the copy and started from it, her re-grant to bob held.
    drop(b);
    drop(a);
    std::fs::remove_dir_all(&alice)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot remove {}: {e}", alice.display()));
    copy_dir(&backup, &alice);
    std::fs::write(&regrant, &bob_fp).expect("APPARATUS: write the re-grant hold file");
    let tag = "alice-restored";
    let a = daemon_with(&alice, tag, Some((&hold, &regrant)));
    let said =
        || std::fs::read_to_string(alice.join(format!("daemon-{tag}.err"))).unwrap_or_default();
    // The watchdog owns a recovery that never completes: dave holds her whole feed.
    while !said().contains("this node recovered its own history") {
        std::thread::sleep(Duration::from_millis(250));
    }
    // The restore took: she reads what the copy held, and not her posts after it, whose
    // generations only the directory put aside held the keys of.
    let hers = read(&alice, &room);
    assert!(
        count(&hers, "p6 2") == 1 && count(&hers, "p7 ") == 0 && count(&hers, "p8 ") == 0,
        "APPARATUS: the restore did not take: alice, recovered from the copy, reads {hers:?}"
    );
    println!("[proof] alice, started from the copy, recovered her own history");
    post(&alice, &room, "p9 1");
    // The watchdog owns a prune that never decides with the recovered generation.
    let recovered = loop {
        if let Some(generation) = decided_up_to(&said()) {
            break generation;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // One more rotation retires the generation her recovery minted.
    untrust(&alice, &dave_fp);
    post(&alice, &room, "p10 1");
    while decided_up_to(&said()).is_none_or(|generation| generation <= recovered) {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::fs::remove_file(&regrant).expect("APPARATUS: release the re-grant hold");
    println!(
        "[proof] alice's recovery minted generation {recovered} with bob offline; she rotated past it"
    );
    let _b = daemon(&bob, "bob-restored");
    let (ok, t) = read_until(&bob, &room, 120, |t| {
        count(t, "p9 1") == 1 && count(t, "p10 1") == 1
    });
    println!("[proof] bob, back after alice's recovery, shows {t:?}");
    assert!(
        ok,
        "PRODUCT: bob, trusted before and offline across alice's own-history recovery, which \
         jumped her generation, and a rotation after it, never read post p9 1 or p10 1 in 120 s: \
         {t:?}"
    );
    drop(a);
}
