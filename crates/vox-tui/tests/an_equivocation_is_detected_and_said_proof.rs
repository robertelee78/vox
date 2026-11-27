//! V210-63 (#252) — **a member who signs two different messages at one place is caught, said, and
//! held back, by every member, and a restart does not forget it**, through the shipped binary.
//!
//! **The defect.** A sync asked a peer only for what came after its own head, and compared heads
//! only when both sides' histories of an author were the same length. When one member held an
//! author's message X at position p and had gone on past it, and another held a different X′ at p,
//! the shorter one was sent the longer one's next entry, refused it as a broken link
//! (`Rejected::Feed`), which proves nothing, and the longer one asked for nothing at all. Nobody
//! compared position p: the member holding X′ stayed stuck behind it, and nothing was said
//! anywhere. And a fork that *was* detected was never said to anyone, and was forgotten on a
//! restart, since the DAG is rebuilt from stored entries that hold one side only.
//!
//! **The scene** — real `vox` processes only. An anchor and five members (`vox daemon`s, all
//! trusting each other) share a room: alice, bob, carol, and eve and frank, whose profiles are
//! then **copied** — two processes of one identity each, the one way a real node signs two
//! messages at one place.
//! 1. Everyone reads everyone's hello.
//! 2. eve and frank stop, and their profiles are copied (eve′, frank′).
//! 3. carol is frozen. eve posts three messages and frank one; bob reads them.
//! 4. eve and frank stop; bob is frozen. eve′ posts one message and frank′ one: each at the
//!    position its original's first went to. eve's fork is **below the head** (3 against 1), frank's
//!    **at the head** (1 against 1).
//! 5. carol and bob are continued; eve′ and frank′ keep running.
//!
//! **What must hold, on bob and on carol**, within [`DETECT`]:
//! - `vox status --json` lists eve's and frank's equivocation in this room, each with a position;
//! - `vox room read` says it, one `! … signed two different messages at the same place …` line per
//!   author, by the short id its rows use;
//! - **held back**: once alice (who forked nothing) lists both equivocations too, eve's original
//!   posts again, then alice posts; bob reads alice's post, and neither bob nor carol reads eve's;
//! - **gone from the split** (rule F3, ledger 73; assertion changed by ruling: before it, the
//!   staging required alice still to show eve's and frank's first-side posts): alice, bob and
//!   carol, each holding both proofs, show none of eve's or frank's posts from the place each
//!   split (all of them when the shared start is not proved), while alice's, bob's and carol's
//!   own posts stay;
//! - **kept**: with **every other node stopped** — so nobody could show either fork again
//!   (V210-66) — carol's daemon is restarted, and `vox status --json` still lists both;
//!   (An anchor that is not a member keeps no copy of the room, so it has nothing to hold anyone
//!   back in: ADR-023 decision 6, PRD-001 R34. The case that restarted it and read its notice
//!   is gone with that copy.)
//! - **in the TUI**: carol's real `vox tui`, in a pty, says both — each on its own line, by the
//!   names carol gave them (V210-66).
//!
//! The "room still moves" witness is a post of alice's, which cites only the first side, the one
//! bob holds. That a post citing a forked author's other branch (bob's or alice's, read by carol,
//! who holds the second side) still reaches a reader waits for ledger 73's fork-parent evidence
//! path, which this change does not build.
//!
//! Mutations: the old `wants_for` (from past our head, no comparison of a shorter peer's head) —
//! eve's fork is never listed; the `room read` notice removed; `keep_forks` doing nothing — the
//! restarted carol lists neither; the TUI drawing only the first — frank is never said;
//! `VOX_MUTANT_FORK=equal-size-only` (MP-9: heads of different sizes are never compared) — eve's
//! fork, below the head, is never listed.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

const SETUP: Duration = Duration::from_secs(120);
/// How long one round of hellos is given before everyone posts the next.
const HELLO_ROUND: Duration = Duration::from_secs(10);
/// How long a member may take to read what the precondition needs.
const REACH: Duration = Duration::from_secs(60);
/// How long both members may take to catch both forks once they are continued.
const DETECT: Duration = Duration::from_secs(90);
/// MP-9 acts: how long a member started after a scene's posts may take to read them. It is never a
/// verdict.
const STAGE: Duration = Duration::from_secs(300);
/// How long a held-back message is watched for, after the control message has arrived.
const HELD: Duration = Duration::from_secs(10);

fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox: {e}"));
    // A vox that exits before reading closes the pipe; its status and what it said are then the
    // verdict, so a failed write is not one.
    let _ = child
        .stdin
        .take()
        .expect("APPARATUS: vox was spawned without a stdin pipe")
        .write_all(stdin.as_bytes());
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot collect vox's output: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn signal(p: &VoxProc, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &p.child.id().to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "APPARATUS: `kill {sig}` of {} failed", p.name);
}

/// Stop a process by its PID with SIGTERM, so it closes its connections, and reap it.
fn stop(mut p: VoxProc) {
    signal(&p, "-TERM");
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if matches!(p.child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Drop kills it by PID.
}

fn daemon(name: &str, data: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    daemon_env(name, data, spec, pass_file, &[])
}

fn daemon_env(
    name: &str,
    data: &Path,
    spec: &str,
    pass_file: &Path,
    env: &[(&str, &str)],
) -> VoxProc {
    daemon_exe(Path::new(VOX), name, data, spec, pass_file, env)
}

/// [`daemon_env`] with the `vox` binary at `exe` (arm (d)'s mutant signer).
fn daemon_exe(
    exe: &Path,
    name: &str,
    data: &Path,
    spec: &str,
    pass_file: &Path,
    env: &[(&str, &str)],
) -> VoxProc {
    let mut p = VoxProc::spawn_exe(
        exe,
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file
                .to_str()
                .expect("APPARATUS: a temp path is not UTF-8"),
        ]),
        env,
    );
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "PRODUCT (staging): {name}'s daemon never answered `vox room list` within {SETUP:?}, so the \
         scene was not staged:\n{}",
        p.transcript()
    );
}

/// A stopped member's whole profile, copied: a second process of the same identity.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("APPARATUS: cannot make a directory");
    // A private directory stays private: the daemon refuses a computer management path another
    // account could read ("must be owned by this account, private").
    std::fs::set_permissions(
        to,
        std::fs::metadata(from)
            .expect("APPARATUS: cannot read a stopped profile directory")
            .permissions(),
    )
    .expect("APPARATUS: cannot keep a copied directory's mode");
    for e in std::fs::read_dir(from).expect("APPARATUS: cannot list a stopped profile") {
        let e = e.expect("APPARATUS: cannot read a stopped profile's entry");
        let target = to.join(e.file_name());
        let kind = e
            .file_type()
            .expect("APPARATUS: cannot read a stopped profile entry's type");
        if kind.is_dir() {
            copy_dir(&e.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(e.path(), &target).expect("APPARATUS: cannot copy a staging file");
        }
        // A socket or a lock of the stopped process is not part of the profile.
    }
}

fn post(data: &Path, room: &str, who: &str, text: &str) {
    let (ok, out, err) = vox_in(data, &["room", "post", room, "-"], text);
    assert!(
        ok,
        "PRODUCT: {who}'s `vox room post` of {text:?} failed: {out}{err}"
    );
}

fn reads(data: &Path, room: &str, text: &str) -> bool {
    vox_once(data, &args(&["room", "read", room]))
        .1
        .contains(text)
}

/// Wait until `data` reads `text`, or `within` passes.
fn wait_reads(data: &Path, room: &str, text: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if reads(data, room, text) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// The equivocations `vox status --json` lists for `room`: `(author, position)`. A status that
/// fails, or is not JSON, is the product's red, never an empty list.
fn listed(data: &Path, room_id: &str) -> Vec<(String, u64)> {
    let (ok, out, err) = vox_once(data, &args(&["status", "--json"]));
    assert!(ok, "PRODUCT: `vox status --json` failed: {out}{err}");
    let v = serde_json::from_str::<serde_json::Value>(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` printed no JSON ({e}): {out}"));
    v["equivocations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["room"].as_str() == Some(room_id))
        .filter_map(|e| Some((e["author"].as_str()?.to_owned(), e["position"].as_u64()?)))
        .collect()
}

fn names(list: &[(String, u64)], fp: &str) -> bool {
    list.iter().any(|(a, p)| a == fp && *p > 0)
}

#[test]
#[ignore = "real vox processes, five members and two copied profiles; CI runs it in release"]
fn an_equivocation_is_caught_said_held_back_and_kept() {
    watchdog::arm();
    // A mutant a run names is in the `vox` under test; the daemons inherit it.
    if std::env::var_os("VOX_MUTANT_FORK").is_some() {
        test_knobs::require(&["VOX_MUTANT_FORK"]);
    }
    let mut tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
        tmp.disable_cleanup(true);
        eprintln!(
            "[proof] retained daemon directory: {}",
            tmp.path().display()
        );
    }
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: cannot make a directory");
        d
    };
    let (anchor_dir, alice_dir, bob_dir, carol_dir, eve_dir, frank_dir) = (
        dir("anchor"),
        dir("alice"),
        dir("bob"),
        dir("carol"),
        dir("eve"),
        dir("frank"),
    );
    let (eve2_dir, frank2_dir) = (tmp.path().join("eve2"), tmp.path().join("frank2"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: cannot write a staging file");

    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id failed: {err}");
        out.trim().to_owned()
    };
    let members = [
        ("alice", &alice_dir),
        ("bob", &bob_dir),
        ("carol", &carol_dir),
        ("eve", &eve_dir),
        ("frank", &frank_dir),
    ];
    let fps: Vec<String> = members.iter().map(|(_, d)| fp(d)).collect();
    let (eve_fp, frank_fp) = (fps[3].clone(), fps[4].clone());
    for (i, (_, d)) in members.iter().enumerate() {
        for (j, (name, _)) in members.iter().enumerate() {
            if i != j {
                let (ok, out, err) = vox_once(d, &args(&["trust", "add", &fps[j], "--name", name]));
                assert!(
                    ok,
                    "PRODUCT (staging): vox trust add {name} failed: {out}{err}"
                );
            }
        }
    }
    let alice = daemon("alice", &alice_dir, &spec, &idpass);
    let mut bob = daemon("bob", &bob_dir, &spec, &idpass);
    let mut carol = daemon("carol", &carol_dir, &spec, &idpass);
    let eve = daemon("eve", &eve_dir, &spec, &idpass);
    let frank = daemon("frank", &frank_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "eq"],
        "room pass",
    );
    assert!(ok, "PRODUCT (staging): vox room create failed: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): vox room list failed: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("eq"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): the new room is not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "link", &room]));
    assert!(ok, "PRODUCT (staging): vox room link failed: {err}");
    for (name, d) in &members[1..] {
        let (ok, out, err) = vox_in(
            d,
            &["room", "join", "--passphrase-file", "-", link.trim()],
            "room pass",
        );
        assert!(ok, "PRODUCT (staging): {name}'s join failed: {out}{err}");
    }
    // The room's full id, as `vox status --json` names it: the room link carries it.
    let room_id = link
        .trim()
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .unwrap_or_else(|| {
            panic!("APPARATUS: the proof cannot read the room id in the room link {link}")
        })
        .to_owned();
    assert!(
        room_id.starts_with(&room),
        "PRODUCT: the room link names another room: {room_id} for {room}"
    );

    // ---- 1. everyone reads everyone's hello ----------------------------------------------------
    let deadline = Instant::now() + SETUP;
    let mut round = 0u32;
    'warm: loop {
        round += 1;
        for (name, d) in members {
            post(d, &room, name, &format!("hello from {name} r{round}"));
        }
        let round_ends = Instant::now() + HELLO_ROUND;
        let mut missing: Vec<String> = Vec::new();
        while Instant::now() < round_ends {
            missing.clear();
            for (reader, d) in members {
                let (_, r, _) = vox_once(d, &args(&["room", "read", &room]));
                for (n, _) in members {
                    if !r.contains(&format!("hello from {n} r{round}")) {
                        missing.push(format!("{reader} cannot read {n}"));
                    }
                }
            }
            if missing.is_empty() {
                eprintln!("[setup] everyone reads everyone's hello of round {round}");
                break 'warm;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): after {SETUP:?} ({round} rounds) the members still do not all read \
             each other: {missing:?}"
        );
    }

    // ---- 2. eve and frank stop; their profiles are copied ------------------------------------
    stop(eve);
    stop(frank);
    copy_dir(&eve_dir, &eve2_dir);
    copy_dir(&frank_dir, &frank2_dir);

    // ---- 3. carol frozen: eve posts three, frank one, and bob reads them ----------------------
    signal(&carol, "-STOP");
    let eve = daemon("eve", &eve_dir, &spec, &idpass);
    let frank = daemon("frank", &frank_dir, &spec, &idpass);
    for i in 1..=3 {
        post(&eve_dir, &room, "eve", &format!("EQ-EVE-A-{i}"));
    }
    post(&frank_dir, &room, "frank", "EQ-FRANK-A-1");
    // Every post of eve's side, not only the last: eve's fork is at her first post's position,
    // where bob's side must be opened (see `staged_reads_all`).
    staged_reads_all(
        &bob_dir,
        &[&eve_dir, &frank_dir],
        &room,
        &["EQ-EVE-A-1", "EQ-EVE-A-2", "EQ-EVE-A-3", "EQ-FRANK-A-1"],
        REACH,
        "bob never read all of eve's and frank's first side, so the first side of the fork is not \
         in place",
    );
    stop(eve);
    stop(frank);

    // ---- 4. every node frozen: the copies post one each, before they can learn of the first side --
    // A copy that could reach anyone would first sync its own identity's messages from them and
    // post after them — a continuation, not a fork. Frozen nodes answer nothing, so each copy signs
    // its message at the position its original's first went to.
    for p in [&anchor, &alice, &bob] {
        signal(p, "-STOP");
    }
    let eve2 = daemon("eve2", &eve2_dir, &spec, &idpass);
    let frank2 = daemon("frank2", &frank2_dir, &spec, &idpass);
    post(&eve2_dir, &room, "eve'", "EQ-EVE-B-1");
    post(&frank2_dir, &room, "frank'", "EQ-FRANK-B-1");
    for (who, d, text) in [
        ("eve'", &eve2_dir, "EQ-EVE-A-1"),
        ("frank'", &frank2_dir, "EQ-FRANK-A-1"),
    ] {
        assert!(
            !reads(d, &room, text),
            "PRODUCT (staging): {who} already reads {text}, so its message continued the first side \
             instead of forking it"
        );
    }

    // ---- 5. everyone continues; both forks must be caught on both members ----------------------
    for p in [&anchor, &alice, &carol, &bob] {
        signal(p, "-CONT");
    }
    let back = Instant::now();
    let mut caught = [false, false];
    let mut last: [Vec<(String, u64)>; 2] = [Vec::new(), Vec::new()];
    while back.elapsed() < DETECT && !caught.iter().all(|c| *c) {
        for (i, d) in [&bob_dir, &carol_dir].into_iter().enumerate() {
            last[i] = listed(d, &room_id);
            caught[i] = names(&last[i], &eve_fp) && names(&last[i], &frank_fp);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!(
        "[proof] {:.1?} after both continued: bob lists {:?}, carol lists {:?}",
        back.elapsed(),
        last[0],
        last[1]
    );
    if !caught.iter().all(|c| *c) {
        // What each actually holds of the two sides, so a red says whether a fork ever met.
        for (who, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
            let (_, r, _) = vox_once(d, &args(&["room", "read", &room]));
            for l in r
                .lines()
                .filter(|l| l.contains("EQ-") || l.starts_with("! "))
            {
                eprintln!("[{who} reads] {l}");
            }
        }
        for (who, p) in [
            ("bob", &mut bob),
            ("carol", &mut carol),
            ("anchor", &mut anchor),
        ] {
            eprintln!("---- {who} said ----\n{}", p.transcript());
        }
    }
    for (i, who) in ["bob", "carol"].into_iter().enumerate() {
        assert!(
            names(&last[i], &eve_fp),
            "PRODUCT: {who} does not list eve's equivocation below the head within {DETECT:?}: {:?}",
            last[i]
        );
        assert!(
            names(&last[i], &frank_fp),
            "PRODUCT: {who} does not list frank's equivocation at the head within {DETECT:?}: {:?}",
            last[i]
        );
    }

    // `vox room read` says it, naming the member as its rows do: by the reader's own name for it,
    // or by 26 characters of its fingerprint when the reader has none (V210-162).
    let short = |f: &str| f.chars().take(26).collect::<String>();
    for (who, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
        let (_, r, _) = vox_once(d, &args(&["room", "read", &room]));
        for (name, f) in [("eve", &eve_fp), ("frank", &frank_fp)] {
            let said = r.lines().any(|l| {
                let Some(rest) = l.strip_prefix("! ") else {
                    return false;
                };
                (rest.starts_with(&format!("{name} ")) || rest.starts_with(&short(f)))
                    && rest.contains("signed two different messages at the same place")
            });
            assert!(
                said,
                "PRODUCT: {who}'s `vox room read` does not say {name} equivocated:\n{r}"
            );
        }
    }

    // ---- held back: eve's original posts again; a post of a member who forked nothing arrives ---
    // alice holds the first side, as bob does. Once she has recorded both forks she takes nothing
    // of eve's later, so her post cites only what bob holds of eve and frank. (Under rule F3 the
    // first side's posts are no longer shown to her once she holds the proofs: that is asserted
    // below, not read here as her holding them.)
    let staged = Instant::now() + STAGE;
    let alice_ready = || {
        let now = listed(&alice_dir, &room_id);
        let ready = names(&now, &eve_fp) && names(&now, &frank_fp);
        (ready, now)
    };
    let (mut ready, mut alice_lists) = alice_ready();
    while !ready && Instant::now() < staged {
        std::thread::sleep(Duration::from_millis(500));
        (ready, alice_lists) = alice_ready();
    }
    assert!(
        ready,
        "PRODUCT (staging): alice does not list both equivocations, so her post could cite what \
         bob cannot hold: she lists {alice_lists:?}"
    );
    stop(eve2);
    stop(frank2);
    let eve = daemon("eve", &eve_dir, &spec, &idpass);
    post(&eve_dir, &room, "eve", "EQ-EVE-AFTER");
    post(&alice_dir, &room, "alice", "EQ-CONTROL");
    assert!(
        wait_reads(&bob_dir, &room, "EQ-CONTROL", REACH),
        "PRODUCT (staging): bob never read alice's control message, so nothing shows the room moves"
    );
    std::thread::sleep(HELD);
    for (who, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
        assert!(
            !reads(d, &room, "EQ-EVE-AFTER"),
            "PRODUCT: {who} read a message eve posted after her equivocation was caught"
        );
    }
    stop(eve);

    // ---- gone from the split (rule F3): every computer holding the proofs shows none of eve's or
    // frank's posts from where each split; everyone else's posts stay ----------------------------
    let split = [
        "EQ-EVE-A-1",
        "EQ-EVE-A-2",
        "EQ-EVE-A-3",
        "EQ-EVE-B-1",
        "EQ-FRANK-A-1",
        "EQ-FRANK-B-1",
    ];
    // What the members who forked nothing posted, which every one of them read before the split.
    let others = [
        format!("hello from alice r{round}"),
        format!("hello from bob r{round}"),
        format!("hello from carol r{round}"),
    ];
    for (who, d) in [
        ("alice", &alice_dir),
        ("bob", &bob_dir),
        ("carol", &carol_dir),
    ] {
        let shown = |text: &str| reads(d, &room, text);
        let until = Instant::now() + DETECT;
        while split.iter().any(|tag| shown(tag)) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(500));
        }
        let left: Vec<&str> = split.iter().copied().filter(|tag| shown(tag)).collect();
        assert!(
            left.is_empty(),
            "PRODUCT: {who}, holding eve's and frank's fork proofs, still shows {left:?} within \
             {DETECT:?}: their posts from the place each split must be gone:\n{}",
            room_read(d, &room)
        );
        let lost: Vec<&String> = others.iter().filter(|text| !shown(text)).collect();
        assert!(
            lost.is_empty(),
            "PRODUCT: {who} no longer shows {lost:?}, posted by members who forked nothing:\n{}",
            room_read(d, &room)
        );
    }

    // ---- kept: every other node stops, so nobody could show either fork again (V210-66) ---------
    // With a live peer holding the other side, a restarted node could meet the fork again and list
    // it without having kept it (verifier-252). Here nobody is left to show it.
    stop(bob);
    stop(alice);
    stop(anchor);
    stop(carol);
    let carol = daemon("carol", &carol_dir, &spec, &idpass);
    // Listed only once the room is open again, so an empty list is the room's, not a room not
    // yet reopened.
    assert!(
        wait_reads(
            &carol_dir,
            &room,
            &format!("hello from bob r{round}"),
            REACH
        ),
        "PRODUCT (staging): carol's restarted daemon never reopened the room"
    );
    let after = listed(&carol_dir, &room_id);
    eprintln!("[proof] carol, restarted alone, lists {after:?}");
    assert!(
        names(&after, &eve_fp) && names(&after, &frank_fp),
        "PRODUCT: carol forgot an equivocation across a restart: she lists {after:?}"
    );
    stop(carol);

    // ---- the TUI says both, each on its own line, by carol's names for them (V210-66) ----------
    // Carol's real `vox tui`, on her stopped profile, in a pty (`tests/pty/tui_equivocation.py`).
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_equivocation.py");
    let (data, cfg) = (
        carol_dir
            .to_str()
            .expect("APPARATUS: a temp path is not UTF-8"),
        carol_dir.join("cfg"),
    );
    // The driver waits on the TUI's unlock.
    let out = pty_driver::run_for(
        script,
        &[
            env!("CARGO_BIN_EXE_vox"),
            "eq",
            data,
            cfg.to_str().expect("APPARATUS: a temp path is not UTF-8"),
            "eq",
        ],
        watchdog::debug_cost(0, 1),
    );
    eprintln!(
        "{}\n[proof] the TUI driver took {:?}; its last stage: {:?}",
        out.stdout, out.took, out.stage
    );
    let stage = out.stage.as_deref().unwrap_or("(before its first stage)");
    if let Some(traceback) = out.crash() {
        panic!("APPARATUS: the TUI driver crashed at stage {stage:?}:\n{traceback}");
    }
    match out.code {
        Some(0) => assert!(
            out.stdout.contains("eq PASS"),
            "APPARATUS: the TUI driver exited 0 without a PASS line: {}",
            out.stdout
        ),
        Some(2) => panic!(
            "APPARATUS: the TUI apparatus failed at stage {stage:?}: {}",
            out.stdout
        ),
        _ if !out.has_verdict("eq") => panic!(
            "APPARATUS: the TUI driver was stopped from outside before it gave a verdict, at \
             stage {stage:?} after {:?} (exit {:?}; its stack is above, on stderr): {}",
            out.took, out.code, out.stdout
        ),
        _ if out.stdout.contains("outlived SIGKILL") => panic!(
            "APPARATUS: the TUI driver could not stop the `vox tui` it started: {}",
            out.stdout
        ),
        _ if out.stdout.contains("eq HUNG at") && stage == "stopping every process" => panic!(
            "APPARATUS: the TUI driver hung stopping its processes, after its verdict: {}",
            out.stdout
        ),
        _ if out.stdout.contains("eq RED: PRODUCT (staging)") => panic!(
            "PRODUCT (staging): carol's `vox tui` never opened the room: {}",
            out.stdout
        ),
        _ if out.stdout.contains("eq HUNG at") => panic!(
            "PRODUCT: carol's `vox tui` did not get past {stage:?} within the driver's budget \
             ({:?}; its stack is above, on stderr): {}",
            out.took, out.stdout
        ),
        _ => panic!(
            "PRODUCT: carol's TUI must say eve and frank are held back, each on its own line: {}",
            out.stdout
        ),
    }
}

// ---- MP-9 (ADR-053): a split view of unequal sizes is caught when views meet -------------------
//
// eve's profile is copied (eve′): two processes of one identity. eve posts three posts alone and
// bob, started after, reads them; eve′ posts six different posts alone and carol, started after,
// reads them. eve's history is then a different length on each: no message of anyone cites either
// side, so nothing but the members' comparison of eve's signed heads can catch it. alice (the
// creator) and dave hold neither side. A member out of a scene is stopped (SIGTERM, so it closes
// its connections) and started again when a scene needs it; nobody's flows wait on a frozen peer.
// A staging read is always made by a member started after the posts it reads, and waits until it
// reads every post of the side, not only the last (`staged_reads_all`).
//
// - `..._when_the_two_members_meet`: bob and carol continue together. Each lists eve's
//   equivocation in `vox status --json` and says it in `vox room read`; started again after
//   alice (an unrelated sender) and eve post once more, each reads alice's post and not eve's.
// - `..._through_a_member_who_meets_both`: bob and carol never run at the same time again; dave
//   meets carol, then bob, restarts, then meets carol again. bob and carol each list eve's
//   equivocation.
// - `..._held_unresolved_between_two_groups_...` (rule 6): bob (group A) and carol (group B)
//   never run at the same time again. dave meets bob (side A), then carol (side B) as a holder
//   that kept eve's accepted head but no opening of it (staging knob
//   `VOX_TEST_NO_ACCEPTED_OPENING_FILE`): nobody at either meeting holds both sides, so no fork
//   proof exists. dave keeps side B's head unresolved and restarts. bob, who never met side B,
//   fetches that head from dave by its id and catches the fork; carol then gets the fork proof
//   from dave. dave, restarted, still reads side A and none of side B.
// - `..._whose_prefixes_differ_below_a_matching_entry` (rule 7, arm d): eve and eve′ run the
//   mutant sender build (`VOX_MUTANT_SENDER`, mode `split-chain`): eve′ appends every entry eve
//   signed on side A at its position except her second post's, where it signs its own, so the
//   root it signs holds eve's entry at the overlap position m above a different one below it (a
//   signed tree that is not a chain: every entry names the one before it, a root does not). bob
//   holds side A; started with eve′ running, the opening at m matches and only the prefix below
//   it proves the fork. bob lists it and says it. eve′'s own node compares as any member's does
//   and would find the same split from bob's side A and list it, so bob would take its listed
//   proof instead of walking: at the meeting bob gives eve′ only heads (staging knob
//   `VOX_TEST_HEADS_ONLY_FILE`), and what bob lists is his own walk's.
//
// Mutants (`VOX_MUTANT_FORK`): `equal-size-only` (heads of different sizes are never compared)
// turns `..._when_the_two_members_meet` and `..._through_a_member_who_meets_both` red;
// `fork-unpropagated` (a recorded fork is never listed) turns `..._through_a_member_who_meets_both`
// and rule 6 red at carol, since carol meets only dave, whose current head is her own or
// unopenable; `second-head-unkept` (an unresolved head is neither kept nor listed) turns rule 6
// red at bob; `terminal-header-only` (a matching entry at the overlap ends the comparison) turns
// arm d red. (A withheld proof is never called a fork: a spike, not committed here; see the PR.)

/// What eve posts on each side; a member holds a side once it reads all of it.
const SIDE_A: [&str; 3] = ["UF-A-1", "UF-A-2", "UF-A-3"];
const SIDE_B: [&str; 6] = ["UF-B-1", "UF-B-2", "UF-B-3", "UF-B-4", "UF-B-5", "UF-B-6"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Meeting {
    Direct,
    ThroughDave,
    Unresolved,
    PrefixDiffers,
}

/// The mutant sender build arm (d) runs eve on: `VOX_MUTANT_SENDER`, carrying its marker, while
/// the `vox` under test does not. Otherwise the act cannot stage its signer: APPARATUS.
fn mutant_sender() -> std::path::PathBuf {
    let mutant = std::env::var("VOX_MUTANT_SENDER").unwrap_or_else(|_| {
        panic!(
            "APPARATUS (harness): VOX_MUTANT_SENDER does not name the mutant sender build \
             (VOX_MUTANT_SENDER=$(scripts/build-mutant-sender.sh))"
        )
    });
    let carries = |path: &str| {
        std::fs::read(path)
            .map(|b| b.windows(17).any(|w| w == b"VOX-MUTANT-SENDER"))
            .unwrap_or(false)
    };
    assert!(
        carries(&mutant) && !carries(VOX),
        "APPARATUS (harness): VOX_MUTANT_SENDER={mutant} is not the mutant sender build, or the \
         binary under test carries its marker"
    );
    std::path::PathBuf::from(mutant)
}

/// The positions `dir` holds an exported entry at (the mutant's `split-chain` writes `<seq>`).
fn exported(dir: &Path) -> std::collections::BTreeSet<u64> {
    std::fs::read_dir(dir)
        .expect("APPARATUS: cannot list the mutant's entry directory")
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect()
}

/// Wait until `data` lists `author`'s equivocation in `room_id`, or `within` passes.
fn wait_listed(data: &Path, room_id: &str, author: &str, within: Duration) -> Vec<(String, u64)> {
    let deadline = Instant::now() + within;
    loop {
        let now = listed(data, room_id);
        if names(&now, author) || Instant::now() >= deadline {
            return now;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn says_equivocated(read: &str, name: &str, fp: &str) -> bool {
    let short: String = fp.chars().take(26).collect();
    read.lines().any(|l| {
        l.strip_prefix("! ").is_some_and(|rest| {
            (rest.starts_with(&format!("{name} ")) || rest.starts_with(&short))
                && rest.contains("signed two different messages at the same place")
        })
    })
}

fn room_read(data: &Path, room: &str) -> String {
    vox_once(data, &args(&["room", "read", room])).1
}

/// A staging read: one `vox room read` of `reader`'s shows every one of `texts`, which `posters`
/// posted, within `within`. Every post of a side, not its last: a member that has read only a
/// side's last post may hold only that position (a live window fetches the tip first and walks
/// down), and the comparison an arm stages needs that side opened at the other side's size
/// (m-a: carol held only position 15 of side B, so nobody running could open it at bob's 12).
/// Not reached, the act has no result: `APPARATUS NO RESULT (staging)`, never a verdict; the
/// members' `vox status --json` and what the reader still lacks go with it.
fn staged_reads_all(
    reader: &Path,
    posters: &[&Path],
    room: &str,
    texts: &[&str],
    within: Duration,
    what: &str,
) {
    let deadline = Instant::now() + within;
    let mut missing: Vec<&str>;
    loop {
        let read = room_read(reader, room);
        missing = texts
            .iter()
            .copied()
            .filter(|text| !read.contains(text))
            .collect();
        if missing.is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    for (who, d) in
        std::iter::once(("reader", reader)).chain(posters.iter().map(|d| ("poster", *d)))
    {
        let (_, status, _) = vox_once(d, &args(&["status", "--json"]));
        eprintln!("[staging] the {who}'s status: {status}");
    }
    panic!(
        "APPARATUS NO RESULT (staging): {what}: after {within:?} the reader still lacks \
         {missing:?}"
    );
}

#[allow(clippy::too_many_lines)]
fn unequal_fork(meeting: Meeting) {
    watchdog::arm();
    // The staging knobs an arm needs, and a mutant a run names, are in the `vox` under test.
    let mut knobs = match meeting {
        Meeting::Unresolved => vec!["VOX_TEST_NO_ACCEPTED_OPENING_FILE"],
        Meeting::PrefixDiffers => vec!["VOX_TEST_HEADS_ONLY_FILE"],
        Meeting::Direct | Meeting::ThroughDave => vec![],
    };
    if std::env::var_os("VOX_MUTANT_FORK").is_some() {
        knobs.push("VOX_MUTANT_FORK");
    }
    test_knobs::require(&knobs);
    // Arm (d)'s signer: the mutant sender build, refused as APPARATUS before anything starts.
    let mutant = (meeting == Meeting::PrefixDiffers).then(mutant_sender);
    let mut tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
        tmp.disable_cleanup(true);
        eprintln!(
            "[proof] retained daemon directory: {}",
            tmp.path().display()
        );
    }
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: cannot make a directory");
        d
    };
    let (anchor_dir, alice_dir, bob_dir, carol_dir, dave_dir, eve_dir) = (
        dir("anchor"),
        dir("alice"),
        dir("bob"),
        dir("carol"),
        dir("dave"),
        dir("eve"),
    );
    let eve2_dir = tmp.path().join("eve2");
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: cannot write a staging file");
    // Each staging knob names an author only once a scene writes its file; empty, it does nothing.
    let staging_file = |n: &str| {
        let path = tmp.path().join(n);
        std::fs::write(&path, "").expect("APPARATUS: cannot write a staging file");
        let text = path
            .to_str()
            .expect("APPARATUS: a temp path is not UTF-8")
            .to_owned();
        (path, text)
    };
    let (sparse, sparse_path) = staging_file("sparse");
    // Arm (d): bob, at the meeting, gives the peer named here (eve′) only heads.
    let (heads_only, heads_only_path) = staging_file("heads-only");
    let dave_env = [("VOX_TEST_NO_ACCEPTED_OPENING_FILE", sparse_path.as_str())];
    // Arm (d): each copy of eve writes the entries it signs to its own directory; eve′ appends
    // `adopt-<seq>` (eve's entry) in place of its own at that position.
    let (eve_entries, eve2_entries) = (
        tmp.path().join("eve-entries"),
        tmp.path().join("eve2-entries"),
    );
    for d in [&eve_entries, &eve2_entries] {
        std::fs::create_dir_all(d).expect("APPARATUS: cannot make a directory");
    }
    let entries_env = |d: &Path| {
        [
            ("VOX_MUTANT_SENDER_MODE", "split-chain".to_owned()),
            (
                "VOX_MUTANT_ENTRY_DIR",
                d.to_str()
                    .expect("APPARATUS: a temp path is not UTF-8")
                    .to_owned(),
            ),
        ]
    };

    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();
    // eve's daemon for a side: the mutant signer in arm (d), else the `vox` under test.
    let eve_daemon = |name: &str, data: &Path, entries: &Path| match &mutant {
        Some(exe) => {
            let env = entries_env(entries);
            let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
            daemon_exe(exe, name, data, &spec, &idpass, &env)
        }
        None => daemon(name, data, &spec, &idpass),
    };
    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id failed: {err}");
        out.trim().to_owned()
    };
    let members = [
        ("alice", &alice_dir),
        ("bob", &bob_dir),
        ("carol", &carol_dir),
        ("dave", &dave_dir),
        ("eve", &eve_dir),
    ];
    let fps: Vec<String> = members.iter().map(|(_, d)| fp(d)).collect();
    let eve_fp = fps[4].clone();
    for (i, (_, d)) in members.iter().enumerate() {
        for (j, (name, _)) in members.iter().enumerate() {
            if i != j {
                let (ok, out, err) = vox_once(d, &args(&["trust", "add", &fps[j], "--name", name]));
                assert!(
                    ok,
                    "PRODUCT (staging): vox trust add {name} failed: {out}{err}"
                );
            }
        }
    }
    let alice = daemon("alice", &alice_dir, &spec, &idpass);
    let bob = daemon("bob", &bob_dir, &spec, &idpass);
    let carol = daemon("carol", &carol_dir, &spec, &idpass);
    let dave = daemon_env("dave", &dave_dir, &spec, &idpass, &dave_env);
    let eve = daemon("eve", &eve_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "uf"],
        "room pass",
    );
    assert!(ok, "PRODUCT (staging): vox room create failed: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): vox room list failed: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("uf"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): the new room is not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "link", &room]));
    assert!(ok, "PRODUCT (staging): vox room link failed: {err}");
    for (name, d) in &members[1..] {
        let (ok, out, err) = vox_in(
            d,
            &["room", "join", "--passphrase-file", "-", link.trim()],
            "room pass",
        );
        assert!(ok, "PRODUCT (staging): {name}'s join failed: {out}{err}");
    }
    let room_id = link
        .trim()
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .unwrap_or_else(|| {
            panic!("APPARATUS: the proof cannot read the room id in the room link {link}")
        })
        .to_owned();

    // ---- everyone reads everyone's hello ------------------------------------------------------
    let deadline = Instant::now() + SETUP;
    let mut round = 0u32;
    'warm: loop {
        round += 1;
        for (name, d) in members {
            post(d, &room, name, &format!("hello from {name} r{round}"));
        }
        let round_ends = Instant::now() + HELLO_ROUND;
        let mut missing: Vec<String> = Vec::new();
        while Instant::now() < round_ends {
            missing.clear();
            for (reader, d) in members {
                let r = room_read(d, &room);
                for (n, _) in members {
                    if !r.contains(&format!("hello from {n} r{round}")) {
                        missing.push(format!("{reader} cannot read {n}"));
                    }
                }
            }
            if missing.is_empty() {
                eprintln!("[setup] everyone reads everyone's hello of round {round}");
                break 'warm;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): after {SETUP:?} ({round} rounds) the members still do not all read \
             each other: {missing:?}"
        );
    }

    // ---- eve stops and is copied; everyone stops ------------------------------------------------
    // Every staging read below is made by a member started AFTER the posts it reads, never by a
    // member already running when the poster starts again: a member started again who posts in
    // its first seconds was not read by a member already running for 148 s (main-b3) or at all
    // within 300 s (mut-a5-equal, mut-b5-equal, cand-b3, cand-b4, cand-u1, main-b2, main-c,
    // main-c2), on main as on this change; that is not what these acts measure.
    stop(eve);
    copy_dir(&eve_dir, &eve2_dir);
    stop(alice);
    stop(dave);
    stop(carol);
    stop(bob);

    // ---- side A: eve posts three alone; bob, started after, reads them ---------------------------
    let eve = eve_daemon("eve", &eve_dir, &eve_entries);
    // Arm (d): the positions each post of eve's took (a control may precede a post).
    let mut eve_posts: Vec<std::collections::BTreeSet<u64>> = Vec::new();
    for i in 1..=3 {
        let before = exported(&eve_entries);
        post(&eve_dir, &room, "eve", &format!("UF-A-{i}"));
        eve_posts.push(
            exported(&eve_entries)
                .difference(&before)
                .copied()
                .collect(),
        );
    }
    let bob = daemon("bob", &bob_dir, &spec, &idpass);
    staged_reads_all(
        &bob_dir,
        &[&eve_dir],
        &room,
        &SIDE_A,
        STAGE,
        "bob never read all of eve's side A, so the first side of the fork is not in place",
    );
    stop(eve);
    stop(bob);

    // ---- side B: eve′ posts six other posts alone; carol, started after, reads them -------------
    // Arm (d): eve′ (the mutant signer, kept running: it alone holds its root) appends every entry
    // eve signed on side A, her posts and any control she wrote before she stopped, at their
    // positions, except her second post's, where it signs its own. eve may write a control after
    // her last post (n-mut-d-terminal: at 12, after her third post at 11); left out, eve′'s root
    // would differ from bob's side A at the overlap itself, and no prefix walk would be needed.
    // carol does not read it: an honest member refuses eve's third entry above eve′'s second,
    // which it does not name.
    let mut eve2_running = None;
    let mut carol_running = None;
    let mut below = 0;
    if meeting == Meeting::PrefixDiffers {
        below = eve_posts[1]
            .iter()
            .copied()
            .max()
            .expect("APPARATUS (staging): eve's second post wrote no entry");
        // Read after eve stopped, so nothing she signed is missed.
        let adopted: Vec<u64> = exported(&eve_entries)
            .into_iter()
            .filter(|seq| *seq != below)
            .collect();
        for seq in &adopted {
            std::fs::copy(
                eve_entries.join(seq.to_string()),
                eve2_entries.join(format!("adopt-{seq}")),
            )
            .expect("APPARATUS: cannot copy eve's entry for eve′");
        }
        let mut eve2 = eve_daemon("eve2", &eve2_dir, &eve2_entries);
        for i in 1..=6 {
            let text = format!("UF-B-{i}");
            let (ok, out, err) = vox_in(&eve2_dir, &["room", "post", &room, "-"], &text);
            assert!(
                ok,
                "APPARATUS (staging): the mutant signer eve′ could not post {text}: {out}{err}\n{}",
                eve2.transcript()
            );
        }
        let said = eve2
            .transcript()
            .matches("appends the other copy's entry at")
            .count();
        assert!(
            said >= adopted.len(),
            "APPARATUS (staging): eve′ appended {said} of eve's entries {adopted:?}, so its root \
             does not hold eve's entry at the overlap:\n{}",
            eve2.transcript()
        );
        eprintln!(
            "[setup] bob holds eve's side A {eve_posts:?}; eve′ (running) signed a root holding \
             eve's entries at {adopted:?} and its own at {below}"
        );
        eve2_running = Some(eve2);
    } else {
        let eve2 = daemon("eve2", &eve2_dir, &spec, &idpass);
        for i in 1..=6 {
            post(&eve2_dir, &room, "eve'", &format!("UF-B-{i}"));
        }
        assert!(
            !reads(&eve2_dir, &room, "UF-A-1"),
            "PRODUCT (staging): eve′ reads UF-A-1, so its posts continued the first side instead \
             of forking it"
        );
        let carol = daemon("carol", &carol_dir, &spec, &idpass);
        staged_reads_all(
            &carol_dir,
            &[&eve2_dir],
            &room,
            &SIDE_B,
            STAGE,
            "carol never read all of eve′'s side B, so the second side of the fork is not in place",
        );
        assert!(
            !reads(&carol_dir, &room, "UF-A-1"),
            "PRODUCT (staging): carol already reads side A before the sides were made to meet"
        );
        stop(eve2);
        eprintln!("[setup] bob holds eve's side A (3 posts), carol eve's side B (6 posts)");
        carol_running = Some(carol);
    }

    match meeting {
        Meeting::Direct => {
            let carol = carol_running.expect("APPARATUS: carol was staged with side B");
            let bob = daemon("bob", &bob_dir, &spec, &idpass);
            let met = Instant::now();
            let listed_by: Vec<_> = [("bob", &bob_dir), ("carol", &carol_dir)]
                .into_iter()
                .map(|(who, d)| (who, wait_listed(d, &room_id, &eve_fp, DETECT)))
                .collect();
            eprintln!(
                "[proof] {:.1?} after the sides met: {listed_by:?}",
                met.elapsed()
            );
            for (who, list) in &listed_by {
                assert!(
                    names(list, &eve_fp),
                    "PRODUCT: {who} does not list eve's equivocation within {DETECT:?} of the \
                     two sides meeting: it lists {list:?}"
                );
            }
            for (who, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
                let r = room_read(d, &room);
                assert!(
                    says_equivocated(&r, "eve", &eve_fp),
                    "PRODUCT: {who}'s `vox room read` does not say eve equivocated:\n{r}"
                );
            }
            // Held back: bob posts once more while carol runs; his post cites eve's side A,
            // which carol refuses under today's full check (ADR-053 MP-9 "Why"); it is reported,
            // not asserted. Then bob and carol stop. alice (stopped since before the fork, so she
            // cites neither side) posts as soon as she is started, an unrelated sender; eve posts
            // again. bob and carol, started after both posts (see the staging note above), read
            // alice's and neither reads eve's: what each recorded is kept across its restart.
            post(&bob_dir, &room, "bob", "UF-BOB-AFTER");
            stop(bob);
            stop(carol);
            let alice = daemon("alice", &alice_dir, &spec, &idpass);
            post(&alice_dir, &room, "alice", "UF-CONTROL");
            let eve = daemon("eve", &eve_dir, &spec, &idpass);
            post(&eve_dir, &room, "eve", "UF-AFTER");
            let bob = daemon("bob", &bob_dir, &spec, &idpass);
            let carol = daemon("carol", &carol_dir, &spec, &idpass);
            for (who, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
                assert!(
                    wait_reads(d, &room, "UF-CONTROL", STAGE),
                    "PRODUCT: {who} never read alice's control message, an unrelated sender"
                );
            }
            std::thread::sleep(HELD);
            for (who, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
                assert!(
                    !reads(d, &room, "UF-AFTER"),
                    "PRODUCT: {who} read a post eve made after her equivocation was recorded"
                );
            }
            eprintln!(
                "[proof] observation: carol reads bob's post made after the fork (it cites eve's \
                 side A): {}",
                reads(&carol_dir, &room, "UF-BOB-AFTER")
            );
            stop(eve);
            drop((alice, bob, carol));
        }
        Meeting::ThroughDave => {
            let carol = carol_running.expect("APPARATUS: carol was staged with side B");
            // dave meets carol (side B) alone, then bob (side A) alone, restarts, then meets
            // carol again. bob and carol never run at the same time again.
            let dave = daemon_env("dave", &dave_dir, &spec, &idpass, &dave_env);
            staged_reads_all(
                &dave_dir,
                &[&carol_dir],
                &room,
                &SIDE_B,
                STAGE,
                "dave never read all of carol's copy of side B",
            );
            stop(carol);
            let bob = daemon("bob", &bob_dir, &spec, &idpass);
            let bob_list = wait_listed(&bob_dir, &room_id, &eve_fp, DETECT);
            let dave_list = listed(&dave_dir, &room_id);
            let bob_read = room_read(&bob_dir, &room);
            eprintln!(
                "[proof] with dave and bob running: bob lists {bob_list:?}, dave {dave_list:?}"
            );
            stop(bob);
            // dave restarts before he meets carol again: what he recorded or kept is durable.
            stop(dave);
            let dave = daemon_env("dave", &dave_dir, &spec, &idpass, &dave_env);
            let carol = daemon("carol", &carol_dir, &spec, &idpass);
            let carol_list = wait_listed(&carol_dir, &room_id, &eve_fp, DETECT);
            eprintln!("[proof] with dave and carol running: carol lists {carol_list:?}");
            assert!(
                names(&bob_list, &eve_fp),
                "PRODUCT: bob (side A) does not list eve's equivocation within {DETECT:?} of \
                 meeting dave, who had met side B: bob lists {bob_list:?}, dave lists {dave_list:?}"
            );
            assert!(
                names(&carol_list, &eve_fp),
                "PRODUCT: carol (side B) does not list eve's equivocation within {DETECT:?} of \
                 meeting dave again: carol lists {carol_list:?}"
            );
            for (who, r) in [("bob", bob_read), ("carol", room_read(&carol_dir, &room))] {
                assert!(
                    says_equivocated(&r, "eve", &eve_fp),
                    "PRODUCT: {who}'s `vox room read` does not say eve equivocated:\n{r}"
                );
            }
            drop((carol, dave));
        }
        Meeting::Unresolved => {
            let carol = carol_running.expect("APPARATUS: carol was staged with side B");
            // dave meets bob (side A) alone and holds it as any member does.
            stop(carol);
            let bob = daemon("bob", &bob_dir, &spec, &idpass);
            let mut dave = daemon_env("dave", &dave_dir, &spec, &idpass, &dave_env);
            staged_reads_all(
                &dave_dir,
                &[&bob_dir],
                &room,
                &SIDE_A,
                STAGE,
                "dave never read all of bob's copy of side A",
            );
            stop(bob);
            // From here dave keeps eve's accepted head but neither opens nor serves it.
            std::fs::write(&sparse, &eve_fp).expect("APPARATUS: cannot write a staging file");
            let carol = daemon("carol", &carol_dir, &spec, &idpass);
            let author = format!("author={eve_fp} ");
            // Observed, not asserted (a build without the knob or the line, main, goes on to the
            // act's own assertions): dave, holding side A, opened side B's overlap under carol's
            // head and came to wait for an opening of his own side, which nobody running holds.
            let compared = dave.line_within(STAGE, |l| {
                l.contains("history comparison unresolved")
                    && l.contains(&author)
                    && l.contains("awaits=accepted-side")
            });
            eprintln!("[proof] dave's comparison with carol: {compared:?}");
            let dave_then = listed(&dave_dir, &room_id);
            let carol_then = listed(&carol_dir, &room_id);
            assert!(
                !names(&dave_then, &eve_fp) && !names(&carol_then, &eve_fp),
                "PRODUCT (staging): a fork proof exists before dave's restart, so the second head \
                 is not what brings the views together: dave lists {dave_then:?}, carol \
                 {carol_then:?}"
            );
            stop(carol);
            // dave restarts: the second head and its comparison survive, neither forgotten nor
            // promoted.
            stop(dave);
            let dave = daemon_env("dave", &dave_dir, &spec, &idpass, &dave_env);
            let dave_read = room_read(&dave_dir, &room);
            assert!(
                dave_read.contains("UF-A-3") && !dave_read.contains("UF-B-1"),
                "PRODUCT: dave, restarted, no longer reads side A as he held it, or shows side B \
                 from a head he only kept:\n{dave_read}"
            );
            // bob (group A) never met side B: only dave's kept head can bring it to him.
            let bob = daemon("bob", &bob_dir, &spec, &idpass);
            let bob_list = wait_listed(&bob_dir, &room_id, &eve_fp, DETECT);
            let dave_list = wait_listed(&dave_dir, &room_id, &eve_fp, DETECT);
            let bob_read = room_read(&bob_dir, &room);
            eprintln!(
                "[proof] with dave (restarted) and bob running: bob lists {bob_list:?}, dave \
                 {dave_list:?}"
            );
            stop(bob);
            // carol (group B) meets dave again.
            let carol = daemon("carol", &carol_dir, &spec, &idpass);
            let carol_list = wait_listed(&carol_dir, &room_id, &eve_fp, DETECT);
            eprintln!("[proof] with dave and carol running: carol lists {carol_list:?}");
            assert!(
                names(&bob_list, &eve_fp),
                "PRODUCT: bob (side A), who never met side B, does not list eve's equivocation \
                 within {DETECT:?} of meeting dave, who kept side B's head unresolved across his \
                 restart: bob lists {bob_list:?}, dave lists {dave_list:?}"
            );
            assert!(
                names(&carol_list, &eve_fp),
                "PRODUCT: carol (side B) does not list eve's equivocation within {DETECT:?} of \
                 meeting dave after bob recorded it: carol lists {carol_list:?}"
            );
            for (who, r) in [("bob", bob_read), ("carol", room_read(&carol_dir, &room))] {
                assert!(
                    says_equivocated(&r, "eve", &eve_fp),
                    "PRODUCT: {who}'s `vox room read` does not say eve equivocated:\n{r}"
                );
            }
            drop((carol, dave));
        }
        Meeting::PrefixDiffers => {
            let eve2 = eve2_running.expect("APPARATUS: eve′ was staged with side B");
            // bob gives eve′ only heads, consistency proofs and inventory, never a header, an
            // inclusion proof or an entry: eve′ (whose node compares as any member's does) cannot
            // open bob's side A, so it cannot find its own split and list it before bob does.
            // What bob lists is then his own comparison's: the prefix walk below the matching
            // entry (m-mut-d-terminal: with eve′ free to open side A, bob took eve′'s listed
            // proof and the walk's mutant stayed green). bob's own asks are not touched.
            std::fs::write(&heads_only, &eve_fp).expect("APPARATUS: cannot write a staging file");
            let bob = daemon_env(
                "bob",
                &bob_dir,
                &spec,
                &idpass,
                &[("VOX_TEST_HEADS_ONLY_FILE", heads_only_path.as_str())],
            );
            let bob_list = wait_listed(&bob_dir, &room_id, &eve_fp, DETECT);
            let r = room_read(&bob_dir, &room);
            eprintln!("[proof] bob (side A) met eve′'s root: bob lists {bob_list:?}");
            assert!(
                names(&bob_list, &eve_fp),
                "PRODUCT: bob does not list eve's equivocation within {DETECT:?} of meeting a root of \
                 hers that holds his entry at the overlap above a different one: he lists \
                 {bob_list:?}"
            );
            // Printed, not asserted: this arm's mutant stops at the listing above, so neither line
            // below would have a mutant of its own (ADR-018 §7).
            eprintln!(
                "[proof] observed, not asserted: bob places eve's equivocation at {below}: {}; his \
                 `vox room read` says eve equivocated: {}",
                bob_list.iter().any(|(a, p)| a == &eve_fp && *p == below),
                says_equivocated(&r, "eve", &eve_fp)
            );
            stop(eve2);
            drop((bob, carol_running));
        }
    }
}

#[test]
#[ignore = "real vox processes, five members and a copied profile; CI runs it in release"]
fn a_split_view_of_unequal_sizes_is_caught_when_the_two_members_meet() {
    unequal_fork(Meeting::Direct);
}

#[test]
#[ignore = "real vox processes, five members and a copied profile; CI runs it in release"]
fn a_split_view_of_unequal_sizes_is_caught_through_a_member_who_meets_both() {
    unequal_fork(Meeting::ThroughDave);
}

#[test]
#[ignore = "real vox processes, five members and a copied profile; CI runs it in release"]
fn a_second_head_held_unresolved_between_two_groups_is_caught_on_both_sides() {
    unequal_fork(Meeting::Unresolved);
}

#[test]
#[ignore = "real vox processes, five members, a copied profile and the mutant sender build \
            (VOX_MUTANT_SENDER); CI runs it in release"]
fn a_split_view_whose_prefixes_differ_below_a_matching_entry_is_caught() {
    unequal_fork(Meeting::PrefixDiffers);
}
