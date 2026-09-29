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
//! - **held back**: eve's original posts again, and neither reads it, while a control message bob
//!   posts reaches carol;
//! - **kept**: with eve′ and frank′ stopped — so no sync can meet either fork again — carol's
//!   daemon is restarted, and `vox status --json` still lists both.
//!
//! Mutations: the old `wants_for` (from past our head, no comparison of a shorter peer's head) —
//! eve's fork is never listed; the `room read` notice removed; `keep_forks` doing nothing — the
//! restarted carol lists neither.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

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
        .expect("run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("vox finished");
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
    assert!(ok, "kill {sig} {}", p.name);
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

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn daemon(name: &str, data: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    let p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file.to_str().unwrap(),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{name}'s daemon never answered `vox room list`");
}

/// A stopped member's whole profile, copied: a second process of the same identity.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        let kind = e.file_type().unwrap();
        if kind.is_dir() {
            copy_dir(&e.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(e.path(), &target).unwrap();
        }
        // A socket or a lock of the stopped process is not part of the profile.
    }
}

fn post(data: &Path, room: &str, who: &str, text: &str) {
    let (ok, out, err) = vox_in(data, &["room", "post", room, "-"], text);
    assert!(ok, "{who} posts {text:?}: {out}{err}");
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

/// The equivocations `vox status --json` lists for `room`: `(author, position)`.
fn listed(data: &Path, room_id: &str) -> Vec<(String, u64)> {
    let (ok, out, _) = vox_once(data, &args(&["status", "--json"]));
    if !ok {
        return Vec::new();
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&out) else {
        return Vec::new();
    };
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
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
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
    std::fs::write(&idpass, IDENTITY).unwrap();

    let port = free_udp_port();
    let listen = format!("127.0.0.1:{port}");
    let mut anchor = VoxProc::spawn("anchor", &anchor_dir, &args(&["node", "--listen", &listen]));
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "vox id: {err}");
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
                assert!(ok, "vox trust add {name}: {out}{err}");
            }
        }
    }
    let alice = daemon("alice", &alice_dir, &spec, &idpass);
    let mut bob = daemon("bob", &bob_dir, &spec, &idpass);
    let mut carol = daemon("carol", &carol_dir, &spec, &idpass);
    let eve = daemon("eve", &eve_dir, &spec, &idpass);
    let frank = daemon("frank", &frank_dir, &spec, &idpass);

    let (ok, out, err) = vox_in(&alice_dir, &["room", "create", "--name", "eq"], "room pass");
    assert!(ok, "vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("eq"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
    assert!(ok, "vox room invite: {err}");
    for (name, d) in &members[1..] {
        let (ok, out, err) = vox_in(
            d,
            &["room", "join", link.trim(), "--name", "eq"],
            "room pass",
        );
        assert!(ok, "{name} joins: {out}{err}");
    }
    // The room's full id, as `vox status --json` names it: the invite link carries it.
    let room_id = link
        .trim()
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .unwrap_or_else(|| panic!("no room id in the invite link {link}"))
        .to_owned();
    assert!(
        room_id.starts_with(&room),
        "the invite link names another room: {room_id} for {room}"
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
            "CANNOT MEASURE: after {SETUP:?} ({round} rounds) the members still do not all read \
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
    for text in ["EQ-EVE-A-3", "EQ-FRANK-A-1"] {
        assert!(
            wait_reads(&bob_dir, &room, text, REACH),
            "CANNOT MEASURE: bob never read {text}, so the first side of the fork is not in place"
        );
    }
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
            "CANNOT MEASURE: {who} already reads {text}, so its message continued the first side \
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
            "{who} does not list eve's equivocation below the head within {DETECT:?}: {:?}",
            last[i]
        );
        assert!(
            names(&last[i], &frank_fp),
            "{who} does not list frank's equivocation at the head within {DETECT:?}: {:?}",
            last[i]
        );
    }

    // `vox room read` says it, by the short id its rows use.
    let short = |f: &str| f.chars().take(26).collect::<String>();
    for (who, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
        let (_, r, _) = vox_once(d, &args(&["room", "read", &room]));
        for (name, f) in [("eve", &eve_fp), ("frank", &frank_fp)] {
            let said = r.lines().any(|l| {
                l.starts_with("! ")
                    && l.contains(&short(f))
                    && l.contains("signed two different messages at the same place")
            });
            assert!(
                said,
                "{who}'s `vox room read` does not say {name} equivocated:\n{r}"
            );
        }
    }

    // ---- held back: eve's original posts again; a control message still arrives --------------
    stop(eve2);
    stop(frank2);
    let eve = daemon("eve", &eve_dir, &spec, &idpass);
    post(&eve_dir, &room, "eve", "EQ-EVE-AFTER");
    post(&bob_dir, &room, "bob", "EQ-CONTROL");
    assert!(
        wait_reads(&carol_dir, &room, "EQ-CONTROL", REACH),
        "CANNOT MEASURE: carol never read bob's control message, so nothing shows the room moves"
    );
    std::thread::sleep(HELD);
    for (who, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
        assert!(
            !reads(d, &room, "EQ-EVE-AFTER"),
            "{who} read a message eve posted after her equivocation was caught"
        );
    }
    stop(eve);

    // ---- kept: carol restarts with nobody left who could show her either fork again ------------
    stop(carol);
    let _carol = daemon("carol", &carol_dir, &spec, &idpass);
    // Listed only once the room is open again, so an empty list is the room's, not a room not
    // yet reopened.
    assert!(
        wait_reads(&carol_dir, &room, "EQ-CONTROL", REACH),
        "CANNOT MEASURE: carol's restarted daemon never reopened the room"
    );
    let after = listed(&carol_dir, &room_id);
    eprintln!("[proof] carol, restarted, lists {after:?}");
    assert!(
        names(&after, &eve_fp) && names(&after, &frank_fp),
        "carol forgot an equivocation across a restart: she lists {after:?}"
    );
    drop(alice);
}
