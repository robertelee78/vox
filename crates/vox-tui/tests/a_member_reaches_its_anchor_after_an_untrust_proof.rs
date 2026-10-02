//! V210-139 (a) — **a member's sessions to its anchor still carry its posts after it removes
//! someone from its ring**, through the shipped `vox` binary only: a `vox node` anchor and three
//! `vox daemon`s, every step typed as an operator types it.
//!
//! ## The defect this guards
//! ADR-016 recorded that in the untrust-and-lock gate the member→anchor session "fails every time
//! (`sync failed: transport`), in greens as well as reds". Removing a member from the ring changes
//! the lock: it rotates the remover's sender key and re-keys everyone still trusted (ADR-020 §3).
//! The anchor is the hop a message takes when two members are never online together, so a member
//! whose sessions to it fail after a removal leaves its later posts on no node but its own. The
//! gate that showed it was deleted with the in-process tests (V29-17), so nothing proved it since.
//! Measured through the shipped binary on integrate/v0.2.10 10ff9310 (a spike before this proof):
//! every member→anchor session completed after the removal, none failed. So this is a guard.
//!
//! ## The staging
//! An anchor; alice, bob and carol, each a `vox daemon` on it, all trusting each other. Alice makes
//! **two** rooms (a removal changes the lock in every shared room) and bob and carol join both.
//! Alice posts in each, and carol renders those posts (`PRODUCT (staging)` otherwise). Then:
//! 1. carol's daemon stops (killed by PID): she is offline from here on;
//! 2. alice removes bob from her ring (`vox trust remove`), and posts once more in each room.
//!
//! ## What is asserted
//! - **(1)** the anchor takes alice's posts made after the removal, in both rooms, within
//!   [`TAKEN_WITHIN`] (its `took … for room …` lines): her sessions to it carried them;
//! - **(2)** alice's daemon never logs a sync with the anchor that did not complete after the
//!   removal;
//! - **(3)** alice and bob then stop too, so the anchor is the only node holding those posts besides
//!   their authors, and carol's daemon starts again: carol renders alice's posts made after the
//!   removal, in both rooms, within [`READ_WITHIN`] — the journey the anchor exists for.
//!
//! **A red names its side.** (1)–(3) are `PRODUCT:`, quoting what vox said. A `vox` step the scene
//! needs that fails is `PRODUCT (staging):`. The test's own files are `APPARATUS:`.
//!
//! **Mutation:** a member whose sessions to an anchor fail once it has removed someone from its
//! ring (the defect, re-introduced) goes red at (1) and (3).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, mkdir, tempdir, utf8, vox_once, VoxProc, IDENTITY, VOX};

/// How long the anchor may take to say it took a post: a sync tick and its session.
const TAKEN_WITHIN: Duration = Duration::from_secs(60);
/// How long carol, back, may take to render what the anchor holds: her daemon reopens the rooms,
/// redials the anchor and syncs; an upper wait for a functional claim, not a latency bound.
const READ_WITHIN: Duration = Duration::from_secs(120);
/// How long a staging read may take.
const STAGING: Duration = Duration::from_secs(120);

/// A `vox` verb with `stdin` piped in (a room passphrase, never argv).
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
        .unwrap_or_else(|e| panic!("APPARATUS: run vox {argv:?}: {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: vox's stdin")
        .write_all(stdin.as_bytes())
        .expect("APPARATUS: write vox's stdin");
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `vox daemon` on `data`'s profile, its identity passphrase from a file; returns once it answers
/// `vox room list`.
fn daemon(name: &str, data: &Path, spec: &str, pass_file: &str) -> VoxProc {
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
            pass_file,
        ]),
    );
    let deadline = Instant::now() + STAGING;
    while !vox_once(data, &args(&["room", "list"])).0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): {name}'s daemon never answered `vox room list`"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    p
}

/// Whether `who` renders `text` in `room`.
fn renders(data: &Path, room: &str, text: &str) -> bool {
    vox_once(data, &args(&["room", "read", room]))
        .1
        .lines()
        .any(|l| l.contains(text))
}

#[test]
#[ignore = "an anchor and three vox daemons with production Argon2id; CI runs it in release"]
fn a_member_reaches_its_anchor_after_an_untrust() {
    watchdog::arm();
    let tmp = tempdir();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        mkdir(&d.join("cfg"));
        d
    };
    let (anchor_dir, alice_dir, bob_dir, carol_dir) =
        (dir("anchor"), dir("alice"), dir("bob"), dir("carol"));
    let pass_file = tmp.path().join("identity-passphrase");
    std::fs::write(&pass_file, IDENTITY).expect("APPARATUS: write the passphrase file");
    let pass_file = utf8(&pass_file);

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

    let fp = |d: &Path, who: &str| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id ({who}): {err}");
        out.trim().to_owned()
    };
    let members = [
        ("alice", &alice_dir),
        ("bob", &bob_dir),
        ("carol", &carol_dir),
    ];
    let fps: Vec<String> = members.iter().map(|(n, d)| fp(d, n)).collect();
    for (i, (name, d)) in members.iter().enumerate() {
        for (j, (other, _)) in members.iter().enumerate() {
            if i != j {
                let (ok, out, err) =
                    vox_once(d, &args(&["trust", "add", &fps[j], "--name", other]));
                assert!(ok, "PRODUCT (staging): {name} trusts {other}: {out}{err}");
            }
        }
    }
    let mut alice = daemon("alice", &alice_dir, &spec, &pass_file);
    let bob = daemon("bob", &bob_dir, &spec, &pass_file);
    let carol = daemon("carol", &carol_dir, &spec, &pass_file);

    // ---- two rooms, both shared with bob and carol ----------------------------------------------
    let mut rooms = Vec::new();
    for (name, pass) in [("one", "passphrase one"), ("two", "passphrase two")] {
        let (ok, out, err) = vox_in(&alice_dir, &["room", "create", "--name", name], pass);
        assert!(ok, "PRODUCT (staging): alice creates {name}: {out}{err}");
        let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
        assert!(ok, "PRODUCT (staging): vox room list: {err}");
        let room = list
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some(name))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("PRODUCT (staging): {name} is not listed: {list}"))
            .to_owned();
        let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
        assert!(ok, "PRODUCT (staging): vox room invite {name}: {err}");
        for (who, d) in [("bob", &bob_dir), ("carol", &carol_dir)] {
            let (ok, out, err) = vox_in(d, &["room", "join", link.trim(), "--name", name], pass);
            assert!(ok, "PRODUCT (staging): {who} joins {name}: {out}{err}");
        }
        rooms.push(room);
    }
    for room in &rooms {
        let (ok, _, err) = vox_once(&alice_dir, &args(&["room", "post", room, "before removal"]));
        assert!(ok, "PRODUCT (staging): alice posts: {err}");
    }
    let deadline = Instant::now() + STAGING;
    while !rooms
        .iter()
        .all(|r| renders(&carol_dir, r, "before removal"))
    {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): carol never rendered alice's first posts"
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    // ---- carol goes offline; alice removes bob, and posts ---------------------------------------
    drop(carol);
    let (ok, out, err) = vox_once(&alice_dir, &args(&["trust", "remove", &fps[1]]));
    assert!(
        ok && out.contains("no longer trusting"),
        "PRODUCT (staging): alice removes bob from her ring: {out}{err}"
    );
    let anchor_mark = anchor.transcript().lines().count();
    let alice_mark = alice.transcript().lines().count();
    for room in &rooms {
        let (ok, _, err) = vox_once(&alice_dir, &args(&["room", "post", room, "after removal"]));
        assert!(
            ok,
            "PRODUCT (staging): alice posts after the removal: {err}"
        );
    }

    // ---- (1) the anchor takes them --------------------------------------------------------------
    let started = Instant::now();
    let took = |anchor: &mut VoxProc, room: &str| {
        anchor
            .transcript()
            .lines()
            .skip(anchor_mark)
            .any(|l| l.contains("took ") && l.contains(&format!("for room {}", &room[..12])))
    };
    while !rooms.iter().all(|r| took(&mut anchor, r)) {
        if started.elapsed() > TAKEN_WITHIN {
            panic!(
                "PRODUCT: (1) {TAKEN_WITHIN:?} after alice removed bob and posted, the anchor had \
                 not taken her posts in every room — her sessions to it did not carry them.\n\
                 --- the anchor since:\n{}\n--- alice since:\n{}",
                anchor
                    .transcript()
                    .lines()
                    .skip(anchor_mark)
                    .collect::<Vec<_>>()
                    .join("\n"),
                alice
                    .transcript()
                    .lines()
                    .skip(alice_mark)
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    println!(
        "[proof] (1) the anchor took alice's posts after the removal, in {} rooms, within {:.1?}",
        rooms.len(),
        started.elapsed()
    );

    // ---- (2) no failed session with the anchor --------------------------------------------------
    let anchor12 = &spec[..12];
    let failed: Vec<String> = alice
        .transcript()
        .lines()
        .skip(alice_mark)
        .filter(|l| l.contains("did not complete") && l.contains(anchor12))
        .map(str::to_owned)
        .collect();
    assert!(
        failed.is_empty(),
        "PRODUCT: (2) after the removal, alice's daemon logged syncs with the anchor that did not \
         complete: {failed:?}"
    );

    // ---- (3) carol, back while alice and bob are gone, reads them through the anchor ----------
    drop(alice);
    drop(bob);
    let carol = daemon("carol", &carol_dir, &spec, &pass_file);
    let back = Instant::now();
    while !rooms
        .iter()
        .all(|r| renders(&carol_dir, r, "after removal"))
    {
        if back.elapsed() > READ_WITHIN {
            let read: Vec<String> = rooms
                .iter()
                .map(|r| vox_once(&carol_dir, &args(&["room", "read", r])).1)
                .collect();
            let mut carol = carol;
            panic!(
                "PRODUCT: (3) carol, back with only the anchor online, did not render alice's posts \
                 made after the removal within {READ_WITHIN:?}; she reads {read:?}.\n--- carol:\n{}",
                carol.transcript()
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!(
        "[proof] (3) carol, back with only the anchor online, rendered both rooms' posts made after \
         the removal in {:.1?}",
        back.elapsed()
    );
    drop(carol);
    drop(anchor);
}
