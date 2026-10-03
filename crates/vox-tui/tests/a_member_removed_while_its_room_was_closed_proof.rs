//! V210-118 amendment (#316 c3) — **a member removed from the ring while a room was closed is
//! acted on when the room opens again**, driven through the **shipped `vox` binary** and the real
//! `vox tui` in a pty.
//!
//! **The claim.** Removing a member from the keyring stops this node reading it (V210-118) and
//! changes the lock so it stops reading this node (ADR-020 §3). A room a person closed in the TUI
//! stays closed across restarts and its key is not held, so neither could reach it: after the
//! reopen each side went on reading the other, and re-trusting the member never restored this
//! node's reading of it there. The removal is now recorded for the closed room and acted on when it
//! opens: the member's keys are dropped and the lock changes.
//!
//! **And a key goes only to a member the owner trusts** (V210-148). There are rooms, nodes and
//! trust, and no per-room grant beside them: the TUI's `:consent grant` is gone, and the node
//! itself refuses to release a key to a member its keyring does not name, whatever a client asks.
//! So carol, admitted to C but never trusted by bob, reads nothing bob writes, until bob trusts her.
//!
//! **Staging.** Alice, bob and carol, three daemons on loopback, no anchor. Alice creates room C;
//! bob and carol join. Alice and bob trust each other; carol trusts bob; bob does not trust carol.
//! Alice posts until bob reads her. Bob's daemon stops and his real `vox tui` opens C, selects
//! carol, types `:consent grant`, posts `BOB-AFTER-GRANT` from the composer and keeps the TUI's node
//! up 20 s to deliver it, and `:close`s C (`tests/pty/tui_close_room.py`). Bob's daemon
//! starts with C closed (`[closed]`, or `PRODUCT (staging)`), bob removes alice from his ring, and
//! his daemon restarts with C's passphrase, which opens C.
//!
//! **Asserted:**
//! - (a) alice posts after the removal, and 20 s later bob renders **0** of those posts;
//! - (b) bob posts after the reopen, and 20 s later alice renders **0** of them, and carol, whom bob
//!   never trusted, renders **0** of them;
//! - (c) bob trusts alice again, and within 120 s renders alice's posts made after that, and those
//!   from (a) too (they reached him; only her key was missing); alice renders bob's post made
//!   after the re-trust; and bob trusts carol, and within 120 s she renders his post made after
//!   it — the positive control for (b): bob's posts go out, and carol reads him once he trusts her;
//! - (d) `:consent grant` is not a command: the TUI answers "unknown command", and carol's row never
//!   shows her trusted;
//! - (e) bob's post right after it: alice, whom bob trusts, renders it (so it went out), and carol,
//!   whom he never trusted, renders **0** of it 10 s after alice has.
//!
//! **Mutations that must turn it red:** the key drop on opening disabled (`forget_untrusted_keys`
//! in `act_on_removals_while_closed`): (a) red. The lock change on opening disabled
//! (`revoke_untrusted_consents` there, and the `revoke` after it): (b) red for alice, and (c) red.
//! The TUI's `:consent grant` restored **with** the node's keyring check in `release_key_to` kept:
//! (e) holds — the node refuses the key — and only (d) is red. Restored with that check removed:
//! (e) red, as PRODUCT: carol reads bob's post. ((b) stays 0 for carol even then: the reopen
//! withdraws any consent to a member the keyring does not name.)

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::io::Write;
use std::path::Path;
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
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("APPARATUS (harness): spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS (harness): vox stdin")
            .write_all(text.as_bytes())
            .expect("APPARATUS (harness): write vox stdin");
        drop(child.stdin.take());
    }
    let out = child
        .wait_with_output()
        .expect("APPARATUS (harness): wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` with `stdin` piped in (the identity passphrase, then any room passphrase
/// lines), its output to files by the profile, and wait until its socket answers.
fn daemon(dir: &Path, tag: &str, stdin: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out")))
        .expect("APPARATUS (harness): the daemon's stdout file");
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS (harness): the daemon's stderr file");
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS (harness): spawn vox daemon");
    // Write, then close: the daemon reads stdin to EOF before it binds its socket.
    let mut pipe = child
        .stdin
        .take()
        .expect("APPARATUS (harness): daemon stdin");
    pipe.write_all(stdin.as_bytes())
        .expect("APPARATUS (harness): write daemon stdin");
    drop(pipe);
    let d = Daemon(child);
    attached(dir, tag);
    d
}

/// `vox room list` once the daemon's socket answers.
fn attached(dir: &Path, tag: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (ok, out, err) = vox(dir, &["room", "list"], None);
        if ok {
            return out;
        }
        last = err;
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "PRODUCT (staging): {tag}'s `vox daemon` never answered `vox room list`: {last}\nits stderr: {}",
        std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
    );
}

fn reads(dir: &Path, room: &str, text: &str) -> bool {
    vox(dir, &["room", "read", room], None)
        .1
        .lines()
        .any(|l| l.ends_with(&format!(" {text}")))
}

fn count(dir: &Path, room: &str, tag: &str) -> usize {
    vox(dir, &["room", "read", room], None)
        .1
        .lines()
        .filter(|l| l.contains(tag))
        .count()
}

fn until(within: Duration, mut ok: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(
        ok,
        "PRODUCT (staging): `vox room post` of {text} was refused: {err}"
    );
}

#[test]
#[ignore = "three real daemons and `vox tui` in a pty, with production Argon2id; CI runs it in release"]
fn a_member_removed_while_its_room_was_closed_is_acted_on_when_it_opens() {
    watchdog::arm_for(Duration::from_secs(1300));
    let tmp = tempfile::tempdir().expect("APPARATUS (harness): a temporary directory");
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    let carol = tmp.path().join("carol");
    let mut fps = Vec::new();
    for d in [&alice, &bob, &carol] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS (harness): a profile directory");
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
        fps.push(out.trim().to_owned());
    }
    let trust = |who: &Path, whom: usize, name: &str| {
        let (ok, _, err) = vox(who, &["trust", "add", &fps[whom], "--name", name], None);
        assert!(
            ok,
            "PRODUCT (staging): `vox trust add` of {name} failed: {err}"
        );
    };
    trust(&alice, 1, "bob");
    trust(&bob, 0, "alice");
    trust(&carol, 1, "bob");

    let _alice_d = daemon(&alice, "alice", &format!("{IDENTITY}\n"));
    let bob_d = daemon(&bob, "bob-1", &format!("{IDENTITY}\n"));
    let _carol_d = daemon(&carol, "carol", &format!("{IDENTITY}\n"));
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "c"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room create` failed: {err}");
    let room = attached(&alice, "alice")
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): `vox room list` names no room after `vox room create`")
        .to_owned();
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): `vox room invite` failed: {err}");
    for (d, who) in [(&bob, "bob"), (&carol, "carol")] {
        let (ok, _, err) = vox(
            d,
            &[
                "room",
                "join",
                "--passphrase-file",
                "-",
                link.trim(),
                "--name",
                "c",
            ],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "PRODUCT (staging): {who}'s `vox room join` failed: {err}"
        );
    }
    // Bob reads alice before anything else happens.
    let mut n = 0;
    let read_before = until(Duration::from_secs(120), || {
        n += 1;
        post(&alice, &room, &format!("ALICE-BEFORE {n}"));
        // Any of them: the one just posted has not had time to arrive.
        count(&bob, &room, "ALICE-BEFORE") > 0
    });
    assert!(
        read_before,
        "PRODUCT (staging): bob, who trusts alice and is trusted by her, never read her posts in 120 s"
    );

    // ---- bob's TUI: `:consent grant` on carol (never trusted), then `:close` C -------------
    drop(bob_d);
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_close_room.py");
    let out = pty_driver::run(
        script,
        &[
            VOX,
            &bob.to_string_lossy(),
            &bob.join("cfg").to_string_lossy(),
            IDENTITY,
            ROOMPASS,
            "closed",
            &fps[2][..26],
        ],
    );
    let said = out.stdout.clone();
    println!("[proof] tui: {}", said.trim());
    assert!(
        out.has_verdict("closed"),
        "APPARATUS (watchdog): the TUI driver was stopped before a verdict, at stage {:?} (exit \
         {:?}): {said}",
        out.stage,
        out.code
    );
    assert!(
        !said.contains("closed APPARATUS"),
        "APPARATUS (harness): the TUI driver's own fault (exit {:?}): {said}",
        out.code
    );
    assert!(
        out.code == Some(0) && said.contains("closed the TUI said done to :close"),
        "PRODUCT (staging): bob's `vox tui` did not close room C as a person does; exit {:?} at \
         stage {:?}:\n{said}",
        out.code,
        out.stage
    );

    // ---- (e) bob's post right after `:consent grant`: alice reads it, carol does not -------------
    assert!(
        said.contains("closed posted BOB-AFTER-GRANT"),
        "PRODUCT (staging): bob's `vox tui` did not post from its composer after `:consent grant`: \
         {said}"
    );
    let e_alice = until(Duration::from_secs(60), || {
        reads(&alice, &room, "BOB-AFTER-GRANT")
    });
    assert!(
        e_alice,
        "PRODUCT (staging): alice, who trusts bob and is trusted by him, never read the post bob made \
         in his TUI, so carol not reading it would show nothing"
    );
    std::thread::sleep(Duration::from_secs(10));
    let e_carol = count(&carol, &room, "BOB-AFTER-GRANT");
    println!("[proof] (e) carol renders {e_carol} of bob's post made after `:consent grant`");

    // ---- with C closed, bob removes alice from his ring ---------------------------------------
    let bob_d = daemon(&bob, "bob-2", &format!("{IDENTITY}\n"));
    let line = attached(&bob, "bob-2");
    assert!(
        line.lines().any(|l| l.contains("[closed]")),
        "PRODUCT (staging): room C, closed in the TUI, is open again when bob's daemon restarts: {line}"
    );
    let (ok, o, e) = vox(&bob, &["trust", "remove", &fps[0]], None);
    assert!(
        ok,
        "PRODUCT (staging): bob's `vox trust remove` of alice failed: {o}{e}"
    );
    drop(bob_d);

    // ---- C opens again: its passphrase to bob's daemon ----------------------------------------
    let _bob_d = daemon(&bob, "bob-3", &format!("{IDENTITY}\n{ROOMPASS}\n"));
    let line = attached(&bob, "bob-3");
    assert!(
        !line.lines().any(|l| l.contains("[closed]")),
        "PRODUCT (staging): `vox daemon`, given room C's passphrase, did not open C: {line}"
    );

    // ---- (a) alice's posts after the removal stay unreadable to bob ---------------------------
    for k in 1..=3 {
        post(&alice, &room, &format!("ALICE-AFTER-REMOVAL {k}"));
    }
    std::thread::sleep(Duration::from_secs(20));
    let a = count(&bob, &room, "ALICE-AFTER-REMOVAL");
    println!("[proof] (a) bob renders {a} of alice's 3 posts made after he removed her");

    // ---- (b) bob's posts after the reopen: neither alice nor carol reads them --------------------
    for k in 1..=3 {
        post(&bob, &room, &format!("BOB-AFTER-REOPEN {k}"));
    }
    std::thread::sleep(Duration::from_secs(20));
    let b = count(&alice, &room, "BOB-AFTER-REOPEN");
    let b_carol = count(&carol, &room, "BOB-AFTER-REOPEN");
    println!("[proof] (b) after the reopen alice renders {b} of bob's 3 posts, carol {b_carol}");

    // ---- (c) bob trusts alice again and reads her again --------------------------------------
    let (ok, _, err) = vox(&bob, &["trust", "add", &fps[0], "--name", "alice"], None);
    assert!(
        ok,
        "PRODUCT (staging): bob's `vox trust add` of alice failed: {err}"
    );
    post(&alice, &room, "ALICE-AFTER-RETRUST");
    post(&bob, &room, "BOB-AFTER-RETRUST");
    let t0 = Instant::now();
    let c = until(Duration::from_secs(120), || {
        reads(&bob, &room, "ALICE-AFTER-RETRUST") && reads(&bob, &room, "ALICE-AFTER-REMOVAL 3")
    });
    // And the other direction: alice, who never stopped trusting bob, reads him again too.
    let c_alice = until(Duration::from_secs(120), || {
        reads(&alice, &room, "BOB-AFTER-RETRUST")
    });
    println!(
        "[proof] (c) bob reads alice again after trusting her: {c}; alice reads bob again: \
         {c_alice} ({:?})",
        t0.elapsed()
    );
    // And carol, once bob trusts her: the positive control for (b).
    let (ok, _, err) = vox(&bob, &["trust", "add", &fps[2], "--name", "carol"], None);
    assert!(
        ok,
        "PRODUCT (staging): bob's `vox trust add` of carol failed: {err}"
    );
    post(&bob, &room, "BOB-AFTER-TRUSTING-CAROL");
    let c_carol = until(Duration::from_secs(120), || {
        reads(&carol, &room, "BOB-AFTER-TRUSTING-CAROL")
    });
    println!("[proof] (c) carol reads bob once he trusts her: {c_carol}");

    assert_eq!(
        a, 0,
        "PRODUCT: (a) bob renders {a} of alice's posts made after he removed her from his ring \
         while room C was closed: her keys were not dropped when C opened"
    );
    assert_eq!(
        b, 0,
        "PRODUCT: (b) alice renders {b} of bob's posts made after he removed her while room C was \
         closed: the lock did not change when C opened"
    );
    assert_eq!(
        b_carol, 0,
        "PRODUCT: (b) carol, whom bob never trusted, renders {b_carol} of his posts in room C: his \
         node released her his key (V210-148). The TUI said: {said}"
    );
    assert!(
        c,
        "PRODUCT: (c) bob trusted alice again, yet within 120 s he does not read her posts in \
         room C (after the re-trust, and those after the removal): her key never came back"
    );
    assert!(
        c_alice,
        "PRODUCT: (c) bob trusted alice again, yet within 120 s she does not read his post made \
         after it in room C: his key never came back to her"
    );
    assert!(
        c_carol,
        "PRODUCT: (c) bob trusted carol, yet within 120 s she does not read his post made after it \
         in room C: so (b)'s zero for her may only mean his posts never went out"
    );
    assert_eq!(
        e_carol, 0,
        "PRODUCT: (e) carol, whom bob never trusted, renders bob's post made after `:consent \
         grant`: his node released her his key (V210-148). The TUI said: {said}"
    );
    assert!(
        said.contains("closed :consent grant is not a command"),
        "PRODUCT: (d) bob's `vox tui` still takes `:consent grant`, a per-room grant outside the \
         keyring (V210-148): {said}"
    );
    assert!(
        !said
            .lines()
            .filter(|l| l.contains(":consent grant answered"))
            .any(|l| l
                .rsplit("row then:")
                .next()
                // The row says "not trusted · …" for a member bob does not trust (the members
                // pane's mark mirrors trust): only a "trusted" outside that phrase is a red.
                .is_some_and(|row| row.replace("not trusted", "").contains("trusted"))),
        "PRODUCT: (d) after `:consent grant`, bob's TUI shows carol trusted: {said}"
    );
}
