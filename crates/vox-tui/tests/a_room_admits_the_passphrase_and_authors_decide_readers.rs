//! **A room admits whoever holds the passphrase, and each author decides who may read them** —
//! proved with nothing but the shipped `vox`: a `vox node` anchor and three `vox daemon`s, every
//! step typed as an operator would.
//!
//! This replaces `node_m14_gate`, which proved the same claims with in-process nodes (V29-17:
//! a test counts only if it drives the shipped product). Its claims, now through real binaries:
//!
//! 1. **A wrong passphrase is refused**, and the refusal says so — Carol's first join, with the
//!    wrong passphrase, fails while the room's creator is up to check it.
//! 2. **The right passphrase joins**, through the anchor, in another process.
//! 3. **Two members who trust each other read each other, both ways.**
//! 4. **A member nobody consented to reads nothing of theirs** — Carol, joined and synced, never
//!    renders what Alice said, because Alice never trusted her.
//!
//! **Claim 4 carries a positive control, or it would prove nothing.** An absence passes just as
//! well when Carol's node never synced at all. So Bob *does* trust Carol, and she must render
//! Bob's message: that proves her node is receiving the room, and only then does Alice's
//! message staying absent mean the refusal works rather than the plumbing failing.
//!
//! No escape hatch: every join here must succeed. A failed join is a failed proof, not an
//! "unproven" pass.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// A long-running `vox` child, killed however the test ends.
struct Proc {
    name: &'static str,
    child: Child,
    out: Option<BufReader<ChildStdout>>,
    /// Everything the child wrote to stderr, drained continuously — see `spawn`.
    err: Arc<Mutex<String>>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proc {
    fn spawn(
        name: &'static str,
        dir: &std::path::Path,
        args: &[String],
        stdin: Option<&str>,
    ) -> Self {
        let mut cmd = Command::new(VOX);
        cmd.args(args)
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env_remove("VOX_ROOM")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {name}: {e}"));
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin")
                .write_all(text.as_bytes())
                .expect("write stdin");
            drop(child.stdin.take());
        }
        let out = child.stdout.take().map(BufReader::new);
        // **stderr is piped, so it must be read.** It was piped and never read, which is a
        // 64 KiB fuse on the child: once the pipe buffer fills, the daemon blocks in `write` and
        // the proof sees a node that has stopped doing anything, with no failure and no output —
        // a hang, and bimodal in exactly the shape ADR-018 recorded for this gate's own flake.
        // `vox daemon` now reports every event that explains a failure, so it writes more than it
        // used to and this fuse got shorter, not longer. Drained on a thread into a string the
        // panic below prints, so the bytes that were the hazard become the diagnosis.
        let err = Arc::new(Mutex::new(String::new()));
        if let Some(mut pipe) = child.stderr.take() {
            let sink = Arc::clone(&err);
            std::thread::spawn(move || {
                let mut buf = String::new();
                let _ = pipe.read_to_string(&mut buf);
                if let Ok(mut guard) = sink.lock() {
                    guard.push_str(&buf);
                }
            });
        }
        Self {
            name,
            child,
            out,
            err,
        }
    }

    /// Wait for a line matching `want`, so readiness is observed rather than slept on.
    fn expect_line(&mut self, what: &str, want: impl Fn(&str) -> bool) -> String {
        let reader = self.out.as_mut().expect("stdout");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let mut seen = Vec::new();
        while std::time::Instant::now() < deadline {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let l = line.trim_end().to_owned();
                    if want(&l) {
                        return l;
                    }
                    seen.push(l);
                }
                Err(_) => break,
            }
        }
        let err = self
            .err
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone());
        panic!(
            "{}: never printed {what}; saw: {seen:#?}\nits stderr:\n{err}",
            self.name
        );
    }
}

/// One `vox` command, run to completion.
fn vox(dir: &std::path::Path, args: &[String], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // Not `--identity-passphrase`: a command line is world-readable while the process
        // runs, so the flag is refused (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", "an identity passphrase")
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Poll a command until its stdout satisfies `ok`.
fn until(
    dir: &std::path::Path,
    what: &str,
    args: &[String],
    secs: u64,
    ok: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let (_, out, err) = vox(dir, args, None);
        last = format!("stdout={out:?} stderr={err:?}");
        if ok(&out) {
            return Ok(out);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!("timed out waiting for {what}; last saw {last}"))
}

const IDPASS: &str = "an identity passphrase\n";
const ROOMPASS: &str = "the room passphrase";

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

#[test]
#[ignore = "four real vox processes, a real anchor and production Argon2id; CI runs it in release"]
fn a_room_admits_the_passphrase_and_each_author_decides_who_reads_them() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, alice, bob, carol) = (dir("anchor"), dir("alice"), dir("bob"), dir("carol"));

    let mut anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &s(&["node", "--listen", "127.0.0.1:0"]),
        None,
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();

    // ---- identities, headless ----
    let fp = |d: &std::path::Path| {
        let (ok, out, err) = vox(d, &s(&["id"]), None);
        assert!(ok, "vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp, carol_fp) = (fp(&alice), fp(&bob), fp(&carol));

    // ---- the decisions, made before any daemon holds a profile ----
    // Alice and Bob trust each other. Bob trusts Carol. Alice does NOT trust Carol.
    for (d, who, name) in [
        (&alice, &bob_fp, "bob"),
        (&bob, &alice_fp, "alice"),
        (&bob, &carol_fp, "carol"),
        (&carol, &bob_fp, "bob"),
        (&carol, &alice_fp, "alice"),
    ] {
        let (ok, _, err) = vox(d, &s(&["trust", "add", who, "--name", name]), None);
        assert!(ok, "vox trust add {name}: {err}");
    }

    let mut daemons = Vec::new();
    for (name, d) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let mut p = Proc::spawn(
            name,
            d,
            &s(&["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec]),
            Some(IDPASS),
        );
        p.expect_line("its control socket", |l| l.contains("control socket"));
        daemons.push(p);
    }

    // ---- Alice makes the room and its address ----
    let (ok, _, err) = vox(
        &alice,
        &s(&["room", "create", "--name", "mission"]),
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "room create: {err}");
    let listed = until(&alice, "the room", &s(&["room", "list"]), 30, |o| {
        o.contains("mission")
    })
    .expect("alice's room");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("a room id")
        .to_owned();
    let (ok, link, err) = vox(&alice, &s(&["room", "invite", &room]), None);
    assert!(ok, "room invite: {err}");
    let link = link.trim().to_owned();

    // ---- claim 1: a wrong passphrase is refused, and the refusal names the passphrase ----
    let (ok, out, err) = vox(
        &carol,
        &s(&["room", "join", &link, "--name", "mission"]),
        Some("not the passphrase\n"),
    );
    assert!(
        !ok,
        "a wrong passphrase must not join: stdout={out:?} stderr={err:?}"
    );
    assert!(
        err.to_lowercase().contains("passphrase"),
        "the refusal must say the passphrase is the likely problem, since the creator is up to check it: {err:?}"
    );

    // ---- claim 2: the right passphrase joins, through the anchor ----
    for (name, d) in [("bob", &bob), ("carol", &carol)] {
        let (ok, out, err) = vox(
            d,
            &s(&["room", "join", &link, "--name", "mission"]),
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(
            ok,
            "{name} must join with the right passphrase: stdout={out:?} stderr={err:?}"
        );
    }

    // ---- claim 3: two members who trust each other read each other, both ways ----
    let post = |d: &std::path::Path, text: &str| {
        let (ok, _, err) = vox(d, &s(&["room", "post", &room, text]), None);
        assert!(ok, "post {text}: {err}");
    };
    post(&alice, "FROM-ALICE");
    post(&bob, "FROM-BOB");
    let read = s(&["room", "read", &room]);
    until(&bob, "bob to read alice", &read, 90, |o| {
        o.contains("FROM-ALICE")
    })
    .expect("claim 3: bob reads alice");
    until(&alice, "alice to read bob", &read, 90, |o| {
        o.contains("FROM-BOB")
    })
    .expect("claim 3: alice reads bob");

    // ---- claim 4, positive control first: Carol receives the member who trusts her ----
    //
    // A sender key is forward-only: Bob's key reaches Carol at some point after she joins, and
    // only what Bob writes after that is readable to her, by design. So the control is not "Carol
    // reads FROM-BOB" (posted before the release, it may never render) but "Carol reads *a* Bob
    // post made after the release": Bob keeps posting until one arrives.
    let control_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut n = 0;
    loop {
        n += 1;
        post(&bob, &format!("FROM-BOB-LATE-{n}"));
        if until(&carol, "carol to read a late bob post", &read, 5, |o| {
            o.contains("FROM-BOB-LATE-")
        })
        .is_ok()
        {
            break;
        }
        assert!(
            std::time::Instant::now() < control_deadline,
            "claim 4's control failed: in 120s Carol never rendered any post from Bob, who trusts \
             her, so an absence of Alice below would prove nothing"
        );
    }
    // ...and only now does Alice's absence mean something. She posts *after* Carol is provably
    // receiving keys, then Bob posts once more: once Carol renders Bob's last post she has synced
    // past Alice's, so Alice's absence is her decision and not an unsynced log.
    post(&alice, "FROM-ALICE-LATE");
    post(&bob, "FROM-BOB-FINAL");
    let carol_view = until(&carol, "carol to read bob's final post", &read, 90, |o| {
        o.contains("FROM-BOB-FINAL")
    })
    .unwrap_or_else(|e| panic!("claim 4's control failed after it had passed once: {e}"));
    assert!(
        !carol_view.contains("FROM-ALICE"),
        "claim 4: Carol rendered Alice, who never trusted her: {carol_view:?}"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        let (_, out, _) = vox(&carol, &read, None);
        assert!(
            !out.contains("FROM-ALICE"),
            "claim 4: Carol rendered Alice, who never trusted her: {out:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    drop(daemons);
    drop(anchor);
}
