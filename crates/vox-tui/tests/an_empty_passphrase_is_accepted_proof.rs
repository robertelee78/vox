//! **An empty identity or room passphrase is accepted** (V030-36) — proved with nothing but the
//! shipped `vox`: a `vox node` anchor and three `vox daemon`s, every step as an operator or an
//! agent's harness types it. The decider, 2026-10-02: "passphrase is a good idea, but is
//! technically optional". The node takes an empty one; the CLI says one line encouraging a
//! passphrase and goes on.
//!
//! 1. `vox id`, `vox trust add` and `vox daemon` make and unlock identities with no passphrase:
//!    given as `VOX_IDENTITY_PASSPHRASE` set to nothing, an empty line on a daemon's stdin, and an
//!    empty `--passphrase-file`. Each says the encouraging line and succeeds.
//! 2. `vox room create` makes a room with no passphrase (an empty line on `--passphrase-file -`),
//!    saying the line.
//! 3. A join to that room with a wrong, non-empty passphrase is refused, naming the passphrase.
//! 4. A join with no passphrase (an empty `--passphrase-file`) gets in, and the two members read
//!    each other's posts both ways.
//!
//! Each was refused before: "an empty identity passphrase; nothing was created", "no identity
//! passphrase", "expected a passphrase for the new room in stdin, and it is empty", and the node
//! read a room retained with an empty passphrase as locked, so it could never answer a join.
//!
//! Mutation: the room's empty passphrase read as locked again (`join_passphrase` refusing an
//! empty one) — red, PRODUCT (claim 4: the join is refused).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

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
            .env_remove("VOX_IDENTITY_PASSPHRASE")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn {name}: {e}"));
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .expect("APPARATUS: no stdin pipe")
                .write_all(text.as_bytes())
                .unwrap_or_else(|e| panic!("APPARATUS: cannot write {name}'s stdin: {e}"));
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
        let reader = self.out.as_mut().expect("APPARATUS: no stdout pipe");
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
            "PRODUCT (staging): {} never printed {what}; saw: {seen:#?}\nits stderr:\n{err}",
            self.name
        );
    }
}

/// One `vox` command, run to completion.
/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox(dir: &std::path::Path, args: &[String], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = args.iter().map(String::as_str).collect();
    match attach::needs(dir, &verb) {
        Some(node) => attach::Root::at(dir, "").attached(&node, || vox_plain(dir, args, stdin)),
        None => vox_plain(dir, args, stdin),
    }
}

fn vox_plain(
    dir: &std::path::Path,
    args: &[String],
    stdin: Option<&str>,
) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // Set, and empty: an identity with no passphrase, given on purpose (V030-36).
        .env("VOX_IDENTITY_PASSPHRASE", "")
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox: {e}"));
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: no stdin pipe")
            .write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write vox's stdin: {e}"));
        drop(child.stdin.take());
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot wait for vox: {e}"));
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

/// The line the CLI says when a passphrase is left empty.
const ENCOURAGED: &str = "A passphrase is encouraged.";

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

#[test]
#[ignore = "four real vox processes, a real anchor and production Argon2id; run on demand"]
fn an_empty_identity_and_room_passphrase_are_accepted() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: cannot make a profile directory");
        d
    };
    let (anchor_dir, alice, bob, carol) = (dir("anchor"), dir("alice"), dir("bob"), dir("carol"));
    // A file with nothing in it: a passphrase given, and empty.
    let empty_file = tmp.path().join("empty-passphrase");
    std::fs::write(&empty_file, b"").expect("APPARATUS: cannot write the empty passphrase file");
    let empty_file = empty_file
        .to_str()
        .expect("APPARATUS: the temp path is not UTF-8")
        .to_owned();

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

    // ---- claim 1: identities with no passphrase, made and unlocked ----
    let fp = |d: &std::path::Path| {
        let (ok, out, err) = vox(d, &s(&["id"]), None);
        assert!(
            ok,
            "PRODUCT: `vox id` with VOX_IDENTITY_PASSPHRASE set to nothing did not make an \
             identity: {err}"
        );
        assert!(
            err.contains(ENCOURAGED),
            "PRODUCT: `vox id` with no passphrase did not encourage one: {err:?}"
        );
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp) = (fp(&alice), fp(&bob));
    let _ = fp(&carol);
    for (d, who, name) in [(&alice, &bob_fp, "bob"), (&bob, &alice_fp, "alice")] {
        let (ok, _, err) = vox(d, &s(&["trust", "add", who, "--name", name]), None);
        assert!(
            ok,
            "PRODUCT: `vox trust add {name}` did not unlock an identity with no passphrase: {err}"
        );
    }
    // Alice and Carol give it as an empty line on stdin, Bob as an empty file.
    let mut daemons = Vec::new();
    for (name, d, file) in [
        ("alice", &alice, false),
        ("bob", &bob, true),
        ("carol", &carol, false),
    ] {
        let mut args = s(&["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec]);
        if file {
            args.extend(s(&["--passphrase-file", &empty_file]));
        }
        let mut p = Proc::spawn(name, d, &args, (!file).then_some("\n"));
        p.expect_line("its control socket", |l| l.contains("control socket"));
        daemons.push(p);
    }

    // ---- claim 2: a room with no passphrase ----
    let (ok, _, err) = vox(
        &alice,
        &s(&["room", "create", "--passphrase-file", "-", "--name", "open"]),
        Some("\n"),
    );
    assert!(
        ok,
        "PRODUCT: `vox room create` refused an empty room passphrase: {err}"
    );
    assert!(
        err.contains(ENCOURAGED),
        "PRODUCT: `vox room create` with no passphrase did not encourage one: {err:?}"
    );
    let listed = until(&alice, "the room", &s(&["room", "list"]), 30, |o| {
        o.contains("open")
    })
    .unwrap_or_else(|e| panic!("PRODUCT (staging): alice's room never listed: {e}"));
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT (staging): no room id in `vox room list`: {listed:?}"))
        .to_owned();
    let (ok, link, err) = vox(&alice, &s(&["room", "invite", &room]), None);
    assert!(ok, "PRODUCT (staging): room invite failed: {err}");
    let link = link.trim().to_owned();

    // ---- claim 3: a wrong, non-empty passphrase is refused ----
    let (ok, out, err) = vox(
        &carol,
        &s(&[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "open",
        ]),
        Some("not empty\n"),
    );
    assert!(
        !ok,
        "PRODUCT: a non-empty passphrase joined a room made with none: stdout={out:?} \
         stderr={err:?}"
    );
    assert!(
        err.to_lowercase().contains("passphrase"),
        "PRODUCT: the refusal of a wrong passphrase must name the passphrase: {err:?}"
    );

    // ---- claim 4: no passphrase joins, and the two read each other ----
    let (ok, out, err) = vox(
        &bob,
        &s(&[
            "room",
            "join",
            "--passphrase-file",
            &empty_file,
            &link,
            "--name",
            "open",
        ]),
        None,
    );
    assert!(
        ok,
        "PRODUCT: bob could not join a room made with no passphrase, giving none: \
         stdout={out:?} stderr={err:?}"
    );
    assert!(
        err.contains(ENCOURAGED),
        "PRODUCT: `vox room join` with no passphrase did not encourage one: {err:?}"
    );
    let post = |d: &std::path::Path, text: &str| {
        let (ok, _, err) = vox(d, &s(&["room", "post", &room, text]), None);
        assert!(ok, "PRODUCT: vox room post {text} failed: {err}");
    };
    post(&alice, "FROM-ALICE");
    post(&bob, "FROM-BOB");
    let read = s(&["room", "read", &room]);
    until(&bob, "bob to read alice", &read, 90, |o| {
        o.contains("FROM-ALICE")
    })
    .unwrap_or_else(|e| panic!("PRODUCT: claim 4: bob never read alice: {e}"));
    until(&alice, "alice to read bob", &read, 90, |o| {
        o.contains("FROM-BOB")
    })
    .unwrap_or_else(|e| panic!("PRODUCT: claim 4: alice never read bob: {e}"));
    drop(daemons);
    drop(anchor);
}
