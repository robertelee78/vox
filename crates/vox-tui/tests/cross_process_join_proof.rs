//! ADR-020 §12 / M19.10 — **agent comms across processes, through an anchor**, the
//! shape the feature's own premise requires and every other proof of mine avoids.
//!
//! ADR-020's first paragraph says agent sessions may be "on the same host, or
//! n-count remote hosts". Every agent-comms proof written before this one joins two
//! **in-process** nodes over loopback with no anchor in the path, so none of them
//! can see a defect in the anchor-mediated join — and there is one, recorded in
//! ADR-016 and ADR-012 with measurements. A gate that cannot fail for the reason
//! the feature is most likely to break is not evidence about that reason.
//!
//! It also proves something that was impossible until this milestone. `vox daemon`
//! (M19.5c) let a node hold rooms with no terminal, but **nothing could put a room
//! on it**: creating and joining were TUI-only, so an agent on a remote machine
//! could run a daemon forever and never have anything in it. `vox room
//! create|invite|join` close that, and this drives the whole chain as an operator
//! would type it:
//!
//! ```text
//! vox id                     # bootstrap an identity, print the fingerprint
//! vox daemon                 # hold the profile, serve the control socket
//! vox room create            # a room, on the daemon
//! vox room invite            # its address, to send to the other host
//! vox trust add <fpr>        # the decision: who may read me
//! vox room join <address>    # the other host joins, through the anchor
//! vox room post / read       # and they talk
//! ```
//!
//! ## Honest coverage
//!
//! The join defect in ADR-016 is open: a cross-process join through an anchor fails
//! a large fraction of the time, measured between 40% and 80% depending on the
//! tree. While it is open this proof reports **unproven** rather than red, named as
//! `cross-process-join` — the repo's idiom for a gap that is a deliberate, visible
//! decision rather than a silence or a false green. When the defect closes, the
//! allowance comes off and this becomes an ordinary gate.
//!
//! It is written now, failing, on purpose: it gives that fix an agent-comms-shaped
//! acceptance test, the same way the NAT gate became one for the accept-loop split.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

fn allow_unproven(name: &str) -> bool {
    std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .any(|s| s.trim().eq_ignore_ascii_case(name))
}

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

#[test]
#[ignore = "three real vox processes, a real anchor and production Argon2id; CI runs it in release"]
fn two_agents_on_separate_processes_join_through_an_anchor_and_talk() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let anchor_dir = tmp.path().join("anchor");
    let alice_dir = tmp.path().join("alice");
    let bob_dir = tmp.path().join("bob");
    for d in [&anchor_dir, &alice_dir, &bob_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let idpass = "an identity passphrase\n";
    let roompass = "the room passphrase";

    // ---- the anchor: what makes this cross-process rather than loopback ----
    let mut anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &["node".into(), "--listen".into(), "127.0.0.1:0".into()],
        None,
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    assert!(
        !spec.contains("0.0.0.0"),
        "an anchor spec must be dialable, not a wildcard bind: {spec}"
    );

    // ---- identities, headless. `vox id` bootstraps one on a fresh profile ----
    let mut fps = Vec::new();
    for dir in [&alice_dir, &bob_dir] {
        let (ok, out, err) = vox(dir, &["id".into()], None);
        assert!(ok, "vox id must bootstrap an identity headlessly: {err}");
        fps.push(out.trim().to_owned());
    }
    let (alice_fp, bob_fp) = (fps[0].clone(), fps[1].clone());
    assert_eq!(
        alice_fp.len(),
        52,
        "a fingerprint pipes as one line: {alice_fp:?}"
    );

    // ---- the decision, before any daemon holds the profile (redb is single-writer) ----
    for (dir, fp, name) in [(&alice_dir, &bob_fp, "bob"), (&bob_dir, &alice_fp, "alice")] {
        let (ok, _, err) = vox(
            dir,
            &[
                "trust".into(),
                "add".into(),
                fp.clone(),
                "--name".into(),
                name.into(),
            ],
            None,
        );
        assert!(ok, "vox trust add {name}: {err}");
    }

    // ---- daemons: agent comms with no terminal anywhere ----
    let mut daemons = Vec::new();
    for (name, dir) in [("alice", &alice_dir), ("bob", &bob_dir)] {
        let mut d = Proc::spawn(
            if name == "alice" { "alice" } else { "bob" },
            dir,
            &[
                "daemon".into(),
                "--listen".into(),
                "127.0.0.1:0".into(),
                "--anchor".into(),
                spec.clone(),
            ],
            Some(idpass),
        );
        d.expect_line("its control socket", |l| l.contains("control socket"));
        daemons.push(d);
    }

    // ---- alice creates a room on her daemon and mints its address ----
    let (ok, _, err) = vox(
        &alice_dir,
        &[
            "room".into(),
            "create".into(),
            "--name".into(),
            "mission".into(),
        ],
        Some(&format!("{roompass}\n")),
    );
    assert!(ok, "vox room create on a running daemon: {err}");
    let listed = until(
        &alice_dir,
        "the room to appear",
        &["room".into(), "list".into()],
        30,
        |o| o.contains("mission"),
    )
    .expect("alice's room");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("a room id in `room list`")
        .to_owned();

    let (ok, link, err) = vox(
        &alice_dir,
        &["room".into(), "invite".into(), room.clone()],
        None,
    );
    assert!(ok, "vox room invite: {err}");
    let link = link.trim().to_owned();
    assert!(
        link.starts_with("vox://"),
        "an address, not prose: {link:?}"
    );
    assert!(
        !link.contains(roompass),
        "the address must never carry the passphrase: {link}"
    );

    // ---- THE ACT UNDER TEST: bob joins, in a different process, through the anchor ----
    let (ok, _, err) = vox(
        &bob_dir,
        &[
            "room".into(),
            "join".into(),
            link.clone(),
            "--name".into(),
            "mission".into(),
        ],
        Some(&format!("{roompass}\n")),
    );
    if !ok {
        assert!(
            allow_unproven("cross-process-join"),
            "UNPROVEN: a cross-process join through an anchor failed — {err}\n\
             This is the open defect in ADR-016/ADR-012, not a regression in agent comms. \
             Set VOX_PROOF_ALLOW_UNPROVEN=cross-process-join to accept it deliberately; \
             remove that allowance when the defect closes and this becomes a real gate."
        );
        eprintln!("UNPROVEN (allowed): cross-process join failed: {err}");
        return;
    }

    // ---- and they talk, over the overlay, as agents ----
    let room_for_file = room.clone();
    let room_for_announce = room.clone();
    let (ok, _, err) = vox(
        &alice_dir,
        &[
            "room".into(),
            "post".into(),
            room.clone(),
            "PLAN: port the wire codec".into(),
        ],
        None,
    );
    assert!(ok, "alice posts: {err}");
    until(
        &bob_dir,
        "alice's message to reach bob across processes",
        &["room".into(), "read".into(), room.clone()],
        60,
        |o| o.contains("port the wire codec"),
    )
    .expect("the message crosses");

    // A claim, so the work board is exercised across processes too.
    let (ok, out, err) = vox(
        &bob_dir,
        &[
            "room".into(),
            "claim".into(),
            room.clone(),
            "port-the-codec".into(),
        ],
        None,
    );
    assert!(ok, "bob claims: stdout={out:?} stderr={err:?}");
    assert!(out.contains("you hold port-the-codec"), "{out:?}");
    until(
        &alice_dir,
        "bob's claim to reach alice",
        &["room".into(), "board".into(), room],
        60,
        |o| o.contains("port-the-codec"),
    )
    .expect("the claim crosses");

    // ---- the file leg: agent-comms file transfer, across processes ----
    //
    // This is a **different subsystem** from everything above. Posting and claiming
    // ride the log and its sync; `vox room send|get` rides a room-bound service and
    // a `Forward` — a QUIC tunnel over the overlay. ADR-012 currently records that
    // path failing at establishment and mid-stream, so this leg is expected to be
    // the flaky one, and it is named separately for exactly that reason: a single
    // allowance covering both would let a tunnel regression hide behind a join
    // defect, or the reverse.
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let source = tmp.path().join("artifact.bin");
    std::fs::write(&source, &payload).unwrap();

    let mut offer = Proc::spawn(
        "alice-send",
        &alice_dir,
        &[
            "room".into(),
            "send".into(),
            room_for_file.clone(),
            source.to_string_lossy().into_owned(),
        ],
        None,
    );
    offer.expect_line("the offer's announcement", |l| l.contains("offering"));

    // The announcement is a log entry and has to reach bob before he can ask for it.
    // Without this wait the collector reports "no offer in this room matches", which
    // is the *test* being early rather than the transfer failing — a distinction the
    // error message makes and an earlier version of this leg did not respect.
    until(
        &bob_dir,
        "the file announcement to reach bob",
        &["room".into(), "read".into(), room_for_announce.clone()],
        60,
        |o| o.contains("artifact.bin"),
    )
    .expect("the announcement crosses");

    let dest = tmp.path().join("collected.bin");
    let (ok, out, err) = vox(
        &bob_dir,
        &[
            "room".into(),
            "get".into(),
            room_for_file,
            "artifact.bin".into(),
            "--out".into(),
            dest.to_string_lossy().into_owned(),
        ],
        None,
    );
    if !ok {
        assert!(
            allow_unproven("cross-process-tunnel"),
            "UNPROVEN: a file transfer across processes failed — {err}\n\
             `vox room send|get` rides a room-bound service and a `Forward`, which is \
             the tunnel path ADR-012 records as failing at establishment and mid-stream. \
             Set VOX_PROOF_ALLOW_UNPROVEN=cross-process-tunnel to accept it deliberately; \
             remove the allowance when that path is fixed."
        );
        eprintln!("UNPROVEN (allowed): cross-process file transfer failed: {err}");
        drop(offer);
        drop(daemons);
        drop(anchor);
        return;
    }
    assert!(
        out.contains("verified"),
        "the collector must verify: {out:?}"
    );
    let got = std::fs::read(&dest).expect("the collected file");
    assert!(
        got == payload,
        "the bytes differ across the overlay: got {} of {}",
        got.len(),
        payload.len()
    );

    drop(offer);
    drop(daemons);
    drop(anchor);
}
