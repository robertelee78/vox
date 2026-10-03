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
//! ## An ordinary gate (#192)
//!
//! It was written failing, when a cross-process join through an anchor failed 40–80% of the time,
//! and reported **unproven** under the `cross-process-join` and `cross-process-tunnel` allowances
//! while that defect was open. The allowances are gone: a join that fails here, or a tunnel that
//! does not carry, is red, whatever `VOX_PROOF_ALLOW_UNPROVEN` says.
//!
//! **What is and is not known (ADR-018, "No proof is excluded by name").** One red was seen after
//! the allowances were withdrawn (on 005b801, `Unreachable`), and it has not recurred in the runs
//! since. Its cause is **not named**, and those runs bound its rate; they do not show it is gone.
//! What changed is that the next red names itself:
//!
//! - `vox room join` now says **which side** was unreachable — the board, named as the room's
//!   host or an anchor (`BoardUnreachable`), or every member it knows (`Unreachable`) — and
//!   prints the join's recorded steps and what each responder said, so the failing step is in
//!   the error;
//! - each daemon's and the anchor's output is read line by line as it is written (the shared
//!   harness's `VoxProc`), so a red prints what they said up to that moment. It used to read
//!   stderr to EOF, which only arrives when the child exits — after the panic — so every red's
//!   daemon and anchor sections were empty.
//!
//! Mutation: a join with a wrong room passphrase is red, and its panic shows non-empty daemon and
//! anchor sections; an anchor killed between the invite and the join is red with the anchor named.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::Write;
use std::process::{Command, Stdio};

use world::{VoxProc, IDENTITY, VOX};

/// One `vox` command, run to completion.
fn vox(dir: &std::path::Path, args: &[String], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // Not `--identity-passphrase`: a command line is world-readable while the process
        // runs, so the flag is refused (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        // Work coordination is owned per session (ADR-021 §4). Name one, and never let
        // a session the test process inherited from its own harness leak in.
        .env_remove("CLAUDE_CODE_SESSION_ID")
        .env_remove("CODEX_THREAD_ID")
        .env("VOX_SESSION", "cross-process")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: stdin")
            .write_all(text.as_bytes())
            .expect("PRODUCT (staging): vox exited without reading its stdin");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("APPARATUS: wait");
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
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let anchor_dir = tmp.path().join("anchor");
    let alice_dir = tmp.path().join("alice");
    let bob_dir = tmp.path().join("bob");
    for d in [&anchor_dir, &alice_dir, &bob_dir] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
    }
    let idpass = tmp.path().join("identity-passphrase");
    std::fs::write(&idpass, format!("{IDENTITY}\n")).expect("APPARATUS: write a staging file");
    let roompass = "the room passphrase";

    // ---- the anchor: what makes this cross-process rather than loopback ----
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &["node".into(), "--listen".into(), "127.0.0.1:0".into()],
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
        "PRODUCT: an anchor spec must be dialable, not a wildcard bind: {spec}"
    );

    // ---- identities, headless. `vox id` bootstraps one on a fresh profile ----
    let mut fps = Vec::new();
    for dir in [&alice_dir, &bob_dir] {
        let (ok, out, err) = vox(dir, &["id".into()], None);
        assert!(
            ok,
            "PRODUCT: vox id must bootstrap an identity headlessly: {err}"
        );
        fps.push(out.trim().to_owned());
    }
    let (alice_fp, bob_fp) = (fps[0].clone(), fps[1].clone());
    assert_eq!(
        alice_fp.len(),
        52,
        "PRODUCT: a fingerprint pipes as one line: {alice_fp:?}"
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
        assert!(ok, "PRODUCT (staging): vox trust add {name}: {err}");
    }

    // ---- daemons: agent comms with no terminal anywhere ----
    let mut daemons = Vec::new();
    for (name, dir) in [("alice", &alice_dir), ("bob", &bob_dir)] {
        let mut d = VoxProc::spawn(
            name,
            dir,
            &[
                "daemon".into(),
                "--listen".into(),
                "127.0.0.1:0".into(),
                "--anchor".into(),
                spec.clone(),
                "--passphrase-file".into(),
                idpass.to_string_lossy().into_owned(),
            ],
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
    assert!(
        ok,
        "PRODUCT (staging): vox room create on a running daemon: {err}"
    );
    let listed = until(
        &alice_dir,
        "the room to appear",
        &["room".into(), "list".into()],
        30,
        |o| o.contains("mission"),
    )
    .expect("PRODUCT: alice's room");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("PRODUCT: a room id in `room list`")
        .to_owned();

    let (ok, link, err) = vox(
        &alice_dir,
        &["room".into(), "invite".into(), room.clone()],
        None,
    );
    assert!(ok, "PRODUCT (staging): vox room invite: {err}");
    let link = link.trim().to_owned();
    assert!(
        link.starts_with("vox://"),
        "PRODUCT: an address, not prose: {link:?}"
    );
    assert!(
        !link.contains(roompass),
        "PRODUCT: the address must never carry the passphrase: {link}"
    );

    // ---- THE ACT UNDER TEST: bob joins, in a different process, through the anchor ----
    let started = std::time::Instant::now();
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
    let took = started.elapsed().as_secs_f64();
    println!(
        "[proof] bob's join: {} in {took:.2}s",
        if ok { "joined" } else { "FAILED" }
    );
    if !ok {
        // **A red says why** (#192): the join's own error — which side was unreachable, the steps
        // it took, what each responder said — and what each daemon and the anchor printed up to
        // this moment, read line by line as they wrote it.
        println!("[proof] bob's join said:\n{err}");
        let transcript = format!(
            "--- alice's daemon ---\n{}\n--- bob's daemon ---\n{}\n--- the anchor ---\n{}",
            daemons[0].transcript(),
            daemons[1].transcript(),
            anchor.transcript()
        );
        panic!(
            "PRODUCT: a cross-process join through an anchor failed after {took:.2}s — {err}\n{transcript}"
        );
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
    assert!(ok, "PRODUCT (staging): alice posts: {err}");
    until(
        &bob_dir,
        "alice's message to reach bob across processes",
        &["room".into(), "read".into(), room.clone()],
        60,
        |o| o.contains("port the wire codec"),
    )
    .expect("PRODUCT: the message crosses");

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
    assert!(ok, "PRODUCT: bob claims: stdout={out:?} stderr={err:?}");
    assert!(
        out.contains("you hold port-the-codec"),
        "PRODUCT: bob's claim did not say he holds it: {out:?}"
    );
    until(
        &alice_dir,
        "bob's claim to reach alice",
        &["room".into(), "board".into(), room],
        60,
        |o| o.contains("port-the-codec"),
    )
    .expect("PRODUCT: the claim crosses");

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
    std::fs::write(&source, &payload).expect("APPARATUS: write a staging file");

    let mut offer = VoxProc::spawn(
        "alice-send",
        &alice_dir,
        &[
            "room".into(),
            "send".into(),
            room_for_file.clone(),
            source.to_string_lossy().into_owned(),
        ],
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
    .expect("PRODUCT: the announcement crosses");

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
        panic!(
            "PRODUCT: a file transfer across processes failed — {err}\n`vox room send|get` rides a \
             room-bound service and a `Forward`\n--- alice's send ---\n{}\n--- alice's daemon \
             ---\n{}\n--- bob's daemon ---\n{}",
            offer.transcript(),
            daemons[0].transcript(),
            daemons[1].transcript()
        );
    }
    assert!(
        out.contains("verified"),
        "PRODUCT: the collector must verify: {out:?}"
    );
    let got = std::fs::read(&dest).expect("PRODUCT: the collected file");
    assert!(
        got == payload,
        "PRODUCT: the bytes differ across the overlay: got {} of {}",
        got.len(),
        payload.len()
    );

    drop(offer);
    drop(daemons);
    drop(anchor);
}
