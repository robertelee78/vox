//! #208 (V210-35) — a restarted `vox daemon` holds every room it held before, with **no room
//! passphrase given to it**, driven through the shipped `vox` binary.
//!
//! **The defect.** A room is double-locked at rest (ADR-010): its SEK is wrapped under the room
//! passphrase *and* the identity. `vox daemon` unlocks with the identity passphrase alone, so a
//! daemon that restarted came back holding no open room, and every `vox room` verb answered
//! `room "" is not open on this node` — an agent machine running only a daemon lost every room at
//! every reboot, and the error could not even say which room. The decider's answer: the daemon
//! reopens by itself every room it held open, from the room keys kept sealed under the identity.
//!
//! What this drives, as an operator would type it:
//!
//! ```text
//! vox id; vox trust add …               # alice and bob, consenting to each other
//! vox daemon                            # unlock once and remember; no passphrase on restarts
//! vox room create / post                # alice's room, one post
//! vox room link / vox room join       # bob joins it (the join path remembers too)
//! (kill -9 both daemons) vox daemon     # a crash: both rooms must be open again
//! (kill -TERM alice) vox daemon         # a clean stop: the same
//! ```
//!
//! What it does **not** drive: a room closed on purpose staying closed. Only `vox tui` closes a
//! room, so that half is not proven here.
//!
//! Mutations: make `reopen_remembered` return at once and this goes red at alice's first read
//! after the crash; take `remember_open` out of `finish_join_channel` and it goes red at bob's.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/optional_proof.rs"]
mod optional_proof;
#[cfg(feature = "optional-proofs")]
#[path = "support/test_knobs.rs"]
mod refresh_knobs;
#[path = "support/room.rs"]
mod refresh_room;
use refresh_room::{attach, typed};
optional_proof::not_run!(a_restarted_room_drives_its_session_refresh_to_ready);

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
const POST: &str = "said before any restart";

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    /// Stop it the way a service manager does, and wait for it to leave.
    fn terminate(mut self) {
        let pid = self.0.id().to_string();
        let ok = Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .expect("APPARATUS: run kill")
            .success();
        assert!(ok, "APPARATUS: kill -TERM {pid} did not take");
        let deadline = Instant::now() + Duration::from_secs(30);
        while self
            .0
            .try_wait()
            .expect("APPARATUS: the daemon's exit status could not be read")
            .is_none()
        {
            assert!(
                Instant::now() < deadline,
                "PRODUCT: the daemon did not leave within 30s of SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = args.to_vec();
    match attach::needs(dir, &verb) {
        Some(node) => {
            attach::Root::at(dir, IDENTITY).attached(&node, || vox_plain(dir, args, stdin))
        }
        None => vox_plain(dir, args, stdin),
    }
}

fn vox_plain(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(attach::persistent_args(dir, args, IDENTITY))
        .env("HOME", dir.join("home"))
        .env("VOX_TEST_KEYCHAIN", attach::keychain(dir))
        .env("VOX_PROXY", "127.0.0.1:0")
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // In the environment, not argv: a command line is world-readable (ADR-015).
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
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` without any passphrase. The first start is explicitly unlocked once;
/// every restart has only the state the product remembered, never an auto-unlock helper.
fn daemon(dir: &Path, tag: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out")))
        .expect("APPARATUS: harness file I/O");
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: harness file I/O");
    let child = Command::new(VOX)
        .args(["daemon", "--no-node", "--listen", "127.0.0.1:0"])
        .env("HOME", dir.join("home"))
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_TEST_KEYCHAIN", attach::keychain(dir))
        .env("VOX_PROXY", "127.0.0.1:0")
        .env_remove("VOX_NODE")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let d = Daemon(child);
    // Only the first start receives an explicit operator unlock. Restart probes below use
    // vox_plain: the staging wrapper must never unlock on behalf of the claim.
    if tag.ends_with("-start") {
        let (ok, out, err) = vox_plain(dir, &["node", "unlock", "default"], None);
        assert!(
            ok && out.contains("Ready"),
            "PRODUCT (staging): initial Unlock failed: {out}{err}"
        );
    }
    // The first start is staging; every later start is the restart this proof is about.
    let side = if tag.ends_with("-start") {
        "PRODUCT (staging): on its first start,"
    } else {
        "PRODUCT: restarted without any passphrase input,"
    };
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (ok, _, err) = vox_plain(dir, &["room", "list", "--node", "default"], None);
        if ok {
            return d;
        }
        assert!(
            Instant::now() < deadline,
            "{side} {tag}'s daemon never answered on its control socket: {err}\nits stderr: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `vox room read` must succeed on `room` — which it does only if the room is OPEN on the
/// daemon — and, when `want` is given, must return that post.
fn reads(dir: &Path, who: &str, when: &str, room: &str, want: Option<&str>) {
    let (ok, out, err) = vox_plain(dir, &["room", "read", room, "--node", "default"], None);
    let (_, listed, _) = vox_plain(dir, &["room", "list", "--node", "default"], None);
    // At the first start the room being open is staging; after a restart it is the claim.
    let side = if when == "start" {
        "PRODUCT (staging):"
    } else {
        "PRODUCT:"
    };
    assert!(
        ok,
        "{side} {when}: {who}'s daemon does not hold the room open (#208): {err}\n`room list`: \
         {listed:?}\nits stderr: {}",
        std::fs::read_to_string(dir.join(format!("daemon-{who}-{when}.err"))).unwrap_or_default()
    );
    if let Some(want) = want {
        assert!(
            out.lines().any(|l| l.ends_with(want)),
            "{side} {when}: {who} reads the room but not the post {want:?}: {out:?}"
        );
    }
}

/// The public status comes from the reopened live node, with no helper unlock.
fn free_is_ready(dir: &Path, when: &str) {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let (ok, out, err) = vox_plain(dir, &["status", "--node", "free", "--json"], None);
        let status = serde_json::from_str::<serde_json::Value>(&out).ok();
        if ok && status.as_ref().is_some_and(|s| s["status"] == "Ready") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: the passphrase-free node did not become Ready {when}: {out}{err}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_restarted_daemon_holds_every_room_it_held_without_a_room_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("home")).expect("APPARATUS: scratch HOME");
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: harness file I/O");
    }

    // ---- two identities that consent to each other -------------------------------------
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id failed: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [(&alice, &fps[1], "bob"), (&bob, &fps[0], "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "PRODUCT (staging): vox trust add {name} failed: {err}");
    }

    // ---- alice creates a room and posts; bob joins it ----------------------------------
    let a = daemon(&alice, "alice-start");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "kept"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create failed: {err}");
    let (_, listed, list_err) = vox(&alice, &["room", "list"], None);
    let room: String = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): `room list` shows no room id after `room create`: \
                 {listed:?} {list_err:?}"
            )
        })
        .chars()
        .take(12)
        .collect();
    let (ok, _, err) = vox(&alice, &["room", "post", &room, POST], None);
    assert!(ok, "PRODUCT (staging): vox room post failed: {err}");
    reads(&alice, "alice", "start", &room, Some(POST));

    let (ok, link, err) = vox(&alice, &["room", "link", &room], None);
    assert!(ok, "PRODUCT (staging): vox room link failed: {err}");
    let b = daemon(&bob, "bob-start");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room join failed: {err}");
    reads(&bob, "bob", "start", &room, None);

    // A passphrase-free node is Ready after creation and after Forget. It has no saved
    // credential to restore; startup must actually open its identity with an empty credential.
    let (ok, out, err) = vox_plain(
        &alice,
        &["node", "create", "free", "--passphrase-file", "-"],
        Some("\n"),
    );
    assert!(
        ok && out.contains("Ready"),
        "PRODUCT: no-passphrase creation was not Ready: {out}{err}"
    );
    let (ok, out, err) = vox_plain(&alice, &["node", "lock", "free"], None);
    assert!(
        ok && out.contains("is Ready after the lock request"),
        "PRODUCT: no-passphrase Lock did not stay Ready: {out}{err}"
    );

    // ---- a crash: SIGKILL both, restart both without supplying any passphrase --------
    drop(a);
    drop(b);
    let a = daemon(&alice, "alice-crash");
    let b = daemon(&bob, "bob-crash");
    free_is_ready(&alice, "after a crash");
    reads(&alice, "alice", "crash", &room, Some(POST));
    reads(&bob, "bob", "crash", &room, None);
    drop(b);

    // ---- a clean stop: SIGTERM, restart ------------------------------------------------
    a.terminate();
    let _a = daemon(&alice, "alice-term");
    free_is_ready(&alice, "after a clean daemon stop");
    reads(&alice, "alice", "term", &room, Some(POST));
    let (ok, _, err) = vox(
        &alice,
        &[
            "room",
            "post",
            &room,
            "said after the restarts",
            "--node",
            "default",
        ],
        None,
    );
    assert!(ok, "PRODUCT: the reopened room refused a post: {err}");
    reads(
        &alice,
        "alice",
        "term",
        &room,
        Some("said after the restarts"),
    );
}

/// Keep foreign lifecycle records in the original replay order. Only automatic refresh
/// continuations change; no author selector, index or stored row is introduced.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two real daemons, a real wire client and retained Session history; run in release"]
fn a_restarted_room_drives_its_session_refresh_to_ready() {
    use vox_core::node::api::NodeEvent;
    use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};
    watchdog::arm();
    refresh_knobs::require(&["VOX_TEST_SESSION_REFRESH_RECEIPT"]);
    let tmp = refresh_room::diagnostic_tempdir();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: wire peer runtime");
    let mut room = rt.block_on(refresh_room::room(tmp.path(), &["owner", "foreign"]));
    for (index, other) in [(0, 1), (1, 0)] {
        let fp = vox_core::node::link::b32_encode(&room.workers[other].fp);
        room.workers[index]
            .vox(
                None,
                &[
                    "trust",
                    "add",
                    &fp,
                    "--name",
                    &room.workers[other].name,
                    "--drive",
                    "--identity-passphrase-file",
                    room.workers[index]
                        .pass
                        .to_str()
                        .expect("APPARATUS: passphrase path"),
                ],
            )
            .expect_ok("APPARATUS: give the peer drive so it holds lifecycle records");
    }
    // Register real agents and require private Session delivery before seeding.
    // A local append receipt alone does not prove the other node holds the row.
    for (index, label) in [(0, "own"), (1, "foreign")] {
        let session = format!("rg12-{label}");
        let transcript = tmp.path().join(format!("{session}.jsonl"));
        std::fs::write(&transcript, "").expect("APPARATUS: agent transcript");
        let event = serde_json::json!({
            "session_id": session, "hook_event_name": "UserPromptSubmit",
            "cwd": tmp.path(), "transcript_path": transcript, "prompt": "work",
            "prompt_id": format!("{label}-prompt"),
        });
        room.workers[index]
            .vox_env(
                None,
                &[("CLAUDE_CODE_ENTRYPOINT", "cli")],
                &["agent", "hook", "--node", "default", "--room", &room.id],
                Some(&event.to_string()),
            )
            .expect_ok("APPARATUS: register an agent and negotiate its private Session");
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let shown = room.workers[0].vox(None, &["room", "sessions", &room.id, "--json"]);
        if shown.ok && shown.stdout.contains("rg12-own") && shown.stdout.contains("rg12-foreign") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: private Session delivery was not negotiated before seeding: {shown:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // These are real protocol requests to the shipped daemon, not an in-process Node.
    // Each Appended response says this exact lifecycle record is saved.
    const PER_AUTHOR: usize = 512;
    let unchanged_room = vox_core::node::api::Fault::RoomChangePending.to_string();
    for (index, label) in [(0, "own"), (1, "foreign")] {
        let worker = &room.workers[index];
        let at = NodeSocket::one_shot(
            worker.paths.account().socket(),
            vox_core::node::paths::NodeName::parse("default").expect("APPARATUS: node name"),
        );
        let mut peer = rt
            .block_on(IpcClient::open_at(&at))
            .expect("APPARATUS: real node socket");
        for row in 0..PER_AUTHOR {
            let session = format!("rg12-{label}-{row}");
            let mut opening =
                vox_agentcomms::envelope::Envelope::new(vox_agentcomms::envelope::SESSION, "");
            opening.from.clone_from(&session);
            opening.at.session_name = Some(format!("rg12-{label}-{row}"));
            opening.data = serde_json::json!({"session":{"harness":"claude"}});
            let request = Request::AppendSession {
                channel_id: room.cid,
                session_id: session,
                body: opening.to_text(),
            };
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                match rt.block_on(peer.request(&request)) {
                    Ok(Frame::Appended { .. }) => break,
                    Ok(Frame::Error { reason }) if reason == unchanged_room => {
                        // The previous append was saved; its Drive postlude may still own the
                        // room. Only this definite-no-change refusal can retry the same input.
                        assert!(Instant::now() < deadline,
                            "APPARATUS: the prior room change did not release staging {label}/{row}");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    other => {
                        panic!("APPARATUS: lifecycle row {label}/{row} was not saved: {other:?}")
                    }
                }
            }
        }
    }
    let authors = [0, 1].map(|index| vox_core::node::link::b32_encode(&room.workers[index].fp));
    let expected_heads = ["own", "foreign"].map(|label| {
        [
            format!("rg12-{label}"),
            format!("rg12-{label}-{}", PER_AUTHOR - 1),
        ]
    });
    // Another author's head listing is a delivery window: it shows newest heads and
    // fetches older ones on demand, so stage each author's initial and final head.
    let head_summary = |output: &refresh_room::Out| {
        if !output.ok {
            return None;
        }
        let values = match output
            .stdout
            .lines()
            .filter(|line| !line.is_empty())
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(values) => values,
            Err(_) => return None,
        };
        let heads = values
            .iter()
            .filter_map(|row| Some((row["node"].as_str()?, row["id"].as_str()?)))
            .collect::<std::collections::BTreeSet<_>>();
        let counts = authors.each_ref().map(|author| {
            heads
                .iter()
                .filter(|(node, _)| *node == author.as_str())
                .count()
        });
        let endpoints = expected_heads.iter().enumerate().all(|(index, ids)| {
            ids.iter()
                .all(|id| heads.contains(&(authors[index].as_str(), id.as_str())))
        });
        Some((counts, endpoints))
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let shown = room.workers[0].vox(None, &["room", "sessions", &room.id, "--json"]);
        if let Some((listed, true)) = head_summary(&shown) {
            eprintln!(
                "RG12 staged public Session heads: own={} foreign={}",
                listed[0], listed[1]
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS: owner did not hold the known foreign/own lifecycle rows: {shown:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // No peer, periodic status probe or room-list loop supplies incidental wakes during replay.
    room.workers[1].stop_daemon_cleanly();
    room.workers[0].stop_daemon_cleanly();
    let receipt = tmp.path().join("refresh-walk.tsv");
    let err = tmp.path().join("refresh-restart.err");
    let worker = &room.workers[0];
    let start = Instant::now();
    let mut command = Command::new(VOX);
    command
        .args(["daemon", "--listen", "127.0.0.1:0", "--passphrase-file"])
        .arg(&worker.pass)
        .env("VOX_DATA_DIR", &worker.data)
        .env("VOX_CONFIG_DIR", &worker.cfg)
        .env("VOX_TEST_SESSION_REFRESH_RECEIPT", &receipt)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&err).expect("APPARATUS: restart stderr"));
    refresh_room::strip_harness_env(&mut command);
    let _daemon = Daemon(
        command
            .spawn()
            .expect("APPARATUS: restart the retained node"),
    );
    let at = NodeSocket::one_shot(
        worker.paths.account().socket(),
        vox_core::node::paths::NodeName::parse("default").expect("APPARATUS: node name"),
    );
    let ready = rt.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        let mut events = loop {
            if let Ok(mut events) = IpcClient::open_at(&at).await {
                events.subscribe().await.expect("APPARATUS: subscribe to public node events");
                break events;
            }
            assert!(tokio::time::Instant::now() < deadline,
                "APPARATUS: restarted node never exposed its event stream");
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let mut check = IpcClient::open_at(&at).await.expect("APPARATUS: initial room observation");
        let already_open = matches!(check.rooms().await,
            Ok(Frame::Rooms { rooms }) if rooms.iter().any(|(id, _, open, ..)| *id == room.cid && *open));
        if !already_open {
            loop {
                let event = tokio::time::timeout_at(deadline, events.next()).await
                    .expect("APPARATUS: no terminal room-open report within the measurement watchdog")
                    .expect("APPARATUS: read node event stream")
                    .expect("APPARATUS: node event stream ended during restart");
                eprintln!("RG12 restart {:?}: {event:?}", start.elapsed());
                if matches!(event, Frame::Event(NodeEvent::ChannelOpened { channel_id })
                    if channel_id == room.cid) { break; }
            }
        }
        start.elapsed()
    });
    let walked = std::fs::read_to_string(&receipt)
        .expect("APPARATUS: restart did not reach its Session-refresh batches");
    let (rows, foreign) = walked
        .lines()
        .fold((0usize, 0usize), |(rows, foreign), line| {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(
                fields.len(),
                3,
                "APPARATUS: malformed refresh receipt {line:?}"
            );
            (
                rows + fields[1].parse::<usize>().expect("APPARATUS: walked rows"),
                foreign + fields[2].parse::<usize>().expect("APPARATUS: foreign rows"),
            )
        });
    eprintln!(
        "RG12 restart READY: authored={} own_openings={} foreign_openings={} walked={rows} own_walked={} foreign_walked={foreign} \
        spawn_to_room_open={ready:?}\nwalk:\n{walked}\nproduct stderr:\n{}",
        2 * (PER_AUTHOR + 1),
        PER_AUTHOR + 1,
        PER_AUTHOR + 1,
        rows - foreign,
        std::fs::read_to_string(&err).expect("APPARATUS: read restart product report")
    );
    // Replay walks retained, indexed lifecycle sources rather than folded Session heads,
    // so its counts need not match the number of acknowledged openings.
    assert!(
        foreign > 0 && rows > foreign,
        "APPARATUS: restart did not walk a positive share of both own and foreign Session sources"
    );
    let shown = worker.vox(None, &["room", "sessions", &room.id, "--json"]);
    assert!(
        head_summary(&shown).is_some_and(|(_, endpoints)| endpoints),
        "PRODUCT: reopened room lost saved Session state or replay order: {shown:?}"
    );
    worker
        .vox(None, &["room", "post", &room.id, "rg12-after-refresh"])
        .expect_ok("the automatically refreshed room accepts a saved post");
}
