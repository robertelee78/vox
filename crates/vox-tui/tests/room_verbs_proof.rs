//! ADR-020 §8 — `vox room` driven as a **real binary against a real node**.
//!
//! It replaced the in-process gate `node_m19_ipc_requests_gate` (deleted in V29-17), which only
//! proved the socket answers.
//! This proves the thing an agent actually runs: the `vox` binary, as a separate
//! process, attaching to a node it did not start.
//!
//! That distinction is the whole reason this file exists. M17's rehearsal found
//! three defects that no library gate could catch, every one of them in CLI
//! composition — a passphrase that did not match itself, an address printed that
//! could not be dialled, a race between binding and dialling. Those live in the
//! seam between a binary and a node, which is exactly this seam.
//!
//! What it proves:
//!
//! - `room list` names the room, and `room post` puts a message in it that the
//!   **node's own view** shows — so the post went through the log;
//! - `room read` prints the entry hash first, and **that hash works as a cursor**
//!   for a second `read --since`, which is the loop an agent's drain does;
//! - `--limit` caps;
//! - **posting from stdin works**, which is how an agent sends a JSON envelope
//!   without fighting shell quoting;
//! - `room roster` names the member;
//! - **`room post` refuses every raw claim-protocol message** (`claim`, `release`, `handoff`,
//!   `renew`, and a `decline` naming a resource), says which verb to use, and neither the room nor
//!   its work board holds any of them afterwards; **prose that only sounds like a claim** ("I'll
//!   take the deploy") is posted and claims nothing; a `decline` with no resource, which refuses an
//!   `assign` in conversation, is posted, not refused (ADR-021 §4);
//! - the failures an operator will actually hit say something useful: no node
//!   running, an unknown room, a malformed cursor;
//! - **every change of access says what it is to do before it acts, and what it did after**
//!   (ADR-028 E-5): `vox room retention`, `vox service add` and `remove`, `vox share`, and
//!   `vox trust add` and `remove` each print a "vox: about to …" line naming the room or the node,
//!   then the line saying it was done, in that order; `vox trust remove` and `vox service remove`
//!   name the live sessions there were (none here). `vox room leave` and `end` are proved in
//!   `a_room_can_be_left_and_ended_proof.rs`.
//!
//! **Mutation** (RP-01): drop the raw-claim refusal from `post_cmd` and it goes red on the raw
//! `claim`: it is posted.
//!
//! Production Argon2id once at setup; `#[ignore]`d in the debug suite.
//!
//! **A room is made and posted to in a debug build too**
//! ([`a_debug_daemon_makes_a_room_takes_a_post_and_keeps_running`], not ignored, so the debug
//! suite runs it; V210-127, #341): a debug `vox daemon` aborted on `vox room create` with "thread
//! 'tokio-rt-worker' has overflowed its stack". A debug build gives every future an async fn awaits
//! a stack slot of its own, and the actor's dispatchers await dozens, so their poll frames came to
//! about 815 KiB (`handle_net`) and 471 KiB (`Node::run`), and signing the new room's records on
//! top of them passed the 2 MiB worker stack. The actor's large steps are boxed where they are made
//! (`Boxed` in `node/actor.rs`). Mutation that must turn it red: those steps awaited unboxed
//! again.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// A real `vox daemon`, killed however the test ends.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `vox daemon` on the profile and wait until its control socket answers.
fn daemon(data: &Path, cfg: &Path, pass: &Path, err: &Path) -> Daemon {
    let child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0", "--passphrase-file"])
        .arg(pass)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(err).unwrap_or_else(
            |e| panic!("APPARATUS: cannot create {}: {e}", err.display()),
        )))
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox daemon: {e}"));
    let mut d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (ok, _, list_err) = vox(data, cfg, &["room", "list"], None);
        if ok {
            break;
        }
        if let Ok(Some(status)) = d.0.try_wait() {
            panic!(
                "PRODUCT: vox daemon exited ({status}) before its control socket answered; \
                 stderr:\n{}",
                std::fs::read_to_string(err).unwrap_or_default()
            );
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: the daemon's control socket never answered `vox room list` within 60 s; \
             last `room list` said: {list_err}\ndaemon stderr:\n{}",
            std::fs::read_to_string(err).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    d
}

/// Run `vox room …` against the profile rooted at `data`/`cfg`.
fn vox(
    data: &std::path::Path,
    cfg: &std::path::Path,
    args: &[&str],
    stdin: Option<&str>,
) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox {args:?}: {e}"));
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: the piped stdin was not opened")
            .write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("PRODUCT (staging): vox exited without reading its stdin (cannot write vox {args:?}'s stdin): {e}"));
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot wait for vox {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
#[ignore = "production Argon2id at setup + drives the real binary; CI runs it in release"]
fn vox_room_speaks_to_a_node_it_did_not_start() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    std::fs::create_dir_all(&cfg).expect("APPARATUS: create the config dir");
    let pass = tmp.path().join("identity.pass");
    std::fs::write(&pass, "identity passphrase").expect("APPARATUS: write the passphrase file");

    // ---- the failure an operator hits first, before anything is running ----
    let (ok, _, err) = vox(&data, &cfg, &["room", "list"], None);
    assert!(
        !ok,
        "PRODUCT: `vox room list` succeeded with no node running; stderr: {err}"
    );
    // Since ADR-026 (C-3): no node exists yet, said with how to make one.
    assert!(
        err.contains("there is no node") && err.contains("vox node create"),
        "PRODUCT: the no-node error must say so plainly, got: {err}"
    );

    // ---- stand up a node with a room, as a person does: vox id, vox daemon, vox room create ----
    let (ok, me, err) = vox(
        &data,
        &cfg,
        &[
            "id",
            "--identity-passphrase-file",
            pass.to_str().expect("APPARATUS: a non-UTF-8 temp path"),
        ],
        None,
    );
    assert!(ok, "PRODUCT: vox id failed: {err}");
    let me = me.trim().to_owned();
    let _daemon = daemon(&data, &cfg, &pass, &tmp.path().join("daemon.err"));
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "agents",
        ],
        Some("channel passphrase"),
    );
    assert!(ok, "PRODUCT: vox room create failed: {err}");
    // The CLI identifies a room by its base32 rendering, as every other verb
    // does, so the prefix must be taken from that — not from hex.
    let (_, listed, list_err) = vox(&data, &cfg, &["room", "list"], None);
    let room_prefix: String = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| {
            panic!("PRODUCT: `room list` named no room after `room create`: {listed:?} {list_err}")
        })
        .chars()
        .take(8)
        .collect();

    // ---- list ----
    let (ok, out, err) = vox(&data, &cfg, &["room", "list"], None);
    assert!(ok, "PRODUCT: room list failed: {err}");
    assert!(
        out.contains("agents"),
        "PRODUCT: list did not name the room: {out}"
    );

    // ---- the room's name (ADR-028 R-1, R-2): one DNS label, changed with `vox room rename`,
    // which asks for the identity passphrase; a name that is no label is refused with the reason ----
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "Our Room",
        ],
        Some("channel passphrase"),
    );
    assert!(
        !ok && err.contains("a room name holds only letters a-z, digits and `-`")
            && err.contains("' '"),
        "PRODUCT: `vox room create --name \"Our Room\"` must be refused, saying a room name is \
         one DNS label and what is wrong with this one; it said: {out}{err}"
    );
    let identity = [
        "--identity-passphrase-file",
        pass.to_str().expect("APPARATUS: a UTF-8 path"),
    ];
    let rename = |room: &str, name: &str| {
        vox(
            &data,
            &cfg,
            &[&["room", "rename", room, name][..], &identity[..]].concat(),
            None,
        )
    };
    let (ok, out, err) = rename("agents", "team-");
    assert!(
        !ok && err.contains("a room name cannot start or end with `-`"),
        "PRODUCT: renaming to `team-` must be refused with the reason; it said: {out}{err}"
    );
    // By its name, as a person refers to it.
    let (ok, out, err) = rename("agents", "Team");
    assert!(
        ok && out.contains("renamed") && out.contains("to team"),
        "PRODUCT: `vox room rename agents Team` by the room's creator must rename it to `team` \
         (a name is lower case); it said: {out}{err}"
    );
    let (ok, out, err) = vox(&data, &cfg, &["room", "list"], None);
    assert!(
        ok && out.contains(" team") && !out.contains("agents"),
        "PRODUCT: after the rename `vox room list` must show the room as `team`, and `agents` no \
         more; it said: {out}{err}"
    );
    println!("[proof] a room renamed by its creator lists under its new name: {out}");

    // ---- post, and check the NODE's view rather than trusting the exit code ----
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "post", &room_prefix, "first from the cli"],
        None,
    );
    assert!(ok, "PRODUCT: room post failed: {err}");

    // ---- post from stdin: how an agent sends JSON without quoting trouble ----
    // `to` names nodes, each by its whole fingerprint as `vox room roster` prints it (V210-161):
    // here this node's own.
    let envelope = format!(r#"{{"v":1,"type":"assign","to":["{me}"],"body":"port the codec"}}"#);
    let envelope = envelope.as_str();
    let (ok, _, err) = vox(&data, &cfg, &["room", "post", &room_prefix], Some(envelope));
    assert!(ok, "PRODUCT: room post from stdin failed: {err}");

    // ---- every raw claim-protocol operation is refused (RP-01): it would lack the session, op
    // id and version stamp that make it valid, and `vox room <kind>` sets them. All five kinds, a
    // `decline` counting only when it names a resource ----
    let raw_ops: Vec<(&str, String)> = ["claim", "release", "handoff", "renew", "decline"]
        .iter()
        .map(|kind| {
            (
                *kind,
                format!(
                    r#"{{"v":1,"type":"{kind}","from":"s","data":{{"resource":"deploy","op":"op-12345678"}}}}"#
                ),
            )
        })
        .collect();
    for (kind, raw) in &raw_ops {
        let (ok, out, err) = vox(&data, &cfg, &["room", "post", &room_prefix], Some(raw));
        assert!(
            !ok,
            "PRODUCT: `vox room post` accepted a raw `{kind}` operation; it must refuse it. It \
             said: {out}{err}"
        );
        assert!(
            err.contains(&format!("refusing a raw `{kind}`"))
                && err.contains(&format!("vox room {kind}")),
            "PRODUCT: the refusal must say it refused a raw `{kind}` and name `vox room {kind}`; \
             it said: {err:?}"
        );
    }
    // ---- prose that sounds like a claim is a message, and claims nothing ----
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "post", &room_prefix, "I'll take the deploy"],
        None,
    );
    assert!(ok, "PRODUCT: a prose post was refused: {err}");
    // ---- a decline with no resource refuses an `assign` in conversation: not a claim
    // operation, so it is posted ----
    let decline = r#"{"v":1,"type":"decline","body":"not me"}"#;
    let (ok, _, err) = vox(&data, &cfg, &["room", "post", &room_prefix], Some(decline));
    assert!(
        ok,
        "PRODUCT: a decline with no resource is conversation, not a claim operation, and must \
         be posted; it said: {err:?}"
    );
    let (ok, board, err) = vox(
        &data,
        &cfg,
        &["room", "board", &room_prefix, "--json"],
        None,
    );
    assert!(ok, "PRODUCT: room board failed: {err}");
    let board: serde_json::Value = serde_json::from_str(&board)
        .unwrap_or_else(|e| panic!("PRODUCT: room board --json is not JSON ({e}): {board}"));
    println!(
        "[proof] the work board after the refused raw operations and a prose 'claim': {board}"
    );
    assert_eq!(
        board["resources"].as_array().map(Vec::len),
        Some(0),
        "PRODUCT: nothing was claimed, yet the board shows a resource: {board}"
    );

    // ---- the posts are in the node, not only in the exit code: a separate `vox` process reads
    // them back from the daemon ----
    let (ok, stored, err) = vox(&data, &cfg, &["room", "read", &room_prefix], None);
    assert!(ok, "PRODUCT: room read failed: {err}");
    assert!(
        stored.lines().any(|l| l.ends_with(" first from the cli")),
        "PRODUCT: the node does not have the posted message: {stored}"
    );
    // The text form shows a structured post as words (#406); `--json` carries what was posted.
    let (ok, rows, err) = vox(&data, &cfg, &["room", "read", &room_prefix, "--json"], None);
    assert!(ok, "PRODUCT: room read --json failed: {err}");
    assert!(
        rows.lines().any(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .is_ok_and(|row| row["text"].as_str() == Some(envelope))
        }),
        "PRODUCT: the stdin-posted envelope did not arrive intact: {rows}"
    );
    // What each row says it is: none of the refused operations, by its text or by its kind (the
    // conversational decline aside, which carries no resource).
    let posted: Vec<serde_json::Value> = rows
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|row| {
            row["text"]
                .as_str()
                .and_then(|t| serde_json::from_str(t).ok())
        })
        .collect();
    for (kind, raw) in &raw_ops {
        assert!(
            !rows.contains(raw.as_str())
                && !posted
                    .iter()
                    .any(|e| e["type"] == *kind && !e["data"]["resource"].is_null()),
            "PRODUCT: the refused raw `{kind}` is in the room anyway: {rows}"
        );
    }
    assert!(
        stored.lines().any(|l| l.ends_with(" I'll take the deploy"))
            && rows.lines().any(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .is_ok_and(|row| row["text"].as_str() == Some(decline))
            }),
        "PRODUCT: the prose post or the conversational decline is missing: {stored}\n{rows}"
    );
    assert!(
        // The addressee is named on the line after the row.
        stored.contains(" assign: port the codec\n  (to you)"),
        "PRODUCT: `vox room read` does not show the assign as words: {stored}"
    );

    // ---- read, and use the printed hash as a cursor ----
    let (ok, out, err) = vox(&data, &cfg, &["room", "read", &room_prefix], None);
    assert!(ok, "PRODUCT: room read failed: {err}");
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines.len() >= 2,
        "PRODUCT: read printed {} lines: {out}",
        lines.len()
    );
    let first_hash = lines[0]
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT: read's first line has no hash column: {out}"));
    assert_eq!(
        first_hash.len(),
        52,
        "PRODUCT: the first column must be a full entry hash in the CLI's own encoding, got: {out}"
    );

    let (ok, out2, err) = vox(
        &data,
        &cfg,
        &["room", "read", &room_prefix, "--since", first_hash],
        None,
    );
    assert!(ok, "PRODUCT: room read --since failed: {err}");
    let after: Vec<&str> = out2.lines().collect();
    assert_eq!(
        after.len(),
        lines.len() - 1,
        "PRODUCT: a cursor must return only what follows it; all:\n{out}\n--since {first_hash}:\n{out2}"
    );
    assert!(
        !out2.contains(first_hash),
        "PRODUCT: the cursor entry itself came back: {out2}"
    );

    // ---- limit ----
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &["room", "read", &room_prefix, "--limit", "1"],
        None,
    );
    assert!(ok, "PRODUCT: room read --limit failed: {err}");
    assert_eq!(
        out.lines().count(),
        1,
        "PRODUCT: `--limit 1` printed more or less than one entry: {out}"
    );

    // ---- roster ----
    let (ok, out, err) = vox(&data, &cfg, &["room", "roster", &room_prefix], None);
    assert!(ok, "PRODUCT: room roster failed: {err}");
    // The roster names this node's own member, by its whole fingerprint (agent_comms's review
    // of acc5dc0: "not empty" let a roster that printed "(roster unavailable)" pass).
    assert!(
        out.lines().any(|l| l.trim() == me),
        "PRODUCT: the roster must list this member ({me}), got: {out:?}"
    );

    // ---- every change of access says what it is to do, then what it did (ADR-028 E-5) ----
    let pass_file = pass.to_str().expect("APPARATUS: a UTF-8 temp path");
    // The first line starting `before` that holds every one of `naming`, and after it a line
    // starting `after` that holds `then`: both, in that order.
    let said = |out: &str, before: &str, naming: &[&str], after: &str, then: &str| {
        let lines: Vec<&str> = out.lines().collect();
        let b = lines
            .iter()
            .position(|l| l.starts_with(before) && naming.iter().all(|n| l.contains(n)));
        b.is_some_and(|b| {
            lines[b + 1..]
                .iter()
                .any(|l| l.starts_with(after) && l.contains(then))
        })
    };
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &[
            "room",
            "retention",
            &room_prefix,
            "1w",
            "--identity-passphrase-file",
            pass_file,
        ],
        None,
    );
    assert!(ok, "PRODUCT: room retention failed: {err}");
    assert!(
        said(
            &out,
            "vox: about to set how long",
            &["\"agents\""],
            "vox: ",
            "keeps messages for"
        ),
        "PRODUCT: `vox room retention` must say what it is to do, naming the room, then what it \
         did: {out:?}"
    );
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &["service", "add", &room_prefix, "echo", "127.0.0.1:9"],
        None,
    );
    assert!(ok, "PRODUCT: service add failed: {err}");
    assert!(
        said(
            &out,
            "vox: about to offer \"echo\"",
            &["\"agents\""],
            "vox: offering \"echo\"",
            ""
        ),
        "PRODUCT: `vox service add` must say what it is to do, naming the room, then what it \
         did: {out:?}"
    );
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &["service", "remove", &room_prefix, "echo"],
        None,
    );
    assert!(ok, "PRODUCT: service remove failed: {err}");
    assert!(
        said(
            &out,
            "vox: about to stop offering \"echo\"",
            &["\"agents\""],
            "vox: no longer offering \"echo\"",
            "live sessions cut: none was open"
        ),
        "PRODUCT: `vox service remove` must say what it is to do, naming the room, then what it \
         did, naming the live sessions it cut: {out:?}"
    );
    let shared = tmp.path().join("shared.txt");
    std::fs::write(&shared, "a file shared for the access proof\n")
        .expect("APPARATUS: cannot write the shared file");
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &[
            "share",
            &room_prefix,
            shared.to_str().expect("APPARATUS: a UTF-8 temp path"),
            "--for",
            "1s",
        ],
        None,
    );
    assert!(ok, "PRODUCT: vox share failed: {err}");
    assert!(
        said(
            &out,
            "vox: about to share shared.txt",
            &["\"agents\""],
            "vox: sharing shared.txt",
            ""
        ) && said(
            &out,
            "vox: sharing shared.txt",
            &[],
            "vox: no longer sharing shared.txt",
            "fetched 0"
        ),
        "PRODUCT: `vox share` must say what it is to do, naming the room, then that it shares, \
         then that it stopped: {out:?}"
    );
    // A node this one shares no room with: a fingerprint nobody holds.
    let stranger = "a".repeat(52);
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &[
            "trust",
            "add",
            &stranger,
            "--name",
            "stranger",
            "--identity-passphrase-file",
            pass_file,
        ],
        None,
    );
    assert!(ok, "PRODUCT: trust add failed: {err}");
    assert!(
        said(
            &out,
            "vox: about to trust",
            &["\"stranger\""],
            "vox: trusting",
            "\"stranger\""
        ) && out.contains("you share no open room with it yet"),
        "PRODUCT: `vox trust add` must say what it is to cover (no room shared yet), then what it \
         did: {out:?}"
    );
    let (ok, out, err) = vox(
        &data,
        &cfg,
        &[
            "trust",
            "remove",
            &stranger,
            "--identity-passphrase-file",
            pass_file,
        ],
        None,
    );
    assert!(ok, "PRODUCT: trust remove failed: {err}");
    assert!(
        said(
            &out,
            "vox: about to stop trusting",
            &[],
            "vox: no longer trusting",
            ""
        ) && said(
            &out,
            "vox: no longer trusting",
            &[],
            "     cut: none was open",
            ""
        ),
        "PRODUCT: `vox trust remove` must say what it is to stop, then what it did, naming the \
         live sessions it cut: {out:?}"
    );

    // ---- the remaining failures say something useful ----
    let (ok, _, err) = vox(&data, &cfg, &["room", "read", "zzzzzzzz"], None);
    assert!(!ok, "PRODUCT: reading an unknown room succeeded: {err}");
    assert!(
        err.contains("nothing here matches") && err.contains("zzzzzzzz"),
        "PRODUCT: an unknown room must say that nothing matches it, naming it, got: {err:?}"
    );

    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "read", &room_prefix, "--since", "not-a-hash"],
        None,
    );
    assert!(!ok, "PRODUCT: a malformed cursor was accepted: {err}");
    assert!(
        err.contains("52-character"),
        "PRODUCT: a malformed cursor must say what a cursor looks like, got: {err}"
    );

    let (ok, _, err) = vox(&data, &cfg, &["room", "post", &room_prefix, "   "], None);
    assert!(!ok, "PRODUCT: an empty message was posted: {err}");
    assert!(
        err.contains("empty"),
        "PRODUCT: an empty message's refusal must say it is empty, got: {err}"
    );
}

/// A debug `vox daemon` makes a room, takes a post into it, and is still running afterwards. A red
/// is PRODUCT and quotes the daemon's own stderr (an abort there says "has overflowed its stack").
#[test]
fn a_debug_daemon_makes_a_room_takes_a_post_and_keeps_running() {
    // `vox id` and the daemon's unlock, and the room key's seal: three Argon2id runs.
    watchdog::arm_for_setup(0, 3);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    std::fs::create_dir_all(&cfg).expect("APPARATUS: create a staging directory");
    let pass = tmp.path().join("identity.pass");
    std::fs::write(&pass, "identity passphrase").expect("APPARATUS: write a staging file");
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &[
            "id",
            "--identity-passphrase-file",
            pass.to_str().expect("APPARATUS: a path that is not UTF-8"),
        ],
        None,
    );
    assert!(ok, "PRODUCT (staging): vox id: {err}");
    let daemon_err = tmp.path().join("daemon.err");
    let mut node = daemon(&data, &cfg, &pass, &daemon_err);
    let said = |what: &str| {
        format!(
            "{what}. The daemon said:\n{}",
            std::fs::read_to_string(&daemon_err).unwrap_or_default()
        )
    };

    let (ok, _, err) = vox(
        &data,
        &cfg,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "made-in-debug",
        ],
        Some("channel passphrase"),
    );
    assert!(
        ok,
        "{}",
        said(&format!("PRODUCT: vox room create failed: {err}"))
    );
    let (ok, out, err) = vox(&data, &cfg, &["room", "list"], None);
    let room = out
        .lines()
        .find(|l| l.contains("made-in-debug"))
        .and_then(|l| l.split_whitespace().next())
        .map(str::to_owned);
    let Some(room) = room.filter(|_| ok) else {
        panic!(
            "{}",
            said(&format!(
                "PRODUCT: the daemon does not list the room it made: {out}{err}"
            ))
        );
    };
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &["room", "post", &room, "posted in debug"],
        None,
    );
    assert!(
        ok,
        "{}",
        said(&format!("PRODUCT: vox room post failed: {err}"))
    );
    let (ok, read, err) = vox(&data, &cfg, &["room", "read", &room], None);
    assert!(
        ok && read.lines().any(|l| l.ends_with(" posted in debug")),
        "{}",
        said(&format!(
            "PRODUCT: the post is not in the room: {read}{err}"
        ))
    );
    let exited = node.0.try_wait().ok().flatten();
    assert!(
        exited.is_none(),
        "{}",
        said(&format!(
            "PRODUCT: vox daemon exited ({exited:?}) after making a room and a post"
        ))
    );
}
