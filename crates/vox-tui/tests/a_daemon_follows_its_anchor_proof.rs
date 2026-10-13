//! A running daemon must follow its anchor when the anchor moves.
//!
//! An anchor spec may name a host rather than an address (M17.5), and the stated reason
//! it may is that a home connection's address changes whenever the ISP decides — so a
//! person should not have to re-issue it to every client. The implementation resolved
//! once, when the process read its configuration, so a daemon that runs for days held
//! whatever the name meant at startup and redialled that address for ever.
//!
//! The failure attributes badly, which is what makes it worth a gate: the anchor is up,
//! the name is right, and the client says only that it cannot reach a peer. Nothing in
//! that points at a stale address.
//!
//! **Real-binary journey.** Alice starts with eight dead addresses and a bad line in
//! its manual anchor file. While its daemon runs, that file changes to the real anchor.
//! `vox anchor list --json` must report only the new address and its hand-added source.
//! Alice's room link must keep that machine input out of the room's sources. The apparatus
//! supplies Bob a link containing only the moved anchor and the original responder pin:
//! Bob must join through it, then render Alice's nonce-bearing message after mutual trust.
//! That delivery proves Alice actually reached and published to the moved anchor; a list
//! projection alone cannot prove it. Bob's machine list must identify the learned room source.
//!
//! This consolidates the former single-address, eight-address and bad-line runs into one
//! journey. It also attaches Carol before refresh and requires both identities to report their own
//! reach. Dave then creates an unrelated room on Bob’s daemon: its public status must
//! show no anchor or live connection to Bob’s room anchor, and the machine list must
//! retain only the original room source. This is an observed status claim, not a claim
//! that no future helper traffic can occur. It does not prove live DNS-record changes, helper
//! isolation, canonical migration or all #779 requirements. Those remain separate claims.
//!
//! Mutants must fail the corresponding product assertion: disable refresh, retain old
//! addresses, fail the whole file on its bad line, carry manual anchors in issued room links,
//! drop room publication, or lose the room source in the machine projection.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/typed.rs"]
mod typed;

use std::io::Write;
use std::process::{Child, Command, Stdio};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "daemon passphrase";

/// Longer than the daemon's own 30s refresh, with room for a dial afterwards.
const FOLLOW_PATIENCE: std::time::Duration = std::time::Duration::from_secs(120);
/// How long bob may take to render alice's post once both have joined and trust.
const READ_PATIENCE: std::time::Duration = std::time::Duration::from_secs(120);
const ROOM_PASS: &str = "a room passphrase\n";

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(data: &std::path::Path, cfg: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    vox_stdin(data, cfg, args, None)
}

/// `vox`, optionally with something piped to its stdin (`room create` wants a passphrase).
fn vox_stdin(
    data: &std::path::Path,
    cfg: &std::path::Path,
    args: &[&str],
    input: Option<&str>,
) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .env("VOX_NODE", "default")
        .env_remove("VOX_ANCHORS")
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM");
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
    let mut child = cmd
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: spawn vox");
    if let Some(text) = input {
        let mut pipe = child.stdin.take().expect("APPARATUS: vox stdin");
        pipe.write_all(text.as_bytes())
            .expect("APPARATUS: write vox stdin");
        drop(pipe);
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
#[ignore = "production Argon2id, a real anchor and a 30s refresh; CI runs it in release"]
fn a_daemon_picks_up_an_anchor_that_moved_under_it() {
    // Eight addresses and a bad line cover the old separate runs in the same journey.
    follow(&[9, 10, 11, 12, 13, 14, 15, 16], true);
}

/// The scene: the daemon starts with the anchor at `dead_ports`, the file is rewritten to name
/// its real one, and the daemon must follow. With `bad_line`, both versions of the file start with
/// a line whose host does not resolve.
fn follow(dead_ports: &[u16], bad_line: bool) {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");

    // ---- a real anchor, on a port nobody knew at startup ----
    let anchor_data = tmp.path().join("anchor-data");
    let anchor_cfg = tmp.path().join("anchor-cfg");
    std::fs::create_dir_all(&anchor_cfg).expect("APPARATUS: harness file I/O");
    let mut anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &anchor_data)
            .env("VOX_CONFIG_DIR", &anchor_cfg)
            .env("VOX_NODE", "default")
            .env_remove("VOX_ANCHORS")
            // To a file, never a pipe nobody reads: `vox node` prints a status line each
            // time its peers change, and once the read end of a pipe is gone that print
            // fails and takes the anchor down. An earlier version of this proof dropped
            // the pipe, so the anchor died the moment the daemon reached it — hidden only
            // because the joiner then went to the daemon directly.
            .stdout(Stdio::from(
                std::fs::File::create(tmp.path().join("anchor.out"))
                    .expect("APPARATUS: harness file I/O"),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(tmp.path().join("anchor.err"))
                    .expect("APPARATUS: harness file I/O"),
            ))
            .spawn()
            .expect("APPARATUS: spawn vox node"),
    );
    // `vox node` writes its own spec into its config dir; that file is the truth.
    let anchors_file = anchor_cfg.join("anchors");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let real_spec = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "PRODUCT (staging): the anchor never wrote its spec to {}; its stderr: {:?}",
            anchors_file.display(),
            std::fs::read_to_string(tmp.path().join("anchor.err")).unwrap_or_default()
        );
        if let Ok(text) = std::fs::read_to_string(&anchors_file) {
            if let Some(line) = text
                .lines()
                .map(str::trim)
                .find(|l| l.contains("127.0.0.1") && l.contains('@'))
            {
                break line.to_owned();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };

    // ---- a client profile, and an anchors file pointing at nothing ----
    let data = tmp.path().join("data");
    let cfg = tmp.path().join("cfg");
    std::fs::create_dir_all(&cfg).expect("APPARATUS: harness file I/O");
    let (ok, fp, err) = vox(&data, &cfg, &["id"]);
    assert!(ok, "PRODUCT (staging): alice's `vox id` failed: {err}");
    assert_eq!(
        fp.trim().len(),
        52,
        "PRODUCT (staging): `vox id` did not print a fingerprint: {fp:?}"
    );
    // The same identity, a different port: reachable by nobody. This stands in for the
    // address a name used to resolve to.
    let anchor_id = real_spec
        .split_once('@')
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): the anchor wrote a spec with no `@`: {real_spec:?}")
        })
        .0;
    let wrong_specs: Vec<String> = dead_ports
        .iter()
        .map(|p| format!("{anchor_id}@/ip4/127.0.0.1/udp/{p}"))
        .collect();
    let wrong_spec = wrong_specs.join(" ");
    // Line 1, when asked for: a host that cannot resolve (`.invalid` never does, RFC 2606).
    let bad = if bad_line {
        format!("{anchor_id}@no-such-anchor.invalid:4433\n")
    } else {
        String::new()
    };
    std::fs::write(
        anchors_file_for(&cfg),
        format!("{bad}{}\n", wrong_specs.join("\n")),
    )
    .expect("APPARATUS: harness file I/O");

    // ---- the daemon starts against the address that is wrong ----
    let mut daemon = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .env("VOX_NODE", "default")
        .env_remove("VOX_ANCHORS")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(tmp.path().join("daemon.err"))
                .expect("APPARATUS: harness file I/O"),
        ))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let mut pipe = daemon.stdin.take().expect("APPARATUS: daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes())
        .expect("APPARATUS: write the daemon's passphrase");
    drop(pipe);
    let _daemon = Proc(daemon);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !vox(&data, &cfg, &["room", "list"]).0 {
        let stderr = std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default();
        // With a bad line, a daemon that will not start is the defect, not a precondition.
        assert!(
            !bad_line || std::time::Instant::now() < deadline,
            "PRODUCT: the daemon did not start with an anchors file whose line 1 names a host that does \
             not resolve: one bad line must be skipped, not fail every anchor. Its stderr: \
             {stderr:?}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "PRODUCT (staging): the daemon never answered on its control socket; its stderr: \
             {stderr:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // A second identity attaches before refresh. It owns no room, but the shared
    // hand-added anchor must provide its own reach too, rather than only Alice's.
    let (ok, _, err) = vox_stdin(
        &data,
        &cfg,
        &["node", "create", "carol", "--passphrase-file", "-"],
        Some(IDENTITY),
    );
    assert!(ok, "PRODUCT: creating the second node failed: {err}");
    let (ok, _, err) = vox(&data, &cfg, &["node", "attach", "carol", "--no-remember"]);
    assert!(ok, "PRODUCT: attaching the second node failed: {err}");

    // ---- the anchor moves: the configuration is rewritten under the running daemon ----
    std::fs::write(anchors_file_for(&cfg), format!("{bad}{real_spec}\n"))
        .expect("APPARATUS: harness file I/O");

    // ---- it must reach the anchor without being restarted ----
    // First inspect the public machine list; actual reach is proven by Bob's join
    // and message delivery below, rather than inferred from this configuration view.
    // **The address, not the identity.** The wrong spec names the same identity on a
    // dead port — that is what makes it a stand-in for an anchor that moved — so looking
    // for the fingerprint in the list proves nothing: it is there either way. A first
    // version of this gate did exactly that and passed in 1.8 seconds, which is less
    // than the refresh interval and therefore could not have been a follow at all.
    let real_port = real_spec
        .rsplit('/')
        .next()
        .unwrap_or_else(|| panic!("PRODUCT (staging): no port in the anchor's spec {real_spec:?}"))
        .to_owned();
    assert!(
        !dead_ports.iter().any(|p| p.to_string() == real_port),
        "APPARATUS: the specs must differ by address, or this gate measures nothing"
    );
    let started = std::time::Instant::now();
    let mut last = String::new();
    let followed = loop {
        if started.elapsed() > FOLLOW_PATIENCE {
            break false;
        }
        let (_, out, _) = vox(&data, &cfg, &["anchor", "list", "--json"]);
        last = out.clone();
        if out.contains(&format!("/udp/{real_port}")) {
            break true;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    };

    println!(
        "[proof] followed={followed} after {:?}: started against {wrong_spec}, file rewritten to {real_spec}",
        started.elapsed()
    );
    assert!(
        followed,
        "PRODUCT: the machine list never reported the anchor address its configuration now names, after {:?}. It \
         started against {wrong_spec}, the file was rewritten to {real_spec} while it ran, \
         and an anchor spec may be a NAME precisely so it can move — a node that resolves \
         once holds the address it got at startup for ever. The machine list said: {last:?}\n\
         daemon stderr: {:?}",
        started.elapsed(),
        std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default()
    );

    let projection: serde_json::Value = serde_json::from_str(&last).unwrap_or_else(|error| {
        panic!("PRODUCT: anchor list returned invalid JSON: {error}: {last:?}")
    });
    let listed = projection["anchors"]
        .as_array()
        .and_then(|anchors| {
            anchors
                .iter()
                .find(|anchor| anchor["fingerprint"] == anchor_id)
        })
        .unwrap_or_else(|| panic!("PRODUCT: anchor list omitted the moved anchor: {last:?}"));
    let addresses = listed["addresses"]
        .as_array()
        .unwrap_or_else(|| panic!("PRODUCT: anchor list omitted addresses: {last:?}"));
    assert!(
        addresses.len() == 1
            && addresses[0]
                .as_str()
                .is_some_and(|address| address.ends_with(&format!("/udp/{real_port}"))),
        "PRODUCT: moved anchor retained old addresses instead of replacing them: {last:?}"
    );
    assert_eq!(
        listed["sources"],
        serde_json::json!([{"kind": "added-by-hand"}]),
        "PRODUCT: a hand-added machine anchor acquired a room source: {last:?}"
    );

    // The public list describes inputs, not reach. Wait for the node's public status
    // to say the anchor is reached, then create: create waits for its initial publish
    // rounds. Thus Bob's one-shot join follows a real product readiness boundary.
    let deadline = std::time::Instant::now() + FOLLOW_PATIENCE;
    for node in ["default", "carol"] {
        loop {
            let (ok, report, err) = vox(&data, &cfg, &["status", "--json", "--node", node]);
            let reached = ok
                && serde_json::from_str::<serde_json::Value>(&report)
                    .ok()
                    .and_then(|value| value["anchors"].as_array().cloned())
                    .is_some_and(|anchors| {
                        anchors
                            .iter()
                            .any(|anchor| anchor["id"] == anchor_id && anchor["reached"] == true)
                    });
            if reached {
                break;
            }
            assert!(std::time::Instant::now() < deadline,
                "PRODUCT: attached node {node} never reported its own reach to the moved machine anchor: {report:?} {err:?}");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        println!("[proof] attached node {node} reached the refreshed machine anchor");
    }
    let (ok, _, err) = vox_stdin(
        &data,
        &cfg,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "mission",
        ],
        Some(ROOM_PASS),
    );
    assert!(ok, "PRODUCT: room create on the daemon failed: {err}");
    let room = {
        let (_, out, err) = vox(&data, &cfg, &["room", "list"]);
        out.split_whitespace()
            .find(|w| w.len() == 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
            .unwrap_or_else(|| {
                panic!(
                    "PRODUCT: `vox room list` shows no room id after `room create`: {out:?} \
                     {err:?}"
                )
            })
            .to_owned()
    };

    // ---- step 2: a second daemon joins through the moved anchor ----
    let (ok, issued, err) = vox(&data, &cfg, &["room", "link", &room]);
    assert!(ok, "PRODUCT: room link failed: {err}");
    let issued = issued.trim();
    assert!(
        !issued.contains(&format!("a={anchor_id}")),
        "PRODUCT: room link carried the hand-added machine anchor: {issued:?}"
    );
    // An explicitly supplied room-link anchor is permitted existing input. Keep only
    // the original room/responder pin, then provide that anchor at its current address.
    // Removing Alice's directly reachable member address forces Bob through the anchor.
    let (base, _) = only_anchor(issued, anchor_id);
    let (_, address) = real_spec
        .split_once('@')
        .expect("APPARATUS: anchor spec was checked above");
    let link = format!("{base}&a={anchor_id}&b={address}");
    if bad_line {
        let stderr = std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default();
        let named = stderr
            .lines()
            .filter(|l| l.contains("line 1 is skipped"))
            .count();
        println!("[proof] the daemon named the bad line {named} time(s) on its stderr");
        assert!(
            named >= 1,
            "PRODUCT: the daemon followed the anchor but never said which line of its anchors file it \
             skipped (\"line 1 is skipped\"). Its stderr: {stderr:?}"
        );
    }
    let bob_data = tmp.path().join("bob-data");
    let bob_cfg = tmp.path().join("bob-cfg");
    std::fs::create_dir_all(&bob_cfg).expect("APPARATUS: harness file I/O");
    let (ok, bob_fp, err) = vox(&bob_data, &bob_cfg, &["id"]);
    assert!(ok, "PRODUCT (staging): bob's `vox id` failed: {err}");
    let bob_fp = bob_fp.trim().to_owned();
    assert_eq!(
        bob_fp.len(),
        52,
        "PRODUCT (staging): bob's `vox id` did not print a fingerprint: {bob_fp:?}"
    );
    let alice_fp = fp.trim().to_owned();
    // Bob has no anchors file and no --anchor: the link is the only way to the room.
    assert!(
        !anchors_file_for(&bob_cfg).exists(),
        "PRODUCT (staging): bob has an anchor of his own, so the link would not be the only way in"
    );
    let bob_err = tmp.path().join("bob.daemon.err");
    let mut bob = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &bob_data)
        .env("VOX_CONFIG_DIR", &bob_cfg)
        .env("VOX_NODE", "default")
        .env_remove("VOX_ANCHORS")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(&bob_err).expect("APPARATUS: harness file I/O"),
        ))
        .spawn()
        .expect("APPARATUS: spawn bob's vox daemon");
    let mut pipe = bob.stdin.take().expect("APPARATUS: bob's daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes())
        .expect("APPARATUS: write bob's passphrase");
    drop(pipe);
    let _bob = Proc(bob);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !vox(&bob_data, &bob_cfg, &["room", "list"]).0 {
        assert!(
            std::time::Instant::now() < deadline,
            "PRODUCT (staging): bob's daemon never answered on its control socket; its stderr: {:?}",
            std::fs::read_to_string(&bob_err).unwrap_or_default()
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // One attempt: a join that fails is the product failing, and retrying past it would hide it.
    let join_started = std::time::Instant::now();
    let (joined, _, join_error) = vox_stdin(
        &bob_data,
        &bob_cfg,
        &["room", "join", "--passphrase-file", "-", &link],
        Some(ROOM_PASS),
    );
    println!(
        "[proof] bob joined through the moved anchor: {joined} in one attempt, {:?}",
        join_started.elapsed()
    );
    assert!(
        joined,
        "PRODUCT: bob could not join the room through the supplied anchor-only link after the anchor \
         moved. The link names the anchor at {real_spec}, bob has no other anchor, so alice \
         must have reached the anchor at its new address and registered the room there. The \
         join said: {:?}\nalice's stderr: {:?}\nbob's stderr: {:?}",
        join_error.trim(),
        std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default(),
        std::fs::read_to_string(&bob_err).unwrap_or_default()
    );

    let (ok, bob_list, err) = vox(&bob_data, &bob_cfg, &["anchor", "list", "--json"]);
    assert!(ok, "PRODUCT: Bob's anchor list failed after joining: {err}");
    let bob_projection: serde_json::Value =
        serde_json::from_str(&bob_list).unwrap_or_else(|error| {
            panic!("PRODUCT: Bob's anchor list returned invalid JSON: {error}: {bob_list:?}")
        });
    let learned = bob_projection["anchors"]
        .as_array()
        .and_then(|anchors| {
            anchors
                .iter()
                .find(|anchor| anchor["fingerprint"] == anchor_id)
        })
        .unwrap_or_else(|| {
            panic!("PRODUCT: Bob's machine list omitted the room-link anchor: {bob_list:?}")
        });
    let sources = learned["sources"]
        .as_array()
        .unwrap_or_else(|| panic!("PRODUCT: Bob's room-link anchor has no sources: {bob_list:?}"));
    assert!(
        sources.len() == 1
            && sources[0]["kind"] == "room"
            && sources[0]["room"]
                .as_str()
                .is_some_and(|id| id.starts_with(&room)),
        "PRODUCT: Bob's room-link anchor was not sourced to the joined room alone: {bob_list:?}"
    );

    // A room-link anchor belongs to Bob's joined room. A second identity on this
    // daemon creates an unrelated room without inheriting that room's input.
    let (ok, _, err) = vox_stdin(
        &bob_data,
        &bob_cfg,
        &["node", "create", "dave", "--passphrase-file", "-"],
        Some(IDENTITY),
    );
    assert!(ok, "PRODUCT: creating Bob's second node failed: {err}");
    let (ok, _, err) = vox(
        &bob_data,
        &bob_cfg,
        &["node", "attach", "dave", "--no-remember"],
    );
    assert!(ok, "PRODUCT: attaching Bob's second node failed: {err}");
    let (ok, _, err) = vox_stdin(
        &bob_data,
        &bob_cfg,
        &[
            "room",
            "create",
            "--node",
            "dave",
            "--passphrase-file",
            "-",
            "--name",
            "unrelated",
        ],
        Some(ROOM_PASS),
    );
    assert!(
        ok,
        "PRODUCT: second node could not create its unrelated room without an anchor: {err}"
    );
    let (ok, report, err) = vox(&bob_data, &bob_cfg, &["status", "--node", "dave", "--json"]);
    assert!(ok, "PRODUCT: second node's public status failed: {err}");
    let status: serde_json::Value = serde_json::from_str(&report).unwrap_or_else(|error| {
        panic!("PRODUCT: second node returned invalid status JSON: {error}: {report:?}")
    });
    assert!(
        status["anchors"].as_array().is_some_and(Vec::is_empty),
        "PRODUCT: unrelated node's status inherited another node's room anchor: {report:?}"
    );
    assert!(status["peers"].as_array().is_some_and(|peers|
        peers.iter().all(|peer| peer["id"] != anchor_id)),
        "PRODUCT: unrelated node's status shows a connection to another node's room anchor: {report:?}");
    let (ok, after, err) = vox(&bob_data, &bob_cfg, &["anchor", "list", "--json"]);
    assert!(
        ok,
        "PRODUCT: machine list failed after unrelated room creation: {err}"
    );
    let after: serde_json::Value = serde_json::from_str(&after)
        .unwrap_or_else(|error| panic!("PRODUCT: machine list returned invalid JSON: {error}"));
    let recorded = after["anchors"]
        .as_array()
        .and_then(|anchors| {
            anchors
                .iter()
                .find(|anchor| anchor["fingerprint"] == anchor_id)
        })
        .unwrap_or_else(|| panic!("PRODUCT: machine list lost Bob's joined-room anchor: {after}"));
    assert_eq!(
        recorded["sources"], learned["sources"],
        "PRODUCT: unrelated room acquired Bob's joined-room anchor source: {after}"
    );
    println!("[proof] unrelated node created its room without inheriting Bob's room anchor");

    // Trust after the join, as `support/room.rs` does (forward-only rooms release a key
    // at once to a member trusted after joining).
    let (ok, _, err) = vox(&data, &cfg, &["trust", "add", &bob_fp, "--name", "bob"]);
    assert!(
        ok,
        "PRODUCT (staging): alice's `vox trust add` failed: {err}"
    );
    let (ok, _, err) = vox(
        &bob_data,
        &bob_cfg,
        &["trust", "add", &alice_fp, "--name", "alice"],
    );
    assert!(ok, "PRODUCT (staging): bob's `vox trust add` failed: {err}");

    // ---- step 3: bob renders a post by alice, carried through the moved anchor ----
    let nonce = format!(
        "moved-anchor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("APPARATUS: clock before the epoch")
            .as_nanos()
    );
    let read_started = std::time::Instant::now();
    let mut posts = 0u32;
    let mut bob_saw = String::new();
    let rendered = loop {
        if read_started.elapsed() > READ_PATIENCE {
            break false;
        }
        posts += 1;
        let (ok, _, err) = vox(
            &data,
            &cfg,
            &["room", "post", &room, &format!("{nonce} #{posts}")],
        );
        assert!(ok, "PRODUCT: alice's vox room post failed: {err}");
        std::thread::sleep(std::time::Duration::from_secs(2));
        let (_, out, _) = vox(&bob_data, &bob_cfg, &["room", "read", &room]);
        if out.contains(&nonce) {
            break true;
        }
        bob_saw = out;
    };
    println!(
        "[proof] bob rendered alice's post: {rendered} after {posts} post(s), {:?}",
        read_started.elapsed()
    );
    assert!(
        rendered,
        "PRODUCT: bob joined but never rendered a post by alice ({posts} posts over {:?}). The room \
         is reachable only through the anchor that moved. bob's read said: {bob_saw:?}\n\
         alice's stderr: {:?}\nbob's stderr: {:?}",
        read_started.elapsed(),
        std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default(),
        std::fs::read_to_string(&bob_err).unwrap_or_default()
    );

    // The anchor must still be the one serving: a join that went anywhere else would
    // not be the claim.
    let alive = anchor
        .0
        .try_wait()
        .expect("APPARATUS: the anchor's exit status could not be read")
        .is_none();
    let anchor_out = std::fs::read_to_string(tmp.path().join("anchor.out")).unwrap_or_default();
    println!(
        "[proof] anchor alive at the end: {alive}; its last line: {:?}",
        anchor_out.lines().last().unwrap_or("")
    );
    assert!(
        alive,
        "PRODUCT (staging): the anchor exited during the run. stdout: {anchor_out:?} stderr: {:?}",
        std::fs::read_to_string(tmp.path().join("anchor.err")).unwrap_or_default()
    );
}

/// `link` with every anchor entry (`a=<id>` and the `b=<addr>` that follow it) removed
/// except `anchor_id`'s; the channel id and the responder pin (`r=`) are kept. Returns
/// the link and how many entries were dropped.
fn only_anchor(link: &str, anchor_id: &str) -> (String, usize) {
    let (head, query) = link.split_once('?').unwrap_or_else(|| {
        panic!("PRODUCT: `vox room link` printed a link with no query: {link:?}")
    });
    let mut kept = Vec::new();
    let mut keeping = false;
    let mut dropped = 0;
    for part in query.split('&') {
        if let Some(id) = part.strip_prefix("a=") {
            keeping = id == anchor_id;
            if !keeping {
                dropped += 1;
            }
        } else if let Some(id) = part.strip_prefix("m=") {
            // A member mark stays only with the entry it marks.
            keeping = id == anchor_id;
        } else if part.starts_with("r=") {
            keeping = true;
        }
        if keeping {
            kept.push(part);
        }
    }
    (format!("{head}?{}", kept.join("&")), dropped)
}

/// The anchors file inside a config dir, as `Paths` lays it out.
fn anchors_file_for(cfg: &std::path::Path) -> std::path::PathBuf {
    cfg.join("anchors")
}
