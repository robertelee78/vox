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
//! **What this drives, with real binaries.** A daemon (alice) starts with an anchors file
//! naming an anchor that is not there. While it runs, the file is rewritten to name the
//! real one — the same edit a dynamic-DNS update amounts to from the node's point of view,
//! since both change what the configuration resolves to. Alice must pick it up without
//! being restarted, and the proof of that is a room joined *through* the anchor
//! afterwards, not a log line saying it noticed:
//!
//! 1. Alice creates a room after the rewrite, and `vox room invite` must come to name the
//!    anchor's real port. That shows only that the room's *record* took the new address
//!    (the record is filled from configuration whether or not anything was reached), so it
//!    is a step, not the claim.
//! 2. A second profile (bob: `vox id`, `vox daemon` with **no anchor of its own**) joins
//!    with that invite, and alice and bob trust each other with `vox trust add`. The invite
//!    also names alice herself, last, with her own addresses; on loopback those are always
//!    reachable (behind a home NAT they are not), so bob is handed the link with every
//!    entry but the anchor's removed. The only way bob can find the room is then the moved
//!    anchor at the address the link carries.
//! 3. Alice posts a line carrying a per-run nonce until bob's `vox room read` renders it.
//!    That needs alice to have dialled the anchor at its new address and registered the
//!    room there: a daemon that records the new address but never reaches it leaves bob
//!    with nothing to join through.
//!
//! **What it does not prove.** A name whose A record moves while the file is untouched
//! is the same code path — the refresh re-reads and re-parses, and parsing is what
//! resolves — but this machine has no DNS record it can move, so that step is reasoned
//! rather than measured. Closing it needs a resolver the proof owns. Recorded here
//! rather than implied by a passing test.
//!
//! **Every participant is the shipped binary**: the anchor is `vox node`, each identity is
//! made by `vox id`, and alice and bob are `vox daemon`s. Nothing in this process runs a
//! node.
//!
//! **Mutations that must turn it red.**
//! - Make the daemon's anchor refresh (`ANCHOR_REFRESH` in `app.rs`) an hour, or drop the
//!   refresh task: red at step 1 after `FOLLOW_PATIENCE`, the invite never names the real
//!   port.
//! - Let the refresh reach the room's record but never dial the new address
//!   (`NodeCommand::AddAnchors` neither merges nor redials, and `adopt_channel_anchors`
//!   records and returns before dialling): step 1 stays green, and step 2 or 3 goes red —
//!   bob cannot join, or never renders alice's post.
//! - Dial the moved anchor but publish no room to it (`NetEvent::AnchorConnected` skips
//!   `publish_channel_to_anchor`): red at step 2 or 3 for the same reason.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::process::{Child, Command, Stdio};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "daemon passphrase";

/// Longer than the daemon's own 30s refresh, with room for a dial afterwards.
const FOLLOW_PATIENCE: std::time::Duration = std::time::Duration::from_secs(120);
/// How long bob may take to render alice's post once both have joined and trust.
const READ_PATIENCE: std::time::Duration = std::time::Duration::from_secs(120);
/// Join attempts for bob, 5 s apart: a join can be turned away while the host is busy
/// admitting (a separate, known defect), and the harness in `support/room.rs` allows 6.
const JOIN_ATTEMPTS: u32 = 6;
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
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    if let Some(text) = input {
        let mut pipe = child.stdin.take().expect("vox stdin");
        pipe.write_all(text.as_bytes()).expect("write stdin");
        drop(pipe);
    }
    let out = child.wait_with_output().expect("vox ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
#[ignore = "production Argon2id, a real anchor and a 30s refresh; CI runs it in release"]
fn a_daemon_picks_up_an_anchor_that_moved_under_it() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();

    // ---- a real anchor, on a port nobody knew at startup ----
    let anchor_data = tmp.path().join("anchor-data");
    let anchor_cfg = tmp.path().join("anchor-cfg");
    std::fs::create_dir_all(&anchor_cfg).unwrap();
    let mut anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &anchor_data)
            .env("VOX_CONFIG_DIR", &anchor_cfg)
            // To a file, never a pipe nobody reads: `vox node` prints a status line each
            // time its peers change, and once the read end of a pipe is gone that print
            // fails and takes the anchor down. An earlier version of this proof dropped
            // the pipe, so the anchor died the moment the daemon reached it — hidden only
            // because the joiner then went to the daemon directly.
            .stdout(Stdio::from(
                std::fs::File::create(tmp.path().join("anchor.out")).unwrap(),
            ))
            .stderr(Stdio::from(
                std::fs::File::create(tmp.path().join("anchor.err")).unwrap(),
            ))
            .spawn()
            .expect("spawn vox node"),
    );
    // `vox node` writes its own spec into its config dir; that file is the truth.
    let anchors_file = anchor_cfg.join("anchors");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let real_spec = loop {
        assert!(
            std::time::Instant::now() < deadline,
            "the anchor never wrote its spec to {}",
            anchors_file.display()
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
    std::fs::create_dir_all(&cfg).unwrap();
    let (ok, fp, err) = vox(&data, &cfg, &["id"]);
    assert!(ok, "vox id: {err}");
    assert_eq!(fp.trim().len(), 52, "`vox id` prints a fingerprint: {fp:?}");
    // The same identity, a different port: reachable by nobody. This stands in for the
    // address a name used to resolve to.
    let wrong_spec = {
        let (id, _) = real_spec.split_once('@').expect("a well-formed spec");
        format!("{id}@/ip4/127.0.0.1/udp/9")
    };
    std::fs::write(anchors_file_for(&cfg), format!("{wrong_spec}\n")).unwrap();

    // ---- the daemon starts against the address that is wrong ----
    let mut daemon = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(tmp.path().join("daemon.err")).unwrap(),
        ))
        .spawn()
        .expect("spawn vox daemon");
    let mut pipe = daemon.stdin.take().expect("daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
    drop(pipe);
    let _daemon = Proc(daemon);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !vox(&data, &cfg, &["room", "list"]).0 {
        assert!(
            std::time::Instant::now() < deadline,
            "CANNOT MEASURE: the daemon never answered on its control socket; its stderr: {:?}",
            std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default()
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // ---- the anchor moves: the configuration is rewritten under the running daemon ----
    std::fs::write(anchors_file_for(&cfg), format!("{real_spec}\n")).unwrap();

    // ---- it must reach the anchor without being restarted ----
    // Creating a room and getting an invite that names the anchor is the observable
    // consequence: a link carries the anchors the node has actually reached, so an
    // invite naming this one is the node saying it followed.
    let (ok, _, err) = vox_stdin(
        &data,
        &cfg,
        &["room", "create", "--name", "mission"],
        Some(ROOM_PASS),
    );
    assert!(ok, "room create on the daemon: {err}");
    let room = {
        let (_, out, _) = vox(&data, &cfg, &["room", "list"]);
        out.split_whitespace()
            .find(|w| w.len() == 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
            .expect("a room id")
            .to_owned()
    };

    // **The address, not the identity.** The wrong spec names the same identity on a
    // dead port — that is what makes it a stand-in for an anchor that moved — so looking
    // for the fingerprint in the invite proves nothing: it is there either way. A first
    // version of this gate did exactly that and passed in 1.8 seconds, which is less
    // than the refresh interval and therefore could not have been a follow at all.
    let real_port = real_spec
        .rsplit('/')
        .next()
        .expect("a port in the anchor spec")
        .to_owned();
    let dead_port = wrong_spec
        .rsplit('/')
        .next()
        .expect("a port in the wrong spec")
        .to_owned();
    assert_ne!(
        real_port, dead_port,
        "the two specs must differ by address, or this gate measures nothing"
    );
    let started = std::time::Instant::now();
    let mut last = String::new();
    let followed = loop {
        if started.elapsed() > FOLLOW_PATIENCE {
            break false;
        }
        let (_, out, _) = vox(&data, &cfg, &["room", "invite", &room]);
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
        "the daemon never reached the anchor its configuration now names, after {:?}. It \
         started against {wrong_spec}, the file was rewritten to {real_spec} while it ran, \
         and an anchor spec may be a NAME precisely so it can move — a node that resolves \
         once holds the address it got at startup for ever. The invite said: {last:?}\n\
         daemon stderr: {:?}",
        started.elapsed(),
        std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default()
    );

    // ---- step 2: a second daemon joins through the moved anchor, with that link ----
    let issued = last.trim().to_owned();
    assert!(
        issued.contains(&format!("/udp/{real_port}")) && !issued.contains('\n'),
        "CANNOT MEASURE: the invite is not one link naming the real port: {issued:?}"
    );
    // **Only the anchor.** An invite also names the issuing node itself, last, with its
    // own addresses — and on loopback those are always reachable, so bob could join
    // alice directly and never touch the anchor (a first version of this step stayed
    // green against a daemon that never dialled the moved anchor, for exactly that
    // reason). Behind a home NAT that entry is what does not work; the anchor is what
    // does. So bob gets the link with every entry but the anchor's removed, which is the
    // link as a NATed joiner can use it.
    let anchor_id = real_spec.split_once('@').expect("a well-formed spec").0;
    let (link, dropped) = only_anchor(&issued, anchor_id);
    println!(
        "[proof] invite carried {} anchor entr(ies); kept the moved anchor's, dropped {dropped}",
        dropped + 1
    );
    assert!(
        link.contains(&format!("a={anchor_id}")) && link.contains(&format!("/udp/{real_port}")),
        "CANNOT MEASURE: the stripped link does not name the anchor at its new address: \
         {link:?} (from {issued:?})"
    );
    let bob_data = tmp.path().join("bob-data");
    let bob_cfg = tmp.path().join("bob-cfg");
    std::fs::create_dir_all(&bob_cfg).unwrap();
    let (ok, bob_fp, err) = vox(&bob_data, &bob_cfg, &["id"]);
    assert!(ok, "bob: vox id: {err}");
    let bob_fp = bob_fp.trim().to_owned();
    assert_eq!(
        bob_fp.len(),
        52,
        "`vox id` prints a fingerprint: {bob_fp:?}"
    );
    let alice_fp = fp.trim().to_owned();
    // Bob has no anchors file and no --anchor: the link is the only way to the room.
    assert!(
        !anchors_file_for(&bob_cfg).exists(),
        "CANNOT MEASURE: bob has an anchor of his own, so the link would not be the only way in"
    );
    let bob_err = tmp.path().join("bob.daemon.err");
    let mut bob = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &bob_data)
        .env("VOX_CONFIG_DIR", &bob_cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&bob_err).unwrap()))
        .spawn()
        .expect("spawn bob's vox daemon");
    let mut pipe = bob.stdin.take().expect("bob's daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
    drop(pipe);
    let _bob = Proc(bob);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !vox(&bob_data, &bob_cfg, &["room", "list"]).0 {
        assert!(
            std::time::Instant::now() < deadline,
            "CANNOT MEASURE: bob's daemon never answered on its control socket; its stderr: {:?}",
            std::fs::read_to_string(&bob_err).unwrap_or_default()
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let join_started = std::time::Instant::now();
    let mut join_attempts = 0u32;
    let mut join_errors = Vec::new();
    let joined = loop {
        join_attempts += 1;
        let (ok, _, err) = vox_stdin(
            &bob_data,
            &bob_cfg,
            &["room", "join", &link, "--name", "mission"],
            Some(ROOM_PASS),
        );
        if ok {
            break true;
        }
        join_errors.push(err.trim().to_owned());
        if join_attempts >= JOIN_ATTEMPTS {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    };
    println!(
        "[proof] bob joined through the moved anchor: {joined} after {join_attempts} attempt(s), {:?}",
        join_started.elapsed()
    );
    assert!(
        joined,
        "bob could not join the room through the link alice issued after the anchor moved \
         ({join_attempts} attempts). The link names the anchor at {real_spec}, bob has no \
         other anchor, so alice must have reached the anchor at its new address and \
         registered the room there. Join errors: {join_errors:?}\nalice's stderr: {:?}\n\
         bob's stderr: {:?}",
        std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default(),
        std::fs::read_to_string(&bob_err).unwrap_or_default()
    );

    // Trust after the join, as `support/room.rs` does (forward-only rooms release a key
    // at once to a member trusted after joining).
    let (ok, _, err) = vox(&data, &cfg, &["trust", "add", &bob_fp, "--name", "bob"]);
    assert!(ok, "alice trusts bob: {err}");
    let (ok, _, err) = vox(
        &bob_data,
        &bob_cfg,
        &["trust", "add", &alice_fp, "--name", "alice"],
    );
    assert!(ok, "bob trusts alice: {err}");

    // ---- step 3: bob renders a post by alice, carried through the moved anchor ----
    let nonce = format!(
        "moved-anchor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
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
        assert!(ok, "alice posts: {err}");
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
        "bob joined but never rendered a post by alice ({posts} posts over {:?}). The room \
         is reachable only through the anchor that moved. bob's read said: {bob_saw:?}\n\
         alice's stderr: {:?}\nbob's stderr: {:?}",
        read_started.elapsed(),
        std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default(),
        std::fs::read_to_string(&bob_err).unwrap_or_default()
    );

    // The anchor must still be the one serving: a join that went anywhere else would
    // not be the claim.
    let alive = anchor.0.try_wait().expect("anchor status").is_none();
    let anchor_out = std::fs::read_to_string(tmp.path().join("anchor.out")).unwrap_or_default();
    println!(
        "[proof] anchor alive at the end: {alive}; its last line: {:?}",
        anchor_out.lines().last().unwrap_or("")
    );
    assert!(
        alive,
        "CANNOT MEASURE: the anchor exited during the run. stdout: {anchor_out:?} stderr: {:?}",
        std::fs::read_to_string(tmp.path().join("anchor.err")).unwrap_or_default()
    );
}

/// `link` with every anchor entry (`a=<id>` and the `b=<addr>` that follow it) removed
/// except `anchor_id`'s; the channel id and the responder pin (`r=`) are kept. Returns
/// the link and how many entries were dropped.
fn only_anchor(link: &str, anchor_id: &str) -> (String, usize) {
    let (head, query) = link.split_once('?').expect("an invite link has a query");
    let mut kept = Vec::new();
    let mut keeping = false;
    let mut dropped = 0;
    for part in query.split('&') {
        if let Some(id) = part.strip_prefix("a=") {
            keeping = id == anchor_id;
            if !keeping {
                dropped += 1;
            }
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
