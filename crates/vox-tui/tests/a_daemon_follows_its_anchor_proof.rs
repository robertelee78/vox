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
//! 1. Alice creates a room after the rewrite, and `vox room link` must come to name the
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
//!
//! **V210-75 (#266): the addresses are replaced, and a bad line is skipped.** Two more cases
//! run the same scene:
//! - [`a_daemon_follows_an_anchor_that_had_eight_addresses`]: the file first names the anchor at
//!   **eight** dead addresses, the most one anchor may have. A refresh used to *add* the new
//!   address to the old ones, so the ninth did not fit, the refresh failed every 30 s, and the
//!   anchor could not be followed at all.
//! - [`a_bad_anchors_file_line_is_skipped_and_named`]: both versions of the file start with a
//!   line whose host does not resolve (`.invalid`, RFC 2606). One such line used to fail the whole
//!   file: the daemon would not start, and the refresh skipped every update. Now the daemon must
//!   start, follow the anchor, and say `line 1 is skipped` on its stderr.
//!
//! In every case the invite's entry for the anchor must name **only** the real port: the dead
//! addresses are replaced, not kept first in line to be dialled before it.
//!
//! **Mutations that must turn these red (V210-75).**
//! - `BootstrapSet::merge_endpoints` appends addresses again (the union): the eight-address case
//!   is red at step 1 (never follows), and the other two at the only-the-real-port check.
//! - `merge_anchors_file` fails the file on a bad line again (`?`): the bad-line case is red, the
//!   daemon does not start.

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
    follow(&[9], false);
}

#[test]
#[ignore = "production Argon2id, a real anchor and a 30s refresh; CI runs it in release"]
fn a_daemon_follows_an_anchor_that_had_eight_addresses() {
    // Eight: the most addresses one anchor may have (`MAX_ENDPOINTS`), written out here so a
    // changed constant does not silently change what this case measures.
    follow(&[9, 10, 11, 12, 13, 14, 15, 16], false);
}

#[test]
#[ignore = "production Argon2id, a real anchor and a 30s refresh; CI runs it in release"]
fn a_bad_anchors_file_line_is_skipped_and_named() {
    follow(&[9], true);
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

    // ---- the anchor moves: the configuration is rewritten under the running daemon ----
    std::fs::write(anchors_file_for(&cfg), format!("{bad}{real_spec}\n"))
        .expect("APPARATUS: harness file I/O");

    // ---- it must reach the anchor without being restarted ----
    // Creating a room and getting an invite that names the anchor is the observable
    // consequence: a link carries the anchors the node has actually reached, so an
    // invite naming this one is the node saying it followed.
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

    // **The address, not the identity.** The wrong spec names the same identity on a
    // dead port — that is what makes it a stand-in for an anchor that moved — so looking
    // for the fingerprint in the invite proves nothing: it is there either way. A first
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
        let (_, out, _) = vox(&data, &cfg, &["room", "link", &room]);
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
        "PRODUCT: the daemon never reached the anchor its configuration now names, after {:?}. It \
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
        "PRODUCT (staging): the invite is not one link naming the real port: {issued:?}"
    );
    // **Only the anchor.** An invite also names the issuing node itself, last, with its
    // own addresses — and on loopback those are always reachable, so bob could join
    // alice directly and never touch the anchor (a first version of this step stayed
    // green against a daemon that never dialled the moved anchor, for exactly that
    // reason). Behind a home NAT that entry is what does not work; the anchor is what
    // does. So bob gets the link with every entry but the anchor's removed, which is the
    // link as a NATed joiner can use it.
    let (link, dropped) = only_anchor(&issued, anchor_id);
    println!(
        "[proof] invite carried {} anchor entr(ies); kept the moved anchor's, dropped {dropped}",
        dropped + 1
    );
    assert!(
        link.contains(&format!("a={anchor_id}")) && link.contains(&format!("/udp/{real_port}")),
        "PRODUCT (staging): the stripped link does not name the anchor at its new address: \
         {link:?} (from {issued:?})"
    );
    // **Replaced, not accumulated** (V210-75): the anchor's entry names the address it has now,
    // and none of the ones it had. Kept, they would stay first in line to be dialled.
    let addresses: Vec<&str> = link
        .split('&')
        .filter_map(|p| p.strip_prefix("b="))
        .collect();
    println!(
        "[proof] the anchor's entry names {} address(es) after the move (it had {}): {addresses:?}",
        addresses.len(),
        dead_ports.len()
    );
    assert!(
        addresses.len() == 1 && addresses[0].ends_with(&format!("/udp/{real_port}")),
        "PRODUCT: the invite's entry for the moved anchor must name only its new address, port \
         {real_port}; it names {addresses:?}. The {} address(es) it had before the move were \
         kept beside the new one rather than replaced.",
        dead_ports.len()
    );
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

    // **Bob joins once alice says the anchor has the room.** When the invite was issued before the
    // anchor took the room, alice said "anchor … has not taken room … yet … this node will say when
    // it has", and a guest who joins before then is turned away by design. So the proof waits for
    // her own "anchor … has taken room …", then joins once: no retry past a refusal. Alice never
    // saying so is the product's (she did not register the room at the anchor's new address).
    let alice_err = tmp.path().join("daemon.err");
    let owed = std::time::Instant::now() + FOLLOW_PATIENCE;
    loop {
        let said = std::fs::read_to_string(&alice_err).unwrap_or_default();
        if said.contains("has taken room") || !said.contains("has not taken room") {
            break;
        }
        assert!(
            std::time::Instant::now() < owed,
            "PRODUCT: alice said the anchor at {real_spec} had not taken the room, and never said \
             it had within {FOLLOW_PATIENCE:?}: she did not register it at the anchor's new \
             address\nalice's stderr: {said:?}"
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    // One attempt: a join that fails is the product failing, and retrying past it would hide it.
    let join_started = std::time::Instant::now();
    let (joined, _, join_error) = vox_stdin(
        &bob_data,
        &bob_cfg,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "mission",
        ],
        Some(ROOM_PASS),
    );
    println!(
        "[proof] bob joined through the moved anchor: {joined} in one attempt, {:?}",
        join_started.elapsed()
    );
    assert!(
        joined,
        "PRODUCT: bob could not join the room through the link alice issued after the anchor \
         moved. The link names the anchor at {real_spec}, bob has no other anchor, so alice \
         must have reached the anchor at its new address and registered the room there. The \
         join said: {:?}\nalice's stderr: {:?}\nbob's stderr: {:?}",
        join_error.trim(),
        std::fs::read_to_string(tmp.path().join("daemon.err")).unwrap_or_default(),
        std::fs::read_to_string(&bob_err).unwrap_or_default()
    );

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
