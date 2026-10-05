//! V210-137 (#356) — **after a room re-keys, a member who reaches the others only through an
//! anchor, and a joiner who comes after, are still in step**, through the shipped `vox` binary.
//!
//! The defect as filed: the anchor's own copy of a room (`node/anchor.rs`) recorded `epoch: 0`
//! only, so after an epoch change what an anchor held and served could describe the wrong epoch.
//! That copy was deleted with ADR-023 M23.5 (8e912563): an anchor now holds only rendezvous board
//! records, each signed by its member for the `(room, epoch)` that member is in. And no operation
//! advances a room's epoch (ADR-007 G-21): a removal re-keys the room by rotating the remover's
//! sender key, inside the epoch.
//!
//! **What this drives.** An anchor (`vox node`, dual-stack), alice and bob on `127.0.0.1`, carol on
//! `[::1]`: carol reaches alice and bob only through the anchor (its board and its circuits). All
//! three join alice's room with `vox room join`. Then alice removes bob (`vox trust remove`), which
//! re-keys the room, and posts. Then dave, also on `[::1]` only, joins after the re-key.
//!
//! **What is asserted.**
//! - The re-key happened: alice's room holds a new sender-key generation, and bob, removed, reads
//!   none of her later posts once carol has them (PRODUCT (staging) otherwise).
//! - carol reads every post alice made after the re-key within [`PROMPT`] of the post.
//! - dave, who joins through the anchor after the re-key, gets in and reads them within [`PROMPT`]
//!   of his join.
//! - Every node reports the same epoch for the room, before and after the re-key (`vox status
//!   --json`).
//!
//! **Mutant:** the re-key is not delivered to a member reached over a relay (in vox-core's
//! `Node::deliver_rekeys_for`, `node/actor.rs`, a target whose connection is relayed is skipped):
//! carol never gets alice's new generation, and this goes red as PRODUCT at "carol … must read
//! every post alice made after the re-key".

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

#[path = "support/family_split.rs"]
mod family_split;

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use relay::{Anchor, Split};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "room passphrase";
/// How soon a post must be read by a member reached only through the anchor, and a joiner must
/// read what was said before it joined.
const PROMPT: Duration = Duration::from_secs(30);
/// What alice posts after the re-key.
const AFTER: [&str; 3] = ["AFTER-REKEY-1", "AFTER-REKEY-2", "AFTER-REKEY-3"];

fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = args.to_vec();
    match world::attach::needs(dir, &verb) {
        Some(node) => {
            world::attach::Root::at(dir, IDPASS).attached(&node, || vox_plain(dir, args, stdin))
        }
        None => vox_plain(dir, args, stdin),
    }
}

fn vox_plain(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: the harness could not spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child
            .stdin
            .take()
            .expect("APPARATUS: the harness has no stdin pipe");
        pipe.write_all(text.as_bytes())
            .expect("PRODUCT (staging): the harness could not write to stdin");
    }
    let out = child
        .wait_with_output()
        .expect("APPARATUS: the harness could not wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn reads(dir: &std::path::Path, room: &str, text: &str) -> bool {
    vox(dir, &["room", "read", room], None).1.contains(text)
}

fn until(what: &str, secs: u64, ok: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("[proof] {what}: not within {secs} s");
    false
}

/// A daemon, killed by its own PID however the test ends, its output kept.
struct Daemon(Child, Arc<Mutex<String>>);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    fn said(&self) -> String {
        self.1
            .lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
            .clone()
    }
}

fn daemon(dir: &std::path::Path, listen: &str, anchors: &[&str]) -> Daemon {
    daemon_with(dir, listen, anchors, &[])
}

/// [`daemon`], with `env` set for it.
fn daemon_with(
    dir: &std::path::Path,
    listen: &str,
    anchors: &[&str],
    env: &[(&str, &str)],
) -> Daemon {
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", listen])
        .args(anchors.iter().flat_map(|a| ["--anchor", a]))
        .envs(env.iter().copied())
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: the harness could not spawn a daemon");
    let mut pipe = child
        .stdin
        .take()
        .expect("APPARATUS: the harness has no stdin pipe");
    pipe.write_all(format!("{IDPASS}\n").as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    drop(pipe);
    let said = Arc::new(Mutex::new(String::new()));
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let sink = Arc::clone(&said);
        let mut stream = stream;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink
                        .lock()
                        .expect("APPARATUS: a lock the proof holds was poisoned")
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }
    let d = Daemon(child, said);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !d
        .1
        .lock()
        .expect("APPARATUS: a lock the proof holds was poisoned")
        .contains("control socket")
    {
        assert!(
            Instant::now() < deadline,
            "PRODUCT: a `vox daemon` never served its control socket:\n{}",
            d.1.lock()
                .expect("APPARATUS: a lock the proof holds was poisoned")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

/// Each of the node's rooms by id: its epoch and its own sender-key generations, from `vox status
/// --json`.
fn room_state(dir: &std::path::Path, room: &str) -> Option<(u64, u64)> {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(ok, "PRODUCT (staging): `vox status --json` failed: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON ({e}): {out}"));
    v["rooms"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["id"].as_str().is_some_and(|id| id.starts_with(room)))
        .map(|r| {
            (
                r["epoch"].as_u64().unwrap_or(u64::MAX),
                r["key_generations"].as_u64().unwrap_or(0),
            )
        })
}

/// The path of the node's connection to `peer` (`direct`, `relayed`, or `none`), from its own
/// `vox status --json`.
fn path_to(dir: &std::path::Path, peer: &str) -> String {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(ok, "PRODUCT (staging): `vox status --json` failed: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON ({e}): {out}"));
    v["reach"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["peer"].as_str() == Some(peer))
        .and_then(|r| r["path"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "none".to_owned())
}

fn join(dir: &std::path::Path, link: &str, who: &str) {
    let (ok, _, err) = vox(
        dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            link,
            "--name",
            "rekeyed",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): {who}'s join failed: {err}");
}

#[test]
#[ignore = "an anchor and four vox daemons with production Argon2id; run in release"]
fn a_member_reached_only_through_the_anchor_and_a_later_joiner_stay_in_step_after_a_rekey() {
    watchdog::arm();
    family_split::assert_the_families_are_split();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let names = ["alice", "bob", "carol", "dave"];
    let dirs: Vec<std::path::PathBuf> = names.iter().map(|n| tmp.path().join(n)).collect();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
    }
    let _reaper = world::Reaper(dirs.clone());
    let (alice, bob, carol, dave) = (&dirs[0], &dirs[1], &dirs[2], &dirs[3]);
    let anchor = Anchor::start(&tmp.path().join("anchor"));
    let mut fps = Vec::new();
    for d in &dirs {
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    let v6 = Split::Families.guest_spec(&anchor).to_owned();
    let _a = daemon(alice, "127.0.0.1:0", &[&anchor.v4_spec]);
    let _b = daemon(bob, "127.0.0.1:0", &[&anchor.v4_spec]);
    let carol_d = daemon(carol, Split::Families.guest_listen(), &[&v6]);
    for (i, name) in [(1usize, "bob"), (2, "carol"), (3, "dave")] {
        let (ok, _, err) = vox(alice, &["trust", "add", &fps[i], "--name", name], None);
        assert!(ok, "PRODUCT (staging): alice trusts {name}: {err}");
    }
    for i in 1..=2 {
        let (ok, _, err) = vox(
            &dirs[i],
            &["trust", "add", &fps[0], "--name", "alice"],
            None,
        );
        assert!(ok, "PRODUCT (staging): {} trusts alice: {err}", names[i]);
    }
    let (ok, _, err) = vox(
        alice,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "rekeyed",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): room create: {err}");
    let listed = vox(alice, &["room", "list"], None).1;
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("PRODUCT (staging): no room id in `vox room list` after `room create`")
        .to_owned();
    let (ok, link, err) = vox(alice, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): room invite: {err}");
    let link = link.trim().to_owned();
    join(bob, &link, "bob");
    join(carol, &link, "carol");

    // ---- precondition: bob and carol read alice ----
    let (ok, _, err) = vox(alice, &["room", "post", &room, "BEFORE-REKEY"], None);
    assert!(ok, "PRODUCT (staging): alice's post: {err}");
    assert!(
        until("bob and carol read alice's first post", 90, || {
            reads(bob, &room, "BEFORE-REKEY") && reads(carol, &room, "BEFORE-REKEY")
        }),
        "PRODUCT (staging): bob and carol did not read alice's first post within 90 s"
    );
    // carol's only way to alice is the anchor: her connection to alice is relayed.
    let carol_path = path_to(carol, &fps[0]);
    eprintln!("[proof] carol's path to alice: {carol_path}");
    assert!(
        carol_path == "relayed",
        "PRODUCT (staging): carol on [::1] must reach alice only through the anchor; her path to \
         alice is {carol_path}"
    );
    let before: Vec<Option<(u64, u64)>> = [alice, bob, carol]
        .iter()
        .map(|d| room_state(d, &room))
        .collect();

    // ---- the re-key: alice removes bob, and posts ----
    let (ok, out, err) = vox(alice, &["trust", "remove", &fps[1]], None);
    assert!(
        ok,
        "PRODUCT (staging): alice's `vox trust remove bob`: {out}{err}"
    );
    let posted = Instant::now();
    for text in AFTER {
        let (ok, _, err) = vox(alice, &["room", "post", &room, text], None);
        assert!(ok, "PRODUCT (staging): alice's post {text}: {err}");
    }
    let carol_in_step = until(
        "carol reads every post after the re-key",
        PROMPT.as_secs(),
        || {
            let shown = vox(carol, &["room", "read", &room], None).1;
            AFTER.iter().all(|t| shown.contains(t))
        },
    );
    let carol_took = posted.elapsed();
    let after: Vec<Option<(u64, u64)>> = [alice, bob, carol]
        .iter()
        .map(|d| room_state(d, &room))
        .collect();
    let bob_read = {
        let shown = vox(bob, &["room", "read", &room], None).1;
        AFTER.iter().filter(|t| shown.contains(*t)).count()
    };
    eprintln!(
        "[proof] room {room}: (epoch, own key generations) before the re-key alice/bob/carol \
         {before:?}, after {after:?}; carol read every post after the re-key: {carol_in_step} in \
         {:.1}s; bob, removed, reads {bob_read} of them",
        carol_took.as_secs_f64()
    );
    let (gen_before, gen_after) = (before[0].map_or(0, |s| s.1), after[0].map_or(0, |s| s.1));
    assert!(
        gen_after > gen_before && bob_read == 0,
        "PRODUCT (staging): alice's `vox trust remove bob` must re-key the room — a new sender-key \
         generation ({gen_before} before, {gen_after} after) that bob cannot read ({bob_read} of \
         {} read)",
        AFTER.len()
    );
    assert!(
        carol_in_step,
        "PRODUCT: carol, who reaches the others only through the anchor, must read every post \
         alice made after the re-key within {PROMPT:?}; she reads:\n{}\nher daemon \
         said:\n{}",
        vox(carol, &["room", "read", &room], None).1,
        carol_d.said()
    );

    // ---- a joiner after the re-key, through the anchor only ----
    let (ok, _, err) = vox(dave, &["trust", "add", &fps[0], "--name", "alice"], None);
    assert!(ok, "PRODUCT (staging): dave trusts alice: {err}");
    let dave_d = daemon(dave, Split::Families.guest_listen(), &[&v6]);
    let t = Instant::now();
    join(dave, &link, "dave");
    let dave_in_step = until(
        "dave reads every post after the re-key",
        PROMPT.as_secs(),
        || {
            let shown = vox(dave, &["room", "read", &room], None).1;
            AFTER.iter().all(|t| shown.contains(t))
        },
    );
    let dave_state = room_state(dave, &room);
    eprintln!(
        "[proof] dave joined and read every post after the re-key: {dave_in_step} in {:.1}s; his \
         (epoch, generations) {dave_state:?}",
        t.elapsed().as_secs_f64()
    );
    assert!(
        dave_in_step,
        "PRODUCT: dave, joining through the anchor only after the re-key, must read every post \
         alice made after it within {PROMPT:?} of his join; he reads:\n{}\nhis \
         daemon said:\n{}",
        vox(dave, &["room", "read", &room], None).1,
        dave_d.said()
    );
    let epochs: Vec<u64> = before
        .iter()
        .chain(after.iter())
        .chain(std::iter::once(&dave_state))
        .map(|s| s.map_or(u64::MAX, |s| s.0))
        .collect();
    assert!(
        epochs.iter().all(|e| *e == epochs[0]) && epochs[0] != u64::MAX,
        "PRODUCT: every node must report one epoch for the room, before and after the re-key: \
         {epochs:?}"
    );
}
