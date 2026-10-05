//! PRD-001 R14 on the receiving side — a member deletes another member's superseded sender key
//! once it has read everything sealed under it — driven through the **shipped `vox` binary**.
//!
//! "Sender keys no longer needed must be deleted (forward secrecy)." The sender's own store is
//! proved in `history_grant_proof`; this proves the copies the other members were given. A member
//! that kept every generation it was ever given could still open all of them from its store.
//!
//! What runs: alice, bob and carol join alice's room, and each trusts the others. Alice posts
//! three messages, then stops trusting carol, which rotates her sender key, and posts three more.
//!
//! - **Staging (CANNOT MEASURE if not achieved):** carol reads the first three and none of the
//!   later three, so a new generation really was started and withheld from her.
//! - **PRODUCT:** bob reads all six; then bob's `vox status --json` reports **one** generation of
//!   received sender keys for the room, not two; bob still reads all six after his daemon
//!   restarts, so deleting the key took no message he had read; and he reads a seventh post, so
//!   the live generation was kept.
//!
//! - **PRODUCT:** alice then trusts carol again and posts: carol reads it within 90 s, and
//!   neither alice's own count of generations nor bob's received count grows back. A re-offer
//!   after R14 deleted a generation skips it and does not fail (V210-118).
//!
//! **Not driven here:** a generation kept because an entry under it is **not received yet**
//! (V030-10). Its body is still to come and its generation unknown until it does, so the prune
//! keeps every generation from that entry on (`ChannelState::prune_superseded_receivers`).
//!
//! Mutation (red): receiver pruning disabled leaves bob's count at 2.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One `vox` run against `dir`'s profile: `(succeeded, stdout, stderr)`.
fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox {args:?}: {e}"));
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: the piped stdin was not opened")
            .write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write vox {args:?}'s stdin: {e}"));
        drop(child.stdin.take());
    }
    // Bounded: a node that stops answering fails this proof by name rather than hanging it.
    let deadline = Instant::now() + Duration::from_secs(120);
    while child
        .try_wait()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot poll vox {args:?}: {e}"))
        .is_none()
    {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "PRODUCT: `vox {}` got no answer in 120 s: the node stopped answering",
                args.join(" ")
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot collect vox {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn daemon(dir: &Path, tag: &str) -> Daemon {
    let log = |ext: &str| {
        std::fs::File::create(dir.join(format!("daemon-{tag}.{ext}")))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot create {tag}'s daemon log: {e}"))
    };
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log("out")))
        .stderr(Stdio::from(log("err")))
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn {tag}'s vox daemon: {e}"));
    let mut pipe = child
        .stdin
        .take()
        .expect("APPARATUS: the daemon's stdin was not opened");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes())
        .unwrap_or_else(|e| panic!("APPARATUS: cannot unlock {tag}'s daemon: {e}"));
    drop(pipe);
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !vox(dir, &["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): {tag}'s daemon never answered `vox room list` in 90 s: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    d
}

fn identity(tmp: &Path, name: &str) -> (PathBuf, String) {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make {name}'s profile dir: {e}"));
    let (ok, out, err) = vox(&dir, &["id"], None);
    assert!(ok, "PRODUCT (staging): {name}'s `vox id` failed: {err}");
    (dir, out.trim().to_owned())
}

/// The texts `vox room read` returns.
fn read(dir: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "PRODUCT: `vox room read` failed: {err}");
    out.lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

fn count(texts: &[String], prefix: &str) -> usize {
    texts.iter().filter(|t| t.starts_with(prefix)).count()
}

/// Read `room` on `dir` until `done`, for at most `secs`; the last read either way.
fn read_until(
    dir: &Path,
    room: &str,
    secs: u64,
    done: impl Fn(&[String]) -> bool,
) -> (bool, Vec<String>) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let last = read(dir, room);
        if done(&last) {
            return (true, last);
        }
        if Instant::now() >= deadline {
            return (false, last);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(
        ok,
        "PRODUCT (staging): `vox room post {text:?}` failed: {err}"
    );
}

fn trust(dir: &Path, fp: &str, name: &str) {
    let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
    assert!(
        ok,
        "PRODUCT (staging): `vox trust add {name}` failed: {err}"
    );
}

fn join(creator: &Path, joiner: &Path, room: &str) {
    let (ok, link, err) = vox(creator, &["room", "link", room], None);
    assert!(ok, "PRODUCT (staging): `vox room link` failed: {err}");
    let (ok, _, err) = vox(
        joiner,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room join` failed: {err}");
}

/// `key_generations` (this node's own sender keys) for the room, from `vox status --json`.
fn generations(dir: &Path) -> Option<u64> {
    status(dir)["rooms"][0]["key_generations"].as_u64()
}

fn status(dir: &Path) -> serde_json::Value {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(ok, "PRODUCT: `vox status --json` failed: {err}");
    serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON ({e}): {out}"))
}

/// `received_key_generations` for the room, from `vox status --json`.
fn received(dir: &Path) -> Option<u64> {
    status(dir)["rooms"][0]["received_key_generations"].as_u64()
}

#[test]
#[ignore = "three real vox daemons and production Argon2id; CI runs it in release"]
fn a_member_deletes_another_members_key_once_it_has_read_everything_sealed_under_it() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: tempdir: {e}"));
    let tmp = tmp.path();
    let (alice, alice_fp) = identity(tmp, "alice");
    let (bob, bob_fp) = identity(tmp, "bob");
    let (carol, carol_fp) = identity(tmp, "carol");
    let _a = daemon(&alice, "alice");
    let mut b = daemon(&bob, "bob");
    let _c = daemon(&carol, "carol");

    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room create` failed: {err}");
    let (_, listed, _) = vox(&alice, &["room", "list"], None);
    let room = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` shows no room after create"))
        .to_owned();
    join(&alice, &bob, &room);
    join(&alice, &carol, &room);
    trust(&alice, &bob_fp, "bob");
    trust(&alice, &carol_fp, "carol");
    trust(&bob, &alice_fp, "alice");
    trust(&carol, &alice_fp, "alice");

    for i in 1..=3 {
        post(&alice, &room, &format!("first {i}"));
    }
    let (ok, c) = read_until(&carol, &room, 90, |t| count(t, "first ") == 3);
    assert!(
        ok,
        "PRODUCT (staging): carol, trusted, never read alice's first 3 posts in 90 s: {c:?}"
    );
    // Removing carol rotates alice's sender key: the later posts are under a new generation.
    let (ok, _, err) = vox(&alice, &["trust", "remove", &carol_fp], None);
    assert!(
        ok,
        "PRODUCT (staging): `vox trust remove carol` failed: {err}"
    );
    for i in 1..=3 {
        post(&alice, &room, &format!("later {i}"));
    }

    let (ok, t) = read_until(&bob, &room, 90, |t| {
        count(t, "first ") == 3 && count(t, "later ") == 3
    });
    assert!(
        ok,
        "PRODUCT: bob never read all 6 of alice's posts in 90 s: {t:?}"
    );
    // Staging: the later posts are under a generation carol was never given.
    let c = read(&carol, &room);
    assert!(
        count(&c, "first ") == 3 && count(&c, "later ") == 0,
        "CANNOT MEASURE: carol's view does not show a rotation (3 earlier and none later \
         expected), so there is no superseded generation to delete: {c:?}"
    );

    // ---- R14: bob deletes the generation he has read to the end -------------------------
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut held = received(&bob);
    while held != Some(1) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        held = received(&bob);
    }
    println!("[proof] bob holds {held:?} generation(s) of received sender keys");
    assert_eq!(
        held,
        Some(1),
        "PRODUCT: bob read everything under alice's superseded generation and still holds its \
         key 60 s later (`vox status --json` received_key_generations)"
    );

    // Deleting it took nothing bob had read, and the live generation still opens.
    drop(b);
    b = daemon(&bob, "bob-restarted");
    let t = read(&bob, &room);
    assert!(
        count(&t, "first ") == 3 && count(&t, "later ") == 3,
        "PRODUCT: after the key went and his daemon restarted, bob no longer shows all 6: {t:?}"
    );
    post(&alice, &room, "latest");
    let (ok, t) = read_until(&bob, &room, 90, |t| count(t, "latest") == 1);
    assert!(
        ok,
        "PRODUCT: bob never read alice's post under the live generation in 90 s: {t:?}"
    );
    println!("[proof] bob read 3 + 3 before and after the restart, and the later post");

    // ---- A re-offer after the deletion sends nothing retired and does not fail -----------
    // Alice trusting carol again offers carol every generation she is entitled to (V210-118),
    // and carol's key arriving fresh at alice re-offers alice's: generations retired and
    // deleted by now must be skipped, not fail the round. What a person sees: carol reads what
    // alice posts next, and no deleted key comes back on either side.
    let alice_held = generations(&alice);
    trust(&alice, &carol_fp, "carol");
    post(&alice, &room, "again");
    let (ok, c) = read_until(&carol, &room, 90, |t| count(t, "again") == 1);
    println!("[proof] carol, trusted again, shows {c:?}");
    assert!(
        ok,
        "PRODUCT: carol, trusted again, never read alice's next post in 90 s: the re-offer after \
         R14's deletion did not get through: {c:?}"
    );
    let (alice_after, bob_after) = (generations(&alice), received(&bob));
    println!(
        "[proof] after the re-offer: alice holds {alice_after:?} generation(s) (was \
         {alice_held:?}), bob {bob_after:?} received"
    );
    assert!(
        alice_after.is_some() && alice_after <= alice_held && bob_after == Some(1),
        "PRODUCT: a re-offer brought a deleted key back: alice holds {alice_after:?} (was \
         {alice_held:?}), bob holds {bob_after:?} received (want 1)"
    );
    drop(b);
}
