//! PRD-001 R14 on the receiving side — a member deletes another member's superseded sender key
//! once it has read everything sealed under it — driven through the **shipped `vox` binary**.
//!
//! "Sender keys no longer needed must be deleted (forward secrecy)." The sender's own store is
//! proved in `an_author_keeps_a_key_only_while_a_member_still_needs_it_proof`; this proves the
//! copies the other members were given. A member that kept every generation it was ever given
//! could still open all of them from its store. A key deleted stays deleted (design-4 R1): a
//! later offer of it is answered as taken and installs nothing.
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
//! - **Same receiver** (ruling-2 #7): bob stops trusting alice; alice makes room s, bob and
//!   carol join, and alice writes under generations 0, 1 and 2 of it (two rotations by removing
//!   carol). Bob trusts alice again; his node holds her generation 0 back (apparatus,
//!   `VOX_TEST_FWD_HOLD_KEY_FILE`, `NotAccepted` to a key handed over directly, so it stays owed)
//!   and takes 1 and 2. **PRODUCT:** he reads generations 1 and 2, holds one of her keys in room
//!   s once 1 is read and 2 proved (generation 1 deleted while 0 is still to come, and her
//!   retries offer the deleted 1 again).
//! - **A key-package re-offer** (design-4 §3): bob's node goes down while alice still owes him
//!   generation 0, so what she owes him goes into room s's log as key packages, one per
//!   generation from his floor (0) to her live one (2): the deleted generation 1 is offered again
//!   by package (staging: alice's daemon says three keys for him went into room s's log). He
//!   comes back with generation 0 still held back when handed over directly, so it can come only
//!   by package. **PRODUCT:** he reads generation 0's posts late; every row he read in both rooms
//!   is still shown; his status shows one received generation of hers in room s, and he ends
//!   holding one key of hers in each room.
//! - **A Drive key is another namespace** (design-4 R1): alice then trusts bob with drive and
//!   opens a Session in room s. Her first drive key there is generation 0 (`begin_drive`,
//!   `channel/pending_session.rs`), the number of a room key of hers bob deleted. **PRODUCT:** bob
//!   lists her Session as one he can drive (`vox room sessions --json`, `can_drive`), which a node
//!   says only of an author whose current drive key it holds.
//!
//! **Not driven here:** a generation kept because an entry under it is **not received yet**
//! (V030-10). Its body is still to come and its generation unknown until it does, so the prune
//! keeps every generation from that entry on (the native R14 key-pruning selector).
//!
//! Mutation (red): `VOX_TEST_FWD_MUTANT=floor-not-exact` (a deletion recorded as "deleted
//! through" instead of exactly) → "bob never read post 0.x".

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/typed.rs"]
mod typed;

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
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM");
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
    let mut child = cmd
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
    daemon_with(dir, tag, &[])
}

fn daemon_with(dir: &Path, tag: &str, env: &[(&str, &Path)]) -> Daemon {
    let log = |ext: &str| {
        std::fs::File::create(dir.join(format!("daemon-{tag}.{ext}")))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot create {tag}'s daemon log: {e}"))
    };
    let mut cmd = Command::new(VOX);
    // The run's mutant selector reaches the daemon only by name: a proof process keeps no
    // `VOX_TEST_*` of the shell that runs it (`temp_home.rs`).
    if let Some(mutant) = std::env::var_os("VOX_MUTANT_FWD") {
        cmd.env("VOX_TEST_FWD_MUTANT", mutant);
    }
    let mut child = cmd
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .envs(env.iter().copied())
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

/// `room`'s row in `vox status --json`.
fn room_status(dir: &Path, room: &str) -> serde_json::Value {
    let same = |a: &str, b: &str| a.starts_with(b) || b.starts_with(a);
    status(dir)["rooms"]
        .as_array()
        .and_then(|rooms| {
            rooms
                .iter()
                .find(|r| r["id"].as_str().is_some_and(|id| same(id, room)))
                .cloned()
        })
        .unwrap_or(serde_json::Value::Null)
}

/// `key_generations` (this node's own sender keys) for `room`, from `vox status --json`.
fn generations(dir: &Path, room: &str) -> Option<u64> {
    room_status(dir, room)["key_generations"].as_u64()
}

fn status(dir: &Path) -> serde_json::Value {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(ok, "PRODUCT: `vox status --json` failed: {err}");
    serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON ({e}): {out}"))
}

/// `received_key_generations` for `room`, from `vox status --json`.
fn received(dir: &Path, room: &str) -> Option<u64> {
    room_status(dir, room)["received_key_generations"].as_u64()
}

/// Poll `received` until it is `want`, for at most `secs`; the last reading either way.
fn received_until(dir: &Path, room: &str, want: u64, secs: u64) -> Option<u64> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut held = received(dir, room);
    while held != Some(want) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        held = received(dir, room);
    }
    held
}

/// Create a room named `name` on `dir` and return its id as `vox room list` shows it.
fn create(dir: &Path, name: &str) -> String {
    let before: Vec<String> = room_ids(dir);
    let (ok, _, err) = vox(
        dir,
        &["room", "create", "--passphrase-file", "-", "--name", name],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT (staging): `vox room create {name}` failed: {err}"
    );
    room_ids(dir)
        .into_iter()
        .find(|id| !before.contains(id))
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): `vox room list` shows no new room after create")
        })
}

fn room_ids(dir: &Path) -> Vec<String> {
    let (_, listed, _) = vox(dir, &["room", "list"], None);
    listed
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
        .collect()
}

/// The harness session id alice's Session carries.
const SESSION: &str = "5d1e0c3a-7b2f-4e61-9c8d-deleted-key-proof";

/// Alice's harness opens its Session in `room`, as a person's Claude Code session opens it: `vox
/// agent hook` with the harness's own `UserPromptSubmit` payload. Nothing of the environment
/// running this proof that names a harness or a terminal reaches it (a hook given the operator's
/// tmux would bind its session to the operator's own pane), and its HOME is scratch.
fn open_session(dir: &Path, room: &str) {
    let mut cmd = Command::new(VOX);
    for (k, _) in std::env::vars_os() {
        let name = k.to_string_lossy();
        if ["TMUX", "CLAUDE", "CODEX", "OPENCODE", "VOX_"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            cmd.env_remove(&k);
        }
    }
    let home = dir.join("home");
    std::fs::create_dir_all(&home)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make a scratch HOME: {e}"));
    let mut child = cmd
        .args(["agent", "hook", "--node", "default", "--room", room])
        .env("HOME", home)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env("CLAUDE_CODE_ENTRYPOINT", "cli")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox agent hook: {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: the hook's stdin was not opened")
        .write_all(
            format!(
                r#"{{"session_id":"{SESSION}","hook_event_name":"UserPromptSubmit","cwd":"/tmp","transcript_path":"/tmp/t.jsonl","prompt":"go"}}"#
            )
            .as_bytes(),
        )
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write the hook's payload: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot collect vox agent hook: {e}"));
    assert!(
        out.status.success(),
        "APPARATUS (staging): alice's hook did not open her Session: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The row `dir`'s `vox room sessions --json` prints for alice's Session; `None` if it does not
/// list it.
fn session_row(dir: &Path, room: &str) -> Option<serde_json::Value> {
    let (ok, out, err) = vox(dir, &["room", "sessions", room, "--json"], None);
    assert!(ok, "PRODUCT: `vox room sessions --json` failed: {out}{err}");
    out.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|e| {
                panic!("PRODUCT: `vox room sessions --json` printed a malformed row: {line}; {e}")
            })
        })
        .find(|v| v["id"] == SESSION)
}

#[test]
#[ignore = "three real vox daemons and production Argon2id; CI runs it in release"]
fn a_member_deletes_another_members_key_once_it_has_read_everything_sealed_under_it() {
    watchdog::arm();
    let mut tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: tempdir: {e}"));
    if std::env::var_os("VOX_PROOF_KEEP_DIRS").is_some() {
        tmp.disable_cleanup(true);
        println!("[proof] daemon dirs kept under {}", tmp.path().display());
    }
    let tmp = tmp.path();
    let (alice, alice_fp) = identity(tmp, "alice");
    let (bob, bob_fp) = identity(tmp, "bob");
    let (carol, carol_fp) = identity(tmp, "carol");
    let _a = daemon(&alice, "alice");
    // Bob's node holds back one named room key while this file exists (`VOX_TEST_FWD_HOLD_KEY_FILE`,
    // apparatus): the same-receiver part below names alice's generation 0 in it.
    let hold = tmp.join("bob-holds-back");
    let mut b = daemon_with(&bob, "bob", &[("VOX_TEST_FWD_HOLD_KEY_FILE", &hold)]);
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
    let held = received_until(&bob, &room, 1, 60);
    println!("[proof] bob holds {held:?} generation(s) of received sender keys");
    assert_eq!(
        held,
        Some(1),
        "PRODUCT: bob read everything under alice's superseded generation and still holds its \
         key 60 s later (`vox status --json` received_key_generations)"
    );

    // Deleting it took nothing bob had read, and the live generation still opens.
    drop(b);
    b = daemon_with(
        &bob,
        "bob-restarted",
        &[("VOX_TEST_FWD_HOLD_KEY_FILE", &hold)],
    );
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
    let alice_held = generations(&alice, &room);
    trust(&alice, &carol_fp, "carol");
    post(&alice, &room, "again");
    let (ok, c) = read_until(&carol, &room, 90, |t| count(t, "again") == 1);
    println!("[proof] carol, trusted again, shows {c:?}");
    assert!(
        ok,
        "PRODUCT: carol, trusted again, never read alice's next post in 90 s: the re-offer after \
         R14's deletion did not get through: {c:?}"
    );
    let (alice_after, bob_after) = (generations(&alice, &room), received(&bob, &room));
    println!(
        "[proof] after the re-offer: alice holds {alice_after:?} generation(s) (was \
         {alice_held:?}), bob {bob_after:?} received"
    );
    assert!(
        alice_after.is_some() && alice_after <= alice_held && bob_after == Some(1),
        "PRODUCT: a re-offer brought a deleted key back: alice holds {alice_after:?} (was \
         {alice_held:?}), bob holds {bob_after:?} received (want 1)"
    );

    // ---- Same receiver: a deletion does not refuse an older generation still to come ------
    // (ruling-2 #7.) Bob is entitled to alice's generation 0 of a new room but has not taken it:
    // he does not trust alice while she writes under it, so it stays owed to him. When he
    // trusts her again his node holds generation 0 back (apparatus) and takes 1 and 2. He reads
    // generation 1 to its end, and generation 2 is proved, so he deletes 1. Then generation 0
    // comes, late, and he must read its posts: a deletion recorded as "everything up to 1"
    // rather than exactly 1 would refuse it as deleted.
    let (ok, t) = read_until(&bob, &room, 90, |t| count(t, "again") == 1);
    assert!(
        ok,
        "PRODUCT: bob never read alice's post \"again\" under her live generation in 90 s: {t:?}"
    );
    let (ok, _, err) = vox(&bob, &["trust", "remove", &alice_fp], None);
    assert!(
        ok,
        "PRODUCT (staging): bob's `vox trust remove alice` failed: {err}"
    );
    let s = create(&alice, "s");
    join(&alice, &bob, &s);
    join(&alice, &carol, &s);
    for i in 1..=2 {
        post(&alice, &s, &format!("zero {i}"));
    }
    let (ok, c) = read_until(&carol, &s, 90, |t| count(t, "zero ") == 2);
    assert!(
        ok,
        "PRODUCT (staging): carol never read alice's generation-0 posts in room s in 90 s: {c:?}"
    );
    // Removing carol rotates alice's key in room s: generation 1.
    let (ok, _, err) = vox(&alice, &["trust", "remove", &carol_fp], None);
    assert!(
        ok,
        "PRODUCT (staging): `vox trust remove carol` failed: {err}"
    );
    post(&alice, &s, "one 1");
    trust(&alice, &carol_fp, "carol");
    post(&alice, &s, "one 2");
    let (ok, c) = read_until(&carol, &s, 90, |t| count(t, "one 2") == 1);
    assert!(
        ok,
        "PRODUCT (staging): carol, trusted again, never read alice's \"one 2\" in 90 s: {c:?}"
    );
    // And again: generation 2.
    let (ok, _, err) = vox(&alice, &["trust", "remove", &carol_fp], None);
    assert!(
        ok,
        "PRODUCT (staging): `vox trust remove carol` failed: {err}"
    );
    post(&alice, &s, "two 1");
    let t = read(&bob, &s);
    assert!(
        count(&t, "zero ") + count(&t, "one ") + count(&t, "two ") == 0,
        "CANNOT MEASURE: bob, who does not trust alice, already reads her posts in room s, so \
         nothing is still owed to him: {t:?}"
    );
    std::fs::write(&hold, format!("{alice_fp} 0\n"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write bob's hold file: {e}"));
    trust(&bob, &alice_fp, "alice");
    let (ok, t) = read_until(&bob, &s, 90, |t| {
        count(t, "one ") == 2 && count(t, "two ") == 1
    });
    assert!(
        ok,
        "PRODUCT: bob, trusting alice again, never read her generation-1 and -2 posts in room s \
         in 90 s: {t:?}"
    );
    assert_eq!(
        count(&t, "zero "),
        0,
        "CANNOT MEASURE: bob read alice's generation-0 posts while his node held that key back, \
         so it did not arrive late: {t:?}"
    );
    let held = received_until(&bob, &s, 1, 60);
    println!("[proof] room s: bob read generations 1 and 2 and holds {held:?} of alice's keys");
    assert_eq!(
        held,
        Some(1),
        "PRODUCT: bob read alice's generation 1 in room s to its end, and generation 2 is \
         proved, yet he still holds more than one of her keys 60 s later"
    );

    // ---- A key-package re-offer of the deleted generation is ignored too ----------------
    // Bob's node goes down while alice still owes him generation 0: her next try to reach him
    // fails, and what she owes him goes into room s's log as key packages, one per generation
    // from his floor (0) to her live one (2), the deleted 1 among them. His node comes back
    // still holding a directly handed generation 0 back, so generation 0 can come only by
    // package; generation 1's package must change nothing.
    let packaged = || -> usize {
        let log = std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default();
        log.lines()
            .filter(|l| l.contains("went into the room's log as a key package"))
            .filter_map(|l| l.split("in room ").nth(1))
            .filter_map(|rest| rest.split_whitespace().next())
            .filter(|named| named.starts_with(s.as_str()) || s.starts_with(named))
            .count()
    };
    let packaged_before = packaged();
    drop(b);
    let deadline = Instant::now() + Duration::from_secs(120);
    while packaged() < packaged_before + 3 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
    }
    let packages = packaged() - packaged_before;
    println!(
        "[proof] room s: with bob down, alice's daemon put {packages} key(s) for him in the log"
    );
    assert!(
        packages >= 3,
        "CANNOT MEASURE: with bob's node down, alice's daemon said only {packages} key(s) of room \
         s went into the room's log in 120 s, not the three of generations 0, 1 and 2, so no \
         package re-offered the generation bob deleted"
    );
    b = daemon_with(
        &bob,
        "bob-packages",
        &[("VOX_TEST_FWD_HOLD_KEY_FILE", &hold)],
    );
    let (ok, t) = read_until(&bob, &s, 90, |t| count(t, "zero ") == 2);
    println!("[proof] room s: once generation 0 came by package, bob shows {t:?}");
    assert!(
        ok,
        "PRODUCT: bob never read post 0.x: alice's generation-0 posts in room s (\"zero 1\", \
         \"zero 2\") stayed unreadable 90 s after his node came back to her key packages; his \
         deletion of generation 1 refused generation 0: {t:?}"
    );
    assert!(
        count(&t, "one ") == 2 && count(&t, "two ") == 1,
        "PRODUCT: bob no longer shows every row he had read in room s: {t:?}"
    );
    std::fs::remove_file(&hold)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot remove bob's hold file: {e}"));
    let held = received_until(&bob, &s, 1, 60);
    // Alice's removals of carol rotated her key in room r too, with nothing posted under the new
    // generation, so bob's generation of "again" is not yet superseded by anything proved: a
    // post in r under her live generation proves it.
    post(&alice, &room, "after s");
    let (ok, t) = read_until(&bob, &room, 90, |t| count(t, "after s") == 1);
    assert!(
        ok,
        "PRODUCT: bob, trusting alice again, never read her next post in room r in 90 s: {t:?}"
    );
    let r_held = received_until(&bob, &room, 1, 60);
    let r = read(&bob, &room);
    println!(
        "[proof] room s: bob ends holding {held:?} of alice's keys; room r: {r_held:?}, shows {r:?}"
    );
    assert_eq!(
        held,
        Some(1),
        "PRODUCT: after alice's key packages re-offered the generation he deleted and brought \
         generation 0, bob holds {held:?} of her keys in room s 60 s after reading it all (want 1)"
    );
    assert!(
        count(&r, "first ") == 3
            && count(&r, "later ") == 3
            && count(&r, "latest") == 1
            && count(&r, "again") == 1
            && r_held == Some(1),
        "PRODUCT: after bob stopped and started trusting alice, room r no longer shows every row \
         he read, or holds other than 1 of her keys (holds {r_held:?}): {r:?}"
    );

    // ---- A Drive key is another namespace: it installs under a deleted room generation's number
    // Bob deleted alice's room-s generations 0 and 1. She now trusts him with drive and her
    // harness opens a Session in room s: her first drive key there is generation 0, and his node
    // must take it. A node lists `can_drive` true only for an author whose current drive key it
    // holds (ADR-029 CL-3).
    let (ok, _, err) = vox(&alice, &["trust", "drive", &bob_fp], None);
    assert!(ok, "PRODUCT (staging): `vox trust drive bob` failed: {err}");
    open_session(&alice, &s);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut row = session_row(&bob, &s);
    while row.as_ref().map(|v| v["can_drive"].as_bool()) != Some(Some(true))
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(500));
        row = session_row(&bob, &s);
    }
    println!("[proof] room s: bob lists alice's Session as {row:?}");
    assert!(
        session_row(&alice, &s).is_some(),
        "APPARATUS: alice's own `vox room sessions` does not list the Session her hook opened"
    );
    assert_eq!(
        row.as_ref().map(|v| v["can_drive"].as_bool()),
        Some(Some(true)),
        "PRODUCT: bob, trusted by alice with drive, does not list her Session in room s as one he \
         can drive 120 s after it opened: her drive key of generation 0 did not install where he \
         had deleted her room key of that number ({row:?})"
    );
    drop(b);
}
