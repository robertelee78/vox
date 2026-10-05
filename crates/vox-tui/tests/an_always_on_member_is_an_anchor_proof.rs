//! PRD-001 R33, ADR-023 decision 6 — **any always-on member can be the anchor**: an ordinary
//! member's `vox daemon` is the rendezvous and the relay for the other members of its room, with
//! no `vox node` anywhere, through the shipped binary.
//!
//! **The scene.** C, B and A, each a real `vox daemon` made with `vox id`.
//! - **C** is the always-on member: it listens on both families (`[::]`), makes the room and
//!   invites the others. It names no anchor. The others name it by the fingerprint its
//!   `vox daemon: identity` line gives and the address it listens on.
//! - **A** listens on IPv6 loopback only and **B** on IPv4 loopback only, so neither can dial the
//!   other: only a relay can join them. Each names C as its `--anchor`, at the address of its own
//!   family, joins through C's invitation, and trusts the other.
//!
//! **What is asserted.**
//! - B reaches A **relayed through C**: B's `vox status --json` lists A on a `relayed` path whose
//!   relay is C, and C's lists at least one circuit it carries. Not within [`RELAY_WITHIN`] is
//!   `PRODUCT:`.
//! - What A posts, B reads.
//! - A `vox` step that fails while the scene is set (a verb, a daemon that never serves its
//!   socket or says its identity, C listing no room or no invitation) is the product failing:
//!   `PRODUCT (staging):`. This test's own spawns, pipes and files are `APPARATUS:`.
//!
//! **Why a file of its own.** Every other proof with an anchor uses `vox node`; none points
//! `--anchor` at a member.
//!
//! **Mutation.** A member relaying only for a configured anchor, not between the members of a room
//! it holds (`relays_between` without its shared-room rule): C carries no circuit, B never reaches
//! A relayed, and the proof goes red.

#![cfg(unix)]

#[path = "support/ports.rs"]
mod ports;
#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, VoxProc, IDENTITY, VOX};

const ROOMPASS: &str = "the room passphrase";
/// How long B may take to reach A through C once both have joined: a ladder that finds no direct
/// path falls to the relay rung within seconds; the rest is the tick that retries a member.
const RELAY_WITHIN: Duration = Duration::from_secs(120);
/// How long a post may take to reach the other member.
const READ_WITHIN: Duration = Duration::from_secs(90);

/// A one-shot `vox` verb in `dir`'s profile with `stdin`; `(ok, stdout, stderr)`.
fn vox(dir: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: run vox {argv:?}: {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: a piped stdin")
        .write_all(stdin.as_bytes())
        .expect("APPARATUS: write stdin");
    let out = child.wait_with_output().expect("APPARATUS: vox ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A staging verb that must succeed. It is the product doing what a person asks, so a failure
/// is `PRODUCT (staging)`, not a fault of this test.
fn staged(dir: &Path, argv: &[&str], stdin: &str) -> String {
    let (ok, out, err) = vox(dir, argv, stdin);
    assert!(
        ok,
        "PRODUCT (staging): vox {argv:?} in {}: {err}",
        dir.display()
    );
    out
}

/// `dir`'s `vox status --json`.
fn status(dir: &Path) -> serde_json::Value {
    let (ok, out, err) = vox(dir, &["status", "--json"], "");
    assert!(ok, "PRODUCT (staging): vox status --json: {err}");
    serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("APPARATUS: vox status --json is not JSON ({e}): {out}"))
}

/// A member's daemon, listening at `listen`, naming `anchor` if any; `None` if it exits or never
/// says its control socket.
fn try_daemon(name: &str, dir: &Path, listen: &str, anchor: Option<&str>) -> Option<VoxProc> {
    let pass = dir.join("pass");
    std::fs::write(&pass, format!("{IDENTITY}\n{ROOMPASS}\n"))
        .expect("APPARATUS: write the passphrase file");
    let pass = world::utf8(&pass);
    let mut argv = vec!["daemon", "--listen", listen, "--passphrase-file", &pass];
    if let Some(spec) = anchor {
        argv.extend(["--anchor", spec]);
    }
    let mut d = VoxProc::spawn(name, dir, &args(&argv));
    d.line_within(world::LINE_TIMEOUT, |l| l.contains("control socket"))?;
    Some(d)
}

/// [`try_daemon`], where not starting is a staging failure.
fn daemon(name: &str, dir: &Path, listen: &str, anchor: Option<&str>) -> VoxProc {
    try_daemon(name, dir, listen, anchor).unwrap_or_else(|| {
        panic!("PRODUCT (staging): {name}'s daemon never said its control socket")
    })
}

fn member(root: &Path, name: &str) -> (std::path::PathBuf, String) {
    let dir = root.join(name);
    world::mkdir(&dir.join("cfg"));
    let fp = staged(&dir, &["id"], "")
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    (dir, fp)
}

#[test]
#[ignore = "three real vox daemons, one relaying, with production Argon2id; CI runs it in release"]
fn an_always_on_member_is_the_rendezvous_and_relay_for_the_others() {
    watchdog::arm();
    let tmp = world::tempdir();
    let (c_dir, c_fp) = member(tmp.path(), "c");
    let (a_dir, a_fp) = member(tmp.path(), "a");
    let (b_dir, b_fp) = member(tmp.path(), "b");

    // ---- C, the always-on member, on both families ----
    // On a port of its own choosing, read back from its own report (#410): a port the proof
    // picked and released could be another program's by the time C bound it.
    let mut c = daemon("c", &c_dir, "[::]:0", None);
    let port = ports::loopback_listen(&staged(&c_dir, &["status", "--json"], ""))
        .unwrap_or_else(|| panic!("PRODUCT (staging): C's report names no loopback address"))
        .port();
    let id = c
        .line_within(world::LINE_TIMEOUT, |l| {
            l.starts_with("vox daemon: identity ")
        })
        .unwrap_or_else(|| panic!("PRODUCT (staging): C's daemon never said its identity"));
    assert_eq!(
        id.split_whitespace().last(),
        Some(c_fp.as_str()),
        "PRODUCT (staging): C's daemon is not the identity `vox id` made"
    );
    let c_for_a = format!("{c_fp}@/ip6/::1/udp/{port}");
    let c_for_b = format!("{c_fp}@/ip4/127.0.0.1/udp/{port}");
    println!("[proof] A names C as {c_for_a}; B names C as {c_for_b}");

    staged(
        &c_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    let room = staged(&c_dir, &["room", "list"], "")
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT (staging): C lists no room"))
        .to_owned();
    let link = staged(&c_dir, &["room", "link", &room], "")
        .lines()
        .find(|l| l.starts_with("vox://"))
        .unwrap_or_else(|| panic!("PRODUCT (staging): no invitation for room {room}"))
        .trim()
        .to_owned();

    // ---- A on IPv6 only, B on IPv4 only: only a relay joins them; each names C ----
    let _a = daemon("a", &a_dir, "[::1]:0", Some(&c_for_a));
    let _b = daemon("b", &b_dir, "127.0.0.1:0", Some(&c_for_b));
    for d in [&a_dir, &b_dir] {
        staged(
            d,
            &[
                "room",
                "join",
                "--passphrase-file",
                "-",
                &link,
                "--name",
                "r",
            ],
            &format!("{ROOMPASS}\n"),
        );
    }
    staged(&a_dir, &["trust", "add", &b_fp, "--name", "b"], "");
    staged(&b_dir, &["trust", "add", &a_fp, "--name", "a"], "");

    // ---- B reaches A relayed through C ----
    let deadline = Instant::now() + RELAY_WITHIN;
    let (mut b_to_a, mut carried) = (serde_json::Value::Null, 0u64);
    while Instant::now() < deadline {
        let b = status(&b_dir);
        b_to_a = b["peers"]
            .as_array()
            .and_then(|p| p.iter().find(|p| p["id"] == a_fp.as_str()).cloned())
            .unwrap_or(serde_json::Value::Null);
        carried = status(&c_dir)["relaying"].as_u64().unwrap_or(0);
        if b_to_a["path"] == "relayed" && b_to_a["relay"] == c_fp.as_str() && carried > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("[proof] B's path to A: {b_to_a}; circuits C carries: {carried}");
    assert!(
        b_to_a["path"] == "relayed" && b_to_a["relay"] == c_fp.as_str() && carried > 0,
        "PRODUCT: an always-on member must relay between the other members of its room: within \
         {RELAY_WITHIN:?} B's path to A is {b_to_a} (want relayed through C, {c_fp}) and C \
         carries {carried} circuit(s)\nC:\n{}",
        c.transcript()
    );

    // ---- and what A posts, B reads ----
    staged(&a_dir, &["room", "post", &room, "r33-through-a-member"], "");
    let deadline = Instant::now() + READ_WITHIN;
    let mut read = false;
    while Instant::now() < deadline && !read {
        read = vox(&b_dir, &["room", "read", &room], "")
            .1
            .contains("r33-through-a-member");
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("[proof] B read A's post: {read}");
    assert!(
        read,
        "PRODUCT: B must read what A posts, with C, a member, the only anchor"
    );
}
