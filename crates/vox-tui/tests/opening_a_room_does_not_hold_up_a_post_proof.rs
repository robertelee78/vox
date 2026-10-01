//! V210-71 (#262), finding 3 — **a post answers while the same node opens another room with its
//! passphrase**, through the shipped binary. An opt-in proof (`--features heavy-proofs`): it
//! drives the terminal UI and seeds a room with hundreds of posts, so it is not part of every CI
//! run or release gate.
//!
//! Opening a closed room unwraps its key (production Argon2id) and re-verifies every entry of its
//! log. Both ran on the node's actor, the one task every command waits on (ADR-016), so while a
//! person opened a room, every other room of that node (its posts, reads and syncs) waited
//! for it. Now the unwrap and the open run off the actor, and the room is held when they finish
//! (`begin_open_channel` → `NetEvent::ChannelUnsealed`).
//!
//! **Why the TUI.** A daemon opens rooms only from its startup lines, before it serves anything,
//! so nothing else is waiting on it then. The terminal UI is where a person opens a room while
//! the node is busy with others: it runs its own node, and serves the same control socket a
//! daemon does, so an agent session's `vox room post` attaches to it.
//!
//! **Staging**, all through the shipped `vox`:
//! 1. alice's daemon creates room B (`bravo`) and posts [`SEED`] posts to it, so its open has a
//!    log to re-verify, then stops;
//! 2. `vox tui` closes B on purpose (`tests/pty/tui_close_room.py`: the profile's only room);
//! 3. alice's daemon starts again (B stays closed: a room closed on purpose is not reopened) and
//!    creates room A (`alpha`), then stops;
//! 4. `vox tui` (`tests/pty/tui_open_room_while_posting.py`) unlocks, which reopens A by itself.
//!    While `vox room post A` runs every 150 ms through the TUI's socket, the person selects B
//!    and types its passphrase. The driver times every post, and times the open from the
//!    passphrase's Enter to the first `vox room read B` that succeeds.
//!
//! **Asserted:** every post that started while the open ran, from its start to the room being
//! open, answered within [`BOUND`], V210-08's bound for a post on loopback. Preconditions, or
//! `CANNOT MEASURE`: the open took at least [`MIN_OPEN`] (else there was nothing to wait for), at
//! least [`MIN_DURING`] posts started during it, and every post succeeded.
//!
//! **Mutation that must turn it red:** the open back on the actor, where `ChannelState::open`
//! (unwrap and re-verify) is awaited inline, as before 7507d3a. A post made during the open then
//! waits for all of it.
//!
//! **Measured** (release, `timing-lock.sh run-slot.sh`, this machine under its normal load, 3000
//! seeded entries):
//! - candidate, 3 of 3 green: opens of 1.30 s, 3.19 s and 2.73 s, with 9, 21 and 18 posts started
//!   during them; slowest 50.5 ms, 74.2 ms and 39.1 ms;
//! - mutant (the open on the actor), 2 of 2 red: opens of 1.22 s and 1.89 s, with a post made at
//!   the start taking 1091 ms and 1675 ms.

#![cfg(target_os = "macos")]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

use std::io::Write;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// V210-08's bound for a post on loopback: every post made during the open must answer in this.
const BOUND: Duration = Duration::from_millis(500);
/// Posts seeded into the room that is opened, so its open re-verifies a log.
const SEED: usize = 3000;
/// An open shorter than this could not hold a post past [`BOUND`] even on the actor, so it would
/// measure nothing: the open must take at least the bound itself.
const MIN_OPEN: Duration = BOUND;
/// Posts that must start during the open for it to have been measured at all.
const MIN_DURING: usize = 2;

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` with the identity passphrase on stdin, output to files by the profile.
fn daemon(dir: &Path, tag: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn vox daemon");
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes()).unwrap();
    drop(pipe);
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !vox(dir, &["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: {tag}'s daemon never answered: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    d
}

/// Create a room named `name` on the running daemon; its id prefix as `room list` prints it.
fn create(dir: &Path, name: &str) -> String {
    let (ok, _, err) = vox(
        dir,
        &["room", "create", "--name", name],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "CANNOT MEASURE: vox room create {name}: {err}");
    let (_, list, _) = vox(dir, &["room", "list"], None);
    list.lines()
        .find(|l| l.split_whitespace().any(|w| w == name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("CANNOT MEASURE: {name} not in room list: {list}"))
        .to_owned()
}

/// Run a pty driver; its stdout, after checking it gave a verdict and exited 0.
fn drive(script: &str, args: &[&str], tag: &str) -> String {
    let out = pty_driver::run(script, args);
    let said = out.stdout.clone();
    println!(
        "[proof] {tag}: the TUI driver took {:?}; last stage {:?}",
        out.took, out.stage
    );
    assert!(
        out.has_verdict(tag) && out.code == Some(0),
        "CANNOT MEASURE: the {tag} TUI driver gave no verdict, or failed (exit {:?}, stage {:?}): \
         {said}",
        out.code,
        out.stage
    );
    said
}

#[test]
#[ignore = "opt-in (heavy-proofs): drives the TUI and seeds a room; run in release"]
fn a_post_answers_while_the_node_opens_another_room() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    std::fs::create_dir_all(alice.join("cfg")).unwrap();
    let (ok, _, err) = vox(&alice, &["id"], None);
    assert!(ok, "CANNOT MEASURE: vox id: {err}");
    let cfg = alice.join("cfg").to_string_lossy().into_owned();
    let data = alice.to_string_lossy().into_owned();

    // ---- 1. room B, with a log to re-verify ---------------------------------------------------
    let first = daemon(&alice, "alice-1");
    let bravo = create(&alice, "bravo");
    let t = Instant::now();
    for i in 1..=SEED {
        let (ok, _, err) = vox(
            &alice,
            &["room", "post", &bravo, &format!("seed {i}")],
            None,
        );
        assert!(ok, "CANNOT MEASURE: seed post {i}: {err}");
    }
    println!(
        "[proof] {SEED} posts seeded into bravo in {:?}",
        t.elapsed()
    );
    drop(first);

    // ---- 2. B closed on purpose, in the TUI -------------------------------------------------
    let close = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_close_room.py");
    let said = drive(
        close,
        &[VOX, &data, &cfg, IDENTITY, ROOMPASS, "close"],
        "close",
    );
    assert!(
        said.contains("close the TUI said done to :close"),
        "CANNOT MEASURE: the TUI did not close bravo: {said}"
    );

    // ---- 3. room A, while B stays closed ---------------------------------------------------
    let second = daemon(&alice, "alice-2");
    let alpha = create(&alice, "alpha");
    let (_, list, _) = vox(&alice, &["room", "list"], None);
    let bravo_line = list.lines().find(|l| l.contains(&bravo)).unwrap_or("");
    assert!(
        bravo_line.contains("[closed]"),
        "CANNOT MEASURE: bravo is not closed before the TUI opens it: {list}"
    );
    drop(second);

    // ---- 4. open B in the TUI while posting to A through its socket -------------------------
    let open = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/pty/tui_open_room_while_posting.py"
    );
    let said = drive(
        open,
        &[VOX, &data, &cfg, IDENTITY, ROOMPASS, &alpha, &bravo, "open"],
        "open",
    );
    let (mut posts, mut window) = (Vec::new(), None);
    for l in said.lines() {
        let w: Vec<&str> = l.split_whitespace().collect();
        match w.as_slice() {
            ["open", "POST", start, ms, ok] => posts.push((
                start.parse::<f64>().unwrap(),
                ms.parse::<f64>().unwrap(),
                *ok == "1",
            )),
            ["open", "OPEN", start, end] => {
                window = Some((start.parse::<f64>().unwrap(), end.parse::<f64>().unwrap()));
            }
            _ => {}
        }
    }
    let (from, to) = window.unwrap_or_else(|| panic!("CANNOT MEASURE: no open window: {said}"));
    let took = Duration::from_secs_f64(to - from);
    let during: Vec<(f64, f64)> = posts
        .iter()
        .filter(|(start, _, _)| *start >= from && *start < to)
        .map(|(start, ms, _)| (start - from, *ms))
        .collect();
    let slowest = during.iter().map(|(_, ms)| *ms).fold(0.0_f64, f64::max);
    let all_slowest = posts.iter().map(|(_, ms, _)| *ms).fold(0.0_f64, f64::max);
    println!(
        "[proof] the open of bravo ({SEED} entries) took {took:?}; {} post(s) to alpha started \
         during it, slowest {slowest:.1} ms (bound {BOUND:?}); {} post(s) in all, slowest \
         {all_slowest:.1} ms; during: {during:?}",
        during.len(),
        posts.len()
    );
    assert!(
        posts.iter().all(|(_, _, ok)| *ok),
        "CANNOT MEASURE: a post to alpha failed: {said}"
    );
    assert!(
        took >= MIN_OPEN,
        "CANNOT MEASURE: the open took only {took:?}, under {MIN_OPEN:?}: nothing to wait on"
    );
    assert!(
        during.len() >= MIN_DURING,
        "CANNOT MEASURE: only {} post(s) started during the open",
        during.len()
    );
    assert!(
        slowest < BOUND.as_secs_f64() * 1000.0,
        "a post to alpha took {slowest:.1} ms (bound {BOUND:?}) while the same node opened bravo \
         with its passphrase: the open held the node"
    );
}
