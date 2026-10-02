//! PRD-001 R10 — "an expired message leaves nothing visible" — on **every** reading surface,
//! driven through the **shipped `vox` binary**.
//!
//! `retention_proof` shows an expired message gone from `vox room read`. A person or an agent
//! also reads a room through `vox room read --json`, `vox room tail` (replayed from the start),
//! the drain hook a harness runs (`vox agent hook`), and the work board (`vox room board`). This
//! proves each of them on both members. The TUI is proved by `the_tui_shows_no_expired_message_proof`.
//!
//! What runs: alice and bob share a room whose retention is 20 s. Alice posts three messages and
//! claims a work item; bob reads them. Once `vox room read` shows them gone on both members
//! (PRODUCT if it never does), alice posts once more. Then, on each member:
//!
//! - `room read --json`: no row of the expired three, nor the claim;
//! - `room tail --json --since <the room's first entry>`: the later post arrives, and nothing of
//!   the expired ones;
//! - `agent hook` for a fresh session (which is owed the whole backlog): nothing expired;
//! - `room board --json`: the expired claim's item is not on the board.
//!
//! Every red names its side: PRODUCT quotes what `vox` printed; APPARATUS is this proof's own
//! process handling.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// The room's retention, seconds.
const RETENTION: u64 = 20;

/// A `vox` process, killed by its own PID when dropped.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(dir: &Path, args: &[&str], session: Option<&str>) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION");
    if let Some(s) = session {
        cmd.env("VOX_SESSION", s);
    }
    cmd
}

/// One `vox` run: `(succeeded, stdout, stderr)`, bounded at 120 s.
fn vox_as(
    dir: &Path,
    args: &[&str],
    stdin: Option<&str>,
    session: Option<&str>,
) -> (bool, String, String) {
    let mut child = command(dir, args, session)
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

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    vox_as(dir, args, stdin, None)
}

/// `args` must succeed; its stdout.
fn ok(dir: &Path, args: &[&str]) -> String {
    let (ok, out, err) = vox(dir, args, None);
    assert!(ok, "PRODUCT: `vox {}` failed: {err}", args.join(" "));
    out
}

fn daemon(dir: &Path, tag: &str) -> Proc {
    let log = |ext: &str| {
        std::fs::File::create(dir.join(format!("daemon-{tag}.{ext}")))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot create {tag}'s daemon log: {e}"))
    };
    let mut child = command(dir, &["daemon", "--listen", "127.0.0.1:0"], None)
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
    let d = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !vox(dir, &["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT: {tag}'s daemon never answered `vox room list` in 90 s: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    d
}

/// The texts `vox room read` returns (`<entry-hash> <author-prefix> <text>`).
fn read(dir: &Path, room: &str) -> Vec<String> {
    ok(dir, &["room", "read", room])
        .lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

fn count(texts: &[String], prefix: &str) -> usize {
    texts.iter().filter(|t| t.starts_with(prefix)).count()
}

/// Poll `vox room read` until `done`; PRODUCT naming `what` if it never is.
fn until(dir: &Path, room: &str, what: &str, secs: u64, done: impl Fn(&[String]) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let last = read(dir, room);
        if done(&last) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: {what} within {secs} s; `vox room read` shows {last:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Every line of `out` that carries any of the expired texts.
fn leaks<'a>(out: &'a str, expired: &[&str]) -> Vec<&'a str> {
    out.lines()
        .filter(|l| expired.iter().any(|x| l.contains(x)))
        .collect()
}

/// `vox room tail --json --since <since>` for up to `secs`, until a line names `want`.
fn tail(dir: &Path, room: &str, since: &str, want: &str, secs: u64) -> String {
    let mut child = command(
        dir,
        &["room", "tail", room, "--since", since, "--json"],
        None,
    )
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox room tail: {e}"));
    let mut stdout = child
        .stdout
        .take()
        .expect("APPARATUS: tail's stdout was not opened");
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let child = Proc(child);
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut got = Vec::new();
    while Instant::now() < deadline && !String::from_utf8_lossy(&got).contains(want) {
        if let Ok(bytes) = rx.recv_timeout(Duration::from_millis(200)) {
            got.extend(bytes);
        }
    }
    // A short settle, so a row that follows the wanted one is seen too.
    let settle = Instant::now() + Duration::from_secs(1);
    while let Some(left) = settle.checked_duration_since(Instant::now()) {
        if let Ok(bytes) = rx.recv_timeout(left) {
            got.extend(bytes);
        }
    }
    drop(child);
    String::from_utf8_lossy(&got).into_owned()
}

#[test]
#[ignore = "two real vox daemons and real seconds of retention; CI runs it in release"]
fn an_expired_message_shows_on_no_reading_surface_of_any_member() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: tempdir: {e}"));
    let (alice, bob): (PathBuf, PathBuf) = (tmp.path().join("alice"), tmp.path().join("bob"));
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        std::fs::create_dir_all(dir.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make a profile dir: {e}"));
        fps.push(ok(dir, &["id"]).trim().to_owned());
    }
    ok(&alice, &["trust", "add", &fps[1], "--name", "bob"]);
    ok(&bob, &["trust", "add", &fps[0], "--name", "alice"]);
    let _a = daemon(&alice, "alice");
    let _b = daemon(&bob, "bob");

    let (made, _, err) = vox(
        &alice,
        &["room", "create", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(made, "PRODUCT: `vox room create` failed: {err}");
    let room = ok(&alice, &["room", "list"])
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT: `vox room list` shows no room after create"))
        .to_owned();
    let link = ok(&alice, &["room", "invite", &room]);
    let (joined, _, err) = vox(
        &bob,
        &["room", "join", link.trim(), "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(joined, "PRODUCT: bob's `vox room join` failed: {err}");
    ok(
        &alice,
        &["room", "retention", &room, &RETENTION.to_string()],
    );

    // ---- what will expire: three messages and a claim ---------------------------------------
    for i in 1..=3 {
        ok(&alice, &["room", "post", &room, &format!("soon gone {i}")]);
    }
    let (claimed, out, err) = vox_as(
        &alice,
        &["room", "claim", &room, "expiring-item"],
        None,
        Some("a1"),
    );
    assert!(
        claimed,
        "PRODUCT: alice's `vox room claim` failed: {out}{err}"
    );
    until(
        &bob,
        &room,
        "bob never read alice's three messages",
        90,
        |t| count(t, "soon gone ") == 3,
    );
    let board = ok(&bob, &["room", "board", &room, "--json"]);
    assert!(
        board.contains("expiring-item"),
        "PRODUCT: bob's board never showed alice's claim before it expired: {board}"
    );

    // ---- they expire, as `room read` already shows ------------------------------------------
    for (dir, who) in [(&alice, "alice"), (&bob, "bob")] {
        until(
            dir,
            &room,
            &format!("{who}'s `vox room read` still shows the expired messages"),
            RETENTION * 3,
            |t| count(t, "soon gone ") == 0,
        );
    }
    ok(&alice, &["room", "post", &room, "still here"]);
    until(&bob, &room, "bob never read alice's later post", 90, |t| {
        count(t, "still here") == 1
    });

    let expired = ["soon gone ", "expiring-item"];
    for (dir, who) in [(&alice, "alice"), (&bob, "bob")] {
        // `room read --json`.
        let json = ok(dir, &["room", "read", &room, "--json"]);
        assert!(
            json.contains("still here"),
            "PRODUCT: {who}'s `room read --json` lacks the later post: {json}"
        );
        let l = leaks(&json, &expired);
        assert!(
            l.is_empty(),
            "PRODUCT: {who}'s `room read --json` shows expired content: {l:?}"
        );

        // `room tail`, replayed from the room's first entry.
        let hashes = ok(dir, &["room", "read", &room, "--hashes"]);
        let first = hashes
            .split_whitespace()
            .next()
            .unwrap_or_else(|| panic!("PRODUCT: {who}'s `room read --hashes` lists nothing"))
            .to_owned();
        let tailed = tail(dir, &room, &first, "still here", 30);
        assert!(
            tailed.contains("still here"),
            "PRODUCT: {who}'s `room tail --since <first entry>` never printed the later post in \
             30 s: {tailed}"
        );
        let l = leaks(&tailed, &expired);
        assert!(
            l.is_empty(),
            "PRODUCT: {who}'s `room tail` replays expired content: {l:?}"
        );

        // The drain hook, for a session that has never drained here: owed the whole backlog.
        let (drained, out, err) = vox(
            dir,
            &[
                "agent",
                "hook",
                "--room",
                &room,
                "--format",
                "text",
                "--session",
                &format!("fresh-{who}"),
            ],
            Some(""),
        );
        assert!(drained, "PRODUCT: {who}'s `vox agent hook` failed: {err}");
        assert!(
            out.contains("still here"),
            "PRODUCT: {who}'s drain hook, for a fresh session, lacks the later post: {out:?}"
        );
        let l = leaks(&out, &expired);
        assert!(
            l.is_empty(),
            "PRODUCT: {who}'s drain hook injects expired content: {l:?}"
        );

        // The work board.
        let board = ok(dir, &["room", "board", &room, "--json"]);
        assert!(
            !board.contains("expiring-item"),
            "PRODUCT: {who}'s `room board --json` still shows the claim whose message expired: \
             {board}"
        );
        println!(
            "[proof] {who}: read --json, tail from the start, a fresh drain and the board show \
             nothing expired"
        );
    }
}
