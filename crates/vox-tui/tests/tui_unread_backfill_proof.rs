//! **Parked until PRD-001 R12's full-history grant existed** (a default grant releases the
//! sender key from approval onward, so a message posted before it never renders). Alice's
//! grant to bob now uses `--history full`, which makes the pre-approval row readable
//! deterministically — ADR-023 M23.4.
//!
//! PRD-001 R16 — **the TUI's unread badge counts a message that became readable when its
//! sender key arrived**, exactly once — read off the screen of the real `vox` TUI running
//! on a real terminal.
//!
//! ## The defect
//!
//! The badge is kept by `LiveCore` from the node's events. `NewEntry` counts this node's own
//! posts and `Synced.rendered` counts rows a sync rendered, but a row can also become
//! readable **later**: it arrives by sync while this node holds no key for its author, is
//! stored as ciphertext, and renders only when the author's consent delivers the sender key.
//! That path announces itself as `SenderKeyReceived { backfilled }`, and the TUI's arm for it
//! only set a notice. So a room whose messages all arrived before their key — the ordinary
//! case for anyone who joins and is consented to afterwards — showed **no** unread at all.
//!
//! ## What runs
//!
//! - alice: a real `vox daemon`;
//! - bob: the real `vox tui`, on a pseudo-terminal, unlocked by typing the passphrase at its
//!   prompt; what it draws is replayed into a screen grid and read the way a person reads it;
//! - rooms are made over bob's TUI's own control socket with the real CLI: bob's `home`, and
//!   alice's `mission`, which bob joins;
//! - alice posts in `mission` **before** she trusts bob, so the row reaches bob as ciphertext;
//!   then she trusts him, her node consents, and the key renders the row on bob's side.
//!
//! Bob has `home` open on screen throughout — a different room — so the row is off-screen
//! and must be counted. The badge must then read `(1 unread)`: not 0 (the defect) and not 2
//! (counting it on both the sync and the key), and still 1 after the room has settled.
//!
//! **Which event carries the row depends on arrival order**, and both must count once. The key
//! comes over the pairwise stream and the consent grant by sync; a row renders when both are
//! held. Between two reachable nodes the key usually lands first, finds no grant, and the row
//! renders when the grant's sync arrives — counted by `Synced.rendered` (the backfill on grant
//! arrival, `ChannelState::sync_over`). When the grant lands first, the key's backfill renders
//! it — counted by `SenderKeyReceived.backfilled` (`live.rs`). This proof runs the order the
//! product produces; the badge must read 1 either way.
//!
//! Mutations: `--history now` for alice's grant, or the backfill on grant arrival removed —
//! the row never renders and the badge stays at 0.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROWS: u16 = 30;
const COLS: u16 = 120;

/// One `vox` command, run to completion against a profile.
fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
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
        .expect("spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(text.as_bytes()).expect("write");
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn until(dir: &std::path::Path, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (_, out, err) = vox(dir, args, None);
        if ok(&out) {
            return out;
        }
        last = format!("stdout={out:?} stderr={err:?}");
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}; last saw {last}");
}

/// alice's daemon, killed by its own PID however the test ends, stderr drained.
struct Daemon(Child, Arc<Mutex<String>>);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// bob's TUI on a pseudo-terminal, with everything it draws replayed into a screen.
struct Tui {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    input: Box<dyn Write + Send>,
    screen: Arc<Mutex<vt100::Parser>>,
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Tui {
    fn spawn(dir: &std::path::Path) -> Self {
        use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem as _};
        let pair = NativePtySystem::default()
            .openpty(PtySize {
                rows: ROWS,
                cols: COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("open a pty");
        let mut cmd = CommandBuilder::new(VOX);
        cmd.args(["tui", "--listen", "127.0.0.1:0"]);
        cmd.env("VOX_DATA_DIR", dir);
        cmd.env("VOX_CONFIG_DIR", dir.join("cfg"));
        cmd.env("TERM", "xterm-256color");
        cmd.env_remove("VOX_ROOM");
        cmd.env_remove("VOX_IDENTITY_PASSPHRASE");
        let child = pair.slave.spawn_command(cmd).expect("spawn the TUI");
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().expect("pty reader");
        let input = pair.master.take_writer().expect("pty writer");
        let screen = Arc::new(Mutex::new(vt100::Parser::new(ROWS, COLS, 0)));
        let sink = Arc::clone(&screen);
        // The master is kept alive by the reader thread's clone; the pair's own handle is
        // leaked into it so the pty is not closed under the child.
        let master = pair.master;
        std::thread::spawn(move || {
            let _master = master;
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink.lock().unwrap().process(&buf[..n]),
                }
            }
        });
        Self {
            child,
            input,
            screen,
        }
    }

    fn text(&self) -> String {
        self.screen.lock().unwrap().screen().contents()
    }

    fn keys(&mut self, bytes: &[u8]) {
        self.input.write_all(bytes).expect("type into the TUI");
        self.input.flush().expect("flush");
    }

    /// Wait until the screen satisfies `ok`, so every step is observed rather than slept on.
    fn expect(&self, what: &str, secs: u64, ok: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            let t = self.text();
            if ok(&t) {
                return t;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the TUI never showed {what}; its screen:\n{}", self.text());
    }

    /// The channel-list line for `name`, as drawn.
    fn line_for(&self, name: &str) -> Option<String> {
        self.text()
            .lines()
            .find(|l| l.contains(&format!(" {name}")) && l.contains('['))
            .map(|l| l.trim().to_owned())
    }
}

#[test]
#[ignore = "a real TUI on a pty, a real daemon and production Argon2id; CI runs it in release"]
fn a_message_made_readable_by_its_key_counts_once_on_the_badge() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let alice_dir = tmp.path().join("alice");
    let bob_dir = tmp.path().join("bob");
    for d in [&alice_dir, &bob_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let mut fps = Vec::new();
    for dir in [&alice_dir, &bob_dir] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    let bob_fp = fps[1].clone();

    // ---- alice: a daemon ----
    let alice = {
        let mut child = Command::new(VOX)
            .args(["daemon", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &alice_dir)
            .env("VOX_CONFIG_DIR", alice_dir.join("cfg"))
            .env_remove("VOX_ROOM")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn alice's daemon");
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(format!("{IDPASS}\n").as_bytes()).unwrap();
        drop(pipe);
        let said = Arc::new(Mutex::new(String::new()));
        if let Some(mut err) = child.stderr.take() {
            let sink = Arc::clone(&said);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    match err.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => sink
                            .lock()
                            .unwrap()
                            .push_str(&String::from_utf8_lossy(&buf[..n])),
                    }
                }
            });
        }
        Daemon(child, said)
    };

    // ---- bob: the TUI, unlocked at its own prompt ----
    let mut tui = Tui::spawn(&bob_dir);
    tui.expect("the unlock prompt", 60, |t| {
        t.to_lowercase().contains("passphrase")
    });
    tui.keys(format!("{IDPASS}\r").as_bytes());
    tui.expect("that it unlocked", 90, |t| t.contains("unlocked"));

    // ---- rooms, made over the TUI's own control socket ----
    // alice's daemon answers only once it has unlocked and bound its socket. The wait must see
    // `room list` *succeed*: an `until` that accepts any output returned on the first try, and
    // under load the `room create` below then met "no node is running".
    {
        let started = Instant::now();
        loop {
            let (ok, _, err) = vox(&alice_dir, &["room", "list"], None);
            if ok {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(90),
                "alice's daemon never answered: {err}"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        eprintln!(
            "[receipt] alice's daemon answered after {} ms",
            started.elapsed().as_millis()
        );
    }
    let (ok, _, err) = vox(
        &alice_dir,
        &["room", "create", "--name", "mission"],
        Some("mission passphrase\n"),
    );
    assert!(ok, "alice creates mission: {err}");
    let listed = until(&alice_dir, "mission to appear", &["room", "list"], |o| {
        o.contains("mission")
    });
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("a room id")
        .to_owned();
    let (ok, link, err) = vox(&alice_dir, &["room", "invite", &room], None);
    assert!(ok, "invite: {err}");

    let (ok, _, err) = vox(
        &bob_dir,
        &["room", "create", "--name", "home"],
        Some("home passphrase\n"),
    );
    assert!(ok, "bob creates home over the TUI's socket: {err}");
    let (ok, _, err) = vox(
        &bob_dir,
        &["room", "join", link.trim(), "--name", "mission"],
        Some("mission passphrase\n"),
    );
    assert!(
        ok,
        "CANNOT MEASURE: bob's TUI could not join alice's room — {err}\nalice's daemon:\n{}",
        alice.1.lock().unwrap()
    );
    tui.expect("both rooms in the list", 30, |t| {
        t.contains(" home") && t.contains(" mission")
    });

    // ---- bob opens `home`: a different room is on screen from here on ----
    for _ in 0..4 {
        if tui.text().lines().any(|l| l.contains("▶ home")) {
            break;
        }
        tui.keys(b"\x1b[B"); // Down
        std::thread::sleep(Duration::from_millis(300));
    }
    tui.expect("home selected", 10, |t| t.contains("▶ home"));
    tui.keys(b"\r");
    // The list's title is gone once a room is on screen.
    tui.expect("home on screen", 10, |t| !t.contains("Channels (Enter"));

    // Bob trusts alice: his own decision about who reads HIM, which renders nothing of
    // hers. Measured by hand, a consent that only one side has given did not deliver the
    // key; with both, it crossed in about two seconds.
    let alice_fp = fps[0].clone();
    let (ok, _, err) = vox(
        &bob_dir,
        &["trust", "add", &alice_fp, "--name", "alice"],
        None,
    );
    assert!(ok, "bob trusts alice: {err}");

    // ---- alice posts BEFORE she trusts bob, so the row reaches him as ciphertext ----
    let (ok, _, err) = vox(
        &alice_dir,
        &["room", "post", &room, "the plan, before bob can read it"],
        None,
    );
    assert!(ok, "alice posts: {err}");
    // Bob cannot read it yet — no key for alice — and must not be able to: that is what
    // makes the key the thing that renders it. The wait lets the entry reach bob's log.
    std::thread::sleep(Duration::from_secs(8));
    let (_, early, _) = vox(&bob_dir, &["room", "read", &room], None);
    assert!(
        !early.contains("before bob can read it"),
        "bob read alice's post before she consented to him; this proof needs the key path: \
         {early:?}"
    );

    // ---- alice trusts bob; her node consents; the key renders the row on bob's side ----
    let (ok, _, err) = vox(
        &alice_dir,
        &[
            "trust",
            "add",
            &bob_fp,
            "--name",
            "bob",
            "--history",
            "full",
        ],
        None,
    );
    assert!(ok, "alice trusts bob with full history: {err}");
    until(
        &bob_dir,
        "alice's post to become readable on bob's node",
        &["room", "read", &room],
        |o| o.contains("before bob can read it"),
    );
    // Let anything else the consent sets moving land before the badge is read.
    std::thread::sleep(Duration::from_secs(3));

    // ---- back to the list, where the badge is drawn ----
    tui.keys(b"\x1b");
    tui.expect("the channel list", 10, |t| {
        t.contains("Channels (Enter") && t.contains("▶ home")
    });
    let mission = tui.line_for("mission").expect("mission's line");
    let home = tui.line_for("home").expect("home's line");
    eprintln!("badge: {mission:?} / {home:?}");
    assert!(
        mission.contains("(1 unread)"),
        "one message became readable in mission while home was on screen, so its badge must \
         read (1 unread) — not 0 and not 2. It reads: {mission:?}\nscreen:\n{}",
        tui.text()
    );
    assert!(
        !home.contains("unread"),
        "home, the room that was on screen, has nothing unread: {home:?}"
    );

    // ---- and it stays 1 once the room has settled ----
    std::thread::sleep(Duration::from_secs(5));
    let settled = tui.line_for("mission").expect("mission's line");
    assert!(
        settled.contains("(1 unread)"),
        "the badge moved after the room settled; each row counts once: {settled:?}"
    );
    eprintln!("badge after settling: {settled:?}");

    drop(tui);
    drop(alice);
}
