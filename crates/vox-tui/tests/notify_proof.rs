//! PRD-001 R37 — a running daemon notifies its operator when `vox status` would flag
//! something, **once** when it starts and **once** when it clears.
//!
//! Every participant is the shipped binary, driven as a person would (ADR-018, "Only real use
//! of the product is a test"): an anchor (`vox node`), and alice and bob, each a `vox daemon`
//! made with `vox id`, trusting each other with `vox trust add`, sharing one room made with
//! `vox room create`, `vox room link` and `vox room join`. What the proof reads is what a
//! person can read: `vox status --json`, and what the daemon prints.
//!
//! alice's node is set (`notify-command` in its own `config/config`, ADR-026 F-2) to hand
//! each notification to a script that appends it to a file, so what is counted is the
//! shipped binary's own decision to notify. Kill bob: exactly one "unreachable"
//! notification. Leave him dead for three
//! minutes: still exactly one. Start him again: exactly one "recovered".
//!
//! The anchor's proof stages the other condition R37 names, an anchor that cannot be reached,
//! and the rule ADR-012 sets for it: an anchor only bridges hosts that cannot otherwise find each
//! other, so one this node does not need alarms no one.
//!
//! **A red names its side:** `PRODUCT:` quotes what the daemon notified or `vox status` said; a
//! `vox` step the scene needs that fails is `PRODUCT (staging):`; the test's own files and
//! sockets are `APPARATUS:`; a scene that could not be staged as described is `CANNOT MEASURE:`.

#![cfg(unix)]

#[path = "support/ports.rs"]
mod ports;
#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use vox_core::node::paths::Paths;
use world::{args, vox_once, VoxProc, IDENTITY, VOX};

const TIMEOUT: Duration = Duration::from_secs(60);
const ROOM_PASS: &str = "room passphrase";
/// Generous: production Argon2id and a real proof of work happen inside a join.
const SETUP: Duration = Duration::from_secs(180);

/// A one-shot `vox` verb with `stdin` piped in, in `data`'s profile.
fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: run vox");
    child
        .stdin
        .take()
        .expect("APPARATUS: vox's stdin")
        .write_all(stdin.as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `vox status --json`, parsed.
fn status(data: &Path) -> Value {
    let (ok, out, err) = vox_once(data, &args(&["status", "--json"]));
    assert!(ok, "PRODUCT: `vox status --json` failed: {err}");
    serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` printed no JSON ({e}): {out}"))
}

/// Wait until nothing holds UDP `port`, so a daemon can bind it again.
fn port_free(port: u16) {
    let until = Instant::now() + TIMEOUT;
    while Instant::now() < until {
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("PRODUCT (staging): 127.0.0.1:{port} was never released by the stopped process");
}

/// The notifications the script has recorded, one per line.
fn notes(file: &Path) -> Vec<String> {
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn count(lines: &[String], needle: &str, peer: &str) -> usize {
    lines
        .iter()
        .filter(|l| l.contains(needle) && l.contains(peer))
        .count()
}

fn wait_until(what: &str, within: Duration, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("PRODUCT: timed out waiting for {what}");
}

/// A member's profile directory, as the harness lays it out (`cfg` inside it).
fn member_dir(tmp: &tempfile::TempDir, name: &str) -> PathBuf {
    let d = tmp.path().join(name);
    std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: a profile directory");
    d
}

/// A `vox daemon` on `port`, unlocked (and its rooms opened) from `pass_file`, answering
/// `vox room list` before this returns.
fn daemon(
    name: &str,
    data: &Path,
    port: u16,
    anchor: &str,
    pass_file: &Path,
    env: &[(&str, &str)],
) -> VoxProc {
    let listen = format!("127.0.0.1:{port}");
    let mut p = VoxProc::spawn_env(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            &listen,
            "--anchor",
            anchor,
            "--passphrase-file",
            pass_file.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ]),
        env,
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        if matches!(p.child.try_wait(), Ok(Some(_))) && ports::bind_refused(&p.transcript()) {
            panic!(
                "{}: {name}'s daemon on {listen}:\n{}",
                ports::APPARATUS_BIND,
                p.transcript()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!(
        "PRODUCT (staging): {name}'s daemon never answered `vox room list`; it said:\n{}",
        p.transcript()
    );
}

/// The script `VOX_NOTIFY_COMMAND` runs: one line per notification, into `file`.
fn notify_script(tmp: &tempfile::TempDir, file: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let script = tmp.path().join("notify.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s|%s\\n' \"$1\" \"$2\" >> '{}'\n",
            file.display()
        ),
    )
    .expect("APPARATUS: write the notify script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("APPARATUS: make the notify script executable");
    script
}

/// A directory holding a recording stand-in for the desktop's own notification command, put on
/// the daemon's `PATH` ahead of the real one: `osascript` on macOS, `notify-send` on Linux. Each
/// call appends one line to `file`, so what is counted is the shipped binary invoking the real
/// notifier by name, with the arguments it would give it. On macOS the line is the AppleScript
/// `osascript -e` was handed; on Linux it is `<title>|<body>`.
fn desktop_stub(tmp: &tempfile::TempDir, file: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp.path().join("desktop-bin");
    std::fs::create_dir_all(&dir).expect("APPARATUS: the stub's directory");
    let (name, body) = if cfg!(target_os = "macos") {
        ("osascript", "[ \"$1\" = -e ] && printf '%s\\n' \"$2\"")
    } else {
        ("notify-send", "printf '%s|%s\\n' \"$1\" \"$2\"")
    };
    let stub = dir.join(name);
    std::fs::write(
        &stub,
        format!("#!/bin/sh\n{body} >> '{}'\n", file.display()),
    )
    .expect("APPARATUS: write the stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
        .expect("APPARATUS: make the stub executable");
    dir
}

/// The scene the proofs share: an anchor, and alice's and bob's daemons trusting each other in one
/// room, alice's daemon run with `alice_env` (how it notifies). Returns when alice's `vox status`
/// shows bob connected.
struct Scene {
    _anchor: VoxProc,
    anchor: String,
    alice: VoxProc,
    alice_dir: PathBuf,
    bob: VoxProc,
    bob_dir: PathBuf,
    bob_port: u16,
    bob_id: String,
    pass_file: PathBuf,
}

fn scene(
    tmp: &tempfile::TempDir,
    alice_env: &[(&str, &str)],
    before_alice: impl FnOnce(&Path),
) -> Scene {
    let anchor_dir = member_dir(tmp, "anchor");
    let alice_dir = member_dir(tmp, "alice");
    let bob_dir = member_dir(tmp, "bob");
    // The identity passphrase, and a line that opens the room once there is one: that is
    // what reopens bob's room when his daemon starts again.
    let pass_file = tmp.path().join("passphrases");
    std::fs::write(&pass_file, format!("{IDENTITY}\n{ROOM_PASS}\n"))
        .expect("APPARATUS: write the passphrase file");

    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_id, bob_id) = (fp(&alice_dir), fp(&bob_dir));
    for (d, peer, name) in [(&alice_dir, &bob_id, "bob"), (&bob_dir, &alice_id, "alice")] {
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", peer, "--name", name]));
        assert!(ok, "PRODUCT (staging): vox trust add {name}: {out}{err}");
    }
    before_alice(&alice_dir);

    let alice = daemon("alice", &alice_dir, 0, &spec, &pass_file, alice_env);
    let bob = daemon("bob", &bob_dir, 0, &spec, &pass_file, &[]);
    // The port bob chose, from his own report, for his restart to come back on (#410).
    let bob_port = ports::loopback_listen(&vox_once(&bob_dir, &args(&["status", "--json"])).1)
        .expect("PRODUCT (staging): bob reports a loopback listen address")
        .port();

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "ops"],
        ROOM_PASS,
    );
    assert!(ok, "PRODUCT (staging): vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("ops"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): the room alice made is not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "link", &room]));
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let deadline = Instant::now() + SETUP;
    loop {
        let (ok, out, err) = vox_in(
            &bob_dir,
            &["room", "join", "--passphrase-file", "-", link.trim()],
            ROOM_PASS,
        );
        if ok {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): bob never joined: {out}{err}"
        );
        std::thread::sleep(Duration::from_secs(5));
    }

    let reached = Instant::now() + SETUP;
    while !connected(&status(&alice_dir), &bob_id) {
        assert!(
            Instant::now() < reached,
            "PRODUCT (staging): alice's daemon never reached bob's within {SETUP:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    Scene {
        _anchor: anchor,
        anchor: spec,
        alice,
        alice_dir,
        bob,
        bob_dir,
        bob_port,
        bob_id,
        pass_file,
    }
}

/// Whether alice's `vox status` shows `peer` connected in her room.
fn connected(s: &Value, peer: &str) -> bool {
    s["rooms"][0]["members"].as_array().is_some_and(|ms| {
        ms.iter()
            .any(|m| m["id"].as_str() == Some(peer) && m["connected"] == true)
    })
}

/// A blocked desktop command must not prevent a recovery notice. A desktop service that
/// repeatedly fails must cost only one diagnostic line.
#[test]
#[ignore = "an anchor and two real daemons, with a blocked desktop notifier; run on demand"]
fn blocked_desktop_does_not_delay_recovery() {
    use std::os::unix::fs::PermissionsExt;
    struct BlockedChild(Option<String>);
    impl Drop for BlockedChild {
        fn drop(&mut self) {
            if let Some(pid) = &self.0 {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", pid])
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }

    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let bin = tmp.path().join("desktop-bin");
    std::fs::create_dir(&bin).expect("APPARATUS: create desktop command directory");
    let block = tmp.path().join("block");
    let pid = tmp.path().join("blocked-pid");
    let calls = tmp.path().join("desktop-calls");
    let name = if cfg!(target_os = "macos") {
        "osascript"
    } else {
        "notify-send"
    };
    let stub = bin.join(name);
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nif [ -f '{}' ]; then echo $$ > '{}'; exec /bin/sleep 300; fi\n",
            calls.display(), block.display(), pid.display()
        ),
    )
    .expect("APPARATUS: write desktop command");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
        .expect("APPARATUS: make desktop command executable");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let Scene {
        _anchor,
        anchor,
        mut alice,
        alice_dir: _,
        mut bob,
        bob_dir,
        bob_port,
        bob_id,
        pass_file,
    } = scene(&tmp, &[("PATH", &path)], |_| {});
    let bob_short: String = bob_id.chars().take(12).collect();
    std::fs::write(&block, "").expect("APPARATUS: block the desktop command");
    bob.child.kill().expect("APPARATUS: stop bob");
    bob.child.wait().expect("APPARATUS: reap bob");
    alice.expect_within(Duration::from_secs(150), "bob unreachable", |line| {
        line.contains("vox daemon: Vox: needs attention")
            && line.contains("unreachable")
            && line.contains(&bob_short)
    });
    wait_until("the blocked desktop command to start", TIMEOUT, || {
        pid.exists()
    });
    let blocked_pid = std::fs::read_to_string(&pid).expect("APPARATUS: read notifier PID");
    let mut blocked_child = BlockedChild(Some(blocked_pid.trim().to_owned()));
    let alive = || {
        Command::new("/bin/kill")
            .args(["-0", blocked_pid.trim()])
            .status()
            .expect("APPARATUS: check notifier PID")
            .success()
    };
    assert!(alive(), "APPARATUS: the notifier did not remain blocked");
    let calls_before = notes(&calls).len();
    std::fs::remove_file(&block).expect("APPARATUS: unblock later desktop commands");
    drop(bob);
    port_free(bob_port);
    let _bob = daemon("bob", &bob_dir, bob_port, &anchor, &pass_file, &[]);
    loop {
        let recovered = notes(&calls)
            .iter()
            .any(|line| line.contains("Vox: recovered") && line.contains(&bob_short));
        let running = alive();
        if recovered || !running {
            assert!(
                recovered && running,
                "PRODUCT: recovery did not reach the desktop while the first notifier was alive: {}",
                alice.transcript()
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        notes(&calls).len() > calls_before,
        "PRODUCT: the next desktop call was lost behind the blocked notifier"
    );
    assert!(
        alice
            .child
            .try_wait()
            .expect("APPARATUS: check daemon")
            .is_none(),
        "PRODUCT: daemon stopped while the desktop notifier was blocked"
    );

    let _ = Command::new("/bin/kill")
        .args(["-KILL", blocked_pid.trim()])
        .status()
        .expect("APPARATUS: stop blocked notifier");
    wait_until(
        "the blocked desktop command to be reaped",
        Duration::from_secs(130),
        || !alive(),
    );
    blocked_child.0 = None;
}

#[test]
#[ignore = "five real rooms and blocked desktop calls; run in release"]
fn desktop_notification_calls_are_bounded_and_overflow_is_explicit() {
    use std::os::unix::fs::PermissionsExt;
    struct Children(PathBuf);
    impl Drop for Children {
        fn drop(&mut self) {
            for pid in notes(&self.0) {
                let _ = Command::new("/bin/kill")
                    .args(["-KILL", &pid])
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let calls = tmp.path().join("desktop-pids");
    let _children = Children(calls.clone());
    let script = tmp.path().join("blocked-desktop");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho $$ >> '{}'\nexec /bin/sleep 300\n",
            calls.display()
        ),
    )
    .expect("APPARATUS: desktop stub");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("APPARATUS: executable desktop stub");
    let Scene {
        _anchor,
        mut alice,
        alice_dir,
        mut bob,
        bob_dir,
        bob_id,
        ..
    } = scene(
        &tmp,
        &[(
            "VOX_NOTIFY_COMMAND",
            script.to_str().expect("APPARATUS: script path"),
        )],
        |_| {},
    );
    for number in 1..5 {
        let (ok, out, err) = vox_in(
            &alice_dir,
            &[
                "room",
                "create",
                "--passphrase-file",
                "-",
                "--name",
                &format!("cap-{number}"),
            ],
            ROOM_PASS,
        );
        assert!(ok, "APPARATUS: create cap room: {out}{err}");
        let rooms = status(&alice_dir);
        let room = rooms["rooms"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == format!("cap-{number}"))
            .unwrap()["id"]
            .as_str()
            .unwrap();
        let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "link", room]));
        assert!(ok, "APPARATUS: cap room link: {link}{err}");
        let (ok, out, err) = vox_in(
            &bob_dir,
            &["room", "join", "--passphrase-file", "-", link.trim()],
            ROOM_PASS,
        );
        assert!(ok, "APPARATUS: join cap room: {out}{err}");
    }
    wait_until("five rooms to list the connected member", SETUP, || {
        let snapshot = status(&alice_dir);
        snapshot["rooms"].as_array().is_some_and(|rooms| {
            rooms.len() == 5
                && rooms.iter().all(|room| {
                    room["members"].as_array().is_some_and(|members| {
                        members
                            .iter()
                            .any(|m| m["id"] == bob_id && m["connected"] == true)
                    })
                })
        })
    });
    assert!(
        notes(&calls).is_empty(),
        "APPARATUS: desktop calls started before disconnection"
    );
    bob.child.kill().expect("APPARATUS: stop cap member");
    bob.child.wait().expect("APPARATUS: reap cap member");
    let short: String = bob_id.chars().take(12).collect();
    loop {
        let count = notes(&calls).len();
        assert!(
            count <= 4,
            "PRODUCT: {count} desktop calls started despite a four-call cap"
        );
        let transcript = alice.transcript();
        if transcript.contains("desktop notification not shown:")
            && transcript.contains("4 desktop notifications still waiting")
            && count == 4
        {
            assert_eq!(
                count, 4,
                "APPARATUS: cap notice preceded its four child records"
            );
            assert!(
                transcript.contains(&short),
                "PRODUCT: overflow notice did not identify the affected member: {transcript}"
            );
            break;
        }
        if notes(&calls).first().is_some_and(|pid| {
            !Command::new("/bin/kill")
                .args(["-0", pid])
                .stderr(Stdio::null())
                .status()
                .expect("APPARATUS: check desktop child")
                .success()
        }) {
            panic!("PRODUCT: blocked calls ended without an explicit desktop overflow notice: {transcript}");
        }
        assert!(
            alice
                .child
                .try_wait()
                .expect("APPARATUS: check daemon")
                .is_none(),
            "PRODUCT: daemon stopped during desktop overflow"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "real daemons and a missing desktop service; run in release"]
fn a_missing_desktop_service_logs_once() {
    use std::os::unix::fs::PermissionsExt;
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let bin = tmp.path().join("desktop-bin");
    std::fs::create_dir(&bin).expect("APPARATUS: desktop directory");
    let name = if cfg!(target_os = "macos") {
        "osascript"
    } else {
        "notify-send"
    };
    let attempts = tmp.path().join("failed-attempts");
    let fail = tmp.path().join("fail");
    let stub = bin.join(name);
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\nif [ -f '{}' ]; then echo failed >> '{}'; exit 1; fi\n",
            fail.display(),
            attempts.display()
        ),
    )
    .expect("APPARATUS: desktop stub");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
        .expect("APPARATUS: executable desktop stub");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let Scene {
        _anchor,
        anchor,
        mut alice,
        mut bob,
        bob_dir,
        bob_port,
        bob_id,
        pass_file,
        ..
    } = scene(&tmp, &[("PATH", &path)], |_| {});
    let bob_short: String = bob_id.chars().take(12).collect();
    assert!(
        !alice
            .transcript()
            .contains("desktop notification unavailable"),
        "APPARATUS: desktop failed before the missing-service stage"
    );
    std::fs::write(&fail, "").expect("APPARATUS: make the desktop service unavailable");
    let fail_started = Instant::now();
    alice.seen.clear();
    bob.child.kill().expect("APPARATUS: stop bob again");
    bob.child.wait().expect("APPARATUS: reap bob again");
    alice.expect_within(Duration::from_secs(150), "bob unreachable again", |line| {
        line.contains("vox daemon: Vox: needs attention")
            && line.contains("unreachable")
            && line.contains(&bob_short)
    });
    drop(bob);
    port_free(bob_port);
    let mut bob = daemon("bob", &bob_dir, bob_port, &anchor, &pass_file, &[]);
    alice.expect_within(TIMEOUT, "bob recovered again", |line| {
        line.contains("vox daemon: Vox: recovered") && line.contains(&bob_short)
    });
    wait_until("two failing desktop calls", TIMEOUT, || {
        notes(&attempts).len() >= 2
    });
    // Count the product's own missing-service line, never the stub's stderr.
    // These short failing calls are separated by real disconnect/reconnect transitions.
    alice.seen.clear();
    bob.child
        .kill()
        .expect("APPARATUS: stop bob for the third notice");
    bob.child
        .wait()
        .expect("APPARATUS: reap bob for the third notice");
    alice.expect_within(Duration::from_secs(150), "third failing notice", |line| {
        line.contains("vox daemon: Vox: needs attention") && line.contains(&bob_short)
    });
    wait_until("three failing desktop calls", TIMEOUT, || {
        notes(&attempts).len() >= 3
    });
    let log = alice.timed.lock().expect("APPARATUS: daemon log");
    let failures: Vec<_> = log
        .iter()
        .filter(|(_, line)| line.contains("desktop notification unavailable"))
        .collect();
    assert!(
        failures.iter().all(|(at, _)| *at >= fail_started),
        "PRODUCT: missing-service diagnostic preceded the failing service: {failures:?}"
    );
    assert_eq!(
        failures.len(),
        1,
        "PRODUCT: repeated missing service diagnostics: {failures:?}"
    );
}

#[test]
#[ignore = "an anchor and two real daemons, one killed for three minutes; run on demand"]
fn a_condition_notifies_once_when_it_starts_and_once_when_it_clears() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let file = tmp.path().join("notifications.log");
    let script = notify_script(&tmp, &file);
    let script = script.to_str().expect("APPARATUS: a UTF-8 temp path");
    let Scene {
        _anchor,
        anchor,
        alice: _alice,
        alice_dir: _,
        mut bob,
        bob_dir,
        bob_port,
        bob_id,
        pass_file,
    } = scene(&tmp, &[], |alice_dir| {
        // A setting of alice's node (ADR-026 F-2, #399), not of her daemon's environment: its
        // own `config/config`, which a node of several on one daemon keeps to itself.
        let own = Paths::resolve("default", Some(alice_dir), Some(&alice_dir.join("cfg")))
            .expect("APPARATUS: alice's node paths")
            .own_config_path("config")
            .expect("APPARATUS: alice's node config directory");
        std::fs::write(
            own,
            format!("# set by the proof\nnotify-command = {script}\n"),
        )
        .expect("APPARATUS: write alice's node config");
    });
    let bob_short: String = bob_id.chars().take(12).collect();

    // Two checks' worth, so a notification for a healthy state would have fired by now.
    std::thread::sleep(Duration::from_secs(11));
    let healthy = notes(&file);
    assert_eq!(
        count(&healthy, "unreachable", &bob_short),
        0,
        "PRODUCT: a notification about bob while he is up: {healthy:?}"
    );

    // Kill bob's daemon by its PID. QUIC notices at its idle timeout.
    let killed = Instant::now();
    let _ = bob.child.kill();
    let _ = bob.child.wait();
    wait_until(
        "the unreachable notification",
        Duration::from_secs(150),
        || count(&notes(&file), "unreachable", &bob_short) >= 1,
    );
    let raised_after = killed.elapsed();
    // Three minutes of the same condition.
    std::thread::sleep(Duration::from_secs(180));
    let held = notes(&file);
    eprintln!(
        "raised {raised_after:?} after the kill; after 3 minutes of the condition: {} \
         unreachable line(s)",
        count(&held, "unreachable", &bob_short)
    );
    assert_eq!(
        count(&held, "unreachable", &bob_short),
        1,
        "PRODUCT: three minutes of one condition is one notification, not one per check: {held:?}"
    );

    // Bring bob back on the same port; his passphrase file reopens the room.
    drop(bob);
    port_free(bob_port);
    let mut bob_again = daemon("bob", &bob_dir, bob_port, &anchor, &pass_file, &[]);
    bob_again.expect_within(TIMEOUT, "bob's daemon to hold the room", |l| {
        l.contains("holding room")
    });
    let back = Instant::now();
    wait_until(
        "the recovered notification",
        Duration::from_secs(120),
        || count(&notes(&file), "recovered", &bob_short) >= 1,
    );
    let recovered_after = back.elapsed();
    // And a little longer, so a second one would have had its chance.
    std::thread::sleep(Duration::from_secs(11));
    let end = notes(&file);
    eprintln!(
        "recovered {recovered_after:?} after the restart\nall notifications ({}):\n{}",
        end.len(),
        end.join("\n")
    );
    assert_eq!(
        count(&end, "unreachable", &bob_short) - count(&end, "recovered", &bob_short),
        1,
        "PRODUCT: still exactly one raised: {end:?}"
    );
    assert_eq!(
        count(&end, "recovered", &bob_short),
        1,
        "PRODUCT: and exactly one when it cleared: {end:?}"
    );
}

/// **Opt-out.** With `notify = off` in alice's config the same death raises nothing, and
/// the daemon says at start that notifications are off.
#[test]
#[ignore = "an anchor and two real daemons, one killed; run on demand"]
fn notify_off_raises_nothing() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let file = tmp.path().join("notifications.log");
    let script = notify_script(&tmp, &file);
    let script = script.to_str().expect("APPARATUS: a UTF-8 temp path");
    let Scene {
        _anchor,
        mut alice,
        alice_dir,
        mut bob,
        bob_id,
        ..
    } = scene(&tmp, &[("VOX_NOTIFY_COMMAND", script)], |alice_dir| {
        let config = Paths::resolve("default", Some(alice_dir), Some(&alice_dir.join("cfg")))
            .expect("APPARATUS: alice's profile paths")
            .config_file();
        std::fs::write(config, "# set by the proof\nnotify = off\n")
            .expect("APPARATUS: write alice's config");
    });
    std::thread::sleep(Duration::from_secs(2));
    // alice's status lines about bob, from her `vox status --json`.
    let about_bob = || -> Vec<Value> {
        status(&alice_dir)["unhealthy"]
            .as_array()
            .map(|u| {
                u.iter()
                    .filter(|l| l["key"].as_str().is_some_and(|k| k.contains(&bob_id)))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    };
    // R35, as `ops_status_proof` asserted before it went in a1d01323 (#227): a peer that is up
    // is not flagged, and a peer that died is flagged as unreachable.
    let while_up = about_bob();
    assert!(
        while_up.is_empty(),
        "PRODUCT: bob is up, so alice's status must not flag him: {while_up:?}"
    );
    let _ = bob.child.kill();
    let _ = bob.child.wait();
    // Until the condition is certainly flagged — status shows it — and one check more.
    let short: String = bob_id.chars().take(12).collect();
    wait_until(
        "alice's status to flag bob",
        Duration::from_secs(150),
        || !about_bob().is_empty(),
    );
    let flagged = about_bob();
    eprintln!("alice's status about bob once he died: {flagged:?}");
    assert!(
        flagged.iter().any(|l| l["message"]
            .as_str()
            .is_some_and(|m| m.contains("unreachable") && m.contains(&short))),
        "PRODUCT: alice's status must say bob ({short}) is unreachable: {flagged:?}"
    );
    std::thread::sleep(Duration::from_secs(11));
    let lines = notes(&file);
    let said = alice.transcript();
    eprintln!(
        "notify = off: {} notification(s) {lines:?}; alice said: {said}",
        lines.len()
    );
    assert!(
        lines.is_empty(),
        "PRODUCT: notify = off must raise nothing about {short}: {lines:?}"
    );
    assert!(
        said.contains("notifications off"),
        "PRODUCT: the daemon must say at start that notifications are off; it said:\n{said}"
    );
}

/// The anchor named `id` in alice's node-specific status observations: `Some(reached)`, or `None` if she does
/// not list it.
fn anchor_reached(s: &Value, id: &str) -> Option<bool> {
    s["node_anchors"]
        .as_array()?
        .iter()
        .find(|a| a["id"].as_str() == Some(id))
        .and_then(|a| a["reached"].as_bool())
}

/// Whether alice's `vox status --json` shows a live **direct** connection to `peer`.
fn direct_to(s: &Value, peer: &str) -> bool {
    s["peers"].as_array().is_some_and(|ps| {
        ps.iter()
            .any(|p| p["id"].as_str() == Some(peer) && p["path"].as_str() == Some("direct"))
    })
}

/// How long an anchor this node does not need is watched for a notification that must not come:
/// past `ANCHOR_UNREACHABLE_SECS` (60 s), and two of the notifier's checks more.
const UNNEEDED_WATCH: Duration = Duration::from_secs(80);

/// **An anchor that cannot be reached, alarming only when this node needs it** (PRD-001 R37,
/// ADR-012: an anchor only bridges hosts that cannot otherwise find each other).
///
/// alice and bob share a room over a **direct** connection, and alice keeps one anchor.
/// 1. **Not needed.** The anchor is killed by its PID while bob is reached directly: over
///    [`UNNEEDED_WATCH`], past the 60 s an anchor restarting is given, nothing is raised about it.
/// 2. **Needed.** bob's daemon is killed too, so alice has a trusted member she reaches by no
///    direct connection, and an anchor is what would bridge them: exactly one "unreachable"
///    notification naming the anchor, and still one half a minute later.
/// 3. The anchor is started again on the same port with the same profile: exactly one
///    "recovered".
///
/// **Through the desktop's own notifier**, not `VOX_NOTIFY_COMMAND`: alice's daemon finds a
/// recording `osascript` (macOS) or `notify-send` (Linux) first on its `PATH`, so this shows the
/// shipped binary invoking the platform notifier, and that it hands it the right title and body.
/// The other proofs here observe through `VOX_NOTIFY_COMMAND`.
///
/// Mutations: an anchor line raised whether or not the node needs it goes red at (1); no anchor
/// line at all goes red at (2).
#[test]
#[ignore = "an anchor and two real daemons, the anchor killed for over two minutes; run on demand"]
fn an_unreachable_anchor_notifies_once_and_once_when_it_is_back() {
    // Setup, 80 s of an unneeded anchor, up to 150 s for the needed one, then its return.
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let file = tmp.path().join("notifications.log");
    // The desktop's own notifier, not `VOX_NOTIFY_COMMAND`: a recording `osascript` (macOS) or
    // `notify-send` (Linux) ahead of the real one on the daemon's PATH.
    let stub_dir = desktop_stub(&tmp, &file);
    let path = format!(
        "{}:{}",
        stub_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let Scene {
        _anchor: mut the_anchor,
        anchor,
        alice: _alice,
        alice_dir,
        mut bob,
        bob_id,
        ..
    } = scene(&tmp, &[("PATH", path.as_str())], |_| {});
    let anchor_id = anchor.split('@').next().unwrap_or_default().to_owned();
    let anchor_short: String = anchor_id.chars().take(12).collect();
    let anchor_port: u16 = anchor
        .rsplit('/')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("APPARATUS: no port in the anchor spec {anchor}"));
    let about_anchor = |lines: &[String]| count(lines, "unreachable", &anchor_short);
    let flagged = |s: &Value| {
        s["unhealthy"].as_array().is_some_and(|u| {
            u.iter().any(|l| {
                l["key"]
                    .as_str()
                    .is_some_and(|k| k == format!("anchor-unreachable:{anchor_id}"))
            })
        })
    };

    let reached = Instant::now() + SETUP;
    loop {
        let s = status(&alice_dir);
        if anchor_reached(&s, &anchor_id) == Some(true) && direct_to(&s, &bob_id) {
            break;
        }
        assert!(
            Instant::now() < reached,
            "CANNOT MEASURE: alice never both reached her anchor {anchor_short} and held a direct \
             connection to bob: anchors {}, peers {}",
            s["node_anchors"],
            s["peers"]
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // Two checks' worth, so a notification for a healthy anchor would have fired by now.
    std::thread::sleep(Duration::from_secs(11));
    let healthy = notes(&file);
    assert_eq!(
        about_anchor(&healthy),
        0,
        "PRODUCT: a notification about the anchor while it is up: {healthy:?}"
    );

    // (1) Not needed: the anchor is killed by its PID while bob is reached directly.
    let killed = Instant::now();
    let _ = the_anchor.child.kill();
    let _ = the_anchor.child.wait();
    while killed.elapsed() < UNNEEDED_WATCH {
        let s = status(&alice_dir);
        assert!(
            direct_to(&s, &bob_id),
            "CANNOT MEASURE: alice lost her direct connection to bob {:?} after the anchor was \
             killed, so whether she needs the anchor changed under the measurement: peers {}",
            killed.elapsed(),
            s["peers"]
        );
        let raised = notes(&file);
        assert!(
            about_anchor(&raised) == 0 && !flagged(&s),
            "PRODUCT: an anchor this node does not need alarmed a person (ADR-012: an anchor only \
             bridges hosts that cannot otherwise find each other): {:?} after it was killed, with \
             bob reached directly, alice's status flags {} and the notifier got {raised:?}",
            killed.elapsed(),
            s["unhealthy"]
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!(
        "[proof] (1) the anchor down {:?} with bob reached directly: nothing raised",
        killed.elapsed()
    );

    // (2) Needed: bob's daemon is killed too, so no trusted member is reached directly.
    let bob_killed = Instant::now();
    let _ = bob.child.kill();
    let _ = bob.child.wait();
    let until = bob_killed + Duration::from_secs(150);
    while about_anchor(&notes(&file)) == 0 {
        assert!(
            Instant::now() < until,
            "PRODUCT: no notification about the anchor {anchor_short}, down {:?}, {:?} after bob \
             was killed left alice a member she reaches by no direct connection; her status says \
             {}; notifications: {:?}",
            killed.elapsed(),
            bob_killed.elapsed(),
            status(&alice_dir)["unhealthy"],
            notes(&file)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let raised_after = bob_killed.elapsed();
    // Half a minute more of the same condition.
    std::thread::sleep(Duration::from_secs(30));
    let held = notes(&file);
    eprintln!(
        "[proof] (2) raised {raised_after:?} after bob was killed (the anchor down {:?}); 30 s \
         later: {held:?}",
        killed.elapsed()
    );
    assert_eq!(
        about_anchor(&held),
        1,
        "PRODUCT: one condition is one notification, not one per check: {held:?}"
    );
    // What the desktop was handed: the title and the body, in the notifier's own form.
    let raised = held
        .iter()
        .find(|l| l.contains("unreachable") && l.contains(&anchor_short))
        .cloned()
        .unwrap_or_default();
    let title = "Vox: needs attention";
    let body = format!("anchor {anchor_short} unreachable for");
    let well_formed = if cfg!(target_os = "macos") {
        raised.starts_with(&format!("display notification \"{body}"))
            && raised.ends_with(&format!("with title \"{title}\""))
    } else {
        raised.starts_with(&format!("{title}|{body}"))
    };
    assert!(
        well_formed,
        "PRODUCT: the desktop notifier was not handed the title {title:?} and a body starting \
         {body:?}: it got {raised:?}"
    );

    // (3) The anchor again, same profile, same port.
    drop(the_anchor);
    port_free(anchor_port);
    let _anchor_again = VoxProc::spawn(
        "anchor",
        &tmp.path().join("anchor"),
        &args(&["node", "--listen", &format!("127.0.0.1:{anchor_port}")]),
    );
    let back = Instant::now();
    let until = back + Duration::from_secs(120);
    while count(&notes(&file), "recovered", &anchor_short) == 0 {
        assert!(
            Instant::now() < until,
            "PRODUCT: no \"recovered\" notification {:?} after the anchor was back; alice's \
             anchors: {}; notifications: {:?}",
            back.elapsed(),
            status(&alice_dir)["node_anchors"],
            notes(&file)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let recovered_after = back.elapsed();
    std::thread::sleep(Duration::from_secs(11));
    let end = notes(&file);
    eprintln!("[proof] (3) recovered {recovered_after:?} after the anchor was back: {end:?}");
    assert_eq!(
        (about_anchor(&end), count(&end, "recovered", &anchor_short)),
        (2, 1),
        "PRODUCT: exactly one raised (the recovered line repeats its text) and one cleared: \
         {end:?}"
    );
}

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_room_that_cannot_sync_notifies_once_and_once_when_it_syncs_again);

/// **A disconnected room with no new sync entries** (PRD-001 R37), optional because the
/// condition takes ten minutes to start. Kill bob and the anchor so nobody can connect.
/// Exactly one desktop notification names the stale room. Bob reconnects and posts a new
/// message; Alice reads that message and receives exactly one desktop recovery notification.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: an anchor and two daemons, one killed for over ten minutes; run in release"]
fn a_room_that_cannot_sync_notifies_once_and_once_when_it_syncs_again() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let file = tmp.path().join("notifications.log");
    let script = notify_script(&tmp, &file);
    let script = script.to_str().expect("APPARATUS: a UTF-8 temp path");
    let Scene {
        _anchor: mut the_anchor,
        anchor,
        alice: _alice,
        alice_dir,
        mut bob,
        bob_dir,
        bob_port,
        pass_file,
        ..
    } = scene(&tmp, &[("VOX_NOTIFY_COMMAND", script)], |_| {});
    let anchor_port = anchor.rsplit('/').next().unwrap_or_default().to_owned();
    let room: String = status(&alice_dir)["rooms"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("PRODUCT: alice's status lists no room"))
        .chars()
        .take(12)
        .collect();
    let stale = |lines: &[String]| count(lines, "no new sync entries", &room);

    let killed = Instant::now();
    for p in [&mut bob, &mut the_anchor] {
        let _ = p.child.kill();
        let _ = p.child.wait();
    }
    let until = killed + Duration::from_secs(10 * 60 + 120);
    while stale(&notes(&file)) == 0 {
        let s = status(&alice_dir);
        assert!(
            Instant::now() < until,
            "PRODUCT: no notification for room {room} {:?} after its only other member and the \
             anchor were killed; alice last received new sync entries at {} (now {}); \
             her status says {}; notifications: {:?}",
            killed.elapsed(),
            s["rooms"][0]["last_sync_ms"],
            s["now_ms"],
            s["unhealthy"],
            notes(&file)
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    let raised_after = killed.elapsed();
    std::thread::sleep(Duration::from_secs(30));
    let held = notes(&file);
    eprintln!(
        "[proof] room {room} raised {raised_after:?} after bob and the anchor were killed: {held:?}"
    );
    assert_eq!(
        stale(&held),
        1,
        "PRODUCT: one condition is one notification: {held:?}"
    );

    // The anchor back on its port, with its profile; then bob.
    drop(the_anchor);
    let anchor_port: u16 = anchor_port
        .parse()
        .unwrap_or_else(|_| panic!("APPARATUS: no port in the anchor spec {anchor}"));
    port_free(anchor_port);
    let _anchor_again = VoxProc::spawn(
        "anchor",
        &tmp.path().join("anchor"),
        &args(&["node", "--listen", &format!("127.0.0.1:{anchor_port}")]),
    );
    drop(bob);
    port_free(bob_port);
    let mut bob_again = daemon("bob", &bob_dir, bob_port, &anchor, &pass_file, &[]);
    bob_again.expect_within(TIMEOUT, "bob's daemon to hold the room", |l| {
        l.contains("holding room")
    });
    let (ok, out, err) = vox_once(
        &bob_dir,
        &args(&["room", "post", &room, "received-after-disconnection"]),
    );
    assert!(ok, "APPARATUS: returning member could not post: {out}{err}");
    let mut observed_receipt = false;
    let back = Instant::now();
    let cleared = |lines: &[String]| {
        lines
            .iter()
            .filter(|l| {
                l.contains("recovered") && l.contains("no new sync entries") && l.contains(&room)
            })
            .count()
    };
    let until = back + Duration::from_secs(120);
    while cleared(&notes(&file)) == 0 || !observed_receipt {
        let (ok, out, _) = vox_once(&alice_dir, &args(&["room", "read", &room, "--json"]));
        observed_receipt |= ok && out.contains("received-after-disconnection");
        let snapshot = status(&alice_dir);
        if Instant::now() >= until {
            if observed_receipt && cleared(&notes(&file)) == 0 {
                panic!(
                    "PRODUCT: room stale alarm did not clear after a new entry was received; \
                     status {snapshot}; notifications {:?}",
                    notes(&file)
                );
            }
            if !observed_receipt {
                panic!(
                    "APPARATUS: recovery receipt was not staged; status {snapshot}; \
                 returning member said {}; notifications {:?}",
                    bob_again.transcript(),
                    notes(&file)
                );
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    std::thread::sleep(Duration::from_secs(11));
    let end = notes(&file);
    eprintln!(
        "[proof] room {room} recovered {:?} after the anchor and bob were back: {end:?}",
        back.elapsed()
    );
    assert_eq!(
        (stale(&end), cleared(&end)),
        (2, 1),
        "PRODUCT: exactly one raised (the recovered line repeats its text) and one cleared: {end:?}"
    );
}
