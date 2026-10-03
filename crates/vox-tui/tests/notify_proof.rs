//! PRD-001 R37 — a running daemon notifies its operator when `vox status` would flag
//! something, **once** when it starts and **once** when it clears.
//!
//! Every participant is the shipped binary, driven as a person would (ADR-018, "Only real use
//! of the product is a test"): an anchor (`vox node`), and alice and bob, each a `vox daemon`
//! made with `vox id`, trusting each other with `vox trust add`, sharing one room made with
//! `vox room create`, `vox room invite` and `vox room join`. What the proof reads is what a
//! person can read: `vox status --json`, and what the daemon prints.
//!
//! alice's daemon runs with `VOX_NOTIFY_COMMAND` pointed at a script that appends each
//! notification to a file, so what is counted is the shipped binary's own decision to
//! notify. Kill bob: exactly one "unreachable" notification. Leave him dead for three
//! minutes: still exactly one. Start him again: exactly one "recovered".

#![cfg(unix)]

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
        .expect("run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `vox status --json`, parsed.
fn status(data: &Path) -> Value {
    let (ok, out, err) = vox_once(data, &args(&["status", "--json"]));
    assert!(ok, "vox status failed: {err}");
    serde_json::from_str(&out).expect("vox status --json prints JSON")
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    panic!("127.0.0.1:{port} was never released by the stopped daemon");
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
    panic!("timed out waiting for {what}");
}

/// A member's profile directory, as the harness lays it out (`cfg` inside it).
fn member_dir(tmp: &tempfile::TempDir, name: &str) -> PathBuf {
    let d = tmp.path().join(name);
    std::fs::create_dir_all(d.join("cfg")).unwrap();
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
    let p = VoxProc::spawn_env(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            &listen,
            "--anchor",
            anchor,
            "--passphrase-file",
            pass_file.to_str().unwrap(),
        ]),
        env,
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{name}'s daemon never answered `vox room list`");
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
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    script
}

/// The scene both proofs share: an anchor, and alice's and bob's daemons trusting each other
/// in one room, alice's notifying through `script`. Returns when alice's `vox status` shows
/// bob connected.
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

fn scene(tmp: &tempfile::TempDir, script: &Path, before_alice: impl FnOnce(&Path)) -> Scene {
    let anchor_dir = member_dir(tmp, "anchor");
    let alice_dir = member_dir(tmp, "alice");
    let bob_dir = member_dir(tmp, "bob");
    // The identity passphrase, and a line that opens the room once there is one: that is
    // what reopens bob's room when his daemon starts again.
    let pass_file = tmp.path().join("passphrases");
    std::fs::write(&pass_file, format!("{IDENTITY}\n{ROOM_PASS}\n")).unwrap();

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
        assert!(ok, "vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_id, bob_id) = (fp(&alice_dir), fp(&bob_dir));
    for (d, peer, name) in [(&alice_dir, &bob_id, "bob"), (&bob_dir, &alice_id, "alice")] {
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", peer, "--name", name]));
        assert!(ok, "vox trust add {name}: {out}{err}");
    }
    before_alice(&alice_dir);

    let (alice_port, bob_port) = (free_udp_port(), free_udp_port());
    let script = script.to_str().unwrap();
    let alice = daemon(
        "alice",
        &alice_dir,
        alice_port,
        &spec,
        &pass_file,
        &[("VOX_NOTIFY_COMMAND", script)],
    );
    let bob = daemon("bob", &bob_dir, bob_port, &spec, &pass_file, &[]);

    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "ops"],
        ROOM_PASS,
    );
    assert!(ok, "vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("ops"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
    assert!(ok, "vox room invite: {err}");
    let deadline = Instant::now() + SETUP;
    loop {
        let (ok, out, err) = vox_in(
            &bob_dir,
            &[
                "room",
                "join",
                "--passphrase-file",
                "-",
                link.trim(),
                "--name",
                "ops",
            ],
            ROOM_PASS,
        );
        if ok {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: bob never joined: {out}{err}"
        );
        std::thread::sleep(Duration::from_secs(5));
    }

    wait_until("alice's daemon to reach bob's", SETUP, || {
        connected(&status(&alice_dir), &bob_id)
    });
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

#[test]
#[ignore = "an anchor and two real daemons, one killed for three minutes; CI runs it in release"]
fn a_condition_notifies_once_when_it_starts_and_once_when_it_clears() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("notifications.log");
    let script = notify_script(&tmp, &file);
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
    } = scene(&tmp, &script, |_| {});
    let bob_short: String = bob_id.chars().take(12).collect();

    // Two checks' worth, so a notification for a healthy state would have fired by now.
    std::thread::sleep(Duration::from_secs(11));
    let healthy = notes(&file);
    assert_eq!(
        count(&healthy, "unreachable", &bob_short),
        0,
        "nothing about bob while he is up: {healthy:?}"
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
        "three minutes of one condition is one notification, not one per check: {held:?}"
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
        "still exactly one raised"
    );
    assert_eq!(
        count(&end, "recovered", &bob_short),
        1,
        "and exactly one when it cleared"
    );
}

/// **Opt-out.** With `notify = off` in alice's config the same death raises nothing, and
/// the daemon says at start that notifications are off.
#[test]
#[ignore = "an anchor and two real daemons, one killed; CI runs it in release"]
fn notify_off_raises_nothing() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let file = tmp.path().join("notifications.log");
    let script = notify_script(&tmp, &file);
    let Scene {
        _anchor,
        mut alice,
        alice_dir,
        mut bob,
        bob_id,
        ..
    } = scene(&tmp, &script, |alice_dir| {
        let config = Paths::resolve("default", Some(alice_dir), Some(&alice_dir.join("cfg")))
            .unwrap()
            .config_file();
        std::fs::write(config, "# set by the proof\nnotify = off\n").unwrap();
    });
    std::thread::sleep(Duration::from_secs(2));
    let _ = bob.child.kill();
    let _ = bob.child.wait();
    // Until the condition is certainly flagged — status shows it — and one check more.
    let short: String = bob_id.chars().take(12).collect();
    wait_until(
        "alice's status to flag bob",
        Duration::from_secs(150),
        || {
            status(&alice_dir)["unhealthy"].as_array().is_some_and(|u| {
                u.iter()
                    .any(|l| l["key"].as_str().is_some_and(|k| k.contains(&bob_id)))
            })
        },
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
        "notify = off must raise nothing about {short}"
    );
    assert!(
        said.contains("notifications off"),
        "and the daemon must say they are off"
    );
}
