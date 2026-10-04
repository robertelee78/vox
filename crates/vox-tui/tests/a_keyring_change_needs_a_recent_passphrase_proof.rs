//! **A keyring change needs the identity passphrase once 30 minutes have passed since it was last
//! entered, whatever the client** (V210-159, decider 2026-10-02, option A) — driven through the
//! shipped binary and its control socket. Run on demand, with the `test-knobs` feature:
//! `VOX_TEST_KEYRING_WINDOW_SECS` shortens the window to [`WINDOW`].
//!
//! The check lived only in the control socket's handler, which asked for the passphrase on every
//! change; an in-process client could change the keyring with no proof once the identity was
//! unlocked. Now the node keeps when the passphrase was last entered — at unlock, and at any later
//! check of it that passed — and refuses a trust add or remove past the window, until it is given
//! again, to every client alike.
//!
//! Asserted, against a `vox daemon` given its passphrase in `VOX_IDENTITY_PASSPHRASE`:
//! - a `vox trust add` right after the unlock succeeds, with no passphrase given;
//! - past the window, `vox trust remove` with no passphrase and no terminal is refused at once
//!   saying the passphrase is needed, and nothing changes;
//! - past the window, a raw control-socket `Trust` with no passphrase is refused the same way; one
//!   with a wrong passphrase is refused; one with the right passphrase succeeds;
//! - past the window again, `vox trust remove --identity-passphrase-file` succeeds.
//!
//! **A change given the right passphrase is always made.** Every change whose passphrase was just
//! checked waits [`PROVED_DELAY`], longer than [`WINDOW`], between the check and the change
//! (`VOX_TEST_PROVED_CHANGE_DELAY_MS`): the window the check restarted is gone by the time the
//! change is made, as it is when several checks pass at once and race to restart it, or when the
//! clock moves on between the check and the change. The right-passphrase changes of 3 and 4 must
//! still succeed.
//!
//! The TUI has no keyring change to prompt for: it trusts and untrusts nobody, so there is nothing
//! of it to drive here.
//!
//! Mutations: no window check in the node — red, PRODUCT (the change past the window is made). A
//! change given the right passphrase put through the window like one given none — red, PRODUCT
//! (it is refused as needing the passphrase it was given).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::io::BufRead as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::node::ipc::{Frame, Request};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity pass phrase";
const KNOB: &str = "VOX_TEST_KEYRING_WINDOW_SECS";
/// The shortened window.
const WINDOW: Duration = Duration::from_secs(6);
/// How long a refused change may take to be refused: at once.
const ANSWERS_WITHIN: Duration = Duration::from_secs(10);
/// Every change whose passphrase was just checked waits this long between the check and the
/// change (`VOX_TEST_PROVED_CHANGE_DELAY_MS`): past [`WINDOW`], so the change finds the window the
/// check restarted already gone, and must be made anyway.
const PROVED_DELAY: Duration = Duration::from_secs(8);
const DELAY_KNOB: &str = "VOX_TEST_PROVED_CHANGE_DELAY_MS";

fn vox_cmd(dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(VOX);
    c.args(args);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("VOX_") {
            c.env_remove(k);
        }
    }
    c.env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"));
    c
}

/// A command with stdin open and unwritten and no terminal, as an agent's harness runs it:
/// (succeeded, what it said). Red past [`ANSWERS_WITHIN`] (plus [`PROVED_DELAY`], which a
/// change given its passphrase waits by design).
fn run(cmd: &mut Command) -> (bool, String) {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(cmd, || {
            rustix::process::setsid()?;
            Ok(())
        });
    }
    let t0 = Instant::now();
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox");
    let held = child.stdin.take();
    while child.try_wait().expect("APPARATUS: wait").is_none() {
        if t0.elapsed() > ANSWERS_WITHIN + PROVED_DELAY {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "PRODUCT: a trust command was still waiting after {:?}",
                ANSWERS_WITHIN + PROVED_DELAY
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(held);
    let out = child.wait_with_output().expect("APPARATUS: output");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn profile(root: &Path, name: &str) -> (std::path::PathBuf, String) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).expect("APPARATUS: profile dir");
    let out = vox_cmd(&dir, &["id"])
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .stdin(Stdio::null())
        .output()
        .expect("APPARATUS: spawn vox id");
    assert!(
        out.status.success(),
        "CANNOT MEASURE: `vox id` did not make {name}'s identity: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (dir, String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn trusted(dir: &Path) -> String {
    let (ok, said) = run(&mut vox_cmd(dir, &["trust", "list"]));
    assert!(
        ok,
        "PRODUCT: `vox trust list` failed against the running node: {said}"
    );
    said
}

/// A raw `Trust` request on the control socket, as any client of it sends one.
fn raw_trust(sock: &Path, target: &str, petname: &str, passphrase: &str) -> Frame {
    let target =
        vox_core::node::link::b32_decode(target, "fingerprint").expect("APPARATUS: a fingerprint");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: runtime");
    rt.block_on(async {
        // The account socket, as node `default` (ADR-026 C-2): what every client sends on.
        let mut client = attach::client_at(sock, "default")
            .await
            .unwrap_or_else(|e| panic!("CANNOT MEASURE: the control socket did not answer: {e}"));
        tokio::time::timeout(
            ANSWERS_WITHIN + PROVED_DELAY,
            client.request(&Request::Trust {
                target,
                petname: petname.to_owned(),
                identity_passphrase: passphrase.to_owned(),
                full_history: false,
            }),
        )
        .await
        .expect("PRODUCT: a raw Trust request was not answered in time")
        .expect("PRODUCT: a raw Trust request broke the connection")
    })
}

#[test]
fn a_keyring_change_past_the_window_needs_the_passphrase_from_every_client() {
    watchdog::arm();
    test_knobs::require(&[KNOB, DELAY_KNOB]);
    let needed = vox_core::node::api::Fault::PassphraseNeeded.explain();
    let needed_first = needed.lines().next().unwrap_or_default();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let (alice, _) = profile(tmp.path(), "alice");
    let (_, bob) = profile(tmp.path(), "bob");
    let (_, carol) = profile(tmp.path(), "carol");
    let (_, dave) = profile(tmp.path(), "dave");
    let pass_file = tmp.path().join("idpass");
    std::fs::write(&pass_file, format!("{IDPASS}\n")).expect("APPARATUS: passphrase file");

    let mut daemon = vox_cmd(&alice, &["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env(KNOB, WINDOW.as_secs().to_string())
        .env(DELAY_KNOB, PROVED_DELAY.as_millis().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let _held = daemon.stdin.take();
    let mut out = std::io::BufReader::new(daemon.stdout.take().expect("APPARATUS: stdout"));
    let mut sock = None;
    let mut line = String::new();
    while out.read_line(&mut line).is_ok_and(|n| n > 0) {
        if let Some(at) = line.trim().strip_prefix("vox daemon: control socket ") {
            sock = Some(std::path::PathBuf::from(at));
            break;
        }
        line.clear();
    }
    let unlocked = Instant::now();
    let Some(sock) = sock else {
        let _ = daemon.kill();
        panic!("CANNOT MEASURE: the daemon never said where its control socket is");
    };
    let kill = |mut d: std::process::Child| {
        let _ = d.kill();
        let _ = d.wait();
    };

    // 1. Right after the unlock: no passphrase needed.
    let (ok, said) = run(&mut vox_cmd(
        &alice,
        &["trust", "add", &bob, "--name", "bob"],
    ));
    if !ok && unlocked.elapsed() >= WINDOW {
        kill(daemon);
        panic!("CANNOT MEASURE: the first trust add came after the {WINDOW:?} window: {said}");
    }
    if !ok {
        kill(daemon);
        panic!("PRODUCT: a trust add right after the unlock was refused: {said}");
    }

    // 2. Past the window, the CLI with nothing to give: refused at once, nothing changed.
    std::thread::sleep(WINDOW + Duration::from_secs(2));
    let (ok, said) = run(&mut vox_cmd(&alice, &["trust", "remove", &bob]));
    let list = trusted(&alice);
    if ok || !said.contains(needed_first) || !list.contains(&bob) {
        kill(daemon);
        panic!(
            "PRODUCT: past the window, `vox trust remove` with no passphrase was not refused for \
             it (succeeded {ok}); it said:\n{said}\nthe keyring now:\n{list}"
        );
    }

    // 3. Past the window, a raw socket request: none given, then a wrong one, then the right one.
    let none = raw_trust(&sock, &carol, "carol", "");
    let wrong = raw_trust(&sock, &carol, "carol", "not the passphrase");
    let after_refusals = trusted(&alice);
    let right = raw_trust(&sock, &carol, "carol", IDPASS);
    let after_right = trusted(&alice);
    let refused = |f: &Frame| matches!(f, Frame::Error { .. });
    if !matches!(&none, Frame::Error { reason } if reason == needed)
        || !refused(&wrong)
        || after_refusals.contains(&carol)
        || right != Frame::Ok
        || !after_right.contains(&carol)
    {
        kill(daemon);
        panic!(
            "PRODUCT: past the window, the control socket did not refuse a Trust without the \
             passphrase and make it with it.\n none given: {none:?}\n wrong: {wrong:?}\n right: \
             {right:?}\nkeyring after the refusals:\n{after_refusals}\nafter the right \
             one:\n{after_right}"
        );
    }

    // 4. Past the window again: the CLI given the passphrase in a file.
    std::thread::sleep(WINDOW + Duration::from_secs(2));
    let (refused_ok, refused_said) = run(&mut vox_cmd(
        &alice,
        &["trust", "add", &dave, "--name", "d"],
    ));
    let given = run(&mut vox_cmd(
        &alice,
        &[
            "trust",
            "remove",
            &bob,
            "--identity-passphrase-file",
            pass_file.to_str().expect("APPARATUS: path"),
        ],
    ));
    let list = trusted(&alice);
    kill(daemon);
    assert!(
        !refused_ok && refused_said.contains(needed_first) && !list.contains(&dave),
        "PRODUCT: past the window again, `vox trust add` with no passphrase was not refused for \
         it: {refused_said}\nthe keyring:\n{list}"
    );
    assert!(
        given.0 && !list.contains(&bob),
        "PRODUCT: past the window, `vox trust remove --identity-passphrase-file` did not make the \
         change: {}\nthe keyring:\n{list}",
        given.1
    );
    eprintln!("the window held for the CLI and the control socket alike; the keyring:\n{list}");
}
