//! V210-100 (#296) — **a `vox tui` that waits for another vox holding the profile says so in its
//! status line, and its screen stays whole**, through the shipped binary.
//!
//! Creating the identity and migrating a v0.2.9 profile each hold the profile directory's lock,
//! and a vox that waits for it more than a second says so (V210-100 c2). That notice was printed to
//! stderr by the lock itself, and `vox tui` draws on the terminal stderr writes to: under the TUI
//! the line landed inside the screen, across the prompt box's border, and stayed there. The node
//! now reports the wait as an event, and each front end says it in its own place: the CLI on
//! stderr, the TUI in its status line, in its own words (`fg` is no advice inside a TUI).
//!
//! Staging (`tests/pty/tui_lock_wait.py`), in two arms, one per path that takes the lock:
//! 1. **Create.** On a fresh profile, `vox id` A takes the lock and holds it
//!    (`VOX_TEST_LOCK_HOLD_MS`, proof-only, inert when unset, says when it has it), and is
//!    stopped with SIGSTOP by its PID. `vox tui` B starts and is given a passphrase at its
//!    first-run prompt.
//! 2. **Migration.** The same on a profile the **released v0.2.9 binary** wrote: A is
//!    `vox trust add`, migrating it; B is given the passphrase at its unlock prompt.
//!
//! Asserted, per arm, from B's screen through `pyte`: within 15 s the status line says another vox
//! is using this profile; no CLI-only text ("vox: waiting …", "resume it") is anywhere on the
//! screen; every box border row ends with its partner. Then A is resumed with SIGCONT, and B
//! answers: the create arm names the concurrent creation, the migration arm unlocks (or names the
//! other vox holding the profile).
//!
//! Mutation that must turn it red: the notice written to stderr by the lock again (as c2 did) —
//! the line lands on the TUI's screen.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/previous_release.rs"]
mod previous_release;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use previous_release::previous_release;
use world::{args, VoxProc, IDENTITY, VOX};

const HOLD_MS: &str = "4000";
const HOLDING: &str = "holding the profile lock";

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: kill {sig} {pid}");
}

/// One arm; what was wrong with it, if anything.
fn arm(label: &str, data: &Path, mode: &str, holder_args: &[&str], answer: &[&str]) -> Vec<String> {
    test_knobs::require(&["VOX_TEST_LOCK_HOLD_MS"]);
    let mut a = VoxProc::spawn_env(
        &format!("{label} holder"),
        data,
        &args(holder_args),
        &[("VOX_TEST_LOCK_HOLD_MS", HOLD_MS)],
    );
    a.expect_within(
        Duration::from_secs(180),
        "the holder holding the profile lock",
        |l| l.contains(HOLDING),
    );
    let pid = a.child.id();
    signal(pid, "-STOP");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_lock_wait.py");
    let out = pty_driver::run(
        script,
        &[
            VOX,
            &data.to_string_lossy(),
            &data.join("cfg").to_string_lossy(),
            IDENTITY,
            label,
            mode,
            &pid.to_string(),
        ],
    );
    // The driver resumes the holder; make sure, then let it finish.
    let _ = Command::new("kill")
        .args(["-CONT", &pid.to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(180);
    while a
        .child
        .try_wait()
        .expect("APPARATUS: poll a child process")
        .is_none()
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(200));
    }
    let said = out.stdout.clone();
    println!(
        "[proof] {label}: the TUI driver took {:?}, exit {:?}, last stage {:?}\n{}",
        out.took,
        out.code,
        out.stage,
        said.trim()
    );
    let line = |p: &str| {
        said.lines()
            .find_map(|l| l.strip_prefix(&format!("{label} {p}")))
            .map(str::to_owned)
    };
    // What the TUI failed to do (the driver's `RED: PRODUCT`: no prompt, no answer after the
    // holder resumed), or a TUI that stopped reading what is typed (`HUNG at`), is the product's;
    // only the driver's own machinery, or a TUI it could not reap, is the apparatus.
    assert!(
        !said.contains(&format!("{label} RED: PRODUCT"))
            && !said.contains(&format!("{label} HUNG at")),
        "PRODUCT: the {label} arm's `vox tui` failed or stopped answering (exit {:?}, stage \
         {:?}): {said}",
        out.code,
        out.stage
    );
    assert!(
        !out.has_verdict(label),
        "APPARATUS: the {label} arm's TUI driver's own machinery failed, or it could not reap the \
         TUI (exit {:?}, stage {:?}): {said}",
        out.code,
        out.stage
    );
    assert!(
        out.code == Some(0) && line("AFTER:").is_some(),
        "APPARATUS: the {label} arm's TUI driver did not run to the end (exit {:?}, stage \
         {:?}): {said}",
        out.code,
        out.stage
    );
    let notice = line("NOTICE ").unwrap_or_default();
    let stray = line("STRAY: ").unwrap_or_default();
    let frame = line("FRAME: ").unwrap_or_default();
    let after = line("AFTER: ").unwrap_or_default();
    let mut red = Vec::new();
    if !notice.starts_with("after") {
        red.push(format!(
            "{label}: the TUI's status line never said it was waiting: {notice}"
        ));
    }
    if stray.trim() != "no" {
        red.push(format!(
            "{label}: CLI text was written into the TUI's screen (stray = {stray})"
        ));
    }
    if !frame.starts_with("ok") {
        red.push(format!(
            "{label}: the TUI's box borders are broken: {frame}"
        ));
    }
    if !answer.iter().any(|w| after.contains(w)) {
        red.push(format!(
            "{label}: after the holder resumed, the TUI said {after:?}, expected one of {answer:?}"
        ));
    }
    red
}

#[test]
#[ignore = "`vox tui` in a pty with production Argon2id and the v0.2.9 release; needs pyte (VOX_PYTE_PATH); CI runs it in release"]
fn a_tui_waiting_for_the_profile_keeps_its_screen() {
    watchdog::arm_for(Duration::from_secs(if cfg!(debug_assertions) {
        1800
    } else {
        900
    }));
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
        d
    };
    let mut red = Vec::new();

    // ---- 1. create: `vox id` holds the lock, the TUI's first-run create waits ---------------
    red.extend(arm(
        "create",
        &dir("fresh"),
        "create",
        &["id"],
        &["another vox created this profile's identity at the same time"],
    ));

    // ---- 2. migration: `vox trust add` migrates a v0.2.9 profile, the TUI's unlock waits ------
    let old = previous_release();
    let (carol, x) = (dir("carol"), dir("x"));
    let run_old = |data: &Path, argv: &[&str]| {
        let out = Command::new(&old)
            .args(argv)
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", data.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .output()
            .expect("APPARATUS: run a process");
        assert!(
            out.status.success(),
            "APPARATUS (precondition not met): v0.2.9 `vox {argv:?}` failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    run_old(&carol, &["id"]);
    let x_fp = run_old(&x, &["id"]);
    red.extend(arm(
        "migration",
        &carol,
        "unlock",
        &["trust", "add", &x_fp, "--name", "x"],
        &["unlocked", "done", "another vox holds this profile open"],
    ));

    assert!(red.is_empty(), "PRODUCT: {red:#?}");
}
