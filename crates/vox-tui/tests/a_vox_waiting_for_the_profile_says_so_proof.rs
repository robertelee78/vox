//! V210-100 (#296), on the daemon (ADR-026, #409) — **a vox that waits says what it waits for,
//! where its user sees it, and nothing waits silently or for ever**, through the shipped binary.
//!
//! Under ADR-026 two things can make a vox wait, and both are staged here with a holder that is
//! stopped (Ctrl-Z, SIGSTOP) while it holds what the other needs:
//! - **a node's directory**, held while its identity is made (C-5: in the client, `vox id` or the
//!   TUI's first-run prompt). Another vox making the same node's identity waits for it;
//! - **the daemon itself**, while it attaches a node (L-2): it takes a client's connection and
//!   greets only once it can. A client waits for its greeting.
//!
//! Claimed of the vox that waits:
//! - **It says so, once, after a second**: a CLI verb on stderr; `vox tui` in its own status line
//!   when it waits inside the screen, and on the terminal, as a CLI verb does, when it waits before
//!   it takes the screen — never on stderr across its screen.
//! - It waits; it does not fail while the holder is stopped (within its bound).
//! - **The holder goes first**, and then the waiter answers: a creation the holder made is named
//!   (`another vox created this node's identity at the same time`), a request is served.
//! - **Past its bound it stops, saying so truthfully**: that another vox is still using the node's
//!   directory and how to find it (`lsof`, which names the holder), never to stop a node — the
//!   holder may only be slow or stopped.
//!
//! Staging, per arm: vox A takes what B needs and holds it (`VOX_TEST_LOCK_HOLD_MS`, proof-only,
//! inert when unset, says when it has the lock), and is stopped with SIGSTOP by its PID; vox B
//! starts; A is resumed with SIGCONT. Five arms:
//! 1. **CLI, create**: two `vox id`s on a fresh data root. B says it waits for the node's
//!    directory; once A has made the identity, B is refused, naming the concurrent creation.
//! 2. **CLI, daemon**: `vox daemon` (A) attaches a node this build made, and is stopped holding
//!    it; `vox trust add` (B) says it waits for the daemon, and once A is resumed is served: B
//!    exits 0, `vox trust list` names the trusted identity, and A, stopped afterwards, exits 0.
//! 3. **TUI, create** (`tests/pty/tui_lock_wait.py`): `vox id` holds the node's directory, `vox
//!    tui` is given a passphrase at its first-run prompt and says it waits in its status line; then
//!    names the concurrent creation.
//! 4. **TUI, daemon**: as arm 2, with `vox tui` as B. It waits for the daemon before it takes
//!    the screen and says so on the terminal; once A is resumed the TUI starts, its screen clean,
//!    and shows its node attached (given the passphrase at its attach prompt if asked).
//! 5. **CLI, past the patience**: two `vox id`s; A stays stopped until B gives up. B is refused
//!    saying another vox is still using the node's directory, not "Stop that node", and `lsof` on
//!    the directory it names lists A's PID. A, resumed, exits 0.
//!
//! Every red names its side: a PRODUCT verdict quotes what the product said or drew; a vox step
//! of the staging that failed (A never said it holds the lock, `vox id` for arm 5, the TUI driver
//! saying the TUI failed or hung) is PRODUCT (staging); only the proof's own machinery (a signal
//! that could not be sent, `lsof` that would not run, a driver that stopped for any other reason)
//! is APPARATUS, CANNOT MEASURE.
//!
//! Mutations that must turn it red: the notice removed (B waits in silence, arms 1–4: the client's
//! `create_noting` given no notice, or `open_noting` given none); the notice written to stderr while
//! the TUI draws (arm 3: CLI text on the TUI's screen).

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// B must say it is waiting within this of starting (its own start-up, then the one-second
/// patience).
const SAYS_WITHIN: Duration = Duration::from_secs(15);
/// How long A stays stopped once B has said so: B must still be waiting at the end of it.
const STOPPED_FOR: Duration = Duration::from_secs(5);
/// Both must finish within this of A being resumed (production Argon2id, in a debug build too).
const FINISHES_WITHIN: Duration = Duration::from_secs(240);
/// How long A holds the lock once it has it, so it can be stopped holding it.
const HOLD_MS: &str = "4000";
const HOLDING: &str = "holding the node lock";
const WAITING: &str = "waiting: another vox holds this node open";
/// What a client says while the daemon has not greeted it.
const DAEMON_WAITING: &str = "waiting: the vox daemon here has not answered yet";
const CONCURRENT: &str = "another vox created this node's identity at the same time";
/// What B says when A has not finished in all the time B waits (arm 5).
const STILL_USING: &str = "another vox is still using this node's directory";
/// What B points to, to find A: `lsof` on the profile directory.
const FIND_IT: &str = "To see which process it is: lsof ";
/// The remedy for a holder that serves the profile (a daemon or a TUI): wrong for one that is
/// only slow or stopped.
const STOP_THAT_NODE: &str = "Stop that node";
/// How long B may take to be refused when A never lets go: the 30 s patience, B's own start-up,
/// and room for an ordinary load.
const REFUSED_WITHIN: Duration = Duration::from_secs(120);

fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(
        ok,
        "APPARATUS, CANNOT MEASURE: could not send {sig} to vox A (pid {pid}), so the staging \
         (A stopped holding the lock) did not happen"
    );
}

/// Start A, wait until it holds the lock, and stop it there. Its process and PID.
fn hold_and_stop(label: &str, data: &Path, a_args: &[&str]) -> (VoxProc, u32) {
    test_knobs::require(&["VOX_TEST_LOCK_HOLD_MS"]);
    let mut a = VoxProc::spawn_env(
        &format!("{label} A"),
        data,
        &args(a_args),
        &[("VOX_TEST_LOCK_HOLD_MS", HOLD_MS)],
    );
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut held = false;
    while !held && Instant::now() < deadline {
        match a.lines.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                eprintln!("[{label} A] {line}");
                held = line.contains(HOLDING);
                a.seen.push(line);
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    assert!(
        held,
        "PRODUCT (staging): vox A never said it holds the profile lock, so nothing below would \
         wait on it; A said:\n{}",
        a.transcript()
    );
    let pid = a.child.id();
    signal(pid, "-STOP");
    (a, pid)
}

/// Wait until `p` exits or `deadline` passes: its status and when it was seen to exit.
fn exit_of(p: &mut VoxProc, deadline: Instant) -> Option<(ExitStatus, Instant)> {
    loop {
        if let Some(s) = p.child.try_wait().expect("APPARATUS: poll a child process") {
            return Some((s, Instant::now()));
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Both A and B, polled together so each one's exit time is when it exited.
fn exits(a: &mut VoxProc, b: &mut VoxProc) -> [Option<(ExitStatus, Instant)>; 2] {
    let deadline = Instant::now() + FINISHES_WITHIN;
    let (mut ea, mut eb) = (None, None);
    while (ea.is_none() || eb.is_none()) && Instant::now() < deadline {
        if ea.is_none() {
            ea = a
                .child
                .try_wait()
                .expect("APPARATUS: poll a child process")
                .map(|s| (s, Instant::now()));
        }
        if eb.is_none() {
            eb = b
                .child
                .try_wait()
                .expect("APPARATUS: poll a child process")
                .map(|s| (s, Instant::now()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    [ea, eb]
}

/// What a CLI arm expects once A is resumed.
enum Then {
    /// A made the identity; B is refused, naming the concurrent creation.
    ARefusesB,
    /// A is a daemon: B exits 0 once A is resumed, and A, stopped then, exits 0.
    DaemonServesB,
}

/// A CLI arm: A holds the lock and is stopped, B waits; then A is resumed.
fn cli_arm(
    label: &str,
    data: &Path,
    a_args: &[&str],
    b_args: &[&str],
    waiting: &str,
    then: &Then,
) -> Vec<String> {
    let (mut a, a_pid) = hold_and_stop(label, data, a_args);
    let t0 = Instant::now();
    let mut b = VoxProc::spawn(&format!("{label} B"), data, &args(b_args));
    // Not `expect_within`: a B that says nothing must be a product red, not a timeout panic.
    let mut said_at = None;
    while t0.elapsed() < SAYS_WITHIN && said_at.is_none() {
        if let Ok(line) = b.lines.recv_timeout(Duration::from_millis(100)) {
            eprintln!("[{label} B] {line}");
            if line.contains(waiting) {
                said_at = Some(t0.elapsed());
            }
            b.seen.push(line);
        }
    }
    std::thread::sleep(STOPPED_FOR);
    let b_still_waiting = b
        .child
        .try_wait()
        .expect("APPARATUS: poll a child process")
        .is_none();
    let waited = t0.elapsed();
    signal(a_pid, "-CONT");
    let resumed = Instant::now();
    if matches!(then, Then::DaemonServesB) {
        // A daemon runs until stopped: once B has its answer, A is asked to stop as a person would.
        let _ = exit_of(&mut b, resumed + FINISHES_WITHIN);
        signal(a_pid, "-TERM");
    }
    let [ea, eb] = exits(&mut a, &mut b);
    let b_said = b.transcript();
    let a_said = a.transcript();
    let notices = b_said.matches(waiting).count();
    let at = |e: &Option<(ExitStatus, Instant)>| {
        e.map(|(s, t)| format!("{s} at +{:.2}s", t.duration_since(resumed).as_secs_f64()))
    };
    println!(
        "[proof] {label}: A held the lock and was stopped; B said it was waiting after {said_at:?} \
         (bound {SAYS_WITHIN:?}), {notices} time(s); B still waiting after {waited:?} = \
         {b_still_waiting}; after SIGCONT: A {:?}, B {:?}",
        at(&ea),
        at(&eb)
    );
    let mut red = Vec::new();
    if said_at.is_none() {
        red.push(format!(
            "PRODUCT: {label}: B did not say it was waiting within {SAYS_WITHIN:?}; it said:\n{b_said}"
        ));
    }
    if notices > 1 {
        red.push(format!(
            "PRODUCT: {label}: B said it was waiting {notices} times:\n{b_said}"
        ));
    }
    if !b_still_waiting {
        red.push(format!(
            "PRODUCT: {label}: B exited while A was stopped, instead of waiting: {b_said}"
        ));
    }
    let (Some((sa, ta)), Some((sb, tb))) = (ea, eb) else {
        red.push(format!(
            "PRODUCT: {label}: not both finished {FINISHES_WITHIN:?} after SIGCONT: A {:?}, B {:?}",
            at(&ea),
            at(&eb)
        ));
        return red;
    };
    if !sa.success() {
        red.push(format!(
            "PRODUCT: {label}: A, which held the lock first, failed after it was resumed: {a_said}"
        ));
    }
    match then {
        Then::ARefusesB => {
            if sb.success() || !b_said.contains(CONCURRENT) {
                red.push(format!(
                    "PRODUCT: {label}: B did not refuse naming the concurrent creation ({sb}): \
                     {b_said}"
                ));
            }
        }
        Then::DaemonServesB => {
            if !sb.success() {
                red.push(format!(
                    "PRODUCT: {label}: B was not served once the daemon was resumed ({sb}): {b_said}"
                ));
            } else if ta < tb {
                red.push(format!(
                    "PRODUCT: {label}: the daemon ended before it served B ({:.2}s earlier)",
                    tb.duration_since(ta).as_secs_f64()
                ));
            }
        }
    }
    red
}

/// Arm 5: A holds the lock and stays stopped for longer than B waits. B is refused, saying that
/// another vox is still using the profile, never to stop a node (A serves no socket; it is only
/// stopped), and naming `lsof` on the profile directory, which then does name A. A, resumed, then
/// finishes its own command.
fn past_patience_arm(label: &str, data: &Path, a_args: &[&str], b_args: &[&str]) -> Vec<String> {
    let (mut a, a_pid) = hold_and_stop(label, data, a_args);
    let t0 = Instant::now();
    let mut b = VoxProc::spawn(&format!("{label} B"), data, &args(b_args));
    let eb = exit_of(&mut b, t0 + REFUSED_WITHIN);
    let b_said = b.transcript();
    // Read B's advice back before A is resumed, while A still holds the lock.
    let dir = b_said
        .lines()
        .find_map(|l| l.split_once(FIND_IT).map(|(_, d)| d.trim().to_owned()));
    let lsof = dir.as_ref().map(|d| {
        let out = Command::new("lsof").args(["-t", "--", d]).output();
        let out = out.unwrap_or_else(|e| {
            panic!("APPARATUS, CANNOT MEASURE: could not run `lsof {d}` as B advised: {e}")
        });
        String::from_utf8_lossy(&out.stdout).into_owned()
    });
    signal(a_pid, "-CONT");
    let ea = exit_of(&mut a, Instant::now() + FINISHES_WITHIN);
    let a_said = a.transcript();
    println!(
        "[proof] {label}: A held the lock and stayed stopped; B {:?} after {:.1}s; B pointed at          {dir:?}; `lsof` there listed {:?} (A is {a_pid}); A after SIGCONT: {:?}",
        eb.map(|(s, _)| s),
        eb.map_or(t0.elapsed(), |(_, t)| t.duration_since(t0))
            .as_secs_f64(),
        lsof.as_deref().map(str::split_whitespace).map(Iterator::collect::<Vec<_>>),
        ea.map(|(s, _)| s)
    );
    let mut red = Vec::new();
    match eb {
        None => red.push(format!(
            "PRODUCT: {label}: B was still waiting {REFUSED_WITHIN:?} after it started, with A \
             stopped holding the lock all along; it said:\n{b_said}"
        )),
        Some((sb, _)) if sb.success() => red.push(format!(
            "PRODUCT: {label}: B exited 0 while A was stopped holding the lock: {b_said}"
        )),
        Some(_) => {}
    }
    if eb.is_some() {
        if !b_said.contains(STILL_USING) {
            red.push(format!(
                "PRODUCT: {label}: B's refusal does not say {STILL_USING:?}: {b_said}"
            ));
        }
        if b_said.contains(STOP_THAT_NODE) {
            red.push(format!(
                "PRODUCT: {label}: B told its user to stop a node, and A is a stopped command \
                 that serves nothing: {b_said}"
            ));
        }
        match (&dir, &lsof) {
            (Some(d), Some(l)) => {
                if !l.split_whitespace().any(|p| p == a_pid.to_string()) {
                    red.push(format!(
                        "PRODUCT: {label}: B said to find the holder with `lsof {d}`, and that \
                         does not list A (pid {a_pid}); it listed {:?}",
                        l.trim()
                    ));
                }
            }
            _ => red.push(format!(
                "PRODUCT: {label}: B's refusal names no way to find the holder ({FIND_IT:?}): \
                 {b_said}"
            )),
        }
    }
    if !ea.is_some_and(|(s, _)| s.success()) {
        red.push(format!(
            "PRODUCT: {label}: A, resumed after B gave up, did not finish its command ({:?}): \
             {a_said}",
            ea.map(|(s, _)| s)
        ));
    }
    red
}

/// A TUI arm: A holds the lock and is stopped, `vox tui` waits on it (driven in a pty); then the
/// driver resumes A.
fn tui_arm(label: &str, data: &Path, mode: &str, a_args: &[&str], answer: &[&str]) -> Vec<String> {
    let (mut a, pid) = hold_and_stop(label, data, a_args);
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
    // The driver resumes A; make sure, then let it finish. A daemon runs until stopped: it is
    // asked to, as a person would.
    let _ = Command::new("kill")
        .args(["-CONT", &pid.to_string()])
        .status();
    if a_args.first() == Some(&"daemon") {
        signal(pid, "-TERM");
    }
    let ea = exit_of(&mut a, Instant::now() + FINISHES_WITHIN);
    let said = out.stdout.clone();
    println!(
        "[proof] {label}: the TUI driver took {:?}, exit {:?}, last stage {:?}; A {:?}\n{}",
        out.took,
        out.code,
        out.stage,
        ea.map(|(s, _)| s),
        said.trim()
    );
    let line = |p: &str| {
        said.lines()
            .find_map(|l| l.strip_prefix(&format!("{label} {p}")))
            .map(str::to_owned)
    };
    // The driver prints `<tag> RED: PRODUCT…` or `HUNG at` when `vox tui` failed (no prompt, no
    // answer, a wait that never ended): the product's, at staging. Anything else that stops it is
    // the driver's own machinery.
    let side = if said.contains(&format!("{label} RED: PRODUCT"))
        || said.contains(&format!("{label} HUNG at"))
    {
        "PRODUCT (staging)"
    } else {
        "APPARATUS"
    };
    let notice = line("NOTICE ").unwrap_or_default();
    let mut red = Vec::new();
    // **The claim first** (V210-100): whether the TUI said it was waiting is read before anything
    // that needs the rest of its run, so a TUI that waited in silence is a PRODUCT red that names
    // the missing notice, whatever happened after.
    if !notice.starts_with("after") {
        red.push(format!(
            "PRODUCT: {label}: the TUI never said it was waiting: {notice}"
        ));
    }
    // Collected, not panicked: the other arms' claims are reported too.
    if out.has_verdict(label) || out.code != Some(0) || line("AFTER:").is_none() {
        red.push(format!(
            "{side}: the {label} arm's TUI driver did not run to the end (exit {:?}, stage {:?}): \
             {said}",
            out.code, out.stage
        ));
        return red;
    }
    let stray = line("STRAY: ").unwrap_or_default();
    let frame = line("FRAME: ").unwrap_or_default();
    let after = line("AFTER: ").unwrap_or_default();
    if stray.trim() != "no" {
        red.push(format!(
            "PRODUCT: {label}: CLI text was written into the TUI's screen: {stray}"
        ));
    }
    if !frame.starts_with("ok") {
        red.push(format!(
            "PRODUCT: {label}: the TUI's box borders are broken: {frame}"
        ));
    }
    if !answer.iter().any(|w| after.contains(w)) {
        red.push(format!(
            "PRODUCT: {label}: after A resumed, the TUI said {after:?}, expected one of {answer:?}"
        ));
    }
    match ea {
        Some((s, _)) if s.success() => {}
        other => red.push(format!(
            "PRODUCT: {label}: A, which held the lock first, did not succeed after it was resumed \
             ({:?}): {}",
            other.map(|(s, _)| s),
            a.transcript()
        )),
    }
    red
}

#[test]
#[ignore = "real vox processes and `vox tui` in a pty, with production Argon2id; needs pyte (VOX_PYTE_PATH); CI runs it in release"]
fn a_vox_waiting_for_the_profile_says_so() {
    watchdog::arm_for(Duration::from_secs(if cfg!(debug_assertions) {
        2400
    } else {
        900
    }));
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
        d
    };
    // A node this build made, for the daemon to attach (arms 2 and 4).
    let made = |name: &str| -> PathBuf {
        let d = dir(name);
        let (ok, out, err) = vox_once(&d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): `vox id` failed: {out}{err}");
        d
    };
    let y_fp = {
        let (ok, out, err) = vox_once(&dir("y"), &args(&["id"]));
        assert!(ok, "PRODUCT (staging): `vox id` failed: {out}{err}");
        out.trim().to_owned()
    };
    let mut red = Vec::new();

    // ---- 1. CLI, create ---------------------------------------------------------------------
    red.extend(cli_arm(
        "cli-create",
        &dir("fresh-cli"),
        &["id"],
        &["id"],
        WAITING,
        &Then::ARefusesB,
    ));

    // ---- 2. CLI, daemon: the daemon attaches the node; B's `trust add` waits ----------------
    let carol = made("carol");
    red.extend(cli_arm(
        "cli-daemon",
        &carol,
        &["daemon", "--listen", "127.0.0.1:0"],
        &["trust", "add", &y_fp, "--name", "y"],
        DAEMON_WAITING,
        &Then::DaemonServesB,
    ));
    let (ok, listed, err) = vox_once(&carol, &args(&["trust", "list"]));
    println!(
        "[proof] cli-daemon: `vox trust list` afterwards: {}",
        listed.trim()
    );
    assert!(
        ok,
        "PRODUCT: cli-daemon: `vox trust list` afterwards failed: {listed}{err}"
    );
    if red.iter().all(|r| !r.contains("cli-daemon")) {
        for name in ["y"] {
            if !listed
                .lines()
                .any(|l| l.trim_end().ends_with(&format!("  {name}")))
            {
                red.push(format!(
                    "PRODUCT: cli-daemon: `trust add` exited 0, and `trust list` does not \
                     name {name}: {listed}"
                ));
            }
        }
    }

    // ---- 3. TUI, create ---------------------------------------------------------------------
    red.extend(tui_arm(
        "tui-create",
        &dir("fresh-tui"),
        "create",
        &["id"],
        &[CONCURRENT],
    ));

    // ---- 4. TUI, daemon --------------------------------------------------------------------
    red.extend(tui_arm(
        "tui-daemon",
        &made("dave"),
        "startup",
        &["daemon", "--listen", "127.0.0.1:0"],
        &["attached: default"],
    ));

    // ---- 5. CLI, past the patience: A never lets go while B waits ---------------------------
    red.extend(past_patience_arm(
        "cli-past-patience",
        &dir("erin"),
        &["id"],
        &["id"],
    ));

    assert!(red.is_empty(), "PRODUCT: {red:#?}");
}
