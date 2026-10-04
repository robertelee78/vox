//! **A passphrase is asked for where it can be, and refused at once where it cannot** — driven
//! through the shipped binary, as a person and as an agent's harness run it. Run on demand.
//!
//! ## A `vox daemon` started in a terminal (V210-153)
//! [`a_daemon_on_a_terminal_serves_after_the_passphrase`]: `vox daemon` on a pty asks for the
//! identity passphrase without echoing it, and serves once it is typed, with the terminal still
//! open: no end of input is needed. It read stdin to its end first, so it served only after
//! Ctrl-D, and echoed the passphrase as it was typed. Then a SIGHUP stops it cleanly.
//!
//! [`a_stop_before_a_daemon_serves_is_clean`]: SIGINT, SIGTERM, SIGHUP or SIGQUIT while it waits at
//! the prompt stops it cleanly — `stopped by SIG<x>`, status 0 — with the terminal's echo back on.
//! The handler was installed after the read, so each took its default action and the daemon died
//! saying nothing: closing the terminal killed it uncleanly, against the ruling that SIGHUP is
//! always a clean stop (decider, 2026-09-30).
//!
//! [`closing_the_terminal_before_a_daemon_serves_is_a_clean_stop`]: closing the terminal itself at
//! the prompt, a real hangup, is a clean stop too. The read ends at the moment the SIGHUP is sent,
//! and the empty line won: 11 of 13 closes exited 1 with "no identity passphrase".
//!
//! Mutations: the end-of-input wait restored for a terminal — red, PRODUCT (it never serves); the
//! signal handler installed after the wait — red, PRODUCT (killed by the signal); no wait for the
//! hangup's signal once the terminal's input ends — red, PRODUCT (exit 1, "no identity
//! passphrase").
//!
//! ## No command waits silently for input it cannot get (V210-165)
//! [`no_command_waits_for_input_it_cannot_get`]: with stdin open, nothing written to it and no
//! terminal — an agent's harness — every command that needs a passphrase it has not been given
//! fails at once, saying what it needs and how to give it; `vox trust list`, a read, succeeds
//! against the running node with no passphrase; and a `vox daemon` given its identity passphrase in
//! `VOX_IDENTITY_PASSPHRASE` serves without reading stdin. `vox trust add` waited over three
//! minutes there, saying nothing, and `vox trust list` demanded the passphrase.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity pass phrase";

/// How long a daemon given its passphrase may take to serve: an unlock is one Argon2id run.
const SERVES_WITHIN: Duration = Duration::from_secs(30);
/// How long a stop may take to end a daemon that is not yet serving: nothing is running.
const STOPS_WITHIN: Duration = Duration::from_secs(10);
/// How long a command that cannot get what it needs may take to say so. "At once": the defect
/// waited over three minutes.
const FAILS_WITHIN: Duration = Duration::from_secs(10);

/// A `vox` command for the profile at `dir`, with nothing of the caller's `VOX_*` passed on.
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

/// A profile with an identity, made with the passphrase in the environment.
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
    let fp = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (dir, fp)
}

/// `vox daemon` on a pty of its own, as its controlling terminal: what a person gets by typing it.
struct OnTerminal {
    child: Child,
    /// The controlling side: typed on, and read for what the daemon drew.
    keys: std::fs::File,
    shown: Arc<Mutex<Vec<u8>>>,
}

/// `vox daemon` on a new pty as its controlling terminal, as a shell gives it; what it writes goes
/// to `output` if given, else to the pty. Returns it and the pty's controlling side.
fn daemon_on_a_pty(dir: &Path, output: Option<&Path>) -> (Child, std::fs::File) {
    use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
    let apparatus = |what: &str, e: &dyn std::fmt::Debug| -> ! {
        panic!("CANNOT MEASURE: setting up the pty: {what}: {e:?}")
    };
    let controller =
        openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap_or_else(|e| apparatus("openpt", &e));
    // Not inherited by the daemon or by any other child: a daemon holding its own terminal's
    // controlling side open never sees that terminal close.
    rustix::io::fcntl_setfd(&controller, rustix::io::FdFlags::CLOEXEC)
        .unwrap_or_else(|e| apparatus("close-on-exec on the pty", &e));
    grantpt(&controller).unwrap_or_else(|e| apparatus("grantpt", &e));
    unlockpt(&controller).unwrap_or_else(|e| apparatus("unlockpt", &e));
    let name = ptsname(&controller, Vec::new()).unwrap_or_else(|e| apparatus("ptsname", &e));
    let name = name
        .to_str()
        .unwrap_or_else(|e| apparatus("the pty's name", &e))
        .to_owned();
    let open = || -> OwnedFd {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .unwrap_or_else(|e| apparatus("open the pty", &e))
            .into()
    };
    let mut cmd = vox_cmd(dir, &["daemon", "--listen", "127.0.0.1:0"]);
    cmd.stdin(Stdio::from(open()));
    if let Some(output) = output {
        let file = std::fs::File::create(output)
            .unwrap_or_else(|e| apparatus("create the output file", &e));
        let again = file
            .try_clone()
            .unwrap_or_else(|e| apparatus("the output file", &e));
        cmd.stdout(Stdio::from(file)).stderr(Stdio::from(again));
    } else {
        cmd.stdout(Stdio::from(open())).stderr(Stdio::from(open()));
    }
    // Its own session, with the pty as its controlling terminal, as a shell gives it.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
            rustix::process::setsid()?;
            // Descriptor 0, the pty: no allocation between fork and exec.
            rustix::process::ioctl_tiocsctty(std::os::fd::BorrowedFd::borrow_raw(0))?;
            Ok(())
        });
    }
    let child = cmd
        .spawn()
        .unwrap_or_else(|e| apparatus("spawn vox daemon on the pty", &e));
    (child, std::fs::File::from(controller))
}

impl OnTerminal {
    fn start(dir: &Path) -> Self {
        let apparatus = |what: &str, e: &dyn std::fmt::Debug| -> ! {
            panic!("CANNOT MEASURE: setting up the pty: {what}: {e:?}")
        };
        let (child, mut screen) = daemon_on_a_pty(dir, None);
        let keys = screen
            .try_clone()
            .unwrap_or_else(|e| apparatus("the pty, to type on", &e));
        let shown = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&shown);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = screen.read(&mut buf) {
                if n == 0 {
                    break;
                }
                into.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Self { child, keys, shown }
    }

    fn shown(&self) -> String {
        String::from_utf8_lossy(&self.shown.lock().unwrap()).into_owned()
    }

    /// Wait up to `within` for `text` on the terminal; whether it came.
    fn until_shown(&mut self, text: &str, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if self.shown().contains(text) {
                return true;
            }
            if self.child.try_wait().ok().flatten().is_some() {
                std::thread::sleep(Duration::from_millis(200));
                return self.shown().contains(text);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// Whether the terminal echoes what is typed now.
    fn echoes(&self) -> bool {
        let modes = rustix::termios::tcgetattr(&self.keys)
            .expect("CANNOT MEASURE: reading the pty's modes");
        modes
            .local_modes
            .contains(rustix::termios::LocalModes::ECHO)
    }

    fn signal(&self, sig: rustix::process::Signal) {
        let pid = rustix::process::Pid::from_child(&self.child);
        rustix::process::kill_process(pid, sig).expect("APPARATUS: signalling the daemon");
    }

    /// Its exit within `within`, or `None` (it is then killed, by its pid).
    fn exit_within(&mut self, within: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Some(s) = self.child.try_wait().expect("APPARATUS: wait") {
                std::thread::sleep(Duration::from_millis(200));
                return Some(s);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        None
    }
}

impl Drop for OnTerminal {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn a_daemon_on_a_terminal_serves_after_the_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let (dir, _) = profile(tmp.path(), "alice");
    let mut d = OnTerminal::start(&dir);
    assert!(
        d.until_shown("identity passphrase:", STOPS_WITHIN),
        "PRODUCT: `vox daemon` on a terminal did not ask for the identity passphrase within \
         {STOPS_WITHIN:?}. Its terminal:\n{}",
        d.shown()
    );
    d.keys
        .write_all(format!("{IDPASS}\n").as_bytes())
        .expect("APPARATUS: typing on the pty");
    let typed = Instant::now();
    let served = d.until_shown("control socket", SERVES_WITHIN);
    let shown = d.shown();
    assert!(
        served,
        "PRODUCT: a passphrase typed at `vox daemon`'s prompt did not get it serving within \
         {SERVES_WITHIN:?}, with the terminal still open. Its terminal:\n{shown}"
    );
    eprintln!(
        "serving {:.2}s after the passphrase was typed",
        typed.elapsed().as_secs_f64()
    );
    assert!(
        !shown.contains(IDPASS),
        "PRODUCT: the passphrase was echoed on the terminal as it was typed:\n{shown}"
    );
    d.signal(rustix::process::Signal::HUP);
    let status = d.exit_within(STOPS_WITHIN);
    let shown = d.shown();
    assert!(
        status.is_some_and(|s| s.code() == Some(0)) && shown.contains("stopped by SIGHUP"),
        "PRODUCT: a serving daemon did not stop cleanly on SIGHUP (status {status:?}). Its \
         terminal:\n{shown}"
    );
}

#[test]
fn a_stop_before_a_daemon_serves_is_clean() {
    watchdog::arm();
    use rustix::process::Signal;
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let (dir, _) = profile(tmp.path(), "alice");
    let mut reds = Vec::new();
    for (sig, name) in [
        (Signal::INT, "SIGINT"),
        (Signal::TERM, "SIGTERM"),
        (Signal::HUP, "SIGHUP"),
        (Signal::QUIT, "SIGQUIT"),
    ] {
        let mut d = OnTerminal::start(&dir);
        assert!(
            d.until_shown("identity passphrase:", STOPS_WITHIN),
            "PRODUCT: `vox daemon` on a terminal did not ask for the identity passphrase. Its \
             terminal:\n{}",
            d.shown()
        );
        let quiet = !d.echoes();
        d.signal(sig);
        let status = d.exit_within(STOPS_WITHIN);
        let shown = d.shown();
        let echo_back = d.echoes();
        eprintln!(
            "{name} at the prompt: status {status:?}, echo off at the prompt {quiet}, back on \
             after {echo_back}"
        );
        if !(status.is_some_and(|s| s.code() == Some(0))
            && shown.contains(&format!("stopped by {name}"))
            && echo_back)
        {
            reds.push(format!(
                "{name}: status {status:?}, echo back on {echo_back}; its terminal:\n{shown}"
            ));
        }
    }
    assert!(
        reds.is_empty(),
        "PRODUCT: a stop while `vox daemon` waited for its passphrase was not a clean stop \
         (\"stopped by SIG<x>\", status 0, echo back on):\n{}",
        reds.join("\n")
    );
}

/// How many times the terminal is closed at the prompt. The defect was a race the end of input
/// won 11 times in 13, so five closes all lose it to the defect only rarely.
const HANGUPS: usize = 5;

#[test]
fn closing_the_terminal_before_a_daemon_serves_is_a_clean_stop() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let (dir, _) = profile(tmp.path(), "alice");
    let mut reds = Vec::new();
    for run in 0..HANGUPS {
        // What it says goes to a file: the terminal it would say it on is the one being closed.
        let out = tmp.path().join(format!("hangup-{run}.out"));
        let (mut child, terminal) = daemon_on_a_pty(&dir, Some(&out));
        let said = || std::fs::read_to_string(&out).unwrap_or_default();
        let deadline = Instant::now() + STOPS_WITHIN;
        while !said().contains("identity passphrase:") && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            said().contains("identity passphrase:"),
            "PRODUCT: `vox daemon` on a terminal did not ask for the identity passphrase. It \
             said:\n{}",
            said()
        );
        std::thread::sleep(Duration::from_millis(300));
        // The person closes the terminal: its controlling side goes, and the session's hangup
        // with it.
        drop(terminal);
        let deadline = Instant::now() + STOPS_WITHIN;
        let status = loop {
            if let Some(s) = child.try_wait().expect("APPARATUS: wait") {
                break Some(s);
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let said = said();
        eprintln!("terminal closed at the prompt, run {run}: status {status:?}; said {said:?}");
        if !(status.is_some_and(|s| s.code() == Some(0)) && said.contains("stopped by SIGHUP")) {
            reds.push(format!("run {run}: status {status:?}; it said:\n{said}"));
        }
    }
    assert!(
        reds.is_empty(),
        "PRODUCT: closing the terminal while `vox daemon` waited for its passphrase was not a \
         clean stop (\"stopped by SIGHUP\", status 0) in {} of {HANGUPS} runs:\n{}",
        reds.len(),
        reds.join("\n")
    );
}

/// A command run with stdin open and nothing written to it, and no terminal: an agent's harness.
/// Returns whether it succeeded, what it said, and how long it took; `None` if it was still
/// running after [`FAILS_WITHIN`] (it is then killed, by its pid).
fn as_a_harness(cmd: &mut Command) -> Option<(bool, String, Duration)> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // No controlling terminal: a session of its own.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(cmd, || {
            rustix::process::setsid()?;
            Ok(())
        });
    }
    let t0 = Instant::now();
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox");
    // Held open, unwritten, until the command has ended.
    let held = child.stdin.take();
    while t0.elapsed() < FAILS_WITHIN {
        if child.try_wait().expect("APPARATUS: wait").is_some() {
            drop(held);
            let out = child.wait_with_output().expect("APPARATUS: output");
            let said = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return Some((out.status.success(), said, t0.elapsed()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
fn no_command_waits_for_input_it_cannot_get() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let (alice, _) = profile(tmp.path(), "alice");
    let (bob, bob_fp) = profile(tmp.path(), "bob");

    // Alice's daemon, as a harness starts it: the passphrase in the environment, stdin open and
    // never written. It must serve without waiting for stdin to close.
    let mut daemon = vox_cmd(&alice, &["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let _held = daemon.stdin.take();
    let out = daemon.stdout.take().expect("APPARATUS: daemon stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut out = std::io::BufReader::new(out);
        let mut line = String::new();
        while std::io::BufRead::read_line(&mut out, &mut line).is_ok_and(|n| n > 0) {
            let _ = tx.send(std::mem::take(&mut line));
        }
    });
    let started = Instant::now();
    let mut said = String::new();
    while !said.contains("control socket") && started.elapsed() < SERVES_WITHIN {
        if let Ok(l) = rx.recv_timeout(Duration::from_millis(100)) {
            said.push_str(&l);
        }
    }
    let serving = said.contains("control socket");
    if !serving {
        let _ = daemon.kill();
    }
    assert!(
        serving,
        "PRODUCT: a `vox daemon` given VOX_IDENTITY_PASSPHRASE, with stdin open, did not serve \
         within {SERVES_WITHIN:?}. It said:\n{said}"
    );

    let mut reds = Vec::new();
    let mut check = |what: &str, cmd: &mut Command, should_succeed: bool, says: &[&str]| {
        match as_a_harness(cmd) {
            None => reds.push(format!(
                "{what}: still waiting after {FAILS_WITHIN:?}, saying nothing"
            )),
            Some((ok, said, took)) => {
                eprintln!(
                    "{what}: {} in {:.2}s: {}",
                    if ok { "ok" } else { "refused" },
                    took.as_secs_f64(),
                    said.trim()
                );
                if ok != should_succeed || !says.iter().all(|s| said.contains(s)) {
                    reds.push(format!(
                        "{what}: {} in {took:?}, expected {} saying {says:?}; it said:\n{said}",
                        if ok { "succeeded" } else { "failed" },
                        if should_succeed {
                            "success"
                        } else {
                            "a failure"
                        },
                    ));
                }
            }
        }
    };
    // Against the running node.
    check(
        "vox trust list (running node)",
        &mut vox_cmd(&alice, &["trust", "list"]),
        true,
        &[],
    );
    check(
        "vox room join (running node)",
        &mut vox_cmd(&alice, &["room", "join", "vox://not-read", "--name", "r"]),
        false,
        &["no terminal to ask at", "--passphrase-file"],
    );
    check(
        "vox room create (running node)",
        &mut vox_cmd(&alice, &["room", "create", "--name", "r"]),
        false,
        &["no terminal to ask at", "--passphrase-file"],
    );
    // With no node attached (ADR-026 L-2, S-3): `vox id` reads the public fingerprint from the
    // node's files and needs no passphrase; the one-shot verbs refuse at once, saying how to attach
    // the node, and never open it themselves.
    check(
        "vox id (no node)",
        &mut vox_cmd(&bob, &["id"]),
        true,
        &[bob_fp.as_str()],
    );
    for (what, args) in [
        ("vox trust list (no node)", vec!["trust", "list"]),
        (
            "vox trust add (no node)",
            vec!["trust", "add", &bob_fp, "--name", "x"],
        ),
        (
            "vox service add",
            vec!["service", "add", "aaaa", "ssh", "127.0.0.1:22"],
        ),
    ] {
        check(what, &mut vox_cmd(&bob, &args), false, &["vox node attach"]);
    }
    // `vox connect` asks for the room's passphrase first.
    check(
        "vox connect",
        &mut vox_cmd(&bob, &["connect", "vox://not-read"]),
        false,
        &["no terminal to ask at", "--passphrase-file"],
    );
    // A passphrase given changes nothing for a one-shot verb: it never attaches its node, so it
    // reads none and refuses at once, saying how to attach it (ADR-026 L-2).
    check(
        "vox service add (identity given, no node attached)",
        vox_cmd(&bob, &["service", "add", "aaaa", "ssh", "127.0.0.1:22"])
            .env("VOX_IDENTITY_PASSPHRASE", IDPASS),
        false,
        &["vox node attach"],
    );
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert!(
        reds.is_empty(),
        "PRODUCT: with stdin open and no terminal, a command waited for input it cannot get, or \
         said nothing of how to give it, or a read demanded a passphrase:\n{}",
        reds.join("\n\n")
    );
}
