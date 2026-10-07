//! A `vox` verb run as a person runs it at a terminal: under a pty, with the identity passphrase
//! typed at its prompt. **A keyring change takes its passphrase from nothing else** (ADR-028 K-13):
//! not `VOX_IDENTITY_PASSPHRASE`, not a file. So a proof that trusts, untrusts or renames someone
//! as part of its staging does it here, as the person at the keyboard would.
//!
//! The pty is a `python3` `os.forkpty` (no third-party module). The passphrase reaches the driver
//! on its stdin, never in its environment or argv, which the `vox` it starts would inherit or show.
//!
//! Included with `#[path]` by a proof, or by a support module, which is why not every item is used
//! by every includer.

#![allow(dead_code)]

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

/// How long a typed verb may take, end to end: past it the driver kills `vox` and says so.
pub const BOUND: Duration = Duration::from_secs(120);

/// The driver: reads the passphrase on stdin, runs the verb under a pty, types the passphrase at
/// the first prompt that asks for one, and prints everything the terminal showed, then
/// `TYPED-EXIT <code> PROMPTED <True|False>`.
const DRIVER: &str = r#"
import os, select, signal, sys, time
bound = float(sys.argv[1])
argv = sys.argv[2:]
secret = sys.stdin.readline().rstrip("\n").encode()
pid, fd = os.forkpty()
if pid == 0:
    os.execv(argv[0], argv)
out, sent, deadline, killed = b"", False, time.time() + bound, False
while True:
    if time.time() > deadline and not killed:
        os.kill(pid, signal.SIGKILL)
        killed = True
    r, _, _ = select.select([fd], [], [], 0.2)
    if not r:
        if killed:
            break
        continue
    try:
        d = os.read(fd, 4096)
    except OSError:
        break
    if not d:
        break
    out += d
    if not sent and out.rstrip().endswith(b"passphrase:"):
        time.sleep(0.5)  # as a person reads the prompt: never before its terminal is raw
        os.write(fd, secret + b"\r")
        sent = True
_, st = os.waitpid(pid, 0)
sys.stdout.write(out.decode("utf-8", "replace"))
code = os.waitstatus_to_exitcode(st)
sys.stdout.write("\nTYPED-EXIT %d PROMPTED %s%s\n" % (code, sent, " KILLED" if killed else ""))
"#;

/// Whether `args` (a `vox` command line, without the program) is a keyring change: `vox trust
/// add`, `remove`, `rename`, `drive` or `read`.
pub fn is_keyring_change<S: AsRef<str>>(args: &[S]) -> bool {
    args.iter()
        .position(|a| a.as_ref() == "trust")
        .and_then(|i| args.get(i + 1))
        .is_some_and(|v| matches!(v.as_ref(), "add" | "remove" | "rename" | "drive" | "read"))
}

/// Run `cmd`, a `vox` command, at a terminal, typing `passphrase` if it asks for one: whether it
/// succeeded, and everything the terminal showed (stdout and stderr together, as a person sees
/// them). `VOX_IDENTITY_PASSPHRASE` is taken out of its environment: a person types it.
pub fn typed(cmd: &Command, passphrase: &str) -> (bool, String) {
    let mut child = driver(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start the pty driver (python3): {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: the pty driver's stdin")
        .write_all(format!("{passphrase}\n").as_bytes())
        .unwrap_or_else(|e| panic!("APPARATUS: cannot give the pty driver the passphrase: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: the pty driver: {e}"));
    let shown = String::from_utf8_lossy(&out.stdout).into_owned();
    let Some(tail) = shown.lines().rev().find(|l| l.starts_with("TYPED-EXIT ")) else {
        panic!(
            "APPARATUS: the pty driver ended without saying how vox ended ({}): {}\n{shown}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    if tail.ends_with("KILLED") {
        panic!(
            "PRODUCT: `vox {:?}` at a terminal was still running after {BOUND:?}; it showed:\n{shown}",
            cmd.get_args().collect::<Vec<_>>()
        );
    }
    let ok = tail.starts_with("TYPED-EXIT 0 ");
    // What the terminal showed, without the driver's own last line.
    let shown = shown
        .rsplit_once("\nTYPED-EXIT ")
        .map_or(shown.as_str(), |(before, _)| before)
        .to_owned();
    (ok, shown)
}

/// [`typed`], started and left running: the driver's process, whose stdout carries what the
/// terminal shows and then `TYPED-EXIT <code> …` once `vox` ends. For a proof that watches the
/// verb while it runs.
pub fn spawn(cmd: &Command, passphrase: &str) -> std::process::Child {
    let mut py = driver(cmd);
    let mut child = py
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start the pty driver (python3): {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: the pty driver's stdin")
        .write_all(format!("{passphrase}\n").as_bytes())
        .unwrap_or_else(|e| panic!("APPARATUS: cannot give the pty driver the passphrase: {e}"));
    child
}

/// The driver's command for `cmd`.
fn driver(cmd: &Command) -> Command {
    let mut py = Command::new("python3");
    py.arg("-c")
        .arg(DRIVER)
        .arg(BOUND.as_secs().to_string())
        .arg(cmd.get_program())
        .args(cmd.get_args());
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => py.env(k, v),
            None => py.env_remove(k),
        };
    }
    py.env_remove("VOX_IDENTITY_PASSPHRASE");
    if let Some(dir) = cmd.get_current_dir() {
        py.current_dir(dir);
    }
    py
}

/// A keyring change as the proof wrote it — with the passphrase in `VOX_IDENTITY_PASSPHRASE` or
/// `--identity-passphrase-file` — run as a person runs it: those taken out, and the passphrase
/// typed at the prompt. Whether it succeeded, and what the terminal showed.
pub fn keyring(cmd: &Command) -> (bool, String) {
    let mut passphrase = cmd
        .get_envs()
        .find(|(k, _)| *k == "VOX_IDENTITY_PASSPHRASE")
        .and_then(|(_, v)| v)
        .map(|v| v.to_string_lossy().into_owned())
        .or_else(|| std::env::var("VOX_IDENTITY_PASSPHRASE").ok());
    let mut args = Vec::new();
    let mut given = cmd.get_args();
    while let Some(a) = given.next() {
        if a == "--identity-passphrase-file" {
            let file = given
                .next()
                .unwrap_or_else(|| panic!("APPARATUS: --identity-passphrase-file with no path"));
            let text = std::fs::read_to_string(file).unwrap_or_else(|e| {
                panic!("APPARATUS: cannot read the passphrase file {file:?}: {e}")
            });
            passphrase = Some(text.lines().next().unwrap_or_default().to_owned());
            continue;
        }
        args.push(a.to_os_string());
    }
    let mut person = Command::new(cmd.get_program());
    person.args(&args);
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => person.env(k, v),
            None => person.env_remove(k),
        };
    }
    if let Some(dir) = cmd.get_current_dir() {
        person.current_dir(dir);
    }
    let passphrase = passphrase.unwrap_or_else(|| {
        panic!("APPARATUS: a keyring change staged with no identity passphrase to type: {args:?}")
    });
    typed(&person, &passphrase)
}
