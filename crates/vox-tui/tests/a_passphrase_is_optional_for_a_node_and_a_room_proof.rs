//! **A passphrase is optional, for a node and for a room** (ADR-005 J-2, V030-36, restored by the
//! decider 2026-10-09: "passphrases are optional"; ADR-028 K-11 as amended) — proved with nothing
//! but the shipped `vox`: a `vox node` anchor and three `vox daemon`s, every step as an operator
//! types it.
//!
//! 1. A node is made with an empty identity passphrase, however it is given: `vox id` with
//!    `VOX_IDENTITY_PASSPHRASE` set to nothing, `vox node create` with an empty
//!    `--passphrase-file`, and `vox node create` at a terminal with Enter alone, twice. Each makes
//!    the identity and says once what it means: the key is kept on this machine unencrypted. With
//!    no terminal and no passphrase given, `vox node create` refuses, says how to give one in its
//!    own words (`--passphrase-file`), and leaves no `nodes/<name>/`. `vox node --help` says an
//!    empty one gives the node none. Bob's node has none: his daemon attaches it from an empty
//!    `--passphrase-file`, his trust change is typed as Enter alone, and he posts and reads in
//!    claim 4.
//! 2. `vox room create` makes a room with no passphrase (an empty line on `--passphrase-file -`),
//!    saying the line that encourages one.
//! 3. A join to that room with a wrong, non-empty passphrase is refused, naming the passphrase.
//! 4. A join with no passphrase (an empty `--passphrase-file`) gets in, and the two members read
//!    each other's posts both ways.
//!
//! Mutations: an empty identity passphrase refused again (`Profile::create_noting`) — red, PRODUCT
//! (claim 1); `node_create` resolving its paths before it has the passphrase (no terminal) — red,
//! PRODUCT (claim 1: `nodes/n/` left behind); the room's empty passphrase read as locked again
//! (`join_passphrase` refusing an empty one) — red, PRODUCT (claim 4: the join is refused).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;
#[path = "support/typed.rs"]
mod typed;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// A long-running `vox` child, killed however the test ends.
struct Proc {
    name: &'static str,
    child: Child,
    out: Option<BufReader<ChildStdout>>,
    /// Everything the child wrote to stderr, drained continuously — see `spawn`.
    err: Arc<Mutex<String>>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proc {
    fn spawn(
        name: &'static str,
        dir: &std::path::Path,
        args: &[String],
        stdin: Option<&str>,
    ) -> Self {
        let mut cmd = Command::new(VOX);
        cmd.args(args)
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env_remove("VOX_ROOM")
            // A harness session running this proof names its own node here; never this run's.
            .env_remove("VOX_NODE")
            .env_remove("VOX_IDENTITY_PASSPHRASE")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn {name}: {e}"));
        if let Some(text) = stdin {
            child
                .stdin
                .as_mut()
                .expect("APPARATUS: no stdin pipe")
                .write_all(text.as_bytes())
                .unwrap_or_else(|e| panic!("APPARATUS: cannot write {name}'s stdin: {e}"));
            drop(child.stdin.take());
        }
        let out = child.stdout.take().map(BufReader::new);
        // **stderr is piped, so it must be read.** It was piped and never read, which is a
        // 64 KiB fuse on the child: once the pipe buffer fills, the daemon blocks in `write` and
        // the proof sees a node that has stopped doing anything, with no failure and no output —
        // a hang, and bimodal in exactly the shape ADR-018 recorded for this gate's own flake.
        // `vox daemon` now reports every event that explains a failure, so it writes more than it
        // used to and this fuse got shorter, not longer. Drained on a thread into a string the
        // panic below prints, so the bytes that were the hazard become the diagnosis.
        let err = Arc::new(Mutex::new(String::new()));
        if let Some(mut pipe) = child.stderr.take() {
            let sink = Arc::clone(&err);
            std::thread::spawn(move || {
                let mut buf = String::new();
                let _ = pipe.read_to_string(&mut buf);
                if let Ok(mut guard) = sink.lock() {
                    guard.push_str(&buf);
                }
            });
        }
        Self {
            name,
            child,
            out,
            err,
        }
    }

    /// Wait for a line matching `want`, so readiness is observed rather than slept on.
    fn expect_line(&mut self, what: &str, want: impl Fn(&str) -> bool) -> String {
        let reader = self.out.as_mut().expect("APPARATUS: no stdout pipe");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let mut seen = Vec::new();
        while std::time::Instant::now() < deadline {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let l = line.trim_end().to_owned();
                    if want(&l) {
                        return l;
                    }
                    seen.push(l);
                }
                Err(_) => break,
            }
        }
        let err = self
            .err
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone());
        panic!(
            "PRODUCT (staging): {} never printed {what}; saw: {seen:#?}\nits stderr:\n{err}",
            self.name
        );
    }
}

/// One `vox` command, run to completion.
/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox(dir: &std::path::Path, args: &[String], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = args.iter().map(String::as_str).collect();
    let pass = identity_of(dir);
    match attach::needs(dir, &verb) {
        Some(node) => {
            attach::Root::at(dir, pass).attached(&node, || vox_as(dir, args, stdin, pass))
        }
        None => vox_as(dir, args, stdin, pass),
    }
}

/// The identity passphrase of the node in `dir`: Bob's node has none (claim 1), every other one
/// [`PASS`].
fn identity_of(dir: &std::path::Path) -> &'static str {
    if dir.ends_with("bob") {
        ""
    } else {
        PASS
    }
}

/// The identity passphrase every node here is made and unlocked with.
const PASS: &str = "an identity passphrase";

/// One `vox` command with `VOX_IDENTITY_PASSPHRASE` set to `identity`.
fn vox_as(
    dir: &std::path::Path,
    args: &[String],
    stdin: Option<&str>,
    identity: &str,
) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", identity)
        .env_remove("VOX_ROOM")
        // A harness session running this proof names its own node here; never this run's.
        .env_remove("VOX_NODE")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        let (ok, shown) = typed::keyring(&cmd);
        return (ok, shown.clone(), shown);
    }
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox: {e}"));
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: no stdin pipe")
            .write_all(text.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write vox's stdin: {e}"));
        drop(child.stdin.take());
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot wait for vox: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Poll a command until its stdout satisfies `ok`.
fn until(
    dir: &std::path::Path,
    what: &str,
    args: &[String],
    secs: u64,
    ok: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let (_, out, err) = vox(dir, args, None);
        last = format!("stdout={out:?} stderr={err:?}");
        if ok(&out) {
            return Ok(out);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(format!("timed out waiting for {what}; last saw {last}"))
}

/// The line the CLI says when a room passphrase is left empty.
const ENCOURAGED: &str = "A passphrase is encouraged.";

/// What a node made with no identity passphrase is told, once (`vox_text::node::NO_PASSPHRASE`).
const NO_PASSPHRASE: &str = "no identity passphrase: this node's identity key is kept on this \
                             machine unencrypted";

/// Every identity vault under `dir`: an identity left behind.
fn vaults(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                todo.push(p);
            } else if p.file_name().is_some_and(|n| n == "vault.cbor") {
                found.push(p);
            }
        }
    }
    found
}

/// `vox node create <name>` at a terminal (a pty), answering both passphrase prompts with Enter
/// alone: what the terminal showed, and how `vox` exited.
fn create_at_a_terminal(dir: &std::path::Path, name: &str) -> String {
    const DRIVER: &str = r#"
import os, select, sys, time
vox, name = sys.argv[1], sys.argv[2]
pid, fd = os.forkpty()
if pid == 0:
    os.execv(vox, [vox, "node", "create", name])
out, sent, again, deadline = b"", False, False, time.time() + 60
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 0.5)
    if not r:
        continue
    try:
        d = os.read(fd, 4096)
    except OSError:
        break
    if not d:
        break
    out += d
    if not sent and b"new identity passphrase" in out:
        os.write(fd, b"\r")
        sent = True
    elif sent and not again and b"again" in out:
        os.write(fd, b"\r")
        again = True
_, st = os.waitpid(pid, 0)
sys.stdout.write(out.decode("utf-8", "replace"))
sys.stdout.write("\nPROMPTED %s EXIT %d\n" % (sent, os.waitstatus_to_exitcode(st)))
"#;
    let out = Command::new("python3")
        .args(["-c", DRIVER, VOX, name])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_ROOM")
        // A harness session running this proof names its own node here; never this run's.
        .env_remove("VOX_NODE")
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run the pty driver: {e}"));
    assert!(
        out.status.success(),
        "APPARATUS: the pty driver failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

#[test]
#[ignore = "four real vox processes, a real anchor and production Argon2id; run on demand"]
fn a_passphrase_is_optional_for_a_node_and_a_room() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: cannot make a profile directory");
        d
    };
    let (anchor_dir, alice, bob, carol) = (dir("anchor"), dir("alice"), dir("bob"), dir("carol"));
    // A file with nothing in it: a passphrase given, and empty.
    let empty_file = tmp.path().join("empty-passphrase");
    std::fs::write(&empty_file, b"").expect("APPARATUS: cannot write the empty passphrase file");
    let empty_file = empty_file
        .to_str()
        .expect("APPARATUS: the temp path is not UTF-8")
        .to_owned();

    let mut anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &s(&["node", "--listen", "127.0.0.1:0"]),
        None,
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();

    // ---- claim 1: a node is made with an empty identity passphrase, and told what it means ----
    let made = |how: &str, d: &std::path::Path, ok: bool, said: &str| {
        let left = vaults(d);
        assert!(
            ok && said.contains(NO_PASSPHRASE) && left.len() == 1,
            "PRODUCT: {how} must make the node, saying once {NO_PASSPHRASE:?} (ADR-005 J-2); it \
             {} and left {left:?}, saying:\n{said}",
            if ok { "succeeded" } else { "failed" }
        );
    };
    let by_variable = dir("by-variable");
    let (ok, out, err) = vox_as(&by_variable, &s(&["id"]), None, "");
    made(
        "`vox id` with VOX_IDENTITY_PASSPHRASE set to nothing",
        &by_variable,
        ok,
        &format!("{out}{err}"),
    );
    let by_file = dir("by-file");
    let (ok, out, err) = vox_as(
        &by_file,
        &s(&["node", "create", "e", "--passphrase-file", &empty_file]),
        None,
        PASS,
    );
    made(
        "`vox node create` with an empty --passphrase-file",
        &by_file,
        ok,
        &format!("{out}{err}"),
    );
    let at_terminal = dir("at-terminal");
    let shown = create_at_a_terminal(&at_terminal, "t");
    assert!(
        shown.contains("PROMPTED True"),
        "APPARATUS: `vox node create` at a pty never showed its passphrase prompt:\n{shown}"
    );
    made(
        "`vox node create` at a terminal with Enter alone, twice",
        &at_terminal,
        shown.contains("EXIT 0\n"),
        &shown,
    );
    let no_terminal = dir("no-terminal");
    let out = Command::new(VOX)
        .args(["node", "create", "n"])
        .env("VOX_DATA_DIR", &no_terminal)
        .env("VOX_CONFIG_DIR", no_terminal.join("cfg"))
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .stdin(Stdio::null())
        .output()
        .expect("APPARATUS: cannot run vox");
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success()
            && said.contains("--passphrase-file <path>")
            && !said.contains("--identity-passphrase-file")
            && !no_terminal.join("nodes").join("n").exists(),
        "PRODUCT: `vox node create` with no terminal must refuse, name its own --passphrase-file, \
         and leave no nodes/n/: exit {:?}, nodes/n/ there: {}, said:\n{said}",
        out.status.code(),
        no_terminal.join("nodes").join("n").exists()
    );
    let (_, help, _) = vox_as(&by_file, &s(&["node", "--help"]), None, PASS);
    let create = help
        .lines()
        .skip_while(|l| !l.trim_start().starts_with("create "))
        .take_while(|l| !l.trim_start().starts_with("attach "))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        create.contains("an empty one gives the node none") && !create.contains("refused"),
        "PRODUCT: `vox node --help` must say an empty passphrase gives the node none, as `vox \
         node create` does; it says of create: {create:?}"
    );
    let fp = |d: &std::path::Path| {
        let (ok, out, err) = vox(d, &s(&["id"]), None);
        assert!(
            ok,
            "PRODUCT (staging): `vox id` with a passphrase failed: {err}"
        );
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp) = (fp(&alice), fp(&bob));
    let _ = fp(&carol);
    for (d, who, name) in [(&alice, &bob_fp, "bob"), (&bob, &alice_fp, "alice")] {
        let (ok, _, err) = vox(d, &s(&["trust", "add", who, "--name", name]), None);
        assert!(
            ok,
            "PRODUCT (staging): `vox trust add {name}` failed: {err}"
        );
    }
    // Alice and Carol give it as a line on stdin; Bob gives none, in an empty file.
    let mut daemons = Vec::new();
    for (name, d, file) in [
        ("alice", &alice, false),
        ("bob", &bob, true),
        ("carol", &carol, false),
    ] {
        let mut args = s(&["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec]);
        if file {
            // Bob's node has no passphrase: an empty file attaches it (claim 1).
            args.extend(s(&["--passphrase-file", &empty_file]));
        }
        let line = format!("{PASS}\n");
        let mut p = Proc::spawn(name, d, &args, (!file).then_some(line.as_str()));
        p.expect_line("its control socket", |l| l.contains("control socket"));
        daemons.push(p);
    }

    // ---- claim 2: a room with no passphrase ----
    let (ok, _, err) = vox(
        &alice,
        &s(&["room", "create", "--passphrase-file", "-", "--name", "open"]),
        Some("\n"),
    );
    assert!(
        ok,
        "PRODUCT: `vox room create` refused an empty room passphrase: {err}"
    );
    assert!(
        err.contains(ENCOURAGED),
        "PRODUCT: `vox room create` with no passphrase did not encourage one: {err:?}"
    );
    let listed = until(&alice, "the room", &s(&["room", "list"]), 30, |o| {
        o.contains("open")
    })
    .unwrap_or_else(|e| panic!("PRODUCT (staging): alice's room never listed: {e}"));
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("PRODUCT (staging): no room id in `vox room list`: {listed:?}"))
        .to_owned();
    let (ok, link, err) = vox(&alice, &s(&["room", "link", &room]), None);
    assert!(ok, "PRODUCT (staging): room link failed: {err}");
    let link = link.trim().to_owned();

    // ---- claim 3: a wrong, non-empty passphrase is refused ----
    let (ok, out, err) = vox(
        &carol,
        &s(&["room", "join", "--passphrase-file", "-", &link]),
        Some("not empty\n"),
    );
    assert!(
        !ok,
        "PRODUCT: a non-empty passphrase joined a room made with none: stdout={out:?} \
         stderr={err:?}"
    );
    assert!(
        err.to_lowercase().contains("passphrase"),
        "PRODUCT: the refusal of a wrong passphrase must name the passphrase: {err:?}"
    );

    // ---- claim 4: no passphrase joins, and the two read each other ----
    let (ok, out, err) = vox(
        &bob,
        &s(&["room", "join", "--passphrase-file", &empty_file, &link]),
        None,
    );
    assert!(
        ok,
        "PRODUCT: bob could not join a room made with no passphrase, giving none: \
         stdout={out:?} stderr={err:?}"
    );
    assert!(
        err.contains(ENCOURAGED),
        "PRODUCT: `vox room join` with no passphrase did not encourage one: {err:?}"
    );
    let post = |d: &std::path::Path, text: &str| {
        let (ok, _, err) = vox(d, &s(&["room", "post", &room, text]), None);
        assert!(ok, "PRODUCT: vox room post {text} failed: {err}");
    };
    post(&alice, "FROM-ALICE");
    post(&bob, "FROM-BOB");
    let read = s(&["room", "read", &room]);
    until(&bob, "bob to read alice", &read, 90, |o| {
        o.contains("FROM-ALICE")
    })
    .unwrap_or_else(|e| panic!("PRODUCT: claim 4: bob never read alice: {e}"));
    until(&alice, "alice to read bob", &read, 90, |o| {
        o.contains("FROM-BOB")
    })
    .unwrap_or_else(|e| panic!("PRODUCT: claim 4: alice never read bob: {e}"));
    drop(daemons);
    drop(anchor);
}
