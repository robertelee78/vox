//! V210-72 (#263) — **the control socket, passphrases and shared files cannot leak to another
//! local user or process**, driven through the shipped `vox` binary.
//!
//! Seven findings from the v0.2.10 defect sweep, one claim each:
//!
//! 1. **A stopped share is withdrawn.** A share whose service stayed registered once it ended
//!    carried a member's dial to a port nobody served any more — or to whatever took that port
//!    next. Staged: alice shares a file and stops it (`vox share stop`), bob asks for it, and
//!    alice's own daemon says why it refused bob. "no such service is offered in that room" is
//!    the withdrawn share; "the local service did not accept the connection" is the leaked one.
//!    And **two shares of the same file are two shares**: their tags were the content's, so
//!    ending one withdrew the other while it still ran. Staged: two `vox share`s of one file,
//!    the first stopped, and bob collects the file whole by the second's tag. And a get **by
//!    name** is not hidden by a newer share that has ended: a third share is announced and
//!    stopped, and `vox room get twin.bin` still collects the file through the second. The
//!    fallback is only ever the same file from the same member: a newer `twin.bin` with other
//!    content is shared and stopped, and the get by name must fail, leave nothing, and name only
//!    the live shares of that name, each by its exact tag; every suggested command is run and
//!    must collect the right bytes. The verifier's arms (v1, v2) add a third member, carol:
//!    alice's newest share ends while bob's copy of the same file is served, carol's get by name
//!    fails rather than taking another member's share, and the refusal names bob's copy as the
//!    same file with a command that collects it.
//! 2. **A share that outlives its daemon is served, never a port nobody serves.** A daemon that
//!    stopped while an offer ran came back offering its port with nothing behind it. A share now
//!    outlives its daemon's restart by design (ADR-028 F-2), so what must hold is that the port
//!    it is offered on after the restart is served: staged by stopping alice's daemon with a share
//!    live, bringing the node back (`vox node attach`), and bob collecting the share whole.
//! 3. **A get's forward is withdrawn however `vox room get` ends.** An interrupted get left
//!    bob's daemon listening on the forward's port. Staged: alice's daemon, which serves the
//!    share, is stopped (SIGSTOP) so the transfer stalls; the get is killed with each signal
//!    while bob's daemon listens on its forward (`lsof`), and the port must close.
//! 4. **The control socket's fallback is private to its user** (Linux put it in `/tmp` under a
//!    predictable name). A profile path over the socket-address limit puts the socket in
//!    `<tmp>/vox-<uid>/`, which is `0700` — tightened if it was left wider — with the socket
//!    `0600`; nothing lands in `<tmp>` itself; and a `vox-<uid>` that is a symlink is refused,
//!    so the daemon does not start and the directory it points at is untouched.
//! 5. **A client refuses a socket that is not its user's own.** Another uid cannot be staged
//!    without privileges, so the stand-in is a symlink planted where a profile's socket goes,
//!    pointing at another profile's live socket: `vox room list` must refuse it, never list the
//!    other profile's rooms. The kernel peer-credential check on both ends (a different uid)
//!    rests on code review.
//! 6. **One accept error does not end the control socket.** A daemon under `ulimit -n 64` is
//!    given connections until it cannot accept one (a connection that is never greeted); they
//!    are closed, and `vox room list` must answer within 20 s. It ended the accept loop for
//!    good, so every client after was told nothing was listening.
//! 7. **`vox shell-setup` keeps an rc file's symlink and mode.** It replaced a symlinked
//!    `.zshrc` with a plain file, and wrote `0644` over a `0600` rc.
//! 8. **A room passphrase is never taken from argv or the environment.** `--passphrase` and
//!    `VOX_ROOM_PASSPHRASE` are refused with the replacement named; `--passphrase-file` is not.
//!
//! "Created 0600 from the start" (the socket is bound under a staging name, chmod'ed, then
//! renamed into place) has no observable window a proof can stage reliably; it rests on code
//! review, and the directory being `0700` is what (4) asserts.
//!
//! Mutations, each red for its own reason: (1) `vox share stop` not withdrawing the service, a
//! share's tag being its content's alone, a get trying only the newest matching share, and a get
//! falling back to a different file of that name (the twin cases); (2) a restarted daemon offering
//! a share's service without serving it; (3) the daemon not releasing the forward a closed
//! connection held; (4) the old flat `<tmp>/vox-<hex>.sock` fallback; (5) the
//! client's owner check removed; (6) the accept loop returning on its first error; (7) the rc
//! written `0644` over the path; (8) `--passphrase` accepted.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/layout.rs"]
mod layout;

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const ID_PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";

/// A long-running child with its output drained into a string; killed and reaped however the
/// test ends.
struct Running(Child, Arc<Mutex<String>>);

impl Running {
    fn said(&self) -> String {
        self.1.lock().map(|s| s.clone()).unwrap_or_default()
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
    /// Wait up to `within` for it to exit; its success, or `None` if it is still running.
    fn exited_within(&mut self, within: Duration) -> Option<bool> {
        let deadline = Instant::now() + within;
        loop {
            if let Ok(Some(status)) = self.0.try_wait() {
                return Some(status.success());
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    /// Wait up to `within` for a line containing `what`, and return the whole output.
    fn wait_for(&self, what: &str, within: Duration) -> String {
        let deadline = Instant::now() + within;
        loop {
            let said = self.said();
            if said.contains(what) {
                return said;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): {what:?} was never said; said:\n{said}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn drain(stream: Option<impl std::io::Read + Send + 'static>, into: &Arc<Mutex<String>>) {
    let Some(mut stream) = stream else { return };
    let sink = Arc::clone(into);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if let Ok(mut s) = sink.lock() {
                        s.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
            }
        }
    });
}

/// Send `sig` (a `kill -s` name) to `pid`, one of this test's own children.
fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args(["-s", sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: `kill -s {sig} {pid}` did not take");
}

/// This user's uid, as the filesystem records it.
fn my_uid(tmp: &Path) -> u32 {
    std::fs::metadata(tmp)
        .expect("APPARATUS: stat the temp dir")
        .uid()
}

/// One profile: its data and config directories, its identity passphrase file, and the extra
/// environment every `vox` it runs gets.
struct Profile {
    data: PathBuf,
    cfg: PathBuf,
    pass: PathBuf,
    env: Vec<(String, String)>,
}

impl Profile {
    fn new(root: &Path, env: &[(&str, &str)]) -> Self {
        let data = root.join("data");
        let cfg = root.join("cfg");
        std::fs::create_dir_all(&cfg).expect("APPARATUS: a profile dir");
        let pass = root.join("id.pass");
        std::fs::write(&pass, ID_PASS).expect("APPARATUS: the passphrase file");
        Self {
            data,
            cfg,
            pass,
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_ROOM_PASSPHRASE")
            .env_remove("VOX_ANCHORS");
        for (k, v) in &self.env {
            c.env(k, v);
        }
        c
    }

    /// Run `vox args` to completion with `stdin`, bounded by `within`: (ok, stdout, stderr).
    fn run(&self, args: &[&str], stdin: &str, within: Duration) -> (bool, String, String) {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("APPARATUS: spawn vox");
        let _ = child
            .stdin
            .take()
            .expect("APPARATUS: vox's stdin")
            .write_all(stdin.as_bytes());
        let (out, err) = (
            Arc::new(Mutex::new(String::new())),
            Arc::new(Mutex::new(String::new())),
        );
        drain(child.stdout.take(), &out);
        drain(child.stderr.take(), &err);
        let mut running = Running(child, Arc::new(Mutex::new(String::new())));
        let ended = running.exited_within(within);
        std::thread::sleep(Duration::from_millis(100));
        let (out, err) = (
            out.lock()
                .expect("APPARATUS: a poisoned output buffer")
                .clone(),
            err.lock()
                .expect("APPARATUS: a poisoned output buffer")
                .clone(),
        );
        match ended {
            Some(ok) => (ok, out, err),
            None => (
                false,
                out,
                format!("{err}\n[proof] vox {args:?} did not finish within {within:?}; killed"),
            ),
        }
    }

    fn vox(&self, args: &[&str]) -> (bool, String, String) {
        self.run(args, "", Duration::from_secs(120))
    }

    fn spawn(&self, args: &[&str]) -> Running {
        let mut child = self
            .command(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("APPARATUS: spawn vox");
        let said = Arc::new(Mutex::new(String::new()));
        drain(child.stdout.take(), &said);
        drain(child.stderr.take(), &said);
        Running(child, said)
    }

    fn id(&self) -> String {
        let (ok, out, err) = self.vox(&["id", "--identity-passphrase-file", self.p()]);
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        out.trim().to_owned()
    }

    fn p(&self) -> &str {
        self.pass.to_str().expect("APPARATUS: a UTF-8 temp path")
    }

    /// A real `vox daemon`, and the control socket it says it serves.
    fn daemon(&self, anchor: Option<&str>) -> (Running, PathBuf) {
        let mut args = vec![
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            self.p(),
        ];
        if let Some(spec) = anchor {
            args.extend(["--anchor", spec]);
        }
        let d = self.spawn(&args);
        let said = d.wait_for("vox daemon: control socket ", Duration::from_secs(120));
        let sock = said
            .lines()
            .find_map(|l| l.strip_prefix("vox daemon: control socket "))
            .map(|s| PathBuf::from(s.trim()))
            .unwrap_or_else(|| panic!("PRODUCT: the daemon named no control socket path: {said}"));
        (d, sock)
    }
}

/// A real `vox node` anchor on loopback, and its `--anchor` spec.
fn anchor(root: &Path) -> (Running, String) {
    let p = Profile::new(root, &[]);
    let node = p.spawn(&["node", "--listen", "127.0.0.1:0"]);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(spec) = node
            .said()
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (node, spec.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the anchor printed no spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Poll `vox args` until its stdout satisfies `ok`, for up to 60 s. `side` names who failed if
/// it never does: `PRODUCT (staging)` for staging, `PRODUCT` for a propagation the claim relies on.
fn until(side: &str, who: &Profile, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (_, out, err) = who.vox(args);
        if ok(&out) {
            return;
        }
        last = format!("stdout={out:?} stderr={err:?}");
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{side}: timed out after 60 s waiting for {what}; `vox {args:?}` last said {last}");
}

/// Run, as `who`, every `vox room get …` a refusal suggests (each in backticks), into `dir`, and
/// return how many collected exactly `want`. Panics on one that does not: a suggested command
/// that fails is the defect.
fn run_suggestions(who: &Profile, said: &str, dir: &Path, want: &[u8]) -> usize {
    std::fs::create_dir_all(dir).expect("APPARATUS: the suggestions dir");
    let mut ran = 0usize;
    for (i, cmd) in said.split('`').skip(1).step_by(2).enumerate() {
        let Some(args) = cmd.strip_prefix("vox ") else {
            continue;
        };
        let mut args: Vec<&str> = args.split_whitespace().collect();
        if args.first() != Some(&"room") {
            continue;
        }
        let out = dir.join(format!("{i}.bin"));
        args.extend(["--out", out.to_str().expect("APPARATUS: a UTF-8 temp path")]);
        let (ok, stdout, stderr) = who.vox(&args);
        let got = std::fs::read(&out).ok();
        assert!(
            ok && got.as_deref() == Some(want),
            "PRODUCT: the suggested `{cmd}` did not collect the named file ({} bytes): {stdout} \
             {stderr}",
            got.as_ref().map_or(0, Vec::len)
        );
        ran += 1;
    }
    ran
}

/// The TCP ports `pid` listens on, by `lsof`; `None` if `lsof` cannot be run.
fn listening(pid: u32) -> Option<std::collections::BTreeSet<String>> {
    let out = Command::new("lsof")
        .args([
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
            "-iTCP",
            "-sTCP:LISTEN",
            "-Fn",
        ])
        .output()
        .ok()?;
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.strip_prefix('n'))
            .map(str::to_owned)
            .collect(),
    )
}

#[test]
#[ignore = "two networked nodes and real child processes; CI runs it in release"]
fn an_offer_and_a_get_are_withdrawn_however_the_verb_ends() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let (_anchor, spec) = anchor(&tmp.path().join("anchor"));
    let alice = Profile::new(&tmp.path().join("alice"), &[]);
    let bob = Profile::new(&tmp.path().join("bob"), &[]);
    let (alice_fp, bob_fp) = (alice.id(), bob.id());
    let (alice_daemon, _) = alice.daemon(Some(&spec));
    let (bob_daemon, _) = bob.daemon(Some(&spec));
    for (who, peer, name) in [(&alice, &bob_fp, "bob"), (&bob, &alice_fp, "alice")] {
        let (ok, _, err) = who.vox(&[
            "trust",
            "add",
            peer,
            "--name",
            name,
            "--identity-passphrase-file",
            who.p(),
        ]);
        assert!(ok, "PRODUCT (staging): trust {name}: {err}");
    }
    let (ok, _, err) = alice.run(
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "mission",
        ],
        ROOM_PASS,
        Duration::from_secs(120),
    );
    assert!(ok, "PRODUCT (staging): room create: {err}");
    let (_, listed, list_err) = alice.vox(&["room", "list"]);
    let label = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| {
            panic!("PRODUCT: `vox room list` names no room after a create: {listed}{list_err}")
        })
        .to_owned();
    let (ok, link, err) = alice.vox(&["room", "link", &label]);
    assert!(ok, "PRODUCT (staging): room link: {err}");
    let link = link.trim().to_owned();
    let room = link
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .unwrap_or_else(|| panic!("PRODUCT: the invite names no room: {link}"))
        .to_owned();
    // One join, no retry: a join that fails is the product's failure, and #217's busy-host
    // refusal is fixed (V210-43), so nothing known excuses one.
    let (ok, out, err) = bob.run(
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "mission",
        ],
        ROOM_PASS,
        Duration::from_secs(120),
    );
    assert!(
        ok,
        "PRODUCT: `vox room join` failed for bob.\nstdout: {out}\nstderr: {err}"
    );
    for (who, other, word) in [(&alice, &bob, "warm-bob"), (&bob, &alice, "warm-alice")] {
        let (ok, _, err) = other.vox(&["room", "post", &room, word]);
        assert!(ok, "PRODUCT: a warm-up post failed: {err}");
        until(
            "PRODUCT (staging)",
            who,
            "each to read the other",
            &["room", "read", &room],
            |o| o.contains(word),
        );
    }

    // `vox share` returns once the sharer's daemon serves the file, naming its tag.
    let share = |who: &Profile, file: &Path| -> String {
        let (ok, out, err) = who.vox(&[
            "share",
            &room,
            file.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ]);
        assert!(ok, "PRODUCT (staging): `vox share`: {out}{err}");
        out.split_whitespace()
            .find(|w| w.starts_with("file-"))
            .unwrap_or_else(|| panic!("PRODUCT: `vox share` named no tag: {out}"))
            .to_owned()
    };
    let stop = |who: &Profile, tag: &str| {
        let (ok, out, err) = who.vox(&["share", "stop", &room, tag]);
        assert!(ok, "PRODUCT (staging): `vox share stop {tag}`: {out}{err}");
    };

    // ---- (1) a stopped share is withdrawn ----
    let name = "stopped.bin";
    let file = tmp.path().join(name);
    std::fs::write(&file, vec![1u8; 4096]).expect("APPARATUS: the shared file");
    let tag = share(&alice, &file);
    until(
        "PRODUCT",
        &bob,
        "the share to reach bob",
        &["room", "read", &room],
        |o| o.contains(name),
    );
    stop(&alice, &tag);
    let mark = alice_daemon.said().len();
    let out = tmp.path().join("got-stopped.bin");
    let (ok, stdout, stderr) = bob.vox(&[
        "room",
        "get",
        &room,
        name,
        "--out",
        out.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    assert!(
        !ok,
        "PRODUCT: a stopped share was collected: {stdout} {stderr}"
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let why = loop {
        let said = alice_daemon.said()[mark..].to_owned();
        if said.contains("no such service is offered in that room")
            || said.contains("did not accept the connection")
        {
            break said;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): alice's daemon never said why it refused bob after the stop; \
             bob's get said: {stdout} {stderr}\nalice's daemon since:\n{said}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!(
        "[proof] after `vox share stop`: alice's daemon said: {}",
        why.trim()
    );
    assert!(
        why.contains("no such service is offered in that room")
            && !why.contains("did not accept the connection"),
        "PRODUCT: a share stopped with `vox share stop` left its service registered: alice's \
         daemon carried bob's dial to a port nobody serves:\n{why}"
    );

    // ---- (1b) two shares of the same file: stopping one leaves the other serving ----
    let twin = tmp.path().join("twin.bin");
    let twin_bytes: Vec<u8> = (0..65_536u32).map(|i| (i % 253) as u8).collect();
    std::fs::write(&twin, &twin_bytes).expect("APPARATUS: the twin file");
    let t1 = share(&alice, &twin);
    until(
        "PRODUCT",
        &bob,
        "the first twin share to reach bob",
        &["room", "read", &room],
        |o| o.contains("twin.bin"),
    );
    // Collected by the second share's own tag, so the get asks for exactly the share that is
    // still served.
    let t2 = share(&alice, &twin);
    eprintln!("[proof] twin shares of one file: tags {t1} and {t2}");
    until(
        "PRODUCT",
        &bob,
        "the second twin share to reach bob",
        &["room", "read", &room, "--json"],
        |o| o.contains(&t2),
    );
    stop(&alice, &t1);
    let got = tmp.path().join("twin-got.bin");
    let (ok, stdout, stderr) = bob.vox(&[
        "room",
        "get",
        &room,
        &t2,
        "--out",
        got.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    let collected = std::fs::read(&got).ok();
    eprintln!(
        "[proof] get after the first twin ended: ok={ok}, {} bytes of 65536",
        collected.as_ref().map_or(0, Vec::len)
    );
    assert!(
        ok && collected.as_deref() == Some(&twin_bytes[..]),
        "PRODUCT: stopping one share of a file withdrew another share of the same file that was \
         still served (tags {t1} and {t2}): {stdout} {stderr}"
    );

    // ---- (1c) a get by name is not hidden by a newer share that has ended ----
    let t3 = share(&alice, &twin);
    until(
        "PRODUCT",
        &bob,
        "the third twin share to reach bob",
        &["room", "read", &room, "--json"],
        |o| o.contains(&t3),
    );
    stop(&alice, &t3);
    let by_name = tmp.path().join("twin-by-name.bin");
    let (ok, stdout, stderr) = bob.vox(&[
        "room",
        "get",
        &room,
        "twin.bin",
        "--out",
        by_name.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    let collected = std::fs::read(&by_name).ok();
    eprintln!(
        "[proof] get by name with the newest offer ({t3}) ended and an older one ({t2}) live: \
         ok={ok}, {} bytes of 65536; said: {}",
        collected.as_ref().map_or(0, Vec::len),
        stderr.trim()
    );
    assert!(
        ok && collected.as_deref() == Some(&twin_bytes[..]),
        "PRODUCT: a get by name failed on the newest offer, which had ended, although an older offer of \
         the same file was still served: {stdout} {stderr}"
    );

    // ---- (1d) the negative control: a different file of the same name is never the fallback ----
    // A newer `twin.bin` with other content is offered and ended. The only live offer by that
    // name is then the older one, which is a different file: the get by name must fail, leave
    // nothing behind, and say how to ask for the other file exactly.
    let other_dir = tmp.path().join("other");
    std::fs::create_dir_all(&other_dir).expect("APPARATUS: the other dir");
    let other_twin = other_dir.join("twin.bin");
    std::fs::write(&other_twin, vec![0x5au8; 65_536]).expect("APPARATUS: the other twin");
    let t4 = share(&alice, &other_twin);
    assert!(
        t4.len() > 21 && t4[..21] != t2[..21],
        "PRODUCT: `vox share` shared two files with different contents under the same content \
         hash ({t4} vs {t2})"
    );
    until(
        "PRODUCT",
        &bob,
        "the different twin share to reach bob",
        &["room", "read", &room, "--json"],
        |o| o.contains(&t4),
    );
    stop(&alice, &t4);
    let wrong = tmp.path().join("twin-wrong.bin");
    let (ok, stdout, stderr) = bob.vox(&[
        "room",
        "get",
        &room,
        "twin.bin",
        "--out",
        wrong.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    let left = std::fs::read(&wrong).ok();
    eprintln!(
        "[proof] get by name with the newest ({t4}, other content) ended and only {t2} live: \
         ok={ok}, file left: {} bytes; said: {}",
        left.as_ref().map_or(0, Vec::len),
        stderr.trim()
    );
    assert!(
        !ok && left.is_none(),
        "PRODUCT: a get by name fell back to a DIFFERENT file that only shares the name \
         ({} bytes collected): {stdout} {stderr}",
        left.as_ref().map_or(0, Vec::len)
    );
    assert!(
        stderr.contains("a different file also matches")
            && stderr.contains(&format!("vox room get {room} {t2}")),
        "PRODUCT: the refusal does not say a different file matches and name its live offer \
         exactly: {stderr}"
    );
    for dead in [&t1, &t3, &t4] {
        assert!(
            !stderr.contains(dead.as_str()) || stderr.contains(&format!("the offer {dead} of")),
            "PRODUCT: the refusal suggests an offer that has ended ({dead}): {stderr}"
        );
    }
    let ran = run_suggestions(&bob, &stderr, &tmp.path().join("sugg-1d"), &twin_bytes);
    eprintln!("[proof] (1d) suggested commands run and collected the right bytes: {ran}");
    assert!(
        ran >= 1,
        "PRODUCT (staging): (1d) suggested no command: {stderr}"
    );

    // ---- (verifier v1) the command the refusal suggests collects exactly the named file ----
    let sug = t2[5..21].to_owned();
    let exact = tmp.path().join("twin-exact.bin");
    let (ok, _o, se) = bob.vox(&[
        "room",
        "get",
        &room,
        &sug,
        "--out",
        exact.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    let got = std::fs::read(&exact).ok();
    eprintln!(
        "[verifier] v1 suggested `vox room get <room> {sug}`: ok={ok}, {} bytes, equals A: {}; said: {}",
        got.as_ref().map_or(0, Vec::len),
        got.as_deref() == Some(&twin_bytes[..]),
        se.trim()
    );
    let v1 = ok && got.as_deref() == Some(&twin_bytes[..]);

    // ---- (verifier v2) a same-sha offer from ANOTHER member is not the fallback; carol collects ----
    stop(&alice, &t2);
    let carol = Profile::new(&tmp.path().join("carol"), &[]);
    let carol_fp = carol.id();
    let (_carol_daemon, _) = carol.daemon(Some(&spec));
    for (who, peer, name) in [
        (&alice, &carol_fp, "carol"),
        (&bob, &carol_fp, "carol"),
        (&carol, &alice_fp, "alice"),
        (&carol, &bob_fp, "bob"),
    ] {
        let (ok, _, err) = who.vox(&[
            "trust",
            "add",
            peer,
            "--name",
            name,
            "--identity-passphrase-file",
            who.p(),
        ]);
        assert!(ok, "PRODUCT (staging): trust {name}: {err}");
    }
    let (ok, out, err) = carol.run(
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "mission",
        ],
        ROOM_PASS,
        Duration::from_secs(120),
    );
    assert!(
        ok,
        "PRODUCT: `vox room join` failed for carol.\nstdout: {out}\nstderr: {err}"
    );
    for (other, word) in [(&alice, "warm-c-alice"), (&bob, "warm-c-bob")] {
        let (ok, _, err) = other.vox(&["room", "post", &room, word]);
        assert!(ok, "PRODUCT: a warm-up post failed: {err}");
        until(
            "PRODUCT (staging)",
            &carol,
            "carol to read alice and bob",
            &["room", "read", &room],
            |o| o.contains(word),
        );
    }
    let tb = share(&bob, &twin);
    until(
        "PRODUCT",
        &carol,
        "bob's twin offer to reach carol",
        &["room", "read", &room, "--json"],
        |o| o.contains(&tb),
    );
    // control: carol CAN collect bob's offer by its exact tag
    let ctl = tmp.path().join("twin-ctl.bin");
    let (okc, _o, sec) = carol.vox(&[
        "room",
        "get",
        &room,
        &tb,
        "--out",
        ctl.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    eprintln!(
        "[verifier] v2 control: carol gets bob's {tb} by tag: ok={okc}; said: {}",
        sec.trim()
    );
    assert!(
        okc && std::fs::read(&ctl).ok().as_deref() == Some(&twin_bytes[..]),
        "PRODUCT (staging): carol cannot collect bob's offer by tag"
    );
    let tn = share(&alice, &twin);
    until(
        "PRODUCT",
        &carol,
        "alice's newest twin to reach carol",
        &["room", "read", &room, "--json"],
        |o| o.contains(&tn),
    );
    stop(&alice, &tn);
    let cross = tmp.path().join("twin-cross.bin");
    let (ok2, _o, se2) = carol.vox(&[
        "room",
        "get",
        &room,
        "twin.bin",
        "--out",
        cross.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    let got2 = std::fs::read(&cross).ok();
    eprintln!(
        "[verifier] v2 newest {tn} (alice, A) ended, bob's {tb} (A, same sha) live: ok={ok2}, file left: {} bytes; said: {}",
        got2.as_ref().map_or(0, Vec::len),
        se2.trim()
    );
    let v2 = !ok2 && got2.is_none();
    let exact2 = tmp.path().join("twin-cross-exact.bin");
    let (ok3, _o, se3) = carol.vox(&[
        "room",
        "get",
        &room,
        &sug,
        "--out",
        exact2.to_str().expect("APPARATUS: a UTF-8 temp path"),
    ]);
    eprintln!(
        "[verifier] v2b the suggested sha command in that state: ok={ok3}, {} bytes; said: {}",
        std::fs::read(&exact2).map_or(0, |b| b.len()),
        se3.trim()
    );
    // Every command the v2 refusal suggests is run as carol, and must collect bob's copy.
    assert!(
        se2.contains("the same file is also offered by"),
        "PRODUCT: v2: bob's live copy of the same file is not named as the same file: {se2}"
    );
    assert!(
        !se2.contains("a different file also matches"),
        "PRODUCT: v2: only the same file is served, yet the refusal names a different one: {se2}"
    );
    let ran2 = run_suggestions(&carol, &se2, &tmp.path().join("sugg-v2"), &twin_bytes);
    eprintln!("[proof] (v2) suggested commands run and collected the right bytes: {ran2}");
    assert!(
        ran2 >= 1,
        "PRODUCT (staging): v2 suggested no command: {se2}"
    );
    stop(&bob, &tb);
    assert!(
        v1,
        "PRODUCT: v1: the suggested `vox room get <room> {sug}` did not collect exactly the named \
         file; it said: {se}"
    );
    assert!(
        v2,
        "PRODUCT: v2: a same-sha offer from another member was used as the fallback ({} bytes \
         left); it said: {se2}",
        got2.as_ref().map_or(0, Vec::len)
    );

    // ---- (3) a get ended by SIGTERM, SIGHUP or SIGKILL closes its forward ----
    let Some(_) = listening(bob_daemon.pid()) else {
        panic!("APPARATUS, CANNOT MEASURE: lsof cannot be run here");
    };
    let ports = |pid: u32| {
        listening(pid)
            .unwrap_or_else(|| panic!("APPARATUS, CANNOT MEASURE: lsof could not be run on {pid}"))
    };
    let big = tmp.path().join("stalled.bin");
    std::fs::write(&big, vec![7u8; 1 << 20]).expect("APPARATUS: the stalled file");
    share(&alice, &big);
    until(
        "PRODUCT",
        &bob,
        "the stalled share to reach bob",
        &["room", "read", &room],
        |o| o.contains("stalled.bin"),
    );
    // Alice's daemon, which serves it, is stopped, so the transfer stalls and the get is still
    // running when it is signalled.
    signal(alice_daemon.pid(), "STOP");
    let mut closed = 0usize;
    for sig in ["TERM", "HUP", "KILL"] {
        let before = ports(bob_daemon.pid());
        let out = tmp.path().join(format!("stalled-{sig}.bin"));
        let mut get = bob.spawn(&[
            "room",
            "get",
            &room,
            "stalled.bin",
            "--out",
            out.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ]);
        let deadline = Instant::now() + Duration::from_secs(20);
        let forward = loop {
            let now = ports(bob_daemon.pid());
            if let Some(p) = now.difference(&before).next() {
                break p.clone();
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): bob's daemon never opened a forward for the get; it said: {}",
                get.said()
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            get.exited_within(Duration::ZERO).is_none(),
            "PRODUCT (staging): the get ended before it was signalled: {}",
            get.said()
        );
        signal(get.pid(), sig);
        assert!(
            get.exited_within(Duration::from_secs(10)).is_some(),
            "PRODUCT (staging): `vox room get` did not end on SIG{sig}"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let t0 = Instant::now();
        while ports(bob_daemon.pid()).contains(&forward) {
            assert!(
                Instant::now() < deadline,
                "PRODUCT: `vox room get` ended by SIG{sig} left bob's daemon listening on its forward \
                 {forward} for 10 s"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!(
            "[proof] SIG{sig} of `room get`: forward {forward} closed after {:?}",
            t0.elapsed()
        );
        closed += 1;
    }
    signal(alice_daemon.pid(), "CONT");
    eprintln!("[proof] forwards closed after SIGTERM/SIGHUP/SIGKILL: {closed} of 3");

    // ---- (2) a share that outlives its daemon is served after the restart ----
    let live = tmp.path().join("live.bin");
    let live_bytes = b"shared while the daemon stops".to_vec();
    std::fs::write(&live, &live_bytes).expect("APPARATUS: the live file");
    let tag = share(&alice, &live);
    until(
        "PRODUCT",
        &bob,
        "the live share to reach bob",
        &["room", "read", &room],
        |o| o.contains("live.bin"),
    );
    let mut alice_daemon = alice_daemon;
    signal(alice_daemon.pid(), "TERM");
    assert!(
        alice_daemon
            .exited_within(Duration::from_secs(30))
            .is_some(),
        "PRODUCT: alice's `vox daemon` was still running 30 s after SIGTERM"
    );
    // The node again, as a person brings it back after its daemon stopped (ADR-026 L-2: a
    // one-shot verb refuses a node nothing holds).
    let (ok, _, err) = alice.vox(&["node", "attach", "default", "--passphrase-file", alice.p()]);
    assert!(
        ok,
        "PRODUCT (staging): vox node attach after the stop: {err}"
    );
    // That attach started a daemon of its own: stopped by its lock's pid however this ends.
    let _reaper = layout::Reaper(vec![alice.data.clone()]);
    // Bob collects it from the restarted daemon: the port it is offered on is served. Asked again
    // while bob's daemon has not yet reached alice's new one; the last answer is the verdict.
    let back = tmp.path().join("live-back.bin");
    let deadline = Instant::now() + Duration::from_secs(60);
    let (ok, stdout, stderr) = loop {
        let _ = std::fs::remove_file(&back);
        let r = bob.vox(&[
            "room",
            "get",
            &room,
            &tag,
            "--out",
            back.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ]);
        if r.0 || Instant::now() > deadline {
            break r;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    let collected = std::fs::read(&back).ok();
    eprintln!(
        "[proof] the share after its daemon's restart: ok={ok}, {} bytes; said: {}",
        collected.as_ref().map_or(0, Vec::len),
        stderr.trim()
    );
    assert!(
        ok && collected.as_deref() == Some(&live_bytes[..]),
        "PRODUCT: a share live when its daemon stopped was not served by the restarted daemon \
         within 60 s: {stdout} {stderr}"
    );
}

#[test]
#[ignore = "real daemons and production Argon2id; CI runs it in release"]
fn the_control_socket_is_private_and_a_client_refuses_one_that_is_not_its_own() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let uid = my_uid(tmp.path());
    let t = tmp.path().join("t");
    std::fs::create_dir_all(&t).expect("APPARATUS: the shared temp dir");
    let t_env = [("TMPDIR", t.to_str().expect("APPARATUS: a UTF-8 temp path"))];
    // Profile paths over the 100-byte socket budget, so the fallback is the one used.
    let p = Profile::new(&tmp.path().join("a".repeat(90)), &t_env);
    let q = Profile::new(&tmp.path().join("b".repeat(90)), &t_env);
    assert!(
        p.data.join(".daemon").join("vox.sock").as_os_str().len() > 104,
        "APPARATUS, CANNOT MEASURE: the proof's profile path is short enough for the natural \
         socket"
    );
    p.id();
    q.id();

    // ---- (4) the fallback directory is private, even if it was left wide open ----
    let private = t.join(format!("vox-{uid}"));
    std::fs::create_dir(&private).expect("APPARATUS: staging the open per-user dir");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o777))
        .expect("APPARATUS: staging the open per-user dir");
    let (_pd, sock) = p.daemon(None);
    eprintln!("[proof] fallback socket: {}", sock.display());
    assert_eq!(
        sock.parent(),
        Some(private.as_path()),
        "PRODUCT: the fallback socket is not in the per-user directory {}",
        private.display()
    );
    let dir_meta = std::fs::symlink_metadata(&private)
        .unwrap_or_else(|e| panic!("PRODUCT: the per-user directory is gone: {e}"));
    let sock_meta = std::fs::symlink_metadata(&sock).unwrap_or_else(|e| {
        panic!(
            "PRODUCT: the daemon named {} but it is not there: {e}",
            sock.display()
        )
    });
    eprintln!(
        "[proof] {} mode {:o} uid {}; socket mode {:o} uid {}",
        private.display(),
        dir_meta.mode() & 0o7777,
        dir_meta.uid(),
        sock_meta.mode() & 0o7777,
        sock_meta.uid()
    );
    assert!(
        dir_meta.is_dir() && dir_meta.mode() & 0o7777 == 0o700 && dir_meta.uid() == uid,
        "PRODUCT: the per-user directory {} is left directory={} mode {:o} uid {}, not a 0700 \
         directory owned by uid {uid}",
        private.display(),
        dir_meta.is_dir(),
        dir_meta.mode() & 0o7777,
        dir_meta.uid()
    );
    assert!(
        sock_meta.file_type().is_socket()
            && sock_meta.mode() & 0o7777 == 0o600
            && sock_meta.uid() == uid,
        "PRODUCT: the control socket {} is socket={} mode {:o} uid {}, not a 0600 socket owned \
         by uid {uid}",
        sock.display(),
        sock_meta.file_type().is_socket(),
        sock_meta.mode() & 0o7777,
        sock_meta.uid()
    );
    let in_tmp: Vec<String> = std::fs::read_dir(&t)
        .expect("APPARATUS: list the shared temp dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".sock"))
        .collect();
    assert!(
        in_tmp.is_empty(),
        "PRODUCT: a control socket landed in the shared temp directory itself: {in_tmp:?}"
    );
    let (ok, _, err) = p.run(
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "p-only-room",
        ],
        ROOM_PASS,
        Duration::from_secs(120),
    );
    assert!(
        ok,
        "PRODUCT (staging): room create through the fallback socket: {err}"
    );
    let (ok, out, err) = p.vox(&["room", "list"]);
    assert!(
        ok && out.contains("p-only-room"),
        "PRODUCT (staging): room list: {out} {err}"
    );

    // ---- (5) a client refuses what is at its socket path unless it is its own socket ----
    let (mut qd, q_sock) = q.daemon(None);
    signal(qd.pid(), "TERM");
    assert!(
        qd.exited_within(Duration::from_secs(30)).is_some(),
        "PRODUCT (staging): q's daemon did not stop"
    );
    assert!(
        std::fs::symlink_metadata(&q_sock).is_err(),
        "PRODUCT (staging): q's socket was left behind"
    );
    std::os::unix::fs::symlink(&sock, &q_sock).expect("APPARATUS: planting the symlink");
    let (ok, out, err) = q.vox(&["room", "list"]);
    eprintln!("[proof] room list at a planted symlink: ok={ok} stdout={out:?} stderr={err:?}");
    assert!(
        !out.contains("p-only-room"),
        "PRODUCT: a client sent its request to a socket that is not its own and was answered with \
         another profile's rooms: {out}"
    );
    assert!(
        !ok && err.contains("not a socket owned by you") && err.contains("symlink"),
        "PRODUCT: a client did not refuse a socket path that is not its own socket, saying so \
         (ok={ok}): {err}"
    );
    std::fs::remove_file(&q_sock).expect("APPARATUS: removing the planted symlink");

    // ---- (4) a per-user directory that is a symlink is refused, not followed ----
    let t3 = tmp.path().join("t3");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&t3).expect("APPARATUS: staging t3");
    std::fs::create_dir_all(&elsewhere).expect("APPARATUS: staging elsewhere");
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755))
        .expect("APPARATUS: staging elsewhere");
    std::os::unix::fs::symlink(&elsewhere, t3.join(format!("vox-{uid}")))
        .expect("APPARATUS: planting the symlinked per-user dir");
    let q3 = Profile {
        env: vec![(
            "TMPDIR".into(),
            t3.to_str()
                .expect("APPARATUS: a UTF-8 temp path")
                .to_owned(),
        )],
        ..Profile::new(&tmp.path().join("b".repeat(90)), &[])
    };
    let mut d3 = q3.spawn(&[
        "daemon",
        "--listen",
        "127.0.0.1:0",
        "--passphrase-file",
        q3.p(),
    ]);
    let ended = d3.exited_within(Duration::from_secs(120));
    let said = d3.said();
    eprintln!(
        "[proof] daemon with a symlinked vox-{uid}: ended={ended:?} said: {}",
        said.trim()
    );
    let touched: Vec<String> = std::fs::read_dir(&elsewhere)
        .expect("APPARATUS: list elsewhere")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let elsewhere_mode = std::fs::metadata(&elsewhere)
        .expect("APPARATUS: stat elsewhere")
        .mode()
        & 0o7777;
    assert_eq!(
        ended,
        Some(false),
        "PRODUCT: the daemon started with its socket directory a symlink: {said}"
    );
    assert!(
        said.contains("not a directory owned by you") && said.contains("symlink"),
        "PRODUCT: the refusal does not say the directory is a symlink not owned by you: {said}"
    );
    assert!(
        touched.is_empty() && elsewhere_mode == 0o755,
        "PRODUCT: the directory the symlink points at was used or changed: it holds {touched:?}, \
         mode {elsewhere_mode:o} (was 755)"
    );
    eprintln!("[proof] private dir 0700 (from 0777): 1; socket 0600: 1; sockets in <tmp>: 0; foreign socket refused: 1; symlinked dir refused: 1");
}

#[test]
#[ignore = "a real daemon under a descriptor limit; CI runs it in release"]
fn an_accept_error_does_not_end_the_control_socket() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let p = Profile::new(&tmp.path().join("p"), &[]);
    p.id();
    // `ulimit` then `exec`, so the daemon itself runs under the limit.
    let script = "ulimit -n 64 && exec \"$0\" daemon --listen 127.0.0.1:0 --passphrase-file \"$1\"";
    let mut c = Command::new("sh");
    c.args(["-c", script, VOX, p.p()])
        .env("VOX_DATA_DIR", &p.data)
        .env("VOX_CONFIG_DIR", &p.cfg)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ANCHORS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().expect("APPARATUS: spawn sh");
    let said = Arc::new(Mutex::new(String::new()));
    drain(child.stdout.take(), &said);
    drain(child.stderr.take(), &said);
    let mut daemon = Running(child, said);
    let out = daemon.wait_for("vox daemon: control socket ", Duration::from_secs(120));
    let sock = out
        .lines()
        .find_map(|l| l.strip_prefix("vox daemon: control socket "))
        .map(|s| PathBuf::from(s.trim()))
        .unwrap_or_else(|| panic!("PRODUCT: `vox daemon` named no control socket: {out}"));

    // Connect until one is never greeted: the daemon is out of descriptors and its accept fails.
    let mut held = Vec::new();
    let (mut greeted, mut ungreeted, mut refused) = (0usize, 0usize, 0usize);
    for _ in 0..120 {
        // A refused connect after an ungreeted one is the old defect showing already: the
        // accept loop has ended and dropped the listener. It stops the loading, not the proof.
        let Ok(mut s) = std::os::unix::net::UnixStream::connect(&sock) else {
            refused += 1;
            break;
        };
        s.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("APPARATUS: set a read timeout on the control socket");
        let mut len = [0u8; 4];
        if s.read_exact(&mut len).is_ok() {
            greeted += 1;
            ungreeted = 0;
        } else {
            ungreeted += 1;
        }
        held.push(s);
        if ungreeted >= 3 {
            break;
        }
    }
    eprintln!(
        "[proof] connections greeted before the limit: {greeted}; ungreeted (accept failed): \
         {ungreeted}; refused: {refused}"
    );
    assert!(
        ungreeted >= 1,
        "APPARATUS, CANNOT MEASURE: {greeted} connections were all greeted; the proof's \
         descriptor limit never ran the daemon out of descriptors"
    );
    drop(held);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        daemon.exited_within(Duration::ZERO).is_none(),
        "PRODUCT: the daemon died of the descriptor limit: {}",
        daemon.said()
    );
    let t0 = Instant::now();
    let (ok, out, err) = p.run(&["room", "list"], "", Duration::from_secs(20));
    eprintln!(
        "[proof] vox room list after the accept errors: ok={ok} in {:?}: {} {}",
        t0.elapsed(),
        out.trim(),
        err.trim()
    );
    assert!(
        ok,
        "PRODUCT: the control socket stopped answering after an accept error: {out} {err}"
    );
}

#[test]
fn shell_setup_keeps_the_rc_files_symlink_and_mode() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let home = tmp.path().join("home");
    let dotfiles = home.join("dotfiles");
    let staged = "APPARATUS: staging the person's rc files";
    std::fs::create_dir_all(&dotfiles).expect(staged);
    let target = dotfiles.join("zshrc");
    std::fs::write(&target, "export KEPT=1\n").expect(staged);
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect(staged);
    std::os::unix::fs::symlink(&target, home.join(".zshrc")).expect(staged);
    // A plain rc of another shell the person uses, at a mode of their choosing.
    std::fs::write(home.join(".bashrc"), "export ALSO=1\n").expect(staged);
    std::fs::set_permissions(home.join(".bashrc"), std::fs::Permissions::from_mode(0o640))
        .expect(staged);

    let run = |extra: &[&str]| {
        let out = Command::new(VOX)
            .arg("shell-setup")
            .args(extra)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("SHELL", "/bin/zsh")
            .output()
            .expect("APPARATUS: run vox shell-setup");
        assert!(
            out.status.success(),
            "PRODUCT: vox shell-setup {extra:?} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let mut kept = 0usize;
    for (step, extra) in [("setup", &[][..]), ("remove", &["--remove"][..])] {
        run(extra);
        let gone = |what: &str, e: std::io::Error| -> ! {
            panic!("PRODUCT: after {step}, the person's {what} is gone or unreadable: {e}")
        };
        let link =
            std::fs::symlink_metadata(home.join(".zshrc")).unwrap_or_else(|e| gone(".zshrc", e));
        let text = std::fs::read_to_string(&target).unwrap_or_else(|e| gone("zshrc target", e));
        let mode = std::fs::metadata(&target)
            .unwrap_or_else(|e| gone("zshrc target", e))
            .mode()
            & 0o7777;
        let bash_mode = std::fs::metadata(home.join(".bashrc"))
            .unwrap_or_else(|e| gone(".bashrc", e))
            .mode()
            & 0o7777;
        let bash =
            std::fs::read_to_string(home.join(".bashrc")).unwrap_or_else(|e| gone(".bashrc", e));
        eprintln!(
            "[proof] after {step}: .zshrc symlink={} target mode {mode:o}; .bashrc mode {bash_mode:o}",
            link.file_type().is_symlink()
        );
        let points_at = std::fs::read_link(home.join(".zshrc")).ok();
        assert!(
            link.file_type().is_symlink() && points_at.as_deref() == Some(target.as_path()),
            "PRODUCT: {step}: the symlinked .zshrc was replaced (symlink={}, points at \
             {points_at:?})",
            link.file_type().is_symlink()
        );
        assert_eq!(
            mode, 0o600,
            "PRODUCT: {step}: the rc file's mode was changed"
        );
        assert_eq!(
            bash_mode, 0o640,
            "PRODUCT: {step}: .bashrc's mode was changed"
        );
        assert!(
            text.contains("export KEPT=1") && bash.contains("export ALSO=1"),
            "PRODUCT: {step}: the person's own lines were lost:\n--- zshrc:\n{text}\n--- \
             .bashrc:\n{bash}"
        );
        let wired = text.contains("vox") && bash.contains("vox");
        assert_eq!(
            wired,
            step == "setup",
            "PRODUCT: {step}: the block was not {} through the symlink",
            if step == "setup" {
                "written"
            } else {
                "removed"
            }
        );
        kept += 1;
    }
    eprintln!("[proof] rc symlink and modes kept across setup and remove: {kept} of 2");
}

#[test]
fn a_room_passphrase_is_never_taken_from_argv_or_the_environment() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let p = Profile::new(&tmp.path().join("p"), &[]);
    // A node to run as: since ADR-026 a verb with no node refuses before it reads its flags.
    p.id();
    let room_pass = tmp.path().join("room.pass");
    std::fs::write(&room_pass, ROOM_PASS).expect("APPARATUS: the room passphrase file");
    let base = [
        "up",
        "aaaa",
        "--identity-passphrase-file",
        p.p(),
        "--listen",
        "127.0.0.1:0",
    ];
    let within = Duration::from_secs(120);

    let (ok, _, err) = p.run(
        &[&base[..], &["--passphrase", ROOM_PASS]].concat(),
        "",
        within,
    );
    eprintln!("[proof] --passphrase: ok={ok} {}", err.trim());
    assert!(
        !ok && err.contains("--passphrase is refused") && err.contains("--passphrase-file"),
        "PRODUCT: a room passphrase on the command line was not refused naming the replacement \
         (ok={ok}): {err}"
    );

    let mut with_env = Profile::new(&tmp.path().join("p"), &[]);
    with_env
        .env
        .push(("VOX_ROOM_PASSPHRASE".into(), ROOM_PASS.into()));
    let (ok, _, err) = with_env.run(&base, "", within);
    eprintln!("[proof] VOX_ROOM_PASSPHRASE: ok={ok} {}", err.trim());
    assert!(
        !ok && err.contains("VOX_ROOM_PASSPHRASE is refused"),
        "PRODUCT: a room passphrase in the environment was not refused (ok={ok}): {err}"
    );

    // The control: the file form gets past the passphrase check to the next step — the node,
    // attached, holds no room `aaaa` (since ADR-026 the node exists: C-3). A refusal by the check
    // is the product refusing the form it tells people to use.
    let (_, _, err) = p.run(
        &[
            &base[..],
            &[
                "--passphrase-file",
                room_pass.to_str().expect("APPARATUS: a UTF-8 temp path"),
            ],
        ]
        .concat(),
        "",
        within,
    );
    eprintln!("[proof] --passphrase-file: {}", err.trim());
    assert!(
        !err.contains("is refused"),
        "PRODUCT: --passphrase-file, the form the refusals name, was refused too: {err}"
    );
    assert!(
        err.contains("holds no rooms"),
        "PRODUCT (staging): --passphrase-file did not reach the room lookup after the check, so \
         this control does not show the file form passes it: {err}"
    );
    eprintln!(
        "[proof] room passphrase refused from argv: 1, from the environment: 1; file accepted: 1"
    );
}
