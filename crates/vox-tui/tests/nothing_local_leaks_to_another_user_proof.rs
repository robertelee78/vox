//! V210-72 (#263) — **the control socket, passphrases and shared files cannot leak to another
//! local user or process**, driven through the shipped `vox` binary.
//!
//! Seven findings from the v0.2.10 defect sweep, one claim each:
//!
//! 1. **A file offer is withdrawn however `vox room send` ends.** It was withdrawn only on
//!    Ctrl-C: a SIGTERM, a SIGHUP or a SIGKILL left the service registered, so a member's dial
//!    was carried to a port nobody served any more — or to whatever took that port next.
//!    Staged: alice offers a file, the offer is killed with each signal, bob asks for it, and
//!    alice's own daemon says why it refused bob. "no such service is offered in that room" is
//!    the withdrawn offer; "the local service did not accept the connection" is the leaked one.
//! 2. **An offer is never persisted.** It was: a daemon that stopped while an offer ran came
//!    back offering its port. Staged: alice's daemon is stopped with an offer live, and
//!    `vox service list` reads alice's store; a `vox service add` afterwards is the control
//!    that the listing shows a persisted service at all.
//! 3. **A get's forward is withdrawn however `vox room get` ends.** An interrupted get left
//!    bob's daemon listening on the forward's port. Staged: alice's offer is stopped (SIGSTOP)
//!    so the transfer stalls; the get is killed with each signal while bob's daemon listens on
//!    its forward (`lsof`), and the port must close.
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
//! Mutations, each red for its own reason: (1) the daemon not releasing what a closed
//! connection held; (2) an offer over the control socket persisted; (3) the same as (1), for
//! the forward; (4) the old flat `<tmp>/vox-<hex>.sock` fallback; (5) the client's owner check
//! removed; (6) the accept loop returning on its first error; (7) the rc written `0644` over
//! the path; (8) `--passphrase` accepted.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

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
                "CANNOT MEASURE: {what:?} was never said; said:\n{said}"
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
    assert!(ok, "CANNOT MEASURE: kill -s {sig} {pid} failed");
}

/// This user's uid, as the filesystem records it.
fn my_uid(tmp: &Path) -> u32 {
    std::fs::metadata(tmp).unwrap().uid()
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
        std::fs::create_dir_all(&cfg).unwrap();
        let pass = root.join("id.pass");
        std::fs::write(&pass, ID_PASS).unwrap();
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
            .expect("spawn vox");
        let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
        let (out, err) = (
            Arc::new(Mutex::new(String::new())),
            Arc::new(Mutex::new(String::new())),
        );
        drain(child.stdout.take(), &out);
        drain(child.stderr.take(), &err);
        let mut running = Running(child, Arc::new(Mutex::new(String::new())));
        let ended = running.exited_within(within);
        std::thread::sleep(Duration::from_millis(100));
        let (out, err) = (out.lock().unwrap().clone(), err.lock().unwrap().clone());
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
            .expect("spawn vox");
        let said = Arc::new(Mutex::new(String::new()));
        drain(child.stdout.take(), &said);
        drain(child.stderr.take(), &said);
        Running(child, said)
    }

    fn id(&self) -> String {
        let (ok, out, err) = self.vox(&["id", "--identity-passphrase-file", self.p()]);
        assert!(ok, "vox id: {err}");
        out.trim().to_owned()
    }

    fn p(&self) -> &str {
        self.pass.to_str().unwrap()
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
            .unwrap();
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
            "CANNOT MEASURE: the anchor printed no spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Poll `vox args` until its stdout satisfies `ok`, for up to 60 s.
fn until(who: &Profile, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) {
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
    panic!("CANNOT MEASURE: timed out waiting for {what}; last saw {last}");
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
    let tmp = tempfile::tempdir().unwrap();
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
        assert!(ok, "trust {name}: {err}");
    }
    let (ok, _, err) = alice.run(
        &["room", "create", "--name", "mission"],
        ROOM_PASS,
        Duration::from_secs(120),
    );
    assert!(ok, "room create: {err}");
    let label = alice.vox(&["room", "list"]).1;
    let label = label.split_whitespace().next().expect("a room").to_owned();
    let (ok, link, err) = alice.vox(&["room", "invite", &label]);
    assert!(ok, "room invite: {err}");
    let link = link.trim().to_owned();
    let room = link
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .expect("an invite naming the room")
        .to_owned();
    let mut joined = String::new();
    for _ in 0..6 {
        let (ok, _, err) = bob.run(
            &["room", "join", &link, "--name", "mission"],
            ROOM_PASS,
            Duration::from_secs(120),
        );
        if ok {
            joined.clear();
            break;
        }
        joined = err;
        std::thread::sleep(Duration::from_secs(5));
    }
    assert!(
        joined.is_empty(),
        "CANNOT MEASURE: bob never joined: {joined}"
    );
    for (who, other, word) in [(&alice, &bob, "warm-bob"), (&bob, &alice, "warm-alice")] {
        let (ok, _, err) = other.vox(&["room", "post", &room, word]);
        assert!(ok, "post: {err}");
        until(
            who,
            "each to read the other",
            &["room", "read", &room],
            |o| o.contains(word),
        );
    }

    // ---- (1) an offer ended by SIGTERM, SIGHUP or SIGKILL is withdrawn ----
    let mut withdrawn = 0usize;
    for (i, sig) in ["TERM", "HUP", "KILL"].into_iter().enumerate() {
        let name = format!("offer-{sig}.bin");
        let file = tmp.path().join(&name);
        std::fs::write(&file, vec![i as u8 + 1; 4096]).unwrap();
        let mut send = alice.spawn(&["room", "send", &room, file.to_str().unwrap()]);
        send.wait_for("vox: offering", Duration::from_secs(60));
        until(
            &bob,
            "the offer to reach bob",
            &["room", "read", &room],
            |o| o.contains(&name),
        );
        signal(send.pid(), sig);
        assert!(
            send.exited_within(Duration::from_secs(10)).is_some(),
            "CANNOT MEASURE: `vox room send` did not end on SIG{sig}"
        );
        let mark = alice_daemon.said().len();
        let out = tmp.path().join(format!("got-{sig}.bin"));
        let (ok, stdout, stderr) =
            bob.vox(&["room", "get", &room, &name, "--out", out.to_str().unwrap()]);
        assert!(
            !ok,
            "a withdrawn offer must not be collected: {stdout} {stderr}"
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
                "CANNOT MEASURE: alice's daemon never said why it refused bob after SIG{sig}; \
                 bob's get said: {stdout} {stderr}\nalice's daemon since:\n{said}"
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        eprintln!(
            "[proof] SIG{sig} of `room send`: alice's daemon said: {}",
            why.trim()
        );
        assert!(
            why.contains("no such service is offered in that room")
                && !why.contains("did not accept the connection"),
            "`vox room send` ended by SIG{sig} left its offer registered: alice's daemon \
             carried bob's dial to a port nobody serves:\n{why}"
        );
        withdrawn += 1;
    }
    eprintln!("[proof] offers withdrawn after SIGTERM/SIGHUP/SIGKILL: {withdrawn} of 3");

    // ---- (3) a get ended by SIGTERM, SIGHUP or SIGKILL closes its forward ----
    let Some(_) = listening(bob_daemon.pid()) else {
        panic!("CANNOT MEASURE: lsof cannot be run here");
    };
    let big = tmp.path().join("stalled.bin");
    std::fs::write(&big, vec![7u8; 1 << 20]).unwrap();
    let stalled = alice.spawn(&["room", "send", &room, big.to_str().unwrap()]);
    stalled.wait_for("vox: offering", Duration::from_secs(60));
    until(
        &bob,
        "the stalled offer to reach bob",
        &["room", "read", &room],
        |o| o.contains("stalled.bin"),
    );
    // Stopped, so the transfer stalls and the get is still running when it is signalled.
    signal(stalled.pid(), "STOP");
    let mut closed = 0usize;
    for sig in ["TERM", "HUP", "KILL"] {
        let before = listening(bob_daemon.pid()).unwrap();
        let out = tmp.path().join(format!("stalled-{sig}.bin"));
        let mut get = bob.spawn(&[
            "room",
            "get",
            &room,
            "stalled.bin",
            "--out",
            out.to_str().unwrap(),
        ]);
        let deadline = Instant::now() + Duration::from_secs(20);
        let forward = loop {
            let now = listening(bob_daemon.pid()).unwrap();
            if let Some(p) = now.difference(&before).next() {
                break p.clone();
            }
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE: bob's daemon never opened a forward for the get; it said: {}",
                get.said()
            );
            std::thread::sleep(Duration::from_millis(100));
        };
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            get.exited_within(Duration::ZERO).is_none(),
            "CANNOT MEASURE: the get ended before it was signalled: {}",
            get.said()
        );
        signal(get.pid(), sig);
        assert!(
            get.exited_within(Duration::from_secs(10)).is_some(),
            "CANNOT MEASURE: `vox room get` did not end on SIG{sig}"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let t0 = Instant::now();
        while listening(bob_daemon.pid()).unwrap().contains(&forward) {
            assert!(
                Instant::now() < deadline,
                "`vox room get` ended by SIG{sig} left bob's daemon listening on its forward \
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
    signal(stalled.pid(), "CONT");
    drop(stalled);
    eprintln!("[proof] forwards closed after SIGTERM/SIGHUP/SIGKILL: {closed} of 3");

    // ---- (2) an offer is never persisted: the daemon stops while one runs ----
    let live = tmp.path().join("live.bin");
    std::fs::write(&live, b"offered while the daemon stops").unwrap();
    let live_send = alice.spawn(&["room", "send", &room, live.to_str().unwrap()]);
    let offered = live_send.wait_for("vox: offering", Duration::from_secs(60));
    let tag = offered
        .split_whitespace()
        .find(|w| w.starts_with("file-"))
        .expect("the offer's tag")
        .to_owned();
    let mut alice_daemon = alice_daemon;
    signal(alice_daemon.pid(), "TERM");
    assert!(
        alice_daemon
            .exited_within(Duration::from_secs(30))
            .is_some(),
        "CANNOT MEASURE: alice's daemon did not stop on SIGTERM"
    );
    drop(live_send);
    let room_pass = tmp.path().join("room.pass");
    std::fs::write(&room_pass, ROOM_PASS).unwrap();
    let list = |what: &str| {
        let (ok, out, err) = alice.vox(&[
            "service",
            "list",
            &room,
            "--passphrase-file",
            room_pass.to_str().unwrap(),
            "--identity-passphrase-file",
            alice.p(),
            "--listen",
            "127.0.0.1:0",
        ]);
        assert!(ok, "CANNOT MEASURE: vox service list ({what}): {err}");
        eprintln!("[proof] vox service list ({what}): {}", out.trim());
        out
    };
    let after = list("after the daemon stopped with an offer live");
    // The control: the listing shows a persisted service when there is one.
    let (ok, _, err) = alice.vox(&[
        "service",
        "add",
        &room,
        "kept",
        "127.0.0.1:9",
        "--passphrase-file",
        room_pass.to_str().unwrap(),
        "--identity-passphrase-file",
        alice.p(),
        "--listen",
        "127.0.0.1:0",
    ]);
    assert!(ok, "CANNOT MEASURE: vox service add: {err}");
    let control = list("control, after `vox service add kept`");
    assert!(
        control.contains("kept"),
        "CANNOT MEASURE: `vox service list` does not show a persisted service: {control}"
    );
    assert!(
        !after.contains(&tag) && !after.contains("file-"),
        "an offer over the control socket was persisted: alice's store still offers {tag} \
         after her daemon stopped:\n{after}"
    );
    eprintln!("[proof] offers persisted across a daemon stop: 0 (control service listed: 1)");
}

#[test]
#[ignore = "real daemons and production Argon2id; CI runs it in release"]
fn the_control_socket_is_private_and_a_client_refuses_one_that_is_not_its_own() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let uid = my_uid(tmp.path());
    let t = tmp.path().join("t");
    std::fs::create_dir_all(&t).unwrap();
    let t_env = [("TMPDIR", t.to_str().unwrap())];
    // Profile paths over the 100-byte socket budget, so the fallback is the one used.
    let p = Profile::new(&tmp.path().join("a".repeat(90)), &t_env);
    let q = Profile::new(&tmp.path().join("b".repeat(90)), &t_env);
    assert!(
        p.data.join("default").join("node.sock").as_os_str().len() > 104,
        "CANNOT MEASURE: the profile path is short enough for the natural socket"
    );
    p.id();
    q.id();

    // ---- (4) the fallback directory is private, even if it was left wide open ----
    let private = t.join(format!("vox-{uid}"));
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o777)).unwrap();
    let (_pd, sock) = p.daemon(None);
    eprintln!("[proof] fallback socket: {}", sock.display());
    assert_eq!(
        sock.parent(),
        Some(private.as_path()),
        "the fallback socket is not in the per-user directory {}",
        private.display()
    );
    let dir_meta = std::fs::symlink_metadata(&private).unwrap();
    let sock_meta = std::fs::symlink_metadata(&sock).unwrap();
    eprintln!(
        "[proof] {} mode {:o} uid {}; socket mode {:o} uid {}",
        private.display(),
        dir_meta.mode() & 0o7777,
        dir_meta.uid(),
        sock_meta.mode() & 0o7777,
        sock_meta.uid()
    );
    assert!(dir_meta.is_dir() && dir_meta.mode() & 0o7777 == 0o700 && dir_meta.uid() == uid);
    assert!(
        sock_meta.file_type().is_socket()
            && sock_meta.mode() & 0o7777 == 0o600
            && sock_meta.uid() == uid
    );
    let in_tmp: Vec<String> = std::fs::read_dir(&t)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".sock"))
        .collect();
    assert!(
        in_tmp.is_empty(),
        "a control socket landed in the shared temp directory itself: {in_tmp:?}"
    );
    let (ok, _, err) = p.run(
        &["room", "create", "--name", "p-only-room"],
        ROOM_PASS,
        Duration::from_secs(120),
    );
    assert!(
        ok,
        "CANNOT MEASURE: room create through the fallback socket: {err}"
    );
    let (ok, out, err) = p.vox(&["room", "list"]);
    assert!(
        ok && out.contains("p-only-room"),
        "CANNOT MEASURE: room list: {out} {err}"
    );

    // ---- (5) a client refuses what is at its socket path unless it is its own socket ----
    let (mut qd, q_sock) = q.daemon(None);
    signal(qd.pid(), "TERM");
    assert!(
        qd.exited_within(Duration::from_secs(30)).is_some(),
        "CANNOT MEASURE: q's daemon did not stop"
    );
    assert!(
        std::fs::symlink_metadata(&q_sock).is_err(),
        "CANNOT MEASURE: q's socket was left behind"
    );
    std::os::unix::fs::symlink(&sock, &q_sock).unwrap();
    let (ok, out, err) = q.vox(&["room", "list"]);
    eprintln!("[proof] room list at a planted symlink: ok={ok} stdout={out:?} stderr={err:?}");
    assert!(
        !out.contains("p-only-room"),
        "a client sent its request to a socket that is not its own and was answered with \
         another profile's rooms: {out}"
    );
    assert!(
        !ok && err.contains("not a socket owned by you") && err.contains("symlink"),
        "a client must refuse a socket path that is not its own socket, and say so: {err}"
    );
    std::fs::remove_file(&q_sock).unwrap();

    // ---- (4) a per-user directory that is a symlink is refused, not followed ----
    let t3 = tmp.path().join("t3");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&t3).unwrap();
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, t3.join(format!("vox-{uid}"))).unwrap();
    let q3 = Profile {
        env: vec![("TMPDIR".into(), t3.to_str().unwrap().to_owned())],
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
    let touched: Vec<_> = std::fs::read_dir(&elsewhere).unwrap().collect();
    assert_eq!(
        ended,
        Some(false),
        "the daemon started with its socket directory a symlink: {said}"
    );
    assert!(
        said.contains("not a directory owned by you") && said.contains("symlink"),
        "the refusal must say why: {said}"
    );
    assert!(
        touched.is_empty() && std::fs::metadata(&elsewhere).unwrap().mode() & 0o7777 == 0o755,
        "the directory the symlink points at was used or changed"
    );
    eprintln!("[proof] private dir 0700 (from 0777): 1; socket 0600: 1; sockets in <tmp>: 0; foreign socket refused: 1; symlinked dir refused: 1");
}

#[test]
#[ignore = "a real daemon under a descriptor limit; CI runs it in release"]
fn an_accept_error_does_not_end_the_control_socket() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
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
    let mut child = c.spawn().expect("spawn sh");
    let said = Arc::new(Mutex::new(String::new()));
    drain(child.stdout.take(), &said);
    drain(child.stderr.take(), &said);
    let mut daemon = Running(child, said);
    let out = daemon.wait_for("vox daemon: control socket ", Duration::from_secs(120));
    let sock = out
        .lines()
        .find_map(|l| l.strip_prefix("vox daemon: control socket "))
        .map(|s| PathBuf::from(s.trim()))
        .unwrap();

    // Connect until one is never greeted: the daemon is out of descriptors and its accept fails.
    let mut held = Vec::new();
    let (mut greeted, mut ungreeted) = (0usize, 0usize);
    for _ in 0..120 {
        let Ok(mut s) = std::os::unix::net::UnixStream::connect(&sock) else {
            break;
        };
        s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
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
    eprintln!("[proof] connections greeted before the limit: {greeted}; ungreeted: {ungreeted}");
    assert!(
        ungreeted >= 3,
        "CANNOT MEASURE: {greeted} connections were all greeted; the daemon never ran out of \
         descriptors"
    );
    drop(held);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        daemon.exited_within(Duration::ZERO).is_none(),
        "CANNOT MEASURE: the daemon died of the descriptor limit: {}",
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
        "the control socket stopped answering after an accept error: {out} {err}"
    );
}

#[test]
fn shell_setup_keeps_the_rc_files_symlink_and_mode() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let dotfiles = home.join("dotfiles");
    std::fs::create_dir_all(&dotfiles).unwrap();
    let target = dotfiles.join("zshrc");
    std::fs::write(&target, "export KEPT=1\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, home.join(".zshrc")).unwrap();
    // A plain rc of another shell the person uses, at a mode of their choosing.
    std::fs::write(home.join(".bashrc"), "export ALSO=1\n").unwrap();
    std::fs::set_permissions(home.join(".bashrc"), std::fs::Permissions::from_mode(0o640)).unwrap();

    let run = |extra: &[&str]| {
        let out = Command::new(VOX)
            .arg("shell-setup")
            .args(extra)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("SHELL", "/bin/zsh")
            .output()
            .expect("shell-setup ran");
        assert!(
            out.status.success(),
            "vox shell-setup {extra:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let mut kept = 0usize;
    for (step, extra) in [("setup", &[][..]), ("remove", &["--remove"][..])] {
        run(extra);
        let link = std::fs::symlink_metadata(home.join(".zshrc")).unwrap();
        let text = std::fs::read_to_string(&target).unwrap();
        let mode = std::fs::metadata(&target).unwrap().mode() & 0o7777;
        let bash_mode = std::fs::metadata(home.join(".bashrc")).unwrap().mode() & 0o7777;
        let bash = std::fs::read_to_string(home.join(".bashrc")).unwrap();
        eprintln!(
            "[proof] after {step}: .zshrc symlink={} target mode {mode:o}; .bashrc mode {bash_mode:o}",
            link.file_type().is_symlink()
        );
        assert!(
            link.file_type().is_symlink()
                && std::fs::read_link(home.join(".zshrc")).unwrap() == target,
            "{step}: the symlinked .zshrc was replaced by a plain file"
        );
        assert_eq!(mode, 0o600, "{step}: the rc file's mode was changed");
        assert_eq!(bash_mode, 0o640, "{step}: .bashrc's mode was changed");
        assert!(text.contains("export KEPT=1") && bash.contains("export ALSO=1"));
        let wired = text.contains("vox") && bash.contains("vox");
        assert_eq!(
            wired,
            step == "setup",
            "{step}: the block was not {} through the symlink",
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
    let tmp = tempfile::tempdir().unwrap();
    let p = Profile::new(&tmp.path().join("p"), &[]);
    let room_pass = tmp.path().join("room.pass");
    std::fs::write(&room_pass, ROOM_PASS).unwrap();
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
        "a room passphrase on the command line must be refused, naming the replacement: {err}"
    );

    let mut with_env = Profile::new(&tmp.path().join("p"), &[]);
    with_env
        .env
        .push(("VOX_ROOM_PASSPHRASE".into(), ROOM_PASS.into()));
    let (ok, _, err) = with_env.run(&base, "", within);
    eprintln!("[proof] VOX_ROOM_PASSPHRASE: ok={ok} {}", err.trim());
    assert!(
        !ok && err.contains("VOX_ROOM_PASSPHRASE is refused"),
        "a room passphrase in the environment must be refused: {err}"
    );

    // The control: the file form gets past the passphrase to the room, which does not exist.
    let (_, _, err) = p.run(
        &[
            &base[..],
            &["--passphrase-file", room_pass.to_str().unwrap()],
        ]
        .concat(),
        "",
        within,
    );
    eprintln!("[proof] --passphrase-file: {}", err.trim());
    assert!(
        !err.contains("is refused"),
        "CANNOT MEASURE: --passphrase-file was refused too: {err}"
    );
    eprintln!(
        "[proof] room passphrase refused from argv: 1, from the environment: 1; file accepted: 1"
    );
}
