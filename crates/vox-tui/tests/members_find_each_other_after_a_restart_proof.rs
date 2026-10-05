//! **V210-167 — members find each other again after a restart, with no anchor**, through the
//! shipped `vox` binary only: two `vox daemon`s on this computer, every step typed as an operator
//! types it (`vox id`, `vox room create|invite|join|post|read`, `vox trust add`).
//!
//! ## The defect
//! A node bound a new random port on every start, and a node that is not an anchor keeps its
//! board in memory: after a restart the joiner knew the host only at the address it joined by,
//! and the host knew nothing of the joiner. When both restarted they never met again, and
//! `vox room join` with the host's new address was refused ("already holds that room").
//!
//! ## What is asserted
//! - both restart together: each reads the other's post within 60 s;
//! - both restart, and another program has taken the host's port meanwhile: the host says it
//!   listens elsewhere, and each reads the other's post within 60 s — the joiner can only have
//!   found it on this computer, since it dials the old port.
//!
//! On demand (`--include-ignored`), never a gate.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/layout.rs"]
mod layout;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How long a member has to read the other's post after the restart.
const AFTER_RESTART: Duration = Duration::from_secs(60);

/// Everything a harness might have put in this process's environment (see `support/room.rs`).
const HARNESS_VARS: [&str; 13] = [
    "VOX_SESSION",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
    "VOX_ROOM",
    "VOX_AGENT_NAME",
    "CLAUDE_CODE_MESSAGING_SOCKET",
    "CLAUDE_CODE_MESSAGING_TOKEN",
    "VOX_OPENCODE_WAKE_SOCKET",
    "VOX_OPENCODE_WAKE_TOKEN",
    "VOX_HARNESS",
    "VOX_ANCHORS",
    "VOX_LISTEN",
];

struct Member {
    name: &'static str,
    dir: PathBuf,
    pass: PathBuf,
    fp: String,
    daemon: Option<Child>,
}

impl Member {
    /// Stop the daemon as a person does (SIGTERM), and wait for it.
    fn stop(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            let _ = Command::new("kill").arg(child.id().to_string()).status();
            let deadline = Instant::now() + Duration::from_secs(20);
            while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// The port this node keeps: its own `<data>/nodes/default/port`, else the data root's
    /// `<data>/.daemon/port` (ADR-026 D-3), where a daemon of several nodes keeps its one port.
    fn kept_port(&self) -> u16 {
        let read = |p: PathBuf| {
            std::fs::read_to_string(p)
                .ok()
                .and_then(|t| t.trim().parse().ok())
        };
        read(layout::node_dir(&self.dir, layout::DEFAULT_NODE).join("port"))
            .or_else(|| read(layout::daemon_dir(&self.dir).join("port")))
            .unwrap_or_else(|| {
                panic!(
                    "PRODUCT (staging): {} records no port it first bound, in its node's \
                     directory or the daemon's",
                    self.name
                )
            })
    }

    fn daemon_said(&self, tag: &str) -> String {
        std::fs::read_to_string(self.dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    use std::io::Write as _;
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for v in HARNESS_VARS {
        cmd.env_remove(v);
    }
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn member(tmp: &Path, name: &'static str) -> Member {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let pass = tmp.join(format!("{name}.pass"));
    std::fs::write(&pass, IDPASS).unwrap();
    let (ok, out, err) = vox(&dir, &["id"], None);
    assert!(ok, "{name}: vox id: {err}");
    Member {
        name,
        dir,
        pass,
        fp: out.trim().to_owned(),
        daemon: None,
    }
}

/// `vox daemon` with no `--listen` and no anchor: what a person runs.
fn start_daemon(m: &mut Member, tag: &str) {
    let err = m.dir.join(format!("daemon-{tag}.err"));
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--passphrase-file"])
        .arg(&m.pass)
        .env("VOX_DATA_DIR", &m.dir)
        .env("VOX_CONFIG_DIR", m.dir.join("cfg"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&err).unwrap()));
    for v in HARNESS_VARS {
        cmd.env_remove(v);
    }
    m.daemon = Some(cmd.spawn().expect("spawn vox daemon"));
    let deadline = Instant::now() + Duration::from_secs(60);
    while !vox(&m.dir, &["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "{}'s daemon never answered",
            m.name
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Keep `author` posting probes tagged `tag` until `reader` renders one, or `within` ends.
fn until_read(
    author: &Member,
    reader: &Member,
    room: &str,
    tag: &str,
    within: Duration,
) -> Option<Duration> {
    let t0 = Instant::now();
    let mut n = 0u32;
    while t0.elapsed() < within {
        n += 1;
        let _ = vox(
            &author.dir,
            &["room", "post", room, &format!("{tag} {n}")],
            None,
        );
        std::thread::sleep(Duration::from_millis(1500));
        let (_, out, _) = vox(&reader.dir, &["room", "read", room], None);
        if out.lines().any(|l| l.contains(&format!("{tag} "))) {
            return Some(t0.elapsed());
        }
    }
    None
}

/// alice creates a room, bob joins it by its address, they trust each other and read each other.
fn a_pair(tmp: &Path) -> (Member, Member, String) {
    let mut alice = member(tmp, "alice");
    let mut bob = member(tmp, "bob");
    start_daemon(&mut alice, "start");
    start_daemon(&mut bob, "start");
    let (ok, _, err) = vox(
        &alice.dir,
        &["room", "create", "--passphrase-file", "-", "--name", "pair"],
        Some(ROOMPASS),
    );
    assert!(ok, "CANNOT MEASURE: room create: {err}");
    let (_, listed, _) = vox(&alice.dir, &["room", "list"], None);
    let room = listed
        .split_whitespace()
        .next()
        .expect("the room in `vox room list`")
        .to_owned();
    let (ok, link, err) = vox(&alice.dir, &["room", "link", &room], None);
    assert!(ok, "CANNOT MEASURE: room link: {err}");
    let (ok, _, err) = vox(
        &bob.dir,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(ROOMPASS),
    );
    assert!(ok, "CANNOT MEASURE: bob could not join: {err}");
    for (a, b) in [(&alice, &bob), (&bob, &alice)] {
        let (ok, _, err) = vox(
            &a.dir,
            &[
                "trust",
                "add",
                &b.fp,
                "--name",
                b.name,
                "--identity-passphrase-file",
                a.pass.to_str().unwrap(),
            ],
            None,
        );
        assert!(ok, "CANNOT MEASURE: {} trusts {}: {err}", a.name, b.name);
    }
    for (a, r) in [(&alice, &bob), (&bob, &alice)] {
        assert!(
            until_read(a, r, &room, "ready", AFTER_RESTART).is_some(),
            "CANNOT MEASURE: {} never read {} before the restart",
            r.name,
            a.name
        );
    }
    (alice, bob, room)
}

fn read_each_other_again(alice: &Member, bob: &Member, room: &str) {
    for (a, r) in [(alice, bob), (bob, alice)] {
        let took = until_read(a, r, room, &format!("after {}", a.name), AFTER_RESTART);
        assert!(
            took.is_some(),
            "{} never read {} after both restarted, within {AFTER_RESTART:?}; {}'s daemon \
             said:\n{}",
            r.name,
            a.name,
            r.name,
            r.daemon_said("again")
        );
        eprintln!("[proof] {} read {} {took:?} after", r.name, a.name);
    }
}

#[test]
#[ignore = "on demand: real vox daemons and production Argon2id"]
fn two_members_restarted_together_read_each_other() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (mut alice, mut bob, room) = a_pair(tmp.path());
    let ports = (alice.kept_port(), bob.kept_port());
    alice.stop();
    bob.stop();
    start_daemon(&mut alice, "again");
    start_daemon(&mut bob, "again");
    assert_eq!(
        (alice.kept_port(), bob.kept_port()),
        ports,
        "a profile's port changed across a restart"
    );
    read_each_other_again(&alice, &bob, &room);
}

#[test]
#[ignore = "on demand: real vox daemons and production Argon2id"]
fn a_member_whose_port_was_taken_is_found_again() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (mut alice, mut bob, room) = a_pair(tmp.path());
    alice.stop();
    bob.stop();
    // Another program takes the host's port while both are down.
    let port = alice.kept_port();
    let _held = std::net::UdpSocket::bind(("0.0.0.0", port))
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: could not take port {port}: {e}"));
    start_daemon(&mut alice, "again");
    start_daemon(&mut bob, "again");
    let said = alice.daemon_said("again");
    assert!(
        said.contains(&format!("port {port} is not free")),
        "alice's daemon did not say its port was taken; it said:\n{said}"
    );
    read_each_other_again(&alice, &bob, &room);
}
