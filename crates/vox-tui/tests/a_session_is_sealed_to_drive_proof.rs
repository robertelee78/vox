//! **ADR-029 SC-2, SC-2a, SC-2b (#543) — a Session is read only by the members its node trusts
//! with drive**, through the shipped `vox` binary: a `vox node` anchor and three `vox daemon`s.
//!
//! ## The claims
//! 1. **Read only with drive** (SC-2, SC-2a, SC-4). Alice's node trusts bob with read + drive
//!    and carol with read only. The entries of alice's Session reach both of their nodes in the
//!    room's log, and bob's node opens every one of them; carol's opens none, though it reads
//!    alice's messages to the room written before and after them. Neither shows Session activity
//!    in the room's timeline (`vox room read`).
//! 2. **Losing drive changes the key** (SC-2b). Alice downgrades bob to read (`vox trust read`).
//!    Bob's node opens none of the entries alice's Session writes afterwards, while it still holds
//!    the ones it read before and still reads alice's messages to the room.
//!
//! ## The staging
//! - Every `vox` is the shipped binary in a scratch `VOX_DATA_DIR`/`VOX_CONFIG_DIR`; every step a
//!   person takes is typed as one types it (`vox id`, `vox room create|link|join|post|read`,
//!   `vox trust add [--drive]`, `vox trust read`).
//! - A Session's entries are written as its harness's hook writes them: through the daemon's
//!   control socket ([`Request::AppendSession`]), in the harnesses' activity format, the proof
//!   speaking that protocol itself as apparatus (staging). Each member's verdict is read as a
//!   person reads a Session: `vox room session ROOM SESSION --json`.
//! - Positive controls make each "none" mean something: carol reads a room message alice posts
//!   after the Session entries, so her node has synced past them; bob, after the downgrade, reads a
//!   room message alice posts after the later entries.
//!
//! ## The mutations that must turn it red
//! - **Release the drive key on read** (claim 1): `drive_holders` in
//!   `crates/vox-core/src/node/actor.rs` returns every trusted node. Carol's node opens alice's
//!   Session entries: red PRODUCT.
//! - **No rotation on losing drive** (claim 2): `rotate_drive_if_lost` in
//!   `crates/vox-core/src/node/channel.rs` returns the lost members without changing the key. Bob's
//!   node opens the entries written after his downgrade: red PRODUCT.
#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/typed.rs"]
mod typed;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const ID_PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";
/// The harness session id alice's Session carries.
const SESSION: &str = "3f0c25bf-1d2e-4c5b-9a8f-session-proof";
/// How many entries alice's Session writes before, and after, bob's downgrade.
const ENTRIES: usize = 3;

/// A child killed and reaped by its own PID when dropped — never by pattern.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Member {
    name: &'static str,
    data: PathBuf,
    pass: PathBuf,
    fp: String,
    _daemon: Option<Proc>,
}

impl Member {
    fn vox(&self, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13): the passphrase file's first line, typed at the prompt.
        if typed::is_keyring_change(args) {
            let mut cmd = Command::new(VOX);
            cmd.args(args)
                .env("VOX_DATA_DIR", &self.data)
                .env("VOX_CONFIG_DIR", self.data.join("cfg"))
                .env_remove("VOX_ROOM")
                .env_remove("VOX_SESSION")
                .env_remove("VOX_ROOM_PASSPHRASE");
            let (ok, shown) = typed::keyring(&cmd);
            return (ok, shown.clone(), shown);
        }
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", self.data.join("cfg"))
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .env_remove("VOX_ROOM_PASSPHRASE")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("APPARATUS: spawn vox");
        if let Some(text) = stdin {
            child
                .stdin
                .take()
                .expect("APPARATUS: vox's stdin")
                .write_all(text.as_bytes())
                .expect("APPARATUS (staging): vox exited without reading its stdin");
        }
        let out = child.wait_with_output().expect("APPARATUS: wait for vox");
        let r = (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        eprintln!(
            "[receipt] <{}> vox {} -> {}\n  stdout: {}\n  stderr: {}",
            self.name,
            args.join(" "),
            r.0,
            r.1.trim(),
            r.2.trim()
        );
        r
    }

    fn reads(&self, room: &str, text: &str) -> bool {
        self.vox(&["room", "read", room], None).1.contains(text)
    }

    fn pass(&self) -> &str {
        self.pass.to_str().expect("APPARATUS: a UTF-8 temp path")
    }

    /// `vox trust add`, with drive when `drive`.
    fn trust(&self, other: &Member, drive: bool) {
        let mut args = vec![
            "trust",
            "add",
            &other.fp,
            "--name",
            other.name,
            "--identity-passphrase-file",
            self.pass(),
        ];
        if drive {
            args.push("--drive");
        }
        let (ok, o, e) = self.vox(&args, None);
        assert!(
            ok,
            "APPARATUS (staging): {} could not trust {}: {o}{e}",
            self.name, other.name
        );
    }

    /// The node's control socket, as the TUI and the app reach it.
    fn socket(&self, rt: &tokio::runtime::Runtime) -> IpcClient {
        let paths = vox_core::node::paths::Paths::resolve(
            "default",
            Some(&self.data),
            Some(&self.data.join("cfg")),
        )
        .expect("APPARATUS: resolve a data root's paths");
        rt.block_on(IpcClient::open_at(&NodeSocket::one_shot(
            paths.account().socket(),
            vox_core::node::paths::NodeName::parse("default").expect("APPARATUS: a node name"),
        )))
        .unwrap_or_else(|e| {
            panic!(
                "PRODUCT: {}'s node did not answer its socket: {e}",
                self.name
            )
        })
    }
}

fn member(tmp: &Path, name: &'static str, anchor: &str) -> Member {
    let data = tmp.join(name);
    std::fs::create_dir_all(data.join("cfg")).expect("APPARATUS: create a staging dir");
    let pass = tmp.join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS).expect("APPARATUS: write a staging file");
    let mut m = Member {
        name,
        data,
        pass,
        fp: String::new(),
        _daemon: None,
    };
    let (ok, out, err) = m.vox(&["id", "--identity-passphrase-file", m.pass()], None);
    assert!(ok, "APPARATUS (staging): {name}: vox id: {err}");
    m.fp = out.trim().to_owned();
    assert_eq!(
        m.fp.len(),
        52,
        "PRODUCT: `vox id` printed no 52-character fingerprint for {name}: {:?}",
        m.fp
    );
    let err = std::fs::File::create(tmp.join(format!("{name}.daemon.err")))
        .expect("APPARATUS: create a log file");
    let child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0", "--anchor", anchor])
        .arg("--passphrase-file")
        .arg(&m.pass)
        .env("VOX_DATA_DIR", &m.data)
        .env("VOX_CONFIG_DIR", m.data.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    m._daemon = Some(Proc(child));
    let deadline = Instant::now() + Duration::from_secs(90);
    while !m.vox(&["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "APPARATUS (staging): {name}'s daemon never answered"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    m
}

fn anchor(tmp: &Path) -> (Proc, String) {
    let dir = tmp.join("anchor");
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: create a staging dir");
    let out = tmp.join("anchor.out");
    let p = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .stdout(Stdio::from(
                std::fs::File::create(&out).expect("APPARATUS: create a log file"),
            ))
            .stderr(Stdio::null())
            .spawn()
            .expect("APPARATUS: spawn vox node"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if let Some(spec) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (p, spec.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "APPARATUS (staging): the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Keep `author` posting fresh `tag n` lines until `reader` renders one. Returns whether it did.
fn posts_until_read(author: &Member, reader: &Member, room: &str, tag: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut n = 0u32;
    while Instant::now() < deadline {
        n += 1;
        let (ok, _, e) = author.vox(&["room", "post", room, &format!("{tag} {n}")], None);
        assert!(
            ok,
            "PRODUCT: `vox room post` failed for {}: {e}",
            author.name
        );
        std::thread::sleep(Duration::from_secs(1));
        if reader.reads(room, &format!("{tag} ")) {
            return true;
        }
    }
    false
}

fn until(within: Duration, ok: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

/// The id `vox room list` prints for the room named `name`.
fn room_id(m: &Member, name: &str) -> String {
    let (ok, list, e) = m.vox(&["room", "list"], None);
    assert!(ok, "APPARATUS (staging): {}'s room list: {e}", m.name);
    list.lines()
        .find(|l| l.split_whitespace().any(|w| w == name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| {
            panic!(
                "APPARATUS (staging): {name} is not in {}'s list: {list}",
                m.name
            )
        })
        .to_owned()
}

/// The room's whole id on `m`'s node, from the short one `vox room list` prints.
fn channel_id(rt: &tokio::runtime::Runtime, m: &Member, short: &str) -> [u8; 32] {
    match rt.block_on(m.socket(rt).rooms()) {
        Ok(Frame::Rooms { rooms }) => rooms
            .iter()
            .map(|(id, _, _, _)| *id)
            .find(|id| vox_core::node::link::b32_encode(id).starts_with(short))
            .unwrap_or_else(|| panic!("APPARATUS (staging): the room is not on {}'s node", m.name)),
        other => panic!("APPARATUS (staging): {}'s rooms: {other:?}", m.name),
    }
}

/// One reply of alice's Session, in the harnesses' activity format.
fn reply(seq: usize, text: &str) -> String {
    serde_json::json!({ "v": 1, "session": SESSION, "kind": "reply", "seq": seq, "text": text })
        .to_string()
}

/// The replies of alice's Session that `m` reads, as `vox room session --json` gives them: what
/// each line says after "reply: ". A member that can open none is told no Session answers.
fn opened(m: &Member, room: &str) -> Vec<String> {
    let (_, out, _) = m.vox(&["room", "session", room, SESSION, "--json"], None);
    out.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["kind"] == "reply")
        .filter_map(|v| {
            v["line"]
                .as_str()
                .and_then(|l| l.strip_prefix("reply: "))
                .map(str::to_owned)
        })
        .collect()
}

/// How many entries `m`'s node holds in the room, as `vox status --json` counts them.
fn entries(m: &Member, room: &str) -> u64 {
    let (_, o, _) = m.vox(&["status", "--json"], None);
    let v: serde_json::Value = serde_json::from_str(&o).unwrap_or_default();
    v["rooms"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["id"].as_str().is_some_and(|id| id.starts_with(room)))
        .and_then(|r| r["entries"].as_u64())
        .unwrap_or(0)
}

#[test]
#[ignore = "an anchor and three daemons with production Argon2id; CI runs it in release"]
fn a_session_is_read_only_by_members_with_drive_and_a_downgrade_changes_its_key() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a runtime");
    let (_anchor, spec) = anchor(tmp.path());
    let alice = member(tmp.path(), "alice", &spec);
    let bob = member(tmp.path(), "bob", &spec);
    let carol = member(tmp.path(), "carol", &spec);

    // ---- one room; alice trusts bob with drive and carol with read; they trust her back ----
    let (ok, _, e) = alice.vox(
        &["room", "create", "--passphrase-file", "-", "--name", "repo"],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "APPARATUS (staging): vox room create failed: {e}");
    let room = room_id(&alice, "repo");
    let (ok, link, e) = alice.vox(&["room", "link", &room], None);
    assert!(ok, "APPARATUS (staging): vox room link failed: {e}");
    for m in [&bob, &carol] {
        let (ok, o, e) = m.vox(
            &["room", "join", "--passphrase-file", "-", link.trim()],
            Some(&format!("{ROOM_PASS}\n")),
        );
        assert!(ok, "PRODUCT: `vox room join` failed for {}: {o}{e}", m.name);
    }
    alice.trust(&bob, true);
    alice.trust(&carol, false);
    bob.trust(&alice, false);
    carol.trust(&alice, false);
    assert!(
        posts_until_read(&alice, &bob, &room, "READY-BOB")
            && posts_until_read(&alice, &carol, &room, "READY-CAROL"),
        "APPARATUS (staging): bob and carol never read alice's room messages"
    );
    let id = channel_id(&rt, &alice, &room);

    // ---- claim 1: alice's Session writes entries; bob opens them, carol none ----
    let before: Vec<String> = (1..=ENTRIES)
        .map(|n| format!("BEFORE-DOWNGRADE {n}"))
        .collect();
    let carol_held = entries(&carol, &room);
    for (n, text) in before.iter().enumerate() {
        match rt.block_on(alice.socket(&rt).request(&Request::AppendSession {
            channel_id: id,
            session_id: SESSION.to_owned(),
            body: reply(n + 1, text),
        })) {
            Ok(Frame::Appended { .. }) => {}
            other => panic!("PRODUCT: alice's node refused a Session entry: {other:?}"),
        }
    }
    let bob_read = until(Duration::from_secs(120), || opened(&bob, &room) == before);
    // Carol's control: a room message alice posts after the entries, read by carol, so her node
    // holds the log past them.
    let carol_synced = posts_until_read(&alice, &carol, &room, "AFTER-ENTRIES");
    let carol_holds = entries(&carol, &room).saturating_sub(carol_held);
    let carol_opened = opened(&carol, &room);
    let timeline_bob = bob.vox(&["room", "read", &room], None).1;
    let timeline_carol = carol.vox(&["room", "read", &room], None).1;
    eprintln!(
        "[proof] claim 1: bob opened {:?}; carol synced past them: {carol_synced}, holds {carol_holds} \
         new entries, opened {carol_opened:?}",
        opened(&bob, &room)
    );
    assert!(
        carol_synced && carol_holds as usize >= ENTRIES,
        "APPARATUS (staging): carol's node never held the log past alice's Session entries ({carol_holds} \
         new entries, synced {carol_synced}), so her opening none would say nothing"
    );
    assert!(
        bob_read,
        "PRODUCT: bob, whom alice trusts with drive, must open every entry of her Session: he \
         opened {:?}",
        opened(&bob, &room)
    );
    assert!(
        carol_opened.is_empty(),
        "PRODUCT: carol, whom alice trusts with read only, must open none of her Session's \
         entries: she opened {carol_opened:?}"
    );
    assert!(
        !timeline_bob.contains("BEFORE-DOWNGRADE") && !timeline_carol.contains("BEFORE-DOWNGRADE"),
        "PRODUCT: Session activity must not show in the room's timeline (SC-4): bob's read: \
         {timeline_bob}\ncarol's read: {timeline_carol}"
    );

    // ---- claim 2: alice downgrades bob to read; her Session's later entries are not his ----
    let (ok, o, e) = alice.vox(
        &[
            "trust",
            "read",
            &bob.fp,
            "--identity-passphrase-file",
            alice.pass(),
        ],
        None,
    );
    assert!(ok, "PRODUCT: `vox trust read` of bob failed: {o}{e}");
    let after: Vec<String> = (1..=ENTRIES)
        .map(|n| format!("AFTER-DOWNGRADE {n}"))
        .collect();
    for (n, text) in after.iter().enumerate() {
        match rt.block_on(alice.socket(&rt).request(&Request::AppendSession {
            channel_id: id,
            session_id: SESSION.to_owned(),
            body: reply(ENTRIES + n + 1, text),
        })) {
            Ok(Frame::Appended { .. }) => {}
            other => panic!("PRODUCT: alice's node refused a Session entry: {other:?}"),
        }
    }
    // Bob's control: he still reads alice's room messages, posted after those entries.
    let bob_synced = posts_until_read(&alice, &bob, &room, "AFTER-DOWNGRADE-CONTROL");
    // Ten seconds more for anything still on its way.
    std::thread::sleep(Duration::from_secs(10));
    let bob_now = opened(&bob, &room);
    eprintln!(
        "[proof] claim 2: bob synced past the later entries: {bob_synced}; opened {bob_now:?}"
    );
    assert!(
        bob_synced,
        "APPARATUS (staging): bob never read alice's room message after the later Session entries, \
         so his opening none of them would say nothing"
    );
    assert!(
        after.iter().all(|a| !bob_now.contains(a)),
        "PRODUCT: after alice downgraded bob to read, he must open none of the Session entries \
         written afterwards: he opened {bob_now:?}"
    );
    assert!(
        before.iter().all(|b| bob_now.contains(b)),
        "PRODUCT: bob keeps the Session entries he read before the downgrade: he has {bob_now:?}"
    );
}
