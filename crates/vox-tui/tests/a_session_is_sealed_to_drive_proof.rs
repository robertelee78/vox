//! **ADR-029 SC-2, SC-2a, SC-2b (#543) — a Session is read only by the members its node trusts
//! with drive**, through the shipped `vox` binary: a `vox node` anchor and three `vox daemon`s.
//!
//! ## The claims
//! 1. **Read only with drive** (SC-2, SC-2a, SC-4). Alice's node trusts bob with read + drive
//!    and carol with read only. The entries of alice's Session reach both of their nodes in the
//!    room's log, and bob's node opens every one of them; carol's opens none, though it reads
//!    alice's messages to the room written before and after them. Neither shows Session activity
//!    in the room's timeline (`vox room read`).
//!    `vox room sessions --json` says so too: alice's Session is listed for both, `can_drive`
//!    true for bob and false for carol.
//! 3. **A file out of a Session reaches only drive** (DR-1.8, #546). Alice's session runs
//!    `vox agent send`: bob's node pulls the file by itself, byte for byte, into its files
//!    directory; carol's pulls nothing. Carol, given the share's tag by a member that has it (an
//!    apparatus attacker reading bob's Session), forwards to alice's service and asks for it
//!    herself: refused (403), though alice's node trusts her.
//! 4. **A file into a Session comes only from drive** (DR-1.7, #546). Bob runs `vox room session
//!    ROOM SESSION --file PATH --note …`: alice's node answers that it is pulling it, the file lands
//!    in alice's files directory byte for byte, and the Session shows it come in, as bob reads it.
//!    Carol, read only, sending a file the same way is refused by alice's node, and nothing of
//!    hers lands there. A file larger than alice's disk can take past its reserve is refused when
//!    it is offered, before anything is pulled (ADR-028 F-3: a pull never fills the disk): bob's
//!    node, as an apparatus attacker, sends a drive request naming a petabyte. That the session is
//!    then told the path is not asserted here: alice's
//!    session has no terminal in this proof (its hook runs with no tmux of anyone's), so the told
//!    line is proved in the tmux proof's own scratch server (a_claude_session_is_mirrored…, arm 11).
//! 2. **Losing drive changes the key** (SC-2b). Alice downgrades bob to read (`vox trust read`).
//!    Bob's node opens none of the entries alice's Session writes afterwards, while it still holds
//!    the ones it read before and still reads alice's messages to the room; and its
//!    `vox room sessions --json` lists alice's Session with `can_drive` false.
//!
//! 5. **A burst of key-packages names a fresh one-time prekey each** (ADR-030 P-3). With a
//!    Session of alice's in two rooms, alice gives carol drive (`vox trust drive`): carol is owed
//!    alice's drive key in both rooms at once, each as a key-package in that room's log. Carol's
//!    own `vox status` says how many one-time prekeys her node has used: exactly two more. Two
//!    packages naming one prekey use one, and the second is opened as a replay, last-resort.
//!
//! ## The staging
//! - Every `vox` is the shipped binary in a scratch `VOX_DATA_DIR`/`VOX_CONFIG_DIR`; every step a
//!   person takes is typed as one types it (`vox id`, `vox room create|link|join|post|read`,
//!   `vox trust add [--drive]`, `vox trust read`).
//! - Alice's Session is opened by her harness's hook, as a person's Claude Code session opens it:
//!   `vox agent hook` with the harness's own `UserPromptSubmit` payload.
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
//! - **`can_drive` always true** (claims 1 and 2): `sessions::fold` in
//!   `crates/vox-core/src/node/sessions.rs` sets it true. Carol's listing says she can drive:
//!   red PRODUCT.
//! - **A Session's file served to any trusted member** (claim 3): `Witness::allowed` in
//!   `crates/vox-core/src/node/shares.rs` lets anyone in. Carol is served the file: red PRODUCT.
//! - **A driven file taken without checking drive** (claim 4): the DR-2 check in `drive` in
//!   `crates/vox-tui/src/host.rs` is removed. Carol's file lands on alice's node: red PRODUCT.
//! - **A driven file's size not checked** (claim 4): `short_of_space` is not asked in `drive`'s
//!   file arm in `crates/vox-tui/src/host.rs`. The petabyte is accepted: red PRODUCT.
//! - **A package's one-time prekey not noted** (claim 5): the `refused_otps.note` after the seal
//!   in `post_key_package` in `crates/vox-core/src/node/actor.rs` removed. Both packages name one
//!   prekey, and carol's node uses one: red PRODUCT.
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

/// `vox` with none of the environment of whatever runs this proof: above all no `TMUX*` (a staged
/// hook inheriting the operator's tmux binds its session to the operator's own pane, and a drive is
/// typed there), `CLAUDE*`, `CODEX*`, `OPENCODE*` or `VOX_*`. Walked from the environment itself,
/// not a fixed list, so a variable a harness adds later is cleared too.
fn vox_cmd() -> Command {
    let mut cmd = Command::new(VOX);
    // A clean environment: every variable this process has is removed by name except this
    // whitelist of what any program needs, so nothing of a harness, a terminal or the operator's
    // own vox reaches it. By name, not `env_clear`: a keyring change is run through `typed`, which
    // copies a command's named variables and removals, and a removal made after `env_clear` is not
    // recorded as one.
    const PASS: [&str; 7] = [
        "HOME", "PATH", "TMPDIR", "USER", "LOGNAME", "LANG", "LC_ALL",
    ];
    for (k, _) in std::env::vars_os() {
        if !PASS.iter().any(|p| k == *p) {
            cmd.env_remove(&k);
        }
    }
    // A daemon this starts never takes port 1080.
    cmd.env("VOX_PROXY", "127.0.0.1:0");
    // **Checked, not trusted**: every such variable in this process's environment is removed from
    // the child's, or nothing runs. A staged hook given a pane would bind a real terminal.
    let removed: std::collections::BTreeSet<_> = cmd
        .get_envs()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| k.to_owned())
        .collect();
    for (k, _) in std::env::vars_os() {
        let name = k.to_string_lossy();
        if (name.starts_with("TMUX") || name.starts_with("CLAUDE")) && !removed.contains(&k) {
            panic!("APPARATUS: {name} would reach a vox this proof starts; nothing is run");
        }
    }
    cmd
}

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
        self.vox_with(args, stdin, &[])
    }

    fn vox_with(
        &self,
        args: &[&str],
        stdin: Option<&str>,
        env: &[(&str, &str)],
    ) -> (bool, String, String) {
        let mut cmd = vox_cmd();
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13): the passphrase file's first line, typed at the prompt.
        if typed::is_keyring_change(args) {
            cmd.args(args)
                .envs(env.iter().copied())
                .env("VOX_DATA_DIR", &self.data)
                .env("VOX_CONFIG_DIR", self.data.join("cfg"))
                .env_remove("VOX_ROOM")
                .env_remove("VOX_SESSION")
                .env_remove("VOX_ROOM_PASSPHRASE");
            let (ok, shown) = typed::keyring(&cmd);
            return (ok, shown.clone(), shown);
        }
        let mut child = cmd
            .args(args)
            .envs(env.iter().copied())
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
    let child = vox_cmd()
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
        vox_cmd()
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

/// Whether `m`'s `vox room sessions --json` lists alice's Session as one it can drive; `None` if
/// it does not list it.
fn can_drive(m: &Member, room: &str) -> Option<bool> {
    let (_, out, _) = m.vox(&["room", "sessions", room, "--json"], None);
    out.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["id"] == SESSION)
        .and_then(|v| v["can_drive"].as_bool())
}

/// How many one-time prekeys `m`'s node has used, as its `vox status --json` says (`prekeys`
/// `consumed`); `None` if it does not say.
fn consumed(m: &Member) -> Option<u64> {
    fn find(v: &serde_json::Value) -> Option<u64> {
        match v {
            serde_json::Value::Object(o) => o
                .get("prekeys")
                .and_then(|p| p["consumed"].as_u64())
                .or_else(|| o.values().find_map(find)),
            serde_json::Value::Array(a) => a.iter().find_map(find),
            _ => None,
        }
    }
    let (_, out, _) = m.vox(&["status", "--json"], None);
    serde_json::from_str::<serde_json::Value>(out.trim())
        .ok()
        .as_ref()
        .and_then(find)
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

/// The file `name` in `m`'s files directory for the room, if it has landed (ADR-028 F-4).
fn landed(m: &Member, room: &[u8; 32], name: &str) -> Option<Vec<u8>> {
    let dir = m
        .data
        .join("nodes")
        .join("default")
        .join("files")
        .join(vox_core::node::link::b32_encode(room));
    std::fs::read(dir.join(name)).ok()
}

/// Ask `m`'s node to forward to `host`'s service `tag` and GET it: the HTTP status line it
/// answers, or why there was no answer.
fn fetch_as(
    rt: &tokio::runtime::Runtime,
    m: &Member,
    room: [u8; 32],
    host: [u8; 32],
    tag: &str,
) -> Result<String, String> {
    use std::io::{Read as _, Write as _};
    // The forward lives as long as the connection that asked for it: held until the fetch ends.
    let mut client = m.socket(rt);
    let bound = match rt.block_on(client.request(&Request::Forward {
        channel_id: room,
        host,
        service_tag: tag.to_owned(),
        local: "127.0.0.1:0".into(),
    })) {
        Ok(Frame::Bound { local }) => local,
        other => return Err(format!("no forward: {other:?}")),
    };
    let mut s = std::net::TcpStream::connect(&bound).map_err(|e| format!("connect: {e}"))?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
    s.write_all(b"GET / HTTP/1.1\r\nHost: share\r\nConnection: close\r\n\r\n")
        .map_err(|e| format!("send: {e}"))?;
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    drop(client);
    let head = String::from_utf8_lossy(&got);
    Ok(head.lines().next().unwrap_or_default().to_owned())
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
    // Alice is at her session: its hook opens its Session in the room.
    let (ok, o, e) = alice.vox_with(
        &["agent", "hook", "--node", "default", "--room", &room],
        Some(&format!(
            r#"{{"session_id":"{SESSION}","hook_event_name":"UserPromptSubmit","cwd":"/tmp","transcript_path":"/tmp/t.jsonl","prompt":"go"}}"#
        )),
        &[("CLAUDE_CODE_ENTRYPOINT", "cli")],
    );
    assert!(ok, "APPARATUS (staging): alice's hook failed: {o}{e}");

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
    let bob_lists = until(Duration::from_secs(60), || {
        can_drive(&bob, &room) == Some(true)
    });
    let carol_lists = can_drive(&carol, &room);
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
        bob_lists && carol_lists == Some(false),
        "PRODUCT: `vox room sessions --json` must list alice's Session with can_drive true for bob \
         and false for carol: bob {:?}, carol {carol_lists:?}",
        can_drive(&bob, &room)
    );
    assert!(
        !timeline_bob.contains("BEFORE-DOWNGRADE") && !timeline_carol.contains("BEFORE-DOWNGRADE"),
        "PRODUCT: Session activity must not show in the room's timeline (SC-4): bob's read: \
         {timeline_bob}\ncarol's read: {timeline_carol}"
    );

    // ---- claim 3: alice's session sends a file out of its Session; it reaches bob alone ----
    let file = tmp.path().join("for-drive.bin");
    let bytes: Vec<u8> = (0..120_000u32).map(|i| (i * 31 % 251) as u8).collect();
    std::fs::write(&file, &bytes).expect("APPARATUS: write the file to send");
    let (ok, o, e) = alice.vox_with(
        &[
            "agent",
            "send",
            file.to_str().expect("APPARATUS: a UTF-8 temp path"),
            "--note",
            "the numbers",
            "--node",
            "default",
            "--session",
            SESSION,
        ],
        None,
        &[],
    );
    assert!(ok, "PRODUCT: `vox agent send` failed: {o}{e}");
    let bob_got = until(Duration::from_secs(120), || {
        landed(&bob, &id, "for-drive.bin").as_deref() == Some(&bytes[..])
    });
    // The tag, as a member with drive reads it in the Session: what an attacker would be handed.
    let tag = match rt.block_on(
        bob.socket(&rt)
            .request(&Request::SessionEntries { channel_id: id }),
    ) {
        Ok(Frame::SessionEntries { rows }) => rows
            .iter()
            .filter_map(|r| serde_json::from_str::<serde_json::Value>(&r.body).ok())
            .find(|v| v["kind"] == "file" && v["name"] == "for-drive.bin")
            .and_then(|v| v["tag"].as_str().map(str::to_owned))
            .unwrap_or_default(),
        other => panic!("APPARATUS: bob's Session entries: {other:?}"),
    };
    // Five seconds more for carol's node, as long as bob's had.
    std::thread::sleep(Duration::from_secs(5));
    let carol_landed = landed(&carol, &id, "for-drive.bin").is_some();
    let alice_fp: [u8; 32] = vox_core::node::link::b32_decode(&alice.fp, "alice")
        .expect("APPARATUS: alice's fingerprint");
    let carol_fetch = if tag.is_empty() {
        Err("no tag".to_owned())
    } else {
        fetch_as(&rt, &carol, id, alice_fp, &tag)
    };
    eprintln!(
        "[proof] claim 3: bob pulled it: {bob_got}; carol's node pulled it: {carol_landed}; \
         carol asking by tag {tag:?}: {carol_fetch:?}"
    );
    assert!(
        bob_got,
        "PRODUCT: bob, whom alice trusts with drive, must pull the file her session sent out of its \
         Session, byte for byte"
    );
    assert!(
        !tag.is_empty(),
        "PRODUCT: bob's Session must carry the file's entry with its tag"
    );
    assert!(
        !carol_landed,
        "PRODUCT: carol, read only, must not get a file sent out of alice's Session"
    );
    let status = carol_fetch.unwrap_or_else(|e| {
        panic!("CANNOT MEASURE (apparatus): carol's forward to alice's share was not made: {e}")
    });
    assert!(
        status.contains("403"),
        "PRODUCT: alice's node must refuse carol the Session's file though she asks by its tag: it \
         answered {status:?}"
    );

    // ---- claim 4: bob drives a file into alice's Session; carol, read only, cannot ----
    let into = tmp.path().join("for-session.bin");
    let into_bytes: Vec<u8> = (0..90_000u32).map(|i| (i * 17 % 241) as u8).collect();
    std::fs::write(&into, &into_bytes).expect("APPARATUS: write the file to drive in");
    let (bob_ok, bob_said, bob_err) = bob.vox(
        &[
            "room",
            "session",
            &room,
            SESSION,
            "--file",
            into.to_str().expect("APPARATUS: a UTF-8 temp path"),
            "--note",
            "for your review",
        ],
        None,
    );
    let alice_got = until(Duration::from_secs(120), || {
        landed(&alice, &id, "for-session.bin").as_deref() == Some(&into_bytes[..])
    });
    let came_in = until(Duration::from_secs(60), || {
        let (_, out, _) = bob.vox(&["room", "session", &room, SESSION, "--json"], None);
        out.lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .any(|v| {
                v["kind"] == "file"
                    && v["line"]
                        .as_str()
                        .is_some_and(|l| l.starts_with("file to ") && l.contains("for-session.bin"))
            })
    });
    let carol_file = tmp.path().join("from-carol.bin");
    std::fs::write(&carol_file, b"carol has read only").expect("APPARATUS: write carol's file");
    let (carol_ok, carol_said, carol_err) = carol.vox(
        &[
            "room",
            "session",
            &room,
            SESSION,
            "--file",
            carol_file.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ],
        None,
    );
    // As long as alice's node took to land bob's, and five seconds more.
    std::thread::sleep(Duration::from_secs(5));
    let carol_landed_at_alice = landed(&alice, &id, "from-carol.bin").is_some();
    eprintln!(
        "[proof] claim 4: bob's --file: {bob_ok} {bob_said}{bob_err}; it landed at alice: \
         {alice_got}; bob's Session shows it come in: {came_in}; carol's --file: {carol_ok} \
         {carol_said}{carol_err}; hers landed at alice: {carol_landed_at_alice}"
    );
    assert!(
        bob_ok && bob_said.contains("pulling"),
        "PRODUCT: bob, whom alice trusts with drive, must have his file accepted: {bob_said}{bob_err}"
    );
    assert!(
        alice_got,
        "PRODUCT: the file bob drove into alice's Session must land on her node, byte for byte"
    );
    assert!(
        came_in,
        "PRODUCT: alice's Session must show the file come in, as bob reads it"
    );
    // A petabyte, named by bob's node as an attacker would: never accepted.
    let alice_fp_for_drive: [u8; 32] = vox_core::node::link::b32_decode(&alice.fp, "alice")
        .expect("APPARATUS: alice's fingerprint");
    let bob_at = {
        let paths = vox_core::node::paths::Paths::resolve(
            "default",
            Some(&bob.data),
            Some(&bob.data.join("cfg")),
        )
        .expect("APPARATUS: bob's paths");
        NodeSocket::one_shot(
            paths.account().socket(),
            vox_core::node::paths::NodeName::parse("default").expect("APPARATUS: a node name"),
        )
    };
    let huge = rt.block_on(vox_core::node::drive_input::send(
        &bob_at,
        id,
        alice_fp_for_drive,
        &vox_agentcomms::drive::Request {
            v: 1,
            session: SESSION.to_owned(),
            action: vox_agentcomms::drive::Action::File {
                name: "huge.bin".into(),
                size: 1_000_000_000_000_000,
                sha256: "0".repeat(64),
                tag: "file-0000000000000000-0000000000000000".into(),
                note: None,
            },
        },
    ));
    eprintln!("[proof] claim 4: a petabyte offered: {huge:?}");
    let huge = huge.unwrap_or_else(|e| {
        panic!("CANNOT MEASURE (apparatus): bob's crafted drive request got no answer: {e:?}")
    });
    assert!(
        !huge.ok && huge.said.contains("not enough free disk on"),
        "PRODUCT: a file past alice's disk reserve must be refused when it is offered: she \
         answered {huge:?}"
    );
    assert!(
        !carol_ok && !carol_landed_at_alice,
        "PRODUCT: carol, read only, must be refused a file into alice's Session, and none of hers \
         may land: she was told {carol_said}{carol_err}"
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
    let bob_lists_after = can_drive(&bob, &room);
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
    assert_eq!(
        bob_lists_after,
        Some(false),
        "PRODUCT: after the downgrade and the entries sealed since, bob's `vox room sessions \
         --json` must list alice's Session with can_drive false"
    );
    assert!(
        before.iter().all(|b| bob_now.contains(b)),
        "PRODUCT: bob keeps the Session entries he read before the downgrade: he has {bob_now:?}"
    );

    // ---- claim 5: a burst of key-packages to one member names a fresh one-time prekey each ----
    let (ok, _, e) = alice.vox(
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "second",
        ],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(
        ok,
        "APPARATUS (staging): the second vox room create failed: {e}"
    );
    let room2 = room_id(&alice, "second");
    let (ok, link2, e) = alice.vox(&["room", "link", &room2], None);
    assert!(
        ok,
        "APPARATUS (staging): vox room link of the second room failed: {e}"
    );
    let (ok, o, e) = carol.vox(
        &["room", "join", "--passphrase-file", "-", link2.trim()],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT: carol's `vox room join` of the second room failed: {o}{e}"
    );
    assert!(
        posts_until_read(&alice, &carol, &room2, "READY-CAROL-SECOND"),
        "APPARATUS (staging): carol never read alice's messages in the second room"
    );
    // A Session of alice's in the second room too, with an entry: her drive key there.
    let session2 = format!("{SESSION}-second");
    let id2 = channel_id(&rt, &alice, &room2);
    let (ok, o, e) = alice.vox_with(
        &["agent", "hook", "--node", "default", "--room", &room2],
        Some(&format!(
            r#"{{"session_id":"{session2}","hook_event_name":"UserPromptSubmit","cwd":"/tmp","transcript_path":"/tmp/t.jsonl","prompt":"go"}}"#
        )),
        &[("CLAUDE_CODE_ENTRYPOINT", "cli")],
    );
    assert!(
        ok,
        "APPARATUS (staging): alice's hook in the second room failed: {o}{e}"
    );
    let body = serde_json::json!({
        "v": 1, "session": session2, "kind": "reply", "seq": 1, "text": "SECOND-ROOM 1"
    })
    .to_string();
    match rt.block_on(alice.socket(&rt).request(&Request::AppendSession {
        channel_id: id2,
        session_id: session2.clone(),
        body,
    })) {
        Ok(Frame::Appended { .. }) => {}
        other => {
            panic!("PRODUCT: alice's node refused a Session entry in the second room: {other:?}")
        }
    }
    // Quiet first: every key of the join and the trust above has gone.
    std::thread::sleep(Duration::from_secs(10));
    let base = consumed(&carol).unwrap_or_else(|| {
        panic!("APPARATUS (precondition unmet): carol's `vox status --json` says no prekey counts")
    });
    let (ok, o, e) = alice.vox(
        &[
            "trust",
            "drive",
            &carol.fp,
            "--identity-passphrase-file",
            alice.pass(),
        ],
        None,
    );
    assert!(ok, "PRODUCT: `vox trust drive` of carol failed: {o}{e}");
    // Both packages taken; then ten seconds more for any further use to show.
    let _ = until(Duration::from_secs(90), || {
        consumed(&carol).is_some_and(|n| n >= base + 2)
    });
    std::thread::sleep(Duration::from_secs(10));
    let used = consumed(&carol).unwrap_or(base).saturating_sub(base);
    let alice_said =
        std::fs::read_to_string(tmp.path().join("alice.daemon.err")).unwrap_or_default();
    let away: Vec<&str> = alice_said
        .lines()
        .filter(|l| l.contains(&carol.fp[..20]) && l.contains("it is away"))
        .collect();
    eprintln!(
        "[proof] claim 5: carol's node used {used} one-time prekeys for alice's drive keys in two \
         rooms; alice's node said carol was away: {away:?}"
    );
    assert!(
        used == 2 || !away.is_empty(),
        "PRODUCT: alice's drive keys to carol in two rooms, released at once, must each name a \
         one-time prekey of its own: carol's node used {used}"
    );
    assert!(
        away.is_empty(),
        "APPARATUS (precondition unmet): carol was not connected to alice when her keys went, so \
         they went to her signed prekey as a member away's do: {away:?}"
    );
}
