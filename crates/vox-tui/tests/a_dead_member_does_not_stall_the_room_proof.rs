//! **One member whose process died does not stall the room for everyone else**, through the
//! shipped binaries: a real `vox node` anchor and three real `vox daemon`s.
//!
//! A push to a member reconciles the room with it and waits for its answer. When that member's
//! process has died without closing its connections (a crash, a kill, a laptop lid), nothing
//! answers. The connection is declared dead only after `SILENCE_IS_DEATH` (30 s). The node used to
//! hold the whole *room* for that session: every other member's session for the room was refused,
//! and every push to them was owed, so a post between two live members waited up to 30 s behind a
//! member who was gone (log-scale measured it: 29.5 s and 21.9 s to converge).
//!
//! Here Carol's daemon is killed by its PID once the three read each other. Alice then posts
//! [`POSTS`] messages, and each one's crossing to Bob is timed. From `vox room post` returning to
//! Bob's `vox room read` showing it, each must be within PRD-001 R40's chat bar, [`BOUND`].
//!
//! Mutation: key the session guard by room again (the pre-fix behaviour), and posts wait behind
//! the push to the dead member.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const ID_PASS: &str = "an identity passphrase";
const ROOM_PASS: &str = "the room passphrase";

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
    cfg: PathBuf,
    pass: PathBuf,
}

impl Member {
    fn new(root: &Path, name: &'static str) -> Self {
        let (data, cfg) = (root.join(name).join("data"), root.join(name).join("cfg"));
        std::fs::create_dir_all(&cfg).unwrap();
        let pass = root.join(format!("{name}.pass"));
        std::fs::write(&pass, ID_PASS).unwrap();
        Self {
            name,
            data,
            cfg,
            pass,
        }
    }

    fn vox(&self, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
        let mut cmd = Command::new(VOX);
        cmd.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .env_remove("CODEX_THREAD_ID")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn vox");
        if let Some(s) = stdin {
            child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
        }
        let out = child.wait_with_output().unwrap();
        let r = (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        eprintln!(
            "[receipt] {} vox {} -> {} {}",
            self.name,
            args.join(" "),
            r.0,
            r.2.trim()
        );
        r
    }

    fn fingerprint(&self) -> String {
        let (ok, out, err) = self.vox(
            &[
                "id",
                "--identity-passphrase-file",
                self.pass.to_str().unwrap(),
            ],
            None,
        );
        assert!(ok, "{} id: {err}", self.name);
        out.trim().to_owned()
    }

    fn daemon(&self, anchor: &str, err: &Path) -> Proc {
        let child = Command::new(VOX)
            .args([
                "daemon",
                "--listen",
                "127.0.0.1:0",
                "--anchor",
                anchor,
                "--passphrase-file",
            ])
            .arg(&self.pass)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_DEBUG_SYNC", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(err).unwrap()))
            .spawn()
            .expect("spawn vox daemon");
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.vox(&["room", "list"], None).0 {
            assert!(
                Instant::now() < deadline,
                "{}'s daemon never answered",
                self.name
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        Proc(child)
    }
}

fn spawn_anchor(root: &Path) -> (Proc, String) {
    let (a_data, a_cfg) = (root.join("anchor/data"), root.join("anchor/cfg"));
    std::fs::create_dir_all(&a_cfg).unwrap();
    let anchor_out = root.join("anchor.out");
    let anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &a_data)
            .env("VOX_CONFIG_DIR", &a_cfg)
            .env("VOX_DEBUG_SYNC", "1")
            .stdout(Stdio::from(std::fs::File::create(&anchor_out).unwrap()))
            .stderr(Stdio::from(std::fs::File::create(root.join("anchor.err")).unwrap()))
            .spawn()
            .expect("spawn vox node"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(&anchor_out).unwrap_or_default();
        if let Some(s) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (anchor, s.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// PRD-001 R40: a message is readable by the other members within a second.
const BOUND: Duration = Duration::from_secs(1);
/// Posts timed after Carol dies.
const POSTS: usize = 5;

#[test]
#[ignore = "a real anchor and three real daemons with production Argon2id; CI runs it in release"]
fn a_dead_member_does_not_stall_the_room() {
    watchdog::arm();
    // DEBUG (dbg/180-sessions): keep every file under VOX_PROOF_ROOT when set.
    let tmp = tempfile::tempdir().unwrap();
    let kept = std::env::var_os("VOX_PROOF_ROOT").map(std::path::PathBuf::from);
    if let Some(k) = &kept {
        std::fs::create_dir_all(k).unwrap();
    }
    let root: &Path = kept.as_deref().unwrap_or(tmp.path());
    let (_anchor, spec) = spawn_anchor(root);
    let members = [
        Member::new(root, "alice"),
        Member::new(root, "bob"),
        Member::new(root, "carol"),
    ];
    let fps: Vec<String> = members.iter().map(Member::fingerprint).collect();
    for (i, m) in members.iter().enumerate() {
        for (j, other) in members.iter().enumerate() {
            if i != j {
                let (ok, _, err) = m.vox(
                    &[
                        "trust",
                        "add",
                        &fps[j],
                        "--name",
                        other.name,
                        "--identity-passphrase-file",
                        m.pass.to_str().unwrap(),
                    ],
                    None,
                );
                assert!(ok, "{} trusts {}: {err}", m.name, other.name);
            }
        }
    }
    let mut daemons: Vec<Proc> = members
        .iter()
        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
        .collect();
    let [alice, bob, carol] = &members;
    let (ok, _, err) = alice.vox(&["room", "create", "--name", "mission"], Some(ROOM_PASS));
    assert!(ok, "create: {err}");
    let room = alice
        .vox(&["room", "list"], None)
        .1
        .split_whitespace()
        .next()
        .expect("a room")
        .to_owned();
    let link = alice
        .vox(&["room", "invite", &room], None)
        .1
        .trim()
        .to_owned();
    for m in [bob, carol] {
        let mut joined = false;
        for attempt in 1..=6 {
            if m.vox(
                &["room", "join", &link, "--name", "mission"],
                Some(ROOM_PASS),
            )
            .0
            {
                joined = true;
                eprintln!("[receipt] {} joined on attempt {attempt}", m.name);
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
        }
        assert!(
            joined,
            "{} never joined, which is not what this proves",
            m.name
        );
    }
    // Everyone reads everyone before Carol dies: keys have flowed and every pair has a session.
    let mut pending: Vec<(&str, &str)> = Vec::new();
    for r in &members {
        for w in &members {
            if r.name != w.name {
                pending.push((r.name, w.name));
            }
        }
    }
    let start = Instant::now();
    let mut round = 0u32;
    while !pending.is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "CANNOT MEASURE: {pending:?} still unread after 90 s, before anyone died"
        );
        round += 1;
        for w in &members {
            if pending.iter().any(|(_, pw)| *pw == w.name) {
                let (ok, _, err) = w.vox(
                    &["room", "post", &room, &format!("warm-{}-{round}", w.name)],
                    None,
                );
                assert!(ok, "{} posts: {err}", w.name);
            }
        }
        std::thread::sleep(Duration::from_secs(1));
        for r in &members {
            let (_, out, _) = r.vox(&["room", "read", &room], None);
            pending.retain(|(pr, pw)| !(*pr == r.name && out.contains(&format!("warm-{pw}-"))));
        }
    }
    eprintln!("everyone reads everyone after {:?}", start.elapsed());

    // Carol's process dies without closing anything.
    let pid = daemons[2].0.id();
    let _ = daemons[2].0.kill();
    let _ = daemons[2].0.wait();
    eprintln!("[test] carol's daemon, pid {pid}, killed and reaped");
    daemons.truncate(2);

    let mut took = Vec::new();
    for i in 1..=POSTS {
        let text = format!("after-carol-{i}");
        let (ok, _, err) = alice.vox(&["room", "post", &room, &text], None);
        assert!(ok, "alice posts: {err}");
        let posted = Instant::now();
        eprintln!("[dbg-proof {}] post {i} returned", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
        let seen = loop {
            let (_, out, _) = bob.vox(&["room", "read", &room], None);
            if out.contains(&text) {
                break Some(posted.elapsed());
            }
            if posted.elapsed() > Duration::from_secs(40) {
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        eprintln!(
            "post {i} after carol died: bob read it {}",
            seen.map_or("never within 40 s".to_owned(), |d| format!(
                "{d:?} after it was posted"
            ))
        );
        took.push(seen);
    }
    let late: Vec<String> = took
        .iter()
        .enumerate()
        .filter(|(_, t)| t.is_none_or(|d| d > BOUND))
        .map(|(i, t)| format!("post {}: {t:?}", i + 1))
        .collect();
    assert!(
        late.is_empty(),
        "with carol dead, alice's posts reached bob beyond {BOUND:?}: {late:?} — a push to the dead \
         member held the room for everyone"
    );
}
