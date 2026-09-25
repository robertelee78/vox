//! ADR-021 F12 — **every member of a room of three eventually reads every other
//! member**, through the shipped binaries: a real `vox node` anchor and three real
//! `vox daemon`s, every trust edge added before the daemons start, in both join orders.
//!
//! ## What forward-only promises, and why an early post may stay unreadable
//!
//! A room is **ForwardOnly** (ADR-006; confirmed by the decider): a member reads another
//! member's messages from the moment that author releases its key to it, never before.
//! Two members who both joined learn of each other only when the board brings the
//! other's record in, and each releases its key to the other only then. A post an
//! author makes in the second or so before it has released its key to a reader is
//! sealed where that reader can never open it — **by design**, not by defect. So this
//! proof does not demand that the first post be read. It demands what forward-only
//! does promise: once the keys have flowed, **every author's later posts reach every
//! reader**. Each author keeps posting fresh, uniquely tagged messages until each reader
//! has rendered one of them, bounded at 60 s for every ordered pair.
//!
//! What F12 was, and what this still catches: members that opened pairwise sessions to
//! each other at the same moment each kept their own and could never open the other's
//! key; and a host that trusted a joiner released its key only on its next tick. Either
//! defect leaves a pair unable to read **anything**, however long the author keeps
//! posting — which is what this asserts against.
//!
//! **Mutation** (`VOX_PROOF_F12_MUTATE=carol-never-trusts-bob`): carol never adds bob to
//! her trust ring, so she never releases her key to him. The proof must then go red on
//! exactly one ordered pair, `bob cannot read carol`.

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
            .stdout(Stdio::from(std::fs::File::create(&anchor_out).unwrap()))
            .stderr(Stdio::null())
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

/// Stand up the room with the joiners joining in `order`, then keep every author
/// posting until every reader has rendered one of its posts, or 60 s pass.
fn every_member_eventually_reads_every_other(order: [&'static str; 2]) {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (_anchor, spec) = spawn_anchor(root);
    let mutate = std::env::var("VOX_PROOF_F12_MUTATE").unwrap_or_default();

    let members = [
        Member::new(root, "alice"),
        Member::new(root, "bob"),
        Member::new(root, "carol"),
    ];
    let fps: Vec<String> = members.iter().map(Member::fingerprint).collect();
    for (i, m) in members.iter().enumerate() {
        for (j, other) in members.iter().enumerate() {
            if i == j {
                continue;
            }
            if mutate == "carol-never-trusts-bob" && m.name == "carol" && other.name == "bob" {
                eprintln!("[mutation] carol never trusts bob");
                continue;
            }
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
    let _daemons: Vec<Proc> = members
        .iter()
        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
        .collect();
    let by_name = |n: &str| members.iter().find(|m| m.name == n).unwrap();
    let alice = by_name("alice");

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
    for name in order {
        let m = by_name(name);
        // A join can be turned away while the room's host is busy admitting another
        // joiner — a separate, known defect, not this one. Retry it, and say so.
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
            "{name} never joined — the join failed, which is not what this proves"
        );
    }

    // Every ordered (reader, writer) pair still waiting.
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
    while !pending.is_empty() && start.elapsed() < Duration::from_secs(60) {
        round += 1;
        // Only authors someone is still waiting on keep posting — fresh, unique tags.
        for w in &members {
            if pending.iter().any(|(_, pw)| *pw == w.name) {
                let (ok, _, err) = w.vox(
                    &["room", "post", &room, &format!("tag-{}-{round}", w.name)],
                    None,
                );
                assert!(ok, "{} posts: {err}", w.name);
            }
        }
        std::thread::sleep(Duration::from_secs(2));
        for r in &members {
            let (_, out, _) = r.vox(&["room", "read", &room], None);
            pending.retain(|(pr, pw)| {
                let met = *pr == r.name && out.contains(&format!("tag-{pw}-"));
                if met {
                    eprintln!("[receipt] {pr} reads {pw} at {:?}", start.elapsed());
                }
                !met
            });
        }
    }
    let missing: Vec<String> = pending
        .iter()
        .map(|(r, w)| format!("{r} cannot read {w}"))
        .collect();
    assert!(
        missing.is_empty(),
        "F12 (join order {order:?}): {missing:?} after 60 s of fresh posts; daemon logs:\n{}",
        members
            .iter()
            .map(|m| format!(
                "--- {} ---\n{}",
                m.name,
                std::fs::read_to_string(root.join(format!("{}.err", m.name))).unwrap_or_default()
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
#[ignore = "a real anchor and three real daemons with production Argon2id; CI runs it in release"]
fn every_member_eventually_reads_every_other_bob_joins_first() {
    every_member_eventually_reads_every_other(["bob", "carol"]);
}

#[test]
#[ignore = "a real anchor and three real daemons with production Argon2id; CI runs it in release"]
fn every_member_eventually_reads_every_other_carol_joins_first() {
    every_member_eventually_reads_every_other(["carol", "bob"]);
}
