//! ADR-021 F12 — **every member of a room of three reads every other**, through the
//! shipped binaries: a real `vox node` anchor and three real `vox daemon`s.
//!
//! What F12 was: two members who opened a pairwise session to each other at the same
//! moment each kept their own and ignored the other's hello, so neither could open the
//! sender key the other released. It met users two ways, both covered here:
//!
//! - **joiner ↔ joiner** — bob and carol both joined alice's room; each auto-consents to
//!   the other the moment it learns of it, and they race;
//! - **creator → joiner with trust before the join** — alice already trusts bob when he
//!   joins, so her tick opens a session to him while his join opens another.
//!
//! Every trust edge is added **before the daemons start**, which is how an operator sets
//! up agents in advance and the case that was reported failing.

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

    fn reads(&self, room: &str, text: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            let (_, out, _) = self.vox(&["room", "read", room], None);
            if out.contains(text) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }
}

#[test]
#[ignore = "a real anchor and three real daemons with production Argon2id; CI runs it in release"]
fn every_member_of_a_room_of_three_reads_every_other() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // ---- a real anchor ----
    let (a_data, a_cfg) = (root.join("anchor/data"), root.join("anchor/cfg"));
    std::fs::create_dir_all(&a_cfg).unwrap();
    let anchor_out = root.join("anchor.out");
    let _anchor = Proc(
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
    let spec = loop {
        let text = std::fs::read_to_string(&anchor_out).unwrap_or_default();
        if let Some(s) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            break s.to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    };

    // ---- three identities, every trust edge added before any daemon starts ----
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
    let _daemons: Vec<Proc> = members
        .iter()
        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
        .collect();
    let [alice, bob, carol] = &members;

    // ---- alice creates; bob and carol join ----
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
            "{} never joined — the join itself failed, which is not what this proves",
            m.name
        );
    }

    // ---- everyone speaks; everyone must read everyone ----
    for m in &members {
        let (ok, _, err) = m.vox(
            &["room", "post", &room, &format!("hello from {}", m.name)],
            None,
        );
        assert!(ok, "{} posts: {err}", m.name);
    }
    let mut missing = Vec::new();
    for reader in &members {
        for writer in &members {
            if reader.name != writer.name
                && !reader.reads(&room, &format!("hello from {}", writer.name), 90)
            {
                missing.push(format!("{} cannot read {}", reader.name, writer.name));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "F12: {missing:?}; daemon logs:\n{}",
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
