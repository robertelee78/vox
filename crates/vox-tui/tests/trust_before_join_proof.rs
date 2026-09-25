//! ADR-021 F12 — **a joiner reads what the room's host posts the moment the join
//! returns**, when the host already trusted it: a real `vox node` anchor and two real
//! `vox daemon`s.
//!
//! A room is ForwardOnly (ADR-006): a newcomer reads only what is sealed after a key
//! is released to it. With the joiner already in the host's trust ring, the host's
//! release used to wait for its next tick, so a post made right after the join was
//! sealed before the key and was unreadable to the joiner for good — "bob never sees
//! alice's warmup", every time. With trust added AFTER the join it crossed in 2 s,
//! because trusting consents at once. Found by `peer.sh`, narrowed with instrumented
//! daemons: the entry synced, the key arrived, and decryption refused "group
//! iteration before chain head". The host now releases the key at admission.
//!
//! Every trust edge is added before either daemon starts, and alice posts the moment
//! bob's `vox room join` returns — the shape that failed.

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
#[ignore = "a real anchor and two real daemons with production Argon2id; CI runs it in release"]
fn a_trusted_joiner_reads_what_the_host_posts_right_after_the_join() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
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

    let members = [Member::new(root, "alice"), Member::new(root, "bob")];
    let fps: Vec<String> = members.iter().map(Member::fingerprint).collect();
    for (i, m) in members.iter().enumerate() {
        let j = 1 - i;
        let (ok, _, err) = m.vox(
            &[
                "trust",
                "add",
                &fps[j],
                "--name",
                members[j].name,
                "--identity-passphrase-file",
                m.pass.to_str().unwrap(),
            ],
            None,
        );
        assert!(ok, "{} trusts {}: {err}", m.name, members[j].name);
    }
    let _daemons: Vec<Proc> = members
        .iter()
        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
        .collect();
    let [alice, bob] = &members;

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
    let mut joined = false;
    for attempt in 1..=6 {
        if bob
            .vox(
                &["room", "join", &link, "--name", "mission"],
                Some(ROOM_PASS),
            )
            .0
        {
            joined = true;
            eprintln!("[receipt] bob joined on attempt {attempt}");
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    assert!(
        joined,
        "bob never joined — the join itself failed, which is not what this proves"
    );

    // The moment the join returns: this is the post that used to be lost for good.
    assert!(
        alice
            .vox(&["room", "post", &room, "warmup from alice"], None)
            .0
    );
    assert!(bob.vox(&["room", "post", &room, "warmup from bob"], None).0);
    let bob_reads_alice = bob.reads(&room, "warmup from alice", 60);
    let alice_reads_bob = alice.reads(&room, "warmup from bob", 60);
    assert!(
        bob_reads_alice && alice_reads_bob,
        "F12: bob reads alice = {bob_reads_alice}, alice reads bob = {alice_reads_bob}; daemon logs:\n{}",
        members
            .iter()
            .map(|m| format!("--- {} ---\n{}", m.name, std::fs::read_to_string(root.join(format!("{}.err", m.name))).unwrap_or_default()))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
