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
//! bob's `vox room join` returns — the shape that failed. Bob joins once, as a person would:
//! a refused join is a PRODUCT red quoting the join and both daemons, never retried past.
//! Staging that did not happen (an identity, trust, the anchor, a room) reads CANNOT MEASURE.

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
        std::fs::create_dir_all(&cfg).expect("APPARATUS: create a member's config dir");
        let pass = root.join(format!("{name}.pass"));
        std::fs::write(&pass, ID_PASS).expect("APPARATUS: write a member's passphrase file");
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
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn `vox {}`: {e}", args.join(" ")));
        if let Some(s) = stdin {
            child
                .stdin
                .take()
                .expect("APPARATUS: the child's stdin was not piped")
                .write_all(s.as_bytes())
                .unwrap_or_else(|e| {
                    panic!(
                        "APPARATUS: could not write `vox {}`'s stdin: {e}",
                        args.join(" ")
                    )
                });
        }
        let out = child.wait_with_output().unwrap_or_else(|e| {
            panic!(
                "APPARATUS: could not wait for `vox {}`: {e}",
                args.join(" ")
            )
        });
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
        assert!(
            ok,
            "CANNOT MEASURE: staging not achieved — {}'s `vox id` failed: {err}",
            self.name
        );
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
            .stderr(Stdio::from(
                std::fs::File::create(err).expect("APPARATUS: create a daemon's stderr file"),
            ))
            .spawn()
            .expect("APPARATUS: could not spawn `vox daemon`");
        let child = Proc(child);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let (ok, _, said) = self.vox(&["room", "list"], None);
            if ok {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE: staging not achieved — {}'s daemon never answered `vox room \
                 list` in 60 s; the last answer: {said}\nthe daemon's stderr:\n{}",
                self.name,
                std::fs::read_to_string(err).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        child
    }

    /// Whether `vox room read` showed `text` within `secs`, and its last answer, so a red
    /// quotes what the reader was shown (or why the read failed) rather than a bare `false`.
    fn reads(&self, room: &str, text: &str, secs: u64) -> (bool, String) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut last = String::new();
        while Instant::now() < deadline {
            let (ok, out, err) = self.vox(&["room", "read", room], None);
            if out.contains(text) {
                return (true, out);
            }
            last = if ok { out } else { format!("(failed) {err}") };
            std::thread::sleep(Duration::from_millis(500));
        }
        (false, last)
    }
}

#[test]
#[ignore = "a real anchor and two real daemons with production Argon2id; CI runs it in release"]
fn a_trusted_joiner_reads_what_the_host_posts_right_after_the_join() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let (a_data, a_cfg) = (root.join("anchor/data"), root.join("anchor/cfg"));
    std::fs::create_dir_all(&a_cfg).expect("APPARATUS: create the anchor's config dir");
    let (anchor_out, anchor_err) = (root.join("anchor.out"), root.join("anchor.err"));
    let file = |p: &Path| std::fs::File::create(p).expect("APPARATUS: create an anchor log file");
    let _anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &a_data)
            .env("VOX_CONFIG_DIR", &a_cfg)
            .stdout(Stdio::from(file(&anchor_out)))
            .stderr(Stdio::from(file(&anchor_err)))
            .spawn()
            .expect("APPARATUS: could not spawn `vox node`"),
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
            "CANNOT MEASURE: staging not achieved — the anchor printed no spec in 60 s.\n\
             stdout:\n{text}\nstderr:\n{}",
            std::fs::read_to_string(&anchor_err).unwrap_or_default()
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
        assert!(
            ok,
            "CANNOT MEASURE: staging not achieved — {} could not trust {}: {err}",
            m.name, members[j].name
        );
    }
    let _daemons: Vec<Proc> = members
        .iter()
        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
        .collect();
    let [alice, bob] = &members;

    let logs = || {
        members
            .iter()
            .map(|m| {
                let log = std::fs::read_to_string(root.join(format!("{}.err", m.name)));
                format!("--- {}'s daemon ---\n{}", m.name, log.unwrap_or_default())
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let (ok, _, err) = alice.vox(&["room", "create", "--name", "mission"], Some(ROOM_PASS));
    assert!(
        ok,
        "CANNOT MEASURE: staging not achieved — alice's `vox room create` failed: {err}"
    );
    let (_, listed, _) = alice.vox(&["room", "list"], None);
    let room = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| {
            panic!("CANNOT MEASURE: staging not achieved — alice's `vox room list` shows no room: {listed:?}")
        })
        .to_owned();
    let (ok, link, err) = alice.vox(&["room", "invite", &room], None);
    assert!(
        ok,
        "CANNOT MEASURE: staging not achieved — alice's `vox room invite` failed: {err}"
    );
    let link = link.trim().to_owned();
    // One join, as a person makes it: no retry past a refusal, so a join turned away is a red
    // of its own, with the host's own account of why.
    let (ok, out, err) = bob.vox(
        &["room", "join", &link, "--name", "mission"],
        Some(ROOM_PASS),
    );
    assert!(
        ok,
        "PRODUCT: bob's `vox room join` of alice's fresh invite failed.\nstdout:\n{out}\n\
         stderr:\n{err}\n{}",
        logs()
    );

    // The moment the join returns: this is the post that used to be lost for good.
    for (who, text) in [(alice, "warmup from alice"), (bob, "warmup from bob")] {
        let (ok, _, err) = who.vox(&["room", "post", &room, text], None);
        assert!(
            ok,
            "PRODUCT: {}'s `vox room post` right after the join failed: {err}\n{}",
            who.name,
            logs()
        );
    }
    let (bob_reads_alice, bob_saw) = bob.reads(&room, "warmup from alice", 60);
    let (alice_reads_bob, alice_saw) = alice.reads(&room, "warmup from bob", 60);
    assert!(
        bob_reads_alice && alice_reads_bob,
        "PRODUCT: F12: bob reads alice = {bob_reads_alice}, alice reads bob = {alice_reads_bob} \
         within 60 s.\nbob's last `vox room read`:\n{bob_saw}\nalice's last `vox room \
         read`:\n{alice_saw}\n{}",
        logs()
    );
}
