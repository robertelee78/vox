//! **A new member is seen by the room's other members within seconds of joining**, through
//! the shipped binaries: a real `vox node` anchor and three real `vox daemon`s.
//!
//! Membership travels on boards. A member who joins through Alice puts its records on Alice's
//! board, and every other member used to learn of it only when *it* next read that board, on its
//! own periodic sync (`SYNC_INTERVAL_SECS`, 30 s). Measured before the fix with three real nodes,
//! the third member saw the new one 24–28 s after the join returned.
//!
//! Here Bob joins, then Carol joins. The clock starts when Carol's `vox room join` returns. It stops
//! when Bob's `vox room roster` lists her. The bound is [`BOUND`], printed with every sample.
//!
//! **Apparatus clock.** Each poll spawns one `vox room roster`, which this proof cannot subtract,
//! so every poll's own duration is measured on the same clock. If the slowest poll took longer
//! than [`APPARATUS_BUDGET`] and Bob listed Carol late, the runner owned the time:
//! `CANNOT MEASURE: apparatus took X`. Otherwise a late listing is
//! `PRODUCT: took X (apparatus Y)`, with the daemons' stderr.
//!
//! Mutation: take out the prompt pass-on (`note_new_members`). Bob then learns of Carol only on his
//! periodic sync, and the proof goes red.

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
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn vox {}: {e}", args.join(" ")));
        if let Some(s) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(s.as_bytes())
                .unwrap_or_else(|e| panic!("APPARATUS: write vox's stdin: {e}"));
        }
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: wait for vox {}: {e}", args.join(" ")));
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
        assert!(ok, "CANNOT MEASURE: {}'s `vox id` failed: {err}", self.name);
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
                std::fs::File::create(err).expect("APPARATUS: create the daemon stderr file"),
            ))
            .spawn()
            .expect("APPARATUS: spawn vox daemon");
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.vox(&["room", "list"], None).0 {
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE: {}'s daemon never answered `vox room list` within 60 s of its \
                 start; its stderr:\n{}",
                self.name,
                std::fs::read_to_string(err).unwrap_or_default()
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
            .expect("APPARATUS: spawn vox node"),
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
            "CANNOT MEASURE: the anchor never printed its spec within 60 s; its stdout:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// How soon after Carol's join returns Bob must list her.
const BOUND: Duration = Duration::from_secs(3);
/// The slowest single poll (one `vox room roster`) the runner may take before a late listing is
/// the runner's, not vox's.
const APPARATUS_BUDGET: Duration = Duration::from_secs(1);

#[test]
#[ignore = "a real anchor and three real daemons with production Argon2id; CI runs it in release"]
fn a_member_who_joins_through_another_is_seen_by_the_third_within_seconds() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let (_anchor, spec) = spawn_anchor(root);
    let members = [
        Member::new(root, "alice"),
        Member::new(root, "bob"),
        Member::new(root, "carol"),
    ];
    // `vox id` creates each identity before its daemon starts.
    let fps: Vec<String> = members.iter().map(Member::fingerprint).collect();
    let carol_fp = fps[2].clone();
    let _daemons: Vec<Proc> = members
        .iter()
        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
        .collect();
    let [alice, bob, carol] = &members;
    let (ok, _, err) = alice.vox(&["room", "create", "--name", "mission"], Some(ROOM_PASS));
    assert!(
        ok,
        "CANNOT MEASURE: alice's `vox room create` failed: {err}"
    );
    let listing = alice.vox(&["room", "list"], None).1;
    let room = listing
        .split_whitespace()
        .next()
        .unwrap_or_else(|| {
            panic!("CANNOT MEASURE: alice's `vox room list` names no room: {listing:?}")
        })
        .to_owned();
    let link = alice
        .vox(&["room", "invite", &room], None)
        .1
        .trim()
        .to_owned();
    // One join each, no retries. A join can be turned away while the host is busy admitting
    // another joiner (a known, separate product defect); it is named in the red, not retried past.
    for m in [bob, carol] {
        let (ok, out, err) = m.vox(
            &["room", "join", &link, "--name", "mission"],
            Some(ROOM_PASS),
        );
        assert!(
            ok,
            "PRODUCT: {}'s `vox room join` failed (staging for this proof, not its claim; a refusal \
             while the host admits another joiner is the known busy-admitting join defect): {} {}",
            m.name,
            out.trim(),
            err.trim()
        );
    }
    let joined_at = Instant::now();
    // The apparatus: the slowest single poll.
    let mut slowest = Duration::ZERO;
    let seen = loop {
        let poll = Instant::now();
        let (ok, out, _) = bob.vox(&["room", "roster", &room], None);
        slowest = slowest.max(poll.elapsed());
        if ok && out.contains(&carol_fp) {
            break Some(joined_at.elapsed());
        }
        if joined_at.elapsed() > Duration::from_secs(60) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let alice_lists = alice
        .vox(&["room", "roster", &room], None)
        .1
        .contains(&carol_fp);
    eprintln!(
        "[proof] bob listed carol {} after her join returned (bound {BOUND:?}); alice lists her: \
         {alice_lists}; apparatus: slowest roster poll {slowest:?}",
        seen.map_or("never within 60 s".to_owned(), |d| format!("{d:?}"))
    );
    if seen.is_none_or(|d| d > BOUND) {
        assert!(
            slowest <= APPARATUS_BUDGET,
            "CANNOT MEASURE: apparatus took {slowest:?} for one roster poll (budget \
             {APPARATUS_BUDGET:?}); bob listed carol after {seen:?}"
        );
        let stderr =
            |n: &str| std::fs::read_to_string(root.join(format!("{n}.err"))).unwrap_or_default();
        panic!(
            "PRODUCT: took {seen:?} (apparatus {slowest:?}): bob listed carol beyond {BOUND:?} after \
             her join returned: a member who joins through another reaches the rest of the room \
             only on their periodic sync\nbob's daemon:\n{}\ncarol's daemon:\n{}",
            stderr("bob"),
            stderr("carol")
        );
    }
}
