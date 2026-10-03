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
//! Mutation: take out the prompt pass-on (`note_new_members`). Bob then learns of Carol only on his
//! periodic sync, and the proof goes red.
//!
//! **And the anchor's operator sees them as members, not as people still waiting to join**
//! (V210-102, #297). `vox node` prints each room it serves as `<room> <members>m/<pending>p`, and a
//! joiner's pre-join record — its announcement that it is waiting to join — lived its full two
//! hours after the join, so every member who joined in that time was also counted as waiting: a
//! room of 301 showed `301m/256p`. Once Bob and Carol are in, the anchor's last board line must show
//! the room with all three members and nobody pending, within [`BOARD_PATIENCE`]. Its first line
//! naming three members not printed in that time is CANNOT MEASURE (the anchor never learned the
//! room's members, which is not this claim); three members with anyone pending is the product red,
//! quoting the line. Mutation: a pre-join record kept after its joiner is admitted
//! (`RendezvousStore::forget_prejoin` a no-op) — the line reads `3m/2p`.

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

/// How soon after Carol's join returns Bob must list her.
const BOUND: Duration = Duration::from_secs(3);

/// How long the anchor may take to print a board line counting all three members.
const BOARD_PATIENCE: Duration = Duration::from_secs(60);

/// The anchor's latest `vox node: board — …` entry. It serves one room, so its board line has one
/// entry.
fn board_entry(anchor_out: &Path) -> Option<String> {
    std::fs::read_to_string(anchor_out)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.strip_prefix("vox node: board — "))
        .rfind(|e| counts(e).is_some())
        .map(str::to_owned)
}

/// `(members, pending)` from a board entry `<room> <m>m/<p>p[/<e>e]`.
fn counts(entry: &str) -> Option<(usize, usize)> {
    let mut parts = entry.split_whitespace().nth(1)?.split('/');
    let m = parts.next()?.strip_suffix('m')?.parse().ok()?;
    let p = parts.next()?.strip_suffix('p')?.parse().ok()?;
    Some((m, p))
}

#[test]
#[ignore = "a real anchor and three real daemons with production Argon2id; CI runs it in release"]
fn a_member_who_joins_through_another_is_seen_by_the_third_within_seconds() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (_anchor, spec) = spawn_anchor(root);
    let anchor_out = root.join("anchor.out");
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
    let (ok, _, err) = alice.vox(
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "mission",
        ],
        Some(ROOM_PASS),
    );
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
        // A join can be turned away while the host is busy admitting another joiner (a known,
        // separate defect). Retry it, and say so.
        let mut joined = false;
        for attempt in 1..=6 {
            if m.vox(
                &[
                    "room",
                    "join",
                    "--passphrase-file",
                    "-",
                    &link,
                    "--name",
                    "mission",
                ],
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
    let joined_at = Instant::now();
    let seen = loop {
        let (ok, out, _) = bob.vox(&["room", "roster", &room], None);
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
        "bob listed carol {} after her join returned (bound {BOUND:?}); alice lists her: {alice_lists}",
        seen.map_or("never within 60 s".to_owned(), |d| format!("{d:?}"))
    );
    // The anchor's operator: all three as members, nobody still waiting to join.
    let since = Instant::now();
    let entry = loop {
        let entry = board_entry(&anchor_out);
        if entry
            .as_deref()
            .and_then(counts)
            .is_some_and(|(m, p)| m >= 3 && p == 0)
            || since.elapsed() > BOARD_PATIENCE
        {
            break entry;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    eprintln!("the anchor's last board line: {entry:?}");
    let (members, pending) = entry
        .as_deref()
        .and_then(counts)
        .filter(|(m, _)| *m >= 3)
        .unwrap_or_else(|| {
            panic!(
                "CANNOT MEASURE: the anchor printed no board line counting the room's 3 members \
                 within {BOARD_PATIENCE:?}; its last entry for the room was {entry:?}"
            )
        });
    assert_eq!(
        pending,
        0,
        "the anchor tells its operator {pending} people are still waiting to join a room whose \
         {members} members have all joined: `{}`",
        entry.unwrap_or_default()
    );
    let seen = seen.expect("bob never listed carol within 60 s");
    assert!(
        seen <= BOUND,
        "bob listed carol {seen:?} after her join returned, beyond {BOUND:?}: a member who joins \
         through another reaches the rest of the room only on their periodic sync"
    );
}
