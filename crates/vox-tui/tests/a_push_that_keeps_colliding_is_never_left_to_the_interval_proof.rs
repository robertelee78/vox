//! **A push that keeps colliding is never left to the 30 s interval** (#41), through the shipped
//! binaries: a real `vox node` anchor and two real `vox daemon`s.
//!
//! When two members push to each other at the same moment, each refuses the other's inbound
//! session because its own is running, and both fail. A failed push was retried three times after
//! a random 20–100 ms wait and then left to the periodic interval, so a collision that outlasted
//! three retries left the message for ~30 s. Measured with instrumented shipped daemons
//! (`dbg/180-sessions`): alice and bob failing on each other in lockstep past three retries in
//! about one warm-up in ten, hidden only because the next post re-pushed.
//!
//! Here both post at once, then nothing is posted until every member has read every other's
//! post, and each crossing is timed. Nothing re-pushes, so a push abandoned to the interval shows.
//!
//! The warm-up (everyone reads everyone) can meet #200's pairwise-session race, which fails as
//! CANNOT MEASURE, never as a pass.

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

/// A crossing must land far inside the 30 s interval a push used to be left to. The backoff past
/// the quick retries waits at most `MAX_PUSH_RETRY_WAIT` (8 s) between tries, so a message caught
/// in a long collision still lands within this; one left to the interval takes ~30 s.
const BOUND: Duration = Duration::from_secs(12);
/// Rounds in which both post at once. A collision long enough to exhaust the old three quick
/// retries came up in about one warm-up in ten (measured, dbg/180-sessions); this many rounds
/// gives the old code many chances to show it.
const ROUNDS: usize = 60;

#[test]
#[ignore = "a real anchor and three real daemons with production Argon2id, 40 rounds; CI runs it in release"]
fn a_push_that_keeps_colliding_is_never_left_to_the_interval() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (anchor, spec) = spawn_anchor(root);
    let members = [Member::new(root, "alice"), Member::new(root, "bob")];
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
    let daemons: Vec<Proc> = members
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
    for m in [bob] {
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
    // The two now hold a direct connection. The anchor keeps the room's log and would carry a post
    // the pair failed to exchange, which hides a push left to the interval: measured, streaks of
    // 5–7 failed sessions between members went unseen in a room of three with an anchor. Without
    // it, the pair's own push is the only way a post crosses.
    drop(anchor);
    eprintln!("[test] the anchor is stopped; alice and bob are each other's only path");

    // Both post at the same instant, then nothing more is posted until every member has
    // read every other's post. A push that collides past the quick retries is then carried only by
    // its own retry: with the old code, left to the 30 s interval; with the fix, backed off.
    let mut worst = Duration::ZERO;
    let mut late: Vec<String> = Vec::new();
    for r in 1..=ROUNDS {
        std::thread::scope(|s| {
            for m in &members {
                let room = &room;
                s.spawn(move || {
                    let (ok, _, err) = m.vox(
                        &["room", "post", room, &format!("round-{r}-{}", m.name)],
                        None,
                    );
                    assert!(ok, "{} posts: {err}", m.name);
                });
            }
        });
        let posted = Instant::now();
        let mut unseen: Vec<(&str, &str)> = Vec::new();
        for rd in &members {
            for w in &members {
                if rd.name != w.name {
                    unseen.push((rd.name, w.name));
                }
            }
        }
        let mut seen_at: Vec<(String, Duration)> = Vec::new();
        while !unseen.is_empty() && posted.elapsed() < Duration::from_secs(45) {
            for rd in &members {
                if !unseen.iter().any(|(x, _)| *x == rd.name) {
                    continue;
                }
                let (_, out, _) = rd.vox(&["room", "read", &room], None);
                let at = posted.elapsed();
                unseen.retain(|(x, w)| {
                    let got = *x == rd.name && out.contains(&format!("round-{r}-{w}"));
                    if got {
                        seen_at.push((format!("{w}->{x}"), at));
                    }
                    !got
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let slowest = seen_at
            .iter()
            .map(|(_, d)| *d)
            .max()
            .unwrap_or(Duration::MAX);
        eprintln!(
            "round {r}: slowest crossing {slowest:?}{}",
            if unseen.is_empty() {
                String::new()
            } else {
                format!(", never within 45 s: {unseen:?}")
            }
        );
        worst = worst.max(slowest);
        for (who, d) in &seen_at {
            if *d > BOUND {
                late.push(format!("round {r} {who}: {d:?}"));
            }
        }
        for (x, w) in &unseen {
            late.push(format!("round {r} {w}->{x}: never within 45 s"));
        }
    }
    eprintln!(
        "{ROUNDS} rounds, slowest crossing {worst:?}, {} late",
        late.len()
    );
    assert!(
        late.is_empty(),
        "with every member posting at once, a post crossed later than {BOUND:?}: {late:?} — a push \
         that kept colliding was left to the 30 s interval"
    );
    drop(daemons);
}
