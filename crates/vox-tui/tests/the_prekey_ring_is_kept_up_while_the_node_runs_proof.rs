//! V210-77 (#268) — **a running node keeps its prekey ring up**: it rotates its signed prekey when
//! the cadence is up and refills its one-time prekeys, while it runs, through the shipped binary.
//!
//! The ring was maintained only at unlock (`PrekeyRing::maintain` from `load_or_create`). A daemon
//! up for weeks offered its 64 one-time prekeys and then none, so every later session was set up
//! without one; it never rotated its signed prekey; and it kept every consumed one-time prekey
//! until the next unlock. The node now maintains the ring on its tick.
//!
//! **Read through the product**: `vox status --json` names the ring the running node last
//! maintained — `prekeys.one_time` (left to offer), `prekeys.consumed` (used, still retained for a
//! concurrent duplicate), `prekeys.signed_prekey` (the id offered now), and what the running node
//! did itself, `prekeys.rotated` and `prekeys.refilled`.
//!
//! Two stagings, each its own test:
//!
//! 1. **Rotation while running.** The `vox id` that makes the identity, and with it the ring, runs
//!    with its clock [`LEAD`] seconds short of seven days behind (`VOX_TEST_CLOCK_SKEW_MS`,
//!    test-only, inert when unset); its daemon runs on the true clock. So the signed prekey falls
//!    due [`LEAD`] seconds after `vox id` — after the daemon's unlock, while it runs. Before:
//!    signed prekey 1, nothing rotated (anything else is CANNOT MEASURE: the rotation came at
//!    unlock). Within [`ROTATE_WITHIN`]: signed prekey 2, rotated once.
//! 2. **More than 64 sessions.** An anchor, a daemon that creates [`JOINS`] rooms, and a second
//!    daemon that joins each. Every join's session is set up with one of the creator's one-time
//!    prekeys when it offers one. After all of them the creator has consumed more than 64 — its
//!    whole first pool — and still has one-time prekeys to offer, having refilled while running.
//!
//! Mutation that must turn both red: the tick's maintenance leaves the ring as it is (the ring
//! maintained only at unlock). Stage 1 then never rotates; stage 2 consumes exactly 64.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase for the prekey ring proof";
const ROOM_PASS: &str = "room passphrase for the prekey ring proof";

/// How long after the ring is made its signed prekey falls due, on the skewed clock: long enough
/// for `vox id` and the daemon's unlock to finish first, short enough to wait for.
const LEAD: u64 = 45;
/// Seven days, the signed prekey's cadence (ADR-002 §2), written out rather than read from the
/// product so a changed cadence goes red.
const SEVEN_DAYS: u64 = 7 * 24 * 60 * 60;
/// How long, from the daemon answering, the rotation may take: the lead, and the tick.
const ROTATE_WITHIN: Duration = Duration::from_secs(120);
/// Joins to the creator: past the 64 one-time prekeys a ring starts with.
const JOINS: usize = 70;
/// The first pool's size (ADR-002 §2's target), written out.
const FIRST_POOL: u64 = 64;

/// A child killed and reaped by its own handle when dropped, never by a name pattern.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One profile: its directory, its passphrase file, and the clock skew its `vox id` runs with.
struct Profile {
    name: &'static str,
    dir: PathBuf,
    pass: PathBuf,
    skew: Option<String>,
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Profile {
    fn new(tmp: &Path, name: &'static str, skew: Option<String>) -> Self {
        let dir = tmp.join(name);
        std::fs::create_dir_all(dir.join("cfg")).unwrap();
        let pass = tmp.join(format!("{name}.pass"));
        std::fs::write(&pass, format!("{IDENTITY}\n")).unwrap();
        Self {
            name,
            dir,
            pass,
            skew,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.args(args)
            .env("VOX_DATA_DIR", &self.dir)
            .env("VOX_CONFIG_DIR", self.dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM_PASSPHRASE")
            .env_remove("VOX_TEST_CLOCK_SKEW_MS");
        c
    }

    fn vox(&self, args: &[&str], stdin: Option<&str>) -> Out {
        use std::io::Write as _;
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("{}: spawn vox: {e}", self.name));
        let mut input = child.stdin.take().unwrap();
        if let Some(s) = stdin {
            let _ = writeln!(input, "{s}");
        }
        drop(input);
        let out = child.wait_with_output().unwrap();
        Out {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// `vox id`: make the identity, and its ring — on the skewed clock, if this profile has one.
    fn id(&self) {
        let mut c = self.command(&["id"]);
        if let Some(s) = &self.skew {
            c.env("VOX_TEST_CLOCK_SKEW_MS", s);
        }
        let out = c.stdin(Stdio::null()).output().expect("run vox id");
        let o = Out {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        assert!(o.ok, "{}: vox id: {}{}", self.name, o.stdout, o.stderr);
    }

    /// `vox daemon`, answering `vox room list` before this returns.
    fn daemon(&self, anchor: Option<&str>) -> Proc {
        let mut args = vec!["daemon", "--listen", "127.0.0.1:0"];
        if let Some(a) = anchor {
            args.extend(["--anchor", a]);
        }
        args.push("--passphrase-file");
        let pass = self.pass.to_str().unwrap();
        args.push(pass);
        let err = std::fs::File::create(self.dir.join("daemon.err")).unwrap();
        let p = Proc(
            self.command(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(err))
                .spawn()
                .expect("spawn vox daemon"),
        );
        let deadline = Instant::now() + Duration::from_secs(120);
        while !self.vox(&["room", "list"], None).ok {
            assert!(
                Instant::now() < deadline,
                "{}'s daemon never answered: {}",
                self.name,
                std::fs::read_to_string(self.dir.join("daemon.err")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        p
    }

    /// `prekeys` from `vox status --json`, once the running node has maintained its ring.
    fn prekeys(&self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let o = self.vox(&["status", "--json"], None);
            if o.ok {
                let v: serde_json::Value = serde_json::from_str(&o.stdout)
                    .unwrap_or_else(|e| panic!("vox status --json: {e}: {}", o.stdout));
                if !v["prekeys"].is_null() {
                    return v["prekeys"].clone();
                }
            }
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE: {}'s `vox status --json` never named its prekey ring: {}{}",
                self.name,
                o.stdout,
                o.stderr
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn n(v: &serde_json::Value, k: &str) -> u64 {
    v[k].as_u64()
        .unwrap_or_else(|| panic!("prekeys.{k} is not a count: {v}"))
}

#[test]
#[ignore = "real binaries and a clock knob; the release gate runs it"]
fn a_running_node_rotates_its_signed_prekey() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    // The ring is made at `vox id`, on this clock: its signed prekey falls due LEAD seconds on,
    // on the true clock the daemon keeps.
    let behind_ms = (SEVEN_DAYS - LEAD) * 1000;
    let node = Profile::new(tmp.path(), "node", Some(format!("-{behind_ms}")));
    let made = Instant::now();
    node.id();
    let _daemon = node.daemon(None);
    let before = node.prekeys();
    eprintln!(
        "[proof] {:.1}s after the ring was made, before: {before}",
        made.elapsed().as_secs_f64()
    );
    assert!(
        n(&before, "signed_prekey") == 1 && n(&before, "rotated") == 0,
        "CANNOT MEASURE: the signed prekey rotated before the daemon ran ({:.1}s after the ring \
         was made, {LEAD}s lead): {before}",
        made.elapsed().as_secs_f64()
    );
    let deadline = Instant::now() + ROTATE_WITHIN;
    let after = loop {
        let p = node.prekeys();
        if n(&p, "rotated") > 0 || Instant::now() >= deadline {
            break p;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    eprintln!(
        "[proof] {:.1}s after the ring was made, after: {after}",
        made.elapsed().as_secs_f64()
    );
    assert_eq!(
        (n(&after, "signed_prekey"), n(&after, "rotated")),
        (2, 1),
        "the running daemon must rotate its signed prekey once its seven days are up \
         (within {ROTATE_WITHIN:?} of answering): {after}"
    );
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW per join; the release gate runs it"]
fn sessions_get_one_time_prekeys_past_the_first_64() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).unwrap();
    let anchor_out = tmp.path().join("anchor.out");
    let _anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &anchor_dir)
            .env("VOX_CONFIG_DIR", anchor_dir.join("cfg"))
            .env_remove("VOX_TEST_CLOCK_SKEW_MS")
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
    let host = Profile::new(tmp.path(), "host", None);
    let guest = Profile::new(tmp.path(), "guest", None);
    host.id();
    guest.id();
    let _host_daemon = host.daemon(Some(&spec));
    let _guest_daemon = guest.daemon(Some(&spec));
    let first = host.prekeys();
    eprintln!("[proof] the host's ring at the start: {first}");
    assert!(
        n(&first, "one_time") == FIRST_POOL && n(&first, "consumed") == 0,
        "CANNOT MEASURE: the host's ring did not start with a full pool and nothing used: {first}"
    );

    let started = Instant::now();
    let mut least = n(&first, "one_time");
    for i in 0..JOINS {
        let name = format!("r{i}");
        let o = host.vox(&["room", "create", "--name", &name], Some(ROOM_PASS));
        assert!(o.ok, "room create {name}: {}{}", o.stdout, o.stderr);
        let o = host.vox(&["room", "list"], None);
        let id = o
            .stdout
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some(name.as_str()))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("room {name} not in `vox room list`: {}", o.stdout))
            .to_owned();
        let o = host.vox(&["room", "invite", &id], None);
        assert!(o.ok, "room invite {name}: {}{}", o.stdout, o.stderr);
        let link = o.stdout.trim().to_owned();
        // A join can be turned away while the host is busy admitting another (a known,
        // separate defect): retried, bounded, and said.
        let joined = (1..=4).any(|attempt| {
            let o = guest.vox(&["room", "join", &link, "--name", &name], Some(ROOM_PASS));
            if !o.ok {
                eprintln!(
                    "[proof] join {i} attempt {attempt} refused: {}",
                    o.stderr.trim()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            o.ok
        });
        assert!(joined, "CANNOT MEASURE: the guest could not join room {i}");
        let p = host.prekeys();
        least = least.min(n(&p, "one_time"));
        if i % 10 == 9 {
            eprintln!(
                "[proof] {} joins in {:.0}s: {p}",
                i + 1,
                started.elapsed().as_secs_f64()
            );
        }
    }
    // The last consume is picked up by the next tick.
    std::thread::sleep(Duration::from_secs(3));
    let last = host.prekeys();
    eprintln!(
        "[proof] {JOINS} joins in {:.0}s; the host's ring now: {last}; fewest one-time prekeys \
         left after any join: {least}",
        started.elapsed().as_secs_f64()
    );
    assert!(
        n(&last, "consumed") > FIRST_POOL,
        "{JOINS} sessions must each get a one-time prekey, past the first {FIRST_POOL}: the host \
         used {} ({last})",
        n(&last, "consumed")
    );
    assert!(
        least > 0 && n(&last, "one_time") > 0,
        "the host must never run out of one-time prekeys to offer (fewest {least}): {last}"
    );
    assert!(
        n(&last, "refilled") > 0,
        "the running host must have refilled its pool: {last}"
    );
}
