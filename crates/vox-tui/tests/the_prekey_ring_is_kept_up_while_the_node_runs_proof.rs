//! V210-77 (#268) — **a running node keeps its prekey ring up**: it rotates its signed prekey when
//! the cadence is up, keeps the one it replaced for a session already under way, and refills its
//! one-time prekeys, while it runs, through the shipped binary.
//!
//! The ring was maintained only at unlock (`PrekeyRing::maintain` from `load_or_create`). A daemon
//! up for weeks offered its 64 one-time prekeys and then none, so every later session was set up
//! without one; it never rotated its signed prekey; and it kept every consumed one-time prekey
//! until the next unlock. The node now maintains the ring on its tick.
//!
//! **Read through the product**: `vox status --json` names the ring the running node last
//! maintained — `prekeys.one_time` (left to offer), `prekeys.consumed` (used, still retained for a
//! concurrent duplicate), `prekeys.signed_prekey` (the id offered now), what the running node did
//! itself (`prekeys.rotated`, `prekeys.refilled`), and `prekeys.previous_used`, the sessions it set
//! up with the signed prekey it had just rotated out; and, since ADR-030 P-1, `prekeys.retired`
//! (unused one-time prekeys it retired), `prekeys.retired_held` (held, unadvertised, in their
//! grace) and `prekeys.oldest_one_time` (when the oldest one it offers was made).
//!
//! Three stagings, each its own test:
//!
//! 1. **Rotation while running.** The `vox id` that makes the identity, and with it the ring, runs
//!    with its clock [`LEAD`] seconds short of seven days behind (`VOX_TEST_CLOCK_STEP_MS`,
//!    test-only, inert when unset: the step moves the seconds clock, which the ring reads; since
//!    v0.3.0 `VOX_TEST_CLOCK_SKEW_MS` moves only the milliseconds); its daemon runs on the true clock. So the signed prekey falls
//!    due [`LEAD`] seconds after `vox id` — after the daemon's unlock, while it runs. Before:
//!    signed prekey 1, nothing rotated (anything else is CANNOT MEASURE: the rotation came at
//!    unlock). Within [`ROTATE_WITHIN`]: signed prekey 2, rotated once. The one-time prekeys were
//!    made with the ring and none was used, so the same maintenance retires them all (ADR-030
//!    P-1): `prekeys.retired` and `prekeys.retired_held` are the whole pool, and the pool offered
//!    is full again, its oldest (`prekeys.oldest_one_time`) made in this run. Then the daemon is
//!    started again with its clocks half an hour on: it still holds every retired prekey, so the
//!    grace survived the restart; and an hour and a minute on: it holds none.
//!    Deliveries in flight across the retirement (ADR-030 P-1): a guest joins a room on this node
//!    and on a second node made the same way, each trusts it, and its daemon is stopped. Test-side
//!    code holding the guest's profile (apparatus) then builds a key delivery to each node, against
//!    the bundle on its board, before either rotates. Sent to the first node seconds after its
//!    retirement, the delivery is taken, and `prekeys.retired_used` counts it. Sent to the second
//!    once it has retired and been started again an hour and a minute on, it is answered "it does
//!    not hold the one-time prekey the delivery named".
//! 2. **A session started before a rotation completes after it.** A host made the same way, with
//!    [`WINDOW_LEAD`] seconds to its rotation, and a guest that starts joining one of its rooms a
//!    moment before. The guest's daemon is stopped (SIGSTOP, by its PID) mid-join and resumed
//!    (SIGCONT) once the host has rotated, so the join's last message names the signed prekey the
//!    host offered before it rotated. The join must complete. An attempt counts only when the host
//!    reports it answered with the previous signed prekey (`previous_used`); one where the stop
//!    fell before the host's offer (the join then used the new prekey) is tried again with a new
//!    host, [`WINDOW_TRIES`] at most, then CANNOT MEASURE.
//! 3. **Past the whole pool.** An anchor, a host whose one-time pool is [`POOL`] rather than 64
//!    (`VOX_TEST_ONE_TIME_PREKEYS`, test-only, inert when unset; the low-water mark is a quarter of
//!    it), and a guest that joins [`JOINS`] of its rooms. Every join's session is set up with one
//!    of the host's one-time prekeys when it offers one. After all of them the host has consumed
//!    more than its whole first pool, and still has one-time prekeys to offer, having refilled
//!    while running. The smaller pool keeps this to a dozen joins, well inside the watchdog on a
//!    small CI runner and in a debug build; the 70 joins it took at 64 used 418 of 600 s.
//!
//! Mutations that must turn it red: the tick's maintenance leaves the ring as it is (1 never
//! rotates; 3 consumes exactly [`POOL`]); a rotation drops the signed prekey it replaces at once
//! (2's join fails); unused one-time prekeys never retired (1: `retired` 0, the old pool still
//! offered); the retired set not saved (1: none held half an hour on); the grace never ending (1:
//! all still held an hour and a minute on, and first the delivery past the grace taken); a grace
//! of zero (1: the delivery in its grace answered as naming an unknown prekey); a retired prekey
//! not looked up when a delivery names it (1: the same).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/layout.rs"]
mod layout;
#[path = "support/ports.rs"]
mod ports;
#[path = "support/typed.rs"]
mod typed;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase for the prekey ring proof";
const ROOM_PASS: &str = "room passphrase for the prekey ring proof";

/// How long after the ring is made its signed prekey falls due, on the skewed clock: long enough
/// for `vox id` and the daemon's unlock to finish first, short enough to wait for. 45 s was not
/// enough on a loaded box: a daemon took 45.6 s to answer, and the rotation came at its unlock.
const LEAD: u64 = 180;
/// Seven days, the signed prekey's cadence (ADR-002 §2), written out rather than read from the
/// product so a changed cadence goes red.
const SEVEN_DAYS: u64 = 7 * 24 * 60 * 60;
/// How long, from the daemon answering, the rotation may take: the lead, and the tick.
const ROTATE_WITHIN: Duration = Duration::from_secs(300);
/// Stage 2's lead: time for the host to start and make a room before its rotation (15 s was
/// not enough in a debug build).
const WINDOW_LEAD: u64 = 60;
/// How long before the host's rotation falls due the guest starts to join.
const JOIN_BEFORE_DUE: Duration = Duration::from_millis(2500);
/// Stage 2's attempts, each stopping the guest a little later into its join.
const WINDOW_TRIES: u64 = 4;
/// The test-only one-time pool (`VOX_TEST_ONE_TIME_PREKEYS`).
const POOL: u64 = 8;
/// Joins to the host in stage 3: past its whole first pool.
const JOINS: usize = 12;
/// Stage 1's restarts, inside and past a retired one-time prekey's one-hour grace (ADR-030 P-1),
/// written out rather than read from the product.
const HALF_HOUR_MS: i64 = 30 * 60 * 1000;
const HOUR_AND_A_MINUTE_MS: i64 = 61 * 60 * 1000;

/// A child killed and reaped by its own handle when dropped, never by a name pattern.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One profile: its directory, its passphrase file, the clock skew its `vox id` runs with, and
/// the test-only one-time pool size every one of its commands runs with.
struct Profile {
    name: String,
    dir: PathBuf,
    pass: PathBuf,
    skew: Option<String>,
    pool: Option<u64>,
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Profile {
    fn new(tmp: &Path, name: &str, skew: Option<String>, pool: Option<u64>) -> Self {
        let dir = tmp.join(name);
        std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: create a staging directory");
        let pass = tmp.join(format!("{name}.pass"));
        std::fs::write(&pass, format!("{IDENTITY}\n")).expect("APPARATUS: write a staging file");
        Self {
            name: name.to_owned(),
            dir,
            pass,
            skew,
            pool,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.args(args)
            .env("VOX_DATA_DIR", &self.dir)
            .env("VOX_CONFIG_DIR", self.dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM_PASSPHRASE")
            .env_remove("VOX_TEST_CLOCK_SKEW_MS")
            .env_remove("VOX_TEST_CLOCK_STEP_MS")
            .env_remove("VOX_TEST_ONE_TIME_PREKEYS");
        if let Some(n) = self.pool {
            c.env("VOX_TEST_ONE_TIME_PREKEYS", n.to_string());
        }
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
            .unwrap_or_else(|e| panic!("APPARATUS: {}: spawn vox: {e}", self.name));
        let mut input = child.stdin.take().expect("APPARATUS: a piped stdio handle");
        if let Some(s) = stdin {
            let _ = writeln!(input, "{s}");
        }
        drop(input);
        let out = child
            .wait_with_output()
            .expect("APPARATUS: wait for a child process");
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
            c.env("VOX_TEST_CLOCK_STEP_MS", s);
        }
        let out = c
            .stdin(Stdio::null())
            .output()
            .expect("APPARATUS: run vox id");
        assert!(
            out.status.success(),
            "PRODUCT (staging): {}'s `vox id` failed: {}{}",
            self.name,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `vox daemon`, answering `vox room list` before this returns.
    fn daemon(&self, anchor: Option<&str>) -> Proc {
        self.daemon_stepped(anchor, None)
    }

    /// [`Profile::daemon`], its clocks moved by `step_ms` (`VOX_TEST_CLOCK_STEP_MS`) when given.
    fn daemon_stepped(&self, anchor: Option<&str>, step_ms: Option<i64>) -> Proc {
        let mut args = vec!["daemon", "--listen", "127.0.0.1:0"];
        if let Some(a) = anchor {
            args.extend(["--anchor", a]);
        }
        args.push("--passphrase-file");
        let pass = self
            .pass
            .to_str()
            .expect("APPARATUS: a path that is not UTF-8");
        args.push(pass);
        let err = std::fs::File::create(self.dir.join("daemon.err"))
            .expect("APPARATUS: create a staging file");
        let mut c = self.command(&args);
        if let Some(step) = step_ms {
            c.env("VOX_TEST_CLOCK_STEP_MS", step.to_string());
        }
        let p = Proc(
            c.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(err))
                .spawn()
                .expect("APPARATUS: spawn vox daemon"),
        );
        let deadline = Instant::now() + Duration::from_secs(120);
        while !self.vox(&["room", "list"], None).ok {
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): {}'s daemon never answered `vox room list` within 120 s: {}",
                self.name,
                std::fs::read_to_string(self.dir.join("daemon.err")).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        p
    }

    /// A new room's room link: `vox room create`, then `vox room link` by its id.
    fn room(&self, name: &str) -> String {
        let o = self.vox(
            &["room", "create", "--passphrase-file", "-", "--name", name],
            Some(ROOM_PASS),
        );
        assert!(
            o.ok,
            "PRODUCT: room create {name}: {}{}",
            o.stdout, o.stderr
        );
        let o = self.vox(&["room", "list"], None);
        let id = o
            .stdout
            .lines()
            .find(|l| l.split_whitespace().nth(1) == Some(name))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("PRODUCT: room {name} not in `vox room list`: {}", o.stdout))
            .to_owned();
        let o = self.vox(&["room", "link", &id], None);
        assert!(o.ok, "PRODUCT: room link {name}: {}{}", o.stdout, o.stderr);
        o.stdout.trim().to_owned()
    }

    /// `prekeys` from `vox status --json`, once the running node has maintained its ring.
    fn prekeys(&self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let o = self.vox(&["status", "--json"], None);
            if o.ok {
                let v: serde_json::Value = serde_json::from_str(&o.stdout)
                    .unwrap_or_else(|e| panic!("PRODUCT: vox status --json: {e}: {}", o.stdout));
                if !v["prekeys"].is_null() {
                    return v["prekeys"].clone();
                }
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): {}'s `vox status --json` never named its prekey ring: {}{}",
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
        .unwrap_or_else(|| panic!("PRODUCT: prekeys.{k} is not a count: {v}"))
}

/// A `vox node` anchor, and its `--anchor` spec.
fn anchor(tmp: &Path) -> (Proc, String) {
    let anchor_dir = tmp.join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).expect("APPARATUS: create a staging directory");
    let anchor_out = tmp.join("anchor.out");
    let p = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &anchor_dir)
            .env("VOX_CONFIG_DIR", anchor_dir.join("cfg"))
            .env_remove("VOX_TEST_CLOCK_SKEW_MS")
            .env_remove("VOX_TEST_CLOCK_STEP_MS")
            .env_remove("VOX_TEST_ONE_TIME_PREKEYS")
            .stdout(Stdio::from(
                std::fs::File::create(&anchor_out).expect("APPARATUS: create a staging file"),
            ))
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
            return (p, s.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The wall clock, in milliseconds since the epoch.
fn wall_ms() -> u64 {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("APPARATUS: the clock")
        .as_millis();
    u64::try_from(ms).expect("APPARATUS: the clock")
}

/// Send `sig` to `pid` with `kill(1)`.
fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([&format!("-{sig}"), &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: kill -{sig} {pid}");
}

#[test]
#[ignore = "real binaries and a clock knob; the release gate runs it"]
fn a_running_node_rotates_its_signed_prekey() {
    test_knobs::require(&["VOX_TEST_CLOCK_STEP_MS"]);
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    // The ring is made at `vox id`, on this clock: its signed prekey falls due LEAD seconds on,
    // on the true clock the daemon keeps.
    let behind_ms = (SEVEN_DAYS - LEAD) * 1000;
    let node = Profile::new(tmp.path(), "node", Some(format!("-{behind_ms}")), None);
    // A second node made the same way, for the grace's end (below).
    let node2 = Profile::new(tmp.path(), "node2", Some(format!("-{behind_ms}")), None);
    let made = Instant::now();
    let made_ms = wall_ms();
    node.id();
    node2.id();
    let daemon = node.daemon(None);
    let daemon2 = node2.daemon(None);
    let before = node.prekeys();
    eprintln!(
        "[proof] {:.1}s after the ring was made, before: {before}",
        made.elapsed().as_secs_f64()
    );
    assert!(
        n(&before, "signed_prekey") == 1 && n(&before, "rotated") == 0,
        "APPARATUS, CANNOT MEASURE: the proof's lead was too short; the signed prekey rotated \
         before the daemon ran ({:.1}s after the ring \
         was made, {LEAD}s lead): {before}",
        made.elapsed().as_secs_f64()
    );
    let pool = n(&before, "one_time");
    assert!(
        pool > 0 && n(&before, "retired") == 0 && n(&before, "retired_held") == 0,
        "APPARATUS, CANNOT MEASURE: the one-time prekeys were retired, or there were none to \
         retire, before the daemon ran: {before}"
    );
    // A member of a room on each node, trusted by it, whose deliveries are in flight across the
    // retirement: each built now, against the node's bundle as its board serves it, and sent
    // once the one-time prekey it names is retired (ADR-030 P-1).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: a runtime");
    let guest = Profile::new(tmp.path(), "guest", None, None);
    guest.id();
    let guest_daemon = guest.daemon(None);
    let guest_fp = guest.vox(&["id"], None).stdout.trim().to_owned();
    for host in [&node, &node2] {
        // One name per room: a node holds one room of a name.
        let link = host.room(&format!("grace-{}", host.name));
        let o = guest.vox(
            &["room", "join", "--passphrase-file", "-", &link],
            Some(ROOM_PASS),
        );
        assert!(
            o.ok,
            "PRODUCT (staging): the guest's join of {}'s room: {}{}",
            host.name, o.stdout, o.stderr
        );
        let (ok, shown) =
            typed::keyring(&host.command(&["trust", "add", &guest_fp, "--name", "guest"]));
        assert!(
            ok,
            "PRODUCT (staging): {} could not trust the guest: {shown}",
            host.name
        );
    }
    drop(guest_daemon);
    let member = rt.block_on(Member::of(&guest));
    let in_grace = rt.block_on(member.delivery_to(&node));
    let past_grace = rt.block_on(member.delivery_to(&node2));
    assert!(
        n(&node.prekeys(), "rotated") == 0 && n(&node2.prekeys(), "rotated") == 0,
        "APPARATUS, CANNOT MEASURE: the lead was too short; a node rotated before the deliveries \
         in flight were built ({:.1}s after the rings were made, {LEAD}s lead)",
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
        "PRODUCT: the running daemon must rotate its signed prekey once its seven days are up \
         (within {ROTATE_WITHIN:?} of answering): {after}"
    );

    // In its grace, the delivery in flight against a retired one-time prekey still opens: the
    // node takes the key, or refuses it only after opening it (the room's or its trust's
    // refusal), never as a prekey it does not hold.
    let answer = rt.block_on(in_grace.send(&node));
    // Counted at the node's next maintenance, a tick on.
    let deadline = Instant::now() + Duration::from_secs(10);
    let used = loop {
        let u = n(&node.prekeys(), "retired_used");
        if u > 0 || Instant::now() >= deadline {
            break u;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    eprintln!(
        "[proof] a delivery naming a one-time prekey retired seconds ago: {answer:?}; sessions \
         set up with a retired one-time prekey: {used}"
    );
    assert!(
        answer.as_deref().is_none_or(opened_then_refused) && used == 1,
        "PRODUCT: a delivery in flight against a one-time prekey the node retired seconds ago \
         must still open in its one-hour grace, and be counted as one (ADR-030 P-1); the node \
         answered {answer:?} and counts {used} session(s) set up with a retired one-time prekey"
    );

    // Past the grace, a delivery in flight against a retired one-time prekey is answered as naming
    // a prekey the node does not hold (ADR-030 P-1, P-3): the second node, once it has retired its
    // pool, started again an hour and a minute on.
    let deadline = Instant::now() + ROTATE_WITHIN;
    while n(&node2.prekeys(), "retired") == 0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT: the second node never retired its one-time prekeys: {}",
            node2.prekeys()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    drop(daemon2);
    let d2 = node2.daemon_stepped(None, Some(HOUR_AND_A_MINUTE_MS));
    let answer = rt.block_on(past_grace.send(&node2));
    eprintln!("[proof] a delivery naming a one-time prekey retired 61 min ago: {answer:?}");
    assert!(
        answer.as_deref() == Some(UNKNOWN_PREKEY),
        "PRODUCT: past its one-hour grace, a delivery naming a retired one-time prekey must be \
         answered \"{UNKNOWN_PREKEY}\" (ADR-030 P-1, P-3); the node answered {answer:?}"
    );
    drop(d2);

    // ADR-030 P-1: the one-time prekeys were made with the ring, as old as its signed prekey, and
    // none was used. The same maintenance retires every one, keeps each for its grace, and offers
    // a fresh pool, none of it older than this run.
    // The guest's join used one of them (or more): the rest were unused.
    let unused = pool - n(&after, "consumed");
    let oldest = after["oldest_one_time"].as_u64().unwrap_or(0);
    let ok = n(&after, "retired") == unused
        && n(&after, "retired_held") == unused
        && n(&after, "one_time") == pool
        && oldest >= made_ms;
    eprintln!(
        "[proof] unused one-time prekeys retired {}, held in their grace {}, offered {}, the \
         oldest offered made at {oldest} (this run began at {made_ms})",
        n(&after, "retired"),
        n(&after, "retired_held"),
        n(&after, "one_time")
    );
    assert!(
        ok,
        "PRODUCT: the running daemon must retire its {unused} unused one-time prekeys once they \
         are seven days old, hold them for their grace, and offer {pool} made in this run (none \
         before {made_ms}): {after}"
    );

    // The grace survives a restart, and ends at an hour: the daemon started again with its clocks
    // half an hour on still holds every retired prekey but the one just used, and an hour and a
    // minute on holds none.
    drop(daemon);
    for (on_ms, held) in [(HALF_HOUR_MS, unused - 1), (HOUR_AND_A_MINUTE_MS, 0)] {
        let d = node.daemon_stepped(None, Some(on_ms));
        let p = node.prekeys();
        eprintln!(
            "[proof] started again {} min on: retired held {}",
            on_ms / 60_000,
            n(&p, "retired_held")
        );
        assert_eq!(
            n(&p, "retired_held"),
            held,
            "PRODUCT: a daemon started again {} min after its one-time prekeys were retired must \
             hold {held} of them (the grace is one hour, kept across a restart): {p}",
            on_ms / 60_000
        );
        drop(d);
    }
}

#[test]
#[ignore = "real binaries, a clock knob, production Argon2id and a PoW; the release gate runs it"]
fn a_session_started_before_a_rotation_completes_after_it() {
    test_knobs::require(&["VOX_TEST_CLOCK_STEP_MS"]);
    // A join per attempt; 14 unlocks: the guest's `vox id` and daemon, and per attempt the host's
    // `vox id`, daemon and room.
    watchdog::arm_for_setup(WINDOW_TRIES as u32, 2 + 3 * WINDOW_TRIES as u32);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (_anchor, spec) = anchor(tmp.path());
    let guest = Profile::new(tmp.path(), "guest", None, None);
    guest.id();
    let guest_daemon = guest.daemon(Some(&spec));
    let guest_pid = guest_daemon.0.id();
    let behind_ms = (SEVEN_DAYS - WINDOW_LEAD) * 1000;

    for attempt in 1..=WINDOW_TRIES {
        let host = Profile::new(
            tmp.path(),
            &format!("host{attempt}"),
            Some(format!("-{behind_ms}")),
            None,
        );
        let made = Instant::now();
        host.id();
        let due = made + Duration::from_secs(WINDOW_LEAD);
        let _host_daemon = host.daemon(Some(&spec));
        let link = host.room(&format!("w{attempt}"));
        let before = host.prekeys();
        let start = due.checked_sub(JOIN_BEFORE_DUE).expect(
            "APPARATUS, CANNOT MEASURE: the proof's ring falls due sooner than a join can be \
             staged before it",
        );
        assert!(
            n(&before, "rotated") == 0 && Instant::now() < start,
            "APPARATUS, CANNOT MEASURE (timing): attempt {attempt}: the host was not ready {JOIN_BEFORE_DUE:?} before \
             its rotation ({:.1}s after `vox id`, {WINDOW_LEAD}s lead): {before}",
            made.elapsed().as_secs_f64()
        );
        std::thread::sleep(start.saturating_duration_since(Instant::now()));

        // The join runs in the guest's daemon; `vox room join` waits for it.
        let joining = std::thread::spawn({
            let cmd = guest
                .command(&["room", "join", "--passphrase-file", "-", &link])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("APPARATUS: spawn vox room join");
            move || {
                use std::io::Write as _;
                let mut cmd = cmd;
                let mut input = cmd.stdin.take().expect("APPARATUS: a piped stdio handle");
                let _ = writeln!(input, "{ROOM_PASS}");
                drop(input);
                cmd.wait_with_output()
                    .expect("APPARATUS: wait for a child process")
            }
        });
        // Later into the join each attempt, so one of them stops it after the host's offer.
        std::thread::sleep(Duration::from_millis(300 * attempt));
        signal(guest_pid, "STOP");
        let stopped = Instant::now();
        let deadline = due + Duration::from_secs(20);
        let rotated = loop {
            let p = host.prekeys();
            if n(&p, "rotated") > 0 || Instant::now() >= deadline {
                break p;
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        signal(guest_pid, "CONT");
        let out = joining
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        std::thread::sleep(Duration::from_secs(2));
        let after = host.prekeys();
        let (ok, said) = (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        );
        eprintln!(
            "[proof] attempt {attempt}: guest stopped {:.1}s into its join for {:.1}s; the host \
             then: {rotated}; join ok={ok}; the host after: {after}",
            0.3 * attempt as f64,
            stopped.elapsed().as_secs_f64()
        );
        assert!(
            n(&rotated, "rotated") == 1,
            "PRODUCT (staging): attempt {attempt}: the running host never rotated its signed \
             prekey within 20 s of it falling due: {rotated}"
        );
        assert!(
            ok,
            "PRODUCT: a join the host offered its signed prekey for before it rotated must complete after \
             the rotation (attempt {attempt}): {} — the host: {after}",
            said.trim()
        );
        if n(&after, "previous_used") >= 1 {
            eprintln!(
                "[proof] a session started with signed prekey 1 completed after the rotation to \
                 {}: previous_used {}",
                n(&after, "signed_prekey"),
                n(&after, "previous_used")
            );
            return;
        }
    }
    panic!(
        "APPARATUS, CANNOT MEASURE (timing): in {WINDOW_TRIES} attempts no join had the host's offer before it rotated"
    );
}

#[test]
#[ignore = "real binaries, a pool knob, production Argon2id and a PoW per join; the release gate runs it"]
fn sessions_get_one_time_prekeys_past_the_whole_pool() {
    test_knobs::require(&["VOX_TEST_ONE_TIME_PREKEYS"]);
    // JOINS joins; 16 unlocks: two `vox id`s, two daemon starts, and a room created per join.
    watchdog::arm_for_setup(JOINS as u32, 16);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (_anchor, spec) = anchor(tmp.path());
    let host = Profile::new(tmp.path(), "host", None, Some(POOL));
    let guest = Profile::new(tmp.path(), "guest", None, None);
    host.id();
    guest.id();
    let _host_daemon = host.daemon(Some(&spec));
    let _guest_daemon = guest.daemon(Some(&spec));
    let first = host.prekeys();
    eprintln!("[proof] the host's ring at the start: {first}");
    assert!(
        n(&first, "one_time") == POOL && n(&first, "consumed") == 0,
        "APPARATUS, CANNOT MEASURE (test knob): the host's ring did not start with a pool of {POOL} and nothing used \
         (is VOX_TEST_ONE_TIME_PREKEYS honoured?): {first}"
    );

    let started = Instant::now();
    let mut least = n(&first, "one_time");
    for i in 0..JOINS {
        let name = format!("r{i}");
        let link = host.room(&name);
        // A join can be turned away while the host is busy admitting another (a known,
        // separate defect): retried, bounded, and said.
        let joined = (1..=4).any(|attempt| {
            let o = guest.vox(
                &["room", "join", "--passphrase-file", "-", &link],
                Some(ROOM_PASS),
            );
            if !o.ok {
                eprintln!(
                    "[proof] join {i} attempt {attempt} refused: {}",
                    o.stderr.trim()
                );
                std::thread::sleep(Duration::from_secs(3));
            }
            o.ok
        });
        assert!(
            joined,
            "PRODUCT (staging): the guest could not join room {i}"
        );
        let p = host.prekeys();
        least = least.min(n(&p, "one_time"));
        eprintln!(
            "[proof] {} joins in {:.0}s: {p}",
            i + 1,
            started.elapsed().as_secs_f64()
        );
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
        n(&last, "consumed") > POOL,
        "PRODUCT: {JOINS} sessions must each get a one-time prekey, past the whole first pool of {POOL}: \
         the host used {} ({last})",
        n(&last, "consumed")
    );
    assert!(
        least > 0 && n(&last, "one_time") > 0,
        "PRODUCT: the host must never run out of one-time prekeys to offer (fewest {least}): {last}"
    );
    assert!(
        n(&last, "refilled") > 0,
        "PRODUCT: the running host must have refilled its pool: {last}"
    );
}

// ---- the member in flight (ADR-030 P-1) ------------------------------------------------------
//
// **Apparatus, as AGENTS.md allows.** A real member, made and joined by the shipped binary, whose
// daemon is then stopped; test-side code holding its profile builds a key delivery to a node the
// way a sender's node does (a session of its own, `OP_ROTATION_HELLO`), against the node's bundle
// as the node's own board serves it, and sends it later. What is asserted is the node's answer.

use std::sync::Arc;
use vox_core::hash::Digest32;
use vox_core::nat::service::{RecordKinds, RendezvousClient};
use vox_core::node::pairwise_stream as pw;
use vox_core::transport::quic::{VoxConnection, VoxEndpoint};
use vox_core::transport::streams::{open_typed, StreamKind};

/// What a node answers when a delivery names a one-time prekey it does not hold.
const UNKNOWN_PREKEY: &str = "it does not hold the one-time prekey the delivery named";

/// A refusal a node makes only after the delivery's session opened and its key was read: the
/// room's or its trust's, not the prekey's nor the hello's.
fn opened_then_refused(why: &str) -> bool {
    why == "the room would not take the key"
        || why == "its owner has not trusted us, so it does not read us yet"
}

struct Member {
    signer: Arc<vox_core::atrest::vault::VaultRootSigner>,
    ring: vox_core::node::prekeys::PrekeyRing,
    _profile: vox_core::node::profile::Profile,
}

/// One delivery, built and not yet sent.
struct InFlight {
    frame: Vec<u8>,
    signer: Arc<vox_core::atrest::vault::VaultRootSigner>,
}

impl Member {
    async fn of(p: &Profile) -> Self {
        let node = match layout::find_named(&p.dir.join("nodes"), "store.redb").as_slice() {
            [one] => one
                .parent()
                .and_then(|d| d.file_name())
                .and_then(|n| n.to_str())
                .expect("APPARATUS: the member's node name")
                .to_owned(),
            found => panic!(
                "APPARATUS: the member's data root holds {} stores",
                found.len()
            ),
        };
        let paths =
            vox_core::node::paths::Paths::resolve(&node, Some(&p.dir), Some(&p.dir.join("cfg")))
                .expect("APPARATUS: the member's paths");
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut profile = loop {
            match vox_core::node::profile::Profile::open(paths.clone()) {
                Ok(pr) => break pr,
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => panic!("APPARATUS: the member's profile did not open: {e:?}"),
            }
        };
        profile
            .unlock(IDENTITY.as_bytes())
            .expect("APPARATUS: the member's identity unlocks");
        let signer = profile
            .signer_arc()
            .expect("APPARATUS: the member's signer");
        let ring = vox_core::node::prekeys::load(profile.store(), signer.as_ref())
            .expect("APPARATUS: the member's ring opens")
            .expect("APPARATUS: the member has a ring");
        Self {
            signer,
            ring,
            _profile: profile,
        }
    }

    /// A key delivery to `host` in its room, built now against its bundle on its own board.
    async fn delivery_to(&self, host: &Profile) -> InFlight {
        let (_e, conn, room, ctx) = reach(&self.signer, host).await;
        let host_id = host_fingerprint(host);
        let mut c = RendezvousClient::open(&conn)
            .await
            .expect("APPARATUS: a rendezvous stream");
        let set = c
            .get(&room, ctx.epoch, RecordKinds::BUNDLES)
            .await
            .expect("APPARATUS: the host's board answers");
        c.finish();
        let bundle = set
            .bundles
            .into_iter()
            .find(|b| b.author_id == host_id)
            .expect("APPARATUS: the host's own bundle is on its board")
            .prekey_bundle;
        assert!(
            bundle.one_time_prekey.is_some(),
            "APPARATUS: the host's bundle names no one-time prekey"
        );
        let (initial, mut session) = vox_core::pairwise::session::Session::initiate(
            self.ring.identity_dh(),
            &bundle,
            &ctx.channel_id,
            ctx.epoch,
            ctx.suite_id,
            ctx.floor,
        )
        .expect("APPARATUS: a session opens from the host's bundle");
        use vox_core::identity::composite::RootSigner as _;
        let skdm = vox_core::group::skdm::Skdm::build(
            self.signer.as_ref(),
            &room,
            ctx.epoch,
            1_000_000,
            0,
            vox_core::group::senderkey::ChainKey::generate().expect("APPARATUS: a chain key"),
            self.signer.public_key().to_bytes(),
        )
        .expect("APPARATUS: a sender-key distribution message");
        let frame = pw::rotation_hello_frame(&room, &initial, &mut session, &skdm)
            .expect("APPARATUS: the delivery's frame");
        InFlight {
            frame,
            signer: Arc::clone(&self.signer),
        }
    }
}

impl InFlight {
    /// Send it to `host` now: `None` if the host took it, else its refusal in words.
    async fn send(&self, host: &Profile) -> Option<String> {
        let (_e, conn, _, _) = reach(&self.signer, host).await;
        let (mut send, recv) = open_typed(&conn, StreamKind::Pairwise)
            .await
            .expect("APPARATUS: a pairwise stream to the host");
        vox_core::transport::framing::write_frame(&mut send, &self.frame)
            .await
            .expect("APPARATUS: write the delivery");
        let _ = send.finish();
        pw::refused(recv, Duration::from_secs(20)).await
    }
}

fn host_fingerprint(host: &Profile) -> Digest32 {
    let fp = host.vox(&["id"], None).stdout;
    vox_core::node::link::b32_decode(fp.trim(), "fingerprint")
        .unwrap_or_else(|e| panic!("APPARATUS: {}'s id is no fingerprint: {e:?}", host.name))
}

/// Connect to `host` as the member, and its one room's id and context.
async fn reach(
    signer: &Arc<vox_core::atrest::vault::VaultRootSigner>,
    host: &Profile,
) -> (
    VoxEndpoint,
    Arc<VoxConnection>,
    Digest32,
    vox_core::join::session::JoinContext,
) {
    let status = host.vox(&["status", "--json"], None).stdout;
    let addr = ports::loopback_listen(&status).unwrap_or_else(|| {
        panic!(
            "APPARATUS: {}'s status names no loopback address",
            host.name
        )
    });
    let v: serde_json::Value = serde_json::from_str(status.trim()).expect("APPARATUS: status JSON");
    let r = &v["rooms"][0];
    let room = vox_core::node::link::b32_decode(r["id"].as_str().unwrap_or_default(), "room")
        .unwrap_or_else(|e| panic!("APPARATUS: {}'s room id: {e:?}: {status}", host.name));
    let epoch = r["epoch"].as_u64().unwrap_or(0);
    let endpoint = VoxEndpoint::bind(
        Arc::clone(signer) as Arc<_>,
        "127.0.0.1:0".parse().expect("APPARATUS: an address"),
    )
    .expect("APPARATUS: bind the member's endpoint");
    let host_id = host_fingerprint(host);
    let deadline = Instant::now() + Duration::from_secs(60);
    let conn = loop {
        match endpoint.connect(addr, host_id, wall_ms()).await {
            Ok(c) => break Arc::new(c),
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await
            }
            Err(e) => panic!(
                "APPARATUS: the member could not connect to {}: {e:?}",
                host.name
            ),
        }
    };
    let mut c = RendezvousClient::open(&conn)
        .await
        .expect("APPARATUS: a rendezvous stream");
    let set = c
        .get(&room, epoch, RecordKinds::GENESIS)
        .await
        .expect("APPARATUS: the host's board answers");
    c.finish();
    let genesis = set
        .genesis
        .expect("APPARATUS: the room's genesis is on its host's board");
    let ctx = vox_core::node::channel::join_context_from_genesis(&genesis, epoch)
        .expect("APPARATUS: the room's context");
    (endpoint, conn, room, ctx)
}
