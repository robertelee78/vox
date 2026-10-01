//! V210-94 (#288) — **when a lock is done, the process holds no copy of a passphrase that work
//! still running was given**, driven through the shipped `vox` binary and the real `vox tui` in a
//! pty, with the memory of the running TUI read from inside it.
//!
//! **The defect.** Three kinds of work run on a blocking thread holding a secret: a room's key
//! sealed under its passphrase with Argon2id (room creation, and a join), the identity
//! passphrase checked for a trust edit, and a room reopened at unlock from its remembered key and
//! passphrase (#208). A lock aborted the tasks that started them, but no abort reaches a blocking
//! thread: each ran on after the node said it was locked, holding what it was given — and the
//! seal was given the identity signer and the room's key as well as the passphrase.
//!
//! **Staging.** Bob's `vox tui` runs in a pty with `crates/vox-test-interpose` loaded, whose scan
//! (`VOX_INTERPOSE_SCAN`) reports every copy of a byte string in the process's written memory on
//! cue. `VOX_TEST_SECRET_WORK_DELAY_MS` makes each such blocking thread wait, holding its inputs,
//! before it works, so the lock lands while one runs. Per case: start the work, scan until the
//! passphrase it was given shows up in memory **more times than before it started** (the thread
//! holds it: this is also the check that the scan sees it at all), lock, and scan again once the
//! TUI has answered the lock.
//!
//! - **seal:** `vox room create`, the room passphrase;
//! - **check:** `vox trust list`, which asks the node to check the identity passphrase;
//! - **reopen:** bob's second TUI unlocks a profile with a remembered room and is locked with
//!   SIGHUP while that room reopens; the room passphrase.
//!
//! "Once the TUI has answered the lock" is once it shows LOCKED with an empty passphrase prompt:
//! the node publishes a locked view only when its lock is done, and a TUI still waiting on its
//! unlock (the reopen case) shows the prompt it was typed into, dots and all, until then.
//!
//! **Asserted,** with no tolerance: after the lock, the passphrase is **nowhere** in the process's
//! written memory, live or freed. Preconditions, or `CANNOT MEASURE`: the work had not finished
//! when the lock was asked for; the scan saw the work's copy before the lock.
//!
//! Not "no more copies than before the work": the identity passphrase typed at unlock is in memory
//! before a check starts, and the lock wipes that copy, which let a thread still holding its own
//! copy after the lock pass that comparison (measured on the mutant below: 1 before, 1 after).
//!
//! **Mutation that must turn it red:** the lock not waiting for those threads (`lock_all` without
//! taking `secret_work`'s write side): measured, one copy of the passphrase left after the lock in
//! each case, the lock answered in about 0.4 s instead of the 15 s the held thread takes.
//!
//! Also asserted, in the seal case: while the lock waits on the held seal, the node still
//! answers — a `vox room create` asked 2 s into the lock is answered (refused: locked) within
//! [`ANSWERS`] (V210-71). Mutation: the wait for the blocking threads back on the actor; measured
//! below in the commit's evidence.
//!
//! Also asserted: a typed `:lock` that waits more than [`SAID_LOCKING_AFTER`] shows "locking…"
//! meanwhile. Mutation: `say_locking` not called (`app.rs`); the TUI then looks frozen for the
//! whole wait.
//!
//! - **grind:** bob joins alice's room, and his node's proof-of-work grind is held long
//!   (`VOX_TEST_SOLVE_AT_LEAST_MS`, the product's test-only floor on a joiner's grind); the room
//!   passphrase. The join task held it across the whole grind, which no abort reached, so the lock
//!   waited the grind out. Asserted here besides the scan: a command asked at once is answered
//!   within [`ANSWERS`], and the lock settles within [`SETTLES`], not once the grind ends.
//!   Mutation: the grind back inside the task (`block_in_place`, holding the passphrase); the lock
//!   then settles only when the held grind ends, about [`GRIND_MS`] later.
//!
//! What is not measured here, and rests on review: that the seal's thread is given the passphrase
//! alone (not the signer or the room key), since neither the identity's key nor a random room key
//! is known to a test; and the zeroizing of CBOR buffers that grow (`Encoder::for_secrets`).

#![cfg(target_os = "macos")]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[path = "support/syscalls.rs"]
mod syscalls;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// How long each blocking thread holding a secret waits before its work, holding it.
const DELAY_MS: &str = "15000";
/// How long the work has to show up in memory once started.
const SHOWS_UP: Duration = Duration::from_secs(60);
/// A command asked of the node while its lock settles is answered within this.
const ANSWERS: Duration = Duration::from_secs(5);
/// How long a joiner's grind is held in the grind case: far past [`SETTLES`].
const GRIND_MS: &str = "60000";
/// A lock with nothing but a join's grind in flight settles within this.
const SETTLES: Duration = Duration::from_secs(10);
/// A typed `:lock` that took longer than this must have shown "locking…" while it waited.
const SAID_LOCKING_AFTER: Duration = Duration::from_secs(2);
/// The scanner's mask (`crates/vox-test-interpose/src/scan.rs`).
const MASK: u8 = 0xA5;

/// A child process, killed by its own PID when dropped.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A passphrase no other run, and nothing else in the process, can hold.
fn unique(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{tag}-{:x}-{nanos:x}", std::process::id())
}

fn command(dir: &Path, args: &[&str], identity: &str) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", identity)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION");
    cmd
}

/// Start `vox <args>` with `stdin` written to it.
fn start(dir: &Path, args: &[&str], identity: &str, stdin: Option<&str>) -> Proc {
    let mut child = command(dir, args, identity)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(text.as_bytes()).expect("write stdin");
    }
    Proc(child)
}

/// Wait up to `within` for `path` to exist.
fn cue(path: &Path, within: Duration) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < within {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The TUI's memory scanner, asked through files.
struct Scanner {
    dir: PathBuf,
}

/// One scan: how many copies of each needle, and where the first few are.
struct Scan {
    counts: BTreeMap<String, usize>,
    hits: Vec<String>,
    scanned: String,
}

impl Scan {
    fn of(&self, label: &str) -> usize {
        self.counts[label]
    }
}

impl Scanner {
    fn new(dir: PathBuf, needles: &[(&str, &str)]) -> Self {
        std::fs::create_dir_all(&dir).unwrap();
        let text: String = needles
            .iter()
            .map(|(label, s)| {
                let hex: String = s.bytes().map(|b| format!("{:02x}", b ^ MASK)).collect();
                format!("{label}\t{hex}\n")
            })
            .collect();
        std::fs::write(dir.join("needles"), text).unwrap();
        Self { dir }
    }

    fn scan(&self) -> Scan {
        let result = self.dir.join("result");
        let _ = std::fs::remove_file(&result);
        std::fs::write(self.dir.join("go"), b"").unwrap();
        assert!(
            cue(&result, Duration::from_secs(60)),
            "CANNOT MEASURE: the TUI's scanner never answered (is the interposer loaded?)"
        );
        let text = std::fs::read_to_string(&result).unwrap();
        let mut scan = Scan {
            counts: BTreeMap::new(),
            hits: Vec::new(),
            scanned: String::new(),
        };
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            match f.first().copied() {
                Some("count") => {
                    scan.counts.insert(f[1].to_owned(), f[2].parse().unwrap());
                }
                Some("hit") => scan.hits.push(f[1..].join(" ")),
                Some("scanned") => scan.scanned = f[1..].join(" "),
                _ => panic!("CANNOT MEASURE: the scanner said {line:?}"),
            }
        }
        assert!(
            !scan.scanned.is_empty(),
            "CANNOT MEASURE: a scan with no total:\n{text}"
        );
        scan
    }

    /// Scan until `label` shows more copies than `before`, for up to [`SHOWS_UP`].
    fn until_more(&self, label: &str, before: usize) -> Option<Scan> {
        let t0 = Instant::now();
        while t0.elapsed() < SHOWS_UP {
            let scan = self.scan();
            if scan.of(label) > before {
                return Some(scan);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }
}

/// Bob's TUI, driven by `tui_lock_for_scan.py`.
struct Tui {
    cues: PathBuf,
    driver: Option<std::thread::JoinHandle<pty_driver::Driven>>,
    tag: String,
}

impl Tui {
    fn start(bob: &Path, identity: &str, cues: PathBuf, tag: &str, extra: &[String]) -> Self {
        std::fs::create_dir_all(&cues).unwrap();
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pty/tui_lock_for_scan.py"
        );
        let mut args: Vec<String> = vec![
            VOX.to_owned(),
            bob.to_str().unwrap().to_owned(),
            bob.join("cfg").to_str().unwrap().to_owned(),
            identity.to_owned(),
            cues.to_str().unwrap().to_owned(),
            tag.to_owned(),
        ];
        args.extend(extra.iter().cloned());
        let driver = std::thread::spawn(move || {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            pty_driver::run(script, &args)
        });
        Self {
            cues,
            driver: Some(driver),
            tag: tag.to_owned(),
        }
    }

    fn pid(&self) -> u32 {
        assert!(
            cue(&self.cues.join("pid"), Duration::from_secs(60)),
            "CANNOT MEASURE: {}'s TUI never started",
            self.tag
        );
        std::fs::read_to_string(self.cues.join("pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn unlocked(&mut self) {
        if cue(&self.cues.join("unlocked"), Duration::from_secs(120)) {
            return;
        }
        // What the TUI showed instead: the driver prints its screen when stopped early.
        std::fs::write(self.cues.join("stop"), b"").unwrap();
        let driven = self.driver.take().unwrap().join().expect("the TUI driver");
        panic!(
            "CANNOT MEASURE: {}'s TUI never unlocked; its driver said:\n{}",
            self.tag, driven.stdout
        );
    }

    /// Lock the TUI — `:lock` typed, or with `hup` a SIGHUP — and wait until it shows itself
    /// locked; how long that took. A typed `:lock` that waits must have said "locking…" meanwhile:
    /// the TUI waits on the lock's answer, and looked frozen (V210-94).
    fn lock(&self, hup: bool) -> Duration {
        let t0 = self.ask_lock(hup);
        self.wait_locked(t0, hup)
    }

    /// Ask for the lock, without waiting for it; when it was asked.
    fn ask_lock(&self, hup: bool) -> Instant {
        let how: &[u8] = if hup { b"hup" } else { b"key" };
        std::fs::write(self.cues.join("lock"), how).unwrap();
        Instant::now()
    }

    /// Whether the TUI has shown itself locked yet.
    fn is_locked(&self) -> bool {
        self.cues.join("locked").exists()
    }

    /// Wait until the TUI shows itself locked; how long since the lock was asked for at `t0`.
    fn wait_locked(&self, t0: Instant, hup: bool) -> Duration {
        assert!(
            cue(&self.cues.join("locked"), Duration::from_secs(150)),
            "CANNOT MEASURE: {}'s TUI never showed itself locked",
            self.tag
        );
        let took = t0.elapsed();
        let cue_text = std::fs::read_to_string(self.cues.join("locked")).unwrap_or_default();
        let (said, waited) = cue_text.split_once(' ').unwrap_or((cue_text.as_str(), ""));
        // How long the TUI itself waited, from `:lock` to showing itself locked: `took` also
        // counts whatever the proof did in between.
        let waited = Duration::from_secs_f64(waited.trim().parse().unwrap_or(0.0));
        println!(
            "[proof] {}'s TUI while the lock ran: {said}, for {waited:?}",
            self.tag
        );
        if !hup && waited > SAID_LOCKING_AFTER {
            assert_eq!(
                said, "said-locking",
                "{}'s TUI waited {waited:?} on :lock and never said it was locking: it looked \
                 frozen",
                self.tag
            );
        }
        took
    }

    fn stop(mut self) {
        std::fs::write(self.cues.join("stop"), b"").unwrap();
        let driven = self.driver.take().unwrap().join().expect("the TUI driver");
        println!(
            "[proof] {}'s TUI driver exited {:?} after {:?} at {:?}",
            self.tag, driven.code, driven.took, driven.stage
        );
        assert!(
            driven.has_verdict(&self.tag) && driven.code == Some(0),
            "CANNOT MEASURE: {}'s TUI driver did not finish cleanly:\n{}",
            self.tag,
            driven.stdout
        );
    }
}

/// The environment bob's TUI runs with: the scanner loaded, and each secret-holding thread slow.
fn tui_env(scan: &Path) -> Vec<String> {
    vec![
        format!("VOX_PTY_DYLD_INSERT={}", syscalls::interposer().display()),
        format!("VOX_INTERPOSE_SCAN={}", scan.display()),
        format!("VOX_TEST_SECRET_WORK_DELAY_MS={DELAY_MS}"),
    ]
}

fn new_profile(dir: &Path, identity: &str) {
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let out = command(dir, &["id"], identity).output().expect("vox id");
    assert!(
        out.status.success(),
        "vox id: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Whether `work` is still running; `CANNOT MEASURE` if it already finished.
fn still_running(work: &mut Proc, what: &str) {
    let early = work.0.try_wait().expect("poll");
    assert!(
        early.is_none(),
        "CANNOT MEASURE: {what} finished ({early:?}) before the lock, so nothing was in flight"
    );
}

/// The verdict for one case: no copy of the needle after the lock.
fn judge(case: &str, label: &str, before: &Scan, during: &Scan, after: &Scan, took: Duration) {
    println!(
        "[proof] {case}: copies of the {label} passphrase in the TUI's memory — before the work \
         {}, while it ran {}, after the lock {} (the lock answered {took:?} after it was asked); \
         after the lock: {:?}; scanned {}",
        before.of(label),
        during.of(label),
        after.of(label),
        after.hits,
        after.scanned
    );
    assert!(
        after.of(label) == 0,
        "{case}: the lock is done and the {label} passphrase is still in memory: {} copies, at \
         {:?} ({} before the work started, {} while it ran) — work the lock did not wait for \
         still holds it",
        after.of(label),
        after.hits,
        before.of(label),
        during.of(label)
    );
}

#[test]
#[ignore = "real vox tui in a pty with the interposer loaded, production Argon2id; macOS"]
fn a_lock_waits_for_a_room_seal_and_leaves_no_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let bob = tmp.path().join("bob");
    let (identity, roompass) = (unique("idp"), unique("seal-rp"));
    new_profile(&bob, &identity);
    let scanner = Scanner::new(tmp.path().join("scan"), &[("room", &roompass)]);
    let mut tui = Tui::start(
        &bob,
        &identity,
        tmp.path().join("cues"),
        "bob",
        &tui_env(&scanner.dir),
    );
    tui.unlocked();
    let before = scanner.scan();
    let mut create = start(
        &bob,
        &["room", "create", "--name", "r"],
        &identity,
        Some(&format!("{roompass}\n")),
    );
    let during = scanner
        .until_more("room", before.of("room"))
        .expect("CANNOT MEASURE: the room passphrase never showed up in the TUI's memory");
    still_running(&mut create, "vox room create");
    let asked = tui.ask_lock(false);
    // **The node answers while the lock settles** (V210-71): a command that goes through the
    // node's actor, asked while the lock waits on the held seal, is answered within
    // [`ANSWERS`], not once the lock is done.
    std::thread::sleep(Duration::from_secs(2));
    let probe_at = Instant::now();
    let mut probe = start(
        &bob,
        &["room", "create", "--name", "probe"],
        &identity,
        Some("a probe passphrase\n"),
    );
    let probe_status = probe.0.wait().expect("the probe");
    let probe_took = probe_at.elapsed();
    let settled_first = tui.is_locked();
    let took = tui.wait_locked(asked, false);
    println!(
        "[proof] seal: a `vox room create` asked 2 s into the lock answered in {probe_took:?} \
         ({probe_status}); the lock had settled by then: {settled_first}"
    );
    assert!(
        !settled_first,
        "CANNOT MEASURE: the lock settled before the probe answered, so nothing was waited on"
    );
    assert!(
        probe_took < ANSWERS,
        "the node answered nobody while its lock settled: a command took {probe_took:?} (bound \
         {ANSWERS:?}) — the actor waited for the lock"
    );
    let after = scanner.scan();
    let answered = create.0.try_wait().expect("poll");
    println!("[proof] seal: vox room create after the lock: {answered:?}");
    tui.stop();
    judge("seal", "room", &before, &during, &after, took);
}

#[test]
#[ignore = "real vox tui in a pty with the interposer loaded, production Argon2id; macOS"]
fn a_lock_waits_for_a_passphrase_check_and_leaves_no_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let bob = tmp.path().join("bob");
    let identity = unique("check-idp");
    new_profile(&bob, &identity);
    let scanner = Scanner::new(tmp.path().join("scan"), &[("identity", &identity)]);
    let mut tui = Tui::start(
        &bob,
        &identity,
        tmp.path().join("cues"),
        "bob",
        &tui_env(&scanner.dir),
    );
    tui.unlocked();
    let before = scanner.scan();
    let mut check = start(&bob, &["trust", "list"], &identity, None);
    let during = scanner
        .until_more("identity", before.of("identity"))
        .expect("CANNOT MEASURE: the identity passphrase never showed up again in memory");
    still_running(&mut check, "vox trust list");
    let took = tui.lock(false);
    let after = scanner.scan();
    tui.stop();
    judge("check", "identity", &before, &during, &after, took);
}

#[test]
#[ignore = "real vox tui in a pty with the interposer loaded, production Argon2id; macOS"]
fn a_lock_waits_for_a_room_reopening_and_leaves_no_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let bob = tmp.path().join("bob");
    let (identity, roompass) = (unique("idp"), unique("reopen-rp"));
    new_profile(&bob, &identity);
    // A room bob holds open, so his next unlock reopens it (#208).
    {
        let mut tui = Tui::start(&bob, &identity, tmp.path().join("cues1"), "bob1", &[]);
        tui.unlocked();
        let mut create = start(
            &bob,
            &["room", "create", "--name", "r"],
            &identity,
            Some(&format!("{roompass}\n")),
        );
        let status = create.0.wait().expect("vox room create");
        assert!(status.success(), "CANNOT MEASURE: vox room create failed");
        tui.lock(false);
        tui.stop();
    }
    let scanner = Scanner::new(tmp.path().join("scan"), &[("room", &roompass)]);
    let tui = Tui::start(
        &bob,
        &identity,
        tmp.path().join("cues2"),
        "bob2",
        &tui_env(&scanner.dir),
    );
    tui.pid();
    let before = scanner.scan();
    let during = scanner
        .until_more("room", before.of("room"))
        .expect("CANNOT MEASURE: the room passphrase never showed up: no reopening");
    assert!(
        !tui.cues.join("unlocked").exists(),
        "CANNOT MEASURE: the TUI finished unlocking, so the reopening was not in flight"
    );
    let took = tui.lock(true);
    let after = scanner.scan();
    tui.stop();
    judge("reopen", "room", &before, &during, &after, took);
}

/// Read `child`'s stdout until a line matches `wanted`; the line.
fn line_from(child: &mut Proc, what: &str, wanted: impl Fn(&str) -> bool) -> String {
    use std::io::BufRead as _;
    let out = child.0.stdout.take().expect("stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(60) {
        if let Ok(line) = rx.recv_timeout(Duration::from_millis(200)) {
            if wanted(&line) {
                return line;
            }
        }
    }
    panic!("CANNOT MEASURE: {what} never printed what was waited for");
}

#[test]
#[ignore = "real vox tui in a pty with the interposer loaded, a real join; macOS"]
fn a_lock_does_not_wait_out_a_joins_grind_and_leaves_no_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, alice, bob) = (
        tmp.path().join("anchor"),
        tmp.path().join("alice"),
        tmp.path().join("bob"),
    );
    let (alice_id, identity, roompass) = (unique("alice-idp"), unique("idp"), unique("grind-rp"));
    std::fs::create_dir_all(anchor_dir.join("cfg")).unwrap();
    new_profile(&alice, &alice_id);
    new_profile(&bob, &identity);
    // An anchor, and alice hosting a room through it, all the shipped binary.
    let mut anchor = start(
        &anchor_dir,
        &["node", "--listen", "127.0.0.1:0"],
        "unused",
        None,
    );
    let spec = line_from(&mut anchor, "the anchor", |l| {
        l.contains("@/ip4/127.0.0.1/udp/")
    })
    .split_whitespace()
    .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
    .unwrap()
    .to_owned();
    let _alice_daemon = start(
        &alice,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &alice_id,
        Some(&format!("{alice_id}\n")),
    );
    let t0 = Instant::now();
    while !command(&alice, &["room", "list"], &alice_id)
        .output()
        .is_ok_and(|o| o.status.success())
    {
        assert!(
            t0.elapsed() < Duration::from_secs(120),
            "CANNOT MEASURE: alice's daemon never answered"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let mut create = start(
        &alice,
        &["room", "create", "--name", "team"],
        &alice_id,
        Some(&format!("{roompass}\n")),
    );
    assert!(
        create.0.wait().expect("room create").success(),
        "CANNOT MEASURE: alice could not create the room"
    );
    let list = command(&alice, &["room", "list"], &alice_id)
        .output()
        .unwrap();
    let prefix = String::from_utf8_lossy(&list.stdout)
        .split_whitespace()
        .next()
        .expect("CANNOT MEASURE: alice's room in `vox room list`")
        .to_owned();
    let invite = command(&alice, &["room", "invite", &prefix], &alice_id)
        .output()
        .unwrap();
    assert!(invite.status.success(), "CANNOT MEASURE: room invite");
    let link = String::from_utf8_lossy(&invite.stdout).trim().to_owned();

    // Bob's TUI, scanned, with his node's grind held long.
    let scanner = Scanner::new(tmp.path().join("scan"), &[("room", &roompass)]);
    let mut env = tui_env(&scanner.dir);
    env.retain(|e| !e.starts_with("VOX_TEST_SECRET_WORK_DELAY_MS="));
    env.push(format!("VOX_TEST_SOLVE_AT_LEAST_MS={GRIND_MS}"));
    env.push(format!("VOX_ANCHORS={spec}"));
    let mut tui = Tui::start(&bob, &identity, tmp.path().join("cues"), "bob", &env);
    tui.unlocked();
    let before = scanner.scan();
    let mut join = start(
        &bob,
        &["room", "join", &link, "--name", "team"],
        &identity,
        Some(&format!("{roompass}\n")),
    );
    let during = scanner
        .until_more("room", before.of("room"))
        .expect("CANNOT MEASURE: the room passphrase never showed up in the TUI's memory");
    // Into the grind: past the dial and the challenge, well short of the held grind's end.
    std::thread::sleep(Duration::from_secs(5));
    still_running(&mut join, "vox room join");
    let asked = tui.ask_lock(false);
    // **The node answers while the lock settles** (V210-71), asked at once.
    let probe_at = Instant::now();
    let mut probe = start(
        &bob,
        &["room", "create", "--name", "probe"],
        &identity,
        Some("a probe passphrase\n"),
    );
    let probe_status = probe.0.wait().expect("the probe");
    let probe_took = probe_at.elapsed();
    let took = tui.wait_locked(asked, false);
    let after = scanner.scan();
    let joined = join.0.try_wait().expect("poll");
    println!(
        "[proof] grind: a `vox room create` asked as the lock began answered in {probe_took:?} \
         ({probe_status}); the lock settled {took:?} after it was asked (bound {SETTLES:?}, the \
         held grind {GRIND_MS} ms); vox room join after the lock: {joined:?}"
    );
    assert!(
        probe_took < ANSWERS,
        "the node answered nobody while its lock settled: a command took {probe_took:?} (bound \
         {ANSWERS:?}) — the actor waited for the lock"
    );
    assert!(
        took < SETTLES,
        "the lock waited out the join's grind: it settled {took:?} after it was asked (bound \
         {SETTLES:?}) — the grind held the join's secrets where no abort reached them"
    );
    tui.stop();
    judge("grind", "room", &before, &during, &after, took);
}
