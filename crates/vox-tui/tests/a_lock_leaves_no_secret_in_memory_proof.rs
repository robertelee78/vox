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
//! Also asserted: a typed `:lock` that waits more than [`SAID_LOCKING_AFTER`] shows "locking…"
//! meanwhile. Mutation: `say_locking` not called (`app.rs`); the TUI then looks frozen for the
//! whole wait.
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
        let t0 = Instant::now();
        let how: &[u8] = if hup { b"hup" } else { b"key" };
        std::fs::write(self.cues.join("lock"), how).unwrap();
        assert!(
            cue(&self.cues.join("locked"), Duration::from_secs(150)),
            "CANNOT MEASURE: {}'s TUI never showed itself locked",
            self.tag
        );
        let took = t0.elapsed();
        let said = std::fs::read_to_string(self.cues.join("locked")).unwrap_or_default();
        println!("[proof] {}'s TUI while the lock ran: {said}", self.tag);
        if !hup && took > SAID_LOCKING_AFTER {
            assert_eq!(
                said, "said-locking",
                "{}'s TUI waited {took:?} on :lock and never said it was locking: it looked frozen",
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
    let took = tui.lock(false);
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
