//! V210-94 (#288), retargeted to the daemon (ADR-026 N-2, L-3; #409) — **when a node's detach is
//! done, the daemon's process holds no copy of a passphrase that work still running for that node
//! was given**, and **the TUI holds no copy of the identity passphrase typed into it once its node
//! has attached**: driven through the shipped `vox` binary — a `vox daemon` and the real `vox tui`
//! in a pty — with the memory of the running daemon (and of the TUI) read from inside it.
//!
//! **What changed.** There is no lock any more (ADR-026 N-2): the TUI is a client of the account's
//! daemon and holds no node (S-4). A node takes its passphrase once, when it attaches, and its
//! secrets are wiped when it detaches (L-3). So what V210-94 proved of a lock is proved here of a
//! detach, in the process that holds the secrets now: the daemon. The defect it guards is the same:
//! three kinds of work run on a blocking thread holding a secret — a room's key sealed under its
//! passphrase with Argon2id (room creation, and a join), the identity passphrase checked for a
//! trust read, and a room reopened at attach from its remembered key and passphrase (#208). No
//! abort reaches a blocking thread, so a detach that did not wait for them left each running on
//! after it, holding what it was given.
//!
//! **Staging.** A `vox daemon` started by hand (so it does not exit when bob's node goes, L-8) runs
//! with `crates/vox-test-interpose` loaded, whose scan (`VOX_INTERPOSE_SCAN`) reports every copy
//! of a byte string in the process's written memory on cue. It holds a node `keeper` with no
//! passphrase, so it is a daemon with something attached; bob's node is attached by bob's real
//! `vox tui`, given his identity passphrase at its "Attach node" prompt
//! (`tests/pty/tui_attach_for_scan.py`). `VOX_TEST_SECRET_WORK_DELAY_MS` makes each blocking thread
//! holding a secret wait, holding its inputs, before it works, so the detach lands while one runs.
//! Per case: start the work, scan until the passphrase it was given shows up in the daemon's memory
//! **more times than before it started** (the thread holds it: this is also the check that the
//! scan sees it at all), detach bob's node, and scan again once the detach is done.
//!
//! - **seal:** `vox room create`, the room passphrase; detached with `vox node detach bob`;
//! - **check:** `vox trust add`, which sends the identity passphrase for the node to check;
//! - **reopen:** bob's TUI attaches a node with a remembered room, and is stopped with SIGHUP while
//!   that room reopens: the TUI was the node's last holder, so the node detaches once its attach is
//!   done (L-3); the room passphrase;
//! - **grind:** bob joins alice's room and his node's proof-of-work grind is held long
//!   (`VOX_TEST_SOLVE_AT_LEAST_MS`); detached mid-grind; the room passphrase. Asserted besides the
//!   scan: the detach is done within [`SETTLES`], not once the held grind ends.
//!
//! **Every case looks for every passphrase the detach is to wipe**: the one its work held, and the
//! identity passphrase the node was attached with.
//!
//! **Asserted,** with no tolerance: after the detach, no passphrase is anywhere in the daemon's
//! written memory, live or freed, **whole or as any 6-byte piece** (the scanner's `+pieces`). Also
//! asserted, in the seal and grind cases: while the detach waits on the held work, the daemon still
//! answers — a `vox node list` asked during it is answered within [`ANSWERS`] (V210-71).
//! Preconditions, or `PRODUCT (staging)`: the work had not finished when the detach was asked for;
//! the scan saw the work's copy before the detach.
//!
//! - **attach:** the TUI is scanned, not the daemon: once its node shows attached, the TUI holds no
//!   piece of the identity passphrase typed at its prompt. The terminal library kept a typed
//!   passphrase in its input buffer (V210-94); a secret field is read past it, and the `Use` that
//!   carries the passphrase to the daemon is wiped once sent (C-6).
//!
//! **Mutations that must turn it red:** the detach not waiting for the secret-holding threads
//! (`lock_all` without taking `secret_work`'s write side) — a passphrase copy left after the detach;
//! the TUI's attach passphrase kept (`DaemonCore::attach` holding the `Use`'s passphrase past the
//! attach) — the attach case red.
//!
//! **Why a file of its own.** Each case needs the scanner (`vox-test-interpose`, loaded with
//! `DYLD_INSERT_LIBRARIES` and reading memory with `mach_vm_*`), which is macOS-only, and a moment
//! held open by a test-only knob (`--features vox-tui/test-knobs`, #300); each case refuses as
//! CANNOT MEASURE a `vox` without them (`support/test_knobs.rs`'s `require`).
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

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// How long each blocking thread holding a secret waits before its work, holding it.
const DELAY_MS: &str = "15000";
/// The same for the reopen case, where the attach's own passphrase check is held first and a scan
/// of the daemon takes a second or so: long enough that the reopen is still held when it is seen.
const REOPEN_DELAY_MS: &str = "45000";
/// How long the work has to show up in memory once started.
const SHOWS_UP: Duration = Duration::from_secs(60);
/// A daemon request asked while a detach settles is answered within this.
const ANSWERS: Duration = Duration::from_secs(5);
/// How long a joiner's grind is held in the grind case: far past [`SETTLES`].
const GRIND_MS: &str = "60000";
/// A detach with nothing but a join's grind in flight is done within this, in either build (the
/// lock's bound, V210-94: 5.1 s measured at worst, doubled and rounded up; the held grind is 60 s).
const SETTLES: Duration = Duration::from_secs(25);
/// The scanner's mask (`crates/vox-test-interpose/src/scan.rs`).
const MASK: u8 = 0xA5;

/// **Every red names which it is** (the decider's rule 1). A step of the proof's own staging that
/// fails — a file, a process, a parse — is `APPARATUS (harness error)` at its line; what the
/// product did wrong is `PRODUCT:`. Nothing here unwraps bare.
trait Staged<T> {
    /// The value, or `APPARATUS (harness error)` naming this line and what failed.
    fn staged(self) -> T;
}

impl<T, E: std::fmt::Debug> Staged<T> for Result<T, E> {
    #[track_caller]
    fn staged(self) -> T {
        let at = std::panic::Location::caller();
        self.unwrap_or_else(|e| panic!("APPARATUS (harness error) at {at}: {e:?}"))
    }
}

impl<T> Staged<T> for Option<T> {
    #[track_caller]
    fn staged(self) -> T {
        let at = std::panic::Location::caller();
        self.unwrap_or_else(|| panic!("APPARATUS (harness error) at {at}: nothing there"))
    }
}

/// A child process, stopped by its own PID when dropped: SIGTERM, a bounded wait, then SIGKILL.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(10) {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A passphrase no other run, and nothing else in the process, can hold — **nor any 6-byte piece
/// of** (V210-94). Its letters come only from a rare alphabet and in no word, drawn from the clock,
/// the process and `tag` and stirred, so two passphrases in one run share no piece.
fn unique(tag: &str) -> String {
    const ALPHABET: &[u8; 16] = b"QXJZKVWYqxjzkvwy";
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .staged()
        .as_nanos();
    let mut state = (nanos as u64)
        ^ u64::from(std::process::id()).rotate_left(32)
        ^ tag.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
        });
    // splitmix64, one draw per 16 letters.
    let mut next = || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    let mut out = String::with_capacity(32);
    for _ in 0..2 {
        let mut word = next();
        for _ in 0..16 {
            out.push(char::from(ALPHABET[(word & 0xf) as usize]));
            word >>= 4;
        }
    }
    out
}

/// `vox <args>` as `node`, in the data root `dir`. No passphrase is in its environment: one a
/// verb needs is given in a file or on stdin, as a person gives it.
fn command(dir: &Path, node: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_NODE", node)
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION");
    cmd
}

/// Start `vox <args>` as `node` with `stdin` written to it and closed.
fn start(dir: &Path, node: &str, args: &[&str], stdin: Option<&str>) -> Proc {
    start_with(command(dir, node, args), stdin)
}

fn start_with(mut cmd: Command, stdin: Option<&str>) -> Proc {
    let mut child = cmd
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .staged();
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().staged();
        pipe.write_all(text.as_bytes()).staged();
    }
    Proc(child)
}

/// Run `vox <args>` as `node` to its end: whether it succeeded, and what it said.
fn run(dir: &Path, node: &str, args: &[&str]) -> (bool, String) {
    let out = command(dir, node, args).output().staged();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
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

/// A process's memory scanner, asked through files.
struct Scanner {
    dir: PathBuf,
    whose: &'static str,
}

/// One scan: how many copies of each needle, and where the first few are.
struct Scan {
    counts: BTreeMap<String, usize>,
    /// For each needle, how many places hold a 6-byte piece of it (the scanner's `+pieces`).
    pieces: BTreeMap<String, usize>,
    hits: Vec<String>,
    scanned: String,
}

impl Scan {
    fn of(&self, label: &str) -> usize {
        self.counts.get(label).copied().unwrap_or_else(|| {
            panic!("APPARATUS (harness error): the scan reported no count for {label}")
        })
    }

    fn pieces_of(&self, label: &str) -> usize {
        self.pieces.get(label).copied().unwrap_or_else(|| {
            panic!("APPARATUS (harness error): the scan reported no pieces for {label}")
        })
    }
}

impl Scanner {
    fn new(dir: PathBuf, whose: &'static str, needles: &[(&str, &str)]) -> Self {
        std::fs::create_dir_all(&dir).staged();
        let text: String = needles
            .iter()
            .map(|(label, s)| {
                let hex: String = s.bytes().map(|b| format!("{:02x}", b ^ MASK)).collect();
                // `+pieces`: every 6-byte window of it is looked for too (V210-94). A copy the
                // product partly overwrote is still a copy.
                format!("{label}+pieces\t{hex}\n")
            })
            .collect();
        std::fs::write(dir.join("needles"), text).staged();
        Self { dir, whose }
    }

    fn scan(&self) -> Scan {
        let result = self.dir.join("result");
        let _ = std::fs::remove_file(&result);
        std::fs::write(self.dir.join("go"), b"").staged();
        assert!(
            cue(&result, Duration::from_secs(60)),
            "APPARATUS: the {}'s scanner never answered (is the interposer loaded?)",
            self.whose
        );
        let text = std::fs::read_to_string(&result).staged();
        let mut scan = Scan {
            counts: BTreeMap::new(),
            pieces: BTreeMap::new(),
            hits: Vec::new(),
            scanned: String::new(),
        };
        let number = |v: Option<&&str>| -> usize {
            v.and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("APPARATUS (harness error): the scanner wrote {text:?}"))
        };
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            match f.first().copied() {
                Some("count") => {
                    scan.counts.insert(f[1].to_owned(), number(f.get(2)));
                }
                Some("pieces") => {
                    scan.pieces.insert(f[1].to_owned(), number(f.get(2)));
                }
                Some("hit") => scan.hits.push(f[1..].join(" ")),
                Some("scanned") => scan.scanned = f[1..].join(" "),
                _ => panic!("APPARATUS (harness error): the scanner said {line:?}"),
            }
        }
        assert!(
            !scan.scanned.is_empty(),
            "APPARATUS: a scan with no total:\n{text}"
        );
        scan
    }

    /// Scan until `label` shows more copies than `before`, for up to [`SHOWS_UP`].
    /// `PRODUCT (staging)` if it never does: the work the case detaches during never held the
    /// passphrase where the scan could see it.
    fn until_more(&self, label: &str, before: usize) -> Scan {
        let t0 = Instant::now();
        while t0.elapsed() < SHOWS_UP {
            let scan = self.scan();
            if scan.of(label) > before {
                return scan;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "PRODUCT (staging): the {label} passphrase never showed up in the {}'s memory within \
             {SHOWS_UP:?} of the work starting",
            self.whose
        )
    }
}

/// An account: its data root, with node `keeper` (no passphrase) and node `bob` (`identity`).
struct Account {
    dir: PathBuf,
    identity: String,
    /// `keeper`'s fingerprint, as `vox node create` printed it: someone for bob to trust.
    keeper: String,
}

impl Account {
    fn new(dir: PathBuf, identity: &str) -> Self {
        std::fs::create_dir_all(dir.join("cfg")).staged();
        let mut keeper = String::new();
        for (node, pass) in [("keeper", ""), ("bob", identity)] {
            let file = dir.join(format!("{node}.pass"));
            std::fs::write(&file, format!("{pass}\n")).staged();
            let (ok, said) = run(
                &dir,
                node,
                &[
                    "node",
                    "create",
                    node,
                    "--passphrase-file",
                    file.to_str().staged(),
                ],
            );
            // The file held it only to make the node: gone before the daemon starts.
            std::fs::remove_file(&file).staged();
            assert!(
                ok,
                "PRODUCT (staging): `vox node create {node}` made no node to stage with: {said}"
            );
            if node == "keeper" {
                keeper = said
                    .split_whitespace()
                    .find(|w| w.len() == 52)
                    .unwrap_or_else(|| {
                        panic!(
                            "PRODUCT (staging): `vox node create` printed no fingerprint: {said}"
                        )
                    })
                    .to_owned();
            }
        }
        Self {
            dir,
            identity: identity.to_owned(),
            keeper,
        }
    }

    /// `vox daemon` started by hand, holding `keeper`, with `env` (the scanner, the knobs).
    fn daemon(&self, env: &[(String, String)]) -> Proc {
        let mut cmd = command(
            &self.dir,
            "keeper",
            &["daemon", "--node", "keeper", "--listen", "127.0.0.1:0"],
        );
        for (k, v) in env {
            cmd.env(k, v);
        }
        // `keeper` has no passphrase: an empty line gives none.
        let daemon = start_with(cmd, Some("\n"));
        let t0 = Instant::now();
        loop {
            let (ok, said) = run(&self.dir, "keeper", &["node", "list"]);
            if ok && said.lines().any(|l| l.starts_with("keeper attached")) {
                return daemon;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): the daemon never listed keeper attached: {said}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Whether `vox node list` says bob is detached: not attached, attaching or detaching.
    fn bob_detached(&self) -> bool {
        let (ok, said) = run(&self.dir, "keeper", &["node", "list"]);
        ok && said.lines().any(|l| l.starts_with("bob detached"))
    }

    /// Start `vox node detach bob`.
    fn detach_bob(&self) -> Proc {
        start(&self.dir, "bob", &["node", "detach", "bob"], None)
    }
}

/// Wait for a started `vox node detach` to end: how long since `t0`. `PRODUCT` if it fails.
fn detached(mut detach: Proc, t0: Instant) -> Duration {
    let status = detach.0.wait().staged();
    let took = t0.elapsed();
    let mut said = String::new();
    if let Some(mut e) = detach.0.stderr.take() {
        use std::io::Read as _;
        let _ = e.read_to_string(&mut said);
    }
    assert!(
        status.success(),
        "PRODUCT: `vox node detach bob` failed ({status}): {said}"
    );
    took
}

/// Ask the daemon something while a detach settles: how long it took to answer.
fn answered_meanwhile(account: &Account) -> Duration {
    let t0 = Instant::now();
    let (ok, said) = run(&account.dir, "keeper", &["node", "list"]);
    let took = t0.elapsed();
    assert!(
        ok,
        "PRODUCT: `vox node list` failed during the detach: {said}"
    );
    took
}

/// Bob's TUI, driven by `tui_attach_for_scan.py`.
struct Tui {
    cues: PathBuf,
    driver: Option<std::thread::JoinHandle<pty_driver::Driven>>,
    tag: String,
}

impl Tui {
    fn start(account: &Account, cues: PathBuf, tag: &str, extra: &[String]) -> Self {
        std::fs::create_dir_all(&cues).staged();
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/pty/tui_attach_for_scan.py"
        );
        let mut args: Vec<String> = vec![
            VOX.to_owned(),
            account.dir.to_str().staged().to_owned(),
            account.dir.join("cfg").to_str().staged().to_owned(),
            account.identity.clone(),
            cues.to_str().staged().to_owned(),
            tag.to_owned(),
            "VOX_NODE=bob".to_owned(),
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

    fn started(&mut self) {
        if !cue(&self.cues.join("pid"), Duration::from_secs(60)) {
            std::fs::write(self.cues.join("stop"), b"").staged();
            let said = self.said();
            panic!(
                "{}: {}'s TUI never started; {said}",
                driver_side(&said),
                self.tag
            );
        }
    }

    /// Wait until the passphrase is typed at the attach prompt, not yet submitted.
    fn typed(&mut self) {
        if cue(&self.cues.join("typed"), Duration::from_secs(120)) {
            return;
        }
        std::fs::write(self.cues.join("stop"), b"").staged();
        let said = self.said();
        panic!(
            "{}: {}'s TUI never asked for its node's passphrase; {said}",
            driver_side(&said),
            self.tag
        );
    }

    /// Submit the passphrase typed at the attach prompt.
    fn submit(&mut self) {
        self.typed();
        std::fs::write(self.cues.join("submit"), b"").staged();
    }

    /// Submit the passphrase typed at the attach prompt, and wait until the node shows attached.
    fn attached(&mut self) {
        self.submit();
        if cue(&self.cues.join("attached"), Duration::from_secs(120)) {
            return;
        }
        // What the TUI showed instead: the driver prints its screen when stopped early.
        std::fs::write(self.cues.join("stop"), b"").staged();
        let said = self.said();
        panic!(
            "{}: {}'s TUI never showed its node attached; {said}",
            driver_side(&said),
            self.tag
        );
    }

    /// SIGHUP the TUI, and wait until it has gone.
    fn hang_up(&self) {
        std::fs::write(self.cues.join("hup"), b"").staged();
        assert!(
            cue(&self.cues.join("gone"), Duration::from_secs(60)),
            "PRODUCT: {}'s TUI did not stop on SIGHUP",
            self.tag
        );
    }

    /// What the driver said when it stopped, or why it could not say.
    fn said(&mut self) -> String {
        match self.driver.take().map(std::thread::JoinHandle::join) {
            Some(Ok(d)) => format!("its driver exited {:?} saying:\n{}", d.code, d.stdout),
            Some(Err(_)) => "the TUI driver thread panicked".to_owned(),
            None => "its driver was already collected".to_owned(),
        }
    }

    fn stop(mut self) {
        std::fs::write(self.cues.join("stop"), b"").staged();
        let driven = self.driver.take().staged().join().staged();
        println!(
            "[proof] {}'s TUI driver exited {:?} after {:?} at {:?}",
            self.tag, driven.code, driven.took, driven.stage
        );
        if !(driven.has_verdict(&self.tag) && driven.code == Some(0)) {
            let own = !driven.has_verdict(&self.tag)
                || driven.stdout.contains(&format!("{} APPARATUS", self.tag));
            let side = if own { "APPARATUS" } else { "PRODUCT" };
            panic!(
                "{side}: {}'s TUI driver did not finish cleanly (exit {:?}):\n{}",
                self.tag, driven.code, driven.stdout
            );
        }
    }
}

/// The environment the daemon runs with: the scanner loaded, and each secret-holding thread slow.
fn daemon_env(scan: &Path, delay: Option<&str>) -> Vec<(String, String)> {
    let mut env = vec![
        (
            "DYLD_INSERT_LIBRARIES".to_owned(),
            syscalls::interposer().display().to_string(),
        ),
        ("VOX_INTERPOSE_SCAN".to_owned(), scan.display().to_string()),
    ];
    if let Some(ms) = delay {
        test_knobs::require(&["VOX_TEST_SECRET_WORK_DELAY_MS"]);
        env.push(("VOX_TEST_SECRET_WORK_DELAY_MS".to_owned(), ms.to_owned()));
    }
    env
}

/// Whether `work` is still running; `PRODUCT (staging)` if it already finished.
fn still_running(work: &mut Proc, what: &str) {
    let early = work.0.try_wait().staged();
    assert!(
        early.is_none(),
        "PRODUCT (staging): {what} finished ({early:?}) before the detach, so nothing was in flight"
    );
}

/// The verdict for one case: after the detach, **no copy and no 6-byte piece of any passphrase the
/// case looked for** in `whose` memory.
fn judge(case: &str, whose: &str, before: &Scan, during: &Scan, after: &Scan, took: Duration) {
    for label in after.counts.keys() {
        println!(
            "[proof] {case}: the {label} passphrase in the {whose}'s memory, copies (and 6-byte \
             pieces) — before the work {} ({}), while it ran {} ({}), after {} ({}) (done \
             {took:?} after it was asked)",
            before.of(label),
            before.pieces_of(label),
            during.of(label),
            during.pieces_of(label),
            after.of(label),
            after.pieces_of(label),
        );
    }
    println!(
        "[proof] {case}: after: {:?}; scanned {}",
        after.hits, after.scanned
    );
    for label in after.counts.keys() {
        assert!(
            after.of(label) == 0 && after.pieces_of(label) == 0,
            "PRODUCT: {case}: it is done and the {label} passphrase is still in the {whose}'s \
             memory: {} copies and {} places holding a 6-byte piece of it, at {:?} ({} copies \
             before the work started, {} while it ran)",
            after.of(label),
            after.pieces_of(label),
            after.hits,
            before.of(label),
            during.of(label)
        );
    }
}

#[test]
#[ignore = "real vox daemon with the interposer loaded and a real vox tui in a pty, production Argon2id; macOS"]
fn a_detach_waits_for_a_room_seal_and_leaves_no_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().staged();
    let (identity, roompass) = (unique("idp"), unique("seal-rp"));
    let account = Account::new(tmp.path().join("acct"), &identity);
    let scanner = Scanner::new(
        tmp.path().join("scan"),
        "daemon",
        &[("room", &roompass), ("identity", &identity)],
    );
    let _daemon = account.daemon(&daemon_env(&scanner.dir, Some(DELAY_MS)));
    let mut tui = Tui::start(&account, tmp.path().join("cues"), "bob", &[]);
    tui.attached();
    let before = scanner.scan();
    let mut create = start(
        &account.dir,
        "bob",
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{roompass}\n")),
    );
    let during = scanner.until_more("room", before.of("room"));
    still_running(&mut create, "vox room create");
    let asked = Instant::now();
    let mut detach = account.detach_bob();
    // **The daemon answers while the detach settles** (V210-71).
    std::thread::sleep(Duration::from_secs(2));
    let answered = answered_meanwhile(&account);
    let settled_first = detach.0.try_wait().staged().is_some();
    let took = detached(detach, asked);
    println!(
        "[proof] seal: a `vox node list` asked 2 s into the detach answered in {answered:?}; the \
         detach had settled by then: {settled_first}; it was done {took:?} after it was asked"
    );
    assert!(
        !settled_first,
        "PRODUCT (staging): the detach settled before the probe, so nothing was waited on"
    );
    assert!(
        answered < ANSWERS,
        "PRODUCT: the daemon answered nobody while a detach settled: `vox node list` took \
         {answered:?} (bound {ANSWERS:?})"
    );
    let after = scanner.scan();
    let answered = create.0.try_wait().staged();
    println!("[proof] seal: vox room create after the detach: {answered:?}");
    tui.stop();
    judge("seal", "daemon", &before, &during, &after, took);
}

#[test]
#[ignore = "real vox daemon with the interposer loaded and a real vox tui in a pty, production Argon2id; macOS"]
fn a_detach_waits_for_a_passphrase_check_and_leaves_no_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().staged();
    let identity = unique("check-idp");
    let account = Account::new(tmp.path().join("acct"), &identity);
    let scanner = Scanner::new(
        tmp.path().join("scan"),
        "daemon",
        &[("identity", &identity)],
    );
    let _daemon = account.daemon(&daemon_env(&scanner.dir, Some(DELAY_MS)));
    let mut tui = Tui::start(&account, tmp.path().join("cues"), "bob", &[]);
    tui.attached();
    let before = scanner.scan();
    let pass_file = tmp.path().join("idp");
    std::fs::write(&pass_file, format!("{identity}\n")).staged();
    // A keyring change sends the identity passphrase for the node to check (V210-159); a read
    // sends none (V210-165).
    let mut check = start(
        &account.dir,
        "bob",
        &[
            "trust",
            "add",
            &account.keeper,
            "--name",
            "keeper",
            "--identity-passphrase-file",
            pass_file.to_str().staged(),
        ],
        None,
    );
    let during = scanner.until_more("identity", before.of("identity"));
    still_running(&mut check, "vox trust add");
    let asked = Instant::now();
    let took = detached(account.detach_bob(), asked);
    let after = scanner.scan();
    tui.stop();
    judge("check", "daemon", &before, &during, &after, took);
}

#[test]
#[ignore = "real vox daemon with the interposer loaded and a real vox tui in a pty, production Argon2id; macOS"]
fn a_tui_gone_mid_attach_leaves_no_passphrase_once_its_node_detaches() {
    watchdog::arm();
    let tmp = tempfile::tempdir().staged();
    let (identity, roompass) = (unique("idp"), unique("reopen-rp"));
    let account = Account::new(tmp.path().join("acct"), &identity);
    let scanner = Scanner::new(
        tmp.path().join("scan"),
        "daemon",
        &[("room", &roompass), ("identity", &identity)],
    );
    let _daemon = account.daemon(&daemon_env(&scanner.dir, None));
    // A room bob holds open, so his node's next attach reopens it (#208).
    {
        let mut tui = Tui::start(&account, tmp.path().join("cues1"), "bob1", &[]);
        tui.attached();
        let mut create = start(
            &account.dir,
            "bob",
            &["room", "create", "--passphrase-file", "-", "--name", "r"],
            Some(&format!("{roompass}\n")),
        );
        assert!(
            create.0.wait().staged().success(),
            "PRODUCT (staging): vox room create failed"
        );
        tui.stop();
        wait_detached(&account, "bob1's TUI quit");
    }
    // The daemon again, now with each secret-holding thread slow: the reopen is held.
    drop(_daemon);
    let _daemon = account.daemon(&daemon_env(&scanner.dir, Some(REOPEN_DELAY_MS)));
    let mut tui = Tui::start(&account, tmp.path().join("cues2"), "bob2", &[]);
    tui.started();
    tui.typed();
    let before = scanner.scan();
    tui.submit();
    let during = scanner.until_more("room", before.of("room"));
    assert!(
        !tui.cues.join("attached").exists(),
        "PRODUCT (staging): the TUI's node finished attaching, so the reopening was not in flight"
    );
    let hup = Instant::now();
    tui.hang_up();
    let gone = hup.elapsed();
    // Still held when the TUI had gone: the reopen was in flight when its last holder went.
    let held = scanner.scan();
    println!(
        "[proof] reopen: the TUI was gone {gone:?} after SIGHUP; the room passphrase then: {} \
         copies",
        held.of("room")
    );
    assert!(
        held.of("room") > 0,
        "PRODUCT (staging): the reopen had finished by the time the TUI went ({gone:?} after \
         SIGHUP), so nothing was in flight"
    );
    let took = wait_detached(&account, "bob2's TUI went on SIGHUP mid-attach");
    let after = scanner.scan();
    tui.stop();
    judge("reopen", "daemon", &before, &during, &after, took);
}

/// Wait until `vox node list` says bob is detached, within [`SHOWS_UP`] plus the held delay:
/// how long that took. `PRODUCT` if it never does — the TUI was his node's last holder (L-3).
fn wait_detached(account: &Account, after: &str) -> Duration {
    let t0 = Instant::now();
    let bound = SHOWS_UP + Duration::from_millis(REOPEN_DELAY_MS.parse().staged());
    while !account.bob_detached() {
        assert!(
            t0.elapsed() < bound,
            "PRODUCT: bob's node was still attached {bound:?} after {after}; the TUI was its last \
             holder (ADR-026 L-3)"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    t0.elapsed()
}

/// Read `child`'s stdout until a line matches `wanted`; the line.
fn line_from(child: &mut Proc, what: &str, wanted: impl Fn(&str) -> bool) -> String {
    use std::io::BufRead as _;
    let out = child.0.stdout.take().staged();
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
    panic!("PRODUCT (staging): {what} never printed what was waited for");
}

#[test]
#[ignore = "real vox daemons with the interposer loaded, a real join; macOS"]
fn a_detach_does_not_wait_out_a_joins_grind_and_leaves_no_passphrase() {
    watchdog::arm();
    let tmp = tempfile::tempdir().staged();
    let (anchor_dir, alice) = (tmp.path().join("anchor"), tmp.path().join("alice"));
    let (alice_id, identity, roompass) = (unique("alice-idp"), unique("idp"), unique("grind-rp"));
    std::fs::create_dir_all(anchor_dir.join("cfg")).staged();
    std::fs::create_dir_all(alice.join("cfg")).staged();
    let account = Account::new(tmp.path().join("acct"), &identity);
    // An anchor, and alice hosting a room through it, all the shipped binary.
    let mut anchor = start(
        &anchor_dir,
        "anchor",
        &["node", "--listen", "127.0.0.1:0"],
        None,
    );
    let spec = line_from(&mut anchor, "the anchor", |l| {
        l.contains("@/ip4/127.0.0.1/udp/")
    })
    .split_whitespace()
    .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
    .staged()
    .to_owned();
    let alice_pass = tmp.path().join("alice.pass");
    std::fs::write(&alice_pass, format!("{alice_id}\n")).staged();
    let (ok, said) = run(
        &alice,
        "alice",
        &[
            "node",
            "create",
            "alice",
            "--passphrase-file",
            alice_pass.to_str().staged(),
        ],
    );
    assert!(ok, "PRODUCT (staging): alice's node: {said}");
    let _alice_daemon = start(
        &alice,
        "alice",
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        Some(&format!("{alice_id}\n")),
    );
    let t0 = Instant::now();
    while !run(&alice, "alice", &["room", "list"]).0 {
        assert!(
            t0.elapsed() < Duration::from_secs(120),
            "PRODUCT (staging): alice's daemon never answered"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let mut create = start(
        &alice,
        "alice",
        &["room", "create", "--passphrase-file", "-", "--name", "team"],
        Some(&format!("{roompass}\n")),
    );
    assert!(
        create.0.wait().staged().success(),
        "PRODUCT (staging): alice could not create the room"
    );
    let (_, list) = run(&alice, "alice", &["room", "list"]);
    let prefix = list.split_whitespace().next().staged().to_owned();
    let (ok, link) = run(&alice, "alice", &["room", "link", &prefix]);
    assert!(ok, "PRODUCT (staging): room link: {link}");
    let link = link.lines().next().staged().trim().to_owned();

    // Bob's daemon, scanned, with his node's grind held long.
    let scanner = Scanner::new(
        tmp.path().join("scan"),
        "daemon",
        &[("room", &roompass), ("identity", &identity)],
    );
    let mut env = daemon_env(&scanner.dir, None);
    test_knobs::require(&["VOX_TEST_SOLVE_AT_LEAST_MS"]);
    env.push(("VOX_TEST_SOLVE_AT_LEAST_MS".to_owned(), GRIND_MS.to_owned()));
    env.push(("VOX_ANCHORS".to_owned(), spec.clone()));
    let _daemon = account.daemon(&env);
    let mut tui = Tui::start(&account, tmp.path().join("cues"), "bob", &[]);
    tui.attached();
    let before = scanner.scan();
    let mut join = start(
        &account.dir,
        "bob",
        &["room", "join", "--passphrase-file", "-", &link],
        Some(&format!("{roompass}\n")),
    );
    let during = scanner.until_more("room", before.of("room"));
    // Into the grind: past the dial and the challenge, well short of the held grind's end.
    std::thread::sleep(Duration::from_secs(5));
    still_running(&mut join, "vox room join");
    let asked = Instant::now();
    let detach = account.detach_bob();
    let answered = answered_meanwhile(&account);
    let took = detached(detach, asked);
    let after = scanner.scan();
    let joined = join.0.try_wait().staged();
    println!(
        "[proof] grind: a `vox node list` asked as the detach began answered in {answered:?}; the \
         detach was done {took:?} after it was asked (bound {SETTLES:?}, the held grind {GRIND_MS} \
         ms); vox room join after the detach: {joined:?}"
    );
    assert!(
        answered < ANSWERS,
        "PRODUCT: the daemon answered nobody while a detach settled: `vox node list` took \
         {answered:?} (bound {ANSWERS:?})"
    );
    assert!(
        took < SETTLES,
        "PRODUCT: the detach waited out the join's grind: it was done {took:?} after it was asked \
         (bound {SETTLES:?}) — the grind held the join's secrets where no abort reached them"
    );
    tui.stop();
    judge("grind", "daemon", &before, &during, &after, took);
}

#[test]
#[ignore = "real vox tui in a pty with the interposer loaded; macOS"]
fn an_attached_tui_holds_no_piece_of_the_identity_passphrase() {
    // Nothing in flight: the identity passphrase typed at the attach prompt is the only secret the
    // TUI ever held, and once its node is attached the TUI holds no piece of it (V210-94, ADR-026
    // C-6): the daemon holds the node, not the client.
    watchdog::arm();
    let tmp = tempfile::tempdir().staged();
    let identity = unique("attach-idp");
    let account = Account::new(tmp.path().join("acct"), &identity);
    let _daemon = account.daemon(&[]);
    let scanner = Scanner::new(tmp.path().join("scan"), "TUI", &[("identity", &identity)]);
    let mut tui = Tui::start(
        &account,
        tmp.path().join("cues"),
        "bob",
        &[
            format!("VOX_PTY_DYLD_INSERT={}", syscalls::interposer().display()),
            format!("VOX_INTERPOSE_SCAN={}", scanner.dir.display()),
        ],
    );
    tui.started();
    let before = scanner.scan();
    // Typed and not yet submitted, the passphrase is in the prompt's field: the scan must see it
    // there, or it could not see it anywhere.
    tui.typed();
    let during = scanner.until_more("identity", before.of("identity"));
    let asked = Instant::now();
    tui.attached();
    let took = asked.elapsed();
    let after = scanner.scan();
    tui.stop();
    judge("attach", "TUI", &before, &during, &after, took);
}

/// Which side a TUI driver that stopped early is on, from what it said. The driver prints
/// `<tag> RED: PRODUCT…` or `HUNG at <stage>` when `vox tui` failed or stopped answering: the
/// product's, at staging. `<tag> APPARATUS` (pyte missing, a cue it could not read), a driver
/// thread that panicked, or one that said nothing it should have: the apparatus's.
fn driver_side(said: &str) -> &'static str {
    if said.contains("RED: PRODUCT") || said.contains("HUNG at") {
        "PRODUCT (staging)"
    } else {
        "APPARATUS"
    }
}
