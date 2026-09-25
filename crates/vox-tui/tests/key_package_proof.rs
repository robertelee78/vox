//! ADR-023 decision 4 / M23.3, PRD-001 R11 — **keys reach an offline member through an
//! always-on member**, driven through the shipped binary.
//!
//! Before this, a sender key travelled only on a direct pairwise stream, so two members who
//! were never online at the same time converged on each other's ciphertext and could never
//! read it. Now a key the direct path cannot deliver is sealed to its recipient and posted to
//! the room's log as a `key-package`, which every member replicates.
//!
//! Three real `vox daemon`s: **C** is always on and made the room; **A** and **B** are never
//! up at the same time.
//!
//! 1. A joins and posts one message **before** it has granted B anything, trusts B and C, and
//!    goes down.
//! 2. B joins (through C), trusts A, and goes down.
//! 3. A comes back. It learns from C that B joined, owes B a key, cannot reach B, and posts a
//!    key-package for B. A posts three messages; then A stops trusting C, which rotates A's
//!    sender key and owes B the new generation — again a key-package; then three more. A goes
//!    down.
//! 4. B comes back, syncs with C only, and must read all **six** — across the rotation — and
//!    **not** the message from step 1 (forward-only, R12: a grant opens what is sealed after
//!    it, never before).
//! 5. With every daemon stopped, the stores are read at rest: C carries the key-packages for B
//!    and **cannot open one**; B's own ring opens every one.
//!
//! The second test removes C before A comes back: B reads none of A's messages, and B's log
//! holds no key-package for B — nothing was online with both. That is "keys wait for overlap"
//! (ADR-023 decision 4's accepted consequence), read from B's timeline and log; the `vox status`
//! line is added when status reaches this branch.
//!
//! Mutation: no key-package posted → B reads 0.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";

/// A daemon, killed by its own PID however the test ends, with stdout and stderr collected.
struct Daemon {
    name: &'static str,
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
    err: Arc<Mutex<Vec<String>>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn collect(stream: impl Read + Send + 'static) -> Arc<Mutex<Vec<String>>> {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            sink.lock().unwrap().push(line);
        }
    });
    lines
}

impl Daemon {
    /// Start a daemon for `dir`, unlocking the identity and opening every room the room
    /// passphrase opens.
    fn start(name: &'static str, dir: &std::path::Path) -> Self {
        let pass = dir.join("pass");
        std::fs::write(&pass, format!("{IDPASS}\n{ROOMPASS}\n")).unwrap();
        let mut child = Command::new(VOX)
            .args(["daemon", "--listen", "127.0.0.1:0", "--passphrase-file"])
            .arg(&pass)
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env_remove("VOX_ROOM")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
        let out = collect(child.stdout.take().expect("stdout"));
        let err = collect(child.stderr.take().expect("stderr"));
        let d = Self {
            name,
            child,
            out,
            err,
        };
        d.wait_out("its control socket", |l| l.contains("control socket"));
        d
    }

    fn stderr(&self) -> String {
        self.err.lock().unwrap().join("\n")
    }

    fn wait_out(&self, what: &str, pred: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if self.out.lock().unwrap().iter().any(|l| pred(l)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "{}: never printed {what}\nstderr:\n{}",
            self.name,
            self.stderr()
        );
    }

    /// Wait until stderr has more than `already` lines matching `pred`; returns the count.
    fn wait_err_count(
        &self,
        what: &str,
        already: usize,
        secs: u64,
        pred: impl Fn(&str) -> bool,
    ) -> usize {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            let n = self.err.lock().unwrap().iter().filter(|l| pred(l)).count();
            if n > already {
                return n;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "{}: never said {what} (a {}th time)\nstderr:\n{}",
            self.name,
            already + 1,
            self.stderr()
        );
    }

    /// Stop it and wait until the process is gone, so the profile's store is released.
    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn vox(dir: &std::path::Path, args: &[&str], stdin: &str) -> (bool, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(stdin.as_bytes()).expect("write");
    drop(pipe);
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn ok(dir: &std::path::Path, args: &[&str], stdin: &str) -> String {
    let (ok, said) = vox(dir, args, stdin);
    assert!(ok, "`vox {}` failed: {said}", args.join(" "));
    said
}

/// How many of `texts` `dir`'s node can read in `room`.
fn readable(dir: &std::path::Path, room: &str, texts: &[String]) -> usize {
    let (_, said) = vox(dir, &["room", "read", room], "");
    texts.iter().filter(|t| said.contains(t.as_str())).count()
}

/// The key-packages `dir`'s store holds in its (only) room, read at rest with the daemon
/// stopped: `(for_recipient, opened_by_this_identity)` counting packages addressed to
/// `recipient`.
fn packages_at_rest(dir: &std::path::Path, recipient: &vox_core::hash::Digest32) -> (usize, usize) {
    use vox_core::node::channel::ChannelState;
    let paths = vox_core::node::paths::Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
        .unwrap();
    let mut profile = vox_core::node::profile::Profile::open(paths).unwrap();
    profile.unlock(IDPASS.as_bytes()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let channels = profile.store().channels().unwrap();
    assert_eq!(channels.len(), 1, "one room in {}", dir.display());
    let channel = ChannelState::open(&profile, &channels[0], ROOMPASS.as_bytes(), now).unwrap();
    let ctx = channel.join_context().unwrap();
    let signer = profile.signer().unwrap();
    let dh = *signer.x25519_identity_secret();
    let (mut ring, _) =
        vox_core::node::prekeys::load_or_create(profile.store(), signer, &dh, now).unwrap();
    let mut held = 0;
    let mut opened = 0;
    for (_, pkg) in channel.key_packages() {
        if pkg.recipient != *recipient {
            continue;
        }
        held += 1;
        match pkg.open_with_ring(&mut ring, &ctx, now) {
            Ok(_) => opened += 1,
            Err(e) => eprintln!("[at rest {}] cannot open a package: {e}", dir.display()),
        }
    }
    (held, opened)
}

struct Cast {
    _tmp: tempfile::TempDir,
    a: std::path::PathBuf,
    b: std::path::PathBuf,
    c: std::path::PathBuf,
    d: std::path::PathBuf,
    fps: [String; 4],
    room: String,
    link: String,
}

fn cast() -> Cast {
    let tmp = tempfile::tempdir().unwrap();
    let mk = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (a, b, c, d) = (mk("a"), mk("b"), mk("c"), mk("d"));
    let fp = |d: &std::path::Path| ok(d, &["id"], "").trim().lines().next().unwrap().to_owned();
    let fps = [fp(&a), fp(&b), fp(&c), fp(&d)];
    Cast {
        _tmp: tmp,
        a,
        b,
        c,
        d,
        fps,
        room: String::new(),
        link: String::new(),
    }
}

fn b32(fp: &str) -> vox_core::hash::Digest32 {
    vox_core::node::link::b32_decode(fp, "fingerprint").unwrap()
}

/// C makes the room and stays up; A joins, trusts C, posts `before`, trusts B and D, and D joins
/// and leaves; A goes down;
/// B joins through C, trusts A, and goes down.
fn set_up(k: &mut Cast, before: &str) -> Daemon {
    let c = Daemon::start("c", &k.c);
    ok(
        &k.c,
        &["room", "create", "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    let listed = ok(&k.c, &["room", "list"], "");
    k.room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .expect("a room id")
        .to_owned();
    k.link = ok(&k.c, &["room", "invite", &k.room], "")
        .lines()
        .find(|l| l.starts_with("vox://"))
        .expect("an address")
        .trim()
        .to_owned();

    let a = Daemon::start("a", &k.a);
    ok(
        &k.a,
        &["room", "join", &k.link, "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    // C first, and consent to it confirmed before anything is posted: C must be able to read
    // what it carries here, which is how this setup knows C has it.
    ok(&k.a, &["trust", "add", &k.fps[2], "--name", "c"], "");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        ok(&k.a, &["room", "post", &k.room, "r11-warm-up"], "");
        std::thread::sleep(Duration::from_secs(2));
        if ok(&k.c, &["room", "read", &k.room], "").contains("r11-warm-up") {
            break;
        }
        assert!(Instant::now() < deadline, "CANNOT MEASURE: C never read A");
    }
    ok(&k.a, &["room", "post", &k.room, before], "");
    ok(&k.a, &["trust", "add", &k.fps[1], "--name", "b"], "");
    // D is only here to be removed later: A stops trusting D, which rotates A's sender key
    // while C — the carrier — keeps reading, so C's timeline shows when it has everything.
    ok(&k.a, &["trust", "add", &k.fps[3], "--name", "d"], "");
    let d = Daemon::start("d", &k.d);
    ok(
        &k.d,
        &["room", "join", &k.link, "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    d.stop();
    // C holds A's first entry before A goes: C reads it once A's consent has reached it.
    let deadline = Instant::now() + Duration::from_secs(90);
    while !ok(&k.c, &["room", "read", &k.room], "").contains(before) {
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: C never received A's message"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    a.stop();

    let b = Daemon::start("b", &k.b);
    ok(
        &k.b,
        &["room", "join", &k.link, "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    ok(&k.b, &["trust", "add", &k.fps[0], "--name", "a"], "");
    b.stop();
    c
}

#[test]
#[ignore = "three real daemons restarted in turn, production Argon2id; CI runs it in release"]
fn keys_reach_an_offline_member_through_an_always_on_member() {
    watchdog::arm();
    let mut k = cast();
    let before = "r11-before-the-grant".to_owned();
    let c = set_up(&mut k, &before);
    let b_short: String = k.fps[1].chars().take(12).collect();

    // ---- A comes back; B is down. The key for B goes into the log ----
    let a = Daemon::start("a", &k.a);
    let unreachable_b = |l: &str| l.contains("could not reach") && l.contains(&b_short);
    let n = a.wait_err_count("that B cannot be reached", 0, 120, unreachable_b);
    std::thread::sleep(Duration::from_secs(2));
    let mut sent = Vec::new();
    for i in 0..3 {
        let t = format!("r11-generation-one-{i}");
        ok(&k.a, &["room", "post", &k.room, &t], "");
        sent.push(t);
    }
    // Stop trusting D: A's sender key rotates, and B is owed the new generation.
    ok(&k.a, &["trust", "remove", &k.fps[3]], "");
    a.wait_err_count(
        "that B cannot be reached, after the rotation",
        n,
        120,
        unreachable_b,
    );
    std::thread::sleep(Duration::from_secs(2));
    for i in 0..3 {
        let t = format!("r11-generation-two-{i}");
        ok(&k.a, &["room", "post", &k.room, &t], "");
        sent.push(t);
    }
    // A goes down only once C — still trusted, still reading — has everything: A's entries
    // reach C in order, so C reading the last one means C holds every one before it.
    ok(&k.a, &["room", "post", &k.room, "r11-sentinel"], "");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let c_read = ok(&k.c, &["room", "read", &k.room], "");
        if c_read.contains("r11-sentinel") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: C never received A's last entry\nC read:\n{c_read}\nA stderr:\n{}\n\
             C stderr:\n{}",
            a.stderr(),
            c.stderr()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    a.stop();

    // ---- B comes back; A is down. Only C is there ----
    let b = Daemon::start("b", &k.b);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut got = 0;
    while Instant::now() < deadline {
        got = readable(&k.b, &k.room, &sent);
        if got == sent.len() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let early = readable(&k.b, &k.room, std::slice::from_ref(&before));
    let b_said = b.stderr();
    b.stop();
    c.stop();

    // ---- at rest: who holds the packages for B, and who can open them ----
    let for_b = b32(&k.fps[1]);
    let (a_held, _) = packages_at_rest(&k.a, &for_b);
    let (c_held, c_opened) = packages_at_rest(&k.c, &for_b);
    let (b_held, b_opened) = packages_at_rest(&k.b, &for_b);
    eprintln!(
        "[R11] B read {got} of {} of A's messages, across a rotation; the one sealed before the \
         grant: {early} of 1",
        sent.len()
    );
    eprintln!(
        "[R11] key-packages for B: A posted {a_held}; C holds {c_held}, opens {c_opened}; B holds \
         {b_held}, opens {b_opened}"
    );
    assert_eq!(
        got,
        sent.len(),
        "B must read every message A posted after granting it, through C alone\nB stderr:\n{b_said}"
    );
    assert_eq!(
        early, 0,
        "forward-only: a message sealed before the grant must stay unreadable to B"
    );
    assert!(
        c_held >= 2,
        "C must carry B's packages (consent + rotation): {c_held}"
    );
    assert_eq!(
        c_opened, 0,
        "a member carrying a package for someone else cannot open it"
    );
    assert_eq!(b_opened, b_held, "B's own ring opens every package for B");
}

#[test]
#[ignore = "three real daemons restarted in turn, production Argon2id; CI runs it in release"]
fn without_an_always_on_member_keys_wait_for_overlap() {
    watchdog::arm();
    let mut k = cast();
    let c = set_up(&mut k, "r11-no-carrier-before");
    // C is removed: nobody is online with both A and B from here on.
    c.stop();

    let a = Daemon::start("a", &k.a);
    let mut sent = Vec::new();
    for i in 0..3 {
        let t = format!("r11-no-carrier-{i}");
        ok(&k.a, &["room", "post", &k.room, &t], "");
        sent.push(t);
    }
    std::thread::sleep(Duration::from_secs(5));
    a.stop();

    // B's own log says why: the one member who could hand it A's key is not there.
    let b = Daemon::start("b", &k.b);
    let a_short: String = k.fps[0].chars().take(12).collect();
    let unreachable_a = |l: &str| l.contains("could not reach") && l.contains(&a_short);
    b.wait_err_count("that A cannot be reached", 0, 120, unreachable_a);
    std::thread::sleep(Duration::from_secs(10));
    let got = readable(&k.b, &k.room, &sent);
    let timeline = ok(&k.b, &["room", "read", &k.room], "");
    let why = b
        .stderr()
        .lines()
        .find(|l| unreachable_a(l))
        .unwrap_or_default()
        .to_owned();
    b.stop();
    let (b_held, _) = packages_at_rest(&k.b, &b32(&k.fps[1]));
    eprintln!("[R11, no carrier] B's timeline:\n{timeline}");
    eprintln!("[R11, no carrier] B's log: {why}");
    eprintln!(
        "[R11, no carrier] B read {got} of {} of A's messages and holds {b_held} key-packages \
         for itself — keys wait for overlap",
        sent.len()
    );
    assert_eq!(
        got, 0,
        "with no member online with both, B can read nothing of A's"
    );
    assert_eq!(b_held, 0, "and nothing carried a key to B");
}
