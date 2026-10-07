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
//! 5. **And not through the anchor** (ADR-023 decision 6, proof 6; PRD-001 R34, R11): A, B and C
//!    all run with `--anchor` at a `vox node` that is a member of nothing. Its board serves the
//!    room (it says so), and after the whole exchange its data directory has **no store file**,
//!    the one place a node keeps anything for a room: no log, no key-package, nothing at rest.
//!    B read A's keys with A down and only C up, so they reached it through C, the always-on
//!    member. (The anchor may relay a circuit between members, the in-flight datagrams decision 6
//!    leaves it; the most it carried is printed.)
//!
//! Everything is read from what the binaries say and what is on disk; nothing is opened in this
//! process.
//!
//! The second test removes C before A comes back: B reads none of A's messages — nothing was
//! online with both. That is "keys wait for overlap"
//! (ADR-023 decision 4's accepted consequence), read from B's timeline and log; the `vox status`
//! line is added when status reaches this branch.
//!
//! The third test is #226's (V030-01): **a key through the log releases what a direct one does.**
//! What a member may read depends on when it was trusted (V210-45), never on the path its key
//! took. A trusts B and D *before* posting six messages across a rotation, and neither has joined
//! yet; both join while A is down. When A comes back, D is up and reached directly, and B is down
//! and reached only through the log. B, reading through C alone, must read the same six D reads;
//! and neither reads the message A posted before trusting them (never wider).
//!
//! Mutations: the anchor keeping its old ciphertext copy of the room (as before ADR-023 decision
//! 6) → the anchor's data directory holds a store file. No key-package posted → B reads 0. The log path releasing forward-only from the key
//! held when the consent fell due (what it did before #226) → B reads 0 of the six, D all six.
//! R14 deleting every superseded generation whatever V210-45 still owes (as the merge had it) →
//! D and B each read 3 of the six: generation one's key was gone before either joined.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/layout.rs"]
mod layout;
#[path = "support/typed.rs"]
mod typed;

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";

thread_local! {
    /// The `--anchor` every daemon this test's thread starts names, if it set one. Per thread,
    /// since the tests of this file run side by side and only the first uses an anchor.
    static ANCHOR: RefCell<Option<String>> = const { RefCell::new(None) };
}

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
        let mut cmd = Command::new(VOX);
        cmd.args(["daemon", "--listen", "127.0.0.1:0", "--passphrase-file"])
            .arg(&pass);
        if let Some(spec) = ANCHOR.with(|a| a.borrow().clone()) {
            cmd.args(["--anchor", &spec]);
        }
        let mut child = cmd
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env_remove("VOX_ROOM")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn {name}: {e}"));
        let out = collect(child.stdout.take().expect("APPARATUS: a piped stdout"));
        let err = collect(child.stderr.take().expect("APPARATUS: a piped stderr"));
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
            "CANNOT MEASURE (staging): {} never printed {what}\nstderr:\n{}",
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
            "CANNOT MEASURE (staging): {} never said {what} (a {}th time)\nstderr:\n{}",
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
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM");
    // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028 K-13).
    if typed::is_keyring_change(args) {
        return typed::keyring(&cmd);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: spawn vox");
    let mut pipe = child.stdin.take().expect("APPARATUS: a piped stdin");
    pipe.write_all(stdin.as_bytes())
        .expect("APPARATUS: write stdin");
    drop(pipe);
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
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
    assert!(
        ok,
        "CANNOT MEASURE (staging): `vox {}` failed: {said}",
        args.join(" ")
    );
    said
}

/// How many of `texts` `dir`'s node can read in `room`.
fn readable(dir: &std::path::Path, room: &str, texts: &[String]) -> usize {
    let (_, said) = vox(dir, &["room", "read", room], "");
    texts.iter().filter(|t| said.contains(t.as_str())).count()
}

/// A `vox node` anchor, killed by its own PID however the test ends, with its stdout collected.
struct Anchor {
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
    spec: String,
}

impl Anchor {
    fn start(dir: &std::path::Path) -> Self {
        let mut child = Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn the anchor: {e}"));
        let out = collect(child.stdout.take().expect("APPARATUS: the anchor's stdout"));
        // Held from here, so its `Drop` kills and reaps the anchor on every path out.
        let mut anchor = Self {
            child,
            out,
            spec: String::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let spec = anchor.out.lock().unwrap().iter().find_map(|l| {
                let l = l.trim();
                (l.contains('@') && l.starts_with(|c: char| c.is_alphanumeric()))
                    .then(|| l.to_owned())
            });
            if let Some(spec) = spec {
                anchor.spec = spec;
                return anchor;
            }
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE (staging): the anchor never printed its --anchor spec"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn out(&self) -> String {
        self.out.lock().unwrap().join("\n")
    }
}

impl Drop for Anchor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Cast {
    _tmp: tempfile::TempDir,
    a: std::path::PathBuf,
    b: std::path::PathBuf,
    c: std::path::PathBuf,
    d: std::path::PathBuf,
    e: std::path::PathBuf,
    fps: [String; 5],
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
    let (a, b, c, d, e) = (mk("a"), mk("b"), mk("c"), mk("d"), mk("e"));
    let fp = |d: &std::path::Path| ok(d, &["id"], "").trim().lines().next().unwrap().to_owned();
    let fps = [fp(&a), fp(&b), fp(&c), fp(&d), fp(&e)];
    Cast {
        _tmp: tmp,
        a,
        b,
        c,
        d,
        e,
        fps,
        room: String::new(),
        link: String::new(),
    }
}

/// C makes the room and stays up; A joins, trusts C, posts `before`, trusts B and D, and D joins
/// and leaves; A goes down;
/// B joins through C, trusts A, and goes down.
fn set_up(k: &mut Cast, before: &str) -> Daemon {
    let c = Daemon::start("c", &k.c);
    ok(
        &k.c,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    let listed = ok(&k.c, &["room", "list"], "");
    k.room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .expect("CANNOT MEASURE (staging): a room id")
        .to_owned();
    k.link = ok(&k.c, &["room", "link", &k.room], "")
        .lines()
        .find(|l| l.starts_with("vox://"))
        .expect("CANNOT MEASURE (staging): an address")
        .trim()
        .to_owned();

    let a = Daemon::start("a", &k.a);
    ok(
        &k.a,
        &["room", "join", "--passphrase-file", "-", &k.link],
        &format!("{ROOMPASS}\n"),
    );
    // C first, and consent to it confirmed before anything is posted: C must be able to read
    // what it carries here, which is how this setup knows C has it.
    ok(&k.a, &["trust", "add", &k.fps[2], "--name", "c"], "");
    // Trust runs one way (V210-161): C reads A only once it trusts A too.
    ok(&k.c, &["trust", "add", &k.fps[0], "--name", "a"], "");
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
        &["room", "join", "--passphrase-file", "-", &k.link],
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
        &["room", "join", "--passphrase-file", "-", &k.link],
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
    // A `vox node` that is a member of nothing: every daemon names it as its anchor.
    let anchor_dir = k._tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).unwrap();
    let anchor = Anchor::start(&anchor_dir);
    ANCHOR.with(|a| *a.borrow_mut() = Some(anchor.spec.clone()));
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
    // The anchor served the room: its board said so. Without that, zero pages would say nothing.
    let room_short: String = k.room.chars().take(12).collect();
    let anchor_out = anchor.out();
    let served = anchor_out
        .lines()
        .any(|l| l.contains("vox node: board — ") && l.contains(&room_short));
    drop(anchor);
    assert!(
        served,
        "CANNOT MEASURE (staging): the anchor never said its board serves room {room_short}, so \
         what it stores proves nothing\nanchor:\n{anchor_out}"
    );
    // **Nothing at rest** (R34, ADR-023 proof 6): what a person sees in the anchor's data
    // directory. An anchor that kept a copy of the room kept it in a store file, the one place a
    // node keeps anything for a room; this build's anchor keeps none.
    // Anywhere under its data root, not only where this build keeps a node's store.
    let stores = layout::find_named(&anchor_dir, "store.redb");
    // **Relayed, not kept** (R11): the anchor says how many circuits it carries. A circuit is the
    // relay's in-flight datagrams, which decision 6 leaves an anchor; it is printed, not asserted.
    // What R11 and R34 take from an anchor is the room kept at rest, which the store file is.
    let carried: u64 = anchor_out
        .lines()
        .filter_map(|l| {
            l.split(" circuit(s) carried")
                .next()?
                .rsplit(' ')
                .next()?
                .parse()
                .ok()
        })
        .max()
        .unwrap_or(0);
    eprintln!(
        "[R11] B read {got} of {} of A's messages, across a rotation, with A down and only C up; \
         the one sealed before the grant: {early} of 1",
        sent.len()
    );
    eprintln!(
        "[R11/R34] the anchor, a member of nothing: store files under its data root: \
         {stores:?}; the most circuits it said it carried (relay, in flight): {carried}"
    );
    assert!(
        stores.is_empty(),
        "PRODUCT: an anchor that is not a member of a room must store nothing for it (ADR-023 \
         decision 6, PRD-001 R34): its data directory holds a store file, {stores:?}"
    );
    assert_eq!(
        got,
        sent.len(),
        "PRODUCT: B must read every message A posted after granting it, with A down and only C, \
         the always-on member, up (PRD-001 R11)\nB stderr:\n{b_said}"
    );
    assert_eq!(
        early, 0,
        "PRODUCT: forward-only: a message sealed before the grant must stay unreadable to B"
    );
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
    eprintln!("[R11, no carrier] B's timeline:\n{timeline}");
    eprintln!("[R11, no carrier] B's log: {why}");
    eprintln!(
        "[R11, no carrier] B read {got} of {} of A's messages — keys wait for overlap",
        sent.len()
    );
    assert_eq!(
        got, 0,
        "PRODUCT: with no member online with both, B can read nothing of A's"
    );
}

/// Wait until `dir`'s node reads every one of `texts` in `room`; how many it read.
fn read_all(dir: &std::path::Path, room: &str, texts: &[String], secs: u64) -> usize {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let got = readable(dir, room, texts);
        if got == texts.len() || Instant::now() >= deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
#[ignore = "five real daemons restarted in turn, production Argon2id; CI runs it in release"]
fn a_key_through_the_log_releases_what_a_direct_one_does() {
    watchdog::arm();
    let mut k = cast();
    let (b_fp, d_fp, e_fp) = (k.fps[1].clone(), k.fps[3].clone(), k.fps[4].clone());

    // ---- C makes the room and stays up; A joins and C reads it ----
    let c = Daemon::start("c", &k.c);
    ok(
        &k.c,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    k.room = ok(&k.c, &["room", "list"], "")
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .expect("CANNOT MEASURE (staging): a room id")
        .to_owned();
    k.link = ok(&k.c, &["room", "link", &k.room], "")
        .lines()
        .find(|l| l.starts_with("vox://"))
        .expect("CANNOT MEASURE (staging): an address")
        .trim()
        .to_owned();
    let join = |dir: &std::path::Path| {
        ok(
            dir,
            &["room", "join", "--passphrase-file", "-", &k.link],
            &format!("{ROOMPASS}\n"),
        );
    };
    let a = Daemon::start("a", &k.a);
    join(&k.a);
    ok(&k.a, &["trust", "add", &k.fps[2], "--name", "c"], "");
    // Trust runs one way (V210-161): C reads A only once it trusts A too.
    ok(&k.c, &["trust", "add", &k.fps[0], "--name", "a"], "");
    let warmed = |dir: &std::path::Path, tag: &str| {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            ok(&k.a, &["room", "post", &k.room, tag], "");
            std::thread::sleep(Duration::from_secs(2));
            if ok(dir, &["room", "read", &k.room], "").contains(tag) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE: {tag} never read"
            );
        }
    };
    warmed(&k.c, "v226-warm-c");

    // ---- E joins and is consented to directly, so that removing it later rotates A's key ----
    let e = Daemon::start("e", &k.e);
    join(&k.e);
    ok(&k.e, &["trust", "add", &k.fps[0], "--name", "a"], "");
    ok(&k.a, &["trust", "add", &e_fp, "--name", "e"], "");
    warmed(&k.e, "v226-warm-e");
    e.stop();

    // ---- one post before B and D are trusted, then the trust, then six posts across a rotation ----
    let before = "v226-before-the-trust".to_owned();
    ok(&k.a, &["room", "post", &k.room, &before], "");
    ok(&k.a, &["trust", "add", &b_fp, "--name", "b"], "");
    ok(&k.a, &["trust", "add", &d_fp, "--name", "d"], "");
    let mut sent = Vec::new();
    for i in 0..3 {
        let t = format!("v226-generation-one-{i}");
        ok(&k.a, &["room", "post", &k.room, &t], "");
        sent.push(t);
    }
    ok(&k.a, &["trust", "remove", &e_fp], "");
    for i in 0..3 {
        let t = format!("v226-generation-two-{i}");
        ok(&k.a, &["room", "post", &k.room, &t], "");
        sent.push(t);
    }
    // C holds everything before A goes: it reads A's last entry.
    let got = read_all(&k.c, &k.room, &sent, 90);
    assert_eq!(
        got,
        sent.len(),
        "CANNOT MEASURE: C never held A's six posts"
    );
    a.stop();

    // ---- B and D join while A is down; B goes down again, D stays ----
    let b = Daemon::start("b", &k.b);
    join(&k.b);
    ok(&k.b, &["trust", "add", &k.fps[0], "--name", "a"], "");
    b.stop();
    let d = Daemon::start("d", &k.d);
    join(&k.d);
    ok(&k.d, &["trust", "add", &k.fps[0], "--name", "a"], "");

    // ---- A comes back: D is reached directly, B only through the log ----
    let a = Daemon::start("a", &k.a);
    let b_short: String = b_fp.chars().take(12).collect();
    a.wait_err_count("that B cannot be reached", 0, 120, |l| {
        l.contains("could not reach") && l.contains(&b_short)
    });
    let d_got = read_all(&k.d, &k.room, &sent, 120);
    let d_early = readable(&k.d, &k.room, std::slice::from_ref(&before));
    // A's entries reach C in order: C reading a post made after the packages means C holds them.
    ok(&k.a, &["room", "post", &k.room, "v226-sentinel"], "");
    let deadline = Instant::now() + Duration::from_secs(90);
    while !ok(&k.c, &["room", "read", &k.room], "").contains("v226-sentinel") {
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: C never received A's sentinel\nA stderr:\n{}",
            a.stderr()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    a.stop();
    d.stop();

    // ---- B comes back with only C up ----
    let b = Daemon::start("b", &k.b);
    let b_got = read_all(&k.b, &k.room, &sent, 120);
    let b_early = readable(&k.b, &k.room, std::slice::from_ref(&before));
    let b_said = b.stderr();
    b.stop();
    c.stop();
    eprintln!(
        "[V030-01] trusted before six posts across a rotation: D (reached directly) read {d_got} of \
         {n}, B (through the log only) read {b_got} of {n}; the post before the trust: D {d_early}, \
         B {b_early} of 1",
        n = sent.len()
    );
    assert_eq!(
        d_got,
        sent.len(),
        "PRODUCT: a member trusted before it joined, reached directly, must read every post made since its \
         trust (V210-45) — across the rotation too: no generation it is owed may be deleted first \
         (R14 deletes only what is no longer needed)"
    );
    assert_eq!(
        b_got, d_got,
        "PRODUCT: a member reached only through the log must read what a directly reached one reads\n\
         B stderr:\n{b_said}"
    );
    assert_eq!(
        (d_early, b_early),
        (0, 0),
        "PRODUCT: never wider: a post made before the trust stays unreadable, whichever path the key took"
    );
}
