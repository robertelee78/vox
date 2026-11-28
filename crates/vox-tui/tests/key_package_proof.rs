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
//!
//! ADR-053 MP-10 boundary 3 (**addressed-package open and install**), removed-author arm: a
//! removed author's package installs nothing on a member that knows the removal
//! (`a_removed_authors_package_opens_nothing`). The runner's `VOX_PROOF_MP10_KEYS=package-open`
//! hands the boundary-off mutant to the recipient only; it turns PRODUCT red on the recipient's
//! `vox status --json` received-key count.

// The optional relay act reuses room/world's attachment and typed-command modules.
#![cfg_attr(feature = "optional-proofs", allow(clippy::duplicate_mod))]
#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

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
        Self::start_env(name, dir, &[])
    }

    fn start_env(
        name: &'static str,
        dir: &std::path::Path,
        env: &[(&str, &std::ffi::OsStr)],
    ) -> Self {
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
            .envs(env.iter().copied())
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

/// Twelve observed ten-second reach bounds leave room for sealing and carrying.
///
/// "Carried" is: A's log route to B has posted every key B is owed now (A's daemon says so, the
/// `test-knobs` line `every key owed to <B> is in the log of room <r>`, said again after the
/// moment this is called), and C holds A's feed through what A has appended, those packages
/// included. A's own status keeps B's `key_delivery_pending` true: a package settles nothing
/// (V210-45, #1422), only B's answer over a direct connection does, and A and B are never up
/// together here.
fn wait_for_log_delivery(k: &Cast, a: &Daemon, c: &Daemon, verdict: &str) {
    test_knobs::require(&["is in the log of room"]);
    let room_short: String = k.room.chars().take(12).collect();
    let in_log = format!(
        "every key owed to {} is in the log of room {room_short}",
        k.fps[1]
    );
    let said = || a.stderr().lines().filter(|l| l.contains(&in_log)).count();
    let said_before = said();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        // Read before A's status: what A appended before saying it is inside `through` below.
        let posted = said() > said_before;
        // Repeating this operation posts once. Its fresh reach report says whether A's
        // room log currently grants B consent, rather than merely naming B in its ring.
        let (probe_ok, probe) = vox(
            &k.a,
            &[
                "room",
                "post",
                &k.room,
                "r11-renewal-receipt",
                "--to",
                &k.fps[1],
                "--session",
                "r11-renewal",
                "--op",
                "r11-renewal",
                "--json",
            ],
            "",
        );
        let (a_ok, a_status) = vox(&k.a, &["status", "--json"], "");
        let (c_ok, c_status) = vox(&k.c, &["status", "--json"], "");
        let ready = (|| {
            let probe: serde_json::Value = probe
                .lines()
                .find_map(|line| serde_json::from_str(line).ok())?;
            let a_status: serde_json::Value = serde_json::from_str(&a_status).ok()?;
            let c_status: serde_json::Value = serde_json::from_str(&c_status).ok()?;
            let room = |status: &serde_json::Value| {
                status["rooms"]
                    .as_array()?
                    .iter()
                    .find(|room| {
                        room["id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with(&k.room))
                    })
                    .cloned()
            };
            let a_room = room(&a_status)?;
            let c_room = room(&c_status)?;
            let a_at_c = c_room["members"]
                .as_array()?
                .iter()
                .find(|member| member["id"].as_str() == Some(k.fps[0].as_str()))?;
            let renewed = probe["reach"].as_array()?.first()?["you_trust"].as_bool()?;
            let through = a_room["own_feed_through"].as_u64()?;
            // C's authenticated position in A's feed: `verified_through` since 1edf35498, which
            // gave `holds_through` the latest message C can show.
            Some(renewed && posted && a_at_c["verified_through"].as_u64()? >= through)
        })() == Some(true);
        if probe_ok && a_ok && c_ok && ready {
            eprintln!("[keys-by-log] B's grant and all owed keys carried before A stops:\npost: {probe}\nA status: {a_status}\nC status: {c_status}");
            // What A's operator reads about B now: its keys went through the room, and B has
            // not confirmed them (printed, not asserted).
            eprintln!(
                "[keys-by-log] A's `vox status`:\n{}",
                vox(&k.a, &["status"], "").1
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{verdict}: A did not complete delivery to B through the log within 120 s\n\
             post (success={probe_ok}): {probe}\nA status (success={a_ok}): {a_status}\n\
             C status (success={c_ok}): {c_status}\nA stderr:\n{}\nC stderr:\n{}",
            a.stderr(),
            c.stderr()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
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
    // C reading the sentinel proves it holds the posts, not the asynchronously renewed
    // grant/package for offline B. Wait for that grant and C's role-complete receipt too.
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
    wait_for_log_delivery(&k, &a, &c, "APPARATUS");
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
    let (b_read_ok, b_read) = vox(&k.b, &["room", "read", &k.room], "");
    let (history_ok, history) = vox(&k.b, &["room", "read", &k.room, "--history", "status"], "");
    eprintln!("[R11] B room read (success={b_read_ok}):\n{b_read}");
    eprintln!("[R11] B history status (success={history_ok}):\n{history}");
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
         the always-on member, up (PRD-001 R11)\nB room read (success={b_read_ok}):\n{b_read}\n\
         B history status (success={history_ok}):\n{history}\nB stderr:\n{b_said}"
    );
    assert_eq!(
        early, 0,
        "PRODUCT: forward-only: a message sealed before the grant must stay unreadable to B"
    );
}

/// `dir`'s `vox status --json` row for `room`, or `None` when status did not answer with it.
fn room_status(dir: &std::path::Path, room: &str) -> Option<serde_json::Value> {
    let (answered, said) = vox(dir, &["status", "--json"], "");
    if !answered {
        return None;
    }
    let status: serde_json::Value = serde_json::from_str(&said).ok()?;
    status["rooms"]
        .as_array()?
        .iter()
        .find(|r| r["id"].as_str().is_some_and(|id| id.starts_with(room)))
        .cloned()
}

/// The mutant the proof runner chose for MP-10's key boundaries (`VOX_PROOF_MP10_KEYS`), as the
/// environment of the one daemon it is aimed at. The runner's own variable never reaches a
/// daemon, so every other daemon runs as shipped.
fn mp10_keys_mutant() -> Vec<(&'static str, std::ffi::OsString)> {
    std::env::var_os("VOX_PROOF_MP10_KEYS")
        .map(|mode| vec![("VOX_MUTANT_MP10_KEYS", mode)])
        .unwrap_or_default()
}

/// `vox room remove-member`, following only the product's explicit no-change instruction.
fn remove_member(dir: &std::path::Path, room: &str, member: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (removed, said) = vox(dir, &["room", "remove-member", room, member], "");
        if removed {
            return said;
        }
        assert!(
            said.contains("still being applied") && Instant::now() < deadline,
            "PRODUCT (staging): `vox room remove-member` failed: {said}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// ADR-053 MP-10 boundary 3, **a removed author's package opens nothing** (arm (i)).
///
/// Staged as the first act stages a package: C made the room and stays up; A posts three
/// messages while B is down, so the only way B can ever read them is A's key-package for B,
/// which C carries (`wait_for_log_delivery`). A goes down and C, the creator, removes A. B
/// comes back and syncs with C only, its package work held (`VOX_TEST_HOLD_PACKAGES_FILE`,
/// test-knobs) until it has applied A's removal and holds every log entry C holds (A's package
/// among them), so the package meets a node that knows the removal. Its received sender-key
/// generations are counted, the hold is released, and over three rounds made by C's posts
/// (each complete when B holds C's entries and has no package work left) `vox room read` on B
/// shows none of the three posts and `vox status --json` shows no more received generations
/// than before. Today `pending_package.rs` refuses the package at open (`is_member_removed`)
/// and again at install ("sender key author is removed").
///
/// Mutant (`VOX_PROOF_MP10_KEYS=package-open`, to B only): the boundary off at both lines; B
/// installs A's package → PRODUCT red.
#[test]
#[ignore = "three real daemons restarted in turn, production Argon2id; CI runs it in release"]
fn a_removed_authors_package_opens_nothing() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_HOLD_PACKAGES_FILE"]);
    let mutant = mp10_keys_mutant();
    if !mutant.is_empty() {
        test_knobs::require(&["VOX_MUTANT_MP10_KEYS"]);
    }
    let mut k = cast();
    let (c, sent) = posts_only_a_package_opens(&mut k);

    // ---- C, the creator, removes A ----
    remove_a(&k, &c);
    let c_entries = room_status(&k.c, &k.room)
        .and_then(|r| r["log_entries"].as_u64())
        .expect("CANNOT MEASURE (staging): C's status names no log_entries");

    // ---- B comes back with only C up. Its package work is held (VOX_TEST_HOLD_PACKAGES_FILE)
    // until it has applied A's removal, so the package meets a node that knows the removal ----
    let hold = k._tmp.path().join("hold-packages");
    std::fs::write(&hold, b"").expect("APPARATUS: write the package hold file");
    let mut env: Vec<(&str, &std::ffi::OsStr)> =
        mutant.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
    env.push(("VOX_TEST_HOLD_PACKAGES_FILE", hold.as_os_str()));
    let b = Daemon::start_env("b", &k.b, &env);
    b_catches_up(&k, &b, c_entries, false);
    let baseline = room_status(&k.b, &k.room)
        .and_then(|r| r["received_key_generations"].as_u64())
        .expect("CANNOT MEASURE (staging): B's status names no received_key_generations");
    eprintln!(
        "[MP-10 b3 (i)] B applied A's removal and holds every entry C holds ({c_entries}) with \
         its package work held; received_key_generations {baseline}; releasing package work"
    );
    std::fs::remove_file(&hold).expect("APPARATUS: release the package hold");
    none_read_in_three_syncs(&k, &b, &sent, baseline, "b3 (i)");
    eprintln!(
        "[MP-10 b3 (i)] GREEN: B, knowing A's removal, installed no key of A's and across three \
         rounds read none of A's posts sealed under A's package\nB stderr:\n{}",
        b.stderr()
    );
    drop(b);
    drop(c);
}

/// The staging of MP-10's removed-author arms: C up; A, still a member, writes three posts
/// while B is down, so B can open them only through A's key-package, which C carries; A stops.
/// Returns C's daemon and the three posts.
fn posts_only_a_package_opens(k: &mut Cast) -> (Daemon, Vec<String>) {
    let c = set_up(k, "mp10-before-the-grant");
    let b_short: String = k.fps[1].chars().take(12).collect();
    let a = Daemon::start("a", &k.a);
    let unreachable_b = |l: &str| l.contains("could not reach") && l.contains(&b_short);
    a.wait_err_count("that B cannot be reached", 0, 120, unreachable_b);
    let sent: Vec<String> = (0..3).map(|i| format!("mp10-removed-author-{i}")).collect();
    for t in &sent {
        ok(&k.a, &["room", "post", &k.room, t], "");
    }
    ok(&k.a, &["room", "post", &k.room, "mp10-sentinel"], "");
    let deadline = Instant::now() + Duration::from_secs(90);
    while !ok(&k.c, &["room", "read", &k.room], "").contains("mp10-sentinel") {
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE (staging): C never received A's last post\nA stderr:\n{}",
            a.stderr()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    wait_for_log_delivery(k, &a, &c, "CANNOT MEASURE (staging)");
    a.stop();
    (c, sent)
}

/// C, the creator, removes A and posts after it; A's three posts stay A's eligible history,
/// which C still reads.
fn remove_a(k: &Cast, c: &Daemon) {
    remove_member(&k.c, &k.room, &k.fps[0]);
    let deadline = Instant::now() + Duration::from_secs(60);
    while ok(&k.c, &["room", "roster", &k.room], "").contains(&k.fps[0]) {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): C still lists removed A\nC stderr:\n{}",
            c.stderr()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    ok(&k.c, &["room", "post", &k.room, "mp10-after-removal"], "");
    let sent: Vec<String> = (0..3).map(|i| format!("mp10-removed-author-{i}")).collect();
    assert_eq!(
        readable(&k.c, &k.room, &sent),
        sent.len(),
        "CANNOT MEASURE (staging): C no longer reads A's three posts after the removal, so \
         they are not A's eligible history and B's refusal would prove nothing"
    );
}

/// B has A off its roster and holds every log entry C held after the removal (`c_entries`: A's
/// package, A's posts and C's post after the removal among them), and, when `idle`, has no
/// package work left. (C does not consent to B reading it, so C's post is held, not shown.)
fn b_catches_up(k: &Cast, b: &Daemon, c_entries: u64, idle: bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let roster = ok(&k.b, &["room", "roster", &k.room], "");
        let room = room_status(&k.b, &k.room);
        let held = room
            .as_ref()
            .and_then(|r| r["log_entries"].as_u64())
            .is_some_and(|n| n >= c_entries);
        let idle = !idle
            || room
                .as_ref()
                .is_some_and(|r| r["key_packages_pending"] == false);
        if !roster.contains(&k.fps[0]) && held && idle {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): B did not catch up with C (A off the roster: {}, every entry C \
             holds: {held}, package work done: {idle})\nB status: {room:?}\nB stderr:\n{}",
            !roster.contains(&k.fps[0]),
            b.stderr()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// After each of three delivery rounds, check whether B can read any of `sent`.
/// The received-generation count is printed only as a diagnostic.
fn none_read_in_three_syncs(k: &Cast, b: &Daemon, sent: &[String], baseline: u64, arm: &str) {
    let mut reds = Vec::new();
    for round in 1..=3 {
        ok(
            &k.c,
            &["room", "post", &k.room, &format!("mp10-round-{round}")],
            "",
        );
        let c_entries = room_status(&k.c, &k.room)
            .and_then(|r| r["log_entries"].as_u64())
            .expect("CANNOT MEASURE (staging): C's status names no log_entries");
        let deadline = Instant::now() + Duration::from_secs(120);
        let room = loop {
            let room = room_status(&k.b, &k.room);
            let done = room.as_ref().is_some_and(|r| {
                r["log_entries"].as_u64().is_some_and(|n| n >= c_entries)
                    && r["key_packages_pending"] == false
            });
            if done {
                break room.expect("a status row");
            }
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE: B did not take C's round-{round} post ({c_entries} entries) \
                 with its package work done\nB status: {room:?}\nB stderr:\n{}",
                b.stderr()
            );
            std::thread::sleep(Duration::from_millis(500));
        };
        let (_, read) = vox(&k.b, &["room", "read", &k.room], "");
        let got: Vec<&String> = sent.iter().filter(|t| read.contains(t.as_str())).collect();
        let now = room["received_key_generations"].as_u64().unwrap_or(0);
        eprintln!(
            "[MP-10 {arm}] round {round}: B holds C's {c_entries} entries, no package work; it \
             read {} of removed A's three posts {got:?}; received_key_generations {now} (before: \
             {baseline})\nB read:\n{read}",
            got.len()
        );
        if !got.is_empty() {
            reds.push(format!(
                "round {round}: B read {} of removed A's posts sealed under its package {got:?}",
                got.len()
            ));
        }
    }
    assert!(
        reds.is_empty(),
        "PRODUCT: {}\nB status: {:?}\nB stderr:\n{}",
        reds.join("; "),
        room_status(&k.b, &k.room),
        b.stderr()
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

/// Kept log delivery completes without another failed reach after D reads all six.
/// Measured elapsed times were 3.426 s when kept and 33.729 s when rescued by
/// ordinary maintenance; elapsed time is printed, not a PRODUCT verdict.
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
    let log_release_started = Instant::now();
    let failed_reaches = || {
        a.stderr()
            .lines()
            .filter(|line| line.contains("could not reach") && line.contains(&b_short))
            .count()
    };
    let failures_when_d_read = failed_reaches();
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
    wait_for_log_delivery(&k, &a, &c, "PRODUCT");
    let failures_when_delivery_completed = failed_reaches();
    eprintln!(
        "[V030-01 kept delivery] A's failed reaches to B: when D read all six \
         {failures_when_d_read}, when delivery completed {failures_when_delivery_completed}"
    );
    a.stop();
    d.stop();

    // ---- B comes back with only C up ----
    let b = Daemon::start("b", &k.b);
    let b_got = read_all(&k.b, &k.room, &sent, 120);
    let log_release_elapsed = log_release_started.elapsed();
    eprintln!("[V030-01 elapsed] D read all six → B read {b_got}: {log_release_elapsed:?}");
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

#[test]
#[ignore = "real binary governance refusal and read recovery; run with test-knobs"]
fn a_governance_refresh_is_a_retryable_read_refusal() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_HOLD_GOVERNANCE_READ_FILE"]);
    let k = cast();
    let hold = k.c.join("governance-read-hold");
    let _c = Daemon::start_env(
        "c",
        &k.c,
        &[("VOX_TEST_HOLD_GOVERNANCE_READ_FILE", hold.as_os_str())],
    );
    ok(
        &k.c,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "refresh",
        ],
        &format!("{ROOMPASS}\n"),
    );
    let room = ok(&k.c, &["room", "list"], "")
        .split_whitespace()
        .next()
        .expect("APPARATUS: created room")
        .to_owned();
    ok(&k.c, &["room", "post", &room, "after-refresh"], "");
    std::fs::write(&hold, "hold").unwrap();
    let (accepted, out) = vox(&k.c, &["room", "read", &room], "");
    std::fs::remove_file(hold).unwrap();
    assert!(
        !accepted && out.contains("room governance is refreshing; try again when it is ready"),
        "PRODUCT: a governance refresh must be the recognised retry refusal, not an internal \
         failure or a different spelling: {out}"
    );
    assert!(
        ok(&k.c, &["room", "read", &room], "").contains("after-refresh"),
        "PRODUCT: releasing governance must make the same room readable"
    );
}

#[test]
#[ignore = "real offline key package with direct key sends held; run with test-knobs"]
fn an_abandoned_key_request_is_selected_again() {
    watchdog::arm();
    test_knobs::require(&[
        "VOX_TEST_ABANDON_KEY_PACKAGE_ONCE",
        "VOX_TEST_HOLD_PAIRWISE_KEY_FILE",
    ]);
    let k = cast();
    let direct_hold = k.a.join("hold-direct");
    let a = Daemon::start_env(
        "a",
        &k.a,
        &[("VOX_TEST_HOLD_PAIRWISE_KEY_FILE", direct_hold.as_os_str())],
    );
    ok(
        &k.a,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "abandon",
        ],
        &format!("{ROOMPASS}\n"),
    );
    let room = ok(&k.a, &["room", "list"], "")
        .split_whitespace()
        .next()
        .expect("APPARATUS: created room")
        .to_owned();
    let link = ok(&k.a, &["room", "link", &room], "")
        .lines()
        .find(|line| line.starts_with("vox://"))
        .expect("APPARATUS: the product's room link")
        .to_owned();
    let b = Daemon::start("b", &k.b);
    ok(
        &k.b,
        &["room", "join", "--passphrase-file", "-", link.trim()],
        &format!("{ROOMPASS}\n"),
    );
    ok(&k.b, &["trust", "add", &k.fps[0], "--name", "a"], "");
    b.stop();
    let stage_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let status = ok(&k.a, &["status", "--json"], "");
        let status: serde_json::Value =
            serde_json::from_str(&status).expect("APPARATUS: shipped status JSON");
        let disconnected = status["rooms"].as_array().is_some_and(|rooms| {
            rooms.iter().any(|row| {
                row["members"].as_array().is_some_and(|members| {
                    members
                        .iter()
                        .any(|member| member["id"] == k.fps[1] && member["connected"] == false)
                })
            })
        });
        if disconnected {
            break;
        }
        assert!(
            Instant::now() < stage_deadline,
            "APPARATUS: stopped recipient was never reported disconnected: {status}"
        );
        std::thread::yield_now();
    }
    std::fs::write(&direct_hold, &k.fps[1]).unwrap();
    ok(&k.a, &["trust", "add", &k.fps[1], "--name", "b"], "");
    eprintln!("[RG4] recipient stopped after joining; sender granted it read");
    let marker = "rg4-post-readable-only-through-the-logged-key";
    ok(&k.a, &["room", "post", &room, marker], "");
    // The state this act is about: B's key travels only through the room's log. A logs it once
    // its reach to the stopped B has failed, and says so; B comes back only after that, so the
    // direct send (held) is never what B could be offered.
    a.wait_err_count("that B's key went into the room's log", 0, 120, |l| {
        l.contains("went into the room's log as a key package")
    });
    let arm = k.b.join("abandon.arm");
    std::fs::write(&arm, "abandon one real selection").unwrap();
    let b = Daemon::start_env(
        "b",
        &k.b,
        &[("VOX_TEST_ABANDON_KEY_PACKAGE_ONCE", arm.as_os_str())],
    );
    let selected = arm.with_extension("selected");
    let stage_deadline = Instant::now() + Duration::from_secs(120);
    while !selected.exists() {
        let answer = vox(&k.b, &["room", "read", &room], "");
        assert!(
            Instant::now() < stage_deadline,
            "APPARATUS: the logged package was not selected: {answer:?}; receiver: {}; sender: {}",
            b.stderr(),
            a.stderr()
        );
        std::thread::yield_now();
    }
    eprintln!("[RG4] a real selected package was abandoned before Open");
    let stage_deadline = Instant::now() + Duration::from_secs(120);
    let mut shown = false;
    while Instant::now() < stage_deadline {
        let (accepted, out) = vox(&k.b, &["room", "read", &room], "");
        assert!(
            !b.stderr().contains("key-package attempt unacknowledged"),
            "PRODUCT: an abandoned key request permanently refused its next selection: {}",
            b.stderr()
        );
        if accepted && out.contains(marker) {
            shown = true;
            break;
        }
        eprintln!("[RG4] answered history demand: {out}");
        std::thread::yield_now();
    }
    assert!(
        shown,
        "APPARATUS: readable sender post was not observed after the abandoned key request; \
         direct key sends remain held; receiver: {}",
        b.stderr()
    );
    b.stop();
    a.stop();
}

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    a_delayed_relay_keeps_up_with_a_two_per_second_author,
    a_delayed_relay_keeps_up_with_two_authors_each_posting_twice_a_second
);

#[cfg(feature = "optional-proofs")]
#[path = "support/room.rs"]
mod room;
#[cfg(feature = "optional-proofs")]
#[path = "support/world.rs"]
mod world;

/// A small, counted sync measurement; no product setting creates its latency.
#[cfg(feature = "optional-proofs")]
mod delayed_relay {
    use super::*;
    use room::{Out, Worker};
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};

    const POSTS: usize = 300;
    // The same per-client, dual-family UDP forwarding recipe as RcaWedge/udpdelay.py.
    // Every datagram spends at least 75 ms in each direction of each member's anchor hop.
    const FORWARDER: &str = r#"
import heapq, selectors, socket, sys, time
upstream = ('127.0.0.1', int(sys.argv[1]))
sel, clients, owners, queue = selectors.DefaultSelector(), {}, {}, []
serial, counts, minimum = 0, [0, 0], [999999., 999999.]
fronts = []
for family, host in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
    s = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((host, 0)); s.setblocking(False)
    sel.register(s, selectors.EVENT_READ, ('front', s)); fronts.append(s)
print('ready', fronts[0].getsockname()[1], fronts[1].getsockname()[1], flush=True)
last = time.monotonic()
while True:
    now = time.monotonic()
    wait = max(0., min(.05, queue[0][0] - now)) if queue else .05
    for key, _ in sel.select(wait):
        kind, s = key.data
        while True:
            try:
                if kind == 'front':
                    data, address = s.recvfrom(65535)
                    identity = (s.fileno(), address)
                    if identity not in clients:
                        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        u.connect(upstream); u.setblocking(False)
                        clients[identity] = u; owners[u.fileno()] = (s, address)
                        sel.register(u, selectors.EVENT_READ, ('up', u))
                    target, address, direction = clients[identity], None, 0
                else:
                    data = s.recv(65535)
                    target, address = owners[s.fileno()]
                    direction = 1
            except BlockingIOError:
                break
            serial += 1
            arrived = time.monotonic()
            heapq.heappush(queue, (arrived + .075, serial, target, address, data, direction, arrived))
    now = time.monotonic()
    while queue and queue[0][0] <= now:
        _, _, s, address, data, direction, arrived = heapq.heappop(queue)
        try:
            s.send(data) if address is None else s.sendto(data, address)
        except OSError as error:
            print('APPARATUS forward failed', error, flush=True); raise
        counts[direction] += 1
        minimum[direction] = min(minimum[direction], time.monotonic() - arrived)
    if now - last >= 1:
        print('delay', *counts, *(round(n * 1000, 3) for n in minimum), flush=True)
        last = now
"#;

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn accepted(out: Out) -> Out {
        assert!(out.code.is_some(), "APPARATUS: command killed: {out:?}");
        out.expect_ok("delayed relay command");
        out
    }

    fn status(w: &Worker) -> Value {
        let out = accepted(w.vox(None, &["status", "--json"]));
        let all = out.json();
        all["rooms"]
            .as_array()
            .and_then(|rows| rows.first())
            .expect("APPARATUS: measurement room status")
            .clone()
    }

    // This measurement needs the authenticated contiguous feed, not sparse retained rows.
    // RG-7 calls it verified_through; older measurement trees call it holds_through.
    fn held(status: &Value, author: &str) -> u64 {
        let row = status["members"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["id"] == author))
            .expect("APPARATUS: reader status names author");
        row["verified_through"]
            .as_u64()
            .or_else(|| row["holds_through"].as_u64())
            .expect("APPARATUS: contiguous feed position")
    }

    fn read(w: &Worker, id: &str) -> BTreeSet<String> {
        let mut before = None::<String>;
        let mut cursors = BTreeSet::new();
        let mut texts = BTreeSet::new();
        for page in 1.. {
            let mut args = vec!["room", "read", id, "--json", "--limit", "200"];
            if let Some(cursor) = before.as_deref() {
                args.extend(["--before", cursor]);
            }
            let out = accepted(w.vox(None, &args));
            for row in out.ndjson() {
                if let Some(text) = row["text"].as_str() {
                    texts.insert(text.to_owned());
                }
            }
            let next = out
                .stderr
                .lines()
                .find(|line| line.contains("older messages not shown:"))
                .map(|line| {
                    line.split_whitespace()
                        .collect::<Vec<_>>()
                        .windows(2)
                        .find(|pair| pair[0] == "--before")
                        .expect("APPARATUS: pageable footer")[1]
                        .trim_matches(['\'', '"'])
                        .to_owned()
                });
            eprintln!("[RG6 page] {} page={page} next={next:?}", w.name);
            let Some(next) = next else { return texts };
            assert!(
                cursors.insert(next.clone()),
                "APPARATUS: repeated paging cursor"
            );
            before = Some(next);
        }
        unreachable!()
    }

    fn start(w: &Worker, listen: &str, anchor: &str) -> ChildGuard {
        room::reap_daemon(&w.data);
        let mut command = Command::new(&w.exe);
        room::strip_harness_env(&mut command);
        let mut daemon = ChildGuard(
            command
                .args([
                    "daemon",
                    "--node",
                    &w.name,
                    "--listen",
                    listen,
                    "--anchor",
                    anchor,
                    "--passphrase-file",
                ])
                .arg(&w.pass)
                .env("VOX_DATA_DIR", &w.data)
                .env("VOX_CONFIG_DIR", &w.cfg)
                .env("HOME", w.data.with_extension("home"))
                .env("VOX_PROXY", "127.0.0.1:0")
                .stdin(Stdio::null())
                .stdout(std::fs::File::create(w.data.with_extension("out")).unwrap())
                .stderr(std::fs::File::create(w.data.with_extension("err")).unwrap())
                .spawn()
                .expect("APPARATUS: serving daemon"),
        );
        let since = Instant::now();
        while !world::daemon_lock(&w.data).exists() {
            assert!(
                daemon.0.try_wait().unwrap().is_none() && since.elapsed().as_secs() < 120,
                "APPARATUS: serving daemon did not acquire its scratch lock"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        loop {
            if w.vox(None, &["room", "list"]).ok {
                assert_eq!(
                    world::daemon_pid(&w.data),
                    Some(daemon.0.id()),
                    "APPARATUS: foreground pid must serve this scratch profile"
                );
                return daemon;
            }
            assert!(
                since.elapsed().as_secs() < 120,
                "APPARATUS: daemon not ready"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    #[ignore = "optional counted delayed-relay measurement; run ALONE"]
    fn a_delayed_relay_keeps_up_with_a_two_per_second_author() {
        relay(1);
    }

    /// The same path and delay with two members each posting twice a second at once: the reader
    /// needs four posts a second over its relayed path, and each author reads the other through
    /// the same relay.
    #[test]
    #[ignore = "optional counted delayed-relay measurement; run ALONE"]
    fn a_delayed_relay_keeps_up_with_two_authors_each_posting_twice_a_second() {
        relay(2);
    }

    /// What a person reads for author `i`'s posts, as the reader and as each author.
    fn prefix(i: usize) -> String {
        if i == 0 {
            "rg6-post".to_owned()
        } else {
            format!("rg6-a{}-post", i + 1)
        }
    }

    /// `writers` authors each post twice a second, [`POSTS`] times, to a reader that reaches
    /// every one of them only through the anchor's relay, 75 ms each way on every hop.
    fn relay(writers: usize) {
        watchdog::arm();
        let tmp = room::diagnostic_tempdir();
        eprintln!(
            "[RG6] scratch={} authors={writers} each=2/s maximum={POSTS}",
            tmp.path().display()
        );
        let (_anchor, spec) = room::spawn_anchor(tmp.path());
        let upstream = world::spec_addr(&spec);
        let mut emulator = ChildGuard(
            Command::new("python3")
                .args(["-u", "-c", FORWARDER, &upstream.port().to_string()])
                .stdout(Stdio::piped())
                .stderr(std::fs::File::create(tmp.path().join("emulator.err")).unwrap())
                .spawn()
                .expect("APPARATUS: UDP delay emulator"),
        );
        let output = collect(emulator.0.stdout.take().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        let (v4, v6) = loop {
            let ready = output
                .lock()
                .unwrap()
                .iter()
                .find(|line| line.starts_with("ready "))
                .cloned();
            if let Some(line) = ready {
                let words: Vec<_> = line.split_whitespace().collect();
                break (
                    words[1].parse::<u16>().unwrap(),
                    words[2].parse::<u16>().unwrap(),
                );
            }
            assert!(Instant::now() < deadline, "APPARATUS: emulator not ready");
            std::thread::sleep(Duration::from_millis(20));
        };
        let a_spec = world::respec(&spec, format!("127.0.0.1:{v4}").parse().unwrap());
        let b_spec = world::respec(&spec, format!("[::1]:{v6}").parse().unwrap());
        // Authors listen on IPv4 and the reader on IPv6 only, so the reader reaches every author
        // only through the delayed relay.
        let authors: Vec<Worker> = (0..writers)
            .map(|i| {
                let name = if i == 0 {
                    "author".to_owned()
                } else {
                    format!("author{}", i + 1)
                };
                room::named_worker_as(tmp.path(), &name, &name, VOX)
            })
            .collect();
        let reader = room::named_worker_as(tmp.path(), "reader", "reader", VOX);
        let _authors: Vec<_> = authors
            .iter()
            .map(|author| start(author, "127.0.0.1:0", &a_spec))
            .collect();
        let _b = start(&reader, "[::1]:0", &b_spec);
        let author = &authors[0];
        accepted(author.vox_in(
            None,
            &[
                "room",
                "create",
                "--name",
                "relay-count",
                "--passphrase-file",
                "-",
            ],
            Some(&format!("{}\n", room::ROOM_PASS)),
        ));
        let id = author
            .vox(None, &["room", "list"])
            .stdout
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        let link_out = accepted(author.vox(None, &["room", "link", &id]));
        let link = link_out
            .stdout
            .lines()
            .find(|line| line.starts_with("vox://"))
            .unwrap();
        let everyone: Vec<&Worker> = authors.iter().chain([&reader]).collect();
        for w in everyone.iter().skip(1) {
            accepted(w.vox_in(
                None,
                &["room", "join", "--passphrase-file", "-", link],
                Some(&format!("{}\n", room::ROOM_PASS)),
            ));
        }
        // The typed-command stand-in also needs the empty headless passphrase explicitly.
        for w in &everyone {
            for other in everyone.iter().filter(|other| other.name != w.name) {
                accepted(w.vox(
                    None,
                    &[
                        "trust",
                        "add",
                        &other.b32(),
                        "--name",
                        &other.name,
                        "--identity-passphrase-file",
                        w.pass.to_str().unwrap(),
                    ],
                ));
            }
        }
        for w in &everyone {
            accepted(w.vox(None, &["room", "post", &id, &format!("ready-{}", w.name)]));
        }
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if everyone.iter().all(|w| {
                let texts = read(w, &id);
                everyone
                    .iter()
                    .all(|other| texts.contains(&format!("ready-{}", other.name)))
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "APPARATUS: quiet relay did not establish readable keys both ways"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        let relay_log = format!(
            "{}\n{}",
            std::fs::read_to_string(tmp.path().join("anchor.out")).unwrap(),
            std::fs::read_to_string(tmp.path().join("anchor.err")).unwrap()
        );
        let reader_status = status(&reader);
        eprintln!("[RG6 route] reader={reader_status}; anchor={relay_log}");
        assert!(
            relay_log.lines().any(|line| line
                .split_once(" circuit(s) carried")
                .and_then(|(prefix, _)| prefix.split_whitespace().next_back())
                .and_then(|n| n.parse::<usize>().ok())
                .is_some_and(|n| n > 0)),
            "APPARATUS: anchor did not report carrying a relay circuit: {relay_log}"
        );
        // With one author a line reads as it always has; with more, each author's part names it.
        let who = move |w: &Worker| {
            if writers == 1 {
                String::new()
            } else {
                format!("{}: ", w.name)
            }
        };
        let stop = AtomicBool::new(false);
        let acknowledged: Vec<Mutex<Vec<u64>>> =
            (0..writers).map(|_| Mutex::new(Vec::new())).collect();
        let failure = Mutex::new(None::<String>);
        let begun = Instant::now();
        let progress = std::thread::scope(|scope| {
            let posters: Vec<_> = authors
                .iter()
                .enumerate()
                .map(|(i, author)| {
                    let (stop, failure, acked, id) = (&stop, &failure, &acknowledged[i], &id);
                    scope.spawn(move || {
                        let start = Instant::now();
                        for n in 1..=POSTS {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            let due = start + Duration::from_millis((n as u64 - 1) * 500);
                            if let Some(wait) = due.checked_duration_since(Instant::now()) {
                                std::thread::sleep(wait);
                            }
                            if Instant::now().saturating_duration_since(due)
                                > Duration::from_secs(1)
                            {
                                *failure.lock().unwrap() =
                                    Some("APPARATUS: 2/s posting cadence not attained".into());
                                break;
                            }
                            let out = author.vox(
                                None,
                                &["room", "post", id, &format!("{}-{n:04}", prefix(i))],
                            );
                            if !out.ok {
                                *failure.lock().unwrap() = Some(format!(
                                    "{}: {}post {n} refused: {out:?}",
                                    if out.code.is_none() {
                                        "APPARATUS"
                                    } else {
                                        "PRODUCT"
                                    },
                                    who(author)
                                ));
                                break;
                            }
                            let through = status(author)["own_feed_through"]
                                .as_u64()
                                .expect("APPARATUS: author feed position");
                            acked.lock().unwrap().push(through);
                            eprintln!(
                                "[RG6 ACK] {}post={n} feed_seq={through} at_ms={}",
                                who(author),
                                start.elapsed().as_millis()
                            );
                        }
                    })
                })
                .collect();
            let deadline = Instant::now() + Duration::from_secs(240);
            let outcome = loop {
                let texts = read(&reader, &id);
                let reader_status = status(&reader);
                let mut line = String::new();
                let mut starving = None;
                let mut done = true;
                let mut all_shown = true;
                for (i, author) in authors.iter().enumerate() {
                    let ack = acknowledged[i].lock().unwrap().clone();
                    let p = prefix(i);
                    let newest = (1..=ack.len())
                        .rev()
                        .find(|n| texts.contains(&format!("{p}-{n:04}")))
                        .unwrap_or(0);
                    let shown = (1..=ack.len())
                        .filter(|n| texts.contains(&format!("{p}-{n:04}")))
                        .count();
                    let raw = held(&reader_status, &author.b32());
                    let count = ack.iter().filter(|seq| **seq <= raw).count();
                    line += &format!("{}reader shows {shown} of {}; feed held through {count} of {}; raw_seq={raw}; latest_shown={newest}; ", who(author), ack.len(), ack.len());
                    if ack.len().saturating_sub(newest) >= 100 {
                        starving = Some(format!("{}author acknowledged {} further posts after last shown post {newest}; reader shows {shown} of {}; feed held through {count} of {}; raw_seq={raw}",
                            who(author), ack.len() - newest, ack.len(), ack.len()));
                    }
                    done &= ack.len() == POSTS && newest == POSTS;
                    all_shown &= shown == POSTS;
                }
                eprintln!("[RG6 count] {line}at_ms={}", begun.elapsed().as_millis());
                if failure.lock().unwrap().is_some() {
                    break (false, false);
                }
                if let Some(starving) = starving {
                    eprintln!("[RG6 starvation] PRODUCT: {starving}");
                    break (false, false);
                }
                if done {
                    break (all_shown, false);
                }
                if Instant::now() >= deadline {
                    break (false, true);
                }
                std::thread::sleep(Duration::from_millis(250));
            };
            stop.store(true, Ordering::Relaxed);
            for poster in posters {
                poster.join().expect("APPARATUS: poster panicked");
            }
            outcome
        });
        let texts = read(&reader, &id);
        let reader_status = status(&reader);
        let author_texts: Vec<_> = authors.iter().map(|a| read(a, &id)).collect();
        let delays = output.lock().unwrap().clone();
        std::fs::write(tmp.path().join("emulator.out"), delays.join("\n")).unwrap();
        assert!(
            emulator.0.try_wait().unwrap().is_none()
                && delays.iter().any(|line| {
                    let words: Vec<_> = line.split_whitespace().collect();
                    words.len() == 5
                        && words[0] == "delay"
                        && words[1].parse::<u64>().unwrap_or(0) > 0
                        && words[2].parse::<u64>().unwrap_or(0) > 0
                        && words[3].parse::<f64>().unwrap_or(0.) >= 75.
                        && words[4].parse::<f64>().unwrap_or(0.) >= 75.
                }),
            "APPARATUS: delay not attained: {delays:?}"
        );
        let failure = failure.lock().unwrap();
        let apparatus = progress.1 || failure.as_ref().is_some_and(|s| s.starts_with("APPARATUS"));
        let mut green = progress.0 && failure.is_none();
        let mut counts = String::new();
        for (i, author) in authors.iter().enumerate() {
            let ack = acknowledged[i].lock().unwrap();
            let p = prefix(i);
            let shown_in = |texts: &BTreeSet<String>| {
                (1..=ack.len())
                    .filter(|n| texts.contains(&format!("{p}-{n:04}")))
                    .count()
            };
            let shown = shown_in(&texts);
            // Every author shows every author's posts too.
            let author_shown = author_texts.iter().map(shown_in).min().unwrap_or(0);
            let raw = held(&reader_status, &author.b32());
            let count = ack.iter().filter(|seq| **seq <= raw).count();
            green &= shown == ack.len() && author_shown == ack.len();
            let n = ack.len();
            counts += &format!(
                "{}reader shows {shown} of {n}; author{} shows {author_shown} of {n}; feed held \
                 through {count} of {n}; raw_seq={raw}; ",
                who(author),
                if writers == 1 { "" } else { "s" }
            );
        }
        let verdict = format!(
            "{} {}: {counts}last-post deadman={}; failure={failure:?}",
            if green { "GREEN" } else { "RED" },
            if apparatus { "APPARATUS" } else { "PRODUCT" },
            progress.1
        );
        eprintln!("{verdict}");
        assert!(green, "{verdict}");
    }
}
