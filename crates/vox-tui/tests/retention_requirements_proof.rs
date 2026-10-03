//! PRD-001 R6, R7 and R10 — the three retention requirements that had no gate of their own,
//! each driven through the **shipped `vox` binary** (ADR-023 decision 2, ADR-010).
//!
//! `retention_proof` proves the retroactive shortening (R8) and the node-shorter-than-room rule
//! (R9). What it did not prove on its own:
//!
//! - **R6, forever by default.** A room nobody set a retention on keeps every message. The
//!   messages here are authored by a node whose clock is **ten years behind**
//!   (`VOX_TEST_CLOCK_SKEW_MS`, the test-only knob the causal-order proofs use), so every one of
//!   them is ten years old by its author's claim — and age runs from that claim. They must all
//!   still read, on both members, across sweeps and a restart.
//! - **R7, the admin changes it later.** Only the room's creator or an admin — a holder of the
//!   `policy` capability — sets the room's retention (V030-32). A member who is neither may set
//!   **their own node's**, lower than the room's and governing only that member's copy: their
//!   messages go at that bound on their node alone, while every other member keeps the room's. A
//!   member asking for longer than the room is refused and changes nothing anywhere; a node
//!   retention file asking for longer is ignored and the node says so. The admin's change applies
//!   to what is already stored, on every member, in both directions: shortened, older messages go
//!   everywhere; lengthened to forever, what is left stays.
//! - **R10, a skeleton still does its job.** An expired entry keeps its signed skeleton, and that
//!   skeleton still takes part in fork detection: a second, conflicting entry signed by the same
//!   author for an **expired** position is caught as an equivocation, and the author is frozen
//!   (ADR-008) — its later posts stop reaching the node that saw the fork. Below the author's
//!   checkpoint, where ADR-023 decision 3 lets a node shed the signatures, the same conflict is
//!   **refused as pre-checkpoint, never classified as a fork**, so the author is not frozen.
//!
//! **A red names its side.** A claim's assertion is PRODUCT and quotes what `vox` showed. A `vox`
//! command that fails or a node that does not get there while the scene is set (an identity, a
//! daemon, a room, a join, a trust, a post, a first read, a retention reaching every member) is
//! the product failing: PRODUCT (staging); each wait says which it is. What R10's author-side
//! client must achieve on its own (its profile, its connection, an answered session that lists
//! and serves the position) is CANNOT MEASURE. The test's own processes, files, ports and runtime
//! are APPARATUS.
//!
//! Mutations (each run, each red): a non-zero default retention (R6); the admin check skipped,
//! and a change that reaches only new entries (R7); the fork check skipped for a pruned position
//! (R10); the pre-checkpoint refusal removed (R10: bob refuses nothing below the checkpoint; this
//! claim was `checkpoint_proof`'s, offered in-process until #227).

#![cfg(unix)]

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "../../vox-core/tests/support/raw_sync.rs"]
mod raw_sync;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use raw_sync::Ask;
use vox_core::log::entry::Entry;
use vox_core::log::sync::WantRange;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// Ten years, in milliseconds: how far behind R6's author's clock runs.
const TEN_YEARS_MS: i64 = 10 * 365 * 24 * 3_600 * 1_000;

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("APPARATUS: vox's stdin")
            .write_all(text.as_bytes())
            .expect("APPARATUS: write to vox's stdin");
        drop(child.stdin.take());
    }
    // Bounded: a node that stops answering must fail this proof by name, not hang it.
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().expect("APPARATUS: wait on vox").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("PRODUCT: `vox {}` got no answer in 120 s", args.join(" "));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A free loopback UDP port, so a node can come back on the address its peers know.
fn free_port() -> String {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: a free UDP port");
    format!(
        "127.0.0.1:{}",
        s.local_addr().expect("APPARATUS: a free UDP port").port()
    )
}

/// `vox daemon` on `listen`, with `env` added, answering on its socket before this returns.
fn daemon(
    dir: &Path,
    tag: &str,
    stdin_lines: &str,
    listen: &str,
    env: &[(&str, String)],
) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out")))
        .expect("APPARATUS: the daemon's output file");
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: the daemon's output file");
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", listen])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox daemon");
    let mut pipe = child.stdin.take().expect("APPARATUS: the daemon's stdin");
    pipe.write_all(stdin_lines.as_bytes())
        .expect("APPARATUS: write the daemon's passphrases");
    drop(pipe);
    let d = Daemon(child);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if vox(dir, &["room", "list"], None).0 {
            return d;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): {tag}'s daemon never answered: {}",
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn identity(tmp: &Path, name: &str) -> (PathBuf, String) {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: a profile directory");
    let (ok, out, err) = vox(&dir, &["id"], None);
    assert!(ok, "PRODUCT (staging): vox id {name}: {err}");
    (dir, out.trim().to_owned())
}

/// The texts `vox room read` returns.
fn read(dir: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "PRODUCT: vox room read: {err}");
    out.lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

fn count(texts: &[String], prefix: &str) -> usize {
    texts.iter().filter(|t| t.starts_with(prefix)).count()
}

/// Poll `vox room read` until `done`. `what` starts with its side (`PRODUCT:` for a claim,
/// `PRODUCT (staging):` for the scene), and the red quotes what `vox room read` last showed.
fn until(dir: &Path, room: &str, what: &str, secs: u64, done: impl Fn(&[String]) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last = Vec::new();
    while Instant::now() < deadline {
        last = read(dir, room);
        if done(&last) {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{what} — not within {secs} s; `vox room read` shows {last:?}");
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(ok, "PRODUCT (staging): vox room post {text:?}: {err}");
}

fn trust(dir: &Path, fp: &str, name: &str) {
    let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
    assert!(ok, "PRODUCT (staging): vox trust add {name}: {err}");
}

/// The node's `vox status --json` report.
fn status(dir: &Path) -> serde_json::Value {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(ok, "PRODUCT: vox status: {err}");
    serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` did not parse ({e}): {out}"))
}

/// The room's effective retention as `vox status --json` reports it, seconds (`0` forever), or
/// `None` while the node lists no room yet (one still opening). A room that is listed must name
/// its retention, also while a sync session holds it (#58): a `null` there is PRODUCT, at once.
fn retention(dir: &Path, who: &str) -> Option<u64> {
    let st = status(dir);
    let room = st["rooms"].get(0)?;
    Some(room["retention"].as_u64().unwrap_or_else(|| {
        panic!("PRODUCT: {who}'s `vox status --json` lists the room with no retention: {room}")
    }))
}

/// The room's effective retention on `dir` now. The room must be listed: it was joined or made.
fn retention_now(dir: &Path, who: &str) -> u64 {
    retention(dir, who).unwrap_or_else(|| {
        panic!(
            "PRODUCT (staging): {who}'s `vox status --json` lists no room: {}",
            status(dir)
        )
    })
}

/// Poll until the room's effective retention on `dir` is `want`, and return how long it took.
/// `side` is the red's label: `PRODUCT` where reaching it is the claim, `PRODUCT (staging)` where
/// it sets the scene.
fn until_retention(dir: &Path, side: &str, who: &str, want: u64, secs: u64) -> Duration {
    let started = Instant::now();
    let mut last = None;
    while started.elapsed() < Duration::from_secs(secs) {
        last = retention(dir, who);
        if last == Some(want) {
            return started.elapsed();
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{side}: {who}'s room never reported retention {want} within {secs} s; last {last:?}");
}

/// What `dir`'s node reports it caught in the room: the authors it froze for a fork, and how
/// many entries it refused as at or below their author's checkpoint. Polled until `done` holds,
/// or `secs` pass. A listed room must name both, also while a session holds it (#58): a `null`
/// is PRODUCT, at once.
fn fork_watch(dir: &Path, secs: u64, done: impl Fn(&[String], u64) -> bool) -> (Vec<String>, u64) {
    let started = Instant::now();
    let mut last = None;
    while started.elapsed() < Duration::from_secs(secs) {
        let st = status(dir);
        if let Some(room) = st["rooms"].get(0) {
            let (Some(frozen), Some(refused)) = (
                room["frozen"].as_array(),
                room["refused_below_checkpoint"].as_u64(),
            ) else {
                panic!(
                    "PRODUCT: `vox status --json` lists the room without its frozen members or \
                     its refusals below a checkpoint: {room}"
                );
            };
            let frozen: Vec<String> = frozen
                .iter()
                .filter_map(|f| f.as_str().map(str::to_owned))
                .collect();
            if done(&frozen, refused) {
                return (frozen, refused);
            }
            last = Some((frozen, refused));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    last.expect("PRODUCT (staging): the room was never listed in `vox status`")
}

/// `creator` makes a room; returns its short id as `vox room list` prints it.
fn create(creator: &Path) -> String {
    let (ok, _, err) = vox(
        creator,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let (_, listed, _) = vox(creator, &["room", "list"], None);
    listed
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): a room id in `vox room list`")
        .to_owned()
}

fn join(creator: &Path, joiner: &Path, room: &str) {
    let (ok, link, err) = vox(creator, &["room", "invite", room], None);
    assert!(ok, "PRODUCT (staging): vox room invite: {err}");
    let (ok, _, err) = vox(
        joiner,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            link.trim(),
            "--name",
            "r",
        ],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room join: {err}");
}

/// `author` posts a probe until every one of `readers` shows one: from then on they read it.
fn until_readable(author: &Path, readers: &[&Path], room: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        post(author, room, "probe");
        std::thread::sleep(Duration::from_millis(500));
        if readers.iter().all(|r| count(&read(r, room), "probe") > 0) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): a reader never read the author's probe within 120 s"
        );
    }
}

fn set_retention(dir: &Path, room: &str, value: &str) -> (bool, String) {
    let (ok, out, err) = vox(dir, &["room", "retention", room, value], None);
    (ok, format!("{out}{err}"))
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn r6_a_room_with_no_retention_keeps_every_message_however_old() {
    watchdog::arm();
    let t = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let (alice, alice_fp) = identity(t.path(), "alice");
    let (bob, bob_fp) = identity(t.path(), "bob");
    test_knobs::require(&["VOX_TEST_CLOCK_SKEW_MS"]);
    let skew = vec![("VOX_TEST_CLOCK_SKEW_MS", format!("-{TEN_YEARS_MS}"))];
    let _a = daemon(
        &alice,
        "alice",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &skew,
    );
    let bob_d = daemon(&bob, "bob", &format!("{IDENTITY}\n"), "127.0.0.1:0", &[]);
    let room = create(&alice);
    join(&alice, &bob, &room);
    trust(&alice, &bob_fp, "bob");
    trust(&bob, &alice_fp, "alice");
    // Nobody set a retention: the room's must be forever on both members.
    let (ra, rb) = (retention_now(&alice, "alice"), retention_now(&bob, "bob"));
    println!("R6: retention nobody set — alice {ra:?}, bob {rb:?} (0 = forever)");
    assert_eq!(
        (ra, rb),
        (0, 0),
        "PRODUCT: a new room must keep history forever"
    );

    // Readable from here: alice's key reaches bob, so her messages render on his node.
    until_readable(&alice, &[&bob], &room);

    // Ten messages whose author claims they were written ten years ago, and five from now.
    for i in 1..=10 {
        post(&alice, &room, &format!("old {i}"));
    }
    for i in 1..=5 {
        post(&bob, &room, &format!("now {i}"));
    }
    for (dir, who) in [(&alice, "alice"), (&bob, "bob")] {
        until(
            dir,
            &room,
            &format!("PRODUCT: {who} must read all 15, the ten-year-old 10 included"),
            60,
            |t| count(t, "old ") == 10 && count(t, "now ") == 5,
        );
    }
    // Sweeps run every second; give them several passes, then a restart, which reopens the room
    // and sweeps it again from its stored history.
    std::thread::sleep(Duration::from_secs(5));
    drop(bob_d);
    let _b = daemon(
        &bob,
        "bob-2",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        "127.0.0.1:0",
        &[],
    );
    std::thread::sleep(Duration::from_secs(3));
    let (a, b) = (read(&alice, &room), read(&bob, &room));
    println!(
        "R6: after sweeps and bob's restart — alice reads {} ten-year-old + {} new, bob reads {} + {}",
        count(&a, "old "),
        count(&a, "now "),
        count(&b, "old "),
        count(&b, "now ")
    );
    for (who, t) in [("alice", &a), ("bob", &b)] {
        assert_eq!(
            (count(t, "old "), count(t, "now ")),
            (10, 5),
            "PRODUCT: {who}: a room with no retention set must keep every message, however old"
        );
    }
}

#[test]
#[ignore = "real vox daemons and real seconds (about three minutes); CI runs it in release"]
fn r7_only_the_admin_changes_retention_later_and_it_reaches_what_every_member_holds() {
    watchdog::arm();
    let t = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let (alice, alice_fp) = identity(t.path(), "alice");
    let (bob, bob_fp) = identity(t.path(), "bob");
    let (carol, carol_fp) = identity(t.path(), "carol");
    let _a = daemon(
        &alice,
        "alice",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &[],
    );
    let _b = daemon(&bob, "bob", &format!("{IDENTITY}\n"), "127.0.0.1:0", &[]);
    // carol's node retention file asks for 60 days, longer than every value the admin sets
    // below: a node may keep less than its room, never more, so it is ignored, and her node says
    // so (V030-32).
    std::fs::write(carol.join("cfg").join("retention"), "default 5184000\n")
        .expect("APPARATUS: carol's node retention file");
    let _c = daemon(
        &carol,
        "carol",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &[],
    );
    let room = create(&alice);
    join(&alice, &bob, &room);
    join(&alice, &carol, &room);
    trust(&alice, &bob_fp, "bob");
    trust(&alice, &carol_fp, "carol");
    // Trust runs one way (V210-161): bob and carol read alice only once they trust her too.
    trust(&bob, &alice_fp, "alice");
    trust(&carol, &alice_fp, "alice");
    until_readable(&alice, &[&bob, &carol], &room);
    let members = [(&alice, "alice"), (&bob, "bob"), (&carol, "carol")];

    // ---- the admin sets it: each preset the CLI offers, parsed into the room's ttl ---------
    // ADR-023 decision 2 offers 1 hour, 1 week, 1 month or a custom value; the custom value
    // is the 30 s below. The preset is what a person types, so it goes through the shipped
    // CLI's parser, and what is checked is the ttl the room then carries on every member.
    for (preset, want) in [("1h", 3_600), ("1m", 2_592_000), ("1w", 604_800)] {
        let (ok, said) = set_retention(&alice, &room, preset);
        assert!(ok, "PRODUCT: the admin sets {preset}: {said}");
        for (dir, who) in members {
            until_retention(dir, "PRODUCT", who, want, 30);
        }
        println!("R7: the admin set {preset}; all three members report {want}");
    }

    // ---- carol's file asked for longer than the room: ignored, and her node says so -----
    // The presets above already showed carol reporting the room's value each time. What a person
    // running her node reads is the warning on its output.
    let carol_said = std::fs::read_to_string(carol.join("daemon-carol.err")).unwrap_or_default();
    println!(
        "R7: carol's node, whose file asks for 60 days: warned = {}",
        carol_said.contains("longer than the room keeps it")
    );
    assert!(
        carol_said.contains("longer than the room keeps it"),
        "PRODUCT: carol's node file asks for longer than the room keeps messages; it is ignored, \
         and her node must say so. Her daemon said:\n{carol_said}"
    );

    // ---- a member who is not the admin never keeps longer than the room -------------------
    let (ok, said) = set_retention(&bob, &room, "2w");
    println!(
        "R7: bob (not the admin) asked for 2 weeks in a 1-week room: ok={ok} — {}",
        said.trim()
    );
    assert!(
        !ok && said.contains("never longer"),
        "PRODUCT: a member who is not the admin must be refused a retention longer than the \
         room's, saying why: ok={ok}, {said}"
    );
    std::thread::sleep(Duration::from_secs(3));
    for (dir, who) in members {
        assert_eq!(
            retention_now(dir, who),
            604_800,
            "PRODUCT: {who}: a refused change must change nothing"
        );
    }

    // ---- ...but may keep less, on their own node only -------------------------------------
    let (ok, said) = set_retention(&bob, &room, "30");
    println!(
        "R7: bob (not the admin) set 30 s for himself: ok={ok} — {}",
        said.trim()
    );
    assert!(
        ok && said.contains("set your own retention"),
        "PRODUCT: a member who is not the admin may set a retention below the room's for their \
         own node, and must be told it is their own: ok={ok}, {said}"
    );
    until_retention(&bob, "PRODUCT", "bob", 30, 30);
    for (dir, who) in [(&alice, "alice"), (&carol, "carol")] {
        assert_eq!(
            retention_now(dir, who),
            604_800,
            "PRODUCT: {who}: bob's own retention must change nothing on {who}'s node"
        );
    }
    for i in 1..=3 {
        post(&alice, &room, &format!("mine {i}"));
    }
    until(
        &bob,
        &room,
        "PRODUCT (staging): bob to read alice's 3",
        60,
        |t| count(t, "mine ") == 3,
    );
    until(
        &bob,
        &room,
        "PRODUCT: bob's own 30 s must take the 3 from bob's node",
        90,
        |t| count(t, "mine ") == 0,
    );
    for (dir, who) in [(&alice, "alice"), (&carol, "carol")] {
        let t = read(dir, &room);
        println!(
            "R7: after bob's own 30 s took them on his node, {who} still reads {} of 3",
            count(&t, "mine ")
        );
        assert_eq!(
            count(&t, "mine "),
            3,
            "PRODUCT: bob's own retention governs only bob's copy: {who} must still read all 3"
        );
    }
    // bob asks for the room's own week: that is "follow the room", which clears his own value,
    // so the admin's later changes reach his node too (checked at "forever" below).
    let (ok, said) = set_retention(&bob, &room, "1w");
    assert!(
        ok && said.contains("follow the room's retention"),
        "PRODUCT: a member asking for the room's own value follows the room again, and is told \
         so: ok={ok}, {said}"
    );
    until_retention(&bob, "PRODUCT", "bob", 604_800, 30);

    // ---- messages, then the admin shortens it: it reaches what is already held -----------
    for i in 1..=10 {
        post(&alice, &room, &format!("old {i}"));
    }
    std::thread::sleep(Duration::from_secs(45));
    for i in 1..=5 {
        post(&alice, &room, &format!("new {i}"));
    }
    for (dir, who) in members {
        until(
            dir,
            &room,
            &format!("PRODUCT (staging): {who} to read all 15"),
            60,
            |t| count(t, "old ") == 10 && count(t, "new ") == 5,
        );
    }
    let (ok, said) = set_retention(&alice, &room, "30");
    assert!(ok, "PRODUCT: the admin shortens to 30 s: {said}");
    let changed = Instant::now();
    // The whole of what each member reads, not a count by prefix: exactly the five newer
    // messages, and nothing expired in any form — no older message, no probe, no other row.
    let newer: Vec<String> = (1..=5).map(|i| format!("new {i}")).collect();
    let only_newer = |t: &[String]| {
        let mut t = t.to_vec();
        t.sort();
        t == newer
    };
    for (dir, who) in members {
        until(
            dir,
            &room,
            &format!("PRODUCT: {who} must show only the 5 newer once the admin shortened to 30 s"),
            20,
            |t| only_newer(t),
        );
        println!(
            "R7: shortened to 30 s — {who}'s whole `room read` is the 5 newer and nothing else \
             (0 of 10 older, 0 probes; {} ms after the change)",
            changed.elapsed().as_millis()
        );
    }

    // ---- and lengthens it again: what is left stays --------------------------------------
    let (ok, said) = set_retention(&alice, &room, "forever");
    assert!(ok, "PRODUCT: the admin sets forever: {said}");
    for (dir, who) in [(&alice, "alice"), (&bob, "bob")] {
        until_retention(dir, "PRODUCT", who, 0, 30);
    }
    // carol's file asks for 60 days. Above every value the room had, it was ignored; below
    // forever, it is the shorter, and it governs her node (a node keeps less than its room).
    until_retention(&carol, "PRODUCT", "carol", 5_184_000, 30);
    std::thread::sleep(Duration::from_secs(40));
    for (dir, who) in members {
        let t = read(dir, &room);
        println!(
            "R7: forever again, 40 s later (past the old 30 s) — {who} reads {} rows, {} of 5 \
             newer",
            t.len(),
            count(&t, "new ")
        );
        assert!(
            only_newer(&t),
            "PRODUCT: {who}: lengthened, what is left must stay, and only it: {t:?}"
        );
    }
}

/// Open `dir`'s profile — its daemon must be stopped — and return its signer, plus an endpoint
/// bound as that identity.
async fn as_member(
    dir: &Path,
) -> (
    Arc<vox_core::atrest::vault::VaultRootSigner>,
    vox_core::transport::quic::VoxEndpoint,
    vox_core::node::profile::Profile,
) {
    let paths = vox_core::node::paths::Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
        .expect("APPARATUS: the author's profile paths");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut profile = loop {
        match vox_core::node::profile::Profile::open(paths.clone()) {
            Ok(p) => break p,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("CANNOT MEASURE: the author's stopped profile did not open: {e:?}"),
        }
    };
    profile
        .unlock(IDENTITY.as_bytes())
        .expect("CANNOT MEASURE: the author's identity did not unlock");
    let signer = profile
        .signer_arc()
        .expect("CANNOT MEASURE: the author's signer");
    let ep = vox_core::transport::quic::VoxEndpoint::bind(
        &*signer,
        "127.0.0.1:0".parse().expect("APPARATUS: an address"),
    )
    .expect("CANNOT MEASURE: the author's endpoint did not bind");
    (signer, ep, profile)
}

/// As the room's author (whose node is stopped), connect to `victim` at `victim_at`, read the
/// entry the victim holds at `seq` of the author's feed — waiting, up to 60 s, until whether it
/// still carries its signature is `expect_signed` (a checkpoint takes time to reach it) — and
/// **offer** the victim a second entry for that position, signed by the author, as the head of
/// the author's feed. The victim asks for it because that head differs from its own (V210-63);
/// an entry it did not ask for it would refuse as a protocol violation (ADR-025 P9) before its
/// log saw it. Returns `(seq, was the held entry's body pruned, was it still signed, how many
/// offered entries the victim asked for, how the session ended)`.
fn equivocate(
    author: &Path,
    author_id: vox_core::hash::Digest32,
    victim_id: vox_core::hash::Digest32,
    victim_at: &str,
    channel_id: vox_core::hash::Digest32,
    seq: Option<u64>,
    expect_signed: bool,
) -> (u64, bool, bool, usize, Option<String>) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: the author client's runtime");
    rt.block_on(async {
        let (signer, ep, profile) = as_member(author).await;
        let conn = ep
            .connect(
                victim_at.parse().expect("APPARATUS: the victim's address"),
                victim_id,
                raw_sync::now(),
            )
            .await
            .expect("CANNOT MEASURE: the author's client could not connect to the victim");
        // Where: a fixed position, or, if none is given, five below the author's head.
        let mut have = None;
        for _ in 0..40 {
            let y = raw_sync::ask(&conn, channel_id, 0, Ask::Ranges(vec![]), None).await;
            if y.hello {
                have = y
                    .have
                    .iter()
                    .find(|(a, _)| *a == author_id)
                    .map(|(_, m)| *m);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let head = have
            .expect("CANNOT MEASURE: no answered session listed the author's feed on the victim");
        let seq = seq.unwrap_or(head - 4);
        let waiting = Instant::now();
        let held = loop {
            let mut held = None;
            for _ in 0..40 {
                let y = raw_sync::ask(
                    &conn,
                    channel_id,
                    0,
                    Ask::Ranges(vec![WantRange {
                        author_id,
                        from_seq: seq,
                        to_seq: seq,
                    }]),
                    None,
                )
                .await;
                if y.hello {
                    held = y.wires.first().cloned();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            let held = Entry::from_wire(&held.expect(
                "CANNOT MEASURE: no answered session served the victim's entry at that position",
            ))
            .expect("PRODUCT (staging): the victim served a malformed entry");
            if held.is_signed() == expect_signed || waiting.elapsed() > Duration::from_secs(60) {
                break held;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        let pruned = held.payload.is_none();
        let signed = held.is_signed();
        println!(
            "R10: bob's entry at seq {seq} read signed={signed} after {:?} (waited for \
             signed={expect_signed})",
            waiting.elapsed()
        );
        // The same position, a different body: an equivocation only the author could sign.
        let mut sk = held.skeleton.clone();
        let body = format!("a conflicting entry for seq {seq}");
        sk.payload_hash = vox_core::hash::sha256(body.as_bytes());
        sk.payload_len = body.len() as u64;
        let conflicting = Entry::build_signed_skeleton_only(&*signer, sk)
            .expect("APPARATUS: sign the conflicting entry");
        let head = vox_core::log::sync::FeedFrontier {
            author_id,
            max_seq: seq,
            head_hash: conflicting.entry_hash(),
        };
        let mut ended = Some("never answered".to_owned());
        let mut served = 0;
        for _ in 0..40 {
            let y = raw_sync::ask_offering(
                &conn,
                channel_id,
                0,
                Ask::Ranges(vec![]),
                vec![(head, conflicting.to_wire())],
            )
            .await;
            if y.hello {
                ended = y.ended;
                served = y.served;
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        drop(conn);
        drop(ep);
        drop(profile);
        (seq, pruned, signed, served, ended)
    })
}

#[test]
#[ignore = "real vox daemons and real seconds (about three minutes); CI runs it in release"]
fn r10_an_expired_entrys_skeleton_still_catches_a_fork() {
    watchdog::arm();
    let t = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let (alice, alice_fp) = identity(t.path(), "alice");
    let (bob, bob_fp) = identity(t.path(), "bob");
    let (carol, carol_fp) = identity(t.path(), "carol");
    let bob_at = free_port();
    let mut alice_d = Some(daemon(
        &alice,
        "alice",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &[],
    ));
    let _b = daemon(&bob, "bob", &format!("{IDENTITY}\n"), &bob_at, &[]);
    let _c = daemon(
        &carol,
        "carol",
        &format!("{IDENTITY}\n"),
        "127.0.0.1:0",
        &[],
    );
    let room = create(&alice);
    join(&alice, &bob, &room);
    join(&alice, &carol, &room);
    trust(&alice, &bob_fp, "bob");
    trust(&alice, &carol_fp, "carol");
    // Trust runs one way (V210-161): bob and carol read alice only once they trust her too.
    trust(&bob, &alice_fp, "alice");
    trust(&carol, &alice_fp, "alice");
    until_readable(&alice, &[&bob, &carol], &room);
    let (ok, said) = set_retention(&alice, &room, "20");
    assert!(ok, "PRODUCT (staging): the admin sets 20 s: {said}");
    until_retention(&bob, "PRODUCT (staging)", "bob", 20, 30);
    let decode = |s: &str| {
        vox_core::node::link::b32_decode(s, "fingerprint")
            .unwrap_or_else(|e| panic!("PRODUCT (staging): vox printed no id in {s:?}: {e:?}"))
    };
    let (alice_id, bob_id) = (decode(&alice_fp), decode(&bob_fp));
    let channel_id = decode(
        status(&alice)["rooms"][0]["id"]
            .as_str()
            .expect("PRODUCT (staging): `vox status --json` names the room's id"),
    );

    // ---- below the author's checkpoint: refused as pre-checkpoint, not a fork -------------
    // 40 expire — past the 32 that make alice post a checkpoint of her own feed.
    for i in 1..=40 {
        post(&alice, &room, &format!("a {i}"));
    }
    until(
        &bob,
        &room,
        "PRODUCT (staging): bob to read the 40",
        60,
        |t| count(t, "a ") == 40,
    );
    until(
        &bob,
        &room,
        "PRODUCT (staging): the 40 to expire on bob",
        60,
        |t| count(t, "a ") == 0,
    );
    std::thread::sleep(Duration::from_secs(15)); // alice's checkpoint reaches bob
    let (frozen, refused) = fork_watch(&bob, 30, |_, _| true);
    println!("R10: before — bob has frozen {frozen:?} and refused {refused} below a checkpoint");
    assert!(
        frozen.is_empty() && refused == 0,
        "PRODUCT (staging): nothing has been caught yet: frozen {frozen:?}, refused {refused}"
    );
    // Alice's node is stopped so the conflicting entry is signed with her own key, and started
    // again after: it finds bob and carol at the addresses it last reached them on.
    drop(alice_d.take());
    let (seq, pruned, signed, served, ended) = equivocate(
        &alice,
        alice_id,
        bob_id,
        &bob_at,
        channel_id,
        Some(5),
        false,
    );
    alice_d = Some(daemon(
        &alice,
        "alice-2",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        "127.0.0.1:0",
        &[],
    ));
    println!(
        "R10: below the checkpoint — bob held seq {seq} pruned={pruned} signed={signed}; the \
         conflicting entry was asked for {served} time(s); its session ended {ended:?}"
    );
    assert!(
        pruned,
        "PRODUCT (staging): the position must be expired (its body pruned) on bob"
    );
    assert!(
        !signed,
        "PRODUCT (staging): below the checkpoint bob must have shed the signature (ADR-023 \
         decision 3)"
    );
    // **The refusal itself, not the absence of a freeze.** A conflicting entry at a position whose
    // held side has shed its signature cannot freeze anyone in any case — it cannot incriminate —
    // so "bob still reads alice" is what both a refusal and a fork that proves nothing look like.
    // Only bob's count of entries refused below a checkpoint tells them apart.
    assert_eq!(
        served, 1,
        "PRODUCT: bob must ask for the conflicting entry offered as alice's head, once (V210-63): \
         otherwise nothing reached his log to refuse"
    );
    assert!(
        ended.is_none(),
        "PRODUCT: a refused entry does not end the session (ADR-008): {ended:?}"
    );
    let (frozen, refused) = fork_watch(&bob, 30, |_, n| n > 0);
    println!(
        "R10: below the checkpoint — bob refused {refused} entry as at or below alice's \
         checkpoint, and has frozen {frozen:?}"
    );
    assert_eq!(
        (refused, frozen.len()),
        (1, 0),
        "PRODUCT: the conflicting entry must be refused as older than alice's checkpoint (ADR-023 \
         decision 3), exactly once, and freeze nobody"
    );
    post(&alice, &room, "after-1");
    until(
        &bob,
        &room,
        "PRODUCT: bob must read alice's next post (she is not frozen)",
        90,
        |t| t.iter().any(|x| x == "after-1"),
    );
    println!(
        "R10: below the checkpoint the conflict was refused, not a fork: bob still reads alice"
    );

    // ---- above it: an expired position's skeleton catches the fork ------------------------
    for i in 1..=10 {
        post(&alice, &room, &format!("b {i}"));
    }
    until(
        &bob,
        &room,
        "PRODUCT (staging): bob to read the 10",
        60,
        |t| count(t, "b ") == 10,
    );
    until(
        &bob,
        &room,
        "PRODUCT (staging): the 10 to expire on bob",
        60,
        |t| count(t, "b ") == 0,
    );
    drop(alice_d.take());
    let (seq, pruned, signed, served, ended) =
        equivocate(&alice, alice_id, bob_id, &bob_at, channel_id, None, true);
    let _a = daemon(
        &alice,
        "alice-3",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        "127.0.0.1:0",
        &[],
    );
    println!(
        "R10: above the checkpoint — bob held seq {seq} pruned={pruned} signed={signed}; the \
         conflicting entry was asked for {served} time(s); its session ended {ended:?}"
    );
    assert!(
        pruned,
        "PRODUCT (staging): the position must be expired (its body pruned) on bob"
    );
    assert!(
        signed,
        "PRODUCT (staging): above the checkpoint the expired skeleton keeps its signature"
    );
    assert_eq!(
        served, 1,
        "PRODUCT: bob must ask for the conflicting entry offered as alice's head, once (V210-63)"
    );
    assert!(
        ended.is_none(),
        "PRODUCT: a fork does not end the session (ADR-008): {ended:?}"
    );
    let (frozen, refused) = fork_watch(&bob, 30, |f, _| !f.is_empty());
    println!(
        "R10: above the checkpoint — bob has frozen {frozen:?} (alice is {alice_fp}), refused \
         {refused} below a checkpoint"
    );
    assert_eq!(
        (frozen, refused),
        (vec![alice_fp.clone()], 1),
        "PRODUCT: the conflicting entry at an expired position must freeze alice as a fork, not \
         be refused as pre-checkpoint"
    );
    post(&alice, &room, "after-2");
    until(
        &carol,
        &room,
        "PRODUCT (staging): carol (who saw no fork) to read alice's next post",
        90,
        |t| t.iter().any(|x| x == "after-2"),
    );
    std::thread::sleep(Duration::from_secs(15));
    let b = read(&bob, &room);
    println!(
        "R10: carol reads after-2; bob, who saw the fork, reads it {} times (0 = alice frozen)",
        b.iter().filter(|x| *x == "after-2").count()
    );
    assert!(
        !b.iter().any(|x| x == "after-2"),
        "PRODUCT: a conflicting entry at an expired position must be caught as a fork and its \
         author frozen: bob still accepts alice's posts"
    );
}
