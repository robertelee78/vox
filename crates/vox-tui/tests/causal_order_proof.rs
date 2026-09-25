//! ADR-023 M23.2 / PRD-001 R13 — one order on every node, driven through the **shipped `vox`
//! binary**.
//!
//! Each entry's signed skeleton names the heads of the other authors' feeds its author had
//! applied (`seen`) and the author's clock (`claimed_ms`). The room's order is a hybrid logical
//! clock over that DAG, ties broken by `(claimed ms, entry hash)`, so it is a function of the
//! entry set alone: every node that holds the same entries shows them in the same sequence,
//! whatever order they arrived in.
//!
//! **Proof 1 (same order):** three real daemons. All three post at once; one goes offline while
//! the other two keep posting; it comes back and all three post at once again. After
//! convergence, `vox room read --hashes` (every entry the node holds, readable or not) prints
//! the identical sequence on all three — its length and SHA-256 are printed per node — and each
//! node's `vox room read` timeline is that sequence restricted to the rows it can read, in the
//! same relative order.
//!
//! **Proof 2 (causal):** the replier's clock is an hour behind (the test-only
//! `VOX_TEST_CLOCK_SKEW_MS`, read by the shipped binary's millisecond clock). A member posts a
//! question; the replier reads it and answers. On every node the answer is ordered after the
//! question — although its claimed time is an hour earlier, which the gate reads back from the
//! replier's own store so the skew is proven to have reached the entry.
//!
//! **Proof 3 (a clock far ahead):** a member's clock is a day ahead. It posts; another member
//! reads that post and then writes. The later post names the day-ahead one in `seen`, so without a
//! cap it would be placed a day in the future, and so would everything after it. The gate reads
//! each entry's placing clock from `vox room read --hashes`. It asserts the later post is placed
//! less than 15 minutes ahead of when it was written, still after what it saw. It also reads the
//! day-ahead claim back from the author's store.
//!
//! Mutations (each run, each red): `seen` ignored when ordering (proof 2); the cap removed
//! (proof 3). Arrival order is the in-process gate's mutation (`one_order_gate`).
//!
//! **Proof 1 is intermittently red on v0.2.8, and not for the order.** In about half of runs the
//! second joiner of three daemons is cut off from the first post onward: 5 red of 9 with M23.2,
//! and 1 of 4 on 3cac220 without it, with the same signature. In each of the four reds whose logs were captured, the second joiner's
//! restarted daemon logs "the board holds a newer record from that author". Whenever the three
//! converged, their orders were identical (e.g. 58/58/58 entries, one SHA-256). CI skips it by name
//! with this cause (release.yml, ci.yml). The order is proven in the blocking set by
//! `crates/vox-core/tests/one_order_gate.rs` and by proofs 2 and 3.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// Messages each poster writes per round.
const PER_ROUND: usize = 6;
/// An hour, in milliseconds, behind.
const HOUR_BEHIND: i64 = -3_600_000;
/// A day, in milliseconds, ahead.
const DAY_AHEAD: i64 = 86_400_000;

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    /// Kill it by its PID now, in place, and report whether it is gone (reaped).
    fn kill_now(&mut self) -> bool {
        let _ = self.0.kill();
        let _ = self.0.wait();
        matches!(self.0.try_wait(), Ok(Some(_)))
    }

    /// Send it a signal by its PID (`-STOP` freezes it, `-CONT` thaws it).
    fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.0.id().to_string()])
            .status()
            .is_ok_and(|s| s.success());
        assert!(ok, "kill {sig} {} failed", self.0.id());
    }

    /// Kill it by its PID and report whether it is gone (reaped): the check that nothing
    /// was left running.
    fn stop(mut self) -> bool {
        let _ = self.0.kill();
        let _ = self.0.wait();
        matches!(self.0.try_wait(), Ok(Some(_)))
    }
}

/// Stop every daemon and assert none is left running.
fn stop_all(daemons: Vec<Daemon>) {
    let n = daemons.len();
    let gone = daemons.into_iter().map(Daemon::stop).filter(|g| *g).count();
    println!(
        "{gone} of {n} daemons stopped by PID; {} left running",
        n - gone
    );
    assert_eq!(gone, n, "a daemon outlived its test");
}

/// The claimed times of `question` and `answer` (entry hashes as `vox` prints them) as stored
/// in a **stopped** node's own copy of the room — read back so the gate knows the skew reached
/// the signed entry rather than assuming it did.
fn claimed_times(dir: &Path, question: &str, answer: &str) -> (u64, u64) {
    let paths = vox_core::node::paths::Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut profile = loop {
        match vox_core::node::profile::Profile::open(paths.clone()) {
            Ok(p) => break p,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => panic!("the store did not open: {e:?}"),
        }
    };
    profile.unlock(IDENTITY.as_bytes()).expect("unlock");
    let cid = profile.store().channels().unwrap()[0];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ch = vox_core::node::channel::ChannelState::open(&profile, &cid, ROOMPASS.as_bytes(), now)
        .expect("open the room");
    let find = |h: &str| {
        ch.timeline()
            .iter()
            .find(|r| vox_core::node::link::b32_encode(&r.entry_hash) == h)
            .unwrap_or_else(|| panic!("the stopped store lacks {h}"))
            .created_millis
    };
    (find(question), find(answer))
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
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` on `dir` at `listen`, optionally with its millisecond clock skewed
/// (test-only).
fn daemon(dir: &Path, tag: &str, listen: &str, stdin_lines: &str, skew_ms: Option<i64>) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut cmd = Command::new(VOX);
    cmd.args(["daemon", "--listen", listen])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .env_remove(vox_core::time::TEST_CLOCK_SKEW_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    if let Some(skew) = skew_ms {
        cmd.env(vox_core::time::TEST_CLOCK_SKEW_ENV, skew.to_string());
    }
    let mut child = cmd.spawn().expect("spawn vox daemon");
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(stdin_lines.as_bytes()).unwrap();
    drop(pipe);
    Daemon(child)
}

/// `vox room list` once the daemon's socket answers.
fn attached(dir: &Path, tag: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (ok, out, err) = vox(dir, &["room", "list"], None);
        if ok {
            return out;
        }
        last = err;
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "{tag}'s daemon never answered: {last}\nits stderr: {}",
        std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
    );
}

/// `vox room read`: `(entry hash, text)` per row, in the order printed.
fn read(dir: &Path, room: &str) -> Vec<(String, String)> {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    assert!(ok, "vox room read: {err}");
    // `<entry-hash> <author-prefix> <text>`
    out.lines()
        .filter_map(|l| {
            let mut parts = l.splitn(3, ' ');
            let hash = parts.next()?.to_owned();
            let text = parts.nth(1)?.to_owned();
            Some((hash, text))
        })
        .collect()
}

/// `vox room read --hashes`: every entry the node holds, in the room's order.
fn order(dir: &Path, room: &str) -> Vec<String> {
    order_clocks(dir, room)
        .into_iter()
        .map(|(h, _)| h)
        .collect()
}

/// `vox room read --hashes` with the clock that placed each entry: `(hash, clock ms)`.
fn order_clocks(dir: &Path, room: &str) -> Vec<(String, u64)> {
    let (ok, out, err) = vox(dir, &["room", "read", room, "--hashes"], None);
    assert!(ok, "vox room read --hashes: {err}");
    out.lines()
        .map(|l| {
            let (h, c) = l.split_once(' ').expect("`<hash> <clock>`");
            (h.to_owned(), c.parse().expect("a clock"))
        })
        .collect()
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn texts(rows: &[(String, String)]) -> Vec<&str> {
    rows.iter().map(|(_, t)| t.as_str()).collect()
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(ok, "vox room post {text:?}: {err}");
}

/// Fresh profiles that all trust each other.
fn members(tmp: &Path, names: &[&str]) -> Vec<PathBuf> {
    let dirs: Vec<PathBuf> = names.iter().map(|n| tmp.join(n)).collect();
    let mut fps = Vec::new();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    for (i, d) in dirs.iter().enumerate() {
        for (j, fp) in fps.iter().enumerate() {
            if i != j {
                let name = format!("peer{j}");
                let (ok, _, err) = vox(d, &["trust", "add", fp, "--name", &name], None);
                assert!(ok, "vox trust add: {err}");
            }
        }
    }
    dirs
}

/// `creator` makes a room and every joiner joins; returns the room id as `vox` prints it once
/// every joiner reads the creator.
fn room(creator: &Path, joiners: &[&Path]) -> String {
    let (ok, _, err) = vox(
        creator,
        &["room", "create", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let room = attached(creator, "creator")
        .split_whitespace()
        .next()
        .expect("a room id")
        .to_owned();
    for joiner in joiners {
        let (ok, link, err) = vox(creator, &["room", "invite", &room], None);
        assert!(ok, "vox room invite: {err}");
        let (ok, _, err) = vox(
            joiner,
            &["room", "join", link.trim(), "--name", "r"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "vox room join: {err}");
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        post(creator, &room, "probe");
        std::thread::sleep(Duration::from_millis(500));
        if joiners
            .iter()
            .all(|j| texts(&read(j, &room)).contains(&"probe"))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the joiners never read the creator"
        );
    }
    room
}

/// Every poster writes [`PER_ROUND`] messages `"<round> <who> <i>"` at the same time.
fn round(room: &str, round: &str, posters: &[(&Path, &str)]) {
    std::thread::scope(|s| {
        for (dir, who) in posters {
            s.spawn(move || {
                for i in 1..=PER_ROUND {
                    post(dir, room, &format!("{round} {who} {i}"));
                }
            });
        }
    });
}

/// Poll until every node holds the same entry set (as a set: the order is what is being
/// measured, so it cannot be the stopping condition) and `done` holds. Returns each node's
/// `--hashes` sequence from one read.
fn converge(
    nodes: &[(&Path, &str)],
    room: &str,
    what: &str,
    secs: u64,
    done: impl Fn(&[Vec<String>]) -> bool,
) -> Vec<Vec<String>> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut stable = 0usize;
    loop {
        let orders: Vec<Vec<String>> = nodes.iter().map(|(d, _)| order(d, room)).collect();
        let sets: Vec<BTreeSet<&String>> = orders.iter().map(|o| o.iter().collect()).collect();
        if sets.windows(2).all(|w| w[0] == w[1]) && done(&orders) {
            // Twice in a row, so a sync landing between the reads cannot pass half a state.
            stable += 1;
            if stable == 2 {
                return orders;
            }
        } else {
            stable = 0;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}; entries held: {}\n{}",
            nodes
                .iter()
                .zip(&orders)
                .map(|((_, who), o)| format!("{who} {}", o.len()))
                .collect::<Vec<_>>()
                .join(", "),
            daemon_logs(nodes)
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Every daemon's stderr for these nodes, so a red that is not about the order says what the
/// daemons saw.
fn daemon_logs(nodes: &[(&Path, &str)]) -> String {
    let mut out = String::new();
    for (dir, who) in nodes {
        let mut logs: Vec<PathBuf> = std::fs::read_dir(dir)
            .map(|d| d.filter_map(|e| e.ok().map(|e| e.path())).collect())
            .unwrap_or_default();
        logs.retain(|p| p.extension().is_some_and(|x| x == "err"));
        logs.sort();
        for p in logs {
            let name = p
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            out.push_str(&format!("--- {who} {name} ---\n{text}"));
        }
    }
    out
}

fn digest(seq: &[String]) -> String {
    let joined = seq.join("\n");
    vox_core::hash::sha256(joined.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Assert `rows` (a node's timeline) is `seq` restricted to those rows, in the same relative
/// order. Returns how many rows it checked.
fn is_ordered_subsequence(who: &str, rows: &[(String, String)], seq: &[String]) -> usize {
    let position = |h: &String| seq.iter().position(|x| x == h);
    let mut last = None;
    for (h, text) in rows {
        let at = position(h)
            .unwrap_or_else(|| panic!("{who}'s timeline shows {text:?}, which it does not hold"));
        assert!(
            last.is_none_or(|l| l < at),
            "{who}'s timeline shows {text:?} out of the room's order (at {at}, after {last:?})"
        );
        last = Some(at);
    }
    rows.len()
}

#[test]
#[ignore = "three real vox daemons (about two minutes); intermittently red on v0.2.8 for a cause \
            below the log (module docs); CI skips it by name"]
fn three_members_one_offline_for_a_while_show_one_order() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs = members(tmp.path(), &["alice", "bob", "carol"]);
    let (alice, bob, carol) = (&dirs[0], &dirs[1], &dirs[2]);
    let alice_d = daemon(
        alice,
        "alice",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        None,
    );
    attached(alice, "alice");
    let bob_d = daemon(bob, "bob", "127.0.0.1:0", &format!("{IDENTITY}\n"), None);
    attached(bob, "bob");
    // Carol goes down and comes back on whatever port she gets, as a person's restarted node
    // does: finding her again is part of converging.
    let carol_d = daemon(
        carol,
        "carol",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        None,
    );
    attached(carol, "carol");
    let room = room(alice, &[bob, carol]);
    let nodes = [
        (alice.as_path(), "alice"),
        (bob.as_path(), "bob"),
        (carol.as_path(), "carol"),
    ];
    // All three hold one entry set before anything is measured.
    let settled = Instant::now();
    let before = converge(&nodes, &room, "the three to hold the joins", 120, |_| true);
    println!(
        "before posting: {} entries on every node, {} ms to settle",
        before[0].len(),
        settled.elapsed().as_millis()
    );

    // ---- all three at once --------------------------------------------------------------
    round(
        &room,
        "one",
        &[(alice, "alice"), (bob, "bob"), (carol, "carol")],
    );
    // ---- carol goes offline; the other two keep going --------------------------------------
    drop(carol_d);
    round(&room, "two", &[(alice, "alice"), (bob, "bob")]);
    // ---- carol comes back and posts straight away, while all three post at once -------------
    let carol_d = daemon(
        carol,
        "carol-2",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        None,
    );
    attached(carol, "carol");
    round(
        &room,
        "three",
        &[(alice, "alice"), (bob, "bob"), (carol, "carol")],
    );
    let posted = PER_ROUND * 8;
    // Converged: one entry set everywhere, and alice (who reads everyone) shows every post.
    let orders = converge(&nodes, &room, "the three to converge", 180, |_| {
        let t = read(alice, &room);
        texts(&t)
            .iter()
            .filter(|x| x.starts_with("one ") || x.starts_with("two ") || x.starts_with("three "))
            .count()
            == posted
    });

    for ((_, who), o) in nodes.iter().zip(&orders) {
        println!("{who}: {} entries, order sha256 {}", o.len(), digest(o));
    }
    for ((_, who), o) in nodes.iter().zip(&orders).skip(1) {
        if *o != orders[0] {
            let first = o.iter().zip(&orders[0]).position(|(a, b)| a != b);
            panic!(
                "{who}'s order differs from alice's ({} vs {} entries, first difference at \
                 {first:?}) — the room shows two orders",
                o.len(),
                orders[0].len()
            );
        }
    }
    // Each timeline is that order, restricted to what the node can read.
    for (dir, who) in &nodes {
        let rows = read(dir, &room);
        let checked = is_ordered_subsequence(who, &rows, &orders[0]);
        println!("{who}: its {checked} readable rows are in the room's order");
    }
    assert!(
        orders[0].len() >= posted,
        "the order holds {} entries for {posted} posts",
        orders[0].len()
    );
    stop_all(vec![alice_d, bob_d, carol_d]);
}

#[test]
#[ignore = "three real vox daemons (about a minute); CI runs it in release"]
fn a_reply_follows_what_it_answered_even_from_a_clock_an_hour_behind() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs = members(tmp.path(), &["alice", "bob", "carol"]);
    let (alice, bob, carol) = (&dirs[0], &dirs[1], &dirs[2]);
    let alice_d = daemon(
        alice,
        "alice",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        None,
    );
    attached(alice, "alice");
    // Bob's clock is an hour behind.
    let bob_d = daemon(
        bob,
        "bob",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        Some(HOUR_BEHIND),
    );
    attached(bob, "bob");
    let carol_d = daemon(
        carol,
        "carol",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        None,
    );
    attached(carol, "carol");
    let room = room(alice, &[bob, carol]);

    post(alice, &room, "question");
    let deadline = Instant::now() + Duration::from_secs(60);
    while !texts(&read(bob, &room)).contains(&"question") {
        assert!(Instant::now() < deadline, "bob never read the question");
        std::thread::sleep(Duration::from_millis(200));
    }
    post(bob, &room, "answer");

    let nodes = [
        (alice.as_path(), "alice"),
        (bob.as_path(), "bob"),
        (carol.as_path(), "carol"),
    ];
    let q = read(alice, &room)
        .into_iter()
        .find(|(_, t)| t == "question")
        .expect("alice shows her question")
        .0;
    let a = read(bob, &room)
        .into_iter()
        .find(|(_, t)| t == "answer")
        .expect("bob shows his answer")
        .0;
    let orders = converge(&nodes, &room, "the answer to reach everyone", 90, |o| {
        o.iter().all(|seq| seq.contains(&a) && seq.contains(&q))
    });
    for ((dir, who), seq) in nodes.iter().zip(&orders) {
        let qi = seq.iter().position(|h| *h == q).unwrap();
        let ai = seq.iter().position(|h| *h == a).unwrap();
        println!(
            "{who}: question at {qi}, answer at {ai} of {} (sha256 {})",
            seq.len(),
            digest(seq)
        );
        assert!(
            qi < ai,
            "{who} orders the answer ({ai}) before the question it answered ({qi})"
        );
        // Where the node reads both, its timeline shows them in that order too.
        let rows = read(dir, &room);
        let rq = rows.iter().position(|(h, _)| *h == q);
        let ra = rows.iter().position(|(h, _)| *h == a);
        if let (Some(rq), Some(ra)) = (rq, ra) {
            println!("{who}: timeline shows the question at {rq}, the answer at {ra}");
            assert!(rq < ra, "{who}'s timeline shows the answer first");
        }
    }

    // The skew really reached the entry: read bob's own store, stopped, for both claimed times.
    stop_all(vec![bob_d]);
    let (q_ms, a_ms) = claimed_times(bob, &q, &a);
    println!(
        "bob's store: the answer claims {} ms, the question {} ms: {} min earlier",
        a_ms,
        q_ms,
        (q_ms as i64 - a_ms as i64) / 60_000
    );
    assert!(
        a_ms + 30 * 60_000 < q_ms,
        "the answer's claimed time ({a_ms}) is not well behind the question's ({q_ms}): the \
         skew did not reach the entry, so this run proved nothing about clocks"
    );
    stop_all(vec![alice_d, carol_d]);
}

#[test]
#[ignore = "two real vox daemons (about a minute); CI runs it in release"]
fn a_post_from_a_clock_a_day_ahead_does_not_drag_the_room_a_day_forward() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs = members(tmp.path(), &["alice", "bob"]);
    let (alice, bob) = (&dirs[0], &dirs[1]);
    let alice_d = daemon(
        alice,
        "alice",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        None,
    );
    attached(alice, "alice");
    // Bob's clock is a day ahead.
    let bob_d = daemon(
        bob,
        "bob",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        Some(DAY_AHEAD),
    );
    attached(bob, "bob");
    let room = room(alice, &[bob]);

    post(bob, &room, "from tomorrow");
    let deadline = Instant::now() + Duration::from_secs(60);
    let tomorrow = loop {
        if let Some((h, _)) = read(alice, &room)
            .into_iter()
            .find(|(_, t)| t == "from tomorrow")
        {
            break h;
        }
        assert!(Instant::now() < deadline, "alice never read bob's post");
        std::thread::sleep(Duration::from_millis(200));
    };
    // Alice has seen it; what she writes next names it in `seen`.
    let posted_at = now_ms();
    post(alice, &room, "after it");
    let after = read(alice, &room)
        .into_iter()
        .find(|(_, t)| t == "after it")
        .expect("alice shows her post")
        .0;
    let deadline = Instant::now() + Duration::from_secs(60);
    let clocks = loop {
        let a = order_clocks(alice, &room);
        let b = order_clocks(bob, &room);
        if b.iter().any(|(h, _)| *h == after) {
            break [("alice", a), ("bob", b)];
        }
        assert!(Instant::now() < deadline, "bob never received alice's post");
        std::thread::sleep(Duration::from_millis(200));
    };
    let minutes = |ms: u64| (ms as i64 - posted_at as i64) / 60_000;
    for (who, seq) in &clocks {
        let ti = seq.iter().position(|(h, _)| *h == tomorrow).unwrap();
        let ai = seq.iter().position(|(h, _)| *h == after).unwrap();
        let (t_clock, a_clock) = (seq[ti].1, seq[ai].1);
        println!(
            "{who}: `from tomorrow` placed at {} min from now, `after it` at {} min (positions \
             {ti} and {ai} of {})",
            minutes(t_clock),
            minutes(a_clock),
            seq.len()
        );
        assert!(ti < ai, "{who}: the post that saw it must still follow it");
        assert!(
            a_clock < posted_at + 15 * 60_000,
            "{who}: a post written after seeing a day-ahead post was placed {} min ahead of \
             when it was written — one member dragged the room's clock forward",
            minutes(a_clock)
        );
    }

    // The skew really reached the entry: bob's stored claimed time is a day ahead.
    stop_all(vec![bob_d]);
    let (t_ms, a_ms) = claimed_times(bob, &tomorrow, &after);
    println!(
        "bob's store: `from tomorrow` claims {} min from when `after it` was written, `after it` \
         {} min",
        minutes(t_ms),
        minutes(a_ms)
    );
    assert!(
        t_ms > posted_at + 20 * 3_600_000,
        "`from tomorrow` does not claim a time a day ahead ({t_ms} vs {posted_at}): the skew \
         did not reach the entry, so this run proved nothing about clocks"
    );
    stop_all(vec![alice_d]);
}

/// `vox room read --late`: the texts of the rows marked late.
fn late(dir: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(dir, &["room", "read", room, "--late"], None);
    assert!(ok, "vox room read --late: {err}");
    out.lines()
        .filter_map(|l| l.splitn(3, ' ').nth(2).map(str::to_owned))
        .collect()
}

#[test]
#[ignore = "two real vox daemons (about a minute); CI runs it in release"]
fn a_late_arrival_is_marked_and_posts_that_cross_are_not() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs = members(tmp.path(), &["alice", "bob"]);
    let (alice, bob) = (&dirs[0], &dirs[1]);
    let alice_d = daemon(
        alice,
        "alice",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        None,
    );
    attached(alice, "alice");
    let bob_d = daemon(bob, "bob", "127.0.0.1:0", &format!("{IDENTITY}\n"), None);
    attached(bob, "bob");
    let room = room(alice, &[bob]);
    // Bob must read alice for the crossing posts to be counted on his side too.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        post(bob, &room, "bob probe");
        std::thread::sleep(Duration::from_millis(500));
        if texts(&read(alice, &room)).contains(&"bob probe") {
            break;
        }
        assert!(Instant::now() < deadline, "alice never read bob");
    }

    // ---- posts that cross in flight are ordinary concurrency: nothing is late -------------
    round(&room, "cross", &[(alice, "alice"), (bob, "bob")]);
    let deadline = Instant::now() + Duration::from_secs(60);
    for (dir, who) in [(alice, "alice"), (bob, "bob")] {
        while texts(&read(dir, &room))
            .iter()
            .filter(|t| t.starts_with("cross "))
            .count()
            < 2 * PER_ROUND
        {
            assert!(
                Instant::now() < deadline,
                "{who} never showed all crossing posts"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    for (dir, who) in [(alice, "alice"), (bob, "bob")] {
        let l = late(dir, &room);
        println!(
            "{who}: {} of {} crossing posts marked late",
            l.len(),
            2 * PER_ROUND
        );
        assert!(l.is_empty(), "{who} marks crossing posts late: {l:?}");
    }

    // ---- a post that did not get out at once is late when it does ------------------------
    // Bob posts and his daemon is frozen (SIGSTOP) straight away, before its push; retried if
    // the push won the race. It is thawed, not restarted, so the same node on the same address
    // delivers it: what arrives late is the post, not a different node.
    let mut attempt = 0;
    let away = loop {
        attempt += 1;
        assert!(
            attempt <= 5,
            "bob's post got out before his node froze, 5 times"
        );
        let text = format!("while away {attempt}");
        post(bob, &room, &text);
        bob_d.signal("-STOP");
        std::thread::sleep(Duration::from_secs(2));
        if !texts(&read(alice, &room)).contains(&text.as_str()) {
            break text;
        }
        bob_d.signal("-CONT");
    };
    for i in 1..=3 {
        post(alice, &room, &format!("meanwhile {i}"));
    }
    // What alice has now been shown for longer than the late threshold; under the transport's
    // 60 s idle limit, so the connection outlives the freeze.
    std::thread::sleep(Duration::from_secs(12));
    bob_d.signal("-CONT");
    let deadline = Instant::now() + Duration::from_secs(90);
    while !texts(&read(alice, &room)).contains(&away.as_str()) {
        assert!(
            Instant::now() < deadline,
            "alice never received {away:?}\n{}",
            daemon_logs(&[(alice.as_path(), "alice"), (bob.as_path(), "bob")])
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let shown = texts(&read(alice, &room))
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let at = shown.iter().position(|t| *t == away).unwrap();
    let meanwhile = shown.iter().position(|t| t == "meanwhile 1").unwrap();
    let l = late(alice, &room);
    println!(
        "alice: {away:?} at {at}, above \"meanwhile 1\" at {meanwhile}; marked late: {l:?} \
         (after {attempt} attempt(s))"
    );
    assert!(at < meanwhile, "the late post is not in its true place");
    assert_eq!(
        l,
        vec![away.clone()],
        "exactly the late post is marked late"
    );
    stop_all(vec![alice_d, bob_d]);
}

/// The other way a member goes offline: its node **restarts**. Bob posts and his daemon is killed
/// before its push; alice goes on; bob's daemon starts again (on a new port, as a restarted node
/// does) and delivers the post, which lands above what alice was already shown and is marked
/// late.
///
/// Red today for v0.2.9 V29-23 (#104), not for the order: the restarted daemon's board records
/// restart their sequence at 1, the board holds a newer one from before the restart, and nobody
/// can reach it at its new address (2 of 5 runs never delivered). It becomes a gate when that fix
/// lands; the frozen-daemon variant above carries the claim meanwhile.
#[test]
#[ignore = "red for v0.2.9 V29-23 (#104, a restarted daemon's board record is refused); CI skips it \
            by name until that fix lands"]
fn a_late_arrival_after_a_restart_is_marked() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs = members(tmp.path(), &["alice", "bob"]);
    let (alice, bob) = (&dirs[0], &dirs[1]);
    let alice_d = daemon(
        alice,
        "alice",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n"),
        None,
    );
    attached(alice, "alice");
    let mut bob_d = daemon(bob, "bob", "127.0.0.1:0", &format!("{IDENTITY}\n"), None);
    attached(bob, "bob");
    let room = room(alice, &[bob]);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        post(bob, &room, "bob probe");
        std::thread::sleep(Duration::from_millis(500));
        if texts(&read(alice, &room)).contains(&"bob probe") {
            break;
        }
        assert!(Instant::now() < deadline, "alice never read bob");
    }
    // Killed straight after posting, before the push; retried if the push won the race.
    let mut attempt = 0;
    let away = loop {
        attempt += 1;
        assert!(
            attempt <= 5,
            "bob's post got out before his node went down, 5 times"
        );
        let text = format!("while away {attempt}");
        post(bob, &room, &text);
        assert!(bob_d.kill_now(), "bob's daemon did not stop");
        std::thread::sleep(Duration::from_secs(2));
        if !texts(&read(alice, &room)).contains(&text.as_str()) {
            break text;
        }
        bob_d = daemon(
            bob,
            &format!("bob-{attempt}"),
            "127.0.0.1:0",
            &format!("{IDENTITY}\n{ROOMPASS}\n"),
            None,
        );
        attached(bob, "bob");
    };
    for i in 1..=3 {
        post(alice, &room, &format!("meanwhile {i}"));
    }
    std::thread::sleep(Duration::from_secs(12));
    let bob_d = daemon(
        bob,
        "bob-back",
        "127.0.0.1:0",
        &format!("{IDENTITY}\n{ROOMPASS}\n"),
        None,
    );
    attached(bob, "bob");
    let deadline = Instant::now() + Duration::from_secs(90);
    while !texts(&read(alice, &room)).contains(&away.as_str()) {
        assert!(
            Instant::now() < deadline,
            "alice never received {away:?}\n{}",
            daemon_logs(&[(alice.as_path(), "alice"), (bob.as_path(), "bob")])
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let shown: Vec<String> = texts(&read(alice, &room))
        .into_iter()
        .map(str::to_owned)
        .collect();
    let at = shown.iter().position(|t| *t == away).unwrap();
    let meanwhile = shown.iter().position(|t| t == "meanwhile 1").unwrap();
    let l = late(alice, &room);
    println!(
        "alice: {away:?} at {at}, above \"meanwhile 1\" at {meanwhile}; marked late: {l:?} \
         (after {attempt} attempt(s))"
    );
    assert!(at < meanwhile, "the late post is not in its true place");
    assert_eq!(
        l,
        vec![away.clone()],
        "exactly the late post is marked late"
    );
    stop_all(vec![alice_d, bob_d]);
}
