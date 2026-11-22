//! ADR-025 **P8** — a peer whose session failed is retried **when its backoff is due**, by this
//! node's own outbound session, with the connection held up the whole time so a reconnect cannot
//! rescue it. Through the shipped binary: two real `vox daemon`s and no anchor, so the pair's own
//! sessions are the only path.
//!
//! ADR-025 D5: a failed session puts the port in a backoff of its kind and arms its own wakeup
//! (`BackoffExpired`); when that fires the port re-evaluates and, still needing a session, opens
//! one. Without the wakeup nothing re-evaluates the port until an unrelated trigger — at worst
//! the 30 s interval.
//!
//! ## Staging
//! Alice and Bob share a room and read each other. Bob is frozen with `SIGSTOP` — not killed, so
//! the QUIC connection is still filed alive on Alice's side and no reconnect happens. Alice posts.
//! Her session to Bob cannot be answered and fails at the frame timeout (20 s, shorter than the
//! 30 s after which a silent connection is filed dead). As soon as `vox status --json` shows that
//! failure, and [`AFTER_FAILURE`] later, Bob is continued (`SIGCONT`). The clock starts then.
//!
//! ## Asserted
//! 1. Bob reads Alice's post within [`BOUND`] of being continued;
//! 2. **Alice's own port retried while Bob was still frozen**, with the connection up: by the time
//!    Bob is continued Alice has opened two sessions to him since her post — the one that failed
//!    and the retry her backoff's wakeup started ~200 ms later (her counters, read before Bob is
//!    continued, so nothing Bob does can count).
//!
//! Bob's own periodic request may also fall due while he is frozen (every 30 s), and then his pull
//! can carry the post too; that is why (2) is read from Alice's side before he is continued and
//! does not depend on who delivered.
//!
//! **Why 3 s and not the ADR row's 9 s.** The row's 9 s is the 8 s backoff cap plus a second, for a
//! staging where every retry fails fast. Here the only failure is one frame timeout, after which
//! the backoff is its first step (200 ms), so the retry is already open and waiting on Bob when he
//! is continued. Without the wakeup, the next trigger is a periodic sync, 30 s after the warm-up:
//! at least 6 s after Bob is continued.
//!
//! ## Preconditions
//! The pair read each other before the freeze, and Alice's session to Bob failed while Bob was
//! frozen (`failed` rose within 28 s): each is the product's, so a miss is `PRODUCT (staging)`.
//! Her `opened` counter did not go backwards (a restarted node starts it again at 0), else
//! PRODUCT: nothing in the proof restarts a node.
//!
//! ## Apparatus clock
//! (1) is timed from `SIGCONT`. On the same timeline a thread of this process sleeps 10 ms at a
//! time and keeps the most it overslept: the runner's own stall, which vox cannot move. If it
//! overslept more than [`APPARATUS_BUDGET`] and Bob read late, the runner owned the window:
//! `APPARATUS (runner stalled)`. Otherwise a late read is `PRODUCT: took X (runner
//! stalled at most Y)`. When Bob first answered after `SIGCONT`, and the largest gap between
//! polls of his room, are vox's own timing: printed, never the clock.
//! (2) reads Alice's own counters before Bob is continued, so it needs no clock.
//!
//! ## Mutation
//! Remove `BackoffExpired`: nothing re-evaluates the port until an unrelated trigger, so Alice
//! opens no retry while Bob is frozen and (2) goes red; (1) too unless Bob's own periodic pull
//! happens to carry the post.
//!
//! # Second act: a member that hiccuped twice still delivers in seconds
//! [`a_peer_that_failed_twice_half_a_minute_apart_still_delivers_in_seconds`]: what a person
//! feels is that a member whose connection hiccuped twice, half a minute apart, with hundreds of
//! good exchanges between, still delivers its next post in seconds, not half a minute.
//!
//! ## Staging
//! The same pair, both with the connection up throughout. A hiccup is Bob refusing every bounded
//! history stream he is asked to serve (test-knobs `VOX_TEST_REFUSE_HISTORY_FILE`, only while the
//! named file exists): he resets it with `TransportFailed`, as a busy member's stream resets do,
//! which paces Alice's whole port to him (the transport scope). A freeze does not stage it: in
//! the first try of this act Alice's port to a frozen Bob showed `connected: false` at the first
//! failure, a new connection clears every backoff, and `backoff` showed one failure both times.
//!
//! Alice posts while Bob refuses, until her `failed` count for him rises; he stops refusing at
//! once. Bob posts [`HEALTHY_POSTS`], one a second, and the staging waits until Alice shows every
//! one: her own answered turns with him, the good exchanges. The second hiccup is staged the same
//! way and must fail more than 30 s after the first, with the port connected at both failures:
//! the persistent pacing applies to a streak of at least two failures that began 30 s or more
//! before. Alice's `vox status --json` row for Bob (`sync[].backoff`, the kind and the streak's
//! failure count written by the failure that set the pacing) is printed at both failures, with
//! the port record (`lanes.ports[]`: `connected`, `backing_off_classes`). Bob then posts a
//! marker; the clock starts then.
//!
//! ## Asserted
//! Alice shows the marker within [`STREAK_BOUND`] of Bob posting it. A red is `PRODUCT` with
//! what her status showed for Bob's port (backing off while connected), or `APPARATUS (runner
//! stalled)` under the same runner clock as the first act. Every wait before the clock is causal
//! (her `failed` rising, the posts shown) and `APPARATUS (staging not reached)` on expiry.
//!
//! ## Mutation
//! `VOX_MUTANT_TRANSPORT_STREAK`, forwarded to both daemons (test-knobs build): an answered turn
//! no longer ends the transport failure streak. The second failure then extends the first one's
//! streak past 30 s, the port stops for 30 s, and the marker arrives late. Alice's daemon says
//! when the mutant first keeps a streak; the act requires that line when the mutant is asked for.
//!
//! # Third act: a member that keeps refusing is retried less and less often
//! [`a_peer_that_keeps_refusing_is_retried_less_and_less_often`]: ending the streak on an answer
//! must not stop a member that answers nothing from being paced. Bob refuses every history
//! stream for the whole act (the same knob, never removed) and Alice posts once. From Alice's
//! first failed session to Bob, her `vox status --json` is read every 250 ms for
//! [`REFUSING_WINDOW`]: her row for Bob must show `backoff` `unreachable` with `failures` of at
//! least [`REFUSING_STREAK`] at some read, and her `failed` count for him must rise by at most
//! [`REFUSING_MOST`] over the window (the doubling 200 ms to 8 s pacing fails about seven times in
//! 20 s; a port retried every 200 ms fails several times that). The red is `PRODUCT` with the
//! streak and count she showed. Mutation: a streak that every returned turn resets, even one
//! that never reached Bob (528d25bfd's rule), holds it at one failure.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{counter, failures, Member};

/// Bob reads Alice's post within this of being continued.
const BOUND: Duration = Duration::from_secs(3);
/// How long after the failure is seen that Bob is continued.
const AFTER_FAILURE: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(10);
/// The most the runner may oversleep one 10 ms sleep before a late read is the runner's, not
/// vox's.
const APPARATUS_BUDGET: Duration = Duration::from_secs(1);
/// Alice shows Bob's marker within this of his being continued after his second hiccup. The
/// persistent pacing it guards against stops the port for 30 s.
const STREAK_BOUND: Duration = Duration::from_secs(10);
/// Posts Bob makes, one a second, between his two hiccups.
const HEALTHY_POSTS: usize = 35;
/// What Alice's daemon says when `VOX_MUTANT_TRANSPORT_STREAK` first keeps a streak.
const STREAK_MUTANT_LINE: &str = "VOX_MUTANT_TRANSPORT_STREAK engaged";
/// How long Alice's status is read while Bob keeps refusing.
const REFUSING_WINDOW: Duration = Duration::from_secs(20);
/// The unreachable streak Alice's status must reach for a Bob who keeps refusing.
const REFUSING_STREAK: u64 = 3;
/// The most failed sessions to Bob Alice may count over [`REFUSING_WINDOW`].
const REFUSING_MOST: u64 = 12;

/// The runner's own clock: a thread that sleeps 10 ms at a time and keeps the most it overslept.
/// It measures whether this process was scheduled, never vox: a slow vox does not move it, so a
/// late result with this clock quiet is the product's.
struct RunnerStall {
    worst_us: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RunnerStall {
    fn start() -> Self {
        use std::sync::atomic::Ordering;
        let worst_us = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (worst, stopped) = (
            std::sync::Arc::clone(&worst_us),
            std::sync::Arc::clone(&stop),
        );
        std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let asked = Instant::now();
                std::thread::sleep(Duration::from_millis(10));
                let over = asked.elapsed().saturating_sub(Duration::from_millis(10));
                worst.fetch_max(
                    u64::try_from(over.as_micros()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
            }
        });
        Self { worst_us, stop }
    }

    /// The most the runner overslept one 10 ms sleep since [`RunnerStall::start`].
    fn worst(&self) -> Duration {
        Duration::from_micros(self.worst_us.load(std::sync::atomic::Ordering::Relaxed))
    }
}

impl Drop for RunnerStall {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
#[ignore = "two real daemons with production Argon2id, one frozen for ~20 s; CI runs it in release"]
fn a_backed_off_peer_is_retried_when_due() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon(None);
    let bob_d = bob.daemon(None);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    let mut ra = alice.reader();
    let mut rb = bob.reader();
    let (ca, cb) = (ra.room(&room), rb.room(&room));

    let start = Instant::now();
    let mut n = 0;
    loop {
        n += 1;
        alice.post(&room, &format!("warm alice {n}"));
        bob.post(&room, &format!("warm bob {n}"));
        std::thread::sleep(Duration::from_millis(500));
        if ra.texts(ca).iter().any(|t| t.starts_with("warm bob"))
            && rb.texts(cb).iter().any(|t| t.starts_with("warm alice"))
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "PRODUCT (staging): the pair never read each other in 90 s\nalice:\n{}\nbob:\n{}",
            alice_d.transcript(),
            bob_d.transcript()
        );
    }
    std::thread::sleep(Duration::from_secs(1));

    let a0 = alice.status();
    bob_d.signal("-STOP");
    let frozen = Instant::now();
    let text = "p8 while bob was frozen";
    alice.post(&room, text);
    // Wait for Alice's session to Bob to fail, with the connection still up.
    let mut failed_at = None;
    let mut a_fail = alice.status();
    while frozen.elapsed() < Duration::from_secs(28) {
        a_fail = alice.status();
        if counter(&a_fail, "failed", Some(&bob.fp)) > counter(&a0, "failed", Some(&bob.fp)) {
            failed_at = Some(frozen.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let Some(failed_at) = failed_at else {
        bob_d.signal("-CONT");
        panic!(
            "PRODUCT (staging): alice's session to frozen bob never failed within 28 s (counters: \
             {})",
            a_fail
        );
    };
    std::thread::sleep(AFTER_FAILURE);
    let a_mid = alice.status();
    let backoff = a_mid["sync"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r["peer"].as_str().is_some_and(|p| bob.fp.starts_with(p)))
                .map(|r| r["backoff"].clone())
        })
        .unwrap_or(serde_json::Value::Null);
    let stall = RunnerStall::start();
    bob_d.signal("-CONT");
    let resumed = Instant::now();
    let b_mid = bob.status();
    // Vox's own timing, printed: when Bob first answered after SIGCONT (his `vox status --json`
    // returned), and the largest gap between two polls of his room.
    let answered = resumed.elapsed();
    let mut read_at = None;
    let (mut last_poll, mut max_gap) = (Instant::now(), Duration::ZERO);
    while resumed.elapsed() < Duration::from_secs(40) {
        let now = Instant::now();
        max_gap = max_gap.max(now - last_poll);
        last_poll = now;
        if rb.has(cb, text) {
            read_at = Some(resumed.elapsed());
            break;
        }
        std::thread::sleep(POLL);
    }
    let apparatus = stall.worst();
    std::thread::sleep(Duration::from_millis(500));
    let (a1, b1) = (alice.status(), bob.status());
    // A counter that went backwards was reset by a restart: nothing below would mean anything.
    let rose = |who: &str, later: &serde_json::Value, earlier: &serde_json::Value, peer: &str| {
        let (l, e) = (
            counter(later, "opened", Some(peer)),
            counter(earlier, "opened", Some(peer)),
        );
        l.checked_sub(e).unwrap_or_else(|| {
            panic!(
                "PRODUCT: {who}'s `opened` counter went backwards ({e} -> {l}): the node \
                 was restarted under the proof"
            )
        })
    };
    let a_retried = rose("alice", &a_mid, &a0, &bob.fp);
    let b_opened = rose("bob", &b1, &b_mid, &alice.fp);
    let a_after = rose("alice", &a1, &a_mid, &bob.fp);
    println!(
        "[proof] P8: bob frozen; alice's session failed {failed_at:?} after the freeze (\"{}\"); \
         backoff then {backoff}; bob continued {:?} after the freeze; read {read_at:?} after \
         continuing; alice opened {a_retried} to bob between her post and bob's continuing \
         (the failed one and the retry), {a_after} after; bob opened {b_opened} to alice after; \
         bob first answered {answered:?} after SIGCONT, largest poll gap {max_gap:?}; the runner \
         overslept at most {apparatus:?}",
        failures(&a_fail).join(" | "),
        resumed - frozen,
    );
    assert!(
        a_retried >= 2,
        "PRODUCT: alice's port did not retry while bob was frozen: her `vox status` shows \
         {a_retried} session(s) opened to him between her post and his continuing (the failed \
         one, and a retry when the backoff was due)"
    );
    let Some(read_at) = read_at else {
        panic!(
            "PRODUCT: bob never read alice's post within 40 s of being continued (the runner \
             overslept at most {apparatus:?})\nalice:\n{}\nbob:\n{}",
            alice_d.transcript(),
            bob_d.transcript()
        )
    };
    if read_at > BOUND {
        assert!(
            apparatus <= APPARATUS_BUDGET,
            "APPARATUS (runner stalled): the runner stalled: it overslept a 10 ms sleep by {apparatus:?} \
             (budget {APPARATUS_BUDGET:?}) while bob read alice's post {read_at:?} after being \
             continued"
        );
        panic!(
            "PRODUCT: took {read_at:?} (runner stalled at most {apparatus:?}): bob read alice's post past \
             {BOUND:?} after being continued: the backed-off port was not retried when due"
        );
    }
}

/// The `(room, peer)` row in `rows` (a `vox status --json` array) for the peer `fp`.
fn peer_row(rows: &serde_json::Value, fp: &str) -> serde_json::Value {
    rows.as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| {
                    r["peer"]
                        .as_str()
                        .is_some_and(|p| fp.starts_with(p) || p.starts_with(fp))
                })
                .cloned()
        })
        .unwrap_or(serde_json::Value::Null)
}

/// What Alice's status shows for her port to Bob: the streak it holds and whether it is backing
/// off while connected.
fn port_seen(status: &serde_json::Value, fp: &str) -> String {
    let port = peer_row(&status["lanes"]["ports"], fp);
    format!(
        "backoff={} connected={} backing_off={} backing_off_classes={} needs={} queued={}",
        peer_row(&status["sync"], fp)["backoff"],
        port["connected"],
        port["backing_off"],
        port["backing_off_classes"],
        port["needs"],
        port["queued"],
    )
}

/// Have Bob refuse every history stream he is asked to serve (his
/// `VOX_TEST_REFUSE_HISTORY_FILE` exists) while Alice posts, until her `failed` count for him
/// rises; then stop refusing. When it rose, and her status then.
fn hiccup_until_failed(
    alice: &Member,
    bob: &Member,
    refuse: &std::path::Path,
    room: &str,
    text: &str,
) -> (Instant, serde_json::Value) {
    let before = counter(&alice.status(), "failed", Some(&bob.fp));
    std::fs::write(refuse, b"refuse").expect("APPARATUS: could not write bob's refusal file");
    let began = Instant::now();
    alice.post(room, text);
    let mut last = serde_json::Value::Null;
    while began.elapsed() < Duration::from_secs(28) {
        last = alice.status();
        if counter(&last, "failed", Some(&bob.fp)) > before {
            std::fs::remove_file(refuse).expect("APPARATUS: could not remove bob's refusal file");
            return (Instant::now(), last);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_file(refuse);
    panic!(
        "APPARATUS (staging not reached): alice's session to bob did not fail within 28 s of \
         {text:?} while bob refused his history streams (her row for him: {})",
        peer_row(&last["sync"], &bob.fp)
    );
}

#[test]
#[ignore = "two real daemons with production Argon2id, about two minutes; CI runs it in release"]
fn a_peer_that_failed_twice_half_a_minute_apart_still_delivers_in_seconds() {
    watchdog::arm();
    let mutant = std::env::var("VOX_MUTANT_TRANSPORT_STREAK").ok();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let refuse = root.join("bob-refuses-history");
    let refuse_text = refuse
        .to_str()
        .expect("APPARATUS: the scratch path is not UTF-8")
        .to_owned();
    let mut alice_env: Vec<(&str, &str)> = Vec::new();
    if let Some(m) = mutant.as_deref() {
        alice_env.push(("VOX_MUTANT_TRANSPORT_STREAK", m));
    }
    let mut bob_env = alice_env.clone();
    bob_env.push(("VOX_TEST_REFUSE_HISTORY_FILE", &refuse_text));
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon_with(&alice_env);
    let bob_d = bob.daemon_with(&bob_env);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    let mut ra = alice.reader();
    let mut rb = bob.reader();
    let (ca, cb) = (ra.room(&room), rb.room(&room));

    let start = Instant::now();
    let mut n = 0;
    loop {
        n += 1;
        alice.post(&room, &format!("warm alice {n}"));
        bob.post(&room, &format!("warm bob {n}"));
        std::thread::sleep(Duration::from_millis(500));
        if ra.texts(ca).iter().any(|t| t.starts_with("warm bob"))
            && rb.texts(cb).iter().any(|t| t.starts_with("warm alice"))
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "APPARATUS (staging not reached): the pair never read each other in 90 s\nalice:\n{}\nbob:\n{}",
            alice_d.transcript(),
            bob_d.transcript()
        );
    }
    std::thread::sleep(Duration::from_secs(1));

    // The first hiccup.
    let (first_at, a_first) = hiccup_until_failed(
        &alice,
        &bob,
        &refuse,
        &room,
        "streak: alice posts, bob refuses, 1",
    );
    let first_seen = port_seen(&a_first, &bob.fp);

    // The good exchanges: Bob posts one a second and Alice shows every post.
    for i in 1..=HEALTHY_POSTS {
        bob.post(&room, &format!("streak good {i}"));
        std::thread::sleep(Duration::from_secs(1));
    }
    let posted = Instant::now();
    loop {
        let texts = ra.texts(ca);
        if (1..=HEALTHY_POSTS).all(|i| texts.iter().any(|t| t == &format!("streak good {i}"))) {
            break;
        }
        assert!(
            posted.elapsed() < Duration::from_secs(60),
            "APPARATUS (staging not reached): alice did not show bob's {HEALTHY_POSTS} posts \
             within 60 s of the last one (her status for his port: {})",
            port_seen(&alice.status(), &bob.fp)
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let a_good = alice.status();

    // The second hiccup.
    let (second_at, a_second) = hiccup_until_failed(
        &alice,
        &bob,
        &refuse,
        &room,
        "streak: alice posts, bob refuses, 2",
    );
    let streak_age = second_at - first_at;
    let second_seen = port_seen(&a_second, &bob.fp);
    let good = counter(&a_good, "completed", Some(&bob.fp)).saturating_sub(counter(
        &a_first,
        "completed",
        Some(&bob.fp),
    ));
    assert!(
        streak_age > Duration::from_secs(30),
        "APPARATUS (staging not reached): the second failure came {streak_age:?} after the \
         first, not more than 30 s"
    );
    // A new connection clears every backoff; the hiccups must leave it up, as a stream reset
    // from a connected peer does in a busy room.
    for (which, status) in [("first", &a_first), ("second", &a_second)] {
        assert!(
            peer_row(&status["lanes"]["ports"], &bob.fp)["connected"] == true,
            "APPARATUS (staging not reached): alice's port to bob was not connected at the \
             {which} failure: {}",
            port_seen(status, &bob.fp)
        );
    }

    let stall = RunnerStall::start();
    let posted = Instant::now();
    let marker = "streak: bob's post after his second hiccup";
    bob.post(&room, marker);
    let mut read_at = None;
    let mut late_seen = None;
    while posted.elapsed() < Duration::from_secs(60) {
        if ra.has(ca, marker) {
            read_at = Some(posted.elapsed());
            break;
        }
        if late_seen.is_none() && posted.elapsed() > STREAK_BOUND {
            late_seen = Some(port_seen(&alice.status(), &bob.fp));
        }
        std::thread::sleep(POLL);
    }
    let apparatus = stall.worst();
    let said = alice_d.transcript();
    let mutant_line = said.lines().find(|l| l.contains(STREAK_MUTANT_LINE));
    println!(
        "[proof] streak: first failure, alice's port to bob: {first_seen}; {good} completed \
         exchanges with bob between the two; second failure {streak_age:?} after the first: \
         {second_seen}; marker shown {read_at:?} after bob posted it; at {STREAK_BOUND:?}: \
         {late_seen:?}; runner overslept at most {apparatus:?}; mutant asked: {mutant:?}, \
         alice's daemon said: {mutant_line:?}",
    );
    if mutant.is_some() {
        assert!(
            mutant_line.is_some(),
            "APPARATUS: VOX_MUTANT_TRANSPORT_STREAK was asked for but alice's daemon never said \
             it engaged\nalice:\n{said}"
        );
    }
    let Some(read_at) = read_at else {
        panic!(
            "PRODUCT: alice never showed bob's post within 60 s of his posting it after his \
             second hiccup ({streak_age:?} after the first, {good} good exchanges between); her \
             status for his port at {STREAK_BOUND:?}: {late_seen:?} (the runner overslept at \
             most {apparatus:?})"
        )
    };
    if read_at > STREAK_BOUND {
        assert!(
            apparatus <= APPARATUS_BUDGET,
            "APPARATUS (runner stalled): the runner overslept a 10 ms sleep by {apparatus:?} \
             (budget {APPARATUS_BUDGET:?}) while alice showed bob's post {read_at:?} after he \
             posted it"
        );
        panic!(
            "PRODUCT: alice showed bob's post {read_at:?} after he posted it, past \
             {STREAK_BOUND:?}, although they had {good} good exchanges since his first hiccup \
             {streak_age:?} earlier; her status for his port at the second failure: \
             {second_seen}; at {STREAK_BOUND:?}: {late_seen:?}"
        );
    }
}

#[test]
#[ignore = "two real daemons with production Argon2id, about a minute; CI runs it in release"]
fn a_peer_that_keeps_refusing_is_retried_less_and_less_often() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let refuse = root.join("bob-refuses-history");
    let refuse_text = refuse
        .to_str()
        .expect("APPARATUS: the scratch path is not UTF-8")
        .to_owned();
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon_with(&[]);
    let bob_d = bob.daemon_with(&[("VOX_TEST_REFUSE_HISTORY_FILE", &refuse_text)]);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    let mut ra = alice.reader();
    let mut rb = bob.reader();
    let (ca, cb) = (ra.room(&room), rb.room(&room));

    let start = Instant::now();
    let mut n = 0;
    loop {
        n += 1;
        alice.post(&room, &format!("warm alice {n}"));
        bob.post(&room, &format!("warm bob {n}"));
        std::thread::sleep(Duration::from_millis(500));
        if ra.texts(ca).iter().any(|t| t.starts_with("warm bob"))
            && rb.texts(cb).iter().any(|t| t.starts_with("warm alice"))
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "APPARATUS (staging not reached): the pair never read each other in 90 s\nalice:\n{}\nbob:\n{}",
            alice_d.transcript(),
            bob_d.transcript()
        );
    }
    std::thread::sleep(Duration::from_secs(1));

    // Bob refuses from now to the end; Alice's post gives her port to him work.
    let before = counter(&alice.status(), "failed", Some(&bob.fp));
    std::fs::write(&refuse, b"refuse").expect("APPARATUS: could not write bob's refusal file");
    alice.post(&room, "refusing: alice posts while bob refuses");
    let began = Instant::now();
    let mut first = None;
    while began.elapsed() < Duration::from_secs(28) {
        let status = alice.status();
        if counter(&status, "failed", Some(&bob.fp)) > before {
            first = Some(status);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let Some(first) = first else {
        panic!(
            "APPARATUS (staging not reached): alice's session to bob did not fail within 28 s \
             while he refused his history streams"
        );
    };
    let at_first = counter(&first, "failed", Some(&bob.fp));
    let window = Instant::now();
    let (mut streak, mut last) = (0, first);
    while window.elapsed() < REFUSING_WINDOW {
        let status = alice.status();
        let backoff = &peer_row(&status["sync"], &bob.fp)["backoff"];
        if backoff["kind"] == "unreachable" {
            streak = streak.max(backoff["failures"].as_u64().unwrap_or(0));
        }
        last = status;
        std::thread::sleep(Duration::from_millis(250));
    }
    let failed = counter(&last, "failed", Some(&bob.fp)).saturating_sub(at_first);
    let _ = std::fs::remove_file(&refuse);
    println!(
        "[proof] refusing: over {REFUSING_WINDOW:?} after her first failed session to bob, \
         alice's status showed an unreachable streak of at most {streak} and {failed} more failed \
         sessions to him; her port at the end: {}",
        port_seen(&last, &bob.fp)
    );
    assert!(
        streak >= REFUSING_STREAK && failed <= REFUSING_MOST,
        "PRODUCT: bob refused every history stream, and over {REFUSING_WINDOW:?} alice's status \
         showed an unreachable streak of at most {streak} (at least {REFUSING_STREAK} expected) \
         and {failed} failed sessions to him (at most {REFUSING_MOST} expected): her port to a \
         member that answers nothing is not paced; at the end: {}",
        port_seen(&last, &bob.fp)
    );
}
