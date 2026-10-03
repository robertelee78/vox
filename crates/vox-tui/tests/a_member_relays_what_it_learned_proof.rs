//! ADR-025 — **a member relays what it learned**: entries a member absorbs from one peer are
//! offered to its other peers at once, through the shipped binary.
//!
//! ADR-025 D1: a port (room, peer) needs a session when the room's generation `gen` has moved past
//! what that peer was credited with. `ChannelState::absorb_arrived` raises `gen` by the rows a sync
//! committed, which makes the absorbing member's other ports due, so it hands on what it just
//! learned. In every other proof each peer's own posts raise `gen` as well, so a build in which
//! absorbing never raised it stayed green everywhere (the verifier on #209, point 4).
//!
//! ## Staging (real `vox` processes only)
//! An anchor (`vox node`) and three `vox daemon`s, alice, bob and carol, all trusting each other, in
//! one room alice creates and bob and carol join through the CLI. No daemon is restarted.
//! 1. Warm-up: each member posts a hello and reads the other two, so every key is in place.
//! 2. The periodic request (every 30 s, ADR-025 D7) raises every port, and would carry alice's posts
//!    to carol by itself. So the proof watches bob's and carol's `opened` counters with each other
//!    (`vox status --json`) until it has seen each side's tick, and places the measured window where
//!    neither can fire. The tick cannot pass this proof.
//! 3. Carol is frozen (`SIGSTOP`). Alice posts [`POSTS`] entries, and **bob reads all of them**
//!    (the precondition: bob holds something to relay).
//! 4. Alice and the anchor are frozen, so neither can serve carol anything, and carol is continued.
//!    **Bob, who posts nothing, is the only live member holding alice's entries.** No freeze
//!    approaches the 30 s after which a silent connection is declared dead, so no connection is
//!    re-made, and a new connection's request plays no part.
//!
//! ## Asserted
//! Within [`BOUND`] of carol's return, **carol reads all [`POSTS`]** of alice's entries, and while
//! alice and the anchor were frozen carol ended no session with alice: bob carried them.
//!
//! ## Apparatus clock
//! From carol's `SIGCONT`, a thread of this process sleeps 10 ms at a time and keeps the most it
//! overslept: the runner's own stall, which vox cannot move. If carol fell short and the runner
//! overslept more than [`APPARATUS_BUDGET`], the runner, not bob, owned the window:
//! `APPARATUS (runner stalled)`. Otherwise the red is `PRODUCT: took X (runner stalled at most
//! Y)`. When carol's socket first answered after `SIGCONT` is vox's own timing: printed, never the
//! clock.
//!
//! ## Mutation
//! `absorb_arrived` never raises `gen` (the verifier's mutant B): bob stores alice's entries, but no
//! port of his becomes due, and nothing else asks for a session with carol until the next tick,
//! which the window excludes. Carol reads 0 of [`POSTS`] and the proof goes red.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{counter, Member};

/// Entries alice posts.
const POSTS: usize = 5;
/// How long carol may take to read them all after she is continued. A relay is a session or two on
/// a live loopback connection, well under a second; the periodic request comes every 30 s.
const BOUND: Duration = Duration::from_secs(5);
/// The periodic request's interval, hard-coded (ADR-025 D7, `SYNC_INTERVAL_SECS`).
const TICK: Duration = Duration::from_secs(30);
/// Kept clear of a tick either side of the window: the tick runs on a one-second timer against a
/// whole-second clock, and the counters are read by polling.
const MARGIN: Duration = Duration::from_secs(3);
/// The most that step 3 (alice's posts, and bob reading them) may take before the window no
/// longer fits between two ticks. Measured 0.1 s (release) to 0.8 s (debug, load 30-90). It is 3 s,
/// not more, so that a window always fits (V210-110, #306): the window and its margins come to
/// 3 + 5 + 2 × 3 = 14 s, and two ticks on a 30 s period always leave a gap of at least 15 s. At 6 s
/// they came to 17 s, and every run whose two tick phases were 13–17 s apart (about one in eight)
/// was a CANNOT MEASURE.
const STAGING: Duration = Duration::from_secs(3);
const SETUP: Duration = Duration::from_secs(90);
/// The most the runner may oversleep one 10 ms sleep before a shortfall is the runner's.
const APPARATUS_BUDGET: Duration = Duration::from_secs(2);

fn texts_of(m: &Member, room: &str) -> Vec<String> {
    let mut r = m.reader();
    let id = r.room(room);
    r.texts(id)
}

fn relayed_count(texts: &[String]) -> usize {
    (0..POSTS)
        .filter(|i| texts.iter().any(|t| *t == format!("relay-{i}")))
        .count()
}

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
#[ignore = "real vox processes timed against the 30 s periodic request; CI runs it in release"]
fn a_member_relays_what_it_learned() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let (anchor, spec) = sync_pair::anchor(root);
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    let carol = Member::new(root, "carol");
    let all = [&alice, &bob, &carol];
    for a in all {
        for b in all {
            if a.name != b.name {
                a.trust(b);
            }
        }
    }
    let alice_d = alice.daemon(Some(&spec));
    let bob_d = bob.daemon(Some(&spec));
    let carol_d = carol.daemon(Some(&spec));
    let room = alice.create("relay");
    let link = alice.invite(&room);
    bob.join(&link, "relay");
    carol.join(&link, "relay");

    // ---- 1. warm-up: everyone reads everyone ----------------------------------------------------
    for m in all {
        m.post(&room, &format!("hello from {}", m.name));
    }
    let start = Instant::now();
    loop {
        let mut missing = Vec::new();
        for reader in all {
            let texts = texts_of(reader, &room);
            for author in all {
                if !texts.contains(&format!("hello from {}", author.name)) {
                    missing.push(format!("{} cannot read {}", reader.name, author.name));
                }
            }
        }
        if missing.is_empty() {
            break;
        }
        assert!(
            start.elapsed() < SETUP,
            "PRODUCT (staging): after {SETUP:?} the members do not all read each other: {missing:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    println!(
        "[proof] warm-up: every member reads every other after {:.1?}",
        start.elapsed()
    );
    // Let the join's and the warm-up's own sessions settle before looking for the tick.
    std::thread::sleep(Duration::from_secs(5));

    // ---- 2. find each side's periodic request on the bob-carol ports ---------------------------
    let opened = |m: &Member, o: &Member| counter(&m.status(), "opened", Some(&o.fp));
    let (mut b_last, mut c_last) = (opened(&bob, &carol), opened(&carol, &bob));
    let (mut b_tick, mut c_tick): (Option<Instant>, Option<Instant>) = (None, None);
    let watch = Instant::now();
    while b_tick.is_none() || c_tick.is_none() {
        assert!(
            watch.elapsed() < TICK * 2,
            "PRODUCT (staging): in {:?}, bob opened a session to carol: {}, carol to bob: {}; the \
             periodic request was not seen",
            TICK * 2,
            b_tick.is_some(),
            c_tick.is_some()
        );
        std::thread::sleep(Duration::from_millis(200));
        let (b, c) = (opened(&bob, &carol), opened(&carol, &bob));
        if b > b_last {
            b_tick = Some(Instant::now());
        }
        if c > c_last {
            c_tick = Some(Instant::now());
        }
        (b_last, c_last) = (b, c);
    }
    let ticks = [
        b_tick.expect("APPARATUS: set by the loop above"),
        c_tick.expect("APPARATUS: set by the loop above"),
    ];
    // The first tick of `seen`'s series at or after `t`.
    let next_tick = |seen: Instant, t: Instant| {
        let mut n = seen;
        while n < t {
            n += TICK;
        }
        n
    };
    // [go, go + STAGING + BOUND] must stay MARGIN clear of every tick of either side.
    let window = STAGING + BOUND;
    let now = Instant::now();
    let mut go = now;
    while !ticks.iter().all(|&seen| {
        let next = next_tick(seen, go);
        let prev = next - TICK;
        go.saturating_duration_since(prev) >= MARGIN && next >= go + window + MARGIN
    }) {
        go += Duration::from_millis(250);
        assert!(
            go < now + TICK,
            "APPARATUS: no {window:?} window clear of both ticks"
        );
    }
    println!(
        "[proof] ticks: bob->carol seen {:.1?} ago, carol->bob {:.1?} ago; staging in {:.1?}, \
         leaving {:.1?} and {:.1?} to their next ticks",
        now.duration_since(ticks[0]),
        now.duration_since(ticks[1]),
        go.duration_since(now),
        next_tick(ticks[0], go).duration_since(go),
        next_tick(ticks[1], go).duration_since(go)
    );
    std::thread::sleep(go.saturating_duration_since(Instant::now()));

    // ---- 3. carol frozen; alice posts; bob reads every entry -----------------------------------
    // Sessions carol has ended with alice, read now: her status cannot be read while she is frozen.
    let ended_with_alice = || {
        let st = carol.status();
        counter(&st, "completed", Some(&alice.fp)) + counter(&st, "partial", Some(&alice.fp))
    };
    let ended_before = ended_with_alice();
    let staged = Instant::now();
    carol_d.signal("-STOP");
    for i in 0..POSTS {
        alice.post(&room, &format!("relay-{i}"));
    }
    let posted = staged.elapsed();
    let mut bob_has = 0;
    while staged.elapsed() < STAGING {
        bob_has = relayed_count(&texts_of(&bob, &room));
        if bob_has == POSTS {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!(
        "[proof] carol frozen; alice posted {POSTS} in {posted:.1?}; bob reads {bob_has}/{POSTS} \
         {:.1?} after the freeze",
        staged.elapsed()
    );
    assert!(
        bob_has == POSTS,
        "PRODUCT (staging): within {STAGING:?} bob reads only {bob_has}/{POSTS} of alice's entries, so \
         he holds nothing to relay\nbob:\n{}",
        bob_d.transcript()
    );

    // ---- 4. alice and the anchor frozen; carol back: only bob can give her the entries --------
    alice_d.signal("-STOP");
    anchor.signal("-STOP");
    let stall = RunnerStall::start();
    carol_d.signal("-CONT");
    let back = Instant::now();
    let mut have = 0;
    // Vox's own timing, printed: when carol's control socket first answered after SIGCONT.
    let mut answered = None;
    while back.elapsed() < BOUND {
        have = relayed_count(&texts_of(&carol, &room));
        answered.get_or_insert(back.elapsed());
        if have == POSTS {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = back.elapsed();
    let answered = answered.unwrap_or(took);
    let runner = stall.worst();
    drop(stall);
    println!(
        "[proof] carol reads {have}/{POSTS} of alice's entries {took:.1?} after she was continued \
         (bound {BOUND:?}); her socket first answered {answered:.1?} after SIGCONT; the runner \
         overslept at most {runner:?}"
    );
    let ended = ended_with_alice() - ended_before;
    println!("[proof] sessions carol ended with alice meanwhile: {ended}");
    alice_d.signal("-CONT");
    anchor.signal("-CONT");
    assert!(
        ended == 0,
        "PRODUCT (staging): carol ended {ended} session(s) with alice, so bob was not her only source"
    );
    // The staging held (bob holds all of them, carol ended nothing with alice, no tick in the
    // window), so a short count is the product's: bob did not relay what he learned. Both sides'
    // sessions and connections are printed, so the red says which event was lost.
    assert!(
        have == POSTS || runner <= APPARATUS_BUDGET,
        "APPARATUS (runner stalled): the runner stalled: it overslept a 10 ms sleep by {runner:?} (budget \
         {APPARATUS_BUDGET:?}) while carol read {have}/{POSTS} within {BOUND:?}"
    );
    assert!(
        have == POSTS,
        "PRODUCT: took more than {took:?} (runner stalled at most {runner:?}): carol reads {have}/{POSTS} of \
         alice's entries {BOUND:?} after she was continued: bob holds all {POSTS} and did not hand \
         them on\nbob's status:\n{}\ncarol's status:\n{}\nbob:\n{}\ncarol:\n{}",
        bob.status(),
        carol.status(),
        bob_d.transcript(),
        carol_d.transcript()
    );
}
