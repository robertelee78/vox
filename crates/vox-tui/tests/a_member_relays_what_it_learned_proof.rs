//! A member relays posts it learned from another member, through the shipped binary.
//!
//! ## Staging (real `vox` processes only)
//! An anchor (`vox node`) and three `vox daemon`s, alice, bob and carol, all trusting each other, in
//! one room alice creates and bob and carol join through the CLI. No daemon is restarted.
//! 1. Warm-up: each member posts a hello and reads the other two, so every key is in place.
//! 2. Carol is frozen (`SIGSTOP`). Alice posts [`POSTS`] entries, and **bob reads all of them**
//!    (the precondition: bob holds something to relay).
//! 3. Alice and the anchor are frozen, so neither can serve carol anything, and carol is continued.
//!    **Bob, who posts nothing, is the only live member holding alice's entries.** No freeze
//!    approaches the 30 s after which a silent connection is declared dead, so no connection is
//!    re-made, and a new connection's request plays no part.
//!
//! Within [`BOUND`] of Carol's return, she reads all of Alice's posts from Bob.
//!
//! ## Apparatus clock
//! From carol's `SIGCONT`, a thread of this process sleeps 10 ms at a time and keeps the most it
//! overslept: the runner's own stall, which vox cannot move. If carol fell short and the runner
//! overslept more than [`APPARATUS_BUDGET`], the runner, not bob, owned the window:
//! `APPARATUS (runner stalled)`. Otherwise the red is `PRODUCT: took X (runner stalled at most
//! Y)`. When carol's socket first answered after `SIGCONT` is vox's own timing: printed, never the
//! clock.
//!

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::Member;

/// Entries alice posts.
const POSTS: usize = 5;
/// The delivery and staging bounds.
const BOUND: Duration = Duration::from_secs(5);
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

    // ---- 3. carol frozen; alice posts; bob reads every entry -----------------------------------
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
    alice_d.signal("-CONT");
    anchor.signal("-CONT");
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
