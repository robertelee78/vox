//! A burst of posts across many rooms reaches the other member through the shipped binary.
//!
//! ## Staging
//! Alice creates [`ROOMS`] rooms and Bob joins each; they trust each other, and Bob reads a
//! warm-up post in every room (each timed from Alice's first warm-up post there, printed). Then
//! Bob's daemon is paused (SIGSTOP), Alice posts once in every room concurrently, and Bob resumes.
//! Each post is timed from the later of its completion and Bob resuming until Bob can read it.
//!
//! ## Asserted
//! Every post of the burst is readable by Bob within [`BOUND`] of the later of its post and his
//! resuming.
//!
//! A warm-up post that never reaches Bob once both joins succeeded is a product red (`PRODUCT:`),
//! not a precondition: delivery is the product.
//!
//!

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{pct, Member};

/// Number of rooms in the burst.
const ROOMS: usize = 40;
/// Each post readable by Bob within this of its `vox room post` returning: 2 s in a release build,
/// where timing bounds count. A debug build seals and opens every post unoptimized, about ten times
/// as slowly (#295: three debug runs' burst crossings, most 4.89 s, 4.58 s and 6.13 s, against p50
/// 0.21 s in release), so it gets 13 s, about twice its most measured.
const BOUND: Duration = Duration::from_secs(if cfg!(debug_assertions) { 13 } else { 2 });
/// Which build's bounds apply, said in the log.
const PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};
const POLL: Duration = Duration::from_millis(10);
/// How many of the [`ROOMS`] Bob joins at once. One in a release build, as the staging always ran.
/// Three in a debug build, where a join's proof of work costs up to `watchdog::DEBUG_JOIN` and forty
/// in turn were about 55 minutes of setup (V210-99): three, because a node answering fewer than
/// four joins at once asks no more work of each (`Difficulty::ADAPT_THRESHOLD`), so no join is made
/// harder by the others.
const JOINS_AT_ONCE: usize = if cfg!(debug_assertions) { 3 } else { 1 };

/// Print a line that reaches the log **when the test passes too**: straight to stderr, past
/// libtest's capture, which swallows `println!` of a passing test. CI shows a green run's burst
/// meeting the cap this way, not only a red one's (V210-90).
fn shown(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{line}");
}

#[test]
#[ignore = "two real daemons with production Argon2id and 40 rooms; CI runs it in release"]
fn a_burst_past_the_slot_cap_is_queued() {
    watchdog::arm();
    shown(&format!(
        "[proof] {PROFILE} build: bound {BOUND:?} for the burst"
    ));
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon(None);
    let bob_d = bob.daemon(None);

    let rooms: Vec<String> = (0..ROOMS)
        .map(|i| alice.create(&format!("burst{i:02}")))
        .collect();
    let links: Vec<String> = rooms.iter().map(|r| alice.invite(r)).collect();
    for chunk in (0..ROOMS).collect::<Vec<_>>().chunks(JOINS_AT_ONCE) {
        std::thread::scope(|s| {
            for &i in chunk {
                let (bob, link) = (&bob, &links[i]);
                s.spawn(move || bob.join(link, &format!("burst{i:02}")));
            }
        });
    }
    let mut rb = bob.reader();
    let ids: Vec<_> = rooms.iter().map(|r| rb.room(r)).collect();

    // Bob reads a post in every room first: keys have flowed in every room. Each room's read is
    // timed from Alice's first warm-up post there (V210-34): right after the joins, this is where a
    // push refused while Bob was still sealing a room shows.
    let start = Instant::now();
    let mut first_post: Vec<Option<Instant>> = vec![None; ROOMS];
    let mut read_at: Vec<Option<Instant>> = vec![None; ROOMS];
    let mut n = 0;
    loop {
        n += 1;
        let unread: Vec<usize> = (0..ROOMS).filter(|&i| read_at[i].is_none()).collect();
        if unread.is_empty() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(240),
            "PRODUCT: after both joins succeeded, bob read no warm-up post in rooms {unread:?} \
             within 240 s of alice posting there\nalice:\n{}\nbob:\n{}",
            alice_d.transcript(),
            bob_d.transcript()
        );
        for &i in &unread {
            alice.post(&rooms[i], &format!("warm {i} {n}"));
            first_post[i].get_or_insert_with(Instant::now);
        }
        let round = Instant::now();
        while round.elapsed() < Duration::from_secs(2) && read_at.iter().any(Option::is_none) {
            for i in 0..ROOMS {
                if read_at[i].is_none() && rb.texts(ids[i]).iter().any(|t| t.starts_with("warm ")) {
                    read_at[i] = Some(Instant::now());
                }
            }
            std::thread::sleep(POLL);
        }
    }
    let mut warm_late: Vec<String> = Vec::new();
    let mut warm_max = Duration::ZERO;
    for i in 0..ROOMS {
        if let (Some(p), Some(r)) = (first_post[i], read_at[i]) {
            let l = r.saturating_duration_since(p);
            warm_max = warm_max.max(l);
            if l > Duration::from_secs(2) {
                warm_late.push(format!("room {i}: {l:?}"));
            }
        }
    }
    println!(
        "[proof] warm-up: first posts read after at most {warm_max:?}; {} over 2s \
         {warm_late:?}",
        warm_late.len()
    );
    eprintln!("[proof] warm-up done after {:?}", start.elapsed());

    // Pause Bob while the concurrent posts are made.
    bob_d.signal("-STOP");
    let paused = Instant::now();
    let barrier = std::sync::Barrier::new(ROOMS);
    let done: Vec<Instant> = std::thread::scope(|s| {
        let hs: Vec<_> = rooms
            .iter()
            .enumerate()
            .map(|(i, room)| {
                let (alice, barrier) = (&alice, &barrier);
                s.spawn(move || {
                    barrier.wait();
                    alice.post(room, &format!("burst {i}"));
                    Instant::now()
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    });
    bob_d.signal("-CONT");
    let resumed = Instant::now();
    shown(&format!(
        "[proof] bob paused for {:?} while the burst was posted",
        resumed - paused
    ));
    let mut seen: Vec<Option<Instant>> = vec![None; ROOMS];
    let deadline = Instant::now() + Duration::from_secs(45);
    while seen.iter().any(Option::is_none) && Instant::now() < deadline {
        for i in 0..ROOMS {
            if seen[i].is_none() && rb.has(ids[i], &format!("burst {i}")) {
                seen[i] = Some(Instant::now());
            }
        }
        std::thread::sleep(POLL);
    }

    let mut lat: Vec<Duration> = Vec::new();
    let mut late: Vec<String> = Vec::new();
    for i in 0..ROOMS {
        match seen[i] {
            Some(t) => {
                let l = t.saturating_duration_since(done[i].max(resumed));
                lat.push(l);
                if l > BOUND {
                    late.push(format!("room {i}: {l:?}"));
                }
            }
            None => late.push(format!("room {i}: never within 45 s")),
        }
    }
    let max = lat.iter().copied().max().unwrap_or_default();
    shown(&format!(
        "[proof] P2: {ROOMS} rooms posted at once; crossings p50 {:?} p95 {:?} max {max:?}; {} \
         over {BOUND:?}",
        pct(&mut lat.clone(), 50.0),
        pct(&mut lat.clone(), 95.0),
        late.len()
    ));
    for l in late.iter().take(10) {
        println!("[late] {l}");
    }

    assert!(
        late.is_empty(),
        "PRODUCT: {} of {ROOMS} posts took longer than {BOUND:?} to reach bob: {late:?}",
        late.len()
    );
}
