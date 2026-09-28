//! ADR-025 **P2** — a burst of posts across more rooms than there are sync slots is **queued, not
//! skipped**: every post reaches the other member at once. Through the shipped binary: two real
//! `vox daemon`s and no anchor, so the pair's own sessions are the only path.
//!
//! Before ADR-025, past the 16 outbound slots a due session was skipped (`sync_one` returned
//! `false`), the peer's schedule was then marked synced, and the skipped room waited for another
//! trigger — at worst the 30 s interval. ADR-025 D6 queues the port instead (16 slots, at most 4
//! per peer, round-robin) and serves it when a slot frees.
//!
//! ## Staging
//! Alice creates [`ROOMS`] rooms and Bob joins each; they trust each other, and Bob reads a
//! warm-up post in every room, each timed from Alice's first warm-up post there. Then Alice posts once in every room at the same instant
//! ([`ROOMS`] concurrent `vox room post`s). Each post is timed from its own `vox room post`
//! returning to readable on Bob's node, over his control socket as `vox room read` reads it.
//!
//! ## Asserted
//! 1. Each room's first warm-up post, made right after the joins, is readable by Bob within
//!    [`WARM_BOUND`] (V210-34). A host's push can meet Bob still sealing a room he is joining,
//!    which he refuses (`EpochMismatch`); before the fix Alice's port then waited out a 30 s
//!    `Policy` backoff although Bob had synced with her since, and a post there arrived up to
//!    30 s late (CI run 36389831839: the burst's post in room 39, 24 s);
//! 2. every post of the burst readable by Bob within [`BOUND`].
//!
//! ## Precondition (else CANNOT MEASURE)
//! The burst reached the slot cap: on Alice's `vox status --json`, `skipped_at_cap` rose (the
//! base) or `queued` rose (ADR-025). A burst that never met the cap proves nothing.
//!
//! ## Mutation
//! Restore `try_acquire`-or-skip in place of the queue: a skipped port waits for the interval and
//! (2) goes red. Remove the release of a backoff by a clean session the peer opened (`file_session`,
//! V210-34): a room whose join met the refusal waits out the 30 s backoff, and (1) or (2) goes red
//! when that join was among the last before the warm-up or the burst. The refusal is a race
//! between the host's push and the joiner's seal, met on 0–3 of 40 joins per run here, so the
//! mutant is red only on the runs in which it is met late enough.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{counter, failures, pct, Member};

/// More rooms than the 16 outbound slots, and ten times the 4 a peer may hold.
const ROOMS: usize = 40;
/// Each post readable by Bob within this of its `vox room post` returning.
const BOUND: Duration = Duration::from_secs(2);
/// Each room's first warm-up post, made right after the joins, readable by Bob within this. Well
/// under the 30 s `Policy` backoff a refused push used to wait out (24 s measured on CI), and well
/// above the warm-up's measured length here (2.4 s for all 40 rooms, in every run without it).
const WARM_BOUND: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(10);

/// Alice's ports to `peer` that are in backoff, as `room-prefix kind/failures (last failure)`.
fn backoffs(status: &serde_json::Value, peer: &str) -> Vec<String> {
    status["sync"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|r| r["peer"].as_str().is_some_and(|p| peer.starts_with(p)))
                .filter(|r| !r["backoff"].is_null())
                .map(|r| {
                    format!(
                        "{} {}/{} ({})",
                        &r["room"].as_str().unwrap_or("?")[..8],
                        r["backoff"]["kind"].as_str().unwrap_or("?"),
                        r["backoff"]["failures"],
                        r["last_failure"].as_str().unwrap_or("-")
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
#[ignore = "two real daemons with production Argon2id and 40 rooms; CI runs it in release"]
fn a_burst_past_the_slot_cap_is_queued() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
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
    for (i, room) in rooms.iter().enumerate() {
        bob.join(&alice.invite(room), &format!("burst{i:02}"));
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
            "CANNOT MEASURE: bob never read the warm-up in rooms {unread:?}\nalice:\n{}\nbob:\n{}",
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
            if l > WARM_BOUND {
                warm_late.push(format!("room {i}: {l:?}"));
            }
        }
    }
    println!(
        "[proof] warm-up: first posts read after at most {warm_max:?}; {} over {WARM_BOUND:?} \
         {warm_late:?}",
        warm_late.len()
    );
    eprintln!("[proof] warm-up done after {:?}", start.elapsed());
    // Let the warm-up's sessions drain, so the burst starts from idle slots.
    std::thread::sleep(Duration::from_secs(3));
    let before = alice.status();
    let held_back = backoffs(&before, &bob.fp);
    println!(
        "[proof] at the burst, alice's ports to bob in backoff: {} {held_back:?}",
        held_back.len()
    );

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
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
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
    std::thread::sleep(Duration::from_secs(1));
    let after = alice.status();
    let d = |k: &str| counter(&after, k, Some(&bob.fp)) - counter(&before, k, Some(&bob.fp));
    let (skipped, queued, opened, failed) =
        (d("skipped_at_cap"), d("queued"), d("opened"), d("failed"));

    let mut lat: Vec<Duration> = Vec::new();
    let mut late: Vec<String> = Vec::new();
    for i in 0..ROOMS {
        match seen[i] {
            Some(t) => {
                let l = t.saturating_duration_since(done[i]);
                lat.push(l);
                if l > BOUND {
                    late.push(format!("room {i}: {l:?}"));
                }
            }
            None => late.push(format!("room {i}: never within 45 s")),
        }
    }
    let max = lat.iter().copied().max().unwrap_or_default();
    println!(
        "[proof] P2: {ROOMS} rooms posted at once; alice->bob skipped_at_cap {skipped}, queued \
         {queued}, opened {opened}, failed {failed}; crossings p50 {:?} p95 {:?} max {max:?}; {} \
         over {BOUND:?}; last failures {:?}",
        pct(&mut lat.clone(), 50.0),
        pct(&mut lat.clone(), 95.0),
        late.len(),
        failures(&after)
    );
    let refused: Vec<usize> = (0..ROOMS)
        .filter(|&i| {
            after["sync"].as_array().is_some_and(|rows| {
                rows.iter().any(|r| {
                    r["room"].as_str().is_some_and(|x| x.starts_with(&rooms[i]))
                        && r["peer"].as_str().is_some_and(|p| bob.fp.starts_with(p))
                        && r["last_failure"]
                            .as_str()
                            .is_some_and(|f| f.contains("epoch mismatch"))
                })
            })
        })
        .collect();
    println!("[proof] rooms whose alice->bob sessions bob refused as epoch mismatch: {refused:?}");
    let after_backoffs = backoffs(&after, &bob.fp);
    println!(
        "[proof] after the burst, alice's ports to bob in backoff: {} {after_backoffs:?}",
        after_backoffs.len()
    );
    for l in late.iter().take(10) {
        println!("[late] {l}");
    }
    assert!(
        skipped >= 1 || queued >= 1,
        "CANNOT MEASURE: the burst never met the slot cap (skipped_at_cap {skipped}, queued \
         {queued})"
    );
    assert!(
        warm_late.is_empty(),
        "{} of {ROOMS} rooms' first warm-up posts, made right after bob joined, took longer than \
         {WARM_BOUND:?} to reach him: {warm_late:?}; rooms whose sessions bob refused as epoch \
         mismatch: {refused:?}",
        warm_late.len()
    );
    assert!(
        late.is_empty(),
        "{} of {ROOMS} posts took longer than {BOUND:?} to reach bob: {late:?}",
        late.len()
    );
}
