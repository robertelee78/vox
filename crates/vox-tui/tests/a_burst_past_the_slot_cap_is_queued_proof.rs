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
//! warm-up post in every room (each timed from Alice's first warm-up post there, printed). Then
//! Bob's daemon is **paused** (SIGSTOP) and Alice posts once in every room at the same instant
//! ([`ROOMS`] concurrent `vox room post`s). Her sessions to him open and cannot finish, so the burst
//! meets the cap however fast the pair would otherwise drain it: unpaused, a fast runner finished
//! each session before the next post arrived and never held more than the 4 a peer may (CI ubuntu
//! run 36627328546: `opened 40, queued 0`). Bob resumes (SIGCONT) once Alice's status shows the cap
//! met, or after [`PAUSE_MAX`], which is well inside a session's patience. Each post is timed from
//! the later of its own `vox room post` returning and Bob resuming, to readable on Bob's node, over
//! his control socket as `vox room read` reads it.
//!
//! Then **V210-34, staged deterministically**: one more room, joined last, while Alice posts in it
//! every [`STAGE_EVERY`]. One of her pushes lands inside Bob's seconds-long seal of the room, which
//! he refuses (`EpochMismatch`: not held here yet), and her port with him for it takes a 30 s
//! `Policy` backoff. A join no push met is not the staging, and another room is joined, up to
//! [`STAGE_TRIES`]. Once Bob's own sessions with her there have run and settled (her `vox status
//! --json`: an admitted session, none running, the row unchanged for [`SETTLE`]), Alice posts once
//! more, timed to Bob's read and to her own push opening.
//!
//! ## Asserted
//! 1. Every post of the burst readable by Bob within [`BOUND`] of the later of its post and his
//!    resuming;
//! 2. the post in the late-joined room readable by Bob, and **carried by Alice's own push** (her
//!    `opened` rises), both within [`LATE_BOUND`]. Before the fix nothing released Alice's backoff
//!    when Bob synced with her, so her push waited out the 30 s (CI run 36389831839: the burst's
//!    post in room 39, 24 s). The push is asserted, not only the read, because Bob's own 30 s tick
//!    can carry the post and would hide a port still backing off.
//!
//! ## Preconditions (else CANNOT MEASURE)
//! - The burst reached the slot cap: on Alice's `vox status --json`, `skipped_at_cap` rose (the
//!   base) or `queued` rose (ADR-025). A burst that never met the cap proves nothing.
//! - During the late join, Alice's `vox status --json` row for that room and Bob showed the
//!   refusal (`last_failure` "epoch mismatch") and a `policy` backoff. Without it (2) measures
//!   nothing.
//!
//! ## Mutation
//! - Restore `try_acquire`-or-skip in place of the queue: a skipped port waits for the interval and
//!   (1) goes red.
//! - Remove the release of a backoff by a clean session the peer opened (`file_session`, V210-34),
//!   or release it only on sessions this node opened: Alice's port waits out the 30 s and (2) goes
//!   red, on every run.

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
/// The post in the late-joined room readable by Bob within this, once he has synced with Alice
/// there: well under the 30 s `Policy` backoff the refused push used to wait out (24 s on CI).
const LATE_BOUND: Duration = Duration::from_secs(5);
/// Longest Bob stays paused while the burst is posted: well inside the 5 s an outbound session's
/// setup may take, so no session fails for the pause.
const PAUSE_MAX: Duration = Duration::from_secs(3);
/// How often Alice posts in the late-joined room while Bob's join of it runs.
const STAGE_EVERY: Duration = Duration::from_millis(50);
/// How long she keeps posting after Bob's `vox room join` returns.
const STAGE_AFTER: Duration = Duration::from_secs(2);
/// Late joins tried for one whose seal met a push (it did in 6 of 7 single tries measured).
const STAGE_TRIES: usize = 5;
/// How long Alice's row for the late-joined room must stay unchanged and idle before the timed post.
const SETTLE: Duration = Duration::from_secs(1);
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
    // Bob's joins, [`JOINS_AT_ONCE`] at a time, and the late joins; unlocks: two `vox id`s, two
    // `trust add`s, two daemons, and a room created per join.
    watchdog::arm_for(
        (ROOMS.div_ceil(JOINS_AT_ONCE) + STAGE_TRIES) as u32,
        (6 + ROOMS + STAGE_TRIES) as u32,
    );
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
    // Let the warm-up's sessions drain, so the burst starts from idle slots.
    std::thread::sleep(Duration::from_secs(3));
    let before = alice.status();
    let held_back = backoffs(&before, &bob.fp);
    println!(
        "[proof] at the burst, alice's ports to bob in backoff: {} {held_back:?}",
        held_back.len()
    );

    // Bob paused, so Alice's sessions to him hold their slots until he resumes.
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
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let met = |st: &serde_json::Value| {
        counter(st, "skipped_at_cap", Some(&bob.fp)) + counter(st, "queued", Some(&bob.fp))
            > counter(&before, "skipped_at_cap", Some(&bob.fp))
                + counter(&before, "queued", Some(&bob.fp))
    };
    while !met(&alice.status()) && paused.elapsed() < PAUSE_MAX {
        std::thread::sleep(Duration::from_millis(20));
    }
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
        "[proof] P2: {ROOMS} rooms posted at once; alice->bob skipped_at_cap {skipped}, queued \
         {queued}, opened {opened}, failed {failed}; crossings p50 {:?} p95 {:?} max {max:?}; {} \
         over {BOUND:?}; last failures {:?}",
        pct(&mut lat.clone(), 50.0),
        pct(&mut lat.clone(), 95.0),
        late.len(),
        failures(&after)
    ));
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

    // The burst's claim is settled before the late join is staged.
    assert!(
        skipped >= 1 || queued >= 1,
        "CANNOT MEASURE: the burst never met the slot cap (skipped_at_cap {skipped}, queued \
         {queued})"
    );
    assert!(
        late.is_empty(),
        "{} of {ROOMS} posts took longer than {BOUND:?} to reach bob: {late:?}",
        late.len()
    );
    // **V210-34, staged.** One more room, joined last, while Alice posts in it every
    // [`STAGE_EVERY`]: one of her pushes lands inside Bob's seconds-long seal of the room, which he
    // refuses (`EpochMismatch`), and her port with him for it takes a 30 s `Policy` backoff. Seen
    // on her `vox status --json` while the join runs (with the fix, Bob's first clean session to
    // her clears it moments after his join returns, so it is looked for as it happens). A join
    // whose seal no push met is not the staging, and another room is joined, up to
    // [`STAGE_TRIES`].
    let row_in = |st: &serde_json::Value, room: &str| -> serde_json::Value {
        st["sync"]
            .as_array()
            .and_then(|rows| {
                rows.iter()
                    .find(|r| {
                        r["room"].as_str().is_some_and(|x| x.starts_with(room))
                            && r["peer"].as_str().is_some_and(|p| bob.fp.starts_with(p))
                    })
                    .cloned()
            })
            .unwrap_or_default()
    };
    let mut staged: Option<(String, String)> = None;
    let mut tries: Vec<String> = Vec::new();
    for k in 0..STAGE_TRIES {
        let name = format!("latejoin{k}");
        let lr = alice.create(&name);
        let link = alice.invite(&lr);
        let mut posts = 0usize;
        std::thread::scope(|s| {
            let joining = s.spawn(|| bob.join(&link, &name));
            let mut after_join: Option<Instant> = None;
            loop {
                if after_join.is_none() && joining.is_finished() {
                    after_join = Some(Instant::now());
                }
                if staged.is_some() || after_join.is_some_and(|t| t.elapsed() > STAGE_AFTER) {
                    break;
                }
                posts += 1;
                alice.post(&lr, &format!("during join {posts}"));
                let r = row_in(&alice.status(), &lr);
                let refused = r["last_failure"]
                    .as_str()
                    .is_some_and(|f| f.contains("epoch mismatch"));
                if refused && r["backoff"]["kind"].as_str() == Some("policy") {
                    staged = Some((lr.clone(), r.to_string()));
                }
                std::thread::sleep(STAGE_EVERY);
            }
            joining.join().unwrap();
        });
        tries.push(format!(
            "{name}: {posts} posts, {}",
            if staged.is_some() {
                "refused"
            } else {
                "not refused"
            }
        ));
        if staged.is_some() {
            break;
        }
    }
    println!("[proof] late joins: {tries:?}");
    let Some((lr, refusal)) = staged else {
        panic!(
            "CANNOT MEASURE: in {STAGE_TRIES} late joins, no push of alice's was refused as epoch \
             mismatch into a policy backoff: {tries:?}"
        );
    };
    println!("[proof] late join: refusal and policy backoff seen: {refusal}");
    let row = |st: &serde_json::Value| row_in(st, &lr);
    let c = |r: &serde_json::Value, k: &str| r[k].as_u64().unwrap_or(0);
    let idle = |r: &serde_json::Value| {
        c(r, "opened") + c(r, "admitted")
            <= c(r, "completed") + c(r, "partial") + c(r, "failed") + c(r, "stale")
    };

    // Bob's own sessions with Alice there have run, cleanly, since the refusal, and settled: on her
    // side at least one admitted session, nothing running and nothing changing for [`SETTLE`].
    let lid = rb.room(&lr);
    let synced = Instant::now();
    let mut last = String::new();
    let mut still_since = Instant::now();
    let settled = loop {
        let r = row(&alice.status());
        let now = r.to_string();
        if now != last {
            last = now;
            still_since = Instant::now();
        } else if c(&r, "admitted") >= 1 && idle(&r) && still_since.elapsed() >= SETTLE {
            break r;
        }
        assert!(
            synced.elapsed() < Duration::from_secs(20),
            "CANNOT MEASURE: bob's sessions with alice in the late-joined room never ran and \
             settled: {r}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let synced = synced.elapsed();

    // The timed post: readable by Bob, **carried by Alice's own push** (her `opened` rises). Bob's
    // pulls could carry it too, on his 30 s tick, and would hide a port still backing off.
    let opened_before = c(&settled, "opened");
    alice.post(&lr, "late timed");
    let posted = Instant::now();
    let (mut read_at, mut pushed_at) = (None, None);
    while (read_at.is_none() || pushed_at.is_none()) && posted.elapsed() < Duration::from_secs(45) {
        if read_at.is_none() && rb.has(lid, "late timed") {
            read_at = Some(posted.elapsed());
        }
        if pushed_at.is_none() && c(&row(&alice.status()), "opened") > opened_before {
            pushed_at = Some(posted.elapsed());
        }
        std::thread::sleep(POLL);
    }
    println!(
        "[proof] late join: bob's sessions ran and settled {synced:?} after it; alice's backoff \
         then {}; the timed post read by bob after {read_at:?}, alice's own push opened after \
         {pushed_at:?}",
        settled["backoff"]
    );
    assert!(
        read_at.is_some_and(|t| t <= LATE_BOUND) && pushed_at.is_some_and(|t| t <= LATE_BOUND),
        "in the room whose join refused alice's push, after bob had synced with her there, her \
         next post reached bob after {read_at:?} and her own push to him opened after \
         {pushed_at:?} (both at most {LATE_BOUND:?}; her backoff then {}): the 30 s policy \
         backoff was not released",
        settled["backoff"]
    );
}
