//! PRD-001 R2 (#53) — **a room of about 500 member nodes works**: every member joins, a post
//! reaches every member, and a member that was stopped catches up when it starts again, through
//! the shipped binary.
//!
//! **Staging**, every node the shipped `vox`: an anchor (`vox node`) on loopback; the host's
//! `vox daemon`, which creates the room; then the members, each its own identity (`vox id`), its
//! own `vox daemon` behind the anchor, which stays up for the whole proof. A few at a time, as
//! production Argon2id and each join's proof of work allow, each member trusts the host, joins
//! from the host's invite link **once** (a refused join is the product's red, never retried), and
//! the host trusts it, so the host's posts are sealed for every member (authors decide readers).
//!
//! **Asserted**, each timed and printed:
//! 1. **join**: every member's `vox room join` succeeds, and the host's `vox room roster` lists
//!    every member and itself;
//! 2. **delivery**: one post by the host is readable on **every** member's node (read over its own
//!    control socket, as `vox room read` reads it) within the arm's delivery bound;
//! 3. **catch-up**: [`RESTARTED`] members are stopped as a person stops them (SIGINT), the host
//!    posts [`MISSED`] more while they are down, and once each is started again it reads all of
//!    them within the arm's catch-up bound. A member that stayed up reading them too is the
//!    control that they were sent at all (else CANNOT MEASURE).
//!
//! The bounds are generous: R2 claims the room works at this size, not how fast. What each step
//! took is printed (the slowest join, the delivery's p50/p90/last), for the decision on any
//! latency claim at this size.
//!
//! **Two arms.** [`a_room_of_many_members_works`] stages [`SMALL`] members: blocking, in the
//! release gate with the other real-parameter proofs. [`a_room_of_about_500_members_works`]
//! stages [`LARGE`]: **optional** (`--features optional-proofs`), run by hand, never in CI; without
//! the feature a stand-in, `optional_proof_not_run::a_room_of_about_500_members_works`, takes its
//! place, so a run is never silent about it. Run it, in release, with
//!
//! ```text
//! cargo test --release -p vox-tui --features optional-proofs \
//!     --test a_room_of_about_500_members_works_proof -- --ignored --nocapture \
//!     a_room_of_about_500_members_works
//! ```
//!
//! **Measured** (release, an 18-core Mac under other agents' load, once each): at 16 members the
//! whole proof took 34 s (each join p90 7.1 s; every member read the post within 0.57 s; the three
//! restarted members caught up within 1.8 s); at 64, 203 s (joins 187 s, each p90 23.7 s; the post
//! read by all within 3.8 s; catch-up within 3.2 s). A join's cost grows with the room (1.6 s per
//! member staged at 16, 2.9 s at 64), so the large arm's staging is expected to take about 1.5 to
//! 2.5 hours; its watchdog allows 4. Run it in a terminal that stays open, not a background job
//! with a shorter limit.
//!
//! **What loopback does not show, stated:** every member here is on one machine and one network,
//! so the anchor sees a single source for all of them, and no packet is lost or delayed. A room
//! of 500 members on 500 networks is not what this stages.
//!
//! **Every red says which it is**: `PRODUCT:` quotes what `vox` said or did; `CANNOT MEASURE:`
//! names staging that was not achieved or a harness too slow to look; `APPARATUS:` names a fault
//! of the proof's own; the watchdog says it is the watchdog.
//!
//! **Mutation that must turn it red:** a room that cannot hold this many members — the cap on
//! admitted authors per room (`MAX_AUTHORS`, `vox-core/src/node/channel.rs`) below the arm's
//! size (8 for the small arm, 256 for the large).

#![cfg(unix)]
// Without the feature the large arm is not compiled, so part of the staging is used by one arm.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code))]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_room_of_about_500_members_works);

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use sync_pair::{anchor, Member, Proc, Reader};

/// The blocking arm's members, besides the host.
const SMALL: usize = 16;
/// The optional arm's members, besides the host: PRD-001 R2's "about 500".
const LARGE: usize = 500;
/// Members stopped and started again for the catch-up claim.
const RESTARTED: usize = 3;
/// Posts the host makes while they are down.
const MISSED: usize = 3;
/// How long a sweep of every member's node may take before the harness, not the product, is
/// the reason a deadline passed: fewer than this many sweeps by the deadline is CANNOT MEASURE.
const MIN_SWEEPS: u32 = 5;

/// One arm's size and bounds.
struct Arm {
    members: usize,
    /// Every member reads the host's post within this.
    deliver_within: Duration,
    /// Every restarted member reads what it missed within this of being started again.
    catch_up_within: Duration,
}

#[test]
#[ignore = "real binaries and production Argon2id: the release gate runs it"]
fn a_room_of_many_members_works() {
    // A debug build's budget: a join per member; an unlock for each `vox id`, daemon and trust
    // (the member's and the host's), the host's own three, and each restart.
    watchdog::arm_for_setup(SMALL as u32, (4 * SMALL + 3 + RESTARTED) as u32);
    a_room_of(&Arm {
        members: SMALL,
        deliver_within: Duration::from_secs(60),
        catch_up_within: Duration::from_secs(60),
    });
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "500 daemons and production Argon2id; run by hand in release, never in CI"]
fn a_room_of_about_500_members_works() {
    // Staging 500 members takes far past the default 600 s (see the module docs for the time).
    watchdog::arm_for(Duration::from_secs(4 * 3600));
    a_room_of(&Arm {
        members: LARGE,
        deliver_within: Duration::from_secs(300),
        catch_up_within: Duration::from_secs(300),
    });
}

/// A member with its daemon, kept up for the proof.
struct Up {
    m: Member,
    daemon: Option<Proc>,
}

fn a_room_of(arm: &Arm) {
    let n = arm.members;
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);
    let host = Member::new(root, "host");
    let _host_d = host.daemon(Some(&spec));
    let room = host.create("r2");
    let link = host.invite(&room);
    let lanes = std::thread::available_parallelism().map_or(4, |p| p.get().min(12));

    // ---- 1. join: every member, a few at a time -----------------------------------------------
    let t_stage = Instant::now();
    let names: Vec<&'static str> = (1..=n)
        .map(|i| &*Box::leak(format!("m{i:03}").into_boxed_str()))
        .collect();
    let mut up: Vec<Up> = Vec::with_capacity(n);
    let mut joins: Vec<Duration> = Vec::with_capacity(n);
    for chunk in names.chunks(lanes) {
        let done: Vec<(Up, Duration)> = std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|name| {
                    let (spec, link, host) = (&spec, &link, &host);
                    s.spawn(move || {
                        let m = Member::new(root, name);
                        let d = m.daemon(Some(spec));
                        m.trust(host);
                        let t = Instant::now();
                        m.join(link, "r2");
                        let took = t.elapsed();
                        host.trust(&m);
                        (Up { m, daemon: Some(d) }, took)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
                .collect()
        });
        for (u, took) in done {
            up.push(u);
            joins.push(took);
        }
    }
    let mut sorted = joins.clone();
    let (p50, p90, slowest) = (
        sync_pair::pct(&mut sorted, 50.0),
        sync_pair::pct(&mut sorted, 90.0),
        sync_pair::pct(&mut sorted, 100.0),
    );
    let (ok, roster, err) = host.vox(&["room", "roster", &room], None);
    assert!(ok, "PRODUCT: the host's `vox room roster` failed: {err}");
    let listed = roster.lines().filter(|l| !l.trim().is_empty()).count();
    println!(
        "[proof] 1. join: {n} members joined in {:?} ({lanes} at a time); each `vox room join` \
         p50 {p50:?}, p90 {p90:?}, slowest {slowest:?}; the host's roster lists {listed}",
        t_stage.elapsed()
    );
    let missing: Vec<&str> = up
        .iter()
        .filter(|u| !roster.lines().any(|l| l.trim() == u.m.fp))
        .map(|u| u.m.name)
        .collect();
    assert!(
        listed > n && missing.is_empty(),
        "PRODUCT: every member's join succeeded, but the host's roster lists {listed} (want {}: \
         the host and {n} members) and leaves out {} of them: {:?}\n{roster}",
        n + 1,
        missing.len(),
        &missing[..missing.len().min(20)]
    );

    // ---- 2. delivery: one post, read on every member's node -----------------------------------
    let mut readers: Vec<Reader> = up.iter().map(|u| u.m.reader()).collect();
    let room_id = readers[0].room(&room);
    let text = "r2: one post for every member";
    let t_post = Instant::now();
    host.post(&room, text);
    let posted = t_post.elapsed();
    let arrived = read_by_all(&mut readers, room_id, &[text], t_post, arm.deliver_within);
    let late: Vec<&str> = arrived
        .iter()
        .zip(&up)
        .filter(|(a, _)| a.is_none())
        .map(|(_, u)| u.m.name)
        .collect();
    let mut seen: Vec<Duration> = arrived.iter().flatten().copied().collect();
    let (d50, d90, last) = (
        sync_pair::pct(&mut seen, 50.0),
        sync_pair::pct(&mut seen, 90.0),
        sync_pair::pct(&mut seen, 100.0),
    );
    println!(
        "[proof] 2. delivery: the host's `vox room post` took {posted:?}; {} of {n} members read \
         it, p50 {d50:?}, p90 {d90:?}, the last {last:?} after the post (bound {:?})",
        n - late.len(),
        arm.deliver_within
    );
    assert!(
        late.is_empty(),
        "PRODUCT: {} of {n} members never read the host's post within {:?} of it: {:?}",
        late.len(),
        arm.deliver_within,
        &late[..late.len().min(20)]
    );

    // ---- 3. catch-up: members stopped, posts missed, members started again --------------------
    let first_restarted = n - RESTARTED;
    for u in &mut up[first_restarted..] {
        stop(u);
    }
    // Their readers are on sockets that just went away.
    readers.truncate(first_restarted);
    let missed: Vec<String> = (1..=MISSED)
        .map(|i| format!("r2: missed while down, {i} of {MISSED}"))
        .collect();
    let missed: Vec<&str> = missed.iter().map(String::as_str).collect();
    let t_missed = Instant::now();
    for t in &missed {
        host.post(&room, t);
    }
    // The control: a member that stayed up reads them, so they were sent.
    let control = read_by_all(
        &mut readers[..1],
        room_id,
        &missed,
        t_missed,
        arm.deliver_within,
    );
    assert!(
        control[0].is_some(),
        "CANNOT MEASURE: {}, which stayed up, never read the {MISSED} posts made while the others \
         were down, within {:?}: nothing measures whether the restarted members catch up",
        up[0].m.name,
        arm.deliver_within
    );
    let t_back = Instant::now();
    for u in &mut up[first_restarted..] {
        u.daemon = Some(u.m.daemon(Some(&spec)));
    }
    let mut back: Vec<Reader> = up[first_restarted..].iter().map(|u| u.m.reader()).collect();
    let caught = read_by_all(&mut back, room_id, &missed, t_back, arm.catch_up_within);
    let behind: Vec<&str> = caught
        .iter()
        .zip(&up[first_restarted..])
        .filter(|(a, _)| a.is_none())
        .map(|(_, u)| u.m.name)
        .collect();
    println!(
        "[proof] 3. catch-up: {} of {RESTARTED} restarted members read all {MISSED} missed posts; \
         each at {:?} after they were started again (bound {:?})",
        RESTARTED - behind.len(),
        caught,
        arm.catch_up_within
    );
    assert!(
        behind.is_empty(),
        "PRODUCT: restarted members {behind:?} never read the {MISSED} posts they missed within \
         {:?} of being started again, in a room of {n}",
        arm.catch_up_within
    );
}

/// Stop a member's daemon as a person does (SIGINT), and wait for it to exit.
fn stop(u: &mut Up) {
    let mut d = u.daemon.take().expect("APPARATUS: a member stopped twice");
    d.signal("-INT");
    let t = Instant::now();
    while d.child.try_wait().ok().flatten().is_none() {
        assert!(
            t.elapsed() < Duration::from_secs(30),
            "PRODUCT: {}'s daemon did not stop within 30 s of SIGINT. It said:\n{}",
            u.m.name,
            d.transcript()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// When each reader first read every one of `texts`, from `t0`, looking until `within`: `None`
/// for a reader that never did. A deadline met in fewer than [`MIN_SWEEPS`] sweeps of every
/// reader is the harness's, not the product's.
fn read_by_all(
    readers: &mut [Reader],
    room: vox_core::hash::Digest32,
    texts: &[&str],
    t0: Instant,
    within: Duration,
) -> Vec<Option<Duration>> {
    let mut at: Vec<Option<Duration>> = vec![None; readers.len()];
    let mut sweeps = 0u32;
    loop {
        for (r, a) in readers.iter_mut().zip(at.iter_mut()) {
            if a.is_none() {
                let have = r.texts(room);
                if texts.iter().all(|t| have.iter().any(|h| h == t)) {
                    *a = Some(t0.elapsed());
                }
            }
        }
        sweeps += 1;
        if at.iter().all(Option::is_some) {
            return at;
        }
        if t0.elapsed() >= within {
            assert!(
                sweeps >= MIN_SWEEPS,
                "CANNOT MEASURE: the harness swept the members' nodes only {sweeps} time(s) in \
                 {within:?}: too slow to look, so a member that did not read is not the product's"
            );
            return at;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
