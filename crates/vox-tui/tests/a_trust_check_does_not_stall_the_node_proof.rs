//! **V210-26 — checking the identity passphrase never stalls the node**, through the shipped
//! `vox` binary.
//!
//! Every `vox trust add/list/remove` asks the daemon to verify the identity passphrase, and
//! that is production Argon2id: ~0.3 s of CPU. It ran on the node's actor, which serves every
//! command and event in turn, so for as long as it ran nothing else on the node was served —
//! a post, a read, a sync. It now runs on a blocking thread and answers from there.
//!
//! What this measures, on alice's daemon: `vox room post` then `vox room read` until the
//! post is readable, timed end to end, first with the node otherwise idle and then while
//! four `vox trust list`s run back to back against the same daemon. With the check on the
//! actor, each post waits behind whatever checks are queued ahead of it.
//!
//! **Then a flood:** 32 `vox trust list`s at once with a wrong passphrase — a wrong one costs
//! the same Argon2id as a right one, so nothing can refuse it early. A check off the actor
//! and unbounded is one 256 MiB derivation per request, which is how an agent session running
//! model-authored code could take the node, or the machine, down. So checks share
//! `VERIFIES_IN_FLIGHT` (2) slots: the daemon's resident memory must stay within its level
//! before the flood plus [`FLOOD_HEADROOM`], it must answer afterwards, and a post must still
//! be readable within [`LOCAL_BOUND`] throughout.
//!
//! **The bound** is from what the product promises a person at the keyboard, not from a
//! quiet run: a post they make is readable on their own node well inside PRD-001 R40's
//! one second for a message to a peer. So every loaded sample must be under
//! [`LOCAL_BOUND`], and the loaded median must not be more than [`MEDIAN_SLACK`] above the
//! quiet one. Both are printed with the samples.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use support::Worker;

/// Resident memory of `pid`, in bytes.
fn rss(pid: u32) -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("ps");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .map_or(0, |kib| kib * 1024)
}

/// A post a person makes, readable on their own node, end to end.
const LOCAL_BOUND: Duration = Duration::from_millis(1_000);
/// How much a concurrent trust check may add to the median.
const MEDIAN_SLACK: Duration = Duration::from_millis(150);
const SAMPLES: usize = 20;
/// Concurrent wrong-passphrase checks in the flood.
const FLOOD: usize = 32;
/// What the flood may add to the daemon's resident memory: two 256 MiB Argon2id derivations
/// in flight (`VERIFIES_IN_FLIGHT`), and one more for slack. Unbounded, 32 would want 8 GiB.
const FLOOD_HEADROOM: u64 = 3 * 256 * 1024 * 1024;
const CHECKERS: usize = 4;

fn post_then_read(w: &Worker, r: &str, tag: &str) -> Duration {
    let started = Instant::now();
    let o = w.vox(Some("s"), &["room", "post", r, tag]);
    assert!(o.ok, "post {tag}: {o:?}");
    loop {
        let o = w.vox(None, &["room", "read", r]);
        assert!(o.ok, "read: {o:?}");
        if o.stdout.contains(tag) {
            return started.elapsed();
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "{tag} never became readable on its own node"
        );
    }
}

fn stats(label: &str, v: &[Duration]) -> (Duration, Duration) {
    let mut s = v.to_vec();
    s.sort();
    let median = s[s.len() / 2];
    let max = *s.last().unwrap();
    eprintln!(
        "[proof] {label}: n={} min={:?} median={median:?} p90={:?} max={max:?}",
        s.len(),
        s[0],
        s[s.len() * 9 / 10]
    );
    (median, max)
}

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_trust_check_does_not_stall_posts_and_reads_on_the_same_node() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let alice = &room.workers[0];
    let r = room.id.as_str();
    let pass = alice.pass.to_str().unwrap().to_owned();

    let quiet: Vec<Duration> = (0..SAMPLES)
        .map(|i| post_then_read(alice, r, &format!("QUIET-{i:02}")))
        .collect();

    // Four trust checks back to back against the same daemon, for the whole loaded phase.
    let stop = Arc::new(AtomicBool::new(false));
    let checks = Arc::new(AtomicUsize::new(0));
    let loaded: Vec<Duration> = std::thread::scope(|scope| {
        for _ in 0..CHECKERS {
            let (stop, checks, pass) = (stop.clone(), checks.clone(), pass.clone());
            scope.spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let o = alice.vox(
                        None,
                        &["trust", "list", "--identity-passphrase-file", &pass],
                    );
                    assert!(o.ok, "trust list: {o:?}");
                    checks.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        // Let the checkers get going before the first sample.
        while checks.load(Ordering::SeqCst) < CHECKERS {
            std::thread::sleep(Duration::from_millis(20));
        }
        let before = checks.load(Ordering::SeqCst);
        // Sample until there are enough samples AND every checker has finished at least two
        // checks inside the window: the samples measure nothing unless the checks were
        // running while they were taken.
        let window = Instant::now();
        let mut v = Vec::new();
        while v.len() < SAMPLES || checks.load(Ordering::SeqCst) - before < 2 * CHECKERS {
            assert!(
                window.elapsed() < Duration::from_secs(60),
                "the loaded phase never saw {} trust checks finish ({} did)",
                2 * CHECKERS,
                checks.load(Ordering::SeqCst) - before
            );
            v.push(post_then_read(alice, r, &format!("LOADED-{:03}", v.len())));
        }
        let during = checks.load(Ordering::SeqCst) - before;
        stop.store(true, Ordering::SeqCst);
        eprintln!("[proof] {during} trust checks finished inside the sampled window");
        v
    });
    eprintln!(
        "[proof] {} trust checks ran during the loaded phase",
        checks.load(Ordering::SeqCst)
    );
    // ---- the flood: 32 wrong-passphrase checks at once ----
    let daemon = alice.daemon_pid().expect("alice's daemon");
    let wrong = tmp.path().join("wrong.pass");
    std::fs::write(&wrong, "not the identity passphrase\n").unwrap();
    let base_rss = rss(daemon);
    let done = Arc::new(AtomicUsize::new(0));
    let (peak, flood_posts) = std::thread::scope(|scope| {
        for _ in 0..FLOOD {
            let (done, wrong) = (done.clone(), wrong.clone());
            scope.spawn(move || {
                let o = alice.vox(
                    None,
                    &[
                        "trust",
                        "list",
                        "--identity-passphrase-file",
                        wrong.to_str().unwrap(),
                    ],
                );
                assert!(!o.ok, "a wrong passphrase must be refused: {o:?}");
                done.fetch_add(1, Ordering::SeqCst);
            });
        }
        let mut peak = base_rss;
        let mut posts = Vec::new();
        let started = Instant::now();
        while done.load(Ordering::SeqCst) < FLOOD {
            assert!(
                started.elapsed() < Duration::from_secs(300),
                "the flood never drained: {} of {FLOOD} checks answered",
                done.load(Ordering::SeqCst)
            );
            peak = peak.max(rss(daemon));
            posts.push(post_then_read(
                alice,
                r,
                &format!("FLOOD-{:03}", posts.len()),
            ));
        }
        (peak, posts)
    });
    let after = alice.vox(None, &["room", "list"]);
    assert!(
        after.ok,
        "the daemon must still answer after the flood: {after:?}"
    );
    eprintln!(
        "[proof] flood: {FLOOD} wrong-passphrase checks; daemon RSS {} MiB before, peak {} MiB \
         (+{} MiB; headroom {} MiB)",
        base_rss >> 20,
        peak >> 20,
        peak.saturating_sub(base_rss) >> 20,
        FLOOD_HEADROOM >> 20
    );
    let (_, flood_max) = stats("flood  post → readable", &flood_posts);
    assert!(
        peak.saturating_sub(base_rss) <= FLOOD_HEADROOM,
        "the flood raised the daemon's resident memory by {} MiB, past {} MiB: checks are \
         not bounded",
        peak.saturating_sub(base_rss) >> 20,
        FLOOD_HEADROOM >> 20
    );
    assert!(
        flood_max < LOCAL_BOUND,
        "a post waited {flood_max:?} during the flood (bound {LOCAL_BOUND:?})"
    );

    let (quiet_median, _) = stats("quiet  post → readable", &quiet);
    let (loaded_median, loaded_max) = stats("loaded post → readable", &loaded);
    assert!(
        loaded_max < LOCAL_BOUND,
        "a post waited {loaded_max:?} behind concurrent trust checks (bound {LOCAL_BOUND:?})"
    );
    assert!(
        loaded_median <= quiet_median + MEDIAN_SLACK,
        "concurrent trust checks raised the median from {quiet_median:?} to {loaded_median:?} \
         (slack {MEDIAN_SLACK:?})"
    );
}
