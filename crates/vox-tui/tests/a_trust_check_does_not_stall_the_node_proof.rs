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

/// A post a person makes, readable on their own node, end to end.
const LOCAL_BOUND: Duration = Duration::from_millis(1_000);
/// How much a concurrent trust check may add to the median.
const MEDIAN_SLACK: Duration = Duration::from_millis(150);
const SAMPLES: usize = 20;
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
