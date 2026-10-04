//! **V210-26 — checking the identity passphrase never stalls the node**, through the shipped
//! `vox` binary.
//!
//! A keyring change (`vox trust add`, `vox trust remove`) past the keyring window asks the
//! daemon to verify the identity passphrase again (V210-159; a read such as `vox trust list` never
//! does since ADR-026: the passphrase is given once at attach), and that is production Argon2id:
//! ~0.3 s of CPU. It ran on the node's actor, which serves every
//! command and event in turn, so for as long as it ran nothing else on the node was served —
//! a post, a read, a sync. It now runs on a blocking thread and answers from there.
//!
//! What this measures, on alice's daemon: `vox room post` then `vox room read` until the
//! post is readable, timed end to end, first with the node otherwise idle and then while
//! four checkers each add and remove a trusted stranger back to back against the same daemon,
//! every change past the window (`VOX_TEST_KEYRING_WINDOW_SECS=0`), so every one is checked. With the check on the
//! actor, each post waits behind whatever checks are queued ahead of it.
//!
//! **Then a flood:** 32 `vox trust add`s at once with a wrong passphrase — a wrong one costs
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

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_trust_check_does_not_stall_posts_and_reads_on_the_same_node);

#[path = "support/room.rs"]
mod support;
#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

/// Every keyring change past the window, so every one checks the passphrase (V210-159).
const KNOB: &str = "VOX_TEST_KEYRING_WINDOW_SECS";

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use support::Worker;

/// A stranger's fingerprint for a checked keyring change: 32 bytes of `seed`, as text.
fn stranger(seed: u8) -> String {
    vox_core::node::link::b32_encode(&[seed; 32])
}

/// Resident memory of `pid`, in bytes.
fn rss(pid: u32) -> u64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .expect("APPARATUS: ps");
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
    assert!(o.ok, "PRODUCT: post {tag}: {o:?}");
    loop {
        let o = w.vox(None, &["room", "read", r]);
        assert!(o.ok, "PRODUCT: read: {o:?}");
        if o.stdout.contains(tag) {
            return started.elapsed();
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "PRODUCT (staging): {tag} never became readable on its own node"
        );
    }
}

fn stats(label: &str, v: &[Duration]) -> (Duration, Duration) {
    let mut s = v.to_vec();
    s.sort();
    let median = s[s.len() / 2];
    let max = *s.last().expect("APPARATUS: no samples");
    eprintln!(
        "[proof] {label}: n={} min={:?} median={median:?} p90={:?} max={max:?}",
        s.len(),
        s[0],
        s[s.len() * 9 / 10]
    );
    (median, max)
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "two networked nodes with production Argon2id; optional, run it in release"]
fn a_trust_check_does_not_stall_posts_and_reads_on_the_same_node() {
    test_knobs::require(&[KNOB]);
    watchdog::arm();
    // Inherited by every daemon this proof starts: a window of 0 s, so each change is checked.
    // Set before any thread of this test starts, and read only by child processes.
    std::env::set_var(KNOB, "0");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: start a runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let alice = &room.workers[0];
    let r = room.id.as_str();
    let pass = alice
        .pass
        .to_str()
        .expect("APPARATUS: a path that is not UTF-8")
        .to_owned();

    let quiet: Vec<Duration> = (0..SAMPLES)
        .map(|i| post_then_read(alice, r, &format!("QUIET-{i:02}")))
        .collect();

    // Four trust checks back to back against the same daemon, for the whole loaded phase.
    let stop = Arc::new(AtomicBool::new(false));
    let checks = Arc::new(AtomicUsize::new(0));
    let loaded: Vec<Duration> = std::thread::scope(|scope| {
        for c in 0..CHECKERS {
            let (stop, checks, pass) = (stop.clone(), checks.clone(), pass.clone());
            // A stranger of its own per checker, added and removed in turn: two checked changes.
            let stranger = stranger(u8::try_from(c).expect("APPARATUS: few checkers"));
            scope.spawn(move || {
                let mut add = true;
                while !stop.load(Ordering::SeqCst) {
                    let o = if add {
                        alice.vox(
                            None,
                            &[
                                "trust",
                                "add",
                                &stranger,
                                "--name",
                                &format!("s{c}"),
                                "--identity-passphrase-file",
                                &pass,
                            ],
                        )
                    } else {
                        alice.vox(
                            None,
                            &[
                                "trust",
                                "remove",
                                &stranger,
                                "--identity-passphrase-file",
                                &pass,
                            ],
                        )
                    };
                    // Made, every time: the right passphrase was given. A refusal here ("needs
                    // your identity passphrase again") is a check that passed and did not count —
                    // two checks racing to restart the window — a lost event, PRODUCT.
                    assert!(
                        o.ok,
                        "PRODUCT: a keyring change given the right passphrase was refused: {o:?}"
                    );
                    add = !add;
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
                "PRODUCT: the loaded phase never saw {} trust checks finish ({} did)",
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
    let daemon = alice.daemon_pid().expect("PRODUCT: alice's daemon");
    let wrong = tmp.path().join("wrong.pass");
    std::fs::write(&wrong, "not the identity passphrase\n")
        .expect("APPARATUS: write a staging file");
    let base_rss = rss(daemon);
    let done = Arc::new(AtomicUsize::new(0));
    let flood_stranger = stranger(0xF0);
    let (peak, flood_posts) = std::thread::scope(|scope| {
        for _ in 0..FLOOD {
            let (done, wrong, flood_stranger) =
                (done.clone(), wrong.clone(), flood_stranger.clone());
            scope.spawn(move || {
                let o = alice.vox(
                    None,
                    &[
                        "trust",
                        "add",
                        &flood_stranger,
                        "--name",
                        "flood",
                        "--identity-passphrase-file",
                        wrong.to_str().expect("APPARATUS: a path that is not UTF-8"),
                    ],
                );
                assert!(
                    !o.ok,
                    "PRODUCT: a keyring change past the window with a wrong passphrase must be \
                     refused: {o:?}"
                );
                done.fetch_add(1, Ordering::SeqCst);
            });
        }
        let mut peak = base_rss;
        let mut posts = Vec::new();
        let started = Instant::now();
        while done.load(Ordering::SeqCst) < FLOOD {
            assert!(
                started.elapsed() < Duration::from_secs(300),
                "PRODUCT: the flood never drained: {} of {FLOOD} checks answered",
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
        "PRODUCT: the daemon must still answer after the flood: {after:?}"
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
        "PRODUCT: the flood raised the daemon's resident memory by {} MiB, past {} MiB: checks are \
         not bounded",
        peak.saturating_sub(base_rss) >> 20,
        FLOOD_HEADROOM >> 20
    );
    assert!(
        flood_max < LOCAL_BOUND,
        "PRODUCT: a post waited {flood_max:?} during the flood (bound {LOCAL_BOUND:?})"
    );

    let (quiet_median, _) = stats("quiet  post → readable", &quiet);
    let (loaded_median, loaded_max) = stats("loaded post → readable", &loaded);
    assert!(
        loaded_max < LOCAL_BOUND,
        "PRODUCT: a post waited {loaded_max:?} behind concurrent trust checks (bound {LOCAL_BOUND:?})"
    );
    assert!(
        loaded_median <= quiet_median + MEDIAN_SLACK,
        "PRODUCT: concurrent trust checks raised the median from {quiet_median:?} to {loaded_median:?} \
         (slack {MEDIAN_SLACK:?})"
    );
}
