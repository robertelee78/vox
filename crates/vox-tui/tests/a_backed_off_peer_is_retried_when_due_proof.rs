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
//! ## Precondition (else CANNOT MEASURE)
//! Alice's session to Bob failed while Bob was frozen (`failed` rose within 28 s).
//!
//! ## Mutation
//! Remove `BackoffExpired`: nothing re-evaluates the port until an unrelated trigger, so Alice
//! opens no retry while Bob is frozen and (2) goes red; (1) too unless Bob's own periodic pull
//! happens to carry the post.

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

#[test]
#[ignore = "two real daemons with production Argon2id, one frozen for ~20 s; CI runs it in release"]
fn a_backed_off_peer_is_retried_when_due() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
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
            "CANNOT MEASURE: the pair never read each other\nalice:\n{}\nbob:\n{}",
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
            "CANNOT MEASURE: alice's session to frozen bob never failed within 28 s (counters: {})",
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
    bob_d.signal("-CONT");
    let resumed = Instant::now();
    let b_mid = bob.status();
    let mut read_at = None;
    while resumed.elapsed() < Duration::from_secs(40) {
        if rb.has(cb, text) {
            read_at = Some(resumed.elapsed());
            break;
        }
        std::thread::sleep(POLL);
    }
    std::thread::sleep(Duration::from_millis(500));
    let (a1, b1) = (alice.status(), bob.status());
    let a_retried =
        counter(&a_mid, "opened", Some(&bob.fp)) - counter(&a0, "opened", Some(&bob.fp));
    let b_opened =
        counter(&b1, "opened", Some(&alice.fp)) - counter(&b_mid, "opened", Some(&alice.fp));
    let a_after = counter(&a1, "opened", Some(&bob.fp)) - counter(&a_mid, "opened", Some(&bob.fp));
    println!(
        "[proof] P8: bob frozen; alice's session failed {failed_at:?} after the freeze (\"{}\"); \
         backoff then {backoff}; bob continued {:?} after the freeze; read {read_at:?} after \
         continuing; alice opened {a_retried} to bob between her post and bob's continuing \
         (the failed one and the retry), {a_after} after; bob opened {b_opened} to alice after",
        failures(&a_fail).join(" | "),
        resumed - frozen,
    );
    let read_at = read_at.unwrap_or_else(|| {
        panic!(
            "bob never read alice's post within 40 s of being continued\nalice:\n{}",
            alice_d.transcript()
        )
    });
    assert!(
        read_at <= BOUND,
        "bob read alice's post {read_at:?} after being continued, past {BOUND:?}: the backed-off \
         port was not retried when due"
    );
    assert!(
        a_retried >= 2,
        "alice's port did not retry while bob was frozen: she opened {a_retried} session(s) to him \
         between her post and his continuing (the failed one, and a retry when the backoff was due)"
    );
}
