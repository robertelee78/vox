//! **A host answers the next joiner straight after the last one** (PRD-001 R42's
//! prerequisite, defect D8; ADR-017 "Open proof gap", ADR-018 "Root cause of
//! `service_rehearsal_proof:490`").
//!
//! The node's accept loop awaited each TLS handshake inline, so it served one at a time for
//! up to 30 seconds each. `vox connect` is a one-shot — it exits the moment it has joined —
//! and that left the host mid-handshake on something and deaf to everybody for the next half
//! minute. Measured on the serialised loop: a lone joiner gets in in about 2 s; a second one
//! **immediately** after the first is locked out with `direct attempt timed out` against the
//! host's real, still-bound port; a second one 40 s later gets in.
//!
//! This is that reproduction as a proof: one host, then two `vox connect`s back to back, with
//! no trust, no malice and no waiting in between. Both must get in, and quickly.
//!
//! ## Why it is `#[ignore]`d
//!
//! Production Argon2id on four profiles plus a real ADR-005 proof of work per join. CI runs
//! it in release with the other real-parameter proofs.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::time::Duration;

use world::{echo_service, World};

/// Well under the 30 s handshake bound whose serialisation this proves gone, and well over
/// the ~2 s a lone join takes, so it separates the two shapes with room on both sides.
const PROMPT: Duration = Duration::from_secs(12);

#[test]
#[ignore = "production Argon2id profiles + real PoW joins, driving the real binary; CI runs it in release"]
fn two_joiners_back_to_back_both_get_in_promptly() {
    watchdog::arm();
    // The world's own guest is the first joiner; `World::new` asserts it got in.
    let w = World::new(echo_service(), false);
    let second = w.tmp.path().join("second");
    let third = w.tmp.path().join("third");
    for d in [&second, &third] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    // The first joiner's `vox connect` has already exited — the one-shot that used to leave
    // the host mid-handshake. Nothing is awaited between these.
    let (ok2, t2, out2, err2) = w.join(&second);
    eprintln!("[test] second joiner: joined={ok2} after {t2:?}");
    let (ok3, t3, out3, err3) = w.join(&third);
    eprintln!("[test] third joiner:  joined={ok3} after {t3:?}");
    assert!(
        ok2,
        "a second joiner straight after the first must get in (PRD-001 D8); after {t2:?}:\n\
         stdout:\n{out2}\nstderr:\n{err2}"
    );
    assert!(
        ok3,
        "a third joiner straight after the second must get in; after {t3:?}:\n\
         stdout:\n{out3}\nstderr:\n{err3}"
    );
    assert!(
        t2 < PROMPT && t3 < PROMPT,
        "back-to-back joins must each take under {PROMPT:?}; they took {t2:?} and {t3:?}"
    );
}
