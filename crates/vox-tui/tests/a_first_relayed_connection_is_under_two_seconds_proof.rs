//! RP-24 (#131), for #167 — **a first relayed connection completes in under 2 s**, through the
//! shipped binary (PRD-001 R42: "a first connection to a peer, including NAT traversal, must
//! complete in under 2 s").
//!
//! It replaces `crates/vox-core/tests/perf_r42_first_connect_relay_gate.rs`, an in-process gate on
//! a NAT simulator that is already deleted (V29-17). That gate's runs took 635–1328 s (#167's
//! "915 s"), and none of it was the connection: each of its twenty samples restarted a node,
//! paid two production Argon2id steps and waited ~6.5 s for the peer to notice, while the timed
//! window itself — first request to a path — stayed under 2 s. So this proof times what R42
//! bounds, and the product now says it: `vox forward` prints `reached <host> in <N> ms (<k>
//! attempts)`, counted from its first attempt (after unlocking and opening the room, the two
//! steps a person waits for at the prompt) to the attempt that got through.
//!
//! **Relayed, and asserted.** The host listens on IPv4 and the guest on IPv6 (`support/relay.rs`,
//! `Split::Families`), so the only path is a circuit through the anchor (ADR-012 rung 4); the
//! guest's own "still relayed" line and the anchor's circuit count are asserted, never assumed.
//!
//! **Cold.** Each of [`SAMPLES`] is a new `vox forward`: a new process, a new node, a new port, no
//! connection kept from the sample before. An echo crosses each one, so "reached" means carried.
//!
//! Mutation: make the ladder's circuit rung wait (or remove it) and every sample either exceeds
//! [`R42`] or never connects.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::Duration;

use relay::{RelayWorld, Split};
use world::round_trip;

/// PRD-001 R42.
const R42: Duration = Duration::from_secs(2);
/// Cold first connections measured; the bound is asserted on every one.
const SAMPLES: usize = 5;

/// `vox: reached <host> in <N> ms (<k> attempts)` → (N, the line).
fn reached(transcript: &str) -> Option<(u64, String)> {
    transcript.lines().find_map(|l| {
        let rest = l.split("vox: reached ").nth(1)?;
        let ms = rest
            .split(" in ")
            .nth(1)?
            .split(" ms")
            .next()?
            .trim()
            .parse()
            .ok()?;
        Some((ms, l.to_owned()))
    })
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_first_relayed_connection_completes_in_under_two_seconds() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT PROVE: the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );

    let mut samples: Vec<(u64, String)> = Vec::new();
    for n in 0..SAMPLES {
        // A fresh `vox forward` each time: the previous one's process is killed by its PID first.
        drop(w.fwd.take());
        let at = w.forward();
        let payload = format!("sample {n}");
        let back =
            round_trip(at, payload.as_bytes(), Duration::from_secs(120)).unwrap_or_else(|e| {
                panic!(
                    "CANNOT PROVE (sample {n}): no echo through the forward ({e}).\n{}",
                    w.fwd.as_mut().unwrap().transcript()
                )
            });
        assert_eq!(
            back,
            payload.as_bytes(),
            "sample {n}: the echo came back changed"
        );
        w.expect_still_relayed();
        let said = w.fwd.as_mut().unwrap().transcript();
        let sample = reached(&said).unwrap_or_else(|| {
            panic!("sample {n}: the forward never said how long reaching the host took:\n{said}")
        });
        samples.push(sample);
    }
    w.assert_relayed("after the samples");

    let mut ms: Vec<u64> = samples.iter().map(|(m, _)| *m).collect();
    ms.sort_unstable();
    eprintln!(
        "[proof] {SAMPLES} cold first connections over the relay: {} ms (min {} / median {} / max {})",
        samples.iter().map(|(m, _)| m.to_string()).collect::<Vec<_>>().join(", "),
        ms[0],
        ms[ms.len() / 2],
        ms[ms.len() - 1]
    );
    for (m, line) in &samples {
        assert!(
            Duration::from_millis(*m) < R42,
            "a first relayed connection took {m} ms, over PRD-001 R42's {R42:?}: {line}"
        );
    }
}
