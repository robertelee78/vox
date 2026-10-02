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
//! **A restart is as quick as a first start** (V210-57, #243). Samples 1 on are each a new process
//! of an identity whose previous process was just killed, and the anchor still held that
//! predecessor's connection. It used to probe it for `probe_patience`'s 250 ms floor on every
//! restart (samples 1–4 at 250–258 ms against sample 0's 6–30 ms, both trees), and could keep it:
//! CI run 36418572653 had a sample at 30065 ms after the anchor closed the restarted process's
//! connection. The anchor now supersedes another process's connections outright, so every restart
//! sample is asserted under [`RESTART_WITHIN`], and the anchor must say it superseded the previous
//! process on each restart and never put the restarted guest to a tie-break.
//!
//! Mutations: make the ladder's circuit rung wait (or remove it) and every sample either exceeds
//! [`R42`] or never connects; stop superseding another process's connections and the restart
//! samples exceed [`RESTART_WITHIN`], with no supersede said.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_first_relayed_connection_completes_in_under_two_seconds);

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
/// A restart (samples 1 on) connects this fast: under the 250 ms a probe of the dead predecessor
/// cost, with margin for a loaded box. Sample 0 took 6–30 ms.
const RESTART_WITHIN: Duration = Duration::from_millis(150);
/// What the anchor says when a newcomer supersedes another process of its identity.
const SUPERSEDED: &str = "a new connection is from a new process of this identity";

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

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "real binaries, production Argon2id and a PoW; optional, run it in release"]
fn a_first_relayed_connection_completes_in_under_two_seconds() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "PRODUCT: the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );

    let guest_fp = {
        let (ok, out, err) = world::vox_once(&w.guest_dir, &world::args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id (guest): {err}");
        out.trim().chars().take(26).collect::<String>()
    };
    // Only what the anchor says from the first forward on counts for the restart claims.
    let mark = w.anchor.proc.transcript().lines().count();
    let mut samples: Vec<(u64, String)> = Vec::new();
    for n in 0..SAMPLES {
        // A fresh `vox forward` each time: the previous one's process is killed by its PID first.
        drop(w.fwd.take());
        let at = w.forward();
        let payload = format!("sample {n}");
        let back =
            round_trip(at, payload.as_bytes(), Duration::from_secs(120)).unwrap_or_else(|e| {
                panic!(
                    "PRODUCT (sample {n}): no echo through the forward ({e}).\n{}",
                    w.fwd
                        .as_mut()
                        .map(world::VoxProc::transcript)
                        .unwrap_or_default()
                )
            });
        assert_eq!(
            back,
            payload.as_bytes(),
            "PRODUCT: sample {n}: the echo came back changed"
        );
        w.expect_still_relayed();
        let said = w
            .fwd
            .as_mut()
            .map(world::VoxProc::transcript)
            .unwrap_or_default();
        let sample = reached(&said).unwrap_or_else(|| {
            panic!("PRODUCT: sample {n}: the forward never said how long reaching the host took:\n{said}")
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
    if samples
        .iter()
        .any(|(m, _)| Duration::from_millis(*m) >= R42)
    {
        // A red names its cause from the other ends too: the anchor carrying the circuits and the
        // host behind them, whose connection notes say what they did with each new process (#229).
        eprintln!("---- the anchor said ----\n{}", w.anchor.proc.transcript());
        if let Some(host) = w.host.as_mut() {
            eprintln!("---- the host said ----\n{}", host.transcript());
        }
    }
    for (m, line) in &samples {
        assert!(
            Duration::from_millis(*m) < R42,
            "PRODUCT: a first relayed connection took {m} ms, over PRD-001 R42's {R42:?}: {line}"
        );
    }
    // ---- a restart is as quick as a first start, and the anchor supersedes, never weighs ----
    let anchor_said: Vec<String> = w
        .anchor
        .proc
        .transcript()
        .lines()
        .skip(mark)
        .filter(|l| l.contains(&format!("connection to {guest_fp}")))
        .map(str::to_owned)
        .collect();
    let superseded = anchor_said
        .iter()
        .filter(|l| l.contains(SUPERSEDED))
        .count();
    let weighed: Vec<&String> = anchor_said
        .iter()
        .filter(|l| l.contains("tie-break"))
        .collect();
    eprintln!(
        "[proof] the anchor on the guest's {} restarts: superseded the previous process {superseded} \
         time(s), tie-breaks {}",
        SAMPLES - 1,
        weighed.len()
    );
    for (n, (m, line)) in samples.iter().enumerate().skip(1) {
        assert!(
            Duration::from_millis(*m) < RESTART_WITHIN,
            "PRODUCT: restart {n} took {m} ms, over {RESTART_WITHIN:?} — a restarted process waited on its \
             dead predecessor: {line}\nthe anchor said:\n{}",
            anchor_said.join("\n")
        );
    }
    assert!(
        superseded >= SAMPLES - 1,
        "PRODUCT: the anchor superseded the guest's previous process {superseded} time(s) in {} restarts:\n{}",
        SAMPLES - 1,
        anchor_said.join("\n")
    );
    assert!(
        weighed.is_empty(),
        "PRODUCT: the anchor put a restarted guest to a tie-break against its predecessor:\n{}",
        anchor_said.join("\n")
    );
}
