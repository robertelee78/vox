//! PRD-001 **R42, punch** (both behind port-restricted-cone NATs: rung 3, a coordinated simultaneous open) — a **first connection** to a peer, cold, including NAT traversal,
//! completes in **under 2 s**.
//!
//! Measured on the NAT simulator (`support/vnet.rs`) with real nodes, because the shipped
//! binary has no way to put itself behind a NAT: the three topologies the ADR-012 ladder
//! distinguishes each get [`SAMPLES`] cold connections —
//!
//! - **open**: both nodes on public addresses (rung 1, a direct dial);
//! - **punch**: both behind port-restricted-cone NATs, so an unsolicited datagram is
//!   dropped and only a coordinated simultaneous open gets through (rung 3);
//! - **relay**: both behind symmetric NATs, which defeat the punch, so the only path is a
//!   circuit through the anchor (rung 4).
//!
//! **What "cold" means here.** Alice and bob are already members of one room and trust each
//! other — the state two people are in the day after they met. For each sample bob's node
//! is shut down and a **new** one is started on a **new** address behind a **new** NAT, so
//! no mapping, no filter and no connection survives from the last sample; bob unlocks and
//! opens the room (the two production-Argon2id steps a person waits for at the prompt,
//! excluded from the clock), and the clock then runs from bob's first request that needs
//! alice — a `Forward` to her, which is what `vox forward` and `vox up` send — until the
//! node answers that it has a path. That wait is what the ADR-012 ladder, the anchor's
//! board and the punch coordination together decide. (A node that has just come up does
//! not dial its room's members on its own; measured, it sat connected to the anchor alone
//! for 60 s. So "first connection" is the first one something asks for.)
//!
//! The simulator delivers every datagram at once, so a red here is the node's time, not a
//! network's. Printed per topology as min / median / p95 / max; the PRD target is asserted
//! on every sample.
//!
//! Mutation knobs (test-side only): `VOX_PERF_THRESHOLD_MS` replaces the target;
//! `VOX_PERF_INJECT_MS` sleeps inside the timed window.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

#[path = "support/perf_r42.rs"]
mod perf_r42;

#[test]
#[ignore = "twenty cold restarts on the NAT simulator with production Argon2id, 7-17 min; CI runs it in release"]
fn r42_a_first_connection_completes_in_under_two_seconds_punch() {
    // **Long by construction, not hung.** Twenty cold restarts, each waiting for alice to
    // notice the old node went away (about 6.5 s, measured) and paying two production
    // Argon2id steps, measured at 430–1025 s a topology — past the watchdog's 600 s
    // default. So this binary's budget is raised, unless an operator already set one.
    if std::env::var_os("VOX_TEST_WATCHDOG_SECS").is_none() {
        std::env::set_var("VOX_TEST_WATCHDOG_SECS", "1800");
    }
    watchdog::arm();
    perf_r42::run(perf_r42::Topology::Punch);
}
