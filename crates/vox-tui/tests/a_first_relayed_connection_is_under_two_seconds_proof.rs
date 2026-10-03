//! RP-24 (#131), for #167 — **a first relayed connection completes in under 2 s**, through the
//! shipped binary (PRD-001 R42: "a first connection to a peer, including NAT traversal, must
//! complete in under 2 s").
//!
//! It replaces `crates/vox-core/tests/perf_r42_first_connect_relay_gate.rs`, an in-process gate on
//! a NAT simulator that is already deleted (V29-17).
//!
//! **Timed from outside, by this test's own clock** (#91, attempt 1). The clock starts when the
//! test reads the guest's `vox up on <address>` line — the moment a person sees the proxy is up
//! and asks it for the host's service — and stops when the **first echoed byte** of that request
//! comes back through the proxy. Everything the person waits for in between is on it: the SOCKS5
//! exchange, the node's wait for its anchor, the reach (direct head start, circuit, any retry), the
//! host's side and the echo. The two production-Argon2id unlocks `vox up` does before it can take
//! a request are outside it, as for R42's direct and punched arms: a person waits for them at the
//! prompt. The proof used to read `vox forward`'s own "reached … in N ms", which counts from the
//! forward's first attempt: a wait before that attempt was never on the clock.
//!
//! **Relayed, and asserted.** The host listens on IPv4 and the guest on IPv6 (`support/relay.rs`,
//! `Split::Families`), so the only path is a circuit through the anchor (ADR-012 rung 4); the
//! guest's own "still relayed" line and the anchor's circuit count are asserted, never assumed.
//! Either missing is `CANNOT MEASURE`: nothing staged a relayed path.
//!
//! **Cold.** Each of [`SAMPLES`] is a new `vox up`: a new process, a new node, a new port, no
//! connection kept from the sample before (the previous one is killed by its PID first).
//!
//! **A restart is as quick as a first start** (V210-57, #243). Samples 1 on are each a new process
//! of an identity whose previous process was just killed, and the anchor still held that
//! predecessor's connection. It used to probe it for `probe_patience`'s 250 ms floor on every
//! restart, and could keep it: CI run 36418572653 had a sample at 30065 ms. The anchor now
//! supersedes another process's connections outright, so every restart sample is asserted under
//! [`RESTART_WITHIN`] on the same outside clock (a sample whose proxy first found no anchor
//! connected yet, "no peer is connected to carry a circuit", waited on its own start-up and is held
//! to R42 only), and the anchor must say it superseded the previous
//! process on each restart and never put the restarted guest to a tie-break.
//!
//! **Every red is labelled**: `PRODUCT` when the product did the wrong thing, `CANNOT MEASURE` when
//! the staging did not happen or the harness could not see, `APPARATUS` when the test's own
//! machinery failed.
//!
//! Mutations: a 2.5 s sleep in `vox up`'s request path before it reaches for the host (the wait
//! the old clock could not see) makes every sample exceed [`R42`]: red, as PRODUCT. A circuit that
//! waits out the direct head start with no direct dial under way makes every restart exceed
//! [`RESTART_WITHIN`]; so does an anchor that stops superseding another process's connections,
//! which also says no supersede.

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

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::socks5_connect;

/// PRD-001 R42.
const R42: Duration = Duration::from_secs(2);
/// Cold first connections measured; the bound is asserted on every one.
const SAMPLES: usize = 10;
/// A restart (samples 1 on) connects this fast: a relayed reach's direct head start (V210-122)
/// plus 150 ms, under the head start plus the 250 ms a probe of the dead predecessor cost.
const RESTART_WITHIN: Duration =
    vox_core::node::network::DIRECT_HEAD_START.saturating_add(Duration::from_millis(150));
/// What the proxy says of an attempt made before its node had any anchor connected.
const NO_HELPER_YET: &str = "no peer is connected to carry a circuit";
/// What the anchor says when a newcomer supersedes another process of its identity.
const SUPERSEDED: &str = "a new connection is from a new process of this identity";
/// How long one request may wait for its first echoed byte before it counts as never answered.
const GIVE_UP: Duration = Duration::from_secs(60);

/// One request through the proxy at `proxy`: CONNECT to the host's service, send `payload`, and
/// return when its first byte came back, after reading the whole echo.
fn request(w: &mut RelayWorld, proxy: std::net::SocketAddr, payload: &[u8], n: usize) -> Instant {
    let port: u16 = w
        .service
        .parse()
        .unwrap_or_else(|_| panic!("APPARATUS: the echo service {:?} is not a port", w.service));
    let (reply, mut s) = socks5_connect(proxy, &w.hostname(), port);
    let mut said = || {
        w.fwd
            .as_mut()
            .map(world::VoxProc::transcript)
            .unwrap_or_default()
    };
    if reply != 0 {
        let said = said();
        panic!("PRODUCT (sample {n}): the proxy refused CONNECT to the host's service (reply {reply}).\n{said}");
    }
    s.set_read_timeout(Some(GIVE_UP))
        .unwrap_or_else(|e| panic!("APPARATUS: could not set a read timeout: {e}"));
    s.write_all(payload).unwrap_or_else(|e| {
        let said = said();
        panic!("PRODUCT (sample {n}): the proxy took the CONNECT, then refused the request's bytes ({e}).\n{said}")
    });
    let mut back = vec![0u8; payload.len()];
    s.read_exact(&mut back[..1]).unwrap_or_else(|e| {
        let said = said();
        panic!("PRODUCT (sample {n}): no echo came back through the proxy within {GIVE_UP:?} ({e}).\n{said}")
    });
    let first = Instant::now();
    s.read_exact(&mut back[1..]).unwrap_or_else(|e| {
        let said = said();
        panic!("PRODUCT (sample {n}): the echo stopped after its first byte ({e}).\n{said}")
    });
    assert!(
        back == payload,
        "PRODUCT (sample {n}): the echo came back changed: sent {payload:?}, got {back:?}"
    );
    first
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

    let guest_fp = world::fingerprint(&w.guest_dir, "guest")
        .chars()
        .take(26)
        .collect::<String>();
    // Only what the anchor says from the first proxy on counts for the restart claims.
    let mark = w.anchor.proc.transcript().lines().count();
    let mut samples: Vec<Duration> = Vec::new();
    // Per sample: the proxy found no anchor connected yet on an attempt (a wait on its start-up).
    let mut before_its_anchor: Vec<bool> = Vec::new();
    for n in 0..SAMPLES {
        // A fresh `vox up` each time: the previous one's process is killed by its PID first.
        drop(w.fwd.take());
        let (proxy, ready) = w.up();
        let payload = format!("sample {n}");
        let first = request(&mut w, proxy, payload.as_bytes(), n);
        let waited = first - ready;
        eprintln!(
            "[proof] sample {n}: first echoed byte {} ms after `vox up` said it was up",
            waited.as_millis()
        );
        w.expect_still_relayed();
        before_its_anchor.push(
            w.fwd
                .as_mut()
                .map(world::VoxProc::transcript)
                .unwrap_or_default()
                .lines()
                .any(|l| l.contains(NO_HELPER_YET)),
        );
        samples.push(waited);
    }
    w.assert_relayed("after the samples");

    let mut ms: Vec<u128> = samples.iter().map(Duration::as_millis).collect();
    ms.sort_unstable();
    eprintln!(
        "[proof] {SAMPLES} cold first connections over the relay, outside clock: {} ms (min {} / median {} / max {})",
        samples.iter().map(|d| d.as_millis().to_string()).collect::<Vec<_>>().join(", "),
        ms[0],
        ms[ms.len() / 2],
        ms[ms.len() - 1]
    );
    let guest_said = w
        .fwd
        .as_mut()
        .map(world::VoxProc::transcript)
        .unwrap_or_default();
    if samples.iter().any(|d| *d >= R42) {
        // A red names its cause from the other ends too: the anchor carrying the circuits and the
        // host behind them, whose connection notes say what they did with each new process (#229).
        eprintln!("---- the anchor said ----\n{}", w.anchor.proc.transcript());
        if let Some(host) = w.host.as_mut() {
            eprintln!("---- the host said ----\n{}", host.transcript());
        }
    }
    for (n, d) in samples.iter().enumerate() {
        assert!(
            *d < R42,
            "PRODUCT: sample {n}'s first relayed connection took {} ms from `vox up` saying it was up \
             to the first echoed byte, over PRD-001 R42's {R42:?}.\nthe last proxy said:\n{guest_said}",
            d.as_millis()
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
    let mut judged = 0;
    for (n, d) in samples.iter().enumerate().skip(1) {
        if before_its_anchor[n] {
            eprintln!(
                "[proof] restart {n}: {} ms, not held to {RESTART_WITHIN:?}: its proxy found no \
                 anchor connected yet ({NO_HELPER_YET:?}), a wait on its own start-up",
                d.as_millis()
            );
            continue;
        }
        judged += 1;
        assert!(
            *d < RESTART_WITHIN,
            "PRODUCT: restart {n} took {} ms to its first echoed byte, over {RESTART_WITHIN:?} — a \
             restarted process waited on something before its circuit.\nthe last proxy said:\n\
             {guest_said}\nthe anchor said:\n{}",
            d.as_millis(),
            anchor_said.join("\n")
        );
    }
    assert!(
        judged > 0,
        "CANNOT MEASURE: every restart's first attempt found no anchor connected yet, so none \
         measures a wait on a predecessor"
    );
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
