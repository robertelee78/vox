//! V210-51 (#230) — **a fresh process's address is taken by its board**, through the shipped binary.
//!
//! A board replaces a member's record only with a later `seq` and `timestamp` (ADR-012's bound of
//! one changed claim a second per author, `nat::store::check_replacement`). A process that signs
//! its first record at or below its predecessor's — in the same second, or with a clock a moment
//! behind — was refused as stale, and the board went on naming the previous, dead process's address
//! until the next publish round. Every cold `vox forward` on integrate 1de7548 logged `a board would
//! not take our address … the board holds a newer record from that author`.
//!
//! The node now publishes its own record again just past the next second when a board refuses it
//! as stale (`NetEvent::RepublishTo`, at most three in a row), says so when a republish is taken
//! (`vox: our address (board …) … was taken on a republish, after the board refused it as stale`),
//! and says a refusal no republish cured once its short grace is over — held, never dropped.
//!
//! **Staged, not hoped for.** A fresh process usually publishes more than a second after its
//! predecessor, so back to back the refusal came or not by chance (#230's first verdict: 0 of 30
//! samples refused in two runs). So each sample is a pair of processes of the guest's identity:
//! **A**, a plain `vox forward` whose address the anchor is seen to hold, then killed; and **B**, a
//! `vox forward` started at once with its millisecond clock [`SKEW_MS`] behind
//! (`VOX_TEST_CLOCK_SKEW_MS`, test-only, inert when unset — the clock that floors a record's
//! `seq`). B publishes about a second after A (kill, unlock, bind), so its first record is at or
//! below A's: refused as stale. Its republishes, a second apart, each move its `seq` floor further
//! past its clock (V210-61) until one passes A's. A fixed predecessor per sample keeps every sample alike; one skew across a chain
//! of forwards did not (each as far behind as the last: only the first was ever refused).
//!
//! **Read through the product.** Each forward's own stderr says the refusal was cured (or not); the
//! anchor's `vox node` prints the address its board holds for each member (`board — <room> holding
//! <addr> … for <member>`).
//!
//! **What must hold, every sample:** the forward reports its address refused as stale **and taken
//! on a republish** (a sample with no refusal is CANNOT MEASURE); it never reports a refusal left
//! uncured; and the anchor, in lines printed after the sample began, holds **that** process's
//! address for the guest.
//!
//! Mutations: `NetEvent::RepublishTo` does nothing; the republish sent at once instead of past the
//! second; no republish at all (cap 0); the `seq` floor left where the clock puts it (V210-61); the
//! `timestamp` floor left where the clock puts it (V210-64) — each red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::{args, vox_once, VoxProc};

/// Cold forwards, one after another.
const SAMPLES: usize = 5;
/// How far behind B's clocks run — **both**, the milliseconds that floor `seq` and the seconds a
/// record is stamped with, as in a real clock step (V210-64) — **further than waiting can cure**
/// (V210-61). At
/// -2500 ms the cure came on the last of the three tries in 57 of 60 samples on integrate dd78874,
/// and now and then not at all, because each try only waited a second for the clock. Five
/// seconds is out of reach of three such waits, so this stage is red unless each republish also
/// moves the record's `seq` floor past the clock.
const SKEW_MS: i64 = -5000;
/// How long a sample may take, from binding, to report its refusal cured and have the anchor hold
/// its address: the republishes go a second apart, three at most.
const CURED_WITHIN: Duration = Duration::from_secs(7);
/// What a forward prints when a republish is taken after a refusal as stale.
const CURED: &str = "was taken on a republish, after the board refused it as stale";
/// What a node prints when a board would not take its own address, and no republish cured it.
const REFUSED: &str = "would not take our address";

/// A UDP port nobody holds right now.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A `vox forward` of the guest's identity on UDP `port`, with its millisecond clock skewed if asked.
fn spawn_forward(w: &RelayWorld, port: u16, skew: Option<&str>) -> VoxProc {
    let listen = format!("127.0.0.1:{port}");
    let env: Vec<(&str, &str)> = skew
        .map(|s| vec![("VOX_TEST_CLOCK_SKEW_MS", s)])
        .unwrap_or_default();
    VoxProc::spawn_env(
        "forward",
        &w.guest_dir,
        &args(&[
            "forward",
            &w.room,
            &w.host_fp,
            &w.service,
            "127.0.0.1:0",
            "--passphrase",
            &w.passphrase,
            "--anchor",
            &w.anchor.v4_spec,
            "--listen",
            &listen,
        ]),
        &env,
    )
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_fresh_process_is_taken_by_its_board() {
    watchdog::arm();
    let skew: i64 = std::env::var("VOX_PROOF_230_SKEW_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SKEW_MS);
    let skew_env = skew.to_string();
    let mut w = RelayWorld::new(Split::None);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT PROVE: the guest could not join ({took:?}).\n{out}\n{err}"
    );
    let (ok, guest_fp, err) = vox_once(&w.guest_dir, &args(&["id"]));
    assert!(ok, "vox id (guest): {err}");
    let guest: String = guest_fp.trim().chars().take(26).collect();

    let mut failures: Vec<String> = Vec::new();
    let mut refusals = 0usize;
    let samples: usize = std::env::var("VOX_PROOF_230_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(SAMPLES);
    for n in 0..samples {
        // Only the anchor's lines printed from here on count for this sample.
        drop(w.fwd.take());
        let mark = w.anchor.proc.transcript().lines().count();
        // A: the previous process, plain, until the anchor holds its address.
        let a_port = free_udp_port();
        let mut a = spawn_forward(&w, a_port, None);
        a.expect_line("A's bound address", |l| {
            l.starts_with("vox: 127.0.0.1:") && l.contains('→')
        });
        let a_tag = format!("/udp/{a_port}");
        let deadline = Instant::now() + CURED_WITHIN;
        loop {
            let anchor = w.anchor.proc.transcript();
            if anchor.lines().skip(mark).any(|l| {
                l.contains(" holding ")
                    && l.contains(&a_tag)
                    && l.ends_with(&format!(" for {guest}"))
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE: sample {n}'s previous process was never held by the anchor"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(a);
        let mark = w.anchor.proc.transcript().lines().count();
        // B: the fresh process, a moment behind.
        let port = free_udp_port();
        let mut fwd = spawn_forward(&w, port, Some(&skew_env));
        fwd.expect_line("the forward's bound address", |l| {
            l.starts_with("vox: 127.0.0.1:") && l.contains('→')
        });
        let bound = Instant::now();
        let port_tag = format!("/udp/{port}");
        let for_guest = format!(" for {guest}");
        let (mut cured, mut refused, mut held) = (None, 0usize, None);
        while bound.elapsed() < CURED_WITHIN {
            let said = fwd.transcript();
            if cured.is_none() && said.contains(CURED) {
                cured = Some(bound.elapsed());
            }
            refused = said.lines().filter(|l| l.contains(REFUSED)).count();
            if held.is_none() {
                let anchor = w.anchor.proc.transcript();
                if anchor.lines().skip(mark).any(|l| {
                    l.contains(" holding ") && l.contains(&port_tag) && l.ends_with(&for_guest)
                }) {
                    held = Some(bound.elapsed());
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        eprintln!(
            "[proof] sample {n} (clock {skew} ms): refused and cured after {cured:?}; uncured \
             refusals said: {refused}; the anchor holds its address after {held:?}"
        );
        if cured.is_some() || refused > 0 {
            refusals += 1;
        }
        if cured.is_none() {
            failures.push(format!("sample {n}: never reported its refusal cured"));
        }
        if refused > 0 {
            failures.push(format!(
                "sample {n}: {refused} uncured refusal(s) said:\n{}",
                fwd.transcript()
            ));
        }
        if held.is_none() {
            failures.push(format!(
                "sample {n}: the anchor never held its address (port {port}) within {CURED_WITHIN:?}"
            ));
        }
        w.fwd = Some(fwd);
    }
    eprintln!("[proof] {refusals} of {samples} samples were refused as stale");
    assert!(
        refusals > 0,
        "CANNOT MEASURE: no sample was refused (clock {skew} ms is not far enough behind), so the \
         republish was never exercised"
    );
    assert!(
        failures.is_empty(),
        "a fresh process's address was not taken by its board: {failures:?}"
    );
}
