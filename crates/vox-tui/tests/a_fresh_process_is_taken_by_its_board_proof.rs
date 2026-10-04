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
//! (`VOX_TEST_CLOCK_STEP_MS`, test-only, inert when unset — the clock that floors a record's
//! `seq`). B publishes as long after A as it takes to start (kill, unlock, bind): about a second in
//! a release build, and as much as 15 s in a debug build, whose production Argon2id unlock alone
//! was measured at 6–14 s (V210-99). So B's clock is behind by [`SKEW_MS`] **plus** what A, started
//! the same way a moment before, took from spawn to its bound address — B's own start, measured on
//! this machine in this sample — and its first record is at or below A's: refused as stale. With a
//! fixed skew a debug build's start used the skew up, and B was never refused (#295). Its republishes, a second apart, each move its `seq` floor further
//! past its clock (V210-61) until one passes A's. A fixed predecessor per sample keeps every sample alike; one skew across a chain
//! of forwards did not (each as far behind as the last: only the first was ever refused).
//!
//! **Read through the product.** Each forward's own stderr says the refusal was cured (or not); the
//! anchor's `vox node` prints the address its board holds for each member (`board — <room> holding
//! <addr> … for <member>`).
//!
//! **What must hold, every sample:** the forward reports its address refused as stale **and taken
//! on a republish**; it never reports a refusal left uncured; and the anchor, in lines printed
//! after the sample began, holds **that** process's address for the guest. A sample whose forward
//! says neither — no cure, no refusal left uncured — while the anchor holds its address at once was
//! never refused, so it cannot measure the republish: it is counted apart and is neither green nor
//! red, and fewer than [`MIN_REFUSED`] refused samples is PRODUCT (staging). (A refusal that is never
//! cured cannot hide there: the anchor would go on holding A's address, and the forward says the
//! refusal once its grace is over.)
//!
//! Mutations: `NetEvent::RepublishTo` does nothing; the republish sent at once instead of past the
//! second; no republish at all (cap 0); the `seq` floor left where the clock puts it (V210-61); the
//! `timestamp` floor left where the clock puts it (V210-64) — each red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::{args, vox_once, VoxProc};

/// Cold forwards, one after another.
const SAMPLES: usize = 5;
/// How far behind B's clocks run, beyond B's own start (see the module docs) — **both**, the milliseconds that floor `seq` and the seconds a
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
/// How many samples must be refused, so that the republish was exercised.
const MIN_REFUSED: usize = 3;
/// What a forward prints when a republish is taken after a refusal as stale.
const CURED: &str = "was taken on a republish, after the board refused it as stale";
/// What a node prints when a board would not take its own address, and no republish cured it.
const REFUSED: &str = "would not take our address";

/// A UDP port nobody holds right now.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("APPARATUS: bind a socket")
        .local_addr()
        .expect("APPARATUS: read a socket the proof bound")
        .port()
}

/// A `vox forward` of the guest's identity on UDP `port`, with its millisecond clock skewed if asked.
fn spawn_forward(w: &RelayWorld, port: u16, skew: Option<&str>) -> VoxProc {
    let listen = format!("127.0.0.1:{port}");
    let env: Vec<(&str, &str)> = skew
        // A whole clock step, both clocks (V210-64): `VOX_TEST_CLOCK_SKEW_MS` moves the
        // millisecond clock only, and would prove half the cure.
        .map(|s| vec![("VOX_TEST_CLOCK_STEP_MS", s)])
        .unwrap_or_default();
    VoxProc::spawn_env(
        "forward",
        &w.guest_dir,
        &args(&[
            "forward",
            &format!("{}.{}.{}.vox", w.service, w.host_fp, w.room),
            "127.0.0.1:0",
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
    test_knobs::require(&["VOX_TEST_CLOCK_STEP_MS"]);
    watchdog::arm();
    // A fixed skew, in place of SKEW_MS beyond B's start, for a manual experiment.
    let fixed_skew: Option<i64> = std::env::var("VOX_PROOF_230_SKEW_MS")
        .ok()
        .and_then(|v| v.parse().ok());
    let mut w = RelayWorld::new(Split::None);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "PRODUCT (staging): the guest could not join ({took:?}).\n{out}\n{err}"
    );
    let (ok, guest_fp, err) = vox_once(&w.guest_dir, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): vox id (guest): {err}");
    let guest: String = guest_fp.trim().chars().take(26).collect();

    let mut failures: Vec<String> = Vec::new();
    let mut refusals = 0usize;
    let mut unrefused = 0usize;
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
        let a_spawned = Instant::now();
        let mut a = spawn_forward(&w, a_port, None);
        a.expect_line("A's bound address", |l| l.starts_with("vox: forwarding "));
        let a_start = a_spawned.elapsed();
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
                "PRODUCT (staging): sample {n}'s previous process was never held by the anchor"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(a);
        let mark = w.anchor.proc.transcript().lines().count();
        // B: the fresh process, behind by SKEW_MS beyond its own start, measured as A's.
        let skew = fixed_skew.unwrap_or(SKEW_MS - a_start.as_millis() as i64);
        let port = free_udp_port();
        let mut fwd = spawn_forward(&w, port, Some(&skew.to_string()));
        fwd.expect_line("the forward's bound address", |l| {
            l.starts_with("vox: forwarding ")
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
            "[proof] sample {n} (A started in {a_start:?}; B's clock {skew} ms): refused and cured \
             after {cured:?}; uncured refusals said: {refused}; the anchor holds its address after \
             {held:?}"
        );
        if cured.is_none() && refused == 0 && held.is_some() {
            // Never refused: taken on its first publish. It measures nothing here.
            unrefused += 1;
            w.fwd = Some(fwd);
            continue;
        }
        refusals += 1;
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
    eprintln!(
        "[proof] {refusals} of {samples} samples were refused as stale, {unrefused} never were; \
         {} failure(s) among the refused",
        failures.len()
    );
    assert!(
        refusals >= MIN_REFUSED.min(samples),
        "PRODUCT (staging): only {refusals} of {samples} samples were refused (B's clock not far enough \
         behind its predecessor's), so the republish was exercised too seldom"
    );
    assert!(
        failures.is_empty(),
        "PRODUCT: a fresh process's address was not taken by its board: {failures:?}"
    );
}
