//! ADR-012 M15.1b, RP-25 / V29-14 (#132, #49) — **a pair that starts out relayed keeps trying for a
//! direct path, and finds one once one becomes possible**, driven through the shipped `vox` binary.
//!
//! A relayed path works, so nothing forces a retry. But it spends a third party's bandwidth, adds a
//! hop, and lets that third party see who talks to whom. The one attempt made when the pair first
//! connects happens at the worst moment; without a retry a pair that starts relayed stays relayed
//! for the life of the connection. The field case: a guest reaches its host while no direct path
//! exists, and then the network changes — a router's port forward comes up, a firewall state
//! clears. Nothing tells either node. They must find it anyway.
//!
//! **The staging — real processes only.** A `vox node` anchor on `[::]` (dual-stack), a `vox serve`
//! host on `127.0.0.1`, and the guest on `[::1]`, set up with `vox id`, `vox trust add` and
//! `vox connect`; the guest then runs `vox up` and asks it for the host's service over SOCKS5, as
//! `ssh user@<room>.vox` does. Split by address family, host and guest cannot send each other a
//! datagram (`support/relay.rs`). The host advertises a **port forward** the proof owns
//! (`support/port_forward.rs`, via the proof-only `VOX_TEST_ADVERTISE`) — an `[::1]` socket that
//! carries datagrams to and from the host — which is therefore the pair's only possible direct
//! path. It starts **closed** (it drops every datagram), so the only path is the anchor's circuit;
//! then, with both processes still running, it is **opened**, and a direct path exists.
//!
//! **What is observed, never assumed:**
//! - relayed at the start: the anchor reports a circuit carried, the first request's echo did not
//!   cross the forward, and the forward dropped the direct attempts made at it;
//! - the pair keeps trying: `vox up` says `still relayed` for a first attempt and then **again** for
//!   a later one, within [`TRIED_AGAIN_WITHIN`] — a retry, not the connect-time attempt;
//! - it finds the direct path: after the forward opens, a request's echo **crosses the forward**
//!   (its bytes are counted there) within [`UPGRADED_WITHIN`].
//!
//! **Bounds are numbers.** The product retries a relayed peer every `UPGRADE_RETRY` = 60 s
//! (tailscale's `upgradeUDPDirectInterval`). The forward opens just after an attempt failed, so the
//! next one is at most 60 s away: [`UPGRADED_WITHIN`] = 75 s and [`TRIED_AGAIN_WITHIN`] = 75 s allow
//! that interval and 15 s of margin, written here as literals so a longer interval goes red.
//!
//! - **the relay is not held back** (V210-122): with the forward closed, a `vox forward` reaches the
//!   host over the anchor's circuit within [`RELAYED_REACH_WITHIN`] = 1000 ms, and the anchor
//!   carries that circuit. The direct dial's head start is the whole extra cost.
//!
//! **The mutations that must turn it red:** `retry_upgrades_if_due` returning at once (nothing
//! retries — no second attempt, and the opened forward is never found); and `UPGRADE_RETRY` raised
//! to 600 s (the retry comes too late for both bounds). And for V210-122: `DIRECT_HEAD_START` raised
//! to 2 s, so the relay is held back past the bound.
//!
//! Replaces `crates/vox-core/tests/relayed_path_is_retried.rs`, which ran every node in process on
//! a NAT simulator with an injected clock.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

#[path = "support/port_forward.rs"]
mod port_forward;

use std::time::{Duration, Instant};

use port_forward::{echo_over, interrupt, ForwardedWorld};
use world::socks5_connect;

/// A relayed pair's next attempt must follow its last within this: the product's 60 s interval
/// and 15 s of margin. A number, not the product constant.
const TRIED_AGAIN_WITHIN: Duration = Duration::from_secs(75);
/// From the forward opening to a request riding it. Same reasoning.
const UPGRADED_WITHIN: Duration = Duration::from_secs(75);
/// How long the first attempt may take to report: the connect-time ladder, on a loaded box.
const FIRST_ATTEMPT_WITHIN: Duration = Duration::from_secs(90);
/// Big enough that a request which rode the forward is unmistakable in its byte count.
const PAYLOAD: usize = 16 * 1024;

/// How long a `vox forward` may take to reach the host when only the anchor's circuit can (V210-122):
/// the direct dial's 250 ms head start, the circuit (measured: 255 ms and 268 ms in all on the
/// candidate), and margin for a loaded box. A number, not the product constant: a longer head start
/// goes red.
const RELAYED_REACH_WITHIN: Duration = Duration::from_millis(1000);

/// Start the guest's `vox forward` to the host's service through the closed forward, and read how
/// long it says reaching the host took; it is returned still running, for the caller to stop.
fn relayed_reach_ms(w: &ForwardedWorld) -> (u128, world::VoxProc) {
    use world::{args, room_pass_file, VoxProc};
    let mut fwd = VoxProc::spawn(
        "forward",
        &w.guest_dir,
        &args(&[
            "forward",
            &w.room,
            &w.host_fp,
            &w.service_port.to_string(),
            "127.0.0.1:0",
            "--passphrase-file",
            &room_pass_file(&w.guest_dir, &w.passphrase),
            "--anchor",
            &w.anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    let line = fwd.expect_line(
        "`vox forward` saying how long reaching the host took",
        |l| l.contains("vox: reached ") && l.contains(" ms ("),
    );
    let ms = line
        .split(" in ")
        .nth(1)
        .and_then(|r| r.split(" ms").next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("CANNOT MEASURE: no duration in `vox forward`'s line {line:?}"));
    (ms, fwd)
}

fn is_still_relayed(l: &str) -> bool {
    l.starts_with("! vox: still relayed to")
}

#[test]
#[ignore = "production Argon2id + a real PoW, a relayed pair held across two 60 s retries; run in release"]
fn a_relayed_pair_finds_a_direct_path_once_one_becomes_possible() {
    watchdog::arm();
    let mut w = ForwardedWorld::new(false);
    eprintln!(
        "[proof] guest joined through the relay in {:?}; the forward at {} (closed) stands for the \
         host at {}",
        w.joined_in, w.forward.public, w.forward.host
    );
    let hostname = w.hostname();
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();

    // **The relay is not held back for long** (V210-122). A direct dial now gets a head start
    // before any circuit is asked for; for a pair that cannot reach each other directly, that head
    // start is the whole cost. A `vox forward` says how long reaching the host took; through the
    // closed forward, only the anchor's circuit can reach it, and it must still do so promptly.
    let (reached_ms, mut fwd) = relayed_reach_ms(&w);
    eprintln!(
        "[proof] `vox forward` reached the host over the anchor's circuit in {reached_ms} ms"
    );
    // Read while the forward still holds its circuit: stopped, it closes it.
    w.anchor
        .assert_relayed("after `vox forward` reached the host");
    interrupt(&mut fwd, Duration::from_secs(15));
    drop(fwd);
    assert!(
        reached_ms < RELAYED_REACH_WITHIN.as_millis(),
        "PRODUCT: a pair with no direct path took {reached_ms} ms to reach each other through the \
         anchor, past {RELAYED_REACH_WITHIN:?}: the direct dial's head start held the relay back"
    );

    let (mut up, proxy, _ready) = w.up("up");

    // Relayed, observed three ways.
    let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
    assert_eq!(
        code,
        0,
        "CANNOT MEASURE: the guest's first request to {hostname} was refused (SOCKS {code}), so \
         there is no relayed pair to watch.\nup:\n{}",
        up.transcript()
    );
    let sent = w.forward.to_host();
    assert!(
        echo_over(&mut s, &payload, Duration::from_secs(60)),
        "CANNOT MEASURE: no echo over the relayed path.\nup:\n{}",
        up.transcript()
    );
    drop(s);
    assert_eq!(
        w.forward.to_host() - sent,
        0,
        "CANNOT MEASURE: the first request crossed the forward while it was closed"
    );
    w.anchor.assert_relayed("after the first request");

    let first = up.expect_within(
        FIRST_ATTEMPT_WITHIN,
        "`still relayed` for the first attempt at a direct path",
        is_still_relayed,
    );
    let t1 = Instant::now();
    eprintln!("[proof] attempt 1 found nothing: {first}");
    let dropped = w.forward.dropped();
    assert!(
        dropped > 0,
        "CANNOT MEASURE: the guest said `still relayed` but never sent the forward a datagram — \
         the direct path this proof opens was never the one being tried"
    );

    // The pair keeps trying: a second attempt, a retry interval later.
    let deadline = t1 + TRIED_AGAIN_WITHIN;
    let mut second = None;
    while second.is_none() && Instant::now() < deadline {
        if let Ok(line) = up.lines.recv_timeout(Duration::from_millis(200)) {
            eprintln!("[up] {line}");
            if is_still_relayed(&line) {
                second = Some((Instant::now(), line.clone()));
            }
            up.seen.push(line);
        }
    }
    let Some((t2, line)) = second else {
        panic!(
            "NOT RETRIED: {TRIED_AGAIN_WITHIN:?} after its first attempt found no direct path, the \
             relayed pair has not tried again — a pair that starts relayed stays relayed.\nup:\n{}",
            up.transcript()
        );
    };
    eprintln!(
        "[proof] attempt 2, {:?} after attempt 1, found nothing: {line}; the forward dropped {} \
         datagrams so far",
        t2 - t1,
        w.forward.dropped()
    );

    // The network changes: a direct path becomes possible.
    w.forward.open();
    let opened = Instant::now();
    let mut requests = 0usize;
    let mut upgraded = None;
    while Instant::now() - opened < UPGRADED_WITHIN {
        std::thread::sleep(Duration::from_millis(500));
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        if code != 0 {
            continue;
        }
        let sent = w.forward.to_host();
        if !echo_over(&mut s, &payload, Duration::from_secs(10)) {
            continue;
        }
        requests += 1;
        if w.forward.to_host() - sent >= PAYLOAD as u64 {
            upgraded = Some(Instant::now() - opened);
            break;
        }
    }
    let attempts = up.seen.iter().filter(|l| is_still_relayed(l)).count();
    eprintln!(
        "[proof] {requests} requests after the forward opened; {attempts} `still relayed` \
         attempts in all; the forward carried {} B to the host and {} B back",
        w.forward.to_host(),
        w.forward.to_guest()
    );
    let Some(took) = upgraded else {
        panic!(
            "NOT UPGRADED: {UPGRADED_WITHIN:?} after a direct path became possible, every request \
             still rode the anchor's circuit ({requests} tried) — nothing found the direct path.\n\
             up:\n{}",
            up.transcript()
        );
    };
    eprintln!("[proof] on the direct path {took:?} after it became possible");
    assert!(took < UPGRADED_WITHIN);
    interrupt(&mut up, Duration::from_secs(15));
    drop(up);
}
