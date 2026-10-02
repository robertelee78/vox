//! PRD-001 **R42, open** (RP-22) — **a first direct connection completes in under 2 s**, driven
//! through the shipped `vox` binary.
//!
//! **The claim.** Two people have met: the guest has joined the host's room, the host trusts the
//! guest, and nothing is running on the guest's side. The guest starts `vox up` and asks it for the
//! host's service (`ssh user@<room>.vox` does exactly this, over SOCKS5). The wait from that moment
//! until the pair is **on a direct path** — rung 1, a direct dial of an address the host advertises —
//! must be under 2 s, and so must the wait until the request is answered by any path at all.
//!
//! **The staging — real processes only.** A `vox node` anchor on `[::]` (dual-stack), a `vox serve`
//! host on `127.0.0.1`, and the guest on `[::1]`, set up with `vox id`, `vox trust add` and
//! `vox connect`. Split by address family, host and guest cannot send each other a datagram; the
//! host advertises a **port forward** the proof owns (`support/port_forward.rs`, via the proof-only
//! `VOX_TEST_ADVERTISE`), an `[::1]` socket that carries datagrams to and from the host with no
//! delay — the host is "publicly reachable at a forwarded port", the open topology. The forward is
//! therefore the pair's **only direct path** (the host's own address and the address the anchor
//! observes for it are IPv4, which the guest cannot reach), and so "direct" is **counted**: a
//! request whose echo payload crossed the forward rode the direct path; one whose payload did not
//! rode the anchor's circuit.
//!
//! **Cold, each sample.** Each sample starts a **new** `vox up` on a **new** port, so no connection
//! and no forward mapping carries over; the last one was stopped with Ctrl-C (by PID), so the host
//! was told it went away. The two production-Argon2id unlocks `vox up` does before it can take a
//! request are outside the clock, as a person waits for them at the prompt. The clock starts at the
//! earlier of the moment `vox up` says it is up and the first datagram of that `vox up` at the
//! forward — so a dial the node begins by itself, before anyone asks, is on the clock too.
//!
//! **What is asserted**, on every one of [`SAMPLES`] samples, against hard-coded numbers:
//! - the first request is answered (SOCKS reply 0 and a whole echo) in under 2000 ms;
//! - the pair is on the direct path (an echo whose bytes crossed the forward) in under 2000 ms;
//! - every sample reached the direct path at all ([`GIVE_UP`]), and the forward carried bytes.
//!
//! - **the side that can reach directly asks for no circuit** (V210-122): the guest's
//!   `vox status --json` counts no circuit asked for to the host, by any `vox up` or by a
//!   `vox forward`, which reaches the host the moment it starts over a direct path with 30 ms of
//!   latency (the case R41's transcripts showed). The host's circuits to the guest, which it cannot
//!   dial, are legitimate bridges (the decider, 2026-10-02) and are printed, not asserted, with the
//!   anchor's own count.
//!
//! Printed: min / median / p95 / max of both, how many first answers came over the circuit, and
//! how many dials began before `vox up` said it was up.
//!
//! **The mutation that must turn it red:** delay the ladder's direct dial (not a circuit's) by
//! 2.5 s in `nat::reachability::connect_direct_within`. The first answer still comes fast, over the
//! anchor's circuit, and the direct path lands only after 2.5 s — red on the direct bound.
//!
//! - **the anchor carries nothing for the pair** (V030-22): its own `circuit(s) carried` report
//!   never goes above 0 for the whole run, the host's reaches for a guest it cannot dial included;
//! - **the host asks a guest to dial back** (V030-22): a second test,
//!   `the_host_asks_a_guest_to_dial_back`, stages it — carol joins from an anchor-only address and
//!   comes online, so the host must reach a guest it cannot dial; she must be reached with no
//!   circuit at all, the anchor carrying none (see `dial_back_is_asked_for`).
//!
//! For V030-22 the whole-run "anchor carried 0" assertion is supporting evidence only: it is red
//! only in a run where the host happens to reach for a guest that is online but not connected to
//! it. The discriminating arm is `the_host_asks_a_guest_to_dial_back`; its mutants are the
//! dial-back rung removed from `NodeNet::reach_ladder`, and `NodeNet::member_endpoints` reading
//! only this node's own board — each makes the anchor bridge the pair: red, as PRODUCT.
//!
//! And for V210-122: `DIRECT_HEAD_START` set to 0, the old race. The guest's `vox forward` asks for
//! a circuit through the anchor beside its direct dial over the 30 ms path, and the guest's status
//! counts it: red, as PRODUCT.
//!
//! Replaces `crates/vox-core/tests/perf_r42_first_connect_open_gate.rs`, which ran every node in
//! process on a NAT simulator.

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

/// PRD-001 R42. A number, not a product constant.
const TARGET: Duration = Duration::from_millis(2000);
/// The one-way delay of the forward for the `vox forward` step (V210-122): a direct path with
/// latency, slower than the anchor's next door, and a handshake's few flights well inside the
/// direct dial's 250 ms head start.
const FORWARD_DELAY: Duration = Duration::from_millis(30);
/// Cold first connections measured per run.
const SAMPLES: usize = 12;
/// How long a sample may take to reach the direct path before it is recorded at this bound
/// (already five times the target) and the proof is red.
const GIVE_UP: Duration = Duration::from_secs(10);
/// The echo payload: big enough that a request which rode the forward is unmistakable in its byte
/// count, small enough to be one flight.
const PAYLOAD: usize = 16 * 1024;

/// **The host asks a guest to dial back, and nothing bridges them** (V030-22, #335) — the claim's
/// own arm. See [`dial_back_is_asked_for`] for the staging and what is asserted.
#[test]
#[ignore = "production Argon2id + a real PoW, a third member staged; run in release"]
fn the_host_asks_a_guest_to_dial_back() {
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm();
    let mut w = ForwardedWorld::new(true);
    dial_back_is_asked_for(&mut w);
}

/// **The host asks a guest to dial back** (V030-22, #335), staged so it must, and with nothing of
/// the guest's own in flight to the host: carol joins from an address that names **only the
/// anchor** (the host's own entries taken out), so her room holds no address for the host and her
/// `vox up` dials only the anchor. She is online, the host cannot dial her at all (`[::1]`), and
/// the host posts to the room: to deliver, it must reach her.
///
/// An earlier staging held the guest's own dial of the host back (forward closed, or slow) instead;
/// those stalled attempts were answered by the host ahead of the dial-back, one post-quantum
/// handshake at a time, and the dial-back's own connection came 1–3 s late — the staging, not the
/// product (measured: every send `Ok`, the host's handshakes 150–575 ms each at load 45–97).
///
/// **Re-staged, up to [`STAGINGS`] times, when it did not stage.** Carol may reach the host herself
/// first — her node reads the host's address off the anchor's board and dials it directly, which is
/// right — and then the host never needs to reach her. That run measures nothing about a dial-back
/// and is said as such; a fresh guest is staged again. Any run that did stage decides: a PRODUCT
/// red stops at once.
///
/// Asserted, on the first run that stages (the host asked her to dial back and she answered, or the
/// anchor carried something for them): she answered, and the anchor carried **no** circuit for the
/// pair from the moment she came online. Circuits the host asked for and the anchor refused (to a
/// process of hers that had already exited: "relay cannot reach the peer") carry nothing and are
/// printed, not asserted. Every run unstaged: `CANNOT MEASURE`.
fn dial_back_is_asked_for(w: &mut ForwardedWorld) {
    let mut unstaged = Vec::new();
    for n in 1..=STAGINGS {
        match stage_dial_back(w, n) {
            Staging::Staged => return,
            Staging::NotStaged(why) => {
                eprintln!("[proof] staging {n}: not staged — {why}");
                unstaged.push(why);
            }
        }
    }
    panic!(
        "CANNOT MEASURE: in {STAGINGS} stagings the host never had to reach a guest that was \
         online and not connected to it:\n{}",
        unstaged.join("\n")
    );
}

/// How many fresh guests [`dial_back_is_asked_for`] stages before it says it could not measure.
const STAGINGS: usize = 5;
/// The forward's one-way latency, guest to host, while a dial-back is staged: a real path's, and
/// short enough that a direct handshake over it (two flights, measured about 2× this plus the
/// crypto) lands well inside the direct dial's 250 ms head start (V210-122). At 200 ms a guest's own
/// direct dial took over 400 ms, its circuit started on the head start's expiry, and the anchor
/// carried it — the head start's designed limit, not this claim.
const STAGING_DELAY: Duration = Duration::from_millis(50);

enum Staging {
    /// Measured and asserted.
    Staged,
    /// Nothing to measure, and why.
    NotStaged(String),
}

/// One staging, with a fresh guest `carol-<n>`: see [`dial_back_is_asked_for`].
fn stage_dial_back(w: &mut ForwardedWorld, n: usize) -> Staging {
    use world::{args, room_pass_file, vox_once, VoxProc};
    let (carol, carol_fp) = anchor_only_guest(w, &format!("carol-{n}"));
    // Counted from before carol comes online: the host reaches for her as soon as she does.
    let before = (
        reach_count(&w.host_dir, &carol_fp, "the host", "circuits"),
        reach_count(&w.host_dir, &carol_fp, "the host", "dial_backs_answered"),
    );
    let mark = w.anchor.mark();
    // A direct path with latency, as a real one has: carol's own dial of the host then takes a few
    // hundred milliseconds, so the host's reach for her starts while she is not yet connected to
    // it — the case. Her dial back crosses the same path.
    w.forward.set_delay(STAGING_DELAY);
    let mut up = VoxProc::spawn(
        &format!("carol-{n}-up"),
        &carol,
        &args(&[
            "up",
            &w.room,
            "--passphrase-file",
            &room_pass_file(&carol, &w.passphrase),
            "--bind",
            "127.0.0.1:0",
            "--anchor",
            &w.anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    up.expect_line("carol's proxy is up", |l| l.starts_with("vox up on "));
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["room", "post", &w.room, "for carol, by a dial-back"]),
    );
    assert!(
        ok,
        "CANNOT MEASURE: the host's `vox room post` failed:\n{out}{err}"
    );
    // Until the host has reached for carol one way or the other, or 10 s.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let now = (
            reach_count(&w.host_dir, &carol_fp, "the host", "circuits"),
            reach_count(&w.host_dir, &carol_fp, "the host", "dial_backs_answered"),
        );
        if now != before {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_secs(2));
    let carried = w.anchor.circuits_since(mark, Duration::from_secs(2));
    let circuits = reach_count(&w.host_dir, &carol_fp, "the host", "circuits") - before.0;
    let answered =
        reach_count(&w.host_dir, &carol_fp, "the host", "dial_backs_answered") - before.1;
    eprintln!(
        "[proof] staging {n}: the host's dial-backs answered {answered}, circuits asked \
         {circuits}; the anchor carried up to {carried} since carol came online"
    );
    w.forward.set_delay(Duration::ZERO);
    let host = w.host.transcript();
    let said = up.transcript();
    interrupt(&mut up, Duration::from_secs(15));
    if answered == 0 && carried == 0 {
        return Staging::NotStaged(format!(
            "no dial-back answered and nothing carried (circuits asked: {circuits}); carol \
             reached the host herself, or the host did not need her"
        ));
    }
    assert!(
        answered > 0 && carried == 0,
        "PRODUCT: the host, which cannot dial carol, had to reach her while she could dial the \
         host; it must ask her to dial back, and the anchor must carry nothing for them. \
         Dial-backs answered: {answered}; circuits asked: {circuits}; the anchor carried up to \
         {carried}.\nhost:\n{host}\ncarol:\n{said}\nanchor:\n{}",
        w.anchor.proc.transcript()
    );
    Staging::Staged
}

/// A guest, `name`, trusted by the host and joined from an address that names **only the anchor**
/// (the host's own entries taken out): its room holds no address for the host, so whatever it
/// knows of where the host is, it must learn from a board. Returns its profile and fingerprint.
fn anchor_only_guest(w: &ForwardedWorld, name: &str) -> (std::path::PathBuf, String) {
    use world::{args, room_pass_file, vox_once};
    let carol = w.tmp.path().join(name);
    world::mkdir(&carol.join("cfg"));
    let carol_fp = world::fingerprint(&carol, name);
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["trust", "add", &carol_fp, "--name", name]),
    );
    assert!(
        ok,
        "CANNOT MEASURE: the host's `vox trust add` of {name}:\n{out}{err}"
    );
    let anchor_only = without_entry_of(&w.address, &w.host_fp);
    assert!(
        !anchor_only.contains(&format!("a={}", w.host_fp)),
        "CANNOT MEASURE: the host's entry is still in {name}'s address: {anchor_only}"
    );
    let (ok, out, err) = vox_once(
        &carol,
        &args(&[
            "connect",
            &anchor_only,
            "--passphrase-file",
            &room_pass_file(&carol, &w.passphrase),
            "--anchor",
            &w.anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    assert!(
        ok,
        "CANNOT MEASURE: {name} could not join from the anchor-only address:\n{out}{err}"
    );
    (carol, carol_fp)
}

/// **A node reads the board before it bridges** (V030-22, #335). Dave joins from an anchor-only
/// address, so his node holds no address for the host, and starts a `vox forward` to the host's
/// service — which reaches the host the moment it starts. The host's only address dave can use is
/// its record on the anchor's board (the forward it advertises); the host cannot dial dave at all
/// (`[::1]`), so a dial-back cannot help either. Asserted: the forward reached the host, dave asked
/// for **no** circuit to it, and the anchor carried none from the forward's start. Without the board
/// read, the reach knows no address, its dial-back fails, and it bridges.
#[test]
#[ignore = "production Argon2id + a real PoW, a third member staged; run in release"]
fn a_node_reads_the_board_before_bridging() {
    use world::{args, room_pass_file, VoxProc};
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm();
    let mut w = ForwardedWorld::new(true);
    let (dave, _dave_fp) = anchor_only_guest(&w, "dave");
    let mark = w.anchor.mark();
    let mut fwd = VoxProc::spawn(
        "dave-forward",
        &dave,
        &args(&[
            "forward",
            &w.room,
            &w.host_fp,
            &w.service_port.to_string(),
            "127.0.0.1:0",
            "--passphrase-file",
            &room_pass_file(&dave, &w.passphrase),
            "--anchor",
            &w.anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    let reached = fwd.expect_line("dave's `vox forward` saying it reached the host", |l| {
        l.contains("vox: reached ") && l.contains(" ms (")
    });
    let asked = circuits_asked(&dave, &w.host_fp, "dave's `vox forward`");
    let dial_backs = reach_count(&dave, &w.host_fp, "dave's `vox forward`", "dial_backs");
    std::thread::sleep(Duration::from_secs(2));
    let carried = w.anchor.circuits_since(mark, Duration::from_secs(2));
    eprintln!(
        "[proof] dave's forward: {reached}; it asked for {asked} circuit(s) and {dial_backs} \
         dial-back(s) to the host; the anchor carried up to {carried}"
    );
    let said = fwd.transcript();
    interrupt(&mut fwd, Duration::from_secs(15));
    assert!(
        asked == 0 && carried == 0,
        "PRODUCT: dave's node held no address for the host, and the host's board record on the \
         anchor gave one dave could dial; it must read the board and go direct, yet it asked for \
         {asked} circuit(s) ({dial_backs} dial-back(s)) and the anchor carried up to {carried}.\n\
         dave:\n{said}\nanchor:\n{}",
        w.anchor.proc.transcript()
    );
}

/// `address` with `who`'s entry (its `a=` and the `b=` addresses after it) taken out.
fn without_entry_of(address: &str, who: &str) -> String {
    let (head, query) = address.split_once('?').expect("an address with a query");
    let mut kept = Vec::new();
    let mut skipping = false;
    for part in query.split('&') {
        if let Some(id) = part.strip_prefix("a=") {
            skipping = id == who;
        } else if !part.starts_with("b=") {
            skipping = false;
        }
        if !skipping {
            kept.push(part);
        }
    }
    format!("{head}?{}", kept.join("&"))
}

/// Start the guest's `vox forward` to the host's service, wait until it says it reached the host,
/// read how many circuits it asked for to the host while it still runs, and stop it (by its PID).
fn forward_once(w: &ForwardedWorld) -> (String, u64) {
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
    let line = fwd.expect_line("`vox forward` saying it reached the host", |l| {
        l.contains("vox: reached ") && l.contains(" ms (")
    });
    let asked = circuits_asked(&w.guest_dir, &w.host_fp, "the guest's `vox forward`");
    interrupt(&mut fwd, Duration::from_secs(15));
    (line, asked)
}

/// How many circuits the node running on the profile at `dir` has asked a relay for, to `peer`,
/// from its `vox status --json` (`reach[].circuits`, counted where every circuit is asked for).
///
/// **Never a silent 0.** A status that does not answer, or answers without its `reach` section,
/// measured nothing: `CANNOT MEASURE`, naming `who`. A `reach` section with no row for `peer` is
/// a measured 0 — a row is there for every peer this node ran a ladder to or asked a circuit for.
fn circuits_asked(dir: &std::path::Path, peer: &str, who: &str) -> u64 {
    reach_count(dir, peer, who, "circuits")
}

/// `field` of `peer`'s `reach` row in the `vox status --json` of the node on `dir`, under the same
/// rule as [`circuits_asked`]: no answer or no `reach` section is `CANNOT MEASURE`, no row is 0.
fn reach_count(dir: &std::path::Path, peer: &str, who: &str, field: &str) -> u64 {
    let (ok, out, err) = world::vox_once(dir, &world::args(&["status", "--json"]));
    assert!(
        ok,
        "CANNOT MEASURE: {who}'s `vox status --json` did not answer, so how many circuits it asked \
         for is unknown.\nstdout:\n{out}\nstderr:\n{err}"
    );
    let Some(reach) = out.split("\"reach\":[").nth(1) else {
        panic!(
            "CANNOT MEASURE: {who}'s `vox status --json` has no `reach` section, so how many \
             circuits it asked for is unknown:\n{out}"
        );
    };
    let reach = reach.split(']').next().unwrap_or_default();
    let Some(row) = reach.split("{\"peer\":\"").find(|r| r.starts_with(peer)) else {
        return 0;
    };
    row.split(&format!("\"{field}\":"))
        .nth(1)
        .and_then(|n| n.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| {
            panic!("CANNOT MEASURE: {who}'s `reach` row for {peer} has no {field:?}: {row}")
        })
}

fn stats(label: &str, samples: &[Duration]) -> Duration {
    let mut s = samples.to_vec();
    s.sort();
    let at = |q: f64| s[((q * s.len() as f64).ceil() as usize).clamp(1, s.len()) - 1];
    eprintln!(
        "[proof] {label}: n={} min={:?} median={:?} p95={:?} max={:?}",
        s.len(),
        s[0],
        at(0.5),
        at(0.95),
        s[s.len() - 1]
    );
    s[s.len() - 1]
}

#[test]
#[ignore = "production Argon2id + a real PoW, a dozen cold `vox up` processes; run in release"]
fn a_first_direct_connection_completes_in_under_two_seconds() {
    watchdog::arm();
    let mut w = ForwardedWorld::new(true);
    eprintln!(
        "[proof] guest joined in {:?}; the forward at {} carries {} for the host",
        w.joined_in, w.forward.public, w.forward.host
    );
    let hostname = w.hostname();
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();

    let mut any = Vec::new();
    let mut direct = Vec::new();
    let mut first_over_circuit = 0usize;
    let mut guest_circuits = 0u64;
    let mut dialled_before_ready = 0usize;
    let mut requests = 0usize;
    for i in 0..SAMPLES {
        let before = w.forward.sources();
        let (mut up, proxy, ready) = w.up(&format!("up-{i}"));

        // First request: the proxy holds the CONNECT until it has a path (HOST_PATIENCE).
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        assert_eq!(
            code,
            0,
            "sample {i}: the first CONNECT to {hostname} was refused (SOCKS {code}).\nup:\n{}",
            up.transcript()
        );
        let sent = w.forward.to_host();
        let echoed = echo_over(&mut s, &payload, GIVE_UP);
        let answered = Instant::now();
        assert!(
            echoed,
            "sample {i}: the first CONNECT succeeded but no whole echo came back.\nup:\n{}",
            up.transcript()
        );
        requests += 1;
        let mut on_direct = w.forward.to_host() - sent >= PAYLOAD as u64;
        let first_direct = on_direct;
        if !on_direct {
            first_over_circuit += 1;
        }
        drop(s);
        // Until a request rides the direct path: a fresh CONNECT each time, on whatever
        // connection the node holds to the host now.
        let mut direct_at = on_direct.then_some(answered);
        while direct_at.is_none() && answered.duration_since(ready) < GIVE_UP * 2 {
            std::thread::sleep(Duration::from_millis(20));
            let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
            if code != 0 {
                continue;
            }
            let sent = w.forward.to_host();
            if !echo_over(&mut s, &payload, GIVE_UP) {
                continue;
            }
            requests += 1;
            let now = Instant::now();
            on_direct = w.forward.to_host() - sent >= PAYLOAD as u64;
            if on_direct {
                direct_at = Some(now);
            } else if now.duration_since(ready) >= GIVE_UP {
                break;
            }
        }

        // The clock's start: `vox up` ready, or its first datagram at the forward if that was
        // earlier (a dial begun before anyone asked).
        let new: Vec<Instant> = w
            .forward
            .sources()
            .into_iter()
            .filter(|(src, _)| !before.contains_key(src))
            .map(|(_, at)| at)
            .collect();
        let first_dgram = new.iter().min().copied();
        let t0 = match first_dgram {
            Some(d) if d < ready => {
                dialled_before_ready += 1;
                d
            }
            _ => ready,
        };
        assert!(
            first_dgram.is_some(),
            "CANNOT MEASURE (sample {i}): this `vox up` never sent the forward a datagram, so the \
             direct path this proof counts was never tried — the staging is not what it claims.\n\
             up:\n{}",
            up.transcript()
        );
        let a = answered.duration_since(t0);
        let d = direct_at.map_or(GIVE_UP + a, |at| at.duration_since(t0));
        eprintln!(
            "[proof] sample {i}: answered {a:?} ({}), direct {}",
            if first_direct {
                "direct"
            } else {
                "over the circuit"
            },
            direct_at.map_or_else(|| "NEVER".to_owned(), |_| format!("{d:?}"))
        );
        any.push(a);
        direct.push(d);
        // The circuits this `vox up` asked a relay for, to the host it could reach directly.
        let asked = circuits_asked(&w.guest_dir, &w.host_fp, "the guest's `vox up`");
        eprintln!("[proof] sample {i}: the guest asked for {asked} circuit(s) to the host");
        guest_circuits += asked;
        if !interrupt(&mut up, Duration::from_secs(15)) {
            eprintln!("[proof] sample {i}: `vox up` did not exit on Ctrl-C within 15 s; killed");
        }
        drop(up);
    }

    let never = direct.iter().filter(|d| **d > GIVE_UP).count();
    eprintln!(
        "[proof] {SAMPLES} cold first connections, {requests} requests; {first_over_circuit} first \
         answers came over the circuit; {dialled_before_ready} dials began before `vox up` said it \
         was up; {never} never reached the direct path; forward carried {} B to the host, {} B back",
        w.forward.to_host(),
        w.forward.to_guest()
    );
    let any_max = stats("first request answered, any path", &any);
    let direct_max = stats("on the direct path", &direct);
    assert!(
        w.forward.to_host() > 0 && w.forward.to_guest() > 0,
        "CANNOT MEASURE: the forward carried nothing, so there was no direct path to time"
    );
    // **A side that can reach directly never asks for a circuit** (V210-122, ADR-012). Every reach
    // raced a circuit through the anchor against the direct dial; the circuit lost, was retired,
    // and the anchor carried it for its 60 s grace. With the direct dial's head start, the guest —
    // which reaches the host through the forward — asks for none, by any `vox up` or `vox forward`.
    //
    // **The host's circuits are not counted** (the decider, 2026-10-02, on #321). The host cannot
    // dial the guest at all (`[::1]`, no forward), so when it reaches the guest while no guest
    // process has connected to it, the anchor bridging them is what an anchor is for. They are
    // printed, with the anchor's own count and any first answer that rode one, and not asserted.
    // That the host asks the guest to dial back instead is planned for v0.3.0.
    //
    // The case R41's transcripts showed: a `vox forward` reaches the host the moment it starts,
    // with its anchor already connected. That reach raced a circuit through the anchor against the
    // direct dial, and over a path with any latency the circuit — through an anchor next door —
    // won. So the forward now holds each datagram to the host for FORWARD_DELAY: a direct path a
    // real network would have, slower than the anchor's but well inside the direct dial's head
    // start.
    w.forward.set_delay(FORWARD_DELAY);
    let (reached, forward_asked) = forward_once(&w);
    w.forward.set_delay(Duration::ZERO);
    eprintln!(
        "[proof] `vox forward` to the reachable host: {reached}; it asked for {forward_asked} \
         circuit(s) to the host"
    );
    guest_circuits += forward_asked;
    let ever = w.anchor.circuits_ever(Duration::from_secs(2));
    let guest_fp = world::fingerprint(&w.guest_dir, "guest");
    let host_asked = circuits_asked(&w.host_dir, &guest_fp, "the host");
    eprintln!(
        "[proof] the most circuits the anchor ever reported carrying: {ever}; the guest asked for \
         {guest_circuits} to the host; the host asked for {host_asked} to the guest"
    );
    // **A pair that can reach each other directly costs the anchor nothing** (V030-22, #335): the
    // anchor's own report never counts a circuit, at any point of the run, the host's reaches for
    // a guest it cannot dial included — it asks the guest to dial back instead.
    assert!(
        ever == 0,
        "PRODUCT: the guest can dial the host, yet the anchor reported carrying up to {ever} \
         circuit(s) for the pair (the host asked for {host_asked}).\nhost:\n{}\nanchor:\n{}",
        w.host.transcript(),
        w.anchor.proc.transcript()
    );
    assert!(
        guest_circuits == 0,
        "PRODUCT: the guest reached the host directly through the forward, yet it asked for \
         {guest_circuits} circuit(s) to the host: a side that could reach directly made an anchor \
         carry a circuit for it.\nanchor:\n{}",
        w.anchor.proc.transcript()
    );
    let over_any = any.iter().filter(|d| **d >= TARGET).count();
    let over_direct = direct.iter().filter(|d| **d >= TARGET).count();
    assert!(
        never == 0 && over_direct == 0 && over_any == 0,
        "R42 open: a first connection must complete in under {TARGET:?}. {over_any} of {SAMPLES} \
         first answers took longer (slowest {any_max:?}); {over_direct} of {SAMPLES} reached the \
         direct path at or past it (slowest {direct_max:?}), {never} never within {GIVE_UP:?}"
    );
}
