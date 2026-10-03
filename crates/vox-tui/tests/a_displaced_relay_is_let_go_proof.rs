//! ADR-012 M15.1b, V29-15 (#50) — **a relayed path that a direct one displaced is let go once its
//! grace is up**, driven through the shipped `vox` binary: the anchor stops carrying the circuit.
//!
//! When a direct path appears behind a relayed one, the direct one replaces it and the relayed one
//! is *retired*, not closed, for a grace (`RETIRE_GRACE_SECS`, 60 s) so nothing in flight on it is
//! cut; then, if nothing is carried on it, it is closed. The defect this holds against: each
//! connection's stream loop held the connection's `Arc` for its whole life, so the "still carried"
//! count never fell and **no retired connection was ever closed** — a pair that went direct kept
//! its circuit on the anchor for good: the anchor's slot, its two connections' keep-alives, and a
//! third party still able to see that the pair talks, for a path nobody used.
//!
//! **The staging — real processes only.** `support/port_forward.rs`: a `vox node` anchor on `[::]`,
//! a `vox serve` host on `127.0.0.1` advertising a port forward the proof owns, and a guest on
//! `[::1]` that joined with `vox connect` and asks for the host's service through `vox up`. Split by
//! address family, the forward is the pair's only direct path. It starts **closed**, so the guest's
//! first request rides the anchor's circuit (observed: the anchor reports a circuit carried, and no
//! payload crossed the forward); then it is **opened**, and the pair's own retry finds the direct
//! path (observed: a request's echo payload counted crossing the forward).
//!
//! **What is asserted:** from the moment a request rides the direct path, the anchor's own report
//! of circuits carried falls to **0** within [`LET_GO_WITHIN`] = 75 s — the 60 s grace and 15 s for
//! a status line and a loaded box, written as a number so a longer grace goes red. Nothing is
//! carried on the circuit meanwhile: every request after the upgrade rides the forward.
//!
//! **The mutation that must turn it red:** `ConnectionManager::retire_expired` treating every
//! retired connection as still carried (the old defect's effect). The circuit stays at the anchor
//! and the count never reaches 0.
//!
//! **Both ends keep the same one of the two** (V29-15, #50: "a duplicate is resolved identically
//! at both ends regardless of path classification") is held by the blocking RP-26 test below,
//! on the same upgrade: see [`both_ends_keep_the_same_connection`].
//!
//! Replaces `crates/vox-core/tests/displaced_relay_is_let_go.rs` (property 1), which ran every node
//! in process on a NAT simulator with an injected clock. Its property 2 — a displaced path carrying
//! a live tunnel stays up past the grace — is RP-26's, held below by
//! `a_tunnel_on_a_displaced_path_is_not_cut_by_its_grace` on the same staging.

// Three tests. The let-go test is optional (decider, 2026-10-01: a 60 s grace watched): it blocks
// nothing and CI only compiles it; without `--features optional-proofs` a stand-in takes its place
// and says it was not run (`support/optional_proof.rs`; docs/release/optional-proofs.md). RP-26's
// `a_tunnel_on_a_displaced_path_is_not_cut_by_its_grace` and #272's
// `the_tunnel_cap_holds_across_a_path_upgrade` block.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_relayed_path_a_direct_one_displaced_is_let_go_after_its_grace);

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

/// From the direct path taking over to the anchor carrying no circuit: the 60 s grace and 15 s of
/// margin. A number, not the product constant.
const LET_GO_WITHIN: Duration = Duration::from_secs(75);
/// How long the pair may take to find the opened forward: one 60 s retry interval, the ladder,
/// and margin. Past it the proof cannot measure what it is for.
const UPGRADE_WITHIN: Duration = Duration::from_secs(100);
const PAYLOAD: usize = 16 * 1024;

/// How long both ends may take, once a request rode the direct path or one end decided, to name
/// the same connection for each other in `vox status --json`: one upgrade's dials all land within
/// about a second (measured), so the rest is scheduling.
const BOTH_DECIDED_WITHIN: Duration = Duration::from_secs(20);

/// Every connection note `p` printed about `peer` (named by the first 26 characters of its
/// fingerprint, as `vox` names a peer), in order: what a red quotes, so it can be read alone.
fn notes_about(p: &world::VoxProc, peer: &str) -> Vec<String> {
    let about = format!("connection to {} — ", &peer[..26]);
    p.timed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|(_, l)| l.contains(&about))
        .map(|(_, l)| l.clone())
        .collect()
}

/// Every connection note `p` printed about `peer`, each with its time since `t0` in seconds: so a
/// reader can tell dials that raced from a connection replaced again and again.
fn timed_notes_about(p: &world::VoxProc, peer: &str, t0: Instant) -> Vec<String> {
    let about = format!("connection to {} — ", &peer[..26]);
    p.timed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|(_, l)| l.contains(&about))
        .map(|(at, l)| {
            let secs = match at.checked_duration_since(t0) {
                Some(d) => d.as_secs_f64(),
                None => -t0.duration_since(*at).as_secs_f64(),
            };
            format!("[{secs:+.3}s] {l}")
        })
        .collect()
}

/// One decision an end said it made between two live connections to the same peer.
#[derive(Clone, Debug)]
struct Decision {
    /// The two connections' tags, in sorted order: the same pair at both ends.
    pair: (String, String),
    /// The one kept.
    kept: String,
    /// The line that said so.
    line: String,
}

/// Every decision `p` said it made between two connections to `peer`, in order.
///
/// Read from the lines the product prints when a second connection to one peer is filed: the
/// newcomer `displaced` the held one or `replaced` a dead one (the newcomer is kept); it `lost the
/// tie-break to the one held` (the held one is kept); or the held one `did not answer a probe in
/// time when a new one … arrived; retired` (V210-104: the newcomer is then filed against no rival,
/// and kept).
fn decisions(p: &world::VoxProc, peer: &str) -> Vec<Decision> {
    let token = |rest: &str, marker: &str| {
        rest.split_once(marker)
            .and_then(|(_, r)| r.split_whitespace().next())
            .map(|t| t.trim_end_matches([',', ';']).to_owned())
    };
    let mut out = Vec::new();
    for line in notes_about(p, peer) {
        let Some((_, rest)) = line.split_once(" — ") else {
            continue;
        };
        // (the newcomer, the held one, whether the newcomer was kept)
        let decided = if rest.starts_with("a new connection ") {
            let (n, h) = (
                token(rest, "a new connection "),
                token(rest, "the one held "),
            );
            if rest.contains(" lost the tie-break to the one held ") {
                n.zip(h).map(|(n, h)| (n, h, false))
            } else if rest.contains(" displaced the one held ")
                || rest.contains(" replaced the one held ")
            {
                n.zip(h).map(|(n, h)| (n, h, true))
            } else {
                None
            }
        } else if rest.starts_with("the connection held ")
            && rest.contains(" did not answer a probe in time when a new one ")
        {
            token(rest, "when a new one ")
                .zip(token(rest, "the connection held "))
                .map(|(n, h)| (n, h, true))
        } else {
            None
        };
        if let Some((n, h, newcomer_kept)) = decided {
            let kept = if newcomer_kept { n.clone() } else { h.clone() };
            let pair = if n <= h { (n, h) } else { (h, n) };
            out.push(Decision {
                pair,
                kept,
                line: line.clone(),
            });
        }
    }
    out
}

/// Every pair of connections **both** ends decided between, with each end's decision: (the
/// host's, the guest's). A pair only one end has filed yet is not a disagreement.
fn shared(w: &ForwardedWorld, up: &world::VoxProc) -> Vec<(Decision, Decision)> {
    let (host, guest) = (decisions(&w.host, &w.guest_fp), decisions(up, &w.host_fp));
    host.iter()
        .filter_map(|h| {
            guest
                .iter()
                .find(|g| g.pair == h.pair)
                .map(|g| (h.clone(), g.clone()))
        })
        .collect()
}

/// Whether the two ends decided one pair differently: two such ends may never send a request over
/// the direct path, so a wait for one would only hide what they said.
fn ends_disagree(w: &ForwardedWorld, up: &world::VoxProc) -> bool {
    shared(w, up).iter().any(|(h, g)| h.kept != g.kept)
}

/// The connection `dir`'s running node says it holds for `peer` in `vox status --json` (its `reach`
/// row's `connection`, with the row's `path`), or why it could not say: the status failed, did not
/// parse, or names no connection for the peer.
fn status_holds(dir: &std::path::Path, peer: &str) -> Result<(String, String), String> {
    let (ok, out, err) = world::vox_once(dir, &world::args(&["status", "--json"]));
    if !ok {
        return Err(format!("`vox status --json` failed: {err}"));
    }
    let v: serde_json::Value = serde_json::from_str(&out)
        .map_err(|e| format!("`vox status --json` is not JSON ({e}): {out}"))?;
    let row = v["reach"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["peer"] == peer))
        .ok_or_else(|| format!("no `reach` row for the peer: {out}"))?;
    match (row["connection"].as_str(), row["path"].as_str()) {
        (Some(tag), Some(path)) => Ok((tag.to_owned(), path.to_owned())),
        _ => Err(format!("its row names no connection: {row}")),
    }
}

/// What the host's and the guest's `vox status --json` each say they hold for the other (see
/// [`status_holds`]).
type Holds = (
    Result<(String, String), String>,
    Result<(String, String), String>,
);

/// **V29-15: both ends keep the same one of two live connections.**
///
/// **Judged on the end state.** Each end's `vox status --json` names the connection it holds for
/// the other. Within [`BOTH_DECIDED_WITHIN`] of the upgrade, both must name **the same one**, and
/// still do a second later (`PRODUCT` otherwise, quoting both ends' rows and every connection note
/// each gave about the other). An end that decided differently, silently, holds a different one
/// here whatever it wrote.
///
/// **The notes as further evidence.** Every pair of connections both ends wrote a decision about
/// must have been decided alike (`PRODUCT` otherwise). A pair only one end wrote about is not
/// compared: an end can file a connection the other has not yet.
fn both_ends_keep_the_same_connection(
    w: &mut ForwardedWorld,
    up: &mut world::VoxProc,
    direct_seen: bool,
    opened: Instant,
) {
    let any_decided = |w: &ForwardedWorld, up: &world::VoxProc| {
        !decisions(&w.host, &w.guest_fp).is_empty() || !decisions(up, &w.host_fp).is_empty()
    };
    if !direct_seen && !any_decided(w, up) {
        return;
    }
    // Timed from the forward opening, on every run: the order and spacing of the dials is
    // part of what a reader needs.
    let notes = |w: &ForwardedWorld, up: &world::VoxProc| {
        format!(
            "Every connection note the host gave about the guest, timed from the forward \
             opening:\n{}\nEvery connection note the guest gave about the host:\n{}",
            timed_notes_about(&w.host, &w.guest_fp, opened).join("\n"),
            timed_notes_about(up, &w.host_fp, opened).join("\n")
        )
    };
    // ---- the end state: both name the same connection, steadily ----
    let read = |w: &ForwardedWorld| {
        (
            status_holds(&w.host_dir, &w.guest_fp),
            status_holds(&w.guest_dir, &w.host_fp),
        )
    };
    let agree = |r: &Holds| matches!(r, (Ok(h), Ok(g)) if h.0 == g.0);
    let since = Instant::now();
    let mut last = read(w);
    loop {
        if agree(&last) {
            std::thread::sleep(Duration::from_secs(1));
            let again = read(w);
            if agree(&again) && again.0.as_ref().map(|h| &h.0) == last.0.as_ref().map(|h| &h.0) {
                last = again;
                break;
            }
            last = again;
        }
        if since.elapsed() >= BOTH_DECIDED_WITHIN {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
        last = read(w);
    }
    eprintln!("[proof] {}", notes(w, up));
    eprintln!(
        "[proof] which connection each end says it holds for the other (`vox status --json`): \
         host {:?}, guest {:?}",
        last.0, last.1
    );
    assert!(
        agree(&last),
        "PRODUCT: {BOTH_DECIDED_WITHIN:?} after the upgrade, the two ends do not hold the same \
         connection to each other: the host's `vox status --json` says {:?} and the guest's says \
         {:?}; each end will open streams on one the other has retired.\n{}",
        last.0,
        last.1,
        notes(w, up)
    );
    // ---- and every duplicate both ends wrote about was decided alike ----
    let both = shared(w, up);
    eprintln!(
        "[proof] {} pair(s) of connections decided at both ends: {:?}",
        both.len(),
        both.iter()
            .map(|(h, g)| format!("{:?}: host kept {}, guest kept {}", h.pair, h.kept, g.kept))
            .collect::<Vec<_>>()
    );
    for (h, g) in &both {
        assert_eq!(
            h.kept,
            g.kept,
            "PRODUCT: the two ends decided one duplicate differently: of {:?}, the host kept {} \
             (it said: {:?}) and the guest kept {} (it said: {:?}); each end will open streams on \
             one the other has retired.\n{}",
            h.pair,
            h.kept,
            h.line,
            g.kept,
            g.line,
            notes(w, up)
        );
    }
}

/// RP-26 (#133) — **a better path displacing a worse one cuts nothing it carries**, through the
/// shipped `vox`, on the staging above.
///
/// A person has a session open through `vox up` — an `ssh`, a file transfer — while the pair is on
/// the anchor's circuit. A direct path appears and displaces the circuit, which is retired for its
/// 60 s grace. The session must not notice: a retired connection still carrying something is kept
/// for as long as it does. The defect this holds against closed on the timer alone, which reached
/// the person as `Connection reset by peer` mid-session whenever a better path came along.
///
/// **Observed, never assumed** (CANNOT MEASURE otherwise): the session's first echo rode the
/// circuit (the forward was closed and carried none of it); after the forward opened a *new*
/// request rode it (the pair went direct); the host or the guest reported its relayed connection
/// displaced; and every later echo on the session still crossed the anchor, not the forward — it
/// stayed on the displaced path.
///
/// **Asserted:**
/// - **V29-15 (#50): both ends keep the same one of the two live connections.** When the direct
///   connection is filed, each end holds two live connections to the other, one relayed and one
///   direct, and decides alone which to keep. Each says which on stderr (`vox: connection to
///   <peer> — a new connection <tag> … displaced / lost the tie-break to the one held <tag>`),
///   naming connections by a tag from the connection's own TLS exporter, so one connection has one
///   tag at both ends, and `vox status --json` names the connection each holds for the other by
///   the same tag. **The end state is judged:** within 20 s of the upgrade, the host's `vox serve`
///   and the guest's `vox up` must name the same connection for each other, and still do a second
///   later (`PRODUCT` otherwise). An end that decided differently and said nothing is caught here.
///   As further evidence, every pair of connections both ends wrote a decision about must have
///   been decided alike (`PRODUCT`); a pair only one end has filed yet is not compared. Ends that
///   disagree open streams on a connection the other has retired.
/// - The session opened before the upgrade answers an echo, whole, every few seconds until the
///   grace and 15 s for the tick have passed since the direct path took over.
///
/// **The mutations that must turn it red:**
/// - `ConnectionManager::retire_expired` treating no retired connection as still carried
///   (`let still_carried = false;`): the displaced path closes when its grace ends and the
///   session's next echo fails.
/// - The tie-break reading the path class the other way round at one end only (in `file_inner`,
///   the end whose fingerprint sorts higher swaps the newcomer's and the held connection's
///   classes, as an end that classified the path differently would): that end keeps the relayed
///   connection and the other the direct one, and the two tags differ.
#[test]
#[ignore = "production Argon2id + a real PoW, a relayed pair upgraded and a 60 s grace held; run in release"]
fn a_tunnel_on_a_displaced_path_is_not_cut_by_its_grace() {
    watchdog::arm();
    // From the direct path taking over, past the grace and a tick: the product's constant, so a
    // longer grace lengthens the hold rather than letting a cut at its end go unseen.
    let hold = Duration::from_secs(vox_core::node::net::RETIRE_GRACE_SECS + 15);
    let mut w = ForwardedWorld::new(false);
    eprintln!(
        "[proof] guest joined through the relay in {:?}; forward {} (closed) for the host at {}",
        w.joined_in, w.forward.public, w.forward.host
    );
    let hostname = w.hostname();
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    let (mut up, proxy, _) = w.up("up");

    // The person's session, opened while the circuit is the only path.
    let (code, mut session) = socks5_connect(proxy, &hostname, w.service_port);
    assert_eq!(
        code,
        0,
        "PRODUCT (staging): vox up refused the session over the anchor's circuit (SOCKS reply \
         {code}).\nup:\n{}",
        up.transcript()
    );
    // One echo on the session; whether it came back, and whether it crossed the forward.
    let echo = |s: &mut std::net::TcpStream, w: &ForwardedWorld| -> (bool, bool) {
        let sent = w.forward.to_host();
        let ok = echo_over(s, &payload, Duration::from_secs(10));
        (ok, w.forward.to_host() - sent >= PAYLOAD as u64)
    };
    let (ok, direct) = echo(&mut session, &w);
    assert!(
        ok,
        "PRODUCT (staging): the session's first echo over the anchor's circuit did not come back \
         whole.\nup:\n{}",
        up.transcript()
    );
    assert!(
        !direct,
        "CANNOT MEASURE: the session's first echo crossed the forward while it was closed"
    );
    let n = w.anchor.circuits(Duration::from_secs(2));
    assert!(
        n >= 1,
        "CANNOT MEASURE: the anchor reports {n} circuits with the session open — it is not on a \
         relayed path.\nanchor:\n{}",
        w.anchor.proc.transcript()
    );

    // A direct path becomes possible; the pair's retry finds it, seen by a new request riding it.
    // The session is exercised meanwhile, as a person's would be.
    w.forward.open();
    let opened = Instant::now();
    let mut direct_at = None;
    while opened.elapsed() < UPGRADE_WITHIN {
        std::thread::sleep(Duration::from_millis(500));
        let (ok, _) = echo(&mut session, &w);
        assert!(
            ok,
            "PRODUCT: the session stopped answering {:?} after the forward opened, before any \
             request rode it.\nup:\n{}\nhost:\n{}",
            opened.elapsed(),
            up.transcript(),
            w.host.transcript()
        );
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        if code == 0 && echo(&mut s, &w) == (true, true) {
            direct_at = Some(Instant::now());
            break;
        }
        if ends_disagree(&w, &up) {
            break;
        }
    }
    both_ends_keep_the_same_connection(&mut w, &mut up, direct_at.is_some(), opened);
    let Some(direct_at) = direct_at else {
        panic!(
            "CANNOT MEASURE: {UPGRADE_WITHIN:?} after the forward opened, no request rode it — there \
             is no displaced path under the session.\nup:\n{}",
            up.transcript()
        );
    };
    // Either side's own report that its relayed connection was displaced.
    let displaced = |p: &world::VoxProc| {
        p.timed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(_, l)| l.contains("displaced the one held") && l.contains("Relayed)"))
            .map(|(at, _)| at.saturating_duration_since(opened))
    };
    let (host_displaced, up_displaced) = (displaced(&w.host), displaced(&up));
    assert!(
        host_displaced.is_some() || up_displaced.is_some(),
        "CANNOT MEASURE: a request rode the forward, but neither side reported its relayed \
         connection displaced.\nup:\n{}\nhost:\n{}",
        up.transcript(),
        w.host.transcript()
    );
    eprintln!(
        "[proof] a request rode the direct path {:?} after the forward opened; relayed connection \
         displaced at the host {host_displaced:?}, at the guest {up_displaced:?}",
        direct_at - opened
    );

    // The hold: the session answers, on the displaced path, until well past its grace.
    let mut echoes = 0usize;
    while direct_at.elapsed() < hold {
        std::thread::sleep(Duration::from_secs(3));
        let (ok, direct) = echo(&mut session, &w);
        assert!(
            ok,
            "PRODUCT: CUT — the session opened over the relayed path stopped answering {:?} after \
             the direct path displaced it ({echoes} echoes answered before): a better path cut a \
             live session it carried.\nup:\n{}\nhost:\n{}",
            direct_at.elapsed(),
            up.transcript(),
            w.host.transcript()
        );
        assert!(
            !direct,
            "CANNOT MEASURE: an echo on the session crossed the forward {:?} after the upgrade — it \
             was not on the displaced path",
            direct_at.elapsed()
        );
        echoes += 1;
    }
    let n = w.anchor.circuits(Duration::from_secs(2));
    assert!(
        n >= 1,
        "CANNOT MEASURE: the session answered, but the anchor reports {n} circuits — it was not \
         on the displaced path.\nanchor:\n{}",
        w.anchor.proc.transcript()
    );
    eprintln!(
        "[proof] the session answered {echoes}/{echoes} echoes on the displaced path, the last {:?} \
         after the direct path took over (grace {}s)",
        direct_at.elapsed(),
        vox_core::node::net::RETIRE_GRACE_SECS
    );
    drop(session);
    interrupt(&mut up, Duration::from_secs(15));
    drop(up);
}

/// V210-81 (#272 c6) — **the per-member tunnel cap holds across a path upgrade**, through the
/// shipped `vox`, on the staging above.
///
/// The cap is per member (decider, 2026-10-01): "Past the per-member cap (16), a new tunnel is
/// refused". A member has two connections at once whenever a direct path displaces a relayed one,
/// since the relayed one stays open while its tunnels run. c5 counted per connection, so the new
/// connection started at 0: a member could open 16 tunnels relayed and 16 more direct, and closing
/// one of the old ones freed nothing on the count that refused the next.
///
/// **Staging, observed** (CANNOT MEASURE otherwise): 15 sessions through `vox up` while the
/// forward is closed, each echoing over the anchor's circuit; the forward opens, and a 16th
/// request rides it (the pair went direct, reported displaced by either side), and is held.
///
/// **Asserted:** a 17th session, with 15 tunnels on the displaced path and 1 on the direct one, is
/// refused, and `vox up` says "16 tunnels are already open to this member"; then, one of the
/// relayed sessions closed, a new session is carried within [`FREED_WITHIN`].
///
/// **The mutation that must turn it red:** counting each connection's own tunnels again (c5): the
/// direct connection carries 1, so the 17th is carried.
#[test]
#[ignore = "production Argon2id + a real PoW, a relayed pair upgraded at the tunnel cap; run in release"]
fn the_tunnel_cap_holds_across_a_path_upgrade() {
    /// How long a closed session's tunnel may take to give its place back: its splice ends, and
    /// waits at most `ACK_BOUND` (10 s) for the far end to acknowledge what it sent.
    const FREED_WITHIN: Duration = Duration::from_secs(20);
    const CAP: usize = vox_core::transport::quic::TUNNELS_PER_PEER as usize;
    const LIMIT_SAID: &str = "16 tunnels are already open to this member";
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm();
    let mut w = ForwardedWorld::new(false);
    eprintln!(
        "[proof] guest joined through the relay in {:?}; forward {} (closed) for the host at {}",
        w.joined_in, w.forward.public, w.forward.host
    );
    let hostname = w.hostname();
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();
    let (mut up, proxy, _) = w.up("up");
    // One echo on a session; whether it came back, and whether it crossed the forward.
    let echo = |s: &mut std::net::TcpStream, w: &ForwardedWorld| -> (bool, bool) {
        let sent = w.forward.to_host();
        let ok = echo_over(s, &payload, Duration::from_secs(10));
        (ok, w.forward.to_host() - sent >= PAYLOAD as u64)
    };

    // 15 sessions over the anchor's circuit, each held open.
    let mut relayed = Vec::new();
    for i in 0..CAP - 1 {
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        assert_eq!(
            code,
            0,
            "PRODUCT (staging): vox up refused relayed session {i} of {} (SOCKS reply {code}), \
             below the cap.\nup:\n{}",
            CAP - 1,
            up.transcript()
        );
        let (ok, direct) = echo(&mut s, &w);
        assert!(
            ok && !direct,
            "CANNOT MEASURE: relayed session {i} did not echo over the circuit (came back: {ok}, \
             crossed the forward: {direct})"
        );
        relayed.push(s);
    }
    w.anchor.assert_relayed("with 15 sessions open");

    // A direct path becomes possible; a 16th request finds it and is held.
    w.forward.open();
    let opened = Instant::now();
    let mut on_direct = None;
    while opened.elapsed() < UPGRADE_WITHIN {
        std::thread::sleep(Duration::from_millis(500));
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        if code == 0 && echo(&mut s, &w) == (true, true) {
            on_direct = Some(s);
            break;
        }
    }
    let Some(mut on_direct) = on_direct else {
        panic!(
            "CANNOT MEASURE: {UPGRADE_WITHIN:?} after the forward opened, no request rode it — the \
             pair never went direct.\nup:\n{}",
            up.transcript()
        );
    };
    let displaced = |p: &world::VoxProc| {
        p.timed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|(_, l)| l.contains("displaced the one held") && l.contains("Relayed)"))
    };
    assert!(
        displaced(&w.host) || displaced(&up),
        "CANNOT MEASURE: a request rode the forward, but neither side reported its relayed \
         connection displaced, so the member may not have two connections.\nup:\n{}\nhost:\n{}",
        up.transcript(),
        w.host.transcript()
    );
    let (ok, _) = echo(&mut relayed[0], &w);
    assert!(
        ok,
        "CANNOT MEASURE: a relayed session stopped answering after the upgrade, so the displaced \
         path no longer carries the 15"
    );
    eprintln!(
        "[proof] 15 sessions on the displaced relayed path, 1 on the direct path {:?} after the \
         forward opened",
        opened.elapsed()
    );

    // The 17th: refused, saying why, though the direct connection carries only one.
    let asked = Instant::now();
    let (code, _refused) = socks5_connect(proxy, &hostname, w.service_port);
    // Only what `vox up` said after this request was made: a polling request above may have
    // met the cap while an earlier one was still finishing.
    let told = loop {
        if let Some(l) = up
            .said_since(asked)
            .into_iter()
            .find(|l| l.starts_with("[+") && l.contains(LIMIT_SAID))
        {
            break Ok(l);
        }
        if asked.elapsed() > Duration::from_secs(10) {
            break Err(up.said_since(asked).join("\n"));
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!(
        "[proof] the 17th session: SOCKS reply {code} after {:?}; vox up said: {told:?}",
        asked.elapsed()
    );
    assert!(
        code != 0 && told.is_ok(),
        "PRODUCT: with 16 tunnels open to the host — 15 on the displaced relayed path, 1 on the \
         direct one — a 17th was not refused saying {LIMIT_SAID:?}: SOCKS reply {code}; {told:?}"
    );

    // Closing any one of the member's tunnels gives its place back, wherever it ran.
    drop(relayed.pop());
    let closed = Instant::now();
    let mut carried = false;
    while closed.elapsed() < FREED_WITHIN {
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        if code == 0 && echo(&mut s, &w).0 {
            carried = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!(
        "[proof] after closing one relayed session, a new one carried: {carried} after {:?}",
        closed.elapsed()
    );
    assert!(
        carried,
        "PRODUCT: after one of the member's 16 sessions was closed, no new session was carried \
         within {FREED_WITHIN:?}: closing a tunnel the refusal points at freed nothing.\nup:\n{}",
        up.transcript()
    );
    let _ = echo(&mut on_direct, &w);
    drop(relayed);
    interrupt(&mut up, Duration::from_secs(15));
    drop(up);
}
