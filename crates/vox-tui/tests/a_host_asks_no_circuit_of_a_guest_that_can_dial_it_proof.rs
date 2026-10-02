//! V030-27 (#349) — **a host that cannot dial a just-joined guest, while the guest can dial it,
//! asks the anchor for no circuit**: every reach asks the guest to dial back first, and a relay that
//! could not reach the guest for that dial-back is not asked to carry a circuit to it either.
//!
//! **The defect.** The host asked the anchor for a circuit 0 ms into every reach for the guest —
//! the key resend and the sync retries after a join — before its dial-back through that anchor had
//! even been refused. 4 or 5 a run, refused only while the guest was not yet on the anchor; in 1 of
//! 3 runs of R42's direct arm the guest had reached it in between and the anchor carried one.
//!
//! **The staging — real processes only** (`support/port_forward.rs`'s `ForwardedWorld`). A `vox
//! node` anchor; a `vox serve` host on `127.0.0.1`; the guest on `[::1]`, joined with `vox
//! connect`. Split by address family, the host cannot dial the guest at all, while the guest
//! reaches the host through a port forward the host advertises. The guest then starts
//! [`UPS`] `vox up`s, one after another, each answering one request through the forward.
//!
//! **Asserted.** The premise: the host reached for the guest it cannot dial — its own notes show a
//! dial-back asked or refused (none: `CANNOT MEASURE`). The claim: the host's own `vox status
//! --json` counts **0** circuits asked to the guest for the whole run. Not a timing claim: before
//! the fix the host asked in every run.
//!
//! **The mutation that must turn it red:** the circuit's wait for its relay's word on the dial-back
//! removed from `NodeNet::reach_ladder` — the host asks circuits 0 ms into its reaches: red, as
//! PRODUCT.

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

use std::time::Duration;

use port_forward::{echo_over, interrupt, ForwardedWorld};
use world::socks5_connect;

/// New `vox up`s the guest starts, each a new process the host may reach for.
const UPS: usize = 3;
/// How long one request may take to be echoed.
const GIVE_UP: Duration = Duration::from_secs(60);

/// `field` of `peer`'s `reach` row in the `vox status --json` of the node on `dir`: no answer or no
/// `reach` section is `CANNOT MEASURE`, no row is 0.
fn reach_count(dir: &std::path::Path, peer: &str, who: &str, field: &str) -> u64 {
    let (ok, out, err) = world::vox_once(dir, &world::args(&["status", "--json"]));
    assert!(
        ok,
        "CANNOT MEASURE: {who}'s `vox status --json` did not answer, so its {field} is unknown.\n\
         stdout:\n{out}\nstderr:\n{err}"
    );
    let Some(reach) = out.split("\"reach\":[").nth(1) else {
        panic!("CANNOT MEASURE: {who}'s `vox status --json` has no `reach` section:\n{out}");
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

#[test]
#[ignore = "production Argon2id + a real PoW; run in release"]
fn a_host_asks_no_circuit_of_a_just_joined_guest_that_can_dial_it() {
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm();
    let mut w = ForwardedWorld::new(true);
    let hostname = w.hostname();
    let payload = b"a request through the forward".to_vec();
    for i in 0..UPS {
        let (mut up, proxy, _) = w.up(&format!("up-{i}"));
        let (code, mut s) = socks5_connect(proxy, &hostname, w.service_port);
        assert!(
            code == 0,
            "PRODUCT: up {i}: the CONNECT to {hostname} was refused (SOCKS {code}).\nup:\n{}",
            up.transcript()
        );
        assert!(
            echo_over(&mut s, &payload, GIVE_UP),
            "PRODUCT: up {i}: the CONNECT succeeded but no whole echo came back.\nup:\n{}",
            up.transcript()
        );
        drop(s);
        interrupt(&mut up, Duration::from_secs(15));
    }
    let guest_fp = world::fingerprint(&w.guest_dir, "guest");
    let asked = reach_count(&w.host_dir, &guest_fp, "the host", "circuits");
    let host_said = w.host.transcript();
    let dial_backs: Vec<&str> = host_said
        .lines()
        .filter(|l| {
            l.contains("a dial-back could not be asked") || l.contains("a dial-back was answered")
        })
        .collect();
    let ever = w.anchor.circuits_ever(Duration::from_secs(2));
    eprintln!(
        "[proof] the host reached for the guest it cannot dial {} time(s) by its dial-back notes; \
         circuits it asked to the guest: {asked}; the anchor carried up to {ever}",
        dial_backs.len()
    );
    assert!(
        !dial_backs.is_empty(),
        "CANNOT MEASURE (staging not achieved): the host never reached for the guest it cannot \
         dial (no dial-back asked or refused), so nothing here could have asked for a circuit.\n\
         host:\n{host_said}"
    );
    assert!(
        asked == 0,
        "PRODUCT: the guest can dial the host, yet the host asked the anchor for {asked} \
         circuit(s) to the guest instead of waiting on its dial-back (the anchor carried up to \
         {ever}).\nhost:\n{host_said}\nanchor:\n{}",
        w.anchor.proc.transcript()
    );
}
