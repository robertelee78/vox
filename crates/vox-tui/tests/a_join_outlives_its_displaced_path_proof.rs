//! A join must survive the path it started on being displaced by a better one (V210-87, #279).
//!
//! **The defect.** A member answering a join ran the exchange holding only the join's streams.
//! When a better path to the joiner arrived — a direct connection displacing the relayed one the
//! join had started on — the old connection was retired, and a retired connection is closed once
//! its 60s grace is up *unless something still holds it*: a sync or a tunnel does, a join did not.
//! So a joiner still grinding its proof of work had its connection closed under it. The member's
//! own report, from a debug run of the new-joiner proof: `a retired connection … was closed: its
//! grace was over and nothing was carried on it`, then `a join did not complete — answering …:
//! peer unreachable: quic stream: closed by the peer`; the joiner was told no member could be
//! reached. The release build grinds in a second or two and never met the grace; the unoptimized
//! build grinds 22–194s, and so does a slow device.
//!
//! **The staging — real processes only** (`support/port_forward.rs`): a `vox node` anchor on
//! `[::]`, a `vox serve` host on `127.0.0.1` advertising a port forward the proof owns (via the
//! proof-only `VOX_TEST_ADVERTISE`), and the guest on `[::1]` joining with `vox connect`. Split by
//! address family, the pair can only meet through the anchor's circuit until the forward opens.
//! The guest is started with `VOX_TEST_SOLVE_AT_LEAST_MS` = 300s, the product's test-only floor on
//! its own grind (inert when unset), standing in for a slow device. The forward is closed when the
//! join starts and opened 10s in, so a direct path appears while the guest is still grinding.
//!
//! **Observed, never assumed** (CANNOT MEASURE otherwise): the host reports its *relayed*
//! connection to the guest displaced at least 75s before the grind ends — its 60s grace and the
//! tick that closes it fit inside the grind — and the forward carried datagrams to the host. A run
//! in which that path closed mid-grind and the join still got in was not measuring it (the join had
//! gone direct), and is CANNOT MEASURE.
//!
//! **Asserted:** the guest's `vox connect` joins, and the host reports no join that did not
//! complete.
//!
//! **The mutation that must turn it red:** drop the connection the join task holds
//! (`let _carried = conn;` in `Node::answer_inbound_join`): the host closes the displaced path
//! when its grace ends, about 60s after the upgrade and inside the 300s grind, and the join
//! fails.

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

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use port_forward::{free_v4_udp_port, PortForward};
use world::{after_label, args, echo_service, room_pass_file, vox_once, VoxProc};

/// The guest's grind floor: long enough that a displacement on the host's 60s upgrade retry still
/// has its 60s grace end mid-grind.
const GRIND_MS: u64 = 300_000;
/// How long before the grind ends the relayed path must have been displaced, for its grace (60s,
/// and the tick that closes it) to have run out under the join if nothing held it.
const GRACE_AND_TICK: Duration = Duration::from_secs(75);
/// How long the guest may take to reach the host through the anchor's circuit after it starts:
/// it unlocks its identity first (production Argon2id).
const RELAYED_WITHIN: Duration = Duration::from_secs(180);
/// How long the join may take in all: the grind, and the rest of the exchange with room.
const JOIN_WITHIN: Duration = Duration::from_secs(480);

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

#[test]
#[ignore = "a grind floored at 300s, a relayed then direct path, real processes; CI runs it in release"]
fn a_join_outlives_its_displaced_path() {
    test_knobs::require(&["VOX_TEST_ADVERTISE", "VOX_TEST_SOLVE_AT_LEAST_MS"]);
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let mut anchor = relay::Anchor::start(&anchor_dir);
    let (ok, guest_fp, err) = vox_once(&guest_dir, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id (guest): {err}");
    let (ok, _, err) = vox_once(&host_dir, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id (host): {err}");
    let (ok, out, err) = vox_once(
        &host_dir,
        &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
    );
    assert!(ok, "CANNOT MEASURE: trust add: {out}\n{err}");

    let host_addr: SocketAddr = format!("127.0.0.1:{}", free_v4_udp_port()).parse().unwrap();
    let forward = PortForward::start(host_addr, false);
    let advertise = forward.public.to_string();
    let mut host = VoxProc::spawn_env(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &echo_service().to_string(),
            "--anchor",
            &anchor.v4_spec,
            "--listen",
            &host_addr.to_string(),
        ]),
        &[("VOX_TEST_ADVERTISE", advertise.as_str())],
    );
    let address = after_label(
        &host.expect_line("address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );

    let t0 = Instant::now();
    let grind = GRIND_MS.to_string();
    let mut guest = VoxProc::spawn_env(
        "guest",
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
            "--anchor",
            &anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
        &[("VOX_TEST_SOLVE_AT_LEAST_MS", grind.as_str())],
    );
    // The forward opens only once the guest has reached the host through the anchor's circuit,
    // so the join is on the relayed path and a direct one appears under it, mid-grind. Opened on
    // a timer instead, a guest slow to unlock found the forward already open and went direct.
    while anchor.circuits(Duration::from_secs(1)) == 0 {
        assert!(
            t0.elapsed() < RELAYED_WITHIN,
            "CANNOT MEASURE: the guest never reached the host through the anchor's circuit\n\
             guest:\n{}",
            guest.transcript()
        );
    }
    let relayed_at = t0.elapsed();
    forward.open();
    let status = loop {
        if let Some(status) = guest.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            t0.elapsed() < JOIN_WITHIN,
            "the guest's join had not ended after {JOIN_WITHIN:?}\nguest:\n{}\nhost:\n{}",
            guest.transcript(),
            host.transcript()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let took = t0.elapsed();
    // Let the output readers catch up with a process that has already exited.
    std::thread::sleep(Duration::from_millis(500));
    let (guest_said, host_said) = (guest.transcript(), host.transcript());
    for l in host.said_since(t0) {
        eprintln!("[host] {l}");
    }
    // The host's own report of the relayed path the join started on being displaced, and when.
    let displaced_at = host
        .timed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|(_, l)| l.contains("displaced the one held") && l.contains("Relayed)"))
        .map(|(at, l)| {
            let tag = l
                .split("displaced the one held ")
                .nth(1)
                .and_then(|r| r.split_whitespace().next())
                .unwrap_or_default()
                .to_owned();
            (at.saturating_duration_since(t0), tag)
        });
    // The displaced path closed while the join was still grinding, and the join got in anyway:
    // then the join was not on it, and this run measured nothing about it. A join on it keeps it
    // open until the exchange ends, which is the evidence the join rode it.
    let closed_under_the_join = displaced_at.as_ref().is_some_and(|(_, tag)| {
        host.timed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|(at, l)| {
                l.contains(&format!("a retired connection {tag} was closed"))
                    // Before the grind ended: a join on it holds it until the exchange is done,
                    // and no join can be done before its grind floor.
                    && at.saturating_duration_since(t0) < Duration::from_millis(GRIND_MS)
            })
    });
    let displaced_at = displaced_at.map(|(d, _)| d);
    let displaced = displaced_at.map_or("never".to_owned(), |d| {
        format!("at {:.1}s", d.as_secs_f64())
    });
    eprintln!(
        "[proof] {} displaced-path join (grind ≥ {}s): relayed at {:.1}s, relayed path displaced \
         {displaced}, {} in {:.1}s; forward carried {} datagram bytes to the host",
        profile(),
        GRIND_MS / 1000,
        relayed_at.as_secs_f64(),
        if status.success() {
            "got in"
        } else {
            "refused"
        },
        took.as_secs_f64(),
        forward.to_host()
    );
    assert!(
        displaced_at.is_some_and(|d| d + GRACE_AND_TICK <= Duration::from_millis(GRIND_MS))
            && forward.to_host() > 0,
        "CANNOT MEASURE: the host's relayed path to the guest was not displaced early enough for \
         its grace to end mid-grind (displaced {displaced}, grind {}s, forward to host {} B)\n\
         host:\n{host_said}\nguest:\n{guest_said}",
        GRIND_MS / 1000,
        forward.to_host()
    );
    assert!(
        !(status.success() && closed_under_the_join),
        "CANNOT MEASURE: the displaced relayed path was closed mid-grind and the join got in anyway, \
         so the join was not on it\nhost:\n{host_said}"
    );
    assert!(
        status.success(),
        "a join whose path was displaced mid-grind failed after {:.1}s\nguest:\n{guest_said}\n\
         host (the refusing side's own report):\n{host_said}",
        took.as_secs_f64()
    );
    assert!(
        took >= Duration::from_millis(GRIND_MS),
        "CANNOT MEASURE: the join took {:.1}s, under the {}s grind floor",
        took.as_secs_f64(),
        GRIND_MS / 1000
    );
    assert!(
        !host_said.contains("a join did not complete"),
        "the host reported a join that did not complete although the guest got in:\n{host_said}"
    );
    eprintln!(
        "[proof] {} displaced-path join: 1/1 got in after its path was displaced, {:.1}s",
        profile(),
        took.as_secs_f64()
    );
}
