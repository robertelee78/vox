//! V030-44 (#418, ADR-012 N-56, N-57, N-58) — **a daemon deletes its port mappings when it
//! stops, and a raced gateway's grant it does not use at once**, through the shipped binary.
//!
//! Before, no PCP or NAT-PMP mapping was deleted at stop (only a permanent UPnP one), and the
//! grant of a raced candidate that lost was left to expire: each held a port on its gateway for
//! up to two hours after nothing listened behind it. This closes N-43's "not proved".
//!
//! **The staging.** Two PCP server stand-ins on loopback (`support/pcp_standin.rs`, RFC 6887's
//! MAP with its nonce rule and deletion), both answering, and a `vox daemon` pointed at both
//! with the test-knobs gateway override `VOX_TEST_GATEWAY`, so the two are raced and both grant.
//!
//! **What is asserted, from the stand-ins' logs and `vox status --json`:**
//! - the two grants carry **different nonces** (N-55: nonces differ between servers);
//! - **the losing grant is deleted as the race ends** (N-57): the stand-in `vox status` does not
//!   name as the one that answered receives a MAP with lifetime 0 and its grant's nonce, within
//!   [`UNMAP_PATIENCE`] of its grant, and deletes it;
//! - **the winner is deleted at stop** (N-56): after a SIGTERM to the daemon (by its pid), the
//!   stand-in that answered receives a MAP with lifetime 0 and its grant's nonce within
//!   [`UNMAP_PATIENCE`], and deletes it; the daemon exits cleanly.
//!
//! **Three more arms, each its own test:**
//! - **a UPnP mapping is deleted at stop without a search** (N-56): a UPnP IGD stand-in
//!   (`support/upnp_standin.rs`) answers SSDP at the edge of what UPnP allows (2.2 s; a device may
//!   wait up to the search's MX, 2 s, plus the way back). The daemon maps through it (the PCP
//!   stand-in it is pointed at is silent), and after SIGTERM the stand-in receives
//!   `DeletePortMapping` for the port within [`UNMAP_PATIENCE`], with no search after the stop:
//!   the grant's control URL was kept. Searching again at stop would cost the 2.2 s alone.
//! - **a grant that comes while the daemon stops is deleted** (N-56, N-57): stand-in B answers
//!   4 s late (it makes the mapping on receipt), A at once; A wins, and the daemon is stopped
//!   while B's answer is still on its way. B receives a deletion with the nonce it was asked
//!   with, within [`UNMAP_PATIENCE`] of the SIGTERM.
//! - **one router asked at two addresses keeps its mapping**: one NAT-PMP-only stand-in named
//!   twice (as `.1` and the anycast address can both be one router). Both candidates are granted
//!   the one mapping, which has no nonce to tell them apart; the losing "grant" is the winner's own
//!   mapping and is not deleted while the daemon runs; it is deleted at stop.
//!
//! **Which side a red is on.** A deletion that never comes, comes late, or carries another nonce
//! is `PRODUCT:`. A machine with no IPv4 route (no IPv4 mapping asked) is `CANNOT MEASURE`.
//!
//! Mutations, each red as PRODUCT: no deletion at stop (`NetPresence::close` deleting nothing);
//! a losing grant abandoned (`first_success` not deleting the late grants); a UPnP deletion that
//! searches again (`unmap` ignoring the kept control URL); the races not settled at stop
//! (`Races::to_delete` returning nothing); every losing grant deleted (`same_mapping` false).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/pcp_standin.rs"]
mod pcp_standin;

#[path = "support/upnp_standin.rs"]
mod upnp_standin;

use std::path::Path;
use std::time::{Duration, Instant};

use pcp_standin::{Answer, Request, Standin};
use serde_json::Value;
use world::{args, tempdir, utf8, vox_once, Reaper, VoxProc, IDENTITY};

/// ADR-012 N-56's bound on the deletions at stop, and the one this proof gives a losing grant's.
const UNMAP_PATIENCE: Duration = Duration::from_secs(2);
/// Allowance for scheduling between the stand-in's clock and the event it is measured from.
const SLACK: Duration = Duration::from_millis(500);

/// `vox daemon` on a fresh profile at `data`, listening on `0.0.0.0`, pointed at `gateways`.
fn daemon(data: &Path, gateways: &str) -> VoxProc {
    daemon_env(data, &[("VOX_TEST_GATEWAY", gateways)])
}

/// `vox daemon` on a fresh profile at `data`, listening on `0.0.0.0`, with the knobs `env`.
fn daemon_env(data: &Path, env: &[(&str, &str)]) -> VoxProc {
    world::mkdir(&data.join("cfg"));
    let (ok, _, err) = vox_once(data, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): vox id failed: {err}");
    let pass = data.join("daemon-passphrase");
    std::fs::write(&pass, format!("{IDENTITY}\n"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write {}: {e}", pass.display()));
    let mut d = VoxProc::spawn_env(
        "daemon",
        data,
        &args(&[
            "daemon",
            "--passphrase-file",
            &utf8(&pass),
            "--listen",
            "0.0.0.0:0",
        ]),
        env,
    );
    d.expect_line("the daemon to start", |l| l.contains("control socket"));
    d
}

/// SIGTERM to the daemon `d`, by its pid; when it was sent, and how the daemon ended.
fn stop(d: &mut VoxProc) -> (Instant, Option<std::process::ExitStatus>) {
    let pid = d.child.id();
    let at = Instant::now();
    let killed = std::process::Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot signal the daemon {pid}: {e}"));
    assert!(killed.success(), "APPARATUS: kill -TERM {pid} failed");
    let exited = loop {
        if let Some(status) = d.child.try_wait().unwrap_or(None) {
            break Some(status);
        }
        if at.elapsed() > Duration::from_secs(30) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (at, exited)
}

/// Wait up to `within` for `done`.
fn wait(within: Duration, done: impl Fn() -> bool) -> bool {
    let until = Instant::now() + within;
    while !done() {
        if Instant::now() > until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

/// A CANNOT MEASURE red unless this machine has an IPv4 default route.
fn require_ipv4_route() {
    let route = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    assert!(
        route.contains("gateway"),
        "CANNOT MEASURE (precondition unmet): no IPv4 default route, so no IPv4 mapping is asked \
         for:\n{route}"
    );
}

fn show(name: &str, log: &[Request], t0: Instant) -> String {
    let lines: Vec<String> = log
        .iter()
        .map(|r| {
            format!(
                "  {name} +{:.2}s nonce {:02x?} lifetime {} -> {:?}",
                r.at.saturating_duration_since(t0).as_secs_f64(),
                r.nonce,
                r.lifetime,
                r.answer
            )
        })
        .collect();
    lines.join("\n")
}

/// The first grant in `log`.
fn grant(log: &[Request]) -> Option<Request> {
    log.iter()
        .find(|r| matches!(r.answer, Answer::Granted(_)))
        .cloned()
}

/// The first deletion in `log`: a map request with lifetime 0 (not another kind of request,
/// which is logged with lifetime 0 too).
fn deletion(log: &[Request]) -> Option<Request> {
    log.iter()
        .find(|r| r.lifetime == 0 && !matches!(r.answer, Answer::NotPcp | Answer::Unsupported))
        .cloned()
}

#[test]
#[ignore = "real binaries and production Argon2id; run on demand"]
fn a_stopped_daemon_deletes_its_mappings_and_a_losing_grant_at_once() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_GATEWAY"]);
    let tmp = tempdir();
    let data = tmp.path().join("node");
    let _reaper = Reaper(vec![data.clone()]);
    let (a, b) = (Standin::start(7200), Standin::start(7200));
    let t0 = Instant::now();
    let mut d = daemon(&data, &format!("{},{}", a.addr, b.addr));
    let logs = || format!("{}\n{}", show("A", &a.log(), t0), show("B", &b.log(), t0));

    // Both grant; the winner is the one `vox status` names.
    let until = Instant::now() + Duration::from_secs(30);
    while (grant(&a.log()).is_none() || grant(&b.log()).is_none()) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(100));
    }
    let (Some(ga), Some(gb)) = (grant(&a.log()), grant(&b.log())) else {
        let route = std::process::Command::new("/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        assert!(
            route.contains("gateway"),
            "CANNOT MEASURE (precondition unmet): no IPv4 default route, so no IPv4 mapping is \
             asked for:\n{route}"
        );
        panic!(
            "PRODUCT: both stand-ins were to be asked and grant; they logged:\n{}",
            logs()
        );
    };
    assert_ne!(
        ga.nonce,
        gb.nonce,
        "PRODUCT: two PCP servers were given one nonce (N-55: nonces differ between servers):\n{}",
        logs()
    );
    let answered = {
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            let (ok, out, err) = vox_once(&data, &args(&["status", "--json"]));
            assert!(
                ok,
                "PRODUCT: `vox status --json` did not answer: {out}\n{err}"
            );
            let v: Value = serde_json::from_str(&out).unwrap_or_else(|e| {
                panic!("PRODUCT: `vox status --json` is not JSON ({e}):\n{out}")
            });
            if let Some(at) = v["gateway"]["ipv4"]["answered"]["address"].as_str() {
                break at.to_owned();
            }
            assert!(
                Instant::now() < until,
                "PRODUCT: both stand-ins granted, but `vox status` names no answer: {}",
                v["gateway"]
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    let (winner, loser, won, lost) = if answered == a.addr.to_string() {
        (&a, &b, ga, gb)
    } else {
        assert_eq!(
            answered,
            b.addr.to_string(),
            "PRODUCT: vox names {answered} as the gateway that answered, neither stand-in"
        );
        (&b, &a, gb, ga)
    };
    println!(
        "[proof] the winner is {}, the loser {}",
        winner.addr, loser.addr
    );

    // ---- the losing grant is deleted at once (N-57) ----
    let until = lost.at + UNMAP_PATIENCE + Duration::from_secs(4);
    while deletion(&loser.log()).is_none() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(100));
    }
    let gone = deletion(&loser.log()).unwrap_or_else(|| {
        panic!(
            "PRODUCT: the losing stand-in {}'s grant was never deleted (N-57):\n{}",
            loser.addr,
            logs()
        )
    });
    println!(
        "[proof] the losing grant was deleted {:.2}s after it was granted",
        gone.at.duration_since(lost.at).as_secs_f64()
    );
    assert!(
        gone.nonce == lost.nonce && gone.answer == Answer::Deleted,
        "PRODUCT: the losing grant's deletion must carry its nonce and delete it:\n{}",
        logs()
    );
    assert!(
        gone.at.duration_since(lost.at) <= UNMAP_PATIENCE + SLACK,
        "PRODUCT: the losing grant was deleted {:.2}s after it was granted; N-57 wants it as the \
         race ends:\n{}",
        gone.at.duration_since(lost.at).as_secs_f64(),
        logs()
    );
    assert!(
        deletion(&winner.log()).is_none(),
        "PRODUCT: the winning grant, which the daemon holds, was deleted while it runs:\n{}",
        logs()
    );

    // ---- the winner is deleted at stop (N-56) ----
    let pid = d.child.id();
    let stop = Instant::now();
    let killed = std::process::Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot signal the daemon {pid}: {e}"));
    assert!(killed.success(), "APPARATUS: kill -TERM {pid} failed");
    let exited = loop {
        if let Some(status) = d.child.try_wait().unwrap_or(None) {
            break Some(status);
        }
        if stop.elapsed() > Duration::from_secs(30) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    println!(
        "[proof] the daemon exited {exited:?} {:.2}s after SIGTERM",
        stop.elapsed().as_secs_f64()
    );
    let gone = deletion(&winner.log()).unwrap_or_else(|| {
        panic!(
            "PRODUCT: the daemon stopped and never deleted its mapping at {} (N-56):\n{}",
            winner.addr,
            logs()
        )
    });
    let after = gone.at.saturating_duration_since(stop);
    println!(
        "[proof] the held mapping was deleted {:.2}s after SIGTERM",
        after.as_secs_f64()
    );
    assert!(
        gone.nonce == won.nonce && gone.answer == Answer::Deleted,
        "PRODUCT: the deletion at stop must carry the mapping's nonce and delete it:\n{}",
        logs()
    );
    assert!(
        gone.at >= stop && after <= UNMAP_PATIENCE + SLACK,
        "PRODUCT: the held mapping was deleted {:.2}s after SIGTERM; N-56 bounds it at {}s:\n{}",
        after.as_secs_f64(),
        UNMAP_PATIENCE.as_secs(),
        logs()
    );
    assert!(
        exited.is_some_and(|s| s.success()),
        "PRODUCT: the daemon did not exit cleanly after SIGTERM: {exited:?}"
    );
}

#[test]
#[ignore = "real binaries and production Argon2id; run on demand"]
fn a_upnp_mapping_is_deleted_at_stop_without_a_search() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_GATEWAY", "VOX_TEST_UPNP"]);
    require_ipv4_route();
    let tmp = tempdir();
    let data = tmp.path().join("node");
    let _reaper = Reaper(vec![data.clone()]);
    let pcp = Standin::start(7200);
    pcp.set_silent(true);
    let igd = upnp_standin::UpnpStandin::start(Duration::from_millis(2200));
    let mut d = daemon_env(
        &data,
        &[
            ("VOX_TEST_GATEWAY", &pcp.addr.to_string()),
            ("VOX_TEST_UPNP", &igd.ssdp.to_string()),
        ],
    );
    let t0 = Instant::now();
    let show = || {
        igd.log()
            .iter()
            .map(|a| {
                format!(
                    "  +{:.2}s {} {:?}",
                    a.at.saturating_duration_since(t0).as_secs_f64(),
                    a.what,
                    a.port
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let mapped = wait(Duration::from_secs(30), || {
        igd.log().iter().any(|a| a.what == "AddPortMapping")
    });
    assert!(
        mapped,
        "PRODUCT: the daemon never mapped through the UPnP stand-in:\n{}",
        show()
    );
    let port = igd
        .log()
        .iter()
        .find(|a| a.what == "AddPortMapping")
        .and_then(|a| a.port)
        .unwrap_or_else(|| panic!("APPARATUS: the stand-in logged no port:\n{}", show()));
    // The grant is held once `vox status` names it.
    let named = wait(Duration::from_secs(15), || {
        let (ok, out, _) = vox_once(&data, &args(&["status", "--json"]));
        ok && serde_json::from_str::<Value>(&out)
            .is_ok_and(|v| v["gateway"]["ipv4"]["answered"]["rung"].as_str() == Some("UPnP-IGD"))
    });
    assert!(
        named,
        "PRODUCT: `vox status` never named the UPnP grant:\n{}",
        show()
    );
    let (stopped, exited) = stop(&mut d);
    let deleted = wait(UNMAP_PATIENCE + Duration::from_secs(3), || {
        igd.log().iter().any(|a| a.what == "DeletePortMapping")
    });
    let log = igd.log();
    println!("[proof] the UPnP stand-in's log:\n{}", show());
    let searched_after = log.iter().any(|a| a.what == "search" && a.at >= stopped);
    let gone = log.iter().find(|a| a.what == "DeletePortMapping");
    assert!(
        deleted && gone.is_some_and(|a| a.port == Some(port)),
        "PRODUCT: the daemon stopped and the UPnP mapping of port {port} was never deleted \
         (N-56){}:\n{}",
        if searched_after {
            ", and it searched for the router again first"
        } else {
            ""
        },
        show()
    );
    let after = gone.map_or(Duration::MAX, |a| a.at.saturating_duration_since(stopped));
    println!(
        "[proof] DeletePortMapping {:.2}s after SIGTERM; a search after the stop: {searched_after}",
        after.as_secs_f64()
    );
    assert!(
        after <= UNMAP_PATIENCE + SLACK && !searched_after,
        "PRODUCT: the UPnP deletion came {:.2}s after SIGTERM (N-56 bounds it at {}s){}:\n{}",
        after.as_secs_f64(),
        UNMAP_PATIENCE.as_secs(),
        if searched_after {
            ", after searching for the router again"
        } else {
            ""
        },
        show()
    );
    assert!(
        exited.is_some_and(|s| s.success()),
        "PRODUCT: the daemon did not exit cleanly: {exited:?}"
    );
}

#[test]
#[ignore = "real binaries and production Argon2id; run on demand"]
fn a_grant_that_comes_while_the_daemon_stops_is_deleted() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_GATEWAY"]);
    require_ipv4_route();
    let tmp = tempdir();
    let data = tmp.path().join("node");
    let _reaper = Reaper(vec![data.clone()]);
    let (a, b) = (Standin::start(7200), Standin::start(7200));
    b.set_delay(Duration::from_secs(4));
    let t0 = Instant::now();
    let mut d = daemon(&data, &format!("{},{}", a.addr, b.addr));
    let logs = || format!("{}\n{}", show("A", &a.log(), t0), show("B", &b.log(), t0));
    // A grants at once and wins; B has the request and has not answered.
    let asked = wait(Duration::from_secs(30), || {
        grant(&a.log()).is_some() && !b.log().is_empty()
    });
    assert!(
        asked,
        "PRODUCT: both stand-ins were to be asked, A to grant:\n{}",
        logs()
    );
    let named = wait(Duration::from_secs(3), || {
        let (ok, out, _) = vox_once(&data, &args(&["status", "--json"]));
        ok && serde_json::from_str::<Value>(&out).is_ok_and(|v| {
            v["gateway"]["ipv4"]["answered"]["address"].as_str() == Some(&a.addr.to_string())
        })
    });
    assert!(
        named,
        "PRODUCT: `vox status` never named A as the gateway that answered:\n{}",
        logs()
    );
    let asked_b = b.log()[0].clone();
    let (stopped, exited) = stop(&mut d);
    assert!(
        stopped < asked_b.at + Duration::from_secs(4),
        "CANNOT MEASURE: the stop came after B's late answer, so no grant was on its way:\n{}",
        logs()
    );
    wait(UNMAP_PATIENCE + Duration::from_secs(3), || {
        deletion(&b.log()).is_some()
    });
    println!("[proof] the stand-ins' logs:\n{}", logs());
    let gone = deletion(&b.log()).unwrap_or_else(|| {
        panic!(
            "PRODUCT: B's mapping, asked for and granted while the daemon stopped, was never \
             deleted (N-56, N-57):\n{}",
            logs()
        )
    });
    let after = gone.at.saturating_duration_since(stopped);
    println!(
        "[proof] B's grant was deleted {:.2}s after SIGTERM",
        after.as_secs_f64()
    );
    assert!(
        gone.nonce == asked_b.nonce
            && gone.answer == Answer::Deleted
            && after <= UNMAP_PATIENCE + SLACK,
        "PRODUCT: B's deletion must carry the nonce it was asked with, delete it, and come within \
         {}s of the stop ({:.2}s):\n{}",
        UNMAP_PATIENCE.as_secs(),
        after.as_secs_f64(),
        logs()
    );
    assert!(
        exited.is_some_and(|s| s.success()),
        "PRODUCT: the daemon did not exit cleanly: {exited:?}"
    );
}

#[test]
#[ignore = "real binaries and production Argon2id; run on demand"]
fn one_router_asked_at_two_addresses_keeps_its_mapping() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_GATEWAY"]);
    require_ipv4_route();
    let tmp = tempdir();
    let data = tmp.path().join("node");
    let _reaper = Reaper(vec![data.clone()]);
    let router = Standin::start_natpmp(7200);
    let t0 = Instant::now();
    let at = router.addr.to_string();
    let mut d = daemon(&data, &format!("{at},{at}"));
    let grants = || {
        router
            .log()
            .iter()
            .filter(|r| matches!(r.answer, Answer::Granted(_)))
            .count()
    };
    let both = wait(Duration::from_secs(30), || grants() >= 2);
    assert!(
        both,
        "PRODUCT: both candidates were to be granted the router's one NAT-PMP mapping:\n{}",
        show("R", &router.log(), t0)
    );
    // Long enough for a losing grant's deletion to have come (it comes at once).
    std::thread::sleep(UNMAP_PATIENCE + Duration::from_secs(1));
    let early = deletion(&router.log());
    println!(
        "[proof] the router's log:\n{}",
        show("R", &router.log(), t0)
    );
    assert!(
        early.is_none(),
        "PRODUCT: the daemon deleted its own mapping while it runs: the losing candidate was the \
         winner's router at another address, granted the same mapping:\n{}",
        show("R", &router.log(), t0)
    );
    let (stopped, exited) = stop(&mut d);
    wait(UNMAP_PATIENCE + Duration::from_secs(3), || {
        deletion(&router.log()).is_some()
    });
    let gone = deletion(&router.log()).unwrap_or_else(|| {
        panic!(
            "PRODUCT: the daemon stopped and never deleted its mapping (N-56):\n{}",
            show("R", &router.log(), t0)
        )
    });
    assert!(
        gone.answer == Answer::Deleted
            && gone.at.saturating_duration_since(stopped) <= UNMAP_PATIENCE + SLACK,
        "PRODUCT: the mapping must be deleted within {}s of the stop:\n{}",
        UNMAP_PATIENCE.as_secs(),
        show("R", &router.log(), t0)
    );
    assert!(
        exited.is_some_and(|s| s.success()),
        "PRODUCT: the daemon did not exit cleanly: {exited:?}"
    );
}
