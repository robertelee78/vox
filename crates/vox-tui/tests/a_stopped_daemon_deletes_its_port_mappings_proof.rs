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
//! **Which side a red is on.** A deletion that never comes, comes late, or carries another nonce
//! is `PRODUCT:`. A machine with no IPv4 route (no IPv4 mapping asked) is `CANNOT MEASURE`.
//!
//! Mutations, each red as PRODUCT: no deletion at stop (`NetPresence::close` deleting nothing);
//! a losing grant abandoned (`first_success` not deleting the late grants).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/pcp_standin.rs"]
mod pcp_standin;

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
        &[("VOX_TEST_GATEWAY", gateways)],
    );
    d.expect_line("the daemon to start", |l| l.contains("control socket"));
    d
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

/// The first deletion in `log` (a MAP with lifetime 0).
fn deletion(log: &[Request]) -> Option<Request> {
    log.iter().find(|r| r.lifetime == 0).cloned()
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
