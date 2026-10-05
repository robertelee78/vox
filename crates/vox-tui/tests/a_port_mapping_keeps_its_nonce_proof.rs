//! V030-43 (#417, ADR-012 N-55, N-58) — **a PCP mapping keeps its nonce, and is renewed on RFC
//! 6887's schedule**, through the shipped binary.
//!
//! Each PCP request drew a fresh nonce, renewals included, and a renewal re-ran the whole
//! discovery at half the lease. A server in RFC 6887's Simple Threat Model refuses a request for
//! a mapping it holds under another nonce (§11.3), so on a real router the mapping could not be
//! renewed: it ran out, and the node fell off its mapped address.
//!
//! **The staging.** A PCP server stand-in on loopback (`support/pcp_standin.rs`) that grants at
//! most [`GRANT`] seconds and refuses another nonce `NOT_AUTHORIZED`, as §11.3 requires, and a
//! `vox daemon` pointed at it with the test-knobs gateway override `VOX_TEST_GATEWAY`. The
//! stand-in logs every datagram with when it came.
//!
//! **What is asserted, from the stand-in's log:**
//! - every request for the mapping, from its creation until its lease ends, carries **the
//!   creation nonce**: the first renewal, the renewals the stand-in leaves unanswered, and every
//!   retransmission within each (§8.1.1, §11.2.1); none is refused;
//! - the first renewal starts in **1/2–5/8 of the lease** after the grant, and so does the next
//!   after the renewal's grant;
//! - with the stand-in then silent, the renewal is tried again at **3/4 and then 7/8** of the
//!   lease, each attempt **at least 4 s** after the one before.
//!
//! "Uniformly random" is not provable from two samples; that each lies in the window is.
//! Times are allowed [`SLACK`] for the daemon's one-second clock.
//!
//! **Which side a red is on.** Another nonce, a refusal, or an attempt outside its window is
//! `PRODUCT:`. A machine with no IPv4 route (no IPv4 mapping asked) is `CANNOT MEASURE`.
//!
//! Mutation: a renewal drawing a fresh nonce (`renew` with `random_array()` in place of the
//! held nonce) → red, as PRODUCT: the stand-in answers `NOT_AUTHORIZED`.

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
use world::{args, tempdir, utf8, vox_once, Reaper, VoxProc, IDENTITY};

/// The lease the stand-in grants, in seconds: short, so the schedule plays out in under a minute.
const GRANT: u32 = 32;
/// Allowance for the daemon's one-second clock and scheduling.
const SLACK: f64 = 1.5;
/// Requests less than this apart are one attempt and its retransmissions (they are sent at 0,
/// 0.25, 0.75 and 1.75 s).
const ONE_ATTEMPT: Duration = Duration::from_millis(2500);

/// `vox daemon` on a fresh profile at `data`, listening on `0.0.0.0`, pointed at `gateway`.
fn daemon(data: &Path, gateway: &str) -> VoxProc {
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
        &[("VOX_TEST_GATEWAY", gateway)],
    );
    d.expect_line("the daemon to start", |l| l.contains("control socket"));
    d
}

/// Wait up to `within` for the stand-in's log to satisfy `done`; the log either way.
fn wait_for(s: &Standin, within: Duration, done: impl Fn(&[Request]) -> bool) -> Vec<Request> {
    let until = Instant::now() + within;
    loop {
        let log = s.log();
        if done(&log) || Instant::now() > until {
            return log;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The requests grouped into attempts: a request within [`ONE_ATTEMPT`] of the one before is its
/// retransmission.
fn attempts(log: &[Request]) -> Vec<Vec<Request>> {
    let mut out: Vec<Vec<Request>> = Vec::new();
    for r in log {
        match out.last_mut() {
            Some(a) if r.at.duration_since(a[a.len() - 1].at) < ONE_ATTEMPT => a.push(r.clone()),
            _ => out.push(vec![r.clone()]),
        }
    }
    out
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

/// Assert `t` lies in `lo..=hi` seconds, with [`SLACK`].
fn within(what: &str, t: f64, lo: f64, hi: f64, log: &str) {
    assert!(
        t >= lo - SLACK && t <= hi + SLACK,
        "PRODUCT: {what} came {t:.2}s after the grant; RFC 6887 §11.2.1 (N-55) puts it in \
         {lo:.1}–{hi:.1}s of a {GRANT}s lease.\nthe stand-in's log:\n{log}"
    );
}

#[test]
#[ignore = "real binaries and production Argon2id; about a minute; run on demand"]
fn a_pcp_mapping_keeps_its_nonce_and_renews_on_the_rfcs_schedule() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_GATEWAY"]);
    let tmp = tempdir();
    let data = tmp.path().join("node");
    let _reaper = Reaper(vec![data.clone()]);
    let standin = Standin::start(GRANT);
    let _daemon = daemon(&data, &standin.addr.to_string());
    let l = f64::from(GRANT);

    // The grant, then the first renewal, answered.
    let log = wait_for(
        &standin,
        Duration::from_secs(30) + Duration::from_secs(u64::from(GRANT)),
        |log| {
            log.iter()
                .filter(|r| matches!(r.answer, Answer::Granted(_)))
                .count()
                >= 2
        },
    );
    let granted: Vec<&Request> = log
        .iter()
        .filter(|r| matches!(r.answer, Answer::Granted(_)))
        .collect();
    let show = |log: &[Request]| {
        let t0 = log.first().map(|r| r.at);
        log.iter()
            .map(|r| {
                format!(
                    "  +{:.2}s nonce {:02x?} lifetime {} -> {:?}",
                    t0.map_or(0.0, |t| secs(r.at.duration_since(t))),
                    r.nonce,
                    r.lifetime,
                    r.answer
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    if granted.is_empty() {
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
    }
    // Every request in the first lease is for the mapping it created: its nonce, never refused.
    let first = granted.first().map(|r| (r.nonce, r.at));
    if let Some((nonce, g0)) = first {
        let lease = g0 + Duration::from_secs(u64::from(GRANT));
        for r in log.iter().filter(|r| r.at >= g0 && r.at < lease) {
            assert!(
                r.nonce == nonce && r.answer != Answer::NotAuthorized,
                "PRODUCT: a renewal carried another nonce than the mapping's creation (RFC 6887 \
                 §11.3, N-55), and the stand-in answered {:?}.\nthe stand-in's log:\n{}",
                r.answer,
                show(&log)
            );
        }
    }
    assert!(
        granted.len() >= 2,
        "PRODUCT: the mapping was not renewed within {GRANT}s of its grant.\nthe stand-in's log:\n{}",
        show(&log)
    );
    let nonce = granted[0].nonce;
    let (g0, g1) = (granted[0].at, granted[1].at);
    within(
        "the first renewal",
        secs(g1.duration_since(g0)),
        l / 2.0,
        l * 5.0 / 8.0,
        &show(&log),
    );

    // Silent from here: the next renewal, then its retries at 3/4 and 7/8.
    standin.set_silent(true);
    let end = g1 + Duration::from_secs(u64::from(GRANT));
    let rest = wait_for(
        &standin,
        end.saturating_duration_since(Instant::now())
            .saturating_sub(Duration::from_millis(500)),
        |_| false,
    );
    let text = show(&rest);
    println!("[proof] the stand-in's log:\n{text}");
    let before_end: Vec<Request> = rest.iter().filter(|r| r.at < end).cloned().collect();
    for r in &before_end {
        assert_eq!(
            r.nonce, nonce,
            "PRODUCT: a request for the mapping carried another nonce than its creation's \
             (RFC 6887 §11.3, N-55); the stand-in answered {:?}.\nthe stand-in's log:\n{text}",
            r.answer
        );
        assert_ne!(
            r.answer,
            Answer::NotAuthorized,
            "PRODUCT: the stand-in refused a renewal NOT_AUTHORIZED.\nthe stand-in's log:\n{text}"
        );
    }
    let after: Vec<Request> = before_end.iter().filter(|r| r.at > g1).cloned().collect();
    let tries = attempts(&after);
    let starts: Vec<f64> = tries
        .iter()
        .map(|a| secs(a[0].at.duration_since(g1)))
        .collect();
    println!("[proof] attempts after the renewal's grant start at {starts:.2?} s");
    assert!(
        tries.len() >= 3,
        "PRODUCT: after the renewal's grant, with the stand-in silent, the mapping must be tried \
         at 1/2–5/8, 3/4 and 7/8 of its {GRANT}s lease; the attempts started at {starts:.2?} s.\n\
         the stand-in's log:\n{text}"
    );
    within(
        "the second renewal",
        starts[0],
        l / 2.0,
        l * 5.0 / 8.0,
        &text,
    );
    within(
        "the retry after a failed renewal",
        starts[1],
        l * 3.0 / 4.0,
        l * 3.0 / 4.0 + 4.0,
        &text,
    );
    within(
        "the second retry",
        starts[2],
        l * 7.0 / 8.0,
        l * 7.0 / 8.0 + 4.0,
        &text,
    );
    for w in starts.windows(2) {
        assert!(
            w[1] - w[0] >= 4.0,
            "PRODUCT: two renewal attempts {:.2}s apart; RFC 6887 §11.2.1 (N-55) wants at least \
             4 s.\nthe stand-in's log:\n{text}",
            w[1] - w[0]
        );
    }
    assert!(
        tries.iter().any(|a| a.len() > 1),
        "PRODUCT: no unanswered renewal was retransmitted, so §8.1.1's same-nonce \
         retransmission is unshown.\nthe stand-in's log:\n{text}"
    );
}
