//! V030-42 (#416, ADR-012 N-54, N-58) — **`vox status` says which gateways were asked for a port
//! mapping and which one answered, on which rung**, through the shipped binary.
//!
//! Before, `vox status` said nothing of the gateway: a person whose node was not reachable from
//! outside could not tell whether any router was asked, which, or whether one answered.
//!
//! **The staging.** A PCP server stand-in the proof runs on loopback (`support/pcp_standin.rs`,
//! RFC 6887's MAP as a real server answers it), and a `vox daemon` pointed at it with the
//! test-knobs gateway override `VOX_TEST_GATEWAY`, which replaces every candidate the machine
//! would ask (and leaves UPnP's search out), so the stand-in is the only server asked. The daemon
//! listens on `0.0.0.0`, so its IPv4 work runs; IPv6 is not asked (the override names no IPv6
//! server).
//!
//! **Two arms:**
//! - **the stand-in answers:** `vox status --json`'s `gateway.ipv4` names the stand-in's address
//!   as asked, and `answered` is that address on rung `PCP`; the stand-in logged the MAP it
//!   granted. `vox status` says "asked <stand-in>: PCP answered at <stand-in>".
//! - **the stand-in is silent:** another daemon, pointed at a silent stand-in, names it as asked
//!   and `answered` null once its discovery ends; `vox status` says "none answered". The stand-in
//!   logged the requests, so the ask really happened.
//!
//! **Which side a red is on.** `vox` naming the wrong server, the wrong rung, an answer that never
//! came, or no ask, is `PRODUCT:`. A machine with no IPv4 route (so no IPv4 mapping is asked at
//! all) is `CANNOT MEASURE (precondition unmet)`. A `vox` without `test-knobs` is `CANNOT MEASURE`.
//!
//! Mutation: the report of what answered dropped (`GatewayAsk::of` naming no answer) → red on
//! the first arm, as PRODUCT.

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

use pcp_standin::{Answer, Standin};
use serde_json::Value;
use world::{args, tempdir, utf8, vox_once, Reaper, VoxProc, IDENTITY};

/// How long a discovery may take: PCP's retransmissions (3.75 s) then NAT-PMP's, with room.
const DISCOVERY: Duration = Duration::from_secs(30);

/// A profile at `<root>/<name>` with its identity made.
fn profile(root: &Path, name: &str) -> std::path::PathBuf {
    let data = root.join(name);
    world::mkdir(&data.join("cfg"));
    let (ok, _, err) = vox_once(&data, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): vox id for {name} failed: {err}");
    data
}

/// `vox daemon` on `data`, listening on `0.0.0.0`, pointed at `gateway`.
fn daemon(data: &Path, gateway: &str) -> VoxProc {
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

/// `vox status --json` on `data` once its IPv4 discovery has asked someone: the report.
fn status_after_discovery(data: &Path) -> Value {
    let started = Instant::now();
    loop {
        let (ok, out, err) = vox_once(data, &args(&["status", "--json"]));
        assert!(
            ok,
            "PRODUCT: `vox status --json` did not answer.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v: Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON ({e}):\n{out}"));
        let asked = v["gateway"]["ipv4"]["asked"].as_array().map_or(0, Vec::len);
        if asked > 0 {
            return v;
        }
        if started.elapsed() > DISCOVERY {
            // No IPv4 address to map for: the machine has no IPv4 route, not a product fault.
            let route = std::process::Command::new("/sbin/route")
                .args(["-n", "get", "default"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            assert!(
                route.contains("gateway"),
                "CANNOT MEASURE (precondition unmet): this machine has no IPv4 default route, so \
                 no IPv4 mapping is asked for:\n{route}"
            );
            panic!(
                "PRODUCT: {}s after the daemon started, `vox status --json` names no IPv4 gateway \
                 asked: {}",
                DISCOVERY.as_secs(),
                v["gateway"]
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The gateway section of `vox status` (the person's form) on `data`, its `ipv4` lines.
fn status_words(data: &Path) -> String {
    let (ok, out, err) = vox_once(data, &args(&["status"]));
    assert!(
        ok,
        "PRODUCT: `vox status` did not answer.\nstdout:\n{out}\nstderr:\n{err}"
    );
    out.lines()
        .skip_while(|l| *l != "gateway")
        .take(5)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
#[ignore = "real binaries and production Argon2id; run on demand"]
fn vox_status_names_the_gateway_asked_and_the_one_that_answered() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_GATEWAY"]);
    let tmp = tempdir();
    let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
    let _reaper = Reaper(vec![a.clone(), b.clone()]);

    // ---- the stand-in answers ----
    let answering = Standin::start(7200);
    let at = answering.addr.to_string();
    let a = profile(tmp.path(), "a");
    let _da = daemon(&a, &at);
    let report = status_after_discovery(&a);
    let g = &report["gateway"]["ipv4"];
    println!("[proof] answering stand-in {at}: vox status says {g}");
    let log = answering.log();
    println!("[proof] the stand-in logged {log:?}");
    assert!(
        log.iter().any(|r| matches!(r.answer, Answer::Granted(_))),
        "PRODUCT: the answering stand-in at {at} granted nothing; it logged {log:?}"
    );
    assert_eq!(
        g["asked"],
        serde_json::json!([at]),
        "PRODUCT: vox must name the one gateway asked, {at}: {g}"
    );
    assert_eq!(
        (
            g["answered"]["address"].as_str(),
            g["answered"]["rung"].as_str()
        ),
        (Some(at.as_str()), Some("PCP")),
        "PRODUCT: the stand-in at {at} granted a PCP mapping; vox must name it, on PCP: {g}"
    );
    let words = status_words(&a);
    println!("[proof] vox status says:\n{words}");
    assert!(
        words.contains(&format!("asked {at}: PCP answered at {at}")),
        "PRODUCT: `vox status` must say the stand-in {at} was asked and answered on PCP:\n{words}"
    );

    // ---- the stand-in is silent ----
    let silent = Standin::start(7200);
    silent.set_silent(true);
    let at = silent.addr.to_string();
    let b = profile(tmp.path(), "b");
    let _db = daemon(&b, &at);
    let report = status_after_discovery(&b);
    let g = &report["gateway"]["ipv4"];
    println!("[proof] silent stand-in {at}: vox status says {g}");
    let log = silent.log();
    assert!(
        !log.is_empty(),
        "PRODUCT: vox names {at} as asked, but the silent stand-in received nothing"
    );
    assert_eq!(
        g["asked"],
        serde_json::json!([at]),
        "PRODUCT: vox must name the one gateway asked, {at}: {g}"
    );
    assert!(
        g["answered"].is_null(),
        "PRODUCT: the stand-in at {at} answered nothing; vox names an answer: {g}"
    );
    let words = status_words(&b);
    println!("[proof] vox status says:\n{words}");
    assert!(
        words.contains(&format!("asked {at}: none answered")),
        "PRODUCT: `vox status` must say the stand-in {at} was asked and none answered:\n{words}"
    );
}
