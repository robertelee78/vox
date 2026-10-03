//! ADR-021 M21.3 — **a renewal is bound to one acquisition**, through the shipped
//! `vox` binary against two real nodes.
//!
//! A lease that can only be extended by releasing and re-claiming briefly frees the
//! work to a competitor; one that can be extended by *anything the owner says* can be
//! revived after it died, or can silently extend a later, unrelated holding. So a
//! renewal names the claim it extends (`data.acquisition`), and the fold applies it
//! only while that exact claim still holds, for that exact session.
//!
//! What this proves, each read back from **both** nodes' boards:
//!
//! 1. a renewed claim outlives its original TTL, and an unrenewed one lapses;
//! 2. a renewal posted **after** its holding expired revives nothing;
//! 3. a renewal naming a **previous** acquisition — by the same session, after a
//!    re-claim — does not extend the new one, and is reported as stale;
//! 4. a renewal from another session of the same harness has no effect, and the CLI
//!    refuses to post one at all.
//!
//! Cases 2 and 3 cannot be produced by `vox room renew`, which reads the current
//! acquisition before posting — correctly. They are what a *delayed* or *stale*
//! renewal from a worker on this same version looks like on the wire, so they are
//! written onto the control socket as exactly those bytes: a correctly stamped,
//! correctly formed `renew` naming the wrong acquisition.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::time::Duration;

use support::{post_raw, resource, until, Out, Worker};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn board(w: &Worker, r: &str) -> serde_json::Value {
    let o = w.vox(None, &["room", "board", r, "--json"]);
    assert!(
        o.ok,
        "PRODUCT: {}: `vox room board --json` failed: {o:?}",
        w.name
    );
    o.json()
}

fn held(b: &serde_json::Value, r: &str) -> Option<serde_json::Value> {
    resource(b, r).filter(|x| x["state"] == "held").cloned()
}

/// The wall clock in milliseconds — the clock every TTL here is measured against.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("APPARATUS: the system clock is before 1970")
        .as_millis() as u64
}

fn sleep_past(at_millis: u64) {
    std::thread::sleep(Duration::from_millis(
        at_millis.saturating_sub(now_ms()) + 1_000,
    ));
}

/// `vox room claim … --ttl` as `session`, returning the acquisition and the expiry vox
/// reported for it — read from its own answer, so each window below is checked on the
/// clock the claim lapses on.
fn claim(w: &Worker, session: &str, r: &str, res: &str, ttl: u64) -> (String, u64) {
    let ttl_s = ttl.to_string();
    let t0 = now_ms();
    let o = w.vox(
        Some(session),
        &["room", "claim", r, res, "--ttl", &ttl_s, "--json"],
    );
    assert!(
        o.ok,
        "PRODUCT: {session}'s --ttl {ttl} claim of {res} failed: {o:?}"
    );
    let state = o.json()["state"].clone();
    match (
        state["acquisition"].as_str(),
        state["expires_millis"].as_u64(),
    ) {
        (Some(a), Some(e)) => (a.to_owned(), e),
        _ => {
            let took = now_ms() - t0;
            assert!(
                took < ttl * 1_000,
                "CANNOT MEASURE: the {ttl} s claim of {res} took {took} ms, so it may have \
                 lapsed before vox answered: {o:?}"
            );
            panic!("PRODUCT: a --ttl claim must report its acquisition and expiry: {o:?}");
        }
    }
}

/// A stamped, well-formed renewal, exactly as a worker on this version writes it.
fn renew_text(session: &str, res: &str, acquisition: &str, op: &str) -> String {
    serde_json::json!({
        "v": 1, "type": "renew", "from": session, "body": format!("renewing {res}"),
        "data": { "resource": res, "acquisition": acquisition, "op": op, "vox": VERSION }
    })
    .to_string()
}

fn wait_entries(a: &Worker, b: &Worker, r: &str) {
    let n = board(a, r)["position"]["entries"].clone();
    until(
        b,
        None,
        "the other node to catch up",
        &["room", "board", r, "--json"],
        |o: &Out| o.ok && o.json()["position"]["entries"] == n,
    );
}

/// The TTL of (1)'s two claims, and how far into it `kept` is renewed. The renewal adds a
/// whole TTL, so the boards are read in the gap between the original expiry and the
/// renewed one: `TTL - RENEW_AT` seconds.
const TTL: u64 = 8;
const RENEW_AT: u64 = 4;

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn a_renewal_extends_exactly_one_acquisition() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("APPARATUS: could not build the test's tokio runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: could not make a temp dir");
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();

    // ---- (1) renewed outlives its TTL; unrenewed lapses ----
    let (acq_kept, kept_was) = claim(alice, "a1", r, "kept", TTL);
    let (_, dropped_at) = claim(alice, "a1", r, "dropped", TTL);
    std::thread::sleep(Duration::from_secs(RENEW_AT));
    let o = alice.vox(Some("a1"), &["room", "renew", r, "kept", "--json"]);
    let done = now_ms();
    if !(o.ok && o.json()["outcome"] == "applied") {
        assert!(
            done >= kept_was,
            "PRODUCT: a renewal {} ms before the claim lapsed was not applied: {o:?}",
            kept_was - done
        );
        panic!(
            "CANNOT MEASURE: the renewal finished {} ms after the {TTL} s claim lapsed, so \
             whether a renewal extends a live claim was never tested: {o:?}",
            done - kept_was
        );
    }
    let kept_until = o.json()["state"]["expires_millis"]
        .as_u64()
        .unwrap_or_else(|| panic!("PRODUCT: an applied renewal must report its expiry: {o:?}"));
    assert!(
        kept_until > kept_was,
        "PRODUCT: an applied renewal did not move the expiry ({kept_was} -> {kept_until}): {o:?}"
    );
    sleep_past(kept_was.max(dropped_at)); // past the original TTL of both
    wait_entries(alice, bob, r);
    for w in [alice, bob] {
        let b = board(w, r);
        let read = now_ms();
        if held(&b, "kept").is_none() {
            assert!(
                read >= kept_until,
                "PRODUCT: {}: a renewed claim lapsed at its original TTL, {} ms before its \
                 renewed expiry: {b}",
                w.name,
                kept_until - read
            );
            panic!(
                "CANNOT MEASURE: {}: the board was read {} ms after even the renewed expiry, \
                 so whether a renewal outlives the original TTL was never tested: {b}",
                w.name,
                read - kept_until
            );
        }
        assert!(
            resource(&b, "dropped").is_none(),
            "PRODUCT: {}: an unrenewed claim is still on the board {} ms past its TTL: {b}",
            w.name,
            read - dropped_at
        );
    }

    // ---- (4) another session of the same harness cannot renew ----
    let o = alice.vox(Some("a2"), &["room", "renew", r, "kept"]);
    assert_eq!(
        o.code,
        Some(1),
        "PRODUCT: the CLI must refuse to renew what this session does not hold: {o:?}"
    );
    rt.block_on(post_raw(
        alice,
        room.cid,
        &renew_text("a2", "kept", &acq_kept, "op-a2-renew-kept"),
    ));

    // ---- (2) a renewal after expiry revives nothing ----
    let (acq_late, late_at) = claim(alice, "a1", r, "late", 2);
    sleep_past(late_at);
    rt.block_on(post_raw(
        alice,
        room.cid,
        &renew_text("a1", "late", &acq_late, "op-a1-renew-late-1"),
    ));

    // ---- (3) a renewal of a previous acquisition does not extend the new one ----
    // `again`'s TTL covers everything up to the boards below; they are read against it.
    const AGAIN_TTL: u64 = 12;
    let (acq_old, _) = claim(alice, "a1", r, "again", AGAIN_TTL);
    let o = alice.vox(Some("a1"), &["room", "release", r, "again"]);
    assert!(o.ok, "PRODUCT: alice/a1 could not release `again`: {o:?}");
    let (acq_new, before) = claim(alice, "a1", r, "again", AGAIN_TTL);
    assert_ne!(
        acq_old, acq_new,
        "PRODUCT: a re-claim must be a new acquisition"
    );
    rt.block_on(post_raw(
        alice,
        room.cid,
        &renew_text("a1", "again", &acq_old, "op-a1-renew-old"),
    ));

    wait_entries(alice, bob, r);
    let rows = alice.vox(None, &["room", "read", r, "--json"]);
    for row in rows.ndjson() {
        eprintln!(
            "[row] {} {} {} op={}",
            row["envelope"]["type"], row["envelope"]["from"], row["envelope"]["data"], row["op"]
        );
    }
    for w in [alice, bob] {
        let b = board(w, r);
        let read = now_ms();
        assert!(
            resource(&b, "late").is_none(),
            "PRODUCT: {}: a renewal after expiry revived it: {b}",
            w.name
        );
        let Some(again) = held(&b, "again") else {
            assert!(
                read >= before,
                "PRODUCT: {}: `again` is not held {} ms before its expiry: {b}",
                w.name,
                before - read
            );
            panic!(
                "CANNOT MEASURE: {}: the board was read {} ms after `again`'s {AGAIN_TTL} s \
                 TTL ran out, so whether a stale renewal extends it was never tested: {b}",
                w.name,
                read - before
            );
        };
        assert_eq!(
            again["expires_millis"], before,
            "PRODUCT: {}: a stale renewal extended a later acquisition: {b}",
            w.name
        );
        let stale = b["violations"]
            .as_array()
            .unwrap_or_else(|| panic!("PRODUCT: {}: the board has no violations list: {b}", w.name))
            .iter()
            .filter(|v| v["type"] == "renew" && v["outcome"]["no_effect"].is_string())
            .count();
        assert_eq!(
            stale, 3,
            "PRODUCT: {}: the three rejected renewals must each be reported: {b}",
            w.name
        );
    }
    // …and the new acquisition still lapses on its own clock.
    sleep_past(before);
    let b = board(bob, r);
    assert!(
        resource(&b, "again").is_none(),
        "PRODUCT: `again` is still on bob's board {} ms past its expiry: {b}",
        now_ms() - before
    );
}
