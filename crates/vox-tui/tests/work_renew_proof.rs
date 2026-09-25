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
    assert!(o.ok, "{o:?}");
    o.json()
}

fn held(b: &serde_json::Value, r: &str) -> Option<serde_json::Value> {
    resource(b, r).filter(|x| x["state"] == "held").cloned()
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

#[test]
#[ignore = "two networked nodes with production Argon2id; CI runs it in release"]
fn a_renewal_extends_exactly_one_acquisition() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();

    // ---- (1) renewed outlives its TTL; unrenewed lapses ----
    assert!(
        alice
            .vox(Some("a1"), &["room", "claim", r, "kept", "--ttl", "4"])
            .ok
    );
    assert!(
        alice
            .vox(Some("a1"), &["room", "claim", r, "dropped", "--ttl", "4"])
            .ok
    );
    std::thread::sleep(Duration::from_secs(2));
    let o = alice.vox(Some("a1"), &["room", "renew", r, "kept", "--json"]);
    assert!(o.ok, "{o:?}");
    assert_eq!(o.json()["outcome"], "applied", "{o:?}");
    std::thread::sleep(Duration::from_secs(3)); // 5 s after the claim: past the original 4
    wait_entries(alice, bob, r);
    for w in [alice, bob] {
        let b = board(w, r);
        assert!(
            held(&b, "kept").is_some(),
            "{}: a renewed claim must outlive its TTL: {b}",
            w.name
        );
        assert!(
            resource(&b, "dropped").is_none(),
            "{}: an unrenewed claim must lapse: {b}",
            w.name
        );
    }

    // ---- (4) another session of the same harness cannot renew ----
    let o = alice.vox(Some("a2"), &["room", "renew", r, "kept"]);
    assert_eq!(
        o.code,
        Some(1),
        "the CLI must refuse to renew what this session does not hold: {o:?}"
    );
    let acq_kept = held(&board(alice, r), "kept").unwrap()["acquisition"]
        .as_str()
        .unwrap()
        .to_owned();
    rt.block_on(post_raw(
        alice,
        room.cid,
        &renew_text("a2", "kept", &acq_kept, "op-a2-renew-kept"),
    ));

    // ---- (2) a renewal after expiry revives nothing ----
    assert!(
        alice
            .vox(Some("a1"), &["room", "claim", r, "late", "--ttl", "2"])
            .ok
    );
    let acq_late = held(&board(alice, r), "late").unwrap()["acquisition"]
        .as_str()
        .unwrap()
        .to_owned();
    std::thread::sleep(Duration::from_secs(3));
    rt.block_on(post_raw(
        alice,
        room.cid,
        &renew_text("a1", "late", &acq_late, "op-a1-renew-late-1"),
    ));

    // ---- (3) a renewal of a previous acquisition does not extend the new one ----
    assert!(
        alice
            .vox(Some("a1"), &["room", "claim", r, "again", "--ttl", "8"])
            .ok
    );
    let acq_old = held(&board(alice, r), "again").unwrap()["acquisition"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(alice.vox(Some("a1"), &["room", "release", r, "again"]).ok);
    assert!(
        alice
            .vox(Some("a1"), &["room", "claim", r, "again", "--ttl", "8"])
            .ok
    );
    let acq_new = held(&board(alice, r), "again").unwrap()["acquisition"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(acq_old, acq_new, "a re-claim is a new acquisition");
    let before = held(&board(alice, r), "again").unwrap()["expires_millis"].clone();
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
        assert!(
            resource(&b, "late").is_none(),
            "{}: a renewal after expiry revived it: {b}",
            w.name
        );
        let again = held(&b, "again")
            .unwrap_or_else(|| panic!("{}: `again` should still be held: {b}", w.name));
        assert_eq!(
            again["expires_millis"], before,
            "{}: a stale renewal extended a later acquisition: {b}",
            w.name
        );
        let stale: Vec<&serde_json::Value> = b["violations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["type"] == "renew" && v["outcome"]["no_effect"].is_string())
            .collect();
        assert_eq!(
            stale.len(),
            3,
            "{}: the three rejected renewals must each be reported: {b}",
            w.name
        );
    }
    // …and the new acquisition still lapses on its own clock.
    std::thread::sleep(Duration::from_secs(9));
    assert!(resource(&board(bob, r), "again").is_none());
}
