//! ADR-052 RG-10: claim rules, not package versions, determine the work board.
//!
//! A real wire peer posts a claim under different rules and one stamped exactly as
//! v0.4.30 wrote it. The shipped binary shows the former ignored and the latter held.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use support::{post_raw, resource, until, Out};

#[test]
#[ignore = "two real nodes and authenticated claim envelopes; run in release"]
fn claims_use_their_rules_and_keep_the_v0430_package_stamp() {
    watchdog::arm();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("APPARATUS: claim-rule runtime");
    let temporary = tempfile::tempdir().expect("APPARATUS: claim-rule profiles");
    let room = runtime.block_on(support::room(temporary.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    // Wire apparatus must also compile against the unfixed package-only implementation.
    let rules = "1";
    let other = (rules
        .parse::<u32>()
        .expect("APPARATUS: decimal claim rules")
        + 1)
    .to_string();

    for (item, operation, stamp) in [
        (
            "other-rules-work",
            "claim-other-rules",
            Some(other.as_str()),
        ),
        ("legacy-work", "claim-legacy-0430", None),
    ] {
        // An explicit rules stamp takes precedence over the old package-only stamp.
        let mut data = serde_json::json!({"resource": item, "op": operation, "vox": "0.4.30"});
        if let Some(stamp) = stamp {
            data["claims"] = stamp.into();
        }
        let envelope = serde_json::json!({
            "v": 1, "type": "claim", "from": "legacy-session", "body": item, "data": data
        });
        runtime.block_on(post_raw(bob, room.cid, &envelope.to_string()));
        let received = until(
            alice,
            None,
            "the signed claim to reach the reader",
            &["room", "read", &room.id, "--json"],
            |out: &Out| {
                out.ok
                    && out
                        .ndjson()
                        .iter()
                        .any(|row| row["envelope"]["data"]["op"] == operation)
            },
        );
        println!("reader received {operation}: {}", received.stdout);
    }

    let board = alice.vox(None, &["room", "board", &room.id, "--json"]);
    println!("claim-rules board: {board:?}");
    assert!(
        board.ok,
        "PRODUCT: the claim-rules board was refused: {board:?}"
    );
    let board = board.json();
    assert!(
        resource(&board, "other-rules-work").is_none()
            && board["violations"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|row| row["outcome"]["other_version"] == "mismatched")),
        "PRODUCT: a claim under other claim rules must change nothing: {board}"
    );
    assert!(
        resource(&board, "legacy-work")
            .is_some_and(|row| row["state"] == "held" && row["owner_session"] == "legacy-session"),
        "PRODUCT: the v0.4.30 package-stamped claim must remain held: {board}"
    );
}
