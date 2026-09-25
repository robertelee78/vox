//! ADR-020 §4/§5/§9 and ADR-021 §4–§6 — the envelope and the claim protocol.
//!
//! One property is worth this pure gate above all, and it is not a restatement of
//! the code: **the fold converges.** Every worker on one version must reach the same
//! state having received the operations in a different order. That is proved here by
//! folding *every permutation* of a contested set and asserting one answer — which no
//! two-node product proof can do, because two nodes see two orders, not all of them.
//! Everything a person touches is proved through the shipped `vox` binary instead
//! (`crates/vox-tui/tests/work_*_proof.rs`).
//!
//! Cheap and pure: no network, no identity, no Argon2, so these run in the ordinary
//! debug suite rather than the release gates.

use vox_agentcomms::claim::{
    fold, is_claim_protocol, parse_op, Fold, Outcome, Owner, Posted, State, CLAIM, HANDOFF,
    RELEASE, RENEW,
};
use vox_agentcomms::envelope::work;
use vox_agentcomms::version::Stamp;
use vox_agentcomms::{Envelope, SAY};

const V: &str = "9.9.9";
const ALICE: [u8; 32] = [1u8; 32];
const BOB: [u8; 32] = [2u8; 32];
const CAROL: [u8; 32] = [3u8; 32];

/// One claim-protocol message, stamped with [`V`], from `author`'s session `s`.
fn op(
    author: [u8; 32],
    s: &str,
    hash: u8,
    secs: u64,
    kind: &str,
    data: serde_json::Value,
) -> Posted {
    let mut env = Envelope::new(kind, "");
    env.from = s.to_owned();
    let mut data = data;
    data["op"] = serde_json::json!(format!("op-{hash:02x}-{kind}-test"));
    data["vox"] = serde_json::json!(V);
    env.data = data;
    Posted {
        entry_hash: [hash; 32],
        author,
        // The cases are written in seconds, and several deliberately give two ops the
        // SAME second to exercise the tie-break; equal seconds stay equal milliseconds.
        created_millis: secs.saturating_mul(1_000),
        envelope: env,
    }
}

fn claim(author: [u8; 32], s: &str, hash: u8, secs: u64, resource: &str) -> Posted {
    op(
        author,
        s,
        hash,
        secs,
        CLAIM,
        serde_json::json!({ "resource": resource }),
    )
}

fn owner(f: &Fold, r: &str) -> Option<Owner> {
    match f.resources.get(r) {
        Some(State::Held { owner, .. }) => Some(owner.clone()),
        _ => None,
    }
}

fn who(author: [u8; 32], s: &str) -> Owner {
    Owner {
        author,
        session: s.to_owned(),
    }
}

/// Every ordering of `items`.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut p in permutations(&rest) {
            p.insert(0, head.clone());
            out.push(p);
        }
    }
    out
}

/// THE property: the same set of operations yields the same state in every order —
/// across a contested claim, a handoff, its completion, a renewal and a release.
#[test]
fn the_fold_converges_in_every_order() {
    let msgs = vec![
        claim(ALICE, "a1", 0xAA, 200, "deploy"),
        claim(BOB, "b1", 0xBB, 100, "deploy"),
        claim(CAROL, "c1", 0xCC, 300, "deploy"),
        op(
            BOB,
            "b1",
            0xB2,
            400,
            HANDOFF,
            serde_json::json!({"resource": "deploy", "to_fp": vox_agentcomms::claim::b32(&CAROL), "ttl_secs": 60}),
        ),
        claim(CAROL, "c1", 0xC2, 410, "deploy"),
    ];
    let orders = permutations(&msgs);
    assert_eq!(orders.len(), 120, "all orderings");
    let first = fold(&orders[0], V, 1_000_000);
    for order in &orders {
        assert_eq!(
            fold(order, V, 1_000_000),
            first,
            "workers disagreed about the state depending on arrival order"
        );
    }
    assert_eq!(owner(&first, "deploy"), Some(who(CAROL, "c1")));
}

/// A tie on time is broken by entry hash, not by arrival.
#[test]
fn a_dead_heat_is_broken_deterministically_by_entry_hash() {
    let msgs = vec![
        claim(ALICE, "a", 0xF0, 500, "build"),
        claim(BOB, "b", 0x0F, 500, "build"),
    ];
    let mut backwards = msgs.clone();
    backwards.reverse();
    assert_eq!(fold(&msgs, V, 1_000_000), fold(&backwards, V, 1_000_000));
    // 0x0F < 0xF0, so Bob's entry sorts first and Bob wins.
    assert_eq!(
        owner(&fold(&msgs, V, 1_000_000), "build"),
        Some(who(BOB, "b"))
    );
}

/// Two sessions on one harness are two owners (ADR-021 F3).
#[test]
fn ownership_is_per_session_not_per_harness() {
    let msgs = vec![
        claim(ALICE, "s1", 0x01, 100, "db"),
        claim(ALICE, "s2", 0x02, 101, "db"),
        op(
            ALICE,
            "s2",
            0x03,
            102,
            RELEASE,
            serde_json::json!({"resource": "db"}),
        ),
    ];
    let f = fold(&msgs, V, 1_000_000);
    assert_eq!(owner(&f, "db"), Some(who(ALICE, "s1")));
    assert_eq!(f.outcomes.get(&[0x02; 32]), Some(&Outcome::Lost));
    assert!(matches!(
        f.outcomes.get(&[0x03; 32]),
        Some(Outcome::NoEffect(_))
    ));
}

/// An operation from another version, or with no stamp, changes nothing (ADR-021 §5).
#[test]
fn another_versions_operation_changes_nothing() {
    let mut old = claim(ALICE, "a", 0x01, 100, "x");
    old.envelope.data.as_object_mut().unwrap().remove("vox");
    let mut other = claim(BOB, "b", 0x02, 101, "x");
    other.envelope.data["vox"] = serde_json::json!("0.2.9");
    let f = fold(&[old, other], V, 1_000_000);
    assert!(f.resources.is_empty());
    assert_eq!(
        f.outcomes.get(&[0x01; 32]),
        Some(&Outcome::OtherVersion(Stamp::Missing))
    );
    assert_eq!(
        f.outcomes.get(&[0x02; 32]),
        Some(&Outcome::OtherVersion(Stamp::Other("0.2.9".into())))
    );
}

/// A handoff with no TTL on the original claim still has a finite deadline, and a
/// session-targeted one can be completed only by that exact session.
#[test]
fn a_targeted_handoff_is_completed_only_by_its_session_and_lapses() {
    let to = vox_agentcomms::claim::b32(&BOB);
    let msgs = vec![
        claim(ALICE, "a", 0x01, 100, "t"),
        op(
            ALICE,
            "a",
            0x02,
            110,
            HANDOFF,
            serde_json::json!({"resource": "t", "to_fp": to, "to_session": "b2", "ttl_secs": 30}),
        ),
        claim(BOB, "b1", 0x03, 120, "t"),
        op(
            BOB,
            "b1",
            0x04,
            121,
            work::DECLINE,
            serde_json::json!({"resource": "t"}),
        ),
    ];
    let f = fold(&msgs, V, 125_000);
    assert!(
        matches!(f.resources.get("t"), Some(State::Pending { .. })),
        "{f:?}"
    );
    assert_eq!(f.outcomes.get(&[0x03; 32]), Some(&Outcome::Lost));
    assert!(matches!(
        f.outcomes.get(&[0x04; 32]),
        Some(Outcome::NoEffect(_))
    ));
    // Past the handoff's own deadline (110 + 30), it is free.
    assert!(fold(&msgs, V, 141_000).resources.is_empty());
    // The targeted session completes it.
    let mut done = msgs.clone();
    done.push(claim(BOB, "b2", 0x05, 130, "t"));
    assert_eq!(owner(&fold(&done, V, 131_000), "t"), Some(who(BOB, "b2")));
}

/// A decline frees the resource; it does not return to the sender.
#[test]
fn a_decline_frees_rather_than_returns() {
    let msgs = vec![
        claim(ALICE, "a", 0x01, 100, "t"),
        op(
            ALICE,
            "a",
            0x02,
            110,
            HANDOFF,
            serde_json::json!({"resource": "t", "to_fp": vox_agentcomms::claim::b32(&BOB), "ttl_secs": 300}),
        ),
        op(
            BOB,
            "b",
            0x03,
            120,
            work::DECLINE,
            serde_json::json!({"resource": "t"}),
        ),
    ];
    assert!(fold(&msgs, V, 130_000).resources.is_empty());
}

/// A renewal extends one acquisition: never a lapsed one, never a later one.
#[test]
fn a_renewal_is_bound_to_one_acquisition() {
    let acq = vox_agentcomms::claim::b32(&[0x01; 32]);
    let base = op(
        ALICE,
        "a",
        0x01,
        100,
        CLAIM,
        serde_json::json!({"resource": "r", "ttl_secs": 10}),
    );
    let renew = op(
        ALICE,
        "a",
        0x02,
        105,
        RENEW,
        serde_json::json!({"resource": "r", "acquisition": acq}),
    );
    let f = fold(&[base.clone(), renew], V, 112_000);
    assert!(
        owner(&f, "r").is_some(),
        "renewed at 105 for 10s, so held at 112"
    );

    // Posted after the holding lapsed at 110: revives nothing.
    let late = op(
        ALICE,
        "a",
        0x03,
        111,
        RENEW,
        serde_json::json!({"resource": "r", "acquisition": acq}),
    );
    let f = fold(&[base.clone(), late], V, 112_000);
    assert!(f.resources.is_empty());

    // A re-claim at 120 is a new acquisition; renewing the OLD one does not extend it.
    let reclaim = op(
        ALICE,
        "a",
        0x04,
        120,
        CLAIM,
        serde_json::json!({"resource": "r", "ttl_secs": 10}),
    );
    let stale = op(
        ALICE,
        "a",
        0x05,
        125,
        RENEW,
        serde_json::json!({"resource": "r", "acquisition": acq}),
    );
    let f = fold(&[base, reclaim, stale], V, 131_000);
    assert!(
        f.resources.is_empty(),
        "the old acquisition's renewal extended the new one"
    );
    assert!(matches!(
        f.outcomes.get(&[0x05; 32]),
        Some(Outcome::NoEffect(_))
    ));
}

/// A retry is one operation; a conflicting reuse voids every entry of it, whatever
/// order they arrive in (ADR-021 §6).
#[test]
fn a_retry_is_one_operation_and_a_conflict_voids_it() {
    let mut a = claim(ALICE, "a", 0x01, 100, "x");
    let mut b = claim(ALICE, "a", 0x02, 101, "x");
    a.envelope.data["op"] = serde_json::json!("same-op-id");
    b.envelope.data["op"] = serde_json::json!("same-op-id");
    b.envelope.body = "reworded body is still the same operation".into();
    let f = fold(&[b.clone(), a.clone()], V, 1_000_000);
    assert_eq!(owner(&f, "x"), Some(who(ALICE, "a")));
    assert_eq!(
        f.outcomes.get(&[0x02; 32]),
        Some(&Outcome::Duplicate { of: [0x01; 32] })
    );

    let mut c = claim(ALICE, "a", 0x03, 99, "y");
    c.envelope.data["op"] = serde_json::json!("same-op-id");
    for order in permutations(&[a, b, c]) {
        let f = fold(&order, V, 1_000_000);
        assert!(
            f.resources.is_empty(),
            "a conflicted operation had an effect"
        );
        assert!(f
            .outcomes
            .values()
            .all(|o| matches!(o, Outcome::Conflict { .. })));
    }
}

/// A claim-protocol message missing a required field is invalid and changes nothing.
#[test]
fn an_operation_missing_a_required_field_is_invalid() {
    let mut no_session = claim(ALICE, "a", 0x01, 100, "x");
    no_session.envelope.from.clear();
    let mut handoff_no_ttl = op(
        ALICE,
        "a",
        0x02,
        100,
        HANDOFF,
        serde_json::json!({"resource": "x", "to_fp": vox_agentcomms::claim::b32(&BOB)}),
    );
    handoff_no_ttl
        .envelope
        .data
        .as_object_mut()
        .unwrap()
        .remove("ttl_secs");
    assert!(parse_op(&no_session.envelope).is_err());
    assert!(parse_op(&handoff_no_ttl.envelope).is_err());
    let f = fold(&[no_session], V, 1_000_000);
    assert!(f.resources.is_empty());
    assert!(matches!(
        f.outcomes.get(&[0x01; 32]),
        Some(Outcome::Invalid(_))
    ));
}

// ---- the envelope ----------------------------------------------------------

/// Prose from a human is a message, not an error — this is what lets the
/// operator share a room with agents without learning a format.
#[test]
fn plain_text_is_a_say_and_round_trips_as_plain_text() {
    let env = Envelope::parse("what's blocking the deploy?").expect("prose parses");
    assert_eq!(env.kind, SAY);
    assert_eq!(env.body, "what's blocking the deploy?");
    // And it is written back as prose, so the room stays readable and greppable.
    assert_eq!(env.to_text(), "what's blocking the deploy?");
}

#[test]
fn an_unknown_type_is_carried_not_rejected() {
    let raw = r#"{"v":1,"type":"bench-result","body":"ok","data":{"score":91}}"#;
    let env = Envelope::parse(raw).expect("unknown type is carried");
    assert_eq!(env.kind, "bench-result");
    assert_eq!(env.data.get("score").and_then(|v| v.as_u64()), Some(91));
}

#[test]
fn a_newer_envelope_version_is_refused_rather_than_guessed_at() {
    let raw = r#"{"v":99,"type":"say","body":"from the future"}"#;
    assert!(Envelope::parse(raw).is_err());
}

/// Only addressed **and** urgent interrupts. An urgent broadcast must not stop
/// the whole room — that is the wall-of-noise failure the design exists to avoid.
#[test]
fn interrupting_requires_being_addressed_and_urgent() {
    let addressed_urgent = Envelope::new(work::ASSIGN, "take this")
        .addressed_to(&["codex@host2"])
        .urgent();
    assert!(addressed_urgent.may_interrupt("codex@host2"));
    assert!(!addressed_urgent.may_interrupt("someone-else"));

    let addressed_calm = Envelope::new(work::ASSIGN, "when you can").addressed_to(&["codex@host2"]);
    assert!(!addressed_calm.may_interrupt("codex@host2"));

    let urgent_broadcast = Envelope::new(work::BLOCKED, "everything is on fire").urgent();
    assert!(
        !urgent_broadcast.may_interrupt("codex@host2"),
        "an urgent broadcast must not interrupt everyone"
    );
}

/// Reply only when addressed, and never to a terminal acknowledgement.
#[test]
fn auto_reply_is_confined_to_messages_addressed_to_you() {
    let to_me = Envelope::new(work::ASK, "status?").addressed_to(&["me"]);
    assert!(to_me.may_auto_reply("me"));
    assert!(!to_me.may_auto_reply("not-me"));

    let broadcast = Envelope::new(work::ASK, "anyone?");
    assert!(
        !broadcast.may_auto_reply("me"),
        "every agent answering every broadcast makes a room unusable"
    );

    for terminal in [work::ACK, work::NOT_UNDERSTOOD, "hello", "bye"] {
        let m = Envelope::new(terminal, "").addressed_to(&["me"]);
        assert!(
            !m.may_auto_reply("me"),
            "{terminal} must not beget another reply"
        );
    }
}

/// The hop budget is a hard cap, and running out means drop.
#[test]
fn hops_run_out_and_the_message_is_dropped() {
    let mut env = Envelope::new(work::ASSIGN, "relay me");
    assert_eq!(env.hops, 8, "ruflo ADR-097's default");

    let mut relays = 0;
    while let Some(next) = env.relayed() {
        env = next;
        relays += 1;
        assert!(relays <= 8, "the cap did not hold");
    }
    assert_eq!(relays, 8);
    assert_eq!(env.hops, 0);
    assert!(
        env.relayed().is_none(),
        "a message at zero hops must be dropped, not forwarded"
    );
}

/// An envelope that carries something is JSON; the addressing survives the trip.
#[test]
fn an_addressed_message_round_trips_through_the_log_text() {
    let sent = Envelope::new(work::ASSIGN, "port the codec")
        .addressed_to(&["codex@host2"])
        .urgent();
    let text = sent.to_text();
    assert!(text.starts_with('{'), "an addressed message must be JSON");

    let back = Envelope::parse(&text).expect("round trips");
    assert_eq!(back.kind, work::ASSIGN);
    assert!(back.is_addressed_to("codex@host2"));
    assert!(back.urgent);
    assert!(back.may_interrupt("codex@host2"));
}

#[test]
fn a_claim_op_is_only_read_from_a_real_claim_message() {
    let not_a_claim = Envelope::new(SAY, "I'll take the deploy");
    assert!(!is_claim_protocol(&not_a_claim));

    // `decline` without a resource refuses an `assign` — conversation, not this protocol.
    let request_decline = Envelope::new(work::DECLINE, "not me");
    assert!(!is_claim_protocol(&request_decline));

    let mut missing_resource = Envelope::new(CLAIM, "");
    missing_resource.from = "s".into();
    missing_resource.data = serde_json::json!({ "ttl_secs": 60, "op": "op-12345678" });
    assert!(is_claim_protocol(&missing_resource));
    assert!(parse_op(&missing_resource).is_err());

    let mut good = Envelope::new(CLAIM, "");
    good.from = "s".into();
    good.data = serde_json::json!({ "resource": "deploy-api", "op": "op-12345678" });
    assert_eq!(
        parse_op(&good).map(|o| o.resource().to_owned()),
        Ok("deploy-api".to_owned())
    );
}
