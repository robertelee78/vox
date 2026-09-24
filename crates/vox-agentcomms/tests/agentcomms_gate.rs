//! ADR-020 §4/§5/§9 **M19.3 gate** — the envelope and the claim rules.
//!
//! Two properties are worth a gate, and neither is a restatement of the code:
//!
//! 1. **Claims converge.** Every node must reach the same owner having received
//!    the claims in a different order. Proved by resolving *every permutation* of
//!    a contested set and asserting one answer — a property a coordinator would
//!    normally be needed for.
//! 2. **The room's rules hold.** What may interrupt, who may answer, and when a
//!    message stops being relayed — the three things that decide whether a room
//!    with several agents is usable or a wall of noise.
//!
//! Cheap and pure: no network, no identity, no Argon2, so these run in the
//! ordinary debug suite rather than the release gates.

use vox_agentcomms::claim::{resolve, resolve_with, ClaimOp, Posted, CLAIM, HANDOFF, RELEASE};
use vox_agentcomms::envelope::work;
use vox_agentcomms::{Envelope, SAY};

const ALICE: [u8; 32] = [1u8; 32];
const BOB: [u8; 32] = [2u8; 32];
const CAROL: [u8; 32] = [3u8; 32];

fn posted(author: [u8; 32], hash: u8, secs: u64, kind: &str, data: serde_json::Value) -> Posted {
    let mut env = Envelope::new(kind, "");
    env.data = data;
    Posted {
        entry_hash: [hash; 32],
        author,
        // These helpers speak seconds because the cases are written in seconds — and several
        // deliberately give two ops the SAME second to exercise §5's tie-break. Scaling keeps
        // that: equal seconds are still equal milliseconds, so every tie stays a tie.
        created_millis: secs.saturating_mul(1_000),
        envelope: env,
    }
}

fn claim(author: [u8; 32], hash: u8, secs: u64, resource: &str) -> Posted {
    posted(
        author,
        hash,
        secs,
        CLAIM,
        serde_json::json!({ "resource": resource }),
    )
}

/// Every ordering of `items`, by index.
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

/// THE property: the same set of claims yields the same owner in every order.
#[test]
fn contested_claims_converge_in_every_order() {
    // Three agents race for one resource. Bob is earliest, so Bob owns it —
    // whatever order any given node happens to receive these in.
    let msgs = vec![
        claim(ALICE, 0xAA, 200, "deploy-api"),
        claim(BOB, 0xBB, 100, "deploy-api"),
        claim(CAROL, 0xCC, 300, "deploy-api"),
    ];

    let orders = permutations(&msgs);
    assert_eq!(orders.len(), 6, "all six orderings");
    let mut answers = Vec::new();
    for order in &orders {
        let owned = resolve(order, 1_000);
        let owner = owned.get("deploy-api").expect("owned").owner;
        answers.push(owner);
    }
    assert!(
        answers.windows(2).all(|w| w[0] == w[1]),
        "nodes disagreed about the owner depending on arrival order"
    );
    assert_eq!(answers[0], BOB, "the earliest claim should win");
}

/// A tie on time is broken by entry hash, not by arrival — otherwise two nodes
/// that saw the same two claims would disagree.
#[test]
fn a_dead_heat_is_broken_deterministically_by_entry_hash() {
    let msgs = vec![
        claim(ALICE, 0xF0, 500, "build"),
        claim(BOB, 0x0F, 500, "build"), // same second
    ];
    let forwards = resolve(&msgs, 1_000);
    let mut backwards_input = msgs.clone();
    backwards_input.reverse();
    let backwards = resolve(&backwards_input, 1_000);

    assert_eq!(forwards, backwards, "tie-break depended on arrival order");
    // 0x0F < 0xF0, so Bob's entry hash sorts first and Bob wins.
    assert_eq!(forwards.get("build").unwrap().owner, BOB);
}

#[test]
fn only_the_owner_may_release_or_hand_off() {
    let base = claim(ALICE, 0x01, 100, "db");

    // Bob tries to release Alice's claim.
    let bobs_release = posted(
        BOB,
        0x02,
        200,
        RELEASE,
        serde_json::json!({ "resource": "db" }),
    );
    let owned = resolve(&[base.clone(), bobs_release], 1_000);
    assert_eq!(
        owned.get("db").map(|o| o.owner),
        Some(ALICE),
        "a non-owner released someone else's claim"
    );

    // Bob tries to hand Alice's claim to Carol.
    let bobs_handoff = posted(
        BOB,
        0x03,
        200,
        HANDOFF,
        serde_json::json!({ "resource": "db", "to": "carol" }),
    );
    let owned = resolve_with(&[base.clone(), bobs_handoff], 1_000, |n| {
        (n == "carol").then_some(CAROL)
    });
    assert_eq!(
        owned.get("db").map(|o| o.owner),
        Some(ALICE),
        "a non-owner handed off someone else's claim"
    );

    // The owner may do both.
    let alices_handoff = posted(
        ALICE,
        0x04,
        300,
        HANDOFF,
        serde_json::json!({ "resource": "db", "to": "carol" }),
    );
    let owned = resolve_with(&[base, alices_handoff], 1_000, |n| {
        (n == "carol").then_some(CAROL)
    });
    assert_eq!(owned.get("db").map(|o| o.owner), Some(CAROL));
}

#[test]
fn a_lapsed_claim_frees_the_resource_without_anyone_saying_so() {
    let short = posted(
        ALICE,
        0x01,
        100,
        CLAIM,
        serde_json::json!({ "resource": "runner", "ttl_secs": 50 }),
    );
    // Alice's claim lapses at 150; Bob claims at 200 and gets it.
    let later = claim(BOB, 0x02, 200, "runner");

    let owned = resolve(&[short.clone(), later], 1_000);
    assert_eq!(owned.get("runner").map(|o| o.owner), Some(BOB));

    // With nobody else claiming, it is simply unowned once it lapses.
    assert!(resolve(std::slice::from_ref(&short), 1_000).is_empty());
    // …and still owned before it does.
    assert_eq!(
        resolve(std::slice::from_ref(&short), 120)
            .get("runner")
            .map(|o| o.owner),
        Some(ALICE)
    );
}

#[test]
fn a_handoff_to_an_unknown_name_changes_nothing() {
    let base = claim(ALICE, 0x01, 100, "task");
    let to_nobody = posted(
        ALICE,
        0x02,
        200,
        HANDOFF,
        serde_json::json!({ "resource": "task", "to": "who?" }),
    );
    // The node cannot resolve the name, so ownership must be left exactly as it
    // was — not transferred to a guess, and not silently freed.
    let owned = resolve(&[base, to_nobody], 1_000);
    assert_eq!(owned.get("task").map(|o| o.owner), Some(ALICE));
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
    assert!(ClaimOp::from_envelope(&not_a_claim).is_none());

    let mut missing_resource = Envelope::new(CLAIM, "");
    missing_resource.data = serde_json::json!({ "ttl_secs": 60 });
    assert!(ClaimOp::from_envelope(&missing_resource).is_none());

    let mut good = Envelope::new(CLAIM, "");
    good.data = serde_json::json!({ "resource": "deploy-api" });
    assert_eq!(
        ClaimOp::from_envelope(&good).map(|o| o.resource().to_owned()),
        Some("deploy-api".to_owned())
    );
}
