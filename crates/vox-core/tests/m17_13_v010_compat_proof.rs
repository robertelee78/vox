//! ADR-017 **M17.13 proof** — a room created by v0.1.0 keeps its name, and its genesis
//! service grant authorizes nobody.
//!
//! M17.7 withdrew the model where a genesis service grant conferred `dial:` on every
//! admitted member. Withdrawing it must not orphan the rooms that already exist. A room's
//! **channelID is the SHA-256 of its canonical genesis body**, and it is the room's name —
//! it is what a `.vox` hostname encodes and what every record on the log is filed under. So
//! if today's encoder disagreed with v0.1.0's by a single byte, every existing room would
//! change name and nothing would resolve.
//!
//! The fixture beside this file is **not a re-derivation of today's code by today's code.**
//! It was produced by building the `v0.1.0` tag (875e2f8) and printing what that binary
//! computed for a genesis with fixed seeds, a fixed nonce and a non-empty service grant. So
//! the comparison is against a real old build, which is the only version of this claim worth
//! making — today's code agreeing with itself proves nothing about compatibility.
//!
//! What this asserts:
//!
//! 1. today's encoder produces the **same canonical body, byte for byte**, for the same
//!    inputs — the field still occupies the same place in the same CBOR arity;
//! 2. the **channelID is unchanged**, so the room keeps its name and its `.vox` hostname;
//! 3. that grant, on that room, **authorizes nobody** — the capability it names is refused
//!    to a full member of the room.
//!
//! 1 and 2 are compatibility. 3 is the security property, and together they are the whole
//! of M17.13: the old bytes still parse and still mean the same room, and they no longer
//! mean anybody may dial it.
//!
//! The arity is the thing to watch. A mismatched `e.array(N)` fails *silently* — a record
//! is simply rejected, three layers away from the cause — which has already happened once
//! in this codebase. Comparing whole bodies rather than fields is deliberate for that
//! reason: it catches a reordering or a width change that a field-by-field check would not.

use vox_core::governance::capability::{Capability, CapabilitySet};
use vox_core::governance::evaluator::{Evaluator, Verdict};
use vox_core::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};

/// Captured from a build of the **v0.1.0 tag**, not from this tree.
const V010_CHANNEL_ID: &str = "c82a371cc61c45b9e3a5c226bfe42c6b3c67350c2e70beabb4afded6517347dc";

/// The canonical genesis body that build produced, hex, same provenance.
const V010_BODY_HEX: &str = include_str!("fixtures/genesis-v0.1.0-canonical-body.hex");

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Exactly the inputs the v0.1.0 build was given.
fn the_same_genesis() -> Genesis {
    let signer = SoftwareRootSigner::from_component_seeds(&[0xA7; 32], &[0x58; 32]).unwrap();
    let policy = ChannelPolicy {
        history_mode: HistoryMode::ForwardOnly,
        deniability_mode: DeniabilityMode::Attributable,
        ttl: 0,
        min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
    };
    Genesis::create_with_nonce_and_grant(
        &signer,
        1_800_000_000,
        policy,
        CapabilitySet::from_iter_caps([Capability::dial("22"), Capability::dial("ssh")]),
        [0x13; 16],
    )
    .unwrap()
}

#[test]
fn m17_13_a_v010_room_keeps_its_name_and_its_grant_authorizes_nobody() {
    let g = the_same_genesis();

    // (1) The bytes. Compared whole, because a silent arity change is the failure mode.
    let body = g.body.canonical_body();
    assert_eq!(
        body,
        unhex(V010_BODY_HEX),
        "today's encoder no longer produces v0.1.0's canonical genesis body — every room \
         created before this release would change its channelID, and therefore its .vox \
         name, and nothing already published would resolve"
    );

    // (2) The name.
    let cid = g.channel_id();
    assert_eq!(
        hex(&cid),
        V010_CHANNEL_ID,
        "the channelID a v0.1.0 build computed for this genesis is not the one this build \
         computes: existing rooms would be renamed"
    );

    // (3) And that grant authorizes nobody — the security half.
    //
    // A full member of that very room, asking for the capability the genesis names. Under
    // the withdrawn model this was `Granted` and that was finding #1: admission to a room
    // is a passphrase and a proof of work, so membership was reach.
    let creator = SoftwareRootSigner::from_component_seeds(&[0xA7; 32], &[0x58; 32]).unwrap();
    let member = SoftwareRootSigner::from_component_seeds(&[0x22; 32], &[0xDD; 32]).unwrap();
    let creator_fp = RootSigner::public_key(&creator).fingerprint();
    let member_fp = RootSigner::public_key(&member).fingerprint();
    let keys: std::collections::BTreeMap<_, _> = [
        (creator_fp, RootSigner::public_key(&creator)),
        (member_fp, RootSigner::public_key(&member)),
    ]
    .into_iter()
    .collect();

    let eval = Evaluator::build_with_members(
        &g,
        &[],
        1_900_000_000,
        |id| keys.get(id).cloned(),
        [creator_fp, member_fp].into_iter().collect(),
    )
    .unwrap();

    for tag in ["22", "ssh"] {
        assert!(
            matches!(
                eval.grants(&member_fp, &Capability::dial(tag)),
                Verdict::Denied(_)
            ),
            "a v0.1.0 room's genesis grant still authorizes a member for dial:{tag} — the \
             withdrawn model is live again for every room created before this release, which \
             is finding #1 surviving in exactly the rooms that already exist"
        );
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
