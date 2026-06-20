//! End-to-end integration tests for the M7 deniable mode (ADR-009): the full
//! 4-round DGKA among m≥3 members, the DSKE bind/confirm, and the integration with
//! M5's [`crate::log::dag::Dag::accept_with_deniable`] (deniable content accepted
//! in-epoch; the deniable-content fork raising the non-attributable *alarm* without
//! freezing the author).

use std::collections::BTreeMap;

use crate::deniable::dgka::DgkaMember;
use crate::deniable::epoch::{EpochContext, MemberEpk};
use crate::deniable::key::EpochKey;
use crate::deniable::rounds::{Confirm, Reveal};
use crate::deniable::share::SHARE_LEN;
use crate::deniable::verifier::{build_deniable_content, EpochVerifier};
use crate::hash::{sha256, Digest32};
use crate::identity::composite::{RootSigner, SoftwareRootSigner};
use crate::log::dag::{AdmissionPolicy, Dag, ForkOutcome, Rejected};
use crate::log::entry::{EntryKind, EntrySkeleton, ZERO_HASH};
use crate::log::feed::{lipmaa, Feed};
use crate::suite::algo;

const CHANNEL: Digest32 = [0xC1; 32];
const EPOCH: u64 = 7;

/// The outcome of a completed DGKA for one member: the canonical context, the
/// member's run handle (holding its fresh signing key), its agreed key, and its
/// **static** identity (the entry author + admitted-set key — distinct from the
/// per-epoch ephemeral key).
struct Completed {
    ctx: EpochContext,
    member: DgkaMember,
    key: EpochKey,
    static_id: SoftwareRootSigner,
}

/// Drive the full 4-round DGKA among `n` members and return each member's
/// completed view plus the shared `X_*` (round-2) map. Every member's bind +
/// confirm is verified against every peer (over the bind transcript `T_bind`).
fn run_full_dgka(n: usize) -> (Vec<Completed>, BTreeMap<Digest32, [u8; SHARE_LEN]>) {
    // Each member has a real STATIC composite identity; its fingerprint is the
    // entry author_id and admitted-set key. The per-epoch ephemeral key is
    // separate (generated inside DgkaMember::start).
    let static_ids: Vec<SoftwareRootSigner> = (0..n)
        .map(|k| {
            SoftwareRootSigner::from_component_seeds(&[k as u8 + 1; 32], &[k as u8 + 100; 32])
                .unwrap()
        })
        .collect();
    // Round 0: each member starts (generates esk_i, x_i, nonce_i), signed by its
    // STATIC identity.
    let mut members: Vec<DgkaMember> = static_ids
        .iter()
        .map(|s| DgkaMember::start(CHANNEL, EPOCH, s).unwrap())
        .collect();

    // Round 1: broadcast commits; everyone records everyone's commit.
    let commits: Vec<(Digest32, Digest32)> = members
        .iter()
        .map(|m| (m.author_id(), m.commit()))
        .collect();
    for m in &mut members {
        for (author, commit) in &commits {
            m.recv_commit(*author, *commit).unwrap();
        }
    }

    // Round 2: broadcast reveals; everyone records everyone's reveal (checked
    // against the stored commit).
    let reveals: Vec<Reveal> = members.iter().map(DgkaMember::reveal).collect();
    for m in &mut members {
        for r in &reveals {
            m.recv_reveal(r.clone()).unwrap();
        }
    }

    // Every member builds the SAME canonical context from the reveals.
    let ctxs: Vec<EpochContext> = members.iter().map(|m| m.epoch_context().unwrap()).collect();
    // They must all be byte-identical (same transcript).
    for c in &ctxs {
        assert_eq!(c.transcript(), ctxs[0].transcript());
    }

    // Round 3: gather every member's BD round-2 value X_i over the ring BEFORE any
    // member derives K (round 4 needs the full X vector).
    let mut x_map: BTreeMap<Digest32, [u8; SHARE_LEN]> = BTreeMap::new();
    for m in &members {
        x_map.insert(m.author_id(), m.own_round2(&ctxs[0]).unwrap());
    }

    // Round 4: each member finalizes — derives K, signs T (DSKE bind), MACs T.
    let mut confirms: Vec<Confirm> = Vec::new();
    let mut keys: Vec<EpochKey> = Vec::new();
    for (i, m) in members.iter().enumerate() {
        let (c, k) = m.finalize(&ctxs[i], &x_map).unwrap();
        confirms.push(c);
        keys.push(k);
    }

    // Every member verifies every peer's bind + confirm under its own K, against
    // the bind transcript that commits to the full X_* vector.
    for (i, m) in members.iter().enumerate() {
        for c in &confirms {
            if c.author_id == m.author_id() {
                continue;
            }
            m.verify_confirm(&ctxs[i], &keys[i], &x_map, c).unwrap();
        }
    }

    let completed = members
        .into_iter()
        .zip(ctxs)
        .zip(keys)
        .zip(static_ids)
        .map(|(((member, ctx), key), static_id)| Completed {
            ctx,
            member,
            key,
            static_id,
        })
        .collect();
    (completed, x_map)
}

#[test]
fn full_dgka_three_members_all_agree_and_confirm() {
    let (done, _x) = run_full_dgka(3);
    // All members derived the identical epoch key K.
    for c in &done {
        assert!(c.key.equals(&done[0].key));
    }
    // All members agree on the member set + transcript.
    assert_eq!(done[0].ctx.member_count(), 3);
}

#[test]
fn full_dgka_five_members_all_agree() {
    let (done, _x) = run_full_dgka(5);
    for c in &done {
        assert!(c.key.equals(&done[0].key));
    }
}

#[test]
fn forged_bind_with_wrong_transcript_rejected() {
    // A member's bind signature over a DIFFERENT transcript must not verify.
    let (done, real_x) = run_full_dgka(3);
    let victim = &done[0];
    // Craft a Confirm whose bind_sig is over a tampered transcript.
    let tampered_ctx = {
        // Same members but a different epoch → different T.
        EpochContext::new(
            victim.ctx.channel_id(),
            victim.ctx.epoch() + 1,
            victim.ctx.members().to_vec(),
        )
        .unwrap()
    };
    // Build a Confirm carrying a bind over the WRONG transcript by finalizing
    // member 1 against tampered_ctx, then verifying it against the REAL ctx. For
    // n=3 finalize needs all three members' X over the tampered ring.
    let mut xmap = BTreeMap::new();
    for other in &done {
        xmap.insert(
            other.member.author_id(),
            other.member.own_round2(&tampered_ctx).unwrap(),
        );
    }
    let (wrong_confirm, _wrong_key) = done[1].member.finalize(&tampered_ctx, &xmap).unwrap();
    // Verifying member 1's tampered-transcript bind against the REAL ctx fails.
    assert!(victim
        .member
        .verify_confirm(&victim.ctx, &victim.key, &real_x, &wrong_confirm)
        .is_err());
}

/// Author the next deniable content entry for `signer`'s feed in `dag`, signed by
/// `esk` (the member's per-epoch ephemeral key). Links into the feed like M5's
/// helper so replicated entries chain correctly.
fn next_deniable(
    dag: &Dag,
    author_id: Digest32,
    esk: &crate::deniable::epoch::EphemeralSigningKey,
    payload: &[u8],
) -> crate::log::entry::Entry {
    let feed = dag.feed(&author_id);
    let max = feed.map_or(0, Feed::max_seq);
    let seq = max + 1;
    let prev_hash = if seq == 1 {
        ZERO_HASH
    } else {
        feed.unwrap().get(seq - 1).unwrap().entry_hash()
    };
    let lipmaa_backlink = if seq == 1 {
        ZERO_HASH
    } else {
        feed.unwrap().get(lipmaa(seq)).unwrap().entry_hash()
    };
    let sk = EntrySkeleton {
        author_id,
        seq,
        prev_hash,
        lipmaa_backlink,
        channel_id: CHANNEL,
        epoch: EPOCH,
        algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
        payload_hash: sha256(payload),
        payload_len: payload.len() as u64,
        end_of_feed: false,
    };
    build_deniable_content(esk, sk, payload.to_vec()).unwrap()
}

#[test]
fn deniable_content_accepted_by_dag_with_epoch_verifier() {
    // Full M5 integration: a deniable content entry signed by epk_i is accepted by
    // Dag::accept_with_deniable when the EpochVerifier holds the released epk.
    let (done, _x) = run_full_dgka(3);
    let author = &done[0];
    let author_id = author.member.author_id();

    // The admitted set keys on the STATIC author id (the entry's author_id is the
    // member's static fingerprint). Admit all three.
    let mut adm = AdmissionPolicy::new();
    for c in &done {
        adm.admit(CHANNEL, EPOCH, c.member.author_id());
    }

    // The recipient releases (consents to) the author's epk for this epoch.
    let mut verifier = EpochVerifier::new();
    verifier
        .release(
            CHANNEL,
            EPOCH,
            &MemberEpk {
                author_id,
                epk: author.member.epk(),
            },
        )
        .unwrap();

    let mut dag = Dag::new();
    let entry = next_deniable(&dag, author_id, author.member.signing_key(), b"hi there");
    // The DAG gates `author_id == root.fingerprint()` even on the deniable path:
    // the entry author is the member's STATIC identity, so the root presented is the
    // STATIC composite key. The deniable *signature* is then verified by the
    // EpochVerifier against the per-epoch epk (separate from this static key).
    let root = author.static_id.public_key();
    let hash = dag
        .accept_with_deniable(entry, EntryKind::Content, &root, &adm, 0, Some(&verifier))
        .unwrap();
    assert!(dag.contains(&hash));
}

#[test]
fn deniable_content_fork_raises_alarm_does_not_freeze() {
    // The ADR-009/M7 deniable-content fork: two distinct deniable entries at the
    // same (author, seq) raise a NON-attributable alarm and do NOT freeze the
    // author (auto-freeze would be a framing/DoS primitive).
    let (done, _x) = run_full_dgka(3);
    let author = &done[0];
    let author_id = author.member.author_id();
    let root = author.static_id.public_key();

    let mut adm = AdmissionPolicy::new();
    adm.admit(CHANNEL, EPOCH, author_id);
    let mut verifier = EpochVerifier::new();
    verifier
        .release(
            CHANNEL,
            EPOCH,
            &MemberEpk {
                author_id,
                epk: author.member.epk(),
            },
        )
        .unwrap();

    let mut dag = Dag::new();
    // First deniable content entry stores.
    let e1 = next_deniable(&dag, author_id, author.member.signing_key(), b"first");
    dag.accept_with_deniable(e1, EntryKind::Content, &root, &adm, 0, Some(&verifier))
        .unwrap();

    // A second, DIFFERENT deniable entry at seq 1 (built against an empty view).
    let scratch = Dag::new();
    let e2 = next_deniable(
        &scratch,
        author_id,
        author.member.signing_key(),
        b"second-equivocation",
    );
    match dag.accept_with_deniable(e2, EntryKind::Content, &root, &adm, 0, Some(&verifier)) {
        Err(Rejected::Fork(ForkOutcome::DeniableAlarm { author_id: a, seq })) => {
            assert_eq!(a, author_id);
            assert_eq!(seq, 1);
        }
        other => panic!("expected deniable alarm, got {other:?}"),
    }
    // NOT frozen — the conflict does not incriminate a specific author.
    assert!(!dag.is_frozen(&author_id));
}

#[test]
fn governance_must_stay_attributable_in_deniable_channel() {
    // A governance entry carrying a deniable authenticator is rejected by M5 even
    // with an M7 verifier present (ADR-008/ADR-009: governance is always composite
    // root-signed). This confirms M7 does NOT weaken the governance plane.
    let (done, _x) = run_full_dgka(3);
    let author = &done[0];
    let author_id = author.member.author_id();
    let root = author.static_id.public_key();
    let mut adm = AdmissionPolicy::new();
    adm.admit(CHANNEL, EPOCH, author_id);
    let verifier = EpochVerifier::new();

    let mut dag = Dag::new();
    let e = next_deniable(
        &dag,
        author_id,
        author.member.signing_key(),
        b"gov-deniable",
    );
    assert!(matches!(
        dag.accept_with_deniable(e, EntryKind::Governance, &root, &adm, 0, Some(&verifier)),
        Err(Rejected::GovernanceNotAttributable)
    ));
}

#[test]
fn dgka_setup_envelope_is_attributable_static_signed() {
    // The DGKA setup rounds ride the log as GOVERNANCE entries — root-composite
    // signed envelopes (participation attributable = weak deniability). Confirm a
    // dgka-setup-class entry authored with the STATIC root key is accepted as
    // attributable governance (the envelope), independent of the deniable content
    // path. This models how the four rounds are carried (ADR-009 §"Concrete
    // protocol": all four rounds are governance/control-class).
    let signer = SoftwareRootSigner::from_component_seeds(&[42; 32], &[24; 32]).unwrap();
    let author_id = signer.fingerprint();
    let mut adm = AdmissionPolicy::new();
    adm.admit(CHANNEL, EPOCH, author_id);

    // The dgka-setup body would be a commit/reveal/confirm payload; here we carry
    // an opaque body and sign the ENVELOPE with the static composite key.
    let payload = b"dgka-setup round body (opaque)";
    let sk = EntrySkeleton {
        author_id,
        seq: 1,
        prev_hash: ZERO_HASH,
        lipmaa_backlink: ZERO_HASH,
        channel_id: CHANNEL,
        epoch: EPOCH,
        algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
        payload_hash: sha256(payload),
        payload_len: payload.len() as u64,
        end_of_feed: false,
    };
    let entry = crate::log::entry::Entry::build_signed(&signer, sk, payload.to_vec()).unwrap();
    assert!(entry.authenticator.is_attributable());
    let mut dag = Dag::new();
    dag.accept(entry, EntryKind::Governance, &signer.public_key(), &adm, 0)
        .unwrap();
}
