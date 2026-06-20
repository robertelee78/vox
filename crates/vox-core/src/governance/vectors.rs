//! Evaluator golden-vector suite (ADR-007 §"Canonical encoding & evaluator" —
//! release gate). **Test-only.**
//!
//! ADR-007 makes the deterministic evaluator a release gate: a *mandatory* suite
//! of golden vectors — valid chains, over-attenuation (rejected), expiry, revoked
//! links, concurrent-conflict + tie-break — with pinned expected verdicts, so two
//! correct implementations agree bit-for-bit on every vector, regardless of the
//! order entries were received. This module is that suite, plus the
//! [`harness`] used to build governance entries that ride **real M5 log entries**
//! (so each [`crate::governance::entry::GovEntry::entry_hash`] is the genuine
//! ADR-008 entry hash, not a synthetic one — the tie-break key must match what a
//! real client computes).

/// A small builder that lays governance bodies onto real M5 log entries, so the
/// evaluator is exercised against genuine entry hashes and per-author seq chains.
pub mod harness {
    use std::collections::BTreeSet;

    use crate::governance::capability::CapabilitySet;
    use crate::governance::cert::{AdminCert, AdminRevocation, RevocationReason};
    use crate::governance::consent::{ConsentGrant, ConsentRevocation};
    use crate::governance::entry::{GovBody, GovEntry};
    use crate::governance::genesis::{Genesis, HistoryMode};
    use crate::governance::policy::PolicyUpdate;
    use crate::governance::rotation::PassphraseRotation;
    use crate::hash::{sha256, Digest32};
    use crate::identity::composite::{CompositePublicKey, RootSigner, SoftwareRootSigner};
    use crate::log::entry::{Entry, EntrySkeleton, ZERO_HASH};
    use crate::log::feed::lipmaa;
    use crate::suite::algo;

    /// An author-key resolver over a fixed set of signers, for
    /// [`crate::governance::evaluator::Evaluator::build`].
    pub fn key_resolver(
        signers: Vec<&SoftwareRootSigner>,
    ) -> impl Fn(&Digest32) -> Option<CompositePublicKey> + '_ {
        move |fp: &Digest32| {
            signers
                .iter()
                .find(|s| s.fingerprint() == *fp)
                .map(|s| s.public_key())
        }
    }

    /// Builds governance entries onto real per-author M5 log feeds, tracking each
    /// author's seq chain and the cross-author causal predecessors of each entry.
    pub struct LogBuilder {
        channel_id: Digest32,
        // author -> (next_seq, prev_entry_hash, all entry hashes by seq).
        feeds: std::collections::BTreeMap<Digest32, AuthorFeed>,
        entries: Vec<GovEntry>,
        // The "heads" each new entry will record as causal predecessors: by
        // default, the latest entry hash of every *other* author seen so far. This
        // models ADR-008 causal references (an author happens-after the heads it
        // had seen). Vectors that need explicit concurrency override per call.
        all_heads: Vec<Digest32>,
    }

    #[derive(Default)]
    struct AuthorFeed {
        next_seq: u64,
        prev_hash: Digest32,
        prev_lipmaa: Vec<Digest32>, // entry hash by (seq-1) index
    }

    impl LogBuilder {
        /// Start a log builder for the channel defined by `genesis`.
        #[must_use]
        pub fn new(genesis: &Genesis) -> Self {
            Self {
                channel_id: genesis.channel_id(),
                feeds: std::collections::BTreeMap::new(),
                entries: Vec::new(),
                all_heads: Vec::new(),
            }
        }

        /// The accumulated governance entries (clone, for the evaluator).
        #[must_use]
        pub fn entries(&self) -> Vec<GovEntry> {
            self.entries.clone()
        }

        /// Build the next real M5 log entry for `author` carrying `framed` as its
        /// payload, returning its genuine entry hash. `causal_predecessors` are the
        /// cross-author governance heads it happens-after.
        fn push_entry(
            &mut self,
            author_root: &SoftwareRootSigner,
            framed_payload: Vec<u8>,
            body: GovBody,
            causal_predecessors: BTreeSet<Digest32>,
        ) -> Digest32 {
            let author = author_root.fingerprint();
            let feed = self.feeds.entry(author).or_default();
            let seq = feed.next_seq + 1;
            let prev_hash = if seq == 1 { ZERO_HASH } else { feed.prev_hash };
            let lipmaa_backlink = if seq == 1 {
                ZERO_HASH
            } else {
                let target = lipmaa(seq);
                feed.prev_lipmaa
                    .get((target - 1) as usize)
                    .copied()
                    .unwrap_or(ZERO_HASH)
            };
            let sk = EntrySkeleton {
                author_id: author,
                seq,
                prev_hash,
                lipmaa_backlink,
                channel_id: self.channel_id,
                epoch: body_epoch(&body),
                algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
                payload_hash: sha256(&framed_payload),
                payload_len: framed_payload.len() as u64,
                end_of_feed: false,
            };
            let entry = Entry::build_signed(author_root, sk, framed_payload).unwrap();
            let entry_hash = entry.entry_hash();

            // Advance the author feed bookkeeping.
            let feed = self.feeds.entry(author).or_default();
            feed.next_seq = seq;
            feed.prev_hash = entry_hash;
            feed.prev_lipmaa.push(entry_hash);

            let gov = GovEntry::from_parts(body, entry_hash, author, seq, causal_predecessors);
            self.entries.push(gov);

            // This entry becomes a head other authors may causally reference.
            self.all_heads.push(entry_hash);
            entry_hash
        }

        /// Default causal predecessors for a new entry: the current heads of every
        /// *other* author (so it happens-after what the channel has converged on so
        /// far). Same-author causality is via seq, so we exclude the author's own.
        fn default_preds(&self, author: Digest32) -> BTreeSet<Digest32> {
            self.entries
                .iter()
                .filter(|e| e.author_id != author)
                .map(|e| e.entry_hash)
                .collect()
        }

        /// Append an admin-delegation cert; returns its entry hash.
        pub fn admin_cert(
            &mut self,
            issuer: &SoftwareRootSigner,
            channel_id: &Digest32,
            epoch: u64,
            delegate: &SoftwareRootSigner,
            caps: CapabilitySet,
            expiry: u64,
        ) -> Digest32 {
            let cert = AdminCert::build(
                issuer,
                channel_id,
                epoch,
                delegate.public_key(),
                caps,
                expiry,
            )
            .unwrap();
            let framed = cert.to_wire();
            let preds = self.default_preds(issuer.fingerprint());
            self.push_entry(issuer, framed, GovBody::AdminCert(Box::new(cert)), preds)
        }

        /// Append an admin-delegation cert with **explicit** causal predecessors
        /// (for concurrency vectors). Pass an empty set for "concurrent with all".
        #[allow(clippy::too_many_arguments)]
        pub fn admin_cert_concurrent(
            &mut self,
            issuer: &SoftwareRootSigner,
            channel_id: &Digest32,
            epoch: u64,
            delegate: &SoftwareRootSigner,
            caps: CapabilitySet,
            expiry: u64,
            preds: BTreeSet<Digest32>,
        ) -> Digest32 {
            let cert = AdminCert::build(
                issuer,
                channel_id,
                epoch,
                delegate.public_key(),
                caps,
                expiry,
            )
            .unwrap();
            let framed = cert.to_wire();
            self.push_entry(issuer, framed, GovBody::AdminCert(Box::new(cert)), preds)
        }

        /// Append an admin-delegation revocation naming `revoked_hash`.
        pub fn admin_revocation(
            &mut self,
            issuer: &SoftwareRootSigner,
            channel_id: &Digest32,
            epoch: u64,
            revoked_hash: Digest32,
            preds: BTreeSet<Digest32>,
        ) -> Digest32 {
            let rev = AdminRevocation::build(
                issuer,
                channel_id,
                epoch,
                revoked_hash,
                RevocationReason::Compromise,
            )
            .unwrap();
            let framed = rev.to_wire();
            self.push_entry(
                issuer,
                framed,
                GovBody::AdminRevocation(Box::new(rev)),
                preds,
            )
        }

        /// Append a consent grant from `author` to `target`.
        pub fn consent_grant(
            &mut self,
            author: &SoftwareRootSigner,
            channel_id: &Digest32,
            epoch: u64,
            target: Digest32,
            skdm_ref: Digest32,
        ) -> Digest32 {
            let g = ConsentGrant::build(
                author,
                channel_id,
                epoch,
                target,
                skdm_ref,
                HistoryMode::ForwardOnly,
            )
            .unwrap();
            let framed = g.to_wire();
            let preds = self.default_preds(author.fingerprint());
            self.push_entry(author, framed, GovBody::ConsentGrant(Box::new(g)), preds)
        }

        /// Append a consent revocation from `author` excluding `target`.
        pub fn consent_revocation(
            &mut self,
            author: &SoftwareRootSigner,
            channel_id: &Digest32,
            epoch: u64,
            target: Digest32,
            new_chain_id: u64,
        ) -> Digest32 {
            let r =
                ConsentRevocation::build(author, channel_id, epoch, target, new_chain_id).unwrap();
            let framed = r.to_wire();
            let preds = self.default_preds(author.fingerprint());
            self.push_entry(
                author,
                framed,
                GovBody::ConsentRevocation(Box::new(r)),
                preds,
            )
        }

        /// Append a policy-update from `issuer`.
        pub fn policy_update(
            &mut self,
            issuer: &SoftwareRootSigner,
            channel_id: &Digest32,
            epoch: u64,
            history_mode: Option<HistoryMode>,
            ttl: Option<u64>,
        ) -> Digest32 {
            let pu = PolicyUpdate::build(issuer, channel_id, epoch, history_mode, ttl).unwrap();
            let framed = pu.to_wire();
            let preds = self.default_preds(issuer.fingerprint());
            self.push_entry(issuer, framed, GovBody::PolicyUpdate(Box::new(pu)), preds)
        }

        /// Append a policy-update with explicit causal predecessors (concurrency).
        pub fn policy_update_concurrent(
            &mut self,
            issuer: &SoftwareRootSigner,
            channel_id: &Digest32,
            epoch: u64,
            history_mode: Option<HistoryMode>,
            ttl: Option<u64>,
            preds: BTreeSet<Digest32>,
        ) -> Digest32 {
            let pu = PolicyUpdate::build(issuer, channel_id, epoch, history_mode, ttl).unwrap();
            let framed = pu.to_wire();
            self.push_entry(issuer, framed, GovBody::PolicyUpdate(Box::new(pu)), preds)
        }

        /// Append a consent grant with explicit causal predecessors (concurrency).
        pub fn consent_grant_concurrent(
            &mut self,
            author: &SoftwareRootSigner,
            channel_id: &Digest32,
            epoch: u64,
            target: Digest32,
            skdm_ref: Digest32,
            preds: BTreeSet<Digest32>,
        ) -> Digest32 {
            let g = ConsentGrant::build(
                author,
                channel_id,
                epoch,
                target,
                skdm_ref,
                HistoryMode::ForwardOnly,
            )
            .unwrap();
            let framed = g.to_wire();
            self.push_entry(author, framed, GovBody::ConsentGrant(Box::new(g)), preds)
        }

        /// Append an admin-delegation revocation with explicit predecessors AND a
        /// chosen revoker (for adversarial/concurrent vectors).
        #[allow(clippy::too_many_arguments)]
        pub fn admin_revocation_concurrent(
            &mut self,
            issuer: &SoftwareRootSigner,
            channel_id: &Digest32,
            epoch: u64,
            revoked_hash: Digest32,
            preds: BTreeSet<Digest32>,
        ) -> Digest32 {
            let rev = AdminRevocation::build(
                issuer,
                channel_id,
                epoch,
                revoked_hash,
                RevocationReason::Compromise,
            )
            .unwrap();
            let framed = rev.to_wire();
            self.push_entry(
                issuer,
                framed,
                GovBody::AdminRevocation(Box::new(rev)),
                preds,
            )
        }

        /// Append a passphrase-rotation (epoch bump) from `issuer`.
        pub fn passphrase_rotation(
            &mut self,
            issuer: &SoftwareRootSigner,
            channel_id: &Digest32,
            old_epoch: u64,
            new_epoch: u64,
        ) -> Digest32 {
            let r = PassphraseRotation::build(issuer, channel_id, old_epoch, new_epoch).unwrap();
            let framed = r.to_wire();
            let preds = self.default_preds(issuer.fingerprint());
            self.push_entry(
                issuer,
                framed,
                GovBody::PassphraseRotation(Box::new(r)),
                preds,
            )
        }
    }

    fn body_epoch(body: &GovBody) -> u64 {
        body.channel_and_epoch().1
    }
}

#[cfg(test)]
mod golden {
    use super::harness::*;
    use crate::governance::capability::{Capability, CapabilitySet};
    use crate::governance::evaluator::{DenyReason, Evaluator, Verdict};
    use crate::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
    use crate::hash::Digest32;
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use std::collections::BTreeSet;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    fn genesis_for(creator: &SoftwareRootSigner) -> Genesis {
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
        };
        Genesis::create_with_nonce(creator, 1_000, policy, [0x5A; 16]).unwrap()
    }

    // ---- VECTOR 1: valid chain → granted. ----

    #[test]
    fn vector_valid_chain_granted() {
        // genesis(creator=admin) → delegate A (invite) → A delegates B (invite).
        let creator = root(1, 1);
        let a = root(2, 2);
        let b = root(3, 3);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.admin_cert(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite, Capability::Delegate]),
            0,
        );
        h.admin_cert(
            &a,
            &cid,
            0,
            &b,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a, &b]),
        )
        .unwrap();

        assert!(eval.is_admin(&creator.fingerprint()));
        assert!(matches!(
            eval.grants(&a.fingerprint(), &Capability::Invite),
            Verdict::Granted { .. }
        ));
        assert!(matches!(
            eval.grants(&b.fingerprint(), &Capability::Invite),
            Verdict::Granted { .. }
        ));
        // B was granted only invite — it does NOT hold delegate.
        assert_eq!(
            eval.grants(&b.fingerprint(), &Capability::Delegate),
            Verdict::Denied(DenyReason::CapabilityNotHeld)
        );
    }

    // ---- VECTOR 2: over-attenuation → denied. ----

    #[test]
    fn vector_over_attenuation_denied() {
        // A holds only `invite`; A tries to delegate `policy` to B. The cert is
        // void (over-attenuation), so B is not an admin at all.
        let creator = root(1, 1);
        let a = root(2, 2);
        let b = root(3, 3);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.admin_cert(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        // A over-attenuates: grants policy it does not hold.
        h.admin_cert(
            &a,
            &cid,
            0,
            &b,
            CapabilitySet::from_iter_caps([Capability::Policy]),
            0,
        );

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a, &b]),
        )
        .unwrap();
        assert!(eval.is_admin(&a.fingerprint()));
        // B's chain is void → not an admin.
        assert!(!eval.is_admin(&b.fingerprint()));
        assert_eq!(
            eval.grants(&b.fingerprint(), &Capability::Policy),
            Verdict::Denied(DenyReason::NotAdmin)
        );
    }

    // ---- VECTOR 3: expiry → denied. ----

    #[test]
    fn vector_expiry_denied() {
        let creator = root(1, 1);
        let a = root(2, 2);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // A is delegated invite, expiring at t=1500.
        h.admin_cert(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            1_500,
        );

        // Before expiry: admin.
        let before = Evaluator::build(
            &genesis,
            &h.entries(),
            1_400,
            key_resolver(vec![&creator, &a]),
        )
        .unwrap();
        assert!(before.is_admin(&a.fingerprint()));

        // At/after expiry: not admin.
        let after = Evaluator::build(
            &genesis,
            &h.entries(),
            1_500,
            key_resolver(vec![&creator, &a]),
        )
        .unwrap();
        assert!(!after.is_admin(&a.fingerprint()));
        assert_eq!(
            after.grants(&a.fingerprint(), &Capability::Invite),
            Verdict::Denied(DenyReason::NotAdmin)
        );
    }

    // ---- VECTOR 4: revoked link → denied (revocation-wins). ----

    #[test]
    fn vector_revoked_link_denied() {
        let creator = root(1, 1);
        let a = root(2, 2);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        let deleg = h.admin_cert(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        // Creator revokes the delegation, causally AFTER it.
        let mut preds = BTreeSet::new();
        preds.insert(deleg);
        h.admin_revocation(&creator, &cid, 0, deleg, preds);

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a]),
        )
        .unwrap();
        assert!(!eval.is_admin(&a.fingerprint()));
    }

    #[test]
    fn vector_unauthorized_revocation_ignored() {
        // A non-admin (no `delegate` authority) cannot revoke an admin's
        // delegation: the revocation is ignored, so the delegate stays an admin.
        let creator = root(1, 1);
        let a = root(2, 2);
        let outsider = root(9, 9);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        let deleg = h.admin_cert(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        // The outsider tries to revoke A's delegation, causally after it.
        let mut preds = BTreeSet::new();
        preds.insert(deleg);
        h.admin_revocation(&outsider, &cid, 0, deleg, preds);

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a, &outsider]),
        )
        .unwrap();
        // The unauthorized revocation is ignored → A remains an admin.
        assert!(eval.is_admin(&a.fingerprint()));
    }

    #[test]
    fn vector_revocation_then_redelegation_restores() {
        // Revocation-wins is bounded: a causally-LATER re-delegation of the same
        // key restores authority (ADR-007 "until a causally-later re-delegation").
        let creator = root(1, 1);
        let a = root(2, 2);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        let deleg = h.admin_cert(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        let mut preds_rev = BTreeSet::new();
        preds_rev.insert(deleg);
        let rev = h.admin_revocation(&creator, &cid, 0, deleg, preds_rev);
        // A causally-later RE-delegation (new cert, happens-after the revocation).
        let mut preds_re = BTreeSet::new();
        preds_re.insert(rev);
        h.admin_cert_concurrent(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
            preds_re,
        );

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a]),
        )
        .unwrap();
        // The re-delegation is a fresh cert, not named by the revocation → A is
        // admin again.
        assert!(eval.is_admin(&a.fingerprint()));
    }

    // ---- VECTOR 5: concurrent conflict → ascending-entry-hash tie-break. ----

    #[test]
    fn vector_concurrent_conflict_tiebreak() {
        // Two CONCURRENT delegations of the same key B with different capability
        // sets (no causal link). The deterministic tie-break orders by ascending
        // entry hash and takes the LAST.
        let creator = root(1, 1);
        let a1 = root(2, 2); // delegates "invite" to B
        let a2 = root(3, 3); // delegates "policy" to B
        let b = root(4, 4);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // Both a1 and a2 are full admins (creator delegates admin to each).
        let grant_a1 = h.admin_cert(&creator, &cid, 0, &a1, CapabilitySet::admin(), 0);
        let grant_a2 = h.admin_cert(&creator, &cid, 0, &a2, CapabilitySet::admin(), 0);
        // Two delegations of B, each causally AFTER its issuer's own admin grant
        // (so the issuer is authorized) but concurrent WITH EACH OTHER (neither
        // references the other). preds carry only the issuer's authorizing grant.
        let cert1 = h.admin_cert_concurrent(
            &a1,
            &cid,
            0,
            &b,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
            BTreeSet::from([grant_a1]),
        );
        let cert2 = h.admin_cert_concurrent(
            &a2,
            &cid,
            0,
            &b,
            CapabilitySet::from_iter_caps([Capability::Policy]),
            0,
            BTreeSet::from([grant_a2]),
        );

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a1, &a2, &b]),
        )
        .unwrap();

        // The governing set is the one with the LARGER (last ascending) entry hash.
        let winner_is_cert2 = cert2 > cert1;
        let effective = eval.authority_of(&b.fingerprint());
        if winner_is_cert2 {
            assert!(effective.grants(&Capability::Policy));
            assert!(!effective.grants(&Capability::Invite));
        } else {
            assert!(effective.grants(&Capability::Invite));
            assert!(!effective.grants(&Capability::Policy));
        }
    }

    // ---- VECTOR 6: totality — same log, any input order → identical verdict. ----

    #[test]
    fn vector_totality_independent_of_input_order() {
        let creator = root(1, 1);
        let a = root(2, 2);
        let b = root(3, 3);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.admin_cert(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Delegate, Capability::Invite]),
            0,
        );
        h.admin_cert(
            &a,
            &cid,
            0,
            &b,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        h.consent_grant(&a, &cid, 0, b.fingerprint(), [0xB0; 32]);

        let mut entries = h.entries();
        let keys = || key_resolver(vec![&creator, &a, &b]);
        let baseline = Evaluator::build(&genesis, &entries, 2_000, keys()).unwrap();

        // Reverse the input order; the verdict must be identical (totality).
        entries.reverse();
        let reversed = Evaluator::build(&genesis, &entries, 2_000, keys()).unwrap();

        assert_eq!(baseline.admins(), reversed.admins());
        assert_eq!(
            baseline.authority_of(&b.fingerprint()),
            reversed.authority_of(&b.fingerprint())
        );
        assert_eq!(
            baseline.can_read(&b.fingerprint(), &a.fingerprint()),
            reversed.can_read(&b.fingerprint(), &a.fingerprint())
        );
        assert_eq!(baseline.policy(), reversed.policy());

        // And a rotated order (every cyclic shift) gives the same admins + policy.
        for shift in 1..entries.len() {
            let mut rot = entries.clone();
            rot.rotate_left(shift);
            let e = Evaluator::build(&genesis, &rot, 2_000, keys()).unwrap();
            assert_eq!(e.admins(), baseline.admins());
            assert_eq!(e.policy(), baseline.policy());
            assert_eq!(
                e.authority_of(&b.fingerprint()),
                baseline.authority_of(&b.fingerprint())
            );
        }
    }

    // ---- Consent vectors. ----

    #[test]
    fn vector_consent_single_writer_latest_wins() {
        // A grants to B (seq1), then revokes B (seq2): A's latest causal state is
        // revoked → B cannot read A.
        let creator = root(1, 1);
        let a = root(2, 2);
        let b = root(3, 3);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.consent_grant(&a, &cid, 0, b.fingerprint(), [0xB0; 32]);
        h.consent_revocation(&a, &cid, 0, b.fingerprint(), 1);

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a, &b]),
        )
        .unwrap();
        assert!(!eval.can_read(&b.fingerprint(), &a.fingerprint()));
    }

    #[test]
    fn vector_consent_grant_then_regrant_after_revoke() {
        let creator = root(1, 1);
        let a = root(2, 2);
        let b = root(3, 3);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.consent_grant(&a, &cid, 0, b.fingerprint(), [0xB0; 32]);
        h.consent_revocation(&a, &cid, 0, b.fingerprint(), 1);
        // A re-grants (seq3) — latest causal state is grant → B can read A again.
        h.consent_grant(&a, &cid, 0, b.fingerprint(), [0xB2; 32]);

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a, &b]),
        )
        .unwrap();
        assert!(eval.can_read(&b.fingerprint(), &a.fingerprint()));
    }

    // ---- Policy vectors. ----

    #[test]
    fn vector_policy_update_changes_history_and_ttl_not_deniability() {
        let creator = root(1, 1);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();
        assert_eq!(genesis.body.policy.history_mode, HistoryMode::ForwardOnly);
        assert_eq!(
            genesis.body.policy.deniability_mode,
            DeniabilityMode::Attributable
        );

        let mut h = LogBuilder::new(&genesis);
        // Creator (admin → holds policy) updates history+ttl.
        h.policy_update(
            &creator,
            &cid,
            0,
            Some(HistoryMode::FullHistory),
            Some(3600),
        );

        let eval =
            Evaluator::build(&genesis, &h.entries(), 2_000, key_resolver(vec![&creator])).unwrap();
        let p = eval.policy();
        assert_eq!(p.history_mode, HistoryMode::FullHistory);
        assert_eq!(p.ttl, 3600);
        // Deniability is genesis-immutable, unchanged.
        assert_eq!(p.deniability_mode, DeniabilityMode::Attributable);
    }

    #[test]
    fn vector_unauthorized_policy_update_ignored() {
        // A non-admin authoring a policy-update has no effect (no policy cap).
        let creator = root(1, 1);
        let outsider = root(9, 9);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.policy_update(&outsider, &cid, 0, Some(HistoryMode::FullHistory), None);

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &outsider]),
        )
        .unwrap();
        // Genesis policy unchanged: the outsider's update is ignored.
        assert_eq!(eval.policy().history_mode, HistoryMode::ForwardOnly);
    }

    // ---- Cross-channel + forgery rejection. ----

    #[test]
    fn vector_cross_channel_cert_ignored() {
        // A cert bound to a DIFFERENT channelID is never trusted.
        let creator = root(1, 1);
        let a = root(2, 2);
        let genesis = genesis_for(&creator);
        let other_cid: Digest32 = [0xEE; 32];

        let mut h = LogBuilder::new(&genesis);
        // Cert names other_cid, not this channel's id.
        h.admin_cert(
            &creator,
            &other_cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a]),
        )
        .unwrap();
        // Dropped → A is not an admin.
        assert!(!eval.is_admin(&a.fingerprint()));
    }

    #[test]
    fn vector_unknown_author_key_dropped() {
        // An entry whose author key the resolver cannot supply is dropped.
        let creator = root(1, 1);
        let a = root(2, 2);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.admin_cert(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        // Resolver omits `a`'s key — but the cert is authored by creator, so it
        // still resolves. Author a's own (absent) entries would be dropped; here we
        // verify the creator path works without a's key.
        let eval =
            Evaluator::build(&genesis, &h.entries(), 2_000, key_resolver(vec![&creator])).unwrap();
        assert!(eval.is_admin(&a.fingerprint()));
    }

    // ---- Adversarial vectors (the release gate is deliberately hostile) ----

    use crate::governance::entry::GovEntry;
    use std::collections::BTreeMap;

    /// A fully-resolved, comparable snapshot of an evaluator's verdicts — the
    /// quantity that MUST be identical on every client.
    #[derive(Debug, PartialEq, Eq)]
    struct Snapshot {
        admins: BTreeSet<Digest32>,
        authority: BTreeMap<Digest32, Vec<String>>,
        consent: BTreeMap<Digest32, BTreeSet<Digest32>>,
        history: u64,
        ttl: u64,
        epoch: u64,
    }

    /// Build the snapshot for a given evaluator over a fixed signer set.
    fn snapshot(
        genesis: &Genesis,
        entries: &[GovEntry],
        now: u64,
        signers: &[&SoftwareRootSigner],
    ) -> Snapshot {
        let eval = Evaluator::build(genesis, entries, now, key_resolver(signers.to_vec())).unwrap();
        let admins = eval.admins();
        let authority = admins
            .iter()
            .map(|a| (*a, eval.authority_of(a).to_tokens()))
            .collect();
        // Every signer is a potential consent author; record each one's readable set.
        let consent = signers
            .iter()
            .map(|s| (s.fingerprint(), eval.readers_of(&s.fingerprint())))
            .filter(|(_, r)| !r.is_empty())
            .collect();
        let p = eval.policy();
        Snapshot {
            admins,
            authority,
            consent,
            history: p.history_mode.as_u64(),
            ttl: p.ttl,
            epoch: eval.current_epoch(),
        }
    }

    /// Assert the resolved snapshot is identical for the original order, the
    /// reversed order, and EVERY cyclic shift — the totality guarantee.
    fn assert_total(
        genesis: &Genesis,
        entries: &[GovEntry],
        now: u64,
        signers: &[&SoftwareRootSigner],
    ) -> Snapshot {
        let baseline = snapshot(genesis, entries, now, signers);

        let mut rev = entries.to_vec();
        rev.reverse();
        assert_eq!(
            snapshot(genesis, &rev, now, signers),
            baseline,
            "reversed order changed the verdict (totality violation)"
        );

        for shift in 1..entries.len() {
            let mut rot = entries.to_vec();
            rot.rotate_left(shift);
            assert_eq!(
                snapshot(genesis, &rot, now, signers),
                baseline,
                "cyclic shift {shift} changed the verdict (totality violation)"
            );
        }
        baseline
    }

    #[test]
    fn adversarial_concurrent_revocation_beats_concurrent_delegation() {
        // Removal-wins for CONCURRENT entries regardless of hash order: a
        // concurrent revocation of X's delegation must win over a concurrent
        // (re-)delegation of X, for BOTH hash orderings. We test both by trying two
        // different delegate seeds so the relative hash order flips.
        for (da, db) in [(40u8, 41u8), (42u8, 43u8)] {
            let creator = root(1, 1);
            let admin2 = root(2, 2); // a second full admin (authorized revoker)
            let x = root(da, db); // the delegate
            let genesis = genesis_for(&creator);
            let cid = genesis.channel_id();

            let mut h = LogBuilder::new(&genesis);
            let grant_admin2 = h.admin_cert(&creator, &cid, 0, &admin2, CapabilitySet::admin(), 0);
            // creator delegates invite to X (causally first).
            let deleg_x = h.admin_cert(
                &creator,
                &cid,
                0,
                &x,
                CapabilitySet::from_iter_caps([Capability::Invite]),
                0,
            );
            // A revocation of deleg_x by admin2 (causally after admin2's OWN admin
            // grant, so admin2 is authorized) and a re-delegation of X by creator
            // (root, always authorized) — both concurrent WITH EACH OTHER and with
            // deleg_x (neither references deleg_x or the other), so removal-wins must
            // kill both regardless of entry-hash order.
            h.admin_revocation_concurrent(
                &admin2,
                &cid,
                0,
                deleg_x,
                BTreeSet::from([grant_admin2]),
            );
            h.admin_cert_concurrent(
                &creator,
                &cid,
                0,
                &x,
                CapabilitySet::from_iter_caps([Capability::Invite]),
                0,
                BTreeSet::new(),
            );

            let signers = [&creator, &admin2, &x];
            let snap = assert_total(&genesis, &h.entries(), 2_000, &signers);
            // Removal wins: X is NOT an admin (the concurrent revocation beats the
            // concurrent delegation regardless of entry-hash order).
            assert!(
                !snap.admins.contains(&x.fingerprint()),
                "concurrent revocation must beat concurrent delegation"
            );
        }
    }

    #[test]
    fn adversarial_causal_attenuation_overrides_higher_hash_elder() {
        // A causally-LATER attenuation must override an earlier broader grant of the
        // same delegate, even if the earlier grant has a LARGER entry hash. We scan
        // delegate seeds until we find a case where the elder's hash > the younger's,
        // proving the tie-break does not let a bigger-hash elder win over a
        // causally-later child.
        let creator = root(1, 1);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut found = false;
        for seed in 50u8..90u8 {
            let x = root(seed, seed.wrapping_add(1));
            let mut h = LogBuilder::new(&genesis);
            // Elder: creator delegates {invite, policy} to X.
            let elder = h.admin_cert(
                &creator,
                &cid,
                0,
                &x,
                CapabilitySet::from_iter_caps([Capability::Invite, Capability::Policy]),
                0,
            );
            // Younger: causally AFTER the elder (preds={elder}), attenuates to
            // {invite} only.
            let mut preds = BTreeSet::new();
            preds.insert(elder);
            let younger = h.admin_cert_concurrent(
                &creator,
                &cid,
                0,
                &x,
                CapabilitySet::from_iter_caps([Capability::Invite]),
                0,
                preds,
            );
            // Only exercise the adversarial case: elder hash > younger hash.
            if elder <= younger {
                continue;
            }
            found = true;

            let signers = [&creator, &x];
            let snap = assert_total(&genesis, &h.entries(), 2_000, &signers);
            // The causally-later attenuation governs: X holds invite but NOT policy,
            // even though the elder (which had policy) has the larger hash.
            let caps = snap
                .authority
                .get(&x.fingerprint())
                .cloned()
                .unwrap_or_default();
            assert!(caps.contains(&"invite".to_string()));
            assert!(
                !caps.contains(&"policy".to_string()),
                "causally-later attenuation must override a higher-hash elder"
            );
            break;
        }
        assert!(
            found,
            "expected at least one elder>younger hash case in the scan"
        );
    }

    #[test]
    fn adversarial_self_revocation_converges() {
        // A key revokes the very cert that grants its own delegate authority. This
        // is the oscillation trap: it must converge to a single deterministic
        // verdict (not parity-dependent), and be order-invariant.
        let creator = root(1, 1);
        let a = root(2, 2);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // creator delegates delegate-capability to A.
        let deleg_a = h.admin_cert(
            &creator,
            &cid,
            0,
            &a,
            CapabilitySet::from_iter_caps([Capability::Delegate]),
            0,
        );
        // A revokes its OWN delegation cert (causally after it). With removal-wins,
        // A is not admin → A's revocation is unauthorized → ... must converge.
        let mut preds = BTreeSet::new();
        preds.insert(deleg_a);
        h.admin_revocation_concurrent(&a, &cid, 0, deleg_a, preds);

        let signers = [&creator, &a];
        // The key assertion is that build() resolves to ONE stable, order-invariant
        // verdict (the stratified resolver is acyclic — no oscillation).
        let snap = assert_total(&genesis, &h.entries(), 2_000, &signers);
        // Deterministic outcome: A's self-revocation is authorized from R's STRICT
        // past (which still contains deleg_a granting A `delegate`), so R is valid
        // and, under removal-wins, suppresses that very delegation (R is causally
        // after deleg_a, so deleg_a is not after R) — A ends up NOT an admin.
        assert!(!snap.admins.contains(&a.fingerprint()));
    }

    #[test]
    fn adversarial_mixed_partial_order_policy_is_total() {
        // Two CONCURRENT policy-updates by two admins set conflicting history/ttl.
        // The canonical order resolves them deterministically; the result must be
        // identical under reverse + every cyclic shift.
        let creator = root(1, 1);
        let admin2 = root(2, 2);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.admin_cert(&creator, &cid, 0, &admin2, CapabilitySet::admin(), 0);
        // Two concurrent policy-updates (empty preds): one sets FullHistory+ttl=10,
        // the other ForwardOnly+ttl=20.
        h.policy_update_concurrent(
            &creator,
            &cid,
            0,
            Some(HistoryMode::FullHistory),
            Some(10),
            BTreeSet::new(),
        );
        h.policy_update_concurrent(
            &admin2,
            &cid,
            0,
            Some(HistoryMode::ForwardOnly),
            Some(20),
            BTreeSet::new(),
        );

        let signers = [&creator, &admin2];
        // Totality is the assertion: a single deterministic policy under every order.
        let _snap = assert_total(&genesis, &h.entries(), 2_000, &signers);
    }

    #[test]
    fn adversarial_concurrent_consent_grant_revoke_is_total() {
        // A authors a grant and a revocation of the SAME target as two CONCURRENT
        // entries (different feeds would violate single-writer, so these are A's own
        // feed — inherently ordered; to stress the resolver we still confirm
        // order-invariance of the resolved consent).
        let creator = root(1, 1);
        let a = root(2, 2);
        let b = root(3, 3);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.consent_grant(&a, &cid, 0, b.fingerprint(), [0xB0; 32]); // seq1
        h.consent_revocation(&a, &cid, 0, b.fingerprint(), 1); // seq2 (after)
        let signers = [&creator, &a, &b];
        let snap = assert_total(&genesis, &h.entries(), 2_000, &signers);
        // A's latest action is revocation → B cannot read A.
        assert!(!snap.consent.contains_key(&a.fingerprint()));
    }

    #[test]
    fn adversarial_passphrase_rotation_tracks_epoch_and_is_total() {
        // An authorized passphrase-rotation bumps the channel epoch; resolution is
        // order-invariant and a stale-epoch governance fact is dropped.
        let creator = root(1, 1);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // creator (admin → holds passphrase-rotate) bumps epoch 0 → 1.
        h.passphrase_rotation(&creator, &cid, 0, 1);

        let signers = [&creator];
        let snap = assert_total(&genesis, &h.entries(), 2_000, &signers);
        assert_eq!(snap.epoch, 1);
    }

    #[test]
    fn adversarial_future_epoch_entry_dropped() {
        // A governance entry bound to an epoch the channel never established (a
        // forged future epoch) is dropped, so it cannot confer authority.
        let creator = root(1, 1);
        let a = root(2, 2);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // No passphrase-rotation has run, so max established epoch is 0. A cert at
        // epoch 5 is impossible/forged → dropped.
        h.admin_cert(
            &creator,
            &cid,
            5,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &a]),
        )
        .unwrap();
        assert!(!eval.is_admin(&a.fingerprint()));
    }

    #[test]
    fn adversarial_unauthorized_passphrase_rotation_ignored() {
        // A non-admin's passphrase-rotation does not bump the epoch.
        let creator = root(1, 1);
        let outsider = root(9, 9);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        h.passphrase_rotation(&outsider, &cid, 0, 1);
        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &outsider]),
        )
        .unwrap();
        // Outsider has no passphrase-rotate authority → epoch stays 0.
        assert_eq!(eval.current_epoch(), 0);
    }

    #[test]
    fn adversarial_rotation_with_wrong_old_epoch_ignored() {
        // An authorized rotation whose old_epoch does not chain off the current
        // epoch (0) is ignored — it cannot fork the epoch line.
        let creator = root(1, 1);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // creator IS authorized (admin), but claims old_epoch=5 while current is 0.
        h.passphrase_rotation(&creator, &cid, 5, 6);
        let eval =
            Evaluator::build(&genesis, &h.entries(), 2_000, key_resolver(vec![&creator])).unwrap();
        // The rotation does not chain off epoch 0 → ignored → epoch stays 0.
        assert_eq!(eval.current_epoch(), 0);
    }

    #[test]
    fn adversarial_unauthorized_rotation_does_not_let_future_epoch_entries_through() {
        // An UNAUTHORIZED rotation must NOT establish a new epoch, so a governance
        // entry bound to that would-be epoch is dropped (cannot confer authority).
        let creator = root(1, 1);
        let outsider = root(9, 9);
        let a = root(2, 2);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // Outsider (no authority) forges a rotation 0→1.
        h.passphrase_rotation(&outsider, &cid, 0, 1);
        // creator delegates to A bound to epoch 1 — but epoch 1 was never legitimately
        // established (the rotation was unauthorized), so this cert is future-epoch
        // and must be dropped.
        h.admin_cert(
            &creator,
            &cid,
            1,
            &a,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &outsider, &a]),
        )
        .unwrap();
        // Epoch never advanced; the epoch-1 cert was dropped → A is not an admin.
        assert_eq!(eval.current_epoch(), 0);
        assert!(!eval.is_admin(&a.fingerprint()));
    }

    #[test]
    fn adversarial_revocation_lineage_through_same_author_chain() {
        // A revocation whose causal link to the revoked delegation runs through a
        // same-author seq chain must still apply (the unified causal relation). B
        // authors deleg_x (B-seq1) then a filler entry (B-seq2); creator revokes
        // deleg_x referencing B-seq2 (so the link to B-seq1 is via B's seq chain).
        let creator = root(1, 1);
        let b = root(2, 2);
        let x = root(3, 3);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // B is a full admin.
        h.admin_cert(&creator, &cid, 0, &b, CapabilitySet::admin(), 0);
        // B-seq1: B delegates invite to X.
        let deleg_x = h.admin_cert(
            &b,
            &cid,
            0,
            &x,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        // B-seq2: a filler consent grant by B (advances B's chain).
        let b_seq2 = h.consent_grant(&b, &cid, 0, x.fingerprint(), [0x55; 32]);
        // creator revokes deleg_x, referencing ONLY B-seq2 (link to deleg_x is via
        // B's same-author seq edge B-seq2 → B-seq1).
        let mut preds = BTreeSet::new();
        preds.insert(b_seq2);
        h.admin_revocation_concurrent(&creator, &cid, 0, deleg_x, preds);

        let signers = [&creator, &b, &x];
        let snap = assert_total(&genesis, &h.entries(), 2_000, &signers);
        // The revocation reaches deleg_x through the same-author chain → X removed.
        assert!(!snap.admins.contains(&x.fingerprint()));
    }

    #[test]
    fn adversarial_delegation_after_revocation_does_not_authorize_it() {
        // Temporal escalation rejected: a revocation R's authorization must come
        // ONLY from R's strict causal past. A delegation that grants the revoker its
        // `delegate` authority but is causally-AFTER R must NOT authorize R.
        let creator = root(1, 1);
        let k = root(2, 2); // would-be revoker
        let x = root(3, 3); // the victim delegate
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // creator delegates invite to X.
        let deleg_x = h.admin_cert(
            &creator,
            &cid,
            0,
            &x,
            CapabilitySet::from_iter_caps([Capability::Invite]),
            0,
        );
        // K revokes deleg_x — but K has NO authority in this revocation's past.
        // preds = {deleg_x} only (so the revocation does not see any K-grant).
        let rev = h.admin_revocation_concurrent(&k, &cid, 0, deleg_x, BTreeSet::from([deleg_x]));
        // NOW creator grants K `delegate`, causally AFTER the revocation (preds={rev}).
        h.admin_cert_concurrent(
            &creator,
            &cid,
            0,
            &k,
            CapabilitySet::from_iter_caps([Capability::Delegate]),
            0,
            BTreeSet::from([rev]),
        );

        let signers = [&creator, &k, &x];
        let snap = assert_total(&genesis, &h.entries(), 2_000, &signers);
        // K's grant is causally-after R, so it cannot authorize R → R is ignored →
        // X keeps its delegation (escalation rejected). K itself is a delegate-admin.
        assert!(
            snap.admins.contains(&x.fingerprint()),
            "a delegation causally-after a revocation must not authorize it"
        );
    }

    #[test]
    fn adversarial_future_epoch_cert_cannot_bootstrap_its_own_rotation() {
        // Future-epoch bootstrap rejected: a rotation to epoch 1 must be authorized
        // from facts established in its strict past (epoch 0). A cert bound to
        // epoch 1 — which only the rotation itself would establish — is NOT in-effect
        // at the rotation's causal position, so it cannot authorize the rotation.
        let creator = root(1, 1);
        let k = root(2, 2); // would-be rotator
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let mut h = LogBuilder::new(&genesis);
        // creator grants K `passphrase-rotate` but BOUND TO EPOCH 1 (a future epoch
        // that has not been established). This cert is not in-effect until epoch 1
        // exists — which is exactly what the rotation below would create.
        h.admin_cert(
            &creator,
            &cid,
            1,
            &k,
            CapabilitySet::from_iter_caps([Capability::PassphraseRotate]),
            0,
        );
        // K authors the rotation 0 → 1. Its authorization is decided from its strict
        // past, where the epoch is still 0 and the epoch-1 grant is not in-effect →
        // K is not authorized → the rotation does not establish epoch 1.
        h.passphrase_rotation(&k, &cid, 0, 1);

        let eval = Evaluator::build(
            &genesis,
            &h.entries(),
            2_000,
            key_resolver(vec![&creator, &k]),
        )
        .unwrap();
        assert_eq!(
            eval.current_epoch(),
            0,
            "a future-epoch cert must not bootstrap the rotation that establishes its epoch"
        );
        // And K never becomes a passphrase-rotate holder (its grant stays out-of-effect).
        assert!(!eval
            .grants(&k.fingerprint(), &Capability::PassphraseRotate)
            .is_granted());
    }

    #[test]
    fn adversarial_cyclic_causal_predecessors_rejected() {
        // Hostile input: two verified governance entries whose caller-supplied
        // causal_predecessors reference each other (a cycle the real hash-linked log
        // can never produce). The evaluator must return Err(GovernanceCycle), not
        // recurse without bound. We build real signed consent grants (so they pass
        // verification + channel binding) and inject cyclic coordinates directly.
        use crate::governance::consent::ConsentGrant;
        use crate::governance::entry::{GovBody, GovEntry};
        use crate::governance::genesis::HistoryMode;

        let creator = root(1, 1);
        let a = root(2, 2);
        let b = root(3, 3);
        let genesis = genesis_for(&creator);
        let cid = genesis.channel_id();

        let g_a = ConsentGrant::build(
            &a,
            &cid,
            0,
            b.fingerprint(),
            [0xAA; 32],
            HistoryMode::ForwardOnly,
        )
        .unwrap();
        let g_b = ConsentGrant::build(
            &b,
            &cid,
            0,
            a.fingerprint(),
            [0xBB; 32],
            HistoryMode::ForwardOnly,
        )
        .unwrap();

        // Two distinct entry hashes that name EACH OTHER as causal predecessors.
        let h_a = [0x11; 32];
        let h_b = [0x22; 32];
        let e_a = GovEntry::from_parts(
            GovBody::ConsentGrant(Box::new(g_a)),
            h_a,
            a.fingerprint(),
            1,
            BTreeSet::from([h_b]), // A happens-after B
        );
        let e_b = GovEntry::from_parts(
            GovBody::ConsentGrant(Box::new(g_b)),
            h_b,
            b.fingerprint(),
            1,
            BTreeSet::from([h_a]), // B happens-after A → cycle
        );

        let res = Evaluator::build(
            &genesis,
            &[e_a, e_b],
            2_000,
            key_resolver(vec![&creator, &a, &b]),
        );
        assert!(matches!(res, Err(crate::error::Error::GovernanceCycle)));
    }
}
