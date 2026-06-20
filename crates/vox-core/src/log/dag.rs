//! The cross-author causal Merkle-DAG (ADR-008 §Decision) — a CRDT for causal
//! histories.
//!
//! ## Causality model (explicit — the SSB / Hypercore model ADR-008 cites)
//! Vox uses **per-author causal chains merged as concurrent feeds**, exactly the
//! Secure-Scuttlebutt / Hypercore structure ADR-008 §Decision names. Concretely:
//! - **Within one author** the feed is a *total order*: `seq` is strictly
//!   monotonic and each entry hash-links its predecessors (`prev_hash` = seq−1,
//!   `lipmaa_backlink` = the Bamboo skip predecessor). Entry *n* causally
//!   precedes *n+1* of the same author.
//! - **Across authors** entries are **concurrent**: the ADR-008 entry schema has
//!   **no cross-author parent field**, so M5 records no happens-before edge
//!   between two different authors' entries. (Any application-level cross-author
//!   reference lives inside the encrypted, opaque payload and surfaces in later
//!   milestones; adding a cross-author parent to the *schema* would be an ADR-008
//!   amendment and is deliberately NOT done here.)
//! - **Merge = union.** The DAG is the set union of all per-author feeds. Because
//!   each feed is independently hash-chain-verifiable and there is no cross-author
//!   edge to reconcile, the union of the same entry set is identical on every
//!   replica regardless of receipt order — **Strong Eventual Consistency**. This
//!   is a valid causal CRDT (the Matrix-event-graph convergence result, ADR-008).
//!
//! The convergence test exercises *concurrent cross-author* entries: two authors'
//! feeds delivered to two replicas in different interleavings yield byte-identical
//! [`Dag::causal_order`] output.
//!
//! ## What this module owns
//! - The **store**: feeds keyed by author, plus a content-addressed index by
//!   entry hash, so an entry is inserted once and looked up by its 32-byte hash
//!   (the Negentropy key, ADR-008 §Sync).
//! - The **acceptance predicate** (ADR-008 §"Abuse resistance"): an entry is
//!   accepted only if (a) its author is in the admitted set for `(channelID,
//!   epoch)` (M3/M6 input), (b) its per-author authenticator verifies, and (c) it
//!   is within the author's quota ([`crate::log::quota`]).
//! - **Fork / equivocation handling** (ADR-008 §"Fork / equivocation handling"):
//!   two distinct entries at the same `(author, seq)` with different hashes are an
//!   equivocation. For **attributable** entries this is a self-authenticating
//!   fork proof → the author is frozen and the proof recorded. For **deniable**
//!   content (M7) the authenticator is forgeable, so a conflict raises a
//!   non-attributable *alarm* and does **not** auto-freeze.
//! - **Render-gating** ([`Dag::render`]): the store holds ciphertext regardless of
//!   readability; rendering attempts decryption and succeeds only if keys are held
//!   (the decryptor is M4/M6).
//!
//! ## Causal ordering / convergence
//! [`Dag::causal_order`] returns a topological order: every entry appears after
//! all of its causal predecessors. The order is made **deterministic** (stable
//! across replicas) by breaking ties on `(author_id, seq)`, so two replicas with
//! the same entry set produce the identical sequence — the observable form of
//! convergence.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::log::entry::{DeniableVerifier, Entry, EntryKind};
use crate::log::feed::Feed;
use crate::log::quota::{QuotaReject, QuotaTracker};

/// An uninhabited [`DeniableVerifier`] naming the concrete type for the `None`
/// default in [`Dag::accept`] (which performs no deniable verification). Its
/// method is unreachable.
enum NoDeniable {}
impl DeniableVerifier for NoDeniable {
    fn verify_deniable(&self, _: &crate::log::entry::EntrySkeleton, _: &[u8]) -> Result<()> {
        Err(Error::DeniableVerificationUnavailable)
    }
}
/// The typed `None` deniable verifier used by [`Dag::accept`].
const NO_DENIABLE: Option<&NoDeniable> = None;

/// The set of identities admitted to a `(channelID, epoch)` — the membership
/// input to the acceptance predicate (ADR-008 §"Abuse resistance"). M5 models
/// this as an explicit input; the *population* of the set from authenticated join
/// (CPace, ADR-005/M3) and consent (ADR-007/M6) is those milestones' job. An
/// entry from an author not admitted for its `(channelID, epoch)` is rejected
/// before any quota or DAG mutation.
#[derive(Debug, Default, Clone)]
pub struct AdmissionPolicy {
    /// (channel, epoch) -> admitted author fingerprints.
    admitted: HashMap<(Digest32, u64), HashSet<Digest32>>,
}

impl AdmissionPolicy {
    /// An empty policy (no one admitted).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit `author` to `(channel, epoch)`.
    pub fn admit(&mut self, channel: Digest32, epoch: u64, author: Digest32) {
        self.admitted
            .entry((channel, epoch))
            .or_default()
            .insert(author);
    }

    /// Whether `author` is admitted to `(channel, epoch)`.
    #[must_use]
    pub fn is_admitted(&self, channel: &Digest32, epoch: u64, author: &Digest32) -> bool {
        self.admitted
            .get(&(*channel, epoch))
            .is_some_and(|s| s.contains(author))
    }
}

/// A self-authenticating fork proof (ADR-008): two validly-signed, distinct
/// entries by one author at the same `seq`. For attributable entries this
/// genuinely incriminates the author, so clients freeze it and record the proof.
#[derive(Debug, Clone)]
pub struct ForkProof {
    /// The equivocating author's fingerprint.
    pub author_id: Digest32,
    /// The shared sequence number with two different entries.
    pub seq: u64,
    /// The already-stored entry at `(author_id, seq)`.
    pub existing: Entry,
    /// The conflicting entry presented for the same `(author_id, seq)`.
    pub conflicting: Entry,
}

/// The result of attempting to accept an entry that conflicts with a stored one.
#[derive(Debug)]
#[non_exhaustive]
pub enum ForkOutcome {
    /// Attributable conflict: a self-authenticating fork proof. The author is
    /// frozen; the proof is returned for recording + UI surfacing (ADR-014). The
    /// proof carries two full entries (each with a multi-kilobyte composite
    /// signature), so it is boxed to keep the common `Ok`/error paths small.
    Attributable(Box<ForkProof>),
    /// Deniable-content conflict (M7 authenticator): the proof does NOT
    /// incriminate a specific author (any member could mint it), so this is a
    /// non-attributable *alarm* — surfaced for manual resolution, **never** an
    /// auto-freeze (it would be a framing/DoS primitive, ADR-008/ADR-009).
    DeniableAlarm {
        /// The author whose `(author, seq)` slot saw a conflict.
        author_id: Digest32,
        /// The shared sequence number.
        seq: u64,
    },
}

/// Why an entry was not accepted into the DAG.
#[derive(Debug)]
#[non_exhaustive]
pub enum Rejected {
    /// The author is not in the admitted set for the entry's `(channel, epoch)`.
    NotAdmitted,
    /// The entry's authenticator (or author/structure) failed verification.
    Verification(Error),
    /// The entry exceeded the author's quota and was dropped (not relayed).
    Quota(QuotaReject),
    /// The entry conflicts with a stored entry at the same `(author, seq)`
    /// (equivocation); the [`ForkOutcome`] carries the attributable-vs-deniable
    /// remedy.
    Fork(ForkOutcome),
    /// The entry did not link correctly into the author's feed (bad seq, broken
    /// `prev_hash`/`lipmaa_backlink`, append past end-of-feed).
    Feed(Error),
    /// A duplicate of an already-stored entry (same hash) — idempotently ignored.
    Duplicate,
    /// A governance/control entry carried a non-attributable (deniable)
    /// authenticator. Governance MUST be composite-signed in every channel
    /// (ADR-008), so this is rejected before storage.
    GovernanceNotAttributable,
}

/// The replicated log store: per-author feeds, a hash index, frozen authors, and
/// the quota tracker. One [`Dag`] per channel.
#[derive(Debug, Default)]
pub struct Dag {
    /// author -> feed.
    feeds: HashMap<Digest32, Feed>,
    /// entry hash -> (author, seq), for content-addressed lookup and Negentropy.
    by_hash: HashMap<Digest32, (Digest32, u64)>,
    /// Authors frozen by an attributable fork proof; their later entries are
    /// refused (ADR-008 — members revoke/rotate to exclude the equivocator).
    frozen: HashMap<Digest32, ForkProof>,
    /// Per-author quotas.
    quota: QuotaTracker,
}

impl Dag {
    /// An empty DAG with the ADR-008 default quota policy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            feeds: HashMap::new(),
            by_hash: HashMap::new(),
            frozen: HashMap::new(),
            quota: QuotaTracker::with_defaults(),
        }
    }

    /// An empty DAG with an explicit quota tracker (policy from a channel policy).
    #[must_use]
    pub fn with_quota(quota: QuotaTracker) -> Self {
        Self {
            feeds: HashMap::new(),
            by_hash: HashMap::new(),
            frozen: HashMap::new(),
            quota,
        }
    }

    /// The number of entries stored across all authors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Whether the DAG holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    /// The feed for `author`, if any.
    #[must_use]
    pub fn feed(&self, author: &Digest32) -> Option<&Feed> {
        self.feeds.get(author)
    }

    /// All authors with a feed, sorted (deterministic iteration).
    #[must_use]
    pub fn authors(&self) -> Vec<Digest32> {
        let mut a: Vec<Digest32> = self.feeds.keys().copied().collect();
        a.sort_unstable();
        a
    }

    /// Whether `author` has been frozen by a fork proof.
    #[must_use]
    pub fn is_frozen(&self, author: &Digest32) -> bool {
        self.frozen.contains_key(author)
    }

    /// The recorded fork proof for a frozen author, if any.
    #[must_use]
    pub fn fork_proof(&self, author: &Digest32) -> Option<&ForkProof> {
        self.frozen.get(author)
    }

    /// Look up a stored entry by its 32-byte hash (the Negentropy key).
    #[must_use]
    pub fn get_by_hash(&self, hash: &Digest32) -> Option<&Entry> {
        let (author, seq) = self.by_hash.get(hash)?;
        self.feeds.get(author).and_then(|f| f.get(*seq))
    }

    /// Whether an entry with this hash is stored.
    #[must_use]
    pub fn contains(&self, hash: &Digest32) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Accept an entry into the DAG, enforcing the full ADR-008 predicate.
    ///
    /// Steps, in order (any failure leaves the DAG unchanged):
    /// 1. If the author is frozen, refuse ([`Rejected::Fork`] with the recorded
    ///    proof is *not* re-raised; later entries from a frozen author are simply
    ///    refused via [`Rejected::NotAdmitted`]-style guard — see below).
    /// 2. Duplicate (same hash already stored) → [`Rejected::Duplicate`]
    ///    (idempotent replication).
    /// 3. Equivocation: a different entry already occupies `(author, seq)` →
    ///    [`Rejected::Fork`]; for an attributable entry the author is frozen.
    /// 4. Admission: author ∈ admitted set for `(channel, epoch)`.
    /// 5. Authenticator + structure verify under `author_root`.
    /// 6. Quota: within the author's rate/byte budget.
    /// 7. Feed link: `seq`/`prev_hash`/`lipmaa_backlink`/end-of-feed.
    ///
    /// `kind` selects the governance/content rule; fork attributability is then
    /// determined by the entry's authenticator type (governance is forced
    /// composite above). `now_secs` feeds the quota clock.
    ///
    /// Equivalent to [`Dag::accept_with_deniable`] with no deniable verifier, so a
    /// **deniable** content entry fails verification with
    /// [`Error::DeniableVerificationUnavailable`] (the M7 verifier is supplied via
    /// [`Dag::accept_with_deniable`]). The equivocation check runs *before*
    /// verification, so a deniable fork is still classified (as an alarm) without
    /// a verifier.
    pub fn accept(
        &mut self,
        entry: Entry,
        kind: EntryKind,
        author_root: &CompositePublicKey,
        admission: &AdmissionPolicy,
        now_secs: u64,
    ) -> std::result::Result<Digest32, Rejected> {
        self.accept_with_deniable(entry, kind, author_root, admission, now_secs, NO_DENIABLE)
    }

    /// Accept an entry, verifying a [`crate::log::entry::Authenticator::Deniable`] authenticator with
    /// the supplied M7 [`DeniableVerifier`] when one is given (ADR-009 crypto is
    /// M7). The composite path is unaffected. This is the seam M7 fills; M5 callers
    /// use [`Dag::accept`].
    pub fn accept_with_deniable<V: DeniableVerifier>(
        &mut self,
        entry: Entry,
        kind: EntryKind,
        author_root: &CompositePublicKey,
        admission: &AdmissionPolicy,
        now_secs: u64,
        deniable: Option<&V>,
    ) -> std::result::Result<Digest32, Rejected> {
        let author = entry.skeleton.author_id;
        let seq = entry.skeleton.seq;
        let channel = entry.skeleton.channel_id;
        let epoch = entry.skeleton.epoch;
        let hash = entry.entry_hash();

        // Governance/control entries MUST be composite (attributable) in EVERY
        // channel (ADR-008 §"Per-entry-type authentication"): a deniable
        // authenticator on a governance entry is rejected outright, so the
        // governance plane — and its fork attribution — stays intact even in
        // deniable channels.
        if matches!(kind, EntryKind::Governance) && !entry.authenticator.is_attributable() {
            return Err(Rejected::GovernanceNotAttributable);
        }

        // A frozen author's further entries are refused outright.
        if self.frozen.contains_key(&author) {
            return Err(Rejected::NotAdmitted);
        }

        // Idempotent duplicate.
        if self.by_hash.contains_key(&hash) {
            return Err(Rejected::Duplicate);
        }

        // Equivocation: a *different* entry already occupies (author, seq)?
        if let Some(feed) = self.feeds.get(&author) {
            if let Some(existing) = feed.get(seq) {
                // Same seq, different hash (duplicate handled above) ⇒ a fork.
                let outcome = self.classify_fork(existing.clone(), entry.clone());
                if let ForkOutcome::Attributable(ref proof) = outcome {
                    // Verify BOTH conflicting entries are validly signed before
                    // freezing — an attributable fork proof must be
                    // self-authenticating (both composite signatures verify).
                    if entry.verify_with_deniable(author_root, deniable).is_ok()
                        && existing.verify_with_deniable(author_root, deniable).is_ok()
                    {
                        self.frozen.insert(author, (**proof).clone());
                    }
                }
                return Err(Rejected::Fork(outcome));
            }
        }

        // Admission.
        if !admission.is_admitted(&channel, epoch, &author) {
            return Err(Rejected::NotAdmitted);
        }

        // Authenticator + structure (deniable verified via the M7 seam if given).
        entry
            .verify_with_deniable(author_root, deniable)
            .map_err(Rejected::Verification)?;

        // Feed link: validate (without mutating) BEFORE committing quota, so a
        // structural rejection never consumes the author's quota budget. The feed
        // enforces seq/prev_hash/lipmaa_backlink/end-of-feed.
        let feed = self.feeds.entry(author).or_default();
        feed.validate_next(&entry).map_err(Rejected::Feed)?;

        // Quota (drop, do not relay, on breach).
        self.quota
            .admit(&author, epoch, entry.skeleton.payload_len, now_secs)
            .map_err(Rejected::Quota)?;

        // Commit: append (cannot fail — validate_next just succeeded and the feed
        // was not mutated in between) and index by hash.
        let feed = self.feeds.entry(author).or_default();
        feed.append(entry).map_err(Rejected::Feed)?;
        self.by_hash.insert(hash, (author, seq));
        Ok(hash)
    }

    /// Classify a `(author, seq)` conflict by the **authenticator type** of the
    /// conflicting entries (ADR-008 §"Fork / equivocation handling"). A conflict
    /// is a self-authenticating fork proof only if *both* entries are attributable
    /// (composite-signed): governance entries are forced composite at acceptance,
    /// so this rule alone covers them — no caller hint is consulted. If either
    /// entry carries a forgeable (deniable) authenticator, the conflict is a
    /// non-attributable alarm (auto-freeze would be a framing/DoS primitive).
    fn classify_fork(&self, existing: Entry, conflicting: Entry) -> ForkOutcome {
        let author_id = conflicting.skeleton.author_id;
        let seq = conflicting.skeleton.seq;
        let attributable =
            conflicting.authenticator.is_attributable() && existing.authenticator.is_attributable();
        if attributable {
            ForkOutcome::Attributable(Box::new(ForkProof {
                author_id,
                seq,
                existing,
                conflicting,
            }))
        } else {
            ForkOutcome::DeniableAlarm { author_id, seq }
        }
    }

    /// A deterministic causal (topological) order of every stored entry: each
    /// entry appears after all of its causal predecessors (its own feed's earlier
    /// entries). Ties between concurrent entries are broken on `(author_id, seq)`,
    /// so two replicas holding the same entry set yield the **identical** order —
    /// the observable form of Strong Eventual Consistency.
    ///
    /// The visible causal edges in M5 are the per-author `seq` chains; cross-author
    /// causal references travel inside (opaque, encrypted) payloads and surface in
    /// later milestones, so the merge here is the union of per-author total orders,
    /// deterministically interleaved.
    #[must_use]
    pub fn causal_order(&self) -> Vec<Digest32> {
        // Within an author, seq order is the causal order. Across authors there is
        // no edge visible to M5, so we interleave deterministically by author id,
        // emitting all entries in (author_id, seq) lexicographic order. This is a
        // valid topological order (per-author predecessors precede successors) and
        // is identical on any replica with the same set.
        let mut keyed: BTreeMap<(Digest32, u64), Digest32> = BTreeMap::new();
        for (author, feed) in &self.feeds {
            for entry in feed.iter() {
                keyed.insert((*author, entry.skeleton.seq), entry.entry_hash());
            }
        }
        keyed.into_values().collect()
    }

    /// Render-gating seam (ADR-008): attempt to decrypt+render the payload of the
    /// entry at `hash` with `decrypt`. The store holds ciphertext regardless of
    /// readability; this returns `Some(plaintext)` only if a payload is retained
    /// **and** `decrypt` succeeds (the holder has keys). A `None` means "store it,
    /// replicate it, but do not render" — exactly the data-side of per-sender
    /// consent. The real decryptor is M4/M6; M5 only owns this seam.
    pub fn render<F>(&self, hash: &Digest32, decrypt: F) -> Option<Vec<u8>>
    where
        F: FnOnce(&Entry, &[u8]) -> Option<Vec<u8>>,
    {
        let entry = self.get_by_hash(hash)?;
        let payload = entry.payload.as_deref()?;
        decrypt(entry, payload)
    }

    /// Verify the entire DAG: every feed's chain + signatures, given a resolver
    /// from author fingerprint to that author's composite root key. Used after a
    /// bulk import / sync to confirm convergence integrity.
    pub fn verify_all<F>(&self, mut author_key: F) -> Result<()>
    where
        F: FnMut(&Digest32) -> Option<CompositePublicKey>,
    {
        for (author, feed) in &self.feeds {
            let key = author_key(author).ok_or(Error::MalformedBundle("dag missing author key"))?;
            feed.verify()?;
            feed.verify_all_signatures(&key)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::log::entry::{EntrySkeleton, ZERO_HASH};
    use crate::log::feed::lipmaa;
    use crate::suite::algo;

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    const CHANNEL: Digest32 = [0xC0; 32];
    const EPOCH: u64 = 1;

    /// Author the next entry for `author`'s feed in `dag`, linking to whatever is
    /// already stored (so replicated entries chain correctly).
    fn next_entry(dag: &Dag, r: &SoftwareRootSigner, payload: &[u8]) -> Entry {
        let author = r.fingerprint();
        let feed = dag.feed(&author);
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
            author_id: author,
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
        Entry::build_signed(r, sk, payload.to_vec()).unwrap()
    }

    fn admission_for(authors: &[&SoftwareRootSigner]) -> AdmissionPolicy {
        let mut a = AdmissionPolicy::new();
        for r in authors {
            a.admit(CHANNEL, EPOCH, r.fingerprint());
        }
        a
    }

    #[test]
    fn accepts_admitted_authored_entries() {
        let r = root(1, 2);
        let adm = admission_for(&[&r]);
        let mut dag = Dag::new();
        for _ in 0..5 {
            let e = next_entry(&dag, &r, b"hello");
            dag.accept(e, EntryKind::Content, &r.public_key(), &adm, 0)
                .unwrap();
        }
        assert_eq!(dag.len(), 5);
        assert_eq!(dag.feed(&r.fingerprint()).unwrap().max_seq(), 5);
    }

    #[test]
    fn rejects_non_admitted_author() {
        let r = root(3, 4);
        let adm = AdmissionPolicy::new(); // nobody admitted
        let mut dag = Dag::new();
        let e = next_entry(&dag, &r, b"x");
        assert!(matches!(
            dag.accept(e, EntryKind::Content, &r.public_key(), &adm, 0),
            Err(Rejected::NotAdmitted)
        ));
        assert_eq!(dag.len(), 0);
    }

    #[test]
    fn duplicate_is_idempotent() {
        let r = root(5, 6);
        let adm = admission_for(&[&r]);
        let mut dag = Dag::new();
        let e = next_entry(&dag, &r, b"dup");
        dag.accept(e.clone(), EntryKind::Content, &r.public_key(), &adm, 0)
            .unwrap();
        assert!(matches!(
            dag.accept(e, EntryKind::Content, &r.public_key(), &adm, 0),
            Err(Rejected::Duplicate)
        ));
        assert_eq!(dag.len(), 1);
    }

    #[test]
    fn attributable_fork_freezes_author() {
        let r = root(7, 8);
        let adm = admission_for(&[&r]);
        let mut dag = Dag::new();
        // Two distinct, validly-signed entries at seq 1.
        let e1 = next_entry(&dag, &r, b"first");
        dag.accept(e1, EntryKind::Content, &r.public_key(), &adm, 0)
            .unwrap();
        // A second seq-1 entry with different content (different hash).
        let dag2_view = Dag::new();
        let e2 = next_entry(&dag2_view, &r, b"second-equivocation");
        let out = dag.accept(e2, EntryKind::Content, &r.public_key(), &adm, 0);
        match out {
            Err(Rejected::Fork(ForkOutcome::Attributable(proof))) => {
                assert_eq!(proof.author_id, r.fingerprint());
                assert_eq!(proof.seq, 1);
            }
            other => panic!("expected attributable fork, got {other:?}"),
        }
        assert!(dag.is_frozen(&r.fingerprint()));
        assert!(dag.fork_proof(&r.fingerprint()).is_some());
        // A frozen author's further (well-formed) entries are refused.
        let later = next_entry(&dag, &r, b"after-freeze");
        assert!(matches!(
            dag.accept(later, EntryKind::Content, &r.public_key(), &adm, 0),
            Err(Rejected::NotAdmitted)
        ));
    }

    #[test]
    fn governance_fork_is_always_attributable() {
        // Governance entries are always attributable regardless of authenticator
        // (ADR-008): a governance fork freezes the author.
        let r = root(9, 10);
        let adm = admission_for(&[&r]);
        let mut dag = Dag::new();
        let e1 = next_entry(&dag, &r, b"gov-a");
        dag.accept(e1, EntryKind::Governance, &r.public_key(), &adm, 0)
            .unwrap();
        let other_view = Dag::new();
        let e2 = next_entry(&other_view, &r, b"gov-b-equivocation");
        match dag.accept(e2, EntryKind::Governance, &r.public_key(), &adm, 0) {
            Err(Rejected::Fork(ForkOutcome::Attributable(_))) => {}
            other => panic!("governance fork must be attributable, got {other:?}"),
        }
        assert!(dag.is_frozen(&r.fingerprint()));
    }

    /// A stand-in M7 deniable verifier that accepts any non-empty authenticator.
    /// Lets M5 tests drive the deniable wire/fork seam without the real ADR-009
    /// crypto.
    struct AcceptAnyDeniable;
    impl DeniableVerifier for AcceptAnyDeniable {
        fn verify_deniable(&self, _: &crate::log::entry::EntrySkeleton, auth: &[u8]) -> Result<()> {
            if auth.is_empty() {
                Err(Error::SignatureInvalid)
            } else {
                Ok(())
            }
        }
    }

    /// Author the next *deniable* content entry for `r`'s feed in `dag`.
    fn next_deniable_entry(dag: &Dag, r: &SoftwareRootSigner, payload: &[u8]) -> Entry {
        let author = r.fingerprint();
        let feed = dag.feed(&author);
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
            author_id: author,
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
        // The deniable auth bytes vary by payload so two seq-1 entries differ.
        let auth = sha256(payload).to_vec();
        Entry::with_deniable_authenticator(sk, auth, Some(payload.to_vec())).unwrap()
    }

    #[test]
    fn governance_entry_must_be_attributable() {
        // A governance entry carrying a deniable authenticator is rejected outright
        // (ADR-008: governance is always composite-signed, in every channel).
        let r = root(20, 21);
        let adm = admission_for(&[&r]);
        let mut dag = Dag::new();
        let e = next_deniable_entry(&dag, &r, b"gov-deniable");
        assert!(matches!(
            dag.accept(e, EntryKind::Governance, &r.public_key(), &adm, 0),
            Err(Rejected::GovernanceNotAttributable)
        ));
        assert_eq!(dag.len(), 0);
    }

    #[test]
    fn deniable_content_fork_raises_alarm_and_does_not_freeze() {
        // The full deniable-content fork seam (ADR-009/M7): two distinct deniable
        // entries at the same (author, seq) raise a non-attributable ALARM and do
        // NOT freeze the author (auto-freeze would be a framing/DoS primitive).
        let r = root(11, 12);
        let adm = admission_for(&[&r]);
        let mut dag = Dag::new();
        let v = AcceptAnyDeniable;

        // First deniable content entry stores (verified via the M7-stub seam).
        let e1 = next_deniable_entry(&dag, &r, b"first");
        dag.accept_with_deniable(e1, EntryKind::Content, &r.public_key(), &adm, 0, Some(&v))
            .unwrap();

        // A second, different deniable entry at seq 1 (built against an empty view).
        let scratch = Dag::new();
        let e2 = next_deniable_entry(&scratch, &r, b"second-equivocation");
        match dag.accept_with_deniable(e2, EntryKind::Content, &r.public_key(), &adm, 0, Some(&v)) {
            Err(Rejected::Fork(ForkOutcome::DeniableAlarm { author_id, seq })) => {
                assert_eq!(author_id, r.fingerprint());
                assert_eq!(seq, 1);
            }
            other => panic!("expected deniable alarm, got {other:?}"),
        }
        // Crucially: NOT frozen (the proof would not incriminate a specific author).
        assert!(!dag.is_frozen(&r.fingerprint()));
    }

    #[test]
    fn deniable_content_entry_needs_m7_verifier_to_accept() {
        // Without a deniable verifier, accept() rejects a deniable content entry
        // with the honest boundary error surfaced as a verification failure.
        let r = root(13, 14);
        let adm = admission_for(&[&r]);
        let mut dag = Dag::new();
        let e = next_deniable_entry(&dag, &r, b"x");
        assert!(matches!(
            dag.accept(e, EntryKind::Content, &r.public_key(), &adm, 0),
            Err(Rejected::Verification(
                Error::DeniableVerificationUnavailable
            ))
        ));
    }

    #[test]
    fn over_quota_dropped_and_surfaced() {
        let r = root(1, 1);
        let adm = admission_for(&[&r]);
        let policy = crate::log::quota::QuotaPolicy {
            max_entries_per_hour: 2,
            max_bytes_per_epoch: u64::MAX,
        };
        let mut dag = Dag::with_quota(QuotaTracker::new(policy));
        for _ in 0..2 {
            let e = next_entry(&dag, &r, b"ok");
            dag.accept(e, EntryKind::Content, &r.public_key(), &adm, 100)
                .unwrap();
        }
        let e = next_entry(&dag, &r, b"over");
        assert!(matches!(
            dag.accept(e, EntryKind::Content, &r.public_key(), &adm, 100),
            Err(Rejected::Quota(QuotaReject::RateExceeded))
        ));
        // Dropped, not stored.
        assert_eq!(dag.len(), 2);
    }

    #[test]
    fn causal_order_is_deterministic_across_receipt_order() {
        // Two authors; insert in different orders into two DAGs; both converge to
        // the same causal order (SEC).
        let ra = root(1, 2);
        let rb = root(3, 4);
        let adm = admission_for(&[&ra, &rb]);

        let mut dag1 = Dag::new();
        let mut dag2 = Dag::new();

        // Author each author's 3 entries once (so the bytes are identical), by
        // building them against a scratch DAG per author.
        let mut scratch_a = Dag::new();
        let mut a_entries = Vec::new();
        for _ in 0..3 {
            let e = next_entry(&scratch_a, &ra, b"a");
            scratch_a
                .accept(e.clone(), EntryKind::Content, &ra.public_key(), &adm, 0)
                .unwrap();
            a_entries.push(e);
        }
        let mut scratch_b = Dag::new();
        let mut b_entries = Vec::new();
        for _ in 0..3 {
            let e = next_entry(&scratch_b, &rb, b"b");
            scratch_b
                .accept(e.clone(), EntryKind::Content, &rb.public_key(), &adm, 0)
                .unwrap();
            b_entries.push(e);
        }

        // dag1: all of A then all of B.
        for e in a_entries.iter().chain(b_entries.iter()) {
            let key = if e.skeleton.author_id == ra.fingerprint() {
                ra.public_key()
            } else {
                rb.public_key()
            };
            dag1.accept(e.clone(), EntryKind::Content, &key, &adm, 0)
                .unwrap();
        }
        // dag2: interleaved, reversed within each author requires correct linking,
        // so interleave in forward per-author order but alternate authors.
        for i in 0..3 {
            let ea = &a_entries[i];
            dag2.accept(ea.clone(), EntryKind::Content, &ra.public_key(), &adm, 0)
                .unwrap();
            let eb = &b_entries[i];
            dag2.accept(eb.clone(), EntryKind::Content, &rb.public_key(), &adm, 0)
                .unwrap();
        }

        assert_eq!(dag1.causal_order(), dag2.causal_order());
        assert_eq!(dag1.len(), 6);
        assert_eq!(dag2.len(), 6);
    }

    #[test]
    fn render_gating_decrypts_only_with_keys() {
        let r = root(2, 2);
        let adm = admission_for(&[&r]);
        let mut dag = Dag::new();
        let e = next_entry(&dag, &r, b"ciphertext-bytes");
        let hash = dag
            .accept(e, EntryKind::Content, &r.public_key(), &adm, 0)
            .unwrap();
        // Holder without keys: render returns None (store + replicate, don't render).
        assert_eq!(dag.render(&hash, |_, _| None), None);
        // Holder with keys: a successful "decrypt" renders.
        let rendered = dag.render(&hash, |_, ct| Some(ct.to_vec()));
        assert_eq!(rendered.as_deref(), Some(&b"ciphertext-bytes"[..]));
    }

    #[test]
    fn verify_all_checks_every_feed() {
        let r = root(4, 4);
        let adm = admission_for(&[&r]);
        let mut dag = Dag::new();
        for _ in 0..4 {
            let e = next_entry(&dag, &r, b"v");
            dag.accept(e, EntryKind::Content, &r.public_key(), &adm, 0)
                .unwrap();
        }
        let key = r.public_key();
        dag.verify_all(|a| {
            if *a == r.fingerprint() {
                Some(key.clone())
            } else {
                None
            }
        })
        .unwrap();
    }
}
