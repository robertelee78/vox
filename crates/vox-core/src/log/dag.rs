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
//!   links into the author's feed. There is **no rate or volume limit** on an
//!   admitted author (PRD-001 R1/R3): members are invited and trusted, and a limit
//!   here was re-applied on every reopen, so a room with more than a thousand
//!   entries from one author could not be opened at all.
//! - **Fork / equivocation handling** (ADR-008 §"Fork / equivocation handling"):
//!   two distinct entries at the same `(author, seq)` with different hashes are an
//!   equivocation. For **attributable** entries this is a self-authenticating
//!   fork proof → the author is frozen and the proof recorded. Every entry is
//!   attributable (composite-signed), so every fork is one.
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
use crate::log::entry::{Entry, EntryKind};
use crate::log::feed::Feed;

/// The set of identities admitted to a `(channelID, epoch)` — the membership
/// input to the acceptance predicate (ADR-008 §"Abuse resistance"). M5 models
/// this as an explicit input; the *population* of the set from authenticated join
/// (CPace, ADR-005/M3) and consent (ADR-007/M6) is those milestones' job. An
/// entry from an author not admitted for its `(channelID, epoch)` is rejected
/// before any DAG mutation.
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
}

/// Why an entry was not accepted into the DAG.
#[derive(Debug)]
#[non_exhaustive]
pub enum Rejected {
    /// The author is not in the admitted set for the entry's `(channel, epoch)`.
    NotAdmitted,
    /// The entry's authenticator (or author/structure) failed verification.
    Verification(Error),
    /// The entry conflicts with a stored entry at the same `(author, seq)`
    /// (equivocation); the [`ForkOutcome`] carries the proof.
    Fork(ForkOutcome),
    /// The entry did not link correctly into the author's feed (bad seq, broken
    /// `prev_hash`/`lipmaa_backlink`, append past end-of-feed).
    Feed(Error),
    /// A duplicate of an already-stored entry (same hash) — idempotently ignored.
    Duplicate,
}

/// The replicated log store: per-author feeds, a hash index, and frozen authors.
/// One [`Dag`] per channel.
#[derive(Debug, Default)]
pub struct Dag {
    /// author -> feed.
    feeds: HashMap<Digest32, Feed>,
    /// entry hash -> (author, seq), for content-addressed lookup and Negentropy.
    by_hash: HashMap<Digest32, (Digest32, u64)>,
    /// Authors frozen by an attributable fork proof; their later entries are
    /// refused (ADR-008 — members revoke/rotate to exclude the equivocator).
    frozen: HashMap<Digest32, ForkProof>,
}

impl Dag {
    /// An empty DAG.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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

    /// Drop the payload body of the stored entry `hash`, keeping its signed skeleton
    /// (ADR-010 retention). A peer that asks for it afterwards is served the skeleton.
    /// Returns whether a body was dropped.
    pub fn prune_payload(&mut self, hash: &Digest32) -> bool {
        let Some((author, seq)) = self.by_hash.get(hash).copied() else {
            return false;
        };
        self.feeds
            .get_mut(&author)
            .is_some_and(|f| f.prune_payload(seq))
    }

    /// Whether an entry with this hash is stored.
    #[must_use]
    pub fn contains(&self, hash: &Digest32) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Accept an entry into the DAG, enforcing the full ADR-008 predicate.
    ///
    /// Steps, in order (any failure leaves the DAG unchanged):
    /// 0. Governance entries must carry an attributable (composite)
    ///    authenticator → otherwise [`Rejected::GovernanceNotAttributable`].
    /// 1. If the author is frozen, refuse ([`Rejected::Fork`] with the recorded
    ///    proof is *not* re-raised; later entries from a frozen author are simply
    ///    refused via [`Rejected::NotAdmitted`]).
    /// 2. Duplicate (same hash already stored) → [`Rejected::Duplicate`]
    ///    (idempotent replication).
    /// 3. Admission: author ∈ admitted set for `(channel, epoch)`.
    /// 4. Authenticator + structure verify under `author_root`.
    /// 5. Equivocation: a different entry already occupies `(author, seq)` →
    ///    [`Rejected::Fork`]; for an attributable entry the author is frozen.
    /// 6. Feed link: `seq`/`prev_hash`/`lipmaa_backlink`/end-of-feed.
    ///
    /// Equivocation is classified **only after** admission and verification
    /// (steps 3–4 precede 5). An ADR-008 fork proof must be *self-authenticating*;
    /// classifying first would let a peer holding *no* valid key surface fork
    /// proofs — a framing / attention-DoS primitive
    /// (2026-09-19 review, HIGH). A conflicting entry that is unadmitted or fails
    /// verification is therefore rejected as [`Rejected::NotAdmitted`] /
    /// [`Rejected::Verification`], never as a fork.
    ///
    /// `kind` is the entry's classification. The DAG no longer branches on it — every
    /// entry is composite-signed since deniable rooms were removed — but callers already
    /// classify each entry, and keeping the argument keeps that classification at the
    /// seam where a future per-kind rule would go.
    pub fn accept(
        &mut self,
        entry: Entry,
        kind: EntryKind,
        author_root: &CompositePublicKey,
        admission: &AdmissionPolicy,
    ) -> std::result::Result<Digest32, Rejected> {
        let _ = kind;
        let author = entry.skeleton.author_id;
        let seq = entry.skeleton.seq;
        let channel = entry.skeleton.channel_id;
        let epoch = entry.skeleton.epoch;
        let hash = entry.entry_hash();

        // A frozen author's further entries are refused outright.
        if self.frozen.contains_key(&author) {
            return Err(Rejected::NotAdmitted);
        }

        // Idempotent duplicate.
        if self.by_hash.contains_key(&hash) {
            return Err(Rejected::Duplicate);
        }

        // Admission.
        if !admission.is_admitted(&channel, epoch, &author) {
            return Err(Rejected::NotAdmitted);
        }

        // Authenticator + structure. This precedes equivocation classification on
        // purpose: only an entry that is admitted AND authenticates may surface a
        // fork proof.
        entry.verify(author_root).map_err(Rejected::Verification)?;

        // Equivocation: a *different* entry already occupies (author, seq)?
        if let Some(feed) = self.feeds.get(&author) {
            if let Some(existing) = feed.get(seq) {
                // Same seq, different hash (duplicate handled above) ⇒ a fork.
                let outcome = self.classify_fork(existing.clone(), entry);
                let ForkOutcome::Attributable(ref proof) = outcome;
                // `conflicting` verified just above. `existing` was verified
                // when it was accepted (only this path stores entries); the
                // re-check is an invariant guard so the recorded proof is
                // self-authenticating regardless of how `existing` arrived.
                if existing.verify(author_root).is_ok() {
                    self.frozen.insert(author, (**proof).clone());
                }
                return Err(Rejected::Fork(outcome));
            }
        }

        // Feed link: `append` validates seq/prev_hash/lipmaa_backlink/end-of-feed
        // and leaves the feed untouched on a rejection. Then index by hash.
        self.feeds
            .entry(author)
            .or_default()
            .append(entry)
            .map_err(Rejected::Feed)?;
        self.by_hash.insert(hash, (author, seq));
        Ok(hash)
    }

    /// Build the fork proof for a `(author, seq)` conflict (ADR-008 §"Fork /
    /// equivocation handling"). Every entry is composite-signed, so a conflict
    /// between two that both verified is always a self-authenticating proof.
    fn classify_fork(&self, existing: Entry, conflicting: Entry) -> ForkOutcome {
        ForkOutcome::Attributable(Box::new(ForkProof {
            author_id: conflicting.skeleton.author_id,
            seq: conflicting.skeleton.seq,
            existing,
            conflicting,
        }))
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
