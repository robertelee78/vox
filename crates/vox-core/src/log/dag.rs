//! The cross-author causal Merkle-DAG (ADR-008 §Decision) — a CRDT for causal
//! histories.
//!
//! ## Causality model (ADR-008 as amended by ADR-023 decision 1)
//! - **Within one author** the feed is a *total order*: `seq` is strictly
//!   monotonic and each entry hash-links its predecessors (`prev_hash` = seq−1,
//!   `lipmaa_backlink` = the Bamboo skip predecessor). Entry *n* causally
//!   precedes *n+1* of the same author.
//! - **Across authors** an entry's `seen` names the heads of other authors' feeds
//!   its author had applied when writing it. Those are real happens-before edges:
//!   an entry follows everything it saw, and everything those saw. Two entries
//!   neither of which reaches the other are **concurrent**.
//! - **Merge = union.** The DAG is the set union of all per-author feeds. The edges
//!   are signed into each entry, so the same entry set is the same graph on every
//!   replica, whatever order it arrived in — Strong Eventual Consistency.
//!
//! ## The one order (PRD-001 R13)
//! Every entry gets a **hybrid logical clock**:
//!
//! ```text
//! clock(e) = max( claimed_ms(e), clock(p) + 1 for every parent p this node holds )
//! parents(e) = { e's own seq−1 } ∪ seen(e)
//! ```
//!
//! and the order is ascending `(clock, entry_hash)`. A parent's clock is strictly
//! below its child's, so this is a topological order of the DAG; among concurrent
//! entries it is the authors' claimed milliseconds, then the hash. It is a function
//! of the entry set alone, so every node holding the same entries computes the
//! identical sequence. An author's clock can move its entry only among its concurrent
//! peers: an entry written an hour "early" is still lifted to just after the newest
//! thing it saw. A clock running ahead drags everything that later sees the entry
//! along with it — which reorders nothing that entry did not already precede.
//!
//! **A `seen` hash this node does not hold never blocks acceptance.** Entries arrive
//! out of order (a member was offline, a sync session died half-way), and refusing
//! an entry until its parents arrive would let one lost entry stall a room. The
//! missing parent simply contributes nothing yet; when it arrives, the clocks of
//! everything that named it are raised and propagated to their descendants
//! ([`Dag::reorder_generation`] counts those moves, so a timeline knows to re-sort).
//! Because a clock only ever rises to what the full set requires, the result is the
//! same as if everything had arrived in causal order.
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

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::log::entry::{Entry, EntryKind, MAX_SEEN};
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
    /// entry hash -> its hybrid logical clock (module docs).
    clock: HashMap<Digest32, u64>,
    /// Every stored entry keyed `(clock, entry_hash)`: iterating it **is** the order.
    ordered: BTreeSet<(u64, Digest32)>,
    /// hash -> the stored entries whose `seen` names it. Kept for hashes not held
    /// yet too: that is how a late parent finds the children it has to lift.
    seen_by: HashMap<Digest32, Vec<Digest32>>,
    /// `(author, other author)` -> the highest seq of `other` that one of `author`'s
    /// entries names in its `seen`. What [`Dag::seen_for`] need not name again.
    referenced: HashMap<(Digest32, Digest32), u64>,
    /// Bumped whenever an already-stored entry's clock moves (a late parent arrived),
    /// so a timeline can tell a re-sort is due without recomputing anything.
    reorder_generation: u64,
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
        self.place(hash);
        Ok(hash)
    }

    /// Give a just-stored entry its clock, record its `seen` edges, and lift every
    /// stored entry that was waiting for it (module docs, "The one order").
    fn place(&mut self, hash: Digest32) {
        let Some(entry) = self.get_by_hash(&hash) else {
            return;
        };
        let author = entry.skeleton.author_id;
        let seq = entry.skeleton.seq;
        let seen = entry.skeleton.seen.clone();
        let mut clock = entry.skeleton.claimed_ms;
        if seq > 1 {
            // Feeds are contiguous, so the own predecessor is always held.
            if let Some(c) = self.clock.get(&entry.skeleton.prev_hash) {
                clock = clock.max(c.saturating_add(1));
            }
        }
        for parent in &seen {
            if let Some(c) = self.clock.get(parent) {
                clock = clock.max(c.saturating_add(1));
            }
            if let Some((other, other_seq)) = self.by_hash.get(parent).copied() {
                let r = self.referenced.entry((author, other)).or_insert(0);
                *r = (*r).max(other_seq);
            }
            self.seen_by.entry(*parent).or_default().push(hash);
        }
        self.clock.insert(hash, clock);
        self.ordered.insert((clock, hash));

        // Children that named this entry before it arrived.
        let waiting = self.seen_by.get(&hash).cloned().unwrap_or_default();
        for child in &waiting {
            if let Some((child_author, _)) = self.by_hash.get(child).copied() {
                let r = self.referenced.entry((child_author, author)).or_insert(0);
                *r = (*r).max(seq);
            }
        }
        let mut work: Vec<(Digest32, u64)> = waiting
            .into_iter()
            .map(|c| (c, clock.saturating_add(1)))
            .collect();
        while let Some((h, floor)) = work.pop() {
            let Some(old) = self.clock.get(&h).copied() else {
                continue;
            };
            if old >= floor {
                continue;
            }
            self.ordered.remove(&(old, h));
            self.ordered.insert((floor, h));
            self.clock.insert(h, floor);
            self.reorder_generation = self.reorder_generation.wrapping_add(1);
            let next = floor.saturating_add(1);
            if let Some((a, s)) = self.by_hash.get(&h).copied() {
                if let Some(succ) = self.feeds.get(&a).and_then(|f| f.get(s + 1)) {
                    work.push((succ.entry_hash(), next));
                }
            }
            if let Some(children) = self.seen_by.get(&h) {
                work.extend(children.iter().map(|c| (*c, next)));
            }
        }
    }

    /// What an entry `author` writes now should list in `seen`: the head of every
    /// other author's feed that none of `author`'s entries has named yet, at most
    /// [`MAX_SEEN`], in canonical (ascending) order.
    ///
    /// A head `author` already named — or an older entry of that feed — is left out:
    /// `author`'s own previous entry already follows it, and the feed chain carries
    /// the rest. When more than [`MAX_SEEN`] feeds moved, the most recent by the order
    /// are named; the others stay unnamed and are picked up by the next entry, so
    /// nothing is lost, only deferred.
    #[must_use]
    pub fn seen_for(&self, author: &Digest32) -> Vec<Digest32> {
        let mut heads: Vec<(u64, Digest32)> = self
            .feeds
            .iter()
            .filter(|(other, _)| *other != author)
            .filter_map(|(other, feed)| {
                let head = feed.max_seq();
                let named = self
                    .referenced
                    .get(&(*author, *other))
                    .copied()
                    .unwrap_or(0);
                if head == 0 || head <= named {
                    return None;
                }
                let h = feed.get(head)?.entry_hash();
                Some((self.clock.get(&h).copied().unwrap_or(0), h))
            })
            .collect();
        heads.sort_unstable_by(|a, b| b.cmp(a));
        heads.truncate(MAX_SEEN);
        let mut seen: Vec<Digest32> = heads.into_iter().map(|(_, h)| h).collect();
        seen.sort_unstable();
        seen
    }

    /// The entry's position key in [`Dag::causal_order`]: `(clock, entry_hash)`.
    /// Comparing two keys compares the two entries' places in the room's order.
    #[must_use]
    pub fn order_key(&self, hash: &Digest32) -> Option<(u64, Digest32)> {
        self.clock.get(hash).map(|c| (*c, *hash))
    }

    /// How many times an already-stored entry has moved in the order (a parent it
    /// named arrived after it). A consumer that keeps its own sorted copy re-sorts
    /// when this changes.
    #[must_use]
    pub fn reorder_generation(&self) -> u64 {
        self.reorder_generation
    }

    /// Whether `a` **happened before** `b`: `a` is a proper causal ancestor of `b`
    /// through `b`'s own feed and the `seen` edges, as far as this node holds them.
    ///
    /// This is the relation claims are to be built on (PRD-001 R17, ADR-020): a claim
    /// that saw another claim follows it. `false` means concurrent **or** not yet
    /// known to be ordered — `a` may be an ancestor through an entry this node has not
    /// received. Neither entry held is `false`.
    #[must_use]
    pub fn happened_before(&self, a: &Digest32, b: &Digest32) -> bool {
        let (Some(ca), Some(cb)) = (self.clock.get(a).copied(), self.clock.get(b).copied()) else {
            return false;
        };
        // An ancestor's clock is strictly below its descendant's.
        if ca >= cb {
            return false;
        }
        let Some((a_author, a_seq)) = self.by_hash.get(a).copied() else {
            return false;
        };
        let mut visited: HashSet<Digest32> = HashSet::new();
        let mut stack = vec![*b];
        while let Some(h) = stack.pop() {
            if !visited.insert(h) {
                continue;
            }
            let Some(entry) = self.get_by_hash(&h) else {
                continue;
            };
            let sk = &entry.skeleton;
            // Reaching `a`'s feed at or past `a` means `a` precedes it on that chain.
            if h != *b && sk.author_id == a_author && sk.seq >= a_seq {
                return true;
            }
            if h == *b && sk.author_id == a_author {
                return sk.seq > a_seq;
            }
            let parents = sk
                .seen
                .iter()
                .copied()
                .chain((sk.seq > 1).then_some(sk.prev_hash));
            for p in parents {
                // Anything at or below `a`'s clock cannot have `a` as an ancestor
                // (unless it is `a`, which the feed check above catches).
                if p == *a {
                    return true;
                }
                if self.clock.get(&p).is_some_and(|c| *c > ca) {
                    stack.push(p);
                }
            }
        }
        false
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

    /// The room's one order (PRD-001 R13): every stored entry, ascending by
    /// `(clock, entry_hash)` — a topological order of the DAG whose ties between
    /// concurrent entries fall to the authors' claimed milliseconds, then the hash
    /// (module docs). Identical on every replica holding the same entry set.
    #[must_use]
    pub fn causal_order(&self) -> Vec<Digest32> {
        self.ordered.iter().map(|(_, h)| *h).collect()
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
