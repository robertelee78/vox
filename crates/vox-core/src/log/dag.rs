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
//! latest(e)  = max clock(p) over the parents p this node holds (or the room's genesis time)
//! clock(e)   = max( min(claimed_ms(e), latest(e) + MAX_LEAD_MS), latest(e) + 1 )
//! parents(e) = { e's own seq−1 } ∪ seen(e)
//! ```
//!
//! and the order is ascending `(clock, entry_hash)`. A parent's clock is strictly
//! below its child's, so this is a topological order of the DAG; among concurrent
//! entries it is the authors' claimed milliseconds, then the hash. It is a function
//! of the entry set alone, so every node holding the same entries computes the
//! identical sequence. An author's clock can move its entry only among its concurrent
//! peers: an entry written an hour "early" is still lifted to just after the newest
//! thing it saw. A clock running *ahead* is capped at [`MAX_LEAD_MS`] past the
//! entry's latest parent, so one member cannot drag everyone's clocks into the future.
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

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::log::checkpoint::Checkpoint;
use crate::log::entry::{Entry, EntryKind, EntryRead, EntryWrite, MAX_SEEN};

/// How far an entry's claimed time may run ahead of the latest entry it names (or of the room's
/// genesis, if it names none) before it is capped: ten minutes.
///
/// Without a cap one member could pin everyone's clocks forward: an entry claiming "tomorrow"
/// lifts every entry that later sees it to tomorrow too, and everything concurrent with those
/// then sorts before them for a day. The cap is computed from the entry's parents, never from
/// the receiving node's clock, because a cap on "now" would differ between nodes and so would the
/// order. With it, one post can move the room's clocks at most ten minutes, and moving them a day
/// takes 144 posts, each visible and attributable.
///
/// Why ten minutes: honest clocks without time sync drift by seconds to a few minutes, so an
/// honest entry is almost never capped; when it is (after a quiet spell of more than ten
/// minutes), capping moves it only among entries it did not see, which is all the claimed time
/// is ever used for. A larger bound would be a larger lever for a dishonest one.
pub const MAX_LEAD_MS: u64 = 10 * 60 * 1_000;
use crate::log::feed::{Feed, FeedError};

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
    /// The author was frozen by an attributable fork proof; its further entries are refused.
    /// Split from [`Rejected::NotAdmitted`] (ADR-025 D3): sync classifies the two differently, and
    /// a frozen author's position counts as filled where an unadmitted one's does not.
    Frozen,
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
    /// A local encrypted index/log read or write failed. Never a peer authenticator failure.
    Local(Error),
    /// A position at or below its author's checkpoint that this node does not hold as
    /// this entry (ADR-023 decision 3). Refused, never classified as a fork: below the line
    /// the body is expired, so it could never be shown, and a fork proof would need the
    /// very signature the checkpoint lets nodes drop.
    PreCheckpoint,
}

/// Compact state for one already authenticated, durably published feed prefix.
/// Never serialize a staging DAG head: it can be ahead of the committed root switch.
#[derive(Clone, Debug, Default)]
pub(crate) struct PublishedFeed {
    pub seq: u64,
    pub hash: Digest32,
    pub first_claimed_ms: u64,
    pub ended: bool,
    pub checkpoint: Option<(u64, Digest32)>,
    pub swept_to: u64,
}

/// The replicated log store: per-author feeds, a hash index, and frozen authors.
/// One [`Dag`] per channel.
#[derive(Debug, Default)]
pub struct Dag {
    /// author -> feed.
    feeds: HashMap<Digest32, Feed>,
    /// Authors frozen by an attributable fork proof; their later entries are
    /// refused (ADR-008 — members revoke/rotate to exclude the equivocator).
    frozen: HashMap<Digest32, ForkProof>,
    /// author -> the highest checkpoint its own signed feed carries: `(seq, entry_hash)`
    /// (ADR-023 decision 3).
    checkpoints: HashMap<Digest32, (u64, Digest32)>,
    /// author -> the lowest seq of the run of **unsigned** entries at the top of its feed:
    /// skeletons that arrived with their signature dropped and have no signed successor
    /// yet. They are authentic only once one arrives; [`Dag::discard_unverified`] takes
    /// back whatever never is.
    unverified_from: HashMap<Digest32, u64>,
    /// author -> the seq through which [`Dag::drop_checkpointed_signatures`] has looked, so
    /// each checkpoint's range is walked once. An entry there that still had its body is
    /// handled when it is pruned ([`Dag::drop_signature_if_checkpointed`]).
    swept_to: HashMap<Digest32, u64>,
    /// Bumped whenever an already-stored entry's clock moves (a late parent arrived),
    /// so a timeline can tell a re-sort is due without recomputing anything.
    reorder_generation: u64,
    /// One published tail clock, refreshed with the durable order revision.
    newest_clock: Option<u64>,
    /// Body presence changed without replacing a signed skeleton. Display projections must
    /// notice this even if the caller's later persistence or rendering step fails.
    body_generation: u64,
    /// How many entries this node has refused as at or below their author's checkpoint since
    /// it loaded the room. Counted so the refusal can be *seen*: from outside it looks exactly
    /// like a fork whose held side cannot incriminate (both are dropped and the session goes
    /// on), and a gate that can only watch for a freeze cannot tell the two apart.
    refused_below_checkpoint: u64,
    /// Entries held without their body whose body has since arrived and been put back
    /// ([`Dag::fill_body`], V030-10), for the caller to store and render; taken by
    /// [`Dag::take_filled`].
    filled: Vec<Digest32>,
    /// Authors whose feed is closed here from a position on, because the entry they signed there
    /// could not be classified (V210-74): nothing from that position on is taken, and it is not
    /// asked for again. Kept in memory only; after a restart the entry is refused again on sight.
    refused: HashMap<Digest32, u64>,
}

impl Dag {
    /// An empty DAG.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty room DAG. The durable entry index owns the genesis time used to cap
    /// root clocks; it publishes those facts atomically with each accepted prefix.
    #[must_use]
    pub fn for_room(_origin_ms: u64) -> Self {
        Self::default()
    }

    /// Bootstrap only after the complete historical acceptance pass has discarded all
    /// unverified tails. Live publication derives each changed author from its own witness.
    pub(crate) fn published_feeds(&self) -> Result<BTreeMap<Digest32, PublishedFeed>> {
        if !self.unverified_from.is_empty() {
            return Err(Error::MalformedAtRest("unverified feed in restart state"));
        }
        Ok(self
            .feeds
            .iter()
            .filter(|(_, feed)| !feed.is_empty())
            .map(|(author, feed)| {
                (
                    *author,
                    PublishedFeed {
                        seq: feed.max_seq(),
                        hash: feed.head_hash(),
                        first_claimed_ms: feed.first_claimed_ms().unwrap_or(0),
                        ended: feed.ended(),
                        checkpoint: self.checkpoints.get(author).copied(),
                        swept_to: self.swept_to.get(author).copied().unwrap_or(0),
                    },
                )
            })
            .collect())
    }

    /// Restore sealed accepted metadata. Head/source authentication is checked by the room
    /// loader; incoming entries still pass the unchanged acceptance predicate.
    pub(crate) fn restore_published(feeds: &BTreeMap<Digest32, PublishedFeed>) -> Result<Self> {
        let mut dag = Self::new();
        for (author, state) in feeds {
            dag.feeds.insert(
                *author,
                Feed::restore_published(
                    *author,
                    state.seq,
                    state.hash,
                    state.first_claimed_ms,
                    state.ended,
                )?,
            );
            if let Some(checkpoint) = state.checkpoint {
                if checkpoint.0 == 0 || checkpoint.0 >= state.seq || state.swept_to > checkpoint.0 {
                    return Err(Error::MalformedAtRest("published checkpoint bound"));
                }
                dag.checkpoints.insert(*author, checkpoint);
            } else if state.swept_to != 0 {
                return Err(Error::MalformedAtRest("sweep without checkpoint"));
            }
            dag.swept_to.insert(*author, state.swept_to);
        }
        Ok(dag)
    }

    /// Apply one compact state only after the matching header-only Feed validation and
    /// sealed restart update commit. This never invents a prefix from a sparse tip.
    pub(crate) fn restore_contiguous_author(
        &mut self,
        author: Digest32,
        state: &PublishedFeed,
    ) -> Result<()> {
        let feed = Feed::restore_published(
            author,
            state.seq,
            state.hash,
            state.first_claimed_ms,
            state.ended,
        )?;
        if self
            .feeds
            .get(&author)
            .is_some_and(|old| old.max_seq() > state.seq)
        {
            return Err(Error::MalformedAtRest(
                "contiguous author state moved backwards",
            ));
        }
        self.feeds.insert(author, feed);
        Ok(())
    }

    /// Restore only sealed local staging metadata for one explicit legacy request. Every
    /// staged row already passed admission and contiguous/skip linkage when it was written;
    /// this avoids replaying that unsigned suffix on each explicit Resume. It is not accepted
    /// history: `verified_head` remains at `base`, and ordinary frontiers must use that boundary.
    // The exact sealed base and tail scalars are checked together; no history is loaded.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore_legacy_provisional(
        &mut self,
        author: Digest32,
        base: u64,
        base_hash: Digest32,
        tail: u64,
        tail_hash: Digest32,
        first_claimed_ms: u64,
        ended: bool,
    ) -> Result<()> {
        let current = self.feeds.get(&author);
        if self.unverified_from.contains_key(&author)
            || current.map_or(0, Feed::max_seq) != base
            || current.map_or(crate::log::entry::ZERO_HASH, Feed::head_hash) != base_hash
            || tail < base
            || tail > crate::log::feed::MAX_SEQ
        {
            return Err(Error::MalformedAtRest("legacy provisional base differs"));
        }
        if tail > base {
            self.feeds.insert(
                author,
                Feed::restore_published(author, tail, tail_hash, first_claimed_ms, ended)?,
            );
            self.unverified_from.insert(author, base + 1);
        }
        Ok(())
    }

    /// Detach an exact request's volatile suffix without deleting its sealed spool. The
    /// caller obtains `base` from the current accepted restart root, never a peer's claim.
    pub(crate) fn detach_legacy_provisional(
        &mut self,
        author: Digest32,
        base: u64,
        base_hash: Digest32,
        first_claimed_ms: u64,
        ended: bool,
    ) -> Result<()> {
        if base == 0 {
            self.feeds.remove(&author);
        } else {
            self.feeds.insert(
                author,
                Feed::restore_published(author, base, base_hash, first_claimed_ms, ended)?,
            );
        }
        self.unverified_from.remove(&author);
        Ok(())
    }

    pub(crate) fn restore_legacy_accepted(
        &mut self,
        author: Digest32,
        state: &PublishedFeed,
    ) -> Result<()> {
        self.detach_legacy_provisional(
            author,
            state.seq,
            state.hash,
            state.first_claimed_ms,
            state.ended,
        )?;
        match state.checkpoint {
            Some(checkpoint) => {
                self.checkpoints.insert(author, checkpoint);
            }
            None => {
                self.checkpoints.remove(&author);
            }
        }
        self.swept_to.insert(author, state.swept_to);
        Ok(())
    }

    pub(crate) fn swept_positions(&self) -> impl Iterator<Item = (&Digest32, &u64)> {
        self.swept_to.iter()
    }

    /// The number of entries stored across all authors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.feeds
            .values()
            .fold(0usize, |n, feed| n.saturating_add(feed.len()))
    }

    /// Whether the DAG holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.feeds.values().all(Feed::is_empty)
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

    /// Every author frozen by a fork proof, sorted.
    #[must_use]
    pub fn frozen_authors(&self) -> Vec<Digest32> {
        let mut a: Vec<Digest32> = self.frozen.keys().copied().collect();
        a.sort_unstable();
        a
    }

    /// How many entries were refused as at or below their author's checkpoint since this
    /// DAG was built (ADR-023 decision 3).
    #[must_use]
    pub fn refused_below_checkpoint(&self) -> u64 {
        self.refused_below_checkpoint
    }

    /// The position from which `author`'s feed is closed here, if it is (see [`Dag::refuse_from`]).
    #[must_use]
    pub fn refused_from(&self, author: &Digest32) -> Option<u64> {
        self.refused.get(author).copied()
    }

    /// Close `author`'s feed here from `seq` on: the entry the author signed at `seq` could not be
    /// classified, so it is never held, and nothing after it can link (V210-74).
    pub fn refuse_from(&mut self, author: Digest32, seq: u64) {
        let at = self.refused.entry(author).or_insert(seq);
        *at = (*at).min(seq);
    }

    /// The recorded fork proof for a frozen author, if any.
    #[must_use]
    pub fn fork_proof(&self, author: &Digest32) -> Option<&ForkProof> {
        self.frozen.get(author)
    }

    /// Every recorded fork proof, in author order: what a node says about equivocation, and
    /// what it keeps so a restart does not forget it (V210-63).
    #[must_use]
    pub fn fork_proofs(&self) -> Vec<&ForkProof> {
        let mut proofs: Vec<&ForkProof> = self.frozen.values().collect();
        proofs.sort_unstable_by_key(|p| p.author_id);
        proofs
    }

    /// Freeze an author again from a fork proof this node kept (V210-63): after a restart the
    /// DAG is rebuilt from the stored entries, which hold only one side of the fork.
    ///
    /// **The proof is checked, not trusted**, as a new one would be: both entries by
    /// `proof.author_id` at `proof.seq`, different, still signed, and each verified against
    /// `author_root`. Anything else is refused and freezes nothing.
    ///
    /// # Errors
    /// [`Rejected::Verification`] if the pair is not a proof or either entry fails to verify.
    pub fn restore_fork(
        &mut self,
        proof: ForkProof,
        author_root: &CompositePublicKey,
    ) -> std::result::Result<(), Rejected> {
        let same_place =
            |e: &Entry| e.skeleton.author_id == proof.author_id && e.skeleton.seq == proof.seq;
        if !same_place(&proof.existing)
            || !same_place(&proof.conflicting)
            || proof.existing.entry_hash() == proof.conflicting.entry_hash()
            || !proof.existing.is_signed()
            || !proof.conflicting.is_signed()
        {
            return Err(Rejected::Verification(Error::MalformedBundle(
                "kept fork proof is not two different signed entries at one place",
            )));
        }
        proof
            .existing
            .verify(author_root)
            .map_err(Rejected::Verification)?;
        proof
            .conflicting
            .verify(author_root)
            .map_err(Rejected::Verification)?;
        self.frozen.insert(proof.author_id, proof);
        Ok(())
    }

    /// Look up a stored entry by its 32-byte hash (the Negentropy key).
    pub fn get_by_hash(&self, entries: &impl EntryRead, hash: &Digest32) -> Result<Option<Entry>> {
        // A sparse source is separately evidence-validated and atomically published. It
        // does not become a contiguous Feed merely to be available to local consumers.
        if let Some(entry) = entries.get_sparse_published(hash)? {
            return Ok(Some(entry));
        }
        let Some((author, seq)) = entries.locate(hash)? else {
            return Ok(None);
        };
        let Some(feed) = self.feeds.get(&author) else {
            return Ok(None);
        };
        let entry = feed.get(entries, seq)?;
        if entry.as_ref().is_some_and(|e| e.entry_hash() != *hash) {
            return Err(Error::MalformedAtRest("DAG locator hash differs"));
        }
        Ok(entry)
    }

    fn position(
        &self,
        entries: &impl EntryRead,
        hash: &Digest32,
    ) -> Result<Option<(Digest32, u64)>> {
        Ok(entries.locate(hash)?.filter(|(author, seq)| {
            self.feeds
                .get(author)
                .is_some_and(|f| *seq != 0 && *seq <= f.max_seq())
        }))
    }

    /// Drop the payload body of the stored entry `hash`, keeping its signed skeleton
    /// (ADR-010 retention). A peer that asks for it afterwards is served the skeleton.
    /// Returns whether a body was dropped.
    pub fn prune_payload(
        &mut self,
        entries: &mut impl EntryWrite,
        hash: &Digest32,
    ) -> Result<bool> {
        let Some((author, seq)) = self.position(entries, hash)? else {
            return Ok(false);
        };
        let dropped = self
            .feeds
            .get_mut(&author)
            .ok_or(Error::MalformedAtRest("DAG feed missing"))?
            .prune_payload(entries, seq)?;
        if dropped {
            self.body_generation = self.body_generation.wrapping_add(1);
        }
        Ok(dropped)
    }

    /// **A body that arrives for a skeleton held without one is put back** (V030-10). A skeleton
    /// is taken whenever it verifies, so an author's feed never stops at a body a peer did not
    /// send; the body stays owed, and when any peer serves it — the payload the skeleton commits
    /// to, by hash and length — it is the entry's again. A checkpoint that arrives this way is
    /// read as one arriving whole would be. Returns whether a body was put back.
    pub fn fill_body(&mut self, entries: &mut impl EntryWrite, entry: &Entry) -> Result<bool> {
        let Some(payload) = entry.payload.as_ref() else {
            return Ok(false);
        };
        if entry.verify_payload_binding().is_err() {
            return Ok(false);
        }
        let hash = entry.entry_hash();
        let Some((author, seq)) = self.position(entries, &hash)? else {
            return Ok(false);
        };
        let feed = self
            .feeds
            .get_mut(&author)
            .ok_or(Error::MalformedAtRest("DAG feed missing"))?;
        if !feed.restore_payload(entries, seq, payload.clone())? {
            return Ok(false);
        }
        let signed = feed.get(entries, seq)?.is_some_and(|e| e.is_signed());
        if let Some(cp) = Checkpoint::from_payload(payload)
            .ok()
            .flatten()
            .filter(|_| signed)
        {
            let names = feed.get(entries, cp.seq)?.map(|e| e.entry_hash()) == Some(cp.entry_hash);
            if cp.seq < seq && names {
                let held = self.checkpoints.entry(author).or_insert((0, cp.entry_hash));
                if cp.seq > held.0 {
                    *held = (cp.seq, cp.entry_hash);
                }
            }
        }
        self.filled.push(hash);
        self.body_generation = self.body_generation.wrapping_add(1);
        Ok(true)
    }

    /// Revision of existing entries' body presence, independent of durable sync credit.
    pub(crate) fn body_generation(&self) -> u64 {
        self.body_generation
    }

    /// The entries whose body [`Dag::fill_body`] put back since the last call.
    pub fn take_filled(&mut self) -> Vec<Digest32> {
        std::mem::take(&mut self.filled)
    }

    /// Whether an entry with this hash is stored.
    pub fn contains(&self, entries: &impl EntryRead, hash: &Digest32) -> Result<bool> {
        Ok(self.position(entries, hash)?.is_some())
    }

    /// Accept an entry into the DAG, enforcing the full ADR-008 predicate.
    ///
    /// Steps, in order (any failure leaves the DAG unchanged):
    /// 1. If the author is frozen, refuse ([`Rejected::Fork`] with the recorded
    ///    proof is *not* re-raised; later entries from a frozen author are simply
    ///    refused via [`Rejected::Frozen`]).
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
        entries: &mut impl EntryWrite,
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
            return Err(Rejected::Frozen);
        }

        // Idempotent duplicate.
        if self.contains(entries, &hash).map_err(Rejected::Local)? {
            return Err(Rejected::Duplicate);
        }

        // Below its author's checkpoint, nothing new is taken: every position there is
        // already held (the feed is contiguous), so a different entry for one is refused as
        // pre-checkpoint — not raised as a fork.
        if entry.skeleton.v2.is_none()
            && self
                .checkpoints
                .get(&author)
                .is_some_and(|(below, _)| seq <= *below)
        {
            self.refused_below_checkpoint = self.refused_below_checkpoint.saturating_add(1);
            return Err(Rejected::PreCheckpoint);
        }

        // Admission.
        if !admission.is_admitted(&channel, epoch, &author) {
            return Err(Rejected::NotAdmitted);
        }

        // Authenticator + structure. This precedes equivocation classification on
        // purpose: only an entry that is admitted AND authenticates may surface a
        // fork proof.
        //
        // A skeleton whose signature was dropped under a checkpoint cannot verify on its own.
        // It is taken provisionally, body-less only, and becomes authentic when a signed
        // entry of the same feed chains to it (module docs, "Checkpoints").
        let signed = entry.is_signed();
        if signed {
            entry.verify(author_root).map_err(Rejected::Verification)?;
        } else if entry.payload.is_some() {
            return Err(Rejected::Verification(Error::MalformedBundle(
                "an unsigned log entry must carry no body",
            )));
        }

        // Equivocation: a *different* entry already occupies (author, seq)?
        if let Some(feed) = self.feeds.get(&author) {
            if let Some(existing) = feed.get(entries, seq).map_err(Rejected::Local)? {
                // An unsigned entry proves nothing: it can conflict, never incriminate.
                if !signed {
                    return Err(Rejected::Verification(Error::MalformedBundle(
                        "an unsigned log entry conflicts with a held one",
                    )));
                }
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

        // A checkpoint must name its own feed truthfully: a position below this entry,
        // with the hash this node holds there.
        let checkpoint = match entry.payload.as_deref() {
            Some(p) if signed => Checkpoint::from_payload(p).map_err(Rejected::Verification)?,
            _ => None,
        };
        if let Some(cp) = checkpoint {
            let named = match self.feeds.get(&author) {
                Some(feed) => feed.get(entries, cp.seq).map_err(Rejected::Local)?,
                None => None,
            };
            if cp.seq >= seq || named.map(|e| e.entry_hash()) != Some(cp.entry_hash) {
                return Err(Rejected::Verification(Error::MalformedBundle(
                    "checkpoint names a position its own feed does not hold",
                )));
            }
        }

        // Feed link: `append` validates seq/prev_hash/lipmaa_backlink/end-of-feed
        // and leaves the feed untouched on a rejection. Then index by hash.
        self.feeds
            .entry(author)
            .or_default()
            .append(entries, &entry)
            .map_err(|e| match e {
                FeedError::Invalid(e) => Rejected::Feed(e),
                FeedError::Local(e) => Rejected::Local(e),
            })?;
        if signed {
            // Chains every unsigned entry below it to a signature.
            self.unverified_from.remove(&author);
        } else {
            self.unverified_from.entry(author).or_insert(seq);
        }
        if let Some(cp) = checkpoint.filter(|_| entry.skeleton.v2.is_none()) {
            let held = self.checkpoints.entry(author).or_insert((0, cp.entry_hash));
            if cp.seq > held.0 {
                *held = (cp.seq, cp.entry_hash);
            }
        }
        Ok(hash)
    }

    /// Take back every unsigned skeleton no signed entry has chained to (ADR-023 decision
    /// 3): what a sync session or a reload leaves provisional at its end. They are not
    /// authentic, and keeping them would block the real entries at those positions.
    /// Returns how many were removed.
    pub fn discard_unverified(&mut self, entries: &mut impl EntryWrite) -> Result<usize> {
        let mut removed = 0usize;
        for (author, from) in std::mem::take(&mut self.unverified_from) {
            let Some(feed) = self.feeds.get_mut(&author) else {
                continue;
            };
            removed += feed.truncate_from(entries, from, |_| {})?;
        }
        // Provisional rows never enter the published display order.
        Ok(removed)
    }

    /// Drop the signature of `hash` if its author's checkpoint covers it and its body is gone
    /// — for an entry pruned after the checkpoint arrived. Returns whether one was dropped.
    pub fn drop_signature_if_checkpointed(
        &mut self,
        entries: &mut impl EntryWrite,
        hash: &Digest32,
    ) -> Result<bool> {
        let Some((author, seq)) = self.position(entries, hash)? else {
            return Ok(false);
        };
        if self
            .checkpoints
            .get(&author)
            .is_none_or(|(below, _)| seq > *below)
        {
            return Ok(false);
        }
        let feed = self
            .feeds
            .get_mut(&author)
            .ok_or(Error::MalformedAtRest("DAG feed missing"))?;
        if feed.get(entries, seq)?.is_some_and(|e| e.payload.is_none()) {
            feed.drop_signature(entries, seq)
        } else {
            Ok(false)
        }
    }

    /// The highest seq of `author`'s feed that is authentic: its head, less any run of
    /// unsigned skeletons at the top that no signed entry has chained to yet (ADR-023
    /// decision 3). What a caller may persist.
    #[must_use]
    pub fn verified_head(&self, author: &Digest32) -> u64 {
        let head = self.feeds.get(author).map_or(0, Feed::max_seq);
        self.unverified_from
            .get(author)
            .map_or(head, |from| from.saturating_sub(1).min(head))
    }

    /// The highest checkpoint `author` has posted on its own feed: `(seq, entry_hash)`.
    #[must_use]
    pub fn checkpoint(&self, author: &Digest32) -> Option<(u64, Digest32)> {
        self.checkpoints.get(author).copied()
    }

    /// Whether a held author has checkpointed positions this node has not swept yet.
    ///
    /// This is deliberately a read-only preflight for the durable sweep. Opening and committing
    /// an empty store batch is not free: it fsyncs the room database and can park the node actor
    /// even though [`Dag::drop_checkpointed_signatures`] has no position to examine.
    #[must_use]
    pub fn checkpoint_signature_sweep_due(&self) -> bool {
        self.checkpoints.iter().any(|(author, (below, _))| {
            self.feeds.contains_key(author)
                && self.swept_to.get(author).copied().unwrap_or(0) < *below
        })
    }

    /// Drop the signatures of every entry at or below its author's checkpoint whose body is
    /// already pruned (ADR-023 decision 3), returning their hashes so the caller can rewrite
    /// what it stores. An entry with a body keeps its signature: governance is never pruned,
    /// and content keeps it until it expires here.
    ///
    /// Walks only what no earlier call covered and at most `limit` positions in one call. The
    /// caller persists the cursor with the rewritten entries, then resumes any remainder in a
    /// later maintenance turn.
    pub fn drop_checkpointed_signatures(
        &mut self,
        entries: &mut impl EntryWrite,
        limit: usize,
    ) -> Result<usize> {
        let mut dropped = 0usize;
        let mut examined = 0usize;
        for (author, (below, _)) in &self.checkpoints {
            let Some(feed) = self.feeds.get_mut(author) else {
                continue;
            };
            let from = self.swept_to.get(author).map_or(1, |s| s + 1);
            if from > *below {
                continue;
            }
            for seq in from..=*below {
                if examined >= limit {
                    return Ok(dropped);
                }
                if let Some(entry) = feed.get(entries, seq)? {
                    if entry.is_signed()
                        && entry.payload.is_none()
                        && feed.drop_signature(entries, seq)?
                    {
                        dropped += 1;
                    }
                }
                self.swept_to.insert(*author, seq);
                examined += 1;
            }
        }
        Ok(dropped)
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
    pub fn seen_for(&self, entries: &impl EntryRead, author: &Digest32) -> Result<Vec<Digest32>> {
        let mut heads = std::collections::BTreeSet::new();
        for (other, feed) in &self.feeds {
            if other == author {
                continue;
            }
            let head = self.verified_head(other);
            if head == 0 || head <= entries.referenced(author, other)? {
                continue;
            }
            let hash = feed
                .get(entries, head)?
                .ok_or(Error::MalformedAtRest("seen head missing"))?
                .entry_hash();
            if let Some(clock) = entries.clock(&hash)? {
                heads.insert((clock, hash));
                if heads.len() > MAX_SEEN {
                    heads.pop_first();
                }
            }
        }
        let mut seen: Vec<_> = heads.into_iter().map(|(_, hash)| hash).collect();
        seen.sort_unstable();
        Ok(seen)
    }

    /// Read one published display key. Absence and local read failure are distinct.
    pub fn order_key(
        &self,
        entries: &impl EntryRead,
        hash: &Digest32,
    ) -> Result<Option<(u64, Digest32)>> {
        Ok(entries.clock(hash)?.map(|clock| (clock, *hash)))
    }

    /// Install the durable late-parent revision only after its root publication commits.
    pub(crate) fn set_order_revision(&mut self, revision: u64, newest: Option<u64>) {
        self.reorder_generation = revision;
        self.newest_clock = newest;
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
    pub fn happened_before(
        &self,
        entries: &impl EntryRead,
        a: &Digest32,
        b: &Digest32,
    ) -> Result<bool> {
        let Some((a_author, a_seq)) = self.position(entries, a)? else {
            return Ok(false);
        };
        let Some((b_author, b_seq)) = self.position(entries, b)? else {
            return Ok(false);
        };
        if a_author == b_author {
            return Ok(a_seq < b_seq);
        }
        // Reaching an author's position reaches its complete prefix. Scan each newly reached
        // interval once; the work maps have one high-water per author, never one row per entry.
        // This also works during authenticated provisional acceptance, before display clocks
        // are published, and never substitutes display order for causal authority.
        let mut pending = BTreeMap::from([(b_author, b_seq)]);
        let mut scanned: BTreeMap<Digest32, u64> = BTreeMap::new();
        while let Some((author, through)) = pending.pop_first() {
            let from = scanned.get(&author).copied().unwrap_or(0).saturating_add(1);
            if from > through {
                continue;
            }
            for seq in from..=through {
                let entry = entries
                    .get(&author, seq)?
                    .ok_or(Error::MalformedAtRest("causal prefix missing"))?;
                for parent in &entry.skeleton.seen {
                    let Some((other, reached)) = self.position(entries, parent)? else {
                        continue;
                    };
                    if other == a_author && reached >= a_seq {
                        return Ok(true);
                    }
                    if reached > scanned.get(&other).copied().unwrap_or(0) {
                        let at = pending.entry(other).or_insert(0);
                        *at = (*at).max(reached);
                    }
                }
            }
            scanned.insert(author, through);
        }
        Ok(false)
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
    pub fn causal_order(&self, entries: &impl EntryRead) -> Result<Vec<Digest32>> {
        let mut rows = Vec::new();
        let mut cursor = None;
        while let Some(key) = entries.order_next(cursor)? {
            rows.push(key.1);
            cursor = Some(key);
        }
        Ok(rows)
    }

    /// Newest published clock, without collecting the order.
    #[must_use]
    pub fn newest_clock(&self) -> Option<u64> {
        self.newest_clock
    }

    /// Transitional whole-view caller. New consumers use the pinned one-row order cursor.
    pub fn order_keys(&self, entries: &impl EntryRead) -> Result<Vec<(Digest32, u64)>> {
        let mut rows = Vec::new();
        let mut cursor = None;
        while let Some(key) = entries.order_next(cursor)? {
            rows.push((key.1, key.0));
            cursor = Some(key);
        }
        Ok(rows)
    }

    /// Render-gating seam (ADR-008): attempt to decrypt+render the payload of the
    /// entry at `hash` with `decrypt`. The store holds ciphertext regardless of
    /// readability; this returns `Some(plaintext)` only if a payload is retained
    /// **and** `decrypt` succeeds (the holder has keys). A `None` means "store it,
    /// replicate it, but do not render" — exactly the data-side of per-sender
    /// consent. The real decryptor is M4/M6; M5 only owns this seam.
    pub fn render<F>(
        &self,
        entries: &impl EntryRead,
        hash: &Digest32,
        decrypt: F,
    ) -> Result<Option<Vec<u8>>>
    where
        F: FnOnce(&Entry, &[u8]) -> Option<Vec<u8>>,
    {
        let Some(entry) = self.get_by_hash(entries, hash)? else {
            return Ok(None);
        };
        let Some(payload) = entry.payload.as_deref() else {
            return Ok(None);
        };
        Ok(decrypt(&entry, payload))
    }

    /// Verify the entire DAG: every feed's chain + signatures, given a resolver
    /// from author fingerprint to that author's composite root key. Used after a
    /// bulk import / sync to confirm convergence integrity.
    pub fn verify_all<F>(&self, entries: &impl EntryRead, mut author_key: F) -> Result<()>
    where
        F: FnMut(&Digest32) -> Option<CompositePublicKey>,
    {
        for (author, feed) in &self.feeds {
            let key = author_key(author).ok_or(Error::MalformedBundle("dag missing author key"))?;
            feed.verify(entries)?;
            feed.verify_all_signatures(entries, &key)?;
        }
        Ok(())
    }
}
