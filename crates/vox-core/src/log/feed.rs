//! The per-author hash-linked feed (Bamboo-derived, ADR-008).
//!
//! Each identity owns a single-writer, append-only, hash-linked log. Entry `seq`
//! starts at 1 and is strictly monotonic; every entry carries two backlinks:
//! - `prev_hash` — the SHA-256 of the seq−1 entry's canonical body (the
//!   contiguous chain), and
//! - `lipmaa_backlink` — the SHA-256 of the entry at the Bamboo `lipmaa(seq)`
//!   predecessor (the skip-link), which gives O(log n) verification certificates
//!   for partial replication.
//!
//! ## The lipmaa construction (Bamboo, AljoschaMeyer/bamboo README)
//! The skip-link target of entry `n` is `n − jump(n)`, where `jump(n)` is the
//! Bamboo back-jump distance. The certificate-pool predecessors are the entries
//! at sequence numbers of the form `(3^k − 1)/2` (whose ternary representation is
//! all `1`s). [`lipmaa`] computes the *target sequence number* with the exact
//! integer arithmetic from the Bamboo reference (verified against a known-answer
//! table in this module's tests); the genesis entry (seq 1) has no predecessor
//! and reports target `1` (a self-reference the feed treats as "no backlink").
//!
//! ## Verification paths
//! - **Full verify** ([`Feed::verify`]): every contiguous `prev_hash` and every
//!   `lipmaa_backlink` is checked against the hash of the entry it names. A broken
//!   link, a non-monotonic `seq`, an author mismatch, or an append after an
//!   end-of-feed marker is rejected.
//! - **Lipmaa skip-link certificate** ([`Feed::lipmaa_certificate`],
//!   [`verify_lipmaa_certificate`]): a logarithmic-length chain of entries from a
//!   head down to a target seq, following the larger of the lipmaa/prev backlink
//!   at each step, so a peer can prove a head's ancestry without the whole feed
//!   (partial replication).

use crate::error::{Error, Result};
use crate::hash::{Digest32, DIGEST_LEN};
use crate::identity::composite::CompositePublicKey;
use crate::log::entry::{Entry, EntryRead, EntryWrite, ZERO_HASH};

/// Maximum per-author sequence number Vox supports.
///
/// The Bamboo lipmaa arithmetic walks powers of three; the largest
/// certificate-pool value `(3^k − 1)/2` must fit in a `u64`. `3^40 ≈ 1.2e19 <
/// u64::MAX` but `3^41` overflows, so `seq` is capped well below that — at
/// `2^48`, which is astronomically beyond any real single-writer feed (≈2.8e14
/// entries) yet leaves the lipmaa loop overflow-free. The cap is enforced at the
/// boundaries (entry decode and feed append), so [`lipmaa`] is never called with
/// a value that could make its power-of-three loop diverge.
pub const MAX_SEQ: u64 = 1 << 48;

/// The Bamboo lipmaa skip-link **target** sequence number for entry `n`
/// (1-indexed): the predecessor whose hash entry `n` records in
/// `lipmaa_backlink`. Returns `1` for `n == 1` (genesis — no predecessor; the
/// feed encodes this as an all-zero backlink, not a self-hash). For `n` above
/// [`MAX_SEQ`] it saturates to [`MAX_SEQ`] internally rather than diverging — but
/// such an `n` is already rejected at the boundaries ([`Feed::validate_next`],
/// entry decode), so this is a belt-and-braces guard, not a reachable path.
///
/// This is `n − jump(n)`, where `jump(n)` is the Bamboo back-jump distance
/// computed by the reference integer arithmetic (AljoschaMeyer/bamboo README).
/// The certificate-pool entries are those at `(3^k − 1)/2`.
#[must_use]
pub fn lipmaa(n: u64) -> u64 {
    if n <= 1 {
        return 1;
    }
    // Defense in depth: clamp to the supported range so the power-of-three loop
    // below cannot spin even if a caller bypasses the boundary checks.
    let n = n.min(MAX_SEQ);
    // Reference arithmetic (bamboo README, "cft" iterative form). `po3` walks
    // powers of three; `m = (po3 − 1)/2` is a certificate-pool value. The loop
    // narrows `po3` to the back-jump distance; the target is `n − po3`. Because
    // `n ≤ MAX_SEQ = 2^48`, `po3` reaches at most 3^31 (≈6.2e14) before `m ≥ n`,
    // so `checked_mul` never overflows here; the `expect`-free fallback caps it.
    let mut m: u64 = 1;
    let mut po3: u64 = 3;
    let mut x: u64 = n;

    // Find the smallest certificate-pool value m ≥ n.
    while m < n {
        po3 = match po3.checked_mul(3) {
            Some(v) => v,
            // Unreachable for n ≤ MAX_SEQ; saturate rather than panic/diverge.
            None => break,
        };
        m = (po3 - 1) / 2;
    }
    po3 /= 3;

    // If n is not itself a certificate-pool value, narrow to the largest jump.
    if m != n {
        while x != 0 {
            m = (po3 - 1) / 2;
            po3 /= 3;
            x %= m;
        }
        if m != po3 {
            po3 = m;
        }
    }
    n - po3
}

/// A per-author hash-linked feed: the ordered entries `1..=len`, indexed by seq.
///
/// The feed enforces single-writer append: every entry shares one `author_id`,
/// `seq` is contiguous from 1, and `prev_hash`/`lipmaa_backlink` must name the
/// hashes of the entries they point at. An entry after one whose `end_of_feed`
/// flag is set is rejected.
#[derive(Debug, Default, Clone)]
pub struct Feed {
    author_id: Option<Digest32>,
    head: u64,
    head_hash: Digest32,
    first_claimed_ms: u64,
    ended: bool,
}

/// Structural rejection and local storage failure are different: the latter never becomes an
/// authenticator refusal and must poison/report the local room instead.
#[derive(Debug)]
pub enum FeedError {
    /// A peer entry violates the feed structure.
    Invalid(Error),
    /// The local entry store could not be read or written.
    Local(Error),
}

impl Feed {
    /// An empty feed, with no accepted author or head.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// The accepted author, once this feed has held an entry.
    #[must_use]
    pub fn author_id(&self) -> Option<Digest32> {
        self.author_id
    }
    /// The last accepted sequence, including an unverified provisional tail.
    #[must_use]
    pub fn max_seq(&self) -> u64 {
        self.head
    }
    /// The first accepted position, or none for an empty feed.
    #[must_use]
    pub fn min_seq(&self) -> Option<u64> {
        (self.head != 0).then_some(1)
    }
    /// The number of accepted positions, saturating on narrower platforms.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::try_from(self.head).unwrap_or(usize::MAX)
    }
    /// Whether this feed has no accepted positions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.head == 0
    }
    /// The hash at the accepted head, or the all-zero genesis predecessor.
    #[must_use]
    pub fn head_hash(&self) -> Digest32 {
        self.head_hash
    }
    /// The first accepted entry’s signed clock claim, used for membership context.
    pub fn first_claimed_ms(&self) -> Option<u64> {
        (self.head != 0).then_some(self.first_claimed_ms)
    }

    /// Read one accepted position as an owned entry; an unreadable held row is an error.
    pub fn get(&self, entries: &impl EntryRead, seq: u64) -> Result<Option<Entry>> {
        if seq == 0 || seq > self.head {
            return Ok(None);
        }
        let author = self
            .author_id
            .ok_or(Error::MalformedAtRest("nonempty feed has no author"))?;
        entries
            .get(&author, seq)?
            .map(Some)
            .ok_or(Error::MalformedAtRest("held feed entry missing"))
    }
    /// Stream accepted entries in order without retaining a complete feed copy.
    pub fn iter<'a>(
        &'a self,
        entries: &'a impl EntryRead,
    ) -> impl Iterator<Item = Result<Entry>> + 'a {
        self.range(entries, 1, self.head)
    }
    /// Stream only held positions within the inclusive requested range.
    pub fn range<'a>(
        &'a self,
        entries: &'a impl EntryRead,
        from: u64,
        to: u64,
    ) -> impl Iterator<Item = Result<Entry>> + 'a {
        // Feeds are contiguous. Clip peer-supplied bounds before walking: a WANT ending at
        // u64::MAX visits only positions actually held, never every requested integer.
        (from.max(1)..=to.min(self.head)).map(move |seq| {
            self.get(entries, seq)?
                .ok_or(Error::MalformedAtRest("held feed entry missing"))
        })
    }
    /// Validate author, sequence, end marker and both backlinks before writing.
    pub fn validate_next(
        &self,
        entries: &impl EntryRead,
        entry: &Entry,
    ) -> std::result::Result<(), FeedError> {
        let bad = |why| FeedError::Invalid(Error::MalformedBundle(why));
        let seq = entry.skeleton.seq;
        if seq > MAX_SEQ {
            return Err(FeedError::Invalid(Error::SizeLimitExceeded(
                "feed seq exceeds MAX_SEQ",
            )));
        }
        if self
            .author_id
            .is_some_and(|a| a != entry.skeleton.author_id)
        {
            return Err(bad("feed author mismatch"));
        }
        if self.head.checked_add(1) != Some(seq) {
            return Err(bad("feed seq not contiguous"));
        }
        if self.ended {
            return Err(bad("feed already ended"));
        }
        if entry.skeleton.prev_hash != self.head_hash {
            return Err(bad("feed prev_hash mismatch"));
        }
        let backlink = if seq == 1 {
            ZERO_HASH
        } else {
            self.get(entries, lipmaa(seq))
                .map_err(FeedError::Local)?
                .ok_or_else(|| bad("feed backlink target missing"))?
                .entry_hash()
        };
        if entry.skeleton.lipmaa_backlink != backlink {
            return Err(bad("feed lipmaa_backlink mismatch"));
        }
        Ok(())
    }
    /// Write one validated entry through the transaction context, then advance metadata.
    pub fn append(
        &mut self,
        entries: &mut impl EntryWrite,
        entry: &Entry,
    ) -> std::result::Result<(), FeedError> {
        self.validate_next(entries, entry)?;
        entries.put(entry).map_err(FeedError::Local)?;
        if self.head == 0 {
            self.first_claimed_ms = entry.skeleton.claimed_ms;
        }
        self.author_id = Some(entry.skeleton.author_id);
        self.head = entry.skeleton.seq;
        self.head_hash = entry.entry_hash();
        self.ended = entry.skeleton.end_of_feed;
        Ok(())
    }
    /// Drop one retained body while keeping its authenticated skeleton.
    pub fn prune_payload(&mut self, entries: &mut impl EntryWrite, seq: u64) -> Result<bool> {
        let Some(mut entry) = self.get(entries, seq)? else {
            return Ok(false);
        };
        if !entry.prune_payload() {
            return Ok(false);
        }
        entries.put(&entry)?;
        Ok(true)
    }
    /// Restore a body already authenticated by the caller against its held skeleton.
    pub fn restore_payload(
        &mut self,
        entries: &mut impl EntryWrite,
        seq: u64,
        payload: Vec<u8>,
    ) -> Result<bool> {
        let Some(mut entry) = self.get(entries, seq)? else {
            return Ok(false);
        };
        if entry.payload.is_some() {
            return Ok(false);
        }
        entry.payload = Some(payload);
        entries.put(&entry)?;
        Ok(true)
    }
    /// Remove a signature covered by a later authenticated checkpoint.
    pub fn drop_signature(&mut self, entries: &mut impl EntryWrite, seq: u64) -> Result<bool> {
        let Some(mut entry) = self.get(entries, seq)? else {
            return Ok(false);
        };
        if !entry.drop_signature() {
            return Ok(false);
        }
        entries.put(&entry)?;
        Ok(true)
    }
    /// Remove a provisional tail backwards, reporting each removed entry to the caller.
    pub fn truncate_from(
        &mut self,
        entries: &mut impl EntryWrite,
        from: u64,
        mut removed: impl FnMut(Entry),
    ) -> Result<usize> {
        if from == 0 || from > self.head {
            return Ok(0);
        }
        let author = self
            .author_id
            .ok_or(Error::MalformedAtRest("nonempty feed has no author"))?;
        let mut count = 0;
        for seq in (from..=self.head).rev() {
            let entry = self
                .get(entries, seq)?
                .ok_or(Error::MalformedAtRest("unpublished feed entry missing"))?;
            entries.remove(&author, seq)?;
            self.head = seq - 1;
            self.head_hash = entry.skeleton.prev_hash;
            self.ended = false;
            removed(entry);
            count += 1;
        }
        Ok(count)
    }
    /// Recheck contiguous and skip linkage using owned, fallible reads.
    pub fn verify(&self, entries: &impl EntryRead) -> Result<()> {
        let mut expected = Self::new();
        for entry in self.iter(entries) {
            let entry = entry?;
            expected
                .validate_next(entries, &entry)
                .map_err(|e| match e {
                    FeedError::Invalid(e) | FeedError::Local(e) => e,
                })?;
            expected.author_id = self.author_id;
            expected.head = entry.skeleton.seq;
            expected.head_hash = entry.entry_hash();
            expected.ended = entry.skeleton.end_of_feed;
        }
        Ok(())
    }
    /// Verify retained signatures and refuse an unsigned tail without a successor.
    pub fn verify_all_signatures(
        &self,
        entries: &impl EntryRead,
        author_root: &CompositePublicKey,
    ) -> Result<()> {
        let mut unchained = false;
        for entry in self.iter(entries) {
            let entry = entry?;
            if entry.is_signed() {
                entry.verify(author_root)?;
                unchained = false;
            } else {
                unchained = true;
            }
        }
        if unchained {
            return Err(Error::MalformedBundle(
                "feed ends in unsigned entries no signature chains to",
            ));
        }
        Ok(())
    }
    /// Read the logarithmic backlink certificate from the head to the requested position.
    pub fn lipmaa_certificate(
        &self,
        entries: &impl EntryRead,
        target_seq: u64,
    ) -> Result<Vec<Entry>> {
        if target_seq == 0 || target_seq > self.head {
            return Err(Error::MalformedBundle("lipmaa cert target out of range"));
        }
        let mut chain = Vec::new();
        let mut cur = self.head;
        loop {
            let entry = self
                .get(entries, cur)?
                .ok_or(Error::MalformedAtRest("lipmaa cert missing entry"))?;
            chain.push(entry);
            if cur == target_seq {
                break;
            }
            let lip = lipmaa(cur);
            cur = if cur >= 2 && lip >= target_seq && lip < cur {
                lip
            } else {
                cur - 1
            };
        }
        Ok(chain)
    }
}

/// Verify a lipmaa skip-link certificate produced by [`Feed::lipmaa_certificate`].
///
/// Checks the chain is head-first and strictly descending in seq, that each step
/// follows a real backlink (the next entry's hash matches the current entry's
/// `prev_hash` when the step is −1, or its `lipmaa_backlink` when the step is a
/// lipmaa jump), that the final entry's seq equals `target_seq`, and (given the
/// author key) that every entry on the path is validly composite-signed. This
/// lets a peer accept a head's ancestry from a logarithmic slice of the feed.
pub fn verify_lipmaa_certificate(
    chain: &[Entry],
    target_seq: u64,
    author_root: &CompositePublicKey,
) -> Result<()> {
    if chain.is_empty() {
        return Err(Error::MalformedBundle("lipmaa cert empty"));
    }
    let author = chain[0].skeleton.author_id;
    for entry in chain {
        if entry.skeleton.author_id != author {
            return Err(Error::MalformedBundle("lipmaa cert author mismatch"));
        }
        entry.verify(author_root)?;
    }
    for window in chain.windows(2) {
        let cur = &window[0];
        let next = &window[1];
        let cur_seq = cur.skeleton.seq;
        let next_seq = next.skeleton.seq;
        if next_seq >= cur_seq {
            return Err(Error::MalformedBundle("lipmaa cert not descending"));
        }
        let next_hash = next.entry_hash();
        if next_seq == cur_seq - 1 {
            // A prev-link step.
            if cur.skeleton.prev_hash != next_hash {
                return Err(Error::MalformedBundle("lipmaa cert prev link broken"));
            }
        } else if next_seq == lipmaa(cur_seq) {
            // A lipmaa skip step.
            if cur.skeleton.lipmaa_backlink != next_hash {
                return Err(Error::MalformedBundle("lipmaa cert skip link broken"));
            }
        } else {
            return Err(Error::MalformedBundle("lipmaa cert step is not a backlink"));
        }
    }
    if chain[chain.len() - 1].skeleton.seq != target_seq {
        return Err(Error::MalformedBundle("lipmaa cert does not reach target"));
    }
    Ok(())
}

/// Compute the all-zero genesis backlink (re-exported convenience).
#[must_use]
pub const fn zero_backlink() -> [u8; DIGEST_LEN] {
    ZERO_HASH
}
