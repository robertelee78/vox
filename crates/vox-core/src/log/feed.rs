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

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::hash::{Digest32, DIGEST_LEN};
use crate::identity::composite::CompositePublicKey;
use crate::log::entry::{Entry, ZERO_HASH};

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
    /// seq -> entry. A `BTreeMap` keeps entries seq-ordered for iteration and
    /// makes the contiguity check a simple range walk.
    entries: BTreeMap<u64, Entry>,
}

impl Feed {
    /// An empty feed (no author bound yet).
    #[must_use]
    pub fn new() -> Self {
        Self {
            author_id: None,
            entries: BTreeMap::new(),
        }
    }

    /// The author this feed is bound to, once it holds at least one entry.
    #[must_use]
    pub fn author_id(&self) -> Option<Digest32> {
        self.author_id
    }

    /// The highest seq present (the head), or 0 if empty.
    #[must_use]
    pub fn max_seq(&self) -> u64 {
        self.entries.keys().next_back().copied().unwrap_or(0)
    }

    /// The number of entries held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the feed holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at `seq`, if present.
    #[must_use]
    pub fn get(&self, seq: u64) -> Option<&Entry> {
        self.entries.get(&seq)
    }

    /// The hash of the head entry (the entry at `max_seq`), or the all-zero hash
    /// if empty. This is the `head_hash` gossiped in `HAVE` and used in
    /// fork-head comparison ([`crate::log::sync`]).
    #[must_use]
    pub fn head_hash(&self) -> Digest32 {
        self.entries
            .values()
            .next_back()
            .map(Entry::entry_hash)
            .unwrap_or(ZERO_HASH)
    }

    /// Iterate entries in ascending seq order.
    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// The entries this feed **holds** with `from <= seq <= to`, in ascending seq
    /// order. The cost is bounded by what is stored, never by the numbers asked
    /// for: a peer's `WANT (author, 1, u64::MAX)` walks this feed's entries, not
    /// eighteen quintillion lookups (PRD-001 R4). An inverted range is empty.
    pub fn range(&self, from: u64, to: u64) -> impl Iterator<Item = &Entry> {
        (from <= to)
            .then(|| self.entries.range(from..=to).map(|(_, e)| e))
            .into_iter()
            .flatten()
    }

    /// Append `entry` as the next contiguous entry, validating it links correctly.
    ///
    /// Enforces, in order: single author; `seq == max_seq + 1` (contiguous,
    /// monotonic); the previous entry was not an end-of-feed; `prev_hash` equals
    /// the seq−1 entry's hash (or all-zero at seq 1); `lipmaa_backlink` equals the
    /// `lipmaa(seq)` entry's hash (or all-zero at seq 1). Returns
    /// [`Error::MalformedJoin`]-free, log-specific errors on any violation.
    ///
    /// The caller is responsible for the *authenticator* (call [`Entry::verify`]
    /// before append, or use [`Feed::append_verified`]); this method enforces the
    /// structural feed invariants the signature does not cover.
    pub fn append(&mut self, entry: Entry) -> Result<()> {
        self.validate_next(&entry)?;
        let seq = entry.skeleton.seq;
        if self.author_id.is_none() {
            self.author_id = Some(entry.skeleton.author_id);
        }
        self.entries.insert(seq, entry);
        Ok(())
    }

    /// Validate that `entry` would be a legal next append — single author,
    /// contiguous monotonic `seq`, no append past end-of-feed, and correct
    /// `prev_hash`/`lipmaa_backlink` — **without** mutating the feed. The caller
    /// uses this to gate side effects (e.g. committing quota) before the insert,
    /// so a later rejection never leaves partial state.
    pub fn validate_next(&self, entry: &Entry) -> Result<()> {
        let seq = entry.skeleton.seq;

        // Bound the sequence so the lipmaa power-of-three arithmetic stays
        // overflow-free (ADR-008; see [`MAX_SEQ`]).
        if seq > MAX_SEQ {
            return Err(Error::SizeLimitExceeded("feed seq exceeds MAX_SEQ"));
        }

        // Single-writer: every entry shares the feed's author.
        match self.author_id {
            None => {}
            Some(a) if a == entry.skeleton.author_id => {}
            Some(_) => return Err(Error::MalformedBundle("feed author mismatch")),
        }

        // Contiguous, monotonic from 1.
        let expected = self.max_seq() + 1;
        if seq != expected {
            return Err(Error::MalformedBundle("feed seq not contiguous"));
        }

        // No append past an end-of-feed marker.
        if let Some(prev) = self.entries.get(&self.max_seq()) {
            if prev.skeleton.end_of_feed {
                return Err(Error::MalformedBundle("feed already ended"));
            }
        }

        // prev_hash chaining.
        let expect_prev = if seq == 1 {
            ZERO_HASH
        } else {
            self.hash_at(seq - 1)?
        };
        if entry.skeleton.prev_hash != expect_prev {
            return Err(Error::MalformedBundle("feed prev_hash mismatch"));
        }

        // lipmaa skip-link chaining.
        let expect_lipmaa = if seq == 1 {
            ZERO_HASH
        } else {
            self.hash_at(lipmaa(seq))?
        };
        if entry.skeleton.lipmaa_backlink != expect_lipmaa {
            return Err(Error::MalformedBundle("feed lipmaa_backlink mismatch"));
        }

        Ok(())
    }

    /// Verify the authenticator of `entry` under `author_root`, then append it
    /// with the structural checks of [`Feed::append`]. The single, ordered seam
    /// for accepting a new own-or-replicated entry once authorship is known.
    pub fn append_verified(
        &mut self,
        entry: Entry,
        author_root: &CompositePublicKey,
    ) -> Result<()> {
        entry.verify(author_root)?;
        self.append(entry)
    }

    /// Full structural + chain verification of the whole feed: every entry's
    /// `prev_hash` and `lipmaa_backlink`, monotonic contiguous seq, single
    /// author, and end-of-feed discipline. Does NOT check authenticators (call
    /// [`Feed::verify_all_signatures`] for that, given the author key).
    pub fn verify(&self) -> Result<()> {
        let mut expected_seq = 1u64;
        let mut ended = false;
        for (&seq, entry) in &self.entries {
            if ended {
                return Err(Error::MalformedBundle("feed entry after end-of-feed"));
            }
            if seq != expected_seq {
                return Err(Error::MalformedBundle("feed seq not contiguous"));
            }
            if Some(entry.skeleton.author_id) != self.author_id {
                return Err(Error::MalformedBundle("feed author mismatch"));
            }
            let expect_prev = if seq == 1 {
                ZERO_HASH
            } else {
                self.hash_at(seq - 1)?
            };
            if entry.skeleton.prev_hash != expect_prev {
                return Err(Error::MalformedBundle("feed prev_hash mismatch"));
            }
            let expect_lipmaa = if seq == 1 {
                ZERO_HASH
            } else {
                self.hash_at(lipmaa(seq))?
            };
            if entry.skeleton.lipmaa_backlink != expect_lipmaa {
                return Err(Error::MalformedBundle("feed lipmaa_backlink mismatch"));
            }
            ended = entry.skeleton.end_of_feed;
            expected_seq += 1;
        }
        Ok(())
    }

    /// Verify every entry's composite authenticator under `author_root`. Combined
    /// with [`Feed::verify`], this is a complete cryptographic feed check.
    pub fn verify_all_signatures(&self, author_root: &CompositePublicKey) -> Result<()> {
        for entry in self.entries.values() {
            entry.verify(author_root)?;
        }
        Ok(())
    }

    /// Build a lipmaa skip-link certificate: the chain of entries from the head
    /// (`max_seq`) back to `target_seq`, following at each step the *larger* valid
    /// backlink (lipmaa if its target ≥ `target_seq`, else prev). The result is a
    /// logarithmic-length list (head-first) that [`verify_lipmaa_certificate`] can
    /// check end-to-end without the whole feed — the partial-replication path
    /// (ADR-008 §"lipmaa skip-links give logarithmic-length verification certs").
    pub fn lipmaa_certificate(&self, target_seq: u64) -> Result<Vec<Entry>> {
        let head = self.max_seq();
        if target_seq == 0 || target_seq > head {
            return Err(Error::MalformedBundle("lipmaa cert target out of range"));
        }
        let mut chain = Vec::new();
        let mut cur = head;
        loop {
            let entry = self
                .entries
                .get(&cur)
                .ok_or(Error::MalformedBundle("lipmaa cert missing entry"))?;
            chain.push(entry.clone());
            if cur == target_seq {
                break;
            }
            // Prefer the longer jump that does not overshoot the target.
            let lip = lipmaa(cur);
            cur = if cur >= 2 && lip >= target_seq && lip < cur {
                lip
            } else {
                cur - 1
            };
        }
        Ok(chain)
    }

    fn hash_at(&self, seq: u64) -> Result<Digest32> {
        self.entries
            .get(&seq)
            .map(Entry::entry_hash)
            .ok_or(Error::MalformedBundle("feed backlink target missing"))
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
