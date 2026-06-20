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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256;
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::log::entry::EntrySkeleton;
    use crate::suite::algo;

    // ---- lipmaa known-answer table (verified vs the Bamboo reference). ----

    #[test]
    fn lipmaa_known_answers() {
        // (n, target) pairs — the authoritative Bamboo / lipmaa-link reference
        // table (AljoschaMeyer/lipmaa-link). target = n − f(n); the
        // certificate-pool entries (3^k−1)/2 = {1,4,13,40,...} are the long-jump
        // anchors. Known landmark values: lipmaa(8)=4, lipmaa(13)=4, lipmaa(40)=13.
        let table: &[(u64, u64)] = &[
            (2, 1),
            (3, 2),
            (4, 1),
            (5, 4),
            (6, 5),
            (7, 6),
            (8, 4),
            (9, 8),
            (10, 9),
            (11, 10),
            (12, 8),
            (13, 4),
            (14, 13),
            (17, 13),
            (26, 13),
            (39, 26),
            (40, 13),
        ];
        for &(n, want) in table {
            assert_eq!(lipmaa(n), want, "lipmaa({n})");
        }
    }

    #[test]
    fn lipmaa_skip_coincides_with_prev_at_2_3_and_neighbors() {
        // The skip link equals the prev link (target == n−1) when the back-jump
        // distance f(n) == 1. From the reference table that is exactly the n whose
        // immediate predecessor is *not* a deeper certificate anchor: n in
        // {2,3,6,7,10,11,...}. Verify a couple of representative cases and that the
        // checkpoints (4,13,40) jump strictly further than prev.
        assert_eq!(lipmaa(2), 1); // == prev (1)
        assert_eq!(lipmaa(3), 2); // == prev (2)
        for &cp in &[4u64, 13, 40] {
            assert!(lipmaa(cp) < cp - 1, "checkpoint {cp} should skip past prev");
        }
    }

    #[test]
    fn lipmaa_terminates_at_and_above_max_seq() {
        // The power-of-three loop must not diverge for very large n: at MAX_SEQ it
        // returns a sane target < n, and above MAX_SEQ it clamps (defense in depth).
        let t = lipmaa(MAX_SEQ);
        assert!(t < MAX_SEQ);
        // u64::MAX would previously spin forever with saturating_mul; now it clamps.
        let t2 = lipmaa(u64::MAX);
        assert!(t2 <= MAX_SEQ);
    }

    // ---- feed append / verify ----

    fn root(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    /// Author a correctly-linked entry for the next seq of `feed`.
    fn next_entry(feed: &Feed, r: &SoftwareRootSigner, payload: &[u8]) -> Entry {
        let seq = feed.max_seq() + 1;
        let prev_hash = if seq == 1 {
            ZERO_HASH
        } else {
            feed.get(seq - 1).unwrap().entry_hash()
        };
        let lipmaa_backlink = if seq == 1 {
            ZERO_HASH
        } else {
            feed.get(lipmaa(seq)).unwrap().entry_hash()
        };
        let sk = EntrySkeleton {
            author_id: r.fingerprint(),
            seq,
            prev_hash,
            lipmaa_backlink,
            channel_id: [0xAB; 32],
            epoch: 1,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(payload),
            payload_len: payload.len() as u64,
            end_of_feed: false,
        };
        Entry::build_signed(r, sk, payload.to_vec()).unwrap()
    }

    fn build_feed(r: &SoftwareRootSigner, n: u64) -> Feed {
        let mut feed = Feed::new();
        for i in 0..n {
            let p = format!("entry-{i}");
            let e = next_entry(&feed, r, p.as_bytes());
            feed.append_verified(e, &r.public_key()).unwrap();
        }
        feed
    }

    #[test]
    fn append_chains_and_verifies() {
        let r = root(1, 2);
        let feed = build_feed(&r, 20);
        assert_eq!(feed.max_seq(), 20);
        assert_eq!(feed.len(), 20);
        feed.verify().unwrap();
        feed.verify_all_signatures(&r.public_key()).unwrap();
    }

    #[test]
    fn rejects_non_monotonic_seq() {
        let r = root(3, 4);
        let mut feed = build_feed(&r, 3);
        // Try to append an entry at seq 5 (skipping 4).
        let mut e = next_entry(&feed, &r, b"x"); // this is seq 4
        e.skeleton.seq = 5;
        // Re-sign so the authenticator matches the tampered skeleton.
        let resigned = Entry::build_signed(&r, e.skeleton.clone(), b"x".to_vec()).unwrap();
        assert!(matches!(
            feed.append(resigned),
            Err(Error::MalformedBundle("feed seq not contiguous"))
        ));
    }

    #[test]
    fn rejects_broken_prev_link() {
        let r = root(5, 6);
        let mut feed = build_feed(&r, 3);
        let mut e = next_entry(&feed, &r, b"y");
        e.skeleton.prev_hash = [0xFF; 32]; // wrong link
        let resigned = Entry::build_signed(&r, e.skeleton.clone(), b"y".to_vec()).unwrap();
        assert!(matches!(
            feed.append(resigned),
            Err(Error::MalformedBundle("feed prev_hash mismatch"))
        ));
    }

    #[test]
    fn rejects_broken_lipmaa_link() {
        let r = root(7, 8);
        // seq 8 has lipmaa target 4 (a real skip), so a wrong backlink is caught.
        let mut feed = build_feed(&r, 7);
        let mut e = next_entry(&feed, &r, b"z"); // seq 8
        e.skeleton.lipmaa_backlink = [0x11; 32];
        let resigned = Entry::build_signed(&r, e.skeleton.clone(), b"z".to_vec()).unwrap();
        assert!(matches!(
            feed.append(resigned),
            Err(Error::MalformedBundle("feed lipmaa_backlink mismatch"))
        ));
    }

    #[test]
    fn rejects_foreign_author() {
        let r = root(1, 1);
        let other = root(2, 2);
        let mut feed = build_feed(&r, 2);
        // An entry authored by a different identity cannot extend this feed.
        let mut foreign = Feed::new();
        let e = next_entry(&foreign, &other, b"f");
        foreign
            .append_verified(e.clone(), &other.public_key())
            .unwrap();
        // Force its seq to slot after r's feed; author still mismatches.
        let e2 = next_entry(&feed, &other, b"g");
        assert!(matches!(
            feed.append(e2),
            Err(Error::MalformedBundle("feed author mismatch"))
        ));
    }

    #[test]
    fn end_of_feed_blocks_further_append() {
        let r = root(9, 9);
        let mut feed = build_feed(&r, 2);
        // Author an end-of-feed entry at seq 3.
        let seq = 3;
        let sk = EntrySkeleton {
            author_id: r.fingerprint(),
            seq,
            prev_hash: feed.get(seq - 1).unwrap().entry_hash(),
            lipmaa_backlink: feed.get(lipmaa(seq)).unwrap().entry_hash(),
            channel_id: [0xAB; 32],
            epoch: 1,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(b"end"),
            payload_len: 3,
            end_of_feed: true,
        };
        let last = Entry::build_signed(&r, sk, b"end".to_vec()).unwrap();
        feed.append_verified(last, &r.public_key()).unwrap();
        // Any further append is rejected.
        let after = next_entry(&feed, &r, b"after");
        assert!(matches!(
            feed.append(after),
            Err(Error::MalformedBundle("feed already ended"))
        ));
    }

    // ---- lipmaa certificate ----

    #[test]
    fn lipmaa_certificate_is_logarithmic_and_verifies() {
        let r = root(2, 3);
        let feed = build_feed(&r, 40);
        let cert = feed.lipmaa_certificate(1).unwrap();
        // The head is 40; a full prev-chain would be 40 entries. The skip-link
        // path is far shorter (logarithmic): assert it is well under linear.
        assert!(cert.len() <= 12, "cert len {} not logarithmic", cert.len());
        verify_lipmaa_certificate(&cert, 1, &r.public_key()).unwrap();
        // Head is first, target last.
        assert_eq!(cert[0].skeleton.seq, 40);
        assert_eq!(cert[cert.len() - 1].skeleton.seq, 1);
    }

    #[test]
    fn lipmaa_certificate_to_mid_target() {
        let r = root(4, 5);
        let feed = build_feed(&r, 26);
        let cert = feed.lipmaa_certificate(13).unwrap();
        verify_lipmaa_certificate(&cert, 13, &r.public_key()).unwrap();
        assert_eq!(cert[cert.len() - 1].skeleton.seq, 13);
    }

    #[test]
    fn tampered_certificate_rejected() {
        let r = root(6, 7);
        let feed = build_feed(&r, 13);
        let mut cert = feed.lipmaa_certificate(1).unwrap();
        // Corrupt a middle entry's backlink so a step no longer matches.
        let mid = cert.len() / 2;
        cert[mid].skeleton.prev_hash = [0xEE; 32];
        assert!(verify_lipmaa_certificate(&cert, 1, &r.public_key()).is_err());
    }

    #[test]
    fn certificate_target_out_of_range_rejected() {
        let r = root(8, 9);
        let feed = build_feed(&r, 5);
        assert!(feed.lipmaa_certificate(0).is_err());
        assert!(feed.lipmaa_certificate(6).is_err());
    }
}
