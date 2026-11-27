//! What this node holds of each author's public history, kept in memory per room (ADR-054
//! PL-2, PL-3). A committed batch names the authors and positions it changed
//! (`Batch::touch_history`); the room's next snapshot publication reads only those again and
//! publishes the record with the snapshot. The connections' pull loops plan and tell from it
//! alone: no store read and no room lock per plan or per Have.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::error::Result;
use crate::hash::Digest32;
use crate::log::entry::Entry;
use crate::log::feed::MAX_SEQ;
use crate::log::history::{LogScope, SignedEntryKind, SignedHead};
use crate::node::history_stream::{fork_mutant_is, AuthorHave, MAX_HAVE_RUNS};
use crate::node::store::Store;

use super::{entry_store, ChannelState, ServedRoom};

/// A page of runs: the span of positions it tells completely, and its runs.
type RunPage = ((u64, u64), Vec<(u64, u64)>);

/// Positions as runs, ascending and disjoint, adjacent runs joined.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Runs(Vec<(u64, u64)>);

impl Runs {
    fn at(&self, seq: u64) -> usize {
        self.0.partition_point(|&(_, b)| b < seq)
    }

    pub(crate) fn contains(&self, seq: u64) -> bool {
        self.0.get(self.at(seq)).is_some_and(|&(a, _)| a <= seq)
    }

    pub(crate) fn set(&mut self, seq: u64, on: bool) {
        if self.contains(seq) == on {
            return;
        }
        let i = self.at(seq);
        if on {
            let left = i > 0 && self.0[i - 1].1 + 1 == seq;
            let right = self.0.get(i).is_some_and(|&(a, _)| a == seq + 1);
            match (left, right) {
                (true, true) => self.0[i - 1].1 = self.0.remove(i).1,
                (true, false) => self.0[i - 1].1 = seq,
                (false, true) => self.0[i].0 = seq,
                (false, false) => self.0.insert(i, (seq, seq)),
            }
        } else {
            let (a, b) = self.0[i];
            match (a == seq, b == seq) {
                (true, true) => {
                    self.0.remove(i);
                }
                (true, false) => self.0[i].0 = seq + 1,
                (false, true) => self.0[i].1 = seq - 1,
                (false, false) => {
                    self.0[i].1 = seq - 1;
                    self.0.insert(i + 1, (seq + 1, b));
                }
            }
        }
    }

    /// The lowest position from `seq` up that no run holds.
    pub(crate) fn absent_from(&self, seq: u64) -> u64 {
        match self.0.get(self.at(seq)) {
            Some(&(a, b)) if a <= seq => b + 1,
            _ => seq,
        }
    }

    /// The highest position from `seq` down that no run holds (0 when none is).
    pub(crate) fn absent_below(&self, seq: u64) -> u64 {
        match self.0.get(self.at(seq)) {
            Some(&(a, _)) if a <= seq => a - 1,
            _ => seq,
        }
    }

    /// The lowest position from `seq` up that a run holds (`u64::MAX` when none is).
    pub(crate) fn present_from(&self, seq: u64) -> u64 {
        self.0
            .get(self.at(seq))
            .map_or(u64::MAX, |&(a, _)| a.max(seq))
    }

    /// The highest position from `seq` down that a run holds (0 when none is).
    pub(crate) fn present_below(&self, seq: u64) -> u64 {
        match self.0.partition_point(|&(a, _)| a <= seq) {
            0 => 0,
            i => self.0[i - 1].1.min(seq),
        }
    }

    /// Holds every position `lo..=hi` too.
    pub(crate) fn insert(&mut self, lo: u64, hi: u64) {
        let i = self.0.partition_point(|&(_, b)| b.saturating_add(1) < lo);
        let j = self.0.partition_point(|&(a, _)| a <= hi.saturating_add(1));
        let (lo, hi) = self.0[i..j]
            .iter()
            .fold((lo, hi), |(lo, hi), &(a, b)| (lo.min(a), hi.max(b)));
        self.0.splice(i..j, [(lo, hi)]);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The runs, ascending.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.0.iter().copied()
    }

    fn newest(&self) -> Vec<(u64, u64)> {
        self.0[self.0.len().saturating_sub(MAX_HAVE_RUNS)..].to_vec()
    }

    /// The runs as pages of at most [`MAX_HAVE_RUNS`] runs, oldest first, each with the span
    /// of positions it tells completely; the spans tile `1..=MAX_SEQ`, the newest page's
    /// reaching `MAX_SEQ`. Nothing is dropped: every run is in exactly one page.
    fn pages(&self) -> Vec<RunPage> {
        let mut chunks: Vec<&[(u64, u64)]> = self.0.rchunks(MAX_HAVE_RUNS).collect();
        chunks.reverse();
        if chunks.is_empty() {
            return vec![((1, MAX_SEQ), Vec::new())];
        }
        (0..chunks.len())
            .map(|i| {
                let lo = if i == 0 {
                    1
                } else {
                    chunks[i - 1][chunks[i - 1].len() - 1].1 + 1
                };
                let hi = chunks.get(i + 1).map_or(MAX_SEQ, |next| next[0].0 - 1);
                ((lo, hi), chunks[i].to_vec())
            })
            .collect()
    }
}

/// One author's row: written only when a commit touched that author.
#[derive(Clone, Debug, Default)]
pub(crate) struct HeldAuthor {
    /// The committed head, decoded once when it was committed.
    pub(crate) committed: Option<Arc<SignedHead>>,
    /// Every signed head held, by id: the committed one, the highest observed, a conflicting
    /// pair. Each is decoded once and shared, never cloned per connection.
    pub(crate) heads: Vec<(Digest32, Arc<SignedHead>)>,
    /// Two different signed heads of one size: nothing is walked under either.
    pub(crate) conflict: bool,
    /// The walk's floor (set by the author's first committed head): nothing below is owed.
    floor: u64,
    /// Positions whose header is validated here; of those, the ones whose body is held; and
    /// the ones whose admission completed (body held, not needed, or its lifetime over).
    proof: Runs,
    bodies: Runs,
    walked: Runs,
    /// Positions of other authors' sealed key packages whose body this node still owes: a
    /// durable KeyBody obligation keyed by the accepted entry (its fixed source head, author,
    /// position and entry hash), the recipient being the one the signed header names. It
    /// survives a missing body and later heads of the author; only the typed refill or the
    /// package's expiry ends it. The loops ask these bodies explicitly (`RangeWant::Body`).
    owed_bodies: Runs,
    /// What this node knows of the author's controls, kept per author whatever committed head
    /// proved it: coverage from 1 through `controls_covered`, and the positions of the controls
    /// found.
    controls_covered: u64,
    control_positions: Vec<u64>,
    /// The Have this node tells of the author: its newest page, with its heads, proof and
    /// controls; and its older pages of body runs (`AuthorHave::bodies_span`), oldest first.
    pub(crate) have: AuthorHave,
    pages: Vec<AuthorHave>,
}

impl HeldAuthor {
    pub(crate) fn walked(&self, seq: u64) -> bool {
        self.walked.contains(seq)
    }

    /// The positions whose admission completed, as runs.
    pub(crate) fn walked_runs(&self) -> &Runs {
        &self.walked
    }

    /// The positions whose sealed package body this node owes, as runs.
    pub(crate) fn owed_bodies(&self) -> &Runs {
        &self.owed_bodies
    }

    /// This node's Have of the author (its newest page, which carries its heads and proof
    /// runs) and its older pages whose body span meets `lo..=hi`.
    pub(crate) fn pages_over(&self, lo: u64, hi: u64) -> impl Iterator<Item = &AuthorHave> {
        std::iter::once(&self.have).chain(
            self.pages
                .iter()
                .filter(move |page| page.bodies_span.0 <= hi && lo <= page.bodies_span.1),
        )
    }

    pub(crate) fn committed_size(&self) -> u64 {
        self.committed.as_ref().map_or(0, |head| head.root.leaves)
    }

    /// The author's control coverage known from 1, through this position.
    pub(crate) fn controls_covered(&self) -> u64 {
        self.controls_covered
    }

    /// The positions of the author's controls that coverage enumerated, ascending.
    pub(crate) fn control_positions(&self) -> &[u64] {
        &self.control_positions
    }

    /// Position `seq`'s header and body are held here (published with its body), read from the
    /// store's runs whatever the walk's floor: true below the floor too.
    pub(crate) fn held(&self, seq: u64) -> bool {
        self.bodies.contains(seq)
    }

    /// The highest position from `seq` down whose body is not held here (0 when none is).
    pub(crate) fn unheld_below(&self, seq: u64) -> u64 {
        self.bodies.absent_below(seq)
    }

    /// The highest position from `seq` down whose body is held here (0 when none is).
    pub(crate) fn held_below(&self, seq: u64) -> u64 {
        self.bodies.present_below(seq)
    }

    /// Position `seq`'s validated header is held here.
    pub(crate) fn header_held(&self, seq: u64) -> bool {
        self.proof.contains(seq)
    }

    /// The walk's floor: it syncs from here to the committed head (0 before the first commit).
    pub(crate) fn floor(&self) -> u64 {
        self.floor
    }

    /// What the walk still owes, `(lowest, highest)`: from the floor to the committed head, less
    /// the positions admission completed at either end.
    pub(crate) fn window(&self) -> Option<(u64, u64)> {
        let through = self.committed_size();
        if self.floor == 0 || through == 0 || self.conflict {
            return None;
        }
        let (from, to) = (
            self.walked.absent_from(self.floor),
            self.walked.absent_below(through),
        );
        (from <= to).then_some((from, to))
    }

    /// One position's facts, read again after a commit touched it.
    fn position(
        &mut self,
        room: &ChannelState,
        read: &entry_store::Read<'_>,
        author: &Digest32,
        seq: u64,
    ) -> Result<()> {
        let header = read.history_position_header(author, seq)?;
        let walked = match &header {
            Some(header) => completed(room, read, header)?,
            None => false,
        };
        let package = header.as_ref().is_some_and(|header| {
            header
                .skeleton
                .v2
                .as_ref()
                .is_some_and(|v2| v2.kind == SignedEntryKind::KeyPackage)
        });
        // A package's body is held here exactly when its published entry carries it
        // (`Read::history_body_stored`, the fact serving sends from): not when a debt or the
        // missing set says so. Its live debt says only that recovery still owes it, and is
        // owed only while the body is not stored. Every write that changes either touches this
        // position: the debt published or ended (refill or expiry,
        // `Write::keep_history_obligation`, `finish_history_obligation`) and the body stored or
        // withdrawn (`Write::put_committed`). The missing set cannot say it: the effect of a
        // package addressed to another member takes its position out of that set while only its
        // header is held (`finish_history_effect`), and an expired debt leaves it so.
        let held = match &header {
            Some(header) if package => read.history_body_stored(&header.entry_hash())?,
            Some(_) => !read.missing_contains(author, seq)?,
            None => false,
        };
        let owed = package && !held && read.history_key_body_owed_at(author, seq)?.is_some();
        self.proof.set(seq, header.is_some());
        self.bodies.set(seq, held);
        self.walked.set(seq, walked);
        self.owed_bodies.set(seq, owed);
        Ok(())
    }
}

/// A room's record: one row per author of its public history.
#[derive(Debug, Default)]
pub(crate) struct HeldHistory {
    authors: BTreeMap<Digest32, Arc<HeldAuthor>>,
}

impl HeldHistory {
    pub(crate) fn author(&self, author: &Digest32) -> Option<&HeldAuthor> {
        self.authors.get(author).map(|row| &**row)
    }

    /// Every page of every author's Have.
    pub(crate) fn haves(&self) -> impl Iterator<Item = &AuthorHave> {
        self.authors
            .values()
            .flat_map(|row| std::iter::once(&row.have).chain(&row.pages))
    }

    /// A signed head this node holds, by id.
    pub(crate) fn head(&self, id: &Digest32) -> Option<&Arc<SignedHead>> {
        self.authors
            .values()
            .flat_map(|row| &row.heads)
            .find(|(held, _)| held == id)
            .map(|(_, head)| head)
    }
}

/// Admission completed this validated position: its effect finished with its body held, or
/// the body is not needed, or its lifetime is over.
fn completed(room: &ChannelState, read: &entry_store::Read<'_>, header: &Entry) -> Result<bool> {
    let hash = header.entry_hash();
    let content = header
        .skeleton
        .v2
        .as_ref()
        .is_some_and(|v2| v2.kind == SignedEntryKind::Content);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        });
    Ok(read.history_effect_finished(&hash)?
        && (!content
            || read.retention(&hash)?.is_some()
            || room.body_expired(header.skeleton.claimed_ms, crate::time::Ms(now))))
}

/// Admission completed position `seq` of `author` (read from the store: the answer check only).
pub(crate) fn walked(
    room: &ChannelState,
    read: &entry_store::Read<'_>,
    author: &Digest32,
    seq: u64,
) -> Result<bool> {
    match read.history_position_header(author, seq)? {
        Some(header) => completed(room, read, &header),
        None => Ok(false),
    }
}

impl ChannelState {
    /// The record after the commits since `previous` was published: the rows of the authors
    /// they touched are read again, the others are shared as they were. Without a previous
    /// record (a new room instance) or after a rebuilt index, every row is read.
    pub(super) fn held_history(
        &self,
        store: &Store,
        previous: Option<Arc<HeldHistory>>,
    ) -> Result<Arc<HeldHistory>> {
        let touched = store.take_history_touched(&self.channel_id);
        // MP-9: the authors whose fork proof this node holds, each listed in its Have of them
        // with what tells its kept proof apart (`fork_listing`), read from the room as the
        // snapshot's own list of fork proofs is.
        let forks: BTreeMap<Digest32, (Digest32, u64)> = if fork_mutant_is("fork-unpropagated") {
            BTreeMap::new()
        } else {
            self.history_fork_listings()
        };
        let previous = match previous {
            Some(previous) if !touched.all => previous,
            _ => {
                let read = self.history_read(store)?;
                let mut authors = BTreeMap::new();
                let mut after = None;
                while let Some((author, _)) = read.history_author_after(after)? {
                    after = Some(author);
                    if let Some(row) = self.held_author(store, &read, author, None, &[], &forks)? {
                        authors.insert(author, Arc::new(row));
                    }
                }
                return Ok(Arc::new(HeldHistory { authors }));
            }
        };
        let mut changed: BTreeMap<Digest32, Vec<u64>> = touched
            .authors
            .into_iter()
            .map(|(author, positions)| (author, positions.into_iter().collect()))
            .collect();
        // A fork recorded since changes the author's Have: it lists the fork and no longer its
        // unresolved head. So does a kept proof replaced by a lower one (`record_history_fork`):
        // the Have lists the new proof, which a peer holding another may ask for (the fork rule,
        // `pull::FORK_ASKS`).
        for (author, listing) in &forks {
            if previous
                .authors
                .get(author)
                .is_some_and(|row| !row.have.fork || row.have.unresolved != Some(*listing))
            {
                changed.entry(*author).or_default();
            }
        }
        if changed.is_empty() {
            return Ok(previous);
        }
        let read = self.history_read(store)?;
        let mut authors = previous.authors.clone();
        for (author, positions) in changed {
            match self.held_author(
                store,
                &read,
                author,
                authors.get(&author).map(|row| &**row),
                &positions,
                &forks,
            )? {
                Some(row) => authors.insert(author, Arc::new(row)),
                None => authors.remove(&author),
            };
        }
        Ok(Arc::new(HeldHistory { authors }))
    }

    /// One author's row: from `old` with `positions` read again, or whole without `old`.
    fn held_author(
        &self,
        store: &Store,
        read: &entry_store::Read<'_>,
        author: Digest32,
        old: Option<&HeldAuthor>,
        positions: &[u64],
        forks: &BTreeMap<Digest32, (Digest32, u64)>,
    ) -> Result<Option<HeldAuthor>> {
        let Some(state) = read.sparse_author(&author, LogScope::Public)? else {
            return Ok(None);
        };
        let mut row = match old {
            Some(old) => old.clone(),
            None => {
                let (proof, bodies) = read.history_held_runs(&author)?;
                HeldAuthor {
                    proof: Runs(proof),
                    bodies: Runs(bodies),
                    ..HeldAuthor::default()
                }
            }
        };
        for &seq in positions {
            row.position(self, read, &author, seq)?;
        }
        let conflict = state
            .observed_conflict
            .map_or([None, None], |(a, b)| [Some(a), Some(b)]);
        let mut heads = Vec::new();
        for id in [state.committed, state.observed]
            .into_iter()
            .chain(conflict)
            .flatten()
        {
            if heads.iter().any(|(held, _)| *held == id) {
                continue;
            }
            let shared = row
                .heads
                .iter()
                .find(|(held, _)| *held == id)
                .map(|(_, head)| Arc::clone(head));
            let head = match shared {
                Some(head) => head,
                None => match read.history_head(&id)? {
                    Some(head) => Arc::new(head),
                    None => continue,
                },
            };
            heads.push((id, head));
        }
        row.committed = state
            .committed
            .and_then(|id| heads.iter().find(|(held, _)| *held == id))
            .map(|(_, head)| Arc::clone(head));
        row.heads = heads;
        row.conflict = state.observed_conflict.is_some();
        let size = row.committed_size();
        // The walk's floor, set once in the store (`AuthorState::floor`): by the author's first
        // non-empty commit, or, for a store written before floors existed, at its upgrade
        // (`followed_floor`), so every author with a committed head has one.
        row.floor = state.floor;
        // While this node's own history is behind, its whole own prefix is owed, from position
        // 1: native completion needs every own position through the target held
        // (`require_own_recovery_complete`), not only the walk's window.
        if author == self.me() && self.own_behind {
            row.floor = 1;
        }
        if old.is_none() {
            // The walk reads its own positions once, here; below the floor nothing is owed, and
            // a need below it that is already met is found so by the answer check.
            for seq in row.floor.max(1)..=size {
                if row.proof.contains(seq) {
                    row.position(self, read, &author, seq)?;
                }
            }
        }
        // What this node knows of the author's controls, whatever committed head proved it.
        // Coverage from 1 matters only while nothing of the author is admitted here
        // (`controls_first`); once positions are published, each adds its own interval.
        if row.walked.is_empty() {
            row.controls_covered = read.history_controls_covered(&author)?;
        }
        // The author's controls: read whole once, then only the positions a commit touched
        // (a new control source touches its own position); none is ever removed.
        if old.is_none() {
            row.control_positions = read.history_control_positions(&author)?;
        } else {
            for &seq in positions {
                if let Err(at) = row.control_positions.binary_search(&seq) {
                    if read.history_is_control(&author, seq)? {
                        row.control_positions.insert(at, seq);
                    }
                }
            }
        }
        if old.is_none() {
            // Controls outside the walk's positions are read once too: below its floor the
            // author's posts wait for every one of them, and above its committed size a header
            // held under another head is a control like any other. Every key package is a
            // control (`SignedEntryKind::is_control`, kept in `control_sources` at publication),
            // so each package position is read by `HeldAuthor::position`, its body from its
            // stored payload, never from the runs above.
            for seq in row.control_positions.clone() {
                if (seq < row.floor || seq > size) && row.proof.contains(seq) {
                    row.position(self, read, &author, seq)?;
                }
            }
        }
        // Control intervals it answers under its committed head: the run of headers from 1,
        // from which the serving walk rebuilds the head's whole tree. Coverage verified without
        // those headers is kept per author and names no head to answer under.
        let whole = row
            .proof
            .0
            .first()
            .filter(|&&(a, _)| a == 1)
            .map_or(0, |&(_, b)| b.min(size));
        let controls = if whole > 0 {
            vec![(1, whole)]
        } else {
            Vec::new()
        };
        // MP-9 (rule 6): the author's kept unresolved head, as `ServedRoom` lists it (not while
        // the author is frozen, nor once the head is accepted). For an author whose fork is
        // listed (frozen here, so it has no unresolved head), the slot names the kept proof
        // instead (`fork_listing`): what tells a replacement apart, never a head to ask by id.
        let unresolved = if let Some(listing) = forks.get(&author) {
            Some(*listing)
        } else if fork_mutant_is("second-head-unkept") {
            None
        } else {
            self.history_unresolved_hint(read, &author)?
                .map(|hint| (hint.head, hint.leaves))
        };
        let mut pages = row.bodies.pages();
        let (bodies_span, bodies) = pages.pop().unwrap_or(((1, MAX_SEQ), Vec::new()));
        row.have = AuthorHave {
            author,
            heads: row.heads.iter().map(|(_, head)| head.to_wire()).collect(),
            committed: row.committed.is_some(),
            proof: row.proof.newest(),
            bodies,
            controls,
            fork: forks.contains_key(&author),
            unresolved,
            // The exact role-complete head (a receipt hint for the author; the receipt is the
            // author's Control Head(self) exchange, which flushes before answering).
            role: super::room_snapshot::ServedRoom::history_role_head(self, store, &author)
                .ok()
                .flatten()
                .map(|head| (head.id(), head.root.leaves)),
            bodies_span,
        };
        row.pages = pages
            .into_iter()
            .map(|(bodies_span, bodies)| AuthorHave {
                author,
                bodies,
                bodies_span,
                ..AuthorHave::default()
            })
            .collect();
        Ok(Some(row))
    }
}
