//! The room's published read snapshot: what answering another member needs, taken from the room
//! after every committed history write, so that a member's requests for headers, proofs and
//! bodies are authorized and read without the room's lock, the node actor's turn or this node's
//! own pending save.
//!
//! It holds the room's key, its epoch, who its authors and members are, who left and who may
//! recover its own history, frozen authors and the two signed headers of each fork proof that
//! froze one (MP-9), inventory incarnations and role state. It holds no
//! history: every read opens its own store read transaction under the key, so it sees redb's
//! committed roots, and every read checks the peer's applied removal and the recipient cut in the
//! store itself, as the room-locked reads did.
use super::sparse_history::{HistoryHeadHint, HistoryHeadPage, HistoryHeader};
use super::*;
use crate::log::history::{ControlContext, LogScope, SignedHead};
use std::sync::Mutex as StdMutex;

/// The facts of one room published after a committed history write (see the module).
pub(crate) struct RoomSnapshot {
    admission: sparse_history::PendingHistoryAdmission,
    authors: BTreeSet<Digest32>,
    left: BTreeSet<Digest32>,
    frozen: BTreeSet<Digest32>,
    /// Rule F2: each frozen author's recorded boundary (`governance::splits`), as the
    /// room knew it at publication: what meets a parked entry's fork wait (`pull::Need::Fork`).
    fork_boundaries: BTreeMap<Digest32, u64>,
    /// MP-9: per frozen author whose kept proof is still signed, its two signed entry headers:
    /// what `Query::Fork` serves (the Have's fork flag is the record's, `held_history`).
    forks: BTreeMap<Digest32, (Vec<u8>, Vec<u8>)>,
    back: BTreeMap<Digest32, u64>,
    left_at: BTreeMap<Digest32, u64>,
    recovery: BTreeSet<Digest32>,
    creator: Digest32,
    now_hint: u64,
    /// Whether the room syncs by bounded history requests at all.
    sparse: bool,
    /// What this node holds of each author's history, as the commits up to this publication
    /// left it; absent for a room without bounded history, or when it could not be read (the
    /// next publication reads it whole).
    history: Option<Arc<held_history::HeldHistory>>,
    /// The room's generation at this publication: what a Have told from `history` credits.
    generation: u64,
    /// The peers this room's private serve would answer now (room and peer preconditions,
    /// `ChannelState::private_have_peers`); a Have tells each of them only a position a native
    /// discovery found it may be served (`pull::tell`). Empty while this node cannot serve
    /// private Sessions; `None` while the room cannot decide (its governance refreshing, its
    /// Session upgrade work running): then nobody is told anything and a teller keeps its walk
    /// until a publication that can decide.
    private_peers: Option<BTreeSet<Digest32>>,
    /// The room's private permission generation as this publication read it: moved by every
    /// committed Session floor or floor-source change (`private_index::permission_generation`).
    /// `None`: unreadable.
    private_permission: Option<u64>,
}

/// Where a room publishes its [`RoomSnapshot`]; empty while the room is poisoned, locked or gone.
/// Every publication (and revocation) wakes the answers waiting for the room's next commit.
pub(crate) struct RoomSnapshotCell {
    current: StdMutex<Option<Arc<RoomSnapshot>>>,
    published: tokio::sync::watch::Sender<()>,
}

impl Default for RoomSnapshotCell {
    fn default() -> Self {
        Self {
            current: StdMutex::new(None),
            published: tokio::sync::watch::Sender::new(()),
        }
    }
}

impl RoomSnapshotCell {
    pub(crate) fn current(&self) -> Option<Arc<RoomSnapshot>> {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    /// Subscribe before a read: the receiver wakes at the next publication after it.
    pub(crate) fn next_publication(&self) -> tokio::sync::watch::Receiver<()> {
        self.published.subscribe()
    }
    fn set(&self, snapshot: Option<Arc<RoomSnapshot>>) {
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = snapshot;
        self.published.send_replace(());
    }
    pub(crate) fn revoke(&self) {
        self.set(None);
    }
}

impl RoomSnapshot {
    pub(crate) fn room(&self) -> Digest32 {
        self.admission.room
    }
    /// Whether this room's private serve would answer `peer` now (ruling (b)); `None` while the
    /// room cannot decide (`private_peers`). Not read authorization: a Have tells such a peer
    /// only what a native discovery found servable.
    pub(crate) fn private_peer(&self, peer: &Digest32) -> Option<bool> {
        self.private_peers
            .as_ref()
            .map(|peers| peers.contains(peer))
    }
    /// The private permission generation this publication read (`private_permission`).
    pub(crate) fn private_permission(&self) -> Option<u64> {
        self.private_permission
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.admission.epoch
    }
    pub(crate) fn sparse(&self) -> bool {
        self.sparse
    }
    pub(crate) fn history(&self) -> Option<&Arc<held_history::HeldHistory>> {
        self.history.as_ref()
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    /// This node, as the room knows it.
    pub(crate) fn me(&self) -> Digest32 {
        self.admission.me
    }
    pub(crate) fn is_author(&self, id: &Digest32) -> bool {
        self.authors.contains(id)
    }
    pub(crate) fn has_left(&self, id: &Digest32) -> bool {
        !departed_as_member(id, &self.admission.me) && self.left.contains(id)
    }
    pub(crate) fn is_member(&self, id: &Digest32) -> bool {
        self.is_author(id) && !self.has_left(id)
    }
    /// A departed author's narrow standing to recover its own signed history, as the room
    /// judged it when this snapshot was published.
    pub(crate) fn recovery_standing(&self, id: &Digest32) -> bool {
        if self.has_left(id) {
            self.recovery.contains(id)
        } else {
            self.is_member(id)
        }
    }
    /// The peer's [`Standing`] here, as the room judged it at publication ([`standing`]).
    pub(crate) fn standing(&self, peer: &Digest32) -> Option<Standing> {
        standing(
            self.is_member(peer),
            self.is_author(peer) && self.has_left(peer),
            self.has_left(peer) && self.recovery.contains(peer),
        )
    }
    /// The position of the author's departure, while it has left.
    pub(crate) fn left_at(&self, author: &Digest32) -> Option<u64> {
        self.left_at.get(author).copied()
    }
    /// An author frozen by fork evidence (MP-9a), as the room knew it at publication.
    pub(crate) fn is_frozen(&self, id: &Digest32) -> bool {
        self.frozen.contains(id)
    }
    /// Rule F2: a frozen author's recorded boundary, as the room knew it at publication.
    pub(crate) fn fork_boundary(&self, id: &Digest32) -> Option<u64> {
        self.fork_boundaries.get(id).copied()
    }
    /// The peer's current removal, read in the store; never from the snapshot.
    pub(crate) fn peer_removal_applied(&self, store: &Store, peer: &Digest32) -> Result<bool> {
        self.admission
            .with(|room| governance::peer_removal_applied(store, room.sek(), &self.room(), peer))
    }
    /// Run one bounded read against the committed store under this snapshot's key.
    pub(crate) fn with<T>(&self, read: impl FnOnce(&mut RoomView<'_>) -> Result<T>) -> Result<T> {
        self.admission.with(|room| {
            read(&mut RoomView {
                snapshot: self,
                room,
            })
        })
    }
}

/// One read under a [`RoomSnapshot`]: its facts and the committed store.
pub(crate) struct RoomView<'a> {
    snapshot: &'a RoomSnapshot,
    room: &'a HistoryAdmission<'a>,
}

impl<'a> RoomView<'a> {
    /// The committed-history reader the existing admission verifiers take.
    pub(super) fn admission(&self) -> &'a HistoryAdmission<'a> {
        self.room
    }
}

/// `VOX_TEST_DEPARTED_AS_MEMBER_FILE` with the `sync-departed-peer` mutant: a departed peer
/// counts as a member (test-knobs only), read at each use as [`ChannelState::has_left`] reads it.
pub(super) fn departed_as_member(author: &Digest32, me: &Digest32) -> bool {
    #[cfg(feature = "test-knobs")]
    {
        author != me
            && crate::node::computer::fx28_mutant("sync-departed-peer")
            && std::env::var_os("VOX_TEST_DEPARTED_AS_MEMBER_FILE")
                .is_some_and(|path| std::path::Path::new(&path).is_file())
    }
    #[cfg(not(feature = "test-knobs"))]
    {
        let _ = (author, me);
        false
    }
}

/// `VOX_MUTANT_POISON_KEEPS_SNAPSHOT` (test-knobs only): a poisoned room keeps the snapshot it
/// last published, through its poisoning and every publication after it; said as it is poisoned.
fn poison_keeps_snapshot(room: &Digest32, say: bool) -> bool {
    #[cfg(feature = "test-knobs")]
    if std::env::var_os("VOX_MUTANT_POISON_KEEPS_SNAPSHOT").is_some() {
        if say {
            eprintln!(
                "vox: VOX_MUTANT_POISON_KEEPS_SNAPSHOT engaged: room {} keeps its snapshot",
                crate::node::link::b32_encode(room)
            );
        }
        return true;
    }
    let _ = (room, say);
    false
}

/// Whether a room is poisoned (a failed save; it refuses until reopened). Its field is private to
/// this module, so [`ChannelState::mark_poisoned`] is the only code that can set it, and it
/// revokes the room's published snapshot in the same step.
#[derive(Debug, Default)]
pub(super) struct Poisoned(bool);

impl Poisoned {
    pub(super) fn get(&self) -> bool {
        self.0
    }
}

/// Who a peer is to this room: the one rule for what this node serves the peer
/// (`history_stream/source.rs` access checks, `actor.rs` `run_sync_session`) and whether a
/// connection's loop keeps telling it (`history_stream/pull.rs` `standing`, its `current`,
/// `actor.rs` `start_pull_loops`, `actor/admission.rs` `retire_departed_port`). The peer's
/// applied removal ends every standing; its callers read it in the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// A current member: everything a member is served and told.
    Member,
    /// A departed author with a verified admission after its departure (recovery standing):
    /// its own public tree, its own receipt and its own row; nothing else.
    Returning,
    /// A departed author: its own departure receipt and its own row; nothing else.
    Departed,
}

/// [`Standing`] from the room's facts: `member`, `departed_author` (an author that left), and
/// `recovery` (a departed author's recovery standing).
pub(crate) fn standing(member: bool, departed_author: bool, recovery: bool) -> Option<Standing> {
    if member {
        Some(Standing::Member)
    } else if departed_author && recovery {
        Some(Standing::Returning)
    } else if departed_author {
        Some(Standing::Departed)
    } else {
        None
    }
}

impl ChannelState {
    /// The peer's [`Standing`] here, read from the room itself ([`standing`]).
    pub(crate) fn standing(&self, store: &Store, peer: &Digest32) -> Result<Option<Standing>> {
        let departed_author = self.is_author(peer) && self.has_left(peer);
        Ok(standing(
            self.is_member(peer),
            departed_author,
            departed_author && self.recovery_standing(store, peer)?,
        ))
    }

    /// The cell serving reads this room's published snapshot from.
    pub(crate) fn room_snapshot(&self) -> Arc<RoomSnapshotCell> {
        Arc::clone(&self.room_snapshot)
    }

    /// Publish what serving needs after a committed history write. A poisoned room publishes
    /// nothing (see [`Self::mark_poisoned`]).
    pub(crate) fn publish_room_snapshot(&self, store: &Store) {
        let snapshot = if !self.poisoned.get() {
            self.capture_room_snapshot(store).ok().map(Arc::new)
        } else if poison_keeps_snapshot(&self.channel_id, false) {
            return;
        } else {
            None
        };
        self.room_snapshot.set(snapshot);
    }

    /// The one way a room becomes poisoned. Its published snapshot is revoked in the same step,
    /// so a poisoned room answers nobody's request: there is no snapshot to answer from, and none
    /// is published while it stays poisoned. Its storage recovery opens a new room instance,
    /// which publishes its own snapshot when the actor installs it (`Node::open_room`).
    pub(super) fn mark_poisoned(&mut self) {
        let keeps = poison_keeps_snapshot(&self.channel_id, !self.poisoned.get());
        self.poisoned = Poisoned(true);
        if !keeps {
            self.room_snapshot.revoke();
        }
    }

    fn capture_room_snapshot(&self, store: &Store) -> Result<RoomSnapshot> {
        let authors: BTreeSet<Digest32> = self.authors.keys().copied().collect();
        let left: BTreeSet<Digest32> = authors
            .iter()
            .filter(|author| self.departed(author))
            .copied()
            .collect();
        let sparse = self.uses_sparse_history(store)?;
        Ok(RoomSnapshot {
            admission: self.served_history_admission(store)?,
            back: authors
                .iter()
                .filter_map(|author| {
                    let presence = self.presence.get(author)?;
                    presence.back.map(|(seq, _)| (*author, seq))
                })
                .collect(),
            left_at: authors
                .iter()
                .filter_map(|author| self.left_at(author).map(|seq| (*author, seq)))
                .collect(),
            frozen: authors
                .iter()
                .filter(|author| self.dag.is_frozen(author))
                .copied()
                .collect(),
            fork_boundaries: self.history_splits(store)?.boundaries().collect(),
            forks: self
                .dag
                .fork_proofs()
                .into_iter()
                .filter(|proof| signed_fork(proof))
                .map(|proof| {
                    (
                        proof.author_id,
                        (
                            proof.existing.header_wire(),
                            proof.conflicting.header_wire(),
                        ),
                    )
                })
                .collect(),
            recovery: left
                .iter()
                .filter(|author| self.recovery_standing(store, author).unwrap_or(false))
                .copied()
                .collect(),
            creator: self.genesis.creator_pubkey().fingerprint(),
            now_hint: self.now_hint,
            sparse,
            history: sparse
                .then(|| {
                    let previous = self.room_snapshot.current().and_then(|s| s.history.clone());
                    self.held_history(store, previous).ok()
                })
                .flatten(),
            generation: self.gen.load(std::sync::atomic::Ordering::Acquire),
            private_permission: super::session_projection::private_index::permission_generation(
                store,
                &self.channel_id,
            )
            .ok(),
            private_peers: self.private_have_peers(store),
            authors,
            left,
        })
    }

    /// MP-9: the authors this node holds a verified, still-signed fork proof for, ascending,
    /// each with what its Have says of the kept proof (`fork_listing`): what its Have lists so
    /// a peer that never met the second history, or holds an older proof, can ask for it.
    pub(super) fn history_fork_listings(&self) -> BTreeMap<Digest32, (Digest32, u64)> {
        self.dag
            .fork_proofs()
            .into_iter()
            .filter(|proof| signed_fork(proof))
            .take(crate::log::history::MAX_CONTEXT_AUTHORS)
            .map(|proof| (proof.author_id, fork_listing(proof)))
            .collect()
    }

    /// What this node's Have says of the proof it keeps for `author` (`fork_listing`), if it
    /// keeps one: what the fork rule compares a peer's listing with (`pull::FORK_ASKS` (c)).
    pub(crate) fn history_fork_listing(&self, author: &Digest32) -> Option<(Digest32, u64)> {
        self.dag.fork_proof(author).map(fork_listing)
    }
}

/// What a Have lists of a kept fork proof besides its fork flag, in the author's `unresolved`
/// slot, which is otherwise empty for a frozen author: a digest of the proof's two entry hashes,
/// in byte order (so one pair is one identity whichever entry a node held first), and its
/// position. A proof replaced by a lower one (`record_history_fork`) lists another, so the Have
/// is told again. A peer never trusts it: it only spares asking for a proof the peer already
/// holds, and its position gates nothing (the fork rule, `pull::FORK_ASKS`). No new wire field.
fn fork_listing(proof: &ForkProof) -> (Digest32, u64) {
    let (a, b) = (proof.existing.entry_hash(), proof.conflicting.entry_hash());
    let mut hashes = [0u8; 64];
    hashes[..32].copy_from_slice(&a.min(b));
    hashes[32..].copy_from_slice(&a.max(b));
    (crate::hash::sha256(&hashes), proof.seq)
}

/// A fork proof whose two entries still carry their signatures: the only kind that is listed or
/// served (MP-9). A peer verifies what it receives; an unsigned pair would prove nothing to it.
fn signed_fork(proof: &ForkProof) -> bool {
    proof.existing.is_signed() && proof.conflicting.is_signed()
}

/// What a served request reads, whether through the room (a client's own flow) or through the
/// room's published snapshot (an answer to another member). The provided reads use only the
/// committed store under the room's key.
pub(crate) trait ServedRoom {
    fn channel_id(&self) -> Digest32;
    fn me(&self) -> Digest32;
    fn epoch(&self) -> u64;
    fn is_author(&self, id: &Digest32) -> bool;
    fn has_left(&self, id: &Digest32) -> bool;
    fn is_member(&self, id: &Digest32) -> bool {
        self.is_author(id) && !self.has_left(id)
    }
    fn history_inventory_incarnation(&self, member: &Digest32) -> Option<u64>;
    fn history_author_inventory_incarnation(&self, author: &Digest32) -> Option<u64>;
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>>;
    /// This node's Have pages of `author` whose body span meets `lo..=hi`, as its last
    /// publication recorded them (the newest page, with its heads, first when it meets it).
    fn held_pages(
        &self,
        author: &Digest32,
        lo: u64,
        hi: u64,
    ) -> Vec<crate::node::history_stream::AuthorHave>;
    fn recipient_body_eligibility(
        &self,
        store: &Store,
        recipient: &Digest32,
        entry: &Entry,
    ) -> Result<governance::ContentEligibility>;
    /// An author frozen by a fork proof (MP-9a): its later history is refused, so nothing of it
    /// is fetched, and its unresolved head is not listed.
    fn history_author_frozen(&self, author: &Digest32) -> bool;
    /// MP-9: the two signed headers of the proof this node verified and kept for `author`.
    /// No body and no key material travel.
    fn history_fork_proof(&self, author: &Digest32) -> Option<(Vec<u8>, Vec<u8>)>;
    /// MP-9: of the authors a peer lists, the first one this node has not frozen and whose key
    /// it holds. A listing never makes this node ask for more than one at a time.
    fn history_fork_wanted(&self, authors: &[Digest32]) -> Option<Digest32> {
        authors
            .iter()
            .copied()
            .find(|author| !self.history_author_frozen(author) && self.is_author(author))
    }
    /// MP-9 (rule 6): the author's kept signed head whose continuity with the accepted chain is
    /// still unresolved: what this node's Have of the author lists so a peer holding the other
    /// history can fetch it by id and compare. An author frozen by a fork proof, or a head
    /// accepted since, is resolved and not listed. At most one per author.
    fn history_unresolved_hint(
        &self,
        read: &entry_store::Read<'_>,
        author: &Digest32,
    ) -> Result<Option<HistoryHeadHint>> {
        if self.history_author_frozen(author) {
            return Ok(None);
        }
        let Some(id) = read.history_unresolved_head(author)? else {
            return Ok(None);
        };
        let Some(head) = read.history_head(&id)? else {
            return Ok(None);
        };
        if read.history_head_accepted(&id, head.binding)? {
            return Ok(None);
        }
        Ok(Some(HistoryHeadHint {
            author: *author,
            leaves: head.root.leaves,
            head: id,
        }))
    }
    fn history_head_by_id(&self, store: &Store, head: &Digest32) -> Result<Option<SignedHead>> {
        let read = self.history_read(store)?;
        let Some(value) = read.history_head(head)? else {
            return Ok(None);
        };
        // MP-9 (rule 6): besides committed heads, the one kept unresolved head of an author is
        // served by its id, with what this node proved under it; the asker's own gates decide.
        if read.history_head_committed(head, value.binding)?
            || read.history_unresolved_head(&value.binding.author)? == Some(*head)
        {
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// One bounded page of commitments (archive paging's newest selection). No scan or
    /// signed-head vector survives this read.
    fn history_head_hints(
        &self,
        store: &Store,
        after: Option<Digest32>,
    ) -> Result<HistoryHeadPage> {
        let read = self.history_read(store)?;
        let mut next = after;
        let mut heads = Vec::new();
        for _ in 0..64 {
            let Some((author, state)) = read.history_author_after(next)? else {
                return Ok(HistoryHeadPage { heads, next: None });
            };
            next = Some(author);
            if let Some(id) = state.committed {
                let head = read
                    .history_head(&id)?
                    .ok_or(Error::MalformedAtRest("committed history head missing"))?;
                heads.push(HistoryHeadHint {
                    author,
                    leaves: head.root.leaves,
                    head: id,
                });
            }
        }
        Ok(HistoryHeadPage { heads, next })
    }
    /// The latest consistency-accepted commitment. It is not a control-ready or contiguous
    /// position, and serving it does not change either state.
    fn history_head(&self, store: &Store, author: &Digest32) -> Result<Option<SignedHead>> {
        let read = self.history_read(store)?;
        let Some(id) = read
            .sparse_author(author, LogScope::Public)?
            .and_then(|state| state.committed)
        else {
            return Ok(None);
        };
        read.history_head(&id)
    }

    /// A durable context, or one a serving reconstruction generated for an asked prefix and
    /// still holds only in the serving cache (ADR-053 P). Both are content-addressed.
    fn history_context(&self, store: &Store, hash: &Digest32) -> Result<Option<ControlContext>> {
        Ok(match self.history_read(store)?.history_context(hash)? {
            Some(context) => Some(context),
            None => entry_store::sparse::serving_context(&self.channel_id(), hash),
        })
    }

    fn history_header(
        &self,
        store: &Store,
        author: &Digest32,
        seq: u64,
    ) -> Result<Option<HistoryHeader>> {
        self.history_read(store)?
            .history_position_header(author, seq)?
            .map(|entry| {
                Ok(HistoryHeader {
                    wire: entry.header_wire(),
                })
            })
            .transpose()
    }

    /// Return only a retained signed commitment exactly at this node's completed role cut.
    /// A newer accepted commitment is metadata, not a receipt for its unfinished source.
    fn history_role_head(&self, store: &Store, author: &Digest32) -> Result<Option<SignedHead>> {
        let read = self.history_read(store)?;
        let Some(state) = read.sparse_author(author, LogScope::Public)? else {
            return Ok(None);
        };
        let (through, hash) = read.history_held_through(author).unwrap_or((0, [0; 32]));
        let source = if through == 0 {
            None
        } else {
            read.history_validated_header(author, through)?
                .map(|(head, _)| head)
        };
        for id in [state.committed, source].into_iter().flatten() {
            let head = read
                .history_head(&id)?
                .ok_or(Error::MalformedAtRest("role receipt head missing"))?;
            if head.id() != id
                || head.binding.room != self.channel_id()
                || head.binding.author != *author
                || head.binding.scope != LogScope::Public
            {
                return Err(Error::MalformedAtRest("role receipt head binding"));
            }
            if head.root.leaves != through || !read.history_head_committed(&id, head.binding)? {
                continue;
            }
            if through != 0 {
                let Some(included) = read.history_inclusion_receipt(&id, author, through)? else {
                    continue;
                };
                if included.head_id() != id
                    || included.binding() != head.binding
                    || included.root() != head.root
                    || included.header().entry().skeleton.seq != through
                {
                    return Err(Error::MalformedAtRest("role receipt inclusion binding"));
                }
                if included.header().entry().entry_hash() != hash {
                    continue;
                }
            }
            return Ok(Some(head));
        }
        Ok(None)
    }

    /// Metadata-only fallback: an exact sealed inclusion receipt can retain a signed header
    /// before its source/effect has reached the canonical position index. This never supplies
    /// Entry/Page bodies or publishes a canonical position. The receipt is the resolved source
    /// head's: its prefix through the asked size is the asked head's (ADR-053 P). Under a source
    /// in the accepted chain a receipt kept under another head of that chain names the same
    /// entry at this position, so it is found by author and position.
    fn history_proof_header(
        &self,
        store: &Store,
        target: &super::ResolvedTarget,
        seq: u64,
    ) -> Result<Option<HistoryHeader>> {
        let read = self.history_read(store)?;
        let binding = target.target.binding;
        // An admitted position is under the accepted chain only. Under another signed head
        // (MP-9: an unresolved second history, served as itself) only an entry proven under
        // that head is served. A prefix resolved to a committed source is under that chain.
        let accepted = read.history_head_accepted(&target.source, binding)?;
        if accepted {
            if let Some(entry) = read.history_position_header(&binding.author, seq)? {
                return Ok(Some(HistoryHeader {
                    wire: entry.header_wire(),
                }));
            }
        }
        let source = read
            .history_head(&target.source)?
            .ok_or(Error::MalformedAtRest("proof header source head missing"))?;
        let included = match read.history_inclusion_receipt(&target.source, &binding.author, seq)? {
            Some(included) => {
                if included.head_id() != target.source || included.root() != source.root {
                    return Err(Error::MalformedAtRest("proof header receipt binding"));
                }
                included
            }
            None if accepted && seq <= source.root.leaves => {
                match read.history_included_header(&binding.author, seq)? {
                    Some(included) => included,
                    None => return Ok(None),
                }
            }
            None => return Ok(None),
        };
        let entry = included.header().entry();
        if included.binding() != binding
            || entry.skeleton.channel_id != self.channel_id()
            || entry.skeleton.author_id != binding.author
            || entry.skeleton.seq != seq
        {
            return Err(Error::MalformedAtRest("proof header receipt binding"));
        }
        Ok(Some(HistoryHeader {
            wire: entry.header_wire(),
        }))
    }

    /// Decode and authenticate one body once under the caller's large-record envelope.
    /// The response driver borrows its chunks for this quantum and drops the body before
    /// yielding; it must not call whole-record AEAD once for every 64-KiB frame.
    fn history_payload(&self, store: &Store, hash: &Digest32) -> Result<HistoryPayload> {
        let read = self.history_read(store)?;
        let Some(entry) = read.history_entry(hash)? else {
            return Ok(HistoryPayload::Missing);
        };
        if entry.skeleton.v2.is_none() {
            return Err(Error::MalformedAtRest("legacy entry in activated history"));
        }
        let payload_len = entry.skeleton.payload_len;
        let Some(payload) = entry.payload else {
            return Ok(HistoryPayload::BodyNotHeld { payload_len });
        };
        if payload.len() as u64 != payload_len || sha256(&payload) != entry.skeleton.payload_hash {
            return Err(Error::MalformedAtRest(
                "stored history payload differs from header",
            ));
        }
        Ok(HistoryPayload::Held {
            payload_len,
            bytes: payload,
        })
    }

    fn recovery_context_allowed(
        &self,
        store: &Store,
        author: &Digest32,
        context: &Digest32,
    ) -> Result<bool> {
        let read = self.history_read(store)?;
        let Some(id) = read.recovery_context_head(author, context)? else {
            return Ok(false);
        };
        let head = read
            .history_head(&id)?
            .ok_or(Error::MalformedAtRest("recovery context head missing"))?;
        Ok(head.binding.room == self.channel_id()
            && head.binding.author == *author
            && head.binding.scope == LogScope::Public)
    }
}

impl ServedRoom for ChannelState {
    fn channel_id(&self) -> Digest32 {
        ChannelState::channel_id(self)
    }
    fn me(&self) -> Digest32 {
        ChannelState::me(self)
    }
    fn epoch(&self) -> u64 {
        ChannelState::epoch(self)
    }
    fn is_author(&self, id: &Digest32) -> bool {
        ChannelState::is_author(self, id)
    }
    fn has_left(&self, id: &Digest32) -> bool {
        ChannelState::has_left(self, id)
    }
    fn history_inventory_incarnation(&self, member: &Digest32) -> Option<u64> {
        ChannelState::history_inventory_incarnation(self, member)
    }
    fn history_author_inventory_incarnation(&self, author: &Digest32) -> Option<u64> {
        ChannelState::history_author_inventory_incarnation(self, author)
    }
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>> {
        ChannelState::history_read(self, store)
    }
    fn held_pages(
        &self,
        author: &Digest32,
        lo: u64,
        hi: u64,
    ) -> Vec<crate::node::history_stream::AuthorHave> {
        let snapshot = self.room_snapshot.current();
        let row = snapshot
            .as_ref()
            .and_then(|s| s.history())
            .and_then(|h| h.author(author));
        row.map(|row| row.pages_over(lo, hi).cloned().collect())
            .unwrap_or_default()
    }
    fn recipient_body_eligibility(
        &self,
        store: &Store,
        recipient: &Digest32,
        entry: &Entry,
    ) -> Result<governance::ContentEligibility> {
        ChannelState::recipient_body_eligibility(self, store, recipient, entry)
    }
    fn history_author_frozen(&self, author: &Digest32) -> bool {
        self.dag.is_frozen(author)
    }
    fn history_fork_proof(&self, author: &Digest32) -> Option<(Vec<u8>, Vec<u8>)> {
        let proof = self.dag.fork_proof(author)?;
        signed_fork(proof).then(|| {
            (
                proof.existing.header_wire(),
                proof.conflicting.header_wire(),
            )
        })
    }
}

impl ServedRoom for RoomView<'_> {
    fn channel_id(&self) -> Digest32 {
        self.snapshot.room()
    }
    fn me(&self) -> Digest32 {
        self.snapshot.admission.me
    }
    fn epoch(&self) -> u64 {
        self.snapshot.epoch()
    }
    fn is_author(&self, id: &Digest32) -> bool {
        self.snapshot.is_author(id)
    }
    fn has_left(&self, id: &Digest32) -> bool {
        self.snapshot.has_left(id)
    }
    fn history_inventory_incarnation(&self, member: &Digest32) -> Option<u64> {
        self.is_member(member)
            .then(|| self.snapshot.back.get(member).copied().unwrap_or(0))
    }
    fn history_author_inventory_incarnation(&self, author: &Digest32) -> Option<u64> {
        self.is_author(author).then(|| {
            self.snapshot
                .left_at
                .get(author)
                .or_else(|| self.snapshot.back.get(author))
                .copied()
                .unwrap_or(0)
        })
    }
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>> {
        HistoryAdmissionRoom::history_read(self.room, store)
    }
    fn held_pages(
        &self,
        author: &Digest32,
        lo: u64,
        hi: u64,
    ) -> Vec<crate::node::history_stream::AuthorHave> {
        let row = self.snapshot.history().and_then(|h| h.author(author));
        row.map(|row| row.pages_over(lo, hi).cloned().collect())
            .unwrap_or_default()
    }
    fn recipient_body_eligibility(
        &self,
        store: &Store,
        recipient: &Digest32,
        entry: &Entry,
    ) -> Result<governance::ContentEligibility> {
        governance::recipient_body_eligibility_at(
            store,
            self.room.sek(),
            &self.channel_id(),
            self.snapshot.creator,
            self.snapshot.now_hint,
            recipient,
            entry,
        )
    }
    fn history_author_frozen(&self, author: &Digest32) -> bool {
        self.snapshot.is_frozen(author)
    }
    fn history_fork_proof(&self, author: &Digest32) -> Option<(Vec<u8>, Vec<u8>)> {
        self.snapshot.forks.get(author).cloned()
    }
}
