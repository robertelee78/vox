//! The room's published read snapshot: what answering another member needs, taken from the room
//! after every committed history write, so that a request is authorized and read without the
//! room's lock, the node actor's turn or this node's own pending save.
//!
//! It holds the room's key, its epoch, who its authors and members are, who left and who may
//! recover its own history, frozen authors, inventory incarnations and role state. It holds no
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
    back: BTreeMap<Digest32, u64>,
    left_at: BTreeMap<Digest32, u64>,
    held: BTreeMap<Digest32, u64>,
    recovery: BTreeSet<Digest32>,
    availability: BTreeMap<Digest32, Arc<availability::Peer>>,
    creator: Digest32,
    now_hint: u64,
    /// Whether the room syncs by bounded history requests at all.
    sparse: bool,
}

/// Where a room publishes its [`RoomSnapshot`]; empty while the room is poisoned, locked or gone.
#[derive(Default)]
pub(crate) struct RoomSnapshotCell(StdMutex<Option<Arc<RoomSnapshot>>>);

impl RoomSnapshotCell {
    pub(crate) fn current(&self) -> Option<Arc<RoomSnapshot>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn set(&self, snapshot: Option<Arc<RoomSnapshot>>) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = snapshot;
    }
    pub(crate) fn revoke(&self) {
        self.set(None);
    }
}

impl RoomSnapshot {
    pub(crate) fn room(&self) -> Digest32 {
        self.admission.room
    }
    pub(crate) fn epoch(&self) -> u64 {
        self.admission.epoch
    }
    pub(crate) fn sparse(&self) -> bool {
        self.sparse
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
    /// An author frozen by fork evidence (MP-9a), as the room knew it at publication.
    pub(crate) fn is_frozen(&self, id: &Digest32) -> bool {
        self.frozen.contains(id)
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

impl ChannelState {
    /// The cell serving reads this room's published snapshot from.
    pub(crate) fn room_snapshot(&self) -> Arc<RoomSnapshotCell> {
        Arc::clone(&self.room_snapshot)
    }

    /// Publish what serving needs after a committed history write. A poisoned room serves
    /// nothing, as its room-locked reads did not.
    pub(crate) fn publish_room_snapshot(&self, store: &Store) {
        let snapshot = if self.poisoned {
            None
        } else {
            self.capture_room_snapshot(store).ok().map(Arc::new)
        };
        self.room_snapshot.set(snapshot);
    }

    fn capture_room_snapshot(&self, store: &Store) -> Result<RoomSnapshot> {
        let authors: BTreeSet<Digest32> = self.authors.keys().copied().collect();
        let left: BTreeSet<Digest32> = authors
            .iter()
            .filter(|author| self.departed(author))
            .copied()
            .collect();
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
            held: self.held.clone(),
            recovery: left
                .iter()
                .filter(|author| self.recovery_standing(store, author).unwrap_or(false))
                .copied()
                .collect(),
            availability: self.availability.peers(),
            creator: self.genesis.creator_pubkey().fingerprint(),
            now_hint: self.now_hint,
            sparse: self.uses_sparse_history(store)?,
            authors,
            left,
        })
    }
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
    fn held_through(&self, member: &Digest32) -> Option<u64>;
    fn history_inventory_incarnation(&self, member: &Digest32) -> Option<u64>;
    fn history_author_inventory_incarnation(&self, author: &Digest32) -> Option<u64>;
    fn role_owed(&self) -> Arc<role_owed::RoleOwed>;
    fn availability_peer(&mut self, author: Digest32) -> Result<Arc<availability::Peer>>;
    fn history_instance(&self, store: &Store) -> Result<[u8; 16]>;
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>>;
    fn history_sek(&self) -> &Sek;
    fn recipient_body_eligibility(
        &self,
        store: &Store,
        recipient: &Digest32,
        entry: &Entry,
    ) -> Result<governance::ContentEligibility>;
    fn history_departure_matches(
        &self,
        store: &Store,
        hint: crate::node::history_stream::HeadHint,
    ) -> Result<bool>;
    fn forget_history_decline(
        &self,
        store: &Store,
        peer: Digest32,
        author: Digest32,
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<()>;
    fn history_head_by_id(&self, store: &Store, head: &Digest32) -> Result<Option<SignedHead>> {
        let read = self.history_read(store)?;
        let Some(value) = read.history_head(head)? else {
            return Ok(None);
        };
        if read.history_head_committed(head, value.binding)? {
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// One bounded page of commitments. No scan or signed-head vector survives this read.
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
        for id in [state.committed, state.control_ready, source]
            .into_iter()
            .flatten()
        {
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
    /// head's: its prefix through the asked size is the asked head's (ADR-053 P).
    fn history_proof_header(
        &self,
        store: &Store,
        target: &super::ResolvedTarget,
        seq: u64,
    ) -> Result<Option<HistoryHeader>> {
        let read = self.history_read(store)?;
        let binding = target.target.binding;
        if let Some(entry) = read.history_position_header(&binding.author, seq)? {
            return Ok(Some(HistoryHeader {
                wire: entry.header_wire(),
            }));
        }
        let Some(included) =
            read.history_inclusion_receipt(&target.source, &binding.author, seq)?
        else {
            return Ok(None);
        };
        let source = read
            .history_head(&target.source)?
            .ok_or(Error::MalformedAtRest("proof header source head missing"))?;
        let entry = included.header().entry();
        if included.head_id() != target.source
            || included.binding() != binding
            || included.root() != source.root
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
    /// Enumerate one locally held sealed package using the durable acquisition cursor.
    /// An ineligible catalog entry advances the cursor without advertising it.
    fn history_key_available_page(
        &self,
        store: &Store,
        after: Option<u64>,
    ) -> Result<Option<(u64, Option<crate::node::history_stream::KeyBodyAvailable>)>> {
        let read = self.history_read(store)?;
        let Some((cursor, log)) = read.key_package_after(after)? else {
            return Ok(None);
        };
        let sealed = store
            .snapshot()?
            .get_segment_bounded(
                &self.channel_id(),
                SegmentKind::LogDb,
                log,
                crate::node::keypackage::MAX_KEY_PACKAGE
                    + crate::log::history::MAX_HEADER_BYTES
                    + 9,
            )?
            .ok_or(Error::MalformedAtRest("key-package catalog body missing"))?;
        let wire = open_segment(self.history_sek(), SegmentKind::LogDb, log, &sealed)?;
        let entry = Entry::from_wire(&wire)?;
        entry.verify_payload_binding()?;
        let Some(v2) = entry.skeleton.v2.as_ref() else {
            return Ok(Some((cursor, None)));
        };
        if v2.kind != crate::log::history::SignedEntryKind::KeyPackage {
            return Err(Error::MalformedAtRest("key-package catalog entry differs"));
        }
        if entry.payload.is_none() {
            return Ok(Some((cursor, None)));
        }
        let recipient = v2
            .recipient
            .ok_or(Error::MalformedAtRest("key-package recipient missing"))?;
        let Some((head, header)) =
            read.history_validated_header(&entry.skeleton.author_id, entry.skeleton.seq)?
        else {
            return Ok(Some((cursor, None)));
        };
        if header.entry_hash() != entry.entry_hash() {
            return Err(Error::MalformedAtRest("key-package source header differs"));
        }
        Ok(Some((
            cursor,
            Some(crate::node::history_stream::KeyBodyAvailable {
                cursor,
                author: entry.skeleton.author_id,
                head,
                seq: entry.skeleton.seq,
                hash: entry.entry_hash(),
                recipient,
            }),
        )))
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
    fn held_through(&self, member: &Digest32) -> Option<u64> {
        ChannelState::held_through(self, member)
    }
    fn history_inventory_incarnation(&self, member: &Digest32) -> Option<u64> {
        ChannelState::history_inventory_incarnation(self, member)
    }
    fn history_author_inventory_incarnation(&self, author: &Digest32) -> Option<u64> {
        ChannelState::history_author_inventory_incarnation(self, author)
    }
    fn role_owed(&self) -> Arc<role_owed::RoleOwed> {
        ChannelState::role_owed(self)
    }
    fn availability_peer(&mut self, author: Digest32) -> Result<Arc<availability::Peer>> {
        ChannelState::availability_peer(self, author, None)
    }
    fn history_instance(&self, store: &Store) -> Result<[u8; 16]> {
        ChannelState::history_instance(self, store)
    }
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>> {
        ChannelState::history_read(self, store)
    }
    fn history_sek(&self) -> &Sek {
        &self.sek
    }
    fn recipient_body_eligibility(
        &self,
        store: &Store,
        recipient: &Digest32,
        entry: &Entry,
    ) -> Result<governance::ContentEligibility> {
        ChannelState::recipient_body_eligibility(self, store, recipient, entry)
    }
    fn history_departure_matches(
        &self,
        store: &Store,
        hint: crate::node::history_stream::HeadHint,
    ) -> Result<bool> {
        ChannelState::history_departure_matches(self, store, hint)
    }
    fn forget_history_decline(
        &self,
        store: &Store,
        peer: Digest32,
        author: Digest32,
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        ChannelState::forget_history_decline(self, store, peer, author, committed)
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
    fn held_through(&self, member: &Digest32) -> Option<u64> {
        self.snapshot.held.get(member).copied()
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
    fn role_owed(&self) -> Arc<role_owed::RoleOwed> {
        HistoryAdmissionRoom::role_owed(self.room)
    }
    fn availability_peer(&mut self, author: Digest32) -> Result<Arc<availability::Peer>> {
        self.snapshot
            .availability
            .get(&author)
            .filter(|_| self.snapshot.is_author(&author))
            .cloned()
            .ok_or(Error::MalformedBundle("availability author not admitted"))
    }
    fn history_instance(&self, _store: &Store) -> Result<[u8; 16]> {
        Ok(self.snapshot.admission.instance)
    }
    fn history_read<'a>(&'a self, store: &Store) -> Result<entry_store::Read<'a>> {
        HistoryAdmissionRoom::history_read(self.room, store)
    }
    fn history_sek(&self) -> &Sek {
        self.room.sek()
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
    fn history_departure_matches(
        &self,
        store: &Store,
        hint: crate::node::history_stream::HeadHint,
    ) -> Result<bool> {
        HistoryAdmissionRoom::history_departure_matches(self.room, store, hint)
    }
    fn forget_history_decline(
        &self,
        store: &Store,
        peer: Digest32,
        author: Digest32,
        committed: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        let read = self.history_read(store)?;
        if read.history_declined_head(&peer, &author)?.is_none() {
            return Ok(());
        }
        drop(read);
        HistoryAdmissionRoom::history_write_classified(self.room, store, false, |index| {
            index.forget_history_declined_head(peer, author)
        })?;
        committed.store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }
}
