//! The anchor's copy of a channel's log (ADR-016 M15.2b): a **ciphertext log with no
//! secrets**, so two members who are never online at the same time still converge.
//!
//! A node that anchors a room it is not a member of holds, for that room, exactly
//! what any peer can verify without a key: the genesis, the members the board knows
//! (the creator, and everyone a member vouched for — `node::network`), and the log's
//! entries — sender-key ciphertext for content, signed frames for governance. That is
//! everything the ADR-008 sync engine needs, on either side of a session, because
//! the engine is secret-free: it verifies authorship and ordering, never plaintext.
//!
//! What is *not* here, structurally: no SEK, no sender chain, no receiver chains, no
//! passphrase, no timeline. There is nothing to render and no way to. The at-rest
//! pages are sealed all the same — under a key derived from the anchor's own
//! identity, per channel — so a stolen disk yields neither membership nor traffic
//! shape without the identity file; the segment kinds are the anchor's own, so a
//! node that later *joins* a room it anchored never mistakes these pages for its own.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::atrest::idfactor::{IdentityFactor, SignatureIdentityFactor};
use crate::atrest::sek::{Sek, SEK_LEN};
use crate::atrest::store::{open_segment, seal_segment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::genesis::Genesis;
use crate::hash::Digest32;
use crate::identity::composite::{CompositePublicKey, RootSigner};
use crate::log::dag::{AdmissionPolicy, Dag};
use crate::log::entry::{Entry, EntryKind};
use crate::log::sync::{frontier_session_peer, Transport};
use crate::node::channel::{
    authors_bytes, classify_payload, parse_authors, sync_failure, ChannelAuthors, SyncOutcome,
};
use crate::node::store::Store;

/// HKDF `info` separating an anchor's per-channel sealing key from every other use
/// of the identity factor.
pub const ANCHOR_SEK_INFO: &[u8] = b"vox/anchor-log-sek/v1";

/// The metadata segment's id within [`SegmentKind::AnchorMeta`].
const SEG_META: u64 = 0;

/// Metadata encoding version.
const META_VERSION: u64 = 1;

/// Derive the sealing key for the anchor's copy of `channel_id` from the anchor's
/// identity: the identity factor for that channel (ADR-010's `factor_id`), expanded
/// under [`ANCHOR_SEK_INFO`]. Deterministic, so a restart reopens its own pages.
pub fn anchor_sek(signer: &dyn RootSigner, channel_id: &Digest32) -> Result<Sek> {
    let factor = SignatureIdentityFactor::new(signer);
    let factor_id = factor.factor_id(channel_id)?;
    let hk = Hkdf::<Sha256>::new(None, factor_id.as_ref());
    let mut key = Zeroizing::new([0u8; SEK_LEN]);
    hk.expand(ANCHOR_SEK_INFO, key.as_mut())
        .map_err(|_| Error::Argon2Failed)?;
    Ok(Sek::from_bytes(key))
}

/// A channel as an anchor holds it.
pub struct AnchorState {
    channel_id: Digest32,
    genesis: Genesis,
    epoch: u64,
    authors: BTreeMap<Digest32, CompositePublicKey>,
    admission: AdmissionPolicy,
    dag: Dag,
    next_log_id: u64,
    sek: Sek,
    poisoned: bool,
}

impl std::fmt::Debug for AnchorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorState")
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("authors", &self.authors.len())
            .field("entries", &self.dag.len())
            .finish_non_exhaustive()
    }
}

impl AnchorState {
    /// Start anchoring `genesis`'s channel: file the genesis and the creator, sealed
    /// under `sek`. Fails if the channel is already anchored in `store`.
    pub fn create(store: &Store, sek: Sek, genesis: &Genesis, now_secs: u64) -> Result<Self> {
        genesis.verify()?;
        let channel_id = genesis.channel_id();
        if store
            .get_segment(&channel_id, SegmentKind::AnchorMeta, SEG_META)?
            .is_some()
        {
            return Err(Error::Profile("channel is already anchored"));
        }
        let mut authors = BTreeMap::new();
        authors.insert(
            genesis.body.creator_pubkey.fingerprint(),
            genesis.body.creator_pubkey.clone(),
        );
        let mut state = Self {
            channel_id,
            genesis: genesis.clone(),
            epoch: 0,
            admission: AdmissionPolicy::new(),
            authors,
            dag: Dag::new(),
            next_log_id: 1,
            sek,
            poisoned: false,
        };
        state.rebuild_admission();
        state.persist_meta(store)?;
        let _ = now_secs;
        Ok(state)
    }

    /// Reopen an anchored channel from `store`: the metadata, then every stored
    /// entry re-passes the acceptance predicate under the authors on file.
    pub fn open(store: &Store, sek: Sek, channel_id: &Digest32) -> Result<Self> {
        let meta_seg = store
            .get_segment(channel_id, SegmentKind::AnchorMeta, SEG_META)?
            .ok_or(Error::Profile("channel is not anchored here"))?;
        let meta = open_segment(&sek, SegmentKind::AnchorMeta, SEG_META, &meta_seg)?;
        let (genesis, authors) = parse_meta(&meta)?;
        genesis.verify()?;
        if genesis.channel_id() != *channel_id {
            return Err(Error::MalformedAtRest("anchor meta genesis mismatch"));
        }
        let mut state = Self {
            channel_id: *channel_id,
            genesis,
            epoch: 0,
            admission: AdmissionPolicy::new(),
            authors,
            dag: Dag::new(),
            next_log_id: 1,
            sek,
            poisoned: false,
        };
        state.rebuild_admission();
        for (id, seg) in store.segments(channel_id, SegmentKind::AnchorLog)? {
            let wire = open_segment(&state.sek, SegmentKind::AnchorLog, id, &seg)?;
            let entry = Entry::from_wire(&wire)?;
            let key = state
                .authors
                .get(&entry.skeleton.author_id)
                .ok_or(Error::MalformedAtRest("stored entry from unknown author"))?
                .clone();
            // A skeleton whose body a member pruned is kept like any other entry: it still
            // verifies and still links the feed (ADR-023 decision 2). Governance is never pruned.
            let kind = match entry.payload.as_deref() {
                Some(payload) => classify_payload(payload)?,
                None => EntryKind::Content,
            };
            state
                .dag
                .accept(entry, kind, &key, &state.admission)
                .map_err(|_| Error::MalformedAtRest("stored entry failed acceptance"))?;
            state.next_log_id = id.saturating_add(1);
        }
        Ok(state)
    }

    /// The channelID.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        self.channel_id
    }

    /// The genesis.
    #[must_use]
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    /// The epoch this anchor tracks (0 until epoch changes are carried by the board).
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// How many entries the anchor holds.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.dag.len()
    }

    /// The authors whose entries this anchor accepts.
    #[must_use]
    pub fn authors(&self) -> Vec<Digest32> {
        self.authors.keys().copied().collect()
    }

    /// The known authors' keys.
    #[must_use]
    pub fn author_keys(&self) -> Vec<CompositePublicKey> {
        self.authors.values().cloned().collect()
    }

    /// Whether `fingerprint` is a known author.
    #[must_use]
    pub fn is_author(&self, fingerprint: &Digest32) -> bool {
        self.authors.contains_key(fingerprint)
    }

    /// Admit authors the board has come to know (the creator is always one). Returns
    /// how many were new; a key that differs from one on file for the same
    /// fingerprint is refused, never replaced.
    pub fn admit_authors(
        &mut self,
        store: &Store,
        keys: impl IntoIterator<Item = CompositePublicKey>,
    ) -> Result<usize> {
        let mut added = 0;
        for key in keys {
            let fp = key.fingerprint();
            match self.authors.get(&fp) {
                Some(existing) if existing.to_bytes() == key.to_bytes() => {}
                Some(_) => {
                    return Err(Error::MalformedGovernance(
                        "another key is already admitted for this fingerprint",
                    ))
                }
                None => {
                    self.authors.insert(fp, key);
                    added += 1;
                }
            }
        }
        if added > 0 {
            self.rebuild_admission();
            self.persist_meta(store)?;
        }
        Ok(added)
    }

    /// Run one ADR-008 frontier session over `transport` — as responder or initiator,
    /// the engine is symmetric — and durably file every entry that arrived. Nothing is
    /// decrypted, because nothing can be.
    pub fn sync_over<T: Transport>(
        &mut self,
        store: &Store,
        transport: &mut T,
    ) -> Result<SyncOutcome> {
        if self.poisoned {
            return Err(Error::Profile(
                "anchored channel is poisoned after a failed persist; reopen it",
            ));
        }
        let before: BTreeMap<Digest32, u64> = self
            .authors
            .keys()
            .map(|a| (*a, self.dag.feed(a).map_or(0, |f| f.max_seq())))
            .collect();
        let resolver = ChannelAuthors::new(self.authors.clone());
        let session = frontier_session_peer(transport, &mut self.dag, &resolver, &self.admission);
        let mut out = self.absorb_arrived(store, &before)?;
        if let Ok(n) = session {
            out.applied = n;
        }
        match session {
            Ok(_) => Ok(out),
            Err(code) => Err(sync_failure(code)),
        }
    }

    fn heads(&self) -> BTreeMap<Digest32, u64> {
        self.authors
            .keys()
            .map(|a| (*a, self.dag.feed(a).map_or(0, |f| f.max_seq())))
            .collect()
    }

    /// Persist every entry a sync added past `before`'s heads.
    fn absorb_arrived(
        &mut self,
        store: &Store,
        before: &BTreeMap<Digest32, u64>,
    ) -> Result<SyncOutcome> {
        let mut arrived: Vec<Digest32> = Vec::new();
        for (author, head) in before {
            let Some(feed) = self.dag.feed(author) else {
                continue;
            };
            for seq in (head + 1)..=feed.max_seq() {
                if let Some(entry) = feed.get(seq) {
                    arrived.push(entry.entry_hash());
                }
            }
        }
        let mut out = SyncOutcome {
            applied: arrived.len(),
            ..SyncOutcome::default()
        };
        for entry_hash in arrived {
            let entry = self
                .dag
                .get_by_hash(&entry_hash)
                .ok_or(Error::MalformedGovernance("synced entry vanished"))?;
            let wire = entry.to_wire();
            let is_governance = entry
                .payload
                .as_deref()
                .map(classify_payload)
                .transpose()?
                .is_some_and(|k| k == EntryKind::Governance);
            let id = self.next_log_id;
            let seg = seal_segment(&self.sek, SegmentKind::AnchorLog, id, &wire)?;
            if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::AnchorLog, id, &seg) {
                self.poisoned = true;
                return Err(e);
            }
            self.next_log_id = id.saturating_add(1);
            if is_governance {
                out.governance += 1;
            }
        }
        Ok(out)
    }

    /// Reconcile with a peer over `transport`, holding `shared`'s lock only inside each protocol
    /// step. See [`crate::log::sync::SessionRoom`] and `ChannelState::sync_over_room`.
    ///
    /// # Errors
    /// The copy is poisoned, a persist fails, or the session hard-fails.
    pub fn sync_over_room<T: Transport>(
        shared: &tokio::sync::Mutex<Self>,
        store: &Store,
        transport: &mut T,
    ) -> Result<SyncOutcome> {
        let epoch = {
            let st = shared.blocking_lock();
            if st.poisoned {
                return Err(Error::Profile(
                    "anchored channel is poisoned after a failed persist; reopen it",
                ));
            }
            st.epoch
        };
        let room = AnchorSessionRoom {
            shared,
            store,
            epoch,
            out: std::cell::RefCell::new(SyncOutcome::default()),
            fatal: std::cell::RefCell::new(None),
        };
        let session = crate::log::sync::frontier_session_room(transport, &room);
        if let Some(e) = room.fatal.take() {
            return Err(e);
        }
        let mut out = room.out.into_inner();
        match session {
            Ok(n) => {
                out.applied = n;
                Ok(out)
            }
            Err(code) => Err(sync_failure(code)),
        }
    }

    fn rebuild_admission(&mut self) {
        let mut admission = AdmissionPolicy::new();
        for author in self.authors.keys() {
            admission.admit(self.channel_id, self.epoch, *author);
        }
        self.admission = admission;
    }

    fn persist_meta(&mut self, store: &Store) -> Result<()> {
        let mut e = Encoder::new();
        e.array(3)
            .uint(META_VERSION)
            .bytes(&self.genesis.to_wire())
            .bytes(&authors_bytes(&self.authors));
        let seg = seal_segment(&self.sek, SegmentKind::AnchorMeta, SEG_META, &e.finish())?;
        if let Err(err) =
            store.put_segment(&self.channel_id, SegmentKind::AnchorMeta, SEG_META, &seg)
        {
            self.poisoned = true;
            return Err(err);
        }
        Ok(())
    }
}

fn parse_meta(bytes: &[u8]) -> Result<(Genesis, BTreeMap<Digest32, CompositePublicKey>)> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 3 {
        return Err(Error::MalformedAtRest("anchor meta arity"));
    }
    if d.uint()? != META_VERSION {
        return Err(Error::MalformedAtRest("anchor meta version"));
    }
    let genesis = Genesis::from_wire(d.bytes()?)?;
    let authors = parse_authors(d.bytes()?)?;
    d.finish()?;
    Ok((genesis, authors))
}

/// An anchored copy as a [`crate::log::sync::SessionRoom`]; see `AnchorState::sync_over_room`.
struct AnchorSessionRoom<'a> {
    shared: &'a tokio::sync::Mutex<AnchorState>,
    store: &'a Store,
    epoch: u64,
    out: std::cell::RefCell<SyncOutcome>,
    fatal: std::cell::RefCell<Option<Error>>,
}

impl AnchorSessionRoom<'_> {
    fn copy(
        &self,
    ) -> std::result::Result<tokio::sync::MutexGuard<'_, AnchorState>, crate::wire::WireError> {
        let st = self.shared.blocking_lock();
        if st.poisoned {
            return Err(crate::wire::WireError::TransportFailed);
        }
        if st.epoch != self.epoch {
            return Err(crate::wire::WireError::EpochMismatch);
        }
        Ok(st)
    }
}

impl crate::log::sync::SessionRoom for AnchorSessionRoom<'_> {
    fn frontiers(
        &self,
    ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
        Ok(crate::log::sync::frontiers_of(&self.copy()?.dag))
    }

    fn wants(
        &self,
        remote: &[crate::log::sync::FeedFrontier],
    ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
        Ok(crate::log::sync::wants_for(&self.copy()?.dag, remote))
    }

    fn entries(
        &self,
        wants: &[crate::log::sync::WantRange],
    ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
        Ok(crate::log::sync::entries_for_wants(
            &self.copy()?.dag,
            wants,
        ))
    }

    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
        let mut guard = self.copy()?;
        let st = &mut *guard;
        let before = st.heads();
        let resolver = ChannelAuthors::new(st.authors.clone());
        // Absorb what was stored, then report the failure: see `ChannelSessionRoom::apply`.
        let stored = crate::log::sync::apply_staged(&mut st.dag, &resolver, &st.admission, &staged);
        match st.absorb_arrived(self.store, &before) {
            Ok(got) => {
                self.out.borrow_mut().governance += got.governance;
                stored
            }
            Err(e) => {
                *self.fatal.borrow_mut() = Some(e);
                Err(crate::wire::WireError::TransportFailed)
            }
        }
    }
}
