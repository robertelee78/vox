//! Board membership persistence on a native owner; no live room or history is transferred.
use super::*;
use crate::atrest::sek::WeakSek;
use crate::nat::record::MemberBundleRecord;

pub(crate) type VerifiedRecord<'a> = (&'a MemberBundleRecord, CompositePublicKey);

struct AdmissionState<'a> {
    witnesses: &'a mut BTreeMap<Digest32, CompositePublicKey>,
    authors: &'a mut Option<BTreeMap<Digest32, CompositePublicKey>>,
    board: &'a mut BoardKept,
}

pub(crate) fn verify_unknown_records<'a>(
    known: &BTreeSet<Digest32>,
    records: &'a [MemberBundleRecord],
) -> Vec<VerifiedRecord<'a>> {
    records
        .iter()
        .filter_map(|record| {
            let key = CompositePublicKey::from_bytes(&record.prekey_bundle.root_pub).ok()?;
            if known.contains(&key.fingerprint()) {
                return None;
            }
            record.verify(&key).is_ok().then_some((record, key))
        })
        .collect()
}

/// Borrowed board inventories retain only candidates unknown to this room. Signature checks
/// remain on the native owner; known keys are never copied or verified again.
pub(crate) fn copy_unknown_records(
    known: &BTreeSet<Digest32>,
    records: &[MemberBundleRecord],
) -> Vec<MemberBundleRecord> {
    records
        .iter()
        .filter(|record| {
            CompositePublicKey::from_bytes(&record.prekey_bundle.root_pub)
                .is_ok_and(|key| !known.contains(&key.fingerprint()))
        })
        .cloned()
        .collect()
}

/// The quota covers the entire witness fixpoint, not each pass.
pub(crate) fn admit_verified_records(
    mut pending: Vec<VerifiedRecord<'_>>,
    quota: usize,
    mut admit: impl FnMut(&MemberBundleRecord, &CompositePublicKey) -> Result<bool>,
) -> usize {
    let mut admitted = 0;
    while admitted < quota {
        let before = admitted;
        pending.retain(|(record, key)| {
            if admitted >= quota {
                return true;
            }
            match admit(record, key) {
                Ok(true) => {
                    admitted += 1;
                    false
                }
                Ok(false) => false,
                Err(_) => true,
            }
        });
        if admitted == before {
            break;
        }
    }
    admitted
}

/// Canonical board evidence check, shared by unpublished constructors and owned live saves.
pub(super) fn verify_admission(
    authors: &BTreeMap<Digest32, CompositePublicKey>,
    board: &BoardKept,
    creator: Digest32,
    room: Digest32,
    epoch: u64,
    key: &CompositePublicKey,
    admission: &Admission,
) -> Result<Option<crate::nat::notice::AdmissionNotice>> {
    let fingerprint = key.fingerprint();
    match admission {
        Admission::Creator => {
            if creator != fingerprint {
                return Err(Error::MalformedGovernance(
                    "board record claims to be the creator and is not",
                ));
            }
            Ok(None)
        }
        Admission::Witnessed(w) => {
            let witness_key = authors
                .get(&w.witness_id)
                .ok_or(Error::MalformedGovernance(
                    "join witness signed by an unadmitted key",
                ))?;
            w.verify(witness_key, &room, epoch, &fingerprint)?;
            if !authors.contains_key(&fingerprint)
                && board
                    .withdraws
                    .get(&fingerprint)
                    .is_some_and(|(at, _)| *at >= w.timestamp_ms)
            {
                return Err(Error::MalformedGovernance(
                    "admission withdrawn: the member left the room",
                ));
            }
            Ok(Some(crate::nat::notice::AdmissionNotice::new(
                key.clone(),
                (**w).clone(),
            )?))
        }
    }
}

pub(crate) struct NoticeTail {
    pub(crate) notices: Vec<crate::nat::notice::AdmissionNotice>,
    pub(crate) withdraws: Vec<crate::nat::withdraw::BoardWithdraw>,
    pub(crate) quota: usize,
}

pub(crate) struct JoinCandidate {
    pub(crate) peer: Digest32,
    pub(crate) key: CompositePublicKey,
    pub(crate) witness: crate::nat::record::JoinWitness,
    pub(crate) responder: CompositePublicKey,
}
struct PendingJoin {
    candidate: Box<JoinCandidate>,
    existing: Option<bool>,
    name: Option<String>,
}
pub(crate) struct Joined {
    pub(crate) name: Option<String>,
    pub(crate) notice: Box<crate::nat::notice::AdmissionNotice>,
}

pub(crate) struct Prepared {
    room: Digest32,
    epoch: u64,
    owner: Arc<()>,
    sek: WeakSek,
    creator: Digest32,
    known: BTreeSet<Digest32>,
    witnesses: BTreeMap<Digest32, CompositePublicKey>,
    records: Vec<MemberBundleRecord>,
    tail: Option<NoticeTail>,
    join: Option<PendingJoin>,
    quota: usize,
    now: crate::time::Ms,
    pin: Option<history::PendingHistoryRead>,
}

pub(crate) struct Saved {
    pub(crate) admitted: Vec<(Digest32, usize)>,
    pub(crate) result: Result<()>,
    pub(crate) joined: Option<Joined>,
}

pub(crate) struct Completed {
    pending: Prepared,
    added: Vec<CompositePublicKey>,
    notices: BTreeMap<Digest32, (u64, Vec<u8>)>,
    withdraws: BTreeMap<Digest32, (u64, Vec<u8>)>,
    saved: Saved,
    poison: Option<String>,
}

impl ChannelState {
    pub(crate) fn prepare_pending_roster(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        records: Vec<MemberBundleRecord>,
        quota: usize,
        now: crate::time::Ms,
        tail: Option<NoticeTail>,
    ) -> Result<Prepared> {
        if self.is_poisoned() {
            return Err(self.save_failure());
        }
        let known = self.authors.keys().copied().collect();
        let witness_ids = records
            .iter()
            .filter(|record| !self.authors.contains_key(&record.author_id))
            .filter_map(|record| match &record.admission {
                Admission::Witnessed(witness) => Some(witness.witness_id),
                Admission::Creator => None,
            })
            .chain(
                tail.iter()
                    .flat_map(|tail| tail.notices.iter())
                    .filter(|notice| !self.authors.contains_key(&notice.joiner()))
                    .map(|notice| notice.witness.witness_id),
            );
        let mut witnesses = BTreeMap::new();
        for id in witness_ids {
            if let Some(key) = self.authors.get(&id) {
                witnesses.entry(id).or_insert_with(|| key.clone());
            }
        }
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(Prepared {
            room: self.channel_id,
            epoch: self.epoch,
            owner,
            sek: self.sek.reader(),
            creator: self.genesis.creator_pubkey().fingerprint(),
            known,
            witnesses,
            records,
            quota,
            now,
            tail,
            pin: Some(pin),
            join: None,
        })
    }
    pub(crate) fn prepare_pending_join_admission(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        candidate: Box<JoinCandidate>,
        now: crate::time::Ms,
    ) -> Result<Prepared> {
        if self.ended(now.get()).is_some() {
            return Err(Error::JoinRoomEnded);
        }
        if self.has_left(&self.me()) {
            return Err(Error::JoinResponderLeft);
        }
        if !self.can_answer_join() {
            return Err(Error::JoinRefused(
                "the room can no longer answer this join",
            ));
        }
        if candidate.key.fingerprint() != candidate.peer {
            return Err(Error::MalformedJoin(
                "admission identity differs from the authenticated joiner",
            ));
        }
        let existing = self
            .authors
            .get(&candidate.peer)
            .map(|key| key.to_bytes() == candidate.key.to_bytes());
        let name = self.name().map(str::to_owned);
        let mut pending = self.prepare_pending_roster(store, owner, Vec::new(), 0, now, None)?;
        pending.join = Some(PendingJoin {
            candidate,
            existing,
            name,
        });
        Ok(pending)
    }
}

impl Prepared {
    pub(crate) fn can_run(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.room == channel.channel_id
            && self.epoch == channel.epoch
            && Arc::ptr_eq(owner, &self.owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
    pub(crate) fn refuse(self, error: Error) -> Completed {
        Completed {
            pending: self,
            added: Vec::new(),
            notices: BTreeMap::new(),
            withdraws: BTreeMap::new(),
            saved: Saved {
                admitted: Vec::new(),
                result: Err(error),
                joined: None,
            },
            poison: None,
        }
    }
    pub(crate) fn run(mut self, store: &Store) -> Completed {
        let mut kernel = NativeRoster {
            added: Vec::new(),
            notices: BTreeMap::new(),
            withdraws: BTreeMap::new(),
            admitted: Vec::new(),
            poison: None,
            failure: None,
        };
        let mut witnesses = std::mem::take(&mut self.witnesses);
        let mut join = self.join.take();
        let mut joined = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.sek.with(|sek| {
                // Evidence-only turns need fingerprints and selected witness keys, not another
                // decoded roster. Reconstruct the persisted table only for an actual new author.
                let mut authors = None;
                let mut board = match store.get_segment(
                    &self.room,
                    SegmentKind::KeyMaterial,
                    SEG_BOARD_KEPT,
                )? {
                    Some(segment) => parse_board_kept(
                        &open_segment(sek, SegmentKind::KeyMaterial, SEG_BOARD_KEPT, &segment)?,
                        &self.room,
                    )?,
                    None => BoardKept::default(),
                };
                if let Some(join) = join.take() {
                    let PendingJoin {
                        candidate,
                        existing,
                        name,
                    } = join;
                    candidate.witness.verify(
                        &candidate.responder,
                        &self.room,
                        self.epoch,
                        &candidate.peer,
                    )?;
                    let notice = Box::new(crate::nat::notice::AdmissionNotice::new(
                        candidate.key,
                        candidate.witness,
                    )?);
                    if let Err(error) = kernel.admit_join(
                        store,
                        sek,
                        &self,
                        AdmissionState {
                            witnesses: &mut witnesses,
                            authors: &mut authors,
                            board: &mut board,
                        },
                        existing,
                        &notice,
                    ) {
                        return Err(kernel.failure.take().unwrap_or(error));
                    }
                    joined = Some(Joined { name, notice });
                    return Ok(());
                }
                let pending = verify_unknown_records(&self.known, &self.records);
                admit_verified_records(pending, self.quota, |record, key| {
                    kernel.admit(
                        store,
                        sek,
                        &self,
                        AdmissionState {
                            witnesses: &mut witnesses,
                            authors: &mut authors,
                            board: &mut board,
                        },
                        key,
                        &record.admission,
                    )
                });
                if let Some(tail) = &self.tail {
                    for withdraw in &tail.withdraws {
                        if let Err(error) =
                            kernel.keep_withdraw(store, sek, self.room, &mut board, withdraw)
                        {
                            // A failed withdrawal cannot be treated as absent by later admission.
                            return Err(kernel.failure.take().unwrap_or(error));
                        }
                    }
                    let mut pending = Vec::new();
                    for notice in &tail.notices {
                        if kernel.is_known(&self.known, &notice.joiner()) {
                            let _ = kernel.keep_notice(store, sek, self.room, &mut board, notice);
                        } else {
                            pending.push(notice);
                        }
                    }
                    pending.sort_by_key(|notice| notice.witness.timestamp_ms);
                    let mut admitted = 0;
                    while admitted < tail.quota {
                        let before = admitted;
                        pending.retain(|notice| {
                            if admitted >= tail.quota {
                                return true;
                            }
                            // Notice wire integrity is checked separately from board record signatures.
                            let result = (|| {
                                let witness = witnesses.get(&notice.witness.witness_id).ok_or(
                                    Error::MalformedGovernance(
                                        "join witness signed by an unadmitted key",
                                    ),
                                )?;
                                notice.verify(witness, &self.room, self.epoch)?;
                                if !kernel.is_known(&self.known, &notice.joiner())
                                    && board
                                        .withdraws
                                        .get(&notice.joiner())
                                        .is_some_and(|(at, _)| *at >= notice.witness.timestamp_ms)
                                {
                                    return Err(Error::MalformedGovernance(
                                        "admission withdrawn: the member left the room",
                                    ));
                                }
                                kernel.keep_notice(store, sek, self.room, &mut board, notice)?;
                                let admitted = kernel.admit_key(
                                    store,
                                    sek,
                                    self.room,
                                    &mut authors,
                                    &notice.key,
                                )?;
                                if admitted {
                                    witnesses.insert(notice.joiner(), notice.key.clone());
                                }
                                Ok(admitted)
                            })();
                            match result {
                                Ok(true) => {
                                    admitted += 1;
                                    false
                                }
                                Ok(false) => false,
                                Err(_) => true,
                            }
                        });
                        if before == admitted {
                            break;
                        }
                    }
                }
                match kernel.failure.take() {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
            })
        }))
        .unwrap_or_else(|_| {
            kernel.poison = Some("native roster worker stopped".to_owned());
            Err(Error::Profile("native roster worker stopped"))
        });
        Completed {
            pending: self,
            added: kernel.added,
            notices: kernel.notices,
            withdraws: kernel.withdraws,
            saved: Saved {
                admitted: kernel.admitted,
                result,
                joined,
            },
            poison: kernel.poison,
        }
    }
}

impl Completed {
    pub(crate) fn joined_notice(&self) -> Option<&crate::nat::notice::AdmissionNotice> {
        self.saved.result.as_ref().ok()?;
        self.saved
            .joined
            .as_ref()
            .map(|joined| joined.notice.as_ref())
    }
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.can_run(channel, owner)
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.pin.take()
    }
    pub(crate) fn finish(self, channel: &mut ChannelState) -> Saved {
        if !self.can_install(channel, &self.pending.owner) {
            return Saved {
                admitted: Vec::new(),
                joined: None,
                result: Err(Error::Profile(
                    "roster completion lost its room reservation",
                )),
            };
        }
        channel.board_kept.notices.extend(self.notices);
        channel.board_kept.withdraws.extend(self.withdraws);
        if !self.added.is_empty() {
            channel.now_hint = channel.now_hint.max(self.pending.now.get());
            for key in self.added {
                let fingerprint = key.fingerprint();
                channel.authors.insert(fingerprint, key);
                channel
                    .admission
                    .admit(channel.channel_id, channel.epoch, fingerprint);
                if channel.is_member(&fingerprint) {
                    channel.key_member_became_current(fingerprint);
                }
            }
            *channel
                .consent_facts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                ConsentFactsState::Building(ConsentFactsBuild::new(&channel.authors));
            channel.owe_private_support();
            channel.governance_ready = false;
        }
        if self.saved.result.is_ok() {
            if let Some(joined) = &self.saved.joined {
                channel.now_hint = channel.now_hint.max(self.pending.now.get());
                channel
                    .role_owed
                    .retain_authors(|peer| channel.authors.contains_key(peer));
                channel.readmit(joined.notice.joiner());
            }
        }
        if let Some(error) = self.poison {
            channel.poisoned = true;
            channel.save_error = Some(error);
        }
        channel.release_pending_text(&self.pending.owner, false);
        self.saved
    }
    pub(crate) fn into_result(self) -> Saved {
        self.saved
    }
}

struct NativeRoster {
    added: Vec<CompositePublicKey>,
    notices: BTreeMap<Digest32, (u64, Vec<u8>)>,
    withdraws: BTreeMap<Digest32, (u64, Vec<u8>)>,
    admitted: Vec<(Digest32, usize)>,
    poison: Option<String>,
    failure: Option<Error>,
}

impl NativeRoster {
    fn is_known(&self, known: &BTreeSet<Digest32>, member: &Digest32) -> bool {
        known.contains(member) || self.admitted.iter().any(|(author, _)| author == member)
    }
    fn failed(&mut self, error: Error) -> Error {
        self.poison = Some(error.to_string());
        self.failure = Some(error);
        Error::Profile("native roster component write failed")
    }
    fn keep_notice(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: Digest32,
        board: &mut BoardKept,
        notice: &crate::nat::notice::AdmissionNotice,
    ) -> Result<()> {
        let fingerprint = notice.joiner();
        let at = notice.witness.timestamp_ms;
        if board
            .withdraws
            .get(&fingerprint)
            .is_some_and(|(held, _)| *held >= at)
            || board
                .notices
                .get(&fingerprint)
                .is_some_and(|(held, _)| *held >= at)
            || (!board.notices.contains_key(&fingerprint)
                && board.notices.len() >= AUTHORS_HARD_LIMIT)
        {
            return Ok(());
        }
        let wire = notice.to_wire();
        let previous = board.notices.insert(fingerprint, (at, wire.clone()));
        let save = (|| {
            let segment = seal_segment(
                sek,
                SegmentKind::KeyMaterial,
                SEG_BOARD_KEPT,
                &board_kept_bytes(board),
            )?;
            store.put_segment_derived(&room, SegmentKind::KeyMaterial, SEG_BOARD_KEPT, &segment)
        })();
        if let Err(error) = save {
            match previous {
                Some(value) => {
                    board.notices.insert(fingerprint, value);
                }
                None => {
                    board.notices.remove(&fingerprint);
                }
            }
            return Err(self.failed(error));
        }
        self.notices.insert(fingerprint, (at, wire));
        Ok(())
    }
    fn keep_withdraw(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: Digest32,
        board: &mut BoardKept,
        withdraw: &crate::nat::withdraw::BoardWithdraw,
    ) -> Result<()> {
        if withdraw.channel_id != room
            || withdraw.scope != crate::nat::withdraw::WithdrawScope::Member
        {
            return Ok(());
        }
        let member = withdraw.author_id;
        let at = withdraw.timestamp_ms;
        if board
            .withdraws
            .get(&member)
            .is_some_and(|(held, _)| *held >= at)
            || (!board.withdraws.contains_key(&member)
                && board.withdraws.len() >= AUTHORS_HARD_LIMIT)
        {
            return Ok(());
        }
        let wire = withdraw.to_wire();
        let previous = board.withdraws.insert(member, (at, wire.clone()));
        let save = (|| {
            let segment = seal_segment(
                sek,
                SegmentKind::KeyMaterial,
                SEG_BOARD_KEPT,
                &board_kept_bytes(board),
            )?;
            store.put_segment(&room, SegmentKind::KeyMaterial, SEG_BOARD_KEPT, &segment)
        })();
        if let Err(error) = save {
            match previous {
                Some(value) => {
                    board.withdraws.insert(member, value);
                }
                None => {
                    board.withdraws.remove(&member);
                }
            }
            return Err(self.failed(error));
        }
        self.withdraws.insert(member, (at, wire));
        Ok(())
    }
    fn admit(
        &mut self,
        store: &Store,
        sek: &Sek,
        pending: &Prepared,
        state: AdmissionState<'_>,
        key: &CompositePublicKey,
        admission: &Admission,
    ) -> Result<bool> {
        let AdmissionState {
            witnesses,
            authors,
            board,
        } = state;
        if let Some(notice) = verify_admission(
            witnesses,
            board,
            pending.creator,
            pending.room,
            pending.epoch,
            key,
            admission,
        )? {
            self.keep_notice(store, sek, pending.room, board, &notice)?;
        }
        let admitted = self.admit_key(store, sek, pending.room, authors, key)?;
        if admitted {
            witnesses.insert(key.fingerprint(), key.clone());
        }
        Ok(admitted)
    }
    /// A directly authenticated join decides capacity here and commits author+notice together.
    fn admit_join(
        &mut self,
        store: &Store,
        sek: &Sek,
        pending: &Prepared,
        state: AdmissionState<'_>,
        existing: Option<bool>,
        notice: &crate::nat::notice::AdmissionNotice,
    ) -> Result<bool> {
        let AdmissionState { authors, board, .. } = state;
        let fingerprint = notice.key.fingerprint();
        if notice.channel_id() != pending.room
            || notice.witness.epoch != pending.epoch
            || notice.joiner() != fingerprint
        {
            return Err(Error::MalformedGovernance(
                "admission notice does not name this room, epoch and joiner",
            ));
        }
        let added = match existing {
            Some(true) => false,
            Some(_) => {
                return Err(Error::MalformedGovernance(
                    "another key is already admitted for this fingerprint",
                ))
            }
            None if pending.known.len() >= max_authors() => {
                return Err(Error::RoomFull {
                    members: pending.known.len() as u64,
                })
            }
            None => true,
        };
        let at = notice.witness.timestamp_ms;
        if board
            .withdraws
            .get(&fingerprint)
            .is_some_and(|(held, _)| *held >= at)
        {
            return Err(Error::MalformedGovernance(
                "admission withdrawn: the member left the room",
            ));
        }
        let keep = board
            .notices
            .get(&fingerprint)
            .is_none_or(|(held, _)| *held < at);
        if !board.notices.contains_key(&fingerprint) && board.notices.len() >= AUTHORS_HARD_LIMIT {
            return Err(Error::SizeLimitExceeded("kept notices"));
        }
        if !added && !keep {
            return Ok(false);
        }
        let authors = self.authors(store, sek, pending.room, authors)?;
        authors.insert(fingerprint, notice.key.clone());
        let wire = keep.then(|| notice.to_wire());
        if let Some(wire) = &wire {
            board.notices.insert(fingerprint, (at, wire.clone()));
        }
        let authors_seg = seal_segment(
            sek,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_bytes(authors),
        )?;
        let board_seg = seal_segment(
            sek,
            SegmentKind::KeyMaterial,
            SEG_BOARD_KEPT,
            &board_kept_bytes(board),
        )?;
        let committed = (|| {
            let mut batch = store.batch()?;
            batch.put_segment(
                &pending.room,
                SegmentKind::KeyMaterial,
                SEG_AUTHORS,
                &authors_seg,
            )?;
            batch.put_segment(
                &pending.room,
                SegmentKind::KeyMaterial,
                SEG_BOARD_KEPT,
                &board_seg,
            )?;
            batch.commit()
        })();
        if let Err(error) = committed {
            return Err(self.failed(error));
        }
        if let Some(wire) = wire {
            self.notices.insert(fingerprint, (at, wire));
        }
        if added {
            self.added.push(notice.key.clone());
            self.admitted.push((fingerprint, authors.len()));
        }
        Ok(added)
    }
    fn authors<'a>(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: Digest32,
        authors: &'a mut Option<BTreeMap<Digest32, CompositePublicKey>>,
    ) -> Result<&'a mut BTreeMap<Digest32, CompositePublicKey>> {
        match authors {
            Some(loaded) => Ok(loaded),
            slot @ None => {
                let loaded = (|| {
                    Ok(
                        match store.get_segment(&room, SegmentKind::KeyMaterial, SEG_AUTHORS)? {
                            Some(segment) => parse_authors(&open_segment(
                                sek,
                                SegmentKind::KeyMaterial,
                                SEG_AUTHORS,
                                &segment,
                            )?)?,
                            None => BTreeMap::new(),
                        },
                    )
                })();
                match loaded {
                    Ok(loaded) => Ok(slot.insert(loaded)),
                    Err(error) => {
                        self.failure = Some(error);
                        Err(Error::Profile("native roster author read failed"))
                    }
                }
            }
        }
    }
    fn admit_key(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: Digest32,
        authors: &mut Option<BTreeMap<Digest32, CompositePublicKey>>,
        key: &CompositePublicKey,
    ) -> Result<bool> {
        let fingerprint = key.fingerprint();
        let authors = self.authors(store, sek, room, authors)?;
        if let Some(existing) = authors.get(&fingerprint) {
            return if existing.to_bytes() == key.to_bytes() {
                Ok(false)
            } else {
                Err(Error::MalformedGovernance(
                    "another key is already admitted for this fingerprint",
                ))
            };
        }
        if authors.len() >= AUTHORS_HARD_LIMIT {
            return Err(Error::RoomFull {
                members: authors.len() as u64,
            });
        }
        authors.insert(fingerprint, key.clone());
        let save = (|| {
            let segment = seal_segment(
                sek,
                SegmentKind::KeyMaterial,
                SEG_AUTHORS,
                &authors_bytes(authors),
            )?;
            store.put_segment_derived(&room, SegmentKind::KeyMaterial, SEG_AUTHORS, &segment)
        })();
        if let Err(error) = save {
            authors.remove(&fingerprint);
            return Err(self.failed(error));
        }
        self.added.push(key.clone());
        self.admitted.push((fingerprint, authors.len()));
        Ok(true)
    }
}
