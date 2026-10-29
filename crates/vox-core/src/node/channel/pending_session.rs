//! Owned private-Session, drive-ledger and floor-publication transactions.
//! Preparation reads committed authority; only the physical worker acquires Store's writer.
use super::super::pending_text::{CompletedText, PendingText, Saved};
use super::*;
use crate::atrest::sek::{Sek, WeakSek};
use crate::log::history::SignedEntryKind;
use crate::node::drive::DriveState;
use crate::node::session_ingress::Completion;

pub(crate) enum SessionWrite {
    Append {
        content: crate::node::content::SessionEntry,
        completion: Option<Completion>,
    },
    /// `ensure` is the committed HasOpen answer, not absence inferred from a failed query.
    Drive {
        ensure: bool,
    },
    Refresh {
        owed: Vec<Digest32>,
    },
    Delivered {
        member: Digest32,
        generation: u64,
    },
    Package {
        package: crate::node::keypackage::KeyPackage,
    },
}

impl SessionWrite {
    pub(crate) fn append(
        session: &str,
        body: &str,
        now: u64,
        completion: Option<Completion>,
    ) -> Result<Self> {
        Ok(Self::Append {
            content: crate::node::content::SessionEntry::new(now, session, body)?,
            completion,
        })
    }
}

pub(crate) enum SessionSaved {
    Appended(Digest32),
    Drive {
        refresh: SessionRefresh,
        releases: Vec<(Digest32, Skdm, u64)>,
        key_changed: Option<Digest32>,
    },
    Refreshed(SessionRefresh),
    Delivered,
    Package {
        package: crate::node::keypackage::KeyPackage,
    },
}

pub(crate) struct PendingSession {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    me: Digest32,
    sek: WeakSek,
    controls: Option<PendingText>,
    history_pin: Option<history::PendingHistoryRead>,
    drive: DriveState,
    receiver_version: receiver_overlay::Stamp,
    own_feed: Option<crate::log::feed::Feed>,
    used: Option<u64>,
    members: BTreeSet<Digest32>,
    holders: BTreeSet<Digest32>,
    memberships: BTreeMap<Digest32, u64>,
    entries: entry_store::EntryIndex,
    next: u64,
    refresh: Option<RefreshWork>,
    retention: u64,
    drive_input: Option<Zeroizing<Vec<u8>>>,
    step_retention: u64,
    refresh_wait: Option<&'static str>,
    refresh_finished: bool,
    release_ready: bool,
    authoring_error: Option<Error>,
    now: u64,
    write: Option<SessionWrite>,
    committed_drive: Option<Zeroizing<Vec<u8>>>,
    committed_change_unsaid: Option<Option<bool>>,
    committed_rows: u64,
    news: Vec<String>,
    encrypted: bool,
    package_attempted: bool,
    refresh_changed: bool,
}

pub(crate) struct CompletedSession {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    receiver_version: receiver_overlay::Stamp,
    controls: Option<CompletedText>,
    history_pin: Option<history::PendingHistoryRead>,
    drive: Option<DriveState>,
    change_unsaid: Option<bool>,
    next: u64,
    refresh: Option<RefreshWork>,
    refresh_changed: bool,
    committed_rows: u64,
    news: Vec<String>,
    failure: Option<String>,
    package_attempted: bool,
    pub(crate) result: Result<SessionSaved>,
}

impl CompletedSession {
    pub(crate) fn package_unconfirmed(&self) -> bool {
        self.package_attempted && self.result.is_err()
    }

    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.controls
            .as_mut()
            .and_then(CompletedText::take_history_pin)
            .or_else(|| self.history_pin.take())
    }

    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.room == channel.channel_id
            && self.epoch == channel.epoch
            && Arc::ptr_eq(&self.owner, owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }
}

impl ChannelState {
    /// Called under the original Computer publication lease and one short room preparation.
    /// No batch, floor continuation, projection advancement or ratchet advancement occurs here.
    pub(crate) fn prepare_pending_session(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        holders: &BTreeSet<Digest32>,
        write: SessionWrite,
        now: crate::time::Ms,
    ) -> Result<PendingSession> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let delivered = matches!(&write, SessionWrite::Delivered { .. });
        let package = matches!(&write, SessionWrite::Package { .. });
        let refresh_request = matches!(&write, SessionWrite::Refresh { .. });
        let refresh_wait = if delivered || package {
            None
        } else if !self.private_policy_ready(store, now.get())? {
            Some("its governance records being refreshed")
        } else if self.session_upgrade_local_work() {
            Some("its Session upgrade")
        } else {
            None
        };
        let refresh_finished = self.has_left(&self.me()) || self.ended(now.get()).is_some();
        let passive = delivered
            || package
            || (refresh_request && (refresh_wait.is_some() || refresh_finished));
        if !passive {
            self.require_governance_ready(store, now)?;
        }
        let me = self.me();
        if let SessionWrite::Append {
            content,
            completion,
        } = &write
        {
            if !self.settled {
                return Err(Error::RoomNotSynced);
            }
            self.require_own_history_current()?;
            if !self.authors.contains_key(&me) {
                return Err(Error::Profile("this identity is not an author of the room"));
            }
            if self.has_left(&me) || self.ended(now.get()).is_some() {
                return Err(Error::Profile("this room has ended or was left"));
            }
            if completion.is_some()
                && !crate::node::sessions::is_record(&content.body)
                && !crate::node::drive::is_key_changed(&content.session_id)
            {
                use super::super::session_projection::{Query, Reply};
                if !matches!(
                    self.session_query(
                        store,
                        Query::Lookup {
                            node: me,
                            id: content.session_id.clone(),
                        },
                        1,
                        now.get()
                    ),
                    Ok(Reply::Lookup(Some(_)))
                ) {
                    return Err(Error::StreamRefused(SESSION_NOT_OPEN));
                }
            }
        }
        let mut authoring_error = if !passive && !self.current_session_control_ready(store, &me)? {
            Some(Error::StreamRefused(floor_index::REFRESHING))
        } else {
            None
        };
        if !refresh_request {
            if let Some(error) = authoring_error.take() {
                return Err(error);
            }
        }
        // This is the bounded key/ledger component, not ChannelState or Session history.
        // Preserve every actual receiver ratchet in the monolithic drive-state transaction.
        let drive_input = (!(package || refresh_request && passive)).then(|| self.drive.to_state());
        let mut drive = DriveState::default();
        drive.change_unsaid = self.drive.change_unsaid;
        let used = if passive {
            None
        } else {
            match self.legacy_drive_generation(store, &me) {
                Ok(used) => used,
                Err(error) if refresh_request && Self::authorization_refreshing(&error) => {
                    authoring_error.get_or_insert(error);
                    None
                }
                Err(error) => return Err(error),
            }
        };
        let refresh = if matches!(
            &write,
            SessionWrite::Drive { .. } | SessionWrite::Refresh { .. }
        ) {
            self.private_sessions
                .refresh
                .as_ref()
                .map(|work| RefreshWork {
                    grant: work.grant,
                    public: work.public,
                    private: work.private,
                    through: work.through,
                    public_after: work.public_after,
                    private_after: work.private_after,
                    stage: work.stage,
                })
        } else {
            None
        };
        let members = if passive {
            BTreeSet::new()
        } else {
            self.drive_members()
        };
        let memberships = if passive {
            BTreeMap::new()
        } else {
            self.authors
                .keys()
                .map(|peer| (*peer, self.admission(peer).0))
                .collect()
        };
        let own_feed = if passive {
            None
        } else {
            self.dag.feed(&me).cloned()
        };
        let release_ready = matches!(&write, SessionWrite::Drive { .. })
            && self.require_legacy_current(store).is_ok();
        let (controls, history_pin) = if (passive && !package) || authoring_error.is_some() {
            (
                None,
                Some(self.reserve_pending_write(store, Arc::clone(&owner))?),
            )
        } else {
            match self.prepare_pending_control(store, Arc::clone(&owner), now) {
                Ok(controls) => (Some(controls), None),
                Err(
                    error @ (Error::OwnHistoryBehind
                    | Error::RoomNotSynced
                    | Error::Profile("room publication is busy; retry this operation")),
                ) if refresh_request => {
                    authoring_error = Some(error);
                    (
                        None,
                        Some(self.reserve_pending_write(store, Arc::clone(&owner))?),
                    )
                }
                Err(error) => return Err(error),
            }
        };
        Ok(PendingSession {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            me,
            sek: self.sek.reader(),
            authoring_error,
            controls,
            history_pin,
            drive,
            drive_input,
            receiver_version: self.receiver_persistence.drive(),
            own_feed,
            used,
            members,
            holders: if passive {
                BTreeSet::new()
            } else {
                holders.clone()
            },
            memberships,
            entries: entry_store::EntryIndex::default(),
            next: self.private_sessions.next,
            refresh,
            retention: self.effective_retention(),
            step_retention: self.effective_step_retention(),
            refresh_wait,
            refresh_finished,
            release_ready,
            now: now.get(),
            write: Some(write),
            committed_drive: None,
            committed_change_unsaid: None,
            committed_rows: 0,
            news: Vec::new(),
            encrypted: false,
            package_attempted: false,
            refresh_changed: false,
        })
    }

    /// The dispatcher checks retained room pointer/attachment before calling this exact-owner install.
    pub(crate) fn finish_pending_session(
        &mut self,
        store: &Store,
        completed: CompletedSession,
    ) -> Result<SessionSaved> {
        if !completed.can_install(self, &completed.owner) {
            return completed.result;
        }
        let CompletedSession {
            owner,
            receiver_version,
            controls,
            history_pin: _,
            mut drive,
            next,
            refresh,
            refresh_changed,
            committed_rows,
            news,
            change_unsaid,
            mut failure,
            result,
            ..
        } = completed;
        if self.receiver_persistence.drive() != receiver_version {
            failure = Some("Session save receiver basis changed during its reservation".to_owned());
            drive = None;
        }
        if let Some(controls) = controls {
            if let Err(error) = self.finish_pending_text(store, controls) {
                failure = Some(error.to_string());
            }
        } else {
            self.release_pending_text(&owner, false);
        }
        if let Some(mut saved) = drive {
            // Undrained notifications and nonpersistent read/render buffers are not the save's.
            saved.pending = std::mem::take(&mut self.drive.pending);
            saved.news = std::mem::take(&mut self.drive.news);
            saved.told_unheld = std::mem::take(&mut self.drive.told_unheld);
            self.drive = saved;
        }
        if let Some(unsaid) = change_unsaid {
            self.drive.change_unsaid = Some(unsaid);
        }
        self.drive.news.extend(news);
        self.private_sessions.next = self.private_sessions.next.max(next);
        if refresh_changed {
            self.private_sessions.refresh = refresh;
        }
        if committed_rows != 0 {
            self.gen
                .fetch_add(committed_rows, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(failure) = failure {
            self.poisoned = true;
            self.save_error = Some(failure);
        }
        self.history_publication_changed.notify_waiters();
        result
    }
}

impl PendingSession {
    /// Includes writer admission, native durability, floor cursors and refresh permission work.
    /// The caller must not hold ChannelState or Computer.state while this runs.
    pub(crate) fn run(mut self, store: &Store, signer: &dyn RootSigner) -> CompletedSession {
        let sek = self.sek.clone();
        let work = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sek.with(|sek| self.run_inner(store, sek, signer))
        }));
        let result = match work {
            Ok(result) => result,
            Err(_) => Err(Error::Profile("Session save worker stopped")),
        };
        let mut failure = result
            .as_ref()
            .err()
            .filter(|error| {
                self.encrypted
                    || !(super::super::governance::refreshing(error)
                        || ChannelState::authorization_refreshing(error)
                        || matches!(
                            error,
                            Error::OwnHistoryBehind
                                | Error::RoomNotSynced
                                | Error::Profile("room publication is busy; retry this operation")
                        ))
            })
            .map(ToString::to_string);
        let drive = self
            .committed_drive
            .take()
            .map(|bytes| DriveState::from_state(&bytes))
            .transpose();
        let drive = match drive {
            Ok(mut drive) => {
                if let Some(saved) = &mut drive {
                    saved.change_unsaid = self.committed_change_unsaid.flatten();
                }
                drive
            }
            Err(error) => {
                failure = Some(error.to_string());
                None
            }
        };
        // Session failure poisoning belongs to this capsule; completed public floors still install.
        let controls = self
            .controls
            .take()
            .map(|controls| controls.complete_control(Ok(Saved::Governance(None))));
        CompletedSession {
            owner: self.owner,
            room: self.room,
            epoch: self.epoch,
            receiver_version: self.receiver_version,
            controls,
            history_pin: self.history_pin,
            drive,
            next: self.next,
            refresh: self.refresh,
            refresh_changed: self.refresh_changed,
            change_unsaid: if result.is_ok() {
                self.drive.change_unsaid
            } else {
                None
            },
            package_attempted: self.package_attempted,
            committed_rows: self.committed_rows,
            news: self.news,
            failure,
            result,
        }
    }

    fn run_inner(
        &mut self,
        store: &Store,
        sek: &Sek,
        signer: &dyn RootSigner,
    ) -> Result<SessionSaved> {
        let write = self
            .write
            .take()
            .ok_or(Error::Profile("Session save input missing"))?;
        if let SessionWrite::Package { package } = write {
            let controls = self
                .controls
                .as_mut()
                .ok_or(Error::Profile("Session package owner missing"))?;
            self.package_attempted = true;
            controls.append_control_owned(
                store,
                signer,
                package.to_wire(),
                EntryKind::Content,
                SignedEntryKind::KeyPackage,
                crate::time::Ms(self.now),
            )?;
            return Ok(SessionSaved::Package { package });
        }
        if matches!(&write, SessionWrite::Refresh { .. }) {
            if let Some(wait) = self.refresh_wait {
                return Ok(SessionSaved::Refreshed(SessionRefresh::Waiting(wait)));
            }
            if self.refresh_finished {
                return Ok(SessionSaved::Refreshed(SessionRefresh::Complete));
            }
        }
        let change_unsaid = self.drive.change_unsaid;
        self.drive = DriveState::from_state(
            &self
                .drive_input
                .take()
                .ok_or(Error::Profile("Session drive input missing"))?,
        )?;
        self.drive.change_unsaid = change_unsaid;
        if let SessionWrite::Delivered { member, generation } = write {
            self.drive.note_delivered(member, generation);
            self.persist_drive(store, sek)?;
            return Ok(SessionSaved::Delivered);
        }
        let lost = self.drive.lost(&self.holders);
        let rotated = !lost.is_empty() && self.drive.chain.is_some();
        if rotated {
            if let Some(error) = self.authoring_error.take() {
                return Err(error);
            }
            self.drive.forget(&lost);
            self.begin_drive(store, sek)?;
            self.drive.change_unsaid = Some(true);
            self.persist_drive(store, sek)?;
        }
        match write {
            SessionWrite::Append {
                content,
                completion,
            } => self
                .append(store, sek, signer, content, completion.as_ref(), None)
                .map(SessionSaved::Appended),
            SessionWrite::Refresh { owed } => self
                .refresh_records(store, sek, signer, &owed, rotated)
                .map(SessionSaved::Refreshed),
            SessionWrite::Drive { ensure } => {
                if ensure
                    && self.drive.chain.is_none()
                    && self.holders.iter().any(|peer| self.members.contains(peer))
                {
                    self.begin_drive(store, sek)?;
                    self.drive.change_unsaid = None;
                    self.persist_drive(store, sek)?;
                }
                self.ensure_floors(store, sek, signer)?;
                let owed = self.drive.take_owed(&self.members, &self.holders);
                if !owed.is_empty() {
                    self.persist_drive(store, sek)?;
                }
                let refresh = if owed.is_empty() {
                    SessionRefresh::Complete
                } else {
                    self.refresh_records(store, sek, signer, &owed, rotated)?
                };
                let mut releases = Vec::new();
                if refresh == SessionRefresh::Complete && self.release_ready {
                    for peer in &owed {
                        let (skdm, generation) = self.drive.release_for(signer, peer)?;
                        releases.push((*peer, skdm, generation));
                    }
                }
                let unsaid = match self.drive.change_unsaid {
                    Some(unsaid) => unsaid,
                    None => {
                        let live = self
                            .drive
                            .chain
                            .as_ref()
                            .map(SenderChain::chain_id)
                            .unwrap_or(0);
                        live != 0 && self.drive_used(store, sek)?.is_none_or(|used| used < live)
                    }
                };
                self.drive.change_unsaid = Some(unsaid);
                let key_changed = if owed.is_empty() && unsaid {
                    let content = crate::node::content::SessionEntry::new(
                        self.now,
                        crate::node::drive::KEY_CHANGED,
                        r#"{"kind":"drive-key"}"#,
                    )?;
                    Some(self.append(store, sek, signer, content, None, None)?)
                } else {
                    None
                };
                Ok(SessionSaved::Drive {
                    refresh,
                    releases,
                    key_changed,
                })
            }
            SessionWrite::Delivered { .. } | SessionWrite::Package { .. } => unreachable!(),
        }
    }

    fn drive_used(&self, store: &Store, sek: &Sek) -> Result<Option<u64>> {
        let mut used = self.used;
        let read = self.entries.read(store, sek, &self.room)?;
        if let Some(feed) = &self.own_feed {
            for entry in feed.iter(&read) {
                let entry = entry?;
                if let Some(message) = entry
                    .payload
                    .as_deref()
                    .and_then(|body| GroupMessage::from_wire(body).ok())
                    .filter(|message| message.header.channel_id == drive_channel(&self.room))
                {
                    used = Some(used.map_or(message.header.chain_id, |old| {
                        old.max(message.header.chain_id)
                    }));
                }
            }
        }
        Ok(used)
    }

    fn begin_drive(&mut self, store: &Store, sek: &Sek) -> Result<()> {
        let published = floor_index::author(
            Transaction::Snapshot(&store.snapshot()?),
            sek,
            &self.room,
            &self.me,
        )?
        .announced;
        let floor = self
            .drive
            .chain
            .as_ref()
            .map(SenderChain::chain_id)
            .into_iter()
            .chain(self.drive_used(store, sek)?)
            .chain(published)
            .max();
        let first = if self.memberships.get(&self.me).copied().unwrap_or(0) == 0 {
            0
        } else {
            1u64 << 63
        };
        let next = floor.map_or(Ok(first), |generation| {
            generation
                .checked_add(1)
                .ok_or(Error::MalformedBundle("drive chain_id overflow"))
        })?;
        let chain = SenderChain::new(
            &drive_channel(&self.room),
            self.epoch,
            &self.me,
            next,
            self.now,
        )?;
        self.drive.begin(
            chain,
            self.holders
                .iter()
                .filter(|peer| self.members.contains(*peer))
                .copied(),
        );
        Ok(())
    }

    fn persist_drive(&mut self, store: &Store, sek: &Sek) -> Result<()> {
        let state = self.drive.to_state();
        let segment = seal_segment(sek, SegmentKind::KeyMaterial, SEG_DRIVE, &state)?;
        let mut batch = store.batch()?;
        batch.put_segment(&self.room, SegmentKind::KeyMaterial, SEG_DRIVE, &segment)?;
        receiver_overlay::wrote_drive(&mut batch, sek, &self.room, self.receiver_version)?;
        batch.commit()?;
        self.committed_drive = Some(state);
        self.committed_change_unsaid = Some(self.drive.change_unsaid);
        Ok(())
    }

    fn ensure_floors(&mut self, store: &Store, sek: &Sek, signer: &dyn RootSigner) -> Result<()> {
        let Some(generation) = self.drive.chain.as_ref().map(SenderChain::chain_id) else {
            return Ok(());
        };
        let snapshot = store.snapshot()?;
        for peer in self
            .holders
            .iter()
            .filter(|peer| self.members.contains(*peer))
        {
            if floor_index::floor(
                Transaction::Snapshot(&snapshot),
                sek,
                &self.room,
                &(self.me, *peer, self.epoch, generation),
            )?
            .is_some_and(|(membership, _, _)| Some(&membership) != self.memberships.get(peer))
            {
                self.drive.forget(&[*peer]);
            }
        }
        drop(snapshot);
        let owed = self.drive.take_owed(&self.members, &self.holders);
        if !owed.is_empty() {
            // The durable owed mark must precede even the first public floor transaction.
            self.persist_drive(store, sek)?;
        }
        let mut marks = self
            .holders
            .iter()
            .filter(|peer| self.members.contains(*peer))
            .filter_map(|peer| {
                self.drive
                    .floor_mark(peer)
                    .map(|(generation, iteration)| (*peer, generation, iteration))
            })
            .collect::<Vec<_>>();
        marks.push((self.me, generation, 0));
        for (recipient, generation, iteration) in marks {
            let membership = self.memberships.get(&recipient).copied().unwrap_or(0);
            if floor_index::floor(
                Transaction::Snapshot(&store.snapshot()?),
                sek,
                &self.room,
                &(self.me, recipient, self.epoch, generation),
            )?
            .is_some_and(|(old, after, _)| old == membership && after >= iteration)
            {
                continue;
            }
            let controls = self
                .controls
                .as_mut()
                .ok_or(Error::Profile("Session floor owner missing"))?;
            let head = controls.control_head(&self.me);
            let first_seq = floor_index::first_sequence(
                store,
                sek,
                &self.room,
                &self.me,
                self.epoch,
                generation,
                iteration,
                head,
                |seq| {
                    self.entries
                        .read(store, sek, &self.room)?
                        .get(&self.me, seq)?
                        .ok_or(Error::MalformedAtRest("Session floor feed entry missing"))
                },
            )?
            .ok_or(Error::StreamRefused(floor_index::REFRESHING))?
            .map(Ok)
            .unwrap_or_else(|| {
                head.checked_add(2)
                    .ok_or(Error::MalformedAtRest("feed sequence exhausted"))
            })?;
            let floor = super::super::session_floor::Floor {
                room: self.room,
                author: self.me,
                recipient,
                epoch: self.epoch,
                generation,
                iteration,
                first_seq,
                membership,
            };
            controls.append_control_owned(
                store,
                signer,
                floor.wire(),
                EntryKind::Content,
                SignedEntryKind::SessionFloor,
                crate::time::Ms(self.now),
            )?;
        }
        Ok(())
    }

    fn boundary(&self, store: &Store, sek: &Sek) -> Result<crate::node::api::HistoryCursor> {
        let view = self.entries.render_view(store, sek, &self.room)?;
        Ok(crate::node::api::HistoryCursor {
            instance: view.history_instance(),
            arrival: view
                .step(None, false, None, true)?
                .map_or(0, |(_, fact)| fact.cache),
        })
    }

    fn append(
        &mut self,
        store: &Store,
        sek: &Sek,
        signer: &dyn RootSigner,
        content: crate::node::content::SessionEntry,
        completion: Option<&Completion>,
        attention_after: Option<AttentionOpening>,
    ) -> Result<Digest32> {
        if let Some(error) = self.authoring_error.take() {
            return Err(error);
        }
        if self
            .drive
            .chain
            .as_ref()
            .is_none_or(|chain| chain.epoch() != self.epoch || chain.should_rotate(self.now))
        {
            self.begin_drive(store, sek)?;
        }
        self.ensure_floors(store, sek, signer)?;
        let boundary =
            if attention_after.is_none() && crate::node::sessions::is_record(&content.body) {
                Some(self.boundary(store, sek)?)
            } else {
                None
            };
        // Even an encrypt error may have consumed the candidate iteration. Never retry its basis.
        self.encrypted = true;
        let message = self
            .drive
            .chain
            .as_mut()
            .ok_or(Error::Profile("drive key missing"))?
            .encrypt(&Zeroizing::new(content.to_canonical_vec()))?;
        let record = Record::new(signer, self.room, message)?;
        let hash = record.hash();
        let attention_after = attention_after.or_else(|| {
            boundary.map(|after| AttentionOpening {
                after,
                identity: hash,
            })
        });
        let row = SessionRow {
            entry_hash: hash,
            author: self.me,
            created_millis: content.created_millis,
            session_id: content.session_id,
            body: content.body,
        };
        let saved = Stored {
            record,
            row: Some(row),
            first_seen: self.now,
            attention_after,
        };
        let id = private_index::find(&store.snapshot()?, sek, &self.room, &hash)?
            .unwrap_or(self.next.max(1));
        let next = id
            .checked_add(1)
            .ok_or(Error::SizeLimitExceeded("private Session records"))?;
        let segment = seal_segment(sek, SegmentKind::PrivateSession, id, &saved.bytes())?;
        let state = self.drive.to_state();
        let drive = seal_segment(sek, SegmentKind::KeyMaterial, SEG_DRIVE, &state)?;
        let mut batch = store.batch()?;
        // Unchanged ruled durability; inbox receipt, record, index and advanced ratchet are atomic.
        batch.ruled();
        if let Some(old) = batch.get_segment(&self.room, SegmentKind::PrivateSession, id)? {
            let old = Stored::read(&open_segment(sek, SegmentKind::PrivateSession, id, &old)?)?;
            private_index::remove(&mut batch, sek, &self.room, id, &old)?;
        }
        batch.put_segment(&self.room, SegmentKind::PrivateSession, id, &segment)?;
        batch.put_segment(&self.room, SegmentKind::KeyMaterial, SEG_DRIVE, &drive)?;
        private_index::put(&mut batch, sek, &self.room, id, &saved)?;
        if let Some(completion) = completion {
            completion.queue(&mut batch)?;
        }
        batch.commit()?;
        self.drive.change_unsaid = Some(false);
        self.committed_drive = Some(state);
        self.committed_change_unsaid = Some(Some(false));
        self.next = self.next.max(next);
        self.committed_rows = self.committed_rows.saturating_add(1);
        if let Some(row) = saved.row {
            if !crate::node::drive::is_key_changed(&row.session_id) {
                self.news.push(row.session_id);
            }
        }
        Ok(hash)
    }

    fn refresh_grant(&self, store: &Store, sek: &Sek, owed: &[Digest32]) -> Result<Digest32> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"vox/private-session-refresh-grant/v1");
        hash.update(self.epoch.to_be_bytes());
        hash.update(
            self.drive
                .chain
                .as_ref()
                .map_or(0, SenderChain::chain_id)
                .to_be_bytes(),
        );
        hash.update((self.holders.len() as u64).to_be_bytes());
        for peer in &self.holders {
            hash.update(peer);
        }
        hash.update((owed.len() as u64).to_be_bytes());
        for peer in owed {
            hash.update(peer);
            hash.update(
                self.memberships
                    .get(peer)
                    .copied()
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
        }
        hash.update(
            floor_index::author(
                Transaction::Snapshot(&store.snapshot()?),
                sek,
                &self.room,
                &self.me,
            )?
            .revision
            .to_be_bytes(),
        );
        Ok(hash.finalize().into())
    }

    fn expired(&self, saved: &Stored) -> bool {
        let ttl = if saved
            .row
            .as_ref()
            .is_some_and(|row| crate::node::sessions::is_record(&row.body))
        {
            self.retention
        } else {
            self.step_retention
        };
        let claimed = saved
            .row
            .as_ref()
            .map(|row| row.created_millis)
            .or_else(|| saved.record.legacy_claimed_ms())
            .unwrap_or(saved.first_seen);
        ttl != 0
            && saved.first_seen.min(claimed) <= self.now.saturating_sub(ttl.saturating_mul(1000))
    }

    fn private_at(&self, store: &Store, sek: &Sek, id: u64) -> Result<Stored> {
        let segment = store
            .snapshot()?
            .get_segment_bounded(&self.room, SegmentKind::PrivateSession, id, 2 * MAX_RECORD)?
            .ok_or(Error::MalformedAtRest(
                "Session refresh private source missing",
            ))?;
        Stored::read(&open_segment(
            sek,
            SegmentKind::PrivateSession,
            id,
            &segment,
        )?)
    }

    fn permitted(
        &self,
        store: &Store,
        sek: &Sek,
        record: &Record,
        peer: &Digest32,
    ) -> Result<bool> {
        if *peer == self.me {
            return Ok(true);
        }
        if !self.members.contains(peer) {
            return Ok(false);
        }
        let h = &record.message.header;
        let membership = self.memberships.get(peer).copied().unwrap_or(0);
        let Some((old, iteration, _)) = floor_index::floor(
            Transaction::Snapshot(&store.snapshot()?),
            sek,
            &self.room,
            &(h.author_id, *peer, h.epoch, h.chain_id),
        )?
        else {
            return Ok(false);
        };
        if old != membership || h.iteration < iteration {
            return Ok(false);
        }
        let range =
            floor_index::continuity_step(store, sek, &self.room, &h.author_id, peer, membership)?
                .ok_or(Error::StreamRefused(floor_index::REFRESHING))?;
        Ok(range.is_some_and(|(lower, upper)| {
            lower <= (h.epoch, h.chain_id) && (h.epoch, h.chain_id) <= upper
        }))
    }

    fn refresh_one(
        &mut self,
        store: &Store,
        sek: &Sek,
        signer: &dyn RootSigner,
        owed: &[Digest32],
        record: (u64, &str, &str, Digest32),
    ) -> Result<()> {
        let (created, session, body, source) = record;
        let matched = private_index::matching_lifecycle(
            &store.snapshot()?,
            sek,
            &self.room,
            &self.me,
            created,
            body,
        )?;
        let mut attention_after = None;
        let mut identity = source;
        if let Some(id) = matched {
            let saved = self.private_at(store, sek, id)?;
            if !saved.row.as_ref().is_some_and(|row| {
                row.author == self.me && row.created_millis == created && row.body == body
            }) {
                return Err(Error::MalformedAtRest("Session refresh locator binding"));
            }
            attention_after = saved.attention_after;
            identity = saved.record.hash();
            if !self.expired(&saved) {
                let mut all = true;
                for peer in owed {
                    if !self.permitted(store, sek, &saved.record, peer)? {
                        all = false;
                        break;
                    }
                }
                if all {
                    return Ok(());
                }
            }
        }
        let attention_after = match attention_after {
            Some(boundary) => boundary,
            None => AttentionOpening {
                after: self.boundary(store, sek)?,
                identity,
            },
        };
        let content = crate::node::content::SessionEntry::new(created, session, body)?;
        self.append(store, sek, signer, content, None, Some(attention_after))?;
        Ok(())
    }

    fn refresh_records(
        &mut self,
        store: &Store,
        sek: &Sek,
        signer: &dyn RootSigner,
        owed: &[Digest32],
        rotated: bool,
    ) -> Result<SessionRefresh> {
        if let Some(wait) = self.refresh_wait {
            return Ok(SessionRefresh::Waiting(wait));
        }
        if self.refresh_finished {
            return Ok(SessionRefresh::Complete);
        }
        let grant = self.refresh_grant(store, sek, owed)?;
        let public = self
            .entries
            .render_view(store, sek, &self.room)?
            .session_revision();
        let private = private_index::lifecycle_revision(&store.snapshot()?, sek, &self.room)?;
        if self.refresh.as_ref().is_none_or(|work| {
            work.grant != grant || work.public != public || work.private != private
        }) {
            self.refresh = Some(RefreshWork {
                grant,
                public,
                private,
                through: self.next,
                public_after: None,
                private_after: None,
                stage: 0,
            });
        }
        let mut work = self
            .refresh
            .take()
            .ok_or(Error::MalformedAtRest("Session refresh cursor missing"))?;
        let mut bytes = 0usize;
        let progress = (|| -> Result<()> {
            for _ in 0..WORK_ROWS {
                if work.stage == 0 {
                    let next = {
                        let view = self.entries.render_view(store, sek, &self.room)?;
                        view.session_candidate(work.public_after)?
                            .map(|(key, _)| {
                                let row = view.row(&key.2)?.ok_or(Error::MalformedAtRest(
                                    "Session refresh candidate missing",
                                ))?;
                                Ok::<_, Error>((key, row))
                            })
                            .transpose()?
                    };
                    let Some((key, row)) = next else {
                        work.stage = 1;
                        continue;
                    };
                    if bytes != 0 && bytes.saturating_add(row.text.len()) > WORK_BYTES {
                        break;
                    }
                    bytes = bytes.saturating_add(row.text.len());
                    if row.author == self.me && crate::node::sessions::is_record(&row.text) {
                        let tracked = self
                            .entries
                            .read(store, sek, &self.room)?
                            .retention(&row.entry_hash)?
                            .ok_or(Error::MalformedAtRest("Session refresh retention missing"))?;
                        if self.retention == 0
                            || tracked.first_seen_ms.min(row.created_millis)
                                > self.now.saturating_sub(self.retention.saturating_mul(1000))
                        {
                            let env = vox_agentcomms::envelope::Envelope::parse(&row.text)
                                .map_err(|_| {
                                    Error::MalformedAtRest("classified Session envelope changed")
                                })?;
                            let session = if env.from.is_empty() {
                                env.data["session_parts"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_owned()
                            } else {
                                env.from
                            };
                            self.refresh_one(
                                store,
                                sek,
                                signer,
                                owed,
                                (row.created_millis, &session, &row.text, row.entry_hash),
                            )?;
                        }
                    }
                    work.public_after = Some(key);
                } else if work.stage == 1 {
                    let next = private_index::candidate_after(
                        &store.snapshot()?,
                        sek,
                        &self.room,
                        work.private_after,
                    )?;
                    let Some((key, id)) = next else {
                        work.stage = 2;
                        break;
                    };
                    if id < work.through {
                        let saved = self.private_at(store, sek, id)?;
                        let size = saved.record.message.ciphertext.len();
                        if bytes != 0 && bytes.saturating_add(size) > WORK_BYTES {
                            break;
                        }
                        bytes = bytes.saturating_add(size);
                        if !self.expired(&saved) {
                            if let Some(row) = saved.row.filter(|row| {
                                row.author == self.me && crate::node::sessions::is_record(&row.body)
                            }) {
                                self.refresh_one(
                                    store,
                                    sek,
                                    signer,
                                    owed,
                                    (
                                        row.created_millis,
                                        &row.session_id,
                                        &row.body,
                                        row.entry_hash,
                                    ),
                                )?;
                            }
                        }
                    }
                    work.private_after = Some(key);
                } else {
                    break;
                }
            }
            Ok(())
        })();
        if progress.as_ref().is_err_and(floor_index::refreshing) {
            self.refresh = Some(work);
            self.refresh_changed = true;
            return Ok(if rotated || self.committed_rows != 0 {
                SessionRefresh::Progressed
            } else {
                SessionRefresh::Waiting("its Session index being refreshed")
            });
        }
        progress?;
        work.private = private_index::lifecycle_revision(&store.snapshot()?, sek, &self.room)?;
        let complete = work.stage == 2 && work.grant == self.refresh_grant(store, sek, owed)?;
        self.refresh = Some(work);
        self.refresh_changed = true;
        Ok(if complete {
            SessionRefresh::Complete
        } else {
            SessionRefresh::Progressed
        })
    }
}
