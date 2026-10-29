//! The legacy control importer and authenticated support announcement have separate cursors.
use super::*;
use crate::atrest::sek::WeakSek;
use crate::node::channel::pending_text::{CompletedText, PendingText, Saved};

pub(crate) struct PendingImport {
    owner: Arc<()>,
    room: Digest32,
    epoch: u64,
    sek: WeakSek,
    authors: BTreeSet<Digest32>,
    after: Option<(usize, u64, Digest32)>,
    pin: Option<history::PendingHistoryRead>,
}

pub(crate) struct CompletedImport {
    pending: PendingImport,
    progress: Option<Option<(usize, u64, Digest32)>>,
    pub(crate) result: Result<bool>,
}

impl CompletedImport {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.pending.room == channel.channel_id
            && self.pending.epoch == channel.epoch
            && Arc::ptr_eq(owner, &self.pending.owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
    }

    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.pending.pin.take()
    }
}

pub(crate) struct PendingSupport {
    append: PendingText,
    room: Digest32,
    author: Digest32,
    now: crate::time::Ms,
}

pub(crate) struct CompletedSupport {
    append: CompletedText,
    pub(crate) appended: bool,
}

impl CompletedSupport {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        self.append.can_install(channel, owner)
    }
    pub(crate) fn into_result(self) -> Result<bool> {
        self.append.result.map(|_| self.appended)
    }

    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.append.take_history_pin()
    }
}

impl ChannelState {
    pub(crate) fn prepare_pending_control_import(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
    ) -> Result<Option<PendingImport>> {
        if !self.private_sessions.controls_import {
            return Ok(None);
        }
        let pin = self.reserve_pending_write(store, Arc::clone(&owner))?;
        Ok(Some(PendingImport {
            owner,
            room: self.channel_id,
            epoch: self.epoch,
            sek: self.sek.reader(),
            authors: self.authors.keys().copied().collect(),
            after: self.private_sessions.controls_import_after,
            pin: Some(pin),
        }))
    }

    pub(crate) fn finish_pending_control_import(
        &mut self,
        completed: CompletedImport,
    ) -> Result<bool> {
        if completed.can_install(self, &completed.pending.owner) {
            if let Some(after) = completed.progress {
                self.private_sessions.controls_import_after = after;
                self.private_sessions.controls_import = after.is_some();
            }
            if let Err(error) = &completed.result {
                self.private_save_failed(error);
            }
            self.release_pending_text(&completed.pending.owner, false);
        }
        completed.result
    }

    pub(crate) fn prepare_pending_private_support(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        now: crate::time::Ms,
        discovery_ready: bool,
    ) -> Result<Option<PendingSupport>> {
        let me = self.me();
        if !self.settled
            || self.poisoned
            || self.has_left(&me)
            || (self.private_sessions.support_rediscovery && !discovery_ready)
        {
            return Ok(None);
        }
        if (!self.private_sessions.support_owed || self.uses_sparse_history(store)?)
            && self.supports_private(store, &me)?
        {
            self.private_sessions.support_owed = false;
            self.private_sessions.support_rediscovery = false;
            return Ok(None);
        }
        Ok(Some(PendingSupport {
            append: self.prepare_pending_control(store, owner, now)?,
            room: self.channel_id,
            author: me,
            now,
        }))
    }

    pub(crate) fn finish_pending_private_support(
        &mut self,
        store: &Store,
        completed: CompletedSupport,
    ) -> Result<bool> {
        let matching = self
            .pending_text
            .as_ref()
            .is_some_and(|owner| completed.can_install(self, owner));
        if matching && completed.appended {
            self.private_sessions.support_owed = false;
            self.private_sessions.support_rediscovery = false;
        }
        self.finish_pending_text(store, completed.append)
            .map(|_| completed.appended)
    }
}

impl PendingSupport {
    pub(crate) fn run(mut self, store: &Store, signer: &dyn RootSigner) -> CompletedSupport {
        let payload = support_body(&self.room, &self.author);
        let target = crate::hash::sha256(&payload);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.append.append_control_owned(
                store,
                signer,
                payload,
                EntryKind::Content,
                crate::log::history::SignedEntryKind::PrivateSupport,
                self.now,
            )
        }))
        .unwrap_or_else(|_| Err(Error::Profile("private support worker stopped")));
        let appended = self.append.committed_control(
            &target,
            crate::log::history::SignedEntryKind::PrivateSupport,
        );
        let append = self
            .append
            .complete_control(result.map(|hash| Saved::Governance(Some(hash))));
        CompletedSupport { append, appended }
    }
}

impl PendingImport {
    pub(crate) fn run(self, store: &Store) -> CompletedImport {
        let mut progress = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Some(segment) = store.get_segment(
                &self.room,
                SegmentKind::KeyMaterial,
                SEG_LEGACY_DRIVE_GENERATIONS,
            )?
            else {
                progress = Some(None);
                return Ok(false);
            };
            if segment.ciphertext.len()
                > AUTHORS_HARD_LIMIT * 48 + 128 + crate::atrest::sek::TAG_LEN
            {
                return Err(Error::MalformedAtRest(
                    "legacy drive generation record exceeds author bound",
                ));
            }
            let bytes = self.sek.with(|sek| {
                open_segment(
                    sek,
                    SegmentKind::KeyMaterial,
                    SEG_LEGACY_DRIVE_GENERATIONS,
                    &segment,
                )
            })?;
            let mut header = Decoder::new(&bytes);
            if header.array()? != 2 || header.uint()? != 1 {
                return Err(Error::MalformedAtRest("legacy drive generations version"));
            }
            let count = header.array()?;
            if count > AUTHORS_HARD_LIMIT {
                return Err(Error::MalformedAtRest("legacy drive generation authors"));
            }
            let (offset, mut done, mut previous) =
                self.after
                    .unwrap_or((bytes.len() - header.remaining(), 0, [0; 32]));
            let rest = bytes
                .get(offset..)
                .ok_or(Error::MalformedAtRest("legacy drive generation cursor"))?;
            let mut decoder = Decoder::new(rest);
            let mut batch = store.batch()?;
            // Same Session-record durability as the original importer (FX-30).
            batch.ruled();
            self.sek.with(|sek| {
                for _ in 0..WORK_ROWS {
                    if done == count as u64 {
                        break;
                    }
                    if decoder.array()? != 2 {
                        return Err(Error::MalformedAtRest("legacy drive generation row"));
                    }
                    let author: Digest32 = decoder
                        .bytes()?
                        .try_into()
                        .map_err(|_| Error::MalformedAtRest("legacy drive author"))?;
                    if done != 0 && author <= previous {
                        return Err(Error::MalformedAtRest(
                            "legacy drive authors not unique ordered",
                        ));
                    }
                    if !self.authors.contains(&author) {
                        return Err(Error::MalformedAtRest("legacy drive author unknown"));
                    }
                    let generation = decoder.uint()?;
                    private_index::observe_control(
                        &mut batch,
                        sek,
                        &self.room,
                        &author,
                        private_index::Control {
                            generation: Some(generation),
                            ..Default::default()
                        },
                    )?;
                    previous = author;
                    done += 1;
                }
                Ok(())
            })?;
            let complete = done == count as u64;
            let next_offset = bytes.len() - decoder.remaining();
            if complete {
                decoder.finish()?;
                batch.delete_segment(
                    &self.room,
                    SegmentKind::KeyMaterial,
                    SEG_LEGACY_DRIVE_GENERATIONS,
                )?;
            }
            batch.commit()?;
            progress = Some((!complete).then_some((next_offset, done, previous)));
            Ok(false)
        }))
        .unwrap_or_else(|_| Err(Error::Profile("private control import worker stopped")));
        CompletedImport {
            pending: self,
            progress,
            result,
        }
    }
}
