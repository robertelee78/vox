//! Durable local marks and signed receipts use the same retained native publication owner.
use super::*;

pub(crate) enum Work {
    Mark {
        shown: Vec<Digest32>,
        expected_instance: Option<[u8; 16]>,
    },
    Flush {
        interval_ms: u64,
    },
}

pub(crate) enum Effect {
    Marked,
    Flushed,
}
pub(crate) struct Saved {
    pub(crate) result: Result<Effect>,
    pub(crate) appended: bool,
}

pub(crate) struct Prepared {
    owner: Arc<()>,
    room: Digest32,
    sek: WeakSek,
    history_pin: Option<history::PendingHistoryRead>,
    work: Selected,
}
enum Selected {
    Mark {
        reader: Digest32,
        marks: BTreeSet<Digest32>,
    },
    Flush(Box<Flush>),
}
struct Flush {
    append: Option<PendingText>,
    read: Vec<Digest32>,
    next: Option<ReadMarkScan>,
    complete: Option<ReadMarkEligibility>,
    sent_ms: u64,
}

type ReadSelection = (
    Vec<Digest32>,
    Option<ReadMarkScan>,
    Option<ReadMarkEligibility>,
);
pub(crate) struct Completed {
    prepared: Prepared,
    append: Option<PendingText>,
    marks_committed: bool,
    pub(crate) saved: Saved,
}

/// Present only for the receipt append, never its preceding context control.
pub(super) struct ReadAppend {
    row: ReadRow,
    sent_ms: u64,
}
impl ReadAppend {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn queue(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        entries: &entry_store::EntryIndex,
        sek: &Sek,
        room: &Digest32,
        entry: &Entry,
        id: u64,
        sender: &SenderChain,
    ) -> Result<()> {
        self.row.entry_hash = entry.entry_hash();
        let row = &self.row;
        batch.put_segment(
            room,
            SegmentKind::LogDb,
            id,
            &seal_segment(sek, SegmentKind::LogDb, id, &entry.to_wire())?,
        )?;
        batch.put_segment(
            room,
            SegmentKind::PlaintextCache,
            id,
            &seal_segment(sek, SegmentKind::PlaintextCache, id, &read_cache_bytes(row))?,
        )?;
        batch.put_segment(
            room,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &seal_segment(
                sek,
                SegmentKind::KeyMaterial,
                SEG_SENDER,
                &sender.to_state(),
            )?,
        )?;
        batch.put_segment(
            room,
            SegmentKind::Index,
            id,
            &seal_segment(
                sek,
                SegmentKind::Index,
                id,
                &first_seen_bytes(row.created_millis, false),
            )?,
        )?;
        let mut index = entries.write(batch, sek, room)?;
        index.set_retention(
            entry.entry_hash(),
            Some(Tracked {
                log_id: id,
                first_seen_ms: row.created_millis,
                steps: false,
                claimed_ms: Some(row.created_millis),
                cache_id: Some(id),
            }),
        )?;
        // This deletes exactly these pending marks in the same transaction as the receipt.
        index.put_read_receipt(row, id)?;
        index.read_sent(self.sent_ms);
        index.seal()
    }
}

impl ChannelState {
    pub(crate) fn prepare_pending_read(
        &mut self,
        store: &Arc<Store>,
        owner: Arc<()>,
        work: Work,
        now: crate::time::Ms,
    ) -> Result<Prepared> {
        let me = self.me();
        let selected = match work {
            Work::Mark {
                shown,
                expected_instance,
            } => {
                self.require_legacy_current(store)?;
                if shown.len() > crate::node::content::MAX_READ_HASHES {
                    return Err(Error::SizeLimitExceeded("read marks"));
                }
                if self.poisoned {
                    return Err(self.save_failure());
                }
                self.require_governance_display(store, now)?;
                if !self.authors.contains_key(&me) || self.has_left(&me) {
                    return Err(Error::Profile("this identity has left the room"));
                }
                if self.ended(now.get()).is_some() {
                    return Err(Error::Profile("this room has ended"));
                }
                let rendered = self
                    .entries
                    .render_view(store, &self.sek, &self.channel_id)?;
                if expected_instance.is_some_and(|expected| rendered.history_instance() != expected)
                {
                    return Err(Error::Profile("read selection changed; refresh and retry"));
                }
                let facts = self.consent_facts()?;
                let mut marks = BTreeSet::new();
                for hash in shown {
                    if rendered.was_read(&hash, &me)? {
                        continue;
                    }
                    if rendered.fact(&hash)?.is_none() {
                        return Err(Error::Profile("read selection changed; refresh and retry"));
                    }
                    let entry = rendered
                        .order()
                        .entry(&hash)?
                        .ok_or(Error::MalformedAtRest("rendered read-mark entry missing"))?;
                    let retained = rendered.retention(&hash)?.ok_or(Error::MalformedAtRest(
                        "rendered read-mark retention missing",
                    ))?;
                    if expired_at(
                        retained.base(),
                        now.get(),
                        self.entry_retention(rendered.transaction(), &entry)?,
                    ) {
                        return Err(Error::Profile("read selection changed; refresh and retry"));
                    }
                    if entry.skeleton.author_id == me {
                        continue;
                    }
                    if !facts.can_read(&me, &entry.skeleton.author_id) {
                        return Err(Error::Profile("read selection changed; refresh and retry"));
                    }
                    marks.insert(hash);
                }
                Selected::Mark { reader: me, marks }
            }
            Work::Flush { interval_ms } => {
                if self.poisoned {
                    return Err(self.save_failure());
                }
                if self.legacy_cache_only(store)? {
                    Selected::Flush(Box::new(Flush {
                        append: None,
                        read: Vec::new(),
                        next: self.read_mark_scan,
                        complete: self.read_mark_complete,
                        sent_ms: now.get(),
                    }))
                } else {
                    if !self.settled {
                        return Err(Error::RoomNotSynced);
                    }
                    self.require_own_history_current()?;
                    self.require_governance_display(store, now)?;
                    let selection = if self.has_left(&me) || self.ended(now.get()).is_some() {
                        None
                    } else {
                        self.select_pending_read_page(store, me, now, interval_ms)?
                    };
                    let (read, next, complete) = selection.unwrap_or_else(|| {
                        (Vec::new(), self.read_mark_scan, self.read_mark_complete)
                    });
                    let append = if read.is_empty() {
                        None
                    } else {
                        self.ensure_local_append_available(store)?;
                        if !self.authors.contains_key(&me) {
                            return Err(Error::Profile(
                                "this identity is not an author of the room",
                            ));
                        }
                        let (stamp, skipped) = self.stamp_after_held(store, now.get())?;
                        let sparse = self
                            .entries
                            .read(store, &self.sek, &self.channel_id)?
                            .sparse_enabled();
                        Some(self.prepare_pending_append(
                            store,
                            me,
                            Arc::clone(&owner),
                            stamp,
                            now.get(),
                            sparse,
                            skipped,
                            None,
                        )?)
                    };
                    Selected::Flush(Box::new(Flush {
                        append,
                        read,
                        next,
                        complete,
                        sent_ms: now.get(),
                    }))
                }
            }
        };
        let history_pin = if matches!(&selected, Selected::Flush(flush) if flush.append.is_some()) {
            None
        } else {
            Some(self.reserve_pending_write(store, Arc::clone(&owner))?)
        };
        Ok(Prepared {
            owner,
            room: self.channel_id,
            sek: self.sek.reader(),
            history_pin,
            work: selected,
        })
    }

    /// One fixed-tail page: bounded hashes and selected entries, never a resident mark/history map.
    fn select_pending_read_page(
        &self,
        store: &Store,
        me: Digest32,
        now: crate::time::Ms,
        interval_ms: u64,
    ) -> Result<Option<ReadSelection>> {
        let rendered = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let last = rendered.read_sent_ms();
        if last != 0 && now.get() < last.saturating_add(interval_ms) {
            return Ok(None);
        }
        let facts = self.consent_facts()?;
        let eligibility = ReadMarkEligibility {
            reader: me,
            pending: rendered.pending_reads_root()?,
            rendered: rendered.display_roots(),
            governance: self.governance_revision(now)?,
            retention: (self.effective_retention(), self.effective_step_retention()),
        };
        if self.read_mark_scan.is_none() && self.read_mark_complete == Some(eligibility) {
            return Ok(None);
        }
        let scan = match self.read_mark_scan {
            Some(scan) => scan,
            None => match rendered.pending_reads_tail(&me)? {
                Some(through) => ReadMarkScan {
                    after: None,
                    through,
                    started: eligibility,
                },
                None => return Ok(Some((Vec::new(), None, Some(eligibility)))),
            },
        };
        let (page, more) = rendered.pending_reads_page(&me, scan.after)?;
        let mut read = Vec::new();
        let mut cursor = scan.after;
        let mut complete = !more;
        for hash in page {
            if hash > scan.through {
                complete = true;
                break;
            }
            cursor = Some(hash);
            if hash == scan.through {
                complete = true;
            }
            if rendered.fact(&hash)?.is_none() {
                continue;
            }
            let entry = rendered
                .order()
                .entry(&hash)?
                .ok_or(Error::MalformedAtRest("pending read-mark entry missing"))?;
            let retained = rendered.retention(&hash)?.ok_or(Error::MalformedAtRest(
                "pending read-mark retention missing",
            ))?;
            if entry.skeleton.author_id == me
                || expired_at(
                    retained.base(),
                    now.get(),
                    self.entry_retention(rendered.transaction(), &entry)?,
                )
                || !facts.can_read(&me, &entry.skeleton.author_id)
            {
                continue;
            }
            read.push(hash);
        }
        let next = if complete {
            None
        } else {
            Some(ReadMarkScan {
                after: cursor,
                ..scan
            })
        };
        let finished =
            (complete && read.is_empty() && scan.started == eligibility).then_some(eligibility);
        Ok(Some((read, next, finished)))
    }
}

impl Prepared {
    pub(crate) fn run(mut self, store: &Store, signer: &dyn RootSigner) -> Completed {
        let mut marks_committed = false;
        let work = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Effect> {
            match &mut self.work {
                Selected::Mark { reader, marks } => {
                    if !marks.is_empty() {
                        let mut batch = store.batch()?;
                        let changed = self.sek.with(|sek| {
                            let entries = entry_store::EntryIndex::default();
                            let mut index = entries.write(&mut batch, sek, &self.room)?;
                            let mut changed = false;
                            for hash in marks.iter() {
                                changed |= index.put_read_mark(hash, reader)?;
                            }
                            if changed {
                                index.seal()?;
                            }
                            Ok(changed)
                        })?;
                        if changed {
                            batch.commit()?;
                            marks_committed = true;
                        }
                    }
                    Ok(Effect::Marked)
                }
                Selected::Flush(flush) => {
                    if let Some(pending) = flush.append.as_mut() {
                        pending.append_read_owned(
                            store,
                            signer,
                            std::mem::take(&mut flush.read),
                            flush.sent_ms,
                        )?;
                    }
                    Ok(Effect::Flushed)
                }
            }
        }));
        let result = match work {
            Ok(result) => result,
            Err(_) => Err(Error::Profile("read save worker stopped")),
        };
        // Keep the candidate outside the unwind closure so partial durable entries survive panic.
        let append = match &mut self.work {
            Selected::Flush(flush) => flush.append.take(),
            Selected::Mark { .. } => None,
        };
        let appended = append
            .as_ref()
            .is_some_and(|pending| pending.read_committed);
        Completed {
            prepared: self,
            append,
            marks_committed,
            saved: Saved { result, appended },
        }
    }
}

impl PendingText {
    fn append_read_owned(
        &mut self,
        store: &Store,
        signer: &dyn RootSigner,
        read: Vec<Digest32>,
        sent_ms: u64,
    ) -> Result<Digest32> {
        let record = crate::node::content::ReadRecord::new(self.now_millis, read)?;
        if self
            .context(store, signer)?
            .is_some_and(|(_, _, changed)| changed)
        {
            self.append(
                store,
                signer,
                Vec::new(),
                EntryKind::Content,
                SignedEntryKind::ContextUpdate,
                None,
                &[],
                None,
            )?;
            self.cleanup(store)?;
        }
        let payload = self
            .sender
            .encrypt(&Zeroizing::new(record.to_canonical_vec()))?
            .to_wire();
        self.read_append = Some(ReadAppend {
            row: ReadRow {
                entry_hash: [0; 32],
                reader: signer.fingerprint(),
                created_millis: self.now_millis,
                read: record.read,
            },
            sent_ms,
        });
        self.append(
            store,
            signer,
            payload,
            EntryKind::Content,
            SignedEntryKind::Content,
            None,
            &[],
            None,
        )?;
        let hash = self
            .committed
            .last()
            .ok_or(Error::Profile("read receipt save did not complete"))?
            .entry_hash();
        self.cleanup(store)?;
        Ok(hash)
    }
}

impl Completed {
    pub(crate) fn can_install(&self, channel: &ChannelState, owner: &Arc<()>) -> bool {
        Arc::ptr_eq(owner, &self.prepared.owner)
            && channel
                .pending_text
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, owner))
            && self
                .append
                .as_ref()
                .is_none_or(|append| Arc::ptr_eq(&append.owner, owner))
    }
    pub(crate) fn take_history_pin(&mut self) -> Option<history::PendingHistoryRead> {
        self.append
            .as_mut()
            .and_then(|pending| pending.history_pin.take())
            .or_else(|| self.prepared.history_pin.take())
    }
    pub(crate) fn finish(mut self, channel: &mut ChannelState, store: &Store) -> Saved {
        let failed = self.saved.result.as_ref().err().map(ToString::to_string);
        if let Some(append) = self.append.take() {
            let result = self.saved.result.map(|_| super::Saved::Governance(None));
            self.saved.result = channel
                .finish_pending_text(store, append.complete_control(result))
                .map(|_| Effect::Flushed);
        } else {
            channel.release_pending_text(&self.prepared.owner, false);
        }
        if self.marks_committed {
            channel.entries.committed();
        }
        if let Selected::Flush(flush) = self.prepared.work {
            // A failed publication never advances past marks that remain pending.
            if self.saved.result.is_ok() || self.saved.appended {
                channel.read_mark_scan = flush.next;
                channel.read_mark_complete = if self.saved.appended {
                    None
                } else {
                    flush.complete
                };
            }
        }
        if let Some(error) = failed {
            channel.poisoned = true;
            channel.save_error = Some(error);
        }
        self.saved
    }
    pub(crate) fn into_result(self) -> Saved {
        self.saved
    }
}
