//! Durable progress over the authenticated package-only catalog. No package body remains
//! resident after an attempt, and unrelated room history is never walked for key delivery.

use std::collections::BTreeMap;

use super::{
    open_segment, seal_segment, Digest32, Entry, Error, Result, SegmentKind, Sek, Store,
    AUTHORS_HARD_LIMIT,
};
use crate::cbor::{Decoder, Encoder};
use crate::node::keypackage::KeyPackage;

const RECORDS_PER_TURN: usize = 64;
const CHECKPOINT: u64 = 21;

#[derive(Clone, Copy)]
struct Replay {
    through: u64,
    end: u64,
}
#[derive(Clone, Copy)]
struct Attempt {
    cursor: u64,
    log_id: u64,
    author: Digest32,
    replay: bool,
}

pub(crate) struct Pending {
    pub(crate) log_id: u64,
    pub(crate) author: Digest32,
    pub(crate) package: KeyPackage,
}
pub(crate) struct Progress {
    pub(crate) package: Option<Pending>,
    pub(crate) pending: bool,
}

#[derive(Clone)]
pub(super) struct Queue {
    through: u64,
    published: u64,
    refresh: bool,
    replay: Option<Replay>,
    replay_requested: u64,
    replay_next: bool,
    trust: Option<Digest32>,
    attempt: Option<Attempt>,
    // A bounded discovery hint, never permission to open a package or read a Session.
    authors: BTreeMap<Digest32, u64>,
}

impl Queue {
    pub(super) fn new(_next_log_id: u64) -> Self {
        Self {
            through: 0,
            published: 0,
            refresh: true,
            replay: None,
            replay_requested: 0,
            replay_next: false,
            trust: None,
            attempt: None,
            authors: BTreeMap::new(),
        }
    }

    pub(super) fn restore(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        tip: u64,
    ) -> Result<()> {
        if let Some(segment) = store.get_segment(room, SegmentKind::KeyMaterial, CHECKPOINT)? {
            if segment.ciphertext.len() > AUTHORS_HARD_LIMIT * 48 + 256 {
                return Err(Error::MalformedAtRest("key-package checkpoint size"));
            }
            let bytes = open_segment(sek, SegmentKind::KeyMaterial, CHECKPOINT, &segment)?;
            let mut d = Decoder::new(&bytes);
            if d.array()? != 7 || d.uint()? != 1 {
                return Err(Error::MalformedAtRest("key-package checkpoint version"));
            }
            self.through = d.uint()?;
            self.replay = match d.array()? {
                0 => None,
                2 => Some(Replay {
                    through: d.uint()?,
                    end: d.uint()?,
                }),
                _ => return Err(Error::MalformedAtRest("key-package replay cursor")),
            };
            self.replay_requested = d.uint()?;
            self.replay_next = match d.uint()? {
                0 => false,
                1 => true,
                _ => return Err(Error::MalformedAtRest("key-package replay flag")),
            };
            self.trust = match d.bytes()? {
                [] => None,
                b => Some(
                    b.try_into()
                        .map_err(|_| Error::MalformedAtRest("key-package trust binding"))?,
                ),
            };
            let count = d.array()?;
            if count > AUTHORS_HARD_LIMIT {
                return Err(Error::MalformedAtRest("key-package author bound"));
            }
            for _ in 0..count {
                if d.array()? != 2 {
                    return Err(Error::MalformedAtRest("key-package author row"));
                }
                let author = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("key-package author"))?;
                let log = d.uint()?;
                if log == 0 {
                    return Err(Error::MalformedAtRest("key-package log position"));
                }
                self.authors
                    .entry(author)
                    .and_modify(|held| *held = (*held).max(log))
                    .or_insert(log);
            }
            d.finish()?;
        }
        if self.authors.len() > AUTHORS_HARD_LIMIT
            || self.through > tip
            || self.replay_requested > self.through
            || self
                .replay
                .is_some_and(|r| r.through >= r.end || r.end > self.through)
        {
            return Err(Error::MalformedAtRest("key-package checkpoint bounds"));
        }
        self.published = tip;
        self.refresh = false;
        Ok(())
    }

    fn save(&self, store: &Store, sek: &Sek, room: &Digest32) -> Result<()> {
        let mut e = Encoder::new();
        e.array(7).uint(1).uint(self.through);
        match self.replay {
            Some(r) => {
                e.array(2).uint(r.through).uint(r.end);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(self.replay_requested)
            .uint(u64::from(self.replay_next))
            .bytes(self.trust.as_ref().map_or(&[][..], |v| &v[..]))
            .array(self.authors.len());
        for (author, id) in &self.authors {
            e.array(2).bytes(author).uint(*id);
        }
        let segment = seal_segment(sek, SegmentKind::KeyMaterial, CHECKPOINT, &e.finish())?;
        store.put_segment(room, SegmentKind::KeyMaterial, CHECKPOINT, &segment)
    }

    pub(super) fn published(&mut self, _next_log_id: u64) {
        self.refresh = true;
    }
    pub(super) fn note(&mut self, author: Digest32, log_id: u64) -> Result<()> {
        if log_id == 0 {
            return Err(Error::MalformedAtRest("key-package log position"));
        }
        if !self.authors.contains_key(&author) && self.authors.len() == AUTHORS_HARD_LIMIT {
            return Err(Error::MalformedAtRest("too many key-package authors"));
        }
        self.authors
            .entry(author)
            .and_modify(|last| *last = (*last).max(log_id))
            .or_insert(log_id);
        self.refresh = true;
        Ok(())
    }
    pub(super) fn pending_from(&self, author: &Digest32) -> bool {
        self.authors.contains_key(author)
    }

    /// Selection does not acknowledge work. Effects are durable before this call; a crash
    /// between their commit and this checkpoint merely retries an idempotent installation.
    pub(super) fn attempted(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        author: &Digest32,
        log_id: u64,
    ) -> Result<()> {
        let attempt = self
            .attempt
            .ok_or(Error::MalformedAtRest("key-package attempt missing"))?;
        if attempt.author != *author || attempt.log_id != log_id {
            return Err(Error::MalformedAtRest("key-package attempt differs"));
        }
        let mut done = self.clone();
        done.advance(attempt.cursor, attempt.replay);
        done.attempt = None;
        if done.authors.get(author) == Some(&log_id) {
            done.authors.remove(author);
        }
        done.save(store, sek, room)?;
        *self = done;
        Ok(())
    }
    pub(super) fn retry_retained(&mut self) {
        self.replay_requested = self.replay_requested.max(self.through);
        self.start_replay();
    }
    fn start_replay(&mut self) {
        if self.replay.is_none() && self.replay_requested != 0 {
            self.replay = Some(Replay {
                through: 0,
                end: self.replay_requested,
            });
            self.replay_requested = 0;
        }
    }
    fn advance(&mut self, at: u64, replay: bool) {
        if replay {
            if let Some(scan) = self.replay.as_mut() {
                scan.through = at;
                if scan.through >= scan.end {
                    self.replay = None;
                    self.start_replay();
                }
            }
        } else {
            self.through = at;
        }
        self.replay_next = !replay;
    }
    pub(super) fn pending(&self) -> bool {
        self.refresh
            || self.through < self.published
            || self.replay.is_some()
            || self.replay_requested != 0
            || self.attempt.is_some()
    }

    // One bounded read needs the room's storage, binding and acceptance predicate together.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn next(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        recipient: &Digest32,
        read: &super::entry_store::Read<'_>,
        trust: Digest32,
        verified: impl Fn(&Entry) -> bool,
    ) -> Result<Progress> {
        if self.attempt.is_some() {
            return Err(Error::MalformedAtRest("key-package attempt unacknowledged"));
        }
        self.published = read.key_package_tip()?;
        self.refresh = false;
        let mut changed = false;
        if self.trust != Some(trust) {
            self.retry_retained();
            self.trust = Some(trust);
            changed = true;
        }
        self.start_replay();
        for _ in 0..RECORDS_PER_TURN {
            let forward = self.through < self.published;
            let replay = self.replay.is_some() && (!forward || self.replay_next);
            let (after, end) = if replay {
                let r = self
                    .replay
                    .ok_or(Error::MalformedAtRest("key-package replay missing"))?;
                (r.through, r.end)
            } else if forward {
                (self.through, self.published)
            } else {
                break;
            };
            let Some((cursor, id)) = read
                .key_package_after(Some(after))?
                .filter(|(at, _)| *at <= end)
            else {
                self.advance(end, replay);
                changed = true;
                continue;
            };
            let package = match store.get_segment(room, SegmentKind::LogDb, id)? {
                None => return Err(Error::MalformedAtRest("key-package catalog body missing")),
                Some(segment) => {
                    let wire = open_segment(sek, SegmentKind::LogDb, id, &segment)?;
                    let entry = Entry::from_wire(&wire)?;
                    verified(&entry)
                        .then_some(&entry)
                        .and_then(|e| e.payload.as_deref())
                        .filter(|p| KeyPackage::is_key_package(p))
                        .and_then(|p| KeyPackage::from_wire(p).ok())
                        .filter(|p| &p.recipient == recipient)
                        .map(|package| Pending {
                            log_id: id,
                            author: entry.skeleton.author_id,
                            package,
                        })
                }
            };
            if let Some(package) = package {
                // Persist replay requests and completed irrelevant locators, never this
                // not-yet-attempted locator. A crash must still find it in the catalog.
                if changed || replay {
                    self.save(store, sek, room)?;
                }
                self.attempt = Some(Attempt {
                    cursor,
                    log_id: id,
                    author: package.author,
                    replay,
                });
                return Ok(Progress {
                    package: Some(package),
                    pending: true,
                });
            }
            self.advance(cursor, replay);
            changed = true;
        }
        if changed {
            self.save(store, sek, room)?;
        }
        Ok(Progress {
            package: None,
            pending: self.pending(),
        })
    }
}
