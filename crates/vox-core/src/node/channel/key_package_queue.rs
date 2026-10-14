//! Key delivery scans the retained sealed log; no package body stays in a room's queue.
//!
//! The forward cursor visits each newly published log position. A trust change requests a
//! replay of the already visited prefix, coalesced without rewinding an active replay. The two
//! cursors alternate work, so neither new arrivals nor repeated trust changes starve the other.
//! Cursors are deliberately volatile: reopening offers the retained packages again, including
//! one committed immediately before a crash. Installing an already held sender key is harmless.

use std::collections::BTreeMap;

use super::{
    open_segment, Digest32, Entry, Error, Result, SegmentKind, Sek, Store, AUTHORS_HARD_LIMIT,
};
use crate::node::keypackage::KeyPackage;

const RECORDS_PER_TURN: usize = 64;

#[derive(Clone, Copy)]
struct Replay {
    through: u64,
    end: u64,
}

/// One attempted installation. The caller drops its body after the attempt and acknowledges
/// its locator even when opening or installing fails. Retried bodies are read from the log.
pub(crate) struct Pending {
    pub(crate) log_id: u64,
    pub(crate) author: Digest32,
    pub(crate) package: KeyPackage,
}

/// A bounded scan can yield no package while still needing another maintenance turn.
pub(crate) struct Progress {
    pub(crate) package: Option<Pending>,
    pub(crate) pending: bool,
}

pub(super) struct Queue {
    through: u64,
    published: u64,
    replay: Option<Replay>,
    replay_requested: u64,
    replay_next: bool,
    // At most one locator per admitted author, never one locator per historical package.
    // It is a drive-discovery hint, not permission to open a package or read a Session.
    authors: BTreeMap<Digest32, u64>,
}

impl Queue {
    /// `next_log_id` is the next unused position, after recovery of unpublished entry work.
    pub(super) fn new(next_log_id: u64) -> Self {
        Self {
            through: 0,
            published: next_log_id.saturating_sub(1),
            replay: None,
            replay_requested: 0,
            replay_next: false,
            authors: BTreeMap::new(),
        }
    }

    /// Publish only after the corresponding LogDb transaction commits. A sparse position is
    /// harmless: a scan examines it once and proceeds without constructing a missing-body list.
    pub(super) fn published(&mut self, next_log_id: u64) {
        self.published = self.published.max(next_log_id.saturating_sub(1));
    }

    /// Record an admitted author's valid package addressed to this node. The caller checks
    /// that binding during the existing verified startup scan or after a committed arrival.
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
        self.published = self.published.max(log_id);
        // A retained skeleton can acquire its package body after the forward scan passed it.
        if log_id <= self.through {
            self.retry_retained();
        }
        Ok(())
    }

    pub(super) fn pending_from(&self, author: &Digest32) -> bool {
        self.authors.contains_key(author)
    }

    /// Taking an older package must not erase a newer pending package from the same author.
    /// Held/untrusted packages have no drive hint after an attempt, as on the former hold path.
    pub(super) fn attempted(&mut self, author: &Digest32, log_id: u64) {
        if self.authors.get(author) == Some(&log_id) {
            self.authors.remove(author);
        }
    }

    /// A trust/prekey change can retry a failed installation without retaining its body.
    /// New positions need no replay: their forward attempt observes the new state directly.
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

    pub(super) fn pending(&self) -> bool {
        self.through < self.published || self.replay.is_some() || self.replay_requested != 0
    }

    /// Read at most 64 log positions and return at most one package. Only the current sealed
    /// entry and returned package allocate body bytes. Read/decode errors leave that position
    /// unadvanced; the caller reports storage failure instead of silently dropping authority.
    pub(super) fn next(
        &mut self,
        store: &Store,
        sek: &Sek,
        room: &Digest32,
        recipient: &Digest32,
        verified: impl Fn(&Entry) -> bool,
    ) -> Result<Progress> {
        self.start_replay();
        for _ in 0..RECORDS_PER_TURN {
            let forward = self.through < self.published;
            let replay = self.replay.is_some() && (!forward || self.replay_next);
            let id = if replay {
                // An active replay always has an unvisited position (retired below).
                self.replay.as_ref().expect("active replay").through + 1
            } else if forward {
                self.through + 1
            } else {
                break;
            };
            let package = match store.get_segment(room, SegmentKind::LogDb, id)? {
                None => None,
                Some(segment) => {
                    let wire = open_segment(sek, SegmentKind::LogDb, id, &segment)?;
                    let entry = Entry::from_wire(&wire)?;
                    verified(&entry)
                        .then_some(&entry)
                        .and_then(|entry| entry.payload.as_deref())
                        .filter(|payload| KeyPackage::is_key_package(payload))
                        .and_then(|payload| KeyPackage::from_wire(payload).ok())
                        .filter(|package| &package.recipient == recipient)
                        .map(|package| Pending {
                            log_id: id,
                            author: entry.skeleton.author_id,
                            package,
                        })
                }
            };
            if replay {
                let scan = self.replay.as_mut().expect("active replay");
                scan.through = id;
                if scan.through == scan.end {
                    self.replay = None;
                    self.start_replay();
                }
            } else {
                self.through = id;
            }
            self.replay_next = !replay;
            if package.is_some() {
                return Ok(Progress {
                    package,
                    pending: self.pending(),
                });
            }
        }
        Ok(Progress {
            package: None,
            pending: self.pending(),
        })
    }
}
