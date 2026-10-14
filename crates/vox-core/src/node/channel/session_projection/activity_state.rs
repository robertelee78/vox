//! The fixed publication/repair descriptor for activity indexes. A repair walks
//! retained facts in bounded turns and publishes roots only after catch-up.

use super::record::Key;
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};

#[derive(Clone, Copy)]
pub(super) enum ActivityTree {
    Visible,
    VisibleCount,
    RawRank,
    Parts,
    PartCount,
    OpenParts,
    Outcomes,
    OutcomeCount,
    Requests,
    Resolved,
    Driven,
    Pending,
    PendingCount,
    PendingRefs,
    WaitingOpen,
    PendingLast,
    RoomPending,
    RawCount,
    WaitingParts,
    PartBytes,
    OutcomeBytes,
    AllRank,
    AllCount,
    FileRank,
    FileCount,
    RequestRank,
    RequestCount,
    RawPending,
    RawPendingPrefix,
    RawResolved,
    RawRetire,
}
pub(super) const ACTIVITY_TREES: usize = 31;
pub(super) const ALL: [ActivityTree; ACTIVITY_TREES] = [
    ActivityTree::Visible,
    ActivityTree::VisibleCount,
    ActivityTree::RawRank,
    ActivityTree::Parts,
    ActivityTree::PartCount,
    ActivityTree::OpenParts,
    ActivityTree::Outcomes,
    ActivityTree::OutcomeCount,
    ActivityTree::Requests,
    ActivityTree::Resolved,
    ActivityTree::Driven,
    ActivityTree::Pending,
    ActivityTree::PendingCount,
    ActivityTree::PendingRefs,
    ActivityTree::WaitingOpen,
    ActivityTree::PendingLast,
    ActivityTree::RoomPending,
    ActivityTree::RawCount,
    ActivityTree::WaitingParts,
    ActivityTree::PartBytes,
    ActivityTree::OutcomeBytes,
    ActivityTree::AllRank,
    ActivityTree::AllCount,
    ActivityTree::FileRank,
    ActivityTree::FileCount,
    ActivityTree::RequestRank,
    ActivityTree::RequestCount,
    ActivityTree::RawPending,
    ActivityTree::RawPendingPrefix,
    ActivityTree::RawResolved,
    ActivityTree::RawRetire,
];
impl ActivityTree {
    pub fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone)]
pub(super) struct ActivityState {
    pub roots: [u64; ACTIVITY_TREES],
    pub applied: u64,
    pub invalidated: u64,
    pub ready: bool,
    pub work: Option<ActivityWork>,
    pub waiting: super::waiting::State,
}
#[derive(Clone)]
pub(super) struct ActivityWork {
    pub roots: [u64; ACTIVITY_TREES],
    pub boundary: u64,
    pub invalidated: u64,
    pub phase: u8,
    pub cursor: Option<Key>,
    pub cleanup: usize,
}
impl Default for ActivityState {
    fn default() -> Self {
        Self {
            roots: [0; ACTIVITY_TREES],
            applied: 0,
            invalidated: 0,
            ready: true,
            work: None,
            waiting: super::waiting::State::default(),
        }
    }
}
impl ActivityState {
    pub fn invalidate(&mut self) -> Result<()> {
        self.ready = false;
        self.waiting.ready = false;
        self.invalidated = self
            .invalidated
            .checked_add(1)
            .ok_or(Error::MalformedAtRest(
                "Session activity revision exhausted",
            ))?;
        Ok(())
    }
    pub fn put(&self, e: &mut Encoder) {
        e.array(6).array(ACTIVITY_TREES);
        for root in self.roots {
            e.uint(root);
        }
        e.uint(self.applied)
            .uint(self.invalidated)
            .uint(u64::from(self.ready))
            .array(usize::from(self.work.is_some()));
        if let Some(work) = &self.work {
            e.array(6).array(ACTIVITY_TREES);
            for root in work.roots {
                e.uint(root);
            }
            e.uint(work.boundary)
                .uint(work.invalidated)
                .uint(u64::from(work.phase))
                .bytes(work.cursor.as_ref().map_or(&[][..], |key| &key[..]))
                .uint(work.cleanup as u64);
        }
        self.waiting.put(e);
    }
    pub fn read(d: &mut Decoder<'_>, next: u64) -> Result<Self> {
        let invalid = || Error::MalformedAtRest("Session activity publication state");
        if d.array()? != 6 {
            return Err(invalid());
        }
        let roots = |d: &mut Decoder<'_>| -> Result<[u64; ACTIVITY_TREES]> {
            if d.array()? != ACTIVITY_TREES {
                return Err(invalid());
            }
            let mut roots = [0; ACTIVITY_TREES];
            for root in &mut roots {
                *root = d.uint()?;
                if *root >= next {
                    return Err(invalid());
                }
            }
            Ok(roots)
        };
        let active = roots(d)?;
        let applied = d.uint()?;
        let invalidated = d.uint()?;
        let ready = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(invalid()),
        };
        let work = match d.array()? {
            0 => None,
            1 => {
                if d.array()? != 6 {
                    return Err(invalid());
                }
                let roots = roots(d)?;
                let boundary = d.uint()?;
                let invalidated = d.uint()?;
                let phase = u8::try_from(d.uint()?).map_err(|_| invalid())?;
                if !(1..=5).contains(&phase) {
                    return Err(invalid());
                }
                let cursor = match d.bytes()? {
                    [] => None,
                    bytes => Some(bytes.try_into().map_err(|_| invalid())?),
                };
                let cleanup = usize::try_from(d.uint()?).map_err(|_| invalid())?;
                if cleanup > ACTIVITY_TREES {
                    return Err(invalid());
                }
                Some(ActivityWork {
                    roots,
                    boundary,
                    invalidated,
                    phase,
                    cursor,
                    cleanup,
                })
            }
            _ => return Err(invalid()),
        };
        let waiting = super::waiting::State::read(d, next)?;
        Ok(Self {
            roots: active,
            applied,
            invalidated,
            ready,
            work,
            waiting,
        })
    }
}
