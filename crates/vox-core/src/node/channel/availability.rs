//! Ephemeral, recipient-own-author serving edges. No token grants access or acknowledges history.
use crate::{
    error::{Error, Result},
    hash::Digest32,
};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, Weak,
};
use tokio::sync::Notify;

static NEXT_OPEN: AtomicU64 = AtomicU64::new(1);

/// Ordered only within an authenticated connection to one process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Token {
    pub(crate) open: u64,
    pub(crate) revision: u64,
}

/// One admitted author's scalar serving state, shared with its existing port. No secret material.
pub(crate) struct Peer {
    open: u64,
    revision: AtomicU64,
    pending: AtomicBool,
    remote: Mutex<Option<(u64, Token)>>,
    wake: Mutex<Weak<Notify>>,
}
impl Peer {
    pub(crate) fn local(&self) -> Token {
        Token {
            open: self.open,
            revision: self.revision.load(Ordering::Acquire),
        }
    }
    fn notify(&self) {
        if let Some(wake) = self
            .wake
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade()
        {
            wake.notify_one();
        }
    }
    fn changed(&self) -> Result<()> {
        self.revision
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |r| r.checked_add(1))
            .map_err(|_| Error::SizeLimitExceeded("author availability revision"))?;
        self.notify();
        Ok(())
    }
    pub(crate) fn remote(&self, connection: u64) -> Option<Token> {
        self.remote
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .filter(|(c, _)| *c == connection)
            .map(|(_, t)| t)
    }
    pub(crate) fn observe(&self, connection: u64, token: Token) -> bool {
        let mut remote = self
            .remote
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if remote.is_some_and(|(c, t)| c > connection || (c == connection && t >= token)) {
            return false;
        }
        *remote = Some((connection, token));
        drop(remote);
        self.notify();
        true
    }
}

/// At most one scalar per admitted author, bounded by the existing room author limit.
pub(super) struct State {
    open: u64,
    peers: BTreeMap<Digest32, Arc<Peer>>,
}
impl State {
    pub(super) fn new() -> Result<Self> {
        let open = NEXT_OPEN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| Error::SizeLimitExceeded("room availability lifetime"))?;
        Ok(Self {
            open,
            peers: BTreeMap::new(),
        })
    }
    fn peer(&mut self, author: Digest32) -> Result<Arc<Peer>> {
        if !self.peers.contains_key(&author) && self.peers.len() >= super::AUTHORS_HARD_LIMIT {
            return Err(Error::SizeLimitExceeded("room availability authors"));
        }
        Ok(Arc::clone(self.peers.entry(author).or_insert_with(|| {
            Arc::new(Peer {
                open: self.open,
                revision: AtomicU64::new(0),
                pending: AtomicBool::new(false),
                remote: Mutex::new(None),
                wake: Mutex::new(Weak::new()),
            })
        })))
    }
}
impl super::ChannelState {
    pub(crate) fn availability_peer(
        &mut self,
        author: Digest32,
        wake: Option<&Arc<Notify>>,
    ) -> Result<Arc<Peer>> {
        if !self.is_author(&author) {
            return Err(Error::MalformedBundle("availability author not admitted"));
        }
        let peer = self.availability.peer(author)?;
        if let Some(wake) = wake {
            *peer
                .wake
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::downgrade(wake);
        }
        Ok(peer)
    }
    /// Called only after the batch which made a formerly absent body or original release serveable.
    pub(super) fn note_available(&mut self, store: &super::Store, author: Digest32) -> Result<()> {
        self.availability_peer(author, None)?
            .pending
            .store(true, Ordering::Release);
        self.flush_available(store)
    }
    pub(super) fn flush_available(&mut self, store: &super::Store) -> Result<()> {
        if self.history_publication_busy(store)? {
            return Ok(());
        }
        for peer in self.availability.peers.values() {
            if peer.pending.load(Ordering::Acquire) {
                peer.changed()?;
                peer.pending.store(false, Ordering::Release);
            }
        }
        Ok(())
    }
}
