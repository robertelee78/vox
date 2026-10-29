//! Direct-peer and anchor hints remain usable while their best-effort saves run natively.
//! Original dirty requests coalesce in the existing cache and native policy book.
use super::*;
use crate::identity::composite::RootSigner;
use crate::node::peer_book::PeerBook;
use crate::node::store::Store;
use std::net::SocketAddr;

/// Unsaved cache changes alone never schedule a write. Only a meaningful original sighting
/// makes work Deferred; a failed attempt therefore cannot create an automatic retry.
#[derive(Default)]
pub(super) enum State {
    #[default]
    Clean,
    Unsaved,
    Deferred,
}

struct Sighting {
    peer: Digest32,
    address: SocketAddr,
    now: u64,
}

enum Work {
    Sighting(Sighting),
    Snapshot(PeerBook),
    AnchorHints(BootstrapSet),
}

impl Work {
    fn run(
        self,
        store: &Store,
        signer: &dyn RootSigner,
        attachment: &tokio::sync::watch::Receiver<u64>,
        epoch: u64,
    ) -> crate::error::Result<()> {
        if *attachment.borrow() != epoch {
            return Err(Error::Profile("peer book attachment retired"));
        }
        // Acquire the actual writer before reading the latest durable book. A direct sighting
        // is an exact delta, never a stale read followed by a separately admitted replacement.
        let mut batch = store.batch()?;
        if *attachment.borrow() != epoch {
            return Err(Error::Profile("peer book attachment retired"));
        }
        match self {
            Self::Sighting(sighting) => {
                let mut book = PeerBook::load(store, signer)?;
                book.note(sighting.peer, sighting.address, sighting.now);
                book.queue_save(&mut batch, signer)?;
            }
            // This retained global owner is the only writer of either cache key.
            Self::Snapshot(book) => book.queue_save(&mut batch, signer)?,
            Self::AnchorHints(hints) => {
                crate::node::peer_book::queue_anchor_hints(&mut batch, signer, &hints)?
            }
        }
        if *attachment.borrow() != epoch {
            return Err(Error::Profile("peer book attachment retired"));
        }
        batch.commit()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Cache {
    Peers,
    Anchors,
}

pub(super) struct Pending {
    store: Arc<Store>,
    epoch: u64,
    cache: Cache,
    _secret: Arc<tokio::sync::OwnedRwLockReadGuard<()>>,
    result: Arc<std::sync::Mutex<Option<crate::error::Result<()>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Pending {
    pub(super) async fn retire(self) {
        // Retirement is detached from the actor, and cannot release the original secret while
        // a physical writer still uses its signer. Dropping a JoinHandle would not cancel I/O.
        let _ = self.task.await;
        let _ = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

impl Node {
    /// A relay circuit is process-local, so only a directly reached endpoint enters the cache.
    pub(super) fn note_peer_endpoint(&mut self, conn: &VoxConnection) {
        let Some(net) = self.net.as_ref() else { return };
        if crate::node::net::path_class(net.manager().endpoint(), conn)
            == crate::node::net::PathClass::Relayed
        {
            return;
        }
        let sighting = Sighting {
            peer: conn.peer_id(),
            address: conn.quinn().remote_address(),
            now: self.now_ms().get(),
        };
        let changed = self
            .peer_book
            .note(sighting.peer, sighting.address, sighting.now);
        if !changed {
            // note() still refreshes the in-memory timestamp. The next meaningful save used to
            // include that refresh too, so a later save must capture the aggregate cache.
            if matches!(self.peer_book_save, State::Clean) {
                self.peer_book_save = State::Unsaved;
            }
            return;
        }
        let exact_delta = matches!(self.peer_book_save, State::Clean);
        self.peer_book_save = State::Deferred;
        self.begin_peer_book_save(exact_delta.then_some(sighting));
    }

    fn begin_peer_book_save(&mut self, sighting: Option<Sighting>) {
        if self.policy_save_pending() || !matches!(self.peer_book_save, State::Deferred) {
            return;
        }
        let work = match sighting {
            Some(sighting) => Work::Sighting(sighting),
            // Coalesced hints need the original bounded cache's eviction and address ordering.
            None => Work::Snapshot(self.peer_book.clone()),
        };
        self.begin_cache_save(work);
    }

    pub(super) fn save_anchor_hints(&mut self) {
        if self.anchor_hints_load_error || matches!(self.anchor_hints_save, State::Clean) {
            return;
        }
        self.anchor_hints_save = State::Deferred;
        self.begin_anchor_hints_save();
    }

    fn begin_anchor_hints_save(&mut self) {
        if self.anchor_hints_load_error
            || self.policy_save_pending()
            || !matches!(self.anchor_hints_save, State::Deferred)
        {
            return;
        }
        self.begin_cache_save(Work::AnchorHints(self.anchor_hints.clone()));
    }

    fn begin_cache_save(&mut self, work: Work) {
        let cache = match &work {
            Work::AnchorHints(_) => Cache::Anchors,
            Work::Sighting(_) | Work::Snapshot(_) => Cache::Peers,
        };
        let state = match cache {
            Cache::Peers => &mut self.peer_book_save,
            Cache::Anchors => &mut self.anchor_hints_save,
        };
        let Some(profile) = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
        else {
            *state = State::Unsaved;
            return;
        };
        let signer = match profile.signer_arc() {
            Ok(signer) => signer,
            Err(_) => {
                *state = State::Unsaved;
                return;
            }
        };
        let secret = match self.secret_work.clone().try_read_owned() {
            Ok(secret) => Arc::new(secret),
            Err(_) => {
                *state = State::Unsaved;
                return;
            }
        };
        let store = profile.store_handle();
        let native_store = Arc::clone(&store);
        let held_secret = Arc::clone(&secret);
        let epoch = self.delivery_epoch;
        let attachment = self.pairwise_epoch.subscribe();
        let result = Arc::new(std::sync::Mutex::new(None));
        let output = Arc::clone(&result);
        let wake = Arc::clone(&self.post_save_wake);
        let task = tokio::spawn(async move {
            let saved = tokio::task::spawn_blocking(move || {
                let _secret = held_secret;
                work.run(&native_store, signer.as_ref(), &attachment, epoch)
            })
            .await
            .unwrap_or_else(|_| Err(Error::Profile("native hint cache worker stopped")));
            *output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(saved);
            wake.notify_one();
        });
        // Clean acknowledges capture only. New hints replace it with their own dirty state.
        *state = State::Clean;
        self.pending_policy = Some(policy_save::Pending::PeerBook(Pending {
            store,
            epoch,
            cache,
            _secret: secret,
            result,
            task,
        }));
    }

    /// Called after the existing global book advances, using its same native completion wake.
    /// Unsaved (including a failed save) is deliberately not enough to schedule another write.
    pub(super) fn resume_peer_book_save(&mut self) {
        if matches!(self.peer_book_save, State::Deferred) {
            self.begin_peer_book_save(None);
        }
        if matches!(self.anchor_hints_save, State::Deferred) {
            self.begin_anchor_hints_save();
        }
    }

    pub(super) fn complete_peer_book_save(&mut self, pending: Pending) {
        let saved = pending
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let saved = match saved {
            Some(saved) => saved,
            None if !pending.task.is_finished() => {
                self.pending_policy = Some(policy_save::Pending::PeerBook(pending));
                return;
            }
            None => Err(Error::Profile("native peer book completion missing")),
        };
        let current = pending.epoch == self.delivery_epoch
            && self
                .profile
                .as_ref()
                .is_some_and(|profile| Arc::ptr_eq(&profile.store_handle(), &pending.store));
        if current {
            if let Err(error) = saved {
                let state = match pending.cache {
                    Cache::Peers => &mut self.peer_book_save,
                    Cache::Anchors => &mut self.anchor_hints_save,
                };
                // A failed save alone never schedules a retry. A newer original request does.
                if matches!(state, State::Clean) {
                    *state = State::Unsaved;
                }
                if pending.cache == Cache::Anchors {
                    eprintln!("vox: anchor endpoint cache could not be saved; will retry: {error}");
                }
            }
        }
        // No actor await of a native task, even after its terminal cell is available. The worker
        // retains its own secret until physical completion; a retired attachment changes nothing.
        drop(pending);
    }
}
