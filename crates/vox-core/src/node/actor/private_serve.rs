//! The private Session serve, off the actor (ruling (b), build order 6). A peer's Session-stream
//! ask is read and answered on the stream's own task: the room comes from the serving registry,
//! the node's Drive holders, secret-work lease and policy authority from what the actor last
//! published (`PrivateServing`), and the page from the unchanged native serve
//! (`prepare_pending_private_page`, then its native run and install), which keeps every check:
//! the room and peer preconditions, per-record `permitted_to`, continuity preparation, the
//! first donor incarnation save, and at every physical answer write the removal generation and
//! the keyring incarnation of the Drive holders (`sessionstream::answer`). The actor's turn is
//! never taken.

use super::*;
use crate::node::history_budget::{BufferCharge, Job, Lane};
use crate::node::history_stream::private::PrivateSink;
use crate::node::history_stream::Serving;
use crate::node::sessionstream::{self, Ask, Page};

/// What the private serve needs of this node, published by the actor while it is unlocked
/// (`Node::publish_private_serving`): who its keyring trusts with Drive (its own records go
/// only to them) together with the exact keyring incarnation that set was derived from, the
/// secret-work lease lock and policy authority. The serve and its every physical write check
/// that incarnation is still the durable one; a newer one is never sampled in its place.
pub(crate) struct PrivateServing {
    node: Digest32,
    holders: BTreeSet<Digest32>,
    incarnation: Option<[u8; crate::atrest::sek::NONCE_LEN]>,
    secret_work: Arc<tokio::sync::RwLock<()>>,
    authority: computer::ComputerAuthority,
}

impl Node {
    /// Publish the private serve's inputs; nothing while locked or without policy authority.
    pub(super) fn publish_private_serving(&mut self) {
        let private = self
            .profile
            .as_ref()
            .filter(|profile| profile.is_unlocked())
            .map(Profile::fingerprint)
            .zip(self.computer_authority())
            .map(|(node, authority)| {
                Arc::new(PrivateServing {
                    node,
                    holders: self.drive_holders(),
                    incarnation: self.trust_incarnation,
                    secret_work: Arc::clone(&self.secret_work),
                    authority,
                })
            });
        self.serving.set_private(private);
    }

    /// Where a connection's loop hands its private pages: this actor's native private admission
    /// (`private_loop_page`).
    pub(super) fn private_sink(&self) -> PrivateSink {
        let tx = self.net_tx.clone();
        Arc::new(move |page| {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(NetEvent::PrivateLoopPage(Box::new(page))).await;
            })
        })
    }
}

/// Read one Session-stream ask and answer it, or refuse it: an ask that does not decode (a zero
/// or missing LiveTail anchor among them, ruling-private-tip §6) gets the same generic refusal
/// as any other this node will not serve, never a silent end. A readable ask is its
/// connection's one loop exchange in the room (`Serving::place`, as a room-history Range is):
/// registered so a retirement ends it, waiting (`page`) and transmitting alike, and answered
/// patiently until its asker leaves. Ending it drops whatever it holds then: its page, the
/// page's charge and the encoded answer.
pub(super) async fn serve(
    net: &Arc<NodeNet>,
    serial: u64,
    peer: Digest32,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let unavailable = || Error::StreamRefused("private Session room unavailable");
    let ask = sessionstream::read_ask(&mut recv).await;
    let serving = net.serving();
    let room = ask.as_ref().map_or([0; 32], |ask| ask.room);
    let fence = crate::transport::stream_transport::Fence::new();
    let token = serving
        .filter(|_| ask.is_ok())
        .and_then(|serving| serving.begin(room, peer, serial, Arc::clone(&fence)));
    let answered = match (ask, serving, token) {
        (Err(error), _, _) => Err(error),
        (Ok(ask), Some(serving), Some(token))
            if serving.place(
                room,
                token,
                crate::node::history_stream::Place::Loop { have: false },
            ) =>
        {
            let left = send.stopped();
            let answer = async {
                let (page, store, trust) = page(serving, peer, ask).await?;
                sessionstream::answer(&mut send, page, &store, &room, trust).await
            };
            tokio::select! {
                biased;
                () = fence.retired() => Err(unavailable()),
                _ = left => Err(Error::Unreachable("private Session asker left")),
                answered = answer => answered,
            }
        }
        _ => Err(unavailable()),
    };
    match answered {
        Ok(()) => drop(recv),
        Err(_) => crate::transport::streams::refuse(&mut send, &mut recv),
    }
    if let (Some(serving), Some(token)) = (serving, token) {
        serving.end(room, token);
    }
}

/// A peer's ask, answered as the room-history loop's exchanges are (design simple-sync §1,
/// serving): this node's own business is waited for, never refused. Local admission (a job,
/// the page's capacity) is waited for on its release; a room whose publication is held, or
/// which cannot decide the peer now, is waited for on that edge (`Ran::Held`), with the ask
/// back and every admission let go. No job, capacity, lease or room ownership is held while it
/// waits; one such wait per connection and room (`Serving::place`), ended by the asker's
/// leaving or the answer's retirement (`serve`).
async fn page(
    serving: &Serving,
    peer: Digest32,
    mut ask: Ask,
) -> crate::error::Result<(
    Page,
    Arc<crate::node::store::Store>,
    Option<[u8; crate::atrest::sek::NONCE_LEN]>,
)> {
    let lane = if ask.query.archive() {
        Lane::Archive
    } else {
        Lane::Live
    };
    loop {
        let node = serving.private().ok_or(Error::AtRestLocked)?.node;
        let job = serving.budget.admit_job(node, lane).await;
        let mut work = match job.reserve_or_pressure(sessionstream::CURRENT_PAGE_ENVELOPE) {
            Ok(work) => work,
            Err(Error::HistoryCapacity(pressure)) => {
                drop(job);
                pressure.released().await;
                continue;
            }
            Err(error) => return Err(error),
        };
        let page_charge = work
            .split_off(sessionstream::PAGE_ENVELOPE)
            .ok_or(Error::Profile(
                "private page reservation is smaller than its page envelope",
            ))?;
        match native(
            serving,
            peer,
            (ask.room, ask.epoch),
            Native::Page { ask, page_charge },
            (job, work),
        )
        .await?
        {
            Ran::Saved(mut saved, store, nonce) => {
                let page = saved
                    .page
                    .take()
                    .ok_or(Error::Profile("native private page receipt missing"))?;
                return Ok((page, store, nonce));
            }
            Ran::Held(released, back) => {
                ask = back.ok_or(Error::Profile("held private page lost its ask"))?;
                released.await;
            }
        }
    }
}

/// The edge a native private step that could not run now resumes on (the room's publication
/// released, a policy transition ended, the room's next publication), subscribed before the
/// attempt it lets go of.
pub(crate) type Released = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// One quantum of a connection teller's discovery walk (ruling-private-tip §1-§4).
pub(crate) enum Quantum {
    /// The newest record `peer` may be served now, and the authority it was decided under,
    /// which the Have's physical write checks (`sessionstream::Authority`).
    Found(sessionstream::Cursor, sessionstream::Authority),
    /// The bound was reached; the walk goes on below this position.
    Below(u64),
    /// Nothing between the walk's floor and bound may be served to `peer`.
    Exhausted,
    /// A permission fact of the named author is not known here yet: the walk stays at this
    /// position until that fact's own event (`history_stream::private::Wait::Author`).
    Waiting(u64, Digest32),
    /// The next record's permission needs more bounded local preparation (progress saved,
    /// nothing missing): the walk stays at this position and runs its next quantum at once.
    Preparing(u64),
    /// The room's publication (or a policy transition) is held, or the room cannot decide the
    /// peer now: resume on this edge.
    Held(Released),
}

/// One bounded native quantum of `peer`'s discovery walk in `room`: below `before`, above
/// `floor`, at most `WORK_ROWS` records and `WORK_BYTES`. A looking quantum (`write: false`)
/// only reads: no room publication ownership, no policy publication lease, nothing installed.
/// A writing quantum (a permission preparation step or the first donor incarnation) holds the
/// room's pending-write ownership, released when it returns. `admitted` (the caller's job and
/// capacity) ends with it either way.
pub(crate) async fn discover(
    serving: &Serving,
    peer: Digest32,
    (room, epoch): (Digest32, u64),
    (before, floor): (u64, u64),
    write: bool,
    admitted: (Job, BufferCharge),
) -> crate::error::Result<Quantum> {
    let ran = native(
        serving,
        peer,
        (room, epoch),
        Native::Discover {
            before,
            floor,
            write,
        },
        admitted,
    )
    .await?;
    let (mut saved, nonce) = match ran {
        Ran::Saved(saved, _, nonce) => (saved, nonce),
        Ran::Held(released, _) => return Ok(Quantum::Held(released)),
    };
    use crate::node::channel::pending_upgrade::Discovered;
    Ok(
        match saved
            .discovered
            .take()
            .ok_or(Error::Profile("native private discovery receipt missing"))?
        {
            Discovered::Found(cursor, removal) => Quantum::Found(
                cursor,
                sessionstream::Authority {
                    removal,
                    trust: nonce,
                },
            ),
            Discovered::Below(at) => Quantum::Below(at),
            Discovered::Exhausted => Quantum::Exhausted,
            Discovered::Waiting(at, author) => Quantum::Waiting(at, author),
            Discovered::Preparing(at) => Quantum::Preparing(at),
        },
    )
}

/// What a native private step does: serve a peer's page, or one discovery quantum.
enum Native {
    Page {
        ask: Ask,
        page_charge: BufferCharge,
    },
    Discover {
        before: u64,
        floor: u64,
        write: bool,
    },
}

impl Native {
    /// A page's ask, given back unconsumed by a step that could not run now; its capacity ends.
    fn into_ask(self) -> Option<Ask> {
        match self {
            Self::Page { ask, .. } => Some(ask),
            Self::Discover { .. } => None,
        }
    }
}

/// A native step's result, or that it cannot run now: the room's publication is held, or the
/// room cannot decide the peer. It resumes on that edge, with a page's ask given back.
// A transient step result consumed at once; `Saved` is the common outcome, so boxing it would
// allocate on every served page and discovery quantum.
#[allow(clippy::large_enum_variant)]
enum Ran {
    Saved(
        crate::node::channel::pending_upgrade::Saved,
        Arc<crate::node::store::Store>,
        Option<[u8; crate::atrest::sek::NONCE_LEN]>,
    ),
    Held(Released, Option<Ask>),
}

/// The native private step for `peer` in `room`, with every serve check: the room's last
/// publication counts the peer eligible, the secret-work lease, the trust incarnation of the
/// published holders before and after, and the unchanged native preparation, run off the
/// room's lock. A step that may write also holds the policy publication lease and the room's
/// pending-write ownership and installs; a looking discovery quantum holds neither and installs
/// nothing. Also returns the store it read and that keyring incarnation, which every physical
/// write checks again.
async fn native(
    serving: &Serving,
    peer: Digest32,
    (room, epoch): (Digest32, u64),
    work: Native,
    (job, charge): (Job, BufferCharge),
) -> crate::error::Result<Ran> {
    let refused = || Error::StreamRefused("private Session room unavailable");
    let private = serving.private().ok_or(Error::AtRestLocked)?;
    let entry = serving.room(&room).ok_or_else(refused)?;
    let (Some(cell), Some(shared), Some(store)) = (
        entry.snapshot.upgrade(),
        entry.channel.upgrade(),
        entry.store.upgrade(),
    ) else {
        return Err(refused());
    };
    // Only a peer the room's last publication counts eligible for its private Sessions; the
    // native preparation checks it again and `permitted_to` decides each record. A room that
    // cannot decide now (its governance refreshing, its Session upgrade work running) decides
    // at a later publication: the step waits for the next one, subscribed before this look.
    let mut next = cell.next_publication();
    match cell
        .current()
        .filter(|snapshot| snapshot.epoch() == epoch)
        .map(|snapshot| snapshot.private_peer(&peer))
    {
        Some(Some(true)) => {}
        Some(None) => {
            let published: Released = Box::pin(async move {
                let _ = next.changed().await;
            });
            return Ok(Ran::Held(published, work.into_ask()));
        }
        _ => return Err(refused()),
    }
    let lease = Arc::clone(&private.secret_work)
        .try_read_owned()
        .map_err(|_| Error::AtRestLocked)?;
    let looks = matches!(work, Native::Discover { write: false, .. });
    let publication = if looks {
        None
    } else {
        match private.authority.try_acquire_publication()? {
            Some(publication) => Some(publication),
            None => {
                return Ok(Ran::Held(
                    private.authority.publication_released(),
                    work.into_ask(),
                ));
            }
        }
    };
    // The incarnation the published holders were derived from, never a newer durable one.
    let (holders, nonce, authority) = (
        private.holders.clone(),
        private.incarnation,
        private.authority.clone(),
    );
    let worker = Arc::clone(&store);
    let ran = tokio::task::spawn_blocking(move || -> crate::error::Result<Ran> {
        let (_lease, _publication, _charge, _job) = (lease, publication, charge, job);
        let store = worker;
        // The trust incarnation the holders were derived from and the policy the serve began
        // under, at each physical step.
        let current = || -> crate::error::Result<()> {
            if !authority.current()
                || store.get_meta_prefix::<{ crate::atrest::sek::NONCE_LEN }>(
                    crate::node::trust::TRUST_META_KEY,
                )? != nonce
            {
                return Err(Error::StreamRefused(
                    "private authority changed or request expired",
                ));
            }
            Ok(())
        };
        current()?;
        let owner = Arc::new(());
        let pending = {
            let mut room = shared.blocking_lock();
            if looks {
                // Looking takes no publication ownership: nothing to wait for, nothing held.
                let Native::Discover { before, floor, .. } = work else {
                    return Err(Error::Profile("private discovery step changed"));
                };
                room.prepare_pending_private_discovery(
                    &store,
                    Arc::clone(&owner),
                    peer,
                    &holders,
                    (before, floor),
                    false,
                )?
            } else {
                // Subscribed before the attempt: a publication released after it is not missed.
                let released = room.history_publication_wake();
                // This node's own post has the room's next publication, or another native
                // owner holds it: let go, and resume on its release. Checked under the lock the
                // preparation below reserves under, so that reservation is never refused busy.
                if room.authored_save_waits() || room.history_publication_busy(&store)? {
                    return Ok(Ran::Held(released, work.into_ask()));
                }
                match work {
                    Native::Page { ask, page_charge } => room.prepare_pending_private_page(
                        &store,
                        Arc::clone(&owner),
                        ask,
                        peer,
                        &holders,
                        page_charge,
                    ),
                    Native::Discover { before, floor, .. } => room
                        .prepare_pending_private_discovery(
                            &store,
                            Arc::clone(&owner),
                            peer,
                            &holders,
                            (before, floor),
                            true,
                        ),
                }?
            }
        };
        // The native run, off the room's lock, as the native owner runs it.
        let mut completed = pending.run(&store);
        if completed.result.is_ok() {
            if let Err(error) = current() {
                completed.result = Err(error);
            }
        }
        if looks {
            // It changed nothing: nothing to install and no ownership to release.
            return Ok(Ran::Saved(completed.result?, Arc::clone(&store), nonce));
        }
        let mut room = shared.blocking_lock();
        let saved = room.finish_pending_private_upgrade(completed);
        room.release_pending_text(&owner, false);
        drop(room);
        Ok(Ran::Saved(saved?, Arc::clone(&store), nonce))
    })
    .await
    .map_err(|_| Error::StreamRefused("private disk worker stopped"))??;
    Ok(ran)
}
