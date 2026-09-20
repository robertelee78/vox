//! ADR-008 anti-entropy sync on a typed `sync` stream, and the schedule ADR-016
//! specifies for it (§"Sync scheduling").
//!
//! The reconciliation engine is ADR-008's and is used unchanged; this module only
//! opens/accepts the stream and states the policy:
//!
//! - **When.** A session per shared channel on every new connection
//!   ([`SyncTrigger::Connected`]), every [`SYNC_INTERVAL_SECS`] while connected
//!   ([`SyncTrigger::Periodic`]), and a push immediately after a local append
//!   ([`SyncTrigger::LocalAppend`]). [`SyncSchedule`] is the pure clock-driven
//!   decision, so the node's timer logic is testable without a network.
//! - **Which mode.** Frontier mode until a channel exceeds
//!   [`RANGE_MODE_AUTHOR_THRESHOLD`] authors, then range reconciliation
//!   ([`should_use_range_mode`]) — the scale rule ADR-008 requires.
//!
//! ## The stream names its channel first
//! A frontier session reconciles **one channel's** log, but a connection is per
//! *peer* (ADR-016 §"Connections") and a peer may share several channels with us —
//! so the ADR-008 frames alone are not enough to know which log to open. The
//! initiator therefore sends a one-field preamble naming the `(channelID, epoch)`
//! before handing the stream to the engine, exactly as the join stream does. The
//! ADR-008 frame sequence itself is untouched; the channelID is not a secret (it is
//! on the board and in the invite link) and the preamble is inside the authenticated
//! stream regardless.
//!
//! ## Blocking, deliberately
//! ADR-008's engine is synchronous, and [`QuicStreamTransport`] bridges it onto
//! async quinn with [`tokio::runtime::Handle::block_on`]. A session therefore runs
//! on a thread that may block — `tokio::task::spawn_blocking` in the node, a plain
//! thread in tests — never inside an async task on a runtime worker.

use quinn::{RecvStream, SendStream};
use tokio::runtime::Handle;

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::{QuicStreamTransport, VoxConnection};
use crate::transport::streams::{open_typed, StreamKind};

/// Seconds between periodic sync sessions with a connected peer (ADR-016).
pub const SYNC_INTERVAL_SECS: u64 = 30;

/// Author count above which a channel reconciles in **range** mode instead of
/// frontier mode (ADR-008 at scale).
pub const RANGE_MODE_AUTHOR_THRESHOLD: usize = 100;

/// Whether a channel with `authors` admitted authors should use range
/// reconciliation rather than frontier mode.
#[must_use]
pub fn should_use_range_mode(authors: usize) -> bool {
    authors > RANGE_MODE_AUTHOR_THRESHOLD
}

/// Why a sync session is being run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncTrigger {
    /// A connection to this peer was just established.
    Connected,
    /// The periodic interval elapsed.
    Periodic,
    /// This node appended locally and is pushing it out.
    LocalAppend,
}

/// The per-peer sync clock (ADR-016 §"Sync scheduling"), as a pure function of
/// time and local appends so it can be tested without a network.
#[derive(Debug, Clone, Copy)]
pub struct SyncSchedule {
    last_sync: u64,
    pending_append: bool,
}

impl SyncSchedule {
    /// A schedule for a peer that has just connected: the first session is due
    /// immediately.
    #[must_use]
    pub fn connected() -> Self {
        Self {
            last_sync: 0,
            pending_append: false,
        }
    }

    /// Record a local append: the next check pushes it out without waiting for the
    /// interval.
    pub fn note_local_append(&mut self) {
        self.pending_append = true;
    }

    /// Record that a session ran at `now_secs`.
    pub fn note_synced(&mut self, now_secs: u64) {
        self.last_sync = now_secs;
        self.pending_append = false;
    }

    /// The trigger due at `now_secs`, if any. A local append wins over the
    /// interval, and the first call after [`SyncSchedule::connected`] is
    /// `Connected`.
    #[must_use]
    pub fn due(&self, now_secs: u64) -> Option<SyncTrigger> {
        if self.last_sync == 0 {
            return Some(SyncTrigger::Connected);
        }
        if self.pending_append {
            return Some(SyncTrigger::LocalAppend);
        }
        if now_secs.saturating_sub(self.last_sync) >= SYNC_INTERVAL_SECS {
            return Some(SyncTrigger::Periodic);
        }
        None
    }
}

impl Default for SyncSchedule {
    fn default() -> Self {
        Self::connected()
    }
}

/// The largest sync preamble either side will read (`[channel_id, epoch]`).
const MAX_SYNC_PREAMBLE: usize = 64;

/// Open a `sync`-typed bi-stream on `conn` for one channel and wrap it as the
/// ADR-008 transport. The kind frame is written first so the peer dispatches it,
/// then the preamble naming the channel (see the module docs).
pub async fn open_sync(
    conn: &VoxConnection,
    handle: Handle,
    channel_id: &Digest32,
    epoch: u64,
) -> Result<QuicStreamTransport> {
    let (mut send, recv) = open_typed(conn, StreamKind::Sync).await?;
    let mut e = Encoder::new();
    e.array(2).bytes(channel_id).uint(epoch);
    write_frame(&mut send, &e.finish()).await?;
    Ok(QuicStreamTransport::new(handle, send, recv))
}

/// Read the preamble from an accepted `sync` stream: which `(channelID, epoch)` the
/// peer wants to reconcile.
pub async fn read_sync_request(recv: &mut quinn::RecvStream) -> Result<(Digest32, u64)> {
    let bytes = read_frame(recv, MAX_SYNC_PREAMBLE)
        .await?
        .ok_or(Error::MalformedGovernance(
            "sync stream closed before preamble",
        ))?;
    let mut d = Decoder::new(&bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedGovernance("sync preamble arity"));
    }
    let channel_id: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedGovernance("sync preamble channel_id"))?;
    let epoch = d.uint()?;
    d.finish()?;
    Ok((channel_id, epoch))
}

/// Wrap an already-accepted, already-authorized `sync` stream as the ADR-008
/// transport (the manager accepted and classified it).
#[must_use]
pub fn accept_sync(handle: Handle, send: SendStream, recv: RecvStream) -> QuicStreamTransport {
    QuicStreamTransport::new(handle, send, recv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atrest::sek::Argon2Profile;
    use crate::error::Error;
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};
    use crate::nat::multiaddr::{EndpointList, Multiaddr};
    use crate::node::channel::ChannelState;
    use crate::node::net::{accept_authorized, ConnectionManager, PeerPolicy};
    use crate::node::paths::Paths;
    use crate::node::profile::Profile;
    use crate::transport::quic::{Admission, VoxEndpoint};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(20);
    const T0: u64 = 1_700_000_000;

    #[test]
    fn the_schedule_fires_on_connect_then_on_append_or_the_interval() {
        let mut s = SyncSchedule::connected();
        // A fresh connection syncs immediately.
        assert_eq!(s.due(1_000), Some(SyncTrigger::Connected));
        s.note_synced(1_000);
        assert_eq!(s.due(1_000), None);
        assert_eq!(s.due(1_000 + SYNC_INTERVAL_SECS - 1), None);

        // A local append pushes without waiting, and wins over the interval.
        s.note_local_append();
        assert_eq!(s.due(1_001), Some(SyncTrigger::LocalAppend));
        s.note_synced(1_001);
        assert_eq!(s.due(1_001), None);

        // Otherwise the interval governs.
        assert_eq!(
            s.due(1_001 + SYNC_INTERVAL_SECS),
            Some(SyncTrigger::Periodic)
        );
        assert_eq!(SYNC_INTERVAL_SECS, 30, "ADR-016 says every 30 seconds");
    }

    #[test]
    fn range_mode_is_selected_past_the_author_threshold() {
        assert!(!should_use_range_mode(1));
        assert!(!should_use_range_mode(RANGE_MODE_AUTHOR_THRESHOLD));
        assert!(should_use_range_mode(RANGE_MODE_AUTHOR_THRESHOLD + 1));
        assert_eq!(
            RANGE_MODE_AUTHOR_THRESHOLD, 100,
            "ADR-016 says a channel over 100 authors"
        );
    }
    fn signer_of(p: &Profile) -> crate::identity::composite::CompositePublicKey {
        RootSigner::public_key(p.signer().unwrap())
    }

    fn profile(tmp: &tempfile::TempDir, name: &str) -> Arc<Profile> {
        let paths = Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
        Arc::new(
            Profile::create_with_profile(paths, b"identity-pp", T0, Argon2Profile::REDUCED)
                .unwrap(),
        )
    }

    fn manager(seed: u8) -> Arc<ConnectionManager> {
        let s = SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0xFF; 32]).unwrap();
        let ep = Arc::new(VoxEndpoint::bind(&s, "127.0.0.1:0".parse().unwrap()).unwrap());
        Arc::new(ConnectionManager::new(ep, Arc::new(|| T0)))
    }

    fn endpoints_for(addr: SocketAddr) -> EndpointList {
        let SocketAddr::V4(v4) = addr else {
            unreachable!("loopback is v4")
        };
        EndpointList::new(vec![Multiaddr::Ip4(v4)]).unwrap()
    }

    /// Run one frontier session between two channels over a real `sync` stream,
    /// each half on its own thread (the ADR-008 engine blocks).
    fn sync_pair(
        rt: &tokio::runtime::Runtime,
        (left, left_p, left_seed): (ChannelState, Arc<Profile>, u8),
        (right, right_p, right_seed): (ChannelState, Arc<Profile>, u8),
        now: u64,
    ) -> (ChannelState, SyncOutcomePair, ChannelState) {
        let channel_id = left.channel_id();
        rt.block_on(async move {
            let lm = manager(left_seed);
            let rm = manager(right_seed);
            let l_id = lm.local_id();
            let l_eps = endpoints_for(lm.endpoint().local_addr().unwrap());
            let mut policy = PeerPolicy::new();
            policy.add_members([rm.local_id()]);

            let accept = {
                let lm = Arc::clone(&lm);
                tokio::spawn(async move {
                    let conn = lm
                        .accept(Admission::AcceptAnyAuthenticated)
                        .await
                        .unwrap()
                        .unwrap();
                    let (kind, send, recv) = accept_authorized(&conn, &policy).await.unwrap();
                    assert_eq!(kind, StreamKind::Sync);
                    (send, recv, conn)
                })
            };
            let conn = tokio::time::timeout(TIMEOUT, rm.connect(l_id, &l_eps))
                .await
                .unwrap()
                .unwrap();
            let right_t = open_sync(&conn, Handle::current(), &channel_id, 0)
                .await
                .unwrap();
            let (send, mut recv, server_conn) = accept.await.unwrap();
            let (want, epoch) = read_sync_request(&mut recv).await.unwrap();
            assert_eq!((want, epoch), (channel_id, 0));
            let left_t = accept_sync(Handle::current(), send, recv);

            let lh = std::thread::spawn(move || {
                let mut ch = left;
                let mut t = left_t;
                let out = ch.sync_over(left_p.store(), &mut t, now);
                (ch, out)
            });
            let rh = std::thread::spawn(move || {
                let mut ch = right;
                let mut t = right_t;
                let out = ch.sync_over(right_p.store(), &mut t, now);
                (ch, out)
            });
            let (left, out_l) = lh.join().unwrap();
            let (right, out_r) = rh.join().unwrap();
            drop(conn);
            drop(server_conn);
            lm.close_all();
            rm.close_all();
            (
                left,
                SyncOutcomePair {
                    left: out_l,
                    right: out_r,
                },
                right,
            )
        })
    }

    struct SyncOutcomePair {
        left: Result<crate::node::channel::SyncOutcome>,
        right: Result<crate::node::channel::SyncOutcome>,
    }

    /// Two members converge over a real `sync` stream and each renders the other's
    /// messages; a third member that syncs the same log but holds no sender key and
    /// no consent gets every entry and renders **nothing**.
    #[test]
    fn frontier_sync_over_quic_converges_and_renders_only_what_consent_allows() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let alice_p = profile(&tmp, "alice");
        let bob_p = profile(&tmp, "bob");
        let carol_p = profile(&tmp, "carol");
        let a_key = signer_of(&alice_p);
        let b_key = signer_of(&bob_p);
        let c_key = signer_of(&carol_p);
        let (a_fp, b_fp, c_fp) = (
            a_key.fingerprint(),
            b_key.fingerprint(),
            c_key.fingerprint(),
        );

        // Alice creates the channel and writes one message before anyone joins.
        let mut a = ChannelState::create_with_profile(
            &alice_p,
            "team",
            b"channel-pp",
            T0,
            Argon2Profile::REDUCED,
        )
        .unwrap();
        let cid = a.channel_id();
        a.append_text(&alice_p, "before bob", T0).unwrap();

        // Bob and Carol join from the genesis; keys come from it and the board.
        let mut b = ChannelState::join_channel_with_profile(
            &bob_p,
            a.genesis(),
            &cid,
            "team",
            b"channel-pp",
            T0,
            Argon2Profile::REDUCED,
        )
        .unwrap();
        let mut c = ChannelState::join_channel_with_profile(
            &carol_p,
            a.genesis(),
            &cid,
            "team",
            b"channel-pp",
            T0,
            Argon2Profile::REDUCED,
        )
        .unwrap();
        a.admit_author(alice_p.store(), &b_key, T0).unwrap();
        a.admit_author(alice_p.store(), &c_key, T0).unwrap();
        b.admit_author(bob_p.store(), &a_key, T0).unwrap();
        c.admit_author(carol_p.store(), &a_key, T0).unwrap();

        // Alice consents to Bob (never to Carol); Bob consents to Alice. In
        // production the SKDMs travel over a `pairwise` stream (proven there); here
        // they are handed over directly so this test isolates sync.
        let skdm_a = a.skdm_for_consent(&alice_p).unwrap();
        a.issue_consent(&alice_p, b_fp, &skdm_a, T0).unwrap();
        b.accept_skdm(bob_p.store(), &skdm_a, T0).unwrap();
        let skdm_b = b.skdm_for_consent(&bob_p).unwrap();
        b.issue_consent(&bob_p, a_fp, &skdm_b, T0).unwrap();
        a.accept_skdm(alice_p.store(), &skdm_b, T0).unwrap();

        // Each writes a message the other should be able to read.
        a.append_text(&alice_p, "hello bob", T0 + 1).unwrap();
        b.append_text(&bob_p, "hello alice", T0 + 1).unwrap();

        // --- Alice <-> Bob ---
        let (a, out, b) = sync_pair(
            &rt,
            (a, Arc::clone(&alice_p), 21),
            (b, Arc::clone(&bob_p), 23),
            T0 + 2,
        );
        let (l, r) = (out.left.unwrap(), out.right.unwrap());
        assert!(l.applied > 0 && r.applied > 0, "both learned");
        assert_eq!(l.rendered, 1, "Alice rendered Bob's message");
        assert_eq!(r.rendered, 1, "Bob rendered Alice's post-consent one");
        assert!(r.governance >= 1, "Bob learned Alice's grant");
        assert_eq!(a.entry_count(), b.entry_count(), "converged");

        let a_texts: Vec<&str> = a.timeline().iter().map(|r| r.text.as_str()).collect();
        let b_texts: Vec<&str> = b.timeline().iter().map(|r| r.text.as_str()).collect();
        assert!(a_texts.contains(&"hello alice"), "{a_texts:?}");
        assert!(b_texts.contains(&"hello bob"), "{b_texts:?}");
        // Forward-only history: Bob never sees what Alice wrote before consenting.
        assert!(!b_texts.contains(&"before bob"), "{b_texts:?}");

        // --- Alice <-> Carol, first attempt: Alice's log now carries Bob's entries,
        // and Carol has not admitted Bob — so she cannot verify them and the session
        // hard-fails with the coded reason. That is the constraint, not a defect: a
        // member must admit the channel's current members (their keys are on the
        // board) before it can sync. Whatever arrived before the failure is still
        // persisted, so even the failed attempt made durable progress.
        let (a, out, c) = sync_pair(
            &rt,
            (a, Arc::clone(&alice_p), 31),
            (c, Arc::clone(&carol_p), 33),
            T0 + 3,
        );
        assert!(matches!(
            out.right,
            Err(Error::MalformedGovernance(
                "sync failed: authenticator invalid"
            ))
        ));
        assert!(c.timeline().is_empty(), "nothing readable either way");

        // Carol admits Bob (whose key is on the board) and syncs again: the whole
        // log crosses — and she can still read none of it.
        let mut c = c;
        c.admit_author(carol_p.store(), &b_key, T0 + 4).unwrap();
        let (_a, out, c) = sync_pair(
            &rt,
            (a, Arc::clone(&alice_p), 41),
            (c, Arc::clone(&carol_p), 43),
            T0 + 5,
        );
        let r = out.right.unwrap();
        assert!(r.applied > 0, "Carol received the rest of the log");
        assert_eq!(
            r.rendered, 0,
            "no sender key and no consent: ciphertext only"
        );
        assert!(c.entry_count() > 0, "Carol holds the entries");
        assert!(c.timeline().is_empty(), "and can read none of them");
        assert!(!c.may_read(&a_fp, &c_fp), "Alice never consented to Carol");
    }
}
