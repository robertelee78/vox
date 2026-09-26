[0m
> build · gpt-6-astra
[0m
[0m⚙ [0mak_skill_search {"query":"github-work-accountability","limit":1}
[0m→ [0mSkill "github-work-accountability"
[0m✱ [0mGlob "**/AGENTS.md"[90m 0 matches[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m✱ [0mGlob "docs/adr/ADR-025-reviews/*.md"[90m 12 matches[0m
[0m
[0m$ [0mawa status --json
{"host": "github.com", "managed": true, "managed_issue_count": 206, "repository": "robertelee78/vox", "schema": "agent-work-accountability/status-v1", "transport": "github-rest-search"}
[0m
[0m✱ [0mGrep "^## (BLOCKER|MAJOR|MINOR|NIT|VERDICT)|^### |^## .*review|^# "[90m in docs/adr/ADR-025-reviews · 71 matches[0m
[0m
[0m$ [0mgit log -1 --oneline && git -C /opt/vox/.claude/worktrees/ac-fix202 log -1 --oneline
5846720 docs(adr): ADR-025 revision 4 — retirement, receive classes, backoff kinds, schedule points, journals; round-3 reviews (all BLOCK)
8436100 fix(sync): a sync that did not complete says why — a collision is not a governance error (#202, V210-29)
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/sync.rs[90m [offset=450, limit=580][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs[90m [offset=650, limit=310][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-astra.md[90m [offset=2948, limit=180][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-glm-5.3.md[90m [offset=2855, limit=130][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review-glm-5.3.md[90m [offset=259, limit=65][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review-astra.md[90m [offset=1607, limit=165][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-kimi-k3.md[90m [offset=2280, limit=90][0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review-kimi-k3.md[90m [offset=353, limit=80][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/syncstream.rs
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
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | python3 -c 'import sys; lines=sys.stdin.readlines(); spans=[(218,230),(1930,1945),(2000,2138),(2635,2740)]; [print(f"{i+1}: {s}",end="") for a,b in spans for i,s in enumerate(lines) if a<=i+1<=b]'
218: /// What one [`ChannelState::sync_over`] session did.
219: #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
220: pub struct SyncOutcome {
221:     /// Entries the ADR-008 session applied to the log.
222:     pub applied: usize,
223:     /// How many of those were governance entries folded into the evaluator.
224:     pub governance: usize,
225:     /// How many of those were decrypted and rendered into the timeline.
226:     pub rendered: usize,
227: }
228: 
229: /// What [`ChannelState::accept_entry`] did with a peer's entry.
230: #[derive(Debug, Clone, Copy, PartialEq, Eq)]
1930:             &self.authors,
1931:             &self.gov_entries,
1932:             now_secs,
1933:         )?);
1934:         Ok(hash)
1935:     }
1936: 
1937:     /// The governance entries a newly authored governance entry happens-after: the
1938:     /// hashes accepted so far (ADR-007's causal relation is only ever *followed*,
1939:     /// never trusted for authority).
1940:     fn gov_heads(&self) -> std::collections::BTreeSet<Digest32> {
1941:         self.gov_entries.iter().map(|g| g.entry_hash).collect()
1942:     }
1943: 
1944:     /// The resolver ADR-008 sync needs: this channel's admitted authors and the
1945:     /// entry classification for `kind_for`.
2000:         if let Ok(n) = session {
2001:             out.applied = n;
2002:         }
2003:         match session {
2004:             Ok(_) => Ok(out),
2005:             Err(code) => Err(sync_failure(code)),
2006:         }
2007:     }
2008: 
2009:     /// Each author's head, for [`ChannelState::absorb_arrived`] to find what a sync added.
2010:     fn heads(&self) -> BTreeMap<Digest32, u64> {
2011:         self.authors
2012:             .keys()
2013:             .map(|a| (*a, self.dag.feed(a).map_or(0, |f| f.max_seq())))
2014:             .collect()
2015:     }
2016: 
2017:     /// Persist, fold and render every entry a sync added past `before`'s heads.
2018:     fn absorb_arrived(
2019:         &mut self,
2020:         store: &Store,
2021:         before: &BTreeMap<Digest32, u64>,
2022:         now_secs: u64,
2023:     ) -> Result<SyncOutcome> {
2024:         let mut arrived: Vec<(Digest32, Digest32, Vec<u8>)> = Vec::new();
2025:         for (author, head) in before {
2026:             let Some(feed) = self.dag.feed(author) else {
2027:                 continue;
2028:             };
2029:             for seq in (head + 1)..=feed.max_seq() {
2030:                 if let Some(entry) = feed.get(seq) {
2031:                     let Some(payload) = entry.payload.clone() else {
2032:                         continue;
2033:                     };
2034:                     arrived.push((*author, entry.entry_hash(), payload));
2035:                 }
2036:             }
2037:         }
2038: 
2039:         let mut out = SyncOutcome {
2040:             applied: arrived.len(),
2041:             ..SyncOutcome::default()
2042:         };
2043:         for (author, entry_hash, payload) in arrived {
2044:             let key = self
2045:                 .authors
2046:                 .get(&author)
2047:                 .ok_or(Error::MalformedGovernance(
2048:                     "synced entry from an unadmitted author",
2049:                 ))?
2050:                 .clone();
2051:             let wire = self
2052:                 .dag
2053:                 .get_by_hash(&entry_hash)
2054:                 .ok_or(Error::MalformedGovernance("synced entry vanished"))?
2055:                 .to_wire();
2056:             let id = self.next_log_id;
2057:             let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
2058:             if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg) {
2059:                 self.poisoned = true;
2060:                 return Err(e);
2061:             }
2062:             self.next_log_id = id.saturating_add(1);
2063:             match classify_payload(&payload)? {
2064:                 EntryKind::Governance => {
2065:                     let entry = self
2066:                         .dag
2067:                         .get_by_hash(&entry_hash)
2068:                         .ok_or(Error::MalformedGovernance("synced entry vanished"))?
2069:                         .clone();
2070:                     let gov = GovEntry::from_verified_log_entry(
2071:                         &entry,
2072:                         &key,
2073:                         &self.channel_id,
2074:                         self.gov_heads(),
2075:                     )?;
2076:                     self.gov_entries.push(gov);
2077:                     self.evaluator = Arc::new(Self::build_evaluator(
2078:                         &self.genesis,
2079:                         &self.authors,
2080:                         &self.gov_entries,
2081:                         now_secs,
2082:                     )?);
2083:                     out.governance += 1;
2084:                 }
2085:                 EntryKind::Content => {
2086:                     if self.render_content(store, author, entry_hash, &payload, now_secs)? {
2087:                         out.rendered += 1;
2088:                     }
2089:                 }
2090:             }
2091:         }
2092:         // Reconciliation done; only now surface a session failure, with its coded
2093:         // reason preserved (ADR-008 never downgrades a failure silently).
2094:         Ok(out)
2095:     }
2096: 
2097:     /// Reconcile the room with a peer over `transport`, holding `shared`'s lock only inside each
2098:     /// protocol step — never across a send or a receive. See [`crate::log::sync::SessionRoom`].
2099:     ///
2100:     /// # Errors
2101:     /// The room is poisoned, a persist fails, or the session hard-fails.
2102:     pub fn sync_over_room<T: Transport>(
2103:         shared: &tokio::sync::Mutex<Self>,
2104:         store: &Store,
2105:         transport: &mut T,
2106:         now_secs: u64,
2107:     ) -> Result<SyncOutcome> {
2108:         let epoch = {
2109:             let ch = shared.blocking_lock();
2110:             if ch.poisoned {
2111:                 return Err(Error::Profile(
2112:                     "channel is poisoned after a failed persist; reopen it",
2113:                 ));
2114:             }
2115:             ch.epoch
2116:         };
2117:         let room = ChannelSessionRoom {
2118:             shared,
2119:             store,
2120:             now_secs,
2121:             epoch,
2122:             out: std::cell::RefCell::new(SyncOutcome::default()),
2123:             fatal: std::cell::RefCell::new(None),
2124:         };
2125:         let session = crate::log::sync::frontier_session_room(transport, &room);
2126:         if let Some(e) = room.fatal.take() {
2127:             return Err(e);
2128:         }
2129:         let mut out = room.out.into_inner();
2130:         match session {
2131:             Ok(n) => {
2132:                 out.applied = n;
2133:                 Ok(out)
2134:             }
2135:             Err(code) => Err(sync_failure(code)),
2136:         }
2137:     }
2138: 
2635:     /// Both ends must derive identical values or CPace simply fails to agree, so
2636:     /// deriving them from the shared genesis (rather than passing them around) is
2637:     /// what keeps the two sides honest.
2638:     pub fn join_context(&self) -> Result<crate::join::session::JoinContext> {
2639:         join_context_from_genesis(&self.genesis, self.epoch)
2640:     }
2641: 
2642:     /// Whether this channel can currently answer an inbound join.
2643:     #[must_use]
2644:     pub fn can_answer_join(&self) -> bool {
2645:         !self.passphrase.is_empty()
2646:     }
2647: }
2648: 
2649: /// A channel as a [`crate::log::sync::SessionRoom`]: each step locks the room, does its work, and
2650: /// lets go. See [`ChannelState::sync_over_room`].
2651: struct ChannelSessionRoom<'a> {
2652:     shared: &'a tokio::sync::Mutex<ChannelState>,
2653:     store: &'a Store,
2654:     now_secs: u64,
2655:     /// The epoch the session began at; a room that has moved on refuses what was staged for it.
2656:     epoch: u64,
2657:     out: std::cell::RefCell<SyncOutcome>,
2658:     /// A local failure (a persist that failed) that must reach the caller as itself, not as a code.
2659:     fatal: std::cell::RefCell<Option<Error>>,
2660: }
2661: 
2662: impl ChannelSessionRoom<'_> {
2663:     fn room(
2664:         &self,
2665:     ) -> std::result::Result<tokio::sync::MutexGuard<'_, ChannelState>, crate::wire::WireError>
2666:     {
2667:         let ch = self.shared.blocking_lock();
2668:         if ch.poisoned {
2669:             return Err(crate::wire::WireError::TransportFailed);
2670:         }
2671:         if ch.epoch != self.epoch {
2672:             return Err(crate::wire::WireError::EpochMismatch);
2673:         }
2674:         Ok(ch)
2675:     }
2676: }
2677: 
2678: impl crate::log::sync::SessionRoom for ChannelSessionRoom<'_> {
2679:     fn frontiers(
2680:         &self,
2681:     ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
2682:         Ok(crate::log::sync::frontiers_of(&self.room()?.dag))
2683:     }
2684: 
2685:     fn wants(
2686:         &self,
2687:         remote: &[crate::log::sync::FeedFrontier],
2688:     ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
2689:         Ok(crate::log::sync::wants_for(&self.room()?.dag, remote))
2690:     }
2691: 
2692:     fn entries(
2693:         &self,
2694:         wants: &[crate::log::sync::WantRange],
2695:     ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
2696:         Ok(crate::log::sync::entries_for_wants(
2697:             &self.room()?.dag,
2698:             wants,
2699:         ))
2700:     }
2701: 
2702:     fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
2703:         let mut guard = self.room()?;
2704:         let ch = &mut *guard;
2705:         let before = ch.heads();
2706:         // The resolver as it is *now*: an author revoked while this batch was on the wire is not
2707:         // an author of this room any more, and its entries are refused.
2708:         let resolver = ch.resolver();
2709:         // **Absorb what was stored, then report the failure.** `apply_staged` stores entries one
2710:         // at a time and stops at the first it refuses; those before it are already in the log.
2711:         // Returning the refusal first skipped persisting and rendering them, yet the log now held
2712:         // them, so every later session saw nothing to send and they were never shown: one joiner
2713:         // read nothing from the host in a room, silently, about one run in four (tworooms.sh). The
2714:         // refusal was the other joiner's entry, from an author this node had not admitted yet.
2715:         // `sync_over` always did it in this order ("reconciliation done; only now surface a
2716:         // session failure"); the per-step path lost it.
2717:         let stored = crate::log::sync::apply_staged(&mut ch.dag, &resolver, &ch.admission, &staged);
2718:         match ch.absorb_arrived(self.store, &before, self.now_secs) {
2719:             Ok(got) => {
2720:                 let mut out = self.out.borrow_mut();
2721:                 out.rendered += got.rendered;
2722:                 out.governance += got.governance;
2723:                 stored
2724:             }
2725:             Err(e) => {
2726:                 *self.fatal.borrow_mut() = Some(e);
2727:                 Err(crate::wire::WireError::TransportFailed)
2728:             }
2729:         }
2730:     }
2731: }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | python3 -c 'import sys; lines=sys.stdin.readlines(); spans=[(3320,3510),(4680,4750),(4770,4815),(4890,5000),(5010,5330)]; [print(f"{i+1}: {s}",end="") for a,b in spans for i,s in enumerate(lines) if a<=i+1<=b]'
3320:                 let entry = self.key_backoff.entry((channel_id, peer)).or_insert((0, 0));
3321:                 entry.0 = entry.0.saturating_add(1);
3322:                 entry.1 = now.saturating_add(1u64 << entry.0.min(6));
3323:                 let _ = self.event_tx.send(NodeEvent::KeyNotTaken {
3324:                     channel_id,
3325:                     peer,
3326:                     why,
3327:                 });
3328:             }
3329:             NetEvent::PublishDone {
3330:                 channel_id,
3331:                 board,
3332:                 outcomes,
3333:             } => {
3334:                 self.publishing.remove(&(channel_id, board));
3335:                 self.report_publish(&channel_id, board, outcomes);
3336:                 if !self.publishing.iter().any(|(room, _)| *room == channel_id) {
3337:                     let (ready, waiting): (Vec<_>, Vec<_>) =
3338:                         std::mem::take(&mut self.publish_waiters)
3339:                             .into_iter()
3340:                             .partition(|(room, _, _)| *room == channel_id);
3341:                     self.publish_waiters = waiting;
3342:                     if !ready.is_empty() {
3343:                         self.publish().await;
3344:                         for (_, reply, outcome) in ready {
3345:                             let _ = reply.send(outcome);
3346:                         }
3347:                     }
3348:                 }
3349:                 if self.publish_again.remove(&(channel_id, board)) {
3350:                     let conn = self.net.as_ref().and_then(|n| n.manager().existing(&board));
3351:                     if let Some(conn) = conn {
3352:                         self.publish_channel_to_anchor(&channel_id, &conn).await;
3353:                     }
3354:                 }
3355:                 // A session with that board for this room was held back while the round ran.
3356:                 self.push_now = true;
3357:             }
3358:             NetEvent::SkdmTaken { channel_id, peer } => {
3359:                 self.key_backoff.remove(&(channel_id, peer));
3360:             }
3361:             NetEvent::PushRetry { channel_id, peer } => {
3362:                 self.pending_push.insert(channel_id);
3363:                 // The failed session carried nothing, so this peer is owed the room again.
3364:                 if let Some(to) = self.pushed_to.get_mut(&channel_id) {
3365:                     to.remove(&peer);
3366:                 }
3367:                 if let Some(schedule) = self.schedules.get_mut(&peer) {
3368:                     schedule.note_local_append();
3369:                 }
3370:                 self.owed_first.insert(peer);
3371:                 self.push_now = true;
3372:             }
3373:             NetEvent::SyncDone {
3374:                 channel_id,
3375:                 peer,
3376:                 outcome,
3377:             } => {
3378:                 self.syncing.remove(&(channel_id, peer));
3379:                 self.answer_pending_consents(|room, _| *room == channel_id, None)
3380:                     .await;
3381:                 // **A session that failed delivered nothing, so its push is owed again.**
3382:                 // `run_due_syncs` counts a push as done when the session *starts*, which is the
3383:                 // only thing it can know then; a session the peer refused — because its own
3384:                 // session for this room was running — or that died on the wire carried nothing, and
3385:                 // the entry waited for the peer's next 30s interval. Measured over a forced relay
3386:                 // once pushes went out at once instead of on the tick: median 40–110ms, and a tail
3387:                 // at exactly 30s (p95 29.7–30.0s) — the collisions an immediate push makes more
3388:                 // likely. Owed again, retried on the *next tick* and not at once: a peer that keeps
3389:                 // refusing must not be answered with a tight loop.
3390:                 //
3391:                 // **Owed to that peer only, and not for ever.** The first version re-owed the room to
3392:                 // *every* peer, every time any session failed. A peer whose sessions always fail —
3393:                 // an anchor that keeps no log for the room refuses every one — was then re-owed
3394:                 // every tick, sorted ahead of the member it shared the room with, took the room each
3395:                 // pass, and the member's owed push lost every round: the independent verdict
3396:                 // measured 2–3 relayed runs in 10 losing a message for 120s (vox-bc, #41). Now the
3397:                 // retry goes to the peer that failed, at most `MAX_PUSH_RETRIES` times running; past
3398:                 // that the pair waits for the periodic interval like any other.
3399:                 //
3400:                 // **After a short random wait, not the next tick.** The commonest failure is a
3401:                 // collision: both ends push on the same event, each refuses the other because its
3402:                 // own session for the room is running, and both fail. Retried on the tick, the two
3403:                 // retries landed together again and a message took up to a second (median 364–531ms
3404:                 // in 3 of 10 relayed runs, measured). A random 20–100ms wait desynchronises them.
3405:                 if outcome.is_err() {
3406:                     let failures = self.push_failures.entry((channel_id, peer)).or_insert(0);
3407:                     *failures = failures.saturating_add(1);
3408:                     if *failures <= MAX_PUSH_RETRIES {
3409:                         let jitter = crate::identity::rng::random_array::<1>().map_or(0, |b| b[0]);
3410:                         let wait = Duration::from_millis(20 + u64::from(jitter) * 80 / 255);
3411:                         let tx = self.net_tx.clone();
3412:                         tokio::spawn(async move {
3413:                             tokio::time::sleep(wait).await;
3414:                             let _ = tx.send(NetEvent::PushRetry { channel_id, peer }).await;
3415:                         });
3416:                     }
3417:                 } else {
3418:                     self.push_failures.remove(&(channel_id, peer));
3419:                 }
3420:                 // The room is free now **whatever the outcome**: a push that found it mid-session
3421:                 // is owed and goes at once. Gating this on success left an owed push waiting for the
3422:                 // tick whenever the session that held the room failed — which a log-less anchor's
3423:                 // always does — and put a 1.00s ceiling on exactly the messages it delayed.
3424:                 if !self.pending_push.is_empty() {
3425:                     // A push that found this room mid-session is owed; the room is free now.
3426:                     self.push_now = true;
3427:                 }
3428:                 self.refresh_network_view().await;
3429:                 if let Ok(o) = outcome {
3430:                     // **Event, not interval.** Propagation was event-driven in one direction only:
3431:                     // an append here pushed at once, but a sync that *brought entries in* marked
3432:                     // nothing, so this node sat on them until its own `SYNC_INTERVAL_SECS`. For an
3433:                     // anchor that is the entire job undone — it holds the log for whoever is away and
3434:                     // then forwards it a half-minute late. End to end the worst case was 30s to reach
3435:                     // the anchor plus 30s for the next member to pull.
3436:                     //
3437:                     // Self-limiting rather than a storm: reconciliation is idempotent, so the peer
3438:                     // this came from applies nothing on the way back and marks nothing onward.
3439:                     // The actor-side half of what the slot just did: a session may have admitted
3440:                     // authors and mirrored records onto this node's board, and both change who may
3441:                     // reach whom and what the anchors should hold. `learn_members` used to do this
3442:                     // inline, which is how a round trip ended up on the single writer.
3443:                     //
3444:                     // **Only when the session actually brought something in**, which is the guard
3445:                     // the original had (`if learned > 0`, `if gained > 0`) and I dropped when moving
3446:                     // this out. Without it the actor did a publish round trip after *every* sync,
3447:                     // and syncs are frequent: measured, that turned a 0-1s crossing into 20s in
3448:                     // seven runs of ten while removing the losses. Losses gone is the right trade;
3449:                     // paying a publish per sync for it is not.
3450:                     if o.applied > 0 {
3451:                         self.note_local_append(&channel_id);
3452:                         self.refresh_reachers().await;
3453:                         self.publish_channel_to_anchors(&channel_id).await;
3454:                     }
3455:                     // **A newcomer this session admitted is consented to now, not on the tick.** Two
3456:                     // members who joined the same room learn of each other only here, from the board.
3457:                     // Under ForwardOnly a post sealed before the author consents to a reader is never
3458:                     // readable to it, so every tick of delay is a window of posts lost to the
3459:                     // newcomer. Measured in room_of_three_keys_proof: the joiners' keys to each other
3460:                     // landed 388ms and 846ms after their posts. This shrinks the window; it cannot
3461:                     // close it, since nobody can consent to a member it has not yet heard of.
3462:                     if !self.trust.is_empty() {
3463:                         let trusted = self.trust.trusted();
3464:                         let owes = match self.channels.get(&channel_id).map(Arc::clone) {
3465:                             Some(shared) => !shared.lock().await.owed_consents(&trusted).is_empty(),
3466:                             None => false,
3467:                         };
3468:                         if owes {
3469:                             self.deliver_owed_consents(None).await;
3470:                         }
3471:                     }
3472:                     if o.rendered > 0 || o.governance > 0 {
3473:                         let _ = self.event_tx.send(NodeEvent::Synced {
3474:                             channel_id,
3475:                             applied: o.applied as u64,
3476:                             rendered: o.rendered as u64,
3477:                         });
3478:                     }
3479:                 }
3480:             }
3481:             NetEvent::Stream { conn, inbound } => {
3482:                 // Held for the whole handler: the connection must outlive the streams
3483:                 // opened on it, or the peer sees it close mid-exchange.
3484:                 let connection = conn;
3485:                 match inbound {
3486:                     Inbound::Join { .. } => {
3487:                         // Unreachable: the stream loop turns these into
3488:                         // `NetEvent::JoinRequest` once the request is read.
3489:                     }
3490:                     Inbound::Pairwise { peer, send, recv } => {
3491:                         self.take_inbound_skdm(peer, send, recv).await;
3492:                     }
3493:                     Inbound::Sync { .. } => {
3494:                         // Unreachable: the stream loop converts these into
3495:                         // `NetEvent::SyncRequest` once the preamble is read.
3496:                     }
3497:                     Inbound::Punch {
3498:                         peer,
3499:                         coordinator,
3500:                         send,
3501:                         recv,
3502:                     } => {
3503:                         self.answer_punch(peer, coordinator, send, recv);
3504:                     }
3505:                     Inbound::Tunnel { peer, send, recv } => {
3506:                         // The snapshot is taken here (only the actor reads channel
3507:                         // state) and the tunnel runs on its own task: it lives as long
3508:                         // as the TCP connection it carries, which may be hours.
3509:                         let snapshot = self.host_snapshot().await;
3510:                         // The host is told who reached what, because the carried
4680:     /// third member saw a new one 24–28 s after the join returned; with the interval forced to
4681:     /// 5 s, 1.9–2.6 s. So when this node's board gains a bundle record from an author it has
4682:     /// not seen, it admits what the evidence allows and pushes the room to its connected members.
4683:     /// That push offers their boards the records they lack (`sync_one`), and each receiving
4684:     /// member does the same once, when the newcomer is new to it.
4685:     ///
4686:     /// **Bounded, not a storm.** Only a *new author* triggers this: a member's periodic refresh of
4687:     /// its own records does not. Each node therefore pushes at most once per newcomer, which is
4688:     /// the same fan-out one chat message already has, and in a 500-member room it is one pass per
4689:     /// member per join, over the connections it already holds, with nothing forwarded twice
4690:     /// because a board that already holds the record does not grow.
4691:     async fn note_new_members(&mut self, channel_id: &Digest32) {
4692:         // Not deferred while a session runs; see `publish_channel_to_anchors`.
4693:         let (Some(net), Some(shared)) = (
4694:             self.net.as_ref().map(Arc::clone),
4695:             self.channels.get(channel_id).map(Arc::clone),
4696:         ) else {
4697:             return;
4698:         };
4699:         let epoch = shared.lock().await.epoch();
4700:         let bundles = net.board_bundles(channel_id, epoch);
4701:         let known = self.board_authors.entry(*channel_id).or_default();
4702:         let fresh = bundles.iter().filter(|b| known.insert(b.author_id)).count();
4703:         if fresh == 0 {
4704:             return;
4705:         }
4706:         if let Some(store) = self.profile.as_ref().map(Profile::store_handle) {
4707:             let now = self.now();
4708:             let mut channel = shared.lock().await;
4709:             let _ = admit_board_records(
4710:                 &mut channel,
4711:                 &store,
4712:                 &bundles,
4713:                 ChannelState::MAX_ADMISSIONS_PER_SWEEP,
4714:                 now,
4715:             )
4716:             .await;
4717:         }
4718:         self.refresh_network_view().await;
4719:         self.note_local_append(channel_id);
4720:     }
4721: 
4722:     /// Whether a sync session with `peer` is running on `channel_id`: the collision a new
4723:     /// session with that peer for that room must not start into (see `syncing`).
4724:     fn in_session_with(&self, channel_id: &Digest32, peer: &Digest32) -> bool {
4725:         self.syncing.contains(&(*channel_id, *peer))
4726:     }
4727: 
4728:     /// Mark a channel as having a local append to push, and make every peer's
4729:     /// schedule due (ADR-016: "a push immediately after a local append").
4730:     fn note_local_append(&mut self, channel_id: &Digest32) {
4731:         if self.net.is_none() {
4732:             return;
4733:         }
4734:         self.push_now = true;
4735:         self.pending_push.insert(*channel_id);
4736:         // Something new: every peer is owed it again, including those that had the last one.
4737:         self.pushed_to.remove(channel_id);
4738:         for schedule in self.schedules.values_mut() {
4739:             schedule.note_local_append();
4740:         }
4741:     }
4742: 
4743:     /// Run whatever the ADR-016 sync schedule says is due. Returns whether anything
4744:     /// ran, so the caller only republishes the view when it might have changed.
4745:     ///
4746:     /// A peer with no live connection is skipped, not retried in place: it gets a
4747:     /// fresh schedule when it reconnects.
4748:     /// Re-run the ladder's publish side when the granted mappings are halfway through
4749:     /// their lifetime, so a node that outlives a two-hour mapping stays dialable.
4750:     ///
4770:         tokio::spawn(async move {
4771:             let mappings = net.refresh_advertised().await;
4772:             let _ = tx.send(NetEvent::AddressesDiscovered { mappings }).await;
4773:         });
4774:     }
4775: 
4776:     /// Push what a local append made due **now**, rather than at the next tick.
4777:     ///
4778:     /// A message was marked due by `note_local_append` and then waited for `TICK` — up to a full
4779:     /// second — before anything sent it: PRD-001 R40 asks for chat under a second, and measured
4780:     /// through the real binary the median was 322–894ms with a maximum of 1.021s, the tick's own
4781:     /// shape. Run after the command or event that made the push due, and after its reply, so the
4782:     /// command's own latency is unchanged.
4783:     ///
4784:     /// A burst coalesces for free: a room mid-session is owed rather than re-sent (see
4785:     /// `run_due_syncs`), and the session's `SyncDone` re-arms this while pushes are still owed, so
4786:     /// posts go out back to back instead of one per tick.
4787:     async fn push_if_owed(&mut self) {
4788:         if std::mem::take(&mut self.push_now) && self.run_due_syncs().await {
4789:             self.publish().await;
4790:         }
4791:     }
4792: 
4793:     async fn run_due_syncs(&mut self) -> bool {
4794:         let Some(net) = self.net.as_ref().map(Arc::clone) else {
4795:             return false;
4796:         };
4797:         let now = self.now();
4798:         let mut due: Vec<(Digest32, SyncTrigger)> = self
4799:             .schedules
4800:             .iter()
4801:             .filter_map(|(peer, s)| s.due(now).map(|t| (*peer, t)))
4802:             .collect();
4803:         // **Owed peers first.** `schedules` is keyed by fingerprint, so without this every pass
4804:         // visited peers in the same order, and one that sorted first and took the room each time
4805:         // left the rest skipped each time. A stable sort keeps fingerprint order within each group.
4806:         due.sort_by_key(|(peer, _)| !self.owed_first.contains(peer));
4807:         for (peer, _) in &due {
4808:             self.owed_first.remove(peer);
4809:         }
4810:         if due.is_empty() {
4811:             return false;
4812:         }
4813:         let mut ran = false;
4814:         // Which channels a local-append push actually got out. Everything else stays owed.
4815:         let mut pushed: std::collections::BTreeSet<Digest32> = std::collections::BTreeSet::new();
4890:                     };
4891:                     self.may_sync(&cid, &peer, epoch).await
4892:                 };
4893:                 if belongs {
4894:                     channels.push(cid);
4895:                 }
4896:             }
4897:             // An anchor forwards a room it keeps only to that room's authors — read fresh off its
4898:             // own board first, so a member that has just been vouched for is not skipped. It used to
4899:             // forward every kept room to any peer that connected or pushed.
4900:             let mut kept_rooms: Vec<Digest32> = Vec::new();
4901:             for cid in self.anchored.keys() {
4902:                 if trigger == SyncTrigger::LocalAppend
4903:                     && (!self.pending_push.contains(cid)
4904:                         || self.pushed_to.get(cid).is_some_and(|to| to.contains(&peer)))
4905:                 {
4906:                     continue;
4907:                 }
4908:                 if self.in_session_with(cid, &peer) {
4909:                     owed.push(*cid);
4910:                     continue;
4911:                 }
4912:                 kept_rooms.push(*cid);
4913:             }
4914:             for cid in kept_rooms {
4915:                 self.refresh_anchored_authors(&cid).await;
4916:                 let Some(state) = self.anchored.get(&cid).map(Arc::clone) else {
4917:                     continue;
4918:                 };
4919:                 if state.lock().await.is_author(&peer) {
4920:                     channels.push(cid);
4921:                 }
4922:             }
4923:             for channel_id in channels {
4924:                 if self.sync_one(&channel_id, peer).await {
4925:                     ran = true;
4926:                     // Any session carries the room's latest append, whatever triggered it.
4927:                     self.pushed_to.entry(channel_id).or_default().insert(peer);
4928:                     if trigger == SyncTrigger::LocalAppend {
4929:                         pushed.insert(channel_id);
4930:                     }
4931:                 }
4932:             }
4933:             if let Some(schedule) = self.schedules.get_mut(&peer) {
4934:                 schedule.note_synced(now);
4935:                 // **A room skipped because it was mid-session is owed, not synced.**
4936:                 //
4937:                 // The in-flight mark is per room, so when two peers came due for one room in the
4938:                 // same pass the first took it and the second was skipped — and `note_synced` above
4939:                 // then recorded the skipped peer as synced at the same `now` as the first. Both came
4940:                 // due together again, in the same `BTreeMap` order, and the same peer lost again:
4941:                 // **aligned once, aligned forever.** A local append makes every peer due at once, so
4942:                 // the alignment was the default after the first post, and which peer starved came
4943:                 // down to how the fingerprints sorted.
4944:                 //
4945:                 // Measured in `node_m15_anchor_gate` (instrumented, by the other session): in every
4946:                 // red, each member skipped the *other member* nine rounds running while its only
4947:                 // session — with the anchor — failed each time, so the one leg that could carry the
4948:                 // room never ran. Red about half the time in CI since before v0.2.5.
4949:                 //
4950:                 // Owed is not the unconditional retry the note on `pending_push` below warns
4951:                 // against: nothing here takes a lock, and it is retried only while that room is
4952:                 // mid-session, which is milliseconds. The next tick finds the room free.
4953:                 if !owed.is_empty() {
4954:                     owed_rooms.extend(owed.iter().copied());
4955:                     schedule.note_local_append();
4956:                     self.owed_first.insert(peer);
4957:                 }
4958:             }
4959:         }
4960:         // **Keep what did not go out.** This cleared unconditionally, which discarded the intent to
4961:         // push an append whenever it had not actually been pushed — and the ordinary case is a peer
4962:         // that has just joined: `note_local_append` marks "every peer's schedule due", but a peer
4963:         // whose `NetEvent::Connected` the actor has not handled yet **has no schedule to mark**, so
4964:         // nothing was owed to it and the entry was dropped rather than delayed. It then waited for
4965:         // that peer's own `SYNC_INTERVAL_SECS`, and if that raced too, longer.
4966:         //
4967:         // Measured as a user: with the daemons settled, twelve posts crossed twelve times in 0-1s;
4968:         // the proof that posts seconds after joining lost one in three.
4969:         //
4970:         // Note what is deliberately NOT changed: `note_synced` above still runs whether or not
4971:         // anything went out. Making it conditional looks right and is wrong — it leaves the peer due
4972:         // every tick, so one that cannot sync is retried once a second, each attempt taking the
4973:         // room's lock. Measured: that took the same proof from 4 of 6 to 3 of 8. The backoff must
4974:         // hold on failure; what must survive is the work owed, which is this line.
4975:         self.pending_push.retain(|cid| !pushed.contains(cid));
4976:         // **After** the retain, or it undoes this. The skip happens in exactly the pass where the
4977:         // room *was* pushed — to whichever peer took it first — so an owed room added inside the loop
4978:         // was then removed here as "pushed", and the skipped peer's retry next tick found nothing
4979:         // owed and dropped the push. It still arrived, on the next interval: up to 30s late instead
4980:         // of immediately, and invisible to any gate that only asks whether it arrived. Found in
4981:         // review by the other session.
4982:         //
4983:         // Known and not fixed here: `pushed` means a session *started*, not that it delivered, so a
4984:         // push to a peer whose session then fails is counted as done.
4985:         self.pending_push.extend(owed_rooms);
4986:         ran
4987:     }
4988: 
4989:     /// Start reconciling one channel with one peer: learn who else has joined, then
4990:     /// hand the channel to a detached session task.
4991:     ///
4992:     /// Returns whether a session was *started*. It is deliberately not awaited — see
4993:     /// [`NetEvent::SyncDone`] for why awaiting deadlocks two nodes that start at the
4994:     /// same moment. While the channel is away it is invisible to commands (they answer
4995:     /// `UnknownChannel`) and, usefully, to this function, so a second pass cannot start
4996:     /// a concurrent session for the same channel.
4997:     async fn sync_one(&mut self, channel_id: &Digest32, peer: Digest32) -> bool {
4998:         let Some(net) = self.net.as_ref().map(Arc::clone) else {
4999:             return false;
5000:         };
5010:         ) {
5011:             (Some(shared), _) => SessionTarget::Channel(shared),
5012:             (None, Some(state)) => SessionTarget::Anchored(state),
5013:             (None, None) => return false,
5014:         };
5015:         // An anchor's authors come from its own board, which is local: cheap, and it has to happen
5016:         // before the session so the anchor can verify what arrives.
5017:         if matches!(target, SessionTarget::Anchored(_)) {
5018:             self.refresh_anchored_authors(channel_id).await;
5019:         }
5020:         if self.in_session_with(channel_id, &peer) {
5021:             return false; // a session with this peer already has this room
5022:         }
5023:         let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
5024:             return false; // past the cap: skipped, not queued. The schedule comes round again.
5025:         };
5026:         self.syncing.insert((*channel_id, peer));
5027:         let admit_store = self.profile.as_ref().map(Profile::store_handle);
5028:         let cid = *channel_id;
5029:         let now = self.now();
5030:         let tx = self.net_tx.clone();
5031:         tokio::spawn(async move {
5032:             let _slot = slot;
5033:             // 1. Learn who else has joined, or the first entry from a newer member kills the session
5034:             //    (ADR-008). A round trip, so it belongs here and not on the actor.
5035:             let epoch = match &target {
5036:                 SessionTarget::Channel(shared) => {
5037:                     let known = shared.lock().await.epoch();
5038:                     if let Some(pstore) = admit_store {
5039:                         if let Ok(set) = net.fetch_channel(&conn, &cid, known).await {
5040:                             {
5041:                                 let mut ch = shared.lock().await;
5042:                                 let _ = admit_board_records(
5043:                                     &mut ch,
5044:                                     &pstore,
5045:                                     &set.bundles,
5046:                                     ChannelState::MAX_ADMISSIONS_PER_SWEEP,
5047:                                     now,
5048:                                 )
5049:                                 .await;
5050:                             }
5051:                             // What the peer's board holds is filed on this node's own, so its board
5052:                             // carries the whole membership it knows. Bundles go first: they carry
5053:                             // the key an address record is verified with (M15.2a). Mirroring to the
5054:                             // anchors follows on the actor when `SyncDone` lands, because that needs
5055:                             // channel state.
5056:                             for wire in set
5057:                                 .bundles
5058:                                 .iter()
5059:                                 .map(MemberBundleRecord::to_wire)
5060:                                 .chain(set.members.iter().map(RendezvousRecord::to_wire))
5061:                             {
5062:                                 let _ = net.publish_local(&wire);
5063:                             }
5064:                             // **And the other way: what this node's board holds that the peer's
5065:                             // lacks.** A member who joined through this node is on this node's
5066:                             // board and no other, and the peer learned of it only when *it* next
5067:                             // read this board, on its own periodic sync: 24–28 s for a third
5068:                             // member to see a new one, measured. Offered here, a push that follows
5069:                             // a join carries the newcomer to every connected member at once.
5070:                             // Best-effort: a refusal (a record the peer's board already holds
5071:                             // newer) costs nothing, and the peer's own sync still reads this board.
5072:                             let missing = net.board_records_missing_from(&cid, known, &set);
5073:                             if !missing.is_empty() {
5074:                                 if let Ok(mut client) =
5075:                                     crate::nat::service::RendezvousClient::open(&conn).await
5076:                                 {
5077:                                     for wire in &missing {
5078:                                         if let Err(e) = client.put(wire).await {
5079:                                             if !matches!(e, Error::RendezvousRejected(_)) {
5080:                                                 break;
5081:                                             }
5082:                                         }
5083:                                     }
5084:                                     client.finish();
5085:                                 }
5086:                             }
5087:                         }
5088:                     }
5089:                     shared.lock().await.epoch()
5090:                 }
5091:                 SessionTarget::Anchored(state) => state.lock().await.epoch(),
5092:             };
5093:             // 2. Open the stream. Also a round trip.
5094:             //
5095:             // **A stream that will not open still reports.** This returned without a word, and the
5096:             // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
5097:             // marked mid-session for good: every later sync of it skipped, every inbound one
5098:             // refused, and nothing said so. Every exit from this task now sends `SyncDone`.
5099:             let handle = tokio::runtime::Handle::current();
5100:             let transport =
5101:                 match crate::node::syncstream::open_sync(&conn, handle, &cid, epoch).await {
5102:                     Ok(t) => t,
5103:                     Err(e) => {
5104:                         let _ = tx
5105:                             .send(NetEvent::SyncDone {
5106:                                 channel_id: cid,
5107:                                 peer,
5108:                                 outcome: Err(e),
5109:                             })
5110:                             .await;
5111:                         return;
5112:                     }
5113:                 };
5114:             // 3. Run the session. It takes the room's lock inside each protocol step and never across
5115:             //    a send or a receive (`sync_over_room`), so a peer slow to answer no longer holds the
5116:             //    room — or, through `publish()` and every other lock on it, the actor.
5117:             let joined = tokio::task::spawn_blocking(move || {
5118:                 let mut t = transport;
5119:                 match target {
5120:                     SessionTarget::Channel(shared) => {
5121:                         crate::node::channel::ChannelState::sync_over_room(
5122:                             &shared, &store, &mut t, now,
5123:                         )
5124:                     }
5125:                     SessionTarget::Anchored(state) => {
5126:                         crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
5127:                     }
5128:                 }
5129:             })
5130:             .await;
5131:             // A session that panicked still hands the room back: `Err` from the join is the panic.
5132:             let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
5133:                 "sync session panicked",
5134:             )));
5135:             let _ = tx
5136:                 .send(NetEvent::SyncDone {
5137:                     channel_id: cid,
5138:                     peer,
5139:                     outcome,
5140:                 })
5141:                 .await;
5142:         });
5143:         true
5144:     }
5145: 
5146:     /// Take the channel out of the actor's map and run a session on its own task,
5147:     /// returning it through [`NetEvent::SyncDone`].
5148:     fn start_session(
5149:         &mut self,
5150:         channel_id: Digest32,
5151:         peer: Digest32,
5152:         transport: crate::transport::quic::QuicStreamTransport,
5153:     ) {
5154:         let Some(store) = self.log_store() else {
5155:             return;
5156:         };
5157:         let target = match (
5158:             self.channels.get(&channel_id).map(Arc::clone),
5159:             self.anchored.get(&channel_id).map(Arc::clone),
5160:         ) {
5161:             (Some(shared), _) => SessionTarget::Channel(shared),
5162:             (None, Some(state)) => SessionTarget::Anchored(state),
5163:             (None, None) => return,
5164:         };
5165:         // Marked here, past both early returns above, so a session that never starts never
5166:         // leaves the room marked. Its caller used to mark it first.
5167:         self.syncing.insert((channel_id, peer));
5168:         let now = self.now();
5169:         let tx = self.net_tx.clone();
5170:         tokio::spawn(async move {
5171:             let joined = tokio::task::spawn_blocking(move || {
5172:                 // The room is locked inside each protocol step only, never across the
5173:                 // network (`sync_over_room`).
5174:                 let mut t = transport;
5175:                 match target {
5176:                     SessionTarget::Channel(shared) => {
5177:                         crate::node::channel::ChannelState::sync_over_room(
5178:                             &shared, &store, &mut t, now,
5179:                         )
5180:                     }
5181:                     SessionTarget::Anchored(state) => {
5182:                         crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
5183:                     }
5184:                 }
5185:             })
5186:             .await;
5187:             let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
5188:                 "sync session panicked",
5189:             )));
5190:             let _ = tx
5191:                 .send(NetEvent::SyncDone {
5192:                     channel_id,
5193:                     peer,
5194:                     outcome,
5195:                 })
5196:                 .await;
5197:         });
5198:     }
5199: 
5200:     /// Reconcile a channel with every member this node can reach, now (the `Sync`
5201:     /// command; the schedule does this automatically — ADR-016 §"Sync scheduling").
5202:     async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
5203:         if self.net.is_none() {
5204:             return Outcome::Failed(Fault::NotNetworked);
5205:         }
5206:         let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
5207:             return Outcome::Failed(Fault::UnknownChannel);
5208:         };
5209:         let peers: Vec<Digest32> = {
5210:             let channel = shared.lock().await;
5211:             let me = channel.me();
5212:             channel.members().into_iter().filter(|m| *m != me).collect()
5213:         };
5214:         let mut synced = 0usize;
5215:         for peer in peers {
5216:             if self.sync_one(channel_id, peer).await {
5217:                 synced += 1;
5218:             }
5219:         }
5220:         if synced == 0 {
5221:             return Outcome::Failed(Fault::Unreachable);
5222:         }
5223:         Outcome::Done
5224:     }
5225: 
5226:     /// Reconcile one channel's log with a peer over an inbound `sync` stream (ADR-008
5227:     /// frontier mode), on its own task for the reason [`NetEvent::SyncDone`] gives.
5228:     /// Serve one sync session for a request that has **already been read**.
5229:     ///
5230:     /// The preamble is read on the per-connection stream task (`node::network`), not here: the
5231:     /// actor is the only writer of channel state and anything it awaits inline stops the whole
5232:     /// node, so it must never wait on an untrusted peer to speak. What it does here is local
5233:     /// and ordered, which is what the single-task design is for.
5234:     /// **Only a member of *this* room is served its log** (PRD-001 R5). The stream-kind gate
5235:     /// in `node::net` asks whether the peer may open a sync stream *at all*, which any member
5236:     /// of any room this node holds may — and the preamble then names whichever channel the
5237:     /// peer likes. Nothing here checked the two against each other, so a member of room A who
5238:     /// had ever seen room B's `.vox` name was handed B's whole log (PRD-001 D5). See
5239:     /// [`Self::may_sync`] for who counts.
5240:     async fn run_sync_session(
5241:         &mut self,
5242:         peer: Digest32,
5243:         channel_id: Digest32,
5244:         epoch: u64,
5245:         send: quinn::SendStream,
5246:         recv: quinn::RecvStream,
5247:     ) {
5248:         use crate::node::syncstream::accept_sync;
5249:         // Answering while our own session holds this room is the other half of the deadlock.
5250:         //
5251:         // **Refused explicitly, not by dropping the streams.** Letting them drop leaves the peer
5252:         // reading for a frame that will never come until `SYNC_FRAME_TIMEOUT` expires — the
5253:         // silent refusal that reads as a hang, which is the shape of defect this whole change
5254:         // exists to remove. A reset reaches it on the next read, and its schedule brings it
5255:         // back in a second.
5256:         //
5257:         // **Refused before the lock, not after.** A session holds this room's mutex for its whole
5258:         // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
5259:         // behind the very session this check exists to detect.
5260:         if self.in_session_with(&channel_id, &peer) {
5261:             let (mut send, mut recv) = (send, recv);
5262:             crate::node::net::refuse_stream(&mut send, &mut recv);
5263:             return;
5264:         }
5265:         // Only a channel we hold open at that epoch — or keep as an anchor — can be
5266:         // reconciled. An anchor whose board just received the genesis adopts it here
5267:         // rather than making the member wait for the next tick.
5268:         if !self.channels.contains_key(&channel_id) {
5269:             self.adopt_anchored(&channel_id).await;
5270:             self.refresh_anchored_authors(&channel_id).await;
5271:         }
5272:         let matches_epoch = match (
5273:             self.channels.get(&channel_id),
5274:             self.anchored.get(&channel_id),
5275:         ) {
5276:             (Some(shared), _) => shared.lock().await.epoch() == epoch,
5277:             (None, Some(state)) => state.lock().await.epoch() == epoch,
5278:             (None, None) => false,
5279:         };
5280: 
5281:         // **Refused, not dropped.** A node asked for a room it does not hold — an anchor that keeps
5282:         // no log for it, most often — or at an epoch it is not at, returned here and let the streams
5283:         // fall, and the initiator learned only `sync failed: transport` — indistinguishable from a
5284:         // connection that died. Every push to an anchor that keeps no log for the room read as a
5285:         // network fault. A coded reset says what happened. (It does not recover time: a dropped
5286:         // stream already ended the initiator's session within milliseconds, measured; the long
5287:         // losses once blamed on this were the room-wide starvation v0.2.8 fixed.)
5288:         if !matches_epoch {
5289:             let (mut send, mut recv) = (send, recv);
5290:             crate::node::net::refuse_stream(&mut send, &mut recv);
5291:             return;
5292:         }
5293:         if !self.may_sync(&channel_id, &peer, epoch).await {
5294:             // Refused explicitly, with the same coded reset as a stream kind the peer may not
5295:             // open, rather than left to read for a frame that never comes.
5296:             let (mut send, mut recv) = (send, recv);
5297:             crate::node::net::refuse_stream(&mut send, &mut recv);
5298:             return;
5299:         }
5300:         let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
5301:         self.start_session(channel_id, peer, transport);
5302:     }
5303: 
5304:     /// Whether `peer` may reconcile `channel_id`'s log with this node.
5305:     ///
5306:     /// - An **admitted author** of that room. If it is not one yet, this node's own board is
5307:     ///   consulted first — local, so cheap — because a member that joined through somebody
5308:     ///   else is on the board before it is in this node's author table, and refusing it for
5309:     ///   that would be the "precondition behind its own check" defect `run_due_syncs` documents.
5310:     ///   Admission there takes the same M17.6 evidence as everywhere else.
5311:     /// - An **anchor of that room** — in the room's own anchor set, which holds this node's
5312:     ///   configured anchors and those the room's link named. It keeps the room's ciphertext by
5313:     ///   design (ADR-016 M15.2b) for members who are away. An anchor named only by *another*
5314:     ///   room's link is not an anchor of this one.
5315:     ///
5316:     /// For a room this node only anchors, the peer must be an author the board knows.
5317:     async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
5318:         if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
5319:             {
5320:                 let channel = shared.lock().await;
5321:                 if channel.is_author(peer)
5322:                     || channel.anchors().nodes().iter().any(|a| a.id == *peer)
5323:                 {
5324:                     return true;
5325:                 }
5326:             }
5327:             let (Some(net), Some(store)) = (
5328:                 self.net.as_ref().map(Arc::clone),
5329:                 self.profile.as_ref().map(Profile::store_handle),
5330:             ) else {
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | python3 -c 'import sys; lines=sys.stdin.readlines(); spans=[(560,621),(811,940)]; [print(f"{i+1}: {s}",end="") for a,b in spans for i,s in enumerate(lines) if a<=i+1<=b]'
560: }
561: 
562: /// Map a DAG [`Rejected`] to the M0 wire application-error code.
563: #[must_use]
564: pub fn wire_error_for_rejected(rej: &Rejected) -> WireError {
565:     match rej {
566:         Rejected::NotAdmitted => WireError::EpochMismatch,
567:         Rejected::Verification(e) => wire_error_for(e),
568:         Rejected::Feed(_) => WireError::AuthenticatorInvalid,
569:         Rejected::Fork(_) => WireError::AuthenticatorInvalid,
570:         Rejected::GovernanceNotAttributable => WireError::AuthenticatorInvalid,
571:         // A duplicate is not a hard fail; callers handle it before mapping. If it
572:         // ever reaches here, treat as a benign authenticator-class rejection.
573:         Rejected::Duplicate => WireError::AuthenticatorInvalid,
574:     }
575: }
576: 
577: /// The outcome of applying a received `ENTRY` frame.
578: #[derive(Debug)]
579: #[non_exhaustive]
580: pub enum ApplyOutcome {
581:     /// The entry was newly stored.
582:     Stored,
583:     /// The entry was a duplicate (idempotent — already held).
584:     Duplicate,
585:     /// The entry conflicted with a stored one at the same `(author, seq)`: a fork.
586:     /// This is a *local security event*, NOT a wire-protocol violation — it is
587:     /// recorded/surfaced (an attributable fork freezes the author; a deniable one
588:     /// raises an alarm) and sync **continues**. The stream is not closed for a
589:     /// fork (ADR-008 §"Fork / equivocation handling").
590:     Fork,
591: }
592: 
593: /// Apply a received `ENTRY` wire frame to the local [`Dag`] under the full
594: /// acceptance predicate.
595: ///
596: /// Returns [`ApplyOutcome`] for the non-fatal cases (stored / duplicate / fork)
597: /// and `Err(WireError)` only for a *hard wire fail* that must close the stream —
598: /// mapped to the exact M0 code via [`wire_error_for`] / [`wire_error_for_rejected`]
599: /// (unknown tag, unsupported version, unknown algo, authenticator, …). A
600: /// **fork is not a wire fail**: it is surfaced and sync continues, so two
601: /// partitions can exchange conflicting heads and form the proof.
602: pub fn apply_entry<R: AuthorResolver>(
603:     dag: &mut Dag,
604:     resolver: &R,
605:     admission: &AdmissionPolicy,
606:     entry_wire: &[u8],
607: ) -> std::result::Result<ApplyOutcome, WireError> {
608:     let entry = Entry::from_wire(entry_wire).map_err(|e| wire_error_for(&e))?;
609:     let key = resolver
610:         .key_for(&entry.skeleton.author_id)
611:         .ok_or(WireError::AuthenticatorInvalid)?;
612:     let kind = resolver.kind_for(&entry);
613:     match dag.accept(entry, kind, &key, admission) {
614:         Ok(_) => Ok(ApplyOutcome::Stored),
615:         Err(Rejected::Duplicate) => Ok(ApplyOutcome::Duplicate),
616:         // A fork is recorded by `accept` (freeze / proof) and surfaced; it does
617:         // not close the stream.
618:         Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork),
619:         Err(other) => Err(wire_error_for_rejected(&other)),
620:     }
621: }
811: /// What a frontier session may do to a room, **one step at a time**. Each method takes the room's
812: /// lock, does its step, releases the lock and returns owned data; none of them sees the transport.
813: /// [`frontier_session_room`] sees the transport and never the room. So no lock can be held across a
814: /// network wait, and the compiler keeps it that way: there is no scope in which both exist.
815: ///
816: /// This replaces a session that held the room's mutex from its first frame to its last. A peer that
817: /// was slow to answer then held the room for up to the frame timeout, and every other use of the
818: /// room — a message being posted, the node's view being published after every event — waited
819: /// behind it (ADR-008's own implementation note named the fix).
820: pub trait SessionRoom {
821:     /// The room's frontiers, for `HAVE`.
822:     ///
823:     /// # Errors
824:     /// The room is unusable (poisoned, or moved to another epoch).
825:     fn frontiers(&self) -> std::result::Result<Vec<FeedFrontier>, WireError>;
826:     /// What to ask the peer for, given its `HAVE`.
827:     ///
828:     /// # Errors
829:     /// As [`SessionRoom::frontiers`].
830:     fn wants(&self, remote: &[FeedFrontier]) -> std::result::Result<Vec<WantRange>, WireError>;
831:     /// The entries to serve for the peer's `WANT` — owned and bounded.
832:     ///
833:     /// # Errors
834:     /// As [`SessionRoom::frontiers`].
835:     fn entries(&self, wants: &[WantRange]) -> std::result::Result<Vec<Vec<u8>>, WireError>;
836:     /// Apply a batch of received entries under a fresh lock, **against the room's current rules**: an
837:     /// author revoked while the batch was on the wire is refused, and a room that moved to another
838:     /// epoch refuses the whole batch. Returns how many were newly stored.
839:     ///
840:     /// # Errors
841:     /// A hard sync failure from an entry, or the room is unusable.
842:     fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, WireError>;
843: }
844: 
845: /// How many received entries are staged before a batch is applied. Bounds what a session holds in
846: /// memory between locks; each batch is one short hold of the room.
847: pub const MAX_STAGED: usize = 256;
848: 
849: /// One peer's half of a frontier session, over `t`, against `room` — the same protocol as
850: /// [`frontier_session_peer`], with the room locked only inside each [`SessionRoom`] step and never
851: /// across a send or a receive.
852: ///
853: /// # Errors
854: /// The coded [`WireError`] of a hard fail; the transport is closed with it.
855: pub fn frontier_session_room<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
856: where
857:     T: Transport,
858:     S: SessionRoom + ?Sized,
859: {
860:     match frontier_session_room_inner(t, room) {
861:         Ok(applied) => Ok(applied),
862:         Err(code) => {
863:             t.close(code);
864:             Err(code)
865:         }
866:     }
867: }
868: 
869: fn frontier_session_room_inner<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
870: where
871:     T: Transport,
872:     S: SessionRoom + ?Sized,
873: {
874:     let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);
875: 
876:     send(t, encode_hello(SYNC_MODE_FRONTIER))?;
877:     let remote_hello = expect_hello(t.recv())?;
878:     negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;
879: 
880:     send(t, encode_have(&room.frontiers()?))?;
881:     let remote_have = expect_have(t.recv())?;
882: 
883:     send(t, encode_want(&room.wants(&remote_have)?))?;
884:     let their_wants = expect_want(t.recv())?;
885: 
886:     let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
887:     for wire in room.entries(&their_wants)? {
888:         if std::time::Instant::now() >= serve_deadline {
889:             break;
890:         }
891:         send(t, encode_entry(&wire))?;
892:     }
893:     t.finish();
894: 
895:     // Drained with no lock held; applied a batch at a time under a fresh one.
896:     let deadline = std::time::Instant::now() + DRAIN_BUDGET;
897:     let mut staged: Vec<Vec<u8>> = Vec::new();
898:     let mut applied = 0;
899:     while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
900:         if std::time::Instant::now() >= deadline {
901:             return Err(WireError::SyncModeUnsupported);
902:         }
903:         match decode_frame(&frame) {
904:             Ok(SyncFrame::Entry(wire)) => {
905:                 staged.push(wire);
906:                 if staged.len() >= MAX_STAGED {
907:                     applied += room.apply(std::mem::take(&mut staged))?;
908:                 }
909:             }
910:             Ok(_) | Err(_) => return Err(WireError::SyncModeUnsupported),
911:         }
912:     }
913:     if !staged.is_empty() {
914:         applied += room.apply(staged)?;
915:     }
916:     Ok(applied)
917: }
918: 
919: /// Apply staged entries into `dag`, returning how many were newly stored — the apply half of
920: /// [`SessionRoom::apply`], for a caller that already holds its room.
921: ///
922: /// # Errors
923: /// The first hard sync failure.
924: pub fn apply_staged<R: AuthorResolver>(
925:     dag: &mut Dag,
926:     resolver: &R,
927:     admission: &AdmissionPolicy,
928:     staged: &[Vec<u8>],
929: ) -> std::result::Result<usize, WireError> {
930:     let mut stored = 0;
931:     for wire in staged {
932:         if matches!(
933:             apply_entry(dag, resolver, admission, wire)?,
934:             ApplyOutcome::Stored
935:         ) {
936:             stored += 1;
937:         }
938:     }
939:     Ok(stored)
940: }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/anchor.rs | python3 -c 'import sys; lines=sys.stdin.readlines(); spans=[(280,470)]; [print(f"{i+1}: {s}",end="") for a,b in spans for i,s in enumerate(lines) if a<=i+1<=b]'
280:         before: &BTreeMap<Digest32, u64>,
281:     ) -> Result<SyncOutcome> {
282:         let mut arrived: Vec<Digest32> = Vec::new();
283:         for (author, head) in before {
284:             let Some(feed) = self.dag.feed(author) else {
285:                 continue;
286:             };
287:             for seq in (head + 1)..=feed.max_seq() {
288:                 if let Some(entry) = feed.get(seq) {
289:                     arrived.push(entry.entry_hash());
290:                 }
291:             }
292:         }
293:         let mut out = SyncOutcome {
294:             applied: arrived.len(),
295:             ..SyncOutcome::default()
296:         };
297:         for entry_hash in arrived {
298:             let entry = self
299:                 .dag
300:                 .get_by_hash(&entry_hash)
301:                 .ok_or(Error::MalformedGovernance("synced entry vanished"))?;
302:             let wire = entry.to_wire();
303:             let is_governance = entry
304:                 .payload
305:                 .as_deref()
306:                 .map(classify_payload)
307:                 .transpose()?
308:                 .is_some_and(|k| k == EntryKind::Governance);
309:             let id = self.next_log_id;
310:             let seg = seal_segment(&self.sek, SegmentKind::AnchorLog, id, &wire)?;
311:             if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::AnchorLog, id, &seg) {
312:                 self.poisoned = true;
313:                 return Err(e);
314:             }
315:             self.next_log_id = id.saturating_add(1);
316:             if is_governance {
317:                 out.governance += 1;
318:             }
319:         }
320:         Ok(out)
321:     }
322: 
323:     /// Reconcile with a peer over `transport`, holding `shared`'s lock only inside each protocol
324:     /// step. See [`crate::log::sync::SessionRoom`] and `ChannelState::sync_over_room`.
325:     ///
326:     /// # Errors
327:     /// The copy is poisoned, a persist fails, or the session hard-fails.
328:     pub fn sync_over_room<T: Transport>(
329:         shared: &tokio::sync::Mutex<Self>,
330:         store: &Store,
331:         transport: &mut T,
332:     ) -> Result<SyncOutcome> {
333:         let epoch = {
334:             let st = shared.blocking_lock();
335:             if st.poisoned {
336:                 return Err(Error::Profile(
337:                     "anchored channel is poisoned after a failed persist; reopen it",
338:                 ));
339:             }
340:             st.epoch
341:         };
342:         let room = AnchorSessionRoom {
343:             shared,
344:             store,
345:             epoch,
346:             out: std::cell::RefCell::new(SyncOutcome::default()),
347:             fatal: std::cell::RefCell::new(None),
348:         };
349:         let session = crate::log::sync::frontier_session_room(transport, &room);
350:         if let Some(e) = room.fatal.take() {
351:             return Err(e);
352:         }
353:         let mut out = room.out.into_inner();
354:         match session {
355:             Ok(n) => {
356:                 out.applied = n;
357:                 Ok(out)
358:             }
359:             Err(code) => Err(sync_failure(code)),
360:         }
361:     }
362: 
363:     fn rebuild_admission(&mut self) {
364:         let mut admission = AdmissionPolicy::new();
365:         for author in self.authors.keys() {
366:             admission.admit(self.channel_id, self.epoch, *author);
367:         }
368:         self.admission = admission;
369:     }
370: 
371:     fn persist_meta(&mut self, store: &Store) -> Result<()> {
372:         let mut e = Encoder::new();
373:         e.array(3)
374:             .uint(META_VERSION)
375:             .bytes(&self.genesis.to_wire())
376:             .bytes(&authors_bytes(&self.authors));
377:         let seg = seal_segment(&self.sek, SegmentKind::AnchorMeta, SEG_META, &e.finish())?;
378:         if let Err(err) =
379:             store.put_segment(&self.channel_id, SegmentKind::AnchorMeta, SEG_META, &seg)
380:         {
381:             self.poisoned = true;
382:             return Err(err);
383:         }
384:         Ok(())
385:     }
386: }
387: 
388: fn parse_meta(bytes: &[u8]) -> Result<(Genesis, BTreeMap<Digest32, CompositePublicKey>)> {
389:     let mut d = Decoder::new(bytes);
390:     if d.array()? != 3 {
391:         return Err(Error::MalformedAtRest("anchor meta arity"));
392:     }
393:     if d.uint()? != META_VERSION {
394:         return Err(Error::MalformedAtRest("anchor meta version"));
395:     }
396:     let genesis = Genesis::from_wire(d.bytes()?)?;
397:     let authors = parse_authors(d.bytes()?)?;
398:     d.finish()?;
399:     Ok((genesis, authors))
400: }
401: 
402: /// An anchored copy as a [`crate::log::sync::SessionRoom`]; see `AnchorState::sync_over_room`.
403: struct AnchorSessionRoom<'a> {
404:     shared: &'a tokio::sync::Mutex<AnchorState>,
405:     store: &'a Store,
406:     epoch: u64,
407:     out: std::cell::RefCell<SyncOutcome>,
408:     fatal: std::cell::RefCell<Option<Error>>,
409: }
410: 
411: impl AnchorSessionRoom<'_> {
412:     fn copy(
413:         &self,
414:     ) -> std::result::Result<tokio::sync::MutexGuard<'_, AnchorState>, crate::wire::WireError> {
415:         let st = self.shared.blocking_lock();
416:         if st.poisoned {
417:             return Err(crate::wire::WireError::TransportFailed);
418:         }
419:         if st.epoch != self.epoch {
420:             return Err(crate::wire::WireError::EpochMismatch);
421:         }
422:         Ok(st)
423:     }
424: }
425: 
426: impl crate::log::sync::SessionRoom for AnchorSessionRoom<'_> {
427:     fn frontiers(
428:         &self,
429:     ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
430:         Ok(crate::log::sync::frontiers_of(&self.copy()?.dag))
431:     }
432: 
433:     fn wants(
434:         &self,
435:         remote: &[crate::log::sync::FeedFrontier],
436:     ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
437:         Ok(crate::log::sync::wants_for(&self.copy()?.dag, remote))
438:     }
439: 
440:     fn entries(
441:         &self,
442:         wants: &[crate::log::sync::WantRange],
443:     ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
444:         Ok(crate::log::sync::entries_for_wants(
445:             &self.copy()?.dag,
446:             wants,
447:         ))
448:     }
449: 
450:     fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
451:         let mut guard = self.copy()?;
452:         let st = &mut *guard;
453:         let before = st.heads();
454:         let resolver = ChannelAuthors::new(st.authors.clone());
455:         // Absorb what was stored, then report the failure: see `ChannelSessionRoom::apply`.
456:         let stored = crate::log::sync::apply_staged(&mut st.dag, &resolver, &st.admission, &staged);
457:         match st.absorb_arrived(self.store, &before) {
458:             Ok(got) => {
459:                 self.out.borrow_mut().governance += got.governance;
460:                 stored
461:             }
462:             Err(e) => {
463:                 *self.fatal.borrow_mut() = Some(e);
464:                 Err(crate::wire::WireError::TransportFailed)
465:             }
466:         }
467:     }
468: }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/net.rs | python3 -c 'import sys; lines=sys.stdin.readlines(); spans=[(810,928)]; [print(f"{i+1}: {s}",end="") for a,b in spans for i,s in enumerate(lines) if a<=i+1<=b]'
810:         n
811:     }
812: 
813:     /// Close every connection (node shutdown).
814:     pub fn close_all(&self) {
815:         for (conn, _) in lock(&self.retiring).drain(..) {
816:             conn.close(WireError::AuthenticatorInvalid);
817:         }
818:         for (_, conn) in lock(&self.conns).drain() {
819:             conn.close(WireError::AuthenticatorInvalid);
820:         }
821:     }
822: }
823: 
824: /// Whether a connection is still usable.
825: fn is_live(conn: &VoxConnection) -> bool {
826:     conn.quinn().close_reason().is_none()
827: }
828: 
829: /// What filing one connection decided: which one is the peer's primary, and whether a duplicate was
830: /// retired rather than closed and so still needs reading.
831: pub struct Filed {
832:     /// The connection that is now this peer's primary.
833:     pub kept: Arc<VoxConnection>,
834:     /// A duplicate that was retired rather than closed, and still needs reading for its grace.
835:     pub also_serve: Option<Arc<VoxConnection>>,
836: }
837: 
838: /// Accept the next stream on `conn` and authorize it against `policy`: the peer's
839: /// class must be allowed to open that kind, or the stream is reset with the coded
840: /// rejection and [`Error::StreamRefused`] is returned (see the module docs).
841: pub async fn accept_authorized(
842:     conn: &VoxConnection,
843:     policy: &PeerPolicy,
844: ) -> Result<(StreamKind, SendStream, RecvStream)> {
845:     let (kind, mut send, mut recv) = accept_typed(conn).await?;
846:     let class = policy.classify(&conn.peer_id());
847:     if !PeerPolicy::allows(class, kind) {
848:         refuse_stream(&mut send, &mut recv);
849:         return Err(Error::StreamRefused("peer may not open this stream kind"));
850:     }
851:     Ok((kind, send, recv))
852: }
853: 
854: /// Reset both halves of a stream with the coded rejection — the same code an
855: /// unauthenticated peer gets, so probing stream kinds reveals nothing.
856: pub fn refuse_stream(send: &mut SendStream, recv: &mut RecvStream) {
857:     let code = close_code(WireError::AuthenticatorInvalid);
858:     let _ = send.reset(code);
859:     let _ = recv.stop(code);
860: }
[0m
Two material gaps remain: aborting the async task does not establish that its blocking session worker has stopped, and the ADR’s claim that forks currently fail a session is false—the cited `apply_entry` path already classifies forks and continues. I’m checking how those affect retirement, retry pacing, and the proof mutants.
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/log/dag.rs[90m [offset=185, limit=280][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [offset=2638, limit=90][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/channel.rs[90m [offset=1930, limit=220][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/stream_transport.rs[90m [offset=1, limit=170][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/anchor.rs[90m [offset=200, limit=270][0m
[0m✱ [0mGrep "enum WireError|AuthenticatorInvalid|SyncModeUnsupported|ProtocolViolation"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src · 6 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=5220, limit=100][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs[90m [offset=180, limit=30][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs[90m [offset=758, limit=35][0m
[0m✱ [0mGrep "SILENCE_IS_DEATH|fn tend_liveness|pub fn existing|NetEvent::Connected|NetEvent::Disconnected|SyncRequest"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node · 23 matches[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/wire.rs[90m [offset=255, limit=96][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 diff -- crates/vox-core/src/node/actor.rs crates/vox-core/src/log/sync.rs crates/vox-core/src/node/channel.rs crates/vox-core/src/node/syncstream.rs crates/vox-core/src/node/net.rs crates/vox-core/src/node/anchor.rs crates/vox-core/src/log/dag.rs crates/vox-core/src/transport/stream_transport.rs crates/vox-core/src/transport/quic.rs crates/vox-core/src/wire.rs
(no output)
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/net.rs | python3 -c 'import sys; lines=sys.stdin.readlines(); spans=[(610,770)]; [print(f"{i+1}: {s}",end="") for a,b in spans for i,s in enumerate(lines) if a<=i+1<=b]'
610:     /// protocol: the side that punched files the direct connection as an improvement,
611:     /// and the side that accepted it does too.
612:     ///
613:     /// **The equal-path case must not depend on arrival order**, and it used to: "the held
614:     /// one wins". That agreed across the two ends only while the accept loop handled one
615:     /// handshake at a time, so both ends filed a pair in the same order. With handshakes
616:     /// concurrent (v0.2.8) the acceptor could file a node's second dial first. Measured
617:     /// with both ends logging the same connection's exporter tag: the dialer kept `6352…`
618:     /// and closed `97c8…` while the anchor kept `97c8…` — a dead connection it went on
619:     /// using, with the dialer seeing a live one and never redialling. Relaying to that
620:     /// node then failed ("relay cannot reach the peer") until the grace ran out. This is
621:     /// the "cross-connection interaction in circuit establishment" ADR-017 recorded as
622:     /// unidentified: the serial loop was hiding an order-dependent tie-break.
623:     fn file(&self, conn: VoxConnection) -> Arc<VoxConnection> {
624:         // **Closes the loser, because this caller will not serve it.** Retiring a duplicate is only
625:         // safe where somebody keeps reading it; retiring it here and dropping the handle would
626:         // leave it transport-alive and application-deaf, which is strictly worse than the close it
627:         // replaced. `connect`, the one-shot `accept` and `adopt` all arrive through here and none of
628:         // them serves a second connection, so for them the old behaviour is the correct one.
629:         let filed = self.file_inner(conn, false);
630:         debug_assert!(filed.also_serve.is_none());
631:         filed.kept
632:     }
633: 
634:     /// [`Self::file`], also handing back a duplicate it **retired rather than closed**.
635:     ///
636:     /// The tie-break is unchanged: the held connection still wins when the newcomer is no
637:     /// better. What changes is what happens to the loser. Closing it reset whatever the peer
638:     /// already had in flight on it — the peer dialled that connection and was never told we
639:     /// preferred another, so it opens streams there and reads back a reset it had every reason
640:     /// to expect to work. Measured at the product level: a real SOCKS5 client through a real
641:     /// `vox up` wrote its bytes and then got `ConnectionReset` reading the echo, and the same
642:     /// close showed up on `vox forward` as `malformed identity bundle: quic stream read len`.
643:     ///
644:     /// So the loser is retired on the ordinary grace instead, and returned here so the caller
645:     /// can keep reading it until that grace is up. `retire_expired` closes it after that.
646:     /// Retiring without serving it would be worse than the close it replaces: the connection
647:     /// would be transport-alive and application-deaf, and the peer's request would never be
648:     /// answered at all.
649:     fn file_reporting(&self, conn: VoxConnection) -> Filed {
650:         self.file_inner(conn, true)
651:     }
652: 
653:     /// [`Self::file_reporting`]'s body. `serve_loser` says whether the caller will read a duplicate
654:     /// this keeps alive: with it the loser is retired and handed back, without it the loser is
655:     /// closed. There is no third option — a retired connection nobody reads is the worst of both.
656:     fn file_inner(&self, conn: VoxConnection, serve_loser: bool) -> Filed {
657:         let peer = conn.peer_id();
658:         let mut map = lock(&self.conns);
659:         if let Some(existing) = map.get(&peer) {
660:             // **A held connection that has gone silent is not a rival.** The process behind it
661:             // is gone (see [`SILENCE_IS_DEATH`]), so the newcomer is filed and the dead one
662:             // closed, whatever the tie-break would have said. Everything else is decided by
663:             // path class and then by `tie_key`, which both ends compute identically.
664:             if is_live(existing) && self.is_silent(existing) {
665:                 existing.close(WireError::AuthenticatorInvalid);
666:             } else if is_live(existing) {
667:                 let existing = Arc::clone(existing);
668:                 let (new_class, held_class) = (
669:                     path_class(&self.endpoint, &conn),
670:                     path_class(&self.endpoint, &existing),
671:                 );
672:                 let newcomer_loses = new_class < held_class
673:                     || (new_class == held_class && tie_key(&conn) >= tie_key(&existing));
674:                 if newcomer_loses {
675:                     drop(map);
676:                     if !serve_loser {
677:                         conn.close(WireError::AuthenticatorInvalid);
678:                         return Filed {
679:                             kept: existing,
680:                             also_serve: None,
681:                         };
682:                     }
683:                     let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
684:                     let retired = Arc::new(conn);
685:                     lock(&self.retiring).push((Arc::clone(&retired), retire_at));
686:                     return Filed {
687:                         kept: existing,
688:                         also_serve: Some(retired),
689:                     };
690:                 }
691:                 let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
692:                 lock(&self.retiring).push((existing, retire_at));
693:             }
694:         }
695:         let conn = Arc::new(conn);
696:         // The baseline for its silence: it has just completed a handshake, so it was heard now.
697:         let _ = self.silent_for(&conn);
698:         map.insert(peer, Arc::clone(&conn));
699:         Filed {
700:             kept: conn,
701:             also_serve: None,
702:         }
703:     }
704: 
705:     /// How long a retired connection is kept readable before it is closed.
706:     #[must_use]
707:     pub fn retire_grace_secs(&self) -> u64 {
708:         self.retire_grace_secs
709:     }
710: 
711:     /// Close every retired connection whose grace has elapsed (or that the peer
712:     /// already closed). Returns how many were closed. The node's tick calls this.
713:     pub fn retire_expired(&self) -> usize {
714:         let now = (self.clock)();
715:         let mut retiring = lock(&self.retiring);
716:         let before = retiring.len();
717:         retiring.retain(|(conn, at)| {
718:             // **Still carried** means somebody other than this list holds the connection:
719:             // a tunnel task splicing bytes, a sync in progress. Those hold an `Arc` for as
720:             // long as they run, so the strong count is the liveness signal, and it needs no
721:             // bookkeeping that could disagree with reality.
722:             //
723:             // The grace alone is not enough to close on. It is sized for a request finishing
724:             // — but what rides a connection here is a *tunnel*, and an `ssh` session or a
725:             // file transfer is in flight for hours. Closing on the timer killed live sessions
726:             // mid-stream whenever a better path displaced the one they were on, which reached
727:             // the person as `Connection reset by peer` in the middle of their work.
728:             let still_carried = Arc::strong_count(conn) > 1;
729:             if (now >= *at && !still_carried) || !is_live(conn) {
730:                 conn.close(WireError::AuthenticatorInvalid);
731:                 false
732:             } else {
733:                 true
734:             }
735:         });
736:         before - retiring.len()
737:     }
738: 
739:     /// Retire `conn` as [`Self::file`] would when a better path displaces it. For proofs of
740:     /// the retirement rule, which otherwise needs two real paths to the same peer.
741:     #[doc(hidden)]
742:     pub fn retire_for_test(&self, conn: &Arc<VoxConnection>) {
743:         // Exactly what `file` does: the displaced connection leaves the per-peer map and
744:         // moves to the retiring list. Leaving it in the map would keep a reference of the
745:         // manager's own, which is not what "still carried" means.
746:         lock(&self.conns).retain(|_, c| !Arc::ptr_eq(c, conn));
747:         let at = (self.clock)().saturating_add(self.retire_grace_secs);
748:         lock(&self.retiring).push((Arc::clone(conn), at));
749:     }
750: 
751:     /// How many displaced connections are still within their grace.
752:     #[must_use]
753:     pub fn retiring_count(&self) -> usize {
754:         lock(&self.retiring).len()
755:     }
756: 
757:     /// Drop every connection the peer or the network has closed. Returns how many
758:     /// were reaped.
759:     pub fn prune_closed(&self) -> usize {
760:         let mut map = lock(&self.conns);
761:         let before = map.len();
762:         map.retain(|_, c| is_live(c));
763:         before - map.len()
764:     }
765: 
766:     /// The peers with a live connection, in unspecified order.
767:     #[must_use]
768:     pub fn peers(&self) -> Vec<Digest32> {
769:         let held: Vec<(Digest32, Arc<VoxConnection>)> = lock(&self.conns)
770:             .iter()
[0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs[90m [offset=309, limit=35][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/net.rs[90m [offset=443, limit=129][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=3238, limit=91][0m
[0m→ [0mRead /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/node/actor.rs[90m [offset=546, limit=60][0m
[0m✱ [0mGrep "KEEP_ALIVE"[90m in /opt/vox/.claude/worktrees/ac-fix202/crates/vox-core/src/transport/quic.rs · 2 matches[0m
[0m
[0m$ [0mgit diff -- docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
(no output)
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-kimi-k3.md[90m [offset=2252, limit=32][0m
[0m
[0m$ [0mgh issue view 209 --repo robertelee78/vox --json number,title,body,state
{"body":"<!-- work-accountability:begin -->\n<!-- work-accountability:key robertelee78/vox:RELEASE-HARDENING:V210-34 -->\nStorage profile: `project-fields`\nProject: https://github.com/users/robertelee78/projects/22/views/2\nSource: `docs/release/v0.2.10.md` at `cde30171222a91d9d8b4466adf56680c61889a0d` (`a224d571633c4af19b76882a47a10fab0f062a88`), V210-34\nAcceptance:\n- As ADR-025 decides.\n\nValidation: ADR-025's proof table, each measured on the base first.\nDelivery boundary: Included in the published vox v0.2.10 GitHub release.\n<!-- work-accountability:end -->\n\n**Sync is scheduled like a switch, not a hub (ADR-025).**\n\nThe decider asked for sync to behave like a switch, \"with slots and queues\". Today:\n- two members posting at once refuse each other's sessions (`SessionBusy`) and retry after a random wait: about 2.3 refused streams per simultaneous round with #180, and 0 late posts;\n- a push past the 16-slot cap is *skipped, not queued*, and can wait for the 30 s interval;\n- a truncated serve counts as done;\n- a receiver stores entries it did not ask for.\n\n**ADR-025** (branch `docs/adr-025-sync-switch`, `docs/adr/ADR-025-sync-scheduling-switch-not-hub.md`) is under three-model review. Revision 3 recommends **full duplex**: inbound sessions are never refused for busy, and both directions run at once, with no collision, tie-break or random wait. It also specifies a per-(room, peer) port with tokens, requests captured at admission, receive coverage, a fair queue over slots, and backoff only for real failures.\n\nNot decided: the option (full duplex / designated opener / glare rule) and whether the collision change goes in v0.2.10 are the decider's.\n\nChecklist (ADR-025 Plan):\n- [ ] S0 #180 and #202 integrated\n- [ ] S0b observability in `vox status --json`\n- [ ] S0c the base measured\n- [ ] S1–S4 implementation\n- [ ] S5 proofs P1–P9\n- [ ] S6 independent verifier\n","number":209,"state":"OPEN","title":"V210-34: Sync is scheduled like a switch, not a hub (ADR-025)"}
[0m
Reviewed revision 4 at `5846720`, the requested prior reviews, `58fde36`, and the relevant unchanged files in the `8436100` working tree. No edits, builds, or tests.

Citations below use `ADR:` for the proposed document and `180:` / `202:` for paths relative to `crates/vox-core/src/`.

## BLOCKER

### B1. D1a releases accounting resources without establishing worker termination

“Remove attempt; abort task; drop permit” does **not** establish the claimed bound on unfinished work.

The actual task arrangement is an async supervisor awaiting `spawn_blocking`; the supervisor subsequently sends `SyncDone` (`180:node/actor.rs:5031–5032,5117–5142,5170–5197`). Aborting that supervisor does not interrupt an already-running blocking closure. Aborting the blocking task’s handle also cannot interrupt it once started.

Consequently:

- A worker already inside `apply` keeps its room lock while applying and persisting. Both implementations deliberately perform those operations under one guard (`202:node/channel.rs:2694–2720`; `180:node/anchor.rs:450–465`).
- It may store entries **after** retirement, contrary to D1a’s explanation limited to stores “before the abort” (`ADR:202–203`).
- Dropping the permit immediately allows replacement work while the old worker remains active. The semaphore then bounds registered attempts, not actual session workers.
- Aborting the supervisor can suppress the very `SyncDone` that would report completion. A generation increment alone does not deliver the actor event needed by D6a.

This is **not evidence that abort corrupts a locked batch**: the blocking operation continues rather than being torn apart. The unresolved problem is cancellation, resource accounting, and notification.

The single-owner `OwnedSemaphorePermit` design can prevent **double release** on retirement. It does not specify release on normal completion, panic, or setup failure, nor justify releasing capacity before execution ends.

**Required decision:** specify cooperative cancellation and stream interruption; let an entered apply/persist step finish; check cancellation before subsequent steps; retain an execution/resource record until worker exit; and publish durable progress independently of whether the attempt’s completion remains current. Bind the worker to `Attempt.epoch`, rather than silently recapturing whichever epoch exists when execution begins—the current wrappers capture epoch at worker entry (`180:node/channel.rs:2108–2124`; `180:node/anchor.rs:333–348`).

**“Displaced but carried is not death” is resolved and consistent with `net.rs`.** Displacement puts a live connection into retirement, and outstanding references preserve it beyond grace; actual closure remains distinct (`202:node/net.rs:827–855,874–898`). Do not revert that decision.

## MAJOR

### M1. D3’s predicates are obtainable, but `stored` still has the wrong durability boundary

At both apply sites, the DAG, resolver, admission policy, and room state are available under the lock (`202:node/channel.rs:2694–2710`; `180:node/anchor.rs:450–457`). Thus the classification machinery is implementable.

| Class | Assessment |
|---|---|
| `stored` | `Dag::accept → Ok` means **in-memory acceptance**, not completed persistence. Persistence follows separately and can fail (`202:log/dag.rs:352–360`; `202:node/channel.rs:2035–2054`; `180:node/anchor.rs:297–315`). Define durable `nP`, generation increments, and the successful prefix on failure. |
| `duplicate` | Available directly. No new acceptance semantics needed (`180:log/sync.rs:613–615`). |
| `fork-handled` | Available directly, but the ADR’s “fails today; continue is new” claim is false. `apply_entry` already returns `Ok(ApplyOutcome::Fork)`, and `apply_staged` continues (`180:log/sync.rs:613–619,930–938`). |
| `frozen` | Available through `is_frozen`; splitting the shared rejection is explicitly planned and answers the prior finding (`202:log/dag.rs:216–220,312–324`). |
| `unadmitted` | Missing resolver key is observable before acceptance; ordinary admission rejection is observable after the split (`180:log/sync.rs:608–619`). |
| `poisoning` | Observable during persistence, not merely from `Dag::accept`. Terminal handling until reopen is now specified (`202:node/channel.rs:2050–2052,2100–2106`). |

**Continuing does not inherently bypass acceptance.** Skipping an unadmitted entry and checking each subsequent entry normally permits later admissible entries that the old fail-fast session never reached; it need not permit the rejected entry itself. Admission, signature verification, fork classification, and feed-link checks remain ordered in `Dag::accept` (`202:log/dag.rs:322–360`). Preserve those checks and keep verification/feed errors fatal.

Likewise, continuing after the first fork is already shipped behavior. Subsequent entries from the frozen author are rejected before storage (`202:log/dag.rs:312–315`). The new behavior is classifying those subsequent rejections and continuing past them.

The unresolved design requirement is a **structured partial result even on failure**, with durable IDs/counts and notification. Today the wrapper returns only the error after preserving the applied prefix (`202:node/channel.rs:2701–2720,2117–2127`). “`SyncOutcome` extended” does not yet define that contract.

### M2. D5 needs exhaustive outcomes and precedence across concurrent completions

The empty-serve retry loop is resolved: incomplete coverage with no progress enters timed `NoProgress` backoff (`ADR:258–260,291–298`). The held-stream wedge is also removed by immediate refusal beyond three inbound attempts.

Remaining decisions:

1. **Map all failures.** D5 omits authentication failures, invalid feed links, malformed protocol frames, unsupported modes, and local non-persist failures. Those exist in the supplied paths (`180:log/sync.rs:548–574,899–910`; `202:node/channel.rs:2048–2074`). State their retry/request policy explicitly.
2. **Define precedence.** A session can fill all requested positions and subsequently fail; a separate inbound completion can make progress while an outbound failure enters backoff. Specify whether these outcomes consume requests, credit generations, reset failure counts, replace deadlines, or invalidate timers. The rows are currently overlapping rather than an ordered transition function.
3. **Clarify `Policy` classification.** “Not a member” is not a distinct received wire reason: the membership refusal uses the uninformative reset, whereas an authorized epoch refusal can use `EpochMismatch` (`202:node/actor.rs:5265–5283`). The sender cannot infer every policy cause from the wire code alone.
4. **Define `ProtocolViolation` as local or wire-visible.** It is absent from the current wire enum (`202:wire.rs:257–309`). Either choice is allowed; it must be made.

D6a resolves the previous omission of **which events schedule work**. B1 remains responsible for making worker-side changes actually reach those events.

D6 also now accurately discloses aggregate slot starvation. Four stalled peers can occupy all slots; round-robin does not preempt them. No stronger latency guarantee follows from this ADR. Moreover, existing permits cover membership preparation as well as reconciliation (`180:node/actor.rs:5023–5039,5073–5089,5117–5142`), so a bound stated only in terms of sync-frame budgets is not a complete attempt deadline.

### M3. S0b and several proofs still lack causal discrimination

Sequence numbers and overflow detection resolve **silent journal loss**. They do not resolve missing causal fields.

S0b still needs:

- request-raise events with cause, generation and time, including periodic/manual/connect triggers;
- actual room generation at admission;
- backoff deadline and timer identity;
- separate worker-exit, retirement, and actor-completion times;
- an unambiguous cross-end session correlation key;
- event timestamps/generations sufficient to compare a post with `t_have`;
- complete transfer evidence, or explicit “identity list truncated” handling.

A list of **up to 32 served IDs cannot prove an ID was not served** when the count exceeds 32 (`ADR:362`). Journal-overflow detection does not detect that omission.

#### P1–P10 assessment

| Proof | Revision-4 assessment |
|---|---|
| **P1** | Direction-aware justification is fixed. Still define admission-time room generation and cross-end correlation. Observe the inbound check while the competing outbound is active; unspecified session “overlap” is weaker than that exact precondition. |
| **P2** | Separate base skip/change queue observations are fixed. A queued event does not establish that removing the queue loses delivery: D1 retains need and D6a schedules again on slot release. Specify exactly what `try_acquire-or-skip` mutates and exclude later posts, reverse sessions, and periodic rescue. |
| **P3** | The **140 MiB** arithmetic fixes the byte-leg error. The contribution assertion—one matching ID per partial session—does not exclude other sessions rescuing the double mutant. Still lacks bilateral backlog and time-budget truncation coverage. |
| **P4** | **The mutant can remain green.** Removing the special `unadmitted` request still leaves an unfilled position, so D3’s general incomplete-coverage rows raise a request. “No other outbound … except the one it raised” neither identifies the request cause nor excludes an already-pending request. |
| **P5** | Entry IDs help, but a truncated served-ID list cannot prove absence. Require the specific post’s durable generation/time and complete transfer membership; exclude later posts and other outstanding sessions rescuing the completion-generation mutant. |
| **P6** | Inherits P1’s remaining observation requirements. |
| **P7** | **Does not establish either required race.** With ordinary network waiting, the frame timeout is 20 s, while silence death is approximately 30 s (`202:transport/stream_transport.rs:29,104–115`; `202:node/net.rs:319–336`). The stopped session may finish before retirement. Also, aborting its supervisor can prevent its later `SyncDone` altogether (`180:node/actor.rs:5117–5142`). Require observed worker activity at retirement and an old completion arriving after replacement; merely renaming the mutant to “whole stale guard” is insufficient. |
| **P8** | **Still permits a green expiry mutant.** Direction checking excludes Bob’s pull, but D5 explicitly clears Alice’s backoff on a new connection and D2 raises Alice’s request. Alice can therefore open without `BackoffExpired`. An earlier expiry while Bob was down does not prove recovery was expiry-driven. |
| **P9** | A legitimate binary-level fault-injection proof, provided the mutant changes only sender behavior and the receiver is the production build. Observe the receiver’s actual WANT and use an otherwise valid/admissible extra entry. Sender “served” identity alone does not prove it was outside WANT. |
| **P10** | Also legitimate binary-level fault injection. The proposed backoff/count assertion can discriminate the no-progress mutant. Establish a nonempty advertised/requested tail and an otherwise quiet target port; distinguish the receiver’s outbound attempts from incoming attempts. |

P9/P10 count as **real-binary defensive proofs**, not evidence that honest peers normally generate those failures. Run the normal receiver and the receiver mutant against the **same faulty sender and scenario**.

The blanket S0c requirement also remains impossible literally: it asks the base to satisfy revised preconditions involving partial classes, retirement, and `Unreachable` backoff-expiry events that the proposed implementation introduces. S0b says the base reports only existing fields (`ADR:373–374,423`). Give each proof a separate base-observable predicate or mark it change-only.

### M4. #212 is owned, but its required binary proof is not an acceptance dependency

The inherited deadlock is now explicitly owned by #212, with concurrent serve/drain and an S5 dependency. That resolves the previously missing fix direction and release ownership.

However, the earlier astra/glm requirement included a **bilateral large-backlog binary proof**. P3 remains unilateral, and S5 requires only “#212,” without specifying that its acceptance includes bilateral backlog and concurrent sessions sharing connection credit (`ADR:403,428`).

This is a proof dependency gap, not a re-raised claim that full duplex introduces the deadlock. The existing serve-before-drain ordering and shared flow-control limits are as described (`180:log/sync.rs:886–914`; `202:transport/quic.rs:191–203`).

## MINOR

### The headline still promises something D4 explicitly permits

The options table says correct peers have **no** busy refusals, and the recommendation says neither end refuses for busy (`ADR:146,151–152`). D4 correctly admits that a correct peer can exceed the three-inbound turnover allowance and receive `SessionBusy` (`ADR:269–276`).

The fixed cap resolves unbounded holding. It does **not** prove universally refusal-free turnover. Qualify the headline to match the decision.

### Remaining implementation decisions

Beyond B1 and M1–M3, settle:

- how normal completion, cancellation and panic remove attempts and release both global and per-peer accounting;
- how connection-death events identify the exact connection, including carried non-primary connections;
- how partial durable progress survives a stale/cancelled completion;
- how queued `vox room sync` commands retain a reply until something actually starts;
- how consent waiters migrate across retirement/replacement, beyond naming `(room,target,token)`.

The proposed status and consent wording no longer describe planned work as completed. The newly introduced false baseline statement is the fork row identified in M1.

## NIT

Define “opened,” “started,” “ended,” “completed,” and “unfinished” consistently, and give endpoint-local conservation equations that include refusal, retirement, cancellation and still-running work. P7 cannot use retirement time interchangeably with worker-exit time.

## Round-3 finding disposition

**A/G/K** identify astra/glm/kimi findings in their respective `review3-*.md` files. “Resolved” means resolved **in the design**, not implemented.

| Round-3 finding | Disposition | Reason |
|---|---|---|
| A-B1, G-B1: bilateral deadlock and proof | **PARTIAL** | Concurrent fix and release dependency specified; bilateral binary acceptance still missing, M4. |
| K-B2: deadlock omitted/unowned | **RESOLVED** | Explicit #212 ownership and prerequisite answer this finding. |
| A-B2: held bounds, no-progress retries, coverage allocation | **PARTIAL** | Holding removed; empty-serve pacing and intervals fixed. Actual execution-resource bounds remain open under B1. |
| G-M1, K-M1: unsafe held queue | **RESOLVED** | No held queue; immediate bounded admission/refusal. |
| K-B3 and G-M1’s no-progress subfinding | **RESOLVED** | All incomplete/no-progress receives now back off. |
| A-M1, G-B2, K-B1: stale-attempt lifecycle | **PARTIAL** | Logical retirement and displaced-connection policy specified; physical termination and resource lifetime are not. |
| A-M2, G-M2, K-M2: classes/policy/durability | **PARTIAL** | Frozen split, revocation correction, poison/reopen policy and interval representation fixed. Durable result boundary remains unspecified; fork baseline is wrong. |
| A-M3, G-M3, K-B4: proof discrimination | **PARTIAL** | Direction fixes, byte size and #202 setup improved; P4/P7/P8 and other isolation gaps remain, M3. |
| A-M4, G-M4, K-B4’s schema findings | **PARTIAL** | Journals now expose many missing fields and detect loss; causal and complete transfer evidence remain missing. |
| K-M3: scheduling points | **RESOLVED** | D6a enumerates the required events. Worker notification is the remaining lifecycle issue. |
| A-m1, G-m1, K-m1: regressing credit | **RESOLVED** | Epoch-scoped `max` advancement specified. |
| A-m2, G-m2: aggregate starvation | **PARTIAL** | Limitation corrected; requested sustained mixed-peer service proof still absent. |
| G-m3: epoch/reconnect backoff | **RESOLVED** | Explicit clearing rules. |
| K-m2: failure reset/permanent refuser pacing | **RESOLVED** | Progress reset and 30 s `Policy` pacing specified; exhaustive classification remains M2. |
| A-m3, G-m4, K planned-as-done finding | **RESOLVED** | Consent keying explicitly labelled planned. |
| A-m3, G-m5, K-m3: understated attempt envelope | **PARTIAL** | Logical envelope corrected to 1+3; actual unfinished workers can exceed it under B1. |
| K-m4 and A/G #202-proof subfinding | **RESOLVED** | Setup now explicitly establishes `owed_a_reason`. |
| K-m5: fingerprint orientations | **RESOLVED** | Removed. |
| K-m6: undetectable journal loss | **RESOLVED** | Sequencing, overflow detection and CANNOT MEASURE specified. |
| A/G counter/timestamp nits | **NOT RESOLVED** | Lifecycle boundaries and conservation equations still unspecified. |
| G generation-home/restart nit | **RESOLVED** | Room-state home and joint restart reset specified. |
| G contradictory held/admitted wording nit | **RESOLVED** | Holding removed; the different refusal-free headline contradiction remains above. |
| K citation-prefix/range nits; G/K revision-table nits; K “no new state” nit | **RESOLVED** | Corrected or removed. |

*Accountability: managed work is `robertelee78/vox:RELEASE-HARDENING:V210-34` (#209). Tracker reconciliation was deferred under the read-only constraint; Project phase/health and a verified reconciliation receipt were not established.*

## VERDICT

**BLOCK**

The three changes I would most insist on:

1. **Replace abort-equals-retirement with a real worker lifecycle:** cooperative cancellation, completion-independent durable-progress notification, and capacity retained until execution ends.
2. **Finish the receive/completion contract:** durable partial outcomes, exhaustive failure classification, and deterministic precedence across concurrent completions.
3. **Make the binary proofs causally discriminating:** fix P4/P7/P8, complete S0b’s evidence schema, separate base/change preconditions, and require #212’s bilateral shared-connection backlog proof.
