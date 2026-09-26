[0m
> build · glm-5.3
[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m
[0m$ [0mls /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/ && git -C /opt/vox/.claude/worktrees/ac-adr025 log --oneline -5 && git -C /opt/vox/.claude/worktrees/ac-fix202 log --oneline -3
review-astra.md
review-glm-5.3.md
review-kimi-k3.md
review2-astra.md
review2-glm-5.3.md
review2-kimi-k3.md
review3-astra.md
review3-glm-5.3.md
review3-kimi-k3.md
review4-astra.md
review4-glm-5.3.md
review4-kimi-k3.md
5846720 docs(adr): ADR-025 revision 4 — retirement, receive classes, backoff kinds, schedule points, journals; round-3 reviews (all BLOCK)
141dc11 docs(adr): ADR-025 revision 3 — full duplex (no busy refusals), request lifecycle, receive coverage, observable proofs; round-2 astra review
16951fe docs(adr): ADR-025 revision 2 — designated opener, observable completion, rebuilt proofs; round-1 reviews (astra BLOCK, glm REVISE, kimi REVISE)
8c4e347 docs(adr): ADR-025 draft — sync is scheduled like a switch, not a hub (for review)
1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
8436100 fix(sync): a sync that did not complete says why — a collision is not a governance error (#202, V210-29)
1aab21a merge: #201 — an aborted gate leaves nothing running: the watchdog kills the test's descendants first
2244a2e merge: #198 — a member is named past the reach of key grinding, or by the name you gave it; the TUI proof runs in CI
[0m
[0m$ [0mwc -l /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-*.md && grep -n "^## " /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md
3112 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-astra.md
    2954 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-glm-5.3.md
    2332 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-kimi-k3.md
    8398 total
2948:## BLOCKER
2982:## MAJOR
3051:## MINOR
3082:## NIT
3104:## VERDICT
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-astra.md[90m [offset=2948][0m
[0m
[0m$ [0mgrep -n "^## \|^### " /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-glm-5.3.md | tail -40
2859:## Round-2 disposition (review2-astra.md)
2873:## BLOCKER
2875:### B1. Full duplex makes a bilateral flow-control livelock reachable and permanent
2885:### B2. "A stale SyncDone changes nothing" wedges the port: result-ignoring and resource-release are conflated
2893:## MAJOR
2895:### M1. Holding is not safe against a malicious member, and manufactures failures for correct ones
2903:### M2. D3's entry classes and coverage are not computable from the code as specified
2913:### M3. The proof table: preconditions unobservable, two mutants provably green
2923:### M4. S0b cannot supply what the proofs need (beyond M3's specifics)
2927:## MINOR
2935:## NIT
2942:## What I could not break (option C, question 2, directly)
2946:## VERDICT
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-glm-5.3.md[90m [offset=2859][0m
[0m
[0m$ [0mgrep -n "^## \|^### " /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review3-kimi-k3.md | tail -40
2264:## Round-2 finding dispositions
2284:## BLOCKER
2298:## MAJOR
2306:## MINOR
2315:## NIT
2324:## VERDICT
[0m
[0m→ [0mRead docs/adr/ADR-025-reviews/review3-kimi-k3.md[90m [offset=2264][0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '5010,5330p'
) {
            (Some(shared), _) => SessionTarget::Channel(shared),
            (None, Some(state)) => SessionTarget::Anchored(state),
            (None, None) => return false,
        };
        // An anchor's authors come from its own board, which is local: cheap, and it has to happen
        // before the session so the anchor can verify what arrives.
        if matches!(target, SessionTarget::Anchored(_)) {
            self.refresh_anchored_authors(channel_id).await;
        }
        if self.in_session_with(channel_id, &peer) {
            return false; // a session with this peer already has this room
        }
        let Ok(slot) = Arc::clone(&self.sync_slots).try_acquire_owned() else {
            return false; // past the cap: skipped, not queued. The schedule comes round again.
        };
        self.syncing.insert((*channel_id, peer));
        let admit_store = self.profile.as_ref().map(Profile::store_handle);
        let cid = *channel_id;
        let now = self.now();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let _slot = slot;
            // 1. Learn who else has joined, or the first entry from a newer member kills the session
            //    (ADR-008). A round trip, so it belongs here and not on the actor.
            let epoch = match &target {
                SessionTarget::Channel(shared) => {
                    let known = shared.lock().await.epoch();
                    if let Some(pstore) = admit_store {
                        if let Ok(set) = net.fetch_channel(&conn, &cid, known).await {
                            {
                                let mut ch = shared.lock().await;
                                let _ = admit_board_records(
                                    &mut ch,
                                    &pstore,
                                    &set.bundles,
                                    ChannelState::MAX_ADMISSIONS_PER_SWEEP,
                                    now,
                                )
                                .await;
                            }
                            // What the peer's board holds is filed on this node's own, so its board
                            // carries the whole membership it knows. Bundles go first: they carry
                            // the key an address record is verified with (M15.2a). Mirroring to the
                            // anchors follows on the actor when `SyncDone` lands, because that needs
                            // channel state.
                            for wire in set
                                .bundles
                                .iter()
                                .map(MemberBundleRecord::to_wire)
                                .chain(set.members.iter().map(RendezvousRecord::to_wire))
                            {
                                let _ = net.publish_local(&wire);
                            }
                            // **And the other way: what this node's board holds that the peer's
                            // lacks.** A member who joined through this node is on this node's
                            // board and no other, and the peer learned of it only when *it* next
                            // read this board, on its own periodic sync: 24–28 s for a third
                            // member to see a new one, measured. Offered here, a push that follows
                            // a join carries the newcomer to every connected member at once.
                            // Best-effort: a refusal (a record the peer's board already holds
                            // newer) costs nothing, and the peer's own sync still reads this board.
                            let missing = net.board_records_missing_from(&cid, known, &set);
                            if !missing.is_empty() {
                                if let Ok(mut client) =
                                    crate::nat::service::RendezvousClient::open(&conn).await
                                {
                                    for wire in &missing {
                                        if let Err(e) = client.put(wire).await {
                                            if !matches!(e, Error::RendezvousRejected(_)) {
                                                break;
                                            }
                                        }
                                    }
                                    client.finish();
                                }
                            }
                        }
                    }
                    shared.lock().await.epoch()
                }
                SessionTarget::Anchored(state) => state.lock().await.epoch(),
            };
            // 2. Open the stream. Also a round trip.
            //
            // **A stream that will not open still reports.** This returned without a word, and the
            // only thing that clears `syncing` is `SyncDone` — so one failed open left the room
            // marked mid-session for good: every later sync of it skipped, every inbound one
            // refused, and nothing said so. Every exit from this task now sends `SyncDone`.
            let handle = tokio::runtime::Handle::current();
            let transport =
                match crate::node::syncstream::open_sync(&conn, handle, &cid, epoch).await {
                    Ok(t) => t,
                    Err(e) => {
                        let _ = tx
                            .send(NetEvent::SyncDone {
                                channel_id: cid,
                                peer,
                                outcome: Err(e),
                            })
                            .await;
                        return;
                    }
                };
            // 3. Run the session. It takes the room's lock inside each protocol step and never across
            //    a send or a receive (`sync_over_room`), so a peer slow to answer no longer holds the
            //    room — or, through `publish()` and every other lock on it, the actor.
            let joined = tokio::task::spawn_blocking(move || {
                let mut t = transport;
                match target {
                    SessionTarget::Channel(shared) => {
                        crate::node::channel::ChannelState::sync_over_room(
                            &shared, &store, &mut t, now,
                        )
                    }
                    SessionTarget::Anchored(state) => {
                        crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
                    }
                }
            })
            .await;
            // A session that panicked still hands the room back: `Err` from the join is the panic.
            let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
                "sync session panicked",
            )));
            let _ = tx
                .send(NetEvent::SyncDone {
                    channel_id: cid,
                    peer,
                    outcome,
                })
                .await;
        });
        true
    }

    /// Take the channel out of the actor's map and run a session on its own task,
    /// returning it through [`NetEvent::SyncDone`].
    fn start_session(
        &mut self,
        channel_id: Digest32,
        peer: Digest32,
        transport: crate::transport::quic::QuicStreamTransport,
    ) {
        let Some(store) = self.log_store() else {
            return;
        };
        let target = match (
            self.channels.get(&channel_id).map(Arc::clone),
            self.anchored.get(&channel_id).map(Arc::clone),
        ) {
            (Some(shared), _) => SessionTarget::Channel(shared),
            (None, Some(state)) => SessionTarget::Anchored(state),
            (None, None) => return,
        };
        // Marked here, past both early returns above, so a session that never starts never
        // leaves the room marked. Its caller used to mark it first.
        self.syncing.insert((channel_id, peer));
        let now = self.now();
        let tx = self.net_tx.clone();
        tokio::spawn(async move {
            let joined = tokio::task::spawn_blocking(move || {
                // The room is locked inside each protocol step only, never across the
                // network (`sync_over_room`).
                let mut t = transport;
                match target {
                    SessionTarget::Channel(shared) => {
                        crate::node::channel::ChannelState::sync_over_room(
                            &shared, &store, &mut t, now,
                        )
                    }
                    SessionTarget::Anchored(state) => {
                        crate::node::anchor::AnchorState::sync_over_room(&state, &store, &mut t)
                    }
                }
            })
            .await;
            let outcome = joined.unwrap_or(Err(crate::error::Error::MalformedGovernance(
                "sync session panicked",
            )));
            let _ = tx
                .send(NetEvent::SyncDone {
                    channel_id,
                    peer,
                    outcome,
                })
                .await;
        });
    }

    /// Reconcile a channel with every member this node can reach, now (the `Sync`
    /// command; the schedule does this automatically — ADR-016 §"Sync scheduling").
    async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
        if self.net.is_none() {
            return Outcome::Failed(Fault::NotNetworked);
        }
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        let peers: Vec<Digest32> = {
            let channel = shared.lock().await;
            let me = channel.me();
            channel.members().into_iter().filter(|m| *m != me).collect()
        };
        let mut synced = 0usize;
        for peer in peers {
            if self.sync_one(channel_id, peer).await {
                synced += 1;
            }
        }
        if synced == 0 {
            return Outcome::Failed(Fault::Unreachable);
        }
        Outcome::Done
    }

    /// Reconcile one channel's log with a peer over an inbound `sync` stream (ADR-008
    /// frontier mode), on its own task for the reason [`NetEvent::SyncDone`] gives.
    /// Serve one sync session for a request that has **already been read**.
    ///
    /// The preamble is read on the per-connection stream task (`node::network`), not here: the
    /// actor is the only writer of channel state and anything it awaits inline stops the whole
    /// node, so it must never wait on an untrusted peer to speak. What it does here is local
    /// and ordered, which is what the single-task design is for.
    /// **Only a member of *this* room is served its log** (PRD-001 R5). The stream-kind gate
    /// in `node::net` asks whether the peer may open a sync stream *at all*, which any member
    /// of any room this node holds may — and the preamble then names whichever channel the
    /// peer likes. Nothing here checked the two against each other, so a member of room A who
    /// had ever seen room B's `.vox` name was handed B's whole log (PRD-001 D5). See
    /// [`Self::may_sync`] for who counts.
    async fn run_sync_session(
        &mut self,
        peer: Digest32,
        channel_id: Digest32,
        epoch: u64,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) {
        use crate::node::syncstream::accept_sync;
        // Answering while our own session holds this room is the other half of the deadlock.
        //
        // **Refused explicitly, not by dropping the streams.** Letting them drop leaves the peer
        // reading for a frame that will never come until `SYNC_FRAME_TIMEOUT` expires — the
        // silent refusal that reads as a hang, which is the shape of defect this whole change
        // exists to remove. A reset reaches it on the next read, and its schedule brings it
        // back in a second.
        //
        // **Refused before the lock, not after.** A session holds this room's mutex for its whole
        // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
        // behind the very session this check exists to detect.
        if self.in_session_with(&channel_id, &peer) {
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        // Only a channel we hold open at that epoch — or keep as an anchor — can be
        // reconciled. An anchor whose board just received the genesis adopts it here
        // rather than making the member wait for the next tick.
        if !self.channels.contains_key(&channel_id) {
            self.adopt_anchored(&channel_id).await;
            self.refresh_anchored_authors(&channel_id).await;
        }
        let matches_epoch = match (
            self.channels.get(&channel_id),
            self.anchored.get(&channel_id),
        ) {
            (Some(shared), _) => shared.lock().await.epoch() == epoch,
            (None, Some(state)) => state.lock().await.epoch() == epoch,
            (None, None) => false,
        };

        // **Refused, not dropped.** A node asked for a room it does not hold — an anchor that keeps
        // no log for it, most often — or at an epoch it is not at, returned here and let the streams
        // fall, and the initiator learned only `sync failed: transport` — indistinguishable from a
        // connection that died. Every push to an anchor that keeps no log for the room read as a
        // network fault. A coded reset says what happened. (It does not recover time: a dropped
        // stream already ended the initiator's session within milliseconds, measured; the long
        // losses once blamed on this were the room-wide starvation v0.2.8 fixed.)
        if !matches_epoch {
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        if !self.may_sync(&channel_id, &peer, epoch).await {
            // Refused explicitly, with the same coded reset as a stream kind the peer may not
            // open, rather than left to read for a frame that never comes.
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        let transport = accept_sync(tokio::runtime::Handle::current(), send, recv);
        self.start_session(channel_id, peer, transport);
    }

    /// Whether `peer` may reconcile `channel_id`'s log with this node.
    ///
    /// - An **admitted author** of that room. If it is not one yet, this node's own board is
    ///   consulted first — local, so cheap — because a member that joined through somebody
    ///   else is on the board before it is in this node's author table, and refusing it for
    ///   that would be the "precondition behind its own check" defect `run_due_syncs` documents.
    ///   Admission there takes the same M17.6 evidence as everywhere else.
    /// - An **anchor of that room** — in the room's own anchor set, which holds this node's
    ///   configured anchors and those the room's link named. It keeps the room's ciphertext by
    ///   design (ADR-016 M15.2b) for members who are away. An anchor named only by *another*
    ///   room's link is not an anchor of this one.
    ///
    /// For a room this node only anchors, the peer must be an author the board knows.
    async fn may_sync(&mut self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
        if let Some(shared) = self.channels.get(channel_id).map(Arc::clone) {
            {
                let channel = shared.lock().await;
                if channel.is_author(peer)
                    || channel.anchors().nodes().iter().any(|a| a.id == *peer)
                {
                    return true;
                }
            }
            let (Some(net), Some(store)) = (
                self.net.as_ref().map(Arc::clone),
                self.profile.as_ref().map(Profile::store_handle),
            ) else {
[0m
Now let me examine the code. First, the key files at 58fde36:
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | sed -n '60,100p; 440,540p'
/// The whole drain phase's budget, however many frames arrive.
///
/// Chosen absolutely, not derived from the per-frame timeout. A room's lock is held for the entire
/// session, so this is how long one member may stop every other operation on that room — a bound on
/// what the rest of the node will tolerate, which is a different question from how patient any one
/// frame should be. The two must not be tied: a per-frame bound tightened to abandon a dead peer
/// sooner would otherwise also abandon an honest sync that is merely slow.
///
/// The references bound the total as well as the gap, for this reason: go-libp2p's relay sets a
/// per-stream timeout *and* an absolute `Duration` cap on the whole relayed connection, and Tor
/// reclaims a circuit on total idle. A per-frame bound alone defends only against a peer that
/// stops, never against one that drips.
const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// The most entries one session serves to a peer's `WANT`.
///
/// The session holds the room's lock throughout, so what one peer may ask for is
/// what every other operation on the room waits behind. This bounds one session,
/// not a catch-up: the requester applies what it got and, because it applied
/// something, syncs again at once for the rest (see the module docs). A thousand
/// entries verify and file in well under the requester's `DRAIN_BUDGET`.
pub const MAX_SERVE_ENTRIES: usize = 1024;

/// The most entry bytes one session serves, for the same reason as
/// [`MAX_SERVE_ENTRIES`]: a single entry may be up to [`MAX_PAYLOAD_LEN`], so a
/// count alone would still let one `WANT` pull gigabytes into memory. At least one
/// entry is always served, so an entry larger than this still gets through.
pub const MAX_SERVE_BYTES: usize = 64 * 1024 * 1024;

/// The serve phase's wall-clock budget. Each frame is bounded by the transport,
/// but a peer that *reads* one frame every nineteen seconds would otherwise keep
/// the room's lock for as long as there are entries to send — the drip that
/// `DRAIN_BUDGET` closes on the other direction. Stopping here is not a failure:
/// what was served is kept, and the requester comes back for the rest.
pub const SERVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// Hard upper bound on an `ENTRY` frame's carried wire bytes, checked **before**
/// `to_vec` so a hostile frame cannot force a large allocation ahead of
/// [`Entry::from_wire`]'s own per-field caps (ADR-008 anti-abuse). It is the sum
/// of the entry's structural maxima — the payload, the authenticator, and a
/// - for every remote feed whose `max_seq` **exceeds** what we hold, request
///   `(local_max + 1 ..= remote_max)` (the ordinary tail-extension case);
/// - **and** — the equal-length fork case — when the remote's `max_seq` **equals**
///   our `max_seq` but its `head_hash` **differs** from ours, request the head
///   `(max_seq ..= max_seq)`. Two partitions each holding `(author, seq = N)` with
///   different valid hashes would otherwise never exchange the conflicting entry
///   and no fork proof would form (ADR-008 §"Fork / equivocation handling"). The
///   pulled conflicting entry is fed into DAG fork handling, which freezes the
///   author on an attributable proof and raises an alarm on a deniable one.
#[must_use]
pub fn wants_for(dag: &Dag, remote: &[FeedFrontier]) -> Vec<WantRange> {
    let mut wants = Vec::new();
    for rf in remote {
        let local = dag.feed(&rf.author_id);
        let local_max = local.map_or(0, |f| f.max_seq());
        if rf.max_seq > local_max {
            wants.push(WantRange {
                author_id: rf.author_id,
                from_seq: local_max + 1,
                to_seq: rf.max_seq,
            });
        } else if rf.max_seq == local_max && local_max > 0 {
            // Equal head seq: compare the gossiped head hashes. A mismatch is a
            // divergence (equal-length fork) — pull the remote head entry so the
            // conflict reaches DAG fork handling.
            let local_head = local.map_or(crate::log::entry::ZERO_HASH, |f| f.head_hash());
            if local_head != rf.head_hash {
                wants.push(WantRange {
                    author_id: rf.author_id,
                    from_seq: local_max,
                    to_seq: local_max,
                });
            }
        }
    }
    wants
}

/// Collect the `ENTRY` wire frames satisfying a peer's `WANT` ranges from the
/// local [`Dag`], in per-author seq order, up to [`MAX_SERVE_ENTRIES`] /
/// [`MAX_SERVE_BYTES`].
///
/// **The work is bounded by what this node holds, never by the ranges' numbers.**
/// This used to loop `from_seq..=to_seq` doing one lookup per number, collecting
/// into memory with the room's lock held, so a single `WANT (author, 1,
/// u64::MAX)` — any member may send one — pinned a core on a loop that would not
/// finish in the life of the machine, and nothing else could touch that room
/// again (PRD-001 D2). Now each author's ranges are merged, so duplicates and
/// overlaps cost nothing and serve nothing twice, and each merged range walks
/// only the entries the feed actually has. Entries not held are simply omitted.
#[must_use]
pub fn entries_for_wants(dag: &Dag, wants: &[WantRange]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for (author, ranges) in merged_wants(wants) {
        let Some(feed) = dag.feed(&author) else {
            continue;
        };
        for (from, to) in ranges {
            for entry in feed.range(from, to) {
                let wire = entry.to_wire();
                if !out.is_empty()
                    && (out.len() >= MAX_SERVE_ENTRIES
                        || bytes.saturating_add(wire.len()) > MAX_SERVE_BYTES)
                {
                    return out;
                }
                bytes = bytes.saturating_add(wire.len());
                out.push(wire);
            }
        }
    }
    out
}

/// A `WANT`'s ranges grouped by author (in author order) with each author's
/// ranges sorted and merged, so the ranges are disjoint and ascending. Inverted
/// ranges are dropped. The cost is `O(n log n)` in the number of ranges, which
/// the frame size already bounds.
fn merged_wants(wants: &[WantRange]) -> std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> {
    let mut by_author: std::collections::BTreeMap<Digest32, Vec<(u64, u64)>> =
        std::collections::BTreeMap::new();
    for w in wants.iter().filter(|w| w.from_seq <= w.to_seq) {
        by_author
            .entry(w.author_id)
            .or_default()
            .push((w.from_seq, w.to_seq));
    }
    for ranges in by_author.values_mut() {
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for &(from, to) in ranges.iter() {
            match merged.last_mut() {
                Some(last) if from <= last.1.saturating_add(1) => last.1 = last.1.max(to),
                _ => merged.push((from, to)),
            }
        }
        *ranges = merged;
    }
    by_author
}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | sed -n '550,630p; 740,780p; 860,940p'
Error::UnknownStructTag(_) => WireError::UnknownStructTag,
        Error::UnsupportedVersion { .. } => WireError::ProtocolVersionUnsupported,
        Error::UnknownAlgoId(_) | Error::UnexpectedAlgo { .. } => WireError::UnknownAlgoId,
        Error::SuiteBelowFloor { .. } => WireError::SuiteBelowFloor,
        // Signature/authenticator failures, malformed structures, the deniable
        // boundary, and oversize/CBOR malformation are all "this authenticator/
        // structure is not acceptable" → AuthenticatorInvalid. (Size limits are a
        // structural rejection; there is no dedicated size code in the M0 table.)
        _ => WireError::AuthenticatorInvalid,
    }
}

/// Map a DAG [`Rejected`] to the M0 wire application-error code.
#[must_use]
pub fn wire_error_for_rejected(rej: &Rejected) -> WireError {
    match rej {
        Rejected::NotAdmitted => WireError::EpochMismatch,
        Rejected::Verification(e) => wire_error_for(e),
        Rejected::Feed(_) => WireError::AuthenticatorInvalid,
        Rejected::Fork(_) => WireError::AuthenticatorInvalid,
        Rejected::GovernanceNotAttributable => WireError::AuthenticatorInvalid,
        // A duplicate is not a hard fail; callers handle it before mapping. If it
        // ever reaches here, treat as a benign authenticator-class rejection.
        Rejected::Duplicate => WireError::AuthenticatorInvalid,
    }
}

/// The outcome of applying a received `ENTRY` frame.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplyOutcome {
    /// The entry was newly stored.
    Stored,
    /// The entry was a duplicate (idempotent — already held).
    Duplicate,
    /// The entry conflicted with a stored one at the same `(author, seq)`: a fork.
    /// This is a *local security event*, NOT a wire-protocol violation — it is
    /// recorded/surfaced (an attributable fork freezes the author; a deniable one
    /// raises an alarm) and sync **continues**. The stream is not closed for a
    /// fork (ADR-008 §"Fork / equivocation handling").
    Fork,
}

/// Apply a received `ENTRY` wire frame to the local [`Dag`] under the full
/// acceptance predicate.
///
/// Returns [`ApplyOutcome`] for the non-fatal cases (stored / duplicate / fork)
/// and `Err(WireError)` only for a *hard wire fail* that must close the stream —
/// mapped to the exact M0 code via [`wire_error_for`] / [`wire_error_for_rejected`]
/// (unknown tag, unsupported version, unknown algo, authenticator, …). A
/// **fork is not a wire fail**: it is surfaced and sync continues, so two
/// partitions can exchange conflicting heads and form the proof.
pub fn apply_entry<R: AuthorResolver>(
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    entry_wire: &[u8],
) -> std::result::Result<ApplyOutcome, WireError> {
    let entry = Entry::from_wire(entry_wire).map_err(|e| wire_error_for(&e))?;
    let key = resolver
        .key_for(&entry.skeleton.author_id)
        .ok_or(WireError::AuthenticatorInvalid)?;
    let kind = resolver.kind_for(&entry);
    match dag.accept(entry, kind, &key, admission) {
        Ok(_) => Ok(ApplyOutcome::Stored),
        Err(Rejected::Duplicate) => Ok(ApplyOutcome::Duplicate),
        // A fork is recorded by `accept` (freeze / proof) and surfaced; it does
        // not close the stream.
        Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork),
        Err(other) => Err(wire_error_for_rejected(&other)),
    }
}

/// Drive a complete **frontier-mode** session between two peers, each over its
/// own [`Transport`] endpoint, to convergence — exercising the real frame path
/// (`HELLO`/`HAVE`/`WANT`/`ENTRY`) over the abstract transport. `a` is the
/// initiator. `pump` moves frames between the two endpoints (for the in-memory
/// duplex it is [`DuplexTransport::pump`]; over QUIC the network is the pump).
/// Returns `(applied_into_a, applied_into_b)`.
///
/// Protocol per side: send `HELLO` (offering frontier); both compute and send
/// [`WireError`].
///
/// Returns the number of entries newly applied into `dag`.
pub fn frontier_session_peer<T, R>(
    t: &mut T,
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
) -> std::result::Result<usize, WireError>
where
    T: Transport,
    R: AuthorResolver,
{
    match frontier_session_peer_inner(t, dag, resolver, admission) {
        Ok(applied) => Ok(applied),
        Err(code) => {
            t.close(code);
            Err(code)
        }
    }
}

fn frontier_session_peer_inner<T, R>(
    t: &mut T,
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
) -> std::result::Result<usize, WireError>
where
    T: Transport,
    R: AuthorResolver,
{
    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);

    // 1. HELLO exchange + mode negotiation.
    send(t, encode_hello(SYNC_MODE_FRONTIER))?;
    let remote_hello = expect_hello(t.recv())?;
    negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;

    // 2. HAVE exchange.
    send(t, encode_have(&frontiers_of(dag)))?;
    match frontier_session_room_inner(t, room) {
        Ok(applied) => Ok(applied),
        Err(code) => {
            t.close(code);
            Err(code)
        }
    }
}

fn frontier_session_room_inner<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
where
    T: Transport,
    S: SessionRoom + ?Sized,
{
    let send = |t: &mut T, f: Vec<u8>| t.send(&f).map_err(|_| WireError::TransportFailed);

    send(t, encode_hello(SYNC_MODE_FRONTIER))?;
    let remote_hello = expect_hello(t.recv())?;
    negotiate_mode(SYNC_MODE_FRONTIER, remote_hello)?;

    send(t, encode_have(&room.frontiers()?))?;
    let remote_have = expect_have(t.recv())?;

    send(t, encode_want(&room.wants(&remote_have)?))?;
    let their_wants = expect_want(t.recv())?;

    let serve_deadline = std::time::Instant::now() + SERVE_BUDGET;
    for wire in room.entries(&their_wants)? {
        if std::time::Instant::now() >= serve_deadline {
            break;
        }
        send(t, encode_entry(&wire))?;
    }
    t.finish();

    // Drained with no lock held; applied a batch at a time under a fresh one.
    let deadline = std::time::Instant::now() + DRAIN_BUDGET;
    let mut staged: Vec<Vec<u8>> = Vec::new();
    let mut applied = 0;
    while let Some(frame) = t.recv().map_err(|_| WireError::TransportFailed)? {
        if std::time::Instant::now() >= deadline {
            return Err(WireError::SyncModeUnsupported);
        }
        match decode_frame(&frame) {
            Ok(SyncFrame::Entry(wire)) => {
                staged.push(wire);
                if staged.len() >= MAX_STAGED {
                    applied += room.apply(std::mem::take(&mut staged))?;
                }
            }
            Ok(_) | Err(_) => return Err(WireError::SyncModeUnsupported),
        }
    }
    if !staged.is_empty() {
        applied += room.apply(staged)?;
    }
    Ok(applied)
}

/// Apply staged entries into `dag`, returning how many were newly stored — the apply half of
/// [`SessionRoom::apply`], for a caller that already holds its room.
///
/// # Errors
/// The first hard sync failure.
pub fn apply_staged<R: AuthorResolver>(
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    staged: &[Vec<u8>],
) -> std::result::Result<usize, WireError> {
    let mut stored = 0;
    for wire in staged {
        if matches!(
            apply_entry(dag, resolver, admission, wire)?,
            ApplyOutcome::Stored
        ) {
            stored += 1;
        }
    }
    Ok(stored)
}
[0m
Now let me verify the code claims. Starting with the key files:
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | grep -n "apply_entry\|ApplyOutcome::Fork\|Rejected::Fork\|ok_or(WireError::AuthenticatorInvalid)\|NotAdmitted => WireError::EpochMismatch\|const SERVE_BUDGET\|const DRAIN_BUDGET\|const MAX_SERVE" | head -30
73:const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
82:pub const MAX_SERVE_ENTRIES: usize = 1024;
88:pub const MAX_SERVE_BYTES: usize = 64 * 1024 * 1024;
95:pub const SERVE_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);
566:        Rejected::NotAdmitted => WireError::EpochMismatch,
569:        Rejected::Fork(_) => WireError::AuthenticatorInvalid,
602:pub fn apply_entry<R: AuthorResolver>(
611:        .ok_or(WireError::AuthenticatorInvalid)?;
618:        Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork),
933:            apply_entry(dag, resolver, admission, wire)?,
947:/// from [`apply_entry`].
974:                    apply_entry(dag, resolver, admission, &wire)?,
982:            // non-entry frame costs the sender nothing and never reaches `apply_entry`, so it
1120:            apply_entry(dst, resolver, admission, &wire)?,
[0m
Key discovery — at 58fde36, `apply_entry` already maps `Rejected::Fork` to `Ok(ApplyOutcome::Fork)` (sync continues). Let me verify the `SessionRoom::apply` implementations and line numbers:
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | sed -n '2600,2740p'
self.poisoned
    }

    /// Whether this channel's SEK is `mlock`ed (ADR-010 best-effort; surfaced to
    /// the UI as the memory-protection honesty flag).
    #[must_use]
    pub fn mlock_active(&self) -> bool {
        self.sek.is_mlocked()
    }

    /// App-lock this channel: wipe the SEK now. The state should be dropped
    /// afterwards; any further seal/open fails with [`Error::AtRestLocked`].
    pub fn lock_now(&mut self) {
        self.sek.lock_now();
        // Wipe the retained passphrase with the SEK: after an app-lock this channel
        // can neither unseal nor answer a join until it is reopened (ADR-010/015).
        self.passphrase.zeroize();
        self.passphrase = Zeroizing::new(Vec::new());
    }

    /// The retained channel passphrase, for answering an ADR-005 join (the only
    /// thing that needs it). Fails once the channel has been app-locked.
    ///
    /// Stays crate-internal: it is a secret, and the only legitimate consumer is the
    /// node's own join-responder path.
    pub(crate) fn join_passphrase(&self) -> Result<&[u8]> {
        if self.passphrase.is_empty() {
            return Err(Error::AtRestLocked);
        }
        Ok(self.passphrase.as_slice())
    }

    /// The ADR-005 binding parameters for a join in this channel: its channelID,
    /// current epoch, the negotiated suite, and the genesis policy's floor.
    ///
    /// Both ends must derive identical values or CPace simply fails to agree, so
    /// deriving them from the shared genesis (rather than passing them around) is
    /// what keeps the two sides honest.
    pub fn join_context(&self) -> Result<crate::join::session::JoinContext> {
        join_context_from_genesis(&self.genesis, self.epoch)
    }

    /// Whether this channel can currently answer an inbound join.
    #[must_use]
    pub fn can_answer_join(&self) -> bool {
        !self.passphrase.is_empty()
    }
}

/// A channel as a [`crate::log::sync::SessionRoom`]: each step locks the room, does its work, and
/// lets go. See [`ChannelState::sync_over_room`].
struct ChannelSessionRoom<'a> {
    shared: &'a tokio::sync::Mutex<ChannelState>,
    store: &'a Store,
    now_secs: u64,
    /// The epoch the session began at; a room that has moved on refuses what was staged for it.
    epoch: u64,
    out: std::cell::RefCell<SyncOutcome>,
    /// A local failure (a persist that failed) that must reach the caller as itself, not as a code.
    fatal: std::cell::RefCell<Option<Error>>,
}

impl ChannelSessionRoom<'_> {
    fn room(
        &self,
    ) -> std::result::Result<tokio::sync::MutexGuard<'_, ChannelState>, crate::wire::WireError>
    {
        let ch = self.shared.blocking_lock();
        if ch.poisoned {
            return Err(crate::wire::WireError::TransportFailed);
        }
        if ch.epoch != self.epoch {
            return Err(crate::wire::WireError::EpochMismatch);
        }
        Ok(ch)
    }
}

impl crate::log::sync::SessionRoom for ChannelSessionRoom<'_> {
    fn frontiers(
        &self,
    ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
        Ok(crate::log::sync::frontiers_of(&self.room()?.dag))
    }

    fn wants(
        &self,
        remote: &[crate::log::sync::FeedFrontier],
    ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
        Ok(crate::log::sync::wants_for(&self.room()?.dag, remote))
    }

    fn entries(
        &self,
        wants: &[crate::log::sync::WantRange],
    ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
        Ok(crate::log::sync::entries_for_wants(
            &self.room()?.dag,
            wants,
        ))
    }

    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
        let mut guard = self.room()?;
        let ch = &mut *guard;
        let before = ch.heads();
        // The resolver as it is *now*: an author revoked while this batch was on the wire is not
        // an author of this room any more, and its entries are refused.
        let resolver = ch.resolver();
        // **Absorb what was stored, then report the failure.** `apply_staged` stores entries one
        // at a time and stops at the first it refuses; those before it are already in the log.
        // Returning the refusal first skipped persisting and rendering them, yet the log now held
        // them, so every later session saw nothing to send and they were never shown: one joiner
        // read nothing from the host in a room, silently, about one run in four (tworooms.sh). The
        // refusal was the other joiner's entry, from an author this node had not admitted yet.
        // `sync_over` always did it in this order ("reconciliation done; only now surface a
        // session failure"); the per-step path lost it.
        let stored = crate::log::sync::apply_staged(&mut ch.dag, &resolver, &ch.admission, &staged);
        match ch.absorb_arrived(self.store, &before, self.now_secs) {
            Ok(got) => {
                let mut out = self.out.borrow_mut();
                out.rendered += got.rendered;
                out.governance += got.governance;
                stored
            }
            Err(e) => {
                *self.fatal.borrow_mut() = Some(e);
                Err(crate::wire::WireError::TransportFailed)
            }
        }
    }
}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/log/dag.rs | sed -n '210,230p; 300,330p'
pub fn authors(&self) -> Vec<Digest32> {
        let mut a: Vec<Digest32> = self.feeds.keys().copied().collect();
        a.sort_unstable();
        a
    }

    /// Whether `author` has been frozen by a fork proof.
    #[must_use]
    pub fn is_frozen(&self, author: &Digest32) -> bool {
        self.frozen.contains_key(author)
    }

    /// The recorded fork proof for a frozen author, if any.
    #[must_use]
    pub fn fork_proof(&self, author: &Digest32) -> Option<&ForkProof> {
        self.frozen.get(author)
    }

    /// Look up a stored entry by its 32-byte hash (the Negentropy key).
    #[must_use]
    pub fn get_by_hash(&self, hash: &Digest32) -> Option<&Entry> {
        let epoch = entry.skeleton.epoch;
        let hash = entry.entry_hash();

        // Governance/control entries MUST be composite (attributable) in EVERY
        // channel (ADR-008 §"Per-entry-type authentication"): a deniable
        // authenticator on a governance entry is rejected outright, so the
        // governance plane — and its fork attribution — stays intact even in
        // deniable channels.
        if matches!(kind, EntryKind::Governance) && !entry.authenticator.is_attributable() {
            return Err(Rejected::GovernanceNotAttributable);
        }

        // A frozen author's further entries are refused outright.
        if self.frozen.contains_key(&author) {
            return Err(Rejected::NotAdmitted);
        }

        // Idempotent duplicate.
        if self.by_hash.contains_key(&hash) {
            return Err(Rejected::Duplicate);
        }

        // Admission.
        if !admission.is_admitted(&channel, epoch, &author) {
            return Err(Rejected::NotAdmitted);
        }

        // Authenticator + structure (deniable verified via the M7 seam if given).
        // This precedes equivocation classification on purpose: only an entry
        // that is admitted AND authenticates may surface a fork proof / alarm.
        entry
[0m
Confirmed: at 58fde36 `apply_entry` maps `Rejected::Fork` → `Ok(ApplyOutcome::Fork)` (sync continues). Now the 202 tree files:
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/channel.rs | sed -n '1800,1840p; 1930,1950p; 2045,2110p'
/// say otherwise.
    ///
    /// The remaining consenters are re-keyed by the caller (the node's tick, from
    /// [`ChannelState::owed_rekeys`]); the rotation does not wait on that, because a
    /// revocation that took effect only once everyone else was reachable would be no
    /// revocation at all.
    pub fn revoke_consent(
        &mut self,
        profile: &Profile,
        target: Digest32,
        now_secs: u64,
    ) -> Result<ConsentRevocation> {
        let me = self.me();
        if target == me {
            return Err(Error::MalformedGovernance(
                "an identity cannot revoke its own consent",
            ));
        }
        if !MembershipView::new(&self.evaluator)
            .readers_of(&me)
            .contains(&target)
        {
            return Err(Error::MalformedGovernance("no consent to revoke"));
        }
        // Rotate first: the entry names the generation that excludes `target`, so
        // that generation has to exist before the fact is signed.
        let new_chain_id = self.rotate_sender(profile.store(), now_secs)?;
        let signer = profile.signer()?;
        let revocation =
            issue_consent_revocation(signer, &self.channel_id, self.epoch, target, new_chain_id)?;
        self.append_governance(profile, &revocation.to_wire(), now_secs)?;
        // Nothing is owed to a revoked member; drop the row so a later re-consent
        // starts from "holds nothing".
        if self.delivered.remove(&target).is_some() {
            self.persist_delivered(profile.store())?;
        }
        Ok(revocation)
    }

    /// Forget that `target` holds this identity's current sender key, so the next
    /// re-key round delivers it again (ADR-021 F12).
    /// hashes accepted so far (ADR-007's causal relation is only ever *followed*,
    /// never trusted for authority).
    fn gov_heads(&self) -> std::collections::BTreeSet<Digest32> {
        self.gov_entries.iter().map(|g| g.entry_hash).collect()
    }

    /// The resolver ADR-008 sync needs: this channel's admitted authors and the
    /// entry classification for `kind_for`.
    #[must_use]
    pub fn resolver(&self) -> ChannelAuthors {
        ChannelAuthors {
            authors: self.authors.clone(),
        }
    }

    /// Run one ADR-008 **frontier sync** session over `transport` against a peer,
    /// then durably record and render whatever arrived (ADR-016 §"Sync
    /// scheduling").
    ///
    /// Sync is ADR-008's business and applies entries to the log itself; this method
    /// is the reconciliation the runtime owes afterwards. It snapshots each author's
                .get_by_hash(&entry_hash)
                .ok_or(Error::MalformedGovernance("synced entry vanished"))?
                .to_wire();
            let id = self.next_log_id;
            let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
            if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg) {
                self.poisoned = true;
                return Err(e);
            }
            self.next_log_id = id.saturating_add(1);
            match classify_payload(&payload)? {
                EntryKind::Governance => {
                    let entry = self
                        .dag
                        .get_by_hash(&entry_hash)
                        .ok_or(Error::MalformedGovernance("synced entry vanished"))?
                        .clone();
                    let gov = GovEntry::from_verified_log_entry(
                        &entry,
                        &key,
                        &self.channel_id,
                        self.gov_heads(),
                    )?;
                    self.gov_entries.push(gov);
                    self.evaluator = Arc::new(Self::build_evaluator(
                        &self.genesis,
                        &self.authors,
                        &self.gov_entries,
                        now_secs,
                    )?);
                    out.governance += 1;
                }
                EntryKind::Content => {
                    if self.render_content(store, author, entry_hash, &payload, now_secs)? {
                        out.rendered += 1;
                    }
                }
            }
        }
        // Reconciliation done; only now surface a session failure, with its coded
        // reason preserved (ADR-008 never downgrades a failure silently).
        Ok(out)
    }

    /// Reconcile the room with a peer over `transport`, holding `shared`'s lock only inside each
    /// protocol step — never across a send or a receive. See [`crate::log::sync::SessionRoom`].
    ///
    /// # Errors
    /// The room is poisoned, a persist fails, or the session hard-fails.
    pub fn sync_over_room<T: Transport>(
        shared: &tokio::sync::Mutex<Self>,
        store: &Store,
        transport: &mut T,
        now_secs: u64,
    ) -> Result<SyncOutcome> {
        let epoch = {
            let ch = shared.blocking_lock();
            if ch.poisoned {
                return Err(Error::Profile(
                    "channel is poisoned after a failed persist; reopen it",
                ));
            }
            ch.epoch
        };
        let room = ChannelSessionRoom {
            shared,
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/net.rs | sed -n '760,900p'
// when the peer's process is, and it is exactly what [`Self::promote_heard`] reaches for
        // when a primary closes: measured, an anchor promoted the connection to a process two
        // restarts old, because it had been silent for only 3s of the 30s silence needs, and
        // relayed a client onto it for 28s. Probing them here closes them while the evidence is
        // fresh.
        let mut held: Vec<Arc<VoxConnection>> = Vec::new();
        if let Some(primary) = lock(&self.conns).get(&peer) {
            held.push(Arc::clone(primary));
        }
        held.extend(
            lock(&self.retiring)
                .iter()
                .filter(|(c, _)| c.peer_id() == peer)
                .map(|(c, _)| Arc::clone(c)),
        );
        // A closed or already-dead (silent, or severed) connection is no rival to `file_inner` or
        // to a promotion.
        held.retain(|c| is_live(c) && !self.is_dead(c));
        // Probed at once, so a peer with a dead primary and a dead retired connection costs one
        // patience, not two.
        //
        // **Nothing is closed here.** The probes are awaited, and while they are another newcomer
        // for the same peer can be filed and a retired connection promoted; closing on the spot
        // would act on a verdict about a table that has since changed. The verdicts go to
        // `file_inner`, which acts on them under the lock, re-checked (see there).
        let mut probes = tokio::task::JoinSet::new();
        for c in held {
            probes.spawn(async move { probe_unanswered(&c).await.map(|before| (c, before)) });
        }
        let mut unanswered = Vec::new();
        while let Some(done) = probes.join_next().await {
            if let Ok(Some(dead)) = done {
                unanswered.push(dead);
            }
        }
        unanswered
    }

    /// [`Self::file_reporting`]'s body. `serve_loser` says whether the caller will read a duplicate
    /// this keeps alive: with it the loser is retired and handed back, without it the loser is
    /// closed. There is no third option — a retired connection nobody reads is the worst of both.
    ///
    /// `unanswered` is what [`Self::probe_held`] found, and it is acted on **here, under the
    /// lock**, not where it was found: the probes were awaited, and during that await another
    /// newcomer can have been filed or a retired connection promoted. A connection is closed only
    /// if it is still live and has received **nothing since its probe was sent** — so one that
    /// answered late, or that became the peer's connection because it is live, is spared.
    /// Newcomers filed during the await were never probed, so they cannot be closed by it.
    /// `a_live_duplicate_is_decided_alike` covers the case this protects: two live newcomers
    /// for one peer, filed concurrently at both ends, each probing the other's.
    fn file_inner(&self, conn: VoxConnection, serve_loser: bool, unanswered: Unanswered) -> Filed {
        let peer = conn.peer_id();
        let mut map = lock(&self.conns);
        for (dead, before) in unanswered {
            if is_live(&dead) && dead.quinn().stats().udp_rx.datagrams == before {
                dead.close(WireError::Unresponsive);
            }
        }
        if let Some(existing) = map.get(&peer) {
            // **A held connection that is dead is not a rival.** Silent: the process behind it
            // is gone (see [`SILENCE_IS_DEATH`]). Severed: its circuit is gone, so it can send
            // nothing — and a second circuit to this peer is exactly what severs it, so it is
            // severed at both ends by the time either files the newcomer that replaced it. The
            // newcomer is filed and the dead one closed, whatever the tie-break would have said.
            // Everything else is decided by path class and then by `tie_key`, which both ends
            // compute identically; the class is the connection's own recorded fact (see
            // [`path_class`]), not a reading of a table that changes underneath it.
            if is_live(existing) && self.is_dead(existing) {
                existing.close(WireError::Unresponsive);
            } else if is_live(existing) {
                let existing = Arc::clone(existing);
                let (new_class, held_class) = (
                    path_class(&self.endpoint, &conn),
                    path_class(&self.endpoint, &existing),
                );
                let newcomer_loses = new_class < held_class
                    || (new_class == held_class && tie_key(&conn) >= tie_key(&existing));
                if newcomer_loses {
                    drop(map);
                    if !serve_loser {
                        conn.close(WireError::AuthenticatorInvalid);
                        return Filed {
                            kept: existing,
                            also_serve: None,
                        };
                    }
                    let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
                    let retired = Arc::new(conn);
                    lock(&self.retiring).push((Arc::clone(&retired), retire_at));
                    return Filed {
                        kept: existing,
                        also_serve: Some(retired),
                    };
                }
                let retire_at = (self.clock)().saturating_add(self.retire_grace_secs);
                lock(&self.retiring).push((existing, retire_at));
            }
        }
        let conn = Arc::new(conn);
        // The baseline for its silence: it has just completed a handshake, so it was heard now.
        let _ = self.silent_for(&conn);
        map.insert(peer, Arc::clone(&conn));
        Filed {
            kept: conn,
            also_serve: None,
        }
    }

    /// How long a retired connection is kept readable before it is closed.
    #[must_use]
    pub fn retire_grace_secs(&self) -> u64 {
        self.retire_grace_secs
    }

    /// Close every retired connection whose grace has elapsed (or that the peer
    /// already closed). Returns how many were closed. The node's tick calls this.
    pub fn retire_expired(&self) -> usize {
        let now = (self.clock)();
        let mut retiring = lock(&self.retiring);
        let before = retiring.len();
        retiring.retain(|(conn, at)| {
            // **Still carried** means somebody other than this list holds the connection:
            // a tunnel task splicing bytes, a sync in progress. Those hold an `Arc` for as
            // long as they run, so the strong count is the liveness signal, and it needs no
            // bookkeeping that could disagree with reality.
            //
            // The grace alone is not enough to close on. It is sized for a request finishing
            // — but what rides a connection here is a *tunnel*, and an `ssh` session or a
            // file transfer is in flight for hours. Closing on the timer killed live sessions
            // mid-stream whenever a better path displaced the one they were on, which reached
            // the person as `Connection reset by peer` in the middle of their work.
            let still_carried = Arc::strong_count(conn) > 1;
            if (now >= *at && !still_carried) || !is_live(conn) {
                conn.close(WireError::AuthenticatorInvalid);
                false
            } else {
                true
            }
        });
        before - retiring.len()
    }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/net.rs | grep -n "SILENCE\|silence" | head; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/transport/quic.rs | sed -n '185,205p; 275,290p; 760,785p'
303:/// # Why silence, and not the address a newcomer came from
336:pub const SILENCE_IS_DEATH: Duration = Duration::from_secs(KEEP_ALIVE.as_secs() * 3 / 2);
394:    /// sampled, and when that count last moved. The evidence [`SILENCE_IS_DEATH`] reads.
445:    /// [`SILENCE_IS_DEATH`] is not handed out, because what is behind it is a process that has
478:    /// Whether `conn` has been silent past [`SILENCE_IS_DEATH`].
480:        self.silent_for(conn) > SILENCE_IS_DEATH
484:    /// [`SILENCE_IS_DEATH`], or relayed over a circuit this node no longer has
499:    /// holds nothing else — uses it. Once the old one passes [`SILENCE_IS_DEATH`] the two ends
537:    /// the silence measurement honest: a connection sampled only when somebody asks for it would
538:    /// look freshly heard after any gap, and its death would be noticed one [`SILENCE_IS_DEATH`]
/// windows (an experiment since dropped): without these buffers the MTU fell back to 1200 in
/// 3 of 3 runs (`black_holes_detected` 1–9); with them, 0 black holes in 3 of 3.
/// The OS may grant less, and Linux does so silently (`net.core.rmem_max`); that is not an
/// error, but it decides the path-MTU ceiling (`mtu_ceiling_for`).
const UDP_SOCKET_BUFFER: usize = 4 << 20;

/// Per-stream flow-control window (and half the connection's send window), sized for the
/// bandwidth-delay product of a 1 Gbit/s path at ~130 ms, or 10 Gbit/s at ~13 ms.
pub const STREAM_WINDOW: u32 = 16 << 20;

/// Flow-control credit a peer gets for the whole connection, across all its streams: what this
/// node will buffer for one peer that sends and is not read.
///
/// quinn's default is unlimited, which is safe only while the per-stream window is small. At
/// [`STREAM_WINDOW`] a peer may open quinn's default 100 concurrent bidirectional streams, so an
/// unlimited connection window let one peer park 100 × 16 MiB = 1.6 GiB in this node's memory
/// by writing into streams nobody reads. Two full stream windows keeps a single tunnel at full
/// speed, and lets a second one run beside it.
pub const CONNECTION_WINDOW: u32 = 2 * STREAM_WINDOW;

/// quinn's own path-MTU ceiling (`MtuDiscoveryConfig::default().upper_bound`): 1500-byte Ethernet
    // Enough flow-control credit to fill a long, fast path (PRD-001 R41). quinn's default
    // stream window is 1.25 MB, sized for 100 Mbit/s at 100 ms; at 1 Gbit/s and 20 ms RTT that
    // caps a tunnel at ~500 Mbit/s whatever the link does. Measured over a shaped 1 Gbit/s,
    // 20 ms path: 414 Mbit/s with the default, ~940 with these. The window is credit the
    // receiver grants, not memory it allocates up front.
    cfg.stream_receive_window(quinn::VarInt::from_u32(STREAM_WINDOW));
    cfg.send_window(2 * u64::from(STREAM_WINDOW));
    cfg.receive_window(quinn::VarInt::from_u32(CONNECTION_WINDOW));
    // Cubic, restarted after the connection idles: a tunnel's transfer must not inherit the
    // congestion history of an older one on the same long-lived connection (PRD-001 R41).
    cfg.congestion_controller_factory(Arc::new(
        crate::transport::congestion::IdleRestartConfig::default(),
    ));
    Arc::new(cfg)
}

        debug_assert_eq!(self.session.negotiated_group, X25519MLKEM768_CODE_POINT);
        self.session.negotiated_group
    }

    /// Open a fresh outbound bidirectional stream for a logical flow.
    ///
    /// **Bounded, and reported as the peer being gone.** `open_bi` waits for stream credit, and
    /// it waits indefinitely: a peer that stops granting credit — or a connection one end has
    /// retired while the other still holds it — parked the caller for good with no error, and a
    /// sync session parked there holds its room. And a connection that had closed came back as
    /// `MalformedBundle("quic open_bi")`, which nothing maps, so it reached a person as
    /// `Failed(Internal)`: a join whose stream opened on a retired connection said "internal
    /// error" rather than "unreachable". Both failures are the same fact — this peer is not there
    /// on this connection — and now say so.
    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream)> {
        match tokio::time::timeout(OPEN_STREAM_PATIENCE, self.connection.open_bi()).await {
            Ok(Ok(pair)) => Ok(pair),
            Ok(Err(_)) => Err(Error::Unreachable("quic stream: the connection is closed")),
            Err(_) => Err(Error::Unreachable(
                "quic stream: the peer granted no stream in time",
            )),
        }
    }

    /// Accept the next inbound bidirectional stream the peer opened.
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream)> {
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/net.rs | grep -n "KEEP_ALIVE\s*:\|const KEEP_ALIVE" | head -5; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '230,260p; 4925,4940p; 4975,4990p'
/// the node it hurts most because it is the hop a message takes when two members are never online
/// together:
///
/// ```text
/// vox node: took 1 entry for room 4yxukqstptuq
/// vox node: BUSY 20033ms — filing a sync that finished — nobody could be answered
/// ```
///
/// Past the cap a sync is **skipped, not queued**: the schedule comes round again, and a queue of
/// sessions for rooms whose state has since moved on is worse than none.
const SYNCS_IN_FLIGHT: usize = 16;

/// How many inbound joins this node answers at once.
///
/// Answering a join is the one inbound thing a **stranger** can ask for: the passphrase is the
/// join credential, so anyone holding the address and the passphrase gets an exchange, and the
/// exchange waits on them three times and verifies their proof of work. Run on the actor, that
/// made one joiner — slow, malicious, or merely behind a bad link — able to stop a node from
/// answering anybody: no messages, no syncs, nothing, for as long as it cared to stall. An anchor
/// is the worst place for it, because the whole point of an anchor is being the node that is
/// always there.
///
/// So the actor decides and a slot does the waiting. Past the cap a join is **refused, not
/// queued** — the same rule as [`SYNCS_IN_FLIGHT`], and for a stronger reason here: a queue of
/// half-finished exchanges is exactly the resource a flood wants to fill, and a joiner that is
/// told "no" now retries in a second, which is cheaper for both sides than a held stream.
///
/// The count of joins actually in flight also feeds `Difficulty::adapted_for_load`, which raises
/// the proof-of-work a joiner must do as the load climbs. That knob existed all along and was
/// passed a hardcoded `0`, so it had never once adapted.
const JOINS_IN_FLIGHT: usize = 16;
                    ran = true;
                    // Any session carries the room's latest append, whatever triggered it.
                    self.pushed_to.entry(channel_id).or_default().insert(peer);
                    if trigger == SyncTrigger::LocalAppend {
                        pushed.insert(channel_id);
                    }
                }
            }
            if let Some(schedule) = self.schedules.get_mut(&peer) {
                schedule.note_synced(now);
                // **A room skipped because it was mid-session is owed, not synced.**
                //
                // The in-flight mark is per room, so when two peers came due for one room in the
                // same pass the first took it and the second was skipped — and `note_synced` above
                // then recorded the skipped peer as synced at the same `now` as the first. Both came
                // due together again, in the same `BTreeMap` order, and the same peer lost again:
        self.pending_push.retain(|cid| !pushed.contains(cid));
        // **After** the retain, or it undoes this. The skip happens in exactly the pass where the
        // room *was* pushed — to whichever peer took it first — so an owed room added inside the loop
        // was then removed here as "pushed", and the skipped peer's retry next tick found nothing
        // owed and dropped the push. It still arrived, on the next interval: up to 30s late instead
        // of immediately, and invisible to any gate that only asks whether it arrived. Found in
        // review by the other session.
        //
        // Known and not fixed here: `pushed` means a session *started*, not that it delivered, so a
        // push to a peer whose session then fails is counted as done.
        self.pending_push.extend(owed_rooms);
        ran
    }

    /// Start reconciling one channel with one peer: learn who else has joined, then
    /// hand the channel to a detached session task.
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '3445,3460p; 4725,4745p; 4785,4805p; 5200,5225p'
// the original had (`if learned > 0`, `if gained > 0`) and I dropped when moving
                    // this out. Without it the actor did a publish round trip after *every* sync,
                    // and syncs are frequent: measured, that turned a 0-1s crossing into 20s in
                    // seven runs of ten while removing the losses. Losses gone is the right trade;
                    // paying a publish per sync for it is not.
                    if o.applied > 0 {
                        self.note_local_append(&channel_id);
                        self.refresh_reachers().await;
                        self.publish_channel_to_anchors(&channel_id).await;
                    }
                    // **A newcomer this session admitted is consented to now, not on the tick.** Two
                    // members who joined the same room learn of each other only here, from the board.
                    // Under ForwardOnly a post sealed before the author consents to a reader is never
                    // readable to it, so every tick of delay is a window of posts lost to the
                    // newcomer. Measured in room_of_three_keys_proof: the joiners' keys to each other
                    // landed 388ms and 846ms after their posts. This shrinks the window; it cannot
        self.syncing.contains(&(*channel_id, *peer))
    }

    /// Mark a channel as having a local append to push, and make every peer's
    /// schedule due (ADR-016: "a push immediately after a local append").
    fn note_local_append(&mut self, channel_id: &Digest32) {
        if self.net.is_none() {
            return;
        }
        self.push_now = true;
        self.pending_push.insert(*channel_id);
        // Something new: every peer is owed it again, including those that had the last one.
        self.pushed_to.remove(channel_id);
        for schedule in self.schedules.values_mut() {
            schedule.note_local_append();
        }
    }

    /// Run whatever the ADR-016 sync schedule says is due. Returns whether anything
    /// ran, so the caller only republishes the view when it might have changed.
    ///
    /// `run_due_syncs`), and the session's `SyncDone` re-arms this while pushes are still owed, so
    /// posts go out back to back instead of one per tick.
    async fn push_if_owed(&mut self) {
        if std::mem::take(&mut self.push_now) && self.run_due_syncs().await {
            self.publish().await;
        }
    }

    async fn run_due_syncs(&mut self) -> bool {
        let Some(net) = self.net.as_ref().map(Arc::clone) else {
            return false;
        };
        let now = self.now();
        let mut due: Vec<(Digest32, SyncTrigger)> = self
            .schedules
            .iter()
            .filter_map(|(peer, s)| s.due(now).map(|t| (*peer, t)))
            .collect();
        // **Owed peers first.** `schedules` is keyed by fingerprint, so without this every pass
        // visited peers in the same order, and one that sorted first and took the room each time
        // left the rest skipped each time. A stable sort keeps fingerprint order within each group.
    /// Reconcile a channel with every member this node can reach, now (the `Sync`
    /// command; the schedule does this automatically — ADR-016 §"Sync scheduling").
    async fn sync_channel(&mut self, channel_id: &Digest32) -> Outcome {
        if self.net.is_none() {
            return Outcome::Failed(Fault::NotNetworked);
        }
        let Some(shared) = self.channels.get(channel_id).map(Arc::clone) else {
            return Outcome::Failed(Fault::UnknownChannel);
        };
        let peers: Vec<Digest32> = {
            let channel = shared.lock().await;
            let me = channel.me();
            channel.members().into_iter().filter(|m| *m != me).collect()
        };
        let mut synced = 0usize;
        for peer in peers {
            if self.sync_one(channel_id, peer).await {
                synced += 1;
            }
        }
        if synced == 0 {
            return Outcome::Failed(Fault::Unreachable);
        }
        Outcome::Done
    }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '1755,1768p; 3370,3385p; 4350,4395p'
/// When a background dial to each member was last started: see `reach_member`.
    member_dialed_at: BTreeMap<Digest32, u64>,
    /// Explicit consents waiting on the network: for a member's dial (answered on `Dialed` by
    /// delivering, or on `ReachFailed` as `Unreachable`), or for that member's bundle record to
    /// reach this node's board (retried on the room's `SyncDone`). Each carries its attempts so
    /// far, so one that cannot succeed is answered rather than kept. The person gets the real
    /// outcome and the node keeps answering meanwhile.
    pending_consents: Vec<(Digest32, Digest32, oneshot::Sender<Outcome>, u8)>,
    /// Consecutive failed sessions per `(room, peer)`; see `MAX_PUSH_RETRIES`.
    push_failures: BTreeMap<(Digest32, Digest32), u32>,
    /// Each room's view summary and detail as this node's own latest write left them, taken under the room's lock
    /// by the write itself. `view_of` uses it when a session holds the room, so a person always sees
    /// their own post in what they read straight after, however long that session holds on. A room's
    /// entry is removed once a view reads the room under its lock, since that read includes the
                self.owed_first.insert(peer);
                self.push_now = true;
            }
            NetEvent::SyncDone {
                channel_id,
                peer,
                outcome,
            } => {
                self.syncing.remove(&(channel_id, peer));
                self.answer_pending_consents(|room, _| *room == channel_id, None)
                    .await;
                // **A session that failed delivered nothing, so its push is owed again.**
                // `run_due_syncs` counts a push as done when the session *starts*, which is the
                // only thing it can know then; a session the peer refused — because its own
                // session for this room was running — or that died on the wire carried nothing, and
                // the entry waited for the peer's next 30s interval. Measured over a forced relay
            }
        } else if attempts > 0 {
            // A dial already landed once for this consent and the connection is gone again.
            let _ = reply.send(outcome);
            return;
        }
        self.pending_consents
            .push((channel_id, target, reply, attempts.saturating_add(1)));
    }

    /// Retry the explicit consents `matches` selects (`Dialed` passes its peer, `SyncDone` its
    /// room), or answer them all with `failed` (`ReachFailed`).
    async fn answer_pending_consents(
        &mut self,
        matches: impl Fn(&Digest32, &Digest32) -> bool,
        failed: Option<Outcome>,
    ) {
        let (waiting, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_consents)
            .into_iter()
            .partition(|(room, target, _, _)| matches(room, target));
        self.pending_consents = rest;
        if waiting.is_empty() {
            return;
        }
        for (channel_id, target, reply, attempts) in waiting {
            match failed {
                Some(o) => {
                    let _ = reply.send(o);
                }
                None => {
                    // Still waiting on its dial: that is `Dialed`'s or `ReachFailed`'s to answer, not
                    // a session with somebody else that happened to finish first.
                    let connected = self
                        .net
                        .as_ref()
                        .is_some_and(|n| n.manager().existing(&target).is_some());
                    if !connected {
                        self.pending_consents
                            .push((channel_id, target, reply, attempts));
                        continue;
                    }
                    let outcome = self.consent(&channel_id, target, false).await;
                    self.settle_consent(channel_id, target, reply, outcome, attempts)
                        .await;
                }
            }
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/syncstream.rs | sed -n '85,115p'; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/anchor.rs | sed -n '405,425p'; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/transport/stream_transport.rs | sed -n '15,35p; 85,120p'
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

    store: &'a Store,
    epoch: u64,
    out: std::cell::RefCell<SyncOutcome>,
    fatal: std::cell::RefCell<Option<Error>>,
}

impl AnchorSessionRoom<'_> {
    fn copy(
        &self,
    ) -> std::result::Result<tokio::sync::MutexGuard<'_, AnchorState>, crate::wire::WireError> {
        let st = self.shared.blocking_lock();
        if st.poisoned {
            return Err(crate::wire::WireError::TransportFailed);
        }
        if st.epoch != self.epoch {
            return Err(crate::wire::WireError::EpochMismatch);
        }
        Ok(st)
    }
}

use crate::log::sync::Transport;
use crate::transport::framing::{read_frame, write_frame};
use crate::transport::quic::{close_code, VoxConnection, MAX_STREAM_FRAME};
use crate::wire::WireError;

/// How long one sync frame may take to arrive or to be accepted for sending before
/// the session is failed.
///
/// A session runs with the channel's lock held (the ADR-008 engine is synchronous
/// over channel state), so a peer that stops answering — its actor busy, its
/// network gone — would otherwise hold that lock for as long as it liked, and every
/// other use of the channel on this node would wait behind it: a join to answer, a
/// key to take, a message to send. Twenty seconds is far longer than any real
/// exchange and shorter than anyone waits.
pub const SYNC_FRAME_TIMEOUT: Duration = Duration::from_secs(20);

/// A [`sync::Transport`](crate::log::sync::Transport) over one reliable QUIC
/// bi-stream, bridging the synchronous M5 sync engine onto async quinn via a tokio
/// runtime [`Handle`].
///
/// M5 frames are opaque byte vectors; here they are length-delimited on the stream
    }
}

impl Transport for QuicStreamTransport {
    fn send(&mut self, frame: &[u8]) -> Result<()> {
        if self.closed.is_some() {
            return Err(Error::Unreachable("quic transport: send after close"));
        }
        let send = &mut self.send;
        let bound = self.frame_timeout;
        self.handle
            .block_on(async move {
                tokio::time::timeout(bound, write_frame(send, frame))
                    .await
                    .map_err(|_| Error::Unreachable("sync: peer stopped taking frames"))
            })
            .and_then(|r| r)
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        // A clean FIN exactly at a frame boundary is the peer's success
        // half-close → `Ok(None)`; anything else is a real transport failure.
        let recv = &mut self.recv;
        let bound = self.frame_timeout;
        self.handle
            .block_on(async move {
                tokio::time::timeout(bound, read_frame(recv, MAX_STREAM_FRAME))
                    .await
                    .map_err(|_| Error::Unreachable("sync: peer went quiet"))
            })
            .and_then(|r| r)
    }

    fn close(&mut self, code: WireError) {
        if self.closed.is_some() {
            return;
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/net.rs | grep -n "KEEP_ALIVE" | head -3; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/log/sync.rs | sed -n '595,625p'; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/channel.rs | sed -n '2650,2725p'
50:use crate::transport::quic::{close_code, Admission, VoxConnection, VoxEndpoint, KEEP_ALIVE};
320:/// `KEEP_ALIVE`: quinn re-arms the keep-alive on every packet it *receives*, so the side that
336:pub const SILENCE_IS_DEATH: Duration = Duration::from_secs(KEEP_ALIVE.as_secs() * 3 / 2);
///
/// Returns [`ApplyOutcome`] for the non-fatal cases (stored / duplicate / fork)
/// and `Err(WireError)` only for a *hard wire fail* that must close the stream —
/// mapped to the exact M0 code via [`wire_error_for`] / [`wire_error_for_rejected`]
/// (unknown tag, unsupported version, unknown algo, authenticator, …). A
/// **fork is not a wire fail**: it is surfaced and sync continues, so two
/// partitions can exchange conflicting heads and form the proof.
pub fn apply_entry<R: AuthorResolver>(
    dag: &mut Dag,
    resolver: &R,
    admission: &AdmissionPolicy,
    entry_wire: &[u8],
) -> std::result::Result<ApplyOutcome, WireError> {
    let entry = Entry::from_wire(entry_wire).map_err(|e| wire_error_for(&e))?;
    let key = resolver
        .key_for(&entry.skeleton.author_id)
        .ok_or(WireError::AuthenticatorInvalid)?;
    let kind = resolver.kind_for(&entry);
    match dag.accept(entry, kind, &key, admission) {
        Ok(_) => Ok(ApplyOutcome::Stored),
        Err(Rejected::Duplicate) => Ok(ApplyOutcome::Duplicate),
        // A fork is recorded by `accept` (freeze / proof) and surfaced; it does
        // not close the stream.
        Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork),
        Err(other) => Err(wire_error_for_rejected(&other)),
    }
}

/// Drive a complete **frontier-mode** session between two peers, each over its
/// own [`Transport`] endpoint, to convergence — exercising the real frame path
/// (`HELLO`/`HAVE`/`WANT`/`ENTRY`) over the abstract transport. `a` is the
    /// A local failure (a persist that failed) that must reach the caller as itself, not as a code.
    fatal: std::cell::RefCell<Option<Error>>,
}

impl ChannelSessionRoom<'_> {
    fn room(
        &self,
    ) -> std::result::Result<tokio::sync::MutexGuard<'_, ChannelState>, crate::wire::WireError>
    {
        let ch = self.shared.blocking_lock();
        if ch.poisoned {
            return Err(crate::wire::WireError::TransportFailed);
        }
        if ch.epoch != self.epoch {
            return Err(crate::wire::WireError::EpochMismatch);
        }
        Ok(ch)
    }
}

impl crate::log::sync::SessionRoom for ChannelSessionRoom<'_> {
    fn frontiers(
        &self,
    ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
        Ok(crate::log::sync::frontiers_of(&self.room()?.dag))
    }

    fn wants(
        &self,
        remote: &[crate::log::sync::FeedFrontier],
    ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
        Ok(crate::log::sync::wants_for(&self.room()?.dag, remote))
    }

    fn entries(
        &self,
        wants: &[crate::log::sync::WantRange],
    ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
        Ok(crate::log::sync::entries_for_wants(
            &self.room()?.dag,
            wants,
        ))
    }

    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
        let mut guard = self.room()?;
        let ch = &mut *guard;
        let before = ch.heads();
        // The resolver as it is *now*: an author revoked while this batch was on the wire is not
        // an author of this room any more, and its entries are refused.
        let resolver = ch.resolver();
        // **Absorb what was stored, then report the failure.** `apply_staged` stores entries one
        // at a time and stops at the first it refuses; those before it are already in the log.
        // Returning the refusal first skipped persisting and rendering them, yet the log now held
        // them, so every later session saw nothing to send and they were never shown: one joiner
        // read nothing from the host in a room, silently, about one run in four (tworooms.sh). The
        // refusal was the other joiner's entry, from an author this node had not admitted yet.
        // `sync_over` always did it in this order ("reconciliation done; only now surface a
        // session failure"); the per-step path lost it.
        let stored = crate::log::sync::apply_staged(&mut ch.dag, &resolver, &ch.admission, &staged);
        match ch.absorb_arrived(self.store, &before, self.now_secs) {
            Ok(got) => {
                let mut out = self.out.borrow_mut();
                out.rendered += got.rendered;
                out.governance += got.governance;
                stored
            }
            Err(e) => {
                *self.fatal.borrow_mut() = Some(e);
                Err(crate::wire::WireError::TransportFailed)
            }
        }
    }
}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/actor.rs | grep -n "SessionBusy\|owed_a_reason" | head -10; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | grep -n "fn in_session_with\|past the cap: skipped\|means a session \*started\|worse than none\|flood wants to fill" | head
1734:    /// (`SessionBusy`) only to that peer: it is a room peer this node chose to sync with, so the
5228:            if self.owed_a_reason(&channel_id, &peer, epoch) {
5230:                // with another). Said to a room peer, so its session ends as `SessionBusy`, not as
5235:                    crate::wire::WireError::SessionBusy,
5267:            if self.owed_a_reason(&channel_id, &peer, epoch) {
5306:    fn owed_a_reason(&self, channel_id: &Digest32, peer: &Digest32, epoch: u64) -> bool {
239:/// sessions for rooms whose state has since moved on is worse than none.
254:/// half-finished exchanges is exactly the resource a flood wants to fill, and a joiner that is
4724:    fn in_session_with(&self, channel_id: &Digest32, peer: &Digest32) -> bool {
4983:        // Known and not fixed here: `pushed` means a session *started*, not that it delivered, so a
5024:            return false; // past the cap: skipped, not queued. The schedule comes round again.
[0m
[0m$ [0mhead -30 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-astra.md; echo ---; head -5 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-glm-5.3.md; echo ---; head -5 /opt/vox/.claude/worktrees/ac-adr025/docs/adr/ADR-025-reviews/review4-kimi-k3.md
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
---
[0m
> build · glm-5.3
[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m
---
[0m
> build · kimi-k3
[0m
[0m→ [0mRead docs/adr/ADR-025-sync-scheduling-switch-not-hub.md
[0m
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/transport/quic.rs | grep -n "KEEP_ALIVE\s*:\|const KEEP_ALIVE\|OPEN_STREAM_PATIENCE" | head -5; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | grep -n "MAX_STAGED" | head -3; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | sed -n '5255,5270p'
153:const OPEN_STREAM_PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);
162:pub(crate) const KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(20);
775:        match tokio::time::timeout(OPEN_STREAM_PATIENCE, self.connection.open_bi()).await {
847:pub const MAX_STAGED: usize = 256;
906:                if staged.len() >= MAX_STAGED {
        // back in a second.
        //
        // **Refused before the lock, not after.** A session holds this room's mutex for its whole
        // run, and this is the actor: awaiting that lock to read the epoch parked the whole node
        // behind the very session this check exists to detect.
        if self.in_session_with(&channel_id, &peer) {
            let (mut send, mut recv) = (send, recv);
            crate::node::net::refuse_stream(&mut send, &mut recv);
            return;
        }
        // Only a channel we hold open at that epoch — or keep as an anchor — can be
        // reconciled. An anchor whose board just received the genesis adopts it here
        // rather than making the member wait for the next tick.
        if !self.channels.contains_key(&channel_id) {
            self.adopt_anchored(&channel_id).await;
            self.refresh_anchored_authors(&channel_id).await;
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/channel.rs | sed -n '214,230p'; git -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/anchor.rs | grep -n "impl crate::log::sync::SessionRoom for AnchorSessionRoom" 
.unwrap_or(EntryKind::Content)
    }
}

/// What one [`ChannelState::sync_over`] session did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncOutcome {
    /// Entries the ADR-008 session applied to the log.
    pub applied: usize,
    /// How many of those were governance entries folded into the evaluator.
    pub governance: usize,
    /// How many of those were decrypted and rendered into the timeline.
    pub rendered: usize,
}

/// What [`ChannelState::accept_entry`] did with a peer's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
426:impl crate::log::sync::SessionRoom for AnchorSessionRoom<'_> {
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/anchor.rs | sed -n '425,490p'
impl crate::log::sync::SessionRoom for AnchorSessionRoom<'_> {
    fn frontiers(
        &self,
    ) -> std::result::Result<Vec<crate::log::sync::FeedFrontier>, crate::wire::WireError> {
        Ok(crate::log::sync::frontiers_of(&self.copy()?.dag))
    }

    fn wants(
        &self,
        remote: &[crate::log::sync::FeedFrontier],
    ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
        Ok(crate::log::sync::wants_for(&self.copy()?.dag, remote))
    }

    fn entries(
        &self,
        wants: &[crate::log::sync::WantRange],
    ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
        Ok(crate::log::sync::entries_for_wants(
            &self.copy()?.dag,
            wants,
        ))
    }

    fn apply(&self, staged: Vec<Vec<u8>>) -> std::result::Result<usize, crate::wire::WireError> {
        let mut guard = self.copy()?;
        let st = &mut *guard;
        let before = st.heads();
        let resolver = ChannelAuthors::new(st.authors.clone());
        // Absorb what was stored, then report the failure: see `ChannelSessionRoom::apply`.
        let stored = crate::log::sync::apply_staged(&mut st.dag, &resolver, &st.admission, &staged);
        match st.absorb_arrived(self.store, &before) {
            Ok(got) => {
                self.out.borrow_mut().governance += got.governance;
                stored
            }
            Err(e) => {
                *self.fatal.borrow_mut() = Some(e);
                Err(crate::wire::WireError::TransportFailed)
            }
        }
    }
}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/net.rs | grep -n "PROBE_PATIENCE\|fn probe_unanswered" | head -5; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/node/net.rs | sed -n '/fn probe_unanswered/,/^}/p' | head -25
361:async fn probe_unanswered(conn: &VoxConnection) -> Option<u64> {
async fn probe_unanswered(conn: &VoxConnection) -> Option<u64> {
    let quic = conn.quinn();
    let before = quic.stats().udp_rx.datagrams;
    if quic
        .send_datagram(bytes::Bytes::from_static(&[PROBE_BYTE]))
        .is_err()
    {
        return None;
    }
    let deadline = tokio::time::Instant::now() + probe_patience(quic.rtt());
    loop {
        if quic.stats().udp_rx.datagrams != before || !is_live(conn) {
            return None;
        }
        if tokio::time::Instant::now() >= deadline {
            return Some(before);
        }
        tokio::time::sleep(PROBE_POLL).await;
    }
}
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | grep -n "let _slot = slot\|tokio::task::spawn_blocking\|tokio::spawn(async move\|board_records_missing_from\|fn sync_one\|fn start_session\|fn run_sync_session" | head -12
750:        tokio::spawn(async move {
768:    tokio::spawn(async move {
820:                tokio::spawn(async move {
866:                    tokio::spawn(async move {
889:                    tokio::spawn(async move {
988:    tokio::spawn(async move {
1006:            tokio::spawn(async move {
1429:        let sealed = tokio::task::spawn_blocking(move || {
2398:            tokio::spawn(async move {
2417:            tokio::spawn(async move {
2440:        tokio::spawn(async move {
2472:                tokio::spawn(async move {
[0m
Let me pin exact line numbers for the citations I'll use:
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/log/sync.rs | grep -n "ApplyOutcome::Fork$\|sync \*\*continues\*\*\|is not closed for a fork\|fn frontier_session_room_inner\|t.finish()" | head -8; git -C /opt/vox/.claude/worktrees/ac-fix202 show 8436100:crates/vox-core/src/log/sync.rs | grep -n "Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork)" 
588:    /// raises an alarm) and sync **continues**. The stream is not closed for a
804:    t.finish();
869:fn frontier_session_room_inner<T, S>(t: &mut T, room: &S) -> std::result::Result<usize, WireError>
893:    t.finish();
618:        Err(Rejected::Fork(_)) => Ok(ApplyOutcome::Fork),
[0m
[0m$ [0mgit -C /opt/vox/.claude/worktrees/ac-fix202 show 58fde36:crates/vox-core/src/node/actor.rs | grep -n "let _slot = slot;\|spawn_blocking(move || {\|board_records_missing_from\|async fn sync_one\|fn start_session\|async fn run_sync_session" 
1429:        let sealed = tokio::task::spawn_blocking(move || {
3656:            let _slot = slot;
4997:    async fn sync_one(&mut self, channel_id: &Digest32, peer: Digest32) -> bool {
5032:            let _slot = slot;
5072:                            let missing = net.board_records_missing_from(&cid, known, &set);
5117:            let joined = tokio::task::spawn_blocking(move || {
5148:    fn start_session(
5171:            let joined = tokio::task::spawn_blocking(move || {
5240:    async fn run_sync_session(
6011:            let sealed = tokio::task::spawn_blocking(move || {
[0m
# Review 4 — ADR-025 revision 4 (5846720)

Trees checked: `58fde36` (#180) and `8436100` (#202) via `git -C /opt/vox/.claude/worktrees/ac-fix202 show`. All code claims below were line-read in those trees. Not re-verified (read-only constraint): the measured numbers (35–47 collisions/40 rounds, 702–703 refusals/300 rounds), vox-0e's gate `3bb6ca1`, prior-art links, and #212's own tree.

## 1. Round-3 findings, disposition in revision 4

**review3-astra.md**

| Finding | Disposition | Reason |
|---|---|---|
| B1 bilateral serve-before-drain deadlock | RESOLVED (design) | Owned as V210-39/#212 with the fix direction (concurrent serve/drain) and S5 gated on it. The bilateral real-binary proof the finding required is not in this ADR's table and not explicitly assigned to #212 — see MINOR 4. |
| B2 held streams unbounded / holding manufactures failures / zero-progress forever / per-position allocation | RESOLVED | Held queue deleted (D4: immediate `SessionBusy` past 3); zero-progress → D3 row 3 + D5 `NoProgress` + P10; coverage is intervals + a filled-interval set, never per-position. |
| M1 filtering ≠ lifecycle | RESOLVED | D1a retires (remove → abort → drop permit), displaced ≠ death, stale `SyncDone` inert. Consent-waiter handling on retirement is still unstated (NIT 3). |
| M2 classes/durability | RESOLVED (mostly) | Classes from real predicates, `NotAdmitted` split marked, "revoked" dropped, poison → `poisoned` port with no retry until reopen, stored at the durable boundary (absorb-before-error, `8436100:node/channel.rs` 2701–2721). Residuals: MINOR 2, MINOR 3. |
| M3 proof mutants | PARTIAL | P1/P2/P3/P5/P6/P9/#202 fixed; P4, P7, P8 still don't discriminate — MAJOR 1–3. |
| M4 S0b causal evidence | RESOLVED | Two sequenced journals, overflow counters, at-admission/completion generations, queue/slot/backoff/retirement/bump events, served ids, reasons. Residual: NIT 1. |
| m1 monotonic credit | RESOLVED | `done_gen = max(done_gen, credit)` (D2). |
| m2 aggregate stall | RESOLVED | Stated honestly (4 stalled peers × 4 slots; live peer waits ≤ a session lifetime; not fixed, no proof claims a bound). |
| m3 "at most two"; consent planned-vs-done | RESOLVED | "1 out + 3 in" stated; consent bullet marked "Planned change" against the real room-only keying (`58fde36:node/actor.rs` 1762, 3373–3380, 4356–4393 — verified). |
| NIT started/ended semantics, counter equations | NOT RESOLVED | Still undefined (NIT 1). |

**review3-glm-5.3.md**

| Finding | Disposition | Reason |
|---|---|---|
| B1 bilateral livelock | RESOLVED (design) | As astra B1. |
| B2 stale `SyncDone` wedges port | RESOLVED | D1a; the wedge case (stale attempt left in `out`) is exactly what retirement removes. |
| M1 holding safety / zero-progress on any class | RESOLVED | Held queue removed; `NoProgress` covers truncation and `ProtocolViolation`, not just `unadmitted`. |
| M2 classes computable | RESOLVED (mostly) | Split marked; revoked dropped; poisoned-port terminal; intervals + advertised head hash. Residuals: MINOR 2 (resolver-key split unmarked), MINOR 3 (fork row false). |
| M3 P1 direction; P7/P8 mutants; observability | PARTIAL | P1 fixed and observable; P7's second mutant and P8's mutant still green (MAJOR 2–3); P4's control still insufficient (MAJOR 1). |
| M4 S0b | RESOLVED | As astra M4. |
| m1–m5 | RESOLVED | Max-credit; stated stall limit; backoff cleared by new epoch (D5); consent marked; envelope stated. |
| NITs | RESOLVED except counter equations | Room generation has a home (D1: on `ChannelState`/`AnchorState`, in-memory, restart resets both) ; options table fixed; rev-4 "not yet reviewed" was accurate at authoring (the `review4-*.md` files are this round's live transcripts). |

**review3-kimi-k3.md**

| Finding | Disposition | Reason |
|---|---|---|
| B1 stale rule wedges port | RESOLVED | D1a. |
| B2 bilateral deadlock | RESOLVED (design) | #212 owned, gated before S5. |
| B3 unbounded zero-progress loop | RESOLVED | D3 row 3 + D5 `NoProgress` + P10. |
| B4 P3 byte leg / P7, P8 mutants / S0b fields | PARTIAL | P3 arithmetic fixed (140 MiB > 2×64 MiB → ≥2 partials); S0b fields present; P7's and P8's mutants still don't discriminate (MAJOR 2–3). |
| M1 held safety | RESOLVED | Removed; the tree's own joins argument (180:252–255) is now cited for it. |
| M2 classes | RESOLVED (mostly) | Same residuals as glm M2. |
| M3 scheduler evaluation points | RESOLVED (mostly) | D6a lists them; the pass's scan set is still open (MAJOR 4). |
| m1–m6 | RESOLVED | Max-guarded credit; `failures` reset + `Policy` 30 s; envelope; `owed_a_reason` pinned in the #202 row; orientations gone; seq + overflow. |
| NITs | RESOLVED | Prefixes, 869–917, revision table, "no new state" claim all fixed. |

## 2. D1a — retirement, abort, permit, displaced connections

**Safe, but the abort semantics are unstated (MAJOR 5).** The attempt's task is the outer `tokio::spawn` wrapper (`58fde36:node/actor.rs` 5030–5032, 5165–5171); the session itself runs on `tokio::task::spawn_blocking` (5117, 5171), which an `AbortHandle` **cannot interrupt**. Aborting the outer task drops it at the `joined.await`, so no `SyncDone` is ever sent — good, that is exactly what makes "a stale `SyncDone` changes nothing but the `stale` counter" sufficient. The blocking worker then runs on: bounded by the per-frame 20 s timeout (`8436100:transport/stream_transport.rs` 29, 88–113), the 30 s serve + 30 s drain budgets (`58fde36:log/sync.rs` 73, 95), and the epoch/poison fences (`8436100:node/channel.rs` 2654–2666; `58fde36:node/anchor.rs` 411–422) — worst case ~80 s, typically it dies at its next frame op after a connection death. It holds the room lock only inside a step (sends occur outside `room()`; `apply` takes it per ≤256-frame batch, `58fde36:log/sync.rs` 847, 906), so the retired worker and its replacement interleave at step granularity — the two-sessions-one-room case round 3 verified safe. Its stores are idempotent and generation-covered, as D1a says. None of this is wrong; none of it is *said* — an implementer could keep the permit inside the task as today (`let _slot = slot;`, `58fde36:node/actor.rs` 5032) or expect the session to stop at once.

**Permit exactly once: yes.** It lives in `Attempt` (D1 struct), and removal happens once — at retirement or at `SyncDone` processing, both actor-serialized; the queued/stale paths cannot double-drop.

**Displaced-but-carried: consistent with net.rs.** `retire_expired` closes a displaced connection only when the grace lapses *and* nobody carries it (`Arc::strong_count > 1`, `8436100:node/net.rs` 874–898); `file_inner` retires the loser and keeps it readable. So a displaced connection's in-flight session keeps running and its `SyncDone` processes normally — matching D1a's rule that only a filed death retires.

## 3. D3 — predicates at the apply points, classify-and-continue

At both `ChannelSessionRoom::apply` and `AnchorSessionRoom::apply` (`8436100:node/channel.rs` ~2694–2725; `58fde36:node/anchor.rs` 426–470), via `apply_entry` (`log/sync.rs` 602–625): `stored`/`duplicate`/`fork` are available today as `ApplyOutcome`s; `poisoning` via the fatal cell. `frozen`/`unadmitted` both arrive as `Rejected::NotAdmitted` (`8436100:log/dag.rs` 313–315, 322–324) → `EpochMismatch` (`log/sync.rs` 566) — the split is correctly marked. Two residuals:

- **MINOR 2 — the resolver-key half of `unadmitted` needs a second, unmarked split.** "No resolver key" (`log/sync.rs` 609–611) and a bad signature both surface as `AuthenticatorInvalid` (verification failures map there too, 550–560); classifying key-missing as `unadmitted` requires distinguishing them, which is a code change the row doesn't mark (the `frozen` row marks its own).
- **MINOR 3 — the `fork-handled` row's "Today: fails the session" is false.** At both trees a fork is `Ok(ApplyOutcome::Fork)` and sync continues (`58fde36:log/sync.rs` 585–590, 618; `8436100:log/sync.rs` 618). What fails today is the frozen author's *subsequent* entries (NotAdmitted → `EpochMismatch`) — which is the `frozen` row's change, already marked. The row overstates the change; the port-level classification is the only new part.

**Classify-and-continue is safe.** Every entry still passes the full acceptance predicate per-entry (`dag.accept`: frozen check, duplicate, admission, authenticity — `8436100:log/dag.rs` 306–330); unadmitted/frozen entries are refused and never stored; continuing only admits later *independently verified* entries that today's fail-fast merely deferred to a later session. Serving stays gated by `may_sync` (D4: unchanged). The unadmitted-author amplification is paced: a peer mixing one unadmitted entry into every batch gets one progress row, then session 2 has no new progress → `NoProgress` backoff. The coverage check closes the store-what-you-didn't-ask-for hole (the security-relevant defect, correctly claimed).

## 4. D4 / D5 / D6a — loops, starvation, wedges

No unbounded loop or wedge found in D4/D5: inbound attempts are bounded receiver-side by the budgets (30 s + 30 s + 20 s frames), so the 3 inbound slots always free within ~80 s; `SessionBusy` is immediate and never held; the refused peer's `Busy` backoff (200 ms → 8 s) bounds the retry rate; symmetric lockstep backoff resolves when any session completes. D5's kinds cover the failure surface (`Policy` 30 s answers the permanent-refuser regression; `NoProgress` covers truncation and `ProtocolViolation`). One NIT: a peer that always serves ≥1 genuinely new entry stays in the progress row — back-to-back justified sessions forever against an infinite advertised tail; bounded (1 slot, 1 port, real progress each time) and no worse than today's honest catch-up, but the ADR could say so.

D6's starvation limit is stated honestly and no proof claims a bound. **D6a's real gap is MAJOR 4 below.**

## 5. S0b and the proof table

The journals now cover every precondition I checked (at-admission/completion generations, `gen_at_have`, queue/dequeue with occupancy, backoff enter/expire, retirement cause, bumps with entry ids, served ids, reasons; seq + overflow; 256 covers P1's ~80 records). The rows that still fail:

- **MAJOR 1 — P4's mutant is rescued by the ADR's own trigger list.** The setup's outbound publish-missing path (`board_records_missing_from` + `RendezvousClient::put`, `58fde36:node/actor.rs` 5072–5085 — inside the very setup the row cites) puts Carol's bundle on Bob's board; D2 raises a request on "new board members"; Bob's outbound then runs `learn_members` and stores Carol's entry ≤ 2 s with the `unadmitted` request removed. The precondition ("no other outbound from Bob… except the one it raised") cannot attribute the retry between the two triggers. The row must suppress the board publish or state that the rendezvous-put path does not raise a request (which is itself an unstated decision — see open list).
- **MAJOR 2 — P7's precondition is unachievable as written, and its second mutant is green.** `SILENCE_IS_DEATH` = `KEEP_ALIVE`(20 s, `8436100:transport/quic.rs` 162) × 3/2 = 30 s (`node/net.rs` 336), but the mid-session worker fails its own frame op at 20 s — the attempt self-completes (normal `SyncDone`) *before* the silence death is filed, so "an attempt retired by connection death" never appears via the stated mechanism. The achievable retirement is the newcomer probe (`probe_unanswered`, `node/net.rs` 361+, RTT-scaled patience) — which requires the new Bob to start within the ~20 s worker window; unstated. And the second mutant ("stale-result guard removed") is green on a correct-D1a build: retirement's abort prevents the old `SyncDone` from ever being sent, so nothing exists to clear the new attempt; the only source is a send winning the race with the abort, which a harness cannot control. The "two outbound overlap" red is therefore not realizable; the row's red rests on the first mutant alone. (Also: "slot occupancy returns to prior" has no standalone observable — occupancy rides only on queue events.)
- **MAJOR 3 — P8's mutant is green under the ADR's own D5/D6a rules.** D5 clears the backoff "by … a new connection" and D6a runs a pass on "a connection opened": Bob's return is a new connection at both ends, so Alice's outbound opens and completes ≤ 9 s with `BackoffExpired` entirely removed. The direction-checked assert (the round-3 fix) doesn't isolate the timer. The row needs a setup with no new connection (unreachable on a *live* connection, e.g. stream-open failure) or the clearing rule must go.
- **MAJOR 4 — P2's mutant depends on the unstated `schedule()` scan set.** If a slot-release pass re-evaluates all needy ports, a skipped port (mutant) is re-admitted at the next slot release and the ≤ 2 s assert stays green; if the pass serves only queued ports, it goes red. D6a lists the trigger events but not each pass's scope — a load-bearing open decision (it also decides the "partial apply's forwarding is prompt" claim).
- **MINOR 4 — the #212 finding's bilateral proof is nowhere.** Round 3 required a real-binary bilateral large-backlog proof; the ADR gates S5 on #212 but never says #212 must carry that proof. One sentence fixes it.
- **MINOR 5 — P5's precondition under-pins the spanning case.** It doesn't require the session to *complete after* the bump (only `t_have` before it), so a run where the session also ended before the bump leaves the mutant green; and "without that id in its served ids" is unverifiable when the session served > 32 entries (32-id cap + count).
- **MINOR 6 — P9 doesn't pin the extra entry's validity.** Round 3 required it be otherwise valid and admissible so no other rejection masks the coverage mutant; the row still doesn't say it.

**P9/P10 legitimacy: yes.** The system under test is the real shipped receiver binary driven through a real QUIC session by real use; the mutant sender is a fault-injected *build of the same shipped tree* playing the peer. That satisfies "proofs that drive the real shipped binaries" — the defender is the shipped binary; the mutant is the environment — and it is the only way to prove defence against a faulty peer through real use. The mutant's own journal as the send-oracle is acceptable for a proof harness.

P1, P3, P6, P10 (and P2's observability, P9's observability) check out: preconditions observable, mutants red, arithmetic sound (140 MiB > 2×64 MiB; ≤ 6 sessions in 30 s matches 1 s doubling).

## 6. Implementability, tree accuracy, planned-vs-done

Implementable without new design decisions *except*:

1. `schedule()`'s per-event scan set (MAJOR 4).
2. The abort target and the `spawn_blocking` non-interruptibility + the residual worker's bound (MAJOR 5).
3. The resolver-key split (MINOR 2).
4. Which paths count as "new board members" for a request (fetch admission vs rendezvous put) — decides P4's rescue and the request semantics.
5. Where the WANT intervals, filled-interval set live (per attempt vs per port) and their reset rules (the frozen-skip set is per-epoch; the filled set's lifetime is unstated).
6. Counter equations and whether `t_start`/`t_end` are stream-open, worker, or actor-processing times (NIT 1 — unresolved from round 3; it affects P7's overlap check).

**Tree accuracy:** one false claim — the `fork-handled` row's "Today: fails the session" (MINOR 3). Everything else I checked matched: serve bounds and silent truncation (`58fde36:log/sync.rs` 82, 88, 95, 501–506, 888–890); `SyncOutcome` mute (`node/channel.rs` 218–227); no WANT check on receive (899–914); NotAdmitted→EpochMismatch (566); no-key→AuthenticatorInvalid (609–611); poison (2050–2052, 2100–2106); revocation non-eviction (1806–1836, 1936–1943); glare refusal (5260–5263; `SessionBusy` at `8436100:node/actor.rs` 5226–5240); slot-cap skip (5023–5024); `note_synced` (4933–4934); `due()` (`node/syncstream.rs` 93–113); "pushed means started" (4983–4984); the queue arguments (237–239, 252–255); the explicit wakes (3450–3453, 4730–4740, 4788–4801); `sync_channel` Done-once-started (5202–5223); adoption before membership (5265–5313); consent room-only keying (1762, 3373–3380, 4356–4393); windows (`8436100:transport/quic.rs` 191–203, 280–282); bounded `open_stream` (764–781); frame timeout 20 s; epoch fences; absorb-before-error; `is_frozen` (216–220); duplicate idempotence (317–320); `owed_a_reason` (5306).

**Planned-vs-done:** clean. The ADR labels itself "Not decided and not built"; the consent keying and the `NotAdmitted` split are marked as planned/code changes. One overclaim: the "What each review changed" table says the P7/P8 rows were "fixed as described" — they were not (MAJOR 2–3).

**NIT 2** — the journal's "served" field ("the stored entry ids … and the served entry ids") uses "stored" to mean received-and-stored by this side; naming it "received-and-stored" would avoid colliding with the apply-path term.

## Findings summary

**BLOCKER** — none. The design (D1–D7, S0b) is specified, internally consistent, and matches both trees; I found no unbounded loop, no wedge, and no starvation beyond the honestly-stated slot case.

**MAJOR**
1. P4's mutant rescued by the "new board members" trigger via the setup's own publish-missing path (`58fde36:node/actor.rs` 5072–5085).
2. P7's precondition unachievable as written (SILENCE_IS_DEATH 30 s > the worker's 20 s frame timeout; the real path is the newcomer probe within ~20 s) and its second mutant green (the abort prevents the old `SyncDone`).
3. P8's mutant green under D5's "cleared by a new connection" + D6a's connection-opened pass.
4. `schedule()`'s per-event scan set unspecified — decides P2's mutant and the promptness claim.
5. Abort semantics unstated: which task is aborted, `spawn_blocking` uninterruptible, the residual worker's bound, permit only in `Attempt`.

**MINOR** — 1. none beyond the below; 2. resolver-key split unmarked; 3. fork row's false "Today"; 4. #212's bilateral proof unassigned; 5. P5's spanning-case and 32-id-cap gaps; 6. P9's entry validity unpinned.

**NIT** — 1. counter equations and timestamp semantics still undefined; 2. journal "served"/"stored" naming; 3. consent-waiter handling on attempt retirement unstated; 4. the infinite-tail progress row could be acknowledged.

## VERDICT

**REVISE**

The three changes I would most insist on:

1. **Make the proof table meet its own "each mutant red" gate:** rework P8 (a setup with no new connection, or drop the new-connection clearing for the asserted case), P4 (suppress or account for the board-member trigger rescue), and P7 (retire via the newcomer probe inside the 20 s worker window, not `SILENCE_IS_DEATH`; drop or make real the second mutant's "two outbound overlap" red), and pin P2's pass scope and P9's extra-entry validity.
2. **State the abort and worker semantics in D1a:** the `AbortHandle` belongs to the outer async task; `spawn_blocking` cannot be interrupted; the retired worker runs to its fence/budget bound (≤ ~80 s), holds the room lock only per step, sends no `SyncDone`, and its stores are idempotent and generation-covered; the permit lives only in `Attempt`. While there, correct the `fork-handled` row's false "Today" and mark the resolver-key split.
3. **Specify `schedule()`'s per-event scan set** (which ports each pass evaluates — all needy ports, the affected room's ports, or queued ports), because the partial-apply promptness claim, P2's mutant, and the tick's "no proof passes because of it" rule all hang on it.
