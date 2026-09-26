# ADR-025: Sync Is Scheduled Like a Switch, Not a Hub

**Status**: **Proposed, revision 3 — 2026-09-26.** Not decided and not built.

| Revision | Collision rule | Reviews (transcripts in [`ADR-025-reviews/`](ADR-025-reviews/)) |
|---|---|---|
| 1 (8c4e347) | a glare rule | gpt-6-astra **BLOCK**, glm-5.3 **REVISE**, kimi-k3 **REVISE** |
| 2 (16951fe) | a designated opener | gpt-6-astra **BLOCK**. glm-5.3 and kimi-k3 could not run: the OpenCode Zen account is out of funds |
| 3 (this) | **full duplex** | not yet reviewed |

- Revision 3 recommends full duplex and specifies the port's whole lifecycle.
- See "What each review changed" at the end.
**Date**: 2026-09-26
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: sync, scheduling, node-runtime, latency
**Builds on**: #180 (`fix/180-no-defer`, 33da864 + 58fde36) and #202 (8436100, accepted). It assumes
both are integrated. Line numbers are prefixed with their tree: **`180:`** is 58fde36 and **`202:`** is
8436100.
**Relates to**: #41 (V29-06; its backoff is deleted by D5), #200 (V210-27).

## Context

The decider, on the collisions #202 made visible: *"it kind of reminds me of a networking hub vs. a
switch — is there something that we can do that's more intelligent to make it more like a switch
instead of a hub, with slots and queues"*, and *"it's cute that it kind of sort of works but we can do
better"*.

### What a sync session is

A sync session reconciles one room's log between two nodes over one QUIC bi-stream, and **either end
may open it**. Both ends run the same steps (`180:log/sync.rs` 869–922):
1. each sends `HELLO`, then `HAVE`, then `WANT` (what it lacks of the other's `HAVE`);
2. each serves the other's `WANT` and sends FIN (893);
3. each drains and applies what it is sent (896–916).

So one session moves entries **both ways**. The room's lock is taken one step at a time
(`SessionRoom`, `ChannelState::sync_over_room`), so two sessions on one room interleave safely step by
step. A duplicate entry is refused idempotently (`202:log/dag.rs` 317–320).

Three limits shape the design:
- **Serving stops silently at a bound.** It stops at `MAX_SERVE_ENTRIES` (1,024), `MAX_SERVE_BYTES`
  (64 MiB) or `SERVE_BUDGET` (30 s) (`180:log/sync.rs` 501–506, 888–890). The session still ends
  `Ok`, and `SyncOutcome` (`180:node/channel.rs` 218–227) doesn't say so.
- **A side's success says nothing about the other side's apply.** Each side sends FIN before it
  applies what it received. Only the receiver knows whether its applies succeeded.
- **The receiver doesn't check what it receives against what it asked for.** It checks neither `WANT`
  membership nor uniqueness (`180:log/sync.rs` 899–914).

### Where scheduling behaves like a hub

1. **Glare, then random backoff (CSMA/CD).**
   - **How it happens.** A local append pushes to every peer at once. When two members post within a
     round trip, each opens a session to the other, and each end's responder refuses the other's
     because its own session with that peer is running (`180:node/actor.rs` 5260–5263; `SessionBusy`
     after #202).
   - **What it costs.** Both sessions fail. Retries follow after a random 20–100 ms, then a
     disjoint-window backoff to 8 s (#41, b6545e5).
   - **Measured** (vox-0e's instrumented harness outputs and #202's proof):
     - 35–47 collisions per 40 simultaneous rounds.
     - Room-keyed guard, on main: 1,397 refusals in 40 rounds.
     - **With #180 underneath:** 0 late posts in 600 rounds (slowest 0.30 s), but 702–703 refusals per
       300 rounds.
   - **So on the trees v0.2.10 ships, this is waste and randomness, not lost messages.**
2. **Skipped, not queued.** Past 16 slots, `sync_one` returns `false`: *"skipped, not queued"*
   (`180:node/actor.rs` 5023–5024).
   - **Why it can be lost.** The pair is not added to `owed`, and the peer's schedule is then marked
     synced (4933–4934). `due()` gates every later pass (`node/syncstream.rs` 93–113).
   - **What doesn't rescue it.** The `SyncDone` re-arm only sets `push_now`, which still hits `due()`.
     Unless another trigger happens to re-mark that peer, the push waits for the 30 s interval.
     astra and kimi-k3 traced this path. glm-5.3 argued the base recovers promptly, and astra showed
     that `due()` still gates it.
   - **Not yet measured on a real harness.** P2 measures it first.
   - **What the code argues.** It defends the skip: *"a queue of sessions for rooms whose state has
     since moved on is worse than none"* (180:237–239). D6 queues *ports*, which re-check whether they
     still need a session when their turn comes.
3. **"Pushed" means started** (`180:node/actor.rs` 4983–4984: *"Known and not fixed here"*).
   - **What rescues it today:** failures are re-owed (`PushRetry`), and an append during a session is
     re-armed at `SyncDone`.
   - **What's left:** a truncated serve counts as done, and a partial apply that then fails doesn't
     wake the room's other peers.
4. **Seven maps and a flag for one question**: `schedules`, `pending_push`, `pushed_to`, `owed_first`,
   `push_failures`, `syncing`, #202's `syncing_with`, and `push_now`. Their disagreements are recorded
   as past defects at the sites themselves.

## Prior art

Researched 2026-09-26; primary sources linked, and items marked *(unverified)* were not line-read.

- **Collide, then retry at random: today's behaviour.**
  - SIP glare (RFC 3261 §14, `491`) *(unverified against the RFC text)*.
  - libp2p simultaneous open's coin toss
    ([simopen.md](https://github.com/libp2p/specs/blob/master/connections/simopen.md)).
  - Wi-Fi RTS/CTS.
- **Deterministic tie-breaks.** BGP ([RFC 4271 §6.8](https://www.rfc-editor.org/rfc/rfc4271.html)),
  WebRTC perfect negotiation ([Mozilla](https://blog.mozilla.org/webrtc/perfect-negotiation-in-webrtc/)),
  `iroh-persistent` ([ppetr/iroh-persistent](https://github.com/ppetr/iroh-persistent)), and Vox's own
  `incoming_session_wins`.
  - The pitfall is deciding by timing, not identity
    ([go-libp2p-swarm#79](https://github.com/libp2p/go-libp2p-swarm/issues/79)).
  - Revisions 1 and 2 built on these. Revision 3 doesn't need a tie-break at all.
- **Full duplex: both directions at once, no collision detection.** This is switched Ethernet
  (IEEE 802.3x): a full-duplex port has no CSMA/CD because both ends may transmit simultaneously.
  - **TCP simultaneous open** ([RFC 9293 §3.5](https://www.rfc-editor.org/rfc/rfc9293.html)) accepts
    both SYNs rather than refusing either.
  - **Yjs** sends `SyncStep1` from **both** ends and treats the redundancy as harmless
    ([y-protocols sync.js](https://github.com/yjs/y-protocols/blob/master/sync.js)).
  - **WireGuard** lets two simultaneous handshakes both complete.
  - Each accepts duplicate work in exchange for having no collision state. That trade is revision 3's.
- **A dirty flag, re-queued once.** Kubernetes client-go's workqueue
  ([queue.go](https://github.com/kubernetes/client-go/blob/master/util/workqueue/queue.go)).
- **Persistent streams: deferred to v0.3.0.** Scuttlebutt EBT, Hypercore
  ([DEP-0010](https://www.datprotocol.com/deps/0010-wire-protocol/)) and Willow WGPS
  ([spec](https://willowprotocol.org/specs/sync/index.html)).
  - Their shipped bugs: EBT stalls ([ssb-ebt#77](https://github.com/ssbc/ssb-ebt/issues/77)), stale
    per-peer state ([automerge-repo#742](https://github.com/automerge/automerge-repo/pull/742)), a dead
    connection blocking its replacement ([syncthing#9337](https://github.com/syncthing/syncthing/issues/9337)).
  - Short-lived sessions have their own versions of these (a running-marker wedge, `180:node/actor.rs`
    5095–5098). The deferral is because the persistent stream is a new protocol, not because
    per-event sessions are immune.
- **Stacked coalescing mechanisms produce circular waits** (Cheshire,
  [Nagle/delayed-ACK](https://www.stuartcheshire.org/papers/NagleDelayedAck/)). That's why D5 deletes
  the jitter instead of layering a new rule on it.

## Options for the collision (the decider's choice)

| | **C. Full duplex** (recommended) | A. Designated opener (revision 2) | B. Glare rule (revision 1) |
|---|---|---|---|
| Who opens | either end, whenever its port needs a session | only the lower fingerprint; the higher sends `SYNC_NOTIFY` | either; on glare the lower's is kept |
| Busy refusals | **none**: an inbound session is always admitted, queued if the port is at its inbound limit | still possible: the opener's next session can arrive while the other end is still applying the last (astra round 2, finding 1) | one per glare |
| Sessions per pair at once | at most one outbound from each end, so at most two when both need one | at most one outbound, plus turnover overlap | up to two |
| New machinery | tokens and an inbound limit | a new stream kind and its accept path, a notify lifecycle (outstanding, failed, dropped, re-sent), a manual-sync override flag, member learning on the higher end, anchor adoption on notify, amplification bounds | tokens, `Awaiting`, deadline, stale-refusal rows |
| Wire change | **none** | yes | none |
| Cost | when both ends need a session at once, both run: a duplicate `HAVE`/`WANT` exchange, and possibly entries sent twice (refused idempotently) | an extra one-way trip for the higher end's posts | a refused stream per glare |

**Recommended: C.** It is the switch's full-duplex port.
- Neither end ever waits on, refuses, or backs off from the other for being busy, so there's no
  collision to detect, no random wait, and no tie-break.
- The price is duplicate work when both ends need a session at the same instant: about one extra
  session per simultaneous round, which is cheap at family scale.
- A spent its complexity preventing a harmless duplicate, and two review rounds kept finding new
  states it needed. C needs no new state beyond tokens.

## Decision (proposed, option C)

### D1. One port per (room, peer), owned by the actor

```text
struct Port {
    out:       Option<Attempt>,            // at most one outbound session at a time
    inbound:   BTreeMap<Token, Attempt>,   // admitted inbound sessions (≤ INBOUND_PER_PORT)
    held:      VecDeque<HeldStream>,       // inbound streams waiting for admission (D4)
    queued:    Option<Instant>,            // waiting for an outbound slot (D6)
    backoff:   Option<Backoff>,            // { until, failures, token }  (D5)
    req_gen:   u64,                        // requests raised (D2)
    req_done:  u64,                        // requests satisfied
    done_gen:  u64,                        // room generation this peer is known current with (D3)
    epoch:     u64,
    conn:      ConnIncarnation,            // the connection this port's attempts ride
}
struct Attempt { token: Token, dir: Out|In, conn: ConnIncarnation, epoch: u64, req_at_start: u64 }
```

- **`ports: BTreeMap<(room, peer), Port>` replaces** `pushed_to`, `pending_push`, `owed_first`,
  `push_failures`, `syncing`, `syncing_with` and `push_now`.
- **`schedules` remains** only to raise the connect and periodic triggers.
- **Every session has a `Token`** carried to its `SyncDone`. A `SyncDone` whose token is not in `out`
  or `inbound`, or whose `conn` or `epoch` is stale, **changes nothing** except a `stale` counter.
- **Room content generation.** A room gains a monotonic `u64` generation, bumped by every stored
  entry from any source. It is read **in the same lock acquisition as the frontiers sent in `HAVE`**
  (`SessionRoom::frontiers` returns both), so it never credits an append the `HAVE` did not contain.

A port **needs a session** iff `room.gen > done_gen` or `req_gen > req_done`.

### D2. Requests: raised, captured at start, consumed at completion

Every trigger other than a stored entry **raises a request** (`req_gen += 1`):
- connect and reconnect (a new `conn` incarnation);
- the periodic tick;
- new board members;
- a person's `vox room sync`;
- a failure, truncation or temporary refusal seen by this side (D3).

A stored entry bumps the room generation instead.

**Capture and consumption:**
- An attempt captures `req_at_start = req_gen` **when it is admitted** (outbound, when it opens;
  inbound, when it leaves `held`).
- A **clean completion** of an attempt in **either direction** sets
  `req_done = max(req_done, req_at_start)`.
- **A request raised after an attempt started is never consumed by it.** So a request is never lost,
  and never loops: the workqueue rule, with its transition made exact.

**Entries applied from peer P don't re-owe P** (astra's exact condition). Let `gH` be the generation
captured with this side's `HAVE`, and `nP` the entries newly stored from P in that attempt:
- if, **at completion and in the same epoch**, `room.gen == gH + nP`, then `done_gen = gH + nP`;
- otherwise `done_gen = gH`, which re-owes P at most one idempotent session.

Duplicates and fork heads are not "newly stored".

### D3. What a side may conclude, from its own observations only

No side concludes anything about the other side's applies. **The side that sees a problem raises the
request, and under C it opens its own outbound**, whose existing setup already fetches the peer's board
and admits new authors (`180:node/actor.rs` 5033–5089). So the preparation revision 2 was missing on
one role comes free.

**Receive coverage.** The receiver keeps its `WANT` (today it is computed and discarded,
`180:log/sync.rs` 880–884) as a set of requested positions: `(author, seq)` over each range, clamped to
the peer's `HAVE`, and for an equal-sequence fork request `(N, N)` the advertised head hash.
- **Each received entry must match an unfilled requested position.** Anything else is a protocol
  violation, which fails the session and is reported. It closes astra's duplicate-substitution hole.
- **Each received entry is classified:** `stored`, `duplicate`, `fork-handled`, `excluded`
  (permanent: an author revoked or frozen in this epoch), `unadmitted` (temporary: an author not yet
  admitted here), or `persist-failed`.

At `SyncDone` (`Ok`, token current), this side:

| This side observed | Port afterwards |
|---|---|
| every requested position filled with `stored`, `duplicate`, `fork-handled` or `excluded` | `req_done = max(req_done, req_at_start)`; `done_gen` per D2; needs another session only if something newer arrived |
| some positions unfilled (the peer's serve hit a bound) | raises a request: the rest is fetched at once. `truncated` counter +1 |
| any `unadmitted` | raises a request **with `learn_members` first**; if the retry makes no progress (nothing stored, nobody admitted), D5 backoff |
| any `persist-failed`, or the session failed | raises a request; D5 backoff for a real failure |
| any `stored`, whatever the outcome | the generation bump makes every **other** port of the room need a session (astra's partial-apply finding) |

**Progress past permanent refusals.** An `excluded` author is recorded for the epoch, and later
`WANT`s skip that author's ranges. So a served prefix of 1,024 excluded entries can't be re-served
forever (astra round 2, finding 3).

### D4. Full duplex: inbound sessions are always admitted, in order

- **An inbound session for a port is never refused for being busy.** It is admitted as long as the
  port holds fewer than `INBOUND_PER_PORT = 2` inbound attempts. A correct peer has at most one
  outbound per port, and the second covers turnover: the peer's next session arriving while this side
  is still applying its last one (astra round 2, finding 1).
- **Past the limit, the stream is held**, not refused, and admitted when an inbound attempt of that
  port ends. A held stream is bounded by the peer's own frame timeout (20 s,
  `202:transport/stream_transport.rs` 20–29), which ends the peer's attempt as a transport failure if
  this side never admits it. It is queueing, not collision.
- **The outbound decision ignores inbound sessions.** A port opens an outbound when it needs a session,
  has no `out`, is not in backoff, and gets a slot. An inbound session running at the same moment is
  the "both directions at once" case, and both complete.
- **Policy refusals stay as they are:** a non-member, an epoch mismatch, or a room not held
  (`180:node/actor.rs` 5265–5313, with #202's reasons). An anchor still adopts a just-published room
  and refreshes its authors before the membership check (5265–5293), unchanged.
- **Sender-key sessions are untouched**, and so is their tie-break (`incoming_session_wins`, pairwise
  sessions).

### D5. Backoff is only for real failures, and it wakes itself

`Backoff { until, failures, token }` is entered on:
- `Unreachable` or a transport failure;
- `EpochMismatch` or a policy refusal;
- a stream-open failure (the existing bounded opener, `202:transport/quic.rs` 764–781);
- a retry that made no progress on `unadmitted` entries.

It keeps #41's growth to 8 s.
- **At `until`, a timer event `BackoffExpired { room, peer, token }` re-evaluates the port.** A stale
  token is ignored. It's the one timer besides the tick.
- **A person's `vox room sync` clears the backoff and raises a request.** Ordinary triggers wait it out.
- **Deleted:** the 20–100 ms jitter, `QUICK_PUSH_RETRIES`, the disjoint halves and `PushRetry`.
  Nothing collides, so nothing needs desynchronising.

### D6. Queued ports, fair across peers

- **16 outbound slots.** Inbound sessions take none, as today (`start_session`, `180:node/actor.rs`
  5148–5197), so two nodes cannot deadlock on each other's slots.
- **New: at most 4 outbound slots per peer**, so a stalled peer cannot hold all 16 while a live peer
  waits (astra round 2, finding 4). A stalled session still holds its slot until its frame timeout.
- **Queued ports are served round-robin across peers**, and FIFO within a peer.
- **After each session, a port that still needs one goes to the tail.**
- **A queued port re-checks its need when its turn comes**, and does not open if it has become clean.

### D7. The periodic tick is a safety net, not a delivery path

`SYNC_INTERVAL_SECS` (30 s) stays, and each tick raises a request on every shared port. No proof may
pass *because of* the tick: every delivery bound below is well under 30 s.

### Epochs, reconnects and restarts

- **A new epoch:** every attempt of the old epoch becomes stale, each port resets
  `done_gen = 0` and raises a request, and the `excluded` set is cleared. The room generation is not
  reset, because it is monotonic per room.
- **A new connection incarnation** (reconnect, or a peer restarted under the same identity): attempts
  on the old one become stale, and every shared port raises a request. The old session's eventual
  `SyncDone` is counted stale and changes nothing.
- **A consent's retry keys on (room, target) and the token**, not on the room alone
  (`180:node/actor.rs` 3373–3380, 4362–4393).
- **`vox room sync` keeps today's reply semantics**: `Done` once at least one session started
  (5202–5223). It isn't made to wait on a completion.

### Observability (S0b; lands first, so the proofs can run on the base)

`vox status --json` gains, per (room, peer):
- **counters:** sessions opened, admitted, held, completed, truncated, failed, busy-refused, stale;
- **a bounded log of the last 64 sessions:** token, direction, connection incarnation, start and end
  in unix ms, `gen_at_have`, requested positions, and received by class;
- **the room's current generation.**

It's a person's diagnostic view ("why is this room slow?"), and it makes each causal boundary a proof
needs observable through the shipped binary. On the base (#180+#202), the same fields report what exists
there: sessions, refusals and generations. The fields that exist only after the change read absent.

## Scope and release

**Proposed: v0.2.10; the decider decides.**
- **Defects in shipped code**, which belong in v0.2.10 under the every-known-defect rule:
  - the slot-cap skip (D6), once P2 measures it on the base;
  - a truncated serve counted as done (D3);
  - a partial apply that fails and doesn't wake the other peers (D3);
  - a receiver that accepts entries it didn't ask for (D3's coverage). That last one is a
    **security-relevant** gap found by the review.
- **The collision change (D4, D5) is an improvement to a mechanism that works** with #180. It removes
  ~2.3 refused streams per simultaneous round and the random wait. That is the decider's *"we can do
  better"*.
- The port (D1–D3) is what the defect fixes need, and keeping the jitter alive inside it would be the
  stacked-mechanism trap.
- The persistent stream stays a v0.3.0 candidate.

## Proof (real binaries only; timing runs take the timing lock; each prints its counts)

"The base" is #180+#202 with S0b. **No proof claims base-red until it has been run on the base**: the
column says what the analysis predicts, and S5 replaces each prediction with the measurement. A proof
whose precondition (a saturation, a refusal, a boundary) is not observed in its own log fails as
**CANNOT MEASURE**, never as green.

| # | Proof | Precondition it must observe | Asserts | Base (predicted) | Mutant that must turn it red |
|---|---|---|---|---|---|
| P1 | `simultaneous_posts_never_collide`: 2 daemons + anchor, 40 barrier-synchronised rounds | at least 20 rounds in which both members' sessions for the pair overlap in time, from the session log | `busy-refused = 0`; every post read by the other within 250 ms of `vox room post` returning (p100, loopback, one host); **every session in the log is justified** (it started while its port needed one: a generation or request newer than the port's last completion) | red: refusals > 0 | busy refusal restored at the inbound check |
| P2 | `a_burst_past_the_slot_cap_is_queued`: 2 daemons, **no anchor**, 40 rooms; only Alice posts, once in each room at once; both fingerprint orientations | at least one port recorded as queued while 4 of that peer's slots were in use | every post read by Bob within 2 s | predicted red at ~30 s by the traced path; to be measured | `try_acquire`-or-skip restored |
| P3 | `a_long_backlog_catches_up`: Bob offline while Alice posts 3,000 small entries, and separately 70 entries of 1 MiB (past `MAX_SERVE_BYTES`); both orientations | at least 2 truncated sessions in Bob's log | Bob holds every entry within 20 s of starting | to be measured (`applied > 0` may rescue it) | receive coverage **and** the `applied > 0` re-owe both removed |
| P4 | `a_refused_entry_is_asked_again`: Carol joins through Alice and posts at once | Bob's log shows an `unadmitted` class for Carol's post | Bob reads it within 2 s of that session's end | to be measured | the `unadmitted` request removed (D3 row 3) |
| P5 | `a_post_after_have_follows`: Alice posts repeatedly while sessions run | a session whose `gen_at_have` is below a post's generation and that did not carry that post | that post arrives within 250 ms | **green**: `pending_push` rescues it. **It is a mutant guard only** | `done_gen` taken at `SyncDone` instead of at `HAVE` |
| P6 | vox-0e's gate (`test/two-member-collisions` 3bb6ca1): 2 members, anchor stopped, 60 rounds | as P1 | `busy-refused = 0`, every post within its bound | red: 702–703 refusals per 300 rounds measured | as P1 |
| P7 | `a_stale_session_changes_nothing`: Bob is `SIGSTOP`ped mid-session, a new Bob starts under the same identity on another data dir clone, Alice syncs with the new Bob, then the old Bob is killed | Alice's log: an attempt on the old incarnation ending **after** an attempt on the new one started | `stale ≥ 1`; never two concurrent outbound attempts on one port; posts flow both ways throughout | to be measured | tokens ignored at `SyncDone` |
| P8 | `a_backed_off_peer_is_retried_when_due`: Bob down for 5 s, then back | Alice's log shows backoff entered | Alice's post reaches Bob within 9 s of his return; the tick excluded (bound < 30 s) | to be measured | `BackoffExpired` removed (only the tick wakes it) |
| P9 | `an_entry_that_was_not_asked_for_is_refused`: a mutant **sender** binary serves one extra entry outside the `WANT` | the extra entry is visible in the sender's own log | the receiver fails that session as a protocol violation and does not store the entry | red: the base stores it | coverage check removed |
| — | existing: `a_dead_member_does_not_stall_the_room`, R40 relayed and direct, `a_new_member_is_seen_promptly` | — | unchanged bounds | — | — |
| — | #202's proof, **rewritten**: with no busy refusals left, it forces a real failure (an anchor that keeps no log for the room) and asserts the named reason (`EpochMismatch`'s text) on that pair | the refusal in the log | reason named; no governance/malformed text | red on the #202 base's own mutants | the governance wrapper restored; the uninformative code for a room peer restored |

**Not covered, and said so:** a stalled peer holds its slots until its frame timeout. D6's per-peer cap
bounds the harm, and no proof asserts a delivery bound for the seventeenth *stalled* peer.

## Plan

| Step | Work | Depends on |
|---|---|---|
| S0 | #180 and #202 integrated into `integrate/v0.2.10` | — |
| S0b | Observability: counters, session log, generation in `vox status --json` (vox-0e offered to own it and P6) | S0 |
| S0c | **Measure the base**: P1, P2, P3, P4, P7 and P8 run on the base, and the table's predictions are replaced with the numbers | S0b |
| S1 | Generation with `HAVE`; kept `WANT`; receive coverage and classes; `SyncOutcome` extended | S0 |
| S2 | `Port` with tokens, requests and incarnations; the maps migrated; triggers only raise (D1–D3) | S1 |
| S3 | Inbound admission and holding (D4); `BackoffExpired`; jitter, `QUICK_PUSH_RETRIES` and `PushRetry` deleted (D5) | S2 |
| S4 | Per-peer slot cap, round-robin and tail requeue (D6) | S2 |
| S5 | P1–P9 on the change: red where the base measured red, each mutant red; the existing proofs re-run | S3, S4, S0c |
| S6 | Independent verifier; ADR-016's sync section points here | S5 |

One branch, `fix/adr025-sync-ports`, off `integrate/v0.2.10` after S0. Tracked as one v0.2.10 item
(V210-34) with S0b–S6 as its checklist. D3's coverage check (P9) could land first on its own if the
decider wants the security gap closed before the rest.

## What each review changed

**Round 1 → revision 2** (astra BLOCK, glm REVISE, kimi REVISE):
- tokens added;
- D3 limited to what the local side observes;
- an explicit request flag added;
- `AWAIT_KEEPER` removed;
- outbound-only slots and tail requeue;
- the proof table rebuilt;
- the false `room_in_session` claim removed;
- options compared;
- the code's defence of skipping quoted in full.

**Round 2 → revision 3** (astra BLOCK; glm and kimi unavailable):

| Finding (astra round 2) | Change |
|---|---|
| 1. The designated opener's next session can meet the other end still applying, so busy refusals return | option C: inbound is never refused, `INBOUND_PER_PORT = 2` covers turnover, past it the stream is held |
| 2. `owed` and notify lifecycle incomplete (Running, Backoff, failed or dropped notify, manual override, epoch, reconnect) | no notify exists under C; requests are captured at admission and consumed at completion (D2); `BackoffExpired`; the manual sync clears backoff; epoch and incarnation rules |
| 3. Count ≠ coverage (duplicate substitution); permanent refusals can re-serve the same prefix forever | position-matched coverage, entry classes, a per-epoch excluded set that later `WANT`s skip |
| 4. Anchors as opener; the higher end's member learning; command waiters; the uni accept path; slot saturation | C keeps anchors' and members' paths as they are, and the retry opens an outbound, whose setup already learns members; `vox room sync` keeps its semantics; no uni stream; per-peer slot cap |
| 5. Notify amplification | no notify; an inbound flood is bounded by the per-port admission limit, and holding |
| 6. Proofs lacked observed preconditions and measured base results | S0b session log; every proof must observe its precondition or report CANNOT MEASURE; S0c measures the base before any base-red claim; P7–P9 added |
| 7. D2's condition must be exact and atomic | stated with `gH + nP` checked at completion in the same epoch |
| 8. Citations from the wrong tree | every line prefixed `180:` or `202:` and re-checked |
| Nit: "exactly one" | "at most one outbound from each end" |
