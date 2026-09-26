# ADR-025: Sync Is Scheduled Like a Switch, Not a Hub

**Status**: **Proposed — 2026-09-26.** Not decided and not built. For review by three models, then the decider.
**Date**: 2026-09-26
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: sync, scheduling, node-runtime, latency
**Builds on**: #180 (sessions guarded per room and peer, `fix/180-no-defer`), #202 (`WireError::SessionBusy`,
`fix/202-sync-failure-reason`). Neither is on `integrate/v0.2.10` yet; this ADR assumes both.
**Relates to**: #41 (V29-06; its backoff is what D5 deletes), #200 (V210-27), #180, #202.

## Context

The decider, on the collisions #202 made visible: *"it kind of reminds me of a networking hub vs. a
switch — is there something that we can do that's more intelligent to make it more like a switch
instead of a hub, with slots and queues"*.

### What a sync session is

A sync session reconciles one room's log between two nodes over one QUIC bi-stream. **It is already
full duplex.** Both ends run the same steps (`log/sync.rs`, `frontier_session_room_inner`): each sends
`HELLO`, then `HAVE` (its frontiers), then `WANT` (what it lacks of the other's `HAVE`), serves the
other's `WANT`, finishes its send side and drains what it is sent. One session, opened by either end,
moves entries **both ways**. The room's lock is taken one protocol step at a time, never across the
network (`SessionRoom`, `ChannelState::sync_over_room`).

So the only thing a session opened by Alice cannot carry from Bob is **an entry Bob stored after Bob
computed his `HAVE` for that session**.

### How sessions are scheduled today, and where it behaves like a hub

Every place below is cited from `fix/202-sync-failure-reason` at 8436100 (`crates/vox-core/src/node/actor.rs`).

1. **Glare, then random backoff (CSMA/CD).** A local append marks every peer due
   (`note_local_append`, `run_due_syncs`), and the push goes out at once. When Alice and Bob post
   within a round trip of each other, each opens a session to the other. Each end's responder finds
   its own session with that peer running (`run_sync_session`, the `syncing` check, ~5226) and
   refuses with `SessionBusy`. **Both sessions fail; neither carried anything.** The `SyncDone` handler
   (~3377–3460) then re-owes the push after a random 20–100 ms (`QUICK_PUSH_RETRIES = 3`), and past
   three failures backs off from 200 ms to `MAX_PUSH_RETRY_WAIT` (8 s) with the two ends drawing from
   disjoint halves by fingerprint order (#41, b6545e5). That is Ethernet on a hub: transmit, collide,
   back off at random, transmit again.
   - Measured by `a_sync_failure_names_its_reason_proof` (#202): **35–47 collisions in 40 rounds** of
     both members posting at once, every one resolved by retry.
   - Measured by the V29-06 verdict before #41: six mutual refusals in ~200 ms with the random waits
     landing 0–8 ms apart, then a message waited **29.7 s** for the periodic tick.
   - Measured by vox-0e on main (instrumented, 2026-09-26), 3 members plus an anchor: **1,397
     refusals in 40 rounds**, with streaks of 5–7 failed sessions past `QUICK_PUSH_RETRIES`. No post was
     late only because the third member and the anchor carried what the colliding pair failed to
     exchange. With two members and the anchor stopped, the same gate is red in round 1 at 30–31 s on
     main; that stall is #180's (a room-keyed guard behind a dead peer), so #41's backoff cannot be
     judged without #180 underneath.
   - **With #180 underneath, the tail is gone but the collisions are not** (vox-0e, same gate, 5
     interleaved runs per arm, 300 rounds each): #180 alone, 0 late, slowest 0.30 s, **703 refusals**,
     longest failed streak 3; #180 plus #41's backoff, 0 late, slowest 0.25 s, **702 refusals**, longest
     streak 3. So on the trees v0.2.10 will ship, collide-and-retry *works*: about 2.3 refusals per round,
     each a stream opened, refused and retried after a random wait, and a delivery time set by that
     random wait (hundreds of milliseconds) rather than by one session (tens). That is the honest size
     of item 1: waste and randomness, not lost or 30 s-late messages.
   - The retry is redundant even when it succeeds: whichever session had run would already have
     carried both ends' entries.
2. **Skipped, not queued.** `sync_one` takes one of `SYNCS_IN_FLIGHT = 16` slots with `try_acquire`;
   past the cap the push is *"skipped, not queued. The schedule comes round again."* (~5010). A node
   with more than 16 room–peer pairs to push at once drops the excess to the next pass, and the
   `pushed_to`/`pending_push` bookkeeping decides whether that pass comes at once or on the tick.
3. **"Pushed" means started, not delivered.** `run_due_syncs` records a push as done when the
   session *starts* (~4960, the comment says so: *"Known and not fixed here: `pushed` means a
   session started, not that it delivered"*). The failure path re-owes it (`PushRetry`); nothing
   re-owes an entry stored after the session's `HAVE`, except the separate `pending_push` path when
   the room is busy at the next append.
4. **Six maps for one question.** Whether room *R* is owed to peer *P* is spread across `schedules`,
   `pending_push`, `pushed_to`, `owed_first`, `push_failures` and `syncing`, updated at different
   points in `run_due_syncs`, `PushRetry` and `SyncDone`. Several of the comments in those places record
   defects that came from those maps disagreeing (a skipped peer marked synced, an owed room removed
   by the `retain` that follows it, a failed peer re-owed to every peer).
5. **Room-wide busy.** Before #180, one session made the whole room refuse every other peer. #180 fixes
   this by keying the guard by (room, peer); this ADR keeps that.

### What a switch does differently

A switch gives each port its own full-duplex link and its own queue, so frames are **queued, never
collided**; contention is resolved by the switch's scheduler, deterministically, not by random
backoff. The equivalents here:

| Switch | Vox |
|---|---|
| Port | a **(room, peer) pair**: the one place a session between those two can run |
| Full-duplex link | a session already carries both directions; a second concurrent one is waste |
| Per-port queue | a pair is **dirty** (owes the peer something) or clean; triggers set the flag, they never open a second session |
| Store-and-forward, no collision domain | a node that wants a pair already in session **waits for that session to end**, then runs again only if it is still dirty |
| Scheduler | a fair queue over dirty pairs for the 16 slots, instead of `try_acquire`-or-skip |

## Prior art

Researched 2026-09-26. Links are to primary sources; the items marked *(unverified)* were not
line-read.

**Collide and retry at random: what we do now.** SIP glare (RFC 3261 §14, `491 Request Pending`)
retries after a randomized window, with no bound on the number of rounds; re-glare happens in real
deployments *(unverified against the RFC text)*. libp2p's simultaneous-open extension
([simopen.md](https://github.com/libp2p/specs/blob/master/connections/simopen.md)) tosses a random
64-bit coin and fails outright on a tie. Wi-Fi RTS/CTS reduces collisions without removing them. All
three are the hub end of the spectrum.

**A deterministic tie-break, decided before the collision: D4.**
- BGP, [RFC 4271 §6.8](https://www.rfc-editor.org/rfc/rfc4271.html): *"retain only the connection
  initiated by the BGP speaker with the higher-valued BGP Identifier"*. There's no randomness and no
  retry, and it's computed from values both ends hold beforehand. FRR shipped a bug in it over IPv6
  ([FRR#1219](https://github.com/FRRouting/frr/issues/1219)): deterministic on paper still has to be
  wired correctly.
- WebRTC *perfect negotiation* ([Mozilla](https://blog.mozilla.org/webrtc/perfect-negotiation-in-webrtc/)):
  a pre-agreed polite peer rolls back and accepts, while the impolite one keeps its own offer. That's
  the shape of D4. Its load-bearing detail is that both ends compute the role identically.
- `iroh-persistent` ([ppetr/iroh-persistent](https://github.com/ppetr/iroh-persistent)), on Rust and
  QUIC like us, documents our exact collision: *"a deterministic rule from the ordering of the two
  EndpointIds makes both sides keep the same [connection] and drop the other"*.
- Vox already does this for pairwise sessions (`incoming_session_wins`, ADR-021 F12).
- **The pitfall to design against:** go-libp2p's dial dedup cancelled an outbound when an inbound
  succeeded. That's a timing heuristic, not an identity rule, and it closed connections that should
  have survived ([go-libp2p-swarm#79](https://github.com/libp2p/go-libp2p-swarm/issues/79)). D4 must
  never depend on two ends agreeing about *timing*, only about fingerprints. See the interleavings
  under D4.

**A dirty flag, re-queued once when processing ends: D2 and D3.** Kubernetes client-go's workqueue
([queue.go](https://github.com/kubernetes/client-go/blob/master/util/workqueue/queue.go)) keeps
`dirty` and `processing` sets. An `Add` while a key is processing marks it dirty without enqueueing it
twice, and `Done` re-queues it exactly once if it's still dirty. So N posts during one session become
exactly one follow-up. Go's `singleflight` looks similar but isn't: it forgets a key the moment its
call ends, with no rerun-once rule. Automerge keeps an `in_flight` flag per peer
([sync::State](https://automerge.org/automerge/automerge/sync/struct.State.html)) to suppress
duplicate messages within one exchange.

**Persistent streams instead of per-event sessions: the full switch, deferred.**
- Scuttlebutt EBT ([epidemic-broadcast-trees](https://github.com/ssbc/epidemic-broadcast-trees)) keeps
  one duplex exchange per connection and announces appends via `onAppend`.
- Hypercore multiplexes `Want/Have/Request/Data` channels over one stream
  ([DEP-0010](https://www.datprotocol.com/deps/0010-wire-protocol/)).
- Yjs sends `SyncStep1` from *both* ends on connect, so initiation is symmetric and idempotent, then
  streams `Update`s ([y-protocols sync.js](https://github.com/yjs/y-protocols/blob/master/sync.js)).
- Willow's WGPS ([spec](https://willowprotocol.org/specs/sync/index.html)) runs range reconciliation
  forever over one connection, with credit-based logical channels. It explicitly leaves how that
  connection came to exist, which is our collision, to the transport.
- **Their lessons are costs:**
  - EBT has shipped replication stalls between two connected peers
    ([ssb-ebt#77](https://github.com/ssbc/ssb-ebt/issues/77), [#61](https://github.com/ssbc/ssb-ebt/issues/61)):
    a long-lived stream still needs a reliable "there is news" signal.
  - automerge-repo has shipped a family of stale per-peer sync-state bugs on reconnect
    ([#742](https://github.com/automerge/automerge-repo/pull/742),
    [#763](https://github.com/automerge/automerge-repo/pull/763),
    [#343](https://github.com/automerge/automerge-repo/issues/343)).
  - Syncthing has let a dead connection block its replacement for minutes
    ([syncthing#9337](https://github.com/syncthing/syncthing/issues/9337)).
- Each of these is a defect class that Vox's per-event sessions do not have today. That's why the
  persistent stream is left for v0.3.0 and not for a defect release.

**Where prior art does not transfer.**
- TCP's simultaneous open ([RFC 9293 §3.5](https://www.rfc-editor.org/rfc/rfc9293.html)) merges both
  SYNs into one connection, because a connection *is* its 4-tuple. A Vox session is a payload-bearing
  reconciliation, and there's no free merge point.
- WireGuard tolerates two handshakes because a handshake is cheap. Two Vox sessions are two full
  reconciliations.
- Credit-based flow control (QUIC RFC 9000 §4, WGPS guarantees) governs data already flowing. It does
  not stop two ends from opening at the same instant.
- **Stacking layers:** Cheshire's Nagle/delayed-ACK paper
  ([link](https://www.stuartcheshire.org/papers/NagleDelayedAck/)) shows two reasonable coalescing
  mechanisms, stacked without a precedence rule, producing a circular wait broken only by a timer.
  That's the argument for D5 *deleting* the jitter rather than layering D4 over it, and for D2 making
  the port the one authoritative trigger path.

## Decision (proposed)

**Each (room, peer) pair gets one port: a small state machine that the actor owns. Triggers mark a
port dirty; a scheduler runs dirty ports into slots; a collision is resolved by a fixed rule, never by
random backoff.** No wire change: the frames, the stream kind and `SessionBusy` (0x0B) stay as they
are.

### D1. One port per (room, peer), with one owner of its state

```text
struct Port {
    state:     Idle | Queued | Running { dir: Out | In, gen_at_have: u64 } | Awaiting { until } | Backoff { until, failures },
    dirty_gen: u64,   // the room's content generation this peer is owed up to
    done_gen:  u64,   // the generation the last completed session delivered
}
```

`ports: BTreeMap<(room, peer), Port>` replaces `pushed_to`, `pending_push`, `owed_first` and
`push_failures`. `syncing` becomes `Running`. `schedules` stays for the periodic tick and connect
triggers, which now only mark ports dirty.

Each room gains a **content generation**: a counter the room bumps whenever it stores an entry, from
any source (a local post, a session, a backfill). A port is **dirty** while `room.gen > port.done_gen`.

### D2. Triggers mark ports dirty; they never open a session themselves

A local append, a session that applied entries (anchor forwarding, `o.applied > 0`), a connect, a new
member, the periodic tick and a person's `vox room sync` all do the same thing: bump or read the
generation and mark the affected ports dirty. The scheduler opens sessions. This is the Kubernetes
controller workqueue rule (dedup while queued; a key marked dirty while it is processing is re-queued
once when processing ends), and it is what makes a burst of posts one session per peer instead of N.

### D3. A session delivers up to the generation of its `HAVE`, and only if it completed

When a session computes this node's `HAVE`, it records the room's generation `gen_at_have`. On
`SyncDone`:
- **completed** (both directions drained, serve not cut short by `SERVE_BUDGET`/`MAX_SERVE_*`):
  `done_gen = gen_at_have`. If `room.gen > done_gen` (something was stored after the `HAVE`), the port
  is dirty and is queued again **at once**, not on the tick;
- **failed or cut short**: `done_gen` is unchanged, so the port is still dirty; see D5 for when it runs.

This applies to sessions **in either direction**. A session Bob opened to Alice clears Alice's port
for Bob exactly as one Alice opened would, because Alice's `HAVE` went into it. That is the point:
whichever end's session runs, it serves both, and the other end does not open a second one.

### D4. A collision is resolved by a fixed rule: the lower fingerprint's session is kept

Glare (both ends opened a session for the same room to each other before either saw the other's) is
resolved the way BGP resolves a connection collision (RFC 4271 §6.8: the higher identifier's
connection is kept) and the way Vox already resolves two pairwise sessions opened at once
(`incoming_session_wins`, ADR-021 F12: the lower fingerprint's is kept). **The same side wins here
as there: the session opened by the lower fingerprint.**

- **The lower end** (its own session is the keeper) refuses the inbound one with `SessionBusy`, as
  today.
- **The higher end** accepts the inbound session even though its own outbound is running, so for a
  moment that pair has two streams on the higher end. Its own outbound is refused by the lower end with
  `SessionBusy`. That refusal is **not a failure**: the port moves to `Awaiting` and nothing is retried,
  because the inbound session it is serving carries its `HAVE`, and D3 decides on that session's
  `SyncDone` whether anything is still owed.
- `Awaiting` has a deadline, `AWAIT_KEEPER` (proposed 2 s; see the open questions). If no session from
  that peer for that room completes by then (its session died before it reached us), the port is queued
  and runs as an ordinary outbound. So a lost keeper costs one bounded wait, never the 30 s tick.

**The interleavings.** Alice is lower (L) and Bob is higher (H). Each end decides from **its own
port state and the two fingerprints only**, never from a belief about what the other end is doing.
That is the libp2p #79 lesson.

| At the moment the other's stream arrives | L's action | H's action | Sessions that run |
|---|---|---|---|
| L idle or queued, H's arrives | accept → `Running{In}`; L's queued outbound waits on it (D2) | — | 1 (H's) |
| H idle or queued, L's arrives | — | accept → `Running{In}` | 1 (L's) |
| both `Running{Out}` (glare) | refuse H's with `SessionBusy` | accept L's; H's own is refused → `Awaiting` | 1 (L's) |
| L `Running{In}` from H, and H opens again | impossible: H's port is `Running{Out}` for that session, and H opens one session per port | — | 1 |
| L `Running{Out}` completes, then H's arrives | ordinary inbound, accept | — | 2, in sequence, and the second runs only if H was dirty past its `HAVE` in the first (D3) |

- **The two ends can never refuse each other**, because H never refuses on glare.
- **Two sessions can't run to completion at once.** A stream only arrives from an end that opened
  it, so "both streams in flight" is exactly the glare row, and there L's survives and H's is refused.
- **A port can't stay `Awaiting` forever.** `AWAIT_KEEPER` bounds it, and the tick (D7) stands behind
  that.
- The reviewers are asked to break this table (open question 3).

A `SessionBusy` refusal is no longer reported as `SyncFailed`: it is an expected outcome. #202's
reporting stays for real failures.

**What this does to the numbers:** in steady state, one session per collision instead of two
refusals plus 1–3 retries, and **no random wait on the delivery path at all**. The worst case for a
message posted during a collision is the length of the keeper's session plus, if the post landed after
the keeper's `HAVE`, one more session queued at once.

### D5. Backoff is only for real failures

`Backoff` is entered only by a failure that is not a collision: `Unreachable`, a transport failure,
`EpochMismatch`, a policy refusal. It keeps #41's growth to `MAX_PUSH_RETRY_WAIT` (8 s), so a peer
whose sessions always fail (an anchor that keeps no log for the room) costs one session every few
seconds. **The jittered quick retries, `QUICK_PUSH_RETRIES` and the disjoint-halves rule are deleted:
nothing collides any more, so there is nothing to desynchronise.**

### D6. Queued, not skipped: a fair scheduler over the 16 slots

`sync_one`'s `try_acquire`-or-skip becomes a queue. Dirty ports wait in `Queued`; whenever a slot
frees (on every `SyncDone`), the scheduler starts the queued port that has waited longest (FIFO by the
time it became dirty, so one busy room cannot starve another and one peer that always goes first
cannot starve the rest; this is what `owed_first` approximated). `SYNCS_IN_FLIGHT` stays 16. The
anchor publish, `note_new_members` and a consent's retry keep `room_in_session` from #180 unchanged.

### D7. The periodic tick is a safety net, not a delivery path

`SYNC_INTERVAL_SECS` (30 s) stays as anti-entropy: every tick marks every shared port dirty, which
catches anything a bug in D1–D6 misses. No proof may pass *because of* the tick: every delivery proof
below bounds latency well under 30 s.

### Not decided here, and why

- **A persistent replication stream per peer** (one long-lived stream per peer that carries every room's
  changes as they happen, like Scuttlebutt EBT or Hypercore) is the fullest form of a switch. It changes
  the protocol, the stream lifecycle and the anchor, and is a feature, not a defect fix: a **v0.3.0**
  candidate. D1–D7 do not block it; the port state machine is what it would drive.
- **Accept-both** (never refuse; let both sessions run). Correct now that the lock is per step, and
  simpler than D4, but every collision still costs two full sessions, and it keeps the redundant session
  as the normal case. Rejected in favour of D4.

## Scope and release

**Proposed: v0.2.10, and the decider decides.** The parts are not equally defects:
- **D3 and D6 are defects** in shipped code by the code's own account (*"`pushed` means a session
  started, not that it delivered"*; *"skipped, not queued"*). Under the rule that every known defect is
  fixed in the current release, they belong in v0.2.10 however D4 is decided.
- **D4/D5 replace a mechanism that, with #180, works**: vox-0e measured 0 late posts in 600 rounds
  across both arms. What they remove is ~2.3 wasted refusals per simultaneous round and a random wait
  on the delivery path. The decider's words were *"it kind of sort of works but we can do better"*.
  That is an improvement to shipped behaviour rather than a defect with a failing proof, so the
  release it goes in is the decider's call. The case for v0.2.10 is that D1–D3 build the port that D4
  needs, and building D1–D3 without D4 means keeping the jitter code alive inside the new structure.
- The persistent stream stays for v0.3.0.

## Proof (real binaries only, ADR-018; each red-first on the base and mutation-checked)

| # | Proof (new unless noted) | Asserts | Mutant that must turn it red |
|---|---|---|---|
| P1 | `a_collision_costs_one_session_proof` — the #202 harness: a real `vox node`, two `vox daemon`s, 40 barrier-synchronised rounds of simultaneous posts | every post readable by the other member within 250 ms (p100, not p95); **zero** `did not complete` reports; zero random-wait retries | D4 inverted so both ends refuse (today's behaviour); and D4 with *both* ends accepting |
| P2 | same harness, 3 members | as P1 for every pair | D3 with `done_gen` set at session start (the old "pushed = started") |
| P3 | `a_burst_past_the_slot_cap_is_queued_proof` — 24 rooms shared by two members; both post in all 24 at once | every post arrives within 2 s; none waits for the tick | D6 reverted to `try_acquire`-or-skip |
| P4 | `a_lost_keeper_costs_a_bounded_wait_proof` — the lower end's daemon is `SIGSTOP`ped right after the higher end posts into a collision, then continued after `AWAIT_KEEPER` | the higher end's post reaches a third member (or the anchor) within `AWAIT_KEEPER` + 1 s | `Awaiting` with no deadline |
| P5 | a post stored after the keeper's `HAVE` | it arrives in the queued follow-up session, within 250 ms of the keeper's `SyncDone` | D3 without the re-queue (`done_gen` = the generation at `SyncDone`) |
| P6 | vox-0e's #41 gate (`test/41-collision-gate`): 2 members, the anchor stopped after warm-up, both posting at once, 60 rounds | every post read by the other within its bound; and, instrumented, **zero** refusals between the pair in steady state (today: streaks of 5–7) | today's collide-and-backoff restored |
| — | existing: #180's `a_dead_member_does_not_stall_the_room_proof`, #41's gate, R40 (relayed and direct), `node_m15_anchor_gate`, #202's proof (its collision assertion is replaced by P1's zero-report assertion) | unchanged bounds | — |

Every timing proof runs inside the shared timing lock. P1–P5 each print their counts (rounds run,
reports seen, sessions started), never just `ok`, so a run that measured nothing cannot read as green.

## Plan

| Step | Work | Depends on |
|---|---|---|
| S0 | Integrate #180 and #202 into `integrate/v0.2.10` (both awaiting their independent verdicts) | — |
| S0b | **Make the counts observable in the product**: `vox status --json` reports, per room and peer, sessions started, completed, refused as busy, and failed. vox-0e's refusal logging (`dbg/180-sessions` dddd316, `VOX_DEBUG_SYNC`) is debug-only, and a proof counts only what the shipped binary shows. Lands first, so P1/P6 can be run red on the base | S0 |
| S1 | Room content generation; `gen_at_have` recorded by both session directions and returned in `SyncOutcome` | S0 |
| S2 | `Port` state machine and `ports` map; migrate `pushed_to`, `pending_push`, `owed_first`, `push_failures`, `syncing` into it; triggers only mark dirty (D1, D2, D3) | S1 |
| S3 | Glare rule and `Awaiting` with its deadline; `SessionBusy` no longer reported (D4); delete the jitter and quick retries (D5) | S2 |
| S4 | FIFO scheduler over slots (D6) | S2 |
| S5 | P1–P5 red-first on the base, green on the change, each mutant red; the existing proofs above re-run | S3, S4 |
| S6 | Independent verifier; ADR-016's sync-scheduling section updated to point here | S5 |

One branch, `fix/adr025-sync-ports`, off `integrate/v0.2.10` after S0. Tracked as one v0.2.10 item
(V210-31) with S1–S6 as its checklist.

## Open questions for review

1. `AWAIT_KEEPER = 2 s`: long enough for a relayed session's first frame on a slow link, short enough
   to stay inside PRD-001 R40's 1 s budget only when the keeper is alive. Is a deadline measured from
   the refusal right, or should it be measured from the last frame the higher end saw on the keeper's
   session?
2. The room generation bumps on entries *this peer just sent us*, so after a session that applied
   entries from P, P's own port is dirty and runs one more (idempotent, empty) session. Is it worth
   tracking the entries each session applied so that session's peer is not re-owed them?
3. The higher end briefly runs two streams for one pair (its refused outbound and the accepted
   inbound). Is there any path where both complete and both apply, and does anything assume one?
