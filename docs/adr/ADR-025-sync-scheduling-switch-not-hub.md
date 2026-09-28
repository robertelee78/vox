# ADR-025: Sync Is Scheduled Like a Switch, Not a Hub

**Status**: **Accepted by the decider — 2026-09-26, revision 4 with the decisions below.** Not built.

**The decider's decisions (2026-09-26), as product manager.** The reviewers advised and the decider decided:
1. **Option C, full duplex.**
2. **All of it in v0.2.10**, both the defects and the collision redesign.
3. **Simple counters only in `vox status --json`, not a sync journal.** The reviewers asked for a detailed journal so the proofs could observe causes. The decider judged that to be product surface nobody asked for. Proofs therefore assert what a person sees, plus a few counters.
4. **The review loop stops after round 4, and building starts**, with #212 and the counters first. The remaining implementation-level findings (listed under "Settled in the code") are resolved in the implementation and checked by the independent verifier. There are no further design rounds.

| Revision | Collision rule | Reviews (transcripts in [`ADR-025-reviews/`](ADR-025-reviews/)) |
|---|---|---|
| 1 (8c4e347) | a glare rule | gpt-6-astra BLOCK, glm-5.3 REVISE, kimi-k3 REVISE |
| 2 (16951fe) | a designated opener | gpt-6-astra BLOCK (glm-5.3 and kimi-k3 were unavailable) |
| 3 (141dc11) | full duplex | all three BLOCK |
| 4 (5846720) | full duplex, specified | gpt-6-astra BLOCK, glm-5.3 **REVISE**, kimi-k3 **REVISE**: *"the architecture survives attack … revisable without touching the design"* |

**Date**: 2026-09-26
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: sync, scheduling, node-runtime, latency
**Builds on**: #180 (33da864 + 58fde36) and #202 (8436100, accepted), both assumed integrated.
**Depends on**: V210-39 (#212), the bilateral backlog deadlock, fixed separately and before S5 (see
"The inherited transport deadlock").
**Lines** are prefixed with their tree: `180:` = 58fde36, `202:` = 8436100.
**Relates to**: #41 (V29-06; its backoff is deleted by D5), #200 (V210-27).

## Context

The decider: *"it kind of reminds me of a networking hub vs. a switch — is there something that we can
do that's more intelligent to make it more like a switch instead of a hub, with slots and queues"*;
*"it's cute that it kind of sort of works but we can do better"*.

### What a sync session is

A sync session reconciles one room's log between two nodes over one QUIC bi-stream, and either end may
open it. Both ends run the same steps (`180:log/sync.rs` 869–917):
1. each sends `HELLO`, then `HAVE`, then `WANT`;
2. each serves the other's `WANT` and sends FIN;
3. each drains and applies.

The room's lock is held one step at a time (`SessionRoom`), so two sessions on one room interleave
safely. Duplicates are refused idempotently (`202:log/dag.rs` 317–320), and a partial batch is absorbed
before its error is reported (`202:node/channel.rs` 2701–2721). All three round-3 reviewers checked
this.

Facts the design must respect:
- **Serving stops silently at a bound:** 1,024 entries, 64 MiB or 30 s (`180:log/sync.rs` 501–506,
  888–890). The session still ends `Ok`, and `SyncOutcome` (`180:node/channel.rs` 218–227) doesn't say
  so.
- **Each side sends FIN before applying.** Only the receiver knows its apply outcome.
- **The receiver doesn't check what it gets against its `WANT`** (`180:log/sync.rs` 899–914).
- **Rejections today:**
  - A frozen author and an unadmitted author both return `Rejected::NotAdmitted`
    (`202:log/dag.rs` 312–324), which maps to the wire code `EpochMismatch` and **fails the session**
    (`180:log/sync.rs` 564–566).
  - An author with no resolver key fails as `AuthenticatorInvalid` (`180:log/sync.rs` 609–611).
  - A persist failure **poisons** the room until it is reopened (`202:node/channel.rs` 2050–2052,
    2100–2106).
  - **Consent revocation does not evict an author**: their entries stay valid
    (`202:node/channel.rs` 1806–1836, 1936–1943).

### Where scheduling behaves like a hub

1. **Glare, then random backoff (CSMA/CD).**
   - **What happens.** Two members posting within a round trip each open a session to the other, and
     each refuses the other's (`180:node/actor.rs` 5260–5263; `SessionBusy` after #202). Both retry
     after a random 20–100 ms, then a disjoint-window backoff (#41).
   - **Measured** (vox-0e's harness and #202's proof): 35–47 collisions per 40 simultaneous rounds.
     With #180, 0 late posts in 600 rounds but 702–703 refusals per 300 rounds.
   - **So it's waste and randomness, not loss.**
2. **Skipped, not queued.**
   - **What happens.** Past 16 slots, `sync_one` returns `false` (`180:node/actor.rs` 5023–5024). The
     peer's schedule is then marked synced (4933–4934), and `due()` gates later passes
     (`180:node/syncstream.rs` 93–113).
   - **What doesn't rescue it.** The `SyncDone` re-arm sets only `push_now`. Unless another trigger
     re-marks the peer, the push waits for the 30 s interval.
   - **What's measured.** astra and kimi-k3 traced this path. It is not measured on a harness yet (S0c).
   - **What the code argues.** It defends skipping: *"a queue of sessions for rooms whose state has
     since moved on is worse than none"* (180:237–239). D6 queues ports that re-check whether they
     still need a session.
3. **"Pushed" means started** (`180:node/actor.rs` 4983–4984). Failures and mid-session appends are
   rescued today. A truncated serve counted as done, and a failed partial apply that doesn't wake the
   room's other peers, are not.
4. **Seven maps and a flag** for one question. Past defects at those sites came from the maps
   disagreeing.

### The inherited transport deadlock (V210-39, #212)

Found by all three round-3 reviews.
- **Why it happens.** Both ends serve their whole batch before draining. A batch can approach 64 MiB,
  but the stream receive window is 16 MiB and the connection windows are 32 MiB
  (`202:transport/quic.rs` 191–203, 280–282).
- **What follows.** With a large backlog in both directions, both ends block in `write_all`, fail at
  the 20 s write timeout, and apply nothing. Retries repeat the same state.
- **It exists today** in a single session: a session already carries both directions. glm-5.3 argued
  the glare serialises it, but one session is enough to deadlock.
- **Not yet reproduced.**
- **The fix is #212's, not this ADR's**: serve and drain run concurrently (the send and receive halves
  on their own threads). Merely lowering `MAX_SERVE_BYTES` below the stream window does not suffice,
  because many rooms' sessions share one connection window.
- **ADR-025 depends on it.** Full duplex makes simultaneous sessions normal, so #212 must land before
  S5.

## Prior art

Researched 2026-09-26; primary sources linked, and items marked *(unverified)* were not line-read.

- **Collide, then retry at random** (today): SIP glare (RFC 3261 §14) *(unverified)*, libp2p
  simultaneous open ([simopen.md](https://github.com/libp2p/specs/blob/master/connections/simopen.md)),
  Wi-Fi RTS/CTS.
- **Deterministic tie-breaks:** BGP ([RFC 4271 §6.8](https://www.rfc-editor.org/rfc/rfc4271.html)),
  WebRTC perfect negotiation ([Mozilla](https://blog.mozilla.org/webrtc/perfect-negotiation-in-webrtc/)),
  `iroh-persistent` ([ppetr/iroh-persistent](https://github.com/ppetr/iroh-persistent)), and Vox's
  `incoming_session_wins`. The pitfall is deciding by timing
  ([go-libp2p-swarm#79](https://github.com/libp2p/go-libp2p-swarm/issues/79)). Revisions 1–2 used a
  tie-break; revision 4 needs none.
- **Full duplex** (switched Ethernet, IEEE 802.3x: no CSMA/CD because both ends transmit at once):
  - TCP simultaneous open accepts both SYNs ([RFC 9293 §3.5](https://www.rfc-editor.org/rfc/rfc9293.html)).
  - Yjs sends `SyncStep1` from both ends ([y-protocols](https://github.com/yjs/y-protocols/blob/master/sync.js)).
  - WireGuard lets simultaneous handshakes complete.
  - Each trades duplicate work for having no collision state.
- **A dirty flag, re-queued once:** Kubernetes client-go's workqueue
  ([queue.go](https://github.com/kubernetes/client-go/blob/master/util/workqueue/queue.go)).
- **Persistent streams, deferred to v0.3.0:** EBT, Hypercore
  ([DEP-0010](https://www.datprotocol.com/deps/0010-wire-protocol/)), Willow WGPS
  ([spec](https://willowprotocol.org/specs/sync/index.html)).
  - Their stalls ([ssb-ebt#77](https://github.com/ssbc/ssb-ebt/issues/77)), stale state
    ([automerge-repo#742](https://github.com/automerge/automerge-repo/pull/742)) and dead-connection
    blocking ([syncthing#9337](https://github.com/syncthing/syncthing/issues/9337)) have equivalents in
    short-lived sessions too (`180:node/actor.rs` 5095–5098).
  - They're deferred because they are a new protocol.
- **Stacked coalescing produces circular waits** (Cheshire,
  [Nagle/delayed-ACK](https://www.stuartcheshire.org/papers/NagleDelayedAck/)). That's why D5 deletes
  the jitter.

## Options for the collision (the decider's choice)

| | **C. Full duplex** (recommended) | A. Designated opener | B. Glare rule |
|---|---|---|---|
| Who opens | either end, when its port needs a session | only the lower fingerprint, which the higher prompts with `SYNC_NOTIFY` | either; on glare the lower's is kept |
| Busy refusals between correct peers | **none**: up to `INBOUND_PER_PORT = 3` inbound sessions per port are admitted | possible at turnover (astra, round 2) | one per glare |
| Unfinished sessions per pair, per end | at most 1 outbound + 3 inbound | 1 + turnover | 2 |
| Wire change | none | a new stream kind | none |
| Cost | a duplicate reconciliation when both ends need a session at once (~1 extra session per simultaneous round) | an extra one-way trip for the higher end's posts, plus the notify lifecycle | a refused stream per glare |

**Recommended: C.** It is the full-duplex switch port: neither end refuses, waits on or backs off from
the other for being busy.

## Decision (proposed, option C)

### D1. One port per (room, peer)

```text
struct Port {
    out:       Option<Attempt>,           // at most one outbound
    inbound:   BTreeMap<Token, Attempt>,  // ≤ INBOUND_PER_PORT (3)
    queued:    Option<QueuedSince>,       // waiting for an outbound slot (D6)
    backoff:   Option<Backoff>,           // { until, failures, kind, timer_token }  (D5)
    poisoned:  bool,                      // the room is poisoned (D3)
    req_gen:   u64,  req_done: u64,       // requests (D2)
    done_gen:  u64,                       // monotonic within an epoch (D2)
    epoch:     u64,
}
struct Attempt { token: Token, dir: Out|In, conn: ConnId, epoch: u64, req_at_start: u64,
                 abort: AbortHandle, permit: Option<OwnedSemaphorePermit> }
```

- **`ports` replaces** `pushed_to`, `pending_push`, `owed_first`, `push_failures`, `syncing`,
  `syncing_with` and `push_now`. `schedules` only raises the connect and tick requests.
- **The room generation** is a `u64` on the room's `ChannelState` (or `AnchorState`), bumped by every
  stored entry from any source. It is read in the same lock acquisition as the `HAVE` frontiers. It is
  in memory, and a restart resets it together with every port.

A port **needs a session** iff it is not poisoned, and `room.gen > done_gen` or `req_gen > req_done`.

**Unfinished sessions per pair, per end:** at most 1 outbound plus `INBOUND_PER_PORT` inbound (kimi-k3
and glm-5.3 corrected revision 3's "two").

### D1a. Retirement is separate from ignoring a result

Every attempt carries its task's `AbortHandle` and, if outbound, its slot permit.

**A port retires an attempt** when:
- **its connection dies** (the connection manager files it closed). A *displaced but still carried*
  connection is **not** a death (`202:node/net.rs` 827–855, 874–898): streams on it stay attributed to
  the port;
- **the room changes epoch**;
- **the room is poisoned**;
- **the node shuts down**.

Retiring an attempt:
1. removes it from `out` or `inbound`;
2. aborts its task;
3. drops its permit. That happens exactly once, because the permit lives in the attempt and the
   attempt is removed once.

Stores the old worker made before the abort stay: they are durable and idempotent, and D2's generation
bump covers them.

**A `SyncDone` for a retired or unknown token changes nothing but the `stale` counter.** Its resources
were already released at retirement. This is the distinction all three round-3 reviews asked for:
revision 3 only filtered results, and a stale attempt left in `out` would have silenced the port for
good.

### D2. Requests and credit

**Raising a request** (`req_gen += 1`): a new connection, the tick, new board members, a person's
`vox room sync`, and a D3 or D5 outcome.

**A port with no connection reaches its peer** (added 2026-09-28, V210-58, #246). A port that needs a
session and is not backing off, but has no connection to its peer, must reach that peer itself:
- off the actor;
- one reach per peer at a time;
- from the member's known addresses (this node's board and peer book);
- never through a session.

A reach that fails backs that peer's unconnected ports off as `Unreachable` (D5). One that succeeds is
a new connection, which D2 already makes a trigger and D5 a reset.

Before this, a connection dropped as dead (silent past `SILENCE_IS_DEATH`) was never replaced when no
anchor was left between the two members, and neither synced with the other again. CI saw this twice,
in `two_backlogs_meet_proof`.

**Capture and consumption:**
- An attempt captures `req_at_start` when it is admitted.
- A completion that D3 counts as **clean** sets `req_done = max(req_done, req_at_start)`.
- A request raised after an attempt started is never consumed by it.

**Credit is monotonic within an epoch** (all three reviews): `done_gen = max(done_gen, credit)`.
- Normally `credit = gH`, the generation captured with this side's `HAVE`.
- It is `gH + nP` when that attempt stored `nP` entries newly from P and, at completion, in the same
  epoch, `room.gen == gH + nP` (astra's exact condition).
- Duplicates and fork heads are not "newly stored".

### D3. Receive coverage, entry classes, and what each side concludes

**Coverage is interval arithmetic, never per-position sets.** glm-5.3 and astra pointed out that a
`HAVE` can claim `max_seq = u64::MAX`.
- The receiver keeps its `WANT` as per-author inclusive intervals, clamped to the peer's `HAVE`, plus
  the advertised head hash for an equal-sequence fork request `(N, N)`.
- Each received entry must fall in an unfilled interval position of its author, which is tracked as a
  filled-interval set. A fork request's entry must carry the advertised head hash.
- **Anything else is a protocol violation.** The session fails with reason `ProtocolViolation`, the
  entry is not stored, and D5 backs off with the peer reported.

**Classes, computed from predicates the code has.** Two are new apply semantics and are marked:

| Class | Predicate | Today |
|---|---|---|
| `stored` | `Dag::accept` → stored | same |
| `duplicate` | `Rejected::Duplicate` | same (idempotent) |
| `fork-handled` | `Rejected::Fork` (the author is frozen) | fails the session; **new**: classified, session continues |
| `frozen` | the author is in `Dag::frozen` (`202:log/dag.rs` 216–220). **Needs `NotAdmitted` split into `Frozen` and `NotAdmitted`** in `dag.rs`, which is a code change | fails as `EpochMismatch` |
| `unadmitted` | `Rejected::NotAdmitted` after the split, or no resolver key | fails the session; **new**: classified, session continues |
| `poisoning` | the room's persist failed | poisons the room (unchanged) |

- **"Revoked" is not a class.** Consent revocation doesn't evict an author; its entries are stored as
  normal (glm-5.3, kimi-k3).
- **Filled positions:** `stored`, `duplicate`, `fork-handled` and `frozen` fill the position.
  `unadmitted` does not.

At `SyncDone` (token current), this side:

| This side observed | Port afterwards |
|---|---|
| every requested position filled | **clean**: `req_done` and `done_gen` per D2 |
| some unfilled, and **progress** (≥1 `stored`, or a newly admitted author, or a position newly filled) | raises a request; the rest is fetched at once |
| some unfilled, and **no progress** | raises a request **and enters backoff** (D5, kind `NoProgress`). A peer that advertises what it never serves costs one session per backoff step, never a tight loop |
| any `unadmitted` | raises a request with `learn_members` first (the outbound setup, `180:node/actor.rs` 5033–5089, which under C this side runs itself); no progress → backoff |
| the room was poisoned | the room's ports retire their attempts and are marked `poisoned`, reported once. **No retry** until the room is reopened (by a person, or by #208's reopen at unlock), which re-creates its ports |
| any `stored`, whatever the outcome | the generation bumped, so every port of the room is evaluated (D6a) |

**Progress past frozen authors:** a `frozen` author's ranges are skipped in later `WANT`s for the
epoch, so the same prefix is not re-served.

### D4. Full duplex admission

- **An inbound session is admitted if the port holds fewer than `INBOUND_PER_PORT = 3` inbound
  attempts.** A correct peer has one outbound per port. The spare two cover this side still applying
  the peer's previous sessions at turnover (astra, round 2).
- **Past the limit it is refused at once with `SessionBusy`.** It is never held. The tree's own
  argument for joins applies: *"a queue of half-finished exchanges is exactly the resource a flood
  wants to fill"* (180:252–255). The refused peer treats `SessionBusy` as D5 kind `Busy`.
  - For a correct peer this only happens when this side's applies are slower than three of the peer's
    sessions.
  - P1 and P6 assert that it doesn't happen under simultaneous posting.
  - Revision 3's held queue is removed: all three reviews found it unbounded.
- **The outbound decision ignores inbound attempts** (both directions at once). glm-5.3 traced an
  honest pair converging with at most one extra session. The unbounded case was zero-progress retries,
  which D3 now paces.
- Policy refusals, and an anchor's adoption and author refresh before the membership check
  (`180:node/actor.rs` 5265–5313), are unchanged.

### D5. Backoff, by kind, with its own wakeup

| Kind | Entered on | Growth | Cap |
|---|---|---|---|
| `Unreachable` | transport failure, stream-open failure (`202:transport/quic.rs` 764–781) | from 200 ms, doubling | 8 s |
| `Busy` | `SessionBusy` (only past `INBOUND_PER_PORT`) | from 200 ms, doubling | 8 s |
| `Busy` (also) | `NotYetMember` (0x0C, #217: an anchor that has not yet admitted a just-joined member; claimed by vox-0e) | from 200 ms, doubling | 8 s: a new member's first sync must not wait on the 30 s `Policy` pacing |
| `NoProgress` | D3's no-progress rows, `ProtocolViolation` | from 1 s, doubling | 30 s |
| `Policy` | `EpochMismatch`, not a member, room not held | 30 s flat | 30 s: an anchor that keeps no log is asked once per interval, as today, not every 8 s (kimi-k3) |

- **Wakeup:** entering backoff arms `BackoffExpired { room, peer, timer_token }`. The port re-evaluates
  when it fires, and a stale `timer_token` is ignored.
- **Reset:** `failures` returns to 0 on any completion that made progress.
- **Cleared by:** a new epoch, a new connection, or a person's `vox room sync`. Ordinary triggers wait
  it out.
- **Deleted:** the 20–100 ms jitter, `QUICK_PUSH_RETRIES`, the disjoint halves and `PushRetry`.

### D6. Slots: queued, fair, bounded per peer

- **16 outbound slots, and at most 4 per peer.** Inbound sessions take none.
- **Queued ports** are served round-robin across peers and FIFO within a peer. A port that still needs
  a session after its turn goes to the tail. A queued port re-checks its need when its turn comes.
- **Stated limit** (glm-5.3, kimi-k3): four stalled peers can occupy all 16 slots until their sessions
  time out (a frame timeout of 20 s, plus the budgets). A live peer then waits up to that long.
  Round-robin decides admission; it doesn't pre-empt. This is **not fixed here**, and no proof claims a
  bound for it.

### D6a. When ports are evaluated

A single `schedule()` pass runs at the end of every actor event that can change a port's need or a
slot:
- a room generation bump (every port of that room);
- a request raised;
- a `SyncDone`;
- slot release;
- `BackoffExpired`;
- a connection opened or closed;
- an epoch change;
- a room opened or poisoned.

The pass is deduplicated per event. This replaces today's explicit wakes (`180:node/actor.rs`
3450–3453, 4730–4740, 4788–4801), so a partial apply's forwarding is prompt, never left to the tick
(kimi-k3).

### D7. The periodic tick is a safety net

It raises a request on every shared port every 30 s. No proof passes because of it.

### Consents, commands, epochs

- **Planned change:** a consent's retry will key on (room, target, token). **Today it keys on the room
  alone** (`180:node/actor.rs` 1762, 3373–3380, 4356–4393).
- `vox room sync` keeps today's reply: `Done` once a session starts (5202–5223).
- **A new epoch** retires every attempt, sets `done_gen = 0`, clears backoff and the frozen-skip set,
  and raises a request.

### Observability (S0b): simple counters (the decider's decision 3)

`vox status --json` gains, per (room, peer):
- **counters:** sessions opened, admitted, busy-refused, completed, partial, failed (with the last failure's reason), stale, skipped at the slot cap (on the base) and queued;
- **the current backoff**, if any, with its kind.

There is no session journal. Proofs assert what a person sees, above all how long a post takes to be
readable, and use these counters for what a person cannot see directly: that nothing was refused or
skipped.

## Scope and release

**Proposed: v0.2.10; the decider decides.**
- **Defects:**
  - the slot-cap skip, once S0c measures it;
  - a truncated serve counted as done;
  - a failed partial apply not waking the room's other peers;
  - the receiver storing entries it didn't ask for, which is **security-relevant**;
  - an honest pair retrying zero-progress sessions without pacing, once C removes the refusal that
    hides it;
  - separately, **#212**.
- **Improvement:** the collision change (D4, D5), which removes ~2.3 refused streams per simultaneous
  round and the random wait.

## Proof (real binaries; the timing lock; counts printed)

**How to read the table:**
- **"Base"** is #180+#202 with S0b.
- **Nothing is claimed red on the base until S0c has measured it.**
- **A proof whose precondition isn't shown by the counters, or by the proof's own setup, fails as
  CANNOT MEASURE**, never green.
- **Rows written against the withdrawn journal are to be restated against counters and timing when
  their proof is written.** Each restated row keeps its mutant, and the verifier checks that the
  mutant is still red. The round-4 reviewers' corrections to P4, P7 and P8 apply at that point:
  - **P8** backs off with the connection held up, so a reconnect cannot rescue its mutant.
  - **P4's** mutant removes the retry itself.
  - **P7** retires by the newcomer probe, not by `SILENCE_IS_DEATH`.

| # | Proof | Precondition (from the journals) | Asserts | Mutant that must turn it red |
|---|---|---|---|---|
| P1 | `simultaneous_posts_never_collide`: 2 daemons + anchor, 40 barrier-synchronised rounds | ≥ 20 rounds in which the pair's opposite-direction sessions overlap in time | `busy-refused = 0`; each post read by the other ≤ 250 ms after `vox room post` returns (p100, loopback); **every outbound session is justified by the opener's own journal** (at admission, `req_gen > req_done` or a generation bump since `done_gen`) and every inbound session is matched to a justified outbound in the peer's journal (direction-aware, glm-5.3) | busy refusal at the inbound check restored |
| P2 | `a_burst_past_the_slot_cap_is_queued`: 2 daemons, no anchor, 40 rooms, only Alice posts, once in each room at once | base: a skipped-at-cap event; change: a queued event with the peer's occupancy = 4 | each post read by Bob ≤ 2 s | `try_acquire`-or-skip restored |
| P3 | `a_long_backlog_catches_up`: Bob offline; Alice posts (a) 3,000 small entries, (b) 140 × 1 MiB; then Bob starts | (a) ≥ 2 partial completions; (b) ≥ 2 partial completions (140 MiB > 2 × 64 MiB) | Bob holds every entry ≤ 20 s after starting; ≥ 1 of Alice's `stored` ids per partial session in Bob's journal | receive coverage **and** the `applied > 0` re-owe removed |
| P4 | `a_refused_entry_is_asked_again`: Carol joins through Alice and posts at once | Bob's journal: a session with an `unadmitted` class; **no other outbound from Bob between it and the retry** except the one it raised | Bob reads Carol's post ≤ 2 s after that session ends | the `unadmitted` request removed |
| P5 | `a_post_after_have_follows`: Alice posts while sessions run | a session with `t_have` before the post's generation bump (from the event journal's entry id) and without that id in its served ids | the post arrives ≤ 250 ms after `vox room post` | `done_gen` taken at `SyncDone` instead of `HAVE` (a **mutant guard**: the base passes via `pending_push`) |
| P6 | vox-0e's gate (3bb6ca1): 2 members, anchor stopped, 60 rounds | as P1 | `busy-refused = 0`; every post within its bound | as P1 |
| P7 | `a_retired_attempt_frees_its_port`: Bob `SIGSTOP`ped mid-session; Bob's connection is then filed dead (Alice's `SILENCE_IS_DEATH`); a new Bob starts; the old Bob is killed | Alice's journal: an attempt retired by connection death, then a new outbound on the new connection | the new outbound opens within 2 s of the new connection; **never two unfinished outbound attempts on one port** (journal overlap check); the slot occupancy returns to its prior value | retirement removed (a stale attempt stays in `out`: no new outbound, red); **and** the stale-result guard removed entirely (the old `SyncDone` clears the new attempt, so two outbound overlap, red) |
| P8 | `a_backed_off_peer_is_retried_when_due`: Bob down 5 s, then back | Alice's journal: backoff `Unreachable` entered, then expired | **Alice's own outbound** (direction checked, kimi-k3 and glm-5.3) completes clean ≤ 9 s after Bob returns | `BackoffExpired` removed |
| P9 | `an_entry_that_was_not_asked_for_is_refused`: a mutant sender binary serves one entry outside the `WANT` | that id in the sender's served ids | the receiver's session fails with `ProtocolViolation`; the id is absent from its stored ids and from `vox room read` | the coverage check removed |
| P10 | `a_peer_that_serves_nothing_is_paced`: a mutant sender binary advertises a tail and serves nothing | the receiver's partial, no-progress completions | ≤ 6 sessions to that peer in 30 s; backoff `NoProgress` entered | the no-progress backoff removed (dozens of sessions, red) |
| — | #202's proof, **rewritten**: a real failure named on its pair. The setup makes `owed_a_reason` hold: the refusing anchor has the member's record on its board and keeps no log for the room (glm-5.3, kimi-k3). The refusal's reason is observed in the journal | the refusal | the named reason, with no governance or malformed text | the governance wrapper; the uninformative code for a room peer |
| — | existing: `a_dead_member_does_not_stall_the_room`, R40, `a_new_member_is_seen_promptly` | | unchanged | |

P9 and P10 need a *mutant sender*, a deliberately misbehaving build of the shipped binary. That is how
the product's defence against a faulty peer is proved through real use.

## Settled in the code (round-4 findings, not further design rounds)

Each is resolved in the implementation and stated in its commit. The independent verifier checks it.
- **D1a's mechanism** (all three reviewers).
  - An abort stops the outer task, not a started `spawn_blocking` worker. The worker stops at its next
    room step or transport operation, fenced by epoch, poison, or its stream being reset.
  - A retired worker's stores stay, and report themselves through a generation-bump event independent
    of `SyncDone`.
  - The slot permit is held until the worker exits, so slots bound running workers.
- **D5 is exhaustive.** Every hard-fail path (authentication, feed link, malformed frame, unsupported
  mode, local failure) maps to a kind. `ProtocolViolation` is local-only (no wire code), and the
  refusal is a reset. The rule for concurrent completions: progress wins over failure for `failures`
  and credit, and a failure's backoff never cancels a newer attempt.
- **`stored` means persisted.** Credit and the generation count only entries the persist step
  committed. A failure returns its committed prefix in a structured partial outcome.
- **`fork-handled` already continues today** (`180:log/sync.rs` 613–619). The table's "today" column
  is corrected in the code's comments. The new behaviour is classifying the rejections that follow.
- **`schedule()` scans** every queued port, plus the ports of the room whose event it is.
- **#212's acceptance includes a bilateral, concurrent-session, shared-connection backlog proof**
  before S5.

## Plan

| Step | Work | Depends on |
|---|---|---|
| S0 | #180, #202 integrated | — |
| S0b | observability (counters, both journals) on the base | S0 |
| S0c | the base measured: P1–P4 and P6–P8 run, predictions replaced with numbers | S0b |
| S1 | generation with `HAVE`; interval coverage and classes (including the `NotAdmitted` split); `SyncOutcome` extended | S0 |
| S2 | `Port`, tokens, requests, retirement (D1, D1a, D2); the maps migrated | S1 |
| S3 | admission (D4), backoff kinds and wakeup (D5), `schedule()` points (D6a); jitter and `PushRetry` deleted | S2 |
| S4 | per-peer slot cap, round-robin, tail requeue (D6) | S2 |
| S5 | P1–P10 on the change; each mutant red; existing proofs re-run | S3, S4, S0c, **#212** |
| S6 | independent verifier; ADR-016's sync section points here | S5 |

One branch, `fix/adr025-sync-ports`, tracked as V210-34 (#209).

## What each review changed

**Round 1 → 2:**
- tokens;
- local-only conclusions;
- request flags;
- `AWAIT_KEEPER` removed;
- outbound-only slots;
- the proofs rebuilt;
- the false `room_in_session` claim removed;
- options compared.

**Round 2 → 3:**
- option C;
- request capture and consumption;
- position-matched coverage;
- per-peer slot cap;
- the session log;
- citations prefixed by tree.

**Round 3 → 4** (astra, glm-5.3 and kimi-k3, all BLOCK):

| Finding | Reviewers | Change |
|---|---|---|
| A stale result was filtered but never retired, so the port wedged for good | all | D1a: retirement aborts the task and drops the permit exactly once; displaced connections are not deaths |
| The bilateral serve-before-drain deadlock | all | own item V210-39 (#212): concurrent serve and drain; S5 depends on it |
| The held queue was unbounded, could time out correct peers, and was a flood target | all | held queue removed; `INBOUND_PER_PORT = 3`, then an immediate `SessionBusy` with D5 kind `Busy` |
| Zero-progress retries looped forever | all | D3 progress rule; D5 kind `NoProgress`; P10 |
| Coverage as per-position sets was unbounded | astra, glm | interval arithmetic |
| Classes weren't computable: frozen vs unadmitted, "revoked", poison, `NotAdmitted` failing the session | glm, kimi | classes table from real predicates; the `NotAdmitted` split and the continue-instead-of-fail semantics marked as code changes; "revoked" dropped; poison → the port is `poisoned` with no retry |
| Scheduler evaluation points | kimi | D6a |
| `done_gen` not monotonic; `failures` reset; backoff across an epoch; a permanent refuser every 8 s | all | D2 max-credit; D5 reset and clearing; kind `Policy` at 30 s |
| "At most two" understated | glm, kimi | stated per end: 1 out + 3 in |
| S0b couldn't observe the preconditions; a 64-entry log could evict silently | all | S0b derived from the proofs: two sequenced journals with overflow counters and the listed fields |
| P1's justification was not direction-aware; P3's byte leg made only one truncation; P7's and P8's mutants stayed green; the #202 rewrite missed `owed_a_reason` | glm, kimi | each row fixed as described |
| P2's "orientations" was left over from option A | kimi | removed |
| The consent bullet read as today's behaviour | glm, kimi | marked as a planned change against today's room-only keying |
| D6's limit named the wrong case | glm | stated: stalled peers can starve a live one until timeout, and it's not fixed here |
