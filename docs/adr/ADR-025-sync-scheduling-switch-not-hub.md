# ADR-025: Sync Is Scheduled Like a Switch, Not a Hub

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted by the decider, 2026-09-26 (decisions 1–4). **Built on this tree** as V210-34
(#209, closed). The code is:
- `crates/vox-core/src/node/ports.rs`: the port, D1, D4–D6;
- `node/actor.rs`: scheduling, D1a, D2, D6a, D7;
- `log/sync.rs`: coverage and classes, D3;
- `node/channel.rs`: the room generation;
- `node/status.rs`: the S0b counters.

Not built:
- the consent-retry keying in D9 (Planned);
- the proofs for P3, P4, P5 and P7.

The P1 and P10 proofs were deleted with the decider's approval in V210-106 (#301, `233a870a`). P6
asserts what P1 asserted about refusals.

On this tree D3's class set has three more classes from later items: `BodyArrived` (V030-10), and
`Unlinked` and `Refused` (V210-74).
**Date**: 2026-09-26
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: sync, scheduling, node-runtime, latency

## Context

The decider: *"it kind of reminds me of a networking hub vs. a switch — is there something that we can
do that's more intelligent to make it more like a switch instead of a hub, with slots and queues"*.

A sync session reconciles one room's log between two nodes over one QUIC bi-stream. Either end may
open it, and both ends run the same steps:
1. each sends `HELLO`, then `HAVE`, then `WANT`;
2. each serves the other's `WANT`;
3. each drains and applies what it was sent.

The room's lock is held one step at a time (`SessionRoom`), so two sessions on one room interleave
safely. Duplicates are refused idempotently.

Before this ADR, scheduling behaved like a hub:
- two members posting at once each refused the other's session, then retried after a random wait;
- past the slot cap, a due session was skipped, not queued;
- "pushed" meant started, not completed;
- seven maps and a flag answered one question, and disagreed.

Option C, full duplex, removes the collision. It works as in switched Ethernet, TCP simultaneous
open, Yjs `SyncStep1` from both ends, and WireGuard's simultaneous handshakes: it trades a duplicate
reconciliation for having no collision state.

## Requirements

### The decider's decisions (2026-09-26)

- **Decision 1.** The collision MUST be resolved by **option C, full duplex** (D4). The designated
  opener (A) and a glare rule (B) are rejected.
- **Decision 2.** All of it was scheduled for v0.2.10: the defects and the collision redesign.
- **Decision 3.** Observability MUST be simple counters in `vox status --json`, not a sync journal
  (S0b). Proofs MUST assert what a person sees, plus those counters.
- **Decision 4.** The design review loop stopped after round 4. Implementation-level findings are
  settled in the code and checked by the independent verifier, with no further design rounds.

### D1. One port per (room, peer)

- **D1.1.** A node MUST keep one port per (room, peer). A port holds:
  - at most one outbound attempt, and at most `INBOUND_PER_PORT` (3) inbound attempts;
  - its queued state (D6) and its backoff (D5);
  - a `poisoned` flag (D3);
  - its requests and credit (`req_gen`, `req_done`, `done_gen`; D2);
  - its epoch.
- **D1.2.** The ports MUST replace `pushed_to`, `pending_push`, `owed_first`, `push_failures`,
  `syncing`, `syncing_with` and `push_now`.
- **D1.3.** Each room MUST have a **generation**, a `u64` on its state that every stored entry bumps,
  whatever its source. It MUST be read in the same lock acquisition as the `HAVE` frontiers. It is
  in memory: a restart resets it, together with every port.
- **D1.4.** A port **needs a session** iff it is not poisoned, and `room.gen > done_gen` or
  `req_gen > req_done`.
- **D1.5.** Per pair, per end, there MUST be at most 1 outbound session plus `INBOUND_PER_PORT`
  inbound sessions unfinished.

### D1a. Retirement is separate from ignoring a result

- **D1a.1.** Every attempt MUST carry its task's abort handle and its fence. The slot is held by the
  worker until the worker exits, so slots bound running workers.
- **D1a.2.** A port MUST retire an attempt in each of these cases:
  - its connection dies, where a connection that is displaced but still carried is **not** a death;
  - the room changes epoch;
  - the room is poisoned;
  - the node shuts down or locks.
- **D1a.3.** Retiring MUST remove the attempt from the port, retire its fence and abort its task,
  exactly once. A worker already running on a blocking thread MUST stop at its next room step or
  transport operation.
- **D1a.4.** Stores a retired worker made MUST stay: they are durable and idempotent. They MUST
  report themselves through a generation-bump event that is independent of `SyncDone`.
- **D1a.5.** A `SyncDone` for a retired or unknown token MUST change nothing but the `stale` counter.

### D2. Requests and credit

- **D2.1.** A request (`req_gen += 1`) MUST be raised on any of these:
  - a new connection;
  - the tick (D7);
  - new board members;
  - a person's `vox room sync`;
  - a D3 or D5 outcome.
- **D2.2 (V210-58, #246).** A port that needs a session, is not backing off and has no connection to
  its peer MUST reach that peer itself:
  - off the actor;
  - one reach per peer at a time;
  - from the member's known addresses, which are this node's board and peer book;
  - never through a session.

  A failed reach MUST back that peer's unconnected ports off as `Unreachable` (D5). A successful one
  is a new connection.
- **D2.3.** An attempt MUST capture `req_at_start` when it is admitted. A completion D3 calls
  **clean** MUST set `req_done = max(req_done, req_at_start)`. A request raised after an attempt
  started MUST NOT be consumed by it.
- **D2.4.** Credit MUST be monotonic within an epoch: `done_gen = max(done_gen, credit)`.
  - `credit` is `gH`, the generation read with this side's `HAVE`.
  - It is `gH + nP` instead when the attempt newly stored `nP` entries from the peer and, at
    completion in the same epoch, `room.gen == gH + nP`.
  - Duplicates and fork heads are not "newly stored". "Stored" means persisted: credit and the
    generation MUST count only entries the persist step committed.
### D3. Receive coverage, entry classes, and what each side concludes

- **D3.1.** The receiver MUST keep its `WANT` as per-author inclusive intervals, clamped to the
  peer's `HAVE`. For an equal-sequence fork request `(N, N)` it also keeps the advertised head hash.
  Coverage MUST be interval arithmetic, never per-position sets.
- **D3.2.** Each received entry MUST fall in an unfilled position of its author's intervals, and a
  fork request's entry MUST carry the advertised head hash. Anything else is a protocol violation:
  - the session MUST fail with `ProtocolViolation`, which is local only, has no wire code, and resets
    the stream;
  - the entry MUST NOT be stored;
  - the port MUST back off as `NoProgress` (D5).
- **D3.3.** Each received entry MUST be classified from the DAG's predicates:

  | Class | Predicate | Effect |
  |---|---|---|
  | `stored` | accepted and persisted | fills its position |
  | `duplicate` | `Rejected::Duplicate` | fills its position |
  | `fork-handled` | `Rejected::Fork` (the author is frozen) | fills its position; the session continues |
  | `frozen` | `Rejected::Frozen` (split from `NotAdmitted` in `dag.rs`) | fills its position; the session continues |
  | `unadmitted` | `Rejected::NotAdmitted`, or no resolver key | does **not** fill; the session continues |
  | `poisoning` | the room's persist failed | poisons the room |

  "Revoked" is not a class. Consent revocation does not evict an author, and that author's entries
  are stored as normal.
- **D3.4.** At a current `SyncDone`, the port MUST act as follows:

  | This side observed | Port afterwards |
  |---|---|
  | every requested position filled | **clean**: `req_done` and `done_gen` per D2 |
  | some unfilled, with **progress** (≥1 `stored`, a newly admitted author, or a newly filled position) | raises a request |
  | some unfilled, with **no progress** | raises a request **and** enters `NoProgress` backoff |
  | any `unadmitted` | raises a request with `learn_members` first (the outbound setup); no progress → backoff |
  | the room was poisoned | the room's ports retire their attempts and are marked `poisoned`, reported once; **no retry** until the room is reopened, which re-creates its ports |
  | any `stored`, whatever the outcome | every port of the room is evaluated (D6a) |

- **D3.5.** A `frozen` author's ranges MUST be skipped in later `WANT`s for the epoch.
- **D3.6.** A failure MUST return the prefix it committed, in a structured partial outcome.

### D4. Full duplex admission (option C)

- **D4.1.** An inbound session MUST be admitted while the port holds fewer than `INBOUND_PER_PORT`
  (3) inbound attempts.
- **D4.2.** Past that limit, an inbound session MUST be refused at once with `SessionBusy`. It MUST
  never be held. The refused peer treats `SessionBusy` as D5 kind `Busy`.
- **D4.3.** The outbound decision MUST ignore inbound attempts. Both directions run at once.
- **D4.4.** Policy refusals MUST be unchanged by this ADR. So MUST an anchor's adoption and its
  author refresh before the membership check.

### D5. Backoff, by kind, with its own wakeup

- **D5.1.** A failed session MUST put its port in a backoff of one of these kinds:

  | Kind | Entered on | Wait |
  |---|---|---|
  | `Unreachable` | transport failure, stream-open failure, a failed reach (D2.2) | from 200 ms, doubling, cap 8 s |
  | `Busy` | `SessionBusy`; `NotYetMember` (0x0C, #217: an anchor that has not yet admitted a just-joined member) | from 200 ms, doubling, cap 8 s |
  | `NoProgress` | D3's no-progress rows, `ProtocolViolation` | from 1 s, doubling, cap 30 s |
  | `Policy` | `EpochMismatch`, not a member, room not held | 30 s flat |

- **D5.2.** The kinds MUST be exhaustive: every hard-fail path (authentication, feed link, malformed
  frame, unsupported mode, local failure) maps to a kind.
- **D5.3.** Entering backoff MUST arm a `BackoffExpired { room, peer, timer_token }` wakeup. The port
  re-evaluates when it fires, and a stale `timer_token` MUST be ignored.
- **D5.4.** `failures` MUST return to 0 on any completion that made progress. When completions run
  concurrently, progress wins over failure for `failures` and for credit, and a failure's backoff
  MUST NOT cancel a newer attempt.
- **D5.5.** A backoff MUST be cleared by a new epoch, a new connection, or a person's `vox room sync`.
  Ordinary triggers wait it out.
- **D5.6.** The 20–100 ms jitter, `QUICK_PUSH_RETRIES`, the disjoint halves and `PushRetry` MUST NOT
  exist.

### D6. Slots: queued, fair, bounded per peer

- **D6.1.** There MUST be `OUTBOUND_SLOTS` (16) outbound slots, at most `OUTBOUND_PER_PEER` (4) per
  peer. Inbound sessions take none.
- **D6.2.** A port that needs a session and has no slot MUST be queued, never skipped. Queued ports
  are served round-robin across peers and FIFO within a peer. A queued port MUST re-check its need
  when its turn comes, and a port that still needs a session after its turn MUST go to the tail.
- **D6.3. Known limit.** Four stalled peers can occupy all 16 slots until their sessions time out (a
  frame timeout of 20 s, plus the budgets), and a live peer then waits up to that long. Round-robin
  decides admission and does not pre-empt. This is **not fixed**, and no proof claims a bound for it.

### D6a. When ports are evaluated

- **D6a.1.** One deduplicated evaluation pass MUST run at the end of every actor event that can
  change a port's need or a slot:
  - a room generation bump (every port of that room);
  - a request raised;
  - a `SyncDone`;
  - a slot released;
  - `BackoffExpired`;
  - a connection opened or closed;
  - an epoch change;
  - a room opened or poisoned.

  The pass MUST scan every queued port, plus the ports of the room whose event it is. A partial
  apply's forwarding MUST NOT be left to the tick.

### D7. The periodic tick is a safety net

- **D7.1.** Every `SYNC_INTERVAL_SECS` (30 s), the tick MUST raise a request on every shared port.
  No proof MAY pass because of it.

### D8. Epochs and commands

- **D8.1.** A new epoch MUST retire every attempt, set `done_gen = 0`, clear backoff and the
  frozen-skip set, and raise a request.
- **D8.2.** `vox room sync` MUST raise a request on every port of the room and clear its backoff. It
  MUST reply `Done` once a session starts.

### D9. Consent retries (Planned)

- **D9.1 (Planned).** A consent's retry MUST key on (room, target, token). Before this ADR it keyed
  on the room alone.

### S0b. Observability (decision 3)

- **S0b.1.** `vox status --json` MUST report, per (room, peer), these counters: sessions opened,
  admitted, busy-refused, completed, partial, failed (with the last failure's reason), stale,
  skipped at the slot cap, and queued. It MUST also report the current backoff, if any, with its kind.
- **S0b.2.** There MUST be no session journal.

### Proofs

Each proof MUST drive the shipped binary (ADR-018). A proof whose precondition is not shown by the
counters, or by its own setup, MUST fail as CANNOT MEASURE, never pass. A row first written against
the withdrawn journal MUST be restated against counters and timing when its proof is written, and its
mutant MUST still be red. P9 and P10 use a *mutant sender*: a build with vox-core's `mutant-sender`
feature, whose behaviour is chosen with `VOX_MUTANT_SENDER_MODE`. No shipped build MAY carry it
(`package-release.sh` refuses a binary marked `VOX-MUTANT-SENDER`).

| # | Proof | Asserts | Mutant that MUST turn it red | On this tree |
|---|---|---|---|---|
| P1 | `simultaneous_posts_never_collide`: 2 daemons + anchor, 40 synchronised rounds | `busy-refused = 0`; each post read by the other ≤ 250 ms after `vox room post` returns | busy refusal restored at the inbound check | deleted, V210-106 (#301) |
| P2 | `a_burst_past_the_slot_cap_is_queued`: 40 rooms, one post each at once | each post read ≤ 2 s; `queued` rose, `skipped_at_cap` did not | `try_acquire`-or-skip restored | built |
| P3 | `a_long_backlog_catches_up`: (a) 3,000 small entries, (b) 140 × 1 MiB, ≥ 2 partial completions each | the peer holds every entry ≤ 20 s after starting | receive coverage **and** the re-ask after a partial apply removed | not built |
| P4 | `a_refused_entry_is_asked_again`: Carol joins through Alice and posts at once | Bob reads Carol's post ≤ 2 s after the `unadmitted` session ends | the `unadmitted` request removed (the mutant removes the retry itself) | not built |
| P5 | `a_post_after_have_follows` | a post made after a session's `HAVE` arrives ≤ 250 ms after `vox room post` | `done_gen` taken at `SyncDone` instead of `HAVE` | not built |
| P6 | `two_members_posting_at_once_are_never_refused`: 2 members, anchor stopped, 60 rounds | `busy-refused = 0`; every post within its bound | as P1 | built |
| P7 | `a_retired_attempt_frees_its_port`: Bob frozen mid-session, filed dead, a new Bob starts | the new outbound opens ≤ 2 s after the new connection; never two unfinished outbound attempts on one port; the slot occupancy returns to its prior value | retirement removed; **and** the stale-result guard removed | not built (retires by the newcomer probe, not `SILENCE_IS_DEATH`) |
| P8 | `a_backed_off_peer_is_retried_when_due`: Bob down, then back | Alice's own outbound completes clean ≤ 9 s after Bob returns; an `Unreachable` backoff was entered and expired | `BackoffExpired` removed (the backoff is taken with the connection held up) | built |
| P9 | `an_entry_that_was_not_asked_for_is_refused`: mutant sender `serve-unasked` | the session fails with `ProtocolViolation`; the entry is absent from the store and from `vox room read` | the coverage check removed | built |
| P10 | `a_peer_that_serves_nothing_is_paced`: mutant sender `serve-nothing` | ≤ 6 sessions to that peer in 30 s; `NoProgress` backoff entered | the no-progress backoff removed | deleted, V210-106 (#301); the mutant mode remains |
| — | #202's proof, `a_sync_failure_names_its_reason` | a real failure is named on its pair, with no governance or malformed text; no collision is reported between correct members | the governance wrapper; the uninformative code for a room peer | built |
| — | `a_member_relays_what_it_learned` (D1), `a_member_whose_connection_died_is_synced_again` (D2.2), `a_dead_member_does_not_stall_the_room`, R40, `a_new_member_is_seen_promptly` | unchanged | | built |
| — | `two_backlogs_meet` (#212): a bilateral, concurrent-session, shared-connection backlog | both backlogs cross | | built, opt-in |

- **PF-1.** The latency bounds in P1, P5 and P6 MUST hold under normal use: a machine doing ordinary
  work. A red seen only under extreme overload does not block a release (the decider, 2026-09-30).
- **PF-2.** A heavy proof MUST be opt-in and MUST NOT run in every build or CI run (ADR-018).

## Consequences

- Two members posting at once no longer refuse each other. The cost is a duplicate reconciliation,
  about one extra session per simultaneous round.
- A burst past the slot cap waits in a queue instead of waiting for the 30 s tick.
- A faulty peer cannot get unrequested entries stored, and cannot drive a tight retry loop.
- One stalled set of peers can still delay a live one by up to a session timeout (D6.3).

### Fixed since

- The bilateral serve-before-drain deadlock (V210-39, #212) is fixed: serve and drain run
  concurrently (`d700d0a1`, `cf42f553`, merged `39c38841`). Proof: `two_backlogs_meet_proof`.
- The defects in this ADR's scope are fixed by V210-34 (#209):
  - a session skipped at the slot cap (P2);
  - a truncated serve counted as done (D3, the `partial` counter);
  - a failed partial apply that did not wake the room's other peers (D6a);
  - a receiver storing entries it did not ask for (P9);
  - an honest pair retrying zero-progress sessions without pacing (D3/D5).

## Related ADRs

ADR-008 (replicated log and sync), ADR-016 (node runtime; its sync section points here), ADR-018
(proof from the user's vantage).
Prior art: libp2p simultaneous open, BGP (RFC 4271 §6.8), WebRTC perfect negotiation, TCP simultaneous
open (RFC 9293 §3.5), y-protocols, Kubernetes client-go's workqueue, and Cheshire on Nagle/delayed-ACK
(stacked coalescing produces circular waits, so D5.6 deletes the jitter). Persistent streams (EBT,
Hypercore DEP-0010, Willow WGPS) were deferred to v0.3.0 as a new protocol.
