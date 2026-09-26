# ADR-025: Sync Is Scheduled Like a Switch, Not a Hub

**Status**: **Proposed, revision 2 — 2026-09-26.** Not decided and not built.
- Revision 1 (8c4e347) was reviewed by gpt-6-astra (**BLOCK**), glm-5.3 (**REVISE**) and kimi-k3
  (**REVISE**); the transcripts are in [`ADR-025-reviews/`](ADR-025-reviews/).
- Revision 2 answers every finding (see "What the review changed") and replaces revision 1's collision
  rule with a designated opener.
**Date**: 2026-09-26
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: sync, scheduling, node-runtime, latency, wire
**Builds on**: #180 (sessions guarded per room and peer, `fix/180-no-defer` 33da864 + 58fde36) and #202
(`WireError::SessionBusy`, 8436100, accepted). This ADR assumes both are integrated. Code is cited
**from the #180 tree (58fde36)** unless it says otherwise.
**Relates to**: #41 (V29-06; its backoff is what D5 deletes), #200 (V210-27).

## Context

The decider, on the collisions #202 made visible: *"it kind of reminds me of a networking hub vs. a
switch — is there something that we can do that's more intelligent to make it more like a switch
instead of a hub, with slots and queues"*, and *"it's cute that it kind of sort of works but we can do
better"*.

### What a sync session is

A sync session reconciles one room's log between two nodes over one QUIC bi-stream, and **either end
may open it**. Both ends run the same steps (`log/sync.rs` `frontier_session_room_inner`, 869–922):
1. each sends `HELLO`, then `HAVE` (its frontiers), then `WANT` (what it lacks of the other's `HAVE`);
2. each serves the other's `WANT` and finishes its send side (`t.finish()`, 893);
3. each drains and applies what it is sent (896–916).

So one session moves entries **both ways**. The room's lock is taken one step at a time, never across
the network (`SessionRoom`, `ChannelState::sync_over_room`).

Two limits matter below:
- **Serving stops silently at a bound.** `entries_for_wants` stops at `MAX_SERVE_ENTRIES` (1,024) or
  `MAX_SERVE_BYTES` (64 MiB) (501–506), and the serve loop stops at `SERVE_BUDGET` (30 s) (888–890).
  In both cases the session still ends `Ok`, and `SyncOutcome` (`node/channel.rs` 211–219) says
  nothing about it. The rule so far has been "applied something ⇒ sync again at once" (sync.rs 43–48,
  riding `o.applied > 0`).
- **A side's success says nothing about the other's apply.** Each side finishes sending *before* it
  applies what it received. So Alice can finish cleanly while Bob is still applying what she sent, and
  Bob may then refuse an entry (an author he hasn't admitted yet: `AuthenticatorInvalid`, sync.rs 611)
  or fail to persist. Alice never learns of it; only Bob knows.

### Where scheduling behaves like a hub

1. **Glare, then random backoff (CSMA/CD).**
   - **How it happens.** A local append makes every peer due (`note_local_append`, `run_due_syncs`),
     and the push goes out at once. When Alice and Bob post within a round trip, each opens a session
     to the other. Each end's responder finds its own session with that peer running
     (`run_sync_session`, `in_session_with`) and refuses it (`SessionBusy` after #202).
   - **What it costs.** Both sessions fail. The `SyncDone` handler re-owes the push after a random
     20–100 ms (`QUICK_PUSH_RETRIES = 3`), and past three failures it backs off to
     `MAX_PUSH_RETRY_WAIT` (8 s) with the ends drawing from disjoint halves by fingerprint (#41,
     b6545e5).
   - **Measured** (harness outputs from vox-0e's instrumented runs and #202's proof, not reproducible
     from the trees alone):
     - #202's proof: 35–47 collisions in 40 simultaneous rounds.
     - Before #180, on main, with 3 members and an anchor: 1,397 refusals in 40 rounds, with streaks of
       5–7.
     - **With #180 underneath** (5 interleaved runs per arm, 300 rounds each): #180 alone had 0 late
       posts, slowest 0.30 s, 703 refusals, longest streak 3. #180 plus b6545e5 had 0 late, 0.25 s,
       702 refusals, streak 3.
   - **So on the trees v0.2.10 ships, this is waste and randomness, not lost messages:** about 2.3
     refused streams per simultaneous round, and a delivery time set by a random wait rather than by
     one session.
2. **Skipped, not queued: a real 30 s defect.** `sync_one` takes one of `SYNCS_IN_FLIGHT = 16` slots
   with `try_acquire`, and past the cap returns `false` (5010–5011).
   - **Why it's lost.** The skipped pair is not added to `owed`, and the peer's schedule is marked
     synced anyway (`note_synced`, 4920–4921). `due()` then gates every later pass
     (`syncstream.rs` 102–113).
   - **What doesn't rescue it.** The `SyncDone` re-arm only sets `push_now`, which still hits `due()`.
     Unless a new append or a `PushRetry` happens to re-mark that peer, **the skipped push waits for
     the 30 s interval**. All three reviewers confirmed this.
   - **What the code argues.** It defends the skip: *"a queue of sessions for rooms whose state has
     since moved on is worse than none"* (actor.rs 237–239). That is true of a queue of *sessions*.
     D6 queues *ports*: a port that has become clean by the time a slot frees never opens.
3. **"Pushed" means started.** `run_due_syncs` counts a push as done when its session starts
   (actor.rs 4970–4971: *"Known and not fixed here"*).
   - **Today, the paths that rescue it:** a failed session re-owes it (`PushRetry`), and an append
     during a session is caught by the in-session check and re-armed at `SyncDone`.
   - **What's left** is the accounting window between a session's start and its failure, and
     truncated serves (above), which count as done.
4. **Seven maps for one question.** Whether room *R* is owed to peer *P* is spread across
   `schedules`, `pending_push`, `pushed_to`, `owed_first`, `push_failures`, `syncing` and #202's
   `syncing_with`, plus the `push_now` flag. Several comments at those sites record defects that came
   from the maps disagreeing (4922–4935, 4963–4968, 3406–3413).

## Prior art

Researched 2026-09-26; primary sources linked, and items marked *(unverified)* were not line-read.

**Collide, then retry at random: today's behaviour.**
- SIP glare (RFC 3261 §14, `491 Request Pending`) *(unverified against the RFC text)*.
- libp2p simultaneous open's random coin toss
  ([simopen.md](https://github.com/libp2p/specs/blob/master/connections/simopen.md)).
- Wi-Fi RTS/CTS.

**A deterministic rule, decided before any collision.**
- BGP ([RFC 4271 §6.8](https://www.rfc-editor.org/rfc/rfc4271.html)) keeps the connection opened by
  the higher identifier. FRR mis-wired it over IPv6 ([FRR#1219](https://github.com/FRRouting/frr/issues/1219)).
- WebRTC *perfect negotiation* ([Mozilla](https://blog.mozilla.org/webrtc/perfect-negotiation-in-webrtc/))
  uses a pre-agreed polite and impolite peer. It holds only if both compute the roles identically.
- `iroh-persistent` ([ppetr/iroh-persistent](https://github.com/ppetr/iroh-persistent)) is Rust over
  QUIC, like Vox, and solves our exact collision by EndpointId ordering.
- Vox already keeps the pairwise session opened by the lower fingerprint (`incoming_session_wins`,
  ADR-021 F12).
- **The pitfall:** go-libp2p decided dial dedup by *timing*, and closed connections that should have
  survived ([go-libp2p-swarm#79](https://github.com/libp2p/go-libp2p-swarm/issues/79)).

**A dirty flag, re-queued once.** Kubernetes client-go's workqueue
([queue.go](https://github.com/kubernetes/client-go/blob/master/util/workqueue/queue.go)): an `Add`
while a key is processing marks it dirty, and `Done` re-queues it exactly once. Go's `singleflight`
forgets the key when the call ends, so it has no rerun-once rule.

**Persistent streams: the full switch, deferred.**
- Scuttlebutt EBT, Hypercore ([DEP-0010](https://www.datprotocol.com/deps/0010-wire-protocol/)), Yjs
  (a symmetric `SyncStep1` from both ends) and Willow WGPS
  ([spec](https://willowprotocol.org/specs/sync/index.html)) all keep one long-lived stream.
- Their bugs are the costs: EBT replication stalls ([ssb-ebt#77](https://github.com/ssbc/ssb-ebt/issues/77),
  [#61](https://github.com/ssbc/ssb-ebt/issues/61)); stale per-peer state in automerge-repo
  ([#742](https://github.com/automerge/automerge-repo/pull/742),
  [#763](https://github.com/automerge/automerge-repo/pull/763)); a dead connection blocking its
  replacement in Syncthing ([#9337](https://github.com/syncthing/syncthing/issues/9337)).
- Short-lived sessions are not immune to their own versions of these. The code records a
  permanent running-marker wedge (actor.rs 5060–5063), and dead connections blocking replacements
  (`node/net.rs` 727–744). The persistent stream is deferred because it is a new protocol and a
  feature, not because per-event sessions are free of these bug classes.

**Where prior art does not transfer.**
- TCP's simultaneous open ([RFC 9293 §3.5](https://www.rfc-editor.org/rfc/rfc9293.html)) merges for
  free because a connection *is* its 4-tuple; a Vox session carries a reconciliation.
- WireGuard tolerates double handshakes because they're cheap.
- Credit-based flow control doesn't stop two ends opening at once.
- **Stacked coalescing mechanisms produce circular waits** (Cheshire's Nagle/delayed-ACK paper,
  [link](https://www.stuartcheshire.org/papers/NagleDelayedAck/)). That is why D5 deletes the jitter
  rather than layering a new rule over it.

## Options for the collision (the decider's choice)

| | **A. Designated opener** (recommended) | B. Glare rule (revision 1's D4) | C. Accept both |
|---|---|---|---|
| Who opens a session for (room, pair) | only the **lower** fingerprint; the higher sends `SYNC_NOTIFY` | either; on glare the lower's is kept, the higher's is refused | either; neither refuses |
| Collisions | **impossible by construction** | one refused stream per glare | none refused; two sessions run |
| Sessions per pair at once | **exactly one** | up to two briefly (the refused outbound and the accepted inbound) | two on glare |
| State the port needs | `Idle / Queued / Running` (lower); `Idle / Serving` (higher) | inbound and outbound held together, session tokens, `Awaiting` with a deadline, stale-refusal rows (all three reviews) | a session count, and attribution for two `SyncDone`s per pair |
| Timers | **none** except the 30 s tick | `AWAIT_KEEPER` (measured from arrival, not completion) | none |
| Wire change | **one new stream kind** (`SYNC_NOTIFY`; no compatibility is needed) | none | none |
| Latency cost | a higher-fingerprint member's post waits one extra one-way trip (the notify), e.g. ~20 ms relayed | none | none |
| Bytes cost | a 40-byte notify | a refused stream per glare | a duplicate reconciliation per glare |

**Recommended: A.** It is the only option in which a collision cannot happen at all. That is the
switch: one port owner, one session at a time, no collision domain.
- **The cost is real but small.** Posts from the higher-fingerprint member take one extra one-way
  trip, tens of milliseconds even relayed, against PRD-001 R40's 1 s.
- **It deletes the hardest part of B**, where all three reviews found holes: two streams for one pair,
  `SyncDone` attribution, stale refusals, and a deadline whose meaning (arrival or completion) was
  wrong.
- **C** is the smallest code change, but it keeps the duplicate work, and it still needs attribution
  of two `SyncDone`s per pair.

The rest of this Decision assumes A. D1–D3 and D5–D7 hold under B or C as well.

## Decision (proposed)

### D1. One port per (room, peer), owned by the actor

```text
struct Port {
    role:       Opener | Notifier,        // lower fingerprint (network identity) opens
    state:      Idle | Queued { since } | Running { token, gen_at_have: Option<u64> } | Backoff { until, failures },
    owed:       bool,                     // the explicit request flag (D2)
    done_gen:   u64,                      // room generation this peer is known to be current with
    epoch:      u64,
}
```

- **`ports: BTreeMap<(room, peer), Port>`** replaces `pushed_to`, `pending_push`, `owed_first`,
  `push_failures`, `syncing`, `syncing_with` and `push_now`.
- **`schedules` stays** only to raise the periodic tick and connect triggers, and those only mark
  ports owed.
- **Roles use the authenticated network identity** (the comparison #41 already makes, actor.rs 3447),
  never a profile lookup.

A room gets a **content generation**, a `u64` that increases whenever the room stores an entry from
any source.
- It is read in **the same lock acquisition** as the frontiers the session sends in `HAVE`
  (`SessionRoom::frontiers` returns both), so it never credits an append that the `HAVE` did not
  contain.
- A new epoch resets every port for the room to owed.

A port **needs a session** when any of these holds:
- `room.gen > done_gen`: this node has something the peer may lack;
- `owed`: someone asked (connect, the tick, a notify, a person's `vox room sync`, new board members,
  a failed or incomplete session). The flag exists because an unchanged generation can still need
  reconciliation, which revision 1 missed.

### D2. Triggers mark ports; only the scheduler opens sessions

A local post, a stored entry from any session (including a session that then **fails**), a connect,
the tick, new members, and `vox room sync` each only bump the generation or set `owed`.

Then, for a port that needs a session:
- **as `Opener`:** the port is queued, and the scheduler (D6) opens it;
- **as `Notifier`:** the node sends `SYNC_NOTIFY { room, epoch }` on a unidirectional stream, **once
  per change of need**. It sends no second notify while one is outstanding and no session has started
  since.

A port that is `Running` just records the need; the need is re-evaluated at that session's `SyncDone`.
This is the workqueue rule: any number of triggers during a session become exactly one follow-up.

**Entries applied from peer P don't re-owe P** (glm-5.3's answer to revision 1's open question 2).
After a session with P that applied *n* entries, P's `done_gen` advances by the generation those
applies produced, provided nothing else bumped the room meanwhile. If something did, P is simply owed:
one idempotent session.

### D3. What a port may conclude from a session, **on its own side only**

No side ever concludes that the peer *applied* anything: it cannot see that (see Context). Each side
decides only what it can observe, and **the side that sees a problem is the side that asks again**.
Under A, asking again means opening (lower) or notifying (higher), so nothing waits on the other end.

At `SyncDone`, on this node's side:

| This side observed | Port afterwards |
|---|---|
| session ended `Ok`, **and** every entry this side `WANT`ed arrived (the count received equals the count its `WANT` ranges named, clamped to the peer's `HAVE`), **and** its applies all succeeded | `done_gen = gen_at_have`; still needs a session if `room.gen > done_gen` (something was stored after this side's `HAVE`), and then queues or notifies **at once** |
| fewer entries arrived than it `WANT`ed (the peer's serve hit `MAX_SERVE_*` or `SERVE_BUDGET`) | `owed`: the rest is fetched at once. This is the truncation flag revision 1 lacked. It is observable on the receiving side, with no wire change |
| an apply failed, or refused an entry, or the session failed | `owed`, with D5's backoff if it is a real failure; `done_gen` unchanged |
| the session stored some entries and then failed | as above, **and** the stored entries bumped the generation, so every *other* port for the room needs a session (astra's partial-apply finding) |

Entries refused because they can never be accepted (an author revoked in this epoch) count as
received, so a permanent refusal is not retried forever. An author that is merely **not admitted yet**
is `owed` with backoff, and `learn_members` runs first on the retry.

**Why this closes the case revision 1 had open.** Alice (opener) serves Bob entries from an author Bob
hasn't admitted.
1. Bob refuses them, and Alice ends `Ok`.
2. Bob's port for Alice is now `owed`. Bob is the notifier, so he sends `SYNC_NOTIFY`.
3. Alice runs another session, and Bob runs `learn_members` before applying.

The retry is driven by the side that saw the failure, within milliseconds; nobody waits for the 30 s
tick.

### D4. The designated opener (option A)

For each (room, peer), **only the lower network identity opens sync streams.**

**The higher end:**
- **never opens a sync stream** for that room to that peer. It sends `SYNC_NOTIFY`, a new stream kind:
  one unidirectional stream carrying `{channel_id, epoch}`, and nothing comes back;
- **serves the inbound session** as today.

**The lower end, on a `SYNC_NOTIFY`:**
- checks `may_sync` (the same membership rule as an inbound session);
- if that passes, sets the port `owed`;
- if not, **silently drops it**. There is no reply, so a notify is no oracle for whether this node
  holds a room (#202's probe concern).

Notifies coalesce into the one flag, so a member that floods notifies costs at most one session per
port at a time.

**Reliability, without a timer.**
- A notify rides a QUIC reliable stream. On a live connection it arrives or the connection dies.
- If the connection dies, reconnecting marks every shared port `owed` (the connect trigger), and the
  sessions start from there.
- The remaining gap is a bug that swallows a notify. The 30 s tick (D7) covers it, and it is the reason
  the tick stays.
- EBT's lesson (a long-lived channel still needs a reliable "there is news") is met by construction.
  The "news" is a fresh stream every time, so no stale per-peer state carries across a reconnect.

**Inbound sync streams from a peer that should not open them** (a higher fingerprint opening to a
lower one) are refused with `SessionBusy`'s neighbour, a new code `WrongOpener` (0x0C), and reported
as a defect. A correct node never sends one.

**A person's `vox room sync`, or a consent's retry, on the higher end.**
- It sends the notify.
- It is answered from the `SyncDone` of the inbound session that follows, which `start_session`
  already reports.
- If no session arrives within the command's own patience (today's `Sync` reply bound), it answers
  `Unreachable`, as a failed open does today.

**Restart under the same identity.** The restarted node has no port state. The connect trigger marks
all of its ports owed. Its old session on the other end dies when the dead connection is filed
(restart-probe, 582f18a), and that end's `SyncDone` for the old token is ignored (D1 tokens: a
`SyncDone` whose token is not the port's current one changes nothing).

### D5. Backoff is only for real failures

`Backoff` is entered only by a real failure:
- `Unreachable` or a transport failure;
- `EpochMismatch` or a policy refusal;
- an author not yet admitted.

It keeps #41's growth to `MAX_PUSH_RETRY_WAIT` (8 s). **Deleted:** the jittered quick retries,
`QUICK_PUSH_RETRIES`, the disjoint-halves rule and the `PushRetry` event. Under A nothing collides, so
there is nothing to desynchronise. A trigger never bypasses an active backoff; a person's
`vox room sync` does.

### D6. Queued ports, not skipped sessions: a fair scheduler

- **The 16 slots stay, for outbound sessions only.** Inbound sessions take no slot (as today:
  `start_session` never acquires one), so two nodes cannot fill each other's slots and deadlock
  (astra).
- **A queued port waits in FIFO order** of when it became queued. **After each session, a port that
  still needs one goes to the tail**, not back to its original place, so a perpetually dirty port
  cannot starve later ones.
- **A queued port re-checks its need when its turn comes** and does not open if it has become clean.
  That answers the code's own objection to a queue.

### D7. The periodic tick is a safety net, not a delivery path

`SYNC_INTERVAL_SECS` (30 s) stays. Each tick sets `owed` on every shared port. No proof may pass
*because of* the tick: every delivery bound below is far under 30 s.

### Reporting

`vox status --json` gains, per room and peer:
- sessions opened, served, completed, truncated and failed;
- notifies sent and received;
- `WrongOpener` refusals.

`SyncFailed` (#202) stays for real failures. A `WrongOpener` refusal is reported as a defect.

## Scope and release

**Proposed: v0.2.10; the decider decides.**
- **Defects in shipped code, which belong in v0.2.10 under the every-known-defect rule:**
  - item 2's 30 s skip (D6);
  - a truncated serve that is counted as done (D3's receive-side completeness);
  - a partial apply that fails and doesn't wake the other ports (D3).
- **The collision behaviour (D4, D5) is an improvement to something that works with #180**: 0 late
  posts in 600 rounds. It removes ~2.3 wasted streams per simultaneous round and the random wait. That
  is the decider's *"we can do better"*, and whether it goes in v0.2.10 is the decider's call.
- **Why together.** The port (D1–D3) is what the defect fixes need. Building it while keeping the
  jitter and `PushRetry` alive inside it would be the stacked-mechanism trap the prior art warns
  about.
- The persistent stream stays a v0.3.0 candidate.

## Proof (real binaries only; each prints its counts; timing runs take the timing lock)

"Red on the base" means red on the #180+#202 tree without this ADR. S0b lands first, so each proof's
counters exist on the base too.

| # | Proof | Asserts (all through the shipped binary's output) | Red on the base? | Mutant that must turn it red |
|---|---|---|---|---|
| P1 | `a_collision_is_impossible_proof`: 2 daemons + anchor, 40 barrier-synchronised rounds of simultaneous posts | every post read by the other within 250 ms of `vox room post` returning (p100, loopback, one host); per pair, **sessions opened ≤ rounds + 2** and **refused-busy = 0**; opened = completed + failed at the end (quiescence) | yes: refusals > 0 | today's both-ends-open (refusals > 0); **accept-both** (sessions ≈ 2× rounds, over the bound) |
| P2 | `a_skipped_push_is_queued_proof`: 24 rooms shared by 2 members; **only Alice posts**, once in each room at once, in both fingerprint orientations | every post read by Bob within 2 s; no port waits for the tick | **yes: ~30 s** (single-direction posting removes the `PushRetry` rescue kimi-k3 found) | `try_acquire`-or-skip restored |
| P3 | `a_long_backlog_catches_up_proof`: Bob offline while Alice posts 3,000 entries (> 2 × `MAX_SERVE_ENTRIES`), then Bob starts | Bob holds all 3,000 within 10 s of starting; `truncated` ≥ 2 | to be measured; the base may pass via `applied > 0` | D3's receive-side completeness **and** the `applied > 0` re-owe both removed |
| P4 | `a_refused_entry_is_asked_for_again_proof`: Carol joins through Alice; Alice immediately serves Bob a post of Carol's before Bob admits Carol | Bob reads Carol's post within 2 s, the tick excluded | to be measured | the refusing side's `owed` removed (D3 row 3) |
| P5 | `a_post_after_have_follows_proof`: many posts during one session | every post arrives within 250 ms of its `vox room post` | **no**: the base passes via `pending_push`. It is **a mutant guard only**, and says so | `done_gen` set at `SyncDone` instead of at `HAVE` |
| P6 | vox-0e's gate (`test/two-member-collisions` 3bb6ca1): 2 members, anchor stopped, 60 rounds | every post within its bound; **refused-busy = 0** | yes (702–703 refusals per 300 rounds) | both-ends-open restored |
| P7 | `a_restarted_peer_resumes_its_ports_proof`: Bob killed by PID mid-session, restarted under the same identity | posts in both directions within 2 s of Bob's restart; no stale-token change (the counters stay consistent) | to be measured | tokens ignored (a stale `SyncDone` clears the current port) |
| — | existing: `a_dead_member_does_not_stall_the_room`, R40 relayed and direct, `a_new_member_is_seen_promptly`, #202's proof **rewritten** (with no collisions left, it forces a real failure, an anchor that keeps no log, and asserts the reason) | unchanged bounds | — | — |

**Not provable by real use, and said so:** a notify swallowed by a bug on a live connection. The tick
covers it; no proof pretends to force it.

## Plan

| Step | Work | Depends on |
|---|---|---|
| S0 | #180 and #202 integrated into `integrate/v0.2.10` | — |
| S0b | `vox status --json` per-(room, peer) counters (Reporting above); vox-0e offered to own this and P6 | S0 |
| S1 | Room generation read with the frontiers; `SyncOutcome` gains `gen_at_have`, the received-vs-`WANT`ed count and the applied count; partial applies are reported | S0 |
| S2 | `Port` and `ports`, with tokens; the seven maps and `push_now` migrated into it; triggers only mark (D1–D3) | S1 |
| S3 | `SYNC_NOTIFY` stream kind and the opener rule; `WrongOpener` (0x0C); jitter, `QUICK_PUSH_RETRIES` and `PushRetry` deleted (D4, D5) | S2 |
| S4 | FIFO scheduler with requeue-at-tail (D6) | S2 |
| S5 | P1–P7 red-first where the table says so; each mutant red; existing proofs re-run | S3, S4 |
| S6 | Independent verifier; ADR-016's sync-scheduling section points here | S5 |

One branch, `fix/adr025-sync-ports`, off `integrate/v0.2.10` after S0. Tracked as one v0.2.10 item
(V210-34) with S0b–S6 as its checklist; P2's defect alone could land first if the decider wants it
split.

## What the review changed (revision 1 → 2)

| Finding | Reviewers | Change |
|---|---|---|
| D4's port couldn't represent two streams per pair; `SyncDone` had no attribution; stale refusals | astra, glm, kimi | Option A removes the second stream; tokens on every session; B kept as an option with the table's costs |
| D3 claimed delivery it couldn't observe (truncation, the peer's apply after FIN, partial applies) | all three | D3 now decides only on this side's observations; receive-side completeness; the refusing side asks again; partial applies wake the other ports |
| The generation alone couldn't encode connect, tick and new-member triggers | astra | explicit `owed` flag |
| `AWAIT_KEEPER` measured completion; 2 s unsupported | astra, glm, kimi | gone: no deadline exists under A |
| Slots: inbound-plus-outbound deadlock risk; FIFO starvation | astra | outbound-only slots; requeue at the tail; re-check need at the turn |
| P1 green on accept-both; P3 green on the base; P4 tested the wrong pair; P5 not red on the base; P6 contradicted D4 | all three | table rebuilt: session-count bound, single-direction P2, P4 replaced, P5 labelled a mutant guard, P6 consistent with A; truncation, refused-entry and restart proofs added |
| False claim: #180 keeps `room_in_session` | all three | removed. 58fde36 deleted it, and D6 no longer mentions it |
| Claim 1 cited the room-keyed tree; claim 3 overstated; "never refuse each other" overstated | glm, kimi | citations now from 58fde36; claim 3 restated; refusals for epoch and membership remain and go to backoff |
| Designated opener and accept-both weren't argued | astra, glm, kimi | Options table |
| The code's own defence of skipping was quoted selectively | glm | quoted in full and answered |
