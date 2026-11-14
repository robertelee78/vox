# ADR-046: Sync Always Makes Progress

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted (2026-11-13) as the design for v0.4.31; its acceptance is owed: no sync
change is built until the replacement prototype passes every B3 assertion (build-list B38). The
fifteenth independent review by GPT-6.1-Sol passed revision 16 with no P1 under the decider's
ledger row 83, under his authorization of 2026-11-13 ("post review can accept them too");
**revision 16 is the accepted text**; proposed 2026-11-12. This is design acceptance only:
nothing in it is built, every change is written as what is to be done, and implementation,
acceptance and delivery are recorded on the source-bound issues, separately from decision
status. Revision 16, 2026-11-14,
after fourteen independent reviews by GPT-6.1-Sol (`adr-046-sol-review.md` to
`adr-046-sol-review-14.md`), the decider's rows 82 and 83 and Main's row 82b (two
lanes), cycle 5a's design gap (`arm-replace.md`), the round-2 prototype measurement (`arm-replace.md`,
FAILS the decisive case on one assertion; `arm-replace-next.md`), the decider's ruling
on SY-28 (ledger row 76), the decider's rulings of 2026-11-13 (ledger rows 18, 19,
26, 27, 32, 34, 37–40, 49, 51–53, 55, 57–59, 61–65, 68) and the deciding round's two final
reports; the "Review record" section lists each finding of every review and
the requirement that answers it. Requirements changed in revision 2 are marked *(changed)*, in
revision 3 *(changed r3)*, in revision 4 *(changed r4)*, in revision 5 *(changed r5)*, in
revision 6 *(changed r6)*, in revision 7 *(changed r7)*, in revision 8 *(changed r8)*, in
revision 9 *(changed r9)*, in revision 10 *(changed r10)*, in revision 11 *(changed r11)*, in
revision 12 *(changed r12)*, in revision 13 *(changed r13)*, in revision 14 *(changed r14)*, in
revision 15 *(changed r15)*, in revision 16 *(changed r16)*; SY-24 to SY-30 are new since
revision 1. **Receipts**: the Mac rebooted on 2026-11-13
and cleared `/tmp` and `/private/tmp`; every receipt this ADR cites under those paths is lost
(marked †): the figure stands as recorded in the named report, and the run is to be repeated as
the fleet baseline (ledger row 64). New receipts go to `/opt/vox-evidence/v0431/<agent>/<run>/`.
**Date**: 2026-11-12
**Deciders**: Robert E. Lee
**Tags**: sync, history, late join, governance, wire, scheduling, store, status
**Related**: ADR-005, ADR-006, ADR-007, ADR-008, ADR-018, ADR-023, ADR-025, ADR-034, ADR-036,
ADR-037, ADR-038, ADR-040, ADR-042, ADR-044, ADR-045, ADR-047, ADR-048 (trust containment),
ADR-049 (leaving and ending rooms), ADR-050 (the turn journal)
**Inputs**: the v0.4.31 fix list (items 1–14, 83, 85–87); plan A of 2026-11-12 and its receipts
(`/tmp/plan-sync/runs/`†); the sync trial (`/tmp/trial-sync/runs/`†); the root-cause reports
RcaFrozen, RcaWedge, RcaKeys, RcaSlow and RcaSchedStall (`/tmp/RcaSchedStall/receipts/`†); the IO
repair drill; the consolidated analysis of 2026-11-12; plans B, C, D and G; the operator's
evidence under `/private/tmp/vox-rca/`†; ADR-045 E-1 (the slow path on the release asset). Code is
cited at tag v0.4.30 (`8d71ab337`). The decider's rule for this release: every known defect is
fixed in it (AGENTS.md, "Releases").
**Requirement ids**: `SY-1` … `SY-26`. The prefix `SP-` is taken (ADR-024 SP-1–SP-5), so this
ADR uses `SY-`.

> **Read this first.** The decider chose on 2026-11-13: **the replacement** (R2, per-author
> range reconciliation, §3) is the mechanism; "add the two missing parts, then measure your room's
> shape again before anything else is built on it" (ledger row 57). The repair route (R1) is the
> recorded alternative, with the measured reason it was not chosen. He also stated the intent the
> whole design is tested against (row 63): a newcomer takes **the most recent chunk and has
> access at once**; older chunks come **just in time when a person scrolls up**; nothing makes a
> newcomer walk from message one. That intent is **SY-27**, first among the requirements, and
> every other requirement is tested against it there. The two missing parts are built on the
> replace arm's worktree and the measurement is running; its results land in SY-27's named places
> (the next revision). **Nothing else is built on sync until that measurement is in.** He
> answered Q7 and Q8 on the reviewer-verified cost statement (ledger row 68): the fence post
> stays, knowing that cost; while the creator is away newcomers start from the last fence post
> and their catch-up grows with what was posted since, nobody else signs, and status shows the
> fence's age. No question is open for him in this revision.
>
**Rulings recorded** (the decider, 2026-11-12):

- On the sync proof records: "no need to keep anything like this".
- On what the store holds: "we need to store only what we need".
- No fix without a reproduced root cause (ADR-045 R-5; the consolidated analysis §3.8: "already
  ruled").
- No minimal or partial release: "minimal continues the shit cascade" (ADR-045 R-1). v0.4.31
  ships every item of the fix list, or it does not ship.

Standing rulings this ADR relies on: v0.4.x keeps no prior-release compatibility (AGENTS.md,
"Releases"); the decider, 2026-11-13: **all machines move to 0.4.31 together, with no
mixed-version sync** (ledger row 18; this answers the cutover question revision 2 left open as
Q4), and the whole release gate for a candidate fits in 8–10 hours of wall clock (row 19), so
every in-tree act of this ADR is bounded in minutes and says so; the operator's machines are
updated only on his explicit go (AGENTS.md, "The operator's machines").

## Context

### What the operator saw

On 2026-11-12 the operator ran agents on four machines in the room `repo-to-cve`, about 4,400
entries from a dozen nodes. Agents posted and stepped their Sessions every second or two.

- **A newcomer cut off for three hours.** The node omp-io (four nodes on one daemon, on IO)
  joined at 19:36:38Z through robert-work's link. Until about 22:30Z it held 65 to 97 of the
  room's log entries (70 at 20:04Z, 76 at 20:27Z; `io/status-omp-io-200453Z.json`,
  `io/status-omp-io-202732Z.json`) and showed only its own 5 to 14 rows. Its governance revision
  stayed at 44 while the members were at 56–57. Its `vox agent doctor` said of each of the six
  members "you trust it, but it has not trusted you: it cannot read you"
  (`io/doctor-omp-io-203050Z.txt:17-28`), while each member's doctor said "you trust each other".
  The members held omp-io's headers through 34 and showed none of its posts. `vox status` on
  omp-io said `healthy: nothing needs attention` and `last sync 1s ago` (ADR-042 owns that half).
- **A rebuilt node stalled.** A fresh omp-io joined at 22:23:01Z. At 22:38:53Z it was at
  governance revision 51 against the Mac's 155, held 73 log entries against 4,932, and showed 0
  rows (`io/newnode-watch2-223448Z.tsv`).
- **Per-peer failures that meant nothing to him**: `the peer refused: transport failed`,
  `history frame deadline elapsed`, `quic stream: closed before the frame was written`,
  `malformed identity bundle: inclusion header is absent`, `the peer was busy syncing this room`.
- **Commands that did not help**: `vox room read --history newest` and `--history resume` said
  "one bounded history quantum is queued" and never moved; two daemon restarts did not cure the
  node; only a quiet room sometimes did.

Fix-list items 1–14 are the sync half of that day. Each is listed below with what a person saw.
Items 85, 86 and 87 (a personal node that stops starting rounds while its sibling on the same
daemon syncs; a leave that fails on such a node) came a day later and are this ADR's too: their
root cause is under SY-24.

### What the runs show

Plan A ran the operator's shape on scratch nodes with traces added (build `vox-plan` = trial +
traces; build `vox-reach` = trial + traces + a 5-line prototype that keeps the live window's floor;
receipts `/tmp/plan-sync/runs/<run>/`†). The rig shapes are defined under Terms. Times are seconds
after the newcomer's join. **Every "never" in a hello column of a B3 row measured before
2026-11-13 is unreliable**: the rig's room reader parsed the paging footer from stdout while the
product prints it on stderr (`room_cli.rs:1993`), so it never paged and only the newest 200
rows were searched, which three authors at 1/s fill in about 66 s (`arm-repair.md`, the
apparatus defect). Entry counts, governance and store numbers are unaffected.

| run | build | every member's hello on n-new | heavy authors' live posts (y1 / z1 / n-old1) | governance equal | n-new entries | W store |
|---|---|---|---|---|---|---|
| B3-plan | trial + traces | unreliable (the rig read only the newest 200 rows; two quiet joiners' seen) | unreliable | 205 s | 3 | 93 MB |
| B3-reach | trial + traces + reach | unreliable (four quiet joiners' seen at 31–101 s) | unreliable / 187 s / 167 s | not in 300 s (63 vs 68) | 229 | 201 MB |
| B2-reach | same | 108.5 s (the slow member's own) | n/a | 72.3 s | — | — |
| B1-reach | same | 36.8 s | 27.8 / 27.8 s | 23.8 s | 628 | 201 MB |

What the traces say (`runs/B3-plan/logs/*.rca`, `runs/B3-reach/*/rca.log`, `analysis.txt`):

1. In 115 s the newcomer made 2,428 wire exchanges and fetched 7 bodies: 1,054 proofs,
   418 inventories, 357 headers, 130 contexts.
2. The proofs were a header-by-header walk down the heavy authors' feeds. The earlier late joiners'
   grant entries name (in `seen`) the members' positions at the time they joined, about 250
   positions below the newcomer's window. Admitting a grant demanded a proof for each named
   position. Up to five flows walked at once, one per peer that had passed on the hint.
3. The live window dropped positions: 31 `window-cut` lines on the newcomer in 115 s, each
   dropping positions that were never asked for again. With the floor kept (`vox-reach`), 0 cuts.
4. `the peer refused: transport failed` was the other side cancelling its own request.
5. A heavy author's actor held inbound sync requests for up to 12.0–15.7 s before serving.
6. The scheduler spun: 525 flow starts a second and 37,604 reroutes across six nodes in 429 s.

### Root causes at v0.4.30, item by item

Status words: **KNOWN** = read in code and reproduced on a build that ran, with the run named;
**INFERRED** = fits the evidence, not isolated; **UNKNOWN** = not explained, with the experiment
that settles it. Paths are under `crates/vox-core/src/` unless written in full. "Not caught
because" names only what is particular to the item; the common reason follows this list.

**Item 1. A fetch is replaced by a newer head before it brings home an entry.**
- *Seen*: a reader holding 3 of 487 entries after 150 s; a newcomer frozen in 9 of 9 runs.
- *Cause*: three replacement sites in `node/actor/bounded_sync.rs`: the parked-waiter supersede
  (`:1553-1560`), the slice-boundary supersede (`:4108-4121`) and the hint-turn preempt timer
  (`:5653-5664`), all keyed on `HINT_TURN` = 1 s (`:18`). A fetch needs at least four exchanges
  (head, header, inventory, proof) before its first body, so a peer slower than about 250 ms an
  exchange never delivers. Put there by ADR-036 H-7's coalescing rule and its "owner's turn"
  (`ADR-036-…md:705-734`), which bounds a fetch's turn by wall time, not by progress.
- *Status*: KNOWN. `/tmp/rca-RcaWedge/runs/rca-direct-serve300`†; cure measured by the trial
  (`/tmp/trial-sync/runs/B1-trial`†, `B2-trial`).
- *Not caught because*: no proof has an author posting while a peer fetches from a slow server.

**Item 2. One public sync round per node.**
- *Seen*: one slow member froze everyone; quiet did not help.
- *Cause*: `node/history_budget.rs:46` `BOUNDED_SYNC_RUNNING_SLOTS = 2`, one Public and one
  Background position (`node/ports.rs:60-64` `PhysicalSlot`, mapped at `:66-71`). ADR-025 D1.5
  (2026-09-26) requires exactly that, and makes D6's 16 slots, 4 per peer, moot.
- *Status*: KNOWN on the rig (`/tmp/rca-RcaFrozen/runs/slow1500`†; trial B2: fast members 90–95 s
  on v0.4.30, 1.2 s with a second position). INFERRED as the operator's condition: omp-io's one
  slot was held by a round toward robert-work aged 0.7 → 16.8 s
  (`io/quiet-fullstate-omp-io-215043Z.jsonl`).
- *Not caught because*: no proof has a member that answers in seconds.

**Item 3. Trust, membership and key entries travel with bulk; a late joiner stays at its join
snapshot.**
- *Seen*: omp-io at governance revision 44 for hours; doctor "has not trusted you" for every member.
- *Cause*: two rules compound. (i) `node/history_stream/runtime.rs:999-1026`
  `push_control_closure` demands each head's control closure above body work (ADR-036
  `…md:582-590`). (ii) `node/history_stream/admission.rs:940-1030` `preflight` demands a parent
  receipt (an inclusion proof and a consistency proof, combined at `:544-562` `combine_parent`)
  for the entry's own previous position and for *every* `seen` reference. A late joiner's grant
  names positions hundreds below the newcomer's window, so admission walks those feeds header by
  header. Why the code is that way: ADR-036 H-6 binds proofs to exact heads, and ADR-007 G-31's
  readmission rule ("eligible only if it causally descends from …", `ADR-007-…md:318-321`) was
  implemented as a fetch prerequisite instead of a fold rule, against ADR-036 H-8: "Ordinary
  order gaps initiate no network request" (`ADR-036-…md:827`).
- *Status*: KNOWN. Trace `/tmp/plan-sync/runs/B3-plan/logs/W.rca`†
  (`preflight-need-header … parent_seq=286 … entry_seq=12`). An earlier late joiner is
  necessary: without one the newcomer read everyone 14 s after joining
  (`/tmp/rca-RcaFrozen/runs/ctl-no-n-old`†); with one, 9 of 9 runs froze.
- *Not caught because*: no proof joins a room that already has a late joiner.

**Item 4. A body is requested once; nothing remembers a missing body; a bodiless entry is
skipped silently.**
- *Seen*: members held omp-io's headers through 34 and showed none of its posts.
- *Cause*: `node/channel/entry_store/sparse.rs:2577-2605` `select_history_live_window`: a newer
  head over an unfinished window keeps the window's start only down to `through − 127`; the rest is
  "older history, on demand" and never asked for again. `runtime.rs:2474-2499` `LiveRetry` retries
  once, inside the window. `node/channel.rs:7902-7903` skips a held header whose body is missing.
  Put there by ADR-037 R1's "one known deviation" (`ADR-037-…md:73-75`) and ADR-036 H-4 ("a
  changed live tip is not permission to drain its older gap", `ADR-036-…md:253-254`), against the
  standing ruling ADR-008 LS-33 (the decider, 2026-10-01): a missing body "MUST be asked of every
  peer until one supplies it" and shown "not received yet".
- *Status*: KNOWN. 31 window cuts in 115 s (`B3-plan/logs/W.rca`); keeping the floor took the
  newcomer from 3 to 229 entries (`B3-reach`).
- *Not caught because*: no proof writes more than 128 positions of one author during a join.

**Item 5. "inclusion header is absent".**
- *Seen*: that text as `last failure` toward two of omp-io's peers.
- *Cause*: `admission.rs:1002-1030` asks a proof for a `seen` parent whose header is not held; the
  proof's check needs that header (`admission.rs:234-237`) and fails the round. `start_entry`
  (`admission.rs:779-792`) already asks for the header first. An omission in the preflight path.
- *Status*: KNOWN. 291 of 300 samples on v0.4.30, 0 on the trial (`/tmp/trial-sync/runs/B1-base`†,
  `B1-trial`).
- *Not caught because*: no proof has an earlier late joiner (item 3).

**Item 6. `vox room read --history newest/resume` says "one bounded history quantum is queued" and
never moves.**
- *Seen*: io-repair-drill, three tries then `--history resume`; RcaFrozen `cure-newest-early`.
- *Cause*: the text is set at `node/actor/history_demand.rs:1093` and `:1129`. The request is an
  Archive operation; it needs the node's one Background position (ADR-025 D1.1, "Background is
  either recipient-key body work or Archive, never both"), has no priority over key-body work, and
  ADR-036 allows one unfinished archive operation per node (`ADR-036-…md:673`). `--history newest`
  also meets item 7's gate.
- *Status*: symptom KNOWN; mechanism INFERRED. Settling experiment: B2 shape, issue
  `vox room read --history newest` on the frozen newcomer, sample `vox status --json`
  `lanes.bounded` at 1 Hz, read the Archive flow's `waiting`, `slot_wait` and `root`.
- *Not caught because*: the history proofs ask for older pages in a quiet room.

**Item 7. A reader about 8,000 entries behind is refused "protocol limits exceeded".**
- *Seen*: readers stuck at position 87 of 8,473 (RcaSlow L1-quiet).
- *Cause*: `node/history_stream/server.rs:828-848` serves a live body only inside the newest
  window; otherwise `node/history_budget.rs:1060-1063` returns `MalformedBundle("live request is
  outside the bounded newest window")`, which `node/history_stream.rs:160-167` sends as
  `WireError::ProtocolLimits`, shown as "protocol limits exceeded" (`wire.rs:586-587`). Put there
  by ADR-036: "A live body must be the current accepted author's tail when selected"
  (`ADR-036-…md:560-561`).
- *Status*: KNOWN. `/tmp/rca-RcaSlow/r1/runs/L1-quiet`†; 31 such refusals served in B3-plan's trace.
- *Not caught because*: no proof has a reader more than 128 entries behind one author.

**Item 8. Joining through a saturated member fails: 38 s against a 30 s frame patience.**
- *Seen*: three failed joins through a busy member.
- *Cause*: `transport/framing.rs:65` `FRAME_PATIENCE` = 30 s; `node/joinstream.rs:740`
  `ADMISSION_PATIENCE` = 20 s; a 5 s busy read at `:1108`. The member answers the join on its
  actor, where an inbound request waited up to 15.7 s (`B3-reach`, Y). One B3-reach join failed
  in 5.4 s with "remote admission may have occurred, but its acceptance could not be verified and
  saved" (`/tmp/plan-sync/runs/B3-reach/rig.log:37`†).
- *Status*: symptom KNOWN; the split of the 38 s INFERRED; the 5.4 s failure UNKNOWN. Settling
  experiment: RcaSlow L2-oplike member plus `vox room join`, with the actor wait traced on the
  join answer path.
- *Not caught because*: `a_slow_joiner_gets_in_or_is_told_why_proof.rs` slows the joiner's proof
  of work, never the member.

**Item 9. "Every join makes every member rotate its key"; members that lag stop showing the
rotated authors.**
- *Seen*: after a join under traffic, y1 stopped showing z1 past post 833 until the room was quiet.
- *Cause*: no rotation runs on a join: a grant writes one governance entry
  (`node/channel/pending_text/consent.rs:622-632`). The "+1 received key generation everywhere" is
  the newcomer's own key arriving. What stops display is item 3: each member's grant is a control
  entry at its head, and every reader's fetch of that author first walks the grant's parents.
- *Status*: symptom KNOWN; the rotation reading INFERRED to be wrong. Settling experiment: B1
  shape, count each member's `received_key_generations` and `key_generations` before and after a
  join, and trace the walk toward y1 in the 30 s after it.
- *Not caught because*: no proof joins under traffic and then checks the existing members.

**Item 10. After leave and rejoin, the node's posts are refused for about 6 minutes.**
- *Seen*: "this node's record of its own history in this room is behind what a member holds".
- *Cause*: `node/channel/own_history.rs:1079-1190` `own_recovery_evidence` finds a member holding
  more of the node's own feed; `node/channel.rs:9296-9297` refuses writes
  (`error.rs:358-363` `OwnHistoryBehind`), as ADR-023 RL-8.5 requires. The fence lifts when an
  Archive operation has fetched the node's own entries back. It competes for the one Background
  position (item 6) and backs off 200 ms to 8 s (`node/ports.rs:263-284`). No 6-minute constant
  exists.
- *Status*: symptom KNOWN (io-repair-drill run C); pacing INFERRED. Settling experiment: drill
  Path 2 with `lanes.bounded` sampled at 1 Hz on the rejoined node.
- *Not caught because*: `a_node_leaves_a_room_proof.rs` never rejoins.

**Item 11. "quic stream: closed before the frame was written"; "the peer refused: transport
failed" in every run.**
- *Seen*: these two texts as `last failure`, in every sample, on every peer.
- *Cause*: two mechanisms. (i) `history_stream.rs:160-167`, `node/history_stream/driver.rs:57-62`
  and `node/history_stream/transport.rs:300-306` send `TransportFailed` for every local error,
  including a cancellation (`transport.rs:184-186`, "history request cancelled") and the 20 s frame
  deadline. The receiving side counts it as a failure (`node/actor.rs:13590-13591`) and nothing
  ever clears `last_failure`. (ii) `transport/framing.rs:36-43`: the stream was stopped with no
  Vox code or the connection went. Producers: an unreadable preamble (`actor.rs:2544-2546`), a
  missing store, room or port (`actor.rs:18834-18862`), an aborted serving task, and
  `transport/quic.rs:1121-1135` closing a connection when the node's inbound queue is full.
- *Status*: (i) KNOWN, both ends traced (`B3-plan`: 25 served "transport failed" were client
  cancellations). (ii) KNOWN for the producers; which one fired on IO is INFERRED. Settling
  experiment: on IO, count inbound drops, `route()` closes and aborted serving tasks while the
  laptop asks; only with the operator's go (ADR-045 FG-16).
- *Not caught because*: `a_sync_failure_names_its_reason_proof.rs` checks three named refusals,
  not what a cancellation is called.

**Item 12. Relayed key exchange stalls.**
- *Seen*: two members on a 75 ms relay never read each other.
- *Cause*: a key package is a log entry (kind 6, `log/entry.rs:302-303`) fetched by the same
  starved flows as items 1, 3 and 4.
- *Status*: KNOWN, identical on 0.4.29, 0.4.30 and a later commit (`/tmp/rca-RcaWedge/runs/
  r30-relay75-b10x2`†).
- *Not caught because*: `key_package_proof.rs` runs on loopback with no delay.

**Item 13. "last sync" moves only on a completed outbound round.**
- *Seen*: "last sync" stale about 30 s after a busy room opened; elsewhere "0s ago" while nothing
  arrived.
- *Cause*: `node/status.rs:384` reads `room.last_sync`, set only by `note_lane_sync`
  (`bounded_sync.rs:3732, 4063, 4434`). A killed, superseded, parked, served or partial round
  does not count; a round that delivered nothing does.
- *Status*: KNOWN (RcaSlow L2: 311 s on the author's side).
- *Not caught because*: the quiet-room journey asserts `last_sync_ms` only in a quiet room.

**Item 14. Rounds toward heavy authors run about 3 s and bring nothing.**
- *Seen*: the operator measured it on his machines on 2026-11-12.
- *Cause*: no 3 s constant is on the round path (the one 5 s constant there is `SETUP_PATIENCE`,
  `actor.rs:738`). Measured: an inbound request waits in the heavy author's actor queue
  (`actor.rs:2554` sends `NetEvent::SyncRequest`, handled at `:11928`) p90 60–84 ms, max
  12.0–15.7 s, then for the room's pending write (`node/history_stream/source.rs:744-761`), then
  the serve. The reader's exchange meanwhile hits the 20 s frame deadline or the 1 s turn.
- *Status*: the mechanism KNOWN on the rig (`B3-reach`, Y, 1,277 admissions); the operator's
  "about 3 s" INFERRED to be that sum. Settling experiment: ADR-044 E-14.
- *Not caught because*: no proof loads the serving node.

**Why no proof caught any of them.** ADR-018's gate as built runs two or three nodes on one
machine, with peers that answer in milliseconds, small stores, no author posting during a join, no
late joiner behind an earlier late joiner, and no member that answers in seconds (consolidated
analysis, finding F). Every item above needs at least two of those. The trial and plan A reproduced
them only after adding them. ADR-045 (the fleet) is the answer to this; §4 below names the
journeys.

### Citations checked

Each file:line above was read with `git show v0.4.30:<path>`. Confirmed as the plan gave them:
`bounded_sync.rs:18, 1553-1560, 4108-4121, 5653-5664`; `history_budget.rs:46, 1060-1063`;
`runtime.rs:999-1026, 2474-2499`; `admission.rs:234-237, 449-466, 544-562, 779-792, 940-1030`;
`sparse.rs:2508-2539, 2577-2605`; `channel.rs:7813-7826, 7902-7903, 9296-9297`;
`history_stream.rs:160-167`; `wire.rs:586-587`; `framing.rs:36-43, 65`; `joinstream.rs:740, 1108`;
`error.rs:358-363`; `ports.rs:263-284`; `quic.rs:1121-1135`; `status.rs:384`; `actor.rs:738`;
`source.rs:744-761`; `driver.rs:57-62`; `transport.rs:184-186, 300-306`; `entry.rs:302-303`;
`consent.rs:622-632`; `actor.rs:18834-18862`. Corrected:

| Plan A cited | At v0.4.30 |
|---|---|
| `history_demand.rs:2989-3013` (the "quantum is queued" text) | `node/actor/history_demand.rs:1093, 1129`; `node/history_demand.rs` has no such text |
| `actor.rs:13596` (`last_failure` set) | `actor.rs:13590-13591` |
| `actor.rs:2549` (unreadable preamble) | `actor.rs:2544-2546` |
| `actor.rs:11933` (`SyncRequest`) | sent at `actor.rs:2554`, handled at `:11928` |
| `bounded_sync.rs:3744, 4059, 4434` (`note_lane_sync`) | `:3732, 4063, 4434` |
| `history_stream.rs:652-656` (`HeadHint.size`) | `history_stream.rs:636-640` |
| `ports.rs:60-109` (`PhysicalSlot`) | `ports.rs:60-64`; lines 65-109 are the trial's |
| `own_history.rs:1149-1190` (`own_recovery_evidence`) | the function is `:1079-1190`; the "behind" results at `:1164, 1170` |
| ADR-036: "Arbitrarily old signed heads cannot turn Live into archive demand" | no such sentence; the rule is `ADR-036-…md:560-561` and `:567-568` |
| ADR-007 G-27/G-28 ("causally descends") | G-31, `ADR-007-…md:318-321` |
| ADR-036 H-7 "one unfinished archive op per node" | H-6, `ADR-036-…md:673` |

### What mature systems do, and what this ADR takes

| Source | What it does | Taken here |
|---|---|---|
| SSB and its EBT replication ([protocol guide](https://ssbc.github.io/scuttlebutt-protocol-guide), [EBT notes](http://dev.planetary.social/replication/ebt.html)) | Replicates per feed. A peer says "the sequence I hold"; the other streams from there. A message is checked against its own feed's hash chain only. | `Have` per author; verification by chain link; no other author's entry is a prerequisite (SY-3, SY-13). |
| Hypercore ([protocol](https://hypercore-protocol.github.io/new-website/protocol)) | A signed Merkle log. Peers exchange what they have; blocks are requested by index; a longer signed length only extends what is wanted. | Requests by position; never cancelled by growth (SY-1); signed heads stay the authority for size. |
| Negentropy / range-based set reconciliation ([Hoyte 2023](https://logperiodic.com/rbsr.html), [spec](https://github.com/hoytech/negentropy/blob/master/docs/negentropy-protocol-v1.md)) | Compares ranges, recurses on difference, and "does not require storing per-connection state". | Demand kept as nothing but what can be recomputed (SY-14). ADR-008 LS-27 already names Negentropy above about 100 authors; per-author intervals are its exact small case. |
| Matrix federation ([server-server API](https://spec.matrix.org/v1.18/server-server-api)) | Backfill is bounded by `limit`; authorization is resolved on the auth chain (the control subset), not the whole graph. | Control fetched as a set per author, apart from content (SY-3); the fold works on control entries only. |
| Automerge sync ([SyncState](https://docs.rs/automerge/latest/src/automerge/sync/state.rs.html)) | The per-peer state is a few hashes; after a restart it is rebuilt from heads. | Nothing per fetch or per peer is stored (SY-8, SY-18). |
| Git fetch ([protocol v2](https://git-scm.com/docs/gitprotocol-v2/2.38.0)) | The client says what it has; the server sends only the difference; a push during a fetch does not cancel it. | The requester computes what it lacks (SY-14); a newer head cancels nothing (SY-1). |
| Cassandra anti-entropy repair ([manual repair](https://docs.datastax.com/en/cassandra-oss/3.0/cassandra/operations/opsRepairNodesManualRepair.html)) | Merkle trees are built per range on demand, compared, then discarded. | Verified ranges live in memory and are dropped (SY-18; the decider's ruling). |
| Kafka replication ([Confluent guide](https://developer.confluent.io/courses/architecture/data-replication/)) | A follower fetches from its own offset; a new append never restarts the fetch; lag is measured per replica; a catching-up replica does not lead until caught up. | Per-author positions as the only cursor; "behind" per author (SY-20); own-feed recovery completes before the node writes (SY-11). |
| Delta-state CRDTs ([Almeida, Shoker, Baquero](https://repositorio.inesctec.pt/server/api/core/bitstreams/7e87bf63-1250-409c-a416-7a29f70718ea/content)) | A lost acknowledgement re-ships the delta; applying it twice is harmless. | Range answers are idempotent; a duplicate entry is ignored (SY-13). |

## Terms

- **Feed**: one author's entries in a room, numbered from 1. A number is a **position**.
- **Entry**: a **header** (the author-signed skeleton: position, previous entry's hash, kind,
  `seen` references) and a **body** (the payload). A header held without its body is
  **bodiless**.
- **Control entry**: an entry of kinds 1–8 (Governance, Checkpoint, StepPolicy, SessionFloor,
  PrivateSupport, KeyPackage, ContextUpdate, Termination; `log/history.rs:60-79, 97-99`). Kind 0 is
  Content. Trust, membership and keys are control entries.
- **`seen` reference**: a pointer in a header to another author's entry the writer had seen. It
  orders entries across authors.
- **Signed head**: an author-signed statement of its feed's size and Merkle root
  (`SignedHead`, `log/history.rs:882-892`). **Observed**: its signature verifies. **Accepted**:
  observed and consistent with the heads this node accepted before (SY-13).
- **Known size** of an author: the size in the newest signed head of that author this node has
  accepted (SY-13). A member's `Have` never sets it.
- **Anchor**: per room and author, the first position whose body this node fetches without being
  asked. Set when the node joins: the size of the author's verified signed head at the join, plus
  one (the decider, ledger row 38); for a room that exists before this release, by SY-26. An author first seen
  after the join has anchor 1.
- **Control-complete position** (`control_through`): per author, the highest position up to which
  this node holds every control entry, proven by a control proof.
- **Owed body**: a position at or above the anchor whose body this node lacks, whose retention
  has not expired by this node's own computation (ADR-008 LS-33), and that no holder has refused
  as `not for you` (SY-25).
- **Holder**: any member that holds the entries asked for, whether or not it wrote them.
- **Request in flight**: a request sent to one peer and not yet answered, refused or timed out.
  **Slot**: the place a request in flight occupies; held by nothing else (SY-24).
- **Chain link**: an entry's `prev_hash` field equals the hash of the entry before it
  (`log/entry.rs:159`).
- **Inclusion proof**, **consistency proof**, **control proof**: the Merkle proofs ADR-036 H-3 and
  H-6 define: an entry is in a signed tree; a smaller tree is a prefix of a larger one; a range
  holds exactly these control entries.
- **Fork evidence**: two valid author signatures over different entries at one position, or over
  two different roots of the same size (ADR-036 H-6).
- **Slow member**: a member every exchange with which takes about T (1.5 s on the rigs), made by
  ADR-045 FG-5's slow path (its datagrams delayed outside the process), never by a knob or a
  process pause. **Heavy author**: one that posts about once a second or more. **Late joiner**: a
  node that joins a room with history. **Earlier late joiner**: one that joined before the late
  joiner under test.
- **Rig shapes** (from the trial, `/tmp/trial-sync/README.txt`†): **H**, two nodes, quiet.
  **B1**, 300 seed entries, two authors at 1 post a second, one earlier late joiner. **B2**, B1
  with one member answering 1.5 s late and the room quiet. **B3**, the operator's shape: 3,000
  seed entries, three heavy authors, three Session-stepping agents on one of them, six earlier late
  joiners, one slow member. **L1-quiet** and **L2-oplike**: RcaSlow's reader 8,000 entries behind,
  and its author under agent load (`/tmp/rca-RcaSlow/r1/runs/`†). In every shape each member posts
  "hello to n-new" within 1 s of the newcomer's join.
- **R1**: repair the present mechanism. **R2**: replace it with per-author range reconciliation.
  **D-1 … D-6**: plan A's decisions for the decider; here Q1, Q2, Q6 (D-3, D-4 and D-5 are closed
  by SY-3, SY-15 and the amendments: engineering, not the decider's choice). **I-1 … I-8**: plan
  A's invariants; here SY-1 … SY-8.
- **Trial build**: v0.4.30 plus the trial's three changes (commit 28bd77347). **Reach build**: the
  trial build plus plan A's floor-keeping prototype.

## Requirements

Every proof below drives the shipped `vox` binary and asserts what a person sees (ADR-018). A
test-side server that answers the real daemon over the wire is apparatus and allowed (the decider,
2026-10-01). A slow member is made outside the process, by the slow path ADR-045 FG-5 defines (the
member's outbound datagrams delayed by T through the forwarder), never by a knob, an instrumented
binary or a process pause (fix-list item 83; FG-5: a `SIGSTOP` is a process-pause fault, not a
slow member). Each proof names: the journey that fails on v0.4.30 and passes on the fix; the
existing proof it extends; its mutant; its acceptance number. Each red names PRODUCT or APPARATUS.

**How each "v0.4.30 is red" was obtained.** *Verified* means the red was seen on the release asset
`vox 0.4.30` with no knob: B1 (`/tmp/trial-sync/runs/B1-base`†, `B1-base2`: every node the release
asset; B1 has no slow member), RcaFrozen's runs (release asset throughout), RcaWedge's relay runs
through the delay proxy (`r30-relay75-b10x2`), ADR-045's E-1 (B2 shape, the slow path at 1.5 s, on
the release asset: fast members' hellos 52.5 s and 150.8 s, control-current 134.8 s, join through
the slow member 33.8 s), and the operator's receipts under `/private/tmp/vox-rca/io/`†.
*Investigation* means the run used the `VOX_RCA_SERVE_DELAY_MS` or trace binary (B2-base, B3-base,
`rca-direct-serve300`, RcaSlow's L1-quiet and L2) and stands as evidence of the mechanism, not as a
mutant receipt (ADR-045 FG-5). Every proof below says which it has; an investigation-only red names
the run on the release asset that is to verify it.

### 1. The intent, and the invariants

These hold under the chosen mechanism (R2, §3) and would have held under R1. Each can be tested
on the rig. SY-27 comes first because every other requirement is tested against it.

- **SY-27. A newcomer takes the most recent chunk and has access at once; older chunks come just
  in time when a person scrolls up; nothing a newcomer must fetch before access grows with the
  length of the room's history.** *(new r5: the decider's intent, ledger row 63, his words: "they
  should only have to do the most recent chunk so they can immediately start having access to
  the room and if they want to go back in history they can scroll up and just in time start
  grabbing older chunks"; row 62: "yes chunks were the intent", one admitted range is one store
  transaction.)* **Access** means: the newcomer renders every member's posts made from its join
  on, is read by every member, and can post. **Chunk** means one `Range` or `ControlRange`
  answer (≤ 128 positions, ≤ 1 MiB), admitted in one store transaction (SY-13 rule 4).

  *What a newcomer, a rebuilt node or a rejoining node (a fresh join, ledger row 34) still fetches
  from the start of a feed before access, by entry kind; why access cannot be given without it
  (which check cannot be made); and its size in the operator's rooms* (`repo-to-cve` on
  2026-11-12: a dozen authors, three heavy; governance revision 56 → 155 over the day; the
  measured B3 shape: 3,000 seed entries, three heavy authors, 1,500–2,000 positions each, 21 % of
  a heavy author's entries being `ContextUpdate`, `arm-replace.md`):

  | kind | fetched from the start? | the check that needs it before access | size in the operator's rooms | grows with |
  |---|---|---|---|---|
  | 0 Content | **no**: bodies from the anchor on (SY-4, SY-17); older only when a person pages back (SY-9) | none | 0 before access | — |
  | 1 Governance (grants, trust, removals, readmissions, admin certificates, policy) | yes, today | the fold: who is a member, whose key signs, who may remove, which readmission cuts apply (ADR-007 G-29–G-31; ADR-037 R2/R3); the egress gate and `vox agent doctor` cannot answer without the whole set, because a later fact's validity depends on an earlier certificate | about 155 entries in the operator's room (the revision count); UNKNOWN per author (the reports count positions, not kinds); ≈ 3.7 KB each with its composite signature | membership and policy events, not messages |
  | 2 Checkpoint (an author's own feed) | yes, today | lets a holder drop old signatures; not needed for access | at most a few per author; UNKNOWN count | retention periods |
  | 3 StepPolicy, 4 SessionFloor | yes, today | Session reading only (ADR-031); not needed to read or post text | UNKNOWN; few | policy changes |
  | 5 PrivateSupport | yes, today | private transport declarations; not needed for access | UNKNOWN; one per node | nodes |
  | 6 KeyPackage | yes, today (every member keeps every sealed body: ledger row 40) | the newcomer's **own** keys are minted after its grant, so none from before the join is needed for its access; older ones are relay stock for other members (ADR-023 RL-4.5) | UNKNOWN count; a few KB each; members × key rotations | membership and rotations |
  | 7 ContextUpdate (an empty entry advancing a writer's signed context) | yes, today, because `ControlRange`'s proof must expand every control-kind leaf to count them (`ControlToken::Leaf`, `log/history.rs:1723-1741`) | none by itself: the fold never waits on one (SY-3, r4); a governance entry's `pre_context` coordinate that names one is checked against that one header (`validate_control_coordinate`) | **≈ 21 % of every entry**: 300–400 per heavy author in the measured room, ≈ 1.1–1.5 MB each with signatures; the 1,500–2,000 "control positions" per heavy author the reports count are almost all these | **messages** |
  | 8 Termination | yes, today | the feed ends; one per feed | ≤ 1 per author | — |

  So of what a newcomer fetches before access today, one kind grows with the room's messages
  (`ContextUpdate`, 21 % of them) and one grows with membership events (Governance); the rest
  are small or not needed for access at all. The design below removes the first and bounds what
  it can of the second; what it cannot bound without taking someone's word is Q7.

  *Bounding, by kind* **(what this ADR requires)**:
  1. **Content, Checkpoint, StepPolicy, SessionFloor, PrivateSupport, Termination, and relay
     KeyPackages are never fetched before access.** They are "older history": content from the
     anchor on; the Session kinds, checkpoints and relay packages in the lowest class after
     access (SY-15), from position 1, with no bound on their total but no effect on access.
  2. **`ContextUpdate` is never fetched below the fence post, and a kind filter cannot bound it
     above.** A `ControlRange` proof must expand every control-kind leaf in its interval,
     because the tree's control count (`Descriptor.controls`) is kind-blind (ADR-036 H-3) and a
     leaf hash needs the header bytes; a "governance only" filter would therefore save nothing
     on the wire under the shipped tree, and this ADR does not claim one. What bounds
     `ContextUpdate` is the **fence post** (3): below it no control range is fetched at all;
     above it, the newest chunk of each author carries at most 128 positions, of which about 27
     are `ContextUpdate` headers (≈ 100 KB) in the measured room, independent of the room's
     length. The fold never waits on a `ContextUpdate` as such (SY-3, r4).
  3. **The fence post: a governance checkpoint on the room, signed by the creator.** *(changed
     r6: fourth review; changed r7: fifth review P1-1, P1-3, P1-4 and Part 1; the decider kept
     it on the corrected cost, ledger rows 65, 68.)* A control entry of kind 1
     (`GovBody::GovernanceCheckpoint`, a new payload under ADR-007 G-9's registry; tag to be
     allocated) in the **creator's** feed. It carries, signed by the creator: per author A the
     **fence** `(seq, entry_hash)`, which is at or below A's newest entry, at or below A's
     **validated and settled frontier** on the creator (min of `closed_through(A)`, SY-3 rule
     3's closure index, and `settled_through(A)`, every fold phase committed — below, r13; r12:
     not the received clock `control_through`), and **strictly below any unresolved governance-kind entry
     of A**: one the creator holds whose validation is still pending on a missing prerequisite
     (SY-3 rule 4). A governance-kind entry the creator has **settled** passes under the fence
     whatever its disposition: applied, or conclusively inert (refused as unauthorized or
     underclaiming once every prerequisite was held, `member_fold.rs:908-935`,
     `governance/sparse.rs:509-550`), and for the inert ones the snapshot carries the record
     (entry hash, position, author, the refusal reason) so the newcomer's fold reproduces the
     disposition without the evidence (r8: sixth review 4; revision 7's "strictly below any held
     but unapplied" let a hostile member pin its own fence for ever with one unauthorized act).
     Every fence is bound to the **same committed fold generation** as the snapshot: the creator
     reads fences, coverage and projection in one snapshot of its store (ADR-044 RD-8's lease),
     never from a projection that moved since; the **summary hash** `H` and its **length**;
     and the previous checkpoint's entry hash.
     **The summary** *(r10: simplified; eighth review 3, 4, 5 and the decider's standing words
     "don't over engineer things", "we have no users yet"; revision 9's chunked, resumable,
     multi-supplier assembly, its holder advertisement, pinning, Retire, reclamation and acts
     s1–s5 are deleted; changed r11: ninth review 5 and 7, the comparison-record schema and the
     encoded limit; changed r12: tenth review P1 "readmission cuts" and "sizes": every projection
     is now the value its consumer reads, the readmission's covering removals and the resulting
     member state are carried, and the sizes are CBOR byte counts from this schema)* is one
     canonical CBOR object whose hash is `H`, in three tables, each a CBOR array of arrays with
     integers and byte strings only (deterministic encoding, RFC 8949 §4.2.1). **The rule for
     every projection**: a hash authenticates a fact, it does not supply a value; so each record
     carries, besides its hash, **every field a consumer reads from that fact when it has no
     body** — the newcomer installs the baseline without fetching the listed bodies, so the
     table is what its fold, its membership check, its egress gate and its display have.
     **(a) The member table**, one row per member ever admitted, indexed by row number:
     fingerprint (32 B), the 1,984-byte composite key (`identity/composite.rs:14`; carried
     because a newcomer must encrypt to the member without fetching the grant's body), the hash
     of that key (32 B), the admission grant's row in table (b), **`state`** (1 B: member |
     removed), **`active_removals`** (rows of the removals not covered by a later readmission,
     the fold's "is m a member at the fence" answer), and **`cuts`**: the pairs (removal row,
     readmission row) that are the member's `RecipientCut`s (`governance/view.rs:990-1012`: a
     readmitted member does not read what was posted between its removal and its readmission;
     the egress gate SY-25 and the key-package queue read this list). Encoded: 1 + 34 + 1,987 +
     34 + 3 + 1 + (1 + 3 per active removal) + (1 + 7 per cut) = **2,062 B** plus 10 B per
     removal/readmission the member has had. **(b) The comparison-record table**, one row per
     **governance-kind source fact at or below its author's fence**, sorted by (author row,
     position), each row the CBOR array [`author` row, `position`, `kind`, `hash` (bstr 32),
     `disposition`, projection…]: encoded, the first five fields are 1 + 2 + 3 + 1 + 34 + 1 =
     **42 B** (author row ≤ 255, position ≤ 65,535; 45 B at the widths' maxima), so no row is
     under 42 B and "48 B" (r11) was wrong. The hash authenticates the whole signed body
     (equality of hashes is equality of the fact); the projection is authenticated by the
     creator's signature on `H` and, on a member that holds the body, checked against it; the
     **disposition** (applied | inert with reason code) is the creator's fold conclusion, read
     by `control_effects_complete` below the fence and **never compared** (SY-28 (iv)). The
     fact set is every `GovBody` variant at the tag (`governance/entry.rs:57-95`, bodies in
     `governance/*.rs`) plus the two typed-policy kinds, each with the fields its consumer reads:
     `ConsentGrant` (target row 3, `skdm_ref` 34, `history_mode_at_grant` 1: **80 B**, read by
     the membership fold and the newcomer's key-package expectation); `ConsentRevocation`
     (target row 3, `new_chain_id` 9: **54 B**); `AdminCert` (delegate row 3 — a delegate is a
     member, so its 1,984-byte `delegate_pubkey` is the member table's key, never repeated —
     `capability_set` 3, `expiry_ms` 9: **57 B**, read by `authority::Query`); `AdminRevocation`
     (revoked certificate's row 3, `reason` 1: **46 B**); `PolicyUpdate` (`ttl_ms` 9 or 1 for
     none, `format` 1: **52 B**, read as the room's retention); `StepPolicyUpdate` (`ttl_ms` 9:
     **51 B**) and the **SessionFloor** kind *(changed r13: eleventh review P1 "SessionFloor")*:
     the shipped floor (`session_floor.rs:13-22`, nine wired fields) is read by
     `session_projection/floor_index.rs` to select the recipient and key and to enforce the
     boundary: `floor_index.rs:436` matches `epoch`, `:472,494` the `recipient`, `:549` orders
     by `generation`, `:715-716` keys on (author, recipient, epoch, generation) and `membership`,
     `:730` takes the boundary (`iteration`, `first_seq`); so the projection carries
     **`recipient` ref (3), `epoch`, `generation`, `iteration`, `first_seq`, `membership`** (five
     CBOR unsigned integers, 1–9 B each, **5–45 B**), and omits `room` (the summary is one
     room's) and `author` (the row's author column) as the two justified implicit fields; the
     row is **50–90 B**; a newcomer reconstructs the `Floor` the index expects from (room,
     author, these six) exactly; both typed kinds read by the typed-policy evaluation (ADR-031); `MemberRemoval` (target row 3: **45 B**; the body has no
     cut position — the cut is SY-3 rule 5's recorded triple, carried by the attestation rows
     and the member table's `cuts`); `MemberReadmission` (target ref 3, **`covers`**: an array
     (1 B) of refs to the removals its `removal_entry_hashes` name, 3 each: **46 B + 3 per
     covered removal** (r13: r12's 49 miscounted);
     `membership.rs:237`, consumed by `member_fold.rs:60-108` — a readmission restores
     membership only against the removals it names — and by `authority.rs:485-505`, the G-29
     cutoff restore, which asks whether a readmission's list contains the cutoff removal);
     `CutAttestation` (removal row 3, `through` 5: **50 B**); `Lifecycle` (`kind` 1, `format` 1:
     **44 B**, read as "the room ended"); `Presence` (`here` 1, `chain_id` 9: **52 B**, the
     member's left/back state); `ServiceShare` (`name` tstr ≤ 64, `udp`, `shared`, `kind` 3:
     **≤ 110 B**, read by the share list); `RoomName` (the `name` string as the body bounds it,
     ≤ 64: **≤ 108 B**, read by the room-name display, which has no body to read); `RoomAnchors`
     (the `BootstrapSet` as encoded by `nat/bootstrap.rs`, about 80 B a node, the anchor
     resolver's input: **≈ 42 + 80 × nodes**); `Genesis` (**42 B**). Key packages (kind 6) are
     **not** in the table: the fold derives nothing from them and a summary says nothing about
     them, so their absence contradicts nothing. **References that have no row** *(changed r13:
     eleventh review P1 "absent identities")*: every reference in a projection is a CBOR
     two-element array `ref` = `[0, row]` (the member or record row) **or** `[1, id]` where `id`
     is the 32-byte identifier the body carries — a delegate key's hash for an `AdminCert`
     whose delegate was never admitted (the shipped decoder accepts any valid delegate key,
     `governance/cert.rs:189`), a target fingerprint for a grant, revocation or removal of an
     identity not in the table, a removal entry hash for a readmission's `covers` entry whose
     removal this creator does not hold (`ReadmissionValidation::advance`,
     `member_fold.rs:60-108`, classifies it inert) or for an attestation's removal. Such facts
     stay in table (b) with their inert dispositions and compare exactly as any row (SY-28
     (iv) compares hash and projection; a member holding the body checks `id` against it); no
     row is invented for them, no fact is dropped, and the encoding cannot fail, so no fence
     post is ever blocked by one. A `[0, row]` ref costs 3–4 B, a `[1, id]` ref 36 B; the sizes
     below assume `[0, row]`. **(d) The context-invalid table** *(new r14: twelfth review P1
     "invalid context across the baseline"; revision 13 kept a carrier's context-invalid status
     in the local closure index only, and the baseline resolver made any unlisted pre-fence
     header terminal, so a newcomer installing the baseline lost the distinction and E naming
     the settled U below the fence escaped the cover requirement that exposed C2)*: one row per
     **control-kind entry at or below its author's fence that the creator's `CLOSE` recorded
     context-invalid** (an underclaiming carrier, a governance entry refused as underclaiming,
     an entry naming an object its author never signed): [`author` row, `position`, `kind`,
     `hash`, `reason` (1 B), **`exposed`**: the frontier the creator's expansion of that entry's
     deps exposed, an array of (author row, control position) pairs, one per author in its
     closure, ≤ the member count × 5 B]. The row certifies, under the creator's signature on
     `H`, both that the entry's declaration is not to be used as anyone's post-context and what
     the true post-context is; rows are rare (hostile) and cost 42 + 5 per author. Every
     control-kind entry below a fence is settled on the creator (`settled_through`), so absence
     from (d) certifies context-valid. **The baseline's causal scope**: on a node that installed
     the baseline, a post-fence entry E's authority query (`authority::Query`) runs over the
     baseline's rows at or below **E's covered frontier per author** (the positions E's context
     covers, after the cover check below) plus E's post-fence closure — never over every row; so
     a certificate the baseline lists is in E's scope exactly when E's context covers its
     position. **The paths from field to consumer**, so that
     nothing is left to the hash: membership at the fence ← table (a) `state` and
     `active_removals`, computed by the creator from (b)'s removals and readmissions' `covers`;
     with removals R1 and R2 and a readmission covering R1 only, `active_removals` = [R2],
     `state` = removed, and the post-fence fold, which replays only post-fence facts over this
     state, cannot cancel R2 without a readmission that names it; the egress gate and
     key-package queue ← (a) `cuts`; a post-fence delegated act whose cutoff is a pre-fence
     removal ← (b)'s readmission rows' `covers` (the `authority.rs:496` test runs on rows, not
     hashes, and resolves a row to its hash through the table); authority ← (b)'s certificates
     and revocations plus (c)'s admin set; retention and typed policy ← (b)'s newest policy
     rows named by (c); the room's name and anchors ← (b)'s newest `RoomName` and `RoomAnchors`
     rows named by (c); presence ← each member's newest `Presence` row. **(c) The fold state at
     the fences**: the creator's revocation cutoff state (ADR-007 G-29), the rows of the current
     policy, step policy, room name and anchors entries, the live admin set (rows) — under
     300 B. **How large it is, encoded** (the worked example, CBOR byte counts from the widths
     above, a 1-byte array header per row and 550 B for envelope, table headers and (c)): B3's
     room of 8 members (8 grants, 2 certificates, 1 policy, 40 presence flips, 8 shares, 1 name):
     16,496 + 640 + 114 + 52 + 2,080 + 880 + 108 + 550 = **20,920 B** (20.4 KiB). The operator's
     rooms, about ten members and about 300 entries (10 grants, 3 certificates, 2 policy, 240
     presence flips, 10 shares, 2 names, 1 removal, 10 attestations): 20,620 + 800 + 171 + 104 +
     12,480 + 1,100 + 216 + 45 + 500 + 550 = **36,586 B** (35.7 KiB). A room of 100 members with
     two years of use (100 grants, 20 certificates, 5 revocations, 10 policy, 10 step-policy, 10
     removals, 5 readmissions each covering one, 1,000 attestations, 2,000 presence flips, 100
     shares, 5 names, 5 anchor sets of 3 nodes): 206,300 + 8,000 + 1,140 + 230 + 520 + 510 +
     450 + 260 + 50,000 + 104,000 + 11,000 + 540 + 1,410 + 550 = **384,910 B** (376 KiB). The cap
     of 1,024 members with nothing but their grants: 1,024 × (2,062 + 80) + 550 = **2,193,958 B**
     (2.09 MiB), which no room has. These are byte counts of this schema's CBOR, not
     measurements: the prototype encodes real rooms (build item 5 records the encoded length)
     and the figures are replaced by what it measures. **The v0.4.31 limit, on the
     encoded answer**: a creator publishes a fence post only when the **encoded `Snapshot`
     response** — the summary, the response envelope and the frame headers, which is what
     `MAX_RESPONSE_BYTES` counts ("total wire credit for one explicit response quantum,
     including framing", `log/history.rs:27-28`) — is **at most 1 MiB** (1,048,576 bytes); the
     creator encodes the response it would serve and measures it, it does not estimate. The
     single answer is carried as up to four frames of at most 256 KiB **each including its
     frame header**, so the summary itself is at most 1 MiB minus the envelope and four frame
     headers (a few hundred bytes), and the checkpoint entry's `summary_len` is that measured
     length. From the schema's encoding, 1,048,576 − 550 bytes admit **489 members** with
     nothing but their grants (2,142 B each), or **272 members** with the worked example's
     history per member (3,843 B each); these counts are computed, not measured, and are not
     put to the decider as capacities until the reviewer has verified them (Q9, held). A
     creator whose encoded answer would exceed it publishes **no** fence post, the room then has
     no current fence post, newcomers and behind members verify from the last fence post or from
     position 1 (point 4; the decider's accepted cost, row 68), and status says so in plain
     words: `no fence post: the room's membership summary (<size>) exceeds this release's 1 MiB
     limit` (ADR-042's words). **A receiver applies the same limit before installation, and
     separates the signed declaration from a supplier's bytes** *(changed r12: tenth review P2
     "malformed answers"; ADR-042 r13 G2's mismatch sentence is superseded by this)*: (1) a
     creator-signed checkpoint whose **signed `summary_len`** exceeds the limit is intrinsically
     unusable and is **rejected as a candidate**: the node keeps the last usable checkpoint, or
     verifies from position 1 when there is none, and status says `creator checkpoint <hash>
     declares a <size> summary, over this release's 1 MiB answer; using the fence post of <when>
     instead` (or `…; verifying from the start instead`), recorded under `checkpoint-dispute:
     <room>` so a person sees why newer fence posts are ignored; (2) a `Snapshot` answer whose
     bytes decode to a length other than `summary_len`, or hash to something other than `H`, is
     **that supplier's bad answer and nothing more**: untrusted response bytes never invalidate
     a signed checkpoint; the answer is discarded, the supplier is rotated (as on `NotHeld`,
     the transport section), the next member whose `Have` names the checkpoint is asked, and the
     checkpoint stays the candidate; meanwhile the node uses what it has, and when no member
     reached has yet served it intact the room block says `creator fence post <hash> of <when>:
     the summary has not yet arrived intact from any member reached (<n> asked); using the
     fence post of <when-prev> meanwhile; still asking` (or `…; verifying from the start
     meanwhile; still asking`), a progress line (not under `checkpoint-dispute:`), cleared when
     an intact answer installs. A relay that serves short answers therefore delays, and cannot
     force the fallback that a forged declaration would need. Nothing is truncated and no valid
     room is refused; a room above the limit works as before this ADR, only slower for
     newcomers. **Transport**: the join answer (SY-17) carries the checkpoint entry and the
     summary whole in one `Snapshot` answer; a joiner that did not get it in the join answer
     (the answer budget was spent) asks `Snapshot{H}` (SY-12) of any connected member whose
     `Have` names that checkpoint (`Have` carries, per room, the installed checkpoint's entry
     hash and `H`; a member that has installed it holds the summary whole, so there is no
     separate "snapshot held" state), and a `NotHeld` rotates to the next such member; the
     joiner hashes the bytes and refuses a mismatch. **Installation** is one store transaction
     of at most 1 MiB plus the row: the summary becomes the room's **baseline** object keyed by
     `H`, the fold's starting state is set from it, `control_through(A)` := A's fence for every
     named author, and the previous baseline, if any, is deleted in the same transaction. There
     is no partial state: a kill before the commit leaves nothing and the joiner asks again; a
     newer checkpoint accepted before installation simply replaces the candidate (one answer
     each, nothing lost); a short disk refuses the one write under the floor and the joiner
     waits `StoreRecovery(room)` holding the bytes in memory under its permit (≤ 1 MiB) or asks
     again later. The baseline survives restart and every post-fence projection update (the
     projection is derived from baseline + folded entries, never written into it) and is served
     to later joiners whole.
     **The trust this takes, in the words the decider accepted** (row 68, after the reviewer's
     correction; the RL-3.1 analogy of revision 5 was wrong): a newcomer trusts the creator's
     account of the room before the fence, including removal and readmission history. A false
     account could make an honest bootstrapped holder serve old messages that its verified
     history would forbid; receiving ciphertext is not reading it, the recipient still needs the
     key. The creator cannot forge another identity's signatures or change which key matches its
     fingerprint, and the summary never overrides a node's local trust (ADR-048) or its own
     feed's continuity. Full-record members refuse a snapshot they can prove wrong and report the
     disagreement, but that is a **local defence, not a network-wide veto**: a newcomer can
     receive a false snapshot from any connected member, the creator included, even when its
     admitting member holds the full record, and newcomers that meet only bootstrapped members
     have no independent historical check. **The local defence**: every member that holds the
     full record compares each creator checkpoint with its own authenticated fold at the exact
     frontier (the snapshot it computes, byte for byte); a mismatch is a **checkpoint dispute**:
     the member refuses to serve that checkpoint or its baseline, keeps its own cuts, fork
     evidence, own continuity and ADR-048 trust debt untouched, and status says `creator
     checkpoint <hash> disagrees with this node's record`. A dispute is not author-fork evidence
     (SY-13 rule 2 applies only to two creator-signed statements that contradict each other).
     **The boundary, authenticated** (P1-3): `EntryV2` carries `pre_context`, `seen` and
     `prev_hash`; the boundary evidence is explicit, outside the control-only trace: the
     `ControlRange{governance}` answer that starts at A's `seq + 1` carries, as its **boundary
     frame**, two framed inclusion proofs under the holder's head (ADR-036 H-3's inclusion
     object; the `ControlRangeVerifier` cannot carry a content leaf outside its interval,
     `log/history.rs:1950-2140`): A's header at `seq` and A's header at `seq + 1`, whatever
     their kinds. The joiner checks the fence header's hash equals the checkpoint's `entry_hash`
     and that `seq + 1`'s `prev_hash` names it. A mismatch is a contradiction between A's signed
     chain and the creator's fence, **not** fork evidence against either: the joiner refuses the
     checkpoint, reports `creator checkpoint disagrees with <A>'s chain`, and falls back to point
     4. **Exact coordinates below the fence** (P1-3): a post-fence entry's `pre_context`
     coordinate at or below A's fence is satisfied without a fetch **only** when the baseline
     lists that exact coordinate (author, position, hash, kind): the per-author frontier record
     and every governance-kind record it carries; any other coordinate below the fence is
     fetched as a single witnessed header and checked by the kept `validate_control_coordinate`
     (`governance/sparse.rs:587-617`: exact hash, room, scope, control kind), so a writer that
     declares a nonexistent or non-control coordinate below the numeric fence is refused as
     today, never accepted on the number alone.
     **Cadence** (Part 1(c): revision 6 defined none): the creator's node signs a new fence post
     when **any** of these holds and at least 60 s have passed since the last: (i) **any author
     has 96 control-kind positions above its fence**, a **trigger, not a bound** (r9, seventh
     review P2-1): an author writing three control entries a second reaches 180 inside the 60 s
     minimum, and the delta a newcomer fetches per author is therefore `96 + (that author's
     control rate × (60 s + the creator's signing delay))`, measured by slot (e) as the largest
     per-author control delta over a fence's life; "one chunk per author" holds only when that
     delta is ≤ 128, which the measurement states per run rather than this ADR promising it
     (revision 8's unconditional claim is withdrawn); or 10,000 entries have been posted
     room-wide since the last fence, whichever comes first (each fence post
     costs one control entry plus a snapshot of members × ~2.1 KB plus the event records, a few
     hundred KB in his rooms, written once and served from the baseline); (ii) a governance event (grant, removal, readmission, certificate, policy)
     has been applied and 10 minutes have passed (so a newcomer's baseline carries recent
     membership and the creator does not sign on every event in a burst); (iii) 24 hours have
     passed with any post at all (so a quiet room's fence never ages past a day while the creator
     is present). **What the creator signs** *(changed r13: eleventh review P1 "completed
     prefix": a committed generation can hold a half-done fold step — at v0.4.30
     `member_fold.rs:773` `decide` commits a removal's decision in one phase and
     `current_step` (`:1008-1016`, phase 2) publishes its cuts in a later one; r12 let a trigger
     between them put the removal below the fence over an older member state)*: the fence post
     is an **explicitly completed projection for the exact selected frontier**, never a copy of
     the live projection. The fold keeps, per room, a persisted **`settled_through(A)`**: the
     highest position of A such that every **control-kind** entry of A at or below it
     (governance, typed-policy, key package, and the summary carriers `ContextUpdate`,
     Checkpoint, PrivateSupport; r14) has its
     closure row **and every phase of its fold step committed** (the fold advances it in the
     transaction that commits a step's last phase, and in no other); a step whose first phase
     is committed and whose last is not leaves `settled_through` below it, so that entry is
     "unresolved" for the fence rule above. At the trigger the creator reads one store snapshot
     (ADR-044 RD-8's lease) and takes per author `f_A` = min(`closed_through(A)`,
     `settled_through(A)`); then it **derives** tables (a), (b) and (c) from the closure index's
     rows at or below the fences and their dispositions — the member state, active removals,
     cuts, admin set, cutoff state and current policy are recomputed from those settled records
     by the same fold functions, as a pure function of the selected prefix — and never from the
     live `MemberState`/cut tables, which may already carry a later step's first phase. **The
     publication boundary**: the checkpoint entry and its baseline row are appended in **one
     transaction**; before it nothing is published, after it the room has the new fence post;
     the derivation is repeatable, so a crash during it costs nothing and the next trigger
     derives again. The fold's newer work goes on in later turns, invisible to the snapshot: the
     creator keeps the **last completed prefix** as its fence while the tip moves. **It never
     waits for the fold to become current, for posting to pause or for a flow to idle** (row
     82, SY-29): under continuous posting the fences simply sit lower, and the fence post's lag
     is read in status as `at <N> entries behind`, never as a reason to wait. *Act* (in the
     fence-post act): the apparatus pauses the creator's fold between a removal's two phases
     (a `test-knobs` hold on `current_step`, never in the release) while the cadence trigger
     fires; the fence post lists the removal above its fence and the newcomer that installs it
     and then receives the removal hides the target's later posts; mutant (**copy the live
     projection**): the summary's member row already says removed while the removal is above
     the fence, the newcomer replays it over an already-removed state, the readmission that
     follows in the act fails to restore the member (its `covers` resolves to an active removal
     the state does not list), red, PRODUCT. While the creator's node is catching
     up after an absence its fences are old positions, so **the creator's return helps
     newcomers only once its fold has caught up and a fence post with current fences is
     published**, not at once; a creator whose fold does not advance under load (SY-27 slot (a)
     on the creator's own node) produces fence posts whose fences do not advance: presence alone
     guarantees nothing, and the fleet's J1(m) measures the fences' lag under load. **Status** (ADR-042 owns the words; r8, sixth review
     7): per room, `fence post: <age> old, at <N> entries behind the room's newest confirmed
     entries; catch-up since it: about <M> entries, est. <B> MB`, where `N` and `M` are computed
     from **accepted signed heads only** (SY-13 rule 3: the known sizes), never from a `Have`;
     a member's advertisement above the known size is shown apart as `advertised, unverified:
     <k> more by <member>` (ADR-042 TR-1's `size_advertised`) and enters no estimate;
     `B` = `M` × 0.21 × 3.7 KB, printed as an estimate (`est.`), never as a remaining time; a
     room without any fence post prints `no fence post: verifying from the start` or, above the
     limit, the line above; a member that adopted one (SY-28) prints `adopted the creator's fence
     post of <when> at <position>` once in its room block and `vox agent doctor`'s room summary.
     **When the creator makes no fence posts** (the decider accepted this for v0.4.31, row 68):
     every author keeps posting; the newcomer's `ControlRange{governance}` from each fence still
     expands every intervening `ContextUpdate` leaf (the kind-blind control count:
     `ControlRangeVerifier` refuses a collapsed descriptor with a nonzero count inside the
     interval, `log/history.rs:1990-2060`; verification reads those headers and their contexts,
     and governance validates coordinates naming them), so what a newcomer fetches before access
     grows with the messages posted since the last fence. **Estimate, not a measurement**: with
     21 % of the room's entries being such headers (measured on one heavy author's feed, not
     across the room), about 6 entries a second room-wide and 3.7 KB a header, about 4.66 KB/s of
     accumulated history: **about 0.78 MB per thousand entries posted since the fence, about
     403 MB or 109,000 headers for a day**, before other proof and context traffic; the catch-up
     time is to be measured (slot (e)), not estimated. Old-checkpoint replay by a hostile member
     imposes the same cost (never a forgery) and is bounded by the joiner asking every connected
     member for its newest checkpoint and taking the highest fence among those whose signature
     verifies. **Crash windows**: a creator killed between folding and signing writes no
     checkpoint and the previous one stands; a newcomer killed mid-install has nothing and asks
     again. **When there was never a fence post**: point 4.
     *Alternatives not taken* (the decider, row 68): **a proof design that skips empty context
     entries** while proving governance completeness (per-kind counts in the tree's descriptors
     or a per-author governance index committed by the signed head, for future entries only, since
     existing feeds cannot be re-signed): not chosen for v0.4.31; it would change the proof
     format, not who may summarize the room. **A second signer** when the creator is away (an
     admin, or the oldest connected member): not chosen; it would add that signer's power to
     falsify the room's history, and a removed admin could conceal its own removal, which the
     creator, who cannot be removed, cannot.
  4. **What remains unbounded**: without any checkpoint, Governance (kind 1) and every
     intervening `ContextUpdate` from position 1 (the kind-blind count: revision 5's "grows with
     membership events, not messages" was wrong for the kept verifier; it grows with messages,
     about 21 % of them); with a checkpoint, the same from the last fence (point 3). Both are the
     decider's accepted cost for v0.4.31 (row 68).

  *The newcomer's path to access, under this design* (and a rebuilt or returning node's: a
  node that left and comes back is a newcomer here, ADR-049 LE-9, X049-7, with these three
  limits: the fence post is **never** the source of that node's **own** head, generation or
  continuity, which come from its own append checkpoint (SY-11); it applies to the node's own
  feed only **above** that checkpoint; and a verified return updates every online member's
  roster at once, the next fence post consolidating it, never activating it): join answer =
  `Have` + heads + the creator's newest checkpoint and its summary + own feed (SY-17); per author, one
  `ControlRange{governance}` from its fence post to its head, with the boundary frame; the fold
  applies them over the baseline; the room is readable and writable (ADR-037 R2, R5); bodies from
  the anchor on arrive in chunks behind. Older chunks come when a person pages back (SY-9), one
  `Range{descending}` per page, and a page below the fence post that needs an old key or an old
  governance fact fetches that fact then, just in time, as a prerequisite.

  *Where the earlier rulings stand*: row 38 ("control entries for all time") is superseded for
  governance by rows 65 and 68 (the fence post); bodies from the join on and paging back are
  unchanged. Row 63's "one chunk per author whatever the room's age" holds **while the creator
  keeps posting fence posts** at the cadence above **and the measured per-author control delta
  since the last fence is at most 128** (r10, eighth review 8: the cadence is a trigger, and an
  author writing three controls a second inside the 60 s minimum exceeds one chunk; slot (e)
  measures the delta per run and the claim is made per run, never here); without fence posts
  the cost grows as point 3 states, which the decider accepted for v0.4.31.

  - *Closes*: the sync half of the operator's day, as he described its cause.
  - *Changes*: SY-12 (`ControlRange{kind}`), SY-13 rule 4 (one transaction per chunk), SY-14
    (control wanted from the fence post), SY-15 (the after-access class), SY-17 (the checkpoint
    in the join answer), SY-26 (existing rooms: `control_through` from the newest creator
    checkpoint, else 0), amendment 11; ADR-007 (the new governance payload; Q7).
  - *Measurement, with one named place for each result* (the replace arm's re-run,
    `arm-replace.md`, to replace the top of that report; written here in revision 7):
    (a) **time to access** on B3 with all six earlier joiners staged and reads in both directions:
    the newcomer contract, stated once here and restated by ADR-045 J1(a) (X045-1): the clock
    starts at `joined` (the moment `vox room join` prints it); within **30 s** every member's
    post-join hello renders on the newcomer and the newcomer's own hello renders on every member,
    the slow member included (there is no separate 60 s for the slow member: SY-2's 5 s is the
    quiet-room act, SY-4's 120 s is the B3 proof's acceptance while the contract is unmet and is
    superseded by 30 s when the measurement passes), with a current fence post; with the creator
    away the promise is qualified as Q8 records; (b) **bytes and
    requests fetched before access**, by kind; (c) **the same two with the prior history doubled**
    (6,000 seed entries): neither may grow by more than 20 %; (d) **paging back on request**: a
    page below the anchor renders within 10 s (SY-9); (e) **the cost without a fence post**
    (ADR-045 J1(m)): the same B3 with the creator's last checkpoint 3,000 and 6,000 entries behind
    the heads, measured **together**: the fence's age and distance, bytes and requests fetched
    before access, and the actual time to access, so the 0.78 MB per thousand entries estimate
    is replaced by a measured figure per thousand entries and a measured time, never derived
    from a bandwidth guess. *Consequence if worse than required*: if (a) exceeds 30 s or (c)
    grows, the design has not met row 63 and this ADR says so; the remedy is named per cause in
    the build list below, else to stop the sync work and tell him plainly (row 53).
    **Round 2's results in these slots** (the replace arm's final binary 4189c291c, run set
    r2d, `arm-replace.md`, receipts `/opt/vox-evidence/v0431/arm-replace/r2d-*/`; the
    build had the two missing parts and neither the fence post nor the baseline-aware
    resolution nor SY-28; the decisive case **FAILS** on one assertion): (a) time to access to
    the two fast heavy authors and every present member 21.7 / 22.7 s (duty cycle), 40.7 / 44.2 s
    (slow path); **never to the slow heavy author y1** in all three variants, because y1's own
    fold froze at revision 8 of 87 (62 of 86; 50 of 92) and y1 never minted the newcomer's key
    package (cause 1 below; SY-28 is the answer); every one of the eight joins succeeded where
    v0.4.30's newcomer join fails at 6.4 s; (b) before access 417 requests, 38.8 MB, 390 entries
    + 47 control positions; 18 admissions below the anchors (37 Governance, 8 `ContextUpdate`,
    2 PrivateSupport, 4 Content: the governance walk from 1); (c) with history doubled: access
    21.7 → 31.4 s, governance equal 18.5 → 36.0 s, below-anchor admissions 18 → 85
    (`ContextUpdate` 8 → 68): the growth is the walk from position 1 and the below-anchor
    coordinates that the fence post and baseline-aware resolution are to remove, **unbuilt and
    therefore unproved**; (d) paging back: **no older chunk within 60 s** in any run (the
    request rode the shipped Archive path; SY-9 is not wired in that build); (e) not run. B1:
    every greeting 2.4 s against 50.2 s; restart mid catch-up: nothing lost. **Cause 1,
    retraced against revision 8's text**: revision 8, built exactly as written, would **not** have
    let y1's fold reach the newcomer's grant: its SY-3 rule 3 gated every governance entry on
    `control_through` of every author it named (coverage that y1 advanced at 2.7 positions/s
    through every `ContextUpdate`, from position 1, against ~6 entries/s), and its effect
    consumer resolved every above-fence coordinate of every received Content entry against
    completed effects (y1's owed effects 10 → 409 in 180 s). Revision 9 changes both (SY-3 rules
    3–4, SY-13 rule 5) and adds SY-28; the prototype's fatal wiring fault (a 256-effect batch under one
    request deadline) is not design and is in the build list; the "idle lane" reading of round
    2 is **retracted** (`arm-replace-next.md`, r10: in the duty-cycle runs y1's own new
    posts never committed to y1's own feed, so there was nothing for the newcomer to request;
    the receiving demand rule was sound), and y1's own **publication stall** is traced and
    repaired in the build list without assuming which of the report's candidate causes is
    responsible. No claim here is "inferred to fix": every unbuilt item is marked unbuilt and
    acceptance of this ADR waits on the re-measurement passing every B3 assertion.
  - *Proof*: the B3 act of SY-4 asserts (a); a **doubled-history** act in
    `a_newcomer_reads_the_whole_history_proof.rs` (optional in tree, mandatory on the fleet,
    J1): the B1 shape seeded twice, 300 and 600 entries; time to access and
    `vox status --json`'s bytes-before-access differ by at most 20 %, and `vox room read
    --history older` on the 600-entry room shows its oldest page within 10 s. v0.4.30 is red
    (the parent walk grows with history: B1 54.2–88.9 s against H 0.8 s). Mutant: fetch
    `ControlRange{all}` from position 1 (bytes before access double; red, PRODUCT). Acceptance:
    30 s; 20 %; 10 s.

- **SY-28. An existing member's governance fold and the key packages it owes progress at that
  member's own request rate, never at the room's content rate or any author's `ContextUpdate`
  rate; a member that falls behind adopts the creator's newest fence post as its baseline
  exactly as a newcomer does.** *(new r9: the round-2 measurement, `arm-replace.md`; the
  seventh review's first P1; uses only what ledger rows 63, 65 and 68 chose: the creator's fence
  post, no second signer, no change to what the control proof witnesses.)*
  - *The rule.* (i) A received entry's **rendering** depends on nothing another author wrote
    (SY-13 rule 5; SY-3's effect rule: two lookups, the reader's key and its own cut). (ii) A
    governance-kind entry's **validation** depends on its pinned prerequisite frontier (SY-3
    rule 3: the exact headers it names and its author's chain back to the fence), fetched as
    single witnessed headers or one adjacent control chunk, never on any author's
    `control_through`. (iii) The fold and the key-package queue own their progress (SY-3 rule 4).
    (iv) **Adoption** *(the decider, 2026-11-13 17:25 PST, ledger row 76: "Like a newcomer. It
    jumps to the creator's latest fence post and is current about as fast as a newcomer would
    be. For the stretch it skipped, it takes the creator's word on membership: the same trust
    you accepted for newcomers, now also for members that fall behind. It still rejects a
    summary that contradicts anything it already holds."; the rule, r10, eighth review's SY-28
    paragraph)*: a member M for which, for any author A, `control_through(A)` on M lies more than
    one control chunk (128 control-kind positions) below A's fence in the creator's newest
    checkpoint that M has accepted (SY-13's signature and the creator's chain) is a **candidate**
    for adoption. **One rule**: M adopts a summary only if it **agrees with every fact M already
    holds for the part M held**, and a summary that contradicts any held fact is **disputed
    exactly as a full-record member disputes it** (SY-27 point 3's local defence: refused, never
    installed, reported `creator checkpoint <hash> disagrees with this node's record`) and never
    adopted. **The comparison, as an algorithm** *(changed r11: ninth review 4 and 6; the
    comparison is over immutable source facts, never over fold conclusions, and over the
    checkpoint's covered prefix, never over M's coverage)*. *Input*: the checkpoint C (creator-
    signed; per author A its fence `f_A`; its summary S with the comparison-record table of
    SY-27 point 3 (b) and the member table (a)); M's **held facts** `F_M`: every governance-kind
    entry M has validated itself (SY-3 rule 3: contiguous ones at or below its
    `closed_through(A)` **and the sparse ones above it**), each as (author, position, kind,
    hash, body); and per author M's **validated frontier** `v_A` = `closed_through(A)` (SY-3
    rule 3's closure index; below it M has closed every entry of A, so `F_M` is complete there;
    r12: not the received clock `control_through`, below which entries may be held and not yet
    closed). *Steps*, per author A: (1) the **domain** is `D_A` = { r in
    `F_M` with r.author = A and r.position ≤ `f_A` }; held facts of A **strictly above** `f_A`
    are outside the comparison, kept, and folded after adoption (M may be ahead of the fence for
    A and behind for another author); (2) **forward**: for each r in `D_A`, S must hold a row
    with the same (author, position, kind, hash) whose projection equals the fields of r's body;
    a missing row or a different hash or field is a **contradiction**; (3) **reverse**: for each
    row of S for A at a position ≤ min(`v_A`, `f_A`) — the stretch where M holds everything —
    `F_M` must hold that entry; a row M lacks there is a **contradiction** (rows above `v_A` M
    cannot judge complete and does not count against); (4) **members** *(changed r12: tenth
    review P2 "clip the member comparison")*: for each member m whose admission grant M holds
    **at or below the admitting author's fence `f_admitter`**, S's member row must carry the same
    fingerprint, key hash and grant coordinate (source facts; the member's `state`,
    `active_removals` and `cuts` are conclusions, not compared); a member whose grant lies
    **above** its admitter's fence is rightly absent from an older summary — M keeps that grant,
    the member's key and identity material, and replays them over the adopted baseline (the
    re-fold below), which is the "ahead for one author, behind for another" case (iv) permits;
    (5) **own feed**: compared through M's own checkpoint (ADR-049 LE-9), never
    adopted. *Not compared* (ninth review 6): dispositions, cuts, the admin set, the cutoff
    state — fold conclusions that legitimately change when M learns governance it lacked (a
    creator removal concurrent with a delegated removal E that M applied, missing on M and in
    the checkpoint, makes E inert under G-29; an honest checkpoint records E inert while M has
    it applied; the facts agree, the verdicts differ, and M's verdict is the one to move). M's
    **recorded cuts and attestations** are its obligations (SY-3 rule 5) and stay in force
    unchanged whatever the comparison. **(6) Causal validity, table (d)** *(changed r15:
    thirteenth review P1; row 76)*: M's closure index holds, for every control-kind entry it
    closed — carriers included — the **context** column (valid | invalid) and, for an invalid
    one, the frontier its own expansion exposed; these are causal-evidence conclusions fixed by
    the entries' bytes, not fold conclusions, and they are compared. For every author A and
    **every control-kind entry r of A that M has closed at a position ≤ `f_A` — contiguous ones
    below `closed_through(A)` and sparse ones above it alike** *(changed r16: fourteenth review
    P1; r15 ignored (d) above the contiguous frontier even where M held the evidence)*: if M
    recorded r **context-invalid**, S's table (d) must list (A, r.position) with the same hash
    and an `exposed` frontier equal to M's (a listing missing, or a different frontier, is a
    **contradiction**: the summary would make U a reusable context that M has proved invalid);
    if M recorded r **context-valid** and S's (d) lists it, that is a **contradiction** (the
    creator asserts an invalidity M's own expansion refutes). A row of (d) is ignored **only
    where M lacks independent evidence at that coordinate** (a position M has not closed); no
    completeness is demanded for unknown sparse positions — M does not count a (d) row against
    the summary merely because it has not seen the entry. This check is distinct from
    step 4's member rows and from the uncompared dispositions, cuts, admin set and cutoff
    state: context validity never changes with later governance, so it is evidence; a
    disposition can. *Output*: **AGREES** or **CONTRADICTS(first witness)**.
    *Stopping*: one pass over `F_M` per author and one over S's rows at or below `v_A`; bounded
    by M's held governance set plus the summary's rows in M's contiguous stretch; no network.
    *The comparison is authenticated*: S by the creator's signature on `H`, `F_M` by the
    witnessed signatures M checked itself. *When it AGREES*: M installs the baseline as a
    newcomer does (SY-27 point 3's one transaction) for the stretch it did not hold: the fold's
    state at the fences is taken from S, M's held facts above the fences are **re-folded over
    that state** (verdicts recomputed: that is where E above turns inert), M's own recorded
    cuts, attestations, fork evidence, own feed continuity and ADR-048 trust debt are kept
    untouched, `control_through(A)` is raised to `f_A` for every author whose coverage was below
    it, and M's control demand is then the delta since the fence, the same bound a newcomer
    has. *When it CONTRADICTS*: M adopts nothing, keeps verifying from its own `control_through`
    at its own request rate (rules (i)–(iii) still hold, so it progresses), disputes the
    checkpoint, serves neither it nor its summary, and status says `creator checkpoint <hash>
    disagrees with this node's record; verifying from <position> instead` (ADR-042's words); a
    later checkpoint is compared afresh. *Hand-run against the ninth review's cases*: a false
    checkpoint that omits a removal M validated sparsely above `v_A` but at or below `f_A` — the
    removal is in `D_A` (step 1 takes sparse facts), step 2 finds no row: CONTRADICTS; M ahead of
    the fence for A — its facts above `f_A` are outside `D_A`, kept, re-folded: AGREES on the
    rest; M holding T's admission above the admitter's fence while behind another author — T's
    row is not demanded of the older summary, T is replayed after adoption: AGREES; the honest
    checkpoint with E inert — hashes agree, dispositions not compared: AGREES,
    E becomes inert on M after the re-fold. A member that holds the full record through the
    fences compares and adopts nothing (it has nothing to skip). (v) Without
    any fence post, M's catch-up is the walk from position 1 at its own request rate, the
    decider's accepted cost (row 68), and still independent of other authors' content rate by
    (i)–(iii).
  - *What it replaces at v0.4.30*: `prepare_received_effect`'s coordinate loop for non-governance
    kinds (`pending_received.rs:134-147`: a validated header and completed control effects per
    coordinate), `control_effects_complete` as a gate on rendering and on governance validation
    (`governance/sparse.rs:587-617` keeps the exact-coordinate check, loses the coverage
    requirement), and the implicit rule that an existing member's governance is walked from
    position 1 only (`push_control_closure`, `runtime.rs:999-1026`, already deleted by SY-3).
  - *What it costs on the wire* *(changed r11: ninth review 3)*: for the newcomer's grant on a
    slow member, the grant's header and the closure SY-3 rule 3 defines: each named author's
    chain from its stop (fence or validated frontier) to the named position, one witnessed
    header each (chunked when adjacent), bodies for the governance-kind entries in that span;
    no header twice and none below the fence; its size per entry is measured by the prototype
    (build item 4), not bounded here; for adoption, the summary once (SY-27 point 3's sizes)
    instead of every author's control range from position 1; nothing per content entry for
    rendering (SY-13 rule 5).
  - *Why it admits nothing the member lacked authority for*: rendering never decides authority
    (ADR-037 R3: provisional until the fold is current, hidden when a folded removal cuts it);
    validation keeps every exact-coordinate and coverage-of-context check (rule 3) and only stops
    waiting for coverage it does not need; adoption takes the creator's word for pre-fence facts
    exactly as a newcomer does (the trust the decider accepted) and never for a fact M already
    holds, so M cannot be made to forget a removal it folded itself.
  - *Hostile cases*: a member advertises a bogus checkpoint (signature fails; nothing adopted); the
    creator's checkpoint disagrees with M's held facts (M keeps its own, reports the dispute,
    adopts **nothing**, (iv)); a flood of `ContextUpdate`s by one author (M's rendering of
    others is untouched; that author's own control chunk grows, bounded by the fence delta).
  - *Closes*: round 2's decisive miss; the seventh review's first P1; the SY-15/SY-24 claim that a
    node progresses at its own rate now holds for governance too.
  - *Proof*: a **slow existing member** act in `a_newcomer_reads_the_whole_history_proof.rs`'s
    B3 arm (optional in tree, mandatory on the fleet, ADR-045 J1): the slow heavy author y1 (duty
    cycle and slow path) folds the newcomer's grant, mints its key package, and the newcomer
    renders y1's posts, all within 120 s of `joined`, while the other authors post at 1/s and
    y1's `vox agent doctor` says "you trust each other" for the newcomer; a second arm with the
    creator's fence post 3,000 entries behind the heads (the adoption path), same assertions
    within 180 s. v0.4.30 is red by the round-2 baseline (y1's governance 8 of 87, never; the
    receipt is `/opt/vox-evidence/v0431/arm-replace/r2d-B3dc-arm/`; on the release asset the
    join itself fails, item 88, so the v0.4.30 red of this act is the join's). *(r10, eighth
    review 5)*: the **fold-isolation** act stages blocked unrelated Content: an apparatus holder
    serves y1 a chunk of Content whose author's chain key y1 lacks (its effects park on
    `key_delivery_pending`) and keeps y1's two slots busy with such chunks, while the newcomer's
    grant arrives; y1 folds the grant and mints the package within 60 s regardless (mutant: run
    the fold's evaluation behind the room's effect queue; the grant folds only after the blocked
    Content, never within 60 s, red, PRODUCT); the **Content two-lookup** mutant: restore the
    completed-effects dependency on every coordinate of a received Content entry
    (`prepare_received_effect` as shipped, loop and post-loop `checked_governance` deferral);
    y1's rendering of z1 stops within 120 s while z1's control delta is held back by the
    apparatus, red, PRODUCT (the fold still progresses under rule 4, so the assertion is the
    render, not the fold). The **adoption** act (the second arm) *(changed r11: ninth review 9;
    policy is asserted through the public status outcomes, timing is not claimed)*: the
    precondition is asserted first (y1's `control_through` for z1 more than 128 control
    positions below z1's fence in the creator's newest checkpoint, read from `vox status
    --json`; the apparatus stages ten control chunks of z1's history so the gap is real), then
    the assertion is the **outcome**: y1's room block prints `adopted the creator's fence post of
    <when> at <position>` and `.rooms[].fence_post.adopted_at_ms` is set, y1's doctor trusts the
    newcomer and the newcomer renders y1 (both within the act's 180 s window, which is a
    staging bound, not the red); mutant: skip adoption (verify from `control_through` only):
    the adopted line never appears, the block reads `verifying from <position>` throughout, red,
    PRODUCT on the status outcome whatever the wall clock. The **disputed summary** act: the
    apparatus creator signs a checkpoint whose summary omits a removal y1 validated (the member
    listed as never removed); y1 refuses it — the room block prints `creator checkpoint <hash>
    disagrees with this node's record; verifying from <position> instead`, the adopted line never
    appears, y1's `Have` does not name that checkpoint — keeps that member's posts hidden, and
    still becomes current by verification; mutant: **skip the comparison** (adopt any
    creator-signed summary); the mutation does not bypass y1's own cut, so the red is **not** on
    y1's screen: it is that y1 now serves the false checkpoint, and a **fresh newcomer** that
    joins through y1 installs it and renders the removed member's post-removal entry, red,
    PRODUCT (what a person at the newcomer sees), with y1's status showing the adopted line
    where the dispute line was asserted (a second red on the same mutant). **The
    sparse-contradiction order** (r16): y1 holds, above its contiguous `closed_through` for D
    but below D's fence in the checkpoint, the carrier U it closed context-invalid on its own
    evidence (U's `exposed` naming the creator through X, so C2); the apparatus creator signs a
    checkpoint whose (d) row for U hides C2 (an `exposed` frontier stopping at C1) or omits U;
    y1 refuses it with the dispute line, adopts nothing, and the newcomer that joins through a
    full-record member still shows the target as a member; mutant (**compare (d) only up to
    `closed_through`**): y1 adopts, serves the checkpoint, and a fresh newcomer joining through
    y1 installs it, accepts B's later removal E naming D@U and C1, and hides the target's later
    post while every other member shows it, red, PRODUCT. **Whole-checkpoint
    refusal** (SY-27 point 3's over-limit case) is asserted the same way: the checkpoint-
    dispute line names the size and the fence post in use. Acceptance: 120 s; 60 s; 180 s;
    300 s (staging bounds).

- **SY-29. Nothing in sync waits for a quiet room, an idle flow or a silent member; the
  actor's room turn has its own lane and standing over inbound sync work.** *(new r12: the
  decider, ledger row 82: "yeah we need different queues for priority messages or something";
  "quiet room -- lol"; "not the point of vo[x]"; ArmReplace's cycle-5a trace,
  `arm-replace.md`.)* A busy room is the normal case. **The rule**: every step this ADR
  defines finishes within its own bound under continuous posting by every member, and no step
  waits for, reserves or requires a room, flow or member to fall quiet. *Checked step by step*:
  a flow's request (SY-1, SY-2) completes on its own answer, never on the flow idling; a port's
  serving (SY-10, SY-25) answers from the committed state it has, `Busy{retry_after}` when at
  budget, never "when the room is quiet"; the fence post (SY-27 point 3) is signed from the
  committed generation at the trigger, fences at the validated frontier, never after the fold
  "becomes current"; `CLOSE` (SY-3 rule 3) is PENDING on named prerequisites only; the summary's
  installation and the adoption comparison (SY-28) run on committed state under the owned-write
  protocol, with posts landing meanwhile; SY-26's migration runs before the room is published
  and reads nothing live; SY-13 rule 4's chunk admission renders its Content in its own
  transaction (SY-30), so a stream of chunks never waits for the stream to end. **Lanes**: control work — the governance
  fold and `CLOSE`, computer-policy application, roster and rekey work, the key-package queue,
  and the actor's **own room turn** (its own publication: committing its own posts and control
  entries) — travels on its own lane and is never queued behind, starved by or refused because
  of ordinary posts or inbound sync work; posts are never refused because a control change is
  being applied (fix-list item 93 is owned by ADR-043/ADR-048; this ADR states only that a
  member's own publication path is not blocked by policy application). **The lane rule, as
  ADR-040 NW-3, ADR-044 RD-10 and ADR-048 TC-4 state it** *(changed r13: ledger row 82b)*:
  each room has **two lanes, FIFO within each** — **control** (trust, computer policy, roster,
  rekey, key packages, keyring batches, evictions and readmissions; here also the governance
  fold and `CLOSE`) and **authored** (posts, Session activity, read marks). When both have
  ready work they **alternate: one control turn, then one authored turn**; a turn is **one
  native transaction**, ending at its own Immediate commit and installation (row 74 unchanged:
  one flush per ruled save; an in-flight ruled save keeps its owner through its own flush and
  completion, and the handoff comes after — no group commit). A multi-step control operation
  takes one turn per transaction and keeps its continuation between turns; **a child
  transaction it dispatches runs in its parent's turn** and never queues behind its parent.
  When only one lane has work it runs back to back. Bounds (row 82c): a control step, once at
  the head of its lane, waits for at most the transaction in flight plus one authored write;
  an authored write waits for the writes
  ahead of it in its lane plus at most one control transaction. A turn is bounded work — one
  transaction — never "drain the control backlog". **The actor's room turn has standing**: it
  takes the room writer as the next turn of its lane, never by `try_lock` with a stand-aside
  (fix-list item 96: `node/actor/governance.rs:325-340` at v0.4.30 has the prototype's shape,
  45 `try_lock` sites under `node/actor/`; in cycle 5a y1's governance fold lost every tick to
  lane, effects and serve waiters and never ran). **Where inbound sync admission goes** *(r13;
  `adr-046-pending-r12.md` "cycle 5a": 536 of 612 "publication busy" refusals of y1's
  own posts were inbound chunk admission holding `reserve_pending_write`'s single place,
  `pending_text.rs:278-292`)*: an inbound chunk's admission transaction (SY-13 rule 4: one
  chunk, ≤ 128 entries or 1 MiB, headers plus Content rendering by two lookups) is an item of
  the **authored lane's FIFO** — it is this member's reading, ordinary traffic — with **at most
  one queued admission per flow** (SY-13 rule 4's window: the next chunk is asked for when the
  previous one's transaction committed), and it **never takes the pending-write place**, which
  is for the member's own text only; so a post is never refused for a chunk, it waits for the
  writes ahead of it (at most one chunk per connected flow) plus one control transaction, and a
  chunk waits likewise. Governance-kind entries in a chunk are admitted in that transaction and
  their `CLOSE` and effects run in the **control lane** (the fold's turns). Served reads (SY-25)
  take no turn: they read committed state. *The handoff*: inbound work holding the writer ends
  its transaction and the next turn belongs to whichever lane is due; nothing stands aside on a
  timer. *Proof*: the B3 duty-cycle act
  (SY-27 slot (a)) under continuous posting by all six heavy authors asserts, besides the
  render, that y1's fold completes the newcomer's grant (the run record's first event) within
  the act's window while every author keeps posting without pause; mutant: the room turn takes
  the writer with `try_lock` and stands aside when it is held (the prototype's shape): the grant
  never folds on y1, the newcomer is never trusted by y1 and never renders it, red, PRODUCT
  (observed on the prototype in cycle 5a; on the release asset unverified, the run that
  verifies it is this act on v0.4.30). No step in this ADR is granted a "quiet" precondition;
  a future step that needs one is a design defect, not a configuration.

- **SY-30. A member's coverage keeps pace with the room under continuous posting, or
  falls behind by a stated bound; nothing per entry waits.** *(new r13: cycle 5a's design gap,
  `arm-replace.md`: after the wiring repairs the slow member y1, behind a 1.5 s
  per-direction delay, covered 1.3–1.5 positions/s per author against a room writing
  5.7 entries/s, effects owed 1,587 / done 211, its fold 20/69 → 20/89 for 420 s, the
  newcomer's key never issued — B3sp PRODUCT red; the prototype's author names the above-fence
  `pre_context` wait and the coverage rate as design.)* **The rule**: a member's intake of an
  author's feed advances by **whole chunks**, and **no step per entry waits on anything** — not
  on a coordinate, not on another author's coverage, not on an effect completing, not on the
  room writer beyond its place in the authored lane. Concretely: (1) **Content** is rendered in
  the chunk's admission transaction by SY-13 rule 5's two lookups (reader's key, own cut) —
  there is no owed-effects queue for Content, so "effects owed" cannot grow; the chunk is
  rendered when it is committed. (2) **The next request never waits for effects** (SY-1,
  SY-13 rule 4): a flow asks for the next chunk when the previous one's transaction committed.
  (3) **Governance** is closed by `CLOSE` on named prerequisites fetched **directly** (SY-14's
  closure class: one `Range{headers}` for a named coordinate or span), never by waiting for
  this node's coverage of that author to reach the coordinate — the prototype's "source walk
  stops at a parked control position" is exactly the wait this rule forbids — and it runs in
  the control lane, alternating with intake, never behind it. **What the pipeline actually
  does, and what it guarantees** *(changed r14: twelfth review P1; revision 13's "128 entries
  per round trip plus one turn", "about 40 entries/s per author" and "lag at most one chunk plus
  one round trip" were not what this pipeline establishes)*. The pipeline is **byte- and
  entry-limited**: per flow one request is outstanding; an answer carries at most 128 positions
  and at most 1 MiB (SY-12), and a single body may continue across answers up to 16 MiB, so an
  answer may carry one entry or 128. It is **queue-aware**: the answer's admission is one
  authored-lane turn (SY-29) that waits for the authored items ahead of it — this member's own
  queued posts and at most one admission per other flow — with one control turn between
  consecutive authored turns while the control lane has work; the next request is issued when
  that turn commits. **The progress guarantee** is therefore: every received answer is admitted
  within its lane position, each item ahead of it one bounded transaction; every flow re-issues
  on commit; no per-entry wait exists; so intake per flow is one answer (≤ 128 entries, ≤ 1
  MiB) per (supplier round trip + the answer's queue wait), and total intake is the sum over
  flows that have a supplier answering. **Lag is bounded only conditionally**: when the room's
  production, in entries and in bytes, is within this member's **measured** service capacity
  (answers committed per second × their payload, under its actual round trips, lane queue and
  host) **and** suppliers are available for every author's range, lag stays near one answer
  per flow plus one round trip plus the queue wait; when production exceeds that capacity, or
  suppliers are missing, lag **grows** at production minus intake, and the member reports it
  as growing — there is no fixed promise, and no number in this ADR is a target (rows 80/81).
  **Governance latency** is likewise not depth alone: a control entry closes after its
  prerequisite exchanges (each a round trip plus queue wait), the **transfer** of the headers,
  spans, bodies and context lists its closure names (bytes over 1 MiB answers), and the control
  turns its `CLOSE` steps take; the room's content rate enters only through the queue wait and
  the span headers, never as a per-entry gate. Status prints the measured, never a bound:
  `.rooms[].intake: {entries_per_s, bytes_per_s, lag_entries, lag_ms, trend}` with `trend` ∈
  growing | steady | shrinking over the last minute, per room block `behind by <n> entries
  (<t> s), <trend>` (ADR-042's words), and per governance entry the closure measurements
  (headers, bodies, bytes, depth, exchanges). **"Rendered on commit" does not mean "complete on
  commit"** (twelfth review): the admission transaction commits whatever it has — a complete
  body is rendered by the two lookups; an **incomplete body** is staged as SY-18's partial body
  and rendered when its continuation lands, with no second delivery; a body whose **key is not
  yet held** is retained sealed and rendered when the key-package path delivers the key, with
  no second delivery; an entry whose **recipient eligibility is undecided** (this reader's own
  cut not yet folded) is **committed and retained unrendered** *(changed r15: thirteenth review
  P1; r14's "rendered provisionally" was wrong — at the tag `channel.rs:8130-8153` keeps such a
  body unrendered, queues backfill and returns `Deferred`, and SY-25 keeps that defence)*: the
  transaction commits the header and body, the entry is parked on the room's governance
  refresh exactly as an unsettled consent fact is today, and it is re-evaluated at the fold's
  completion event for that cut (rendered if eligible, hidden if the cut excludes it) without
  a second delivery and without blocking any later admission; what ADR-037 R3 shows
  provisionally is the **author's membership** (the roster line, the author's name on entries
  already eligible), which is separate from the **reader's entitlement** to a body and never
  substitutes for it — the existing nonblocking completion and backfill paths, none of which
  blocks the next admission; and **rendering never marks a header context-valid**: rule 2's recursive verifier
  does that, separately, before any governance entry inherits the header's context.
  *Proof* (B3 is the deciding test): the B3 slow-path act (SY-27 slot (c)): y1 behind the 1.5 s
  per-direction delay, every heavy author posting continuously at B3's measured rate; asserts,
  through status, that y1's `trend` for each heavy author is `steady` or `shrinking` after the
  first minute (the lag it settles at is recorded, not asserted), that y1's fold completes the
  newcomer's grant and issues its key (the run record's events 1 and 2), and that the newcomer
  renders y1; mutant (**the prototype's shape**): a Content entry's rendering
  waits on its `pre_context` coordinates being covered (the per-entry effect of cycle 5a): the
  lag grows without bound at the room's rate minus y1's effect rate, the grant never folds,
  the key is never issued, the newcomer never renders y1, red, PRODUCT — observed on the
  prototype in cycle 5a (`r5a-B3sp-arm`), on the release asset the same assertion is the
  round-2 base row (heavy authors never rendered). Cycle 5b is built from this rule and SY-29's
  lanes.

- **SY-1 (I-1). A request in flight is never cancelled because an author's head moved.** A newer
  head only adds positions to what is wanted.
  - *Closes*: items 1 and 12; part of 9.
  - *Changes*: R2: SY-14, SY-15. R1: R1 step 1 (no supersede or preempt for head growth, at all;
    the trial's "after one admitted entry" was a measurement step, not the rule, finding 15), then
    R1 step 2 (without step 2 this regresses B3, see "The considered alternative").
  - *Deleted*: the three replacement sites (`bounded_sync.rs:1553-1560, 4108-4121, 5653-5664`),
    `HINT_TURN`, and `hints.rs` `newer_pending`.
  - *Proof*: extends `a_newcomer_reads_the_whole_history_proof.rs` with a B1 act: an earlier late
    joiner present, two authors posting 1 a second, a newcomer joins, every member posts "hello to
    n-new". Within 30 s of `joined`, `vox room read` on the newcomer shows every member's hello.
    v0.4.30 is red, verified (57.5 s and 88.9 s; `B1-base`, `B1-base2`); the trial build was
    23.3 s. Second act: one author posts 2 a second behind a slow path of 300 ms; after 150 s the
    reader's `vox status` member line shows that author at most 50 behind. v0.4.30 is red by
    investigation (3 of 487 held, `rca-direct-serve300`, knob); verified by the same shape on the
    release asset through FG-5's forwarder, which is to run before the fix lands. Mutant (both):
    cancel the requests in flight for an author when its known size grows; both acts go red,
    PRODUCT. Acceptance: 30 s; 50 behind.

- **SY-2 (I-2). A peer that answers in T seconds delays no request toward another peer by more
  than one exchange.**
  - *Closes*: item 2; part of 14.
  - *Changes*: R2: per-peer requests (SY-15) and any holder answers (SY-16). R1: R1 step 4.
  - *Deleted*: `PhysicalSlot`'s one-Public rule and `BOUNDED_SYNC_RUNNING_SLOTS` (R2).
  - *Proof*: same file, a B2 act: one member behind a slow path of 1.5 s, the room quiet, a
    newcomer joins. Within 5 s of `joined` the newcomer shows the fast members' hellos. v0.4.30 is
    red, verified (52.5 s and 150.8 s, ADR-045 E-1 on the release asset; 90.3 s and 95.3 s by
    investigation, `B2-base`); the trial build was 1.2 s. Mutant (R2): one request in flight per
    node; red, PRODUCT. Acceptance: 5 s (ADR-045 J1(a) adopts 30 s for every fast member's hello
    and 60 s for the slow member's own; this act is stricter because the room is quiet).

- **SY-3 (I-3). Admitting an entry needs only its author's signature and chain. A room's
  governance is current once every author's control entries up to its known size are held, and
  the fold decides from control entries and the signed context summaries of the entries they
  name.** *(changed: findings 3, 17; changed r3: N2, N11, N12; changed r4: third review P1
  "inherited summaries", P1 "required ancestors", P2 "migrated cuts"; the replace arm's two
  design findings.)* **What is bounded, and what is not** *(r4)*: the facts the fold *waits on*
  are the governance kinds (Governance, Checkpoint, Termination: 1, 2, 8) and the key packages
  (6), whose number is bounded by membership and key events, independent of how many messages
  the room carries. `ContextUpdate` (7) is also a control kind (`is_control()`,
  `log/history.rs:60-79`) and is written per writer activity: the replace arm measured 21 % of a
  heavy author's entries as `ContextUpdate`, so "every author's control entries" is *not* a
  bounded set, and revision 3's claim that it was is withdrawn. The fold never waits on a
  `ContextUpdate` as such: a context coordinate that names one is validated against the header
  the control proof carries (every control leaf of a `ControlRange` answer is an expanded
  header, `ControlToken::Leaf`, `log/history.rs:1723-1741`), and a `ContextUpdate` above the
  governance frontier that no context names is never a prerequisite. What made the slow heavy
  author y1 never current in both arms was not the fold but the *rate* at which its control
  enumeration advanced (8 expanded headers per 1.5 s page, 1.9 positions a second against a room
  writing 6 a second); SY-12 r4 therefore carries up to 128 control positions per `ControlRange`
  answer and SY-13 r4 admits an answer in one store transaction. The fold's rule, the same on
  every node:
  1. *Input.* Every held control entry (kinds 1–8) of every author, each with its signed header:
     position, `prev_hash`, `seen` references and the `pre_context` hash naming the control
     context the writer had applied (`log/history.rs:764-818` reads it today); and, for each
     content entry a control entry names in its `seen`, that content entry's signed **header**
     (its `pre_context` is the writer's signed, control-only summary of everything in its past).
     Content bodies are never input. Content headers not named by a control entry are not input.
  2. *Causal past.* For ADR-007 G-29's "strict causal past" and G-31's "causally descends", the
     past of a control entry E is: E's own earlier control entries; every control coordinate
     `(author, seq, hash)` named in E's `pre_context`; every control entry named in E's `seen`;
     every control coordinate named in the `pre_context` of a content entry named in E's `seen`
     or standing immediately before E on E's own chain; and recursively the pasts of those
     control entries. The recursion never enters a content entry's past beyond its own header: a
     content header's `pre_context` is its writer's signed, control-only summary of its past
     (`governance/sparse.rs:518-520` already refuses a content entry that changes the control
     context without a control). **What that summary is worth** *(r4: third review, P1 "inherited
     summaries")*: a writer cannot underclaim its *own* author's controls (its context must
     cover its own previous control's post-context, checked against the held control chain), so
     for the facts that confer authority, which are creator-signed certificates and revocations,
     the creator's own content carries a summary that is always exact. A writer can underclaim
     *another* author's content it references (the C1/C2 attack); that is caught wherever the
     reference is validated (rule 3: a control entry's `seen`, and the content entry immediately
     before it on its own chain) and is not caught for a reference buried deeper in its own or a
     colluder's content. *(changed r6: fourth review P1-4; changed r7: fifth review P1-2,
     whose "trustworthy once the author's following control validates" rule deadlocked on a
     quiet author and on two writers referencing each other, and whose whole-run walk could
     reach below a fresh fence; changed r8: sixth review 2, the colluding content author D whose
     K1 underclaims and whose K2, with an empty `seen`, is referenced by admin B's removal.)*
     **The rule, on preceding facts only**: a content header K of author D is **verified** when
     its `pre_context` covers (per author, a position at least as high and the same hash at an
     equal position) (i) the verified `pre_context` of **D's own immediately preceding entry**,
     whatever its kind: a content predecessor is verified by this same rule, recursively back
     along D's chain to D's previous control entry (which is held as a witnessed header and
     validated by rule 3 through its own closure, fetched as a prerequisite if missing; **never
     "at or below `control_through(D)`"**: r10, eighth review 2) or to D's fence (vouched for by
     the baseline); and (ii) the verified
     `pre_context` of each header K names in `seen`. So D's K2 is verified only through K1, and
     K1's underclaim of the creator's X (C2 omitted) is refused at K1, which keeps K2 unverified
     and B's removal E, which references K2, **inert**: a referencing author never inherits more
     than the referenced chain actually carries, whoever wrote it; a `seen` reference to a header at or below its author's fence is taken as
     verified by the baseline (the certified fence is the verification boundary: the creator
     folded that author's chain through it, which is the trust Q7 accepts), and a reference to a
     control entry is verified when that entry is validated by rule 3. The recursion runs only
     over **earlier** entries (a `seen` reference names an entry the writer had already seen, so
     the reference graph is acyclic), stops at every fence and every control entry, and needs no
     future entry: an honest author that posts X and goes quiet leaves X verifiable from X's own
     `pre_context` against its previous control and its `seen`; two writers whose controls
     reference each other's content (EA names XB, EB names XA) verify XA and XB against their
     authors' previous controls, never against EA or EB. A control entry E of D is validated
     (rule 3) when D's content run since D's previous control, K1 … Kn, is verified this way and
     E's `pre_context` covers each; that run is bounded by what D wrote since its fence (above a
     fence nothing older is needed; without any fence it is bounded by D's writing since its last
     control, which an author that never writes controls can make long, the same growth point 3
     of SY-27 states). An unverified summary keeps E **inert**, never authorizes. So D's removal E
     after K1 (referencing the creator's X under C1) and K2 is refused as "underclaims parent
     control" at K1 exactly as the shipped validator refuses it (`governance/sparse.rs:509-550`),
     and `authority.rs:207-237` never selects C1; the same holds when K1 and K2 are D's and E is
     B's (act (iii-c)). Every header this recursion needs and this node lacks is demand (SY-14's
     ancestry class), fetched singly with its witness.
     **The effect consumer, migrated** (r8: sixth review 3; the prototype's time to access grew
     25.3 → 48.7 s when the pre-fence history was doubled, and the reviewer traced it to this
     loop): `PendingReceived::prepare_received_effect` (`pending_received.rs:134-147`) walks
     every coordinate of a received entry's `pre_context`, content entries included, and demands
     a validated header **and completed control effects** for each. Under the fence it is
     replaced by **baseline-aware resolution**, for the effect loop and for every visibility
     consumer that reads it (`control_effects_complete`, `body_eligibility_after`, the doctor):
     **the baseline resolver**, one algorithm shared by rule 3's closure, the effect consumers
     and the doctor *(changed r11: ninth review 3)*. *Input*: a coordinate `c` = (author A,
     position p, hash h, kind when named) that some entry names, and the installed baseline
     with A's fence `f_A`. *Steps* *(changed r15: thirteenth review P1 "cover before every
     fast path"; r14's step 1 returned on a table (b) match before 2a/2b, so a context-invalid
     governance entry — a `ServiceShare` G underclaiming C2, listed in (b) with its inert
     disposition and in (d) with its `exposed` frontier — resolved without imposing its cover
     requirement)*: **(0) context first, for every control-kind coordinate below the fence,
     before any return**: if table (d) lists (A, p), the namer's cover requirement is the row's
     `exposed` frontier; otherwise the coordinate is certified context-valid and the namer's
     cover requirement is its declared post-context (one context list fetched by digest, 2b
     below, plus the coordinate itself); this requirement is attached to the namer's cover check
     whichever branch returns next. (1) if the baseline lists (A, p) in table (b): h and the kind must equal
     the listed row's, and c **resolves at once** with the disposition the row records; a
     **different hash is a checkpoint dispute, never fork evidence** *(changed r12: tenth review
     P1 "dispute, not fork")*: a baseline row is the creator's assertion about A's history and
     the naming entry is one signed object, so neither is two contradictory A-signed objects
     (SY-13's definition); the node fetches A's witnessed header at that position (one header,
     SY-14's closure class; the naming entry is PENDING meanwhile) and decides on it — A's header
     bears the baseline's hash: the namer named an object A never signed, REFUSED (`names a
     coordinate its author never signed`); A's header bears the namer's hash: the **checkpoint**
     is wrong, refused and reported exactly as the boundary-frame case (`creator checkpoint
     <hash> disagrees with <A>'s chain`, `checkpoint-dispute:<room>`), the node falls back to
     point 4 and the coordinate resolves as terminal evidence under that; two A-signed headers
     at that position: SY-13's fork, said as SY-13 says it. No effect below the fence is
     replayed in any branch; (2)
     else if p ≤ `f_A`: c needs its **single witnessed header** (one `Range{headers}` of that
     position, SY-14's closure class) and the exact binding checks — signed by A, hash h,
     position p, the named kind — and is then **terminal historical evidence**: it resolves, and
     it is never an instruction to resolve its `seen`, its predecessor or its old effects,
     whatever its kind; **but a pre-fence control-kind coordinate still owes the namer a cover
     requirement** *(changed r14: twelfth review P1; r15: now computed in step 0 for listed
     coordinates too)*: (2a) if the baseline's table (d) lists
     (A, p), the namer E must cover the row's **`exposed`** frontier (not c's declaration, which
     is certified invalid); (2b) otherwise c is certified context-valid (every control-kind
     entry below the fence is settled on the creator) and E must cover c's **declared
     post-context**: c's header carries `pre_context` as the digest of a context list
     (`log/entry.rs:248,393`; `sparse.rs:456` resolves it with `history_context`), so the namer
     fetches that one list by digest from any holder (SY-14's closure class, the `contexts`
     object of SY-18) and covers it plus c's own position — **one header and one list, no
     recursion, no walk**; in both branches E's cover check runs against that frontier, and E's
     authority query's baseline scope is bounded by E's covered frontier (SY-27 point 3 (d)), so
     the controls c's refusal exposed (C2, below the fence and listed in (b)) are in E's scope
     exactly when E covers them, and an E that does not is REFUSED as underclaiming; (3) else
     (p > `f_A`, or no baseline) the resolver returns **not baseline** and rule 3's
     closure owns c. *Output*: resolved(disposition) | terminal | not baseline | refused.
     *Stopping*: one header at most, no recursion. **Above the fence** *(changed r9: the round-2 measurement,
     `arm-replace.md`; revision 8's "resolved as today" is withdrawn)*: what a received
     entry's coordinates above the fence gate depends on the entry's **kind**, in one direction,
     and SY-13 rule 5 is the rule for Content:
     - a **governance-kind** entry (kinds 1 and 8; a key package, kind 6, by its header only,
       r11) is validated by rule 3's `CLOSE` against every coordinate it names and the spans
       they imply, fetched as prerequisites, and is pending until they are held: that is the
       fold, and it is what `prepare_received_effect` keeps for these kinds;
     - a **Content** entry (and a `ContextUpdate`, Checkpoint, StepPolicy, SessionFloor or
       PrivateSupport) is admitted by SY-13 rule 4 and **rendered without resolving its
       coordinates**: its `pre_context` orders it and is read by rule 2 only when a later
       governance entry references it. Rendering needs (i) the reader's key for the author's
       chain (the recipient's own, `key_delivery_pending` otherwise: ADR-042's words) and (ii)
       the reader's own eligibility cut (`body_eligibility_after`, which reads *one* coordinate,
       the reader's readmission, from the baseline or a held fact); the author's membership at
       that position is the fold's egress decision as the fold currently knows it, shown
       **provisional** while the fold is behind (ADR-037 R3's `provisional: bool`, unchanged)
       and withdrawn from display when a later-folded removal cuts it. The shipped loop
       (`pending_received.rs:134-147`, demanding a validated header and completed control
       effects for every coordinate of every kind) is replaced for these kinds by that
       two-input check. **Why this admits nothing the author lacked authority for**: admission
       already requires the author's signature and a witness under its accepted head (SY-13);
       authority is never decided by the coordinate loop but by the fold (ADR-037 R2/R3), which
       the two-input check consults as today and which marks the row provisional until current;
       a removed author's posts after the removal are hidden the moment the removal folds, as
       today for live delivery. The coordinate loop protected nothing beyond that: it delayed
       rendering until *every* other author's control coverage reached the named positions,
       which is what froze the slow member y1 (its owed effects 10 → 409 in 180 s, each parked
       on another author's newest control position).
     Membership and readmission checks are unchanged in meaning: they read the baseline's
     per-member record plus the post-fence facts. So the work a received entry costs is *(changed
     r12: tenth review P2 "constant-work claim"; "bounded by its own coordinate count, ≤ 2,048"
     was false, a context bounds one list, not a closure)*: for a governance kind, its pinned
     closure (rule 3's `CLOSE`: finite, fixed by the entry's bytes, never enlarged by later
     arrivals, never below a fence, its headers, bodies, bytes and depth measured per entry by
     the prototype); for every other kind two lookups; and never a wait on other authors'
     control production or on the pre-fence chains.
  3. *Validation.* A control entry E is validated when: its author's signature and chain verify
     (SY-13); every coordinate its `pre_context` names is the exact validated control at that
     position (hash, room, scope, control kind: `validate_control_coordinate`,
     `governance/sparse.rs:587-612`, kept whole), **held as a witnessed header and closed under
     governance dependency** *(changed r9: seventh review P1-1; changed r10: eighth review 1 and
     2; revision 9's "a `ContextUpdate` coordinate is satisfied by its exact header alone" is
     withdrawn: a witnessed header proves the entry exists, not the governance history its
     context summarizes, and the reviewer's attack, the creator's C2 then `ContextUpdate` U,
     with B's removal naming U on a receiver that holds C1 and U but not C2, would select C1 in
     `authority::Query` and accept the forbidden removal)*. **The pinned closure, as an
     algorithm `CLOSE(E)`** *(changed r11: ninth review 1, 2 and 3; revision 10 followed only a
     summary carrier's declared context and required every governance body, which a malicious
     carrier underclaiming its parents and a key package addressed to a readmitted member both
     defeat)*. *Input*: a **control-kind** entry E — governance kinds 1 and 8, typed-policy
     kinds 3 (StepPolicy) and 4 (SessionFloor), key packages (kind 6), and the summary carriers
     `ContextUpdate`, Checkpoint and PrivateSupport — with its witnessed header, and its body
     when its kind is governance or typed-policy (never for a key package, whose body is
     ciphertext for one recipient: a package is **authenticated by its header** and its closure,
     and **installed** by its recipient from the body under SY-25's gate, two different things);
     the installed baseline (fences `f_A`); and the room's **closure index** (below), from which
     per author the **validated frontier `closed_through(A)`** is read. **Two frontiers, two
     owners** *(changed r12: tenth review P1 "received coverage versus validated closure";
     revision 11 identified CLOSE's stop with SY-14's `control_through`, which advances on
     receipt and so put received-but-unclosed controls below the stop)*:

     | value | meaning | owner and producer | consumers | crash points | mutant |
     |---|---|---|---|---|---|
     | `control_through(A)` (SY-14) | **received coverage**: the highest position through which every control header of A is held and every needed body is held or `not for you` | the room's sync demand state; the receiver advances it when a header or body lands (SY-13 rule 4's owned write) | SY-14's demand (control wanted = `control_through + 1` … size); status `control: <n> behind`; SY-28's adoption gap | none: derived from what is held, recomputed on open | advance it on a `Have` (SY-13 rule 3's act) |
     | **closure index** (A, position) → (hash, kind, **context** ∈ {valid, invalid}, **disposition** ∈ {applied, inert(reason), content-verified}) *(changed r13: eleventh review P1 "context-invalid carriers": causal-context validity and semantic disposition are two columns)* | every position of A this node has **closed**: a control-kind entry whose `CLOSE` finished — **context valid** when its deps resolved and rule 2's cover check held, whatever its semantic outcome (an unauthorized act is settled, inert, and context-valid: a reusable boundary); **context invalid** when it underclaims its parents or names an object its author never signed (an underclaiming carrier U: its hash is recorded for fork detection and SY-13's admission, and it is **never a boundary**: step 3 does not stop at it, every namer of U expands U's deps afresh, and U's declared context is never used as anyone's post-context); a Content or other non-control entry whose header passed **rule 2's recursive header verifier** (signature, chain, its `pre_context` covering its `seen` parents' and predecessor's headers, each of those verified the same way) is context-valid, content-verified | the governance fold under `governance_work` (ADR-040 NW-1); written in the **same transaction** as the entry's disposition | `CLOSE` step 3's hash check, step 2's stop; the creator's fences (SY-27 point 3: a fence is at or below `closed_through(A)`); the doctor's `control_current` | the index row and the disposition are one write, so a kill leaves neither or both; `closed_through` is never stored, it is the highest contiguous closed position read from the index on open, so two owners cannot drift | treat held headers as closed (stop at `control_through`): the hidden-certificate act with C2 and E in one chunk is red |
     | `closed_through(A)` | **validated frontier**: the highest position such that every position of A at or below it is in the closure index (or at or below `f_A`, where the baseline is terminal) | derived from the closure index; never written | `CLOSE` step 2's stop `s_A`; SY-27's fences | — | — |

     The two clocks are **derived independently and neither bounds the other** *(changed r13:
     eleventh review "frontier ordering"; r12's "`control_through` ≥ `closed_through` always"
     was false: a key package addressed to this node is closed on its header while SY-14 still
     waits for its body, so the validated frontier can be ahead)*: no reading of their
     difference is made anywhere, nothing waits on either becoming equal to the other, and
     neither is repaired by a body prerequisite or a coverage gate in `CLOSE` (no global
     coverage gate: a received entry is closed by `CLOSE` on its own named prerequisites;
     SY-14's producer stays as it is — it measures receipt — and only the stop's consumer
     changes, from the received clock to the validated frontier). *Steps*:
     (1) **deps(E)** = E's own previous entry, every coordinate E's `pre_context` names (for a
     carrier, its declared context list), and every coordinate E's `seen` names. (2) For each
     author A named in deps(E) let `p_A` be the highest position named for A and `s_A` =
     max(`f_A`, `closed_through(A)`) its **stop**. (3) Every named coordinate c of A with
     position ≤ `s_A` goes to the baseline resolver (above) when ≤ `f_A` (its branches 2a/2b
     supply the cover requirement for control-kind coordinates: table (d)'s `exposed` frontier
     or the fetched declared context, r14), else must equal the
     **closure index's** hash at that position (defined for content positions too, by rule 2's
     verifier) **and that row must be context-valid**: a context-invalid row (r13) is not a
     stop — c's deps are expanded as in steps 4–5 as if c were above the stop, c itself stays
     refused, and E's cover check is made against the control those deps expose, never against
     c's declaration; a different hash means the naming entry names an object A never signed as far
     as this node knows: the entry is **PENDING** on A's witnessed header at that position
     (SY-14's closure class), and when it arrives either it matches the namer (then the index
     was wrong only if two A-signed headers at one position exist, which is SY-13's fork
     evidence, said as SY-13 says it) or it matches the index (the namer is REFUSED: `names a
     coordinate its author never signed`); one signed object against another node's record is
     never fork evidence. (4) For the span (`s_A`, `p_A`] of
     every named author A, the closure needs A's **witnessed headers** at every position in the
     span (one `Range{headers}` of the span, or the control chunk when the span is chunked:
     SY-14's closure class); this is the walk that finds the control entries a carrier's
     declared context hides — C2 on the creator's chain below X, whatever U declares. (5) Every
     control-kind entry in those spans is validated by `CLOSE` itself, lowest position first
     (its body fetched when its kind is governance or typed-policy; **a key package needs no
     body**: step 5 authenticates its header and runs `CLOSE` on its own deps); content entries
     in the span are **verified by rule 2's recursive header verifier** (signature, chain, and
     their `pre_context` covering their `seen` parents' and predecessor's headers, those
     verified the same way — the verifier that catches the preceding-Content-carrier variant;
     it recurses through headers, never through `CLOSE`) and enter the closure index as
     content-verified; "no `CLOSE`" for content never means "no verification". (6) Anything
     missing — a header, a governance body — is **demand** in
     SY-14's closure class and E is **PENDING**, inert, re-evaluated when the arrival lands
     (rule 4); nothing waits on a coverage number. (7) All present: the binding checks on every
     named coordinate (hash, kind, position, author), rule 2's **cover** check on E's declared
     context (below), and E's own typed evaluation over V (`authority::Query`, the policy and
     StepPolicy/SessionFloor evaluations, ADR-031) → **VALID** (E enters the closure index as
     valid; `closed_through(A)` advances while contiguous) or **REFUSED(reason)** (recorded in
     the index as inert; G-29). *Output*: VALID | REFUSED | PENDING(demand). *Stopping*: every
     named position is finite and ≤ the namer's own view, no coordinate is examined twice (the
     closure index and the per-author stop), and the walk never goes below a fence (the
     resolver terminates there); so `CLOSE` is **finite and pinned** to E — its members are
     determined by E's bytes and the headers they name, never by any author's coverage;
     `closed_through` is a stop that only shortens it, never a gate, and `control_through` plays
     no part in it. "**Already validated**" means **in the closure index as context-valid**
     (applied, inert-settled, or content-verified): SY-13's admission of a header, a witnessed
     header merely held, or a context-invalid row, is not validation (r13). *The cached-U order*
     (eleventh review): U arrives first, is refused for hiding C2 and recorded context-invalid;
     E then arrives naming D@U and C1: step 3 finds U's row context-invalid, expands U's deps
     (creator@X → the creator's span → C2), and E's cover check must cover the control through X;
     E names C1 only: REFUSED. Were U a boundary, E's closure would stop at U and
     `authority::Query`, which selects certificates within the action's causal scope
     (`authority.rs:207-237`), would never see C2 however well indexed it is. *Hand-run against the ninth review's attack*: B holds C1
     (non-expiring) and superseding C2 (expiring); the creator's content X carries C2 on the
     creator's chain; colluder D signs `ContextUpdate` U whose `seen` names X and whose declared
     context names only C1; B's removal E names D@U and C1. `CLOSE(E)`: deps(E) ∋ D@U, U is a
     carrier so `CLOSE(U)`: deps(U) ∋ creator@X, so step 4 walks the creator's chain from its
     stop to X and finds C2 (a governance kind) in the span; step 5 validates C2; U's declared
     context must cover X's `pre_context` and the creator's control through X (rule 2's cover
     check) — it names C1 only, so U is REFUSED as underclaiming; and even were U accepted, the
     closure index now holds C2 valid and `authority::Query` refuses C1's authority for E. The
     preceding-carrier variant (X buried in U's own previous entry K): K ∈ deps(U); when K is a
     carrier `CLOSE(K)` makes the same walk, and when K is content rule 2's recursive header
     verifier (step 5) requires K's `pre_context` to cover X's and the creator's control through
     X, which exposes C2 the same way; the same result in both delivery orders (U before C2 or C2
     before U: step 6 holds E pending until the span's headers and C2's body are present). *The
     readmission case*: B's key package K addressed to M, M removed and readmitted by the
     creator's S whose context names B@K; `CLOSE(S)` needs K's **header** and K's own deps, never
     K's body, which every informed provider rightly refuses M (SY-25); S validates; M's
     installation of K stays gated as before (it does not need K: a package after readmission is
     what it uses). **Its size is not claimed**: the closure is finite but not constant; it can
     include every control entry of each named author between its stop and the named position
     and the content headers of that span (the 2,048-coordinate limit bounds one context, not a
     closure). What is claimed is the **narrower progress claim**, in two distinct parts: (a)
     **independence from future arrivals** — `CLOSE(E)` is pinned: nothing that arrives after E
     can enlarge E's closure, and E waits on nothing but its own named prerequisites, never on
     another author's coverage or on a flow going quiet; (b) **not** independence from
     accumulated history — E's closure can include every control entry and content header of
     each named author between its stop and the named position, so its cost grows with what was
     posted since that author's fence or last closed position; what bounds it in practice is the
     fence cadence and the frontier advancing as entries close (no header twice, none below a
     fence). The cost per entry (headers fetched, bodies fetched, bytes, depth) is measured by
     the prototype's per-entry closure measurements (build item 4), not asserted here. In the measured room a governance entry's `pre_context` names about ten
     coordinates and a `ContextUpdate`'s a similar number; the span walks are what the
     measurement adds. And E's declared context, **the cover check** of rule 2, **covers** (per
     author, a position at least as high, and the same hash
     at an equal position: the "underclaims parent control" check, `:521-550`, kept) the context
     of E's own previous control entry, the post-context of every control entry in E's `seen`,
     the `pre_context` of every content entry in E's `seen`, **and the `pre_context` of E's own
     previous entry K when K is content, where K is itself validated the same way against its
     `seen` parents' headers** (the one content hop on E's own chain; r4). So delegate D's removal
     E whose `seen` names the creator's content X, or whose previous entry K names it, while the
     declared context omits the certificate C2 that X's `pre_context` carries, is refused as
     "underclaims parent control", and `authority.rs:207-237` never selects C1 for it. Through U:
     B's removal names the creator's `ContextUpdate` U; U's `pre_context` names C2; the closure
     fetches C2's header and body and validates it; `authority::Query` then sees C2 and refuses
     C1's authority, in either delivery order (U before C2, or C2 before U). Headers are fetched
     for every coordinate and every span position, bodies for governance and typed-policy kinds
     only (rule 4, SY-14); key packages are authenticated by header. **The acts** (ninth review
     1 and 2; in `governance_acts_proof.rs`, no new file): *the hidden certificate*: a room on
     the ballast with B holding C1 and C2, the creator's content X on its chain after C2, the
     apparatus colluder D signing U (declared context C1 only, `seen` naming X), B's removal
     naming D@U and C1; on every member the removal is refused and the target's later posts stay
     visible; variants: X buried in U's previous entry K; U delivered before C2 and after it;
     mutant (**the U-terminal shortcut**): treat a carrier as terminal once its declared context
     is resolved (no span walk): the removal is applied, the target's post after it hidden, red,
     PRODUCT; third order (r13, **cached U**): U delivered and refused a minute before E, then
     E; mutant (**refused rows are boundaries**): the closure stops at the cached U, the removal
     is applied, red, PRODUCT; fourth order (r14, **U below the fence**): U is delivered and
     refused on every member, the creator's next fence post passes U (its row in table (d) with
     `exposed` naming the creator through X), a **newcomer installs** that baseline, then B
     submits E naming D@U and C1; the newcomer refuses E (`vox agent doctor` shows the target
     still a member on the newcomer as on every full-record member, and the target's later post
     renders there); mutant (**the resolver makes a listed context-invalid carrier terminal**,
     ignoring table (d)): the newcomer applies the removal and hides the target's later post
     while every other member shows it, red, PRODUCT. *The old package*: B publishes a package K for M while M is offline; M is removed
     and readmitted by S (context naming B@K); M, back online, is a member again within 60 s
     and renders the room's posts after S; mutant (**require all package bodies**): `CLOSE`
     demands K's body for S; S stays pending for ever on M (`not for you` on every provider),
     M's room block reads `verifying …` without end and no post after S renders, red, PRODUCT.
     Acceptance: 60 s each; v0.4.30 reds unverified (the certificate act depends on the sparse
     projection's selection in `authority.rs:207-237`; the run that verifies it is the act on the
     release asset).
  4. *Pending, never a barrier; the fold and key generation own their own progress.* A control
     entry whose check cannot run yet is pending: inert in the fold (ADR-007 G-29's word), not
     applied, not a reason to refuse anything. *(r9: seventh review P1-1.)* The fold is driven by
     governance-kind arrivals and by prerequisite-header arrivals (ADR-037 R2b), runs under the
     room's governance work owner (`governance_work`, ADR-040 NW-1's `GovernanceFold(room)`
     release), and is **never queued behind content effects, never run under a request
     deadline, and never waits on `control_through`**; the **key package a member owes a
     newcomer** is minted by the fold's completion event for that grant (ADR-040's key class,
     SY-15's key demand), owned by the room's key-package queue as today
     (`key_package_queue.rs`), not by any effects worker. So a slow existing member's fold
     reaches a newcomer's grant after: the grant's header, its pinned frontier's headers, and the
     admitting member's chain back to its stop (rule 3's `CLOSE`), each one witnessed header (or
     one control chunk when they are adjacent), at that member's own request rate; nothing in it
     waits on another author's coverage or on a future arrival, and what it costs per entry is
     measured, not asserted (rule 3). Its
     prerequisites are bounded and named: every member of its pinned closure (rule 3) this node
     does not yet hold, header or body, **re-evaluated when any of them arrives** (SY-14's
     closure demand; r10: revision 9's "re-evaluated when that author's control range advances"
     is withdrawn, it was a coverage gate); a coordinate above an author's known size raises a
     `Head` toward its holders; each prerequisite is authenticated by SY-13: signature and a
     witness under an accepted head of its author. A prerequisite no honest holder can ever supply (a
     coordinate no signed head covers; a content position no holder has) keeps that entry and its
     honest descendants pending, harming no one else: an honest writer inherits only contexts it
     validated. Two nodes holding the same control entries and the same named content headers
     compute the same projection: the order is the canonical rank (`governance/canonical.rs`,
     kept), which depends on `seen` among control entries, the context and the hash, and on no
     content body.
  5. *Removal and readmission.* A removal MUST carry the target's newest position its issuer
     holds as a required **content** ancestor: `pending_text.rs:592-600`
     (`GovernanceWrite::RemoveMember`) adds `(target, settled tip)` to `required_ancestors`, and
     `local_history.rs:505-512` already gives a required position priority among the sixteen
     `seen` slots (N12: the revision-2 citation of `consent.rs:622-632` was the grant writer,
     not this one). `authored_context`'s final guard (`local_history.rs:544-568`) is split *(r4:
     third review, P1 "required ancestors")*: a required **control** ancestor is reached when the
     writer's context coordinate for that author reaches it, as today; a required **content**
     ancestor is reached when a `seen` reference names that author at that position or higher
     with the entry's hash, since no context coordinate can (the target's last control may lie
     below its newest post). A target-authored content entry at position p is historical for a
     removal if p is at or below a position of the target named by the removal's `seen`, by any
     control entry in the removal's past, by the `pre_context`/`seen` of a content header in the
     removal's past (rule 2), **or by the removal's cut attestation** (below); otherwise it is
     eligible only if its own signed `pre_context` covers a valid creator readmission superseding
     that removal (G-31, decided from the entry's own header and the control set). An entry's
     eligibility for a once-removed *recipient* is decided the same way (`body_eligibility_after`,
     `governance/view.rs:990-1012`, with `contains_cut` reading contexts and attestations instead
     of the DAG). **Cut attestation** *(r4: third review, P2 "migrated cuts")*: for every removal
     already validated in a store at the first open under this release, SY-26 computes from the
     v0.4.30 DAG projection it still has the highest position of the target in that removal's
     validated causal past, `(removal hash, target, through)`. If this node is the removal's
     issuer or the room's creator, it appends that triple as a governance control entry
     `CutAttestation` (signed; the issuer attests its own removal's cut; the creator may attest
     any removal's, as G-30 gives the creator precedence over membership facts), and every node
     folds the attestation like any control entry, so a fresh joiner receives it in the control
     range and classifies the target's posts exactly as the upgraded holders do. *(changed r6:
     fourth review P1-4, P1-2.)* **An attestation is not an unchecked scalar**: a malicious
     issuer could sign `through` above the target's posts made after the removal and so turn
     unauthorized posts historical. So an attestation is **accepted** only when its `through` is
     at or below a position the attester provably held of the target before the removal: the
     attestation carries the target's header at `through` and the removal entry's `seen` or
     `pre_context` must name the target at or above `through`, or the attester's own content
     entry immediately before the removal (rule 3's content hop) must name it; an attestation
     whose `through` is covered by none of these is refused, and the attester's claim is reported
     (`CutAttestation by <m> for <removal> exceeds what it held`), never applied. A removal whose
     old-DAG cut cannot be shown this way keeps the conservative classification. Until an accepted
     attestation exists a holder uses its locally recorded triple; a fresh joiner with neither
     classifies the target's positions above the removal's named references as not historical
     (hidden, never shown as post-removal content that is not), the conservative side, and status
     says the cut is unattested (ADR-042). An accepted attestation proves a **lower bound** on
     the historical coverage (r7: fifth review P2): two accepted attestations for one removal
     that differ are not equivocation by either signer, and the fold applies the **higher**
     accepted `through`, since each was accepted only on evidence the attester provably held;
     nothing an accepted attestation proved historical is hidden again on a later disagreement,
     and status names the two claims. The creator's checkpoint, when one is made after them,
     carries the accepted bound forward (SY-27 point 3).
     Removals written under this release carry the reference themselves and need no attestation.
     Nothing is deleted, hidden or reset on an upgraded holder: its recorded cut is exactly the
     cut the shipped fold applied (N12).
  6. *Local appends.* The writer's own `pre_context` and `seen` (`authored_context`,
     `local_history.rs:493-541`) stop requiring a canonical prefix descriptor `[1, p]` per `seen`
     tip (`:535-541`, which fails "authored history settled peer prefix missing" for a
     chain-admitted tip; the prototype reproduced it). A `seen` tip of author B at position p
     qualifies when p is an accepted header of B (SY-13) with p ≤ `control_through(B)`; the
     writer's context is the join of the held control frontiers through p (the same frontier the
     fold computed from held control entries), not a tree descriptor's. Required ancestors
     (removals, readmissions as control; the target position of rule 5 as content) are selected
     first and satisfied as rule 5 says. So the first post after a sparse receive and a restart
     succeeds, and a reader validates it by rule 3 (N11).
  7. *Egress.* ADR-037 R3's gate refuses only while the fold has held control entries it has not
     yet folded (`GovernanceFold(room)`, ADR-040 NW-1); a pending fact never holds the gate.
     When a removal applies, its generation fence applies to every send after it, including an
     already-open `Range` or `Have` stream (`source.rs:991-996`'s per-frame authorization, kept;
     SY-25).
  - *Closes*: items 3, 5, 9 and 12.
  - *Changes*: R2: SY-12 (`ControlRange`), SY-13 rule 5, SY-14 (parent headers), SY-15. R1: R1
    step 2. Both: `ValidatedSparseEntry::new` (`governance/sparse.rs:380-420`) takes the control
    parents and the named content headers it holds, no parent receipt; `contains_cut` reads
    contexts and recorded cuts; `authored_context` as rule 6; the removal writer as rule 5.
  - *Deleted*: `preflight`'s parent demands (`admission.rs:940-1030`), `combine_parent`
    (`:544-562`), the `ParentReceipt` and `PrefixReceipt` objects, `push_control_closure`
    (`runtime.rs:999-1026`), the DAG walk in `contains_cut`, the `[1, p]` prefix demand in
    `authored_context`.
  - *Proof*: same file, the B1 act with RcaFrozen's assertions: within 30 s of `joined`,
    `vox agent doctor --room R --node n-new` says "you trust each other" for every member, the
    newcomer's `control_current` (ADR-042 TR-1) is true for every member, every member shows the
    newcomer's hello and the newcomer shows each member's, and no `vox status --json` sample in
    its 300 holds `inclusion header is absent` (v0.4.30: 291 of 300, verified, `B1-base`). The
    governance-revision equality this ADR asserted before is withdrawn: the trial measured "at
    least the sampled revisions" (`rig.py:618-621`), the members themselves end 16/17/17 while
    everything renders, and a counter is not a product outcome (finding 17). v0.4.30 is red,
    verified ("has not trusted you" at 88 s, `/tmp/rca-RcaFrozen/runs/base1`†). Governance acts
    in the same file, each under 120 s: (i) a control entry arrives before a content entry it
    `seen`s and the content entry's author goes offline after a member has its header: every
    member's hello still renders and the doctor still says "you trust each other" (v0.4.30 red by
    code: `preflight` demands the parent's receipt; the release-asset red is owed on this
    staging); (ii) a member is removed, posts twice, is readmitted and posts once: every other
    member shows its pre-removal posts and the post after readmission and never the two between
    (ADR-007 G-31; v0.4.30 passes; kept so the fold rule is proved); (iii) **superseding
    certificate** (N2): the creator delegates to D with a non-expiring certificate, then a newer
    one with an expiry, then posts; an apparatus writer signing as D appends a removal whose
    `seen` names that post and whose `pre_context` names only the old certificate; the target
    keeps reading and writing on every real member and `vox agent doctor` shows it a member
    (v0.4.30 passes by `sparse.rs:521-550`; kept so the check's survival is proved); the same
    act through the content hop (r4): D's removal follows D's own content entry K whose `seen`
    names the creator's post and whose context omits C2; same assertion, same v0.4.30 result;
    (iii-c) the **colluding content author** (r8; corrected r9, seventh review P2-3): the
    creator issues admin **B** a non-expiring certificate C1 and then a superseding expiring C2,
    and posts X carrying C2; the separate colluder **D** posts K1 whose `seen` names X but whose
    context declares only C1, then K2 with no `seen`; B's removal of a quiet target references
    K2 and declares C1, and B meets C2 only through D's K1/K2 path. The staging first shows that
    the removal **would** be authorized under C1 alone (the apparatus asserts C1 is in force on
    every member and the target is a member); then the removal is appended: the target keeps
    reading and writing on every real member and `vox agent doctor` shows it a member (v0.4.30
    passes by `sparse.rs:509-550`; kept so the recursion's survival is proved); mutant: verify a
    content header against its previous control and its `seen` only, not its own content
    predecessor; the removal is authorized under C1 and the target is removed, red, PRODUCT;
    (iii-d) the **fresh-fence pair** (r8): two rooms with identical post-fence traffic whose
    pre-fence context chains differ by a factor of two (300 and 600 `ContextUpdate`-bearing
    entries per author before the creator's fence); a newcomer's time to access and its count of
    prerequisite headers fetched (`vox status --json`) differ by at most 10 % between the two
    (mutant: resolve every coordinate through its validated header and completed effects, as
    `prepare_received_effect` does today; the 600-room's access time grows, PRODUCT);
    (iii-b) a removal by an admin of a quiet target whose last control lies below its newest post
    (r4, P1 "required ancestors"): the removal is appended (no "required governance ancestors
    exceed the authored frontier") and every member stops showing the target's later posts
    within 10 s; (iv)
    **sparse receive, restart, post** (N11): a node joins with anchor above an author's tail,
    receives one unaligned range, is restarted, posts, grants a consent and is read by every
    member within 10 s of each (v0.4.30 red unverified: the prototype's poisoned first post is
    the evidence, `proto-range-sync.md:23-24,38`). A relay act extends `key_package_proof.rs`:
    two members 75 ms apart per hop read each other within `ONE_TIME_WAIT_MS` (`actor.rs:327`);
    v0.4.30 is red, verified (not in 180 s, `r30-relay75-b10x2`, release asset through the
    proxy). Mutants: require every `seen` parent's header before admitting an entry (the doctor
    assertion goes red, PRODUCT); apply a removal's cut from `seen` alone without the readmission
    test ((ii)'s post after readmission is not shown, PRODUCT); skip the content-header coverage
    clause of rule 3 ((iii)'s target is removed, PRODUCT); require the `[1, p]` descriptor ((iv)'s
    post fails, PRODUCT); satisfy a content ancestor by context coverage ((iii-b)'s removal is
    refused, PRODUCT). Acceptance: 30 s; 0 of 300; 10 s. On the fleet: ADR-045 J1(b)–(d),
    J2(b).

- **SY-4 (I-4). Every position at or above an author's anchor is asked for until its body is
  held, its retention has expired, or every holder has said it is not for this node. Meanwhile a
  held header without its body is shown as "not received yet".** *(changed: finding 1.)*
  - *Closes*: items 4 and 9 (display); part of 7.
  - *Changes*: R2: SY-14, SY-15 (ask every holder, SY-25's `not for you` ends the asking). R1: R1
    step 3. Both: the placeholder row in `vox room read` (ADR-008 LS-33; ADR-042 owns the words),
    and the server serves any position at or above the requester's anchor (SY-25's gate applied).
  - *Deleted*: the 128-position live window and its floor (`sparse.rs:2577-2605`), `LiveRetry`
    and `LiveAdvance` (`runtime.rs`), the silent skip (`channel.rs:7902-7903`).
  - *Proof*: same file, a B3 act (optional proof, expensive; mandatory on the fleet, J1). Within
    120 s of `joined`, `vox room read` on the newcomer shows every member's hello, the slow
    member's included. A second assertion: an apparatus member serves one entry's header and
    withholds its body (`not held here`); the reader's `vox room read` shows that row as "not
    received yet" within 10 s, and shows the text once the body is served by another member. A
    third: an apparatus holder advertises a covering interval and answers every `Range` for one
    position short, one entry fewer than asked, with no `Missing`; the honest member supplies the
    missing text within 20 s (finding 5). v0.4.30's red for the first assertion on the B3 shape
    is **not measurable yet**: on the release asset the newcomer cannot join (item 88, SY-10),
    and every earlier B3 "never" count came from the unpaged reader (SY-23); the verified reds
    are B2's (SY-2) and the B3 slow-path baseline on the corrected reader (`arm-repair.md`
    B3sp-base s2: n-old2..6 at 213–279 s, n-old1, z1 and y1 never), with the fleet's J1 stage as
    the mutant receipt once SY-10 lets the newcomer in. The row assertion is red by code (the
    row is absent, `channel.rs:7902-7903`). No build has passed the first assertion yet: the
    repair arm's B3 never reads the slow heavy author; the replace arm's interim reads 7 of 8.
    Mutants
    (R2): ask only for positions within 127 of the known size (first assertion red); keep asking
    the short holder (third assertion red); PRODUCT. Acceptance: 120 s; 10 s; 20 s.

- **SY-5 (I-5). A reader N entries behind an author catches up as fast as the path and the
  holders allow; the gate proves at least 1,000 entries a minute, for any N, under these
  conditions: bodies of at most 1 KiB, one connected holder that is not under load, a path of at
  most 100 ms round trip.** *(changed: finding 16; changed r4: the decider's ruling, ledger row
  39: Q3 closed.)* The decider: "any reason not to go faster?"; 1,000 a minute is "a minimum";
  "I'd like it to just go until the bandwidth doesn't permit faster". So 1,000/min is the floor
  the gate proves, to be raised to what the chosen mechanism measures on the fleet, and **no
  rule of this ADR exists as a rate limit**. Every throttle, cap or pacing rule the design keeps,
  and why it is needed: K = 2 requests in flight per peer (so a slow peer costs only its own
  requests, SY-2, and two answers can stream while one is verified); 128 entries and 1 MiB per
  answer (one verification unit, one frame budget: ADR-036 H-4's memory bound); 64 MiB of answer
  permits per node and 8 MiB retained per room (memory, SY-24); the 20 s deadline (so a silent
  holder frees its slot); `Busy`'s retry time (the holder's own serving budget, ADR-044 RD-8);
  the port backoff for an unreachable peer (ADR-025 D5, nothing to do with a reachable one); the
  250 ms coalescing of `Have` updates and the 30 s heartbeat (metadata, not data). Catch-up speed
  is therefore permits × answer size over the round trip, bounded by the path and the holders'
  reads, never by a timer. At 100 entries a minute (this ADR's earlier floor) the operator's
  4,932-entry backlog takes 49 minutes; larger bodies and slower paths scale the proved floor by
  bytes and round trips and are reported, not asserted.
  - *Closes*: item 7; part of 6.
  - *Changes*: R2: `Range` has no window (SY-12); requests of 128 entries, two in flight per
    holder. R1: R1 step 3's anchored server gate.
  - *Deleted*: `MalformedBundle("live request is outside the bounded newest window")`
    (`history_budget.rs:1060-1063`) and the window test at `server.rs:828-848`.
  - *Proof*: L1 shape (a reader holding an author's feed through 87 of 5,087, quiet room, 330 B
    posts), a mandatory act of `a_newcomer_reads_the_whole_history_proof.rs` (the staging is a
    seeded store, not a slow member, so it needs no knob and no fleet): within 5 minutes `vox room
    read` on the reader shows the author's row 88 and its row 5,087 by their text, and `vox
    status` shows the author 0 behind. v0.4.30 is red by investigation (stays at 87,
    `L1-quiet`, the trace binary); the same shape on the release asset is to be run before the
    fix lands and recorded as the verified red. Mutant (R2): refuse a `Range` that starts more
    than 127 below the holder's size; red, PRODUCT. Acceptance: 5,000 entries in 5 minutes. On the
    fleet, ADR-045 J1(g) is to adopt the same floor and conditions (sibling change).

- **SY-6 (I-6). A served request starts within 100 ms of its preamble, even when the serving node's
  actor is saturated.**
  - *Closes*: item 14; part of 8.
  - *Changes*: ADR-044 RD-16 (a served request is admitted without the actor) and RD-8 (serving is
    a read); R2 adds that any holder answers (SY-16), so a heavy author is asked less.
  - *Deleted*: the serving path's wait in the actor queue (`actor.rs:2554` → `:11928`; ADR-044
    RD-16) and the stand-aside for the room's pending write when serving (`source.rs:744-761`;
    ADR-044 RD-8).
  - *Proof*: the 100 ms is reported per run from `vox status --json` (`served_wait_ms`, SY-20),
    not asserted: a timing that is not what a person sees is not a gate (AGENTS.md, "Tests"). What
    is asserted is what a person sees: ADR-044 RD-3 (each reader shows each of the busy author's
    posts within 5 s) and SY-10 (a join through that author). Mutant: as ADR-044 RD-16's.
    Acceptance: RD-3's 5 s; SY-10's 15 s.

- **SY-7 (I-7). A status line names a fault only when there was one. A cancellation by either side
  is shown as a cancellation and is never counted as a failure. "Last received" moves when an
  entry or header arrives, and only then; "last entry" moves when an entry with its body is
  admitted or a control entry applied.**
  - *Closes*: items 11 and 13.
  - *Changes*: truthful codes (SY-21); `last_failure` carries a time and is cleared by the next
    request that delivered something; served and fetched progress counted where the entry moves
    (SY-20; the served side from ADR-044 RD-16's `BoundedSyncDone`). ADR-042 owns every word.
  - *Deleted*: the catch-all `TransportFailed` mapping (`history_stream.rs:160-167`,
    `driver.rs:57-62`, `transport.rs:300-306`); `note_lane_sync` as the "last sync" clock.
  - *Proof*: extends `a_sync_failure_names_its_reason_proof.rs`: during the B1 act, none of 300
    `vox status --json` samples holds `transport failed` while no transport fault was staged; a
    member that withdraws a request shows as cancelled, not failing. v0.4.30 is red, verified (273
    to 302 of 300 samples hold it, `B1-base`); the trial build likewise. L2-oplike: the reader's
    "last received" for the author never exceeds 60 s (v0.4.30: 311 s by investigation; the
    release-asset run is ADR-045 J3). Mutant: map a cancellation to `TransportFailed` again; red,
    PRODUCT. Acceptance: 0 of 300; 60 s.

- **SY-8 (I-8). A sync writes nothing to the store except entries, headers and the per-author
  facts SY-18 lists.** *(changed: finding 10.)* No proof record, receipt, cursor, window or demand
  is written for a fetch. A restart in the middle of a catch-up loses no entry, no interval and
  no staged partial body; it loses the requests in flight and the explicit page a person had in
  flight (SY-9 says what the person is told), and re-derives everything else.
  - *Closes*: the sync half of item 20 (ADR-047 owns the rows already on disk); the store growth of
    B1 (150–376 MB in 5 minutes on every build).
  - *Changes*: SY-18. ADR-047 SO-1–SO-3 and ADR-044 RD-9 remove the writes this ADR's mechanism no
    longer makes.
  - *Deleted*: see SY-19.
  - *Proof*: extends the same file's B1 act. After the read completes, `vox status --json` shows
    `store.sync_bytes` = 0 on the newcomer and on every member (ADR-047 SO-15's field) and the
    newcomer's data bytes at most 24 KB per admitted entry plus 2 MB (ADR-047 SO-1's bound). A
    restart arm kills the newcomer's daemon in the middle of its catch-up, starts it, and asserts
    that the catch-up completes with every member's hello shown, within SY-1's bound counted from
    the restart. A large-body arm: a member posts a 12 MiB attachment; the reader's daemon is
    killed when `vox status --json` shows the entry's staged bytes between 4 and 8 MiB; after the
    restart the attachment renders within 60 s and the holder served fewer bytes than the
    attachment's size (SY-18 keeps the staged prefix with its binding). v0.4.30 is red, verified
    (268 MB and 39,500 proof-like rows in `B1-base`). Mutants: write the verified range on
    admission again (`keep_history_proof_range`; `sync_bytes` > 0, PRODUCT); discard the staged
    prefix at restart (the holder serves the whole 12 MiB again, PRODUCT). Acceptance: 0 bytes;
    the size bound; SY-1's 30 s; 60 s.

- **SY-24. A sync round is never refused because of another round's failed cleanup. A slot is
  held only by a running exchange with a deadline and is released on every exit path. A node with
  wanted entries and a connected holder always has a request in flight toward some holder, or a
  named wait that says why it has none.** *(new: fix-list items 85, 86 and 87; ledger rows 11,
  14, 17; `rca-RcaSchedStall.md`.)*
  - *What was seen*: robert-work (the operator's personal node) stopped starting sync rounds for
    49 minutes on 2026-11-13 (01:33–02:16Z) while its sibling omp-work on the same daemon kept
    syncing: every port `queued: true, needs: true, round_running: false`, `start_age` up to
    2,631 s, `lanes.bounded.retiring` = 11 flows, all Public, 10 for room k4qxsi with the ledger
    error `store save room: malformed at-rest artifact: key-package attempt unacknowledged` and 1
    for an ended room; four rooms `no completed sync in 10 minutes`; the person's post "only on
    this machine" (`/private/tmp/vox-rca/mac/stall-robert-work-021627Z.json`†). Vince's personal
    node vovando was in the same state at 02:35Z as seen from the Mac (item 87; INFERRED until its
    log arrives). `vox room leave` on such a node fails "an internal error" (item 86) and
    `vox room end` loops `cleanup stopped` (item 64).
  - *Cause*: KNOWN, reproduced on the v0.4.30 release binary (RcaSchedStall, receipts
    `/tmp/RcaSchedStall/receipts/`†; checked here at the tag). Every round's `Flow` is retained
    after its round (`bounded_sync.rs:1827-1833`) and cleaned by `retire_slice`. When that local
    save fails, `accept_retirement_slice` (`:1854-1860`) puts the flow in `retiring` and
    `retirement_failed` and waits on `retirement_erasure` (`runtime.rs:1814-1848`), a future that
    completes only on a node lock, or on the store's flush debt when the failure was in the flush
    phase; a failure in the room-save phase (the operator's, and ENOSPC on the rig) sets no
    settlement, so the waiter waits for a lock that never comes. Store recovery replaces the room
    (`metadata_save.rs:3756-3790`, `retire_port`, `:2255-2303`) and does not discard the flow.
    `can_retain_new` (`:1789-1810`) counts `retiring` against `RETAINED_FLOW_LIMIT = 12` (`:580`);
    at 11 the last place is reserved for the other family, so every Public start on every port is
    refused at `:4749-4757`, deliberately without a `start_reason`. The Public inventory round is
    the only carrier of own heads to peers, hence "only on this machine"; rounds are pulls, so the
    node fetches nothing either. On the rig: 60 s of failing saves on a full volume → 11 pinned
    flows that survive "recovered; it can save again"; B's 72 further posts never read; sibling B
    healthy throughout; only a node restart clears it. `lanes.slots` in use with nothing running
    (3 on the operator's snapshot) is a separate leak whose owner is UNKNOWN (`actor.rs:24206-24259`,
    `history_demand.rs:1842-1857`, `actor.rs:23652`; settling: status must name the slot owner).
  - *The invariant* (stated for R2, with R1's form for the record) *(changed r3: N10, N15)*: (i) no node-wide count includes a
    flow whose cleanup failed: under R1 `RETAINED_FLOW_LIMIT` counts only `ready`, `running` and
    `deferred`, and flows in `retirement_failed` are capped per room (4) so a room's failures cost
    that room its places and no other room anything. (ii) A failed cleanup is retried on every
    store recovery of its room (**`StoreRecovered(room)`**, the instance-qualified event ADR-047
    SO-11 raises on every transition out of "cannot save", a floor recovery without a reopen
    included (r4: third review, P1 "the event the store emits"); ADR-040 NW-1 names the wait
    `NotYet{StoreRecovery(room)}`, released by that event) and is dropped when its room instance is
    replaced (`history_instance != instance` is already "Gone") or the node locks; `vox room
    leave` and `vox room end` of such a room succeed (ADR-049's `Retire::Deleting`, formerly
    ADR-040 NW-7/NW-15, discards it). (iii) **Every bounded resource a sync can hold has one
    named owner, a release on every exit path, and a stated behaviour under a failed local
    write.** The table is the invariant; R2 deleting the flow pool proves nothing by itself.

    | Resource (bound) | Owner | Held from … to | On a failed local write | On room replaced / closed / node lock |
    |---|---|---|---|---|
    | Per-peer slot, K = 2 per peer (R2); physical position / retained place (R1) | the running exchange | send → answer complete, refusal, reset or 20 s deadline | nothing: the network exchange is over before any write | released with the exchange; a room close resets its streams (`Cancelled`) |
    | Answer-budget permit, 1 MiB per in-flight answer, 64 MiB per node (ADR-036 H-7's buffer permits), of which a **room may retain at most 8 MiB** past its exchanges' end and **all failed rooms together at most 16 MiB** (r6: fourth review P1-5): the **runnable pool** is the remaining 48 MiB and is never retained by a failed admission, so a ninth healthy room always has permits | the received answer's bytes | send → the bytes are **committed or discarded** (not the network end: N10) | the bytes wait in the room's admission queue holding their permit up to the room's 8 MiB and the failed rooms' 16 MiB together; a room at either cap starts no request (its named wait is `StoreRecovery(room)` or `RoomWrite(room)`) and answers that would exceed a cap are discarded unverified and re-derived later; the 48 MiB runnable pool and every healthy room are untouched, however many rooms cannot save | queue discarded, permits released at once |
    | Admission queue per room (received answers not yet committed) | the room's `RoomWrite(room)` owner (ADR-044 RD-10's FIFO place) | enqueue → commit or discard | retried on `StoreRecovered(room)`; a duplicate of positions already queued or held is discarded on arrival | discarded |
    | Staged partial body, ≤ 4 per room, on disk (SY-18) | the entry hash | first chunk committed → body complete, entry expired or audience changed | it is a write like any other: stays as last committed; resumed from the committed offset | deleted with the room |
    | Inbound serving job (ADR-044 RD-16's serving book), ≤ `INBOUND_PER_PORT` per peer, under the buffer permits | the stream task | preamble accepted → stream end or reset | none: serving writes nothing (RD-8) | job cancelled, permits released when the task is joined |
    | Proof handoff per peer and room (ADR-044 RD-9: last 4 proofs' contexts) | the serving book | proof served → connection or instance gone | none | dropped |
    | Pending control entries in the fold (SY-3 rule 4), bounded by held control entries | the fold | admission → applied or superseded | none (held entries are committed) | gone with the room |
    | R1 only: retained flow (`RETAINED_FLOW_LIMIT`, 12 → per room 4 for failed cleanups) | the flow until `retire_slice` succeeds | round end → retirement committed | counted toward no node-wide cap; retried on `StoreRecovered(room)` | discarded (`Retire::Deleting`); transferred on lock as today |

    A native worker that still owns a reservation (`source.rs:532-568`) is joined, not dropped,
    before its permits are released (ADR-036 H-4, unchanged). (iv) Every refused start records
    its reason in `lanes.ports[].start_reason` (`retained_flows_full`, `retirement_failed`,
    `budget_exhausted`, `cannot_save`; ADR-042 TR-25), the retirement ledger is shown per node,
    not daemon-wide (ADR-042), status names every slot and permit owner, and the node-level state
    "wanted entries, a connected holder, nothing in flight, no named wait" is ADR-042's
    `NOT ASKING` verdict, which ADR-045 FG-12/FG-20 watch, staged by the trigger below.
  - *Proof* *(changed r3: N15; changed r4: third review P2 "failed cleanup"; r9: this journey is
    ADR-047 SO-11's arm 1c, one file, optional in tree and blocking on the fleet, X047-8)*:
    extends `a_sync_failure_names_its_reason_proof.rs` with
    RcaSchedStall's journey on ADR-045 FG-20's staging: A and B in three rooms, A's data on a
    **256 MB** image (ADR-047 SO-11's image: 64 MB floor plus the write reservation; the RCA's
    64 MiB image left 42 MiB free after the fill, below the floor, so it cannot stage the fixed
    binary, N15); an external file fills the image to below the floor while B posts 20 times in
    each room; the file is deleted; B posts once more in each room; **two such cycles** (FG-20);
    A shows every post within 30 s of the second free and `vox status` lists no room `no
    completed sync in 10 minutes` and no `NOT ASKING`; then A ends one room and leaves another:
    both gone from `vox room list` within 60 s, and `vox room leave` prints no internal error. The
    staging is asserted before the claim: the driver reads A's `vox status --json` `cannot save`
    during the fill and `recovered` after the free (else APPARATUS). Because ADR-047 SO-11 lets a
    cleanup run as reclamation under the ballast, filling below the floor need not fail any
    retirement on the fixed binary; so the act also stages a **cleanup that actually fails**
    with SO-11's admission-to-write apparatus (`test-knobs`: the external fill, or the commit
    hold, placed between a flow's retirement being admitted and its write, so the write meets
    the latch), and asserts the failure happened before the claim (A's `vox status --json`
    `retirement ledger` shows at least one failed cleanup for a room, else APPARATUS). Both acts
    are **optional proofs in tree** (`optional-proofs`, loud when not run; the decider's ruling,
    ledger row 51) and **blocking on the fleet** (ADR-045 J5(g), FG-20; confirmed, row 59). v0.4.30 is red, verified
    (`/tmp/RcaSchedStall/receipts/exp2.log`†, `A-stalled.json`: 11 retiring flows, every port
    queued with no reason, the posts after the free never shown, `last_sync` 709 s; PRODUCT; on
    v0.4.30 the 64 MiB image sufficed because it had no floor). A second act:
    one node in **nine** rooms with one member each (r6, fourth review P1-5 and P2; restaged r7,
    fifth review P2): the members of rooms 1–8 keep **offering** 1 MiB answers (each posts
    128-entry bursts continuously) while those rooms' writes fail (the apparatus latch of
    ADR-047 SO-11 placed on those rooms' commits), so the node's retention reaches whichever cap
    binds first and must discard the rest; room 9's member posts every 2 s throughout, and the
    apparatus member (a test-side server answering the real daemon, SY-12's apparatus) **withholds
    the answer on one selected stream** while keeping the QUIC connection and every other stream
    live (r9, seventh review P2-2: blackholing the hop stalled the shared connection and so both
    slots), guarded by an explicit rule in the apparatus: it withholds on a new stream only when
    **no other request from this node is currently withheld**, so at most one of the node's two
    slots is ever silent, and it answers retries of a withheld request normally; the node
    renders each of room 9's posts within 5 s throughout that phase. A **separate double stall**
    is staged once, at the end: the apparatus withholds on both streams it holds from the node;
    the node's next room-9 post renders within **one deadline (20 s) plus 5 s** of the second
    stall, since the first slot's deadline frees it and the retry is answered; `vox status --json` shows at every sample retained permits ≤
    16 MiB, the runnable pool ≥ 48 MiB, discarded answers counted for rooms 1–8, and for rooms
    1–8 the wait `StoreRecovery(room)` with no slot or permit in use by nothing; after the latch
    is released every room's posts render within 30 s. The assertion is room 9's rendering, the
    user-visible effect; mutants: retain beyond the 16 MiB cap (room 9's posts stop rendering
    once the pool is gone), or **do not release the slot when its request's deadline elapses**
    (the retry is never sent; room 9's post after the double stall never renders inside 25 s,
    failing the recovery assertion, while the single-stall phase stays green); PRODUCT. A third act (N10): the
    full-volume staging above with B posting 128-entry bursts; while A `cannot
    save`, A's `vox status --json` shows at most 64 MiB of permits held and no new request once
    they are; after the free every burst renders within 30 s. Whole journey under 6 minutes.
    Mutants: keep counting `retirement_failed` flows in `can_retain_new`, or skip the retry on
    `StoreRecovered(room)` (the failed-cleanup act stages **eleven** failed cleanups across its
    three rooms under the latch, the shipped Public-flow threshold, so under the mutant every
    Public start is refused and the post after the free never renders, red on its own assertion;
    fewer failed cleanups would leave the mutant green: r6); under R2, retain a failed room's permits
    beyond the 16 MiB cap, or release the slot late on the deadline path (second act: room 9's
    posts stop rendering, red); release the permit at network
    end (third act: permits held exceed 64 MiB, or the daemon's resident bytes grow past the
    bound, red); PRODUCT. Acceptance: 30 s; 60 s; 5 s; every sample; 64 MiB.

- **SY-25. Every body a node serves, on every path, passes the same entitlement check as the
  present `entry()` path, from the server's own committed governance projection, and the check
  is re-run per frame under the room's current generation.** *(new: finding 1; changed r3: N14.)*
  The check is `recipient_body_eligibility` (`server.rs:780-809`, consumed from
  `governance/view.rs:990-1012`), applied before any body read to every `Range` body including
  offset continuations, to the join answer's bodies (the joiner's own feed), and to a key package
  addressed to the requester (ADR-007 G-30's forward-only rule); `ControlRange` carries no body.
  A package addressed to another member is relayed sealed and unchecked (only its recipient can
  open it; the requester cannot override the signed recipient; the decider, ledger row 40: every member, members only). Outcomes: `Eligible`
  serves; `Ineligible` answers the header with `body_state = not for you` (SY-12), which the
  requester treats as permanent for that position until its own governance view applies a later
  readmission; `Refreshing` (the server's projection is behind its held control entries) answers
  `Refuse{Busy, retry_after}` with the fold's bound (ADR-037 R2: one bounded turn), the one case
  a read answers Busy, and it never answers a restricted body from a stale projection. Each frame
  of a long answer is authorized under the room's current access generation (`source.rs:991-996`,
  kept): a removal applied during an exchange stops the next frame. The check costs nothing for a
  requester with no validated removal in its past (`RecipientCut::Unrestricted` short-circuits).
  A requester that is not an admitted member is refused `NotMember` before any of this (ADR-008
  LS-34). A server that has not yet learned a removal serves the still-admitted target until the
  removal applies: that is the accepted unaware-partition window, and a pending (unvalidated)
  removal changes nothing (SY-3 rule 4). The receiver's own gates (`channel.rs:8115-8150` for
  rendering, `pending_package.rs:547-566` for installing a package) stay as the independent
  second defence.
  - *Hostile cases*: a removed member asks (NotMember); a readmitted member asks for a package or
    content from before its readmission (not for you, from every holder, so SY-4 stops asking); a
    holder whose fold is behind is asked by a readmitted member (Busy, then the answer from the
    current projection); a holder that lies `not for you` for an eligible body (the requester
    asks the other holders, SY-15, and marks the lie's source short, SY-15 rule 4); a readmitted
    member that kept an old chain key and speaks the wire itself (below).
  - *Proof* *(changed r3)*: two acts in `a_node_leaves_a_room_proof.rs`. **Sender boundary**
    (the claim of this requirement): the creator removes member M, posts twice, readmits M and
    posts once; a **test-side hostile client** holding M's identity, M's admission and the sender
    chain key M held before its removal (apparatus; AGENTS.md: a crafted attacker against the
    real binary is allowed) asks the real serving daemon, in turn, `Range{bodies}` for the two
    positions, the same by `offset` continuation, the join answer, and M's own old key package;
    it asserts that no body bytes for those positions were sent (every answer is header +
    `not for you`) and that, with its old key, it can decrypt nothing of them; during the second
    exchange the apparatus also applies a fresh removal of M on the creator and asserts the
    stream stops with `NotMember` before its next frame. Mutant: skip the gate on the `Range`
    path; the client receives the ciphertext of the two posts (and, where the old chain still
    covers them, their text), red on its own assertion, PRODUCT (N14: the real recipient's render
    gate would hide this, so the assertion is at the wire). **Receiver** (the independent
    defence; r4: third review, P2 "decryptable forbidden material"): the staging gives M a body
    it can decrypt and must not see: the creator sends M a key package (chain K1) and posts P1
    under K1 while M is offline, so M holds K1 and not P1's body; M is then removed, the creator
    posts P2 and P3, readmits M and sends a fresh chain; M comes back and pages back: P1, P2 and
    P3 are "not available to this node" (P1 is pre-cut for M under G-30's forward-only rule even
    though K1 opens it), and the post after readmission shows. Mutant: skip the render gate
    while an apparatus holder serves P1's body; M shows P1's text, red on its own assertion,
    PRODUCT (P2/P3 would stay dark under the mutant for lack of a chain; P1 is the decryptable
    one). **Mid-stream** (r4; restaged r6, fourth review P2): M, eligible, is served a 900 KiB
    attachment by one `Range` answer of fifteen 64 KiB frames (one answer, ≤ 1 MiB: an answer
    never reaches a "second MiB"); the apparatus holds the holder's stream after its fifth frame
    (`test-knobs` commit hold on the serving task) while the creator removes M and the holder's
    fold applies it; released, the holder must stop with `NotMember` and send **no sixth frame**;
    the hostile client of the sender act counts the frames and asserts five, and real M shows the
    attachment as "not received yet" and never its bytes. Mutant: authorize once per answer
    instead of per frame; the client receives frames six to fifteen of that answer, red at the
    wire, PRODUCT (the next `offset` request is rechecked either way, which is why the assertion
    is on the suffix of one answer, not on the whole attachment). v0.4.30: the `entry()` path passes the receiver act; the sender
    and mid-stream acts are new with the range paths. Acceptance: within 30 s of each ask.

- **SY-26. A room that exists before this release gets its anchors, control-complete positions
  and recorded removal cuts once, from what the store already holds, before the room is
  published.** *(new: finding 11; changed r3: N12; changed r4: third review P2 "migrated cuts";
  changed r10: ADR-047 r11's R8-2, "one commit per room" withdrawn: the recorded cuts are
  unbounded by member count; changed r11: ninth review 8, the entry predicate is the marker's
  absence.)* At every open under v0.4.31 a room **without the marker
  `meta.anchors_initialized(room)`** — the sole unfinished-migration predicate; anchor rows that
  exist from an interrupted earlier run do not count — runs (or resumes from `meta.sy26_cursor`),
  in ADR-047 SO-2 step 4's **migration-batch stage**, **before** the sweep deletes
  anything (**the ordering, for ADR-047 SO-2 to cite**: SO-2 step 4's sweep of a room MUST NOT
  start until SY-26's completion marker for that room is durable, because SY-26 reads
  `LiveWindow` and the DAG projection rows the sweep deletes; the preparing step runs SY-26's
  batches first, then the sweep, then publishes the room). SY-26's work is written in **bounded
  batches**, each one transaction of at most 256 keys and under 2 MB of updates (3 MB on the
  ballast; SO-11's migration class), driven by a cursor `meta.sy26_cursor` (room, author, and
  the last removal processed) written with every batch, and a marker `meta.anchors_initialized`
  written in the **last** batch; nothing is deleted and nothing is read as migrated before the
  marker exists. A kill between batches resumes from the cursor at the next open; a batch
  written twice is idempotent (anchors are the same minimum, cuts the same triple). **What a
  reader does before the marker**: the room is not published (it is `preparing: initializing
  anchors, <n> rooms left`, ADR-042's words), so no reader, no fold and no sync sees a half
  migrated room; `vox status` names the stage. The values, per author A with a
  committed head here, `anchor(A)` = the least of (a) A's persisted live-window start
  (`LiveWindow` in `AuthorState`, read once and then deleted), (b) the lowest position of a held
  header of A whose body is missing and whose retention has not expired, and (c) the committed
  size minus 127, clamped to 1, when neither (a) nor (b) exists (what v0.4.30 promised that author:
  its newest 128). `control_through(A)` = A's fence post in the newest creator checkpoint the
  store holds and has folded, else 0, and the closure index starts empty with the baseline
  terminal below the fence, so `closed_through(A)` is the fence too (r12) (r5: SY-27; an upgraded node already holds the whole
  governance set, so nothing is re-fetched that it has; what it lacks is enumerated from there),
  and the fold meanwhile works on what is held, so ADR-037 R1's "preparation waits only on this
  node's own work" holds. For every removal the room's fold
  has validated, the **recorded cut** of SY-3 rule 5 is computed from the v0.4.30 DAG projection
  still on disk (the validated parents' closure, `contains_cut`'s walk, run once here) and kept
  as `(removal hash, target, through)`; the removal's visibility after the upgrade is therefore
  exactly what it was before (N12). If this node is that removal's issuer or the room's creator,
  it appends the triple as a `CutAttestation` control entry once the room is published (SY-3
  rule 5), so that a fresh joiner, which receives neither the old DAG nor this node's local
  triple, classifies the target's posts as the upgraded holders do (r4). An author with no committed head here gets anchor 1 when
  first seen, as a new author. Nothing is deleted or reset; a kill during the step leaves the room
  without the marker and the next open resumes from the cursor (the DAG rows are still there, because the sweep
  runs after this commit). The `CutAttestation` obligation (SY-3 rule 5) is **not** a one-time
  step *(r6: fourth review P2)*: at every open, a node that is a removal's issuer or the room's
  creator derives the attestations still owed from its persisted cut triples minus the signed
  attestations it already holds in the log, and appends the missing ones once the room is
  published; so a kill between the migration commit and the append leaves the obligation
  derivable, and an attestation already in the log is never appended twice (the derivation is
  keyed by removal hash).
  - *Proof*: a third arm of ADR-047 SO-2's upgrade journey (no new file): a data root first written
    by the v0.4.30 release asset, frozen as RcaFrozen's `base1` leaves it (a bodiless header of a
    member held, its text never shown), opened by the fixed binary with the members running:
    the room prepares, opens, and the member's row renders within 30 s; `sync_bytes` is 0.
    v0.4.30 is red, verified (`base1`: rows 1 at join+88 s). A removal arm (N12): the v0.4.30
    root also holds a removal written by the release asset in a room of 17 authors where the
    target was quiet, so its `seen` omits the target (apparatus: the 17 nodes are real v0.4.30
    daemons; the target's last post is an ancestor through the issuer's own content); after the
    upgrade, every member still shows the target's pre-removal post and never the post it made
    after; then a **fresh node joins** through an upgraded member and pages back: it shows the
    target's pre-removal post and never the later one (r4: the attestation travelled in the
    control range). Mutants: initialize every anchor at the committed size plus one (the row
    stays "not received yet", red, PRODUCT); skip the recorded cut (the target's pre-removal post
    is hidden on the upgraded holder, red, PRODUCT); skip the attestation (the fresh joiner hides
    the pre-removal post, red, PRODUCT). **Interruption arm** (r11): the daemon is killed after
    the first batch (anchors written, no cuts, no marker) and restarted; status shows
    `preparing: initializing anchors` again, then the room publishes, and the removal arm's
    assertions hold on it; mutant: enter the migration on "no anchor exists" instead of on the
    marker's absence: the restart skips the cut batches, the target's pre-removal post is hidden
    (no recorded cut) and the sweep runs, red, PRODUCT. Acceptance: 30 s. The 17-node staging is run once as an
    optional proof (`optional-proofs`, loud when not run) and on the fleet (ADR-045 J5); the
    `base1` arm is mandatory.

### 2. Three more outcomes the invariants require

Plan A's sections for items 6, 8 and 10 each chose an invariant that the eight above do not name.

- **SY-9. A person's explicit history request makes wire progress within one exchange of being
  issued, whatever else the node is doing.** *(changed: findings 10, 14.)* `vox room read
  --history older --before X` asks at most 64 rows and 1 MiB per ask (ADR-037 R1), served newest
  first: under R2 the request is a `Range` with `descending` set (SY-12), so a page the byte cap
  cuts keeps its newest rows and loses its oldest, never a hole. The request lives in memory for
  the daemon's life: a restart forgets the page in flight, never a row already held, and
  `vox room read --history resume` after a restart says `no page in flight since the daemon
  started; ask again with --before X` (ADR-042's words). This replaces ADR-036 H-4's durable
  archive continuation (amendment 10); re-fetching one page is the cost, and nothing is kept per
  fetch.
  - *Closes*: item 6.
  - *Changes*: R2: the request is a `Range` below the anchor at the highest priority after own-feed
    recovery (SY-15). R1: R1 step 8 (a third physical position for explicit history).
  - *Deleted*: the Archive operation's phases and the "one bounded history quantum is queued"
    texts (`actor/history_demand.rs:1093, 1129`). Round 2's binary still routed `--history older`
    through the Archive path and no older chunk arrived within 60 s (SY-27 (d)); the `Range`
    page is build-list item 7, unbuilt.
  - *Proof*: same file, the B2 act after the newcomer has joined: `vox room read --history older`
    shows at least one member row within 10 s. A byte-cut act: a member's 64 newest-but-one rows
    hold 40 KiB bodies; the page shows the newest rows and says how many older ones did not fit
    (ADR-042). A rebuild act in `a_node_leaves_a_room_proof.rs` (the reviewer's Q2 journey): a
    node posts, is read by others, is rebuilt with the same identity on a fresh store and rejoins;
    after `joined` it shows nothing from before the join, pages back once, and shows the members'
    and its own pre-rebuild text (its key packages came with the control ranges, so it holds every
    key ever sent to it). v0.4.30 is red, verified for the first act (never: RcaFrozen `slow1500`,
    io-repair-drill); the byte-cut and rebuild acts are new journeys (v0.4.30 red unverified; the
    rebuild act is expected to pass on v0.4.30 in a quiet room and is kept as the Q2 journey).
    Mutants (R2): put explicit requests below backfill (first act red); send an explicit page
    ascending (the byte-cut act shows the oldest rows, red); PRODUCT. Acceptance: 10 s. Item 6's
    settling experiment runs first (ADR-045 FG-10).

- **SY-10. A join through a member that answers in T seconds completes within T + 10 s, and
  no other member's silence can fail it.** *(changed r4: fix-list item 88, the decider's ruling
  of 2026-11-13, ledger row 37: "the join only requires a single member to validate the
  passphrase was correct, not all members"; "combination of 1 and 2".)*
  - *What was seen (item 88)*: on the v0.4.30 release asset, with one member paused, a newcomer's
    join through the **fast** member failed in 6.4 s in both baseline runs ("member <fp> did not
    answer within 5s, and every member online must agree before the room takes a newcomer"; the
    joiner saw "remote admission may have occurred, but its acceptance could not be verified and
    saved") and 10 of 12 earlier joiners failed the same way (`arm-repair.md`, B3dc-base
    s1/s2). Cause, KNOWN at the tag: ADR-007 G-22's "every member online must agree" is built as
    `seatstream::ask` with `SEAT_ANSWER_WITHIN` = 5 s (`node/seatstream.rs:48, 230-265`), and
    `seat_round` (`node/actor.rs:3480-3590`) turns `Asked::Unanswered` into `SeatNotAgreed`
    (`:3520-3540`), so a member that is up but answers late vetoes every join in the room. Only
    `Gone` (nothing heard at all) and `Refused` are "not counted" today.
  - *Join capacity* (X044-7, ADR-044 RD-16): a join is admitted through RD-16's serving book
    guard (`JOINS_IN_FLIGHT` = 16 per node, `actor.rs:762`) and releases its place through the
    same guard on `ACCEPTED`, a refusal, or the joiner's disconnect, never through the actor.
  - *The admission rule*: the admitting member M admits **alone** whenever it
    cannot be near the cap *(changed r6: fourth review P1-6)*: it counts `authors(M)` (members it
    has applied) plus `promises(M)` (places it has promised and not settled, its own and those it
    holds for other askers, each kept until the joiner is an author, an `ABORT`, or `PROMISE_TTL`
    = 120 s: `reserve_seat`/`answer_seat`, `actor.rs:18354-18440`, unchanged) plus the
    **outstanding admissions it can know of**: `JOINS_IN_FLIGHT` (16, `actor.rs:762`) for each
    connected member, since each may be admitting that many alone at this moment, plus 16 for
    itself. What it cannot know, admissions by members it is not connected to and admissions
    not yet carried to it, is **not** bounded by any constant (revision 5's "R = 16, more than
    the heartbeat can hide" was unsupported and is withdrawn): the cap is **soft** by exactly
    that residual, and the hard limit absorbs it (below). M admits without asking when
    `authors + promises + 16 × (connected + 1)` ≤ `MAX_AUTHORS` (1,024). Only when the sum exceeds it
    (the room is **near the cap**) does M ask every connected member on the `seat` stream, with
    `SEAT_ANSWER_WITHIN` kept at 5 s: `Yes` promises the place as today; `Full{members}` or
    `Taken` refuse the joiner, named, as today; `Unanswered`, `Gone` and `Refused` are **not
    counted and never fail the join**. An unanswered member has promised nothing, so it may at
    the same moment admit a newcomer of its own, and it **may already have reserved** a place
    for this very joiner (`answer_seat` inserts the promise before it delivers `Yes`,
    `actor.rs:18421-18440`): that promise is harmless (it is for this joiner, settled when the
    joiner is an author on that member, or freed by `PROMISE_TTL`). To send `ABORT` to an
    unanswered member when the join is refused, the handoff changes (r7: fifth review P1-5):
    today `Asked::Unanswered` carries no stream (`seatstream.rs:207-220`) because the timed-out
    `ask` future drops the send half, while `abort` writes on that very stream (`:273`) and the
    member's `answer_and_wait` (`:304`) reads it there; so `ask` returns the send half on timeout
    (`Asked::Unanswered(Option<SendStream>)`: `Some` when the stream was opened and the question
    written before the deadline, `None` when `open_typed` itself had not completed inside the
    5 s, which the shipped `ask` includes in its deadline, `seatstream.rs:232-241`, and keeps:
    the whole-operation bound stays; r8, sixth review 5), `seat_round` keeps the `Some` ones in
    `unanswered_sends`, and on refusal writes `ABORT` on each as it does for `Yes`; a member whose
    stream never opened received no question and promised nothing, so nothing is sent to it;
    neither outcome vetoes admission. A member that reads `ABORT` after its late `Yes` frees the
    promise as today, and one that never reads it frees it at `PROMISE_TTL`. On admission
    nothing is sent: the promise is for this joiner and settles when the joiner is an author
    there. The overshoot silence allows is at most 16 × the unanswering members, and the room's
    hard limit absorbs it exactly as a split does: a
    member another member admitted is always admitted from the board, past the cap if it must
    be (`admit_from_board`, `channel.rs:607-615`; `AUTHORS_HARD_LIMIT` = 2 × `MAX_AUTHORS`; G-22d
    unchanged). After a split that let both sides fill the room, the same rule applies when the
    sides reconnect: every admitted member stays admitted, no one is ejected, and new joins are
    refused `Full` on every member until the room shrinks. `SeatNotAgreed` ceases to exist.
  - *A member whose own fold is behind* (r9, round 2's item 4): the admitting member writes the
    grant as a governance entry, which needs its fold current (ADR-037 R3's `GovernanceCurrent`;
    `require_governance_ready` in `reserve_seat`, `actor.rs:18354-18400`, refuses "room governance
    is refreshing" today, on v0.4.30 and on the arm: 2 of 6 joiners per round-2 run). It answers
    the joiner `Refuse{Busy, retry_after}` with the fold's bound (SY-28 makes that bound the
    catch-up from the fence), never a refusal text; the joiner waits it out inside SY-10's
    patience or joins through another member, as for any `Busy`.
  - *Hostile member*: **silence** gains it nothing (not counted). A **false `Full`** or
    **false `Taken`** can refuse a join, named, only while the admitting member is itself near
    the cap (it does not ask otherwise); the joiner is told which member said so and may join
    through another member, which asks the same members and gets the same lie, so near the cap
    one hostile member can hold the room closed, which is the shipped behaviour today at any
    size; a `Full{members}` is honoured when `members` ≥ `MAX_AUTHORS` and refused as `Malformed`
    only when it claims a count above the hard limit or below the asker's own applied `authors`
    (a member cannot hold fewer than what both have applied); the asker's uncertainty sum is
    never used to judge another member's count (r6).
    A **false `Yes`** promises a place the member then does not honour: the joiner is admitted
    by M regardless (M's own count was the admission), and the liar's board catches up.
  - *Closes*: items 8 and 88.
  - *Changes*: the member answers the join off its actor, from a committed snapshot (ADR-044
    RD-16's admission and RD-8's read, applied to joins); the joiner's patience follows the
    member's `Refuse{Busy, retry_after}` instead of a fixed 30 s; the join answer is SY-17's;
    `seat_round` as above; ADR-007 G-22, G-22b and ADR-005 J-18 amended (amendments 22–24).
  - *Deleted*: `SeatNotAgreed` and `Asked::Unanswered`'s veto; R2 deletes ADR-036's join
    settlement on a complete live window (amendment 9).
  - *Proof*: extends `a_slow_joiner_gets_in_or_is_told_why_proof.rs`. **Paused member** (item
    88): three members, one of them paused with `SIGSTOP` (a process-pause fault, ADR-045 FG-12,
    which is the trigger here, not a slow member), the room far from the cap; `vox room join`
    through a running member returns 0 within 10 s and `vox room read` shows the greeting of
    the other running member within 10 s more; v0.4.30 is red, verified (6.4 s failure, both
    baseline runs; 10 of 12 earlier joiners, `arm-repair.md`). **Near the cap**: the
    `test-knobs` build with `VOX_TEST_MAX_AUTHORS` = 6 (`channel.rs:678`, exists at v0.4.30),
    three members and the paused one: a fourth join asks (the driver sees the `seat` exchange in
    the member's log) and succeeds within 10 s with the paused member not counted; a fifth and a
    sixth are admitted; a seventh is refused `room full` naming the count; a **stale-view** act:
    two members on either side of a blackholed partition each admit one newcomer at 5 of 6,
    heal, and both newcomers stay members (7 of 6, the soft cap's residual) while the next join
    is refused `room full` on both (mutant: refuse the second newcomer from the board; it is
    ejected, PRODUCT); a **remote-refusal** act (r7, fifth review P2; the distinguishing case
    before views converge): M has applied 6 of a cap of 8 and is connected to P, which has
    applied 8; a join through M is refused `room full` naming P within 10 s, and M's own count
    stays 6 (mutant: never ask; M admits a ninth member alone, PRODUCT); a **concurrent-ask**
    act: two joins asked at once for the last place; each is told `taken` and to try again, or
    one is admitted, both allowed by G-22c, and on retry at most one is admitted and the other
    told `room full`. **Member under load** (item 8): the member runs RcaSlow's
    L2-oplike load; `vox room join` through it succeeds within 15 s; v0.4.30 is red, verified on
    the slow-path member (33.8 s, ADR-045 E-1) and by investigation under load (38 s and refused,
    three times, `B3-reach`). Mutants: count `Unanswered` as not agreed (the paused-member act's
    join fails, PRODUCT); never ask (the remote-refusal act admits a ninth member, PRODUCT;
    revision 5's "ask only above the cap" and revision 6's stale-view mutants could not fail,
    since the unchanged local `seat_count` refuses at the cap once views converge); answer
    the join on the actor again (the loaded-member act is red, PRODUCT). Acceptance: 10 s; 15 s.
    Item 8's settling experiment, and the unknown 5.4 s failure, are run first (ADR-045 FG-10).

- **SY-11. Own-history recovery is the node's first fetch after a rejoin, never blocks its actor
  when met by an open node, and ends by releasing `OwnHistory(room)`.** *(changed: finding 2;
  ledger row 14; changed r4: fix-list item 89; ledger row 34.)* The node still writes nothing
  until its own feed is held through the highest *signed* own head any connected member has
  produced (ADR-023 RL-8.5, unchanged): the target is set only from `Head(me)` answers whose
  signature verifies (`own_recovery_evidence`, `own_history.rs:1079-1190`, keeps this rule),
  never from a member's `Have`. A member whose `Have` claims more of this node's feed than its
  `Head(me)` answer proves is ignored for the fence (its claim is a hint that raised one `Head`
  request and nothing else). Completion releases ADR-040 NW-1's `OwnHistory(room)` prerequisite,
  which runs every obligation parked on it (ADR-048 TC-6 consumes it for a trust withdrawal);
  this is the completion event ADR-040 asks this ADR to name.
  - *A rejoin after a leave is a fresh join* (the decider, ledger rows 34, 58, 61; ADR-049 LE-9;
    r6: fourth review P1-7): a left or ended room's rows and key are deleted at once (its hidden
    copy, where one is kept, lasts at most 2 days), **except the node's own append checkpoint**
    (LE-2 step 2: the append forest and root context for its own feed's next position), which
    the rejoin installs so that the node's own signed feed continues without a fork and it is
    writable at once even when the admitting member holds less of its feed than it wrote (A's
    feed 10, verified at 11, erased; C holds 5 and cannot supply 6–11). The anchor is set from
    the join answer (SY-17); the own feed's **unconfirmed suffix** (positions above what any
    connected member's `Have` shows of it) is pushed as the node's first `Range` answer to each
    member that lacks it (the producer side of LE-9, here). **The short-peer case** (r7: fifth
    review P1-5): A's forest ends at 11, C holds 5, the member that holds 6–11 is offline; A
    appends 12 and pushes 12 with its signed head 12 to C, but A's forest (the perfect subtrees
    of 1–11) cannot prove consistency 5→12 (it lacks the descriptors of 5, 6 and 7–8 that the
    decomposition needs, SY-13 rule 3) and C accepts no head without it. C therefore keeps A's
    pushed headers and head as **observed, gapped continuation**: a per-author, durable,
    bounded set (SY-18: the suffix's headers, at most 128 positions, and the signed head), not
    accepted, not folded, not served as held, shown by status as `<A>: <n> newer entries held
    unproved; waiting for a member that holds <A>'s entries 6–11 or <A>'s proof`; when any
    holder supplies 6–11 (as a `Range` with its witness, which the returning member can) or A
    itself refetches them and can then prove, C composes the proof (SY-13 rule 3), accepts, and
    the continuation becomes held in one commit. Missing proof is never called a fork; a kill at
    any point leaves the continuation where it was, re-derived from the store at the next open. the own-history fence is set only
    when a member's signed `Head(me)` proves it holds **more** than the checkpoint names (RL-8.5's
    restored-from-older-copy case), and then LE-9's words apply. LE-9's accepted-join crash
    states (killed after `ACCEPTED`, before the checkpoint is installed; after it, before the
    push) are each re-derived at the next open: the checkpoint is durable from the leave, and the
    push is derived from `Have` as any own-feed demand.
  - *ADR-048's row, carried verbatim* (X048-7; ADR-048 r5's words): "SY-11: (a) the own-history
    check a withdrawal makes (`require_own_history_current`, `channel.rs:6477-6481`) MUST be a
    read of `own_behind` under the room lock that never waits on the actor's own-history fence; a
    `behind` answer is `NotYet(OwnHistory(room))` (ADR-048 TC-6; fix-list item 89). (b)
    `OwnHistory(room)` is released at the recovery's authoritative completion, the commit of
    `append_governance_with_sender(recover_own = true)` (`channel.rs:6565-6568`), not on a
    refresh that leaves `own_behind` set. (c) The own-original release to a recovering member
    (`own_original_release`, `channel.rs:7724-7757`) passes the donor's trust fence (ADR-048
    TC-3). (d) ADR-048 TC-9 act 5 stages 'behind own history with the missing original key held
    by one other member' by snapshotting a member's scratch store before a rotation it then
    performs; SY-11's recovery journey owns that staging and ADR-048 reuses it."
  - *An open node meeting the fence* (item 89): a node already open that learns, from a `Head(me)`
    answer, that a member holds more of its feed than it does, sets the fence (`vox room post`
    refused "behind what a member holds", ADR-037 R5), parks daemon-owned work on
    `OwnHistory(room)`, starts the recovery as its first fetch, and **keeps answering**: `vox
    status` within ADR-044 RD-1's bound, every other room untouched. Seen: the repair arm's B3
    duty-cycle run 2 had y1's actor blocked for 136–214 s after meeting the fence
    (`arm-repair.md`, serve-wait column, B3dc-arm s2), and z1 on the v0.4.30 asset. Its
    cause is **UNKNOWN**: not explained by the control-chain fetch, and not attributed. No fix is
    attached to a guessed cause: the settling experiment E-89 (that run's staging on the release
    asset with the actor's blocked turn traced; ADR-045 FG-10) runs first, and its finding is
    added here before any mechanism is changed for it.
  - *Closes*: item 10; item 89 once E-89 names its cause.
  - *Changes*: R2: the join answer carries the joiner's own feed (SY-17), and own-feed recovery is
    the top priority (SY-15). R1: own recovery moved to its own position in R1 step 8.
  - *Deleted*: own recovery as an Archive operation competing for the Background position (R2).
  - *Proof*: extends `a_node_leaves_a_room_proof.rs` with a rejoin act: the node posts 9 entries,
    leaves, rejoins through a fresh link; `vox room post` returns 0 within 10 s of `joined`. A
    false-advertisement act: an apparatus member's `Have` claims the rejoining node's feed at
    size 1,000,000 and answers `Head(me)` with the true signed head at 9; `vox room post` still
    returns 0 within 10 s (the lie set no fence). An **open-node fence** act (item 89): a node is
    open and reading; an apparatus member answers `Head(me)` with a genuine signed own head two
    positions higher (the node's own entries it had lost to a rolled-back store); within 1 s `vox
    status` answers and `vox room post` is refused "behind what a member holds" (not blocked);
    the recovery completes and `vox room post` returns 0 within 10 s; a second room on the same
    node renders a post made meanwhile within 5 s. v0.4.30 is red, verified for the rejoin act
    (about 6 minutes; io-repair-drill run C, release asset); the false-advertisement act is new
    (v0.4.30 has no `Have`); the open-node act's v0.4.30 red is **unverified** (the 136–214 s
    block was observed on an instrumented build and once on the asset, cause untraced; E-89
    verifies it). Mutants (R2): schedule own-feed recovery at backfill priority under B1's
    traffic (first act red); set the fence from the `Have` (second act red: the post is refused
    "behind what a member holds"); run the recovery on the actor's turn (third act: `vox status`
    exceeds 1 s, red); PRODUCT. Acceptance: 10 s, matching ADR-045 J8(d); 1 s; 5 s. Item 10's
    settling experiment runs first.

### 3. The mechanism: per-author range reconciliation (chosen: the decider, 2026-11-13)

Everything in this section is the chosen mechanism, R2 (ledger row 57). It is specified so that
it can be built from. What exists of it is the deciding round's replace arm
(`arm-replace.md`: the slice with chain-keyed coverage, write-free acceptance, read-only
serving, and since the ruling the two missing parts, admission in one transaction per chunk and
a fold that never waits on a `ContextUpdate`, commits b247b598d, 205b7000e, 5b1bdadb5 on
`/opt/vox-worktrees/proto-range-sync`), under measurement; its numbers are under Q1 and land in
SY-27. The model: each author's feed is
already a signed hash chain, so the unit of sync becomes *an author and a range of positions*,
not *a peer, an exact head and a flow*.

- **SY-12. The wire carries seven requests and their answers, and nothing else.** *(changed:
  findings 1, 2, 6, 7, 8, 12, 14; changed r3: N3, N4, N8.)* All of it runs on stream
  kind Sync (1), with the existing four-byte length prefix. No frame exceeds 256 KiB
  (`MAX_FRAME_BYTES`) and no answer exceeds 1 MiB (`MAX_RESPONSE_BYTES`). The preamble is
  `[3, room, epoch, purpose, request_id]`, at most 128 bytes; `3` names this format and `purpose`
  is one of `have`, `own`, `explicit`, `control`, `bodies` (it sets the holder's budget lane).
  Positions and sizes are `u64`, at least 1. A **bridge** is the requester's statement of what it
  holds: `since` (the size of its newest accepted head, or 0), `at` (the highest position of
  the author it holds the header of, with that header's entry hash; 0 when none; informational
  for the holder's overlap check, never a basis for accepting a head), and `wanted`: the ranges
  of a consistency decomposition from `since` the requester still lacks (empty on a first ask;
  SY-13 rule 3's composition).

  | Request | Fields | Answer | Bounds |
  |---|---|---|---|
  | `Have` | per room: `checkpoint` (the installed creator checkpoint's entry hash and `H`, or none; a member that installed it holds the summary whole: r10); per author: `author` (32 B), `size` (u64), `head` (HeadID, 32 B), `control_through` (u64), `held`: up to 16 `[from, through]` body intervals, the highest ones, and `intervals_total` (u16, how many the holder has in all) | the holder's own `Have` for the same room | at most 2,048 authors a room (ADR-036's HAVE cap), 256 a frame, 16 intervals an author; a `Have` exceeding a cap is `Malformed`; whole exchange at most 1 MiB |
  | `Head` | `author`, bridge | `HeadAnswer`: the holder's newest signed head of that author, and the descriptors it has for the consistency decomposition from `since` to its size (all of them, or the `wanted` subset), naming the ranges it lacks; nothing when `since` = 0 (first contact) | one signed head; a decomposition of at most 2 × `MAX_TREE_DEPTH` (48) descriptors; at most 16 KiB; `EvidenceUnavailable{ranges}` when the holder has the head but lacks descriptors (the requester composes, SY-13 rule 3) |
  | `Range` | `author`, bridge, `from`, `to`, `bodies` (bool), `offset` (byte offset into `from`'s body, normally 0), `descending` (bool, explicit pages only) | the holder's newest signed head of the author with the consistency descriptors it has from `since` (as `Head`) when its size differs from `since`; then a **range witness** for exactly the positions this answer carries: the sibling descriptors that open the interval `[a, b]` it sends under that head (ADR-036 H-3's range proof; a single position's witness is its inclusion proof); then `Entry` frames in order, then `Done` or `More{seq, offset}` | `to − from` < 128 (`MAX_PAGE_ENTRIES`); `to` ≤ the holder's size; a header at most 8 KiB; body chunks at most 64 KiB; a witness at most 2 × 48 descriptors; an entry body up to 16 MiB continues across answers by `offset` (ADR-036 H-4), the witness sent once per answer |
  | `ControlRange` | `author`, bridge, `from`, `to`, `kind` (`governance` or `all`; the proof is the same under the shipped tree, SY-27 point 2; the filter decides which bodies the requester will ask for) | the holder's newest signed head with a bridge proof as for `Range`; a control proof under it for `[from, to′]`, `to′` ≤ `to` (it is the witness for those positions); then an `Entry` frame with the **header only** of each control entry in `[from, to′]`; then `Done` or `More{to′ + 1}` | at most 8 expanded control headers, 1,024 tokens and 256 KiB per proof object (ADR-036 H-6's object), **and up to 16 such objects per answer covering up to 128 control positions** within the 1 MiB answer (r4: the replace arm measured 8 headers per 1.5 s page as the slow author's ceiling); control bodies are fetched with `Range{bodies: true}`, so a 16 MiB control body continues by `offset` like any other (finding 8) |
  | `Context` | `hash` | the context object | at most 160 KiB (kept from v0.4.30, see below) |
  | `Probe` | `author`, `from`, `to` | `Held`: the holder's body intervals inside `[from, to]` (at most 16), or `NotHeld` | one frame; answered from the interval set, no disk read beyond it |
  | `Snapshot` | `hash` (a creator checkpoint's summary hash `H`) | the whole summary whose hash is `H` (SY-27 point 3), or `NotHeld` | at most 1 MiB (the v0.4.31 limit on a fence post's summary); the requester hashes the bytes and refuses a mismatch (r10) |

  An `Entry` frame is `[seq, header, body_state, chunk?]`. `body_state` is one of `included`,
  `not held here`, `dropped by retention here`, or `not for you` (SY-25); the receiver computes
  expiry itself (ADR-008 LS-33). **The witness is never omitted** (N3): when the requester holds
  `from − 1` (or `to + 1` for a descending page) the request starts at that held position and the
  holder's entry there is compared with the requester's own (ADR-008 LS-28's overlap rule,
  V210-63), *and* the witness still opens the sent interval, so every admitted interval carries
  its tie to the head (SY-18). The holder chooses the positions that fit its byte budget first,
  then sends the witness for exactly those; an answer whose entries do not match its witness
  (fewer, more, or a cut mid-stream) is verified as far as the witness allows and the rest is
  discarded, since nothing is committed before the answer is verified whole (SY-13 rule 4).
  Positions the holder lacks inside a range are named by `Missing{from, to}` and excluded from
  the witness. A `Range` answer's head is the **holder's** newest accepted head, never one the
  requester named: the requester states its bridge, and the holder proves from there (finding 12,
  N4).

  Any request may instead be answered `Refuse{reason, retry_after_ms}`. Reasons: `Busy` (with a
  retry time of 50 ms to 5 s; a holder at its serving budget, SY-25's refreshing projection, or
  ADR-047 SO-1 r6's **background fill**: a holder whose derivation of the proof material a
  `Range` needs is too large to finish inside the exchange (its E-1: a whole 100,000-leaf,
  200-author feed takes 16–23 s) answers `Busy{retry_after}` at once, starts the derivation in
  the background and keeps the result in its cache; the consumer treats it as any `Busy`, SY-15
  rule 4: no short mark, the next covering holder is tried meanwhile, and the same holder is
  asked again at its retry time, by when the fill has usually completed; the author of such a
  feed never fills, since its own tree is canonical, so the cadence is met by asking the author
  first for feeds above 10,000 positions, r5),
  `NotHeld` (ask another holder), `EvidenceUnavailable` (the holder has the entries but cannot
  prove them from this bridge under any head it has: ADR-044 RD-9; ask another holder, never the
  author alone), `NotMember` (ADR-008 LS-34; permanent until governance changes), `Malformed` (a
  bound was broken; permanent), `UnsupportedVersion` (the peer runs an older format: with the
  decider's ruling that every machine moves together this is said by name and nothing waits on
  that peer). A stream reset carries `Cancelled` when either side withdrew on purpose (shutdown,
  room closed, peer retired), and `TransportFailed` only for a transport fault.

  `Have` runs on one long-lived stream per room and connected member, opened by the connection
  owner when the connection comes up (ADR-042's row: sent by the connection owner, not by the
  request scheduler). The first message is the whole `Have`; after that each side sends only the
  authors whose size, head, held intervals, `intervals_total` or `control_through` changed, and
  the room's `checkpoint` when a baseline is installed, at
  most one update every 250 ms, and a whole `Have` or an `unchanged` heartbeat at least every
  30 s (ADR-042 TR-1's `INVENTORY_FRESH` = 90 s). Losing that stream is not a failure; it reopens
  with the connection. A `Have` is sent only to an admitted member (ADR-008 LS-34). **A `Have` is a
  hint of where to ask and nothing else** (finding 2): it never sets what is wanted, what is
  current, what is shown as behind, an anchor or a write fence; a size above the known size, **or
  a HeadID this node has not accepted at or below the known size** (N8), raises one `Head` request
  to that peer (SY-14) and is otherwise ignored; an author not admitted to the room is dropped
  (ADR-042 TR-1).

  `Context` is kept because control proofs, admission and the fold read the context an entry's
  `pre_context` names (`admission.rs:146-163, 883, 1055`; `log/history.rs:743-785, 825-855`).
  - *Closes*: items 1, 3, 4, 7, 11, 12 (with SY-13–SY-16).
  - *Deleted*: the v2 queries `Inventory`, `Header`, per-position `Proof`, `Entry@seq`,
    `KeyAvailability`, `KeyBody` and `Page` (`history_stream.rs:330-369`), and the HAVE/WANT
    exchange of ADR-036 H-6. `Head` changes shape (it carries the bridge).
  - *Proof*: SY-1–SY-5 and SY-9–SY-11 run on it. Its own mutants: a `Range` answer that skips the
    witness must be refused by the receiver (an apparatus holder sends one; the reader never shows
    the forged entry; mutant: accept it; red, PRODUCT); a `Have` naming an author's size as one
    million (SY-11's and SY-17's acts); a `Have` naming a different HeadID at the known size
    (SY-13's equal-size act).

- **SY-13. An entry is admitted by this rule, and by no other.** *(changed: findings 3, 4, 7, 12;
  changed r3: N1, N3, N4, N8; changed r4: third review P1 "prefix-root equality", P1 "sparse
  control leaves".)* Two states are kept apart: an object is **observed**
  when its author's signature verifies; it is **accepted** when it also fits the chain. Fork
  evidence is decided on observed objects, before any chain test can reject them (finding 4), and
  only on objects the author signed (N1).
  1. *Observe.* A signed head or header of author A, from any peer, is observed when it binds this
     room, its scope and A, and A's composite signature verifies under A's key as this room's
     governance knows it (ADR-008 LS-8, unchanged). A bad Merkle proof, a failed consistency or
     witness, or a wrong chunk hash from a relay never counts against A: it is the relay's fault
     (SY-15 rule 4) and the signed objects it carried are kept as observed, nothing more.
  2. *Fork evidence first.* Before anything else, an observed object is compared with what is
     held: a second observed header at a held position with a different hash; an observed header
     whose `prev_hash` differs from the held entry at N − 1 while both signatures verify; an
     observed head of the same size with a different root; an observed head whose **verified**
     inclusion opening of a position this node holds yields a leaf hash different from the held
     entry's. Each is two author-signed statements that cannot both be true: both are kept
     durably (SY-18) and ADR-036 H-6/H-7's fork rules apply to A, as today (`admission.rs:90-132`
     records the observation before continuity today, and keeps doing so). A failed or missing
     consistency proof is **not** fork evidence (ADR-036 H-3; N1): it leaves the new head observed
     and unaccepted, and the requester asks another holder (SY-14). A frozen author is still
     served to others under the heads this node accepted (ADR-044 RD-9 r3).
  3. *Accept a head.* An observed head H of A (size s′) is accepted when one of: (a) this node
     has accepted no earlier head of A (first contact); (b) a **consistency proof** from the
     accepted size s to s′ verifies: the canonical decomposition of `[1, s]` and `[s+1, s′]`
     (`log/history.rs:2261-2295`) whose descriptors recompute both the accepted root and H's
     root. *(r4: third review, P1 "prefix-root equality"; revision 3's rule (c), acceptance by
     an inclusion opening of the highest held position, is withdrawn: an author can sign H5 and
     then an H16 that contains the same signed leaf 5 over different leaves 1–4, and the opening
     of leaf 5 under H16 proves nothing about them.)* **Composition** (N4): the descriptors of a
     consistency proof need not all come from one holder. The holder sends the descriptors it
     has for the decomposition and names the ranges it lacks (`EvidenceUnavailable{ranges}`);
     the requester supplies, for each lacking range inside `[1, s]`, the descriptor it kept with
     its intervals under the accepted head (SY-18) or computes from leaves it holds whole; a
     range still missing is asked of the next holder as a `Head(A, bridge)` whose bridge names
     the ranges wanted, and the author can always supply all of them (its tree is canonical).
     The proof is verified only when the set is complete; a partial set accepts nothing. Where
     `since` > `at` (a head accepted while no tail is held, the Head-only state) the proof is
     the same pure Merkle object and no held leaf is involved. A set that is complete and fails
     (both heads signed by A) is **not** fork evidence by itself (N1: a relay can alter a node);
     the head stays observed, the requester asks another holder, and the author's own answer
     failing is the author's fault: fork evidence then arises from rule 2 when any witness under
     H opens a position this node holds to a different leaf. A hostile author whose H16 shares
     leaf 5 and differs below it can therefore never get H16 accepted by anyone holding 1–5, and
     the moment any of its leaves 1–4 is opened under H16 the fork is said. When no connected
     holder can complete the set, H stays observed, nothing under it is fetched from that holder,
     and status names the wait ("waiting for a member that can prove A's head from size <s>, or
     A itself", ADR-042). The known size is the size of the newest accepted head. A `Have` is
     never a size (SY-12).
  4. *Accept an answer.* An answer is verified whole in memory (its bridge proof, its witness,
     each header's signature and chain link, each body's hash) and then committed in **one store
     transaction for every entry it carries** (r4: the replace arm's first design finding; the
     shipped per-entry `begin_sparse_publication` cycle, `entry_store/sparse.rs:2038`, admitted
     about 5 entries a second on the arm and is replaced for received ranges; the read view
     reads the committed snapshot, ADR-044 RD-4, not a republished copy; the throughput floor
     SY-5 proves follows from this). *(r9, round 2's items 1 and 6; changed r13: SY-29's lanes
     and SY-30)*: that transaction is one item of the room's **authored lane** (SY-29: at most
     one queued per flow, never the pending-write place), and it **renders the chunk's Content
     in the same transaction** by SY-13 rule 5's two lookups (reader's key, own cut; the Session
     projection's bounded step with it), so a chunk is rendered when it is committed and there
     is no owed-effects queue for Content (cycle 5a's `effects_owed` 1,587 cannot exist); the
     governance-kind entries it carries are admitted in it and **closed in the control lane**
     (`CLOSE`, the fold's turns), never under a history request's job or deadline (round 2's
     fatal fault); ADR-044 RD-4's read view, when built, reads the committed snapshot; and every
     index write a receiver makes goes through the room's **owned-write protocol**
     (`Source::write_owned`, ADR-044 RD-10's FIFO place, as a lane item), never a
     `history_write` that can answer "room publication is busy" to a receiver while the room's
     own post is pending (round 2 dropped 309 verified answers on y1 before fde2e963c):
     the headers, the bodies, the interval or leaves with their witness descriptors coalesced
     into SY-18's set, and the new head if it was accepted here. An observed header at position
     N is accepted when **the witness opens N** under an accepted head of A (a range witness
     opens every position of its interval; a control proof opens each control leaf it carries,
     with the omitted content positions between them proved absent of controls: the shipped
     `ControlRangeVerifier`, `log/history.rs:1950-2150`, returns exactly those separated leaves)
     **and** its chain links agree with whatever neighbours are held: if N − 1 is held, this
     header's `prev_hash` is that entry's hash; if N + 1 is held, that entry's `prev_hash` is
     this header's hash; a disagreement with a held neighbour is rule 2's fork evidence. *(r4:
     third review, P1 "sparse control leaves": revision 3 required adjacency or first position,
     which rejected controls 3 and 5 of a `ControlRange(1, 5)` whose content at 2 and 4 is not
     sent; a witness-opened leaf needs no neighbour.)* Adjacency by itself never admits (N3). A
     proof that needs a context this node lacks (`MissingContext`) parks the answer in memory,
     raises a `Context` request (SY-14) and resumes when it arrives; the parked answer holds its
     permit (SY-24) and is discarded at the request's deadline. A kill between verification and
     commit loses the answer and nothing else.
  5. *Other authors.* Nothing about other authors is checked for **acceptance or rendering** of
     a content entry: a `seen` reference or a `pre_context` coordinate naming an entry not held
     does not stop acceptance, and does not delay rendering (SY-3's effect rule, r9: the effect
     path is resolved in this direction; `prepare_received_effect`'s coordinate loop runs for
     governance kinds only). The fold's rule is SY-3's.
  6. *Bodies.* A body is accepted when its hash equals the header's payload hash; a partly
     received body is staged with its binding under SY-18, as ADR-036 H-4 requires. An entry
     already held is ignored; a range answer that repeats held entries is harmless.
  - *Closes*: items 3 and 5; it removes the walk that made item 1 fatal.
  - *Deleted*: the parent receipt and the prefix receipt (`combine_parent`), the exact-head proof
    per position, the `EvidenceUnavailable` reroute to the author (`bounded_sync.rs:3820-3892`).
  - *Proof*: SY-3's. Plus `an_equivocation_is_detected_and_said_proof.rs`, extended with four
    arrivals through a third member: a second header at a held position; a header whose
    `prev_hash` names a different predecessor; a same-size head with a different root carried in
    a `Range` answer's head; and the **equal-size two-holder** case (N8): the author gives B root
    R and C root R′ at the same size with no body gap, B receives C's `Have`, asks `Head`, and
    says the fork within 30 s. Each is said as a fork, as today, and the room keeps reading the
    other authors. A **malicious relay** act (N1): an apparatus holder answers `Head` with two
    genuine signed heads of an honest author at sizes 4 and 16 and an altered consistency node;
    the author keeps posting and every real member renders its posts within 5 s, and no status
    line calls it conflicting. Mutants: skip rule 2 (no fork said; PRODUCT); test consistency
    before recording the same-size head (the third arrival is not said; PRODUCT); drop the
    equal-size `Head` trigger (the two-holder fork is never said; PRODUCT); treat a failed
    consistency proof as fork evidence (the honest author is frozen, its posts stop rendering;
    PRODUCT). Two r4 acts in the same file: **same-leaf, different prefix**: an apparatus author
    signs H5 over leaves 1–5, then H16 whose leaf 5 is identical and leaves 1–4 differ, and an
    apparatus holder serves H16 with an opening of leaf 5 to a member holding 1–5; the member's
    status never shows the author current at 16, shows the named wait, and once the holder
    serves any of leaves 1–4 under H16 the fork is said (mutant: accept a head by an inclusion
    opening of the highest held position; the member shows the author current at 16, PRODUCT);
    **sparse controls**: a member whose anchor is above an author's tail receives
    `ControlRange(1, 5)` with controls at 1, 3 and 5 and content at 2 and 4, and
    `control_current` for that author is true within 10 s (mutant: require an accepted
    neighbour or first position; it never is, PRODUCT).

- **SY-14. What is wanted is derived from held facts every time it is needed, and never stored.**
  *(changed: findings 2, 6, 7; changed r3: N2, N6, N7, N8, N9.)* Per room and author A,
  the inputs are: the anchor, the held body intervals, the held headers, `control_through`, the
  known size (SY-13 rule 3), each held header's retention (its signed `claimed_ms` against the
  room's retention, ADR-023 RL-2.5), the staged partial bodies, the positions every holder
  answered `not for you`, and, in memory only, each connected peer's `Have`, its **availability
  overlay** (the `Held` answers of probes to it, merged with its `Have` for selection; N6) and its
  negatives (SY-15 rule 4). Then:
  - control wanted = control positions `control_through + 1` to the known size, where
    `control_through(A)` starts at A's **fence post** when the room has a creator checkpoint
    (SY-27 point 3; the newcomer's fold starts from the checkpoint's state) and at 0 otherwise or
    while Q7 is answered "verify everything": headers through `ControlRange`, then through
    `Range{bodies}` the bodies of the governance-kind entries this node needs (kinds 1, 8, and 6
    addressed to it); `control_through` advances to the highest position through which every
    control header is held and every needed body is held or `not for you` (r5: SY-27) — it is
    **received coverage**, the demand clock, and is distinct from `closed_through(A)`, the
    validated frontier the governance fold derives from its closure index (SY-3 rule 3's state
    table, r12); demand reads the first, `CLOSE`'s stop and the creator's fences read the
    second, and nothing waits for them to meet;
  - **after access**, lowest class (SY-15): the sealed bodies of every other key package
    whatever its recipient (the always-on relay of ADR-023 RL-4.5, ledger row 40: every member
    keeps them; the relay must hold the bytes, not merely be allowed to serve them: N9), and the
    Checkpoint, StepPolicy, SessionFloor and PrivateSupport entries, all from position 1
    regardless of the anchor and the fence post; none of it gates access (SY-27);
  - closure wanted (r10, eighth review 2; the ancestry class of r7, widened to SY-3 rule 3's
    pinned closure) = for every held control entry E that is pending, every member of E's
    closure this node lacks: **directly**, the coordinates E names and E's previous own entry;
    **recursively**, the `seen` parents of content headers in it, the coordinates a
    `ContextUpdate`/Checkpoint/PrivateSupport header in it names, and the closures of the
    governance-kind and typed-policy entries in it; **bodies** for governance-kind and
    typed-policy members (`Range{bodies: true}` of that one position), headers only for the rest
    (`Range{bodies: false}` with its witness); **deduplicated** per (author, position) across
    every pending entry that needs it, one request in flight per position, asked of any holder
    whose `Have` or overlay covers it; **wake**: the arrival of any member re-evaluates every
    pending entry that named it (a pending-by-prerequisite index, in memory, derived from the
    pending set at open); a member no holder can supply keeps its dependants pending and is
    shown by ADR-042's dependency line, never a barrier (SY-3 rule 4);
  - bodies wanted = positions from the anchor to the known size, less the held bodies, the expired
    ones and those every holder refused `not for you`; cut into ranges of at most 128, taken from a
    per-author cursor over the interval set (O(log holes) per range, never a materialized list);
  - own feed wanted (this node is A) = positions above the held own feed, up to the highest
    *signed* own head verified from a connected member's `Head(me)` answer (SY-11);
  - explicit = the page a person asked for below the anchor (SY-9);
  - head wanted = one `Head(A, bridge)` toward a peer whose `Have` names a size above the known
    size **or a HeadID this node has not accepted at or below it** (N8; an accepted earlier head's
    id is remembered in memory for the connection's life, so a peer's unchanged, already-checked
    head raises nothing), and toward any holder after a join for every author in the join answer
    that has no accepted head here; at most one in flight per (author, peer). Its outcomes (N7):
    a head accepted → done; `Busy` → re-armed at the retry time; a transport fault → re-armed by
    the port's backoff edge (ADR-025 D5); `EvidenceUnavailable` or `NotHeld` → the same bridge is
    asked of the next peer whose `Have` names that size or head, and when every such peer has
    refused, the advertisement is **unsupported** for those peers: it is re-armed only when one of
    their `Have`s changes for A, a new peer connects, or this node's own bridge changes (it held
    a new position). Nothing is dropped after one refusal, and nothing is retried in a loop;
  - context wanted = each hash a proof or an admission reported `MissingContext` for, asked first
    of the peer whose answer named it, then of any holder; at most one in flight per hash;
  - probe wanted = when a wanted range is covered by no connected `Have` or overlay: one `Probe`
    at a time per author, round-robin over the connected peers not known `NotHeld` for that
    range, those with `intervals_total` > 16 first (finding 6). A `Held` answer is installed in
    that peer's overlay and wakes the pass, so the next pass selects a `Range` toward it (N6); the
    overlay for (peer, A) is dropped when that peer's `Have` for A changes or the peer
    disconnects, and a `NotHeld` answer is a negative for (peer, A, range).

  A restart re-derives all of it from the store and the first `Have` exchange. This is ADR-006
  S-16's rule ("What is owed MUST be derived, never stored") applied to every fetch, and the
  decider's ruling on the proof records applied to all fetch state.
  - *Closes*: items 1, 4 and 7; part of 20.
  - *Deleted*: the live window cursor, the hint inbox (`hints.rs`), the per-flow `Operation` state
    machine, the durable archive continuation of ADR-036 H-4.
  - *Proof*: a **seventeenth-interval** act in `a_newcomer_reads_the_whole_history_proof.rs`
    (N6): an apparatus holder holds seventeen disjoint intervals of an offline author and
    advertises its highest sixteen; a newcomer whose anchor lies in the seventeenth shows that
    text within 60 s. A **Busy-then-Head** act (N7): the only holder of a quiet author answers
    `Head` with `Busy` once and then normally, its `Have` unchanged; the newcomer shows the
    author's text within 30 s. A **late relay** act (N9) in `key_package_proof.rs`: R joins after
    S has sent a key package to T; S goes offline; T comes back and reads S within
    `ONE_TIME_WAIT_MS`, served by R. Mutants: select ranges from `Have` only (the seventeenth never
    renders); do not re-arm after `Busy` (the quiet author never renders); exclude other
    recipients' packages from the control-body class (T never reads S); PRODUCT.

- **SY-15. Requests go out in a fixed order, a few per peer, with a progress bound for every
  class and every peer, and a newer head cancels none.** *(changed: findings 5, 7, 13; changed
  r3: N5, N10, N13.)*
  1. *Slots and permits.* Per connected peer, K = 2 requests in flight, each a slot under SY-24.
     There is no node-wide request count: what bounds the node is the **answer budget**, 1 MiB
     per answer held from the request's send until its bytes are committed or discarded (SY-24's
     table; N10), 64 MiB per node under ADR-036 H-7's buffer permits. When no permit is free,
     would-be requests queue **FIFO by the time they became eligible**, one queue entry per (peer,
     slot); a freed permit goes to the head of that queue. A permit's lifetime L is the
     exchange (≤ 20 s), plus verification in memory (bounded by the answer: ≤ 1 MiB of hashing
     and at most 2 × 48 descriptors), plus the commit wait, which is the room's FIFO place
     (ADR-044 RD-10: behind at most the owners ahead of it, each one bounded commit) or, when the
     room cannot save, until `StoreRecovered(room)`, capped by the room's 8 MiB retention after
     which further answers for that room are discarded, not retained. So a request waits at most
     ⌈(Q + 1) / 64⌉ × L for a permit, Q being the queue entries ahead of it (the first request
     behind 64 active exchanges waits one L, not zero: r4), and with P peers each wanting both
     slots, Q ≤ 2P: at 1,024 peers 32 × L in the worst case where every answer is silent for its
     whole deadline (N5's "one wave" claim is withdrawn; this is the bound). *(r6: P1-5)* The
     bound is finite only over the **runnable pool**: permits retained behind a failed write
     (at most 16 MiB in all, SY-24) are outside it, so the divisor is 48, not 64, and L for a
     runnable permit never includes a `StoreRecovered(room)` wait (a room that cannot save holds
     retained permits only); the bound assumes the store commits (ADR-044 RD-10's FIFO place is
     bounded) and says nothing about a node whose every room cannot save, which is `cannot save`
     (ADR-047 SO-11), not a scheduling state. ADR-025 D6.1's 16-per-node and 4-per-peer caps are withdrawn
     (amendment 16).
  2. *Deadline.* Each request has a 20 s deadline (`SYNC_FRAME_TIMEOUT`,
     `transport/stream_transport.rs:29`). A request that times out keeps what it verified; the
     rest is derived again and goes to another holder (rule 4).
  3. *Order.* **Every** opportunity toward a peer, whichever slot and whether or not a permit had
     to be waited for, is filled by the same rule (N5: fairness cannot live in a second slot that
     may never be admitted): first the two finite, person-shaped classes in strict priority —
     own-feed recovery (bounded by the own feed) and a person's explicit page (one at a time) —
     and then **deficit round-robin over the five open classes** *(r6: P1-7)*: prerequisites
     (`Head`, `Context`, `Probe`, `Snapshot`, parent and below-fence headers), control
     (`ControlRange` and governance bodies), the newest owed range of each author, the oldest
     owed range of each author, and **after-access** (relay key packages for other recipients
     and the Checkpoint, StepPolicy, SessionFloor and PrivateSupport entries from position 1,
     SY-14), which gets one opportunity in five like the others, so a relay that joined after a
     package was minted acquires it within a bounded number of exchanges and never starves
     bodies; an empty class is skipped and keeps no deficit. Within a class, rooms, then authors,
     take turns. Bound, with no permit wait: a class with eligible work toward peer P is served
     within 5 opportunities of P; an author with eligible work in that class, within 5 × (authors
     eligible in that class toward P) opportunities; an opportunity lasts at most one exchange (≤ 20 s). With a permit wait,
     add rule 1's bound. An author's body ranges are fetched whether or not its control is
     complete: the fold and display decide what is shown (ADR-037 R3's provisional marking), so
     an author's control backlog never holds another author's bodies, and a sustained stream of
     control entries by one author costs the body classes at most half of every peer's
     opportunities.
  4. *Holder choice.* A range goes to a connected peer whose `Have` or overlay covers it (or, for
     a probe, to the next peer in the rotation). Among covering peers the choice is by **attempt
     epoch** first, delivery second (N13): per (author, range) the node keeps, in memory, the set
     of covering peers already tried in the current epoch; a peer is not asked again for that
     range until every other covering peer has been tried once in the epoch (an epoch ends when
     all have been tried, and a new one starts; elapsed time never ends an epoch early). Among
     the untried, the one with the best recent delivery (entries delivered per second of exchange
     time toward this node, a decaying average kept in memory per peer), ties to the fewest in
     flight; the author is not preferred (finding 5). So with H covering holders, an honest one
     is asked within H exchanges for that range, whatever the others' scores. Negative
     availability is per (peer, author, range): a peer that answered `NotHeld`, `Missing`,
     `EvidenceUnavailable` or `not for you` for positions is not asked for them again until its
     `Have` for that author changes its intervals or `control_through`; a `Have` update for
     another author changes nothing. A **short** answer (fewer entries than asked with no
     `Missing` or `Done` covering the rest, an empty answer, a bad proof, witness or chunk, or a
     timeout) counts as that peer's try in the epoch, and the remainder is re-derived and goes to
     the next untried covering peer. `Busy` is honoured until its retry time and counts as no
     try.
  5. *Growth.* A newer head of A only raises A's known size. Nothing in flight is cancelled or
     replaced.
  6. *Passes.* A pass runs when something changes: a `Have` update, an answer, an admission, a
     connection, a context or probe arrival, a permit freed, the earliest retry time, or a
     deadline (ADR-037 R7). A pass visits only the authors and peers flagged by the change, and
     starts at most as many requests as there are free slots and permits; no pass walks every
     author. No periodic is the only driver.
  7. *Every request start* stamps the room's `last_request_at` per demand class (ADR-042 r3's
     row: body/control and own/explicit apart) and a refused start records its `start_reason`
     (ADR-042 TR-25; SY-24).
  - *Closes*: items 1, 2, 6, 10, 14, 85 and 87.
  - *Deleted*: supersede, preempt, reroute, deferred flows, the flow-state pool and its family
    (`bounded_sync.rs`), the Public and Background positions (`ports.rs`), the Archive lane,
    `RETAINED_FLOW_LIMIT`.
  - *Proof*: SY-4's third assertion (the short holder); SY-24's acts; a control-stream act in
    `a_newcomer_reads_the_whole_history_proof.rs`'s B1 act: one member appends a `ContextUpdate`
    control entry every second for 60 s while the others post; the newcomer still shows each
    member's post within 5 s. A **budget-saturated** act (N5), optional (`optional-proofs`) because
    of its size and mandatory on the fleet (ADR-045 J1's stage 2): 70 apparatus peers each hold a
    permit by answering nothing for 20 s and each advertise a stream of control entries, while
    one real member posts; the newcomer shows each post within 60 s throughout. A **four short
    holders** act (N13): four apparatus holders rank above the honest member by delivering other
    authors' entries fast and answer the target range one entry short near the deadline; the
    honest member's text renders within 5 × 20 s. Mutants: serve control before any body with no
    rotation (the control-stream posts stop rendering); prefer peers with nothing in flight at
    permit admission (the saturated act's posts stop); expire the short mark at 60 s (the honest
    holder is never asked within the bound); PRODUCT. Acceptance: 5 s; 60 s; 100 s.

- **SY-16. Any holder answers, and answering is a read under the one serving contract of ADR-044
  RD-9 and ADR-047 SO-1.** *(changed: findings 1, 12; ledger row 6; changed r3: N3, N4, sibling
  alignment.)* A member answers `Range`, `ControlRange`, `Head`, `Context` and `Probe`
  for any author whose entries it holds, not only its own feed, to any admitted member (ADR-008
  LS-34), under SY-25's gate for every body. It reads the room's committed snapshot through RD-8's
  lease, writes nothing, and waits for no save. It is admitted without the actor (ADR-044 RD-16).
  It answers under its own newest accepted head of the author (the head it names in its `Have`)
  and proves the requester's bridge to it (a consistency proof from `since`, composed as SY-13
  rule 3 says; an opening of `at` is sent only as the fence-boundary check of SY-27 point 3 and
  never accepts a head: r6, the fourth review's P1-1 retrace) and the witness of what it sends. A subtree it needs comes, in RD-9 r3's
  order, from: (1) a canonical range in the snapshot (one indexed read); (2) the process cache, by
  exact subtree identity; (3) reconstruction from the validated headers of its leaves and the
  contexts they name (one header read, one context read, one hash per leaf; one join per internal
  node), allowed when the head is committed here and every leaf of the subtree is held with its
  validated header; (4) a kept interval descriptor for a subtree it does not hold whole (SY-18).
  The author's fork state does not enter the rule (RD-9 r3: nothing derived is written back, and
  every committed head of one author lies on one chain, so a frozen author's held branch is
  served, after a restart too). A subtree it neither holds whole nor has a descriptor for, or a
  bridge it cannot prove (a `since` or `at` inside a collapsed descriptor), is answered
  `EvidenceUnavailable` at once, never Busy and never a wait for the author; the requester asks
  the next holder (SY-14). Cost, per miss and not per process life (RD-9 r3): O(1) reads for a
  canonical or cached subtree; O(k) reads and joins for a k-leaf reconstruction, a join merging two
  control frontiers, repeated when the cache has evicted it. The contexts a reconstruction
  generates go to RD-9's proof handoff for that peer, so its following `Context` is answered. An
  author serving the feed it appended never reconstructs (every perfect subtree was a canonical
  range at the append, `sparse.rs:1839`); a whole-prefix holder can prove any bridge; a sparse
  holder proves what its leaves and descriptors reach and says `EvidenceUnavailable` for the rest.
  It serves what it holds, names what it lacks (`Missing`), and never waits for the author.
  - *Closes*: items 2 and 14 (a heavy or slow author is asked only for what delivers slowest from
    it, by SY-15 rule 4).
  - *Deleted*: the stand-aside for serving (ADR-044 RD-8 deletes it), the author-only reroute, the
    fork gate and the per-leaf signature re-check in reconstruction (RD-9 r3's reasons).
  - *Proof*: SY-2's B2 act (the quiet-room act in `a_newcomer_reads_the_whole_history_proof.rs`,
    not SY-9's B2 paging act; the one ADR-047:710 means) shows it: the fast members serve the
    slow member's feed. A **sparse,
    unaligned** act in the same file (N3, N4): the author posts 16 entries and goes offline; X
    holds 5–16 under head 16 (its anchor was 5; its interval is not a power of two) and Y holds
    1–5 under head 5; both are restarted cold; Y asks X for 13–16 with bridge (since 5, at 5): X
    sends the descriptors it has for the 5→16 decomposition (leaf 6, 7–8, 9–16) and names 1–4 as
    lacking; Y computes 1–4 from its own leaves, verifies the composed proof, accepts head 16, and
    `vox room read` on Y shows 13–16 within 60 s (r4: composition, SY-13 rule 3). Its negative
    control: X holds 13–16 only (it lacks 6 and 7–8); Y's status says "waiting for a member that
    can prove A's head from size 5, or A itself" within 60 s and shows nothing forged; when the
    author reconnects, Y shows 13–16 within 30 s. Mutants: answer only under the head the
    requester last accepted (Y shows nothing, red); accept the head on a partial decomposition
    (the control shows 13–16 before the author returns, red); PRODUCT. Acceptance: 60 s; 30 s.

- **SY-17. The join answer is a `Have`, each author's signed head, the creator's newest
  governance checkpoint, the joiner's own feed, and every author's control range from its fence
  post.** *(changed: finding 2; changed r3: N9; changed r5: SY-27.)* After admission (ADR-005,
  unchanged), the member sends its `Have`; its newest signed head of every author it holds
  (`HeadAnswer`s with an empty bridge: the joiner has accepted nothing yet); the creator's newest
  governance checkpoint with the creator's chain from it to the creator's head (SY-27 point 3;
  absent when the room has none, and then every fence post is position 1) and the checkpoint's
  snapshot (`Snapshot{hash}`, SY-12; the joiner refuses one whose bytes do not hash to the
  checkpoint's `H`); the joiner's own-feed `Range` if the member holds any of the joiner's feed
  (a rejoin, which is a fresh join after a leave that keeps only the node's own append
  checkpoint: ledger row 34, ADR-049 LE-9, SY-11; the joiner then pushes its unconfirmed own
  suffix to members that lack it); and the `ControlRange` answers for every author, from its fence
  post up to its size, within the answer budget (one chunk per author in the measured room), the
  rest asked by the joiner as its first requests; relay key packages and the Session kinds come
  after access (SY-14). The joiner sets each author's anchor to the size of
  that author's **verified signed head** plus one (ledger row 38); an author named only in the `Have`
  with no verified head gets no anchor until a `Head` answer verifies (SY-14), and an author first
  seen after the join has anchor 1. A `Have` claiming a size above the verified head raises a
  `Head` request and sets nothing. The room becomes writable when the joiner holds its own feed
  through the highest verified signed own head among connected members' `Head(me)` answers and
  its governance fold is current (ADR-037 R2, R5; SY-11). No "complete live window" exists or is
  waited for. The member answers the join off its actor; the joiner's patience follows the
  member's `Busy` retry time (SY-10).
  - *Hostile member*: advertises an author at one million (no head verifies at that size: anchor
    unset, then set from the honest head; nothing suppressed); forges a head (signature fails;
    nothing observed); sends a head of a frozen author (observed, fork evidence kept, served as
    evidence).
  - *Closes*: items 3, 8 and 10.
  - *Deleted*: ADR-036's join settlement on a live window (amendment 9); ADR-037 R10's own-author
    hint (amendment 13).
  - *Proof*: the B1 act; plus a false-advertisement act in the same file: an apparatus member
    answers the join with a `Have` naming an author at size 1,000,000 beside the true signed head
    at 300; the author posts; the newcomer shows the post within 30 s (the anchor was set from the
    head). Mutant: set the anchor from the `Have`; the post never shows, red, PRODUCT. Acceptance:
    30 s.

- **SY-18. A node keeps, per room and author, exactly these facts for sync, and nothing else;
  the list is one with ADR-044 RD-9 r3 and ADR-047 SO-1 r3.** *(changed: findings 9, 10, 12;
  ledger row 5; changed r3: N3, N4, N12, sibling alignment.)*
  - the entries themselves (headers, and bodies held), as today: a header is written only by a
    verified admission (SY-13 rule 4), so the position index is itself the acceptance evidence a
    receipt duplicated (SO-1 r3's words);
  - the anchor (8 bytes) and `control_through` (8 bytes);
  - per removal written before this release, its recorded cut `(removal hash, target, through)`
    (SY-3 rule 5; SY-26 writes it once);
  - the newest accepted signed head per author (exists today as the committed head), and fork
    evidence (both signed witnesses) when there is a fork; every other head object is unreachable
    and is deleted in the commit that accepts the newer head (SO-1 r3's reachability rule);
  - the room's **baseline**: the accepted creator checkpoint's summary (≤ 1 MiB, one object)
    keyed by `H`, with the checkpoint entry hash as provenance (SY-27 point 3; r7, simplified
    r10): immutable, served whole by `Snapshot`, replaced in the transaction that installs a
    newer one; the fold's
    projection is derived from it and never written into it;
  - *(storage classes, for ADR-047 SO-15's `sync_bytes` oracle, r9, D7)*: every fact in this list
    is `index` (headers, heads, fork witnesses, anchors, `control_through`, recorded cuts,
    interval descriptors, contexts, the baseline object (one row, keyed by `H`, replaced in the
    transaction that installs the next; r11: no staged chunks), the gapped continuation's
    headers and head) or `messages` (bodies, staged partial bodies); **nothing this ADR keeps
    is `sync`**, so `sync_bytes` is 0 whenever no fetch is running;
  - per author, an **observed, gapped continuation** when one exists (SY-11's short-peer case;
    r7): its signed head and at most 128 pushed headers, kept unaccepted until the bridge proof
    can be composed, then promoted or discarded in one commit;
  - per held interval, its **descriptors**: the canonical descriptors of the perfect subtrees the
    interval's leaves fill, and the sibling descriptors that connect them to the newest accepted
    head's root (ADR-036 H-3's range-proof shape; about 2·log₂ n descriptors of 71 B per
    interval, ADR-047 Appendix B). They come from the answer's **witness** (SY-12), never from
    adjacency alone (N3), and are coalesced on arrival: two adjacent intervals under the same head
    merge (siblings inside the union become computed nodes), and when the head advances the
    bridge proof that accepted it supplies the path to the new root, which replaces the old path
    in the same commit; the proof itself is dropped. These descriptors, with the validated
    headers, are the **leaf-to-head tie** ADR-044 RD-9's reconstruction gate (its item 3; item 2 is the cache) needs and the one ADR-047 SO-1 r3
    names ("the position index and the head tie"): a whole-prefix holder needs no descriptor
    (its canonical ranges are recomputed from leaves, SY-16); a sparse holder's descriptors are
    what let it serve its leaves under the newest head after a cold restart. No inclusion,
    parent or prefix receipt is kept, by any node, for any feed, under R1 or R2;
  - every context object named by a held header's `pre_context` (content and control alike), the
    post-contexts admission generates, and the frontier contexts the kept descriptors name:
    content-addressed, kept once, and deleted only when no held header or kept descriptor names it
    (finding 9: `leaf_descriptor` and `join_descriptors` read all of these, `log/history.rs:764-864`);
  - a staged partial body: the entry hash, the payload length, the room instance, the audience and
    the bytes received so far (ADR-036 H-4's binding), at most 4 per room, deleted when the body
    completes, the entry expires or the audience changes; this is the entry's own bytes, not a
    fetch record (finding 10).

  Nothing is kept per peer, per request, per fetch or per head: no proof record, no inclusion
  receipt, no parent or prefix receipt, no verifier cursor, no live window, no hint, no
  continuation, no explicit-page state, no probe result, no delivery score. A proof is verified in
  memory and dropped. Store growth per admitted entry is the entry, its header and one interval
  update; a new head costs one path of descriptors. **Atomicity**: an answer's headers, bodies,
  interval and descriptors, and the head it accepted, are one commit (SY-13 rule 4); a kill before
  it loses the answer, a kill after it finds the interval with its tie. There is no state in which
  a held interval lacks its tie.

  `control_through` is kept although plan A listed only the anchor and the intervals: without it,
  governance after a restart would wait for a peer, against ADR-037 R1 ("preparation on open MUST
  wait only on work this node finishes alone") and ADR-036 H-1 ("Persisted control … MUST survive
  restart").
  - *Closes*: item 20's sync half; SY-8.
  - *Deleted*: `ObjectKind::ProofRange` and `keep_history_proof_range` (`sparse.rs:2506-2540`,
    `admission.rs:449-466`); `keep_history_parent_receipt`; inclusion receipts
    (`history_inclusion_receipt` and its writer); the verifier cursor (`sparse.rs:3897-3913`);
    `LiveWindow` in `AuthorState` (after SY-26 reads it once); the `source_heads` per-entry head tie
    (SO-1 r3). ADR-047 SO-2 deletes the rows already on disk, after SY-26 has read them.
  - *Proof*: SY-8's (`sync_bytes` = 0; the large-body restart arm); SY-16's sparse unaligned act
    (the tie serves after a cold restart, for a non-power-of-two interval received in a byte-cut
    answer). A context act in the same file: an author's last control entry is followed by 200
    content entries; the holder is restarted cold and the author goes offline; a newcomer joins
    and reads the 200 within 60 s (finding 9). Mutants: keep only contexts named by control
    headers (the newcomer shows nothing of the author); admit an adjacent entry without a witness
    (SY-16's sparse act: X cannot serve 5–16 after its cold restart, Y shows nothing); PRODUCT.
    Acceptance: 60 s.

- **SY-19. What R2 deletes.** Plan A's count at v0.4.30, verified by line count: all of
  `node/history_stream/hints.rs` (586 lines); in `node/history_stream/runtime.rs` the live window,
  retry, tail, control closure and reroute machinery (about 3,000 of 4,135); in
  `node/history_stream/admission.rs` `preflight` and the parent receipts (about 700 of 1,117); in
  `node/actor/bounded_sync.rs` supersede, preempt, reroute, deferred flows, the pool, the retained
  flow limit and its family (about 3,500 of 6,095); in `node/channel/entry_store/sparse.rs` the
  live window, proof records and receipts (about 1,200 of 4,114); in
  `node/history_stream/client.rs` the per-query receivers (about 1,500 of 2,664); in
  `node/actor/history_demand.rs` the Archive phases. In all, about 10,000 lines deleted and
  3,000–4,000 written (the revision added the probe, the entitlement gate on the range paths,
  head substitution, holder scoring and the context retention rule). Kept: `log/history.rs`
  (signed heads, proof checks, descriptors), `log/entry.rs` (chain checks), `source.rs` read paths
  (pointed at ranges), `ports.rs` (connections and backoff for unreachable peers), `credit.rs`,
  transport framing with truthful codes, `governance/sparse.rs`'s coordinate validation and
  `governance/view.rs`'s eligibility.

- **SY-20. Sync supplies ADR-042's outcome measures from what it already knows.** *(changed:
  finding 2; ADR-042 r2's rows.)*  In
  memory, with no extra round trip and no write:
  - per room and author: the known size (signed); the highest size any member advertises, by whom
    and when (a hint, shown apart from the known size and never as "behind": ADR-042 TR-1's
    `size_advertised`, which this ADR asks ADR-042 to show as unverified); the anchor; bodies held
    through (the highest position up to which every body from the anchor is held, expired or
    `not for you`); bodies owed, split into "no header" and "header without its text"; control
    owed (known size − `control_through`); age of the newest body received; `control_current`;
  - per room and member: last received from it; last sent to it (an answer that delivered at least
    one entry its `Have` said it lacked; this is the "served progress" call site ADR-042 TR-3 and
    ADR-044 RD-3 rely on, fed by RD-16's `BoundedSyncDone`); requests in flight, with age and the
    exchange durations ADR-045 FG-5 reads, as `vox status --json` `peers[].sync.last_exchange_ms`
    (the wall time of the most recent completed exchange toward that member, start to last frame)
    and `peers[].sync.exchange_ms_p50` over the last 32 (r9, X045-4; ADR-042 Appendix A lists both
    under this ADR's name); its delivery rate (SY-15 rule 4); refusals by reason;
    cancellations (never failures); the last failure with its time, cleared by the next request
    that delivered; what it says it holds of this node's feed (`held_through`);
  - per room: `last_request_at`, the last refused start's `start_reason` (SY-24);
  - per node: the served-request wait, median, 90th percentile and maximum (SY-6); flows retained
    and why, and every slot owner by name (SY-24; the `lanes.slots` leak's settling evidence).

  ADR-042 owns every word a person reads. Under R2 its "live window" becomes "at or above the
  anchor" (amendment 20).
  - *Closes*: item 13; with ADR-042, the status half of items 1–4, 85 and 87.

- **SY-21. Each sync refusal is a typed answer, and each maps to an ADR-040 edge or to no wait.**
  *(changed: findings 1, 12; ledger row 6.)* 

  | Refusal or wait | Meaning | What happens |
  |---|---|---|
  | `Refuse{Busy, t}` | the holder is at its serving budget, or its governance projection is one turn behind (SY-25) | that peer is not asked before `t`; others are; no obligation is parked |
  | `Refuse{NotHeld}`, `Missing` | the holder lacks it | asked of another holder; if none is connected, the room reads "waiting for a member" (ADR-042) |
  | `Refuse{EvidenceUnavailable}` | the holder has it but cannot prove it under any head it holds (ADR-044 RD-9) | "not held here; ask another holder": asked of another holder, never Busy, never a wait for the author |
  | `body_state = not for you` | this node may not receive that body (SY-25) | permanent for that position until this node's governance view applies a later readmission; shown as "not available to this node" (ADR-042) |
  | no holder connected | — | `PeerReachable(peer)` (ADR-040 NW-1) for the peers whose `Have` covers it, or any admitted member when none does, released as ADR-049 r7 wrote the row (X049-6, verbatim): predicate `net.manager().existing(peer)` is `Some` with `close_reason()` `None`; released by `NetEvent::Connected { peer }` (`actor.rs:3419`, handled at `:12273`: a new authenticated connection filed) and by a peer's inbound session for a room this node holds hidden (the departure-probe answer path, `actor.rs:13440-13497`); never by a refusal on a live connection (that is the port's backoff, a preserved owner); words `member <name> is reached`. This ADR's `PeerConnected(peer)` is that event; a trusted member that cannot be connected to is shown as the plain fact `offline, last seen <dur> ago` and is not unhealthy; the alarm is `waiting for a member` only when wanted entries have no other holder (the decider, ledger row 27; ADR-042's words) |
  | admitting a received entry waits for the room's pending write | — | `RoomWrite(room)` (ADR-040 NW-1; ADR-044 RD-10's FIFO place) |
  | a control entry names a coordinate not yet held | — | not a refusal; the fold keeps it pending (SY-3); nothing waits on it |
  | nothing in flight although entries are wanted and a holder is connected | must not occur (SY-24) | a named wait with its `start_reason`, shown by status; the fleet alarms on it |
  | `Refuse{NotMember}`, `Malformed` | never | terminal for that request; said to the person |
  | `Cancelled` reset | withdrawn on purpose | counted as a cancellation, not a failure |
  | `TransportFailed` reset, deadline | a fault | a failure; ports back off as for an unreachable peer (ADR-025 D5) |
  | the link returns after every peer dropped at once | — | **the network-change path is driven by the link's return, not only by an address change** (r9, X045-22, this ADR owns it; ADR-042 TR-6 only reports): `PeerConnected(peer)` (the row above) clears that peer's port backoff and runs a pass (SY-15 rule 6) whether or not the local address changed; v0.4.30 clears backoff only at the network-change site that fires on an interface or address change (`network.rs:1753-1760`'s refusal-retire path and the `NetworkChanged` handler in `actor.rs`), so a link that comes back on the same address waits out the full backoff (ADR-045 FG-15 A-1's 15:04Z shape). Proof: ADR-045 FG-15 A-1's act, in tree as an arm of `a_sync_failure_names_its_reason_proof.rs` with the forwarder blackholing every front of M for 16 s on an unchanged address: within 30 s of the heal every peer is `connected` and the first completed exchange follows within 30 s more; mutant: clear backoff on `NetworkChanged` only; the peers stay in backoff past 60 s, red, PRODUCT |

  A **refused inbound request** (X044-6, ADR-044 RD-16) records its reason on the serving side
  as `peers[].served.last_refusal` (`Busy`, `NotMember`, `NotHeld`, `EvidenceUnavailable`,
  `Malformed`) with its time, shown by ADR-042's served line; the outbound `start_reason` is
  SY-24's.

  ADR-040's inventory rows that are this ADR's lane: row 31 (the history demand and Archive busy
  texts) is deleted with the Archive machinery; row 30 (a member busy answering joins) becomes
  `Refuse{Busy, t}` to the joiner, waited out within SY-10's bound; rows 35 and 36 (a join accepted
  but not completed) wait on `RoomWrite(room)`, and row 36's B3-reach instance stays UNKNOWN until
  item 8's experiment names it. No wire code says "inclusion header is absent" (the header is
  always asked before its proof) and `ProtocolLimits` is sent only for a real limit (ADR-042 r2).
  - *Closes*: item 11; part of 6 and 8.

- **SY-22. R1, the repair of the present mechanism, is the recorded alternative; it is not built.**
  *(changed: finding 15; changed r3; changed r5: ledger row 57.)* The decider chose R2 on
  2026-11-13. R1's corrected nine steps and what was measured of it stay under "The recorded
  alternative" so that the reason is on record: its deciding-round arm cured B1 and the join but
  never read the slow heavy author, because its control coverage was keyed to the exact head and
  walked from that author alone, and its own trace named as its next step the change the
  replacement already had. No invariant of §1–2 depends on which route delivers it.
  **One observation contract** (the decider, ledger row 26; r4): this ADR accepts ADR-042's five
  contract rows explicitly and unchanged: (1) a connection-owner inventory heartbeat frame every
  30 s (`unchanged` form) independent of requests (`Have`'s stream, SY-12), so `NOT HEARD FROM`
  exists;
  (2) `control_through` (held) and the fold's applied position per author, with the pending set
  **by entry kind** and each pending entry's wait (context hash, parent header position, or
  fold), and a control range's proof of absence counted as coverage (X042-2); (3) the per-peer
  availability overlay, the negatives per (peer, author, range), their invalidations,
  `intervals_total`, and an **`unknown`** availability state for a range no connected `Have` or
  overlay covers and no probe has answered (X042-3); (4)
  `last_request_at` and the in-flight set per demand class (sync and key), and per runnable
  demand its eligibility inputs (entry time, holder connected at, last answer or refusal at,
  `Busy` until); (5) body-completion and body-chunk events with author and position, `Head`
  acceptance events with their source, fold-application and key-installation events,
  `held_through` as body-complete positions, `start_reason` values with the first ledger error,
  the ledger per node by actor, and slot owners by name. SY-20 supplies them; ADR-042 owns the
  words.

### 4. Proofs

- **SY-23. Each requirement lands with its proof, the proofs it makes redundant go, and the fleet
  holds the release.** *(changed: findings 16, 17, 18; changed r3: N16, the reader defect.)*
  In-tree proofs are the acts named above, added to existing journeys:
  `a_newcomer_reads_the_whole_history_proof.rs` (B1, B2, L1 and the governance, control-stream,
  sparse, context, seventeenth-interval, Busy-then-Head and false-advertisement acts; B3,
  budget-saturated and the 17-node removal arm optional), `key_package_proof.rs` (relay; late
  relay), `a_sync_failure_names_its_reason_proof.rs` (codes; SY-24's three acts),
  `a_slow_joiner_gets_in_or_is_told_why_proof.rs`, `a_node_leaves_a_room_proof.rs` (rejoin,
  rebuild, readmission: sender and receiver), `an_equivocation_is_detected_and_said_proof.rs`
  (four arrivals; the malicious relay), and ADR-047 SO-2's upgrade journey (SY-26's arms). Every
  mandatory act runs under 6 minutes and the optional ones under 10, so the release gate fits the
  decider's 8–10 hours (ledger row 19); every proof runs inside the VMs ADR-045 FG-1 provides,
  nothing on the host but the driver (ledger row 32). The B3 act is an optional proof (`optional-proofs`), loud
  when not run; its mandatory form is ADR-045 J1. Under Q2 = yes, the newcomer proof's claim 2
  stops deriving its staging from the 128-row live window
  (`a_newcomer_reads_the_whole_history_proof.rs` at v0.4.30 `:17-24, 1459-1460, 1513`): every
  pre-join post is older history. On the fleet the claims are ADR-045 J1 and J2 (the decider, ledger row 52: the fleet is the gate). No
  diagnostics land in released commits (ADR-037 R13). Each red names PRODUCT or APPARATUS.
  Timings from knob or trace binaries are investigation evidence in the table and are marked
  "inv."; the release-asset reds are marked "verified". **Every B3 "never rendered" count from
  the trial and the prototype report is unreliable** (Main, 2026-11-13): the rig's room reader
  scanned only the newest 200 rows and never paged, so a hello pushed below them read as absent.
  Those counts are struck below; B3 rows carry only what the corrected reader measured (the
  deciding round's arms) or "unmeasured".

| Requirement | Journey | v0.4.30 | Best so far (build) | Acceptance |
|---|---|---|---|---|
| SY-1 | B1 hellos | 54.2 s (repair session) / 80.6 s (replace session), verified; 57.5 / 88.9 s (trial session) | 10.5 s (repair arm); 8.5 s (replace arm); 23.3 s (trial) | 30 s |
| SY-1 | author at 2/s, slow server | 3 of 487 held (inv.) | — | ≤ 50 behind at 150 s |
| SY-2 | B2 fast members' hellos | 52.5 / 150.8 s (verified, E-1); 90.3 / 95.3 s (inv.) | 1.2 s (trial) | 5 s |
| SY-3 | B1 doctor, control-current, reads both ways | 88 s "has not trusted you" (verified) | gov ≥ sampled 17.3 s (trial), 6.5 s (repair arm), 3.5 s (prototype) — counters, not the assertion; doctor all ok 8.5 s (prototype), 6.5 s (replace arm) | 30 s |
| SY-3 | B3 control-current for every member | **unmeasured**: no rig reads `control_current`; what the reports hold is governance ≥ members and doctor, which are not this assertion | repair, duty cycle session 2 (corrected reader): governance never, doctor "has not trusted you" for y1 and z1; slow path session 2: governance never; replace: doctor ok for 7 of 8 at 46.5 s (duty cycle) and 72–93 s (slow path), y1 "has not trusted you" | 60 s |
| SY-4 | B3 every hello (corrected reader only; session-1 repair rows were read before the pager fix and are **unmeasured**) | duty cycle: not joinable; slow path: 5 quiet joiners at 40–241 s (replace session) / n-old2..6 at 213–279 s (repair session 2), the heavy authors and n-old1 never | repair, duty cycle session 2: n-old1 4.0 s, y1 and z1 never, 26 entries admitted, 5 of 6 earlier joiners failed to join; repair, slow path: **unmeasured** (session 1 only); replace: 7 of 8 at 46.5 s (duty cycle) / 72–93 s (slow path), both fast heavy authors live at 43.5 s / 82.2 s, y1 never | 120 s |
| SY-4 | short holder | n/a (new wire) | — | 20 s |
| SY-5 | L1 catch-up, 5,000 behind | stays at 87 (inv.; release run owed) | — | 5 min |
| SY-7 | B1 "transport failed" samples | 273–302 of 300 (verified) | — | 0 |
| SY-8 | B1 store, proof rows | 268–376 MB, 32–40 k rows (trial session); 21,794 rows (repair session); 24,200 rows on the newcomer, 82,478 on y1 (replace session) | 151 MB (trial); 142 MB and **15,001 rows** (repair arm: its proof-row change was built after the measurement and is unmeasured); +47 MB and **0 rows on every node in every run** (replace arm) | `sync_bytes` 0 |
| SY-8 | 12 MiB body across a restart | unverified | — | 60 s |
| SY-9 | explicit page on a frozen node | never (verified) | — | 10 s |
| SY-10 | join with a paused member; join through a slow-path member | paused member: join fails 6.4 s, 10 of 12 earlier joiners fail (verified, both arms' baselines; item 88); slow path: 33.8 s (E-1), 29.1 s (repair session; J1(e) red) | replace arm: joins 5–7 s on both variants (the veto is unchanged there: one join failed once, repeated clean) | 10 s; 15 s |
| SY-11 | post after rejoin | about 6 min (verified) | — | 10 s |
| SY-24 | two fill/free cycles on one node; A reads B's posts; end and leave succeed | 11 retiring, ports queued, posts never shown (verified, `/tmp/RcaSchedStall/receipts/`†) | — | 30 s; 60 s |
| SY-25 | hostile recipient at the wire; real recipient pages back | passes on `entry()`; new paths | — | 30 s |
| SY-26 | frozen v0.4.30 root upgraded; old removal kept | rows 1 at 88 s (verified) | — | 30 s |
| Q1 arms | B3 on the corrected reader, both variants, each arm against its own v0.4.30 baseline | join fails (duty cycle) / heavy authors never (slow path) | **both FAIL**: repair (session 2) never reads the slow heavy author nor z1 and 5 of 6 earlier joiners fail to join (its control chain walked from that author alone, 441 of 1,521 positions at 300 s); replace reads 7 of 8 and never y1's own posts (y1 itself never becomes current: per-entry admission at 2.7–5.4 entries/s and 8 control headers per page against 6 entries/s); `control_current`, reads in both directions for all members and all-six-joiner staging were not observed for either, so neither has a full set of the rule's observations | every member ≤ 120 s; control-current ≤ 60 s; 0 rows |

## The recorded alternative: R1, repair the present mechanism (not chosen)

The decider chose against R1 on 2026-11-13 (ledger row 57) on the deciding round's numbers (Q1).
R1 keeps the hinted flows (`hints.rs`), the per-flow state machine (`runtime.rs`), the live window
as a cursor, proofs per entry and per head, one pending write per room, and ports with backoff. It
would have changed, in this order (plan A §2.2, corrected after finding 15):

1. No supersede, preempt or coalescing of a flow for head growth, at all (SY-1); a second Public
   position; a header asked before its proof (the trial measured the first two with "after one
   admitted entry" as its stopping rule; that rule is not SY-1 and is not kept; about 100 lines).
2. Item 3: `seen` references order only; control fetched per author as a control-proof set; the
   fold rule of SY-3; delete `ParentReceipt`, `PrefixReceipt` and `combine_parent` (about 600
   lines touched, 300 removed). **Untested on any build.**
3. Item 4: the window's floor is the join anchor (SY-26 initializes it); the server's gate is
   anchored and passes SY-25; placeholder rows (about 60 lines, plus ADR-042's).
4. Item 2: N Public positions, N = min(connected peers, 4) (about 150 lines; ADR-025 D1.5
   amended), each a slot under SY-24.
5. The reroute storm: a holder asked for a proof under a head it lacks answers under its newest
   head with a consistency proof (SY-16's substitution; about 200 lines); removes
   `EvidenceUnavailable` → reroute to the author.
6. No proof records and no receipts: verified ranges in a bounded memory cache; the interval
   descriptors of SY-18 are the tie for serving (the same answer as R2, so ADR-044 RD-9 and
   ADR-047 SO-1 have one contract; R1 would have shared it).
7. Items 11, 13 and 14: wire codes, `last_failure`'s lifetime, admission off the actor, status
   fields (about 400 lines, shared with ADR-042 and ADR-044).
8. Items 6 and 10: a physical position for explicit history and one for own recovery (about 120
   lines), so neither competes with Background work (SY-9, SY-11).
9. Items 85, 86 and 87: `retirement_failed` flows count toward no node-wide cap and are capped per
   room; retried on `StoreRecovered(room)`, dropped on room replacement or lock; `start_reason` recorded
   (SY-24; about 80 lines).

In all about 2,700 lines changed and 900 deleted, in a state machine of about 16,000 lines whose
45 refusal sites (plan D's count) must each become a named wait (ADR-040).

**What has been measured of R1.** All on loopback on one Mac; times are comparable only within one
session. B2 and B3 rows of the trial used the knob slow member and are investigation evidence
(ADR-045 FG-5); every B3 "never rendered" count before the deciding round came from a reader
that scanned only the newest 200 rows and is unreliable (SY-23).

- *The deciding round's repair arm* (`arm-repair.md`, final: "FAILS the decisive case
  (B3), traced"; the build is v0.4.30 + the trial + plan A's traces with the parent walk removed,
  a bounded flow yield, the join-anchor floor and the stall rule; its no-proof-rows change was
  built after the session and is **unmeasured**, the measured B1 kept 15,001 proof-like rows):
  B1, every member's hello 54.2 s → 10.5 s, governance ≥ sampled 31.2 → 6.5 s, doctor all "trust
  each other" 38.2 → 14.5 s, store written 292 → 142 MB, 0 window cuts, 0 `inclusion header is
  absent`. B3 duty cycle: v0.4.30 cannot be measured, its join fails (item 88). The arm's
  **session 1** (before the pager fix, so its "never" counts are unmeasured): joined 5.9 s, 2 of
  6 earlier joiners failed, earlier joiners' hellos 10–14 s, n-old1 live 13 s, z1 272 s,
  governance ≥ members at 260 s. Its **session 2** (corrected reader): joined 6.4 s, 5 of 6
  earlier joiners failed, n-old1's hello 4.0 s, y1 and z1 never, 26 entries admitted, governance
  never, y1's actor blocked 214 s after meeting its own-history fence (item 89). B3 slow path
  (FG-5): baseline session 2 (corrected reader) n-old2..6 at 213–279 s and n-old1, z1, y1 never;
  the arm's slow-path row is session 1 only (unmeasured on the corrected reader): earlier
  joiners' hellos 17–23 s, y1 and z1 not seen in the newest 200 rows, governance never. **The miss, traced**: the slow
  author's control chain is walked only from the slow author at wire latency (author-only
  control coverage reached 441 of 1,521 positions at 300 s); the report's own next step is the
  chain-keyed control coverage and any-holder proof acceptance that the replace arm already has
  (its change 1), after which B3 is still unproven for R1.
- *The trial* (step 1 with its stopping rule; `/tmp/trial-sync/runs/`†): B1, every member's post
  57.5 s and 88.9 s on v0.4.30 → 23.3 s with every node on the trial (21.2 s with only the
  newcomer on it); governance ≥ the sampled revisions 32.4/42.6 s → 17.3 s. B2, the fast members'
  hellos 90.3/95.3 s → 1.2 s; the slow member's own 211.6 s → 108.6 s. B3's hello counts are
  struck (the reader). Store growth unchanged in kind: 151–376 MB and 17,000–40,000 proof-like
  rows in 5 minutes of B1.
- *The all-nodes regression, a named reference failure* (`/tmp/plan-sync/runs/B3-plan`†): step 1
  keeps the parent-walk flows of item 3 alive for 55–192 s instead of killing them each second, so
  they own both Public positions and no flow that would fetch bodies runs; the six earlier
  joiners' `room join` took 11–30 s each on the all-trial build against 4–12 s on the release. It
  is the same mechanism as RcaFrozen's unexplained "an earlier late joiner makes the next joiner's
  trust entries unfetchable", and the repair arm removes that walk. Any R1 candidate is measured
  against this run, not only against the newcomer's own improvement.
- *The owed-bodies prototype* (step 3, but with the floor at position 1, not the join;
  `/tmp/plan-sync/runs/B3-reach`†, `B1-reach`, `B2-reach`): on B3 the newcomer went from 3 to 229
  entries with 0 window cuts; governance not equal in 300 s (63 against 68); the store 93 → 201
  MB; one earlier joiner's `room join` failed in 5.4 s, cause UNKNOWN; its hello counts are
  struck (the reader). On B1, 36.8 s (no gain over the trial, inside its ±30 s noise), 628
  entries fetched (every seed, because the floor was 1) and 4 → 201 MB in 5 minutes. On B2,
  108.5 s, the same as the trial: the slow member still serves its own feed alone. The scheduler
  spun at 525 flow starts a second.
- *Not measured*: steps 4–9 as a set, on one build, with the fleet's staging.

**What has been measured of R2.** The prototype (`proto-range-sync.md`, PARTLY; its slow
member was a `SIGSTOP`/`SIGCONT` duty cycle and its reader never paged, so its numbers are
investigation evidence and its B3 hello counts are struck): B1 governance ≥ sampled 3.5 s
(baseline 26.8 s), the two fast members' posts 4.5/5.5 s (baseline 52.9 s), 1.6 requests and
23 KB on the wire per admitted entry, y1's worst serving wait 95 ms off the actor; 394 MB and
40,254 proof-like rows against 134 MB / 21,398 on the baseline, because the graft committed the
server's head and a prefix proof per answer through the exact-head store this ADR deletes.

*The deciding round's replace arm* (`arm-replace.md`, final: "FAILS the decisive case on
one assertion, traced"; the slice with control coverage keyed by the author's chain, acceptance
that writes nothing derived, read-only serving off the lock in RD-9's order, K = 2 per peer
with holder scoring, and four wiring defects fixed): B1, every member's hello 80.6 s → 8.5 s,
doctor all ok 46.5 → 6.5 s, members read the newcomer in 1.5–2.5 s, 2.2 requests and 31 KB per
entry, store +145 MB → +47 MB, proof-like rows 24,200 (y1: 82,478) → **0 on every node in every
run**. B3 slow path (FG-5, corrected reader): baseline join 5.5 s, five quiet joiners' hellos at
40–241 s, the three heavy authors never, y1 frozen at governance 21 vs 86; the arm joins in
6.9 s, renders 7 of 8 hellos at 72–93 s with both fast heavy authors live at 82.2 s, is read by
z1 and n-old1 in 3.7/2.5 s, trusted by 7, y1 "has not trusted you", y1's own posts never. B3
duty cycle: baseline joins fail (item 88); the arm joins in 5.0 s, 7 of 8 hellos at 46.5 s, both
fast heavy authors live at 43.5 s, read by n-old1/z1 in 2.6/6.2 s, y1's own posts never, y1's
worst serving wait one pause (1,578 ms). Restart mid catch-up (B1): nothing lost, every hello
15.2 s after the restart. **The miss, traced**: the newcomer admits y1's chain (control prefix
complete to 1,796) but y1 *itself* never becomes current with the room, so it never folds the
newcomer's grant and the newcomer cannot decrypt y1's posts; y1's admission runs through the
shipped per-entry publication path at 2.7 entries/s at half duty (5.4 running) and its control
enumeration of the other heavy authors at 8 headers per 1.5 s page (1.9 positions/s), against a
room writing about 6 entries/s of which 21 % are `ContextUpdate` controls; y1 is equally frozen
on v0.4.30 (governance 21 vs 86). The two design findings this leaves against this ADR are
closed in SY-3 (what the fold waits on; 128 control positions per answer) and SY-13 rule 4 (one
transaction per chunk).

**The measured reason R1 was not chosen.** Neither arm passed B3 as SY-4 states it (Q1 has the
table). R1's miss was in its architecture's keying (control coverage by exact head, walked from
the author alone), and its own trace named the replacement's change as its next step; R2's miss
was in the store's admission path, outside the range model, and is specified away in SY-13 rule
4 and SY-3. R1 would also have amended the owner's turn and window rules of ADR-036 a second
time and left every later timing defect a question of which of nine interacting repairs it
lives in.

## Cost

- **What remains** (no durations: the decider, ledger row 55, "it'll take as long as it takes";
  "those estimates were if a jr programmer were coding by hand"). R2, from the replace arm's
  final binary: admission one transaction per chunk and the read view from the committed snapshot
  (SY-13 rule 4, ADR-044 RD-4); the fold of SY-3 with its writer rules and `ContextUpdate` never a
  wait; deleting the hinted machinery (45 refusal sites wired to flow identity, the riskiest
  part), the Inventory round onto `Have`, the join as `Have` + own range + control ranges, own
  recovery and explicit pages as ranges, truthful codes and status; the proofs with v0.4.30 as
  the mutant. R1, from the repair arm's trace: the chain-keyed control coverage the replace arm
  already has (`control_sources/effects` re-keyed, proof acceptance under a newer head), then
  steps 2 and 4–9 of its list, and B3 is unproven after them because the slow author still
  serves its own control chain at wire latency unless any holder may (SY-16).
- **Lines.** R2: about 3,000–4,000 new (the prototype's slice is 2,850 added with none of the
  deletions), about 10,000 deleted. R1: about 2,700 changed, about 900 deleted.
- **The wire format changes (R2).** A v0.4.31 node and a v0.4.30 node cannot sync a room. The
  decider ruled (2026-11-13, ledger row 18): all machines move to 0.4.31 together, no mixed-version
  sync. So there is no bridge and no split to accept; on the operator's machines each update
  needs his go (AGENTS.md), and the update is one coordinated pass. A node that meets an older
  member during that pass says so by name (`UnsupportedVersion`), waits for nothing from it, and
  resets no data and no own-history or fork fence. ADR-045 drops its mixed-version acts.
- **ADR rules withdrawn (R2).** ADR-036's hint inbox, coalescing, the owner's turn, the 128-position
  live window and its join settlement, its parent receipts and its durable archive continuation;
  ADR-025 D1.1's one-Public, one-Background ports, D1.5 and D6.1's caps; ADR-037 R10's own-author
  hint and R11's flow turns. ADR-008 LS-27 and LS-28 are revived as the v2 contract. Listed
  exactly below.

## Unchanged rulings

- ADR-008 LS-8 (every entry is composite-signed), LS-29's "the holder MUST trust nothing in a
  `WANT` for size" (now: nothing in a `Have`), LS-33 (a missing body is owed, asked of every peer,
  shown "not received yet"; the receiver computes expiry), LS-34 (serve only admitted members).
- ADR-036 H-1 (control, live and requested history are separate; the contiguous prefix is never
  set from a sparse tip). Its "MUST NOT request every missing content interval" holds below the
  anchor; at and above it, bodies are owed (LS-33).
- ADR-036 H-3 and H-6's proof formats and bounds (8 control headers, 1,024 tokens, 256 KiB a
  proof; contexts at most 160 KiB); H-4's bounds (128 entries and 1 MiB an answer; 16 MiB entries
  in chunks; partial bytes staged with their binding until the whole entry checks); H-6's fork
  evidence; H-8's "Ordinary order gaps initiate no network request", now also for `seen`
  references.
- ADR-037 R2 (one fold, the gate for everything irreversible; content never raises its barrier),
  R3 (egress structurally gated; provisional display while the fold is behind), R4, R5 (own
  history behind stops writes), R7 (gates are event-driven).
- ADR-007 G-29–G-31: removal ordering, the once-removed recipient's cut and forward enforcement are
  applied by the fold and the serving gate, as today (SY-3, SY-25); the latest-certificate rule
  (`authority.rs:207-237`) and the underclaim check keep their inputs (SY-3 rule 3). Only their
  use as a fetch prerequisite goes; a removal's required ancestor at the target is a writer rule
  added by SY-3; removals already written keep their cut (SY-26).
- ADR-006 S-16: what is owed is derived, never stored. This ADR applies it to all fetch state.
- ADR-023 RL-4 (key packages in the log, carried by always-on members, which under SY-14 hold the
  bytes) and RL-8.4–RL-8.5 (the recovery fence after a rejoin, set from signed own heads). The
  fence stays; it lifts sooner.
- ADR-025 D5 (backoff for an unreachable peer).
- ADR-044 RD-8, RD-9 r3 and RD-16: serving is a read with RD-9's order (canonical, cache,
  reconstruction, then a kept descriptor), its proof handoff and its refusal; the served request
  is admitted without the actor. ADR-047 SO-1 r3: the same list of kept facts and the same
  serving rule (SY-16, SY-18).
- ADR-040 NW-1 (the prerequisite registry; after the split, ADR-040 keeps it): `OwnHistory(room)`
  is released by SY-11's completion; `GovernanceFold(room)` is held only by unfolded held control
  entries (SY-3); `StoreRecovery(room)` is the failed cleanup's wait (SY-24). ADR-049 (leaving and
  ending rooms, formerly NW-7/NW-15) owns the deleting retirement SY-24 relies on; ADR-048 (trust
  containment, formerly NW-2/NW-5) is untouched by this ADR.
- ADR-018 and AGENTS.md "Tests": proofs drive the shipped binary; a spike is run and reported,
  never committed to the gate; a slow member is made by ADR-045 FG-5's slow path.

## Superseded and amended lines

Main applies these after the decider signs. Each quotes the current text exactly, from the tree at
`d9a8667ba`. Every amendment is **unconditional** under the chosen mechanism (the decider,
2026-11-13, ledger row 57); the older "(both)"/"(R2)" marks are historical and bind nothing. Rows
whose target is a proposed ADR with no text at `main` (20, 21) are sibling contracts, not
amendments (`adr-amendment-quotes.md`).

1. **ADR-036 H-6, the inventory and query list** (R2)
   (`docs/adr/ADR-036-live-messages-and-requested-history.md:487-500`). Current:
   > HAVE is a sorted
   > list of at most 2,048 `[author, size, HeadID]` hints, not verified state.
   >
   > WANT (`0x03`) is `[request_id, query]`, where query is exactly one of:
   >
   > ```text
   > [0, author]                                      # head
   > [1, context_hash]                                # context object
   > [2, HeadID, proof_kind, from, to]                 # proof
   > [3, HeadID, seq, offset]                          # one entry/body continuation
   > [4, HeadID, lo, hi, entry_limit, wire_limit]       # bounded page
   > [5, HeadID, seq]                                 # signed header only; no body
   > [6]                                             # current head inventory; control purpose only
   > ```

   Replacement: "The v2 sync requests are ADR-046 SY-12's: `Have` (per author a size, HeadID,
   control-complete position, up to 16 held intervals and their total count; at most 2,048
   authors; a hint, not verified state), `Head(author, since)`, `Range(author, since, from, to,
   bodies, offset, descending)`, `ControlRange(author, since, from, to)`, `Context(hash)` and
   `Probe(author, from, to)` and `Snapshot(hash)`, with the answers and bounds given
   there."
2. **ADR-036 H-6, hints** (R2) (`ADR-036-…md:503-516`). Current:
   > Hints convey no body permission or authority.
   > Only newly eligible, bounded exact head hints wake metadata verification; accepted/in-flight
   > hints are deduplicated, and neither an inventory nor its completion requests archive bodies. A
   > hint is redundant and MUST NOT enter the volatile inbox only when its exact head is already in
   > that author's accepted consistency chain, the selected window for the current committed head is
   > complete, and no selected-live missing position is eligible for retry. Size alone never makes a
   > hint redundant: an unknown head, a newer head and a different same-size head remain eligible, as
   > do exact departure receipts. Control-ready state is not part of this filter; ordinary content
   > tails do not require control effects through their full size.
   > Every in-flight hint MUST have one live flow owner. A normal result retires it; authorization
   > change or controller abandonment while the room/peer scope remains live re-arms the exact hint;
   > room/peer retirement removes it with that scope. An invalidated worker MUST NOT leave an
   > in-flight hint that is skipped by selection, suppresses re-offer through deduplication or blocks
   > settlement until daemon restart.

   Replacement: "A `Have` conveys no body permission, authority or size: it says where to ask. A
   size above the known size, or a HeadID not accepted at or below it (a same-size distinct head
   stays eligible, as before), raises one `Head` request and sets nothing else. There is no hint
   inbox and no flow owner. What a node wants is derived from what it holds and the signed heads
   it has accepted (ADR-046 SY-14)."
3. **ADR-036 H-6, the key-package exception** (R2; the decider, ledger row 40) (`ADR-036-…md:549-550`). Current:
   > Every other member keeps only the authenticated public header and
   > does not request or open the encrypted package body.

   Replacement: "Every other member also keeps the sealed package body, received with the author's
   control entries (ADR-046 SY-12, SY-14), so an always-on member can carry it to an offline
   recipient (ADR-023 RL-4.5). No member but the recipient can open it, and a package is served to
   its recipient only under the recipient's body-eligibility cut (ADR-007 G-30; ADR-046 SY-25)."
4. **ADR-036 H-6, prefix receipts** (both) (`ADR-036-…md:555-556`). Current:
   > Persist the verified
   > prefix range with its authenticated receipt so restart preserves the same decision.

   Replacement: "Keep the accepted signed head and, per held interval, the descriptors that tie
   it to that head, coalesced from each answer's witness; the proof itself is verified and dropped
   (ADR-046 SY-13, SY-18)."
5. **ADR-036 H-6, control closure** (both) (`ADR-036-…md:582-584`). Current:
   > Selecting an author's newest live window MUST immediately drive both the authenticated
   > control-source receipt and the applied control-effect receipt through that exact committed head,
   > independently of and before its ordinary-body walk.

   Replacement: "Every author's control entries from position 1 up to its known size MUST be fetched
   as one set, by control proof, with a bounded share of each peer's exchanges so that no author's
   bodies wait on another author's control backlog (ADR-046 SY-3, SY-15). A `seen` reference is
   never fetched for admission."
6. **ADR-036 H-7, state 3** (both) (`ADR-036-…md:687-688`). Current:
   > 3. **Control pending/ready:** exact-head interval coverage, parent receipts and control dependencies
   >    are accumulated durably.

   Replacement: "3. **Control pending/ready:** the author's control-complete position is kept
   durably; there are no parent receipts; a control entry naming a coordinate not yet held is
   pending in the fold and blocks nothing (ADR-046 SY-3, SY-18)."
7. **ADR-036 H-7, owned continuations and coalescing** (R2) (`ADR-036-…md:701-710`). Current:
   > An owned bounded continuation or queued exact-head hint is itself port demand until it completes,
   > is superseded under the hint coalescing rule, or is explicitly retired. A clean exchange may
   > acknowledge the request generation it observed, but that scalar acknowledgement MUST NOT make an
   > owned continuation or newer pending successor unschedulable.
   > The in-flight owner is immutable while its bounded slice runs. At the slice boundary, a strictly
   > newer queued head for the same room, source peer and author supersedes that owner's remaining
   > transient continuation: retire its capabilities, keep every durable receipt/cursor/missing fact it
   > already committed, discard the obsolete scalar and start the one retained successor. This is
   > coalescing, not cancellation of durable recovery. Equal-size distinct heads never supersede one
   > another because they may be attributable fork evidence.

   Replacement: "A request in flight is never cancelled or replaced because a newer head exists; a
   newer head only raises the known size (ADR-046 SY-1). Equal-size distinct heads are fork
   evidence, recorded before any chain test (ADR-046 SY-13)."
8. **ADR-036 H-7, the owner's turn** (R2) (`ADR-036-…md:711-734`, the paragraph beginning):
   > **The owner's turn (decider, 2026-11-12).** An owner that is progressing — not waiting on the
   > peer, and with a receipt committed or a body moved since it started — keeps its turn against a
   > strictly newer head for up to **1 s** from the owner's start (`HINT_TURN`);

   Replacement: the paragraph is withdrawn, with this sentence in its place: "There is no turn: no
   request is replaced by a newer head (ADR-046 SY-1). Fresh posts wait at most one exchange behind
   an older range of the same author, and every class of request gets one exchange in four
   (ADR-046 SY-15 rule 3)." The measurements in the withdrawn paragraph stay in the git history.
9. **ADR-036 H-7, join settlement** (R2) (`ADR-036-…md:752-758`). Current:
   > Join settlement is a function only of durable exact facts, never volatile hint-inbox occupancy or
   > a completion flag. A joined sparse room becomes writable only after a member's authenticated
   > `Head(local_author)` answer has selected a complete live window naming the exact current committed
   > local head, no higher observed own head or own-head conflict remains, the contiguous own feed is
   > not behind that head, and governance is ready.

   Replacement: "Join settlement is a function only of durable exact facts. A joined sparse room
   becomes writable once this node holds its own feed through the highest signed own head any
   connected member's `Head` answer has proved, no own-head conflict remains, and governance is
   ready (ADR-046 SY-11, SY-17). A member's `Have` sets no fence."
10. **ADR-036 H-4, continuation and the older gap** (both) (`ADR-036-…md:253-254`). Current:
    > Completing one history page MUST NOT automatically request the next; a changed live tip is not
    > permission to drain its older gap.

    Replacement: "Completing one history page MUST NOT automatically request the next. Below an
    author's join anchor a changed tip is not permission to drain the older gap; at and above it,
    every body is owed and asked for until held, expired or refused as not for this node (ADR-008
    LS-33, ADR-046 SY-4). An explicit page lives in memory: a restart forgets the page in flight
    and never a row held; `--history resume` after a restart says so (ADR-046 SY-9). A partly
    received body is staged with its binding and survives a restart (ADR-046 SY-18)."
11. **ADR-037 R1** (both; the decider, ledger row 38) (`docs/adr/ADR-037-a-joined-room-converges-without-waiting.md:73-75`).
    Current:
    > The live window still
    > fetches each author's newest 128 bodies on join; that is the one known deviation from this rule,
    > and making the window fetch bodies only from the join on is the next change (see Consequences).

    Replacement: "A joined node fetches each author's bodies from its join anchor on, and every
    author's control entries for all time; older bodies come only on request (ADR-046 SY-4,
    SY-14)." The matching Negative consequence (`ADR-037-…md:369-372`) is deleted.
12. **ADR-037 R8, second paragraph** (R2) (`ADR-037-…md:282-285`). Current:
    > A history worker this node's own actor cancelled (its ask was replaced by a newer one, paused or
    > stopped) is neither: it stopped at its next store step on a local decision. Its port MUST NOT be
    > failed or backed off, and the room MUST NOT be poisoned by the cancellation; the replacing ask's
    > own flow runs next.

    Replacement: "A request this node withdrew (room closed, peer retired, shutdown) is a
    cancellation: it is sent as `Cancelled`, and neither side counts it as a failure, backs off, or
    marks the room unable to save. No request is withdrawn because a newer head exists (ADR-046
    SY-1, SY-21)."
13. **ADR-037 R10** (R2) (`ADR-037-…md:294-299`). Current:
    > A sparse settlement whose only missing piece is the
    > node's own live-window acknowledgement MUST offer the own-author hint for the committed own head
    > to every connected peer, so the next round fetches it now. Settlement MUST be retried for every
    > open room on every tick: no other sync event reliably arrives for a room whose remaining piece
    > is its own acknowledgement.

    Replacement: "The join answer carries the node's own feed and each member's signed head of it
    (ADR-046 SY-11, SY-17). Settlement is re-checked when a `Head` answer for the own feed or an
    own-feed `Range` answer arrives."
14. **ADR-037 R11** (R2) (`ADR-037-…md:306-335`, beginning):
    > ### R11. A turn may run several control chunks, never a cycle

    Replacement: R11 is withdrawn: there is no flow turn. A request is one exchange; the scheduler
    order is ADR-046 SY-15.
15. **ADR-025 D1.1, first item** (R2) (`docs/adr/ADR-025-sync-scheduling-switch-not-hub.md:69-70`).
    Current:
    > - at most one Public and one Background outbound attempt, and at most `INBOUND_PER_PORT` (3)
    >     inbound attempts; Background is either recipient-key body work or Archive, never both;

    Replacement: "- at most K (2) requests in flight, each a slot held only by a running exchange
    with a deadline, and at most `INBOUND_PER_PORT` (3) inbound requests (ADR-046 SY-15, SY-24);"
16. **ADR-025 D1.5 and D6.1** (R2) (`ADR-025-…md:89-93`; lines 94–107 describe the same two
    positions and go with it; D6.1's "16 outbound, 4 per peer"). Current D1.5:
    > - **D1.5.** Per pair, per end, there MUST be at most one Public plus one Background outbound
    >   session unfinished, and at most `INBOUND_PER_PORT` inbound sessions unfinished. The node's two
    >   physical running positions MUST remain one Public opportunity and one Background opportunity;
    >   Background MUST NOT borrow Public. Eligible Private and Archive work MUST alternate admitted
    >   existing quanta fairly.

    Replacement: "- **D1.5.** Per pair, per end, at most K = 2 requests are in flight, each under its
    own 20 s deadline, and a slow peer costs only its own requests. There are no physical positions
    and no node-wide request count: the answer budget bounds the node, and a peer with nothing in
    flight is admitted round-robin when the budget is exhausted (ADR-046 SY-15 rule 1). The order
    of requests is ADR-046 SY-15's." D6.1's caps are withdrawn with the same words.
17. **ADR-008, new-format amendment** (R2)
    (`docs/adr/ADR-008-replicated-authenticated-log-and-sync.md:29-32`). Current:
    > For that format it supersedes LS-3's automatic replicate-all
    > interpretation, LS-4/LS-10's v1 skeleton shape, LS-28/LS-29's continuous-prefix archive request and
    > automatic continuation, and LS-11/LS-12's exact-predecessor/increase-only behavior for sparse held
    > sets.

    Replacement: "For that format it supersedes LS-3's automatic replicate-all interpretation,
    LS-4/LS-10's v1 skeleton shape, and LS-11/LS-12's exact-predecessor/increase-only behavior for
    sparse held sets. LS-28's frontier exchange is the v2 contract again, in ADR-046 SY-12's form."
18. **ADR-008 LS-28** (R2) (`ADR-008-…md:228-231`). Current:
    > - **LS-28. Frontier mode.** `HAVE` MUST list the feeds a peer holds. The receiver MUST reply `WANT`
    >   with the missing ranges, asking from its own head (not past it) so that the peer's entry at that
    >   position is compared with its own (V210-63). The holder MUST stream `ENTRY` frames (skeleton and
    >   any retained payload) over a reliable QUIC stream (ADR-011).

    Replacement: "- **LS-28. Frontier mode.** `Have` MUST list, per author, the size, head, held
    intervals and control-complete position a peer holds. The receiver MUST ask for missing ranges
    with `Range` and `ControlRange`, starting at its own last held position (not past it) so that
    the holder's entry there is compared with its own (V210-63), and MUST treat nothing in a `Have`
    as a size. The holder MUST answer with `Entry` frames (header and any retained body the
    requester may receive) over a reliable QUIC stream (ADR-011; ADR-046 SY-12, SY-25)."
19. **ADR-008 LS-27, status** (R2) (`ADR-008-…md:225-227`). Current:
    > *Status:*
    >   planned. `range_reconcile_exchange` exists and nothing calls it; `should_use_range_mode` is never
    >   called; every session offers frontier only.

    Replacement: "*Status:* below about 100 authors, `Have`'s per-author intervals with `Probe` are
    the exact form of range reconciliation (ADR-046). Negentropy above that stays planned and
    unbuilt; `range_reconcile_exchange` and `should_use_range_mode` are deleted until it is built."
20. **ADR-042 Terms, "Live window" and "Behind"**: not an amendment (ADR-042 is a proposed ADR with
    no text at `main`; `adr-amendment-quotes.md`, NOT FOUND). The rule is a **sibling
    contract** carried in this ADR's "Related lanes" and ADR-042's own revision: "Join anchor:
    per author, the first position whose body this node fetches without being asked (ADR-046).
    Positions below it are older history, fetched only on request. Behind: for one author, the
    number of positions from the join anchor to the known size (the author's newest signed head
    this node accepted) that this node cannot show; a member's advertised size above the known
    size is shown as unverified beside it and is never counted as behind." ADR-042 r5 already
    holds it (its Terms and TR-1).
21. **ADR-047 SO-1, what acceptance keeps**: not an amendment (a proposed ADR; NOT FOUND at
    `main`). The one text is the **sibling contract** both ADRs now carry (ADR-047 SO-1 r3 and
    this ADR's SY-18, identical in meaning): what acceptance keeps is SY-18's list; no inclusion,
    parent or prefix receipt is kept by any node for any feed; a leaf's tie to a committed head
    is its validated header and its interval's descriptors (ADR-044 RD-9's reconstruction gate). ADR-047 SO-3
    has nothing to govern (no cursor is written); its proof arm stays as the `sync_bytes` = 0
    check after cancellations. ADR-047 SO-2's sweep runs after SY-26's initialization commit.
22. **ADR-007 G-22** (fix-list item 88; the decider, ledger row 37; unconditional under the chosen
    mechanism) (`docs/adr/ADR-007-membership-consent-and-admin-governance.md:155-163`). Current,
    whole:
    > - **G-22.** A room MUST NOT exceed its member cap (`MAX_AUTHORS` = 1024). A newcomer MUST be admitted only
    >   once every member that is online has agreed (V030-30, #366). The member answering a join MUST, before it
    >   sends `ACCEPTED`:
    >   1. hold a place for the joiner, refusing with `FULL` when its authors reach the cap, or with `TAKEN`
    >      when its authors and the places promised and not yet settled fill it;
    >   2. ask every other member of the room it holds a connection to, all at once, on a stream typed `seat`
    >      (`StreamKind::Seat`), whether the joiner may take a place;
    >   3. admit the joiner only if every one of them answered `YES`; otherwise send `ABORT` to each member that
    >      said `YES`, free its own place, and refuse the joiner with `FULL`, `TAKEN`, or `NOT_AGREED` naming
    >      the member that did not agree.

    Replacement (the first sentence and step 1 kept; the second sentence and steps 2–3 replaced):
    "A newcomer is admitted by the one member that verified its passphrase (the
    decider, 2026-11-13: 'the join only requires a single member to validate the passphrase was
    correct'). That member asks the others only when the room is near the cap: when its authors,
    its outstanding promises, the members it is connected to and a margin of 16 together exceed
    `MAX_AUTHORS` (ADR-046 SY-10). 2. Near the cap, ask every other member it holds a connection
    to, all at once, on the `seat` stream, whether the joiner may take a place; 3. admit the
    joiner unless a member answered `FULL` or `TAKEN`; then send `ABORT` to each member that said
    `YES`, free its own place, and refuse the joiner with `FULL` or `TAKEN` naming the member. A
    member that did not answer is not counted. `NOT_AGREED` does not exist."
23. **ADR-007 G-22b** (both) (`ADR-007-…md:170-172`). Current:
    > - **G-22b.** A member that does not answer within `SEAT_ANSWER_WITHIN` (5 s) MUST fail the join, named.

    Replacement: "- **G-22b.** A member that does not answer within `SEAT_ANSWER_WITHIN` (5 s)
    MUST NOT fail the join: it is not counted, named in the admitting member's log, and learns of
    the newcomer from a board. The overshoot that silence allows is bounded by the number of
    silent members and absorbed by G-22d's rule for members admitted elsewhere (ADR-046 SY-10)."
24. **ADR-005 J-18** (unconditional) (`docs/adr/ADR-005-channel-addressing-and-authenticated-join.md:89-92`).
    Current:
    > - **J-18.** The exchange MUST be ordered frames on a bi-stream typed `join` (ADR-016 M14.4):
    >   CHALLENGE → SOLVE → SHARE → PROOF → PROOF → INIT, then ACCEPTED, REJECTED, or, for a joiner the room
    >   cannot take (ADR-007 G-22), FULL at its member cap, TAKEN when its last place went to another newcomer,
    >   or NOT_AGREED naming a member online that did not agree.

    Replacement: "- **J-18.** The exchange MUST be ordered frames on a bi-stream typed `join`
    (ADR-016 M14.4): CHALLENGE → SOLVE → SHARE → PROOF → PROOF → INIT, then ACCEPTED, REJECTED,
    or, for a joiner the room cannot take (ADR-007 G-22 as amended by ADR-046), FULL at its member
    cap or TAKEN when its last place went to another newcomer. No member's silence refuses a join;
    `NOT_AGREED` does not exist."


README index row, for Main: `| [046](ADR-046-sync-always-makes-progress.md) | Sync Always Makes
Progress (progress invariants incl. slot and permit ownership, entitlement on every serve path and
a control-only fold; per-author range reconciliation proposed, prototyped PARTLY, deciding round
running; repair or replace open) — proposed for v0.4.31 | 006, 007, 008, 023, 025, 036, 037, 040,
042, 044, 045, 047, 048, 049 |`

## Implementation order and related work

**Step 0, before anything else is built on sync** (the decider, ledger row 57). Round 2 ran
with the two missing parts built and **failed the decisive case on one assertion** (SY-27's
results; cause 1 traced to revision 8's text, closed by SY-3 rules 3–4, SY-13 rule 5 and SY-28).
One more prototype cycle is owed, and **acceptance of this ADR waits on it passing every B3
assertion**; nothing else is built on sync until then. No unbuilt change is counted as a fix.

### The build list for the next prototype cycle (the minimum for a fair B3 run of revision 13)

*(r10: eighth review 6, 7 and "Is the ten-item prototype list minimal and sufficient?")*
ArmReplace builds exactly this on `proto/range-sync` and re-measures B1, the three B3 variants
(duty cycle, duty cycle at 2× history, slow path), R1 and H, with all six earlier joiners staged
and reads in both directions, each against its own v0.4.30 baseline, receipts under
`/opt/vox-evidence/v0431/arm-replace/`. **The run record separates four events per author**:
fold completion of the newcomer's grant on each member, key-package creation and its delivery
to the newcomer, each member's own-post commit (its own feed's head advancing), and the
newcomer's rendering; a missing row is attributed to the event that did not happen, never to
"governance" by default. **A pass with the "own predecessor plus `seen`" shortcut for Content
is not a pass** of SY-13 rule 5 (it reintroduces cross-author rendering prerequisites); the
two-lookup rule is what is built.

**Cycle 5b, in build order** *(r13; prototype items only; each item's acceptance is the
assertion named; the table below keeps the item numbers of revision 10)*:

1. **The two lanes per room** (SY-29, row 82b): control and authored FIFOs, alternating one
   native transaction per turn, a child in its parent's turn, the actor's room turn as a lane
   turn with no `try_lock` stand-aside (item 96), inbound chunk admission as an authored-lane
   item (≤ 1 queued per flow) that never takes the pending-write place. *Acceptance*: under
   continuous posting y1's own posts are never refused "publication busy" and its fold turn
   runs every alternation (try-lock mutant red).
2. **Chunk admission renders Content in its transaction** (SY-13 rules 4–5, SY-30 (1)–(2)):
   the two lookups, no per-entry coordinate wait, the next request on commit. *Acceptance*:
   `trend` per heavy author `steady` or `shrinking` on the slow path after the first minute
   with the settled lag recorded (the prototype's-shape mutant red); admission commits with
   incomplete bodies, missing keys and undecided cuts through the existing nonblocking paths;
   `effects_owed` does not exist (r14).
3. **The closure index and `CLOSE`** (SY-3 rule 3, r13 states): context and disposition
   columns, `closed_through` derived, context-invalid rows never a stop, span walk, direct
   prerequisite fetch (SY-30 (3)), key packages by header, the baseline resolver with branches
   2a/2b (table (d)'s `exposed` frontier or the declared context fetched as one list; r14).
   *Acceptance*: the hidden-certificate act in all four orders including cached U and U below
   the fence, the old-package act, C2 and E in one chunk.
4. **y1's publication path** (item 2 of the table): own posts commit as authored-lane turns
   under continuous inbound admission; the four run-record events per author.
5. **The fence post** (item 5): `settled_through`, the derived three-table summary with refs,
   the SessionFloor projection, the encoded length recorded per room, the one-transaction
   publication, the half-step act with its copy-the-live-projection mutant, over-limit and bad-
   answer handling.
6. **Adoption** (item 6) and the `Have` rule (item 7), the fold-behind `Busy` (item 8), the
   owned writes (item 9).
7. Items 10–11 as before, wider acceptance.

| # | what | implements | for |
|---|---|---|---|
| 1 | a chunk's admission as one authored-lane transaction that **renders its Content by the two lookups in the same transaction** (no owed-effects queue for Content); governance entries admitted there and closed in the control lane; never under a history request's job or deadline | SY-13 rules 4–5 (r13), SY-29, SY-30 | **B3** (round 2's fatal fault; cycle 5a's effects backlog) |
| 2 | **the slow member's own publication stall, traced and repaired**: in round 2's duty-cycle runs y1's own posts never committed to y1's feed (`arm-replace-next.md`); record per node its accepted posts (`vox room post` returned 0), its own-feed commits (head advance in its own store) and the advancement another member observes of it (`Have` size), and repair whichever of the report's candidate causes the trace names, assuming none in advance; the receiving demand rule is kept unless the trace shows a separate defect | SY-11 (own feed), SY-24 (a post's write owner), ADR-044 RD-10 | **B3** (y1's posts must exist to be rendered) |
| 3 | Content rendering on the two lookups (reader's key, own cut), provisional per ADR-037 R3: `prepare_received_effect`'s coordinate loop **and its post-loop `checked_governance` deferral** run for governance and typed-policy kinds only | SY-13 rule 5, SY-3's effect rule | **B3** (cause 1, part ii) |
| 4 | governance validation as `CLOSE(E)` (SY-3 rule 3, r11/r12): the **closure index** (position → hash, kind, valid/inert/content-verified, written with the disposition) and `closed_through(A)` derived from it, distinct from SY-14's received `control_through`; deps = previous entry + declared context + `seen`; per named author the span walk from `max(fence, closed_through)` to the named position, headers for every span position, content headers through rule 2's recursive verifier, bodies for governance and typed-policy kinds only, **key packages authenticated by header and never by body**, summary carriers validated like any control entry; the shared **baseline resolver** (one header, binding checks, terminal; a baseline mismatch is a checkpoint dispute decided on A's witnessed header, never fork evidence); missing pieces as SY-14 closure demand, deduplicated, re-evaluated on arrival; no coverage gate anywhere; the fold, `CLOSE` and the key-package queue on the actor's control lane (SY-29); per governance entry, record headers fetched, bodies fetched, bytes and span depth; the hidden-certificate (incl. C2-and-E-in-one-chunk), old-package and try-lock acts with their mutants | SY-3 rules 2–4, SY-14, SY-29 | **B3** (cause 1, part i) and the closure-size measurement rule 3 owes |
| 5 | **the whole fence-post mechanism**: the `GovernanceCheckpoint` payload (fences at `closed_through`, `H`, `summary_len`, previous checkpoint) with its summary in the three-table schema of SY-27 point 3 (member table with `state`, `active_removals`, `cuts`; comparison-record table for every governance-kind fact below the fences with the projection its consumer reads, readmissions' `covers` included; fold state at the fences), deterministic CBOR, the **encoded length recorded per room**; publication eligibility on the measured encoded answer ≤ 1 MiB including envelope and frame headers, else no fence post and the status line; the creator's trigger from the committed generation, no wait on a current fold (SY-29); `Snapshot{H}` whole in ≤ 4 frames; `Have.checkpoint`; the receiver's rejection of an intrinsically over-limit **signed** candidate, and rotation on a bad supplier answer with the progress line (never rejecting the checkpoint for untrusted bytes); installation in one transaction replacing the previous baseline row; the boundary frame; the baseline resolver below the fence; the full-record comparison and dispute | SY-27 point 3, SY-12, SY-14, SY-17, SY-18, SY-29 | **B3 at 2×** (SY-27 (b)/(c): the walk from 1 and the below-anchor coordinates) and SY-28's adoption arm |
| 6 | an existing member's adoption under SY-28 (iv)'s **comparison algorithm** (r11/r12): domain = held facts at or below each author's fence including sparse validated ones, held facts above the fence kept and re-folded over the adopted state; **member rows compared only for admissions at or below the admitter's fence**, above-fence admissions and their identity material replayed; forward and reverse checks on (author, position, kind, hash, projection); dispositions, cuts, member state, admin set and cutoff state never compared; AGREES → install + re-fold, CONTRADICTS → dispute, nothing adopted, `Have` silent on it; the acts asserted through the status outcomes (adopted line, verifying line, dispute line) and the newcomer-through-adopter red for the skip-comparison mutant | SY-28 | **B3** (the adoption arm; the slow member's bound) |
| 7 | `Have` triggers verification only: a newer size or unaccepted HeadID raises one `Head`; **only an accepted signed head raises the known size and derives demand**; keep the false-advertisement act in this cycle | SY-12, SY-13 rule 3, SY-14 | **B3** and every run (revision 9's item 2 wording that a `Have` "raises the known size" was wrong and is withdrawn) |
| 8 | a join through a member whose own fold is behind answers `Busy{retry_after}` | SY-10 (r9) | **B3** (admission through the slow member without a retry) |
| 9 | the receiver's index writes through the room's owned-write protocol (fde2e963c, kept) | SY-13 rule 4, ADR-044 RD-10 | **B3** (a heavy author drops answers otherwise) |
| 10 | the just-in-time page as a `Range{descending}` below the anchor | SY-9 | wider acceptance (SY-27 (d)), not the B3 live-post assertion |
| 11 | SY-18's interval descriptors coalesced from witnesses, **with a staging arm in which a sparse late joiner actually serves** a heavy author's range to the newcomer | SY-18, SY-16 | wider acceptance ("any holder"), not the B3 live-post assertion; its presence alone proves nothing without the arm |

Not in the minimum: the kind filter (ruled out: row 68), a second signer (row 68), ADR-044
RD-4's read view, SY-26's upgrade path (no v0.4.30 store in B3), SY-25's wire-level gate acts.
The pass rule is Q1's: every B3 assertion, SY-27's (a)–(c) and SY-28's acts green on the
corrected reader, with the four events recorded per author; items 10–11 pass or fail on their
own assertions and do not gate the B3 verdict. If the cycle fails on an assertion this text does
not explain, the sync work stops and the decider is told plainly (row 53).

## Consequences

### Positive

- A late joiner reads the room and is read, whatever the room's traffic, earlier joiners or one
  slow member. A slow member costs only its own requests.
- Governance arrives as a small set per author, ahead of messages, folded from control entries
  alone, so "has not trusted you" no longer stands in for "not received yet" and no content gap
  can hold a governance fact.
- A node never serves a body the requester is not entitled to, from any path.
- A member's word is a hint: no advertisement sets an anchor, a fence or a "behind".
- A restart loses no entry, interval, staged body or governance progress; it re-derives the rest.
- A slot is never held by nothing; a node with work and a holder always has a request out or a
  named reason.
- The store grows by what was received: entries, headers, intervals, contexts. No proof records,
  no receipts.
- With R2, about 10,000 lines of the hardest code in Vox are deleted.

### Negative

- R2 is a new wire format: every machine in a room updates together; a v0.4.30 member cannot sync
  with a v0.4.31 one, and a member never updated stays out until it is.
- R2's numbers are the deciding round's (7 of 8 on B3, the slow heavy author never) and the
  re-measurement with the two missing parts is owed; if it is worse than SY-27 requires, the
  consequence stated there applies.
- Holders serve more: any member may be asked for any author's entries, up to 2 requests at a time
  per peer, and may be probed for intervals it did not advertise. ADR-044 makes serving a read; its
  cost on a multi-GB store is to be measured on the fleet.
- With Q5 = every member, every member keeps every key package's sealed body (a few KB each).
- With Q2 = yes, a newcomer or rebuilt node shows no posts from before its join until the person
  pages back (SY-9's rebuild act shows that paging back works and the text is readable).
- An explicit page in flight is forgotten by a restart and must be asked again.
- Fresh posts may wait up to four exchanges behind other classes of the same peer (at most 128
  entries or 1 MiB each, under 20 s deadlines); ADR-036's "fresh messages never wait for old
  bodies" is amended again.
- A removal must carry the target's newest position (a writer rule); for removals written before
  this release the recorded cut keeps their old visibility exactly.

### Neutral

- Signed heads, composite signatures, Merkle proofs and fork evidence are unchanged; proofs are used
  only for anchors, control entries, head substitution and forks.
- The fold's canonical rank, the egress gate and the own-history fence are unchanged in meaning;
  the fold's input is narrowed to control entries and their signed contexts.

## Review record

Three independent reviews by GPT-6.1-Sol: the first (`adr-046-sol-review.md`, eighteen
findings), the second (`adr-046-sol-review-2.md`, sixteen remaining findings N1–N16,
each of the first eighteen retraced) and the third (`adr-046-sol-review-3.md`: N1, N6,
N7, N8, N9, N13 closed; N4 not closed; the rest partly; six P1 and four P2 findings). The fourth
review, of revision 4, was interrupted by the Mac's reboot of 2026-11-13 and is to be done on
this revision, re-tracing the third pass's findings here. Each finding was checked against v0.4.30 (`git show
v0.4.30:<path>`) and against this ADR's own text. Every finding held; none was rejected to save
the design, and none was accepted without reading the lines.

### First review (answered in revision 2)

| # | Finding | Classification | Evidence read at v0.4.30 | Answered by |
|---|---|---|---|---|
| 1 | Relaying every key-package body and serving by range bypass the once-removed recipient's body cut | CONFIRMED | `server.rs:776-809` checks `recipient_body_eligibility` before any body read, `:877-919` answers header-only on denial; `governance/view.rs:990-1012` `body_eligibility_after` with `RecipientCut::{Unrestricted, Removed, Refreshing, After}` | SY-25 (every serve path; `not for you`; Busy for a refreshing projection); SY-12's `body_state`; SY-21; amendments 3, 18; the readmission acts |
| 2 | Anchors and the own-feed fence set from an unsigned `Have` | CONFIRMED | `history_stream.rs:636-640` `HeadHint.size` unsigned; `own_history.rs:1079-1190` sets the fence only from `checked_own_head` signed heads | SY-17 (anchor from a verified signed head), SY-11 (fence from `Head(me)` answers), SY-14 (a `Have` raises one `Head`), SY-12 ("a hint and nothing else"), SY-20 (advertised shown apart), amendments 2, 9, 20; false-advertisement acts |
| 3 | "Wait for the ancestor" can wait for ever on a content ancestor; the fold is not order-only; G-29 says inert, not an egress barrier | CONFIRMED | `governance/sparse.rs:380-420` `ValidatedSparseEntry::new` demands a receipt per `seen`; `:540-585` validates `pre_context` coordinates against accepted commitments; `canonical.rs:165-182` ranks; ADR-007 G-29/G-31 | SY-3 (the fold on control entries and named content headers' signed contexts; pending is inert; the removal's required ancestor; eligibility from the entry's own context); SY-13 rule 5; SY-21; amendments 5, 6; the governance acts |
| 4 | Consistency and chain tests before fork recording lose self-authenticating fork evidence | CONFIRMED | `admission.rs:90-132` records the observed head (`observe_history_head`) before continuity | SY-13 (observed vs accepted; fork evidence first, on author-signed objects only); the equivocation arrivals |
| 5 | The author is always preferred; a short or slow holder is never excluded | CONFIRMED | SY-15(4) as written; no negative state for `Missing`/short/timeout existed | SY-15 rule 4 (attempt epochs, then delivery; no author preference; per-(peer, author, range) negatives cleared only by that author's `Have`); SY-4's third assertion |
| 6 | Sixteen advertised intervals hide a seventeenth no one asks for | CONFIRMED | `Have` cap of 16 as written; no probe existed | SY-12 `Probe` and `intervals_total`; SY-14 probe demand and the availability overlay; SY-15 rule 3 (prerequisite class) |
| 7 | `Head` and `Context` have no demand class, dispatch or completion | CONFIRMED | `log/history.rs:743-785` `read_context` → `MissingContext`; `:825-864` `join_descriptors` reads both frontiers | SY-14 (head, context, probe and parent-header wanted, dedup, one in flight, re-arm edges); SY-15 rules 3 and 6; SY-13 rule 4 (park and resume) |
| 8 | A control body above 1 MiB cannot complete through `ControlRange` | CONFIRMED | ADR-036 H-6 allows a 16 MiB control body; `More{to′+1}` has no offset | SY-12 (`ControlRange` = proof + headers; bodies by `Range{bodies, offset}`); SY-14 (`control_through` advances on header + needed body) |
| 9 | Keeping only control-named contexts breaks cold reconstruction | CONFIRMED | `leaf_descriptor` (`:764-818`) reads every leaf's `pre_context`; `join_descriptors` reads both child frontiers | SY-18 (every context a held header or kept descriptor names; GC by reference); the context act |
| 10 | Partial bodies and explicit pages lose their binding or are re-fetched | CONFIRMED | ADR-036 H-4's staging and durable continuation | SY-18 (staged partial body with its binding, at most 4 per room); SY-9 (explicit page in memory; `resume` after a restart says so; amendment 10); SY-8's large-body arm |
| 11 | No anchor for rooms that exist before the release | CONFIRMED | `LiveWindow` in `AuthorState` (`sparse.rs:2577-2605`); the only initialization was the join | SY-26 (one-time initialization from the window start, bodiless headers and the newest 128; `control_through` = 0; before SO-2's sweep); the upgrade arm |
| 12 | Body coverage does not imply a proof under the requester's exact head | CONFIRMED | `proof_range.rs:189-272` returns `Missing` without canonical sources, committed head and receipt | SY-12 (the bridge, not an exact head; the holder's head with a bridge proof); SY-16 (RD-9 r3's order, `EvidenceUnavailable`); SY-18 (interval descriptors as the tie); the sparse unaligned act |
| 13 | Round-robin within a class starves bodies under sustained control; sixteen requests can be held by eight silent peers | CONFIRMED | SY-15 as written; ADR-025 D6.1's caps | SY-15 rule 1 (no node count; FIFO permit queue with its bound), rule 3 (deficit round-robin on every opportunity; bodies fetched regardless of control), rule 6 (passes bounded by the change); the control-stream and budget-saturated acts |
| 14 | An ascending `Range` cannot serve a newest-first explicit page under a byte cap | CONFIRMED | ADR-037 R1's newest-first rule | SY-12 `descending`; SY-9; the byte-cut act |
| 15 | R1's steps 1, 6, 8 contradict SY-1, SY-8, SY-11 | CONFIRMED | trial commit 28bd77347's "after one admitted entry" rule; plan A §2.2 | R1 steps 1, 6, 8 corrected and step 9 added; SY-22; the regression run named as a reference failure |
| 16 | Three catch-up rates; an optional proof asserts a counter | CONFIRMED | SY-5 (100/min), its proof (8,386 in 5 min), ADR-045 J1(g) (now 100/min after its revision) | SY-5 (1,000/min under stated conditions; mandatory act asserting named rows; the decider closed Q3 in r4); sibling change to ADR-045 J1(g) |
| 17 | Governance-revision equality was never measured and is not an outcome | CONFIRMED | `trial-sync-progress.md:7` ("≥ the sampled revisions"); `rig.py:618-621`; B1 ends 16/17/17 | SY-3's proof (doctor, `control_current`, reads both ways, no counter); the SY-23 table relabelled |
| 18 | Knob runs cited as reds for a pause/resume apparatus; "deletion reproduces the cause" | CONFIRMED | `trial-sync-progress.md:3` names the knob binaries; ADR-045 FG-5 forbids both the knob and a process pause as a slow member | The slow member is FG-5's slow path; every red marked verified or investigation with the owed release run; the waiver withdrawn; experiments kept |

### Second review (answered in revision 3)

| # | Finding | Classification | Evidence read at v0.4.30 and in revision 2 | Answered by |
|---|---|---|---|---|
| N1 | A relay's failed consistency proof was called fork evidence and froze an honest author | CONFIRMED | revision 2 SY-13 rule 2 said so; ADR-036 H-3 distinguishes contradictory openings from a missing/invalid proof; `log/history.rs:1528-1567` yields a verifier error, not an author contradiction | SY-13 rules 1–2: fork evidence only from author-signed objects (a verified opening that contradicts a held leaf counts; a failed proof is the relay's fault); the malicious-relay act and its mutant |
| N2 | Skipping the content parent's context check admits an underclaim: a delegate's removal `seen`ing content that descends from a newer expiring certificate while naming only the old one | CONFIRMED | `governance/sparse.rs:521-550` refuses "signed context omits/underclaims parent control" for every parent; `authority.rs:207-237` picks the latest certificate in causal scope; `member_fold.rs:908-920` rejects an expiring one for removal | SY-3 rules 1–4: a content header named in `seen` is input (one header, header-only fetched as a prerequisite, SY-14), its `pre_context` is the control-only summary, and the coverage check runs against it; validation keeps `validate_control_coordinate`'s exact identity checks (`:587-612`); act (iii) and its mutant |
| N3 | Adjacency without an inclusion opening leaves a held interval with no leaf-to-head tie after a cold restart | CONFIRMED | `log/history.rs:2233-2257` needs the exact sibling ranges; `proof_range.rs:202-228` returns `Missing` when a header is absent; revision 2 omitted the proof when `from − 1` was held | SY-12: every answer carries a range witness for exactly the positions sent, never omitted; SY-13 rule 4: acceptance needs the witness and the chain link; SY-18: descriptors come only from witnesses, coalesced on arrival, committed atomically with the interval; the sparse unaligned act and the no-witness mutant |
| N4 | A sparse holder cannot build a consistency proof from an arbitrary `since`; `EvidenceUnavailable` alone does not deliver offline-holder progress | CONFIRMED | `log/history.rs:2261-2295` canonical consistency ranges; `ConsistencyVerifier::new` `:1555-1567` | SY-12's bridge (`since` and `at` with its hash); SY-13 rule 3(c): a head is accepted by an inclusion opening of the requester's highest held position, which commits the same prefix through the chain; SY-16 serves either proof; when neither holder can, status names the wait; the act's negative control |
| N5 | The answer budget is a global cap; the zero-in-flight preference starves the rotating slot; "one wave" is false at 64 permits; six classes, not four | CONFIRMED | revision 2 SY-15 rules 1 and 3; `node/channel.rs:605-615` allows 1,024 authors | SY-15 rule 1: FIFO permit queue with the bound ⌈Q/64⌉ × 20 s stated; rule 3: deficit round-robin on every opportunity, two strict finite classes then four open ones, bounds stated in opportunities; the budget-saturated act (optional in tree, mandatory on the fleet) and its mutant |
| N6 | `Probe`'s `Held` answer had no consumer; `Range` selection read only `Have` | CONFIRMED | revision 2 SY-15 rule 4 selected on `Have` only | SY-14's availability overlay per peer, installed by `Held`, consulted beside `Have`, dropped on `Have` change or disconnect; the seventeenth-interval act and its mutant |
| N7 | One `Busy` on `Head` disarmed the dependency until the `Have` changed; a heartbeat is not a change | CONFIRMED | revision 2 SY-14 "not re-raised until that peer's `Have` for A changes" | SY-14 head wanted: outcomes enumerated (`Busy` re-arms at its retry time; a fault at the port's backoff edge; `NotHeld`/`EvidenceUnavailable` rotate holders and become "unsupported" only after every advertising peer refused, re-armed by a `Have` change, a new peer or a new own position); the Busy-then-Head act |
| N8 | A different HeadID at the known size never triggered `Head`, so an equal-size fork between two honest holders was never observed | CONFIRMED | revision 2 SY-14 keyed the trigger on size only; the accepted hint rule (amendment 2's current text) kept same-size distinct heads eligible | SY-12/SY-14: an unaccepted HeadID at or below the known size raises one `Head` (an accepted earlier head's id remembered in memory); amendment 2 reworded; the equal-size two-holder act and its mutant |
| N9 | Other recipients' package bodies were excluded from control demand and lie below a relay's anchor, so the promised always-on relay never acquires them | CONFIRMED | revision 2 SY-14 control wanted excluded them; amendment 3 promised them | SY-14 control wanted includes every key package's sealed body from position 1 regardless of anchor; SY-17 asks them at join; the late-relay act in `key_package_proof.rs` and its mutant; Q5 depends on it |
| N10 | Releasing the slot and permit at network end lets a failing writer accumulate unbounded received bytes; retaining them contradicted "nothing awaiting a save owns them" | CONFIRMED | ADR-036 H-4 `:234-241` holds permits until buffers are released; `source.rs:532-568` native worker charges | SY-24(iii): the resource table names every bounded resource, its owner, its lifetime and its behaviour under a failed write; the permit is held until the bytes are committed or discarded, so a node that cannot save fetches at most 64 MiB more and stops; SY-15 rule 1 counts permits that way; the third SY-24 act and its mutant |
| N11 | Local appends require a canonical `[1, p]` prefix per `seen` tip; a chain-admitted tip poisons the next post ("authored history settled peer prefix missing"), as the prototype reproduced | CONFIRMED | `local_history.rs:535-541`; `proto-range-sync.md:23-24,38` | SY-3 rule 6: a `seen` tip qualifies by acceptance and `control_through`; the writer's context is the join of held control frontiers; required ancestors selected first; act (iv) (sparse receive, restart, post, consent) and its mutant |
| N12 | Removals written by v0.4.30 need not reference the target (sixteen-tip selection); the control-only rule could hide a post the old fold treated as historical; "no such removal exists" was unsupported | CONFIRMED | `pending_text.rs:592-600, 647-649` is the removal writer (revision 2 cited the consent-grant site, `consent.rs:622-632`, wrongly); `local_history.rs:493-529` drops tips past sixteen | SY-3 rule 5: the required ancestor is added at `pending_text.rs:592-600` through `required_ancestors` (`local_history.rs:505-512` gives it priority); the recorded cut for pre-existing removals, computed by SY-26 from the old DAG before SO-2's sweep; SY-18 keeps it; the 17-author removal arm (optional in tree, fleet J5) and its mutant |
| N13 | The 60 s expiry of the short mark defeats the H-exchange bound: four short holders ranked above an honest one by other authors' deliveries can be revisited first | CONFIRMED | revision 2 SY-15 rule 4 "or 60 s have passed" | SY-15 rule 4: attempt epochs per (author, range), no time expiry, delivery score only among the untried; the four-short-holders act and its mutant |
| N14 | Skipping the `Range` serve gate cannot turn the real recipient's page red: its own render and install gates still hide the bodies; the mutant could not fail | CONFIRMED | `channel.rs:8115-8150` render gate; `pending_package.rs:547-566` install gate; ADR-007 `:294` keeps both defences | SY-25's proof split: a test-side hostile recipient with a retained old chain key asserts at the wire that no body bytes arrive (`Range`, offset continuation, join answer, own old package, a removal applied mid-exchange); the real-recipient act kept for the receiver defence; per-frame generation check stated |
| N15 | A 64 MiB image cannot stage the fixed binary under ADR-047 SO-11's 64 MB floor (42 MiB free after the RCA's free), so the staging would be an apparatus red | CONFIRMED | ADR-047 SO-11 `:931-960` and its 256 MB image; `/tmp/RcaSchedStall/receipts/exp2.log:10-12`† | SY-24's proof on FG-20's staging: a 256 MB image, an external fill file below the floor, two cycles, the staging asserted from `cannot save`/`recovered` before the claim; the v0.4.30 red kept as genuine (no floor then) |
| N16 | The prototype report exists; "no report yet" was stale; its B3 failed, it wrote 40k proof-like rows, its slow member was pause/resume, and its governance counter is not the revised assertion | CONFIRMED | `proto-range-sync.md` (read whole); ADR-045 FG-5 | Preamble, §3's intro, "What has been measured of R2", SY-23's table and Q1 carry the qualified numbers as investigation evidence; every B3 hello count is also struck for the reader defect (Main, 2026-11-13); Q1 stays open with the arms' rule |

### Third review (answered in revision 4)

| # | Finding | Classification | Evidence read at v0.4.30 and in revision 3 | Answered by |
|---|---|---|---|---|
| P1-1 | Accepting a head by an inclusion opening of the highest held position is unsound: H5 then H16 with the same leaf 5 over different leaves 1–4 passes | CONFIRMED | `log/history.rs:764-869, 1314-1408`: an opening proves one leaf's membership, nothing about the other leaves; r3 SY-13 rule 3(c) | SY-13 rule 3: rule (c) withdrawn; acceptance by a consistency proof only, **composed** from the holder's descriptors, the requester's kept or computed ones and further holders (N4 closed this way); `since` > `at` handled; the same-leaf/different-prefix act and mutant; SY-12's `Head` carries the decomposition and names lacking ranges; SY-16's sparse act rewritten |
| P1-2 | Inherited content summaries unvalidated: D's content K underclaims the creator's post carrying C2, then D's removal inherits C1 | CONFIRMED for the one-hop case; PARTLY beyond | `governance/sparse.rs:509-550` validates every parent; `authority.rs:207-237`; `member_fold.rs:908-920`; r3 SY-3 rule 3 checked only E's previous *control* | SY-3 rule 3: E's own previous entry K, when content, is validated against its `seen` parents' headers and E's context must cover K's (one header hop, fetched as a prerequisite); rule 2 states the residual plainly: a reference buried deeper gains the attacker nothing a non-reference does not (both are concurrent with C2 under G-29), and supersession is enforced only against entries that attest having seen it, with G-29's revocation cutoff as the creator's tool; the content-hop act and mutant |
| P1-3 | `ControlRange(1,5)` with controls at 1, 3, 5 commits nothing: rule 4 required adjacency or first position | CONFIRMED | `log/history.rs:1950-2150` returns separated authenticated control leaves; r3 SY-13 rule 4 | SY-13 rule 4: a witness-opened leaf is accepted on its own (a control proof opens each control leaf and proves the gaps control-free); chain links are checked against whatever neighbours are held; the sparse-controls act and mutant |
| P1-4 | Retained permits of one failing room can hold all 64; the `⌈Q/64⌉×20 s` bound ignores commit waits and gives zero for the first queued request | CONFIRMED | r3 SY-24 table and SY-15 rule 1 | SY-24 table: a room retains at most 8 MiB past its exchanges and starts nothing at its cap; answers beyond it are discarded unverified and re-derived; SY-15 rule 1: the permit lifetime L stated (exchange + verification + commit wait or `StoreRecovered(room)`), the bound ⌈(Q + 1)/64⌉ × L |
| P1-5 | The admission queue retried on `StoreReopened`; ADR-047 SO-11 emits `StoreRecovered(room)`, floor recovery included | CONFIRMED | ADR-047 SO-11 `:1198-1208` | SY-24 (ii) and the table: `StoreRecovered(room)` everywhere (admission retry, retirement retry, `StoreRecovery(room)` release); R1 step 9 |
| P1-6 | A content position in `required_ancestors` cannot be satisfied by the context guard (`local_history.rs:544-568`): "required governance ancestors exceed the authored frontier" | CONFIRMED | `local_history.rs:544-568` compares the context coordinate only | SY-3 rule 5: the guard distinguishes control ancestors (context coordinate) from content ancestors (a `seen` reference at or above the position with its hash); rule 6; act (iii-b) and mutant |
| P2-1 | An upgraded holder's recorded cut is local; a fresh joiner cannot reproduce it | CONFIRMED | r3 SY-3 rule 5 / SY-26 | SY-3 rule 5 and SY-26: the removal's issuer or the creator appends a signed `CutAttestation` control entry, folded like any control; a fresh joiner receives it in the control range; without it the joiner classifies conservatively and status says so; the fresh-joiner arm and mutant |
| P2-2 | The receiver mutant (skip the render gate) need not reveal anything: M lacks the chain for posts written during removal; the install gate refuses old packages; no multi-frame body | CONFIRMED | `pending_package.rs:547-566`; r3 SY-25 proof | SY-25 receiver act restaged: P1 posted under a chain M holds while M is offline, M removed, readmitted, pages back; the mutant reveals P1's text; a mid-stream act with an initially eligible 12 MiB body and a removal applied during it, mutant = authorize once per request |
| P2-3 | Filling below SO-11's floor need not fail any cleanup (reclamation under the ballast), so the failed-cleanup mutant can stay green | CONFIRMED | ADR-047 SO-11 `:1168-1190` | SY-24 proof: SO-11's admission-to-write apparatus (`test-knobs`) stages a cleanup that fails, asserted from the ledger before the claim; both acts optional in tree (ledger row 51) and mandatory on the fleet (J5(g), FG-20); the mutant's own missing-post assertion |
| P2-4 | Invalid measurement claims: unpaged B3 "never" counts at D:101–102 and :596–599; the slow-path baseline 12–16 s labelled corrected (the corrected baseline is 213–279 s); "no proof rows written" for a binary that wrote 15,001; "trace still landing"; week estimates | CONFIRMED | `arm-repair.md` (apparatus defect; B3sp-base s2; B1-arm 15,001 rows; the trace: 441 of 1,521) | Context table and SY-4's proof reworded; SY-23's table rebuilt from the two final reports only; the R1 and R2 measured sections rewritten with the traced misses; every week estimate removed (ledger row 55); Q1's table and prose |
| rule | Q1's rule: stage all six earlier joiners, reads in both directions, "neither demonstrated" names the next step | CONFIRMED | — | Q1 rewritten: the fact that neither arm passes, which assertion each fails, the table, the corrected rule, the next measured step for each route |
| 88 | Belongs in SY-10 with amendments to ADR-007 G-22/G-22b and ADR-005 J-18; the veto is `SEAT_ANSWER_WITHIN` | CONFIRMED | `seatstream.rs:48, 230-265`; `actor.rs:3480-3590` (`Unanswered` → `SeatNotAgreed`); `channel.rs:607-615` | SY-10 rewritten per the decider's ruling (row 37); amendments 22–24; the paused-member, near-cap and split acts |
| 89 | Belongs in an expanded SY-11; cause UNKNOWN; RD-1 owns responsiveness; ADR-048 TC-6 consumes the prerequisite | CONFIRMED | `arm-repair.md` B3dc-arm s2 (214 s) | SY-11 expanded: the open-node fence rule, E-89 as the settling experiment with no fix attached, the open-node act (red unverified) |
| arm | Two design findings from the replace arm: per-entry admission; `ContextUpdate` makes "bounded control set" false | CONFIRMED | `entry_store/sparse.rs:2038` `begin_sparse_publication`; `log/history.rs:60-79` (`ContextUpdate` = 7, `is_control`), `:1723-1741` (`ControlToken::Leaf`) | SY-13 rule 4 (one transaction per chunk; the read view from the snapshot); SY-3's head (what the fold waits on; `ContextUpdate` never a wait by itself); SY-12 (128 control positions per answer) |

The second review's cross-boundary notes were applied: the per-frame generation recheck (SY-25);
the sibling serving contract made one in meaning with ADR-044 RD-9 r3 and ADR-047 SO-1 r3 (SY-16,
SY-18, amendment 21: canonical → cache → reconstruction → kept descriptor; the fork gate and
per-leaf re-check dropped; cost per miss, not per process life; no receipts under R1 or R2); the
inert-pending-removal window stated (SY-25); the removal writer cited at its true site (SY-3 rule
5); the class and permit bounds stated in the units the reviewer asked for (SY-15); the kept
Pairwise and Session streams untouched (SY-12 carries no private record). The first review's
assessment notes stand as applied in revision 2.


### Fourth review (answered in revision 6)

The fourth review (`adr-046-sol-review-4.md`) retraced the third pass: P1-3, P1-5, P1-6
closed; P1-1, P1-2, P1-4, P2-1, P2-2, P2-3, P2-4 partly. Its own findings:

| # | Finding | Classification | Evidence read at v0.4.30 and in revision 5 | Answered by |
|---|---|---|---|---|
| 1 | The checkpoint carries a hash and nothing retrieves the state; the removed-and-readmitted cut must survive; RL-3.1 analogy backwards; full-record holders must compare | CONFIRMED | `governance/view.rs:990-1012` (`RecipientCut`); ADR-023 RL-3.1; r5 SY-27 point 3 | SY-27 point 3: the snapshot (canonical bytes, contents incl. per-member removal/readmission state, bound 256 KiB), `Snapshot{hash}` transport (SY-12, seventh request), atomic installation, the trust stated plainly and sent back to the decider, the full-record comparison and the checkpoint dispute (cuts, fork evidence, own continuity, ADR-048 debt untouched) |
| 2 | No "previous governance coordinate" in `EntryV2`; a contradicting successor by another author is not creator fork evidence; disagreeing attestations are not equivocation | CONFIRMED | `log/entry.rs` (`pre_context`, `seen`, `prev_hash` only); SY-13 rule 2 | SY-27 point 3: boundary = the fence header at `(seq, hash)` sent in the witness and `seq+1`'s `prev_hash`; a mismatch is a dispute, not a fork; SY-3 rule 5: disagreeing attestations keep both, apply the lower `through` |
| 3 | The one-chunk promise is false without fresh fence posts: `ControlRange` expands every intervening `ContextUpdate` (kind-blind count); option A's "membership events, not messages" false; below-fence prerequisites must be fetchable and routed | CONFIRMED | `log/history.rs:1990-2060` (collapsed descriptor with nonzero controls refused inside the interval) | SY-27 point 3: the cost without a fence post computed for his room (≈ 4.6 KB/s, ≈ 400 MB a day) and disclosed as Q8; point 4 corrected; below-fence single headers allowed as prerequisites; SY-14's parent-header class covers the previous own entry and its `seen`; measurement slot (e) |
| 4 | Transitive authority through two content hops; a `CutAttestation` with an unchecked `through` | CONFIRMED | `governance/sparse.rs:509-550`; `authority.rs:207-237`; `member_fold.rs:908-920` | SY-3 rule 2: an author's content chain back to its last control is validated and covered, an unverified summary keeps the action inert; rule 5: an attestation's `through` must be covered by what the attester provably held (the removal's references or its own prior content), else refused and reported |
| 5 | Eight failed rooms × 8 MiB exhaust the 64 permits; the bound was not finite over a `StoreRecovered` wait | CONFIRMED | r5 SY-24 table, SY-15 rule 1 | SY-24: failed retention capped at 16 MiB in all, a 48 MiB runnable pool never retained; SY-15 rule 1: the bound over the runnable pool, L excluding recovery waits, its storage assumption stated; the nine-room act |
| 6 | Near-cap arithmetic: a truthful `Full{1024}` classed malformed; `JOINS_IN_FLIGHT` = 16; the heartbeat bounds nothing; an unanswered peer may have reserved | CONFIRMED | `actor.rs:762`, `:18354-18440` (`reserve_seat`, `answer_seat` inserting before `Yes`), `seatstream::PROMISE_TTL` | SY-10: the sum uses 16 per connected member and itself, promises as reserved, the residual stated as a soft cap; `Full` judged against the cap and the applied count; `ABORT` to unanswered members; stale-view and concurrent-ask acts; the mutant restaged (never ask) |
| 7 | The after-access class had no dispatch branch; a rejoin must consume LE-9's append checkpoint and push the unconfirmed suffix | CONFIRMED | r5 SY-15 rule 3; ADR-049 LE-9 | SY-15 rule 3: five open classes, after-access one in five; SY-11 and SY-17: the append checkpoint kept and installed, the suffix pushed, the fence only on a proven higher own head, LE-9's crash states re-derived |
| 8 | SY-26's attestation step is lost to a kill; SY-25's mid-stream act cannot reach a second MiB and the mutant need not leak; SY-24's mutant stays green below eleven failed flows; SY-10's seventh-join mutant cannot fail | CONFIRMED | ADR-047 SO-11; SY-25/SY-24/SY-10 proofs as written | SY-26: attestations derived at every open, keyed by removal hash; SY-25: one 15-frame answer, a hold after frame five, the assertion on the absent sixth frame; SY-24: eleven failed cleanups staged, the nine-room permit act; SY-10: the stale-view mutant |
| 9 | Session-1 repair figures under "corrected reader"; doctor/hello timing presented as `control_current`; "only failed assertion" | CONFIRMED | `arm-repair.md` (session 1 before the pager fix) | SY-23's rows, the R1 section and Q1's table split by session; `control_current` marked unmeasured; the replace arm's miss stated as the one *observed* failed assertion with the unobserved ones named |

### Fifth review (answered in revision 7)

The fifth review (`adr-046-sol-review-5.md`) retraced the fourth pass: 5 closed at the
invariant level; 1–4, 6–9 partly. Part 1 corrected the plain-words statement put to the decider;
he answered on the corrected statement (row 68). Its own findings:

| # | Finding | Classification | Evidence read at v0.4.30 and in revision 6 | Answered by |
|---|---|---|---|---|
| 1 | The snapshot is not representable in 256 KiB (a composite key is 1,984 B; removal history unbounded); certificates need capabilities and history; the baseline is not durable or served | CONFIRMED | `identity/composite.rs:14, 69-70`; r6 SY-18's list | SY-27 point 3: a Merkle-committed chunked snapshot (≤ 1 MiB chunks, root `H`), records enumerated incl. every certificate with capabilities and status; `Snapshot{H, chunk}` (SY-12); the baseline a durable immutable SY-18 fact with provenance, served, reclaimed only when its successor is whole |
| 2 | "Trustworthy once the following control validates" deadlocks (quiet author; two writers); a whole-run walk can reach below a fence; SY-14 scheduled only direct `seen` parents | CONFIRMED | r6 SY-3 rule 2; SY-14 | SY-3 rule 2: verification on preceding facts only, acyclic recursion stopping at fences and controls, the fence as the verification boundary; SY-14's ancestry class |
| 3 | The boundary header may be content and cannot ride in the control trace; `seq+1`'s header may be absent; below-fence coordinates waived without exact checks | CONFIRMED | `log/history.rs:1950-2140`; `governance/sparse.rs:587-617` | SY-27 point 3: a boundary frame of two framed inclusion proofs (fence and `seq+1`) outside the trace; a coordinate waived only when the baseline lists it exactly, else fetched and checked by `validate_control_coordinate` |
| 4 | A fence can seal an inert fact out of a newcomer's view; "certificate in force" is not G-29's causal authority | CONFIRMED | r6 SY-27 point 3 | the fence is strictly below any held-but-unapplied governance entry; the snapshot carries every certificate ever issued with its status |
| 5 | `Asked::Unanswered` carries no stream, so `ABORT` to unanswered members needs the handoff changed; the short-peer rejoin has no defined retention of the gapped continuation | CONFIRMED | `seatstream.rs:207-220, 273, 304`; ADR-049 LE-9 | SY-10: `Asked::Unanswered(SendStream)`, `unanswered_sends`, `ABORT` on refusal; SY-11: the observed, gapped continuation (bounded, durable, unaccepted, status-visible) and its closure; SY-18 lists it |
| 6 | The nine-room act's precondition is impossible (8 × 8 MiB under a 16 MiB cap); its deadline mutant unexercised; the "never ask" mutant cannot fail after convergence; both-`Taken` is allowed; attestation disagreement must not hide proved coverage | CONFIRMED | G-22c; `seat_count`; r6 proofs | SY-24: offered answers, discard asserted, a one-in-three silent member for the deadline path; SY-10: the remote-refusal act and mutant, both-`Taken` accepted; SY-3 rule 5 and SY-27: the higher accepted bound applies, nothing proved historical is hidden |
| 7 | 26.8 s cited as the replace baseline's governance timing (it was the prototype session's); the 15-minute figure unsupported; estimates and measurements to be kept apart | CONFIRMED | `arm-replace.md`; `proto-range-sync.md` | Q1's table cell marked unknown; "15 minutes" removed everywhere; SY-27 point 3's estimate qualified as Part 1(b) words it; slot (e) measures age, distance, bytes, requests and time together |
| Part 1 | The plain-words cost statement for the decider was too strong (a), the time figure unsupported (b), the alternatives incomplete and no cadence defined (c) | CONFIRMED | — | SY-27 point 3: the trust paragraph in the corrected words; the estimate as Part 1(b); the cadence (10,000 entries / governance event + 10 min / 24 h), status line, "return helps only after a new fence"; the two alternatives recorded as not taken (row 68) |

### Sixth review (answered in revision 8)

The sixth review (`adr-046-sol-review-6.md`): item 7 closed; 1–6 partly, each with one
remaining finding. No decider question reopened.

| # | Finding | Classification | Evidence read at v0.4.30 and in revision 7 | Answered by |
|---|---|---|---|---|
| 1 | The snapshot is unbounded and was to be held whole before installation; no per-chunk staging; "all chunks held" undecidable | CONFIRMED | r7 SY-27 point 3; SY-24's permit rule | SY-27 point 3: chunks verified then staged in bounded transactions under `(room instance, H, i)`, permits released on staging; a baseline assembly per room with derived demand, cancellation and reclamation; installation by reference when the signed chunk count and total length are met |
| 2 | A referenced content summary inherited from its previous control and `seen` only; a colluding author's K1/K2 under an admin's removal bypasses it | CONFIRMED | r7 SY-3 rule 2 | SY-3 rule 2: a content header inherits from its own immediately preceding entry, recursively to a control or the fence, and from its `seen` parents; act (iii-c) and mutant |
| 3 | `prepare_received_effect`'s unconditional coordinate loop (content included, validated header + completed effects per coordinate) was not migrated; the prototype's 25.3 → 48.7 s is that loop | CONFIRMED | `pending_received.rs:134-147` | SY-3: baseline-aware resolution in that loop and its visibility consumers (exact baseline facts resolve; a witnessed pre-fence header is terminal evidence; membership checks unchanged); act (iii-d), the fresh-fence pair, and its mutant |
| 4 | "Strictly below any held-but-unapplied governance entry" lets a hostile member pin its own fence; frontiers not bound to coverage and generation; 10,000 entries cannot mean one chunk per author; presence is not freshness | CONFIRMED | r7 SY-27 point 3 | the fence passes settled-inert facts (their disposition carried in the snapshot) and stops only below unresolved ones; bound to `control_through` and the snapshot's fold generation under one lease; cadence (i) = any author 96 control positions above its fence; a creator not current under load signs nothing, stated |
| 5 | `Unanswered` may occur before `open_typed` completes, so `Unanswered(SendStream)` cannot always exist | CONFIRMED | `seatstream.rs:232-241` | `Asked::Unanswered(Option<SendStream>)`; `ABORT` only where a stream exists; the whole-operation deadline kept; neither outcome vetoes |
| 6 | Every third request silent lets both slots stall, so 5 s rendering is impossible for a correct scheduler | CONFIRMED | K = 2, SY-15 | SY-24's act: at most one silent request at a time with 5 s progress through the other slot, one staged double stall with a 20 + 5 s recovery bound; the mutant fails the recovery bound |
| 7 | The catch-up status derived "behind" and its estimate from `Have` sizes | CONFIRMED | r7 SY-27 status line; SY-12's hint rule | `N` and `M` from accepted signed heads only; advertisements shown apart as `advertised, unverified` and in no estimate |
| asks | X049-6 (`PeerReachable` release event), X049-7 (the fence post and a returning author's own feed), X048-7 (the own-history predicate and act 5) | CONFIRMED | `adr-cross-asks.md` | SY-21 (`PeerConnected(peer)`); SY-27 (three limits); the "Related lanes" paragraph corrected and both parts carried |
| quotes | amendment rows 20, 21 NOT FOUND; 22 elided; 24 no quote; conditional marks | CONFIRMED | `adr-amendment-quotes.md`; ADR-005:89-92; ADR-007:155-163 | 20 and 21 restated as sibling contracts; 22 quoted whole; 24 quoted and replaced; every row unconditional |

### Seventh review and the round-2 measurement (answered in revision 9)

The seventh review (`adr-046-sol-review-7.md`): items 5 and 7 of the sixth pass closed;
1, 2, 3, 4, 6 partly; four P1 and three P2. The round-2 measurement
(`arm-replace.md`, final binary 4189c291c) fails the decisive case on one assertion.

| # | Finding | Classification | Evidence read at v0.4.30 and in revision 8 | Answered by |
|---|---|---|---|---|
| P1-1 | r8 does not give a slow existing member content-rate-independent governance progress: validation gated on `control_through`, Content effects resolved against completed effects above the fence | CONFIRMED (and corroborated: y1's governance 8/87, 62/86, 50/92; `pending_received.rs:134-147`) | r8 SY-3 rules 3 and 4, its effect consumer | SY-3 rule 3 (pinned prerequisite frontier, no coverage gate), rule 4 (the fold and key queue own their progress), the effect rule for Content (two lookups), SY-13 rule 5; new SY-28 with its act and mutant; no proof change, no second signer |
| P1-2 | no definition of which holders have a snapshot | CONFIRMED | r8 SY-12's `Have` schema | `Have` carries `checkpoint` and `snapshot_held`; SY-27's holder eligibility with `NotHeld` rotation and re-arming; act (s3) |
| P1-3 | every newer checkpoint cancelled the assembly | CONFIRMED | r8 SY-27 point 3 | the assembly state table: a newer checkpoint is `next`, never a reset; abandonment only by Retire or 24 h unavailability; act (s1) |
| P1-4 | cancellation deleted every chunk in one transaction, against SO-11's 256-key / 2 MB batches | CONFIRMED | ADR-047 SO-11 `:1416-1421` | Retire in one small write, reclamation in SO-11 batches from a cursor, installed baselines protected by reference, late staging refused; act (s4) |
| P2-1 | 96 is a trigger, not a 128 bound | CONFIRMED | r8 cadence (i) | stated as a trigger with the real delta (`96 + rate × (60 s + signing delay)`), measured by slot (e); "one chunk per author" claimed only per measured run |
| P2-2 | blackholing the hop stalls the connection; "every other" does not keep one slot live | CONFIRMED | r8 SY-24's act | the apparatus withholds on one selected stream with a "no other silent request" guard, connection live; a separate double stall; the mutant = no release at the deadline, red on the 25 s recovery |
| P2-3 | (iii-c)'s certificates issued to D, not to B the removal author | CONFIRMED | r8 act (iii-c) | C1/C2 issued to B, D the separate colluder, B meets C2 only through K1/K2; the act first shows the removal would be authorized under C1 |
| round 2 | cause 1 is in the design; wiring faults 2 and 3; items 1–6 of "what this build contradicts" | CONFIRMED | `arm-replace.md`, receipts `/opt/vox-evidence/v0431/arm-replace/r2d-*/` | SY-27's results slot and cause-1 retrace; SY-13 rule 4 (effects per chunk, owned writes); SY-10 (fold-behind member answers `Busy`); SY-9 (page unbuilt, noted); SY-16/SY-18 (descriptors in the build list); the build list section; acceptance waits on the next cycle |

### Eighth review (answered in revision 10)

The eighth review (`adr-046-sol-review-8.md`): P1-2, P2-2, P2-3 of the seventh pass
closed; the rest partly; five P1 and three P2. The decider answered SY-28 (row 76).

| # | Finding | Classification | Evidence read at v0.4.30 and in revision 9 | Answered by |
|---|---|---|---|---|
| 1 | A witnessed `ContextUpdate` header satisfied a coordinate alone, losing the governance behind it (C1/C2/U: the forbidden removal is accepted) | CONFIRMED | `authority.rs:207-237` selects among indexed certificates; r9 rule 3 | SY-3 rule 3: the pinned closure (headers for every coordinate, bodies for governance and typed-policy kinds, summaries followed through their `pre_context`, stop at baseline-listed or validated coordinates); reconciled with rule 2 as one definition; size not claimed, measured; the C1/C2/U act in both orders with the U-terminal mutant; StepPolicy keeps its typed evaluation |
| 2 | Coverage gates survived in rule 2 (previous control "at or below `control_through`") and rule 4 (re-evaluation on coverage advance); SY-14's ancestry demand did not define the rule-3 frontier | CONFIRMED | r9 lines 888–889, 997–999, 1958–1963 | rule 2 and rule 4 reworded (prerequisites fetched, re-evaluated on arrival); SY-14's closure demand (direct, recursive, bodies, dedup, wake); build item 3 names the post-loop `checked_governance` deferral |
| 3 | Suppliers may reclaim a pinned snapshot mid-transfer | CONFIRMED (for r9's assembly) | r9 assembly table | moot: the assembly is deleted; the summary is one ≤ 1 MiB answer (SY-27 point 3's v0.4.31 limit) |
| 4 | Staging not fenced at commit (a queued stage can write a retired assembly) | CONFIRMED (for r9's assembly) | r9 assembly table | moot: no staging; installation is one transaction with no partial state |
| 5 | s1, s4, s5 mutants do not discriminate; SY-28's mutant no longer freezes the fold; adoption untested | CONFIRMED | r9 acts | s1–s5 deleted with the assembly; SY-28's acts rewritten: fold isolation (blocked unrelated Content, mutant queues governance behind it), the two-lookup mutant asserting the render, adoption with its precondition asserted and a skip-adoption mutant, the disputed-summary act with an adopt-despite-contradiction mutant |
| 6 | Build item 2 repaired an idle lane that `arm-replace-next.md` retracts: y1's own posts never committed | CONFIRMED | `arm-replace-next.md` | item 2 = trace and repair y1's publication stall, recording accepted posts, own-feed commits and observed advancement; the round-2 explanation corrected in SY-27 |
| 7 | Build item 2 let a `Have` raise the known size | CONFIRMED | SY-12/SY-13 | item 7: `Have` triggers verification only; an accepted signed head raises size and derives demand; the false-advertisement act kept |
| 8 | "One chunk per author holds whenever the creator keeps the cadence" survived at 680–681 | CONFIRMED | r9 line 681 | qualified by the measured per-author delta; the rate formula an estimate with its assumptions |
| SY-28 | Adoption extends rows 65/68's trust and conflicted with the dispute rule | CONFIRMED; the decider ruled (row 76) | r9 SY-28 (iv) | one rule: adopt only a summary that agrees with every held fact for the held part (comparison authenticated by the creator's signature and M's witnessed facts, bounded by M's held governance set); a contradiction is a dispute, never adopted; M keeps verifying and status says why |
| 047 R8-2 | SY-26's "one commit per room" with unbounded cuts | CONFIRMED | ADR-047 r11 | SY-26: SO-2 step 4's migration batches (≤ 256 keys, < 2 MB), `meta.sy26_cursor`, `meta.anchors_initialized` in the last batch, resumable, nothing read as migrated before the marker, the room unpublished meanwhile |

### Ninth review (answered in revision 11)

The ninth review (`adr-046-sol-review-9.md`): findings 2, 6, 7 and 8 of the eighth pass
closed, the simplification and the adoption policy confirmed (rows 76–77); five P1 and four P2,
all CONFIRMED on the tag or on revision 10's own text.

| # | Finding | Classification | Evidence read | Answered by |
|---|---|---|---|---|
| 1 | A summary carrier was validated through its declared context only; a malicious U underclaiming C1 while `seen` names X (which follows C2 on the creator's chain) admits the forbidden removal | CONFIRMED | r10 lines 1000–1007; `authority.rs:207-237` selects among what the projection indexed; `governance/sparse.rs:509-550` compares declared contexts, it does not walk | SY-3 rule 3 as `CLOSE(E)`: deps = previous + declared context + `seen`; per named author the **span walk** from its stop to the named position; carriers validated by `CLOSE` like any control entry; "validated" = in V; the hidden-certificate act (both orders, preceding-carrier variant) with the U-terminal shortcut mutant |
| 2 | Kind 6 bodies were unconditional prerequisites; a package addressed to a readmitted member can never be fetched by it (SY-25), so the readmission's closure never completes | CONFIRMED | r10 lines 1001–1004; SY-25's `not for you` | a key package is authenticated by header and its own deps, never by body; installation stays the recipient's gate; the old-package act with the require-all-package-bodies mutant |
| 3 | The stop rule did not name the fence: an unlisted pre-fence `ContextUpdate` was walked through its old chain; "few headers / under 1 MiB" and "nothing scales with …" overclaimed | CONFIRMED | r10 lines 1005–1015, 785–788, 1039–1040 | the **baseline resolver** (one header, binding checks, terminal, shared by the closure, the effect consumers and the doctor); the narrower progress claim (no header twice, none below a fence, no wait on coverage) and the per-entry measurement in build item 4 |
| 4 | The comparison took M's records through `control_through` only: a sparse validated removal above it was not compared; and M ahead of a fence demanded records the checkpoint rightly lacks | CONFIRMED | r10 lines 756–769 | the comparison algorithm: domain = held facts (contiguous and sparse) at or below each author's fence; facts above it excluded, kept, re-folded; forward and reverse checks; both directions hand-run |
| 5 | The summary had no record for `ConsentGrant`, `ConsentRevocation`, `Presence` …; the equality the rule stated was not performable | CONFIRMED | `governance/entry.rs:57-95` (the variants); r10 schema at 507–515 | the three-table schema with the canonical comparison record (author, position, kind, hash, projection, disposition-not-compared) for every `GovBody` variant and the typed-policy kinds; key packages excluded with the reason; sizes recomputed (20 KB / 35 KB / 365 KB / 1.04 MiB at 200 members with history); the limit kept, Q9 to the decider |
| 6 | Dispositions and cuts were compared as evidence; an honest checkpoint with E inert under a creator cutoff M lacked was disputed | CONFIRMED | r10 lines 758–761; ADR-007 G-29 | source facts only; conclusions re-folded after adoption; M's own recorded cuts and attestations kept as obligations |
| 7 | The limit was on the summary, not on the encoded answer; the receiver's action on an over-limit candidate unstated | CONFIRMED | `log/history.rs:27-28` ("including framing") | eligibility on the measured encoded response ≤ 1,048,576 B, frames of ≤ 256 KiB including headers, `summary_len` the measured length; a receiver rejects the candidate before installation, keeps the last usable fence post or verifies from 1, with the status line |
| 8 | SY-26 entered on "no anchor exists"; after the anchor batch a restart skipped the rest | CONFIRMED | r10 lines 1494–1504 | `!meta.anchors_initialized(room)` is the sole predicate, resume from the cursor; the interruption arm (kill after the anchor batch) with the enter-on-anchor mutant |
| 9 | The adoption mutants asserted timing (180 s) that a gap of 128 positions does not establish; the adopt-despite mutant does not leak posts on M (its own cut holds) | CONFIRMED | r10 lines 820–830 | acts asserted through the public status outcomes (adopted line, verifying line, dispute line, `Have` silent); ten chunks staged so the gap is real; the skip-comparison mutant's red is the **newcomer through the adopter** rendering the removed member's post |
| cleanup | 649 "baseline chunks", 787 cost bound, 795–796 "adopts missing facts", 2263–2266 staged chunks | CONFIRMED | r10 text | all four rewritten |

**For ADR-047** (the reviewer's list, checked against the frozen r12 `ADR-047.09700b194.md`):
SO-15 (its 2040–2046) already carries the single installed summary as one `index` row replaced in
the installing transaction, "no chunks, no assembly, no staged state" (row 77) — nothing remains
there; SO-2 (its 793–815, 1524) already runs SY-26 as bounded batches with the cursor and marker
before the sweep and keeps the installed-baseline exemption — what remains is to cite SY-26's r11
entry predicate (the marker's absence, not "no anchor") and the kill-after-anchor-batch arm; the
X046-33 baseline contract and SO-11's reclamation text are to be checked for any surviving
"chunk retention", "by-reference switching", "unreachable baseline" or `Reclaiming` wording — none
was found in the frozen r12 by search, so the ask is a confirmation, not a change; SO-2's staged
**body** support is untouched. (Listed in the revision note as X047 asks.)

### Tenth review (answered in revision 12)

The tenth review (`adr-046-sol-review-10.md`): ninth-pass findings 2, 6, 8 and 9 closed;
three P1, three P2, the sizes, and the pending inputs (`adr-046-pending-r12.md`: ADR-042
G2's mismatch sentence, Q9's wording, rows 80/81, item 93, row 82). All CONFIRMED on the tag or
on revision 11's text; nothing the reviewer closed is reopened.

| # | Finding | Classification | Evidence read at v0.4.30 | Answered by |
|---|---|---|---|---|
| P1 readmission state | The summary carried a readmission's subject only; `removal_entry_hashes` and the resulting member/cut state were lost; a readmission covering R1 must not cancel R2; hash-only RoomName/RoomAnchors and typed projections supply no value | CONFIRMED | `governance/membership.rs:237`; `member_fold.rs:60-108` (membership restored only against the removals named); `authority.rs:485-505` (cutoff restore tests the list); `governance/view.rs:990-1012` | SY-27 point 3's schema: the rule "a hash authenticates, it does not supply"; readmission rows carry `covers`; member rows carry `state`, `active_removals`, `cuts`; every projection is the consumer's value (name, anchors, ttl, expiry, caps…); the field-to-consumer paths written out |
| P1 frontiers | `CLOSE`'s `v_A` was identified with SY-14's `control_through`, which advances on receipt; content positions had no defined hash boundary | CONFIRMED | r11 1099–1107 against 2164–2170 | the two-frontier state table: `control_through` (received, demand's) and the closure index → `closed_through` (validated, the stop's and the fences'); content positions enter the index through rule 2's recursive header verifier; one write with the disposition; no coverage gate; SY-14 and SY-27's fence definition changed together |
| P1 dispute not fork | The resolver called a baseline/namer mismatch fork evidence | CONFIRMED | r11 1035–1038 vs 610–612; SY-13's definition | the mismatch is decided on A's witnessed header: namer refused, or checkpoint disputed as the boundary-frame case; fork only with two A-signed objects |
| P2 member clip | Step 4 demanded member rows for admissions above the admitter's fence | CONFIRMED | r11 810–813 | step 4 clipped to `f_admitter`; above-fence admissions kept and replayed; hand-run added |
| P2 bad answers | A short relay answer disqualified an honest checkpoint | CONFIRMED | r11 559–565 | signed over-limit `summary_len` rejects the candidate; a length/hash failure rejects that answer only, rotate, progress line; supersedes ADR-042 G2's mismatch sentence |
| P2 constant-work claim | "bounded by its own coordinate count, ≤ 2,048" survived | CONFIRMED | r11 1075–1079 | replaced by the pinned-closure guarantee and measured costs; independence from future arrivals distinguished from independence from history |
| sizes | 48 B was not a row bound (40 B before CBOR; ServiceShare ≥ 72; readmission variable) | CONFIRMED | arithmetic | rows recomputed as CBOR byte counts (42 B base; per-kind widths); worked examples 20,920 / 36,586 / 384,910 / 2,193,958 B; 489 bare or 272 with history; Q9 held until verified |
| row 82 | quiet-room waits; the room turn's `try_lock` starvation | CONFIRMED on the tag: `node/actor/governance.rs:325-340`, 45 `try_lock` sites under `node/actor/` | SY-29: no step waits for quiet; the control lane with standing; the cadence signs from the committed generation; the try-lock mutant in the duty-cycle act |
| rows 80/81 | numeric speed targets | checked: the ADR's "within N s" figures are proof acceptance windows (apparatus bounds), SY-10's T + 10 s is a bound on the join's own answer, and Q8 cites ADR-045 J1's qualified promise; no SY states a latency target | no change beyond SY-29's "within its own bound" |
| item 93 | own publication vs policy application | owned by ADR-043/ADR-048 | SY-29 states the one sentence and cites them |

### Eleventh review (answered in revision 13)

The eleventh review (`adr-046-sol-review-11.md`, with its relabel after the decider's
row 83): closed dispute-not-fork, member clipping, malformed answers, the constant-work claim;
five P1 (the frontier ordering relabelled P1 under row 83), the lane ruling 82b, and cycle 5a's
design gap. Row 83: the P2s (cached-U and interrupted-projection **staging**, the byte-count
wording) go to the task's acceptance (`v0431-owed-p2.md`) and are not edited here; the
acts the P1s require are added as design, their staging is the task's.

| # | Finding | Classification | Evidence read at v0.4.30 | Answered by |
|---|---|---|---|---|
| P1 context-invalid carriers | a refused underclaiming carrier became a hash-checked boundary; `authority::Query` scopes certificates causally, so an indexed C2 outside E's closure is unseen | CONFIRMED | `authority.rs:207-237`; r12 1236, 1248–1249, 1282–1283 | closure index with **context** and **disposition** columns; context-invalid rows never a stop, their deps expanded by every namer; "validated" = context-valid; the cached-U order in the act with its refused-rows-are-boundaries mutant |
| P1 completed prefix | a committed generation can hold a half-done fold step; the trigger copied the live projection | CONFIRMED | `member_fold.rs:773` (`decide`), `:1008-1016` (`current_step`, phase 2) | `settled_through(A)` advanced only in a step's last phase; `f_A` = min(closed, settled); the summary **derived** from settled records, never copied from live tables; one-transaction publication; crash = repeat; the half-step act with its mutant; no quiet, no catch-up to the tip |
| P1 absent references | row-only refs could not encode certificates to unadmitted delegates or readmissions naming unheld removals | CONFIRMED | `governance/cert.rs:189` (any valid key); `member_fold.rs:60-108` (unavailable removal → inert) | `ref` = `[0,row]` | `[1,id]`; inert facts kept and compared; encoding cannot fail; no fence blocked |
| P1 SessionFloor | "floor fields ≤ 16" could not rebuild the gate | CONFIRMED | `session_floor.rs:13-22`; `floor_index.rs:436,472,494,549,715-716,730` | the six consumed fields with the two justified implicit ones; 50–90 B; reconstruction traced |
| P1 frontier ordering | `control_through ≥ closed_through` is false under the header-only package rule | CONFIRMED | r12 1239–1242 with SY-25 | the clocks are independent; no reading of their difference; no body prerequisite, no coverage gate |
| 82b | SY-29 to state the two-lane rule as the siblings do; where inbound admission goes | — | `pending_text.rs:278-292` (`reserve_pending_write`), cycle 5a's 536/612 | SY-29 restated (two FIFO lanes, alternation, one transaction per turn, child in parent's turn, standing, row 74); inbound admission an authored-lane item, ≤ 1 per flow, never the pending-write place; served reads take no turn |
| 5a design gap | the slow member's coverage a quarter of the room's; above-fence `pre_context` wait | CONFIRMED (prototype measurement) | `arm-replace.md` r5a-B3sp-arm | **SY-30**: whole-chunk intake, nothing per entry waits, Content rendered in the admission transaction, direct prerequisite fetch for governance; the bound (one chunk + one round trip per author); measured status fields; the prototype's-shape mutant; cycle 5b's ordered list |

### Twelfth review (answered in revision 14)

The twelfth review (`adr-046-sol-review-12.md`): closed the partial projection, refs
without rows, SessionFloor, the frontier ordering; confirmed SY-29's two-lane mechanism against
NW-3 r13, RD-10 r16, TC-4 r11 and in-transaction rendering under rule 2 and row 74. Two P1. Its
P2s (82c's "one control transaction per authored write" wording, own posts out of the control
introduction, the body/key/cut staging cases, the half-step mutant's observable, byte counts) are
owed to the task (`v0431-owed-p2.md`) under row 83 and not edited here; Main applied row
82c's head-of-lane wording to SY-29's bound sentence directly.

| # | Finding | Classification | Evidence read at v0.4.30 | Answered by |
|---|---|---|---|---|
| P1 invalid context across the baseline | the context-invalid status lived in the local index only; the resolver made any unlisted pre-fence header terminal; a newcomer installing the baseline lost the distinction and E naming the settled U escaped the cover requirement | CONFIRMED | `log/entry.rs:248,393` (`pre_context` is a context-list digest), `sparse.rs:456` (`history_context`), `authority.rs:207-237` (causal scope) | SY-27 point 3 **table (d)**: every context-invalid control-kind entry below the fences with its `exposed` frontier, under the creator's signature; `settled_through` covers carriers; the baseline's causal scope = E's covered frontier; resolver branches 2a (listed: cover `exposed`) and 2b (unlisted = certified valid: cover the declared context fetched as one list by digest) — one header and one list, no walk; the fourth order of the hidden-certificate act (U below the fence, newcomer installs, B submits E) with the ignore-(d) mutant |
| P1 SY-30's guarantees | 128 entries per exchange, one authored turn, bounded lag "otherwise", depth-only latency were not what the pipeline establishes | CONFIRMED | SY-12 (1 MiB per answer, 16 MiB body continuation); SY-29's alternation | the byte- and entry-limited, queue-aware pipeline and its progress guarantee; lag bounded only under measured capacity and supplier availability, otherwise reported as growing, no fixed promise (rows 80/81); transfer volume and exchanges in governance latency; status fields kept with `bytes_per_s` and `trend`; B3 decisive; "rendered on commit" admits incomplete bodies, missing keys, undecided eligibility through the existing nonblocking paths; rendering never marks a header context-valid |

### Thirteenth review (answered in revision 15)

The thirteenth review (inline, persisted by Main): SY-30's throughput P1 closed; the baseline
cover partly closed; the two-lane mechanism and next-request-on-commit pipeline confirmed; creator
certification of table (d) confirmed as the accepted pre-fence trust cost for a fresh newcomer.
Three P1. Its P2s (say plainly that (d) is trusted, not proved, to a fresh newcomer; extend the
baseline act to a listed governance entry and to a behind member's adoption; the earlier byte-count,
half-step and authored-bound wording) are owed to the task under row 83 and not edited here.

| # | Finding | Classification | Evidence read at v0.4.30 | Answered by |
|---|---|---|---|---|
| P1 undecided eligibility | r14 rendered provisionally when the reader's own cut was undecided | CONFIRMED | `channel.rs:8130-8153`: undecided → body kept unrendered, `queue_backfill`, `Deferred`; SY-25 | SY-30: committed and retained unrendered, parked on the governance refresh, re-evaluated at the fold's completion event, no second delivery, no blocking of later intake; author-membership display (ADR-037 R3) kept separate from the reader's entitlement |
| P1 cover before every fast path | a context-invalid governance entry listed in (b) returned from step 1 before 2a/2b | CONFIRMED | r14 1317–1318, 1335–1342 | resolver step 0: context validity and the exposed (or declared) frontier are resolved for every control-kind coordinate below the fence before any return, and the cover requirement attaches to the namer whichever branch returns |
| P1 COMPARE and table (d) | a behind member that proved U context-invalid could adopt a summary omitting U from (d) | CONFIRMED | row 76; r14 599–602, 933–969 | COMPARE step 6: M's context column and exposed frontiers (carriers included) for every entry M closed at or below the fence (r16: contiguous and sparse alike; r15's "below `closed_through`" was wrong), checked against (d)'s assertions and absences; distinct from member rows and from uncompared dispositions |

### Fourteenth review (answered in revision 16)

The fourteenth review (`adr-046-sol-review-14.md`): the undecided-eligibility and
cover-before-fast-path P1s closed; build items 1–5 ready as a prototype contract. One P1.

| # | Finding | Classification | Evidence read | Answered by |
|---|---|---|---|---|
| P1 COMPARE step 6's domain | r15 compared (d) only below `closed_through(A)`, so a sparse entry M had independently closed above its contiguous frontier but below the fence — U proved context-invalid — escaped, and a checkpoint hiding C2 in U's `exposed` could be adopted | CONFIRMED | r15 970–977; row 76 | step 6 compares every locally closed entry at or below the fence, contiguous and sparse alike; a (d) row is ignored only where M lacks independent evidence at that coordinate; no completeness demanded for unknown sparse positions; the review-record row corrected; the sparse-contradiction order added to the adoption act with the compare-only-up-to-`closed_through` mutant |

## Links

- Plan A (`plan-A.md`), the trial (`trial-sync-progress.md`), the prototype report
  (`proto-range-sync.md`, PARTLY), the deciding round's final reports
  (`arm-repair.md`, fails B3 on one assertion, traced; `arm-replace.md`, fails B3
  on one assertion, traced), the scheduler-stall root cause (`rca-RcaSchedStall.md`,
  receipts `/tmp/RcaSchedStall/receipts/`†), the reviews (`adr-046-sol-review.md`,
  `adr-046-sol-review-2.md`, `adr-046-sol-review-3.md`), the ledger
  (`adr-cross-changes.md`), this ADR's revision record (`adr-046-revision.md`).
- Receipts († = lost in the reboot of 2026-11-13; the figure stands as recorded in the named report; to be re-run as the fleet baseline, ledger row 64; new receipts under `/opt/vox-evidence/v0431/<agent>/<run>/`): `/tmp/arm-repair/runs/`†, `/tmp/arm-replace/runs/`†, `/tmp/plan-sync/runs/`†,
  `/tmp/trial-sync/runs/`†, `/tmp/proto-range/runs/`†, `/tmp/rca-RcaFrozen/runs/`†,
  `/tmp/rca-RcaWedge/runs/`†, `/tmp/rca-RcaSlow/r1/runs/`†, `/tmp/rca-IoDrill/`†,
  `/private/tmp/vox-rca/io/`†, `/private/tmp/vox-rca/mac/stall-robert-work-021627Z.json`†.
- ADR-005 J-18; ADR-006 S-16; ADR-007 G-22–G-22d, G-29–G-31; ADR-008 LS-8, LS-27–LS-29, LS-33,
  LS-34; ADR-018; ADR-023 RL-2.5, RL-4, RL-8.4–RL-8.5; ADR-025 D1.1, D1.5, D5, D6; ADR-036 H-1,
  H-3, H-4, H-6, H-7, H-8; ADR-037 R1, R2, R3, R5, R7, R8, R10, R11, R13.
- v0.4.31 lanes: ADR-040, ADR-041, ADR-042, ADR-043, ADR-044, ADR-045, ADR-047, ADR-048, ADR-049,
  ADR-050.

## Questions for the decider: the answers recorded

Of revision 2's six questions all are now answered by the decider's rulings of 2026-11-13 and
are recorded here, not asked again: Q1 (row 57, below), Q2 (row 38; and row 63, SY-27), Q3 (row
39: 1,000 entries a minute is the floor the gate proves, raised to what the mechanism measures,
no artificial rate limit; SY-5), Q4 (row 18: all machines move together, no mixed-version sync;
Cost), Q5 (row 40: every member keeps each key package's sealed body; members only, no
store-and-forward role for a non-member anchor; SY-14, SY-17, amendment 3), Q6 (row 52: the
fleet is the release gate and reviewers run it; rows 51 and 59: the in-tree full-disk journey
is optional, the fleet's full-disk journey J5 and the stall staging FG-20 block; SY-23, SY-24).
The third review's "retain a non-answering member's admission veto?" is answered by row 37: no
(SY-10, amendments 22–24). Q7 and Q8 are answered (rows 65 and 68, below).

**Q1, recorded (plan A's D-1). Replace the fetch mechanism (R2), or repair it (R1)?** The decider,
2026-11-13 morning (ledger row 57): **the replacement**, "add the two missing parts, then measure
your room's shape again before anything else is built on it". The numbers he decided on, from
the deciding round's final reports (`arm-repair.md`, `arm-replace.md`; corrected
reader only; each arm against its own v0.4.30 baseline in its own session):

| case | v0.4.30 (repair session / replace session) | repair arm (not chosen) | replace arm (chosen) |
|---|---|---|---|
| B1: every member's hello | 54.2 s / 80.6 s | 10.5 s | 8.5 s |
| B1: governance ≥ members / doctor all ok | 31.2 / 38.2 s; unknown / 46.5 s (`arm-replace.md` records no governance timing for its baseline; 26.8 s was the prototype session's) | 6.5 / 14.5 s | — / 6.5 s |
| B1: proof-like rows written on the newcomer | 21,794 / 24,200 | 15,001 (its no-rows change built after, unmeasured) | 0 (every node, every run) |
| B1: store written per admitted entry | 469 KB / 236 KB | 226 KB | 47 KB |
| B3 duty cycle: the newcomer's join | fails 6.4 s / 6.6 s (item 88) | 5.9–6.4 s; 2 of 6, then 5 of 6 earlier joiners still fail | 5.0 s; one earlier join failed once, repeated clean |
| B3 duty cycle: hellos rendered (corrected reader) | not measurable | session 2: n-old1 4.0 s; y1 and z1 never; 26 entries admitted (session 1, uncorrected reader: earlier joiners 10–14 s, z1 272 s, unmeasured) | 7 of 8 at 46.5 s; both fast heavy authors live at 43.5 s; y1 never |
| B3 duty cycle: governance / doctor | — | session 2: never / y1 and z1 "has not trusted you" | — / doctor ok for 7; y1 "has not trusted you" |
| B3 slow path (FG-5): hellos rendered (corrected reader) | n-old2..6 at 213–279 s; n-old1 and heavy authors never / 5 quiet joiners at 40–241 s; heavy authors never | **unmeasured** (session 1 only, uncorrected reader: earlier joiners 17–23 s; governance never) | 7 of 8 at 72–93 s; both fast heavy authors live at 82.2 s; y1 never |
| B3: members read the newcomer | never / never | session 2: z1 and n-old1 0.9 s, y1 never | n-old1 and z1 2.5–6.2 s; y1 not observed |
| B3: proof-like rows | 2,561 / 5,134 | 2,018–18,570-class | 0 |
| restart mid catch-up | — | not run | nothing lost; every hello 15.2 s after |

Neither arm passed B3 as SY-4 states it. *Repair* (session 2, the only corrected-reader run):
the slow heavy author's and z1's posts never rendered and 5 of 6 earlier joiners failed to join
(its control coverage was keyed to the exact head and walked from that author alone: 441 of
1,521 positions at 300 s); its own trace named the replacement's chain-keyed coverage as its next
step. *Replace*: 7 of 8 members rendered and trusted the newcomer and the slow heavy author's own
posts never did (one observed failed assertion; `control_current`, all-member reads in both
directions and all-six-joiner staging were not observed, so "only one" is not claimed), because that author itself never
became current: per-entry admission at 2.7 entries/s and 8 control headers per 1.5 s page against
6 entries/s of room traffic, 21 % of it `ContextUpdate`. Those two are "the two missing parts":
admission in one transaction per chunk (SY-13 rule 4; row 62, "chunks were the intent") and a
fold that never waits on a `ContextUpdate` (SY-3). They are built (commits b247b598d, 205b7000e,
5b1bdadb5) and the re-measurement is step 0 of the implementation order; its results land in
SY-27 and here (revision 7). The receipts of both reports are lost to the reboot of 2026-11-13†;
the figures stand as recorded in them.

**Q7, recorded. What does a newcomer verify itself before it has access, and what does it take
from the creator's word?** The decider, 2026-11-13 (ledger rows 65 and 68): **B, the fence
post**, kept on the corrected cost statement the fifth review verified, in these words: a
newcomer trusts the creator's signed summary of everything before the fence (members, and who
was removed and readmitted); a false summary could make a member that started from it hand old
encrypted messages to someone the real history forbids (handing over is not reading: the key is
still needed); the creator cannot forge another identity; full-record members reject a summary
they can prove wrong, which protects them and not a newcomer who gets the summary elsewhere.
SY-27 point 3 states it in the design's terms.

**Q8, recorded. While the creator makes no fence posts, is catch-up that grows with the messages
posted since the last fence accepted?** The decider, 2026-11-13 (row 68): **yes, for v0.4.31**,
and the 30 s access promise is **qualified** by it: with a current fence post, access within
30 s of `joined`; with the creator away, catch-up grows with the entries posted since the last
fence post (an estimated 0.8 MB per thousand entries, unmeasured; SY-27 slot (e) measures it),
status shows the fence post's age, SY-27 point 3 discloses the growth, and nobody else signs.
This is no longer a decider question (X045-2: ADR-045 J1(m5) is qualified the same way). He did not choose the proof change that
skips context entries, nor a second signer; both are recorded under SY-27 point 3 as
alternatives not taken. What this ADR specifies under his answer: the cadence at which the
creator signs (SY-27 point 3), what status prints (the fence's age and position and the
estimated catch-up since), and the measurement slot for the growth (ADR-045 J1(m)).

**Q9 (r12), held — not yet put to the decider.** The one-answer 1 MiB limit is Main's ruling
(ledger row 77), not the decider's; the decider was told "rooms of about 450 members in this
release" in a progress note. SY-27 point 3's summary, with the comparison-record table and the
member state the adoption rule and the fold need, encodes (CBOR, from the schema) to 2,062 B a
member plus 42–110 B for every governance-kind entry the room ever had; under the limit that is
489 members with nothing but their grants, or 272 with the worked example's two-year history per
member. These counts are computed, not measured, and go to the decider **only after the reviewer
has verified them**; until then he is told the two sentences the reviewer wrote: *Keep the
one-answer 1 MiB limit; when a new summary does not fit, members use the last usable fence post,
or verify from the start if none exists. The room remains usable but catch-up can be slower, and
the proposed member-count estimates need recalculation from the complete encoded format.* The
choice, when asked: **does the 1 MiB limit stand for v0.4.31 with the verified figures?**
Recommendation: **yes** — no room we have is within a tenth of it, the fallback is v0.4.30's
behaviour, and a larger single answer would need the assembly he told us not to build.
