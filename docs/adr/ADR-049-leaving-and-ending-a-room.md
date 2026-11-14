# ADR-049: Leaving and Ending a Room

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted (2026-11-13) as the design for v0.4.31, under the decider's authorization
of 2026-11-13 ("post review can accept them too"), after GPT-6.1-Sol's independent re-check of
revision 14 passed it (`adr-049-sol-review-13`); proposed 2026-11-12. Nothing here is built. Split from ADR-040 revision 2: this
ADR takes over NW-6 (a left room is gone and never reopened), NW-7 (an ended or left room is
always deleted; no sync alarm for an ended room), NW-15 (a person can always leave) and Q6,
which ADR-040 revision 3 lists under "Moved requirements". Those ids are not reused; the
requirements here are `LE-`. **This is revision 14**: revision 2 resolved the first independent
review (`adr-049-sol-review`, F1–F10), applied the decider's answer to Q6 (option B, ledger row
34) and his added requirement on rejoining (LE-9), and applied ledger rows 22, 27, 32, 35 and
37; revision 3 resolved the second review (`adr-049-sol-review-2`, N1–N6); revision 4 applied
rows 58 (the hidden copy is kept at most **2 days**) and 61 (Q7: option B) and noted row 64
(receipts under `/tmp` lost in the reboot); revision 5 resolved the third review
(`adr-049-sol-review-3`, R1–R6) and folded in row 65 (the fence post); revision 6 resolved the
fourth review (`adr-049-sol-review-4`, S1–S5) and recorded which rule for a returning node's
own feed was chosen over the alternatives and why; revision 7 resolved the fifth review
(`adr-049-sol-review-5`, T1–T2), met its conditions on that rule, settled the cross-asks
X049-5, X049-6, X049-8 and X049-11, and quoted every amended sentence whole at `d9a8667ba`;
revision 8 resolved the sixth review (`adr-049-sol-review-6`, U1–U4) by deriving the
publication and withdrawal rules from one table of facts, owners and crash points (LE-2),
closed the remaining cross-asks aimed at this ADR, stated the storage contract of a leave in
one place for ADR-047 and marked every `/tmp` receipt citation as lost (row 64); revision 9
resolved the seventh review (`adr-049-sol-review-7`, V1–V4) by correcting four rows of that
table; revision 10 resolves the eighth review (`adr-049-sol-review-8`, R9-1, R9-2, "Review
record"): LE-5's completion now reads the same route set the table selects by scope, and B (8b)
stages the cleanup window that exists. Requirements changed in revision 7 are marked
**(changed r7: …)**, in revision 8 **(r8)** or **(changed r8: …)**, in revision 9 **(r9)**, in
revision 10 **(r10)** or **(changed r10: …)**; revision 11 resolved the ninth review
(`adr-049-sol-review-9`, R10-1, "Review record"): a staging gate never classifies its own
mutant's outcome as APPARATUS, in B (8b) and, by the same sweep, B (5b), B (7) and B (8);
marked **(r11)**; revision 12 resolves the task cut of revision 11
(`v0431-tasks-ADR-049`, defects D1–D11, "Review record"): every structure named from the tag
is marked R1 (interim) or R2 (ADR-046's replacement, ledger row 57) and the receipt, LE-4's
first two steps and the staging of A (b) and B (2) are stated for both; the wrap-bytes
assertion follows `vox node compact`; LE-5's completion is asserted on `.withdrawals[]`; B (4)
uses the computer-policy hold that exists; the app proof is `FirstRunProof.swift`; every act
has a mutant; every `/tmp` receipt is marked lost; the daemon log lines the acts read are
requirements, stated under "ADR-042 TR-2, TR-8, Appendix A"; the status fields the acts read
are paste rows for ADR-042 Appendix A, with ADR-047 SO-15's `store.free_disk_bytes` and
`store.floor_bytes`; A (b), (c), (m) move to `a_sync_failure_names_its_reason_proof.rs` once
SY-24's disk staging lands; and act A (a′) proves ADR-042 TR-16's sentence; marked **(r12)**;
revision 13 resolves the tenth independent review (`adr-049-sol-review-11`, R12-1–R12-8,
"Review record"): the receipt under the replacement sync is a member's inventory row naming
the departure head's HeadID, `control_through` and `held` through the departure — never a
`Head` answer, never an entry hash compared with a HeadID; B (4) holds the native policy save
inside its worker after `pending_policy` is installed and asserts the replacement's resource
book; the acts A (a-i), A (a-ii), A (a′), B (1b) and B (6) stage the branch their mutants
change and read fields and lines that are owned; marked **(r13)**; revision 14 resolves the
eleventh independent review (`adr-049-sol-review-12`, R13-1–R13-5, "Review record"): a hidden
room may issue the closure prerequisites and discovery its control entries need (witnessed
Content headers without bodies included), never an ordinary post's body; a false `Have` raises
head discovery and no fork; A (a-i) keeps one mutant, A (a-ii) makes every other conjunct
true, B (6) stages cancellable own-feed demand and an End after an unseen Content entry, and
A (a′) binds n to the observed own-feed head; marked **(r14)**; earlier marks are kept.
**Date**: 2026-11-12
**Deciders**: Robert E. Lee
**Tags**: rooms, leave, end, rejoin, departure, withdrawal, erasure, sync, status
**Related**: ADR-005, ADR-007, ADR-012, ADR-018, ADR-023 (RL-8), ADR-025, ADR-034 (HL-2, SR-1),
ADR-037, ADR-038, ADR-040, ADR-041, ADR-042, ADR-045, ADR-046, ADR-047, ADR-048, ADR-050
**Inputs**: fix-list items 10, 27 (the leave side), 64, 85–87; the two reviews of ADR-040
(`adr-040-sol-review` finding 7; `adr-040-sol-review-2` F5–F8, F11, F12, F14–F16 and "Ended/left
rooms, security duties and Q6"); `adr-049-sol-review`; `rca-RcaSchedStall`, `rca-RcaFrozen`,
`io-repair-drill` (item 10); the experiments E-64, E-64b, E-86, E-86b of ADR-040 r2
(`/tmp/adr040/`) and E-49a of this ADR (`/tmp/Adr049Leave/`), both lost in the reboot of 2026-11-13 (row 64; figures as recorded in their notes); the cross-ADR ledger rows 10, 22,
27, 32, 34, 35, 37, 38. Code is cited at tag `v0.4.30` (`8d71ab337`); paths under
`crates/vox-core/src/node/` unless said otherwise.

**The rulings this ADR serves** (the decider):

- 2026-11-12, on a member unable to leave a room its creator had ended (the app: "An internal
  error — a bug in vox, not something you did"): "people should be able to leave a room that
  has already been ended".
- 2026-11-13 (ledger row 34, amended by row 58): when a node leaves a room, its copy is kept
  hidden only until one member has verified the leaving, **2 days** at most (row 58; row 34
  said 7), then erased (option B).
- 2026-11-13 (row 61), Q7: option B. A left or ended room's rows and key are deleted at once;
  the freed pages are reused and cleared at the next store rewrite; no whole-file rewrite at a
  leave or an end.
- 2026-11-13 (row 34), added: "we need to support an instance where a node leaves a room, and
  later comes back -- it should feel like they're freshly joining at that point though".

## Context

### What the operator saw

- **Item 64.** The creator ended `repo-to-cve` on robert-work (2026-11-13 00:50Z). On his own
  node the cleanup stopped: `ended room cleanup stopped: history retirement requires recovery`,
  every lifecycle tick, for hours. The room stayed in the app's list with no "ended" marker and
  raised `sync failing … authenticator invalid` against members that had already deleted it.
- **Item 86.** On Vince's Mac, node vovando still listed `repo-to-cve` two hours after its end.
  That node was stalled by a separate defect (item 85, `rca-RcaSchedStall`), so the end never
  arrived. Leave in the app failed: "An internal error — a bug in vox, not something you did;
  the node's log has the detail". The log had no detail.
- **Item 27.** A room this identity had left stayed `[failed: node: this identity has left the
  room]` for ever and failed at every start and every trust change (`rca-RcaFrozen`, rig26
  +34 s).
- **Item 10.** After `vox room leave` and a rejoin with a fresh link, the node's posts were
  refused for about six minutes: `this node's record of its own history in this room is behind
  what a member holds … it writes nothing here until that is resolved`; `vox status` said
  `UNHEALTHY: own history recovery is pending; writes remain fenced` (`io-repair-drill` run A,
  `/tmp/rca-IoDrill/runA/rig.log:275`, rc 1 at +214 s; run C, about 6 min; release asset;
  receipt lost in the reboot of 2026-11-13, figures as recorded in `io-repair-drill.md`;
  to be re-run as the fleet baseline). The
  decider's answer: a rejoin is to feel like a fresh join.

### What is wrong at v0.4.30 (KNOWN, reproduced on the release binary)

E-49a (`/tmp/Adr049Leave/run.log`, release asset `vox 0.4.30`; receipt lost in the reboot of 2026-11-13, row 64, figures as recorded in `adr-049-revision.md`): node A's data on a 64 MiB
image, filled for 90 s while member B posts (RcaSchedStall's staging), then freed. A holds seven
flows in `retirement_failed`. **Act 1**: `vox room leave room1` on A → rc 1, `room "room1" … was
not left: an internal error — a bug in vox, not something you did; the node's log has the
detail`; the room is still listed; A's log has no line for it. **Act 3** (control): healthy B
leaves `room2` → rc 0, gone at the next list. **Act 5**: after a node restart (`vox node
rename`, which clears the pinned flows) A's leave of the same room → rc 0. RcaSchedStall's
control (iii) is item 64 from the same state: a stalled A ending a room logs `ended room cleanup
stopped` 737 times (`/tmp/RcaSchedStall/receipts/A.daemon.err:2004`; receipt lost in the reboot of 2026-11-13, row 64, figures as recorded in `rca-RcaSchedStall.md`) and keeps the room listed.
(E-49a's act 2 is not that reproduction: A's end was refused while still unable to save; its
act 4 is a healthy leave of an ordinary room, not of an ended one.)

The leave has twelve ways to fail, and the app shows all but one as an internal error:

| Where | Refusal | Site |
|---|---|---|
| `begin_own_key_leave` | a leave already pending; no network; no computer authority; locked | `actor.rs:21641-21670` |
| the room's flow retirement | a flow in `retirement_failed` → `history retirement requires recovery` → `fault_of` has no arm for it → `Fault::Internal` | `actor.rs:21690-21692`, `bounded_sync.rs:832-843`, `leave_save.rs:1338-1354` |
| the publication lease | `ComputerPolicy` while a revision moves | `actor.rs:21700` |
| `begin_leave` | room not open; no network; no authority; locked | `leave_save.rs:377-430` |
| the departure's admission | legacy index not current; marked unable to save; not settled (`RoomNotSynced`); own history behind; not an author | `pending_text/leave.rs:57-59`, `channel.rs:6464-6488` |
| `begin_leave_metadata` | a policy save in flight → `RoomChangePending` | `leave_save.rs:549-551` |
| `begin_owned_purge` | a policy save in flight; Session cleanup busy; Session cleanup unavailable; no identity | `leave_save.rs:729-774` |

Which of these fired on vovando is UNKNOWN (its log is not in hand); E-49a shows the retirement
one on the release asset, and `rca-RcaSchedStall` shows vovando's state produces exactly it.

Facts the design rests on, each read at the tag:

- A departure is heard only by a **positive echo of the departure head**. At the tag (ADR-046's
  R1, which the decider's choice of the replacement, ledger row 57, retires): a bounded
  departure-receipt round completes only when the peer's reply names this author's own feed at
  the departure's sequence and hash with `here = false` (`channel/sparse_history.rs:779-803`,
  `history_stream/runtime.rs:3056-3066`, `actor.rs:13490-13497`); a clean legacy session that
  sent this node's HAVE at or above the departure's generation counts likewise
  (`actor.rs:13642`). A stale or absent echo is `Unreachable("peer has not acknowledged the
  current departure head")` and the port retries on its backoff (`ports.rs:262-284`). Under
  the replacement (ADR-046 SY-12) two identities are kept apart *(r13: R12-2)*: the
  **departure entry** is `(seq d, entry hash e)` (`Entry::entry_hash`); the **departure head**
  is this node's own signed head of size d, whose root commits leaf d = e, identified by
  `SignedHead::id()` — a hash of the head's canonical body under the `LogHead` domain
  (`log/history.rs:882-920`), never equal to e. A member's `Have` row (SY-12) names a `size`,
  a `head` (that HeadID), `control_through` and `held` body intervals; none of them is an entry
  hash. The receipt is defined from that row (Terms). A peer's refusal is never a receipt under
  either. The structures this ADR names from the tag
- A `Presence(false)` body carries room, epoch, author, `here` and chain id, and no feed
  position (`crates/vox-core/src/governance/presence.rs:19-60`); its order comes from the log
  entry that contains it (`channel/governance/channel.rs:25-49`). A member behind the leaver's
  last entries can only take the departure from a node that still serves that prefix. That is
  why the copy is kept hidden until a receipt (Q6, option B).
- The board withdrawal has a durable owner outside the room: the journal
  `pending-board-withdrawals`, one map value for every room (`actor.rs:6137-6160`;
  `MAX_PENDING_WITHDRAWALS = 4096`, refused above it), written at the leave
  (`leave_save.rs:228-258`, scope `Member`) and at an end (`metadata_save.rs:2432-2447`, scope
  `Room`, **the same map slot**), released in the purge's transaction (`:321-336`) and put to
  boards by a spawned task that reports nothing back (`actor.rs:22072-22110`). Each wire holds
  a 3,373-byte composite signature (`crates/vox-core/src/hash.rs:52-54`).
- A sparse room settles, and an own-behind room recovers, by a signed rotation entry
  (`Presence(here: true)` with a new sender generation): `Work::Settle` →
  `prepare_recovery_append(Rotate { here: true, settle: true })`
  (`channel/pending_recovery.rs:391-431`); `Work::Complete` likewise (`:435-485`); only that
  rotation clears `own_behind` (`:1067-1077`). ADR-046 SY-11 makes own-feed recovery the first
  fetch after a rejoin and SY-17 carries the joiner's own-feed range in the join answer.

## Terms

- **Leave record**: the durable per-room entry `left-rooms/<room>` in the node store (LE-2). Its
  existence is what makes a room *left*. It is written in the same transaction as the room's
  board withdrawal entry `pending-board-withdrawal/<room>/<scope>`.
- **Left room**: a room whose leave record exists. For the person it is gone. The node holds it
  **hidden** only to serve members, until it is **erased**.
- **Hidden**: not listed, not read, not posted to, no notifications, no attention items, no
  services or reachers offered, no Session traffic, no sync alarm; serving members its public
  history and its own departure head, and issuing only the requests LE-2 step 3 and LE-3 name
  (ADR-023 RL-8.1a's hidden room).
- **Departure**: the signed `Presence(false)` entry at the tail of this author's own feed.
- **Receipt**: a member's statement, over its authenticated member connection, that it has
  taken and verified the departure *(changed r13: R12-1, R12-2)*. Under the replacement sync
  (ADR-046 R2) it is the member's inventory row for this author (its `Have`, SY-12; what SY-18
  keeps per member as `held_through`) that names **all three**: `size` = d and `head` = the
  departure head's HeadID (so the member accepted this node's own signed head at d, SY-13 rule
  3, and no other head at that size); `control_through` ≥ d (it holds every control entry of
  this author through d under a control proof — the departure is one); and `held` covering d
  (the body is held: it admitted the entry, SY-13 rule 4, and verified the body's hash; d is
  the tail, so it lies in the highest interval listed when it is held at all; should the
  listed intervals stop short of d while `intervals_total` exceeds them, one `Probe(me, d, d)`
  answered `Held` stands for this clause and for nothing else). A
  `Have` naming `size` = d with a HeadID this node did not sign is no receipt *(changed r14:
  R13-2)*: it raises SY-14's ordinary head discovery (one `Head(me, bridge)` toward that
  member, N8) and nothing else, and the answer is judged by SY-13 alone: this node's genuine
  signed head at d, or an earlier consistent one, is accepted or already known, freezes
  nothing and is no fork evidence — the only false statement was the member's unsigned `Have`,
  and the advertisement is then unsupported for that peer (SY-14, N7); fork evidence is
  recorded only when the returned author-signed object fails SY-13 rule 2's contradiction test
  against a held one. A `Have`
  naming the head without `held` covering d is the Head-only state (SY-13 rule 3): the member
  knows the head and cannot yet project the departure; no receipt. Nothing a `Head` answer
  carries is a receipt either: it reports the member's accepted head, not that it holds the
  entry. Under R1, the echo described above. What a receipt is evidence of *(scope stated r14)*:
  one member has admitted and hash-verified the departure's bytes and can serve them (it is in
  the member's `held` intervals, which it serves to others); it is **not** proof that the
  member has closed the departure (SY-3 rule 3's `CLOSE`) or folded it into its roster —
  "taken and verified" means held, servable bytes; a member that lies in its `Have` is a
  member that has the departure and withholds it, which no receipt rule can tell apart from
  one that is honest and then goes away.
- **Erasure**: the room's deletion from the node: every row and its key deleted (ADR-047 SO-9's
  batched deletion, with its cursor), the RL-8.4 continuity marker and the RL-8.2a note the only
  exceptions. The bytes the rows occupied are cleared at the store's next rewrite (Q7: B).
- **Deleting retirement** (R1 only; interim until ADR-046's cutover): `Retire::Deleting`, a mode
  of the room's flow retirement in which a flow whose cleanup failed is discarded with the room
  instead of keeping it. Under R2 nothing is retained after a round, so the erasure only cancels
  the room's in-flight exchanges (LE-4 step 1).
- **Wind-down**: the 60 s an ended room is held to pass the end on (RL-8.2; `WIND_DOWN`,
  `actor.rs:283`).
- **Continuity** (revision 5 called it the append checkpoint): the bounded, public material
  this author's own feed needs after its room rows are gone, kept in the RL-8.4 marker row:
  everything `prepare_own_append_ranges` (`own_history.rs:1518-1586`: the append forest and
  root context for head + 1, `Ranges { marker, binding, context, forest }`,
  `channel/pending_recovery.rs:63-68`) and `Entry::build_signed` (`pending_text.rs:1110-1121`:
  the entry hashes a later `prev_hash` or `lipmaa_backlink` can name, `log/feed.rs:59`) read of
  the feed at the signed head, with the epoch, the highest authored sender generation and the
  genesis the marker already holds; and the **carry**: the signed headers of this author's
  entries above the last member-confirmed position, with the public payload of each lifecycle
  entry among them (LE-2 step 2, LE-4 stage (c)). O(log n) plus the suffix's headers; no post
  body, no key. Authenticated because the node derived it from its own signed feed under the
  own-writer gate. It extends RL-8.4's marker (amended below).
- **Fresh join**: a join of a room this node left, as the person sees it: a fresh link, the
  room's anchors from the link, no rows older than the join shown, a post admitted at once
  (LE-9).
- **Named wait**: ADR-040 NW-1's `NotYet { prerequisite, seen }` parked in NW-3's registry.

## Requirements

Three guarantees, each on its own: what the person gets at once (LE-1); what is owed to others
afterwards and who delivers it (LE-2, LE-3); what is erased, when, and what that gives up
(LE-4, LE-5). Then the ended room (LE-6, LE-7), the proofs (LE-8) and the rejoin (LE-9).

### 1. What the person gets at once

- **LE-1. A leave succeeds at once, in every room state, and the room is gone for the person.**
  **(changed: F3, F7, F8, F9.)** `vox room leave` and the app's Leave MUST answer success on an
  unlocked node for every room the node holds, whatever the room's state: ended and known
  ended; ended but not yet learned; sync stalled; a flow retirement failed; marked unable to
  save; still preparing or not yet settled; own history behind; a trust debt outstanding
  (ADR-048, per room: row 35); a policy revision moving; peers unreachable, or having deleted
  it; no network. The answer MUST follow one durable transaction, the leave record (LE-2 step
  1), and nothing else. From that answer the room is hidden: not in `vox room list` or the app's
  list; a read or post is refused as `RoomLeft` ("you left this room", unchanged); it raises no
  `sync failing` and no other alarm; it is in no trust pass (ADR-048) and no startup trust
  stage; `vox status` prints ADR-042 TR-8's one line, `leaving <room>: no member has been told
  yet; told when one is reached`, **until a member's receipt** (LE-3), and nothing of the room
  after that except LE-4's two-day line.

  *The answer carries the outcome.* The daemon answers `Request::Leave` with
  `Frame::Left(LeaveOutcome { already_left, known_ended, departure })`, `departure` one of
  `Signed`, `Pending(<prerequisite words>)` or `None(<reason>)`, taken from the record it just
  wrote (a control-protocol change counted in ADR-041 RS-12's one bump). The CLI and the app
  print from it, not from a room list read before the command (which races with an end):
  - `Signed` or `Pending`: `vox: left <which>; it is gone for you now; this node keeps a hidden
    copy for at most 2 days, only to tell its members you left, then deletes it` *(changed r5:
    R3)*; with `Pending` a second line, `     its departure is signed once <prerequisite
    words>; until then members list you`;
  - `known_ended`: `vox: left <which>, which had ended; it is deleted once its end has been
    passed on` (LE-7);
  - `None(reason)`: `vox: left <which>; its members cannot be told from here (<reason>): they
    keep listing you until one of them learns otherwise`;
  - `already_left`: `vox: you had already left <which>`, rc 0, nothing changed.
  Before the command acts, ADR-042 TR-16's sentence when the node holds entries of the person's
  that no member has confirmed (`--yes` required when `k > 0`; the words are ADR-042's).

  *The only failures left.* (i) The node is locked: ADR-041's Locked words, with `vox node
  unlock <node>`. (ii) The node store cannot write the leave record: an operating-system write
  error, or ADR-047 SO-11's admission refusal (the record is a reclamation-class batch, LE-2
  step 1; below SO-11's 3 MB it is refused before the operating system would): `vox: <which> was
  not left: this node could not record it (<os error | the disk holding <dir> has <m> MB free;
  3 MB are needed>); nothing has changed; free some space and leave it again`. The room is
  preserved; no leave is claimed. (iii) The room is not held: unchanged (`UnknownChannel`). No
  other refusal exists; in particular `RoomChangePending`, `NotNetworked`, `ComputerPolicy`,
  `ChannelNotOpen`, `RoomNotSynced`, `OwnHistoryBehind`, `SizeLimitExceeded("pending board
  withdrawals")`, the retirement failure and the publication-lifetime failure are no longer
  leave outcomes, and no leave path MAY answer `Fault::Internal`.
  - *Why*: the ruling; items 27, 86; E-49a act 1; second review F8 (a leave that promised
    success in a full-disk state could not write its own record); review F3/F7 (the record's
    write is sized and admitted, not assumed), F9 (the CLI prints `Frame::Ok` unconditionally,
    `crates/vox-tui/src/room_cli.rs:7363-7371`: the outcome must cross the reply).
  - *Changes*: `begin_own_key_leave` (`actor.rs:21641`) becomes: write the record, answer with
    the outcome, then LE-2's steps; `leave_save.rs:377-430` and `pending_text/leave.rs:33-72`
    lose every refusal (the departure's admission moves to LE-2 step 3, where a refusal parks
    instead of failing); `Frame::Left`; `room_cli.rs:7330-7382` and the app's Leave print per
    outcome.
  - *Deleted*: the refusals listed; `LeaveWaiter`'s dependence on a reply.
  - *Proof*: LE-8 journey A.

### 2. What is owed to others, and who delivers it

- **LE-2. The leave record is written first and owns everything the leave still owes.**
  **(changed: F1, F2, F4, F6, F7, F8.)** The record is `left-rooms/<room>` in the node store:

  ```
  LeftRoom {
    instance,                       // the room attachment this record hides (r3: N2)
    name, departure_ms,
    departure:  Pending(prerequisite) | Signed { seq, entry_hash, head_id } | None(reason),  // r13: R12-2
    outcome:    Undelivered | Delivered { peer, ms } | Expired { ms } | Ended,
    erasure:    Hidden | Erasing { stage, cursor } | Erased,   // stages: LE-4 step 4 (r5: R5)
    // r7–r10: no route field (T1, U1–U3, V1): the routes are the publication rows the wire's scope selects (LE-2's W2m/W2r)
    rejoin:     None | Preparing { link_hash, since_ms } | Accepted { since_ms },  // r3: N2
  }
  ```
  The continuity (the append material and the carry) lives in the RL-8.4 continuity marker
  row, not here *(changed r5: R2)*: it outlives this record (LE-5).

  The board withdrawal keeps its own journal, re-keyed per room, scope **and wire**:
  `pending-board-withdrawal/<room>/<Member|Room>/<wire_hash>` → `{ wire, instance,
  awaiting_departure, state }`; its routes are not copied: they are the publication rows its
  scope selects (W2m: its instance's; W2r: every retained row of the room; the table below),
  and its completion is one answer row per board of that set (LE-5).
  Re-keying removes the whole-map write (`pending_withdrawals_bytes`, `actor.rs:6153-6183`:
  every entry re-serialized at every change, 3.4 KB each; addresses as text, `:6171-6177`) and
  the 4,096-room cap, and lets an end's `Room` entry and a later leave's `Member` entry of the
  same room coexist: a leave MUST NOT replace or downgrade an outstanding room-scope
  withdrawal (F2). **Publication and withdrawal: the facts, their owners, and every crash
  point** *(changed r3: N4; r5: R5; r6: S3; r7: T1; **r8: U1, U2, U3**)*. Today the only record
  of where a room was published lives in actor memory (`on_board`, `publishing`,
  `board_routes`: empty at a start, `:6842-6847`, `:6879`, `:7495-7508`; the collector
  `actor.rs:21928-21976` reads them plus the configured anchors), and the route is noted in RAM
  before the send (`:9477-9490`), the puts go one by one (`:9532-9549`), the result is filed
  after (`:9600-9612`, `:12631-12747`), while the board has already changed its store before it
  answers (`nat/service.rs:1317-1324`). So a crash anywhere in a round loses the fact that a
  board may hold the room. The text below is derived from this table, not the other way round:

  | # | Fact | Durable owner (one) | Written when | Crash just after | What the next open does (and whether that can itself be interrupted) |
  |---|---|---|---|---|---|
  | P1 | "this node is about to put R's records to board B at these addresses" | `publications/<room>/<instance>/<board>` → `{ addrs (≤ 64, textual), state: attempted }` | by the publish path, **before the first put**; a failed write prevents the send | the round never ran, or ran partly: B holds nothing new, something, or everything | the row stays `attempted`: B is treated as possibly holding R and is withdrawable; the publish path retries the round under the same row as today (idempotent) |
  | P2 | B accepted one or more puts | B's store (`nat/service.rs:1317-1324`); nothing on this node until P3 | by B | B holds R; this node has only P1 | P1 covers it: `attempted` is withdrawable; no fact is lost (U1) |
  | P3 | the round's result (all taken, stale, refused, dead) | the same row, `state: published`, or `attempted` kept with the last failure | by the `PublishDone` handler, in a batch, before the RAM `on_board` is updated; dispatched only for the attachment it was started for (`metadata_save.rs:4224-4312`'s identity check) | whichever state committed is the state (V4): `published` if the batch committed, else `attempted` | nothing: both states are withdrawable; the next round refreshes it |
  | P4 | the row is no longer needed | the row is deleted, one row per batch | at open and after each W5c, for every row of R with no referencing withdrawal (W2m: its instance's `Member` wires; W2r: any `Room` wire of R) **and** the room not held under that instance | partial: some rows gone, the rest still satisfy the same predicate | the same rule runs again; idempotent per row |
  | W1a | the leave's intent, **before commit** | — | — | nothing happened: no leave was claimed, the room is as it was, P-rows untouched; a repeated leave starts afresh | — |
  | W1b | the leave's intent, **committed** (before or after the reply reached the person): wire, `LeftRoom`, `instance`, `frozen` on the instance's rows (W2m) or on every row of R (W2r) | `left-rooms/<room>` + `pending-board-withdrawal/<room>/<scope>/<wire_hash>` → `{ wire, instance, awaiting_departure, state: pending }` | LE-2 step 1, one reclamation batch | the record is durable; the person may not have seen the answer | the open reads `left-rooms/*` first, opens the room hidden and resumes LE-2 steps 2–3 (the crash-windows paragraph below); a repeated `vox room leave` answers `already_left` (V4) |
  | W2m | a **Member** wire's route set | **not a fact of its own**: its instance's P-rows (`attempted` or `published`) plus the configured anchors, frozen at W1b because a hidden room publishes nothing (LE-1) and a rejoin is a new instance (LE-9) | — | — | — |
  | W2r | a **Room** wire's route set (an end: LE-7) | **not a fact of its own**: **every** retained P-row of the room, under any instance (an older instance's board holds the room's genesis until a room-scope withdrawal reaches it, `nat/store.rs:413` onward; a member-scope one removes that member's records only, `:362-410`), plus the configured anchors, frozen at W1b | — | — | — (V1) |
  | W3 | the wire was put to board B and B answered (taken, or refused as its answer) | `withdrawal-answered/<room>/<scope>/<wire_hash>/<board>` | by the actor on `NetEvent::WithdrawAnswered { room, scope, board, wire_hash, taken }`, after the stale-callback check (the wire hash must be the entry's) | the put may be repeated; a board's second answer is idempotent (`nat/withdraw.rs:23-25`) | the put is tried again at the next connection to B (`actor.rs:12648`'s path) for every board in W2 without a W3 row |
  | W4 | the wire was put with no answer | nothing durable (a retry is owed, not a fact) | — | — | retried as W3 says |
  | W5a | the wire is **complete**: every board in its W2 has a W3 row | the entry's `state: complete` (one small write) | by the actor when the last W3 row is written, in the same batch as that row | the entry says `complete`; its W3 rows exist | resume W5b; no board is asked again (V3) |
  | W5b | the wire's W3 rows are gone | the rows, deleted in batches of at most 256 keys (SO-11's reclamation batch) | after W5a | some rows gone; the entry still says `complete` | resume W5b from whatever rows remain; idempotent |
  | W5c | the entry is gone | the entry row, deleted last | after W5b's last batch | — | an answer row with no entry is an orphan of a crash between W5b and W5c that cannot happen in this order, or of a product defect: deleted at open, one batch, logged once; P4 then runs |
  | E1 | the room's rows and key are erased (LE-4 stage (d)) | the room's own rows | LE-4 | LE-4's stages | **does not touch P-rows** (U2) |

  What follows from the table. The publication inventory is the publish path's, written before
  the send and keyed by the room's attachment instance (U1, U3); a withdrawal copies nothing: a
  `Member` wire references its instance's rows (W2m), a `Room` wire every retained row of the
  room under any instance, because a board that holds the room's genesis under an older
  attachment is only told of the end by a room-scope withdrawal (W2r, V1); rows are immutable
  but for P3's state and P4's deletion; completion is per answer, per scope and per wire (U3):
  a `Member` answer never completes a `Room` wire, an old leave's answer never completes a new
  leave's; a complete wire is cleaned up in three durable steps, `complete` first, its answer
  rows in bounded batches, the entry last, so a crash anywhere in the cleanup asks no board
  again (W5a–c, V3); a fresh attachment after a rejoin publishes under its own instance and
  never reuses or mutates the old one's rows; the room's erasure never deletes a publication
  row (U2); a row goes only when no wire of either scope references it and the room is not held
  under its instance (P4). A committed intent is a leave whether or not the person saw the
  answer: the open hides the room and resumes it, and a second `vox room leave` says
  `already_left` (W1b, V4). The intent batch is
  bounded by the wire plus the `LeftRoom`; nothing is staged or resumed against RAM. Every
  batch's estimate is its actual encoded bytes, computed by the caller as SO-11 requires; no
  fixed envelope is asserted. The intent batch writes directory rows only and precedes a
  deletion, so it is a **reclamation-class** batch under ADR-047 SO-11 (3 MB admission; agreed,
  ADR-047 r4), not an ordinary write; P1 and P3 are the publish path's own ordinary writes, one
  per board per round; W3 rows are one small ordinary write per answer. The
  record is the person's fact: ADR-040 NW-3's durable class, never only
  in memory. The steps, in this order, each durable before the next:

  1. **Record.** Sign the member withdrawal (as today, `leave_save.rs:228-258`); write it and
     the `LeftRoom` (`departure: Pending(…)` or `None(…)` as step 3 decides from a read of the
     room's state, `outcome: Undelivered` or `Ended`, `erasure: Hidden`) in one transaction.
     Answer the person (LE-1). Hide the room in memory. For a room known ended: no member
     withdrawal is written (the creator's room-scope withdrawal takes the whole room off boards;
     a member's would add nothing), `outcome: Ended`, and LE-7 governs from here: **LE-7 takes
     precedence over this requirement's `None` → erase-at-once rule.**
  2. **Quiesce.** Take the room's pending-write owner and the own-writer gate's transition
     (today's leave does, `pending_text/leave.rs:57-70`, `actor.rs:21700-21736`); retire its
     flows in deleting mode (LE-4 step 1); install the **leave fence**: after this step the room
     admits exactly three own appends and no other: (a) ADR-046's own-feed recovery completion
     (`Work::Complete`, `pending_recovery.rs:435-485`), (b) sparse settlement (`Work::Settle`,
     `:391-431`), (c) the departure. (a) and (b) are signed rotations carrying no content; under
     the leave fence their new sender generation is delivered to nobody: no key package, no
     rekey, no consent (the departure is a governance entry readable without a sender key, and
     nothing will be encrypted under the new generation). This is the justified exception F1
     asks for: without it a `Pending(Settled)` or `Pending(OwnHistory)` departure could never be
     signed, and the two-day bound would erase a deliverable departure. A post, receipt, read mark,
     settlement save of content, key package, service share or rotation for any other purpose
     already prepared is drained or dropped here, before any signing (F6). A trust debt the room
     owes (ADR-048) is moot from this fence on: a fenced room publishes no content and no key,
     so there is nothing left to withhold; the debt's withdrawal is not published; the debt's
     entry itself is cleared at the moment ADR-048 TC-2 names, the batch that forgets the room
     (LE-4 stage (a); X049-5). **A room whose own prefix is not authoritative** (own-history
     recovery pending: a member's verified `Head(me)` above this node's own head, RL-8.5) writes
     in this transaction, into the marker row, that highest verified supplied head (the small
     signed head the recovery already holds, `load_recovery_boundary`, `own_history.rs:1436`):
     it is the known signed boundary LE-9's case 2 waits for, and it must survive the room's
     erasure as the marker does.
     **The continuity and the carry boundary** *(changed r3: N1; changed r5: R1, R5; changed
     r6: S2)*: in the same transaction that installs the fence, under the own-writer gate so no
     own append can race it, the node writes into the RL-8.4 continuity marker row
     (`own-continuity/<room>/<author>`, under the continuity key, readable after the room key
     is gone) its **continuity** (Terms), defined by what the shipped code reads rather than by
     a list: the signed head; everything `prepare_own_append_ranges` derives for position
     head + 1 (`own_history.rs:1518-1586`: the append forest and the root context); and every
     entry hash `Entry::build_signed` can name from a later position (`pending_text.rs:1110-1121`:
     `prev_hash` = the head's entry hash; `lipmaa_backlink` = the hash at `lipmaa(n)`,
     `log/feed.rs:59`: the task derives the set from `lipmaa` itself; it is O(log head)).
     Everything in it is O(log n) and public. In the same transaction it writes the **carry
     boundary**: the lowest own position above the highest position any member's inventory has
     confirmed (the **body-complete** `held_through` of a member's inventory, ADR-042 TR-16's source; X042-13) — not the entries themselves (R5: a
     suffix of a thousand root-signed headers is over 3 MB and is not a reclamation batch). The
     entries' headers, and the public payload of each lifecycle entry among them (S2), are
     copied in LE-4 step 4's carry stage, after the room's post bodies are deleted and before
     its header rows and key are. The continuity is updated in the departure's transaction at
     step 3 (the departure is then the head, and its `Presence(false)` body is part of the
     carry) and in a recovery or settlement rotation's transaction under the fence. A room
     whose own prefix is not yet authoritative (`Pending(OwnHistory|Settled)`) writes no
     continuity until that rotation commits: a continuity is never derived from a head a member
     may hold more of; such a room's marker keeps its last signed head alone, which is LE-9's
     case 2.
  3. **Sign, when the room can.** The departure is appended as today
     (`pending_text/leave.rs:75-103`) when the own head is authoritative: the room is settled,
     own history current, this identity an author and not already departed, the store able to
     save. The record becomes `Signed { seq, entry_hash, head_id }` (the entry's hash and the
     HeadID of this node's own signed head at `seq`, kept apart: R12-2). When a check refuses, the sign is a named
     wait `(room, DepartureSign)` parked on the prerequisite it names, `Settled(room)`,
     `OwnHistory(room)` or `StoreRecovery(room)` (ADR-040 NW-1's table), the record says
     `Pending(<prerequisite>)`, and the hidden room runs the rounds that release it: the
     own-feed recovery fetch (ADR-046 SY-11) and the first-sync settlement (SY-10/SY-17), under
     ADR-046's scheduling, and nothing else. `vox status` shows the wait in NW-4's `waiting`
     block as `room <id> (<name>): the departure waits until <prerequisite words>, for <dur>; Vox
     finishes it by itself`. When no prerequisite can admit it (not an author; the room's store
     unreadable or of an unsupported format), the record is `None(reason)` and LE-4 erases at
     once. A node MUST NOT sign a departure from a head a member may hold more of (F6):
     `Pending(OwnHistory)` is the honest state, bounded by LE-4's two days.
  4. **Serve and deliver** (LE-3). On a receipt: `outcome: Delivered { peer, ms }`, durable, then
     erasure (LE-4).
  5. **Erase** (LE-4). The erasure's first batch sets `erasure: Erasing { stage, cursor }`,
     forgets the room from the node's map (`Forget(room)`) and clears `awaiting_departure` (as
     today `leave_save.rs:321-336`); its stages are LE-4 step 4's; its last batch sets `erasure:
     Erased`. Then the board withdrawal is published (LE-5's route completion). The `LeftRoom`
     is forgotten when `erasure: Erased` and, for `Expired`, 24 h have passed (LE-4's line); the
     withdrawal entry and the continuity marker have their own lifetimes (LE-5) *(changed r5:
     R2, R4)*.

  *Crash windows* (the daemon killed between any two durable steps; the on-disk state after
  each). Before 1: nothing happened; the room is as it was. After 1: the record exists, the room
  is intact; at every open the node reads `left-rooms/*` before any room is opened (ADR-040
  NW-3's open-time derivation); a recorded room opens hidden, skipping every stage that authors
  or publishes (the trust stage, reachers, services, Session projection, key delivery), and
  steps 2–3 run again: `Pending` re-checks and signs or parks; `Signed` is verified against the
  own tail; if the tail *is* a departure at a seq the record does not name (the append committed
  and the record's update did not), the record is corrected from the log before anything else
  is appended. After 3, before 4: the hidden room serves and delivers (LE-3). After 4
  (`Delivered`), before 5: erasure starts at open. During 5: `Erasing { stage, cursor }`
  resumes LE-4 step 4's stage from the cursor at open; the room is unremembered but its rows
  exist until `Erased`; no reopen is possible because the record says `Erasing` and the open
  reads records first (F4: an unremembered room with rows is not "erased"). Killed inside
  stage (c), the header carry *(r5: R5)*: the continuity rows written so far are durable and
  keyed by batch number, the source header rows and the room key are intact, and the stage
  resumes at the first batch not yet written (idempotent: a batch rewritten is identical);
  killed between (c)'s last row and (d): the headers exist twice until (d) runs; after (d) the
  room key is gone and only the continuity rows hold them. After `Erased`: only the record,
  the board entry and the continuity marker remain, and the record's forgetting is idempotent.
  A rejoin while the record exists is LE-9.
  - *Why*: second review F5 (the departure stays a log entry served from the own feed; no new
    authentication model), F6 (quiesce first), F15 (no invented expiry), "Ended/left rooms" (one
    record lifecycle; keep the tombstone until erasure is durable); review F1 (the fence
    admitted no recovery), F2 (one slot for end and leave), F4 (erased was set before the rows
    went), F6/F7 (the journal's actual write and completion), F8 (the outcomes a status line
    needs).
  - *Changes*: `PendingWithdrawal` re-keyed per room, scope and wire, with completion as W3 answer rows (`actor.rs:6146-6151`,
    codec `:6160-6260`; `load_journal` callers `metadata_save.rs:2260-2290, 2435`); the new
    `LeftRoom` codec; `resume_leave` (`actor.rs:21801`) derives from the record, not from a
    reopened room's tail; `reopen_remembered` (`actor.rs:20231`) opens a recorded room hidden;
    `ChannelState::takes_policy_writes()` false for a recorded room (ADR-048); the leave fence in
    `local_history.rs:148-153`'s guard (before the departure as well as after; the three
    exceptions); the key-delivery suppression for a fenced room in `consent_release/rekeys.rs`
    and the key-package queue; `wait_for_leave`/`finish_leave_if_heard`/`finish_leave_unheard`
    (`actor.rs:21758-21893`) become the record's completion (LE-3, LE-4).
  - *Deleted*: `MAX_PENDING_WITHDRAWALS` and the whole-map codec; the `[failed: node: this
    identity has left the room]` row (item 27); the hidden room's trust stage and
    `preparation_save.rs` stages for a recorded room.
  - *Depends on*: ADR-040 NW-1 (`Settled`, `OwnHistory`, `StoreRecovery`), NW-3 (open-time
    derivation; a room's removal retires its obligations), NW-4; ADR-046 SY-11, SY-17 (the
    recovery and settlement a hidden room may run); ADR-047 SO-11 (the record admitted as a
    reclamation-class batch; contract), SO-9 (the cursor and the `Erased` completion); ADR-048
    (a recorded room is out of the pass; its debt retired by the fence).

- **LE-3. The departure is delivered by the hidden room, to any member, and completes only on
  a receipt.** **(changed: F5; row 27; changed r12: D1; changed r13: R12-1.)** After LE-2 step
  3 the hidden room keeps its connections to members (`actor.rs:23134-23135` holds a left room
  "only to deliver the departure" today) and its room anchors. Under the replacement sync
  (ADR-046 R2, ledger row 57) the **receipt probe** is the room's `Have` stream to each
  connected member (SY-12: one stream per room and member, opened by the connection, a whole
  `Have` first and then updates): the hidden room reads each member's row for this author and
  completes on a receipt (Terms) and on nothing less; it sends no `Head(me)` for the receipt (a
  `Head` answer reports an accepted head, not possession of the entry: R12-1). Its other
  outbound requests are *(changed r14: R13-1)*: while `Pending`, SY-11's own-feed recovery and
  the settlement requests LE-2 step 3 names; for other authors, SY-14's control coverage
  (`ControlRange`; `Range{bodies: true}` for the governance-kind bodies it needs) and the
  **closure wanted** of every pending control entry it holds (SY-3 rule 3's `CLOSE`: the
  coordinates the entry names and its previous own entry, witnessed Content headers with
  `Range{bodies: false}`, `Context{hash}` for a reported `MissingContext`, bodies only for
  governance-kind and typed-policy members), so an end (LE-7) or a removal both reaches it and
  can be closed; and SY-14's head, context and probe discovery (`Head(A, bridge)` on a newer
  size or an unaccepted HeadID — the Terms' `Head` lives here — `Context`, `Probe`) in service
  of those. SY-14's **bodies wanted** of ordinary posts and `explicit` pages are never issued by
  a hidden room (no ordinary post body is fetched). It answers every SY-12 request a member makes of it (its public
  history, its departure entry and head) as RL-8.1a says — a member in the Head-only state
  reaches the receipt condition only by fetching from this node or another holder, so this
  serving is what makes the receipt answerable. Under R1 (interim) the probe is
  `departure_probe` (`runtime.rs:3056-3066`) on the room's ports, deleted with SY-19. The
  delivery is one logical obligation, `(room, DepartureDelivery(peer))`, one sub-key per member
  in the roster; the first receipt retires every sub-key (`Registry::retire_prefix`, ADR-040
  NW-3). **Two owners, by whether a connection exists** (F5): with no connection to the member,
  the sub-key parks on `PeerReachable(peer)`, this ADR's prerequisite in NW-1's table (*ready
  when* `net.manager().existing(peer)` is `Some`; *released by* the connection-established
  event ADR-046 names and by the member's inbound session for the room; *said as* "member
  <name> is reached"); with a connection, under R2 the room's `Have` stream to that member is
  the owner: the sub-key is held by the stream for as long as the connection lives, each
  `Have` update is tested against the receipt, and the stream's heartbeat (SY-12: a whole
  `Have` or `unchanged` at least every 30 s) means no update is ever waited for in vain; a
  stale row is not an error and is retried by nothing — the member's next update is the only
  event. Under R1 the port's own bounded retry owns the probe (`ports.rs:262-284`: `Busy`
  200 ms → 1 s, `NoProgress` 1 s → 30 s, `Unreachable` 200 ms → 8 s), a preserved owner in
  NW-1's table (contract): a `SessionBusy`, a stale echo or a transport failure on a live
  connection is retried by the port, never parked on a predicate that is already true. A
  member is dialled as ADR-046 schedules the room's ports; an anchor the
  room needs is kept for it (ADR-012: never required when the member is direct). **Completion**
  is a receipt as defined in Terms and nothing else: a peer's `AuthenticatorInvalid` (not a
  member, room not held, entries unacceptable, a feed gap or fork: `ports.rs:293-297`,
  `log/sync.rs:794-800`), `EpochMismatch`, `SessionBusy`, a transport failure or a shutdown
  MUST NOT complete it (second review F7). A refusal from a peer counts toward no alarm: a left
  room raises none (LE-1); a member that cannot be connected to is `offline, last seen <dur>
  ago` in `vox status --json .left[].members[]` (row 27's words), never unhealthy. **If no
  member is reached within two days**, the departure is not delivered; the record becomes
  `Expired` at the bound (LE-4) and the board withdrawal still goes out, so a later join through a
  board is answered as withdrawn, and the members' copies list this identity until one of them
  learns otherwise. This ADR promises no more than that, and says so in LE-1's words. A
  receipt from one member is a receipt from one member: it is not evidence that every member,
  or any honest member, holds the history.
  - *Why*: F7, F14 (second review); F5 (review: a refusal on a live connection parked on
    `PeerReachable` would wait out the whole bound for a willing peer).
  - *Changes*: `LeaveWaiter` (`actor.rs:175-188`) becomes the registry's sub-keys; the `heard`
    edge (`actor.rs:13529`, `:13642`, `:13781`) releases them and writes `Delivered`; a port of a
    hidden room runs the probe and LE-2 step 3's rounds only (today: `limited_recovery` /
    `departure_receipt` attempts, `ports.rs:222-234`).
  - *Deleted*: counting a refusal as "no longer to be told" for a left room (ADR-040 r2's
    NW-6/NW-15 wording).
  - *Depends on*: ADR-046 (port scheduling of a hidden room; SY-24; the connection event),
    ADR-040 NW-1 (the preserved-owner row for the port's backoff), NW-3.

### 3. What is erased, when, and what that gives up

- **LE-4. The room is erased on a receipt, at the bound, or when there is nothing to serve;
  the erasure is never abandoned.** **(changed: F4, F8.)** Erasure runs when the first receipt
  arrives (`Delivered`); when the record's `departure` is `None`; when the room is held alone
  (no other member: at once, RL-8.1); when a known-ended room's wind-down ends (LE-7); or at
  the bound, **two days** from `departure_ms` by the wall clock (the decider, 2026-11-13, row
  58, replacing RL-8.1a's seven; a named bound ADR-040 NW-3 allows), which writes `outcome:
  Expired { ms }`. A `Pending` departure at the bound is erased unsigned. **What `Expired`
  means for others**: the departure was never verified by any member; the hidden copy is gone,
  so no member will take it from this node later; the board withdrawal still goes out (LE-5),
  so a board answers a later join of this identity's old records as withdrawn; each member's
  copy lists this identity as a member until that member learns otherwise (from a member that
  did take it, if any did within the two days, or from this node's return under LE-9, whose
  carry includes the signed departure), and its consents to this identity stand until then.
  The person is told exactly that. **The words follow both `outcome` and `erasure`**
  *(changed r3: N6)*: while `Expired` and not `Erased`, `vox status` prints `left <room>: no
  member could be told in 2 days; deleting<, waits until <prerequisite words>, for <dur>>;
  members list you until one of them learns otherwise` (the parked purge stays a visible owner
  in NW-4's `waiting` block, or a `failed` line for `SessionCleanupUnavailable`, until the next
  open re-derives it); once `Erased`, `left <room>: no member could be told in 2 days; deleted;
  members list you until one of them learns otherwise`, kept for 24 h **from `Erased`**, not
  from the bound; the daemon log says each once; a status read does not consume either (F8).
  "Deleted" is never printed before `RoomRowsPurged`. The erasure is:
  1. **The room's in-flight sync work stops.** Under the replacement sync (ADR-046 R2, ledger
     row 57; D1): SY-24's table — every in-flight exchange of the room is a per-peer slot held
     by the running exchange and released on every exit path; the erasure cancels the room's
     exchanges (a room close resets its streams) and waits for their tasks to end; nothing is
     retained after a round, so there is nothing to discard and no cleanup that can fail. Under
     R1 (interim, until ADR-046's cutover deletes the pool, SY-19): `take_bounded_room(room,
     retire_inbound, Retire::Deleting)` (`bounded_sync.rs:2848`): `RoomRetirement::run` still
     awaits every running slot's task and `join_cleanup` (`:802-826`; a worker is proved stopped
     by joining it); `drain` moves a flow in `retirement_failed`, or one an at-rest lock refuses,
     to `discarded` instead of returning `history retirement requires recovery` (`:832-843`),
     and returns `Ok` once every physical owner has stopped. The decision is made here, in the
     worker, not in the finish handler (first review finding 7: the gate and transition are
     taken only on success, `actor.rs:21540-21559`). A close (`begin_own_key_close`, `:21592`)
     keeps `Retire::Keeping`. The R1 text is interim work that the cutover deletes with the
     pool; what replaces it is the R2 sentence above.
  2. **The ledger** (R1 only; D1). Before the purge, the daemon's `RetirementLedger`
     (`history_budget.rs:289`) drops every entry, error and waiter whose key names this room and
     instance, after the flow it tracks has been joined (including a cleanup adopted at
     controller replacement, `bounded_sync.rs:960-979`); `lanes_json` (`:5847-5866`) then lists
     nothing for the room (F12). Under R2 there is no retirement ledger (SY-19 deletes it) and
     this step is empty.
  3. **The purge**, as today (`begin_owned_purge`), with its refusals turned into named waits
     instead of a dropped attempt (second review F11): a policy save in flight
     (`pending_policy`, `leave_save.rs:549-551`, `:729-733`) parks `(room, EndedPurge)` or the
     leave's purge on **`PolicySave`** (*ready when* `pending_policy.is_none()`; *released by*
     the save's completion, where `pending_policy` is taken back, `actor.rs:19809`,
     `policy_save.rs:248`, `:587`; *said as* "this node's trust save finishes"); Session cleanup
     busy (`session_rooms_retiring`, `session_ingress::retirements`, a full sink, `:734-766`)
     parks on **`SessionCleanup(room)`** (*ready when* no Session retirement of the room is
     pending and the sink has a permit; *released by* the retirement's completion and the
     permit's return; *said as* "this room's Session cleanup finishes").
     `SessionCleanupUnavailable` (the sink closed, `:767-770`) is terminal for this run: NW-4's
     `failed` line names it, and the next open derives the purge again from the end entry or
     the record. "Never abandoned" means exactly this: every refusal is a named wait or a
     terminal that the next open re-derives; it does not promise completion within the
     wind-down when the store itself cannot write (then the room is `cannot save`, ADR-047, and
     the purge parks on `StoreRecovery(room)`).
  4. **The store** *(changed r5: R5; changed r6: S2)*, in stages, `erasure: Erasing { stage,
     cursor }` resumed from the record after a restart, every batch ADR-047 SO-9's 256-key
     reclamation batch: (a) `Forget(room)` and `awaiting_departure: false` in the first batch;
     (b) **post bodies and everything that is not this author's entry headers or lifecycle
     payloads** (received rows, keys other than the room key, sender state, cursors,
     projections, and the hook's cursor and held files for the room: ADR-050 TJ-4's
     `remove_room_cursors`, X050-10, so that a hook asking after the room is told it is not
     held from `client.rooms()`, which omits a hidden room from LE-1 on): the bulk of the room, freed first so the next stage has space; (c) the
     **carry**: this author's signed entry headers from the carry boundary (LE-2 step 2) to
     the head, and the public payload of each lifecycle entry among them (the departure's
     `Presence(false)`, a rotation's `Presence(true)`: S2), copied into continuity rows
     `own-continuity/<room>/<author>/carry/<n>`, each row one batch under 2 MB, re-sealed
     under the continuity key (the source rows are sealed under the room key, which is why
     they cannot simply be kept); these are inserts, admitted as **ordinary** writes (floor +
     2 × estimate + 1 MB, ADR-047 SO-11; the ballast never funds them) against space stage (b)
     just freed; when the disk refuses, the stage parks on `StoreRecovery(room)` with the
     source rows and the room key intact and the status words `deleting, waits until room
     <name> can save again` — a copy whose carry is owed is never deleted under it; (d) this
     author's source rows and the **room key** (the last batch; the RL-8.4 marker kept; the
     ended-room note written, RL-8.2a; the ledger rows), with `erasure: Erased` (SO-9 reports
     that completion as `RoomRowsPurged(room, instance)`; contract). A crash in any stage
     resumes it from the cursor; after (c)'s last row and before (d), the carry exists twice,
     which is harmless and idempotent. The freed pages are reused and cleared at the next
     store rewrite (Q7: B, row 61).

  *What erasure gives up, said plainly* *(changed r5: R2)*. The bodies of the person's posts that
  no member has confirmed holding are gone for good at erasure (ADR-042 TR-16 counts them before
  the leave); their signed headers stay with the continuity marker (LE-5), so the person's later
  entries can still be verified, but no member can ever read those posts from this node again,
  and a rejoin (LE-9) brings their headers back, not their words. History of the room
  that only this node holds is gone for other members too: a member catching up after the
  erasure gets it from nobody. A trust withdrawal the room owed (ADR-048) is never published:
  the fence of LE-2 step 2 made it moot for new content and keys, and the debt is cleared in
  this stage's first batch, the moment ADR-048 TC-2 names (X049-5); old content a removed
  computer already held is not protected by any withdrawal. An end this node held (LE-7) is
  served during the wind-down and then no longer. None of this is hidden from the person:
  TR-16's sentence before the leave, LE-1's messages after it.
  - *Why*: items 64 and 86; first review finding 7; second review F11, F12, "Q6" points 1–3;
    review F4 (the erasure's states), F8.
  - *Changes*: `take_bounded_room` mode; `run`/`drain` in deleting mode; `begin_own_key_ended_purge`
    (`actor.rs:21534`) and the leave's purge as deleting callers; `refuse_owned_purge`
    (`leave_save.rs:704-717`) parks instead of failing; `RetirementLedger::retire_room`; the
    purge as SO-9's cursor stage.
  - *Deleted*: `ended room cleanup stopped: …` and the `return` after it
    (`leave_save.rs:1563-1577`); `LEAVE_RETRY_MS` (`actor.rs:667`: the 10-minute blind retry of
    a refused purge); the leave's `rewrite_fresh` (`leave_save.rs:348`; SO-9 deletes it).
  - *Depends on*: ADR-047 SO-9 (batched row removal, the cursor, `RoomRowsPurged`), ADR-046
    SY-24 (a discarded flow counts toward nothing), ADR-040 NW-3/NW-4.

- **LE-5. Nothing of a left or ended room survives erasure but the checkpoint, the note and
  the record; the board withdrawal has a completion.** **(changed: F6; changed r3: N1, N3;
  changed r8: U2, U3.)**
  After erasure the node holds: the RL-8.4 continuity marker extended to this author's
  continuity (the append material, the carry's signed headers and the lifecycle entries'
  public payloads: public, non-secret; amended below), under the marker's own rule (kept
  until the room's end is verified, or consumed by a rejoin: RL-8.4), **independent of the
  `LeftRoom` and of the board journal** *(changed r5: R2)*; the RL-8.2a ended-room note (for an
  ended room); the `LeftRoom` until LE-2 step 5; every withdrawal entry (`Member` or `Room`)
  until each board in that wire's route set (W2m or W2r, by scope: LE-2's table) has answered
  that wire (r10), and those publication rows until no withdrawal of either scope references
  them — **the erasure of the room never deletes a publication row** (U2). No room key, sender state, received row, post body, member address or
  transport secret is kept in any of them: the hidden room held them until erasure, and
  erasure takes them; the carry holds signed entry headers (sequence, predecessor and
  back-link hashes, payload hash, signature) and, for a lifecycle entry only, its public
  payload (a Presence body: room, epoch, author, `here`, chain id; S2), never a post's.
  **Board completion** (F6; changed r8: U3): completion is kept **per answer**, one row
  `withdrawal-answered/<room>/<scope>/<wire_hash>/<board>`, written when the board answers that
  exact wire; an answer to a `Member` wire marks nothing of a `Room` wire, and an answer to an
  older wire (an earlier leave's) marks nothing of a newer one. The
  put worker (`put_withdraws`, `actor.rs:22072-22110`) reports each put's result as
  `NetEvent::WithdrawAnswered { room, scope, board, wire_hash, taken: bool }`; a board's
  acceptance and a board's refusal (its answer, not retried, as today) both write that wire's
  answer row for that board; a put with no answer writes nothing and is tried again at the next
  connection to that board (today's `actor.rs:12648` path). **Completion** *(changed r10:
  R9-1)*: W5a of LE-2's table is the sole terminal predicate of an entry: **every board in this
  wire's route set — W2m for a `Member` wire (its instance's publication rows plus the
  configured anchors), W2r for a `Room` wire (every retained publication row of the room under
  any instance, plus the anchors) — has an answer row for this wire.** An entry whose
  scope-selected route set is empty (no row under the relevant instance or instances, and no
  configured anchor) is complete at once. **When an entry is dropped** *(changed r3: N3; changed
  r5: R4; changed r8: U3; changed r10: R9-1)*: a `Member` entry and a `Room` entry alike are
  dropped only through W5a–W5c, that is, only once that predicate held. There is no time bound on
  either: a board keeps a member's admission notice with no time limit and passes it on with
  the member's own withdrawal, refusing the notice as admission once the withdrawal is held
  (`nat/store.rs:318-326`, `:524-535`, `:633-640`), so a member withdrawal dropped before a board
  answers would leave that board able to hand out the old notice without its veto; the 2 h and
  7 day expiries (`:108-119`, `:755-785`) cover address and bundle rows only. Revision 4's
  `BUNDLE_MAX_TTL_MS` drop is withdrawn. An entry whose board never answers is listed in `vox
  status --json .withdrawals[]` with its open routes, costs one row, and is bounded by the node's
  board count, not by time; it outlives the `LeftRoom` (LE-2 step 5) and the hidden copy's two
  days, which it does not extend: it holds no room data. A rejoin (LE-9) that publishes newer
  records does not drop it either: the board's tombstone refuses records stamped at or before
  the withdrawal and takes the newer ones (`nat/withdraw.rs:23-25`).
  The `Room` entry's reason is the end's evidence: a board keeps a room's genesis with no time
  limit (`nat/store.rs:137-145`), so no bound makes it moot. Revision 2's 30-day drop and
  revision 4's 7-day `Member` drop are withdrawn: their premises (a board forgets a room's or a
  member's records on a clock) were false at the tag. A `Room` entry is never dropped by a
  `Member` entry's completion and vice versa.
  - *Why*: second review "Q6" point 2 (a record that holds no secrets cannot serve a prefix; so
    it does not serve, the room does); review F6 (`put_withdraws` reports nothing; the record
    would never finish).
  - *Changes*: `put_withdraws` emits the event; the actor's dispatch writes the answer row (W3)
    and, with the last one of the wire's route set, `complete` (W5a); the cleanup W5b–W5c
    replaces `NativeWork::ForgetWithdrawal` (`leave_save.rs:260-275`).
  - *Proof*: `a_room_left_leaves_nothing_on_the_node` (extended: the record's bytes after
    erasure hold no room key; `erasure: Erased`; after a board accepts the withdrawal and the
    daemon restarts, `vox status --json .withdrawals[]` no longer lists the wire (`.left[]` is
    forgotten at `Erased` and says nothing about boards: D3); mutant: do not write the answer
    row on the board's answer → the wire is listed `pending` after the restart, red).

### 4. The ended room

- **LE-6. An ended room is always deleted, is shown as ended until it is gone, and raises no
  sync alarm.** On the ender's node and on every member's node, an ended room is deleted at the
  end of its wind-down by LE-4's erasure (deleting retirement, ledger disposal, parked purge).
  The wind-down MUST be measured from the end entry's own clock, not from the open
  (`winding.since` is an `Instant`, `actor.rs:22222-22224`; E-64b: a restart 20 s into the
  wind-down kept the end and deleted the room at the first tick after open, so a restart
  shortened it): at an open past the bound the room is erased at once. While it waits, every
  surface that lists rooms shows it ended: `vox room list` keeps
  `[ended: its creator or an admin ended it]`; `vox status` prints ADR-042 TR-2's line
  (`ended: its creator or an admin ended it; deleting`, with `, waits until <prerequisite
  words>, for <dur>` when the purge is parked); the app's sidebar shows the same state (its
  presentation is ADR-042's). A member's refusal of the room after the end
  (`AuthenticatorInvalid`: it deleted it, which is what the end asked for) MUST raise no `sync
  failing` line and count toward no failure streak; it is not a receipt of the end either. A
  member that cannot be connected to during the wind-down is `offline, last seen <dur> ago`
  (row 27), not unhealthy.
  - *Why*: item 64 (three `sync failing` lines and no marker for hours); E-64b (`sync failing:
    peer unreachable` for an ended room at +50 s on the release asset).
  - *Changes*: `tend_lifecycle` (`actor.rs:22222-22270`) measures from the entry; the ended
    purge is a named obligation `(room, EndedPurge)`; the sync book skips an ended room's
    refusals (`actor.rs:13570-13590`, `counts.failed`/`failing_since`).
  - *Deleted*: the lifecycle tick's blind re-run of a failed ended purge.

- **LE-7. Leaving an ended room does not cut the end short, and does not touch the end's board
  withdrawal.** **(changed: F2.)** A leave of a room this node knows ended writes the record
  with `departure: None(ended)`, `outcome: Ended`, no member withdrawal (LE-2 step 1), and
  answers at once (LE-1); the room is hidden; the wind-down continues as RL-8.2 requires,
  serving the end to each member reached; an outstanding room-scope withdrawal (the creator's
  or an admin's, `metadata_save.rs:4743-4755`) keeps its own entry, its routes and its
  endorsement retry (RL-8.2), and is published and completed as LE-5 says, whether or not the
  person left meanwhile; erasure follows at the wind-down's end (LE-4). The end is not appended
  over with a departure: the room takes no new message and the end deletes it for everyone. A
  leave of a room that is ended but whose end this node has not learned is an ordinary leave
  (LE-2); if the end arrives while the record is `Pending` or `Signed`, the record becomes
  `outcome: Ended`, the end's wind-down takes over and the departure is served with it. What
  this does not promise: a member unreached within the wind-down by any holder learns the end
  from a board (`0x001B` answers its later join as ended) or from a member that still holds it;
  a member that holds the room after every other holder has deleted it keeps it until the
  person leaves it, which always works (LE-1), and its status shows the members `offline, last
  seen <dur> ago` and the room `waiting for a member` (ADR-042 TR-2), not `sync failing`. This
  is RL-8.2's existing 60 s bound (the decider, 2026-10-03), not a new loss; RL-8.2 is not
  amended.
  - *Why*: second review F16; review F2 (End's `Room` wire and Leave's `Member` wire shared one
    slot: a leave during wind-down replaced the only retained End withdrawal, and a board back
    later could not answer joins as ended).
  - *Proof*: LE-8 journey B acts 5 and 6.

### 5. Proofs

- **LE-8. Every requirement lands with its proof, on the shipped binary, with a mutant that
  reaches its own assertion.** **(changed: F10; row 32.)** Reds name PRODUCT or APPARATUS;
  knobs only behind `test-knobs`; existing journeys are extended, no new file. Every act is
  staged inside the macOS guest or the Linux VM (row 32): the short-disk image is `hdiutil` in
  the guest (no root) and, on Linux, a size-bounded `tmpfs` the VM's provisioning mounts at
  boot (ADR-045 owns the provisioning); everything else is loopback. A baseline not yet run is
  marked **owed** with the run that settles it.

  **Staging the state each mutant needs** (apparatus, `test-knobs` unless said):
  - `VOX_TEST_LEAVE_HOLD=<step>`: the leave holds after step 1, 2 or 3 of LE-2 until the file
    named is removed; observed in the log as `leave of <room> held at step <n>` (else
    APPARATUS). Kills are placed inside the hold.
  - `VOX_TEST_CLOCK_STEP_MS`: the wall clock the bound reads is advanced (ADR-045's clock step
    for timers); observed as a log line.
  - A test-side member (apparatus, allowed by AGENTS.md) that answers a departure probe with
    `AuthenticatorInvalid`: stage it with a real member that has erased the room (a member
    that left it, LE-1: its refusal is the genuine `room not held` code, `ports.rs:295`) — no
    knob.
  - `VOX_TEST_SESSION_CLEANUP_HOLD`: a Session retirement of the room held open.
  - `VOX_TEST_PURGE_HOLD=<room>`: SO-9's purge of the room holds after its first batch until
    the file named is removed; observed as `purge of <room> held at batch <n>` (else APPARATUS).
  - `VOX_TEST_CATCHUP_HOLD=<room>`: a member's ordinary catch-up rounds for the room hold (its
    admission answers still run); observed as `catch-up of <room> held` (else APPARATUS).
  - `VOX_TEST_OWN_RECOVERY_HOLD=<room>` (U4): on the node that sets it, own-history recovery for
    the room stops before any fetch or install of this author's own entries, while the
    signed-head and inventory exchange that sets the recovery target runs as usual; released by
    removing the file; observed as `own-history recovery of <room> held` and `… released` (else
    APPARATUS). It is distinct from the catch-up hold, which does not touch recovery.
  - `VOX_TEST_PUBLISH_HOLD=after-address-put` (U1/V2): a publish round holds after the board has
    answered the **address** put (the third of genesis, bundle, address, `actor.rs:9428-9444`)
    and before the node files the round's result; observed as `publish of <room> to <board> held
    after the address put` (else APPARATUS).
  - `VOX_TEST_LEAVE_HOLD=cleanup-entry` (V3/R9-2/R10-1): a withdrawal's cleanup holds at the
    physical boundary immediately after W5b has deleted its last answer row and before the next
    write, whatever the entry's state; observed as `cleanup of withdrawal <wire>: last answer row
    deleted, held` (else APPARATUS). The entry's state at the hold is a product assertion of the
    act, never part of this gate.
  - `VOX_TEST_WITHDRAW_ORDER=member-first` (U3): when two wires of one room are owed to one
    board, the `Member` wire is put first; observed as the LE-5 W4 line `putting the member
    wire for <room> to <board>` printed before `putting the room wire for <room> to <board>`
    *(r13: R12-7)*.
  - `VOX_TEST_FETCH_HOLD=<room>:<author>:<seq|next>` *(r13: R12-1, R12-6)*: on the node that
    sets it, once that author's signed head of size `seq` (or, for `next`, the first head
    accepted above the head held at arming) is accepted (SY-13 rule 3), no `ControlRange` or
    `Range` for that author's position `seq` is issued until the file named is removed — the
    Head-only state of SY-13 rule 3, held; observed as `fetch of <author>@<seq> in <room> held`
    (else APPARATUS). Its `Have` meanwhile names `size` = `seq` and the accepted head, with
    `control_through` and `held` below it.
  - `VOX_TEST_HOLD_POLICY_SAVE=<node>\t<arm>\t<engaged>\t<release>` *(r13: R12-3)*: the same
    four-field form as `VOX_TEST_HOLD_COMPUTER_POLICY` (`actor/computer.rs:219`), consumed by the
    **native policy save's blocking worker** (`policy_save.rs:505`, the `spawn_blocking`
    closure), immediately before `policy.run` (`:552`): it writes `engaged` (`native policy
    save held`) and blocks until one connection to `release`. By then `begin_pending_policy`
    has installed `pending_policy` (`:574`, the same actor turn as the spawn), so the save is in
    flight (`pending_policy.is_some()`, the predicate `leave_save.rs:729-733` tests today) and
    the actor is free. Neither arm of `VOX_TEST_HOLD_COMPUTER_POLICY` stages this: the
    constructor arm returns the message before application (`computer.rs:439-475`) and the
    other holds the actor itself (`:477`), with no save installed in either.

  **Journey A — leave in every state** (extend
  `a_room_can_be_left_and_ended_proof.rs::a_room_left_leaves_nothing_on_the_node`; acts (b),
  (c) and (m), which stage disk space, go to `a_sync_failure_names_its_reason_proof.rs`, where
  ADR-046 SY-24's full-disk staging on SO-11's 256 MB fixture is added by SY-24's task — at the
  tag that file has no disk staging, so SY-24's act lands first and these three extend it; D10).
  The existing assertion that the deleted sealed SEK wrap's bytes are physically absent from the
  store file (`a_room_can_be_left_and_ended_proof.rs:1374-1380`) contradicts row 61 (cleared at
  the next rewrite) and is moved after a `vox node compact` on the stopped-and-restarted node,
  where it is true again (D2). Three computers A (creator), B, C in three rooms; A's data on
  ADR-047 SO-11's 256 MB fixture (the historical 64 MiB image of E-49a is below the floor and is
  not a proof fixture; r8). Each act asserts
  rc 0 and LE-1's exact words, the room absent from `vox room list` within 1 s, `vox status
  --json .left[]` with the expected `outcome`, no `internal error` and no `cleanup stopped` in
  the log; the roster is read with `vox room roster` (the shipped verb; `members` does not
  exist, `crates/vox-tui/src/cli.rs:418-419`, which E-49a's act 3 hit: APPARATUS).
  (a) healthy, every member reachable (the control of (a-i)): B leaves; A's `vox room roster`
  shows B gone within 10 s; B's record is `Delivered` within 10 s and gone after erasure; B's
  store holds no room key (LE-5). v0.4.30: rc 0 and gone (E-49a act 3, run-with-receipt); the
  roster assertion is **owed** (E-49a used the wrong verb). Mutant *(r13: R12-2)*: compare A's
  `Have.head` with the departure's entry hash instead of its HeadID → no echo is ever
  recognised; B's record is still `Undelivered` at +10 s → red. **(a-i) the Head-only member**
  *(r13: R12-1, R12-6)*: A sets `VOX_TEST_FETCH_HOLD=<room>:B:next` before the leave; B
  leaves; d = B's departure position, read from B's `.left[].departure` after the leave.
  Staging gate (APPARATUS if not met within 10 s):
  A's log `fetch of B@<d> in <room> held` and A's `vox status --json .rooms[]` member row for B
  with `size_known` = d and `headers_through` = d − 1. Product, sampled at 1 Hz for the 10 s
  the hold is kept: B's `.left[].outcome` stays `Undelivered` and B's erasure stays `Hidden`
  (red at the first sample that says otherwise); A's roster still lists B. Release: A's
  roster shows B gone and B's record is `Delivered` within 10 s, then erased. Mutant: complete
  on `size` and `head` alone → `Delivered` during the hold → red on the sampled assertion.
  No second mutant on the `held` clause *(r14: R13-3)*: under the hold `control_through` < d
  as well, so a mutant that completes on coverage without `held` stays `Undelivered` and
  passes; and no reachable state has `control_through` ≥ d without the departure's body
  (SY-14, ADR-046 r12: coverage advances only when every needed governance-kind body is held
  or `not for you`, and a Presence is addressed to no one), so omitting `held` changes no
  outcome. The clause stays as the statement the member's inventory makes directly; it is not
  claimed proved by a mutant. **(a-ii) the false advertiser** *(r13:
  R12-2)*: the apparatus member ADR-046 SY-11's false-advertisement act provides, admitted to
  the room, answers B's connection with a `Have` naming B's feed at `size` = d with a HeadID B
  never signed, `control_through` = d and `held` through d — every other conjunct of the
  receipt true, the HeadID the only false one *(r14: R13-3)*; A stopped. Product: B's record stays `Undelivered` for
  30 s and no `Delivered`; the apparatus member records (apparatus-side) exactly one `Head`
  request from B for B's own feed (SY-14, N8), none for anything else. Mutant: accept any
  HeadID at `size` = d → `Delivered` → red.
  **(a′, ADR-042 TR-16's sentence)** *(changed r13: R12-8)*: in a room of exactly two members,
  A and B (`room3`, created by A, joined by B; C is not a member). First the confirmed
  baseline: B posts some entries with A up; gate (within 10 s, else APPARATUS): B's `vox status
  --json .rooms[].own_feed` shows `members[] | select(.id == A).held_through` = `head`. Then
  n := that observed `head` (not the number of post commands: settlement appends a signed
  Presence, `pending_recovery.rs:391-431`, and the join itself adds lifecycle entries; r14:
  R13-5), and A's `held_through` = n is asserted. Only then A stopped; B posts exactly two
  more; asserted: B's `own_feed.head` = n + 2 and A's
  `held_through` still n (the retained inventory boundary, not a live count).
  B leaves: `vox room leave` without `--yes` exits non-zero printing TR-16's `this node holds 2
  entries of yours in <name> that no member has confirmed holding …; leaving deletes them for
  good`; with `--yes` rc 0 and the room gone (an actual leave, asserted as every act of this
  journey); control: the same with A up and `held_through` = `head` prints no such line and
  needs no `--yes`. The words are ADR-042's, the act is this one. Mutant: count only positions
  above the DAG prefix → the line names 0 when A's `held_through` is behind B's head → red on
  the same count and command assertion (ADR-042 TR-16's mutant).
  (b) **the release red**: A's image filled 90 s under B's posts, then freed (E-49a's staging,
  no knob); A leaves `room1`. v0.4.30: rc 1 `an internal error` (PRODUCT, run-with-receipt,
  `/tmp/Adr049Leave/run.log` 06:09:52; receipt lost in the reboot of 2026-11-13, figures as
  recorded in `adr-049-revision.md`; to be re-run as the fleet baseline). Candidate: rc 0, gone, `Undelivered` then `Delivered`
  and B's roster shows A gone within 60 s. Mutant under R1 (D1): in `drain`, keep returning
  `history retirement requires recovery` in deleting mode: the record is written and rc is 0
  (LE-1 answers after step 1), but the erasure never runs; red on `erasure: Erased` within 60 s
  of `Delivered` and on `cleanup stopped` in the log. Under R2 the same staging leaves no pinned
  flow (SY-19 deletes the pool) and the act keeps its assertions as the regression guard for
  item 86; mutant under R2: refuse the erasure while an exchange of `room1` is still in flight
  instead of cancelling it → `Erased` never reached → red.
  (c) still full (the image not freed, free space under SO-11's 3 MB; APPARATUS unless `df`
  shows it): A leaves `room2`. Candidate: LE-1 (ii)'s exact refusal with the disk words, rc 1,
  the room still listed. With the image at 3–10 MB free (a second staging, `df` asserted):
  rc 0 and `departure: Pending(StoreRecovery)` in `.left[]` and the `waiting` block; after the
  image is freed, `Signed` within 30 s and B's roster shows A gone. The staging selects the
  outcome; neither is accepted without its `df`. v0.4.30: rc 1 by code
  (`ensure_local_append_available_mode`, `leave.rs:58`): **owed**, the first run of this act on
  the release asset. Mutant (N5): answer success before the record's `commit`, with the
  mutant's own hold between its premature reply and its commit (`VOX_TEST_LEAVE_HOLD=reply`,
  observed as `leave of <room> held before commit`); kill there; at open the room is listed
  again → red on "absent after restart".
  (d) leave during wind-down, F16/F2: C's daemon stopped; A ends `room3`; B learns it and
  leaves it within 5 s (`known_ended`, rc 0, B's room gone, `.left[]` shows `Ended`); A's
  daemon stopped so B is the sole holder of the end; C starts **at +20 s, inside B's remaining
  wind-down**: C's `room list` shows `room3` `[ended: …]` within 30 s (B's hidden copy handed
  it on); B's record gone at +70 s. Mutant: erase B's copy at the leave instead of at the
  wind-down's end; C lists `room3` without the marker at +60 s → red. A second staging returns
  C only after +70 s and asserts the permitted outcome: C lists `room3` without the marker, a
  later `vox room join` of C with the room's link is refused as ended by the board (LE-7's
  residual, stated).
  (e) restart in every window: B's daemon stopped; A leaves `room1` with the hold at step 1,
  killed, restarted; hold at step 3, killed, restarted; A's `room list` never shows `room1`;
  `.left[]` names it across both restarts with `departure` moving `Pending` → `Signed`; B
  started: B's roster shows A gone within 60 s; A's record `Delivered` then gone. v0.4.30 red
  (item 27's `[failed: … has left the room]` after restart, rig26 +34 s, run-with-receipt;
  receipt `/tmp/plan-PlanD/keep/` lost in the reboot of 2026-11-13, row 64, figures as recorded in
  `rca-RcaFrozen.md`). Mutant: do not read the records before opening rooms; red on the
  `[failed: …]` row.
  (f) same-connection recovery, F5: B connected but answering the probe `SessionBusy` (B's
  daemon under RcaSlow's L2 load, as ADR-046 SY-10's act stages); A leaves; without any
  reconnect or inbound session, B's roster shows A gone within 60 s of the load ending. Mutant:
  park the probe on `PeerReachable` after a busy answer; A's record stays `Undelivered` for
  the act's 120 s → red.
  (g) refusal is not receipt, F7 (N5: the refusal must exist before the mutant runs): A is
  isolated from C (A's daemon stopped) **before** C leaves `room1`, so A still lists C as a
  member when A returns; C's copy is erased; A starts and leaves `room1`; A's probe to C is
  refused `authenticator invalid` (A's log and `last_failure` in `vox status --json`; the act
  asserts this refusal before anything else, else APPARATUS); A's record stays `Undelivered`;
  B returns; within 60 s B's roster shows A gone and A's record is `Delivered { peer: B }`.
  Mutant: count `AuthenticatorInvalid` as a receipt; A writes `Delivered { peer: C }` and
  erases; B lists A for ever → red at +60 s. A control in the same act: B behind A's last ten
  posts answers a stale echo (`has not acknowledged`, A's log); A does not complete; B catches
  up; then `Delivered`.
  (h) unsettled and own-behind leaves, F1: A joins `room2` (sparse) and leaves 0.5 s into the
  join, before settlement (`.left[]`: `Pending(Settled)`); A's hidden copy settles within 30 s
  with B reachable, `Signed`, B's roster shows A gone within 60 s. Own-behind: A restored from a
  copy of its store taken ten posts ago (the drill's backup staging), leaves; `Pending(OwnHistory)`;
  recovery completes (ADR-046 SY-11), `Signed`, delivered. Mutant: refuse the settlement
  rotation under the leave fence; `Pending(Settled)` until the clock step passes 2 days, then
  `Expired` → red on `Signed` within 60 s.
  (i) the two-day expiry, N6: every member stopped; A leaves `room1`; clock step 2 days + 1 s;
  `.left[]` shows `Expired`; with a Session retirement of `room1` held
  (`VOX_TEST_SESSION_CLEANUP_HOLD`) `vox status` prints `… no member could be told in 2 days;
  deleting, waits until this room's Session cleanup finishes …`; release: within 10 s `Erased`
  and `… deleted; …`; the room's rows are gone (`rooms[].store.messages_bytes` is 0, SO-15);
  clock step 24 h from `Erased`: the line and the `.left[]` entry are gone, and the `Member`
  entry in `.withdrawals[]` stays `pending` until the board answers, then goes (D3). Mutants: do
  not write `Expired` (the leaving line stays → red); print "deleted" at the bound (the
  held-cleanup sample shows "deleted" while `.left[].erasure` is `Erasing` → red).
  (j) parked purge, F11: a Session retirement of `room1` held (`VOX_TEST_SESSION_CLEANUP_HOLD`);
  A leaves, B receipts; `vox status --json .left[]` shows `Erasing` and the `waiting` block
  `… waits until this room's Session cleanup finishes`; release; `Erased` within 10 s. Mutant:
  fail the purge instead of parking (today's `refuse_owned_purge`); red on `Erased`.
  (k) the `None` outcome: A, not an author of `room3` (joined, never settled, store of that
  room made unreadable by the apparatus's corruption of its sealed row — APPARATUS unless the
  log says `could not read`): leave → rc 0, LE-1's `None` words, erased at once. Mutant: answer
  `Signed` for an unreadable room → the departure is never appended; red on the words.
  (l) the success words with everyone offline, R3: every member stopped; A leaves `room1`: rc 0
  and exactly `vox: left room "room1" (…); it is gone for you now; this node keeps a hidden copy
  for at most 2 days, only to tell its members you left, then deletes it`; `vox status --json
  .left[].erasure` is `Hidden`; no line containing `data is deleted` in A's status or log;
  then (i)'s clock step: at `Erased` the status line and one log line read `the room's data is
  deleted; what is left of it in this node's data file is cleared at the next rewrite, and until
  then only someone who holds that file and this node's passphrase could read it`. Mutant:
  print the `data is deleted` sentence at the leave's success → red on the first assertion.
  (m) the carry on a short disk, R5/S4: on ADR-047 SO-11's 256 MB fixture (the 64 MiB image
  cannot hold the 64 MB floor plus a store). B stopped; A has authored 1,200 posts B never
  confirmed; A leaves `room1` (rc 0); the clock step passes 2 days; **first staging, below
  the ordinary floor**: the fixture filled so `vox status --json store.free_disk_bytes` is under
  `store.floor_bytes + 2 × .left[].carry_estimate_bytes + 1 MB` (SO-15's and this ADR's fields,
  D9; ballast excluded; asserted before the act goes on): `.left[].erasure` reaches
  `Erasing { stage: carry }` and stays there with `deleting, waits until room room1 can save
  again` for the act's 60 s; A's source header rows and room key are intact (`.left[].sources`
  non-zero); no `No space left on device` in A's log. **Second staging**: free the fixture so
  `store.free_disk_bytes` exceeds that figure (asserted), then the `Erased` bound starts: `Erased` within
  60 s, at least two continuity carry rows (1,200 × 3.4 KB > 2 MB); B started; A rejoins
  through C (as LE-9's act 2); B's roster shows A once and B renders A's new post. Mutant: copy
  the whole suffix in the fence transaction → under the first staging the leave's step 2 is
  refused and `.left[]` never shows `Hidden` with a continuity, or under the second the
  reclamation ceiling is exceeded and `Erased` is never reached → red on its own stage. Mutant:
  delete the source header rows before the carry commits → A's rejoin never renders on B, or B
  names a fork → red.
  (n) the route inventory across a crash, S3/T1/U1/V2: A's room `room1` is published to the
  anchor only; a second board E (not in A's anchor configuration, reachable by a link) has **no
  publication row** for `room1` on A (`vox status --json .publications[]` has no E entry,
  asserted). **The U1 window, on E's first round**: A publishes `room1` to E (`vox room publish
  room1 <E's link>`, or the address exchange that triggers a first round) with the publisher
  held after E has answered the **address** put — the third of genesis, bundle, address
  (`actor.rs:9428-9444`, `:9532-9549`), the one a joiner needs (V210-96) — and before A files
  `PublishDone` (`VOX_TEST_PUBLISH_HOLD=after-address-put`, `test-knobs`; the ordering receipt:
  E's log `board: took a address record of room1 from A` (the LE-2 line) and A's log `publish of
  room1 to E held after the address put`, in that order, else APPARATUS); A's daemon killed there; E stopped; A
  restarted: `.publications[]` names E `attempted` (PRODUCT if E is absent); A leaves `room1`
  (rc 0): `.withdrawals[].routes[]` names the anchor and E; A's daemon killed after the leave's
  record and restarted: the routes are unchanged; E started: E answers the withdrawal (A's log
  `board E answered the member withdrawal of room1: taken`) and a fresh node's join through E is refused as
  withdrawn for A. Mutant: write the inventory row only on `PublishDone` (revision 7's rule) →
  after the restart `.publications[]` has no E, the withdrawal never names E, the fresh node's
  join through E is admitted with A's records → red on the same assertion. Mutant: keep the
  inventory in RAM (today's `board_routes`) → the same red. (n2, the RAM-only restart without a
  crash in a round) as revision 8's act: E published and `published`, A restarted normally, E
  still named; mutant: RAM only → red.

  **Journey B — the ended room** (extend
  `an_admin_the_creator_named_ends_a_room_and_then_it_takes_no_new_message`). (1) Member M's
  daemon stopped; A ends R: within 70 s `vox room list` on A has no R; no `vox status` sample
  during or after the wind-down has a `sync failing` line for R; A's log has no `cleanup
  stopped`; every sample before deletion shows `[ended: …]`. v0.4.30 red on the alarm, release
  asset, no knob (E-64b +50 s, run-with-receipt; receipt `/tmp/adr040/run64b/rig.log` lost in the
  reboot of 2026-11-13, row 64, figures as recorded in `adr-040-revision.md`; PRODUCT).
  This act is the control of (1b): M, stopped, refuses nothing. **(1b) the refusing member**
  *(r13: R12-6)*: M up; A ends R; M takes the end (gate: M's `vox room list` shows R
  `[ended: …]` within 10 s, else APPARATUS); M's wall clock alone is stepped 60 s
  (`VOX_TEST_CLOCK_STEP_MS` on M; this ADR's in-tree proof, `test-knobs`, X049-11), so M's
  wind-down ends and M erases R while A's has at least 45 s to run (gate: M's `vox room list`
  has no R by the end + 15 s, else APPARATUS); A's `Have` stream and every request for R toward
  M are now refused by M as room not held — observed on M, not inferred: `vox status --json
  .peers[] | select(.id == A).served.last_refusal` names R within 10 s of M's erasure (ADR-042's
  field; else APPARATUS). Product: no `vox status` sample on A through deletion has a `sync
  failing` line for R; every sample before deletion shows `[ended: …]`; A deletes R at its own
  wind-down's end (+60 s to +70 s from the end entry), not before. Mutant (D6): count a
  member's refusal of an ended room in the sync book → a `sync failing` line for R appears
  within the wind-down → red. (2) A's room with a flow in
  `retirement_failed` (journey A's staging; R1 only, D1) ended: gone within 70 s (v0.4.30:
  `cleanup stopped` ×737, RcaSchedStall control (iii), run-with-receipt; receipt
  `/tmp/RcaSchedStall/receipts/` lost in the reboot, row 64, figures as recorded in
  `rca-RcaSchedStall.md`; PRODUCT). Mutant: `Retire::Keeping` for the ended purge → red
  with `cleanup stopped`. Under R2 this act's staging produces no pinned flow (SY-19 deletes the
  pool); the act then stages the same full-disk cycle and asserts the end's erasure within
  70 s, mutant: refuse the erasure while an exchange of R is still in flight → red. (3) A
  restarted 20 s into the wind-down: R is `[ended: …]` at restart +1 s and gone no sooner than
  60 s after the end entry's time and no later than +70 s; v0.4.30 deletes it at the first tick
  (E-64b act 2, run-with-receipt, receipt lost as above; PRODUCT on
  the "no sooner" bound). Mutant: measure from the open → red. (4) A purge parked on
  `PolicySave` *(changed r13: R12-3, R12-5; fix-list item 93)*: A ends R; 5 s before the
  wind-down's end a roster change on A's computer (`vox node create` there: item 93, every
  roster change is a computer-policy revision) starts a native policy save, with
  `VOX_TEST_HOLD_POLICY_SAVE` armed for A: the save's worker holds immediately before
  `policy.run` with `pending_policy` installed and the actor free (gate: A's `engaged` file
  reads `native policy save held`, else APPARATUS; D4 — ADR-048's
  `VOX_TEST_TRUST_WITHDRAW_HOLD_FILE` holds a room's withdrawal, not the save, and
  `VOX_TEST_HOLD_COMPUTER_POLICY` holds the message before any save exists). Product: within
  5 s of the bound `vox status` shows `ended: …; deleting, waits until this node's trust save
  finishes`; during the hold the unrelated room keeps syncing (B's post in `room2` is read on
  A within 5 s): the actor is free, and under ADR-048 TC-4 the save inspects, reserves and
  waits for no room, and TC-5 holds at most the room a pass is working on — so the purge waits
  on the save, the save on nothing of R or `room2`, and no cycle exists; the act does not lean
  on the tag's pre-batch preflight parking (item 93), which TC-4 deletes. After the release the
  purge completes within 10 s; then `vox status --json .rooms[]` has no entry for R,
  `.unhealthy[]` no line naming R (F11/F12), and the replacement's resource book is clear of
  R: `.sync_node.slots.owners[]` and `.sync_node.permits.owners[]` (ADR-046 SY-24's one
  schema, ADR-042 Appendix A) have no entry with `room` = R and `.lanes.ports[]` no row for R
  (R12-5; a room's disappearance and the absence of an alarm prove nothing about these); under
  R1 also `.lanes.bounded.cleanup_errors` has none for R (a field SY-19 deletes with the
  ledger; D1). Mutant: skip the ledger disposal (R1) / leave the cancelled exchange's slot owner
  for R in place after its task is joined (R2) → `.sync_node.slots.owners[]` names R after
  deletion → red on the JSON. (5) End then Leave with the board offline, F2: the anchor stopped; A ends R; A leaves R
  5 s later (`known_ended`); R gone from A at +70 s; the anchor started: A's `Room` withdrawal
  reaches it (A's log `board <anchor> answered the room withdrawal of R: taken`, the LE-5 line, within 30 s; PRODUCT if absent); C, never a member,
  `vox room join` with R's link → `that room has ended` (`JoinedRoomEnded`). Mutant: let the
  leave's `Member` entry replace the `Room` entry; C's join is answered as a member withdrawal
  or admitted → red. (5b, U2) as (5) with the anchor configured out of A after the restart (so
  E, the board, is known only by its journal row): after R is `Erased` on A, `vox status --json
  .withdrawals[]` still names E unanswered for the `Room` wire and `.publications[]`
  still holds E's row; E started and A's connection to it filed (staging gate: A's log
  `connected` for E, else APPARATUS); **product**: E answers (A's log `board E answered the
  room withdrawal of R: taken`, the LE-5 W3 line; PRODUCT if absent within 30 s)
  and only then do both rows go. Mutant: delete the publication rows at stage (d) → after
  `Erased` `.withdrawals[].routes[]` lacks E, E never receives the End, a join through E is
  admitted → red. (8, U3/V1) one board, two scopes and two wires: A creates R, publishes it to E
  (a non-anchor board), B joins; E stopped. **Two scopes**: A leaves R (`Member` wire, instance
  1: its routes are instance 1's rows, so E); A rejoins R through B — a new attachment, instance
  2, which has never published to E — and, as creator, ends R: the `Room` wire's routes are
  **every** retained publication row of R (W2r), so E through instance 1's row, asserted:
  `vox status --json .withdrawals[]` on A shows both wires with E in `routes[]`, the `Room`
  wire's E route carrying `instance: 1` (PRODUCT if the `Room` wire lacks E). E started with A's
  put order fixed so that E's answer to the `Member` wire is filed first
  (`VOX_TEST_WITHDRAW_ORDER=member-first`, `test-knobs`; staging gate, APPARATUS if not met:
  A's log `putting the member wire for R to E`; **product**: E's log `board: took a member withdraw of R from A`
  before `board: took a room withdraw of R from A`, both within 30 s — PRODUCT if the room line never
  appears, which is the routing mutant's state) *(r11)*: after that answer `.withdrawals[]` shows the `Member` wire for E answered and the
  `Room` wire for E **not** answered; after E's second answer both are, and a fresh node's join
  through E is answered as ended. **Two instances**: `.publications[]` shows instance 1's row for
  E (frozen) and instance 2's rows (the anchor) side by side until each wire is answered; then
  W5's cleanup runs for each wire and P4 removes instance 1's row (no reference, not held) and
  instance 2's (R is ended and erased, not held). Mutant: one `done` flag per `(room, board)` →
  the first answer marks the `Room` wire answered; the second wire is never put to E; the fresh
  node's join through E is not answered as ended → red. Mutant: route the `Room` wire by its own
  instance only (revision 8's rule) → the `Room` wire lacks E; E never receives the End; the
  join through E is not answered as ended → red. Also asserted (R9-1): after the anchor
  (instance 2's only row) has answered the `Room` wire and before E returns, `.withdrawals[]`
  still lists the `Room` wire `pending` with E unanswered (PRODUCT if it is `complete` or gone).
  (8b, V3/R9-2/R10-1) kill during cleanup: as (8), with A's daemon killed at the physical
  boundary **immediately after W5b's last answer-row deletion and before the next write**,
  whatever that write is (`VOX_TEST_LEAVE_HOLD=cleanup-entry`, `test-knobs`; the hold is defined
  by the deletion, not by the entry's state). **Staging, APPARATUS if not met**: the hold
  engaged (A's log `cleanup of withdrawal <wire>: last answer row deleted, held`), the entry
  still exists (`.withdrawals[]` lists the wire), and its `answer_rows` is 0 (D9). **Product,
  asserted at the hold**: the entry's `state` is `complete` (PRODUCT if `pending`: the
  completion marker was not written with the last answer, LE-2 W5a). Then A's daemon killed; E
  stopped; A restarted: within 10 s `.withdrawals[]` no longer lists the wire, with E down — no
  board answered again, and A's log has no `putting the room wire for R to E` line after the
  restart; then E started and sampled for 60 s: E's log shows no second `board: took a room
  withdraw of R from A` (the baseline has exactly one, from act (8)). Mutant: delete the answer
  rows before marking the entry complete → at the hold the entry is `pending` (red on the
  product assertion at the hold); after the restart the entry stays `pending` with E unanswered
  and the wire is put to E again when E returns (red on "no `putting` line" and on E's second
  `took a room withdraw`). Neither red is APPARATUS: the
  staging gate names only the hold, the entry's existence and the absence of answer rows, all
  of which the mutant's state also satisfies.
  (6) End arriving after a leave *(changed r13: R12-7; changed r14: R13-1, R13-4)*: B's own
  history is behind, as LE-9 act 6 stages it (B's older store copy restored, A up, A's
  verified `Head(me)` above B's head), with B's own-feed recovery held before its fetch
  (`VOX_TEST_OWN_RECOVERY_HOLD=R` on B); B leaves: `Pending(OwnHistory(R))` — gate: B's
  `.left[].departure` is `pending` with its words and `.waiting[]` lists `(R, DepartureSign)`
  on `OwnHistory(R)` (ADR-040 NW-4), else APPARATUS. B's daemon stopped. A posts Content X in
  R (an ordinary post B's hidden room never fetches the body of) and then ends R: the End's
  previous own entry is X. B started: B's hidden room takes the End through control coverage
  and must close it — `CLOSE(E)` needs X's witnessed header, fetched with `Range{bodies:
  false}` (LE-3's allowance, R13-1); asserted on B: `.rooms[] | select(.room == R).members[] |
  select(.id == A)` shows `headers_through` ≥ X's position and `held_intervals` not covering X
  (header taken, body not), and B's record moves to `Ended` within 10 s of B's connection to A
  — B's `.left[]` sampled at 1 Hz, T_e the first sample that says so; B's copy is erased at the
  wind-down's end measured from the end entry. Independent gate that cancellable work existed:
  B's log `own-history recovery of R held` appears before T_e (SY-11 orders own-feed recovery
  first; else APPARATUS). At T_e + 5 s the hold is released. After T_e B asks A nothing more
  for R: on A, `.rooms[] | select(.room == R).members[] | select(.id == B)` read at T_e + 30 s
  and again just before A's own deletion shows `last_request_from_ms` ≤ T_e + 2 s and
  `in_flight` empty (ADR-042 Appendix A's per-member fields; PRODUCT otherwise; the exchange
  that fetched the End and X's header is the last request). Mutant (D6/R13-4): do not cancel
  the hidden room's own-feed recovery at the End → the released recovery fetches B's own
  entries from A → `last_request_from_ms` advances past T_e + 2 s → red. Mutant (R13-1):
  forbid a hidden room every non-control header → `CLOSE(E)` never completes, B's record
  never reads `Ended` (red at T_e + 10 s), and `headers_through` stays below X. The app's ended
  marker is proved in the app's first-run journey (`FirstRunProof.swift`, the `room-health-`
  keys, as ADR-042 TR-22 does; D5) under ADR-034 PF-3 with the mutant "omit the marker" red on
  that row's text.
  (7) the member veto, R4: the anchor (a board holding R's admission notices) stopped; C leaves
  R (`Delivered` via A, `Erased`); clock step 8 days; the anchor started and C's connection to
  it filed (C's log `connected` for the anchor, else APPARATUS); **product**: C's `Member`
  withdrawal reaches it (C's log `board <anchor> answered the member withdrawal of R: taken`, the LE-5 line; PRODUCT if absent within
  30 s) and a fresh node D's `vox room join` through that board is not handed C's old admission
  notice as a current member (D's roster after joining shows C absent). Mutant: drop the
  `Member` entry at 7 days → C never puts the withdrawal (red on the `taken` line), the board
  hands D the old notice, D's roster lists C → red. *(r11: the `taken` line is a product
  assertion, not a staging gate, so the mutant's own state is judged on it.)*

### 6. Coming back

- **LE-9. A rejoin of a room this node left is a fresh join: the hidden copy and every
  leftover of the old membership are discarded first, the node's own signed feed continues
  without a fork, and the person sees nothing older than the join and no refusal.** *(new in
  r2: the decider, 2026-11-13, row 34; fix-list item 10; row 22. **Changed r3: N1, N2, N5.**)*

  *What the person sees.* `vox room join <link>` on a node that left the room (any state: the
  departure not yet verified, verified, erasure in progress, the room ended meanwhile) runs as
  a first join: the room's anchors come from the link; `vox: joined <name>` is printed within
  ADR-046 SY-10's bound; `vox room read` shows no row older than the join (ADR-046's row 38
  ruling for bodies: from the join onward; for members and rules, SY-27's fence post, row 65, which supersedes row 38 for governance); `vox room post` is
  admitted at once after `joined` and MUST NOT be refused `own history behind what a member
  holds` (item 10: six minutes on v0.4.30); `vox status` shows the room as any newly joined
  room. The join is admitted by one member unless the room is near its member cap, and a
  member that does not answer never fails it (row 37; ADR-046 SY-10 owns the cap protocol).
  One exception, said truthfully rather than hidden: when the admitting member proves, by a
  `Head(me)` answer this identity's own signature verifies, that it holds **more** of this
  node's feed than the node's checkpoint names (possible only after the node was restored from
  an older copy of its store: RL-8.5's case), the join completes but writing waits on
  `OwnHistory(room)` as RL-8.5 requires, `vox status` says `own history recovery is pending`
  as today, and `joined` is followed by `     your earlier entries here are being recovered
  from <member>; posting resumes when they are`.

  *Why the continuity, not the head.* A signed head is a commitment, not the material an
  append needs: the own-entry constructor reads the append forest and root context for
  position head + 1 (`prepare_own_append_ranges`, `own_history.rs:1518-1586`) and the entry
  hashes at the predecessor and at `lipmaa(n)` (`pending_text.rs:1110-1121`), and refuses
  `OwnHistoryBehind` when they are missing. After erasure the rows that held them are gone,
  and the admitting member may hold less of this feed than the node had (A's feed 10, B
  confirmed it and verified the departure at 11, A erased; A rejoins through C, which holds
  5: C cannot supply 6–11). So the node keeps the continuity (LE-2 step 2: everything those
  two functions read at head n, all O(log n), plus the carry) and appends from it: writable at
  once, from its own authenticated material, whoever admits it. The RL-8.4 marker alone (head,
  epoch, generation, genesis, `own_history.rs:25-60`) is not that material; RL-8.4 is amended
  below. The rules that were weighed instead, and why they cannot work, are in the review
  record (revision 5's review). ADR-046 SY-11's sentence "nothing from the discarded copy sets
  the fence" stays true: the continuity sets where the node writes from, never a fence; the
  fence (`own_behind`) is set only by a member's verified signed `Head(me)` above it.

  *What the fence post gives a returning node, and what it does not* *(r5: row 65; changed r6:
  S5)*. Under ADR-046 SY-27 a newcomer starts from the creator's **last** signed summary of
  members and rules and verifies what came after, taking one chunk per author; a node that
  left and comes back is a newcomer for that purpose: it does not replay the room's control
  history. The roster every member holds is that summary plus the authenticated membership
  changes after it: a verified admission, departure or return updates every online member's
  roster the moment it is verified, without the creator (who may be away: row 65); the
  creator's next fence post consolidates those facts, it does not activate them. What the
  fence post cannot give the returning node is the continuity of its **own** signed feed: a
  fence post summarises membership and rules at a position, not an author's entry chain, and
  the creator's word about membership is not this author's signature over its own history. So
  LE-9 keeps its own continuity (R1, S1) regardless of the fence post, and SY-27's
  chunk-per-author start applies to this author's own feed only above its continuity head
  (contract below).

  *What is discarded, and what is carried.* In the join's first durable step, before any
  admission is sent (`rejoin: Preparing`): the `(room, DepartureSign)` and
  `DepartureDelivery(*)` obligations are retired; the hidden copy's rows are deleted (LE-4
  step 4's stages, instance-qualified; the record says `Erasing`); the `Member` withdrawal
  entry is dropped if unsent or, if already put, left to the board's rule that a member
  joining again publishes newer records, which are taken (`nat/withdraw.rs:23-25`); the
  RL-8.2a note is dropped. **Carried**, from the continuity marker, not from the room: the
  continuity (the append material for head + 1), and the **carry** (the signed headers of this
  author's entries above the carry boundary, and, for each of them that is a lifecycle entry —
  the departure's `Presence(false)`, a rotation's `Presence(true)` — its public payload, a
  few hundred bytes, so a member can project it (S2: a header authenticates a payload by its
  hash, `log/entry.rs:448-453`, and the fold needs the body, `governance/channel.rs:883-901`);
  no post body), pushed as the node's first entries in the join exchange (RL-8.1a: "what the
  node holds goes first"; ADR-046 SY-17's exchange): header-only posts a member holds as it
  holds any entry whose body it lacks, lifecycle entries whole. Nothing else: no received rows,
  no keys, no sender state, no cursors, no anchors, no post bodies. The carry is invisible to
  the person: it is not in the new room's render, index or cursor frontier (row 38: bodies from
  the join onward). It exists so that a member that never got the departure, or that lacks the
  suffix, can verify the chain it later sees and learn the departure; it brings back no words of
  the person's.

  *The own head and the return* *(changed r5: R1; changed r6: S1)*. What the node holds decides
  the case; what the admitting member answers decides the order.
  **Case 1, continuity held** (the marker holds the continuity of LE-2 step 2): (i) when the
  admission's verified `Head(me)` (SY-17; this identity's own signature, never a `Have`,
  SY-11) is **at or below** the continuity's head, the local continuation needs no peer: the
  join installs the continuity as the own append frontier and signs the return
  (`Presence(true)`, RL-8.1b) at head + 1 from its forest, context and hashes, with a sender
  generation above both the continuity's and any the member's answer shows; `joined` is
  printed after the return is durable. No prefix comparison with the member is a prerequisite:
  the continuity was derived under the own-writer gate from an authoritative head, and the
  node cannot prove an arbitrary older prefix from it (the forest for 11 holds 1–8, 9–10 and
  11, not 5), so it does not try. A member whose head is below (C at 5) holds A's return and
  carried entries as a range it still wants filled (`feed.rs:244-262` checks each entry's
  predecessor and back-link as the chain fills, from a holder of 6–11 or from the carry) and
  shows them as `waiting for a member` (ADR-042 TR-2) until then; a chain that does not fill is
  a gap; a chain whose filled entries contradict what C holds is detected by C's feed check at
  that moment — that, and only that, is a fork, and C freezes the author as today
  (`log/dag.rs:684-703`). Missing proof is never classified as a fork. (ii) When the admission's
  verified `Head(me)` is **above** the continuity's head (the restored-older-copy case,
  RL-8.5), **no return is signed yet**: `joined` means admitted and readable; the words
  `     your earlier entries here are being recovered from <member>; posting resumes when they
  are` follow; recovery fetches the entries with their ranges (SY-11), the existing check
  compares the recovered prefix root at the continuity's size with the continuity's root
  (`own_history.rs:1433-1449`): equal → recovery completes, the return is signed at the
  recovered head + 1 (the order `Work::Complete` keeps today, `pending_recovery.rs:435-485`),
  posting resumes; unequal → `Recovery::Fork`, the author frozen as today, RL-8.5's disclosed
  residual after an erasure or a restore, not repaired here.
  **Case 2, a marker with a signed head and no continuity** (the room was erased with the
  departure never signed: `Pending(OwnHistory|Settled)` at the bound, LE-2 writes no
  continuity from a head a member may hold more of; the RL-8.4 marker still names the last
  own signed head n): the node knows it signed through n and holds nothing to continue from.
  It MUST NOT sign at any position until a member supplies this feed through n (recovery under
  RL-8.5, the material then reconstructed and checked as in case 1 (ii)); an admitting member
  that holds none of the feed, or less than n, does not change that, however long it lasts:
  `joined`, then `     your earlier entries in <name> (<n>) are held by no member reached yet;
  posting here waits until one is`; writing waits on `OwnHistory(room)`; the wait is listed in
  `vox status` and may last until a holder returns, or for ever if none exists (the person was
  told at the leave, TR-16, that those entries were held by nobody). It is never RL-8.7's
  absent-history case: a known signed boundary is not absent history. Here n is the higher of
  the marker's own signed head and the verified supplied head LE-2 step 2 kept with it *(r7:
  T2)*. **A second leave of such a room** (LE-1 applies to it as to any held room: the person
  can leave again, and the record, departure and expiry follow LE-2–LE-4) MUST NOT erase the
  marker or the supplied head: the next join is case 2 again, never case 3; only a verified end
  retires the boundary (RL-8.4). The person is not offered a way to turn a known boundary into
  absent history.
  **Case 3, neither** (no marker: the room was never authored in, or the marker was consumed
  by a verified end, RL-8.4): RL-8.5's unmarked binding: `joined`; the admitting member's
  verified `Head(me)` sets the recovery target if it holds any of this feed; when the join
  exchange and the following rounds find no member holding any, RL-8.7's authenticated
  absent-history classification applies (a fresh head, with the residual fork risk RL-8.5
  discloses, said in status as today). Only this case may start a fresh sequence.

  *What the other members see.* Two events, in feed order: the old membership's departure
  (`here = false`, if it was signed and delivered or is carried into the join) and the return
  (`here = true`, new generation). Their roster shows the identity gone and then back; its
  consents start over on the authenticated return (`governance/evaluator.rs:914-917`). A
  member that never received the departure sees only the return: its roster never showed the
  identity gone, and that is the truth of what it knew; its consents for this author restart
  all the same. Under the fence post (row 65) the roster a newcomer sees is the creator's
  summary: gone in a fence post signed after the departure, present in the one after the
  return.

  *The four states.* (1) Departure not yet verified (`Undelivered`, hidden copy present): as
  above, the departure in the header carry. (2) Verified (`Delivered`, `Erased`): only the
  marker with its checkpoint and header carry, the note and the record remain; nothing to
  discard but the note. (3) Erasure in progress (`Erasing { stage, cursor }`): the join's
  network exchange proceeds; installing the new room's rows waits for the **old instance's**
  last batch as a named wait `(room, JoinAfterPurge)` on `RoomRowsPurged(room, old instance)`
  (ADR-047 SO-9's instance-qualified completion; a completion for another attachment opens
  nothing), said as `joining <name>: waits until its old copy is erased` (seconds for an
  ordinary room; SO-9's batches bound it; a carry stage parked on `StoreRecovery` holds the
  join with it and says so); the purge is of the old instance's rows only and never sweeps
  the new attachment's. (4) Ended meanwhile (the hidden copy in wind-down, or the note says
  ended): the join is answered as ended by the member or the board (`JoinedRoomEnded`,
  unchanged words); the hidden copy keeps winding down; nothing is discarded by a refused
  join. In every state the continuity and carry, if they exist, are the marker's and survive
  the state; a marker without continuity is case 2 above, no marker case 3 (D11).

  *Crash windows* (the daemon killed at each boundary; the on-disk state after it). The join
  has the three durable states ADR-023 RL-8.7 and the shipped code already distinguish:
  **Preparing** (the link parsed, nothing accepted), **Accepted** (the member's verified
  acceptance durable: proposal, final witness, verified genesis, name reservation and SEK wrap
  in the accepted-joins journal, `retain_accepted_join_native`, `metadata_save.rs:157-189`),
  **Installed** (the room's rows exist and `joined` was printed).
  - Before the first durable step: nothing; the room is still left.
  - `rejoin: Preparing`, killed during the purge or the exchange before acceptance: at open the
    purge resumes from the cursor; the join is **not** resumed (its command died with the
    daemon, ADR-041's words); RL-8.6's cleanup removes the transient projection and RL-8.7's
    uncertain-withdrawal rule applies (a retry publishes past its rollback-withdrawal
    timestamp); the continuity and carry are durable rows of the RL-8.4 marker, not of the
    record, and are kept (D11); the person runs the join again and it finds state (2) or (3).
    The record's `Preparing` is cleared at open; the record itself stays until erased and
    forgotten by LE-2 step 5, or until a later join installs.
  - **Accepted** durable, killed before `RoomRowsPurged` or before installation: the accepted
    join is an obligation the daemon owns and resumes at open with the **same** witness and
    wrap (`JoinAccepted::Resumed`, `actor.rs:4563-4592`), never re-admitted and never expired
    by this ADR; `queue_unpublished_purge` already refuses an ordinary purge while it exists
    (`metadata_save.rs:4370-4394`); `JoinAfterPurge` composes with it: the old instance's purge
    runs to `RoomRowsPurged`, then the accepted join installs. The record says `rejoin:
    Accepted` so the open knows the room is being joined, not left: no departure probe, no
    two-day expiry of the record, no `Expired` line. The two-day bound of LE-4 applies to
    `Preparing` only.
  - Installed: the record is forgotten in the installing transaction (the one durable handoff:
    `Forget` of `left-rooms/<room>` and the new attachment's remember in one batch), so an open
    that reads records first never meets a record for a room that is held; a record whose
    `instance` is not the held room's instance is a finished purge record, never a hidden-room
    marker.
  - *Why*: the decider's words; item 10 (`io-repair-drill` run A `rig.log:275`: `joined` rc 0
    at +214.5 s then post rc 1, own-feed recovery competing for the Background position,
    ADR-046's cause); review N1 (a head is not append material; the short-admitter case), N2
    (an accepted join is not transient).
  - *Changes*: `vox room join` on a recorded room: the discard step before admission
    (`room_cli.rs` join path; the actor's join entry, where RL-8.7's name reservation already
    checks held rooms); `JoinAfterPurge`; the continuity installed as the append frontier
    (`prepare_own_append_ranges` and `Entry::build_signed` read it from the marker row when
    the room holds no rows); the carry as the join's first push (ADR-046 SY-17's exchange);
    the return's generation rule and its ordering after recovery; the record's `rejoin` and
    `instance` fields; the marker's `continuity` fields.
  - *Deleted*: nothing; a leave during a rejoin cancels it, as today.
  - *Proof*: extend `a_node_leaves_a_room_proof.rs::a_node_leaves_a_room_and_the_others_see_it_gone`
    (ADR-046 SY-11's rejoin act lives in the same file; one act serves both, with SY-11's 10 s
    bound). Three computers A, B, C in R: A posts 10 entries; B reads all 10; C is stopped after
    reading 5 (C holds A's feed through 5; stated and asserted with `vox status --json` on C
    before it stops). Act 1 (state 1): B stopped; C started; A leaves (`Undelivered`); A rejoins
    at once through C (C admits alone: row 37): `joined` within SY-10's bound; `vox room read`
    on A shows none of the ten; `vox room post` rc 0 within 10 s of `joined`; C's roster shows A
    once, as a member; C shows A's new post as `waiting for a member` until B returns (C lacks
    6–11), then rendered; B started: B's roster shows A once; B's `vox room read` shows the new
    post; B's roster history shows the departure before the return (the words are ADR-042's).
    Act 2 (state 2, the short admitter): B stopped, C running as before; A leaves while B is
    still up, B receipts, A's record `Erased`; B stopped; A rejoins through C: same assertions,
    A's status never says `own history recovery is pending`; B returns: C renders A's post
    within 60 s. Act 3 (state 3): R with 5,000 posts; A leaves, B receipts; the purge held at
    its cursor (`VOX_TEST_PURGE_HOLD=<room>`, `test-knobs`; observed as `purge of <room> held at
    batch <n>`, else APPARATUS); A rejoins: `joining R: waits until its old copy is erased`;
    release; `joined`; same assertions. Act 3b (N2): as act 3, with the hold still on, A's
    daemon killed once `vox status --json .left[].rejoin` reads `accepted` (the accepted-joins
    journal written; D8) and restarted: the purge finishes, the join installs **without a second
    admission** (C's `vox status --json .rooms[].admissions` for R counts one admission of A;
    the LE-9 row below), `joined` state in `vox room list`, post rc 0, one membership
    on C's roster. Act 4 (state 4): A leaves; B ends R; A rejoins → `that room has ended`; A's
    hidden copy gone at +70 s; A's `.left[]` shows `outcome: Ended` and `rejoin: none` (the
    refused join discarded nothing). Mutant (D6): let a refused join discard the hidden copy →
    A's `.left[].erasure` is `erasing` before the wind-down ends, and C (a member offline since
    before the end) never receives the end from A → red. Act 5 (restored older **left** snapshot, R6): A posts 5, leaves
    (`Signed` at 6), B receipts, `Erased`; A's daemon stopped and its data directory copied —
    the copy holds the `LeftRoom`, the marker and checkpoint at head 6 and no room rows
    (asserted with `vox status --json .left[]` before the copy); A started, rejoins through B
    (return at 7), posts 5 more (8–12); A's daemon stopped, its data directory replaced by the
    left snapshot; A started, rejoins through B: B's verified `Head(me)` is 12, above the
    checkpoint's 6: `joined`, then `your earlier entries here are being recovered from B`,
    `vox room post` refused `own history behind` until recovery (B supplies 7–12 with their
    ranges; the recovered prefix root at 6 equals the checkpoint's), then rc 0; B's roster one
    membership; no fork named on B. Act 2's short admitter is kept short through the exchange:
    C's ordinary catch-up is held (`VOX_TEST_CATCHUP_HOLD=<room>`, `test-knobs`; observed as
    `catch-up of <room> held`, else APPARATUS) from before A's leave until after `joined`, and
    C's head of A's feed at the exchange is read from A's `vox status --json .rooms[]`:
    `.own_feed.members[] | select(.id == C).held_through` (5; ADR-042 Appendix A's row, LE-9;
    r13: R12-4, the one convention), asserted
    (D8); A holds no rows then: it erased in state 2, so there is nothing C could have caught up from.
    v0.4.30 red: act 2's refusal is item 10 (**run-with-receipt**, another
    agent's run on the release asset: `/tmp/rca-IoDrill/runA/rig.log:275` (receipt lost in the
    reboot of 2026-11-13, row 64; figures as recorded in `io-repair-drill.md`), `joined` rc 0 at
    +214.5 s then post rc 1 `behind what a member holds`; run C about 6 min, PRODUCT); acts 1,
    3, 3b and 5 are **owed** (v0.4.30 has no checkpoint, no hidden-copy rejoin path and no
    accepted-join-over-purge case; the run that settles them is this proof's first run on the
    release asset). Mutants, each on the act's own assertion: skip the discard (act 1: `vox
    room read` shows the ten old rows → red); install the head from the admitting member's
    forged `Have` instead of the verified `Head(me)` (SY-11's staging: an apparatus member
    answers `Have` at 1,000,000 and `Head(me)` at the true head; act 2: the post is refused
    `behind what a member holds` → red); install the room before `RoomRowsPurged(room, old
    instance)` (act 3: `vox room read` shows old rows, or RL-8.7's name reservation fails the
    join → red); drop the continuity and keep only the old marker (act 2 through C: `joined`
    but the post is refused `OwnHistoryBehind`, or `joined` never prints within SY-10's bound →
    red); reset the continuity's head to the marker's head minus one (act 1: A signs the
    return at a position the departure occupies; B freezes A's feed, `vox status` on B names a
    fork for A, A's post never shown on B → red); expire or re-admit an accepted join at open
    (act 3b: C's log shows two admissions, or `vox room list` on A lacks R → red).
    Act 6 (S1/T2, the marker without continuity; staged by the product's own commands): A posts
    10 in R, B and C hold them; A's daemon stopped and its whole data directory copied (the
    snapshot: marker 10, rows 10, asserted with `vox status --json` before the stop); A started,
    posts 10 more (11–20), B reads them; C stopped before them (C holds through 10); A's daemon
    stopped, its data directory replaced by the snapshot; A's own-history recovery held
    (`VOX_TEST_OWN_RECOVERY_HOLD=R`, U4: the signed-head and inventory exchange runs, the fetch
    and install of this author's own entries do not) and A started: A's inventory exchange with
    B verifies B's `Head(me)` at 20; A's log shows `own-history recovery of R held` and `vox
    status` on A says `own history recovery is pending` with `.rooms[].own_feed` `head 10,
    recovery_target 20` (D9; all three asserted before anything else; else APPARATUS: the hold or
    the prefix was not achieved); B stopped; **the hold released** (the file removed; the log
    shows `own-history recovery of R released`), so what follows is the product's own behaviour
    with no donor; A leaves R: `Pending(OwnHistory)`, no continuity written, the marker row keeps
    head 10 and the supplied boundary 20 (`.left[]` shows `continuity: marker-only, head 10,
    supplied 20`); clock step 2 days: `Expired`, erased unsigned, the marker row kept; A rejoins
    through C (C holds through 10, less than 20): `joined`, then `     your earlier entries in R
    (20) are held by no member reached yet; posting here waits until one is`; `vox room post`
    refused with those words; A's log shows no return signed; C's roster shows A admitted, with
    no return entry; B started: within 60 s A's status drops the wait (B supplies 11–20 with
    their ranges; the recovered prefix root at 10 equals the marker's), the return is signed at
    21, post rc 0, B's and C's rosters show A once, no fork named (PRODUCT if a return is signed
    below 20 at any point, or if the wait does not end within 60 s of B's return). Mutant: treat
    marker-only as RL-8.7's absent history when C's head is below the supplied boundary → A
    signs a return at 11 (red on "no return signed"); B returns and freezes A (`vox status` on B
    names a fork). Mutant: drop the supplied boundary from the marker row at the leave →
    `.left[]` lacks `supplied 20` (red on its retention), and A signs at 11 from C's 10 → the
    same red. Mutant: sign the return at `joined` before recovery in act 5 → B names a fork → red.
    Act 7 (S2, the departure's body): B stopped before A leaves; A leaves (`Signed` at 11, the
    departure's Presence body in the continuity); clock step 2 days (`Expired`, erased: no node
    holds the departure's body but A's continuity); A rejoins through C (C holds through 5):
    `joined`; B started: within 60 s B's roster history shows A **left** (the departure at 11)
    and then **back** (the return at 12), in that order, and B lists A once; C the same once it
    has 6–10 from B. Mutant: carry the departure's header without its body → B's roster history
    shows no departure (the fold has no body to project: `governance/channel.rs:883-901`) and
    B's consents for A never restart → red on the history line.
    Act 1 additionally asserts S5: the creator of R is a fourth computer D, stopped from before
    A's leave until the end of the act; C (not the creator) admits A's return; C's roster shows
    A once and renders A's new post before any fence post signed after A's return exists (D is
    down). Mutant: show a returned member only from the next fence post → C's roster lacks A
    while D is down → red.
  - *Depends on*: ADR-046 SY-10 (the join; row 37's cap protocol), SY-11 (own-feed recovery
    first; `OwnHistory`'s release; "nothing from the discarded copy sets the fence"), SY-17
    (the join answer carries the own-feed range; a member holds a wanted range it cannot yet
    verify); ADR-047 SO-9 (`RoomRowsPurged(room, instance)`); ADR-023 RL-8.4 (amended below),
    RL-8.5–RL-8.7 (unchanged); ADR-042 (the words a roster history prints; `waiting for a
    member`).

## Unchanged rulings

- ADR-023 RL-8.1 (the room is deleted; every row and key; the RL-8.4 exception), RL-8.1b
  (a departed author is out of rosters and key delivery once its departure is authenticated; a
  rejoin moves to a higher generation and says it is back), RL-8.2 (End: 60 s wind-down;
  boards; the creator's room-scope withdrawal and its endorsement retry), RL-8.2a (the
  ended-room note), RL-8.3 (no `vox room forget`; the record's bound is why none is needed),
  RL-8.4 (continuity marker; its contents extended below, its rule unchanged), RL-8.5 (a withdrawal signed before a witnessed readmission vetoes
  nothing after it; a scalar count or an unverified statement is not continuity evidence),
  RL-8.6, RL-8.7.
- ADR-023 RL-8.1a's hidden room is kept as the departure's carrier (Q6: B); its bound becomes
  two days (row 58; tabled below). Only the sentences tabled below change.
- ADR-012: a member reachable directly needs no anchor for the departure or the rejoin.
- ADR-038 FX-27, FX-40: no timer-driven retry; the bound ends an obligation, it does not retry
  one. `LEAVE_RETRY_MS` goes; the port's backoff is a preserved owner, not a retry rule of this
  ADR.
- ADR-042 TR-2, TR-8, TR-16 (their words), row 27's `offline, last seen <dur> ago`.
- ADR-046's row 38 ruling: a joined node fetches bodies from its join onward.

## Superseded and amended lines

Main applies these at sign-off. Quotes are from `/opt/vox/docs/adr/` at `d9a8667ba`.

| ADR and rule | Current text (file:line) | Replacement text |
|---|---|---|
| ADR-023 RL-8.1 | "`vox room leave` MUST post the node's presence statement (`0x0015`, `here` = false), take the node's records off boards with a signed member withdraw (`0x001A`), and MUST delete the room from the node — every stored row and its key, the store rewritten so none of the deleted bytes stay — once a sync session has carried the statement to another member (V210-164)." (`ADR-023-room-lifecycle.md:224-227`) | "`vox room leave` MUST post the node's presence statement (`0x0015`, `here` = false), take the node's records off boards with a signed member withdraw (`0x001A`), and MUST delete the room from the node — every stored row and its key; the bytes they occupied are cleared at the store's next rewrite (ADR-047 SO-10), not by a rewrite at the leave (the decider, 2026-11-13, ledger row 61) — once a member has echoed the departure head (ADR-049 LE-3), or at RL-8.1a's bound, or at once when the room cannot sign a departure (ADR-049 LE-2, LE-4)." |
| ADR-023 RL-8.1 | "A room held alone MUST go at once." (`:228`) | Unchanged. |
| ADR-023 RL-8.1a | "`vox room leave` and the app's Leave MUST answer as soon as the signed departure and the member withdrawal are durable." (`:234-235`) | "`vox room leave` and the app's Leave MUST answer, with success, as soon as the leave record (the member withdrawal and the leave's state) is durable, on an unlocked node, in every room state (ADR-049 LE-1); the departure is signed when the room's own head is authoritative and owed as a named wait until then (LE-2)." |
| ADR-023 RL-8.1a | "Delivery of the departure goes on in the background: the node MUST hold the room hidden, and go on leaving across a restart, until a sync session has carried the departure to another member, and MUST then delete it as RL-8.1 says." (`:238-240`) | "Delivery of the departure goes on in the background: the node MUST hold the room hidden, and go on leaving across a restart, until a member has echoed the departure head, and MUST then delete it as RL-8.1 says (ADR-049 LE-3, LE-4); a member's refusal is not a receipt." |
| ADR-023 RL-8.1a | "A join of the room with its link while the departure is undelivered is an ordinary rejoin: what the node holds goes first (RL-8.1b)." (`:251-252`) | "A join of the room with its link, while the departure is undelivered or after it, is a fresh join (ADR-049 LE-9): the hidden copy is discarded first, the node's own unconfirmed signed entries go first, and the person sees nothing older than the join and no refusal." |
| ADR-023 RL-8.1a | "**Bound.** A departure no member can be told of MUST NOT hold the hidden room for ever: seven days after the departure's own clock, the node deletes the room unheard and publishes its member withdrawal all the same." (`:253-255`) | "**Bound.** A departure no member can be told of MUST NOT hold the hidden room for ever: two days after the departure's own clock (the decider, 2026-11-13, ledger row 58), the node deletes the room unheard and publishes its member withdrawal all the same (ADR-049 LE-4)." |
| ADR-023 RL-8.2 | "A node holding an ended room MUST take no new message in it, MUST pass the end on to each member at its next sync (for at most 60 s for a member it cannot reach), and MUST then delete the room as RL-8.1 does." (`:270-272`) | "A node holding an ended room MUST take no new message in it, MUST pass the end on to each member at its next sync (for at most 60 s for a member it cannot reach, measured from the end entry's own clock), and MUST then delete the room as RL-8.1 does; a cleanup of the room's sync state that failed is discarded with the room, never keeps it, and the deletion that cannot run now is a named wait (ADR-049 LE-4, LE-6); until the room is gone every surface that lists rooms shows it ended; a member's leave during the wind-down neither shortens it nor touches the room-scope withdrawal (LE-7)." |
| ADR-023 RL-8.4 | "Before any own signed room entry can become externally visible, the append transaction MUST durably retain a room/author-bound continuity marker: the last own signed history head (the existing recovery-head type, including room/author binding and signature), highest authored sender chain/generation, and immutable verified public genesis bound to that same room." (`:305-309`) | Unchanged, followed by: "and, from the leave fence on (ADR-049 LE-2 step 2), this author's **continuity**: everything the own append reads of the feed at that head (`prepare_own_append_ranges`, `own_history.rs:1518-1586`: the append forest and root context; `Entry::build_signed`, `pending_text.rs:1110-1121`: the entry hashes a later entry's `prev_hash` and `lipmaa_backlink` can name), the signed headers of this author's entries above the last member-confirmed position, and the public payload, with its signature, of each lifecycle entry among them (a Presence: departure or rotation), all public and non-secret, no post body and no key, so that a rejoin after erasure appends from its own authenticated material and members can verify the chain and project the departure (ADR-049 LE-9); and, while own-history recovery is pending, the highest verified supplied own head (ADR-049 LE-9 case 2). The continuity is derived only from an authoritative own head and sets no fence; the marker keeps its existing lifetime." |
| ADR-034 HL-2 | "A peer whose every sync fails over a window MUST be shown as "sync failing", with the reason, and its syncs MUST back off (ADR-025), not repeat every few seconds." (`ADR-034-the-app-and-daemon-never-hang-or-hide-a-failure.md:180-181`) | Unchanged, followed by: "A room that has ended or that this identity left raises no "sync failing": a member that refuses it has deleted it, which is what the end asked for, or has not yet taken the departure, which the hidden room goes on serving (ADR-049 LE-3, LE-6)." (ADR-042's amendment of the same sentence stands beside this one.) |

ADR-040 revision 2's amendments of RL-8.1 and RL-8.1a (delete at once; the record as the one
carrier) are withdrawn with NW-15; ADR-040 revision 3 no longer carries them. Ledger row 10's
"deletes the room at once" is corrected at sign-off to "hides the room at once; erases it on a
receipt, at the bound, or when there is nothing to serve".

### What sibling ADRs must change (by requirement id)

- **ADR-040 NW-1.** Add `PeerReachable(peer)` with LE-3's four columns, `PolicySave` and
  `SessionCleanup(room)` with LE-4's; add to the preserved-owners table the port's bounded
  retry for a departure probe refused or unanswered on a live connection (LE-3; `ports.rs:262-284`).
  **NW-3.** The kinds `DepartureSign`, `DepartureDelivery(peer)` (sub-keys, `retire_prefix`),
  `EndedPurge`, `JoinAfterPurge`; the two-day bound and the 60 s wind-down are named bounds
  (r5: the board entries have none); `left-rooms/*` is this ADR's durable store,
  read at open before
  any room is opened. **NW-4.** The `waiting` lines of LE-2 step 3, LE-4 step 3 and LE-9
  state (3) in TR-23's form.
- **ADR-047 SO-9, SO-11 — the storage contract of a leave, in one place** *(r8; ADR-047 aligns
  to this by requirement id)*:
  | What | Rule | Owner |
  |---|---|---|
  | What a leave needs free to **answer** | one reclamation-class batch (LE-2 step 1: the wire, the `LeftRoom`, the `frozen` mark; actual encoded bytes as the estimate): SO-11's 3 MB admission. Below that LE-1 (ii) refuses with SO-11's words and the room preserved; the leave never "waits as cannot save" | LE-1, LE-2 |
  | What the **departure** needs | an ordinary append in the hidden room (floor + 2 × estimate + 1 MB); below it, `departure: Pending(StoreRecovery)`, a named wait, and the leave has still succeeded | LE-2 step 3 |
  | **When rows and the key are erased** | when erasure runs (a receipt, the two-day bound, `None`, held alone, or a wind-down's end: LE-4), at once and without a rewrite (row 61): stages (a), (b), (d) are SO-9's reclamation batches and run under the ballast on a full disk; stage (c), the carry, is ordinary inserts and parks on `StoreRecovery(room)` below the floor with the source rows and key intact; so on a full disk a room whose carry is empty (every own entry member-confirmed, or `None`) reaches `Erased` and 0 data bytes, and a room with an unconfirmed suffix stops at `Erasing { stage: carry }` with the truthful words until space is freed. The freed pages are cleared at the next rewrite (SO-10) | LE-4 |
  | **Image** | ADR-047 SO-11's 256 MB fixture (APFS image in the macOS guest, sized tmpfs in the Linux VM) for every act of LE-8 that stages disk space: A (b), (c), (m) and SO-9's leave arm. The 64 MiB HFS+ image appears only as E-49a's historical staging (the retirement failure of item 86 needs no floor) and is not a proof fixture | LE-8 |
  | SO-9's **leave arm** | stage it as A (c)'s full state **with an empty carry** (B has confirmed every own entry before the fill) if it asserts 0 data bytes on the full image; or as A (m)'s first staging if it asserts the carry wait. "The room is gone from `vox room list` within 1 s" holds at the answer; "data bytes 0" holds only at `Erased` | LE-8 |
  The leave record's transaction (LE-2 step 1) is admitted as a reclamation-class batch, not an
  ordinary write; the sentence "under the floor it waits as 'cannot save' and the room is already
  gone from the listing" is withdrawn. **SO-9.** The purge is a cursor stage resumed from the
  record; its last batch reports `RoomRowsPurged(room, instance)`; the leave's `rewrite_fresh`
  goes (already SO-9's); Q7 is answered B (row 61): no rewrite at a leave or an end; SO-10's
  next rewrite clears the pages. SO-9's "delete-only batches" must admit stage (c)'s inserts as
  ordinary writes between them.
- **ADR-048 (trust containment; row 35: per room; X049-5).** A room with a leave record is out
  of the trust pass's room list (`takes_policy_writes()` false) and no leave waits on a debt.
  **The moment the debt is retired is the one ADR-048 TC-2 names**: the `PendingLocks` entry
  is cleared in the batch that forgets the room (this ADR's LE-4 stage (a), the erasure's first
  batch), as `leave_save.rs:298-302` does today; between LE-2 step 2's fence and that batch the
  debt exists and is moot — the fenced room publishes no content and no key, so the debt
  neither blocks the departure, the two rotations nor the probe, and is never paid. What this
  ADR needs of TC-2: (i) the pass skips a room whose leave record exists (TC-2 says so); (ii)
  the debt's presence refuses nothing LE-2 step 2 admits; (iii) the clearing batch is LE-4's
  `Forget(room)` batch, not a batch of its own, so a crash between fence and erasure leaves a
  moot debt that the next open ignores by (i).
  **Item 93 and B (4)** *(r13)*: every roster change is a computer-policy revision; at the tag
  the application's pre-batch preflight parks on any busy room (item 93, confirmed by ADR-048's
  author). B (4) needs a native save in flight and holds it inside the save's own worker
  (`VOX_TEST_HOLD_POLICY_SAVE`), after `pending_policy` is installed; it does not lean on that
  parking. What this ADR relies on, by id: TC-4 (the save inspects, reserves and waits for no
  room) and TC-5 (a pass holds at most the room it works on), so an ended purge parked on
  `PolicySave` waits on a save that waits on nothing of any room: no cycle.
- **ADR-046.** SY-11 and SY-17 are the own-feed recovery and settlement a hidden room may run
  (LE-2 step 3) and the join exchange LE-9 rides on (the carry as the joiner's first push:
  header-only entries a member holds as any entry whose body it lacks, and the lifecycle
  entries with their public bodies; `Head(me)` verified, never a `Have`; a member that lacks
  the prefix of a verified own continuation holds it as a wanted range and shows `waiting for
  a member`); SY-11's "nothing from the discarded copy sets the fence" is agreed and stays (the
  continuity sets the append frontier, never the fence); SY-10 owns row 37's cap protocol; a
  hidden room runs its `Have` stream to each member (the receipt probe, LE-3; a receipt is the
  member's row naming size, HeadID, `control_through` and `held` through the departure, Terms;
  R12-1), issues, while `Pending`, SY-11's own-feed recovery and SY-10/SY-17's settlement
  requests, and for other authors SY-14's control coverage, the closure wanted of its pending
  control entries (witnessed Content headers with `Range{bodies: false}`, `Context`, bodies
  for governance-kind and typed-policy members only) and head, context and probe discovery —
  never SY-14's bodies wanted of ordinary posts (r14: R13-1) — and serves every SY-12 request
  a member makes of it (D1); under R1 the
  departure probe and SY-24's
  discard of a retained flow stand until the cutover. **`PeerReachable(peer)`'s release** *(X049-6; the exact row for ADR-046 SY-21's wait table, to pass to its author)*:
  | Prerequisite | Ready when | Released by (the state change that bumps the generation; v0.4.30 site) | Said as |
  |---|---|---|---|
  | `PeerReachable(peer)` | `net.manager().existing(peer)` is `Some` with `close_reason()` `None` | `NetEvent::Connected { peer }` (`actor.rs:3419`, handled at `:12273`: a new authenticated connection filed), and a peer's inbound session for a room this node holds hidden (the departure-probe answer path, `actor.rs:13440-13497`); never a refusal on a live connection (that is the port's backoff, a preserved owner) | `member <name> is reached` |
  **SY-27 (the fence
  post, row 65)** *(r5; changed r6: S5)*: a node that left and comes back is a newcomer: it
  starts from the creator's **last** fence post for members and rules and verifies what came
  after; the roster every member holds is that summary **plus the authenticated membership
  changes after it** (admissions, departures, returns), applied as they are verified, without
  waiting for the creator: a verified return updates every online member's roster at once, and
  a later fence post consolidates it, it does not activate it. The fence post MUST NOT be the
  source of this author's own head, generation or continuity — those come from LE-9's
  continuity record — and SY-27's chunk-per-author start applies to every other author's feed,
  and to this author's own feed only above its continuity head.
- **ADR-042 TR-2, TR-8, Appendix A** *(X049-8; the exact rows for ADR-042's author)*. No change
  to TR-2's or TR-16's words; TR-2's ended line keeps the parked form shown in LE-6. TR-8 is to
  list, after its `leaving` line, these variants and fields, each owned here and printed by
  ADR-042:
  | Surface | Exact text | When |
  |---|---|---|
  | `vox status`, rooms block | `left <room>: no member could be told in 2 days; deleting, waits until <prerequisite words>, for <dur>; members list you until one of them learns otherwise` | `outcome: Expired` and `erasure` not `Erased` (LE-4) |
  | `vox status`, rooms block | `left <room>: no member could be told in 2 days; deleted; members list you until one of them learns otherwise` | `Expired` and `Erased`, for 24 h from `Erased` (LE-4) |
  | `vox status`, rooms block and the daemon log, once | `<room>: the room's data is deleted; what is left of it in this node's data file is cleared at the next rewrite, and until then only someone who holds that file and this node's passphrase could read it` | at `Erased` only (Q7, row 61; R3) |
  | `vox status`, rooms block | `joining <name>: waits until its old copy is erased` | LE-9 state (3), `JoinAfterPurge` parked |
  | `vox status --json .left[]` | one object per `LeftRoom`: `room`, `name`, `departure_ms`, `departure` (`pending`/`signed`/`none` with its words; `signed` carries `seq`, `entry_hash` and `head_id`, the HeadID of this node's own signed head at `seq` — two identities, never compared with each other: R12-2), `outcome`, `erasure` (`hidden`/`erasing` with `stage`/`erased`), `continuity` (`held`/`marker-only` with `head` and `supplied`/`none`), `rejoin` (`none`/`preparing`/`accepted`), `sources` (the count of this author's source header rows still held by the hidden copy: LE-4 stage (c)'s sources, non-zero until stage (d)), `carry_estimate_bytes` (the next carry batch's estimate, LE-4 stage (c); 0 when no carry is owed), `members[]` each with `id` and `reach` (`offline, last seen <dur> ago` / `connected` / `not attached at <addr>`, row 27's words) | while the record exists (LE-2) |
  | `vox status --json .withdrawals[]` | one object per board-withdrawal entry: `room`, `scope`, `wire_hash`, `instance`, `state` (`pending`/`complete`), `answer_rows` (the count of W3 rows still held for this wire: equals the answered routes while `pending`, falls to 0 during W5b), `routes[]` with `board`, `instance` (the row's) and `answered` (W3) — the route set is W2m's for a `Member` wire and W2r's for a `Room` wire (r10) | while the entry exists (LE-5) |
  | `vox status --json .publications[]` | one object per publication row: `room`, `instance`, `board`, `state` (`attempted`/`published`), `frozen` (LE-2's table) | while the row exists |
  | `vox status --json .rooms[].own_feed` *(r12: paste row for ADR-042 Appendix A, LE-9)* | `{head, recovery_target, members: [{id, held_through}]}`: this author's own signed head in the room; the highest verified supplied head while recovery is pending (`null` otherwise; LE-9 case 1 (ii) and case 2); per member, the highest position of this author's feed that member's last `Have` reported, body-complete | while the room is held |
  | `vox status --json .rooms[].admissions[]` *(r12: paste row, LE-9)* | `{member, count}`: how many times this node has admitted each identity to the room since the room was created or joined here | while the room is held |
  | `vox status --json store.free_disk_bytes`, `store.floor_bytes` | ADR-047 SO-15's names, as ADR-042 r11 Appendix A already lists them; this ADR's acts read these two and `.left[].carry_estimate_bytes`, never a `.disk.free` (the † row `.disk.free_bytes` is withdrawn in favour of SO-15's name: D9) | — |
  | `vox room roster --history <room>` (or the surface ADR-042 names) | per member, its authenticated lifecycle entries in feed order: `<id> left at <time>` then `<id> back at <time>` for LE-9's departure-then-return | ADR-042's words; LE-9's proof asserts the order only |
  **Required daemon log lines** *(r12: D8; each is a requirement of the LE named, printed in
  shipped builds, not under `mutant-sender`; ADR-042 Appendix D lists them)*: on a board,
  `board: took a <genesis|bundle|address> record of <room> from <node>` and `board: took a
  <member|room> withdraw of <room> from <node>` (LE-2 P2, LE-5 W3: the board's side of the
  facts); on the publishing node, `publish of <room> to <board>: <taken|stale|refused|dead>`
  (LE-2 P3) and `board <board> answered the <member|room> withdrawal of <room>: <taken|refused
  (<reason>)>` (LE-5 W3; at the tag this line prints only under the `mutant-sender` feature,
  `actor.rs:22088-22099`, and is to print always); on the leaving node, `leaving <room>: <step>`
  for LE-2's steps 1–5 and `putting the <member|room> wire for <room> to <board>` (LE-5 W4).
  Appendix A gains the measures `.left[]` (with `sources`, `carry_estimate_bytes`),
  `.withdrawals[]` (with `answer_rows`), `.publications[]`, `.rooms[].own_feed`,
  `.rooms[].admissions[]` and the rooms-block variants above with this ADR as source; Appendix
  D the log lines above. Read, not added *(r13)*: `.rooms[].members[]`'s `size_known`,
  `headers_through`, `last_request_from_ms` and `in_flight` (A (a-i), B (6)),
  `.peers[].served.last_refusal` (B (1b)), `.sync_node.slots.owners[]`,
  `.sync_node.permits.owners[]` and `.lanes.ports[]` (B (4)) — all ADR-042 Appendix A's as
  frozen at `e2ce20c90`; `.left[].departure.signed` carries `seq`, `entry_hash`, `head_id`
  (one more field in the `.left[]` row above).
- **ADR-041 RS-7, RS-12.** Locked's words for LE-1 (i); `Frame::Left` is a control-protocol
  change inside RS-12's one bump.
- **ADR-045.** Row 32: journey A (c)'s short-disk staging on Linux needs a size-bounded tmpfs
  from the VM's provisioning. The clock step of A (h), (i), (l), (m) and B (7) and of LE-9's acts
  6 and 7 is this ADR's own in-tree proof's, in a `test-knobs` build (`VOX_TEST_CLOCK_STEP_MS`),
  never the fleet's: the fleet runs no clock step (ADR-045 FG-12 (ii); X049-11).

## Implementation order and related work

1. LE-4 steps 1–2 (deleting retirement, ledger disposal) and LE-6: they unblock items 64 and
   86 on their own, before any record change, and ADR-046 SY-24 depends on the discard.
2. LE-2 and LE-1 (the record and re-keyed journal, the fence and its two exceptions, the sign
   as a named wait, `Frame::Left`, the refusals removed) with ADR-040 NW-1/NW-3 and ADR-047
   SO-11's admission.
3. LE-3 (two owners, receipt-only completion), LE-4 steps 3–4 (parked purge, the cursor), LE-5
   (board completion), LE-7.
4. LE-9 with ADR-046 SY-11/SY-17.
5. LE-8's journeys, extending the three files named; A (b), (c) and (m) land after ADR-046
   SY-24's full-disk act in `a_sync_failure_names_its_reason_proof.rs` (D10); the proofs they
   make redundant go (`a_node_leaves_a_room_proof.rs`'s restart act is absorbed by journey A
   (e)).

Related: ADR-046 SY-10, SY-11, SY-17, SY-24; ADR-047 SO-9, SO-11; ADR-048; ADR-042 TR-16.

## Comparison with other systems

- **Matrix** separates *leave* (a signed `m.room.member` event the server delivers to the
  room) from *forget* (the client's later erasure of its copy; the server keeps the room while
  anyone is in it). Vox has no server: the leaver's own node is the only carrier of its leave
  until a member holds it. Taken: the separation (the leave is a delivered signed event; the
  erasure is its own later step), with the forget automatic (receipt, bound, or nothing to
  serve), as RL-8.3 rules. A Matrix rejoin keeps the server's history; Vox's rejoin is fresh
  (LE-9), which the decider asked for.
- **Signal groups** send a group-update message when a member leaves; the member's local copy
  of the conversation stays until the person deletes it, separately. Taken: the person's view
  ends the moment they leave; the message to others is a background duty with its own owner.
- **Slack-style clients** leave on the server; history stays on the server and the person can
  rejoin and read it. Nothing to take: there is no "my copy" to delete, and no delivery duty
  on the client.
- What Vox adds that none of them has: the leaver may hold history nobody else does, so the
  erasure has a stated cost (LE-4) and a sentence before the command (TR-16); the departure's
  delivery needs the room's own serving until a member can verify it (LE-3); and a rejoin must
  continue the identity's signed feed without forking it (LE-9's checkpoint and carry).

## Consequences

### Positive

- A leave never fails for a reason inside the room, in any state, and says what it owes and
  what it cannot promise. Items 27, 64 and 86 close; a stalled node (item 85) can shed its
  rooms. Leave-then-join is a safe manual route (row 22), and item 10 closes with ADR-046 SY-11.
- One record, one owner, one lifecycle for the departure and the board withdrawal; no new
  wire protocol, no new authentication model: the departure stays a log entry served from the
  own feed, and the receipt that exists today is the only completion.
- An ended room is gone within its wind-down on every node, shown ended until then, with no
  alarm, and leaves nothing in the daemon's ledger.

### Negative

- A left room stays on disk, hidden, until a member echoes the departure or 2 days pass
  (Q6: B, row 58): up to its full size for up to two days. The node serves it meanwhile and
  runs the two recovery rounds for it. A member away for more than two days is not told of the
  departure by this node and lists it until it learns otherwise; the person is told so.
- A departure that cannot be signed yet waits as a named wait, bounded by the same 2 days;
  a member may list this identity until then or until it learns otherwise. The person is told.
- The room's bytes stay in the node's data file until its next rewrite (Q7: B, row 61); the
  person is told who could read them until then.
- `PendingWithdrawal` changes key and shape; `Frame::Left` is new IPC; v0.4.x has no
  prior-release compatibility requirement (AGENTS.md).
- A rejoin carries the identity's continuity (append material, the unconfirmed entries' signed
  headers and their public lifecycle payloads) into the join without showing them: invisible,
  but not "nothing kept". A node restored from an older copy of its store still waits for its
  own history after a rejoin, as RL-8.5 requires; it is told. A node whose room was erased
  before its departure could be signed, and whose last entries no member holds, waits for a
  holder and may wait for ever; it is told that too (LE-9 case 2).

### Neutral

- **Under the replacement sync** (ADR-046 R2, ledger row 57; D1): no sync-protocol change of
  this ADR's own — the receipt is read from SY-12's `Have` stream (size, HeadID,
  `control_through`, `held`: R12-1), and the hidden room issues only SY-12 requests (own-feed
  recovery and settlement while `Pending`; control coverage, closure prerequisites and
  discovery for other authors' control entries, witnessed Content headers included; never an
  ordinary post's body: R13-1).
  Under R1 (the interim, until ADR-046's cutover)
  the departure probe, the flow pool and the retirement ledger are the v0.4.30 structures named
  in LE-3 and LE-4 and go with SY-19's deletion. Three prerequisites, four kinds and one
  preserved owner added to ADR-040's registry. The RL-8.4 marker grows by the append inputs
  (O(log n)) and the carry (O(k) signed headers and lifecycle payloads of the unconfirmed
  suffix, 3.4 KB each).
- The publish path writes one `publications/<room>/<instance>/<board>` row before each round's
  first put and files its result after (LE-2's table, U1); `board_routes` stops being the only
  record of where a withdrawal must go.
- `LEAVE_RETRY_MS`, `MAX_PENDING_WITHDRAWALS` and the ended purge's blind re-run go; the bound
  and the wind-down stay.

## Review record

### Parent reviews (ADR-040), in this lane

| Finding | Classification | Answered by |
|---|---|---|
| First review 7: a finish-side discard cannot manufacture the missing transition | CONFIRMED (`actor.rs:21540-21559`; `leave_save.rs:1585-1625`) | LE-4 step 1 |
| Second review closure 7 | CONFIRMED | LE-4 steps 2–3 |
| F5: an ordered, verifiable carrier | CONFIRMED (`presence.rs:19-60`; `governance/channel.rs:25-49`; `sparse_history.rs:779-803`) | LE-2 step 3, LE-3 |
| F6: quiesce before signing; a behind feed must not sign | CONFIRMED (`leave.rs:57-70`; `local_history.rs:148-153`; `channel.rs:6474-6481`) | LE-2 steps 2–3 |
| F7: "not held" vs rejection | CONFIRMED (`net.rs:35-37`, `ports.rs:293-297`, `log/sync.rs:794-800`) | LE-3, LE-6 |
| F8: storage admission for the record | CONFIRMED (`store.rs:653-678`; SO-11) | LE-1 (ii), LE-2 step 1; SO-11 contract |
| F11: purge admissions after retirement | CONFIRMED (`leave_save.rs:549-551`, `:729-774`, `:704-717`) | LE-4 step 3 |
| F12: the daemon ledger | CONFIRMED (`history_budget.rs:289`; `bounded_sync.rs:913-915`, `:960-979`, `:5847-5866`) | LE-4 step 2 |
| F14: an active owner and an any-member wait | CONFIRMED (`actor.rs:23208-23214`; `:16688-16691`) | LE-3 |
| F15: the invented expiry | CONFIRMED (`channel.rs:9018-9025`, `:9103-9106`; RL-8.1a:253-256) | LE-1, LE-3, LE-4 |
| F16: end propagation during wind-down | CONFIRMED (`actor.rs:283`, `:22222-22224`) | LE-7 |
| "Ended/left rooms": one record lifecycle; tombstone through erasure; reuse the withdrawal owner | CONFIRMED (`leave_save.rs:228-258`, `:321-336`; `actor.rs:21898-21926`) | LE-2, LE-4, LE-5 |
| "Q6" points 1–6 | CONFIRMED as the questions to answer | LE-4, LE-5, LE-7, LE-2, LE-1 (ii); Q6 answered (B) |
| Receipt ledger: the unhealthy-state red | CONFIRMED, verified: E-49a act 1 | LE-8 journey A (b) |
| Final question 6 (storage boundary) | engineering: durable intent is the success boundary | LE-1 (ii) |

### Review of revision 2 (`adr-049-sol-review-2`, 2026-11-13): verdict "needs revision", six findings

Its closure table closes F1–F6, F8 and F9 and leaves F7 and F10 partly closed (N4, N5); nothing
it closed is changed in revision 3.

| # | Finding | Classification against v0.4.30 and revision 2 | Answered by |
|---|---|---|---|
| N1 | A signed head is not append material; after erasure a short admitting member cannot supply the prefix, so "head from max(suffix, marker, Head(me)) then write at once" was unbuildable; "a gap, not a fork" was overstated | CONFIRMED (`own_history.rs:1518-1586` derives the append forest from held subtree descriptors and the root context and refuses `OwnHistoryBehind` without them; the marker is head/epoch/generation/genesis only, `:25-60`; the prefix-root checks at `:1100-1143`, `:1433-1449`) | LE-2 step 2 writes an **append checkpoint** and the carry into the record under the own-writer gate; LE-9 appends from the checkpoint, runs the existing prefix-root checks, names the restored-older-copy case as a visible `OwnHistory` wait, calls a mismatched root a fork; RL-8.4 amended to carry the checkpoint; SY-11's "nothing from the discarded copy sets the fence" agreed (the checkpoint sets the frontier, never the fence); LE-9 proof acts 2 and 5 |
| N2 | A crash during the admission exchange was treated as transient; an accepted join (proposal, witness, genesis, wrap, reservation) is a durable obligation the shipped code resumes and refuses to purge | CONFIRMED (`retain_accepted_join_native`, `metadata_save.rs:157-189`; `queue_unpublished_purge` refuses with an accepted join, `:4370-4394`; `JoinAccepted::Resumed`, `actor.rs:4563-4592`) | LE-9's crash windows split at Preparing / Accepted / Installed; `rejoin: Accepted` resumes the same witness, is never re-admitted or expired; `JoinAfterPurge` composes with the accepted-join owner; the installing transaction is the one durable handoff; `LeftRoom.instance`; proof act 3b |
| N3 | The 30-day drop of an unanswered withdrawal rested on a board TTL that does not exist for a room's genesis or notices | CONFIRMED (`nat/store.rs:137-145` genesis has no TTL; `:324-326` notices survive expiry; `:755-785` the expiry loop prunes member, bundle and pre-join records only; `:108-119` member 2 h, bundle 7 days) | LE-5: a `Room` entry is dropped only when every route answers; a `Member` entry at `BUNDLE_MAX_TTL_MS` with the reason the shipped TTLs give; the 30-day drop withdrawn |
| N4 | "Under 8 KB with 64 routes" was not a codec bound; a refusing serializer would be a non-storage leave failure | CONFIRMED (`actor.rs:21928-21976` keeps up to 64 candidate addresses per board and every board published to; 3,373 B signature) | LE-2 "Sizing": the estimate is the actual encoded bytes as SO-11 requires; no fixed envelope; nothing truncated; bounded by 64 × 18 B per board and the board count, under the 2 MB reclamation ceiling; an overflow is a product defect, never a leave refusal |
| N5 | Proof defects: LE-9 act 1 had no running admitting member; dropping the carried departure cannot fork while the marker remains; 5,000 posts + 1 s does not force `Erasing`; C's leave removes C from A's roster before the refusal; the commit-order mutant's hold was after the commit | CONFIRMED (`channel.rs:9103-9106` `is_member` excludes a departed author; r2's staging) | LE-9 proof: C runs as the admitting member with a stated prefix; the fork mutant resets the checkpoint head; a separate checkpoint-drop mutant; `VOX_TEST_PURGE_HOLD`; act 3b for N2; act 5 for the restore; `Have`-forging apparatus named. Journey A (g): A isolated before C leaves; the refusal observed before the mutant; (c): `VOX_TEST_LEAVE_HOLD=reply` inside the mutant; (i): the words before and after `Erased` |
| N6 | "Deleted" was printed at the bound while the purge could still be parked; the 24 h ran from the bound | CONFIRMED (r2 LE-4 text; LE-4 step 3's parks) | LE-4: words derived from `outcome` and `erasure`; `deleting, waits until …` until `Erased`; "deleted" only after `RoomRowsPurged`; 24 h from `Erased`; journey A (i) asserts both sentences |
| Q7 assessment | the evidence attached to Q7 misattributed items 64/86 to the rewrite | CONFIRMED (`bounded_sync.rs:832-843`; E-49a's rc 1 precedes deletion) | Q7 reworded as the reviewer proposed; evidence corrected; answered B by the decider (row 61); the rewrite alternative not kept |

### Review of revisions 3 and 4 (`adr-049-sol-review-3`, 2026-11-13): verdict "needs revision", six findings

Its closure table closes N2 and N6; nothing it closed is changed in revision 5.

| # | Finding | Classification against v0.4.30 and revision 4 | Answered by |
|---|---|---|---|
| R1 | The append forest supports appending at head + 1, not proving an arbitrary older prefix a short admitting member names; the constructor also reads predecessor and Lipmaa hashes the checkpoint lacked; `checkpoint: None` after an unsigned expiry was unhandled | CONFIRMED (`log/history.rs:2233-2258`, `own_history.rs:1531-1551`: the forest for 11 is 1–8, 9–10, 11, so prefix 5 is not derivable; `recovered_prefix` `:409-450` returns `None` without the ranges and `:1433-1449` refuses; `pending_text.rs:1110-1121` reads `prev_hash` and `lipmaa_backlink`; `feed.rs:244-262` checks both) | LE-2 step 2: the checkpoint adds the O(log n) entry hashes every later position's constructor reads; LE-9 "The own head and the return": the continuation is a local operation that needs no peer prefix comparison; a member head below the checkpoint is held unverified until the chain fills, never called a fork; a verified head above it is the RL-8.5 wait; a fork is declared only when two witnesses are comparable; `checkpoint: None` handled as RL-8.5's unmarked-binding recovery with its own words; proof act 2 on a cold profile |
| R2 | The carry copied own entry payloads into the record and retained them to the board journal's lifetime, contradicting "gone for good" and the two-day ruling | CONFIRMED (revision 3 LE-2/LE-5 text) | The carry is **headers only** (no payload), lives in the RL-8.4 marker row with the marker's lifetime, independent of the `LeftRoom` and of the board journal (LE-5); LE-4's loss statement says bodies are gone and headers stay; LE-9 "What is carried" |
| R3 | The Q7 "data is deleted" sentence was assigned to the leave's success line while the hidden copy is intact for up to two days | CONFIRMED (revision 4's answer text; LE-1 answers after step 1) | LE-1's success words are temporal (gone for you; hidden copy ≤ 2 days); the Q7 sentence only at `Erased`; journey A act (l) |
| R4 | A `Member` withdrawal dropped at 7 days leaves a board's retained admission notice without its veto | CONFIRMED (`nat/store.rs:318-326` notices kept and passed with member withdraws; `:524-535` a notice refused only while the withdrawal is held; `:633-640`) | LE-5: `Member` and `Room` entries are dropped only when every route answers; no time bound; journey B act (7) |
| R5 | Copying the whole unconfirmed suffix in the fence transaction is unbounded and not a reclamation batch; route rows for thousands of boards likewise | CONFIRMED (3,373 B per root-signed header; the collector's output, `actor.rs:21928-21976`; textual addresses `:6171-6177`; the old 4,096-target map `:6140-6142`) | LE-2: the fence transaction writes only the checkpoint (O(log n)) and the carry boundary; the header carry is LE-4 step 4's stage (c), after the bodies are freed, in batches under 2 MB, parked on `StoreRecovery` with sources intact when the disk refuses; route rows cut to fit with `routes_staged`; journey A act (m) |
| R6 | Act 5 restored a held-room profile, not a left checkpoint; the short admitter could catch up from the hidden copy before admission | CONFIRMED (revision 3's act text) | LE-9 proof act 5 rebuilt: a left snapshot at the older boundary, a rejoin and higher authoring, then the left snapshot restored with the daemon stopped; act 2's C kept short by A's prior erasure and C's catch-up hold, its supplied head asserted at the exchange |

### Review of revision 1 (`adr-049-sol-review`, 2026-11-13): verdict "needs revision", ten findings

| # | Finding | Classification against v0.4.30 and revision 1 | Answered by |
|---|---|---|---|
| F1 | The leave fence forbids the settlement/recovery append that releases `Settled`/`OwnHistory`: a `Pending` departure could never sign | CONFIRMED (`pending_recovery.rs:391-431` `Work::Settle` is a signed `Rotate { here: true, settle: true }`; `:435-485` `Work::Complete`; `:1067-1077` only the rotation clears `own_behind`; revision 1 admitted "no own append but the departure") | LE-2 step 2: the fence admits exactly the recovery completion, the settlement and the departure; the two rotations deliver no key; restart re-arms from `Pending`; journey A (h) |
| F2 | End's `Room` withdrawal and Leave's `Member` withdrawal share one map slot; a leave during wind-down replaced the end's | CONFIRMED (`leave_save.rs:228-258` `WithdrawScope::Member` into `withdrawn.insert(room, …)`; `metadata_save.rs:2432-2447` `scope` `Room` into the same key; `nat/withdraw.rs:11-25` the board distinguishes the scopes) | LE-2: journal re-keyed per room and scope; LE-7: a known-ended leave writes no member withdrawal and LE-7 precedes the `None` rule; journey B (5) |
| F3 | ADR-047 SO-11 classifies the record as ordinary and SO-9 says it waits with the room already gone, contrary to LE-1/LE-2 | CONFIRMED (ADR-047 r3 SO-11 "ordinary batch (… ADR-049's departure record)"; SO-9 "under the floor it waits as 'cannot save' and the room is already gone from the listing") | LE-1 (ii) and LE-2 step 1: reclamation-class, refused below 3 MB with the room preserved. **Resolved with ADR-047's owner (2026-11-13): ADR-047 r4 SO-11 admits the record as a reclamation-class batch, SO-9 drops the "waits while gone" sentence and raises `RoomRowsPurged(room)` (instance-qualified) at its last batch, and cites Q7 for the scrub.** |
| F4 | `erased` was set in the first `Forget` transaction while SO-9's batched purge still owed rows; RL-8.1's rewrite vs SO-9's no-rewrite | CONFIRMED (SO-9 r4: 256-key batches, `rewrite_fresh` deleted; revision 1 LE-2 step 5) | LE-2's `erasure: Hidden | Erasing { cursor } | Erased`; `Erased` only at SO-9's last batch (`RoomRowsPurged`); the scrub is Q7 |
| F5 | A refusal on a live connection parked on `PeerReachable`, whose predicate is already true | CONFIRMED (`ports.rs:262-284` is the existing owner of a `Busy`/stale-echo retry; revision 1 parked every refusal) | LE-3: two owners by whether a connection exists; the port's backoff a preserved owner (NW-1 contract); journey A (f) |
| F6 | `put_withdraws` reports nothing back; "forget once every route is done" had no consumer | CONFIRMED (`actor.rs:22072-22110`: the task returns after five tries, sends no event; `ForgetWithdrawal` removes the whole entry, `leave_save.rs:260-275`) | LE-5: `NetEvent::WithdrawAnswered`, per-route `done`, the drop condition (r3: the 30-day bound withdrawn, N3); LE-5's proof |
| F7 | The journal write is the whole map (3.4 KB per entry), capped at 4,096 rooms; "under 4 KB" was false | CONFIRMED (`actor.rs:6153-6160`, `COMPOSITE_SIG_LEN` 3,373; `MAX_PENDING_WITHDRAWALS = 4096`) | LE-2: per-room, per-scope keys; the cap deleted; `SizeLimitExceeded` no longer a leave outcome (LE-1); r3: the estimate is the actual encoded bytes (N4) |
| F8 | "No member has been told yet" was printed until board completion, after a receipt; `Signed`+`Erased` could not tell receipt from expiry | CONFIRMED (revision 1 LE-1 and LE-2's shape) | LE-2's `outcome: Undelivered | Delivered | Expired | Ended`; LE-1: the line ends on the receipt; LE-4: the 24 h expired line, not consumed by a read |
| F9 | The CLI prints one unconditional success from `Frame::Ok`; the outcome-dependent words had no carrier | CONFIRMED (`room_cli.rs:7363-7371`; `Request::Leave { channel_id }`) | LE-1: `Frame::Left(LeaveOutcome)`; RS-12 contract |
| F10 | Proof defects: A(b)'s mutant could not fail rc; A(d) returned C after the wind-down; A(g)'s "not acknowledged" is not `AuthenticatorInvalid`; `vox room members` does not exist; crash staging unnamed; terminal cases missing | CONFIRMED (`runtime.rs:3062-3065` emits `Unreachable` for a stale echo; `cli.rs:418-419` has `Roster`; E-49a act 3's usage error) | LE-8 rewritten: staging knobs named; A(b) red on erasure; A(d) C inside the wind-down plus the after-bound staging; A(g) a member that erased the room as the genuine refusal, the stale echo as a control; `vox room roster`; acts (h)–(k) for unsettled/own-behind, expiry, parked purge and `None`; every baseline marked run-with-receipt or owed |
| Receipt ledger | E-49a act 4 is not an ended-room experiment; act 2 is not item 64's loop | CONFIRMED | Context corrected |
| Final question 2 (physical erasure) | a real policy choice | CONFIRMED | Q7, answered B (row 61) |

### Review of revision 5 (`adr-049-sol-review-4`, 2026-11-13): verdict "needs revision", five findings

Its closure table closes R2, R3, R4 and R6's staging; nothing it closed is changed in revision 6.

**The simplest rule that satisfies "it should feel like they're freshly joining" and never
forks the node's own feed** (asked by Main before this revision; answered from the tag).
Three rules were weighed:

- **(c) A new feed identity per return.** Not available in this identity model: an entry's
  `author_id` is the root key's fingerprint (`pending_text.rs:1110-1121`, `presence.rs:75-90`),
  and so is everything that names a member — admission notices and board records
  (`nat/store.rs:318-326`), computer trust (ADR-035, ADR-038), consents and key delivery
  (RL-8.1b), the roster. A per-room sub-identity would be a new identity, trust and admission
  design, not a leave rule. Rejected.
- **(b) Keep nothing; on return, learn the own head from a member before the first post.** This
  is what v0.4.30 does (RL-8.5; item 10: six minutes, ADR-046 SY-11 makes it 10 s) and it works
  whenever a member holds the whole feed. It fails exactly where the person was warned: the own
  entries no member holds (ADR-042 TR-16's `k`). After the two days they are erased; the node
  keeps RL-8.4's marker (head n, signed) and nothing a member can supply reaches n. The node
  then has two choices and both are wrong: wait for a holder of n that does not exist (fenced
  for ever, `OwnHistoryBehind`), or re-base at the highest head a member holds and sign a
  second entry at a position it already signed — a fork whenever a member received those
  entries without this node seeing its inventory (`log/dag.rs:684-703` freezes the author;
  S1 forbids resetting a known signed boundary). Dropping the marker too would hide the
  problem, not remove it. What a person would read under (b): `you cannot post in <name>: your
  last k posts there were never received by anyone and were deleted when you left; this node
  cannot continue your history without them`. Rejected: it closes none of S1–S5 and reopens
  N1.
- **(a) Keep, outside the room, the one thing nobody else can supply: the material to append
  at head + 1 and the signed headers of the unconfirmed suffix** (plus the public lifecycle
  payloads among them, S2). This is the existing RL-8.4 marker with more fields, written where
  the marker is already written, under the own-writer gate; it holds no body of a post and no
  key; it lets the node continue at n + 1 whoever admits it, and lets a member verify the
  chain across the erased suffix. Chosen. What it costs, plainly *(corrected r7, as the fifth
  review asked)*: the fixed part is O(log n) (a few kilobytes); the carry is O(k) in the
  unconfirmed suffix: k signed headers of 3.4 KB each (A(m)'s 1,200 are over 4 MB) and the
  signed lifecycle payloads among them, kept for the marker's lifetime (until a verified end or
  a rejoin consumes it; no suffix cap and no time expiry), admitted by actual bytes and copied in
  batches; one more erasure stage; and the case split of S1. What it guarantees, plainly: a
  node that retained its append inputs posts at once after a rejoin whoever admits it; a node
  whose room was erased **before** its own prefix was authoritative (case 2) keeps only the
  signed boundary it knows and waits, possibly for ever, for a holder — an honest named wait,
  not a fork; so "never fences for ever" holds only in case 1, and revision 6's claim is
  withdrawn. Why the earlier revisions kept finding new cases: each fix named one more input
  the shipped constructor and consumer read (`own_history.rs:1518-1586`;
  `pending_text.rs:1110-1121`; `feed.rs:244-262`; `governance/channel.rs:883-901`); revision 6
  names the set once, by the code that reads it: the marker holds *everything
  `prepare_own_append_ranges` and `Entry::build_signed` read of the own feed at head n*, plus
  the suffix headers and their public lifecycle payloads. No simpler rule both never forks and
  keeps writability where the inputs were retained.

| # | Finding | Classification against v0.4.30 and revision 5 | Answered by |
|---|---|---|---|
| S1 | `checkpoint: None` was treated as "no continuity", though the RL-8.4 marker may hold a signed head; the return Presence was signed before recovery when a member proved a higher head | CONFIRMED (`own_history.rs:25-60` the marker holds head, epoch, generation; `pending_recovery.rs:435-485` checks recovery before the rotation) | LE-9 "The own head and the return": three cases — usable continuity; a marker with a signed head and no continuity (fenced on `OwnHistory` until a holder supplies the material through the marker's head, whatever an absence answer says); neither (RL-8.7); and the return is signed only after recovery when the admission shows a higher head, `joined` meaning admitted and readable; proof act 6 |
| S2 | A header-only carry cannot project `Presence(false)`: the payload is signed by hash and the fold needs the body | CONFIRMED (`log/entry.rs:448-453`, `:561-565`; `governance/channel.rs:883-901`, `:134-142`) | LE-2 step 2 / LE-4 stage (c) / LE-5: the carry keeps the **public lifecycle payloads** of its own entries (Presence bodies: the departure, rotations; a few hundred bytes each; no post body); the schema names them; proof act 7 |
| S3 | `routes_staged` resumed against RAM-only collections (`on_board`, `publishing`, `board_routes`) | CONFIRMED (`actor.rs:21943-21974`; initialised empty, `:6842-6847`, `:6879`, `:7495-7508`) | LE-2 step 1: every route row is durable **before** the leave answers; the answering transaction is the last and marks the inventory complete; orphan route rows without a `LeftRoom` are deleted at open (nothing was answered); `routes_staged` withdrawn; journey A act (n) |
| S4 | Act A(m) demanded a multi-batch ordinary-write carry on a 64 MiB image whose floor is 64 MB | CONFIRMED (ADR-047 SO-11: floor 64 MB, ordinary = floor + 2 × estimate + 1 MB, ballast never funds it) | Act (m) rebuilt on SO-11's 256 MB fixture: below-floor staging asserts the truthful wait and intact sources; space raised above `floor + 2 × batch + 1 MB` (figure read from `vox status --json`) before the `Erased` bound starts; the large-suffix mutant fails under the admissible state |
| S5 | "The creator's next fence post is where rosters show the return" would make online members wait for an offline creator | CONFIRMED (row 65: newcomers start from the *last* summary and verify what came after; LE-9's one-member admission) | LE-9's fence-post paragraph: the effective roster is the accepted summary plus authenticated membership changes after it; a verified admission or return updates online peers at once; a later summary consolidates; SY-27 contract row; proof act 1 asserts it with the creator offline |

### Review of revision 6 (`adr-049-sol-review-5`, 2026-11-13): verdict "needs revision", two findings

Its closure table closes S1's rule, S2, S4 and S5; nothing it closed is changed in revision 7. Its
assessment of rule (a) left three conditions, met above and here: the guarantee is conditional
(availability where the node retained its append inputs; a marker-only room may wait for a holder
for ever, said honestly), the cost is `append inputs + O(k)` with the suffix's signed headers and
signed lifecycle payloads, not "a few kilobytes", and a second leave of a recovery-pending room
MUST NOT erase the known signed boundary (LE-9 case 2); the "Still unsure" escape in the note is
withdrawn.

| # | Finding | Classification against v0.4.30 and revision 6 | Answered by |
|---|---|---|---|
| T1 | Deleting orphan route rows at open and re-collecting from RAM-only collections lost boards known only by a past publication; A(n)'s hold could not leave no `LeftRoom` | CONFIRMED (`actor.rs:21928-21976` reads `on_board`/`publishing`/`board_routes` plus anchors; all empty at a start `:7495-7508`, `:6842-6847`, `:6879`; the `board_routes` comment itself says the route must survive "after a restart" and today it does not) | LE-2 "Where the routes come from": a durable publication inventory `published/<room>/<board>` written by the publish path at publication time; the leave copies nothing and writes one intent transaction that freezes it; the withdrawal's routes are those rows plus the anchors; crash windows; LE-5 marks the rows `done`; journey A (n) restaged as kill-before-leave / kill-after-record with E known only by publication |
| T2 | Act 6 restored a whole directory copy and asserted a marker (20) the copy could not contain (10) | CONFIRMED (`own_history.rs:9-22`, `:66-81`, `:91-130`: the marker is a scope of the same store) | LE-2 step 2 keeps the highest verified supplied own head in the marker row while recovery is pending; act 6 restaged from product commands (snapshot at 10, author to 20, restore, catch-up hold, observe `recovery_target 20`, stop B, leave, expire, rejoin through a short C) with its own mutants |

### Review of revision 7 (`adr-049-sol-review-6`, 2026-11-13): verdict "needs revision", four findings

Its closure table closes rule (a)'s three conditions; nothing it closed is changed in revision 8.
T1 had failed twice on crash points; revision 8 derives the text from one table of states (LE-2,
"Publication and withdrawal: the facts, their owners, and every crash point").

| # | Finding | Classification against v0.4.30 and revision 7 | Answered by |
|---|---|---|---|
| U1 | The inventory row was written only after a successful round; a board can accept a put before the node files the answer | CONFIRMED (`actor.rs:9477-9490` records the route in RAM before spawning the send; `:9532-9549` puts one record at a time; `:9600-9612` files `PublishDone` after; `:12631-12747` the handler updates RAM; `nat/service.rs:1317-1324` the board mutates its store before answering) | LE-2's table: the `attempted` row is durable **before the first put**; a failed inventory write prevents the send; an attempted round is withdrawable until a board answers the withdrawal; journey A (n) crash after E's put |
| U2 | Stage (d) deleted the inventory rows while a `Room` or `Member` withdrawal still needed them | CONFIRMED (revision 7 LE-2 "deleted when … erased (LE-4 stage (d))"; LE-5 kept them for a `Member` entry only) | The rows belong to the publication journal, not to the room: erasure never deletes a row referenced by an outstanding withdrawal of either scope; a row is deleted only when no withdrawal references it and the room is not held; journey B (5) extended |
| U3 | One `done` flag on a room-keyed row cannot hold "answered Member, not yet Room"; a fresh attachment's publications would mutate the old withdrawal's route set | CONFIRMED (revision 7's shape; LE-2 allows both scopes; LE-5 requires independent completion) | Rows keyed by `(room, instance, board)`; a withdrawal references its instance (immutable: a hidden room publishes nothing, LE-1; a rejoin is a new instance, LE-9); completion is one row per `(scope, wire_hash, board)` answer; a fresh attachment writes its own instance's rows; the old instance's rows outlive it until its withdrawals complete; the wire-hash check kept; journey B (8) |
| U4 | `VOX_TEST_CATCHUP_HOLD` held ordinary catch-up, not own-history recovery, and was never released | CONFIRMED (revision 7's act 6 and knob definition; ADR-046 SY-11 schedules own-feed recovery first) | A separate knob `VOX_TEST_OWN_RECOVERY_HOLD=<room>` (allows the head and inventory exchange, stops the own-history fetch and install, observed as a log line); act 6 asserts the held prefix and target before the leave, releases the hold after B stops, and classifies a missed hold APPARATUS |

### Review of revision 8 (`adr-049-sol-review-7`, 2026-11-13): verdict "needs revision", four findings

Its closure table closes U4 and the rules of U1–U3; nothing it closed is changed in revision 9.
The faults are rows of LE-2's table; revision 9 changes the rows (W1 split; P3; W2 split by scope;
W5 as three steps; P4's trigger) and re-derives only the text and acts those rows touch, then walks
every row once more for the three questions (is the crash-after state listed; can the next-open
action itself be interrupted; does exactly one durable owner hold the fact): each row now answers
all three in its own cells.

| # | Finding | Classification against v0.4.30 and revision 8 | Answered by |
|---|---|---|---|
| V1 | A `Room` wire referenced only the ending attachment's rows, so a board known under an older instance never received the End | CONFIRMED (`nat/store.rs:362-410` a member withdraw removes that member's records only; `:413` onward a room withdraw takes the genesis; revision 8's W2) | W2 split: W2m (a `Member` wire: its instance's rows) and W2r (a `Room` wire: every retained row of the room, any instance); P4 references both; B (8) asserts E in the `Room` wire's routes with `instance: 1`, with a routing mutant |
| V2 | Act (n) crashed a republish after a completed round, so the late-persistence mutant kept E's old row | CONFIRMED (revision 8's act; the own-put order genesis, bundle, address, `actor.rs:9428-9444`, `:9532-9549`) | Act (n) restaged on E's **first** round with no prior row, held after E's **address** put (the record a joiner needs) and before `PublishDone`, with the ordering receipt (E's log then A's); the mutant loses the route and fails the same join assertion; the RAM-only restart kept as (n2) |
| V3 | W5 deleted an entry plus an unbounded set of answer rows with no boundary or recovery | CONFIRMED (revision 8's W5; `leave_save.rs:260-275` deletes one journal item today) | W5a `state: complete` written with the last answer row; W5b batched idempotent deletion of the answer rows; W5c the entry last; orphan rows deleted at open; no board answers again; B (8b) with a kill during cleanup and two ordering mutants |
| V4 | W1's crash-after cell said "nothing happened" for a committed record | CONFIRMED (revision 8's W1 vs the crash-windows paragraph) | W1 split into W1a (before commit) and W1b (committed: the open hides the room and resumes steps 2–3; a repeated leave answers `already_left`); P3's cell keeps whichever state committed |

### Review of revision 9 (`adr-049-sol-review-8`, 2026-11-13): verdict "needs revision", two findings

Its closure table closes V2, V4 and V3's cleanup design; nothing it closed is changed in
revision 10. Before changing LE-5, every other sentence of the ADR that states a completion, a
"done" or a route set was searched for and checked against W2m/W2r (`LeftRoom` comment, the
journal sentence, the derived paragraph, LE-5's three predicates, LE-5's *Changes* and *Proof*,
acts A (n), B (5b) and B (8), the ADR-042 `.withdrawals[]` row, and the review-record cells):
those that said "its instance" or "per route `done`" are corrected below; the rest already
read "every board in the wire's route set".

| # | Finding | Classification against v0.4.30 and revision 9 | Answered by |
|---|---|---|---|
| R9-1 | LE-5's drop and empty-route predicates said "every board of its instance", so a `Room` wire could be dropped while an older instance's board (E) was unanswered | CONFIRMED (revision 9 LE-5 lines 585-586, 601-604; `nat/store.rs:362-410` vs `:413` onward) | LE-5: W5a is the sole terminal predicate: "every board in this wire's route set (W2m for a `Member` wire, W2r for a `Room` wire) has an answer row for this wire"; the zero-route case is defined from the same scope-selected set; B (8) asserts that the anchor's answer does not complete the `Room` wire while E is offline |
| R9-2 | B (8b)'s entry-first mutant is repaired by W5c's orphan sweep, and its hold after the first batch does not leave answer rows when both fit in one batch | CONFIRMED (revision 9's W5c cell and act) | The entry-first mutant withdrawn; the act stages the window after W5b's last batch and before W5c (the `complete` entry with no answer rows: `VOX_TEST_LEAVE_HOLD=cleanup-entry`), asserts that boundary, kills, restarts with E down, and keeps the answer-rows-before-complete mutant |

### Review of revision 10 (`adr-049-sol-review-9`, 2026-11-13): verdict "needs revision", one finding

Its closure table closes R9-1; nothing it closed is changed in revision 11. The same fault — a
staging gate that would classify its own mutant's outcome as APPARATUS — was then looked for in
every act of LE-8 and LE-9's proof; found and fixed in B (5b), B (7) and B (8) as well.

| # | Finding | Classification against revision 10 | Answered by |
|---|---|---|---|
| R10-1 | B (8b)'s pre-kill gate required the entry to be `complete` (else APPARATUS), which is exactly the state the answers-before-complete mutant denies, so the mutant could never reach its PRODUCT red | CONFIRMED (revision 10's act, lines 911-913) | The hold is defined at the physical boundary after the last answer-row deletion, whatever the entry's state; the staging gate names only the hold, the entry's existence and the absence of answer rows; the entry's `complete` state is a product assertion at the hold; the restart assertion runs on a `pending` entry too; E is brought back and sampled for a second `took a withdraw (room)` with the baseline's single line stated |
| the sweep | B (5b) gated on E's `taken` line, which its stage-(d) mutant suppresses; B (7) gated on C's `taken` line, which its 7-day-drop mutant suppresses; B (8) gated on E's `took a withdraw (room)` line, which its routing mutant suppresses | CONFIRMED by reading | Each gate now names only what the apparatus controls (the board started and the connection filed; the member-first put order on the sending node); the board's lines are product assertions with a bound. A (c), (g), (k), (n), LE-9 acts 2, 3, 3b and 6 were checked and gate only on states their mutants do not touch |

### Task cut of revision 11 (`v0431-tasks-ADR-049`, 2026-11-13): eleven defects

The cut found no fault in the rules; it found places where the text named a v0.4.30 structure
that ADR-046's replacement deletes without saying so, acts whose assertions or knobs did not
exist, and status fields and log lines the acts read that no ADR owned. Nothing the ninth
review closed is changed in revision 12. Cells of the earlier records that quote
`took a withdraw (room)` or `a board answered a withdraw` quote the names as they stood in
the revision reviewed; the shipped names are those D8 fixes below.

| # | Defect | Classification against v0.4.30 and revision 11 | Answered by |
|---|---|---|---|
| D1 (blocking) | `departure_probe`, the flow pool, `Retire::Deleting` and the `RetirementLedger` were used as if they survived ADR-046's cutover; the receipt, LE-4 steps 1–2 and the stagings of A (b) and B (2) existed only under R1 | CONFIRMED (ledger row 57; ADR-046 r10 frozen at `1aa0d5579`: SY-12's `Head`/`Have`, SY-19's deletion of the probe, pool and ledger, SY-24's cancellation table) | Context "Facts" first bullet; Terms "Receipt", "Deleting retirement", "Hidden"; LE-3; LE-4 steps 1–2; A (b), B (2), B (4); the ADR-046 contract block; Consequences, Neutral |
| D2 | A (m)'s wrap-bytes assertion ran before the rewrite that clears the pages, so it asserted Q7's effect at a time Q7 does not promise it | CONFIRMED (`a_room_can_be_left_and_ended_proof.rs:1374-1380` reads the file before any compact) | Journey A preamble and A (m): the assertion follows `vox node compact` |
| D3 | LE-5's proof and A (i) asserted completion from log lines a board prints, not from the node's own state | CONFIRMED by reading revision 11 | LE-5 *Proof* and A (i) assert on `vox status --json .withdrawals[]` (`state`, `answer_rows`) |
| D4 (blocking) | B (4) held the policy save with a knob that does not exist | CONFIRMED (`actor/computer.rs:219`: the only hold is `VOX_TEST_HOLD_COMPUTER_POLICY`) | B (4) uses `VOX_TEST_HOLD_COMPUTER_POLICY` |
| D5 | The app act named a proof file and keys that are not in the tree | CONFIRMED (`FirstRunProof.swift` is the app proof; health keys are `room-health-`) | LE-8's app act, per ADR-042 TR-22 |
| D6 | A (a), B (1), B (6) and LE-9 act 4 had no mutant | CONFIRMED by reading | Each act names a mutant that fails on its own assertion |
| D7 | Three receipt citations (rig26, E-64b, RcaSchedStall (iii)) lacked the lost-receipt note | CONFIRMED (row 64) | Each carries "receipt lost in the reboot of 2026-11-13, row 64, figures as recorded in …" |
| D8 | The acts read daemon log lines that no requirement obliged the daemon to print; one prints only under `mutant-sender` | CONFIRMED (`actor.rs:22088-22099`: the answer line is behind `#[cfg(feature = "mutant-sender")]`) | "Required daemon log lines" under the ADR-042 contract block; acts read `.rooms[].own_feed`, `.rooms[].admissions[]`, `.left[].rejoin` where a log read was the only witness |
| D9 (blocking) | The acts read `.disk.free`, `.withdrawal_answers[]`, `.left[].sources` and other fields ADR-042's Appendix A does not list; ADR-047 had renamed the disk measures | CONFIRMED (ADR-042 r11 frozen at `708634ca4`, Appendix A lines 1721, 1733: `store.free_disk_bytes`, `store.floor_bytes`; no `.disk.free`) | SO-15's names adopted; `.left[].sources`, `.left[].carry_estimate_bytes`, `.withdrawals[].answer_rows`, `.rooms[].own_feed`, `.rooms[].admissions[]` stated as paste rows in the ADR-042 contract table |
| D10 | A (b), (c), (m) stage disk space, which ADR-046 SY-24's proof file will own | CONFIRMED by reading (at the tag `a_sync_failure_names_its_reason_proof.rs` has no disk staging) | Journey A's preamble: the three acts extend `a_sync_failure_names_its_reason_proof.rs` after SY-24's full-disk act on SO-11's 256 MB fixture lands; the implementation order puts SY-24's act first |
| D11 | Three sentences still described the pre-r9 journal key and the record as the holder of continuity | CONFIRMED by reading | LE-2's journal sentence (re-keyed per room, scope and wire; completion as W3 answer rows); LE-9's case rule (a marker without continuity is case 2, no marker case 3); the crash-window text (continuity and carry are rows of the RL-8.4 marker, not of the record) |
| TR-16 | Which act proves ADR-042 TR-16's sentence | — | A (a′): A stopped before B's last two posts; B's `vox room leave` without `--yes` exits non-zero printing TR-16's sentence with `k = 2`, with `--yes` rc 0; control with every post confirmed; mutant: `k` counted only above the DAG prefix names 0 → red (ADR-042 TR-16's mutant) |

### Review of revision 12 (`adr-049-sol-review-11`, 2026-11-13): verdict "needs revision", eight findings

Its closure table closes D2, D3, D5, D7, D10 and D11; nothing it closed is changed in revision
13. Each finding was retraced at the tag and against the frozen siblings (ADR-046 `f015de313`,
ADR-042 `e2ce20c90`). The largest: revision 12's receipt accepted knowledge of the signed head
as delivery of the departure, and compared a HeadID with an entry hash.

| # | Finding | Classification against v0.4.30, the frozen siblings and revision 12 | Answered by |
|---|---|---|---|
| R12-1 | A `Head` answer or a `Have` naming the head counted as a receipt while the member may be in the Head-only state and hold no departure body | CONFIRMED (ADR-046 SY-13 rule 3 names the Head-only state, `since` > `at`; SY-18 keeps accepted heads apart from headers and bodies; a `HeadAnswer` reports an accepted head only, SY-12) | Terms "Receipt": the member's `Have` row naming `size` = d, `head` = the departure head's HeadID, `control_through` ≥ d and `held` covering d — possession and verification, not knowledge; LE-3: the `Have` stream is the probe, no `Head(me)`; the hidden room serves and fetches control positions so the condition is reachable; A (a-i) the Head-only act with its sampled no-`Delivered` assertion |
| R12-2 | `Have.head` was compared with the departure's entry hash and called signature-verified | CONFIRMED (`log/history.rs:882-920`: `SignedHead::id()` hashes the canonical head body under the `LogHead` domain, never `Entry::entry_hash`; SY-12: `Have.head` is a HeadID and carries no signature) | Context fact 1 and `LeftRoom.departure: Signed { seq, entry_hash, head_id }`: two identities, bound by the head's root committing leaf d, never compared across; an unknown HeadID at `size` = d raises `Head` (SY-14, N8) and is no receipt; A (a)'s entry-hash mutant and A (a-ii)'s false advertiser |
| R12-3 | `VOX_TEST_HOLD_COMPUTER_POLICY` holds the policy message before any save exists, or the actor itself | CONFIRMED (`actor.rs:14032-14055`: both arms run before `apply_owned_computer_policy`, `:14090`; `computer.rs:439-475` returns the message to a waiter, `:477` awaits on the actor; `pending_policy` is installed only by `begin_pending_policy`, `policy_save.rs:574`, after the worker spawn at `:505`) | `VOX_TEST_HOLD_POLICY_SAVE`: the native worker holds immediately before `policy.run` (`:552`) with `pending_policy` installed and the actor free; B (4) gates on its `engaged` text and asserts the parked purge, the free unrelated room and the completion |
| R12-4 | LE-9 act 2 read `.rooms[].members[].own_feed_held_through`, a path no row defines | CONFIRMED (ADR-042 `e2ce20c90` Appendix A defines `.rooms[].own_feed.members[] = {id, held_through}` only) | LE-9 act 2 reads `.own_feed.members[] \| select(.id == C).held_through`; the note and ADR-042's row say the same |
| R12-5 | B (4)'s R2 mutant corrupted `.lanes.ports[]` while the act asserted only `.rooms[]` and `.unhealthy[]` | CONFIRMED (`status.rs:375-435`: health is derived from listed rooms; a stale slot raises no room alarm) | B (4) asserts `.sync_node.slots.owners[]`, `.sync_node.permits.owners[]` (SY-24's one schema) and `.lanes.ports[]` clear of R after deletion; the mutant leaves the slot owner in that collection |
| R12-6 | A (a)'s stale-echo mutant and B (1)'s refusal mutant changed branches the acts never reached | CONFIRMED by reading revision 12 | A (a) is the control of A (a-i), whose `VOX_TEST_FETCH_HOLD` keeps the member in the Head-only state for 10 s with the no-`Delivered` assertion sampled through it; B (1) is the control of B (1b), where M erases first (its clock alone stepped) and its refusal is observed on M's `.peers[].served.last_refusal` before the no-alarm assertion |
| R12-7 | B (5b) read the old answer line; B (6) judged a mutant from an unowned `Head`-request log; the member-first knob named an old line | CONFIRMED by reading revision 12 against its own "Required daemon log lines" | B (5b) reads `board E answered the room withdrawal of R: taken`; the knob is observed by the W4 put lines in order; B (6) reads A's `.rooms[].members[]` `last_request_from_ms` and `in_flight` (ADR-042 fields) after T_e |
| R12-8 | A (a′) stopped A but not every other confirmer, and had no confirmed baseline | CONFIRMED (ADR-042 TR-16 counts above the highest body-complete `held_through` any member reports) | A (a′) runs in a two-member room: baseline `held_through` = `head` asserted with A up; A stopped; exactly two posts; `held_through` still n; the warning, the `--yes` leave and the control on the same count and command assertion |
| `carry_estimate_bytes` | the note said k × 3.4 KB; the ADR and ADR-042 say the next batch's estimate | CONFIRMED | the note is corrected; the ADR's row stands |

### Review of revision 13 (`adr-049-sol-review-12`, 2026-11-13): verdict "needs revision", five findings

Its closure table closes R12-1 to R12-5 and the staged halves of R12-6 to R12-8; nothing it
closed is changed in revision 14. It confirms the receipt's scope (held, servable bytes; not
proof the member has folded the departure), now stated in Terms, and B (4)'s dependence on
ADR-048 TC-4/TC-5's clean cutover (ADR-048 r10 `e4f5c6467`), to which no quiet prerequisite
is added. The ADR-046 parts were checked against its r12 (`b5acf1eaa`): `control_through` is
received coverage; `closed_through(A)` and the closure index are SY-3 rule 3's; witnessed
Content headers enter `CLOSE` through rule 2's verifier; SY-14's closure-wanted, head, context
and probe classes are quoted by name.

| # | Finding | Classification against v0.4.30, ADR-046 `b5acf1eaa` and revision 13 | Answered by |
|---|---|---|---|
| R13-1 | The hidden room's whitelist allowed control positions and bodies only, so an End whose previous own entry is an unseen Content entry could never be closed (`CLOSE(E)` needs X's witnessed header), and the Terms' `Head` had no place after `Signed` | CONFIRMED (ADR-046 r12 SY-14: closure wanted = the coordinates named and the previous own entry, `seen` parents, witnessed headers with `Range{bodies: false}`, bodies for governance-kind and typed-policy members only; head/context/probe wanted) | LE-3's outbound list: control coverage, closure wanted of pending control entries, head/context/probe discovery; bodies wanted of ordinary posts and explicit pages never; the ADR-046 handoff and the Neutral consequence say the same; B (6) exercises an End after an unseen Content entry with the forbid-non-control-headers mutant |
| R13-2 | "Fork evidence if a signed head arrives" would record a fork from a member's unsigned false `Have` answered with this node's genuine head | CONFIRMED (SY-13 rule 2: two incompatible author-signed objects; SY-14 N7: an unsupported advertisement) | Terms: ordinary head discovery, the answer judged by SY-13 alone; a genuine consistent head freezes nothing and is no fork evidence; the advertisement becomes unsupported for that peer; a fork only on rule 2's contradiction |
| R13-3 | A (a-i)'s second mutant was green under the hold (`control_through` < d too); A (a-ii)'s false `Have` left `control_through` unstated | CONFIRMED by reading the knob contract and SY-14 r12 (coverage counts needed governance bodies) | A (a-i) keeps the size/head-only mutant and states why no mutant on `held` is claimed; A (a-ii)'s `Have` names `control_through` = d and `held` through d, the HeadID the only false conjunct |
| R13-4 | B (6) started in `Signed`, so the mutant "keep own-feed and settlement requests" had no work to retain | CONFIRMED (LE-2 step 3 signs only when own history is current and the room settled; LE-3 permits those requests while `Pending` only) | B (6) stages `Pending(OwnHistory(R))` as LE-9 act 6 does with the recovery held before its fetch; gates the runnable demand independently (`.waiting[]` and the hold's log line before T_e); releases after T_e; the mutant's released fetch moves `last_request_from_ms` |
| R13-5 | A (a′) took n from the number of post commands; settlement appends a Presence (`pending_recovery.rs:391-431`) | CONFIRMED | A (a′): n := the observed `own_feed.head` after the baseline gate, A's `held_through` = n asserted, then A stopped and two posts; `head` = n + 2, `held_through` = n |

## The decider's answers (2026-11-13)

- **Q6** (row 34, amended by row 58): B. When a node leaves a room, its copy is kept hidden only
  until one member has verified the leaving, **2 days at most**, then erased. LE-2–LE-5 are
  written for it. His added requirement is LE-9. The 2 days replace RL-8.1a's seven (tabled
  above). What the 2 days bound, and what they do not: the hidden copy and the departure's
  delivery window (LE-3, LE-4), the `Pending` departure's wait (LE-2 step 3), the `Preparing`
  rejoin's record (LE-9) — all **his 2 days**; the 60 s wind-down of an ended room (LE-6, LE-7)
  is RL-8.2's own clock, ruled 2026-10-03 and not touched; the board entries' lifetimes (LE-5,
  r5: a `Member` and a `Room` entry alike until every board answers, no clock) are the boards'
  business, not the hidden copy's, and not touched; the 24 h the "deleted" line is shown after
  `Erased` is a status line's lifetime, not retention, and not touched.
- **Q7** (row 61): B. A left or ended room's rows and its key are deleted at once (LE-4 step 4;
  ADR-047 SO-9's batches); the freed pages are reused and are cleared at the next store rewrite
  (a daemon start or `vox node compact`, ADR-047 SO-10); there is no whole-file rewrite at a
  leave or an end. What a person reads, and **when** *(changed r5: R3)*: at the leave's success
  LE-1's words (the room is gone for you; a hidden copy stays at most 2 days to tell members);
  only once the erasure has reached `Erased` (`RoomRowsPurged`), in the status line and the
  daemon log: `the room's data is deleted; what is left of it in this node's data file is
  cleared at the next rewrite, and until then only someone who holds that file and this node's
  passphrase could read it`. Before `Erased` the sentence is false twice over (the hidden copy
  is intact and serves members without any file or passphrase), so it is never printed then.
  `Erased` follows `RoomRowsPurged`. RL-8.1's "the store rewritten so none of the deleted bytes
  stay" is amended as tabled. The alternative he did not choose (a rewrite at every leave or
  end) is recorded in the review record for revision 2's Q7 and not kept.

## Links

- ADR-005, ADR-007 (G-22), ADR-023 (RL-8.1–RL-8.7); ADR-034 (HL-2, SR-1, PF-3); ADR-038 (FX-27,
  FX-40); ADR-040 (NW-1, NW-3, NW-4; "Moved requirements"); ADR-041 (RS-7, RS-12); ADR-042
  (TR-2, TR-8, TR-16, TR-23); ADR-045 (row 32); ADR-046 (SY-10, SY-11, SY-17, SY-24); ADR-047
  (SO-9, SO-10, SO-11); ADR-048; ADR-050.
- `adr-049-sol-review.md`, `adr-049-revision.md`, `adr-040-sol-review.md`,
  `adr-040-sol-review-2.md`, `adr-040-revision.md`, `rca-RcaSchedStall.md`,
  `rca-RcaFrozen.md`, `io-repair-drill.md`, `v0431-fix-list.md` (items
  10, 27, 64, 85–87), `adr-cross-changes.md` (rows 10, 22, 27, 32, 34, 35, 37, 38, 49,
  58, 61, 64).
- Experiments: `/tmp/adr040/run64*`, `/tmp/adr040/run86*` (ADR-040 r2); `/tmp/Adr049Leave/`
  (E-49a, this ADR); `/tmp/RcaSchedStall/receipts/` (control (iii), item 64);
  `/tmp/rca-IoDrill/runA`, `runC` (item 10). The reboot of this Mac on 2026-11-13 (row 64)
  cleared `/tmp` and `/private/tmp`: these receipts are lost; their figures stand as recorded
  in `adr-049-revision.md`, `adr-040-revision.md`, `rca-RcaSchedStall.md`
  and `io-repair-drill.md`, and each is to be re-run as the fleet baseline (ADR-045).
