# ADR-048: A Trust Change Stays in Its Room and Finishes

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-13) as the design for v0.4.31, under the decider's authorization
  of 2026-11-13 ("post review can accept them too"), after the eleventh independent review by
  GPT-6.1-Sol (`adr-048-sol-review-11`) found this ADR's own text closed: its one P1 (R11-1) was
  against ADR-044 RD-10's retained whole-policy owner text and is closed in ADR-044 revision 17;
  proposed 2026-11-12. **Revision 11 is the accepted text.** This is design acceptance only:
  nothing is built, every requirement says what the code is to do, and implementation,
  acceptance and delivery are recorded on the source-bound issues, separately from decision
  status. This ADR takes over from
  ADR-040 revision 2 its NW-5 (containment of a failed trust pass and the trust-debt fence), the
  trust side of NW-6 (a trust change skips a room the node has left), the item-67 rule that a
  failed reconciliation pass is run again, and the trust side of item 66 (a fault never on disk
  is never repaired by rebuilding the store). Revision 2 (2026-11-13) answers the six findings of
  the independent review `adr-048-sol-review` (F1–F6), closes every difference between its
  egress inventory and Appendix A, and records the decider's answer to Q1 (per room; cross-ADR
  ledger row 35) and the rulings of rows 27, 32, 34, 37, 40 and 49 where they touch this lane.
  Revision 3 (2026-11-13) answers the second-pass review `adr-048-sol-review-2` (N1–N4): the
  debt's identity is the consent-order stamp, not a keyring digest; the key write to a denied
  peer is fenced at every poll of the frame write; the individual-trust acts use identities a
  manual removal can change; the release-asset evidence is restated as what the asset can show;
  rows 58 and 61 (a left room's copy and keys) are applied. Revision 4 (2026-11-13) answers the
  third-pass review `adr-048-sol-review-3` (R1–R5): a stale completion is installed and then
  retired, never discarded; the stamp is compared in every decision-dependent transaction; the
  key-write fence is the denied set kept under the store writer the frame poll already holds;
  acts 7, 8 and 9 are restaged so each mutant reaches its own assertion. Revision 5
  (2026-11-13) answers the fourth-pass review `adr-048-sol-review-4` (S1–S3): the denial state
  is the keyring's projection with per-peer incarnations, never one batch's view; the Store
  methods that set and read it under the writer are named; act 7's P3 guard and act 9(c) are
  restaged; and the cross-asks X048-7, X048-10 and X049-5 are settled in "Implementation order
  and related work" and "Consequences". Fix-list items 26, 27 (trust side), 66 (trust side),
  67; item 89 through ADR-046 SY-11. Revision 6 (2026-11-13) answers the fifth review
  `adr-048-sol-review-5` (F1–F3), proofs only: act 7(vii) holds the old job by its incarnation
  ticket and reads the fresh post before the release; the P3 guard asserts at the rekey
  selection boundary; act 9(c) stages the Refresh stage's own Session re-authoring, not the
  inbound package opener. Revision 7 (2026-11-13) answers the sixth review
  `adr-048-sol-review-6` (R6-1, R6-2) and the task cut's fifteen "ADR defects"
  (`v0431-tasks-ADR-048`): the secrecy acts' adversary is an individually trusted Y (a removed
  computer's nodes stop trusting N); the fold hold is ADR-040 r10's room-scoped knob with its
  engaging fact and its wake; `--keep-rooms`; the grant continuation is part of the pass (TC-5);
  every oracle is a line or command that exists or that TC-8 adds; the left room's debt has one
  moment (ADR-049's erasure batch); the order of landing is the order the acts can qualify.
  Revision 8 (2026-11-13) answers the seventh review `adr-048-sol-review-7` (R7-1–R7-8), proof
  staging only: the fence acts stage a parked debt with a withdraw hold (a held fold neither
  parks a withdrawal nor admits a post); act 2 completes through a real prerequisite; act 9(c)
  and TC-8's two unproved forms move to the house rule, NOT YET RUN; act 11 asserts the
  barrier's status, not a disclosure; implementation order and proof qualification are
  separated; Appendix B traces every act. Revision 9 (2026-11-13) answers the eighth review
  `adr-048-sol-review-8` (R8-1–R8-6): the withdraw hold covers every withdrawal dispatch
  including the manual Untrust's; act 2 completes through `RoomWrite` (a held Session record);
  act 2b grants full history to an admitted untrusted member and traces the selected builder;
  act 11's mutant is the receipt the status is derived from; act 10(b)'s gate is the lock, not
  the row; TC-6's permanent refusals are untouched by any surface finding. Revision 10
  (2026-11-13) answers the ninth review `adr-048-sol-review-9` (R9-1–R9-3) and folds in
  fix-list item 93 with the decider's row 82 and Main's row 82a: TC-4 gains the control lane (no
  room preflight before the keyring batch; a trust or policy command is never deferred behind a
  pending save; a control step waits for one in-flight owner and runs ahead of queued posts;
  posts delayed by at most one control transaction per write, never refused) and act 12 proves it;
  act 2b's mutant covers the nested `rekey_skdm`; act 11's mutant is the status classifier.
  Revision 11 (2026-11-13) answers the tenth review's R10-1 with Main's row 82b: two lanes per
  room, one turn each, alternating when both are ready, with 82b's bounds; `RemoveRoomMember`
  and `ReadmitRoomMember` are control work (ADR-043 r16's cross-ask); act 12 asserts the
  alternation with the "control back to back" mutant. R10-2 and R10-3 (P2) go to task
  acceptance under the decider's row 83. After the eleventh review Main scoped TC-4's control
  bound to the head of the lane (ledger row 82c, a wording precision that changes no design
  decision).
- **Date**: 2026-11-12; revisions 2 to 11 2026-11-13
- **Deciders**: Robert E. Lee
- **Tags**: computer trust, keyring, sender keys, confidentiality, failure containment, status
- **Related**: ADR-006 (S-14, S-15), ADR-007 (G-19), ADR-016 (NR-48), ADR-020 (V210-118),
  ADR-029 (SC-2b), ADR-034, ADR-035 (CT-14), ADR-037 (R5), ADR-038 (FX-28, FX-40, FX-45, FX-49,
  FX-62); in this release ADR-040 (NW-1–NW-4, NW-12), ADR-042 (TR-11, TR-23), ADR-043, ADR-046
  (SY-11), ADR-047 (SO-11), ADR-049
- **Inputs**: the operator's IO daemon log of 2026-11-12 19:40Z; `rca-RcaTrust`, `rca-RcaFrozen`,
  `plan-D` (D-34, D-35, rig26 on the release asset); ADR-040 revision 2 and both of its reviews;
  `adr-048-sol-review`; the `v0.4.30` tree (`8d71ab337`), every citation below read there.

## Context

### What the operator saw

On 2026-11-12 at 19:40:07Z the operator's IO daemon applied a computer-trust change. Node
omp-io held two rooms: repo-to-cve, where it works, and a room it had left. The trust pass
walked both. In the left room the withdrawal was refused: `node: this identity has left the
room`. The daemon logged `node omp-io computer trust reconciliation at revision 423 failed:
node: this identity has left the room`, then marked **both** rooms unable to save: 36 lines in
36 s of `room … recovery could not complete its retained save: … trust withdrawal is incomplete;
reopen this room` and `authored save worker stopped`, and `Vox: needs attention — repo-to-cve
cannot save`. omp-io could not post in repo-to-cve until the daemon was restarted (item 26). The
node stayed `applying`, every post refused, until that restart (item 67, D-35). Store recovery
rewrote both rooms' stores for a fault that was never on disk (item 66, D-34). After the restart
the left room came back as `[failed: node: this identity has left the room]` and failed again at
every later trust change (item 27).

Plan D reproduced all of it on the published `vox 0.4.30` asset (`/tmp/plan-PlanD/keep/run26-rig.log`):
`+18.3s rev 12->14 state=applying pending=["n: node: this identity has left the room"] | post R2
rc=1: vox: computer trust changed while this command was being applied`, `r2 cannot save: store
save room: node: trust withdrawal is incomplete; reopen this room`, through +27 s; after the
restart `[failed: node: this identity has left the room]` for the left room. Note what the rig
also shows: v0.4.30 disclosed nothing. It refused every post of every room while the pass was
stuck. Its failure is availability, not confidentiality; this ADR must keep the second while
repairing the first.

### Root causes at v0.4.30

| Item | Root cause | Status |
|---|---|---|
| 26 | `start_own_key_computer_drain` gives the pass every room in `channels` (`actor.rs:21011-21015`). `reserve_policy_rooms` (`trust_save.rs:628-701`) takes every room's single pending-write owner and holds all of them for the whole walk. The walk is serial (`continue_managed_trust`, `policy_save.rs:1300-1381`). Any room's error reaches `fail_managed_turn` (`:1384-1389`) → `release_rooms(rooms, poison = true)` (`:172-182`), which calls `poison("trust withdrawal is incomplete; reopen this room")` on **every** reserved room and releases each with `poison = true` (`pending_text.rs:748-761`, "authored save worker stopped"). | KNOWN (rig26, release asset) |
| 27 (trust side) | The pass's room list is every open room, and a left room is reopened at start as a member's room; its withdrawal is refused by `local_append_eligible_mode` (`local_history.rs:152-153`: "this identity has left the room"). A left room has nothing to withdraw: its departure is the narrowing. | KNOWN (rig26 +34 s) |
| 66 (trust side) | `poison()` (`channel.rs:5211-5237`) is called for a released reservation (`release_rooms`), for any trust-write error (`finish_pending_trust`, `pending_trust.rs:202-204`: `if let Err(error) = &result { self.poison(error) }`) and for a real store I/O latch alike; `recover_storage` rewrites every marked room. | KNOWN (rig26: 12 refused recoveries in 12 s) |
| 67 (D-35) | A failed pass leaves `computer_revision = u64::MAX` (`trust_save.rs:1091-1102`) until `finish_managed_policy` stores the revision (`policy_save.rs:1542-1547`), which a failed turn never reaches. `follow_computer_trust` (`host/computer.rs:36`) reconciles on change only; its failure branch (`:237-266`) logs `computer trust reconciliation at revision N failed` and nothing owns a retry. The node is `applying` and every current-authority operation fails until the next policy event or a restart. | KNOWN (rig26 +18–27 s) |

### What v0.4.30 already has, and this ADR builds on

- **The debt is already durable, per room and per removed member, and written in the same
  batch as the keyring.** `PolicyWrite::run_checked` (`trust_save.rs:115-210`) inserts a
  `PendingLocks` entry `(room, target)` for every room in the store for every denied identity
  (`:160-166`), and commits locks, consent order and keyring in one batch (`:198-202`).
  `pending_lock.rs:1-17` says why: a removal must change the lock in every room shared with the
  member and drop its keys; the record stays until the room acts on it, including a room the
  person closed in the TUI, whose key is not held while it is closed. A re-trust forgets it
  (`:172`, `trust_save/grant.rs:136-139`); a leave clears the room's entries
  (`leave_save.rs:298-302`). The pass reads it page by page (`TrustWrite::RemovalPage`,
  `pending_trust.rs:282-300`), withdraws each untrusted target (`ReconcileStage::Withdraw`), and
  clears the entry in the Delete that follows (`pending_trust.rs:264-268`, `debt_cleared`). This
  record is the trust debt. v0.4.30 never consults it on egress; that is the gap.
- **The withdrawal already rotates.** `prepare_pending_withdrawal` (`consent.rs:324-427`) and
  `rotate_for_withdrawal` (`:710-859`) mint a new sender chain, retain its origin, commit sender,
  origins and ledgers; `save` then appends a signed revocation (`:638-666`) and removes the
  target from `entitled`, `history` and `delivered` (`:680-697`). The new chain goes out later
  through the rekey pass (`consent_release/rekeys.rs`), whose recipients are filtered by
  `trust.is_trusted(peer)` (`:328`). This is ADR-006 S-14 ("rotate on every membership change
  that affects it (a trust removal)") and ADR-016 NR-48 ("a revoked member reads nothing after
  the rotation").
- **Every sender-key and drive-key encryption, and every construction of a key of either chain,
  goes through a handful of functions.** Appendix A lists them by effect and follows each to
  the point where bytes leave the node.
- **The authority barrier exists.** `computer_revision = u64::MAX` fails `policy_current` and
  every `with_current_computer_authority` fence; it is set after the keyring commit, on the
  actor (`trust_save.rs:1091-1102`), and cleared at `finish_managed_policy`.
- **A pairwise send to a peer is a per-peer queue the actor owns.** `pairwise_out: BTreeMap<peer,
  PairwiseOut>` (`actor.rs:6832`); each entry holds the `mpsc::Sender` of one writer task
  (`write_pairwise_jobs`, `:2708-2747`); dropping the sender ends the task and discards every
  queued job. A send in progress is fenced only by the room's member-removal generation
  (`pairwise_stream.rs:373-447`), not by the keyring.

## Terms

- **Narrowing**: a change to this node's trust after which some party may read less: a computer
  removed from the group, trust withdrawn from an identity (`vox trust remove`, `Policy::Untrust`
  on any node, managed or individual), a policy expired (`computer.rs:3295-3306`: every granted
  peer is denied). Each is one `PolicyWrite` with a `denied` set and one keyring batch.
- **W**: an identity whose trust is narrowed; **W's node**: a node that authenticates as W. Trust
  is per identity (`trust.rs:365-367`); a removed computer's nodes are each a denied identity
  (`derive_plan`, `computer.rs:3409-3431`).
- **The keyring batch**: the one node-store transaction that commits the new keyring, the pending
  locks and the consent order (`trust_save.rs:198-202`). The node **learns of** a narrowing when
  this batch is durable; the narrowing is **installed** when the actor has, in one turn, replaced
  every open room's mirror and installed the
  keyring (`install_owned_policy`).
- **Decision stamp**: one value of the node's consent-order counter (`consent_order.rs:80-160`:
  a durable counter under a random id, `last` only ever increases, written in the keyring batch by
  `queue_policy`, `:258-283`), drawn for each denied identity at the batch that denies it. Two
  stamps of one counter are ordered by `Stamp::after` (`:94-99`); stamps of two counters are
  never compared, so a counter re-created after a deleted blob can never match an old stamp. A
  keyring content digest is **not** a decision identity: remove W, re-trust W, remove W again
  serializes to the same bytes (`trust.rs:400-415`).
- **Trust debt** (of a room): the set of `PendingLocks` entries `(room, target, stamp)` for that
  room whose member is not trusted. A room with a non-empty debt is **indebted**. The debt is
  paid by the withdrawal of each entry's member and the Delete that clears the entry, both
  carrying the entry's stamp.
- **Protected content**: everything the room's sender chain and drive chain encrypt (posts,
  claims, announcements, read receipts, legacy Session controls, Session drive records), and
  every key of either chain of this node.
- **Fence**: the refusal, while a room is indebted, of (a) every encryption of protected
  content, (b) every construction, log commit or transport handoff of a key of this node's
  sender or drive chain for that room.
- **Public control**: a signed plaintext governance entry of the room (Presence, a consent grant
  or revocation, a ServiceShare, RoomAnchors, an admin certificate, a retention control, a
  departure). Every room member reads it by design; the sender chain plays no part in it.
- **The pass**: the managed trust continuation (`begin_managed_trust_continuation`,
  `policy_save.rs:1060`), the Untrust pass (`trust_save.rs:1190-1280`), the grant continuation
  of a trust decision that needs one (`Policy::Grant` with `needs_decision`,
  `policy_save.rs:438-441`; `policy_save/grant.rs`) and the trust stage of a room's preparation
  (`preparation_save.rs:958-1012`); the first three reserve every room today, all four run the
  same per-room steps.
- **Mirror**: the in-memory copy of a room's trust debt (entries with their stamps) on its
  `ChannelState`. The durable truth is `PendingLocks` and the consent-order counter.
- ADR-040's terms **not-yet**, **prerequisite**, **obligation**, **parked**, **owner**, and
  **marked unable to save** are used unchanged.

## Requirements

### 1. The property

- **TC-1. New sender-encrypted and drive-encrypted content of a room, and the keys that open it,
  never reach a party whose trust this node has narrowed; a trust change that cannot finish in
  one room blocks posting only in that room; and an open, unlocked room pays its debt by itself.**
  **(changed: F6; revision 3: N2's one boundary.)** Once the narrowing is installed (and, for
  every durable commit, once the keyring batch is durable): no protected content of any room
  MUST be encrypted under a chain that W's node can open; no key of this node's sender or drive
  chain MUST be constructed for, committed for, or written to a transport towards W's node; and
  every room other than one that is indebted MUST go on posting, reading and receiving. The
  narrowing
  completes room by room without another policy event, a restart or a command, for every room
  that is open on an unlocked node; a closed or locked room pays its debt at its next open or
  unlock (TC-7). A room whose debt is refused permanently stays fenced and is reported, not
  paid (TC-6).
  - *What the property does not say (the decider's limit, ADR-006/ADR-007).* A public control is
    not protected content: it is readable by every member of the room by design
    (`channel.rs:4712-4714` "This is a public control, not encrypted content"), and computer
    trust does not change who is a member of a room; room governance does (ADR-007). W's node,
    while it remains a room member, goes on reading public controls (a new share, a Presence, a
    revocation naming it) and receiving ciphertext it cannot open, exactly as it would under
    MLS, Signal or Matrix after a removal (see "Why this mechanism"). What W's node read before
    the narrowing it keeps. A key frame whose write to W's node completed under the store
    writer before the keyring batch took it may still be in flight and is not recalled; transport
    write completion is not receiver delivery, and this ADR does not promise that W's node never
    receives such a frame. It promises that the key in it is of the chain the withdrawal then
    retires, that nothing is encrypted under that chain after the batch, and that no frame write
    completes after the batch (TC-3 case 5 states the line). File
    bytes served over a room-bound tunnel are not under the sender chain and keep their own
    admission and revocation (`shares.rs`, `tunnel/`); this ADR does not change them and does
    not claim them.
  - *Why*: ADR-038 FX-28's security property ("a denied peer never reads content the node
    publishes after the denial") is the property; v0.4.30 keeps it only by holding every room's
    pending write for the whole pass and keeping the node non-current, which is what items 26 and
    67 broke. The decider, 2026-11-13: "A trust change that cannot finish in one room blocks
    posting only in that room; other rooms keep working" (ledger row 35).

### 2. The debt and the fence

- **TC-2. The debt is installed with the keyring, for every room, before anything else, and each
  entry carries the stamp of the decision that made it.** **(changed: N1; rows 58, 61.)** The
  keyring batch MUST insert the `PendingLocks` entry `(room, target, stamp)` for every denied
  identity and every room in the node's store, as `trust_save.rs:160-166` does, in the same
  transaction as the keyring; `queue_policy` (`consent_order.rs:258-283`) MUST draw one stamp
  per denied identity (today it draws stamps for additions only) and the batch writes it into
  every entry it inserts for that identity. An entry whose `(room, target)` already exists is
  replaced by the new stamp: the newer decision owns the debt. No design here moves this out of
  that batch. A room this identity has left MUST take no entry: under ADR-049 (rows 34, 58, 61)
  the left copy's rows and key are deleted at once (freed pages are cleared at the next store
  rewrite) and a hidden copy, where one is kept, lasts at most 2 days and only until one member
  has verified the leaving; it authors nothing (`local_history.rs:152-153`) and holds nothing to
  withdraw, so the batch skips a room whose leave record exists. **(revision 7: defect 13,
  X049-5: one moment.)** The room's existing entries are cleared, and its `TrustDebt` obligation
  retired, in **the batch that forgets the room**: ADR-049 LE-4 stage (a), the erasure's first
  batch, as `leave_save.rs:298-302` does today and as ADR-049 r8 states (`ADR-049:1244-1252`).
  Between LE-2 step 2's fence and that batch the debt exists and is moot: the fenced room
  publishes nothing, the debt refuses nothing the fence admits, and `vox computer status` does
  not list a room that has a leave record (TC-8). No batch of its own is added; a crash between
  the fence and the erasure leaves a moot entry the next open ignores (the pass skips the room).
  A rejoin is a fresh join (row 34; ADR-049 LE-9: the old copy's erasure finishes before the new
  room is installed): the new `ChannelState` inherits no consent and no debt, and its old
  `TrustDebt` obligation is retired with the old copy; a later narrowing inserts the room's entry
  as for any room, and its withdrawal is a no-consent ledger cleanup. An ended room's deletion
  (ADR-049) clears the room's entries in the same way.
  - *Why*: second-review F2 (the debt must exist before current authority is published or any
    open-time egress runs). At v0.4.30 it already does.
  - *Changes*: `PendingLocks` entries gain the stamp; `PendingLocks` gains `for_room_in(batch,
    signer, room)` (a read under an open transaction, returning entries with stamps) and
    `clear_stamped(room, target, stamp)` (removes the entry only if its stamp equals `stamp`);
    `queue_policy` draws a stamp per removal and returns it.

- **TC-3. The fence is checked where content is encrypted and where a key of this node's chains
  is built, committed or written to a transport; at prepare from the mirror and at commit from
  the durable record.** **(changed: F2, F3; the shared kernel.)** While a room is indebted:

  1. **No encryption under its sender chain**: `append_text` (`pending_text.rs:983`), the
     read-receipt flush (`pending_text/read.rs:446`), the legacy Session control
     (`pending_text/legacy_session.rs:19`).
  2. **No encryption under its drive chain**: the Session record (`pending_session.rs:1119`).
  3. **No construction of a key of this node's sender or drive chain**: `skdm_for_consent`
     (`channel.rs:4405`), `rekey_skdm` (`:4782`), `release_generation` (`:5360-5383`),
     `rekey_skdm_for` (`:5402`), `history_skdms` (`:5504-5540`), `full_consent_release`
     (`consent.rs:240`), `DriveState::release_for` (`drive.rs:228-241`).
  4. **No log commit of a key package carrying such a key**: the consent grant's package
     (`consent.rs:545-562`, `SignedEntryKind::KeyPackage`) and the Session package
     (`pending_session.rs:605-625`), both sealed to one recipient by `Work::SealOutbound`
     (`pending_package.rs:39-54`).
  5. **No write of such a key to W's node after the keyring batch; the check and the write are
     one critical section.** **(changed: N2; revision 4: R2.)** The one point that orders a
     frame write against a narrowing is the **store writer** (`Store::writer`,
     `store.rs:957-961`, the `Epochs` mutex): every store transaction holds it from
     `begin_write` (`:970-981`) through commit, so the keyring batch holds it; and every poll of
     every pairwise frame write already runs inside it (`write_pairwise_fenced`,
     `pairwise_stream.rs:401-447` → `with_removal_fence` → `with_publication_fence`,
     `read_resource.rs:233-248`, `store.rs:965-968`). The fence is put there and nowhere
     earlier. **(revision 5: S1, the API cutover.)**
     *The state.* The store keeps, beside the writer, the node's **current denial state**, a
     projection of the committed keyring and not of one batch: `Epochs.denied:
     BTreeSet<Digest32>` (every identity the keyring does not trust) and
     `Epochs.peer_incarnation: BTreeMap<Digest32, u64>` (per identity, bumped at every grant of
     it). A batch's commit **adds** its denied identities to `denied` (a manual `Untrust` names
     one target, `trust_save.rs:145-150`; a managed batch its `denied` set) and, for each
     identity it grants (`grants`, `:174-187`), **removes** it from `denied` and bumps its
     incarnation; nothing else touches either. Both are also written in the batch beside the
     keyring, and at open the store rebuilds them from there (`Keyring::load` plus the stored
     incarnations); a missing row rebuilds `denied` as the keyring's untrusted set and every
     incarnation as 0, which is safe because no job survives a restart.
     *The job's ticket.* A `PairwiseJob` sealed for a key carries `incarnation: u64` =
     `peer_incarnation[peer]` read under the writer when the job's credit was reserved
     (`reserve_key_deliveries`, `actor.rs:19216-19306`, already runs for every admitted key
     job). The per-poll check, inside the guard, refuses when `denied.contains(peer) ||
     peer_incarnation[peer] != job.incarnation`. With it: an old job held across "deny W, change
     Y" meets `denied[W]` (Y's batch does not erase W's entry); an old job held across "deny W,
     re-trust W" meets a changed incarnation and is refused, while the jobs the re-trust's rekey
     pass seals carry the new incarnation and pass. A job's permission is one-way: nothing
     restores it. A bare set replaced by each batch, or cleared by a re-trust, fails both
     sequences (S1).
     *The API* (the implementer MUST NOT read the state outside the guard or take the writer
     twice):
     - `Batch::commit(self)` (`store.rs:1971-2036`, consumes the batch and drops `epochs` before
       returning) gains a sibling `Batch::commit_with(self, f: impl FnOnce(&mut Epochs))`, which
       runs `f` **after** `txn.commit()` succeeds and **before** the guard is dropped; it is
       the only way to change `denied` or `peer_incarnation`. `PolicyWrite::run_checked`
       (`trust_save.rs:198-202`) calls `batch.commit_with(|e| e.deny(&removed); e.grant(&newly))`
       in place of `batch.commit()`; `trust_save/grant.rs` likewise for a manual grant.
     - `Store::with_publication_fence(step)` (`:965-968`) keeps its form and gains
       `Store::with_peer_fence(peer, incarnation, step) -> Result<Option<T>>`, which takes the
       writer, evaluates the denial check above on the `Epochs` it holds, and runs `step` only
       when it passes; `ReadResource::with_removal_fence` (`read_resource.rs:233-248`) gains a
       peer-aware form that calls it, and `write_pairwise_fenced` (`pairwise_stream.rs:401-447`)
       uses that form for every poll of every key frame. A `None` makes the poll return
       `StreamRefused("trust withdrawn")`; the stream is not finished (the peer discards a
       partial frame as it does today for a refused write) and the job's `after` reports
       `not delivered`.
     - `Store::peer_incarnation(peer)` is read under the writer by `reserve_key_deliveries` to
       stamp the job; no other reader exists.
     Every node-chain key job already carries `Some(RoomSendFence)` and goes through the
     fenced arm (`reserve_key_deliveries`; `consent_release/outbound.rs:43-64`; `rekeys.rs:457,
     494, 661`); the unfenced `None` arm of `write_pairwise_jobs` carries the reopen `Hello`
     and empty `Open` only (`actor.rs:19069-19120`), never a key. A future job variant that
     carries a key MUST use the fenced arm; this is a review condition, not an assumption.
     **The line.** A frame write is **before** the narrowing if and only if the poll that
     completed it (`write_all` of the body returning `Ready`, `framing.rs:16-24`) ran under a
     writer hold that preceded the keyring batch's hold; it is **after** otherwise, and after
     means refused. There is no third case: the mutex gives every poll and the batch a total
     order. Interleavings: (i) the writer's poll holds the guard and completes the body write;
     the batch then takes the guard: the frame is on the wire (before). (ii) The batch holds the
     guard, commits, updates `denied`, releases; the writer's next poll takes the guard, sees the
     peer denied, refuses: nothing more is written (after); the bytes of any earlier
     length-prefix poll leave the peer with a partial frame it drops. (iii) The poll loaded
     nothing earlier that matters: the only read is inside the guard. (iv) Deny W, then Y's
     unrelated batch: W stays in `denied`; W's held job is refused. (v) Deny W, re-trust W,
     W's held old job resumes: its incarnation is stale; refused; W's new jobs pass.
     *What is promised and what is not (TC-1).* A frame written before the batch may still be
     in flight; transport write completion is not receiver delivery, and this ADR does not
     promise that W's node never receives a key whose write completed before the batch. It
     promises that the key is of the chain the batch's withdrawal then retires (TC-6's
     rotation), that nothing is encrypted under that chain after the batch (the commit half), and
     that no frame write completes after the batch. At the install the actor still drops W's
     `pairwise_out` entry and releases its in-flight accounting so the rekey pass re-selects
     under the new keyring; that drop is housekeeping, not the fence. Per peer only: no other
     peer's writer and no other room is touched.

  Each refusal is `NotYet(TrustDebt(room))` (ADR-040 NW-1). The check has two halves, and both
  are REQUIRED:
  - **Prepare** (on the actor, under the room lock): the mirror is non-empty → refuse. The
    producers are `prepare_pending_text` (`pending_text.rs:299`), the flush selection
    (`read.rs:222-240`), the legacy announcement (`legacy_session_sender.rs:131`),
    `prepare_pending_session` (`pending_session.rs:236-256`), the consent issue
    (`consent.rs:258`), and the key-construction functions of case 3. `DriveState::release_for`
    runs on the Session worker: its capsule carries the mirror's emptiness at prepare, and case 4's
    commit check covers its package.
  - **Commit** (on the worker, inside the write transaction): `PendingLocks::for_room_in(batch,
    signer, room)` non-empty → the transaction is abandoned and the work is refused
    `NotYet(TrustDebt(room))`, exactly as the removal fence is checked at commit today
    (`pending_text.rs:1193`, `check_removal_generation_in`). An abandoned candidate's advanced
    in-memory sender is discarded; the work re-enters from committed state (ADR-040 NW-2 never
    treats this refusal as corruption). This half closes the window between the keyring batch
    committing on its worker and the actor installing the mirror: the keyring batch and the
    content batch serialize on the store writer, so there is no third ordering.
  - **The kernel is shared; the check is by effect.** `PendingText::append` commits encrypted
    content (cases 1, 2 through `pending_session`), key packages (case 4), **and** the
    withdrawal's revocation and the recovery's Presence (`consent.rs:638-666`,
    `pending_recovery.rs:865-882`). The commit check MUST run only when the `PendingText` carries
    a protected effect: a flag `protected: bool` set by the prepare sites of cases 1, 2 and 4, and
    never by `prepare_pending_control` for a control that encrypts nothing. An unconditional
    `PendingLocks != empty` guard in the kernel would refuse the repair (first-review finding 2).

  *What passes the fence* (each is a public control, local work, or a key that is not this
  node's): the withdrawal and its rotation (TC-6); the Delete, RemovalPage and MarkDecisions
  trust writes (`pending_trust.rs`); settlement and own-history recovery (`pending_recovery.rs`:
  a signed Presence with a sender rotation; `channel.rs:4727`); a departure (ADR-049); every
  other `append_governance` caller (`say_share` `channel.rs:3934`, `set_anchors` `:8993`,
  `say_presence` `:9269`, `:6449`); the governance fold and every projection
  (`session_projection/pending.rs:97`); retention, cleanup, roster, key-prune and metadata work;
  incoming records (`private_session/pending_upgrade.rs:270-297`); history serving of stored
  entries (`history_stream/server.rs`, `source.rs:603-669`, `sparse_history.rs:573`) and stored
  key-package bodies (row 40: every member keeps them; a stored body is a release already made,
  under the old chain, which the rotation retires); the recovery receiver seed
  (`pending_recovery.rs:691-698`, an SKDM for this node's own receiver); and **the own-original
  release** (`own_original_release`, `channel.rs:7724-7757` → `prepare_donor_reply`
  `own_keys.rs:2474-2493` → `seal_response` `:2389`): it returns the authenticated requester's
  **own** retained original SKDM from this node's receiver, never a key of this node's chains,
  and only to a trusted peer that is the author (`recovery_standing`, `:7739`; `is_trusted` at
  `own_keys.rs:308-312, 1363, 1469, 1689, 1982, 2216`). A requester's own-history recovery may
  need exactly that key (`own_history.rs:900-943`, `OwnReadability::KeyDebt`) before it can pay
  its own withdrawal; fencing it on the donor's debt would make two indebted members wait on
  each other (F2). W's node cannot use this path: it is untrusted, and the key is its own.

  The reservation function `reserve_pending_write` (`pending_text.rs:278-296`) is **not** the
  fence and gains no `purpose` argument; Appendix B of ADR-040 revision 2 is withdrawn. The
  consumers of the case-3 refusals MUST take the typed refusal into the owned stage: `rekeys.rs:372`
  (`let Ok(mut keys) = selected else { continue }`) and `consent_release.rs:1310` (`.ok()`)
  discard errors today and are to park the rekey or consent obligation on `TrustDebt(room)`
  (ADR-040 NW-3) instead of advancing past it.

  *Why the rotation is the repair.* W's node holds the chain in use when the narrowing is
  learned. No check on new publications protects content under that chain; only a new chain
  that W's node never receives does (first-review finding 1). The withdrawal mints it
  (`rotate_for_withdrawal`), the rekey pass delivers it only to trusted members
  (`rekeys.rs:328`; case 5 at the transport), and the fence keeps the old chain unused in
  between. After the debt is paid, the fence is down and the room's next encryption uses the new
  chain. The drive chain rotates inside the next Session save, before it encrypts
  (`pending_session.rs:653-661`, `drive.lost(holders)` where holders come from the keyring:
  ADR-029 SC-2b), so no Session record is encrypted under a drive chain W's node holds once the
  keyring is installed.
  - *Why*: first-review findings 1 and 8; second-review F1 and the inventory conclusion;
    `adr-048-sol-review` F2 (the own-original release is the requester's key), F3 (built keys
    sit in per-peer queues and in log packages; the builder is not the boundary), and its
    integration notes (the shared kernel; the discarded refusals). The encrypt and
    key-construction functions are a closed set found by reading every caller of
    `SenderChain::encrypt` (`group/state.rs:217`), `skdm_for` (`:244`),
    `OriginKeyStore::release_at`/`full_history_skdm` and `DriveState::release_for` in
    `crates/vox-core/src/node`; Appendix A follows each to its consumer.
  - *Changes*: `ChannelState.trust_debt: BTreeMap<Digest32, Stamp>` (the mirror), loaded from
    `PendingLocks` at channel creation (TC-7) and replaced by the actor at every keyring install
    (TC-4) and after each Delete; `require_no_trust_debt()` at the prepare sites;
    `PendingText.protected`; `PendingLocks::for_room_in` at the commit sites
    (`pending_text.rs:1190-1196`; `pending_session.rs:1096`); `Epochs.denied` set by
    `PolicyWrite::run_checked` under the store writer after its commit and compared in
    `write_pairwise_fenced`'s per-poll closure; `install_owned_policy` removes
    `pairwise_out[target]`. Cost: one sealed segment read per protected commit; the segment holds
    at most `MAX_PENDING` entries and is usually empty; one set lookup per write poll, under a
    mutex the poll already holds.
  - *Deleted*: nothing at v0.4.30; revision 2's `Egress` purpose on the reservation.

- **TC-4. The node is non-current from before the keyring batch until every open room's mirror
  and the new keyring are installed and the pass's exclusive lifetime is released; it is current
  from then on, whatever any room's debt (per room: the decider, 2026-11-13).** **(changed:
  physical lifetime; manual untrust.)** The managed write MUST store `computer_revision =
  u64::MAX` in its `before_commit` closure (`trust_save.rs:115-118, 313`; the atomic is shared,
  `actor.rs:6577`), not after the commit on the actor as today (`:1091-1102`); so no
  `with_current_computer_authority` operation, no rekey enqueue (`rekeys.rs:784`), no own-key
  reply (`own_keys.rs:530, 658`) and no publication lease (`post_save.rs:547-558`) is admitted
  from before the batch until the actor has, under each open room's lock, set its mirror from the
  committed locks and installed the new keyring (`install_owned_policy`, `trust_save.rs:705-738`).
  `finish_managed_policy` then stores the revision and publishes (`policy_save.rs:1542-1556`)
  **before** the room walk, and MUST drop the pass's exclusive Computer publication transition
  and own-writer transitions (`ManagedTurn.lifetime`, `policy_save.rs:92-103`;
  `trust_save.rs:213-225`) at that moment: the walk takes ordinary per-room admissions, and a
  parked debt holds no lease (ADR-040 NW-3). A room's debt neither keeps the node non-current
  nor touches another room. On an individual node (`ComputerAuthority::Unmanaged`, no revision)
  the same install step sets every open room's mirror and releases `TrustDebt(room)` as the
  Untrust pass (`trust_save.rs:1190-1280`) pays it; TC-8's words name the identity instead of
  a computer. A failure before the keyring batch commits keeps today's owner and report
  (`host/computer.rs:237-266`'s current-actor branch); it is not a room debt.

  *The control lane (revision 10: fix-list item 93; the decider's row 82, Main's row 82a).* A
  busy room is the normal case ("quiet room — lol"; "not the point of vox"). The application
  MUST NOT inspect, reserve or wait for any room, flow or member before or during its keyring
  batch: the pre-batch preflight `inspect_policy_rooms` (`trust_save.rs:603-617`, run by
  `start_own_key_computer_drain`, `actor.rs:21038-21075`), `policy_publication_blocker`'s use
  there (`pending_text.rs:242-275`), `PolicyRooms::Blocked`/`NativeOutcome::Blocked`
  (`trust_save.rs:695`; `policy_save.rs:544-546`) and `wait_policy_publication`/
  `park_policy_until` (`policy_save.rs:282-370`) go. At v0.4.30 that preflight parks the whole
  application until one room has no pending write and no sparse publication and restarts the
  inspection on every wake; on a member whose rooms receive writes continuously it never
  finishes, the applied revision stays stale, and every post is refused `Fault::ComputerPolicy`
  ("computer trust changed while this command was being applied", `post_save.rs:547-558` →
  `computer.rs:2839-2852`; `api.rs:1792`): CONFIRMED at the tag, seen on the release asset in
  `/opt/vox-evidence/v0431/arm-replace/r2-B3dc-base/` and dominant in `r5a-B3dc-arm` (2,197
  posts accepted before the roster change, none after). **Two lanes, one turn each (Main's row
  82b; revision 11: R10-1).** Each room has two lanes, FIFO within each: the **control** lane
  (trust and computer-policy commands, roster changes, rekeys, key packages, keyring batches,
  the per-room steps of TC-5, evictions and readmissions) and the **authored** lane (posts,
  Session activity, read marks). When both lanes have ready work they alternate: one control
  turn, then one authored turn; when one lane alone has work it runs back to back. A **turn** is
  one native transaction, ending at its own Immediate commit and installation (row 74: one
  flush per ruled save). A multi-step control operation takes one turn per transaction and keeps
  its continuation between turns: a withdrawal's rotation, its revocation, its ledger cleanup
  and then its Delete are separate turns (`consent.rs:812-853, 655-666, 680-697`;
  `pending_trust.rs:264-268`), each carrying TC-6's stamp and its stage-exact completion across
  the hand-offs; the commits are never merged to shorten a wait. A child transaction a control
  step dispatches runs in its parent's turn and never queues behind its parent. Bounds (row
  82c): a control step, once at the head of its lane, waits for at most the transaction in
  flight plus one authored write; from enrolment it also waits for the control transactions
  ahead of it and the one authored turn each permits; an authored
  write waits for the writes ahead of it in its lane plus at most one control transaction per
  write; newly arriving and re-armed controls are covered by the alternation, so a replenished
  control lane cannot starve a queued post. Nothing is refused in either direction. A trust or
  policy command is never deferred behind a pending ordinary save: `command_waits_for_save`'s
  retention (`post_save.rs:253-276` → `actor.rs:8075-8088`) goes for `Untrust`, `Proved`,
  `Trust`, `TrustWith`, `SetCapability`, and for CJ-12's eviction and readmission,
  `RemoveRoomMember` (`post_save.rs:368-374`) and `ReadmitRoomMember` (ADR-043 r16's cross-ask):
  they are control work. Authored writes keep FIFO among themselves (`post_save.rs:329-335`).
  The barrier interval of this requirement (before the batch until the install) is milliseconds
  and retains, not refuses, a post (`actor.rs:8077-8081`). A roster change with no denied
  identity creates no debt and fences nothing. Every other trust step was checked for a wait on
  a quiet room: the grant continuation's reservation (TC-5, gone), the per-room steps (one turn
  each), and `OwnKeyWriterDrainRequired` (`policy_save.rs:1148-1152`), which waits for in-flight
  own-key responses to the removed peers to retire, bounded by those responses and not by room
  traffic; none remains. Sibling rows: ADR-040 NW-3 ("Two lanes, one turn each", r13) and
  ADR-044 RD-10 state this one rule; RD-10's single mixed FIFO is replaced by it.
  - *Why*: second-review F2 and first-review finding 16; `adr-048-sol-review` integration notes
    (a retained exclusive transition refuses every reader; `vox trust remove` has no revision).
  - *Changes*: the `before_commit` store; `install_owned_policy` sets each open room's mirror
    from `saved.locks` (entries with stamps) and drops each denied identity's queue, in the same
    actor turn, before the revision is stored (the write fence itself was set by the batch under
    the store writer, TC-3 case 5); `ManagedTurn` runs
    after `finish_managed_policy` with `lifetime` released; `host/computer.rs:237-266` reports a
    pass with debts as applied (TC-8); `record_application()` (`host/computer.rs:176, 233,
    258`), the receipt `vox computer status`'s `confirmed` is derived from
    (`pairing.rs:1884-1897, 2060-2072`), MUST be called only after the actor reports the
    install (revision 9: the barrier's person-visible contract).

### 3. Containment and completion

- **TC-5. The pass holds at most the room it is working on; a room's refusal parks that room's
  debt and marks nothing.** **(revision 7: defect 4, the grant path.)** The pass MUST NOT
  reserve any room up front: `reserve_policy_rooms` (`trust_save.rs:628-701`), the `PolicyRoom`
  reservations, and the grant continuation's reservation of every room (`reserves_rooms` for a
  `Policy::Grant` that `needs_decision`, `policy_save.rs:438-441`) go; each room's step, in the
  managed pass, the Untrust pass and the grant continuation alike, takes the room's pending-write
  owner as every other maintenance save does, for that step only. A room's not-yet MUST park the
  obligation `(room, TrustDebt)` (a narrowing) or `(room, TrustGrant)` (a grant's per-room
  consent or key step, ADR-040 NW-3 kind, stage-exact) on the prerequisite that refused it and
  the pass MUST go on to the next room. A room's permanent refusal or storage error retires or
  marks that room only (TC-6). `release_rooms(rooms, poison = true)` (`policy_save.rs:172-182`),
  `fail_managed_turn` (`:1384-1389`) and the grant continuation's five `release_rooms(…, true)`
  calls (`policy_save/grant.rs:64, 73, 81, 396, 596`) MUST NOT exist; `finish_pending_trust`'s
  `self.poison(error)` on any error (`pending_trust.rs:202-204`) goes through ADR-040 NW-2's
  typed decision, so a not-yet or a refusal never marks a room unable to save (item 66, trust
  side). A left room is never in the pass (TC-2; ADR-049).
  - *Why*: item 26; item 66; item 67 and D-35 (with no all-rooms failure there is no failed
    pass; each room's debt has its own owner and its own release).
  - *Changes*: `policy_save.rs`: `ManagedTurn` becomes a cursor over rooms with a per-room
    outcome `Paid | Parked(prerequisite) | Failed(refusal) | Marked`; `continue_managed_trust`'s
    `Err(error)` arm parks or retires by type; `start_own_key_computer_drain`
    (`actor.rs:21011-21015`) passes room ids, not reservations. `host/computer.rs:237-266`: the
    failure branch becomes the debts report (TC-8).
  - *Deleted*: `reserve_policy_rooms`, `release_rooms`, `fail_managed_turn`, the
    `PolicyPublicationBlocked` wait on another room's physical blocker
    (`trust_save.rs:646-670`: a blocked room is now a parked debt on `RoomWrite(room)` or
    `Settled(room)`, not a blocker of the pass).

- **TC-6. The debt is paid by work that never waits on itself, and always under the trust
  decision that is current.** **(changed: F1; crash windows; item 89.)** For each entry
  `(room, target)` of the room's debt, the pass runs, as today, `Withdraw(target)` then
  `Delete { withdrawn: target }`:
  - `prepare_pending_withdrawal` (`consent.rs:324`): if `has_consented(target)` it rotates the
    sender chain, appends a signed revocation and removes the target from `entitled`, `history`
    and `delivered`; if not (already revoked, or never consented), it clears the ledgers and
    appends nothing (`:338`). Neither branch encrypts under a chain or releases a key: the fence
    is not consulted. Its prerequisites are `RoomWrite(room)` (the reservation),
    `GovernanceFold(room)` (`with_consent_facts` refreshing), `Settled(room)`
    (`ensure_governance_append_eligible_by`, `channel.rs:6473-6475`, `RoomNotSynced`) and
    `OwnHistory(room)` (`:6477-6481`), each released as ADR-040 NW-1's table says. It is never
    `ComputerPolicy` (first-review finding 2) and never `TrustDebt` (the debt is its own). The
    own-history check is a read of `own_behind` under the room lock; it MUST NOT wait on the
    actor's own-history fence (fix-list item 89, an actor blocked 136–214 s there): ADR-046
    SY-11's nonblocking prerequisite is what this step consumes, and a `behind` answer parks on
    `OwnHistory(room)`.
  - `Delete` (`pending_trust.rs:216-281`) drops the target's receiver chains and clears the entry
    (`:264-268`). Its commit releases `TrustDebt(room)` once the room's debt is empty: the actor
    removes the target from the mirror under the room lock, bumps the generation and wakes every
    obligation parked on `TrustDebt(room)` (ADR-040 NW-3).

  *The decision the debt is paid under (F1).* A `Reconcile` captures a `trusted` set and
  monotone cursors (`trust_save.rs:405-578`); `RemovalPage` skips members at or below `after`
  and members of the captured set (`pending_trust.rs:282-317`). Parked across a keyring change,
  that capture is wrong twice: a member removed later whose fingerprint sorts below the cursor
  is never visited, and a Delete derived before a re-trust can clear an entry a **second**
  removal inserted, without the second withdrawal, on a chain the re-trust released to W's
  node. Therefore:
  - a parked `(room, TrustDebt)` obligation MUST be rebased at every keyring install: its stage
    is replaced by a fresh `Reconcile` (stage `DeleteInitial`, `trusted` = the new keyring), as
    `preparation_save.rs:958-968` already does when `matches_trust` fails. The kind is
    stage-exact between two installs only. **(revision 4: R1.)** A completion of the old stage
    that arrives after the install (a `CompletedConsent` or `CompletedTrust` the actor has not
    consumed) is **installed and then retired**, never discarded: the completion is the receipt
    of what its worker committed (`CompletedConsent` carries the committed origins, sender,
    entitled/history/delivered ledgers and package seq, `consent.rs:473-528`; `CompletedTrust`
    the committed receiver deletions and version stamps, `pending_trust.rs:167-204`), so the
    actor calls `finish_pending_consent`/`finish_pending_trust` as today (`consent.rs:430-470`;
    `pending_trust.rs:190-206`: installs the committed deltas, releases the reservation and the
    history pin), and then, instead of handing the result to the old `Reconcile`, drops that
    continuation; the rebased obligation runs from `DeleteInitial` under the new keyring. A
    rotation committed under the old decision is therefore the room's sender when the new
    decision's withdrawal runs; it is never lost and never re-done. A completion whose every
    transaction was refused (stamp mismatch) carries nothing committed and installs nothing.
  - every withdrawal and every `TrustWrite::Delete` MUST carry the stamp of the entry it pays
    (`Reconcile` reads it from the `RemovalPage`), and MUST compare it inside **each** write
    transaction that depends on the decision; there is no outer transaction (`PendingConsent::save`
    is a sequence of commits: the rotation batch or the Presence append carrying the rotation
    rows, `consent.rs:812-853`; the revocation append, `:655-666`; the ledger cleanup batch,
    `:680-697`; and `stamp_mint`'s counter update, `consent_order.rs:304-306`). Each of the
    rotation, revocation and cleanup transactions reads `PendingLocks::for_room_in(batch)` and
    proceeds only if `(room, target, stamp)` is present; otherwise it returns
    `NotYet(TrustDebt(room))` with nothing written in that transaction (earlier commits of the
    same `save` stand and are carried by the completion, above). The Delete in
    `PendingTrust::run` (`pending_trust.rs:264-268`) clears through `clear_stamped`, which
    clears only an entry whose stamp is equal; a mismatch refuses, clears nothing, and the actor
    rebases. A stamp cannot repeat: the counter's `last` only increases and is committed with
    the batch that drew it (`consent_order.rs:120-126, 258-283`); two decisions are ordered by
    `Stamp::after`; a crash between two decisions leaves the first durable with its stamp or
    leaves nothing, and the second draws a greater value either way; a counter blob re-created
    after loss carries a fresh id that no old stamp matches, so an old completion can never clear
    a new entry. The keyring's content digest (`sha256(Keyring::to_bytes())`) is not used for
    this: remove, re-trust, remove serializes identically (`trust.rs:400-415`).
  - a re-trust of the target before the debt is paid forgets the entry in the grant's batch
    (`trust_save/grant.rs:136-139`); the actor then replaces the mirror; if the room's debt is
    now empty it releases `TrustDebt(room)` (every transition to "true" releases, ADR-040 NW-3)
    and retires the parked obligation. A re-trust issues a new consent and the rekey pass
    delivers the live chain to W's node, as today: that is the person's decision, and no
    withdrawal is owed for it.

  *Why it cannot wait on itself.* The withdrawal's four prerequisites are released by work that
  passes the fence: the fold and projections are local (second-review F3); the settlement and
  the own-history recovery are a signed Presence with a rotation (`pending_recovery.rs:420-485,
  805-882`; `append_governance_with_sender` with `recover_own`, `channel.rs:4727`), which
  encrypts nothing and releases nothing, so they complete while the room is indebted, and
  `OwnHistory(room)` is released at their authoritative completion (ADR-040 NW-1, ADR-046); the
  original key a recovery may need from another member is the requester's own and passes the
  donor's fence (TC-3). This breaks the OwnHistory↔TrustDebt cycle (second-review F4,
  `adr-048-sol-review` F2) without unfencing any content: the recovery's new chain is minted
  while W's node is still in `entitled`, so the rotation marks W's node owed; the rekey pass is
  fenced (TC-3, cases 3 and 5) and filtered by `is_trusted` (`rekeys.rs:328`), and the
  withdrawal then removes W's node from the ledgers. No chain is released to W's node at any
  point.

  *Terminal outcomes.* A storage error marks the room under ADR-040 NW-2 and the debt parks on
  `StoreRecovery(room)`; the recovery's completion re-derives it on the replacement instance
  (no stale `ChannelState` pointer is kept). A permanent refusal (the room's format unsupported,
  `local_history.rs:156-158`; this identity not an author, `channel.rs:6483`) retires the debt
  with one log line and ADR-042 TR-23's `failed` line; the room stays fenced for good, which is
  safe and is **not** reported as paid. An ended room's debt is retired by the room's deletion
  (ADR-049); a left room has none (TC-2). A room the person closed in the TUI, or a locked node,
  holds its entries until the next open or unlock (TC-7); nothing opens or unlocks a room to pay
  a debt.

  *A revision move while a debt is parked.* The new keyring batch inserts its own entries and
  the obligation is rebased (above); when it runs it pays every entry the room then has.
  - *Why*: first-review finding 2; second-review F3 and F4; `adr-048-sol-review` F1, F2 and its
    liveness table.
  - *Changes*: `Reconcile`, `TrustWrite::Delete` and `consent_save::Work::Withdraw` carry the
    entry's `Stamp`; `PendingConsent::save` and `PendingTrust::run` compare it in each batch;
    the actor's keyring install rebases parked `TrustDebt` obligations, installs then retires
    superseded completions, and replaces mirrors; the Delete and re-trust completions release
    `TrustDebt(room)`.

- **TC-7. A room opens with its fence up and its debt parked; the debt is re-derived from the
  record, never from memory.** When a `ChannelState` is created (every open: start, unlock,
  join, reopen, a TUI-closed room reopened) it MUST load its mirror from `PendingLocks` before
  its first preparation stage runs, so the fence holds through Packages,
  Upgrade and Refresh (`preparation_save.rs:13-31`). **(revision 8: R7-1.)** At the tag none of
  those stages authors protected content for a current-layout room (`Stage::Packages` opens
  incoming keys, `:1038-1054`; `Stage::Refresh` dispatches `Refresh { owed: Vec::new() }`,
  `:1032`, which appends nothing when the record matches, `pending_session.rs:1295-1360`), so
  the early load is defense in depth for the stages ADR-049 and ADR-046 add, and the durable
  commit check (TC-3) is the control that protects a preparing room; its evidence is the
  house-rule spike of TC-9 act 9(c). The trust stage (`:958-1012`) pays the debt as today; a
  not-yet there MUST park `(room, TrustDebt)` and let the room go on to Remember and Ready: an
  indebted room is readable, receives and serves, and is published with the fence up. It MUST
  NOT be reported "stays closed". The mirror is never a restart source: it is a copy of the
  record.

  *Crash windows* (kill the daemon between any two durable steps):

  | Killed after | At the next open |
  |---|---|
  | the keyring batch (locks durable), before the mirrors | every room loads its debt; the trust stage pays it; startup re-derives the binding before Ready (FX-28); no protected commit between the two can have passed (TC-3's commit half) |
  | the withdrawal's rotation (one transaction: sender, origins, ledgers, and the Presence in a sparse room, `consent.rs:812-853`), before the revocation append (`:655-666`, a second transaction) | the entry is still there; `has_consented` is still true; the retry rotates **again** and revokes. The first new chain was retained in `origins` and may have been released by the rekey pass to trusted members only; a second rotation costs one more generation and discloses nothing. Rotation and revocation are not one transaction and this ADR does not say they are |
  | the revocation, before the Delete | `has_consented` is false; `Withdraw(target)` clears ledgers only (`consent.rs:338`); the Delete clears the entry whose stamp it carries |
  | the Delete | the entry is gone; the fence is down; nothing to do |
  | a protected commit that met the locks at commit time | the transaction was abandoned; nothing is on disk under the old chain |
  | the re-trust's grant batch | the entry is forgotten; the mirror loads empty; the parked obligation, if any, is retired at the first keyring install |
  | the keyring batch (which updated `Epochs.denied` and the incarnations under the writer and wrote them beside the keyring), before the install dropped W's queue | the queue was in memory only; at start every queue is empty and `denied`/incarnations are rebuilt from the stored row (or from the keyring's untrusted set at 0 when the row is absent), so W is denied; a frame whose completing poll ran before the batch is on the wire (TC-1's stated limit); none ran after |
  | a keyring batch that re-granted W, before the install | the incarnation bump is durable with the batch; no old job survived the restart; the rekey pass seals new jobs under the stored incarnation |
  | a keyring batch that drew stamps, before the next decision | the counter's `last` is durable with the batch; the next decision draws a greater value; an old Delete's stamp never equals a new entry's |
  - *Why*: second-review F2's second instance; ADR-040 NW-3's durability rule; item 27;
    `adr-048-sol-review`'s crash table.
  - *Changes*: `ChannelState::open*` loads the mirror; `advance_room_preparation`'s trust-stage
    error arm (`actor.rs:20743-20763`) parks instead of recording `reopen_failures` for a
    not-yet.

### 4. What a person is told

- **TC-8. A fenced room says so, once, in the words of the thing it waits for; a cleared fence
  says nothing.** **(changed: F5, F6; revision 7: defects 5, 6, 7, 13.)** A command refused by
  the fence is **not** retained: `vox room post` prints `vox: your message was not posted: room
  <name> still has to withdraw the keys of <k> node(s) of computer "<c>" (or: of <petname>, on
  an individual node); vox computer status shows when that is done; post it again then` and
  exits 1; the app's post (`vox-ffi/src/client.rs:4675-4709`) returns the same sentence. A
  daemon-owned egress (a read-receipt flush, a key delivery, a Session record, a rekey) parks on
  `TrustDebt(room)` silently and appears in `vox status`'s `waiting` block after 30 s as `room
  <id> (<name>): <what> waits until room <name> has withdrawn the keys of <k> node(s) of
  computer "<c>", for <dur>; Vox finishes it by itself` (ADR-042 TR-23; ADR-040 NW-4). `vox
  computer status` says `confirmed` at the new revision and, **at once**, per indebted room
  that has no leave record: `room <name> still has to withdraw the keys of <k> node(s); it
  waits until <ADR-040 NW-1's words for the debt's prerequisite>` (ADR-043's "Not yet applied
  here, a room owes a trust withdrawal" row); for a permanently refused debt the same line ends
  `; it cannot: <refusal>; posting there stays refused`, and `vox status` prints TR-23's `failed`
  line. A closed room's debt is listed as `room <name> (closed) will withdraw the keys of <k>
  node(s) when it is next opened`; a locked node's as ADR-043's locked row (`vox node unlock`).
  The daemon log has these lines, each once per event, in TR-11's form:
  - `node <name> applied computer trust revision <N>; room <room> still has to withdraw the
    keys of <k> node(s), and waits until <words>` (one per pass with debts);
  - `room <id>: trust debt loaded: <k> node(s) of computer "<c>"` when a `ChannelState` loads
    its mirror (TC-7);
  - `room <id>: rekey pass: <k> recipient(s): <fingerprints>` after every rekey selection, the
    selected set before the trust filter (`rekeys.rs:143-215`);
  - `room <id>: key write refused: trust withdrawn (<peer>, incarnation <g>)` when a frame
    write is refused by the peer fence (TC-3 case 5);
  - `room <id>: released <peer>'s own key, generation <g>` when an own-original release is
    sent (TC-3's exemption);
  - `room <id>: Session refresh: preparing` before a Refresh prepares (TC-9 act 9(c));
  and none of `computer trust reconciliation at revision N failed`, `trust withdrawal is
  incomplete`, `authored save worker stopped`, `cannot save` for this cause. When the debt is
  paid the status lines go; no "recovered" line is printed. No surface says a member was
  "removed from the room": at the tag `vox room roster` prints the members' fingerprints
  (`room_cli.rs:2639`) and `vox room post`'s reach line says `you have not trusted it, so it
  cannot read this` (`:1244-1251`); this requirement adds `vox room members` (the name ADR-042
  r10's surface table and X048-9 agree on; ADR-042 owns its layout), which lists every member of
  `vox room roster` with a trust column `trusted` / `not trusted` as the keyring says. W's node
  stays listed (membership is the room's, ADR-007).
  - *`TrustDebt(room)`'s row in ADR-040 NW-1's table*: predicate "the room's `PendingLocks`
    entries for untrusted members are empty (mirror empty)"; released "under the room lock, in
    the actor turn that installs a Delete that cleared the room's last entry **or** a keyring
    install (a re-trust) after which the room has no entry, bumping the generation before the
    wake"; said as "room <name> has withdrawn the keys of the <k> node(s) of computer \"<c>\"".
    ADR-048 owns the row's words.

### 5. Proofs

- **TC-9. Every requirement lands with its proof in an existing journey, and each proof has a
  mutant that fails on its own assertion; two forms rest on the house rule instead.**
  **(revision 8: `adr-048-sol-review-7` R7-1–R7-8; Appendix B is the trace of every act.)**
  Extend `nodes_of_one_daemon_proof.rs::active_and_removed_computers_keep_local_manual_trust`
  (its comment says it has no room premise; the acts add rooms); act 8 extends
  `a_retrust_does_not_inherit_a_withdrawn_key_proof.rs`; act 2b(ii) extends
  `key_package_proof.rs::keys_reach_an_offline_member_through_an_always_on_member`; the app
  sentence is asserted in `app_api_proof.rs`. Every act runs inside one macOS guest or one Linux
  VM (row 32); every daemon takes its own scratch `--data-dir`/`--config-dir`; nothing runs on
  the host; `hostguard.sh` is run first and a `REFUSE` is APPARATUS.

  *Why the fold hold is not the staging gate.* At the tag a held governance fold does **not**
  park a withdrawal: `prepare_pending_withdrawal` treats a refreshing consent fact as "revoke"
  (`consent.rs:336-339`) and the removal-page withdrawal runs; the pass parks later, at its
  consent scan (`policy_save.rs:1372-1380`), after the debt is already paid. And a held fold
  refuses every post at `require_governance_ready` (`pending_text.rs:317`;
  `consent_facts`'s `governance_ready` false after a governance entry arrives,
  `channel.rs:3818, 4912`), so no fence mutant could ever admit a post under it. The fence acts
  therefore use **the withdraw hold**: `VOX_TEST_TRUST_WITHDRAW_HOLD_FILE=<path>:<room>`
  (`test-knobs`, new; prints `test-knob: trust withdrawal held for <room>`). **(revision 9:
  R8-1.)** It sits at the one dispatch boundary every withdrawal crosses,
  `begin_pending_maintenance` with `Work::Consent(consent_save::Work::Withdraw { target })`,
  **before** the worker prepares anything (the reservation is taken inside the worker's
  prepare, `consent.rs:324-427`): the manual Untrust's first room (`finish_owned_policy` →
  `Next::Withdraw`, `trust_save.rs:964-988`, dispatched by `schedule_trust_resume`,
  `policy_save.rs:853-873`) and its later rooms (`trust_save.rs:1242, 1268`), the managed pass
  (`policy_save.rs:1333`), the preparation trust stage (`preparation_save.rs:1005`) and the
  governance turn's withdrawal (`governance_save.rs:962`). For the named room it parks
  `(room, TrustDebt)` on a prerequisite `TestHold(room)` that only the file's removal releases,
  holding no reservation, pin or lifetime; the real narrowing has already committed its stamped
  entries and installed its mirrors (`install_owned_policy` runs before `Next::Withdraw` is
  returned, `trust_save.rs:965`). The marker is printed at that dispatch, after the install and
  before any withdrawal transaction. Under it the room's governance, own history and
  settlement are current and nothing but the fence refuses a post. Completion through a
  **real** prerequisite is act 2's business and uses `RoomWrite(room)`.

  *Cast.* A removed computer's nodes stop trusting N's node (on W's node `derive_plan` makes
  `own_active` false once its computer's grant is gone, `computer.rs:3376-3384`, so N's node
  is denied; W's node then refuses N's keys, `KeyRefusal::NotTrusted`,
  `pairwise_stream.rs:456-458`, `key_body_scan.rs:164, 330`). So the **adversary of every
  secrecy act is Y**, an identity N trusts individually and narrows with `vox trust remove`,
  whose own keyring N's narrowing does not touch; a managed removal is used only where the
  removed party's reading is not asserted (acts 1, 6, 10, 11).
  - **N**: the node under test, in a group with W; holds R1, R2, R3 and administers them.
  - **W, W3**: computers paired into N's group, one per managed-removal act (never re-paired);
    removed with v0.4.30's form `vox computer remove <full fingerprint> --confirm <frontier>`
    plus `--keep-rooms` on the candidate (ADR-043 CJ-12 evicts by default; v0.4.30 has neither
    the flag nor the eviction, so E-48-1 runs the same command without it).
  - **M**: a daemon in no group, trusted individually by N and by Y; a member of every room;
    keeps trusting Y and serves it (N refuses to serve an untrusted peer,
    `bounded_sync.rs:5124-5126`). Every "Y reads" is `vox room read R3 --json` on Y after Y
    synced from M; each secrecy act first asserts the M→Y route with a pre-narrowing post
    (absent: APPARATUS).
  - **X, X2, Y, Z**: identities N trusts individually (`vox trust add`), members of R3; Y is
    the adversary; X and X2 trigger rotations; Z is granted during a hold.
  - **Reading marks**: no CLI marks a message read; the hook does (`Request::MarkRead`,
    `agent_hook.rs:3768-3780`), driven by ADR-041 RS-7's shim. **Session records**: opened
    through the shipped hook as `a_room_with_its_own_session_records_opens_after_a_restart`
    stages it, and a prepared record reserves the room's pending write
    (`pending_session.rs:379-393`), so `VOX_TEST_SESSION_COMMIT_HOLD_FILE=<path>:<room>`
    (act 9(b)'s knob, `test-knobs`, new; holds the prepared record before its commit; prints
    `test-knob: Session record held for <room>`) also holds the room's `RoomWrite` owner.

  - **Act 1, containment (the one release-asset red; recorded).** Stop W's daemon; `vox room
    leave` R1 on N; engage the withdraw hold on R3; `vox computer remove W`. Within 10 s: `vox
    room post` in R2 succeeds and `vox room read` shows it; `vox computer status` says
    `confirmed` at the new revision; the daemon log has no `authored save worker stopped`, no
    `trust withdrawal is incomplete`, no `reconciliation … failed`; `vox status` lists no
    `cannot save`. v0.4.30: recorded in plan D's rig26 report at +18–27 s (`state=applying`,
    `post R2 rc=1`, both rooms `cannot save`: PRODUCT; raw receipt lost; E-48-1 repeats it as
    the fleet baseline with no hold: the left room is the tag's parked room). Mutant: on any
    room's not-yet, mark every room of the pass unable to save (the v0.4.30
    `release_rooms(poison = true)` behaviour); the R2 post and the no-`cannot save` assertions
    go red. No `test-knob:` line is APPARATUS.
  - **Act 2, completion through a real prerequisite (candidate only).** **(revision 9: R8-2;
    revision 10: R9-1.)** Y with drive, a drive holder of N's Session in R3. N's registered
    session opens a Session under `VOX_TEST_SESSION_COMMIT_HOLD_FILE=<path>:<R3>`: the prepared
    record holds R3's pending-write owner and sits in `pending_posts` (gate: the `test-knob:
    Session record held for R3` line). `vox trust remove Y` on N: under TC-4's control lane the
    command is admitted at once (at the tag it would be retained behind the pending save by
    `command_waits_for_save`, `post_save.rs:253-276`, `actor.rs:8075-8088`, and never dispatched
    while the record is pending, `:7876-7878`: that deferral goes, a product contract); its
    keyring batch commits and its mirrors install while the record owns R3; the withdrawal, a
    control step, waits for that one owner: `reserve_pending_write` (`pending_text.rs:278-296`)
    refuses "room publication is busy" = `NotYet(RoomWrite(R3))` and it parks. **Independent
    observation of the committed narrowing before the release**: `vox trust list` on N no longer
    lists Y, and `vox computer status` names R3 at once: `… it waits until an earlier change to
    this room finishes` (either absent within 10 s: PRODUCT, the command was deferred); R2
    posts; `vox status` `waiting` names R3 after 30 s. Remove the file: the held record's
    commit meets the durable debt (`for_room_in`), is refused `NotYet(TrustDebt(R3))` and
    releases the owner (`release_pending_text`, NW-1's release site for `RoomWrite`); the
    parked withdrawal runs ahead of any queued post; within 10 s `vox computer status` drops R3,
    a post in R3 succeeds, and the record then lands under a rotated drive chain (Y cannot read
    it: act 9(b)'s assertion, shared staging). `vox room roster` R3 still lists Y's node. A wait
    outliving the file's removal by 10 s is PRODUCT; no `test-knob:` line before the narrowing
    is APPARATUS. Mutant: drop the `(room, TrustDebt)` resume on `RoomWrite(room)`'s release
    (keep the release itself): status keeps naming R3 and the R3 post stays refused: red.
  - **Act 2b, key work waits (TC-3 cases 3 and 4).** **(revision 9: R8-3.)** Starting state:
    Z's node is a member of R3 that N has **not** trusted (admitted by N as creator; Z reads
    none of N's posts, asserted); N posts the control **C** before the hold. *(i) Builder.*
    Withdraw hold on R3 (Y's withdrawal parked; governance current); `vox trust add Z
    --history full` on N with Z's daemon up (`cli.rs:259`, `HistoryGrant::Full`): the grant
    writes R3's `MarkDecision` and the consent's key selection takes the **full-history
    branch** of `prepare_owned_consent_key` (`consent_release.rs:648-652`) →
    `full_consent_release` (`consent.rs:240`; case 3), refused `NotYet(TrustDebt(R3))`; the
    consent parks: `vox status` `waiting` lists `key delivery to <Z> … waits until room R3 has
    withdrawn …`; Z does not read C while the hold stands. Release: Z reads C within 10 s.
    Mutant **(revision 10: R9-2)**: remove case 3 at `full_consent_release` **and** at its
    nested `rekey_skdm` (`full_consent_release` calls `self.rekey_skdm(profile)?` first,
    `consent.rs:240-244`; `rekey_skdm` carries its own case-3 check, `channel.rs:4782`); the
    other branches, `release_generation` `channel.rs:5360-5383` for a `history_plan` and
    `skdm_for_consent` `:4405`, are not selected under `Full` and are listed so the implementer
    does not mutate the wrong one; the live key and plan are built, the online route
    (`outbound.rs:43-64`) delivers them (Z is not denied: the peer fence passes), and Z reads C
    during the hold: red on "Z does not read C". Surviving checks traced:
    `prepare_owned_consent_key`'s author, settled, own history, `require_governance_ready`
    (all current under the withdraw hold, `consent_release.rs:607-626`), member not removed,
    `room_removal_rotation_needed` (false). *(ii) Package.* Same starting state and hold; Z's
    daemon **stopped** when `vox trust add Z --history full` runs (gate: `vox status` on N
    shows Z `offline, last seen …`, row 27), so the consent takes the offline route
    (`consent_release.rs:690-715`: `prepare_owned_consent_key` then `Work::SealOutbound`,
    `pending_package.rs:39-47`, appended as a `SignedEntryKind::KeyPackage`,
    `consent.rs:545-562`; `key_package_proof.rs` stages this route with an always-on member).
    Under the candidate the key selection is refused as in (i) and the consent parks (the
    `waiting` line). Start Z, which syncs from M: Z does not read C while the hold stands;
    release; Z reads C within 10 s. Mutant: remove case 3 at `full_consent_release` **and** at
    its nested `rekey_skdm` (`consent.rs:240-244`; `channel.rs:4782`) **and** `protected` on the
    package append; the package commits during the hold, M serves it, Z
    opens it and reads C before the release: red. The same surviving checks as (i) plus the
    append's own `check_removal_generation` (unchanged).
  - **Act 2c, a typed refusal is parked, not dropped.** Before the narrowing M is trusted and
    admitted to R3 but M's daemon is stopped, so N owes M the live chain (`owed_rekeys` keeps
    M, `channel.rs:5014-5052`). Withdraw hold on R3; `vox trust remove Y`; start M: the rekey
    pass selects M (TC-8's `rekey pass: 1 recipient(s): <M>` line) and `rekey_skdm_for` is
    refused `NotYet(TrustDebt(R3))` (case 3); assert, while the hold stands, `vox status`
    `waiting`: `key delivery to <M> … waits until room R3 has withdrawn …` (after 30 s) and
    that M reads no post of R3 (M's rows undecrypted). Release: M reads a fresh post within
    10 s (positive control). Mutant: keep `rekeys.rs:372`'s `continue` (discard the typed
    refusal instead of parking): no `waiting` line for M appears while the hold stands: red on
    the waiting assertion, before any later scan can repair it. No `rekey pass` line naming M
    with M started and owed is PRODUCT; M not owed (it read a post before the hold) is
    APPARATUS.
  - **Act 3, confidentiality (candidate only; CANNOT MEASURE on v0.4.30).** M→Y route asserted;
    withdraw hold on R3; `vox trust remove Y` on N (the `test-knob:` line observed); N `vox room
    post` in R3 with the identifier **H**; **first** Y reads R3 via M (M's read asserted to
    show whatever N committed) and the act asserts H is absent on Y; **then** it asserts the
    post's rc was 1 with TC-8's sentence. Release; N posts P1; wait until `vox status` on N
    shows no wait and M reads P1; N posts P2; Y never shows H, P1 or P2 and still shows every
    post from before the removal. v0.4.30 cannot stage this act: CANNOT MEASURE; the evidence
    is the candidate's green and the mutant's red. Mutant (both halves): remove
    `require_no_trust_debt` at `prepare_pending_text` **and** `PendingText.protected`'s commit
    check; H is committed under the chain Y holds, M serves it, Y decrypts it: red on "H absent
    on Y" (PRODUCT). Surviving checks traced: `settled` (true), `require_governance_ready`
    (current), removal generation (unchanged), `require_own_history_current` (current),
    author, ended, the reservation (free). A missing M→Y route is APPARATUS.
  - **Act 4, the limit of the guarantee.** During act 3's hold, `vox service add` in R3 on N
    succeeds and Y's `vox room services` (via M) lists it, while act 3's H assertion stands.
    Mutant: fence `append_governance_with_sender` on the debt; the share is refused during the
    hold and Y's `vox room services` does not list it: red on "lists it" (PRODUCT). Not a
    secrecy assertion.
  - **Act 5, the own-history cycle through an indebted donor (candidate only).** Y with drive
    is M's consented reader; snapshot M's scratch data dir; M `vox trust remove Y` (M's sender
    in R3 rotates, `consent.rs:710-859`); M posts under the new generation and N receives M's
    release; stop M and restore the snapshot (M's own newer generation's key is now held by N
    only). Withdraw hold on N's R3; `vox trust remove X` on N (R3's debt parks: `vox computer
    status` names R3). Start M. **Independent preconditions, each observed before the clock
    starts**: M's `vox status` shows own-history recovering for R3 (ADR-046's line); M's `vox
    status` shows N `connected`; N's log has `room R3: own-key request from <M>, generation
    <g>` (TC-8's line, logged when the request is accepted, before any reply). From that
    request line: within 10 s N's log has `room R3: released <M>'s own key, generation <g>`
    and M's recovery completes (M reads its own posts). Release the hold; N's debt is paid;
    both post. Any precondition absent within 60 s of M's start is APPARATUS; the request
    logged and no release or no completion within 10 s is PRODUCT. Mutant: fence
    `own_original_release` on the donor's debt; the request is logged, the release never is,
    M's recovery does not complete: red (PRODUCT).
  - **Act 6, restart with a debt (candidate only; CANNOT MEASURE on v0.4.30).** Withdraw hold
    on R3 (the knob applies to the preparation trust stage too); `vox computer remove W3
    --keep-rooms`; kill N; start N with the hold still set: the trust stage parks R3's debt and
    the room goes on to Ready; assert `vox room list` shows R3 with no `[failed: …]`, R3 is
    readable, a post in R3 is refused with TC-8's sentence, `trust debt loaded` is in the log
    for R3; release; the post succeeds. Mutant: record `reopen_failures` for the trust-stage
    not-yet as today; R3 shows `[failed: …]` and is not readable: red.
  - **Act 7, a queued key is not written after the batch (candidate only; existing hold).**
    X, Y trusted; M→Y route asserted. Hold Y's pairwise key write with
    `VOX_TEST_HOLD_PAIRWISE_KEY_FILE` (`pairwise_stream.rs:379-396`; content `<peer>
    <incarnation>`, revision 6). `vox trust remove X`: the withdrawal rotates R3's sender to
    **K1** and owes Y and M K1 (`consent.rs:356-371`); assert the `.engaged` marker for Y
    (names g) and M's read of a fresh post **Q1**; assert Y's rows via M lack Q1 while M's have
    it (APPARATUS if Y reads Q1). `vox trust remove Y`; wait for `vox computer status` to show
    no R3 debt (K2 minted); release the hold. **Late-key assertion**: Y never reads Q1; N's log
    has `room R3: key write refused: trust withdrawn (<Y>, incarnation g)`. Mutant: remove the
    denied-identity check from the per-poll closure; the held K1 frame completes, Y decrypts
    Q1: red (PRODUCT). **(vi)** deny Y, then `vox trust remove X2`, release: Y never reads Q1
    (mutant: `denied` replaced by the last batch's set: red). **(vii)** hold `<Y> g`; `vox
    trust remove X` (K1 job held, `.engaged` names g); `vox trust remove Y`; `vox trust add Y`
    (g+1); the rekey pass delivers K2 at g+1 unheld: assert a fresh post **P4** is readable on
    Y; then release: the g job is refused (`key write refused … incarnation g`); Y never reads
    Q1 (mutant: skip the incarnation compare: Y decrypts Q1: red). **Post-removal selection
    guard**: after Y's removal and the K2 rotation, with M owing K2 (M cannot read the K2 post
    until a pass delivers it) and K2 minted (`vox computer status` shows no R3 debt): Y is
    absent from **every** R3 `rekey pass` line; M is named in **at least one** before M reads
    the K2 post (later passes may be empty or M-free, `channel.rs:5014-5052`,
    `actor.rs:16114-16129`); no pass line at all with both preconditions met is PRODUCT; a
    missing precondition is APPARATUS. Mutant: `consented_member_page` ignores `can_read`; a
    pass line names Y: red on "Y absent from every selection"; the Y-read of P3 stays green
    under this mutant (native recheck `rekeys.rs:570-580`, peer fence) and is a second
    assertion, not the red.
  - **Act 8, remove, re-trust, remove (candidate only; extends
    `a_retrust_does_not_inherit_a_withdrawn_key_proof.rs`).** Y consented, holding N's live
    chain. `VOX_TEST_TRUST_DELETE_HOLD_FILE=<path>:<R3>` (`test-knobs`, new; prints
    `test-knob: trust Delete held for <room>`) keeps the Delete request `(R3, Y, S1)` as an
    immutable record before preparation, holding nothing, exempt from the rebase. Sequence:
    `vox trust remove` Y (withdrawal: rotation to K1, revocation; D1 held); `vox trust add Y`
    (re-consented; rekey delivers K1; Y reads a fresh post, asserted); withdraw hold on R3;
    `vox trust remove` Y again (entry `(R3, Y, S2)`, `S2.after(S1)`; the second withdrawal
    parks under the hold); release D1 while the hold stands. `vox trust list` prints the same
    lines before each removal (identity by construction, `trust.rs:400-415`). Assert: `vox
    computer status` still names R3's debt (D1 cleared nothing); N's post in R3 is refused with
    TC-8's sentence; release the hold: W2 rotates to K2 and D2 clears S2; Y never reads a post
    made after the second removal. Mutant: `clear_stamped` ignores the stamp; D1 clears
    `(R3, Y, S2)`, the fence drops while the withdrawal is held, N's post goes out under K1, Y
    decrypts it: red (PRODUCT). The individual-node path of TC-4 (Unmanaged) is this act once
    more on a node of a daemon in no group.
  - **Act 9, receipts and Session records (candidate only).**
    - **(a) Receipt secrecy.** M posts **Q** in R3; N has not read it; Y reads Q. Withdraw hold
      on R3; `vox trust remove Y`; N's registered OMP session marks Q read through the hook's
      `mark_read` under RS-7's shim: the flush is refused at prepare and parks (`vox status`
      `waiting`: read receipts for R3 after 30 s); Y's `vox room read R3 --json` via M shows no
      `read_by` naming N on Q. Release; M shows N in Q's `read_by`. Mutant: remove the whole
      receipt fence (the prepare check in the flush selection and `protected` on its append);
      Y's `read_by` on Q shows N: red (PRODUCT). Surviving checks: `settled`, own history,
      `require_governance_display` (all current under the withdraw hold), author.
    - **(b) Session record commit.** Y trusted with drive, a drive holder of N's Session in
      R3 (reads an earlier record). N's registered session opens a Session (a record is
      prepared); `VOX_TEST_SESSION_COMMIT_HOLD_FILE=<path>:<R3>` (`test-knobs`, new; prints
      `test-knob: Session record held for <room>`) holds the prepared record before its
      commit; `vox trust remove Y`; release. Assert: the record is refused
      `NotYet(TrustDebt(R3))` (parks; `vox status` names it), Y never reads it; after the debt
      is paid the record lands under a rotated drive chain and Y still cannot read it. Mutant:
      skip the record transaction's `for_room_in` check; the held capsule (prepared before the
      narrowing: `drive.lost` ran against the old holders) commits under the drive chain Y
      holds; Y decrypts the record: red (PRODUCT). No `test-knob:` line before the batch is
      APPARATUS.
    - **(c) Open-time order: moved to the house rule (R7-1).** At the tag no pre-Trust stage
      authors protected content for a current-layout room: `Stage::Packages` opens incoming
      keys (`preparation_save.rs:1038-1054` → `Open`/`Attempt`, `:270-322`); `Stage::Refresh`
      dispatches `SessionWrite::Refresh { owed: Vec::new() }` (`:1032`), and `refresh_one`
      appends nothing when every owed recipient (none) is permitted and the record matches
      (`pending_session.rs:1295-1360, 1363-1518`); a capability grant dispatches
      `SessionWrite::Drive`, not `Refresh` (`actor.rs:24462-24584`, `session_save.rs:683-715`).
      No current-product input makes the startup Refresh append, so TC-7's early mirror load
      has no in-tree proof. It stands as a planned requirement under the house rule: review of
      `ChannelState::open*` and the stage order, plus an **uncommitted spike, run and reported,
      NOT YET RUN**: a `test-knobs` build with a diagnostic knob that makes `Stage::Refresh` of
      one room dispatch `owed = [Y]` so one record is re-authored; staging = act 6's restart
      with R3's debt parked; the report shows `trust debt loaded` before `Session refresh:
      preparing` and the prepare refusal, and, with the mirror loaded at Trust, the reversed
      order and a commit refusal. Owner: the task that lands TC-7 (V431-048-12); report under
      `/opt/vox-evidence/v0431/adr048/spike-tc7/`. The durable commit check (9(b)) is the
      control that protects a preparing room; TC-7 is defense in depth and the ordering of any
      stage ADR-049 or ADR-046 adds.
  - **Act 10, what a person is told (TC-8).** *(a)* During act 3's hold: `vox computer status`
    prints TC-8's sentence for R3 and nothing for R2; the daemon log has the `applied … still
    has to withdraw` line once; `vox room post`'s refusal is TC-8's sentence with exit 1;
    `app_api_proof.rs` asserts the FFI post returns the same sentence. Mutant: omit the
    indebted room from `vox computer status`: red on (a). *(b) Locked node, a status journey
    (revision 9: R8-5).* Gate: `vox node lock` N's node returns 0 **and** `vox status` shows the
    node locked (ADR-042's locked line); neither is the row under test. `vox computer remove W3
    --keep-rooms` on the daemon; assert `vox computer status` shows ADR-043's locked row for N
    (PRODUCT if absent); withdraw hold set; `vox node unlock`: `trust debt loaded` is logged
    for R3 and the sentence appears; release the hold; the sentence goes within 10 s. Mutant:
    omit the locked row (print `confirmed` for a locked node): red on the locked-row assertion.
    No ordering or publication claim is made here. *(c)* `vox room members` lists Y's node
    `not trusted` after act 2 (mutant: list only trusted members: red).
    *(d) The closed-room and permanent-refusal forms rest on the house rule (R7-7; revision 9:
    R8-6).* No CLI closes a room (the TUI and the app do), and a withdrawal's permanent
    refusals (unsupported room format, `local_history.rs:156-158`; not an author,
    `channel.rs:6483`) have no current-product staging. Both lines stay planned normative
    requirements, **exempt from this requirement's in-tree-proof sentence**, each with review
    plus an uncommitted spike, run and reported, **NOT YET RUN**: closed room: the TUI shim
    (ADR-041 RS-7's host) closes R3, `vox trust remove Y`, `vox computer status` shows the
    `(closed) will withdraw … when it is next opened` line, the TUI reopens R3, the debt is
    paid and the line goes; owner V431-048-09, report
    `/opt/vox-evidence/v0431/adr048/spike-closed/`. Permanent refusal: a member admitted
    without author capability if the product has one (ADR-007's read-only admission); owner
    V431-048-09, report `…/spike-permanent/`. If the implementation review finds no real
    staging, only the **status line's claim** is removed; TC-6's classification stands
    unchanged: an unsupported format and a non-author are permanent typed refusals
    (`Error::Profile`, never storage), the debt is retired, the room stays fenced and the
    `failed` line of ADR-040 NW-4 is what reports it. Design sign-off does not count either
    as proved; implementation acceptance awaits the reports.
  - **Act 11, the barrier (TC-4).** **(revision 9: R8-4; revision 10: R9-3.)** The
    person-visible contract of the barrier is the receipt: `vox computer status` says
    `confirmed` for this node only after the host has called `record_application()`
    (`host/computer.rs:176, 233, 258`), which the host does only on the actor's reconciliation
    result, after the install; `confirmed` is derived from that signed receipt's validity and an
    empty `pending_nodes` (`pairing.rs:1884-1897, 2060-2072`), not from the actor's atomic.
    `VOX_TEST_TRUST_INSTALL_HOLD_FILE=<path>` (`test-knobs`, new; prints `test-knob: trust
    install held`) holds the actor between the keyring batch's commit and the install. `vox
    computer remove W3 --keep-rooms`; while held: `vox computer status` is `applying`, not
    `confirmed`, and a post in R2 is **retained** (TC-4's lane: `actor.rs:8077-8081`) and
    acknowledged after the release, not refused; release: `confirmed`, R2 posts, R3's debt
    parks. Mutant (the direct wrong-status mutant at `Management::status`'s output boundary,
    `pairing.rs:2060-2072`): classify this applying node's application `confirmed` while its
    real receipt, `pending_nodes` and the retained transition are untouched; `vox computer
    status` says `confirmed` during the hold: red on "not confirmed while held" (PRODUCT). An
    early `record_application()` call is **not** this mutant: it returns without a receipt
    while a current-target pending node remains (`pairing.rs:832-840`), and `Computer::change`
    (`:842`) needs the `changes_writer` the application holds in its
    `ComputerPublicationTransition` (`computer.rs:2664-2666, 4200-4242`;
    `trust_save.rs:213-225`) until the install. TC-4 keeps: `record_application()` MUST be
    called only after the install (mirrors, `denied`, keyring) is reported by the actor. The
    exact `before_commit` placement of the `u64::MAX` store is redundant for fresh person
    operations (the lease and `policy_current` refuse them) and is a **source-review condition**
    backed by the house-rule spike: NOT YET RUN; a `test-knobs` build that delays the store by
    500 ms and posts in that window; owner V431-048-06; report `…/spike-tc4/`; an experiment,
    not an observed distinction. No disclosure assertion is made in this act.
  - **Act 12, a busy member through a roster change (TC-4's lanes; item 93; rows 82, 82b).** N
    and M each run one closed-loop poster in R3 (ADR-044's rig shape, about 0.3 posts/s each, so
    R3 has a received write pending most of the time); after 30 s, `vox node create` on W (a
    roster change bumps the policy revision, `computer.rs:1655-1672`); the posters run 60 s
    more. Assert: every N post in the window is acknowledged (rc 0) within 5 s **and** is read
    back by `vox room read` on N and on M; no post is refused and no output or log line contains
    `computer trust changed while this command was being applied` or `computer policy changed
    while its prior application was pending`; `vox computer status` is `confirmed` ≤ 10 s after
    the create; the new node reads R3 within 60 s. Gate: at least 10 of M's posts landed on N
    during the window (else the room was quiet: APPARATUS). v0.4.30 red: PRODUCT, recorded on
    the release asset in `/opt/vox-evidence/v0431/arm-replace/r2-B3dc-base/` (y1 unhealthy
    `computer policy changed while its prior application was pending`, 7 samples) and in the
    prototype's `r5a-B3dc-arm` (2,197 posts accepted before the change, none after). Mutant (1):
    restore the pre-batch room preflight (park the application until every room has no pending
    write); under the two posters the batch never commits within 60 s and N's posts are refused
    `ComputerPolicy`: red on the 5 s acknowledgment. **Alternation (revision 11; consistent with
    ADR-040 r13's act 3 extension).** The create makes R3's control lane multi-turn without any
    narrowing: the room's `MarkDecisions` turn, then the new node's consent (a key turn, and a
    package turn when it is offline), each a separate transaction (`pending_trust.rs:211-281`;
    `consent.rs:545-562`). Receipt: `test-knob: control turn <room> <stage>` per control turn
    (`test-knobs` only; absent: APPARATUS). Assert: with a post queued in the authored lane
    (the loops keep one in flight at every moment: their per-post times show no gap, else
    APPARATUS), at least one loop post's commit time falls between two consecutive control-turn
    lines of R3, and no post's acknowledgment exceeds its FIFO predecessors' plus one control
    transaction. Mutant (2): **control runs back to back while a post is queued** (the arbiter
    takes the next ready control instead of the authored turn); the queued post lands only
    after the last control transaction: red on the post's bound. Surviving checks traced: the
    barrier (closed only from before the batch to the install), the publication lease (free once
    current), the fence (no denied identity: nothing fenced), authored FIFO. A narrowing is not
    used here on purpose: an indebted room refuses posts by design (act 3); the alternation
    bound under a narrowing is ADR-040's act 3 extension (the rekey's recipients), shared.
  - Acceptance TC-9-A: post in a sibling room accepted ≤ 10 s after `computer remove`;
    `confirmed` ≤ 10 s; zero `cannot save` lines; the indebted room's post accepted ≤ 10 s after
    its prerequisite's release; no post, receipt or Session record of an indebted room authored
    after the narrowing readable on the narrowed party, and no key frame of N's chains for that
    room whose write completed after the keyring batch (a frame completed under the store
    writer before the batch may arrive; it carries only the chain the withdrawal retires).
    Public controls authored after the narrowing are readable on it (act 4).
  - *Evidence and the gate.* Each extended proof gets its row in `docs/release/changed-proofs.md`.
    No existing proof assertion matches TC-8's texts (the only assertion on a trust-pass text
    at the tag, `nodes_of_one_daemon_proof.rs:7558`, is ADR-040 NW-1's `ComputerPolicy` refusal
    and stays). The v0.4.30 release asset can show exactly one red in this lane, act 1's
    availability red, recorded in plan D's rig26 report; every other act needs a `test-knobs`
    build and is CANNOT MEASURE on v0.4.30, with the candidate's green and the mutant's red as
    its evidence (ADR-018 §7). **E-48-1** is act 1 staged on the release asset (left room plus
    removal; W's daemon stopped), repeated as the fleet baseline with receipts under
    `/opt/vox-evidence/v0431/adr048/e48-1/`; it is owed before the release gate (ADR-045), not
    before this ADR's sign-off. Three spikes (TC-7 ordering; the closed-room line; the
    permanent-refusal line; and TC-4's placement) are NOT YET RUN and are owed before
    implementation acceptance of their requirements. Design sign-off rests on the source retrace
    in the review record, Appendix B and the mutants above; no shipped disclosure is claimed
    anywhere.

## Why this mechanism, and not another

Mature group-messaging systems answer removal the same way: **the key changes, and the removed
party is simply not given the new key.** MLS (RFC 9420) removes a member with a Remove proposal
in a Commit; the Commit starts a new epoch whose secrets the removed member cannot derive, and
application messages of the old epoch are not re-protected. Signal's sender-key groups rotate
the sender key on membership change and distribute the new key pairwise to the remaining
members; what a removed member already holds, it keeps. Matrix's Megolm rotates the outbound
session on membership change and shares the new session only with current devices. None of
them tries to fence "every publication"; each fences exactly one thing: **no new content under
a key the removed party holds, and no new key to the removed party**. Vox's sender-key design
(ADR-006 S-14, ADR-016 NR-48) already says the same. This ADR therefore puts the fence at the
places where those two things are decided (encryption; key construction, commit and handoff),
uses the rotation Vox already performs as the repair, and leaves every public control, every
projection and every local write alone. That is why the repair cannot wait on itself: it is
made of exactly the things the fence does not touch.

## Unchanged rulings

- ADR-038 FX-28's security property: a denied peer never reads content the node publishes after
  the denial. TC-1 keeps it at the granularity at which a denied peer can read anything: the
  sender and drive chains of each room.
- ADR-006 S-14 and S-15, ADR-016 NR-48: a trust removal rotates the sender key and re-keys the
  members that keep their trust; a revoked member reads nothing after the rotation.
- ADR-007: room membership is the room's; a computer-trust change does not remove a member.
- ADR-020 V210-118: a removed member's keys are dropped and a key from an untrusted member is
  refused. The Delete does the first; `drive.rs:24` and `key_body_scan.rs` the second.
- ADR-029 SC-2b: a Session's drive chain rotates when a member that held it loses drive.
- ADR-038 FX-62: a key write to a peer is fenced by the room's member-removal generation; TC-3
  case 5 adds the denied-identity check beside it in the same per-poll closure, under the
  same store-writer hold, not instead.
- ADR-038 FX-40 and FX-45 as amended by ADR-040: a parked obligation holds no store, signer,
  lease, lock or worker; it resumes only on its prerequisite. `OwnKeyWriterDrainRequired` stays
  the pass's preserved owner (ADR-040 NW-1's table).
- ADR-040 NW-2: only a storage failure, a malformed artifact or the disk floor marks a room
  unable to save. This ADR removes the trust pass's two callers of `poison()` for other causes.
- ADR-037 R5: `OwnHistoryBehind` refuses a command; a daemon-owned obligation parks on
  `OwnHistory(room)`.
- ADR-034 §4 for real store write failures.
- ADR-018: only real use of the shipped binary proves a claim; every proof has a mutant.
- The file-sharing tunnel's admission and revocation (`shares.rs`, `tunnel/`) are unchanged and
  outside this ADR.

## Superseded and amended lines

Main applies these at sign-off. Quotes are from the tree at `d9a8667ba`.

| ADR and rule | Current text (file:line) | Replacement text |
|---|---|---|
| ADR-035 CT-14 | "Interrupted reconciliation MUST be recoverable without requiring the person to repeat fingerprint-by-fingerprint trust." (`ADR-035-computer-trust-and-daemon-identities.md:115-116`) | "Interrupted reconciliation MUST be recoverable without requiring the person to repeat fingerprint-by-fingerprint trust, without another policy change and without a restart. A room the reconciliation cannot finish yet holds its own trust debt: it encrypts no new content and releases no key of its chains until the debt is paid, and it does not stop the other rooms or keep the node from becoming current (ADR-048 TC-3, TC-5)." |
| ADR-038 FX-28 | "A node actor which has not applied the revision at the local observation boundary remains attached but non-authoritative: status names it pending and its prior projection fails every current-policy fence. The accepted application retains ownership and continues when its queue, room lock or storage can progress." (`ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:323-326`) | Unchanged, followed by: "A node has applied the revision once its keyring batch is durable and every open room's trust debt is installed from it (ADR-048 TC-4). A room whose withdrawal is not yet paid holds that room's trust debt: it encrypts nothing under its sender or drive chain and releases no key of them until the debt is paid (ADR-048 TC-3); the debt neither keeps the node non-authoritative nor reserves, marks or closes any other room (TC-5). A room this identity has left holds no debt (TC-2; ADR-049)." |
| ADR-038 FX-40 (barrier) | "Required authoritative application MUST settle its durable binding, keyring, revocation, key-package and consent work before publishing the exact current actor authority." (`ADR-038-…:970-971`) | "Required authoritative application MUST settle its durable binding and keyring, install every open room's trust debt from that keyring and release its exclusive publication transition, before publishing the exact current actor authority; it MUST be non-authoritative from before the keyring batch commits until then. Its revocation, key-package and consent work is settled room by room afterwards: a room whose share is not yet settled holds a trust debt and encrypts nothing and releases no key of its chains until it is paid (ADR-048 TC-3, TC-4); it does not hold back the authority publication." |
| ADR-038 FX-49 | "Actual supersession and permanent storage or mutation failures MUST retain their refusal and retirement semantics." (`ADR-038-…:1302-1303`) | ADR-040 r3's replacement, followed by: "They MUST NOT mark, reserve or terminalize any other room; a parked trust debt is rebased, never replayed, when the keyring changes (ADR-048 TC-5, TC-6)." |

Withdrawn from ADR-040 revision 2 with this split: NW-5's `Egress::Publish | Narrow | Local`
purpose on `reserve_pending_write`, Appendix B, and the sentence "No append reaches the log
without the owner".

## Implementation order and related work

**(revision 8: R7-8.)** Two orders, not one. **Implementation order** is the order the code is
built; **qualification order** is the order the acts may be run and counted, and an act
qualifies only when every requirement it asserts and every observable it reads exists in the
build under test. **The containment cut (TC-5) MUST NOT enter any build used outside the proof
environment without the replacement content and key fence (TC-2, TC-3, TC-7) in the same
build**: v0.4.30's all-room refusal is its confidentiality protection, and removing it alone
removes that protection.

Implementation order:

1. TC-5 and TC-6 (the pass, the Untrust pass and the grant continuation without reservations;
   park by prerequisite; the stamp-carrying withdrawal and Delete and the rebase; superseded
   completions installed then retired; NW-2's typed marking at `pending_trust.rs:203` lands with
   ADR-040 NW-2; the typed refusal taken into the rekey and consent stages). Scaffolding only;
   nothing qualifies on it alone.
2. TC-2 (stamps per removal in `queue_policy`; `for_room_in`, `clear_stamped`), TC-3 (the
   mirror, `protected`, the prepare and commit checks, the own-original exemption, the per-peer
   denied set under the store writer, compared in the frame-write poll), TC-7 (load at open).
3. TC-4 (the barrier moved before the commit; the install order queue drop → mirrors →
   revision; finish and lifetime release before the walk; the individual-node install).
4. TC-8 (the lines, `vox room members`) with ADR-042 TR-23 and ADR-043's status row.
5. The knobs of TC-9 (`VOX_TEST_TRUST_WITHDRAW_HOLD_FILE`, `_DELETE_HOLD_FILE`,
   `_INSTALL_HOLD_FILE`, `VOX_TEST_SESSION_COMMIT_HOLD_FILE`, the `<peer> <incarnation>` form
   of `VOX_TEST_HOLD_PAIRWISE_KEY_FILE`) and the `changed-proofs.md` rows.

Qualification order (Appendix B's gate column names what each act reads):

- after steps 1–5 together: acts 1, 2, 2b, 2c, 3, 4, 5, 6, 7, 8, 9(a), 9(b), 10(a)–(c), 11, 12 (act
  1's log assertions and act 2's status sentence need TC-8; acts 3, 6, 8 need TC-3 and the
  withdraw hold; act 11 needs TC-4 and its hold; acts 5 and 7 need TC-8's log lines);
- never in-tree: act 9(c), act 10(d) and TC-4's placement, which rest on the house rule
  (spikes NOT YET RUN);
- E-48-1 (act 1 on the release asset) is the fleet baseline, owed before the release gate.

Contracts needed from siblings, by requirement id (their design is theirs):

- **ADR-040 NW-3 ("Two lanes, one turn each", r13) and ADR-044 RD-10** (row 82b; revision 11):
  each room has a control lane and an authored lane, FIFO within each, alternating one turn
  each when both are ready; a turn is one native transaction; a multi-step control operation
  keeps its continuation between turns; a control step at the head of its lane waits for at
  most the in-flight transaction plus one authored write (row 82c), an authored write for the
  writes ahead of it plus at most
  one control transaction per write; nothing is refused; RD-10's single mixed FIFO is replaced.
  TC-4 states this one rule; each ADR names the others as its sibling rows. Act 12's
  alternation assertion and the `test-knob: control turn <room> <stage>` receipt are shared with
  ADR-040's act 3 extension.
- **ADR-040 NW-1**: `TrustDebt(room)`'s row is filled with TC-8's four columns (two release
  transitions); `Settled(room)` and `StoreRecovery(room)` are used as revision 3 defines them.
  **NW-2**: the typed `poison()` decision covers `finish_pending_trust`'s call
  (`pending_trust.rs:203`) and the abandoned protected commit. **NW-3**: kind `TrustDebt` is
  stage-exact between two keyring installs and rebased at every install; a room's deletion
  retires it; the rekey and consent kinds park on `TrustDebt(room)` when a key construction is
  refused; the grant continuation's per-room steps park as kind `TrustGrant` (TC-5). **NW-4**:
  the `failed` line's first reachable case is **not** this ADR's (revision 7, act 10: the two
  permanent refusals of a withdrawal cannot be staged without a faked refusal); ADR-040 is to
  reassign it. **NW-14**: this ADR uses no fold hold (revision 8: a held fold neither parks a
  withdrawal, `consent.rs:336-339`, nor admits a post, `pending_text.rs:317`); its new knobs
  (`VOX_TEST_TRUST_WITHDRAW_HOLD_FILE`, `_DELETE_HOLD_FILE`, `_INSTALL_HOLD_FILE`,
  `VOX_TEST_SESSION_COMMIT_HOLD_FILE`, each `<path>:<room>` with a `test-knob:` line) follow
  NW-14's rules. **NW-3's X040-19**:
  `TrustDebt` admits no person operation (a refused post is not retained), so it is not the
  kind that carries NW-3-C; ADR-040's "Appendix B is ADR-048's" (ADR-040:1063) is stale: this
  ADR withdrew it. **NW-12**: unchanged; its fenced flush is TC-3 case 1 and its settlement
  passes.
- **ADR-049** (row 34; X049-5; defect 13: one moment, settled in revision 7 as ADR-049 r8
  states it). A room's `PendingLocks` entries are cleared and its `TrustDebt` obligation
  retired in the batch that forgets the room, ADR-049 LE-4 stage (a) (`ADR-049:1244-1252`;
  `leave_save.rs:298-302` today). Between LE-2 step 2's fence and that batch the debt is moot
  and is not listed (TC-8 lists no room with a leave record). ADR-049 r8 needs no change; its
  three asks of TC-2 hold: (i) the pass skips a room whose leave record exists; (ii) the debt
  refuses nothing LE-2 step 2 admits; (iii) the clearing batch is LE-4's `Forget(room)` batch,
  not a batch of its own. The row this ADR previously asked ADR-049 to carry (LE-2 step 2 as the
  moment) is withdrawn.
- **ADR-046 SY-11** (item 89; X048-7 settled here). Row for ADR-046 to carry, verbatim: "SY-11:
  (a) the own-history check a withdrawal makes (`require_own_history_current`,
  `channel.rs:6477-6481`) MUST be a read of `own_behind` under the room lock that never waits
  on the actor's own-history fence; a `behind` answer is `NotYet(OwnHistory(room))` (ADR-048
  TC-6; fix-list item 89). (b) `OwnHistory(room)` is released at the recovery's authoritative
  completion, the commit of `append_governance_with_sender(recover_own = true)`
  (`channel.rs:6565-6568`), not on a refresh that leaves `own_behind` set. (c) The own-original
  release to a recovering member (`own_original_release`, `channel.rs:7724-7757`) passes the
  donor's trust fence (ADR-048 TC-3). (d) ADR-048 TC-9 act 5 stages 'behind own history with
  the missing original key held by one other member' by snapshotting a member's scratch store
  before a rotation it then performs; SY-11's recovery journey owns that staging and ADR-048
  reuses it; ADR-046's 'ADR-048 … [has] no row for this ADR' sentence is replaced by this
  row." Row 40 (every member keeps each key package's sealed body): a stored body is a past
  release and is served as today.
- **ADR-042 TR-23**: TC-8's `waiting` and `failed` lines, the `vox computer status` sentences
  (parked, permanent, closed) and the six daemon-log lines of TC-8, in TR-11's form; `vox room
  members` (X048-9: this ADR adds the command, ADR-042's surface table owns its layout and the
  `trusted` / `not trusted` column); the `PoisonCause` set has no trust-pass member (TR-12);
  row 27's `offline, last seen <dur> ago` is the member line this ADR's acts read for a stopped
  W. **ADR-043**: the "Not yet applied here, a room owes a trust withdrawal" row prints TC-8's
  sentence; CJ-12's `--keep-rooms` is what every managed-removal act passes (defect 3), and no
  act re-pairs a removed computer (defect 8: each act pairs a fresh one), so no re-pair verb is
  asked of ADR-043.
- **ADR-045 J6**: its trust act asserts TC-9-A; its "pass fails in the full room" staging is a
  debt parked on `StoreRecovery(room)` (TC-6), not a marked sibling; row 32: its daemons run
  inside the VM. The app's sentence (TC-8) is asserted in `app_api_proof.rs` (act 10(a)).
- **ADR-041 RS-7**: act 9(a) marks a message read through the hook's `mark_read` under RS-7's
  shim (no CLI marks read at the tag: defect 9).
- **ADR-047 SO-11**: the commit-time check is a read; it needs no floor. Row 49 (Session steps
  kept 2 days) does not change TC-3 case 2.
- **ADR-038 (accepted)**: the four amendments above.

## Consequences

### Positive

- One failing room no longer stops the node: item 26's 36 lines, the store rewrites and the
  restart go. The node is current once the keyring and the mirrors are installed.
- The property is held where it is decidable: no code path can encrypt under or build, commit
  or hand over a key of the old chain without passing one of the listed functions, and the
  commit-time check holds even when memory is stale. A changed decision rebases the repair.
- The repair is made only of things the fence does not touch, including the key another member
  needs to recover its own history.
- `vox computer status` names the room, the count and the wait at once; nothing is silent and
  nothing is a fault.

### Negative

- A protected commit reads one small sealed segment (`PendingLocks`) per transaction.
- A post in an indebted room is refused and the person must repeat it; a background receipt
  waits. Both last as long as the room's prerequisite, which is seconds in every reproduced case.
- A public control in an indebted room still reaches W's node while it is a room member; bytes
  whose frame write completed under the store writer before the keyring batch are not recalled. These are the documented
  limits of the property (TC-1), not defects.
- A closed room pays its debt only when the person next opens it; a permanently refused room
  stays fenced. Both are reported, neither is "finished by itself".

### Neutral

- The durable state changes in three places: `PendingLocks` entries gain the decision stamp,
  which the consent-order counter already mints in the keyring batch; the keyring row gains the
  denial generation and per-peer incarnations beside it (TC-3 case 5). No room log or peer-wire
  change. The daemon↔CLI status JSON gains these fields, which ADR-042 is to carry in its
  Appendix A (X048-10; contract row for ADR-042): in `vox computer status --json`, per node,
  `debts: [{room, name, nodes: [{fingerprint, computer}], waits_until: <NW-1 words>, since_ms,
  state: "parked" | "refused" | "closed", refusal?: string}]`; in `vox status --json`, the
  existing `waiting[]` entries for kind `trust-debt` use TR-23's shape with `what = "trust
  withdrawal"`. Plain text is TC-8's.

## Review record

Every finding of the three reviews in this lane, checked against `v0.4.30`.

| Finding | Classification | Evidence | Answered by |
|---|---|---|---|
| First review 1: ordinary content bypasses the debt fence | CONFIRMED | `prepare_pending_text` `pending_text.rs:299-340` calls no eligibility/policy function; rotation only when due `:347-350` | TC-3 (fence at encryption; rotation as repair) |
| First review 2: the withdrawal blocks on its own debt | CONFIRMED | `policy_save.rs:1330-1336` → `consent.rs:389-390` → `prepare_pending_control` → `prepare_pending_append` → `reserve_pending_write` | TC-6; TC-3's kernel check is by effect (`protected`), never unconditional |
| First review 8: receipts and settlement are not local | CONFIRMED | `read.rs:446`; `pending_recovery.rs:420-431, 805-882`; `channel.rs:6464-6488` | TC-3 case 1 (flush fenced); settlement passes; ADR-040 NW-12 keeps the policy lease |
| First review 16: FX-40's barrier contradicted | CONFIRMED | `ADR-038:970-971` | TC-4 and the FX-40 amendment (barrier, mirrors, lifetime release) |
| Second review F1: the live service-share append | CONFIRMED as to the claim; not a disclosure | `channel.rs:3934` → `:6507-6547`, no reservation; signed plaintext | TC-1's limit; TC-3; act 4 |
| Second review F2: debts before current authority and open-time egress | CONFIRMED | `trust_save.rs:1069-1102`; `preparation_save.rs:13-31` | TC-2, TC-4, TC-7, TC-3's commit half |
| Second review F3: admit local prerequisite work | CONFIRMED | `session_projection/pending.rs:97`; `pending_trust.rs:211-370` | TC-3 (not at the reservation; by effect) |
| Second review F4: the OwnHistory↔TrustDebt cycle | CONFIRMED | `channel.rs:6477-6481`; `pending_recovery.rs:435-485, 1067-1077` | TC-6; TC-3's own-original exemption; act 5 |
| Second review inventory conclusion | CONFIRMED | `pending_upgrade.rs:270-297`; `source.rs:603-669`; `sparse_history.rs:573-574` | Appendix A by effect and consumer |
| `adr-048-sol-review` F1: retained reconciliation across a changed decision (cursor skips a lower fingerprint; an old Delete clears a new entry after re-trust) | CONFIRMED | `Reconcile` captures `trusted` and monotone cursors (`trust_save.rs:405-578`); `RemovalPage` filters by both (`pending_trust.rs:282-317`); the Delete's superseded check uses the captured set (`:100-104`), so a re-trust+remove passes it; v0.4.30 never parks a pass, so the ABA is new to this design | TC-6 (rebase at every keyring install; the withdrawal and the Delete carry and compare the decision stamp in the batch (revision 3); re-trust releases and retires); act 8 |
| F2: the original-author key recovery is fenced | CONFIRMED | `own_original_release` (`channel.rs:7724-7757`) returns the requester's own retained SKDM from this node's receiver, gated by `recovery_standing` and `is_trusted`; `own_history.rs:900-943` `KeyDebt` needs it; `require_own_recovery_complete` before the Presence | TC-3 (exempt, with its author/room/epoch/trust checks kept); act 5 extended to a missing original key |
| F3: built keys at their real boundary (queued pairwise jobs; log key packages) | CONFIRMED | `rekeys.rs:749-805` moves sealed jobs to the per-peer queue; `actor.rs:2708-2747` writes later under `RoomSendFence` (removal generation only, `pairwise_stream.rs:373-447`); `install_owned_policy` clears actor maps, not queues (`trust_save.rs:705-738`); packages at `consent.rs:545-562`, `pending_session.rs:605-625` | TC-3 cases 4 and 5 (commit check on packages; queue dropped at install; the writer polls the per-peer flag at every frame write (revision 3); the line is the completing poll; no recall promise); act 7 |
| F4: confidentiality mutants cannot fail; no v0.4.30 disclosure red | CONFIRMED | rig26 refuses every post while the pass is stuck; each single-half mutant is stopped by the other half or by TC-4 | TC-9 act 3 (one mutant removes the whole fence; M serves W; no shipped disclosure claimed; v0.4.30 red is availability), act 6 (reachable mutant: `reopen_failures`), act 7, act 8 |
| F5: membership oracle | CONFIRMED | `members()` `channel.rs:9015-9027` = authors minus departures; the withdrawal touches consent ledgers only (`consent.rs:638-705`) | TC-8 (W's node stays listed, `not trusted`); act 2's assertion; re-pair before each removal |
| F6: overstated words | CONFIRMED | `pending_lock.rs:1-17` (closed rooms); TC-6's terminal cases; act 4 vs TC-9-A | TC-1 (new sender/drive-encrypted content; open, unlocked rooms; permanent and closed stated), TC-6, TC-8 (`vox computer status` at once; closed and permanent lines; "withdraw the keys of", not "remove"), TC-9-A |
| `adr-048-sol-review` crash table: rotation and revocation are two transactions | CONFIRMED | `consent.rs:812-853` (rotation rows; Presence in a sparse room), then `save` appends the revocation (`:655-666`) | TC-7's table (a retry rotates again; nothing is cleared on a rotation alone) |
| Integration notes: shared kernel; discarded refusals; physical lifetime; manual untrust | CONFIRMED | `consent.rs:638-666`, `pending_recovery.rs:865-882`; `rekeys.rs:372`, `consent_release.rs:1310`; `policy_save.rs:92-103`, `trust_save.rs:213-225`; `trust_save.rs:1190-1280` | TC-3 (`protected`; typed refusal taken into the stage), TC-4 (lifetime released before the walk; individual node) |
| Reviewer's Q1 | decided | — | per room (the decider, 2026-11-13; ledger row 35) |

Egress inventory, difference by difference (the reviewer's table against revision 1's
Appendix A): drive SKDM release (`drive.rs:228-241` → `session_save.rs:891-1069` →
`SessionWrite::Package`) added as case 3/4; outbound package publication (`Work::SealOutbound`,
`FrameOutbound`) added as case 4, the package row relabelled mixed; queued pairwise jobs and
cached frames added as case 5; stored private Session ciphertext (`sessionstream::answer`) added
as served-stored; file announcements (`shares.rs`, a sender-sealed post) added under case 1;
file and media bytes over the tunnel added as outside the chains and outside this ADR;
`node/offers.rs` corrected to trust offers; relay circuits added as carrying already-classified
paths; the own-original release moved from fenced to exempt (F2). Nothing in the reviewer's
inventory remains unclassified in Appendix A.

| `adr-048-sol-review-2` N1: a keyring content digest repeats across remove, re-trust, remove | CONFIRMED | `Keyring::to_bytes` (`trust.rs:400-415`) serializes entries, flags, `local_removals` and an import flag, no sequence; `untrust` moves W to `local_removals`, `trust_as` moves it back; both denied keyrings are byte-identical; `package_save.rs:255` hashes those bytes | TC-2 and TC-6: the consent-order stamp (`consent_order.rs:80-160, 258-283`: a durable monotone counter under a random id, drawn in the keyring batch) is the decision identity, carried in the entry, the withdrawal and the Delete and compared in each write transaction; stale completions installed then retired (revision 4); act 8 asserts byte-identical keyrings |
| N2: dropping the mpsc sender neither ends the writer nor empties its buffer; a check before `open_typed` is not a write-time fence | CONFIRMED | `PairwiseOut` holds a sender and semaphores, no task handle (`actor.rs:2656-2661`); an `OwnedPermit` keeps a sender (`:19190-19207`); a receiver drains buffered jobs before `None`; the proof hold sits after dequeue and before `open_typed` (`pairwise_stream.rs:379-400`); the per-poll fence checks the removal generation only (`:401-447`) | TC-3 case 5: the denied set kept under the store writer and compared inside the existing per-poll fence (revision 4); the line is the completing poll's writer hold; act 7's window is after dequeue; TC-1, TC-9-A and Consequences say "written … after the narrowing was installed" |
| N3: act 8 cannot untrust a managed W; act 7's X domain unstated | CONFIRMED | `computer_change_refused` (`actor/computer.rs:1170-1195`) refuses `Untrust` for a group-managed peer | TC-9 cast: X and Y individually trusted, M outside the group; acts 7 and 8 use them, no re-pairing; a managed refusal is APPARATUS |
| N4: acts 3 and 6 need a knob the release asset lacks; E-48-1/2 cannot acquire release provenance | CONFIRMED | the fold hold is `test-knobs` only; rig26 shows refusal, not disclosure | TC-9: only act 1 has a release red (recorded; raw receipt lost in the reboot; E-48-1 repeats it as the fleet baseline); every other act is CANNOT MEASURE on v0.4.30 with the candidate's mutants as evidence; E-48-2 withdrawn; the gate reworded |
| Review-2 act notes: act 3's oracle order and M's domain; act 5's missing-key means; act 7 tested a late key, not new content; TC-9-A promised receipts and Session records no act drove; rejoin "no debt" | CONFIRMED | — | act 3 reads H on W first; M outside the group; act 5 staged by snapshot-before-rotation (`vox trust remove` on M rotates M's sender); act 7 posts P3 after W's removal; act 9 added (flush, Session record, open-time refresh); TC-2 says "no inherited debt" |
| `adr-048-sol-review-3` R1: discarding a stale completion loses committed state | CONFIRMED | `CompletedConsent` carries committed origins, sender, ledgers and package seq whatever the result (`consent.rs:473-528`); `finish_pending_consent` installs them (`:430-470`); `CompletedTrust` carries committed deletions and stamps (`pending_trust.rs:167-204`); `PendingConsent::save` is several commits, not one (`:638-709, 812-853`; `stamp_mint` updates the counter separately) | TC-6: a stale completion is installed (its committed deltas and the reservation release) and then its continuation retired; the stamp is compared inside each decision-dependent transaction (rotation, revocation, cleanup, Delete), with no outer batch |
| R2: an Acquire load before the poll can be overtaken by the install | CONFIRMED | an atomic load is not mutual exclusion; `write_frame` can finish both writes in one admitted poll (`framing.rs:16-24`); the per-poll closure already runs under the store writer (`with_publication_fence` = `self.writer()`, `store.rs:957-968`; `read_resource.rs:233-248`), and every batch holds that writer from `begin_write` through commit (`:970-981`) | TC-3 case 5: `Epochs.denied` set by the keyring batch under the writer it holds, compared inside the same per-poll closure; the line is the completing poll's writer hold versus the batch's; TC-1 says a frame completed before the batch may arrive and that write completion is not delivery; TC-9-A reworded |
| R3: act 7's mutant cannot open P3 (K2) | CONFIRMED | the held job carries K1; W's own withdrawal rotates to K2 (`consent.rs:638-666, 710-859`) | act 7: late-key oracle on Q1 (authored under K1 and shown unreadable on W before the removal), labelled a late-key test; P3 kept as a separate guard with the `rekeys.rs:328` mutant |
| R4: act 8's hold sits after the reservation and blocks the re-consent | CONFIRMED | `prepare_pending_trust` reserves at `pending_trust.rs:146`; the owner is held until the completion is installed (`maintenance_save.rs:935-1030`); the consent needs the same owner (`consent.rs:258-320`) | act 8: the hold is an actor-side immutable Delete request before preparation, holding nothing and exempt from the rebase; the second withdrawal is parked on the fold so the old Delete's release is observable; both stamps and the intervening consent asserted |
| R5: act 9's three inverses are stopped by surviving defenses | CONFIRMED | (a) the flush is refused at prepare (`read.rs:222-240`) and N's own posts are skipped (`:177-179, 335-343`); (b) `drive.lost(holders)` rotates before encrypting (`pending_session.rs:653-666`); (c) the durable record check survives a late mirror | act 9: (a) whole-fence mutant on another author's unread post; (b) a drive holder Y and a capsule held before its commit, mutant on the record's `for_room_in` check; (c) an ordering assertion on the daemon log, not a secrecy claim |
| `adr-048-sol-review-4` S1: a batch-replaced denied set loses earlier denials; a re-trust revives held old jobs | CONFIRMED | `PolicyWrite::Untrust` carries one target (`trust_save.rs:145-150`); grants at `:174-187`; a detached writer and its held job outlive the map entry (`actor.rs:2708-2747, 19163-19207`) | TC-3 case 5: `Epochs.denied` is the keyring's untrusted projection (adds per batch, removes only re-granted identities, written beside the keyring, rebuilt at open) plus per-peer incarnations bumped at every grant and stamped into each job under the writer; the per-poll check is `denied.contains(peer) \|\| incarnation != job.incarnation`; act 7 (vi), (vii) |
| S1/R2 API: `Batch::commit` drops the guard before returning; `with_publication_fence` passes no state | CONFIRMED | `store.rs:1971-2036`, `:965-968`; `Epochs` private | TC-3 case 5 names `Batch::commit_with(f)` (runs `f` after `txn.commit()` and before the guard drops; the only mutator), `Store::with_peer_fence(peer, incarnation, step)` (the only reader, inside the guard), the peer-aware `with_removal_fence`, and `Store::peer_incarnation` for the job stamp; "no second writer hold" is a MUST |
| S2: a selector-only mutant is stopped by the transport fence | CONFIRMED | the per-poll check refuses the frame whatever the selector did | act 7's P3 guard: the mutant removes the selector filter **and** admits the job with no fence (unfenced arm); the bypassed boundaries are named; a selector-only mutation is not the guard's mutant |
| S3: act 9(c) asserts publication order, the mutant changes preparation order | CONFIRMED | a late mirror lets a prepare run and the durable check refuse the commit; no publication, room still opens after Trust | act 9(c): two named log events (`trust debt loaded`, `… prepared for …`), the order of the first `prepared` against `loaded` asserted, prepare-refusal versus commit-refusal distinguished; secrecy stays with 9(b) |
| Review-4 note: obsolete "discards stale completions" at the Changes line and the order list | CONFIRMED | — | both lines now read "installed then retired" |
| X048-10 (cross-ask): status JSON "fields ADR-042 defines" undefined | CONFIRMED | ADR-042 has no debt field | Consequences/Neutral states the fields as a contract row for ADR-042 Appendix A |
| X049-5 (cross-ask): one moment for retiring a left room's debt | CONFIRMED (two moments were stated) | `leave_save.rs:298-302` clears at erasure today | the leave's durable record transaction (LE-2 step 2) clears the entries and retires the obligation; the row for ADR-049 is written in "Contracts" |
| X048-7 (cross-ask): ADR-046 carries the SY-11 ask only partly | CONFIRMED | ADR-046:2575 "no row for this ADR" | the verbatim row for ADR-046 is written in "Contracts" |
| `adr-048-sol-review-5` F1: the P3 mutant never reaches W (selection by consent, native completion recheck) | CONFIRMED | `select_owned_rekeys` builds `pass.targets` from `owed_rekeys`/`owed_history_page` (`rekeys.rs:143-215`); `owed_rekeys` → `consented_member_page` needs `facts.can_read` (`channel.rs:4851-4886, 5014-5052`); the revocation clears W's consent and ledgers (`consent.rs:638-705`); `finish_owned_rekeys` rechecks trust (`rekeys.rs:570-580`) | act 7's P3 guard asserts at the selection boundary (`rekey pass: <k> recipient(s)` log line); mutant = the consent filter in `consented_member_page`; W-read kept as second assertion, not the red |
| F2: act 9(c) staged the inbound package opener | CONFIRMED | `Stage::Packages` dispatches `Work::Packages(Select)` → `Open`/`Attempt` (`preparation_save.rs:1038-1054, 270-322`): incoming keys for N, exempt; `Stage::Refresh` dispatches `SessionWrite::Refresh` (`:1032`), which re-authors N's own Session records under the drive chain (`pending_session.rs:1363-1518`) | act 9(c): producer = the Refresh stage's Session re-authoring; `Session refresh: preparing` emitted before the prepare check; pending state observed with `vox room sessions --json` before the kill |
| F3: the peer-wide hold releases the old job and the re-pair's fresh writer together | CONFIRMED | the knob matches the peer id only (`pairwise_stream.rs:386-396`); `pairwise_out[W]` is re-created for the re-pair (`actor.rs:19163-19188`) | act 7(vii): the knob holds by `<peer> <incarnation>`; the fresh post P4 is read on W **before** the release (causal order), then the old job is released and refused; reds named |
| `adr-048-sol-review-6` R6-1: requiring M in every rekey pass rejects a correct settled node | CONFIRMED | `owed_rekeys` keeps M only while `delivered[M] < chain` (`channel.rs:5014-5052`); `deliver_owed_rekeys_unboxed` scans every open room (`actor.rs:16114-16129`); an empty pass is legal (`rekeys.rs:143-215, 291-423`) | act 7's guard: Y absent from every selection; M in at least one selection while it owes K2; preconditions (K2 minted, M owes it) observed; no pass with both met is PRODUCT, a missing precondition APPARATUS |
| R6-2: `vox room sessions --json` has no refresh field; its `refreshing` is members' control fetching | CONFIRMED | `room_cli.rs:2730-2741` (row fields), `:2700-2718, 2750-2765` (stderr `fetching …`) | act 9(c): the pre-kill observation is the new refresh hold's `test-knob: Session refresh held for <room>` line, engaged when `vox trust drive Y` makes the refresh owed (`refresh_grant` differs, `pending_session.rs:1363-1518`); eligibility is durable in the keyring |
| Defect 1: the fold hold is process-wide, needs a pending fold, prints nothing, wakes nothing | CONFIRMED | `governance.rs:806-809, 812-814, 874-883` | TC-9 cast: ADR-040 r10 NW-14's `<path>:<room>` form and its `test-knob:` line; M's `vox service add` makes the fold pending before the narrowing; M's `vox service remove` wakes it after the release; a wait past that fact is PRODUCT |
| Defect 2: a removed computer's node stops trusting N | CONFIRMED by code | `derive_plan` `own_active` false → `grants` empty, N denied (`computer.rs:3376-3384`); `KeyRefusal::NotTrusted` (`pairwise_stream.rs:456-458`); `key_body_scan.rs:164, 330` | every secrecy act's adversary is Y, individually trusted and narrowed by `vox trust remove`; W only where its reading is not asserted |
| Defect 3: CJ-12 evicts by default | CONFIRMED (frozen ADR-043:695-702) | — | every managed removal passes `--keep-rooms` and the tag's `--confirm <frontier>` form; E-48-1 on v0.4.30 has neither flag nor eviction |
| Defect 4: the grant continuation reserves every room and poisons | CONFIRMED | `policy_save.rs:438-441`; `grant.rs:64, 73, 81, 396, 596` | Terms and TC-5 cover the grant continuation; kind `TrustGrant`; act 8's re-trust runs it |
| Defect 5: oracle lines that do not exist | CONFIRMED (no `eprintln!` in `own_keys.rs`, `rekeys.rs`, `package_save.rs`) | — | TC-8 adds six named lines; acts 5 and 7 assert on them |
| Defect 6: requirements with no act or mutant | CONFIRMED | — | acts 2b (cases 3–4), 2c (discarded refusal), 4's mutant, 10 (TC-8 lines, locked node, `members`, app), 11 (TC-4 barrier; individual path in act 8); closed-room and permanent `failed` lines stated as unproved and NW-4's first case reassigned |
| Defect 7: `vox room members` is not a tag command | CONFIRMED (`cli.rs:419` `Roster`; words at `room_cli.rs:1244-1251` are `vox room post`'s) | — | TC-8 adds `vox room members` (X048-9); act 2 asserts `vox room roster` on the tag |
| Defect 8: re-pairing a removed computer unspecified | CONFIRMED (ADR-043 verbs; state `removed`) | — | no act re-pairs: fresh W, W2, W3; act 7(vii) re-trusts Y with `vox trust add` |
| Defect 9: `vox room read --mark` does not exist | CONFIRMED (`cli.rs:1594-1597`: `--unread` only; `MarkRead` from `agent_hook.rs:3778`, `client.rs:7945`, `live.rs:3841`) | — | act 9(a) marks through the hook under RS-7's shim |
| Defect 10: 9(b)'s record producer unnamed | CONFIRMED | — | the hook-opened Session of `a_room_with_its_own_session_records_opens_after_a_restart`; the knob's `test-knob:` line |
| Defect 11: `vox trust list --json` and byte comparison | CONFIRMED (`cli.rs:1711-1726`; no byte dump) | — | act 8 asserts `vox trust list`'s lines equal before each removal; identity by construction (`trust.rs:400-415`) |
| Defect 12: fence before pass cannot qualify | CONFIRMED | `fail_managed_turn` poisons every room | order reversed: pass first; acts listed per step |
| Defect 13: two moments | CONFIRMED | `ADR-049:1244-1252` | TC-2 and the ADR-049 contract: the erasure batch; ADR-049 r8 unchanged |
| Defect 14: "six old assertions" | CONFIRMED | `nodes_of_one_daemon_proof.rs:7558` is NW-1's text | sentence replaced: no existing assertion matches TC-8's texts |
| Defect 15: pending refresh staged by nothing | CONFIRMED | as R6-2 | act 9(c) as above |
| `adr-048-sol-review-7` R7-1: `vox trust drive` dispatches `Drive`, not `Refresh`; startup's `Refresh` has empty `owed` and appends nothing; the held fold blocks Governance | CONFIRMED | `actor.rs:24462-24584`, `session_save.rs:683-715`; `preparation_save.rs:1032`; `pending_session.rs:1295-1360, 1363-1518` | act 9(c) moved to the house rule (spike NOT YET RUN); TC-7 says the early load is defense in depth |
| R7-2: a held fold leaves `require_governance_ready`/`current_governance` blocking the package | CONFIRMED | `consent_release.rs:543-545`; `channel.rs:4410`; `consent.rs:269` | the fence acts use the withdraw hold (governance current); act 2b split into online builder and offline log package (`key_package_proof.rs`'s route) |
| R7-3: a dropped attempt is rediscovered by the ordinary scan | CONFIRMED | `actor.rs:8555, 11507, 16114-16129`; `channel.rs:5014-5052` | act 2c observes the key-construction refusal and asserts the `waiting` line while the debt is unpaid; the post-release M-read is a control |
| R7-4: act 5's deadline started from the reply under test | CONFIRMED | — | TC-8 adds `own-key request from <M>`; the clock starts there, after independent preconditions (recovering line, `connected`, debt parked) |
| R7-5: skipping the mirror does not bypass the durable fence | CONFIRMED | `PendingLocks` durable; commit check; Trust stage | act 10(b) is a status journey with explicit release and a direct status mutant; ordering is 9(c)'s (HR) |
| R7-6: act 11's hold is after the batch; the durable fence, the lease and `policy_current` refuse a post; Y is not narrowed there | CONFIRMED | `post_save.rs:547-558`; `computer.rs:2839-2852, 2921-2949` | act 11 asserts `not confirmed while held` with a status mutant; the `before_commit` placement is a source-review condition with a spike (HR) |
| R7-7: "specified and unproved" is not closure | CONFIRMED (AGENTS.md) | — | act 10(d): both forms planned, exempt from the in-tree sentence, review + uncommitted spike, owner and report path named, NOT YET RUN; permanent form withdrawn if no read-only admission exists |
| R7-8: qualification claimed before dependencies exist | CONFIRMED | act 2 asserted TC-8's sentence; acts 5/7 read TC-8's lines | implementation order and qualification order separated; no build outside the proof environment carries TC-5 without TC-2/3/7 |
| Revision-8 self-finding: a held fold does not park a withdrawal | CONFIRMED | `consent.rs:336-339` (refreshing → revoke); the pass parks at the consent scan `policy_save.rs:1372-1380`; posts refused at `pending_text.rs:317` | the withdraw hold (`VOX_TEST_TRUST_WITHDRAW_HOLD_FILE`) replaces the fold hold in every fence act |
| `adr-048-sol-review-8` R8-1: the hold at `Reconcile::Withdraw` misses the manual Untrust's direct dispatch | CONFIRMED | `finish_owned_policy` → `Next::Withdraw` `trust_save.rs:964-988`; `schedule_trust_resume` `policy_save.rs:853-873`; later rooms `trust_save.rs:1242, 1268`; the other dispatches `policy_save.rs:1333`, `preparation_save.rs:1005`, `governance_save.rs:962` | the hold sits in `begin_pending_maintenance` on `Work::Consent(Withdraw)` for the named room, after the install (`trust_save.rs:965`) and before any withdrawal transaction |
| R8-2: `VOX_TEST_UNAVAILABLE_HEAD_FILE` is a path whose file names `<author> <requester>`; deletion is no rearm edge; the behind state needs authenticated evidence | CONFIRMED | `server.rs:211-224` (`source.peer` = requester); `a_node_leaves_a_room_proof.rs:195-241` (file path, reconnect); ADR-046 SY-14 | act 2 restaged on `RoomWrite(R3)`: a held Session record (act 9(b)'s knob) reserves the owner (`pending_session.rs:379-393`); release = the held commit's refusal and `release_pending_text` |
| R8-3: the online builder is selected by `history_plan`/`release_generation`, not `skdm_for_consent`; a forward-only key opens nothing during the fence | CONFIRMED | `consent_release.rs:599-675` (branches), `grant.rs` `begin_grant_marks`; `channel.rs:5305-5350` | act 2b: Z admitted untrusted, control post C before the hold, `vox trust add Z --history full` → `full_consent_release` (case 3); mutant on that branch; offline arm gated on Z `offline, last seen` |
| R8-4: the atomic's placement is not what `vox computer status` reads | CONFIRMED | `pairing.rs:1884-1897, 2060-2072` (receipt + `pending_nodes`); `host/computer.rs:176, 233, 258` (`record_application` after the result); `actor/computer.rs:802` (NodeView projection) | act 11's mutant publishes the receipt early; TC-4 gains the receipt-after-install contract; the atomic's placement stays HR |
| R8-5: the locked-row gate is the row under test | CONFIRMED | — | gate = `vox node lock` rc 0 and `vox status`'s locked line |
| R8-6: "only terminal class is storage" contradicts TC-6 | CONFIRMED | `local_history.rs:156-158` (`Error::Profile`) | inference deleted; only the status line's claim is removable; TC-6 unchanged |
| `adr-048-sol-review-9` R9-1: `vox trust remove` is retained behind a pending local save and never dispatched while the held Session is pending | CONFIRMED | `command_waits_for_save` `post_save.rs:253-276` (Untrust not excepted); `actor.rs:8075-8088`, `:7876-7878`; `post_save.rs:329-335` | TC-4's control lane (row 82a): the deferral goes for trust/policy commands as a product contract; act 2 observes the committed narrowing (`vox trust list`, status) before the release |
| R9-2: `full_consent_release` calls `rekey_skdm` first, which has its own case-3 check | CONFIRMED | `consent.rs:240-244`; `channel.rs:4782` | act 2b mutants disable case 3 at both sites (and `protected` for (ii)); Appendix B rows 2b(i), 2b(ii) trace the nested call |
| R9-3: an early `record_application()` publishes no receipt (pending node; `changes_writer` held by the transition) | CONFIRMED | `pairing.rs:832-840, 842`; `computer.rs:2664-2666, 4200-4242`; `trust_save.rs:213-225, 313-339` | act 11's mutant is the direct wrong-status classification at `Management::status` (`pairing.rs:2060-2072`); receipt-after-install kept; MAX placement stays HR |
| Fix-list item 93 (row 82, 82a): the application's pre-batch preflight waits for every room to be quiet; posts refused meanwhile | CONFIRMED | `trust_save.rs:603-617`; `actor.rs:21038-21075`; `pending_text.rs:242-275`; `policy_save.rs:282-370, 544-546`; `post_save.rs:547-558`; `computer.rs:2839-2852`; `api.rs:1792`; receipts `arm-replace/r2-B3dc-base/` | TC-4's control lane; act 12; sibling row to ADR-040 RD-10/NW-3 |
| `adr-048-sol-review-10` R10-1: "ahead of every queued authored write" plus "at most one control transaction" cannot both hold; a replenished control lane starves a post; a withdrawal is several commits | CONFIRMED | `consent.rs:812-853, 655-666, 680-697`; `pending_trust.rs:264-268` (four commits); TC-6's own inventory | TC-4 restated as row 82b: two lanes, FIFO within each, alternating one turn each; a turn is one transaction; multi-step controls keep their continuation between turns, commits never merged; bounds: control ≤ in-flight + one authored write, authored ≤ predecessors + one control transaction per write; act 12's alternation assertion and mutant (2); sibling rows ADR-040 NW-3 r13, ADR-044 RD-10 |
| ADR-043 r16 cross-ask: `RemoveRoomMember`/`ReadmitRoomMember` retained behind a pending save | CONFIRMED | `post_save.rs:368-374`; `:253-276` (not excepted); `actor.rs:8075-8088` | TC-4 lists both among the commands taken out of `command_waits_for_save` retention |
| R10-2, R10-3 (P2: act 12's staging) | deferred to task acceptance (decider's row 83; `v0431-owed-p2`) | — | not edited |
| Amendment quotes | all four FOUND at `d9a8667ba` (`adr-amendment-quotes.md`: ADR-035:115-116; ADR-038:323-326, 970-971, 1302-1303) | — | unchanged |

Experiments: none run for revisions 2 to 11 (the Mac was rebooted and its OS upgraded; `/tmp` is empty); `/tmp/sync-measure.lock` was held by another agent
(`ArmReplace`) at every check and is not this agent's. Receipts under `/tmp` and `/private/tmp`
were lost in the Mac's 2026-11-13 reboot; the rig26 figures stand as recorded in plan D's
report. E-48-1 (act 1 on the release asset) is to be run as the fleet baseline, after
`/opt/vox-evidence/v0431/hostguard.sh` prints `OK`, with receipts under
`/opt/vox-evidence/v0431/adr048/e48-1/`; it is owed before the release gate.

## The decider's answers (2026-11-13)

- **Q1 (TC-4; amends FX-28, FX-40, CT-14): per room.** "A trust change that cannot finish in one
  room blocks posting only in that room; other rooms keep working. Either way nothing is sent
  that the removed member should not read" (ledger row 35). TC-1, TC-3 and TC-4 are written to
  this answer; the inventory of Appendix A and act 3's green on the candidate are requirements
  of the per-room design, not conditions on the choice.
- Rulings that touch this lane and are applied above: row 34 (a left copy hidden until one
  member verifies; rejoin is a fresh join: TC-2), row 37 (a join admitted by one member: no
  effect here; a trust change never admits or removes a member), row 40 (stored key-package
  bodies kept by every member: TC-3 "passes"), row 49 (Session steps 2 days: no effect on case
  2), row 27 (`offline, last seen <dur> ago`: the words act 1 reads for a stopped W), row 32
  (every act stageable inside the VM: TC-9).

No question is open in this lane.

## Appendix A: every path by which this node's content or keys reach another party (v0.4.30)

Classified by effect and followed to the consumer that puts bytes on the wire or in the log:
**fenced** (TC-3 refuses it while the room is indebted, with the case), **exempt** (it passes,
with the reason), **served-stored** (bytes already committed before the narrowing; serving them
makes no new release), or **not egress**.

| Path | Producer | Consumer / where bytes leave | Class |
|---|---|---|---|
| Post, claim, announce; file announcement (`shares.rs`) | `prepare_pending_text` `pending_text.rs:299`; encrypt `:983` | `PendingText::append` commits sender ciphertext; served by sync | **fenced** (case 1) |
| Read-receipt flush | `read.rs:222-240`; encrypt `:446` | same kernel | **fenced** (case 1) |
| Read mark (local) | `read.rs:129-160` | local index | not egress |
| Legacy Session control | `legacy_session_sender.rs:131`; encrypt `legacy_session.rs:19` | same kernel (`encrypted_control`) | **fenced** (case 1) |
| Session record (activity, refresh) | `pending_session.rs:236-256`; encrypt `:1119` | the record transaction; served by `sessionstream::answer` (`sessionstream.rs:389-457`) | **fenced** (case 2); drive chain rotates in the save before encrypting (`:653-661`) |
| Sender-chain rotation on post / in a withdrawal / in recovery | `pending_text.rs:1437-1483`; `consent.rs:710-859`; `pending_recovery.rs:805-882` | a new chain persisted locally | not egress (the repair) |
| Rekey pass (current chain) | build `channel.rs:4782, 5402`; `rekeys.rs:79-423` | `finish_rekey_enqueue` `rekeys.rs:749-805` → `pairwise_out[peer]` queue → `write_pairwise_jobs` `actor.rs:2708-2747` → `write_pairwise_fenced` | **fenced** (case 3 at build; case 5 at the queue and the write); recipients filtered by `is_trusted` `rekeys.rs:328` |
| History SKDMs (past generations) | `channel.rs:5450-5540` | same queue | **fenced** (cases 3, 5) |
| Consent grant and its key package | `skdm_for_consent` `channel.rs:4405`; `consent.rs:258`; `Work::SealOutbound` `pending_package.rs:39-47` | `PendingConsent::save` appends `SignedEntryKind::KeyPackage` (`consent.rs:545-562`); served by every member (row 40) | **fenced** (case 3 at build, case 4 at the log commit) |
| Drive key release | `DriveState::release_for` `drive.rs:228-241` | `SessionSaved::Drive { releases }` → `next_owned_drive_release` → `SealOutbound` → `SessionWrite::Package` (`session_save.rs:891-1069`; `pending_session.rs:605-625`) | **fenced** (case 3 in the capsule, case 4 at the log commit) |
| Cached rekey frames | `Delivery.frame` reuse `rekeys.rs:481-515` | same queue | **fenced** (case 5: the queue is dropped at install; a reused frame meets the same per-poll check) |
| Own-original release to a recovering member | `own_original_release` `channel.rs:7724-7757` → `prepare_donor_reply` `own_keys.rs:2474-2493` → `seal_response` `:2389` | the donor's pairwise reply | **exempt**: the requester's own key, from this node's receiver; `recovery_standing` and `is_trusted` kept; W's node is untrusted |
| Own-key request and non-release replies | `own_keys.rs:2356, 2501` | pairwise | not egress |
| Consent revocation, Presence, settlement, ServiceShare, RoomAnchors, admin certificate, retention control, departure | `append_governance_with_sender` `channel.rs:6507`; callers `:3934, 4727, 6449, 8993, 9269`; `consent.rs:655-665`; ADR-049's departure | signed plaintext in the log, served by sync | **exempt**: a public control (TC-1) |
| History serving of stored entries and stored key-package bodies | `history_stream/server.rs` (`Query::{Entry,Page,KeyBody}`), `source.rs:603-669`, `sparse_history.rs:573`; gate `actor.rs:18717-18720`, `bounded_sync.rs:5124-5126` | `Frame::Chunk` to a trusted member | **served-stored**: no new encryption or key; a stored package is a release made before the narrowing, retired by the rotation |
| Stored private Session ciphertext | `sessionstream::answer` | to a member | **served-stored** |
| Incoming private records, governance fold, projections, retention, cleanup, roster, key prune, metadata, receiver cleanup | `pending_upgrade.rs:270-297`, `session_projection/pending.rs:97`, `pending_retention.rs:348`, `pending_cleanup.rs:57`, `pending_roster.rs:211`, `pending_key_prune.rs:226`, `pending_metadata.rs:22` | local | not egress |
| Inbound key delivery (select, open, install a receiver; `Work::Respond`) | `pending_package.rs:17-38, 487`; `key_body_scan.rs:164, 330` | a pairwise handshake reply | not egress (receiving); a key is taken only from a trusted member (V210-118) |
| Recovery receiver seed | `pending_recovery.rs:691-698` | local | not egress |
| Board join notice, board withdraw, anchor inventory, computer-policy exchange | `roster_save.rs:47-52`, `nat/withdraw.rs:78`, `anchor_inventory.rs`, `computer.rs:2863-2964` | board / computer transport | not egress of room content or keys |
| Pairwise open frames, relay circuits | `pairwise_stream.rs:316`, `joinstream.rs:1227`; `circuitstream.rs::serve_circuit` | empty sealed frames; forwarded inner QUIC | not egress; a relay forwards already-classified paths |
| File, folder and media bytes | `node/shares.rs` HTTP server → room-bound tunnel; `shares/media.rs` | the tunnel to an admitted member | outside the chains and outside this ADR; admission and revocation are the tunnel's (`tunnel/session.rs`), unchanged |
| Trust offers | `node/offers.rs` | pairing surface | not egress of room content |

## Appendix B: every act of TC-9, traced at v0.4.30

Columns: the **gate** the apparatus must see before the verdict (APPARATUS if absent); the
**assertion** a person could check; the **producer** at the tag that makes the asserted thing
happen; the **mutant**; **why it reaches** the assertion, naming each surviving check traced.
An act whose row could not be filled from the tag is on the house rule (marked HR).

| Act | Gate (APPARATUS if absent) | Product assertion | Producer at the tag | Mutant | Why it reaches; surviving checks traced |
|---|---|---|---|---|---|
| 1 containment | `test-knob: trust withdrawal held for R3`; W's daemon stopped; R1 left | R2 post ok ≤ 10 s; `confirmed`; no `cannot save` | the pass, `continue_managed_trust` `policy_save.rs:1300-1381`; the R2 post `pending_text.rs:299-420` | poison every room on a not-yet (`release_rooms(true)`, `:172-182`) | R2's post is refused by `poisoned` (`:311`) under the mutant; under the candidate nothing else refuses R2: governance current, settled, own history current, reservation free |
| 2 completion | `test-knob: Session record held for R3` before the narrowing (the record sits in `pending_posts`); then, before the release, `vox trust list` without Y and status naming R3 ("an earlier change to this room finishes") | status names R3; after the file goes, status drops R3 ≤ 10 s and R3 posts; the record lands under a rotated drive chain | TC-4's lane admits `vox trust remove Y` past the pending save (tag: deferred by `command_waits_for_save` `post_save.rs:253-276`, `actor.rs:8075-8088, 7876-7878`); the withdrawal's `reserve_pending_write` refused `pending_text.rs:278-296` (`RoomWrite`); the held commit refused by `for_room_in`; `release_pending_text` releases the owner | drop the `(room, TrustDebt)` resume on `RoomWrite` release | the debt stays parked; status keeps R3; R3's post refused by the fence (governance/own history current). A deferred command (no `trust list` change within 10 s) is PRODUCT under the candidate, not a gate |
| 2b(i) builder | withdraw hold; Z admitted and untrusted (reads none of N's posts; `key_package_proof.rs::set_up` admits before any `trust add`); control post C before the hold; Z's daemon up | Z does not read C while held; reads C ≤ 10 s after | `vox trust add Z --history full` (`cli.rs:259`) → `prepare_owned_consent_key` full-history branch `consent_release.rs:648-652` → `full_consent_release` `consent.rs:240-244` → nested `rekey_skdm` `channel.rs:4782` (case 3 at both) → online route `outbound.rs:43-64` | remove case 3 at `full_consent_release` **and** at `rekey_skdm` | surviving: author, settled, own history, `require_governance_ready` (`consent_release.rs:607-626`, current under the withdraw hold), not removed, no rotation pending, peer fence (Z not denied); the full plan reaches C; Z decrypts C. `release_generation`/`skdm_for_consent` not selected under `Full` |
| 2b(ii) package | as (i) but Z's daemon stopped at `trust add` (N's `vox status` shows Z `offline, last seen …`); Z started after | Z does not read C while held; reads ≤ 10 s after | offline route `consent_release.rs:690-715` → `prepare_owned_consent_key` → `full_consent_release` → `rekey_skdm` → `SealOutbound` `pending_package.rs:39-47` → `PendingConsent::save` appends `KeyPackage` `consent.rs:545-562`; served by M | remove case 3 at `full_consent_release` **and** at `rekey_skdm` **and** `protected` on the append | same surviving checks as (i) plus the append's `check_removal_generation` (unchanged); the package commits; Z opens it from M and reads C |
| 2c parked refusal | withdraw hold; M admitted, owed (stopped before, started after); `rekey pass: 1 recipient(s): <M>` | `waiting` line for M's key delivery while held; M reads ≤ 10 s after release | `deliver_owed_rekeys` `actor.rs:8555, 11507` → `select_owned_rekeys` `rekeys.rs:143-215` → `rekey_skdm_for` `channel.rs:5402` (case 3) → typed refusal parked (TC-3) | keep `rekeys.rs:372`'s `continue` | the refusal is dropped, nothing parks, no `waiting` line while held: red before any later scan (`actor.rs:16114-16129`) can deliver after release. Governance current, so selection reaches the builder |
| 3 confidentiality | withdraw hold; M→Y route; Y reads a pre-narrowing post | H absent on Y (read first), then rc 1 with TC-8's sentence; P1/P2 absent on Y | `prepare_pending_text` `pending_text.rs:299-350` + commit `:1190-1196` | remove prepare check **and** `protected` commit check | surviving: `settled` (true), `require_governance_ready` `:317` (current), removal generation `:325` (unchanged), own history `:330` (current), author, ended, reservation free; H commits under Y's chain, M serves, Y decrypts |
| 4 limit | act 3's hold | `vox service add` ok; Y lists it; H still absent | `say_share` `channel.rs:3934` → `append_governance_with_sender` `:6507` (plaintext) | fence `append_governance_with_sender` on debt | the share is refused; Y's `vox room services` lacks it: red. Nothing else refuses a share under the hold |
| 5 donor | M recovering (ADR-046 line); M shows N `connected`; `own-key request from <M>` on N; R3's debt parked | `released <M>'s own key` and M's recovery complete ≤ 10 s **from the request line** | request → `own_original_release` `channel.rs:7724-7757` → `prepare_donor_reply` `own_keys.rs:2474-2493` → `seal_response` `:2389`; gates `:308-312, 1363, 1469, 1689, 1982, 2216` | fence `own_original_release` on the donor's debt | the request line (logged before any reply) starts the clock independently; no release line, recovery incomplete: PRODUCT. Trust and membership gates pass (M trusted) |
| 6 restart | withdraw hold across the restart; `trust debt loaded` for R3 | R3 listed, no `[failed]`, readable; post refused with TC-8's sentence; after release ok | preparation trust stage `preparation_save.rs:958-1012` parks; `advance_room_preparation` `actor.rs:20743-20763` | record `reopen_failures` for the not-yet as today | R3 shows `[failed: …]`: red on the list. Governance stage completes (no fold hold), so preparation reaches Trust |
| 7 late key | `.engaged` names g; M reads Q1; Y lacks Q1; K2 minted | Y never reads Q1; `key write refused … (<Y>, incarnation g)` | `rotate_for_withdrawal` `consent.rs:710-859`; the held job `pairwise_stream.rs:379-396`; per-poll fence `:401-447` | remove the denied check in the per-poll closure | the held K1 frame's poll completes after the batch; Y's receiver is chain-keyed and keeps K1 beside K2 (`channel.rs:7279-7425`); Y decrypts Q1 |
| 7(vi) | as 7; X2 removed after Y | Y never reads Q1 | `Epochs.denied` cumulative (TC-3 case 5) | replace `denied` by the last batch's set | Y's entry erased by X2's batch; the held job passes the set half; same incarnation (no re-grant): writes; Y decrypts Q1 |
| 7(vii) | `.engaged` names g; P4 readable on Y **before** the release | old g job refused; Y never reads Q1 | re-grant bumps `peer_incarnation` (TC-3 case 5); `reserve_pairwise` re-creates the writer `actor.rs:19163-19188` | skip the incarnation compare | Y trusted again (not denied), stale g job writes K1: Y decrypts Q1; P4 read first makes the order causal |
| 7 selection guard | K2 minted (no R3 debt); M owes K2 | Y absent from every `rekey pass` line; M in ≥ 1 before it reads the K2 post | `owed_rekeys` → `consented_member_page` `channel.rs:4851-4886, 5014-5052`; `deliver_owed_rekeys_unboxed` `actor.rs:16114-16129` | `consented_member_page` ignores `can_read` | Y (revoked, ledgers cleared `consent.rs:638-705`) re-enters the selected set; the line names Y. Y-read of P3 stays green (native recheck `rekeys.rs:570-580`, peer fence): second assertion only |
| 8 ABA | `test-knob: trust Delete held for R3`; Y re-consented (reads a fresh post); withdraw hold for the second removal | status keeps R3's debt after D1; post refused; Y never reads a post after the second removal | `PendingTrust::run` `pending_trust.rs:264-268` with `clear_stamped` (TC-6); `trust_save/grant.rs:136-139` forgets S1 | `clear_stamped` ignores the stamp | D1 clears S2's entry; mirror empties; the fence drops while the second withdrawal is held; post commits under K1 (Y's chain); Y decrypts |
| 9(a) receipt | withdraw hold; Q by M unread by N; Y reads Q | no `read_by` N on Q at Y while held; then yes at M | flush `read.rs:222-240, 446`; `MarkRead` from the hook `agent_hook.rs:3778` under RS-7's shim | remove the flush's prepare check **and** `protected` | surviving: `settled`, own history, `require_governance_display` (current), author; selector skips N's own posts (`:177-179, 335-343`), Q is M's: the `ReadRecord` commits under Y's chain; Y's `read_by` shows N |
| 9(b) Session record | `test-knob: Session record held for R3` before the batch; Y with drive reads an earlier record | record refused/parked; Y never reads it | hook-opened Session (`a_room_with_its_own_session_records_opens_after_a_restart`); `prepare_pending_session` `pending_session.rs:236-256`; commit `:1096` | skip the record transaction's `for_room_in` | capsule prepared before the batch: `drive.lost` ran against old holders (`:653-666`), chain unchanged; commit lands under Y's drive chain; Y decrypts |
| 9(c) open-time order | — | — | **HR**: no pre-Trust stage appends for a current-layout room (`preparation_save.rs:1032, 1038-1054`; `pending_session.rs:1295-1360`; `actor.rs:24462-24584`) | — | spike NOT YET RUN (V431-048-12; `spike-tc7/`) |
| 10(a) words | act 3's hold | status sentence for R3 only; log line once; post sentence + rc 1; FFI sentence | TC-8; `host/computer.rs:237-266`; `client.rs:4675-4709` | omit the indebted room from `vox computer status` | direct status mutant; nothing else prints the room |
| 10(b) locked | `vox node lock` rc 0 **and** `vox status` shows the node locked; later `trust debt loaded` after unlock | locked row in `vox computer status`; sentence after unlock; gone ≤ 10 s after release | ADR-043's locked row; TC-7 load at unlock-open | omit the locked row (`confirmed` for a locked node) | direct status mutant; the gate is the lock itself, not the row; no ordering or publication claim |
| 10(c) members | act 2 done | `vox room members` lists Y `not trusted` | TC-8 adds the command over `Request::Roster` `room_cli.rs:2639` + keyring | list only trusted members | direct output mutant |
| 10(d) closed / permanent | — | — | **HR**: no CLI closes a room; no current-product permanent refusal staging | — | spikes NOT YET RUN (V431-048-09; `spike-closed/`, `spike-permanent/`); only the status line's claim is removable, TC-6's typed permanent refusals (`Error::Profile`, never storage) stand |
| 11 barrier | `test-knob: trust install held` | `applying`, not `confirmed`, while held; an R2 post retained and acknowledged after release, never refused; after release `confirmed`, R2 ok | `record_application()` after the actor's result `host/computer.rs:176, 233, 258`; `confirmed` from the receipt + empty `pending_nodes` `pairing.rs:1884-1897, 2060-2072`; the retained transition `computer.rs:2664-2666, 4200-4242`, `trust_save.rs:213-225` | at `Management::status`'s output boundary (`pairing.rs:2060-2072`), classify the applying node `confirmed`; receipt, pending set and transition untouched | direct status mutant: red while held. An early `record_application()` is masked (`pairing.rs:832-840` no receipt with a pending node; `Computer::change` `:842` needs the writer the application holds); the atomic's placement is **HR** (spike NOT YET RUN, V431-048-06, `spike-tc4/`) |
| 12 busy member through a roster change | ≥ 10 of M's posts landed on N in the 60 s window (else quiet: APPARATUS); `vox node create` on W returned 0; `test-knob: control turn R3 <stage>` lines present and the loops show no gap (else APPARATUS) | every N post rc 0 ≤ 5 s and read back on N and M; none refused; `confirmed` ≤ 10 s; the new node reads R3 ≤ 60 s; at least one loop post commits between two consecutive control turns; no post's acknowledgment exceeds its FIFO predecessors' plus one control transaction | the roster bump `computer.rs:1655-1672`; the keyring batch with no room preflight (TC-4); the lanes' alternation (TC-4, row 82b); R3's control turns: `MarkDecisions` (`pending_trust.rs:211-281`), the consent key turn, the package turn (`consent.rs:545-562`) | (1) restore the pre-batch room preflight; (2) control runs back to back while a post is queued | (1) some room always has a pending write: the batch never commits, `policy_current` stays false, N's posts refused `Fault::ComputerPolicy` (`post_save.rs:547-558`, `computer.rs:2839-2852`): red on the 5 s acknowledgment; (2) the queued post lands only after the last control turn: red on its one-control-transaction bound. v0.4.30 PRODUCT red recorded in `arm-replace/r2-B3dc-base/`, `r5a-B3dc-arm` |

## Links

- ADR-006 (S-14, S-15), ADR-007 (G-19), ADR-016 (NR-48), ADR-020 (V210-118), ADR-029 (SC-2b),
  ADR-034 (§4), ADR-035 (CT-14), ADR-037 (R5), ADR-038 (FX-28, FX-40, FX-45, FX-49, FX-62).
- v0.4.31 lanes: ADR-040 (NW-1–NW-4, NW-12, NW-14), ADR-042 (TR-11, TR-12, TR-23), ADR-043,
  ADR-045 (J6), ADR-046 (SY-11), ADR-047 (SO-11), ADR-049.
- Reviews: `adr-040-sol-review` (findings 1, 2, 8, 16), `adr-040-sol-review-2` (F1–F4, the
  trust-fence inventory conclusion, Q1), `adr-048-sol-review` (F1–F6), `adr-048-sol-review-2`
  (N1–N4), `adr-048-sol-review-3` (R1–R5), `adr-048-sol-review-4` (S1–S3), `adr-048-sol-review-5` (F1–F3), `adr-048-sol-review-6` (R6-1, R6-2), `adr-048-sol-review-7` (R7-1–R7-8), `adr-048-sol-review-8` (R8-1–R8-6), `adr-048-sol-review-9` (R9-1–R9-3), `adr-048-sol-review-10` (R10-1); `adr-048-item93`; `adr-048-pending-r11`; `v0431-tasks-ADR-048` (ADR defects 1–15); `adr-cross-asks`
  (X048-7, X048-10, X049-5); `adr-amendment-quotes`. Revision note: `adr-048-revision`.
  Cross-ADR ledger rows 27, 32, 34, 35, 37, 40, 82, 82a, 82b, 83,
  49, 58, 61.
- Receipts: plan D's rig26 report (`plan-D.md`; its raw logs under `/tmp/plan-PlanD/`
  were lost in the 2026-11-13 reboot); the operator's IO log
  `/private/tmp/vox-rca/io/daemon-202624Z.log:3706-3712, 3751, 3830` (likewise lost; figures as
  recorded in `rca-RcaFrozen`); future receipts under `/opt/vox-evidence/v0431/adr048/`.
- External: RFC 9420 (MLS) §12.1.3 Remove and §8 epoch secrets ·
  Signal "Private Group Messaging" sender keys ·
  Matrix spec, Megolm session rotation on membership change ·
  `vox` v0.4.30 `pending_lock.rs:1-17`.
- Release milestone v0.4.31.
