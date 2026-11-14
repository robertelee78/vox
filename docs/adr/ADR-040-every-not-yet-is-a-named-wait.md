# ADR-040: Every Not-Yet Is a Named Wait

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-13). Reviewed by GPT-6.1-Sol in nine passes
  (`adr-040-sol-review` … `adr-040-sol-review-9`, the ninth "Verdict: pass"); the decider
  authorized acceptance after review (ledger row 33). Revision 10 (2026-11-13) is a correction
  batch on the accepted text: the fifteen "ADR defects" of the task cut
  (`v0431-tasks-ADR-040`, "Uncertain") and the open rows of `adr-cross-asks`, each retraced on
  `v0.4.30`; it changes no requirement. Revision 11 (2026-11-13) answers the re-check of
  revision 10 (`adr-040-sol-review-recheck-1`, eight findings in those corrections), adds
  Appendix B (every act, what it reads, where it exists at the tag, its mutant), and brings
  every flush mention to ADR-044 RD-7 revision 14's terms (ledger row 74). Revision 12
  (2026-11-13) answers the second re-check (`adr-040-sol-review-recheck-2`, seven findings) and
  applies the decider's direction of ledger row 82: no obligation of this ADR waits for a room
  to fall quiet. Revision 13 (2026-11-13) states that rule as ledger row 82b (re-check 3,
  R12-F1 and R12-F2, the two P1s): two lanes per room, control and authored, alternating one
  turn each, a turn one native transaction; a rekey holds a transferable grant for one
  transaction at a time. Re-check 3's P2s (R12-F3–F6) are owed at build time (ledger row 83,
  `v0431-owed-p2`) and not edited here. **Revision 13 is the accepted text**: the fourth
  re-check (`adr-040-sol-review-recheck-4`, "Verdict: pass") found no P1 under ledger row 83, and
  its P2s are owed to the owning tasks' acceptance; Main then scoped NW-3's control bound and
  the ADR-044 bullet to the head of the lane (ledger row 82c, a wording precision that changes no
  design decision). Nothing in this ADR is built: every requirement is
  written as what the code is to do. Revision 3 (2026-11-12) split revision 2 into four ADRs, as Main
  decided after the second independent review (`adr-040-sol-review-2`): this ADR keeps named
  waits and retry ownership; ADR-048 takes trust-change containment and the trust-debt fence
  (revision 2's NW-5, Appendix B, Q1); ADR-049 takes leaving and ending rooms (NW-6, NW-7,
  NW-15, Q6); ADR-050 takes the agent turn journal (NW-10, Q3). Revision 4 (2026-11-13) answers
  the four findings of the third review (`adr-040-sol-review-3`: a stale authority token parked
  on a policy already current; unbounded queued stage-exact work; a false retention promise on
  reply overflow; non-OMP hook registration writes with no owner) and records the decider's
  answer to Q4 (ledger row 41). Revision 5 (2026-11-13) answered the fourth review
  (`adr-040-sol-review-4`) with a per-session state file; revision 6 (2026-11-13), after the
  fifth review (`adr-040-sol-review-5`) found five more interleavings in that file, deletes it:
  the daemon is the one writer of a session's registration and state, and a hook says its
  state in the request it already sends (NW-9, "Why one writer"). Revision 7 (2026-11-13)
  answers the sixth review (`adr-040-sol-review-6`): a state is admitted before every other
  registration gate, its order is the writer's arrival order with no clock compared, and two
  proof inverses are restaged. Revision 8 (2026-11-13) answers the seventh review
  (`adr-040-sol-review-7`: three proof recipes), carries every verified ask of the sibling
  ADRs (`adr-cross-asks`: X048-2, X048-3, X049-1, X049-2, X043-15, X047-11, X041-8, X040-11)
  and quotes each amended sentence whole. Revision 9 (2026-11-13) answers the eighth review
  (`adr-040-sol-review-8`): act 4(f) establishes `busy` before its mid-retirement `Stop`, and
  `pending_trust.rs:203` is described as it is at the tag. Requirement ids are stable: an
  id that moved is listed under "Moved requirements" and is not reused. This ADR is the design
  record
  for fix-list items 28, 29, 31 and 32 and for defects D-33 and D-34, and it answers every
  finding of the nine reviews and the re-check in its lane (see "Review record"). No question is open: see "The
  decider's answers".
- **Date**: 2026-11-12
- **Deciders**: Robert E. Lee
- **Tags**: daemon, refusals, retries, startup, sessions, key packages, status
- **Related**: ADR-018, ADR-029, ADR-034, ADR-037, ADR-038; in this release ADR-041, ADR-042,
  ADR-043, ADR-044, ADR-045, ADR-046, ADR-047, ADR-048, ADR-049, ADR-050
- **Inputs**: the operator's daemon logs of 2026-11-11/12 (IO, the Mac, beast) and of
  2026-11-13 (robert-work); the root-cause reports RcaTrust (T1, T2), RcaPreparing (P2),
  RcaChurn, RcaSchedStall (items 85/87, which ask this ADR for one prerequisite); the group-D
  plan and its reproductions on the published `vox 0.4.30` release binary; the two independent
  reviews (sixteen and eighteen findings), every finding in this lane checked against the
  `v0.4.30` tree for this revision.

## Context

### What the operator saw

On 2026-11-11 and 2026-11-12 the operator ran v0.4.30 on four machines with up to seven agent
sessions each. These are the failures this ADR covers, as he saw them:

1. **Every restart refused the agents for up to 23 s.** The Mac, at every restart where node
   omp-work became Ready first: `attention selection remains pending: attention waits for current
   computer trust`, one `could not open this session's Session in its room: attention waits for
   current computer trust` per registered OMP session, and `Vox: context preparation unavailable`
   in every hook in the window. The window was 8–23 s on the Mac. (Item 28.)
2. **"session registration is busy".** The Mac and beast, 3–25 s after every restart:
   `vox: session registration was not changed: session registration is busy`, 2–18 times. The
   session's name, idle state or room binding stayed stale until its next event. (Item 29.)
3. **A key was never delivered.** The Mac, 15:25:37Z: `room o6z3 … store save room: malformed
   at-rest artifact: key-package attempt unacknowledged [count=932]`, 24 refused saves and a
   whole-store rewrite 58 s later; and after joins and restarts `could not read its saved key
   deliveries: node: room governance is refreshing` with nothing after it: a member's key never
   opened until some unrelated event touched the room. (Item 31, D-33.)
4. **Every trust change dropped work.** IO 19:40:07Z and 19:50:51Z, the Mac 19:50:52Z:
   `could not publish its saved read marks: computer policy changed while its prior application
   was pending; the marks remain saved`, `could not read its saved key deliveries: computer policy
   changed …`, `a join did not complete — room o6z3 recovery could not complete its retained save:
   computer policy changed …`, at every policy revision (pairing, cancel, creating a node on a
   sibling). (Item 32.)

Four more failures of the same days are in the sibling ADRs: a left room that broke the room he
works in and never went away (items 26, 27: ADR-048, ADR-049), a conversation that died for good
after a restart (item 30: ADR-050), and an ended room that stayed and a room that could not be
left (items 64, 86: ADR-049).

### What they have in common

Every layer of the daemon refuses correctly: "busy", "refreshing", "superseded", "waiting", "lock
held". Each of those refusals means "not yet": the work can be done once something else finishes.
In v0.4.30 nothing owns finishing it. The caller of a "not yet" drops the work, logs it as a
fault, or turns it into a permanent state: a dropped Session opening, a stale registration, a key
that never opens, a read mark that is never published. The consolidated analysis says the same
for the whole product ("the design guarantees what must never happen and nowhere guarantees that
anything eventually does", §2 A).

v0.4.30 already has five private versions of "park this work until X happens"
(`key_package_rooms`/`key_package_unopened`/`key_package_governance_wait` in `actor.rs`,
`governance_work.wake_room`/`again`, `preparation_save::wait_on`, `own_key_policy_waiting`,
`parked_construction`), each with its own wake and its own gaps. ADR-038 FX-40, FX-45, FX-49 and
FX-61b each closed one gap for one kind of work. This ADR makes it one rule and one mechanism,
and keeps every existing owner whose predicate is already exact where it is (NW-1's table of
preserved owners).

### Root causes at v0.4.30

Citations are to the tree at tag `v0.4.30` (commit `8d71ab337`). Status words: **KNOWN** =
reproduced on the release binary, or read from the operator's evidence, with where;
**INFERRED** = fits the evidence, not reproduced; **UNKNOWN** = not explained, with the
experiment that settles it (see "Experiments"). A run marked *instrumented* was made with a
binary that adds log lines only; it attributes a cause and is never the sole evidence that the
release binary behaves so.

| Item | Root cause | Status and evidence |
|---|---|---|
| 28 | `begin_identity_startup` takes the daemon-wide exclusive publication transition (`startup_save.rs:422-428`; `computer.rs:2812-2819` takes the `publications` writer) before Argon2, store open and policy settling, and releases it only after "Ready" (`startup_save.rs:629`). A second node's startup becomes a *waiting* writer, and `Gate::try_read` refuses every reader while a writer merely waits (`publication_gate.rs:49-58`). `publish_with_current_authority` (`computer.rs:2951-2960`) is `try_read` plus `policy_current`, and attention reports either failure as "attention waits for current computer trust" (`actor.rs:23351`). Callers: the attention loop drops the room's selection (`node_tasks.rs:169-173`); `open_registered` retries only two other refusals (`host.rs:2176-2189`) and injects a stale notice (`:2208-2212`); the hook's `--omp-prepare` fails and the extension retries. | KNOWN. RcaTrust `run-s1` (release binary): 9 opening failures per restart; the Mac's log (8–23 s). Why the Mac's window is seconds and the scratch window 0.3 s is UNKNOWN (E-28). |
| 29 | `registration_lock_typed` (`wake.rs:769-790`) calls `try_lock()` once and maps `WouldBlock` to `Busy`; `registration_write` (`wake.rs:807-815`) prints the line and returns `None`; its callers `store_name` (`wake.rs:930`), `store_room` (`:944`), `forget` (`:1352`), `record_omp_state` (`:1396`) return without writing. The hook path (`store_checked`, `wake.rs:865`) maps `Busy` to `LockBusy` (`registration_store_refusal`, `host.rs:1804-1817`) and the extension retries. After a restart N sessions re-register and N bridges send their first state at once. Why: the lock stops a stale whole-record rewrite from restoring a removed room (`wake.rs:766-768`); `try_lock` was chosen so no caller blocks. | KNOWN. RcaTrust `run-s1` (release, 11–18 lines per restart). |
| 31 | `Queue::next` sets `self.attempt` in memory only (`key_package_queue.rs:798-806`) and refuses the next selection with `MalformedAtRest("key-package attempt unacknowledged")` while it is set (`:644-646`). The selection stage runs with `poison = true` (`pending_package.rs:709`) and any error there marks the room unable to save (`:674-677`). The attempt is cleared on few paths; a policy supersession, an at-rest lock, an inbound rejection or the bare refreshing text (D-33) between selection and acknowledgement leaves it set. A selection refused "governance is refreshing" is not re-armed: `begin_owned_package_turn` removes the room (`package_save.rs:239`) and the `After::Logged` arm re-arms only "busy" at selection and "refreshing" at open/install (`package_save.rs:320-346`). | KNOWN by code; the Mac 15:25:37Z (`[count=932]`, the 58 s rewrite). Which refusal tore the chain on the Mac is UNKNOWN (E-31). |
| 32 | Every native save that holds a publication checks the policy fence before preparing and before committing (`maintenance_save.rs:821-823, 883-885`) and returns `ComputerPolicySuperseded` when the node's applied revision differs (`policy_current`, `computer.rs:2921`). The fence is right. What the callers do with it is not: read marks log "could not publish its saved read marks" (`read_save.rs:227-229`; `expected_refusal`, `:16-32`, does not list it); settlement sends `JoinFailed` "a join did not complete" (`recovery_save.rs:282-292`); key packages log and are not re-armed (`package_save.rs:324-358`); `saved_history_query` answers "computer policy is refreshing; retry" (`actor.rs:26100`). `finish_managed_policy` (`policy_save.rs:1548-1555`) resumes governance work only. | KNOWN. The operator's lines above (release binary, three machines); rig26 (`/tmp/plan-PlanD/keep/run26-rig.log`). |
| D-33 | `read_resource.rs:95,101` return `Error::Profile("room governance is refreshing")` without the suffix `; try again when it is ready` that `view::REFRESHING` carries (`governance/view.rs:18-19`). Every classifier matches the suffixed constant exactly (`channel/governance.rs:777-779` → the `poison()` exemption, `fault_of`, `read_save::expected_refusal`, `sessions::opening_refreshing`, `sessions.rs:166-176`). So the bare text is never retried and poisons where the stage poisons (`pending_package.rs:674-677`). | KNOWN by code. Operator: the Mac 15:25:37Z `room o6z3 network authorization unavailable: node: room governance is refreshing [count=27]` 1.5 s before item 31's poison. |
| D-34 | `poison()` (`channel.rs:5211-5237`) is the one remedy for four different things: a released reservation (`release_pending_text(poison = true)`), a key-package selection error, a trust-stage error, and a real store I/O latch. `recover_storage` (`recovery.rs:15`) treats every marked room as a latched store and rewrites it. Direct assignments of `poisoned = true` outside `poison()` exist too (`pending_text.rs:741-743` at read completion, `:755-757` at release). | KNOWN. rig26: 12 refused recoveries in 12 s (`run26-rig.log`, "a join did not complete … [count=12]"), none succeeding until restart; item 31's 58 s rewrite for an in-memory counter. |
| 85/87 (one prerequisite) | A sync flow whose local cleanup save failed stays in `retirement_failed` and waits on a future that completes only on a node lock (`bounded_sync.rs:1854-1860`; `runtime.rs:1814-1848`); store recovery does not wake it; at 11 such flows no round starts (`RETAINED_FLOW_LIMIT = 12`, `bounded_sync.rs:580`, `:1789-1810`, `:4749-4757`). The cap and its retry are ADR-046 SY-24's; the wait it needs a name for is this ADR's `StoreRecovery(room)` (NW-1). | KNOWN, reproduced on the release asset (`rca-RcaSchedStall`, `/tmp/RcaSchedStall/receipts/`). |

Rows 26, 27, D-35 (ADR-048), 30 (ADR-050), 64 and 86 (ADR-049) are in those ADRs.

### Citations checked

The plan's and revision 2's file:line citations in this lane were read at `v0.4.30`. They hold,
except these, corrected above and in Appendix A:

- The attention refusal string is at `actor.rs:23351`, not `23349-23350`.
- `pending_text.rs:289` begins the busy error; the literal text is line 290.
- `maintenance_save.rs:793-804` says "room publication is busy" when `try_acquire_publication`
  could not take the **Computer** publication gate (`computer.rs:2845-2847`), not when the
  room's pending write is held. Appendix A row 3 is corrected (revision 2).
- The refusal inventory's row 8 said `attention.rs:344-347` poisons the bare refreshing text;
  it does not (that site poisons only non-`Profile` errors). The bare text poisons at the
  key-package selection stage (`pending_package.rs:674-677`) (revision 2).
- "computer trust is pending application on this node" is produced at `actor.rs:24500-24502`,
  not `:24515` (second review's spot check; Appendix A row 22 corrected).
- Revision 2 said `PublicationGate` is released by "the gate's writer drop". The gate also
  opens reader admission when its last waiting writer leaves without ever writing
  (`publication_gate.rs:129-133` on deadline, `:175-180` on cancellation), and both call
  `Gate::wake` (`:40-43`) with no `Writer` (second review, F13). NW-3's release rule is restated
  so that it cannot miss a transition.
- Revision 2 said `store_name`/`store_room` "enqueue and return". Their results drive the next
  step of their callers (`host.rs:2296-2323`, `:3730-3743`) (second review, F10). NW-9 is
  restated.

## Terms

- **Not-yet**: a refusal that means "later": the work is valid and can be done once something
  else finishes. Examples: a room's pending write is held, the room's governance (its member and
  permission entries) is still being applied, computer trust is being applied on this node,
  another writer holds or waits for the computer's publication gate, the room's store is
  recovering, a file lock is held. A refusal that means "never" (malformed input, an
  authorization denial, a removed room) is not a not-yet.
- **Prerequisite**: the one named condition that admits a not-yet's work, with a readiness
  predicate the daemon can evaluate and a generation counter that is bumped whenever the
  predicate becomes true. The prerequisites are listed in NW-1.
- **Obligation**: a piece of work that received a not-yet, together with what is needed to run it
  again: the room, the kind of work and its exact stage, the replies waiting on it, the
  prerequisite and the generation at which the prerequisite was observed.
- **Parked**: an obligation held by the node until its prerequisite is released. A parked
  obligation holds no store, signer, publication lease, room lock or worker (ADR-038 FX-40, FX-45).
  It holds no secret, with the one exception FX-61a already grants: an unadmitted room
  constructor's retained work owns its sealed room key or passphrase until the constructor is
  admitted or dropped (`construction_save.rs:64-70, 617-626`).
- **Owned obligation**: work the daemon must finish whatever happens to whoever asked for it
  (a read-mark flush, a key selection, a settlement save). **Requested obligation**: work that
  exists only while a requester waits for its answer (a hook's attention request, a registered
  Session's opening); when its last requester is gone there is nothing left to do.
- **Owner**: the party that produced the obligation and must finish it. Inside the daemon, the
  node; in the hook, the hook's turn journal (ADR-050); in the OMP extension, the extension.
- **Preserved owner**: existing code that already waits on an exact predicate of its own and is
  kept as it is; NW-1 lists them. The registry does not replace them.
- **Marked unable to save** ("poisoned" in the code): the room state `poisoned = true` with a
  `save_error`, shown as "<room> cannot save: …" and handled by store recovery (ADR-034 §4,
  ADR-047 SO-11, SO-12).
- **Revision move**: the computer-trust policy revision changing (pairing, removal, cancel, a node
  created or removed on any computer of the group).

## Requirements

Requirements changed in revision 3 are marked **(changed: …)**; their ids are kept. NW-13 is
withdrawn and says why. The moved ids are listed after NW-14.

### 1. The rule

- **NW-1. A not-yet is typed and names its prerequisite.** **(changed: second review F13,
  registry section; ADR-046 SY-24; ADR-044 ledger row 9.)**
  Every producer of a not-yet MUST return one error kind, `Error::NotYet { prerequisite, seen }`,
  where `seen` is the prerequisite's generation read **before** the condition was observed, and
  no caller MAY classify a not-yet by its text. The prerequisites are a closed set. A
  prerequisite is added to it only by an ADR, with all four columns filled:

  | Prerequisite | Ready when (predicate) | Released when the predicate becomes true (the state change that bumps the generation; v0.4.30 site) | Said to a person as "… waits until" |
  |---|---|---|---|
  | `RoomWrite(room)` | this obligation's turn in its room **lane** has come (ledger row 82b; NW-3 "Two lanes, one turn each"): the room's pending write is free of the transaction in flight and this obligation is at the head of its lane while the other lane has no ready work, or it is the other lane's turn to be followed by this one (the tag's room-quiet tests, `post_pending`/`publication_busy` at `pending_text.rs:283-291`, `sparse_history.rs:1426-1434`, `rekeys.rs:87-91`, are replaced by the lanes) | the transaction in flight commits and installs and the owner is handed to the next turn (`release_pending_text`); the publication completes (`note_publication_complete`, `history_publication_changed`) | control: "the change now being written to this room finishes"; authored: "the <k> messages ahead of it, and at most one trust change each, are written" |
  | `GovernanceFold(room)` | the room's governance projection is current (`require_governance_ready`) | the fold marks the projection current (today's `governance_work.wake_room`) | "this room's member and permission entries are applied" |
  | `Projection(room)` | the room's Session, legacy-Session, floor and private-control projections are not refreshing (`sessions::opening_refreshing`'s five texts) | each projection marks itself current | "this room's Session index is rebuilt" |
  | `ComputerPolicy` | the node's applied revision is the policy revision, its application is settled and authority is not blocked (`policy_current`, `computer.rs:2921-2924`) | `finish_managed_policy` stores the applied revision (`policy_save.rs:1542-1547`); `authority_blocked` clears | "computer trust is applied on this node" |
  | `PublicationGate` | the computer's publication gate admits a reader (`Gate::try_read`: no writer writing or waiting) | inside the gate, under its lock, before `wake`: the `Writer` drops (`publication_gate.rs:168-173`); the waiting count reaches zero without a write (`:129-133` deadline, `:175-180` cancellation) | "node <name> finishes starting" when the writer is a startup; otherwise "a change to this computer's trust is written" |
  | `OwnHistory(room)` | the room's own history is current (`require_own_history_current`) | own recovery completes authoritatively and clears `own_behind` (ADR-046; not a refresh that leaves it set) | "this room's own history is recovered" |
  | `Settled(room)` **(new)** | a sparse-joined room's first sync has settled (`ChannelState.settled`, `is_settled()`; `channel.rs:6474-6475` refuses `RoomNotSynced` until then) | every path that sets `settled = true`: the direct settlement append (`channel.rs:6561-6562`), native recovery installation (`pending_recovery.rs:1027, 1072-1073`), `ChannelState::settle`; the landing task lists each | "this room's first sync settles" |
  | `StoreRecovery(room)` **(new)** | the room's store accepts writes: not marked unable to save, ADR-047 SO-11's floor held, SO-12's reopen done when one was needed | exactly ADR-047's `StoreRecovered(room)` event, instance-qualified, raised in the actor after the room's re-save on both floor recovery without a reopen and recovery through a reopen (ADR-034 SR-3's `recovered; it can save again` is said then); an event for a replaced room instance releases nothing (ADR-044 RD-7 and ADR-046 SY-24 consume the same event) | "room <name> can save again" |
  | `TrustDebt(room)` | owned by ADR-048 (the room owes no trust withdrawal) | ADR-048 | ADR-048's words |
  | `PeerReachable(peer)` | owned by ADR-049 LE-3: a connection to the member exists (`net.manager().existing(peer)` is `Some`) | the connection-established event ADR-046 names, and the member's inbound session for the room | "member <name> is reached" |
  | `PolicySave` | owned by ADR-049 LE-4: no trust save of the node is in flight (`pending_policy.is_none()`) | the save's completion, where `pending_policy` is taken back (`actor.rs:19809`, `policy_save.rs:248, 587`) | "this node's trust save finishes" |
  | `SessionCleanup(room)` | owned by ADR-049 LE-4: no Session retirement of the room is pending and the retirement sink has a permit (`leave_save.rs:734-766`) | the retirement's completion and the permit's return | "this room's Session cleanup finishes" |

  The `publication_gate` `Writer` and waiting writer record their purpose (`Startup(node)` or
  `Policy`) so the words above are true. `OwnHistoryBehind` stays a refusal to a command
  (ADR-037 R5: the person is told); a daemon-owned obligation that receives it parks on
  `OwnHistory(room)`. `ComputerPolicySuperseded` (`maintenance_save.rs:821,883`,
  `computer.rs:2849`) is `NotYet(ComputerPolicy)`: the work runs again under the policy that is
  current at release (NW-3).

  *What is not a prerequisite.* A file lock: NW-9 waits for it inside the caller. An at-rest
  lock: the lock ends the attempt and unlock derives the work again (unchanged). A permanent
  condition: a producer that cannot name a prerequisite whose release will admit the work MUST
  refuse permanently, not with `NotYet`.

  *Preserved owners.* These waits keep their own owner and are **not** folded into NW-3's
  registry; each already re-checks an exact predicate of its own, and no item here touches it:

  | Wait | Owner kept (v0.4.30) | Why it is not a registry prerequisite |
  |---|---|---|
  | the private-drive waits `ControlEntry`, `ControlFrontier`, `LocalPreparation`, `Support`, `SupportPublication`, `Publication`, `Projection` | `private_save/continuation.rs:806-846` | re-checked under the room lock by its own dispatcher (ADR-038 FX-45) |
  | `Error::HistoryCapacity(BytePressure)` (`error.rs:20-22`) | the pressure's own release future (`key_body_scan.rs:440-453`: `pressure.released().await`) | the wait is on an exact byte pool, not on a room, a policy or a gate; ADR-044 and ADR-046 own the pool |
  | `Error::OwnKeyWriterDrainRequired` (`error.rs:527-529`) | the policy drain (`policy_save.rs:1148-1152`), owned by ADR-048's pass | a physical own-history-response retirement, not "own history current" |
  | a received-entry or Drive admission waiting for the room's pending write | ADR-044 RD-10's authored lane (ledger rows 9, 82b) | the wait is bounded by the writes ahead of it in its lane plus at most one control transaction per write; RD-10 is the owner of both lanes; every `RoomWrite(room)` park of this ADR is a place in one of them (NW-3, "Two lanes, one turn each") |
  | `receiver_releases::Remember::Busy` (`receiver_releases.rs:269-275`) | the durable `retry_owed` flag in the receiver header, re-derived by the key-prune sweep | a capacity bound with a durable mark; nothing to park in memory |
  | the 30 s room-lock wait of a history preparation worker (`history_demand.rs:1552-1558`, "history room is busy") | the worker's own bounded wait; after the bound the peer's request fails to the peer, which asks again on its schedule (ADR-046) | the waiter is a worker holding the request, not the actor |
  | a departure probe refused or unanswered on a live connection (ADR-049 LE-3) | the port's own bounded retry (`ports.rs:262-284`: `Busy` 200 ms → 1 s, `NoProgress` 1 s → 30 s, `Unreachable` 200 ms → 8 s) | the predicate `PeerReachable` is already true; the wait is the peer's answer, which the port already owns with a bound |

  - *Why*: D-33 (two copies of the refreshing text drifted and one was never retried); items 28,
    31, 32 (each caller recognised a different subset of strings); first-review finding 10 (the
    five-edge set of revision 1 could not represent the own-history or projection waits);
    finding 11 (a legacy "room" text produced by the Computer gate must not park on the room);
    the second review's registry section (the eight of revision 2 were not a closed
    classification of Appendix A: capacity, the own-key drain and the unclassified strings had
    no row; they now have one each, as a prerequisite, a preserved owner or a permanent
    refusal); ADR-046 SY-24 (the reproduced stall needs a wait named `StoreRecovery(room)`).
  - *Changes*: one new `error.rs` variant and `Prerequisite` enum; a typed carriage to every
    consumer: `Fault::NotYet { prerequisite, said, retained }` in the actor reply (no `seen`: it
    never leaves the actor, NW-3). **How it reaches the four clients, once.** At the tag a
    `Fault` is `Copy` with a fixed `explain() -> &'static str` (`api.rs:1527-1530, 1778`),
    crosses the control socket as `Frame::Error { reason }` text (`ipc.rs:3799, 5998`), and the
    CLI, TUI and FFI recover it where they recover faults at all (`Fault::from_explanation`,
    `api.rs:2028-2041`, called by `live.rs:3745, 3853` and `vox-ffi/src/client.rs:2256`; the
    plain CLI does not: `client.rs:686-693` returns `Frame::Error.reason` as `AppError::Usage`
    and `app.rs:60-64` prints it; the join path has its own `fault_named`,
    `tunnel_cli.rs:990-994`, which keeps only the first line); the app matches seven read
    refusal texts by hand (`NodeModel.swift:1403-1418`). `NotYet` carries data, so it cannot
    be a `Copy` fault with a fixed text. The carrier: `Frame::Error`'s `reason` for a `NotYet`
    is `Failed(NotYet)` on its first line, as `from_explanation` already decodes `Failed(<name>)`
    (`:2030-2034`), followed by one line of JSON `{prerequisite, said, retained}`. **One
    decoder, every receiver:** `Fault::from_explanation` returns `Fault::NotYet { .. }` from
    those two lines and is the only reader of the JSON; the plain CLI's `unexpected`
    (`client.rs:686-693`) runs it before printing and renders NW-4's retained-or-repeat sentence
    from the typed fields, never the two lines; `tunnel_cli::fault_named` is deleted and the
    join path calls `from_explanation` too (re-check F1). The app's FFI hands it a typed
    `NotYet` value (`client.rs:2256` is the daemon-frame site). The app's seven-text list
    (`NodeModel.swift:1403-1418`) goes only when every case it retries has a typed route
    (re-check R11-1): (i) the two governance-refreshing spellings → `NotYet(GovernanceFold)`
    (NW-1's producers); (ii) `the room is refreshing saved history; retry` (`channel/history.rs:266-290`,
    a `ViewPage` while the retention projection is incomplete) and `the room is preparing
    selected history; retry` (`:632-639`, `room_views_ready()` false) → `NotYet(Projection(room))`,
    whose predicate already names the room-view projections (NW-1's table; the producers are
    added to NW-1's list and `ReadResource::query`, `read_resource.rs:395-424`, carries the typed
    error, `Request::RoomViewPage`, `ipc.rs:8188-8224`, forwards it as the carrier above, and the
    FFI's `answered` hands Swift the typed value); (iii) `the room is removing expired saved
    history; retry` → the same `Projection(room)` (the retention sweep is one of its refreshers);
    (iv) the two "room changed while reading" spellings are not daemon refusals: the FFI
    builds "The room changed while reading. Refresh and try again." itself when eight fenced
    read attempts see the room change under them (`under_fence!`, `client.rs:47-66`;
    `room_page_read`, `:2905-2921`), and the daemon's `history.rs:255` spelling is a reader
    re-read too; Swift retries them at opening (`:2358-2364`) and while
    following (`:1506-1520`). Those stay a reader re-read (Appendix A row 34), typed: the FFI
    returns `VoxError::ReadInvalidated` for it, and both Swift consumers keep their retry on
    that case and on `NotYet { retained: false }`; no text is matched (re-check F2). The
    attention transport's answer becomes `Result<Reply,
    AttentionRefusal>` with `AttentionRefusal::NotYet { prerequisite, said, retained } | Other(String)`
    (`attention/transport.rs:63-99`), decoded by `sessions.rs:243-268` and the hook (the hook's
    decoding and its `wait_ms` are this ADR's, NW-3; ADR-050 keeps them as a contract);
    `Saved::Unavailable` (`maintenance_save.rs:793-804`) becomes `NotYet(PublicationGate)`.
    Producers map onto it, each classified by the gate that actually refused:
    `pending_text.rs:289`, `local_history.rs:127`, `rekeys.rs:90`, `HistorySourceStart::Busy`
    (`sparse_history.rs:1340`) → `RoomWrite` (each of the three room-quiet tests becomes a
    queue place, NW-3); `channel/history.rs:266-290, 632-639` and the retention sweep's
    `; retry` → `Projection(room)`; `maintenance_save.rs:793-804`, `post_save.rs:547-558`,
    `metadata_save.rs:1843`, and its three re-wordings `maintenance_save.rs:1183`,
    `package_save.rs:923`, `key_prune_save.rs:112` → `PublicationGate`; `governance/channel.rs:714`,
    `view.rs:377,1055` and the bare `read_resource.rs:95,101` → `GovernanceFold`; the five texts
    of `sessions.rs:166-176` → `Projection`; `actor.rs:26100`, `actor.rs:24500-24502`,
    `policy_current` false at `computer.rs:2951-2960` → `ComputerPolicy`; `try_read` none at
    `computer.rs:2958` → `PublicationGate`; `Error::ComputerPolicySuperseded` → `ComputerPolicy`;
    `Error::OwnHistoryBehind` for a daemon-owned obligation → `OwnHistory`; `Error::RoomNotSynced`
    for a daemon-owned obligation (ADR-048's withdrawal in a sparse-joined room) → `Settled`;
    a write refused because the room cannot save (the store latched, or ADR-047 SO-11's floor),
    for an owner whose state the room's open does not derive again → `StoreRecovery` (ADR-046
    SY-24). A ruled save's own flush is never a not-yet: under ADR-044 RD-7 (revision 14, ledger
    row 74) every ruled commit makes its own flush, off the actor, and its caller waits for
    that one trip; a flush that fails answers that one command `cannot save: disk` at once.
    The daemon↔hook control protocol changes (the typed attention answer and `Fault::NotYet`);
    it is counted in ADR-041 RS-12's one bump of the control-protocol number for this release.
    Hook flags and exit codes are hook surface, not IPC (ADR-041 RS-12). The room log, the peer
    wire and the node store do not change.
  - *Deleted*: the string lists in `poison()` (`channel.rs:5218-5226`), `read_save::expected_refusal`
    (`read_save.rs:16-32`, its not-yet entries), `sessions::opening_refreshing`
    (`sessions.rs:166-176`, its not-yet entries), `governance::refreshing`
    (`channel/governance.rs:777-779`), the exact-text match at `package_save.rs:324-327`, the
    string matches at `key_body_scan.rs:93,102`; the three re-wordings of `Saved::Unavailable`.
  - *Proof*: NW-11's second journey (a key selection refused with the bare text opens the key
    once governance is applied). Mutant: keep the bare string at `read_resource.rs:95` and its
    text classification; NW-11's "key opened within 10 s" goes red. Acceptance NW-1-A: no
    refusal text appears in a classifier (a review condition, not a proof; the proofs are the
    journeys that use the typed value).

- **NW-2. A not-yet never marks a room unable to save.** **(changed: lane split.)** Only a store
  write failure reported by the operating system, a malformed artifact read from disk, or
  ADR-047 SO-11's floor refusal MAY mark a room unable to save and start store recovery. A
  not-yet, a released reservation without a cause of its own, a key-package attempt held in
  memory, and a trust-stage refusal MUST NOT. The marking is one typed decision: `poison()`
  accepts `Error::Storage`, the on-disk `MalformedAtRest` kinds and the floor refusal, and
  refuses every other error by type; the direct assignments of `poisoned = true` outside it
  (`pending_text.rs:741-743, 755-757`) go through the same decision, carrying ADR-042 TR-12's
  `PoisonCause::{WorkerPanicked, SaveFailed(error)}`. A room so marked is the wait
  `StoreRecovery(room)` (NW-1); status shows it as ADR-034 SR-2's `cannot save` line, and
  during ADR-047 SO-12's drain and reopen as its `cannot save: the store is recovering` line
  (ADR-047 X047-11): the same wait, two of ADR-042's words for its two phases. A save never
  waits for a flush that is not its own; a failed ruled commit is told `cannot save: disk` at
  once and is not a wait (ADR-044 RD-7, revision 14). NW-2's wait is the room's, from the latch
  until `StoreRecovered(room)`, after which the next save runs its own commit.
  - *Why*: D-34; item 31 (a 58 s whole-store rewrite for an in-memory counter); item 26 (36
    "cannot save" lines and 12 refused recoveries for a fault never on disk: ADR-048 removes that
    producer, this requirement removes the remedy's misuse).
  - *Changes*: `poison()` decides by type; this ADR lands that decision and every call site it
    governs, once: `release_pending_text` loses its `poison` parameter and takes a
    `PoisonCause` option; the trust pass's `release_rooms` and `Pending::retire`
    (`policy_save.rs:136-153, 172-182`) release without marking; `finish_pending_trust`'s call
    (`pending_trust.rs:203`, which calls `poison(error)` for every error of the trust
    component's commit; whether it marks is decided by `poison()`'s existing exclusions,
    `channel.rs:5218-5230`) and the abandoned protected commit go through the same typed decision, so a trust
    refusal that is a not-yet or a permanent refusal marks nothing and only a storage error
    does (ADR-048 X048-2). ADR-048 owns what the pass does after the release; it does not land
    the marking change.
  - *Deleted*: `Fault::TrustRemovalIncomplete` and "trust withdrawal is incomplete; reopen this
    room"; "authored save worker stopped" as a release text (`pending_text.rs:757`; the panic
    text of `:802-805` is ADR-042 Appendix D's); the `poison = true` of the key-package selection
    stage (`pending_package.rs:709`). Store recovery itself is ADR-047's (SO-11, SO-12).
  - *Proof*: NW-11's journeys assert zero `cannot save` lines and no `recovered; it can save
    again` line in the daemon log while a key selection is refused and re-armed. Mutant: let
    `poison()` accept `NotYet` again and keep the selection stage's `poison = true`; the first
    journey's "no `cannot save`" assertion goes red. Acceptance NW-2-A: zero store recoveries in
    those journeys. ADR-048's journeys add the trust-pass case.

- **NW-3. The owner parks a not-yet on its prerequisite and finishes it when the prerequisite is
  released, without losing a wakeup and without growing.** **(changed: second review F13,
  closure rows 6, 11, 12; registry section: boundaries, bounds, restart.)**
  Every obligation that receives `NotYet` inside the daemon MUST be parked in one per-node
  registry keyed by its logical identity, and the prerequisite's release MUST run it again
  through its original entry point, revalidating every fence (policy revision, room instance,
  attachment). Nothing else MAY run it again: no tick, no timer, no count (ADR-038 FX-27, FX-40,
  FX-45). An obligation MUST be retired only by completing, by a permanent refusal (reported once,
  where it was asked for; for daemon-owned work, one log line and a `vox status` line until the
  room is reopened), by a storage failure (the room is marked under NW-2 and the open after
  recovery derives the work again), by lock or shutdown, by its room's removal or replacement, by
  its last requester leaving (requested obligations only), or by actual supersession, in which
  case it MUST be issued again under the new policy, not dropped (a fencing token rejects the
  stale write; the work re-enters at its stage, never from the command's start, so a committed
  prefix is never replayed: ADR-038 FX-49).

  *A bound is not a retry.* A deadline that answers a requester, or ends an obligation (an
  expiry its owner names), never runs the work; it is allowed, and the owner that sets it says so.

  *Two lanes, one turn each (ledger row 82b, refining row 82).* No obligation of this ADR MAY
  wait for, reserve or require a room to fall quiet; a room with posts in flight is the normal
  case. At the tag three sites refuse control work because a post is pending:
  `reserve_pending_write` (`pending_text.rs:283-291`, every own publication),
  `history_publication_busy` (`sparse_history.rs:1426-1434`, the sparse publication) and the
  rekey's `pending_posts` test (`rekeys.rs:87-91`); under continuous posting each can be refused
  for ever. `RoomWrite(room)` is therefore **a turn in a lane**, never a quiet-room test. Each
  room has two lanes, FIFO within each: **control** (trust, computer policy, roster, rekey, key
  packages, keyring batches, evictions and readmissions) and **authored** (posts, Session
  activity, read marks). When both lanes have ready work they **alternate**, one control turn
  then one authored turn; when one lane alone has work it runs back to back. A **turn** is one
  native transaction, ending at its own Immediate commit and installation (ADR-044 RD-7,
  ledger row 74, unchanged). A multi-step control operation takes one turn per transaction
  and keeps its continuation between turns; a child transaction it dispatches runs in the
  parent's turn and never queues behind its parent (the rekey, below). **Bounds** (ledger row
  82c): a control transaction, once at the head of its lane, waits for at most the transaction
  in flight plus one authored write; from enrolment it also waits for the control transactions
  ahead of it and the one authored turn each permits; an authored write waits
  for the writes ahead of it in its lane plus at most one control transaction per write.
  Nothing is refused, and no trust or policy command is deferred behind a pending ordinary
  save. The predicate of `RoomWrite(room)` is "my turn has come"; its release is the hand-over
  of the owner at the end of the transaction in flight. ADR-044 RD-10 and ADR-048 TC-4 (item 93)
  state this same rule for the queue and for the policy application; the three are one rule.
  Proof: ADR-048 act 3's extension (the `Rekey` fold, below) and NW-12's journey, each with a
  post in flight at every moment (the posting loops' per-post times show no gap, else
  APPARATUS) and its 10 s bound; and the alternation itself: with a post queued in the authored
  lane and a multi-transaction control operation running (the rekey's recipients), the post
  lands between two of the control transactions (the post's commit time falls between two
  `test-knob: control turn <room> <stage>` lines, `test-knobs` only, else APPARATUS). Mutants:
  (1) restore `rekeys.rs:87-91`'s `pending_posts` refusal with a tick-driven retry; under the
  loops the rekey never lands; M never decrypts; red. (2) **control runs back to back while a
  post is queued**: the queued post lands only after the last control transaction; red on the
  post's bound (one control transaction).

  *The park-or-run contract (no lost wakeup).* Every prerequisite carries a generation
  (`AtomicU64`). The code that changes the state the predicate reads bumps the generation in the
  same critical section, **before** any wake or notify, at every transition that makes the
  predicate true (NW-1's third column is that inventory; the rule is what makes it complete: a
  state change without a bump is a defect, wherever the wake lives). A producer, on or off the
  actor, reads the generation before it observes the condition and returns it in `NotYet
  { seen }`. When the actor parks, it makes two checks, and parks only if both say the work
  cannot run: (a) it evaluates the prerequisite's predicate itself, now, on the actor (every
  predicate in NW-1's table is actor-readable); true → do not park, run the obligation again at
  once under the authority, lease or state that is current now; (b) it compares the
  prerequisite's current generation with `seen`: moved → do not park, run again at once. On
  release the actor takes every obligation parked on that prerequisite and runs each again; one
  that receives `NotYet` again parks again with its fresh `seen`, on whichever prerequisite it
  now names (migration to the next dependency keeps the obligation's stage and replies). An
  off-actor worker inside the daemon never parks itself: it returns `Error::NotYet { seen }`
  through its continuation's `Result`, which already crosses to the actor, and the actor parks.
  A spurious release costs one re-check and nothing else.

  *A stale token is not a false predicate (third review F1).* A worker that holds an authority,
  lease or revision captured **before** it ran can be refused because that capture is stale
  while the node is already current: `begin_pending_maintenance` captures `authority` on the
  actor (`maintenance_save.rs:677-683`), its worker later takes the reader and checks the
  captured revision (`:793-803`, `computer.rs:2845-2849`; `held.authority.current()` at
  `maintenance_save.rs:821-822`); metadata has the same capture→spawn→check split
  (`metadata_save.rs:2429-2463`). Between the capture and the check the node can apply r+1 and
  release `ComputerPolicy`; the worker then reads the new generation, is refused for its
  captured r, and nothing releases again. Check (a) is what closes this: at the park,
  `policy_current()` is true, so the obligation re-enters at its stage with the actor's current
  authority (`computer_authority()`), never with the captured one; `ComputerPolicySuperseded` is
  therefore "refresh under current authority; park only if the node is not current". The same
  holds for every captured fact (a room instance, a publication lease): a re-run re-acquires it;
  a parked obligation holds none (FX-40).

  *Where `seen` lives (the boundaries).* `seen` is an actor-internal token. It never crosses the
  actor's reply boundary and never crosses a process boundary: `Fault::NotYet` and
  `AttentionRefusal::NotYet` carry no `seen`. Nothing outside the actor parks on a generation it
  did not observe itself. Concretely:
  - An attention request (`NodeHandle::attention`, `actor.rs:5711-5733`, answered at
    `:8629-8632`) whose operation receives `NotYet` is parked **before the reply is sent**: the
    actor keeps the oneshot and the operation in a requested obligation and answers it when the
    work completes. The requester's bound is its own: a hook's request carries `wait_ms` (the
    hook's remaining budget less a margin; at most `WITHIN` − 1 s, `transport.rs:9`), and at that
    instant the actor answers `AttentionRefusal::NotYet { prerequisite, said }` and drops the
    obligation; a requester that drops its receiver is pruned. A client that receives the typed
    refusal re-issues its whole request; it parks nothing, so it needs no `seen`.
  - The attention loop (`node_tasks.rs:157-173`) is the owner of its per-room cursor. Its
    request for a room that receives `NotYet` is answered at once as retained, the loop keeps the
    room's cursor and MUST NOT ask for that room again until woken; the owned obligation
    `(room, AttentionSelect)` holds the loop's wake, and the release wakes it.
  - A registered Session's opening (`sessions.rs:243-268`, driven by `host.rs:2084-2217`) is a
    requested obligation `(room, SessionOpen(session))` parked with its reply; `open_registered`
    awaits the reply (its 30 s deadline is the requester's bound; past it, it re-issues, a fresh
    observation) and stops only when the session is forgotten or the node detaches. The
    `yield_now` loop of `sessions.rs:256-266` goes.
  - A command of a person whose work the daemon retains is answered with the retained form
    (NW-4) after the actor parked; one whose work is not retained is answered with the
    "run it again" form; the command re-issues the whole operation.

  *Coalescing (bounded parked work).* The registry is `BTreeMap<Key, Obligation>` with
  `Key = (room, Kind)`; the kinds this ADR defines are `ReadFlush`, `Settlement`, `KeyPackage`,
  `Rekey`, `Governance`, `MetadataPublish(component)`, `Construction`, `SessionOpen(session)`,
  `AttentionResolve(session)` and `AttentionSelect`; a sibling ADR adds its kinds under the same
  rules (ADR-048 `TrustDebt`; ADR-049 `DepartureSign`, `DepartureDelivery(peer)`, `EndedPurge`,
  `JoinAfterPurge`; ADR-046 its
  failed-cleanup retry). A `Kind` MAY carry a sub-identity (a session, a component, a peer), and
  `Registry::retire_prefix((room, kind))` retires every sub-key of one logical obligation at
  once: a wait on "any of several peers" is one sub-key per peer, the first completion retiring
  the rest (offered to ADR-049 for F14; this ADR does not design the departure). A second
  not-yet for a parked key merges into the parked obligation: the newest required progress wins
  for re-derivable kinds (a key-package selection re-reads its durable cursor; a read flush
  rescans; a settlement re-reads the sparse root), the exact stage and fences of the first are
  kept for stage-exact kinds (`MetadataPublish`, `Construction`), and `since` is the oldest. A
  stage-exact obligation that carries a person's reply never merges with another person's
  operation: a second distinct operation of the same key queues behind the first, and that
  queue is bounded (below). A producer
  MUST consult the registry before beginning work of a parked key and MUST NOT begin it
  (`flush_reads`, `read_save.rs:170-215`, skips a room whose `(room, ReadFlush)` is parked, as it
  skips `pending_posts` today; the package, governance and settlement producers likewise).

  *Queued work and replies are bounded too (third review F2, F3).* Two bounds, both counted
  until the work completes or is retired, whatever happened to its reply:
  - **Queued distinct operations.** At most 4 distinct stage-exact operations wait behind the
    running one on a key. A fifth is refused at admission with NW-4's not-retained form (`run
    the command again then`) and nothing of it is kept: no stage, no input, no fence. A queued
    operation counts even after its reply was answered or closed, until it completes. An owned
    stage-exact operation that the open derives from a durable row (NW-3's re-derivable class)
    is never queued twice: it is one key. In this ADR's kinds the queue cannot fill: a
    `MetadataPublish` with a person's outcome is one of `PublicationAfter::{Created, Joined,
    Opened}` (`metadata_save.rs:1215-1229`), one per room and lifecycle step, and
    `Construction` is one per room; a person's post or rename that meets a revision move is
    not retained at all (Appendix A row 19). The bound binds the kinds a sibling adds that admit
    several person operations on one key. Neither ADR-048 nor ADR-049 names such a kind today
    (`TrustDebt`, `DepartureSign`, `EndedPurge` and `JoinAfterPurge` are one per room), so the
    bound is a **review condition on `Registry` with no journey** (task cut D6): a reviewer
    checks the limit and the fifth answer by reading the code; the first ADR that adds a kind
    admitting several person operations on one key carries NW-3-C and mutant 5 in its journey.
  - **Replies.** An obligation's replies are a set keyed by requester (the connection or task
    that asked), each with its own deadline. A closed reply is pruned at every touch of the
    obligation (merge, release, status) and never answered. At most 16 live replies wait on one
    key. A 17th requester is answered according to the obligation's class, and the answer is
    true: for an **owned** obligation, NW-4's retained form (the owner survives every reply;
    the requester is told Vox finishes the work, not when) and the requester holds nothing; for
    a **requested** obligation (a Session opening, a hook's Resolve), NW-4's not-retained form
    as `AttentionRefusal::NotYet { prerequisite, said, retained: false }` or
    `Fault::NotYet { …, retained: false }`, because the obligation is retired when its last
    waiting requester leaves and nobody would finish the 17th's request. Each consumer of the
    not-retained answer re-issues: `open_registered` after its own deadline (as for any refusal
    it receives), the hook's extension through `scheduleRetry` as today; the attention loop
    never overflows (one requester per room).
  So the registry holds at most one obligation per room and kind, one per registered session,
  at most 4 queued operations and 16 open replies per obligation; a prerequisite that never
  releases shows as one `waiting` line, not as growth.

  *Durability and restart.* The registry is in memory. Three classes. *Re-derivable*: the
  durable state already implies the work at the next open, and `open` derives it **before the
  room admits any egress**: a key-package selection from its durable cursor; a read-mark flush
  from the marks segment; a settlement save from the sparse root; a rekey from the consent
  state; governance work from the unpublished governance fold; a Session opening from the
  registration files (`open_registered` at start); an attention selection from the attention
  ledger (the loop visits every room at start with no parked marks); a metadata publication from
  the component row the open compares with what was published (the task that lands NW-12 names
  that row for each of the 16 `ComputerPolicySuperseded` occurrences and amends Appendix A row 18; a
  component with no such row is stage-exact and is cancelled at shutdown with its reply told,
  never dropped in silence). *Requested*: gone with its requester; a hook or a command re-issues.
  *Not durable, said so*: a room construction's parked `Work` (`construction_save.rs:64-70`,
  `:617-625`) is in memory with its sealed secret (FX-61a). Daemon death ends an attempt that
  accepted no durable fact: the person's command fails as the daemon stopped (ADR-041's words)
  and he runs it again; nothing reconstructs the secret. An attempt whose remote admission was
  accepted (Appendix A row 36) is finished by the join's durable owner (ADR-046). Work whose loss
  loses a person's fact is not parked here: it is journaled by its own ADR (ADR-050's turn
  journal; ADR-049's departure record).
  - *Why*: items 28 (the attention loop and Session opening dropped their work), 31 (a selection
    refused "refreshing" was never re-armed), 32 (read marks, key deliveries and settlement
    logged and dropped at every revision move); first-review finding 6 (revision 1's edge-keyed
    vector could lose a release that happened between an off-actor observation and the park);
    finding 12 (it could hold one copy per tick); second review F13 (a release at the gate with
    no `Writer`), closure rows 6 and 11 (`seen` was absent from both reply shapes, and sampling a
    fresh generation after decoding would restore the lost wakeup), closure row 12 (an appended
    reply list is unbounded), its restart paragraph (an in-memory construction is not a durable
    source; metadata and attention selection had no named open-time derivation); third review
    F1 (a stale captured authority refused after the node became current would park for ever
    on a true predicate), F2 (queued distinct operations were unbounded behind a bounded key),
    F3 (the 17th requester of a requested obligation was promised a completion nobody owned).
  - *Changes*: a new `actor/parked.rs` with `Registry`, `Key`, `Obligation { room, work, replies,
    prerequisite, seen, since, class }`, and `Prerequisite::generation()`; the generation counters
    live on the objects that own the state (`ChannelState.history_publication_changed`,
    `governance_work`, the projection refreshers, `Gate` itself, `computer_revision`/
    `authority_blocked`, the room's recovery state); `Gate` bumps under its lock at
    `publication_gate.rs:129-133, 170, 177-178`; `finish_managed_policy` (`policy_save.rs:1542-1556`)
    releases `ComputerPolicy`; `release_pending_text` and `note_publication_complete` release
    `RoomWrite(room)`; the park checks the predicate on the actor before comparing generations,
    and a re-run takes `computer_authority()` fresh (`maintenance_save.rs:677-683`,
    `metadata_save.rs:2429-2463` re-enter through the actor, never with a captured authority);
    `Registry` holds the queue bound (4) and the reply bound (16) with the obligation's class;
    `AttentionRefusal::NotYet` and `Fault::NotYet` carry `retained`; the attention command
    handler (`actor.rs:8622-8634`) parks before replying; the attention request gains `wait_ms`
    and the hook sends it (`agent_hook.rs:408-418`; this ADR owns both ends of that request);
    `node_tasks.rs:157-173` keeps its cursor and waits for the wake; `host.rs:2084-2217` awaits
    the parked opening.
  - *Deleted*: the private parking mechanisms named in "What they have in common", folded into
    the registry with their keys, each with the existing act that keeps proving the work it
    carried finishes (nothing is deleted without one): `key_package_rooms`,
    `key_package_unopened`, `key_package_governance_wait`, `key_package_retry_at` (→
    `KeyPackage`; NW-11's two journeys); `redeliver_now` (`rekeys.rs:88`, → `Rekey`; under row
    82b the rekey meets no busy refusal: the `(room, Rekey)` obligation holds a **transferable
    grant for the next bounded native transaction** in the control lane, not the whole sweep.
    The parent walks its recipients (`advance_owned_rekey_pass`, `rekeys.rs:287` onward) and
    dispatches one native Packages child per recipient (`dispatch_owned_rekey_native`,
    `:531-552`, through `begin_pending_maintenance`); that child reserves the room's write
    (`pending_package.rs:487`) **under the parent's grant and identity**, in the parent's turn,
    never queued behind its parent, and the physical ownership is released at that child's
    commit and installation (`:668`), before the next recipient or stage; between recipients
    the parent keeps only its continuation (`RekeyAfter::Consent`'s tail and reply,
    `RekeyAfter::Packages`' remaining redelivery, `:827-851`) and the authored lane takes its
    turn. A recipient's dependency wait (a key not yet constructed) keeps the continuation and
    blocks neither lane. So the act proves the rekey **completes under continuous posting and
    lets posts through between its transactions**: the proving act is **ADR-048's act 3,
    extended** (re-check R11-4, R12-F2, row 82b): before the removal a surviving member M has
    not yet received the rotated generation (M's daemon stopped while the rotation is
    published, as ADR-048's act 2c stages an owed recipient); two members post in R3
    continuously (one post in flight at every moment: the loops' per-post times show no gap,
    else APPARATUS); M's daemon starts; the `(R3, Rekey)` obligation's turn is receipted
    (`test-knob: control turn <room> rekey <recipient>`, `test-knobs` only, else APPARATUS);
    M decrypts a post committed after the rotation within 10 s of its start, read with `vox
    room read R3 --json` on M; at least one of the loops' posts commits between two rekey
    turns; W's `vox room read` never showing a post after the rotation stays a separate
    confidentiality assertion (ADR-048's). Mutants: **drop the `Rekey` resume** (the grant is
    never taken); M never decrypts the post; red on the 10 s bound; and NW-3's mutant (2),
    control back to back; red on the queued post's bound. Until ADR-048's act lands this fold is
    not landed);
    the private
    wakes of `governance_work.again` (→ `Governance`;
    `a_newcomer_reads_the_whole_history_proof.rs::retained_rows_render_once_their_key_and_consent_arrive`,
    `:6831`, which holds and releases the fold and reads the rows); `preparation_save::wait_on`
    (→ the stage's kind; NW-8's act 1, a room preparing while the gate is busy, and ADR-044
    RD-11's preparation journey); `own_key_policy_waiting` (→ the kind of the waiting work;
    NW-12's journey, governance work deferred across the move, `defer_own_key_policy`);
    `parked_construction` (→ `Construction`, keeping FX-61a's sealed-secret exception; at the
    tag the parked consumer retains `Work::Create` only and an unadmitted superseded
    `Work::Join` is aborted, `construction_save.rs:598-636`; a join held at admission proves
    nothing, since admission precedes the constructor's authority capture, `actor.rs:14544-14578`,
    `:11657-11676`, `construction_save.rs:447-478`; re-check R11-3): the registry retains both
    (`Construction` carries `Work::Create | Work::Join`; the abort consumer migrates to a park
    on `ComputerPolicy`, re-entering at `begin_construction` with fresh authority, FX-61a's
    sealed secret retained until admitted or dropped). The proving act is **NW-12's journey,
    extended**: an existing joiner J (a node other than the one `vox node create` makes) joins
    a third room, held by the tag's `VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD`
    (`construction_save.rs:496-535`, after the constructor's authority capture and before its
    publication acquisition) across the `vox node create`; the retention is receipted
    (`test-knob: parked Construction <room> (join)`, `test-knobs` only, else APPARATUS); after
    release the join completes and J reads the room within 10 s; mutant: drop the
    `(room, Construction)` resume on `ComputerPolicy`; the join never completes; red on that
    10 s bound); `publish_waiters`/`publication_pending` (`actor.rs:6870`, →
    `MetadataPublish`; NW-12's journey, the joined room's settlement publication after the move).
    Each fold is accepted only with its act green; review is never the only check.
    Nothing is deleted before every state it covered has an emitting and a consuming route in the
    table of NW-1. The extension of the existing weak parked owner (FX-45) is this registry.
  - *Proof*: NW-12's journey (saves refused at a revision move complete with no later command),
    NW-11's (a refused selection opens the key once the prerequisite clears) and NW-8's (a
    parked reader is released when a waiting writer leaves without writing). Mutants: (1) drop
    the `ComputerPolicy` release in `finish_managed_policy`; NW-12's "read mark visible within
    10 s" goes red. (2) Park unconditionally: skip **both** the predicate check (a) and the
    generation compare (b) while the apparatus releases the prerequisite between the worker's
    observation and the park (NW-11's first journey holds the package worker **after** it has
    produced `NotYet(GovernanceFold)` and before its result reaches the actor, and completes the
    fold during that hold); the key never opens; red on "key opened within 10 s". Skipping (b)
    alone is masked by (a) in this staging (the fold is complete when the actor parks, so (a)
    re-runs the work), and a re-hold of the fold before the park would be released again later;
    so the mutant removes the park-or-run protection as a whole for this ordering, and mutant 4
    is the independent case for (a). (3) Bump the gate's generation on `Writer` drop
    only; NW-8's abandoned-writer act leaves the sibling's post parked; red on that post's
    completion bound. (4) Skip the predicate check at the park (compare generations only) and
    hold the maintenance worker of NW-12's read flush between its authority capture and its
    `try_acquire_publication` with a `test-knobs` hold (`VOX_TEST_MAINTENANCE_AUTHORITY_HOLD_MS`,
    room-scoped, a `test-knob:` log line or APPARATUS) across the revision move; the flush is
    refused for its captured revision, parks on a policy already current, and the read mark is
    never visible; red on NW-12's 10 s bound. (5) Drop the queue bound: carried by no journey
    today (above); a review condition until a sibling adds the kind. Acceptance NW-3-A: every
    parked obligation in those journeys completes within 10 s of its prerequisite's release;
    NW-3-B, **hosted by NW-11's second journey** (the fold held across a restart, `vox status`
    showing the `waiting` line; D5), counted **per kind** (re-check F7): with the fold held, the
    daemon's own read flush (`flush_reads`, `read_save.rs:170-215`, the `mark: false`
    continuation; the hook's `mark_read` creates `mark: true` ones and is not the flush) is
    provoked once a second for 60 s by a hook `--omp-prepare` through RS-7's shim marking a post
    read, so that each tick finds unflushed marks; its first refusal by the held fold is a
    receipt (`vox status --json .waiting[]` shows a `ReadFlush` entry for the room by 35 s, else
    APPARATUS); across the ticks `.waiting[]` holds exactly one `ReadFlush` entry for the room
    beside the host's one `KeyPackage` entry, and the daemon's resident set does not grow with
    the ticks (measured at 0 s and 60 s, within 2 MB; the number is a diagnostic beside the
    one-entry assertion, not a gate of its own); NW-3-C: under a held key, the fifth distinct
    operation is told to run it again and the first four complete after the release (no host
    today, D6).

- **NW-4. A person can read what waits, and is told the truth when asked.** (Q4 answered:
  after 30 s.) **(changed: ADR-042 TR-23's `failed` form; lane split; third review F3.)**
  - `vox status` MUST list every obligation parked longer than 30 s, one line each, in a
    `waiting` block after `UNHEALTHY:`/`healthy:`, in ADR-042 TR-23's two forms:

    ```
    waiting
      room cx7qm2tyy4qs (r2c): opening a member's key waits until this room's member and permission entries are applied, for 35 s; Vox finishes it by itself
      room o6z3enlc2ymd (repo-to-cve): publishing its read marks failed: this identity is not an author of the room; it is not retried; rejoin the room to publish again
    ```

    The first form is a parked obligation; the second is a permanently refused daemon-owned
    obligation, shown until its room is reopened. `vox status --json` MUST carry the same as
    `.waiting[]` with `room`, `what`, `waits_for` (or `failed`), and `since_ms`. A line MUST
    disappear when its obligation completes. An obligation parked on `StoreRecovery(room)` of a
    room whose `cannot save` line (ADR-034 SR-2) is already printed is not printed again in the
    text; the JSON carries it.
  - A command whose request received a not-yet MUST say which of two things is true. When the
    daemon holds the obligation (`retained = true`): `vox: <what> has not happened yet: it waits
    until <prerequisite words>; Vox finishes it by itself`. When nothing was kept: `vox: <what>
    was not done: it waits until <prerequisite words>; run the command again then`. `retained`
    is set by the owner that parked, never guessed from the error.
  - The daemon MUST NOT log a not-yet as a fault. It MAY log a permanent refusal once.
  - *Why*: every item in this group was invisible: v0.4.30 showed none of them in `vox status`
    within the minute they began, and its refusal texts name internals ("authored save worker").
  - *Changes*: `fault_of` maps `NotYet` to `Fault::NotYet { prerequisite, said, retained }`; the
    status reply gains `waiting`. The layout of `vox status` and the style of every sentence are
    ADR-042's (TR-11, TR-23): this requirement fixes what the lines must say.
  - *Deleted*: the sentences the plan found for the same condition ("a previous change to this
    room is still being applied" for a held gate; "attention waits for current computer trust"
    when trust is current; "could not read its saved key deliveries" and "could not publish its
    saved read marks" for a revision move; "a join did not complete" for a settlement save).
    Proofs that match the old texts are to be updated in the same change (at v0.4.30:
    `nodes_of_one_daemon_proof.rs`, `work_board_proof.rs`,
    `a_newcomer_reads_the_whole_history_proof.rs`, `a_room_can_be_left_and_ended_proof.rs`,
    `a_rooms_own_anchor_is_redialled_proof.rs`, `support/room.rs`; and the app's
    `apps/macos/VoxAppProofs/FirstRunProof.swift:9568`, which matches "a previous change to this
    room is still being applied; this request made no change"; D1); each rewritten assertion
    asserts the retained-or-repeat truth of its case, not merely the absence of the old words.
  - *Proof*: NW-11's second journey (a room whose governance fold is held across a restart):
    after 30 s `vox status` shows the room's `waiting` line naming the prerequisite; after the
    hold is released the line is gone within 10 s. Red on v0.4.30: there is no `waiting` section
    (KNOWN by code). Mutant: omit parked obligations from the status reply; red on the line
    assertion. The `failed` form has no reachable case in this ADR's journeys (no daemon-owned
    obligation here fails permanently); its first reachable case and its proof are ADR-048's
    terminal debt. Acceptance NW-4-A: the line appears by 35 s and disappears ≤ 10 s after the
    release.

### 2. A node starting refuses nothing of its siblings

- **NW-8. While one node of a daemon starts, every other Ready node of the daemon posts, opens
  Sessions and prepares hook context without refusal; "attention waits for current computer
  trust" is said only when computer trust really is not applied on that node.** **(changed:
  second review F13, closure row 13, task table.)** The exclusive publication transition MUST
  be held only around policy settling (`settle_policy` and its repeat when the policy moved), not
  across Argon2, store open, network start, reopening rooms or the Ready publication; a fresh
  `policy_current` check MUST be made at the final Ready publication after the narrowed
  transition is dropped. The gate keeps its writer preference (a waiting writer closes the gate
  to new readers, the readers it has drain, and the writer runs: `publication_gate.rs:49-58,
  95-104`, unchanged): there is no yielding startup writer (first-review finding 13). A startup
  writer that gives up waiting, or is cancelled, MUST release `PublicationGate` like a writer
  that wrote (NW-1, NW-3: the bump sits in the gate). What changes is what a refused reader
  does: the refusal is `NotYet(PublicationGate)` or `NotYet(ComputerPolicy)`; the attention
  loop keeps its cursor and is woken; the Session opening is parked with its reply; the hook's
  request is held up to its `wait_ms` and then answered with the typed refusal, which the
  extension retries as today. The window itself shrinks from the whole startup to the settling
  step (milliseconds on scratch).
  - *Why*: item 28 (8–23 s of refusals at every Mac restart; dropped Session openings; stale
    notices; item 30's dead conversations, ADR-050).
  - *Changes*: `startup_save.rs:422-459, 541-571, 623-631` (transition only around policy
    settling; a `policy_current` check before `publish()`); `publication_gate.rs` gains the
    writer purpose and the generation; `computer.rs:2951-2960` returns the two prerequisites;
    `actor.rs:23351` says "computer trust is being applied on this node" or "node <name> is
    starting" / "a change to this computer's trust is written"; `host.rs:2176-2189` awaits the
    parked opening; `node_tasks.rs:169-173` keeps the room's cursor; `sessions.rs:243-268`
    decodes the typed answer.
  - *Deleted*: the stale `vox-notice` injected for a transient opening failure
    (`host.rs:2208-2212` for `NotYet`); the `yield_now` loop of `sessions.rs:256-266`.
  - *Proof*: extend `nodes_of_one_daemon_proof.rs::nodes_attached_at_once_all_serve_at_one_address_each_as_itself`:
    three remembered nodes, one with 3 sessions registered as
    `agent_hook_proof.rs::the_hook_feeds_an_agent_its_room_in_either_harness_shape` does;
    `vox daemon --restart`. Three acts, each staged with a `test-knobs` knob that prints a
    `test-knob:` line to the daemon log when it takes effect (absent line → APPARATUS):
    **Act 1 (the narrowing).** `VOX_TEST_STARTUP_HOLD_MS=5000` holds the second node's startup
    **outside** the narrowed transition (between its store open and its policy settling, where
    v0.4.30 held the gate and NW-8 does not). During the hold, `vox room post` by the first node
    and a hook context call succeed within 2 s. PRODUCT red on v0.4.30 on the release asset
    (KNOWN, RcaTrust `run-s1`): the post is refused "a previous change to this room is still
    being applied", 9 opening failures. Mutant: take the transition around the whole startup
    again; the post assertion goes red.
    **Act 2 (writer progress under overlapping reads).** `VOX_TEST_PUBLICATION_READ_HOLD_MS=500`
    makes every publication read lease of the first node last 500 ms; two of its sessions post
    in parallel loops for 15 s (so a lease is always held: the loops' per-post times show no gap,
    else APPARATUS); the third node starts 2 s into the loops. Assert the third node is Ready
    within 5 s of its start while the loops run on. Mutant: let the gate admit new readers while
    a writer waits; the writer never finds `readers == 0` for 15 s; the Ready assertion goes red.
    **Act 3 (an abandoned writer releases the readers).** `VOX_TEST_STARTUP_WRITER_ABANDON=1`
    makes the third node's startup cancel its waiting write after 1 s (the `WaitingWriter` drop,
    `publication_gate.rs:175-180`; the same no-`Writer` exit as the deadline at `:129-133`) and
    start it again 3 s later, while a first-node lease is held 2 s by the knob of act 2; a
    sibling post issued during
    that second is parked on `PublicationGate`. Assert the post completes within 1 s of the
    abandonment (before the third node's second attempt), and the third node is Ready within
    10 s. Mutant: NW-3's mutant 3 (bump only on `Writer` drop); the post completes only when the
    second attempt's writer drops; red on the 1 s bound.
    Afterwards the log has no `attention waits for current computer trust` and no `could not
    open this session's Session`. Acceptance NW-8-A: zero refusals during a 5 s sibling startup;
    every Session opens on its first attempt; a third node Ready ≤ 5 s under sustained sibling
    reads; a parked reader released ≤ 1 s after a writer abandons.
  - *Depends on*: ADR-044 (E-28 is this ADR's experiment and its condition stays here: if the
    Mac's wait proves to be the first node's seconds-long read leases, NW-8 removes the refusal
    and ADR-044 RD-8's lease already bounds the wait; ADR-044 carries nothing conditional,
    ADR-044 X040-11 answered as ASKER DROPS); ADR-041 (item 41, a competing daemon in the
    restart window, makes the window longer and is independent).

### 3. A registration write waits its turn

- **NW-9. A session registration update is never lost, and a caller that needs the committed
  record gets it.** **(changed: second review F10, closure row 9; third review F4; fourth review
  R4-F1–R4-F3; fifth review R5-F1–R5-F5: one writer; sixth review R6-F1–R6-F4: admission and
  order.)**
  **One process writes a session's registration and its state: the daemon.** No hook process
  writes a registration or a state (the one hook-side write left is `wake::end`'s removal,
  below). There is no state side file, no state lock, no timestamp order across processes and
  no stale-writer check: revision 5's multi-writer state file is deleted (see "Why one writer",
  below).

  *Inside the daemon.* Every registration write of a node (`store_name`, `store_room`, `forget`,
  `record_omp_state`, `clear_room_bindings`, `store`, and `store_checked` for every
  `SessionRegister`, `host.rs:1900` and `:4910`) MUST go through one serialized writer per node
  that takes the lock with a blocking `lock()` on the blocking pool, never `try_lock`; the
  writer never sees `Busy`, and `registration_store_refusal`'s `LockBusy` is never produced.
  Two kinds of caller:
  - **Result-bearing setters** (`store_name`, `store_room`, `forget`) become `async` and return
    only after the record is committed, with the committed record or the previous binding as
    today. Their callers keep their order: `rename_omp_session` opens the renamed Session with
    the committed `reg` (`host.rs:3730-3743`); `session_room` ends the old Session, opens the new
    one and acknowledges `SessionRegistered` with the room the record now holds
    (`host.rs:2296-2323`); `forget` reports whether it removed the record. An acknowledgement to
    a person or a harness is sent after the commit, never before: a daemon killed between the
    request and the commit has acknowledged nothing, the command reports the daemon stopped
    (ADR-041), and the record is as it was.
  - **State events** (busy or idle) are updates of the record and go through the same writer:
    the hook's `SessionRegister` request carries the state the hook observed; the OMP bridge's
    `record_omp_state` (`omp_mirror.rs:1634-1644`, run in the daemon) hands its flip to the
    writer. **Order is the writer's arrival order, and nothing else** (sixth review R6-F2): the
    writer applies each state as it arrives and compares no clock; `state_ms` is stamped by the
    writer with its own `now_millis()` for display and for `Session::idle`'s silence bound
    (`wake.rs:706-710`), never for admission. This is the order v0.4.30 already has: `record_idle`
    and `store_checked` each wrote unconditionally in lock-acquisition order (`wake.rs:865-925,
    1380-1393`). What two hooks racing means under it: if a harness runs a session's `Stop` and
    its next prompt's hook at once and the `Stop`'s request reaches the daemon after the
    prompt's, the record reads idle until the next event, as at the tag; the harnesses Vox
    supports run a session's hooks one after another, and a `Stop` is sent before the hook does
    anything else (`agent_hook.rs:2239-2243`), so this needs an overlapping harness. A clock step
    cannot drop an observation: the wall clock is not compared. What a clock step can do is what
    it does at the tag: a backward step of `d` makes a stored busy look `d` younger to the
    silence bound (`now.saturating_sub(state_ms)`), so a silent session is called idle up to `d`
    later than 10 min; a forward step calls it idle sooner. **Admission of a state is independent
    of every other admission** (R6-F1): in `session_register` (`host.rs:5736-5756`), when the
    request carries a state and a record for `(node, session)` exists, the writer applies the
    state to that record **first**, before the attach wait, `blocked_nodes` (`:1885-1891`,
    `:4636-4644`), `want`/`grant` and the Session opening; a refusal of the rest of the
    registration (a room being retired, a node attaching or detaching, the daemon stopping)
    does not undo it, and the hook is answered with that refusal as today. A request for a
    session with no record carries its state in the record it creates, through the gates as
    today. The route check of `record_omp_state` (`wake.rs:1403-1409`: `same`, `first_seen_ms`,
    `mirror`) runs inside the writer against the record it is about to rewrite, so a flip for a
    replaced registration changes nothing (R5-F2). A daemon killed between a state event's
    arrival and its commit loses that flip and nothing else; the next successful event of the
    session carries the current state. This is said here so nobody takes a state flip for
    durable.
  A genuine storage failure of the writer is reported once (the error line of
  `registration_write`, kept for that case only) and the update is kept for the next write of
  that session.

  *Why one writer (fifth review).* At v0.4.30 the hook process writes a registration in three
  places and nowhere else: `record_idle` on `Stop` (`agent_hook.rs:2243, 2254` → `wake.rs:1380-1393`),
  the attaching fallback `store_checked` while a cold daemon is still starting
  (`agent_hook.rs:2612`), and `wake::end` on `SessionEnd` when no daemon can be reached
  (`:2710`). Every other write is the daemon's: the hook's turn-start record travels over the
  control socket in `SessionRegister` with a 10 s bound (`REGISTER_WITHIN`, `agent_hook.rs:2498,
  2644-2655`) and the daemon writes it (`host.rs:1900`, `:4910`); the bridge's `record_omp_state`
  runs in the daemon; the setters and `clear_room_bindings` are the daemon's. The `Stop` hook
  already makes that daemon exchange before it writes idle: its mirrored branch calls
  `daemon.register` first (`agent_hook.rs:2239-2243`), with a record that says `BUSY`
  (`Session::from_env_untmuxed`, `wake.rs:1007-1008, 1034-1035, 1061-1062, 1085-1086`), and then
  writes `idle` itself. The "direct" `Stop` branch (`:2252-2256`) is unreachable from a shipped
  input: `parse_input` defaults the event to `UserPromptSubmit` (`:94-98`) and a body that says
  `Stop` mirrors (`session_mirror::mirrors`, `session_mirror.rs:335-345`). So the state was
  written by several processes only because `Stop` said `busy` to the daemon and `idle` to the
  disk. Three revisions of ordering a shared file (a bounded lock, an unlocked rename, a
  state-only lock) each opened a new interleaving (fourth review R4-F3, fifth review
  R5-F1–R5-F4); one writer has none of them: no lock inode to unlink, no binding to go stale
  between read and rename, no tie to break across processes, no live holder for a hook to wait
  behind.

  *What the hook sends.* `SessionRegister` gains `state: Busy | Idle`: `Stop` sends `Idle`;
  every other event sends `Busy`; `VoxAttentionRegister` (`registration_only`) sends none and
  the writer keeps the record's state (`wake.rs:894-899`'s no-flip rule, kept). No timestamp
  travels: the writer stamps `state_ms` itself. `record_idle` is deleted; the `Stop` hook's only
  write is its `SessionRegister`. The direct `Stop` branch is deleted with it.

  *What the daemon writes.* Only the daemon's per-node writer opens a file under `sessions/`. It
  still takes the registration lock file with a blocking `lock()`: the only other possible
  holder is another daemon process on the same root in ADR-041's restart window, which RS-13 and
  RS-15 bound (the old daemon stops or is refused), so the wait is bounded by theirs, and a
  `test-knobs` run that holds the file from outside is apparatus. `clear_room_bindings` runs
  inside the same writer: cleanup never contends with a hook, and a registration write never
  waits behind cleanup longer than one rewrite pass (`wake.rs:822-849`, about 1 ms per record).
  Cleanup's other half, the retirement that keeps the node in `blocked_nodes` until it completes
  (`host.rs:4104-4115`), gates activity and the Session opening, never a state (above).

  *The hook's two other writes.* (1) The attaching fallback (`agent_hook.rs:2577-2620`): when
  the cold daemon the hook started has not answered, the hook no longer writes the record; it
  returns `Unregistered::Attaching` as today and the next hook turn presents the registration
  again (`:2578-2581`), to a daemon that now answers. Cost, said plainly: on a cold start the
  kept node learns of that session one hook turn later than today. (2) `SessionEnd` with no
  daemon (`:2710`, `wake::end`): a removal, not a state; it stays, takes the registration lock
  with a bounded wait of 200 ms (an engineering constant), and if it cannot, the record stays
  until the daemon's `forget` removes it when a wake finds the session gone (`wake.rs:1345-1349`,
  the existing owner). Neither write ever carries a state.

  *Readers.* Unchanged: `load` (`wake.rs:1373-1376`), `registered()` (`:1205-1216`; `vox agent
  doctor`, `doctor.rs:851-877`; the pong of `vox room ping`, `ping.rs:71-87`), `Session::idle`
  (`:706-710`). The record is the one place a state lives, as today.

  *Every wait in a hook, bounded and named.* The daemon greeting: `ANSWER_WITHIN`
  (`daemonipc.rs`, `DaemonClient::greet`). `SessionRegister`: `REGISTER_WITHIN` = 10 s
  (`agent_hook.rs:2498`), a wait for the daemon's answer that can include the writer's commit
  behind the registration lock (act 4(a) stages exactly that); past it, `Unregistered::Temporary`,
  printed and emitted (`:2334-2343`), and the next hook turn presents the registration again
  (for OMP the extension retries, `omp-extension.ts:524-526`). The attention request: `wait_ms`
  ≤ `WITHIN` − 1 s (NW-3). `wake::end`'s lock: 200 ms. A hook takes no other lock and opens no
  file of another process; "no hook turn is delayed by a registration lock" means no direct
  file-lock wait in a hook, not that a hook never waits for the daemon's bounded answer.

  *What is lost when the request does not reach the writer, exactly.* A `Stop` whose
  `SessionRegister` is not admitted to the writer (no daemon; no greeting within `ANSWER_WITHIN`;
  no answer within 10 s; a handshake refusal; the daemon stopping before the writer runs) leaves
  the record as the daemon last wrote it, `busy`, until the session's next successful event or
  the silence bound (`agent_busy_idle`, 10 min, `wake.rs:706-710, 1849-1860`). Meanwhile `vox
  agent doctor` and the pong derive `busy` from that stored record (`doctor.rs:851-877` prints
  first seen, last drained and idle/busy; it has no receipt of the failed `Stop`): a stored
  state, not a current observation. Nothing is carried to the next hook call: that call is a
  prompt (busy) or a `SessionEnd` (removal), and either overtakes a carried idle. This loses
  nothing the third review's F4 needed: F4 was a `Stop` dropped by lock contention **while the
  daemon ran**, and with one writer and state-first admission the daemon never refuses a state
  it received. At v0.4.30 a `Stop` with no daemon still wrote idle locally; that was the one
  thing the direct write bought, and it is worth a stale `doctor` line less than a shared file.

  `session registration is busy` MUST NOT be printed after a restart with any number of
  sessions, and no hook MUST ever wait on a registration lock file.
  - *Why*: item 29 (2–18 dropped writes per restart; stale names, idle states and bindings);
    first-review finding 9 (a bounded wait changes how often an update is dropped, not whether);
    second review F10 (revision 2's "enqueue and return" would have handed `session_room` and
    `rename_omp_session` the old record and nobody the missing continuation); third review F4
    (`record_idle` is a hook-process write with no owner on `Busy`: `wake.rs:1380-1393` returns
    `()` and the hook reports success); fourth and fifth reviews (every ordering of a file
    written by several processes opened another interleaving: cleanup parsing it, unmigrated
    publishers, an unlocked rename, a lock inode unlinked under a holder, a stale binding
    replacing current state, a millisecond tie, a hook waiting behind a stopped holder); sixth
    review R6-F1 (a `Stop` arriving while its node sits in `blocked_nodes` for a room's
    retirement was refused before the writer, `host.rs:4636-4644`, `:1885-1891`, where the
    tag's `record_idle` still wrote), R6-F2 (`now_millis` is wall time, `wake.rs:726-730`; a
    backward clock step made revision 6's older-than rule drop a later `Stop`).
  - *Changes*: `wake.rs`: a per-node `RegistrationWriter` (an async mutex over the lock file;
    `store_name` `:930`, `store_room` `:944`, `forget` `:1352`, `store_checked` for `host.rs:1900,
    4910`, `clear_room_bindings` `:822`, `record_omp_state` `:1396` run inside it); the setters
    become `async` and await the commit; the writer applies `state` in arrival order, stamps
    `state_ms` itself, and runs `:1403-1409`'s route check inside; `host.rs:5736-5756`
    (`session_register`) applies a carried state to an existing record before `blocked_nodes`
    (`:1885-1891`, `:4636-4644`), `want`/`grant` and the opening; `daemonipc::SessionRegister`
    gains `state` (control protocol, counted in ADR-041 RS-12's bump); `agent_hook.rs:2239-2243`
    sends `Idle` for `Stop`; `wake::end_checked` (`:1435`) gets the 200 ms bounded wait;
    `registration_write` (`:807-815`) keeps its error line for a real failure only. `host.rs`
    callers (`:1900, :2004, :2296, :2729, :3730, :3754, :4910`) take the writer.
  - *Deleted*: `record_idle` (`wake.rs:1380-1393`) and its calls (`agent_hook.rs:2243, 2254`); the
    direct `Stop` branch (`:2252-2256`); the hook's attaching `store_checked` (`:2612-2620`; the
    `Attaching` return stays); the `try_lock` path for daemon writers; `LockBusy`
    (`host.rs:1804-1817`) for a registration (no hook writes one any more).
  - *Proof*: extend `an_urgent_message_wakes_each_harness_within_seconds_proof.rs::an_urgent_message_to_one_session_wakes_that_session_alone`
    with four acts. Acts 1, 2 and 4(e) run the OMP-shaped sessions under ADR-041 RS-7's host
    shim, because an OMP rename and an OMP state reach the registration only through the bridge
    the extension feeds (`host.rs:765-772`, `omp_mirror.rs:1634-1644`; D15). **Act 1 (the
    burst).** Register 9 OMP-shaped sessions, `vox daemon --restart`, re-register all 9 at once
    with their first state and a rename each (the shim renames each conversation); `vox room
    sessions` lists all 9 with the names sent, `vox agent doctor` shows each with the state
    sent, and the log has no `session registration is busy`. PRODUCT red on v0.4.30 on the
    release asset (KNOWN, RcaTrust `run-s1`: 11–18 lines). **Act 2 (a held lock).** The proof
    process takes the node's registration lock file (`flock`, apparatus) for 1 s while a rename
    and a bridge state change are sent; after it releases, `vox room sessions` shows the name
    and `vox agent doctor` the state within 2 s. Mutant: drop an
    update whose lock wait exceeds 200 ms (revision 1's design); the name is stale; red on the
    `room sessions` assertion (the 1 s hold is what reaches it: act 1's critical sections are
    about 1 ms and force no wait past the bound). **Act 3 (a move under a held lock, and a
    kill).** With the lock held by the apparatus, `vox agent room <new>` for one session: the
    command does not return before the lock is released; after it returns, `vox room sessions`
    shows the session in the new room, and the old room's Session is ended. Then repeat with the
    daemon killed (SIGKILL) while the lock is held: the command reports the daemon stopped, not
    success; after ADR-041's restart the session is in its old room; the command run again moves
    it. Mutant: acknowledge `SessionRegistered` before the commit; the killed run says done while
    the session is in the old room; red. **Act 4 (a Stop's idle is never lost while the daemon
    runs, and state is applied in arrival order).** A Claude-Code-shaped session is registered
    busy; every hook below is driven as the harness drives it: a real event body with
    `hook_event_name` on stdin, through the shipped `vox agent hook` (no new flag). (a) **The
    held lock.** The apparatus holds the registration lock file for 1 s (`flock`) and, during the
    hold, the session's `Stop` hook runs; no further hook event is sent; the hook returns within
    its 10 s bound, and after the hold `vox agent doctor` says `idle` for the session within 2 s
    and a peer's `vox room ping` pong lists it `"idle": true`. PRODUCT red on v0.4.30 on the
    release asset (KNOWN by code: the daemon's `store_checked` meets `try_lock` → `Busy` →
    `LockBusy`, the hook prints `Vox registration temporarily unavailable`, and `record_idle`
    meets the same `try_lock` and returns, `wake.rs:1381-1383`; `doctor` says `busy`; the rig's
    first red is recorded at the proof's first run). The correct program's commit waits out the
    hold inside the writer. **(a′) The hook-side-write inverse.** Mutant: restore `record_idle`'s
    own bounded-lock write in the hook and send `Busy` in the `Stop`'s `SessionRegister`
    (revision 5's shape). Staged at the boundary that write needs: a `test-knobs` hold in the
    hook **after** `daemon.register` has returned (`VOX_TEST_HOOK_AFTER_REGISTER_HOLD_MS`, a
    `test-knob:` line or APPARATUS); the apparatus takes the lock on that line and holds it 1 s;
    the hook resumes. Correct program: idle was committed by the registration; `doctor` says
    `idle`. Mutant: busy was committed, the hook's idle write meets the held lock and gives up;
    `doctor` says `busy`; red. (b) **The next prompt.** A `UserPromptSubmit` hook with no later
    `Stop` or bridge event: `doctor` says `busy` again within 2 s. Mutant: send no state at turn
    start; `doctor` says `idle`; red. (c) **Arrival order.** A `test-knobs` hold in the hook
    before it sends `SessionRegister` (`VOX_TEST_HOOK_REGISTER_HOLD_MS`, a `test-knob:` line or
    APPARATUS) delays a `Stop` while a `UserPromptSubmit` registers first; after the hold
    `doctor` says `idle` (the `Stop` arrived last, as at the tag), and a further
    `UserPromptSubmit` makes it `busy` within 2 s. Mutant: compare the writer's stored
    `state_ms` with a hook-stamped time and drop the older (revision 6's rule); the held `Stop`
    is dropped; `doctor` says `busy` after the hold; red. (d) **A clock step.** Under
    `test-knobs` the **writer's `state_ms` stamp alone** is offset by a file the apparatus can
    change while the daemon runs: `VOX_TEST_STATE_STAMP_STEP_FILE=<path>` names a file the
    registration writer reads at each stamp (an environment variable set at launch cannot be
    changed under a running daemon, re-check F6); the file holds `0` at launch; after a
    `UserPromptSubmit` has committed busy at wall time `m`, the apparatus writes `-3600000` and
    sends a `Stop`; the writer's `test-knob: state stamp offset -3600000 applied` line for that
    `Stop` is the receipt (absent → APPARATUS); the correct writer applies the `Stop` and
    `doctor` says `idle` within 2 s; the apparatus writes `0` again before act 4(f). Why not
    the tag's `VOX_TEST_CLOCK_STEP_MS` (`time.rs:112-136`): it moves the node's whole clock, is
    read once when the clock is made, and `wake::now_millis` (`wake.rs:726-730`) never reads it
    (D4). Mutant: compare the **writer's** freshly stamped `state_ms` for the incoming event
    with the stored one and drop the event when its new stamp is older (a writer-clock
    high-water mark): the `Stop` is stamped `m − 1 h`, dropped, and `doctor` says `busy`; red.
    ((c)'s mutant compares a hook-stamped time; this one the writer's own stamp; the stamp-only
    file drives it, R7-F1.)
    (e) **An old route, with the producer that owns the check.** An OMP-shaped session under
    ADR-041 RS-7's host shim. The shim ends a native turn, so the daemon's bridge produces
    `turn-end` (idle, `omp_mirror.rs:1643-1644`); a `test-knobs` hold inside the daemon between
    the bridge's event and the writer (`VOX_TEST_OMP_STATE_HOLD_MS`, a `test-knob:` line or
    APPARATUS) holds that flip with its captured `expected`. While it is held: the shim begins a
    new native turn (the context is busy); `vox agent room <new>` moves the session (the room
    is part of `same()`, so the captured route no longer matches; the move publishes no state
    itself, `wake.rs:944-957`, but `watch_harness`, `host.rs:2309-2310`, starts a replacement
    bridge, and the real extension sends `event: {type: "state", busy: true}` on its
    subscription, `omp-extension.ts:991-1003`, through `record_omp_state`); the proof waits for
    that new-route **busy** to commit, receipted by a **new** `test-knobs`-only line the writer
    prints when it commits a state for a route, `test-knob: state busy committed for <session>
    route <room>` (the tag logs no successful route-qualified commit: `omp_mirror.rs:597-610`
    accepts the subscription silently and `wake.rs:1396-1422` logs only a failed write;
    `doctor`'s `busy` cannot serve, the stored busy already shows it; re-check R11-6; absent →
    APPARATUS); then the hold is released and no later state event is sent. The
    held old-route idle now arrives **after** the new-route busy (arrival order): the intact
    writer's check rejects it and `doctor` keeps `busy`; mutant: skip the
    `same`/`first_seen_ms`/`mirror` check in the writer; the held idle is applied; `doctor` says
    `idle`; red. Receipts: the log's `test-knob:` release line and the writer's one-line
    `rejected: route changed` (debug) or the applied state, else APPARATUS (R7-F2). (f)
    **Cleanup contention, two rooms.** The node holds rooms A and B; the tested session is bound
    to B. Fixture first, on a normal clock (any clock-step knob of act 4(d) is unset before this
    act): a real `UserPromptSubmit` of the B session is sent, its registration commit awaited,
    and `vox agent doctor` says `busy` with a fresh stamp (missing → APPARATUS). Then the
    apparatus holds the registration lock for 1 s while the node removes room A (the path that
    runs `clear_room_bindings`, `host.rs:4101`); the correct program's cleanup waits inside the
    writer and completes; the log has no `removed room cleanup cannot finish`. A `Stop` of the B
    session sent **during** A's retirement (after the bindings are cleared, before the
    retirement completes; the apparatus delays the completion with
    `VOX_TEST_RETIREMENT_HOLD_MS`, a `test-knob:` line or APPARATUS; no other state event before
    the verdict) leaves `doctor` saying `idle` with no later event (R6-F1). After the retirement
    completes, a `PostToolUse` of the B session with a unique `ref` is sent and read within 5 s
    with `vox room session B <session> --raw --json` (`session_cli.rs:161-196`), each record's
    `body` parsed and the `tool-done` with that `ref` asserted (the rendered Session view skips
    a standalone `tool-done` with no matching tool call, `session_view.rs:532-553`,
    `session_mirror.rs:134-144`; re-check R11-7) (B's binding
    survives; a removed binding reads `room = None` and is skipped by design, `wake.rs:878-885`,
    `session_sink.rs:385-386`, R7-F3). Mutants: (1) run cleanup outside the writer with the old
    `try_lock`; the held lock makes it fail and the log has `removed room cleanup cannot
    finish`: red on that line, PRODUCT (the deterministic oracle; a refused activity is not
    asserted, since a retry can succeed before it arrives). (2) Apply the state after the
    `blocked_nodes` check; the mid-retirement `Stop` is refused and `doctor` still says `busy`
    from the fixture's prompt; red, PRODUCT (the fixture's `busy` is what this mutant can fail
    to change, R8-F1). The reds of acts 4(c)–(f) are knob-staged diagnostic baselines under
    NW-14; act 4(a)'s is the release-asset red.
    Acceptance NW-9-A: zero lines; 9 of 9 current ≤ 2 s after the burst; no acknowledged move
    lost; a `Stop`'s idle never lost once its request reaches the daemon; states applied in
    arrival order.

### 4. A key selection is never lost

- **NW-11. A key package selected and not acknowledged is selected again from its durable cursor
  after any refusal, restart or revision move; a selection refused because governance is not yet
  applied opens the key once it is.** **(changed: second review task table: the generation
  mutant's staging.)** The attempt MUST belong to the work that selected it, not to the room's
  queue, and every not-yet MUST abandon it and park the room's `(room, KeyPackage)` obligation
  on the prerequisite the refusal names (NW-3; none for an at-rest lock, since unlock derives it
  again). A permanent refusal of a package (an inbound rejection, a malformed package) retires
  that package's attempt with one log line and moves the durable cursor past it; the next
  package is selected.
  - *Why*: item 31 (932 refusals, a whole-store rewrite, and a member's key never opened); D-33.
  - *Changes*: `key_package_queue.rs:644-646, 798-806` (no in-memory attempt in the queue; the
    continuation owns it); `package_save.rs:239-262, 320-358` (every not-yet abandons and parks,
    including refreshing at selection; `NotYet` is not logged); `pending_package.rs:709`
    (selection does not mark the room).
  - *Deleted*: `MalformedAtRest("key-package attempt unacknowledged" | "attempt missing" |
    "attempt differs")` as errors (they become debug assertions on the continuation).
  - *Proof*: extend `key_package_proof.rs::a_key_through_the_log_releases_what_a_direct_one_does`.
    **First journey (observation-to-park).** B's room governance fold is held
    (`VOX_TEST_FOLD_HOLD_FILE`; the tag's knob holds every room's fold, `governance.rs:874-883`,
    and stays as it is; the room id is an optional addition, `VOX_TEST_FOLD_HOLD_FILE=<path>`
    unscoped as `a_newcomer_reads_the_whole_history_proof.rs:6662-6668, 6833` use it, or
    `<path>:<room>` for one room; D14); B's package worker selects A's package and
    produces `NotYet(GovernanceFold)`; a second knob, `VOX_TEST_PACKAGE_RESULT_HOLD_FILE`
    (room-scoped), holds that worker **after** it has produced its result and **before** the
    result is posted to the actor (the log says `test-knob: package result held for <room>`,
    else APPARATUS); the apparatus then releases the fold and waits for the fold's release
    receipt: a `test-knobs`-only log line `test-knob: fold ready for <room>` printed where the
    held fold marks the room's governance projection current (the `GovernanceFold(room)` bump
    site, NW-1; the tag has no such observable: `governance.rs:874-883` prints nothing, and
    `vox room roster`, `cli.rs:419`, is served from the cached `open_channels[].members`,
    `ipc.rs:9154-9168`, which reads no fold-ready predicate; re-check F5; the line absent within
    10 s → APPARATUS), then removes the result hold. A reads B's next post within 10 s, `vox status` shows no
    `cannot save`, and the log has no `malformed at-rest artifact` and no `recovered; it can
    save again`. Mutant (NW-3's mutant 2): park unconditionally (neither the predicate check nor
    the `seen` compare); the release happened before the park and nothing releases again; the
    key never opens; red on "within 10 s".
    **Second journey (restart into a held fold).** Restart B into a room whose governance is
    held (`VOX_TEST_FOLD_HOLD_FILE`); after 30 s `vox status` lists the `waiting` line (NW-4);
    release; A's key opens within 10 s with no further join and the line is gone. Mutant: drop
    the `(room, KeyPackage)` resume on `GovernanceFold`; "key opened within 10 s" goes red.
    Red on v0.4.30: both journeys are non-shipping diagnostic baselines (the holds are knobs
    absent from the release asset); the release evidence is the Mac's log (row 31), and E-31 is
    to find a release staging route; until it does, the proofs' reds are the baselines and say
    so. Acceptance NW-11-A: key opened ≤ 10 s after the prerequisite clears; zero store
    recoveries.

### 5. A revision move loses nothing

- **NW-12. A revision move loses no pending save and logs nothing.** **(changed: second review
  task table: observable overlap; committed prefixes.)**
  Every save refused because the policy moved MUST be parked on `ComputerPolicy` under its key
  and finished after the application, without a log line and without `JoinFailed`. Read-mark
  flushes and settlement saves **stay fenced** by the policy publication lease: a flush encrypts
  a signed `ReadRecord` under the sender (`pending_text/read.rs:418-446`) and a settlement
  rotates the sender and appends Presence (`pending_recovery.rs:420-431, 805-882`); both are
  egress. The durable local mark (the marks segment) is written without a lease, as today, and is
  what "the marks remain saved" meant. A metadata publication re-issued after a move re-enters at
  its stage: a component already committed under the old revision is not written again
  (ADR-038 FX-49).
  - *Why*: item 32 (three log sentences per room per revision; key deliveries never re-armed;
    settlement reported as a failed join); first-review finding 8 (revision 1's NW-13 would have
    unfenced them).
  - *Changes*: `read_save.rs:220-233`, `recovery_save.rs:250-295` (no `JoinFailed` for it; ADR-042
    TR-12's `RoomSettlementFailed` is for a real save failure), `package_save.rs:320-358`, the
    metadata publication arms in `metadata_save.rs` (each of the **16** `ComputerPolicySuperseded`
    occurrences at the tag, including `:4199-4200, 4488, 4501, 4507`, is to park under
    `MetadataPublish(component)` or complete; the task that lands this reads each and names its
    durable row, NW-3; D13), and
    `finish_managed_policy` releasing the prerequisite (`policy_save.rs:1542-1556`). `error.rs:533`
    keeps its text for status.
  - *Deleted*: "could not publish its saved read marks: computer policy changed …", "could not
    read its saved key deliveries: computer policy changed …", "a join did not complete — …
    recovery could not complete its retained save: computer policy changed …".
  - *Proof*: extend `nodes_of_one_daemon_proof.rs::paired_ready_nodes_read_both_ways_and_survive_reselection`:
    with one room being read and marked read 20 times by a shipped producer (there is no `vox
    room read --mark`, `cli.rs:1567-1628`; the producers are the TUI reader, `live.rs:3841`, the
    hook's `mark_read`, `agent_hook.rs:3768-3780`, and the FFI, `vox-ffi/src/client.rs:7936`:
    the proof drives the hook's `--omp-prepare` through RS-7's shim, which marks what it shows;
    D2) and a second room settling after a fresh join, `vox node create` a sibling; within 10 s
    of the application the read mark is visible on the post author's node as `vox room read
    <room> --json` on that node, the post selected by its hash, the marker in its `read_by`
    (plain `vox room read` prints no read-by, `room_cli.rs:2368-2415`; footers are JSON and
    requested for the acting node's own messages only, `:1465-1484, 2478-2505`; re-check
    R11-5), and the joined room reads, and the log contains none of the three sentences; and a
    sibling's `vox room post` issued during the application is accepted and visible to the
    other member within 10 s (ADR-043 X043-15, CJ-14's claim proved here). Overlap is observed,
    not assumed, and the refusal each mutant needs is staged on **two schedules, one per
    mutant** (re-check R11-2):
    **Schedule A (policy genuinely not current: the release and log mutants).** The hook's
    marks only commit local marks (`mark: true`, `read_save.rs:142-163`); the log the mutant
    restores runs only for the daemon's own flush (`mark: false`, `:170-215`; `reject_owned_read`
    `:220-233`). A `test-knobs` hold inside `finish_managed_policy`'s turn before the applied
    revision is stored (`VOX_TEST_POLICY_APPLY_HOLD_MS`, room-independent; its `test-knob:` line)
    keeps the node not current for 3 s after `vox node create`; the daemon's own flush runs
    during the hold, is refused `ComputerPolicySuperseded`, and parks on `ComputerPolicy`
    (receipt `test-knob: parked ReadFlush <room>`, `test-knobs` only). Staging receipts (the
    hold's line, the flush's refusal line) absent → APPARATUS; the **park receipt absent while
    the staging receipts are present is PRODUCT** (a dropped park is what the log mutant
    causes). After the hold the retained flush publishes the marks within 10 s, the daemon's
    periodic flush held off for those 10 s by the same knob so no later tick masks a dropped
    park. Mutants: restore `reject_owned_read`'s log and drop the park → the sentence appears
    and the mark is not visible (PRODUCT); drop the `ComputerPolicy` release (NW-3 mutant 1) →
    the mark is not visible within 10 s.
    **Schedule B (stale capture after the policy is current: the predicate-check mutant).**
    `VOX_TEST_MAINTENANCE_AUTHORITY_HOLD_MS` (room-scoped) holds the flush worker between its
    authority capture and `try_acquire_publication` while `vox node create` completes **and
    the node becomes current**; the refusal reaches the actor after that. Correct behaviour is
    **no park**: check (a) finds `policy_current()` true and the flush re-enters at once with
    fresh authority; the mark is visible within 10 s and no `parked ReadFlush` line appears.
    Receipts: the hold's line and the worker's refusal line (absent → APPARATUS). Mutant (NW-3
    mutant 4): skip check (a); the flush parks on a policy already current and the mark is
    never visible; red on the 10 s bound (PRODUCT).
    **The application interval.** The node's application is the whole managed turn, from
    `begin_managed_trust_continuation` (`policy_save.rs:1060`) to `finish_managed_policy`'s
    store of the applied revision (`:1546-1547`) and release (`:1565-1566`), not the terminal
    turn alone; the candidate's two log lines, `node <name>: applying computer trust revision
    <N>` and `node <name>: applied computer trust revision <N>`, sit at those two points, keyed
    by node and revision, and schedule A's park falls between them. The tag has no observable
    of that interval: `vox computer status --json`'s `confirmed` is a signed receipt for the
    current frontier that waits for every roster node (`pairing.rs:180-184, 857-873`) and can
    turn true after this node's own application ended, so it is not a bracket. On v0.4.30 the
    overlap is therefore **not measurable by release-asset polling**; the release red stands on
    the operator's logs, and the rig's own red is a knob-staged diagnostic baseline (NW-14).
    PRODUCT red on v0.4.30: KNOWN from the operator's release logs (the three sentences, three
    machines); the rig's first red is recorded at the proof's first run. Acceptance NW-12-A:
    zero sentences; mark visible ≤ 10 s after the application.
  - *Depends on*: ADR-043 for the proof's revision move only (`vox node create` is a convenient
    move; ADR-043 revision 2 withdrew CJ-14, so no "+2 per create" is a cause here).

- **NW-13. Withdrawn (first-review finding 8).** Revision 1 exempted read marks and settlement
  saves from the revision-move fence on the premise that "neither can disclose anything". The
  premise is false: the flush and the settlement are egress under the shared sender (NW-12).
  Nothing is unfenced; Q2 is withdrawn. The id is kept so the review record and the fix list
  stay readable.

### 6. Proofs

- **NW-14. Every requirement above lands with its proof, and the proofs it makes redundant go.**
  **(changed: lane split; second review closure row 15.)** Each proof drives the shipped `vox`
  binary as a person or harness would, asserts what that person sees, names each red PRODUCT
  (quoting what the product did) or APPARATUS (a hold not achieved, a knob absent, a staging
  precondition unmet), and has the mutant listed with it (ADR-018). Every proof extends an
  existing journey. Each proof states how its v0.4.30 red is obtained **on the release asset**,
  or says that its red is a non-shipping diagnostic baseline because its staging needs a knob
  (NW-11's two journeys; NW-8's acts 1 (the 5 s hold), 2 and 3; NW-9's acts 4(a′), 4(c), 4(d),
  4(e) and 4(f); NW-3's mutant 4; NW-9's acts 1, 2, 3 and 4(a) use `flock` and real hooks and
  are release-asset reds; D10); a
  baseline is reported with the release evidence beside it and is never written as a release
  reproduction. Every proof here is stageable inside the macOS guest or the Linux VM of ADR-045
  (ledger row 32): the holds are knobs and files, the held lock is `flock` on a scratch path,
  the kill is of a scratch daemon. New knobs (`VOX_TEST_STARTUP_HOLD_MS`,
  `VOX_TEST_PUBLICATION_READ_HOLD_MS`, `VOX_TEST_STARTUP_WRITER_ABANDON`,
  `VOX_TEST_PACKAGE_RESULT_HOLD_FILE`, `VOX_TEST_MAINTENANCE_AUTHORITY_HOLD_MS`,
  `VOX_TEST_HOOK_REGISTER_HOLD_MS`, `VOX_TEST_HOOK_AFTER_REGISTER_HOLD_MS` (in the hook),
  `VOX_TEST_STATE_STAMP_STEP_FILE` (a file read at each stamp), `VOX_TEST_OMP_STATE_HOLD_MS`,
  `VOX_TEST_RETIREMENT_HOLD_MS`, `VOX_TEST_POLICY_APPLY_HOLD_MS`, the `test-knob:` receipt
  lines `fold ready for <room>`, `parked ReadFlush <room>`, `parked Construction <room> (join)`,
  `control turn <room> <stage>` and `state busy committed for <session> route <room>`; the
  tag's `VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD` (`construction_save.rs:496-535`) is reused,
  and an optional `:<room>` suffix on the existing
  `VOX_TEST_FOLD_HOLD_FILE`) are compiled only with the cargo feature `test-knobs`; the release
  artifact holds none; each knob prints one `test-knob:` line to the daemon log when it takes
  effect, and each proof that uses one asserts that line and names APPARATUS when it is absent.
  Each extended proof is to get its row in `docs/release/changed-proofs.md`. Assertions that
  match the old refusal texts (NW-4) are to be rewritten to the new texts, not kept beside them.

### Moved requirements

The following ids were revision 2's. The ADRs that now own them renumbered them (ADR-048 TC-*,
ADR-049 LE-*, ADR-050 TJ-*); the NW ids are not reused here, and a citation of "ADR-048 NW-5"
or the like is to be read as the id given below (cross-asks, "Unresolved cross-references").

- **NW-5** (a computer-trust pass that cannot finish in one room; the trust-debt fence;
  Appendix B, the reservation sites; D-35; Q1) → **ADR-048 TC-1–TC-9** (TC-8 the words, TC-5
  and TC-6 the fence).
- **NW-6** (a left room is gone and never reopened), **NW-7** (an ended or left room is always
  deleted; no sync alarm for an ended room), **NW-15** (a person can always leave; Q6) →
  **ADR-049 LE-***.
- **NW-10** (a committed OMP turn is finished exactly once; the turn journal; exit code 79; Q3)
  → **ADR-050 TJ-1–TJ-8, TJ-10**.

What those ADRs need from this one is stated by id under "What sibling ADRs must change".

## Unchanged rulings

- ADR-038 FX-27: nothing is delayed, skipped or spaced by a rule that counts turns or measures
  CPU. NW-3 holds no attempt count; a bound answers a requester or ends an obligation and runs
  nothing.
- ADR-038 FX-40 and FX-45: a parked obligation holds no store, signer, publication lease, room
  lock or worker, and no secret but FX-61a's sealed constructor secret; it resumes only on its
  real prerequisite; tick and status never retry unchanged parked work. NW-3 applies these to
  every not-yet.
- ADR-038 FX-61a: an unadmitted constructor's retained work may own its sealed room key or
  passphrase; NW-3 folds the constructor's wait into the registry with that exception and its
  lifecycle drop intact, and says what daemon death does to it.
- ADR-037 R3 (the irreversible egresses wait on the fold) and R5 (`OwnHistoryBehind` refuses
  every write until resolved). Both stay refusals to a command; a daemon-owned obligation parks
  on `OwnHistory(room)` (NW-1). `OwnHistoryBehind` is already exempt from marking a room unable
  to save.
- ADR-034 §4 SR-1–SR-5 for real store write failures (a full disk): the room is shown unable to
  save, keeps the operating system's text, and recovers by itself (ADR-047 SO-11, SO-12).
- ADR-018: only real use of the shipped binary proves a claim; every proof has a mutant.

## Superseded and amended lines

Main applies these. Quotes are from the tree at `d9a8667ba`; where a physical line starts
mid-sentence the whole sentence is quoted. Amendments that revision 2 listed for ADR-023,
ADR-029 P420-OR-6, ADR-034 HL-2, ADR-035 CT-14, ADR-038 FX-28 and the FX-40 barrier sentence
(`ADR-038:970-971`) belong to ADR-049, ADR-050 and ADR-048 and are stated there.

| ADR and rule | Current text (file:line) | Replacement text |
|---|---|---|
| ADR-034 WT-6 | "Those operations continue as a coalesced idempotent obligation owned by the daemon, recover from the durable registration after daemon restart, retry only the named transient projection-readiness refusals after each bounded attempt, and retain WT-3's permanent failure on the daemon log and the Session's next hook." (`ADR-034-the-app-and-daemon-never-hang-or-hide-a-failure.md:86-90`, one sentence over four lines) | "Those operations continue as a coalesced idempotent obligation owned by the daemon, recover from the durable registration after daemon restart, park each not-yet refusal on its prerequisite and run it again when that prerequisite is released (ADR-040 NW-1, NW-3; no refusal is recognised by its text), and retain WT-3's permanent failure on the daemon log and the Session's next hook." |
| ADR-034 SR-1 | "A room whose store write failed MUST recover by itself once writes succeed again: it MUST retry with backoff and reopen its store, with no restart and no command." (`ADR-034-…:163-164`) | Unchanged, followed by: "Only a store write failure reported by the operating system, a malformed artifact read from disk, or the disk floor (ADR-047 SO-11) marks a room unable to save and starts this recovery. A not-yet refusal, a released reservation and a refused trust or key step never do (ADR-040 NW-2). The marked state is the wait `StoreRecovery(room)`; the recovery's completion releases it (ADR-040 NW-1)." |
| ADR-037 R7 | "Each convergence gate MUST be re-armed by an event its own completion produces, or by the event that produces its missing piece. A periodic MAY run as a backstop; it MUST NOT be the only driver of a gate." (`ADR-037-a-joined-room-converges-without-waiting.md:266-268`) | Unchanged, followed by: "Work that received a not-yet refusal is not a gate's backstop case: it is parked on its prerequisite and only that prerequisite's release runs it again (ADR-040 NW-3; ADR-038 FX-40)." |
| ADR-038 FX-40 (pending work) | "Pending work MUST NOT become terminal failure, fabricated delivery or timer-driven retry." (`ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:986-987`) | Unchanged, followed by: "These rules govern every not-yet refusal in the daemon, not only room and private-drive obligations, through one per-node registry keyed by room and kind and parked on a prerequisite whose generation is checked at the park (ADR-040 NW-1–NW-4)." |
| ADR-038 FX-45 | "The existing weak parked owner and its lifecycle/authority fences MUST be extended rather than duplicated." (`ADR-038-…:1124-1125`) | "The existing weak parked owner and its lifecycle/authority fences MUST be extended rather than duplicated; that extension is ADR-040 NW-3's per-node registry, into which the key-package, rekey, own-key, governance, metadata-publication and construction waits are folded. The private-drive waits and the other preserved owners of ADR-040 NW-1 keep their owner." |
| ADR-038 FX-49 | "Actual supersession and permanent storage or mutation failures MUST retain their refusal and retirement semantics." (`ADR-038-…:1302-1303`) | "Actual supersession and permanent storage or mutation failures MUST retain their refusal and retirement semantics for the room in which they occur; supersession re-issues the work under the new policy at its stage, never from the start (ADR-040 NW-3, NW-12)." (ADR-048 adds the sentence on other rooms.) |
| ADR-038 FX-61b | "Keep permanent and malformed refusals terminal; no timer-driven generic retry or spin." (`ADR-038-…:1556-1557`) | "Keep permanent and malformed refusals terminal; no timer-driven generic retry or spin. A key-package attempt held in memory is not a malformed artifact: any not-yet abandons it and the selection runs again from the durable cursor (ADR-040 NW-11)." |

### What sibling ADRs must change

Stated by requirement id; the sibling owns the words and the design.

- **ADR-048 (trust containment).** Uses NW-1's `NotYet`, NW-2's typed marking and NW-3's
  registry. It fills `TrustDebt(room)`'s row with TC-8's four columns (two release transitions;
  the row above delegates them). Kind `TrustDebt` is stage-exact **between two keyring
  installs** and is rebased at every install (its stage recomputed from the new keyring, never
  replayed; ADR-048 TC-5, TC-6): NW-3's "exact stage of the first is kept" holds within one
  install only, and the install is the one event that may replace a parked stage. A room's
  deletion retires it (NW-3's "room's removal"). The kinds `Rekey` and the consent delivery
  kinds park on `TrustDebt(room)` when a key construction is refused by the debt fence
  (ADR-048 TC-3), as any obligation parks on the prerequisite that refused it. Its withdrawal
  parks on the prerequisite that refused it, never on `ComputerPolicy`. NW-2's typed marking,
  including the `pending_trust.rs:203` call and the abandoned protected commit, lands here
  (NW-2 *Changes*); ADR-048 owns D-35, Appendix B, what the pass does after the release, and
  the first reachable `failed` line (NW-4). Its open-time derivation of the debt must run
  before the room admits any egress (NW-3's durability rule). `OwnKeyWriterDrainRequired` stays
  its pass's preserved owner. Ledger row 82b: ADR-048 TC-4's rule that a policy application
  never waits for a room to be quiet (item 93), ADR-044 RD-10's two lanes and NW-3's "Two
  lanes, one turn each" are one rule; both journeys run their trust change under continuous
  posting, and ADR-048 act 3's extension carries the rekey's one-transaction grant (R12-F2). NW-12 stays in this ADR (ADR-048 X048-5); ADR-043's two
  citations of "ADR-048 NW-12" (`:1496`, `:1692`) are to read "ADR-040 NW-12".
- **ADR-049 (leaving and ending).** `PeerReachable(peer)`, `PolicySave` and
  `SessionCleanup(room)` are in NW-1's table with LE-3's and LE-4's four columns (above), and
  the departure probe's bounded retry on a live connection is a preserved owner (LE-3). The
  kinds `DepartureSign`, `DepartureDelivery(peer)` (sub-keys, `retire_prefix` for an
  any-of-peers wait), `EndedPurge` and `JoinAfterPurge` are NW-3's. Two named bounds end an
  obligation under NW-3 "A bound is not a retry": the hidden copy's two-day bound (the decider,
  ledger row 58) and the ended room's 60 s wind-down (RL-8.2). `SessionCleanupUnavailable` is
  terminal (NW-4's `failed` line). `left-rooms/*` is ADR-049's durable store, read at open
  before any room is opened (NW-3's "not parked here"). A left room's deletion retires every
  obligation of that room (NW-3's "room's removal").
- **ADR-050 (turn journal).** The hook's decoding of `AttentionRefusal::NotYet` and the
  `wait_ms` it sends are **this ADR's** (NW-1 *Changes*, NW-3 *Changes*: the request has two
  ends and both are here; D11). ADR-050 keeps them as a contract and owns what happens after
  the decision is journaled: a `NotYet` after `commit` is waited for inside the hook's deadline
  and then becomes its exit code 79; a `NotYet` before the envelope is NW-8's case and is
  retried by the extension as today. ADR-050 revision 8 (ledger row 79): after a terminal
  provider error on a step that carried room news the conversation stops using Vox; there is
  no pending state and nothing is "delivered after an error"; no act of this ADR stages or
  names such a state (NW-9's `Stop` and prompt hooks carry no room news). The journal is its
  own durable store (NW-3's "not parked here"). ADR-050 r8 already says so (its `:1025-1026`:
  "ADR-040 owns both ends of the hook's `wait_ms` request"); it need not change.
- **ADR-041 RS-7, RS-12.** RS-7 owns the one display rule this ADR needs stated once: a typed
  `NotYet` whose prerequisite is the daemon itself (`PublicationGate` with a `Startup` writer,
  `ComputerPolicy` while a node starts) is not displayed to the person while the watcher
  reports `daemon: starting` (ADR-041 X041-8; NW-8's hook retry is the extension's as today).
  The typed attention answer, `Fault::NotYet` and `SessionRegister`'s `state` are
  control-protocol changes counted in RS-12's one bump to 12; exit code 79 and `--omp-finish`
  are hook surface, not IPC (the cross-ADR ledger's row 15 is corrected to say so).
- **ADR-042 TR-11, TR-23, Appendix C.** No change to TR-23's two forms; NW-4 adopts them. The
  `waiting` block omits obligations parked on `StoreRecovery(room)` of a room whose `cannot
  save` line is printed (text only; JSON carries them). Appendix C's row for the typed refusals
  now reads "ADR-040 NW-1's closed set" with no number (ADR-042 X040-5): the set is twelve
  today (this ADR eight; ADR-048 one; ADR-049 three) and a sibling may add a row under NW-1's
  four-column rule.
- **ADR-043, the `Applying here` rows.** "<what it waits for, in ADR-040's words>" are NW-1's
  prerequisite words; the trust-debt sentence is ADR-048's.
- **ADR-044 RD-7, RD-10.** RD-10 owns the room's two lanes (ledger row 82b): control and
  authored, FIFO within each, alternating one turn each when both have ready work, a turn one
  native transaction, control at the head of its lane waiting for at most the transaction in
  flight plus one authored write (row 82c), an authored write for its lane plus at most one
  control transaction per write, a
  child transaction in its parent's turn. Every `RoomWrite(room)` park of this ADR is a place
  in one of RD-10's lanes (ledger row 9 widened); NW-3 "Two lanes, one turn each" and ADR-048
  TC-4 state the same rule. RD-7 (revision 14, ledger row 74): one save, one trip; there is no
  flusher, token or settlement rule left for this ADR to re-arm; `StoreRecovered(room)`
  releases the room's `StoreRecovery` wait and nothing else of RD-7's.
- **ADR-046 SY-24.** Its failed-cleanup retry is an obligation of its own kind parked on
  `StoreRecovery(room)` and retired when the room instance is replaced or the node locks, as
  SY-24 says; ADR-046 must release `OwnHistory(room)` at actual authoritative completion, not on
  a refresh that leaves `own_behind` set; it owns Appendix A rows 30, 31, 35, 36, 50, 52 and 53.
- **ADR-047 SO-11, SO-12.** Its `StoreRecovered(room)` event, instance-qualified, raised in the
  actor after the room's re-save on both floor recovery without a reopen and recovery through a
  reopen, is exactly the release of `StoreRecovery(room)`; the bump precedes every consumer's
  notification; an event for a replaced instance releases nothing. The floor refusal is one of
  NW-2's three typed causes. The recovery itself keeps its own storage owner and never parks on
  the event it produces.

## Rejected alternatives

- **A periodic "retry everything" pass.** ADR-038 FX-27, FX-40 and FX-44 forbid it, and it
  amplifies load under exactly the contention that causes the refusals ("Addressing Cascading
  Failures", SRE book ch. 22: retry only retriable errors, at one level, never without a budget;
  separate retriable from non-retriable; use clear response codes,
  https://sre.google/sre-book/addressing-cascading-failures/). Parking on a prerequisite is the
  form of retry that does not amplify; `NotYet` is the clear code.
- **An edge-keyed vector registry (revision 1).** It could lose a release that happened between
  an off-actor observation and the park, and it held one copy per producer tick. The generation
  check and the `(room, kind)` key are the smallest additions that close both.
- **Carrying `seen` through the reply to the client (considered for revision 3).** It would
  put an actor-internal token on the control protocol and in the hook, and a client that
  sampled a fresh generation after decoding would reopen the lost wakeup. Parking before the
  reply keeps the token where it was produced and costs one deadline field on the request.
- **Bumping the gate's generation on `Writer` drop only (revision 2).** Misses the abandoned
  waiting writer (F13). Bumping inside the gate at every transition that opens reader admission
  is one rule and cannot miss a site.
- **Making refusals rarer by widening locks.** Item 28's cause is a lock held too widely.
- **Keeping the strings as the contract.** They drifted once already (D-33) and nobody noticed
  for a release.
- **Item 28, a startup writer that yields to readers (revision 1).** Starved by two Ready nodes'
  overlapping reads (first-review finding 13). Ordinary writer preference with typed waiting is
  simpler and bounded. **Readers never refused while a writer waits, for every writer.** The
  same starvation for a policy change. Source: Go's `sync.RWMutex` (readers wait behind a
  pending writer; nobody returns that to the user as an error).
- **Item 29, a bounded wait only (revision 1).** It changes how often an update is dropped, not
  whether (finding 9). **Enqueue-and-return for every setter (revision 2).** Hands the next step
  the old record (F10). **A per-session state file written by every process that observes a
  state (revisions 4 and 5).** Each ordering of it (a bounded lock, an unlocked rename, a
  state-only lock with timestamps and bindings) opened another interleaving: cleanup parsing
  it, publishers left on the old path, a reversed rename, a lock inode unlinked under a holder,
  a stale binding replacing current state, a millisecond tie, a hook waiting behind a stopped
  holder (fourth review R4-F1–R4-F3, fifth review R5-F1–R5-F5). The daemon already writes every
  other registration update and the `Stop` hook already talks to it before writing idle, so the
  boring design was there: one writer, the state said in the request. What it costs is one
  `doctor` line while no daemon runs (NW-9). One writer per node with awaited commits
  for the three result-bearing setters is
  the price of never losing an update. Source: SQLite's busy handler
  (https://sqlite.org/c3ref/busy_timeout.html) for the hook's bounded wait.
- **Item 31, persist the attempt.** Its only safe use after a restart is "abandon", so it is
  strictly worse than not keeping it. **Keep the check but stop poisoning** still drops the
  selection. Source: Kafka consumer offsets (the committed cursor is the only state).
- **Item 32, unfence read marks and settlement (revision 1's NW-13).** They are egress under the
  shared sender (finding 8). Source: fencing tokens (Kleppmann, "How to do distributed
  locking", 2016, https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html):
  the stale write is rejected and the client re-issues it under the new token.
- **One universal rule with no preserved owners.** Capacity, the own-key drain and RD-10's
  queue are waits on things that are not rooms, policies or gates; forcing them into the
  registry by resemblance would give each a wrong release (the second review's objection to
  routing capacity to `RoomWrite`). A short table of preserved owners is the smaller change.

## Implementation order and related work

NW-1 to NW-4 are one mechanism, but they cannot be accepted alone: their proofs are the
journeys of NW-8, NW-11 and NW-12, and D-33's mutant needs NW-11 (task cut D9). So each part of
NW-1–NW-4 lands with the first fix whose host can prove it, in this order:

1. NW-9 (independent; its own journey; it MAY land first).
2. NW-8, with NW-1's `NotYet`, `Prerequisite`, the generations and the gate's bump, NW-3's
   registry, park-or-run, coalescing and bounds, the attention and Session kinds, and the
   `PublicationGate`/`ComputerPolicy`/`Projection` producers (NW-8's three acts prove them).
3. NW-11, with NW-1's `GovernanceFold` producers and D-33, NW-2 and D-34, NW-3's `KeyPackage`
   and `Rekey` folds, NW-4's `waiting` block and the command forms (NW-11's two journeys and
   NW-4's proof host them).
4. NW-12, with NW-1's `ComputerPolicySuperseded` and `Saved::Unavailable` producers, NW-3's
   `ReadFlush`, `Settlement`, `Governance`, `MetadataPublish`, `Construction` and own-key folds
   and the durability classes (NW-12's journey proves them).
5. NW-1's `StoreRecovery`, `OwnHistory` and `Settled` rows with their releasing events
   (ADR-047, ADR-046, ADR-048 land the releases; the rows ship when the first consumer does).
6. The amendments above and the `changed-proofs.md` rows.

ADR-048, ADR-049 and ADR-050 build on step 2's mechanism.

Other lanes in v0.4.31: ADR-048 (trust containment: `TrustDebt`, Appendix B, the `failed`
line's first case); ADR-049 (leaving and ending: `PeerReachable`, the departure record, the
purge); ADR-050 (the turn journal: `wait_ms` in the hook, exit code 79); ADR-041 (restart: item
41's competing daemon lengthens NW-8's window; RS-12 counts the IPC change); ADR-042 (status:
the layout of NW-4's lines and the sentence style of every refusal); ADR-043 (adding, replacing
and removing a computer: the revision moves this ADR parks on); ADR-044 (the daemon stays
responsive: the read leases behind NW-8's 8–23 s, E-28; RD-10's queue place); ADR-045 (the
fleet release gate: restarts with many sessions and trust changes under load are its conditions;
J5(g) names `StoreRecovery(room)`); ADR-046 (sync: `OwnHistory`'s release; SY-24's retry on
`StoreRecovery`; inventory rows 30, 31, 35, 36, 50, 52, 53); ADR-047 (storage: the recovery that
releases `StoreRecovery(room)`). Appendix A rows owned by those lanes are listed there and not
redesigned here.

### Experiments

No experiment was run for revisions 3–5: every finding in this lane was settled by reading the
tag, and `/tmp/sync-measure.lock` was present throughout (two measuring agents share this Mac).
Revision 2's receipts that this lane cites: RcaTrust `run-s1` (release binary: items 28, 29),
the operator's logs (items 31, 32), rig26 (item 32, D-34), RcaSchedStall (the stall that needs
`StoreRecovery(room)`). **Every receipt under `/tmp` or `/private/tmp` was lost in the reboot of
this Mac on 2026-11-13** (the reboot cleared both); each figure stands as recorded in its named
report (`rca-RcaTrust`, `plan-D`, `rca-RcaSchedStall`, the operator's log excerpts quoted in
"What the operator saw") and is to be re-run as the fleet baseline (ADR-045).

Still needed. Neither changes a requirement; each decides whether a proof's red is a release
reproduction or a baseline, and until it is run the proof says "baseline":

- **E-28: why the Mac's second node waits 8–23 s.** Two remembered nodes on one scratch daemon,
  the first holding a 2 GB room mid saved-history preparation; the instrumented binary of
  `/opt/vox-worktrees/rca-RcaTrust`; `vox daemon --restart`. What the result does, one statement
  (D7, the same as NW-8's *Depends on*): if the wait matches the first node's preparation read
  leases, NW-8 removes the refusal and ADR-044 RD-8's lease, already unconditional, bounds the
  wait; ADR-044 carries nothing conditional on E-28. If the wait is about 0.3 s, the cause is
  elsewhere on the Mac and E-28 says where to look next. Read-only on the Mac: at his next
  restart, the gap between the two `is Ready` lines against the first `preparing saved history`
  line.
- **E-31: which refusal tore the Mac's key-package chain at 15:25:37Z.** The apparatus binary
  `/tmp/rca-RcaPreparing/bin/vox-rca` was lost in the reboot of this Mac on 2026-11-13 (ledger
  row 64: the figure stands as recorded in `rca-RcaPreparing`; to be re-run as the fleet
  baseline); its source survives, uncommitted at `8d71ab337`, in
  `/opt/vox-worktrees/rca-RcaPreparing`, and is rebuilt from there (D8). The run:
  (`pkg-stage`/`pkg-inject` trace lines) on a topology like the Mac's (one anchor, two peers
  re-keying while the policy re-applies at start, `vox node create` 1 s after Ready); find a
  selection with no acknowledgement and the refusal after it (`ComputerPolicySuperseded` at
  open/install, or an inbound `NotAccepted`). It settles whether NW-11's first journey has a
  release staging route; until then its red is a diagnostic baseline.

## Consequences

### Positive

- A refusal that means "later" is finished by whoever produced it, no wakeup is lost at any
  boundary, parked work is bounded by rooms, kinds and a fixed number of open replies, and a
  person can see what is waiting and on what within half a minute.
- Restarts stop costing the agents their context and their registrations; a sibling's startup
  refuses nothing for longer than the policy settling step.
- "Cannot save" means a disk or a damaged file again, and store recovery runs only for those;
  the stalled node of items 85/87 has a named wait to park its cleanup on.

### Negative

- A result-bearing registration setter returns only after its commit (about 1 ms, longer under
  cleanup); a `Stop` while no daemon answers leaves the session shown busy until its next event
  or the silence bound; on a cold daemon start the kept node learns of a new session one hook
  turn later.
- A fifth distinct stage-exact operation on one held key, and a seventeenth requester of a
  requested wait, are told to run the command again rather than kept.
- A hook's attention request may be held by the daemon for up to its `wait_ms` instead of
  failing at once; the extension's watchdog bound is unchanged.
- The daemon↔hook control protocol gains a typed refusal (one protocol-number bump, shared with
  ADR-041's and ADR-050's changes); several proofs change their expected texts.

### Neutral

- No room-log, peer-wire or node-store format change in this ADR.
- The registry is in memory; what it holds is derived again at open before the room admits
  egress, re-issued by its requester, or said plainly not to survive (a construction attempt
  that accepted no durable fact).

## Review record

Each finding of both independent reviews in this lane, its classification after checking the
`v0.4.30` tree, and the requirement that now answers it. Findings outside this lane are listed
with the ADR that answers them.

### First review (sixteen findings)

| # | Finding | Classification | Answered by |
|---|---|---|---|
| 1, 2, 8, 16 (barrier) | the trust-debt fence, its repair, settlement and receipts as egress, FX-40's barrier | CONFIRMED in revision 2 | ADR-048 (8's consequence for this lane: NW-13 withdrawn, NW-12 keeps both fenced) |
| 3, 4, 5 | the turn journal's contents, replay idempotence, the exit code's consumer | CONFIRMED in revision 2 | ADR-050 |
| 6 | Parking can lose a release between observation and park | CONFIRMED (revision 1 had no generation or re-check rule; the existing code at `publication_gate.rs:60-70`, `bounded_sync.rs:2047-2051`, `maintenance_save.rs:842-846` enables before checking) | NW-1 `seen`, NW-3's park-or-run contract, and in revision 3 the boundary rule (`seen` never leaves the actor; park before reply); NW-3 mutant 2 |
| 7 | A finish-side discard cannot delete the room | CONFIRMED in revision 2 | ADR-049 |
| 9 | A bounded lock wait still drops the update on expiry | CONFIRMED (`wake.rs:807-815, 930-945, 1352-1355, 1396-1399`) | NW-9: one serialized writer per node with a blocking lock; result-bearing setters await their commit (revision 3, F10); the hook's write is retained by the extension |
| 10 | The five-edge set is incomplete; `OwnHistoryBehind` had no edge | CONFIRMED (`continuation.rs:806-846`; `sessions.rs:166-176`; ADR-037 R5) | NW-1: a closed set with predicates and release transitions, `Projection`, `OwnHistory` and (revision 3) `StoreRecovery` added, two prerequisites reserved for siblings, and a table of preserved owners |
| 11 | `maintenance_save.rs:793-804` is the Computer gate, not a room write; the attention transport carries strings | CONFIRMED (`computer.rs:2845-2847`; `transport.rs:63-99`; `sessions.rs:243-268`) | NW-1: classification by the refusing gate; typed `AttentionRefusal`; the three re-wordings of `Saved::Unavailable` go with it; the IPC change counted in ADR-041 RS-12 |
| 12 | An unrestricted vector grows with every tick | CONFIRMED (`read_save.rs:170-215` revisits rooms each tick) | NW-3: `(room, kind)` keys, merge rules, producer admission checks the registry, and (revision 3) a bounded reply set; NW-3-B |
| 13 | A startup writer that yields to readers is starved | CONFIRMED (`publication_gate.rs:95-104`: a writer needs `readers == 0`) | NW-8: writer preference kept; readers park or are held; act 2 stages overlapping leases so mutant 2 is reachable |
| 14 | Proof placement conflicts with ADR-041 RS-7; several mutants unreachable; internal assertions; knob reds mislabelled | CONFIRMED (in this lane: NW-11's `MalformedAtRest` arm could not recreate a dangling attempt; knob reds were called release reds) | NW-11's dropped-resume mutant and the result-hold staging; NW-14's baseline rule; the OMP placement is ADR-050's, the NW-5/NW-7 mutants ADR-048's and ADR-049's |
| 15 | `run-s3` is instrumented; the needed reds were called nonblocking | CONFIRMED (in this lane: "none blocks the design" stood over E-28 and E-31) | "Experiments" says what each unrun experiment decides and that the affected proofs say "baseline" until it is run; E-30 is ADR-050's |
| 16 (FX-61a) | FX-61a's secret exception unacknowledged | CONFIRMED (`construction_save.rs:64-70, 617-626`) | Terms, "Unchanged rulings", FX-45's amendment, and NW-3's restart paragraph (what daemon death does to the attempt) |

### Second review (closure table and findings F1–F18)

| Item | Finding | Classification | Answered by |
|---|---|---|---|
| closure 6 | `seen` is absent from `Fault::NotYet` and `AttentionRefusal::NotYet`; the consuming routes are off-actor tasks across a oneshot; sampling a fresh generation after decoding restores the bug; the release inventory misses F13 | CONFIRMED (`actor.rs:5711-5733` oneshot, `:8629-8632` reply; `transport.rs:63-99`; `node_tasks.rs:157-173`; `host.rs:2084-2217`) | NW-3 "Where `seen` lives": park before reply, requester's bound, re-issue outside the actor; NW-1's third column restated as "the state change bumps" |
| closure 9 / **F10** | `store_name`/`store_room` results drive the next step; a volatile enqueue acknowledges a move the daemon may not have written | CONFIRMED (`host.rs:2296-2323`: `before` → end old Session → `registration` → `open_session` → `SessionRegistered`; `:3730-3743`: `reg` → `open_registered`; `wake.rs:930-956`) | NW-9: result-bearing setters await their commit and acknowledge after it; best-effort events coalesced and their crash loss said; acts 2 and 3 (held lock, kill between request and commit) |
| closure 10 / registry "not a closed classification" | `HistoryCapacity(BytePressure)` waits on a byte pool; `OwnKeyWriterDrainRequired` is a physical retirement; F11's slots; the unclassified strings | CONFIRMED (`error.rs:20-22`, `key_body_scan.rs:440-453`; `error.rs:527-529`, `policy_save.rs:1148-1152`; Appendix A's tail) | NW-1's preserved-owner table; `StoreRecovery(room)` added; the nine strings classified in Appendix A rows 47–55 (three are re-wordings of row 3, two are `RoomWrite`, one a durable capacity mark, one a bounded worker wait, one a wire refusal, one permanent); F11's slots are ADR-049's to add or preserve under NW-1's rule |
| closure 11 | Preserve the generation when ownership is handed back | CONFIRMED | NW-3: the token is never handed back; the actor parks before it replies |
| closure 12 / registry "bounded entries are not bounded retained state" | The appended reply list is unbounded; different person operations must not merge by component | CONFIRMED (revision 2 line 308) | NW-3: replies as a set keyed by requester, closed replies pruned, at most 16 live, the 17th told and held nothing; stage-exact person operations queue, never merge; NW-3-B's resident-set reading |
| closure 13 | The proof must stage overlapping readers to kill the yielding-writer mutant | CONFIRMED | NW-8 act 2 (held leases, two parallel loops, no observed gap or APPARATUS) |
| closure 14 (in lane) | NW-11's generation mutant needs a worker that actually returned `NotYet` before the fold release; NW-9's burst does not reach its mutant; NW-12 needs observable overlap | CONFIRMED | NW-11's `VOX_TEST_PACKAGE_RESULT_HOLD_FILE` after the result and before the actor; NW-9 act 2's 1 s held lock; NW-12's bracketed-read rule |
| closure 15 (in lane) | "none blocks the design" at revision 2 line 1212 | CONFIRMED | removed; "Experiments" states what each unrun experiment decides |
| **F13** | `blocking_write_until` and `WaitingWriter::drop` remove the last waiting writer without a `Writer`; a parked reader is never released | CONFIRMED (`publication_gate.rs:125-133, 175-180`; `wake` at `:40-43`) | NW-1 (`PublicationGate` released at every transition that opens reader admission, inside the gate), NW-3 (the rule: the state change bumps), NW-8 act 3 and NW-3 mutant 3 |
| registry "restart" | A construction's in-memory `Work` is not a durable restart source; metadata stage-exact work and `AttentionSelect` need their open-time derivation named | CONFIRMED (`construction_save.rs:64-70, 617-625`) | NW-3 "Durability and restart": three classes; daemon death ends an unadmitted attempt and the person is told by his command; the attention ledger and the component row named; a component with no row is cancelled with its reply told |
| registry "a seven-day drop is not delivery" | expiry and board withdrawal must remain explicit owners although NW-3 forbids time-based retries | CONFIRMED as a rule for this ADR | NW-3 "A bound is not a retry"; the departure itself is ADR-049's |
| task table NW-1 | preserve `seen` at ownership boundaries; enumerate all release transitions; "no text classifier" is a review condition | CONFIRMED | NW-3 boundaries; NW-1's third column plus the bump rule; NW-1-A labelled a review condition |
| task table NW-2 | the proof must stage a real not-yet on the room it checks; dropping unreachable literals is not a mutant | CONFIRMED | NW-2's proof is NW-11's first journey with `poison()` accepting `NotYet` and the selection stage's poison kept |
| task table NW-3, NW-4 | bounded replies, stage-exact replacement, cross-boundary ownership and restart; the status wait must not be the only indicator of a permanent failure | CONFIRMED | NW-3 as above; NW-4's `failed` form (TR-23) and its first case in ADR-048 |
| task table NW-8 | where the 5 s hold sits; a separate waiting-writer staging | CONFIRMED | NW-8 acts 1 and 2 |
| task table NW-9 | complete result-bearing caller migration; hold the real lock past the bound | CONFIRMED | NW-9 (five `host.rs` callers named), act 2 |
| task table NW-11, NW-12 | stage the observation-to-park boundary; observable overlap; committed prefixes preserved | CONFIRMED | NW-11's first journey; NW-12's bracketed read and its FX-49 sentence |
| task table NW-13, NW-14 | correctly withdrawn; declared recipes are not measured reds | CONFIRMED | NW-13 kept withdrawn; NW-14 and "Experiments" |
| cross-ADR note | hook flags and exit codes are not daemon IPC; the typed attention answer is, and follows RS-12's protocol-number rule | CONFIRMED (`ADR-041:1008-1036, 1400-1402`) | NW-1's *Changes*; "What sibling ADRs must change", ADR-041; the ledger's row 15 corrected in `adr-040-revision.md` |
| ADR-044 ledger row 9 | bound the `RoomWrite` edge used by Drive admission and attention commits moved off the actor | CONFIRMED (ADR-044 RD-10) | NW-1's preserved-owner table: RD-10's queue place |
| ADR-046 SY-24 / ledger row 17 | name the wait a failed cleanup parks on; release it on store recovery | CONFIRMED (`rca-RcaSchedStall`; `bounded_sync.rs:1854-1860`, `runtime.rs:1814-1848`) | NW-1 `StoreRecovery(room)`; the ADR-047 contract to raise its release |
| F1–F4 | the trust-debt fence (service-share append, debts before current authority, local repair work, the OwnHistory↔TrustDebt cycle) | out of this lane | ADR-048 |
| F5–F8, F11, F12, F14–F16 | the departure protocol, quiescing, acknowledgement, storage admission, purge ownership, the retirement ledger, delivery ownership, the expiry promise, end propagation | out of this lane (the registry offers sub-keys and `retire_prefix` for F14, and NW-1's rule for F11) | ADR-049 |
| F9, F17, F18 | claim commands in the journal's writer protocol, the fresh-delivery oracle, the obsolete-receipt notice | out of this lane | ADR-050 |

### Third review (findings F1–F4)

| # | Finding | Classification | Answered by |
|---|---|---|---|
| F1 | A worker refused for an authority captured before the node became current parks on `ComputerPolicy` with the new generation; the predicate is already true and nothing releases again | CONFIRMED (`maintenance_save.rs:677-683` captures `authority` on the actor, `:793-803` and `:821-822` check the captured one in the worker; `metadata_save.rs:2429-2463` the same split; `computer.rs:2845-2849` validates the captured revision after taking the reader; `policy_save.rs:1542-1547` can run between) | NW-3's park checks the predicate on the actor before comparing generations (check (a)); "A stale token is not a false predicate"; a re-run takes `computer_authority()` fresh and re-enters at its stage; mutant 4 with `VOX_TEST_MAINTENANCE_AUTHORITY_HOLD_MS` |
| F2 | Distinct stage-exact operations queue without bound behind one key; the reply bound counts senders, not payloads | CONFIRMED as a rule (revision 3's "queues behind the first" had no bound); in this ADR's kinds no key admits several person operations (`PublicationAfter::{Created, Joined, Opened}`, `metadata_save.rs:1215-1229`, one per room; `Construction` one per room; a post or rename meeting a move is not retained, row 19) | NW-3: at most 4 queued operations per key, counted until completion whatever the reply did, the fifth told "run it again" and nothing kept; NW-3-C and mutant 5 carried by the first sibling kind that admits several; a review condition on `Registry` until then |
| F3 | The 17th requester of a requested obligation is told Vox finishes the work, but the obligation is retired when its last waiting requester leaves | CONFIRMED (Terms "requested obligation"; NW-3's retirement rule) | NW-3: overflow answered by class, owned → retained form, requested → not-retained form carrying `retained: false` in `AttentionRefusal::NotYet`/`Fault::NotYet`; each consumer's re-issue route named (`open_registered` after its deadline, the extension's `scheduleRetry`; the attention loop never overflows) |
| F4 | `record_idle` is a hook-process whole-record write that returns `()` on `Busy`; a `Stop` under a held lock loses the last idle state with no owner; the daemon's own `store_checked` callers would inherit the hook's bounded path | CONFIRMED (`agent_hook.rs:2243, 2254`; `wake.rs:1380-1393`; `host.rs:1900, 4910`; `agent_hook.rs:2612` the attaching fallback with `Unregistered::Attaching`) | NW-9 (revision 6): the daemon is the one writer; the `Stop` hook says `Idle` in the `SessionRegister` it already sends and `record_idle` is deleted; daemon `store_checked` callers run inside the writer; the hook's attaching write is deleted (next turn presents again); act 4(a) |
| closure rows marked partly: the whole park rule (F1), bounds (F2, F3), the broader registration promise (F4), metadata's per-site durable source | CONFIRMED; the metadata table stays the landing task's deliverable before task acceptance (NW-3, NW-12), as the review says: partly closed, not a loss finding | as above; NW-12's *Changes* and NW-3's durability paragraph |
| Settled's other bump sites (`pending_recovery.rs:1027, 1072-1073`, `ChannelState::settle`) | CONFIRMED | NW-1's `Settled(room)` row lists them |
| ADR-047's event name | the release is `StoreRecovered(room)`, instance-qualified, on both floor recovery and reopen (Main, 2026-11-13) | NW-1's `StoreRecovery(room)` row and the ADR-047 contract consume exactly that event |

### Fourth review (R4-F1–R4-F3 and two proof recipes)

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R4-F1 | A state file inside `sessions/` is parsed by `clear_room_bindings` as a `Session`, fails, and leaves the node's activity refused | CONFIRMED (`wake.rs:822-849` skips only `NOTICES_DIR` and `.tmp`; `host.rs:4101-4122` inserts the node into `blocked_nodes` until cleanup succeeds) | closed by the fifth review for revision 5's placement; moot in revision 6: there is no state file; cleanup runs inside the writer and never meets a hook (act 4(f)) |
| R4-F2 | The turn-start busy publisher (`from_env_untmuxed`, persisted by `store_checked`) and the `registered()` readers (`doctor`, the pong) were not migrated; `registered()` never calls `load` | CONFIRMED (`wake.rs:1007-1008, 1034-1035, 1061-1062, 1085-1086`; `:894-899`; `:1205-1216`; `doctor.rs:851-877`; `ping.rs:71-87`) | closed by the fifth review; in revision 6 the state stays in the record, every reader is unchanged, and the publishers are the hook's `SessionRegister` (`state`) and the bridge's `record_omp_state`, both applied by the writer |
| R4-F3 | An unlocked atomic rename is a last-replacement register, not newest-wins; the OMP route fence needs more than `first_seen_ms` | CONFIRMED (`agent_hook.rs:2243, 2254` are separate processes; `wake.rs:1403-1409`; `:871-876`) | partly closed by the fifth review for revision 5; closed in revision 6 by one writer, and in revision 7 the order is the writer's arrival order (no clock compared, R6-F2); the route check (`:1403-1409`) runs in the writer; acts 4(c), 4(d), 4(e) |
| proof: NW-3 mutant 2 masked by check (a) | CONFIRMED (the fold is complete when the actor parks, so (a) re-runs the work; a re-hold would be released again later) | mutant 2 removes both checks for that ordering; mutant 4 stays the independent case for (a); NW-11's first journey says the same (closed by the fifth review) |
| proof: NW-9 act 4's urgent-announcement oracle does not measure idle; the mirrored `Stop` registers first | CONFIRMED (`wake::tend`, `:2067-2116`, has no caller at the tag; the only readers of idle are `doctor.rs:877` and `ping.rs:87`; `agent_hook.rs:2233-2243`) | `vox agent doctor` and the pong are the oracles (closed by the fifth review); the route is corrected under the fifth review's R5-F5 |
| rulings as applied (30 s, 200 ms, `StoreRecovered`, rows 34/37, VM placement) | closed by the review; unchanged | — |

### Fifth review (R5-F1–R5-F5) and the one-writer decision

| # | Finding | Classification | Answered by |
|---|---|---|---|
| why several processes write the state at all | Main's question: name the single owner the code already has | CONFIRMED by source: the daemon writes every registration update but three hook writes (`record_idle` `agent_hook.rs:2243, 2254`; the attaching `store_checked` `:2612`; `wake::end` `:2710`); the `Stop` hook already sends `SessionRegister` first (`:2239-2243`, bound `REGISTER_WITHIN` 10 s `:2498`) with a record that says `BUSY`; the direct `Stop` branch (`:2252-2256`) is unreachable from a shipped input (`parse_input` `:94-98`; `mirrors` `session_mirror.rs:335-345`) | NW-9 "Why one writer": the daemon is the one writer; `SessionRegister` carries `state` and `observed_ms`; `record_idle`, the direct branch and the attaching write are deleted; `wake::end` stays (a removal, bounded 200 ms, `forget` the owner). What is lost, exactly: a `Stop` while no daemon answers shows busy until the next event or the 10 min silence bound; a cold start learns of a session one turn later. Nothing F4 needed is lost (F4 was contention while the daemon ran) |
| R5-F1 | the state lock's inode is unlinked under a live holder by `forget`/`end` | CONFIRMED for revision 5's file (an unlinked locked inode keeps its lock; `wake.rs:1352-1365, 1458-1474` join nothing) | moot: no state lock exists; the one writer unlinks a record only inside itself |
| R5-F2 | a stale-binding native publisher replaces a valid current-route state | CONFIRMED for revision 5's file (the native publisher's binding was read outside the publication lock) | moot across processes; the route check (`wake.rs:1403-1409`) runs inside the writer against the record it rewrites; act 4(e) |
| R5-F3 | equal millisecond timestamps discard a real busy→idle flip | CONFIRMED (revision 5's "equal keeps what is written" contradicted NW-9-A; `omp_mirror.rs:1634-1646` has adjacent producers) | closed in revision 6 by applying equal stamps in arrival order; in revision 7 no stamp is compared at all (R6-F2): arrival order, which is the tag's own order |
| R5-F4 | a native hook's no-timeout `lock()` can wait behind a stopped holder; the hook runs on a current-thread runtime with no enclosing timeout (`cli.rs:3450-3476`) | CONFIRMED for revision 5's file | moot: a hook takes no state lock; its only waits are `REGISTER_WITHIN` (10 s), `wait_ms` (NW-3) and `wake::end`'s 200 ms, each named in NW-9 "Every wait in a hook" |
| R5-F5 | `vox agent hook --event Stop` does not exist (`AgentHookArgs`, `cli.rs:1323-1368`); a body without `hook_event_name` is a prompt (`parse_input` `:94-98`); a `Stop` body mirrors and registers first | CONFIRMED | act 4(a) drives the shipped hook with a real `Stop` body on stdin; with one writer the daemon's commit waits out the held lock and no handshake inside the hook is needed; the mutant restores revision 5's hook-side write; NW-9's "direct Stop has no daemon exchange" justification is withdrawn (the branch is unreachable and deleted) |

### Sixth review (R6-F1–R6-F4)

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R6-F1 | A running daemon refuses `SessionRegister` for a node in `blocked_nodes` (a room's retirement pending) before the writer sees the carried idle; at the tag `record_idle` still wrote in that window | CONFIRMED (`host.rs:4084-4115` keeps the node blocked past `clear_room_bindings` until `retire_session_room` completes; `want` refuses at `:4636-4644`, the attaching path at `:1885-1891`; `agent_hook.rs:2239-2244` ran `record_idle` after a refused register) | NW-9: a carried state is applied to an existing record **first** in `session_register` (`:5736-5756`), before `blocked_nodes`, attach waits, `want`/`grant` and the opening; a refusal of the rest does not undo it; act 4(f)'s mid-retirement `Stop` with `VOX_TEST_RETIREMENT_HOLD_MS` and mutant (2); act 4(f)'s cleanup inverse restaged with explicit lock contention, `removed room cleanup cannot finish` and a refused `SessionAdmission` as the oracles |
| R6-F2 | `observed_ms` is `SystemTime` (`wake.rs:726-730`); a backward clock step makes revision 6's older-than rule drop a later `Stop`; equal stamps cannot support "the chronologically newer always wins" | CONFIRMED | NW-9: order is the writer's arrival order and nothing else, the order the tag already has (`record_idle` and `store_checked` wrote unconditionally in lock order); no stamp travels; `state_ms` is stamped by the writer for display and the silence bound only; what two racing hooks mean is stated (idle until the next event, as at the tag; needs an overlapping harness); what a clock step can do is stated and bounded (the silence bound shifts by the step, as at the tag); acts 4(c) and 4(d) with the older-than rule as the mutant; "the newer observation always shown" withdrawn from NW-9-A |
| R6-F3 | act 4(a)'s mutant waits out the pre-request hold inside the writer, then `record_idle` succeeds; the tag-red explanation wrongly said registration succeeds under a held lock (`store_checked` uses `try_lock`) | CONFIRMED | act 4(a′): a `test-knobs` hold after `daemon.register` returns (`VOX_TEST_HOOK_AFTER_REGISTER_HOLD_MS`); the apparatus takes the lock on that line; the mutant's idle write fails its bounded lock, the correct program already committed idle; the tag red restated (registration refused `LockBusy`, then `record_idle` refused) |
| R6-F4 | act 4(e) drove a native `Stop` and a bare `vox agent room`; the route check belongs to `record_omp_state`, `store_checked` keeps the stored room (`wake.rs:878-885`), and the move publishes no state (`wake.rs:944-957`, `host.rs:2296-2323`) | CONFIRMED | act 4(e): the OMP bridge's own `turn-end` under RS-7's host shim, held inside the daemon before the writer (`VOX_TEST_OMP_STATE_HOLD_MS`) with its captured `expected`, the session moved during the hold, no masking state; the intact writer keeps `busy`, the mutant skips `same`/`first_seen_ms`/`mirror` and applies idle |
| latency/loss assessment | 10 s is the request-phase bound (greeting `ANSWER_WITHIN` separate); "no hook turn delayed by a registration lock" must mean no direct file-lock wait; answered refusals belong to the unadmitted category; `doctor` prints a derived state, not an observation age; Appendix A row 25 was stale | CONFIRMED | NW-9 "Every wait in a hook" names the greeting, the request bound and the writer's commit behind it; "What is lost when the request does not reach the writer" lists the unadmitted cases; `doctor`'s line described as derived from the stored record; Appendix A row 25 rewritten |

### Seventh review (R7-F1–R7-F3) and the sibling asks

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R7-F1 | act 4(d)'s knob steps the daemon's new `state_ms` stamp, but the stated inverse compared a hook-stamped time, so the mutant accepts idle in both programs | CONFIRMED | act 4(d)'s mutant is a writer-clock high-water mark (drop an event whose fresh writer stamp is older than the stored one); the daemon-only step drives it; act 4(c) keeps the hook-time inverse |
| R7-F2 | the move starts a replacement bridge (`watch_harness`, `host.rs:2309-2310`; `omp_mirror.rs:253-335`) and the real extension sends `state` on subscription (`omp-extension.ts:991-1003`), so a new-route idle masks the held old-route idle | CONFIRMED | act 4(e): a new native turn is begun while the old flip is held, the session is moved, the replacement's **busy** is observed to commit (receipt or APPARATUS), then the hold is released with no later event; arrival order makes the intact check decisive; receipts named |
| R7-F3 | the cleanup journey removed the tested session's own room, so `room = None` (`wake.rs:822-849, 878-885`) and the Session sink skips its activity (`session_sink.rs:385-386`); "red on both" relied on timing | CONFIRMED | act 4(f) with two rooms (retire A, the session bound to B); the activity oracle after retirement completes; the cleanup inverse's red is the deterministic `removed room cleanup cannot finish` line only |
| X048-2 | NW-2 named only `release_rooms`/`Pending::retire`; both ADRs said the `pending_trust.rs:203` change "lands with" the other | CONFIRMED (`pending_trust.rs:202-204` calls `poison(error)` for any error) | NW-2 *Changes* lands the typed decision at every site it governs, `:203` and the abandoned protected commit included; ADR-048 lands nothing of the marking (sibling bullet) |
| X048-3 | `TrustDebt` rebased at every keyring install; rekey/consent kinds park on `TrustDebt(room)` | CONFIRMED (ADR-048 TC-5, TC-6; `:436, 503, 508`) | NW-3's kinds list and the ADR-048 bullet: stage-exact between two installs, rebased at each, never replayed; `Rekey` and the consent kinds park on the debt when the fence refuses a key construction |
| X049-1 | `PolicySave`, `SessionCleanup(room)` rows; the departure probe's bounded retry as a preserved owner; the count | CONFIRMED (ADR-049 LE-3 `:397-402`, LE-4 `:466-475`; `ports.rs:262-284`) | NW-1's table: `PeerReachable(peer)` with LE-3's columns, `PolicySave` and `SessionCleanup(room)` with LE-4's; the preserved-owner row; the count is twelve and ADR-042's row cites the set without a number |
| X049-2 | kinds `DepartureSign`, `JoinAfterPurge`; the 60 s wind-down as a named bound; "7-day expiry" | CONFIRMED (ledger row 58: two days) | NW-3's kinds list; the ADR-049 bullet names the two-day bound and the 60 s wind-down; the 7-day sentence is gone |
| X043-15 | NW-12's proof lacked the sibling-post assertion; ADR-043 cites "ADR-048 NW-12" | CONFIRMED (`ADR-043:1496, 1692`) | NW-12's proof asserts a sibling's post during the application; NW-12 stays here and ADR-043's two citations are to read "ADR-040 NW-12" |
| X047-11 | `cannot save: the store is recovering` during SO-12's drain is an NW-2 edge | CONFIRMED | NW-2: the same `StoreRecovery(room)` wait, shown with that line during the drain and reopen |
| X041-8 | a typed `NotYet` on the daemon's own startup is not displayed while the watcher says `daemon: starting` | CONFIRMED (RS-7 owns the display) | the ADR-041 bullet states the rule once, in RS-7's words |
| X040-11 | ADR-044 does not carry the E-28 condition | CONFIRMED | ASKER DROPS: the condition is this ADR's (NW-8 *Depends on*); ADR-044 RD-8's lease bounds the wait unconditionally |
| amendment quotes | each row must quote the whole existing sentence at `d9a8667ba` | CONFIRMED (`adr-amendment-quotes.md`: all seven FOUND; WT-6's row quoted a fragment) | WT-6's row now quotes the whole sentence (`ADR-034:86-90`) and replaces it whole; the other six already quote whole sentences |

### Eighth review (R8-F1, R8-F2)

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R8-F1 | act 4(f)'s state-first mutant (2) only suppresses the `Stop`'s idle; with the B session already idle from act 4(d) it cannot turn the act red | CONFIRMED (act 4(d) ends with `doctor` idle; 4(e) uses the OMP session; nothing re-busied B before the retirement) | act 4(f): a real `UserPromptSubmit` of the B session, its commit awaited and `doctor` `busy` with a fresh stamp asserted (else APPARATUS), on a normal clock, before the retirement hold; mutant (2) now leaves the fixture's `busy`, PRODUCT; acts 4(c)–(f) labelled knob-staged baselines, 4(a) the release red |
| R8-F2 | NW-2 said `pending_trust.rs:203` "marks the room for any error"; `poison()` returns without marking for its exclusions (`channel.rs:5218-5230`: `OwnHistoryBehind`, `RoomNotSynced`, cleanup pending, the refreshing predicates) | CONFIRMED | NW-2 *Changes*: "calls `poison(error)` for every error of the trust component's commit; whether it marks is decided by `poison()`'s existing exclusions"; the call-site migration and ADR-040's ownership unchanged |

### Ninth review and the task cut's ADR defects (revision 10)

The ninth review (`adr-040-sol-review-9`) passed with no finding. Revision 10 answers the task
cut's fifteen defects (`v0431-tasks-ADR-040`, "Uncertain"; frozen r8 lines) and the open
cross-ask rows; each retraced on `v0.4.30`.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| D1 | `Fault::NotYet` has no carrier to the clients; the app classifies by text | CONFIRMED (`api.rs:1527-1530, 1778, 2028-2041`; `live.rs:3745, 3853`; `vox-ffi/src/client.rs:2256`; `NodeModel.swift:1403-1418`; `FirstRunProof.swift:9568`) | NW-1 *Changes* "How it reaches the four clients, once": `Frame::Error`'s `Failed(NotYet)` first line plus one JSON line, decoded by `from_explanation` for CLI, TUI and FFI; the app's text list replaced by the typed value; NW-4's proof list adds `FirstRunProof.swift:9568` |
| D2 | `vox room read --mark` does not exist; the tag prints no application start/end line | CONFIRMED (`cli.rs:1567-1628`; `host/computer.rs:177, 234, 259`) | NW-12 proof: the marks come from the hook's `mark_read` through RS-7's shim (TUI `live.rs:3841` and FFI `client.rs:7936` named as the other producers); the candidate adds `applying`/`applied computer trust revision <N>` lines around `finish_managed_policy`; on v0.4.30 the bracket is `vox computer status --json` `confirmed` polled at 100 ms |
| D3 | "the fold's completion line" does not exist | CONFIRMED (`governance.rs:874-883` prints nothing) | NW-11 first journey: the observable is `vox room members` on B listing A (the fold admits the member); not within 10 s → APPARATUS |
| D4 | `VOX_TEST_CLOCK_STEP_MS` exists, moves the whole clock, is read once; `wake::now_millis` ignores it | CONFIRMED (`time.rs:112-136`; `wake.rs:726-730`) | act 4(d) uses a new `VOX_TEST_STATE_STAMP_STEP_MS` read by the writer at each stamp; the old knob named as unusable and removed from NW-14's new-knob list; the writer-clock mutant (R7-F1) keeps its red |
| D5 | NW-3-B has no host | CONFIRMED | NW-3-B hosted by NW-11's second journey, the flush provoked once a second by the hook's `mark_read` through the shim |
| D6 | NW-3-C and mutant 5 are carried by no sibling | CONFIRMED (no kind in ADR-048/049 admits several person operations on one key) | NW-3: the bound is a review condition on `Registry` with no journey; the first ADR that adds such a kind carries NW-3-C and mutant 5 |
| D7 | E-28 and NW-8 *Depends on* disagree on ADR-044 | CONFIRMED | one statement in both: ADR-044 RD-8's lease is unconditional; NW-8 removes the refusal; ADR-044 carries nothing conditional |
| D8 | E-31's apparatus path is lost | CONFIRMED (`/tmp` cleared) | E-31 names the loss in ledger row 64's words and the surviving source `/opt/vox-worktrees/rca-RcaPreparing` (uncommitted, at `8d71ab337`) |
| D9 | step 1 (NW-1–NW-4) cannot be accepted alone | CONFIRMED (their proofs are NW-8's, NW-11's and NW-12's journeys) | "Implementation order" rewritten: each part of NW-1–NW-4 lands with the first fix whose host proves it (NW-9; NW-8; NW-11; NW-12; the sibling-released rows; the amendments) |
| D10 | NW-14's baseline list names the wrong acts | CONFIRMED (NW-9's acts 2 and 3 use `flock`, a release-asset staging) | the list now names NW-8 act 1's hold, acts 2 and 3; NW-9 4(a′), 4(c)–(f); NW-3 mutant 4; and says NW-9's 1, 2, 3, 4(a) are release-asset reds |
| D11 | the hook's `wait_ms` placed on the other ADR by each | CONFIRMED (ADR-050 r6 `:695`, `:1086` say it is ADR-040's) | NW-1 and NW-3 *Changes* and the ADR-050 bullet: this ADR owns both ends; ADR-050 keeps it as a contract and need not change |
| D12 | folded waits deleted with no proof each still finishes | CONFIRMED | NW-3 *Deleted* names, for each fold, the existing act that proves its work finishes; review is never the only check |
| D13 | "14 sites": the tag has 16 | CONFIRMED (`grep -c` at the tag: 16) | NW-12 *Changes* says 16 occurrences |
| D14 | a room-scoped fold hold would break existing proofs | CONFIRMED (`a_newcomer_reads_the_whole_history_proof.rs:6662-6668, 6833` use the unscoped form) | NW-11 and NW-14: the unscoped form stays; the room is an optional `:<room>` suffix |
| D15 | an OMP rename reaches the registration only through the bridge | CONFIRMED (`host.rs:765-772`) | NW-9: acts 1, 2 and 4(e) run under RS-7's host shim |
| cross-asks | "keep their numbers in the ADRs that now own them" is false; `:275` says Appendix C for a row in Appendix D | CONFIRMED (ADR-048 TC-*, ADR-049 LE-*, ADR-050 TJ-*; ADR-042 App. D) | "Moved requirements" gives the new ids and the reading rule; NW-2 *Deleted* says Appendix D. Rows already carried in r8 (X048-2, X048-3, X049-1, X049-2, X043-15, X047-11, X041-8, X040-11, X040-5) are STALE; the ledger-15 and "ADR-048 NW-5" contradictions are the siblings' and the ledger's to correct |

### Re-check of revision 10 (revision 11)

| # | Finding | Classification | Answered by |
|---|---|---|---|
| F1 | the plain CLI never calls `from_explanation` (`client.rs:686-693` returns the reason as `AppError::Usage`, `app.rs:60-64` prints it); the join path's `fault_named` (`tunnel_cli.rs:990-994`) keeps the first line only | CONFIRMED | NW-1 *Changes*: `unexpected` runs `from_explanation` and renders NW-4's sentence from the typed fields; `fault_named` deleted, the join path uses the one decoder; the JSON line is read nowhere else |
| F2 | the app's list has seven texts; "The room changed while reading…" is built by the FFI itself (`under_fence!` `client.rs:47-66`, `room_page_read` `:2905-2921`) and retried by Swift at `:2358-2364` and `:1506-1520`; a daemon-frame decoder cannot carry it | CONFIRMED | NW-1 *Changes*: the FFI returns a typed `VoxError::ReadInvalidated` for its own invalidation; both Swift consumers retry on that case and on `NotYet { retained: false }`; no text matched; Appendix A row 34's reader re-read survives |
| F3 | the two candidate lines sat around the terminal turn only (`policy_save.rs:1422-1515` precede it); `confirmed` is a signed frontier receipt waiting for every roster node (`pairing.rs:180-184, 857-873`), not this node's application interval | CONFIRMED | NW-12 proof: the lines sit at `begin_managed_trust_continuation` (`:1060`) and `finish_managed_policy`'s store/release (`:1546-1547`, `:1565-1566`), keyed by node and revision; the tag has no interval observable, so the v0.4.30 overlap is stated as not measurable by release-asset polling and the rig red is a knob-staged baseline |
| F4 | hook marks create `mark: true` continuations (`read_save.rs:142-163`); the restored log runs only for the daemon's `mark: false` flush (`:170-215`, `:220-233`); nothing staged that flush's refusal | CONFIRMED | NW-12 proof: the flush is staged with NW-3 mutant 4's authority hold across the move, its park receipted (`test-knob: parked ReadFlush <room>`), the periodic flush held off so no later tick masks a dropped park; the mutant is tied to that staged continuation |
| F5 | `vox room members` is not a command (`vox room roster`, `cli.rs:419`); the roster is served from cached `open_channels[].members` (`ipc.rs:9154-9168`) and proves no fold completion | CONFIRMED | NW-11 first journey: a `test-knobs`-only `test-knob: fold ready for <room>` line at the `GovernanceFold(room)` bump site is the receipt awaited before the result hold is removed; absent → APPARATUS |
| F6 | an environment variable read at each stamp cannot change under a running daemon | CONFIRMED | act 4(d): `VOX_TEST_STATE_STAMP_STEP_FILE`, a file the writer reads at each stamp (`0` at launch, `-3600000` after the busy commit, `0` before 4(f)); the applied-offset line is the receipt |
| F7 | NW-3-B counted one entry per room while the host already holds a `KeyPackage` entry; NW-3 keys by `(room, Kind)` | CONFIRMED | NW-3-B counts per kind: one `ReadFlush` entry beside the host's one `KeyPackage` entry; the flush's first refusal is a receipt |
| F8 | `a_slow_joiner_gets_in_or_is_told_why_proof.rs:278-399` tests grind floors, never computer trust; `active_and_removed_computers_keep_local_manual_trust` (`:4348-4354`) has no room and reads no rotated post | CONFIRMED | NW-3 *Deleted*: `Construction` is proved by NW-12's journey extended (a join held at admission across the move, `VOX_TEST_HOLD_JOIN_ADMISSION_FILE`, dropped-resume mutant); `Rekey` by ADR-048's act 3 extended; each fold lands only with its act |
| ADR-044 RD-7 r14 (ledger row 74) | one flush per ruled save; no flusher, tokens or settlement rule | applied | NW-1 *Changes* (`StoreRecovery` producers), NW-2 (the paste sentence), the ADR-044 bullet; "flush" elsewhere in this ADR means the read-mark flush (`flush_reads`), untouched |
| ADR-050 r8 (ledger row 79) | after a terminal provider error the conversation stops using Vox; no pending state | applied | the ADR-050 bullet; no act here stages such a state; `wait_ms` stays this ADR's at both ends |

### Second re-check (revision 12)

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R11-1 | the deleted Swift list also retried daemon-made refusals: `the room is refreshing saved history; retry` (`channel/history.rs:266-290`), `preparing selected history; retry` (`:632-639`), forwarded verbatim (`read_resource.rs:395-424`, `ipc.rs:8188-8224`, FFI `answered`) | CONFIRMED | NW-1 *Changes*: every case typed before the list goes: governance → `GovernanceFold`; saved-history/selected-history/retention refresh → `Projection(room)` (producers added); the two "room changed" spellings → `ReadInvalidated` (reader re-read, row 34); both Swift sites retry on the typed cases |
| R11-2 | one schedule mixed a stale capture after the policy was current (no park is correct) with the park the release/log mutants need; a mutation-caused missing park was labelled APPARATUS | CONFIRMED | NW-12 proof: schedule A (`VOX_TEST_POLICY_APPLY_HOLD_MS` keeps the node not current; the flush parks, receipted; staging receipts absent → APPARATUS, park receipt absent with staging present → PRODUCT) for the release and log mutants; schedule B (stale capture after current; correct = no park) for mutant 4; the 10 s no-periodic-repair control kept |
| R11-3 | a join held at admission precedes authority capture (`actor.rs:14544-14578`, `:11657-11676`, `construction_save.rs:447-478`); the tag parks `Work::Create` only and aborts a superseded `Work::Join` (`:598-636`) | CONFIRMED | NW-3 *Deleted*: the join-abort consumer migrates to the registry (`Construction` carries Create and Join); the act holds an existing joiner J with the tag's `VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD` (`:496-535`) after authority capture, receipts the retention, keeps the dropped-resume mutant and the 10 s bound |
| R11-4 | W's negative read proves exclusion, not the Rekey's completion; `rekeys.rs:87-105` refuses on `pending_posts` before selecting owed recipients; a dropped resume stays green | CONFIRMED | under row 82 the busy refusal is gone: the Rekey takes a `RoomWrite` queue place; ADR-048 act 3's extension stages an owed recipient M (act 2c's pattern) under continuous posting, receipts the queue place, requires M to decrypt a post committed after the rotation within 10 s; mutant: drop the `Rekey` resume; W's read stays ADR-048's separate assertion |
| R11-5 | plain `vox room read` prints no read-by (`room_cli.rs:2368-2415`); `read_by` is in JSON footers of the author's own messages (`:1465-1484, 2478-2505`) | CONFIRMED | NW-12 proof and Appendix B: `vox room read <room> --json` on the author's node, the post by hash, the marker in `read_by` |
| R11-6 | the tag logs no successful route-qualified state commit (`omp_mirror.rs:597-610` silent; `wake.rs:1396-1422` logs failure only) | CONFIRMED | act 4(e): a new `test-knobs` receipt `state busy committed for <session> route <room>`, awaited before the held idle is released; marked new in Appendix B |
| R11-7 | the rendered Session view skips a standalone `tool-done` (`session_view.rs:532-553`; `session_mirror.rs:134-144`) | CONFIRMED | act 4(f): `vox room session B <session> --raw --json` (`session_cli.rs:161-196`), `body` parsed, the `tool-done` asserted by unique `ref` |
| ledger row 82 (the decider: no quiet room) | three tag sites refuse control work on a pending post (`pending_text.rs:283-291`, `sparse_history.rs:1426-1434`, `rekeys.rs:87-91`); a `RoomWrite` park released only by `release_pending_text` would race new posts for ever | CONFIRMED | NW-1's `RoomWrite(room)` row and NW-3 "No wait for a quiet room": a queue place in ADR-044 RD-10's FIFO, bounded by the owners ahead, never by the end of posting; the same rule as ADR-048 TC-4 (item 93); proof under continuous posting in ADR-048 act 3's extension and NW-12's journey; mutant: restore the `pending_posts` refusal with a tick retry |

### Re-check 3 (revision 13: the two P1s; P2s owed at build time)

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R12-F1 | revision 12's single mixed FIFO put control behind every queued post and conflicted with row 82a; RD-10's text enrolled node policy at every room's tail (`ADR-044:1004-1031`) | CONFIRMED | ledger row 82b, stated in NW-1's `RoomWrite` row, NW-3 "Two lanes, one turn each" and the ADR-044 bullet: two lanes, alternation one turn each, a turn one native transaction, the two bounds, nothing refused or deferred; proofs restated with the alternation mutant (control back to back while a post is queued); ADR-044 RD-10 and ADR-048 TC-4 named as the same rule |
| R12-F2 | the whole `(room, Rekey)` sweep held one place while its Packages child reserved the same write (`rekeys.rs:287`, `:531-552`; `pending_package.rs:487`, released `:668`): the child would wait on its parent, or the sweep would monopolize the room | CONFIRMED | NW-3 *Deleted* (`Rekey` fold): a transferable grant for the next bounded native transaction, consumed by the child under the parent's identity in the parent's turn, released at that child's commit and installation before the next recipient; continuations (`RekeyAfter::Consent`/`Packages`, `:827-851`) kept between turns; a dependency wait blocks no lane |
| R12-F3–R12-F6 (P2) | — | recorded in `v0431-owed-p2` (ledger row 83) | fixed at build time in the owning tasks' acceptance; not edited here |

The second review's final questions 1 (Q1), 2 (Q3), 5 (Q6) and 6 (the storage boundary) belong
to ADR-048, ADR-050 and ADR-049; the third review's two questions are Q4 and Q5 below.

## The decider's answers (2026-11-13)

- **Q4 (NW-4), answered (ledger row 41).** The `waiting` block in `vox status` lists work
  parked longer than 30 s. NW-4 is written so.
- **Q5 (NW-9), not asked.** The hook's attaching write waits for the lock up to 200 ms; Main
  took it as an engineering constant (the lock is held for about 1 ms, the daemon's own writers
  no longer contend, the next hook turn owns the overrun) and lists it for him. Neither value
  drops an update.
- **Rulings of the same day that touch this ADR's rows.** Row 35 (trust containment is per
  room): `TrustDebt(room)` and `Settled(room)` stay per-room prerequisites. Rows 34, 58 and 61
  (a left room's copy is hidden until one member verifies the leaving, 2 days at most, then
  erased; a rejoin is a fresh join; a left or ended room's rows and key are deleted at once and
  the freed pages are cleared at the next store rewrite): Appendix A row 28 says so; no
  prerequisite of this ADR carries the 7-day figure. Row 36 (an undecided OMP turn stays
  permanently uncertain): no text here depends on it. Row 37 (a join is admitted by one member;
  an unanswered seat question never fails it): `SeatNotAgreed` ceases to exist (ADR-046);
  Appendix A row 30 is updated. Row 27 (`offline, last seen <dur> ago`): no line of this ADR
  prints reachability. Row 32 (every proof stageable in the macOS guest or the Linux VM): NW-14
  states it.

Q2 of revision 1 (unfence read marks and settlement) is withdrawn: its premise was false
(first-review finding 8), so it was never the decider's choice. Q1, Q3 and Q6 moved with their
requirements and are answered there (rows 35, 36, 34).

## Appendix A: every "not yet" a caller can receive in v0.4.30

From the group-D plan's §0.6. Marks: ✔ = read in the code by the plan's author; ○ = from a scout
inventory, not re-read. Rows 1, 3, 5, 8, 9, 10, 12, 14, 16, 22, 24–29, 40, 44 and 47–55 were read
at the tag for this ADR. "Owner" is who must finish the work under NW-3, with the prerequisite
of NW-1; "lane" names the ADR that owns rows outside this one.

| # | Refusal (text / variant) | Produced at | Received by | Retried in v0.4.30? | Owner under NW-3 | Item |
|---|---|---|---|---|---|---|
| 1 | "room publication is busy; retry this operation" / `Fault::RoomChangePending` | `pending_text.rs:289` `reserve_pending_write`; `local_history.rs:127` | CLI `vox room post` via `actor.rs:5347-5351` | yes: 100 ms loop ✔ | daemon, `RoomWrite` | — |
| 2 | same | same | `preparation_save.rs:621-627` `wait_on("current computer trust")` | yes, misnamed (says computer trust for a busy room) ✔ | daemon, `RoomWrite` | 28 (wording) |
| 3 | same text, **the Computer publication gate** (`try_acquire_publication` none, `computer.rs:2845-2847`) | `maintenance_save.rs:793-804` → `Saved::Unavailable`; `post_save.rs:547-558`; `metadata_save.rs:1843` | every maintenance continuation via `outcome()` `policy_save.rs:165-169`; posts | partly: governance, packages at selection, key scan, consent redelivery ✔; read flush and settlement by tick ✔; metadata, leave, consent reply: no ○ | daemon, `PublicationGate` | 28, 31, 32 |
| 4 | "a previous change to this room is still being applied; this request made no change" (`api.rs:1851-1852`) | `fault_of` | person at the CLI | no: told to retry ○ | CLI says the prerequisite; nothing kept | — |
| 5 | "room governance is refreshing; try again when it is ready" (`view::REFRESHING`) / `Fault::GovernanceRefreshing` | `governance/channel.rs:714`, `view.rs:377,1055` | actor projection, governance work, key prune, policy turn (`policy_save.rs:1370-1379`), consent selection, packages at open/install (`package_save.rs:337-346`) | yes, each its own re-arm ✔ | daemon, `GovernanceFold(room)` | 31 |
| 6 | same | same | packages at selection (`package_save.rs:320-346`: only busy is re-armed at selection) | **no** ✔ | daemon, `GovernanceFold` | **31** |
| 7 | same | same | `sessions.rs:166-176` `opening_refreshing` → `host.rs:2176-2189` | yes: 200 ms loop while registered ✔ | daemon (`open_registered`), `GovernanceFold` / `Projection`, key `SessionOpen` | 28 |
| 8 | **bare** "room governance is refreshing" | `read_resource.rs:95,101` (history read view, `history.rs:446`) | every history, attention and read caller; `poison()`, `fault_of`, `expected_refusal`, `opening_refreshing` do not recognise it ✔ | **no**; it marks the room at the key-package selection stage (`pending_package.rs:674-677`) ✔ | daemon, `GovernanceFold` | **D-33** |
| 9 | "attention waits for current computer trust" (lease refused: `publication_gate.rs:49-58` while a writer waits) | `actor.rs:23351` | attention loop `node_tasks.rs:157-173` | no: logs and drops the room's selection until the next 2 s pass ✔ | daemon, `PublicationGate`, key `AttentionSelect` (the loop is woken) | **28** |
| 10 | same | same | `sessions.rs:243-268` `open_when_member` ← `host.rs:2084-2218` | **no**: not in the loop's predicate; stale notice injected later (`host.rs:2208-2212`) ✔ | daemon (`open_registered`), key `SessionOpen`, parked with its reply | **28** |
| 11 | same | same | hook `--omp-prepare` Resolve (`agent_hook.rs:408-418`) | extension `scheduleRetry` (`omp-extension.ts:253-256`) ✔ | daemon holds the request up to `wait_ms` (key `AttentionResolve`), then the extension | 28 |
| 12 | same | same | hook commit-time Resolve (`check_omp_opening`, `agent_hook.rs:234-244` ← `:3601`) | **no**: the conversation dies ✔ | hook (turn journal) | **30**, lane ADR-050 |
| 13 | same (trust really behind: `policy_current` false, `actor.rs:23292,23325,23338`) | same | rows 9–12 | as 9–12 | daemon, `ComputerPolicy` | 26, 28 |
| 14 | `ComputerPolicySuperseded` "computer policy changed while its prior application was pending" / `Fault::ComputerPolicy` | `maintenance_save.rs:821,883`; `computer.rs:2849`; `metadata_save.rs` (14 sites); `consent_release.rs:152`; `trust_save.rs:265,285` | read flush `read_save.rs:220-233` | tick re-runs; logs "could not publish its saved read marks … the marks remain saved" ✔ | daemon, `ComputerPolicy`, key `ReadFlush`, silent | **32** |
| 15 | same | same | settlement `recovery_save.rs:250-295` | tick re-runs; logs `JoinFailed` ✔ | daemon, `ComputerPolicy`, key `Settlement`, silent | **32** |
| 16 | same | same | packages `After::Logged` `package_save.rs:320-358` | **no** re-arm; logs "could not read its saved key deliveries" ✔ | daemon, `ComputerPolicy`, key `KeyPackage` | **31, 32** |
| 17 | same | same | governance `governance_save.rs:223-240` | yes (`again` / `wake_room`) ✔ | daemon, key `Governance` | — |
| 18 | same | same | metadata publication `metadata_save.rs:4199-4200,4488,4501,4507`; `construction_save.rs:464,608-632` | **no**: terminal for the publication ○ | daemon, `ComputerPolicy`, keys `MetadataPublish` (durable row per component to be named by the landing task, NW-3), `Construction` | 32 |
| 19 | same | same | CLI (`vox room post` during a pass): "computer trust changed while this command was being applied; review the current policy and retry" | no: person told ✔ (rig26) | CLI says it; nothing kept | 26 |
| 20 | "current computer trust is unavailable" | `actor/computer.rs:161` | governance, recovery (`defer_own_key_policy`) | yes ✔ | daemon | — |
| 21 | "computer policy is refreshing; retry" | `actor.rs:26100` `saved_history_query` | file-offers reader and saved-history queries | logs; next tick ✔ | daemon, `ComputerPolicy` | 32 |
| 22 | "computer trust is pending application on this node" | `actor.rs:24500-24502` (corrected from `:24515`) | drive input | no ○ | daemon, `ComputerPolicy` | — |
| 23 | "Drive authority or Session opening changed; nothing was sent" | `actor.rs:23364` | drive sender (OMP private Drive) | no (P420-OD-2: refusal shown) ✔ | extension shows it; the lease case is to become `NotYet(PublicationGate)` held by the daemon; the admission's own wait is ADR-044 RD-10's | 28 |
| 24 | "session registration is busy" (`RegistrationStoreError::Busy`, `wake.rs:785-788`) | `registration_write` `wake.rs:807-815` | `store_name` (`:930`), `store_room` (`:944`), `forget` (`:1352`), `record_omp_state` (`:1396`) | **no**: write dropped ✔ | the per-node writer (NW-9); result-bearing callers await the commit | **29** |
| 25 | same → `RegistrationRetryable{LockBusy}` (`host.rs:1804-1817`) | hook `--attention-register` (`registration_only`: route only, no state) | extension `scheduleRetry` (`omp-extension.ts:524-526`) ✔ | the daemon's writer (no `LockBusy` for a registration any more); the extension's retry stays for the daemon's temporary refusals (`Attaching`, `Stopping`, a timeout); a native `Stop`'s idle is owned by the writer once its request arrives (NW-9) | **29** |
| 26 | "trust withdrawal is incomplete; reopen this room" / `Fault::TrustRemovalIncomplete` | `policy_save.rs:172-182` `release_rooms(poison = true)` | every write to every reserved room; `recover_storage` | **no**: marked until restart; recovery rewrites ✔ (rig26) | must not exist (NW-2; the pass is ADR-048's) | **26**, lane ADR-048 |
| 27 | "authored save worker stopped" | `pending_text.rs:748-761` `release_pending_text(poison = true)` | as 26 | as 26 ✔ (operator 19:40:08Z) | must not exist (NW-2) | **26** |
| 28 | "this identity has left the room" | `local_history.rs:153`, `read.rs:151` | trust turn (withdraw), preparation trust stage, read marks, any local append | trust turn fails the pass ✔; preparation "stays closed" ✔ (rig26); reads silent ✔ | not a not-yet: a left room's copy is hidden until one member verifies the leaving, 2 days at most, then its rows and key are deleted at once (freed pages cleared at the next rewrite); a rejoin is a fresh join (ADR-049; the decider, ledger rows 34, 58, 61) | **26, 27**, lanes ADR-048, ADR-049 |
| 29 | `MalformedAtRest("key-package attempt unacknowledged")` | `key_package_queue.rs:644-646` | selection stage (`pending_package.rs:709`, `poison = true`) | **no**: marks the room; store recovery ✔ (Mac 15:25:38Z) | must not exist (NW-11) | **31** |
| 30 | "a member is busy answering other joins" / `Fault::MembersBusy`; `SeatTaken`; `SeatNotAgreed` (`error.rs:460`, unanswered seat question); `JoinEndedForNewcomer` | `error.rs:476,452,460,491` | joiner CLI | no: person told ○ | CLI; `SeatNotAgreed` ceases to exist (the decider, ledger row 37: an unanswered seat question never fails a join; ADR-046 SY-10) | lane ADR-046 / ADR-043 |
| 31 | "history demand buffer budget is busy" (`Error::HistoryCapacity(BytePressure)`), `Phase::Busy`, "History preparation buffers are busy", "Archive worker is busy", "Peer transfer slots are busy" | `error.rs:21`, `history_demand.rs:1263,1376,1422,1436,1837,1847,1877` | history request callers; `key_body_scan.rs:440-453` | some (`bounded_sync.rs:5367-5395`; the pressure's own release future) ✔ | preserved owner: the byte pool's release (NW-1) | lane ADR-046 |
| 32 | `ScanResult::Busy` (`key_body_scan.rs:84-105,494-508`) | key body scan | `key_body_wait` re-spawn ✔○ | yes | daemon, `RoomWrite` | — |
| 33 | "the room is refreshing saved Sessions; retry", "legacy Session classification is refreshing", `StreamRefused("Session authorization facts are refreshing")`, `StreamRefused("Session control facts are refreshing")` | `session_projection/query.rs:21`, `legacy_session.rs:127,275`, `floor_index.rs:16`, `private_session.rs:19` | `opening_refreshing` loop; projection refresh | yes ✔ | daemon, `Projection(room)` | — |
| 34 | "the room changed while reading; refresh and retry" (`history.rs:255`), "read selection changed; refresh and retry" (`read.rs:161`) | history and read | readers | reader re-reads ○ | reader | — |
| 35 | "accepted join remains pending" (`metadata_save.rs:3511`; `:4379,4394`) | join path | joiner | yes at 3511; no at 4379/4394 ○ | daemon | lane ADR-046 |
| 36 | "remote admission may have occurred; retry requires a new authenticated exchange" / "admission was accepted and retained; local completion remains pending" (`actor.rs:4963-4966`) | join | joiner | no ○ | join cleanup owner (FX-28); the durable owner of an admitted construction (NW-3) | lane ADR-046 |
| 37 | "could not finish recovery… Reopen it to try again" (`metadata_save.rs:3802-3827`); "could not reclaim provisional history…; reopen will retry" (`governance_save.rs:1551`) | person | — | no ○ | daemon, `RoomWrite` | lane ADR-047 |
| 38 | `Error::AtRestLocked` / `Fault::Locked` (epoch changed, `maintenance_save.rs:824-826,886-888`) | every native save | — | no: the lock ends the attempt; unlock derives it again ✔ | unlock (already) | — |
| 39 | `Fault::ProfileBusy` "another vox already has this node open"; `PostBusy`; `SessionCleanupBusy`; `AdminChangePending`; `DeliveryBusy` | `api.rs:1836-1864` | person at the CLI | no ○ | CLI says the prerequisite | — |
| 40 | code 78 "Vox delivery in this conversation is uncertain…" (`OMP_UNCERTAIN`, `agent_hook.rs:254,298-302`) | hook → extension `poisonSession` (`omp-extension.ts:78-87,251-252,262-264,517-519`) | — | **no**, by P420-OR-6 ✔ | hook turn journal | **30**, lane ADR-050 |
| 41 | code 75 "Vox OMP preparation is busy" (`agent_hook.rs:291-295`) / "Vox OMP conversation is no longer registered" | extension | — | `scheduleRetry` ✔ | extension | lane ADR-050 |
| 42 | extension-side: "Vox hook unavailable or session changed", "Vox registration failed", "Session registration is no longer present; reacquiring it", "context preparation unavailable; reacquiring registration", "Vox Session ownership temporarily unavailable" | `omp-extension.ts:255,344-345,429,831` | extension | yes, bounded steps ✔ | extension | 28, 29 |
| 43 | `DispatchOutcome::Unknown("room authority/pause changed while submission was pending; no retry without receipt")` | `node_tasks.rs:333` | attention dispatch | no (correct: a notice may have been shown) ✔ | daemon keeps the notice "uncertain"; redelivery with a receipt | lane ADR-042 |
| 44 | `Error::OwnKeyWriterDrainRequired` "waiting for an own-history response to retire" | `error.rs:528`, `policy_save.rs:1098,1148-1153` | policy drain | yes ✔ | preserved owner: the policy drain (NW-1) | 26, lane ADR-048 |
| 45 | "history retirement is pending: store save room: …" | `bounded_sync.rs:1925,2372,2378` | logs | tick ✔ (operator 19:40:08Z ×11) | the failed cleanup parks on `StoreRecovery(room)` (ADR-046 SY-24) | 26, 64, 85 |
| 46 | "history retirement requires recovery; see status" | `bounded_sync.rs:842,2061` (a retiring flow in `retirement_failed`) | ended-room purge (`leave_save.rs:1563-1577`) | **no**: purge abandoned with a note; the room stays ✔ | discarded with the room (ADR-049); kept rooms: `StoreRecovery(room)` (ADR-046 SY-24) | **64, 86**, lanes ADR-049, ADR-046 |
| 47 | "Session save is waiting for its room" | `maintenance_save.rs:1183` (a re-wording of row 3's `Saved::Unavailable`) | `finish_owned_session` | as row 3 ✔ | row 3: `PublicationGate`; the text goes | — |
| 48 | "key delivery is waiting for its saved room" | `package_save.rs:923` (re-wording of row 3) | `reject_owned_packages` | as row 3 ✔ | row 3: `PublicationGate`, key `KeyPackage`; the text goes | 31 |
| 49 | "key pruning is waiting for its room" | `key_prune_save.rs:112` (re-wording of row 3) | `reject_owned_key_prune` | as row 3 ✔ | row 3: `PublicationGate`; the text goes | — |
| 50 | "history room is busy" | `history_demand.rs:1558` (a 30 s `timeout_at` on the room lock inside a preparation worker) | the peer's history request | the worker waits itself; after the bound the request fails to the peer ✔ | preserved owner: the worker's bounded wait (NW-1) | lane ADR-046 |
| 51 | "rekey room publication is busy" | `rekeys.rs:87-91` (`pending_posts` has the room; sets `redeliver_now`) | `finish_owned_rekey_after` | yes, by its own flag ✔ | daemon, `RoomWrite` as a queue place, key `Rekey` (the flag and the `pending_posts` test go; ledger row 82) | — |
| 52 | "accepted join responder authority is unavailable" | `construction_save.rs:187-190` (resuming a join whose responder is no longer a member) | the join | no ✔ | not a not-yet: permanent for this attempt; the person is told to join again with a new link | lane ADR-046 |
| 53 | `HistorySourceStart::Busy` | `sparse_history.rs:1340` (`history_publication_busy`: a pending post) | the actor ("retains and retries that request at its next eligible turn", `:1417-1418`) | yes ✔ | daemon, `RoomWrite` as a queue place (the pending-post test goes; ledger row 82), the sparse publication's kind | lane ADR-046 |
| 54 | `receiver_releases::Remember::Busy` | `receiver_releases.rs:269-275` (`MAX_RECEIVER_CHAINS` reached; `retry_owed` sealed in the header) | the receiver admission | yes: the durable `retry_owed` flag ✔ | preserved owner: the key-prune sweep re-derives it (NW-1) | — |
| 55 | `AppRefusal::Busy` "app: busy — too many app streams to that peer, or too fast" | `app.rs:216-218` (a peer's refusal on the wire) | the opener (a program using app streams) | no: the program is told ✔ | not a daemon obligation: a wire refusal said to the caller | lane ADR-039 |

Every string the plan listed is now classified. A refusal found later is classified under NW-1
before it ships, as a prerequisite with four columns, a preserved owner, or a permanent refusal.

## Appendix B: every act, what it reads, where that exists, and its mutant

One row per act or journey this ADR's proofs run. "Reads" is the command or log line the
assertion reads; "Exists at the tag" is where that command or line is at `v0.4.30`, or which
requirement of this ADR adds it; "Mutant → red on" names the mutant and the assertion it turns
red. A row with an empty cell is a defect; none is empty (revision 11). `test-knob:` receipt
lines and every knob are `test-knobs` only (NW-14).

| Act | Reads | Exists at the tag, or added by | Mutant → red on |
|---|---|---|---|
| NW-8 act 1 (sibling startup held 5 s) | `vox room post` exit and `vox room read` of the post (`cli.rs:405, 408`); a hook `--omp-prepare` through RS-7's shim (`cli.rs:1323-1368`); the log's absence of `attention waits for current computer trust` (`actor.rs:23351`) and `could not open this session's Session` (`host.rs:2210`) | commands and lines at the tag; the hold `VOX_TEST_STARTUP_HOLD_MS` and its `test-knob:` line added by NW-8 | take the transition around the whole startup → the post during the hold is refused |
| NW-8 act 2 (writer progress under overlapping reads) | `vox daemon: node <n> is Ready` (`daemon.rs:674`) for the third node within 5 s; two posting loops' per-post times | line at the tag; `VOX_TEST_PUBLICATION_READ_HOLD_MS` added by NW-8 | admit new readers while a writer waits → no `is Ready` within 5 s |
| NW-8 act 3 (abandoned writer releases readers) | the sibling post's completion time against the abandonment's `test-knob:` line; the third node's `is Ready` | `VOX_TEST_STARTUP_WRITER_ABANDON` and its line added by NW-8 | bump the gate's generation on `Writer` drop only (NW-3 mutant 3) → the post completes only at the next writer; red on the 1 s bound |
| NW-9 act 1 (nine-session burst) | `vox room sessions` names (`cli.rs:428`, `room_cli.rs:2684`); `vox agent doctor` `idle`/`busy` (`cli.rs:1121`, `doctor.rs:851-877`); log absence of `session registration is busy` (`wake.rs:800`) | all at the tag; OMP sessions under RS-7's shim | (release red only; the mutants are acts 2–4's) |
| NW-9 act 2 (rename under a held lock) | `vox room sessions`; `vox agent doctor` | at the tag; the lock held by `flock` on `sessions.lock` (apparatus) | drop an update whose lock wait exceeds 200 ms → the name is stale in `room sessions` |
| NW-9 act 3 (move under a held lock; kill) | `vox agent room <new>` (`cli.rs:1127`) return; `vox room sessions`; the daemon's restart under ADR-041 | at the tag | acknowledge `SessionRegistered` before the commit → the killed run says done while the session is in the old room |
| NW-9 act 4(a) (held lock, real `Stop`) | `vox agent doctor` `idle`; the pong of `vox room ping` (`cli.rs:447`, `ping.rs:87`) | at the tag (`Stop` body with `hook_event_name`, `agent_hook.rs:94-98`) | (release red; the hook-side-write inverse is 4(a′)) |
| NW-9 act 4(a′) (hook-side-write inverse) | `vox agent doctor` | `VOX_TEST_HOOK_AFTER_REGISTER_HOLD_MS` and its line added by NW-9 | restore `record_idle`'s bounded-lock write in the hook and send `Busy` → `doctor` says `busy` |
| NW-9 act 4(b) (next prompt) | `vox agent doctor` | at the tag | send no state at turn start → `doctor` says `idle` |
| NW-9 act 4(c) (arrival order) | `vox agent doctor` | `VOX_TEST_HOOK_REGISTER_HOLD_MS` and its line added by NW-9 | drop the older hook stamp (revision 6's rule) → `doctor` says `busy` after the hold |
| NW-9 act 4(d) (stamp step) | `vox agent doctor`; the writer's `test-knob: state stamp offset … applied` line | `VOX_TEST_STATE_STAMP_STEP_FILE` and its line added by NW-9 (re-check F6) | writer-clock high-water mark → `doctor` says `busy` |
| NW-9 act 4(e) (old route, OMP producer) | `vox agent doctor`; the **new** `test-knob: state busy committed for <session> route <room>` receipt; the writer's `rejected: route changed` debug line | the bridge and its `state` frame at the tag (`host.rs:2309-2310`, `omp_mirror.rs:253-335, 1632-1644`, `omp-extension.ts:991-1003`); `VOX_TEST_OMP_STATE_HOLD_MS`, the commit receipt and the debug line added by NW-9 (re-check R11-6) | skip the `same`/`first_seen_ms`/`mirror` check → `doctor` says `idle` |
| NW-9 act 4(f) (cleanup contention, two rooms) | log absence/presence of `removed room cleanup cannot finish` (`host.rs:4118`); `vox agent doctor`; the injected `tool-done` by unique `ref` in `vox room session B <session> --raw --json` (`session_cli.rs:161-196`) | line and commands at the tag; `VOX_TEST_RETIREMENT_HOLD_MS` added by NW-9 (re-check R11-7) | (1) cleanup outside the writer with `try_lock` → the cleanup line appears; (2) state applied after `blocked_nodes` → `doctor` says `busy` |
| NW-11 first journey (observation-to-park) | `vox room read` on A of B's next post; `vox status` without `cannot save`; log absence of `malformed at-rest artifact` (`key_package_queue.rs:645`) and `recovered; it can save again` (`metadata_save.rs:3802-3804`); the `test-knob: fold ready for <room>` receipt | commands and lines at the tag; `VOX_TEST_FOLD_HOLD_FILE` at the tag (`governance.rs:874-883`), its `:<room>` suffix, `VOX_TEST_PACKAGE_RESULT_HOLD_FILE` and the fold-ready line added by NW-11 (re-check F5) | park unconditionally (NW-3 mutant 2) → A never reads B's post within 10 s |
| NW-11 second journey (restart into a held fold; hosts NW-4 and NW-3-B) | `vox status` `waiting` line (`cli.rs:2450`; the block added by NW-4); `vox status --json .waiting[]` (`ReadFlush` and `KeyPackage` entries); `vox room read` on A | status command at the tag, the `waiting` block added by NW-4; `VOX_TEST_FOLD_HOLD_FILE` at the tag; the hook's marks through RS-7's shim (`agent_hook.rs:3768-3780`) | drop the `(room, KeyPackage)` resume → the key never opens; omit parked obligations from status → no `waiting` line |
| NW-12 journey, schedule A (policy not current; hosts NW-3 mutant 1 and the log mutant) | the mark in `read_by` of `vox room read <room> --json` on the author's node (`room_cli.rs:1465-1484, 2478-2505`), the post selected by hash; the joined room's read; log absence of the three sentences (`read_save.rs:228`, `recovery_save.rs:288`, `package_save.rs:350`); the sibling's `vox room post`; the `test-knob:` lines of the apply hold, the flush's refusal and `parked ReadFlush <room>`; the candidate's `applying`/`applied computer trust revision <N>` lines | commands and old lines at the tag; `vox node create` at the tag; the two application lines, `VOX_TEST_POLICY_APPLY_HOLD_MS` and the park receipt added by NW-12/NW-3 (re-check R11-2, R11-5; the tag has no application interval observable, so the rig red is a baseline) | restore `reject_owned_read`'s log and drop the park → the sentence appears and the mark is not visible (the missing park receipt is PRODUCT); drop the `ComputerPolicy` release (mutant 1) → mark not visible in 10 s |
| NW-12 journey, schedule B (stale capture after current; NW-3 mutant 4) | the same `read_by` mark within 10 s; the hold's and the refusal's `test-knob:` lines; absence of a `parked ReadFlush` line | `VOX_TEST_MAINTENANCE_AUTHORITY_HOLD_MS` and its lines added by NW-3 (re-check R11-2) | skip the predicate check (mutant 4) → the flush parks on a current policy; mark never visible |
| NW-12 extension (`Construction` fold) | the receipt `test-knob: parked Construction <room> (join)`; joiner J's `vox room read` of the third room within 10 s | the tag's `VOX_TEST_HOLD_ROOM_JOIN_AFTER_BOARD` (`construction_save.rs:496-535`); the receipt and the join-abort consumer's migration to the registry added by NW-3 (re-check R11-3) | drop the `(room, Construction)` resume → the join never completes |
| ADR-048 act 3 extension (`Rekey` fold; ledger row 82b) | the receipt `test-knob: control turn <room> rekey <recipient>`; M's `vox room read R3 --json` decrypting a post committed after the rotation within 10 s; a loop post's commit time between two rekey turns; the posting loops' per-post times (no gap) | ADR-048's act; the receipt and the assertions added there; `vox room read --json` at the tag (re-check R11-4, R12-F2) | drop the `Rekey` resume → M never decrypts the post; control back to back while a post is queued → the queued post misses its one-transaction bound; W's negative read is ADR-048's separate assertion |
| NW-3-C | none today | no kind in this ADR or a sibling admits several person operations on one key (D6) | review condition; mutant 5 lands with the first such kind |

## Links

- ADR-018 (proofs), ADR-034 (WT-6, §4), ADR-037 (R3, R5, R7), ADR-038 (FX-27, FX-40, FX-45,
  FX-49, FX-61a, FX-61b).
- v0.4.31 lanes: ADR-041 (RS-7, RS-12), ADR-042 (TR-11, TR-12, TR-23), ADR-043, ADR-044 (RD-7,
  RD-10), ADR-045 (J5(g), J6, J7), ADR-046 (SY-24), ADR-047 (SO-11, SO-12), ADR-048, ADR-049,
  ADR-050.
- Receipts (all under `/tmp` or `/private/tmp`; lost in the reboot of this Mac on 2026-11-13,
  the figures standing as recorded in the named reports; to be re-run as the fleet baseline):
  `/tmp/plan-PlanD/keep/run26-rig.log`, `run26-X-daemon.log`, `run1-rig.log`;
  `/tmp/rca-RcaTrust/run-*` (`run-s1`, `run-m1`, `run-c1`, `run-c2` release; `run-i1`, `run-i2`,
  `run-w1`, `run-s3` instrumented); `/tmp/RcaSchedStall/receipts/`; the operator's logs under
  `/private/tmp/vox-rca/` (IO `daemon-202624Z.log`, the Mac `daemon-current-200453Z.log`,
  `daemon-old-profile.log`, IO `status-omp-io-post-restart-202011Z.json`,
  `mac/stall-robert-work-021627Z.json`).
- The independent reviews: `adr-040-sol-review` (sixteen findings) and `adr-040-sol-review-2`
  (eighteen findings), both 2026-11-12, and `adr-040-sol-review-3` (four findings), `adr-040-sol-review-4` (three findings and two proof recipes), `adr-040-sol-review-5` (five findings), `adr-040-sol-review-6` (four findings), `adr-040-sol-review-7` (three proof recipes), `adr-040-sol-review-8` (two findings) `adr-040-sol-review-9` (pass), `adr-040-sol-review-recheck-1` (eight findings), `adr-040-sol-review-recheck-2` (seven findings) and `adr-040-sol-review-recheck-3` (two P1s, four P2s owed), all 2026-11-13;
  the revision note `adr-040-revision` (revision 13's record first, earlier records below it);
  the sibling asks `adr-cross-asks` and the quotation check `adr-amendment-quotes`.
- External: https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html ·
  https://sre.google/sre-book/addressing-cascading-failures/ ·
  https://sqlite.org/c3ref/busy_timeout.html
- Release milestone v0.4.31.
