# ADR-043: Adding, Replacing and Removing a Computer

- **Status**: Accepted (2026-11-13) after the eighth independent review by GPT-6.1-Sol
  (`adr-043-sol-review-8`), under the decider's authorization of 2026-11-13 ("post review can
  accept them too"); revision 9 corrects experiments and cross-references found when the ADR was
  cut into tasks (`v0431-tasks-ADR-043`, its review), changes no design decision and none of the
  decider's answers; revision 10 carries the second correction batch (cross-ADR asks,
  amendment anchors, the lost-receipt note, CJ-16's spike ruling) and is re-checked by the same
  reviewer; revision 11 answers that re-check's four findings (`adr-043-sol-review-recheck-1`)
  and revision 12 the second re-check's three (`adr-043-sol-review-recheck-2`) and E-43-1's
  verdict; revision 13 the third re-check's four (`adr-043-sol-review-recheck-3`) and the
  established cause of item E-b (`rca-relay-only`, fix-list item 92), which adds CJ-17;
  revision 14 the fourth re-check's one (`adr-043-sol-review-recheck-4`, a proof cast);
  revision 15 the task refresh's six (`v0431-tasks-ADR-043`); revision 16 the sixth re-check's
  three (`adr-043-sol-review-recheck-6`) and the decider's row 82 / Main's row 82a (the control
  lane; ADR-048 TC-4/TC-5 own the change); revision 17 Main's row 82b (two FIFO lanes that
  alternate; cited by id from ADR-040 NW-3 r13, ADR-044 RD-10 r16, ADR-048 TC-4 r11); nothing
  else. **Revision 17 is the accepted text**: the eighth re-check
  (`adr-043-sol-review-recheck-8`, "Verdict: pass") found no P1 under ledger row 83, and its
  P2s, with re-check 7's two, are owed to the owning task's acceptance; Main then scoped CJ-12's
  control bound to the head of the lane (ledger row 82c, a wording precision that changes no
  design decision). The decider
  answered Q1–Q8 on 2026-11-13 (recorded last). This is design acceptance only: nothing in it is
  built, every change below is to land in v0.4.31 with its proof, and implementation, acceptance
  and delivery are recorded on the source-bound issues, separately from decision status. The
  decider's own words of 2026-11-12, quoted in Context, are the reason for this ADR. The
  observation E-b has its cause established (`rca-relay-only`, fix-list item 92) and CJ-17 is
  its fix (r15). Revision 2 was rewritten
  after the independent review (`adr-043-sol-review`, fourteen findings); revision 3 answers
  the second review (`adr-043-sol-review-2`, nine findings, proof corrections) and the cross-ADR
  ledger rows aimed at this ADR; revision 4 answers the third review (`adr-043-sol-review-3`,
  seven findings N1–N7 and two partly closed); revision 5 answers the fourth
  (`adr-043-sol-review-4`, three findings R4-1–R4-3) and nothing else. The Review record names each
  finding and the requirement that answers it. Requirements marked **(changed)** differ from
  revision 1; **(r3)**, **(r4)**, **(r5)** and **(r6)** mark text changed in those revisions.
  Revision 6 answers the fifth review (`adr-043-sol-review-5`, two proof defects) and records
  the decider's answers of 2026-11-13 and ledger rows 24, 27 and 32.
  Revision 7 answers the sixth review (`adr-043-sol-review-6`, one proof defect) and nothing
  else. Revision 8 answers the seventh (`adr-043-sol-review-7`): the proof's JSON selector is
  `.invite_link`.
- **Date**: 2026-11-12
- **Deciders**: Robert E. Lee
- **Tags**: computer-trust, pairing, removal, status, cli, macos, room-pause
- **Related**: ADR-007, ADR-018, ADR-028, ADR-033, ADR-035, ADR-038; in this release ADR-040
  (named waits), ADR-048 (trust containment, split from ADR-040), ADR-049 (leaving and ending
  rooms), ADR-050 (turn journal), ADR-041, ADR-042, ADR-044, ADR-045, ADR-046
- **Source**: plan E (fix-list items 33–38 and E-a), code read at tag v0.4.30 (8d71ab337), the
  review of revision 1, experiments X1 and X2 of 2026-11-13 (`/tmp/adr043/run-x1`, `run-x2`;
  receipt lost in the reboot of 2026-11-13; figure recorded in `adr-043-revision`; to be re-run as the fleet baseline)

## Context

### What the person saw

On 2026-11-12 the decider added a rebuilt Linux computer (`ns1025741`, called IO here) back into
his group of computers. He started at 19:3x with "I need help getting computers to trust each
other". At 22:06 he asked "how do I fix the half way pair". Later he ran `vox computer list` and
`vox computer binding`, read `vox computer status`, and said:

> "vox computer is unusable"; "unreadable"; "no clue what to do".

At 22:18, in Vox.app:

> "I'm trying to use the user interface and nothing is working it's refusing to let me generate a
> pairing code".

What each surface showed, from the operator transcript and the release binary:

- `vox computer` printed Clap's command list and no state (`list` is not one of its commands).
  `vox computer binding` printed
  `error: the following required arguments were not provided: --confirm <CONFIRM> <ACTION> <NODE>`.
- `vox computer status` printed a policy paragraph, five `Policy:` lines and three lines of the
  form `beast: application confirmed; previously exchanged; current connectivity unknown`. It did
  not say who was in the group, what was pending, or what to run next.
- `vox computer status --details` printed 25 lines: fingerprints, `binding release:` for his own
  nodes, five `binding recover:` lines for the nodes of the removed IO, `removed: ns1025741 …; no
  claim that unreachable data or keyrings were erased` and `Removal confirmation frontier:
  oomca7lb…`. The actual next step (make the code on IO and pair from the Mac) was nowhere.
- 19:39:48–19:49:48: the Mac made a code, IO ran `vox computer pair`, the Mac clicked Trust This
  Computer. For ten minutes the Mac said `computer trust: waiting … approved here: true; approved
  there: false … On that computer, review and approve in its terminal with vox computer approve
  iumihq…`. IO said `computer trust: individual` and had nothing to approve; `approve` there was
  refused. `vox computer cancel` on the Mac was refused: `this approval is already signed and the
  other computer may complete it; wait for its result or close the incomplete attempt after it
  expires`. The only true sentence was the last line of `--details`: `… computer relay: peer
  unreachable: no anchor configured for this computer pairing`. After expiry, a code made on IO
  and redeemed on the Mac applied at 19:50:55.
- After `vox computer remove` of the old IO (22:06:39), the old IO's nodes stayed members of
  `repo-to-cve`, came back as trust offers in the keyring, and a second `ns1025741` stood beside
  `removed: ns1025741` with nothing saying which was which.

The same defects reproduce on the published v0.4.30 binary with two scratch computers on one
host. Both print their name as `mac`, so the pairing block reads `Approved here. Approval from mac
(fb4livw5…) has not reached this computer` while the status line above it also says `mac`
(`/tmp/plan-PlanE/run-e2/timeline.log`, 00:01:42Z; receipt lost in the reboot of 2026-11-13; figure recorded in `plan-E`; to be re-run as the fleet
baseline).

### Causes at v0.4.30

Status words: **KNOWN** = reproduced on the release binary or read from the operator's evidence
(the run directory or file is named); **INFERRED** = the mechanism is read in code but not
observed; **UNKNOWN** = not settled, with the experiment that settles it. Every file:line below
was checked against `git show v0.4.30:<path>`. Every run directory named below (`run-e2`,
`run-e3`, `run-x1`, `run-x2`, the `vox-rca` facts, ADR-045's `B2-path*`): receipt lost in the
reboot of 2026-11-13; figure recorded in `plan-E`, `rca-RcaTrust`, `adr-043-revision` or
`adr-045-revision` as named; to be re-run as the fleet baseline (ledger row 64). The addresses in
the journeys are documentation samples (RFC 5737/3849), never a real LAN. `pairing.rs` is
`crates/vox-core/src/node/computer/pairing.rs`; `computer.rs` is
`crates/vox-core/src/node/computer.rs`.

**Item 33. A half-made pairing waits ten minutes. KNOWN** (operator transcript 101705–101769;
`/private/tmp/vox-rca/mac/trust-facts-200453Z.txt`, `/private/tmp/vox-rca/io/facts-200453Z.txt`;
reproduced mirror-image in `/tmp/plan-PlanE/run-e2`, 00:01:42Z; the exact operator state
reproduced in `/tmp/adr043/run-x2`, 02:41:54Z; every `/tmp` and `/private/tmp` receipt named in
this ADR: receipt lost in the reboot of 2026-11-13; figure recorded in `rca-RcaTrust`, `plan-E` or `adr-043-revision` as named; to be re-run as the
fleet baseline). Three mechanisms:

1. The computer that made the code (the inviter) cannot reach the computer that used it (the
   redeemer). `retry` gives a pending peer the endpoints in `s.reaches` and a link from
   `s.pair_link`/`s.links` (`pairing.rs:3734-3750`, inside `retry` at `:3416`). A computer records
   its own reach only once it is a group member (`record_reach_in`, `:786`), and only the
   redeemer holds the link. `connect` (`:2496`) then has no direct candidate (`no direct
   candidates`, `crates/vox-core/src/nat/reachability.rs:822`) and falls back to the code's
   transport lease, whose anchors are the machine's hand-added set (`transport_leases`,
   `pairing.rs:2270-2281`, anchors at `:2277`). That set was empty on the Mac although the Mac
   had anchors **(cause established, r13; `rca-relay-only`)**: the computer management holds
   only the `--anchor` list of the process that took the daemon lock, fixed at its start
   (`crates/vox-tui/src/daemon.rs:422-428, 459-463`; `pairing.rs:413`, `:943`); the machine's
   manual anchors (a client's `--anchor`, `vox anchor add`, the anchors file) are delivered to
   the nodes only (`crates/vox-tui/src/host.rs:1064-1073`, `NodeCommand::SetAnchors`); there is
   no setter for the computer's set. So the error was
   `no anchor configured for this computer pairing` (`:2536`). The inviter reaches the redeemer
   only over the redeemer's own handshake connection (`self.net.manager().existing(&target)`,
   `:2503`), which idles out after `pair` returns. The redeemer is meant to drive (ADR-035 CT-11:
   the link carries the inviter's addresses); nothing told the person so.
2. The inviter records the attempt before the redeemer does, and its status then assumes the
   redeemer holds it. `answer` claims the code (`i.target`, `:3216`) and records the attempt
   (`s.pending = Some(g)`, `:3228`) once the redeemer has proved it holds the code and its key,
   and before the redeemer has recorded anything. The redeemer records last, in `pair`, after
   checking that its policy revision and the link are unchanged (`:2818-2866`). If that check
   fails, or the redeemer dies or loses the connection before its record, the inviter holds an
   attempt naming a computer that holds nothing, and its status says `On that computer, review
   and approve …` (`computer_cli.rs:417-426`), which that computer cannot do. The order itself
   is sound: the inviter owns the code, and the same redeemer can present the same code again
   and resume the same attempt, approvals included (`answer` admits the reserved identity,
   `:3210-3212`, and reuses the recorded approvals when the body is equal, `:3217-3219`).
   **KNOWN** on v0.4.30 (X2, `/tmp/adr043/run-x2/timeline.log`; receipt lost in the reboot of 2026-11-13; figure recorded in `adr-043-revision`; to
   be re-run as the fleet baseline): with the inviter A approved
   and the redeemer B's record lost, A printed `Approval from mac (…) has not reached this
   computer. On that computer, review and approve …` while B printed `computer trust:
   individual`; B re-running `vox computer pair` with the same code resumed the operation, kept
   A's approval, and both computers were `confirmed` within 4 s; a third identity presenting the
   code was refused `already consumed by another identity`. The defect is the status and the
   missing "pair again" instruction, not the order of the records.
3. The person is locked out by design. `cancel` refuses while `locally_approved &&
   s.pending_expires > now()` (`:1320-1321`); a code lives `INVITE_LIFETIME_MS = 600_000`
   (`computer.rs:272`); `begin` refuses a new code while an attempt or a live code exists
   (`pairing.rs:1224-1231`). The refusal is sound in one respect that revision 1 missed: a
   signature already handed to the other computer cannot be withdrawn, and for a two-party
   genesis (or an addition whose sponsor is the other computer) that computer can complete the
   pairing alone with it (`activate`, `:5203-5245`; `merge` calls it at `:5598`). What the
   refusal gets wrong is the remedy: the person must be able to close the attempt here at once
   and be told truthfully what that does and does not do (CJ-6).

Why IO held nothing at 19:45 is **UNKNOWN** (IO's `pair` output was not captured). Candidates:
IO's last check failed because its policy revision moved during the handshake (IO had cancelled
an older code at 19:40:08; `crates/vox-tui/src/host/computer.rs:263` logs an already failed
reconciliation at that time, which is not evidence that it caused the missing record), or IO's
record waited behind a held writer (item 35's mechanism), or the connection ended before IO's
record. CJ-5 makes every candidate recoverable the same way, so the cause need not be settled
to fix the state; experiment E33b (a `test-knobs` build holding the redeemer before its record,
a `vox node create` during the hold) is run once as a spike and reported in the post.

**Item 34. Status does not say who is in, what is pending or what to do. KNOWN** (transcript
102321–102351; `run-e3`, 00:03:18Z). `show` (`crates/vox-tui/src/computer_cli.rs:312`) prints the
status record in storage order: the fixed policy paragraph on every call (`:354`, text at
`computer.rs:268`), then one `Policy:` line per topology entry (`computer_cli.rs:442-444`; built
in `status`, `pairing.rs:1939-1972`), then one line per computer whose "connectivity" is derived
from exchange counters alone (`computer_cli.rs:445-464`). `--details` adds `binding_actions`
(`pairing.rs:1974-2005`: `release` for every node this computer manages, `recover` for every
retained binding whose manager has no grant). These are actions the person may take, printed as
if they were pending. It also adds every former member (`:2015-2026`). The record has no field
for the next action. Next-action text exists only inside the pairing block
(`computer_cli.rs:388-429`) and is wrong when the other side holds nothing (item 33). Bare
`vox computer` is Clap's default (`crates/vox-tui/src/cli.rs:2467`). ADR-038 FX-41 ("every pairing
surface state the next action") was built inside the pairing block only, and ADR-035 CT-15
("whether the requested changes have reached each computer") was built as raw counters.

**Item E-a. Computer names collide. KNOWN** (`run-e2`: two `mac` identities in one pairing
block). A computer's name is the host name at creation (`crates/vox-tui/src/daemon.rs:455`,
`Computer::open(account, &crate::setup::host_name())`). Every scratch rig prints two `mac`s, and
the rebuilt IO printed a second `ns1025741` beside the removed one.

**Item 35. The app refused to make a pairing code. UNKNOWN** (the mechanisms are identified;
which one the Mac hit at 22:15 is not, and the click was not recorded). Every condition under
which Create Pairing Code or `vox computer invite` refuses or stalls at v0.4.30:

| # | Condition | Where | Matches the Mac at 22:15? |
|---|---|---|---|
| 1 | Button absent: an attempt exists; the panel shows "Approved here. Confirm on X" with no create and no cancel | `apps/macos/Vox/ComputerTrust.swift:484, 587-600` | Not at 22:13:45 (no attempt in `--details`); not excluded for 22:14–22:17 |
| 2 | Button absent: a live code exists | app | Not at 22:13:45 |
| 3 | Button disabled: `model.busy` or `!model.reachable`; `reachable` turns false after any failed daemon request, including a refresh | `ComputerTrust.swift:49-60, 546-551` | Possible: the daemon had restarted two minutes earlier, under load |
| 4 | Button disabled: state `removed` | `ComputerTrust.swift:551` | No |
| 5 | `begin` refuses: attempt pending (`pairing.rs:1224-1231`), authority suspended (`:1216-1223`), invitation history full (`:1233-1236`) | daemon | No |
| 6 | `begin` first takes `review_gate` (`pairing.rs:1207`), which `pair`/`answer` hold across their own writer wait (`:2797-2818`, `:3168-3170`), then runs inside `self.computer.change`, which waits for the computer changes writer (`changes_writer`, `computer.rs:2770-2776`, taken at `:4237`) up to `COMPUTER_RETURN_SHOWN_WITHIN` = 60 s (`:38, 4200-4202`) and then fails with `WRITER_WAITED` (`:303`): "the computer transaction waited too long for another computer writer or a held publication and was not applied; try again". The writer is held for each node's whole startup (`crates/vox-core/src/node/actor/startup_save.rs:425-428`; the transition owns changes and publications, `computer.rs:2812-2818`; 30 s on the Mac at 22:12), by each policy application's journal writer (`crates/vox-core/src/node/actor.rs:21278`, `crates/vox-core/src/node/actor/policy_save.rs:322`) and by room-set publication transitions (`actor.rs:21115`) | daemon | Possible: a stall of up to 60 s, which the app reports as a failure |
| 7 | The click is queued behind a refresh: `ComputerTrustModel.perform` lets one operator action wait behind the active refresh (`ComputerTrust.swift:18-27`), and a refresh runs under `AppRequest`'s 60 s deadline (`apps/macos/Vox/AppRequest.swift:7`); a stalled status read therefore holds the click for up to 60 s and then, if it failed, condition 3 disables the button | app | Possible: the same stall seen from the app |
| 8 | `begin` fails in `local_endpoints()` | daemon | No (only a bind error) |

Conditions 3, 6 and 7 are each consistent with "refused" and "timeout"; nothing recorded tells
them apart, and `begin` writes no log line when it fails. **Experiment E35 (one definition,
r9)**: a `test-knobs` build of the candidate with CJ-8's writer hold
(`VOX_TEST_HOLD_COMPUTER_CHANGES_WRITER_FILE`) engaged for 70 s on a scratch daemon whose store
is a clone of the fleet's multi-GB corpus (ADR-045 FG-7: grown by the product, cloned per run;
the operator's stores and the RcaSlow `/tmp` copy, lost in the 2026-11-13 reboot, are never
used), then `time vox computer invite --json` from a second shell, run once on v0.4.30 (the same
store, a second node's startup holding the writer, no knob) and once on the candidate. It
demonstrates mechanism 6 and CJ-8's bound; it cannot say which path the operator's click took.
The design below is correct under every candidate: the daemon never waits for the changes
writer to make a code (CJ-8), the app never queues the click behind a refresh and never
disables the button on stale reachability (CJ-4), and every refusal is logged (CJ-8).

**Item 36. Removing a computer leaves its nodes behind. KNOWN** (`run-e3`, 00:03:18Z; IO doctor at
22:25, transcript 102394). After `vox computer remove`, `vox trust offers` on the node sharing a
room listed the removed node `b1` again, `vox room roster` still listed `b1`, `--details` printed
`binding recover: b1 … manager <removed>` and `removed: mac …`, and the plain status said
`confirmed` with no mention of any of it. Causes:

- Room membership: `remove` (`pairing.rs:1788`) signs a roster removal; policy application
  withdraws read and drive. Room membership is a separate authority (ADR-035 CT-10; ADR-007 G-28:
  removing a room member is the creator's or an admin's act). Nothing links the two, and nothing
  tells the person. A repeated `vox computer remove` cannot finish the job later: `remove`
  refuses a target with no active grant (`:1793-1796`).
- Offers: `offers()` (`crates/vox-core/src/node/offers.rs:167-233`) offers every room member not in
  the keyring and not dismissed (`:176-179`). `vox trust remove` dismisses the member's offers on
  the way out (ADR-028 K-18; `crates/vox-core/src/node/actor/trust_save.rs:990-1009`,
  `FinishUntrust` → dismissal), and that dismissal is best-effort after the grant removal
  (`Ok(None) | Err(_) => false`, `:1002-1004`). The managed path (`trust_save.rs:76`,
  `PolicyCompleted::Managed`) has no dismissal step, so a node removed by policy is offered again
  on the next read.
- Binding lines: retained signed history is the design (the accepted contract on #798; CT-17).
  Printing it is the defect, not keeping it.
- Removal time: no record carries one. `Control::sign` encodes protocol, group, key, grant,
  sequence, predecessor, heads, kind, body and a nonce (`computer.rs:770-784`); the removal body
  is target, grants and roster (`pairing.rs:1797-1801`). A status cannot print `removed 22:06
  UTC` from what is stored.
- Third members: a computer that learns the removal through an ordinary exchange (`merge`,
  `:5556-5560`, folds the signed history) withdraws the grants and has nothing that tells its
  own nodes to dismiss the removed nodes' offers; only the computer that ran `remove` acts.
  The dismissal store itself is bounded: `DismissedOffers` keeps 4,096 entries and drops the
  oldest (`offers.rs:37-39`; `offers/native.rs:12-15`, `pop_first`), so a dismissal is not a
  durable boundary.

**Item E-b. A relay-only computer does not learn a new node of the group. KNOWN; cause
established (r13, fix-list item 92).** First seen in ADR-045's experiment E-1
(`/tmp/adr045/runs/B2-path1500/` and `B2-path0/`; receipt lost in the reboot of 2026-11-13;
figure recorded in `adr-045-revision`; to be re-run as the fleet baseline): `y1`, restarted
reachable only through an anchor, never showed the node `n-new` created on another computer of
its group within 300 s. Reproduced by E-43-1 on the v0.4.30 release asset (host scratch runs
under the host rules, macOS 27.2, 2026-11-13 19:43–19:56Z; receipts
`/opt/vox-evidence/v0431/fleet-exp/receipts/E43-*`; write-up `fleet-experiments`): with
matching anchor sets on both computers (`E43-relay-dual`, PRODUCT red: B stayed `applying` at
revision 9, b1's final trust false, A `expired` at revision 13 with "the exchange did not finish
before its causal convergence deadline", `E43-relay-dual.out:33`) and in both forwarded shapes
(`E43-relay-fwd0.out:31`, `E43-relay-fwd1500.out:32`, PRODUCT red, the same), the relay-only
computer never learns the new node within the 120 s watch; the direct control
(`E43-direct.out:32`, PRODUCT green: a2 trusts b1 at +0.8 s, b1 trusts a2 at +2.8 s, both
`confirmed`) does. Matching anchor sets show that differing anchor sets are not necessary for
this failure class; E-1's own receipts are lost and its cause is inferred from the same staging
shape, not measured. **Cause** (`rca-relay-only`, 2026-11-14, receipts
`/opt/vox-evidence/v0431/rca-relay-only/<run>/`; verdicts on the v0.4.30 asset, macOS 27.3:
`VERDICT R1-base: PRODUCT red (b1 trusts a2: False; A expired: 'the exchange did not finish
before its causal convergence deadline'; B applying: …)` (`R1-base.out:34`), the E-43 staging;
`VERDICT R2-anchoredA: PRODUCT green (b1 trusts a2 at +3.0s; both confirmed at +3.0s)`
(`R2-anchoredA.out:31`), one change: A's serving daemon pre-started with `vox daemon --detach
--anchor …`; `VERDICT R3-anchoraddA: PRODUCT red (…)` (`R3-anchoraddA.out:35`), `vox anchor add`
on A, which reports the anchor connected, does not help). The chain, each link read at the tag
by this ADR's author or measured in the receipts: a daemon's computer management holds only the
`--anchor` list of the process that took the lock, fixed at its start (read:
`crates/vox-tui/src/daemon.rs:422-428` parses its own `anchor_specs`, `:459-463` passes them to
`Management::start`; `pairing.rs:413` the plain field, `:943` stored, `:905-909` added to the
computer network's policy; no setter exists at the tag); the machine's manual anchors are
delivered to the nodes only (read: `host.rs:1064-1073`, `deliver_manual_anchors` →
`NodeCommand::SetAnchors`); so A's signed reach carries no anchors (read: `record_reach_in`,
`pairing.rs:786-795`, writes `self.anchors`), A's computer never registers at the anchor
(measured: A's fingerprint absent from `anchor.out` in every red run), A's relay branch fails with
`no anchor configured for this computer pairing` (read: `:2207-2210` lease anchors = here ∪
there = ∅; `:2536`), B's relay branch asks the anchor for a peer that is not there, and after 60 s
A is `expired` (measured). Not established: why B's anchor-side wait takes about 60 s and ends in
`peer sent no complete frame in time` rather than the coordinator's `NotConnected` refusal
(`crates/vox-core/src/node/coordstream.rs:574-591`); it decides only how fast B reports, not
whether trust arrives, and is fix-list item 95 (U, observed in the red E-43 and RCA runs;
reporting speed, not trust delivery; r15, r16). The rule broken is ADR-038 FX-28
(a policy change reaches every computer within `COMPUTER_RETURN_SHOWN_WITHIN`); the fix is CJ-17,
proved by the E-43-1 journey with its direct control. E-43-1 and the RCA runs are spikes (CJ-16,
ruling X043-14): scratch runs on the host under the host rules, reported, not committed; J9(i) in
the fleet VMs is the blocking proof.

**Item 37. `vox room pause` is refused across computers and does not stop posting. KNOWN** (by
code; RcaFrozen run `roompause`). A remote pause is refused first at the host's drive check: a
driver not in the target's drive set gets an `Answer` with `code: NO_DRIVE`
(`crates/vox-tui/src/host.rs:2974-2990`) before the `Action::RoomPause` branch (`:2995-3016`)
and before the actor's own check (`actor.rs:23539-23575`, refusal at `:23559`; ADR-033 PA-3,
ADR-029 DR-2). The driver's side renders any `NO_DRIVE` answer as the fixed sentence `<node> does
not trust you with drive; it trusts you to read only, or not at all` (`Answer::said_to`,
`crates/vox-agentcomms/src/drive.rs:155-158`, called from
`crates/vox-core/src/node/room_pause.rs:187-190`). Under computer trust only personal nodes drive,
and only the non-personal nodes (ADR-035 CT-3). The refusal names the rule and not the remedy. A
pause interrupts Sessions and holds news (PA-2); it never stopped `vox room post`, and no ADR
claims it does. The operator needed agents to stop posting so a newcomer could catch up; that
need comes from sync starvation (ADR-046).

**Item 38. Creating a node moves the policy revision by 2. KNOWN as a number, not as a defect**
(`run-e3`, 00:02:57Z: the `revision` of `vox computer status --json`, which is `s.policy_revision`
(`pairing.rs:2080`), went A 12→14, B 13→15 within 0.5 s of `vox node create a3`). The number is
explained without a second policy application: `fold_history` assigns `revision = self.revision
+ 1` and then `policy_revision = revision` (`computer.rs:1672-1673, 1761-1763`), while an
application receipt advances `s.revision` on its own "to give it a journal identity"
(`pairing.rs:885-888`). After one receipt the journal is one past the policy ordinal, so the
next single policy change lands the policy ordinal two higher. `policy_changed` is already
derived from a change in members, rosters, quarantine or first activation (`:1656-1671`);
receipts and reach never set it. Revision 1 inferred a second application from the gap and from
`a1`'s log line `computer policy changed while its prior application was pending`; that line is
timestamped 00:02:55, before the 00:02:57 create, and belongs to the pairing. No second
application is reproduced. The sibling losses the gap was blamed for are item 32's (ADR-040
NW-12), which stands on its own. CJ-14 is withdrawn as a product change; E38b stays as a spike.

### Why the proofs did not catch it

The pairing journey (`crates/vox-tui/tests/nodes_of_one_daemon_proof.rs`:
`local_nodes_trust_each_other_without_a_prompt_and_remember_removals` `:556`, through
`pair_computers` `:1743`, `enroll_third` `:2365` and `close_expired_pairing` `:2659`) pairs on
loopback, where the redeemer's connection stays up and both records succeed. No proof loses a
record, kills a daemon between a record and its message, cancels an approved attempt while the
other computer completes, or asserts what a stuck status says. `close_expired_pairing` asserts
the lock-out itself: `err.contains("already signed")` (`:2675`). `enroll_third` asserts the policy
paragraph in the plain status (`:2547-2558`). No proof asserts what a person reads after a
removal, kills the daemon between a computer removal and its room removals, makes a pairing code
while the daemon applies a change, or clicks through the app's Add Computer. The pause helper
`stale_remote_pause_is_refused` (`:8133`) runs only inside the optional
`two_paired_computers_that_are_idle_exchange_nothing` (`:5497`) and asserts the refusal, not the
remedy.

## Terms

- **Computer**: one Vox installation's daemon and data root (ADR-035). Its identity is its
  **fingerprint** (52 base32 characters). Its **name** is a label, by default the host name.
- **Fingerprint prefix**: the first four and last four characters of a fingerprint, joined by
  `…`, as in `2qwy…u2ta`. Display only; no command accepts it. A command that names a computer
  carries the full fingerprint (CJ-1).
- **Group**: the computers paired with each other (ADR-035 "My computers").
- **Pairing code**: the one-time `vox-computer://…` link that `vox computer invite` or Add Computer
  makes. It is valid for ten minutes. It is made on either computer: on the one being added, or
  on one already in the group.
- **Inviter**: the computer that made the code. **Redeemer**: the computer that uses it with `vox
  computer pair`. The redeemer connects to the inviter at the addresses in the code; the inviter
  never connects to the redeemer (ADR-035 CT-11).
- **Sponsor** and **joiner**: for an addition to an existing group, the member is the sponsor and
  the new computer the joiner; the sponsor is `computers[0]` of the attempt and the only computer
  whose signature publishes the addition (`activate`, `pairing.rs:5233-5238`). For a first pairing
  (a genesis) there is no sponsor: either computer completes it once it holds both approvals.
  Inviter/redeemer and sponsor/joiner are independent: on 2026-11-12 the Mac was the redeemer and
  the sponsor.
- **Attempt**: one pairing operation between two computers, named by its operation id, which is
  the hash of its body (code nonce, policy digest, both identities, both grants, expiry, group;
  `Enrollment::operation`, `computer.rs:468`). The same code presented by the same redeemer
  always names the same attempt. A computer **holds** an attempt when it is recorded in its
  computer state. An attempt is **complete** on a computer when that computer holds both
  approvals and has activated it (genesis) or published or received its addition.
- **Confirmed**: the inviter has learned that the redeemer saved the attempt (CJ-5).
- **Closed**: a holder recorded the attempt as closed; it can never complete there (CJ-6).
- **State line**: the first line of the plain status: this computer, its group, what is pending.
- **Next line**: the second line: the next action and the computer it belongs on, or that there
  is nothing to do.
- **Not yet confirmed (a change)**: a computer of the group has not yet confirmed the latest
  change of the group.
- **Leftover member**: a node of a removed computer that is still a member of a room on this
  computer.
- **Personal node**: the node a computer's Vox.app is bound to; it drives the other computers'
  non-personal nodes (ADR-035 CT-3, ADR-038 FX-3).

## The journeys

CJ-1 makes the transcripts in this section the contract. Conventions:

- `…` inside an id or a code in prose and in peer rows marks where the product prints the full
  value. Inside a command the product prints the full value; `…` in a command below is only
  this document's abbreviation. Nothing else is cut.
- Times are UTC, as the product prints them. Fingerprint prefixes are illustrative.
- The group is `mac` (personal node `robert-work`), `beast` (headless) and `vinces-macbook-pro`
  (personal node `vovando`). IO is `ns1025741`, headless, with nodes `omp-io`, `claude-io`,
  `codex-io` and `opencode-io`. The old IO is `ns1025741 (2qwy…u2ta)`; the rebuilt one is
  `ns1025741 (qm2t…yy4q)`.
- Every command that changes something prints its outcome (one line, or the code it made), then
  the plain status.
- A computed name or room name inside a command is single-quoted when it holds anything outside
  `A-Z a-z 0-9 . _ -`; fingerprints and operation ids are never quoted.

### The states, and their two lines

| State | State line | Next line |
|---|---|---|
| Not in a group | `ns1025741 (qm2t…yy4q) · not in a group.` | `Nothing pending. To add this computer to a group: vox computer invite` |
| Code open, made on a computer not in a group **(r3)** | `ns1025741 (qm2t…yy4q) · not in a group · pairing code open until 22:27 UTC.` | `Next on your other computer (or any computer already in your group): vox computer pair 'vox-computer://…' (vox computer invite prints it again)` |
| Code open, made on a member | `mac (qfoj…j4zq) · in a group with beast and vinces-macbook-pro · pairing code open until 22:27 UTC.` | `Next on the computer you are adding: vox computer pair 'vox-computer://…' (vox computer invite prints it again)` |
| Joining, your approval missing | `ns1025741 (qm2t…yy4q) · not in a group · joining mac's group: mac approved, your approval is missing.` | `Next here: vox computer approve 2zq4…` |
| Pairing (first ever), your approval missing **(r3)** | `ns1025741 (qm2t…yy4q) · not in a group · pairing with mac (a new group of two): mac approved, your approval is missing.` | `Next here: vox computer approve 2zq4…` |
| Joining, your approval missing, other not approved | `ns1025741 (qm2t…yy4q) · not in a group · joining mac's group: your approval is missing, then mac's.` | `Next here: vox computer approve 2zq4…` |
| Adding, the other has not confirmed saving the attempt (inviter only) **(r3)** | `mac (qfoj…j4zq) · in a group with beast and vinces-macbook-pro · adding ns1025741: approved here; ns1025741 used the code but has not confirmed that it saved this attempt (it may have saved it and the confirmation was lost).` | `Next on ns1025741: vox computer pair 'vox-computer://…' again (the same code resumes this attempt there; if it already holds it, that shows its status)` |
| Adding, the other must approve | `mac (qfoj…j4zq) · in a group with beast and vinces-macbook-pro · adding ns1025741: approved here, waiting for ns1025741 to approve.` | `Next on ns1025741: vox computer approve 2zq4…` |
| Adding or joining, the other must approve, this computer dials and failed | `mac (qfoj…j4zq) · in a group with … · adding ns1025741: approved here, waiting for ns1025741 to approve; offline, last seen 3 min ago (dial failed at 22:19 UTC: no route to 203.0.113.7:41641).` | `Next on ns1025741: vox computer approve 2zq4… (this computer keeps trying to connect; to give up here: vox computer cancel 2zq4…)` |
| Adding or joining, the other must approve and must connect (it dials, this computer does not) | `ns1025741 (qm2t…yy4q) · not in a group · joining mac's group: approved here, waiting for mac to approve; mac has not connected since 22:19 UTC.` | `Next on mac: vox computer approve 2zq4… (mac connects to this computer by itself; to give up here: vox computer cancel 2zq4…)` |
| The other must connect and never has **(r3)** | `ns1025741 (qm2t…yy4q) · not in a group · joining mac's group: approved here, waiting for mac to approve; mac has not connected since it used the code at 22:19 UTC.` | as above |
| The handshake broke before this computer saved the attempt (redeemer, transient) **(r3)** | printed by `pair`, not held: `The connection ended before this computer could save the attempt. Nothing was approved here.` | `Next here: run the same pair command again` |
| Attempt expired, not approved here | `ns1025741 (qm2t…yy4q) · not in a group · the attempt with mac expired at 22:27 UTC and is closed.` | `Nothing pending. To try again: vox computer invite` |
| Attempt expired, approved here **(r3)** | `ns1025741 (qm2t…yy4q) · not in a group · the attempt with mac expired at 22:27 UTC and is closed here; mac may hold your approval and may have completed it there.` | `Nothing pending. To try again: vox computer invite (if mac shows this computer in its group, run there: vox computer remove qm2t…full…yy4q)` |
| Attempt closed by the other computer | `ns1025741 (qm2t…yy4q) · not in a group · the attempt with mac was closed on mac at 22:21 UTC.` | `Nothing pending. To try again: vox computer invite` |
| Completed here, closed there (CJ-6) **(r3)** | `ns1025741 (qm2t…yy4q) · in a group with mac · this computer completed the pairing; mac closed it on its side at 22:21 UTC (mac's clock) and does not count itself a member.` | `Next here: vox computer remove qfoj…full…j4zq (then pair again with a new code)` |
| Added, never heard from | `mac (qfoj…j4zq) · in a group with beast, vinces-macbook-pro and ns1025741 · ns1025741 was added at 22:19 UTC and has not connected since.` | `Nothing to do here while you wait. If it will not connect: vox computer remove qm2t…full…yy4q` |
| Not yet confirmed elsewhere | `mac (qfoj…j4zq) · in a group with beast, vinces-macbook-pro and ns1025741 · beast has not confirmed the new computer yet.` | `Nothing to do here: beast learns it when it next connects to a computer of the group.` |
| Not yet applied here, automatic **(r3, r9)** | `mac (qfoj…j4zq) · in a group with … · omp-work has not applied the latest change yet.` | `Nothing to do here: omp-work applies it when <ADR-040 NW-1's words for the prerequisite it is parked on: "an earlier change to this room finishes", "node omp-work finishes starting", "a change to this computer's trust is written">; Vox finishes it by itself.` |
| Not yet applied here, a room owes a trust withdrawal (ADR-048 TC-8) **(r3, r9)** | `mac (qfoj…j4zq) · in a group with … · confirmed; room repo-to-cve still has to withdraw the keys of 2 node(s) of computer "ns1025741".` | `Nothing to do here: room repo-to-cve still has to withdraw the keys of 2 node(s); it waits until <ADR-040 NW-1's words for the debt's prerequisite>; posting there is refused until then.` (A closed room: `room repo-to-cve (closed) will withdraw the keys of 2 node(s) when it is next opened`; a permanently refused debt: `…; it cannot: <refusal>; posting there stays refused`, TC-8's words.) |
| Not yet applied here, the node is locked **(r3)** | `mac (qfoj…j4zq) · in a group with … · omp-work has not applied the latest change: it is locked.` | `Next here: vox node unlock omp-work` |
| In a group | `mac (qfoj…j4zq) · in a group with beast, vinces-macbook-pro and ns1025741.` | `Nothing pending.` |
| Two members share a name | `mac (qfoj…j4zq) · in a group with beast, vinces-macbook-pro, ns1025741 (qm2t…yy4q) and ns1025741 (2qwy…u2ta).` | `Two computers are named ns1025741. If 2qwy…u2ta is the old one: vox computer remove 2qwy…full…u2ta` |
| Removal in progress here | `mac (qfoj…j4zq) · in a group with … · removing ns1025741 (2qwy…u2ta): 1 of 2 room removals left.` | `Nothing to do here: repo-to-cve is next (robert-work is admin there); Vox finishes it by itself.` |
| Removal step refused **(r3, r9)** | `mac (qfoj…j4zq) · in a group with … · removing ns1025741 (2qwy…u2ta): repo-to-cve refused the removal of omp-io: <the room's refusal>.` | `Next here: vox room remove-member repo-to-cve 5hrg…full…sssq --node robert-work (or vox computer remove 2qwy…full…u2ta --keep-rooms to stop trying: it keeps the rooms and signs nothing new)` |
| Removal step waiting on a room that cannot open **(r3)** | `mac (qfoj…j4zq) · in a group with … · removing ns1025741 (2qwy…u2ta): repo-to-cve cannot be opened (<error>), so omp-io is not removed from it yet.` | `Next here: vox doctor (the removal finishes by itself once the room opens)` |
| Dismissal pending on a closed room **(r3)** | `mac (qfoj…j4zq) · in a group with … · removed ns1025741 (2qwy…u2ta); r2c-lab is closed here and will stop offering its nodes when it next opens.` | `Nothing to do here.` |
| Leftover member, not removable here | `mac (qfoj…j4zq) · in a group with … · removed ns1025741 (2qwy…u2ta): its node codex-io is still a member of r2c-lab.` | `Next on beast: vox room remove-member r2c-lab cx7q…full…m2ty --node nexus (or any admin of r2c-lab)` |
| Leftover member kept on purpose | `mac (qfoj…j4zq) · in a group with ….` | `Nothing pending. (ns1025741's nodes omp-io and claude-io stay in repo-to-cve: your choice at removal.)` |
| This computer was removed | `ns1025741 (2qwy…u2ta) · removed from the group of mac, beast and vinces-macbook-pro at Nov 12 22:06 UTC.` | `Next here: vox computer advanced retire (stop using the old group on this computer; identities and data stay)` |
| Quarantined or storage failed | `mac (qfoj…j4zq) · in a group with … · this computer's trust store failed: <error>.` | `Next here: vox doctor` |
| Another group established there | `mac (qfoj…j4zq) · in a group with … · ns1025741 is already in a different group.` | `Next on ns1025741: vox computer advanced retire, then pair again` |

Precedence when several apply: quarantined; removed; completed here but closed there; an
attempt whose local approval is missing (always `Next here: approve`, whatever the reach);
an attempt waiting for the other computer (confirm, approve), with its reach clause; a code
open; removal in progress (refused, cannot open, then left); leftover members; a locked node;
not yet applied here; a room owing a withdrawal; dismissal pending; not yet confirmed
elsewhere; shared names; in a group. A line is `Nothing to do here` only when Vox finishes the
wait by itself; whatever needs a person's hand is a `Next here`.

Under the two lines come one line per other computer: its name (with its prefix where CJ-3
requires), its place (`in the group`, `not yet confirmed`, `joining`, `added, not connected`,
`removed <time>`) and its reach (`connected now`, `last heard 40 s ago`, `offline, last seen 3 min ago
(dial failed at 22:19 UTC: <reason>)` (ledger row 27: a computer or node this computer cannot
connect to is `offline`, a plain fact, never "locked" or unhealthy), `has not connected since
22:19 UTC`, `not heard from since this daemon started`).
Then, last: `Everything else: vox computer status --details · What computer trust grants: vox
computer policy`.

### Add a computer

Before anything, on both computers:

```
IO$ vox computer
ns1025741 (qm2t…yy4q) · not in a group.
Nothing pending. To add this computer to a group: vox computer invite
Everything else: vox computer status --details · What computer trust grants: vox computer policy

Commands:
  invite     Make a pairing code (valid 10 minutes)
  pair       Use a pairing code made on another computer
  approve    Approve the pairing that status shows
  cancel     Close a pairing code or attempt
  remove     Remove a computer from your group
  personal   Choose this computer's personal node
  status     This computer's state and the next action (--details for everything)
  policy     What computer trust grants
  advanced   Binding transfer and retirement: only when status tells you to

IO$ vox computer list
vox computer: there is no "list". For the computers in your group and the next action: vox computer
IO$ vox computer binding
vox computer: "binding" moved to vox computer advanced binding; use it only when vox computer status tells you to.

mac$ vox computer status
mac (qfoj…j4zq) · in a group with beast and vinces-macbook-pro.
Nothing pending.
  beast                 in the group · connected now
  vinces-macbook-pro    in the group · last heard 2 min ago
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

Step 1, make the code on IO:

```
IO$ vox computer invite
Pairing code made. Run this on a computer already in your group:
  vox computer pair 'vox-computer://…'
ns1025741 (qm2t…yy4q) · not in a group · pairing code open until 22:27 UTC.
Next on a computer already in your group: vox computer pair 'vox-computer://…' (vox computer invite prints it again)
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

Step 2, use it on the Mac. `pair` connects to IO, shows who it is and what it grants, and asks
once:

```
mac$ vox computer pair 'vox-computer://…'
ns1025741 (qm2t…yy4q) asks to join your group: mac, beast, vinces-macbook-pro.
Its name is what it calls itself; its identity is qm2t…yy4q, proved by the code.
What it grants: every node of these four computers reads every other; robert-work (mac) and
vovando (vinces-macbook-pro) drive every node that is not a personal node. This replaces any
trust you gave these nodes one by one; there are no per-node exceptions. No room is joined.
Full policy: vox computer policy
Trust ns1025741 with this? [y/N] y
Approved here.
mac (qfoj…j4zq) · in a group with beast and vinces-macbook-pro · adding ns1025741: approved here, waiting for ns1025741 to approve.
Next on ns1025741: vox computer approve 2zq4… (on a Mac: My Computers ▸ Trust This Computer)
  beast                 in the group · connected now
  vinces-macbook-pro    in the group · last heard 2 min ago
  ns1025741             joining · connected now
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

When the Mac is not in a group either (the first pairing of two computers), the review's first
line reads `ns1025741 (qm2t…yy4q) asks to pair with this computer: a new group of two.` and the
grants sentence names the two; the rest is the same.

Answering `N` or ending input adds no approval and closes the attempt (CJ-6, ADR-038 FX-42).
It prints `Not approved. The attempt is closed here; ns1025741 sees that when it next connects.
To try again, make a new code on ns1025741.`

Within 5 s, on IO:

```
IO$ vox computer status
ns1025741 (qm2t…yy4q) · not in a group · joining mac's group: mac approved, your approval is missing.
Next here: vox computer approve 2zq4…
mac (qfoj…j4zq) wants to add this computer to its group: mac, beast, vinces-macbook-pro.
What it grants: every node of mac, beast, vinces-macbook-pro and this computer reads every other;
robert-work (mac) and vovando (vinces-macbook-pro) drive every node that is not a personal node.
This replaces any trust you gave these nodes one by one; there are no per-node exceptions.
Full policy: vox computer policy
  mac                   joining · approved · connected now
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

Step 3, approve on IO:

```
IO$ vox computer approve 2zq4…
Approved. ns1025741 is in the group.
ns1025741 (qm2t…yy4q) · in a group with mac, beast and vinces-macbook-pro · beast and vinces-macbook-pro have not confirmed the new computer yet.
Nothing to do here: they learn it when they next connect to a computer of the group.
  mac                   in the group · connected now
  beast                 not yet confirmed · not heard from since this daemon started
  vinces-macbook-pro    not yet confirmed · not heard from since this daemon started
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

Within 5 s of each computer's next exchange (ADR-038 FX-28), on either computer:

```
mac$ vox computer status
mac (qfoj…j4zq) · in a group with beast, vinces-macbook-pro and ns1025741.
Nothing pending.
  beast                 in the group · connected now
  vinces-macbook-pro    in the group · last heard 40 s ago
  ns1025741             in the group · connected now
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

### When an attempt cannot finish

The Mac cannot reach the computer that made the code. `pair` fails at once; nothing is held on
either computer:

```
mac$ vox computer pair 'vox-computer://…'
Could not reach ns1025741 at 203.0.113.7:41641 or [2001:db8::7]:41641 (dial failed: no route to host). Nothing was approved; the code is still valid until 22:27 UTC.
Next: run the same command again when ns1025741 is reachable, or make the code here instead (vox computer invite) and run the pair command on ns1025741.
```

The redeemer did not confirm saving the attempt: its record failed (it printed `this computer's
policy changed while pairing ran; run the same pair command again`), or its daemon died before
saving, or it saved and the confirmation was lost. The inviter cannot tell these apart and says
so; the same code resumes or shows the attempt (CJ-5; this is the 19:45 state):

```
mac$ vox computer status
mac (qfoj…j4zq) · in a group with beast and vinces-macbook-pro · adding ns1025741: approved here; ns1025741 used the code but has not confirmed that it saved this attempt (it may have saved it and the confirmation was lost).
Next on ns1025741: vox computer pair 'vox-computer://…' again (the same code resumes this attempt there; if it already holds it, that shows its status)
  beast                 in the group · connected now
  vinces-macbook-pro    in the group · last heard 2 min ago
  ns1025741             joining, not confirmed · last heard 3 min ago
Everything else: vox computer status --details · What computer trust grants: vox computer policy

IO$ vox computer pair 'vox-computer://…'
mac (qfoj…j4zq) wants to add this computer to its group: mac, beast, vinces-macbook-pro. mac already approved.
…
Trust mac's group with this? [y/N] y
Approved. ns1025741 is in the group.
```

The other computer approved and then went away (its daemon stopped, or the network dropped).
On the computer that must be dialled:

```
IO$ vox computer status
ns1025741 (qm2t…yy4q) · not in a group · joining mac's group: approved here, waiting for mac to approve; mac has not connected since 22:19 UTC.
Next on mac: vox computer approve 2zq4… (mac connects to this computer by itself; to give up here: vox computer cancel 2zq4…)
  mac                   joining · has not connected since 22:19 UTC
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

Closing it, at once, on whichever computer holds it (Q1). What the closer is told depends on
what the other computer can do with what it already has (CJ-6). The closure is a fact this
computer keeps for good and tells the other computer at every later contact until the other
acknowledges it. When the other computer cannot complete without this one (this computer is
the sponsor of an addition, or it never approved):

```
mac$ vox computer cancel 2zq4…
Closed. This pairing cannot complete anywhere: ns1025741 needs this computer's addition, which will not be made. ns1025741 sees the closure when it next connects here.
mac (qfoj…j4zq) · in a group with beast and vinces-macbook-pro.
Nothing pending.
…
```

When the other computer may complete it alone (a first pairing, or it is the sponsor) and this
computer has already approved:

```
IO$ vox computer cancel 2zq4…
Closed here. mac may already hold your approval and may complete the pairing on its side, and any computer already in mac's group would then trust this one until mac removes it. If mac's status shows this computer in its group, run there: vox computer remove qm2t…full…yy4q, then pair again with a new code. mac sees this closure when the two next connect.
ns1025741 (qm2t…yy4q) · not in a group.
Nothing pending. To add this computer to a group: vox computer invite
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

Later `vox computer status` on the closer keeps the local-only words while the closure is
unacknowledged **(r4)**: `… · not in a group · the attempt with mac was closed here at 22:21
UTC; mac has not confirmed receiving the closure (it may have received it and the confirmation
was lost) and may have completed the pairing there.` with `Nothing pending. To try again:
vox computer invite`. When the computers next exchange, the other holder shows `… · the attempt
with ns1025741 was closed on ns1025741 at 22:21 UTC.` and `Nothing pending.` If it had completed
the pairing, it shows instead:

```
mac$ vox computer status
mac (qfoj…j4zq) · in a group with ns1025741 · this computer completed the pairing; ns1025741 closed it on its side at 22:21 UTC (ns1025741's clock) and does not count itself a member.
Next here: vox computer remove qm2t…full…yy4q (then pair again with a new code)
  ns1025741             added, closed there · connected now
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

No order between the two acts is claimed: the closer's time is its own clock, and the
completion may have come before or after it. `vox computer remove` there is the ordinary removal
below; a third member that received the addition learns that removal as it learns any other.
Until the two connect, the completing computer shows `ns1025741 was added at 22:19 UTC and has
not connected since` with the removal offered. Cancelling a completed pairing is refused, as
today: `this pairing is established; to undo it: vox computer remove <fingerprint>`.

Expiry closes an attempt that is not complete here, with the same two kinds of words: not
approved here, `… · the attempt with mac expired at 22:27 UTC and is closed.`; approved here,
`… expired at 22:27 UTC and is closed here; mac may hold your approval and may have completed it
there.` with the removal command for mac. A new code can be made at once either way.

### Replace a rebuilt computer

IO was rebuilt. It has a new identity under the same name. The old one is still in the group.

```
mac$ vox computer status
mac (qfoj…j4zq) · in a group with beast, vinces-macbook-pro and ns1025741.
Nothing pending.
  beast                 in the group · connected now
  vinces-macbook-pro    in the group · last heard 2 min ago
  ns1025741             in the group · offline, last seen Nov 11 09:19 UTC
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

On the rebuilt IO, `vox computer invite` as in step 1. On the Mac, the preview says it is a
different computer:

```
mac$ vox computer pair 'vox-computer://…'
ns1025741 (qm2t…yy4q) asks to join your group: mac, beast, vinces-macbook-pro, ns1025741 (2qwy…u2ta).
This is a different computer from the ns1025741 in your group (2qwy…u2ta, offline, last seen Nov 11 09:19 UTC). A name is what a computer calls itself; nothing is carried over from the old one.
If it replaces that one, remove the old one after pairing: vox computer remove 2qwy…full…u2ta
What it grants: every node of these five computers reads every other; robert-work (mac) and
vovando (vinces-macbook-pro) drive every node that is not a personal node. This replaces any
trust you gave these nodes one by one; there are no per-node exceptions. No room is joined.
Full policy: vox computer policy
Trust ns1025741 (qm2t…yy4q) with this? [y/N] y
```

Steps 2 and 3 continue as for an addition. While both are in the group:

```
mac$ vox computer status
mac (qfoj…j4zq) · in a group with beast, vinces-macbook-pro, ns1025741 (qm2t…yy4q) and ns1025741 (2qwy…u2ta).
Two computers are named ns1025741. If 2qwy…u2ta is the old one: vox computer remove 2qwy…full…u2ta
  beast                    in the group · connected now
  vinces-macbook-pro       in the group · last heard 2 min ago
  ns1025741 (qm2t…yy4q)    in the group · connected now
  ns1025741 (2qwy…u2ta)    in the group · offline, last seen Nov 11 09:19 UTC
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

Then the removal below. Afterwards the old one is shown only while something about it is pending
or while it shares a name with a member (CJ-13):

```
  ns1025741 (2qwy…u2ta)    removed Nov 12 22:06 UTC
```

### Remove a computer

```
mac$ vox computer remove 2qwy…full…u2ta
Remove ns1025741 (2qwy…u2ta) from your group?
  Its nodes omp-io, claude-io, codex-io and opencode-io lose read and drive on every computer of
  the group, including trust you gave them one by one before pairing.
  Data it already received is not erased. A computer that is not reachable now applies the
  removal when it next connects.
  Its nodes are members of these rooms:
    repo-to-cve   omp-io, claude-io   robert-work is admin here: they are removed from it too (--keep-rooms keeps them)
    r2c-lab       codex-io            only nexus (beast), its creator, or an admin of r2c-lab can remove it; status will say so until it is gone
  Only the creator can readmit a removed room member.
Remove ns1025741 (2qwy…u2ta)? [y/N] y
Removed ns1025741 (2qwy…u2ta). Removed omp-io and claude-io from repo-to-cve.
mac (qfoj…j4zq) · in a group with beast, vinces-macbook-pro and ns1025741 (qm2t…yy4q) · removed ns1025741 (2qwy…u2ta): its node codex-io is still a member of r2c-lab.
Next on beast: vox room remove-member r2c-lab cx7q…full…m2ty --node nexus (or any admin of r2c-lab)
  beast                    not yet confirmed · connected now
  vinces-macbook-pro       not yet confirmed · last heard 2 min ago
  ns1025741 (qm2t…yy4q)    not yet confirmed · connected now
  ns1025741 (2qwy…u2ta)    removed Nov 12 22:06 UTC
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

The room line is the default of Q3 (evict from rooms this computer administers, `--keep-rooms`
to keep). If the decider chooses the alternative, the question `Also remove omp-io and claude-io
from repo-to-cve? Only the creator can readmit them. [y/N]` follows the first.

`--confirm <frontier>` still runs it without questions, for scripts, with `--keep-rooms` or
not; the frontier is in `--details`. If the daemon, the CLI or the app stops between the
computer removal and a room removal, the next `vox computer status` shows `removing ns1025741
(2qwy…u2ta): 1 of 2 room removals left` and the daemon finishes it by itself (CJ-12). Once every
remaining computer has confirmed it and the leftover member is gone:

```
mac$ vox computer status
mac (qfoj…j4zq) · in a group with beast, vinces-macbook-pro and ns1025741 (qm2t…yy4q).
Nothing pending.
  beast                    in the group · connected now
  vinces-macbook-pro       in the group · last heard 2 min ago
  ns1025741 (qm2t…yy4q)    in the group · connected now
  ns1025741 (2qwy…u2ta)    removed Nov 12 22:06 UTC
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

The last line stays only because the two share a name (CJ-3). On the removed computer, if it is
ever reachable again:

```
old-IO$ vox computer status
ns1025741 (2qwy…u2ta) · removed from the group of mac, beast and vinces-macbook-pro at Nov 12 22:06 UTC.
Next here: vox computer advanced retire (stop using the old group on this computer; identities and data stay)
Everything else: vox computer status --details · What computer trust grants: vox computer policy
```

### In the app

My Computers shows the state line and the next line at the top, from the same daemon fields.
The daemon's `next.action` names the button; the app never parses the command sentence. The
primary button is the next action when it belongs on this computer; when the next line is
`Nothing pending.` the primary button is Add Computer. Nothing else is above the fold; the
policy is behind "Policy…". Every failed request shows the daemon's sentence under the button
that caused it, with Retry; the buttons stay enabled (CJ-4). When the daemon cannot answer at
all, that is the outcome: `Vox is not answering: <error>` and Retry; no code and no refusal is
invented.

| State | Header | Primary button | Also offered |
|---|---|---|---|
| Not in a group | the two lines | Add Computer (makes a code) | Use a Pairing Code |
| Code open | the two lines, the code, Copy Command, "run it on <where>" | Add Computer (shows the same code again) | Cancel Code |
| Joining, your approval missing | the two lines, the review (peer, prefix, group, what it grants, the replaced-grants sentence) | Trust This Computer | Cancel Pairing, Policy… |
| Adding/joining, the other must act | the two lines with the reach clause | none | Cancel Pairing, Copy Command for <other> |
| Other has not confirmed saving | the two lines | none | Copy Pair Command for <other>, Cancel Pairing |
| Expired, or closed there | the two lines | Add Computer | — |
| Completed here, closed there | the two lines | Remove <other>… | — |
| Not yet confirmed (here or elsewhere) | the two lines, one row per computer | Add Computer | Remove… per row |
| Not yet applied here, the node is locked **(r4)** | the two lines | Unlock <node>… (`Action::Unlock { node }`: the existing outside-harness passphrase sheet for that node, as `vox node unlock` in a terminal) | — |
| In a group | the two lines, one row per computer | Add Computer | Remove… per row |
| Removal in progress | the two lines, the rooms left with each result | none | — |
| Removal step waiting on a locked acting node **(r4)** | the two lines | Unlock <node>… (same action) | — |
| Leftover member | the two lines | Remove From Room (only if this computer can) | Copy Command for <other> |
| Leftover kept on purpose | the two lines | Add Computer | — |
| This computer was removed | the two lines | Retire… (the existing retirement review) | — |
| Quarantined / storage failed | the two lines | Open Doctor | — |
| Another group established there | the two lines | none | Copy Command for <other> |
| No daemon answer yet | "Vox is not answering: <error>" | Retry | — |

Add Computer: click → the code and `vox computer pair '…'` within 5 s, or the daemon's
refusal under the button with Retry, or `Vox is not answering` with Retry. The request is not
queued behind a refresh; if it times out the app re-issues `invite`, which returns the open code
(CJ-8), so a code made just before the timeout is shown and never duplicated. One ownership
rule **(r5)**: operator actions (invite, cancel, approve, remove) run one at a time, in click
order, on their own connection, never behind a refresh; the window's status is owned by the
most recent *accepted* action's result or by a refresh that started after it; a response owns
nothing merely by arriving. A late result of an action that is no longer the most recent is
reported under its button (`Pairing code made, then cancelled` / `Pairing code made (the one
shown)`) and does not touch the status; after every applied action result the app starts a
fresh refresh (CJ-4). Use a Pairing Code: paste → the review above (peer
identity with prefix, the group, what it grants, the replaced-grants sentence, "different
computer" when a name collides) → Trust This Computer approves exactly the operation id shown
(the request carries it; a changed operation is refused as today, `pairing.rs:1595-1599`) →
the header shows "waiting for <other> to approve" with its reach → within 5 s of the other's
approval, "in a group". Cancel Pairing closes at once with the same sentence as `cancel`. A
window closed and reopened shows the state from the daemon, not from the sheet. Two Macs
complete the flow with Add Computer on one and Use a Pairing Code on the other; a headless peer
completes it with the printed command.

## Requirements

Each requirement gives the rule, why (the fix-list item it prevents), what changes, what is
deleted and its proof. "The pairing journey" is `local_nodes_trust_each_other_without_a_prompt_and_remember_removals`
(`nodes_of_one_daemon_proof.rs:556`) with `pair_computers` (`:1743`), `enroll_third` (`:2365`)
and `close_expired_pairing` (`:2659`). "The removal journey" is
`enrolled_computers_follow_node_changes_and_retire_removed_authority` (`:4512`). Both are blocking
proofs, run in release. **(r6, ledger row 32)** Every proof here is stageable inside the macOS
guest or the Linux VM of ADR-045's fleet, never on the operator's host: scratch roots, scratch
daemons, `test-knobs` builds and the app proof's scratch profiles all live in the guest. A red
says PRODUCT and quotes what `vox` printed, or says APPARATUS when
staging failed. "Stop a daemon" in a proof means SIGTERM or SIGKILL to the pid in the scratch
root's `.daemon/lock`, after `ps -o command=` names that root. A v0.4.30 red is marked KNOWN
(run named) or UNVERIFIED (the run that would verify it named).

### 1. One state, one next action

- **CJ-1. The first two lines. (changed, r9)** The plain `vox computer status`, bare `vox computer`
  and the top of My Computers MUST begin with the same two lines, computed once by the daemon:
  the state line and the next line, worded as in "The states, and their two lines", chosen by
  that table's precedence. The next line is one of `Next here: <command>`, `Next on <computer>:
  <command>`, `Nothing to do here: <who> <what>` or `Nothing pending.`, and any command in it
  is complete, copyable and executable as printed: a computer in a command is its full
  fingerprint, a node its full fingerprint, a room its name, quoted by the convention above.
  Prose and peer rows show prefixes. After the two lines the plain output holds only one line
  per other computer, the pairing review while this computer's approval is missing (ADR-038
  FX-41), and the closing `Everything else:` line. It MUST NOT hold the policy paragraph,
  `Policy:` lines, fingerprints outside commands, installation ids, revisions, frontiers,
  binding actions or exchange counters. No state is ever labelled `Nothing to do here` while a
  local action is blocked; a blocked local action is a `Next here` (a locked node of this
  computer, the only node ever called locked, ledger row 24: `vox node unlock <name>`; a room that cannot open: `vox doctor`). **(r3)** The "not yet applied here"
  words are ADR-040 NW-1's prerequisite words for the prerequisite the application is parked on
  and ADR-048 TC-8's `room <name> still has to withdraw the keys of <k> node(s); it waits until
  <ADR-040 NW-1's words for the debt's prerequisite>` for a trust debt (with TC-8's closed-room
  and permanently-refused forms), read from the daemon's typed not-yet, never a placeholder
  (r9: TC-8 is the requirement, "withdraw the keys of" its words; there is no NW-5 in ADR-048).
  - *Why*: item 34; the decider's "unreadable" and "no clue what to do"; review finding 9.
  - *What changes*: `ComputerStatus` (`pairing.rs:263`) is to gain `summary: String`,
    `next: Next { on: Option<ComputerIdentity> /* None = here */, action: Action, command:
    Option<String>, words: String }` with `Action` one of `None`, `Invite`, `Pair { code }`,
    `Approve { operation }`, `Cancel { operation }`, `Remove { computer }`, `RoomRemove { room,
    node, acting_node }`, `Unlock { node }` **(r4)**, `Retire`, `Doctor`, and `peers: Vec<PeerLine { name, fingerprint,
    shown_as, place: "in" | "unconfirmed" | "joining" | "joining-unconfirmed" | "added-silent" |
    "removed", last_heard_ms: Option<u64>, reach: Reach, removed_ms: Option<u64> }>`, derived in
    `status` (`:1809`). `last_heard_ms` comes from the exchange records; `reach` from CJ-7. The
    plain branch of `show` (`computer_cli.rs:312`) prints only these. A new read-only `vox
    computer policy` prints the policy text (`computer.rs:268`) and the topology as one line
    each. `--details` keeps everything else under headings: This computer, Policy, Computers,
    Nodes, Available binding actions, Removed computers, Diagnostics. `--json` keeps every field
    and adds the new ones (format change; v0.4.x has no prior-release requirement).
  - *Deleted*: the plain-mode policy paragraph (`computer_cli.rs:354`) and `Policy:` lines
    (`:442-444`); the "previously exchanged; current connectivity unknown" family (`:445-464`);
    the pairing block's `approved here: …; approved there: …` lines and approval texts
    (`:388-429`), replaced by the two lines.
  - *Proof*: the pairing journey, at each state it stages (not in a group, code open, joining
    with each side to act, not confirmed, closed there, completed here but closed there, not yet
    confirmed, in a group): run `vox computer status` and bare `vox computer` on both accounts
    and assert the first two lines exactly, with the scratch names and prefixes, and that
    `binding`, `frontier`, `installation` and `revision` appear only under `--details`. Every
    printed `Next` command is then run on the computer it names and must be accepted. v0.4.30
    prints the policy paragraph as line 2: red, PRODUCT, KNOWN (`run-e3`). `enroll_third`'s
    plain-status policy assertion (`:2547-2558`) moves to `vox computer policy`. Mutant: print
    `policy` before `summary`; the first-line assertion turns red. Second mutant: print the
    prefix in the `remove` command; running it turns red with the CLI's refusal.

- **CJ-2. Bare `vox computer`. (changed)** `vox computer` with no subcommand MUST print CJ-1's
  status and then the command list shown in "Add a computer", and exit 0. `binding` and `retire`
  MUST be listed under `vox computer advanced`, whose help says to use them only when `vox
  computer status` says so (Q4). An unknown or moved subcommand (`list`, `binding`, `retire`)
  MUST print one actionable line naming the command to use, as in the transcript, and exit 2;
  no alias is kept.
  - *Why*: item 34; the decider ran `vox computer list` and `vox computer binding` first.
  - *What changes*: `Cmd::Computer` (`cli.rs:2467`) takes an optional subcommand; `ComputerCmd`
    (`computer_cli.rs:9`) gains `Policy` and `Advanced { Binding | Retire }`; the error for an
    unknown subcommand is the one line above.
  - *Deleted*: the top-level `Binding` and `Retire` variants (moved, not kept as aliases).
  - *Proof*: the pairing journey: bare `vox computer` on an unpaired and a paired account; assert
    exit 0, first two lines equal to `status`'s, and the nine command names; `vox computer list`
    and `vox computer binding` exit 2 with the two lines above. v0.4.30 prints Clap's help with
    no state: red, PRODUCT, KNOWN (operator transcript). Mutant: fall back to Clap's help.

- **CJ-3. A computer cannot be mistaken for another.** The state line MUST show this computer's
  fingerprint prefix. Another computer's name MUST carry its prefix wherever that name equals the
  name of this computer, of a current member or of a removed computer still shown. A pairing
  review MUST show the peer's prefix, say that the name is what the computer calls itself and the
  fingerprint what the code proved, and when the peer's name equals a member's name it MUST say
  that it is a different computer and name that member with its prefix and reach. When two
  prefixes collide among the computers shown, those two are shown with their full fingerprints.
  - *Why*: item E-a and item 34; the second `ns1025741` of Nov 12.
  - *What changes*: `PeerLine.shown_as`; the review sentences; node lines in `--details` name
    their computer by `shown_as`. Names stay labels (ADR-035 CT-1); nothing matches by name.
  - *Deleted*: none.
  - *Proof*: the proof's accounts share the host name, so every staged pair collides. In the
    pairing journey assert the prefixes in the state line and peer lines and, in the removal
    journey's replacement step (CJ-9), the "different computer" sentence. v0.4.30 prints `mac`
    twice with no way to tell them apart: red, PRODUCT, KNOWN (`run-e2`). Mutant: drop `shown_as`
    from the peer rows; the "no two lines name a computer the same way" assertion turns red.

- **CJ-4. The app says the same, never queues the click, and never lets an old answer undo a
  new one. (changed, r3)** My Computers MUST show `summary` and `next.words` at the top and
  offer the button named by `next.action` as its one primary button, as the table in "In the
  app" says. Create Pairing Code (Add Computer) MUST NOT be disabled because the last daemon
  request failed, nor while a code is open (it shows the same code again), nor queued behind a
  status refresh; it MUST show, within 5 s of the click, the code, or the daemon's refusal, or
  `Vox is not answering: <error>`, each with Retry, and on a timeout it MUST re-issue `invite`
  once and show the open code if there is one. **(r5)** One ownership rule for the window's
  status: operator actions (mutations) MUST run one at a time in the order clicked, never
  queued behind a refresh and never concurrently with each other; the status MUST be owned by
  the result of the most recent *accepted* action (the last one to return) or by a refresh that
  started after that result was applied; a refresh that began before or during an action MUST be
  dropped whenever it arrives, and an action's result that returns after a later action was
  accepted MUST NOT replace the status (it is reported under its button only). A response owns
  the status by this rule, never merely by arriving. Every action's outcome MUST still be
  reported. A fresh refresh MUST follow every applied action result. Trust This Computer MUST submit the operation
  id it displayed. Cancel Pairing MUST be offered whenever this computer holds an attempt that
  is not complete. When no status has been read yet, the header says so with Retry.
  - *Why*: items 34 and 35 (conditions 3, 6 and 7) and 33; review findings 4 and 11.
  - *What changes*: `ComputerTrust.swift` header (`:103-150`) reads the new fields; the policy
    text moves behind "Policy…"; `ComputerTrustModel.perform` (`:18-27`) loses the
    `waitingOperator` queue: an operator action opens its own request at once, with `AppRequest`
    deadline 5 s for `invite`, `cancel` and `status` and 20 s for `pair` (its dial bound), while
    the refresh keeps its own connection; `perform` **(r5)** gains an operator-action serial
    queue (one action in flight, click order; actions never wait for a refresh), a status owner
    (`status`, `problem` and `actionProblem` are written only by the most recent accepted
    action's result or by a refresh started after it; a late action result goes to its button's
    note), and the refresh-start fence; `:546-551` keeps only the `removed` and quarantined conditions; `:587-600` loses the
    `closeExpired` distinction; the approve button needs a status read since the window opened,
    not `reachable`.
  - *Deleted*: `applicationState`'s duplicate wording; "Approved here. Confirm on X" (`:484`);
    the wait-for-expiry texts (`:410-412`, `:573`); the queue in `perform`.
  - *Proof*: app evaluations are optional proofs (ADR-035 CT-21, ADR-018), listed in
    `docs/release/optional-proofs.md`. `apps/macos/VoxAppProofs/FirstRunProof.swift` is extended
    through a real two-computer pairing on scratch profiles: My Computers on A; Add Computer →
    the code appears ≤ 5 s; B (a second scratch daemon driven by the CLI) runs the printed
    command with `--preview`; A's header reads "your approval is missing" with the review; click
    Trust This Computer on A; A's header reads "waiting for <B> to approve"; B approves (CLI);
    A's header reads "in a group" ≤ 5 s; then A's Remove… through the sheet with the room line;
    then the failure path: stop A's daemon, click Add Computer, assert `Vox is not answering`
    under the button and Retry, start the daemon, Retry shows a code. Ordering **(r4)**: with the
    `test-knobs` holds `VOX_TEST_HOLD_STATUS_REPLY_FILE` (the daemon parks one `status` reply
    until released) and `VOX_TEST_HOLD_INVITE_BEFORE_WRITE_FILE` (`begin` parks after admission,
    before its write), two cases: (i) a refresh is started and parked, Add Computer is clicked
    and shows the code, the refresh is released; (ii) Add Computer is clicked and parks, a
    refresh is started and parks, the invite is released and the code shows, the refresh is
    released; in both, assert the code is still shown. Timeout and readback **(r6)**: the
    `test-knobs` hold `VOX_TEST_HOLD_INVITE_REPLY_FILE` parks `begin` after the invitation is
    durably installed and its status snapshot taken, before the reply, outside the invitation
    lock; Add Computer parks there; the 5 s timeout fires (`AppRequest` clears its continuation,
    `AppRequest.swift:20, 36-43`, so the old reply can never reach the model) and the readback
    (`invite` again) returns the same code X; Cancel Code is clicked and the status shows `not
    in a group`; the old reply is released; assert X stays absent from the window. Serial
    ownership **(r7)**: a code X is open and displayed (Code open row, Cancel Code offered); the
    `test-knobs` hold `VOX_TEST_HOLD_INVITE_BEFORE_LOOKUP_FILE` (`<arm>\t<engaged>\t<release
    socket>`: `begin` parks after admission and before its live-code lookup, outside the
    invitation lock, creating `engaged`) is armed; Add Computer is clicked and parks (the proof
    waits for `engaged`; absent within 5 s → APPARATUS); Cancel Code is clicked while the hold
    is held; 2 s later the apparatus releases the hold whether or not the cancel has returned;
    the proof waits until the window shows no busy button, then runs `vox computer status` on
    A's scratch root and reads the window. Expected: the invite returned X (a live code is
    returned again, CJ-8), then the cancel closed X; `vox computer status` line 1 is `<A> ·
    not in a group.` and line 2 `Nothing pending. To add this computer to a group: vox computer
    invite`; `--json` `.invite_link` is `null`; the window header equals those two lines and
    offers Add Computer. Assertion: no open code at all (not merely "X absent"). Mutant 4:
    dispatch operator actions concurrently (drop the serial admission): the cancel runs during
    the hold and closes X; the released invite finds no live code and makes a new code Y;
    `vox computer status` line 1 reads `<A> · not in a group · pairing code open until <time>.`
    and `.invite_link` is non-null; red on the "no open code" assertion. Staging not reached
    (Cancel Code not offered because X is not displayed; `engaged` absent; the window still busy
    after 20 s) is APPARATUS, never a verdict. Log order is not consulted. Mutant 1: restore the
    `waitingOperator` queue and stage a refresh against a stopped daemon before the click; the
    ≤ 5 s assertion turns red. Mutant 2: order results by request start (revision 3's rule);
    case (ii) removes the code; red. Mutant 3: submit `pairing.operation_id` read at click time from a stale
    model after a second `pair` replaced it; the daemon's refusal turns the "in a group"
    assertion red. v0.4.30: UNVERIFIED on the asset (the click was not captured; E35 shows the
    daemon mechanism only). The words come from the daemon, so CJ-1's CLI proof carries the
    blocking assertion.

### 2. Adding

- **CJ-5. The inviter owns the attempt; the redeemer resumes it. (changed)** Invariants:
  (I1) the redeemer holds an attempt only if the inviter recorded it first, naming the redeemer
  by its authenticated identity; (I2) a code is reserved for the redeemer named by the inviter's
  record: that redeemer may present it again and resumes the same operation with every approval
  already made on either side; any other identity is refused; (I3) a record grants nothing: only
  two approvals and activation do; (I4) when the two computers next exchange with each other,
  both hold the same operation with the union of its approvals, or both show it closed, or the
  one that completed it shows the other's closure with the removal command (CJ-6), however
  long the two were apart. The inviter MUST say truthfully whether the redeemer has confirmed
  saving the attempt, MUST NOT say that the redeemer lost its record (the confirmation may have
  been lost instead), and until it is confirmed MUST name `pair` again on the redeemer as the
  next action. Nothing is undone on either computer at a failed send; there is no rollback.
  - *Why*: item 33, mechanism 2; IO holding nothing while the Mac told the person to approve
    there, 19:39–19:49; review finding 1 (an instantaneous two-holder invariant is unachievable).
  - *What changes*: the inviter's record (`answer`, `:3203-3229`) stays first and stays the
    owner; the attempt gains `peer_recorded_ms: Option<u64>` in `State` (persisted with
    `pending`, one transaction). It is set by (a) a last handshake frame `recorded(operation)`
    sent by the redeemer after its own durable record (`pair`, after `:2866`), and (b) any later
    authenticated exchange from the redeemer whose `pending` names the operation (`merge`,
    `:5495`). Both are idempotent. The redeemer's `pair` on a record failure prints the reason
    and `Next here: run the same pair command again`; on a lost connection after the inviter's
    reply it prints `the connection ended before this computer could save the attempt; run the
    same pair command again`. `pair` with a code this computer already holds returns the status
    (today's `:1364-1370`). The pairing operation number changes from 3 (`PAIR_OP`, `:19`) to 5
    for the new frame; a peer using 3 gets the software-update refusal that 1 gets today
    (`:2891-2895`). Crash windows, A inviter, B redeemer: (1) A dies before its record: nothing
    anywhere, the code is open, B's `pair` fails and says to run it again; (2) A records and
    dies before its reply: A holds, unconfirmed; B holds nothing; A's status names `pair` again
    on B; B's replay resumes; (3) B's record fails or B dies before it: as (2); (4) B records and
    dies before `recorded`: both hold; A unconfirmed until B's next exchange (B dials A by
    itself while it holds an incomplete attempt, `retry` `:3424-3431`), then confirmed; B's
    `pair` again returns its status; (5) the frame is sent and lost: as (4); (6) A receives the
    frame and dies before persisting it: as (4). In every window the person's next command is
    the one on the next line, and the same code never serves another identity.
  - *Deleted*: the `On that computer, review and approve` text when the peer has not confirmed
    (`computer_cli.rs:417-426`).
  - *Proof*: the pairing journey, three stagings, each in a `test-knobs` build with a causal
    hold and nothing on the installed release. (a) Redeemer dies before its record
    **(r3)**: the hold `VOX_TEST_HOLD_PAIR_BEFORE_RECORD_FILE` (`<arm>\t<engaged>\t<release
    socket>`: `pair` parks after the inviter's reply and before its own transaction at `:2818`,
    creating `engaged`); A invites; B `pair --preview` engages; A approves; SIGKILL B at
    `engaged`; start B; assert A's state line contains `has not confirmed that it saved this
    attempt` and the next line `Next on <B>: vox computer pair`; B runs the printed command and
    approves; both show `in a group` ≤ 5 s; a third scratch account presenting the code is
    refused `already consumed by another identity`. v0.4.30: UNVERIFIED for this staging (no
    hold on the asset); the nearest asset receipt is X2 (`/tmp/adr043/run-x2/timeline.log`;
    receipt lost in the reboot of 2026-11-13; figure recorded in `adr-043-revision`; to be re-run as the fleet baseline;
    02:41:54Z), where B's record was absent by rollback rather than by a crash and A printed `On
    that computer, review and approve …`: it shows the status defect, not this proof's red.
    Mutant: set `peer_recorded_ms` at the inviter's own record; A says confirmed while B holds
    nothing; the state-line assertion turns red. (b) Inviter killed between record and reply:
    a `test-knobs` build with a new hold `VOX_TEST_HOLD_PAIR_ANSWER_AFTER_RECORD_FILE`
    (`<arm>\t<engaged>\t<release socket>`: `answer` parks after its record and before its
    reply, creating `engaged`); the proof waits for `engaged`, SIGKILLs A, asserts B's `pair`
    says to run it again, starts A, asserts A's two lines as in (a), B replays, both in a group.
    Mutant: skip the resume branch in `answer` (treat a reserved code as consumed); B's replay
    assertion turns red. (c) Redeemer killed after record, before `recorded`: the
    `test-knobs` hold `VOX_TEST_HOLD_PAIR_AFTER_RECORD_FILE` parks `pair` after `:2866`; SIGKILL
    B; start B; assert A unconfirmed, then confirmed ≤ 5 s of B's restart without a new `pair`.
    Mutant: drop branch (b) of `peer_recorded_ms`; the ≤ 5 s assertion turns red. v0.4.30 for
    (b) and (c): UNVERIFIED on the asset (no hold exists there; a kill by hand cannot land in
    the window); the installed release holds no knob (AGENTS.md).

- **CJ-6. Whoever holds an attempt can close it at once, and is told what that means. (changed,
  r3, Q1)** A computer holding an attempt that is not complete here MUST be able to close it at
  once, approved or not: `vox computer cancel <operation>` MUST answer within 2 s (CJ-8's bound;
  busy → its refusal). Closing records the operation as closed here with the time, moves it out
  of `pending`, and MUST NOT claim anything about the other computer beyond what this computer
  knows. The closing line MUST be one of two sentences, chosen by what the other computer can do
  with what it already holds: when this computer is the sponsor of an addition, or never
  approved, `Closed. This pairing cannot complete anywhere: …` (true: no addition will be
  published, or no second signature exists); otherwise `Closed here. <other> may already hold
  your approval and may complete the pairing on its side, and any computer already in <other>'s
  group would then trust this one until <other> removes it …` with the removal command for the
  other computer, and the later status keeps the local-only words while the closure is
  unacknowledged. A closure is a durable fact that is never aged out: it MUST be conveyed to the
  attempt's other computer on every authenticated contact between the two, in either direction
  and whatever either computer's group state, until that computer acknowledges it. The other
  holder MUST show `closed on <closer> at <time>` within 5 s of that contact and close too if it
  has not completed; if it has completed, it MUST keep its authority state, show "this computer
  completed the pairing; <closer> closed it on its side at <closer's time>" (no order between
  the two acts is claimed) and offer `vox computer remove <closer>`; a third member that received
  the addition learns that removal as an ordinary control event once it is accepted. Cancelling
  a completed pairing stays refused and names `remove`. An expired incomplete attempt is closed
  the same way, with the same two kinds of words, by whichever of `status`, `begin` or `cancel`
  sees it first; expiry does not retract an exported signature either. A closed attempt MUST NOT
  block a new code. Answering `N` or EOF at `pair`'s question closes the attempt and adds no
  approval (ADR-038 FX-42).
  - *Why*: item 33, mechanism 3; "how do I fix the half way pair"; review finding 2 (a close
    cannot withdraw a signature the other computer holds); second review F1, F7, F8.
  - *What changes*: `cancel` (`:1277`) loses the refusal at `:1320-1321` and gains the two
    sentences; `State.cancelled` entries gain `closed_ms`, `peer: Digest32` (the attempt's other
    computer), `acknowledged: bool` and `learned_from: Option<Digest32>`; `begin`
    (`:1224-1231`) ignores closed attempts and closes an expired one. *Wire.* The exchange
    payload (`exchange`, `:5252-5297`), the op-2 reply and the closure-only payload below gain a
    sixth element `closed: [(operation, closed_ms)]`, derived at encoding time from every
    `cancelled` entry whose `peer` is the receiver and `acknowledged` is false, and a seventh
    `acknowledged: [operation]` naming the closures this computer has recorded from that peer;
    the three decoders of that payload, `merge` (`:5495`), `authenticated_group_conflict`
    (`:5313`, arity 5 today) and the op-2 reply reader in `sync_peer` (`:4188`), read seven
    elements; there is no five-element form left. *Authorization of a closure (r4).* A closure
    or an acknowledgement is an assertion by one of the two computers of an attempt about that
    attempt, and nothing else: on receipt, each listed operation is resolved against this
    computer's retained attempt of that exact operation id (in `pending`, `cancelled`, `genesis`
    or a history addition; the id is the hash of the body, `computer.rs:468`, so it names one
    nonce, two identities and two grants); the authenticated sender (`conn.peer_id()`, bound to
    the hello's description at `:5141-5143`) must be the *other computer of that attempt*
    (`side(g, &peer)` succeeds, `:4837`), and for an acknowledgement the entry's `peer`; an
    operation this computer does not hold, or whose other party is not the sender, is ignored
    and creates no tombstone and clears no flag. This is why a former member, or any other
    recognized peer, cannot close a pairing it is not party to (B's attempt with C has C's
    identity in its body; A is not `side` of it), why a replayed old closure touches only its
    own old nonce and never a fresh operation, and why no new signed authority type is needed:
    the sender's QUIC identity and the body it is named in are the authorization. The same check
    runs in the full exchange, the closure-only exchange and the conflict preview. `merge`
    reads `closed` before the genesis/intent checks: an operation so authorized is closed here
    (not complete here) or recorded as `closed_after_completion` (complete here); `acknowledged`
    sets the flag on the matching entries; then the exchange continues. In the conflict preview
    (`pair` against a computer established in another group, `:2806-2808`) an authorized closure
    naming the proposed operation closes the preview with "closed on <peer>" and nothing else
    from that payload is admitted. *Closure-only exchange.* `exchange` today requires `s.group()`
    (`:5252-5255`) and `cancel` of a genesis clears the group staging (`:1339-1346`); a computer
    that holds no group but owes a closure encodes a closure-only payload (empty genesis, intent,
    history, receipts and miss; the `closed` and `acknowledged` lists). On receipt, the
    closure-only payload is admitted only for the operations it is authorized for, as above; it
    carries no history, genesis or grant (the end check at `:5556` stays for everything else).
    *Refusals carry closures (r4, r5).* The refusal frame is today `[0, text]` (`serve`,
    `:1147-1178`), and the requester's `response_frame_until` (`:5119-5124`) turns it into
    `Error::ComputerRefused` before `merge` runs (`sync_peer`, `:4225-4232`); a payload after it
    would never be read. The refusal frame becomes `[0, text, closed, acknowledged]` (the same
    two lists, the same authorization), the only form; `response_frame_until` decodes it and
    returns `ComputerRefused { text, closures }`. *Two transactions on every full-exchange
    consumer (r5).* Every consumer of a seven-element payload or a refusal frame, that is the
    requester in `sync_peer`, `pair` and `preview`, and the server in `answer`'s op-2 branch
    (`:2912-2929`, which today runs `merge` and `exchange` in one `change_until` candidate that
    `change_guarded_blocking :4255-4262` discards whole on refusal), first decodes and
    authorizes the `closed` and `acknowledged` lists and commits them in their own
    `change_until` transaction (negative facts only: closures, `closed_after_completion`,
    `acknowledged` flags; no history, genesis, grant or intent), then processes the positive
    evidence in a second candidate whose refusal cannot undo the first. The refusal frame the
    server then writes is built after the negative commit, so an acknowledgement the requester
    sent is durable here before the requester hears the refusal, and the closer's "has not
    confirmed receiving the closure" clears on its next contact. `answer`, when it refuses a
    request from the other party of a closed or completed attempt, fills the two lists from
    `State` as for a reply; every other refusal sends empty lists. Nothing positive is ever
    imported through a refusal or through the negative transaction. *Who dials.* The redeemer dials the inviter by
    itself while it holds an incomplete attempt (`retry`, `:3424-3431`) and, after a closure,
    every `COMPUTER_CHANGE_SHOWN_WITHIN` until acknowledged, bounded to `expires +
    INVITE_LIFETIME_MS` of active dialling, over the retained link (`cancelled_links`, `:1338`,
    now consulted by `retry` beside `pair_link`/`links`, `:3734-3750`); after that bound it
    stops dialling for the closure but still conveys it on any contact (a completed redeemer
    keeps dialling the inviter as a member over `links` and receives the closure in the reply or
    in the refusal). The inviter never dials (CT-11) and conveys its closure in its reply or
    refusal to any contact from the peer. An acknowledgement is stored before it is sent; a
    lost one produces a duplicate, never a different outcome; the closer's status says "has not
    confirmed receiving the closure", never "has not seen it" (r4). A restart changes nothing:
    the entries are in `State`. `activate` and `merge` keep refusing a locally closed operation
    (`:5209`, `:5495-5502`). Who can complete alone is read from the attempt: `group.is_none()`
    (genesis) → either; else only `computers[0]`.
  - *Deleted*: the refusal text "this approval is already signed …"; the `closed_problem`
    sentence (`:1349`); the wait-for-expiry texts in `computer_cli.rs:256-258` and `:366-368`;
    `close_expired_pairing`'s assertion of the refusal (`:2674-2676`), which asserts the defect;
    the five-element exchange form. Its clock-step restart (`VOX_TEST_CLOCK_STEP_MS`) stays only
    for the expiry claim of ADR-035 CT-7.
  - *Proof*: `close_expired_pairing`, four stagings. (a) Sponsor closes: an addition to an
    established group; the joiner B `pair --preview`; the sponsor A approves; A `cancel` answers
    ≤ 2 s with `cannot complete anywhere`; `vox computer invite` on A succeeds at once; B shows
    `closed on <A>` ≤ 5 s of its next exchange; B's `approve` is refused. v0.4.30: `already
    signed`: red, PRODUCT, KNOWN (`run-e2`). Mutant: restore the refusal. (b) The race, genesis
    **(r3, r5 checkpoints)**: B `pair --preview`; A approves; B's status shows `<A> approved` (B
    holds A's signature); the existing `test-knobs` partition
    `VOX_TEST_PARTITION_COMPUTER_PEER_FILE` (`:64`, `:4644`) cuts management traffic between A
    and B both ways (B's background retry cannot learn the closure before B approves); A `cancel`
    prints `Closed here. <B> may already hold your approval …`, the existing-members sentence and
    the removal command; B approves and shows `in a group with <A>`; the partition stays for
    longer than `expires + INVITE_LIFETIME_MS` (the clock step). **Checkpoint b1** (partition
    held): A `not in a group · the attempt with <B> was closed here at … ; <B> has not confirmed
    receiving the closure …`; B `in a group with <A>`. The partition is released; within 5 s of
    B's next contact B shows `this computer completed the pairing; <A> closed it on its side at
    …` and `Next here: vox computer remove <A full>`. **Checkpoint b2** (B completed, A closed,
    nothing removed): subcase (b″) runs here, below. Then B runs the removal; B shows `in a group
    by itself`; A shows `not in a group` with no unconfirmed-closure clause. **Checkpoint b3
    (r6)**: B invites a third account D; D `pair --preview`; B runs `vox computer approve
    <O_BD>` (the new operation has its own body and needs B's own signature, `answer` records
    `approvals: [None, None]` at `:3124-3131`); public outputs: B `adding <D>: approved here,
    waiting for <D> to approve`, D `joining <B>'s group: <B> approved, your approval is missing`
    with `Next here: vox computer approve <O_BD>`; subcase (b‴) runs here, below; then D
    approves, D is in B's one-member group, and a post from B's node reads on D (B's authority
    to sign a later addition is exercised); then a new code pairs A and B again. v0.4.30:
    UNVERIFIED for this trigger (no
    partition and no close on the asset in X1; X1 shows the divergence class after a rollback,
    `/tmp/adr043/run-x1/timeline.log` 02:41:07–02:41:11Z, receipt lost in the reboot of 2026-11-13; figure recorded in `adr-043-revision`, to be
    re-run as the fleet baseline; not this journey's red). Mutant 1: age
    the closure out of the wire list at the bound; B never shows the closure; red. Mutant 2: keep
    the five-element conflict decoder; stage the different-group preview after the cutover; the
    conflict review assertion turns red. (b′) The race, addition **(r4)**: A sponsors B into
    A–C; B `pair --preview`; A approves; B approves (B's signature reaches A; A publishes the
    addition); the `test-knobs` hold `VOX_TEST_HOLD_ADD_DELIVERY_FILE` parks A's next exchange
    toward B after A's `activate` (B is still locally incomplete: it holds both signatures but
    not the published addition) while A→C traffic flows; C receives the addition and shows B `in
    the group`; B `cancel` prints `Closed here …`; release the hold; within 5 s of B's next
    request A shows `completed … <B> closed it on its side …` with `remove <B full>`; run it on
    A; C shows `<B> removed` ≤ 5 s of its next exchange; B shows `not in a group`. Restart A
    before running the removal: the offer persists. Mutant: drop the closure-authorization
    branch from `merge`'s handling of B's *request* (A's admission); A never offers the removal;
    red. (b″) Refusal path, acknowledgement and restart **(r5)**, at checkpoint b2: B (completed,
    dialling A as a member) contacts A (closed, no group); A's `answer` commits B's
    acknowledgement of the closure in the negative transaction, refuses B's intent in the
    positive one, and writes the refusal frame; assert B's status still shows `<A> closed it on
    its side …` and that A's status within 5 s reads `… the attempt with <B> was closed here at
    …` *without* `has not confirmed receiving the closure`; SIGKILL A and restart; A's status
    still carries no unconfirmed clause; SIGKILL B and restart; B's status still shows the
    closure. Mutant 1: keep the `[0, text]` refusal; B never shows A's closure (asserted at the
    release step of (b)); red. Mutant 2: process the lists in the same candidate as the positive
    evidence (today's `:2912-2929`); A keeps `has not confirmed receiving the closure` after B's
    contact; red. (b‴) A former member cannot close another pair's operation **(r5, r6)**, at
    checkpoint b3 (B approved, D's approval missing): a former member F (paired with B before
    this journey and removed; the proof keeps F's keys) sends `closed: [(O_BD, t)]` for the
    pending B–D operation, over a full exchange and over a refusal frame (apparatus: the proof's
    own management client with F's keys, allowed under AGENTS.md); assert B's status still
    reads `adding <D>: approved here, waiting for <D> to approve` and D's still `Next here: vox
    computer approve <O_BD>`; then D approves, and B shows `in a group with <D>`. Mutant: close
    any operation listed by a recognized peer; B shows `the attempt with <D> was closed on <F>`
    and D's approval is refused; red. (c) Expiry: the existing
    clock-step restart; assert the state line says `expired at … and is closed` and `invite`
    succeeds without a `cancel`; on the side that approved, assert the `may hold your approval`
    words. Mutant: keep `begin`'s refusal for an expired pending; red on `invite`.

- **CJ-7. The status names who must act, whether it can be reached, and `pair` resumes.
  (changed)** While an attempt is open, the state line MUST say which computer must act, in the
  precedence of the state table: this computer's missing approval first, always as `Next here`;
  then the other computer's missing confirmation or approval. The reach clause MUST come from a
  fact: `offline, last seen <dur> ago (dial failed at <time>: <reason>)` only after a dial from
  this computer failed at that time with that reason (ledger row 27's word; "locked" is never
  said of another computer's node, ledger row 24); `has not connected since <time>` when the other computer is the
  one that dials and this computer last heard from it then; `connected now` from an existing
  connection; `last heard <ago>` from the exchange record. The inviter MUST NOT claim that it
  will reach the redeemer. A `pair` that cannot reach the inviter MUST fail within its dial bound,
  name the addresses it tried and the error, say that nothing was approved, and give both
  remedies (the same command again; the code made here instead). A `pair` with a code this
  computer already holds MUST return the status without a new review or approval.
  - *Why*: item 33, mechanism 1; the Mac's ten minutes of "waiting" with the cause in the last
    line of `--details`; review finding 10.
  - *What changes*: `PairingPreview` gains `peer_recorded: bool`, `reach { last_heard_ms:
    Option<u64>, last_dial: Option<{ at_ms, error }>, dials_here: bool }`, filled from the
    exchange records, the retry's failed-attempt record (`exchanged`, `:431`) and
    `transport_leases`; `next` is derived from them. The `pair` failure text replaces `the
    connection could not be set up: computer could not be reached; the pairing code was not
    checked: …` in plain output; the raw chain stays in `--details`. Making the inviter dial a
    redeemer behind NAT (plan design B) is not part of this ADR.
  - *Deleted*: "Approved here. Approval from … has not reached this computer. On that computer,
    review and approve …" (`computer_cli.rs:417-426`).
  - *Proof* **(r3)**: the pairing journey: A invites (A never dials); B `pair --preview`; stop
    B's daemon; A approves. Within 5 s, A's state line contains `waiting for <B> to approve` and
    `<B> has not connected since <time>`, and the next line `Next on <B>: vox computer approve`.
    Start B without approving; B's next line is `Next here: vox computer approve` whatever the
    reach; stop A; within 5 s of B's next dial B's state line adds `offline, last seen <dur> ago
    (dial failed at <time>: <reason>)` with the dial's error; B's next line is unchanged. B runs `pair` with the same
    code while A is stopped: the status, no question, no dial error claimed as approval. Then A
    starts, B approves, both in a group, and a post reads both ways (the existing FX-39
    assertion). Second case: B uses a code whose inviter is stopped; `pair` exits 1 within its
    dial bound with the addresses, `Nothing was approved`, `run the same command again` and `vox
    computer invite`. Third case: the connection is cut after A's reply and before B's record
    (CJ-5's hold (a), release socket closed instead of released): `pair` prints `The connection
    ended before this computer could save the attempt. Nothing was approved here.` and `run the
    same pair command again`. v0.4.30 prints `approved here: true; approved there: false`: red,
    PRODUCT, KNOWN (`run-e2`, X2). Mutant 1: derive `offline` from `existing(peer) ==
    None`; A (which never dials) prints it; red. Mutant 2: put the reach clause before the
    missing local approval; B's `Next here` turns red.

- **CJ-8. A pairing code within 2 s, from one state. (changed, r3, r9)** `vox computer invite` MUST
  exit with a code within 2 s of its invocation, whatever the daemon is applying, or within 2 s
  print a refusal naming what is being applied and since when; Add Computer the same within 5 s
  of the click (CJ-4). While a code is open they MUST return that code again rather than
  refuse. Cancelling a code with no attempt MUST NOT wait on the computer changes writer.
  Cancelling an attempt (a policy fact) MUST wait at most 2 s for the writer and then refuse
  with `the daemon is applying a computer-trust change (<what>, started <N> s ago); try again in
  a moment`; `invite` and a code's cancel MUST wait at most 2 s for the invitation lock and
  then refuse with `a pairing with this code is being recorded; try again in a moment`. Every
  refused operator computer command MUST write one daemon log line, `vox daemon: computer
  <command> refused: <why>`. The code's claim MUST remain one atomic fact with the attempt, a
  code reported cancelled MUST never afterwards hold a live attempt, and a code whose attempt
  completed or closed MUST never become usable by another identity.
  - *Why*: item 35; "it's refusing to let me generate a pairing code"; review findings 3 and 4;
    second review F2, F3.
  - *What changes*: invitation secrets leave the computer `State` (`computer.rs:1770-1775`) for
    `.daemon/computer/invitations` (mode 0600, atomic install, the ownership and symlink checks of
    ADR-035's accepted contract) under its own lock. The record holds `id, secret, transport,
    expires, nonce, grants, cancelled`; it holds no `target`. *Claim.* A code is claimed exactly
    when its nonce is carried by `State.pending`, a `cancelled` entry, `genesis`, or an addition
    in `history` (`invitation_finished`'s lookup, `:5184-5197`, without `target`); the identity
    it is claimed for is the other computer of that attempt. `answer`'s early reservation
    (`:2969-2983`, `i.target` before the CPace challenge) becomes that lookup: a nonce claimed
    for another identity refuses `already consumed by another identity`; a nonce claimed for
    this identity continues (replay); an unclaimed nonce continues. The claim is written in
    `answer`'s one state transaction (`:3203-3229`), which also does the cleanup `begin` did
    under the writer (`:1240-1246`: a completed `pending` and its `group_genesis` are cleared
    and `pair_link` moves to `links`) so that an established computer's next addition is not
    refused by `:3213-3215`. *Linearization (F2).* `answer` takes the changes writer, then the
    invitation lock, re-reads the record (`cancelled`, `expires`) and holds the invitation lock
    across its state transaction up to and including the atomic install of the state file; it
    never holds it while waiting for the writer or across network I/O. A code's cancel and
    `begin` take the invitation lock with a 2 s bound; a cancel of a code that finds, under the
    lock, that the nonce is now claimed, answers as a cancel of the attempt (the writer path,
    its 2 s bound) instead of marking the record. So a code is reported cancelled only if no
    attempt will ever be installed for it. Lock order: changes writer → invitation lock → state
    mutex; the state mutex is never held while waiting for the invitation lock. *Lifecycle
    (F3).* A record is retired (deleted) when its nonce's attempt is complete and acknowledged
    by the peer, or closed and acknowledged, or `expires` has passed, whichever first; until
    then it is kept so the claimed identity can replay. Unclaimed and cancelled records are
    pruned to the last 16. `transport_leases` (`:2270-2281`) derives the lease's peer from the
    claim lookup, not from `target`. *Crash windows:* `begin` dies after its write: the code
    exists, unclaimed, open; `answer` dies before its install: the code is open, nothing held;
    after it: the attempt and the claim are one record and the invitation lock is simply
    released; a cancel of an attempt dies after the state transaction and before anything
    else: the attempt is closed and `answer` refuses the code by its nonce in `cancelled`; a
    `begin` that loses its race with an `answer` for an earlier code yields a code whose
    redemption is refused by the singular-pending check, as today. The 2 s is measured by the
    proof from process start to exit and covers client open (r10, X043-5: no ADR-044 bound
    applies to client open; RD-1 bounds `vox status` start to exit and is a separate claim), the
    invitation lock (held by `begin` across one small file write; by `answer` across one state
    install), `local_endpoints()` and the reply. `computer_request`
    (`crates/vox-tui/src/host/computer.rs:372`) logs refusals. This changes the persisted state
    format (allowed in v0.4.x).
  - *Deleted*: the invitation `MAX_RECORDS` check and its text "retained computer invitation
    history is full" (`pairing.rs:1233-1236`); the `begin` refusal for a live code; `begin`'s
    `review_gate` and its cleanup; `Invitation.target` and both of its writers.
  - *Proof* **(r3)**: the pairing journey, with a new `test-knobs` hold at the writer itself,
    `VOX_TEST_HOLD_COMPUTER_CHANGES_WRITER_FILE` (`<arm>\t<engaged>\t<release socket>`: the next
    policy application's journal writer, `policy_save.rs:322`, creates `engaged` once it holds
    the computer changes writer and parks until the release socket connects). Staging: pair A and
    B; arm; `vox node create` on A engages the hold; the proof waits for `engaged` (the causal
    receipt), then times `vox computer invite --json` on A from start to exit: ≤ 2 s with a
    code; a second `invite` returns the same code; `vox computer cancel <that code>` ≤ 2 s;
    `vox computer cancel <attempt>` on a computer holding one answers the busy refusal ≤ 2 s;
    then release; a fresh `invite` on A gives a new code and C pairs with it; C presenting the
    cancelled code is refused `cancelled`. Cancel-versus-record (F2): the hold
    `VOX_TEST_HOLD_PAIR_ANSWER_BEFORE_INSTALL_FILE` parks `answer` after its rechecks and before
    its install, under the invitation lock; `vox computer cancel <code>` from a second shell
    answers the busy refusal ≤ 2 s; release; the attempt exists; then `cancel <code>` again
    closes the attempt (writer path) and the redeemer sees the closure. SIGKILL A at that hold:
    restart; the code is open and unclaimed, or the attempt exists; never a cancelled code with
    an attempt. Lifecycle (F3): complete A–B; A invites again and C pairs (the second addition
    is not refused); B presents its old code again within ten minutes: the status (replay);
    D presents B's old code: `already consumed by another identity`; SIGKILL A after the second
    `answer`'s install and restart: the same. **Local and remote assertions (r9)**: every
    assertion above is local to A and C and lands with CJ-8; the one remote assertion, "the
    redeemer sees the closure" after `cancel <code>` closes an installed attempt, belongs to
    CJ-6's proof (b) and is asserted there once CJ-6 lands, not here. Mutant 1: route `begin`
    back through `self.computer.change`; red with `waited too long`, PRODUCT. Mutant 2: release
    the invitation lock before the install; the cancel-versus-record staging returns `cancelled`
    and then an attempt exists; red. Mutant 3: look the claim up in `pending` and `cancelled`
    only; D's replay of the completed code is admitted; red. v0.4.30: UNVERIFIED on the asset
    for the timing (a tiny scratch store holds the writer for ~0.1 s; `run-e3` measured `invite`
    at 0.13 s during a removal); the run that verifies it is E35 as defined under item 35 (the
    fleet's FG-7 corpus clone; one definition), reported in the post. The
    `VOX_TEST_HOLD_COMPUTER_POLICY` hold of revision 1 (`actor/computer.rs:219`) is not used: it
    parks before the writer is taken (`actor.rs:14035-14053`, writer at `policy_save.rs:322`).

### 3. Replacing

- **CJ-9. A rebuilt computer is a new computer. (changed)** An installation with a new identity
  and an old name MUST be shown as a different computer at every step: the review says so (CJ-3)
  and gives the command to remove the old one, with its full fingerprint, if it is being
  replaced. While two members share a name and nothing else is pending, the next line MUST say
  so and give that removal as a choice. Nothing is merged, carried over or inferred from the
  name (ADR-035 CT-12, CT-17; ADR-007 G-28): the new computer needs its own key, the code and
  both approvals like any other.
  - *Why*: items E-a and 36; Nov 12's second `ns1025741`; review finding 9.
  - *What changes*: the review sentence and the `next` rule above.
  - *Deleted*: none.
  - *Proof* **(r3)**: the removal journey already re-enrolls a removed computer. It is to add a
    fresh account (same host name by construction) that pairs into the group while an old
    member is stopped (the group's earlier completed attempt is cleaned up by `answer`, CJ-8,
    so this addition is not refused). Assert the review's "different computer" sentence names
    the old prefix; after both approvals, the next line offers `vox computer remove <old full
    fingerprint>`; run exactly that line; the old computer is removed; the new one's own status
    says `in a group`, a post from the new computer's node reads on A's node, and a post from
    the old computer's node is refused there. v0.4.30 shows `Joins existing computer group:`
    with two identical names: red, PRODUCT, KNOWN (`run-e2`). Mutant: print the new computer's
    fingerprint in the removal command; the new computer's post is refused; red.

### 4. Removing

- **CJ-10. Removal asks once and needs nothing from `--details`. (r3)** `vox computer remove
  <computer>` without `--confirm` MUST show the computer, its nodes, what they lose, what is not
  claimed (data already received is not erased; an unreachable computer applies it later), the
  rooms of CJ-12 with what will happen in each, and that only a creator can readmit a removed
  room member, then ask once. It submits the frontier it showed and, per room, the room id, the
  member node, the acting admin node, the roster head it reviewed and the choice; the daemon
  refuses with `the rooms changed since you reviewed them; review again` when a reviewed room's
  roster head moved or a listed node's membership changed, and refuses as today when the
  frontier moved; it never widens the reviewed scope. `--confirm <frontier>` stays for scripts,
  with `--keep-rooms` or without. The computer may be given by its full fingerprint, or by its
  name when that name is unique among members; otherwise the refusal lists the candidates with
  their full fingerprints.
  - *Why*: item 36 and CJ-1: the frontier is no longer in the plain output.
  - *What changes*: `ComputerCmd::Remove` (`computer_cli.rs:38-49`, request at `:145-157`)
    previews, asks and submits, as `pair` does (`:262-280`); the app's removal sheet (its
    `ComputerTrustConfirmation`, `ComputerTrust.swift:655`; the paragraph at `:260` is text,
    not the sheet) shows the same lines.
  - *Deleted*: the per-row "no claim that unreachable data or keyrings were erased"
    (`computer_cli.rs:593-597`); ADR-035 CT-18's statement is made once, in the question.
  - *Proof*: the removal journey: `vox computer remove <B>` with `y` on stdin; assert the question
    names B's nodes and rooms and the removal applies. Scope: between the preview and the `y`
    (the proof drives stdin), B's node leaves R; assert the refusal `the rooms changed since you
    reviewed them` and that nothing was removed. v0.4.30: `error: the following required
    arguments were not provided: --confirm`, red, PRODUCT, KNOWN (operator transcript). Mutant 1:
    drop the node list from the question; red on the question assertion. Mutant 2: submit the
    frontier only; the scope assertion turns red.

- **CJ-11. No offers for a removed computer's nodes, durably, on every computer. (changed,
  r3)** Once a removal applies on a computer, whether it ran `remove` or learned the removal in
  an exchange, no node of the removed computer MUST be offered in any keyring there on a basis
  that existed before the removal was applied, for good; a basis the node gives afterwards
  under ADR-028 K-18 (it joins again, or grants consent again) MUST be offered. The suppression
  MUST be an obligation per (local node, room) that survives restart and failure until it is
  stored; for a room that is closed or cannot be opened at that time it MUST be stored when the
  room next opens here, before the room's first exchange, so that nothing the removed node adds
  later is caught by it. While an obligation is owed for a room, that room MUST NOT offer the
  removed node at all (the read barrier). A computer MUST NOT report the removal complete, and
  CJ-13's clean status MUST NOT appear, while an obligation is owed.
  - *Why*: item 36; the old IO's nodes offered back to the keyring; review finding 7; second
    review F4, F5 and its closed-room question.
  - *What changes*: a per-node, per-room **removal boundary** replaces dismissal as the
    mechanism: `RemovedBasis { room, member, removal_event: Digest32, upto_seq: u64 }` in the
    node's trust segment beside `DismissedOffers` (`offers.rs`), never pruned (one entry per
    removed member per room; `DismissedOffers`' 4,096 bound and `pop_first`, `offers/native.rs:12-15`,
    stay for dismissals and are not used here); `offers()` (`:176-179`) skips a basis whose
    `(room, member)` has a boundary with `basis.seq <= upto_seq`, and skips every basis of a
    member for which an obligation is still owed in that room. The obligations are created
    where the removal becomes effective, in one transaction with it: in `remove`'s transaction
    for the remover (`pairing.rs:1788`) and in `merge`'s fold for a computer that receives the
    signed removal (`:5556-5560`), as `DismissalWork { removal_event, member_nodes, per (local
    node, remembered room): stored: bool }` in `State`, keyed by the removal event's id so a
    replayed exchange creates nothing twice; they are separate from `RemovalWork` (CJ-12,
    evictions the person chose on the remover). **(r4)** The boundary is captured where the
    removal becomes effective, not at payment: the same transaction that creates the obligation
    records, per (local node, room), `upto_seq` = the member's highest basis seq the node's room
    projection held at that moment for an open room, read under the room's admission order (the
    policy fence every native save already checks, `maintenance_save.rs:821-823`: a basis
    admitted after the fence sees the new revision and so is after the boundary); for a room
    that is closed at that moment `upto_seq` is captured at its next open, before its first
    exchange (a closed room receives nothing, so that is still the pre-removal frontier). The
    managed policy path (`policy_save.rs`, `PolicyCompleted::Managed` at `trust_save.rs:76`)
    then only *stores* the captured boundary into the node's trust segment; it never resamples.
    A room that cannot open stays owed and the state line says so (`<room> is closed here and
    will stop offering its nodes when it next opens`, or `cannot be opened (<error>)` with `vox
    doctor`). `FinishUntrust`'s best-effort continuation (`trust_save.rs:990-1009`) is not reused.
  - *Deleted*: none.
  - *Proof* **(r3)**: the removal journey, with a third computer C in the group sharing a room
    with B's node and a room RC closed on C during the removal. A removes B. Within 5 s of the
    removal applying on each computer, `vox trust offers` on every node of A and of C prints
    `no offers`. SIGKILL C's daemon at the `test-knobs` hold
    `VOX_TEST_HOLD_DISMISSAL_AFTER_ADMISSION_FILE` (parks C's node after the removal is folded
    and before the obligation is paid, creating `engaged`); restart C; `offers` on C prints
    none, before and after the obligation is paid (the barrier). Open RC on C: none for B's
    node. Then, in the same room RC, B's node (its daemon still running, B now an individual
    computer) grants consent to C's node again: that new basis is offered on C. Open-room race
    **(r4)**: with the `test-knobs` hold `VOX_TEST_HOLD_DISMISSAL_PAYMENT_FILE` (the obligation
    is created and captured, the worker parks before storing), B's node grants consent to A's
    node again in the open room R; release; A's offers in R show B's node on the new basis, and
    after a restart of A and 4,100 further dismissals still show it, while the pre-removal basis
    stays suppressed. Bound: the proof dismisses 4,100 bases on A's node (staged by a scratch
    node posting consent entries) and then reads A's offers in R: none for B's node on the old
    basis. v0.4.30 (`run-e3`) lists `b1`: red, PRODUCT, KNOWN. Mutant 1: mark the obligation
    stored before the write; the post-kill assertion turns red. Mutant 2: create obligations in
    `remove` only; C offers B's node; red. Mutant 3: implement the boundary as a
    `DismissedOffers` entry; the 4,100 staging reoffers B's node; red. Mutant 4: pay a closed
    room's obligation after its first exchange; the new consent in RC is not offered; red.
    Mutant 5: capture `upto_seq` at payment; the open-room new consent is not offered; red.

- **CJ-12. Rooms are part of removal, and the daemon owns it. (changed, r3, r9, r11, r12, r13, Q3)** The removal
  question MUST list every room on this computer where a node of the removed computer is a
  member, and what will happen in each. The person's choices (evict, or keep with
  `--keep-rooms`) MUST be saved with the computer removal in the same transaction, as a removal
  record naming the target, each (room, node, acting local admin node) and the choice, before
  any mutation. The daemon MUST then perform each accepted eviction through the existing room
  removal (ADR-007 G-28, the same actor request `vox room remove-member` makes), record each
  result in the record, resume after any restart, treat a member already gone as done, and show
  the remaining ones and any refusal in the state line until none is left: a refused eviction
  as `Next here` with the exact `vox room remove-member` command and `--keep-rooms` as the way
  to stop; an acting node that is locked as `Next here: vox node unlock`; a room that cannot
  open as `Next here: vox doctor`, the eviction finishing by itself once it opens (`Waiting`
  on ADR-040 NW-1's `Projection(room)`/`OwnHistory(room)` prerequisite, or the room's open
  refused). Only then is
  the removal reported complete. **Repeated `remove` on a removed computer (r9, r11, r12)**:
  `vox computer remove <computer> [--keep-rooms]` for a computer that is no longer an active
  member is not a second removal: the tagged `remove` refuses a target with no active grant
  (`pairing.rs:1793-1796`, `this computer is not an active group member`) and still does; the
  command instead updates that computer's open `RemovalWork` record in one state transaction
  taken under the drain worker's room lock, so no eviction is admitted and no parked retry
  resumes while it runs (no signed event, no frontier). The worker records `Admitted` before it
  issues a room's `RemoveMember` write, and `Done` after that write commits, in two
  transactions; a parked eviction (`Waiting(prerequisite)`) holds a retry registration on
  ADR-040 NW-1's prerequisite. What the command does, per room, is this table, from which the
  text and the stagings below are derived:

  | `result` before | member still in the roster? | `--keep-rooms` | without `--keep-rooms` | printed |
  |---|---|---|---|---|
  | `None` (pending) | yes | → `Keep` | unchanged (the worker continues) | `<node> stays in <room> (kept)` / `<node>'s removal from <room> is still to do` |
  | `None` (pending) | no | → `Done` (reconciled by roster: gone by another hand) | → `Done` | `<node> was already removed from <room>` |
  | `Waiting(prerequisite)` | yes | → `Keep`; the parked retry is retired (the prerequisite's release no longer resumes it) | unchanged | `<node> stays in <room> (kept)` / `<node>'s removal from <room> waits until <NW-1 words>` |
  | `Waiting(prerequisite)` | no | → `Done`; the parked retry is retired | → `Done`; retry retired | `<node> was already removed from <room>` |
  | `Refused(why)` | yes | → `Keep` | → `None`: the worker retries once | `<node> stays in <room> (kept)` / `retrying the removal of <node> from <room>` |
  | `Refused(why)` | no | → `Done` | → `Done` | `<node> was already removed from <room>` |
  | `Admitted` | yes (write issued, not yet committed) | unchanged (in flight) | unchanged | `<node>'s removal from <room> is in flight; status says when it is done` |
  | `Admitted` | no (committed, `Done` not yet recorded; or a crash between the two) | → `Done` | → `Done` | `<node> was already removed from <room>` |
  | `Done` | no | unchanged | unchanged | (not listed) |
  | `Done` | yes (readmitted by the creator since) **(r13)** | unchanged: the old reviewed eviction is complete; the readmission is new consent and is never evicted under the old approval | unchanged | `<node> is in <room> again (readmitted after its removal); nothing is pending for it` |
  | `Keep` | yes | unchanged | unchanged | `<node> stays in <room> (kept)` |
  | `Keep` | no (left, or removed by another admin since) **(r13)** | → `Done` (reconciled by roster) | → `Done` | `<node> was already removed from <room>` (never "stays") |
  | no open record | any | nothing | nothing | `<computer> was removed at <time>; nothing is pending for it`, exit 0 |

  Every combination of result × roster × flag × record open is a row above; "roster" is read
  under the room lock in the same transaction. A crash between the room write's commit and the
  `Done` record leaves the member gone and the result `Admitted`; the next worker run, and the
  next repeated command, reconcile it by roster to `Done` (the "already gone is done" rule),
  never to `Keep`. The record is complete when every room is `Done` or `Keep` and no `Admitted`
  entry remains; an `Admitted` entry completes when its result arrives. After the update the
  command prints the lines above, then the status. Where no local node can evict, the status MUST name
  the room, the node, who can (the creator, or any admin) and the exact command on that
  computer, until the member is gone. A kept membership (`--keep-rooms`) MUST be shown once as
  informational and never as pending work (Q6). Removal times MUST come from the signed removal
  body.
  - *Why*: item 36; the old `omp-io` still in `repo-to-cve`; review findings 6 and 13.
  - *What changes* (r10, X046-41: each eviction is the room's own `GovernanceWrite::RemoveMember`,
    `pending_text.rs:592-600`, whose writer ADR-046 SY-3 step 5 owns; it adds `(target, settled
    tip)` to `required_ancestors`; this ADR issues that write and changes nothing in it):
    `State.removals: Vec<RemovalWork { target, at_ms, rooms: Vec<{ room, node,
    acting: Option<Digest32>, choice: Evict | Keep, result: Option<Admitted | Done | Refused(String) |
    Waiting(prerequisite)> }> }>` (r11: `Admitted` is recorded before the room write is issued,
    `Done` after it commits; the repeated command reconciles between them), written in `remove`'s transaction (`pairing.rs:1788`); a daemon
    task drains it and parks on ADR-040 NW-1's typed not-yet when a room cannot take the
    request. **The control lane (r16, r17; the decider's row 82, Main's rows 82a and 82b;
    ADR-048 TC-4/TC-5 own the change)**: each eviction, and each readmission the table
    protects, is a control turn on the room's control lane. A room has two lanes, FIFO within
    each, control and authored; when both have ready work they alternate, one control turn then
    one authored turn; a turn is one native transaction ending at its own Immediate commit and
    installation; so a control step, once at the head of its lane, waits for at most the
    transaction in flight plus one authored write (row 82c), and an authored write for the
    writes ahead of it in its lane plus at most
    one control transaction per write (ADR-040 NW-3 r13, ADR-044 RD-10 r16, ADR-048 TC-4 r11,
    cited by id). Separately, a trust/policy command is never deferred behind a pending
    ordinary save, nothing is refused in either direction, and no step of this ADR waits for,
    reserves or requires a room, flow or member to fall quiet. At v0.4.30 the eviction's own command,
    `NodeCommand::RemoveRoomMember` (`post_save.rs:368-374`), is not in
    `command_waits_for_save`'s exempt list (`post_save.rs:253-276`) and so is retained behind a
    pending store save (`actor.rs:8075-8088`); ADR-048 TC-4's exempt list is to include it
    (cross-ask in `adr-043-revision`). The computer commands themselves (`invite`, `pair`,
    `approve`, `cancel`, `remove`) reach the computer management through `computer_request`,
    not a node actor, and are not deferred behind saves at the tag; CJ-8 keeps their own 2 s
    bound. ADR-040 NW-3 governs the parked owner's ordering (cited by id).
    The signed removal body gains `at_ms` (the remover's clock, under its signature);
    its two producers (`remove`, `:1797-1801`; `replace_group`'s self-removal, `:1777-1781`), the
    decoder (`Control::event`, `computer.rs:860-877`) and retained-state validation change
    together, with no old-arity form left; it is displayed as `removed <time>` everywhere, and
    on the removed computer as `removed … at <time>`, always as the remover's clock.
    `ComputerStatus.removal_work`, `dismissal_work` (CJ-11) and `leftover_members: Vec<{ room,
    node, node_name, remover_here: Option<String>, removers: Vec<String> }>` feed CJ-1. The
    request carries the choices; `--keep-rooms` sets `Keep` for every room.
  - *Deleted*: none; room removal entries are the existing signed facts.
  - *Proof* **(r3, r14)**: the removal journey: A's node a1 creates room R (a1 is R's creator and
    does every R and R4 operation below); R3 is created on computer C by c1 as staging (i) says;
    B's node is a member of R and R3; a room R2 whose creator is on B. `vox computer remove <B>` with `y`. Within 5 s `vox
    room roster R` and `R3` lack B's node and B's node's `vox room post R` is refused (G-28's
    existing refusal); A's status names R2, its member, its creator and the command. Killed
    between, causally: the `test-knobs` hold `VOX_TEST_HOLD_REMOVAL_WORK_FILE`
    (`<arm>\t<engaged>\t<release socket>\t<after>`: the drain task parks before the eviction
    numbered `<after>`, creating `engaged`); run once with `<after>` = 1 (after the durable
    removal, before any eviction) and once with 2 (after R, before R3): at `engaged`, SIGKILL
    A's daemon; restart; assert the state line `removing <B>: N of 2 room removals left` and then
    both rosters clean ≤ 10 s without any command, and B's post refused in both rooms. Refusal:
    with the acting admin node locked on A, assert `repo-to-cve refused …` is not shown (a
    locked node is `Next here: vox node unlock`) and the eviction completes after the unlock.
    `--keep-rooms`: a second removal with it; assert the rosters keep B's node, the next line
    says `Nothing pending` with the informational clause, and no later status offers an
    eviction. Repeated command **(r11, r12, r13)**, five stagings in the same journey, each derived
    from the table's rows: (i) refused then retried (`Refused` row) **(r13)**: room R3 is
    created on a third computer C by its node c1 (the creator is root admin and cannot lose
    that, ADR-007 G-28/G-29 at `:201-204, 233-234`, so it is kept off A); c1 delegates admin to
    A's node a2, the only eligible local actor on A (a1 is an ordinary member); B's node is a
    member; `vox computer remove <B>` on A with `y` commits with R3's eviction accepted (by a2);
    the hold `VOX_TEST_HOLD_REMOVAL_WORK_FILE` with `<after>` = 2 parks the worker before R3's
    admission; while parked, c1 revokes a2's delegation (the roster head moves after the computer
    removal committed, so CJ-10's scope check is not involved); release; assert the state line
    `removing <B>: R3 refused the removal of <b1>: <refusal>` and `Next here: … (or vox computer
    remove <B full> --keep-rooms to stop trying …)` (an unmet refusal is APPARATUS); c1
    re-delegates a2; run `vox computer remove <B full>` again (no `--keep-rooms`); assert it
    prints `retrying the removal of <b1> from R3`, exits 0, and within 10 s `vox room roster R3`
    lacks B's node, B's post in R3 is refused and the state line is clean. (ii) Pending and
    parked, then kept (`None` and `Waiting` rows) **(r13, r16)**: the same hold with `<after>`
    = 2 parks the worker before R3 (pending), and a fourth room R4, where B's node is a member
    and a1 is creator, has a **control-work owner in flight**: a trust withdrawal of a1's in R4
    held at its dispatch by ADR-048's `test-knobs` withdraw hold
    (`VOX_TEST_TRUST_WITHDRAW_HOLD_FILE=<path>:<R4>`, the one dispatch boundary every withdrawal
    crosses), so that owner holds R4's pending-write slot (a control step at the head of its
    lane waits for at most the transaction in flight plus one authored write, rows 82b/82c; a
    trust debt does not fence a public
    removal control, ADR-048 TC-3) and the worker, on reaching R4, parks as `Waiting(RoomWrite(R4))` behind that
    one owner (the proof reads `vox computer status --json` `.removal_work[].rooms[]` for R4 =
    `waiting` before continuing; absent → APPARATUS). While both holds are held, b1 posts in R4
    continuously (one post per second, apparatus); run `vox computer remove <B full>
    --keep-rooms`; assert `b1 was already removed from R`, `b1 stays in R3 (kept)` and `b1 stays
    in R4 (kept)`; release both holds; restart A; assert `vox room roster R3` and `R4` still list
    B's node, B's posts in R3 and R4 are accepted, no eviction resumed, and the next line is
    `Nothing pending` with the informational clause. Removal under continuous posting
    **(r16, r17, row 82b)**: in a sixth room R6 (a1 creator, b1 member) b1 and a third member
    post one line per second throughout; `vox computer remove <B>` with `y` (no hold); assert
    that the eviction's commit follows at most one authored write committed after the removal
    was accepted (the alternation bound: `vox room history R6` shows at most one post between the
    removal's acceptance time and the roster change), so `vox room roster R6` lacks b1 within
    10 s, that the third member's posts sent during those 10 s all read on a1 (none refused,
    none lost; posts are delayed by at most one control transaction each), and that A's daemon
    log holds no `retained behind a pending save` for the eviction; a1's `vox computer status` shows no R6 line. Mutant
    12: keep `RemoveRoomMember` in `command_waits_for_save`'s retention (today's
    `post_save.rs:253-276`); under the posting load the eviction waits for the posts' saves and
    the 10 s assertion turns red. (ii′) Terminal rows that move
    **(r13, r14)**: with R3's eviction still `Refused` (record open), a1, R's creator, readmits
    b1 to R (whose result is `Done`; readmission needs the creator's root signature, ADR-007
    G-29) and a1, R4's creator, removes b1 from R4 (which is `Keep`); run `vox computer remove <B
    full> --keep-rooms`; assert it prints `b1 is in R again (readmitted after its removal);
    nothing is pending for it`, `b1 was already removed from R4` (never `stays in R4`) and `b1
    stays in R3 (kept)`; `vox room roster R` lists b1 and `R4` does not, after a restart too.
    (iii) Committed but not recorded (`Admitted`, roster no): the hold
    `VOX_TEST_HOLD_REMOVAL_RESULT_FILE` parks the worker after R's roster removal is committed
    and before its `Done` record; run `vox computer remove <B full> --keep-rooms` while engaged;
    assert it prints `b1 was already removed from R` (never `stays in R`), and that `vox room
    roster R` lacks B's node after release and after a restart. (iii′) A room that cannot open
    **(r15)**: B's node is also a member of a fifth room R5 created by a1; A's daemon is
    restarted with ADR-042's `test-knobs` knob `VOX_TEST_HOLD_PREPARATION=<R5>` (the room's
    preparation turn parks until a file appears, so R5 is not open and its eviction is
    `Waiting(Projection(R5))`, ADR-040 NW-1); `vox computer remove <B>` with `y`; assert the
    state line `removing <B>: R5 cannot be opened (<the preparing words>), so <b1> is not removed
    from it yet` and `Next here: vox doctor (the removal finishes by itself once the room
    opens)`; release the hold; within 10 s `vox room roster R5` lacks B's node and the state line
    is clean. The permanent form (the room's open refused: ADR-047 SO-9's verified `Corrupted`
    open, the store header overwritten on a stopped scratch node) is an **owed extension of
    ADR-045 J6(d)**, not an existing proof, until ADR-045 carries the paste in
    `adr-043-revision` (r16): it stages the corrupt open, removes the computer, asserts the R5
    `cannot be opened … not removed from it yet` and `vox doctor` lines and the unfinished
    record, then asserts the continuation after a restore (ADR-038 FX-32) or the node's deletion;
    in-tree the preparation hold is the means. Mutant 11: finish the removal while R5 is held;
    the record is complete and R5's roster still lists B's node; red. (iv)
    No open record: run `vox computer remove <B full>` once more after everything is done;
    assert `was removed at <time>; nothing is pending for it`, exit 0. Missing `engaged`, a
    demotion that did not take, or a roster the staging did not reach is APPARATUS; a reached
    wrong line is PRODUCT. v0.4.30 roster still lists B's node: red, PRODUCT, KNOWN (`run-e3`).
    Mutant 1: skip the room step; red on the roster. Mutant 2: perform evictions from the CLI
    after the removal (no record); the `<after>` = 1 kill leaves both rosters dirty; red.
    Mutant 3: display `now()` as the removal time; a restart of A changes the shown time; red on
    the equality assertion across restart. Mutant 4: leave `replace_group`'s self-removal
    (`:1777-1781`) on the old body; the retirement journey's decoder refuses it; red there.
    Mutant 5 **(r11)**: keep the inactive-member refusal for every repeated command; (i), (ii)
    and (iv) print `this computer is not an active group member`; red on each printed line.
    Mutant 6: ignore the `Refused` → `Pending` update; (i)'s roster keeps B's node; red. Mutant
    7: blanket `Keep` without reconciliation or the room lock; (iii) prints `stays in R` while
    the roster lacks B's node; red on the agreement assertion. Mutant 8 (r12, r13): leave
    `Waiting` evictions as `Evict` under `--keep-rooms`; (ii)'s R4 eviction resumes when the
    held write is released and the roster loses B's node; red. Mutant 9 (r13): treat `Done` +
    roster-yes as pending work; (ii′) evicts the readmitted b1 from R; red on the roster. Mutant
    10 (r13): extend the `Keep` row to roster-no; (ii′) prints `stays in R4`; red on agreement.

- **CJ-13. After a removal the plain status is clean. (changed, r3)** After a removal applies
  here, the plain status MUST show the removed computer only while a remaining member has not
  confirmed the removal, while a node of it is a leftover member (CJ-12), while its removal
  record or a dismissal obligation (CJ-11) has work left, or while its name equals a member's or
  this computer's (CJ-3). A clean status follows the last obligation, never hides one in an
  unrendered field. Available binding
  actions and removed computers MUST appear only in `--details`, under the headings "Available
  binding actions (use only when status tells you to)" and "Removed computers". Retained signed
  bindings are kept (ADR-035 CT-17, the contract on #798); only where they are shown changes.
  - *Why*: item 36; the five `binding recover:` lines the decider read.
  - *What changes*: `status` and `show` as above.
  - *Deleted*: the flat `binding <action>:` and `removed:` lines (`computer_cli.rs:588-597`).
  - *Proof*: the removal journey: after the removal of the only other member, whose name equals
    A's by construction, A's plain status is exactly its state line, `Nothing pending.`, one
    removed row (`<name> (<prefix>) removed <time>`, kept by the shared name) and the closing
    line; it contains no `binding`, `recover`, `release` or `frontier`; `--details` contains
    `recover` only after its heading. v0.4.30 prints `binding recover:` lines in `--details` with
    no heading and the policy text in plain: red, PRODUCT, KNOWN (`run-e3`). Mutant: print
    `binding_actions` in plain output.

### 5. Around computers

- **CJ-14. Withdrawn as a product change; spike E38b stays. (changed, r9, r11)** No requirement: the
  policy ordinal moving by 2 is journal numbering (item 38 above), not a second application. The
  product outcome revision 1 attached here (a sibling's `vox room post` during a create is
  accepted and no pending save is lost) is ADR-040 NW-12's (r10: NW-12 never moved; ADR-040 r8
  adds the sibling-post assertion there, X043-15), proved there. E38b
  is to run once as a spike and reported in the post. **Counting method (r9, r11)**: the
  published asset writes no log line per successful application (`host/computer.rs:228-235`
  records the receipt silently). What the asset exposes is a node's binding derivation, not its
  applications: `vox computer status --json` `.nodes[].binding_revision` and
  `.nodes[].binding_derived_ms` (`pairing.rs:234-238`; `--details` prints them as `binding
  derived at policy revision <N>, <s> s ago`) read the latest `State.derived` entry
  (`pairing.rs:1926-1935`), which binding derivation writes once per policy revision
  (`computer.rs:3259-3264`; a second derivation at the same revision returns without writing,
  `:3138-3145`) and which precedes the policy work itself (`actor.rs:21146-21167`,
  `policy_save.rs:505-559`); so a changed timestamp can precede a failed application, a repeated
  application at one revision never changes it, and a 250 ms poll of a latest-value field cannot
  see two writes between samples. The spike therefore reports those samples (every 250 ms from
  2 s before `vox node create` until 20 s after, on both computers) as **observed
  binding-derivation changes**, corroboration only; an observed count of one is not evidence
  against two applications. The number of completed applications is taken from a run-only,
  append-only trace in the `test-knobs` build of the spike (r12): one line per completed
  authoritative application of a node, emitted at both completion branches of the host's
  reconciliation, the `Ok(())` branch (`host/computer.rs:228-235`) and the `Err`-but-applied
  branch (`:244-260`, where `handle.computer_current()` is true and the node has applied the
  revision although its ancillary room reconciliation reported a fault; that fault is not a
  failed application), once per (node, target revision, pass), with the node, the target
  revision and a unique spike event id (the pass identity; the aggregate receipt may be absent
  or unchanged), written to a file named by `VOX_TEST_APPLICATION_TRACE_FILE`; the spike counts
  lines per node per create. The trace is
  apparatus of the spike (CJ-16), reported in the post and never committed; the installed
  release holds none. If the trace shows two applications for any node on one create, the cause
  is written into a revision of this ADR before anything is built from it (no cause-specific
  repair without a reproduced cause).
  - *Why*: item 38; review finding 8; the decider's "no fix without a reproduced root cause".
  - *What changes*: nothing in the product.
  - *Deleted*: the delta-of-1 assertion planned in revision 1 (never landed).
  - *Proof*: none (spike, reported).

- **CJ-15. A refused pause says who can pause. (changed, r9)** A refused `vox room pause` MUST name,
  for each node it did not pause, the node or nodes that can pause it and the exact command, or
  say that no node of this computer can and give the target's own command on its computer. Run
  from a terminal without an agent mark on a computer that has a personal node, `vox room pause`
  without `--node` MUST act as that personal node; with an agent mark it MUST NOT. The agent mark
  is the existing environment heuristic (`operator_only`, `computer.rs:4732-4747`: a nonempty
  `VOX_SESSION`, `CLAUDE_CODE_SESSION_ID`, `CODEX_THREAD_ID` or `OPENCODE_SESSION_ID`), explicitly
  not OS-account isolation and not proof that a person owns the terminal; the ADR says so and
  claims nothing stronger (Q7). Explicit `--node` and ordinary Drive checks stay. Pausing stops
  Sessions, not posting (ADR-033 PA-2, unchanged); a room-wide quiet is Q2.
  - *Why*: item 37; "does not trust you with drive" with no remedy; review finding 5.
  - *What changes*: the refusal is produced where it is actually decided, the host's drive check
    (`crates/vox-tui/src/host.rs:2974-2990`): for `Action::RoomPause` with `paused.is_some()` it
    answers `code: PAUSE_NO_DRIVE` with a bounded payload `{ target: { fingerprint, name,
    computer }, drivers: [{ fingerprint, name, computer }] (at most 8) }`, the drivers being the
    members of that room (`ch.is_member`) in the target's effective drive set (`view.drive`) with
    Ready presence; `NO_DRIVE` stays for every other drive operation. `Answer::said_to`
    (`drive.rs:155-158`) renders `PAUSE_NO_DRIVE` as `<target> does not accept drive from
    <driver>; <driver2> (on <computer>) can pause it: vox room pause <room> <target full> --node
    <driver2>`, or `… no node of this computer can pause it; on <computer>: vox room pause <room>
    <target full> --node <target full>`; `room_pause.rs:187-190` passes it through; the actor's
    own-socket `Fault::Refused` (`actor.rs:23559`) renders the same sentence; `RoomPause.swift`
    uses the same words. `crates/vox-tui/src/room_pause.rs` resolves the acting node: `--node`,
    else `VOX_NODE`, else (no agent mark) the personal node from `vox computer status --json`
    (`nodes[].personal`, which exists at v0.4.30, `pairing.rs:229`; CJ-1 adds no field for it,
    r9), else the saved selection; it receives the choice, not `Paths` already selected.
  - *Deleted*: the bare `does not trust you with drive` text for pause.
  - *Proof*: `stale_remote_pause_is_refused` (`:8133`) is to be called from the blocking
    `paired_ready_nodes_read_both_ways_and_survive_reselection` (`:1366`), which pairs two
    computers with Ready room members: pause from a non-personal node over the ordinary remote
    path; assert the refusal names the personal node and prints its command; run that command;
    the Session reads Paused on the other computer within 5 s; the same command with an agent
    mark and no `--node` does not act as the personal node; a target whose room has no
    permitted driver gets the "no node of this computer" sentence with its own command. v0.4.30:
    the bare refusal, red, PRODUCT, KNOWN (RcaFrozen `roompause`). Mutant: keep `NO_DRIVE` at the
    host check; red on the sentence.

- **CJ-17. A computer's management uses this machine's anchors. (new, r13)** The computer
  management of a daemon MUST use the same machine anchor set its nodes use: the daemon's own
  `--anchor`, the anchors file, a client's `--anchor` on attach, and `vox anchor add`/`remove`,
  as that set changes, without a daemon restart. A computer reachable only through such an
  anchor MUST learn a node created on another computer of its group within
  `COMPUTER_RETURN_SHOWN_WITHIN` (ADR-038 FX-28), and both computers' `vox computer status
  --json` `.state` MUST read `confirmed` (the plain status: CJ-1's `in a group with …` line with
  no pending clause). A directly reachable computer MUST NOT wait on, fail on, or mention an anchor
  (ADR-012 N-1–N-8; AGENTS.md "Anchors"): the direct dial races first, and an empty set fails
  only the relay branch with the same text as today.
  - *Why*: item E-b and item 33 mechanism 1 (the Mac's "empty" set while `vox anchor list` said
    `reached`); fix-list item 92; `rca-relay-only` (R1 red, R2 green with the only change being
    A's daemon started with `--anchor`, R3 red with `vox anchor add`).
  - *What changes*: `pairing.rs:413` `Management.anchors: BootstrapSet` becomes a mutex-held set
    behind `pub fn set_anchors(&self, anchors: BootstrapSet)`: replace the set; re-apply the ids
    to `self.net.policy()` as `start` does (`:905-909`); call `record_reach()` (`:773-778`) so
    the signed reach carries the new anchors; `self.transport_wake.notify_one()` so
    `refresh_transport` (`:2349-2449`) registers the leases at the new anchors; every reader of
    `self.anchors` (`:789`, `:1269`, `:1844`, `:2239`, `:2277`, `:2377`, `:2384`) reads the
    current set. `crates/vox-tui/src/host.rs:1064-1073` `deliver_manual_anchors` also calls
    `self.inner.defaults.computer.set_anchors(state.set.clone())`, which covers the daemon's own
    `--anchor` (`host.rs:830-834`), the anchors file, a client's `--anchor` on attach
    (`:4679-4680`) and `vox anchor add`/`remove` (`:1123-1125`). `daemon.rs:459-463` is
    unchanged: the startup set is the initial value. What must not change: `connect` keeps
    starting the direct dial first and racing it (`pairing.rs:2506-2508`); room sources are not
    computer anchors (`:2524-2529`).
  - *Deleted*: none.
  - *Status line*: `vox computer status` says nothing about anchors today while `vox status` and
    `vox anchor list` say `reached (connected)`. Once CJ-17 lands the two sets are one, so there
    is no state in which the computer's anchors differ from the machine's to report; the honest
    computer-level line is CJ-7's reach fact (`offline, last seen <dur> ago (dial failed at
    <time>: <reason>)`, the reason being the product's own `no anchor configured for this
    computer pairing` or the anchor's refusal), which `--details` already carries as `problem`
    and the plain status prints per CJ-1. No separate anchor row is added to `vox computer
    status`; ADR-042's row for computers stays CJ-1's `last heard` line (paste text in
    `adr-043-revision`).
  - *Proof*: the E-43-1 journey, extended as a person would do it, in the pairing journey
    (`nodes_of_one_daemon_proof.rs`) and hosted by ADR-045 J9(i): on A `vox node create a1` (the
    daemon starts), then `vox anchor add <fp@addr>`; the same on B; `vox computer invite` on A,
    `vox computer pair <link>` on B, `vox computer approve` on A, both `confirmed`; B's daemon
    stopped and started with `VOX_LISTEN=[::1]:0` and the same anchor (A cannot dial `[::1]`);
    on A `vox node create a2`. Assert: within 60 s `vox trust list` on b1 lists a2 and `vox
    computer status --json` `.state` on both reads `confirmed` (plain: CJ-1's `in a group with
    …` line, no pending clause); `--details` shows no `problem`. Control in the
    same journey: B restarted on `127.0.0.1:0` with no anchor configured anywhere: the same
    assertion, and `vox computer status --details` never mentions an anchor. v0.4.30: red,
    PRODUCT, KNOWN as measured (`R1-base.out:34`, `R3-anchoraddA.out:35`; `E43-relay-*`). Mutant:
    drop the `computer.set_anchors(...)` call in `deliver_manual_anchors` (or make `set_anchors`
    ignore its input): b1 never lists a2 within 60 s and A's `--details` `problem` reads `…
    computer relay: peer unreachable: no anchor configured for this computer pairing`, then `the
    exchange did not finish before its causal convergence deadline`, as in `R3-anchoraddA`; the
    control stays green under the mutant, which separates this assertion from ADR-012's. Staging
    not reached (B still directly connected to A after its restart; pairing not `confirmed`
    before the restart) is APPARATUS.

### 6. The proofs as one journey

- **CJ-16. One extended journey, and what it deletes. (changed, r13)** CJ-1 to CJ-15 and CJ-17 MUST be proved
  by extending the pairing journey, the removal journey and
  `paired_ready_nodes_read_both_ways_and_survive_reselection`; no new test file is added. Each
  independently changed behavior MUST carry its own mutant, named above, that reaches and fails
  its own public assertion; one early red does not count for later claims. Holds MUST be behind
  the `test-knobs` feature with a causal engagement receipt (an `engaged` file) and the installed
  release MUST hold none. A v0.4.30 red is reported as KNOWN with its run or UNVERIFIED with the
  run that would verify it; no new assertion is claimed red on the asset without a receipt. The
  assertions named under *Deleted* above MUST be removed in the same change (ADR-018: a fix
  deletes the tests it makes redundant). ADR-045's fleet journey J9 runs the same journeys under
  load, delay and restarts. **Spikes (r10, ruling X043-14)**: E33b, E35, E38b and E-43-1 are
  spikes: each MAY run as a scratch run on the host under the host rules (the guard, one rig at a
  time, explicit scratch roots, never the operator's profile or daemon), is reported in the post
  with its receipts and is never committed. Each spike has its own blocking proof **(r15,
  r16)**, and a proof that needs a `test-knobs` hold stays in tree (ADR-045's fleet rule; its
  one fleet exception is J5(i), which this ADR does not widen): E33b → CJ-5's proof (a), an
  in-tree `test-knobs` boundary proof (the before-record hold); its fleet claim stays in tree
  (no asset-stageable act reaches that crash window). E35 → CJ-8's proof, an in-tree
  `test-knobs` boundary proof (the writer hold); its asset-stageable claim is J9(c) (a pairing
  code within 2 s under the fleet's load, no knob). E38b → J9(e) (a node create under load; no
  knob; CJ-14's trace is spike apparatus only). E-43-1 → CJ-17's proof, asset-stageable, J9(i).
  No release knob is added. A spike's receipt stands only while it exists; one lost is re-run
  as the fleet baseline. E-43-1 ran on 2026-11-13 (receipts
  `/opt/vox-evidence/v0431/fleet-exp/receipts/E43-*`, item E-b): three relay shapes PRODUCT red,
  the direct control PRODUCT green; `rca-relay-only` (2026-11-14, receipts
  `/opt/vox-evidence/v0431/rca-relay-only/`) established the cause, now CJ-17 (r12, r13).
  - *Why*: AGENTS.md "Extend before adding"; items 33–38 were green on loopback; review finding 12.
  - *Proof*: the reds listed per requirement, each run once on v0.4.30 where KNOWN and once on
    the fix.

## Alternatives rejected

- **Item 33, the protocol.** *Both computers hold the attempt or neither does* (revision 1's
  CJ-5): no last message can make two durable records equal at once; every order leaves one
  side uncertain after a crash or a lost frame (review finding 1). *The redeemer owns the
  attempt and the inviter records last*: reverses the uncertainty and loses the natural
  reservation of the code by the first authenticated redeemer. Chosen: the inviter, which owns
  the code, owns the attempt; the redeemer, which dials, replays it idempotently; the inviter
  states plainly what it has and has not learned. This is two-phase commit with the coordinator's
  durable record and presumed abort on expiry (Gray and Lampson), with the operation id derived
  from the body so a replay is the same operation (idempotent operation ids); it is how Signal
  links a device (the primary's provisioning record waits for the new device's message and a
  lost message is simply re-sent, support.signal.org Linked Devices) and how Matrix treats
  verification (`m.key.verification.cancel` from either side, a request older than ten minutes
  rejected). Tailscale's node authorization is one-sided (the coordination server decides); Vox
  has no such server by design (AGENTS.md "Anchors"), so both people confirm one reviewed
  policy and the inviter's record is the one durable owner.
  *Age a closure out of the wire after a bound* (revision 2's CJ-6): a partition longer than the
  bound leaves the completed side never told (second review F1); chosen: bounded active
  dialling, unbounded reply eligibility, the entries kept in `State` for good (one small entry
  per closed attempt). *A separate signed "withdraw" event the completed side must honour*: a
  new authority type for the same end state `remove` reaches once the person accepts it.
- **Item 33, closing.** *Keep the ten-minute lock-out*: correct about signatures, wrong about the
  remedy; the person waits ten minutes for a state that cannot complete. *Wait for the other
  computer's outcome before reporting closure*: cannot be promised across a partition and leaves
  the person unable to make a new code meanwhile. *A signed withdrawal that the other computer
  must honour as a self-removal*: a new signed event type with its own authorization and
  dispatch, for the same end state that `remove` already reaches. Chosen: immediate local close
  with the exact consequence stated and the removal path offered on the computer that completed
  (Q1).
- **Item 33, the inviter dials the redeemer** (the redeemer's addresses travel in the
  handshake): does not help when the redeemer is behind NAT. Tailscale solves this with its
  coordination server; Vox has none by design. The redeemer drives; reach is shown per computer
  (tailscale.com/kb/1028/key-expiry, Syncthing's "Last seen").
- **Item 34.** *A formatter in the CLI only*: the app would re-derive the words in Swift and drift.
  *A separate `vox computer doctor`*: leaves `status`, the command people type first, unreadable.
  Chosen: one daemon field (as `tailscale status` prints one line per device and details on
  request), plus an action kind so the app never parses a sentence.
- **Item 35.** *Keep invitations in the state and bound the writer wait at 2 s*: a 30 s startup
  hold then refuses the person for 30 s; honest, not usable. *Two claim writes across two files*
  (revision 1's CJ-8): two transaction domains with intermediate states to journal (review
  finding 3). Chosen: the secret in its own small file, the claim derived from the attempt, one
  transaction. *Shorten the holders* (ADR-040, item 28): needed anyway, not enough alone, since
  one policy application over five rooms and a 3 GB store still holds the writer for tens of
  seconds. Signal's "Link a new device" code and Syncthing's add-device dialog never wait on
  sync in flight.
- **Item 36.** *Removal always removes the nodes from rooms*: ADR-035 CT-10 keeps trust and rooms
  apart, and the person may keep a removed computer's nodes as individual members (CT-17); Q3
  offers a default with an opt-out instead. *The CLI or the app drives the room removals*
  (revision 1): forgotten at the first kill, and `remove` cannot be repeated (review finding 6).
  *Prune retained bindings after N days*: the contract keeps them as evidence; where they are
  shown is the defect. Signal's "Unlink device" and Matrix's "sign out device" remove the device
  in one act and leave no residue in the device list.
  *A removal boundary stored as a dismissal* (revision 2's CJ-11): `DismissedOffers` forgets its
  oldest past 4,096 (`offers.rs:37-39`), so the promise would lapse (second review F5); chosen:
  one never-pruned boundary per (room, removed member) and a read barrier while it is owed.
  *Dismiss everything in a room that was closed at removal time* (revision 2): forgets K-18's
  new basis; chosen: pay the obligation at open before the room's first exchange, which is
  exact because a closed room receives nothing.
- **Item 37.** *A room-wide quiet that refuses agent posts* (Slack posting permissions, Matrix
  power levels for `m.room.message`): a new signed entry type, a new fence, and a new way for a
  room to be stuck, enforced by each member with no server; Q2. *Drop PA-3 for pause*: drive is
  the authority boundary for agents (ADR-029 DR-2). *Change only the actor's `Fault::Refused`*
  (revision 1): the ordinary remote path never reaches it (review finding 5).
- **Item 38.** *An independent policy generation counter*: a semantics change across the module
  for a number that is not a defect. *Assert a delta of 1*: a proxy, and false (the ordinal is
  journal order). Chosen: withdraw; spike.

## Unchanged rulings

- ADR-035 CT-7: a pairing code expires after ten minutes, is cancellable and is used once (by one
  identity; that identity may present it again to resume the same attempt).
- ADR-035 CT-10: pairing establishes trust only. Room removal under CJ-12 is a separate act,
  chosen by the person, through ADR-007 G-28.
- ADR-035 CT-11 and AGENTS.md "Anchors": direct reach is enough; nothing waits on an anchor that
  was not needed; the redeemer dials.
- ADR-035 CT-17, CT-18: a removed computer returns only by a new enrollment; removal claims no
  remote erasure.
- ADR-038 FX-42: `--json` stdout is one document; `N` and EOF add no approval.
- ADR-038 FX-52: authentication before group history; two approvals before enrollment; a record
  grants nothing.
- ADR-033 PA-2, PA-3: pausing interrupts Sessions and is driving.
- ADR-007 G-28: only the creator or an admin removes a room member.

## Superseded and amended lines

Narrow amendments. Rules not named here remain in force. Main applies them.

| Rule | Current text (file:line) | Replacement |
|---|---|---|
| ADR-038 FX-41 | "Expired or canceled attempts MUST offer truthful local closure and MUST NOT claim withdrawal of signed authority already recorded elsewhere." (`ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:1018-1019`) | "A computer holding an incomplete attempt, approved or not, MUST be able to close it at once (ADR-043 CJ-6, Q1). Closing MUST mark the attempt so it can never complete on this computer, MUST state whether the other computer can still complete it with what it holds, and MUST NOT claim withdrawal of signed authority recorded elsewhere." |
| ADR-038 FX-41 | "Every pairing surface MUST state the next action and the authenticated computer on which it belongs." (`:1014-1015`) | "Every pairing and computer surface MUST begin with the state line and next line of ADR-043 CJ-1, naming the computer on which the next action belongs." |
| ADR-038 FX-52 | "Invitation claim and final recording MUST recheck expiry, cancellation, authority and the singular pending operation at their transaction boundaries. A claimed invitation survives restart for the same authenticated redeemer; a recorded operation survives with the same grants, staged evidence and approvals." (`:1451-1454`) | Preserved, with: "The claim and the recorded operation are one fact (ADR-043 CJ-8); the inviter records whether the redeemer confirmed saving the operation (CJ-5)." |
| ADR-038 FX-52 | "Obsolete pairing operation 1 receives a truthful software-update refusal without secret or group disclosure;" (`:1456-1457`) | "Obsolete pairing operations 1 and 3 receive a truthful software-update refusal without secret or group disclosure;" |
| ADR-038 FX-52 | "Pairing operation 3" (`:1437`) | "Pairing operation 5" |
| ADR-038 FX-28 | "CLI JSON, plain CLI, the app FFI and the native Computer Trust screen expose the exact missed revision, whether it repaired late, and whether it is expired, replaced, pending or converged, alongside policy revision, per-peer exchange records/counters and per-node binding revision/derivation moment. Neither client has to infer currentness from elapsed time or free-text failure wording." (`ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:429-433` at `d9a8667ba`) | "CLI JSON, `vox computer status --details`, the app FFI and the native Computer Trust screen expose the exact missed revision, whether it repaired late, and whether it is expired, replaced, pending or converged, alongside policy revision, per-peer exchange records/counters and per-node binding revision/derivation moment; the plain CLI prints ADR-043 CJ-1's two lines and peer rows instead. Neither client has to infer currentness from elapsed time or free-text failure wording." (r10) |
| ADR-035 CT-15 | "The operator CLI MUST expose the same effective policy and pending state for a computer such as Beast." (`ADR-035-computer-trust-and-daemon-identities.md:119-120`) | "The operator CLI MUST expose the same effective policy and pending state for a computer such as Beast: the pending state and next action first, in the words of ADR-043 CJ-1; the effective policy through `vox computer policy` and `--details`." |
| ADR-035 CT-16 | "The confirmation MUST state this effect plainly and name the affected computer and nodes." (`:126-127`) | "The confirmation MUST state this effect plainly, name the affected computer and nodes, list the rooms where those nodes are members with what will happen in each, and save the person's choices with the removal (ADR-043 CJ-10, CJ-12)." |
| ADR-028 K-18 | "Removing a member from the keyring MUST also dismiss what it is offered on now, in the same local, silent way," (`ADR-028-one-experience-keyring-rooms-services-files.md:167-168`) | "Removing a member from the keyring MUST also dismiss what it is offered on now, in the same local, silent way; removing the computer that manages it (ADR-043 CJ-11) MUST, on every computer that applies the removal, stop offering it on every basis it had before the removal, for good, and still offer a basis it gives afterwards," |
| ADR-033 PA-3 | "A pause that covers other nodes MUST name each one it did not pause, and why." (`ADR-033-the-repo-room-is-where-agents-work-together.md:71`) | "A pause that covers other nodes MUST name each one it did not pause, why, and which node can pause it, with the exact command (ADR-043 CJ-15)." |
| ADR-035 CT-22 (no amendment; new design under a left-open item) | "Before implementation, the design MUST settle daemon-key protection and lifecycle; authenticated enrollment and proof of node management; authority for group additions, removal and personal-node changes, including authority exercised by a non-founding member and the consequences of a compromised member; update ordering and offline convergence; lost/replaced installations and duplicate restored identities; computer-name ownership, local aliases and collisions; the storage lifecycle of earlier individual grants under CT-4/CT-16; the exact pairing flow; and the current-version storage lifecycle." (`ADR-035-computer-trust-and-daemon-identities.md:157-163` at `d9a8667ba`, the computer-name item at `:161-162`; the sentence is preserved) | No change to CT-22; ADR-043 CJ-3 is the design CT-22 called for on "computer-name ownership, local aliases and collisions" (display only; renaming was Q5, answered: no rename). (r10, r11) |

## Implementation order and related work

1. CJ-1, CJ-2, CJ-3, CJ-13 (items 34, E-a; the frame, r9): `summary`, `next`, `peers`, the two
   lines in the CLI, bare `vox computer`, prefixes; every later proof asserts the lines this
   frame renders, so it lands first, with the rows each later requirement adds landing with that
   requirement.
2. CJ-8 (item 35): invitation secrets out of the computer state, the claim stays with the
   attempt; refusals logged; the writer hold knob; its local assertions only.
3. CJ-5, CJ-6, CJ-7 (item 33): confirmation, closing at once with the closure fact in the
   exchange, reach in the record; CJ-6's proof takes CJ-8's remote closure assertion.
4. CJ-10, CJ-11, CJ-12 (item 36): removal asks once, the removal record, durable dismissal,
   removal time in the body.
5. CJ-4, CJ-9 (items 34, 35, E-a): the app on the frame; the replacement review.
6. CJ-15 (item 37): reads the existing `nodes[].personal` field (`pairing.rs:229`, at v0.4.30);
   depends on nothing above (r9).
7. CJ-17 (item E-b, fix-list item 92; r15): `Management.anchors` behind `set_anchors()`,
   called from `deliver_manual_anchors`; depends on nothing above (its proof reads `--json
   .state` and `vox trust list`, which exist at v0.4.30).
8. CJ-16: the extended journeys, with the deletions. E33b, E35, E38b and E-43-1 (item E-b) run
   as spikes before the build of anything that depends on them (host scratch runs allowed; each
   spike's blocking proof is named in CJ-16: CJ-5(a) in tree, CJ-8 in tree with J9(c) as the
   asset claim, J9(e), CJ-17/J9(i); r10, r15, r16).

Dependencies on other lanes, not redesigned here (the required sibling changes are listed in
`adr-043-revision`):

- **ADR-040** (named waits; split on 2026-11-13 into ADR-040, ADR-048 trust containment, ADR-049
  leaving and ending rooms, ADR-050 turn journal; requirement ids below are as they stood in
  ADR-040 r2 and move with their sections; r10: NW-1 and NW-12 stayed in ADR-040, NW-5 became
  ADR-048 TC-5/TC-6/TC-8 and did not keep its number): ADR-040 NW-12 owns the sibling-post claim
  revision 1 put under CJ-14; item 28 (ADR-040) shortens the writer holds CJ-8 routes around;
  NW-1's prerequisite words (ADR-040) and TC-8's trust-debt sentence (ADR-048; r9: there is no
  NW-5 there) are what the "not yet applied here" rows print (ledger row 13, applied here in
  r3); ADR-048's proof also extends
  `active_and_removed_computers_keep_local_manual_trust` (`:4354`), which CJ-16 does not touch.
  CJ-12's drain task parks on NW-1's typed not-yet. **Decider ruling, ledger row 18 (r4)**: all
  machines move to 0.4.31 together and there is no mixed-version sync; this ADR's wire cutovers
  (pairing operation 5, the seven-element exchange, the four-element refusal frame, the timed
  removal body) therefore keep no old form and need no mixed-version proof, as already stated;
  rows 19 and 20 (gate length, VMs) do not touch this ADR.
- **ADR-042** (status reports outcome): `last heard … ago` wording is its; CJ-1 uses the same
  words for computers (r10, X042-18). `not receiving` is a room fact (TR-4: a room whose oldest
  wanted entry has a connected holder and is not delivered) and has no computer-level meaning;
  CJ-1 prints no `not receiving` line, and `vox computer status` never says it; it lives in
  `vox status`'s room lines (ADR-042 TR-4, TR-23). ADR-042's sibling row for CJ-1 is to read
  `last heard <dur> ago` only.
- **ADR-044** (the daemon stays responsive under agent load): CJ-8's 2 s is its own start-to-exit
  bound on `vox computer invite`; ADR-044 RD-1 bounds `vox status` only (r10, X043-5), and J9(c)
  adds RD-1 as a `vox status` assertion beside CJ-8's, not inside it.
- **ADR-045** (the fleet release gate): journey J9 runs these journeys under real conditions.
  J9(c) bounds the app's code at 5 s, which is CJ-4's bound; J9(d) and (e) were reworded in
  ADR-045 r2 (ledger row 2); J9(g)'s `cancel ≤ 1 s, new invite ≤ 1 s` must read 2 s (CJ-6,
  CJ-8), and X1/X2 are receipts for the divergence class and the replay only, not for J9(h)'s
  four journeys. Item E-b (its E-1 observation) is owned here; E-43-1 reproduced the outcome on
  the asset (receipts `/opt/vox-evidence/v0431/fleet-exp/receipts/E43-*`) and `rca-relay-only`
  established the cause (receipts `/opt/vox-evidence/v0431/rca-relay-only/`); CJ-17 is the fix
  and its proof is J9(i)'s (paste text in `adr-043-revision`); J9(i) is the blocking fleet proof
  of the spikes (r10, r12, r13).
- **ADR-046** (sync progress): the reason Q2 recommends no room-wide quiet.
- **ADR-041** (restart and update need no human): what a rebuilt Linux computer's nodes need
  after a restart is ADR-041's (RS-1: the kernel keyring across restarts; RS-3: a TPM credential
  or passphrase file after a reboot), not part of CJ-9; r10 drops the earlier "must be unlocked
  after its restarts" (contradiction row "Linux restart cost": ADR-041 wins). RS-15's "pairing again"
  words are this ADR's step 1.
- **Fix-list item 63** (IO's half-joined `omp-io` and the old IO's nodes still in `repo-to-cve`
  and the trust group): once v0.4.31 is installed, the operator clears them with the removal
  journey (CJ-10–CJ-12), on his machines and at his go (AGENTS.md "The operator's machines").

## Consequences

### Positive

- A person adds, replaces or removes a computer by following the second line, on the computer it
  names, in the CLI and in the app alike, and every printed command runs as printed.
- No pairing state waits ten minutes; a computer that lost its record resumes with the same code;
  a closed attempt says exactly what the other computer can still do, and the way back is one
  removal.
- Removing a computer leaves no offers, no silent room members, no forgotten room removals and no
  lines in the plain status.

### Negative

- Scripts that parse the plain text break; `--json` keeps every field. The proofs' text
  assertions change in the same change.
- Invitation secrets leave the computer state: one more small file under `.daemon/computer`,
  with its own lock and integrity checks; the claim stays in the state.
- The exchange payload grows by a closure list and an acknowledgement list, in every form
  including the refusal frame; the removal body by a time; the pairing handshake by one frame.
- **Two records grow without bound by design** (disclosed to the decider in Q8): the
  `cancelled` entries of closed attempts in the computer state (one small entry per attempt ever
  closed on this computer, kept so that a closure can be conveyed and never revived after any
  partition; after acknowledgement it leaves the `closed` list but stays in the state and in the
  peer's `acknowledged` list), and the `RemovedBasis` boundaries in each node's trust segment
  (one per removed member per room ever seen, kept so that a removed node is never offered on
  an old basis). Neither is a cache and neither is pruned; both are bounded only by the lifetime
  number of pairings closed and members removed, and both must respect the ordinary frame and
  decoder limits when encoded.
- A removal that also removes nodes from rooms cannot be undone except by the creator's
  readmission; the question says so.
- Closing an attempt one has approved can race the other computer's completion; the closing line
  says so and the completed side offers removal. No design without a coordinator can do better
  across a partition.
- The inviter still cannot reach a redeemer behind NAT; the remedy offered is the other direction.

### Neutral

- Daemon identity, the pairing cryptography, the two approvals and the policy itself are
  unchanged (ADR-035 and its accepted contract; ADR-038 FX-52).
- Retained signed history is unchanged; only where it is shown changes.
- The policy ordinal keeps its journal numbering.

## Review record

Findings of `adr-043-sol-review` (2026-11-12), each with its classification against v0.4.30 and
the requirement that answers it. Evidence per finding is in `adr-043-revision`.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| 1 | CJ-5's "both hold or neither" is unimplementable | CONFIRMED | CJ-5 (inviter-owned attempt, confirmation fact, idempotent replay, crash windows), CJ-7 |
| 2 | Cancel racing a completed peer undefined; "inert signature" false | CONFIRMED | CJ-6 (who can complete alone; two closing sentences; closure fact in the exchange; removal path), the FX-41 amendment, Q1 |
| 3 | Claim and record across two files | CONFIRMED | CJ-8 (the claim is the attempt; one transaction; lock order; crash windows) |
| 4 | The 2 s bound ignores `review_gate`, the app queue and the 60 s deadline; cause UNKNOWN | CONFIRMED | CJ-8 (no `review_gate`, end-to-end measure), CJ-4 (no queue, 5 s, readback); item 35 stays UNKNOWN with rows 6 and 7 corrected |
| 5 | Pause refusal is decided at the host, not the actor | CONFIRMED | CJ-15 |
| 6 | Room evictions have no durable owner; `remove` cannot be repeated | CONFIRMED | CJ-12 (removal record), Q6 |
| 7 | Best-effort dismissal reused as a guarantee | CONFIRMED | CJ-11 |
| 8 | The revision gap is numbering, not a second application | CONFIRMED | CJ-14 withdrawn; item 38 rewritten |
| 9 | Next commands cannot be executable without full ids | CONFIRMED | CJ-1, CJ-9, CJ-10, Terms (quoting) |
| 10 | Missing local approval hidden behind "reconnect" | CONFIRMED | CJ-7 (precedence, reach facts, idempotent `pair`), the state table |
| 11 | The app journey is a header check | CONFIRMED | CJ-4, "In the app" (states, action kind, failure paths, two-computer app proof) |
| 12 | Writer-hold staging does not hold the writer; contradictory deadlines and claims | CONFIRMED | CJ-8 (new hold at the writer), CJ-6 (one 2 s deadline), CJ-13 (same-name row), CJ-16 (per-claim mutants; KNOWN/UNVERIFIED) |
| 13 | Removal timestamps have no source | CONFIRMED | CJ-12 (signed `at_ms`) |
| 14 | The shortened review drops the replaced-grants disclosure | CONFIRMED | The review transcripts (the sentence in every review; `Full policy: vox computer policy`) |
| — | Citation ledger: six wrong lines or descriptions | CONFIRMED | Item 35's table, item 38, CJ-10, CJ-15 corrected |
| — | FX-52 "operation 3" and FX-28 plain diagnostics left unamended | CONFIRMED | Amendment table |

Nothing in the review was rejected. Two of its points are narrowed by evidence: finding 2's
divergence is reachable only when the closer is not the sponsor of an addition (for an addition
the sponsor's close is final, `activate` `:5233-5238`), and finding 1's order question is settled
by X2 (the inviter-first order already resumes correctly; the status was the defect).

Findings of `adr-043-sol-review-2` (2026-11-13) on revision 2, each verified against v0.4.30
and revision 2's own text. Evidence per finding is in `adr-043-revision`, "Revision 3".

| # | Finding | Classification | Answered by |
|---|---|---|---|
| F1 | Closure aged out of the wire after the retry bound; no closure-only exchange without `group()` | CONFIRMED | CJ-6 (entries kept for good, derived at every encoding, `acknowledged`; closure-only payload and its admission; `answer` replies with it even on a refused request; `retry` consults `cancelled_links`); proof (b) with the long partition, (b′) with a third member |
| F2 | Code cancel between `answer`'s recheck and its install | CONFIRMED | CJ-8 (invitation lock held across the state install; 2 s bounded acquisition with a busy refusal; a code cancel that finds the nonce claimed becomes an attempt cancel); proof with the before-install hold |
| F3 | Completed `pending` retained; `begin`'s cleanup lost; spent nonce not a claim | CONFIRMED | CJ-8 (cleanup moves into `answer`; claim lookup covers `genesis` and history additions; record lifecycle; early reservation `:2969-2983` replaced); proof: second and third addition, old-code replay, another identity |
| F4 | Third members create no dismissal obligations | CONFIRMED | CJ-11 (obligations created in `merge`'s fold, keyed by the removal event; read barrier); proof with C and a kill at admission |
| F5 | `DismissedOffers` evicts past 4,096 | CONFIRMED | CJ-11 (`RemovedBasis` boundary, never pruned); proof with 4,100 dismissals |
| F6 | An older refresh can overwrite a newer result in the app | CONFIRMED | CJ-4 (request sequence, applied floor, fresh refresh after an action); proof with a parked `status` reply |
| F7 | `authenticated_group_conflict` decodes arity 5 | CONFIRMED | CJ-6 (all three decoders; no five-element form; closure in the conflict preview); CJ-12 (both REMOVE producers and the decoder together) |
| F8 | "closed … after this computer completed it" asserts an order nobody observed | CONFIRMED | State table, journey, CJ-6 words ("closed it on its side at <closer's clock>"); expiry carries the same local-only words |
| F9 | CJ-5 proof (a) rolls back an acknowledged record | CONFIRMED | CJ-5 proof (a) restaged with a before-record hold and a kill; X2 named as the nearest asset receipt, not the proof's red |
| — | Proof table: CJ-4 journey lacked A's approval; CJ-6 race not partitioned; CJ-7 roles swapped; CJ-8 cancelled code reused and 2.5 s; CJ-10 scope not bound; CJ-12 kill not causal | CONFIRMED | CJ-4, CJ-6, CJ-7, CJ-8, CJ-10, CJ-12 proofs rewritten as named |
| — | Person-facing: first-ever pair wording; "lost its record"; Applying-here placeholder; local-only words after close; removal failure outcomes; honest daemon unavailability | CONFIRMED | State table rows (r3), journeys, CJ-1, CJ-12 |
| — | Q8 (new bases in a closed room) | REJECTED as a decider question; CONFIRMED as a defect | CJ-11 pays a closed room's obligation at open before its first exchange, so a new basis is never caught; no contract exception needed |
| — | One-member group and sponsoring a later addition unexercised | CONFIRMED | CJ-6 proof (b) adds D's addition and a read |
| — | J9(g) 1 s versus CJ-6/CJ-8's 2 s; X1/X2 beside journeys they did not run | CONFIRMED | Listed for ADR-045 in `adr-043-revision` |

Nothing in the second review was rejected except its eighth question, which is answered by
design rather than asked.

Findings of `adr-043-sol-review-3` (2026-11-13) on revision 3. Evidence per finding is in
`adr-043-revision`, "Revision 4".

| # | Finding | Classification | Answered by |
|---|---|---|---|
| F1 (partly) | Closure with a refusal not carried through the refusal consumer; authorization incomplete | CONFIRMED | CJ-6 r4: refusal frame `[0, text, closed, acknowledged]`, `response_frame_until` and its three callers commit authorized closures before surfacing the refusal; authorization paragraph |
| F6 (partly) | A refresh started during a mutation, numbered above the floor, can regress the result | CONFIRMED | CJ-4 r4: results ordered by mutation generation; a refresh applies only if started after the last applied mutation result; proof case (ii) |
| N1 | Any recognized peer could close or acknowledge any listed operation | CONFIRMED | CJ-6 r4 authorization: the sender must be `side` of the retained attempt of that exact operation id; unknown operations create nothing; proof (b″) with a former member |
| N2 | `[0, text]` refusal read before `merge`; closure after it never read; refused transaction not durable | CONFIRMED | CJ-6 r4 refusal frame and separate commit; proof (b″) with restart |
| N3 | Request-start order is not observation order | CONFIRMED | CJ-4 r4 |
| N4 | `upto_seq` sampled at payment suppresses a consent given in an open room after removal | CONFIRMED | CJ-11 r4: boundary captured in the effective-removal transaction under the room's admission order; worker only stores; proof with the payment hold; mutant 5 |
| N5 | (b′) partitions B before its approval, so A cannot publish the addition | CONFIRMED | CJ-6 proof (b′) r4: hold after A's `activate`, before delivery to B; mutant on A's admission of B's request |
| N6 | No typed action for `vox node unlock` | CONFIRMED | CJ-1 `Action::Unlock { node }`; two app rows |
| N7 | "has not yet seen the closure" asserts knowledge of a lost acknowledgement | CONFIRMED | Closer transcript and CJ-6 words: "has not confirmed receiving the closure (it may have received it and the confirmation was lost)" |
| — | Disclose the two unbounded records | CONFIRMED | Negative consequences; Q8 |
| — | E-b may stay UNKNOWN but no requirement may fix it | CONFIRMED (already so) | Item E-b unchanged; `fleet-experiments` did not exist when r4 was written, so E-43-1 is still an open experiment with no fix attached |

Nothing in the third review was rejected.

Findings of `adr-043-sol-review-4` (2026-11-13) on revision 4. Evidence in `adr-043-revision`,
"Revision 5".

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R4-1 | The server's op-2 path (`:2912-2929`) still merges and replies in one candidate; an incoming authorized closure or acknowledgement is lost when the positive exchange is refused (`computer.rs:4255-4262`) | CONFIRMED | CJ-6 r5 "Two transactions on every full-exchange consumer": negative lists decoded, authorized and committed first on every consumer (requester and server), positive evidence in a second candidate; proof (b″) at checkpoint b2 through B's acknowledgement and restarts of both; mutant 2 |
| R4-2 | "Mutations apply in arrival order, never dropped" lets a delayed invite re-display a cancelled code | CONFIRMED | CJ-4 r5 one ownership rule (serial actions, status owned by the most recent accepted action or a later-started refresh, late results reported under the button); floor wording removed; four-step journey; mutant 4 |
| R4-3 | (b″) "after (b)" has no A-closed/B-completed state left and no pending B–D operation | CONFIRMED | (b) given checkpoints b1–b3 with public outputs; (b″) at b2; (b‴) former-member attack at b3 on the pending O_BD before D's approval |

Findings of `adr-043-sol-review-5` (2026-11-13) on revision 5.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R5-1 | The late-result proof parks the invite before its write, so no committed code can be stale; `AppRequest` clears its continuation at timeout (`AppRequest.swift:20, 36-43`) | CONFIRMED | CJ-4 proof r6: `VOX_TEST_HOLD_INVITE_REPLY_FILE` after install and snapshot, before reply; readback/cancel of the same code; serial-ownership case with the cancel clicked while held and a mutant that drops serial admission; the before-write hold kept for the during-action refresh case |
| R5-2 | Checkpoint b3 omitted B's own approval of O_BD (`answer` records `approvals: [None, None]`, `:3124-3131`) | CONFIRMED | Checkpoint b3 r6: B approves after D's preview; public outputs on both; (b‴) asserts both unchanged, then D approves |

Findings of `adr-043-sol-review-6` (2026-11-13) on revision 6.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R6-1 | The serial-admission mutant could still leave X absent (a concurrent cancel closes an already-installed X; stale-response ownership then holds), so the claimed red did not follow | CONFIRMED | CJ-4 proof r7: existing displayed X, hold before the invite's live-code lookup, Cancel X queued while held, apparatus release after 2 s, assertion "no open code at all" from `vox computer status` and the window; the mutant yields a new code Y and `pairing code open`; unmet staging is APPARATUS; log order not consulted |

Nothing in the sixth review was rejected. Nothing in the fifth review was rejected. Revision 10 (second correction batch, `adr-cross-asks` rows for ADR-043, `adr-amendment-quotes`,
ledger row 64, ruling X043-14), each checked against the current sibling text:

| # | Ask | Classification | Answered by |
|---|---|---|---|
| X042-18 | CJ-1 to carry `not receiving` with ADR-042's meaning | PARTLY (a room fact, TR-4; no computer-level meaning) | Siblings paragraph "ADR-042": CJ-1 prints `last heard` only; `not receiving` lives in `vox status`'s room lines; ADR-042's sibling row is to drop it for CJ-1 |
| X046-41 | CJ-12's removal writer adds `(target, settled tip)` to `required_ancestors` | CONFIRMED (the writer is ADR-046 SY-3 step 5's; this ADR only issues the write) | CJ-12 "What changes" |
| L3-64-043 | lost-receipt note on every `/tmp` receipt | CONFIRMED (eight citations lacked it) | Causes legend, item 33, X2 citations, item E-b, CJ-5/CJ-6 proofs, Links; ledger row 64 wording |
| X043-15 / unresolved refs | "ADR-048 NW-12" | CONFIRMED (NW-12 never moved; ADR-040 r8 adds the sibling-post assertion) | CJ-14, item 38, siblings paragraph: "ADR-040 NW-12"; every "ADR-048 NW-" citation checked: none left |
| X043-5 | "client open (ADR-044 RD-1's bound)" | CONFIRMED (RD-1 bounds `vox status`) | CJ-8 "What changes", siblings paragraph "ADR-044" |
| Contradiction "Linux restart cost" | "must be unlocked after its restarts" vs ADR-041 RS-1/RS-3 | CONFIRMED (ADR-041 wins) | Siblings paragraph "ADR-041" |
| Contradiction "Trust-debt sentence" | TC-8's words | STALE (r9 carried them); ADR-042:1300 is ADR-042's to fix | — |
| C-043 | "removing a computer deletes its nodes' stores" | STALE (ADR-047 corrected) | — |
| Amendment quotes | FX-28 row and "No predecessor" row NO QUOTE | CONFIRMED | Amendment table: FX-28's two sentences quoted at `d9a8667ba` `:429-433` with the exact replacement; CT-22 row quotes `:158-164` and states no amendment |
| X043-14 | spikes may run on the host; J9(i) blocks | CONFIRMED (ruling) | CJ-16, order step 7, item E-b, siblings paragraph "ADR-045"; no E-43 figure cited |

Revision 11 (re-check of r10 against the accepted r8, `adr-043-sol-review-recheck-1`):

| # | Finding | Classification | Answered by |
|---|---|---|---|
| 1 | E38b equated binding-derivation samples with application counts | CONFIRMED (`pairing.rs:1926-1935`; `computer.rs:3138-3145`, `3259-3264`) | CJ-14: samples are observed derivation changes, corroboration only; a run-only append-only trace at `record_application()` (`host/computer.rs:233`) in the spike's `test-knobs` build counts applications; never committed |
| 2 | Repeated `--keep-rooms` marked every non-`Done` room kept, including committed-but-unrecorded and in-flight evictions | CONFIRMED (worker commits the room write and records `Done` in two transactions) | CJ-12: `Admitted` result; the command runs under the worker's room lock, reconciles by roster (`Done`), leaves `Admitted` in flight and reports it, switches only `Pending`/`Refused` to `Keep`; staging (iii) with `VOX_TEST_HOLD_REMOVAL_RESULT_FILE`; mutant 7 |
| 3 | The r9 repeated-command branches had no proof or mutant | CONFIRMED | CJ-12 proof stagings (i)–(iv) in the removal journey; mutants 5–7; APPARATUS/PRODUCT rule |
| 4 | CT-22 "Current text" quotation invented | CONFIRMED (`ADR-035…:157` at `d9a8667ba` begins "Before implementation, the design MUST settle …") | Amendment table: the actual sentence, `:157-163` |

Revision 12 (second re-check, `adr-043-sol-review-recheck-2`; E-43-1 verdict):

| # | Finding | Classification | Answered by |
|---|---|---|---|
| 1 | The trace at `host/computer.rs:233` misses the `Err`-but-applied branch | CONFIRMED (`:244-260`: `handle.computer_current()` true, "applied computer trust revision", `record_application()`) | CJ-14: trace at both branches, once per (node, target revision, pass), spike event id; fault not counted as failed application |
| 2 | `Waiting(prerequisite)` evictions untouched by `--keep-rooms`; parked retry could resume | CONFIRMED (r11's rule named `Pending`/`Refused` only; the drain parks on NW-1's prerequisite) | CJ-12 table: `Waiting` → `Keep`, retry retired, under the room lock; completion = all `Done`/`Keep` and no `Admitted`; staging (ii) with a trust-debt-parked R4; mutant 8 |
| 3 | Demoting before the review never yields a `Refused` item (the review selects an eligible actor; CJ-10 rejects a moved roster head before confirm) | CONFIRMED | Staging (i): delegated admin a2, removal committed, worker held before admission, delegation revoked, release → `Refused`; unmet refusal APPARATUS |
| — | E-43-1 verdict lines | — | Item E-b (KNOWN outcome, mechanism UNKNOWN; receipt paths and the four verdicts), CJ-16, siblings "ADR-045" |

Revision 13 (third re-check, `adr-043-sol-review-recheck-3`; `rca-relay-only`):

| # | Finding | Classification | Answered by |
|---|---|---|---|
| 1 | `Done`+roster-yes and `Keep`+roster-no had no row | CONFIRMED (r12's table) | CJ-12 table enumerated: 7 results × roster yes/no × flag, plus no-record; readmission after `Done` is never evicted; `Keep` with the member gone reconciles to `Done`; staging (ii′); mutants 9, 10 |
| 2 | A trust debt does not fence a public removal control, so `Waiting(TrustDebt)` was unestablished | CONFIRMED (`pending_text.rs:592-600`, `:647-648` prepare a public control; ADR-048 TC-3 fences protected content) | Staging (ii): a held earlier room write → `Waiting(RoomWrite(R4))`, parked state read from `--json` before continuing (absent → APPARATUS) |
| 3 | A's own creator a1 cannot lose root admin (ADR-007 G-28/G-29 `:201-204, 233-234`) | CONFIRMED | Staging (i): R3 created on C by c1; a2 the only eligible local actor on A; c1 revokes after the commit and re-delegates |
| 4 | "E-1 was a product defect" overstated what matching anchors showed | CONFIRMED | Item E-b: matching anchor sets show differing sets are not necessary; E-1's cause inferred from the same staging shape, not measured; FX-28 named as the contract without a measured 5 s breach |
| B | Cause established (`rca-relay-only`: R1 red, R2 green, R3 red; chain links re-read at the tag: `daemon.rs:422-428, 459-463`; `pairing.rs:413, 905-909, 943, 786-795, 2207-2210, 2536`; `host.rs:1064-1073`; no `set_anchors` at the tag) | — | Item E-b and item 33 mechanism 1 say so with receipts; new CJ-17 with proof and mutant; the 60 s/`no complete frame` observation stays not established and gets its own fix-list item; `vox computer status` anchor line answered under CJ-17 |

Revision 14 (fourth re-check, `adr-043-sol-review-recheck-4`):

| # | Finding | Classification | Answered by |
|---|---|---|---|
| 1 | Staging (ii′) had c1 readmit b1 to R and remove b1 from R4; c1 is R3's creator only, and readmission needs the room creator's root signature (ADR-007 G-29) | CONFIRMED | CJ-12 proof: a1 named R's creator in the base cast; a1 does the R readmission and the R4 removal; c1 stays R3's creator and delegation authority. Scan of every other CJ-12 and CJ-14 step for actor authority: c1 delegates/revokes in its own R3 (G-29); a2 evicts in R3 only while delegated (G-28); a1 evicts, writes and readmits in its own R and R4; the worker's R eviction is a1's; `vox node create` and `vox computer remove` are the operator's own on A; nothing else found |

Revision 15 (task refresh, `v0431-tasks-ADR-043`, six defects; no design change):

| # | Defect | Answered by |
|---|---|---|
| 1 | Status line said E-b UNKNOWN with no fix | Status line: cause established, CJ-17 is its fix |
| 2 | CJ-17 in no implementation step | Step 7 (depends on nothing); CJ-16 becomes step 8 |
| 3 | "room that cannot open" row had no staging | CJ-12 proof (iii′): `VOX_TEST_HOLD_PREPARATION=<R5>` (ADR-042's knob) in-tree; the permanent form by ADR-047 SO-9's corrupt-store arm on the fleet (J6(d)); mutant 11 |
| 4 | "`vox computer status` MUST say `confirmed`" after CJ-1 | CJ-17 and its proof: `--json .state` reads `confirmed`; plain = CJ-1's "in a group with …" with no pending clause |
| 5 | "its own fix-list item (below)" did not exist | Item E-b cites fix-list item 95 (U; reporting speed, not trust delivery) |
| 6 | "the blocking proof is J9(i)" for all spikes | CJ-16 and step 8 name each: E33b → CJ-5(a)/J9(h); E35 → CJ-8/J9(c); E38b → J9(e); E-43-1 → CJ-17/J9(i) |

Revision 16 (sixth re-check, `adr-043-sol-review-recheck-6`; rows 82 and 82a):

| # | Finding | Classification | Answered by |
|---|---|---|---|
| 1 | CJ-5(a)'s and CJ-8's holds called fleet journeys | CONFIRMED (both need `test-knobs` holds; ADR-045 keeps knob claims in tree, exception J5(i) only) | CJ-16 and order step 8: in-tree boundary proofs; CJ-8's asset claim is J9(c); CJ-5(a)'s stays in tree; no knob added |
| 2 | J6(d) does not prove the corrupt-open removal today | CONFIRMED | CJ-12 (iii′): "owed extension of ADR-045 J6(d)" with the paste in `adr-043-revision` (corrupt open, removal, R5 lines, record, continuation after restore/deletion, mutant) |
| 3 | "observed once in the E-43-1 runs" | CONFIRMED | Item E-b: "observed in the red E-43 and RCA runs" |
| 4 (rows 82/82a) | R4's `Waiting` staging used an ordinary post as the owner; evictions deferred behind saves at the tag (`RemoveRoomMember` not exempt in `command_waits_for_save`, `post_save.rs:253-276` → `actor.rs:8075-8088`) | CONFIRMED | CJ-12 "The control lane": one owner in flight at most, then ahead of queued authored writes, never behind a pending save, no quiet-room wait; ADR-048 TC-4/TC-5 own the change (cross-ask); computer commands checked (not deferred); staging (ii) uses ADR-048's withdraw hold as the owner; new removal-under-continuous-posting assertion; mutant 12 |

Revision 17 (seventh re-check, `adr-043-sol-review-recheck-7`, its one P1 from row 82b; its two
P2s are owed to task acceptance, `v0431-owed-p2`, and not edited):

| # | Finding | Classification | Answered by |
|---|---|---|---|
| P1 | CJ-12 stated an absolute control-first rule ("ahead of every queued authored write"), which conflicts with a post's bound and would let a replenished control lane starve posts | CONFIRMED (row 82b supersedes 82a's absolute form) | CJ-12 "The control lane": two FIFO lanes per room; evictions and readmissions are control turns ending at their own Immediate commit; alternation when both lanes are ready; a control step waits for at most the transaction in flight plus one authored write; the no-deferral-behind-a-save prohibition kept; sibling rules cited by id (NW-3 r13, RD-10 r16, TC-4 r11); staging (ii)'s parenthesis and R6's assertion restated to the alternation bound |

Nothing in the fourth review was rejected. Q8's disclosure stands: acknowledgement removes an
entry from the closer's `closed` list, not from the peer's recurring `acknowledged` list nor from
either computer's state.

## Links

- Fix list items 33–38 and E-a; plan E; `rca-systemic`; RcaFrozen (`roompause`); RcaTrust (T1);
  `adr-043-sol-review`, `adr-043-sol-review-2`; `adr-043-revision`; `adr-cross-changes` rows 2,
  3 and 13; `adr-045-revision` (E-1).
- Evidence (every `/tmp` and `/private/tmp` path: receipt lost in the reboot of 2026-11-13; figure recorded in `plan-E`, `rca-RcaTrust`,
  `adr-043-revision` or `adr-045-revision`; to be re-run as the fleet baseline; ledger row 64):
  `/tmp/plan-PlanE/run-e2/timeline.log`, `/tmp/plan-PlanE/run-e3/timeline.log`,
  `/tmp/adr043/run-x1/timeline.log`, `/tmp/adr043/run-x2/timeline.log`,
  `/tmp/adr045/runs/B2-path1500/`, `/tmp/adr045/runs/B2-path0/`,
  `/private/tmp/vox-rca/mac/trust-facts-200453Z.txt`, `/private/tmp/vox-rca/io/facts-200453Z.txt`,
  the operator transcript of 2026-11-12 19:3x–22:3x.
- [ADR-007](ADR-007-membership-consent-and-admin-governance.md),
  [ADR-018](ADR-018-quality-bar-and-product-proof.md),
  [ADR-028](ADR-028-one-experience-keyring-rooms-services-files.md),
  [ADR-033](ADR-033-the-repo-room-is-where-agents-work-together.md),
  [ADR-035](ADR-035-computer-trust-and-daemon-identities.md),
  [ADR-038](ADR-038-daemons-trust-daemons-and-sessions-are-presence.md); in this release ADR-040,
  ADR-048, ADR-049, ADR-050 (the split of ADR-040), ADR-041, ADR-042, ADR-044, ADR-045, ADR-046.
- #798 (the computer-trust technical contract).
- Gray and Lampson, "Consensus on transaction commit" (presumed abort, the coordinator's durable
  record); support.signal.org Linked Devices; the Matrix client-server specification
  (`m.key.verification.request`, `m.key.verification.cancel`, cross-signing, power levels);
  tailscale.com/kb/1028/key-expiry; docs.syncthing.net/intro/getting-started.

## The decider's answers (2026-11-13)

The decider answered all eight questions on 2026-11-13 (ledger `adr-cross-changes` row 42), each
as recommended; the questions are kept below for the record, with his answer first.

- **Q1: close here at once and keep telling the other computer.** **Q2: no room-wide quiet in
  v0.4.31.** **Q3: evict by default, with `--keep-rooms`.** **Q4: `binding` and `retire` move
  under `vox computer advanced`.** **Q5: display disambiguation only; no rename.** **Q6: kept
  rooms are informational.** **Q7: the environment heuristic, stated as a heuristic.** **Q8:
  accept the two never-pruned records.** CJ-2, CJ-6, CJ-11, CJ-12, CJ-15 and the removal
  transcript stand as written with those choices; "(open: Q…)" marks above are now settled.

- **Q1 (CJ-6).** When a person closes an attempt they have already approved and the other
  computer may complete it alone: close here at once, say that the other computer, and any
  computer already in its group, may trust this one until the other removes it, keep telling the
  other until it acknowledges, and offer the removal there (recommended), or wait for the other
  computer's outcome before reporting closure (cannot be promised across a partition; blocks a
  new code meanwhile). Neither promises instantaneous revocation.
- **Q2 (CJ-15).** A room-wide quiet that refuses agent posts, as a new admin-only room entry, in
  v0.4.31: no (recommended as a scope choice: a new signed entry type and fence for this
  release; ADR-046's progress rule addresses the sync starvation behind the Nov 12 request, but
  does not by itself answer a person's wish to stop agents posting while they catch up) or yes.
- **Q3 (CJ-12).** When removing a computer, evict its nodes from the rooms this computer
  administers by default, listed in the one question, with `--keep-rooms` (recommended), or ask
  a separate question per removal.
- **Q4 (CJ-2).** Move `binding` and `retire` under `vox computer advanced`, with actionable errors
  at the old names (recommended), or keep them top-level with better help.
- **Q5 (E-a).** Renaming a computer (`vox computer rename`): display disambiguation only in
  v0.4.31 (recommended; CJ-3 removes the confusion) or a specified rename requirement now.
- **Q6 (CJ-12).** Nodes kept in rooms with `--keep-rooms`: show once as informational with no
  pending action (recommended), or keep treating them as unfinished removal.
- **Q7 (CJ-15).** The terminal boundary for the automatic personal-node selection: the existing
  environment mark, stated as a heuristic and not an authenticated-human boundary (recommended),
  or require a further person-authenticated action before `vox room pause` acts as the personal
  node without `--node`.
- **Q8 (CJ-6, CJ-11): two records that grow for good.** The design keeps, with no pruning, (a)
  one entry in the computer state per pairing attempt ever closed on that computer (so a closure
  is conveyed after any partition and an old approval never revives), and (b) one boundary per
  removed member per room in each node's trust segment (so a removed node is never offered on an
  old basis, whatever dismissal churn follows). Both are small (tens of bytes) and grow with the
  lifetime count of closed pairings and removed members, not with traffic; acknowledgement stops
  retransmission, not retention. Accept this retention (recommended: a pruning rule would
  reintroduce the lost-closure and reoffer defects after the bound), or ask for a bound with the
  defects it readmits named.
