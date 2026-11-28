# ADR-055: A Member Reads Forward from Its Trust or Its Return

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

*Nobody is given older history; coming back to a room is a new key ceremony; a deleted key stays
deleted; `vox trust add --history full` is removed.*

- **Status**: Accepted (2026-11-27) for v0.4.31 by the decider's rulings 1 to 4 below, given by the
  question form. Ruling 1 asked for a design first, checked by an independent security ruling,
  before the build (the coordinating session's reading, `exec/deviations.md:261`). The design went
  through four revisions and four independent design rulings (`design/forward-only/design.md` to
  `design-4.md`, `ruling-1.md` to `ruling-4.md`); the code through seven security code reviews, each
  ending ACCEPT after its fixes, the last for the product diff through `a8d41d7d6` (`sec-code-1.md`
  to `sec-code-7.md`, (g)). This record writes those rulings and that build down; its text was not
  itself put to the decider. **Merged** in pull request #1418, merge commit `18048bf56` on main
  (2026-11-27), whose second parent is the squashed commit `1d6e98f19`, with the tree of `a8d41d7d6`
  (built on branch `scratch/forward-only`, `/opt/vox-worktrees/forward-only`, carrying main
  `18822e02a`); its checks passed, as the coordinating session reports ((h)). What has run, with
  what result, and what has not, is in (f); what was open and how it ended, and what still rests on
  review, is under "Open items". Implementation, acceptance and delivery are recorded on the
  source-bound issues, separately from decision status.
  *(Amended 2026-11-27, amendment 1, merged in #1422 (`eda5ab5e4`): on main since #1418 an author
  could delete a key generation an offline member never received (`exec/found-reds.md` entry 147).
  FO-12, in the section "Amendment 1", replaces the key-debt ledger of FO-5, FO-6 and FO-9 step 3
  with the set of generations each member has not acknowledged; each amended place is marked.)*
  *(Amended 2026-11-28, amendment 2, merged with the fixes of the sixth proof sweep in pull
  request #1424, merge commit `516c08746` on main: FO-13, a generation an author minted after a returned
  member's return cut and its trust decision is released to that member from its origin; FO-14, a
  trust withdrawal changes the author's key whenever a grant committed, an entitlement is held,
  or the other identity is or was admitted to the room as an author (`exec/found-reds.md`
  entries 155 and 161); a member whose return a node has not taken in is no drive member there
  (entry 164a); the key prune is no longer held off by a flag for keys already saved (entry
  164b); the moment before an author's node takes a return in, and two windows of a newcomer's
  first read, put in words; the owner's answers of 2026-11-28; and every proof change that belongs
  to this record, in the section "Amendment 2". Each amended place is marked.)*
- **Date**: 2026-11-27
- **Deciders**: Robert E. Lee
- **Tags**: sender keys, leaving, rejoining, key deletion, history, migration, version cutover,
  KISS, release
- **Amends**: ADR-006 (S-18, S-19); ADR-007 (G-16; G-30's v0.4.20 history limitation; G-32's
  never-removed full-history control); ADR-023 (R12 and R14 in its context, RL-4.1, RL-4.4, RL-4.8,
  decision 5, RL-8.1b, RL-8.5, RL-8.8, proof 7, M23.4); ADR-030 (W-4, the older-peer bullet of S-5,
  the older-peer consequence); ADR-038 (FX-28's journey, FX-32, FX-62); ADR-054 (PL-2's amendment-3
  summary, PL-20 item 5, PL-21 item 4, PL-23 item 6, PL-24 item 1, PL-25 item 5, PL-27 item 5,
  PL-36 items 1 and 2). Records against ADR-046 (SY-11 (c)), ADR-048 (TC-3's own-original exemption,
  TC-8's release line, TC-9 acts 2b and 5) and ADR-049 (LE-9), all three already superseded for
  v0.4.31 by ADR-052, which of their lines this decision overtakes. Each place is marked where it
  stands, and the text it amends stays beside the mark; the list is under "What this ADR amends".
- **Supersedes**, as recorded with ruling 1 (`exec/deviations.md:260`): "the reviewer's open finding
  keys-18 P1 (a rejoiner's older own keys: not wanted), the "never-removed rejoiner keeps full
  history" arm of the readmission proof (its claim is withdrawn by this ruling), and the question
  "leave key deletion off" (answered: on)". It also replaces the answer `rejoin_keys =
  small_or_named` given earlier the same day to that finding (`exec/deviations.md:246`).
- **Related**: ADR-018 (proof), ADR-037 R5 (the own-history fence, unchanged), ADR-052, ADR-053
  (one Vox version per room, ruling 4 there), PRD-001 R12 and R14.
- **Source**: in the release's evidence archive `/opt/vox-evidence/v0431/`: the decider's words in
  `exec/deviations.md` (the 2026-11-27 sections); under `design/forward-only/`: `design-4.md` (the
  design built, its rules R1 to R11, section 4's conditions and section 5's corrections, which win
  over the text they name), `design.md`, `design-2.md` and `design-3.md` (what was tried and
  dropped), `ruling-1.md` to `ruling-4.md`, `sec-code-1.md` to `sec-code-7.md`; the builders' and
  proof writers' records under `design/forward-only/build/` (`FwdBuild1.md`, `FwdBuild2.md`,
  `FwdBuild3.md`, `FwdBuild7.md`, `FwdFix1.md`, `FwdFix2.md`, `FwdProveKeys.md` with
  `FwdProveKeys-item6.md`, `FwdProveRejoin.md`, `FwdProve2Keys.md`, `FwdProve2Rejoin.md`,
  `FwdProve3Keys.md` with its "Review fixes", `FwdProveUpdate.md`, `FwdProve4.md`, `FwdProve5.md`,
  `FwdProve6.md`), where the code as built wins over the design and this record says so at each
  place; the update spike under `design/forward-only/spike/` as `FwdBuild7.md` reports it; the
  busy-room journeys `simple-sync/pull/journey-36/` and `journey-37/`; and
  `release/legacy-room/report.md`. Run labels are directories under `simple-sync/pull/runs/`. Code
  is cited by file and function at `a8d41d7d6`, under `crates/vox-core/src/node/` unless another
  root is given. Nothing was built or run for this record.

## The rulings this record carries

1. **Coming back reads forward** (2026-11-27, by the question form; `exec/deviations.md:250`).
   Asked whether to leave key deletion off for v0.4.31, with "a member who left a room and rejoined
   loses the others' older posts" listed as a fault, he wrote instead of choosing: "**the question
   is weird -- if someone leaves and comes back, they should see from that point forward, not
   historical**".
2. **Key deletion is turned on, and its design fixed** (2026-11-27, asked again with the facts
   straight: "the failing proof gives a returned member older history on purpose with `vox trust
   add … --history full`; key deletion has never run in any release; with it on, `--history full`
   quietly gives less, a returned member sometimes cannot post, a deleted key is handed back after a
   restart"; `exec/deviations.md:252-253`): "**#2 -- fix this design -- it's basically a new key
   ceremony that is expected.**" (option 2: turn it on now and fix; the release waits.)
3. **`--history full` is removed** (2026-11-27, the same form; `exec/deviations.md:254`):
   "**remove**" (option: remove it: nobody can be given older history; everyone sees from the point
   they joined or came back).
4. **Three losses at the update are accepted** (2026-11-27, by the question form;
   `exec/deviations.md:270-274`). Put to him: "anything a member has already read stays readable and
   a member that was only offline keeps everything it is owed; in three rare cases a member may
   never get to read some posts written before the update that it had not yet received: (1) a
   member that was given older history with the old `--history full` option, where the stored
   record does not say when it was trusted; (2) a member that left a room and came back before the
   update; (3) a member that had a key delivery waiting, made by the old version, that it never
   opened, where the sender has already let the old key go." His answer: "**accept**"
   (`update_losses = accept`): "those members read from the update forward; it is said in the
   notes; no extra migration code". These are the decisions `ruling-3.md` asked for as O1, O2 and O3.

The coordinating session's reading of rulings 1 to 3 (`exec/deviations.md:257-261`), not the
decider's words: "Nobody is given older history"; "Coming back is a new key ceremony. A member that
left and joins again starts fresh: current keys from the others, a fresh key of its own; nothing of
its or the others' superseded generations is asked for, re-sent or waited for. What it needs of its
own history is only what keeps its feed whole (it must not write from behind)"; "Old keys are
deleted. A key of a superseded generation is deleted once its holder has read what was written under
it, and is never handed back".

The same day the decider also wrote "**remember, KISS, fixing bad designs > patching broken bad
designs**" and "**just can't erode security**" (`exec/deviations.md:226`, `:232`; ADR-053's ruling
14). This decision was built under both: the older-history machinery is deleted, not patched, and
every revision was checked by an independent security reviewer before it was built ((g)).

## (a) What was found

1. **Key deletion never ran.** ADR-006 S-19 and ADR-023 RL-4.8 required a superseded key to be
   deleted (R14), and the code had the rule (`select_receivers`, `channel/pending_key_prune.rs`),
   but the prune ran after `tend_drive_keys` on each tick, where a busy room starved it; commit
   `41011e978` moved it first and `d5c8c9679` moved it back (`design.md` §1.3). The decider was told
   "key deletion has never run in any release" (ruling 2).
2. **Made to run, it broke coming back** (`design.md` §1.3, §1.4). A node that left erases the room
   and its keys (ADR-023 RL-8.1). On its return its own-history recovery ran a readability audit that
   demanded a key for every one of its own earlier posts and fetched missing ones from other members
   (own-key release, "OwnRelease"). With deletion on, every holder had deleted the generation the
   audit asked for, so recovery waited for ever: W5Rejoin rj27 shows `KeyDebt { seq: 6, epoch: 0,
   chain: 0 }` 87 times (W1). A holder's claim to hold a release only grew, so a wait on a claim the
   holder had pruned did not end (W2). A member without recovery standing for the returner refused
   it as a departed author while the admitting member was unreachable (W3, FixRejoin2 rk6; the
   cause was not traced). And nothing kept a deleted key deleted: a refusal re-owed history from
   the old floor, W-3 re-sent short batches whole, a full grant run again released every retained
   origin, and the OwnRelease install took any claimed release (FixRejoin2 rk7: `owe_history
   target=81 floor=0`, then bob installs chain 0 again).
3. **Coming back already gave older history.** The others changed no key state for a member that
   left; on its return they re-keyed it from its old entitlement, so FixRejoin2's dave "read every
   post under each author's **current** generation, including posts from before he left and while
   he was away" (`design.md` §1.4). A member offline for the whole absence never saw it and kept
   counting its old delivery as held (W4, an inference in `design.md`, not observed).
4. **Older history cost about 3,800 product lines.** The design this replaces promised older history
   on purpose (`vox trust add --history full`, ADR-006 S-18, ADR-023 decision 5) and key release on
   request (ADR-023 RL-8.5's own-generation recovery; ADR-054 PL-20 item 5, PL-21 item 4, PL-24;
   ADR-048 TC-3's own-original exemption). It needed the network own-key asker, the advertisement of
   releases in a Have, the donor (`actor/own_keys.rs`, 1,211 lines), the release index
   (`channel/receiver_releases.rs`, 447 lines), the blocking readability audit, and the donor writer
   gate with its waits. design-4 §2 estimated "about **3,815 product lines deleted and 950 added**";
   commit 5 alone (the network release, the index and the audit) measured +156 −3,697
   (`FwdBuild3.md`). Measured on the branch against the main it carries: product source +2,458
   −6,005 in 80 files, proofs and the app proof +2,639 −1,096 in 15 files, manual, release plan,
   PRD and scripts +81 −77 in 8 files (`git diff --shortstat 18822e02a a8d41d7d6`, by path).
5. **Rooms made before v0.4.10 are refused, as before.** No room v0.4.30 opens is in the older
   format; both older classes (created by v0.4.5 and earlier; by v0.4.6 to v0.4.9) have been refused
   at open since v0.4.10 with one sentence (`release/legacy-room/report.md`, "Short answer" and §2).
   Since #1417 (merged, main `18822e02a`, outside this decision) that sentence says the room cannot be
   opened by this version, its saved data is kept untouched, and to make a new room; leaving it stays
   refused (ADR-038 FX-18, marked). This decision changes nothing there: design-4 R3's sentence on
   non-sparse rooms has no room to act on, and a stored room that is neither sparse nor a supported
   legacy form is refused at open without any reset; the act
   `a_room_in_a_retired_format_is_refused_never_misread_and_its_data_is_kept` is green on the
   merged tree (ft7, "all 11 saved records of the room are unchanged").

## (b) The rule as built

FO-1 to FO-11 follow design-4's R1 to R11 as corrected by its section 5 (`ruling-4.md`) and by the
code as built. Where the code differs from the design, the code wins and the item says so.

- **FO-1. A deleted key stays deleted.** (R1; `ruling-1.md` condition 1, `ruling-2.md` condition 7.)
  1. The deletion test is unchanged: `select_receivers` (`channel/pending_key_prune.rs`) deletes an
     author's generation once every post under it is shown and a later generation is proved. It
     now also returns, per author it walked, the first generation not finished.
  2. In the same batch that rewrites the receivers, `Prepared::run` records an exact tombstone
     `(author, receiver epoch, generation)` in KeyMaterial segment 31 (`SEG_DELETED_RECEIVERS`,
     `DeletedReceivers`), format `[1, [[author, epoch, floor, [chain, ..]], ..]]`. Decoding is strict
     (version 1, rows and chains strictly ascending, chains at or above the floor, no empty row, at
     most the cap, no trailing bytes), and an invalid record refuses the open with nothing reset: a
     schema failure is `MalformedAtRest("deleted receiver tombstones")`, and a canonical-CBOR
     decoding failure propagates as a CBOR error (`DeletedReceivers::decode`). An absent segment is
     empty. The record is loaded at open with the receivers.
  3. Compaction: per author, tombstones below the finished bound fold into the author's floor. *As
     built* (`FwdBuild3.md`, "differed" 7): the floor is an exclusive bound and rises only to just
     past the highest tombstoned generation below the finished bound, never past a generation that
     was not deleted and finished.
  4. At 16,384 tombstones in a room (`TOMBSTONES_MAX`) a key is kept, not deleted.
  5. The guard, for ordinary room receivers only: an offer of a tombstoned generation, pairwise or by
     package, is authenticated (`ReceiverChain::from_skdm`) and then answered as accepted and
     unchanged with its floor resolved; it installs nothing, queues no backfill and is not fresh, so
     no owed-again or reciprocal fresh-key effect follows. A Drive key never consults the record.
     *As built* (`FwdBuild3.md`, "differed" 1): design-4 placed the pairwise guard in
     `accept_skdm_mode`, whose only caller was the OwnRelease install; it is deleted, and every
     received room key, pairwise or package, passes one install, `ChannelState::package_install` and
     `Native::Install` (`channel/pending_package.rs`), where the guard is.
  6. The prune runs before `tend_drive_keys` (`actor.rs`, the re-landing of `41011e978`).
  7. Segment kind 18 (the release index) is deleted by the first pass after the update; its number
     stays reserved.
  8. Deletion is this node's: a copy that already holds the key or the messages it opened, a backup
     made earlier among them, is not affected (`sec-code-4.md` finding 1).
  *(Amended 2026-11-28, amendment 2: on a node that took the last post under an author's new
  generation live, after the last render backfill, the prune could be skipped on every tick, so
  a key the rule deletes stayed until an unrelated backfill (`exec/found-reds.md` entry 164b).
  Fixed by Amendment 2's (b), "Also fixed", item 4; the deletion rule is unchanged.)*
- **FO-2. A departed member is excluded from keys by its latest Presence.** (R2; `ruling-3.md`
  condition 2.)
  1. `key_departed(X)` is true when X's latest authenticated Presence is a departure; only a later
     authenticated `here` Presence, its return, lifts it, not an admission notice or a later entry
     of another kind. `key_excluded(X)` is `is_member_removed(X) || key_departed(X)`, removal first
     (`channel/governance/channel.rs`). `has_left` keeps its wider meaning for sync and recovery.
  2. Every listed room-key builder excludes removed and departed targets: `skdm_for_consent`,
     `rekey_skdm`, `release_generation`, `rekey_skdm_for`, `history_skdms`, held-consent preparation
     and consent preparation call `require_key_target`, which answers `REFRESHING`; where a builder's
     existing removal check comes first it answers as before, a refusal (`rekey_skdm_for`:
     `StreamRefused("room member was removed")`) or an empty key list (`history_skdms`). The package
     key choice (`prepare_owned_consent_key`, `actor/consent_release.rs`) answers a key-departed
     target `NotAdmitted`.
  3. *As built* (`FwdBuild2.md`, "differed" 5): the selection filters (`owed_consents`,
     `owed_rekeys`, `owed_rekey`, `owed_history_for`, `owed_history_page`, and the owed loops of
     both rotations) change from `has_left` to `key_departed`, not `key_excluded`: removal is
     already checked beside each, and `key_excluded` there would add a governance read that can
     answer `REFRESHING` during a rotation.
  4. Nothing rotates at a departure. A room-key frame sealed before the departure is never written
     after it: the fold batch writes store meta `room-departure/<room>/<target>` (the departure's
     feed sequence) when the latest Presence changes to a departure, `reserve_key_deliveries`
     (`actor.rs`) refuses a key-departed peer and records the value with each job, and
     `ReadResource::with_removal_fence` (`channel/history/read_resource.rs`) refuses the frame inside
     the publication fence when the value has changed. *As built* (`FwdBuild2.md`, "differed" 3):
     the meta is not back-filled for stores from before the update; package eligibility reads
     departures from the governance facts and does not depend on it.
- **FO-3. A return is applied like a readmission: one cut and one counter advance per return, by
  feed position.** (R3 with design-4 §5.1; `ruling-3.md` condition 3; `sec-code-1.md` finding 2,
  `sec-code-2.md`, accepted in `sec-code-3.md`.)
  1. `apply_presence_transition` (`channel/governance/channel.rs`) runs inside the uncommitted
     publication batch at both fold sites (received governance, `channel/pending_received.rs`, on
     every Presence fact, also when the folded state did not change; locally authored governance),
     after `Presence::repair` at open for every repaired author before the room is published, and in
     the update's migration (FO-9). For a departure it writes FO-2's meta; for a current return
     (latest Presence `here` after a departure) it calls `reconcile_return`. This node's own
     Presence takes no cut (`FwdBuild2.md`, "differed" 2: its fresh generation comes from recovery).
     A rotation's `here` with no departure before it is not a return.
  2. The return cut is a version-3 record in the `SenderRemovalCuts` table, `[3, target, sender,
     chain, next_iteration, [entitlement], departure, return_hash]`, built from `SEG_SENDER` and
     `SEG_ENTITLED` in that batch (`ReturnCut`, `Write::record_return_cut`,
     `channel/governance/facts.rs`). *As built* (`FwdBuild2.md`, "differed" 1): **one row per
     member**, keyed `sha256("vox/return-cut/v1" ‖ target)`, with the departure and the return entry
     stored in it, not one row per incarnation keyed by the departure as design-4 R3 wrote: a
     correction that changes only the departure must find the earlier row without a scan.
  3. The decision is by feed position (`reconcile_return`; `FwdFix1.md` round 2). The departure and
     return statements are entries of the member's own feed, ordered by its feed sequence. A handled
     return stays the member's current return while none of its departures is positioned after it.
     An earlier return or departure learned late, a replay and a repair reuse its cut and at most
     rebind the row's departure to the latest departure before the handled return. Only a departure
     positioned after the handled return, followed by the return the fold now shows, is a new
     return: it takes a new cut and calls `advance_removal_generation()` once, in the same batch. So
     `D10 → R21 → late R11 → late D20` and `D10 → R21 → late R15 → late D12` keep the first cut with no
     second advance, and `D10 → R21 → D30 → R41` takes two (`sec-code-3.md`).
  4. `View::return_cut` (`channel/governance/view.rs`) validates the row against the facts only: the
     return entry by hash, the target as its author, `here`, this room, the departure equal to the
     latest held departure before it, and no held departure after it. It never reads
     `MemberDecisions`.
  5. The rotation: the advanced counter makes `room_removal_rotation_needed` true, so the node posts
     nothing and releases no room key until it rotates. `prepare_room_removal_rotation`
     (`channel/pending_text/consent.rs`) also takes every `key_returned` target, whose validated cut
     (missing: `REFRESHING`) joins the removal cuts in the existing rule: a target whose entitlement
     is at or below the cut's chain is moved to `(next_chain, 0)` and its history and delivered rows
     are removed. Stale prepared work, receipts and queued frames are refused by the existing counter
     checks; the Drive rotation checkpoint is marked dirty by the same counter and completes through
     the path a removal uses; Sessions wait on it as after a removal.
     *(Amendment 1, merged in #1422: the history and delivered rows are one set per member, which
     the boundary removes, the rotation then adding what the new entitlement allows; FO-12 items 1
     and 3.)*
  6. Removal wins: `is_member_removed` is checked first everywhere; only the creator's readmission
     lifts a removal, and then the readmission cut and any return cut both apply.
  7. Deleted: `departed_seen`, `begin_owned_rejoin_reset` and `After::Rejoin` (the old reset that
     re-keyed a returner from its old entitlement). The departure clean-up of deliveries, ports and
     key waits stays.
  8. A room left while its own recovery was running leaves nothing that holds the room joined
     again: `finish_saved_purge` (`actor/leave_save.rs`) cancels, when it removes the purged
     instance, what that instance deferred or waited for after the purge began (`cancel_own_key_room`).
     Found by the rejoin prover (`FwdProve2Rejoin.md` item 1; the cause read from code, the stall
     itself not reproduced); main has the same fault. Commit `e3456696c`; reviewed in
     `sec-code-5.md` ("cancels the departing instance's waits before any rejoin begins; no required
     new-instance work is cancelled").
- **FO-4. A returner's room keys come only through return-bound version-2 packages.** (R4;
  `ruling-3.md` condition 1, `ruling-2.md` condition 3.)
  1. Sender: `reserve_key_deliveries` refuses a direct frame to a `key_returned` peer; the rekey pass
     sends a returner to `begin_owned_log_rekeys`, and online consent to a returner goes the offline
     (log) route (`actor/consent_release.rs`, `actor/consent_release/rekeys.rs`). The returner route
     skips a member only while the room's in-flight maintenance save carries a consent continuation
     for it (`maintenance_save::Pending::consent`), so a delivery deferred for a fresh one-time prekey
     is taken up again by the next pass (`sec-code-1.md` finding 3, `FwdFix1.md`).
     *(Amendment 1, merged in #1422: one exception, the returner's acknowledgement probe: a sender
     that knows of the return offers a returner directly only releases it already published to it,
     each in a package bound to its current return; a sender that has not applied the return still
     offers directly as before. Either way the returner answers only for a release it already
     covers or holds a tombstone for, installing nothing; FO-12 item 9.)*
  2. The package names the returner's return Presence as a required ancestor
     (`ChannelState::package_return`, applied to consent packages and to Session key packages): an
     excluded recipient gets no package; a never-left one needs none; a return whose cut this node
     does not hold yet is `REFRESHING`, and the append waits until governance brings it.
  3. Eligibility at open, install and serve (`recipient_eligibility_at`, `view.rs`), for a key
     package not authored by its recipient: a departed recipient, ineligible; a returned recipient,
     `contains_cut(package, r)`, where `r` is the earliest held `here` after its latest held departure
     (*as built*, `FwdBuild2.md`, "differed" 8; the sender binds to its fold's return, the same or
     later); a never-left recipient, as before. The "no removal ever, all eligible" shortcut also
     requires that no key package is asked about. Content bodies are not cut.
  4. Receiver, room keys only (`package_install`): while this node's own history is behind (its own
     membership unknown), a package waits (`REFRESHING`) and a direct offer is refused; a key-departed
     or returned node refuses a direct offer (`NotAccepted`). A version-2 package waits at Open, before
     its one-time prekey is spent, while own history is behind (`sec-code-1.md` finding 1,
     `FwdFix1.md`); install checks again. *As built* (`FwdBuild2.md`, "differed" 7): "unknown" is
     `own_history_behind()`, which `sec-code-1.md` found holds for every retained continuity-marker
     branch of the join. Rendering with keys already held is untouched.
  5. `KeyPackage` is version 2 (`keypackage.rs`). A version-1 package is parsed for structure only, so
     historical typed-body validation and own-feed recovery still read it; it is never opened,
     installed or counted as delivered, and spends no prekey.
- **FO-5. Delayed and renewed consent deliver from the stable floor.** (R5; `ruling-3.md` condition
  4, `ruling-2.md` condition 2.) In `prepare_owned_consent_key`, when the target holds an entitlement
  `(g, i)` and is not excluded: `g` live gives `release_generation(g, i)`; `g` older gives the live
  generation at its origin (`rekey_skdm`) and the history debt; `g` newer than live is
  `MalformedAtRest`. Without an entitlement, a once-removed or returned target gets the current
  position, and others the selection as before (`history_plan` for a newcomer, `skdm_for_consent`
  otherwise). The consent save takes the debt from the merged floor. `prepare_pending_consent` refuses
  `REFRESHING` a key or floor before a held entitlement and holds a returned target to the live chain.
  A withdrawal or revocation removes the entitlement, so a later trust decision starts from its own
  boundary. *As built* (`FwdBuild2.md`, "differed" 4): R5's clause on `delivered` is met through key
  selection; the consent-delivery ledger is unchanged.
  *(Amendment 1, merged in #1422: the consent-delivery ledger is replaced by FO-12: per member,
  the set of generations not acknowledged over a direct delivery; a package settles nothing, and a
  direct answer settles exactly one generation.)*
  *(Amended 2026-11-28, amendment 2: "a once-removed or returned target gets the current
  position" no longer holds for a returned target whose author's live generation was minted after
  that target's return cut and its trust decision: that generation is released from its origin
  (FO-13). A once-removed target that has not returned, and every case of doubt, still gets the
  current position.)*
  **A member trusted again after a revocation** (`FwdFix2.md`; `history_plan`, `channel.rs`): the
  plan for an identity this author has revoked in the room is computed as for one never revoked,
  from this room's trust mark of the author's **current** decision, and is accepted only when that
  mark's decision is the keyring's current decision, the mark lies in the generation the **latest**
  signed revocation moved the author to (its `new_chain_id`) or a later one of the same epoch, and
  the plan starts at or after the mark; otherwise there is no plan. So new key releases to such a
  member start at its re-trust point, as any member's start at its trust point; nothing sealed
  while it was untrusted, or before, is released to it again. Messages and keys it already holds
  stay usable, so earlier posts it can open with a key it kept may still be shown to it (`FwdFix2.md`,
  erin's read). The same function serves a consent after the update, so
  a re-trusted member now gets its key from the position marked at the re-trust decision, not from
  the author's position when the key is delivered. Before this fix every once-revoked identity had
  no plan (design-4 §5.2's defect, met at the update by FwdProveUpdate's case 1b).
- **FO-6. No departed or removed member pins old origins through a history floor.** (R6;
  `ruling-3.md` condition 6.) `oldest_generation_needed` (`channel.rs`) takes history floors only of
  members that are not `key_excluded`. A continuously entitled member that is offline keeps its floor,
  and its origins are kept until it takes them, with no expiry. The 30-day hold for a trusted
  identity that has not joined (`UNJOINED_HOLD_SECS`) is unchanged and separate; a removed identity
  that is still trusted and holds no entitlement here counts under it, so "pins nothing" holds for
  history floors only (`sec-code-1.md` area 4, `FwdFix1.md`). The full-history prune gate is deleted
  with full grants.
  *(Amendment 1, merged in #1422: history floors are replaced by the sets of FO-12. A
  continuously entitled member that is offline keeps each generation pinned until it acknowledges
  that generation over a direct delivery, not merely until it "takes them" or is reachable, except
  that at the 256-origin cap a message-bound or mandatory rotation evicts the oldest origin with a
  named loss line (FO-12 item 8); the prune keeps what any
  non-excluded set holds, the live origin and the never-joined hold (FO-12 item 7). As built on main
  by #1418, this sentence did not hold: an author could delete a generation such a member never
  received ((a) of amendment 1).)*
- **FO-7. Older history is removed; local recovery and the feed-integrity fence are kept.** (R7;
  `ruling-1.md` conditions 6, 7 and 9.)
  1. Removed: the `--history` choice in the CLI, the terminal app, the FFI the Mac app uses and the
     IPC trust request, with `TrustWith.history`, `HistoryGrant` and the trust-save plumbing; the full
     release (`full_consent_release`) and every `full_history` thread; the `readmission-full-plan`
     knobs. A caller that still sends the choice is refused: the CLI by clap, an IPC-12 client at the
     handshake, an IPC-13 trust frame with six fields as malformed ("a trust request no longer takes
     a history choice: a member reads from its trust point on").
  2. Removed, network own-key release: the asker and its debts (`history_stream/pull.rs`), the
     own-release section of a Have, the donor (`actor/own_keys.rs`, the whole file), the install, the
     release index (`channel/receiver_releases.rs`, the whole file) and `channel/role_owed.rs`. An
     own-key request (`RecoveryOpen`) or reply is refused with `NotAccepted` before it reaches the
     actor, on every connection; the own-recovery ALPN is still accepted and never used
     (`FwdBuild7.md` §1).
  3. Removed: the blocking readability audit (`OwnReadability`, `Stage::Audit`, the `KeyDebt`
     plumbing) and the donor writer gate (`channel/own_writer_gate.rs`) with every wait on it. *As
     built* (`FwdBuild7.md` §1, "Kept"): leave, close, purge, untrust and recovered-room publication
     keep their bounded-room retirement, Computer publication and room-lock waits; only the gate is
     gone, and the names `own_key_*` are now historical. The error that named an own-key writer
     drain, whose only producer is headless startup failing to take the Computer publication
     transition, is `ComputerTransitionBusy`, "the computer's publication transition was busy"
     (`FwdProve3Keys.md` item 3, `sec-code-5.md` finding 3).
  4. Removed as dead (`FwdBuild7.md` §2): the long-lived-session key sender (`older`,
     `select_owned_legacy_session`, `frame_owned_legacy_key`, `Stage::Legacy`, `LegacyConsent`,
     `RUNS_OLDER` and the rest); nothing inserted into `older`, so every branch was unreachable.
  5. Kept: the local Receiver stage, now Receiver → Ranges (`channel/pending_recovery.rs`), with
     `full_history_skdm` (`group/history.rs`) for this caller only; the `OwnHistoricalKeys` records,
     their readers and their retirement; local own receivers, with the overlay's stale-record cursor.
     *As built* (`FwdBuild3.md`, "differed" 2): `channel/pending_cleanup.rs` is not deleted whole as
     design-4 listed; it is reduced to that cursor, which local recovery needs (`sec-code-1.md` area
     5: "Keeping `pending_cleanup.rs` is **correct**").
  6. Kept whole: the feed fence. Every local append checks `require_own_history_safe_in`
     (`channel/own_history.rs`), and `own_behind` is cleared only by recovery's `Work::Complete`,
     which first passes `require_own_recovery_complete`: standing, extent, accepted head, held-through,
     root, boundaries, no own backfill pending, legacy current, governance sender generation. Only the
     audit-cursor check is gone. The fresh own generation is `max(sender, retained, recovered) + 1`.
     No timeout, missing key, stale notice or absent holder lifts the fence.
- **FO-8. The "departed author" wait ends through the existing board exchange.** (R8.) A holder
  learns a valid admission notice newer than the departure, from a current witness, through the
  existing full board exchange, then publishes the standing and serves the prefix; "to the actor:
  departed author" is a hand-off, not a refusal. With no such holder the node stays fenced and says
  so. Nothing is added. The W3 act shows it ((f)).
- **FO-9. The update migrates each room once, in one transaction, with three accepted losses.** (R9
  with design-4 §5.2; `ruling-3.md` condition 5, `ruling-2.md` conditions 4 and 5; ruling 4.)
  1. One `Work::ForwardMigration` per room (`TurnStage::ForwardMigration`, `actor/governance_save.rs`)
     runs after a ready fold and before the room's rotation, while the room lacks marker segment 33
     (`SEG_FORWARD_MIGRATED := [1]`, strict). Until it commits, the room's key releases refuse
     `REFRESHING` and no origin is pruned. It prepares from committed state
     (`prepare_forward_migration`, `channel/pending_text/consent.rs`) and writes the entitlement,
     history and delivered ledgers and the marker in one batch; an interrupted migration has no marker
     and runs again at the next open. On completion the daemon says "room <id>: its keys are released
     from each member's trust point on (forward only); this room is updated once" and starts the
     room's re-keys. New rooms are written with the marker.
     *(Amendment 1, merged in #1422: the history and delivered ledgers are one ledger of sets
     (FO-12 item 1); step 1 raises or clears a member's set as it raises or clears its entitlement.)*
  2. Step 1, a member a build before v0.4.31 trusted with full history (keyring column 1): when it has
     a validated removal in this room, its forward-only entitlement and debt are kept unchanged;
     otherwise, when `history_plan` gives a plan, its entitlement is raised to the plan's first
     position (`max(entitled, floor)`) and its history row likewise, the row dropped if it reaches
     the live generation; otherwise (no plan) its entitlement goes to the live position and its
     history row is removed (accepted loss O1). With FO-5's re-trust rule, a member untrusted and
     then trusted again with the old option, whose re-trust this room marked after the latest signed
     revocation, gets a plan from that mark and keeps its catch-up from it; O1 applies only where no
     forward-only boundary can be established (no decision value, a mark of another decision or
     epoch, a mark before the latest revocation, no contiguous origins), as design-4 §5.2 requires.
     A member with no entitlement row (a re-grant still owed at the update) is released from the
     same floor by its consent. *As built* (`FwdBuild1.md`): `trust_marks` is not removed in the
     `None` case.
  3. Step 2, a member that came back before the update: its return is reconciled as FO-3 does, in
     the migration's batch before the ledgers and the marker, so its cut records its pre-update
     entitlement and the next rotation moves it to a fresh chain (accepted loss O2). No clock is
     involved.
  4. Step 3, every other entitled member that is neither excluded nor returned: owed again, from
     its entitlement, every retained generation (its origins are kept by its history row), and its
     delivered row is dropped, so the re-keys deliver the live generation and every retained owed
     generation again, directly or as a version-2 package. The receiver ignores what it holds and
     tombstones what it deleted. What cannot be re-delivered is a generation whose only surviving
     release was an unopened version-1 package and whose origin is gone (accepted loss O3).
     *(Amendment 1, merged in #1422: a member re-owed here has in its set every retained
     generation its entitlement allows and keeps each until it acknowledges it over a direct
     delivery or the 256-origin cap evicts it (FO-12 item 8); a version-1 history row is decoded
     strictly and then read the same way (FO-12 item 1).)*
  5. The keyring's column 1 is written 0 only when every stored room, closed rooms included, holds
     segment 33. *As built* (`FwdBuild1.md`): it is cleared at unlock (`clear_legacy_full`,
     `actor/trust_save.rs`), not right after the last migration; the headless startup path does not
     clear it, and the flag releases nothing. A closed room migrates when it opens.
  6. Signed and stored layouts: a consent's `HistoryMode::FullHistory` (value 1) still parses and
     verifies over its exact signed bytes and is ignored for releases; new grants write 0; unknown
     values stay invalid. The keyring keeps version 4 and its row arity. Segments 31 and 33 have strict
     versions. Segment 24 (the old readability cursor) is never read and is deleted at completion.
     Frame tag `0x0D` is decoded and discarded with no effect.
- **FO-10. The version cutover holds in both directions, per connection.** (R10; `ruling-2.md`
  condition 6, `ruling-1.md` condition 8.)
  1. The history preamble is version 3 (`PREAMBLE_VERSION`, `history_stream.rs`); Sync goes through
     the same decoder. A node that receives a preamble of another version refuses the stream with
     the coded reset `ProtocolVersionUnsupported` (0x01) instead of dropping it, and marks the
     connection (`syncstream.rs` `read_request_preamble` → `Opening::OtherVersion`;
     `actor.rs` `other_version_refused`; `VoxConnection::note_other_version`, `transport/quic.rs`).
  2. A room key is enqueued, written and accepted directly only on a connection that completed a
     version-3 exchange for that room and epoch, in either direction. *As built* (`FwdBuild1.md`): the
     record of that exchange is the existing per-(room, peer, connection) `Holdings`, made by a
     version-3 request either way and gone when the connection closes. A key that cannot be written
     stays owed. A key in the pair's long-lived session is refused, and its sender code is gone
     (FO-7 item 4).
  3. Packages: only version 2 is opened or installed (FO-4). IPC is version 13.
  4. *As built* (`sec-code-4.md` finding 3): the refusal is per connection, not per room. Two updated
     computers exchange history and keys while a third in the room still runs the older version;
     design-4 R10's "a mixed room exchanges nothing until every computer has updated" describes only
     the pair that differs. Nothing is disclosed under the old policy and nothing is misread.
  5. What is said (`FwdProve3Keys.md` item 2 and "Review fixes"): the refusal is written on the sync
     row of that room and peer as its last failure (`history_stream.rs` `OTHER_VERSION`), on the side
     that received the other preamble and on the side whose preamble was refused with 0x01
     (`history_stream/pull.rs` `Connection::failure`). The receiving side writes it only when it
     serves the room the preamble names, the peer is a member there and its removal is not applied
     (the room id is the sender's unauthenticated claim; `sec-code-5.md` finding 1). A round with
     that peer that ends without error retires both the line and the connection's mark, so a later
     unrelated failure carries its own words (`VoxConnection::retire_other_version`;
     `sec-code-5.md` finding 2). A real v0.4.30 computer is unchanged: it drops a version-3 stream
     silently and says what it says of a closed stream; the updated side still names it, from the
     old computer's own version-2 streams on that connection.
- **FO-11. What a person is told.** (R11.) The sentences are in (c).

**Also in this change: two product faults the proofs found, present on main too** (`FwdProve4.md`,
"Product faults and fixes"; `sec-code-6.md`). They are not rules of this decision; they ride with
it because its proofs exposed them.

1. **An idle node never became idle.** A node's own append asked its key-package queue for a turn
   that nothing then gave it, and that request is what `vox status` reports as
   `key_packages_pending`, so an idle node that wrote last kept saying it had key packages pending.
   The request is now made only for a received entry: the queue's `published` call is removed from
   `finish_pending_text` (`channel/pending_text.rs`) and moved out of `finish_entry_publication` to
   its one remote caller, `accept_entry` (`channel.rs`). On main since
   `9c77e22db` and `7bc390c74`; the idle-computers journey passed there by timing [the prover's
   inference]. Commit `53cdf0537`.
2. **A held create was refused by its own name reservation.** A room create parked by a Computer
   policy move found its own reservation of its name when it resumed and refused with "a room this
   node holds already has that name". `resume_parked_construction` (`actor/construction_save.rs`)
   now looks for another holder of the name with this create left out of the search, across
   reservations and published rooms, and drops its reservation only on a final refusal (commits
   `53cdf0537`, `2edfea869` after `sec-code-6.md`'s finding). On main the same code, not reached
   there because the stage before it is red.

*Source*: design-4 §1 and §5; the builders' records; the reviews. *Why*: (a), and rulings 1 to 3.
*Built*: (h).

## (c) What a person sees

- `vox trust add <fp> --history …` is refused by clap: `error: unexpected argument '--history'
  found`, with the usage line. Trust releases what the truster writes from the trust point on; a
  member trusted while offline catches up on what came after its trust point; a member untrusted
  and trusted again reads from where it was trusted again (FO-5).
- A member that leaves and joins again reads what is written from its return on. Each member rotates
  its key for the room at the return and sends the returner only the new chain, by key package.
  Messages written before it left, or while it was away, stay unreadable unless its node still holds
  them. When its own recovery completes the daemon says "room <id>: this node is back in this room:
  it reads what is written from now on and can write here again" (`actor/recovery_save.rs`; set by a
  `returned` bit in `Saved::Recovered`). The restart note ("this node recovered its own history; it
  can write here again") and the fenced notes are unchanged.
- A returner reads nothing written before its return, including what a member wrote while its
  recovery was pending: its return Presence is signed only when its recovery completes, and until
  then every member holds it departed. Its writes are refused meanwhile with ADR-037 R5's sentence,
  and `vox status` says "own history recovery is pending".
  *(Amended 2026-11-28, amendment 2: "before its return" is counted on each author's node. A post
  an author writes after the returner's `vox room join` answered, but before that author's node
  applied the return Presence, is for that author written before the return, and the returner
  never reads it (Amendment 2 (b), "The window before an author takes a return in").)*
- An older-history request that meets posts no retained key opens says "The oldest posts held here
  of {n} member(s) cannot be read with the keys this node retains. Coming back to a room does not
  restore earlier keys." (`actor/history_demand.rs`), counting this node's own posts too. That is
  final for posts from before the trust point or the return and for posts under a deleted key; a key
  still owed for posts written while the node was offline can arrive (the manual says so after
  `sec-code-4.md` finding 2).
- A deleted key is never installed again on that node, whoever offers it.
- Two computers on different versions exchange no history or keys with each other. While they are
  mixed, `vox status` on the updated computer shows, on the sync line of that room and peer, "last
  failure: that computer runs another Vox version; this computer exchanges no history or keys with
  it until both run the same version"; a computer of this build whose preamble the other refused
  shows the same line. A successful round after the update removes it (FO-10 item 5). A real
  v0.4.30 computer says nothing new. A key owed to an older computer stays owed until it updates;
  the troubleshooting page names the line and says to update the older computer. The Mac app shows
  no sync row.
- Each room not yet migrated logs its migration line once, when its migration completes (FO-9); a
  closed room migrates when it is next opened. `[preparing history]` in `vox room list` reports the
  room's opening preparation, not the migration's progress (`summary_of`, `actor.rs`, publishes an
  open room with `preparing: false`; the migration runs afterwards in the room's governance turn).
- `vox status --json`'s `key_generations` is documented as "one, unless a member that stays entitled
  has not yet taken an older one it is owed as catch-up" (`status.rs`).
- The manual (`docs/manual/keyring.md`, `rooms.md`, `troubleshooting.md`) and PRD-001 R12 change with
  the code, in the code pull request.
- The release notes are to carry design-4 R9's sentence, which claims only the three accepted
  losses: "Updating to v0.4.31 keeps everything a member has already read, and a member that was only
  offline still receives what it is owed. In three rare cases a member may never read some posts
  written before the update that it had not yet received: a member given older history with the
  removed `--history full` option whose trust point is not recorded; a member that left a room and
  came back before the update; and a member whose only pending key delivery was made by the old
  version, never opened, and already deleted by its sender. These members read from the update
  forward." `FwdFix2.md` confirms the sentence needs no widening: the member untrusted and trusted
  again before the update is not a loss any more (FO-5, FO-9). With it, from the builders' records:
  `vox trust add --history` is gone; coming back to a room is a new start; a key this computer has
  deleted is never installed again; that the first start prepares each room once and a stop during
  it is finished at the next start; and that computers of one room are to be updated together:
  "posts made meanwhile on either side are shown everywhere once the last one has updated"
  (`FwdProveUpdate.md`; its other wording, "A room exchanges nothing between computers until every
  computer in it runs v0.4.31", is room-wide and FO-10 item 4 says the refusal is per pair).

## (d) What is deliberately not built, and why

- **No rotation at a departure.** By the ruling of 2026-10-01 (`actor.rs`, cited in `design.md`
  §1.4) members do not rotate when someone leaves; an honest leaver erased its keys. The return's
  rotation is the new key ceremony (`design-3.md` Part 0).
- **A departure is not a removal fact.** A removal also refuses public sync and history, which a
  returner needs to recover its feed, and bars an ordinary rejoin (ADR-007 G-30, G-31). So a
  departure excludes only at the key consumers, by FO-2's predicate (`design-3.md` Part 0).
- **No option to give older history, and no key released on request over the network** (rulings 1
  to 3).
- **No migration machinery beyond one transaction.** Parking records, a recovery format and an
  approval switch for the uncertain cases were not built: the decider accepted the three losses
  ("no extra migration code", ruling 4), and `ruling-4.md` says "Do not restore parking records,
  recovery machinery or an approval switch."
- **No version exchange or compatibility path.** One Vox version per room (ADR-053, ruling 4 there:
  "for now, yes").
- **What was tried and dropped.** `design.md` (D1) had one deletion floor "through" a generation,
  which `ruling-1.md` found unsound (a late entitled key would be refused), dropped the local
  Receiver stage (rejected as avoidable loss), and re-keyed a returner at its old position.
  `design-2.md` added a return barrier with its own state (`return_pending`, `release_floor`,
  `SEG_RETURNS`, `Work::ReturnReset`, incarnation fields on prepared work) and a clock-based cut for
  returns before the update; `ruling-2.md` required the clock cut removed and the barrier extended to
  the physical writer and to packages. `design-3.md` replaced all of it by the existing readmission
  machinery (`design-3.md` Part 2: "What design-3 deletes compared with design-2"), and `ruling-3.md`
  accepted that direction with five conditions; design-4 carried them and `ruling-4.md`'s two
  corrections.
- **Not renamed:** the `own_key_*` lifecycle names (`FwdBuild7.md`). **Not removed:** the
  own-recovery ALPN in the transport, still accepted and unused.

## (e) What the rule gives up

1. **Leaving does not rotate keys.** A member that left keeps, in any copy it kept, the keys it held;
   members re-key only when it returns. Revocation of keys a hostile or restored copy kept is not
   claimed (design-4, "Security": "Not claimed").
2. **A backup made before a key was deleted still opens what it held.** Deletion is per node (FO-1
   item 8).
3. **The three accepted losses at the update** (ruling 4): in those cases a member that had not
   received a key before the update reads from the update forward. Nothing already read or held is
   lost, and a member that was only offline loses nothing. Of the three, the update journey produced
   O2 (exactly one post); O3 needs a sender that already deleted the generation and was not produced
   in its small stores; the "no decision value" form of O1 cannot be produced with v0.4.30, which
   records a decision at every `trust add` (`FwdProveUpdate.md`).
   *(Amendment 1: "a member that was only offline loses nothing" was not true of the code merged
   in #1418: a member offline across rotations could lose a generation for good ((a) of amendment
   1). FO-12, merged in #1422, makes it true again except for a member offline through more than
   256 of an author's key changes, which the cap names as it evicts (FO-12 item 8). The returning
   reader 8,000 behind read every post in five runs (amendment 1 (f)); no run reaches the cap.)*
4. **Computers on different versions exchange no history or keys with each other** until both run
   v0.4.31; between those two computers the room is silent, while each side keeps exchanging
   within itself. A computer still on v0.4.30 is told nothing about why.
5. **A returner's keys travel by log package, not directly**, so they need the returner's prekeys and
   a member that has applied its return; a sender that has not received the return Presence defers
   (design-4 §3, "most likely to go wrong" 3). The rejoin acts show a returner's keys arriving by
   package ((f)); the deferral resolving under load is not staged.
   *(Amendment 1, merged in #1422: the returner's acknowledgement probe lets a sender that knows of
   the return offer the returner directly a release it already published to it in a bound
   package; the returner installs nothing from it; FO-12 item 9.)*
6. **A returner reads nothing written while its own recovery was pending** ((c); the rejoin prover's
   reading, `FwdProveRejoin.md` act 4, "changed by ruling").
7. **While a node's own history is behind, version-2 key packages wait unopened**, Drive packages
   included: before decryption a Drive package cannot be told from a room one (`FwdFix1.md`); a
   version-1 package stays ineligible and is passed over without being opened (`Work::Open`,
   `channel/pending_package.rs`). The
   reviewer: "Drive packages also remain pending indefinitely if own recovery never completes. This is
   an additional availability restriction, not guaranteed temporary; held-key rendering remains
   unaffected." (`sec-code-2.md`).
8. **At 16,384 tombstones in a room, keys are kept rather than deleted** (FO-1 item 4).
9. **A removed identity still trusted and without an entitlement holds origins** for the room's
   retention or 30 days, as an unjoined one does (FO-6).
10. **A return learned before its departure** counts as present without a break until the departure
    arrives (`FwdFix1.md` round 2, case (f), marked there as an inference).

Confidentiality: design-4 claims nothing weaker ("Weaker: nothing in confidentiality"), and lists as
strictly safer no pre-return or absence-period release, no own-key release, no full-history release,
fewer keys at rest, and deleted keys staying deleted. That claim rests on the design rulings and the
code reviews, which read and ran nothing ((g)).

## (f) Proof

Each act drives the shipped `vox` binary (ADR-018) and keeps one mutant arm, a test-knobs switch run
as `VOX_MUTANT_FWD=<value>` (the act forwards it to its daemons as `VOX_TEST_FWD_MUTANT`; set
directly it never reached a daemon, so runs fy3-mut to fy9 and fj5's mutant runs gave no verdict,
`FwdProveKeys.md`, `FwdProveRejoin.md`) or `VOX_MUTANT_FX62=<value>`. An arm counts only when its
red is on the act's own assertion and its engaged line is in a kept daemon log. Runs are on scratch
trees of the branch: fy, fj on `99d56ec7a`; fn, fz and fh on `553a7d0c5` with their writer's
uncommitted changes; fu on `553a7d0c5`, fv on `073ea52fe` and fw on `2f83ebbda`; fp on `2f83ebbda`
and fs on `2c97d1b0d`, each with its writer's uncommitted changes; ft on `1227ae9eb`, the tree
merged with main `18822e02a`, plus the revocation act's test change later committed as `a8d41d7d6`
(the two commits differ only in that test file). Every run below was one run unless more are named.

**On the merged tree** (`FwdProve6.md`, "Every act run"; ft runs): every base listed here ran green
once; the arms red on their own assertion with a retained engaged line are named with each. The
revocation act (ft2) and the retired-format act (ft7) ran without an arm. The split-history act and
`VOX_MUTANT_FORK=fallback-off` (ft3); `a_member_that_left_joins_again_and_is_a_member_again` and
`direct-accepted` (ft3, the arm's first counted run with an engaged line); the variants act and
`package-unbound` (ft4); `a_node_that_left_rejoins_and_posts_at_once`, `the_tui_leaves_and_ends`,
`an_ended_room_can_be_left_at_once`, `a_room_left_leaves_nothing_on_the_node` (ft4, no arm run);
the key-deletion act and `floor-not-exact` (ft5); the thirty-day act (ft6, no arm run); the update
journey and `migrate-clamp` (ft8, "finished in 262.83s" / red at `update_proof.rs:4863`). The rest
below ran on earlier trees, as named.

**Deletion and keys** (`FwdProveKeys.md`; `FwdProve2Keys.md`; `FwdProve3Keys.md`):

- `a_member_deletes_another_members_key_once_it_has_read_everything_sealed_under_it`
  (`crates/vox-tui/tests/a_member_deletes_a_key_it_has_read_to_the_end_proof.rs`), with a
  same-receiver part: bob holds alice's generation 0 back, reads and deletes generation 1, then
  generation 0 arrives late and he reads its posts. Green: fy1 (unchanged act), fy3 ("room s: once
  generation 0 came, bob shows [zero 1, zero 2, one 1, one 2, two 1]"). Mutant `floor-not-exact`, fy11,
  red on the act's assertion: "PRODUCT: bob never read post 0.x: alice's generation-0 posts in room s
  ("zero 1", "zero 2") stayed unreadable 90 s after his node let that key through; his deletion of
  generation 1 refused generation 0". Extended in the second round with two stagings: with bob down,
  alice puts what she owes him, the deleted generation 1 among it, into the log as key packages, and
  generation 0 then reaches him only by package; and at the end a Drive key of alice's with the same
  generation number installs ("bob lists alice's Session as … "can_drive": Bool(true)"). Green fz9
  ("with bob down, alice's daemon put 3 key(s) for him in the log"; "once generation 0 came by
  package, bob shows [zero 1, zero 2, one 1, one 2, two 1]"; "bob ends holding Some(1) of alice's
  keys") and fh4; mutant `floor-not-exact` red fz9 and fh4: "PRODUCT: bob never read post 0.x: …
  stayed unreadable 90 s after his node came back to her key packages", fz9 with its engaged line.
  Which generations the three packages carry is read from code, not from output. Runs fh4 to fh7
  are read from their logs; their writer's record stops before them (`FwdProve3Keys.md` item 4).
- `a_key_kept_for_someone_who_never_joins_is_deleted_after_thirty_days`: green fy4, fh5 ("+31 days:
  alice holds Some(1)"); mutant `hold-off`, fy12, fh5, red: "PRODUCT: at +31 days the generation kept
  for dave, who never joined, must be deleted (R14)".
- `an_author_keeps_a_key_only_while_a_member_still_needs_it` (renamed from `history_grant_proof`, its
  full-history arm deleted by ruling 3): bob, trusted before and offline across two rotations, reads
  every post after his trust; alice then holds one generation; carol, who left, pins nothing. Green
  fy5, fh6; mutant `departed-pins`, fy13, fh6, red: "PRODUCT: alice still holds Some(3) generations
  60 s after bob took every key he was owed: carol, who left, must pin nothing".
- `a_member_restored_from_an_older_backup_writes_nothing_until_resolved`: green fy6, fh7, fs11. Its
  arm `receiver-off` went red in fy14 and fh7 on the act's assertion, "PRODUCT: alice, recovered,
  must read her 3 kept rows, the 3 the copy lacked and her 2 new post(s) …", but those runs lack an
  engaged line (the switch printed none then); fs11 is the counted red, with its engaged line.
  `sec-code-1.md`'s staging of a package waiting past the
  one-hour prekey retention belongs here and has not been run (`FwdProve2Rejoin.md` item 5 (iii)).
- Newcomers, assertions unchanged, mutant `no-history-plan` (given an engaged line in the second
  round): `a_newcomer_reads_a_short_history_once_each_in_order` green fz1, fz14; its arm first hung
  in the act's paging wait (fz1, no verdict; the wait now ends on the page sentence), then red fz8:
  "PRODUCT: a member trusted before every post must read all 257 of them on explicit demand
  (V210-45), but read 0". `posts_sealed_before_trust_stay_unreadable_and_everything_after_is_read`
  green fz7; arm red fz13 with its engaged line: "PRODUCT: arm B: bob must read all 950 posts alice
  made after trusting him, 1101-2050, however the generations fall; he read []" (fz7's red did not
  count: the engaged line was lost with its directories).
- Acts restaged because they used `--history full` (`FwdProveKeys-item6.md`): green fz2 (local
  nodes' trust), fz3 (unread badge), fz4 (readmission and queued debt), fz6 (restored-checkpoint
  extent). `retained_rows_render_once_their_key_and_consent_arrive` ended in two findings, neither
  this change's rule. (1) Its own test hold blocked admission: the incoming-consent hold, which this
  change's restaging armed before Bob joined, waited inside the room's one admission, so with the
  consent in Bob's first head nothing after it could be admitted (a hang in fs7 r1; lost the race in
  5 of 7 runs). The hold now keeps the held consent out of the ready set instead (test-knobs code in
  `history_stream/pull.rs`, commit `420cd0e87`); then green 4 of 4 (fs17 r9 to r12), and 7 times in
  all without a red at the newer-equal-grant assertion (`FwdProve5.md`). None of the four runs with
  the corrected hold had the consent arrive in Bob's first head, the order that hung: that the
  corrected hold handles it rests on reading the code, not on a run (open item). (2) fz11's red at that
  assertion ("you trust it; your node has not received its trust for you, so cannot tell whether
  it trusts you" where "you trust each other" was expected) is a momentary one-way reading: the
  doctor reads the published node view, which keeps the room's last good detail while a governance
  turn has retired the fold and publishes only at the turn's end. In fs17 r11 the first read said
  one-way while both held the same rows, and the next read passed. The same path on main; named
  there, not fixed (`FwdProve6.md` item 3; how long it lasts is read from code, not measured).
- **Two computers on different versions**: a new act,
  `a_computer_on_an_older_vox_exchanges_nothing_until_it_updates` (`nodes_of_one_daemon_proof.rs`),
  stages bob and dave as an older Vox with a test-knobs switch (`VOX_TEST_FWD_OLDER_PEER`: this
  build speaking preamble version 2), not with a real v0.4.30 binary. For 30 s nothing passes either
  way between the old and the new computers; alice's `vox status` names bob with the other-version
  line and bob's names alice; after bob and dave update, bob reads both of alice's posts and alice
  reads bob's, alice's row of bob no longer says it, and dave, whose trust alice withdrew meanwhile,
  reads neither. Green fz10, fh1, fw1 (on the reviewed fixes: "last failure: that computer runs
  another Vox version; …" on both sides while mixed, the line gone after the update). Mutant
  `preamble-any`, red fz10, fh1, fw1: "PRODUCT: bob, on an older Vox, read MIXED 1 while the room was
  mixed (R10: a mixed room exchanges nothing)"; fz10's engaged line was not kept, and fh1 and fw1
  are the counted reds, with the engaged line in the red itself. That a later unrelated failure
  is not called "another Vox version" (`sec-code-5.md` finding 2) is not staged and rests on review.
  *(Amended 2026-11-28, amendment 2: "dave … reads neither" is no longer asserted. MIXED 1 is
  sealed under the generation dave was handed directly while trusted, and FO-5 lets him open it
  with the key he kept; the act now asserts that he never reads AFTER-UNTRUST, written after the
  withdrawal (found-reds 158; Amendment 2 (f)).)*
- **The idle-computers journey** (`two_paired_computers_that_are_idle_exchange_nothing`): its arm that
  gave an older-Vox peer its key in the long-lived session is deleted by FO-10, with the rekey-writer
  and stale-authority phases staged through that session (ADR-038 FX-28 is marked) and the test
  switches only they used (`FwdProve3Keys.md` item 3). Its first step,
  `superseded_governance_resumes`, was intermittently red (fz2, fz12; then 2 of 10 in fp2 and 2 of
  10 in fp3, "APPARATUS: source/effect/native work did not drain"). The cause was a product fault
  present on main too, not the suspected eligibility check: an idle node never became idle ((b),
  "Also in this change", item 1); with the fix, 10 of 10 green (fp4). The stale-post stage was red
  because it asserted a refusal the product no longer makes (a post racing a trust revision is kept
  since `465f2345e`; red on main too); it is restaged to hold the post while the moved policy is
  held and assert it is neither published nor refused then, and published once, under the new
  policy, after (`FwdProve4.md` item 4). The full journey then met the held-create fault ((b), item
  2); with both fixes it is green (fp5, "finished in 408.79s"), and the stage's arm
  `VOX_MUTANT_FX28=stale-post-authority` red on its own assertion with its engaged line (fp5 pm).
- The Mac app's `testRoomMembershipRemovalAndReadmission` keeps its assertion (its twin was locked,
  never left); only its words change; not built or run (`FwdProve2Keys.md` item 4).
- **The trust and consent proofs after the re-trust fix** (`FwdProve5.md`, `FwdProve6.md`): green
  `a_retrust_does_not_inherit_a_withdrawn_key` and `a_retrust_through_the_log_does_not_inherit_a_withdrawn_key_either`
  (fs9: "after-retrust read = true; while-untrusted read (a leak) = false"),
  `posts_sealed_before_trust_stay_unreadable_and_everything_after_is_read` (fs10), the restored-backup
  act with `receiver-off` red and engaged (fs11), the short-history newcomer green (fs7) with its arm
  red and engaged in fs16 (fs7's arm run went red on another assertion, traced to the mutant itself,
  and did not count). `revocation_rotates_the_key_proof` was red (ft1: alice "sent dave, still
  trusted, no new key"): its stand-in peer predated the version rule and never made a version-3
  history exchange, so alice rightly sent it no direct key. The stand-in now makes the exchange a
  real node makes at connect (test change, `a8d41d7d6`); green (ft2), every claim unchanged.
- **What a connected member that has not exchanged history yet gets after a removal**
  (`FwdProve6.md`, "The product question"): its rotated key reaches it promptly, directly. Every
  connection makes the version-3 exchange by itself at connect (each pull loop sends its Have at
  once, and either end's exchange marks both), and owed keys are retried every actor tick and when a
  dial lands. There is no key-package fallback for a connected member without the exchange; the
  only standing wait is a connection whose exchanges are refused, a computer on another version (by
  design, said on its sync row). This rests on the code and on ft1 and ft2; it is not staged as an
  act of its own.
  *(Amended 2026-11-28, amendment 2: for a newcomer's first key there are two named windows: the
  key waits for the newcomer's fresh one-time prekey bundle (usually 0.3 to 2 s, bound 30 s), or it
  is refused before the newcomer has recorded the exchange and offered again after a 2 s backoff
  (Amendment 2 (b), "Two windows of a newcomer's first read").)*

**Leaving and coming back** (`FwdProveRejoin.md`; second round `FwdProve2Rejoin.md`; file
`a_room_can_be_left_and_ended_proof.rs` unless named):

- `a_member_that_left_joins_again_and_is_a_member_again`: alice does not read bob's B-BEFORE or
  B-AWAY and reads his posts after her return; bob and carol read all of hers; carol, online and
  unaware of the departure and return, rotates and writes C-AWAY, which alice must not read. Green
  fj4, fj5, fn5 (with FO-3 item 8). Mutant `direct-accepted`, fj6, red: "PRODUCT: alice read C-AWAY,
  written before her return, from a direct key of carol, who had not learnt that she left"; the
  switch printed no engaged line then. After one was added, ft3 ran it again: red on the same
  C-AWAY assertion, with the engaged line kept.
- `a_member_that_comes_back_reads_forward_from_each_return` (the variants): a package sealed before
  alice left does not open; a replayed return rotates no further; after a second return alice reads
  from bob's new chain, including a key that waited for a fresh one-time prekey (`sec-code-1.md`'s
  staging (ii)); carol offline for both absences rotates once; a removal racing a return leaves alice
  removed. Green fj6, fn3 ("test result: ok. 1 passed … finished in 225.26s"). Its first arm,
  `rebump`, did not bite (fj8) and is deleted; its arm is `package-unbound`, fn3 vrtm, red: "PRODUCT:
  alice read B-PKG, written before her first return (B-PKG through a package sealed before she
  left)".
- `a_node_that_left_rejoins_and_posts_at_once`: green fj5, fn5; mutant `audit-back` (the deleted
  audit put back), fj6, red: "PRODUCT: once-only first post immediately after rejoining was refused".
  The switch prints no engaged line, so this red does not count under (f)'s rule (open item).
- `a_returner_reads_while_own_history_is_unavailable` with W3 (`a_node_leaves_a_room_proof.rs`):
  carol does not read what bob wrote while her recovery was pending, reads alice's posts after her
  return; with bob, who admitted her, stopped, alice learns the admission through the board exchange
  and carol's post is accepted. Green fj7, fn6. Mutant `notice-not-offered`, fj7, red: "PRODUCT: with
  bob, who admitted her, stopped, carol never accepted a post: alice did not learn her admission
  through the board exchange and serve her prefix"; the switch prints no engaged line, so this red
  does not count under (f)'s rule (open item). The design's arm `drop-recovery-extent` did not
  bite (fj7) and is deleted. The case where no holder of the prefix is reachable (status
  fenced, post refused) is part of design-4 §3's row; the record shows the refusal sentence in the
  mutant run, not a separate base staging.
  *(Amended 2026-11-27, amendment 1:)* `notice-not-offered` no longer exists. It ran green with its
  engaged line (km8 nn, found-reds 152): the returner fetched the notice from the readmitted
  member's own board, the other half of the board exchange. Its replacement,
  `notice-not-exchanged`, removes admission notices from both halves (what is fetched from a board,
  `exchange_boards_live`, and what is offered to one, `offer_board_records`, `actor.rs`): green
  without it (kn1), red at the act's W3 assertion with its engaged line (kn2). Why the old arm bit
  in fj7 and not in km8 is not established (`release/keyloss/KeyDebt6.md`, last section).
- `an_admin_removes_one_member_and_the_creator_readmits_it_forward_only` and
  `a_queued_key_and_history_debt_cannot_cross_room_removal`, restaged: the never-removed full-history
  arm deleted by ruling 1's consequence, the debt staged as catch-up. Green fj5 (and fz4). The old arm
  `old-entitlement` stayed green on both (fj5) and is replaced by `readmission-backfill`, which undoes
  both the rotation's entitlement boundary and the readmission body cut: fn3 rdm red "PRODUCT [FX62
  readmission-history]: readmission backfilled a removal-period post", fn3 qdm red "PRODUCT [FX62
  history-debt]: a catch-up debt owed before the removal, or SEG_HISTORY, was paid to readmitted
  carol".

**The update** (design-4 §3's last row; §5.3 makes it a landing gate; `FwdProveUpdate.md`,
`FwdFix2.md`):

- The migration spike (`FwdBuild7.md`; scratch, not committed) used debug builds of main
  `a9b428ffa` as the earlier version, not the published v0.4.30, and is superseded by what follows.
- **The update journey**, `stores_of_the_previous_release_open_and_each_member_reads_from_its_trust_point`
  (`update_proof.rs`, optional: it needs `VOX_PROOF_PREVIOUS_BINARY`), driven with the published
  v0.4.30 macOS arm64 binary (sha256 `f3bf4ec2…b463`, equal to the release's published sum) writing
  the stores and this build opening them. Shown: every room opens, the closed one included; every
  post already read is still shown in the same order; fran, trusted with full history while online
  and offline across a rotation, reads her post-trust catch-up; bob, offline from before his full
  grant, reads exactly `R-AFTER-TRUST-1` and `R-AFTER-ROTATION` and not `R-BEFORE-TRUST`; carol, only
  offline, reads `R-AFTER-ROTATION`; carol, who came back before the update, does not read
  `L-AFTER-ROTATION-UNTAKEN` (O2, one post) and her key went by a bound package; the closed room,
  opened by `vox room join`, shows both its posts and migrates then; a second start migrates nothing;
  a power loss at the first answer resumes, every row kept and a post accepted; and three computers
  updated one at a time (FO-10): silent between old and new, each side exchanging within itself,
  then all 12 posts on every member after the last update, no post lost. With `FwdFix2.md`'s case
  1b: erin, untrusted and trusted again with the old option while offline, reads `E-AFTER-RETRUST`,
  not `E-WHILE-UNTRUSTED`, and still shows what she read before. Green fu9 (before case 1b,
  "finished in 235.02s") and fv2 (with it, "finished in 234.80s"). Mutant `migrate-clamp`, red fu10
  and fv3 on the arm's assertion: "PRODUCT: fran, trusted with older history by the previous release
  and offline across a rotation, lost post-trust catch-up", the engaged line checked first.
  In the spikes beside it, power loss at six points of the first open (+0 s to +1 s) migrated each
  room exactly once and lost nothing.
- Not shown: a kill inside one room's migration batch (no point hit it); O3 (every generation was
  still held, so old packages' generations were re-delivered and read; a version-1 package itself is
  named by no output); the "no decision value" form of O1. The one-at-a-time run predates the
  other-version status line (FO-10 item 5): what an updated computer says of a real v0.4.30 one is
  read from code and shown only with the older-preamble switch above.

**The busy-room journey.** journey-36 (`simple-sync/pull/journey-36/`), on main `24f00beba` with the
branch's diff as of `2f83ebbda` applied (`source.txt`): "GREEN: RG-1 apparatus_smoke=false; every
member shown both ways; every post each member is owed (of 3703 acknowledged) shown on it after
authors stop", 16 directions observed, 16 shown (`paused/receipt.log`, `tables.txt`). One run.
journey-37 (`simple-sync/pull/journey-37/`), on main `18822e02a` with the branch's diff as of
`a8d41d7d6` applied (`source.txt`; the applied patch equals `git diff 18822e02a a8d41d7d6`): "GREEN:
RG-1 apparatus_smoke=false; every member shown both ways; every post each member is owed (of 3746
acknowledged) shown on it after authors stop", 16 directions observed, 16 shown, run 255.5 s
(`paused/receipt.log`, `tables.txt`). One run. Neither journey stages a leave and return, so
design-4 §3's ask that room and Drive rotation checkpoints complete after a return is not shown by
them.

**What rests on review, not runs**: canonical parsing and preservation of signed bytes (consent
field 1, keyring column 1, the version-1 package parse); strict versions of segments 31 and 33;
atomicity of `apply_presence_transition` in both fold batches, repair and the migration; removal
precedence; every consumer of the membership counter; removal of every obsolete dispatch path;
every room-key builder calling `require_key_target` and returner routing (design-4 §3); out-of-order
corrections of a return (`D10 → R21 → late R11 → late D20`, `… late R15 → late D12`, R41 before D30),
which no act can stage because an author's feed is admitted in order (`FwdProve2Rejoin.md` item 5
(i)); the one-hour prekey case (above); that a later unrelated failure after an other-version
refusal keeps its own words; that a removed peer cannot write the other-version line; a kill inside
the migration batch; what a real v0.4.30 computer's peer is told after the status-line change. The
reviewers add: "Real-binary ordering/restart acts remain necessary to demonstrate the behavior
operationally" (`sec-code-3.md`). Of the landing gates (design-4 §5.3, `sec-code-1.md`), W3 with the
admitting member stopped has run green, and so has opening stores the published v0.4.30 wrote, a
closed room included; stores written by earlier builds of this release line, and copies of the
decider's own stores (design-4 §4: "the update journey shows it"), were not opened by any run.

## (g) Reviews, in order

All read source and ran nothing.

1. `ruling-1.md` on `design.md`: **ACCEPT WITH CONDITIONS**, seven P1 findings and one P2, nine
   mandatory conditions ("Approve the simplification, not the draft unchanged").
2. `ruling-2.md` on `design-2.md`: **ACCEPT WITH REMAINING CONDITIONS**, seven ("is not ready to
   build unchanged").
3. `ruling-3.md` on `design-3.md`: **ACCEPT WITH CONDITIONS**, five P1 and one P2, and O1 to O3 put
   to the decider (ruling 4).
4. `ruling-4.md` on `design-4.md` before section 5 (fix-only): two defects, conditions 3 and 5 "not
   fully met"; its two corrections became design-4 §5.1 (the return trigger) and §5.2 (do not clamp
   an established forward-only entitlement because `history_plan` is `None`).
5. `sec-code-1.md`, commits 1 to 6 at `99d56ec7a`: **REJECT**, three P1: a package that must wait
   spent its one-time prekey first; a correction overwrote a handled return; a deferred delivery to a
   returner was never retried. Fixed in `b1503639c` (`FwdFix1.md`).
6. `sec-code-2.md`, fix-only at `b1503639c`: **REJECT**, finding 2 remains P1 (`D10 → R21 → late R15
   → late D12` took a second cut); findings 1 and 3 closed. Fixed in `e07daf060` (FO-3 item 3).
7. `sec-code-3.md`, fix-only at `e07daf060`: **ACCEPT**, "original finding 2 is closed".
8. `sec-code-4.md`, commit 7 and the merges at `553a7d0c5`: **REJECT**, three P2 wording defects;
   "No P0/P1 security or data-loss regression established". Its fix-only round on `6000f5266`:
   **ACCEPT**, "All three P2 findings are closed".
9. `sec-code-5.md`, fix-only on `6000f5266..89f3d0190` (the purge fix, the re-trust floor, the
   version refusal and its status line, the switch deletions, the merges): **REJECT**, three P2, "no
   P0/P1 blocker established": a removed member could write the other-version line for its former
   room; the mismatch mark was never retired after a successful round; the startup error blamed a
   policy change. Its dispositions: "Entitlement floor: no disclosure regression established";
   "Purge cancellation: cancels the departing instance's waits before any rejoin begins". Fixed in
   `8213be787` (`FwdProve3Keys.md`, "Review fixes"). Its fix-only round: **ACCEPT**, "forward-only
   scope through `751cbf21d`. P2/1 closed: removed members cannot update the diagnostic. P2/2
   closed: successful v3 rounds retire mismatch evidence. P2/3 closed: busy wording is accurate";
   "unrelated imported-main changes were not re-reviewed".

10. `sec-code-6.md`, the two product fixes of (b) "Also in this change" at `2c97d1b0d` (commit
    `53cdf0537`), reviewer SecFwd9: **REJECT**, one P2, "no P0/P1 blocker established": a resumed
    create filtered its own reservation out after the name search, so another room holding the name
    could be hidden. Of the idle-node fix: "Key-package scheduling — no lost-wake regression found".
    Fixed in `2edfea869`. Its fix-only round: **ACCEPT**, "`53cdf0537` + `2edfea869`; P2 closed. The
    search excludes self across all three sources; reservation removal remains terminal-only."

11. `sec-code-7.md`, final confirmation at `a8d41d7d6`, reviewer SecFwd9: **ACCEPT**, "product diff
    through `a8d41d7d6`; no new defect found in the scoped changes": the ended-during-leave path
    after the merge of main (`09a0d4f8e`); the moved consent test hold, "all `test-knobs`-gated"
    (`420cd0e87`); and the merge's meeting points with main's fixes, "No conflicting interaction with
    forward-only key delivery was found". "Imported main changes were reviewed only at these
    integration boundaries."

So the product diff is accepted in review through `a8d41d7d6`. Main's own changes brought in by the
merges were reviewed only where they meet this change; the test change `a8d41d7d6` (the revocation
act's stand-in) is test code.

## (h) Built

**Built on branch `scratch/forward-only`; merged in pull request #1418** as one change, whole
(design-4 §2: "No prefix is a candidate for main"): merge commit
`18048bf5624624882dca9bdd0389407d37c065f9` on main, parents main `18822e02a` and the squashed
commit `1d6e98f19`, whose tree is that of `a8d41d7d6` (`git diff a8d41d7d6 18048bf56` is empty);
its checks passed, as the coordinating session reports. The branch head `a8d41d7d6`
carries main `18822e02a` through the merge `c0ca28e02` (after `2f83ebbda`). Its commits:
`df8c5bbb5` (design-4 commits 1 and 2: cutover; full grants gone; the migration), `888f8338c` (3
and 4: departure exclusion, return as readmission, bound packages), `d179e400b` (5 and 6: network
own-key release and the audit gone; deletion on), `a4ab26030` (7: donor gate and legacy sender gone;
words and manual), `b1503639c` and `e07daf060` (the code reviews' fixes), `c34dbcc82`, `6c2bb14c9`
and `e3456696c` (proofs, mutant switches and the purge fix), `6000f5266` (`sec-code-4.md`'s
sentences), `555d56fab` (the update journey), `f000e05c2` (the re-trust floor), `2b9392425` (key
proofs of the second and third rounds; the version refusal coded and named in status; test switches
deleted), `d82572748` (two lints), `8213be787` (`sec-code-5.md`'s fixes), `53cdf0537` and
`2edfea869` (the idle node and the held create; the stale-post stage restaged), `09a0d4f8e` (after
merging main), `420cd0e87` (the consent test hold) and `a8d41d7d6` (the revocation act's stand-in),
with their merges. The builders and provers report `cargo check -p vox-core --features test-knobs`,
`cargo check --workspace` and `cargo check --workspace --tests --features test-knobs` clean at their
checkpoints (`FwdBuild1.md` did not run the `--tests` check again after its last edit; `FwdProve6.md`
ran the workspace tests check and the optional-proofs check clean after its last edits), and a
clippy run with `-D warnings` clean except two lints allowed there and fixed in `d82572748`
(`FwdProve3Keys.md`); lint on `a8d41d7d6` is clean, as the coordinating session reports; no build or
check was run for this record. design-4 §2 asked for seven commits
that each compile; the branch carries them as four product commits, fixes and merges. The code pull
request changes the manual, the release plan, PRD-001 R12 and the mutant scripts, and no decision
record; this record lands as its own documentation pull request.

## What this ADR amends

| ADR | Place | Change |
|---|---|---|
| ADR-006 | S-18 | No `full`; a grant releases from the trust point (FO-7, FO-5) |
| ADR-006 | S-19 | Deletion runs and stays (FO-1); no full-grant gate; departed and removed members pin no history floor (FO-6) |
| ADR-007 | G-16 | A grant always records forward only; value 1 still parses (FO-9 item 6) |
| ADR-007 | G-30, history limitation | Its `full` sentence and "Identities never removed keep S-18/RL-5 unchanged" are overtaken; a return is applied like a readmission (FO-3) |
| ADR-007 | G-32, the never-removed rejoiner control | Withdrawn by ruling 1's consequence; a return reads forward (FO-3, FO-7) |
| ADR-023 | Context R12, R14 | R12's choice is removed; R14 runs (FO-1) |
| ADR-023 | RL-4.1, RL-4.4 | Packages are version 2; a returner's are bound to its return; consent delivers from the stable floor; a re-trusted member from its re-trust mark (FO-4, FO-5) |
| ADR-023 | RL-4.8 | No full-grant clause (FO-1, FO-6) |
| ADR-023 | Decision 5 | RL-5.1, RL-5.2 and RL-5.4 withdrawn; RL-5.3 kept (FO-7) |
| ADR-023 | RL-8.1b | Exclusion by latest Presence; a return is applied like a readmission (FO-2, FO-3) |
| ADR-023 | RL-8.5 | No own-generation recovery or key redelivery over the network; no reads before the return (FO-7, (c)) |
| ADR-023 | RL-8.8 | A returner awaiting recovery reads nothing new (FO-3, (c)) |
| ADR-023 | Proof 7, M23.4 | The renamed act; the full arm deleted ((f)) |
| ADR-030 | W-4; S-5's older-peer bullet; the older-peer consequence | No long-lived-session keys; an older computer is owed its key until it updates; the other-version line in status (FO-10) |
| ADR-038 | FX-28 | Its journey's older-peer staging is gone; the older-preamble act; the stale-post stage restaged ((f)) |
| ADR-038 | FX-32 | Holds for a restored node; a returner reads nothing before its return ((c)) |
| ADR-038 | FX-62 | Its proof's arm is `readmission-backfill`; the never-removed full arm is deleted ((f)) |
| ADR-054 | PL-2's amendment-3 summary; PL-20 item 5; PL-21 item 4; PL-23 item 6; PL-24 item 1; PL-25 item 5; PL-36 items 1 and 2 | No own-key release on the loop: no own-release section, news or record; its worker gone, other leases unchanged (FO-7) |
| ADR-054 | PL-27 item 5 | The page sentence (FO-11) |
| ADR-046 (superseded) | SY-11 (c) | No own-original release (FO-7) |
| ADR-048 (superseded) | TC-3's own-original exemption; TC-8's release line; TC-9 acts 2b and 5 | Overtaken (FO-7) |
| ADR-049 (superseded) | LE-9 | For keys, a rejoin is a return applied like a readmission (FO-3, FO-4) |

## Open items

What was open when this record was first updated, and how each ended ((f)):

1. **The idle-computers journey's first step sometimes never settled.** A product fault on main
   too: an idle node never became idle ((b), "Also in this change", item 1). Fixed; 10 of 10 green
   (fp4); the full journey green (fp5).
2. **The retained-rows act.** Its own test hold blocked admission; the hold was corrected and the
   act is green 4 of 4 (fs17), though none of those runs had the consent arrive first (proof gap 2
   below). The one-way trust reading of fz11 is a momentary lag of the published view on main,
   named and not fixed.
3. **The trust and consent proofs after the re-trust fix**: green (fs9, fs10, fs11, fs16). The
   revocation act was red because its stand-in peer predated the version rule; the stand-in now
   exchanges history, and the act is green (ft2).
4. **The idle-computers journey's stale-post stage**: restaged for a kept post; the journey green and
   the stage's arm red (fp5).

journey-37, the busy-room journey on `a8d41d7d6`, was running then; it is GREEN ((f)).

Proof gaps that stay open:

1. **Two arms without an engaged line.** `audit-back` (fj6) and `notice-not-offered` (fj7) went red
   on their intended assertions, but neither switch prints an engaged line
   (`require_own_recovery_complete`, `channel/own_history.rs`; `offer_board_records`, `actor.rs`), so
   no red of either counts under (f)'s rule; a red with a kept engaged line is not shown.
   *(Amendment 1:)* `audit-back` now prints its engaged line and is red on its own assertion with
   it (km1 ab: "once-only first post immediately after rejoining was refused"; the line 16 times in
   alice's daemon log). `notice-not-offered` printed its engaged line but ran green (km8 nn,
   found-reds 152); it is replaced by `notice-not-exchanged`, red at the act's W3 assertion with
   158 engaged lines (kn2; see the mark under (f)). Both arms now count.
2. **The consent-first order of the retained-rows act.** The four runs with the corrected hold were
   green, but none had the consent arrive in Bob's first head, the order that hung before; that the
   corrected hold handles it rests on reading the code, not on a run (`FwdProve5.md`, "Not run";
   `FwdProve6.md`: the act was not run again).

Not shown by any run, resting on review ((f)): a kill inside one room's migration batch; O3 and the
"no decision value" form of O1 at the update; out-of-order corrections of a return; the one-hour
prekey case (not stageable without a new hold, `FwdProve4.md` item 5); a later unrelated failure
after an other-version refusal; what a real v0.4.30 computer's peer says after the status-line
change; a connected member without the history exchange, as an act of its own; room and Drive
rotation checkpoints completing after a return in a busy room; stores written by earlier builds of
this line, and the decider's own stores. The Mac app proof has not been built or run. The `fj3`
stall (a room left at once after a restart, then joined again) was reproduced in its cause only;
FO-3 item 8 is the fix, and its stall was not seen again. The momentary one-way trust reading is
main's and is named, not fixed. Release notes: the sentences in (c); the release must not claim a
loss beyond O1 to O3.
*(Amendment 1:)* `vox room read --history resume` after an interruption has no proof in this
release: #1422 re-stages only the first stale step of the act that carries it,
`interrupted_history_and_private_packages_recover`; its further repairs (found-reds 145) follow as
their own pull request. This is to be named in the release notes.
*(Amendment 2, 2026-11-28:)* The further repairs of found-reds 145 did not follow as their own
pull request: they are in pull request #1424, with the other fixes of the sixth proof sweep. The
resume step is removed there by the coordinating session's ruling, which the owner accepted on
2026-11-27 (Amendment 2 (f)); `vox room read --history resume` after an interruption still has
no proof in this release and is to be named in the release notes.

## Amendment 1 (2026-11-27): the key ledger is the set of generations each member has not acknowledged

*(Added 2026-11-27, amendment 1. The change was accepted in security review and is merged in pull
request #1422 (branch `fix/key-ledger`, one squashed commit `70bd29186` on main `73d373235`),
merge commit `eda5ab5e4`.)* This section states
FO-12, the rule that replaces the author's key-debt ledger of FO-5, FO-6 and FO-9 step 3, and what
it changes in this record. Each amended place is marked where it stands, and the text it amends
stays beside the mark. Sources, in the release's evidence archive `/opt/vox-evidence/v0431/`:
`exec/found-reds.md` entries 147 to 153; the decider's words in `exec/deviations.md`, "Words of the
owner on 2026-11-27 (in conversation)"; under `release/keyloss/`: `audit-1.md` (the audit of the
ledger), `ruling-ledger.md` (the ruling, with the coordinating session's decision and its correction
at the end), `ruling-returner.md` (the returner's acknowledgement, with the coordinating session's
adoption), `sec-1.md` (the security review, all its rounds), the builders' records `KeyDebt1.md` to
`KeyDebt6.md`, `ConsentPass.md`, `CAwayRead.md` and the pull request draft `key-pr-body.md`; and the
acceptance queue in `simple-sync/review/STATE.md`. Code is cited by file and function at main
`eda5ab5e4`, under `crates/vox-core/src/node/` unless another root is given.

### (a) What was found

1. **An author could delete an old key generation an offline member never received**
   (`exec/found-reds.md` entry 147). On main since #1418, not in any published version: the first
   run of the returning-reader act (`a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back`)
   on a main with #1418, a reader 8,000 entries behind whose daemon was stopped (it never left),
   with the author rotating its key every 1,000 posts. Run mr1 (main `18048bf56` with another fault's
   fix): "stopped at 7000 of the 8000 … missing: [(5000, 5999)]"; run mr3: posts 2000 to 2999
   missing. Each time exactly one of the author's chains, 1,000 of 8,000 posts, unreadable for good:
   the reader holds every entry, neither side reports pending key work, the author holds only its
   live key, and restarting both changes nothing. A member that was only offline lost data, against
   (e) item 3's "a member that was only offline loses nothing" and the design's R6.
2. **Cause 1, a settlement that cleared more than it carried** (`audit-1.md`, P1; found-reds 147,
   "cause 1 confirmed"). A history delivery selected a finite batch of generations; generations
   retired while it was on its way stayed owed through the same history row; the older delivery's
   completion then removed the member's whole row (`channel/pending_text/consent_delivery.rs`),
   and with no row the prune kept only the live origin. In mr1, generation 5 was never delivered.
   A first fix (settle only the interval carried, under a debt revision) did not end the loss: mr3
   reproduced it on that fix.
3. **Cause 2, a rotation that owed the retiring generation to nobody** (`KeyDebt1.md` §1; found-reds
   147, "cause 2 confirmed"; traced in run kd1, `rotation-prepare retired=1 owed=[] … readers=[]`).
   Every rotation appends the author's own Presence, which resets its consent facts until it
   re-grants; a second rotation before the re-grant skipped every member as "not a reader"
   (`channel/pending_text.rs`, the scheduled rotation; the same filter in `rotate_sender`,
   `pending_text/consent.rs` and `pending_recovery.rs`). The retired generation was owed to nobody,
   the prune deleted its origin, and the later re-grant re-owed from the entitlement floor, but the
   selection skipped the missing origin and the settlement closed the debt. In mr3, generation 2.
4. **The audit's conclusion** (`audit-1.md`, "Required prune invariant"): "every non-excluded,
   entitled member's undelivered retired generation must remain covered by durable history debt
   until a matching, non-invalidated delivery proves it was carried. `delivered = max generation` is
   not proof of intervening coverage." Neither store in the runs retains the lost generations; no
   fix reconstructs them.
5. **The decider** (`exec/deviations.md`, "Words of the owner on 2026-11-27 (in conversation): the
   lost key generation is fixed in v0.4.31"), told of the loss, its two causes and the redesign:
   "lol", then "**get it fixed please**". The release waits for this fix.

### (b) The rule as built

- **FO-12. An author keeps a key generation until every entitled member has acknowledged it over a
  direct delivery.** *(Added 2026-11-27, amendment 1; `ruling-ledger.md` as decided and corrected by
  the coordinating session, `ruling-returner.md` as adopted; for the decider's words in (a) item 5.)*
  It replaces the ledger of FO-5 ("the consent-delivery ledger is unchanged"), FO-6's history
  floors and FO-9 step 3's history and delivered rows.
  1. **The ledger is a set per member.** For each entitled member the author holds the set of its
     generations, the live one included, that the member has not acknowledged. In ordinary
     selection a member with no row owes the live generation only; when a room is opened, an
     entitled member with no stored row is read like a version-1 row below, owing every retained
     generation its entitlement allows through the live one (`open_with_sek_owned`, `channel.rs`).
     It is stored in `SEG_HISTORY` as version 2, one row per member,
     generations ascending, with the posted marks of item 6 (`outstanding_bytes`,
     `parse_outstanding`, `OUTSTANDING_VERSION`, `channel.rs`). The `delivered` segment is neither
     read nor written; a stored one is left in place. A version-1 row, as main writes it, is decoded
     strictly (its whole structure, bounds and lengths, then `finish()`; anything malformed refuses
     the room unchanged) and then read conservatively at open: every retained generation the
     member's entitlement allows, from the entitlement to the live one, is outstanding.
  2. **Every event that creates debt adds to the set.** Every rotation, of all five kinds (posting,
     scheduled or bound to the message count; explicit; trust withdrawal; removal or return; own
     recovery, with its settlement and catch-up), adds the generation it actually mints to the set of
     every entitled member that is not excluded, whatever that member's grant reads at that moment,
     and the retiring generation stays in each set (`rotation_debt`, which takes the minted
     generation as an argument, `channel.rs`; every native commit mints that generation). That ends
     cause 2, and own recovery that jumps its generation owes the generation it mints (`sec-1.md`
     finding 1). Consent issuance adds what the entitlement allows. A `NotTrusted` refusal, a fresh
     reciprocal key and a session reset add the entitled generations and the live one, and renew the
     member's debt revision even when the set does not change (`owe_keys`,
     `entitled_generations_of`, `channel.rs`; `owed_again`, `owed_anew`, `Ledger`,
     `channel/pending_package.rs`). No debt is created for a member without a durable entitlement
     (`sec-1.md` finding 2).
  3. **Boundaries are not receipts.** A removal, a return and a trust withdrawal rewrite the set
     (remove it; a return's or readmission's rotation adds what the new entitlement allows), never
     counting as received (`channel/pending_text/consent.rs`).
  4. **Only a direct answer settles, and exactly one generation.** An authenticated direct answer
     that the member took generation `g` (`KEY_TAKEN`; an authenticated tombstoned or covered answer
     counts the same), selected under the member's debt revision `r`, removes exactly `g` from that
     set, and only while `r` is still current; a revision renewed while the save ran keeps `g`
     (`begin_owned_pairwise_receipt`, `actor/consent_release.rs`;
     `prepare_pending_consent_delivery`, `channel/pending_text/consent_delivery.rs`). The revision
     is kept in memory only: no delivery outlives the process, so nothing that survives a restart
     settles a debt. A refusal, a timeout, a cancelled or lost write and a publication settle
     nothing. That ends cause 1.
  5. **A package in the log settles nothing.** It only makes a key available to a member that is
     not reachable; the generation stays in the member's set, and the next direct delivery carries
     it and settles it (`advance_owned_log_keys`, `actor/consent_release.rs`).
  6. **A package is posted once per member and release while its generation is outstanding.** Its
     mark is a hash of the member's current
     return and the exact release's `skdm_ref` (`posted_release`, `channel.rs`; `skdm_ref` is the
     hash of the whole signed SKDM, so the mark names generation, release iteration and return),
     kept in the member's ledger row and written in the same batch as the package's append
     (`package_posted`, `note_package_posted`, `channel.rs`; Session packages,
     `channel/pending_session.rs`; consent packages, `PendingConsent::save`,
     `channel/pending_text/consent.rs`, which writes the entitlement, the debt and the mark in the
     package's own batch). Both routes check the durable mark before a bundle is picked
     (`advance_owned_log_keys`; `frame_owned_consent`, `actor/consent_release/outbound.rs`), so a
     restart posts nothing again (`sec-1.md`, round on `31deeee88`, both gaps closed). The mark
     lives only as long as its generation is in the member's set: a mark is stored only beside a
     generation still in its row (`outstanding_bytes`), and opening a room drops any other
     (`open_with_sek_owned`). A settlement, a boundary or an eviction that removes the generation
     removes its stored mark with it (`channel/pending_text/consent_delivery.rs`). If that debt is
     later renewed and the node has restarted in between, a package for it can be posted again
     without any negative answer. A fresh
     prekey bundle does not cause a repost: a member that opens a package spends a one-time prekey
     and publishes a fresh bundle, which the author cannot tell from a package that could not be
     opened (run kg2/lv1: the same key posted 16 times in a minute to a returner; found-reds 149;
     `ruling-ledger.md`, the coordinating session's correction). Besides that renewed debt, the
     one repost is item 9.6.
  7. **The prune keeps what any set holds.** The author deletes a retired origin only when no
     entitled, non-excluded member's set holds it, it is not the live one, and the hold for a trusted
     identity that has not joined (FO-6) does not keep it (`origins_needed`, `OriginsNeeded::keeps`,
     `channel.rs`; `retain_needed`, `crates/vox-core/src/group/history.rs`). A departed or removed
     member's set pins nothing.
  8. **The cap.** At 256 origins in a room and epoch, a rotation made only because of time waits
     (whoever needs the oldest origin). A rotation bound to the message count (1,000 posts) or any
     other rotation (explicit, withdrawal, removal or return, own recovery) evicts the oldest origin;
     the evicted generation leaves every set, and a daemon line names the members whose sets held
     it (`origin_cap_holds`, `RotationDebt::say_lost`, `channel.rs`; `eviction_victim`,
     `group/history.rs`; `sec-1.md` finding 4). The line also names trusted identities that have
     not joined, from the keyring as of the last prune tick; that copy is empty before the first
     tick after a room opens and can be a tick old, so the line can miss such an identity then
     (`KeyDebt3.md` §8; `sec-1.md`, fix-only round, finding 4: it affects only who is named).
  9. **A returner acknowledges through a probe** (`ruling-returner.md`, adopted with its six
     conditions as an explicit exception to FO-4 item 1; `KeyDebt5.md` §2). Condition 6's "not
     eviction of owed keys" does not hold as written: the review found it met under the cap
     ruling, by which a message-bound or mandatory rotation can evict the oldest origin with a
     named loss line (item 8; `sec-1.md`, round on `31deeee88`, B6).
     1. A sender that knows of the return (`key_returned`) offers the returner directly only
        releases it already committed, each in a package
        bound to the returner's current return: the rekey pass goes down the direct path only when
        every owed release is marked for the current return (`releases_posted`, `channel.rs`;
        `advance_owned_rekey_pass`, `actor/consent_release/rekeys.rs`), and
        `reserve_key_deliveries_waiting` (`actor.rs`) refuses a returner otherwise. The direct
        offer carries the key, so an altered returner can read it whatever its installer does;
        that is safe only because the same release was already published to it, and FO-4's
        "packages are the only route" no longer holds literally. A sender that has not yet
        applied the return still offers directly as before (`ruling-returner.md` condition 4); the
        returner accepts such an offer only as in item 9.3, installing nothing.
     2. The mark (item 6) binds room, epoch, recipient, generation, the release and the current
        return; the removal, removal-rotation and departure checks run ahead of it. After a restart
        the durable mark is the evidence; with none, the log route publishes first.
     3. The returner authenticates the offer, then answers it as taken, unchanged, only when it holds
        the exact tombstone or its existing receiver already covers the offered release (the coverage
        test, not the merge that extends coverage), installing nothing, queueing no backfill and
        owing nothing back (`package_install`, `Native::Install`, `channel/pending_package.rs`).
     4. The checks for own history behind and for departure or removal stay ahead of it; it is no new
        route for a node that does not know whether it left.
     5. Only that authenticated answer settles, through item 4; `NotAccepted`, a timeout and a
        publication settle nothing.
     6. A negative answer clears the mark: any authenticated `NotAccepted` from a returner for the
        exact release its current mark names, including the refusal it gives while its own history is
        behind and an answer that comes before it opened its package, clears the mark in memory, and
        the next pass posts one new package (`NetEvent::SkdmRefused`, `actor.rs`;
        `clear_package_posted`, `channel.rs`). At most once per release per unlock
        (`Node.packages_reposted`, cleared at lock), so a returner that keeps answering "not held"
        cannot fill the author's feed. The debt stays. A cleared mark stays on disk until the next
        package's append rewrites the row, so after a restart in between the mark is back and the
        probe is offered again.
     A returner that falsely answers "taken" gives up its own catch-up; one that falsely answers
     "not held" pins origins, as staying offline does, until it is withdrawn or removed or the cap
     evicts the oldest origin (item 8).
  - *Why*: (a). "Explicit sets fix the coverage model; they do not fix an unsound receipt"
    (`ruling-ledger.md`); the coordinating session took the simplest sound receipt, the existing
    direct answer, with no new message and no new stored record type.

**Also fixed in the same change** (not part of FO-12): three findings of this work (found-reds 148,
150, 151) and one found before it (found-reds 127).

- **A member that never left waited seconds for an author's rotated chain** (found-reds 148;
  `CAwayRead.md`, `ConsentPass.md`; commit `f538a54e6`). After an author rotated, the consent pass
  that hands the new key to a member tried the room's lock once and, when it was busy, ended with
  nothing on the wire until a later tick won the race: gaps of 0.1 s to over 60 s, and no node said
  why. The consent route and the rekey pass now wait for the room's lock
  (`reserve_key_deliveries_waiting`, `actor.rs`; its callers `frame_owned_consent` and
  `advance_owned_rekey_pass`); after it the member read the post 272, 272 and 266 ms after the
  author's post command returned (runs kl6). On main too.
- **A member that left and joined again on the same connection was not told about an author that
  stayed offline** (found-reds 150; `KeyDebt6.md`; commit `31deeee88`). A node keeps, per
  connection, what a peer's Have said it holds; nothing cleared that when the peer left, so the
  returner was never told that author's head, its own entries that cite that author stayed
  unadmitted, its own-history recovery never completed, and it never signed its return (red in 6 of
  10 runs of the variants act). A departed peer's rows are now forgotten, and rows told to its
  earlier instance are told again when it is a member again (`standing` and `tell`,
  `history_stream/pull.rs`). Nothing new is served. On main too, by reading.
- **Leaving a room right after opening it printed two notes about a locked store** (found-reds 151;
  `KeyDebt6.md`; commit `31deeee88`). The leave locks the room's key while its settlement or
  recovery is still running, and that stage's failure was reported with advice to re-authenticate.
  The two notes are now skipped when this node itself closed the room under the stage
  (`closed_under`, `actor/recovery_save.rs`; `key_wiped`, `channel.rs`); a locked identity or a
  lock under way still gives them. On main too.
- **The returning reader's newest post waited seconds for its key** (found-reds 127, "fix built";
  `release/owed/KeyLatency.md`). Two changes, reviewed with the fix (`sec-1.md`): a board record
  landing in a room where a key waits starts the delivery passes at once (`NetEvent::BoardGrew`,
  `actor.rs`); an inbound key that meets its room mid-save waits for the save, one per room and
  sender, instead of being refused with a back-off. The newest key was installed 4.8 s after the
  reader's return before (run kl1) and 0.43 s and 0.44 s after (kl3). The second change was not
  seen engaged in any run and rests on review.

### (c) What a person sees

- A member that was only offline reads everything it is owed once it is reached directly and has
  acknowledged each generation, unless it stayed away through more than 256 of an author's key
  changes (the cap, FO-12 item 8; the five returning-reader runs covered 8,000 missed posts, not
  the cap). Being reachable alone releases nothing.
- An author keeps more old keys: `vox status --json`'s `key_generations` stays above one until each
  entitled member has acknowledged each retired generation over a direct delivery.
- At the cap, the daemon says which member loses which generation (with the limit on trusted
  identities that have not joined in FO-12 item 8).
- A member that never left reads an author's posts after a rotation at once (found-reds 148).
- Leaving a room right after opening it prints no notes about a locked store (found-reds 151).

### (d) What is deliberately not built

- **No new receipt message and no new stored record type.** Ruling-ledger's conditions 5 and 6 (a
  durable, authenticated receipt for a key taken from a package) are met by leaving a published
  key outstanding and settling only direct answers; condition 7 (persisted provenance) falls away,
  since nothing that outlives the process settles a debt (`ruling-ledger.md`, the coordinating
  session's decision; `sec-1.md`: "Not applicable").
- **No repost on a fresh bundle**, for anyone ((b) item 6). The freshest-bundle memory built for
  `sec-1.md` finding 3 (`fa78f9d2a`) is removed with it.
- **No backpressure on message-bound or mandatory rotations at the cap**: the reviewer's text
  preferred backpressure; the coordinating session chose eviction with a named loss line.

### (e) What it costs

1. **Old keys stay until each entitled member acknowledged them.** An author keeps a retired origin
   until each entitled, non-excluded member has acknowledged that generation over a direct
   delivery; being reachable is not enough. A member that never acknowledges pins it until it
   leaves, is removed, or the cap evicts it.
2. **A member that already took a key from a package is sent it again** directly, and answers that
   it holds it: one duplicate send per generation and member after a reconnect.
3. **Named limit: a member reached only through others whose one package could not be opened**
   waits for a direct connection for that key; the author keeps the origin meanwhile.
4. **A member offline through more than 256 of an author's key changes** loses the oldest
   generations to message-bound or mandatory rotations, and is named in the daemon's line.
5. **A returner's negative answer costs one package per release per unlock**, and after a restart
   one more is possible ((b) item 9.6); a debt renewed after a restart can cost one more package
   to any member ((b) item 6).
6. **Storage**: one set per member instead of one floor; at most about `2048 × 256` generation ids
   per room (`ruling-ledger.md` condition 11).

### (f) Proof

Runs are under `simple-sync/pull/runs/`. The runs on the final tree (`6b7b8e489`, the tree of
#1422's squash `70bd29186`), as the coordinating session reports them (`simple-sync/review/STATE.md`;
`key-pr-body.md`): the busy-room journey jrnK2 green, 16 of 16 directions; the returning reader
8,000 behind (kp1 rr), leave and return (kp2 lb, lv), the author-origin act (kp3 ak),
`a_returner_reads_while_own_history_is_unavailable` (kp4 ro) green. An earlier journey run on this
change, jrnK1, gave no product verdict: its own check that posts were offered once a second failed
while other runs loaded the machine (`release/keyloss/jrnK1/paused/receipt.log`: "APPARATUS:
offered cadence was not one second"); jrnK2 was the run after it. The returner act's arm
`notice-not-exchanged` ran before the rebase, on `31deeee88` with the arm's changes
(`/opt/vox-worktrees/keydebt-fix`; `KeyDebt6.md`, last section): green without it (kn1), red at
the act's W3 assertion with 158 engaged lines (kn2). The acceptance queue (km1 to km9) ran earlier
on `/opt/vox-worktrees/keydebt-fix`, branch `scratch/key-land`, at `31deeee88`, the tree before the
review fixes of `18dd7e40a` and before its rebase onto #1421; the k5 runs on the builders' trees
named in `KeyDebt5.md`.

- **The returning reader 8,000 entries behind** (the act that found the loss): green five times
  (km2 r1 to r5, 330 to 389 s each).
- **The author-origin act** (`an_author_keeps_a_key_only_while_a_member_still_needs_it`), four
  stages: two rotations back to back while bob's grant reads false (cause 2); bob's keys held on
  their way across two rotations (cause 1); bob away with his keys posted as packages, which settle
  nothing; alice's own recovery jumping her generation with bob offline (`sec-1.md` finding 1).
  Green (km3, k5h, k5n). Arms red on their own assertions with their engaged lines (k5h):
  `rotation-readers` ("never read post p1 1, p1 2, p2 1 or p2 2"), `settle-whole` ("never read post
  p3 1, p3 2 or p4 1"), `departed-pins` ("alice still holds Some(3) generations … carol, who left,
  must pin nothing"). Stage 3 has no arm: its mutant would be "a package settles", which the
  redesign deletes. Stage 4 has no switch; a throwaway revert of the fix turned it red (kf4) and was
  reverted. In stage 3 alice held 2 generations in k5n and 3 in k5h: timing of whether bob answered
  the live key before he stopped, read from the kept logs; no key lost (`KeyDebt5.md` §8.1).
- **Leave and return**: `a_member_that_left_joins_again_and_is_a_member_again` green (km1 lb), arm
  `direct-accepted` red with its engaged line (k5g); the variants act green three times in a row
  (km1 lv1 to lv3; red in 6 of 10 runs before found-reds 150's fix), with a new stage: bob's
  `key_generations` returns to 1 once alice, back and online, has acknowledged through the probe; a
  throwaway that switched the probe off turned that stage red ("bob still keeps Some(2)
  generations", k5f); arm `package-unbound` red with its engaged line (k5i);
  `a_node_that_left_rejoins_and_posts_at_once` green (km1 l2), arm `audit-back` red on its own
  assertion with its engaged line (km1 ab).
- **Key deletion**: the act's package re-offer section re-staged for acknowledged sets (found-reds
  153; `KeyDebt5.md` §9: the author now owes only the generation bob never took, and bob's node is
  shown meeting that package again after deleting the generation); green (k5p), arm
  `floor-not-exact` red with its engaged line (k5q).
- Green on the queue tree, without arms run: the thirty-day act (km5), `revocation_rotates_the_key_proof`
  (km6), the restored-backup act (km7), `a_returner_reads_while_own_history_is_unavailable` (km8 ro),
  the update journey from the published v0.4.30 (km9). The returner act's arm is replaced: see the
  mark under ADR-055 (f).
- **Proofs changed** (`key-pr-body.md`): the author-origin act is new; the variants act has one new
  stage; the key-deletion section is re-staged; `interrupted_history_and_private_packages_recover`
  has its first stale step (a wait rule older than #1411) re-staged. Its further repairs
  (found-reds 145), with the deletion of its privacy section and of the test knob
  `VOX_TEST_SERVE_NONRECIPIENT_HISTORY_BODY_FILE`, are not in #1422: they follow as their own pull
  request, and on main at `eda5ab5e4` the section and the knob are still there. No run here shows
  `vox room read --history resume` after an interruption (Open items).
  *(Amended 2026-11-28, amendment 2: those repairs ride in pull request #1424, not one of their
  own. In it the privacy section and the knob are deleted, the act is renamed
  `a_returning_member_crosses_a_private_package_and_keeps_its_cursors`, and its expired-body
  refill steps are removed as well (Amendment 2 (f)).)*
- **What rests on review, not on a run** (`key-pr-body.md`): the two crash-window fixes of "posted
  once" (a crash between a package's commit and its grant's commit; an author restart after a
  brand-new member's first package); the 256-generation cap and the strict reading of a version-1
  row (no act reaches them); the rekey pass waiting for the room's lock as the consent route does
  (read, shown only through the acts above); an inbound key waiting through its room's save
  (found-reds 127; not seen engaged, `sec-1.md`); a renewed debt posted again after a restart
  ((b) item 6).

### (g) Reviews

All by the same reviewer (SecKeyDebt, `sec-1.md`), source review only.

1. At `f0ad8bed9` with the timing change `2a51bc4f8`: **REJECT**, "one P1 data-loss defect and four
   P2 defects": recovery's debt owed `old + 1` instead of the generation minted; debt created
   without a durable entitlement; only the latest bundle remembered; the cap gate missed the
   never-joined hold; a version-1 ledger accepted without decoding. Fixed in `fa78f9d2a`
   (`KeyDebt3.md`). Fix-only round: **ACCEPT** "for `f0ad8bed9` + `fa78f9d2a`, subject to the
   separate leave-and-return fix-only round": the five findings closed; the verdict did not clear
   the two leave-and-return failures reported apart from it. Finding 3's fix (the freshest-bundle
   memory) was then replaced by the post-once rule.
2. On `scratch/key-land` `3ed162c4b..31deeee88` (post once, the probe, the lock wait, the sync fix):
   **REJECT**, "two P2 contract gaps; no P0/P1 found": a consent package's durable mark was not
   checked after a restart, and a first grant's package wrote no mark. Its returner conditions: B1
   to B4 met, B5 met "with the coordinator's republication correction", B6 "met under the accepted
   cap ruling, not the original literal no-eviction wording"
   (FO-12 item 9). Fixed in `18dd7e40a` (`KeyDebt5.md` §8). Fix-only round: **ACCEPT** "for
   `31deeee88` + `18dd7e40a`. Both P2s are closed".

### (h) Built

Built on branch `scratch/key-land2` in `/opt/vox-worktrees/fjh-main`, head `6b7b8e489` on main
`73d373235`: `a7422ec9d` (the fix as accepted at `18dd7e40a`, with the key-latency change of
found-reds 127, reviewed with it), `db04c1d25` (a lint alias), `15f9eb967` (the key-deletion act
re-staged, with one `test-knobs` line in `channel/pending_package.rs`), `6b7b8e489` (the returner
act's arm `notice-not-exchanged`, `test-knobs` only, and the act's header). Lint on `db04c1d25` is
clean (`release/keyloss/lint1`, as `simple-sync/review/STATE.md` records). Landed as pull request
#1422 (`fix/key-ledger`): one squashed commit `70bd29186` on main `73d373235` with the tree of
`6b7b8e489`, merged as `eda5ab5e4`.

## Amendment 2 (2026-11-28): a returned member reads a generation minted after its return from its start, and a trust withdrawal always changes the author's key

*(Added 2026-11-28, amendment 2. Merged in pull request #1424 (branch `fix/sweep6`, one squashed
commit `08ec7b2aa` on main `695db44c4`), merge commit `516c08746a16fd9da141672c100a8e31f52e08fa`
on main, whose tree is that of `scratch/sweep6-land` at `8761dd46f`. This section was checked
for fidelity against the code and the records (`design/forward-only/adr-sweep6-check-1.md`) and
is filed as its own documentation pull request.)* This section states FO-13
and FO-14, puts in words one moment of the forward-only rule and two windows of a newcomer's
first read, records four smaller fixes, the owner's answers of 2026-11-28 and every proof change
that belongs to this record's rules, and marks the places of this record they make false.
Sources, in `/opt/vox-evidence/v0431/`: `exec/found-reds.md` entries 145, 154, 155, 158 to 162,
164a and 164b (every row of each number; several were corrected); the owner's words in
`exec/deviations.md`, "Answer of the owner on 2026-11-27 (by the question form): two parts of one
old proof removed by the coordinator's ruling are accepted" and the two sections "Answers of the
owner on 2026-11-28 (by the question form)"; under `release/regress6/`: `RejoinRead.md` (with
its sections "Successor (RejoinRead2)" and "Later step"), `R10Fix.md` (rounds 1 to 3),
`FirstKey.md`, `FirstRead.md` (with "Successor"), `KeyPrune.md`, `LateJoin.md`, `Transients.md`,
the security review `sec-regress6-1.md` (all its rounds) and the pull-request text `pr-body.md`;
`release/keyloss/KeyDebt5.md` §10; `release/owed/Trace145c.md` and `Trace145d.md`; and
`simple-sync/review/STATE.md` (passes 7 to 7d, jrnS2) with the pass logs in
`release/gate-sweep/pass7*/logs/`. Code is cited by file and function at main
`516c08746`, under `crates/vox-core/src/node/` unless another root is given. Run labels are
directories under `simple-sync/pull/runs/`. Nothing was built or run for this record.

### (a) What was found

1. **A member that had come back before could never open the first post of an author that had
   just come back itself** (found-reds 155, act 1). The act
   `a_rejoined_author_is_not_sent_its_old_session_steps`
   (`a_claude_session_is_mirrored_and_answered_from_either_side_proof.rs`), green in sweep pass 4,
   was red on main `695db44c4` in five runs of five (rr1, rr2, rr3 and rd2's two runs,
   `RejoinRead.md`): "author did not learn its reader's new membership". In rd2 the author,
   person, sealed its post at iteration 0 of the chain it minted at its own return 27 ms after its
   node said it was back; its key then went to claude-a, which had come back once long before, as
   "chain 3 iteration 1 entitled_from (3, 1)", so iteration 0, the post, never opens. The cause:
   `prepare_owned_consent_key` (`actor/consent_release.rs`), for a once-removed or returned target
   with no entitlement row in the author's room (person's room was rebuilt at its return),
   released `skdm_for_consent`, the live generation at its current position. Whether the release
   came before or after the post was a race: in rd1 (main with a diagnostic) and rb1 (main with
   #1422 reversed) it came first and that step passed. That #1422 made the late order likelier is
   not shown (`RejoinRead.md`: "[INFERENCE] a timing race, not established as #1422's").
2. **A trust withdrawal changed the author's key only when a grant had committed** (found-reds
   161; `R10Fix.md`, round 2; found by reading, no act reaches it).
   `prepare_pending_withdrawal` (`channel/pending_text/consent.rs`) rotated only when
   `has_consented` was true for the target, which holds only once the grant has committed. A first
   grant's save (`PendingConsent::save`, Issue) commits the key package first, with, since #1422,
   the entitlement, the debt row and the posted mark in its batch; then checks
   `require_trust_withdrawn`; then commits the grant. The package-first order predates #1422
   (`73d373235`). A `vox trust remove` landing between the two commits (the check then refuses
   the grant), or a crash after the package followed by the removal, left the member holding the
   live generation with no rotation, so the author's posts after the withdrawal were sealed under
   a key the member may hold. An unmodified client does not show them, because no grant is
   recorded (the render gate); the key is still the member's.
3. **A key delivery to a member that had just left closed the room for its recovery**
   (found-reds 155; `RejoinRead.md`, Successor §3). Behind act 1's first red was a second, at
   `:2719`, "the rejoined Session did not deliver its new step": not #1422's (red also with #1422
   reversed, rb1), and in the ledger's words "older than today's merges, not traced" before this
   work. `prepare_pending_session`
   (`channel/pending_session.rs`) refused a key package to a recipient that had left only at
   `package_return`, after the room's write was reserved; the maintenance save then failed with
   the write held and released it poisoned (`complete_pending_maintenance`,
   `actor/maintenance_save.rs`), so the room failed its save and closed for recovery. Every red
   with a daemon log has "room save did not complete … recovery did not complete its retained
   save" and the room reopening; no pass has it. That this is why the Session step never reached
   the reader is a correlation, six reds against four passes, not traced line by line (the
   builder's [INFERENCE]).
4. **A post written between a returner's `vox room join` answering and the author's node taking
   the return in is never read by the returner** (found-reds 155, act 2). The act
   `revoked_admin_stale_board_does_not_block_live_rejoin` (`a_room_can_be_left_and_ended_proof.rs`)
   posted at once after carol's join returned. In rs2 carol's node said it was back at
   06:13:05.136; alice sealed the post at chain 0 iteration 1 at .165; by .412 alice had applied
   carol's return and rotated to chain 1, the only generation she then releases to carol. Runs rb2
   (#1422 reversed) and rb3 (#1422 and #1421 reversed) were red the same way. The coordinating
   session ruled it this record's rule, not a product fault: the act was stale against #1418
   (`RejoinRead.md`, "Main's ruling on act 2").
5. **`vox status` said a member "is still owed" a key that was already written into the room**
   (found-reds 159; `KeyDebt5.md` §10). Three acts of `key_package_proof.rs` waited for the
   author's `key_delivery_pending` to go false through the log. Since #1422 a package settles
   nothing (FO-12 item 5), so while author and member are never online together it stays true:
   the acts were stale against #1422. The line read as "not sent yet" for a key that was in the
   room's log and that the member may already read with.
6. **Four acts expected the first key in the old form** (found-reds 154, attributed APPARATUS;
   `FirstKey.md`). Their test wire peers never made the version-3 history exchange that a direct
   key now waits for (FO-10 item 2), and took the first key as a bare SKDM in the pair's long-lived
   session, a sender #1418 removed (FO-7 item 4).
7. **The older-Vox act asserted more than this record's rule** (found-reds 158, attributed: not a
   security fault, a proof defect; `R10Fix.md`, round 1). It asserted that dave, whose trust alice
   withdrew while he ran an older Vox, must not read MIXED 1 once he updated. MIXED 1 is sealed
   under the generation dave was handed directly while trusted, before READY, and FO-5 lets him
   open it: "Messages and keys it already holds stay usable". No key reached dave after the
   withdrawal (in xa3 his updated daemon installs nothing); whether his one read already held
   MIXED 1 was timing (red in xa1; green in xa2 and xa3, where he read it within 60 s).
8. **A returned member could hold a Session's step without the Session** (found-reds 164a;
   `RejoinRead.md`, "Later step"). In sweep pass 7 on the integration tree, act 1 went red at a
   later step: "the rejoined Session did not deliver its new step … no Session in this room is
   named …", in the file run and 1 of 2 alone. Reproduced with traces (rx1 to rx4; red in 10 of
   17): in the moment between the author's node accepting the member's readmission (its board
   notice clears `has_left`) and its fold of the member's signed return Presence, the member was
   already a drive member (`drive_members`, `channel.rs`) while still key-departed. So the author
   re-sealed the Session's opening record for it in the old drive chain and built a release of
   that chain, which could not go (R2: `package_return`). At the fold the drive key rotated and
   only the new chain was released, while `refresh_one` (`channel/pending_session.rs`) took the
   old-chain record as already given, because the window's floor (the departure + 1) equals the
   return's position. The member held the step and never the record; none was re-sealed within
   60 s. The order of the two events was 0.5 to 3 s apart there. PRODUCT.
9. **A key a member had finished with was sometimes never deleted** (found-reds 164b;
   `KeyPrune.md`). The key-deletion act went red at stage 1 three times in about 12 runs (pass 7,
   pass 7b and kr1: "still holds its key 60 s later", or "holds Some(3)"). Caught with traces in
   kz2 (1 red in 4): every pass that decrypts saves the whole receiver map in its own batch, yet
   `SemanticProjection::install` (`channel/semantic_projection.rs`) set `chains_advanced` for any
   advance, written or not, and only a committed render backfill clears it
   (`channel/pending_governance.rs`); while it is set every prune tick returns without walking
   (`channel/pending_key_prune.rs`). When the last post under the new generation came live after
   the last backfill, nothing cleared it: in kz2, 30 admitted ticks in 60 s and no walk. Not load
   (60 ticks in 59.9 s) and no missing fact. That the other three reds had this cause is the
   builder's [INFERENCE]: they kept no daemon logs.
10. **A newcomer's first read could miss a post written right after its join** (found-reds 162,
    all rows; `FirstRead.md`). The renamed act of (f) reads the joiner's room once, right after
    its node stores the author's first post, and was red there in 2 of about 9 runs (klm on a
    side tree, lj1 on main): "bob read alice: None (None = never)". The coordinating session first
    read that as "never in 300 s" and corrected it: the 300 s bound applies only to the other
    direction, and "None = never" means that one read missed the post (`FirstRead.md` §1). The
    likely cause, from #1418: the author's first key pass at a join always fails the version-3
    gate (FO-10 item 2: no exchange recorded yet), and nothing runs it again when the exchange is
    recorded, so the key waits for an unrelated event or the 1 s tick; in six traced greens the
    joiner held the key 76 to 220 ms before the post (`FirstRead.md` §2). The two reds are read
    from their logs as the two windows of (b) ([INFERENCE], `FirstRead.md` §3).

### (b) The rules as built

- **FO-13. A generation the author minted after a returned member's return cut and its trust
  decision is released to that member from its origin.** *(Added 2026-11-28, amendment 2; the
  rule the coordinating session approved, found-reds 155; reviewed in `sec-regress6-1.md`.)*
  1. Where: `prepare_owned_consent_key` (`actor/consent_release.rs`), for a target with no
     entitlement row here that is once removed or returned. An entitlement row still wins, as FO-5
     says. When `ChannelState::live_generation_after_return` (`channel.rs`) answers true, the
     release is the live generation from iteration 0 (`release_generation`); otherwise it is
     `skdm_for_consent`, the live position, as before.
  2. The invariant, as the code states it: "a member that came back is never given a position of
     a generation minted before its return cut or its trust point; a generation minted after both
     is given whole."
  3. What decides "after": durable facts on the author's node, none taken from the target. They
     are the author's own return cut for the target's current return (`View::return_cut`,
     `channel/governance/view.rs`: the row the author's own fold of the target's signed return
     Presence wrote, FO-3 item 2, with the author's sender chain and next iteration in that
     batch); the author's sender cut for each validated removal of the target (`View::sender_cut`);
     the target's trust decision stamp; and the live generation's mint stamp (`my_generations`).
     The live generation is after the return when its chain id is above every such cut, and after
     the trust when its mint stamp is after the decision in the same counter (`Stamp::after`,
     `consent_order.rs`, false for stamps of two counters), as `history_plan` reads it. The target
     decides only whether and when its signed return exists; the cut falls where the author's
     sender stood when the author's fold learned of the return.
  4. On doubt the release stays at the live position: no return shown (so a once-removed target
     that has not returned), no return cut held, a removal with no sender cut, no trust decision,
     a missing mint stamp or one of another counter, or a live chain not above the cut. An error
     reading the governance facts refuses the release, and the key stays owed. If the live
     generation's origin is not retained, `release_generation` gives its current position, which
     is narrower (`RejoinRead.md`, Successor §2).
  5. The reviewer's qualification (`sec-regress6-1.md`): "IDs increase through ordinary rotations
     and recovery jumps …, but are not globally monotonic across join recreation or store
     rollback. Join recreation generates fresh chain/signing keys …; recovery likewise mints fresh
     keys above its recovered bounds …. Known own-history-behind state blocks this release
     selection." And: "the existing `trust_decision` loader converts its own read errors to
     `None`, also selecting that narrower fallback." The released position becomes the stored
     entitlement floor and its exact SKDM hash the package mark (FO-12 items 6 and 9), so, in the
     same review's words, "an earlier current-position mark cannot authorize its probe".
- **FO-14. A trust withdrawal changes the author's key whenever a key may have gone to the other
  identity.** *(Added 2026-11-28, amendment 2; found-reds 161; `R10Fix.md`, rounds 2 and 3;
  reviewed in `sec-regress6-1.md` and its fix-only round.)*
  1. The predicate (`prepare_pending_withdrawal`, `channel/pending_text/consent.rs`): the
     withdrawal rotates, and signs its revocation, when a grant to the target has committed, or
     the author holds an entitlement for it, or it is an admitted author of the room (`consented
     || self.entitled.contains_key(&target) || self.is_author(&target)`). A governance read that
     is still refreshing counts as rotate, as before.
  2. Why three parts. A committed grant covers keys handed over through it. The entitlement covers
     the moment of (a) item 2: the first grant's package batch writes it, so it is in memory after
     that batch (`finish_pending_consent` installs it even when the grant is refused) and on disk
     after a crash (`open_with_sek_owned` reads it) (`R10Fix.md`, round 2 (1)). Authorship covers
     stores from before this release.
  3. The legacy window, and how it is closed. A store written by v0.4.30, or by main before
     `eda5ab5e4`, may hold a committed package to the target with neither a grant nor an
     entitlement row: the older code wrote the entitlement only with the grant (`R10Fix.md`, round
     2 (2)). Consent issuance refuses a target that is not an author ("consent target is not an
     author", `channel/pending_text/consent.rs`; the actor checks the same in
     `prepare_owned_consent_key`), so every such package went to an admitted author, and the
     withdrawal now rotates for every recorded author, one that has left included. `authors` is
     this node's own admission state, persisted with the room and read back at open; nothing the
     target says sets it (`R10Fix.md`, round 3). No migration and no feed scan: the reviewer's
     first round named the residual window and this closure ("conservatively rotating whenever an
     admitted room author's trust is withdrawn would close it without a migration or feed scan,
     at extra rotation/cap cost"); its fix-only round: "The legacy window is closed". An identity
     that never was an author here still costs no rotation.
  4. Reach, by reading (`R10Fix.md`, round 2 (1)): the only way in is `Work::Withdraw`. `vox trust
     remove` writes a durable withdrawal lock in every stored room, so a room closed at the time
     meets it at its opening's Removals stage, which takes locked targets whether or not a grant
     committed; the lock clears only after the withdrawal commits. A legacy cache-only opening
     skips that stage and keeps the lock, which keeps refusing issuance. The rebuild of owed rows
     at room open (`open_with_sek_owned`) was not read for this fix (`R10Fix.md`, round 1,
     step 5).
  5. One more rotation after a crash. The reviewer's fix-only round: "'Once per withdrawal' needs
     qualification: normally once per room, but a crash after rotation and before lock clearance
     can cause another rotation on replay—even after ledger cleanup. This retains the existing
     cap-loss consequence." The builder names the same for a crash between the revocation's commit
     and its ledger cleanup (`R10Fix.md`, round 2 (3)).
  6. It rests on review. The window lies between two commits of one save, or at a crash, and no
     test hold sits there; and what a person would see there, the member not reading the posts
     after the withdrawal, the render gate already gives before and after the fix, so a stage
     would pass on main too (`R10Fix.md`, round 2 (4)).
- **The window before an author takes a return in.** *(Added 2026-11-28, amendment 2;
  found-reds 155, act 2.)* The builder's sentence, which this record lacked (`RejoinRead.md`,
  "Named limit, plain words"): "a post an author writes in the moment between a returner's `vox
  room join` answering and the author's node folding the returner's return statement is, for
  that author, written before the return; the returner never reads it." So a returner reads each
  author from the point that author's node applied its return on. In act 2 the returner's `vox
  room join` answered right after its node said it was back, when it signs its return ((c)); each
  author's node learns of the
  return only when its fold applies that Presence, after the entry's header is admitted
  (`channel/pending_received.rs`, the received-history Effect, scheduled from the history-effect
  cursor; `RejoinRead.md`, Successor §1). What already implies it: FO-3 item 1 (the return is
  applied, and its cut taken, in the batch where this node folds the return Presence); FO-3 item
  5 (from then on the node posts nothing and releases no room key until it rotates; a post is
  refused `KEYS_ROTATING` while `room_removal_rotation_needed`, `channel/pending_text.rs`); FO-4
  item 3 ("the sender binds to its fold's return"); FO-5 (a returned target without an
  entitlement is released only the live generation); and (e) item 10. None of them names the
  moment between the returner's completion and each author's fold. FO-13 does not reach it: the
  post is in the generation the fold's rotation retires, minted before the cut. Observed: the post
  sealed 29 ms (rs2), 20 ms (rb2) and 27 ms (rb3) after the returner's node said it was back, and
  in rs2 the author had folded the return and rotated by 276 ms after: in the measured runs the
  window was about 0.3 s, longer while the author's node is busy (`pr-body.md`, "Named, not
  fixed"; a busy node was not measured). The builder wrote "0.03 s to 0.3 s here", the ledger
  "0.03 to 0.25 s"; both count from the returner's completion to the post, not to the fold. No
  `vox` surface shows the fold: the roster counts the returner from the admitting node's witness
  before it, and `verified_through` is header admission (`RejoinRead.md`, Successor §1).
- **Two windows of a newcomer's first read.** *(Added 2026-11-28, amendment 2; found-reds 162,
  the coordinating session's ruling and decision of 2026-11-28; `FirstRead.md`, "Successor".)*
  A newcomer's first read can miss a post an author writes within about 2.5 s of its join, for a
  second or two, and up to 30 s when its fresh key material is late. The post is shown once the
  author's key lands; nothing is lost. The two windows, in the ledger's words:
  1. "the first key can wait for the joiner's fresh one-time prekey bundle because the join used
     its last one (ADR-030 P-3): a newcomer's first read misses what the author writes until that
     bundle reaches the author, usually 0.3 to 2 s, bound 30 s (then the key goes on the signed
     prekey)";
  2. "the author records the version-3 exchange when it authorizes the joiner's request, the
     joiner only at the end of its round: a key sent between the two is refused (0x23) and retried
     after a 2 s backoff" (the author at `history_stream/server.rs`, the joiner in
     `Connection::answered`, `history_stream/pull.rs`).

  Not fixed in v0.4.31: closing window 2 needs a new refusal code on the wire, ruled out this
  late; window 1 might be closed by ordering the joiner's bundle first, not verified. A written fix
  for the cause of (a) item 10 (the key passes run when this node's own version-3 request is first
  answered on a connection; `FirstRead-product.patch`, three files) is **not landed**: with it the
  check passed 8 of 8 whole runs (fh1, fw2 to fw8), but without it it had passed 6 of 6. With it,
  the time from join to the author's feed reaching size 4 on the joiner, taken as a stand-in for
  the key's arrival because the product logs have no line for it, was 123 to 769 ms; before it,
  the traced key receipt came 165 to 857 ms after the join (`FirstRead.md`, "Successor"). No run
  showed the fix's effect. The coordinating session's decision: "A change in the key paths whose effect no
  run shows is not landed". The owner's answer is in (e bis).

**Also fixed in the same change** (not new rules of this record):

- **A key package to a recipient that has left is refused before the room's write is reserved**
  (found-reds 155; (a) item 3). `prepare_pending_session` (`channel/pending_session.rs`) now
  refuses a departed recipient (`key_departed`) with the same error, "key recipient has left the
  room", beside the removed one, before the reservation; `package_return` still checks later.
  Nothing more is released; the refusal no longer fails the room. The reviewer: "The intervening
  package preparation performs no rotation or debt commit; the later `package_return` check
  remains" (`sec-regress6-1.md`, A2).
- **The status line for an unconfirmed key** (found-reds 159; `KeyDebt5.md` §10.1). Plain `vox
  status` said of a member "is still owed one or more of your sender keys here"; it now says "has
  not yet confirmed one or more of your sender keys here; a key it takes from the room counts once
  it confirms over a direct connection" (`render`, `crates/vox-tui/src/status_cli.rs`). The JSON
  field `key_delivery_pending` keeps its name and meaning. No proof asserted on the old words,
  and nothing else in the repository carried them (`KeyDebt5.md` §10.1).
- **A member whose return a node has not taken in is no drive member there** (found-reds 164a;
  (a) item 8). `ChannelState::drive_members` (`channel.rs`) also leaves out a member this node
  still counts as key-departed (`key_departed`: its latest authenticated Presence is its
  departure); one line. In the window nothing Session-related is marked, floored, re-sealed,
  served or released to it; at the fold the drive rotation marks it from the new generation's
  origin, as before, and the Drive write's refresh seals every unexpired Session record again in
  that generation, because no floor at its current membership start exists from before the fold
  (`RejoinRead.md`, "Later step"). Session steps the author sealed before its fold stay before the
  return for that author, as posts do. The reviewer: "Only narrows eligibility …; no earlier or
  broader release is introduced"; "No required rotation/revocation is skipped"
  (`sec-regress6-1.md`, fix-only on `56ed15255`). Named, not fixed: a room that already went
  through the window on an older build keeps the window's floor at the member's membership start,
  so its records there stay "permitted" by it and are not sealed again (`correct_floors` sweeps
  only starts placed too late); not exercised by any act ([INFERENCE] in the record), and "The
  stated limitation remains: stale floors produced by older builds are not repaired" (the review).
- **A pass that saved its keys no longer holds off the key prune** (found-reds 164b; (a) item 9).
  `SemanticProjection` records whether its pass queued the whole receiver map into its batch
  (`receivers_queued`, set in `queue_receivers_with`), and `install` sets `chains_advanced` only
  for advances that pass did not write. What the deletion rule deletes and when is unchanged; the
  prune's skip is kept for a pass that advances without writing (`KeyPrune.md`, "Fix"). The
  reviewer: "The flag still protects against a disk-based prune rewrite losing unsaved receiver
  advances"; "Deletion selection, eligibility and exact tombstones are unchanged"
  (`sec-regress6-1.md`, fix-only on `ffeb805d2`).

### (c) What a person sees

- A member that came back reads the post an author writes right after that author itself came
  back (act 1).
- After `vox trust remove`, each room where the other identity is or was an author changes the
  author's key, whether or not a grant to it had committed.
- A post written in the moment before an author's node took a member's return in stays unread by
  that member. The release notes are to say so (`pr-body.md`, "Named, not fixed": "A post an
  author writes in the moment before its node learns a member has returned is not readable by that
  member (about 0.3 s in the measured runs; longer on a busy node). This is the forward-only
  rule.").
- A newcomer's first read can miss a post written within about 2.5 s of its join, for a second or
  two, up to 30 s when its fresh key material is late; the release notes are to say so
  (`pr-body.md`, "Named, not fixed").
- After an author's node takes a returned member's return in, it seals the unexpired Session
  opening records again under the new drive generation, so the member can read those Sessions; in
  the moment before, it prepares nothing Session-related for that member. A room that met that
  moment on an older build keeps the stale state there: in the release notes' words, "that member
  still lacks that Session record there".
- A key a member has finished with is deleted within about 0.3 s of the last post being recorded
  as read (kx1), not held until an unrelated event.
- A member leaving while a key package for it is being prepared no longer makes the author's
  room close and recover.
- `vox status` says a member "has not yet confirmed" a key, in the words of (b).

### (d) What is deliberately not built

- **Nothing closes the window before an author takes a return in**: it is this record's rule,
  applied per author. The act that met it is re-staged to post once the author's node shows the
  return ((f)).
- **No test hold between a first grant's package and its grant**, so FO-14 has no act (FO-14
  item 6).
- **The fresh-session act is not re-expressed** ((f)): it could not be staged without forging a
  refusal.
- **The written fix for a newcomer's first key is not landed** ((b), "Two windows"): no run
  showed an effect. Window 2 would need a new refusal code on the wire.
- **Stale Session floors from older builds are not repaired** ((b), "Also fixed", item 3).

### (e) What it costs

1. **FO-13 gives a returned member its author's live generation from the start**, so posts sealed
   in it before the release are read. By the invariant that is nothing before the return; that a
   chain id above the cut was minted after it rests on review, with the reviewer's qualification in
   FO-13 item 5.
2. **FO-14 rotates also for an identity that is or was an author without a committed grant**,
   one that never opened a package or left long ago included: one more generation per room per
   withdrawal. It is owed to every other entitled member and pins origins until each acknowledges
   it (FO-12), and at the 256-origin cap a withdrawal's rotation is mandatory and can evict the
   oldest origin with its named loss line (FO-12 item 8; `R10Fix.md`, round 2 (3) and round 3). A
   crash at the places of FO-14 item 5 can cost one generation more.
3. **A returner loses what an author writes before that author's node takes its return in**: in
   the runs above the post came 20 to 29 ms after the returner was back, and the author had taken
   the return in by 276 ms in rs2; a busy node takes longer.
4. **Two promises have no proof in this release**: a member whose pairwise session with an author
   went wrong gets a fresh one, and `vox room read --history resume` after an interruption ((f)).
5. **A member whose trust is withdrawn can still read what the author wrote while it was
   trusted**, posts it had not yet received among them, and nothing written after (FO-5, FO-14):
   accepted by the owner on 2026-11-28 ((e bis)).
6. **A newcomer's first read can miss what is written in the first seconds after its join**
   ((b), "Two windows"): accepted by the owner, to be named, on 2026-11-28 ((e bis)).

### (e bis) The owner's answers of 2026-11-28

By the question form (`exec/deviations.md`, the two sections "Answers of the owner on 2026-11-28
(by the question form)"). Put to him: "(1) three more proof changes by the coordinator's ruling
(the expired-text refill steps removed from the renamed interrupted-history proof; one check
removed from the older-Vox proof; the proof "a member whose session went wrong is offered a fresh
one" deleted, its promise then without a proof); (2) a consequence of forward-only: a member you
stop trusting can still read what you wrote while you trusted it, including posts it had not yet
received, and nothing written after; (3) a newcomer's first read can miss a post written within
about 2.5 s of its join (a second or two; up to 30 s when its fresh key material is late); a fix
was written and not landed because no run showed an effect; closing it properly needs a new
message between nodes."

His answers: to (1), a question, "**what are all of these proofs... sounds like unit tests with a
new name**"; to (2), "**accept**" (`withdrawn_reads_earlier = accept`); to (3), "**name it; do
not hold the release for it**" (`first_read = name_it`). His question was answered (what a proof
here is: real `vox` daemons in scratch folders driven with the commands a person types; by a
rough count 82 of the 203 files use a test switch compiled into test builds, 65 read the daemon's
log, 7 use a hand-built stand-in peer) and (1) put again. His answers then: "**accept all three;
name the missing fresh-session proof in the notes**" (`proof_changes_2 = accept`); and, for the
other proofs that check switches, logs or the wire, "**publish v0.4.31 first; do that pass as the
first work after it**" (`proof_purge = after_release`). So every proof removal and deletion this
amendment lists is accepted by him, the first two on 2026-11-27 and the rest on 2026-11-28; and
several acts this amendment relies on read test-switch lines (the key-package acts' wait, the
checkpoint act of ADR-023 amendment 1), which that pass is to look at after the release.

### (f) Proof

Each run below was one run unless more are named; the tree is named with each.

- **Act 1**, `a_rejoined_author_is_not_sent_its_old_session_steps` (`RejoinRead.md`, Successor
  §§2 to 4), on journey11 (`scratch/rejoin-read` on main `695db44c4`, committed as `8f902a851`):
  red on main 5 of 5 ((a) item 1). With FO-13 the step at `:2747` passed in all 8 runs (rf1, rf2
  a1 and a2, rq1 a1 to a3, rp1 a1 and a2); the act was green in rf1 and rf2 a1 and red later in
  rf2 a2 (`:161`, "the room is locked") and three times in rq1 (`:2719`), the fault of (a) item 3;
  with that fix too, green twice (rp1 a1 and a2, 34.79 s and 22.12 s). No test-knobs arm was built
  for FO-13 or for the early refusal; the reds before each fix are the runs without it. Also green
  on journey11's final tree: `a_member_that_left_joins_again_and_is_a_member_again` (rk1 j),
  `a_member_that_comes_back_reads_forward_from_each_return` (rk1 f) and
  `an_author_keeps_a_key_only_while_a_member_still_needs_it` (rk2 k).
- **Act 2**, `revoked_admin_stale_board_does_not_block_live_rejoin`, re-staged, claim, assertions
  and messages kept: the creator posts only once her own `vox status --json` shows the returner's
  `verified_through` at or past the returner's `own_feed_through` read right after its join; one
  staging assertion is added. Green ra2 (37.26 s) and ra3 (35.33 s, journey11's final tree). The
  builder names what is left: "a post in the moment between the creator's admission of the return
  Presence and its history Effect folding it" (`RejoinRead.md`, Successor §1).
- **The older-Vox act**, `a_computer_on_an_older_vox_exchanges_nothing_until_it_updates`
  (`R10Fix.md`, round 2): the assertion that dave reads neither MIXED 1 nor AFTER-UNTRUST is
  removed. In its place a wait on structure (dave's node holds alice's feed through AFTER-UNTRUST
  and either says a post of hers is held and not shown or shows it; "CANNOT MEASURE" if that never
  comes), then the assertion that he does not show AFTER-UNTRUST, with `MIXED 1 shown` printed.
  The mixed-window checks are unchanged. Green xa4 (`MIXED 1 shown: false`), xa6 with FO-14's
  first form (`MIXED 1 shown: true`, allowed by FO-5) and xa8 with its final form; the arm
  `preamble-any` red in xa5 on the kept mixed-window assertion, with its engaged line, on the
  re-staged act without FO-14, and not run again after FO-14, which does not touch that path. No
  switch delivers the post-withdrawal generation to a withdrawn member, so the kept AFTER-UNTRUST
  assertion has no arm of its own. The removal is the coordinating session's ruling, accepted by
  the owner on 2026-11-28 ((e bis)). Also green with FO-14's final form:
  `removing_one_member_rotates_the_key_in_every_shared_room_and_keeps_the_others_whole` (xa7).
  Neither act reaches the window FO-14 closes. The builder's open question, whether a key
  published by package to a computer on the older Vox while it was still trusted is acceptable
  (FO-10 restricts only direct delivery), is not staged and was not put to the owner (`R10Fix.md`,
  round 1, "For the owner/Main").
- **The first-key acts** (`FirstKey.md`), re-staged, claims and assertions kept: the wire peer
  makes the version-3 exchange on each connection and takes a `RotationHello` as a key.
  `a_taken_first_key_is_not_sent_again_after_a_restart` and `…_after_a_crash`
  (`a_taken_first_key_is_not_sent_again_proof.rs`): green FK5 r and FK5 c;
  `an_admission_reaches_every_member_and_never_outlives_a_leave`
  (`a_board_admits_only_verified_members_proof.rs`): green FKB; the shared helper is
  `exchange_history` (`crates/vox-core/tests/support/raw_sync.rs`).
- **Deleted: `a_member_whose_session_went_wrong_is_offered_a_fresh_one`**
  (`a_member_whose_session_went_wrong_gets_a_fresh_one_proof.rs`; `FirstKey.md`). Its staging
  needed a first key sealed under the pair's long-lived session, which #1418 removed; the
  coordinating session's alternative, a delivery the member's node refuses as `CannotOpen`, cannot
  be produced by the wire peer without forging that refusal, and a member-side knob refusing its
  first delivery "would be a second forgery, inside the product". So "a member whose session went
  wrong gets a fresh one and reads that author again" has no proof in this release. The deletion is
  the coordinating session's ruling, accepted by the owner on 2026-11-28, who asked that the
  missing proof be named in the notes ((e bis)).
- **The key-package acts** (`KeyDebt5.md` §10):
  `keys_reach_an_offline_member_through_an_always_on_member`,
  `a_removed_authors_package_opens_nothing` and
  `a_key_through_the_log_releases_what_a_direct_one_does`, re-staged. Their shared wait no longer
  asks for the author's `key_delivery_pending` to be false; it waits until the author's daemon
  says every key owed to B is in the log (a test-knobs line), then until C holds those appends;
  every claim, bound and message is kept. Green kq2 (all three). The file's named mutant, "no key
  package posted", adapted as a source patch and reverted after, was red in kq3 on its own
  assertion ("B read 0 of 6"); a source patch prints no engaged line. kq4 green, with the new
  status words printed.
- **The interrupted-history act** (`a_newcomer_reads_the_whole_history_proof.rs`; found-reds 145,
  160, 162): renamed from `interrupted_history_and_private_packages_recover` to
  `a_returning_member_crosses_a_private_package_and_keeps_its_cursors`, since it no longer
  interrupts anything (`Trace145d.md`, "Rename"). Re-staged, claims kept: a wait rule older than
  #1411; a wait for a room to open under the act's own package hold; a page back from a row the
  reader had not fetched yet; a wait for a saved request the product no longer saves when nothing
  is owed (found-reds 145); the retention reloads retried on the named wait "permissions are still
  being read", and Carol's and Bob's reloads waiting until each shows the room's week of Session
  step retention (`Trace145c.md`, rounds 4 and 5; `Trace145d.md`, round 2); a page back and a wait
  for exact cursors before the restart (`Trace145d.md`); the pruned-body loop, which raced the
  act's own one-second retention (`Trace145d.md`, round 3); and the late member's
  `shows_not_received_yet` step (`LateJoin.md` §3). Removed, three parts:
  1. Its privacy section, with 14 assertions and the knob
     `VOX_TEST_SERVE_NONRECIPIENT_HISTORY_BODY_FILE` (`Trace145c.md`, round 3): it asserted the
     opposite of what Vox has required since #1075 (every member keeps a sealed package so that an
     always-on member carries it to an offline recipient), which
     `keys_reach_an_offline_member_through_an_always_on_member` proves with its mutant.
  2. Its resume step, with three assertions (`Trace145c.md`, round 7): since #1411 a returning
     member's loop fetches the whole feed unasked, so a request is left to resume only by chance
     (it passed four times and failed the fifth, klf).
  3. Its expired-body refill sub-claim, with its witness steps and the knobs
     `VOX_TEST_FX29_CONTENT_REFILL_OUTCOME_FILE`, `VOX_TEST_FX29_CONTENT_REFILL_HASH` and
     `VOX_TEST_HOLD_RETENTION_SWEEP_FILE` (`LateJoin.md` §3): it waited for an expired Content
     body to be fetched, and since #1411 an expired Content position completes without its body
     being fetched (`completed`, `channel/held_history.rs`), so its wait never ends (ljp/lj2). A
     key-package body still owed can still be fetched and found expired at its checked refill: that
     is the case ADR-054 amendment 4's PL-42 fixes.

  Parts 1 and 2 are the coordinating session's rulings of 2026-11-27 (found-reds 145), put to the
  owner; his answer: "**accept both; name the missing resume proof in the notes**"
  (`proof_removals = accept`). Part 3 is the coordinating session's ruling (found-reds 160),
  accepted by the owner on 2026-11-28 ((e bis)). Runs: the act went green to its end twice, lj3 and
  lj4 (201 s and 215 s, on `scratch/late-join`), once more as shipped with ADR-054's PL-42 complete
  (lt1, 208.88 s, `LateJoin.md`, "Review fix"), then eight times on `scratch/first-read`
  (`149a3bd0e`) with the unlanded first-read fix (fh1, fw2 to fw8). It is an optional act: the
  gate's file runs are built without `optional-proofs`, so in passes 7 and 7d it printed `OPTIONAL
  PROOF NOT RUN` and did not execute (the newcomer file's 15 harness successes there are six
  executed tests and nine such notices). It has not been run on the merged tree; further runs on
  the release commit are to be recorded in `/opt/vox-evidence/v0431/rg-6/close/closing-runs.md`.
  Its one-read check at `:2855` (`:2847` before) stays as it is and can go red in
  about 1 run in 10 for the windows of (b) (found-reds 162, last row).
- **Act 1 again, the Session step** (found-reds 164a; `RejoinRead.md`, "Later step"): no proof
  changed. On `dcc2b58cd` red in 10 of 17 traced runs (rx1 to rx4); with the `drive_members` line,
  green 4 of 4 alone (rj1 to rj4), its whole file green, 7 passed (rw1: six executed and one notice
  of an optional act not run, the build being without `optional-proofs`), and green
  `a_member_that_comes_back_reads_forward_from_each_return` (rk3) and
  `readmitted_member_keeps_read_private_history_but_cannot_backfill_unseen_history` (rk4). No
  test-knobs arm was built.
- **The key-deletion act**, `a_member_deletes_another_members_key_once_it_has_read_everything_sealed_under_it`
  (found-reds 164b; `KeyPrune.md`), unchanged: with the fix green 5 in a row with traces (kx1 to
  kx5), once beside a heavy act (kxl1) and once on the product patch alone (kxp1); its arm
  `floor-not-exact` red on its own assertion with its engaged line (kxm2).
- **Re-staged in the same pull request, for rules of other records** (`pr-body.md`, "Proofs
  changed"): `a_room_bound_service_carries_real_bytes_through_the_real_binaries` asks again on the
  refusal ruled to stay in this release, and the hash-reading helper of the newcomer file
  recognises the refusal as the command's last line (ADR-052, amendment of 2026-11-28 under
  RG-4); `a_full_disk_recovers_without_stranding_sync_or_leave` keeps its nodes' logs (ADR-054
  amendment 4); `a_quiet_room_with_a_one_second_retention_stops_writing_checkpoints` is new
  (ADR-023 amendment 1).
- **On the integrated tree, whole files as the gate runs them** (`simple-sync/review/STATE.md`;
  `pr-body.md`, "Proof"; the logs in `release/gate-sweep/pass7*/logs/`). The gate builds these
  file runs with `--features test-knobs` and without `optional-proofs`, so each optional act
  prints `OPTIONAL PROOF NOT RUN` and is counted as passed. Pass 7 (20 files, on `e396fd1ee`): 15
  green, 5 red, each traced (the terminal app, act 1's Session step, the key prune, the give-back of
  ADR-053 MP-15, and one load red green alone); pass 7b (12 files, `149a3bd0e`): 10 green, the
  key-deletion act red once more (fixed after) and one known load red; pass 7c (4 files,
  `43a3ab3cc`): all green; pass 7d (6 files, `b10f075e8`, quiet machine): all green. Of the
  counts: the leave-and-end file's 33 harness successes are 28 executed tests and 5 notices; the
  newcomer file's 15 are 6 and 9; the key-package file's 8 are 6 and 2; the claude-Session file's
  7 in pass 7b are 6 and 1 (in pass 7, 5 executed passed, 1 failed, 1 notice); the
  nodes-of-one-daemon file's 33 passed are 15 executed and 18 notices, beside its one red. The acts
  this amendment rests on that ran in these files: act 1, act 2, the older-Vox act, the first-key,
  key-package, key-deletion and author-keeps acts, `a_member_that_left_joins_again_and_is_a_member_again`
  and `a_member_that_comes_back_reads_forward_from_each_return`. The optional ones did not: the
  renamed interrupted-history act (above) and `a_node_that_left_rejoins_and_posts_at_once`, last run
  alone in fwl (on `149a3bd0e` with the unlanded first-read fix); further runs on the release
  commit are to be recorded in `/opt/vox-evidence/v0431/rg-6/close/closing-runs.md`. The busy-room
  journey jrnS2 on `b10f075e8`: "GREEN: RG-1 apparatus_smoke=false; every member shown both ways;
  every post each member is owed (of 3668 acknowledged) shown on it after authors stop"
  (`release/regress6/jrnS2/paused/receipt.log`). `8761dd46f` differs from `b10f075e8` by a
  lint-only change (4 lines in `entry_store.rs` and `governance/facts.rs`); lint is clean on it, as
  the pull-request text reports. The other 160 or so proof files were not run on this tree.
- **What rests on review, not runs**: FO-14 (item 6); FO-13's chain-id assumption (item 5); the
  reach of FO-14 to closed rooms (item 4); the stale Session floors of older builds.

### (g) Reviews

Source review only. `sec-regress6-1.md` (SecKeyDebt, 2026-11-28), on journey11 `8f902a851` and
r10-fix `ab9110d86`: **ACCEPT** "for the product hunks …. No patch-introduced defect found", with
the qualifications quoted in FO-13 item 5 and the legacy residual of FO-14 item 3; "Limits:
source-only review; no builds/tests/runs. Test-only changes, proof-sweep claims, broader sync
behavior and arbitrary full-profile rollback resistance were not reviewed." Its fix-only round on
r10-fix `268b4e045`: **ACCEPT**, "The legacy window is closed", "No peer-driven rotation storm
found", with the qualification quoted in FO-14 item 5. Its fix-only round on journey11
`56ed15255` (the drive-member narrowing): **ACCEPT**, quoted in (b), "Also fixed", item 3. Its
fix-only round on kp-fix `ffeb805d2` (the prune flag): **ACCEPT**, quoted there, item 4. The
status words (`ac11a825a`) and the proof changes were in no security review.

### (h) Built

Pull request #1424 (`fix/sweep6`): one squashed commit `08ec7b2aa` on main `695db44c4`, merged as
`516c08746` on main, with the tree of `scratch/sweep6-land` at `8761dd46f`
(`/opt/vox-worktrees/sweep6-land`). The parts of this
amendment came in as its first commit, `84a741d17` (`scratch/first-key`: the first-key acts; the
fresh-session act deleted), and by merges of `ed9c5ff0c` and `ac11a825a` (`scratch/kp-fix`: the
key-package acts; the status words), `8f902a851` (`scratch/rejoin-read`: FO-13, the early refusal, act 2
re-staged), `aea4c4c14` (`scratch/ledger-145`: the interrupted-history act repaired and renamed),
`ab9110d86` and `268b4e045` (`scratch/r10-fix`: FO-14 and the older-Vox act), `33e3f9533`
(`scratch/late-join`: the act's late-member steps), `56ed15255` (`scratch/rejoin2`: the
drive-member narrowing) and `ffeb805d2` (`scratch/keydel`: the prune flag). The builders report
`cargo check --workspace` and `cargo check --workspace --tests --features test-knobs` clean on
their own trees; lint (fmt and four clippy profiles) is clean on `8761dd46f`, as the pull-request
text reports.

### Landed

- Merge commit `516c08746` of #1424 on main.

## Links

- `/opt/vox-evidence/v0431/exec/deviations.md` (the 2026-11-27 sections)
- `/opt/vox-evidence/v0431/design/forward-only/` (`design.md` to `design-4.md`, `ruling-1.md` to
  `ruling-4.md`, `sec-code-1.md` to `sec-code-7.md`, `build/`, `spike/`, `update/`)
- `/opt/vox-evidence/v0431/simple-sync/pull/journey-37/`
- `/opt/vox-evidence/v0431/simple-sync/pull/journey-36/`
- `/opt/vox-evidence/v0431/release/legacy-room/report.md`
- Branch `scratch/forward-only` (`/opt/vox-worktrees/forward-only`)
- `/opt/vox-evidence/v0431/release/keyloss/` (amendment 1), `/opt/vox-evidence/v0431/exec/found-reds.md`
  entries 147 to 153
- `/opt/vox-evidence/v0431/release/regress6/` (`RejoinRead.md`, `R10Fix.md`, `FirstKey.md`,
  `LateJoin.md`, `sec-regress6-1.md`, `pr-body.md`), `release/keyloss/KeyDebt5.md` §10,
  `release/owed/Trace145c.md`, `Trace145d.md`; `exec/found-reds.md` entries 145, 154, 155, 158
  to 162, 164a and 164b (amendment 2); `release/regress6/FirstRead.md`, `KeyPrune.md`,
  `jrnS2/`; pull request #1424, branch `scratch/sweep6-land` (`/opt/vox-worktrees/sweep6-land`)
