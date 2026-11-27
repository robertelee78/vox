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
4. **Computers on different versions exchange no history or keys with each other** until both run
   v0.4.31; between those two computers the room is silent, while each side keeps exchanging
   within itself. A computer still on v0.4.30 is told nothing about why.
5. **A returner's keys travel by log package, not directly**, so they need the returner's prekeys and
   a member that has applied its return; a sender that has not received the return Presence defers
   (design-4 §3, "most likely to go wrong" 3). The rejoin acts show a returner's keys arriving by
   package ((f)); the deferral resolving under load is not staged.
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

## Links

- `/opt/vox-evidence/v0431/exec/deviations.md` (the 2026-11-27 sections)
- `/opt/vox-evidence/v0431/design/forward-only/` (`design.md` to `design-4.md`, `ruling-1.md` to
  `ruling-4.md`, `sec-code-1.md` to `sec-code-7.md`, `build/`, `spike/`, `update/`)
- `/opt/vox-evidence/v0431/simple-sync/pull/journey-37/`
- `/opt/vox-evidence/v0431/simple-sync/pull/journey-36/`
- `/opt/vox-evidence/v0431/release/legacy-room/report.md`
- Branch `scratch/forward-only` (`/opt/vox-worktrees/forward-only`)
