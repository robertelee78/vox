# ADR-042: Status Reports Outcome, Not Activity

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-13) as the design for v0.4.31, under the decider's authorization
  of 2026-11-13 ("post review can accept them too"), after the eighth independent review by
  GPT-6.1-Sol found it ready for acceptance (`adr-042-sol-review-8.md`). Revision 9
  (2026-11-13) corrects proof recipes and two internal contradictions found when the ADR was cut
  into tasks (`v0431-tasks-ADR-042-sol-review.md`, "ADR defects requiring correction
  first"). Revision 10 (2026-11-13) applies the second correction batch: the sync repair's (R1)
  wording is out, since the decider chose the replacement (ledger rows 57, 62); the status lines
  and JSON fields sibling ADRs ask this ADR to carry are in Appendix A ("Lines and fields other
  ADRs ask this ADR to carry"); the cross-asks of `adr-cross-asks.md` targeting this ADR,
  the amendment quotes, ledger row 64's lost-receipt note and the privacy scrub are applied.
  Revision 11 (2026-11-13) answers the re-check of revisions 9 and 10
  (`adr-042-sol-review-recheck-1.md`, R1–R14 and the Appendix A row table) and folds in
  the askers' answers (ADR-046 r10, ADR-044 r14, ADR-047 r11, ADR-048 r7, ADR-049 r10, ADR-041
  r8, ADR-051 r1). Revision 13 (2026-11-13) answers the third re-check
  (`adr-042-sol-review-recheck-3.md`, G1, G2), folds in ADR-049 r12's Appendix A rows
  (`own_feed`, `admissions[]`, `sources`, `carry_estimate_bytes`, `answer_rows`, SO-15's disk
  names; its act A (a′) proves TR-16's sentence) and records the speed rulings (ledger rows 80,
  81: this ADR states no latency target; E1's patience constants are measured, not targets). Revision 12 (2026-11-13) answers the second re-check
  (`adr-042-sol-review-recheck-2.md`, F1–F8) and folds in ADR-043 r13 (CJ-17), ADR-046
  r11 (the 1 MiB encoded summary limit and the over-limit checkpoint rejection) and ADR-047 r11's
  `store.redb` sample. None of the four changes a design decision or a decider's answer; each is
  re-checked by the same reviewer. Changed requirements are marked **(r9)**, **(r10)**, **(r11)**
  or **(r12)**. Revision 8 came after
  seven earlier independent reviews
  (`adr-042-sol-review.md`, sixteen findings, "needs redesign";
  `adr-042-sol-review-2.md`, twelve findings; `adr-042-sol-review-3.md`, R1–R4;
  `adr-042-sol-review-4.md`, D1–D3; `adr-042-sol-review-5.md`, E1; `adr-042-sol-review-6.md`, S1–S2; `adr-042-sol-review-7.md`, T1–T2, "ready for acceptance conditional on ADR-046 accepting contract rows 1–5" once closed) and
  the decider's answers of 2026-11-13 to the six questions (`adr-cross-changes.md` rows
  22–27, recorded in the final section). This is design acceptance only, and nothing in it is
  built: every requirement says what the code is to do. It is the design
  record for fix-list items 49–56, 69–73 and the status half of 85–87 of the v0.4.31 stabilization
  release, for the status half of fix-list items 1–4 (ADR-046 SY-20 carries their mechanism),
  and for the defects found while planning them (49b, 54b, 54c, 55b, 56b); item 53 (a
  repair command) is not in 0.4.31, by ruling. Requirement ids TR-1 … TR-25 are kept; a
  requirement changed in this revision is marked **(r5: Dn/Qn)**, **(r6: E1)**, **(r7: S1/S2)**, **(r8: T1/T2)**, **(r9)** or **(r10)**; a withdrawn one keeps its id and
  says why. ADR-046 revision 4 (SY-22) accepts the five contract rows in "Contract with sibling
  ADRs" unchanged, which was the condition of acceptance. The "Review record" answers every
  finding of the reviews.
- **Date**: 2026-11-12
- **Deciders**: Robert E. Lee
- **Tags**: status, health, doctor, error text, logs, notifications, reach, repair
- **Related**: ADR-011, ADR-018, ADR-025, ADR-026, ADR-028, ADR-034, ADR-036, ADR-037, ADR-038;
  in this release ADR-040, ADR-041, ADR-043, ADR-044, ADR-045, ADR-046, ADR-047, and the three
  ADRs split from ADR-040 (ADR-048 trust containment, ADR-049 leaving and ending rooms, ADR-050
  the agent turn journal), being written as this revision is.
- **Inputs**: the operator's files of 2026-11-12 and 2026-11-13 under
  `/private/tmp/vox-rca/{io,mac,beast}/` (named where used; every file under `/private/tmp` and
  `/tmp` was lost in the reboot of 2026-11-13, ledger row 64: the figures this ADR took from them
  are recorded in Appendix B and `adr-042-revision.md`, and each is to be re-run as the
  fleet baseline); the root-cause reports RcaSlow (S2,
  S4), RcaKeys (K1, K3, K4), RcaFrozen (RC-3), RcaLanPath (L1–L3), RcaSchedStall (items 85/86/87,
  KNOWN, reproduced on the release asset; receipt lost in the reboot of 2026-11-13, figure
  recorded in `rca-RcaSchedStall.md`, to be re-run as the fleet baseline); the sync-progress
  trial; the IO repair drill; the consolidated analysis "Why Vox keeps breaking"; the group-G plan;
  both reviews; ADR-046 revision 2 (`adr-046-revision.md`); the decider's rulings of
  2026-11-13 (all machines move to 0.4.31 together, no mixed-version sync; the release gate fits
  8–10 hours). Every file:line below is at tag v0.4.30 (commit `8d71ab337`) unless it names an ADR,
  and was read there. The receipts of the evidence reads (`/tmp/Adr042Redesign/receipts.txt`)
  were lost in the reboot of 2026-11-13; their figures are recorded in Appendix B and
  `adr-042-revision.md` (ledger row 64).

## Context

### What the operator saw

On 2026-11-12 the operator ran v0.4.30 on four machines. From 19:36:38Z, when omp-io joined
`repo-to-cve` (`io/daemon-202624Z.log:3157`), until about 22:30Z, omp-io held 70 to 97 of the
room's ~4,400 entries and showed only its own rows. Every status surface on both ends said things
were fine. The operator restarted omp-io's daemon at 20:19:29Z (`:3824`) on that; nothing changed
(the recorded count of other members' log entries, `log_entries − own_feed_through`, is 49 at
20:04:54Z, 49 at 20:20:11Z, 49 at 20:27:32Z and 49 at 21:51:03Z; whether a body was refilled or a
control entry applied between samples is not recorded). Three agents and the operator then spent
the day on messages that named the wrong thing. A rebuilt omp-io joined at 22:23:01Z and was still
at governance revision 51 against the members' 155 fifteen minutes later. On Nov 13 at 00:50Z the
operator ended the room; on robert-work it stayed listed, with three red `sync failing …
authenticator invalid` lines against members that had deleted it. In the 02:16:27Z snapshot taken
20 s before the restart that cleared it, the same node's newest surviving Public start record is
01:36:03Z and its Private (key) starts continued to 02:15:17Z, every port queued and none running;
when it actually last started a Public round is not derivable (a port keeps only its newest attempt,
whatever the service, `actor.rs:17419-17428, 17473-17485`); its sibling on the same daemon synced
normally; its status said `no completed sync in 10 minutes` for four rooms, two of which were in
fact up to date, and nothing for the two rooms that were most behind. The decider, reading `vox
computer status` the same day, called it "unreadable".

This ADR is about one failure on every surface: the product reports what it did, not whether the
person got what they should, and when it cannot know, it says nothing or says "fine".

### The four incidents this design must have tripped

Each is replayed in Appendix B as a **conditional replay**: the saved files hold what v0.4.30
recorded (counters, prefixes, revisions, port ages), not this ADR's measures; every time and line
in Appendix B names the file it is derived from or is marked "not derivable".

- **(a) omp-io cut off for three hours.** `io/daemon-202624Z.log:3157, 3824`,
  `io/status-omp-io-200453Z.json`, `io/status-omp-io-post-restart-202011Z.json`,
  `io/status-omp-io-202732Z.json`, `io/quiet-fullstate-omp-io-215043Z.jsonl`,
  `io/discrim-ompio-205749Z.jsonl`, `io/doctor-omp-io-203050Z.txt`,
  `mac/status-omp-work-200453Z.json`, `mac/discrim-ompwork-to-io-205749Z.jsonl`.
- **(b) the rebuilt omp-io stalled at revision 51 against 155.** `io/newnode-progress-222537Z.txt`,
  `io/newnode-watch-222834Z.tsv`, `io/newnode-watch2-223448Z.tsv`, `io/newnode-slot-223234Z.jsonl`.
- **(c) an ended room still listed with red sync lines.** `mac/stall-robert-work-021627Z.json`
  (`unhealthy[]`: three `sync-failing:o6z3…`, one `room-stale:o6z3…`).
- **(d) robert-work stopped starting Public rounds.** `mac/stall-robert-work-021627Z.json`
  (16 ports `queued: true`, `round_running: false`; the newest surviving per-port attempt is
  Public at 01:32:35Z–01:36:03Z on nine ports and Private at 01:40:00Z–02:15:17Z on seven; 3 slots
  in use with `running: [null, null]`; 11 retiring flows: ten for room k4qx with the ledger error
  `store save room: malformed at-rest artifact: key-package attempt unacknowledged`, one for the
  ended room with `node: history retirement worker stopped`) and `mac/stall-omp-work-021627Z.json`
  (the sibling: 0 slots, every port idle, one round running; and the **same 11 `cleanup_errors`**
  in its own status, each tagged `actor: 2`, which the budget's actor map names robert-work: the
  ledger is daemon-wide).

### 49. Status is green while a room receives nothing

**Seen.** `vox status` on omp-io at 20:04Z (`io/status-all-200453Z.txt:20-42, 70-77`): `last
sync 1s ago`, every member `trusted connected last seen 0s ago last sync 2s ago`, `this node holds
their room feed through 13` (ehu3), `7` (nqpf), `8` (nyty), `3` (o73v), `12` (rotl), `6` (vdy4)
while the laptop held those feeds through 15, 2109, 1075, 241, 834 and 84
(`mac/status-omp-work-200453Z.json`). No UNHEALTHY line. The laptop held omp-io's feed "through
21", showed none of its posts, and printed `healthy: nothing needs attention`. omp-io printed no
`healthy:` line at all: the renderer suppresses it whenever the anchor inventory has an error
(`crates/vox-tui/src/status_cli.rs:229-233`).

**Cause — KNOWN (the files above; code).** Every line measures activity:

- `last sync` is `StatusBook::room_synced`, written by `note_lane_sync`
  (`crates/vox-core/src/node/actor/bounded_sync.rs:4482-4486`, called at `:3732`, `:4063`,
  `:4434`) when a round completes, including one that brought nothing (`PortCounters::empty`,
  `crates/vox-core/src/node/status.rs:1264-1269`).
- `trusted` is the keyring and `connected` a live QUIC connection (`status.rs:103-106`).
- `this node holds their room feed through N` is `ChannelState::holds_through`, the DAG's
  contiguous verified prefix (`crates/vox-core/src/node/channel.rs:8764-8767`): headers, not
  bodies, and not positions held above a gap.
- `diagnose` (`status.rs:374-459`) knows `room-stale` (no completed round for 10 minutes),
  `room-flow-state-pool`, `peer-unreachable` and `anchor-unreachable`; `failing_peers`
  (`status.rs:1600-1623`) knows `sync-failing`. None can be true while a peer answers every round
  promptly with nothing.
- `history_fetched` is not delivery: it counts a worker's commit flag (`bounded_sync.rs:3426-3430`,
  one per turn with `work_committed`), set by a locally generated control proof
  (`history_stream/client.rs:327`) and by live-window index work (`runtime.rs:2354-2420`). Toward
  nqpf it rose 2037→2065 and toward nyty 2620→2668 in the 29 s of
  `io/discrim-ompio-205749Z.jsonl`, and from 536/811/765 at 20:04Z to 3,429/5,568/5,745 at 21:50Z,
  while every foreign feed's held prefix stayed at 13, 7, 8, 3, 12, 6 and foreign entries at 49.
  Nothing at v0.4.30 records when an entry of another member last arrived with its body.

Why the code is this way: ADR-025 S0b asked for activity counters; PRD-001 R35, R37 and ADR-034
HL-1/HL-2 define health as "cannot save", "every sync fails", "unreachable"; ADR-038 FX-16
defined `last sync` as "each round the lane completes". No rule asked how far behind the node is,
whether it has verified what exists, or when it last received an entry.

**49b — KNOWN (code).** `sync-failing` needs `consecutive_failures ≥ 2` for 30 s (`status.rs:1607`).
Any completed round resets it (`bounded_sync.rs:3720`; `actor.rs:13575`; `actor.rs:18029` also on a
no-failure partial report), and an empty round is a completed round. `actor.rs:10386` resets it on a
network change and `actor.rs:16815` on port retirement.

**Why no proof caught it.** `notify_proof.rs` (R37) stages a dead peer and a dead anchor;
`vox_status_shows_the_node_proof.rs` (R35) asserts `last sync` is shown and a stopped guest is
flagged. No proof stages a peer that answers every round and serves nothing, and none stages a
newcomer that has verified nobody's head.

### 85. A node stops starting rounds while its sibling syncs

**Seen.** robert-work, Nov 13 (`mac/stall-robert-work-021627Z.json`, 02:16:27.580Z, 20 s before the
restart that cleared it): every port queued, none running; the newest surviving Public start record
on the node is 01:36:03Z (`min` Public `start_age` 2,424,371 ms, o6z3/vdy4; a port keeps only its newest
attempt across services, so the node's actual last Public start is not derivable); Private (key)
starts continued until 02:15:17Z; 3 slots held with no round running; 11 retiring flows. The
sibling omp-work was idle and current. The alarms raised were `room-stale` for agent-memory (5 log
entries fewer than omp-work), ioa-brain (0), repo-to-cve (ended) and cve-to-exploit (0); nothing
for r2c-2 (135 fewer) and vox (37), whose Private rounds had completed within 10 minutes.

**Cause — KNOWN (RcaSchedStall, reproduced on the release asset).** A retained flow whose local
retirement save fails stays in `retiring` and `retirement_failed` (`bounded_sync.rs:1854-1860`)
waiting on a future that completes only on a node lock (`runtime.rs:1814-1848`); such flows count
against the node-wide `RETAINED_FLOW_LIMIT = 12` (`:580`, `can_retain_new :1789-1810`); at 11 every
Public start is refused at `:4749-4757`, deliberately without a `start_reason`. Nothing clears it
but a node restart (`vox node rename`, or lock and unlock; a daemon restart). A stalled node that
ends a room loops `ended room cleanup stopped` and one that leaves gets "An internal error". The
retirement ledger (`lanes.bounded.cleanup_errors`) is daemon-wide: omp-work's status listed
robert-work's 11 errors. The decider chose the replacement (ADR-046 R2, ledger row 57), which has
no retained flow, no pool and no `RETAINED_FLOW_LIMIT` (ADR-046 SY-19): the class of cause is
gone, and ADR-046 SY-24 makes a slot a running exchange's and nothing else's and records every
refused start's reason; ADR-049 owns the ended/left room; this ADR owns what the node and its
sibling say, on the right node, with the reason **(r10)**.

### 50. Messages name internals or the wrong thing

**Seen.** IO's log (`io/daemon-202624Z.log:3707-3712`): `store save room: authored save worker
stopped` ×36, `a join did not complete — room o6z3enlc2ymd recovery could not complete its retained
save`, per-peer `last failure: malformed identity bundle: inclusion header is absent` (trial
B1-base: 291 of 300 samples).

**Cause — KNOWN (RcaFrozen RC-3, RcaKeys K3/K4, the trial; code).** `release_pending_text(owner,
poison = true)` sets "authored save worker stopped" for any poisoned release
(`crates/vox-core/src/node/channel/pending_text.rs:748-761`); the computer-trust pass releases
every room with poison when one fails (`policy_save.rs:172-182`, from `fail_managed_turn`
`:1384-1385`). No worker died. `recovery_save.rs:283-291` raises `NodeEvent::JoinFailed` for a
settlement save; no join was in progress. `Error::MalformedBundle(&'static str)`
(`crates/vox-core/src/error.rs:120-121`) is the Display prefix for 528 decode failures;
`admission.rs:234-237` uses it for "inclusion header is absent", a sync-ordering fault, and
`error_code` maps it to `WireError::ProtocolLimits` (`history_stream/transport.rs:301-306`), which
the other side prints as "the peer refused: protocol limits exceeded". No wire code carries a
reason (`transport.rs:289-297` turns a reset code into `PeerRefused(code)`).

### 51. `vox status` omits preparing rooms; the keyring line reads as a fault; a clock counts from daemon start

**Cause — KNOWN (code; RcaLanPath L3).** The text renderer walks `rooms` and `leaving`, never
`preparing` (`status_cli.rs:262, 361`; `status.rs:545-558` writes it). `keyring_label(None)` is
"keyring asks for the passphrase" (`snapshot.rs:507-511`), printed one line above the verdict.
`since = room.last_sync.unwrap_or(self.started)` (`status.rs:384`) makes a room that gains its first
member twelve minutes after start "stale" at once.

### 52. Agents are told a member "has not trusted" them when the cause is sync

**Seen.** `vox agent doctor` on omp-io, 20:30Z: six times `warn trust <member>: you trust it, but it
has not trusted you: it cannot read you` with `fix: on the computer hosting node …, ask its operator
to accept your fingerprint` (`io/doctor-omp-io-203050Z.txt:17-28`); every one of the six had
trusted it (`mac/doctor-omp-work-203823Z.txt:32-37`). Agents followed the fix.

**Cause — KNOWN (code; RcaKeys K1, K3).** `Request::MemberConsents` answers `inbound =
detail.consenting` (`ipc.rs:9209-9224`), the governance projection's `trusted_by[me]`
(`actor.rs:529-534`): only the consent entries this node has admitted and applied. The renderers
(`doctor.rs:973-984`, `room_cli.rs:1253-1258`, `agent_hook.rs:907-911`) read "absent" as
"refused" and prescribe an action on another computer. ADR-028 K-7 is right for authority; the
doctor used it as a diagnosis with no "as of" and no "cannot tell".

### 53. No command rebuilds a room's local state, and the remedy offered destroys data

**Cause — KNOWN (code) for the remedy; no local fault shown for any incident.** A room keeps
derived layers with no rebuild path: the governance projection; the render index and backfill
cursor (`channel.rs:7859-7904`); the Session projection and activity index; the sparse directory
with its persisted `phase` and `promotion` (`entry_store.rs:288-289, 359, 509`; invariant at
`:799-802`). The directory has an owner: `prepare_owned` runs `cleanup_orphan_provisional` at every
open (`entry_store.rs:2668, 2706`), rolling back `Building` and finishing `Switched`. RcaKeys K4's
"left in `Switched`" hypothesis for omp-io is INFERRED there, and the saved files weigh against it:
the operator restarted omp-io's daemon at 20:19:29Z, the open ran that cleanup, and the recorded
foreign log-entry count and revision were unchanged (49, 44). No saved file of Nov 12–13 shows a
disagreement between a room's derived state and its held log; the decider's rule is no fix without
a reproduced cause, so the repair facility of revisions 1–3 is withdrawn unless he keeps it (Q1).
The remedy the operator was given, `vox room leave` and join again, deletes the local room
(`leave_save.rs:284-348`) and then, on rejoin, finds members holding the old own feed further than
the node does and fences posting for minutes (IO repair drill, path 2). A post that only this node
held is gone. That part stays fixed here (TR-16).

### 54. The daemon log loses the evidence within hours

**Cause — KNOWN (code).** `LIMIT` is 1 MiB (`crates/vox-tui/src/daemon_log.rs:17`); one predecessor
(`:89-101`), named `log.log.1`. A repeated line keeps only its first time (`:81-86`). At open an
oversized file is truncated and an oversized predecessor deleted (`:43-51`), and a file holding any
line not in canonical form is rewritten in place from memory (`:52-66`): a torn last line after a
crash reaches that branch.

### 55. Headless Linux logs a notification-service error at every attention event

**Cause — KNOWN (code; evidence).** `raise` runs `notify-send` and waits (`notify.rs:155-159`);
`watch` awaits it inside its 5-second loop (`:318-341`). Without a notification service it fails at
once (IO: ×640) or blocks 120 s (beast: ×105), delaying every later notice (55b).

### 56. A Locked or just-restarted peer is reported as unreachable

**Cause — KNOWN (RcaLanPath, reproduced on the release binary).** A daemon answers the identity
exchange only for attached nodes (`transport/quic.rs:1177-1190`; `identity.rs:696-697`;
`:774-776` says `nothing at {addr} answers as {expected}`). The dialler knows a daemon answered
(`NotAnswered`, not `TimedOut`); `MemberStatus` has only `connected: bool`, so `diagnose` says
"unreachable". The dial-back through a coordinator is useful after a direct failure
(`network.rs:1753-1760`). `rejected: policy` (`nat/service.rs:267, 1630-1641`) is a harmless race.

### Corrections carried from the reviews

(1) `HeadHint` is `{ author, size, head }` (`history_stream.rs:636-640`): unsigned, a hint, never
authority (ADR-036 H-6; ADR-046 SY-12). (2) omp-io printed no `healthy:` line. (3) The 120 s
notification timeout is beast's. (4) `history_fetched` was not flat. (5) The five streak resets are
three completed-round sites and two lifecycle sites. (6) `control_effects_complete` /
`control_sources_complete` (`sparse.rs:1206, 1360`) are keyed by the exact head hash; this ADR
evaluates control currentness on the applied position (Terms). (7) No saved file holds
per-position holdings, anchors, inventories, delivery times or a per-class request-start history:
Appendix B prints no exact count for an incident and no onset time that a file does not support,
and labels a port's `start_age` as its newest surviving attempt (`actor.rs:17419-17428`,
`:17473-17485`: a later attempt replaces the earlier, whatever its service). (8) The coverage age is
the **oldest** fresh inventory, everywhere. (9) `VOX_SESSION` reaches only Vox's hook subprocesses
(`crates/vox-tui/assets/omp-extension.ts:88-96, 323-324`); OMP's shell tool carries
`PI_SESSION_ID` (`:70-72`); `coord::session_if_named` already reads all five harness marks
(`crates/vox-tui/src/coord.rs:72-78`). (10) The historical renderer skips entries already cached
(`channel.rs:8167-8181`) and returns `Unavailable` when a consumed key cannot be replayed
(`:8210-8224`); the backfill skips an entry whose retention record has a `cache_id` even when it
is not rendered (`:7883-7897`): neither re-queuing nor replay can restore a lost index record of a
cached row. (11) ADR-046 r3 SY-14 raises `Head` only for a size or head this node has not accepted;
an unchanged head is not re-verified by a heartbeat, so a verified head ages in a quiet room by
design. (12) ADR-046's `control_through` advances when control headers are **held** (and needed
bodies held or `not for you`), not when they are applied; this ADR keeps both positions apart.
(13) Ten of robert-work's eleven retirement errors are `key-package attempt unacknowledged` (room
k4qx); the ended room's one is `node: history retirement worker stopped`.

## Terms

- **Activity**: something the node did. **Outcome**: whether the person has what they should.
- **Feed**: one author's sequence of entries in a room, numbered from 1. **Entry**: a header and its
  body; a **control entry** carries trust, membership or key facts; a **content entry** is a post.
- **Delivered**: an entry of another member admitted here with its complete body, or a control
  entry of another member applied to the governance fold. A header without its body, a body chunk,
  a proof, an inventory, a heartbeat and a round are not deliveries. **`last_entry`**: when the room
  last had a delivery; per source member, `last_received_from`.
- **Known size** (`size_known(A)`): the size of the newest signed head of A this node accepted
  (ADR-046 SY-13 rule 3). Authority: A signed it and the consistency proof verified. Blind spot: A
  may have posted since; a head is learned only when some peer answers `Head`, and ADR-046 SY-14
  raises `Head` only for a size or head this node has not accepted, so an unchanged head is never
  re-verified: **`head_age(A)`** (time since the newest accepted head of A was verified, from A
  itself or a relay) grows in a quiet room by design and is a fact to print, never a guard. What
  bounds a quiet room's blind spot is the coverage: no fresh source has advertised anything newer.
  **No head** (`no_head(A)`): no head of A has been accepted yet (after a join whose answer carried
  none for A, or until the first `Head` answer).
- **Inventory**: a member's `Have` for the room (ADR-046 SY-12: per author its size, head,
  `control_through`, up to 16 held body intervals and `intervals_total`; at v0.4.30 the inventory
  frame's `HeadHint`s). **A hint of where to ask and nothing else** (ADR-046 SY-12): it never sets
  what is wanted, what is current, or what is behind. **Fresh**: received from a connected member on
  its current connection within `INVENTORY_FRESH`. **Source**: a connected member whose inventory
  for the room is fresh. **Coverage**: sources / other members, and the age of the **oldest** fresh
  inventory among them.
- **Advertised size** (`size_advertised(A)`): the highest size any source names for A, with the
  sources. Shown apart, labelled unverified; a size above `size_known` raises one `Head` request
  (ADR-046 SY-14) and nothing else. Two sources naming different heads at one size are
  **disagreeing advertisements**, shown as such; **fork evidence** is ADR-046 SY-13 rule 2's, decided
  on two objects A signed, never on advertisements.
- **Anchor** (`anchor(A)`): the first position of A's feed this node fetches without being asked
  (ADR-046 SY-17, SY-26). Positions below it are **older history**, fetched on request.
- **Wanted bodies** (`wanted(A)`): ADR-046 SY-14's set: positions from the anchor to `size_known(A)`
  whose body is not held, not expired and not `not for you`. **Behind** (`behind(A)`): `|wanted(A)|`;
  for a room, the sum over authors; exact, because every input is local or signed.
- **Trust held through** (`control_held(A)`): ADR-046 SY-14's `control_through`: the position up
  to which every control header of A is held and every needed control body is held or `not for
  you`. **Trust applied through** (`control_applied(A)`): the position up to which the held control
  entries of A have been applied by the fold (ADR-046 SY-3); `control_applied ≤ control_held`.
  Positions `control_held(A)+1 … size_known(A)` are **trust to check**: coverage to verify, not a
  count of missing entries; printed as `trust checked through <p> of <s>`, never as "behind".
  Positions `control_applied(A)+1 … control_held(A)` are **trust held, pending application** (a
  held control entry waiting on a context, a parent header or the fold: ADR-046 SY-14's context
  and parent-header wants; ADR-040 NW-1's `GovernanceFold(room)`). **Control current**
  (`control_current(A)`): `control_applied(A) ≥ size_known(A)` and `¬no_head(A)`.
- **Oldest dependency** (`oldest_dependency(A)`) (r5: D1): the lowest unresolved control
  dependency of A, **with its kind**: (i) *unchecked coverage*: the range `control_held(A)+1 …
  size_known(A)` (whatever its relation to the anchor: control is fetched from the room's fence
  post, or from position 1 when there is none, ADR-046 SY-14, SY-27; ruling 65), which says nothing about whether any control entry exists in it; it is resolved by a
  `ControlRange` answer that advances `control_held` (a proof of absence advances it as well as a
  delivery); (ii) *a held control entry pending application*: a specific position whose header is
  held and whose kind is known from that header, with what it waits for (a context hash, a parent
  header position, the fold). A position is named as a trust entry only in kind (ii), after an
  authenticated header or proof established it; kind (i) is always printed as a range.
  **`dependency_since(A)`**: when that dependency became unresolved (changes only when it resolves;
  the next's own time takes over). A `ControlRange` answer that does not advance `control_held` is
  not progress.
- **Held without its text**: a header held whose body is not held and not expired.
- **Readable**: a held content entry whose author has consented to this node in the applied
  projection and whose sender key generation for that entry is held. **Unreadable held**
  (`unreadable(A)`): held content entries of A at or above the anchor that are not readable, with
  the cause: `consent not here` (no applied consent for this node among the entries applied through `control_applied(A)`),
  `consent held, not yet applied` (a control entry held, fold pending: ADR-046 SY-3),
  `sender key not here` (consent applied, key generation missing), and the admission time of the
  oldest such entry (`unreadable_since(A)`).
- **Holder** of a wanted position, by kind (r4: F6): for a body, a source whose fresh inventory
  names a held interval containing it, **or** whose availability overlay (ADR-046 SY-14: the `Held`
  answers of probes to that peer, in memory) names it (**positive**); a source with
  `intervals_total` > 16 whose named intervals and overlay do not contain it and that has no
  negative for it (**possible**, being probed); for a control dependency, a source whose
  inventory's `control_through` is at or above the position; for a context or parent header, any
  source. **Negative**: a `NotHeld` answer from that peer for (A, range), kept until that peer's
  inventory for A changes (ADR-046 SY-15 rule 4). The overlay for (peer, A) is dropped when that
  peer's inventory for A changes or the peer disconnects, and a holder that was positive only by
  its overlay becomes possible again. **Unknown**: no source's inventory, overlay or negative covers
  the position (printed `being located`, never "no holder"). **No holder**: every source is
  negative for the position. **Known holding** (r6: E1; r7: S2): a member's last inventory
  intervals and overlay for A, kept in memory after that inventory goes stale or the member
  disconnects, marked with the member's reach and the inventory's age; one record per member and
  room, the same bound as the live inventory (ADR-046 SY-12's caps), replaced by the member's next
  inventory, dropped when the member leaves the room, and **not kept across a restart** (nothing
  of status is written, ADR-038 FX-29). A known holding is a historical claim: it is not a source,
  creates no wanted work, no coverage and no positive holder, and proves no present possession;
  it only names who **last advertised** a position this node needs and how long ago. **Last
  advertiser** of a position: a member whose known holding covers it and whose reach is `offline`
  or `not attached`.
- **Reach settled** (r7: S1): a member's reach is settled once its first reach ladder after the
  room opened has run to its end (ADR-012's rungs: each candidate `PER_ATTEMPT_TIMEOUT` = 10 s,
  `nat/reachability.rs:91`, then the dial-back; at most `REACH_SETTLED` = 30 s after the first
  dial) and is `connected`, `not attached at <addr>` or `offline, last seen <dur> ago`; before
  that it is `dialling`. **No member reachable**: every other member's reach is settled and none
  is `connected`. What survives a restart for TR-19's alarm: the wanted positions and dependencies
  (derived from the store: anchor, held intervals, `control_held`, the committed head, ADR-046
  SY-14/SY-18) and the reach facts, re-established by the first reach ladder; nothing else is
  needed by the generic branch.
- **Oldest wanted** (`oldest_wanted(A)`): the lowest position in `wanted(A)`; **`oldest_since(A)`**:
  when that position entered `wanted(A)` (it changes only when that position is delivered, expires
  or becomes `not for you`, and the next lowest wanted position's own entry time takes over). **Stuck
  age** of A: `now − oldest_since(A)` while `oldest_wanted(A)` has a positive holder. Deliveries of
  other positions of A, coverage growth, proofs, heads and inventories do not change it. **Byte
  progress**: a chunk of `oldest_wanted(A)`'s body accepted within `RECEIVE_PATIENCE` (a transfer in
  progress; not a delivery).
- **Demand classes** (r4: R3): the **sync class** is everything ADR-046 SY-14 derives (bodies,
  control, head, context, parent header, probe, own feed, explicit page; R1's Public and
  Background positions); the **key class** is key-package delivery and pairwise work (R1's
  Private position). `last_request_at` is kept per room and class (ADR-046 SY-15 rule 7).
- **Runnable demand**: a wanted body position, a control dependency or a prerequisite (head,
  context, parent header, probe) with a positive holder that is not in backoff or `Busy` toward
  it, for which no request is in flight, and that is not parked on a named wait (ADR-040 NW-1).
  Its **eligibility edge** is the latest of: the demand's entry time, the holder's connection time,
  the holder's last answer or refusal for it, the end of a `Busy` retry time, the node's last
  network change or wake from sleep (`actor.rs:10386`'s event), and the daemon's Ready.
  **Missed-start age** of a class in a room (r4: R3): `now − max(oldest eligibility edge among its
  runnable demands, the class's latest request start in the room)`, while some demand of the class
  is runnable and no request of the class is in flight. One old start delays the alarm by at most
  `ASK_PATIENCE`; it never prevents it.
- **Answered refusal**: a dial whose identity exchange completed with a daemon that refused the
  expected node's name. **Silence**: a dial that got no exchange.
- **Verdict**: the first words after a room's name in `vox status`, from a total table (TR-2): a
  **base verdict** (`ended`, `leaving`, `preparing`, `cannot save`, `only this node`,
  `no inventory`, `waiting for a member`, `catching up`, `checking`, `up to date`) or, when an
  alarm of TR-4, TR-5 or TR-25 holds, its **alarm verdict** (`NOT HEARD FROM`, `NOT ASKING`,
  `NOT RECEIVING`, `cannot read`) in its place. Every state of a room has exactly one base verdict;
  an alarm needs its patience to pass and never changes which base state the room is in.
- **Constants**: `INVENTORY_FRESH` = 90 s (three missed 30 s heartbeats, ADR-046 SY-12);
  `RECEIVE_PATIENCE` = 60 s; `ASK_PATIENCE` = 30 s. Proposals, not calibrated; E1 is to measure them
  on the journeys TR-4 and TR-25 name, and the proofs' bounds move with them.
- **Offline** (r5: Q5): a trusted member's node this node cannot connect to (no live connection
  and no answered refusal in the last minute); printed as the plain fact `offline, last seen <dur>
  ago` and nothing more: it says what this node can reach, not what the member is doing.
- **Local fault**: a disagreement between a room's derived state and the authenticated log and
  caches it holds. No saved file of Nov 12–13 shows one; no command repairs one in v0.4.31
  (ruling Q1). A missing entry is not a local fault.
- **Durations** print as `45s`, `1m48s`, `3h2m`, `2d4h`; "ago" is appended where a time is past.

## The observation contract (one interface under either sync mechanism; ruled: Q6)

Every measure above is computed from these inputs and nothing else. ADR-046 supplies them under
either mechanism (R1 repair or R2 replace): the decider ruled on 2026-11-13 that there is one
common contract and no reduced variant, so no verdict in this ADR depends on the mechanism, and if
R1 is chosen it adds the heartbeat row (ledger row 26). A mechanism that cannot supply a row is
not a mechanism this ADR can report on; there is no fallback.

| Input | Who produces it | Under R2 | Under R1 |
|---|---|---|---|
| inventory per (room, member) with `inventory_at`; a whole or `unchanged` heartbeat every 30 s on the connection, sent by the connection owner whether or not a round starts | ADR-046 SY-12 (R2), SY-22 (R1, added by ruling) | the `Have` stream | a heartbeat frame on the inventory stream, independent of rounds |
| `Head` acceptance event: author, size, source (author or relay) | ADR-046 SY-13 rule 3 | yes | yes (`Query::Head`) |
| `control_held(A)` and its advance (including a proof of absence); `control_applied(A)` and its advance; the fold's pending set with each entry's kind and what it waits for | ADR-046 SY-14 (`control_through`) and SY-3 (the fold) | yes | yes |
| body completion event: author, position; body chunk accepted: author, position, bytes | ADR-046 SY-13 rule 6 / ADR-036 H-4 | yes | yes |
| per-peer availability: advertised intervals, `intervals_total`, the overlay of `Held` answers, negatives per (peer, A, range), and their invalidations; an `unknown` state for a position no inventory, overlay or negative covers | ADR-046 SY-14, SY-15 rule 4 | yes | yes (R1 gains `Probe`/`intervals_total`, or reports every uncovered position as `unknown`, never as "no holder") |
| request start and end per (room, class, demand): start time, holder, answer or refusal, `Busy` until; refused start's `start_reason` | ADR-046 SY-15 rule 7, SY-24 | yes | yes (`note_start` gains the class and the reason) |
| named waits per (room, kind) with prerequisite | ADR-040 NW-3 | yes | yes |
| key install and fold application events (readability) | the channel | yes | yes |
| per node: every slot owner (a running exchange) and every permit owner (a received answer, from its send until its bytes are committed or discarded: in flight, awaiting its room's admission place, or awaiting `StoreRecovered(room)`) by name (room, peer, what, age); refused starts with `start_reason` (`budget_exhausted`, `cannot_save`, or none) | ADR-046 SY-24 | yes | yes |

The availability row's `unknown` state is what TR-2 row 12 prints as `locating the oldest with
<k> members` and TR-3 as `being located`; `waiting for a member` (TR-2 row 6, TR-19) needs every
source to be negative for the position, or no member reachable at all; an `unknown` connected
source routes to `locating`, never to the alarm (r7: S2).

## Requirements

Every proof below drives the shipped `vox` binary and asserts what a person reads (ADR-018). A
test-side server that answers the real daemon over the wire (an "apparatus holder") is allowed.
Every red names PRODUCT (quoting what the product printed) or APPARATUS. v0.4.30 reds marked
**KNOWN (files)** were read in the operator's saved files; **KNOWN (code)** means the field or verb
does not exist at the tag (a structural red, not a measured one); **unverified** means not run on
the release asset for this revision. A proof that stages a fault with a `VOX_TEST_*` knob builds
`vox` with the cargo feature `test-knobs`; the release asset holds none (AGENTS.md). No proof here
waits longer than 130 s; together they fit ADR-045's 8–10 hour gate, and every one of them is
stageable inside the macOS guest or the Linux VM (the decider, 2026-11-13, ledger row 32; no
proof here needs the host).

### 1. Each room says what it has verified, what it is missing, and what it rests on

- **TR-1. The node computes outcome measures, each from a named source with a named blind spot,
  in memory, bounded, from the observation contract and nothing else.** **(r4: F2, F6.)** For
  every open room the daemon MUST hold, per author A other than itself: `size_known`, `head_age`,
  `no_head`, `size_advertised` with its sources and whether it exceeds `size_known`, `anchor`,
  `control_held`, `control_applied`, `oldest_dependency` with what it waits for and
  `dependency_since`, the held body intervals at or above the anchor, `headers_without_text` and
  the admission time of the oldest, `wanted` as a count, `oldest_wanted`, `oldest_since`, byte
  progress on it, `unreadable` as a count with its cause and `unreadable_since`, `readable_rows`,
  `last_received_from(A)` as a feed author, the holders of `oldest_wanted` and of
  `oldest_dependency` (positive, possible, none; from inventories **and** the availability
  overlay, with the overlay's invalidations applied: a positive holder reverts to possible when its
  overlay for A is dropped) and the requests in flight for A; per source member M:
  `inventory_at(M)`, `last_received_from(M)` as a transport source, `last_sent_to(M)` (ADR-046
  SY-20), requests in flight toward M with age, refusals, negatives and `Busy`-until, `reach`
  (TR-19), what M says it holds of this node's feed (`held_through`, body-complete, from its
  inventory), and `last_request_from(M)`; per room: `last_entry`, per demand class
  `last_request_at`, the runnable demands and their eligibility edges, the missed-start age per
  class, the last refused start's `start_reason` (ADR-046 SY-24), the coverage, `older_not_held`;
  per node: each slot's owner (a running exchange) and each permit's owner (a received answer:
  `exchange in flight`, `answer awaiting admission` or `answer awaiting store recovery`, ADR-046
  SY-24's table) by name **(r10: no retained flows and no retirement ledger exist under the
  replacement; r11: R1)**. Every one
  of these MUST be in `vox status --json` under Appendix A's names, and the metrics endpoint MUST
  serve `vox_room_entries_behind{room}`, `vox_room_coverage_sources{room}`,
  `vox_room_last_entry_seconds{room}`, `vox_room_unreadable{room}` and
  `vox_member_entries_behind{room,member}`. Nothing here MAY write to the store (ADR-038 FX-29) or
  read it at publication.
  - *Sources and blind spots*: own holdings are exact and say nothing about what exists elsewhere;
    `size_known` is A's own signed word and may be stale (`head_age` says how stale); an inventory
    is a member's unsigned word and only tells the node where to ask; the coverage says how many
    members have spoken and how long ago. **No local computation can discover an unadvertised,
    unverified newer head**; every verdict is therefore "as of the heads verified" and TR-24 makes
    the text say so. `behind` and `unreadable` are exact because their inputs are local or signed;
    `size_advertised` is never added to either.
  - *Bounds*: the per-source inventory records are ADR-046's (`Have` retained per connected member:
    2,048 authors a room, 16 intervals an author). This ADR adds `inventory_at` to each and derives
    the per-author summaries from them at the fact's edge. An inventory entry for an author not
    admitted to the room is dropped; an inventory over the caps is `Malformed` (ADR-046 SY-12). A
    source that disconnects leaves the coverage after `INVENTORY_FRESH`; `wanted` does not change
    (it rests on `size_known`), its holder count does, so `waiting for a member` (TR-2) can become
    true without the gap vanishing. A larger advertisement from a source that then disconnects
    is forgotten with it: it was never counted.
  - *Cost*: every count is maintained where the fact changes (admission, body completion, expiry,
    `not for you`, fold application, an inventory update, an overlay install or drop, a `Head`
    answer, a connection change, a request start or end) as an O(1) update of a per-author
    summary; no renderer, publisher or notifier raises a request or re-verification of its own
    (r4: R1); publication reads the
    summaries, at most 2,048 per room, and reads nothing from disk; ADR-044 RD-4's row bound is for
    row walks, which this does not add. At open, the held intervals, `control_held`,
    `control_applied` and the anchor come from the store (ADR-046 SY-18, SY-3); `size_known` comes
    from the committed head (so `no_head` is false for authors with one); `inventory_at`,
    `last_entry`, `last_request_at` start empty and `head_age` reads `since the daemon started`,
    so a room after a restart reads `no inventory yet` (TR-24) until the first inventory, never
    `up to date`.
  - *Changes*: `SyncBook` gains the summaries above; the inventory acceptance path
    (`history_stream/client.rs:429`, `history_stream/server.rs:159`; under R2 the `Have` stream)
    stamps `inventory_at`; the `Head` acceptance (ADR-046 SY-13 rule 3) stamps `head_age`; the
    admission path that durably admits a complete body or applies a control entry sets
    `last_entry`, `last_received_from`, and advances `oldest_wanted`/`oldest_since`; the fold's
    application and key installation update `unreadable`; the scheduler's request start sets
    `last_request_at` per class. `RoomStatus` and `MemberStatus` gain the fields; JSON
    `holds_through` is renamed `headers_through`; `last_sync_ms` is renamed `last_round_ms`.
  - *Deleted*: `StatusBook::room_synced` and `member_synced` as anything a person reads; the DAG
    prefix as a measure of what is held; the daemon-wide `cleanup_errors` list in a node's status.
  - *Proof*: extends `vox_status_shows_the_node_proof.rs` with a third act. The guest's daemon is
    replaced by an apparatus holder that (i) answers `Head(A)` with A's **valid signed head** of
    size s (the apparatus holds A's key: it is the guest's stand-in), (ii) sends inventories naming
    held intervals covering `1..s`, and (iii) serves nothing for the wanted bodies. Within 70 s the
    host's `--json` has `entries_behind ≥ 1`, `coverage.sources == 1`, `size_known == s`, and the
    metrics endpoint serves `vox_room_entries_behind` equal to it. A **dishonest-inventory
    control**: the holder also advertises `(A, size = 1,000,000, head = random)`; `entries_behind`
    is unchanged, `size_advertised` shows 1,000,000 as `unverified`, and after the holder
    disconnects for `INVENTORY_FRESH` the advertisement is gone while `entries_behind` is not.
    v0.4.30 is red: the fields do not exist (KNOWN, code). Mutant A: `entries_behind` always 0;
    red, PRODUCT. Mutant B: add `size_advertised − size_known` to `entries_behind`; the control goes
    red (behind jumps by ~1,000,000), PRODUCT. Acceptance G49-3.

- **TR-24. A verdict says what it rests on; "up to date" is never said of an unverified
  frontier, and never reached by falling through.** **(r4: R1.)** The room line MUST name its
  coverage and the age of the heads it rests on, and the daemon MUST NOT compute `up to date`
  unless the room has at least one source and every author other than this node has an accepted
  head (`¬no_head`). A head's age is printed, never used as a guard: in a quiet room an unchanged
  signed head is as current as any member has said (ADR-046 SY-14 raises `Head` only for a new size
  or head), so `up to date as of its members' inventories (oldest <dur> ago); heads verified <h>
  ago` is the honest form and no re-observation is polled for. The forms, exactly:

  | State | Room line |
  |---|---|
  | no other member in the room | `only this node is in this room; holds <E> entries` (no coverage clause, no alarm, no `up to date`) |
  | no source, never had one since the room opened | `no inventory yet: joined <dur> ago, no member has said what it holds; <c> connected` |
  | no source now, had one before | `no inventory for <dur>: <c> members connected, none has said what it holds since <time>` |
  | sources `k` of `n`, `k < n` | `<verdict> as of <k> of <n> members' inventories (oldest <dur> ago); heads verified <h> ago; <n−k> not heard from` |
  | sources `k = n` | `<verdict> as of all <n> members' inventories (oldest <dur> ago); heads verified <h> ago` |

  where `<verdict>` is TR-2's and `<h>` is the oldest `head_age` among authors (after a restart,
  the committed heads count as verified at the open: `<h>` is `since the daemon started` until a
  `Head` answer arrives). A brand-new joiner whose join answer carried the inviter's signed heads
  (ADR-046 SY-17) has `size_known` for every author at once and MUST read `catching up` or
  `checking` (TR-2) on its first status, never `up to date`; a joiner whose join answer was
  internally complete and left nothing wanted reads TR-2's `checking: only 1 of <n> members has
  said what it holds` until a second source's inventory arrives or `INVENTORY_FRESH` passes with
  one source, then TR-2's verdict `as of 1 of <n>`. A node whose every peer is silent for
  `INVENTORY_FRESH` while at least one is connected is unhealthy (TR-25's first key).
  - *Why*: finding 2 and F1: a newcomer, a starved node or a pair of mutually stale replicas must
    never read "up to date"; and a relative verdict must say its relativity in the line.
  - *Changes*: `status_cli.rs` room rendering; `RoomStatus::coverage { sources, members, oldest_ms,
    heads_oldest_ms }`.
  - *Proof*: extends `a_newcomer_reads_the_whole_history_proof.rs`: (act N1) a newcomer joins
    through a member that is an apparatus holder answering the join with signed heads and
    inventories and nothing else; the newcomer's first `vox status` within 5 s reads `catching up`
    and `as of 1 of <n> members' inventories`, and never contains `up to date` until the real
    members serve it. (Act N2, mutual staleness) two real members are isolated from the rest for
    120 s; each reads `as of 1 of <n> members' inventories`, `heads verified` and `<n−1> not heard
    from`, never `as of all`. (Act N3, stale complete join) the holder's join answer leaves nothing
    wanted; the newcomer reads `checking: only 1 of <n> members has said what it holds` and never
    `up to date` within 90 s. (Act N4, quiet room, r4: R1) two real members, both current, idle for
    180 s: each reads `up to date as of all 1 members' inventories (oldest <≤ 30>s ago); heads
    verified <≥ 180>s ago` at every sample, no `checking`, no alarm. (Act N5, restart) one member's
    daemon is restarted in the quiet room; within 10 s of Ready its status reads `no inventory yet`
    then, after the first inventory, `up to date … heads verified since the daemon started`, never
    `checking` on the head's age. v0.4.30 is red on N1–N3 (KNOWN, code); N4 and N5 are controls.
    Mutant A: treat `behind = 0` as `up to date as of all`; N2 and N3 go red, PRODUCT. Mutant B: guard
    `up to date` on `head_age < 90 s`; N4 goes red (`checking` after 90 s of quiet), PRODUCT.
    Acceptance G49-9.

- **TR-2. The room line starts with a verdict from a total table: one base verdict for every
  state, an alarm verdict in its place when an alarm holds.** **(r4: R1, F2.)** `vox status` MUST
  print each room the node holds as:

  ```
    <room id> <name>  <verdict line>
      holds <E> log entries (<R> readable rows); older history not here: <O> entries, fetched on request
      trust checked and applied through every member's head | trust to check: <m> members (<ids>) | trust held, pending application: <m'> members (<ids>: waits for <what>)
      sender keys: <K> own generation(s), <k> received; epoch <n>; render backfill <idle|pending>
      messages: <retention>; Session steps: <retention>
  ```

  where `<verdict line>` is the first row of this table whose condition holds. Rows 1–5 are
  lifecycle; row 6 is the needed-holder alarm (r6: E1), which precedes coverage because it rests on
  known holdings, not on live coverage; row 7 is coverage; rows 8–11 are alarms (each needs its
  patience to pass, and prints in place of the base verdict); rows 12–14 are the base verdicts, and
  their conditions partition every
  remaining state, so no state falls through:

  | # | Verdict | Condition |
  |---|---|---|
  | 1 | `ended: its creator or an admin ended it; deleting` + (`, waits until <edge words>, for <dur>` when ADR-049's deletion is parked) | the room is ended. No other verdict and no sync alarm MAY be raised for it. |
  | 2 | `leaving: …` (ADR-049's line, formerly ADR-040 NW-6, unchanged) | the room is being left |
  | 3 | `preparing: …` (TR-8) | the room is preparing |
  | 4 | `cannot save: <os words>` (ADR-034 SR-2, unchanged) | the room is marked unable to save |
  | 5 | `only this node is in this room; holds <E> entries` | no other member |
  | 6 | `waiting for a member: <N> entries behind; no member is reachable (<id>: offline, last seen <dur> ago; <id>: not attached at <addr>); who still holds them is not known` or `…; <A>@<p> was last advertised by <id> <age> ago (now <reach>); every reachable member says it does not hold it` + (`; no inventory for <dur>` or `; no inventory yet` when the room has no source) | TR-19's `waiting-for-member` predicate, either branch (r7: S1, S2; ruled: Q5); key `waiting-for-member:<room>:<member>` under `UNHEALTHY:` |
  | 7 | TR-24's `no inventory …` forms | no source, and row 6 does not hold |
  | 8 | `NOT ASKING: <N> entries wanted from <h> members that hold them; no request started for <dur>; <reason clause>` | TR-25's second condition |
  | 9 | `NOT RECEIVING: <N> entries behind; <what> not delivered for <dur> though <h> members that hold it are connected` | TR-4 (`<what>` is `<A>@<p>` for a body; for a dependency of kind (i) `<A>'s trust not checked through positions <p>–<q>` and of kind (ii) `<A>'s trust entry <p> (held; waits for <context <hash>|parent header <position>|the fold>)`; never "trust entry" for an unchecked range) |
  | 10 | `cannot read <m> members' posts: <u> entries held here are unreadable (<cause>) for <dur>` | TR-5's unreadable condition |
  | 11 | `NOT HEARD FROM` | TR-25's first condition (printed by row 7's form with the alarm word) |
  | 12 | `catching up: <parts>; last entry <dur> ago` (+ `; receiving <A>@<p>: <x> of <y> KiB` on byte progress), `<parts>` being those that apply of `<N> entries behind`, `<u> held, not yet readable (<cause>)`, `trust to check for <m> members`, `trust held for <m'> members, waiting for <what>`, `locating the oldest with <k> members`, `waiting for a member that can prove <A>'s head from size <s>, or <A> itself` | `behind > 0`, or `unreadable > 0`, or some author not control current with an accepted head, or some author has an observed newer head whose bridge no connected member can prove (ADR-046 SY-13 rule 3; the known size is unchanged and nothing is promoted) **(r11)** |
  | 13 | `checking: <parts>`, `<parts>` being those that apply of `no head of <m''> members verified yet`, `only <k> of <n> members has said what it holds (joined <dur> ago)` | nothing of row 12 applies, and some author has `no_head`, or TR-24's single-source join case |
  | 14 | `up to date` | `behind = 0`, `unreadable = 0`, every author control current (so `¬no_head`), and not row 13's join case |

  Row 12's `<cause>` is TR-5's; row 12 is a base verdict and raises no alarm by itself: a held
  key-blocked entry ten seconds old, a trust range not yet checked, a held control entry waiting
  for its context, each reads `catching up` with its part named, and becomes TR-4's or TR-5's alarm
  only when its own clock (`dependency_since`, `unreadable_since`, `oldest_since`) passes
  `RECEIVE_PATIENCE` with a holder connected. A verified head's age never moves a room between rows.

  followed by TR-24's coverage clause. `<N>` is exact (Terms). The second detail row prints `trust
  to check: <m> members` when some author has trust to check and `trust held, pending application`
  when some held control entry is not applied; both are coverage, never "behind". The `older
  history` clause is printed only when `<O> > 0`. Appendix B shows the lines for the four incidents.
  - *Changes*: `status_cli.rs` room rendering; the `sync, per room and peer` block moves to `vox
    status --sync` (ruled: Q2).
  - *Deleted*: `last sync <dur>` from the text; `room-stale`; the "governance revision" row as a
    comparison (the revision is local and means nothing across nodes: it stays in JSON only).
  - *Proof*: TR-1's third act: within 70 s the host's room line reads `NOT RECEIVING: ` followed
    by a count ≥ 1 and `as of 1 of 1 members' inventories`; after the real guest returns and the
    host renders its post, within 10 s the line reads `up to date as of all 1 members' inventories`
    and `last entry` under 10 s. (Totality act, r4: R1) with the real guest, the apparatus holder
    of TR-5's third half withholds one sender key for 20 s then serves it: every status sample in
    those 20 s reads `catching up: 1 held, not yet readable (its sender key for them has not
    arrived …)` and never `up to date`, and no `UNHEALTHY` line; with a control range withheld for
    20 s: `catching up: trust to check for 1 members`. v0.4.30 is red: it prints `last sync 0s
    ago` (KNOWN, files). Mutant A: compute the verdict from the last completed round; the line
    reads `up to date` while the apparatus withholds; red, PRODUCT. Mutant B: drop row 12's
    `unreadable > 0` and trust parts; the totality act reads `up to date` at 10 s; red, PRODUCT.
    The ended precedence is proved in ADR-049's end journey (TR-23). Acceptance G49-2.

- **TR-3. A member line says what this node has verified of that member, what it last did, and
  whether it is asking.** **(r3: F1, F4, F6; item 87.)** `vox status` MUST print each member as:

  ```
      <member id>  <trust>  <reach>  inventory <dur> ago | no inventory yet; head verified <dur> ago | no head verified; last entry from it <dur> ago | never
        its feed: <S> entries verified (advertised, unverified: <k> more by <member>); <feed state>
        it holds this node's feed through <F>; it is <B'> behind this node and has asked for nothing for <dur>
  ```

  `<trust>` is `trusted` or `not in keyring`. `<reach>` is TR-19's. `<feed state>` is one of `up to
  date here`; `<B> behind here` (+ `, <M> of them held without their text (oldest <dur>)`);
  `<B> behind here; oldest <p> held by <k> members | by no connected member | being located`;
  `<u> entries here cannot be read: <cause>` (TR-5's causes); `two signed heads at <s>: fork`
  (ADR-046 SY-13 rule 2); `advertisements disagree at <s>; asking for its head`. The third line
  prints `it holds …` when the member's inventory reports it (body-complete positions of this
  node's feed), and the `it is <B'> behind this node and has asked for nothing for <dur>` clause only
  when, by its inventory, the member lacks positions this node holds and this node has received no
  request from it for `ASK_PATIENCE` while connected: a stalled member (item 87, vovando) as seen
  from a healthy one. This node's own line is `<id>  (this node)  its feed: <S> entries`.
  - *Deleted*: `last sync`, `last seen` for a connected member, `this node holds their room feed
    through N`.
  - *Proof*: TR-5's staging asserts `behind here, ` and `held without their text`; TR-25's
    second act asserts `has asked for nothing for` on the healthy sibling; TR-1's control asserts
    `advertised by`, `unverified`. Mutant: count a header without a body as held; red, PRODUCT.
    Acceptance G49-4.

- **TR-4. A room whose oldest wanted entry or oldest unresolved trust dependency has a connected
  holder and is not resolved for `RECEIVE_PATIENCE` is unhealthy; delivery means complete entries
  or an advance of `control_held`/`control_applied` past the dependency, never rounds, proofs,
  headers, chunks or coverage elsewhere.** **(r5: D1; r9: precedence with TR-5.)** An author A is
  **stuck** when either its stuck age (`now − oldest_since(A)`, `oldest_wanted` with a positive
  holder, no byte progress) or its dependency age (`now − dependency_since(A)`,
  `oldest_dependency` with a positive holder of its kind, or waiting on the fold) is at least
  `RECEIVE_PATIENCE`; each author's clock is its own and deliveries of other authors never move
  it. TR-4 is the **room** form: it holds when **every** author of the room that has an unresolved
  obligation with a positive holder is stuck (nothing any member serves is arriving; a room with
  one such author included), and TR-25 does not hold. TR-5's not-arriving form is the **member**
  form: some authors are stuck while at least one other author with an obligation is not (its
  deliveries arrive). Exactly one of the two holds for a stuck author at any check, so both lines
  are reachable. While TR-4 holds, `vox status` MUST print under `UNHEALTHY:`
  `! room <id> (<name>): NOT RECEIVING: <N> entries behind; <what> not delivered for <dur> though <h> members that hold it are connected (<r> requests in flight for it, oldest <dur>; last answer from <id>: <refusal or 'nothing'>)`
  with `<what>` TR-2 row 8's: an unchecked range is printed as `<A>'s trust not checked through
  positions <p>–<q>` (it may contain no control entry at all; a proof of absence resolves it and
  counts as progress, not as an entry delivered), and only a held control entry is named `<A>'s
  trust entry <p>`; the recovery notice for a resolved range says `room <name> is receiving again:
  <A>'s trust checked through <q>`. Key `room-not-receiving:<room>`; the notifier MUST raise it once
  (PRD-001 R37). While it holds, `healthy:` MUST NOT be printed. The condition MUST be unaffected by
  proofs verified, headers admitted without bodies, inventories, heartbeats, coverage growth that
  does not pass the named dependency, deliveries of other positions or authors, or completed
  rounds. It MUST clear at the first status check (5 s) after the named `<what>` is delivered,
  resolved, expires or becomes `not for you` and no other author meets the condition; the
  "recovered" notice MUST say `room <name> is receiving again: <n> entries delivered`. While
  `<A>@<p>` has byte progress the room line reads `catching up … receiving <A>@<p>: <x> of <y>
  KiB` and no alarm is raised. **(r10)** There is no flow-state pool under the replacement
  (ADR-046 SY-19); the line names its cause in its own clauses and never `flow-state pool`
  (ADR-038 FX-35, amended below).
  - *Why*: items 49 and 51; findings 1 and F2: the clock is the oldest unresolved position's or
    dependency's own; a `ControlRange` stream that answers without passing the dependency is not
    progress.
  - *Changes*: `diagnose` on TR-1's per-author summaries.
  - *Deleted*: `room-stale`, `STALE_SYNC_MS`, `stale_words`, the `started` epochs
    (`StatusBook::started`, `StatusReport::started`, `status.rs:93, 295`) and their use at
    `status.rs:384`; the stale form of `RETAINED_POOL_HEALTH`. In proofs: the `last_sync_ms`
    assertions of the quiet-room journey (ADR-038 FX-16) in
    `a_newcomer_reads_the_whole_history_proof.rs` (`:8700, 9021-9025, 9410-9415`) become
    `verdict == "up_to_date"` with `coverage.sources == coverage.members`; the #84 assertion that
    `vox_status_shows_the_node_proof.rs` lists "its last sync" is replaced by TR-2's.
  - *Proof*: TR-1's third act, with the apparatus holder made busy: beside withholding A@p (the
    oldest wanted position) it answers every exchange with a fresh inventory and heartbeat, serves
    a new valid signed head of A every 10 s (A keeps posting), serves the bodies of those newer
    positions, serves valid control proofs that advance `control_held` past them, and serves
    one header without body every 5 s. Within 70 s the host prints the `NOT RECEIVING` line naming
    `<A>@<p>` under `UNHEALTHY:` and no `healthy:` line; `--json .unhealthy[].key` holds
    `room-not-receiving:<room>`; the line stays through 60 more seconds of that work; after the
    holder serves A@p, the line is gone within 10 s of the host rendering it and the recovery
    notice names the count. A byte-progress control: the holder serves A@p's 12 MiB body at 64
    KiB per 5 s; the room line reads `receiving <A>@<p>:` and no alarm is raised in 120 s. A
    **dependency act** (r5: D1): the holder serves every body and withholds the `ControlRange`
    answer for positions c–d below the host's anchor, answering ranges above d promptly (its
    inventory's `control_through` names d); within 70 s the line reads `NOT RECEIVING: 0 entries
    behind; <A>'s trust not checked through positions c–d not delivered for …` and never `trust
    entry`; a **no-control-in-range control**: the holder then answers c–d with a proof of absence
    (no control entry there); within 10 s the line is gone, the recovery notice reads `trust
    checked through d`, and `last_entry` has not moved; a second half serves c's header (a control
    entry) but withholds the context it names: `<A>'s trust entry c (held; waits for context
    <hash>)`. The host joins late (after the guest has more than 128 entries), so older history
    alone does not raise it **(r10: the sentence cut in r5 restored)**.
    v0.4.30 is red on the first assertion (KNOWN, files). Mutant A: `RECEIVE_PATIENCE = u64::MAX`;
    red, PRODUCT. Mutant B: reset `oldest_since` on any delivery of A; the line clears during the
    60 s of newer deliveries; red, PRODUCT. Mutant C: count a chunk as a delivery; the
    byte-progress control shows `last entry 2s ago` while A@p is incomplete; red, PRODUCT. Mutant
    D: reset `dependency_since` on any `ControlRange` answer; the dependency act never alarms; red,
    PRODUCT. An apparatus holder not reached is APPARATUS. Acceptance G49-1.

- **TR-5. One author whose entries do not arrive, or whose entries are here and cannot be read,
  is unhealthy even while others arrive.** **(r3: F3.)** Two conditions, one key
  `member-unreadable:<room>:<member>`:
  - *not arriving* **(r9)**: author A is stuck (TR-4's definition) and TR-4's room form does not
    hold because at least one other author with an obligation is not stuck (the room delivers):
    `! room <id> (<name>): <member id> is <B> behind here (<M> held without their text, oldest <dur>); <A>@<p> not delivered for <dur>`;
  - *unreadable*: `unreadable(A) > 0` for `RECEIVE_PATIENCE` since `unreadable_since(A)`:
    `! room <id> (<name>): <u> entries of <member id> are here and cannot be read for <dur>: <cause>`,
    where `<cause>` is exactly one of `its sender key for them has not arrived (its consent for this
    node is applied)`, `its consent for this node is not among its trust entries checked through
    <control_applied>`, `its trust entries are held and not yet applied (waiting for <ADR-040 NW-1
    prerequisite words>)`. The room verdict then reads TR-2's `cannot read` row and `up to date` and
    `healthy:` are impossible while it holds; before the patience passes the room reads TR-2 row
    12's `<u> held, not yet readable (<cause>)` (r4: R1).
  - *Why*: item 49, the Mac's half; F3: every body and consent held and the key missing is the
    rebuilt omp-io's shape (`newnode-progress-222537Z.txt`: 4 key generations received, 0 rows;
    which cause applied there is not derivable from the file).
  - *Changes*: `diagnose`; the fold and key installation update `unreadable`.
  - *Proof*: TR-1's third act, second half: the apparatus holder serves headers with inclusion for
    A and refuses every body; another real member keeps posting so the room delivers; within 70 s
    the host prints the not-arriving line. A third half: the holder serves A's bodies and control
    entries including A's consent for the host, and withholds A's sender-key package for the host
    (the key package is addressed to the host and never sent); within 70 s the line reads `cannot
    be read for … its sender key for them has not arrived`, the room line `cannot read 1 members'
    posts`, and no `healthy:`; after the key arrives the lines clear within 10 s. A fourth half:
    the holder withholds A's consent control entry above `control_held`, the entries above are
    checked and applied (`control_applied = control_held = p`); the cause reads `its consent for
    this node is not among its trust entries checked through p` **(r9)**. v0.4.30 is red on the third (KNOWN,
    files: `entries 0` with `received_key_generations 4` and no alarm). Mutant A: count a header
    without a body as readable; the second half goes red, PRODUCT. Mutant B: `unreadable` never
    counted; the third half shows `up to date`; red, PRODUCT. Acceptance G49-5.

- **TR-25. A node with runnable demand that asks nobody is unhealthy, with the scheduler's own
  reason; and so is a node no member tells anything.** **(r4: R3, R4; item 85 KNOWN.)**
  - When at least one member has been connected for `INVENTORY_FRESH` since the node's last network
    change or wake, and no inventory or heartbeat has arrived from any member in that time, `vox
    status` MUST print under `UNHEALTHY:`
    `! room <id> (<name>): NOT HEARD FROM: <c> members connected, none has sent its inventory for <dur>`
    with key `room-no-inventory:<room>` (the observation contract's heartbeat row, required under
    either mechanism by ruling: there is no variant without it).
  - When the sync class's missed-start age in the room (Terms: `now − max(oldest eligibility edge
    of its runnable demands, the class's latest request start in the room)`, while some demand of
    the class is runnable and none of the class is in flight) is at least `ASK_PATIENCE`,
    `vox status` MUST print
    `! room <id> (<name>): NOT ASKING: <N> entries wanted from <h> members that hold them; this node has started no request for them for <dur>; <reason clause>`
    with key `room-not-asking:<room>`, `<dur>` being the missed-start age. One old start of the
    class delays the alarm by at most `ASK_PATIENCE` and never prevents it (r4: R3). The reason
    clause MUST be the scheduler's recorded refusal (ADR-046 SY-24's `start_reason`), rendered
    **(r10: the replacement's reasons only; r11: R1, R2)**: `budget_exhausted` → `its serving
    budget is spent; it retries when a permit is released` (a permit is held by a received answer
    until its bytes are committed or discarded, not until the exchange ends); `cannot_save` is
    recorded but never rendered here: a demand refused for it is parked on `StoreRecovery(room)`
    (ADR-040 NW-2, ADR-046 SY-24), a named wait, so it is not runnable and never enters the
    missed-start age; it is shown in `--json .rooms[].last_start_refusal` and by the doctor's
    cannot-save line below; a refusal ADR-046 has no name for, or none recorded →
    `Vox recorded no reason; this is a fault in Vox, not something you did; keep \`vox status
    --json\` for the report`. A `Busy` holder, a
    negative, a probe in flight or a named wait (ADR-040 NW-1) make the demand not runnable and
    MUST NOT lead here; a key-class request MUST NOT move the sync class's clock.
  - `vox agent doctor` MUST print the same as `fail  room <name>: this node is not asking its
    members for the <N> entries it lacks (no request for <dur>): <reason clause>` with `fix:
    nothing to change on any other computer; keep \`vox status --json\` for the report` **(r10:
    the doctor names no restart; the one cause a restart cured, v0.4.30's retained-flow cap, does
    not exist under the replacement)**. A room that cannot save is a separate doctor line **(r11:
    R2)**: `fail  room <name>: cannot save: <ADR-047's words, SO-11's floor form or SO-12's
    recovering or deferred form>` with a fix conditional on the recorded cause: for the floor or
    a deferred operation (`last_start_refusal.cause` = `floor` or `deferred`), `fix: free <n> MB
    on the disk holding <dir>; Vox continues by itself`; for a recovering store (`cause` =
    `recovering`), `fix: nothing; Vox recovers the store by itself (<SO-12's state words>)`. The
    agent notice
    MUST say `this room is stuck on this node (not asking its members): <reason clause>; tell the
    operator; do not conclude anything about trust`.
  - `vox status` MUST print, per node, `sync slots: <s> in use (<owners by name>); permits: <p> of
    <limit> MiB (<owners by name, each with its state: exchange in flight | answer awaiting
    admission | answer awaiting store recovery>)` **(r10; r11: R1)**: a slot's owner is a running
    exchange; a permit's owner is a received answer until its bytes are committed or discarded
    (ADR-046 SY-24's byte accounting, 1 MiB per in-flight answer, 64 MiB per node, 8 MiB retained
    per room); the daemon-wide `cleanup_errors` list of v0.4.30 is gone with the retirement
    ledger. The watchdog MUST NOT restart anything (TR-13).
  - *Why*: incident (d); F5: a room-wide clock would have been refreshed by the Private starts
    at 02:11–02:15Z and would alarm on a quiet room's first new post before the scheduler had its
    first chance; F6: `NotHeld` and probes are waits, not neglect.
  - *Changes*: `diagnose`; `doctor.rs`; `agent_hook.rs`; the scheduler stamps `last_request_at`
    per class and `start_reason` (ADR-046 SY-15 rule 7, SY-24); `status.rs` splits the ledger by
    actor.
  - *What `NOT ASKING` rests on under the replacement* **(r9; r10)**: the decider chose the
    replacement (ledger row 57), which has no flow pool and no retained flow; v0.4.30's
    `retained_flows_full` and `retirement_failed` have no counterpart and no words here. The
    condition is exactly the Terms' missed-start
    age on runnable sync-class demand with nothing in flight, and the reason clause is SY-24's
    recorded refusal: `budget_exhausted` → `its serving budget is spent; it retries when a permit
    is released`; none recorded → `Vox recorded no reason; this is a fault in Vox, not something
    you did; keep \`vox status --json\` for the report`. `cannot_save` never reaches `NOT
    ASKING` (the demand is parked, above) **(r11: R2)**.
  - *Proof* **(r9)**: extends `a_sync_failure_names_its_reason_proof.rs`. The v0.4.30 red is
    RcaSchedStall's baseline staging (`exp2.log`, `A-stalled.json`: 11 retained Public flows,
    every port queued with no reason, posts never shown; receipt lost in the reboot of
    2026-11-13; figure recorded in `rca-RcaSchedStall.md`; to be re-run as the fleet
    baseline, ADR-045 J10(a) holding it as the baseline receipt only); the candidate cannot
    reproduce that state and is not asked to. The positive rendering is proven twice: (a) the **start-once-then-stop control**
    (r4: R3): under `test-knobs`, `VOX_TEST_SYNC_STARTS_BUDGET_FILE=<path>`; the budget is read
    when the file appears (activation after staging), counts only `Range`/`ControlRange` starts
    (prerequisite requests `Head`/`Context`/`Probe` are not charged) and caps each charged
    `Range` at one position **(r11: R3; r12: F1)**. **The knob is a barrier from the daemon's
    start**: while the variable is set and the file is absent the charged budget is zero, so no
    `Range`/`ControlRange` starts (SY-15 rule 6's passes still run and still start prerequisite
    requests; a charged start is refused without recording a reason, the stall this control
    imitates); when the file appears its count is the budget, read once. Staging: A and B
    current and quiet (control current on both); A's daemon is stopped; B posts three 1 KiB
    entries; A is started with the variable set and no file: A's `Head` runs and accepts B's head
    of size s + 3, so three body positions are wanted under one accepted head with one
    eligibility edge, and nothing charged can have started (asserted before activation, from the
    common contract's two classes only **(r13: G1)**: `entries_behind == 3`, `oldest_since` set,
    `in_flight` empty, `last_request_at_ms.sync` equal to the completed `Head`'s start (the latest
    sync-class start is that `Head`), the knob's counter file absent, that is no charged start
    was ever released); the file is then written with `1`, which is the activation and the
    release of exactly one capped `Range` in one step; that `Range` delivers exactly the oldest
    post (asserted: that row `rendered` on A, `entries_behind == 2`, `in_flight` empty, the
    knob's counter file reads 1, and `last_request_at_ms.sync` now equal to that `Range`'s
    start); nothing further is posted, so no later `Head` or other
    sync-class start occurs; the two remaining demands keep their original edge; within 35 s of
    that one `Range` start A's status prints `NOT ASKING: 2 entries wanted from 1 members …; this
    node has started no request for them for <dur>; Vox recorded no reason …` with `<dur>`
    counted from the `Range` start (the latest sync-class start, later than the edge), the doctor
    its `fail` line, and B's status A's member line with `has asked for nothing for`; a knob or
    staging failure (`entries_behind` ≠ 3 or `in_flight` non-empty before activation, counter ≠ 1
    after) is APPARATUS, and the barrier makes it a defect of the knob, not a lost race; mutant
    D's surviving pre-start demands are the two unrequested positions; (b) the
    **`cannot_save` act** **(r10; r11: R2)**: A's data on ADR-047 SO-11's apparatus (the guest's
    256 MB APFS image, or the Linux VM's size-bounded tmpfs), filled past the floor; B posts;
    A's start is refused with `cannot_save` and the demand is parked on `StoreRecovery(room)`;
    the assertions are `--json .rooms[].last_start_refusal == {reason: "cannot_save", cause:
    "floor"}`, `.waiting[]` naming the room's `StoreRecovery` wait, no `room-not-asking` key for
    90 s (the parked demand is not runnable), the room line `cannot save: the disk holding <dir>
    has <m> MB free; Vox keeps <floor> MB free. It saves again by itself when space is freed.`
    (SO-11's words), and the doctor's `fail  room <name>: cannot save: …` with `fix: free <n> MB
    on the disk holding <dir>; Vox continues by itself`; space is freed; the post shows within
    30 s, the refusal and the wait are gone, and no `NOT ASKING` was ever printed. Mutant F:
    treat a `StoreRecovery`-parked demand as runnable; `NOT ASKING` prints during the act; red,
    PRODUCT. A quiet-to-first-post control: after 120 s of quiet, B
    posts once; A's status never shows `NOT ASKING` and shows the post within 10 s. A `NotHeld`
    control: the apparatus holder of TR-1 advertises an interval and answers `NotHeld` for it;
    A's line reads `catching up: … locating` or `waiting for a member`, never `NOT ASKING`, for
    90 s.
    v0.4.30 is red (KNOWN, files: `stall-robert-work-021627Z.json` has only `room-stale`;
    receipts `A-stalled-10min.json`; and KNOWN, code: no `NOT ASKING` exists). Mutant A:
    `ASK_PATIENCE = u64::MAX`; red,
    PRODUCT. Mutant B: one clock for both classes; a key-class start during the stall clears it;
    red, PRODUCT. Mutant C: count a negative holder as positive; the `NotHeld` control goes red,
    PRODUCT. Mutant D: require no start since the eligibility edge (revision 3's predicate); the
    start-once control never alarms; red, PRODUCT. The `NOT HEARD FROM` act: the apparatus holder
    stays connected and sends no inventory; within 100 s the line appears; a reconnect control:
    the holder reconnects after 95 s away and sends its inventory 20 s later; no line (the whole
    act stays under 130 s) **(r9)**; the v0.4.30 red of the first act (`A-stalled-10min.json`):
    receipt lost in the reboot of 2026-11-13; figure recorded in `rca-RcaSchedStall.md`;
    to be re-run as the fleet baseline **(r10)**;
    mutant `INVENTORY_FRESH = u64::MAX`; red, PRODUCT. Acceptance G85-1.

- **TR-6. "sync failing" measures the transport, and only the transport.** (unchanged in r3; the
  review record's wording corrected.) A port's failure streak (`consecutive_failures`,
  `failing_since`) MUST be reset by any authenticated answer from the peer (an inventory, a
  `Done`, a `Refuse{Busy|NotHeld}`, a served request), including one that brought nothing; the
  network-change (`actor.rs:10386`) and port-retirement (`actor.rs:16815`) sites keep clearing the
  backoff and stop clearing the streak. Whether the room receives is TR-4's question. `sync-failing`
  MUST NOT be raised for an ended room (ADR-049) and MUST NOT be raised against a member that is not
  connected (that is `reach`, TR-19).
  - *Proof* **(r10)**: extends `a_sync_failure_names_its_reason_proof.rs` (`:396-426`): (act 1)
    Bob is replaced by an apparatus holder that first **resets two consecutive streams** (seeding
    `consecutive_failures = 2`; `sync failing: transport failed` is asserted within 35 s) and then
    answers every other exchange with `Refuse{Busy, 1 s}` and the rest with an empty inventory;
    within 10 s of the first answer Alice's `vox status` shows no `sync failing` and the room
    reads `up to date` for the next 60 s; (act 2) the holder resets every stream for 40 s, then
    answers; `sync failing: transport failed` appears within 40 s and is gone within 10 s of the
    first answer. v0.4.30: act 1 green, act 2 green (controls); the change is a narrowing, so its
    red is revision 1's mutant: reset only on a fetching round; act 1's `sync failing` never
    clears; red, PRODUCT. *Deleted*: the journey's existing assertion that a killed or
    disconnected Bob keeps showing `sync failing` (he is `offline, last seen <dur> ago`, TR-19,
    and the streak ends with the connection). Acceptance G49-6.

- **TR-7. The room's own commands say it too.** When a room's verdict is not `up to date`, `vox
  room read` MUST print, before its rows, `this room is <verdict line>` (TR-2's words with TR-24's
  clause), and `vox room list` MUST print the verdict after the room's name, with an ended room
  keeping `[ended: its creator or an admin ended it]`.
  - *Proof*: TR-1's third act: `vox room read` begins `this room is NOT RECEIVING` and `vox room
    list` shows `NOT RECEIVING`; in TR-24's act N1 `vox room read` begins `this room is catching up`
    and contains `as of 1 of` **(r9)**. Mutant: omit the notice; red, PRODUCT. Acceptance G49-7.

### 2. Every room is listed; the keyring is a fact

- **TR-8. `vox status` lists every room the node holds.** **(r5: Q1.)** The `rooms` block MUST
  list open rooms (TR-2), preparing rooms, leaving rooms and ended rooms. A preparing room MUST
  print `  <room id> <name>  preparing: <what it waits for>, <done> of <total> rows, for <dur>`
  (`<what>` from ADR-044's preparation report; a proof reconstruction prints RD-9's `rebuilding
  history evidence from its canonical ranges`; **(r11)** no line names a pending flush, a token
  or a settlement: ADR-044 r14 flushes once per ruled save, and a save whose commit failed is
  answered `could not be confirmed`, the words any status or doctor line uses for it); a leaving room prints ADR-049's line unchanged; an ended room prints TR-2's
  ended line. There is no "repairing" form in v0.4.31 (ruling Q1).
  - *Proof* **(r9)**: extends `the_daemon_and_its_nodes_proof.rs`: after a restart with at least
    2,000 Session rows, the preparation is held at its first turn by the `test-knobs` knob
    `VOX_TEST_HOLD_PREPARATION=<room>` (owned by this ADR: the room's preparation turn parks until
    a file appears; ADR-044 RD-11 supplies progress and a fast open, no hold); while held, `vox
    status` text has the room with `preparing: ` and `--json .preparing` is non-empty; after the
    release, the room is under its TR-2 verdict within 5 s and `.preparing` is empty. RD-7's and
    RD-9's words are asserted in ADR-044's own journeys (RD-7's durability wait, RD-9's
    reconstruction) once those land, and the leaving line in ADR-049's leave journey; this proof
    depends on them for those words only. v0.4.30 is red: the room is absent (KNOWN, code).
    Mutant: skip the preparing rows; red, PRODUCT. Acceptance G51-1.

- **TR-9. The keyring is a fact row, never next to health.** `vox status` MUST print, directly
  after the `daemon log:` line and before any anchor line, `keyring: locked; a trust change will
  ask for your passphrase` or `keyring: open, <m>m left`. The TUI status bar and the app's
  menu-bar extra keep ADR-028 K-9's form.
  - *Proof*: extends `a_keyring_change_needs_a_recent_passphrase_proof.rs`: its three assertions on
    the old label (`:251, 581, 700`) become assertions on the new row, whose line index is the
    `daemon log:` line's plus one, while `UNHEALTHY:`/`healthy:` comes after the anchor lines
    (Appendix C). Mutant: the old label; red, PRODUCT. Acceptance G51-2.

### 3. A trust decision is reported as of what this node has verified, and never with an action on this evidence alone

- **TR-10. Every trust verdict is as-of the author's accepted head and the trust checked and
  applied here; "has not trusted you" with a fix only when the author itself has just said so.**
  **(r4: F4.)** The daemon answers `MemberConsents` per member A with one of three states, each
  carrying `as_of = control_applied(A)`, `checked = control_held(A)`, `size_known(A)`,
  `head_age(A)`, `head_from` (A itself, or a relay), `connected(A)`, `key_held`:
  - `Trusts`: an applied consent for this node is in A's control entries through `as_of`;
  - `HasNotTrusted`: `control_current(A)` (every control entry of A through `size_known(A)` is
    held and applied) and no consent for this node is among them;
  - `CannotTellYet`: otherwise, with its kind: `Unchecked { through: control_held, of: size_known }`
    (trust to check remains), `Pending { through: control_applied, held: control_held, waits_for }`
    (held control entries not yet applied), or `NoHead` (no head of A accepted yet).

  Every surface renders them with these words; the **fix line is printed only when `head_from` is
  A itself and `head_age(A)` < `INVENTORY_FRESH`** (A is connected and has just signed that head):

  | Surface | Trusts | Has not trusted | Cannot tell yet |
  |---|---|---|---|
  | `vox agent doctor` | `ok    trust <name>: you trust each other (as of its entry <s>)` | `warn  trust <name>: you trust it, but as of its entry <s> (verified <dur> ago from <itself|member X>) it had not trusted you: it cannot read you` + fix only when A itself just said so: today's `fix: on the computer hosting node …`; otherwise `fix: none yet: this is as of <dur> ago; Vox asks it again when it is connected` | `warn  trust <name>: you trust it; this node cannot yet tell whether it trusts you` + one of `: its trust is not checked through positions <through+1>–<of> yet` (Unchecked), `: its trust entries through <held> are held here and not yet applied (waits for <what>)` (Pending), `: none of its entries has been verified here yet` (NoHead) + `fix: nothing: do not change trust on this evidence; vox status says whether this room is receiving` |
  | `vox room members` (its trust column also shows `trusted` / `not trusted` as this node's keyring says, ADR-048 TC-8, X048-9 **(r10)**) | `it trusts you (as of its entry <s>)` | `as of its entry <s>, it had not trusted you` | `cannot tell yet whether it trusts you` + the same clause |
  | joined notice to agents | `reads you as of its entry <s>; you read it` | `does not read you as of its entry <s>` | `cannot tell yet whether it reads you; do not ask anyone to trust you on this` |
  | Vox.app member pane | as today, with `as of its entry <s>` | as today, with `as of its entry <s>` | `Trust not known yet: <the same clause>.` |

  When A's sender key has arrived, the third state adds `; its key has arrived`. The outbound
  direction is unchanged.
  - *Why*: item 52; F4: a fresh relay inventory says nothing about A's latest decision; the
    unknown text must not invent an entry range.
  - *Changes*: `Frame::MemberConsents { outbound, inbound: Vec<(Digest32, InboundTrust)> }`
    (control-socket format; client and daemon are one version, ADR-034 UP-2): `ipc.rs` encode and
    decode (`:4516-4517, 5791-5796` and the `MemberConsents` arms), `detail_of` (`actor.rs:529-534`),
    the renderers `doctor.rs:961-985`, `room_cli.rs:1244-1260`, `agent_hook.rs:907-911`,
    `crates/vox-ffi/src/client.rs:7356` and the member pane (`apps/macos/Vox/MainWindow.swift:2575-2579`).
    ADR-028 L-4's `→` gains the third state's words (amended below).
  - *Deleted*: the two-valued `inbound` list; the unqualified `has not trusted you`.
  - *Proof*: extends `a_newcomer_reads_the_whole_history_proof.rs`: (1) a third member joins while
    an apparatus holder standing in for a slow member withholds the members' control entries above
    the newcomer's `control_held`; within 30 s the doctor prints `cannot yet tell whether it
    trusts you: its trust is not checked through positions` for each member and no line with `had
    not trusted you`; the holder serves them; within 30 s `you trust each other`. (2) **Fresh but
    stale relay**: member A consents to the newcomer at its position 11 and then goes offline; the
    relay keeps sending fresh inventories holding A through 10 and answers `Head(A)` with A's
    signed head of size 10; the newcomer's doctor prints `as of its entry 10 (verified … from
    member <relay>) it had not trusted you` and `fix: none yet`, never today's `fix: on the
    computer hosting`; A reconnects; within 30 s `you trust each other`. Control: the existing
    one-way-trust staging (`:997-1001`) with A connected prints `had not trusted you` with today's
    fix. v0.4.30 is red on (1)'s negative assertion and on (2)'s (KNOWN, files:
    `doctor-omp-io-203050Z.txt`). Mutant: print the fix whenever `HasNotTrusted`; (2) goes red,
    PRODUCT. Acceptance G52-1.

### 4. A message says what was lost, where, and what to do

- **TR-11. One rule for every message a person or an agent reads.** **(r3: F10 proof.)** Every
  error, refusal, notice, status line and log line MUST say, in this order: what did not happen for
  the person; in which layer; what to do, if anything. It MUST NOT name a worker, a thread, a type,
  a variant, or a bundle that is not the thing that failed. A "not yet" MUST say which of ADR-040
  NW-4's two things is true (retained and finished by Vox; or run it again) and name its
  prerequisite in NW-1's words. A hint MUST be given only when it applies, and MUST NOT advise an
  action that may destroy an identity or data unless its precondition is known. Form: the first
  clause lower case with no full stop; detail and hint as whole sentences. Every rewrite in
  Appendix D is normative.
  - *Changes*: `Error::MalformedBundle` is replaced by `Error::Malformed(Layer, &'static str)`,
    `Layer ∈ {IdentityBundle, PairwiseMessage, Frame, History, Session}`, Display `malformed
    <identity bundle|pairwise message|frame|history object|session record>: <what>`; the sites are
    swept by layer. "Inclusion header is absent" is not an error: the receiver asks for the header
    first and keeps the proof pending (ADR-046 SY-13 rule 4). `WireError::ProtocolLimits` is kept
    for a real limit; the receiving side prints `the peer could not serve this request: it is over
    that peer's limits; this node asks in smaller pages`. `TransportFailed` only for a transport
    fault (ADR-046 SY-7).
  - *Deleted*: `MalformedBundle` as a catch-all; the `MalformedBundle → ProtocolLimits` arm; `the
    peer refused: protocol limits exceeded` for a decode failure.
  - *Proof* **(r9)**: extends `a_cli_failure_tells_the_truth_proof.rs` with two claims. (1)
    *Prerequisite, not error* (the replacement carries header and proof together in a `Range`
    answer, so "proof before header" cannot occur on the wire and `admission.rs:234-237` is gone
    with ADR-046 SY-19): an apparatus holder serves a `Range` answer with a control entry of A
    whose `pre_context` names a context it has not served; under ADR-046 SY-13 rule 4 the whole
    answer is verified before its one commit and a `MissingContext` answer is **parked in
    memory under its permit, not held** **(r11: R4)**: the host logs nothing containing
    `malformed`, its status for that peer holds no `last_failure`, `--json
    .sync_node.permits.owners[]` names the answer as `answer awaiting context <hash>` and the
    member line reads `answer pending: waits for context <hash>` (never `held`), and a `Context`
    request reaches the apparatus within 10 s (SY-14); (success arm) the apparatus serves the
    context 5 s after the request, before the 20 s deadline; the entry is committed and applied
    within 10 s and the permit released; (timeout arm, separate rerun) the context is never
    served; at the 20 s deadline the answer is discarded, `last_failure` reads `the holder did
    not serve context <hash> within 20 s` (ADR-046 SY-21's typed deadline, never `malformed`),
    and the permit is released. Mutant, in retained code: at the park site, return
    `Error::Malformed(Layer::History, "context is absent")` instead of parking; `last_failure:
    malformed history object` appears in the success arm; red, PRODUCT. (2) *Layer label*: the
    apparatus holder sends a `Range` answer whose `Entry` frame has a truncated header (a frame that
    fails `Frame` decoding, which the design keeps as an error); the host's status shows
    `last_failure: malformed frame: …` and never `malformed identity bundle`; mutant: restore the
    catch-all prefix; (2) goes red on the negative assertion, PRODUCT. v0.4.30 is red on (1) (trial
    B1-base, KNOWN, files) and on (2) (KNOWN, code: the prefix is `identity bundle` for every
    layer). Acceptance G50-1.

- **TR-12. A room's failed save names the room and its cause; a settlement is not a join.**
  (The settlement here is the room's join settlement, `recovery_save.rs`'s retained save, not
  ADR-044 RD-7's withdrawn durability settlement **(r11)**.) A
  released pending write MUST carry its cause (`PoisonCause::{WorkerPanicked, SaveFailed(error)}`;
  ADR-048 removes the trust-pass poison (its TC-5/TC-6 fence; ADR-040 NW-2 keeps the release)), and its words MUST be
  Appendix D's. A failed settlement save MUST be `NodeEvent::RoomSettlementFailed { room, phase,
  error }` with `phase ∈ BeforeCommit | Commit` **(r12: F4)**: `BeforeCommit` is a definite
  refusal before the store transaction committed (ADR-047's floor, a recovering store, a poisoned
  pending write), rendered `room <id>: its settlement could not be saved: <error>; retained and
  run again when <prerequisite words>`; `Commit` is an error returned by `txn.commit()` itself
  (`store.rs:1994`, `Storage{op: "commit"}`), whose bytes may or may not be on disk (ADR-044 RD-7
  r14), rendered `room <id>: its settlement could not be confirmed: <error>; what the store holds
  governs when it is next read`, and this commit is never replayed and never later reported as
  saved: the room's next settlement, if one is still owed, is decided from the reopened store's
  contents. The event has its own IPC tag, encoded and decoded in `ipc.rs` beside `JoinFailed`,
  delivered to every event subscriber (`api.rs`, `app.rs:956`, `live.rs:1233`, `tunnel_cli.rs:710`,
  the FFI event stream). v0.4.30 receives every error generically (`recovery_save.rs:267-291`)
  and cannot tell the two apart.
  - *Proof*: extends `a_cli_failure_tells_the_truth_proof.rs` with two claims. (1) Under
    `test-knobs`, `VOX_TEST_SAVE_WORKER_PANIC=<room>` makes the blocking save worker panic once;
    the daemon log has `the save crashed inside the daemon` for that room, the room's next `vox room
    post` succeeds, and no line contains `worker stopped`. Mutant: restore the generic poison
    string; red, PRODUCT. (2) A settlement save refused by a held store (ADR-047's full-disk
    apparatus, the floor reached before the transaction) logs `its settlement could not be saved`
    with `retained and run again`, and never `a join did not complete`. (3) **(r12: F4)** A
    settlement whose commit fails (ADR-047 SO-12's commit-fault apparatus: the `test-knobs` fault
    that makes `txn.commit()` return an error after the write, the same knob SO-12's proof uses)
    logs `its settlement could not be confirmed: <error>`, never `retained and run again`, and the
    next `vox status` shows the room's settlement state as the reopened store holds it. Mutant for
    (3): map a `Commit` failure to the `BeforeCommit` sentence; `retained and run again` appears
    on the commit fault; red, PRODUCT. v0.4.30 is red on (2) (KNOWN, files:
    `io/daemon-202624Z.log:3707-3712`) and on (3) (one generic event for both; unverified on the
    release asset). Acceptance G50-2.

### 5. A watchdog says when a room is stuck and does nothing by itself; no repair facility in v0.4.31 (ruled)

- **TR-13. The watchdog names what it knows and does nothing by itself.** **(r4: R2.)** The
  notifier's 5-second check MUST evaluate TR-4, TR-5, TR-25 and TR-19's `waiting-for-member`
  predicate (r6: E1) from the published report (no new thread or timer). The unhealthy line's
  remedy clause MUST be, by cause: TR-4's and TR-5's own
  clauses (holders, requests in flight, the last answer); TR-25's reason clause **(r10: no
  restart is named by anything; the one cause a restart cured does not exist under the
  replacement)**. `vox agent doctor` MUST give the same
  as the room's `fix:`. The next agent notice for a room that is behind MUST say `this room is
  behind (<N> entries); do not conclude that members have not trusted you`. The watchdog MUST NOT
  restart a daemon, update anything, leave or join a room, or run any rebuild. No time elapsed MAY
  by itself make the watchdog name any command **(r10)**.
  - *Deleted*: `REPAIR_AFTER`; the `room-stale` condition.
  - *Changes*: `notify::watch`, `diagnose`, `doctor.rs`, `agent_hook.rs`.
  - *Proof* **(r10)**: in TR-4's and TR-25's acts: (1) with the peer withholding, the stuck node's
    line ends with TR-4's clause and names no command; (2) in TR-25's `cannot_save` act the
    doctor prints the room's `cannot save` line with `fix: free <n> MB on the disk holding <dir>;
    Vox continues by itself`, no `NOT ASKING` line and no command **(r11: R2)**, and in the
    start-once control it names no command; in the quiet-to-first-post control it prints nothing. Mutant: name `vox
    daemon --restart` for every `NOT RECEIVING`; (1) red, PRODUCT. Acceptance G53-2.
  - *Withdrawn by ruling (Q1, 2026-11-13)*: the clause "a local fault was found: <which>; vox room
    repair <name> rebuilds it"; the cheap render check in the notifier; and the agent-session
    refusal of `vox room repair` (detected by `coord::session_if_named()`, the five harness marks
    of `crates/vox-tui/src/coord.rs:72-78`, proved through the real OMP extension journey with no
    injected variable, mutant "check only `VOX_SESSION`"). Recorded so a future repair ADR starts
    from them.

- **TR-14. Withdrawn by ruling (Q1, 2026-11-13): no `vox room repair` in v0.4.31.**
  **(r4: R2.)** No saved file of Nov 12–13 shows a disagreement between a room's derived state and
  its held log: (a) and (b) are ADR-046's starvation (the repair arm of the deciding round,
  `arm-repair.md`, fails the decisive case on the slow author's control chain, not on a
  local projection), (c) is ADR-049's, (d) is ADR-046 SY-24's; the decider's rule is no fix without
  a reproduced cause. The facility therefore ships only if he wants a general derived-state rebuild
  independently of these incidents. *What keeping it would require*, stated and not designed
  further: a check for the three disagreements of revision 3 (governance fold, render, Session);
  the governance and Session layers rebuilt into fresh roots from held entries and switched in one
  transaction with a durable repair record (revision 3's steps 1, 3, 4); and, for the render
  layer, **reindexing from the authenticated retained plaintext and `cache_id` bindings** (a
  missing index record for a cached row is re-created from its cache and retention binding, an
  index record whose entry is not held or not readable is removed), ratchets untouched, with
  genuinely unrendered, uncached, readable bodies left to the ordinary backfill. Re-queuing the
  backfill cannot do it: the backfill skips an entry whose retention record has a `cache_id`
  (`channel.rs:7883-7897`) and `render_content_into` skips cached entries (`:8167-8181`), so a
  lost index record of a cached row is never recreated that way. The repair never touches the
  sparse directory's `phase` or `promotion` (`cleanup_orphan_provisional` at every open owns
  them, `entry_store.rs:2668`), never says `catching up` or `receiving` as a claim, exits 2 when
  nothing disagrees, and refuses agent sessions (TR-13's withdrawn clause). Its proof would be
  revision 3's four acts with the corruption and pause knobs under `test-knobs`, act 2 asserting
  the three cached rows come back through the reindex and not through decryption. Acceptance
  G53-1 is void in v0.4.31.

- **TR-15. A rebuild never destroys what only this node has.** **(r5: Q1; withdrawn with TR-14 for
  v0.4.31, recorded as binding on any future repair.)** Any command that rebuilds a room's derived
  state MUST leave byte-identical: the genesis; the node's own feed (every position, its
  signatures, `own_verified_head`), including every entry no member has yet confirmed holding;
  sender-key origins and generations; received bodies; cached plaintext and read-record caches of
  received rows; pairwise sessions and prekeys; read records; the trust keyring; computer bindings;
  the vault. Acceptance G53-3 is void in v0.4.31.

- **TR-16. There is no rejoin command, and no command leaves or joins a room on a person's
  behalf.** (the former Q7 is folded into Q1.) A rejoin cannot restore an entry that only this node held: `vox room leave`
  deletes the local room (ADR-049's leave, formerly ADR-040 NW-15, keeps that, at once), and a
  fresh link brings back only what members hold. What the person does instead: (1) read `vox
  status`: `NOT ASKING` names its reason **(r10: no restart)**; `NOT RECEIVING` with connected
  holders is a sync fault ADR-046 owns and the line names
  the last answer; `cannot read` names the key or consent; `waiting for a member` names who to
  reach; (2) nothing: there is no repair command in v0.4.31 (ruling Q1); a future repair ADR starts from TR-14 and TR-15;
  (3) as the last resort, `vox room leave <room>` and `vox room
  join <link>` by hand, where the leave MUST first say what only this node holds (contract to
  ADR-049): `this node holds <k> entries of yours in <name> that no member has confirmed holding
  (newest <dur> ago); leaving deletes them for good` and require `--yes` when `k > 0`. `k` counts
  own positions above the highest **body-complete** `held_through` any member's inventory reports
  (`source.rs:1667-1676` refuses a scalar echo as that authority, rightly); when no member has
  reported, the sentence reads `this node cannot tell how many of your entries in <name> no
  member holds; leaving may delete some for good` and `--yes` is required **(r10: the locked-node
  form is dropped; ADR-049 LE-1 makes a locked node a leave failure, X042-12)**.
  - *Proof*: owner ADR-049's leave journey, its act A (a′) (r12) **(r13)**; the words are this
    ADR's; the count is the own positions above the highest body-complete
    `.rooms[].own_feed.members[].held_through`. With two unconfirmed posts,
    `vox room leave` without `--yes` exits non-zero printing `2 entries of yours … no member has
    confirmed holding`; with a member whose inventory confirms every own position it prints no such
    line (control); with the node locked it is refused with ADR-049 LE-1's locked refusal and
    ADR-041 RS-3's `Unlock it once: vox node unlock <n>`, and prints no count and no `cannot
    tell` **(r11: R8)**. v0.4.30 is red: it prints `this
    node will delete the local room` with no count (KNOWN, IO drill). Mutant: count only positions
    above the DAG prefix; red when the member's receipt is behind the own head, PRODUCT.

### 6. Evidence survives, and notices are never late

- **TR-17. The daemon log keeps its newest 21 MiB of lines, 48 busy hours at the measured rate;
  opening it never truncates, rewrites or deletes a file, and a restart costs no retention.**
  **(r3: F11.)** The ring is `<data>/.daemon/log` and `log.1` … `log.7`, 3 MiB each; a file is
  rotated when a write would take it past 3 MiB and at no other time. At open the current file is
  **continued in place**: a torn or non-canonical last line is left as it is, a newline is written
  after it if it lacks one, and writing goes on in the same file; nothing is read back, rewritten
  or `set_len`. A current file larger than 3 MiB at open (an older version's) is rotated whole into
  `log.1`; a predecessor named `log.log.1` is renamed `log.2` on the first open after the update;
  the rename chain runs from `log.7` down and tolerates a gap left by a crash between renames; the
  only deletion is `log.7` at a rotation. So a restart consumes no slot, and the retention promise
  is in bytes: at least the newest 21 MiB of lines (7 × 3 MiB plus whatever the current file holds),
  48 h at 2 × 201,217 B/h. A repeated line MUST carry its first time and its last:
  `[count=NNNNNNNNNNNNNNNNNNNN last=YYYY-MM-DDTHH:MM:SS.mmmZ]`, rewritten in place within the
  line; a line repeated across a rotation or a restart starts a new count. `vox status` MUST print
  `daemon log: <path> (keeps 24 MiB in 8 files; oldest line <time>)`, the oldest line read from the
  oldest file present. (ruled: Q4, 24 MiB)
  - *Changes*: `daemon_log.rs`: `LIMIT = 3 MiB`, `KEEP = 7`, the rename chain, the record format,
    the continue-in-place open; the line conversion branch (`:52-66`) and the truncate/delete
    branch (`:43-51`) are deleted.
  - *Proof*: extends `the_daemon_and_its_nodes_proof.rs`'s LG section (`:1951-`), whose apparatus
    already stages files and whose emitted lines are the node lifecycle lines (`node <n> is Ready`,
    `stopping`), one distinct line per node start: (1) a staged 2 MiB current file whose last line
    is torn (40 bytes, no newline) is, after the start, the same file with those bytes intact at
    the same offset followed by a newline and the new lines; a staged `log.log.1` is `log.2`; (2)
    the apparatus restarts the daemon 20 times with the same staged file; `log.1` is unchanged
    (no slot consumed); (3) the apparatus stages `log.1` … `log.7` of 3 MiB each with a known first
    line in `log.7`, and a current file of 3 MiB − 100 bytes; one node start rotates once; `log.7`'s
    old first line is gone and `log.6`'s is now in `log.7` (eviction is only at rotation and only
    the oldest); (4) **(r9)** a line repeated within one run (the apparatus repeats one attention
    event every 2 s for 20 s) shows a first time and a `last=` time that differ by at least 15 s,
    and after the restart the same line starts a fresh count (`count=…1` with a new first time; the
    rule: a repeat across a rotation or a restart starts a new count).
    v0.4.30 is red on (1) (KNOWN, code: `:52-66` rewrites; `:43-51` truncates). Mutant A: rotate at
    open on a torn line; (2) goes red (`log.1` replaced), PRODUCT. Mutant B: `KEEP = 1`; (3) goes
    red, PRODUCT. Acceptance G54-1.

- **TR-18. A missing notification service costs one line per run and never delays a notice.**
  **(r3: the blocked-child staging.)** On Linux the daemon MUST skip `notify-send` when neither
  `DISPLAY` nor `WAYLAND_DISPLAY` is set, silently; when one is set it MUST spawn `notify-send`
  detached with a 5 s kill, MUST NOT await it in the notifier's loop, and on its first failure MUST
  print exactly one line per run, `vox daemon: desktop notifications are not available here
  (notify-send failed: <its first stderr line>); attention notices go to this log only`, and stop
  calling it. Every attention and recovery notice MUST reach the log within one check (5 s) of its
  condition. The disabled flag is one per daemon process (`OnceLock`), shared by every node's
  notifier.
  - *Proof* **(r9)**: extends `notify_proof.rs`, two acts in the Linux VM with the `desktop_stub`
    stand-in (`:191-215`) made to block until a file appears or it is killed, writing a marker at
    start and a heartbeat file every 200 ms while alive, then exit 1; `notify-command` unset. The
    attention event is a genuine outstanding obligation, not a dead member (TR-19 makes `offline` a
    plain fact): TR-4's apparatus holder (depends on TR-1 and TR-4) answers `Head` with a signed
    head, advertises coverage and withholds one body, so `room-not-receiving` is raised 60–65 s
    later; recovery is staged by the holder serving the body. (Act A) `DISPLAY` and
    `WAYLAND_DISPLAY` unset: the attention line within 70 s of the gap, the recovery line within
    10 s of the body being served, the stand-in never executed (marker absent), no `not available`
    line. (Act B, the non-blocking claim) **(r11: R5)** `DISPLAY=:0` and, under `test-knobs`,
    `VOX_TEST_NOTIFY_KILL_MS=20000` (the proof build's kill; the shipping kill stays 5 s): at the
    attention line the stand-in starts (marker present); the apparatus serves the body 1 s after
    the attention line; the recovery line reaches the log within 5 s of the serve (one check,
    TR-18's bound unchanged **(r12: F2)**), **and the stand-in's heartbeat file shows it alive at
    the recovery line's timestamp** (the kill is 20 s away, so a correct detached notifier always
    meets this); the child is then killed at 20 ± 1 s, exactly one `desktop notifications are not
    available` line follows, and a second attention event (the holder withholds the next body)
    executes the stand-in no more; with two nodes in the daemon the line appears once. (Act C,
    the kill claim) the shipping 5 s kill (knob absent): the stand-in's heartbeats stop and its
    exit is recorded as killed at 5 ± 1 s after the marker, and the `not available` line follows
    once. A missing marker or a child that never started is APPARATUS. v0.4.30 is red on act B's
    recovery bound (unverified on the release asset; E2 is the experiment). Mutants: (act B)
    await the child as today; the recovery line appears only after the 20 s kill (≥ 19 s after
    the serve, no live heartbeat at its timestamp); red, PRODUCT; (act C) **(r12)** omit the kill;
    the child's heartbeats continue past 7 s after the marker and no killed exit is recorded;
    red, PRODUCT. Acceptance G55-1.

### 7. A member whose daemon answers is not unreachable

- **TR-19. An answered refusal is shown as "not attached", never "unreachable"; a node this node
  cannot reach is "offline".** **(r5: Q3, Q5.)** The node MUST keep, per member, its reach:
  `connected`; `not attached at <addr>` when the newest dial to it in the last minute was an
  answered refusal; `offline, last seen <dur> ago` for silence; `never dialled` before the first
  dial. `vox status` MUST print the second as
  `node not attached: a daemon at <addr> answers, but holds no node attached as it (locked, starting, or moved), since <time>`
  and the third as `offline, last seen <dur> ago` (the doctor and the app print the same words;
  `unreachable` is printed nowhere). Neither state is unhealthy by itself (ruling Q5). **The
  `waiting-for-member` predicate** (r6: E1; r7: S1, S2), evaluated by `diagnose` and the notifier
  from the published report, independently of TR-2's rendering and of live coverage, in two
  branches for some author A with a **member-supplied obligation** unresolved (r8: T2): a wanted
  body (`oldest_wanted(A)`), unchecked control coverage (`oldest_dependency(A)` of kind (i)), or a
  held entry waiting for a context, parent header or body this node does not hold (kind (ii) with
  a remote prerequisite). A held entry waiting only on the local fold, or on any prerequisite this
  node satisfies by itself, is **not** a member-supplied obligation: it reads TR-2 row 12's `trust
  held … waiting for the fold` (or ADR-040 NW-4's named wait) and TR-4's dependency diagnosis,
  never `waiting for a member`, whatever the members' reach:
  - *no member reachable* (generic; r7: S1): every other member's reach is settled and none is
    `connected`. It needs no inventory and no known holding, so it holds after a restart as soon as
    the reach ladders have run (within `REACH_SETTLED` + `ASK_PATIENCE` + 5 s of Ready), and for as
    long as the members stay away. Line:
    `! room <id> (<name>): waiting for a member: <N> entries behind; no member is reachable (<id>: offline, last seen <dur> ago; <id>: not attached at <addr>); who still holds them is not known`
    (+ `; <id> last advertised <A>@<p> <age> ago` when a known holding exists), one key per
    unreachable member `waiting-for-member:<room>:<member>`; the doctor prints `warn  room <name>:
    this node needs <N> entries and can reach no member of the room (<reaches>); who holds them is
    not known; Vox dials again by itself`.
  - *every reachable member says no* (r7: S2; r8: T1): at least one other member is connected,
    and **every connected member** (whether or not it is a source: a member connected before its
    first inventory, or with an inventory older than `INVENTORY_FRESH`, counts) holds a
    **negative** for the position (a `NotHeld` answered since its inventory last changed; a member
    with no inventory yet, a stale inventory, or an `unknown` or `possible` state is not negative
    and keeps the position at TR-2 row 12's `locating` with ADR-046's probe instead), so at least
    one actual `NotHeld` exists, and at least one last advertiser is known. The condition and the
    sentence quantify over the same set, the connected members. Line:
    `! room <id> (<name>): waiting for a member: <N> entries behind; <A>@<p> was last advertised by <member id> <age> ago (now <offline, last seen <dur> ago | not attached at <addr>>); every reachable member says it does not hold it`
    with key `waiting-for-member:<room>:<member>` per last advertiser; the doctor prints `warn  room
    <name>: <N> entries this node needs were last advertised by <member> <age> ago (now <reach>);
    every reachable member says it does not hold them; Vox asks again when a member reconnects or
    changes its inventory`.

  Neither branch says `held by`, `held only by` or `nothing to do`: a known holding is a claim of
  an age, never present possession, and an admitted member that advertised a position it does not
  hold can make this node print its name and the age, nothing more. The notifier raises the key
  once; the app shows its row; TR-2 row 6 prints the room verdict with the zero-coverage
  qualification when the room has no source. The predicate clears at the first check after the
  position gains a positive or possible holder, is delivered, expires or becomes `not for you`,
  or (generic branch) a member becomes `connected`. A member that is `offline` or `not attached`
  with no such obligation raises nothing. `peer-unreachable` and `member-not-attached` are
  deleted as keys. The dial's own text MUST be `<addr> answered, but holds no node attached as
  <expected node>`. No text MAY call it the member's daemon, and none MAY state "locked" as a
  fact (ruling Q3: no attached-node presence this release; what an answered refusal shows is all
  that is said).
  - *Proof*: extends `a_dial_that_reaches_another_node_names_no_one_proof.rs` with a third act in
    a **two-member room** (alice, bob): alice's daemon restarted `--as-detached` with her node
    Locked on the same port; within 15 s bob's `vox status` member line reads `node not attached:
    a daemon at 127.0.0.1:<port> answers` and, with nothing wanted from her (caught-up control),
    no `UNHEALTHY` line names her and the room reads its coverage form only; then a wanted entry
    is staged so that bob has verified its signed head and recorded a last advertiser **(r9)**: an
    apparatus member dave, admitted to the room and connected to bob, answers bob's `Head(alice)`
    with alice's newest signed head of size s (dave received alice's post s before she was Locked;
    bob was paused for that post) and the consistency proof, advertises an inventory covering s,
    serves bodies through s−1 and withholds s; the proof asserts `size_known == s` and
    `entries_behind == 1` for alice on bob before going on; dave then disconnects (`offline`).
    With alice `not attached` and dave `offline`, bob's `--json .unhealthy[].key` holds
    `waiting-for-member:…:<alice>` (and `…:<dave>`), the line reads
    `waiting for a member … no member is reachable (<alice>: not attached at 127.0.0.1:<port>;
    <dave>: offline, last seen … ago); who still holds them is not known; <dave> last advertised
    <alice>@s … ago` **(r11: R7: dave is the advertiser, alice the author; alice sent no
    inventory)**, the doctor's `can reach no member`, the app's row, and all of them **persist through 100 s**; the line never contains
    `held by`, `only` or `nothing to do`. (Restart half, r7: S1) bob's daemon is restarted while
    alice stays Locked; within `REACH_SETTLED` + 35 s of bob's Ready the same key, line (now without
    the `last advertised` clause: nothing is known), doctor and app outcome are back, and persist;
    a no-required-work restart control (alice caught up before the restart) shows only `not
    attached` on her line and no key. (Third-member half, r7: S2) a third member carol joins
    connected and fresh, her inventory silent about alice's position: the key is gone within 10 s
    and the room reads `catching up: … locating the oldest with 1 members`; carol answers the
    probe `Held` and serves it: rendered, no key; in a rerun carol answers `NotHeld`: the key is
    back within 10 s with `was last advertised by <dave> … ago (now offline …); every reachable
    member says it does not hold it` **(r11: R7)**. (False-claim half) an apparatus member dave advertises an interval covering
    the wanted position, then disconnects: with carol `NotHeld`, the line names dave as `last
    advertised … ago (now offline …)` and never `held by`. (Connected-not-a-source half, r8: T1)
    carol (an apparatus member) connects and sends **no** inventory for 20 s, then sends one and
    **withholds every heartbeat for 95 s** so that her inventory goes stale on bob
    (`inventory_at` is stamped on receipt; the proof asserts `coverage.sources` excludes carol
    after 90 s while her member line reads `connected`) **(r9)**: in both states, with no other
    member and again with a fresh `NotHeld` source erin connected, no `waiting for a member` names
    the position and no line says `every reachable member says`; the room reads `locating`; once
    carol's fresh inventory and her `NotHeld` arrive, the alarm prints within 10 s. (Local-fold half, r8: T2) every header, body, context and parent of a
    control entry of alice is held and only the fold is pending (ADR-040's `GovernanceFold(room)`
    held by ADR-040 NW-11's fold-hold knob **(r10)**), alice and every other member offline: no
    `waiting-for-member` key, the room reads `catching up: trust held for 1 members, waiting for
    the fold` and the `waiting` block names the fold; the restart half's missing body still
    alarms. A second act stops alice's daemon
    instead of locking it: the member line reads `offline, last seen <dur> ago` and the same
    assertions hold; after `vox daemon --node alice --passphrase-file`, `connected` within 10 s and
    the key gone within 10 s of bob rendering the entry. v0.4.30 is red (KNOWN, RcaLanPath on the
    release binary: `unreachable`). Mutant A: map `AnsweredRefused` to `Silent`; red on the member
    line, PRODUCT. Mutant B: evaluate the generic branch only when a known holding exists; the
    restart half never alarms; red, PRODUCT. Mutant C: treat `unknown` as negative; the
    third-member half prints the alarm while carol is unprobed; red, PRODUCT. Mutant D: quantify
    the negative test over fresh sources; the connected-not-a-source half prints the alarm; red,
    PRODUCT. Mutant E: enter the generic branch for any unresolved dependency; the local-fold half
    prints `waiting for a member`; red, PRODUCT. Acceptance G56-1.

- **TR-20. An answered refusal retires that address, not the member.** After an answered refusal
  at an address, that address MUST NOT be dialled again for 60 s; the reach MUST still ask each
  connected coordinator for a dial-back (`network.rs:1753-1760`). Where a coordinator answers that
  it holds no connection to the member, the text MUST be `the anchor holds no connection to <node>
  right now; no circuit was asked for`, logged once per reach at debug, never at the attention level.
  - *Proof*: TR-19's third act with the proof's anchor: the apparatus coordinator records every
    dial-back request; during the Locked span bob asks it at most once per reach, and bob's
    attention log has no `cannot reach` line; a moved-peer act: alice's node is unlocked on a new
    port while a stranger daemon answers on the old one; bob connects to her within 30 s through the
    dial-back. v0.4.30 is red on the log assertion (KNOWN, files: 476 lines). Mutant: skip the
    dial-back after a refusal; the moved-peer act goes red, PRODUCT. Acceptance G56-2.

- **TR-21. A genesis goes only to boards that carry the room.** A node MUST publish a room's genesis
  only to boards of members whose admission to that room it holds, or of the room's anchors. A
  refusal that still arrives MUST be logged once, at debug, as `board <id> does not carry room <id>
  yet; its genesis is not kept there`.
  - *Proof*: TR-19's file: one daemon with two nodes, the second joining a room the first created,
    produces no `rejected: policy` line and both nodes' boards hold the genesis within 10 s.
    Mutant: publish to every connected board; red, PRODUCT. Acceptance G56-3.

### 8. Every surface agrees

- **TR-22. The app shows the same verdicts and states.** Vox.app's room row MUST show the room's
  verdict word (TR-2's first word, `ended` included) and TR-24's coverage clause, from the same
  report as `vox status`, and MUST treat `room-not-receiving:`, `room-not-asking:`,
  `room-no-inventory:`, `member-unreadable:`, `waiting-for-member:` and `checkpoint-dispute:`
  **(r11: R9)** as unhealthy keys beside `room-store:` and `sync-failing:`
  (`NodeModel.roomHealth`, `NodeModel.swift:1161-1166`, an explicit filter); the top
  banner already shows every unhealthy key. The sidebar row of an ended room MUST read `<name> —
  ended` (ADR-049's delegation).
  - *Proof*: extends the app's first-run journey (`FirstRunProof.swift`, the `room-health-`
    element), under the app-proof rule in force (ADR-034 PF-3 or its successor), in two acts
    **(r12: F3)**: (1) staged with TR-4's apparatus holder: the affected room's row reads `NOT
    RECEIVING`; (2) staged with ADR-046 SY-27/SY-28's dispute apparatus (a creator checkpoint
    whose summary disagrees with the node's own record, in a room that is otherwise current, so
    `checkpoint-dispute:<room>` is the room's only key): that room's `room-health-` element reads
    the dispute line (`creator checkpoint <hash> disagrees with this node's record; verifying from
    <position> instead`) beside the room, and no other room's row changes; ADR-049's end journey
    asserts the sidebar row reads `— ended`. Mutants: (a) drop the new prefixes from the filter;
    act 1 red, PRODUCT; (b) remove only `checkpoint-dispute:` from the filter; act 2's row stays
    healthy while the banner shows the key; red, PRODUCT. Acceptance G49-8.

- **TR-23. Lines other ADRs add use this ADR's layout.** These lines MUST print exactly as below;
  each is proved in its owner's journey.
  - ADR-040 NW-4: a `waiting` block after `UNHEALTHY:`/`healthy:`, one line per obligation parked
    longer than 30 s:
    `  room <id> (<name>): <what> waits until <edge words>, for <dur>; Vox finishes it by itself`,
    and one line per permanently refused daemon-owned obligation:
    `  room <id> (<name>): <what> failed: <refusal>; it is not retried; <what to do>`.
  - ADR-049 (formerly ADR-040 NW-6, NW-7, NW-15): the leaving line, unchanged (TR-8), and
    **(r10, X049-8; r11: R12)** LE-4's and LE-9's variants and the `.left[]`, `.withdrawals[]`
    and top-level `.publications[]` fields, each with ADR-049's exact text, in Appendix A's
    sibling table;
    `vox room list` keeps `[ended: its creator or an admin ended it]`; `vox status` prints TR-2's
    ended line; the app TR-22's; the leave's unconfirmed-entries sentence (TR-16); the roster
    history's words `<id> left at <time>` / `<id> back at <time>` on `vox room roster --history
    <room>` (ADR-049 LE-9; the surface name is ADR-049's, confirmed here).
  - ADR-048 TC-8 (trust containment; the words are ADR-048's; the ids are ADR-048's own, not
    ADR-040's) **(r10, X048-8, X042-10)**: `vox computer status`'s three sentences, verbatim: parked,
    `room <name> still has to withdraw the keys of <k> node(s); it waits until <ADR-040 NW-1's
    words for the debt's prerequisite>`; permanently refused, the same line ending `; it cannot:
    <refusal>; posting there stays refused` with TR-23's `failed` line in `vox status`; closed,
    `room <name> (closed) will withdraw the keys of <k> node(s) when it is next opened`; and the
    `waiting` line `room <id> (<name>): <what> waits until room <name> has withdrawn the keys of
    <k> node(s) of computer "<c>", for <dur>; Vox finishes it by itself`. `vox room members`'s
    trust column shows a member the keyring does not trust as `not trusted` (X048-9; TR-10's
    table gains the column).
  - ADR-040 NW-4 **(r10, X040-4)**: the `waiting` block omits, in text only, the obligations parked
    on `StoreRecovery(room)` of a room whose `cannot save` line is printed; JSON carries them.
  - ADR-041 RS-3, RS-5, RS-15 **(r10, X041-14–16)**: layout rows in the node block for RS-3's
    Locked line (`node <n>  Locked: its remembered passphrase is no longer in this computer's
    memory (keyring: <kernel text>)`, or the credential variant `Locked: its systemd credential
    <name> was not given to the daemon`, then `Unlock it once: vox node unlock <n>`; the one
    sentence Appendix A's row carries **(r12: F6)**), `unsupervised: <why>`, `the login item is
    waiting`, and the four factory-reset lines
    (`a factory reset begun <time> did not start; nothing changed`, `… stopped the daemon and moved
    nothing`, `… moved the old data to <to>; this folder is new`, `… cannot be reconciled: …`);
    the words are ADR-041's; the places are Appendix C's.
  - ADR-050: the hook's refusal texts follow TR-11 **(r9: the
    agent-invocation act went with TR-14, ruling Q1)**.
  - ADR-044: TR-8's `<done> of <total> rows`; RD-7 r14: a failed ruled commit is `could not be
    confirmed` wherever a line reports it, and no line names a flush, a token or a settlement
    **(r11)**; RD-9's `rebuilding history evidence from its canonical ranges`; RD-13's doctor lines
    `warn  network: this host gives Vox <N> KiB of UDP receive buffer; it asks for 4 MiB` and
    `fix: as root, sysctl -w net.core.rmem_max=4194304, and keep it in /etc/sysctl.d/90-vox.conf`.
  - ADR-046 SY-20 and SY-24: TR-1's measures under Appendix A's names; `start_reason` values
    rendered as TR-25 says; `not for you` rendered `not available to this node`; `--history resume`
    after a restart: `no page in flight since the daemon started; ask again with --before X`
    **(r10, X046-14: a restart forgets the page in flight, never a row already held)**; a page the
    byte cap cut: `<n> older rows did not fit this page; ask again with --before <oldest shown>`
    (SY-9); slot and permit owners by name in TR-25's node line (X046-4). **(r10)** SY-27's fence
    post line, SY-3's attestation lines, SY-11's unproved line, SY-13's proof wait and SY-27's
    checkpoint disputes: Appendix A's sibling table.
  - ADR-044 RD-9/RD-16 **(r10, X044-21, X044-22)**: the serving side's refusal for
    `EvidenceUnavailable` reads, in `vox status --sync`'s per-port block, `could not serve
    <A>@<p>–<q>: not held here; the peer asks another holder`; a refused inbound request is shown
    as `refused <what> from <peer>: <reason>` with RD-16's reasons; both in Appendix A.
  - ADR-047 SO-2, SO-9–SO-12, SO-14, SO-15 **(r10, X047-13–19)**: the store lines (node and room
    blocks), `rewrite due`, the preparing and recovering forms, the two `cannot save` forms, the
    corrupt-store line and the join refusal: Appendix A's sibling table and Appendix D.
  - ADR-043 CJ-1: `last heard <dur> ago` with this ADR's meaning; CJ-7's `offline, last seen
    <dur> ago (dial failed at <time>: <reason>)`; no `not receiving` and no anchor row there
    **(r12: F5)**.
  - ADR-045: J2(c) and J3(c) assert `last_entry` and `coverage`, not "last sync"; J10(a) asserts
    TR-4, TR-24 and TR-25's lines; FG-12 watches `room-not-asking`; FG-13's outcome numbers are
    TR-1's JSON fields; no mixed-version act exists (the decider, 2026-11-13).

## Alternatives rejected

- **Outcome by beacons (49, design B).** Writes to every room on a timer (ADR-038 FX-29).
- **Behind from receipts (49, design C).** Learned after a round; kept as the alternative source if ADR-046
  removes the position from the inventory.
- **Frontier from the inventory (revision 2).** An unsigned advertisement became missing work and
  could outlive the liar (F1); ADR-046 SY-12 forbids it. Signed heads only.
- **A frontier "known" only when every member is a source.** Silent for a room with one offline
  member; the chosen form says the coverage instead.
- **Resetting `sync failing` only on a fetching round (revision 1).** A quiet room would say it for
  ever.
- **A repair named after a timer (revision 1); a directory-phase repair (revision 2); a repair that
  re-queues the backfill (revision 3); any repair in v0.4.31 (revisions 1–3).** A timer cannot tell
  a local fault from a peer; the open already owns the phase; re-queuing cannot recreate a cached
  row's index record (`channel.rs:7883-7897`); and no incident shows a local fault (TR-14, Q1).
- **A head-freshness guard on `up to date` (revision 3).** Nothing refreshes an unchanged head
  (ADR-046 SY-14), so every quiet room would have read `checking` after 90 s (R1).
- **"No start since the eligibility edge" (revision 3).** One old start vetoes the alarm for ever
  (R3); the missed-start age ages from the later of the edge and the latest class start.
- **`--rejoin` (revision 1).** No design preserves a locally unique post across a leave without an
  export, and v0.4.31 has no export. References: Syncthing's rescan versus `-reset-database`
  (https://docs.syncthing.net/users/faq.html); Postgres `REINDEX` versus `pg_resetwal`; git
  rebuilds the index and never rewrites objects.
- **No dial-back after an answered refusal (revision 1).** Removes a moved member's route.
- **Rotating a torn file into its own slot (revision 2).** Repeated crashes evict the window (F11).
- **A room-wide "no request started" clock (revision 2).** Refreshed by key work; alarms on a quiet
  room's first post (F5).
- **Rewrite strings in place (50, A); hide the keyring when locked (51, B); "key held means
  trusted" alone (52, B); offline `vox store repair` (53, C); time-based log retention (54, B); the
  OS logger (54, C); D-Bus directly (55, B); journald only (55, C); a "locked" refusal code on the
  wire (56, B); presence over daemon trust (56, C, ruled no: Q3).** As revision 1.
- References for the chosen design: Kafka's in-sync test is time behind the leader's log end;
  Postgres `pg_stat_replication` keeps the last measured lag rather than zero when caught up; etcd
  prints `raftIndex` beside `raftAppliedIndex`; Kubernetes conditions distinguish `Unknown` from
  `False`; Syncthing reports `needItems` per folder and device.

## Unchanged rulings

- ADR-025 S0b: `vox status --json` keeps every per-(room, peer) counter; there is no session
  journal. The measures here are derived in memory.
- ADR-038 FX-29: a round that brings nothing writes nothing. Nothing in this ADR writes to the store
  (a kept TR-14 would, run by a person).
- ADR-011 38a and ADR-026 G-1: a dial names no one but the expected node.
- ADR-028 K-7: who trusts whom is the log's consent facts. TR-10 changes only what is said, and as
  of what.
- ADR-036 H-1 and H-6; ADR-046 SY-12: an inventory is a hint, never authority; live entries arrive by
  themselves; older history on request.
- ADR-037 R1 (rehydration from local cache) and R8 (a busy refusal is not unreachable).
- ADR-006 S-10/S-12: consumed live keys are never restored.
- ADR-034 SR-2 and LG-2; PRD-001 R37; ADR-049's rulings on ended and left rooms.
- The decider, 2026-11-13: all machines move to 0.4.31 together; no status form for a mixed-version
  peer exists.
- The operator's machines: no version change or daemon restart without his word (AGENTS.md); the
  doctor names no restart and runs none **(r11: R8)**.

## Superseded and amended lines

Narrow amendments; every rule not named stays in force. Line numbers are at main `d9a8667ba`.

| Rule | Current text (file:line) | Replacement |
|---|---|---|
| ADR-034 HL-1 | "`vox status` and the app MUST NOT say healthy while a room cannot save (SR-2) or a peer's syncs all fail." (`ADR-034-…md:178-179`) | "`vox status` and the app MUST NOT say healthy while a room cannot save (SR-2), a peer's syncs all fail, a room is not receiving, not asking, hears from no member, or holds entries it cannot read (ADR-042 TR-4, TR-5, TR-25); and MUST NOT say up to date of a room whose authors' heads it has not verified (TR-24)." |
| ADR-034 HL-2 | "A peer whose every sync fails over a window MUST be shown as "sync failing", with the reason, and its syncs MUST back off (ADR-025), not repeat every few seconds." (`:180-181`) | Unchanged, and: "Any authenticated answer from the peer ends the failing window; whether the room receives is a separate measure (ADR-042 TR-4, TR-6)." (ADR-049's amendment of the same line, on ended rooms, stands beside this one.) |
| ADR-034 LG-1 | "The daemon's log MUST be bounded in size, and a line repeated many times MUST be written once with its count." (`:185-186`) | "The daemon's log MUST be bounded in size and MUST keep its newest 21 MiB of lines, 48 hours at twice the busiest measured rate (ADR-042 TR-17); a line repeated many times MUST be written once with its count and its last time; opening the log MUST NOT truncate, rewrite or delete a file, and a restart MUST NOT cost retention." |
| ADR-034 LG-3 | "`vox status` and the app MUST name the log's path." (`:191`) | "`vox status` and the app MUST name the log's path, how much it keeps, and the time of its oldest line." |
| ADR-038 FX-16 | "`vox status` and the app MUST record each round the lane completes as the room's and the peer's last completed sync; "no completed sync" MUST fire only when it is true (ADR-034 §5 "Health is true", HL-1; PRD-001 R35)." (`ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:218-220`) | "`vox status --json` MUST report each completed round as `last_round_ms` (activity, not shown in text). What `vox status` and the app say about a room is ADR-042's verdict (TR-2, TR-4, TR-24, TR-25), measured by entries delivered, heads verified and inventories received, never by rounds; there is no "no completed sync" condition." |
| ADR-038 FX-35 (status sentence) | "While at least one port in a room has a retained flow-state continuation waiting for the exact release edge, any "no completed sync" text shown for that room in `vox status` or in the app MUST contain the literal text `flow-state pool`; when no port in the room has such a continuation, that text MUST NOT identify the flow-state pool as the cause." (`ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:796-800`) | Deleted: there is no flow-state pool and no retained continuation under the replacement (ADR-046 SY-19); a `NOT RECEIVING` or `NOT ASKING` line names its cause in its own clauses (ADR-042 TR-4, TR-25). The `room-flow-state-pool:<room>` condition is deleted with it **(r10)**. |
| ADR-038 superseded-lines row | "The lane's completed rounds are completed syncs (FX-16); the control socket answers under sync load (FX-17)" (`:1705`) | "Health is measured by what was delivered and what members have signed and said (ADR-042 TR-1–TR-6, TR-24, TR-25); the control socket answers under sync load (FX-17)" |
| ADR-028 K-9 | "the TUI status bar and the app's menu bar extra MUST show whether a keyring change will ask for the passphrase, for example `keyring open 23m`." (`ADR-028-…md:102-103`) | Unchanged, and: "`vox status` shows it as a fact row directly after the log line, `keyring: locked; a trust change will ask for your passphrase` or `keyring: open, 23m left`, never beside the health verdict (ADR-042 TR-9)." |
| ADR-028 L-4 | "`⇄` (each trusts the other) or `→` (only this node trusts it)" (`:457`) | "`⇄` (each trusts the other) or `→` (this node trusts it, and as of the other's verified head it had not); while this node cannot yet tell, `→` is followed by "cannot tell yet" (ADR-042 TR-10)" |
| ADR-011 38a | "a refusal, "nothing at `<address>` answers as `<expected node>`"" (`ADR-011-…md:295-296`) | "a refusal, "`<address>` answered, but holds no node attached as `<expected node>`"" (ADR-042 TR-19; still names no one) |
| ADR-026 G-1 | "A dial that finds no node answering as the expected identity MUST say "nothing at `<address>` answers as `<expected node>`"." (`ADR-026-…md:331-332`) | "… MUST say "`<address>` answered, but holds no node attached as `<expected node>`"." The rest of G-1 stands. |
| PRD-001 R35 | "last sync, and anything unhealthy." (`docs/prd/PRD-001-…md:135`) | "for each room, whether it is receiving, how far behind it is as of the heads it has verified, how many members have said what they hold, and when it last received an entry; and anything unhealthy." |

## Contract with sibling ADRs (not edited here)

Each change is listed by ADR and requirement id for the ledger (`adr-cross-changes.md`).
ADR-048, ADR-049 and ADR-050 are in progress; the ids named are ADR-040 r2's, which they inherit.
The ADR-046 rows below are the observation contract's rows, stated so that there is one contract
(r5; ruled Q6, ledger row 26):

- **ADR-046 SY-12 and SY-22 (heartbeat)**: r3 has the 30 s whole-or-`unchanged` heartbeat on the
  `Have` stream under R2 and states that under R1 "a node that starts no round sends no inventory"
  and `NOT HEARD FROM` is disabled. **Row 1 (ruled, ledger row 26)**: under R1 too, a heartbeat
  frame on the connection sent by the connection owner every 30 s whether or not a round starts
  (the inventory round's own frame with an `unchanged` form); SY-22's "disabled" sentence is to
  be replaced by it. There is no variant of this ADR without the row.
- **ADR-046 SY-14 (held versus applied)**: r3's `control_through` advances on **held** control
  headers and needed bodies. **Row 2**: expose both positions, `control_through` (held) and the
  fold's applied position per author (SY-3), with the pending set, each pending entry's kind and
  what it waits for (a context hash, a parent header position, the fold), so TR-1's
  `control_held`, `control_applied` and `oldest_dependency` read them; nothing in the fold's
  pending set is dropped at the boundary; a proof of absence that advances `control_through` is
  reported as such (it is coverage, not an entry).
- **ADR-046 SY-14 (availability)**: r3's per-peer availability overlay (`Held` answers), negatives
  per (peer, A, range), and their invalidations (overlay dropped when the peer's `Have` for A
  changes or it disconnects). **Row 3**: expose them in SY-20, with `intervals_total`, so TR-1's
  holders read the same overlay the scheduler selects from, and an `unknown` state for a position
  no inventory, overlay or negative covers; under R1, `Probe`/`intervals_total` or `unknown` for
  every uncovered position, never "no holder".
- **ADR-046 SY-14 (Head refresh)**: r3 raises `Head` only for a size or head not yet accepted.
  **No ask**: this ADR prints `head_age` and never guards on it (TR-24).
- **ADR-046 SY-15 rule 7 / SY-24 (classes and clocks)**: r3 stamps `last_request_at` and
  `start_reason`. **Ask**: `last_request_at` and the in-flight set **per demand class** (sync
  class: everything SY-14 derives; key class: key-package and pairwise work), and per runnable
  demand its eligibility inputs (entry time, holder connected at, last answer or refusal at,
  `Busy` until), so TR-25's missed-start age reads them.
- **ADR-046 SY-20** (applied in r2/r3): advertised shown apart; `control_current`; retention ledger
  per node by actor; slot owners by name. **Ask**: the body-completion and body-chunk events with
  author and position; `head_age` per author with its source; the fold-application and
  key-installation events; `held_through` from inventories as body-complete positions.
- **ADR-046 SY-24** (applied): `start_reason` values `budget_exhausted` and `cannot_save` (the
  replacement's; `retained_flows_full` and `retirement_failed` were v0.4.30's pool, which the
  replacement deletes) **(r10)**; every slot and permit owner by name.
- **ADR-046 SY-13/SY-7 and SY-21** (applied): no wire code for "header absent"; `ProtocolLimits`
  only for a real limit; `TransportFailed` only for transport.
- **ADR-040 NW-1/NW-4**: the `failed` line's form (TR-23); prerequisite words rendered as TR-11
  says; `StoreRecovery(room)` as ADR-046 asks.
- **ADR-048 TC-8** (its own ids; ADR-040's NW-12 stays in ADR-040): the `PoisonCause` set has no
  trust-pass member (TR-12); `vox computer status`'s three sentences are TC-8's, carried in TR-23
  and Appendix A; `not trusted` in `vox room members` (X048-9); the debt JSON (X048-10) in
  Appendix A **(r10)**.
- **ADR-049 (ex NW-6, NW-7, NW-15)**: the ended verdict line and the app's `— ended` row are TR-2's
  and TR-22's, proved in its end journey; the leave prints TR-16's unconfirmed-entries sentence
  (with the `cannot tell` form when the room cannot be read) and requires `--yes`; a stalled node's
  leave and end succeed (SY-24's `Retire::Deleting`).
- **ADR-050 (ex NW-10)**: its refusal texts follow TR-11; no agent-invocation act (ruling Q1).
- **ADR-044 RD-4**: unchanged; TR-1's summaries are maintained at the fact's edge and publication
  reads them only. **RD-7, RD-9, RD-11**: TR-8's words and the APPARATUS rule.
- **ADR-047 SO-1/SO-2**: nothing (ruling Q1).
- **ADR-045 J2(c), J3(c), J10(a), FG-12, FG-13**: migrate to TR-1's fields and TR-2/TR-24/TR-25's
  lines; the fleet's stageable scheduler stall is SY-24's full-volume trigger with a real sibling
  (TR-25's act); drop every mixed-version act (the decider, 2026-11-13); the proofs here each run
  under 130 s and fit the 8–10 hour gate.
- **ADR-041 RS-3, RS-5, RS-15** (r8, re-check passed): it prints the words and facts for the
  Locked line, `unsupervised`, the login item and the four reset lines; this ADR owns the layout
  rows (Appendix A). No doctor line of this ADR names a restart **(r11: R8)**.
- **ADR-043 CJ-1, CJ-7, CJ-17** (r13) **(r12: F5)**: `vox computer status` prints CJ-1's `last
  heard <dur> ago` with this ADR's words and CJ-7's reach fact `offline, last seen <dur> ago
  (dial failed at <time>: <reason>)`, only after a dial from this computer failed at that time
  with that reason; `not receiving` is a room fact (TR-4) with no computer-level meaning and
  never appears there; CJ-17 adds no anchor row to `vox computer status` and asks none of this
  ADR.
- **ADR-051** (r1, in review): the installer's refusal lines for a binary below the supported
  floor are ADR-051's own; no status or doctor line of this ADR reports the floor (out of this
  ADR's scope) **(r11)**.

## Implementation order and related work

1. TR-17 and TR-18, independent: every later proof reads the log.
2. TR-11 and TR-12 (typed errors, poison cause, settlement event). ADR-048 lands the non-poisoning
   release.
3. TR-1, TR-24, then TR-2–TR-7 and TR-25: the summaries, `last_entry`, `head_age`, the dependency
   clock, the per-class request clocks, the coverage; then `diagnose`, text, JSON, metrics; deletion
   of `room-stale`, the epochs and the `last sync` text. Needs every row of the observation
   contract from ADR-046.
4. TR-8 and TR-9 (text only).
5. TR-10 (needs TR-1's `control_current` and `head_age`).
6. TR-19–TR-21 (independent of 3; shares `diagnose`).
7. TR-13 and TR-16 (TR-16's leave sentence needs ADR-049's leave) and TR-22, TR-23 **(r10: TR-14
   and TR-15 are withdrawn and ADR-047 is owed nothing)**.

Experiments (they calibrate; neither settles a cause; none was run for this revision):

- **E1, the patience constants.** On the journeys TR-4 and TR-25 name (quiet-to-busy, a slow
  holder at 300 ms, a 12 MiB body, a join, a reconnect, a laptop sleep/resume staged by a network
  change), sample `vox status --json` at 1 Hz and record, per author, the distribution of
  `now − oldest_since` at delivery and, per demand, the delay from eligibility edge to first request
  start. `RECEIVE_PATIENCE` is set at the p99 of the first plus 30 s margin, at least 60 s;
  `ASK_PATIENCE` at the p99 of the second plus 15 s, at least 30 s; `INVENTORY_FRESH` stays three
  heartbeats. The proofs' bounds move with them. Not run.
- **E2, headless `notify-send`.** A Linux VM with `libnotify-bin`, a session bus
  (`dbus-run-session`), `DISPLAY` set and no notification daemon; two runs **(r11: R6)**. The
  **v0.4.30 run**: the attention event is one v0.4.30 can raise there reliably,
  `peer-unreachable` (`status.rs:383-385`: `room-stale` measures `now − room.last_sync` with the
  daemon's start as the fallback, so every completed round, an empty or control-only one
  included, refreshes `last_sync` while a body stays missing, and a withheld body is no dependable
  `room-stale` trigger **(r12: F7)**); the staging is a trusted member that this node has reached
  once (`last_seen` set, which `status.rs:407-425`'s branch requires) and whose daemon is then
  stopped, `peer-unreachable` within its 60 s bound; recovery is the member's daemon started
  again. Expected on v0.4.30: the GDBus error and a recovery line
  up to 120 s late. The **candidate run**: TR-4's apparatus holder (a signed head, coverage, one
  body withheld) raises `room-not-receiving`; recovery is the body served; expected: one line and
  both notices within 10 s. Never on the operator's machines.

## Consequences

### Positive

- A person reads one verdict per room from a total table, and the verdict says what it rests on:
  the heads this node has verified, how many members have said what they hold and how long ago. A
  newcomer never reads "up to date"; a node that has verified nobody reads `checking`; a held
  key-blocked post ten seconds old reads `catching up`, never `up to date` and never an alarm.
- A node with runnable demand that starts nothing says so within `ASK_PATIENCE` + 5 s of its last
  start, with the scheduler's own reason, and its sibling says it too. For robert-work this is a
  conditional claim: the snapshot shows the state, not the node's start history (Appendix B).
- An agent is never sent to another computer on a trust verdict older than the author's own word.
- No command rebuilds or rejoins a room in v0.4.31 (ruling Q1); the manual leave says what it
  deletes. A member this node cannot reach is a fact on its line, not an alarm (ruling Q5).
- Two days of logs survive an incident and the restarts after it, torn line included.

### Negative

- `vox status` text changes shape; every proof and script that reads it is updated in the same
  change.
- A member can make this node show `advertised … unverified` by advertising a size it does not
  hold; nothing else follows from it.
- The inventory heartbeat is one small frame per room, member and 30 s (ADR-046), under either
  mechanism (ruling Q6).
- Three `test-knobs` knobs (`VOX_TEST_SAVE_WORKER_PANIC`, `VOX_TEST_SYNC_STARTS_BUDGET_FILE`,
  `VOX_TEST_HOLD_PREPARATION`) exist in the proof build and not in the release asset.

### Neutral

- The log ring costs 24 MiB per daemon (ruled: Q4).
- The control-socket `MemberConsents` frame and the `NodeEvent` set change; client and daemon are
  always one version.

## Links

- ADR-006 S-10/S-12, ADR-011 38a, ADR-018 §8b, ADR-025 S0b, ADR-026 G-1, ADR-028 K-7, K-9, L-4,
  ADR-034 HL-1, HL-2, LG-1–LG-3, ADR-036 H-1, H-6, ADR-037 R1, R8, ADR-038 FX-16, FX-17, FX-29,
  FX-35; PRD-001 R35–R37.
- v0.4.31 lanes: ADR-040, ADR-041, ADR-043, ADR-044, ADR-045, ADR-046, ADR-047, ADR-048, ADR-049,
  ADR-050.
- Fix list items 49–56, 69–73, 85–87; 49b, 54b, 54c, 55b, 56b; `adr-042-sol-review.md`;
  `adr-042-sol-review-2.md`; `adr-042-sol-review-3.md`;
  `adr-042-revision.md`; `rca-RcaSchedStall.md`; `arm-repair.md`.

## Appendix A — The measures: source, blind spot, JSON name

Per room (`.rooms[]`):

| Measure | Definition | Source | Blind spot | JSON |
|---|---|---|---|---|
| coverage | sources / other members; oldest fresh inventory age; oldest `head_age` | inventories, `Head` answers, connections | a connected member that sends nothing is not a source; a verified head may be stale | `coverage: {sources, members, oldest_inventory_ms, oldest_head_ms}` |
| behind | Σ `wanted(A)` | own holdings against `size_known` | never more than the authors have signed | `entries_behind` |
| trust to check / pending | authors with `control_held < size_known`; authors with `control_applied < control_held` | `control_held`, `control_applied`, `size_known` | coverage to verify, not a count of entries | `trust_to_check: [ids]`, `trust_pending: [{id, waits_for}]` |
| unreadable | Σ `unreadable(A)` with causes | the applied projection and held keys | — | `unreadable: {count, by_cause}` |
| older history not here | positions below the anchor not held | own holdings | a fact, not a fault | `older_not_held` |
| last entry | newest delivery of another member's complete entry or applied control entry | the admission path | a header or chunk alone does not count | `last_entry_ms` |
| last request started; missed-start age | per class (sync, key) | the scheduler (ADR-046 SY-15 rule 7) | the age counts from the later of the oldest eligibility edge and the latest class start | `last_request_at_ms: {sync, key}`, `missed_start_ms: {sync, key}`, `runnable: {sync, key}`, `last_start_refusal: {reason, first_error}` |
| verdict | TR-2 | all of the above | — | `verdict` ∈ {`ended`,`leaving`,`preparing`,`cannot_save`,`only_this_node`,`no_inventory`,`not_asking`,`not_receiving`,`cannot_read`,`waiting_for_member`,`checking`,`catching_up`,`up_to_date`} |
| last round | newest completed round | the lane | activity only | `last_round_ms` |

Per member (`.rooms[].members[]`): `size_known`, `head_age_ms`, `head_from`, `size_advertised`,
`advertised_by: [ids]`, `advertisements_disagree` (bool), `inventory_at_ms`, `anchor`,
`control_held`, `control_applied`, `oldest_dependency`, `dependency_since`, `headers_through` (the contiguous prefix, kept for diagnosis), `held_intervals`,
`headers_without_text`, `headers_without_text_oldest_ms`, `behind`, `oldest_wanted`,
`oldest_since_ms`, `oldest_holders: {positive: [ids], possible: [ids]}`, `byte_progress: {position,
bytes, of}`, `unreadable: {count, cause, since_ms}`, `readable_rows`, `fork` (bool),
`last_received_from_ms`, `last_sent_to_ms`, `in_flight: [{age_ms, what}]`, `held_through`
(body-complete positions of this node's feed it reports), `behind_this_node`,
`last_request_from_ms`, `reach`, `trust_inbound` (TR-10's state with `as_of`, `size_known`,
`head_age_ms`, `head_from`, `connected`, `key_held`).

Per node (`.sync_node`): `slots: {in_use, owners: [{peer, room, what, age_ms}]}`, `permits:
{in_use_bytes, limit_bytes, owners: [{peer, room, what: "exchange in flight" | "answer awaiting
admission" | "answer awaiting store recovery" | "answer awaiting context <hash>", age_ms}]}` (the
one schema; ADR-046 SY-24; X046-4; **r12: F6**), `rendered_rows`,
`backfill_queued` per room **(r10: no `retained_failed`)**. Per port, in `vox status --sync` and
`--json .lanes.ports[]` (X045-13, kept from v0.4.30's `lanes_json`, as ADR-046 SY-24 keeps it
**(r11: R11)**): `queued`, `round_running`, `start_age_ms`, `start_class` (`sync` | `key`),
`start_reason`; the per-(room, peer) counters of ADR-025 S0b stay under `--json .sync[]`; the
per-member sync facts of ADR-046 SY-20 live under `--json .peers[].sync` and `.peers[].served`.

Health keys: `room-no-inventory`, `room-not-asking` (TR-25), `room-not-receiving` (TR-4),
`member-unreadable` (TR-5), `waiting-for-member` (TR-2 row 6, TR-19's predicate), `sync-failing` (TR-6),
`room-store` (unchanged; ADR-047's two `cannot save` forms print under it), `checkpoint-dispute`
(ADR-046 SY-27, below). `room-flow-state-pool` is deleted with the pool (ADR-046 SY-19) **(r10)**.

### Lines and fields other ADRs ask this ADR to carry (r10)

Each row: the surface and exact text or JSON, the asker's requirement that owns the fact, and the
requirement here that renders it. Words marked † are this ADR's proposal where the asker gave none
("042 proposes; asker to confirm" in `adr-042-revision.md`); every other text is the
asker's, quoted from its snapshot at `984c5593b`.

| Surface | Exact text / JSON | Owner | Rendered by |
|---|---|---|---|
| room block, after the `holds` row | `fence post: <age> old, at <N> entries behind the room's newest confirmed entries; catch-up since it: about <M> entries, est. <B> MB` (N, M from accepted signed heads only; B = M × 0.21 × 3.7 KB, an estimate) | ADR-046 SY-27 | TR-2 room block |
| room block JSON | `.rooms[].fence_post: {age_ms, behind, catch_up_entries, catch_up_bytes_est, adopted_at_ms}` (confirmed, ADR-046 r10; `adopted_at_ms` **(r11)**) | ADR-046 SY-27 | TR-1 |
| member line | `advertised, unverified: <k> more by <member>` (replaces TR-3's `+ <a> advertised by <id>, unverified`) | ADR-046 SY-27 (TR-1's `size_advertised`) | TR-3 |
| room block JSON | `.rooms[].bytes_before_access`: bytes received on the room's sync streams between `joined` and the first moment every member's post-join entry is rendered on this node (ADR-046 r10's definition, confirmed; per room, cumulative from `joined`; SY-27's access event, not the first readable page) **(r11: R10)** | ADR-046 SY-27 (confirmed, `adr-046-revision.md` "Status rows") | TR-1 |
| room block, once; `vox agent doctor`'s room summary | `adopted the creator's fence post of <when> at <position>` (`.rooms[].fence_post.adopted_at_ms`) (ledger row 76) | ADR-046 SY-27, SY-28 (added r10) | TR-2 room block |
| room block | `no fence post: verifying from the start`, or above the limit `no fence post: the room's membership summary (<size>) exceeds this release's 1 MiB limit` (the limit is the encoded answer, framing included, ADR-046 r11) (`.rooms[].fence_post: null`, `.rooms[].fence_post_absent_reason`) | ADR-046 SY-27 (added r10; limit r11) | TR-2 room block |
| room block and `UNHEALTHY:` | a member that did not adopt a newer checkpoint says why, one sentence per cause **(r12; r13: G2)**: a declared or encoded size over the limit → `creator checkpoint <hash> declares a <size> summary, over this release's 1 MiB answer; using the fence post of <when> instead` (or `…; verifying from the start instead`) (ADR-046 r11's words); a `Snapshot` answer whose decoded length differs from the declared `summary_len` → `creator checkpoint <hash> declares a <declared> summary but <received> arrived; using the fence post of <when> instead` (or `…; verifying from the start instead`) (042's words; ADR-046 SY-27's receiving branch routes both causes to one sentence today and is to carry the cause); both are rejections before installation, both recorded under `checkpoint-dispute:<room>` like a dispute, neither is author-fork evidence. *Proof arm* (in ADR-046 SY-27's rejection journey, the words this ADR's): a creator-signed checkpoint declaring 512 KiB whose answer decodes to 480 KiB is rejected and the room block prints the length sentence with `512 KiB` and `480 KiB` and never `over this release's 1 MiB answer`; the over-limit arm prints the over-limit sentence; mutant: route both causes to the over-limit sentence; the under-limit arm's assertion fails; red, PRODUCT | ADR-046 SY-27 (r11; the cause split is a shared change for ADR-046) | TR-2 room block; TR-13; TR-22 |
| room block and `UNHEALTHY:` | `creator checkpoint <hash> disagrees with this node's record`; `creator checkpoint disagrees with <A>'s chain`; the adoption variant `creator checkpoint <hash> disagrees with this node's record; verifying from <position> instead`; key `checkpoint-dispute:<room>` (confirmed) | ADR-046 SY-27, SY-28 (a dispute, not fork evidence) | TR-2 room block; TR-13; TR-22 **(r11: R9)** |
| member line `<feed state>` | `CutAttestation by <m> for <removal> exceeds what it held`; a removal with no accepted attestation: `cut unattested`; two differing accepted attestations: `cut attested through <t> by <m> and through <t'> by <m'>; the higher applies` (`.rooms[].members[].cut: {state: "attested" \| "unattested" \| "exceeded", claims: [{by, through}]}`) (confirmed; the claims list **(r11)**) | ADR-046 SY-3 | TR-3 |
| member line `<feed state>` | `<A>: <n> newer entries held unproved; waiting for a member that holds <A>'s entries <from>–<to> or <A>'s proof` (`.rooms[].members[].unproved: {count, from, to}`; `count` is observed headers, not accepted entries) (confirmed) | ADR-046 SY-11 | TR-3 |
| TR-2 row 12 `<parts>` and condition | `waiting for a member that can prove A's head from size <s>, or A itself`; the row-12 condition includes an observed newer head with no provable bridge (confirmed; condition **(r11)**) | ADR-046 SY-13 rule 3 | TR-2 |
| node block | `sync slots: <s> in use (<owners>); permits: <p> of <limit> MiB (<owners with state>)`; `.sync_node.permits: {in_use_bytes, limit_bytes, owners: [{peer, room, what: "exchange in flight" \| "answer awaiting admission" \| "answer awaiting store recovery" \| "answer awaiting context <hash>", age_ms}]}` (confirmed; owner states **(r11: R1)**) | ADR-046 SY-24 | TR-25 |
| `vox room read --history resume` after a restart | `no page in flight since the daemon started; ask again with --before X` | ADR-046 SY-9 | TR-23 |
| `vox room read --history older`, byte-cut page | `<n> older rows did not fit this page; ask again with --before <oldest shown>` (confirmed) | ADR-046 SY-9 | TR-23 |
| member line | `last sent to it <dur> ago` means a completed served round that moved an object (`.rooms[].members[].last_sent_to_ms`) | ADR-044 RD-3; ADR-046 SY-20 | TR-3 |
| `vox status --json` | `.sync[].exchange_ms: {last, median, p90, max}` per (room, peer): `last` the wall time of the most recent completed exchange toward that member (start to last frame), `median` its p50 over the last 32 exchanges, `p90`, `max` over the same window; milliseconds (ADR-046 r10 confirmed this shape over SY-20's `peers[].sync.last_exchange_ms` / `exchange_ms_p50`, which SY-20 is to cite). ADR-045 FG-5's slow-path witness is `peers[].rtt_ms`, a different measure **(r11: R11)** | ADR-046 SY-20 (confirmed); ADR-045 FG-5 reads it as a diagnostic | TR-1 |
| `vox status --json` | `.rooms[].pending_owners: [{kind, state: "holding" \| "queued", since_ms}]` † (the room's pending-write queue in enrolment order; `kind` ∈ post, drive-admission, received-admission, session-move, projection, governance, key-package, node-save) | ADR-044 RD-10 | TR-1 |
| `vox status --json`; `--sync` text | `.lanes.ports[].inbound_admissions: {held, limit}` † per port: RD-16's inbound serving admissions (`INBOUND_PER_PORT`), not ADR-044 r14's withdrawn durability tokens; text `inbound: <held> of <limit> serving admissions` **(r11)** | ADR-044 RD-16 | TR-1; TR-2 lanes |
| `vox status --sync` per port | `could not serve <A>@<p>–<q>: not held here; the peer asks another holder` (`EvidenceUnavailable`, served side) (confirmed, ADR-046 r10) | ADR-044 RD-9; ADR-046 SY-21 | TR-2 lanes |
| `vox status --sync` per port; JSON | `refused <what> from <peer>: <reason>`; `.peers[].served.last_refusal: {reason: "Busy" \| "NotMember" \| "NotHeld" \| "EvidenceUnavailable" \| "Malformed", at_ms}` (ADR-046 SY-21's path and reasons) **(r11: R11)** | ADR-044 RD-16; ADR-046 SY-21 | TR-2 lanes |
| node block | `store: <f> GB file (<d> GB of disk), <u> GB in use, <b> GB of data; disk: <free> GB free (Vox stops saving below <floor> MB)` (+ `; sampled <n> s ago` when the report reuses a stats sample older than the tick) and `  last rewrite <time>: <from> GB file → <to> GB file (<disk> GB of disk) in <s> s`; `rewrite due: needs <n> GB free; the disk holding <dir> has <m> GB` when due and not possible, `rewrite due: <reason>` otherwise **(r11: R13)** | ADR-047 SO-15, SO-10 | TR-2 node block |
| room block, after `messages: …; Session steps: …` | `stored here: <total> — messages <m>, Session steps <s>, openings and ends <l>, indexes <i>, keys <k>, sync records <y>` (`counting` until seeded) | ADR-047 SO-15 | TR-2 room block |
| `vox status --json` | `store: {file_bytes, file_disk_bytes, in_use_bytes, data_bytes, packed_bytes, free_disk_bytes, floor_bytes, ballast_bytes, file_bytes_at_start, in_use_bytes_at_start, growth_per_hour_bytes, last_rewrite: {at, from_file_bytes, to_file_bytes, to_disk_bytes, seconds, kind} \| null, rewrite_due: null \| "<reason>"}`; `rooms[].store: {messages_bytes, steps_bytes, lifecycle_bytes, index_bytes, key_bytes, sync_bytes, staged_bytes}`; `store.redb: {stored_bytes, allocated_pages, leaf_pages, branch_pages, sampled_ms}` (the `stats()` sample SO-15 takes each maintenance tick, at most once a minute, with its age; SO-15's proof reads it; **r12: F6**); `growth_per_hour_bytes` is of in-use bytes; a fence-post summary's bytes are `index` (ADR-047 r11) **(r11)** | ADR-047 SO-15 | TR-1 |
| room line (TR-2 row 3) | `preparing: removing sync records, <n> left`; `preparing: rewriting the store (<f> GB file, <u> GB in use, <b> GB of data); saves wait until it ends`; `preparing: compacting the store`; `preparing: recovering the store: waiting for <what>`; `preparing: recovering the store: could not reopen it: <error>; trying again in 5 s`; `preparing: recovering the store: could not confirm it: <confirming commit \| repair>: <OS error>; trying again in 5 s` (SO-12 r11's post-open failure, before any root is published; the whole line, tail included **(r12: F6)**) **(r11: R13)**; `the upgrade needs <n> MB to continue`. A recovering room still answers held facts from memory (SO-12) | ADR-047 SO-2, SO-10, SO-12 | TR-8 |
| room line (TR-2 row 4) | `cannot save: the disk holding <dir> has <n> MB free; Vox keeps <floor> MB free. It saves again by itself when space is freed.`; `cannot save: the store is recovering`; the deferred form `cannot save: the disk holding <dir> has <m> MB free; <compacting the store \| removing room <name> \| expiring old steps in <name> \| cleaning up <name>'s sync flows> needs <n> MB more (free that much, in any file, and Vox continues by itself)` (SO-12 r11; `.rooms[].last_start_refusal.cause` ∈ `floor` \| `recovering` \| `deferred`) **(r11: R13)** | ADR-047 SO-11, SO-12 | TR-2 |
| node block | `the store at <path> could not be opened: <redb's words>; it has not been changed` | ADR-047 SO-9 (ruling 48) | TR-2 node block |
| `vox room join` refusal | `vox: cannot join <name>: the member could not write the join to its store` / `       try again later, or join through another member` (two lines; no OS detail travels) (ADR-047 r11's words) **(r11)** | ADR-047 SO-14 | Appendix D |
| `vox computer status` | TC-8's three sentences (parked, permanently refused, closed), verbatim in TR-23; a room with a leave record is not listed (its debt is cleared at ADR-049's erasure batch); TC-8's six daemon-log lines are ADR-048's own, in TR-11's form (ADR-048 r7) **(r11)** | ADR-048 TC-8 | TR-23 |
| `vox computer status --json` | per node `debts: [{room, name, nodes: [{fingerprint, computer}], waits_until, since_ms, state: "parked" \| "refused" \| "closed", refusal?}]`; `vox status --json .waiting[]` entries of kind `trust-debt` use TR-23's shape with `what = "trust withdrawal"` | ADR-048 (X048-10) | TR-1; TR-23 |
| `vox room members` trust column | `not trusted` for a member the keyring does not trust | ADR-048 TC-8 (X048-9) | TR-10 |
| rooms block | `left <room>: no member could be told in 2 days; deleting<, waits until <prerequisite words>, for <dur>>; members list you until one of them learns otherwise` (`outcome: Expired`, not `Erased`; the `waits until` clause only while the erasure is parked, never fabricated) **(r11)** | ADR-049 LE-4 | TR-8 |
| rooms block | `left <room>: no member could be told in 2 days; deleted; members list you until one of them learns otherwise` (24 h from `Erased`) | ADR-049 LE-4 | TR-8 |
| rooms block and the daemon log, once | `<room>: the room's data is deleted; what is left of it in this node's data file is cleared at the next rewrite, and until then only someone who holds that file and this node's passphrase could read it` (at `Erased`) | ADR-049 LE-4 (ruling 61) | TR-8 |
| rooms block | `joining <name>: waits until its old copy is erased` | ADR-049 LE-9 | TR-8 |
| `vox status --json` | `.left[]`: `{room, name, departure_ms, departure, outcome, erasure, continuity, rejoin, sources, carry_estimate_bytes, members: [{id, reach}]}` with ADR-049's values (`reach` in row 27's words; `sources` the count of this author's source header rows still held by the hidden copy, LE-4 stage (c), non-zero until stage (d); `carry_estimate_bytes` the next carry batch's estimate, 0 when no carry is owed; ADR-049 r12 **(r13)**); `.withdrawals[]`: `{room, scope, wire_hash, instance, state: "pending" \| "complete", answer_rows, routes: [{board, instance, answered}]}` (`answer_rows` the count of W3 rows still held for the wire, equal to the answered routes while `pending`, 0 during W5b **(r13)**; the route set is W2m's for a `Member` wire and W2r's for a `Room` wire; ADR-049 r10); top-level `.publications[]`: `{room, instance, board, state: "attempted" \| "published", frozen}`, one per publication row while the row exists, after erasure and across instances included (replaces `.rooms[].published[]`) **(r11: R12)**; the disk figures are ADR-047 SO-15's `store.free_disk_bytes` and `store.floor_bytes` (ADR-049 r12 D9 adopts them; no `.disk.free` or `.disk.free_bytes` exists **(r13)**) | ADR-049 LE-2, LE-5 (r10) | TR-1 |
| `vox room roster --history <room>` | per member, in feed order: `<id> left at <time>`, `<id> back at <time>` | ADR-049 LE-9 (words this ADR's) | TR-23 |
| `vox status` `waiting` block | omits, in text only, obligations parked on `StoreRecovery(room)` of a room whose `cannot save` line is printed; `.waiting[]` carries them | ADR-040 NW-4 (X040-4) | TR-23 |
| node block | `node <n>  Locked: its remembered passphrase is no longer in this computer's memory (keyring: <kernel text>)` (or RS-3's credential variant `Locked: its systemd credential <name> was not given to the daemon`) / `Unlock it once: vox node unlock <n>`; `unsupervised: <why>`; `the login item is waiting`; the four factory-reset lines `a factory reset begun <time> did not start; nothing changed` / `… stopped the daemon and moved nothing` / `… moved the old data to <to>; this folder is new` / `… cannot be reconciled: <root> is not the folder it recorded and <to> <is missing \| is another folder>; nothing was changed; see <journal path>` (ADR-041 r8's words) **(r11)** | ADR-041 RS-3, RS-5, RS-15 (r8) | Appendix C layout |
| `vox status --json` | `.daemon: {supervised: bool, unsupervised_why: "enrollment broken" \| "the manager refused: <answer>" \| "no manager is enrolled" \| null, login_item: "running" \| "waiting" \| null, factory_reset: {begun_ms, state: "did-not-start" \| "stopped-moved-nothing" \| "moved" \| "cannot-reconcile", words} \| null}` † (`supervised` is the hello's `supervised` fact, not the launch method) **(r11)** | ADR-041 RS-5, RS-15 (open: ADR-041 to confirm the names) | TR-1 |
| `vox computer status` | CJ-1's `last heard <dur> ago` (this ADR's words) and CJ-7's `offline, last seen <dur> ago (dial failed at <time>: <reason>)` after a failed dial from this computer; no `not receiving`, no anchor row (CJ-17 adds none) **(r12: F5)** | ADR-043 CJ-1, CJ-7, CJ-17 (r13) | TR-23 |
| any status or doctor row about a conversation's provider error | none: after a terminal provider error on a step that carried room news the conversation stops using Vox and says so in one sentence (ADR-050, ledger row 79); this ADR has no "delivered after an error" or pending-delivery state and names none **(r11)** | ADR-050 (ruled) | — |
| `vox status` room block; `--json .rooms[]` | `own history recovery is pending`; `.rooms[].own_feed: {head, recovery_target, members: [{id, held_through}]}` (this author's own signed head in the room; the highest verified supplied head while recovery is pending, `null` otherwise; per member, the highest position of this author's feed that member's last `Have` reported, **body-complete**, the same measure TR-16 counts from); `.rooms[].admissions[]: {member, count}` (how many times this node admitted each identity since the room was created or joined here) (ADR-049 r12's words, LE-9) **(r13)** | ADR-049 LE-9 (r12) | TR-1; TR-16 |
| `daemon log:` line; JSON | `daemon log: <path> (keeps 24 MiB in 8 files; oldest line <time>)`; `.log: {path, keep_bytes, files, oldest_line_ms}` † (`log_path` stays for the app's reader) | this ADR (TR-17; ADR-034 LG-3) | TR-17 |
| Vox.app Settings, the daemon-log row (`apps/macos/Vox/Settings.swift`, `DaemonLogSetting`, accessibility `settings-daemon-log-path`) | `Daemon log: <path> (keeps 24 MiB in 8 files; oldest line <time>)`, read from `.log` | this ADR (LG-3's app half) | TR-17; TR-22 |

## Appendix B — The four incidents, replayed as conditional replays against the saved files

Each replay states, first, the **measured facts** (with file), then the **prerequisites** this
ADR's lines need and whether the files supply them, then the **lines** a person would have read and
the **earliest time** they could have appeared under those prerequisites. A time is given only when
it is derived from a named file; otherwise it is "not derivable". No `wanted`, `unreadable`,
`oldest_since`, inventory, head or request-class value exists in any saved file; those are printed
as `<N>` or as bounds with their source.

**(a) omp-io, 19:36:38.567Z–22:30Z.**

*Measured.* Join at 19:36:38.567Z (`io/daemon-202624Z.log:3157`); daemon restart, node Ready at
20:19:29.309Z (`:3824`). At 20:04:54Z (`io/status-omp-io-200453Z.json`): six foreign members
connected, `log_entries` 70, `own_feed_through` 21 (foreign entries 49), `entries` 5 (all own),
governance 44, foreign prefixes 13/7/8/3/12/6, `received_key_generations` 6. At 20:20:11Z and
20:27:32Z: 72/23 and 76/27 (foreign 49, 49), revision 44. At 21:50:43–21:51:03Z
(`quiet-fullstate`): 97/48 (foreign 49), revision 45, `entries` 14 (own), the same prefixes;
`history_fetched` 3,429/5,568/5,745 toward ehu3/nqpf/nyty against 536/811/765 at 20:04Z.
`discrim-ompio`: `hf` +28 (nqpf), +48 (nyty) in 29 s, `holds` unchanged. The Mac at 20:04:54Z held
2109/1075/241/834/84/15 of the same authors and 4,379 entries (`mac/status-omp-work-200453Z.json`).
So: **the recorded count of other members' log entries is 49 at 20:04:54Z and 49 at 21:51:03Z,
across a daemon restart, while worker activity rose by thousands.** Equal counts do not exclude a
body refill or a control application between samples (both are deliveries under this ADR);
which 49 they were, and whether any was a complete content entry, is not derivable (`entries`
counts rendered rows; the rows were all own).

*Prerequisites.* `size_known` per author (a `Head` answer): not in the files; the members'
inventories were exchanged every round (`reasons.hint` 334–632 per peer), and under ADR-046 SY-14 a
size above `size_known` raises a `Head`, so `size_known` would have followed within one exchange of
each inventory; the prefixes 2109 … 15 the Mac held at 20:04Z are a lower bound on what a `Head`
would have shown. Positive holders: the Mac's inventory would have named intervals covering its
holdings (lower bound: the Mac alone, 1 of 6). `oldest_since`: the first wanted position's entry
time, between the join and the first `Head` answer: not derivable. Whether the scheduler was
starting sync-class requests (TR-25 versus TR-4): **an inference, not derivable** from a status
file; `running` was non-empty in some discriminator samples (nqpf, an exchanging round 12 ms old
at 20:57:59Z) and `completed` rose, which is consistent with starts, so the replay below assumes
TR-4's alarm and not TR-25's.

*Lines.* Earliest `NOT RECEIVING`: `oldest_since` + 60 s + ≤ 5 s. **Not derivable**: no file
holds `oldest_since`. Under the explicit hypothesis that the first wanted position entered at the
join itself and had a positive holder from then on, with no delivery, the first check would fall
in 19:37:38.567–19:37:43.567Z; this is conditional arithmetic, not a measured onset. At 20:04:54Z,
under the same hypothesis:

```
UNHEALTHY:
  ! room o6z3enlc2ymd (repo-to-cve): NOT RECEIVING: <N> entries behind; <A>@<p> not delivered for <dur: not derivable> though <h ≥ 1> members that hold it are connected (<r> requests in flight for it, oldest <dur>; last answer from <id>: <refusal>)

rooms
  o6z3enlc2ymd repo-to-cve  NOT RECEIVING: <N> entries behind; <A>@<p> not delivered for <dur> though <h> members that hold it are connected  as of <k ≥ 1> of 6 members' inventories (oldest <dur> ago); heads verified <h'> ago
    holds 70 log entries (5 readable rows); older history not here: <O> entries, fetched on request
    trust to check: <m ≤ 6> members (…)
    nqpflbs54itp  trusted  connected  inventory <dur> ago; head verified <dur> ago; last entry from it <not derivable>
      its feed: <S ≥ 2109> entries verified; <B> behind here; oldest <p> held by <h> members
      it holds this node's feed through 17
```

`<N>`, `<A>@<p>`, every `<dur>` and the ages at 21:51Z are **not derivable**: anchors, the first
`Head`, the oldest obligation and its continuity across the restart are not in the files, and the
summaries are in memory, so after the 20:19:29Z restart the clocks would have started again from
the first inventory. The doctor at 20:30Z (TR-10): six times `warn  trust <name>: you trust it;
this node cannot yet tell whether it trusts you: its trust is not checked through positions
<control_held+1>–<size_known> yet` with `fix: nothing: do not change trust on this evidence`,
provided `size_known > control_held` for each (every member trusted omp-io,
`mac/doctor-omp-work-203823Z.txt:32-37`, so their consent entries existed above what omp-io had
applied; the exact positions are not derivable). The Mac at 20:04Z (TR-5, not-arriving): `! room
o6z3enlc2ymd (repo-to-cve): fylgpqwc4tru is <B ≤ 21> behind here (<M> held without their text,
oldest <dur>); fylgpqwc4tru@<p> not delivered for <dur>`; `<M>` is not derivable (the file holds the
prefix 21 and `entries` 2047; RcaKeys K1 marks the Mac's missing-body cause INFERRED).

*What the person would have done.* Not restarted two daemons on a green status; read `last answer
from <id>` (the sync refusal ADR-046 owns) and the sync block. No local fault is shown by the
files, and the restart's open ran the directory cleanup without effect; a kept TR-14 would have
exited 2.

**(b) the rebuilt omp-io, joined 22:23:01.298Z (`newnode-progress-222537Z.txt`).**

*Measured.* 22:25:37Z: governance 9, log 12, rows 0, 4 key generations received; `holds` ehu3 1,
nqpf 1, mg7b 10, others null; one round running toward rotl for 91 ms; 6 peers with counters.
22:28:35–22:30:39Z (`newnode-watch-222834Z.tsv`, 9 samples ~15 s apart): governance 33 → 35 → 36,
log 53 flat, rows 0; the Mac at 142–146 / 4,889–4,891. 22:32:34–22:32:39Z (`newnode-slot`):
governance 51, one slot, one round "exchanging" 1.5–2.2 s, five ports queued. 22:34:49–22:38:53Z
(`newnode-watch2`, 17 samples): governance 51 flat, log 72 → 73 at 22:36:20Z, rows 0 throughout;
the Mac at 155 / 4,924–4,932.

*Prerequisites.* `size_known`: from the join answer's signed heads (ADR-046 SY-17) at 22:23:01Z,
if the inviter served them: assumed. The +1 log entry at 22:36:20Z: its author and whether it was a
complete body or a header is not derivable. `unreadable` and its cause: 0 rows with 4 key
generations received and governance advancing is consistent with every cause in TR-5; which one is
not derivable.

*Lines.* 22:25:37Z: `catching up: <N> entries behind; trust to check for <m> members; last entry
<dur> ago  as of <k> of 6 members' inventories (oldest <dur> ago); heads verified <h> ago`: the
control entries were being applied (9 → 33 by 22:28:35Z), each a delivery. 22:29:06Z–22:30:39Z:
governance 36 and log 53 flat across 93 s; **22:30:11Z (22:29:06Z + 65 s) is the latest check at
which `NOT RECEIVING` would have printed if** the same oldest obligation was continuously wanted,
had a positive holder, saw no byte progress and no delivery in that span (none of which the TSV
records; a body refill changes neither count); no onset or clearing is derivable (the file ends at
22:30:39Z with 36). 22:34:49Z–22:38:53Z: under the same premises, **22:35:54Z** is the latest
check for an alarm (22:34:49Z + 65 s); the +1 log entry at 22:36:20Z is of unknown author and kind,
and under the oldest-position model it clears the alarm only if it resolved the named oldest
obligation and no other author qualified, which is not derivable: the replay asserts no clearing
and no re-onset. Throughout, the room line reads `0 readable rows` and, once any received author's
bodies were held, TR-2 row 12's `<u> held, not yet readable (<cause>)` and after 60 s TR-5's
`cannot read`; whether any body was held is not derivable (`entries 0` counts rendered rows).
Under this ADR's inputs the verdict is never `up to date` **if** the join answer's signed heads
left `wanted` or trust to check non-empty; local revision 51 against remote 155 does not by itself
prove that (revisions are local). The member line for the peer with the 2.2 s exchange: `in
flight: 1 (2.2s)`.

*What the person would have done.* The same as (a). No local fault; a kept TR-14 would have
exited 2.

**(c) the ended room on robert-work, 00:50Z–02:16Z Nov 13.**

*Measured.* `stall-robert-work-021627Z.json` at 02:16:27.580Z: the room listed; `unhealthy[]` holds
`room-stale:o6z3…` and three `sync-failing:o6z3…: the peer refused: authenticator invalid`; its six
ports queued with Public `start_age` 2,424–2,631 s (newest surviving attempts 01:32:35Z–01:36:03Z); one retiring
flow for it in the ledger. The end at 00:50Z and the `[ended: …]` list marker are ADR-049's record
(ADR-040 r2 §"What the operator saw" item 8, now ADR-049's; the end time, the restart time and
the deletion's wait edge are the operator's and the fix list's reports, not fields of the status
file).

*Lines.* Under TR-2 and TR-6, at every sample after the end:

```
rooms
  o6z3enlc2ymd repo-to-cve  ended: its creator or an admin ended it; deleting<, waits until <ADR-049's edge words>, for <dur>>
```

no `sync failing`, no `NOT RECEIVING`, no `room-stale`; the app's sidebar `repo-to-cve — ended`; the
`waiting` block names the deletion's prerequisite when ADR-049 parks it (the edge is ADR-049's;
with SY-24's discard the room is deleted instead of waiting). The ended room's ports take no
Public start (ADR-049's lifecycle stops offering it); nothing of it reaches TR-25.

**(d) robert-work, snapshot 02:16:27.580Z; restart 02:16:46Z.**

*Measured* (`stall-robert-work-021627Z.json`, `now_ms` 1794536187580 = 02:16:27.580Z): 16 ports
`queued: true`, `round_running: false`, `start_outcome: started`, `start_reason: null`. Each
port's record is its **newest surviving attempt across services** (`actor.rs:17419-17428` assigns
`last_start`; `:17473-17485`: "a later attempt replaces the earlier"), so a Private record on a
port hides any earlier Public start on it, and a Public record says only that no later attempt of
either service was made on that port. Surviving Public records: o6z3 mg7b 01:36:03.111Z (age
2,424,469 ms), o6z3 vdy4 01:36:03.209Z (age 2,424,371 ms, the numeric minimum), kn4j vdy4
01:35:49.908Z, morz nyty 01:35:50.403Z, 5xlv nyty 01:35:50.408Z, o6z3 nqpf, ehu3, nyty and rotl
01:32:35.708Z–01:33:41.073Z.
Surviving Private records: kn4j nqpf 02:11:37.706Z, pcny 02:11:48.428Z, ehu3 02:11:49.160Z, rotl
02:11:49.671Z, nyty 02:11:52.933Z; k4qx nyty 02:15:17.730Z; kh57 nyty 01:40:00.075Z. **The node's
actual last Public start and the stall's onset are not derivable** from this snapshot.
`lanes.slots.in_use` 3 (ehu3 2, rotl 1), `running: [null, null]`, `ready: [null, null, null]`;
`retiring` 11, each `service: Public`, 10 for k4qx toward nyty with `store save room: malformed
at-rest artifact: key-package attempt unacknowledged` and 1 for o6z3 with `node: history
retirement worker stopped`, each `actor: 2` (the budget's actor map: robert-work). The sibling
(`stall-omp-work-021627Z.json`): 0 slots, every port `queued: false`, one round running (k4qx,
10 ms old), **and the same 11 `cleanup_errors`**. Holdings against the sibling at the same second
(log entries): r2c-2 149 vs 284 (135 fewer), vox 180 vs 217 (37), agent-memory 70 vs 75 (5),
ioa-brain 19 vs 19, cve-to-exploit 49 vs 49: differences of holdings, not `wanted`. v0.4.30 raised
`room-stale` for agent-memory, ioa-brain, repo-to-cve and cve-to-exploit and nothing for r2c-2 and
vox.

*Prerequisites.* `size_known` per author: the authors were connected (their own heads would have
answered `Head`); assumed. `wanted`: not derivable (anchors, bodies, `not for you` unknown).
Positive holders: the six connected r2c-2 members' inventories: not in the file. The sync class's
`last_request_at` and the eligibility edges: **not derivable** (overwritten per port; no class
history). The `start_reason`: not recorded at v0.4.30 (the refusal site writes none,
`bounded_sync.rs:4749-4757`); under the replacement the state has no mechanism (no pool, no cap,
ADR-046 SY-19), so the replay below shows what the replacement prints for the node-level state
"wanted entries, a connected holder, nothing in flight, no named wait" (ADR-046 SY-24: must not
occur; a named wait with its `start_reason`), with no reason recorded **(r10)**.

*Lines.* `NOT ASKING` prints 30–35 s after the later of the eligibility edge and the class's
latest start (`ASK_PATIENCE` plus up to one 5 s check). **Hypothesis, stated whole** (r5: D3): a
wanted position with a positive holder existed; its eligibility edge (the latest of its entry,
the holder's connection, the last answer or refusal for it, a `Busy` expiry, a wake, Ready) was no
later than the class's hypothesized latest start; no sync-class work was in flight; no later start
occurred; and the class's latest start was the surviving Public record of its room. Under all of
that, for r2c-2 (record 01:35:49.908Z) the line prints in 01:36:19.908–01:36:24.908Z; for vox and
agent-memory no Public record survives and no interval is given. None of the premises is in the
file; the incident's onset is unknown. At 02:16:27Z, with those prerequisites:

```
UNHEALTHY:
  ! room kn4jydtyqxqx (r2c-2): NOT ASKING: <N> entries wanted from <h ≤ 6> members that hold them; this node has started no request for them for <dur: not derivable>; Vox recorded no reason; this is a fault in Vox, not something you did; keep `vox status --json` for the report
  ! room k4qxsidvqzyd (vox): NOT ASKING: <N> entries wanted from 1 member that holds them; this node has started no request for them for <dur>; Vox recorded no reason; …
  ! room kh57aq2zwdss (agent-memory): NOT ASKING: <N> entries wanted from 1 member that holds them; this node has started no request for them for <dur>; Vox recorded no reason; …
sync slots: 3 in use (<owners by name: not derivable at v0.4.30>); permits: <p> of <limit> (<owners>)

rooms
  morzldlcl3wi ioa-brain  up to date as of all 1 members' inventories (oldest <dur> ago); heads verified <dur> ago
  5xlvaj7fgnzq cve-to-exploit  up to date as of all 1 members' inventories (oldest <dur> ago); heads verified <dur> ago
  o6z3enlc2ymd repo-to-cve  ended: its creator or an admin ended it; deleting …
```

The key-class starts at 02:11–02:15Z do not move the sync class's clock (TR-25). ioa-brain and
cve-to-exploit read `up to date` under the observation contract's heartbeat row (their heads were
verified at the open or earlier and no member advertised newer; the age is printed, not guarded):
the heartbeat is required under either mechanism (ruling Q6), so this is the one replay. Neither
line is the false `room-stale` of v0.4.30. The doctor: `fail  room r2c-2: this node is not asking its
members for the <N> entries it lacks (no request for <dur>): Vox recorded no reason; this is a
fault in Vox, not something you did; keep \`vox status --json\` for the report` and `fix: nothing
to change on any other computer; keep \`vox status --json\` for the report` **(r10: under the
replacement no restart is named; the 11 retained flows of v0.4.30 are a state the replacement
cannot enter)**. The sibling omp-work's status lists nothing of robert-work's and prints for
robert-work (o73v) in r2c-2: `o73vzv3lehwr  trusted  connected  inventory <dur> ago; …`
/ `it holds this node's feed through 30; it is <B'> behind this node and has asked for nothing for
<dur>`: the file supplies own prefix 57 and reported `held_through` 30 (a scalar difference of
27), not the body-complete missing set nor the last inbound request time, so `<B'>` and `<dur>`
are conditional. What the operator did, a daemon restart at 02:16:46Z, is what v0.4.30 needed
and what cleared it then (fix-list 85; the node caught up in about 6 minutes); the replacement's
doctor prescribes no restart, because the state it cleared cannot arise **(r11: R8)**.

## Appendix C — `vox status` layout

```
node fylgpqwc4tru  Ready  on the network
  ◣◣◢◢◤◤◢◢◢◢  fylg pqwc 4tru wfgd ilbq
daemon log: /home/ubuntu/.local/share/vox/.daemon/log (keeps 24 MiB in 8 files; oldest line 2026-11-09T12:45:24Z)
keyring: locked; a trust change will ask for your passphrase
governance work queued: none
anchor inventory unavailable: …
sync slots: <s> in use (<owners>); permits: <p> of <limit> (<owners>)
store: <f> GB file (<d> GB of disk), <u> GB in use, <b> GB of data; disk: <free> GB free (Vox stops saving below <floor> MB)
UNHEALTHY:
  ! room … (TR-4, TR-5, TR-19, TR-25, TR-6 lines)
waiting
  room … (ADR-040 NW-4 lines; `failed` lines)

rooms
  <room id> <name>  <verdict line>  as of <k> of <n> members' inventories (oldest <dur> ago); heads verified <h> ago; <n−k> not heard from
    holds <E> log entries (<R> readable rows); older history not here: <O> entries, fetched on request
    trust checked through every member's head | trust to check: <m> members (<ids>)
    sender keys: …; epoch …; render backfill …
    messages: …; Session steps: …
    <member lines, TR-3>
```

`healthy: nothing needs attention` is printed in place of `UNHEALTHY:` only when no condition of
TR-4, TR-5, TR-6, TR-19, TR-25, SR-2 holds and every open room with another member has at least one
source; an anchor inventory error no longer suppresses it. The `sync, per room and peer` counters
are `vox status --sync` (ruled: Q2).

## Appendix D — Rewritten messages, and the rule

**The rule** (TR-11): say what did not happen for the person, in which layer, and what to do, in
that order; never name a worker, thread, type, variant, or a bundle that is not the thing that
failed; a "not yet" says which of ADR-040 NW-4's two things is true; a hint only when it applies.

| v0.4.30 text (site) | What it meant | Rewrite |
|---|---|---|
| `store save room: authored save worker stopped` (`pending_text.rs:757`, a poisoned release for a trust-pass failure elsewhere) | another room's trust pass failed | does not occur (ADR-048: the indebted room holds its own debt; this room is released without marking) |
| `authored save worker stopped` (`pending_text.rs:802-805, 841`, a real panic) | the blocking worker panicked | `room o6z3enlc2ymd: the save crashed inside the daemon (a bug; the daemon log has the backtrace); the room is reopened and the post is retried once` |
| `a join did not complete — room X recovery could not complete its retained save: E` (`api.rs:2763`, `recovery_save.rs:283-291`) | a settlement save failed; no join | before the commit: `room o6z3enlc2ymd: its settlement could not be saved: E; retained and run again when <prerequisite words>`; a failed commit: `room o6z3enlc2ymd: its settlement could not be confirmed: E; what the store holds governs when it is next read` (`NodeEvent::RoomSettlementFailed { phase }`, TR-12 **(r12)**) |
| `malformed identity bundle: inclusion header is absent` (`admission.rs:237`) | a proof arrived before its header | no message: the header is asked for first and the proof kept pending (ADR-046 SY-13) |
| `malformed identity bundle: <any>` (528 lines) | a decode failure in some layer | `malformed <identity bundle, pairwise message, frame, history object or session record>: <what>` |
| `the peer refused: protocol limits exceeded` (`transport.rs:301-306`) | a real limit, or a decode failure | for a real limit only: `the peer could not serve this request: it is over that peer's limits; this node asks in smaller pages` |
| `you trust it, but it has not trusted you: it cannot read you — fix: on the computer hosting …` (`doctor.rs:975-983`); `it has not trusted you` (`room_cli.rs:1257`); `… (mutual trust has not reached this node)` (`agent_hook.rs:910`) | the consent entry is not in this node's applied projection | TR-10's three states, each as of the author's verified entry |
| `its owner has not trusted us, so it does not read us yet` (`pairwise_stream.rs:479`, on `KeyRefusal::NotTrusted`, `package_save.rs:988-995`) | the recipient's keyring does not trust this node, so it did not keep the key | `it did not keep this node's key: its keyring does not trust this node; Vox sends it again in <2s|4s|8s> (the existing backoff, 2 s doubling to 8 s, `actor.rs:12584-12591`)` |
| `nothing at 192.0.2.202:35805 answers as nqpflbs…` (`identity.rs:774-776`) | a daemon answered and holds no attached node by that name | `192.0.2.202:35805 answered, but holds no node attached as nqpflbs54itp` (TR-19) |
| `a dial-back could not be asked …: coord: coordinator cannot reach the peer` (`coordstream.rs:569`) | the anchor has no connection to the target | `the anchor holds no connection to nqpflbs54itp right now; no circuit was asked for` (debug, once per reach, TR-20) |
| `a board would not take the room's genesis (board X) … rejected: policy` (`service.rs:267`) | the board neither holds nor anchors the room yet | not published (TR-21); if a refusal still arrives: `board X does not carry room R yet; its genesis is not kept there`, at debug, once |
| `room … no completed sync in 10 minutes` (`status.rs:388-398`) | no outbound round completed | deleted; TR-4, TR-24 and TR-25's lines |
| `trusted member X unreachable, last seen 12s ago` (`status.rs:420`) | no live connection | `<id>: offline, last seen 12s ago` on the member line (ruling Q5: a fact, not unhealthy); under `UNHEALTHY:` only as `waiting for a member`; TR-19's text for an answered refusal |
| `healthy: nothing needs attention` (`status_cli.rs:232`) | no condition fired | kept, and printed only under Appendix C's conditions |
| `keyring asks for the passphrase` (`snapshot.rs:510`, in `vox status`) | the 30-minute window is closed | `keyring: locked; a trust change will ask for your passphrase` (TR-9) |
| `ended room cleanup stopped: node: history retirement requires recovery; see status` (`leave_save.rs:1563-1578`) | a retained flow's cleanup failed and the purge gave up | does not occur (ADR-049's `Retire::Deleting`; the replacement has no retained flow, ADR-046 SY-19); a parked deletion reads ADR-049 LE-6's `ended … deleting, waits until <prerequisite words>, for <dur>` (TR-2 row 1) **(r10)** |
| `was not left: an internal error — a bug in vox, not something you did; the node's log has the detail` (`leave_save.rs:1467-1488`; no log line is written) | the leave met a failed flow retirement | does not occur (ADR-049's leave always succeeds); a refusal that still reaches the person MUST write the log line it promises |
| `usually the room passphrase is wrong` on a disk-full refusal (item 24) | the member's store write failed; the wire carries one byte and no cause (ADR-047 SO-14) | `vox: cannot join <name>: the member could not write the join to its store` / `       try again later, or join through another member` (two lines; the wire carries one byte and no OS detail; ADR-047 r11 SO-14's words; X047-16; **r12: F6**) |
| `node X is unavailable. If it has not been created, run vox node create …` (`omp-extension.ts:444`) | the daemon dropped | ADR-041 (item 40); the rule forbids a hint that may create a second identity unless its precondition is known |
| `this node will delete the local room, tell its members as they are reached …` (`vox room leave`) | the leave deletes the local copy | prefixed by TR-16's sentence (count, or `cannot tell`) |
| `not for you` (ADR-046 SY-12 `body_state`) | the holder's governance says this node may not have that body | `not available to this node` in member lines and placeholders |
| ADR-049 r12's required daemon-log lines (LE-2, LE-5; printed in shipped builds): on a board `board: took a <genesis\|bundle\|address> record of <room> from <node>` and `board: took a <member\|room> withdraw of <room> from <node>`; on the publishing node `publish of <room> to <board>: <taken\|stale\|refused\|dead>` and `board <board> answered the <member\|room> withdrawal of <room>: <taken\|refused (<reason>)>` (at the tag under `mutant-sender` only, `actor.rs:22088-22099`); on the leaving node `leaving <room>: <step>` (LE-2 steps 1–5) and `putting the <member\|room> wire for <room> to <board>` **(r13)** | ADR-049's words; this ADR lists them (TR-11's form) | unchanged; ADR-049's journeys assert them |
| every `NotYet{prerequisite, seen}` refusal (ADR-040 NW-1's closed set; ADR-040 owns its number) | work parked on a prerequisite | `<what> waits until <prerequisite words>; <retained and finished by Vox | run it again>` (NW-4's two forms) |

## Appendix E — Log retention sizing

Measured on the Mac's log captured at 20:04Z (`mac/daemon-current-200453Z.log`, 664,633 bytes,
first line 2026-11-11T16:53:33Z): the busiest hour wrote 819 lines and 201,217 bytes. Budget: 48 h
× 201,217 B/h × 2 = 19.3 MB. Proposed: **24 MiB, 8 files of 3 MiB**; the guaranteed retained
capacity after a rotation is 7 × 3 MiB = 21 MiB plus the current file, above the budget. Because a
restart continues the current file in place (TR-17), restarts cost no capacity; the promise is in
bytes, and is not a guarantee at an arbitrary storm rate.

## Review record

Every finding of both reviews, its classification against the v0.4.30 source, the saved files and
this ADR's own text, and the requirement that answers it. Receipts:
`/tmp/Adr042Redesign/receipts.txt` (receipt lost in the reboot of 2026-11-13; figures recorded
in Appendix B and `adr-042-revision.md`; to be re-run as the fleet baseline); narrative in
`adr-042-revision.md`.

### First review (`adr-042-sol-review.md`), as closed by revision 2 and finished here

| # | Finding | Classification | Answer (r2) | Finished in r3 |
|---|---|---|---|---|
| 1 | proof/index work counted as receiving | CONFIRMED (`bounded_sync.rs:3426-3430`; `client.rs:327`; `runtime.rs:2354-2420`; files) | TR-1, TR-4 | F2: the clock is `oldest_since` of the oldest wanted position; coverage growth does not move it; chunks are byte progress, not delivery (TR-4 mutant C) |
| 2 | unknown frontier printed as up to date; unknown trust overclaims | CONFIRMED | TR-24, TR-25, TR-10 | F1/F4: frontier from signed heads; `checking` for a stale complete join; every trust verdict as-of; no invented range |
| 3 | rejoin loses local-only posts | CONFIRMED (`leave_save.rs:284-348`; IO drill) | TR-16 withdrawn; TR-15 | the leave's count is body-complete `held_through` (`source.rs:1667-1676`) with a `cannot tell` form |
| 4 | phase reset breaks the directory | CONFIRMED (`entry_store.rs:799-802`) | TR-14 owner finish/rollback | F8/F9: directory kind withdrawn (`cleanup_orphan_provisional` at open, `:2668`); render keeps caches; the pause knob makes the old-roots invariant observable |
| 5 | unbounded advertised map | CONFIRMED | TR-1 bounds | F1: advertisements never become evidence |
| 6 | scalar maximum drops head and sources | CONFIRMED (`sparse.rs:1206-1225, 1360-1379`) | TR-1 per-source records | F1/F6: fork only on signed objects (SY-13 rule 2); holders by demand kind |
| 7 | prefix ≠ held set; counts unmeasured | CONFIRMED (`channel.rs:8764-8767`, `:7813-7826`) | TR-1 intervals; `<N>` | F3/F12: `unreadable` is its own measure; Appendix B prints bounds only |
| 8 | reset-only-on-fetch false health | CONFIRMED (`actor.rs:10386`, `:16815`, `:18029`) | TR-6 | wording: the lifecycle sites **stop** clearing the streak and keep clearing the backoff (r2's record said "untouched"; corrected) |
| 9 | repair on a timer; agents can run it | CONFIRMED (RcaKeys K3; IO drill) | TR-13, TR-14 | F7: detection by `coord::session_if_named`, proved through the real extension; TR-14 says no incident was a local fault |
| 10 | no dial-back after refusal | CONFIRMED (`network.rs:1753-1760`) | TR-20 | closed |
| 11 | "took the key" false | CONFIRMED (`package_save.rs:988-995`) | Appendix D | the retry clock named (`actor.rs:12484-12504`) |
| 12 | wire codes carry no reason | CONFIRMED (`transport.rs:289-306`) | TR-11 | F10: the layer-label mutant reaches a live decode error |
| 13 | measurement cost; bootstrap | CONFIRMED (ADR-044 RD-4) | TR-1 cost | summaries at the fact's edge, read at publication (one statement) |
| 14 | unreachable mutants; TR-9 adjacency | CONFIRMED | TR-17, TR-18, TR-20, TR-12, TR-9 | F9/F10/F11 and the blocked-child staging in TR-18 |
| 15 | second truncate branch; eviction vs never-delete | CONFIRMED (`daemon_log.rs:43-66`) | TR-17 | F11: continue in place; restarts cost no slot |
| 16 | SO-1 vs step 4; no ended state; ADR-045 "last sync" | CONFIRMED | TR-14, TR-2, TR-22, TR-23 | contracts restated by the split ADRs' ids |

### Second review (`adr-042-sol-review-2.md`)

| # | Finding | Classification | Evidence | Answer |
|---|---|---|---|---|
| F1 | an unverified advertised size becomes missing work and outlives the liar; unsigned hashes called fork | CONFIRMED | r2 Terms `frontier = max(size_known, size_advertised)`; `history_stream.rs:636-640` unsigned; ADR-046 SY-12/SY-13 r2 | Terms: frontier is `size_known` (signed heads); `size_advertised` shown apart, unverified, forgotten with its source; fork only per SY-13 rule 2; TR-1 dishonest-inventory control and mutant B; TR-3 `advertised by … unverified` |
| F2 | `progress_at` advances on coverage; withheld-header case has no clock; control owed is coverage, not entries | CONFIRMED | r2 Terms (`progress_at` on `control_through` growth); `sparse.rs:1206-1225, 1360-1379` | Terms `oldest_wanted`/`oldest_since`; `trust to check` printed as coverage (`trust checked through p of s`), never behind; TR-4 busy-holder staging with advancing heads and coverage; mutant B |
| F3 | bodies and consent held, key missing: no alarm, `up to date`, `healthy` | CONFIRMED | r2 TR-5 condition required `wanted ≠ ∅`; `channel.rs:7813-7826` requires consent **and** key | Terms `unreadable(A)` with three causes and `unreadable_since`; TR-2 `cannot read` row and `up to date` excludes it; TR-5 unreadable condition with the key-withheld act and mutant B; HL-1 amendment |
| F4 | relay freshness allowed `HasNotTrusted` with the fingerprint fix; `CannotTellYet` invented a range | CONFIRMED | r2 TR-10 guard "fresh inventory from another source"; `ipc.rs:9209-9224` | TR-10: every state carries `as_of`, `head_age`, `head_from`; the fix only when A itself just signed the head; three unknown clauses, none inventing positions; fresh-but-stale relay act; mutant |
| F5 | room-wide "no request" clock; Private starts refresh it; quiet-to-first-post; `NotHeld` holder | CONFIRMED | `stall-robert-work`: Private starts 02:11–02:15Z, Public last 01:36:03Z (receipts R8); `bounded_sync.rs:4749-4757` no reason; ADR-046 SY-24 "nothing in flight, no named wait" | Terms *runnable demand* and *eligibility edge*; TR-25 per-class clock, reason clause from `start_reason`, restart named only for the retained-flow reasons; quiet-to-first-post, `NotHeld` and reconnect controls; mutants B, C |
| F6 | holder only by body interval; old control with a connected capable member reads "waiting" | CONFIRMED | r2 Terms; ADR-046 r2 `intervals_total`/`Probe` | Terms *holder by kind* (positive/possible/none); TR-2 `checking` row; TR-3 `oldest <p> held by … / being located` |
| F7 | `VOX_SESSION` only in hook subprocesses; OMP's shell tool carries `PI_SESSION_ID` | CONFIRMED | `crates/vox-tui/assets/omp-extension.ts:70-72, 88-96, 323-324`; `coord.rs:72-78` | TR-13: `coord::session_if_named()` (five marks); proof through the real extension with no injected variable; mutant B |
| F8 | render index rebuilt from ciphertext loses cached rows with consumed keys | CONFIRMED | `channel.rs:8167-8181` (cached = already), `:8210-8224` (`Unavailable`); ADR-006 S-10/S-12; ADR-037 R1 | TR-14 step 2 keeps the index and caches, re-derives only the backfill queue; TR-15 lists caches; act 2 with old received rows; mutant A |
| F9 | crash mutant unobservable; orphan promotion cleaned at open; delayed-context staging unstable | CONFIRMED | `entry_store.rs:2668, 2706`; ADR-046 SY-13 rule 4 park/resume | directory kind withdrawn; faults staged by `VOX_TEST_CORRUPT_PROJECTION` under `test-knobs` with a no-knob control; `VOX_TEST_REPAIR_PAUSE_BEFORE_SWITCH` makes old roots observable during the pause; mutant B asserted during the pause |
| F10 | the prefix mutant is unreachable once header absence is not an error | CONFIRMED | r2 TR-11 proof | TR-11 proof split: ordering claim (mutant restores the `Err`) and layer-label claim on a truncated `Entry` frame (mutant restores the prefix) |
| F11 | a torn file per crash consumes a slot; repeated oversized files | CONFIRMED | r2 TR-17 text | TR-17: continue in place at open; rotation only on size; promise in bytes (21 MiB + current); acts 2 and 3; mutant A |
| F12 | Appendix B's onset/clear times and counts not in the files; r2c-2 newest start 274.6 s; Private starts; prefix-derived counts | CONFIRMED | receipts R4, R5, R8: `newnode-watch` ends 22:30:39Z at 36; r2c-2 min age 274,647 ms Private; Public last 2,424,469 ms | Appendix B rewritten as conditional replays: measured facts with files, prerequisites and whether the files supply them, lines with bounds, times only where derived (`19:36:38.567Z`, `20:19:29Z`, `01:36:03Z`, `01:35:50Z`, `02:11:52Z`, `02:15:17Z`) or marked not derivable; no clearing events invented |
| — | coverage age labelled `newest` in TR-24, `oldest` elsewhere | CONFIRMED | r2 text | `oldest` everywhere; `oldest_head_ms` added |
| — | self-only room has no honest state | CONFIRMED | r2 TR-24 | `only this node is in this room; holds <E> entries` |
| — | retirement ledger is daemon-wide; status must show the stall on the right node | CONFIRMED | both snapshots carry the same 11 `cleanup_errors` with `actor: 2` (receipts R9); RcaSchedStall | TR-1/TR-25: per-node ledger split by actor; the node line `sync slots … retained with a failed cleanup`; the sibling lists none |

Reviewer's hard-state table: every row is answered by the requirement its last column names (F1–F6,
TR-24, Q5); the "quiet healthy room" row is TR-24's act N4 and the observation contract's
heartbeat row.

### Third review (`adr-042-sol-review-3.md`)

| # | Finding | Classification | Evidence | Answer |
|---|---|---|---|---|
| R1 | the verdict table was not total (key-blocked entry < 60 s, incomplete coverage, head older than 90 s had no row); `up to date` fell through; a head-freshness guard that nothing refreshes | CONFIRMED | r3 TR-2 rows; ADR-046 r3 SY-14 (`Head` only for a new size or head; an unchanged head raises nothing) | TR-2 rewritten as a total table (rows 11–14 partition every state; alarms separate); `catching up` carries `<parts>`; `checking` for `no_head` and the single-source join; `head_age` printed, never a guard (TR-24; act N4 and mutant B; act N5 after a restart); TR-1: no renderer raises a request |
| R2 | re-queuing the backfill cannot restore a cached row's index record; repair unsupported by any incident | CONFIRMED | `channel.rs:7883-7897` (skip on `cache_id`), `:8167-8181` (cached = already); no saved file shows a local fault; `arm-repair.md` | TR-13's repair clauses, TR-14 and TR-15 withdrawn unless the decider keeps them (Q1, recommended: omit); the keeping requirements stated in one paragraph (reindex from authenticated plaintext/`cache_id` bindings, remove invalid index entries, ratchets untouched); TR-8, TR-16, contracts, consequences and Appendix B aligned |
| R3 | "no start since the eligibility edge" is defeated for ever by one intervening start | CONFIRMED | r3 TR-25 text | Terms *missed-start age* = `now − max(oldest eligibility edge, latest class start)`, excluding named waits and in-flight work; TR-25 rewritten; start-once-then-stop control (`VOX_TEST_SYNC_STARTS_BUDGET=1`) and mutant D |
| R4 | a port's `last_start` is overwritten across services; the minimum surviving Public age is not the last Public start; 2,424,371 ms; ten errors are key-package and one is `worker stopped` | CONFIRMED | `actor.rs:17419-17428, 17473-17485`; receipts R8/R9 re-read: the o6z3 record is `node: history retirement worker stopped` | Context, §85, incident list, Appendix B (d) and Consequences relabelled "newest surviving per-port attempt"; last Public start and onset marked not derivable; +30–35 s kept only as a stated hypothesis; the errors split 10/1 |
| F2 (partly) | control-only obligation below the anchor and held-but-pending controls had no age | CONFIRMED | r3 Terms | Terms `oldest_dependency`/`dependency_since`; TR-4 dependency act and mutant D; TR-2 row 8's `<what>` forms |
| F4 (partly) | `its trust entries <p>–<q> are not here yet` asserts entries; positive joined notice unqualified | CONFIRMED | r3 TR-10 | TR-10: `Unchecked`/`Pending`/`NoHead` kinds with `its trust is not checked through positions …`, `held here and not yet applied (waits for …)`; `reads you as of its entry <s>` |
| F5 (partly) | the replay's historical clock | CONFIRMED | R4 | closed by R3 and R4 |
| F6 (partly) | holders did not consume the `Probe`/`Held` overlay and its invalidations | CONFIRMED | ADR-046 r3 SY-14 (overlay installed by `Held`, dropped on `Have` change or disconnect) | Terms *holder* reads inventory **or** overlay, negatives per (peer, A, range), overlay drop reverts positive to possible; TR-1 holds the overlay; contract row |
| F8 (partly) | the replacement repair was not executable | CONFIRMED | `channel.rs:7883-7897` | closed by R2 |
| F12 (partly) | the 19:38 bound, the 26 m / 1 h 46 m ages, "any delivery clears", 2,424,469 ms, the 27-behind ask-age, TR-4-vs-TR-25 as fact | CONFIRMED | the reviewer's time table, re-checked against the files | every item applied in Appendix B: ages and bounds marked not derivable or hypothetical; no clearing claimed; the inference labelled; 2,424,371 ms; `<B'>`/`<dur>` conditional |
| — | `control_through` held versus applied at the ADR boundary | CONFIRMED | ADR-046 r3 SY-14:1079-1084 | Terms `control_held` (SY-14's) and `control_applied` (SY-3's), both exposed; the contract row asks for the pending set; nothing vanishes at the boundary |
| — | the fallback was not one contract (heartbeat, overlay, classes, Head refresh) | CONFIRMED | ADR-046 r3 SY-22 | the observation contract section: one table for both mechanisms, the R1 heartbeat as the single asked row, every other row supplied by both; Q6 |

### Fourth review (`adr-042-sol-review-4.md`)

| # | Finding | Classification | Evidence | Answer |
|---|---|---|---|---|
| D1 | an unchecked position printed as a missing trust entry | CONFIRMED | r4 TR-2 row 8 and TR-4's act named `trust entry c` for a range only coverage proves; ADR-046 SY-14's control range is coverage including proof of absence | Terms: `oldest_dependency` has a kind, (i) unchecked range, (ii) held entry; a position is named only in (ii); TR-2 row 8, TR-4's line and recovery text route both kinds; the dependency act prints the range and gains the no-control-in-range control (a proof of absence resolves it without moving `last_entry`) |
| D2 | the R1 fallback contradicted the contract (`NOT HEARD FROM` "disabled" yet printed; uncovered positions called "no holder") | CONFIRMED | r4 contract table "If absent" column and R1 overlay row; Appendix B (d) | the decider ruled one common contract (Q6): the "If absent" column and every fallback sentence are deleted; the availability row defines `unknown` (`being located`), never "no holder"; TR-25's `NOT HEARD FROM` has no disabled variant; Appendix B (d) has one replay |
| D3 | the hypothetical onset lacked its premises; mg7b/vdy4 ages cross-assigned | CONFIRMED | `stall-robert-work`: mg7b 2,424,469 ms, vdy4 2,424,371 ms | Appendix B (d): the hypothesis stated whole (eligibility edge ≤ hypothesized latest start; nothing in flight; no later start; the surviving record as the latest start), the interval `last start +30 … +35 s` = 01:36:19.908–01:36:24.908Z for r2c-2 only; onset unknown; ages paired correctly, vdy4 the minimum |

The time-audit rows the fourth review marked closed are kept as they stand; the TSV sample count
in (b) is nine, not eight (the bound is unchanged).

### Fifth review (`adr-042-sol-review-5.md`)

| # | Finding | Classification | Evidence | Answer |
|---|---|---|---|---|
| E1 | with `peer-unreachable`/`member-not-attached` gone, the needed-holder alarm could be suppressed: TR-2's first match chose `no inventory` before `waiting for a member` once the sole holder's inventory went stale, and the watchdog's set was TR-4/TR-5/TR-25 only | CONFIRMED | r5 TR-2 rows 6 and 11; TR-13's evaluation set; TR-19's own proof shape (two members, sole holder offline) | Terms *known holding* (a member's last inventory and overlay, kept past staleness with its reach; not a source, creates no work) and *unavailable holder*; TR-19's `waiting-for-member` predicate defined independently of rendering and coverage (every source negative or absent, and an unavailable holder known), evaluated by `diagnose` and the notifier (TR-13), consumed by doctor and app, holding with zero sources; TR-2 row 6 precedes coverage and carries the zero-coverage qualification; TR-19's act is a two-member room with the sole holder offline/not attached through 100 s, caught-up control neutral, mutant B drops known holdings at staleness |

Late rulings recorded without design change: ledger row 49 (Session steps are kept 2 days, not 7;
this ADR prints `Session steps: <retention>` from the room's setting and names no number); ledger
row 32 (every proof is stageable inside the macOS guest or the Linux VM; stated in the Requirements
preamble; TR-18's two acts run in the Linux VM).

### Sixth review (`adr-042-sol-review-6.md`)

| # | Finding | Classification | Evidence | Answer |
|---|---|---|---|---|
| S1 | after a restart, known holdings are empty and the alarm waits for an inventory that cannot come while every member stays away | CONFIRMED | r6 TR-19 ("rebuilt from the member's first inventory after the open"); known holdings are in memory (ADR-038 FX-29) | Terms *reach settled* and *no member reachable*; what survives a restart named (wanted from the store, reach facts from the first ladder); TR-19's generic branch (`no member is reachable … who still holds them is not known`) needs no inventory and holds within `REACH_SETTLED` + `ASK_PATIENCE` + 5 s of Ready; restart half of the act and its neutral control; mutant B |
| S2 | the line asserted present and exclusive possession from a stale claim; `unknown` connected availability was treated as negative; "nothing to do" | CONFIRMED | r6 TR-19 line and doctor text; Terms *unknown* | Terms *known holding* = historical claim, *last advertiser*; the second branch requires every connected source **negative** (`unknown`/`possible` route to row 12's `locating` and the probe); lines say `was last advertised by <id> <age> ago (now <reach>); every reachable member says it does not hold it`, never `held by`/`only`/`nothing to do`; no reach action advised; third-member and false-claim halves; mutant C |

### Seventh review (`adr-042-sol-review-7.md`)

| # | Finding | Classification | Evidence | Answer |
|---|---|---|---|---|
| T1 | the negative branch quantified over fresh sources, not connected members; a connected member before its first or with a stale inventory escaped the test and the sentence misattributed a `NotHeld` to it | CONFIRMED | r7 TR-19 second branch ("every connected source"); Terms *source* | the branch quantifies over **every connected member**, source or not; no inventory, a stale inventory, `unknown` or `possible` are not negative and keep `locating`; at least one actual `NotHeld` required; the connected-not-a-source half (with and without a fresh negative source); mutant D |
| T2 | a held entry waiting only on the local fold entered the generic branch and blamed absent members | CONFIRMED | r7 TR-19 ("or `oldest_dependency(A)` unresolved"); Terms kind (ii) includes the fold | the predicate consumes only member-supplied obligations (wanted bodies, unchecked coverage, a held entry waiting on a remote context/parent/body); a local-fold wait reads row 12's `trust held … waiting for the fold` or NW-4's named wait; the local-fold half with every member offline; mutant E |

### Readiness review of the tasks cut from this ADR (`v0431-tasks-ADR-042-sol-review.md`), revision 9

| # | Defect | Classification | Evidence | Answer |
|---|---|---|---|---|
| 1 | TR-17's proof (4) required differing timestamps across a restart; its rule starts a new count after a restart | CONFIRMED | r8 TR-17 text | proof (4): repeat timestamps within one run, a fresh count after the restart |
| 2 | TR-18 staged attention by killing a caught-up member, which TR-19/Q5 make non-alarming; "recovers within 10 s while still blocked" against the 5 s kill | CONFIRMED | r8 TR-18 proof; TR-19 Q5 | attention from TR-4's apparatus holder (signed head, coverage, one body withheld; depends on TR-1/TR-4); recovery served 1 s after the alarm, asserted within one 5 s check with the stand-in's heartbeat alive at that timestamp; the kill asserted afterwards; mutant re-stated |
| 3 | TR-4 held for any stuck author and TR-5's not-arriving needed TR-4 not to hold: the member line was unreachable; consent-cause and `from 1 of` wording conflicts | CONFIRMED | r8 TR-4/TR-5/TR-7 text | TR-4 = room form (every author with an obligation stuck), TR-5 = member form (some stuck, others delivering); per-author clocks unchanged; TR-5's fourth half uses the listed cause; TR-7 `as of 1 of` |
| 4 | a 10-minute reconnect control against the 130 s ceiling | CONFIRMED | r8 TR-25 proof | 95 s away, inventory 20 s later |
| 5 | TR-19's pause-Bob/post/lock recipe gave Bob no verified head and no advertiser; "served 95 s old" cannot stage staleness | CONFIRMED | r8 TR-19 proof; `inventory_at` stamped on receipt (TR-1) | an apparatus member answers `Head(alice)` with her signed head, advertises coverage, withholds the body, disconnects; `size_known`/`entries_behind` asserted first; staleness staged by withholding heartbeats for 95 s and asserting `coverage.sources` |
| 6 | TR-25's retained-flow rendering unstageable under the replacement (ledger row 57); start-once fixture underspecified; `cannot_save` reason missing | CONFIRMED | ADR-046 SY-24 reasons (`:1027-1028`); row 57 | what `NOT ASKING` rests on under R2 stated; retained-flow words the recorded R1 alternative; `cannot_save` words; positive rendering by the start-once fixture (file-activated after staging, `Range` starts only, one post delivered and asserted) and a `cannot_save` act; the baseline staging is the v0.4.30 red receipt only (ADR-045 J10(a)) |
| 7 | TR-8 named a preparation hold ADR-044 RD-11 does not supply | CONFIRMED | ADR-044 RD-11 (progress and a fast open, no hold) | `VOX_TEST_HOLD_PREPARATION=<room>` under `test-knobs`, owned here; RD-7/RD-9 words proved in ADR-044's journeys and the leaving line in ADR-049's, named as dependencies |
| 8 | TR-11's ordering act and mutant restored `admission.rs:234-237`, which the replacement deletes (SY-19) | CONFIRMED | ADR-046 SY-19; SY-13 rule 4 | act (1) is the missing-context park (a valid R2 sequence), mutant in retained code at the park site |
| 9 | TR-23 still named TR-13's withdrawn agent act | CONFIRMED | r8 TR-23 | removed |

### Second correction batch (revision 10; `adr-cross-asks.md` "Target ADR-042", `adr-correction-batches.md`, `adr-amendment-quotes.md`, ledger rows 57, 62, 64)

| Row | Disposition | Where |
|---|---|---|
| R1 wording out (rows 57, 62; L1-5; X045-11; contradictions "Retained-flow pool", "Retained flows under R2", "Full-disk image size", "FX-35 amendment", "Linux restart cost", "Control coverage") | CONFIRMED: TR-25, TR-13, TR-16, TR-1, TR-4, the contract table, Appendix A/B/C and the FX-35 amendment named retained flows, the pool, a restart, a 64 MiB image; the replacement has none (ADR-046 SY-19, SY-24) | TR-25 (reasons `budget_exhausted`, `cannot_save`, none; no restart; `sync slots … permits` line; `cannot_save` act on SO-11's 256 MB image), TR-13, TR-16, TR-1, TR-4, Terms (control from the fence post, ruling 65), §85, Appendix B (d), Appendix C, Appendix D, the FX-35 row (deleted), contract rows |
| X040-4 | CONFIRMED | TR-23; Appendix A sibling table |
| X040-5; "Prerequisite count"; "ADR-048 NW-5" | CONFIRMED | Appendix D's NotYet row cites NW-1's set without a number; every "ADR-048 NW-5" / "ex NW-5" is ADR-048 TC-8 (or TC-5/TC-6 for the fence); TR-19's fold hold is ADR-040 NW-11's knob |
| X041-14, X041-15, X041-16 | CONFIRMED | TR-23 layout rows; Appendix A (`.daemon` †) |
| X044-10, X044-21, X044-22, X044-23, X044-24 | CONFIRMED | TR-3 (served progress), TR-23 (RD-9/RD-16 words), Appendix A (`pending_owners` †; r11: `inbound_tokens` renamed `.lanes.ports[].inbound_admissions` †, the refusal moved to ADR-046 SY-21's `.peers[].served.last_refusal`) |
| X045-13; X045-4 | CONFIRMED | Appendix A per-port fields kept; `exchange_ms` † |
| X046-1, X046-4, X046-8 … X046-15; X042-24 | CONFIRMED | Status (items 1–4), Appendix A (fence post, `bytes_before_access` †, checkpoint dispute †, `cut` †, `unproved` †, proof wait, permits), TR-23 (`--history resume`, byte-cut page †), TR-25 (256 MB image) |
| X047-13 … X047-19 | CONFIRMED | Appendix A (store lines and JSON, preparing/recovering forms, two `cannot save` forms, corrupt-store line), Appendix D (join refusal, SO-14's words), TR-23 |
| X048-8, X048-9, X048-10; X042-10 | CONFIRMED | TR-23 (TC-8's three sentences and the `waiting` line), TR-10 (`not trusted` column), Appendix A (`debts[]`, `waiting[]` kind `trust-debt`) |
| X049-8 | CONFIRMED | TR-23, Appendix A (LE-4's two lines, the `Erased` line, LE-9's joining line, `.left[]`, `.withdrawals[]`, `.rooms[].published[]` (r11: now the top-level `.publications[]`, ADR-049 r10), roster history words on `vox room roster --history`) |
| X042-12 | CONFIRMED | TR-16: the locked-node `cannot tell` form dropped |
| X050-7 (asker drops) | STALE here | TR-23 already says the act went with TR-14 |
| "Explicit-page restart"; X046-14 | CONFIRMED | TR-23, Appendix A: `no page in flight since the daemon started; ask again with --before X` |
| "Join refusal words"; X047-16 | CONFIRMED | Appendix D |
| "TR-13–TR-16 (need ADR-047 …)" | CONFIRMED | Implementation order 7 |
| 11:10 additions: "The host joins" fragment; E2's dead member; "NW-5's knob"; TR-6 act 1 unseeded; `<k> rounds retained`; log JSON names | CONFIRMED | TR-4's proof (sentence restored), E2, TR-19's local-fold half, TR-6's proof (two resets seeded; the killed-Bob assertion deleted), TR-25's node line, Appendix A (`.log` †) |
| Amendment quotes 5 and 6 (FOUND-ELIDED) | CONFIRMED | both quoted whole; FX-35's replacement is "deleted" under the replacement |
| Ledger row 64 (L3-64-042) | CONFIRMED | Inputs, TR-25's proof, the Review record's receipts line: "receipt lost in the reboot of 2026-11-13; figure recorded in <report>; to be re-run as the fleet baseline" |
| Privacy | CONFIRMED | a real endpoint was replaced by a documentation example in Appendix D's sample output; the `/home/…` paths that remain are sample output (Appendix C, Appendix D) **(r11: R14; r12: F8)** |
| LG-3's app half | FOUND: `apps/macos/Vox/Settings.swift` `DaemonLogSetting` shows `Daemon log: <path>` (accessibility `settings-daemon-log-path`) from `HealthReport.log_path` (`NodeModel.swift:1155-1159`) | Appendix A: that row owns the two fields, read from `.log` |

### Re-check 1 (revision 11; `adr-042-sol-review-recheck-1.md`, verdict "needs revision")

| Finding | Classification | Answered by |
|---|---|---|
| R1 permit owners are received answers, not running exchanges (SY-24's ownership table) | CONFIRMED | TR-25 node line and reason clause; contract row; Appendix A `.sync_node.permits` |
| R2 `cannot_save` cannot reach `NOT ASKING` (the demand is parked on `StoreRecovery(room)`) | CONFIRMED | TR-25's reason clause, doctor line and act (b) with mutant F; TR-13 proof (2) |
| R3 the start-once fixture's second `Head` restarts the missed-start age | CONFIRMED | TR-25 act (a): three demands staged under one head before activation; the knob caps a `Range` at one position |
| R4 a `MissingContext` answer is a pending in-memory verification, not a held entry (SY-13 rule 4) | CONFIRMED | TR-11 proof (1): pending-answer state, `Context` request, success and timeout arms |
| R5 act B's 5 s recovery bound races the 5 s kill | CONFIRMED | TR-18 proof: act B under `VOX_TEST_NOTIFY_KILL_MS=20000`, act C for the shipping kill |
| R6 E2's v0.4.30 arm cannot raise `room-stale` from a withheld body | CONFIRMED (`status.rs:375-398`: age of the last completed round) | E2 split into a v0.4.30 run (`peer-unreachable`) and a candidate run |
| R7 TR-19's `last advertised` names alice, who sent no inventory | CONFIRMED | TR-19 proof: dave advertises, alice authors |
| R8 TR-16's locked control, and three leftovers of "the doctor names a restart" | CONFIRMED | TR-16 proof (LE-1/RS-3 refusal); Unchanged rulings; ADR-041 contract row; Appendix B (d) |
| R9 `checkpoint-dispute:` missing from TR-22's key list | CONFIRMED | TR-22 |
| R10 `bytes_before_access` definition differed from ADR-046's | CONFIRMED | Appendix A row, ADR-046 r10's words verbatim |
| R11 `exchange_ms` owner, refusal path, per-port envelope | CONFIRMED | Appendix A: ADR-046 SY-20 owns `exchange_ms`; refusal under `.peers[].served.last_refusal`; per-port fields under `.lanes.ports[]`; FG-5 reads `rtt_ms` |
| R12 publications survive erasure; `.rooms[].published[]` is the wrong place (ADR-049 r10) | CONFIRMED | TR-23; Appendix A `.publications[]`, `.withdrawals[]` shape, `.left[].sources` |
| R13 ADR-047 r11's new lines absent | CONFIRMED | Appendix A rows 3, 4, node block, `store.sampled_ms`; `could not confirm it` form |
| R14 the review-record privacy row still printed the real address | CONFIRMED | that row reworded |
| Appendix A row table (askers' frozen words) | applied | each row carries the asker's words; † only where the asker has not yet confirmed (`pending_owners`, `inbound_admissions`, `.daemon`, `.log`, `.disk.free_bytes`) |

### Re-check 2 (revision 12; `adr-042-sol-review-recheck-2.md`, verdict "needs revision")

| Finding | Classification | Answered by |
|---|---|---|
| F1 the start-once fixture raced SY-15 rule 6's passes between the accepted `Head` and activation | CONFIRMED (046 r10 SY-15 rule 6: a pass runs on an answer and fills free slots) | TR-25 act (a): the knob is a barrier from the daemon's start (budget zero until the file appears); activation and the one capped `Range` are one step |
| F2 act B's recovery bound was widened to 10 s; act C had no mutant | CONFIRMED | TR-18 proof: 5 s, one check; act C's omit-the-kill mutant |
| F3 TR-22's proof reached no checkpoint dispute; a single-prefix mutant survived | CONFIRMED (`NodeModel.swift:1161-1166` is an explicit filter) | TR-22 proof act 2 with SY-27/SY-28's dispute apparatus; mutant (b) |
| F4 a failed `txn.commit()` was reported as "retained and run again" | CONFIRMED (`store.rs:1994` `Storage{op: "commit"}`; `recovery_save.rs:267-291` generic) | TR-12 `phase ∈ BeforeCommit \| Commit`, `could not be confirmed` for a commit error, proof (3) and its mutant; Appendix D row |
| F5 the CJ-17 placeholder mandated a row its owner declined | CONFIRMED (043 r13 CJ-17, sibling request) | placeholder removed; CJ-1 `last heard` and CJ-7's reach fact only |
| F6 five schema/wording cutovers left in two forms | CONFIRMED | `.sync_node.permits` one schema; `store.redb{…, sampled_ms}`; `; trying again in 5 s`; Appendix D's two-line join refusal; TR-23's full Locked sentence |
| F7 E2's stale explanation was reversed | CONFIRMED (`status.rs:383-385`: `last_sync.unwrap_or(started)`) | E2 corrected; baseline member previously reached (`status.rs:407-425`) |
| F8 the real port survived in the review-record row | CONFIRMED | row reworded without any endpoint |

### Re-check 3 (revision 13; `adr-042-sol-review-recheck-3.md`, verdict "needs revision")

| Finding | Classification | Answered by |
|---|---|---|
| G1 the barrier assertion used `last_request_at.body`, a clock the contract does not have (classes are sync and key) | CONFIRMED (Appendix A `last_request_at_ms: {sync, key}`; 046 SY-15 rule 7) | TR-25 act (a): asserts the counter file absent and `last_request_at_ms.sync` equal to the completed `Head`'s start before activation, equal to the one `Range`'s start after; no third clock |
| G2 the over-limit sentence was printed for a declared-versus-received length mismatch too (046 r11 SY-27 routes both causes to it) | CONFIRMED (frozen 046:559–566) | Appendix A row: one sentence per cause, a length-mismatch sentence added, an under-limit wrong-length proof arm with a cause-conflation mutant; shared change listed for ADR-046 SY-27 |
| Speed rulings (ledger rows 80, 81) | no latency target in this ADR (E1's `300 ms` is a staged holder delay; patience constants are measured p99s) | Status line records it |
| ADR-049 r12 rows | applied | Appendix A (`own_feed`, `admissions[]`, `sources`, `carry_estimate_bytes`, `answer_rows`, SO-15's disk names), Appendix D (its six log lines), TR-16 proof (act A (a′)); `held_through` taken as body-complete |

## The decider's answers (2026-11-13; `adr-cross-changes.md` rows 22–27)

Every question this ADR put to the decider is answered; the requirements above are written on
the answers, and no "(open: Qn)" remains.

| Q | Question | Ruling | Applied in |
|---|---|---|---|
| Q1 | a general room-repair facility in v0.4.31? | **Omit.** The watchdog, the operator-only restart advice for the reproduced cause and the no-rejoin rule stay; repair-specific clauses withdrawn with ids preserved; fix-list item 53 "not in 0.4.31, by ruling" (row 22). | Status; §53; Terms *local fault*; TR-8; TR-13 (withdrawn clauses); TR-14; TR-15; TR-16; contracts (ADR-047, ADR-050); Consequences |
| Q2 | the raw `sync, per room and peer` block | **Move to `vox status --sync`**; plain status shows outcomes only; JSON keeps every counter (row 23). | TR-2; Appendix C |
| Q3 | authenticated attached-node presence | **No**, this release; an answered refusal is `not attached at <addr>`, never "locked" as a fact (row 24). | TR-19 |
| Q4 | log budget | **24 MiB** (row 25). | TR-17; Appendix E |
| Q5 | a trusted member's node this node cannot connect to | **`offline, last seen <dur> ago`**, a plain fact, not unhealthy; an alarm only when wanted entries have no other holder, as `waiting for a member` (row 27; his words: "why not \"offline\"?"). `not attached at <addr>` and `never dialled` stay. | Terms *offline*, *known holding*; TR-2 row 6; TR-19's predicate (and its doctor/app words); TR-13's evaluation set; Appendix A keys (`peer-unreachable`, `member-not-attached` deleted; `waiting-for-member` added); Appendix D |
| Q6 | the observation contract under either sync mechanism | **One common contract, no reduced variant**; if R1 is chosen it adds the inventory heartbeat row so `NOT HEARD FROM` exists; ADR-046 must accept the five rows (row 26). | the observation contract; TR-25; Appendix B (d); contracts (ADR-046 rows 1–5) |

`--rejoin` stays withdrawn (TR-16); a durable export of the own feed is not in v0.4.31. Sign-off
is conditional on ADR-046's explicit acceptance of contract rows 1–5, unchanged.
