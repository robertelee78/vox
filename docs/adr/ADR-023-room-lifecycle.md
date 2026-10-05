# ADR-023: Room lifecycle — one order, retention, key delivery through members, dumb anchors

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted. Built on integrate/v0.3.0 (M23.1–M23.6), including `vox room admin` and
leaving and ending a room (RL-8, with the lifecycle tags `0x0019`–`0x001B`, ADR-008 LS-21), except
where a requirement says otherwise. Not built: a room created with a retention (RL-2.1), the
`vox status` line for a room with no always-on member (RL-4.9), and pruning a key-package once its
recipient acknowledges it (RL-4.7).
**Date**: 2026-09-24
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: log, ordering, retention, sender-keys, anchors

## Context

PRD-001 sets the room's lifecycle:

- **R1:** a room has no lifetime limit on the number of messages.
- **R6–R10:** history is kept forever by default; the room's creator or admin may make messages
  disappear, and shortening applies retroactively; a node may keep less than the room, and the
  shortest wins; an expired message leaves nothing visible. This is look and feel, not a security
  property.
- **R11:** keys reach an offline member through always-on member nodes, never through the anchor.
- **R12:** the approver chooses history per grant, defaulting to from-approval-onward.
- **R13:** messages appear in the same order on every node.
- **R14:** sender keys that are no longer needed are deleted.
- **R33–R34:** any always-on node can be an anchor, and an anchor stores nothing for rooms it is not
  a member of.

Each skeleton costs about 3.5 KB (a 3,373-byte composite signature), so a
million-message room holds about 3.5 GB of skeletons after every body has expired.

## Requirements

### Decision 1. One order, the same on every node (R13)

- **RL-1.1.** Each entry's signed skeleton MUST carry `seen` (at most 16 heads of other authors'
  feeds the author had applied) and `claimed_ms` (the author's clock in milliseconds), as ADR-008
  LS-10 specifies. The claimed time MUST be in the skeleton, not only in the encrypted envelope, so
  that a node can place an entry it cannot decrypt. Anyone holding skeletons therefore sees the
  claimed send time; under decision 6 no non-member holds skeletons.
- **RL-1.2.** Every node MUST order a room's entries by ADR-008's hybrid logical clock (LS-11): an
  author's claimed time capped at ten minutes past the entry's latest held parent (or the room's
  genesis time for an entry naming none), sorted by `(clock, entry_hash)`. Every node holding the
  same entry set MUST compute the identical order. The cap MUST NOT be against the receiving node's
  clock. An author's clock can move its entry only among its concurrent peers, never ahead of
  anything it saw.
- **RL-1.3. Late arrivals.** An entry from a member who was offline MUST take its causal position,
  even above rows already shown, and MUST NOT move to the bottom. A row MUST be marked late only
  when it lands above a row the reader was already shown, meaning one placed at least
  `LATE_AFTER_MS` (10 s) before it arrived; rows loaded when the room opens count as shown before the
  restart. Posts that cross in flight MUST NOT be marked late. The TUI MUST prefix a late row
  `[late]`, and `vox room read --late` (hidden) MUST list exactly the late rows.
- **RL-1.4. Reads.** `vox room read --since` MUST be arrival-based, so a late row that lands above
  the cursor is still delivered. A paged read of the whole room MUST continue from a page mark in
  the room's order (`Request::Read.after`), never as an arrival cursor, so a late row is shown once
  and in its place. `vox room read --hashes` (hidden) MUST print `<hash> <clock-ms>` for every held
  entry, in order.
- **RL-1.5. Claims.** Claims stay in Vox: agent comms tracks who does what (ADR-020). `seen` gives
  claims a happens-before (`Dag::happened_before`, ADR-008 LS-13): a claim that saw another claim
  follows it, and only truly concurrent claims fall back to the tie-break. Vox MUST NOT hard-lock a
  claim or enforce a takeover (PRD-001 R17).

### Decision 2. Retention (R6–R10)

- **RL-2.1. The room's policy.** The room's retention MUST be the ADR-007 policy-update `ttl`: `0`
  means forever, any other value is disappearing after that many seconds. A room MUST default to
  forever (R6). Only the room's creator, or an admin the creator delegated with `vox room admin`,
  MAY set it (ADR-007 G-6). The UI MUST offer 1 hour, 1 week, 1 month or a custom value (`vox room
  retention <room> 1h|1w|1m|<secs>|forever`, where `1m` is a month). A non-admin's change MUST be
  refused, saying that the change is the admin's (`Fault::NotAdmin`).
  *Status:* built, the check being the `policy` capability that the creator and a delegated admin
  hold (ADR-007 G-5). Not built: a room created with a retention (creation writes `ttl` 0, and
  `vox room retention` sets it after).
- **RL-2.2. The node's policy.** A node's own retention MUST be local configuration (the `retention`
  file in its config directory), per room or as a default. A member MAY set a lower retention for
  its own node only; it MUST NOT raise the room's retention for its node.
- **RL-2.3.** The effective retention MUST be the shorter of the two (shortest wins).
- **RL-2.4. Retroactive.** Whenever the effective retention changes, and on a periodic sweep (every
  tick of the node, so at least once a minute), every content entry older than it MUST be pruned:
  its payload body dropped, its plaintext cache row deleted, its signed skeleton kept.
- **RL-2.5. Age.** An entry's age MUST be measured from its author's claimed time, clamped to no
  later than the time this node first saw it. A back-dated message can expire early; a future-dated
  one cannot live longer. Whether a missing body is expired MUST be the receiver's own computation;
  a body that is not expired and has not arrived is owed and shown as "not received yet" (ADR-008
  LS-33).
- **RL-2.6. Nothing visible remains.** A pruned row MUST NOT be rendered and MUST NOT count toward
  unread.
- **RL-2.7. Pruned entries are accepted.** A pruned entry whose skeleton verifies MUST be accepted
  on reload and on sync. Sync MUST NOT ship a body a node no longer has; a peer asking for one gets
  the skeleton.
- **RL-2.8. Not a security property.** A modified or malicious node can keep everything. The UI and
  the documentation MUST say so. **Open, awaiting the decider:** a pruned message's encrypted bytes
  stay in the store file as freed pages, readable only with that room's key on that node; store
  compaction (`Profile::compact_store`) has no caller.
- **RL-2.9.** Claims and work items are entries like any other and MUST expire with a disappearing
  room. Vox MUST NOT be treated as the record of work: agent comms coordinates, and the work's
  progress is recorded in GitHub through the accountability skill (ADR-020 §5).

### Decision 3. Skeleton growth: checkpoints (R1)

- **RL-3.1. Only the author checkpoints, and only its own feed.** A checkpoint MUST be the payload of
  an ordinary signed entry in the author's own feed (struct tag `0x0016`, `vox/checkpoint/v1`, body
  `[seq, entry_hash]`). A checkpoint by anyone else MUST NOT be honoured: it would let one member
  make every node forget another member's signatures, which are the evidence a fork proof needs.
  An author who never returns never checkpoints, and its old skeletons keep their signatures.
- **RL-3.2. When the author posts one.** Only when the room's retention is not forever (a node's own
  shorter limit does not count), and either:
  - at least `CHECKPOINT_EVERY` (32) more of the author's entries have expired on its node since its
    last checkpoint; or
  - fewer have, and nothing new has expired on its node for `CHECKPOINT_IDLE_SECS` (10 min): a
    closing checkpoint, so that no expired entry keeps its signature indefinitely.

  The check MUST run on every tick, not only after a prune, so that a backlog already expired when
  the room opens is checkpointed.
- **RL-3.3. The position it names.** The highest one below which every content entry of the author
  has had its body pruned on that node. Governance entries and earlier checkpoints keep their bodies
  and MUST NOT hold it back.
- **RL-3.4. Shedding.** A node MUST shed the signature of an entry only when the entry is at or
  below its author's checkpoint, its body is pruned there, and the node's effective retention is not
  forever. It MUST do so when the checkpoint arrives, or when it prunes such an entry afterwards. The
  shed entry MUST be stored with authenticator type `0` and no bytes, and stays authentic through
  the chain: the signed checkpoint names its position's hash, and each successor names it in
  `prev_hash`.
- **RL-3.5. Unsigned entries.** An unsigned entry MUST NOT verify on its own. A node MUST take one
  only inside a sync session or a reload, provisionally, and MUST take it back at the end if no
  signed entry of the same feed chains to it (ADR-008 LS-40). A newcomer therefore syncs signed
  entries from the checkpoint onward and hash-chained skeletons below it, holds the same entry set,
  and shows the same order.
- **RL-3.6. Refusal below the line.** An entry for a position at or below its author's checkpoint
  that the node does not hold as it is MUST be refused as pre-checkpoint, never classified as a
  fork. In a sync session the refusal MUST NOT be fatal. Above the checkpoint, fork detection is
  unaffected.
- **RL-3.7.** A room whose effective retention is forever MUST keep every signature.

### Decision 4. Key delivery through members (R11, R14)

- **RL-4.1. An owed sender key goes into the log.** When a member owes another member a sender key
  (consent granted, or a rotation) and cannot reach the recipient (the dial reports it unreachable),
  it MUST seal the SKDM to the recipient and post it as a `key-package` log entry (struct tag
  `0x0017`, `vox/key-package/v1`).
- **RL-4.2. The seal.** A key-package MUST be sealed with a one-shot PQXDH to the recipient's
  published prekey bundle (ADR-004): the package carries the PQXDH initial message and the first
  ratchet message, whose plaintext is the SKDM. It MUST NOT be sealed in a pairwise session, because
  sessions are not persisted and the recipient this serves is one that restarted. It uses one of the
  recipient's one-time prekeys when one is published.
- **RL-4.3. Direct delivery stays the fast path.** A reachable recipient MUST still get its key over
  the pairwise stream.
- **RL-4.4. Forward-only is preserved.** A package for a consent MUST release the sender key at its
  current position, as direct delivery does; a package for a rotation MUST release the new
  generation at its origin. A message sealed before the grant MUST stay unreadable to the recipient.
- **RL-4.5. Every member node replicates it** like any entry, and an always-on member (a NAS, for
  example) carries it to the recipient when it next syncs. No store-and-forward service is added.
  A non-recipient MUST NOT be able to open a package.
- **RL-4.6. What it reveals.** A key-package shows who is sending keys to whom, and when, which the
  consent entries already reveal to members.
- **RL-4.7. Retention of packages.** A key-package MUST be pruned once its recipient has acknowledged
  it; the recipient's next entry listing it in `seen` is the acknowledgement. *Status:* planned.
  Packages are kept, and are prunable by retention like any content entry.
- **RL-4.8. R14, pruning.** A sender MUST keep only the origin key of the generation in use, plus
  any generation a full-history grant still has to release (decision 5). A superseded generation's
  origin key MUST be deleted (`ChannelState::prune_superseded_origins`, zeroized on drop), and
  `vox status` MUST report the generations held per room (`key_generations`).
- **RL-4.9. The accepted consequence (PRD-001 §7 Q7).** A room with no always-on member, whose
  members are never online together, cannot deliver keys. `vox status` MUST say so for that room
  ("no always-on member: keys wait for overlap"). *Status:* planned; `vox status` reports
  `always_on_member` as unknown. The recipient's own log says why it read nothing (proof 5).

### Decision 5. History per grant (R12)

- **RL-5.1.** When approving a member, the approver MUST choose "from now" (the default) or "full
  history": `vox trust add <fp> --history now|full`. The choice MUST be kept per identity in the
  trust keyring, so it covers every room shared with that identity, now and later, and only the
  approver's own messages, as consent always has.
- **RL-5.2.** `now` MUST release the SKDM at the current iteration. `full` MUST release every
  retained generation at iteration 0, oldest first, the live one last, and the consent grant MUST
  record `FullHistory`.
- **RL-5.3.** A grant that arrives after its key MUST make stored messages readable: a sync that
  brings governance MUST retry the backfill for every author the node holds a key for.
- **RL-5.4.** `--history full` MUST NOT create a gap over `MAX_SKIP` (ADR-006): a generation never
  exceeds `ROTATE_AFTER_MESSAGES` = 1,000 = `MAX_SKIP` iterations, and backfill walks stored bodies
  one iteration at a time.

### Decision 6. Anchors store nothing (R33–R34)

- **RL-6.1.** An anchor that is not a member of a room MUST hold nothing for it except rendezvous
  board records (addresses and bundle records, small and short-lived, ADR-012) and a relay's
  in-flight datagrams (ADR-022). It MUST refuse every sync session for such a room.
- **RL-6.2.** The anchor's ciphertext log is removed: there MUST be no anchor log store, no anchor
  sync session, and no `AnchorLog` / `AnchorMeta` pages (segment kinds 6 and 7 stay reserved,
  ADR-016 NR-45).
- **RL-6.3. No upgrade (M23.5, R45).** There MUST be no upgrade of an anchor store an earlier
  release wrote, which kept room pages: its data root is refused (ADR-026 F-3).
- **RL-6.4.** Convergence for members who are never online together MUST come from decision 4 and an
  always-on member. A node that is both an anchor and a member holds the room because it is a
  member.

### No backwards compatibility

- **RL-7.1.** The ADR-008 skeleton changes once, and every node updates; there is no compatibility
  ceremony. A room made by vox before v0.3.0 MUST be refused when opened, with a plain reason that
  says to make the room again (`Fault::RoomFromBeforeV030`, `node/api.rs`).

### Leaving and ending a room

- **RL-8.1. Leave.** `vox room leave` MUST post the node's presence statement (`0x0015`, `here` =
  false), take the node's records off boards with a signed member withdraw (`0x001A`), and MUST
  delete the room from the node — every stored row and its key, the store rewritten so none of the
  deleted bytes stay — once a sync session has carried the statement to another member (V210-164).
  A room held alone MUST go at once.
- **RL-8.1a.** If no member can be told within 30 s the leave MUST say so (`LeaveNotHeard`), and the
  node MUST keep the room and go on leaving, across a restart, until one is told. Anything the node
  writes in the room meanwhile undoes the leave (`LeaveUndone`).
- **RL-8.1b.** A member whose feed ends in its statement that it left MUST be left out of every other
  member's roster, sync and key delivery. Joining again is an ordinary join: once synced, the node
  moves to a sender generation above any its feed shows and says it is back (`here` = true), which
  starts its consents over.
- **RL-8.2. End.** The room's creator, or an admin it delegated (ADR-007 G-5), MAY end the room (a
  room-lifecycle fact `0x0019`, kind end); the creator MAY choose an idle end at creation (kind idle
  end), and the room then ends once nothing is said in it for that long. A node holding an ended
  room MUST take no new message in it, MUST pass the end on to each member at its next sync (for at
  most 60 s for a member it cannot reach), and MUST then delete the room as RL-8.1 does. The
  ender's node MUST take the whole room off boards (`0x001A`, room scope); a board MUST take that
  only from the creator or an admin on the creator's signed roster (`0x001B`), and MUST answer a
  later join of the room as ended. Lifecycle kind codes 1 and 4 (a leave and a return, before this
  ruling) are reserved and MUST be refused.
- **RL-8.3.** There MUST NOT be a `vox room forget`: leaving and ending are the only ways a room
  leaves a node.

## Proofs

Each proof drives the shipped `vox` binary and has a mutation that turns it red (ADR-018).

1. **Same order** (decision 1): three nodes post concurrently, one offline for part of it; after
   convergence `vox room read --hashes` prints the identical sequence on all three. Mutation:
   arrival order. `crates/vox-tui/tests/causal_order_proof.rs`
   `three_members_one_offline_for_a_while_show_one_order`. **Known defect:** intermittently red,
   the second joiner cut off from the first post onward; tracked by V030-03 (#228).
2. **Causal:** a reply posted after reading a message is ordered after it on every node, even from a
   clock an hour behind. Mutation: `seen` ignored in the sort. Same file,
   `a_reply_follows_what_it_answered_even_from_a_clock_an_hour_behind`. The cap: a post from a clock
   a day ahead moves the room at most ten minutes. Mutation: cap removed.
   `a_post_from_a_clock_a_day_ahead_does_not_drag_the_room_a_day_forward`. Late rows (RL-1.3,
   RL-1.4): `a_late_arrival_is_marked_and_posts_that_cross_are_not`,
   `a_room_read_in_pages_shows_a_late_arrival_once_and_in_its_place`,
   `a_late_arrival_after_a_restart_is_marked` (also tracked by #228).
3. **Retroactive retention:** shortening a room's retention removes older messages on every member,
   and a restart still opens the room. `crates/vox-tui/tests/retention_proof.rs`,
   `crates/vox-tui/tests/retention_requirements_proof.rs` (R6 forever by default; R7 presets, the
   non-admin refusal and the admin's change reaching what every member holds; R10 an expired entry's
   skeleton still catching a fork).
4. **Shortest wins:** a node set shorter than its room prunes at its own limit and never shows what
   arrives expired. `retention_proof.rs`
   `a_node_keeps_less_than_its_room_and_never_shows_what_arrives_expired`.
5. **Offline keys through a member:** A and B never up together, C always on; B reads A's messages
   across a rotation and none sealed before the grant. With C removed, B reads none, and its log
   says why. Mutations: no package posted; a consent package released from the chain origin.
   `crates/vox-tui/tests/key_package_proof.rs`.
6. **Anchors hold nothing:** after a full session through a non-member anchor, its data directory
   holds no store for the room (`key_package_proof.rs` step 5).
7. **R14 and per-grant history:** after each of two rotations the sender holds one generation; a
   `full` grant reads earlier messages and a `now` grant does not.
   `crates/vox-tui/tests/history_grant_proof.rs`; the unread badge with `--history full`:
   `crates/vox-tui/tests/tui_unread_backfill_proof.rs`.
8. **Checkpoints:** a disappearing room sheds expired signatures, reopens, and a cold joiner holds
   the same entries in the same order; a forged entry below the checkpoint is refused; a closing
   checkpoint follows a quiet room; an expired backlog is checkpointed without another prune.
   `crates/vox-tui/tests/checkpoint_proof.rs`.

The ADR-004 O2–O4 delivery proofs stay as proofs of the direct path:
`crates/vox-tui/tests/room_of_three_keys_proof.rs`, `cross_process_join_proof.rs`,
`trust_before_join_proof.rs`.

## Implementation plan

- **M23.1** Reload and sync accept pruned entries; retention policy and sweep (decision 2). Built.
  Not built: a room created with a retention (RL-2.1). Not isolated by any proof: a peer asking for a
  pruned body gets the skeleton (RL-2.7), tracked by V210-138 (#357).
- **M23.2** `seen` and the deterministic causal order (decision 1). Built. Proof 1 is
  intermittently red (#228).
- **M23.3** `key-package` log entries (decision 4). Built. Not built: pruning a package on its
  acknowledgement (RL-4.7) and the `vox status` line (RL-4.9). **Known defect:** when a grant opens a
  pairwise session, only the first of several SKDMs carries the session's `Hello`; the others ride
  streams that could reach the recipient first.
- **M23.4** Per-grant history (decision 5) and R14 pruning (RL-4.8). Built. Not proved: that a
  generation is kept while a full-history grant is owed and released once delivered; tracked by R14
  (#65).
- **M23.5** Delete the anchor log (decision 6). Built.
- **M23.6** Checkpoints (decision 3). Built.

## Consequences

- One order everywhere, and claims gain a real happens-before.
- Retention is possible, and is look and feel, not a guarantee.
- Forward secrecy improves (R14).
- Anchors are dumb pipes with nothing worth seizing.
- Two members who are never online together require an always-on member.
- The skeleton carries `seen` and `claimed_ms`, and checkpoints add an entry kind.
- Late arrivals can appear above rows already read.
- Rooms made before v0.3.0 are made again.

## Related ADRs

ADR-004 (PQXDH), ADR-006 (sender keys), ADR-007 (governance, retention policy), ADR-008 (the
skeleton, the order, checkpoints on the wire), ADR-010 (at-rest pruning), ADR-012 (boards), ADR-016
(node runtime, anchors), ADR-018 (proofs), ADR-020 (agent comms and claims), ADR-022 (datagram
relay). PRD-001 R1, R6–R14, R17, R33–R34, R45.
