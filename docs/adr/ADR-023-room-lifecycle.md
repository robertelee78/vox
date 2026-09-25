# ADR-023: Room lifecycle — one order, retention, key delivery through members, dumb anchors

**Status**: **Accepted by the decider — 2026-09-25**, with the answers to its open questions (below).
**Implementation is not yet on `main`.**
- M23.1 (retention), M23.2 (one order) and M23.6 (checkpoints) are built on `prd1/causal-order` and
  merged into the v0.3.0 integration (`prd1/v030`).
- M23.3–M23.5 are in progress.
- All are to ship in v0.3.0. A `DONE` mark below names the commit and gate on its branch.
**Date**: 2026-09-24
**Deciders**: Robert E. Lee
**Tags**: log, ordering, retention, sender-keys, anchors
**Depends on**: 006, 007, 008, 010, 012, 016 — and PRD-001 (R1, R6–R14, R33–R34, R40)

## Context

PRD-001 records the decider's answers of 2026-09-24:

- **R1:** rooms have no lifetime limit on the number of messages.
- **R6–R10:** retention:
  - history is kept forever by default;
  - an admin may set disappearing messages for the room, and shortening it applies retroactively;
  - a node may keep less than the room, and the shortest wins;
  - an expired message leaves nothing visible. This is look and feel, **not** a security property.
- **R11:** keys reach an offline member **through always-on member nodes**, never through the
  anchor.
- **R12:** the approver chooses history per grant, defaulting to from-approval-onward.
- **R13:** messages appear in the **same order on every node**.
- **R14:** sender keys that are no longer needed are deleted.
- **R33–R34:** any always-on node can be an anchor, and an anchor stores **nothing** for rooms it is
  not a member of.

What the code does today (`origin/main` 671527a):

- **Order is arrival order.** Entries carry no link to other authors' entries (`log/dag.rs`); the
  timeline is `Vec<Rendered>` appended as rows decrypt (`node/channel.rs` `render_content`). Two nodes
  can show two orders. The only timestamp is the one the author wrote into the content envelope. Since
  v0.2.7 it is in milliseconds, which is what claims order by, and it has no happens-before
  relationship between authors.
- **Retention cannot be switched on.** TTL is hardcoded to `0` at room creation (`channel.rs:693`),
  and a reload treats a pruned payload as fatal (`channel.rs:858`). The mechanism exists but has no
  caller: `atrest/retention.rs` `prune_entry_at_ttl_disappearing` prunes the payload and the plaintext
  cache row while keeping the signed skeleton.
- **Old sender keys are kept.** Iteration-0 chain keys are kept for up to 256 generations
  (`group/history.rs`), and `OriginKeyStore::prune_before` has no caller. Every room is created
  forward-only, so nothing ever uses them.
- **Keys travel only on direct pairwise streams.** Anchors are refused those streams
  (`node/net.rs`). Two members who are never online together converge on ciphertext but cannot read
  each other.
- **Anchors keep a ciphertext log for rooms they are not in** (`node/anchor.rs`, ADR-016 M15.2b).
  This was built precisely so that members who are never online together still converge. R34 reverses
  it.
- **Skeletons are large.** The composite signature is 64 + 3309 = 3373 bytes (`hash.rs`), so each
  retained skeleton costs about 3.5 KB. A million-message room holds about 3.5 GB of skeletons even
  after every body has expired.

## Decision

### 1. One order, the same on every node (R13)

- **Proposed schema change (ADR-008).** Each entry's skeleton gains
  `seen: [entry_hash…]`: the heads of *other* authors' feeds that the author had applied when it
  wrote the entry, at most 16 of them. The author's own previous entry is already `prev_hash`. With
  `seen`, the log becomes a true causal DAG across authors, not a set of parallel chains. This is
  the schema change ADR-020 §5 said was needed before claims could have a happens-before.
- **The order.** A deterministic topological sort of the DAG. Ties between concurrent entries are
  broken by `(author's claimed ms, entry_hash)`. Every node holding the same entry set computes the
  identical order. The author's clock can only move an entry among its concurrent peers, never ahead
  of anything it saw.
- **Correction (2026-09-24, found building M23.2): the claimed time is in the skeleton too.**
  The first version of this decision took the claimed ms from the content envelope, which is
  encrypted. A node that cannot decrypt an ancestor (it holds no key for that author yet, or the body
  was pruned) then cannot place it. Every entry after it lands somewhere other than on a node that
  can decrypt it, so the order is not one order. The skeleton therefore carries `claimed_ms` beside
  `seen`, the same value the envelope carries.
  - **Cost:** the claimed send time is visible to anyone holding skeletons. Members already see
    arrival time. Under R34, non-member anchors are to hold nothing (M23.5), so after M23.5 no
    non-member holds skeletons.
  - **The order is a hybrid logical clock.** `clock(e) = max(min(claimed_ms(e), latest(e) + 10 min),
    latest(e) + 1)`, where `latest(e)` is the highest clock among the parents this node holds (its
    own seq−1 and `seen`), or the room's genesis time if it has none. Entries sort by
    `(clock, entry_hash)`. This is the topological sort with the `(claimed ms, hash)` tie-break
    described above, computed incrementally.
- **A claimed time far in the future is capped, relative to the entry's parents.** Without a cap,
  one member posting "tomorrow" would lift every entry that later sees it to tomorrow.
  - **Not against "now":** a cap on the receiving node's clock would differ from node to node, and
    so would the order. The cap is ten minutes past the entry's latest parent (or past the genesis
    for an entry naming none, which closes a crafted parentless entry).
  - **What it costs an attacker:** one post moves the room's clocks at most ten minutes. Moving them
    a day takes 144 posts, each visible and attributable.
  - **Why ten minutes:** honest clocks drift by seconds to minutes, so honest entries are almost
    never capped. When one is (the first post after a quiet spell), the cap moves it only among
    entries it did not see, which is all the claimed time decides.
  - **One lever remains:** the creator's genesis time, which only the creator signs, only once.
- **Late arrivals.** An entry from a member who was offline takes its causal position, which may
  be earlier than rows already shown. The UI inserts it there and marks it as arriving late. It
  does not move to the bottom.
- **Claims.** `seen` gives claims (vox-96's R17 work) a real happens-before: a claim that saw
  another claim follows it. Only truly concurrent claims fall back to the tie-break.
- **Size.** A `seen` entry is 32 bytes; 16 are about 0.5 KB, against a 3.4 KB signature.

### 2. Retention (R6–R10)

- **The room's policy** is the existing ADR-007 policy-update `ttl`:
  - `0` means forever;
  - any other value is disappearing after that many seconds;
  - the UI offers 1 hour, 1 week, 1 month or a custom value;
  - it is set by any holder of the `policy` capability (the admin).
- **The node's policy** is local configuration (`retention` in the node's config directory), per
  room or as a default.
- **Effective retention is the minimum of the two** (shortest wins).
- **Retroactive.** Whenever the effective retention changes, and on a periodic sweep (every minute),
  every entry older than it is pruned:
  - its payload body is dropped;
  - its plaintext cache row is deleted;
  - the signed skeleton is kept.
- **Age** is measured by the author's claimed timestamp, clamped to be no later than the time this
  node first saw the entry. So a back-dated message can expire early, but a future-dated one cannot
  live longer.
- **Nothing visible remains.** A pruned row is not rendered and does not count toward unread.
- **Reload accepts pruned entries.** A pruned entry whose skeleton verifies is accepted on reload
  and on sync (fixes `channel.rs:858`). Sync never ships a body a node no longer has, and a peer
  asking for one gets the skeleton.
- **Not a security property.** A modified or malicious node can keep everything. The UI and docs say
  so.
- **Claims and work items** are entries like any other, and they expire with the room. **Decided
  2026-09-25:** "Agent communication is not meant to be a source of truth… it's a communications
  coordination layer; the source of truth is the accountability skill and GitHub."

### 3. Skeleton growth: checkpoints (R1)

Keeping every skeleton forever makes an unbounded room cost about 3.5 KB per message forever. The
proposal is **author checkpoints**:

- A member may post a checkpoint entry signed by its root. It names one author's feed position
  `(author, seq, entry_hash)` below which that author's skeletons are older than the retention window.
- A node that holds a checkpoint may drop the **signatures** of that author's skeletons at or below
  the named position. It keeps each entry's 32-byte hash and hash links, so the chain still verifies
  up to the signed checkpoint.
- **Fork detection is unaffected above the checkpoint.** Below it, a conflicting entry is refused
  as older than the checkpoint rather than frozen as a fork. It could never be rendered anyway, because
  its body is expired.
- This applies only to rooms with a non-zero effective retention. A forever room keeps everything,
  because its bodies are kept too.

**Decided 2026-09-25: build checkpoints now** (M23.6). As built:

- **Only the author checkpoints, and only its own feed.**
  - The checkpoint is the payload of an ordinary entry in the author's own feed (struct tag
    `0x0015`, body `[seq, entry_hash]`), signed like any entry. It names a position on the same
    hash chain its signatures already vouch for, so it adds no trust.
  - A checkpoint by anyone else would let one member make every node forget another member's
    signatures, which are the evidence a fork proof needs.
  - The cost: an author who never returns never checkpoints, and its old skeletons keep their
    signatures. That is the conservative failure.
- **When the author posts one.** The room's retention is not forever. A node's own shorter limit
  does not count, because it is not the room's business. And at least 32 more of the author's
  entries have expired on its node since its last checkpoint. A checkpoint is itself a signed
  entry about the size one skeleton saves, so one per 32 costs about 3% of what it frees.
  - **Or a closing checkpoint:** fewer than 32 have expired, and nothing new has expired on its
    node for ten minutes. No expired entry keeps its signature indefinitely.
  - **Asked on every tick, not only after a prune.** The check looks only past the last checkpoint
    and stops at the author's first entry still holding a body, so it costs almost nothing. That is
    what checkpoints a backlog that is already expired when the room is opened after a restart, or
    one that expired while the room still kept everything, without waiting for another prune.
- **Which position it names.** The highest one below which every content entry of the author has
  had its body pruned there. Governance and earlier checkpoints keep their bodies and never hold it
  back.
- **Shedding.** A node sheds the signature of an entry at or below its author's checkpoint whose
  body it has pruned, and only when its effective retention is not forever. It does so when the
  checkpoint arrives, or when it prunes such an entry afterwards.
  - The shed entry is stored with authenticator type `0` and no bytes.
  - It stays authentic through the chain: the signed checkpoint names its position's hash, and
    each entry's successor names it in `prev_hash`.
  - An unsigned entry never verifies on its own. The DAG takes one only inside a sync session or
    a reload, provisionally. It becomes authentic once a signed entry of the same feed chains to
    it, and whatever never does is taken back at the end of the session.
  - A newcomer therefore syncs signed entries from the checkpoint onward and hash-chained skeletons
    below it. It holds the same entry set, so it holds the same order.
- **Refusal below the line.** An entry for a position at or below its author's checkpoint that the
  node does not hold as it is refused as pre-checkpoint, never classified as a fork. In a sync
  session the refusal is not fatal.

### 4. Key delivery through members (R11, R14) — and why the anchor needs nothing

- **An owed sender-key message goes into the log.** When a member owes another member a sender key
  (consent granted, or a rotation), it seals the SKDM to the recipient and posts it as a log entry of
  a new kind, `key-package` (struct tag assigned when built). The seal uses the pairwise channel's
  keys if a session exists, and otherwise a one-shot PQXDH to the recipient's published prekey
  (ADR-004).
- **Every member node replicates it** like any entry. An always-on member, the NAS for example,
  holds it and delivers it when the recipient next syncs. **No store-and-forward service is added**:
  the log already is one.
- **What it reveals.** A `key-package` shows who is sending keys to whom, and when. The consent
  entries already reveal that, so it adds no new metadata to a member.
- **Size.** It is roughly one SKDM, a few hundred bytes plus the signature.
- **Retention.** A `key-package` is pruned once its recipient has acknowledged it. The recipient's
  next entry lists it in `seen`, which is the acknowledgement.
- **R14, pruning.** A sender keeps only the origin key of the generation in use, plus any generation
  a *full-history* grant still has to release (decision 5). `prune_before` runs when a generation is
  superseded. Zeroization on drop is already in place (`Zeroizing`).
- **The consequence the decider accepted (PRD-001 §7 Q7).** A room with **no** always-on member,
  whose members are never online together, cannot deliver keys. `vox status` must say so for that
  room ("no always-on member: keys wait for overlap").

### 5. History per grant (R12)

When approving a newcomer, the approver's node asks "from now" (the default) or "full history". It
releases the SKDM at the current iteration, or at iteration 0 of each generation still within
retention (`group/history.rs` already implements the release). The choice is the approver's, and
covers only the approver's own messages, as consent always has.

### 6. Anchors store nothing (R33–R34)

- **An anchor that is not a member of a room holds nothing for it** except:
  - rendezvous board records: addresses and bundle records, small and short-lived (ADR-012);
  - the relay's in-flight datagrams (ADR-022).
- **The ciphertext anchor log is deleted:** `node/anchor.rs`, the anchor sync sessions, and
  `SegmentKind::AnchorLog` / `AnchorMeta`.
- Stored anchor pages on existing nodes are deleted on upgrade. There is no migration: pre-alpha,
  one operator.
- **What replaces it for convergence:** decision 4 plus an always-on **member**. A node that is both
  an anchor and a member (the NAS) holds the room because it is a member, not because it is an
  anchor.
- **The existing gate** `node_m15_anchor_gate` ("members never online together converge through an
  anchor") asserts the withdrawn model. It is **rewritten**, not extended: two members never online
  together converge and read each other through an always-on member node, and a non-member anchor's
  data directory holds zero pages for the room.

## Consequences

**Positive.**

- One order everywhere, and claims gain a real happens-before.
- Retention becomes possible.
- Forward secrecy improves (R14).
- Anchors become what the decider asked for: dumb pipes with nothing worth seizing.

**Negative.**

- Two members who are never online together **require** an always-on member.
- The skeleton gains `seen`.
- Late arrivals can appear above rows already read.
- Checkpoints add a new entry kind, if they are built.

**Neutral.**

- There is no compatibility ceremony. The ADR-008 skeleton changes once and every node updates.

## Proofs (shipped binary, mutation-checked, counts printed)

1. **Same order:**
   - three nodes post concurrently, and one of them was offline for part of it;
   - after convergence, `vox room read` prints the identical sequence of entry hashes on all three;
   - mutation: arrival order, and the gate goes red.
2. **Causal:** a reply posted after reading a message is ordered after it on every node, even when
   the replier's clock is set an hour behind.
3. **Retroactive retention:**
   - a room with 100 messages is switched to 1 hour, with 40 of them older;
   - on every member, `vox room read` shows 60, and the plaintext cache holds 60 rows;
   - a restart still opens the room.
4. **Shortest wins:** the node is set to 1 minute, the room to 1 week, and the node prunes at
   1 minute.
5. **Offline keys through a member:**
   - A and B are never up together, and C is always on;
   - B reads every message of A's, including across a rotation;
   - with C removed, B reads none, and `vox status` says why.
6. **Anchors hold nothing:** after a full session through a non-member anchor, its data directory has
   zero pages for the room.
7. **R14:** after two rotations, the sender's key store holds one generation (read by a diagnostic).

## Implementation plan

- **M23.1** Reload and sync accept pruned entries; retention policy and sweep (decision 2).
  Proofs 3–4. **DONE for proofs 3 and 4 and the late-arrival rule** in 24b4433 on `prd1/retention`
  (`crates/vox-tui/tests/retention_proof.rs`, shipped binary, each mutation-checked red; counts in
  ADR-010 §"Retention / TTL"). Not built within it: a room created with a retention (creation still
  writes `ttl` 0; `vox room retention` sets it after), and a gate isolating "a peer asking for a
  pruned body gets the skeleton" (the code path exists; nothing measures it alone).
- **M23.2** `seen` and the deterministic causal order (decision 1). Proofs 1–2. R17's
  takeover-after-silence does not need it. Hard-lock claims (PRD-001 §7 Q5) are to be designed on it
  if the decider answers "wait for certainty". **Built on `prd1/causal-order` (on v0.2.8). Proofs 2
  and 3 DONE through the shipped binary. Proof 1 DONE on in-process nodes; through three daemons it
  is intermittently red for a connectivity defect below the log, so it is NOT marked done there.**
  - The skeleton carries `seen` (≤16 heads of other authors' feeds, strictly ascending) and
    `claimed_ms` (decision 1, correction).
  - **The order:** the hybrid logical clock with the ten-minute cap, sorted by `(clock, hash)`. An
    unknown `seen` hash never blocks acceptance. When it arrives, what named it is recomputed, and
    whatever moved takes its descendants along.
  - **The timeline:** kept in that order. A late row is inserted at its place and flagged `late`,
    and the TUI prefixes it `[late]`.
    - **Revised 2026-09-25:** a row is late only when it lands above a row the reader was already
      shown, meaning one placed at least 10 s before it arrived. Rows loaded at open count as shown
      before the restart.
    - The first definition ("rendered after a row now below it") also flagged ordinary
      concurrency. Posts crossing in flight land within a second, above one another.
    - **Proof:** `causal_order_proof::a_late_arrival_is_marked_and_posts_that_cross_are_not`,
      shipped binary, 3 of 3 green.
      - Crossing posts: 0 of 12 marked late on either node.
      - Bob posts and his daemon is frozen (SIGSTOP) before its push. Alice posts 3, waits 12 s,
        and then bob is thawed. His post lands at 15, above "meanwhile 1" at 16, and `vox room
        read --late` lists exactly it.
    - **Mutations, each red:** the first definition gives "alice marks crossing posts late"
      (6 of 12); never-late gives "exactly the late post is marked late", left `[]`.
  - **`vox room read --since` is arrival-based:** a late row lands above the cursor, and a
    positional read would skip it forever.
  - **`vox room read --hashes` (hidden):** prints `<hash> <clock-ms>` for every held entry, in
    order.
  - **For claims:** `Dag::happened_before(a, b)` and `ChannelState::happened_before` are the
    relation R17 is to use; nothing consumes them yet.
  - **Proof 2 DONE:** `crates/vox-tui/tests/causal_order_proof.rs`
    `a_reply_follows_what_it_answered_even_from_a_clock_an_hour_behind`, shipped binary.
    - Bob's clock is −1 h (test-only `VOX_TEST_CLOCK_SKEW_MS`). The answer's stored claimed time is
      59 min before the question's.
    - On all three nodes the answer follows the question (11 → 13 of 14, one SHA-256).
    - Mutation, `seen` ignored in the sort: red, "alice orders the answer (1) before the question it
      answered (9)".
  - **Proof 3 (the cap) DONE:** same file,
    `a_post_from_a_clock_a_day_ahead_does_not_drag_the_room_a_day_forward`.
    - Bob's clock is +1 day, and his stored claim is 1439 min ahead.
    - Alice's post after reading his is placed 9 min ahead of when she wrote it, still after his,
      on both nodes.
    - Mutation, cap removed: red, "placed 1439 min ahead of when it was written".
  - **Proof 1 DONE in-process:** `crates/vox-core/tests/one_order_gate.rs`, three networked `Node`s,
    one shut down for a round and restarted.
    - All three end with 54 entries and one SHA-256. Each timeline (48/36/30 readable rows) is an
      ordered subsequence of it.
    - Mutation, arrival order: red, "bob's order differs from alice's (first difference at
      Some(0))", three different SHA-256s.
    - Mutation, the timeline appended in arrival order: red, "alice's timeline shows 'one bob 1' out
      of the room's order".
  - **Proof 1 through the shipped binary:**
    `three_members_one_offline_for_a_while_show_one_order`, 4 green and 5 red of 9 on v0.2.8.
    - Green runs: 58/58/58 and 57/57/57 entries, one SHA-256 each time.
    - Every red has the same signature: the second joiner is cut off from the first post onward (e.g.
      alice 49, bob 49, carol 25). In the four whose logs were captured, its restarted daemon logs "a board would not take our address …
      rejected: the board holds a newer record from that author".
    - The defect is not M23.2's: 1 of 4 red on 3cac220 without it, same signature. Replaying the
      stopped stores through `ChannelState::sync_over` converges them at once.
    - It is skipped by name in release.yml and ci.yml with this cause, and reported as a v0.2.9
      defect.
- **M23.3** `key-package` log entries and R14 pruning (decision 4). Proof 5. This replaces F12's
  delivery mechanism: F12 is a narrow v0.2.8 fix of SKDMs sent over pairwise sessions, covering the
  simultaneous-initiation race and trust-before-join. F12's proofs are to be kept as regression
  gates:
  - joiner↔joiner in a 3-member room;
  - creator→joiner across processes through an anchor;
  - trust-before-join.
- **M23.4** Per-grant history (decision 5).
- **M23.5** Delete the anchor log (decision 6). Rewrite `node_m15_anchor_gate`. Proof 6.
- **M23.6** Checkpoints (decision 3). **DONE** on `prd1/causal-order` (commit in the report).
  - `crates/vox-tui/tests/checkpoint_proof.rs`
    `a_disappearing_room_sheds_expired_signatures_reopens_and_a_newcomer_syncs_it`, shipped
    binary, one author with 100 messages and then a 20 s retention.
    - **Store bytes:** measured stopped. Before: 100 log pages, 709,945 bytes, 0 smaller than a
      signature. After: 102 pages, 32,359 bytes, 100 smaller than a signature.
    - **Mutation, shedding disabled:** red, "only 0 of alice's 100 expired entries shed their
      signature". Its store held 369,859 bytes after the same expiry. The shed room is
      337,500 bytes smaller, 3,375 per entry: the 3,373-byte signature and its CBOR length.
    - **Restart:** alice's room reopens from the shed store.
    - **Cold joiner:** bob joins after the shedding. He holds 104 entries in an order identical to
      alice's 104, and his own store has 100 pages smaller than a signature. He received the
      skeletons below the checkpoint hash-chained, not signed.
    - **Forged entries:** a conflicting entry signed with alice's own key at seq 5 is refused with
      "entry is at or below its author's checkpoint", and the room keeps 102 entries. An unsigned
      one is refused too.
    - **Mutation, pre-checkpoint refusal removed:** red, with the equivocation taken to the fork
      path ("entry failed the acceptance predicate").
  - **Closing checkpoint:** `a_backlog_under_a_batch_is_checkpointed_once_the_room_goes_quiet`.
    - 10 messages expire together, and just after, 0 pages are smaller than a signature.
    - After 20 s quiet (idle set to 15 s by the test-only `VOX_TEST_CHECKPOINT_IDLE_SECS`;
      production is 10 min), 10 of 12 pages are.
    - Mutation, no closing checkpoint: red, 0 of 11.
  - **Without another prune:** `an_expired_backlog_is_checkpointed_without_waiting_for_another_prune`.
    - The node keeps 20 s and the room keeps everything, so 40 messages are pruned and not
      checkpointed.
    - The room is then set to a week and the node restarted. Nothing is left to prune, and 40 of
      42 pages are smaller than a signature.
    - Mutation, checkpoint asked only after a prune (the first M23.6 trigger): red, 0 of 41.

## Decider's answers (2026-09-25)

1. **Claims and work items expire with a disappearing room.** In the decider's words: "The agent
   communication is not meant to be a source of truth for anything — it's just a communications
   coordination layer. The source of truth is the accountability skill and GitHub."
2. **Build checkpoints now** (M23.6).
3. **A late arrival is shown in its causal place, marked late.** Built in M23.2; the flag was narrowed in M23.6 to
   rows placed above something already shown for 10 s.
