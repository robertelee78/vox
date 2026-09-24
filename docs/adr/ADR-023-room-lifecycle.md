# ADR-023: Room lifecycle — one order, retention, key delivery through members, dumb anchors

**Status**: **proposed — nothing here is built.** 2026-09-24. Each milestone is marked `DONE` only
with the commit and gate that proved it.
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
- **Claims and work items** are entries like any other, and they expire with the room. (Open
  question 1 below.)

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

(Open question 2 below: build checkpoints now, or when a real room gets large?)

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
  if the decider answers "wait for certainty". **Built on `prd1/causal-order`; proof 2 DONE, proof 1
  DONE on in-process nodes and red through three daemons for a cause below the log.**
  - The skeleton carries `seen` (≤16 heads of other authors' feeds, strictly ascending) **and
    `claimed_ms`**. The ms had to move into the signed skeleton: a node must place entries it cannot
    decrypt (no key yet, body pruned), or rows after them land elsewhere than on a node that can.
    ADR-008 §"Cross-author edges and the one order" has the rule.
  - The order is a hybrid logical clock, `clock(e) = max(claimed_ms, clock(parent)+1)` over the
    own-feed predecessor and `seen`, sorted by `(clock, entry_hash)`. An unknown `seen` hash never
    blocks acceptance. When it arrives, what named it is lifted and the timeline re-sorts.
  - The timeline is kept in that order, and a late row is inserted at its place and flagged `late`.
    The flag means "rendered here after a row now below it", so ordinary concurrency sets it too, not
    only an offline member's return. `vox room read --since` became arrival-based: a late row lands
    above the cursor and a positional read would skip it forever. `vox room read --hashes` (hidden)
    prints the whole order, readable or not.
  - `Dag::happened_before(a, b)` / `ChannelState::happened_before` is the relation for claims (R17);
    nothing consumes it yet.
  - **Proof 2 DONE:** `crates/vox-tui/tests/causal_order_proof.rs`
    `a_reply_follows_what_it_answered_even_from_a_clock_an_hour_behind`, shipped binary, bob's clock
    skewed −1 h by the test-only `VOX_TEST_CLOCK_SKEW_MS`. The answer's stored claimed time was read
    back 59 min before the question's. On all three nodes the answer came after the question
    (question 11, answer 13 of 14; one SHA-256 across the three). With `seen` ignored in the sort:
    red, "alice orders the answer (1) before the question it answered (9)".
  - **Proof 1 DONE in-process:** `crates/vox-core/tests/one_order_gate.rs`, three networked `Node`s.
    One is shut down for a round and restarted on the same store and address. All three end with 54
    entries and one SHA-256, and each timeline (48/36/30 readable rows) is an ordered subsequence of
    it. Two mutations, each red: arrival order ("bob's order differs from alice's (first difference at
    Some(0))", three different SHA-256s), and the timeline appended in arrival order ("alice's timeline
    shows \"one bob 1\" out of the room's order").
  - **Proof 1 through the shipped binary is red today, and not for the order.**
    `three_members_one_offline_for_a_while_show_one_order` (same file as proof 2) never converges: the
    second joiner's records are refused by the boards and no session with it runs. This reproduces on
    dc868cf without M23.2: over 315 s the second joiner rendered 0 of the other two's posts, and they 0
    of its. Replaying the stopped stores through `ChannelState::sync_over` converged them at once.
    Where the three daemons did overlap, their sequences agreed.
- **M23.3** `key-package` log entries and R14 pruning (decision 4). Proof 5. This replaces F12's
  delivery mechanism: F12 is a narrow v0.2.8 fix of SKDMs sent over pairwise sessions, covering the
  simultaneous-initiation race and trust-before-join. F12's proofs are to be kept as regression
  gates:
  - joiner↔joiner in a 3-member room;
  - creator→joiner across processes through an anchor;
  - trust-before-join.
- **M23.4** Per-grant history (decision 5).
- **M23.5** Delete the anchor log (decision 6). Rewrite `node_m15_anchor_gate`. Proof 6.
- **M23.6** Checkpoints (decision 3), if open question 2 says now.

## Open questions for the decider

1. Do claims and work items expire with a disappearing room, or are they exempt?
2. Checkpoints now, or when a real room gets large?
3. Is a late arrival shown in its causal place (proposed), or at the bottom with a marker?
