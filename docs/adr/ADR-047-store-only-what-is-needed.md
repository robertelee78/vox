# ADR-047: Store Only What Is Needed

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted (2026-11-13) as the design for v0.4.31, under the decider's authorization
of 2026-11-13 ("post review can accept them too"), after the twelfth independent review by
GPT-6.1-Sol passed revision 14 (`adr-047-sol-review-12`); proposed 2026-11-12.
The rulings it records are the decider's own words of 2026-11-12 and 2026-11-13, quoted below.
Nothing in this ADR is built; every change is written as what is to be done. This is revision 14:
revision 2 resolved the first independent review (`adr-047-sol-review`, sixteen findings),
revision 3 the second (`adr-047-sol-review-2`, N1–N13), revision 4 the third
(`adr-047-sol-review-3`, R3-1–R3-7) and the decider's answers of 2026-11-13 (ledger rows 32 and
48–51), revision 5 the fourth (`adr-047-sol-review-4`, R4-1–R4-6 and its ruling on the
experiments), revision 6 folded in the measured experiments (`store-experiments`, E-1, E-2, E-7, E-10) and
the decider's confirmations of 2026-11-13 morning (ledger rows 59 and 61), and this revision
resolves the fifth review (`adr-047-sol-review-5`, R5-1–R5-4), revision 8 reconciled SO-12
with ADR-044 revision 11's six facts (the waiter rule has one owner, RD-7), and this revision
resolves the sixth review (`adr-047-sol-review-6`, R6-1–R6-3 and the reserve outcome) against
ADR-044 revision 12's settlement, and revision 10 the seventh (`adr-047-sol-review-7`,
R7-1–R7-4, C1), ADR-044 RD-7 revision 13's facts, the task cut's ADR defects D1–D22 and the
cross-ADR asks, revision 11 the eighth (`adr-047-sol-review-8`, R8-1–R8-5) and the decider's
row 74 (ADR-044 RD-7 revision 14: one save, one trip; SO-12 settles no waiter), and revision 12
the ninth (`adr-047-sol-review-9`, R9-1–R9-5), ADR-046 revision 10's one-answer fence-post
summary (ledger rows 76, 77) and a removal of dead text, and revision 13 the tenth
(`adr-047-sol-review-10`, R10-1–R10-3), and revision 14 the eleventh (`adr-047-sol-review-11`,
R11-1); all are in "Review record". Where a finding showed a design wrong, the design is
replaced, not qualified.
**Date**: 2026-11-12
**Deciders**: Robert E. Lee
**Tags**: store, disk, redb, retention, session, signatures, compaction, disk-full, status
**Related**: ADR-003, ADR-005, ADR-006, ADR-008, ADR-010, ADR-018, ADR-029, ADR-031, ADR-034,
ADR-036, ADR-037, ADR-038, ADR-040, ADR-041, ADR-042, ADR-043, ADR-044, ADR-045, ADR-046,
ADR-048, ADR-049, ADR-050
**Inputs**: the v0.4.31 fix list (items 20–25, 59, 64, 76–80, 85–87); plan C of 2026-11-12; the
byte accounting of omp-work's store (`rca-StoreSize`); the root-cause reports RcaChurn,
RcaPreparing and RcaSchedStall; the consolidated analysis of 2026-11-12; the operator's evidence
under `/private/tmp/vox-rca/` (**every receipt under `/tmp` or `/private/tmp` cited in this
ADR was lost in the reboot of 2026-11-13; each figure is recorded in the report named beside
it — `rca-StoreSize`, `rca-RcaChurn`, `rca-RcaPreparing`, `adr-047-revision`,
`store-experiments` with `store-exp-receipts/` — and is to be re-run as the fleet baseline;
ledger row 64, said once here for all of them, r10: D21); the reviews `adr-047-sol-review` and
`adr-047-sol-review-2`; the
measurements of revision 2 (`adr-047-revision`, run on a clone of the operator-approved copy of
omp-work's store with redb 4.3.0 alone, receipts under `/tmp/adr047/`); the sibling revisions
ADR-044 r3 (RD-9: fork gate and per-leaf signature re-check dropped; the proof handoff), ADR-046
r2 (SY-18: no inclusion receipts under either representation; SY-24; SY-26) and ADR-049 (leaving
and ending rooms, split from ADR-040). Code is cited at tag v0.4.30 (`8d71ab337`). The decider's
rule for this release: every known defect is fixed in it (AGENTS.md, "Releases").
**Rulings recorded** (the decider, 2026-11-12):

- On the order of work: "compaction is fine -- but not storing things we shouldn't, storing what
  we should efficiently, pruning what we don't need … all come as higher order". This ADR is
  ordered by that rule: (1) do not store what we should not; (2) store what we should,
  efficiently; (3) prune what is no longer needed; (4) compaction only as a backstop.
- On the sync proof records (526,079 rows for 4,221 entries, 268 KB on disk per entry): "no need
  to keep anything like this".
- On agent Session steps (12.8 KB each on disk; 85% of a step is two signatures; the body is
  stored twice): "we need to store only what we need".
- On one small row occupying a whole 4 KB page: "crazy".
- On the Session view rebuilt from scratch at every change (487 page writes a second): "why".
  C-77 answers it before SO-6 replaces it.
- (2026-11-13) All machines move to 0.4.31 together: no mixed-version sync, no mixed-version
  store. The release gate for a candidate fits 8–10 hours of wall clock: long-run store growth is
  judged by a measured rate and its projection, not by a day-long run (the rate bound is SO-15's
  growth arm). The whole gate runs inside VMs (row 32).
- (2026-11-13, his answers to this ADR's questions, ledger rows 48–51; "The decider's answers"
  below): no byte budget for Session steps, and "lets change from seven days to two days": step
  retention is 2 days (SO-8, amendment 8). One signature per private record, the author's root
  composite (SO-4). Recover in place after a write failure, rooms readable until done (SO-12). A
  store redb reports corrupt is left untouched and named (SO-9). Existing stores convert in
  place at the first start (SO-2); the fresh-profile alternative is withdrawn. The backstop runs
  at daemon start and on `vox node compact` only (SO-10). The in-tree full-disk journey is
  optional; the fleet's full-disk and stall journeys block (SO-11, SO-12, SO-14).

## Context

### Where the 3.01 GB went

The operator's node omp-work had a store file of 3,011,973,120 bytes at 19:00Z on 2026-11-12.
An APFS clone of it was read page by page (`rca-StoreSize` §1, tool `redbwalk.py`, cross-checked
against redb's own `stats()`; this revision read it again with redb 4.3.0 itself: 679,546 rows,
739,989,757 B of values, 400,898 leaves, 12,326 branches, 1,421,718,034 B fragmented, the same
figures). Every byte of the file is accounted for:

| Part of the file | Bytes | Share |
|---|---:|---:|
| Leaf pages that hold rows (400,898 leaves) | 2,141,995,008 | 71.1% |
| — of which the rows themselves (679,546 rows: keys and values) | 740,185,443 | 24.6% |
| — of which empty space inside those leaves (leaf slack) | 1,401,809,565 | 46.5% |
| Branch pages (12,326) | 50,487,296 | 1.7% |
| `meta`, `sek_wraps` and redb's system tables | 311,296 | 0.0% |
| **In use** (reachable from the commit slot) | **2,192,793,600** | 72.8% |
| Free pages: freed, reusable, never returned to the disk (199,994 pages) | 819,175,424 | 27.2% |
| redb's super-header | 4,096 | 0.0% |
| **File** | **3,011,973,120** | 100% |

The same leaf pages, by what the rows are for:

| What it is | Leaf bytes on disk | Share of file | Rows' own bytes |
|---|---:|---:|---:|
| Sync proof records and sync bookkeeping | 1,129,850,709 | 37.5% | 133.6 MB |
| Agent Session steps (39,547) | 507,248,640 | 16.8% | 398.3 MB |
| Indexes (entry, Session, governance, attention) | 436,917,114 | 14.5% | 173.9 MB |
| **Messages people and agents posted** (log entries, rendered text, first-seen rows) | **67,166,207** | **2.2%** | 33.7 MB |
| Keys | 812,333 | 0.0% | 0.5 MB |

**The messages are about 2% of the file.** Over a third of the file is sync proof records that
nothing needs once a fetch ends. Almost half of it is empty space inside pages. A quarter is free
pages. One hour later, at 21:38Z, the file was 4,294,971,392 bytes: redb's next growth step
(`/private/tmp/vox-rca/store-size-samples.tsv`).

### What was measured for this revision (the clone, redb 4.3.0 alone, no vault key)

These runs read only sealed bytes, keyed `(room, kind, id)`; the kind is in the clear, the
values are not. Proof records are the EntryIndex rows of 200–223 B (502,406 of them; the RCA's
count by the sealed object directory was 502,408); verifier cursors the three EntryIndex rows of
12–13 KB. Tool: `/tmp/adr047/probe` (redb 4.3.0 from the cargo registry); receipts
`/tmp/adr047/exp1.log`, `exp2.log`, `exp3.log`.

| Run | Result |
|---|---|
| Rewrite every row into a fresh file, one table (what `Store::rewrite_fresh` does) | 8.3 s with a 256 MB redb cache (the RCA measured 21 s with the product's cache bound); file length 1,077,940,224 B; allocated 1,030,926,336 B (740.0 MB stored + 11.7 MB redb metadata + 279.2 MB slack); on disk 1,007,092 KB |
| Rewrite without the proof records and cursors (SO-1–SO-3) | 502,412 rows dropped; data 611,943,479 B; allocated 873.4 MB (slack 254.3 MB); on disk 853,236 KB |
| Rewrite into two tables, values ≤ 2,048 B apart from larger ones (SO-5), proof rows dropped | allocated 834.6 MB: the small table packs 24.3 MB of rows into 6,257 leaves at 93% full (1.3 MB slack); the large table holds 587.6 MB of rows with 215.0 MB of slack, which is the power-of-two rounding of rows over 4 KB and no table layout removes it |
| The same with the threshold at 1,024 B | the same within 0.1 MB (the threshold is not sensitive) |
| Delete the 502,412 proof rows and cursors in place, 256 per commit (SO-2's sweep) | 1,963 commits in 10.0 s, 5.1 ms per commit; the single-row leaves merge away as their rows go (400,898 → 144,314 leaves); the file length does not change |
| Then redb's `compact()` in place, no second file | 1.9 s; file 3,011,973,120 → 1,642,336,256 B; needs no free disk |
| Random `get` of 4,221 EntryIndex rows of 1–12 KB, after a full scan of the table in the same process, default redb cache | 2.6 µs per row on the first pass, 1.1 µs on the second. This is a raw redb lookup microbenchmark: no unseal, no sparse-directory traversal, no context decode or join, no signature; the rows are not identified as one author's headers. It bounds nothing about a derivation (SO-1's cost is E-1's, measured in revision 6) |
| redb 4.3.0 on a 64 MB APFS image: write 1 MB rows until the disk is full, then reopen the same file | commit 30 fails `No space left on device`; the next `begin_write` is `Previous I/O error … close and re-open`; the stock crate refuses reads too (Vox's vendored hunk keeps reads); drop the handle, open the same path: opens; delete four rows: commits; insert 256 B and then 1 MB: commit (freed pages reused); `compact()`: file 83,955,712 → 58,724,352 B, the disk goes from 96% to 86% full |
| Session steps by their measured size distribution (39,547 rows, mean value 10,031 B; body p50 349 B, mean 1,390 B, p99 17.8 KB) | as-is in power-of-two pages: 508.2 MB (measured 507.2 MB, the model holds); one composite signature kept inline: values 260.8 MB, disk 424 MB (most rows stay over 4 KB and keep an 8 KB page); one signature in a row of its own: step rows 127.4 MB packed into 171.6 MB, signature rows 162.0 MB (one 4 KB page each): 333.6 MB; no per-step signature (a hash chain, one checkpoint per ten steps): 188 MB |

Two numbers the first draft got wrong follow from these runs: the two-table split saves little
at the moment of a rewrite (a bulk rewrite already packs small rows; its value is that rows
written later do not strand again), and dropping a signature saves disk only when the signature
leaves the step's row, because a 6.6 KB row still takes an 8 KB page. Appendix B is recomputed
from these runs. Three labels are kept apart everywhere below, because the receipts show them
apart: **file length** (`ls -l`; every rewrite of the clone left 1,077,940,224 B, redb's growth
step), **disk use** (`du`; 835 MB after the drop-and-split rewrite) and **data** (the rows, 612 MB
after the drop). The step-size figures (508.2 / 424.1 / 333.6 / 188 MB) are a model over the
measured value distribution (power-of-two pages for values over 2,048 B, 93% fill below, 41-B
keys, 24-B leaf overhead); the model reproduces today's measured 507.2 MB within 0.2%, and its
inputs are the value lengths kept as `/tmp/rca-StoreSize/clone.redb.sizehist.json`.

### What the operator saw

- Stores of 3.01 GB (omp-work), 6.66 GB (robert-work) and 6.44 GB (beast's omp-beast), flat for
  hours and then a jump (`store-size-samples.tsv`). beast's 6.44 GB file occupies 4.1 GB of disk
  (`beast/node-dir-listing.txt`: `du` 4.1G): the file is sparse, its length is not its disk use.
- On 2026-11-11 beast's disk filled. Its log: 1,276 × `store commit: I/O error: No space left on
  device`, 40 × `recovery could not complete its retained save`, a 13.6-minute loop, then
  `repo-to-cve recovered; it can save again` at 21:48:36Z. A file `store.redb.failed-1` (805 MB
  long, 385 MB on disk) is still there (`beast/node-dir-listing.txt`).
- A joiner refused by that member was told `a member answered and refused the join — usually the
  room passphrase is wrong`.
- Nothing in `vox status` said how big a store was, what a room cost, or how much disk was left.
  The operator learned the numbers with `ls` and a redb parser.
- (Items 64 and 86.) A member could not leave an ended room; the leave's last step is a
  whole-store rewrite (`crates/vox-core/src/node/actor/leave_save.rs:348`), which on a short disk
  fails as the recovery did. ADR-049 owns the leave; SO-9 owns the store's part.
- (Items 85 and 87; `rca-RcaSchedStall`, reproduced on the release asset.) A node whose disk
  filled for 60 s stopped syncing for good: each sync round's flow runs a local cleanup save when
  it ends; the saves that failed on the full disk left their flows pinned in `retirement_failed`
  (`crates/vox-core/src/node/actor/bounded_sync.rs:1854-1860`), waiting on a future that completes
  only on a node lock or a flush settlement (`history_stream/runtime.rs:1814-1848`) and never on
  the room's `recovered; it can save again`; eleven pinned flows exhausted the node-wide cap
  (`RETAINED_FLOW_LIMIT = 12`, `:580`, `can_retain_new`, `:1789-1810`) and every round was refused
  with no reason recorded. So a full or briefly failing disk is not only a storage event: it
  leaves work waiting on the store's recovery. ADR-046 SY-24 owns the scheduler; SO-11 owns what
  the store signals when a room can save again, and the full-disk journey stages this state.

Status words below: **KNOWN** = reproduced on the release binary, or read off the operator's
machines or evidence, or measured on the clone with the receipt named; **INFERRED** = fits the
evidence, not reproduced; **UNKNOWN** = not explained, with the experiment that settles it.

### C-20. Sync proof records are written per fetch and never deleted (fix-list item 20)

**What the person saw.** The file grew by about 320 MB an hour while 360 entries arrived in two
hours.

**Root cause (KNOWN).** repo-to-cve holds 502,408 `ObjectKind::ProofRange` rows of 212–216 B and
23,671 bookkeeping rows for 4,221 log entries (`rca-StoreSize` §1; RcaChurn C1,
`/tmp/rca-RcaChurn/hist-o6z3.txt`). Each one sits alone in a 4 KB leaf (C-76): 1,130 MB of disk
for 134 MB of rows. In two hours 247,256 more were written (34 a second), 687 per entry admitted
(`rca-StoreSize` §3.iii). RcaChurn measured 14 per admitted entry on a healthy direct sync and
about 1,000 on a starved one. Two writers, one key space, no deletion:

- Receiver: when a proof verifier completes, `keep_generated`
  (`crates/vox-core/src/node/history_stream/admission.rs:449-466`) keeps every verified tree range
  through `keep_history_proof_range`
  (`crates/vox-core/src/node/channel/entry_store/sparse.rs:2506-2540`). The key is
  `(head, author, start, leaves)` (`proof_range_key`, `sparse.rs:283-295`). Each abandoned fetch
  targets a newer head (fix-list items 1 and 2, ADR-046), so the same entry's ranges are stored
  again under every head seen.
- Server: answering a peer's proof writes the same records
  (`crates/vox-core/src/node/channel/proof_range.rs:298-301`). ADR-044 RD-8 and RD-9 remove this
  write.
- Nothing deletes them. The only readers are the serving path (`proof_range.rs:179-186`) and
  own-history recovery (`crates/vox-core/src/node/channel/own_history.rs:402-404`); no acceptance
  path reads them (`sparse.rs:218`: "never used by acceptance or authored appends").

**Why it was built.** #1053 (`926b6bd37`, 2026-10-27, "Recover retained-key own history after
restoring a backup"). It lets a node restored from an older profile recover its own feed
(ADR-037 R5, ADR-038 FX-32) and serve proofs without deriving them again. It is a cache with no
eviction, keyed by a value that changes at every post.

**What the cache provides that nothing else persists (KNOWN, from code; the first draft said this
imprecisely).** `ProofRangeRestore::restore` (`proof_range.rs:108`) answers a range first from the
canonical acceptance ranges (`history_range`, `:179-180`), then from the cache (`:181-186`), and
only then reconstructs it from the leaves' validated headers (`:199-290`). Reconstruction is
refused (`reconstruction_allowed`, `:150-154`, used at `:197-201` and `:270-273`) when the target
head is not committed here, when the author is frozen (a fork was seen) or when the author has an
observed conflict. So a canonical range answers in every case; for a *non-canonical* range (a
subtree that no acceptance step wrote) in those three cases, the cache was the only persisted
source. The gate's own comment says why it exists: "no cache is acceptance evidence … A known
fork does not invalidate existing historical math" (`:188-192`): it stops *new* tree nodes from
being generated into a store that a local verifier might read back. SO-1 replaces the cache with
derivation that is never read back by acceptance, so the gate's reason goes with it (SO-1 says
what remains refused and why).

**Why no proof caught it.** Every sync proof runs for seconds on an empty store with a fast peer.
No proof reads store bytes.

### C-21. The file is mostly empty space (fix-list item 21)

**What the person saw.** 2.3 GB of a 3.0 GB file holds no data.

**Root cause (KNOWN; the fix list's cause is corrected).** The fix list blamed a failed room that
pins an old snapshot. The accounting above shows the pin is not needed to explain any sample:
1,400 MB is leaf slack (C-76), 819 MB is free pages left by redb's growth policy (C-80), 50 MB is
branch pages. The pin is real but second-order. A poisoned room keeps its last read snapshot
until recovery (`crates/vox-core/src/node/channel/history/read_resource.rs:446-455`); while it
does, freed pages cannot be reused. RcaChurn C2 reproduced it on the instrumented v0.4.30
(`pin.py`): a 7-second poison grew a scratch file from 12.6 to 50 MB.

**Why no proof caught it.** No proof measures a store after hours. redb grows in steps, so a
minute-long run never sees one.

### C-22. An agent Session step costs 12.8 KB on disk (fix-list item 22)

**What the person saw.** 39,547 steps take 507 MB of disk.

**Root cause (KNOWN; release binary, run `w1`, `rca-StoreSize` §2a).** A stored step
(`Stored::bytes`, `crates/vox-core/src/node/channel/private_session.rs:651-666`) is the record's
wire form, its plaintext cache row, its first-seen time and its attention boundary, sealed. For a
330-B body the row is 7,924 B; fitted on the release binary, row ≈ 7,250 + 2 × body. The
operator's mean row is 10,031 B (mean body about 1,390 B; the first draft used the median).

- 6,746 B are two composite Ed25519 + ML-DSA-65 signatures of 3,373 B each
  (`COMPOSITE_SIG_LEN`, `crates/vox-core/src/hash.rs:52-54`): the sender-key signature inside the
  `GroupMessage` (`crates/vox-core/src/group/message.rs:116-124`; ADR-006 S-8), and a root-key
  signature over room and message added when Session records left the room log
  (`crates/vox-core/src/node/sessionstream.rs:35-68`). C-78 gives the reasons.
- About 2 × body is the body twice: once encrypted, once in clear in the cache row
  (`session_cache_bytes`, `crates/vox-core/src/node/channel.rs:1962-1973`), which also repeats the
  record's hash and author (64 B) that its key and header already hold. The clear copy exists
  because the live decryption path consumes the message key (ADR-006 S-10). But the keys that
  can open a retained record are kept anyway: a receiver chain persists its history key and its
  floor (`crates/vox-core/src/group/state.rs:431-443`) and reopens any record within `MAX_SKIP`
  = 1,000 iterations of that floor without touching the live ratchet (`decrypt_retained`,
  `:669-686`); the sender rotates its generation after `ROTATE_AFTER_MESSAGES` = 1,000 messages
  (`state.rs:40-45`; `pending_session.rs:1096-1104`), so every record of a generation is within
  its own window; the author keeps its own origin (`drive.rs:92-100`) and historical generations
  (`SegmentKind::OwnHistoricalKeys`). The clear copy is therefore derivable from what is kept,
  for every record this node was ever able to read, for as long as that generation's chain is
  kept. On the operator's store it is about 55 MB of the 398 MB of step data (mean body
  1,390 B). SO-4 removes it.
- A row over 4 KB takes a power-of-two page: 8 KB for most steps, 16 KB for 9,212 of them. Its
  269-B index descriptor takes a mostly empty 4 KB leaf (C-76).

Each step also writes about 24 index pages (23.7 measured in a quiet room, `w1`), and re-seals
the whole drive state, 8,971 B, beside the step
(`crates/vox-core/src/node/channel/pending_session.rs:1146-1158`). The drive state is one blob
(`state_with_receiver`, `crates/vox-core/src/node/drive.rs:285`): the sender chain, the origin
key, every receiver chain with its 1,984-B signing key, and delivery marks. A step the node
authors changes its sender chain; a step it receives changes one receiver chain. 355 MB were
written this way for 39,547 steps; 9 KB is kept. ADR-006 S-12 and ADR-010 AR-20 require the
ratchet advance to commit with the step; nothing requires the rest of the blob to.

### C-76. One small row takes a whole 4 KB page (fix-list item 76; the decider: "crazy")

**Root cause (KNOWN; reproduced with redb alone, `rca-StoreSize` `ascend`/`strand`).** Vox keeps
every row in one redb table, `segments`, keyed `(room, kind, id)`
(`crates/vox-core/src/node/store.rs:49-50`). Ids ascend within a kind. Small rows and rows of
4 KB or more share a kind (EntryIndex: 214-B ranges beside 4–16 KB pages; SessionIndex: 269-B
descriptors beside 4,647-B pages) or sit in adjacent kinds (45-B first-seen rows beside 9 KB key
material). Two rules of redb 4.3 then give each small row its own leaf:

1. For a fixed-width key the separator between two leaves is the left leaf's greatest key
   (`branch_separator`, `vendor/redb/src/tree_store/btree_base.rs:35-41`). An ascending key
   therefore goes to the right-hand leaf. When that leaf holds one value of 4 KB or more, the new
   pair cannot share its page (`leaf_split_required`, `btree_base.rs:1000-1014`: a leaf holds one
   page of pairs, or exactly one pair), and `build_split` (`btree_base.rs:901-915`) cuts
   `[new small row] | [large value]`. The next ascending key repeats it. 1,000 ascending 45-B rows
   below one 9 KB row make 1,001 leaves.
2. A leaf under a third full is merged with its sibling unless the sibling holds a single large
   value (`vendor/redb/src/tree_store/btree_mutator.rs:1580-1581`), and inserts only split
   (`:280-283`). A stranded leaf is never packed again until a delete beside it merges it.

In omp-work: 271,895 EntryIndex leaves hold 1.85 small rows each; 14,562 of 15,484 SessionIndex
leaves hold one 269-B descriptor; 3,768 of 3,769 first-seen rows sit alone in a 4 KB leaf. No
upstream issue describes this (cberner/redb issues and changelog through 5.0.0-dev searched).
What a table split does and does not do: it removes the trigger (a small row can never land
beside a large value), it does not remove the power-of-two rounding of rows over 4 KB (215 MB
on this store after every other change, measured above), and after deletes a small leaf is
packed only to redb's merge rule (a third full), not to a fixed fill.

### C-80. Index pages of 4,647 B, and growth by 4 GiB (fix-list item 80)

**Root cause (KNOWN; the first two drafts misread the codec).** An index tree page is CBOR: each
row carries its whole 64-byte key as a byte string (66 B encoded) plus its value
(`crates/vox-core/src/node/channel/entry_store.rs:22-34`, `:1009-1030`); `PAGE_ITEMS` = 128
(`:24`) is the row-count split rule and also the decoder's bound (a page with more rows is
refused, `:1048-1051`; the Session trees use the same codec, `entry_store/session_tree.rs:1-7`).
A page therefore reaches 4 KB long before 128 rows (about 55–60 rows of key and small value), so
the split rule is the wrong unit: pages split by count and land at 4.6–8 KB sealed, each in an
8 KB leaf; what the RCA read as "128 entries of 36 B" is a page of about 60 rows. redb grows a
one-region file to `max(2 × used, used + 2 × needed)`
(`vendor/redb/src/tree_store/page_store/page_manager.rs:2354-2358`); once a 4 GiB region is full
it grows by whole regions (`:2341-2353`). Growth happens inside a transaction while a page is
allocated, and the larger file is synced then (`:2211-2227`, `:2372-2379`), before any commit.
On APFS, ext4 and xfs the growth is sparse (the file's length rises, its disk use does not until
pages are written: beast's 6.44 GB file uses 4.1 GB). The growth leaves free pages that redb
reuses but never returns.

### C-77. The Session view is rebuilt from scratch at every change (fix-list item 77; the decider: "why")

**What the person saw.** Through the operator's samples: 487 Session index page writes a second
in repo-to-cve, 3.5 million in two hours for 2,049 new rows (`rca-StoreSize` §3.i). At 4–8 KB a
page that is roughly 7–14 GB written an hour.

**Root cause (KNOWN; release binary, runs `n100` and `n1500`, logs in `/tmp/rca-StoreSize/`).**
`advance_owned`
(`crates/vox-core/src/node/channel/session_projection/build.rs:521-729`) starts a new build from
phase 1 whenever the published header differs from `(public session revision, private
generation)` (`:566-568`). The private generation moves only for a lifecycle record or a body
that names a session (`private_index.rs:489`, `:567-570`); ordinary tool and output steps move the
separate activity fold (`session_projection/pending.rs:334-344` runs the two apart). Phase 1 walks
every public Session candidate (every room entry whose text names a session: all agent posts) and
puts each one's descriptor again (`put_source`, `:37-72`); phase 2 walks every private record;
phase 3 reassembles every source; phases 4–6 interpret, fold and publish; phase 7 frees the
previous generation. A change in the middle of a build sends it to phase 7 and starts over
(`:561-565`). The room changes every 2–4 seconds, so the fold never stops. One 300-B session post
cost 659–671 page writes with 100 candidates and 8,806–14,772 with 1,500 (public named-session
posts, `slow.py`); the previous rebuild had not finished when the next post landed. Each rebuild
also deletes and re-puts the descriptors, which leaves them stranded one per leaf (C-76): 152 MB
of disk for 12.4 MB of descriptors.

**Why it was built this way (KNOWN, from the commits).**

- `7bc390c74` (2026-10-14, #872, "Bound retained history and live consumers without losing saved
  work") created the storage-backed Session projection. It replaced an in-memory fold, so that
  the daemon's memory is bounded by the page shown, not by the history (ADR-034 FR-4–FR-6). It
  re-folds every input, "matching the old fold's stable source ordering" (`build.rs:49-50`).
- What the full re-fold buys, and what SO-6 must keep: the published view is a pure function of
  the *set* of inputs, evaluated in one stable order, published in one atomic header change
  (`build.rs:1-3`: "an interrupted fold is never confused with an empty set of Sessions"); no
  state is held in memory between turns; work is resumable in bounded turns; the result does not
  depend on the order inputs arrived in. One qualification the old fold never stated: its stable
  order is `(created, private flag, order, hash)` where `order` of a private record is its local
  storage id (`session_projection/record.rs:20-36`), so two events of different kinds with the
  same `created` can sort differently on two nodes; cross-node equality held up to that tie. SO-6
  defines the canonical tie. Inputs do arrive out of order: a late-synced older post lands in
  the middle of the display order, a multi-part bundle's parts arrive in any order, and a
  re-saved logical record must replace its earlier copy. The lifecycle transition itself is
  order-sensitive (`build.rs:396-433`: an opening after an end starts a new row; an end with no
  row does nothing; a later opening of an open row updates only the fields it supplies,
  `:396-408`; a bundle part before part 1 is ignored and an unexpected part deletes the bundle,
  `:164-184`), which is exactly why the full fold evaluates in position order. A logical record's
  identity is `(author, created, body)` and the newest copy by `(private, order, hash)` wins
  (`:37-61`). A name change arrives as a kind-0 event from any named-session post (`:319-337`),
  so a Session can have thousands of name events and a handful of openings and ends. Inputs can
  also change in place: a private row received before its drive key is kept opaque
  (`private_session.rs:593-596`) and, when the key arrives, is re-saved under the same id
  (`pending_upgrade.rs:1492-1496`, `:1560-1563`, `:1579-1591`); the old fold saw it through the
  private generation. An incremental fold that applied events in arrival order would diverge
  between two nodes (the first review's F2), and one that walks only ids above a cursor would
  never see an in-place change (the second review's N2).
- `172dd4741` (2026-10-18, #954) made listings answer from the last published generation while
  a new one builds (ADR-037 R4). That is why a continuous rebuild never showed as a refusal: it
  showed only as disk writes and CPU.
- `8a74a598f` (2026-11-10, #1203) already made expiry removals incremental. Additions still
  rebuild everything.

The cost is linear in the room's candidates at every change. That was invisible with the tens of
candidates the proofs use.

### C-78. Two signatures on every step (fix-list item 78)

**Root cause (KNOWN).** The inner signature is ADR-006 S-8's rule for every group message: a
private Session record reuses the room-message format on the drive channel. The outer one was
added when private records left the room log (#787, 2026-10-12; ADR-031 SA-7):
`sessionstream.rs:3-4`: "The outer signature permits verification after a one-use decryption key
has been consumed; it never grants permission." A node verifies the outer signature against the
author's root key as the room's governance knows it when it restores a stored row
(`crates/vox-core/src/node/channel/private_session/pending_upgrade.rs:1500-1503`, `restore`);
serving (`pending_upgrade/serve.rs`) authorizes and serializes stored records. No ADR requires
two signatures on a private record: ADR-006 S-8 requires the sender-key signature on a group
message, ADR-008 LS-8 a root signature on a *log entry*, which a private record is not (ADR-031
SA-7). ADR-003 H1 and H3 require every signature to be composite, so any per-step signature
costs 3,373 B. The record's identity is `sha256(record.wire())` (`sessionstream.rs:154-158`),
which includes both signatures; that identity is used by the private index, the projection's
sources, the attention boundary (`private_session.rs:736-758`) and by peers that pull records by
hash (`serve.rs:255-260`, `:284`). What each signature protects, against whom, is the table under
Q2; which one to keep is the decider's choice.

### C-79. Compaction exists and is never run (fix-list item 79)

**Root cause (KNOWN).** `Store::rewrite_fresh` (`store.rs:758-764`, body
`rewrite_fresh_locked`, `:767-914`) copies every live row into a fresh file. It runs only on room
leave (`leave_save.rs:348`) and after a native write failure. `Store::compact` (`store.rs:1514-1527`,
redb's `Database::compact`) needs the only handle to the database (`Arc::get_mut`), which a
running daemon never has while rooms are open; `compact_store` (`crates/vox-core/src/node/profile.rs:427`)
has no caller. Measured on the clone: `compact()` returns the free pages (3.01 → 2.20 GB in
10.4 s, `rca-StoreSize` §3.ii.3) and, after the proof rows are deleted, 3.01 → 1.64 GB in 1.9 s
(this revision); it needs no second file. ADR-010 has no compaction rule.

### C-23. A full disk: the error latches, recovery copies the store every 64 s, copies stay forever (fix-list item 23)

**Root cause (KNOWN; RcaPreparing P3, reproduced on the shipped 0.4.30 on a 64 MB disk image,
`/tmp/rca-RcaPreparing/enospc.py`; and on redb 4.3.0 alone, above).**

- redb latches the first OS write failure: every later write transaction fails with
  `PreviousIo` until the database is closed and reopened
  (`vendor/redb/src/tree_store/page_store/cached_file.rs:128, 198-205`). Vox's vendored hunk
  (`Cargo.toml:230-235`) only keeps reads working through the latch. The write that fails need
  not be a commit: redb grows the file during allocation and writes dirty pages while a
  transaction is still being built once its write buffer passes half its cache
  (`cached_file.rs:899-930`, failures latched at `:823-830`).
- Vox's only way out is `resave_room_after_write_failure` (`store.rs:658-679`), which calls
  `rewrite_fresh_locked(retain_original = true)`: copy every live row of every room into
  `store.redb.rewrite`, hard-link the old file as `store.redb.failed-N` (`store.rs:846-873`), and
  rename. On a full disk the copy fails; the retry waits `1 << min(attempts, 6)` seconds
  (`crates/vox-core/src/node/actor/recovery.rs:158`), so every 64 s it writes up to the whole
  store again before failing.
- `.failed-N` is removed only when the install itself fails (`store.rs:880-899`). After a
  successful recovery the full old copy stays on the disk that just ran out.
- Why it was built this way: the old file stays readable for read transactions already open
  ("Old read transactions keep their original MVCC owner", `store.rs:656`), and redb's file lock
  refuses a second open while any handle lives. Every transaction holds a clone of the
  `Arc<Database>` (`store.rs:226-266`), so "no handle lives" is exactly "the store's own `Arc`
  is the last one", the condition `Store::compact` already needs. ADR-038 FX-33 records why
  closing and reopening was abandoned: on 2026-10-21 a recovery closed robert-work's store to
  reopen it, redb refused the reopen while another handle was alive, and every room answered
  "the store is read-only" for hours, because the recovery had no path out of a refused reopen.
  The decision then was: "the recovery re-saves the room's sealed state in an ordinary write
  transaction on the store as it is open, never by closing and reopening the node's store file".
  That re-save cannot run on a latched store (the latch refuses every write), which is why
  v0.4.30 falls back to the copy. The experiment above shows that reopening the same file
  repairs the latch when the handle is the last one; it shows nothing about a refused reopen,
  which SO-12 gives its own state and retry. Q4 puts the choice to the decider with both facts.

**Why no proof caught it.** The full-disk journey exists but is optional
(`a_full_room_recovers_and_keeps_its_session_entries`,
`crates/vox-tui/tests/a_claude_session_is_mirrored_and_answered_from_either_side_proof.rs:2174-2190`,
"needs userspace macOS disk images"; it makes a 64 MB HFS+ image, `:2203-2214`). It asserts
recovery and held entries, not copies made or files left behind.

### C-24. The joiner is told its passphrase is wrong when the member's disk is full (fix-list item 24)

**Root cause (KNOWN; RcaPreparing P3).** `run_responder`'s error arm
(`crates/vox-core/src/node/joinstream.rs:1448-1455`, "Coarse by design") maps every error except
proof-of-work, malformed and ended to `JoinReject::Refused`; the joiner's first-frame dispatch
(`:998-1009`) sets apart only `Busy`, `RoomEnded` and `ResponderLeft` before it expects a
challenge, and `rejected()` (`:712-718`) sends every other reason to `Error::JoinRefused`, which
the CLI prints as the passphrase hint (`crates/vox-tui/src/tunnel_cli.rs:955-956`). The admission
arm already says `NotAdmitted` after the passphrase was accepted (`joinstream.rs:1403-1412`), but a
storage failure earlier in the exchange falls through to `Refused`. Why coarse: ADR-005 J-17, a
stranger must not learn whether a passphrase was right (`joinstream.rs:42-55`). The arm was
written before a member's own storage failure was considered.

### C-25. Nothing shows or bounds disk use (fix-list item 25)

**Root cause (KNOWN).** Never built. ADR-010 has retention by time (AR-27–AR-31), ADR-031 SA-9 a
7-day step retention; `vox status --json` reports retention per room
(`crates/vox-core/src/node/api.rs:703-710`) and no bytes. The only free-space check in the
product guards pulled files (`crates/vox-core/src/node/pulls.rs:12-14, 55, 64`: "A pull never
fills the disk", a 1 GB reserve).

### Corrections to the plan's evidence

Checked against `git show v0.4.30:<path>`. Corrected here (the first draft's list, plus the
review's citation audit):

- `compact_store` is at `profile.rs:427`, not `:429`. redb's growth policy is
  `page_manager.rs:2341-2358`. `PAGE_ITEMS` is in `entry_store.rs:24` and is also the decoder's
  bound (`:1048-1051`). The full-disk journey is at `…_proof.rs:2174-2190`, its image at
  `:2203-2214`. `.failed-N` cleanup on a failed install is `store.rs:880-899`. "A pull never
  fills the disk" is `pulls.rs:12`, the reserve `:55`, `free_space` `:64`. The retry exponent is
  `recovery.rs:158` (`:157` clears the busy flag).
- `build.rs:164-184` is not an out-of-order bundle repair: it starts, looks up and invalidates a
  bundle; order comes from the full walk (SO-6 supplies a real one).
- `pending_upgrade.rs:854` is not the serving check; `restore` verifies a stored row at
  `pending_upgrade.rs:1500-1503`, and serving is `pending_upgrade/serve.rs`.
- `proof_range.rs:150-154` gates new reconstruction only; the canonical range is tried first.
- `group/state.rs:439` persists the signing public key and `:442-443` a history key with its
  floor: a receiver can reopen a retained ciphertext within `MAX_SKIP` (1,000) iterations of
  that floor (`:669-686`); the sender rotates after 1,000 messages (`:40-45`,
  `pending_session.rs:1096-1104`), so the window covers every record of a generation. The first
  two drafts' "this node cannot decrypt it again" was wrong; C-22 and SO-4 are rewritten on it.
- `entry_store.rs` pages carry 66 encoded bytes of key per row; "128 entries of 36 B" was a
  misreading (C-80).
- The 2.6 µs read figure of revision 2 is a raw redb lookup after a full table scan, not a cold
  header read; SO-1's cost is E-1's measured figure (revision 6).
- ADR-038 has no "#1053 paragraph"; FX-32 is the restore rule. ADR-038 FX-22 governs the
  governance projection, not the Session projection.
- The plan's size projections used the median step; this revision uses the measured
  distribution (Appendix B).

## Terms

- **Store**: one node's redb file, `<data root>/nodes/<node>/store.redb`.
- **File length**: the store's length as `ls -l` shows it. **Disk use**: the blocks it occupies
  (`du`); redb grows a file without writing the new part, so on APFS, ext4 and xfs the length
  exceeds the disk use.
- **In use**: the pages the store's current state reaches (redb's "allocated"). The rest of the
  file is free pages.
- **Data**: the bytes of the rows themselves, keys and values, as redb stores them (sealed).
- **Page**: redb's 4,096-B unit. A leaf that holds one value over about 4 KB takes the next power
  of two: 8, 16, 32 KB and so on.
- **Packed bytes**: what the data would occupy in a freshly rewritten store: each value over
  2,048 B at its power-of-two page, smaller values at 93% fill, plus 3% for branches. Measured
  within 2% of two rewrites of the clone (998 MB predicted, 976 measured; 852 predicted, 835
  measured).
- **Leaf slack**: unused bytes inside in-use leaf pages. **Free pages**: pages no current state
  reaches; redb reuses them; only a compaction or a rewrite gives them back to the disk.
- **Proof record**: an `ObjectKind::ProofRange` row: one verified Merkle tree range, kept per head.
- **Verifier cursor**: an `ObjectKind::Verifier` row: the progress of one proof verification.
- **Descriptor** (of a tree range): `(leaves, controls, frontier, hash)`
  (`crates/vox-core/src/log/history.rs:356-366`): a function of the leaves' headers and the
  control contexts they name (`leaf_descriptor`, `:764`; `join_descriptors`, `:825`), and of
  nothing else. A head only says which leaves.
- **Accepted head**: a signed head of an author this node has verified, with the consistency
  proof from its previous one (ADR-046 SY-13 rule 3; "committed here" in v0.4.30's terms). All
  accepted heads of one author in one room lie on one chain: a conflicting head is recorded as
  fork evidence and acceptance for that author stops (`sparse.rs:2676`, `:2582`; ADR-044 RD-9).
  **Newest accepted head**: the one of greatest size.
- **Held interval**: positions of an author's feed whose entries this node holds, with the
  canonical subtree descriptors the interval fills and the sibling descriptors on the path to
  the newest accepted head (ADR-046 SY-18, r2: about 2·log₂ n descriptors of 71 B per interval,
  replaced on head advance from the consistency proof; the same under R1).
- **Fetch**: one attempt to bring an author's entries up to a head. ADR-046 owns it.
- **Session step**: one private Session record of an agent (ADR-031 SA-7), sealed to drive
  holders. **Lifecycle record**: a private opening or end (ADR-031: not a step; it ages by message
  retention, `private_session.rs:484-500`).
- **Session projection**: the sealed index behind `vox room session`, Session listings and file
  pages. **Candidate**: a room entry whose text names a session.
- **Composite signature**: Ed25519 ‖ ML-DSA-65, 3,373 B (ADR-003 H3).
- **Sender key**: an author's per-generation chain on a channel (ADR-006): a chain key and a
  signing key pair; receivers hold the chain key and the signing public key (1,984 B).
- **Rewrite**: copy every live row into a fresh file and swap it in (`Store::rewrite_fresh`).
  **Compaction**: redb's `compact()` on the same file; returns free pages; needs the only handle.
- **Floor**: 64 MB of free disk (plus Vox's own ballast, below) under which Vox admits no
  ordinary write (SO-11). **Reclamation batch**: a bounded delete-only batch (SO-11 lists them).
  **Ballast**: a fully written 32 MB file `store.ballast` beside the store, Vox's own reserve: it
  is released to make room for reclamation and recovery when the disk is otherwise full, and
  restored when space returns (the ballast-file pattern of CockroachDB/Pebble).
- **Latch**: redb's refusal of every write after one OS write failure, until the database is
  reopened. **Drained**: the store's own `Arc<Database>` is the last one (every transaction holds
  a clone, `store.rs:226-266`), so the daemon may drop and reopen the file.
- **Cannot save**: ADR-034 SR-2's room state: the room reads, refuses writes, says why, and
  recovers by itself. **`StoreRecovered(room)`**: the event the store raises when a room passes
  from "cannot save" to "can save", whatever the cause (SO-11); ADR-040's prerequisite
  `StoreRecovery(room)` is released by it, ADR-046 SY-24 retries failed cleanups on it, and
  after it the next ruled save runs its own `Immediate` commit (ADR-044 RD-7 r14).
- **Position** (of a Session event): `(created, class, hash)`, class public before private, hash
  the record's identity; no local id (SO-6).

## Requirements

Ordered by the decider's rule. Acceptance numbers are `C<fix-list item>-<n>`. *(changed)* marks a
requirement whose design changed in this revision; its id is kept.

### 1. Do not store what we should not

- **SO-1. No node writes a proof record, not when it verifies a proof and not when it serves one;
  every proof a node serves is derived, when asked, from the validated headers, the contexts they
  name, the newest accepted head and the held intervals' descriptors it already holds; a head
  that nothing reaches is pruned.** *(changed r3: N1, N13)*
  - *Why:* item 20. 1,130 MB of 3,012 MB, growing 320 MB an hour. The decider: "no need to keep
    anything like this". Review F1: a holder that had seen a fork, or that restarted, could not
    serve a non-canonical range. Review N1: revision 2 pruned heads that the header reader still
    followed (`history_validated_header`, `sparse.rs:1334-1356`, resolves a held position through
    the `source_heads` tie to the *original* head object it was admitted under), so a pruned head
    broke derivation without any fork. This revision changes the reader, then prunes.
  - *What makes derivation possible (the stored structure, one list for R1 and R2, agreed with
    ADR-044 r3 RD-9 and ADR-046 r2 SY-18):* for each held entry, its validated header (written
    only by a verified admission: the position index) and the context its header names
    (content-addressed, one copy); per author, the **newest accepted head** and fork evidence
    (both witnesses) when there is a fork; per held interval, its descriptors (Terms). No
    inclusion, parent or prefix receipt by any node for any feed, under either representation
    (ADR-046 r2's row-5 answer; ADR-044 r3 accepted it: the position index and the head tie are
    the acceptance evidence a receipt duplicated). Nothing per fetch, per peer or per head: a
    descriptor is head-independent.
  - *The head tie, and pruning by reachability:* a held position `p` of author `A` is covered by
    every accepted head of `A` whose size is at least `p`, because all accepted heads lie on one
    chain (Terms). The reader therefore binds a validated header to the newest accepted head of
    size ≥ `p`, never to the head it happened to be admitted under; the `source_heads` tree and
    the per-entry head tie are deleted. Heads kept: the newest accepted head per author; both
    witnesses of a fork. Every other head object is unreachable and is deleted in the commit that accepts the
    newer head (one delete per head advance; nothing is rebound per entry). Crash window: a kill
    between accepting H2 and deleting H1 leaves H1 reachable from nothing; the room's next sync
    write deletes it. Under R2 the interval descriptors are replaced in the same commit from the
    consistency proof (SY-18). A sparse holder (an interval, not the whole prefix) keeps the
    sibling descriptors that connect its interval to the newest accepted head and so can prove
    its held leaves under that head; it cannot prove consistency from an offline member's old
    size that its descriptors do not bound and answers `EvidenceUnavailable` for that; a whole
    prefix holder can.
  - *The other readers of a head:* under ADR-046 R2 (the decider's choice) the local effect
    settlement and the control-receipt inheritance that dereferenced older heads are deleted
    with their machinery (SY-19) and `control_through` is kept per author; nothing here
    rebinds them. (The R1 cutover of revisions 3–11 is in the review record, R3-2.)
  - *The serving rule (one contract with ADR-044 RD-9 and ADR-046 SY-16):* a holder answers a
    range, inclusion or consistency proof under head H for positions it holds when H is a head it
    has accepted (the head it names in its `Have`); it computes each needed subtree from the
    leaves' headers (one header read, one context read, one hash per leaf; one join per internal
    node, each join merging the two children's control frontiers) and uses a kept interval
    descriptor for a subtree it does not hold whole; a subtree it neither holds nor has a
    descriptor for, or a head it has not accepted, is answered `EvidenceUnavailable` (ADR-046
    SY-21: "not held here; ask another holder"), never Busy for lack of evidence (the one `Busy`
    a read gives is a derivation too large for one exchange, "Cost" below) and never a wait for
    the author. The
    fork state of the author does not enter the rule (ADR-044 r3 RD-9 states the reason: nothing
    derived is written back, and branch mixing is impossible on one chain); a frozen author's
    held branch is served under the heads this node accepted and the fork as its two signed
    heads. The per-leaf composite signature re-check of v0.4.30 (`proof_range.rs:264-268`) is
    dropped for serving (RD-9 r3: the header was verified before it was indexed, the sealed
    segment detects a change, the peer verifies the served proof against the signed head). The
    contexts a derivation generates go into RD-9's **proof handoff** (per peer and room, in the
    serving book, bounded to the last four proofs' contexts), because the peer asks `Context` on
    a later stream; a context in neither disk, handoff nor cache is `EvidenceUnavailable` and
    the peer re-asks the proof.
  - *Cost (stated per miss, not per process life; ADR-044 r3 RD-9 withdrew "once per process
    life"):* an indexed or cached lookup is O(1) reads per range; a miss on a k-leaf range is
    O(k) header reads and O(k) joins, where a join merges two control frontiers of up to 2,048
    coordinates each (`log/history.rs:200-208`, `:297-345`), so the work is O(k × frontier
    width), repeated whenever the bounded cache has evicted the subtree or two peers miss at
    once; a 100-author room has frontiers of about 100 coordinates. **Measured (E-1,
    `store-experiments`, receipt `store-exp-receipts/timed-run.log`; the product's own
    `leaf_descriptor`/`join_descriptors`/DFS over sealed headers at tag v0.4.30, a fresh process
    per run, the OS page cache warm):** a cold derivation of the operator-shaped feed (4,221
    leaves, 8 authors) costs **0.107 s** whole (25.5 µs per leaf) without the per-leaf signature
    re-check and 0.417 s with it (the re-check is 70 µs per leaf, 73% of the small-room cost,
    which is why it is dropped); the operator-shaped range of SO-1's arm 1 (positions 3–6)
    0.13 ms; a 1,024-leaf range 26 ms. A synthetic 100,000-leaf feed with a 200-author frontier
    costs **163 µs per leaf**: 1,024 leaves 0.17 s, 8,192 leaves 1.34 s, the whole feed in one
    miss **16.3 s** (23.2 s with the re-check). Cold and warm differ by under 6%. Inferred from
    those figures: about 0.37 µs per frontier coordinate visited, so a 2,048-coordinate frontier
    (the protocol maximum) is about 1.5 ms per leaf; a slice under `WorkBudget::default()` is
    about 5 ms. Not in the figures: the product's directory lookup per header (tens of µs,
    inferred) and a truly cold disk. Derivations run on RD-8's lease off the actor in bounded
    slices (`WorkBudget`, `proof_range.rs:115`), so their cost is latency for the asking peer,
    never a stall of the daemon (ADR-044 RD-1). The contract, in one unit (R5, E-1's own
    definition): a miss's work is k × w coordinate visits, k the leaves, w the author frontier's
    width; a holder answers within ADR-046's 20 s request deadline unconditionally for a miss of
    at most 2 × 10⁶ visits (about 1.3 s at the measured 0.37 µs per visit after the per-leaf
    constant; that is 10,000 leaves at width 200, 250,000 at width 8, and every range of the
    operator's rooms), and for a larger miss (a whole 100,000-leaf, 200-author feed asked in one
    range, or a `Head` bridge whose decomposition needs such a subtree) it answers
    **`Busy{retry_after}`** (R5-1: a temporary, retryable answer, not negative availability;
    ADR-046 r5 SY-21 already dispatches it so: no short mark, the next covering holder is tried
    meanwhile, the same holder is asked again at the retry time), with `retry_after` the
    holder's own estimate of the fill from the measured per-visit cost clamped into
    **ADR-046's wire interval, `max(50 ms, min(estimate, 5 s))`** *(changed r9: R6-3; revision
    7's 20 s cap exceeded the interval SY-21 states, 50 ms to 5 s; changed r10: R7-2, the lower
    bound on every path)*, and starts the derivation in the background within the slice budget
    into RD-9's cache. A retry that arrives while the job still runs is answered `Busy` again
    with the remaining estimate clamped the same way (an overdue job, or one with 20 ms left,
    still answers 50 ms; a cold 100,000-leaf, 200-author fill of 16–23 s is three or four
    `Busy` answers, then the result); a fifth concurrent request gets `Busy` clamped the same
    way. One clamp, on every `Busy` this ADR emits; the wire is unchanged. The fill is deduplicated by the
    subtree's full identity (room, history instance, binding, start, leaves), is owned by its
    job until it completes (not evictable in progress; at most four jobs per node), and the
    completed result is pinned in the cache for its continuation until the requester's retry
    consumes it or 60 s after completion, whichever is first (then it is an ordinary cache
    entry): the pin outlasts the longest run of 5 s retries, so the retry's success is a
    guarantee the holder owns, not a hope, and it needs no change of `Have`, connection or
    bridge on the requester's side. This is the one temporary answer a read gives
    (the serving rule's "never Busy" is amended to "never Busy for lack of evidence"); true
    unavailable evidence stays `EvidenceUnavailable`, a negative. No unproved position is ever
    served (`More` cannot carry a prefix the proof does not cover, and a `Head` consistency proof
    has no `More` at all). The author of such a feed never fills (its tree is canonical), so the
    cadence is met by asking the author first for feeds above 10,000 positions (SY-21). Revision
    5's second fallback (kept descriptors of every completed subtree) is not justified by the
    figures and is deleted. Proof arm (SO-1, arm 4): a holder with a cold cache and a
    100,000-leaf feed at width 200 — one author's feed of 100,000 entries in a room of 200
    authors whose entries are interleaved so the frontier has width 200, E-1's measured shape,
    never 200 small feeds: a node data root the apparatus produces with the product
    (`test-knobs` `VOX_TEST_SEED_FEED=<feed leaves>:<authors>`, which admits the entries
    through the ordinary admission path at start and logs `test knob: seeded one feed of 100000
    entries at width 200`; r11: the eighth review's D12 note) —
    serves a `Head` bridge to a newcomer with the author stopped and no `Have` or connection
    change (v0.4.30: CANNOT MEASURE, `Head` exists only on R2's wire; *changed r10: D12*): the
    newcomer's read
    completes within 60 s, the newcomer received at least two `Busy` answers (the apparatus
    precondition of a cold fill longer than one interval; fewer is APPARATUS), and every
    `Busy` carried a retry time between 50 ms and 5 s (its log), including
    one asked by a second apparatus requester while the job has under 50 ms of estimate left
    (a `test-knobs` hold at the job's last leaf stages it); mutant: answer
    `EvidenceUnavailable` instead of `Busy`; the newcomer never completes, PRODUCT; mutant:
    send the raw 16 s estimate; a `Busy` over the wire bound appears in the newcomer's log,
    PRODUCT; mutant: send the unclamped remainder; a `Busy` under 50 ms appears, PRODUCT (the
    verdict is the out-of-interval refusal, not the derivation's timing; ADR-046 states the
    interval and no clamp; a holder that breaks it is the defect).
  - *Own-history recovery:* as ADR-044 RD-9's contract: a restored node reconstructs its whole
    recovered prefix once from its own validated headers (the recovery fetched every own entry,
    ADR-037 R5), compares the result with the signed root (`own_history.rs:1575-1579` already
    errors on a mismatch), and promotes the forest into canonical ranges in one commit
    (`pending_recovery.rs:769-784`). It needs no record and no receipt: the signed root is the
    authentication. Crash windows: a kill before the promotion commit leaves nothing and the next
    start recomputes from the same headers; a kill after it finds canonical ranges. It does not
    use the serving path (`restore`); it is its own reconstruction over own headers.
  - *Bounded state that persists:* the list above. Existing proof rows, receipts and the
    `source_heads` tree are not read by any path before SO-2 deletes them.
  - *What changes:* the range loop of `keep_generated` (`admission.rs:453-464`) goes; contexts
    stay. `ProofRangeRestore::restore` (`proof_range.rs:144-311`) becomes a read over ADR-044
    RD-8's lease: the cache lookup (`:181-186`), the `reconstruction_allowed` gate (`:150-154`,
    `:197-201`, `:270-273`), the receipt check (`:245-262`), the per-leaf signature re-check
    (`:264-268`) and the write (`:298-301`) go. `history_validated_header` returns the newest
    accepted head of size ≥ `seq` instead of following `source_heads`; `history_head_committed`
    answers for the heads kept. `AppendForest::range` (`own_history.rs:402-404`) and
    `recovered_prefix` reconstruct from own headers. No wire change. Store format: object kind 9
    no longer exists; the `source_heads` tree and receipt kinds 5, 6, 7 no longer exist.
  - *Deleted:* `ObjectKind::ProofRange`, `keep_history_proof_range`, `history_proof_range`,
    `decode_proof_range`, `proof_range_key` (`sparse.rs:218-219, 227, 283-318, 1495-1511,
    2506-2540`); the `source_heads` tree and its writer; `ObjectKind::{ParentReceipt,
    InclusionReceipt, PrefixReceipt}` and their writers and readers; `PendingProofRange` (ADR-044
    RD-8).
  - *Depends on:* ADR-044 RD-8, RD-9 (the lease, the cache, the handoff, the contract); ADR-046
    SY-18 (the interval descriptors) under R2, the decider's choice (ledger rows 57, 62;
    *changed r10: D6; r13: the R1 sentences are gone*).
  - *Proof:* extend `a_newcomer_reads_the_whole_history_proof.rs` (ADR-046's B2 **slow-member
    act**, `ADR-046:638-643`, the one SY-8 shares with ADR-044 RD-9's second arm; not its B2
    trial shape). Arm 1 (cold holders, two heads): the author posts, a member holding the whole
    feed accepts head H1, the author posts again, the member accepts H2 and restarts; the
    requester is a **test-side member speaking R2's wire** (the apparatus client ADR-042's
    V431-042-08 builds; the product newcomer starts from the creator's latest fence post,
    SY-27, and
    asks ranges of its own choosing, so nothing in the product produces this request on
    demand), which asks that member (the author is stopped) for positions 3–6 of the 7-entry
    feed, a range that is not a perfect subtree of the author's appends, and verifies the
    answer under H2; then a product newcomer joins and reads the whole history within the
    proof's bound *(changed r10: D11)*; `vox status --json` on both shows `rooms[].store.sync_bytes`
    = 0 once no fetch runs (SO-15) and the newcomer's `store.data_bytes` at most 24 KB × entries
    + 2 MB. Arm 2 (fork, author gone, everyone restarted): the apparatus author (the test's own
    node, as `an_equivocation_is_detected_and_said_proof.rs` forges) equivocates after H2; two
    honest holders see the fork and both restart; the author is stopped; a newcomer joins and
    reads the pre-fork history from the holders and sees the fork said as today. Arm 3 (own
    recovery, interrupted): `a_member_that_restarts_finds_its_room_proof.rs`'s restore step
    (ADR-038 FX-32) on a 5-entry own prefix (the forest is 4 + 1, so no canonical subtree index
    exists for the frontier); a `test-knobs` hold stops the restored daemon after its own headers
    are durable and before the promotion commit, and it is killed there; after restart it
    recovers its own entries and posts again. A hold or kill that lands outside that window is
    APPARATUS. v0.4.30 is red on arm 1's `sync_bytes` (the field does not exist; the rows it
    would count are at least 14 × 214 B per entry, RcaChurn `runs/direct2`) and on arm 2 (the
    cold holders refuse reconstruction for the frozen author and the newcomer's read never
    completes: KNOWN by code `proof_range.rs:150-154`, to be confirmed at the proof's first run on
    the release asset). Mutants: restore `keep_history_proof_range` in `admission.rs`:
    `sync_bytes` > 0, PRODUCT; delete H1 and keep the old `source_heads` reader: arm 1's range
    read goes red, PRODUCT; refuse derivation for a frozen author: arm 2's read goes red, PRODUCT;
    skip the promotion commit: arm 3 never posts again, PRODUCT. Acceptance C20-1.

- **SO-2. The first v0.4.31 start on an existing store converts it in a fixed order, each step
  resumable, bounded in disk, and reversible until the result is verified; a start on a disk that
  cannot hold the conversion says exactly what it needs and opens the rooms readable.** *(changed
  r4: R3-1; the decider's answer to Q6)*
  - *Why:* item 20 (three stores hold over 500,000 proof records), item 59 (`.failed-1`), items
    76 and 80 (the table split and page size take effect only through a rewrite). Review F4, F7,
    F8, N3 and R3-1 (revision 3 ran the ledger seed and the projection rebuild, ordinary writes,
    before compaction, so a start with 20 MB free and no ballast could never reach the step that
    returns space), N10. The decider (2026-11-13): existing stores convert in place; no fresh
    profile; nothing a person wrote is deleted: the sweep removes derived sync objects only; the
    lifecycle exception (Appendix A) keeps every PrivateSession row.
  - *The order (one executable order, each stage idempotent and resumed from its durable
    cursor; reclamation and compaction before anything that writes new pages):*
    1. Open the live `store.redb` and read `meta.schema_version`. If redb reports corruption the
       start stops here, keeps every file, and says so (SO-9); nothing below runs. redb's own
       open may repair and commit (`db.rs:1641-1668`); if that fails for want of space the start
       reports it as step 7 does.
    2. Delete `store.redb.rewrite` (a candidate never renamed; the live file is authoritative) and
       every `store.redb.failed-*` (hard links to superseded inodes) in the node directory, each
       logged with its name and size, and shown once in status (`removed store.redb.failed-1
       (385 MB of disk)`). Only after step 1 succeeded. Then, if the disk holds floor + 32 MB
       free, write the ballast (SO-11); if not, continue without one.
    3. Unlock as today (the SEK is needed for every stage below).
    4. Per room, the sync-record sweep, a reclamation stage (SO-11: admitted while free + ballast
       ≥ 3 MB, the ballast released if needed), 256 keys per commit, cursor in the room's
       directory: every kind-9 object; every receipt object (kinds 5, 6, 7); the `source_heads`
       tree; every head object other than the newest accepted per author and fork witnesses;
       every verifier cursor; the live window (`LiveWindow` in `AuthorState`); the obligation
       rows, the flow cursors, the parent and prefix receipts and `prior_heads` (Appendix A's
       R2 rows; ADR-046 SY-19's deleted machinery leaves no reader of them); *(changed r10: D5,
       D6: the R1 branch — obligation re-keying, the eager progress copy, "a running fetch's
       target" — is gone; R2 is the decider's choice, ledger rows 57 and 62)*. **Order within
       the room (ADR-046 SY-26, X046-25): SY-26's initialization — anchors from the persisted
       `LiveWindow` start and the held headers, `control_through`, the recorded cuts — runs
       first, and the sweep's first batch runs only after its completion marker is durable**,
       because SY-26 reads the `LiveWindow` and DAG rows the sweep deletes. *(changed r11:
       R8-2: bounded, not one commit.)* The initialization is a **migration batch** stage of
       SO-11's reclamation class in size (at most 256 keys and under 2 MB of updates per
       transaction) and admission (free + ballast ≥ 3 MB, the ballast released if needed), the
       one class of insert that spends the ballast, because nothing that returns space can run
       before it: the anchors and `control_through` of up to 256 authors per batch, then the
       recorded cuts 256 per batch (a room's historical removals are not bounded by its member
       count; 30,000 cuts of 72 B are over 2 MB and take 118 batches), each batch idempotent
       (an anchor or cut re-derived after a kill has the same value and key), with a cursor
       `meta.sy26_cursor(room)` and the completion marker `meta.anchors_initialized(room)`
       written in the same transaction as the last batch. Until the marker is durable no
       `LiveWindow` or DAG row is deleted (the sweep does not start) and the room's sparse
       state is not read as migrated: `!meta.anchors_initialized(room)` is the one predicate
       of an unfinished migration (ADR-046 r11; an anchor without the marker is partial state,
       repeated from the cursor at the next open). A kill in any batch resumes from the cursor; a kill
       between the marker and the sweep's first batch finds the rows present and the sweep
       starts. The prerequisite status names is honest: on a disk with no ballast and under
       3 MB free, step 7's words name the larger of 3 MB and the initialization's remaining
       estimate (`the upgrade needs <n> MB to continue`), since the sweep cannot return space
       before it; with the ballast present the whole initialization of the operator's rooms
       (at most a few MB) runs inside it. ADR-046 SY-26's "in one commit per room" is to read
       "in bounded migration batches with a completion marker, ADR-047 SO-2 step 4" (Sibling
       ADRs). Proof *(changed r12: R9-3: the dependency is staged after the kill cursor)*:
       SO-2's upgrade journey adds a short-disk root written by the release asset (the image
       at 20 MB free, no ballast) with **300 authors** (so the anchor phase takes two batches)
       and 300 removals (so the cut phase takes two): one named author `W`, sorted into the
       second anchor batch, has a persisted `LiveWindow` start at position 10, **no locally
       held header below 1,873 whose body is missing and unexpired** (SY-26's source (b); the
       apparatus asserts both conditions on the v0.4.30 root before the start, else
       APPARATUS), and a committed size of 2,000, so that the window is the only source below
       the fallback 1,873 (size − 127); entry 10 exists at the serving peer, which can serve
       it once `W`'s anchor says 10 (*changed r13: R10-1*); the kill lands after anchor batch 1 (log:
       `migrating sync state: anchors, batch 1 of 2`), while `W`'s anchor is absent; on
       resume the start continues at batch 2, then the cuts (`cuts, batch 2 of 2`), the sweep
       starts only after `anchors initialized`, and `W`'s row at 10 renders within 30 s.
       Mutant: delete `LiveWindow` rows in anchor batch 1 → after the resume `W`'s anchor is
       1,873 and its row at 10 never renders, PRODUCT. Mutant: start the sweep before the
       marker → a removal whose cut is in cut batch 2 loses the DAG rows it needs; its target's
       pre-removal post is hidden or its later post shown (SY-26's cut assertions), PRODUCT.
       The 300-cut case stays for cursor and marker coverage, not as proof that anchors are
       still uninitialized. Status, in
       ADR-042's words: `preparing: removing
       sync records, 182,000 left`. **The sweep deletes page-wise, not key by key** (E-2,
       `store-experiments`, `timed-run.log`): deleting the 502,412 rows in 256-key commits costs
       10.1 s on redb alone (5.16 ms per commit, measured on the clone) but **108.7 s** when each
       delete rewrites a 4-page sealed root-to-leaf path of the room's object tree as
       `change_value` → `replace` does (`entry_store.rs:1654-1744`; measured on an emulation of
       that path, 2,009,648 page rewrites), so revision 2's "20–30 s" was wrong. The sweep
       therefore walks each sealed directory page of the room's object tree once, rebuilds it
       without the swept keys (one unseal, one seal, one put per page; repo-to-cve has 24,921
       pages), commits every 64 pages with the page cursor, and deletes the swept records in
       bulk, 256 per commit: bound, per room, one rewrite per directory page plus one delete per
       swept record; for the operator's store about 1–2 s of page rebuilds (inferred from the
       5 ms-per-commit figure) plus the measured 10 s of record deletes; a 6.4 GB store with an
       inferred million proof rows about 25 s. A kill between a page's rebuild and its records'
       deletion leaves records no page names, which the next batch deletes by the key range the
       cursor records.
    5. The backstop (SO-10) runs once, before any room publishes, because the daemon holds the
       store's only handle: if the disk holds the rewrite's reservation (1.1 × packed bytes + the
       floor), a rewrite into the schema-2 file (`preparing: rewriting the store (3.01 GB file,
       0.61 GB of data)`); otherwise, if free + ballast holds the compaction reserve (16 MB),
       redb's `compact()` in place (`preparing: compacting the store`), which returns the swept
       pages to the disk and so makes the next steps' space; status says what the rewrite would
       need (`rewrite due: needs 0.95 GB free; the disk holding … has 0.40 GB`). Measured on the
       clone: rewrite 5.5–8.3 s with a 256 MB cache (21 s with the product's default cache),
       leaving a 1.08 GB file length and 0.84 GB of disk; `compact()` after the sweep **1.6 s**
       (2.6 s on the tree-churned clone), file length 3.01 → 1.64 GB, **allocated blocks never
       above the start (+0)** while the file length rose transiently by 260 MB (9% of the file;
       redb relocates pages before it shrinks, reusing free pages, not new blocks); and on a
       64 MB APFS image with 3.1 MB free after a real latch, `compact()` succeeded in 0.17 s
       (E-2, `timed-run.log`, `e7-enospc-and-refused-reopen.log`). The 16 MB reserve and the
       32 MB ballast therefore hold **on a filesystem with sparse files, in blocks**: APFS
       measured; ext4, xfs and tmpfs support sparse files and charge blocks (inferred, owed to
       ADR-045 J5 on the Linux VM); on a filesystem or quota that charges file length (HFS+, an
       apparent-size quota) the transient is 9% of the file and compaction under the floor is
       not attempted: status names the space it would need, as the no-space case says. The
       repair that redb's open runs after a latch grew nothing visible at 4 KB granularity on
       the E-7 stores (8–60 ms); its peak on a multi-GB latched store was not measured and is
       covered by the same sparse-file condition (inferred).
    6. Per room, the stages that write new pages, each an ordinary write admitted under SO-11's
       floor, each resumable: (a) the byte ledger's seed walk (SO-15; one ledger row per batch;
       0.8 s for 680k rows on the clone); (b) the Session projection: an old header has no fold
       state, so SO-6's fold starts from one full rebuild, in 32-row turns, the same work as one
       of today's rebuilds. Nothing else: v2 private records stay as they are (SO-4) and index
       pages encoded at 128 rows stay readable (SO-5). If the floor is not met after step 5, these
       stages wait (step 7) and the room publishes without them.
    7. The ballast is written if it is absent and the disk now holds floor + 32 MB. Rooms publish:
       readable always; writable when SO-11 admits. **The readable exit:** if after step 5 the
       disk is still below the floor, every room publishes as `cannot save: the disk holding
       <dir> has 41 MB free; Vox keeps 64 MB free` (SR-2's words) with its entries readable and
       its Session listing `preparing` until step 6 runs; step 6 is retried on
       `StoreRecovered(room)` (SO-11) and completes by itself when space returns. If step 4 or 5
       itself cannot be admitted (free + ballast below 3 MB for a sweep batch, below the
       compaction reserve for step 5, after step 2 freed what it could), the rooms publish the
       same way with `the upgrade needs <n> MB to continue` naming the larger of the two
       figures, and the stage is retried every 5 s. That is the one external prerequisite, named
       exactly, and it exists only on a first start that found no ballast and nothing to delete.
       Freeing that much lets the start reach compaction, which returns the rest.
  - *Every mandatory stage, with what admits it:* step 4 reclamation (3 MB); step 5 compaction
    (the reserve) or rewrite (its reservation); step 6 ordinary (the floor); nothing else writes.
  - *Crash windows:* a kill in step 2 leaves files to delete next time. A kill inside step 4
    re-runs from the cursor; deleting an absent key is a no-op; a head deleted before its author's
    newest head is recorded cannot happen (the newest accepted head already exists as the
    committed head in `AuthorState`; the sweep reads it first). A kill inside 6(a) re-seeds; inside 6(b) resumes the rebuild from its turn. A
    kill inside the rewrite leaves `store.redb.rewrite`, which step 2 deletes at the next start;
    the live file was never modified by the rewrite. A kill after the rename finds the new file
    with `schema_version` 2; the replacement's directory-sync debt (`finish_replacement`,
    `store.rs:919-943`) is settled before any acknowledged save (ADR-044 RD-7). A kill inside
    `compact()`: redb commits each move, so the file is consistent at the next open; the next
    start compacts again from where the ratios stand.
  - *Verified before the cutover:* the rewrite reopens its candidate, compares row counts per
    table and the `meta` rows with the source snapshot, and only then renames (ADR-041 RS-13:
    through the store directory's descriptor). Until the rename the old file is intact and
    authoritative; after it, the old inode is unlinked and no copy is kept (SO-9).
  - *Deleted:* nothing beyond SO-1's list. The sweep is the cutover: after it no kind-9 row, no
    receipt and no `source_heads` tree exists, and nothing writes one.
  - *Proof:* a second arm of SO-1's journey. The newcomer's data root is first written by the
    v0.4.30 release asset, obtained as ADR-045's update journeys obtain it (apparatus: it is the
    binary that wrote these rows on the operator's machines), with a `store.redb.failed-1` hard
    link placed as v0.4.30 makes it. The fixed binary starts on it: `vox status` shows the room
    preparing while it removes sync records, then rewriting; the room opens; `sync_bytes` is 0,
    `data_bytes` is under SO-1's bound, `ls` shows no `.failed-*` and no `.rewrite`, the log names
    the removed file with its size, and the member's row from before the upgrade renders (ADR-046
    SY-26's arm, the `base1` fixture). Interruption arm: kill the daemon during the sweep (status
    shows `removing sync records`) and again during the rewrite (`.rewrite` exists); after each
    restart the start completes with the same outcome and the room's entries read as before.
    Short-disk arms (the full-disk apparatus of SO-11, optional in tree, blocking on the fleet
    as ADR-045 r9 J5(i)): (i) a data root written by the v0.4.30 asset on the 256 MB image with
    20,000 stranded proof rows (one 4 KB leaf each, about 80 MB, left as that binary strands
    them by abandoned fetches, RcaChurn's `relay75` recipe; R4-6: 500,000 rows need over 1 GB
    of leaves and cannot fit the image) and 20 MB free, no ballast: the sweep runs, compaction
    runs and returns about 80 MB, the ledger seeds and the rebuild completes, the room is
    writable within 60 s and no person freed anything; (ii) the same with 2 MB free: status says
    `the upgrade needs 16 MB to continue`, the room's entries are readable meanwhile, and after
    15 MB is freed the start completes by itself within 60 s; (iii) a store whose sweep frees
    little (a fresh v0.4.30 store with 10 entries) on an image with 20 MB free: compaction runs,
    the floor is still not met, the room publishes readable as `cannot save`, its Session
    listing says `preparing`, and after space is freed the listing appears within 30 s; (iv) the
    multi-GB case is ADR-045's multi-GB fixture (a real 2 GB-class old store on a filesystem the
    driver fills with filler to leave exactly 20 MB, then 2 MB), the same assertions, wall time
    and peak disk use recorded. The old-binary
    red for the main arm is the observed store: `du` of the newcomer's node directory before the
    upgrade is at least 14 × 4 KB × entries above its data (the stranded proof rows; measured on
    `runs/direct2`), not the absence of a future status field. Mutant: skip the sweep;
    `sync_bytes` stays above 0, PRODUCT. Mutant: rename before verification; a candidate the
    apparatus truncates (test-knobs hold before the rename) becomes the live store and the
    entries are gone, PRODUCT. Mutant: refuse the sweep under the ordinary floor; the short-disk
    arm never completes, PRODUCT. The multi-GB fixture on the fleet (ADR-045) measures wall time
    and peak disk use on a Mac and a Linux host; those two numbers are UNKNOWN until that run.
    Acceptance C20-2.

- **SO-3. Void under ADR-046 R2 (the decider's choice, ledger rows 57, 62): no verifier cursor
  is written, so there is nothing to bound.** *(changed r10: D6; r12: the R1 text moved to the
  review record.)* Item 20's cursor (12,299 B, rewritten per slice, RcaChurn C1) does not exist
  under R2 (SY-18: a proof is verified in memory and dropped; what is wanted is re-derived,
  SY-14); its acceptance C20-3 is SO-1's `sync_bytes` = 0 assertion. ADR-038 FX-29 is withdrawn
  (amendment 2).

- **SO-4. A Session step's row holds each fact once: the ciphertext, never a clear copy of the
  body; a new record carries one composite signature, the author's root key's, in a row of its
  own that lives and dies with the record.** *(changed r4: the decider's answer to Q2; 2-day
  retention)*
  - *Why:* items 22 and 78. 85% of a step is two signatures and the body is stored twice. The
    decider: "we need to store only what we need"; on 2026-11-13 he chose the root composite
    signature (Q2) and set step retention to 2 days (SO-8). Review F10, F12, F5, N9 (the clear
    copy is derivable: the keys that open a retained record are kept per generation, C-22).
  - *What changes:*
    - Record v3 is `[3, room, header, ciphertext, root_signature]`: the `GroupMessage` header and
      AEAD ciphertext as today, no sender-key signature, and the author's root composite signature
      over `vox/private-session/v3 ‖ [room, header, ciphertext]` (its own domain and version).
      Every holder verifies it against the author's root key as the room's governance knows it,
      which is what `restore` does today (`pending_upgrade.rs:1500-1503`), before the AEAD opens;
      the author signs with the root signer it already uses for the outer signature. Readers hold
      the chain key and can produce a valid AEAD tag; none holds the root key, so none can forge
      the author's step; a compromised sender generation (chain and signing key, ADR-006 S-6)
      cannot either. A member, an auditor with the admitted root key, or a holder whose receiver
      state is gone can verify any retained record without sender-key state. Verification never
      grants reading, regranting or relaying (SA-7, SA-8 unchanged). Every consumer of the record
      (receive, `restore`, serve, the projection's reader, the attention reader) is changed to
      the versioned shape; the v3 AEAD path does not require the removed inner signature.
    - **The body is stored once, encrypted.** The plaintext cache row
      (`session_cache_bytes`, `channel.rs:1962-1973`) becomes a metadata row: `created`, `kind`,
      `session_id`, the body's length and its SHA-256 (about 60 B), parsed once at receipt;
      retention, attention and the projection's selection read it without a key. The body itself
      is opened when it is shown or folded, from the generation's retained chain: for a received
      record the receiver chain's history key at its floor advanced to the record's iteration
      (`decrypt_retained`, `group/state.rs:669-686`, which never changes the live replay state);
      for an own record the author's origin for that generation (`drive.rs:92-100`;
      `OwnHistoricalKeys` for rotated generations). The SA-8 floor is the history floor itself: a
      record below a member's floor was never readable by it and has no clear copy today either.
      Cost per open, **measured (E-10, `store-experiments`, `timed-run.log`; vox-core's own
      group code at tag v0.4.30, 100 generations of 1,000 steps, bodies drawn from the operator's
      measured row sizes): a 100-step page opened from the retained chain, random pages across
      generations, 0.36 ms; the worst case (gap 999 from the floor) 0.61 ms, inferred from the
      measured components (an HKDF advance 0.47 µs, a message key 0.48 µs, an AES-GCM open per
      row); a 100,000-step Session opened sequentially 134 ms (inferred)**: three orders of
      magnitude under ADR-034 FR-4's one second, with the render path keeping, in memory and
      zeroized, the last derived key per generation so a page of consecutive steps advances once
      per row. Not in the figure: the sealed row read (inferred under 2 µs per 1.4 KB row) and
      the terminal. A stored **v2** record opens through `GroupMessage::open`, which verifies its
      sender composite signature before the AEAD (`message.rs:161-180`): **67.7 µs per step**
      measured, so a 100-step v2 page is about 7 ms and a sequential pass over 100,000 v2 steps
      6.8 s; a page is far under FR-4, and the one path that opens a whole Session of v2 records
      at once, SO-6's first full rebuild on an upgraded store, is a preparation stage (SO-2 step
      6), not a render. The key-page fallback of revision 5 is not needed by the figure and is
      deleted. The generation's chain segment (SO-7) is kept while the
      generation is **live or any record of it remains**, on every path including a member's
      removal (SC-2b: a removed holder keeps what it read), and the shared pruning consumer that
      retires a generation applies that rule (a step can expire at two days while its generation
      stays live until 1,000 messages or seven days; the chain must not go with the last step);
      a retained v3 record is opened through the history-opening path for a current or removed
      member alike, never through the live path's `preview` refusal. Saving: the body once (about
      55 MB of data on the operator's store at 7-day retention; 13% of the step rows) and the
      64-B duplicate hash and author.
    - The stored row splits in two: `(room, PrivateSession, id)` holds the header, ciphertext,
      metadata row, first-seen and attention (about 260 B + body: 610 B for the median body,
      1,650 B for the mean); `(room, PrivateSignature, id)` holds the 3,373-B signature. Both are
      put in the step's batch and both are deleted in the same retirement batch (expiry, leave,
      removal): a signature row without its record never exists past one crash window, and the
      sweep that finds one deletes it. Rendering reads the first only; serving and `restore` read
      both. Why two rows: a 4.4 KB row takes an 8 KB page, the signature alone takes a 4 KB page
      and the step row packs (measured distribution: 333.6 MB on disk for the operator's steps
      with the clear copy, about 300 MB without, against 424 MB inline and 508 MB today).
    - **Identity.** A v3 record's identity is `sha256` of its v3 wire. Stored v2 records are not
      converted: they keep their bytes (both signatures, the clear copy), their identity and every
      reference to it (private index, projection sources, attention boundary, pull locators), and
      are read and verified as today (the `Proof` enum gains a third variant beside `Private` and
      `Legacy`). v2 steps expire under the room's step retention, 2 days by default from this
      release (SA-9 as amended; a room whose admin set it longer, or to forever, keeps them for
      that long, and no step is deleted ahead of its retention to save bytes); v2 lifecycle
      records remain for their message retention with their extra signature (one per opening,
      end and grant-refresh copy, `pending_session.rs:1310-1359`; a few MB on the operator's
      store, counted by SO-15 as `lifecycle_bytes`). Nothing is re-keyed, so no reference can
      break and no retained view, lifecycle state or pending attention changes across the
      upgrade. The saving on the operator's stores arrives as the steps turn over under their
      retention (two days after the upgrade for a room at the default), not at first start.
    - Wire: stream 13 carries v3 and, for records written before the upgrade, v2, until each
      such record's ordinary retirement (R4-2: the server sends a retained record's own bytes,
      `serve.rs:212, 289`, and names it by its own hash; a holder that was offline and returns
      within the step's retention, or any holder of a retained v2 opening or end, must still be
      able to pull it from a different holder when the author is gone, and a v2 record cannot
      be re-signed as v3 without the author's root signer). A receiver authenticates a v2 record
      exactly as v0.4.30 did (both signatures) and a v3 record as SO-4 says; nothing authors a
      v2 record. This is retained-data support between updated peers, not mixed-version sync:
      all machines move to 0.4.31 together (the decider, 2026-11-13).
  - *Not chosen (the decider, Q2):* the sender signature alone (strictly weaker: a compromised
    generation forges it and an auditor cannot verify it, the decider's Q2 table) and both signatures (about
    460 MB of the operator's steps at 7-day retention for no property a holder, member or auditor
    lacks).
  - *Deleted (root signature chosen):* the sender-key signature on private records
    (`group/message.rs:116-124` as it applies to them); the v2 write path; the clear body in
    `session_cache_bytes`.
  - *Proof:* extend `a_session_is_sealed_to_drive_proof.rs` (claim 1 already writes steps through
    the hook protocol). 200 steps of 300 B: alice's `vox status --json` shows
    `rooms[].store.steps_bytes` ≤ 200 × 4.2 KB; bob reads every step, carol (no drive) none; bob's
    `vox room session` page of 100 steps renders within 1 s (FR-4) on a cold daemon (bob
    restarted before the read), and a page spanning two generations (alice rotated at step 100)
    within 1 s; the bound is confirmed or the key-page mechanism chosen by E-10 before this arm
    is written in. Restart arm: alice restarts;
    bob restarts; both still show every step, and a step alice posted before the upgrade (the data
    root seeded by the v0.4.30 asset, as SO-2's arm) is still shown beside the new ones, with its
    attention state unchanged. Retained-v2 relay arm (R4-2): three members' data roots seeded by
    the v0.4.30 asset, alice having posted a v2 opening and 20 v2 steps that bob and carol hold;
    carol is stopped before the upgrade; every machine moves to the fixed binary; alice is
    stopped; carol starts within the step retention and pulls the 20 steps and the opening from
    bob: her `vox room session` shows them with their original identities (the attention state
    carol had on the opening is unchanged); v0.4.30 is not red here (it relays v2; the arm guards
    the regression). Mutant: refuse to serve a v2 record; carol's listing lacks the 20 steps,
    PRODUCT. Rotation arm: alice rotates her sender key (ADR-006 S-6) after
    step 100; bob shows steps before and after the rotation, also after his restart (the old
    generation's chain segment is kept). Removal arm: bob is removed from the room after step
    150; he still shows steps 1–150 after a restart and never shows 151–200. Attacker arm
    (apparatus): bob's node, which holds alice's chain, forges a step with a valid AEAD tag and no
    valid root signature and serves it to dave; dave's `vox room session` never shows it; a
    second forged step signed with alice's *sender* signing key (the apparatus holds a copy, as a
    compromised generation would) is refused the same way. Expiry arm: with step retention set to
    60 s, after the sweep `steps_bytes` falls to 0 and no `PrivateSignature` row remains (SO-15's
    ledger shows `steps_bytes` 0; the mutant that leaves the signature row shows it above 0).
    v0.4.30 is red on the bytes (no field; rows of 7,905 B) and the removal arm is unverified on
    v0.4.30 (expected green: the clear copy exists there). Mutant: keep both signatures;
    `steps_bytes` red, PRODUCT. Mutant: accept a record whose root signature fails; dave shows
    the forged step, PRODUCT. Mutant: delete the old generation's chain segment at rotation; bob
    shows steps 1–100 as `cannot be opened` after his restart, PRODUCT. Acceptance C78-1.

### 2. Store what we should, efficiently

- **SO-5. No leaf that holds a value over 2 KB holds any other value; a newly written index page
  is split by its encoded size so that it fits one 4 KB page.** *(changed r3: N7)*
  - *Why:* items 76 and 80. 1,400 MB of leaf slack. The decider: "crazy". Review F4: lowering
    `PAGE_ITEMS` refuses existing pages; N7: the codec writes 66 B of key per row, so a row count
    is the wrong split unit (C-80).
  - *What changes:* two redb tables with the same key `(room, kind, id)`: `segments_small`
    (values ≤ 2,048 B) and `segments_large` (values > 2,048 B), in `store.rs`; schema version 2.
    `put_segment` writes into the table for the value's size and removes the key from the other;
    `get_segment` reads small, then large; `segment_after`, `segment_id_after`, `last_segment_id`
    and every walk (rewrite, room deletion, the ledger) merge the two tables' iterators in key
    order. A schema-1 store (one table) is read and written as today until SO-2's rewrite
    converts it; the split takes effect at that rewrite, and status says `rewrite due` until
    then. The threshold is a constant; changing it needs a rewrite. The index codec's writer
    splits a leaf, branch or ranked page when its *encoded* size, with the seal (34 B) and redb's
    key and leaf overhead (about 70 B), would exceed 4,096 B (`PAGE_SPLIT_BYTES` = 3,990), by
    summing each row's encoded bytes as it is added (66 B of key plus the value's or summary's
    CBOR); the decoder keeps both existing bounds (128 rows, 16 KB), so no page is re-encoded at
    start; a page over the byte budget is rewritten within it the next time it changes, and one
    that never changes keeps its 8 KB leaf. Fanout falls from about 60 to about 55 rows a page
    for leaves; depth is unchanged for the operator's trees (depth 3 holds 166,000 rows at 55).
    Residual for the operator: the SessionIndex pages are all re-put by SO-2's one rebuild (26 MB
    in the 4K–8K bucket today → about 20 MB at 4 KB each); EntryIndex pages that never change
    keep their 8 KB leaf (83 MB in the 4K–8K bucket; how much of it changes is INFERRED, and the
    figure is excluded from Appendix B). The redb defect is reported upstream with the `ascend`
    reproduction; no vendored redb patch is taken.
  - *What this does not do:* remove the power-of-two rounding of rows over 4 KB (215 MB on the
    operator's store: steps with long bodies, log entries, headers); guarantee a fill above redb's
    merge rule after deletes. SO-10's trigger is defined on packed bytes for that reason.
  - *Deleted:* the single `SEGMENTS` table definition (`store.rs:50`) as the writer's target;
    `PAGE_ITEMS` as a split rule (kept as the decoder's bound).
  - *Proof:* extend `retention_proof.rs` proof 3 (it posts 100 messages and reads them on two
    members): after the 100 posts, `vox status --json` shows `store.in_use_bytes` ≤ 1.3 ×
    `store.packed_bytes`. And SO-4's journey: alice's `in_use_bytes` grows by at most 200 × 6 KB
    during the 200 steps. v0.4.30 is red on the observed store: after the 100 posts the
    v0.4.30 daemon is stopped and the apparatus opens the stopped node's `store.redb` with
    redb 4.3.0 (read-only, as `redbwalk.py` did for `rca-StoreSize` §1; a running node's store
    cannot be opened by a second process, E-7) and compares `stats().stored_bytes` and the
    allocated pages with the sum of its rows' bytes: the first-seen rows alone, 45 B each,
    cost 4 KB each at v0.4.30; the red is that ratio, not the absence of the field (D18). The two constants are to be
    calibrated by E-3 on the release asset before they are written in. Mutant: write every value
    into one table; both bounds red, PRODUCT. Mutant: split index pages by row count again; the
    `in_use / packed` ratio goes red, PRODUCT. Acceptance C76-1.

- **SO-6. A change to one Session input costs work bounded by that Session, never by the room,
  every change is discovered, and the published view is the same function of the input set that
  the full rebuild computed, whatever order the inputs arrived in.** *(changed r3: N2, N5, N6)*
  - *Why:* items 22 and 77. 487 page writes a second; 8,806–14,772 per named-session post at
    1,500 candidates. Review F2 (arrival-order folding diverges), F3 (bundle parts past the
    cursor are lost), F13 (the measured red was a public named-session post), N2 (an id cursor
    never sees an in-place change of a private row), N5 (revision 2 named the wrong logical
    identity), N6 (a late event's re-fold is not constant and must be resumable and atomic).
  - *What it keeps of the old design (C-77):* the published view equals the full fold of the same
    input set evaluated in one canonical order; one atomic publication; no state in memory
    between turns; bounded turns; insensitivity to arrival order. Only the work per change
    becomes bounded by the Session it touches.
  - *What changes:*
    1. **Change discovery.** Every transaction that adds, replaces or removes a projection input
       appends the affected key to a `Changes` queue in the same commit: a public candidate's
       `(instance, arrival)`; a private row's id on put, on in-place re-save
       (`pending_upgrade.rs:1579-1591`), on expiry and on removal; a member's eligibility change
       as a room-wide entry. The fold consumes `Changes` in order and retires each entry in the
       commit that publishes its effect; nothing is discovered by comparing ids or generations,
       so a row that becomes readable under its old id is folded then. A kill between the input's
       commit and the fold's leaves the entry queued; the next turn applies it.
    2. **Canonical order and identity.** Every interpreted event has position `P = (created,
       class, hash)` (Terms); no local id enters it, so two nodes order the same events the same
       way (the old fold's tie by local storage id, `record.rs:20-36`, did not promise that).
       Logical-record identity and the winner rule are the old fold's exactly: identity
       `(author, created, body)` (`build.rs:37-45`), newest copy by `(private, order, hash)`
       wins (`:49-61`), where `order` is now the canonical position. A replaced copy retracts the
       event its predecessor produced (rule 4).
    3. **Per-Session fold.** The index keeps `Events(S, P) → event` for openings and ends
       (kinds 1 and 2; a few per Session, but unbounded under forever retention) and
       `Names(S, P) → name` for **every** name assignment: kind-0 name events from any
       named-session post (`build.rs:319-337`, thousands per Session) and the name an opening
       supplies, at the opening's position (`build.rs:396-408` updates `name` and `named_at` on
       a refreshed opening too, so an opening-supplied name is a name assignment like any other;
       R3-3). Openings and ends are folded in position order by the existing transition
       (`build.rs:396-433`, unchanged for every field but the name, which the `Names` rule
       supplies); each Session's descriptor records `applied_through`. A new lifecycle event with
       `P > applied_through` is applied once (O(1)); otherwise, or on a lifecycle removal, the
       Session is re-folded (rule 4). The shown name of an incarnation is the name at the
       greatest position in `Names(S, *)` that is ≥ its opening's position and, if it is ended,
       ≤ its end's position; the sequence opening "A" at t1, post "B" at t2, refreshed opening
       "C" at t3, end at t4 shows "C", as the full fold does; an opening-only Session shows its
       opening's name; a removed name assignment (expiry, replacement) is one delete and the
       next-greatest wins; repeated incarnations each take the maximum within their own bounds.
       A name assignment in any order costs one tree insert and one bounded lookup. No re-fold
       is caused by a name event.
    4. **Re-fold as a resumable job with a captured basis.** A re-fold of `S` is a `Refold(S)`
       task that captures, when it starts, the greatest `Changes` sequence number then queued
       for `S` (its **basis**); it reads only `Events(S, *)` entries at or below the basis, 32
       events per turn, with its own cursor, and builds `S`'s descriptor, opening incarnations
       and lifecycle rows under a new **per-Session generation** `g'` (rule 6). An event of `S`
       that arrives during the job is appended to `Events(S)` and queued as a new `Changes`
       entry above the basis; the job does not restart (R3-4): it finishes and publishes its
       basis, and the queued correction is then applied like any other (O(1) if it is newer than
       `applied_through`, else a further `Refold` with its own basis). A valid completed basis is
       therefore published without any quiet interval, whatever an author posts meanwhile; an
       author that refreshes continuously only queues work, never discards it. Staged rows of an
       abandoned job (a changed history instance, a full rebuild) are retired by cleanup (rule
       6). Cost, stated truthfully: a late lifecycle event or removal costs O(m) where m is the
       number of `S`'s openings and ends (not its name events); N such events delivered in
       reverse order cost O(N²) in all; no replay prefix is ever discarded; a room's total work
       per input is bounded by the Session touched, never by the room's candidates. The per-turn
       bound is 32 events and the trees they touch.
    5. **Bundles.** A multi-part metadata bundle keeps a part index `Parts((author, tag), n) →
       source`; when parts 1 … N are all present (N as the bundle's first part declares, bounded
       by the existing byte bound), the parts are assembled in part order, hash-checked and the
       metadata published; a part arriving in any order, before or after a restart, completes
       it; a replaced part re-checks; a removed part (expiry, replacement) retracts the published
       metadata in the same commit and the bundle waits for its parts again; an incomplete bundle
       publishes nothing and holds only its locators. `build.rs:164-184`'s start/lookup/invalidate
       goes.
    6. **Publication is a bounded swap; retirement is bounded cleanup (R3-5, R4-3).** Every
       per-Session row in the global indexes the queries consume (`Openings`, `AuthorOpenings`,
       `OpeningHash`, `Lifecycle`, the fingerprint lanes; `build.rs:359-503`, `query.rs:27-48,
       153-203`) carries the Session's generation **in its key**, after its ordering component
       and before anything else: `(S, g, …)` for Session-first rows and `(P, g) → S` for
       position-ordered listing rows (a unique-key tree, `session_tree::Write::set` →
       `change_value`; a key `(P)` alone would let the staged `g'` overwrite the live `g` row
       before the swap). `S`'s descriptor names its live generation. A `Refold(S)` writes its
       staged rows into those same trees under `g'` during its turns (each turn bounded, each
       an ordinary commit); a reader that meets `(P, g)` resolves it only if `g` is `S`'s live
       generation, so staged rows are invisible until the swap and the live rows stay visible
       until it, also after a kill in the window. Every exact-opening and position lookup
       applies the same rule. The swap commit writes `S`'s descriptor (live
       generation `g'`, `applied_through`), the count deltas (one row per counter), and retires
       the `Changes` entries the job served: O(1) rows, whatever `S` holds. The rows of `g` are
       then retired by the existing bounded cleanup (`cleanup(limit)`, `storage.rs:823-945`),
       32 keys per turn, resumable after a kill, and a position-ordered listing skips a stale
       `(S, g)` row at one descriptor lookup per candidate until cleanup reaches it. Concurrent
       updates to other Sessions touch other `S` keys and are unaffected by the swap. One
       Derived commit per turn applies up to 32 `Changes` entries (or 32 events of a `Refold`)
       into the trees, retires the entries served, and swaps the published header: queue,
       cursors, generations and roots are never in different commits, so a kill between turns
       leaves the view equal to the fold of exactly the inputs consumed, and the next turn
       continues from the queue. A changed history instance (a rebuilt log) empties the queue
       and starts a full rebuild.
    7. **Display order** is unchanged for a person: positions stay by `created`, with the
       canonical tie.
    8. **Full rebuild** remains for: a changed history instance; Session upgrade or import;
       repair. A member removal or readmission is applied as a `Changes` entry per affected
       Session (its events are re-evaluated for eligibility), not a full rebuild.
    9. `put_source` compares before it writes: an unchanged descriptor is not put again.
    The activity fold (`activity_fold`, `activity_pending.rs`: approvals, questions, resolutions)
    is already keyed by its own facts and is not changed by this requirement.
  - *Deleted:* the phase-1 build on every revision change (`build.rs:566-568`), the reset to
    phase 7 on a change in the middle of a build (`:561-565`) except for rule 8's cases; the
    `private_generation` trigger as a discovery mechanism.
  - *Proof:* extend SO-4's journey, in a room that already holds 1,500 named-session posts. Arm 1
    (cost): the 200 steps are interleaved with 20 public named-session posts and 5 Session ends
    and openings; each step and each lifecycle change is visible in bob's `vox room session`
    within 2 s, and the bytes alice's daemon writes during the run, as the operating system
    counts them for the process (`proc_pid_rusage` `ri_diskio_byteswritten` on macOS,
    `/proc/<pid>/io` `write_bytes` on Linux; the scratch daemon holds only the proof's nodes;
    measured from the first step to 10 s after the last visible change), are at most 40 MB:
    one fixed bound, a workload budget (200 × about 200 KB: the step's rows, its index and
    lifecycle updates, and redb's page rewrites per commit, rounded up), not a measurement and
    not set from any run; E-4 establishes the whole process's write I/O on this workload,
    including lifecycle, index and redb writes *(changed r10: D10; r11)*. E-4 measures v0.4.30 on
    this exact shape (the RCA's 8,806–14,772 page ids per post are allocations, not OS
    writes): the arm's v0.4.30 verdict is that figure against the same 40 MB — red if above,
    and if v0.4.30 writes under 40 MB the arm is **not red on v0.4.30** and says so (SO-6's
    v0.4.30 reds are then arms 2 and 3 and SO-15's growth arm); the bound does not move to
    make it red. Arm 2 (order): two members receive the same
    opening, two same-`created` openings with different bodies (one supplies the harness, the
    later one a new name and no harness), a rename and an end, in different orders (the
    apparatus delays one member's connection so it receives the end before the openings); both
    show the Session ended, with the first opening's harness and the final name. Arm 3 (bundle):
    a three-part metadata bundle delivered 3, 1, 2 with a restart of the receiver between parts;
    the completed metadata appears; with part 2's record then expired (retention 60 s on an
    apparatus room), the metadata disappears within one sweep. Arm 4 (in-place change): carol
    joins with drive granted late: her node receives alice's opening before the drive key and
    keeps it opaque; the key arrives; carol's `vox room session` lists the Session within 5 s,
    also when her daemon is killed between the key's arrival and the fold and restarted. Arm 5
    (crash in a re-fold): a `test-knobs` hold inside a `Refold` of a Session with 40 lifecycle
    events (openings and ends posted by the apparatus) and a kill there; after restart the
    listing shows the Session's final state and never a half-folded one (no duplicate opening
    row, counts equal to the listing). Arm 5b (generation coexistence, R4-3): a `test-knobs`
    hold stops a `Refold` of a Session with 40 lifecycle events after its staged rows are
    written and before the swap; while held, `vox room session` lists the Session exactly as
    before the late event (every previously published incarnation present, nothing of the staged
    generation), also after a kill and restart in the hold; after the swap only the new
    generation shows (mutant: key the listing rows by position alone; while held, the listing
    lacks the Session, PRODUCT). Arm 6 (removal): an expired opening disappears from the
    listing within one sweep. Mutants: apply events in arrival order without the re-fold; arm 2
    shows the Session open on one member, PRODUCT; drop a part that arrives before part 1; arm 3
    never shows the metadata, PRODUCT; discover private inputs by id only; arm 4 never lists the
    Session, PRODUCT; publish the staged rows before the job reaches the end; arm 5 shows a
    duplicate opening, PRODUCT; start a phase-1 build on every basis change; arm 1's bytes bound
    goes red, PRODUCT. Before merge, spike E-5 folds a copy of a 1,500-candidate store both ways
    and compares the published trees, including same-`created` and body-distinct inputs; reported
    in the pull request, not committed. Acceptance C77-1.

- **SO-7. A step rewrites only the key state it changed: the chain it advanced, about 300 B.**
  *(changed r3: N12)*
  - *Why:* item 22. 8,971 B re-sealed per step; 355 MB written for 9 KB kept. A received step
    changes its receiver chain, not this node's sender chain, so the split is per chain.
  - *What changes:* the drive state (`drive.rs:285`, segment `SEG_DRIVE`) splits into one segment
    per chain and one for the rest: `SEG_DRIVE_SENDER` (the sender chain and origin),
    `SEG_DRIVE_RECEIVER(author, chain_id)` (that receiver chain: chain key, next iteration,
    history key and floor, skipped keys, signing public key), `SEG_DRIVE_MARKS` (delivery marks
    and per-recipient grant floors, written on delivery). An authored step's batch puts the
    sender segment; a received step's batch puts its receiver segment; a key receipt, rotation or
    skipped-key change puts the receiver segment it changed. All are read together. A chain's
    segment is kept while its generation is **live or any record of it remains** (SO-4; the
    shared pruning consumer applies this one rule) and deleted with the last of those.
    ADR-006 S-12 and ADR-010 AR-20 are kept: the advance commits with its row.
  - *Deleted:* the whole-state put per step (`pending_session.rs:1147-1148, 1158`).
  - *Proof:* the bytes saving is inside SO-6's bytes-written bound. Its own arm guards the
    sender side: in SO-4's journey, kill alice's daemon after 10 authored steps; after restart her
    11th step is shown on bob's node. Mutant: leave the sender chain out of the step's batch;
    after the restart alice reuses an iteration, bob refuses it as a replay (ADR-006 S-10) and
    never shows step 11, PRODUCT. The receiver side has no visible failure that a journey can
    stage: receipt deduplicates a known record by its hash before the chain is consulted
    (`pending_upgrade.rs:1492-1496`), a stale receiver chain still opens the next step across a
    gap under `MAX_SKIP`, every later successful receive advances the in-memory receiver even if
    its segment write is the omitted one (`:1595-1597`), and an honest author rotates before
    iteration 1,000 (`pending_session.rs:1096-1104`) while the receive checker refuses an
    iteration at or above that bound (`:617-647`), so no gap over `MAX_SKIP` within one
    generation can be produced by real use. The receiver write therefore rests on review and
    spike E-6 (bytes written per step with 1 and 6 drive holders, before and after) reported in
    the pull request, as AGENTS.md permits; no proof claims to isolate it. Acceptance C22-1.

### 3. Prune what is no longer needed

- **SO-8. Session steps are pruned by time, two days by default; there is no byte budget.**
  *(changed r4: the decider's answer to Q1, "lets change from seven days to two days")*
  - *Why:* item 25 ("no bound"). The decider, 2026-11-13: no byte budget, and step retention is
    2 days. Time bounds steps by age, not by bytes: a burst of steps is kept for its two days
    whatever its size, and this requirement does not claim otherwise.
  - *What changes:* the default step lifetime, `DEFAULT_STEP_TTL_MS` (`governance/step_policy.rs:18`,
    7 days; the per-room override file is `STEP_RETENTION_FILE`, `node/paths.rs:52`; ADR-031
    SA-9; *changed r10: D17*) becomes
    2 days (172,800 s) for every room on every node at the first v0.4.31 start, applied
    retroactively as AR-30 says (the existing sweep, `sweep_private`,
    `crates/vox-core/src/node/channel/private_session/pending_upgrade/expiry.rs:4`, removes the
    steps older than two days at its first run; on the operator's stores about 5/7 of the
    stored steps). A room's admin may still set another value, including forever; a node-local
    override stays local. Openings and ends keep message retention (the lifecycle exception).
    The bound of a left room's hidden copy is ADR-049's number, ruled separately (ledger row
    58), and is not this ADR's. Nothing else: no `step-budget`, no byte cap on a person's data (ADR-034 FR-8).
  - *What a holder sees after more than two days offline:* a step expires by its own `created`
    time, or its first-seen time where that is earlier (AR-32, `private_session.rs:484-500`),
    so every node drops it at the same age; a holder that was offline longer than the retention
    never receives the steps that expired meanwhile (SA-8 is forward-only in any case), and its
    `vox room session` shows the Session's openings and ends (message retention) with the
    expired steps absent, the listing printing the room's step-retention setting in ADR-042's
    words (ADR-042 names the setting and no number; D17, X047-18). A step posted while the holder was offline and still within two days when
    it returns is served to it as today.
  - *What relied on seven days, re-checked:* late permitted holders: unchanged (forward from the
    grant, bounded by the steps that still exist). The re-fold (SO-6): operates on openings and
    ends, which keep message retention; unchanged. On-demand opening (SO-4): a generation's chain
    segment is kept while any record of the generation is kept; a generation rotates at 1,000
    messages or 7 days (ADR-006 S-6), so with 2-day retention a live generation routinely
    outlives every retained step of its earlier records; the segment stays while the generation
    is live or any record remains, and goes with the last; unchanged in rule, shorter in effect.
    The fleet's soak (ADR-045): an 8–10 hour gate observes no 2-day expiry; the proofs stage
    expiry with `vox room retention --steps` set to seconds on apparatus rooms, and SO-15's
    growth projection uses two days.
  - *Proof:* add a step-retention arm to `retention_proof.rs` (at the tag it has no `--steps`
    and no step; D17): with no setting, after the
    apparatus clock step of the `test-knobs` build (a 2-day step, as ADR-045 exercises timers)
    the steps posted before the step are gone from `vox room session` and `steps_bytes` falls,
    openings and ends remain; with `--steps 7d` set by the admin, they remain. v0.4.30 is red:
    steps remain after the 2-day step. Mutant: keep 7 days as the default; red, PRODUCT.
    Acceptance C25-2.

- **SO-9. Nothing a recovery creates outlives it; a room is removed by deleting its rows, never
  by rewriting the store; and a store redb reports corrupt is never moved, copied or replaced by
  the product.** *(changed r4: the decider's answer to Q5)*
  - *Why:* item 23 (and item 59: beast's 385 MB `.failed-1`); items 64 and 86 (a leave whose last
    step is a whole-store rewrite, `leave_save.rs:348`, fails on a short disk as the recovery
    did; ADR-049 requires the leave to succeed in every state and names this ADR for the store's
    part).
  - *What changes:* no `store.redb.failed-N` is ever made: `retain_original` and its hard link go
    (`store.rs:845-873`). `store.redb.rewrite` exists only while a rewrite runs; SO-2 step 2
    deletes a stale one at start. Leaving or ending a room deletes the room's rows in reclamation
    batches of 256 keys (SO-11), as a room stage that resumes from its cursor after a restart,
    with the ledger rows last; when that last batch commits the store raises
    `RoomRowsPurged(room)` (instance-qualified, like `StoreRecovered`), which ADR-049 consumes to
    drop the leave record it keeps until then. ADR-049's leave record (`left-rooms/<room>` and
    `pending-board-withdrawal/<room>/<scope>`, one batch of directory rows under 8 KB that
    precedes the deletion) is a reclamation batch (SO-11, 3 MB); below that figure ADR-049 LE-1
    refuses the leave with the room preserved and SO-11's words, and nothing here says otherwise.
    Whether the deleted bytes must also be scrubbed from the file (ADR-023 RL-8.1's "store
    rewritten so none of the deleted bytes stay") against this requirement's logical deletion
    with SO-10 as the later scrub was ADR-049's Q7; the decider answered it on 2026-11-13
    (ledger row 61): the rows and key are deleted at once, the freed pages are reused and cleared
    at the next store rewrite (daemon start or `vox node compact`), never a whole-file rewrite at
    a leave or end, which is what this requirement says. The leave's
    `store.rewrite_fresh()` call goes; the backstop (SO-10) reclaims the freed pages later. **A
    corrupt store** (the decider, Q5): a
    redb `Corrupted` error at open leaves the file untouched under its own name, `vox status`
    names it (`the store at <path> could not be opened: <redb's words>; it has not been changed`),
    the daemon's other nodes start, and nothing is deleted, moved or replaced until a person
    runs a restore (ADR-038 FX-32) or deletes the node. The decider noted he has never
    experienced real corruption; the rule exists so the product never moves a store aside by
    itself, which is what fix-list item 66 and beast's `store.redb.failed-1` were.
  - *Deleted:* `retain_original`, `redundant_retained` and the `.failed-N` paths
    (`store.rs:767-779, 845-899`); the rewrite at the end of a leave (`leave_save.rs:348`).
  - *Proof:* SO-11's journey asserts that `ls` of the node directory never shows `.failed-*` and
    shows `.rewrite` only while the log says a rewrite runs. First-start arm: SO-2's. Leave arm
    *(changed r10: D14, restated on ADR-049's states, `ADR-049.984c5593b`)*: ADR-049 Journey A
    (c) and (m), on **SO-11's 256 MB image** (ADR-049's 64 MiB image cannot hold the 64 MB
    floor plus a store; both ADRs use the 256 MB one, which is also ADR-042 TR-25's, X042-24).
    (c), the image under SO-11's 3 MB: `vox room leave` is refused by LE-1 (ii) with the disk
    words and rc 1, the room still listed — the reclamation-class record is not admitted and
    this ADR says nothing else; with the image at 3–10 MB free: rc 0, `departure:
    Pending(StoreRecovery)`, and the erasure waits as LE-4 says (a receipt, nothing to serve,
    or the 2-day bound), never runs on the full image by this ADR's doing. What this ADR owns
    in (m): once LE-4's erasure runs, its stages (a), (b) and (d) are SO-9's 256-key
    reclamation batches admitted under the ballast on the still-full image; stage (c)'s carry
    rows are ordinary writes that park on `StoreRecovery(room)` until the floor is met; after
    the image is freed, `RoomRowsPurged(room)` is raised at (d)'s last batch, the room's rows
    are 0 in `vox status` and ADR-049 prints "deleted" only then. v0.4.30 is red by code at
    `leave.rs:58` (`ensure_local_append_available_mode` refuses, rc 1, ADR-049's reading; owed:
    the first run of that act on the release asset), and its rewrite at the leave's end
    (`leave_save.rs:348`) fails on the full image. Mutant: keep the rewrite at the end of the
    leave; the erasure on the full image fails, PRODUCT. Mutant: admit stage (c)'s carry as
    reclamation → judged on premature progress, not on an OS error (r11: R8-5; below the 64 MB
    policy floor a small carry row can still find free pages): while the apparatus has not
    freed the floor, the product keeps the carry parked (`deleting, waits until room <name>
    can save again`), the source rows and the room key present, and no `RoomRowsPurged` or
    "deleted"; the mutant advances or completes the carry before the floor is freed (the
    continuity rows appear, or "deleted" prints), PRODUCT; then the apparatus frees the floor
    and the product completes by itself. Corrupt-store arm
    *(added r10: D15)*: a scratch node's daemon is stopped and the apparatus overwrites the
    first 4 KB of its `store.redb` (redb's header; `redbtool`'s recipe) so that open returns
    `Corrupted`; the daemon is started: `vox status` shows that node as `the store at <path>
    could not be opened: <redb's words>; it has not been changed`, the daemon's other node
    opens its rooms, `ls` of the node directory shows the same file with the same inode and
    bytes (`cmp` against the copy the apparatus kept) and no `.failed-*`, `.rewrite` or
    `.corrupt*`; after `vox node restore` (ADR-038 FX-32) the node is back. v0.4.30's result on
    a `Corrupted` open is UNOBSERVED (r11: the eighth review's source audit): `Store::open`
    propagates `open_database(...).map_err(open_error)?` (`store.rs:580-597`) before a Store
    exists, and `retain_original` (`:845-873`) is the copy-install path of a rewrite, not an
    open path, so nothing at the tag is known to move a corrupt file aside; what the tag's
    daemon does with the other nodes on that error is the first run's observation (owed on
    the asset); the apparatus asserts its precondition first (`vox status` names redb's
    `Corrupted` words, else APPARATUS). Mutant: move the corrupt file aside
    and open a fresh one; `ls` shows `.failed-1` and the node reports an empty store, PRODUCT.
    Acceptance C23-3.

### 4. Backstops: compaction, and a full disk

- **SO-10. A store whose in-use bytes exceed 1.5 × its packed bytes, or whose file length exceeds
  2 × its in-use bytes, is rewritten when the disk holds the rewrite's reservation, and compacted
  in place when it does not; this runs at daemon start and on `vox node compact`, and nowhere
  else; status says which and why.** *(changed r4: the decider's answer to Q8)*
  - *Why:* items 21, 79, 80. The decider: "compaction is fine" — last, as a backstop. After
    SO-1–SO-7 the inputs that made the empty space are gone, so this runs rarely. Review F7: the
    first draft's `1.2 × data` was below every measured replacement; N8: revision 2 rechecked the
    whole reservation after the candidate had consumed part of it.
  - *What changes:* the ratios are read from SO-15's numbers at each maintenance tick. The
    rewrite's **reservation** is 1.1 × packed bytes + the floor, free on the disk holding the
    store (packed bytes predict the replacement's disk use within 2%, Terms); it is checked
    before the rewrite starts, and every 64 MB written the check is `free ≥ 1.1 × (packed −
    written so far) + floor`: the candidate's own consumption is never charged twice, only
    another writer's. Below it the rewrite stops, deletes its candidate and status says `not
    rewritten: it needs <n> GB more free and the disk holding <dir> has <m> GB`. A rewrite copies
    into `store.redb.rewrite`, verifies, renames (SO-2) and makes no other file. Compaction
    (`Database::compact()`) returns free pages to the disk on the same file, needs 16 MB free
    (SO-2 step 5; the ballast released if needed) and the only handle, which the daemon has at
    start before rooms open, during SO-12's recovery, and when `vox node compact` quiesces the
    rooms. The backstop runs at daemon start before rooms open (status: `preparing: rewriting
    the store (3.01 GB file, 0.61 GB of data)` or `preparing: compacting the store`) and at once
    on `vox node compact [<node>]`, which quiesces the rooms (every save waits: an explicit
    exception to ADR-044 RD-2 that the person asked for) and prints what a person can check with
    `ls` and `du`:
    ```
    $ vox node compact omp-work
    omp-work: rewriting the store (3.01 GB file, 2.19 GB in use, 0.61 GB of data); saves wait until it ends
    omp-work: done in 8 s; the store is now a 1.08 GB file using 0.84 GB of disk
    ```
    or, when the disk is short, `omp-work: compacting in place (the disk holding … has 0.40 GB
    free; a rewrite needs 0.95 GB)` and `done in 2 s; the store is now a 1.64 GB file`. Nothing
    runs in a running daemon on its own (the decider's Q8); SO-12's reclamation after a write
    failure is that separate recovery, not an idle rewrite. `vox status` keeps the last rewrite
    (SO-15). The start-time and manual triggers are backstops; expiry and page reuse do not
    shrink a continuously running file by themselves, and status says `rewrite due` when the
    ratio trips.
    *(added r9, ADR-041 revision 7's row, carried as written)*: "A rewrite that runs at daemon
    start precedes the node's Ready. The daemon's hello reports that node in state `Rewriting`
    (ADR-041 RS-2's per-node states) from the moment the rewrite is chosen until it ends; `vox
    daemon --restart` and `vox update`, finding a kept node `Rewriting`, print `<node> is
    rewriting its store (<file length>); it is Ready when that ends` and exit 0 at once (ADR-041
    RS-2 item 5), and the OMP watcher shows nothing for it (ADR-041 RS-7). The test build
    (`test-knobs`) honours `VOX_TEST_REWRITE_HOLD_MS=<ms>`, which holds the rewrite's completion
    for that long and logs `test knob: store rewrite held <ms> ms`; SO-10's own in-tree journey is
    the staging ADR-041 RS-7's rewriting act reuses to make a store rewrite-eligible." The same
    holds for in-place compaction at start (`Rewriting`, the line's verb `compacting`); the
    knob holds either.
  - *Deleted:* `Store::compact`'s unreachable caller `NodeProfile::compact_store`
    (`profile.rs:427`); `Store::compact` itself is kept and called where the handle is exclusive.
  - *Proof:* extend `retention_proof.rs` proof 3: after the 100 messages expire (bodies stripped,
    in use > 1.5 × packed), `vox node compact` returns within 30 s, and `vox status` shows the
    file ≤ 1.2 × in use and in use ≤ 1.5 × packed; `ls -l` and `du` of `store.redb` agree with
    the printed figures within 2%; reading the room shows nothing expired. Short-disk arm
    (SO-11's image; **optional in tree under `optional-proofs`, the decider's Q7, and blocking
    on the fleet as ADR-045 J5(i)'s compaction act**, D16): with the image too small for the
    reservation, `vox node compact` compacts in place, says so, and the file length drops.
    Threshold arm (the same image and classification): a store whose packed bytes exceed
    64 MB (the apparatus posts enough bodies that the rewrite writes at least 64 MB, so the
    per-64 MB recheck runs) on an image whose free space is the advertised reservation plus
    1 MB; the rewrite completes (v0.4.30: no verb; the arm's mutant is the whole-reservation
    recheck, which aborts after 64 MB, PRODUCT; r11: the eighth review's D16 note). Start arm: a store left
    over the ratio (the apparatus posts and expires) is rewritten at the next daemon start before
    the room publishes (mutant: skip the start trigger; the ratios stay after a restart,
    PRODUCT). v0.4.30 is red: the verb does not exist and the ratio never falls. Mutant: skip the
    rewrite; the ratios stay, PRODUCT. Mutant: start the rewrite below the reservation; the
    candidate fails on the image and the log shows `No space left on device`, PRODUCT.
    Acceptance C79-1.

- **SO-11. Vox refuses a write before the operating system would: a write transaction is admitted
  only when the disk holds its reservation above the floor; reclamation runs on Vox's own ballast
  when the disk is otherwise full; and a room that can save again says so with one event that
  every piece of work waiting on the store consumes.** *(changed r4: R3-1's figures reconciled;
  the decider's answer to Q7; ADR-046's admission queue as a consumer)*
  - *Why:* items 23 and 25. Today the first refusal comes from the OS, which latches redb. Review
    F6 (redb writes before commit: growth and precommit writeback), F8 and N3 (revision 2
    refused its own deletes below 17 MB, so nothing could be reclaimed on the disk that needed it
    most), R3-1 (two thresholds disagreed; ordinary preparation hid behind reclamation). Items
    85/87: a save that fails during a sync flow's cleanup leaves the flow pinned until the room's
    recovery is signalled, and v0.4.30 signals nothing (`rca-RcaSchedStall`).
  - *Admission:* happens before `begin_write`, in `Store::batch()`, against `free_space` of the
    store's directory (`pulls.rs:64`, a `statvfs`): for an ordinary batch the free disk alone;
    for a reclamation batch, compaction and SO-12's reopen the free disk plus the ballast's size
    when the ballast file exists (it is Vox's own space, spent on those alone). An **ordinary**
    batch (posts, received entries, Session
    steps, index and projection turns, key material, ADR-049's departure record) needs `floor +
    2 × its estimate + 1 MB`, where the estimate is the serialized bytes the caller supplies
    (every caller seals its segments before it opens the batch, so the figure is known; a page
    write of the index trees adds its page size per changed tree) and the doubling covers the
    copy-on-write paths and allocator pages; a batch that exceeds its estimate by more than the
    margin is a product defect the log names. A **reclamation** batch (retention sweeps, SO-2's
    sweep, room deletion, attention retirement, expiry, a sync flow's cleanup and settlement
    saves, and ADR-049's leave record (`left-rooms/<room>` and the board withdrawal, one batch
    under 8 KB of directory rows that precedes a deletion): at most 256 keys deleted, writes
    limited to the directory rows and cursors they update, under 2 MB in all) needs 3 MB: one
    figure, used by SO-2 step 4 and SO-12 state 3 alike (revision 3's 17 MB is withdrawn); the
    one insert stage admitted under the same size and figure is SO-2 step 4's **migration
    batch** (ADR-046 SY-26's initialization, at most 256 keys and under 2 MB per transaction,
    with its cursor and completion marker), because the sweep that returns space cannot run
    before it (r11: R8-2). A
    first-start preparation stage that writes new pages (the ledger seed, a projection rebuild
    turn, SO-2 step 6) and a room's recovery re-save are ordinary batches and need the floor;
    they never spend the ballast, and SO-2 and SO-12 publish the rooms readable while they wait.
    A ruled save (ADR-044 RD-7 r14: one save, one trip) holds its credit until its own
    `Immediate` commit has returned; there is no deferred flush and no flusher. A rewrite needs its own reservation (SO-10); compaction the compaction reserve (16 MB,
    E-2's figure, in blocks on a sparse-file filesystem; SO-12 state 3 names the outcome when
    it is not enough).
  - *The ballast:* a fully written (not sparse) 32 MB file `store.ballast` beside the store,
    created when the disk holds floor + 32 MB free and whenever that becomes true again after it
    was released. When a reclamation batch, compaction, or SO-12's reopen needs space the disk
    does not have, the ballast is released (truncated to zero and deleted) first, which returns
    32 MB of real blocks; the work then runs within that. The ballast is Vox's protected
    maintenance capacity: ordinary admission never counts it, whatever its size relative to the
    floor, so no ordinary write ever runs on it. On a disk that another process has filled to zero
    while the ballast exists, a node can therefore still expire, leave, sweep and compact; on a
    disk filled to zero with no ballast (a first start, SO-2 step 7), it says the exact
    prerequisite. The pattern is CockroachDB's and Pebble's ballast file.
  - *Refusal and recovery:* below its figure a batch is refused with `Error::Storage { op:
    "save", detail: "the disk holding <dir> has 41 MB free; Vox keeps 64 MB free" }` and no OS
    write is attempted, so redb does not latch. The room becomes "cannot save" with the SR-2
    words (`repo-to-cve cannot save: the disk holding /home/robert/.local/share/vox has 41 MB
    free; Vox keeps 64 MB free. It saves again by itself when space is freed.`), checks again
    every 5 s (a free check) and says `recovered; it can save again` (SR-3); Session steps are
    held meanwhile (SR-4); retention sweeps, leaves and flow cleanups keep running as
    reclamation; ADR-040 NW-2 names this wait and ADR-042 owns the words. A batch already
    admitted that meets an OS error anyway (another process filled the disk after admission: an
    external race the reservation cannot exclude) is the latch case, SO-12: its work is not
    acknowledged, no durability mark, fold cursor or held position advances for it, and the
    room's next attempt is after recovery. Growth is sparse on APFS, ext4 and xfs; on a
    filesystem without sparse files the growth step counts against the floor, which is why the
    proof's image is APFS.
  - *`StoreRecovered(room)`, and what triggers the save that precedes it (R4-1):* the store
    raises it once per room on every transition from "cannot save" to "can save", whatever the
    cause. Two transitions are distinct and acyclic: **admission-ready**, an internal condition
    the store's 5-second free-space check (or SO-12's state 3, or SO-2's stage) finds true when
    the floor, the reserve or the reclamation figure is met; and **recovered**, the event. On
    admission-ready the recovery owner itself runs the room's pending work directly, with no
    event: the room's re-save if one is pending (SO-12 state 3), SO-2's held stage, or nothing;
    it retries that work on the next check if it fails. When that work has committed (or there
    was none) the store raises `StoreRecovered(room)`. So the event is raised after the room's
    own pending save committed and never waited for by that save; a consumer that retries on it
    finds a writable store. It carries the room's history instance, and work belonging to a
    replaced instance is discarded, not retried. It is the one event; `StoreReopened`, the name
    ADR-046 SY-24 and ADR-044 RD-7 used while this ADR was being written, is this event and not
    a second one.
    Consumers: ADR-046 SY-24 (a flow's failed cleanup is retried on it; `retirement_erasure`'s
    waiter, `runtime.rs:1814-1848`, is completed by it as well as by a lock), ADR-046's admission
    queue (a received entry whose admission was refused under the floor is re-queued on it, for
    the same instance, including the floor-recovery case with no reopen), ADR-040's
    `NotYet{StoreRecovery(room)}` (released by it), ADR-044 RD-7 r14 (the next ruled save after
    it runs its own commit; nothing of RD-7's is re-armed),
    ADR-049 (a departure record held under the floor is written on it), SO-2 step 6 and SO-6
    (a preparation stage or fold turn held under the floor resumes on it). A consumer subscribes
    before it checks the room's state and re-checks after, so a transition between the two is
    not lost. Nothing else is signalled by the store; nothing is persisted for the event.
  - *Deleted:* nothing; the check is additive.
  - *Proof:* the full-disk journey (`a_full_room_recovers_and_keeps_its_session_entries`) is
    extended and its apparatus changed: a 256 MB APFS image (`hdiutil create -fs APFS`, no
    `sudo`; HFS+ has no sparse files and 64 MB is under the floor plus the room's own data),
    attached inside the macOS guest VM; on the Linux VM a 256 MB tmpfs mount (sparse files and
    ENOSPC behave as on APFS; row 32: nothing runs on a host). **By the decider's answer to Q7
    the in-tree journey is OPTIONAL** (`optional-proofs`: it prints `OPTIONAL PROOF NOT RUN`
    when not run or when the image cannot be attached, never a silent pass, and blocks nothing);
    what blocks for SO-11, SO-12 and SO-14 is the fleet's full-disk journey as ADR-045 r9 J5
    carries it: J5(a)–(g) (ordinary refusal and recovery, the joiner's words, the leave, the
    pinned flows) and J5(i) (this ADR's arms: SO-2's short-disk arms, SO-11's arms 1–1c,
    SO-12's arms 2, 3, 4, 4d and 5, SO-14's image arms, the fault-dependent ones on the
    `test-knobs` build of that member; J5(h) is withdrawn with RD-7 r14) and the
    stall staging (ADR-045 FG-20, SO-11's arm 1c); the decider confirmed on 2026-11-13 (ledger
    row 59) that both stay blocking as fleet journeys. Arm 1 (refused
    before the OS): fill the image to 40 MB free: `vox
    room post` is refused with `cannot save: the disk holding`; `vox status` is unhealthy with
    those words; the daemon log has no `No space left on device` and no `Previous I/O error`; for
    3 minutes `ls` of the node directory shows no `.failed-*` and no `.rewrite`; meanwhile a
    retention sweep staged by the apparatus (`vox room retention` set to 1 s on a room with 50
    old messages) still runs and the room's `messages_bytes` falls. Free the filler: within 10 s
    `recovered; it can save again`, the held Session entries land, the post succeeds. The
    v0.4.30 red of this arm is the small post succeeding on 40 MB free followed by no refusal in
    words (v0.4.30 has no floor), not `.failed-1`, which belongs to SO-12's arm. Arm 1b (ballast):
    fill the image to zero free while the ballast exists; the staged sweep still runs and
    `messages_bytes` falls (mutant: never release the ballast; the sweep stops, PRODUCT). Arm 1d
    (R4-1, space returns with nothing else happening): after SO-12's arm 2 leaves the store
    reopened but under the floor with a pending re-save and a sync admission parked on
    `StoreRecovery(room)` in ADR-046 R2's admission queue (SY-24; *changed r10: D19, R1's
    `retirement_failed` flows and `lanes.bounded.retiring` no longer exist, SY-19*), the
    apparatus frees the filler and does nothing else, no post, no restart: within 10 s the room
    says `recovered; it can save again`, the pending re-save's entry is in `vox room read`,
    `vox status` shows nothing parked on `StoreRecovery` for the room, and a post then succeeds
    at once (mutant: raise `StoreRecovered` only after a save that itself waits for the event;
    nothing ever recovers, PRODUCT). Arm 1c (items 85/87, RcaSchedStall's journey with the
    reproduced v0.4.30 red; **it is ADR-046 SY-24's journey, in SY-24's one file,
    `a_sync_failure_names_its_reason_proof.rs`, on SY-24's staging — two fill-and-free cycles,
    FG-20 — and this ADR adds no file for it**, D19): A and B in three rooms, A's data on the
    image; the image is filled while B posts 20 times in each room; the image is freed; B
    posts once more in each room; A shows every post within 30 s, `vox status` lists no room
    `no completed sync in 10 minutes` and no `NOT ASKING`; then A ends one room and leaves
    another: both gone from `vox room list` within 60 s (ADR-046 SY-24 owns the scheduler's
    assertions; this ADR owns "the event is raised": mutant: raise `StoreRecovered` only from
    SO-12's reopen path, not from the floor-refused → admitted transition; the parked
    admissions never run and A never shows the posts, PRODUCT). Every failure to
    create or attach the image, and a watchdog whose product precondition was not reached, is
    APPARATUS; a watchdog that fires after the precondition is staged (the image full, the post
    refused) is a PRODUCT liveness red; the macOS run never counts as a pass when the image was
    not attached (`OPTIONAL PROOF NOT RUN` elsewhere, PF-2). Mutant: skip the admission check;
    the log shows the OS error, PRODUCT. Mutant: refuse reclamation under the ordinary floor; the
    sweep arm's bytes do not fall, PRODUCT. Acceptance C23-1.

- **SO-12. When an OS write failure does reach the store, the daemon drains its handles while
  the rooms stay readable, reopens the same file, reclaims on the ballast, and continues; a
  refused reopen is a named, retried state, never a locked node; a reopened store whose disk is
  still under the floor publishes its rooms readable; nothing is copied and nothing is left
  behind.** *(changed r4: R3-1; the decider's answer to Q4; E-2 and E-7 landings)*
  - *Why:* item 23. Today a 64-second loop copies the store onto a full disk. Review F7 and F8: a
    fresh-file replacement needs a full replacement's worth of free disk, which a disk the store
    filled does not have; N4: revision 2 had no transition out of a refused reopen and waited on
    a transaction count that is not the handle count, which is the shape of the 2026-10-21
    outage FX-33 records. Measured on redb 4.3.0 (Context): dropping every handle and reopening
    the same file repairs the latch, deletes then commit, and `compact()` returns pages to the
    disk, all on a 64 MB image with 3 MB free; nothing was measured about a refused open.
  - *The states (the decider, Q4: recover in place, rooms readable, not writable, until done):*
    on `PreviousIo` the store enters:
    1. **Draining.** New write transactions are refused as "cannot save: the store is
       recovering" (an SR-2 state, ADR-040 NW-2's edge). **The atomic read boundary** (E-7,
       below, made this the design): from the instant the latch is seen, every room's lease on
       the latched database is refused, in-flight reads finish their step, every pin is dropped
       (the poisoned room's included, SO-13), the published roots of every room are invalidated,
       and until the reopen the rooms answer from what they hold in memory (ADR-037 R4: the last
       published facts, the Session listing's current page, the room list) and say `preparing`
       for anything else; so every room of the node stays readable from memory throughout, and
       no read ever uses a root the failure may have left ambiguous (reads on the latched
       handle, which the vendored hunk keeps working, are not used after the boundary because
       they can show commits the reopen will not, E-7). Leases are bounded to one step on the
       blocking pool and never held across the network (ADR-044 RD-8); a ruled commit's handle
       is released when its `commit()` returns (RD-7 r14: no flusher exists). The store watches the strong count of its `Arc<Database>` (Terms: drained
       means 1). A holder that outlives 5 s is named in the log and in status (`recovering the
       store: waiting for 1 read started 12 s ago`); after 60 s it is logged as a product defect
       with the lease's owner; the wait continues, visible, with the rooms readable, because
       dropping a live handle is not possible and the alternative (a copy) needs disk the node
       does not have. This is the one place FX-33's outage could recur, and it recurs as a named,
       readable state, not as "the store is read-only" with no cause.
    2. **Reopening.** *(changed r11: ADR-044 RD-7 revision 14, the decider's row 74 — one save,
       one trip; the flusher, tokens, generations, the settlement and its six-fact interface are
       withdrawn, so SO-12 settles no waiter and carries no snapshot, fence or token interface.
       RD-7's words for SO-12: "the one commit in flight was answered `could not be confirmed`
       by its own caller, and every commit queued behind it at the writer fails at
       `begin_write` before writing anything and is answered definitely".)* What SO-12 does, in
       order, and why the order:
       (1) **Reopen and repair, one phase, one open.** If the disk holds under 3 MB the ballast
       is released first (the truncation of a separate file: it touches no store page). The
       last `Arc` is dropped and the same path is opened once; redb's open repairs the
       allocator from the commit slot and commits inside `Database::open` (`db.rs:1658-1670`:
       after `do_repair`, a commit at `last_committed.next()` before the handle is returned).
       What the reopened roots hold was measured (E-7, `e7-fault-injection.log`): a failure at
       a data-page write or at the header write leaves the old roots on a fresh open (50 of
       50); a failure at the final `fsync` after the header leaves the failed commit's rows (51
       of 50); 20 `None` commits followed by a data-write failure of the next `Immediate`
       commit are gone (70 on the latched handle, 50 after); `None` commits followed by a
       post-header `fsync` failure survive with the header that carried them (`durable_commit`,
       `page_manager::commit`). Under RD-7 r14 this changes no answer: the ruled commit whose
       `commit()` failed was told "could not be confirmed" by its own caller at that moment
       (its rows may be on disk, E-7's 51 of 50, and nothing later turns that answer into
       "saved"), every ruled commit queued behind it was refused definitely at `begin_write`,
       and every `None` commit is derived state that state 3 rebuilds. So the recovered roots
       are read by the rebuild and by nobody's verdict. Measured on the E-7 stores, the reopen
       with repair took 8–60 ms. A **refused open** (`DatabaseAlreadyOpen`, another process's
       writable handle or a `test-knobs` lock hold; E-7: refused 11 times at 0.5 s spacing
       while another process held an open, `Error::ProfileBusy`, and opened 0.51 s after the
       release) is retried as today: status says `recovering the store: could not reopen it:
       Database already open; trying again in 5 s`, the open is retried every 5 s, between
       attempts no handle exists, the rooms answer from memory as in state 1, and other nodes
       on the daemon are unaffected (each has its own store). A `Corrupted` error leaves this
       state for SO-9's (the decider's Q5). Nothing loops faster than 5 s and nothing writes a
       second file.
       (2) **One confirming commit, before any write and before any event.** Immediately after
       the open, the recovery owner (the task holding the store's exclusive handle and its
       writer) commits one `Immediate` transaction on the reopened file that changes no row of
       Vox's (redb still writes its allocator state and freed-page record into its system
       tables and the header, `transactions.rs:2083-2146`: a few pages, within the 3 MB the
       ballast release guarantees the reopen); the repair commit inside `open` is never taken
       as this commit. **Why before everything:** it is the one proof that the reopened file
       takes and fsyncs a durable commit — a repair that succeeds is not that proof (E-7: a
       reopen after a post-header `fsync` failure succeeds on a disk that still refuses the
       next write) — and no reclamation batch, no compaction, no room rebuild, no pending
       re-save and no `StoreRecovered(room)` is admitted until it has succeeded, so that a
       writable room is never announced on a file that cannot write. The writer is held by the
       recovery owner from the open until state 3's rebuild has published the rooms; its
       release is the rooms' publication (state 3), after which the next ruled save runs its
       own `Immediate` commit (RD-7 r14).
       (3) **One failure exit before the confirming commit succeeds.** Any native failure
       between the open and the confirming commit's return — the ballast release, the repair
       (ENOSPC or an I/O error inside it), the commit itself — is a new latch and takes one
       exit: the reopened handle is dropped, no root is published, no `StoreRecovered(room)`
       goes out, status names the stage and the error (`recovering the store: could not
       confirm it: <repair | confirming commit>: <the OS error text>; trying again in 5 s`),
       and the store returns to (1) after 5 s. Nothing is settled, re-drained or reclassified:
       no caller waits on recovery (RD-7 r14). A failure **after** the confirming commit (a
       reclamation batch, `compact()`, the ballast rewrite, a room's re-save) is an ordinary
       write failure: the store latches and enters state 1 again, and the maintenance
       operation that failed for space is recorded as deferred **before** the store re-enters
       recovery, so the next state 3 skips it (state 3's deferral rule; R7-1). A ruled save's
       own result is immutable in both directions: no later reopen, recovered row or
       `StoreRecovered(room)` turns a failed `commit()` into "saved", and no later maintenance
       failure turns a succeeded one into anything else (the eighth review's item 3).
       (4) Arm 2 stages the native error; arm 4d the post-header position, the confirming
       commit's failure, the early event and the deferral.
       Room state derived from reads of the latched handle after the last flush is stale after
       the reopen; state 3 rebuilds it.
    3. **Recovering.** *(changed r9: the insufficient-reserve outcome; r11: after the confirming
       commit, no settlement)* With the exclusive handle, after state 2(2)'s commit succeeded: the pending
       reclamation (retention, SO-2 sweeps, room deletions, flow cleanups) runs as reclamation
       batches on the ballast; if the disk is still under the floor and free + ballast holds the
       compaction reserve, `compact()` runs once and returns freed pages to the disk; the
       ballast is rewritten if the disk allows. **When the reserve is not enough** (compaction
       or a reclamation batch fails with `No space left on device` although free + ballast
       held the reserve: a filesystem that charges length, a quota, or a relocation layout
       larger than the E-2 clone's; nothing here is guaranteed beyond what E-2 measured): the
       failed transaction is rolled back by redb (every `compact()` step and every batch is its
       own atomic commit, so the file holds every row it held before, never a partial copy; a
       batch's cursor stays where its last committed batch left it), and **the operation that
       failed is recorded as deferred before the store re-enters recovery** *(changed r10:
       R7-1; revision 9 deferred compaction alone and re-ran a failed batch first)*: an
       in-memory `deferred: {op: compaction | retention(room) | room deletion(room) | flow
       cleanup(room) | sweep(room), baseline, needs}` on the store, set in the latch handler
       before state 1 begins: `baseline` is free + ballast at the failure (the capacity that
       already met the reservation and proved insufficient), and `needs` is a **strictly
       positive** amount more than the baseline — the operation's own reservation again (16 MB
       for compaction, 3 MB for a batch), doubled at each repeated failure of the same
       operation, capped at the store's file length — never the deficit against a reservation
       the capacity already met (that is zero or negative, R8-1). The displayed `n` is `needs`,
       and the operation runs again only when free + ballast ≥ baseline + needs. The store latches and recovers as state 2 says; the next state 3
       skips every deferred operation, runs the rest, and publishes the rooms readable without
       waiting for it: `cannot save: the disk holding <dir> has <m> MB free; <compacting the
       store | removing room <name> | expiring old steps in <name> | cleaning up <name>'s sync
       flows> needs <n> MB more (free that much, in any file, and Vox continues by itself)`;
       `vox status` carries the same line, and a deferred operation runs again, from its
       cursor, only when the floor check sees free + ballast ≥ baseline + `n` (never on a 5 s
       loop, never because recovery re-entered state 3, never while capacity is unchanged at
       or above the original reservation). A daemon restart forgets the deferral
       and tries once more at start, where the same failure defers it again. What is preserved: the whole
       store, readable; what is created: nothing. The way out is the person's: free `n` MB
       anywhere on that disk; no restart, no command. Rooms reopen through their ordinary
       preparation from the reopened store (every in-memory fact rebuilt; nothing carried over
       from the latched handle), readable at once, and the room whose write failed re-saves its
       sealed state in an ordinary transaction (FX-33's re-save, now after the reopen) **if the
       floor admits it**; if the disk is still under the floor after compaction (R3-1: a mostly
       live store returns little), the rooms publish readable as `cannot save: the disk holding
       <dir> has 41 MB free; Vox keeps 64 MB free`, the re-save is the room's pending save, and
       the floor check runs it directly when the floor is met (admission-ready, SO-11) and only
       then raises `StoreRecovered(room)` (R4-1: no event is awaited by the save it must
       follow); no room waits behind a write the disk cannot take. The failed batch's work is
       not acknowledged (SO-11).
    No `.rewrite`, no copy. ADR-038 FX-33 is amended (amendment 3): its outcome "other rooms
    remain writable" cannot hold for one latched store under any design (the latch is
    database-wide, and v0.4.30's copy also stops every room until it completes); what this
    design keeps is "every room stays readable while draining, and other nodes' stores are
    untouched", which the decider accepted on 2026-11-13 as FX-33's replacement.
  - *What E-2 and E-7 landed here (`store-experiments`; the receipts
    `store-exp-receipts/timed-run.log`, `e7-fault-injection.log`,
    `e7-enospc-and-refused-reopen.log`, `e7-release-asset-run3.log`, rewritten verbatim from the
    agent's transcript after `/tmp` was cleared):* **E-2**, measured: `compact()` on the swept
    clone allocates no block above the start and raises the file length transiently by 260 MB;
    it succeeds on a 64 MB image 96% full; so the 16 MB compaction reserve and the 32 MB ballast
    hold in blocks on a sparse-file filesystem (SO-2 step 5 states the condition and what happens
    where file length is charged); the ballast never enters ordinary admission whatever its size
    (SO-11); the rule "the measured peak with a 50% margin" is kept with 16 MB as the figure; the
    repair's peak on a multi-GB latched store was not measured (inferred covered by the same
    condition). **E-7**, measured at the redb level with exact failure points and on the release
    asset: the latch is database-wide and reads survive it (asset: `vox room read` answered 30
    rows while 10 posts were refused with `No space left on device`); dropping every handle and
    opening the same path repairs it (8–60 ms) and deletes, inserts and `compact()` then work on
    a 96%-full disk; a second process's open refuses the reopen as `ProfileBusy` and a 0.5 s
    retry recovers; the common full-disk failure on APFS is a data-page write before the header
    (measured once, old roots everywhere), while a failure at the final `fsync` leaves the
    failed commit's rows on the reopened file, and a data-write failure loses the `None` commits
    staged before it (20 of 20). Consequences applied: the atomic read boundary is state 1's design, not a fallback;
    what the reopened store holds is read from it, never assumed by class (state 2(2)); SO-13's
    inferred sentence is withdrawn; arm 4's apparatus is a writable hold, because a read-only
    open of a file whose live writer left the recovery flag set is refused by redb itself with
    `Database repair aborted` (`page_manager.rs:1611-1616`; every `cp -c` snapshot of the running
    store and `.failed-1` itself were refused that way, measured); the post-header case needs a
    failing `fsync`, which the proof stages as such. Not measured: the product's drain and owner
    graph and the refused-first-open retry (v0.4.30 has no reopen path: CANNOT MEASURE there);
    they are the candidate's arms 4 and 5. On the asset, `store.redb.failed-1` was byte-identical
    to the latched snapshot (741 rows, the same digest) and recovery took 4.0 s: the copy
    v0.4.30 keeps is a copy of the file it replaced, nothing more, which is SO-9's reason.
  - *Not chosen (the decider, Q4):* a reserved fresh-file replacement, which needs a full
    replacement's worth of disk that a store which filled the disk does not have, and a person
    must free that much.
  - *Deleted:* the unconditional retry of the copy every 64 s (`recovery.rs:158` as it applies to
    the copy); `resave_room_after_write_failure`'s rewrite branch.
  - *Proof:* SO-11's journey, arm 2 (the native error, staged without a race): a `test-knobs`
    build (never the installed release) holds alice's daemon between admission and commit of one
    write — one post in one run, one Session admission in the other (ADR-044 RD-7's hold,
    X044-16) — while the apparatus fills the image; the hold is released; the log shows `No
    space left on device` once and `Previous I/O error` never after the reopen; `vox status`
    shows `recovering the store` and then `recovered` within 10 s of space returning. Two
    schedules, named apart *(changed r12: R9-1)*: **the in-flight write**, whose own
    `commit()` errors, is told at once what RD-7 says — a post `cannot save: disk`; a Session
    admission `Unconfirmed` (`session_ingress.rs:831` maps `batch.commit()`'s error so;
    `OwnedAdmission`, `:256-271`, returns bodies only for a definite non-commit; the bridge,
    `vox-tui/src/host.rs:6221-6247`, marks the room and replays nothing) — terminal, never
    replayed by anything, and after recovery the step is present or absent (its bytes may be
    on disk, E-7) and never shown twice. **A separate Session admission queued behind the
    failing write** (the apparatus sends a second step while the hold stands) fails at
    `begin_write` before writing anything, is told `NotCommitted{bodies}` at once, and it is
    this one whose bodies the bridge retries after `StoreRecovered(room)` and whose step then
    lands exactly once. A second room on the same node answers `vox room read` throughout,
    `ls` shows no `.failed-*` at any time and no `.rewrite`. v0.4.30 is red here: `.failed-1`
    appears and `recovery could not complete its retained save` repeats (RcaPreparing P3,
    `enospc-room.log`). Arm 3 (no space returns): with the image still full, the reopen runs on
    the released ballast, a staged retention sweep runs and `compact()` returns space; the room
    saves again without any filler removed. Arm 4 (refused reopen): the apparatus, a
    `test-knobs` lock hold in the close/open gap or a second process's **writable** open of the
    store file (E-7: a read-only open of a file the latched writer closed is refused by redb with
    `Database repair aborted`, so it cannot stage this), across the reopen; status says `could
    not reopen it: Database already open … trying again in 5 s`; the apparatus closes it; the
    node recovers within 10 s (E-7 at the redb level: 0.51 s after the release); a second room
    on the node reads from memory throughout the draining state and answers `preparing` for
    what it does not hold, never "the store is read-only" with no cause. Arm 4d (the
    post-header position and the confirming commit; arms 4b and 4c of revisions 6–10 are
    withdrawn with ADR-044 RD-7 r14, review record; on the `test-knobs`
    member in the macOS guest, alice with two rooms R1 and R2; no v0.4.30 baseline, CANNOT
    MEASURE: the asset has no fault knobs): the fault is a `test-knobs` injected `fsync`
    failure in one ruled commit, placed after the primary header write
    (`page_manager.rs:1838-1850`) at the final `storage.flush()` (`:1856`). The unflushed
    suffix is **received, non-ruled content**: after the fixture's last ruled commit (a
    Session step alice's room admits, which flushes itself, `session_ingress.rs:539, 805-831`,
    and is asserted apart through `vox room session`), bob's five received entries are
    admitted at `None` in R1 with no Inventory acknowledgement or other ruled commit in
    between (the apparatus holds the Inventory; *changed r12: R9-2, a Session step is a ruled
    commit under RD-7 r14 and cannot be the suffix*), then `vox room leave R2` is issued while
    draining (R2's deletion queued as pending reclamation). Act 1: alice's
    post hits the fault → `cannot save: disk`, exit non-zero, at once from its own commit
    (RD-7's assertion; a second post queued behind it is refused definitely at once, RD-7's
    arm two) → latch → one reopen → the confirming commit → reclamation (R2's deletion) → the
    rooms rebuilt from the reopened store → `StoreRecovered(R1)`; asserted: the log orders
    `recovery: confirmed` → the first reclamation batch → `StoreRecovered`; `vox room read
    R1` after recovery and after a restart shows bob's five entries (the `None` commits the
    failed commit's header carried, E-7's 51 of 50), `vox room session` shows the step, and
    the read shows alice's post **or not**; either way her command's answer was failure, and
    nothing later reports it saved (RD-7 r14: immutable). Act 1-pre (the pre-header position,
    the product act of the former arm 4c's mutant): the same suffix on a populated root (many
    redb commits before this daemon's start), the fault at a data-page write of alice's commit
    → her post fails at once. Two phases, named apart (*changed r13: R10-3*): **loss
    observation** — the fence is on **alice's received-admission boundary for the five
    target positions** (*changed r14: R11-1*): a `test-knobs` hold `VOX_TEST_HOLD_RECEIVED=
    <room>:<author>:<from>-<to>` on alice's daemon parks every repair admission of those
    coordinates at the point `stage`/`start_entry` (`history_stream/admission.rs:52, 681` at
    the tag; R2's received-admission step) would write them, whatever brought them in — a
    `Range`/`Entry` answer already in flight, one derived from a cached `Have` hint or head
    (SY-14), or one triggered by a new advertisement — holding no database lease, no writer
    and no room lock (the answer's permit is released; the parked admission is retried after
    the hold, SY-15); holding bob's `Have` answers may be added as staging but is not the
    fence. It is engaged before the fault and logs `test knob: received admission held
    (R1, bob, 10-14)` (absent → APPARATUS), and stays engaged through the first
    post-recovery `vox room read R1`, which lacks bob's five entries (E-7: 70 → 50), a
    restart, and a second read, which agrees; the log shows no `admitted` line for those
    coordinates in that phase (one → APPARATUS: the fence did not hold); **repair** — the
    hold is released, bob's normal SY-15 catch-up re-admits the five, they show within 30 s,
    and a further restart and read agree. The stale-rebuild mutant (below) is judged inside
    the loss-observation phase. Act 1-floor: the same with the image under the floor after compaction: no
    `StoreRecovered(R1)` until space returns, the rooms readable meanwhile with SR-2's line.
    Act 2: the same staging, and the reopened store's confirming commit (the knob counts
    `Immediate` commits after the open; the log names `recovery: confirming commit failed:
    <error>`) also faulted → status says `could not confirm it: confirming commit`, no
    `StoreRecovered(room)`, no reclamation batch runs, the next reopen's commit succeeds and
    recovery completes; alice's first post is still reported failed and never saved by any
    surface. Act 2-repair: the fault inside redb's repair commit (`db.rs:1660-1668`, its own
    knob) → status `could not confirm it: repair`, the same exit, the next reopen succeeds.
    Act 2-compact: after a successful confirming commit, `compact()` faulted with `No space
    left on device` **while free + ballast is at or above the 16 MB reservation** (the knob
    faults the write; the image is not short) → the rooms readable, status carries the
    deferral line naming `compacting the store` and `n` = 16 MB (the fixture's store is over
    16 MB — the apparatus posts bodies to that length — so the file-length cap does not reduce
    it; the act asserts the printed `n` and frees that amount); with capacity unchanged for
    30 s the log shows exactly one compaction attempt and no further reopen; then the
    apparatus frees `n` MB beyond the baseline and compaction continues by itself. Act
    2-reclaim (R7-1): the same with the fault in R2's deletion batch, capacity at or above
    the batch's 3 MB → the rooms publish readable with the line naming `removing room R2` and
    `n` = 3 MB, R2's cursor unchanged, no second attempt and no reopen for 30 s, then the
    apparatus frees `n` beyond the baseline and the deletion resumes from the cursor to
    `RoomRowsPurged(R2)` (mutant: compute `n` as the deficit against the reservation → it is
    0, the batch re-runs at once and the reopen loop shows within 30 s, PRODUCT). Mutants: raise
    `StoreRecovered(room)` from the repair commit, before the confirming commit (R7-4, judged
    at the boundary it breaks) → in act 2 the log shows `StoreRecovered` before `recovery:
    confirmed`, status drops `recovering the store` while the confirming commit has failed,
    and a consumer parked on `StoreRecovery(R1)` (ADR-040 NW-1's row: a received-entry
    admission parked in R2's admission queue, SY-24 — not a fresh post, which RD-7 refuses
    definitely while draining) is released into a room that then answers `cannot save`,
    PRODUCT;
    run reclamation before the confirming commit → in act 2 R2's deletion batch runs on a
    file whose next write fails, the log shows a reclamation batch before `recovery:
    confirmed`, PRODUCT (the batch preceding confirmation is the red, whether or not it hits
    the fault); postpone the failed post's answer until recovery has consulted the reopened
    rows (the "recovered row turns failure into success" mutant, r12: R9-5): with recovery
    held by a `test-knobs` hold after the fault and before the reopen, the product has already
    returned the post's non-zero `cannot save: disk` while the hold stands, and releasing the
    hold produces no second terminal answer; the mutant's command is still running at the
    hold, PRODUCT (no per-post status surface exists, `api.rs::NodeView`, and none is added);
    route only the confirming commit's failure to the exit → act 2-repair's repair fault is
    retried as a refused open (`could not reopen it`) and never names the stage, PRODUCT;
    drop the deferral (R7-1) → act 2-reclaim shows a second attempt and a reopen within 30 s
    with no capacity change, PRODUCT. Rebuild from the latched handle's captured result
    instead of the reopened store (act 1-pre's mutant; the stale material is a captured read,
    never a live handle that would block the drain) → inside act 1-pre's loss-observation
    phase, with the received-admission fence still engaged, `vox room read` shows bob's
    entries while the restart does not, PRODUCT. APPARATUS: fault not fired; reopen not reached; the queued deletion not engaged. Arm 5
    (leaked holder): a `test-knobs` hold keeps one lease open past 60 s; status
    names it and the second room reads throughout; the hold is released; recovery completes.
    Failure to stage the hold, the fill or the second open is APPARATUS. Mutant: restore
    `retain_original`; `.failed-1` appears, PRODUCT. Mutant: skip the drain and reopen with a
    lease open; redb refuses the open, and without arm 4's retry the room stays read-only,
    PRODUCT (FX-33's recorded outage, reproduced on purpose). Mutant: give up after one refused
    open; arm 4 never recovers, PRODUCT. Acceptance C23-2.

- **SO-13. A room that cannot save holds no read snapshot while it waits.** Reads in that state
  open a committed snapshot per turn, like every other read (ADR-038 FX-22's rule for derived
  indexes: "no snapshot, row vector, or page survives a caller's bounded turn"). *(changed r6:
  E-7)*
  - *Why:* item 21. A held snapshot stops redb reusing freed pages; a 7-second poison grew a
    scratch file from 12.6 to 50 MB (RcaChurn C2). SO-12's drain cannot complete while a room
    pins one.
  - *What changes:* the poisoned branch of `read_resource.rs:446-455` drops the pinned resource
    instead of refreshing it. The code's reason for the pin is "A definitive failed write cannot
    certify whatever roots redb exposes after its error" (`:447-449`), and E-7 showed that
    reason real (measured, `e7-fault-injection.log`): a fresh open after a failure that reached
    the header swap answers the failed commit's roots, while a failure before it answers the old
    ones, so which commits a fresh read shows depends on the failure's position and is known
    only from the recovered roots (SO-12 state 2); revision 5's inferred "the committed roots are
    the last successful commit's" is withdrawn.
    The pin is therefore not replaced by fresh reads of the latched database but by SO-12
    state 1's atomic read boundary: no disk read of the latched store after the boundary,
    published roots invalidated, rooms answering from memory until the reopen rebuilds them.
    The pin's removal lands with that boundary.
  - *Deleted:* the retained pin (`refresh_pinned_authority` on the poisoned path) and
    `recovery.rs:75-76`'s reliance on "its committed read pin".
  - *Proof:* none by test. No journey a person can see isolates it: a full disk cannot grow, and
    other poisons need a knob the shipped binary does not have. It rests on review and spike E-7
    (spike **S-13**, formerly misnamed E-7: RcaChurn's `pin.py` recipe — a 7-second poison with
    a held read pin while posts continue, `rca-RcaChurn` §"pin" — re-run on a build with SO-13;
    the script was under `/tmp` and is lost in the reboot of 2026-11-13, the recipe and the
    12.6 → 50 MB figure are recorded in `rca-RcaChurn`; D20), reported in
    the pull request (ADR-018).

- **SO-14. A joiner is never told that the member's own failure is the joiner's fault.**
  *(changed)*
  - *Why:* item 24. Review F15: the first draft changed the producer only.
  - *What changes:* a new refusal `JoinReject::Unavailable` (wire code 8; `joinstream.rs` encode,
    decode, `as_str`). The member sends it (1) before the exchange, when its store is below the
    floor or cannot save, through `refuse_join_as` as it sends `Busy` (`joinstream.rs:1279-1281`);
    and (2) for `Error::Storage`, `Error::Io` and `Error::Path` **in the admission rejection
    match itself** (`:1403-1412`, the arm that today reads `_ => NotAdmitted`; an inner
    admission failure sends its frame and returns before the outer error branch is reached)
    and in `run_responder`'s outer error arm (`:1448-1455`) alike (r11: R8-4). The joiner handles it at both
    receiving boundaries: the first-frame dispatch (`:998-1009`) sets it apart before it expects
    a challenge, and `rejected()` (`:712-718`) maps it to a typed `Error::JoinMemberUnavailable`,
    never to `JoinRefused`. The wire carries one byte and no detail: the joiner prints ADR-042's
    words (Appendix D's row for item 24, r10: the contradictions table; ADR-042's `: no space
    left on device` tail cannot be printed, since the wire carries no detail — the member's own
    status has it — and ADR-042 is to drop that tail, Sibling ADRs):
    ```
    vox: cannot join repo-to-cve: the member could not write the join to its store
           try again later, or join through another member
    ```
    and the member logs the detail (`could not record the join: the disk holding <dir> has 41 MB
    free`) and shows it in its own status. *Security:* (1) depends on nothing the joiner sent.
    (2) can follow the passphrase check; it then tells the joiner what `NotAdmitted` already
    tells it after acceptance, and a stranger cannot make a member's disk fail. ADR-005 J-17 is
    amended to name it.
  - *Proof:* extend `a_join_to_a_full_room_is_refused_proof.rs`'s
    `a_join_a_member_cannot_admit_says_why` (line 189). Blocking arm (no image) *(changed r10:
    D13)*: the existing knob `VOX_TEST_ADMISSION_FAILS` raises `Error::Profile("locked")`
    (`roster_save.rs:207-213`), which `run_responder` answers `NotAdmitted`
    (`joinstream.rs:1400-1412`) and the `:212` assertion reads as `a member accepted your
    passphrase, then could not admit you`; that is a locked node, not a storage failure, and it
    stays as it is. This arm adds a second knob, `VOX_TEST_ADMISSION_STORAGE_FAILS=<os error>`
    (`test-knobs`, never in the installed asset), which makes the same admission write return
    `Error::Storage{op: "admit", detail: <os error>}`, the error a full disk produces at that
    write, in two placements: in the admission arm (after the passphrase check; SO-14 (2)) and
    before the passphrase check (`refuse_join_as`'s path; SO-14 (1)). In both the joiner's
    `vox room join` exits non-zero within 5 s, says `could not write the join to its store`, and
    never `passphrase` or `expected challenge`; after the knob is cleared the same command
    joins. v0.4.30's baseline, traced through the consumer that receives the frame (r11:
    R8-4): admission runs only after `AdmissionPrepared` (`joinstream.rs:1394-1416`); a storage
    error there takes the same `_ => NotAdmitted` arm as the locked profile (`:1411`), the
    joiner is then in its ACCEPTED dispatcher, which calls `rejected(r)` (`:1214`), and
    `rejected` maps `NotAdmitted` to `Error::JoinNotAdmitted` (`:715`): the tag prints `a
    member accepted your passphrase, then could not admit you`, exactly what the existing
    `:212` assertion reads, **not** the passphrase sentence. So on the admission placement
    v0.4.30 is not red on the passphrase words; it is red on the new `Unavailable` words
    (`could not write the join to its store`), which it cannot print. The passphrase sentence
    is the tag's result only for an **exchange-stage** error, routed by `:1448-1455` to the
    coarse `Refused`; a pre-challenge refusal is a third placement (arm (a)). Both knob
    placements and the `Unavailable` assertions stand; the `:212` assertion stays as it is.
    Optional arms on SO-11's image (`optional-proofs`, the decider's Q7; blocking on the fleet,
    ADR-045 J5): (a) the member's store below the floor before the join (the early
    `refuse_join_as` path); (b) the member's store failing inside the exchange (the test-knobs
    hold of SO-12's arm). v0.4.30 on arm (b), an exchange-stage failure on the asset: `usually
    the room passphrase is wrong` (the coarse `Refused`), red; on the blocking arm's admission
    placement, `then could not admit you`, red on the new words only; the blocking arm has no
    v0.4.30 run (the knob does not exist at the tag). Mutant: map storage errors back to `Refused`; the passphrase sentence appears,
    PRODUCT. Mutant: leave the first-frame dispatch unchanged; arm (a) prints `expected
    challenge`, PRODUCT (optional arm; on the fleet it blocks). Acceptance C24-1.

### 5. A person can see what is stored

- **SO-15. `vox status` shows, per node, the store's file length, disk use, in-use, data and
  packed bytes, the disk's free space and the floor; per room, its data split into messages,
  Session steps, lifecycle records, indexes, keys and transient sync records; the figures are
  seeded from the store at first start and reconcile to redb's own totals; and the store's
  growth is a measured rate with a stated bound.** *(changed r3: N10, N11; the decider's gate
  ruling)*
  - *Why:* item 25. The operator needed `ls` and a redb parser. Review F16: a ledger by segment
    kind cannot see sync records inside EntryIndex, and an unseeded ledger reads zero. N11: a
    durable evidence row must not be counted as a transient sync record, or the zero oracle
    rejects the design. The decider (2026-11-13): the gate fits 8–10 hours; slow growth is judged
    by a measured rate.
  - *What changes:*
    - A ledger per `(room, class)` of data bytes (serialized key + value, as redb stores them)
      and packed bytes (Terms), kept in `meta` and adjusted in the same batch as every put,
      replace and delete. The class is assigned by the writer that knows it: the sparse-object
      writer (`save_history_object`, `sparse.rs:2539`'s path) classes EntryIndex rows by
      `ObjectKind` into `sync` (**request, proof and cursor bookkeeping only**: ProofRange,
      Verifier, the live window and every receipt a v0.4.30 store still holds until SO-2
      deletes them; nothing that SO-1 lists as kept and nothing that is a person's content),
      `index` (contexts, the kept heads, headers, locators, interval descriptors and tree
      pages, and ADR-046 SY-18 r7's kept facts: the anchor and `control_through`, each
      recorded removal cut, and a **gapped continuation**'s signed head and up to 128 pushed
      headers, which are headers held for the bridge proof and not a fetch's bookkeeping;
      and the room's **baseline** object — ADR-046 r10 SY-27: the creator's fence-post
      summary, one answer of at most 1 MiB **encoded, framing included** (ADR-046 r11's
      limit on the answer's bytes, not on a stored row), installed in one transaction, keyed
      by `H`; stored, it is one sealed row — CBOR `[version, nonce, ciphertext]` with the AEAD
      tag (`atrest/store.rs:219-226`) plus its key and redb's leaf header and length slots
      (`btree_base.rs:1102-1119`) — charged by SO-15's complete-sealed-row rule: a summary at
      the limit does not fit a 1 MiB leaf and takes a **2 MiB** allocation plus its index
      path, which `index_bytes` and the in-use bound count, and E-3's calibration includes a
      near-limit summary (*changed r13: R10-2; revision 12's "at most 1 MiB of `index` per
      room" was the payload, not the allocation*); the previous baseline's bytes go in the same
      transaction that installs the newer, as SY-27 says (one bounded write, within SO-11's
      ordinary admission; no chunks, no assembly, no staged state, nothing for a sweep to
      reclaim; *changed r12: ledger row 77*) — `index` as SY-18 classes it), `messages` for a
      **staged partial body** (R3-7:
      an entry-owned, authenticated prefix that ADR-046 SY-18 keeps across restart until
      completion, expiry or an audience change; it is retained content, shown in the room's
      `messages_bytes` and in a `staged_bytes` sub-figure, and moves to the entry's bytes when
      the body completes, in the completing commit); PrivateSession and PrivateSignature rows
      are `steps` or `lifecycle` by the record's kind; LogDb, PlaintextCache and first-seen rows
      `messages`; SessionIndex, GovernanceIndex and SessionAttention `index`; key material
      `keys`. Node-wide rows (`meta`, `sek_wraps`, trust, prekeys, redb's own metadata from
      `stats()`) are shown as `node`. `sync_bytes` is therefore 0 on any node with no fetch
      running, whether or not a partial body waits for a holder or a gapped continuation is
      held (both are `index`/`messages`, above); the receipts a v0.4.30 store holds are `sync`
      until SO-2 deletes them. Where ADR-046 SY-18 names a class for one of its kept facts,
      SY-18's naming is the rule and this list follows it. Transitions: a row's
      class is fixed by its kind at put; the seed walk classes by the same rule; a delete
      subtracts from the class the row was put under.
    - Seeding: at SO-2 step 6(a) (and whenever `meta.ledger_seeded` is absent) a room's ledger is
      rebuilt by one walk of its rows, after the sweep, and the marker written in the same commit
      as the last batch of the walk; until then the room's figures read `counting`. A room's
      ledger rows are deleted with the room, last.
    - In-use, file length and disk use from redb's `stats()` and `stat` (length, blocks), computed
      off the actor at most once per maintenance tick and kept in the report (the sample is
      also what the proof reads as `store.redb`). The cost of `stats()` on a multi-GB store is
      UNKNOWN: spike E-8 was to time it on the 3 GB clone, which is gone (receipt lost in the
      reboot of 2026-11-13; figure recorded in none, the spike had not run; to be re-run as the
      fleet baseline on ADR-045's grower snapshot, V431-045-15, the store SO-2 (iv) also uses);
      if a sample takes over 100 ms, the tick keeps the last sample and takes a new one at
      most once a minute, and `vox status` says `sampled <n> s ago` beside the figures; the
      figures' meaning does not change (D9).
    - `vox status --json`: `store: {file_bytes, file_disk_bytes, in_use_bytes, data_bytes,
      packed_bytes, free_disk_bytes, floor_bytes, ballast_bytes, file_bytes_at_start,
      in_use_bytes_at_start, growth_per_hour_bytes, last_rewrite: {at, from_file_bytes,
      to_file_bytes, to_disk_bytes, seconds, kind: "rewrite" | "compact"} | null, rewrite_due:
      null | "<reason>"}` and `rooms[].store: {messages_bytes, steps_bytes, lifecycle_bytes,
      index_bytes, key_bytes, sync_bytes}`. The file, at-start and per-hour figures are ADR-042's
      `store_growth` (its Appendix B); `growth_per_hour_bytes` is of in-use bytes, the figure
      that does not move in steps.
    - Text, in the node block and in each room block of ADR-042 TR-2 (ADR-042 owns the layout),
      file length and disk use always both:
      ```
      store: 1.08 GB file (0.84 GB of disk), 0.84 GB in use, 0.61 GB of data; disk: 193 GB free (Vox stops saving below 64 MB)
        last rewrite 2026-11-14 03:12Z: 3.01 GB file → 1.08 GB file (0.84 GB of disk) in 8 s
      ```
      ```
          messages: forever; Session steps: 2 days
          stored here: 190 MB — messages 35 MB, Session steps 86 MB, openings and ends 6 MB, indexes 58 MB, keys 1 MB, sync records 0 B
      ```
  - *The growth bound (what the proofs assert and project; R3-6 and R4-4: counts, bytes and
    page rounding):* with no new content, in-use bytes change by at most 256 KB over any 10
    minutes of sync rounds and the file length not at all (ADR-046 SY-8: a round that brings
    nothing writes nothing). With content, in-use bytes (allocated pages, not row bytes) grow by
    at most the sum over the rows the content creates of each row's **allocation**: a row of
    2,048 B or less costs its bytes at 93% fill (the small table), a larger row its power-of-two
    page (4, 8, 16, 32, 64, 128 KB and upward; SO-5 keeps that rounding), the row being the
    **complete sealed row** (its fixed bytes plus the body plus the seal) with redb's key and
    leaf overhead, plus 15 KB of entry index per entry and about 1 KB of index per step, plus
    4 KB per head advance per author. The rows an entry creates: the log row (7.2 KB of fixed
    part with its two signatures plus the body, encrypted), the rendered cache row (0.5 KB plus
    the body) and the first-seen row; a step creates its record row (0.3 KB plus the body) and
    its 3.4 KB signature row (one 4 KB page). So a 325-B message costs about 24 KB (an 8 KB log
    page, a packed cache row, 15 KB of index), a step with a 349-B body about 5.3 KB, a 40 KiB
    step 64 KB + 4 KB + 1 KB = 69 KB (a 64 KB page for the record, the signature's page, the
    index), and a 64 KiB message **128 KB + 128 KB + 15 KB = 271 KB** (R5-4: a 65,536-B body
    makes a 72.7 KB log row and a 66 KB cache row, each over 64 KB, each a 128 KB leaf). The
    gate asserts the bound with its denominators: the entry and step counts and each body's
    bytes from the run record, rounded by this rule; the calibration run (E-3) includes a
    40 KiB step and a 64 KiB message and checks the rule against the allocations it observes. A
    train of such content is legal and within the bound, not a regression; nothing is capped,
    split away or refused to meet it.
    The linear figures below are the projection for the operator's workload, not the gate:
    for omp-work's observed rates (360 entries and 1,712 steps per 2 hours in repo-to-cve,
    325-B messages, 349-B median steps) at most 104 MB + 110 MB a day of new data before
    expiry, against the measured 320 MB an hour of v0.4.30; after two days the step population
    is steady and the growth is the messages' alone. Two rates are on record and both are
    stated: the sampled burst (1,712 steps per 2 hours in repo-to-cve, 20,500 a day) gives a
    2-day population of about 41,000 steps and 220 MB of disk for that room; the 7-day average
    (39,547 steps on the node, 5,650 a day) gives about 11,300 steps and 86 MB, the figure
    Appendix B uses. The gate measures the rate over 30 minutes on the fleet's load (ADR-045
    J3's run record carries `growth_per_hour_bytes`, the counts and the body bytes) and projects
    it; a rate above the bound is a red naming the class that grew.
  - *Proof:* extend `vox_status_shows_the_node_proof.rs`: the file bytes equal `stat` of
    `store.redb`'s length and the disk bytes its blocks; free disk is within 2% of `df`; the
    rooms' figures plus `node` add up to redb's `stored_bytes` within 1% — read from `vox
    status --json`'s `store.redb: {stored_bytes, allocated_pages, leaf_pages, branch_pages}`,
    the `stats()` sample SO-15 already takes each maintenance tick (D8: no second process can
    open a running node's store, E-7) — on a fresh store, on a store seeded by the v0.4.30
    asset after its first v0.4.31 start (SO-2's arm), and after a restart; a sample taken while a room is changing is retaken once before it is judged (a
    moving store is not a product fault). Growth arm (in SO-1's journey, after the newcomer has
    read everything): 10 minutes of sync rounds with no new content change `in_use_bytes` by at
    most 256 KB and `file_bytes` by 0; then 50 posts and 100 steps grow `in_use_bytes` by at most
    50 × 24 KB + 100 × 6 KB + 256 KB. v0.4.30 is red on the quiet arm, observed: `du` of a
    receiving node's directory grows by at least 14 × 4 KB per entry fetched and keeps growing
    through abandoned fetches (RcaChurn `runs/direct2`, `runs/relay75`). Mutant: report the
    ledger's sum as the file size; the `stat` comparison goes red, PRODUCT. Mutant: skip the seed
    walk; the seeded store's figures read 0 against a non-zero `stored_bytes`, PRODUCT. Mutant:
    class the kept heads as `sync`; `sync_bytes` is above 0 with no fetch running, PRODUCT.
    Acceptance C25-1.

### Alternatives rejected

- **Bound the proof-record cache** (least recently used, N heads per author). Keeps a write per
  verification. The decider: "no need to keep anything like this". Precedent for keeping nothing:
  Certificate Transparency logs compute inclusion and consistency proofs from the tree on request
  and keep nothing per client head (RFC 6962 §2.1); Trillian keeps only the compact range along
  the right edge per tree size.
- **Keep the three reconstruction refusals and let a cold node say "not held".** The first
  draft's design. It loses serving of a frozen author's branch from every restarted holder at
  once (review F1). The refusals guarded a store that acceptance could read back; with nothing
  written there is nothing to guard.
- **Convert stored v2 private records to v3 at first start.** Needs a new identity for every
  stored record and a resumable re-keying of the private index, the projection's sources, the
  attention boundaries and the locators peers pull by; one defect there loses a person's Session
  history. Reading v2 beside v3 costs one enum variant and a few MB of lifecycle records; the
  steps expire by themselves in two days (SO-8).
- **Keep a clear copy of every step's body as a render cache.** Revision 2's choice, on the
  false premise that the key was gone; the key is kept per generation and the generation is at
  most 1,000 messages (C-22). The copy is 55 MB of derivable bytes on the operator's store; its
  only value is render latency, which E-10 measures and the proof bounds (SO-4).
- **Prune heads by age and keep the per-entry source tie.** Revision 2's design; the reader
  followed the tie to a pruned head (N1). Binding a held position to the newest accepted head is
  correct on one chain and needs no per-entry rebind.
- **Discover projection changes by comparing ids or generations.** Misses an in-place re-save
  (N2); a change queue written in the input's own commit cannot.
- **Reclamation under a lower free-space floor without a reserve.** Revision 2's design; on a
  disk another process filled to zero it refused its own deletes (N3). A written ballast file is
  space nobody else can take.
- **Wait for the transaction count to reach zero before reopening.** Not the handle count (N4);
  the `Arc` count is, and it is what `compact()` already requires.
- **Patch redb's two leaf rules** (route an ascending key into the left leaf; allow merging past a
  single large value). Fixes every table, but takes the vendored copy further from upstream (one
  hunk today). The table split removes the trigger whatever redb does; the defect is reported
  upstream. Precedent for keeping large values out of small-row pages: WiscKey (Lu et al.,
  FAST '16) and BadgerDB's value threshold, RocksDB BlobDB (`min_blob_size`), SQLite and LMDB
  overflow pages.
- **Split large values into 4 KB chunks** to beat the power-of-two rounding (215 MB here). Real
  saving, real complexity in every get and put; not taken for this release; the figure is in
  status so the decider can ask for it later.
- **Bigger base page** (`set_page_size` 16 KB). Packs 4.5 KB rows three to a leaf but makes every
  small-row leaf 16 KB. Helps only together with separation.
- **Compaction as the fix.** It returns free pages only and needs the only handle. A rewrite
  returns slack too but runs again as long as the inputs grow. The decider's order puts it last.
  Precedent: etcd `defrag` and SQLite `incremental_vacuum` are operator or threshold actions; LMDB
  never shrinks in place.
- **Keep the Session view a full rebuild and make it cheaper.** Linear in candidates at every
  change whatever the constant.
- **Fold Session inputs in arrival order.** Plan C's and the first draft's design; the lifecycle
  transition is not commutative (an opening after an end opens a new row), so two nodes
  diverge (review F2). The per-Session ordered re-fold keeps the full fold's property at a cost
  bounded by the Session.
- **Re-fold a Session's name events too.** Thousands per Session (N6); the shown name is a
  maximum by position, which needs no re-fold.
- **A MAC for steps.** The AEAD tag already is one; it lets any reader forge steps to other
  readers.
- **Disk full: quota and refusal before the error** is the chosen floor (SO-11). Precedent: etcd's
  `--quota-backend-bytes` and NOSPACE alarm (reads and deletes only until space returns); Postgres
  on a full disk fails the commit, stays up and copies nothing; SQLite's `SQLITE_FULL` rolls back
  and keeps the connection, with `max_page_count` as the quota.
- **Disk full: a fresh-file replacement started "when some space returns".** Needs a whole
  replacement's worth of disk that a store which filled the disk does not have; kept only as Q4
  (b) with its true figure.
- **Disk full: map storage errors to `NotAdmitted`.** Says "accepted" when the failure came before
  the passphrase check. A separate reason is what TLS (`internal_error` apart from
  `bad_record_mac`) and SSH (`SERVICE_NOT_AVAILABLE` apart from authentication failure) do.
- **A drive-state blob per step, made smaller.** Signal's session store writes the one session's
  record per message, not the whole store; SO-7 is the same split, per chain.

## Unchanged rulings

- ADR-010 AR-27–AR-34: retention by time, shortest wins, applied retroactively, honoured by
  clients. AR-18 (what plaintext caches exist stay sealed; SO-4 keeps metadata only) and AR-20
  (an advance commits with its row).
- ADR-031 SA-7 (steps only with drive), SA-8 (forward from the join: the history floor is the
  grant point, and SO-4's on-demand opening starts there), SA-9 (step retention, 7 days by
  default, set by the room's admin, respected as set).
- ADR-006 S-6 (sender-key rotation after 1,000 messages or 7 days), S-10 (the live path's
  consumed keys deleted; the retained history key per generation is unchanged), S-12 (chain
  state persisted); S-8 for room messages unchanged; for private records see amendment 5 (Q2).
- ADR-003 H1 and H3: every signature that exists is composite.
- ADR-008: a room message keeps its two signatures, which have different structural roles (LS-5,
  LS-8 and ADR-006 S-8); not put to the decider; Main lists it for him.
- ADR-038 FX-22 (the governance projection) and FX-32 (own-history recovery after a restore):
  unchanged; FX-32 is now met by reconstruction over own headers, not by a cache.
- ADR-038 FX-30 and FX-31: the ruled set is durable before its command returns.
- ADR-034 SR-1–SR-5: a room that cannot save recovers by itself, says so with the OS words, and
  holds Session entries. FR-8: no caps on a person's data (the decider's Q1: no budget).
- ADR-036 H-7's in-memory bound for proof objects (ADR-044 RD-9's cache).
- ADR-044 RD-1 and RD-2: no post waits behind a store rewrite in a running daemon, except the one
  a person starts with `vox node compact` (SO-10; the decider's Q8).
- v0.4.x keeps no prior-release compatibility; no real data is deleted (AGENTS.md). Proof
  records, receipts, cursors and retained store copies are not a person's data; a person's
  Session records, openings and ends are, and none is touched by any stage here.

## Superseded and amended lines

Main applies these after the decider signs. Each quotes the current text exactly.

1. **ADR-036** (`docs/adr/ADR-036-live-messages-and-requested-history.md:762`). Current:
   > - content-addressed head, context and proof objects, plus `(author, tree range) -> descriptor`;

   Replacement: "- content-addressed head and context objects, plus `(author, tree range) ->
   descriptor` for accepted ranges only; no verified range is kept per head, for verifying or for
   serving: a served range is derived from the leaves' headers when asked (ADR-047 SO-1);"
2. **ADR-038 FX-29** (`docs/adr/ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:562-565`).
   Current:
   > and a verifier
   >   persists its progress once per proof verified to its end (an inclusion proof or a
   >   control range), never once per Merkle join, since a proof is bounded and is verified again
   >   from its bytes after a crash.

   Replacement (ADR-046 R1): "and a verifier persists its progress once per proof verified to its
   end (an inclusion proof or a control range), never once per Merkle join, since a proof is
   bounded and is verified again from its bytes after a crash; that progress is deleted in the
   commit that ends its fetch, however the fetch ends (ADR-047 SO-3)." Replacement (ADR-046 R2):
   "and a verifier persists no progress: a proof is verified in memory and dropped, and what is
   still wanted is derived again after a crash (ADR-046 SY-14, SY-18; ADR-047 SO-3)."
3. **ADR-038 FX-33** (the decider's Q4) (`ADR-038-…md:684-686`). Current:
   > Decision: the recovery
   >   re-saves the room's sealed state in an ordinary write transaction on the store as it is
   >   open, never by closing and reopening the node's store file;

   Replacement: "Decision: the recovery re-saves the room's sealed state in an ordinary write
   transaction on the store as it is open; only when redb has latched an OS write failure does
   the daemon reopen the same store file, after every holder of the database has dropped it (its
   `Arc` count is 1), with any holder that outlives 5 s named in status and every room readable
   while it waits; a refused reopen is named with its error and retried every 5 s; the re-save
   follows the reopen (ADR-047 SO-12). The outcome 'other rooms remain writable' is replaced by
   'every room of the node stays readable while the store drains, and other nodes' stores are
   untouched': no design keeps a latched store writable for any room. The outage of 2026-10-21
   was a refused reopen with no retry and no readable state; both now exist."
4. **ADR-031 SA-7** (`docs/adr/ADR-031-agent-nodes-join-a-repo-room-by-themselves.md:261-262`).
   Current:
   > earlier-release stored steps is out of v0.4.5 scope (SA-5); current-version authorization is
   >   unchanged.

   Replacement: the same, followed by: "A private record MUST carry exactly one composite
   signature, by the author's root key (the decider, 2026-11-13); a stored record keeps the
   format it was written in and its identity (ADR-047 SO-4)."
5. **ADR-006 S-8** (the decider's Q2) (`docs/adr/ADR-006-group-messaging-sender-keys.md:55-57`).
   Current:
   > - **S-8.** A message header MUST be `{channelID, epoch, author_id, chain_id, iteration}`, bound as AEAD
   >   associated data `vox/group-msg-ad/v1 ‖ cbor[cid, epoch, author_id, chain_id, iteration]`; the
   >   ciphertext MUST be Sender-Key-signed under `vox/group-msg/v1`.

   Replacement: the same, followed by: "A private Session record (ADR-031 SA-7) is the exception:
   its ciphertext is not Sender-Key-signed; the author's root key signs `[room, header,
   ciphertext]` under `vox/private-session/v3`, and a receiver verifies that signature before the
   AEAD opens (ADR-047 SO-4)."
6. **ADR-005 J-17** (`docs/adr/ADR-005-channel-addressing-and-authenticated-join.md:85-88`).
   Current:
   > - **J-17.** The joiner MUST prove first. A wrong passphrase is detected by the responder, which MUST
   >   answer with one opaque `Refused`: a wrong passphrase MUST NOT be distinguishable from an identity
   >   mismatch or a policy refusal. `PowInvalid` and `Malformed` MAY stay distinguishable (they are
   >   structural).

   Replacement: the same, followed by: "`Unavailable` MAY stay distinguishable: it says the member's
   own store could not record the join, it is sent before the exchange when the member cannot
   save, it carries no detail, and after the passphrase check it tells no more than `NotAdmitted`
   does (ADR-047 SO-14)."
7. **ADR-034**, new lines after SR-5 (`docs/adr/ADR-034-the-app-and-daemon-never-hang-or-hide-a-failure.md:174`).
   Current (the anchor, kept unchanged): "- **SR-5.** The fault MUST keep the operating system's
   error text." Insert directly after it, before the heading "### 5. Health is true":
   "- **SR-6.** Vox MUST refuse a write before the operating system would, when the disk holding the
   store cannot hold the write's reservation above the floor, and MUST say so in SR-2's words;
   reclamation (deletes and cleanups) MUST stay possible on Vox's own ballast when the disk is
   otherwise full, and a first start with no ballast MUST name the bytes it needs (ADR-047 SO-11,
   SO-2).
   - **SR-7.** A recovery MUST need no more disk than the failure left plus the ballast, and
   nothing it creates MAY outlive it (ADR-047 SO-9, SO-12).
   - **SR-8.** A room that passes from 'cannot save' to 'can save' MUST raise one event,
   `StoreRecovered(room)`; the recovery owner MUST run the room's own pending save directly when
   admission becomes possible and raise the event after that save committed, never waiting for
   the event to start it; and every piece of work that waited on the store MUST be retried from
   the event (ADR-047 SO-11; ADR-046 SY-24; ADR-040 NW-2)."
8. **ADR-031 SA-9** (the decider's Q1, "lets change from seven days to two days")
   (`ADR-031-…md:282`). Current:
   > retention. An ended Session's steps age by it (ADR-029 SE-5 as amended).

   Replacement: the same, with every "7 days" / "seven days" of SA-9's step retention read as
   "2 days", followed by: "The default step retention is 2 days (the decider, 2026-11-13),
   applied retroactively at the first v0.4.31 start; a room's admin MAY set another value. There
   is no byte budget for steps (ADR-047 SO-8). The bound on a left room's hidden copy is
   ADR-049's, ruled separately."

Not amended: ADR-038 FX-22 and FX-32 (see Corrections); ADR-010 (SO-10 and SO-15 add rules that
contradict none of its lines); ADR-028 F-3.

README index row, for Main: `| [047](ADR-047-store-only-what-is-needed.md) | Store Only What Is
Needed (no proof records, proofs derived from headers and the newest accepted head; one signature
per Session step, in its own row, the body stored once; small rows packed and index pages split
by size; an order-independent incremental Session view with change discovery; key state written
per chain; nothing a recovery creates outlives it; a floor, a ballast and `StoreRecovered` before
and after a full disk; recovery in place with a retried reopen; the store shown in status with a
growth bound; rewrite or compaction only as a backstop) — proposed for v0.4.31 | 005, 006, 010,
018, 031, 034, 036, 038, 040, 041, 042, 044, 046, 049 |`

## Implementation order and related work

In dependency order, each one pull request:

1. SO-15 (accounting, seeding, display, the growth figures): every later proof reads its numbers.
2. SO-11 (admission, ballast, `StoreRecovered`) and SO-14: small, additive, and every later
   journey on the full image relies on them; ADR-046 SY-24's retry and ADR-049's departure
   record consume the event.
3. SO-1 and SO-3, with or after ADR-044 RD-8/RD-9; SO-2's sweep stage (with ADR-046 SY-26's
   anchors).
4. SO-5 (two tables, schema 2, the byte-budget split) and SO-10 (rewrite, compaction,
   `vox node compact`); SO-2's steps 2, 5, 6 and 7. E-3 before the bounds are written.
5. SO-4 (after Q2; E-10 first for the render bound).
6. SO-7.
7. SO-6, after E-4 and E-5. Independent of 4–6 and the largest.
8. SO-12 (after Q4; E-7 first), SO-9 (with ADR-049's leave), SO-13.
9. SO-8 (the 2-day default), with SO-15, since the sweep's first run on an upgraded store is
   reclamation work.

Experiments. Run for revision 2, on a clone of the operator-approved copy of omp-work's store
with redb 4.3.0 alone, scratch under `/tmp/adr047/`, receipts `exp1.log` (the as-is and split
rewrites; its "drop" rows dropped nothing, a filter defect corrected in `exp2.log`, which is the
citation for every deletion figure), `exp2.log`, `exp3.log`, the probe's source
(`probe/src/main.rs`), clones and image deleted at the end: the rewrite in one table, without
proof rows, in two tables at 2,048 and 1,024 B; the in-place sweep and `compact()`; a raw
lookup microbenchmark; the 64 MB-image latch, reopen, delete, insert and compact (its transcript
is in `adr-047-revision`, not in a log file; the probe source shows what was run). **Run for
revision 6 by the experiment agent** (`store-experiments`; receipts `store-exp-receipts/`,
rewritten verbatim from its transcript after `/tmp` was cleared; one locked run under
`/tmp/sync-measure.lock`; vox-core and the vendored redb at tag v0.4.30; the 0.4.30 asset for
E-7's rig; clones by `cp -c`, scratch data roots, nothing of the operator's touched), their
figures folded into SO-1, SO-2, SO-4, SO-12 and SO-13:

- **E-1** (SO-1): measured; 25.5 µs per leaf at 8 authors, 163 µs at 200; a whole 4,221-leaf
  feed 0.107 s cold (0.417 s with the per-leaf re-check); a whole 100,000-leaf, 200-author feed
  16.3 s / 23.2 s; cold ≈ warm. Not run: the product's directory lookup per leaf, a cold disk.
- **E-2** (SO-2, SO-12): measured; 10.1 s per 500k deletes on redb alone, 108.7 s per-key
  through an emulated 4-page sealed tree path; `compact()` 1.6–2.6 s, +0 allocated blocks, file
  length +260 MB transiently, Ok on a 64 MB image at 96%. Not run: the repair's peak on a
  multi-GB latched store; the asset has no sweep to time.
- **E-7** (SO-12, SO-13): measured at the redb level at four exact failure points and on the
  asset (latch, readable while latched, recovery in 4.0 s, `.failed-1` byte-identical to the
  latched snapshot); refused reopen = `DatabaseAlreadyOpen`, retry opens 0.51 s after release.
  CANNOT MEASURE on v0.4.30: the drain's owner graph and the refused-first-open retry (no reopen
  path exists there); they are the candidate's arms 4 and 5.
- **E-10** (SO-4): measured; 0.36 ms per random 100-step page, 0.61 ms worst case (inferred from
  measured components), 134 ms per 100,000 steps (inferred), 67.7 µs per v2 step. Not run: the
  sealed row read, the terminal.

Still to run, each on scratch nodes with the release asset, never on the operator's machines,
and never while `/tmp/sync-measure.lock` exists:

- **E-3** (SO-5, SO-10, SO-15): the `in_use / packed` ratio after 100 posts and after 200 steps
  on the release asset, with a 40 KiB step and a 64 KiB message; calibrates SO-5's constants and
  SO-15's rounded bound.
- **E-4** (SO-6): OS bytes written by the v0.4.30 daemon for the exact arm-1 shape; sets the
  bound.
- **E-5** (SO-6): fold a copy of a 1,500-candidate store both ways and compare the published
  trees, with same-`created` and body-distinct inputs staged.
- **E-6** (SO-7): bytes written per step with 1 and 6 drive holders, before and after.
- **E-8** (SO-15): time redb's `stats()` on a multi-GB store: ADR-045's grower snapshot
  (V431-045-15); the 3 GB clone it named is gone (receipt lost in the reboot of 2026-11-13;
  figure recorded in none; to be re-run as the fleet baseline).
- **E-9** (SO-5): run the `ascend` reproduction against redb 4.5 and file it upstream.
- **ADR-045's fleet run**: SO-2 on a real multi-GB store on a Mac and a Linux host: wall time and
  peak disk use; SO-15's growth rate over 30 minutes on J3's load.

Related lanes, not redesigned here:

- **ADR-044** owns the lease (RD-8), the serving contract and cache (RD-9), the ruled save's own
  `Immediate` commit and its reply (RD-7 r14);
  SO-1 and SO-12 rely on them.
- **ADR-046** owns the fetch lifecycle and the sync representation (its Q1); SO-1 and SO-3 hold
  under both answers. Items 85/87 are ADR-046 SY-24's; the store's part is `StoreRecovered(room)`
  (SO-11), raised on both recovery paths.
- **ADR-042** owns every word status and errors say (SO-14's join refusal prints its Appendix D
  row for item 24, `the member could not write the join to its store`, without the `: no space
  left on device` tail, which the one-byte wire cannot carry: ADR-042 is to drop that tail;
  SO-8's listing prints the room's step-retention setting in ADR-042's words and names no
  number; TR-25's `cannot_save` act is staged on SO-11's 256 MB image, not a 64 MiB one, which
  is below the fixed binary's floor, X042-24): the store lines (SO-15) sit in its TR-2
  blocks, `store_growth` is its key (Appendix B), the join text is its Appendix C line, and
  there is no `vox room repair` in v0.4.31 (ledger row 22; TR-14 withdrawn), so nothing here
  becomes one of its steps (r10: D22, L1-15).
- **ADR-040** names the "cannot save: disk" wait (NW-2) and the `StoreRecovery(room)` prerequisite
  that `StoreRecovered` releases; **ADR-049** (leaving and ending rooms) uses SO-9's row deletion
  and admits its departure record under SO-11; **ADR-048** (trust containment) and **ADR-050**
  (the turn journal) need nothing from this ADR beyond SO-11's admission for their small writes.
- **ADR-041** RS-13: every rewrite opens and renames through the store directory's descriptor;
  its revision-7 row for SO-10 (`Rewriting` in the hello, the restart's exit-0 line, the
  `VOX_TEST_REWRITE_HOLD_MS` knob) is carried in SO-10 as written (r9).
- **ADR-045** runs the multi-GB store journeys on the fleet and supplies the v0.4.30 asset SO-2's
  arm starts from; J4(b)'s and FG-8's "per-message and per-step byte bounds" are SO-15's
  allocation bounds (in-use bytes, not data bytes): ADR-045 cites SO-15 and measures what SO-15
  bounds (X045-3). J5(i) keeps SO-12's arms 2 and 4d (acts 1, 1-pre, 1-floor, 2, 2-repair,
  2-compact, 2-reclaim as SO-12 states them: a command's result immutable and independent of
  later row presence; no held token, no lookup, no arm 4b/4c, no J5(h); r12: R9-4), SO-12's
  arms 3, 4 and 5, SO-11's arms 1–1d, SO-14's image arms, and SO-10's short-disk and threshold
  arms (D16).
- **ADR-043**: a computer's removal evicts the removed computer's nodes from this computer's
  rooms through the existing room removal (CJ-12) and stops offers to them (CJ-11); it does not
  delete any store on this computer, and this ADR asks nothing of it. Deleting a node's own
  store is the node's removal (`vox node remove`, ADR-041's), which deletes the node directory
  and its `store.redb` and `store.ballast` together; no change here.

Tests made redundant: none found. No proof at v0.4.30 asserts on proof records, retained copies or
store bytes (`git grep` of `crates/vox-tui/tests`).

## Sibling ADRs

This ADR edits only itself. The contracts below are stated here; the named requirements of the
siblings must agree with them, and Main carries the list (`adr-cross-changes`, rows 4 and 5 are
answered here).

- **ADR-044 RD-9** (r3 accepted the fork gate's and the signature re-check's removal; row 4
  closed). Remaining: item 3 of its contract must bind a leaf's validated header to the newest
  accepted head of size ≥ its position, not to "a committed source head" through `source_heads`
  (SO-1: the tree is deleted and older heads pruned); its own-recovery paragraph is adopted as
  written; its handoff is adopted by SO-1. E-1's measured figures (25.5–163 µs per leaf; 70 µs
  per leaf for the dropped re-check) are RD-9's to cite. RD-9's "`EvidenceUnavailable`, never
  Busy" (`ADR-044:917-919`) and SO-1's `Busy{retry_after}` are two cases RD-9 is to distinguish
  (the contradictions table): evidence the holder cannot prove under any head it holds is
  `EvidenceUnavailable`, a negative; a derivation too large for one exchange is `Busy`, which
  ADR-044 r13 already carries (`retry_after` ≤ 5 s). **RD-7** (ADR-044 is accepted; revision
  14 under the decider's row 74, "one save, one trip"): every ruled commit is `Immediate`, off
  the actor, answered from its own `commit()` result; a `commit()` error is "could not be
  confirmed", terminal, never replayed; commits queued behind a failed one fail at
  `begin_write` and are answered definitely; the flusher, tokens, generations, the settlement
  snapshot and fence, and the six-fact interface are withdrawn, and with them this ADR's SO-12
  states 2(1)–(6) of revisions 7–10, arms 4b and 4c, J5(h) and C1's cost sentence (r11). SO-12
  now owns drain, one reopen and repair, one `Immediate` confirming commit before any write
  and before `StoreRecovered(room)`, the failure exit naming its stage, the refused-open
  retry, state 3's reclamation with the deferral rule, and the event; it settles no waiter and
  carries no snapshot, fence or token interface; SO-11's reserve refusal stays the definite
  pre-commit refusal RD-7 names. Its `StoreReopened` is `StoreRecovered(room)` (SO-11), one
  event, raised on the floor path too. Arm 2 is kept as RD-7 r14 asks (the held post reports
  "cannot save: disk"; an in-flight Session admission whose commit errored is `Unconfirmed`,
  terminal, never replayed; a Session admission queued behind the failure is `NotCommitted`
  and its bodies land on the bridge's retry after recovery; the second room reads throughout;
  no `.failed-*`; r12: R9-1); arm 4d keeps the storage acts of the withdrawn arms.
- **ADR-046 SY-18** (r2's row-5 answer adopted: no receipts under either representation; the tie
  is the interval's descriptors). Remaining: SY-18's kept list must name "the newest accepted
  head" as the only head kept outside a fork (SO-1 prunes the rest) and "context objects named by
  held entries' headers" (the R1 items are withdrawn, r10: D6); SY-16 must drop "not frozen"
  and "once per process" and carry SO-1's rule and RD-9 r3's per-miss bound; SY-21 maps
  `EvidenceUnavailable` to "not held here; ask another holder", never Busy, and every `Busy`
  SO-1 emits is clamped into SY-21's 50 ms–5 s (r10). **SY-27's baseline** (X046-33; *changed
  r12: ADR-046 r10, ledger row 77 — one answer, no assembly*): the installed summary (≤ 1 MiB)
  is kept whole until a newer accepted checkpoint's summary is installed; the install is one
  transaction (the summary at most 1 MiB encoded, framing included; stored as one sealed row
  of up to a 2 MiB allocation, SO-15), an ordinary write under SO-11's floor (a short
  disk refuses it and the joiner waits `StoreRecovery(room)` with the bytes in memory under its
  permit), which replaces the previous baseline in the same transaction — bounded because both
  summaries are at most 1 MiB encoded; a kill before the commit leaves the old summary authoritative and nothing
  partial. SO-15 classes it `index` as SY-18 does; SO-2's sweep never touches it; nothing here
  names chunks, an assembly, `snapshot_held`, pinning, Retire or Reclaiming (deleted with
  SY-27 r10). **SY-24**
  and the admission queue: both consume `StoreRecovered(room)` as SO-11 defines it (one event,
  not `StoreReopened`; both paths, including floor recovery with no reopen;
  instance-qualified); SY-24's journey is SO-11's arm 1c, in SY-24's file, optional in tree
  and blocking on the fleet (FG-20) by the decider's Q7. **SY-26**: runs inside SO-2 step 4,
  before the sweep's first batch, in bounded migration batches with a cursor and a completion
  marker, not one commit per room — SY-26's "in one commit per room" is to change to SO-2 step
  4's words (r10: D5, X046-25; r11: R8-2); **its third arm**
  (X046-26) is carried in SO-2's upgrade journey as SY-26 states it: the `base1` root frozen as
  RcaFrozen left it (a member's bodiless header held, its text never shown) opened by the fixed
  binary with the members running, the member's row rendering within 30 s and `sync_bytes` 0;
  the 17-author removal root where the target was quiet, after which every member still shows
  the target's pre-removal post and never its later one; and a fresh joiner of the upgraded
  room that reads the same; v0.4.30 red verified by SY-26 (`base1`: rows 1 at join+88 s).
- **ADR-040**: `StoreRecovery(room)` is NW-1's prerequisite row, released by
  `StoreRecovered(room)` (X047-10; the generation bump of the room's recovery instance precedes
  every consumer's notification, and no consumer parks on the event it produces, X040-17);
  "cannot save: the store is recovering" is an NW-2 edge during SO-12's drain.
- **ADR-049**: room deletion is SO-9's batched row deletion as reclamation, completed by
  `RoomRowsPurged(room)`; the leave record is a reclamation batch under SO-11 (3 MB), refused by
  LE-1 below that with the room preserved; the leave's rewrite is gone; the scrub is the next
  rewrite (the decider's answer to ADR-049's Q7, row 61).
- **ADR-042 TR-2, TR-8, TR-23, TR-25, Appendix C.** The store lines with file length and disk use
  both, `ballast_bytes`, `growth_per_hour_bytes`, `staged_bytes` (SO-15); `preparing: removing
  sync records` / `rewriting the store (… file, … in use, … of data)` / `compacting the store` /
  `recovering the store: waiting for …` / `recovering the store: could not reopen it: …; trying
  again in 5 s` / `the upgrade needs <n> MB to continue` (SO-2, SO-10, SO-12); `rewrite due`; the
  join refusal text (SO-14); the `cannot save: the disk holding …` and `cannot save: the store is
  recovering` words (SO-11, SO-12); `steps older than 2 days are no longer kept` (SO-8); the
  corrupt-store line (SO-9).
- **ADR-045 J3, J5, J13, FG-12, FG-20** (reconciled with revision 9; the decider confirmed on
  2026-11-13 that J5 and FG-20 stay blocking, row 59). J5(i) carries this ADR's arms on the
  guest's 256 MB APFS image or the Linux VM's sized tmpfs; J5(h) is withdrawn (ADR-044 RD-7
  r14: no waiter parks across recovery) and J5(i) keeps SO-12's arms 2 and 4d; FG-20 stages the stall; J13's retention act runs SO-8's mechanism at
  `--steps 60s` and the 2-day default is SO-8's in-tree clock-step proof (FG-12 (ii)); J3 and
  J13 measure SO-15's growth rate and project it with the counts and body bytes in the run
  record. The exact rows to ask of ADR-045 (what J5(i) still lacks):
  1. J5(i), SO-2's fixture: "a 200 MB store with 500k stranded proof rows" → "a data root
     written by the v0.4.30 asset with 20,000 stranded proof rows (about 80 MB, RcaChurn's
     `relay75` recipe) and 20 MB free, then 2 MB free; the multi-GB case on the multi-GB fixture
     with filler leaving 20 MB, then 2 MB" (SO-2 arms (i)–(iv)).
  2. J5(i), SO-11's arm 1d (r12: R9-4): after a below-floor reopen with a pending re-save and a
     received-entry admission parked on `StoreRecovery(room)` in R2's admission queue, free the
     filler and do nothing else: within 10 s `recovered; it can save again`, the re-save's
     entry readable, nothing parked on `StoreRecovery` for the room in `vox status`, a post
     succeeds (mutant: an event that waits for the save it must follow).
  3. J5(i), SO-12's arm 4 apparatus: the refused reopen is staged by a writable second open or
     the `test-knobs` lock hold in the close/open gap, never a read-only open (E-7: refused with
     `Database repair aborted`); and arm 4d as SO-12 states it (the `fsync` fault after the
     header on one ruled commit on the `test-knobs` member: the command fails at once from its
     own commit, the log orders `recovery: confirmed` → reclamation → `StoreRecovered`, the
     header-carried received entries show, nothing reports the post saved; acts 1-pre,
     1-floor, 2, 2-repair, 2-compact, 2-reclaim; no held token, no lookup; r12: R9-4).
  4. ADR-045 E-9's placement (not this ADR's E-9): the Linux VM's tmpfs is to be shown to give the sparse-file behaviour
     SO-2 step 5 relies on (blocks charged, not length; ENOSPC at a data write) before J5(i)
     runs there; until then the guest's image.
  In tree, not fleet: SO-4's retained-v2 relay arm and SO-6's generation-coexistence arm (arm
  5b). "The soak stages 2-day expiry" is withdrawn in favour of the J13 wording above.
- **ADR-038 FX-33** amended (the decider's Q4); FX-29 withdrawn under R2 (amendment 2; r10: D6).
- **ADR-034** SR-6–SR-8 (amendment 7). **ADR-031 SA-9** 2 days (amendment 8). **ADR-006 S-8**
  (amendment 5).
- **`store-experiments`** (the experiment agent): E-1 lands in SO-1 "Cost"; E-2 in SO-12 "What
  E-2 and E-7 land here" (the compaction reserve and ballast constants); E-7 there and in SO-13
  (the pin); E-10 in SO-4 (the render bound and the key-page mechanism). Each paragraph names
  what changes if the figure is worse than assumed.

## Consequences

### Positive

- The operator's content is projected at about 0.35 GB of disk instead of 3.01 GB once the steps
  have turned over under the 2-day retention (Appendix B; the day-zero figures are measured:
  0.84 GB of disk after the rewrite, a 1.64 GB file after sweep and compaction), and stays
  proportional to what is posted at a stated rate (SO-15).
- About 7–14 GB an hour of SSD writes in a busy agent room stop (SO-6, SO-7).
- A full disk costs a refusal in plain words and nothing else: no loop, no copy, no file left;
  with the ballast in place the node can delete and compact to make room; work that waited on
  the store is retried when it can save again (items 85/87).
- A joiner is told when the member is the one that failed.
- A person can see what a node stores, what each room costs, and how fast it grows.

### Negative

- Proof ranges are derived on demand on a cache miss: 25 µs per leaf in an 8-author room, 163
  µs at 200 authors (E-1, measured); a whole 100,000-leaf, 200-author feed asked in one range is
  refused truthfully and filled in the background (16 s); CPU and read latency for the asking
  peer, no writes.
- Rendering a step opens its ciphertext: 0.36 ms per 100-step page, 67.7 µs per retained v2
  step (E-10, measured).
- After a native write failure, rooms answer from memory until the reopen (E-7: a fresh read of
  the latched file can show a commit the reopen keeps or loses); a post whose commit's `fsync`
  failed after the header may be kept, and the person is told which.
- Two tables mean one extra lookup for a large value; a schema-1 store keeps stranding small
  rows until its first rewrite succeeds; index pages that never change keep their 8 KB leaf.
- The incremental Session fold is subtler than a full rebuild: a late lifecycle event re-folds
  its Session (O(m) in that Session's openings and ends), E-5 is its check, and the full rebuild
  remains as repair.
- The first v0.4.31 start on a multi-GB store spends tens of seconds removing sync records and
  rewriting or compacting; rooms prepare meanwhile; on a short disk the file shrinks only to what
  compaction returns; on a disk with no room at all it names the 16 MB it needs (SO-2 step 7).
- With one root signature a private record is no longer sender-key-signed; the sender key still
  encrypts it (ADR-006), and the root key, not the sender key, is what a forger would need.
- The second signature and the clear copy on the operator's stored steps leave as the steps
  expire under their room's retention (2 days by default), not at first start; stored openings
  and ends keep theirs.
- Steps older than two days are gone from every node by the decider's ruling; a holder offline
  longer than that never sees them (SO-8).
- A 32 MB ballast file per node store is disk Vox holds on purpose; status shows it.
- While a latched store drains, every room of that node refuses writes (readable throughout);
  while a refused reopen is retried, those rooms answer `preparing`.

### Neutral

- Wire changes: the private Session record (SO-4) and the join refusal code (SO-14). v0.4.x
  machines update together.

## Review record

Every disposition below is historical: it records what each review found and what the
revision of that day changed. Mechanisms it names that the requirements above no longer
state (the group flusher, tokens, generations, the settlement snapshot and its six facts,
arms 4b and 4c, R1's cursors and obligations, the 20 s and 17 MB bounds, the chunked
baseline assembly) are withdrawn; the current requirements govern.

The independent review of 2026-11-12 (`adr-047-sol-review`): verdict "needs redesign", sixteen
findings. Each was checked against v0.4.30 (`git show v0.4.30:<path>`) and, where a measurement
could settle it, measured on the clone (Context, "What was measured for this revision").

| # | Finding | Classification | Answered by |
|---|---|---|---|
| F1 | With the cache gone, a cold node cannot serve non-canonical ranges for a frozen or conflicting author or an uncommitted head; the first draft kept the three refusals | CONFIRMED (`proof_range.rs:150-154`, `:179-186`, `:197-201`; the only readers are serving and own recovery, `own_history.rs:403`; the gate's comment names its purpose, `:188-192`) | SO-1: every range derived from held headers and contexts; fork state irrelevant to serving; the one refusal is an unaccepted head; cost measured; the arm with a fork and every holder restarted |
| F2 | Folding in arrival order diverges between nodes; `Pending` is not a lifecycle queue | CONFIRMED (`build.rs:396-433`; `activity_pending.rs:56-79, 112-119` handle approvals and questions) | SO-6 rule 1: per-Session ordered re-fold; cursors and roots in one commit; permutation arm |
| F3 | Bundle parts past the cursor are lost; `build.rs:164-184` is not an ordered repair | CONFIRMED (`:164-184`: part 1 starts, a part without a cursor is ignored, an unexpected part deletes) | SO-6 rule 2: retained part index, completion check, reverse-delivery arm with a restart |
| F4 | Lowering `PAGE_ITEMS` refuses existing 111–128-entry pages; the raw rewrite does not re-encode them | CONFIRMED (`entry_store.rs:1048-1051`; `store.rs:801-808` copies sealed bytes) | SO-5: decoder bound stays 128, the writer splits by encoded bytes (r3, N7); no conversion; residual stated |
| F5 | Dropping the outer signature changes the record's identity, which indexes, attention and peers use | CONFIRMED (`sessionstream.rs:154-158`; `private_session.rs:708-711`, `:736-758`; `serve.rs:255-260, 284` send the hash to peers) | SO-4: v2 rows are not converted; they keep bytes and identity; v3 only for new records; the upgrade arm with retained steps and attention |
| F6 | The floor check before commit is too late: redb grows the file and flushes dirty pages during the transaction | CONFIRMED (`page_manager.rs:2211-2227`, `:2372-2379`; `cached_file.rs:899-930`, `:823-830`) | SO-11: admission before `begin_write` with a reservation; in-flight failure handling; external race to SO-12 |
| F7 | `1.2 × data` is below every measured replacement | CONFIRMED (measured: 1.39–1.43 × data; sparse length vs blocks distinguished) | SO-10: reservation 1.1 × packed bytes + floor, rechecked every 64 MB; packed bytes defined and validated within 2% |
| F8 | No reclamation below the floor: the node cannot delete to recover | CONFIRMED (the first draft refused every commit under 64 MB) | SO-11: reclamation on the ballast (r3, N3); SO-12: reopen, delete, `compact()` in place, measured on a 64 MB image with 3 MB free |
| F9 | SO-1/SO-3 must be conditional on ADR-046 R1/R2; SY-18 and SO-1 disagree on receipts | CONFIRMED | SO-1 and SO-3 written for both; receipts kept only under R1; the tie under R2 named; Sibling ADRs |
| F10 | The sender signature alone loses protection against a compromised sender generation and transferable verification; one root signature is the simpler alternative | CONFIRMED (ADR-006 S-6 treats sender-key compromise; the receiver's 1,984-B key row proves only what it installed) | Q2's corrected table; SO-4 recommends one root signature; amendment 5 |
| F11 | "Cannot decrypt again" is false for the retained-key paths | CONFIRMED (r3; revision 2 said PARTLY on a room-wide count, which N9 showed wrong: the window is per generation and a generation is at most 1,000 messages, `state.rs:40-45`, `:669-686`) | SO-4: the clear copy goes; the body is opened on demand from the generation's retained chain; E-10 bounds the render cost |
| F12 | Projections used the median; dropping a signature inline saves no page | CONFIRMED (mean value 10,031 B; inline 424 MB vs split 334 MB, computed from the measured distribution; the model reproduces today's 507 MB) | Appendix B recomputed; SO-4's split justified by the numbers |
| F13 | The 8,806–14,772 figure is for public named-session posts; ordinary steps do not move the metadata basis; the OS-byte red is unmeasured | CONFIRMED (`private_index.rs:489, 567-570`; `pending.rs:334-344`) | SO-6 arm 1 interleaves named posts and lifecycle changes; the v0.4.30 bytes are UNKNOWN until E-4; measurement boundary defined |
| F14 | The 64 MB HFS+ image is under the floor; the race arm is not staged | CONFIRMED (`…proof.rs:2203-2214`) | SO-11: 256 MB APFS image; SO-12 arm 2 staged with a test-knobs hold; APPARATUS named |
| F15 | `Unavailable` falls through the first-frame dispatch and `rejected()`; one byte carries no detail | CONFIRMED (`joinstream.rs:998-1009`, `:712-718`) | SO-14: both boundaries, typed error, generic wire wording, detail in the member's log |
| F16 | A ledger by segment kind cannot see sync records; no seeding | CONFIRMED (EntryIndex holds pages, receipts, proof rows and cursors under one kind; `sparse.rs:2539`) | SO-15: class assigned by the sparse-object writer; seed walk with a marker; reconciliation to `stored_bytes` |

Byte and lifetime audit (the review's table): every row is in Appendix A with the review's
disposition applied; the lifecycle exception (openings and ends age by message retention,
`private_session.rs:484-500`, `session_projection/source.rs:74-81`) is recorded there and in
SO-2 and SO-8. The review's citation audit is applied under "Corrections". The security table
is Q2's. Of the review's eleven decider questions, 1 (sync representation) is ADR-046's Q1 and
SO-1/SO-3 follow it; 3 (uncheckpointed content) does not arise because the hash-chain option is
not offered in this release; 6 (low-space maintenance) is answered by SO-11 as an engineering
rule, not a choice; the rest are Q1–Q8 below.

### Second review (`adr-047-sol-review-2`, 2026-11-13): verdict "needs revision", thirteen findings

Each was checked against v0.4.30, redb 4.3.0 and revision 2's own text.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| N1 | Pruning heads to the newest breaks derivation: the header reader follows `source_heads` to the original head object | CONFIRMED (`sparse.rs:1334-1356` resolves a position through `source_heads` to the head record and checks its binding; `:1273-1294` loads the head again; so a pruned H1 breaks a leaf admitted under it, no fork needed) | SO-1: the reader binds a position to the newest accepted head of size ≥ p (one chain, Terms); the `source_heads` tree goes; heads pruned by reachability (newest, fork witnesses, running fetch); arm 1 accepts two heads before the holders restart; mutant "delete H1 and keep the old reader" |
| N2 | An id cursor never sees an in-place re-save of a private row | CONFIRMED (`pending_upgrade.rs:1492-1496` dedupes by hash; `:1560-1563` reuses the id; `:1579-1591` removes and re-puts under it; `private_session.rs:593-596` opaque rows) | SO-6 rule 1: a `Changes` queue written in the input's own commit for add, replace, remove and eligibility; arm 4 (late drive key, with a kill between key and fold) |
| N3 | Reclamation under a 17 MB floor is unreachable on a disk filled below it; SO-2's sweep precedes its compaction | CONFIRMED (revision 2's own text; the probe bypassed the floor) | SO-11: a written 32 MB ballast released for reclamation, compaction and reopen; SO-2 step 7 names the one external prerequisite (a first start with no ballast and nothing to delete); arms 1b and 3; SO-12 state 2 releases the ballast before the reopen |
| N4 | No transition out of a refused reopen; the transaction count is not the handle count; FX-33's other-room outcome | CONFIRMED (`store.rs:226-266`: every transaction clones the `Arc<Database>`; the probe printed the error and returned; ADR-038 FX-33 `:681-705`) | SO-12: three states (draining with reads on the latched handle, reopening with a 5 s retry and the error named, recovering); drain = `Arc` count 1; arms 4 and 5; amendment 3 replaces FX-33's outcome explicitly and Q4 asks the decider to accept it |
| N5 | The logical identity and winner rule stated were not the full fold's | CONFIRMED (`build.rs:37-45`: `(author, created, body)`; `:49-61`: newest by `(private, order, hash)`; `:396-408`: a later opening updates only supplied fields) | SO-6 rule 2 keeps both exactly; rule 3 keeps the transition unchanged; arm 2 stages two same-`created` openings with different bodies; the canonical tie replaces the local id (Terms "Position"); the old fold's tie limitation stated in C-77 |
| N6 | A late event's re-fold is O(events) and must be resumable and atomic; name events are thousands | CONFIRMED (`build.rs:319-337`: any named post is a kind-0 event; `:359-503` the emitted rows) | SO-6 rule 3 (names are a max by position, no re-fold) and rule 4 (`Refold(S)` as a resumable staged job, 32 events a turn, one swap, restart on a concurrent event; truthful O(m) and O(N²) bounds); arm 5 (a kill inside a re-fold) |
| N7 | 110 rows do not fit 4 KB: each row carries a 66-B key | CONFIRMED (`entry_store.rs:22-34`, `:1009-1030`; `session_tree.rs:1-7`) | SO-5: split by encoded bytes (`PAGE_SPLIT_BYTES`), decoder bounds unchanged; C-80 corrected; residual restated; Appendix B drops the fanout saving |
| N8 | The 64 MB recheck demanded the whole reservation after the candidate consumed part of it | CONFIRMED (revision 2's own text) | SO-10: recheck against the remaining allocation; threshold arm on an image with exactly the reservation + 1 MB |
| N9 | The duplicate body's rationale ignored per-generation rotation; a message key is 32 B; the copy is 55 MB | CONFIRMED (`state.rs:40-45`, `:288-290`; `pending_session.rs:1096-1104`; `drive.rs:92-100`; mean body 1,390 B × 39,547) | SO-4: the clear copy goes; metadata row only; on-demand opening from the retained generation chain; chain segments kept with the generation's last record on every path; E-10; removal and rotation arms |
| N10 | File length and disk use substituted for each other; 570 MB presented as a day-zero file | CONFIRMED (`exp2.log`: file 1,078 MB, `du` 835 MB) | Every example, status line and Appendix B row carries both; the projected figure is labelled as a projection after turnover |
| N11 | R1's receipts classed `sync` contradict the zero oracle | CONFIRMED for revision 2's text; moot in r3: no receipts under either representation (ADR-046 r2) | SO-15: `sync` is transient only; SO-1's kept list is `index`; mutant "class the kept heads as `sync`" |
| N12 | The receiver-state mutant has no visible effect within `MAX_SKIP` | CONFIRMED (`pending_upgrade.rs:1492-1496` dedupes before the chain; a 10-iteration gap decrypts) | SO-7: the receiver write rests on review, E-6 and an optional 1,100-step proof whose mutant is red at the gap; the sender arm keeps its visible mutant |
| N13 | The 2.6 µs figure is a raw lookup after a full scan, not a cold header read; "once per process life" withdrawn by ADR-044 r3 | CONFIRMED (`probe/src/main.rs:47-75`) | Context and SO-1 relabel it; cost stated per miss as O(k × frontier width); E-1 defines the measurement; Consequences updated |

The review's hard-case conclusions are adopted: the one-chain argument for dropping the fork
gate (SO-1, with ADR-044 r3); the own-recovery kill window (arm 3's hold); the old fold's tie
limitation (C-77, Terms); the v3 consumers changed end to end and the signature row deleted with
its record (SO-4); items 85/87's producer contract on both paths (SO-11). Its experiment audit is
applied: `exp1.log`'s "drop" rows dropped nothing and `exp2.log` is the citation; the 502,412
removed rows are a length-class filter (502,406 proof rows plus six rows of 12–13 KB, of which
three are the cursors the RCA named and three are unclassified without the key); the ENOSPC
transcript lives in the revision note. Its day-zero table is Appendix B's.

### Third review (`adr-047-sol-review-3`, 2026-11-13): verdict "needs revision", seven findings

Each was checked against v0.4.30, redb 4.3.0 and revision 3's own text. Nothing the review
closed (N2, N7, N8, N9, N10, N13) was changed.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R3-1 | The ledger seed, the rebuild and recovery's re-save are ordinary writes that a start with 20 MB free cannot admit, yet they stood before compaction; 17 MB and 3 MB disagreed | CONFIRMED (revision 3's SO-2 steps 4(b)/(c) and SO-12 state 3; SO-11 classed projection turns as ordinary) | SO-2: sweep → compaction → ordinary stages, each with its admission named; step 7's readable exit for every mandatory stage; one reclamation figure (3 MB); SO-12 state 3: the re-save waits for the floor and the rooms publish readable; short-disk arms (i)–(iii) |
| R3-2 | Under R1, settlement follows `source_heads` and `prior_heads[H2]` references H1's record; pruning H1 breaks both | CONFIRMED (`sparse.rs:2006-2035` settlement reads `source_heads` and retires an H1-keyed obligation; `:2818-2822` stores H1's record id; `:3036-3057` dereferences it) | SO-1 "The other readers of a head": obligations keyed `(author, position)`, settlement by the newest accepted head with a size check; eager progress copy in H2's acceptance commit, `prior_heads` deleted; SO-2 step 4 re-keys and copies before deleting; crash windows stated |
| R3-3 | Opening-supplied names were left out of the name maximum | CONFIRMED (`build.rs:396-408` sets `name`/`named_at` on a refreshed opening) | SO-6 rule 3: every name assignment, including an opening's, is in `Names`; the t1–t4 sequence shows "C"; opening-only and removal cases; E-5 and arm 2 extended |
| R3-4 | A re-fold that restarts on every arrival never publishes under continuous refreshes | CONFIRMED (revision 3's rule 4) | SO-6 rule 4: captured basis; arrivals queue above it; the basis is published, then corrections applied; no prefix discarded |
| R3-5 | The final publication commit retracted and installed every incarnation row at once | CONFIRMED (revision 3's rule 4; `build.rs:359-503` emits per-incarnation rows into global trees) | SO-6 rule 6: per-Session generation in every global row's key, staged rows invisible until an O(1) descriptor swap, old rows retired by `cleanup(limit)` in 32-key turns; concurrent Sessions untouched |
| R3-6 | A 24 KB per-entry bound ignores the 64 KiB body a message may carry | CONFIRMED (`content.rs:39-40`, `:171-175`) | SO-15: the bound is 9 KB + 2 × body + 15 KB index per entry, 5 KB + body per step, 4 KB per head advance; the gate asserts with counts and body bytes; nothing is refused to meet it |
| R3-7 | Staged partial bodies classed `sync` make the zero oracle false | CONFIRMED (ADR-046 SY-18 keeps up to four partial bodies across restart) | SO-15: a staged partial body is `messages` (`staged_bytes`), moved to the entry on completion; `sync` is request, proof and cursor bookkeeping only |
| N12 (re-opened) | The 1,100-step optional arm cannot show the receiver write either: rotation at 1,000 and the receive bound make the gap unreachable | CONFIRMED (`pending_session.rs:1096-1104`; `pending_upgrade.rs:617-647`, `:1595-1597`) | SO-7: the receiver write rests on review and E-6; no proof claims it |

The review's disposition of the experiments is adopted: E-2 and E-7 precede the final design of
SO-12 and SO-13 (their landing paragraphs say what changes if they are worse than assumed); E-1
and E-10 may change SO-1's miss path and SO-4's render mechanism, each with its named fallback;
a separate agent runs all four on scratch copies and reports in `store-experiments`. Its
hard-case conclusions are adopted: a read-only open cannot coexist with the live writer, so
E-7's refused-open apparatus takes the file lock in the close/open gap; `StoreReopened` and
`StoreRecovered` are one event (SO-11); a retained v3 record is opened through the
history-opening path for a removed member (SO-4). Its decider table is applied: Q6's
fresh-profile alternative is withdrawn (the binding no-reset rule); the others are answered
below.

### Fourth review (`adr-047-sol-review-4`, 2026-11-13): verdict "needs revision", six findings

Each was checked against v0.4.30, redb 4.3.0, ADR-045 revision 9 and revision 4's own text.
Nothing the review closed (R3-2, R3-3, R3-4, R3-7, N12, and the earlier closures) was changed.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R4-1 | SO-12's deferred re-save waited for `StoreRecovered`, which SO-11 raised only after that save: a cycle that re-creates the retained-flow stall | CONFIRMED (revision 4's own text; the consumers, `runtime.rs:1814-1848`, are released by the event) | SO-11: two acyclic transitions, admission-ready (the floor check runs the pending save directly) then recovered (the event, after the save); SO-12 state 3 and SR-8 say the same; arm 1d |
| R4-2 | Stream 13 carried v3 only while retained v2 records are deliberately kept; a holder back within retention could not pull them from another holder with the author gone | CONFIRMED (`serve.rs:212, 289` send `record.wire()` and name `record.hash()`; a v2 record cannot be re-signed) | SO-4: v2 relayed and authenticated as v0.4.30 did until each record's retirement, nothing authors v2; the retained-v2 relay arm |
| R4-3 | `(P) → (S, g)` lets the staged generation overwrite the live row before the swap (unique-key tree) | CONFIRMED (`session_tree::Write::set` → `change_value`) | SO-6 rule 6: `(P, g) → S` and `(S, g, …)` keys, live rows visible until the swap, also across a kill; every lookup applies the rule; coexistence arm listed for J5(i)'s companion in tree |
| R4-4 | The in-use bound used row bytes; a 40 KiB step takes a 64 KB page | CONFIRMED (SO-5 keeps power-of-two rounding) | SO-15: the bound sums each row's allocation (93% fill under 2 KB, power-of-two above) plus index; a 40 KiB step costs 69 KB, a 64 KiB message 143 KB; the linear figures are the operator projection, not the gate; E-3 calibrates with large bodies |
| R4-5 | The fleet contract read (ADR-045 r7) lacked the refused-open, leak and no-space-returned arms | PARTLY: r7 lacked them; ADR-045 r9 J5(i) carries SO-2's, SO-11's 1–1c, SO-12's 2–5 and SO-14's image arms with the hold-dependent ones on the `test-knobs` member, and J5(h) RD-7's act | SO-11's proof names J5(a)–(i) as r9 carries them; the sibling list says what J5(i) still lacks (the fixture size, arm 1d, the v2-relay and coexistence arms in tree) and withdraws "the soak stages 2-day expiry" for J13's retention act at `--steps 60s` with the default as SO-8's clock-step proof |
| R4-6 | 500,000 stranded rows cannot fit a 256 MB image | CONFIRMED (one 4 KB leaf each is 2 GB; the real store packs them to 1.05 GB) | SO-2: 20,000 stranded rows (80 MB) on the image, and the multi-GB case on ADR-045's multi-GB fixture with filler leaving 20 MB then 2 MB |

Its ruling on the experiments was applied in revision 5 (no figure was then available; revision
6 folds the measured results in, below); revision 5's corrected fallbacks were: E-1's resumable miss is
withdrawn for a truthful `EvidenceUnavailable` with a job-owned background fill, and the
second fallback's count corrected to n − 1 descriptors (SO-1); E-2's ballast can never enter
ordinary admission, the >256 MB vendor variant is withdrawn for a named compaction
prerequisite (SO-11, SO-12); E-7's retained-pin fallback, which would forbid the reopen, is
replaced by an atomic boundary that stops disk reads and answers from memory (SO-12, SO-13);
E-10's key page is keyed by the full chain identity and bounded by the holder's floor (SO-4).
The live-generation exception is applied at the shared pruning consumer (SO-4, SO-7). SO-10's
leftover idle-rewrite paragraph and the implementation order's budget branch are deleted.

### The experiments (`store-experiments`, 2026-11-13): E-1, E-2, E-7, E-10

Each figure is folded in where it lands, with its receipt and its label (measured or inferred,
as the experiment agent reports it); the design changed where a figure contradicted it, and
nothing the fourth review closed was changed.

| Experiment | Result | Where it landed; what changed |
|---|---|---|
| E-1 | MEASURED: 25.5 µs/leaf at 8 authors, 163 µs at 200; 4,221 leaves 0.107 s cold (0.417 s with the re-check); 100,000 leaves / 200 authors 16.3 s / 23.2 s; cold ≈ warm | SO-1 "Cost": the primary design holds unconditionally up to about 2 × 10⁶ coordinate visits; the truthful refusal with a job-owned background fill covers the whole-feed extreme; the kept-descriptor fallback is deleted |
| E-2 | MEASURED: sweep 10.1 s per 500k rows on redb alone, 108.7 s per key through a 4-page sealed path; `compact()` 1.6–2.6 s, +0 blocks, file length +260 MB transiently, Ok at 96% on a 64 MB image; not run: the repair's peak on a multi-GB latched store | SO-2 step 4: the sweep is page-wise (one rebuild per directory page, bulk record deletes), the "20–30 s" withdrawn; step 5 and SO-12: 16 MB / 32 MB hold in blocks on sparse-file filesystems (APFS measured; ext4/xfs/tmpfs inferred, owed to J5 on the Linux VM); where length is charged, compaction under the floor is not attempted and status names the space |
| E-7 | MEASURED (redb level): a failure before the header leaves the old roots; a failure at the final `fsync` leaves the failed commit's rows; the `None` commits staged before a data-write failure are lost on reopen; a refused reopen is `DatabaseAlreadyOpen`, retry opens 0.51 s after release. MEASURED (asset): latch, readable while latched, recovery 4.0 s, `.failed-1` byte-identical to the latched snapshot. CANNOT MEASURE on v0.4.30: the drain and the refused-first-open retry | SO-12 state 1: the atomic read boundary is the design (rooms answer from memory until the reopen); state 2(2): what the reopened store holds is read from it, never assumed by class; arm 4's apparatus is a writable hold; arm 4b added; SO-13's inferred sentence withdrawn; the waiter rule is ADR-044 RD-7's alone (revisions 7–8) |
| E-10 | MEASURED: 0.36 ms per random 100-step page; 0.61 ms worst (inferred from components); 134 ms per 100,000 steps (inferred); 67.7 µs per v2 step | SO-4: the primary design holds three orders of magnitude under FR-4; the key-page fallback deleted; the v2 cost stated with the one whole-Session path (SO-2's rebuild, a preparation stage) |

The decider's confirmations of 2026-11-13 morning are applied: J5 and FG-20 block as fleet
journeys (row 59; "to be confirmed" removed); a left or ended room's rows and key are deleted at
once and the freed pages are cleared at the next store rewrite (row 61; SO-9 as specified;
ADR-049's Q7 answered B).

### Fifth review (`adr-047-sol-review-5`, 2026-11-13): verdict "needs revision", four findings

Each was checked against v0.4.30, redb 4.3.0 and revision 6's text; ADR-044's ninth and tenth
reviews (R9-1–R9-4, and the tenth's finding that a persisted Store-counter watermark can alias
across a restart) were read with it, and Main's ruling that the waiter rule has one owner.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R5-1 | `EvidenceUnavailable` with a background fill makes the over-budget miss negative availability: a cold start of a large room is refused, and ADR-046 (SY-18/SY-21) reads it as "no such evidence" | CONFIRMED (the fill and the refusal raced; the fill result was not pinned, so a retry could miss again) | SO-1 "Cost": the over-budget miss answers `Busy{retry_after}` (temporary, retryable; ADR-046 r5 SY-21 consumes it), the fill is deduplicated by subtree identity and its result pinned 60 s, so the retry at `retry_after` hits; the unit is k × w ≤ 2 × 10⁶ visits; proof arm 4 asserts the retry succeeds; the serving rule reads "never `Busy` for lack of evidence" |
| R5-2 | The token's number and "the reopened store's last committed number" are different counters: `Epochs.next_transaction` starts at 0 per open (`store.rs:1988-1995`); redb's id survives opens, advances on empty flushes and on the repair commit inside `Database::open` (`db.rs:1658-1670`) | CONFIRMED | SO-12 state 2(2): no number from the repair commit is compared with anything and SO-12 persists no watermark, counter or lineage row; the waiter rule is ADR-044 RD-7's alone (Main's ruling; RD-7 revision 11 chose a lookup by durable identity and deleted the watermark), and SO-12 provides its six facts (r8); the per-`Batch` mark of revision 7's first draft is withdrawn |
| R5-3 | "Every `None` commit since the last flush is not kept" is false: an `Immediate` commit's header carries every earlier `None` commit (`transactions.rs::durable_commit`, `page_manager::commit`); E-7 staged None-then-data-write, not None-then-post-header-fsync | CONFIRMED | SO-12 state 2(2): survival is per write, read from the recovered store, whatever the class; the class sentence is deleted here and in the RD-7 row; SO-13's "never answers a non-durable commit's" deleted; 2(3) at least one durable `Immediate` commit and the rooms rebuilt from the reopened store before `StoreRecovered(room)`; 2(3)–(4) the settlement before any write, the event after it (r9); 2(5) a failed recovery is named in status, no event, nothing re-raised or reclassified; arm 4b (2(6)) holds an old waiter across the recovery with RD-7's holds; arm 4c the combined case on a populated root |
| R5-4 | SO-15's growth bound rounded the body alone and stopped its sizes at 64 KB; a 64 KiB body is a 65,551-B row in a 128 KB allocation | CONFIRMED | SO-15: the complete sealed row (header + body + signature) is rounded, sizes continue past 64 KB; a 64 KiB message is 128 KB + 128 KB + 15 KB = 271 KB; the projection table and E-3's calibration bodies follow |

Also applied: ADR-043's sentence corrected (CJ-11/CJ-12 evict and stop offering; they delete no
store; `vox node remove` deletes a node's store); ADR-049's hidden-copy bound is referenced as
ADR-049's number (ledger row 58); ADR-045 revision 10's four J5(i) rows noted in Sibling ADRs.

### Revision 8 (2026-11-13): ADR-044 revision 11's six facts

ADR-044 revision 11 chose RD-7's lookup rule and deleted the watermark; its note lists six facts
SO-12 must provide and what SO-12 must delete. Applied: SO-12 state 2 is restated as facts (1)–(6)
in SO-12's own words (the generation step; reopen and repair with nothing from the repair commit
compared; at least one `Immediate` commit and the rooms rebuilt from the reopened store before
`StoreRecovered(room)`; the event triggered RD-7's lookups (revision 9 moves the settlement
before the event, ADR-044 r12); a second failure raises no event,
reopens again and re-raises or reclassifies nothing; arm 4b as RD-7 restates it). Deleted:
`committed_through`/lineage rows, `durable_watermark`, "retained prefix", the frozen `durable`,
and every sentence that stated or implied what a waiter is told (state 2's old (ii)–(iv), state
3's "may RD-7 answer `Ok`", arm 4b's act 3 and arm 4c's writer-answer mutants). No fact of the six
is unprovided.

### Sixth review (`adr-047-sol-review-6`, 2026-11-13): verdict "needs revision", three findings and the reserve

Each was checked against v0.4.30, redb 4.3.0 and revision 8's text, with ADR-044 revision 12
(the settlement snapshot) read as the current RD-7.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R6-1 | State 3 ran reclamation (room deletions included) and compaction before the confirming commit, and a room event triggered RD-7's lookups; a lookup after that mutation is not a lookup of the recovered roots, and RD-7 r12 settles from one snapshot before any write | CONFIRMED (revision 8's own order; `actor.rs:20643-20716`'s publication waits on the old room's writer gate, so a room's ordinary reopening cannot be the verdict's prerequisite) | SO-12 state 2(3): the explicit `Immediate` commit, then the recovery owner calls RD-7's settlement under the writer and admits nothing until it returns; 2(4): state 3 and the per-room event follow, the event triggers nothing; the ballast release (a separate file's truncation) is the only pre-settlement space step and erases no store page; arm 4b stages a post to R2 with R2's deletion queued (settled before the deletion) and a node-global `vox trust` under the floor (no room event needed), with the two mutants |
| R6-2 | Only "(3)'s commit fails" reached the second-failure exit; repair (`db.rs:1658-1670`) and `compact()`'s forced initial durable commit (`db.rs:1284-1300`, `force_commit = true`) are real failure points before the named commit | CONFIRMED (both read in redb 4.3.0) | SO-12 state 2(5): one exit for every native failure between the open and the settlement's return (ballast release, repair, the commit, the settlement's reads): handle dropped, no root published, no event, status `could not confirm it`, RD-7 told once, reopen after 5 s, nothing reclassified; a refused open stays its own retried state, never a fabricated latch; with R6-1's order no I/O runs between the commit and the settlement, so compaction's commit is after it and its failure is a new generation's ordinary latch; arm 4b act 2 names the commit it faults (`recovery: confirming commit failed`), act 2-compact stages the post-settlement case, a mutant narrows the exit |
| R6-3 | SO-1's 20 s `retry_after` cap exceeds ADR-046's wire bound (50 ms–5 s, its refusal contract) | CONFIRMED (`ADR-046:1486-1487`) | SO-1: `retry_after` ≤ 5 s; `Busy` again while the deduplicated job runs; the fifth-request path uses the same cap; the 60 s pin outlasts the run of retries; arm 4 asserts every `Busy` ≤ 5 s on the cold 100,000-leaf fill; no wire change (ADR-046 unchanged) |
| reserve | The 16 MB reserve / 32 MB ballast is stated as an unconditional recovery guarantee; E-2 measured one APFS clone and no multi-GB repair peak | PARTLY (E-2's +0 blocks is measured for that clone; "every relocation layout" is not, and the multi-GB repair peak is inferred) | SO-12 state 3 names the insufficient-reserve outcome: redb rolls the failed step back (each `compact()` step is its own commit; the file keeps every row), the store latches and recovers as state 2 says, compaction is marked deferred with `compacting the store needs <n> MB more (free that much, in any file, and Vox continues by itself)` in the rooms' readable line and `vox status`, and runs again only when free disk has grown by `n`; nothing is created, nothing restarted; the multi-GB peak stays owed to ADR-045 J5 |

Also applied: ADR-041 revision 7's SO-10 row carried as written (`Rewriting`, the restart's
exit-0 line, `VOX_TEST_REWRITE_HOLD_MS`); amendment 7 quotes its anchor (ADR-034 SR-5); the
E-7 landing prose no longer says every unflushed commit is lost (R5-3's closure note).

### Seventh review (`adr-047-sol-review-7`, 2026-11-13): verdict "needs revision", four findings and C1

Each was retraced on tag v0.4.30 and redb 4.3.0; ADR-044 RD-7 revision 13 (frozen
`ADR-044.026dae4c3`) was read as the current owner of the waiter rule.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R7-1 | The insufficient-reserve branch deferred compaction alone; a reclamation batch that failed for space was re-run first at the next state 3, before the readable exit, and could loop through recovery with no space change | CONFIRMED (revision 9's own text; redb gives no maintenance retry gate: each batch is one commit, `db.rs` has no such state) | SO-12 state 3: the failing operation (compaction, retention, room deletion, flow cleanup, sweep) is recorded as deferred with its `needs` before the store re-enters recovery; the next state 3 skips it, publishes the rooms readable with the line naming the operation and `n` MB, and re-runs it from its cursor only when free + ballast has grown by `n`; state 2(5) names the rule; arm 4b act 2-reclaim (30 s with no second attempt and no reopen, then continuation) and the deferral mutant |
| R7-2 | Repeated and fifth-request `Busy` used the remaining estimate capped at 5 s only; a job with 20 ms left or an overdue one would emit a retry time under ADR-046's 50 ms minimum | CONFIRMED (`ADR-046:1486-1487`, 50 ms to 5 s) | SO-1: `max(50 ms, min(estimate, 5 s))` on every `Busy` this ADR emits (first, repeated, fifth request, overdue); arm 4 asserts both bounds, stages a request with under 50 ms of estimate left, and the unclamped-remainder mutant |
| R7-3 | The lost-Admit fixture was staged in a post-header act, where the `None` Admit survives with its header, so the existence mutant could not go red; RD-7 delegates a pre-header lost-Admit act | CONFIRMED (`durable_commit` carries every earlier `None` commit; E-7's post-header case keeps the failed commit's rows) | arm 4b act 1-pre: the ledger entry durable in a prior flush, the Admit at `None` in the suffix, the fault at a data-page write before any header, confirm and settle; the Admit's effect absent and its person-visible result RD-7's; the existence mutant reports it done, PRODUCT |
| R7-4 | The early-event mutant was judged on the held post, but with the event triggering nothing in RD-7 the post's outcome does not change | CONFIRMED (SO-12 state 2(4) as revision 9 wrote it) | arm 4b: the mutant is judged at the boundary it breaks — `StoreRecovered` logged before `recovery: confirmed`, status dropping `recovering the store` while the confirming commit has failed, a consumer parked on `StoreRecovery(R1)` released into a room that answers `cannot save` — and the held post's outcome is left to RD-7's early-success mutant |
| C1 | "tens of indexed reads, under 100 ms" was copied from RD-7 r12, which ADR-044's twelfth review (R12-5) found unsupported | CONFIRMED | SO-12 state 2(3): the settlement runs on the recovery owner's blocking thread, its cost is RD-7's (r13: the unflushed suffix × 1–2 reads, no bound), its length and the suffix size are recorded in J5(h)'s and arm 4b's run records; SO-12 states no bound, caps nothing, times nothing out |
| audit | The failure notification said "failed before its durable commit" for a settlement-read fault after a successful commit; the sibling row restated a waiter outcome | CONFIRMED | state 2(5) names the stage that failed (open/repair, the commit, the settlement's reads after a successful commit); the RD-7 row cites RD-7's rule and names no outcome; the repair-fault mutant has its own knob (the repair commit's `fsync`), the `_RESULT` hold released under a held following recovery, and judges the original answer and its immutability at the recorded moment |

RD-7 revision 13's two changed facts are carried: fact 5 (a refused open is not a failure, tokens stay pending; one notification for any native failure from the open to the settlement's return) in state 2(2) and 2(5); fact 3 (the settlement on the recovery owner's blocking thread, its length in the run record, no bound) in state 2(3); arm 4b's fixture is RD-7 r13's list (the source-identity step held in both schedules, the consumed-then-expired step, the Received prepared without an input receipt, the offer dismissal, the lost Admit in act 1-pre) with its four mutants.

### Revision 10: the task cut's ADR defects (D1–D22) and the cross-ADR asks

| Item | Disposition | Where |
|---|---|---|
| D1 | closed by r9 (the settlement before any write; the ballast release is the only pre-commit space step) | SO-12 state 2(2)–(4) |
| D2 | closed by r9 and r10 (RD-7 r13's fixture; state 2(6) exists) | arm 4b |
| D3 | fixed: the held write's answer is RD-7's assertion; the hold covers a post and a Session admission (X044-16) | SO-12 arm 2 |
| D4 | closed by r9 (one reopen, one phase) | state 2(2) |
| D5 | fixed: SY-26's commit precedes the sweep's first batch (X046-25) | SO-2 step 4 |
| D6 | fixed: R2 is the decider's; the R1 sweep items are gone; SO-3 void; Appendix A's row and the decider's-answers line follow | SO-1 Depends on, SO-2 step 4, SO-3, Appendix A |
| D7 | fixed: SY-18 r7's kept facts classed (`index` for anchor, `control_through`, cuts, the gapped continuation; `messages`/`baseline_bytes` for the baseline); SY-18's naming prevails where it names one | SO-15 |
| D8 | fixed: the proof reads `vox status --json` `store.redb.stored_bytes` (the tick's `stats()` sample) | SO-15 proof |
| D9 | fixed: the 3 GB clone is lost (row 64's words); E-8 runs on ADR-045's grower snapshot; a slow `stats()` is sampled at most once a minute and status says `sampled <n> s ago` | SO-15, Experiments |
| D10 | fixed: one fixed 40 MB bound; E-4's figure is the v0.4.30 verdict, which may be "not red" | SO-6 arm 1 |
| D11 | fixed: a test-side member speaking R2's wire (V431-042-08's client) asks positions 3–6; ADR-046's B2 slow-member act named | SO-1 proof |
| D12 | fixed: the 100,000-leaf root is produced by the product under `VOX_TEST_SEED_FEED`; v0.4.30 CANNOT MEASURE (`Head` is R2's) | SO-1 arm 4 |
| D13 | fixed: `VOX_TEST_ADMISSION_FAILS` is a `Profile("locked")` → `NotAdmitted` (`roster_save.rs:207-213`, `joinstream.rs:1400-1412`) and its `:212` assertion stays; a new `VOX_TEST_ADMISSION_STORAGE_FAILS` stages `Error::Storage` in both placements; the v0.4.30 claim is INFERRED from `:1411` and observed only on the optional image arm | SO-14 proof |
| D14 | fixed: the leave arm restated on ADR-049 Journey A (c)/(m) and LE-4's stages, on SO-11's 256 MB image; `leave.rs:58` | SO-9 proof |
| D15 | fixed: a corrupt-store arm with staging (the header overwritten on a stopped scratch node), assertions and mutant | SO-9 proof |
| D16 | fixed: optional in tree, blocking as J5(i)'s compaction act | SO-10 proof, ADR-045 row |
| D17 | fixed: `DEFAULT_STEP_TTL_MS` (`step_policy.rs:18`) and `STEP_RETENTION_FILE` (`node/paths.rs:52`); "add a step-retention arm"; the listing prints the setting in ADR-042's words | SO-8 |
| D18 | fixed: the stopped node's store opened by the apparatus with redb 4.3.0, `stored_bytes` and pages against the rows' bytes | SO-5 proof |
| D19 | fixed: arms 1d and 1c on R2's admission queue; 1c in SY-24's file | SO-11 proof |
| D20 | fixed: spike S-13, recipe in `rca-RcaChurn`, script lost | SO-13 |
| D21 | fixed: row 64's note once in Context for every `/tmp` receipt, and on the Links list | Context, Links |
| D22 | fixed: no `vox room repair`; NW-1; ADR-045 E-9; 16 MB; two days; E-2's 16 MB landed | Sibling ADRs, Alternatives, Links |
| X041-6 | carried in r9 | SO-10 |
| X044-2, over-budget serving | stated for RD-9: SO-1's newest accepted head; `EvidenceUnavailable` vs `Busy` as two cases | ADR-044 row |
| X044-16 | carried (D3) | SO-12 arm 2 |
| X040-17, X047-10 | carried: NW-1's row; the bump precedes notification; no consumer parks on its own event | ADR-040 row |
| X045-3 | carried: SO-15's allocation bounds; ADR-045 cites SO-15 | ADR-045 row |
| L1-15 | carried: the repair step deleted | ADR-042 row |
| L3-64-047 | carried (D21) | Context |
| X042-24, image size | carried: the 256 MB image; ADR-042 TR-25 changes its act | ADR-042 row, SO-9 |
| X046-25, upgrade ordering | carried (D5) | SO-2, ADR-046 row |
| X046-26 | carried: the third arm's three fixtures and assertions | ADR-046 row, SO-2 |
| X046-33 | carried: the baseline kept until the newer one is whole | ADR-046 row, SO-15 |
| join refusal words | carried: ADR-042's row for item 24 without the detail tail | SO-14, ADR-042 row |
| Session retention line | carried (D17) | SO-8 |
| arm 4b outcome | RD-7's | arm 4b |
| amendment quotes row 7 | fixed in r9 (ADR-034 SR-5 quoted) | Superseded and amended lines |

### Eighth review (`adr-047-sol-review-8`, 2026-11-13): verdict "needs revision", five findings

Each was retraced on tag v0.4.30, redb 4.3.0 and the frozen ADR-046 r9 (`9cd10f515`) and
ADR-049 r8 (`92b9111a7`).

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R8-1 | `needs = reservation − capacity at failure` is zero or negative in the branch it governs (the capacity already met the reservation), so the deferred operation is eligible again with no growth | CONFIRMED (revision 10's own formula) | SO-12 state 3: `baseline` = capacity at failure; `needs` strictly positive (the operation's reservation again, doubled on repeat, capped at the file length); re-run only when free + ballast ≥ baseline + needs; acts 2-compact and 2-reclaim stage capacity at or above the reservation, unchanged for 30 s, then a positive growth edge; a deficit mutant |
| R8-2 | SY-26's initialization moved before the sweep as one commit per room: a room's historical cuts are unbounded (30,000 × 72 B > 2 MB), SO-11 has no class for it, and the sweep that returns space cannot run before it | CONFIRMED (SY-26 r9 "one commit per room"; SO-11's classes) | SO-2 step 4: a migration-batch stage (≤ 256 keys, < 2 MB, admitted at 3 MB on the ballast), cursor `meta.sy26_cursor`, completion marker `meta.anchors_initialized` in the last batch, no `LiveWindow`/DAG row deleted and nothing read as migrated before the marker, kill behaviour per batch, an honest prerequisite in step 7's words; SO-11 names the class; a 300-cut short-disk root arm with two mutants; ADR-046 SY-26 is to reword |
| R8-3 | "reclaimed in the commit that completes the newer baseline" makes a bounded install into a history-sized deletion; SY-27 installs by reference and reclaims old chunks in a bounded `Reclaiming` state | CONFIRMED (SY-27 r9 state table, `:529-532`) | ADR-046 row and SO-15: Install switches the reference and marks the old baseline unreachable with its reclamation record, no old chunk deleted in it; old chunks go through SY-27's Reclaiming in SO-11's bounded batches; old bytes authoritative until the new reference is durable; class `index` as SY-18 r9 says (the local `messages`/`baseline_bytes` classing deleted, D7) |
| R8-4 | The inferred v0.4.30 baseline for an admission-stage storage failure (`usually the room passphrase is wrong`) is wrong: admission runs after `AdmissionPrepared`, the joiner's ACCEPTED dispatcher calls `rejected(r)` (`joinstream.rs:1214`) and `NotAdmitted` → `JoinNotAdmitted` (`:715`), the accepted-passphrase words | CONFIRMED (`joinstream.rs:712-718`, `:1214`, `:1394-1416`, `:1448-1455` at the tag) | SO-14: the admission-stage baseline is `then could not admit you` (red on the new words only); the passphrase sentence is the exchange-stage result (`:1448-1455`, coarse `Refused`); the pre-challenge refusal is arm (a); Storage/Io/Path mapped to `Unavailable` in the admission match (`:1403-1412`) and in the outer arm; the `:212` assertion untouched |
| R8-5 | The carry mutant claimed an OS refusal; below the policy floor a small carry can find free pages, so the red is not guaranteed | CONFIRMED (LE-4 (c) rows under 2 MB; stage (b) freed the bulk) | SO-9 leave arm: the mutant is judged on premature progress — the carry advanced or completed before the floor is freed — while the product keeps it parked with the source rows and key present and no `RoomRowsPurged`; then the floor is freed and the product completes |
| audit | `retain_original` is not a corrupt-open path (`store.rs:580-597` propagates the open error) | CONFIRMED | SO-9 corrupt-store arm: v0.4.30 UNOBSERVED, the first run's observation; the apparatus asserts the `Corrupted` precondition |
| notes | D12's fixture must keep one 100,000-leaf feed at width 200 and ≥ 2 `Busy`; D16's threshold fixture must write ≥ 64 MB; D10's 40 MB is a budget, not a measurement | CONFIRMED | SO-1 arm 4; SO-10 threshold arm; SO-6 arm 1 |

### Revision 11: ADR-044 RD-7 revision 14 (the decider's row 74, "one save, one trip")

RD-7 r14 withdrew the flusher, tokens, generations, the settlement snapshot and fence and the
six-fact interface. SO-12 is rewritten on its paste text and the eighth review's list ("Required
SO-12 changes if RD-7 chooses each ruled reply waits its own flush"):

| SO-12 element | Kept, changed or removed | Why |
|---|---|---|
| State 1 (drain, atomic read boundary, memory answers, holder naming) | kept; "the flusher holds no handle" → a ruled commit's handle is released when its `commit()` returns | physical recovery is unchanged |
| State 2(1) generation step and waiter notification | removed | no token or generation exists |
| State 2(2) reopen and repair, measured root contents, refused-open retry | kept as 2(1); the pending-old-token exception removed; the E-7 facts now explain why no verdict reads the roots | RD-7 r14: the in-flight commit was answered by its own caller, queued ones definitely |
| State 2(3) confirming commit + settlement call and cost | changed to 2(2): the confirming commit alone, before any write and before the event, with the reason stated (a repair is not proof the file takes a durable commit); the writer held until state 3 publishes; C1's cost sentence removed | the ordering still proves storage behaviour |
| State 2(4) settlement-return prerequisite | removed; state 3 follows the commit | — |
| State 2(5) failure exit | kept as 2(3): one exit naming the stage (repair or confirming commit), no root, no event, retry after 5 s; "RD-7 told once" and the bulk classification removed; a ruled save's result immutable both ways | eighth review item 3 |
| State 2(6) | removed | — |
| State 3 (reclamation, compaction, deferral rule with R8-1's edge, readable exit, re-save, event) | kept; "after the settlement" → after the confirming commit | — |
| Arm 2 | kept; the held write's answer is RD-7's | RD-7 r14 asks for it |
| Arms 4b and 4c | removed (their fixtures, holds `VOX_TEST_HOLD_DURABLE_*`, `VOX_TEST_RECOVERY_HOLD`, acts 1, 1-pre, 2's waiter half, RD-7's four mutants, the reclamation-before-settlement and settle-only-on-event mutants, the repair-fault waiter mutant) | they judged a waiter's verdict, which no longer exists |
| Arm 4d (new) | act 1 (post-header fault on a ruled commit: the command fails at once, recovery orders confirm → reclamation → event, the `None` rows carried by the header are shown, the post is never reported saved whether or not its rows are present), act 1-floor, act 2 (confirming commit faulted), act 2-repair, act 2-compact, act 2-reclaim; mutants: early event (R7-4), reclamation before the confirming commit, recovered row turned into success, narrow failure exit, no deferral, rebuild from the latched handle (the former 4c) | each proves storage ordering or immutability, not a verdict |
| Sibling RD-7 row, SO-11's deferred-flush credits, "flusher re-armed by `StoreRecovered`" (Terms, SO-11), J5(h) in SO-11 and the ADR-045 row | changed to RD-7 r14's words; J5(h) withdrawn; J5(i) keeps arms 2 and 4d | consumer migration (eighth review item 4) |

### Ninth review (`adr-047-sol-review-9`, 2026-11-13): verdict "needs revision", five findings

Each was retraced on tag v0.4.30, redb 4.3.0 and the frozen ADR-044 r14 (`a9bb34bdb`); ADR-046
revision 10 (`1aa0d5579`, ledger rows 76 and 77) was applied in the same revision.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R9-1 | Arm 2 and the RD-7 row promised the held Session admission "lands on retry via `NotCommitted`"; an admission whose own `commit()` errored is `Unconfirmed`, terminal, never replayed | CONFIRMED (`session_ingress.rs:831` maps `batch.commit()`'s error to `Unconfirmed`; `OwnedAdmission` `:256-271`; `host.rs:6221-6247` marks the room and does not replay) | SO-12 arm 2: two named schedules — the in-flight write (`cannot save: disk` / `Unconfirmed`, present or absent after recovery, never twice) and a separate admission queued behind it (`NotCommitted` at `begin_write`, its bodies retried after `StoreRecovered`); the RD-7 row says the same |
| R9-2 | Arm 4d's suffix was a Session step "admitted at `None`"; a Session admission is a ruled `Immediate` commit under RD-7 r14 and flushes any earlier `None` entry | CONFIRMED (`session_ingress.rs:539, 805-831`; ADR-044 r14 RD-7's ruled list) | arm 4d: the suffix is bob's five received entries at `None` after the fixture's last ruled commit with the Inventory held; the step is staged by its own commit and asserted apart; act 1-pre is the explicit pre-header product act on a populated root (70 → 50; re-sent on `Have`) and its stale-rebuild mutant uses a captured read |
| R9-3 | The 300-cut arm's kill lands after anchors are all written, so neither anchor-loss mutant goes red | CONFIRMED (SO-2 step 4's order: anchors first, then cuts) | SO-2 step 4 proof: 300 authors and 300 removals; author `W` in anchor batch 2 with a window start at 10 and size 2,000; the kill after anchor batch 1; `W`'s row at 10 renders on resume; the `LiveWindow` mutant leaves `W` at 1,873; the early-sweep mutant breaks a cut in cut batch 2 |
| R9-4 | The ADR-045 row and the numbered import list still exported arms 4b/4c, act 1-pre's lookup schedule and R1's `retirement_failed` fixture | CONFIRMED | both replaced with arm 4d's schedules and SO-11's R2 parked-admission assertion; J5(h) and the lookup gone from every live sentence |
| R9-5 | The "recovered row turns failure into success" mutant was judged on a `vox status` per-post verdict that does not exist (`api.rs::NodeView`) | CONFIRMED | arm 4d: judged on the original reply — recovery held after the fault, the post's non-zero answer already returned while the hold stands, no second terminal answer on release; the mutant's command is still running at the hold |
| audit | the early-event mutant's parked consumer must be a parked R2 admission, not a fresh post RD-7 refuses; the reclamation-before-confirmation red is the batch order, not a second latch; act 2-compact must honour the file-length cap | CONFIRMED | arm 4d as rewritten |

**ADR-046 revision 10 applied (one answer of at most 1 MiB; chunks, the assembly, `snapshot_held`, pinning, Retire and Reclaiming deleted):** SO-15's class sentence now says what a baseline is (the creator's fence-post summary, ≤ 1 MiB, one install transaction, `index`, at most 1 MiB per room, the previous summary deleted in the installing transaction); the ADR-046 row's R8-3 text (Install by reference, unreachable marking, Reclaiming) is replaced by SY-27 r10's contract; SO-1's "most recent chunk" is "the creator's latest fence post". SO-2 and SO-11 named no chunk or assembly and are unchanged.

**Dead text removed (r12):** SO-1's R1 cutover paragraph ("The other readers of a head, and their cutover under R1", R3-2, 20 lines) and its R1 cursor clause; SO-3's R1 body (Why, What changes, Depends on, Proof; 12 lines) — SO-3 is one void paragraph; arms 4b/4c's withdrawal sentence shortened to a cross-reference. Everything else that reads as history inside a passed requirement is a dated change mark and stays.

### Tenth review (`adr-047-sol-review-10`, 2026-11-13): verdict "needs revision", three findings

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R10-1 | `W`'s fixture held a bodiless header at 10, so SY-26's source (b) supplies the anchor when the window is deleted and the mutant stays green | CONFIRMED (ADR-046 r10 SY-26: anchor = least of (a) the window, (b) the lowest held missing-body unexpired header, else size − 127) | SO-2 step 4 proof: no locally held missing-body header below 1,873; entry 10 at the peer only; both conditions asserted before the mutant is judged |
| R10-2 | "at most 1 MiB of `index` per room" charged the wire payload; the stored row is CBOR `[version, nonce, ciphertext]` + AEAD tag + key + leaf header (`atrest/store.rs:219-226`, `btree_base.rs:1102-1119`) and does not fit a 1 MiB leaf | CONFIRMED | SO-15 and the ADR-046 row: the 1 MiB limit is on the encoded answer (framing included, ADR-046 r11); stored, a summary at the limit takes a 2 MiB allocation plus its index path, by SO-15's complete-sealed-row rule; E-3 calibrates a near-limit summary; no stored bound promised |
| R10-3 | Act 1-pre let bob's live repair race the loss observation and the stale-rebuild discriminator | CONFIRMED (SY-15 re-admits on `Have` with no ordering against the read) | act 1-pre: a loss-observation phase under a hold on bob's `Have` answers (no lease), then a repair phase; the stale-rebuild mutant judged inside the first; hold not engaged is APPARATUS |
| cleanup | nonbinding R1 words left in SO-1's head list, its Depends on and SO-2's crash paragraph | CONFIRMED | deleted (r13) |

ADR-046 r11 alignment: `!meta.anchors_initialized(room)` is stated as the sole unfinished-migration predicate; the summary limit is "at most 1 MiB encoded, framing included". ADR-046's ninth-review list for this ADR was checked: SO-15's staged-chunk accounting, the X046-33 chunk retention / by-reference switch / unreachable record / `Reclaiming`, and any assembly reclamation in SO-11 are gone (r12); SO-2 keeps the installed-baseline exemption, the marker-before-sweep order and the bounded migration.

### Eleventh review (`adr-047-sol-review-11`, 2026-11-13): verdict "needs revision", one finding

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R11-1 | A hold on bob's `Have` answers fences only the advertisement; `Range`/`Entry` repair derived from a cached hint or head (ADR-046 r11 SY-12, SY-14, SY-15) still reaches alice before the loss observation | CONFIRMED (at the tag, bodies arrive through `Range`/`Entry` and are written at `admission.rs:52` `stage` / `:681` `start_entry`, independent of a new `Have`) | act 1-pre: the fence is a `test-knobs` hold on alice's received-admission boundary for the five coordinates (`VOX_TEST_HOLD_RECEIVED=<room>:<author>:<from>-<to>`), no lease/writer/room lock, engaged before the fault (log line, else APPARATUS), held through read, restart and read with no `admitted` line for those coordinates (else APPARATUS), then released for normal catch-up; the stale-rebuild mutant judged inside it |

## The decider's answers (2026-11-13)

Ledger rows 48–51 and 32, applied in this revision. Each answer is the decider's; the
requirement that carries it is named.

1. **Q1, step retention and budget.** No byte budget; and "lets change from seven days to two
   days": step retention is 2 days by default (SO-8, amendment 8). Appendix B, SO-15's
   projection and the operator's figures are recomputed on two days.
2. **Q2, the private record's signature.** One signature, the author's root composite (SO-4,
   amendments 4 and 5). The table below is the comparison he chose from; it is kept as the
   record of what the other options lose.

   | Attacker or observer | Two composites (v0.4.30) | **One root composite (chosen)** | One sender composite |
   |---|---|---|---|
   | An ordinary reader with the released chain secret, not the author's signing key | cannot forge the author's records; can withhold or replay ciphertext, subject to the recipient's iteration checks | the same | the same |
   | A compromised sender generation (chain and sender signing key), root intact (ADR-006 S-6) | the root signature blocks new forged records | blocks them: the forger lacks the root key | can forge that generation's records; rotation stops future generations only |
   | A compromised whole author identity | can sign and equivocate | the same | the same |
   | A removed drive holder with old symmetric keys | cannot read rotated generations nor sign; keeps what it read | the same | the same, provided its old public key row remains |
   | Reorder, drop or replay by a transport or member | signatures prove neither completeness nor freshness; the live iteration, grant and duplicate checks constrain acceptance | the same | the same |
   | A late permitted holder | gets post-grant steps and refreshed lifecycle only (SA-8) | verifies every record with the author's root key the room knows | must hold the sender public key of every generation it verifies |
   | An auditor or a holder whose receiver state is gone | verifies with the admitted root key | verifies with the admitted root key | cannot: a bare retained public key is not a root certification |

   Room messages keep their two signatures (ADR-008); that was not put to him and Main lists it.
3. **Q4, recovery after a write failure.** Recover in place: rooms readable, not writable, until
   done; FX-33's sentence replaced as proposed (SO-12, amendment 3). E-2 and E-7 precede the
   final design, as the review requires; their landing places are in SO-12.
4. **Q5, a store redb reports corrupt.** Left untouched and named in status (SO-9). He noted he
   has never experienced real corruption; the rule exists so the product never moves a store
   aside by itself (fix-list item 66, beast's `store.redb.failed-1`).
5. **Q6, existing stores.** Converted in place at the first v0.4.31 start (SO-2). The
   fresh-profile alternative is withdrawn: it conflicts with the binding rule that no real data
   is deleted or reset (AGENTS.md).
6. **Q7, the in-tree full-disk journey.** Optional, against this ADR's recommendation (SO-11,
   SO-12, SO-14: `optional-proofs`, loud when not run). The fleet's full-disk journey (ADR-045
   J5) and the stall staging (FG-20) remain blocking as fleet journeys (confirmed, row 59);
   SO-14's admission-failure arm blocks in tree without an image.
7. **Q8, the backstop.** At daemon start and on `vox node compact` only (SO-10).
8. **Row 32, where the gate runs.** Inside VMs: the APFS image is attached inside the macOS
   guest, a sized tmpfs inside the Linux VM; nothing runs on a host (SO-11's apparatus).

Nothing else is open to him from this ADR. E-1, E-2, E-7 and E-10 are measured
(`store-experiments`); ADR-046's R2 is his choice (ledger rows 57, 62), under which SO-1 holds
and SO-3 is void (r10).

## Links

- ADR-003 H1, H3; ADR-005 J-17; ADR-006 S-6, S-8, S-10, S-12; ADR-008 LS-5, LS-8, LS-34; ADR-010
  AR-3, AR-18, AR-20, AR-27–AR-34; ADR-018 §7; ADR-029 SC-2b, SE-1; ADR-031 SA-7–SA-9; ADR-034
  FR-4–FR-8, SR-1–SR-5, PF-2; ADR-036 H-6, H-7; ADR-037 R4, R5; ADR-038 FX-22, FX-29–FX-33.
- ADR-040 NW-2; ADR-041 RS-13; ADR-042; ADR-043; ADR-044 RD-2, RD-7, RD-8, RD-9; ADR-045;
  ADR-046 SY-8, SY-13, SY-14, SY-16, SY-18, SY-21, SY-24, SY-26; ADR-048; ADR-049; ADR-050.
- Reports: `rca-StoreSize`, `rca-RcaChurn`, `rca-RcaPreparing`, `rca-RcaSchedStall`, the
  consolidated analysis of 2026-11-12, plan C, `adr-047-sol-review`, `adr-047-sol-review-2`,
  `adr-047-revision`.
- Receipts (all lost in the reboot of 2026-11-13; figures recorded in the reports above; to be
  re-run as the fleet baseline, ledger row 64): `/private/tmp/vox-rca/store-size-samples.tsv`, `/private/tmp/vox-rca/beast/node-dir-listing.txt`,
  `/private/tmp/vox-rca/mac/{current-store-sizes.txt,redbstat/}`, `/tmp/rca-StoreSize/{n100.log,n1500.log,compact.log,clone.redb.groups.json}`,
  `/tmp/rca-RcaChurn/hist-o6z3.txt`, `/tmp/rca-RcaPreparing/{enospc.py,enospc-room.log,enospc-package.log}`,
  `/tmp/adr047/{exp1.log,exp2.log,exp3.log,probe/src/main.rs}` (revision 2; the clone and run
  files deleted at the end), `/tmp/RcaSchedStall/receipts/{exp.log,exp2.log,A-stalled.json}`.
- External: RFC 6962 §2.1; Lu et al., "WiscKey", FAST '16; BadgerDB `ValueThreshold`; RocksDB
  BlobDB; SQLite overflow pages, `auto_vacuum`, `SQLITE_FULL`, `max_page_count`; LMDB overflow
  pages and `mdb_copy -c`; etcd maintenance (`--quota-backend-bytes`, `defrag`, NOSPACE);
  PostgreSQL 16 §29.2 "Disk Full Failure"; CockroachDB and Pebble's ballast file
  (`cockroach start --store=…,ballast-size=`; `pebble/vfs` `Ballast`); redb changelog 4.2.0 (I/O
  latch), 4.4 (`compact()` free regions), 4.5 (`Database::close()`); TLS alerts; SSH disconnect
  codes.

## Appendix A — Every stored structure, one test

The test: what is each byte needed for, and for how long? Verdicts: **keep**, **shrink**,
**prune** (with its rule), **delete**. "Data" and "disk" are omp-work's, 19:00Z Nov 12
(`rca-StoreSize` §1; this revision's histogram). "Has a reader" is not a keep verdict; each row
names what needs the byte after the work that wrote it has ended.

| Structure | Data | Disk | Needed for | For how long | Verdict | By |
|---|---:|---:|---|---|---|---|
| Proof records (`ProofRange`, 212–216 B, 502,406 rows) | 128.0 MB | 1,052.0 MB | nothing: every range is derivable from headers | — | **delete** | SO-1, SO-2 |
| Verifier cursors (12.3 KB, 3 rows) | 0.04 MB | | resuming a fetch after a restart (R1); nothing (R2) | while the fetch runs (R1) | **prune** at fetch end (R1); **delete** (R2) | SO-3 |
| Author frontier and held-interval state (author states; interval descriptors 71 B, about 2·log₂ n per interval) | ≈ 1 MB | | what sync keeps (SY-18): newest accepted head, intervals, their descriptors | life of the feed | **keep**, packed | SO-1, SO-5 |
| Other sync bookkeeping (obligations 104–109 B, flow cursors, parent and prefix receipts, live window, `prior_heads`) | ≈ 4.6 MB | 77.8 MB (with the above) | nothing under R2 (the decider's choice; ADR-046 SY-18 keeps the anchor, `control_through`, the recorded cuts, the baseline, the gapped continuation and the descriptors instead) | — | **delete**, all of it, in SO-2's sweep after SY-26's initialization commit (r10: D6) | SO-2, ADR-046 SY-18, SY-19, SY-26 |
| Validated headers (≈ 3.8 KB, one per entry) and the contexts they name | ≈ 20 MB | | acceptance, fork detection, serving (SO-1 derives from them) | life of the entry | **keep** | |
| Head objects per author (signed heads, ≈ 3.5 KB; the 2K–4K EntryIndex bucket, 7,616 rows, 29 MB, is their upper bound) | ≤ 29 MB | ≤ 31 MB | the tie of every held position (SO-1: the newest accepted head of size ≥ p); fork evidence; a running fetch's target (R1) | newest accepted head: life of the feed; fork witnesses: life of the fork; others: nothing | **prune** by reachability: everything but the newest accepted, fork witnesses and a running fetch's head, in the commit that accepts a newer head; the `source_heads` tree **delete** | SO-1, SO-2 |
| Inclusion receipts (≈ 4.3 KB each in an 8 KB page, one per entry) | ≈ 18 MB | ≈ 34 MB | nothing: the position index and the newest-head tie are the acceptance evidence (ADR-044 r3, ADR-046 r2) | — | **delete** under R1 and R2 | SO-1, SO-2 |
| Entry index locator and tree pages | ≈ 85 MB | ≈ 160 MB | finding an entry | life of the entry; the pages that indexed proof keys go with them | **shrink** (≈ −70 MB with the proof keys, INFERRED); new pages fit 4 KB | SO-2, SO-5 |
| Step: header (≈ 100 B) | | | AEAD associated data, replay check, serving | life of the record | **keep** | |
| Step: ciphertext (body + 76 B) | | | re-serving the author's bytes to later drive holders (SA-7, SA-8) | life of the record (steps: 2 days by default, SA-9 as amended; openings and ends: message retention) | **keep** | |
| Step: one composite signature (3,373 B) | 133 MB | 162 MB (one 4 KB page each) | author authentication (Q2) | life of the record | **keep**, in its own row | SO-4 |
| Step: the second composite signature (3,373 B) | 133 MB | | nothing the kept one does not give (the decider's Q2 table) | — | **delete** for new records; stored v2 records keep it until they expire (steps) or for their life (lifecycle records, a few MB) | SO-4 |
| Step: plaintext cache row (≈ 110 B + body) | ≈ 55 MB | | showing the step without a key; derivable: the generation's retained chain opens it (C-22) | — | **shrink** to a 60-B metadata row (`created`, `kind`, `session_id`, length, body hash); the body is opened on demand | SO-4 |
| Step: first-seen, attention (≈ 60 B); seal (34 B) | | | retention ageing (AR-32; a sender's future timestamp must not extend retention); the attention boundary | life of the record | **keep** | |
| Steps in all (39,547 rows; 14,315 in repo-to-cve) | 398.3 MB | 507.2 MB | | | **shrink** to about 300 MB on disk (334 MB with the clear copy, computed) | SO-4, SO-5 |
| Session index descriptors (269 B) | 12.4 MB | 152.1 MB | the fold's source record, bundle parts, `Events`, `Names`, `Changes` | life of the record it locates | **keep**, not re-put, packed (→ about 14 MB) | SO-5, SO-6 |
| Session index tree pages (4.6–8 KB, about 60 rows each) | 27.5 MB | 46.7 MB | Session listings, activity, files | life of the records | **shrink**: new pages split by encoded bytes to one 4 KB page (→ about 36 MB after one rebuild, more pages of fewer rows) | SO-5 |
| Drive state (8,971 B; rewritten each step) | 9 KB | | the ratchet (S-12, AR-20) | always | **keep**; written per changed chain | SO-7 |
| Session attention ledger | 0.4 MB | 1.0 MB | pending attention and the resolved marks that stop a redelivery after restart | pending: until resolved; resolved marks: the life of the record they mark | **keep** | |
| Log entries (7.5 KB: skeleton, authenticator, payload with signature) | 30.6 MB | 47.8 MB | the replicated log (ADR-008) | body: the room's retention (AR-31); skeleton and signatures: the life of the room (governance bodies have the authority lifetime of their effect) | **prune** by retention (exists); two signatures: Q3 | |
| Plaintext cache, messages (543 B) | 2.8 MB | 3.9 MB | showing messages without a key | the body's retention | **prune** with the body | |
| First-seen rows (45 B) | 0.3 MB | 15.5 MB | retention ageing (AR-32) | while a retention obligation needs the local baseline; a bodyless skeleton after its last body-related action needs none | **prune** then; packed (→ about 0.5 MB) | SO-5 |
| Governance index facts and pages | 8.1 MB | 39.8 MB | who may read whom (ADR-038 FX-22); removal and readmission cutoffs; fork and consent evidence | life of the room for current authority, cutoffs and evidence; a superseded snapshot that is derivable: nothing | **keep**, packed (→ about 9 MB); derivable snapshots UNKNOWN until the projection's author counts them | SO-5 |
| Key material, prekeys, receiver states, ingress receipts, history demands | 0.5 MB | 0.8 MB | distinct lifecycles: a consumed prekey (replay safety), a generation (until its last record expires), an ingress receipt (until consumed), a demand (until completed) | each its own | **prune** each at its own end (exists for prekeys and demands; receiver generations end with their last record) | |
| `meta`, `sek_wraps`, system tables | 0.2 MB | 0.3 MB | the store itself; SO-15's ledger joins it (one row per room and class) | always; a room's rows go with the room | **keep** | |
| Branch pages | — | 50.5 MB | routing the live trees | always | **keep** (fall with the leaves) | |
| Leaf slack | — | 1,401.8 MB | nothing | — | **delete**: the stranding trigger (SO-5); the power-of-two rounding of large rows stays (215 MB) | SO-5, SO-10 |
| Free pages | — | 819.2 MB | reusable headroom, not content | — | **delete** by rewrite or compaction when the ratio trips (a backstop, not a steady-state bound) | SO-10 |
| `store.redb.failed-N` (beast: 805 MB long, 385 MB of disk) | — | 385 MB | a hard link to a superseded inode; nothing once the live store opened | — | **delete** after the live store opened and validated | SO-9, SO-2 |
| `store.redb.rewrite` | — | up to the packed bytes | a candidate until the rename | while the rewrite runs | **delete** at start if present; never kept | SO-9, SO-2 |

## Appendix B — The operator's content after each requirement

Content: 4,335 log entries, 39,547 steps, 5 rooms (omp-work, 19:00Z Nov 12). "Measured" rows
were run on the clone with redb 4.3.0 (Context); "computed" rows use the measured per-row
distribution and the packed-bytes model (within 2% of the measured rows). Three columns are
kept apart: data (the rows), disk use (`du`, what a rewritten file occupies), file length
(`ls -l`; after a rewrite it is redb's growth step above the disk use, 1,078 MB for every
rewrite here, sparse; after compaction it is what compaction left).

| After | Data | Disk use | File length | Basis | What changed |
|---|---:|---:|---:|---|---|
| v0.4.30 | 740 MB | 2,146 MB (`du`); 2,193 MB in use | 3,012 MB (4,295 MB at 21:38Z) | measured | — |
| v0.4.30 content, rewritten as it is | 740 MB | 1,031 MB | 1,078 MB | measured | slack the bulk copy still leaves (279 MB); free pages gone |
| SO-1, SO-2, SO-3 and one rewrite (proof rows and cursors only; receipts, old heads and `source_heads` not yet modelled) | 612 MB | 874 MB | 1,078 MB | measured | −128 MB proof records and cursors; growth of 320 MB/h ends |
| SO-1–SO-3 with the sweep and in-place compaction instead (a short disk) | 612 MB | 1,642 MB | 1,642 MB | measured | no second file needed; slack stays until a rewrite |
| + SO-5 two tables | 612 MB | 835 MB | 1,078 MB | measured | small rows packed at 93%; 215 MB of large-row rounding remains |
| + receipts, old heads and the `source_heads` tree deleted | ≈ 575 MB | ≈ 790 MB | ≈ 1,078 MB | computed (−18 MB receipts, −≈ 20 MB heads INFERRED from the 2K–4K bucket, their 8 KB and 4 KB pages) | day zero after SO-2, every part of SO-2 applied |
| + SO-4, one signature in its own row and no clear copy, after the steps have turned over under a 7-day retention (the figure before the decider's ruling, kept for comparison) | ≈ 430 MB | ≈ 560 MB | ≈ 1,078 MB until the next rewrite | computed from the measured distribution (steps 508 → ≈ 300 MB) | a projection, not a day-zero figure |
| + SO-8, step retention 2 days (the decider, 2026-11-13): the step population at the operator's rate is 2/7 of today's (about 11,300 steps; the busiest room about 4,900) | ≈ 215 MB | ≈ 345 MB | ≈ 1,078 MB until the next rewrite | computed (steps ≈ 300 → ≈ 86 MB of disk; 2/7 of the step rows, same distribution) | a projection: it needs two days of expiry after the upgrade and a later rewrite or compaction to shrink the file; the first sweep after the upgrade removes about 5/7 of the stored steps at once (28,000 rows, reclamation batches, a few minutes) |
| + SO-6, SO-7 | same | same | same | | −487 page writes/s in repo-to-cve; −9 KB written per step |
| + SO-9 | — | — | — | | beast's disk: −385 MB (`store.redb.failed-1`) |

Not in the table: SO-5's page-split saving on index pages that never change (unknown share of
83 MB of EntryIndex pages, excluded) and the ≈ 70 MB of EntryIndex tree pages the RCA attributed
to proof-row keys (INFERRED; the drop rewrite could not tell sealed pages apart, and the 612 MB
data row already includes whatever of it the single-table rewrite kept). robert-work's 6.66 GB
and beast's 6.44 GB (4.1 GB of disk) are not scaled from these figures; the fleet run measures
them.

Steady state: each message adds about 9 KB + 2 × body of data plus 15 KB of entry index
(24 KB for a 325-B message), and each step about 5 KB of disk plus its body (5.3 KB for the
median body: a 0.6 KB packed row and a 4 KB signature page), kept for the room's step retention
(2 days by default); at the sampled burst rate (1,712 steps per 2 hours) a room holds about
41,000 steps and 220 MB of disk at the 2-day steady state, at the 7-day average the node holds
about 11,300 and 86 MB (the table's figure). In use stays within 1.5 × packed and the file
within 2 × in use, or the backstop runs at the next start or `vox node compact`; expiry alone does not shrink a running
file (SO-10). SO-15 states the growth bound the proofs assert. Conversion runtimes and peak disk
use on the operator's 6 GB stores are UNKNOWN until ADR-045's fleet run; the one 3.01 GB
measurement is not transferred to them.
