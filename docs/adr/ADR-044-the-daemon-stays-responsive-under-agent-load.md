# ADR-044: The Daemon Stays Responsive Under Agent Load

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted (2026-11-13) as the design for v0.4.31, under the decider's authorization
of 2026-11-13 ("post review can accept them too"), after the eighth independent review by
GPT-6.1-Sol found it ready for acceptance (`adr-044-sol-review-8`) and after the decider answered
its four questions on 2026-11-13 (recorded in "The decider's answers"). This is design acceptance
only: implementation, acceptance and delivery are recorded on the source-bound issues, separately
from decision status. It also records his own words of 2026-11-12 on the proof records (RD-9).
Nothing in this ADR is built; every change below is written as what is to be done. Revision 9
(2026-11-13) changed one sentence of RD-7, the verdict of an old-generation waiter after a
reopen, after ADR-047's E-7 measurement on redb 4.3 (`store-experiments.md`,
`store-exp-receipts/e7-fault-injection.log`); revision 10 restated it with a persisted watermark;
revision 11 (2026-11-13) replaces every counter with a lookup of what the caller wrote, after the
tenth review and Main's decision that RD-7 alone owns the waiter rule (ADR-047 SO-12 owns the
recovery mechanics and cites it); revision 12 (2026-11-13) settles every waiter from one snapshot
behind a write fence, with the predicates enumerated from the code, after the eleventh review;
revision 13 (2026-11-13) completed the predicates and carried the correction batch (RD-9 adopts
ADR-046 SY-18 and ADR-047 SO-1's evidence and `Busy{retry_after}`; the RD-8/RD-9 cutover; RD-16's
park; RD-14's runner and J3(c); the VM wording); revision 14 (2026-11-13) rewrites RD-7 to the
decider's ruling of 15:45 PST (ledger row 74, superseding row 28): one save, one trip, every
ruled commit `Immediate` off the actor, its reply from its own result; group commit and the whole
recovery settlement rule are withdrawn, and what existed only for them is deleted; revision 15
(2026-11-13) adds the table of every commit the actor's turn still reaches and derives the
cutover from it (Drive delivery's publication fence, room pause, services, own-key responses,
history activation), qualifies what a waiting commit is told by the backing it attempts, and
applies the decider's speed rulings (rows 80, 81: a 5 s per-post gate, figures recorded, no
target until measured); revision 16 (2026-11-13) adds the refused-key, held-note and Resume
rows to the cutover table, removes the last 300 ms figure, cites the measured v0.4.30 baseline,
and replaces RD-10's single queue with the two-lane rule of rows 82, 82a and 82b; the reviews of
revisions 2–13 stay as history. By the decider's row 83, an ADR passes once no P1 remains; the
fifteenth pass's P2 findings (R15-5, R15-6, R15-7) are owed to task acceptance
(`v0431-owed-p2`) and are not edited here. Revision 17 (2026-11-13) closes the sixteenth pass's
two P1s in RD-10: the obsolete all-room, whole-operation ownership text is replaced by
room-local, transaction-sized control turns (ADR-048 TC-4, TC-5), and the control bound is scoped
to the head of its lane (row 82c); its P2s are owed to task acceptance likewise. **Revision 17
is the accepted text**: the seventeenth pass (2026-11-13) found no P1 under ledger row 83; it
also closes ADR-048 review 11's R11-1, which was a finding against RD-10. The "Review record"
section lists each finding of all eight passes and the
requirement that answers it. Requirements changed since the first draft are marked *(changed)*,
those changed again in revisions 3–9 *(changed rN)*; RD-16 is new. Revisions 4–8 closed the
third to seventh passes' findings, each narrowly; revision 7 also records the decider's answers
of 2026-11-13, which close every question this ADR asked; revision 8 named ADR-045 J5(h) as RD-7
arm four's blocking proof, which revision 14 withdraws with the rule it proved.
**Date**: 2026-11-12
**Deciders**: Robert E. Lee
**Tags**: daemon, actor, store, durability, serving, preparation, restart, linux, install, latency
**Related**: ADR-018, ADR-026, ADR-034, ADR-036, ADR-037, ADR-038, ADR-040, ADR-041, ADR-042,
ADR-045, ADR-046, ADR-047
**Inputs**: the v0.4.31 fix list (items 15–19, and the serving side of items 13 and 14); plan B
of 2026-11-12; plan A §0 item 7 and its item 14 (the measured actor-queue wait); the root-cause
reports RcaSlow, RcaChurn and RcaPreparing and the consolidated analysis of 2026-11-12; the trial
of sync progress; the operator's evidence under `/private/tmp/vox-rca/`; the independent review
of this ADR. Code is cited at tag v0.4.30 (`8d71ab337`). The decider's rule for this release:
every known defect is fixed in it (AGENTS.md, "Releases").

## Context

On 2026-11-11 and 11-12 the operator ran his agents on four machines. Each machine's daemon
hosted one or two nodes, and each node ran up to ten OpenCode/OMP agent sessions that posted to
the room and sent their Session steps to it. What he saw:

- Daemons on a LAN with under 5 ms between hosts answered in seconds. beast logged "did not answer
  within 5 s" eight times; the Mac logged 63 silences of 8–27 s over the day.
- `vox status` and harness hooks were slow; a hook said "the vox daemon here did not answer
  promptly".
- Posts and announcements lagged. Readers fell hundreds of posts behind the busiest author.
- After every restart, a room said for minutes that it was preparing:
  `vox: node omp-beast: room o6z3… is still preparing: it waits for refreshing its Session
  records, for 30 s` (`beast/daemon-current.log:1440`, 14:57:13Z; again at `:1680`, 15:32:37Z).
  While a room prepares, a command on it is refused: "that room is preparing its saved history;
  …" (`crates/vox-core/src/node/api.rs:1803`).
- A Linux host printed at every start that its UDP receive buffer was too small.

Status words below: **KNOWN** = reproduced, or read off the operator's machines, with the
receipt named; **INFERRED** = fits the evidence, not reproduced; **UNKNOWN** = not explained, with
the experiment that settles it.

### What was measured, and at what load

The reproductions of items 15–17 ran on the v0.4.30 tag built with trace-only instrumentation
(`/tmp/rca-RcaSlow/vox-rca`; worktree `/opt/vox-worktrees/rca-RcaSlow`, 19 files of trace lines,
nothing that changes behaviour). The rig: four scratch nodes; node A is the author, with 10 named
OMP sessions delivering steps over the bridge; B, C and D read; A's store reached 0.5 GB and
8,473–8,632 log entries. Receipts: `/tmp/rca-RcaSlow/r1/runs/{grow1,L1-quiet,L2-oplike,L2b-oplike}/`
and `/tmp/rca-RcaSlow/sample-grow-A.txt`.

The load the rig offered is read from its code and log, not from its intent (review finding 11):

- Steps: 2 a second, sustained (`rig.log`: `steps=259 … 358` over 50 s in L2b).
- Posts: one poster, closed loop, that issues `vox room post` and sleeps only the remainder of a
  500 ms period (`/tmp/rca-RcaSlow/rig.py:344-353`). It offers 2 a second only while a post takes
  under 500 ms. Once posts took 3.5–5.4 s the acknowledged rate was about 0.27 a second
  (L2b `rig.log:187-190`: 164 → 172 acknowledged posts in 30 s). The 3.5–5.4 s is therefore the
  latency of a post offered one at a time while 2 steps a second arrive, on an 8.5 k-row store;
  it is not the latency at 2 acknowledged posts a second. L2's first 139 attempts failed at once
  ("that room is preparing"; `rig.log:173`) and are excluded from every figure below.

The operator's stores are 3–6.6 GB; the slowdown was already at its worst below 1 GB, because its
cost grows with unread rows and with saves, not with file size.

### Where the daemon's time goes at v0.4.30

Measured on that rig (L2 and L2b): one turn of the node's actor took 51 ms at the median, 187 ms
at the 90th percentile, 716 ms at most. The actor was busy 76 ms per second at the median and
324 ms per second at the 90th percentile in L2b (807 ms per second in L2). `vox status` took 58 ms
at the median and 581 ms at most; the same binary idle answers in 7–9 ms. `vox room post` took
3.5–5.4 s at the offered load above; on an 80-row room, 27–64 ms. Three things spend that time,
all on the actor or on the room's one pending write:

| what spends it | per event | events per second | actor time | fix-list item |
|---|---|---|---|---|
| each view publication walks up to 1,000 unread rows under the room's lock | 20–45 ms once a room has 1,000 unread rows | 20 publications or more, plus 2 per command | 98 ms/s (L2) | 15 |
| disk flushes run on the actor's own threads (Session-step admission, attention) | 20–81 ms each | 2 steps, plus attention turns | 40–160 ms/s | 16 |
| the node's save train: 80–102 save wakes a second; posts and served history wait their turn | 0.2–0.5 ms per wake, but posts queue behind about 100 saves a second | 80–102 | 40–50 ms/s | 17 |

`vox status` is a read request queued to the actor (`crates/vox-core/src/node/actor.rs:5498-5509`).
It waits for the actor's turn, for a publication if one is owed (`actor.rs:8050-8052`), and for
the answer. The actor then runs a second publication and a schedule (`actor.rs:8056-8057`) before
it takes the next request; those delay the next command, not the status answer already sent
(review finding, citation audit). So a status answer costs the actor's queue plus at most one
publication, and every status adds a publication to the queue behind it.

A fourth cost is not on the actor's thread but in its queue. A peer's history request is read off
the actor (`actor.rs:2543-2570`) and then sent to the actor as `NetEvent::SyncRequest`, handled
at `actor.rs:11933-11944` by `start_bounded_inbound` (`actor.rs:18820`), which needs the actor's
budget, ports and token counter. Plan A measured that wait on the heavy author in the sync
trial's B3-reach run, 1,277 admissions: 4 ms at the median, 60–84 ms at the 90th percentile,
12.0–15.7 s at most, before serving began (fast members: at most 0.7–1.5 s). KNOWN. Item 14 is
that wait plus the serving-side stand-aside below.

### C-15. Every view update walks up to 1,000 unread rows (fix-list item 15)

*What the person saw.* On a node whose rooms hold 1,000 or more rows it never marked read (every
agent node), every command and every received entry cost tens of milliseconds of the actor's time.
`vox status` answered in 58 ms at the median and 581 ms at most instead of 7–9 ms. Posts and hook
turns queued behind it. The cost never went away, because agent nodes never mark anything read.

*Root cause, KNOWN* (RcaSlow S1 #1: `sample-grow-A.txt`, 449 of 2,161 samples in `unread`;
L2-oplike `publish` span at most 166 ms, 98 ms per second; verified in code):

- `detail_of` (`actor.rs:455-484`) computes `(read_by, held, unread)` again whenever the room's
  display stamp or read-summary stamp changed (`actor.rs:474-483`). The display stamp changes on
  every post, step, received entry and reorder (`crates/vox-core/src/node/channel.rs:5936-5948`).
- `ChannelState::unread` (`channel.rs:8833-8861`) steps the rendered view newest-first until it
  meets a row this node read, at most `UNREAD_LOOKED` = 1,000 rows (`channel.rs:1130`). Each row
  costs three index reads. It runs inside the publication, under the room's lock, on the actor.
- The publication (`publish`, `actor.rs:24681`) runs at most every 50 ms for network events
  (`VIEW_COALESCE`, `actor.rs:412`) and before and after every client command
  (`actor.rs:8050-8056`).
- Nothing reads the result. `ChannelDetail.unread` (`crates/vox-core/src/node/api.rs:742-744`)
  appears in the tree only at its cache copy (`actor.rs:478`) and its constructor
  (`actor.rs:616`). The TUI, the app and the hooks count unread through `Request::Unread` and
  `Request::UnreadSummary` (`crates/vox-core/src/node/ipc.rs:7253-7256, 8040-8042`), answered off
  the actor from the room's committed snapshot (`crates/vox-core/src/node/channel/history.rs:372`,
  `:1697`; `saved_history_query`, `actor.rs:26037`).
- Why it is so: `547788e52` (2026-10-06) added the field so the TUI could seed its counts at start,
  from memory. `7bc390c74` (2026-10-14) moved the clients to `Request::Unread`, removed the last
  reader, and changed the view's call into the store-walking `ch.unread(store)?`. Since then the
  field has walked the store for nobody. ADR-038's cache of the trust picture in `detail_of`
  (#990, comment at `actor.rs:485-492`) left this walk uncached.
- The two walks that stay, `read_by_own` (`channel.rs:8866-8888`) and `held_own`
  (`channel.rs:8796-8826`), each step at most `READ_BY_SHOWN` = 128 rows (`channel.rs:1126`) and
  are consumed (the snapshot, the TUI, `room_cli`). They too run on every display change today.

*Why it was not caught.* V210-08 (`crates/vox-tui/tests/a_post_answers_promptly_while_a_peer_posts_proof.rs`)
bounds the post tail with two members and a small room. No proof opens a room with more unread
rows than `UNREAD_LOOKED` on a node that never marks read, and none times `vox status` there.

### C-16. Disk flushes run on the actor's threads (fix-list item 16)

*What the person saw.* While agents stepped, each step cost the daemon 20–80 ms during which no
command, no publication, no inbound stream and no sync step ran. `vox status` and hook turns
stalled. On the Mac two nodes share one daemon, so they shared the stall.

*Root cause, KNOWN* (RcaSlow S1 #2: backtraces of commits on runtime threads in L2b, 63 of 100
commits of 20 ms or more ran on `tokio-0`/`tokio-1`; 24 of 39 in L2; verified in code):

- The daemon's async runtime has two worker threads (`crates/vox-tui/src/daemon.rs:135-138`). The
  node's actor is a task on them.
- `NodeCommand::AcceptSessionBatch` (`actor.rs:8740-8789`) calls `session_ingress::admit` inline in
  the actor (`actor.rs:8768`). That opens a store batch
  (`crates/vox-core/src/node/session_ingress.rs:539`) of the flushed class
  (`crates/vox-core/src/node/store.rs:505-507`, `store.rs:1983`) and commits it
  (`session_ingress.rs:831`). One commit with `Durability::Immediate` ends in one flush
  (`vendor/redb/src/tree_store/page_store/page_manager.rs:1856`; two-phase commit is off), which
  on macOS is one `F_FULLFSYNC`. RcaSlow's "flushes twice per commit" is not what the vendored
  code does; the measured cost stands.
- The Drive branch of the same command (`admit_session_drive`, `actor.rs:23354-23413`) checks the
  author's trust and drive permission, the node-wide save gate, the room's instance, membership
  and the Session opening under the room's lock, then commits `session_ingress::admit_drive`
  inline under `with_current_computer_authority` (`actor.rs:23408`). The check and the commit are
  one actor turn, which is what makes them atomic today. `DeliverSessionDrive`
  (`actor.rs:23416-23470`) commits nothing: it writes one frame to the native socket under the
  same fences (`delivery.authority.with_current(|| delivery.frame.try_write(..))`).
- `Node::attention` (`actor.rs:23279-23352`) takes the room's lock (`actor.rs:23306`) and runs the
  operation on the actor (`crates/vox-core/src/node/channel/attention.rs`). The operation
  dispatch commits at `attention.rs:256-348`, the scan at `:517-537` and maintenance at
  `:634-646`, all flushed, all under the room's lock. ADR-038 FX-31 says "No commit's flush runs
  while the room's lock is held"; these paths do.
- Why it is so: FX-30 (2026-10-20) requires Session records on disk before the command returns.
  #1082 (2026-10-29) moved the room saves off the actor (`post_save.rs:582-696` prepares under the
  lock and commits after it is dropped) but left Session admission and the attention ledger inline:
  they do not take the room's pending write, and measured idle they cost about 0.5 ms (FX-30's
  measurement). Under load each flush costs 20–81 ms.

*Found on the way, not on the list (KNOWN by code).* Four attention paths open a write transaction
only to read the ledger, then drop it uncommitted: `attention.rs:173-175` (an Admit's notice),
`:206-208` (Prepare, Received, Observed), `:382-384` (the scan) and `:597-599` (maintenance).
Each takes the store's one writer (`store.rs:523`) and redb's writer for the length of a read, so
it waits behind every save and every flush. Plan B named only the scan. No operator log line is
attributed to it: the "attention selection remains pending" lines in his logs name computer trust
(`[count=351]`, 15:24:51Z) and an unacknowledged key-package attempt (`[count=409]`, 15:25:38Z),
which are ADR-040's.

*Why it was not caught.* The FX-31 journey (`crates/vox-tui/tests/nodes_of_one_daemon_proof.rs`,
`two_paired_computers_that_are_idle_exchange_nothing`, hold knob at `:5517`) holds a post's flush
and shows that status answers. It never delivers a Session step or an attention registration while
a flush is held.

### C-17. Serving history waits for the node's own saves (fix-list item 17)

*What the person saw.* The busiest author is the node everyone must fetch from, and it answered
worst. Readers' rounds toward it ended at the 20 s frame deadline. Nobody kept up with its feed: in
the sync trial's operator-shaped run B3, n-old1 stayed 436–495 posts behind y1 on every build
(`/tmp/trial-sync/runs/`). Its own posts took 3.5–5.4 s while its agents stepped.

*Root cause, KNOWN* (RcaSlow S1 #3 and S2; trial B2/B3 and B3-reach; verified in code). Three
mechanisms:

- (a) *Serving a proof is a write.* A served `Proof` query
  (`crates/vox-core/src/node/history_stream/server.rs:504` → `source.rs:1063` → `range`,
  `source.rs:999-1058` → `write_owned`, `source.rs:1015` → `write_owned_reserved`, `source.rs:679`)
  reserves the room's pending write (`source.rs:782`) for every tree range of the proof, about
  log2(n) ranges for a feed of n entries. A cache miss rebuilds the range and writes it as a proof
  record together with the context it generated
  (`crates/vox-core/src/node/channel/proof_range.rs:298-301`); a hit takes the same reservation.
  While the node's own post or authored save holds or waits for the pending write, a served step
  stands aside (`source.rs:744-761`): a first request for up to `PENDING_WRITE_WAIT` = 250 ms
  (`crates/vox-core/src/node/channel/pending_text.rs:21`) and then answers Busy; a continuation
  waits with no bound. The reader backs off from 200 ms doubling to 1 s
  (`crates/vox-core/src/node/ports.rs:279`) and starts its flow again. The comment at
  `source.rs:734-743` records why: a served write once won the race against the node's own post,
  and the poster paid a retry per post. Nothing bounds how long the saves keep their priority.
- (b) *A served read holds the room through its disk work, and the publication with it.*
  `read_reserved` (`source.rs:518-574`) takes the room's lock as an owned guard and keeps it
  inside the blocking read until the read is done. `ReadResource::with_snapshot`
  (`crates/vox-core/src/node/channel/history/read_resource.rs:360-383`) holds the resource's
  `publication` mutex through its whole callback, disk reads included; the actor's publication
  takes that same mutex while it holds the room (`read_resource.rs:497-533`, called from
  `publish` at `actor.rs:24920-24924`). So one slow served read stops the next view publication,
  and the actor with it. Readers of one room serialize on that mutex although redb reads run
  concurrently.
- (c) *The node's saves are one train with no priority for posts.* A post is held back while its
  room has a pending post, or while any room has one and commands are deferred
  (`crates/vox-core/src/node/actor/post_save.rs:329-334`). Held commands resume only when
  `store_save_pending()` is false (`actor.rs:7876-7877`), and that is true for every room's posts,
  policy, metadata, startup and leave saves (`maintenance_save.rs:622-634`). Fresh maintenance
  (Session moves, projection turns, governance, key packages) is let in under the same node-wide
  gate (`maintenance_save.rs:636-642`). The main loop (`actor.rs:7920`) picks at random among
  ready branches, so a resumed post and a maintenance turn race for the room's pending write. At 2
  steps a second the projection rebuild takes it 80–102 times a second, each a flushed commit and
  then an actor turn. A post waits behind a random number of 10–50 ms saves: 3.5–5.4 s.
- What L2b adds: on the loopback rig A answered no query slower than 100 ms in 400 s, while B, C and
  D's exchanges toward A ran to the 20 s frame deadline and B fetched one entry from A in 15 rounds
  (`L2b-oplike/B.status.final.json`). The time was spent before A started answering: in A's actor
  queue, which plan A then measured (above): up to 12.0–15.7 s.

*Why it was not caught.* V210-08 has two members, no Session steps and a small room.
`a_slow_sender_still_delivers_proof.rs` proves delivery from a slow sender. No proof puts the
serving node under its own agents' save train while readers fetch from it.

### C-18. "Preparing" after restart walks every agent post (fix-list item 18)

*What the person saw.* After `vox daemon --restart` a room said "it waits for refreshing its
Session records" for two minutes on the rig, and up to 2–13 minutes on beast (upper bounds read
from its log). Members were refused meanwhile, and the sync that followed ran about 30 s before
item 13 set in again.

*Root cause: cost KNOWN; beast's minutes INFERRED* (RcaSlow S4: 265–267 turns of 32 rows, 10–16 ms
of work each, 287 ms apart on average; RcaChurn C3 with `prep.py`: 1,500 candidate rows took
16–18 s in all six restarts; verified in code):

- `PendingSession::refresh_records`
  (`crates/vox-core/src/node/channel/pending_session.rs:1363-1518`) walks the `session_candidates`
  render index 32 rows per turn (`WORK_ROWS`, `private_session.rs:22`; loop at
  `pending_session.rs:1402`). That index holds every row that is a Session record *or whose text
  contains `session_name`* (`crates/vox-core/src/node/channel/entry_store/render_facts.rs:326-328`).
  The node stamps `session_name` into every post of a registered named session
  (`crates/vox-core/src/node/sessions.rs:576-588`, `fill_name`). So on an agent node every post is
  a candidate, while the walk uses only this node's own Session records
  (`row.author == self.me && is_record`, `pending_session.rs:1423`): tens of rows out of thousands.
  A second phase walks the private index's `Candidates` tree (`pending_session.rs:1454-1494`;
  `private_index.rs:230-250`) with the same own-author test.
- A turn that made progress sets the next due time 50 ms later (`PREPARE_RETRY`, `actor.rs:240`;
  `retry_after`, `actor.rs:6342-6349`; set at `actor.rs:20583-20588`), but nothing wakes the actor
  then. The readiness checks (`actor.rs:7884-7889`;
  `crates/vox-core/src/node/actor/preparation_save.rs:89-101`) run again only when some other
  branch fires: a network event, a save wake, or the 1 s tick. The governance work has its own
  timer (`actor.rs:7908-7917`); preparation has none. A loaded actor wakes about every 0.3 s; a
  quiet one once a second per 32 rows.
- The walk starts over whenever the candidates' root, the private lifecycle revision or the owed
  grant changes (`pending_session.rs:1380-1395`). The stage's own re-appended records are
  candidates, so each append restarts it.
- Beast's 2–13 minutes need either a slower wake cadence or repeated restarts of the walk (beast
  had 14 registrations, 7 dead). UNKNOWN which; experiment E-18 below settles it. The design
  removes both, so the experiment only sizes the proof's seed.

*Why it was not caught.* The restart proofs restart nodes with a handful of rows and no named
sessions; RcaPreparing measured `pub_rows=0` on a 3,714-row room whose posts carried no
`session_name`.

### C-19. Linux: the UDP receive buffer is too small, and the installer does nothing (fix-list item 19)

*What the person saw.* On IO, a stock Linux host, the daemon printed at each start:

```text
vox: UDP receive buffer 416 KiB: path-MTU ceiling 1452 bytes, not 8192 — the OS granted a smaller receive buffer than 8192-byte datagrams need (on Linux, raise net.core.rmem_max to at least 4 MiB)
```

(`/private/tmp/vox-rca/io/daemon-current.log:2987`, 19:27:22Z, and `:3717`, 19:40:46Z.)

*Root cause, KNOWN* (operator's files; code). Vox asks for a 4 MiB buffer (`UDP_SOCKET_BUFFER`,
`crates/vox-core/src/transport/quic.rs:344`). Linux silently caps it at `net.core.rmem_max` (about
208 KiB by default). `mtu_ceiling_for` (`quic.rs:434`, called at `quic.rs:792`) then drops to 1452
bytes and the daemon says so once per start. The manual tells the person to run
`sysctl -w net.core.rmem_max=4194304` and persist it (`docs/manual/install.md:133-150`); `install.sh`
has no Linux step (its only `sysctl` is the macOS Rosetta check, `install.sh:61`). beast's socket
shows the full grant (`rb8388608`, `beast/net-facts.txt:7`), so someone set it there by hand; IO's
does not. Bursts overflow small buffers: beast counts `RcvbufErrors 1336` since boot
(`beast/net-facts.txt:4`); the Mac counts 2,347 "dropped due to full socket buffers"
(`mac/net-facts.txt:11`). QUIC reads each drop as loss.

*Why it was not caught.* `install_sh_proof.rs` never asserts anything about the buffer.
`the_path_mtu_follows_the_socket_buffer_proof.rs` proves that the fallback is correct, which is the
symptom.

### C-13 and C-14, serving side

*Item 13, KNOWN* (RcaSlow S2). "last sync" moves only when one of this node's own outbound rounds
completes: `note_lane_sync` (`crates/vox-core/src/node/actor/bounded_sync.rs:4482`) is called at
three sites (`bounded_sync.rs:3732, 4063, 4434`) and read by status (`status.rs:384`). Served rounds
never move it. On the author under its save train, its own outbound rounds cannot take the pending
write within their 1 s turn, and the rounds it serves stall for C-17's reasons. The clock is dead
twice over on the one node that matters. Counting served progress is ADR-046's; how status says it
is ADR-042's.

*Item 14, mechanism KNOWN; the operator's figures INFERRED to be it.* No fixed 3 s limit exists in
the code. The operator's samples (`/private/tmp/vox-rca/mac/exchange-latency-221528Z.jsonl`, 60 s
at 1 Hz) show a 1–5 s spread (robert-work→rotlr2 4.8 s, →ehu3jm 3.6 s, →nytype 2.2 s; everything
else under 0.5 s). On the serving side two things produce it, both measured on the rig: the
inbound request's wait in the author's actor queue (plan A: p90 60–84 ms, max 12.0–15.7 s) and
then C-17(a)'s stand-aside per range (13 ranges at 8,000 entries, each up to 250 ms, ending Busy:
0.1–3.3 s). A third, on the reader's side, is ADR-046's. RD-16 removes the first, RD-8 the second.
E-14 is kept as verification after the fix, not as an open question.

## Terms

- **Actor**: the one task per node in the daemon that runs the node's commands, view publications
  and sync steps, one at a time. At v0.4.30 it runs on the runtime's two worker threads.
- **Blocking pool**: the runtime's separate threads for work that may block (`spawn_blocking`).
- **Flush**: the call that makes written data survive a power loss: `F_FULLFSYNC` on macOS,
  `fdatasync` on Linux. One flush makes every earlier unflushed commit durable too.
- **Ruled commit**: a commit whose reply promises the data is on disk; it is made with
  `Durability::Immediate`, one flush each, off the actor (RD-7).
- **Ruled set**: what ADR-038 FX-30 requires on disk before the command returns: own entries,
  consent, trust, keys, Session records, the format marker.
- **View publication**: the snapshot of every open room the daemon rebuilds after events (at most
  every 50 ms) and around client commands. `vox status` and the app read it.
- **Pending write**: the room's single slot that a write must hold to move the room's in-memory
  index roots. Posts and maintenance saves take it; at v0.4.30 served proof steps do too.
- **Owner**: whoever holds a room's pending write: a post, a maintenance turn, a Drive admission.
  `pending_posts` (`actor.rs`) is the actor's registry of owners.
- **Native-save shape**: the way #1082 runs a room save off the actor: capture the Computer
  authority and the attachment epoch on the actor; on a worker, acquire the Computer publication
  lease (`ComputerAuthority::acquire_publication`, `actor/computer.rs:109`), take the room's lock
  only to re-check its facts and prepare under the room's pending write, drop the lock, commit on
  the blocking pool, and install under the lock from the completion (`post_save.rs:470-700`).
- **Save train**: the node's own saves (posts, Session moves, projection rebuilds, policy, startup,
  leave, metadata) in the order the actor runs them.
- **Committed snapshot**: a read of what the store has already committed (redb MVCC; `ReadResource`).
  Any number may be read at once, alongside a writer. Committed is not durable (RD-7).
- **Read lease**: an immutable value taken from a room's `ReadResource` in a moment under its
  publication mutex: one MVCC snapshot, the published index roots, the authorization facts, the
  publication revision and the history instance (RD-8). A bounded disk read runs on a lease with
  no mutex held. What a lease read returns stays valid while the history instance is unchanged
  and the lease is not revoked; a newer publication does not invalidate it.
- **Serving book**: the structure, shared between the node's actor and its connection tasks
  behind one short mutex, that holds the serving budget, the inbound tokens per port, the
  `Running` entries status shows, and the proof handoff below (RD-16). Nothing waits or does I/O
  while holding it.
- **Proof handoff**: the bounded, per-peer, in-memory record of the descriptors and generated
  contexts a served proof exposed to that peer, kept in the serving book so the peer's next
  stream (`Query::Context`) can be answered and, for a returning author, authorized (RD-9).
- **Canonical range**: a verified Merkle subtree of an author's feed kept as acceptance evidence
  (`history_range`, `keep_history_range`, `sparse.rs:2475`): every subtree an author's own append
  formed (`sparse.rs:1839`), the full root of every committed head (`sparse.rs:2832`), and every
  prefix a receipt proved (`sparse.rs:3932`, `:4008`).
- **Proof records**: `ObjectKind::ProofRange` rows, verified Merkle tree ranges kept on disk per
  head, head-keyed and never retired. 502,408 of them filled 1.05 GB of the operator's 3 GB store
  (`rca-StoreSize`). Not canonical ranges.
- **Reconstruction**: rebuilding a tree range from the validated headers of its leaves and the
  contexts of their joins (`ProofRangeRestore::restore`, `proof_range.rs:108-305`). At v0.4.30 it
  costs one header, one signature check and one join per leaf and is refused when the target head
  is not committed here, the author is frozen, or the author has an observed conflict
  (`reconstruction_allowed`, `proof_range.rs:150-154`); RD-9 keeps only the first refusal and
  drops the signature re-check.
- **Own Session records**: this node's Session registration and lifecycle records in a room.
- **Agent load**: one node (the author) whose 10 named agent sessions together deliver 2 Session
  steps a second over the bridge while each session posts in a closed loop (one `vox room post`
  at a time per session), with 3 other members reading; the room holds at least 8,500 entries.
  This is ADR-045's journey J3. The release-gate arm in the tree uses a cheaper shape (RD-15).
- **Unread row**: a row in a room written by another member and not marked read by this node.

## Requirements

### 1. The response-time budget

Plan B derives the budget from the table above. After RD-4 to RD-10 and RD-16: a publication costs
rooms × (about 0.2 ms for the display stamp, plus two walks of at most 128 own rows only when this
node's own rows or read marks changed): about 1–5 ms. No commit runs on the actor. Posts take
their room's pending write in order, each ruled save flushes for itself off the actor (RD-7,
r14), and a peer's request never waits in the actor's queue. No figure for the actor's busy
time is set as an objective (r16): the v0.4.30 baseline is measured
(`/opt/vox-evidence/v0431/perf-baseline/`, its `REPORT.md` when written: a typical post about
1.04 s, the 99th percentile about 2.8 s, the maximum 5.3–5.8 s, two or three posts over 5 s per
10-minute run, the daemon at about 101 % CPU, RSS about 140 MiB), the candidate is measured the
same way by J3, and the target is set from the two with the decider (rows 80, 81). The budget's
arithmetic below is derived, not measured; the requirements make bounds of what is promised and
the proofs measure them. On Linux a flush costs 1–3 ms on ext4/NVMe against 7–80 ms for `F_FULLFSYNC` (not
measured on Vox; the fleet's host B, ADR-045, measures it). A store of several GB adds page-cache
misses on reads only (redb's own cache is 32 MiB per store, `store.rs:146`, a bound on that cache
and on nothing else); once nothing on the actor walks rows, file size stops being an actor cost.
The budget does not cover the about 100 maintenance saves a second that steps cause (the
projection rebuild, fix-list item 22, ADR-047): RD-10 orders posts among them; it does not make
them cheaper.

- **RD-1. `vox status` answers within the budget under agent load.** *(changed)* Timed from start
  to exit of the `vox status` process on the author, every sample, nearest-rank percentiles: under
  RD-15's arm no answer over 250 ms; under agent load (ADR-045 J3) no answer over 1 s, and the
  median and 99th percentile are reported in the release post (expected: 20 ms and 100 ms). The
  250 ms and 1 s figures are the bounds this ADR promises; the medians are not asserted anywhere.
  - *Why:* items 15, 16, 17 and the content-size half of item 51 (status was 58 ms median, 581 ms
    at most).
  - *What changes:* RD-4 to RD-10 and RD-16. Nothing in `vox status`'s output changes.
  - *Proof:* RD-15's arm asserts the 250 ms bound; J3(b) asserts the 1 s bound. v0.4.30 is red
    under L2 (581 ms at most); its red under RD-15's arm is unverified until E-17 stages it on the
    release asset. Mutant: restore `ch.unread(store)?` in `detail_of`. Acceptance: the two bounds.
- **RD-2. A post is committed within the budget under agent load.** *(changed r15; the decider,
  2026-11-13, ledger rows 80 and 81)* `vox room post` on the author, timed from the process's
  start to its exit (the clock that includes the daemon's commit and the reply; it is not the
  bridge's step acknowledgement and not RD-3's reader visibility): under RD-15's arm no
  acknowledged post over 1 s; under J3 and under ADR-045's soak, **no acknowledged post over
  5 s**, the gate that blocks ("Make the hard gate 'every post within 5 seconds'"). J3 and the
  soak record post latency at the median, the 99th percentile and the maximum ("record the
  99-of-100 time as a number in the results, without blocking on it") for v0.4.30 and the
  candidate; those figures block nothing and are not a check that passes or fails. No speed
  target is written here: "we want to be as fast as possible", "and efficient", "but we need to
  measure where we're at", "before setting a target"; the target is to be set with the decider
  from J3's numbers once they exist. A post that fails is a red of its own ("PRODUCT: vox room
  post failed: <text>"), never a timing sample.
  - *Why:* items 16 and 17 (3.5–5.4 s for a post offered one at a time under 2 steps a second).
  - *What changes:* RD-5 to RD-10.
  - *Proof:* RD-15 and J3. v0.4.30 is red on the J3 gate in the measured baseline
    (`perf-baseline`: two or three posts over 5 s per 10-minute run, maximum 5.3–5.8 s); L2b's
    3.5–5.4 s single-poster figure is not that red; RD-15's 1 s red is owed to E-17 (r16). Mutant: make a deferred post wait for every room's saves again (`node_save_pending()`
    for room work). Acceptance: the two gates (1 s cheap arm; 5 s J3 and soak) and the recorded
    figures.
- **RD-3. Readers keep up with a busy author.** *(changed)* Under agent load, each reader shows
  each of the author's posts in `vox room read` within 5 s of `vox room post` returning on the
  author, for the whole run; and each reader's last completed sync toward the author advances at
  least once a minute. Across a restart of the author (J3's `--restart` at +300 s), the rig
  offers no post from the restart until the room is open again (RD-11), and the first post after
  that counts from its own return.
  - *Why:* items 13 and 14 (serving side) and 17: readers 436–495 posts behind (trial B3); B
    fetched one entry from A in 15 rounds (L2b); 12.0–15.7 s in the actor's queue (B3-reach).
  - *What changes:* RD-8 (serving is a read), RD-16 (admission off the actor) and RD-4/RD-5 (a
    short actor queue for what still goes through it). Counting a served round that handed the
    peer an object it lacked as sync progress for that pair, and saying "served" or "fetched", is
    ADR-046's call site (SY-7, SY-20) and ADR-042's words (TR-3); this ADR supplies completed
    served rounds.
  - *Proof:* RD-15's author-under-load arm and J3(c). v0.4.30 is red on lag (trial B3). Mutant:
    revert RD-8 (serve through `write_owned` with the stand-aside, as v0.4.30). Acceptance: 5 s per
    post; one sync advance a minute.

### 2. The view costs the same however much is unread

- **RD-4. A view publication reads at most 256 rows per open room (two walks of at most 128 own
  rows), and none when this node's own rows and its read records are unchanged. Its cost does not
  depend on how many rows the node has not read. A `vox status` answer costs at most one
  publication, and only when one is owed; it leaves no second publication behind it.** *(changed)*
  - *Why:* item 15.
  - *What changes:* `detail_of` stops computing unread. The stamp that decides whether
    `read_by_own` and `held_own` run again (`ReadSummaryStamp`, `channel.rs:1022`, built at
    `:5949-5956`) gains the count of this node's own rows, and changes also when the room's
    history instance, its retention or visibility (`display_removals`, `order_revision`) or a
    rewrite changes, so a foreign post no longer triggers the walks while a change that can alter
    which own rows are shown still does. The unconditional publication and schedule after a
    status answer (`actor.rs:8056-8057`) go: status changes nothing (a publication still runs
    first when one is owed, `actor.rs:8050`). No wire, store or output change: `ChannelDetail` is
    in-process, and the IPC room snapshot never carried `unread`.
  - *Deleted:* `ChannelDetail.unread` (`api.rs:742-744`), `ChannelState::unread`
    (`channel.rs:8828-8861`), the third member of the cached triple (`actor.rs:474-484`, `:616`).
    Kept: `UNREAD_LOOKED`, the off-actor `unread()` that answers `Request::Unread`
    (`history.rs:372`), and `UnreadSummary`.
  - *Proof:* extend V210-08. Alice's node is driven as an agent node is: `vox room post` and
    `vox status` only, never `vox room read` or the TUI. First time `vox status` ×50 idle. Then bob
    posts 2,000 rows that alice never reads; then, while bob keeps posting, time `vox status` ×50
    and alice's posts as today. Assert: median status under load at most 3 × the idle median, and
    99th percentile at most 250 ms. A red reads `PRODUCT: vox status took <p50> ms at the median
    with 2,000 unread rows (idle <p50> ms)`. v0.4.30's red at 2,000 rows is unverified: every
    publication walks 1,000 rows and each status leaves a publication in the queue, so the
    expected figure is at least 40 ms against 7–9 ms idle, and E-17 raises the seed until the
    release asset is red before the constant is written. Mutant: restore `ch.unread(store)?` in
    `detail_of`. Acceptance: ratio at most 3; 99th percentile at most 250 ms; the seed E-17 fixes;
    a posting peer.
  - *Redundant tests:* none.

### 3. No disk flush on the daemon's event threads

- **RD-5. No thread of the daemon's async runtime executes a store commit, and no admission
  commits under a fact the actor checked and could have changed since.** *(changed)* Session-step
  admission, Drive admission and every attention commit run on the blocking pool. A reply that
  promises durability is sent from the commit's completion, after its own `Immediate` commit
  has returned (RD-7), never before.
  - *Why:* item 16; review finding 1 (an off-actor Drive admission must keep the fence its actor
    turn gave it).
  - *What changes, step batches:* `AcceptSessionBatch` without `drive` (`actor.rs:8740-8775`): the
    actor checks as today (the room is not being retired, the node is unlocked) and hands
    `session_ingress::admit` to the blocking pool with the profile's store handle. The inbox is
    node state, not room state, so the fence at commit time is the one `admit_inner` already has
    inside its transaction: `directory.retiring` (`session_ingress.rs:541`) refuses a removed
    room, and the move of the item into the room (`session_save.rs:577-662`) re-validates the
    room as today. A node locked meanwhile leaves a sealed inbox item the next unlock drains, as
    a post prepared across a lock does (`post_save.rs:592`, the attachment check). A completion
    event carries the `OwnedAdmission` receipt back; `ingress_scan_wake` moves to that completion.
    Receipts keep their meaning: `Committed` only after the batch's own `Immediate` commit
    returned; `NotCommitted{bodies}` when nothing was written (the bodies go back to the bridge);
    `Unconfirmed` when the commit returned an error, terminal and never replayed (RD-7). A
    duplicate batch that writes nothing reports `Committed` as today, because the receipt it
    found was itself written by an `Immediate` commit (r14).
  - *What changes, Drive admission (changed r3):* `AcceptSessionBatch` with `drive` becomes a
    room owner in the native-save shape (`begin_pending_maintenance`, `maintenance_save.rs:644`,
    work kind `DriveAdmission`), because a Drive operation depends on room facts (instance,
    membership, the opening) that change only through owners this registry orders. On the actor,
    as today: the node is unlocked, the author is trusted and may drive, no node save (policy,
    startup, leave, metadata) is pending, else `NotCommitted("Drive authority or Session opening
    changed; nothing was sent")`. The worker acquires the Computer publication lease
    (`try_acquire_publication`, which never waits; none → `NotCommitted`), takes the room's lock,
    re-checks the attachment epoch, `history_instance == drive.instance`, `is_member(author)`,
    not poisoned, and the opening open and non-provisional (`session_query(Exact)`, as
    `actor.rs:23383-23404`), then holds the room's pending write, drops the lock, and commits
    `admit_drive` (RD-7, no flush). The pending write is the fence for every room fact: no Session
    lifecycle record can move into the room, and no instance change, removal or leave can commit,
    while the admission owns it. The drive permission is fenced at the store's writer, not by
    room reservations: inside its own write transaction, before it writes, the admission loads
    the keyring as a policy save does (`Keyring::load`, `trust.rs:565`, the same read
    `PolicyWrite::run_checked` makes at `trust_save.rs:118`) and refuses with the same
    `NotCommitted` text unless the author is trusted and may drive. redb's one writer serializes
    this read with the policy save's commit, so exactly one order exists: a revocation that
    committed first is seen and the admission refuses; an admission that committed first was
    admitted under the authority then current, and the revocation that follows denies every later
    operation (today's actor check and `DeliverSessionDrive`'s own fence remain). A revocation
    never waits for a room, a Drive owner or a room's health: `GrantChange::Capability` keeps
    reserving no rooms (`policy_save.rs:452`). The worker commits `Immediate` (RD-7); the
    completion installs and replies through one terminal sender; a `NotCommitted` receipt keeps
    the bodies so the bridge retries with them, as today, and an `Unconfirmed` receipt returns no
    bodies and is never replayed (`session_ingress.rs:240-271`; r13).
  - *Every commit the actor's turn still reaches at v0.4.30 (r15; the cutover is derived from
    this table).* An actor turn is the body of one `handle`/event branch of the main loop and
    every synchronous call it makes; "waits on the writer" means the turn blocks on
    `Store::writer` (`store.rs:959-963`), which an `Immediate` commit on another thread holds for
    its whole flush.

    | # | path from the actor (v0.4.30) | lock held at the commit or wait | v0.4.31 home |
    |---|---|---|---|
    | 1 | `AcceptSessionBatch` → `session_ingress::admit` (`actor.rs:8768`) | none; the commit itself runs on the turn | blocking worker; receipt from the completion (RD-5, step batches) |
    | 2 | `AcceptSessionBatch{drive}` → `admit_session_drive` → `admit_drive` under `with_current_computer_authority` (`:23354-23413`) | the room's lock; the commit on the turn | room owner in the native-save shape (RD-5, Drive admission) |
    | 3 | `DeliverSessionDrive` → `deliver_session_drive` → `delivery.authority.with_current` → `RoomRemovalGuard::with_current` (`api.rs:788-795`) → `ReadResource::with_removal_fence` (`read_resource.rs:233-249`) → `Store::with_publication_fence` (`store.rs:966-969`) (`actor.rs:8790-8799`, `:23443-23468`) | the room's lock, and the **writer mutex** for the frame write: it commits nothing but waits behind any `Immediate` commit in flight (an Inventory's debt flush, `source.rs:1234-1249`, `store.rs:1459-1488`) | the actor tries the fence without blocking (`try_lock` on the writer); busy → the delivery is retained in the room's queue (RD-10) and retried on the writer's release, with the Computer authority, removal generation and history instance re-checked at that later publication (the fences are kept whole); the frame is written on a blocking thread |
    | 4 | `attention` → `channel.attention` (`actor.rs:8630`, `:23328-23351`): dispatch commits at `attention.rs:256-348`, the scan at `:517-537`, maintenance at `:634-646` | the room's lock; the commit on the turn | native-save shape (RD-5, attention) |
    | 5 | room pause → `set_room_pause` → `Store::put_segment` (`actor.rs:23569-23604`, `channel.rs:3655-3700`, `store.rs:1080-1093` marks Ruled and commits) | the room's lock; the commit on the turn | native-save shape: prepare the pause record under the lock, hold the pending write, drop the lock, commit on a blocking thread, install the pause state under the lock from the completion; the authority check (`with_current_computer_authority`) moves to the worker as RD-5's Drive owner does |
    | 6 | add/remove service → `persist_services` → `Store::put_segment` (`actor.rs:22369-22406`, `:22434-22470`, `channel.rs:3991-4021`), a separate transaction before the governance append | the room's lock; the commit on the turn | the same native-save shape, as one owner whose work is the service persistence followed by the governance append (`governance_save.rs`), both on the worker, installed together |
    | 7 | own-key response → `receive_own_key_response` → `accept_own_recovery_release` → `accept_skdm_mode` (`actor.rs:11886`, `own_keys.rs:566-665`, `own_history.rs:1362-1383`, `channel.rs:7279-7441`: four commits, `:7313`, `:7372-7399`, `:7407`, `:7441`) | the room's lock (`try_lock` at `own_keys.rs:588`); the commits on the turn | native-save shape: the response is validated under the lock, the room's pending write held, the lock dropped, the recovery branches committed on a blocking thread, the mode installed under the lock from the completion; a response that arrives while the room is owned is retained and retried (RD-10) |
    | 8 | explicit history request, new or resumed, public or private → `actor/history_demand.rs:1359`, `:1553-1574`: `shared.lock_owned()` moved into `spawn_blocking`, where `prepare` → `demand::start` (`:2946`) → `start_plan` commits `Immediate` (`node/history_demand.rs:893-940`), and the Resume paths at `:2798`, `:2868`, `:3114` → `resume_precharged` commits `Immediate` likewise (`node/history_demand.rs:957-1000`) (r16; R15-3) | the **room's owned guard across the commit** (the commit is off the actor, but an actor branch that needs the room, `NetEvent::SessionActivity` at `actor.rs:13798-13803`, waits behind the flush) | the worker captures the room facts `start_plan` authorizes with (`authorize_in`'s inputs) under the guard, holds the room's pending write as an owner, drops the guard, commits, installs the plan's owner under the lock from the completion |
    | 9 | Drive receipt reclaim → `reclaim_drive_opening` under `with_current_computer_authority` (`actor.rs:23523`) | the room's lock; the commit on the turn | native-save shape, as 2 |
    | 9a | a refused key delivery → `watch_delivery` raises `NetEvent::SkdmRefused` (`actor.rs:2872-2897`); the handler (`:12485-12503`) calls `note_undelivered`, `owe_history`, `owe_entitled_history` → `persist_delivered`/`persist_history` (`channel.rs:5621-5660`) → `Store::put_segment`, Ruled, `Immediate` (`store.rs:1080-1093`) (r16; R15-1) | the room's lock; the commits on the turn | native-save shape: the handler prepares the delivered/history records under the lock, holds the pending write, drops the lock, commits on a blocking thread, installs from the completion and only then continues the refusal and re-key handling; the classification stays Ruled |
    | 9b | a held position learned from a peer → `note_held` (`actor.rs:13683-13689` after a bounded round; `apply_held_notes`, `:22279-22296`, from `:16980`) → `channel.rs:8772-8792` → `Store::put_segment_derived`, which takes the writer mutex (`store.rs:970-974`) (r16; R15-2) | the room's lock; the write on the turn, and the turn waits on the writer behind any `Immediate` commit in flight | the actor keeps its bookkeeping (`held_notes`, `held_through`) and hands the write to a blocking worker keyed by (room, peer) that writes the newest position it was given, so a stale worker result cannot overwrite a newer one (a later note for the same pair replaces the pending value, never queues behind it); stays `Derived`; the actor's in-memory position is installed at once and the write follows |
    | 10 | `Store::put_segment`, `Keyring`, offers, prekeys, pending consent/lock helpers called from `*_save.rs` workers (`trust_save.rs`, `policy_save.rs`, `metadata_save.rs`, `leave_save.rs`, `peer_book_save.rs`, `offers/native.rs`, …) | none on the actor: these already run on workers (#1082) | unchanged |
    | 11 | every `pending_*`/`*_save.rs` room save (`post_save.rs:582-696`, `maintenance_save.rs:644`, …) | the room's pending write only; the lock is dropped before the commit | unchanged |

    Rows 1–9b are the cutover; after it no actor turn commits, and no actor turn waits on the
    writer. The rule that makes rows 5–9 safe is the one row 11 already obeys: the room's
    pending write is the fence for every room fact while the commit runs, and the lock is held
    only to prepare and to install.
  - *What changes, `DeliverSessionDrive` (changed r15; R14-1):* it commits nothing, but at
    v0.4.30 its frame write takes the store's writer mutex through the publication fence (row 3)
    and so waits on the actor's turn behind any `Immediate` commit in flight. The actor keeps
    every fence and loses the wait: it attempts the publication fence without blocking; when the
    writer is held, the delivery is retained as a queued owner of its room (RD-10) and retried
    when the writer is released; at that later publication the Computer authority
    (`with_current_computer_authority`), the removal generation (`RoomRemovalGuard::with_current`)
    and the history instance and opening (`deliver_session_drive`'s checks, `actor.rs:23443-23462`)
    are re-checked exactly as today before the frame is written, and the frame is written on a
    blocking thread. A delivery refused by a changed fact is refused as today (`frame.refuse()`);
    none is dropped silently.
  - *What changes, attention:* every attention operation that writes (dispatch,
    `attention.rs:256-348`; the scan, `:517-537`; maintenance, `:634-646`) takes the native-save
    shape: `Node::attention` prepares under the room's lock (the instance check, membership, the
    read-only facts of RD-6), the write and commit run on a blocking thread with the lock released,
    and the reply comes from the completion. The ledger's mutation stays inside its write
    transaction: the worker opens the batch, re-reads the ledger under the writer, applies the
    operation and commits, so no update is lost to a concurrent turn. A reply that must be durable
    (a registration, ADR-034 WT-6) is sent after its own `Immediate` commit returns (RD-7). No
    format change.
  - *What changes, the other inline writers (r15; R14-2, R14-3):* rows 5, 6, 7 and 9 of the
    table take the native-save shape with their helper transactions (`Store::put_segment`'s own
    commit, `accept_skdm_mode`'s four), their authority checks moved to the worker as the Drive
    owner's are, and their order kept: durable before the state is installed or published. Row 8
    releases the room guard before every activation transaction's writer acquisition, new
    (`start_plan`) and resumed (`resume_precharged`), public and private (r16): `prepare`
    captures under the guard what `authorize_in` and `load` read, enrols the request as the
    room's owner, drops the guard, commits, and installs the plan's durable owner under the lock
    from the completion; a `SessionActivity` query no longer waits behind a history request's
    flush. Rows 9a and 9b (r16) take the same shape: the refusal handler installs its records
    from the completion before it continues; the held-note write is a keyed, newest-wins worker
    write of `Derived` class.
  - *Deleted:* the inline `admit` call (`actor.rs:8768`), the inline `admit_drive` call
    (`actor.rs:23408`), the inline commits in `channel.attention`, `set_room_pause`,
    `persist_services`, `accept_skdm_mode` and `reclaim_drive_opening` as called from the actor's
    turn; the blocking publication fence in `deliver_session_drive`; the owned room guard across
    `start_plan`'s commit.
  - *Proof:* extend the FX-31 arm of `nodes_of_one_daemon_proof.rs`
    (`two_paired_computers_that_are_idle_exchange_nothing`, an optional proof at v0.4.30;
    once a blocking arm by the decider's answer 4). With a ruled commit held (RD-7's `VOX_TEST_HOLD_RULED_COMMIT`), deliver one Session step through
    the shipped bridge path, as `a_claude_session_is_mirrored_and_answered_from_either_side_proof.rs`
    does, and one attention registration through the hook, as `agent_hook_proof.rs` does. Then run
    `vox status`; the proof gives it 1 s; while the hold still stands, bob sends a valid Drive
    operation to alice's session (row 3: its frame write must not wait on the held writer) and
    bob runs `vox room read --history older` against alice (row 8: a history request whose
    `start_plan` commit is held must not hold the room against the actor), then `vox status`
    again within 1 s; alice pauses the room (row 5) and `vox status` answers within 1 s (r15;
    R14-1, R14-3, R14-2); bob's second read is a Resume of the first (row 8, r16); bob's
    bounded round toward alice reports a held position (row 9b: `note_held` must not wait on the
    held writer) and `vox status` answers within 1 s; and, in the key-refusal journey
    (`key_package_proof.rs`'s refusal act, r16; R15-1), a refused key delivery arrives while a
    ruled commit is held and `vox status` on the refused side answers within 1 s, the refusal
    being handled after the release. Release the hold. Assert the step shows in
    `vox room session` and the registration in the hook's next turn. A red reads `PRODUCT: the
    vox daemon did not answer within 1 s while a flush was held`. The release binary has no flush
    hold; its red under load is RD-1's. Mutant: commit the step inline on the actor again.
    Second arm, the Drive fence, in
    `a_codex_and_an_opencode_session_are_mirrored_and_driven_proof.rs` (it already drives a
    session from another node), three acts (changed r3). Act 1, revoked before admission: the
    `test-knobs` hold is placed at the Drive owner's worker, before it takes the room's lock
    (generalized from `VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION`, keyed by work kind); bob sends a
    Drive operation; while it is held, alice runs `vox trust` to take bob's drive permission away
    and that completes (it waits on no room); release; assert bob's command reports "Drive
    authority or Session opening changed; nothing was sent" and `vox room session` shows no Drive
    operation from bob in the inbox or the transcript. Mutant: skip the in-transaction keyring
    read; the operation is admitted and shown, PRODUCT. Act 2, admitted before revocation: no
    hold; bob's operation is admitted and shown; alice revokes; bob's next operation is refused
    with the same text and nothing further is shown; the order is the serial order the person
    saw. Act 3, the opening (changed r4): the hold of act 1 cannot stage this race, because a
    Drive owner that already holds the room's pending write excludes the end's lifecycle record
    from moving in; the hold is therefore placed earlier, at the actor's receipt of the command,
    before it enrols the Drive owner (the command is retained in `deferred_commands` while the
    `test-knobs` hold stands; the actor is not blocked); while it stands, alice ends the session
    and the proof observes the end installed (`vox room session` shows it ended); release; the
    owner enrols, acquires the pending write, re-checks the opening under the lock, and the
    command reports the same refusal with no effect. Mutant: skip the opening re-check under the
    lock; the operation lands on an ended opening and `vox room session` shows it, PRODUCT. A
    Drive owner that acquired the room before an end was asked for is admitted in its earlier
    serial position; that is act 2's order and is correct. Acceptance: status within 1 s while a
    flush is held with a step and a registration in flight; both durable after the release; no
    revoked or stale Drive input reaches a Session, in either order.
- **RD-6. Reading the attention ledger opens no write transaction.** Every attention path reads
  the ledger from a committed snapshot and takes the store's writer only to write.
  - *Why:* the off-list finding in C-16; it serializes every attention turn behind every save and
    every flush.
  - *What changes:* the four reads at `attention.rs:173-175`, `:206-208`, `:382-384`, `:597-599` open
    `store.snapshot()` instead of `store.batch()`. `Ledger` gains a read-only open over a snapshot.
    A path that reads and then writes re-reads under its write transaction (RD-5), so the snapshot
    read decides only whether to write.
  - *Deleted:* the four write transactions opened for reading.
  - *Proof:* RD-5's held-flush arm. Mutant: open the scan's read with `store.batch()` again; the
    attention turn then waits on the held flush under the room's lock and `vox status` is red on the
    same line. Acceptance: as RD-5.
- **RD-7. One save, one trip: every save whose reply means "on disk" makes its own flush, off
  the actor, and its reply is produced only from that commit's own result.** *(changed r14; the
  decider, 2026-11-13 15:45 PST, ledger row 74, superseding row 28: "One save, one trip in
  v0.4.31. Group commit can come back later with measurements.")* Each ruled commit, the set
  whose reply promises the data is on disk, is committed with `Durability::Immediate` on the
  store's blocking path (a `spawn_blocking` worker or the native-save shape, RD-5), never on the
  actor's turn; redb's single writer serializes the commits; the caller's reply is sent only
  after its own commit has returned. The ruled commits, from the code at v0.4.30 (every
  `*_save.rs` worker whose continuation replies to a person, and the inbox and ledger writers):
  a post and every other own entry, a governance append, a public or private Session record, a
  key package, a consent entry, a roster entry, a leave record (`pending_text.rs:775-815`;
  `post_save.rs`, `governance_save.rs`, `session_save.rs`, `package_save.rs`, `consent_save.rs`,
  `roster_save.rs`, `leave_save.rs`, `construction_save.rs`); a Session-step admission and a
  Drive admission (`session_ingress.rs:518-832`, RD-5); every attention operation that writes
  (`attention.rs:256-348`, `:517-537`, `:634-646`); a trust, capability or petname change, an
  offer dismissal, a room's metadata, a read mark, a local key (`trust_save.rs`,
  `policy_save.rs`, `offers/native.rs::dismiss`, `metadata_save.rs`, `read_save.rs`,
  `own_keys.rs`); the received debt an Inventory acknowledges (`flush_received_through`,
  `source.rs:1234-1247`, unchanged). Derived commits stay `Durability::None`: the render and
  projection indexes, verifier cursors, the Session projection's folds, held heads and intervals,
  the sync book, the attention ledger's `scanned` and `pending` bookkeeping (`store.rs:505-507`'s
  `Derived` class, as today). Losing one on a failed flush is safe because each is recomputed
  from what the ruled set holds or re-fetched from a peer (ADR-038 FX-30, unchanged); E-7
  measured (`store-experiments.md`, `store-exp-receipts/e7-fault-injection.log`) that a
  `None` commit visible on the latched handle is gone after a reopen (70 on the handle, 50
  after), which is exactly what "rebuildable" must survive. The same experiment measured that a
  commit whose `fsync` failed after redb wrote its header is present on reopen (51 of 50): that
  is why a failed ruled commit is told "could not be confirmed" and never "not saved".
  - *Why:* item 16. The cost of a flush is not the defect; where it ran was (C-16: on the actor's
    two worker threads, 63 of 100 slow commits in L2b). The decider chose one trip per save over
    group commit after the thirteenth review of the group-commit rule; see "Not chosen in
    v0.4.31" below.
  - *What changes:* nothing in `Batch::commit`'s durability (`store.rs:1983-1987` keeps
    `Immediate` for `Unsaid` and `Ruled`, `None` for `Derived`); what changes is where the ruled
    commits run (RD-5, RD-6) and that every reply is produced from the commit's own result. The
    verdict is the commit's own: `Ok` from `commit()` means the data is on disk, `fsync`
    included, and the reply says so; `Err` from `commit()` means the commit may or may not have
    reached disk (E-7's post-header case), and the caller is told "could not be confirmed"
    (`Err(Storage{op: "commit", detail})`), terminal, never replayed; a failure before the commit
    began (admission refused by ADR-047 SO-11's reserve, a preparation error, the store latched
    from an earlier failure so `begin_write` refuses) is definite and keeps today's definite
    receipt. Receipts, per caller: a post, "cannot save: disk" (ADR-040 NW-2's line), never shown
    as saved, and the person posts again if it is not there; a Session admission, `Unconfirmed`
    for a commit that errored, terminal, no bodies, never replayed (`session_ingress.rs:240-271`:
    "an uncertain commit is never replayed"; the bridge routes it to
    `SessionAdmission::Unconfirmed` and `unconfirmed_room`, `vox-tui/src/host.rs:6243`), and
    `NotCommitted{bodies}` for a definite pre-commit failure, the one receipt that returns the
    bodies and the one retry path (`host.rs:6221`; R12-4's contract, with RD-5); a Drive
    admission, "the Drive operation is unconfirmed; ask the Session what it received" after an
    errored commit and "Drive authority or Session opening changed; nothing was sent" for the
    definite refusal; an attention operation, its existing error; a trust, offer, metadata or
    read command, its exit code and text, and the person runs it again; an Inventory, no
    acknowledgement. *What a waiting commit is told (changed r15; R14-4):* `Store::writer` is a
    standard mutex (`store.rs:523`), not a queue with a promised order, and `begin_write` takes
    the mutex first and the current backing after (`store.rs:970-981`). When a commit fails with
    an I/O error, redb latches the database (`Previous I/O error`, `page_manager.rs:1266`,
    `:1796`). A request that attempts `begin_write` while the store is latched or recovering
    fails definitely before writing anything, and its caller gets its definite receipt
    (`NotCommitted{bodies}`, "cannot save: disk" with no uncertainty), not "could not be
    confirmed". A request still waiting for the mutex when recovery takes it, and whose first
    transaction therefore begins after the reopened backing is in place, gets that transaction's
    own result, `Ok` or its own error: it is not a replay of anything, because nothing of it was
    attempted before. Only the one commit that was in flight at the failure is in doubt.
    Recovery is ADR-047 SO-12's: it drains, reopens and repairs the same file, makes one
    `Immediate` commit to confirm the reopened store, and raises `StoreRecovered(room)`; it
    settles no waiter, because no waiter exists: every caller is answered by its own commit or
    its own refusal. After recovery the next save runs its own commit as any other. A same-identity retry after
    "could not be confirmed" is the caller's choice and is safe only where the store deduplicates
    it (a Drive operation id, a Session source receipt, `admit_inner`'s duplicate path): then the
    retry's own commit is its own verdict. No `Saved` is synthesized on error or close. Nobody
    commits while holding a room's lock or a read lease (FX-31); a ruled save holds only its
    room's pending write while its commit runs, so its roots are installed, and its publication
    exposed to peers, only after they are on disk, as today's order has it. No format change.
    FX-30's "a sync round that persists only derived state MUST make no full flush" holds as
    written: derived commits are `None`, and `full_flushes` in `vox status --json` does not move
    over a quiet minute.
  - *Cost and responsiveness, honestly:* one `F_FULLFSYNC` per ruled save, measured 20–81 ms on
    this Mac's SSD (RcaSlow L2b; ext4/NVMe on the Linux VM unmeasured, E-16-linux). The actor
    never waits on one: RD-5 and RD-6 put every commit on the blocking path, and the actor's turn
    touches the store only through reads, so RD-1's bound on `vox status` does not depend on a
    flush at all; RD-5's held-flush arm proves it (status answers within 1 s while a flush is
    held with a step and a registration in flight, and a Drive delivery, a history request and
    a pause meanwhile, r15). What per-save flushing costs, as conditional arithmetic and
    nothing more (r15; R14-5): the store's writer is a mutex, not a queue with an order; a save
    that finds k ruled commits ahead of it, each costing S, completes in about (k + 1) · S
    before any other work of its own; with S the measured 20–81 ms, five ahead is 120–486 ms
    including the save's own flush, and the last of a burst of 20 is 0.4–1.62 s; none of this is
    a guarantee, because the load fixes neither k nor the mutex's order, and nothing here derives
    a rate from the load. In CPU it is one `F_FULLFSYNC` per ruled save instead of one per group,
    and the writer is held for the flush each time. No rate cap is added. What this ADR promises
    under per-save flushing: RD-1's status bound (the actor never waits on a flush; RD-5's
    table); RD-2's cheap-arm gate (1 s) and its J3 and soak gate (5 s per post, the decider's
    rows 80 and 81); no speed target: "we need to measure where we're at", "before setting a
    target". J3 records, for v0.4.30 and the candidate under RD-14's load, post latency at the
    median, 99th percentile and maximum (start to CLI exit), `vox status` latency, the daemon's
    CPU and memory, and flushes per second (`full_flushes`), and the target is set from those
    with the decider. Group commit, plan B's mechanism for the post budget, returns with those
    measurements if they show per-save flushing is where the time goes.
  - *Not chosen in v0.4.31 (kept as the record):* group commit, revisions 2 to 13 of this ADR:
    every commit at `Durability::None`, one flusher thread per store flushing when durability
    demand exceeded a durable mark, replies waiting on that mark, and, after a failed flush and a
    reopen, a settlement of every pending reply from one snapshot of the recovered store by
    per-caller predicates. Thirteen reviews found a new hole in each revision of the recovery
    rule (transaction ids moved by repair, class against prefix, aliasing after a restart, a
    retired witness, a replayed uncertain commit); the thirteenth judged it not yet a rule a
    builder could implement, and the decider withdrew it. It may return with measurements of the
    per-save design on the fleet. Its reviews stay in "Review record" as history.
  - *Deleted:* nothing of v0.4.30's durability; the inline commits on the actor (RD-5, RD-6).
  - *Proof:* extend `a_daemon_reopens_its_rooms_proof.rs` (it already kills both daemons with
    SIGKILL after a post), built with `test-knobs` for the hold and fault arms, in the macOS
    guest. Arm one, the reply waits for its own flush: a `test-knobs` hold at the store's
    `Immediate` commit (`VOX_TEST_HOLD_RULED_COMMIT`, keyed by the save's kind, of the same hold
    family as `VOX_TEST_HOLD_TEXT_APPEND_PUBLICATION`) is placed; alice runs `vox room post` in
    the background; assert it has not returned while the hold stands and that `vox status`
    answers within 1 s; release; the post returns; SIGKILL alice's daemon the moment it returns;
    restart; `vox room read` shows the post. Red: `PRODUCT: a post vox room post reported was gone
    after the daemon crashed`. Mutant: reply before the commit returns; the post returns while the
    hold stands, the kill before release loses it, red on the same line. Arm two, the failed
    commit: a `test-knobs` fault makes one post's commit fail at its final `fsync`
    (`page_store/page_manager.rs:1856`, after the header), and a `test-knobs` hold keeps SO-12's
    recovery from starting until the proof releases it (r15; R14-4). A, the uncertain one:
    assert alice's `vox room post` exits non-zero with the text "cannot save: disk: could not be
    confirmed after recovery; run the command again to see whether it took" and the daemon's log
    names the store error; after the restart at the end of the arm the post is shown or not
    shown, and the proof asserts only that it was never reported saved. B, the definite one: an
    independently admitted Session batch (the bridge delivers a source-less step) attempts
    `begin_write` while the store is latched and recovery is held; assert the bridge's receipt is
    `NotCommitted` with its bodies (the definite, retryable outcome) and `vox room session` shows
    nothing yet; release recovery; the bridge's one legitimate retry lands and `vox room session`
    shows exactly one step; a third post succeeds and is shown. Mutants: A, tell the failed caller
    the definite words "cannot save: disk: not saved" (the assertion is on the text itself:
    the false definite wording is the red, PRODUCT: `an uncertain commit was reported as not
    saved`); B, turn the precommit refusal into terminal `Unconfirmed`: the step never lands
    after recovery, PRODUCT: `a step refused before any write was never retried`. Arm three, the
    Session receipt: the same `fsync` fault on a Session step's admission (a source-less step,
    so no deduplication can mask a replay); the bridge's receipt is `Unconfirmed`, `vox room
    session` shows the step at most once after recovery, and the bridge sends nothing again;
    mutant: classify the commit's `Err` as `NotCommitted(original bodies)`; the bridge's
    `complete_session_hold` then takes its Held/retry path (`host.rs:6221`) and re-admits the
    bodies, and `vox room session` shows the step twice when the first commit had in fact
    reached disk, PRODUCT: `an uncertain Session step was replayed`. Arm four, quiet: with no ruled save, two members exchange derived sync state for a
    minute (the FX-30 arm) and `full_flushes` does not move; mutant: flush derived commits; red
    on the count, PRODUCT. The existing `a_file_that_holds_the_identity_is_published_durably_proof.rs`
    covers the identity path; the trust, consent and key proofs are run once on the composed
    candidate. The packaged release artifact holds no knob. v0.4.30 on arm one is `CANNOT
    MEASURE` (no hold); its behaviour, a flushed commit per save, is the design's. Acceptance:
    every acknowledged post and step survives SIGKILL; a post does not return while its commit
    is held; a failed commit is told "could not be confirmed" and never "saved" or "not saved";
    a commit attempted while latched is refused definitely and lands once on its retry; an
    uncertain step is never replayed; `full_flushes` unchanged over a quiet minute.
### 4. Serving is a read

- **RD-8. Answering a peer's history query writes nothing to the room and waits for no save.
  The room's lock is held only to capture who may read and what the room knows in memory; the
  disk read runs on a read lease with no mutex held, and its answer stands however many posts
  were published meanwhile.** *(changed r3)*
  - *Why:* items 17 and 13/14 (serving side); review finding 3 (the publication mutex) and its
    snapshot-coherence note.
  - *What changes:* `Source::read_charged` and `read_reserved` (`source.rs:483-574`) take the
    room's lock once, briefly: they capture the authorization facts (epoch, membership, peer
    removal, departed and recovery standing, `source.rs:536-551`) and the in-memory facts a query
    needs (a frozen fork, the history author key, inventory incarnations; `prepare_proof_range`
    captures them today, `proof_range.rs:80-97`), and take a read lease from the room's
    `ReadResource`: under its publication mutex, clone out the pinned or a fresh MVCC snapshot,
    the published index roots, the publication revision, the directory revision and the history
    instance; then release both the mutex and the room's lock. The disk read runs on the lease on
    the blocking pool. Every lookup of one bounded step (head selection, the target head's
    commitment, descriptors, contexts, headers) reads the same lease, so a head chosen from one
    snapshot is never looked up in another (a mismatch would read as "evidence unavailable", not
    corruption). After the read, the result stands if the lease was not revoked (the room removed,
    poisoned, locked or its history instance replaced, `ReadResource::revoke`) and the history
    instance is unchanged; a newer publication (a post, a step, a received entry) changes
    nothing the answer depends on, because the selected head is a committed head and its
    subtrees are immutable, so it never causes a retry. A revoked lease answers
    `EvidenceUnavailable`. A lease is dropped before any wire write or credit wait;
    nothing holds a snapshot across the network. `Source::authorize` (`server.rs:244-264`) still
    re-checks current access before each frame goes out. `Source::range` and `ProofRangeRestore`
    read only (RD-9). `ReadResource::with_snapshot` is replaced by the lease for every reader
    (served queries, `saved_history_query`, the attention page), so the actor's publication
    (`read_resource.rs:497-533`) never waits behind a disk read. An `Inventory` that advertises
    received authors runs the existing debt barrier before it advertises
    (`flush_authors_before_ack` → `flush_received_through`, `source.rs:1338-1346`,
    `store.rs:1459-1488`: one `Immediate` commit on the blocking path, only when a debt is owed;
    unchanged by RD-7, r15), with no room lock and no read lease held across it; it keeps FX-30's
    rule that nothing is acknowledged that a crash can lose.
    Wire unchanged. This is the read path ADR-046 SY-6, SY-10 and SY-16 rely on.
  - *Deleted:* `prepare_proof_range`, `PendingProofRange` (`proof_range.rs:62-97`), the
    `write_owned` step in `range` (`source.rs:1015`), `ProofRangeStep::Busy`; the stand-aside at
    `source.rs:734-761` for served queries; the owned room guard inside the blocking read
    (`source.rs:535-568`); `with_snapshot`'s mutex-held callback. The stand-aside stays only for
    received-entry admission on the fetching side, the one write that must stay a write, ordered
    by RD-10. Cutover (r13): RD-8's deletions and RD-9's conversion of `restore` to a read are
    one step, because the tagged `PendingProofRange::advance` is the only caller of the writing
    `restore` (`proof_range.rs:68-77`); deleting the wrapper first would not build.
  - *Proof:* RD-15's author-under-load arm (RD-3's assertions). A second arm in the FX-31 journey:
    hold a served read (the `test-knobs` hold at the lease's disk read) while bob fetches from
    alice; `vox status` and `vox room read` of already-saved rows on alice answer within 1 s;
    while the read is held alice posts twice (two publications); release; bob's read completes
    with the rows it asked for (changed r3). A red reads `PRODUCT: the vox daemon did not answer
    within 1 s while a history read was stalled` or `PRODUCT: bob's read of alice's history did
    not complete after alice posted during it`. v0.4.30 is red on the first line: the read holds
    the room and the publication mutex. Mutant: revert RD-8 (serve through `write_owned` with the
    stand-aside); bob's lag goes red; second mutant: hold the publication mutex through the read
    again; the stalled-read arm goes red; third mutant: discard the result when the publication
    revision changed; bob's read does not complete, red on the second line. Acceptance: as RD-3;
    status within 1 s while a served read is held; a read completes across two publications.
- **RD-9. No proof records are kept, on disk or in a second table; what may be served is what the
  room's committed snapshot can prove.** *(changed r3)* The decider, 2026-11-12, on keeping these
  records in a bounded form: "no need to keep anything like this".
  - *Why:* items 17 and 20. Each served miss today writes rows that are never retired (C-17).
    Review findings 2 and 9 of the first pass and N1, N6, N8 of the second name what the rows
    were also used for, what reconstruction costs, and what must outlive one stream.
  - *The contract, shared with ADR-046 and ADR-047 (changed r13: the decider chose their
    representation, ledger rows 57 and 62, so SY-18 and SO-1 win where this text differed).*
    After the proof records are gone, a tree range for an author's feed in a room is obtained,
    in this order, from:
    1. a canonical range in the lease's snapshot (`history_range`): one indexed read;
    2. the process cache (below), by exact subtree identity: one lookup;
    3. reconstruction from the validated headers of its leaves in the same snapshot
       (`ProofRangeRestore::restore` without its write, `proof_range.rs:199-290`, its `Visit`
       consulting 1 and 2 before it descends): one header read and one join per leaf, with the
       contexts the joins need, allowed only when the target head is accepted here and every
       leaf of the range is held with its validated header bound to the newest accepted head of
       size at or above its position (ADR-047 SO-1's rule; the `source_heads` tree and the
       receipt kinds 5, 6, 7 no longer exist) and, for a sparse holder, the held interval's
       descriptors tie its leaves to that head (ADR-046 SY-18, SY-16);
    4. for a sparse holder, a kept interval descriptor that covers the requested range exactly
       (ADR-046 SY-16's fallback, ADR-047 SO-1's fill).
    Otherwise the range is not served: the `Proof` answers `EvidenceUnavailable` at once (the
    existing status; ADR-046 SY-21 maps it to "not held here, ask another holder"), and never
    waits for the author. Absent evidence and expensive evidence are different answers: a
    derivation that does not fit one exchange's budget answers `Busy{retry_after}` with
    ADR-047 SO-1's background fill and a `retry_after` of at most 5 s (ADR-047 r9), and the
    peer asks again at that time (ADR-046 SY-21); `EvidenceUnavailable` is only for evidence
    this node does not hold. Two of v0.4.30's gates go, as ADR-047 SO-1 asks, each with
    its reason: *the fork gate* (`!frozen` and no `observed_conflict`, `proof_range.rs:150-154`)
    guarded a reconstructed node that would be written and read back as evidence; nothing is
    written now, and branch mixing is impossible: a conflicting head is recorded and acceptance
    for that author stops (`observe_history_head`, `sparse.rs:2676`; `sparse.rs:2582`), so every
    head ever committed for one author in one room lies on one chain, every held header was
    admitted under a head of that chain, and a target head that is committed here names that
    chain; a frozen author's held branch is therefore served, and after a restart too (the
    reviewer's second-pass hard case: B holds A's five entries, A forks, B restarts while A is
    offline, B still serves C). *The per-leaf signature re-check* (`VerifiedHeader::verify`,
    `:264-268`) re-verifies a header the admission already verified before indexing it, held
    since in a sealed segment whose decryption detects any change; a descriptor is a function of
    header bytes and contexts, and the peer verifies the served proof against the signed head.
    The inclusion-receipt check (`:245-262`) goes with the receipts (ADR-046 SY-18, ADR-047 SO-1):
    the newest accepted head and the held interval's descriptors are the acceptance evidence the
    receipt duplicated (r13). Bounds, stated separately: an indexed or cached lookup is O(1) reads per
    range, O(log n) per proof; a reconstructible miss is O(k) reads and joins for a k-leaf range,
    repeated when the cache has evicted it or two peers miss at once (measured, ADR-047 E-1 on
    this Mac: 164–242 µs per leaf, of which a composite signature verify, no longer done here, was
    about 70 µs; a 100,000-leaf feed's full derivation about 150 s, modelled); unavailable
    evidence costs the reads up to the first absent leaf. The claim "O(log n) hashes from headers" is withdrawn,
    and so is "once per process life": it is once per retained cache entry. An author serving the
    feed it appended itself never reconstructs: every perfect subtree was a forest root at the
    append that completed it and was kept as a canonical range then (`sparse.rs:1839`). A
    restored author (ADR-037 R5) promotes only its append frontier (`pending_recovery.rs:769-784`)
    and reconstructs older subtrees like any holder. A holder serving a received feed
    reconstructs per subtree while the cache misses; a sparse holder (one that holds an interval,
    not the whole prefix) serves the ranges whose leaves it holds and says `EvidenceUnavailable`
    for the rest.
  - *The cache and the proof handoff:* one process-wide cache, in memory, bounded,
    whose entries are only what this node's committed snapshot produced (a canonical range read
    or a reconstruction over committed heads); descriptors a fetch verifies for a head not yet
    committed live and die with that verification and never enter it. Each entry is a
    descriptor with the context its reconstruction generated (a canonical range's context is on
    disk already), keyed exactly by (room, history instance, binding, start, leaves); with the
    one-chain invariant above, a cached subtree serves every committed head that covers it, and
    no entry for another branch can exist. A served proof records, in the serving book's proof
    handoff for that peer and room, the frontier hashes it exposed and the generated contexts
    behind them, bounded per peer to the last 4 proofs' contexts (a Control proof enumerates one
    context per token, `server.rs:520-534`, so the bound is 4 × `MAX_PROOF_TOKENS` + 8 hashes,
    contexts up to 160 KiB each under the shared buffer permits); the peer's next stream's
    `Query::Context` (`server.rs:411-439`) looks on disk, then in the handoff, then in the cache
    by the hash's recorded key; a hash in none of them is `EvidenceUnavailable` and the peer
    re-asks the proof, which refills the handoff. The handoff is dropped with the peer's
    connection or the room's instance. The same handoff replaces `authorize_recovery_contexts`
    (`source.rs:296-324`), which today writes a `keep_recovery_context` row under the room's
    pending write so a returning author may ask for the contexts a proof of its own head named
    (`own_history.rs:595-647`; read by `recovery_context_allowed`, `server.rs:118`): the
    authorization is the handoff entry for that peer, in memory; a restart of the serving node
    loses it and the author re-asks the proof. Serving writes nothing. The cache bounds memory
    for descriptors and their contexts; the work budget per slice (`WorkBudget`,
    `proof_range.rs:115`) and the shared buffer permits (ADR-036 H-7) keep bounding the DFS,
    context and output buffers of concurrent jobs, and two concurrent misses on one subtree do
    the work twice.
  - *Own-history recovery:* `AppendForest::range` (`own_history.rs:384-404`) falls back to the
    proof records today, and `recovered_prefix` (`:409-449`, used at `:1447`) and
    `prepare_own_append_ranges` (`:1522-1588`) read it to rebuild the append frontier of a
    restored node whose prefix "legitimately lacks subtree indices". With the records gone, both
    reconstruct the whole recovered prefix once from this node's own validated headers (the
    recovery fetched every own entry, ADR-037 R5), compare the result with the signed root
    (`:1575-1579`, `root != target.root` is already an error), and `pending_recovery.rs:769-784`
    promotes the forest into canonical ranges in one commit. Reconstruction of the own feed needs
    no receipt: the signed root over all leaves is the authentication, and own headers carry the
    node's own signature. Crash windows: a kill before the promotion commit leaves nothing and the
    restart recomputes from the same headers; a kill after it finds canonical ranges and needs
    nothing. Missing own headers keep the existing recovery debt (`OwnHistoryBehind`), demanded
    from peers as today; nothing new is persisted. ADR-047 SO-1 owns the change and the proof
    (its restart-inside-recovery arm); this ADR fixes the contract.
  - *What changes here:* the serving write (`proof_range.rs:298-301`) goes; `restore` becomes a
    read over the lease plus the cache, without the fork gate, the signature re-check and the
    receipt check; `Query::Context` consults the handoff and the cache; `authorize_recovery_contexts`
    records into the handoff instead of writing. ADR-047 SO-1 and SO-2 remove the receiver-side
    writes (`crates/vox-core/src/node/history_stream/admission.rs:449-466`,
    `crates/vox-core/src/node/channel/entry_store/sparse.rs:2508-2539`) and the rows already on
    disk. Until SO-2 lands, existing rows are not read either: a row that is not consulted cannot
    be relied on, and reading it would hide a reconstruction defect.
  - *Deleted:* the serving write of proof records; the read of proof records in `restore`
    (`proof_range.rs:179-186`) and in `AppendForest::range` (`own_history.rs:402-404`);
    `reconstruction_allowed`'s fork and conflict terms; the per-leaf `VerifiedHeader::verify` in
    `restore`; the `keep_recovery_context` write and its row.
  - *Proof:* RD-15's arm with a restart of alice midway, so the readers' first proofs after it
    are served from a cold cache; the lag bound holds. A second arm in
    `a_newcomer_reads_the_whole_history_proof.rs` (ADR-046's B2 act): a member that holds the
    author's whole feed, not the author, serves the newcomer after its own restart (cold), and
    the newcomer reads the whole history within the proof's bound, across the several streams a
    read takes (proof, then contexts, then entries); a third member that holds only the newest
    100 entries is asked and answers `EvidenceUnavailable` for an older range, after which the
    newcomer gets it from the full holder (the status text is ADR-042's). Third arm (changed r3),
    the fork: in ADR-046 SY-13's equivocation journey (its three arrivals; a
    test-side attacker forges the second head, ADR-018 §9.2), after the fork is seen, the holder
    restarts while the author is stopped, and a newcomer still reads the author's pre-fork
    entries from the holder. Fourth arm, the returning author: `a_member_that_restarts_finds_its_
    room_proof.rs`'s restore step recovers its own feed from a holder that restarted after serving
    the first proof (cold handoff) and posts again. Mutants: restore the serving write and make it
    take the pending write, bob's lag goes red; keep generated contexts only in the serving job,
    the newcomer's read from the cold holder does not complete (PRODUCT: "the newcomer never
    showed <entry>"); restore the fork gate, the fork arm's newcomer reads nothing; re-add the
    old lookup order (reconstruct before the cache), no user-visible red, so that order is
    review-checked, not gated. ADR-047 SO-1's second arm (a kill inside own recovery, on a
    5-entry prefix so the forest is 4 + 1 and no canonical subtree index exists for the
    frontier, then a post) proves the recovery consumer. Acceptance: as RD-3, across the
    restart; the newcomer's read completes from a cold holder over several streams; a sparse
    holder refuses truthfully; a frozen author's held branch is served after the holder restarts;
    a returning author recovers from a cold holder.

### 5. A post waits only for its own room, and nothing waits for ever

- **RD-10. Each room has two lanes, control and authored, FIFO within each and alternating
  when both have work; a post waits only for the writes ahead of it in its lane plus at most one
  control transaction per write; once a control transaction is at the head of its lane it waits
  for at most the transaction in flight plus one authored write; nothing is refused in either
  direction, and no Vox operation waits for a room to fall quiet.** *(changed r3, r16, r17: the
  decider's row 82 and Main's rows 82a, 82b, 82c)*
  - *Why:* item 17(c); review finding 6 (an absolute "posts first" starves Session moves,
    projection turns, keys and governance when posts never stop) and N7 (FIFO gives a finite
    number of predecessors, not one); fix-list items 93 and 96 and the decider's words of
    2026-11-13 ("yeah we need different queues for priority messages or something"; "quiet
    room -- lol"; "not the point of vo[x]").
  - *The lane rule (r16):* each room keeps two ready queues of owners. The **control** lane:
    trust and computer policy, roster changes, rekeys, key packages, keyring batches, evictions
    and readmissions, and the actor's own governance turn for the room. The **authored** lane:
    posts, Session activity (step moves, Drive admissions), read marks. Within a lane the order
    is the order owners became ready. When both lanes have ready work they alternate: one
    control turn, then one authored turn; a turn is one native transaction, ending at its own
    `Immediate` commit and installation (RD-7, row 74). A multi-step control operation (a rekey
    over recipients, a withdrawal's rotation, a revocation, ledger cleanup, a Delete) takes one
    turn per transaction and keeps its continuation between turns; a child transaction it
    dispatches runs in the parent's turn and never queues behind its parent. When only one lane
    has work it runs back to back. Bounds (r17, row 82c): the control bound holds once a control
    transaction is at the head of its lane: it then waits for at most the transaction in flight
    plus one authored write. From enrolment it also waits for the control transactions ahead of
    it in its lane and the one authored turn each of them permits. An authored write waits for
    the writes ahead of it in its lane plus at most one control transaction per write. Nothing
    is refused in either
    direction, and a trust or policy command is never deferred behind a pending ordinary save:
    the retention of commands behind saves (`command_waits_for_save`, `actor.rs:8075-8088`,
    `:7876-7878`; exceptions at `post_save.rs:253-276`) is replaced by enrolment in the control
    lane. No operation waits for, reserves or requires a room, a flow or a member to be quiet: a
    busy room is the normal case. Daemon-wide, the same rule holds for the actor against inbound
    and bulk work: the actor's own room turn has standing over served and inbound work for that
    room, and never stands aside on a `try_lock` that loses every tick to fair-mutex waiters
    (`actor/governance.rs:325-340`, 45 such sites under `node/actor/` at the tag, fix-list item
    96: y1's roster never folded in the arm-replace trace); the sync side of that rule, a control
    lane with a standing claim and its try-lock mutant, is ADR-046 SY-29's, and this ADR adds no
    second mechanism. Sibling rows: ADR-040 NW-3 (the named waits take their lane), ADR-048 TC-4
    and TC-5 (trust and policy application never wait for a quiet room), ADR-046 SY-29.
  - *What changes (changed r17; R16-1):* the node-wide gate (`maintenance_save.rs:622-642`) and
    its retention of commands go; no owner reserves more than the one room it is writing, and no
    owner holds a room across more than one transaction. Each room keeps the two ready queues
    of the lane rule: a deferred post enters the authored lane when its command arrives; a
    Session move, a Drive admission (RD-5), a read mark and a received-entry admission on the
    fetching side (when its stand-aside ends) likewise; a projection turn, governance, a key
    package, a roster, rekey or trust turn enters the control lane when it is due, and a kind
    already queued is not queued again on a later wake (one place per owed kind: the turn that
    runs takes all the work then due). A trust or policy change (`trust_save.rs`,
    `policy_save.rs`): the keyring batch is its own short transaction with no room reservation
    before or during it (ADR-048 TC-4, TC-5 forbid inspecting or reserving rooms there); after
    its commit and install boundary, the pass visits the rooms the change touches, one
    room-local control turn each, each a control-lane owner of that room alone. Every turn, in
    either lane, holds the room's physical pending write, its room bindings and pins and its
    publication leases only until its single transaction's committed delta is installed, then
    releases them all. A multi-step control operation, an Untrust's withdrawal, rotation,
    revocation, ledger cleanup and Delete, a rekey over recipients
    (`TrustContinuation::Untrust`, `continue_owned_trust`), keeps between turns only its stage,
    its stamp, its reply and its continuation, and obtains another control turn for its next
    transaction; a native child transaction it dispatches runs in the parent's turn under the
    parent's current grant and never requeues behind it. `post_save.rs:329-334`,
    `actor.rs:7876-7889` and `reserve_policy_rooms` (`policy_save.rs:536-546`) give way to the
    lanes; the main loop's random choice among ready branches (`actor.rs:7920`) no longer
    decides who gets the room. What a post waits for, stated as a bound: the finite set of
    authored owners enrolled in its room ahead of it at the moment it enrols, every earlier
    post, Drive admission and received-entry admission then queued (none of these is coalesced),
    the owner then active, plus at most one control transaction per write ahead of it; each
    holds the pending write for one `Immediate` commit, flush included, plus one actor
    installation (RD-7), and a ruled owner holds until its commit returned, so peers never see
    what a crash could lose. For
    RD-15's arm only, where alice receives nothing, no Drive operation is sent and no control
    work beyond one key package runs, that set is at most P − 1 earlier posts, the active owner
    and one control transaction per write (P = 4). The number this gives is derived, not measured; RD-2's bound is what RD-15 and
    J3 measure, and ADR-047 (item 22) is what makes the projection turn cheap. The stand-aside
    for received-entry admission (`source.rs:744-761`) becomes a place in the authored lane: an admission that yielded once
    to an authored save is next, so repeated Busy is impossible. No turn is delayed, skipped or
    spaced by counting turns or measuring time (FX-27). Beneath the room's queue, every commit
    also waits for redb's one physical writer, a mutex with no promised order, behind whatever
    commit is in progress, one flushed commit of 20–81 ms on this Mac (RD-7, r14); that queue is
    separate from the room's and is not a room's save.
  - *Deleted:* the node-wide save gate for room work; the random race for the pending write;
    the repeated stand-aside; the retention of commands behind saves (r16); the all-room
    reservation of a policy save (`reserve_policy_rooms`) and the retention of a room across a
    multi-transaction operation (r17).
  - *Proof:* RD-15's arm: alice's post tail (RD-2). Second arm, same file: alice's 4 sessions
    post in closed loop for the whole 60 s; the staging check reads `vox status --json`'s pending
    owners for the room once a second and names `APPARATUS: the room's queue was empty at <t>`
    if it ever is (changed r3); during that, one session delivers a step and one member's key
    package is due (a `vox trust` change on bob); assert that the step is shown in
    `vox room session` within 5 s of its receipt and that bob's key is readable within
    `ONE_TIME_WAIT_MS` (`actor.rs:327`) while posts continue under RD-2's bound. v0.4.30:
    unverified until E-17 stages it (the step's visibility under a full queue is expected red:
    fresh maintenance waits for an empty node-wide gate). Mutant: take a ready post before any
    older owner (the absolute rule this revision withdrew); the step or the key goes red,
    PRODUCT. Third arm (r16): while alice's authored lane is never empty, bob runs
    `vox trust remove` of a third member and a rekey follows; assert the command returns within
    the time of one in-flight save plus one post (under 2 s on this Mac's figures) and the room's
    next posts are accepted throughout; mutant: defer the trust command behind the pending save
    (`command_waits_for_save` restored); it waits for the lane to drain, red, PRODUCT; second
    mutant: run the control lane back to back while the authored lane is ready; a post waits
    behind two control transactions, red on RD-2's cheap-arm gate, PRODUCT. Acceptance: RD-2's
    bound; a step visible within 5 s; a key readable within `ONE_TIME_WAIT_MS`, with a queue the
    staging check saw non-empty throughout; a trust command within one save plus one post.

### 6. A restarted room opens in seconds

- **RD-11. After a restart, a room opens in time that grows with this node's own Session records,
  never with the room's posts or with other members' records; a preparation turn that has work
  runs when it is due.** *(changed)* On a room with 2,000 posts from named sessions and 2,000
  foreign Session lifecycle rows, `vox status --json` lists no `preparing` entry for it within
  2 s of the daemon reporting the node Ready, and `vox room post` there succeeds within 3 s.
  - *Why:* item 18; review finding 12 (an any-author filter makes the cost other agents').
  - *What changes:* the render index gains the filter `SessionRecord(author)`, assigned to a row
    exactly when `is_record(text)` (`render_facts.rs:326`), beside `Author(author)`, which the
    index already keys by author digest (`render_facts.rs:248-262`). `refresh_records` walks
    `SessionRecord(self.me)`: this node's own records and nothing else. `SessionCandidates` stays
    for the Session projection, which needs every session-named post. The private phase walks
    the private index's `RefreshRecords` tree from this node's author prefix
    (`private_index.rs:555-562` keys it by `(author, created, body)`) instead of its `Candidates`
    tree, so it too reads only own records. The render index's version is bumped and the index is
    rebuilt at the first open (v0.4.x carries no older format); that rebuild is a one-time cost
    of the first v0.4.31 start, reported as preparing progress (ADR-042 TR-8's `<done> of <total>
    rows`) and measured apart from the restart bound by J3's stage 3 (the 3 GB snapshot). No lazy
    side index: a room opens when its index is rebuilt, as any first open of a new format does.
    The walk does not restart because of the stage's own appends: it records what it appended and
    continues from where it was when the root changed only by those. The main loop arms a
    preparation timer at the earliest due time across preparing rooms, the way it arms the
    governance timer (`actor.rs:7908-7917`). The stage reports rows walked and rows in total for
    status to show; how status says it is ADR-042's (item 51).
  - *Deleted:* the `|| row.text.contains("session_name")` clause from the refresh's filter (not from
    the projection's); the private phase's walk of `Candidates`; pacing by coincidental wakes.
  - *Proof:* extend `a_received_message_survives_a_post_after_restart_proof.rs` (a blocking proof
    that already restarts a node and posts). Before the restart, alice registers 4 named sessions,
    as `an_agent_session_is_checked_from_both_sides_proof.rs` does, posts 2,000 rows through them,
    and ends 2 of them (beast's shape: dead registrations whose records the stage must refresh);
    bob registers 20 named sessions and starts and ends each 100 times, so the room holds 2,000
    foreign lifecycle rows. After `vox daemon --restart` on alice, assert the two bounds above
    (the restart is of a daemon that has already rebuilt the index once, so the first-open rebuild
    is not in the sample). A red reads `PRODUCT: room still preparing: it waits for refreshing its
    Session records, <n> s after Ready`. v0.4.30 is expected red (4,000 / 32 = 125 turns at
    0.3–1 s; RcaChurn measured 16–18 s for 1,500 rows) and unverified until E-18 stages it on
    the release asset, which also fixes the seed. Mutant one: restore the broad filter and remove
    the timer. Mutant two: walk `SessionRecord` for any author; bob's 2,000 rows make the open
    exceed 2 s, PRODUCT. Acceptance: open within 2 s of Ready and a post within 3 s, with 2,000
    own named-session rows and 2,000 foreign lifecycle rows; the proof's existing assertions
    unchanged.

### 7. Linux gets the receive buffer Vox needs

- **RD-12. On Linux, the installer sets the receive buffer when it can, reads back what the kernel
  granted, and names the exact commands when it cannot or when the grant did not take.**
  *(changed)* When `/proc/sys/net/core/rmem_max` is below 4194304: if the installer can write
  `/etc/sysctl.d` (it runs as root), it writes `/etc/sysctl.d/90-vox.conf` holding the one line
  `net.core.rmem_max = 4194304`, runs `sysctl --system`, reads `/proc/sys/net/core/rmem_max` back,
  and only if the value read is at least 4194304 prints:

  ```text
  net.core.rmem_max: set to 4194304 in /etc/sysctl.d/90-vox.conf (Vox's UDP receive buffer)
  ```

  If it cannot write there, or `sysctl --system` fails, or the value read back is still below
  4194304 (a later-sorting administrator file overrides it), it prints, and installs on:

  ```text
  This host caps Vox's UDP receive buffer at 212992 bytes; Vox needs 4194304. As root, run:
    sysctl -w net.core.rmem_max=4194304
    echo 'net.core.rmem_max = 4194304' > /etc/sysctl.d/90-vox.conf
  ```

  (The first number is the value read back.) It writes nothing but that one file, never edits
  another file under `/etc`, and exits 0 either way. When the value is already at least 4194304
  it writes and prints nothing. When `/proc/sys/net/core/rmem_max` cannot be read it prints the
  second text with `an unknown number of` in place of the number. It never calls `sudo` and never
  sets a file capability.
  - *Why:* item 19; review finding 13 (success was reported from the command's exit, not the
    kernel's value).
  - *What changes:* `install.sh` gains a Linux step after the binary is in place. `VOX_SYSCTL_DIR`
    names the directory written (default `/etc/sysctl.d`), as `VOX_RELEASE_BASE` already names the
    release server for the installer's own test. `docs/manual/install.md:133-150` is to say what
    the installer does and what it prints. Nothing in the daemon changes.
  - *Deleted:* nothing.
  - *Proof (changed r3):* two arms. Apparatus arm, `install_sh_proof.rs` in the Linux VM (ADR-045's host B; CI compiles only),
    proving the installer's behaviour only, with the `/proc` stand-in in every act so it never
    assumes the runner's own cap: run the real `install.sh` with `VOX_SYSCTL_DIR` pointing at a
    directory the proof user cannot write and `VOX_PROC_SYS` (a second documented hook, test-side
    only) answering 212992; assert the printed text names `sysctl -w net.core.rmem_max=4194304`
    and `/etc/sysctl.d/90-vox.conf` verbatim and that the install completed. Run it again with a
    writable directory, a `sysctl` stub first on `PATH` that records its arguments, and a stand-in
    that answers 212992 before and 4194304 after the stub ran: assert the file holds exactly
    `net.core.rmem_max = 4194304`, that `sysctl --system` was run, and that the success line
    printed; then with a stand-in that still answers 212992 after, assert the second text printed
    and no success line. v0.4.30 is red at "the file exists". Mutant: print the success line
    without the readback. Kernel arm: `net.core.rmem_max` is a setting of the initial network
    namespace only (`net/core/sysctl_net_core.c`, `sysctl_core_net_init` strips the write bits
    outside `init_net`), so a container, even with `NET_ADMIN`, cannot stage it. The arm runs as
    root in the initial namespace of a disposable Linux VM the fleet owns: ADR-045's host B is the
    `podman-machine-default` VM itself (reached by `podman machine ssh`, root inside the VM, no
    `sudo` on any operator machine), not a container in it; the driver records the VM's kernel
    and the value before the run, sets `net.core.rmem_max=212992`, runs the installer, starts the
    installed daemon, asserts its stderr carries no `UDP receive buffer` line and `vox agent
    doctor` prints no `network:` warning (RD-13), and restores the value. Where the arm is not
    root in an initial namespace, or the value cannot be set, it names unmet staging
    (`APPARATUS: cannot stage a short rmem_max here: <reason>`) and is not green. Mutant: remove
    the Linux step; the daemon's buffer line appears, PRODUCT. Acceptance: the file's content; the
    readback rule; a daemon start with the full grant after the installer ran on a short host.
- **RD-13. A Linux host whose buffer is short is told how to fix it where the person looks.**
  *(changed)* `vox agent doctor` on such a host prints ADR-042 TR-23's two lines:
  `warn  network: this host gives Vox <N> KiB of UDP receive buffer; it asks for 4 MiB` and
  `fix: as root, sysctl -w net.core.rmem_max=4194304, and keep it in /etc/sysctl.d/90-vox.conf`.
  A host with the setting gets the full grant and the daemon prints no buffer line; the daemon's
  code for that is unchanged (`quic.rs:434`).
  - *Why:* item 19. `vox update` runs unprivileged and cannot write `/etc`, so a host installed
    before v0.4.31 (IO) learns of it only here.
  - *What changes:* the fact comes from `mtu_ceiling_for`'s reason, already computed at
    `quic.rs:792`, carried to the doctor through the daemon's status. The once-per-start log line
    stays.
  - *Proof:* in the Linux VM with the driver's short-cap fixture (`net.core.rmem_max` set to 212992 in the VM's own namespace and restored after, as RD-12's kernel arm does), `vox agent doctor` prints the two lines
    with `208 KiB`. v0.4.30 is red: nothing in `vox agent doctor` names `rmem_max`
    (`crates/vox-tui/src` holds no such text; the verb itself is ADR-042's). Mutant: drop the
    lines. The set-host branch is RD-12's kernel arm. Acceptance: the two lines on a short host;
    none, and no buffer line, on a set host.

### 8. Proof

- **RD-14. The full operator shape runs on the fleet, as ADR-045's journey J3.** *(changed r3)*
  J3's load is this ADR's agent load, written once here so J3 and RD-15 agree: the author hosts
  10 named OMP sessions; steps are offered open-loop at 2 a second in total (one timer, 500 ms
  apart, round-robin over the sessions, 2 KB each; changed r4), and every step is acknowledged by the bridge
  within 5 s or the run is red (`PRODUCT: step <n> acknowledged after <t> s`; this is the
  bridge's clock for a step, a different clock from RD-2's post and from RD-3's reader
  visibility, r15), so a slow daemon cannot earn a green by slowing its steppers; posts are 200 B, one closed loop per session;
  three readers never mark read; the store is RcaSlow's 0.5 GB stage and the 3 GB snapshot;
  `vox daemon --restart` at +300 s; the first 60 s after the room opens and the interval from
  the restart until the room is open again are not sampled; percentiles are nearest-rank over
  every sample; the run record (`fleet/gate.py`) carries the acknowledged post rate, the step
  acknowledgement tail, the served wait (ADR-046 SY-20), the host, its kernel and filesystem.
  J3 asserts RD-1's 1 s, RD-2's 5 s per acknowledged post (start to CLI exit; the decider's
  rows 80 and 81, r15), RD-3's lag and sync advance, and RD-11's open time after the restart,
  and records, blocking on none of them, post latency at the median, 99th percentile and
  maximum, `vox status` latency at the median and 99th percentile, the daemon's CPU and memory,
  and flushes per second, for v0.4.30 and the candidate; the speed target is to be set from
  those with the decider. Whether J3
  blocks a tag is ADR-045's Q1; this ADR adds no separate optional load proof (ADR-045 rejected
  one as leaving the gap open). Each red names `PRODUCT:` with the measured figure or
  `APPARATUS:`/`CANNOT MEASURE:` for staging (ADR-018 §10.1); J3's staging check (ADR-045 FG-14)
  refuses a run whose sessions did not install or whose store is not the named size. J3(c)
  asserts RD-3's "last completed sync toward the author advances at least once a minute" on each
  reader, beside the lag bound (r13; ADR-045 carries it in J3(c)). Mutants, one per claim: RD-1,
  restore `ch.unread(store)?`; RD-2, the node-wide gate for room work; RD-3, revert RD-8; RD-11,
  the broad filter; each is built and run once on the fleet by ADR-045 FG-9's mutant step, which
  records the red beside the baseline (r13). L2's 581 ms status maximum is evidence against the
  250 ms cheap-arm target, not a red against J3's 1 s bound; J3's own v0.4.30 red is its first
  run on the fleet.
- **RD-15. The cheap arms run on every release.** *(changed)* V210-08 is extended into the
  author-under-load journey: alice runs 4 named OMP sessions (the bridge shape of
  `a_claude_session_is_mirrored_and_answered_from_either_side_proof.rs`); together they deliver 2
  steps a second of 2 KB each, and each session posts 200-byte messages in a closed loop (one
  `vox room post` at a time per session, the next issued when the last returns), for 60 s, on a
  room seeded with 2,000 rows; bob runs `vox room read` once a second. The offered post rate is
  therefore at most 4 in flight, and the acknowledged rate is reported, not asserted. It asserts
  RD-3 (5 s per post), RD-2's 1 s bound and RD-1's 250 ms bound over every sample, and RD-10's
  second arm. V210-08's existing two-member arm keeps its bounds (95th percentile 100 ms, max
  500 ms). The seed (rows, then sessions) is raised until v0.4.30's release asset is red on the
  post tail and on the status bound, and that seed is the proof's constant (E-17); until E-17 has
  run, every "v0.4.30 is red" for this arm is unverified. Whether this arm, RD-5's held-flush arm
  and RD-8's stalled-read arm block the release is answered (the decider's answer 4): they block
  once each mutant has been run red; at v0.4.30 V210-08 and the FX-31 journey are both optional
  proofs, and an optional proof that did not run prints `OPTIONAL PROOF NOT RUN`, never a pass.
- **The v0.4.30 reds: run-backed, source-confirmed, or owed (changed r5).** Three states, kept
  apart: *run-backed* means a red observed in a run, with the receipt; *source-confirmed* means
  the defect is read in the tagged code, which says a proof would be red but is not a red; *owed*
  names the run that obtains the red. Only a run-backed red of the proof's own assertion is proof
  evidence; neither of the other two is release evidence (the decider's ruling of 2026-11-13).
  The run-backed rows below are historical shapes, not the proposed arms' own receipts. The
  receipts under `/tmp` and `/private/tmp` named below were lost when this Mac rebooted on
  2026-11-13; the figures stand as recorded in the named reports (`rca-RcaSlow`,
  `trial-sync-progress`, `rca-RcaChurn`), and each is to be re-run as the fleet's baseline
  (ADR-045) before it is cited as a receipt again (changed r9).

  | Requirement | v0.4.30 red | State |
  |---|---|---|
  | RD-1 (status under load) | 581 ms at most, 58 ms median | run-backed on the trace-only v0.4.30 build, `/tmp/rca-RcaSlow/r1/runs/L2-oplike/` (L2's shape; not a J3 1 s red); the release asset under RD-15's arm: owed, E-17 |
  | RD-2 (post under load) | 3.5–5.4 s | run-backed on the same build, `L2b-oplike/rig.log:187-190`; release asset under RD-15's arm: owed, E-17 |
  | RD-3 (readers keep up) | 436–495 posts behind | run-backed on the v0.4.30 build in the sync trial, `/tmp/trial-sync/runs/B3-base/`; RD-15's arm: owed, E-17 |
  | RD-4 (2,000 unread rows) | — | source-confirmed (`actor.rs:474-484`, `channel.rs:8833-8861`); owed: E-17 on the release asset, which also fixes the seed |
  | RD-5 (status while a flush is held with a step in flight) | — | source-confirmed (`actor.rs:8768`); owed: the FX-31 arm on a `test-knobs` build of v0.4.30 (the asset has no hold) |
  | RD-7 (durability) | none claimed: v0.4.30 flushes every commit too; the holds and faults the arms need do not exist on the asset (`CANNOT MEASURE` there) | the arms' reds are the mutants'; all four arms in `a_daemon_reopens_its_rooms_proof.rs` in the macOS guest (r14) |
  | RD-8 (status while a read is held) | — | source-confirmed (`read_resource.rs:360-383`, `source.rs:518-568`); owed: the stalled-read arm on a `test-knobs` build of v0.4.30 |
  | RD-9 (store writes while serving) | ADR-047 SO-1's `sync_bytes` | ADR-047's; the cold-holder and fork arms are not red at v0.4.30 (the asset serves from its records) and claim no v0.4.30 red |
  | RD-10 (a step visible under a full post queue) | — | source-confirmed (`maintenance_save.rs:636-642`); owed: E-17 on the release asset |
  | RD-11 (preparing after restart) | room open again 15.9–18.3 s after the restart command, 1,500 candidate rows | run-backed on the v0.4.30 build, `/tmp/rca-RcaChurn/prep1.log` (RcaChurn's shape, not the proof's); the proof's 2,000 + 2,000 seed on the release asset: owed, E-18 |
  | RD-12 (the installer writes the file) | — | source-confirmed defect (`install.sh` at the tag has no Linux step; its only `sysctl` is the Rosetta check, `:61`); baseline proof red owed: the apparatus arm's first run of `install_sh_proof.rs` against the v0.4.30 `install.sh` and the kernel arm's first run in the Linux VM |
  | RD-13 (doctor names `rmem_max`) | — | source-confirmed defect (no `rmem_max` in `crates/vox-tui/src` at the tag); baseline proof red owed: the first `vox agent doctor` run of the v0.4.30 asset in the Linux VM with the driver's short-cap fixture (`rmem_max` 212992 set and restored in the VM's own namespace) |
  | RD-14 (J3) | — | owed: J3's first run on the fleet (ADR-045) |
  | RD-16 (a read while the actor is parked) | — | source-confirmed (`actor.rs:2554`, `:11933`); owed: the parked-actor arm on a `test-knobs` build of v0.4.30 |

  The decider's rulings of 2026-11-13 as they touch these proofs: all machines move to v0.4.31
  together and no mixed-version sync is supported (ruling 18), so RD-9's "existing rows are not
  read until SO-2 deletes them" is within one release and no proof pairs a v0.4.30 member with a
  v0.4.31 one; the whole release gate fits 8–10 hours (ruling 19), so J3 is one 10-minute run per
  store stage and RD-15's arm is 60 s, and nothing here asks for a standing day-long run; the
  fleet runs inside VMs (ruling 20), which is what RD-12's kernel arm already requires (root in
  the Linux VM's own namespace, nothing on the host but the driver).

### 9. A peer's request never waits in the actor's queue

- **RD-16. A served history request is admitted and served without the node's actor: its wait
  before serving is bounded by the connection task and the store's read, never by the actor's
  queue.** *(new)*
  - *Why:* item 14 and plan A's measurement (above): up to 12.0–15.7 s in the heavy author's actor
    queue before `start_bounded_inbound`. ADR-046 SY-6 and SY-10 assign this change to this ADR.
    Review finding 5.
  - *What changes:* the task that already reads the preamble off the actor (`actor.rs:2541-2566`)
    goes on to admit the request itself. It needs four things the actor owns today
    (`start_bounded_inbound`, `actor.rs:18820-18921`): the room (`channels`), the history budget
    (`history_budget.try_start`), the port's inbound tokens (`ports[(room, peer)].inbound`,
    `next_token`) and the sync book's `Running` entry. The actor publishes the first into a
    registry the connection tasks read (`std::sync::RwLock<BTreeMap<room, (Arc<Mutex<ChannelState>>,
    Arc<ReadResource>)>>`, updated by the actor at open, close and retirement); the other three
    move into one `ServingBook` behind a `std::sync::Mutex`, locked by the connection task and
    the actor for microseconds and never across I/O (the budget's `try_start`/`finish`, the token
    counter, the inbound token set, `Running::start`/`end`). The connection task authenticates the
    peer (the connection's identity, as today), looks the room up, takes its budget slot or
    refuses `SessionBusy` (`net::refuse_stream_because`, as today), and starts the serving task,
    which reads on RD-8's lease and re-checks access per frame (`Source::authorize`). The
    per-request checks `run_sync_session` makes today before `start_bounded_inbound` (the owed
    reason, the port's inbound count against `INBOUND_PER_PORT`, the room's epoch) move with it
    into the connection task, reading the book and the registry. The serving task owns its
    capacity to the end (changed r3): a guard it holds releases, exactly once, on every exit
    (complete, partial, failed, cancelled, panicked), its budget slot, its inbound token for the
    port and its `Running` entry, under the book's mutex, before anything else; no capacity ever
    waits for the actor, and no failed cleanup can pin a slot (the class behind fix-list items
    85 and 87, where failed retirements of outbound flows pin `RETAINED_FLOW_LIMIT` and every
    Public start is refused in silence, `bounded_sync.rs:580`, `:1789-1810`, `:4749-4757`; that
    cap and its retry are ADR-046's, SY-24; this book has no such count: what is released by a
    guard cannot be pinned). After the release, the task posts the terminal receipt to the actor
    as `BoundedSyncDone`: an immutable value with the room, its history instance, the peer, the
    token, the outcome, whether an object was served, whether inventory was added and whether
    the request was a departure receipt or limited recovery. The actor's consumer
    (`actor.rs:13535-13631`) no longer looks the attempt up in `ports` (`Port::take`,
    `ports.rs:727-732`): it reads those facts from the receipt, discards a receipt whose instance
    is not the room's current one, and keeps its accounting, `sched_rooms` scheduling and
    departed-port handling as today. Retirement, disconnect and lock: the actor marks the
    registry entry retired (or the connection task sees the connection close), the book retires
    the fences of that room's or peer's tokens, and each serving task exits through its guard.
    A refusal (`SessionBusy`, the per-port cap, a room not open here) records its reason in the
    book, which status shows per port (ADR-042's words; the opposite of today's silent refusal
    at `bounded_sync.rs:4749-4757`). A join answer takes the same path (ADR-046 SY-10 owns the
    join). The actor's `ports` keep owning outbound rounds. Status reads the book under its
    mutex.
  - *Deleted:* `NetEvent::SyncRequest` and its handling at `actor.rs:11933-11944`; the actor-side
    body of `start_bounded_inbound`; the inbound half of `Port` (`ports.rs:430`, `inbound`) and
    its `take`.
  - *Proof:* what a person sees is RD-3 (RD-15's arm; J3(c)) and ADR-046 SY-10's join through a
    loaded member. Added arm (changed r3), in `a_newcomer_reads_the_whole_history_proof.rs`: a
    `test-knobs` hold parks alice's actor loop (`VOX_TEST_HOLD_ACTOR`, of the same hold family as
    the ruled-commit hold, feature-built only) for the length of the act, released by the proof after
    its fourth assertion, not by a timer (r13: a fixed 20 s did not cover the 2 s observation plus
    four 5 s reads); the proof observes that the park engaged, by `vox status` on alice not
    answering within 2 s while it stands, and says `CANNOT MEASURE: no test-knobs build` on an
    unfeatured binary; while it is parked, bob runs `vox room read --history older` four times,
    each with a `--before` cursor naming a distinct range bob does not yet hold (so a cached read
    cannot stand in for an exchange), and each read shows the rows it asked for within 5 s: more
    than `INBOUND_PER_PORT` = 3 successive exchanges with alice completed and released their
    tokens without her actor; the proof then releases the park, and alice runs `vox room leave`
    while bob's fifth exchange is in flight, and `vox status --json` on alice shows no inbound
    token for that room within 5 s. v0.4.30 is red at the first read (`PRODUCT: bob's read of
    alice's history did
    not complete within 5 s while her actor was busy`): admission needs the actor. The token
    mutant (release the token in the actor's consumer again, as `Port::take` does today) is red
    at the fourth read (`PRODUCT: bob's fourth exchange was refused busy`). The served wait is
    reported per run
    (`served_wait_ms`, ADR-046 SY-20) as investigation evidence; it is not asserted anywhere.
    The admission mutant (admit through the actor's queue again) is red in the parked-actor arm
    at the first read, the same line as v0.4.30. What that arm does not show is that the actor
    queue mattered under load once RD-4, RD-5, RD-7 and RD-10 shortened it: plan A's 12–16 s was
    measured with every other actor stall still present. Whether the admission mutant also turns
    RD-15's load arm or J3 red is measured when E-17 stages it and reported; neither claims it
    until then. Acceptance: RD-3's and SY-10's bounds; four reads complete while the actor is
    parked; no token outlives its exchange or its room.

### Alternatives rejected

- *Keep unread, as a counter kept per room* (seeded once, moved by each entry and read mark). Only
  worth it if something read it; nothing does, and the clients keep their own counts
  (`crates/vox-tui/src/live.rs:1187`). Precedent for deleting the per-event rescan: mail stores
  keep unread as a maintained header count or an on-demand query, never a per-event rescan
  (Dovecot, "Mail index file format").
- *More worker threads.* Hides the stall; a flush still parks whichever worker runs the actor.
- *Move the commits off the actor and stop there* (plan D16-a alone). Posts stay at one flush
  each (the design the decider chose in answer 1, row 74; RD-2's J3 figure is then measured, not derived). Precedents for the off-actor shape: Tokio's rule that
  blocking file work goes to `spawn_blocking` ("CPU-bound tasks and blocking code"); Firefox runs
  every Places/SQLite write on a storage thread (`Sqlite.sys.mjs`); group commit as in PostgreSQL's
  WAL writer (`commit_delay`, "WAL Configuration") and RocksDB's write-group leader
  (`db/write_thread.h`, `JoinBatchGroup`); bbolt's `DB.Batch` is the timer form, not taken. SQLite
  WAL with `synchronous=NORMAL` trades the last transactions' durability (sqlite.org/wal.html §2.3);
  RD-7 trades none, because the reply waits.
- *Group commit* (revisions 2–13; a flusher woken on every commit in the first draft, on demand
  from the second). Withdrawn by the decider (row 74) after the thirteenth review of its recovery
  rule; RD-7's "Not chosen in v0.4.31" keeps the record.
- *Keep the Drive admission on the actor, since it is rare.* Its `Immediate` commit is one flush
  of 20–81 ms on the actor's turn, which is item 16's defect exactly. The native-save shape already exists; it is used (RD-5).
- *Fence an off-actor Drive admission with a new authority token.* The room's pending write
  already fences every room fact; a second mechanism would have to agree with it (RD-5).
- *Fence the drive permission by making a capability change reserve every room* (this ADR's
  second revision). `reserve_pending_write` pins a read of each room, which a poisoned room
  refuses (`publish_history_read_inner`'s `save_failure()`), so one failed room would stop a
  revocation everywhere, and a busy room would put it behind that room's save. The in-transaction
  keyring read at the store's writer orders the same two events with no room involved (RD-5).
- *Retry a failed flush on the next demand* (this ADR's second revision). redb latches an I/O
  failure until recovery, so the next attempt fails the same way; and a waiter that joined the
  failing attempt was told nothing. One recovery owner and attempt-scoped failure instead (RD-7).
- *Invalidate a served read when the publication revision changed* (this ADR's second revision).
  Under continuous posting no read would ever complete; the head a proof is for is committed and
  its subtrees immutable, so only revocation and the instance matter (RD-8).
- *Keep generated contexts in the serving job* (this ADR's second revision). A job is one WANT on
  one stream (`history_stream.rs:206-237`); the peer's `Query::Context` arrives on the next. The
  handoff in the serving book outlives the stream (RD-9).
- *Key the cache by exact head* (v0.4.30's proof records). Needless once only committed-chain
  material enters it: a committed author's heads are one chain (RD-9).
- *Keep the fork gate on reconstruction* (this ADR's second revision; v0.4.30). It guarded a
  written record that would be read back as evidence; with nothing written and no branch mixing
  possible, it only made a frozen author's history unservable after a restart (RD-9).
- *Keep a serving cache on disk in its own table* (plan D17-b). A format change that keeps writing
  per head and contends for redb's one writer; ruled out by the decider's "no need to keep anything
  like this". Precedents for serving as a read: redb's MVCC ("Multiple reads may be performed
  concurrently, with each other, and with writes"); Git serves pack objects from an immutable store
  with an in-memory cache; Certificate Transparency logs compute proofs on request
  (RFC 6962 §2.1).
- *Serve on the committed snapshot through `with_snapshot` as it is.* Its callback holds the
  publication mutex, so a slow read still stops the actor's next view (C-17(b)); the lease (RD-8).
- *Bound the stand-aside instead of removing it* (plan D17-d). Serving stays a write and each proof
  step waits for a save. Kept only for received-entry admission, as a queue place (RD-10).
- *Posts first, always* (this ADR's first draft; plan D17-c(ii)). A never-empty post queue starves
  Session moves, projection turns, keys and governance. FIFO among ready owners holds the post
  bound without a class above everything else (RD-10). Precedent: fair queueing over strict
  priority wherever starvation matters (Linux's CFS over the old RT-only classes for ordinary work).
- *Open the room while the refresh runs* (plan D18-d). The refresh guards the lifecycle of this
  node's own Session records, which the publication's privacy classification relies on.
- *Skip the refresh when nothing changed, by a per-room record* (plan D18-b, chosen by the plan, not
  taken here). After RD-11 the walk costs milliseconds; the record adds persisted state, and no user
  journey can tell it apart, so it would have no proof (ADR-018 §10.10).
- *Let a preparation turn run up to a time budget per wake* (in plan D18-a, not taken). FX-27 forbids
  spacing turns by a rule that measures CPU time, and with RD-11's filter there is little to walk.
  Precedent for the timer: every event loop arms its deadlines (tokio `sleep_until`, libevent);
  for the filter: an index built for the query that reads it (SQLite partial indexes).
- *An any-author Session-record filter* (this ADR's first draft). Its cost is other agents'
  records; the author-keyed filter costs the same to build and reads only this node's (RD-11).
- *A lazily built side index if the rebuild is slow* (this ADR's first draft). Who completes it
  and when the room may open were undefined; the first-open rebuild is a one-time cost like
  ADR-047's record deletion, reported as progress (RD-11).
- *Let the daemon take the buffer itself* (`SO_RCVBUFFORCE` with `CAP_NET_ADMIN`, `socket(7)`).
  `vox update` replaces the binary, so a file capability is lost at each update, and
  `CAP_NET_ADMIN` is far more than a buffer. Precedent for setting `rmem_max`: quic-go's wiki,
  "UDP Buffer Sizes"; packaged daemons ship a `sysctl.d` file.
- *Stay at 1452 bytes and tune QUIC for a small buffer.* Gives up the 8192-byte ceiling (ADR-012,
  #174) on every Linux host.
- *A separate optional load proof file* (this ADR's first draft, RD-14). ADR-045 rejected it: it
  leaves no place where the operator's conditions must be proved before a tag. J3 is that place.

## Unchanged rulings

- ADR-038 FX-30: the ruled set is on disk before the command that wrote it returns, and "a sync
  round that persists only derived state MUST make no full flush". RD-7 changes how, not whether.
- ADR-038 FX-31: a post reports success only once durable, and a failed save is never reported as
  saved.
- ADR-038 FX-27 (the decider, 2026-10-20: "caps on cpu seem like … footguns"): no turn is delayed,
  skipped or spaced by counting turns or measuring CPU time. RD-10 orders; RD-11 arms a due time.
- ADR-038's unchanged rulings: no rate limits.
- ADR-034 WT-6: a hook's request ends after its registration is durable, not after projection.
- ADR-034 HL-1 and HL-2: what counts as a completed sync and how status says it are ADR-046's and
  ADR-042's.
- ADR-037 R4: reads, listings, attention and net queries answer from what is known.
- ADR-036 H-7's cache bound (64 objects, 4 MiB) for its objects; the decider's answer 2 adds the descriptor
  cache beside it.
- The 1,000-row look-back of `vox room read --unread` and the TUI ("unread counts are lower bounds:
  only the newest 1,000 rows were examined", `live.rs:3472`) is unchanged here. Whether it meets
  ADR-034 FR-8 is not decided by this ADR.
- v0.4.x keeps no prior-release compatibility: the render index is rebuilt at open, with no migration.

## Superseded and amended lines

Main applies these after the decider signs. Each quotes the current text exactly.

1. **ADR-034 FR-5** (`docs/adr/ADR-034-the-app-and-daemon-never-hang-or-hide-a-failure.md:114-118`).
   Current:
   > - **FR-5. Pages from an index.** The daemon MUST serve each page from an index, by Session and by
   >   position, at a cost that does not grow with the history's length: it MUST NOT read, decrypt or
   >   decode a whole history to answer for one page. The memory the daemon uses to answer a page, and
   >   the memory the app uses to show a Session or a room, MUST be bounded by the pages shown, not by
   >   the history's length.

   Replacement: the same text, followed by: "The same holds for the view the daemon publishes after
   each event: its cost MUST NOT grow with the history's length or with how much of it is unread
   (ADR-044 RD-4)."
2. **ADR-038 FX-17** (`docs/adr/ADR-038-daemons-trust-daemons-and-sessions-are-presence.md:221-223`).
   Current:
   > - **FX-17.** The daemon MUST answer its control socket within a harness hook's wait while it
   >   syncs; a hook that reports "the vox daemon here did not answer promptly" on an idle machine
   >   is a product defect.

   Replacement: "- **FX-17.** The daemon MUST answer its control socket within a harness hook's wait
   while it syncs and while its agents post and step (ADR-044 RD-1); a hook that reports "the vox
   daemon here did not answer promptly" on an idle machine, or under that load, is a product
   defect."
3. **ADR-038 FX-30** (`ADR-038-…md:644-647`). Current:
   > Decision: derived state commits at redb `Durability::None` (redb 4.3.0 has no
   >   `Eventual`; a later durable commit carries it) and the ruled set stays `Immediate` however it
   >   arrived: a received consent, trust change, key package or Session record is flushed like the
   >   node's own.

   Replacement (r14): the text stands as written; this ADR adds after it: "Every ruled commit runs
   on the store's blocking path, never on the actor's turn, and its reply is produced only from
   that commit's own result (ADR-044 RD-5, RD-7)." The sentence "A sync round that persists only
   derived state MUST make no full flush" at `:643-644` stands as written.
4. **ADR-038 FX-31** (`ADR-038-…md:659`). Current:
   > No commit's flush runs while the room's lock is held.

   Replacement: "No commit's flush runs while the room's lock is held, and no commit runs on a thread
   of the daemon's async runtime (ADR-044 RD-5–RD-7). Answering a peer's history query reads a
   lease of the committed snapshot: it writes nothing, waits for no save, holds neither the
   room's lock nor its publication through the read, and stands however many posts were published
   meanwhile (ADR-044 RD-8); it is admitted and released without the actor (ADR-044 RD-16). A
   node's own post waits only for the owners of its own room that were ready before it, and every
   owner is served in the order it became ready (ADR-044 RD-10)."
5. **ADR-036 H-7**, per the decider's answer 2 (`docs/adr/ADR-036-live-messages-and-requested-history.md:782`).
   Current:
   > lazy object cache is at most 64 objects and 4 MiB, subject to the shared buffer permits. Neither

   Replacement: "lazy object cache is at most 64 objects and 4 MiB, and a cache of tree descriptors
   this node's committed snapshot produced, each with the context its reconstruction generated,
   keyed by (room, history instance, binding, start, leaves), is at most 8 MiB, both subject to
   the shared buffer permits (ADR-044 RD-9). Neither"

Not amended here: ADR-028 R-8. Plan B asked to delete the sentence "The room's view carries it
(`ChannelDetail.unread`)"; no ADR holds that sentence. ADR-036 H-7's `(author, tree range) ->
descriptor` objects (`ADR-036-…md:762`) and ADR-038 FX-29's verifier persistence are ADR-047's.

README index row, for Main: `| [044](ADR-044-the-daemon-stays-responsive-under-agent-load.md) | The
Daemon Stays Responsive Under Agent Load (a response-time budget; the view costs the same however
much is unread; no commit on the event threads; serving is a read, admitted without the actor; a
post waits only for its room, and nothing waits for ever; a restarted room opens in seconds; Linux
gets its receive buffer) — proposed for v0.4.31 | 018, 034, 036, 038, 045, 046, 047 |`

## Sibling ADRs: the shared contract and what they must say

This ADR edits only itself. The contracts below are stated here; the named requirements of the
siblings must agree with them, and Main carries the list.

- **ADR-047 SO-1** (proof records). Agrees since its revision 2 on own-history recovery (own
  headers, the signed root, one promotion commit, no record, no receipt, the 5-entry arm,
  `restore` not reused, existing rows unread before SO-2). This revision accepts its two asks:
  the fork gate and the per-leaf signature re-check go (RD-9, with the one-chain argument). SO-1
  states the evidence rule RD-9 now carries (r14; R13-6): a range is derived only when the target
  head is accepted here and every leaf's validated header is bound to the newest accepted head of
  size at or above its position, a sparse holder's leaves tied by its held interval's
  descriptors; evidence this node does not hold answers `EvidenceUnavailable`, and a derivation
  too large for one exchange answers `Busy{retry_after}` of at most 5 s with SO-1's background
  fill. There is no committed-source-head tie. The frozen-author and own-history recovery
  obligations and their mutants stand; its "third mutant" is "refuse derivation for a frozen
  author", as its note proposes.
- **ADR-047 SO-12** (recovery; r14). It owns draining, reopening and repairing the same file,
  one `Immediate` commit to confirm the reopened store, and `StoreRecovered(room)`; it settles
  no waiter and carries no settlement interface: every ruled commit was answered by its own
  result (RD-7). Its arms 4b and 4c, which held a token across recovery, are withdrawn; its arm 2
  (the native error, staged without a race) stays, with the paste text in this ADR's revision
  note.
- **ADR-046 SY-16, SY-18, SY-21** (serving and what sync keeps; changed r13). RD-9 now carries
  their representation: a served header is bound to the newest accepted head of size at or above
  its position (SO-1), the held interval's descriptors tie a sparse holder's leaves (SY-18), a
  kept interval descriptor is the sparse fallback (SY-16), and a derivation too large for one
  exchange answers `Busy{retry_after}` of at most 5 s with SO-1's background fill (SY-12, SY-21);
  `EvidenceUnavailable` is for evidence not held. Nothing is asked of them beyond what their own
  revisions say; SY-21 must still name a refused inbound request's reason as what status shows
  (RD-16).
- **ADR-046 SY-6 and SY-10**. Reference RD-16 for inbound admission off the actor (not RD-4/RD-5,
  which shorten the queue but do not leave it); SY-10's join answer releases its capacity through
  the same guard. SY-20 reports the served wait; it is not a gate.
- **ADR-046 SY-24** (ledger rows 11, 14, 17; fix-list items 85 and 87). The outbound retained-flow
  cap and its failed retirements are ADR-046's; RD-16 states the contract the inbound side meets
  (capacity released by the serving task's guard on every exit; a refusal records its reason) and
  SY-24 must give the outbound side the same two properties, or delete the cap (R2).
- **ADR-046 SY-7 and SY-20, ADR-042 TR-3** (served progress). RD-3's "sync advances once a
  minute" counts a completed served round that moved an object; this ADR supplies the terminal
  receipt (`BoundedSyncDone` from RD-16's path) with what was served.
- **ADR-045 J3 and host B**. J3's load is RD-14's text (open-loop steps at 2 a second with a 5 s
  acknowledgement bound; closed-loop 200 B posts per session; the sampling rules); its row must
  drop "stepping closed-loop" and "330 B" and carry the run record RD-14 lists. Its claims (a)–(d)
  are RD-1 (1 s), RD-2 (every acknowledged post within 5 s, start to CLI exit; the median, 99th
  percentile and maximum, `vox status` latency, CPU, memory and flushes per second recorded for
  v0.4.30 and the candidate and blocking nothing; no target until the decider sets one from
  them, rows 80 and 81; r16), RD-3 and RD-11. RD-12's kernel arm cannot
  run in a container (`rmem_max` is `init_net` only): host B's role for that arm is root in the
  `podman-machine-default` VM's own namespace, set and restored by the driver, with the kernel
  recorded; ADR-045 must say so, or name another disposable VM.
- **ADR-042 TR-8, TR-23, TR-2 and the lanes**. TR-8's `<done> of <total> rows` is RD-11's
  progress; TR-23's two doctor lines are RD-13's; the serving-side refusal text for
  `EvidenceUnavailable` and a refused inbound request's reason (RD-16) are TR-2's; `vox status
  --json` carries a room's pending owners (RD-10's staging reads it) and the serving book's
  inbound tokens per port (RD-16's proof reads it).
- **ADR-040 NW-1 and NW-2**. A received-entry admission's wait for the room's pending write is a
  queue place (RD-10), so its `RoomWrite(room)` edge is bounded by the owners ahead of it; a
  failed commit is told "cannot save: disk" at once (RD-7, r14): it is not a wait, and no save
  waits for a flush that is not its own; NW-2's wait is the room's, until `StoreRecovered(room)`
  lets the next save run.
- **ADR-043**. No change required any more: a capability change reserves no rooms (RD-5).

## Implementation order and related work

In dependency order:

1. RD-4 (no dependency; the cheapest; removes the only cost on the actor that grows with content).
2. RD-11 (no dependency).
3. RD-5 and RD-6 (the native-save shape for the inbox, Drive and attention).
4. RD-7, with 3: every `*_save.rs` path that reports a save is audited to reply only from its
   own `Immediate` commit's result, and to run it off the actor (r14).
5. RD-10, after 4 (the queue replaces the node-wide gate).
6. RD-8, RD-9 and RD-16, after 4 for the budget, not for correctness. RD-9 lands with or before
   ADR-047 SO-1; RD-16 with ADR-046 SY-6's call site.
7. RD-12 and RD-13 (no dependency; RD-13's words with ADR-042).
8. RD-3's sync advance needs ADR-046's served-progress call site.
9. Each proof lands with its requirement; J3 (RD-14) runs on the composed candidate.

Experiments, each ready to run; none blocks a design choice:

- **E-14**: after RD-8 and RD-16, attribute what remains of the operator's 1–5 s exchanges on the
  fleet: the served wait (SY-20) and the serve time per request, on J3. Verification, not
  attribution.
- **E-17**: stage RD-15's arm on the release asset and raise the seed until the post tail and the
  status bound are red; measure whether RD-16's mutant is red there.
- **E-18**: on a scratch node seeded with 4,000 named-session posts and 14 registrations, 7 dead,
  restart with RcaChurn's `[refresh]` trace and count walk restarts and turn gaps. Sizes RD-11's
  seed and settles beast's minutes.
- **E-16-linux**: one flush-cost sample on ext4/overlay on the fleet's host B, never on the
  operator's machines; engineering evidence for the release post, no decision rests on it.

Related lanes: ADR-040 owns the "attention waits for current computer trust" refusals (item 28);
RD-6 changes only how the ledger is read. ADR-041 owns what a restart needs from a person; RD-11 owns
how long the room then prepares. ADR-042 owns every word status and doctor say (preparing progress,
served or fetched, the buffer line; item 51). ADR-045 runs J3 and RD-12's kernel arm on the fleet.
ADR-046 owns sync progress and what sync keeps; two rounds per node there multiply the author's
served load, which RD-8 makes reads and RD-16 keeps out of the actor. ADR-047 owns the proof
records already on disk, the snapshot pin (item 21), own-history recovery's proof (SO-1) and the
maintenance save rate (item 22).

## Consequences

### Positive

- An agent node answers `vox status` and hooks as fast under load as idle, and its posts commit in
  a fraction of a second.
- Readers keep up with the busiest author; it serves them without its actor and keeps no record
  for serving them.
- Session moves, keys and governance keep moving while an author posts without pause.
- A restart costs seconds of preparing, not minutes.
- A Linux install gets the full receive buffer and says so only when the kernel agrees; otherwise
  the person is told the exact commands.

### Negative

- More commits wait in memory between flushes. Nothing acknowledged is lost (the reply waits), but
  a crash loses more unacknowledged derived work, which peers resend.
- After a restart, a holder that is not the author (or a restored author) reconstructs each
  subtree it serves from headers while the cache misses (CPU, no writes), O(k) per k-leaf range;
  an author serving the feed it appended never does. A sparse holder serves less than it did
  with the cache: ranges whose leaves it lacks are refused and asked of another member. A
  returning author whose serving holder restarted re-asks its proof once (the context
  authorization is in memory now, not a row).
- After a flush fails, every durable reply fails with the disk's error until the store recovers;
  today each would fail on its own commit. The person sees the same "cannot save: disk".
- The render index is rebuilt once at the first open of v0.4.31; on a multi-GB store this takes
  minutes, reported as preparing progress, measured by J3's stage 3.
- Every ruled save holds redb's writer for its own flush, 20–81 ms on this Mac, so a save
  behind k others completes in about (k + 1) × that (RD-7, r14; calculated); the gate is 5 s per
  post, the figures are recorded, and the speed target is set after measurement (rows 80, 81;
  r16).
- Run as root on Linux, the installer writes one file under `/etc/sysctl.d`.
- Three actor-owned structures (the room registry, the serving budget, the inbound tokens) become
  shared with connection tasks behind short locks.

### Neutral

- No wire change. The store stops gaining proof records from serving; the render index gains a
  filter keyed by author.

## Review record

Two independent reviews by GPT-6.1-Sol on 2026-11-12. Each finding was checked against v0.4.30
(and, in the second pass, against this ADR's own revised text) before it was accepted or refused.

### First pass: thirteen findings, verdict "needs revision"

| # | Finding | Classification | Answered by |
|---|---|---|---|
| 1 | Off-actor Drive admission loses the fence its actor turn gave it; `DeliverSessionDrive` is a frame write, not an inbox commit | CONFIRMED (`actor.rs:23354-23413`, `:23416-23470`) | RD-5: Drive admission as a room owner; re-check under the lock; the permission fenced at the store's writer (r3); `DeliverSessionDrive` unchanged; the three-act Drive proof (r3) |
| 2 | Deleting proof-range persistence breaks own-history recovery (`own_history.rs:384-404`, `:409-449`, `:1522-1588`) | CONFIRMED | RD-9 (own-history recovery); the contract for ADR-047 SO-1, which its revision 2 adopted. Second pass: closed |
| 3 | `with_snapshot` holds the publication mutex through disk reads; the actor's publication takes the same mutex under the room | CONFIRMED (`read_resource.rs:360-383`, `:497-533`; `actor.rs:24920-24924`; `source.rs:518-568`) | RD-8: the read lease; the stalled-read arm. Second pass: closed; its retry rule replaced (N4) |
| 4 | A duplicate admission can report success for data not yet durable | CONFIRMED (`session_ingress.rs:821-826`) | RD-7: the writer-captured watermark; the duplicate proof arm (r3). Second pass: closed |
| 5 | The measured inbound actor-queue wait is not removed by RD-4/RD-5/RD-8 | CONFIRMED (`actor.rs:2543-2570` → `:11933-11944` → `start_bounded_inbound`; plan A: max 12.0–15.7 s) | RD-16; the consumer migrated and capacity released by a guard (r3, N5) |
| 6 | Absolute "posts first" starves maintenance; the stand-aside can return Busy for ever; the physical writer | CONFIRMED (`maintenance_save.rs:622-642`, `actor.rs:7876-7889`, `source.rs:744-761`) | RD-10: FIFO among ready owners; the honest predecessor bound and node-save enrolment (r3, N7) |
| 7 | A flusher that wakes on any unflushed commit flushes derived churn, against FX-30 | CONFIRMED (ADR-038 `:643-644`) | RD-7: durability demand; the quiet arm. Second pass: closed |
| 8 | Failed flush, store lifetime and close were undefined | CONFIRMED (`store.rs:415-432`, `:1371`) | RD-7: attempt-scoped failure, one recovery owner, the close order (r3, N2) |
| 9 | "O(log n) from headers" is wrong; sparse nodes cannot reconstruct; generated contexts must be servable | CONFIRMED (`proof_range.rs:106-107`, `:150-154`, `:199-264`; `server.rs:411-439`) | RD-9: the contract, the bounds, the handoff that outlives a stream, the cache's provenance and order (r3, N1, N6, N8) |
| 10 | The durability mutant (kill after the reply) is not deterministic | CONFIRMED | RD-7's proof: the hold at the store's flusher staged before the write. Second pass: closed |
| 11 | The measured load was closed-loop, about 0.27 acknowledged posts a second; seeds and reds unverified; no offload-only control | CONFIRMED (`rig.py:344-353`; L2b `rig.log:187-190`; L2 `rig.log:173`) | Context; RD-1/RD-2 scoped per arm; RD-14's load written once, open-loop steps with an acknowledgement bound (r3) |
| 12 | The any-author filter makes the open cost other members' records | CONFIRMED (`pending_session.rs:1423`, `:1454-1494`; `private_index.rs:205-214`, `:230-250`) | RD-11: `SessionRecord(author)`; the private phase over `RefreshRecords`. Second pass: closed |
| 13 | The installer reports success from the command's exit; the stub proves nothing about the kernel | CONFIRMED | RD-12: readback rule; the apparatus arm with the `/proc` stand-in; the kernel arm in a VM's initial namespace (r3, N9) |

Citation audit of the first pass, accepted and applied: `page_manager.rs` →
`page_store/page_manager.rs`; status latency is queue + one owed publication; RD-4's bound is two
walks of 128; all attention commits go off the actor; `flush_authors_before_ack` is kept in
meaning as demand; `store.rs:146` bounds redb's cache only; ADR-036 H-7 is not evidence of
O(log n); the doctor verb is `vox agent doctor`.

### Second pass: nine findings, verdict "needs revision"

| # | Finding | Classification | Answered by |
|---|---|---|---|
| N1 | Generated contexts were given to a serving job that ends with its one WANT; `Query::Context` is a new stream; `authorize_recovery_contexts` is a persisted write, not a per-job list | CONFIRMED (`history_stream.rs:206-237`, one `server::answer` per stream; `source.rs:296-324` `write_owned`; `own_history.rs:345-359`, `:595-647`; `server.rs:118`) | RD-9: the proof handoff in the serving book, per peer, bounded, consulted by the next stream's `Query::Context` and by `recovery_context_allowed`; the `keep_recovery_context` write deleted; the multi-stream cold-holder and returning-author arms |
| N2 | A waiter that joins an in-flight failing flush is never told; "next demand retries" spins against redb's latched error; close order unspecified | CONFIRMED (my own text; redb latches I/O failure until recovery) | RD-7: `covers_through` per attempt; `failed` stops attempts until the store's recovery edge clears it; waiters with `txn <= covers_through` get the error whenever they arrived; `await_durable` is one call; the six-step close; the late-waiter arm |
| N3 | Reserving every room for a capability change ties a revocation to unrelated poisoned or busy rooms | CONFIRMED (`policy_save.rs:439-452` excludes rooms today; `reserve_pending_write` → `pin_history_read` → `save_failure()` on a poisoned room) | RD-5: the keyring read inside the admission's own transaction at the store's writer; no room reservation; ADR-043 needs nothing |
| N4 | Discarding a lease read when the publication revision changed starves reads under continuous posting | CONFIRMED | RD-8: a result stands unless the lease was revoked or the instance changed; the two-posts-during-a-read arm and its mutant |
| N5 | `BoundedSyncDone`'s consumer takes the attempt from `ports`; tokens had no release path off the actor; the per-port cap would exhaust | CONFIRMED (`actor.rs:13543-13546`; `ports.rs:727-732`; `INBOUND_PER_PORT` = 3, `ports.rs:39`) | RD-16: the serving task's guard releases budget, token and `Running` exactly once on every exit before posting an immutable receipt; the consumer reads the receipt; retirement via fences; the parked-actor arm (four reads, a leave mid-exchange) |
| N6 | A head-independent cache key can return one branch's subtree for another when reconstruction is refused for a frozen author | CONFIRMED as stated against r2; moot once only committed-chain material enters the cache and the fork gate is gone (`observe_history_head`, `sparse.rs:2676`; acceptance refused on conflict, `:2582`) | RD-9: the cache holds only what the committed snapshot produced; verifier-held descriptors never enter it; the one-chain invariant |
| N7 | FIFO does not give one predecessor; node barriers need enrolment and drain; hold time includes the durable wait | CONFIRMED | RD-10: the bound stated as owners ahead (P − 1 + M + 1), each one commit plus a shared flush plus install; node saves enrol at every room's tail; one place per owed kind; the non-empty-queue staging check |
| N8 | Reconstruction ran before the cache lookup, defeating the memoization | CONFIRMED | RD-9: order is canonical range, cache, reconstruction, and `Visit` consults both before descending; "once per process life" withdrawn |
| N9 | `rmem_max` is an `init_net` setting; a rootless container with `NET_ADMIN` cannot stage it | CONFIRMED (`net/core/sysctl_net_core.c`, `sysctl_core_net_init`) | RD-12: the kernel arm as root in the `podman-machine-default` VM's own namespace (or another disposable VM), set and restored by the driver; staging named when not possible; ADR-045's host B row |

Hard cases of the second pass: the Drive proof re-staged in three acts (hold before the owner's
check; admit then revoke; the opening); the duplicate-source arm added (RD-7); the serving book's
lock holds no I/O (RD-16); `served_wait_ms` is report-only everywhere and the 100 ms acceptance
is deleted (RD-16); L2's 581 ms is not a J3 red (RD-14); J3's "stepping closed-loop" and "330 B"
are mismatches ADR-045 must fix to RD-14's text; the SY-18/SO-1 receipt conflict is settled on
this side by naming the tie reconstruction needs (the position index and the `source_heads` tie,
RD-9) and accepting receipt deletion for serving; the reviewer's "historical availability after a
fork" is answered by removing the fork gate with the one-chain argument, which ADR-047's revision
asked for and this revision accepts; "restored author has indexed every old subtree" is not
claimed (RD-9). The reviewer's decider questions 1–6 map to ADR-045 Q1, this ADR's Q4, Q1, Q2,
(settled by RD-9, no vote) and Q3.

### Third pass: four findings, verdict "needs revision" (close)

Seven second-pass findings closed; N2 and N7 partly. Revision 4 changes only what these four
touch.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R3-1 | Recovery cleared the only failure record; a reopened backing has lost a None-committed transaction, and a later flush's scalar mark would certify its number | CONFIRMED (SO-12 drops and reopens the database; `page_store/page_manager.rs:1876-1901` keeps a None commit's root in memory only; the Vox transaction number is a Store-local counter, `store.rs:1988-1995`) | RD-7: the `Commit` token carries the backing generation; durability is answered from the token's own generation; a reopen freezes the old generation's mark before dropping the backing and makes every higher token terminal ("not kept"), for late subscribers too; nothing clears `failed`; the six-step walk; arm four extended with the reopen and a second mutant |
| R3-2 | `P − 1 + M + 1` omits Drive and received admissions, node barriers and a policy owner's multi-transaction hold | CONFIRMED | RD-10: the general bound is the finite set of owners enrolled ahead, each with its complete retained operation; the arithmetic is scoped to RD-15's arm with its restrictions named |
| R3-3 | Act 3's hold parks the Drive owner after it holds the pending write, which excludes the end it needs | CONFIRMED (RD-5's own exclusion rule) | RD-5's proof: the hold moved to the actor's receipt of the command, before the owner enrols; the end is observed installed; an owner that acquired first is admitted first (act 2) |
| R3-4 | A 200 ms timer offers 5 steps a second | CONFIRMED | RD-14: 500 ms; ADR-045 J3 copies it |

Also applied from the third pass: a `test-knobs`-only hold is permitted apparatus (RD-16's
parked-actor arm must observe that the park engaged and say CANNOT MEASURE on an unfeatured
binary); unverified v0.4.30 reds are not release evidence (the table in section 8 says which are
verified, with the receipt, and which are owed, with the run); `Keyring::load` in a Drive
admission is O(keyring size) under the writer, a stated tradeoff, not a measurement. The
reviewer's five decider questions map to this ADR's Q1, Q2, Q3, Q4 and ADR-045 Q1.

### Fourth pass: two findings, verdict "needs revision" (narrow)

All four engineering fixes and N2/N7 closed; the five decider questions stand.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R4-1 | Arm four never delayed the first waiter past the reopen, so the generation-dropping mutant could fail the post on the old flush error and pass | CONFIRMED (my own staging) | RD-7 arm four: two feature-built holds (`VOX_TEST_HOLD_DURABLE_WAITER` before `await_durable`, `VOX_TEST_HOLD_DURABLE_RESULT` after the wake and before the read), owning no writer, transaction, lease or room lock; recovery and a successful generation-2 flush driven through a second room while the waiter is held; the asserted output is the post's exit and `vox room read` before and after a restart; mutant two is red because the scalar mark is satisfied by generation 2's flush |
| R4-2 | RD-12 and RD-13 were labelled "verified" on source reading alone | CONFIRMED | The reds table has three states (run-backed with receipt, source-confirmed, owed) and every row is relabelled; RD-12 and RD-13 are source-confirmed defects with their baseline runs named |

### Fifth pass: two findings, verdict "needs revision" (narrow)

R4-2 closed; R4-1 partly; the generation design and every earlier closure stand.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R5-1 | In the late-subscriber run nothing raised demand before the flusher was released, so the stated failed attempt was never reached | CONFIRMED (RD-7 makes `await_durable` the only place demand is raised) | RD-7 arm four step 2: an R2 post enters `await_durable` while the flusher is held, observed as R2's waiting owner in `vox status --json`; its failed completion (step 6) is what drives the reopen; R2 is reused only after |
| R5-2 | The flusher hold proved no header before the attempt, not where the attempt failed; redb writes the primary header before its final `storage.flush()` (`page_store/page_manager.rs:1838-1856`), so a late failure can leave the post readable | CONFIRMED | RD-7 arm four step 4: a Session step on the full disk latches the I/O error before the release, observed by its "cannot save: disk" receipt and the log; the attempt then fails at `check_io_errors()` (`:1796`), before any header; a latch not reached within 30 s is APPARATUS; the absence assertion and the scalar mutant's lost-post verdict are confined to this staged case, and PF-2's general arm lets an unconfirmed post survive |

### Sixth pass: one finding, verdict "needs revision" (narrow)

R5-1 closed; R5-2 partly.

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R6-1 | A Session batch submitted after the disk is filled is refused by ADR-047 SO-11 before `begin_write`, attempts no OS write and latches nothing, so arm four's latch was never reached | CONFIRMED (SO-11's admission reserve and "a refusal attempts no OS write") | RD-7 arm four steps 3–4: the step is admitted while the disk meets SO-11's reserve and parked by SO-12's arm-2 hold between admission and native write; the disk is filled; the batch is released with the flusher still held; the latch is observed by the receipt and the exact native error in the log (`No space left on device`), never a floor refusal; APPARATUS when not reached within 30 s |

### Seventh pass: one finding, verdict "needs revision" (routing)

R6-1 closed; the decider's answers recorded correctly; ordinary lost-save durability keeps its
blocking in-tree proof (RD-7 arms one–three and five).

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R7-1 | Arm four was assigned to fleet J5 as its blocking proof, but J5's checks did not enrol it | CONFIRMED (ADR-045 J5's checks (a)–(g) at that revision) | ADR-045 revision 7 added J5(h), "the old waiter across recovery"; RD-7 arm four, answer 6 and the reds table now name J5(h) as the blocking proof, the in-tree full-disk journey optional |

### Revision 9, after ADR-047's E-7 (no review finding; the ADR was accepted after the eighth pass)

| # | Measurement | Classification | Answered by |
|---|---|---|---|
| E-7 | On redb 4.3 a failure before the header leaves the old roots on a fresh open; a failure at the final `fsync` after the header leaves the failed commit's rows (51 of 50); `Durability::None` commits since the last flush are lost on reopen; so "not kept" cannot be decided from the generation alone | CONFIRMED (`store-exp-receipts/e7-fault-injection.log`: `[write-data]`/`[write-header]` 50 of 50, `[sync]` 51 of 50 with `sync_data -> injected EIO` after the header write, `[nondurable]` 70 on the handle, 50 after; consistent with `page_store/page_manager.rs:1838-1856`, the header written before the final flush) | RD-7: the old-generation verdict is the reopened store's (ADR-047 SO-12 state 2), read through the failed attempt's redb transaction id; `Ok` only after the new generation's first flush, so a reply still means on disk; the walk restated for both positions; arm four and J5(h) stay the pre-header case and their assertions follow; the post-header half is SO-12's arm 4b; `StoreReopened` → `StoreRecovered(room)` |

### Ninth pass: four findings on revision 9's sentence, verdict "needs revision"

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R9-1 | Comparing a token's number with the reopened store's last committed redb id crosses counter domains, and redb's repair advances the id at open (`db.rs:1658-1670`) | CONFIRMED | RD-7: the flush attempt writes `durable_watermark = covers_through` (a Store sequence) in its own transaction; recovery reads it before anything writes; tokens are compared only with that Store prefix; redb ids are never compared |
| R9-2 | "Every Derived/Received commit since the last flush is not kept" contradicts group commit: a covered None commit of any class survives a post-header failure; E-7's `nondurable` run was a pre-header fault | CONFIRMED (the covering flush carries the whole prefix; `e7-fault-injection.log` `[nondurable]` used the data-write fault) | RD-7: classification by the recovered prefix only, class never enters; the sentence and its sibling copy withdrawn; arm 4b's fixture carries an earlier Received None commit |
| R9-3 | A retained token lacked a fallible confirmation: the early-Ok path through the promoted mark, and a stranded waiter if the confirming flush fails | CONFIRMED | RD-7: `retained_through` kept apart from `durable`; a confirming flush by the recovery owner before any retained answer and before `StoreRecovered(room)`; success → `Ok`; failure → that flush's error to every retained token at once, released, new generation failed from its first attempt, nothing pending for a later reopen; close → `AtRestLocked`; never a later generation's scalar mark |
| R9-4 | Arm 4b did not hold an old token across the reopen, so its "always not kept" mutant was not forced | CONFIRMED (ADR-047 arm 4b as inspected) | RD-7's delegation to arm 4b now states what it must hold (RD-7's two holds), inject (the flusher's `fsync`), assert (caller `Ok`, post shown, earlier Received entry shown) and its second act (confirmation failure: "cannot save: disk", never saved) |

### Tenth pass: two findings on revision 10's rule, verdict "needs revision"

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R10-1 | A persisted Store sequence aliases the counter that restarts at zero (`store.rs:398-410`): after a restart a lost post with sequence 1 is "retained" by an old watermark of 100 | CONFIRMED | RD-7 (r11): no persisted number and no sequence comparison across lifetimes; an old-generation token is answered by looking its identity up in the recovered store after `StoreRecovered(room)`; content-addressed identities cannot alias; coordinates carry the body hash |
| R10-2 | ADR-047 SO-12 read a different row and gave a second reopen a different lifecycle | CONFIRMED | Main's decision (a): RD-7 owns the waiter rule, SO-12 owns the recovery mechanics and cites RD-7; the facts SO-12 must provide are in the revision note; settled outcomes are kept until consumed and never reclassified |

Revision 11 chose the lookup over the watermark on Main's decision (b): every reply-owing
commit has a durable identity (entry hash; source receipt or inbox coordinate plus body hash;
Drive operation id; ledger registration), the lookup is one indexed read per waiter once per
recovery, a retry with the same identity is rightly `Ok`, `Ok` is given only after the reopened
store's durable commit, and a dead caller leaves an unconsumed outcome and nothing else.

### Eleventh pass: four findings on the lookup, verdict "needs revision"

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R11-1 | Reply-owing metadata saves had no predicate: a capability-only grant changes the sealed keyring and appends nothing (`trust_save/grant.rs:59-167`); private Session records are not public objects; node-global waiters had only a per-room trigger | CONFIRMED (`Keyring` has no per-mutation id, `trust.rs:195-205`) | RD-7: predicates enumerated from the `*_save.rs` workers in three kinds, witness, state, none; keyring, metadata, read marks, room presence and local keys are state predicates; private records by their hash; `Remember` results are "could not be confirmed"; settlement is the store's, run for node-global tokens whether or not a room exists |
| R11-2 | A live lookup after the event can find a newer, unflushed retry with the same identity | CONFIRMED | RD-7: one settlement snapshot opened under the writer at the durable commit, with no write, retry, consumption, reclamation, teardown or event admitted until every token is settled; the duplicate-after-recovery act in J5(h) and its live-read mutant |
| R11-3 | A ledger record's presence does not prove its latest mutation (`admit_notice` flips `notice_admitted` on an existing session, `ledger.rs:698-707`) | CONFIRMED (`revision` is incremented by every save, `ledger.rs:300`) | RD-7: attention predicates are the session's `revision` at or above the one the operation produced plus the field it set; arm 4b's lost-Admit act and its existence mutant |
| R11-4 | The inbox row is deleted when the step moves into the Session (`session_ingress.rs:961-987`, `pending_session.rs:1158-1164`); teardown could erase a witness before settlement | CONFIRMED | RD-7: a source-less step is settled by its inbox row or by the private record for its session and `seq` with the same body hash; consumption and teardown wait behind the settlement; an absent container is "could not be confirmed", never "not kept" |

Revision 12 adopted Main's direction (one snapshot, a write fence, enumerated predicates) because
it closes R11-2 and R11-4 by construction and bounds R11-1 and R11-3 honestly; its cost is the
settlement batch (tens of indexed reads, under 100 ms) during which new writes wait.

### Twelfth pass: six findings, verdict "needs revision"

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R12-1 | Offer dismissal (`offers/native.rs::dismiss`, `policy_save.rs:1890-1920`) is a committing reply path with no predicate | CONFIRMED | RD-7: a state predicate over the dismissed-offers set's `(room, OfferBasis)` pairs; arm 4b fixture |
| R12-2 | `Received` leaves no ticket (`ledger.rs:796-830` clears `output_pending`); `write_session` paths do not increment `revision` | CONFIRMED (`save_session` `:299-301` increments; `scanned`/`pending` use `write_session`) | RD-7: per-operation post-state predicates (Admit, Prepare, Received with or without input, Resolve); revision captured only for `save_session` operations, as a floor; superseded field → "could not be confirmed"; the no-input Received act |
| R12-3 | A witness consumed and expired before the failure (`expiry.rs::sweep_private`) read as "not kept"; established success was discarded | CONFIRMED | RD-7: a token at or below its generation's `durable` mark is `Ok` without a lookup; otherwise an absent witness whose domain header sequence (feed head, inbox `session.next`, `DriveIndex.next`, private index `next`, all written in the write's own transaction) has passed the token's sequence is `Ok` (kept, then retired); not passed → "not kept"; no new row, index or counter |
| R12-4 | "the bridge retries with the bodies it kept" replays an uncertain commit, against `session_ingress.rs:240-271` and `host.rs:6243`; "nothing was sent" for an uncertain Drive | CONFIRMED | RD-7 and RD-5: "not kept" → `NotCommitted{bodies}` (definite, the only retry path); "could not be confirmed" → `Unconfirmed`, terminal, no replay; Drive wording split the same way; a same-id Drive retry is allowed only by `admit_drive`'s deduplication with its own flush |
| R12-5 | "tens of tokens, under 100 ms" was unsupported (admissions are node work, dead callers' tokens retained); no `(session, seq, body-hash)` index exists | CONFIRMED | RD-7: the bound withdrawn; the set is the unflushed suffix's unconsumed tokens; one or two indexed reads each on the settlement's blocking thread; the consumed-body lookup is gone (the header sequence replaces it); the pause is measured in J5(h)'s and arm 4b's run records; no cap added |
| R12-6 | A new post has a new hash, so the live-read act forced no red | CONFIRMED | J5(h)'s act: the token under test is a deduplicated Session source identity with unchanged bindings in both schedules; the duplicate's completed None commit is ordered before the verdict by its own `VOX_TEST_HOLD_DURABLE_WAITER` park engaging; the assertion is the original admission's receipt; the old post keeps the scalar-mark mutant |
| 047 r9 | A refused open is not a failure; any native failure before the settlement returns is one notification | ADOPTED | RD-7: tokens stay pending through `DatabaseAlreadyOpen`; repair, ballast release, the durable commit and the settlement's own reads share SO-12 state 2(5)'s single notification → "could not be confirmed" |

### Thirteenth pass: six findings, and the decider's ruling

The thirteenth review (`adr-044-sol-review-13`) found six defects in revision 13's settlement
rule and judged RD-7 "not yet a rule a builder can implement". On the reviewer's and the
author's advice the decider withdrew group commit (ledger row 74). Closure:

| # | Finding | Disposition |
|---|---|---|
| R13-1 | Dismissal's committed result is bounded, not every requested basis | Falls away: no predicate dispatcher exists (RD-7 r14) |
| R13-2 | The attention dispatcher covered four operations of more | Falls away: no dispatcher |
| R13-3 | A receipt-only source admission allocates no inbox sequence | Falls away: no witness or sequence rule |
| R13-4 | The live-read act had a bridge single-flight cycle | Falls away: the act is deleted with the mutant it served |
| R13-5 | The header fallback above the old durable mark was not exercised | Falls away: no durable mark, no fallback |
| R13-6 | The sibling instruction to SO-1 still demanded a committed source-head tie | CONFIRMED and fixed: the SO-1 paragraph now states RD-9's corrected evidence rule and `Busy{retry_after}` |

Revision 14 deleted, with the rule: the flusher, tokens, generations, the durable mark, the
settlement snapshot and its fence, the predicate kinds and the reply-owner inventory, the witness
and header-sequence rules; J5(h) and its scalar-generation and live-read mutants; arm 4b's and
4c's settlement fixtures; the six SO-12 facts as a settlement interface; the terms "Flusher" and
"Durability demand". RD-7 shrank from 366 lines to 133.

### Fourteenth pass: seven findings, verdict "needs revision"

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R14-1 | `DeliverSessionDrive` commits nothing but its frame write takes the writer mutex through `with_publication_fence` (`store.rs:966-969`) on the actor's turn, so a valid delivery waits behind an Inventory's debt flush | CONFIRMED (`api.rs:788-795` → `read_resource.rs:233-249` → `store.rs:966-969`; `with_publication_fence` is `self.writer()?`) | RD-5: the table's row 3; a non-blocking fence attempt, a busy delivery retained as a room owner and re-checked at publication; the held-commit arm's Drive act |
| R14-2 | Room pause, service add/remove and own-key response installation commit `Immediate` on the turn through `put_segment` and `accept_skdm_mode` | CONFIRMED (`store.rs:1080-1093` `ruled()` + `commit()`; `channel.rs:3655-3700`, `:3991-4021`, `:7279-7441`) | RD-5: rows 5, 6, 7 and 9 in the native-save shape with their helper transactions; the pause act |
| R14-3 | History activation holds the room's owned guard across `start_plan`'s `Immediate` commit, and `SessionActivity` on the actor waits behind it | CONFIRMED (`actor/history_demand.rs:1359`, `:1553-1574`; `node/history_demand.rs:893-940`; `actor.rs:13798-13803`) | RD-5: row 8, the guard released before the commit, the request enrolled as owner; the held-commit arm's history act |
| R14-4 | "Every queued commit fails `begin_write`" assumed a FIFO the mutex does not promise; a waiter whose first transaction begins after recovery gets its own result | CONFIRMED (`store.rs:523`, `:970-981`) | RD-7: scoped to requests that attempt `begin_write` while latched or recovering; a later first transaction is its own result, not a replay; the proof holds recovery until B's refusal is observed |
| R14-5 | A four-commits-a-second derivation unsupported; the 300 ms p99 both asserted and "not promised" | CONFIRMED | RD-7: conditional arithmetic only ((k+1)·S; 120–486 ms; 0.4–1.62 s); the decider then ruled (rows 80, 81): 5 s per-post gate, figures recorded, no target until measured; RD-2, RD-14 and the J3 instruction changed together; the three clocks named apart |
| R14-6 | RD-8 still raised demand on the deleted flusher; RD-10 charged a shared flush and one commit per owner; the budget said flushes are shared | CONFIRMED | RD-8: the existing `flush_received_through` barrier, no lock or lease across it; RD-10: the sum of every retained transaction's own flush plus installation; the budget sentence corrected |
| R14-7 | Arm two mixed A's uncertain and B's definite assertions and claimed an unreachable duplicate; arm three's mutant was not executable | CONFIRMED | RD-7's proof: A asserts the false definite wording; B is an independently admitted source-less batch with a staged precommit refusal, exactly one step after its retry, mutant = refusal turned `Unconfirmed`; arm three's mutant = commit `Err` → `NotCommitted(bodies)` with the bridge's Held/retry path and a duplicate on a source-less step |

### Fifteenth pass (frozen `89c2064ec`): four P1 findings, three P2 to task acceptance

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R15-1 | `SkdmRefused`'s handler persists delivered/history records through `put_segment` (Ruled, `Immediate`) on the turn | CONFIRMED (`actor.rs:2872-2897`, `:12485-12503`; `channel.rs:5621-5660`; `store.rs:1080-1093`) | RD-5 row 9a: native-save shape, install before the refusal handling continues; the key-refusal journey's held-writer act |
| R15-2 | `note_held` writes `Derived` through `put_segment_derived`, which takes the writer mutex on the turn | CONFIRMED (`actor.rs:13683-13689`, `:22279-22296`; `channel.rs:8772-8792`; `store.rs:970-974`) | RD-5 row 9b: a keyed newest-wins worker write, actor bookkeeping kept, stays `Derived`; the bounded-round act in the held-writer journey |
| R15-3 | Row 8 covered only new plans; Resume activations commit `Immediate` under the owned guard too | CONFIRMED (`actor/history_demand.rs:2798`, `:2868`, `:3114` → `node/history_demand.rs:957-1000`) | RD-5 row 8 extended to new and resumed, public and private; the Resume act |
| R15-4 | The withdrawn 300 ms target survived in the ADR-045 sibling instruction, a consequence, the budget's "actor busy under 100 ms/s" and RD-2's proof remark | CONFIRMED | Budget, RD-2 proof, consequence and sibling J3 corrected to rows 80/81; the measured v0.4.30 baseline (`perf-baseline`) cited as baseline, never as target |
| R15-5, R15-6, R15-7 | P2: staging of the new held-commit acts at their consuming dependencies; asserting the shipped bridge's Held reply; the uncertain poster's text | to task acceptance by row 83 | `v0431-owed-p2`; frozen text unchanged |
| rows 82, 82a, 82b | The daemon's queues: no operation waits for a quiet room; two lanes per room, alternating | applied | RD-10's lane rule; sibling rows ADR-040 NW-3, ADR-048 TC-4/TC-5, ADR-046 SY-29 |

### Sixteenth pass (frozen `6cf5836b1`): two P1 findings, the P2s to task acceptance

| # | Finding | Classification | Answered by |
|---|---|---|---|
| R16-1 | RD-10's "What changes" still enrolled a node policy save at every room's tail, drained older owners, used `reserve_policy_rooms`, and retained a room across a whole multi-transaction Untrust, against the lane rule and ADR-048 TC-4/TC-5 (ADR-048 review 11 R11-1 found the same conflict) | CONFIRMED (revision 16's own text) | RD-10 "What changes" rewritten: keyring batch with no room reservation; room-local control turns after its install boundary; every turn releases the pending write, bindings, pins and leases after its one transaction; a multi-step operation keeps only stage, stamp, reply and continuation and takes another control turn; the child runs in the parent's turn under its current grant; `reserve_policy_rooms` and whole-operation retention deleted |
| R16-2 | The control bound was unconditional, which FIFO plus alternation cannot meet for C3 behind C1, C2 | CONFIRMED | RD-10 title and bounds use row 82c's sentence: the bound holds once a control transaction is at the head of its lane; from enrolment it also waits for the control transactions ahead and the one authored turn each permits |
| P2s | owed to task acceptance by row 83 | — | `v0431-owed-p2`; frozen text unchanged |

## The decider's answers (2026-11-13)

Recorded from the cross-ADR ledger, rows 28–32 and 51. No question of this ADR's remains open.

1. **Durability** (was Q1; row 28, superseded by row 74 on 2026-11-13 15:45 PST): "One save,
   one trip in v0.4.31. Group commit can come back later with measurements." Every save whose
   reply means "on disk" makes its own flush, off the actor; a reply is sent only after it; a
   failed flush puts only that one command in doubt, told "could not be confirmed"; nothing is
   replayed. Applies to RD-7, RD-5, RD-2, RD-10.
   **Speed** (rows 80 and 81, 2026-11-13, after the fourteenth review asked which latency gate
   stands): "Make the hard gate 'every post within 5 seconds' and record the 99-of-100 time as a
   number in the results, without blocking on it"; "we want to be as fast as possible", "and
   efficient", "but we need to measure where we're at", "before setting a target". Applied in
   RD-2 and RD-14: the per-post gate is 5 s (start to CLI exit) under J3 and the soak; the
   median, 99th percentile and maximum are recorded and block nothing; no speed target is
   written until J3's numbers exist. The cheap arm's 1 s and RD-1's status bound are unchanged.
2. **The in-memory cache** (was Q2): add it, at most 8 MiB, nothing written. Applies to RD-9 and
   amendment 5, which Main now applies at sign-off.
3. **The Linux installer** (was Q3): it writes `/etc/sysctl.d/90-vox.conf` and reads the kernel's
   value back when run as root; otherwise it prints the commands; never `sudo`, never a file
   capability. Applies to RD-12.
4. **Which arms block** (was Q4): RD-15's arm, RD-5's held-flush and Drive arms, RD-8's
   stalled-read arm and RD-16's parked-actor arm block the release gate, run once per candidate,
   CI unchanged, once each arm's mutant has been run red once. Until a mutant has been run red,
   its arm stays optional and prints `OPTIONAL PROOF NOT RUN`. Applies to RD-3, RD-5, RD-6, RD-8,
   RD-15, RD-16; ADR-045 records J3 accordingly (its Q1).
5. **Where the arms run** (ledger row 32, after ruling 20): the whole release gate, these five
   arms included, runs inside VMs; the host runs only the driver. Each arm's place:
   - RD-15's arm (`a_post_answers_promptly_while_a_peer_posts_proof.rs`), RD-5's held-flush arm
     (`nodes_of_one_daemon_proof.rs`), RD-5's Drive arm
     (`a_codex_and_an_opencode_session_are_mirrored_and_driven_proof.rs`), RD-8's stalled-read arm
     (`nodes_of_one_daemon_proof.rs`) and RD-16's parked-actor arm
     (`a_newcomer_reads_the_whole_history_proof.rs`): in the macOS guest (ADR-045's host M), from
     the `test-knobs` build of the candidate the guest makes; they touch no disk image and no
     kernel setting.
   - RD-12's apparatus arm and RD-13's doctor run (`install_sh_proof.rs`, the short-cap doctor
     line): in the Linux VM (ADR-045's host B), as the proof user; RD-12's kernel arm: in the
     same VM as root in its own namespace (RD-12). These are not among the five; they are the
     Linux half of the in-tree suite the guest cannot run, and block or not as that suite does.
   - RD-14 (J3): the fleet, M and B together, as ADR-045 says.
   - RD-7's arms one to four (`a_daemon_reopens_its_rooms_proof.rs`, held commit, injected
     `fsync` fault, SIGKILL): in the macOS guest, with the status that journey has today; they
     need no full disk (r14).
6. **Full-disk staging** (ledger row 51; changed r8, r14): the in-tree full-disk journey is
   optional by ruling. No arm of this ADR needs a full disk any more: the old-waiter-across-recovery
   act (J5(h)) existed only for the withdrawn settlement rule and is withdrawn with it; RD-7's
   failed-commit arm injects an `fsync` fault with `test-knobs` and needs no image. None of the
   five blocking arms depends on a full disk.

## Links

- ADR-018 §10 (blocking, optional, mutants), ADR-034 FR-5 and WT-6, ADR-036 H-7, ADR-037 R4,
  ADR-038 FX-17, FX-27, FX-30, FX-31.
- ADR-040, ADR-041, ADR-042, ADR-045, ADR-046, ADR-047 (lanes above).
- Receipts: `/tmp/rca-RcaSlow/r1/runs/`, `/tmp/rca-RcaSlow/sample-grow-A.txt`, `/tmp/trial-sync/runs/`,
  `/private/tmp/vox-rca/{io,beast,mac}/`; plan A §0 item 7 (`inbound-admit wait_ms`, B3-reach).
