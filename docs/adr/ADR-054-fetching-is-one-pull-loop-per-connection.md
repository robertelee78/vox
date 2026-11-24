# ADR-054: Fetching Is One Pull Loop per Connection

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Accepted (2026-11-24) for v0.4.31 by the coordinating session, as the design fix of
  the fetching side of sync that the decider's words of 2026-11-24 call for (rulings 1 to 3). The
  coordinating session's reading of those words required the design to be checked by gpt-6.1-sol
  before it is built (`exec/deviations.md:189`). That check is `design/simple-sync/ruling.md`:
  "BUILD opus WITH CORRECTIONS", with eight corrections, C1 to C8, all carried here. The design
  carries one amendment by the coordinating session, made while building: the opening of a
  connection is the existing board put, not a new frame (PL-1). **Nothing of it has landed** when
  this record is written (design.md:4: "Nothing here is built"). Every requirement below is to be
  built; where this record says "is" of the mechanism, it states what the build is to do, not what
  main does. Implementation, acceptance and delivery are recorded on the source-bound issues,
  separately from decision status.
- **Date**: 2026-11-24
- **Deciders**: Robert E. Lee
- **Tags**: sync, fetching, serving, admission, KISS, release
- **Amends**: ADR-053, by reference: the fetching machinery its Order assumed is replaced by this
  ADR. ADR-053 records this in its amendment 4. The exact places are under "What this ADR
  supersedes in ADR-053".
- **Related**: ADR-018, ADR-052 (RG-1, RG-5, RG-6, RG-15), ADR-053 (MP-6, MP-7, MP-9, MP-10,
  MP-11, MP-12, MP-13, MP-18)
- **Source**: in the release's evidence archive `/opt/vox-evidence/v0431/`: the decider's words
  in `exec/deviations.md` (sections "Answers of the owner on 2026-11-24 (morning), in chat" and
  "The owner on 2026-11-24 (later the same morning)", lines 168-189);
  `design/simple-sync/design.md` (the final design, with its Amendment 1 at line 152);
  `design/simple-sync/ruling.md` (the independent ruling; it wins wherever the sources differ,
  except where design.md's Amendment 1 replaces the opening); `design/simple-sync/experiment.md`
  (the page experiment the ruling required first); `mp/sync-stack/what-the-room-needed.md` (the
  failures this design must make impossible); `mp/land/plan.md` (the map of the prototype);
  `exec/found-reds.md` (ledger 91, 93, 94). Code lines are in
  `/opt/vox-worktrees/land-1-peer-turns/crates/vox-core/src/node/` unless a path says otherwise
  (design.md:3); the ruling's own citations are in `/opt/vox-worktrees/land-1-peer-turns/crates/vox-core/src/`
  (ruling.md:16). Nothing was built or run for this ADR.

## What this ADR sets out to do, and the rulings it carries

**The goal.** In the busy room of ADR-052 RG-1, every member's messages arrive at every other
member, in all sixteen directions, with both newcomers and the restart, by one fetching mechanism
in place of the rules stacked on today's, with fewer states and less code than today
(design.md:142; `exec/deviations.md:189`).

**The decider's rulings this ADR carries** (2026-11-24; quoted words are his, from
`exec/deviations.md:172-176` and `:187`):

1. **The stack of sync fixes is not the fix.** "yeah -- we have made an ever more elaborate set of
   if then else conditional messes -- we took something that was a bad design, very brittle, and
   with our "fix" made it worse -- worse design, more brittle" … "instead of fixing the design".
   The coordinating session's reading (`exec/deviations.md:189`, "What follows (Main)"), not a
   further quotation: the stack is from then on a prototype, "evidence of what the room needs, not
   what lands"; what lands is "a design fix of the fetching side of sync: one mechanism in place of
   the rules, fewer states than today, code deleted rather than added, checked by gpt-6.1-sol and
   against prior art before it is built, and measured by the same act and the same journey."
2. **Against over-engineering.** "but dang -- we just need to actuallly land tasks better" and "we
   are prone to over engineered messes". The coordinating session's reading
   (`exec/deviations.md:183`): "when a fix needs more rules, more special cases or more readers to
   cope, stop and take the simpler rule, even where that undoes work; prefer deleting to adding".
3. **The scope of v0.4.31 is the busy room.** "we can do the busy room as v0.4.31, then be better
   about disk space for v0.4.32". Earlier the same morning: "still the same 4 open tasks 🙁", and,
   on the fixes that existed only as patches, "get that done".

**Earlier rulings that stand:** the release waits for the busy room (ADR-053 ruling 1); KISS is the
law (ADR-052 ruling 2, RG-0; ADR-053 ruling 2); every member of a room runs the same Vox version,
"for now, yes." (ADR-053 ruling 4), so a wire change needs no compatibility path; a feature is
proven on the real binary and the proof asserts what a person gets (ADR-018); the release gate is
unchanged (ADR-053 MP-18).

**What is built when this record is written.** Nothing of this design has landed (design.md:4).
The page experiment the ruling required before any product code was run on scratch copies and is
reported (`experiment.md`); it is evidence, not product code, and was never committed
(experiment.md:1, :8).

## Context: what the fetching side was

A node learned that another member had something new from that member's inventory, which offered
an author's head to it as a *hint*. Each hint was taken by one *flow* on one *port* (one peer
connection), and the flow walked that author: it re-derived what was missing under the hinted
head, asked one source for it, and ended, parked or routed itself elsewhere when that source could
not answer (`mp/land/plan.md:50-56`). Hints, flows, the routing between ports, refusal memories,
announcements, availability tokens and their re-arming were the fetching side
(design.md:93-100). Accepting a peer's request ran on the holder's node actor, which awaited the
room's lock (design.md:49-50). Body staging was one record per node and purpose
(`what-the-room-needed.md:45-49`). What a member owes itself, the missing intervals of ADR-053
MP-12, is separate and stays (C3).

## Context: the prototype, and why it does not land

From 2026-11-23 to the morning of 2026-11-24 the busy room was driven up by stacking changes on that
machinery. The stack grew to about twenty kept changes and reached 14 of 16 directions; three more
causes were found the same morning (`exec/deviations.md:189`). Mapped one line per change, the
kept stack is 28 lines (`mp/land/plan.md:44-47`):

- **11 structure**: they remove a shared thing or make peers independent (each peer its own turn,
  M0, memory reserved for what is used, answering apart from asking, the body slot claimed late and
  kept per author, and others).
- **3 serve**: a node serves or keeps what it verified (a reader keeps what it verified under a
  newer head; a head answer carries its proofs; a holder keeps a verified parent header).
- **14 rule**: a condition about when to ask, ask again, park, unpark, route, wait or re-arm.

The rule lines all work around one fact: a need (a header, a proof or a body of author A at
position s) has no single owner. It is re-derived by every flow walking A, under every new head,
routed per hint and ended or parked per hint; who can answer is inferred from inventories and
standing declines, with the author as the fallback (`mp/land/plan.md:50-56`). In the run that
reached 14 of 16, what was left (the newcomer and the paused creator, both ways) was "the same need
re-routed without news" (`mp/land/plan.md:57-58`).

It does not land because the decider ruled that the stack is not the fix (ruling 1): it is kept as
the evidence of what the room needs. From it only what is structural is kept: "each peer its own
turn; a holder serves what it verified; M0, which removes an entry per post"
(`exec/deviations.md:189`).

## Context: what the room needed

The failures below were counted in the busy room (8 members, the creator `y1` stopped and continued
every 1.5 s, the newcomer `n-new`); each is something this design is to make impossible, or names
as a limit no fetching design removes (`mp/sync-stack/what-the-room-needed.md`):

- **One request per port, and a holder that accepts a request behind its own node's work.**
  `n-new`'s port toward `y1` had no turn for 12,000 to 33,000 log lines at a time, each gap one
  inventory request in flight; three died on the 20 s frame deadline. By the builder's reading,
  not timed, `y1` spent that time before answering, accepting the stream on its node actor, which
  awaits the room's lock (:12-18). → PL-4, PL-7.
- **Heads arrive only as hints taken per port.** `n-new` took no head of `y1` across 77,000 log
  lines while `y1` went from 1660 to 1741 (:19-20). → PL-2.
- **The same need derived and routed again and again.** `Header(1657)` of `y1` was routed to `y1`
  1,566 times, 1,562 at the same head, and asked on the wire 4 times; same-need routings ran to
  4,593 on one member in one run; closures were re-derived per head (:25-38). → PL-3, PL-4.
- **A source is asked what it cannot answer.** A proof need counted as answerable by head length
  alone; one member declined 31,027 times in one run (:40-43). → PL-2.
- **Node-wide and daemon-wide shared slots.** 2,240 body-slot waits in one act; 7,046 Busy answers
  from a daemon-wide grant held by a silent asker; 239 to 783 serving-bound refusals; a room's own
  saving held 23,445 times; 324 and 418 exchanges refused because one history session per room and
  pair collided (:45-58). → PL-6, PL-7, PL-11.
- **The paused author is the only source** of what it wrote while the others were behind: positions
  nobody else walked, a control proof nobody else held, a fresh one-time prekey (:4-23). → PL-9.
- **Ledger 91**: a member admitted while another member was away can be refused by it as a stranger
  for good in one sequence, because the newcomer's only round toward it did not offer the
  newcomer's board record (`exec/found-reds.md:195`). → PL-1.

## Terms

- **Have**: what a node tells one peer it holds, per author (PL-2).
- **Proof-servable extent**: positions of an author whose header and witness material a node holds
  and can prove (PL-2). **Body-available extent**: positions whose body it can serve now; it can
  shrink (PL-2).
- **The kept evidence** (PL-2, PL-6), in plain words: a *signed head* is an author's signature over
  the root of its whole log at one size; a *PendingHeader* is a signed entry header this node has
  verified and kept while the entry itself is not yet admitted; an *inclusion receipt* is kept proof
  that one entry is in an author's log under a signed head; a *prefix receipt* is one of today's row
  kinds, named here as such and not defined further; *witness ranges* are the pieces of the
  author's hash tree those proofs are made of; *control coverage* is kept proof that a stretch of the
  log holds no control entry other than those listed. These are today's row kinds
  (ruling.md:21; experiment.md:36). Continuity from a reader's earlier anchor to a later head is
  carried in an answer by a ConsistencyProof from that anchor's size (experiment.md:21, :39).
- **Owed**: what a node still lacks and has a standing reason to obtain (PL-3).
- **Frontier**: the one admission frontier per author that the node owns; it runs today's validator
  over held material and says what it still needs (PL-3). The validator does no network work: given
  what is held, it either completes or names the missing piece, a context, an exact parent or
  control requirement (its *Missing* and *Need* results), and a *cursor* records how far its walk
  of that author has come (ruling.md:39-42). An *exact-root* need is a piece needed under one
  particular signed head of the author; only proof under that head satisfies it.
- **Pull loop**: the one loop per connection that asks that connection's peer for what is owed
  (PL-4).
- **Bundle** (the *proof bundle*): one answer, made of the existing proof forms, at most 1 MiB
  (PL-5). Not the board's *bundle record* of PL-1, which is a member's own record on the board.
- **Assembly**: the bytes of a connection's answers held in memory, private to that connection,
  before the frontier admits them (PL-6).
- **Local admission and wire credit** (PL-6): *local work and byte admission* is this node's
  permission to spend its own memory and processing on a piece of work; *wire credit* is how many
  bytes a peer may send on one connection. Bytes received under credit are not thereby accepted.
- **Room snapshot**: what a room publishes after every committed history write, for serving
  (PL-7).
- **Sole source**: the only node that holds something another node needs (PL-9).
- **First slice**: the one change ruling §4 permits (ruling.md:74-79; design.md:127-144).
- **P and H** (ADR-053): *P*, MP-7's prefix serving, lets a holder answer for any earlier state of
  an author that it can rebuild from what it has verified; *H*, MP-8a's head choice, is which signed
  head of an author a node anchors new work on.

## The decision

**The rule.** Each connection runs one loop that asks its peer, one request at a time, for what this
node owes and that peer has said it holds. Answers are the existing proofs, checked by the existing
verifiers and admitted by the existing validator through one frontier per author that the node owns.
A peer serves on its own task from what the room has committed, never waiting for its own node's
work. Nothing runs on a timer, and nothing remembers a refusal: a peer's own statement of what it
holds is the only thing the loop believes about it.

Each requirement gives the rule, its *Source* (the line it comes from) and, where the sources give
one, *Why*. Proof is under "Proof"; the sources name acts for the slice as a whole, not one per
requirement.

### Opening a connection

- **PL-1. A node introduces itself by the existing board put before its first Sync stream.** The
  *board* is the rendezvous store on which a member's own signed records for a room are put (the
  signed admission record the board holds for it, design.md:8); a *Rendezvous put* writes them
  there. The first time a node uses a connection for a room, it MUST make the Rendezvous put of its
  own board records for that room (its bundle record, then its address record; not the proof
  bundle of PL-5), which an unknown peer may already
  make (`nat/service.rs` about :1582-1605, `nat/store.rs:898`), and MUST await that put before
  opening the first Sync stream. It MUST make it unconditionally: the `needs_board` condition is
  removed. It MUST make it again after a refusal as a stranger. The receiving side, deciding
  whether to accept a Sync stream from this peer (its *Sync gate*), classes the peer as a member as
  soon as its record is on the board (`network.rs:1150`, `:1210`) and runs its roster admission on
  that same stream. No new frame, no gate change, no timer: the stream-kind gate that resets an
  unknown peer's Sync stream before any frame is read (`net.rs:213-273`, `network.rs:1079-1119`)
  is not widened.
  - *Source*: design.md:152-153 (Amendment 1), which supersedes design.md:7-12 (a *Hello* frame on
    the Sync stream, an answer "not yet a member" paced as Busy, and "only after the Hello is
    answered does each side send its first Have"). The Hello frame is not built. design.md:119 and
    :135 still say "Hello"; under the amendment that is the board put.
  - *Why*: ledger 91 "failed only because the board offer was conditional (`needs_board`)"
    (design.md:153; `exec/found-reds.md:195`).

### What a node says

- **PL-2. A Have tells one peer, per author, what this node can serve that peer.** For each author,
  scoped to what the asking peer may be served, a Have MUST list:
  1. the signed heads the node holds, including unresolved unequal observations (ADR-053 MP-9), as
     a field separate from the extents;
  2. paged *proof-servable extents*: positions whose header and witness material the node holds,
     read from its validated positions, PendingHeader rows and receipts;
  3. *body-available extents*, kept separate from the proof-servable ones and able to shrink.
  A Have MUST be derived from those rows, never from a head size: a holder's committed head can
  overstate what it can prove. A body stretch without enough witness material MUST NOT be
  advertised as proof-servable. A Have is sent on connect and again only when one of those
  changes, and carries only the authors that changed.
  - *Source*: design.md:14-19; C2 (design.md:64; ruling.md:66); ruling.md:76 (witness material);
    experiment.md:34-35 and :47 (a non-author holder's head of 1732 overstated what it could
    prove; its held extent was 1528..1660).
  - *Why*: heads reached the newcomer only as hints taken per port, and holders were asked under a
    head length they could not prove (`what-the-room-needed.md:19-20,40-43`).

### What a node owes

- **PL-3. What a node owes comes from its own records, through one frontier per author that the
  node owns.** The owed set MUST NOT be derived from what peers advertise. It comes from records
  that exist today:
  1. the floor and missing-interval debt (ADR-053 MP-12, `AuthorState.live` with #1385's
     intervals);
  2. archive intents;
  3. key debts;
  4. the needs of one node-owned admission frontier per author.
  The frontier MUST reuse the existing validator and its Missing and Need results and cursors
  (`channel/governance/sparse.rs:456-605`, `history_stream/admission.rs:768-1007`). It is woken by
  verified local changes, not by a new head, and is not restarted because a new Have names a
  different head. The floor, the debt and every exact-root obligation keep their stored meanings,
  including through a restart. An old hole stays owed while heads keep growing. Expired debt is
  discharged by this node's own retention policy, never by a holder's report that a body is expired
  or not held.
  - *Source*: design.md:21-27; C3 (design.md:65; ruling.md:67); ruling.md:42 (not restarted by a
    new Have), :51 (old holes, restart), :54 (retention).
  - *Why*: one need had no owner; it was re-derived and re-routed per flow, per hint and per head
    (`what-the-room-needed.md:25-38`; `mp/land/plan.md:50-52`).

### What a node asks

- **PL-4. Each connection runs one loop with one request in flight.**
  1. The loop asks for what is owed, inside its peer's last Have, minus what the node has already
     checked.
  2. The frontier's exact-root needs come first. After them the loop alternates between the newest
     page of debt and the oldest, so an old hole is reached while heads keep growing.
  3. A request names the exact head and one of three things: an entry page, a control interval, or
     a continuation `(position, offset)`.
  4. The loop never waits on another connection, and nothing in it runs on a timer.
  5. The loop advances checked local knowledge or an exact byte or proof continuation; it acquires
     no retry, park, source-routing or rearm machinery (PL-13).
  - *Source*: design.md:29-33; ruling.md:12, :71.
  - *Why*: one exchange per port held a member's whole view of a slow peer, and a need went to
    exactly one source when coverage named no holder (`what-the-room-needed.md:8-18`).

### What an answer is

- **PL-5. An answer is a bundle of the existing proof forms, at most 1 MiB.** It MUST contain:
  1. the signed head;
  2. a ConsistencyProof from the anchor size the reader named;
  3. for each entry: the header, an InclusionProof, and the body bytes or `BodyNotHeld`;
  4. ControlRangeProofs of at most 8 headers and 1,024 tokens each, including empty proofs for
     intervals that contain no control;
  5. each distinct context once;
  6. an explicit next `(position, offset)` whenever it stops early.
  The continuation MUST also make progress when the proof and context set itself does not fit in
  one response, not only when a body does, and a controls-only answer records its authenticated
  no-control coverage so that it is not asked again (ruling.md:46, :65). How a proof continuation is
  encoded beyond `(position, offset)` is not decided.
  There is no new durable stretch format and no edge-equality verifier: the "ends" verifier of the
  first design is withdrawn. The canonical multiproof of the first design is not built. In the
  experiment it sent 7,604 B per entry against the bundle's 8,429 B, "so the bundle costs 11 %
  more" (experiment.md:43). By the ruling it is introduced only if the experiment shows the bundle
  cannot meet the product need (ruling.md:22); the experiment found that an 11 % cost does not
  justify introducing the multiproof: "at 11% it is not" (experiment.md:43).
  - *Source*: design.md:35-41; C1 (design.md:63; ruling.md:65); experiment.md:18-26, :43;
    ruling.md:22, :46.
  - *Why*: measured on copies of the j-c21 stores, this bundle verified complete from the author and
    from a holder that is not the author, from empty serving caches and again after a restart; a
    position's body continued at strictly growing offsets, so the same request is never repeated
    (experiment.md:28-40, at a scaled 1 KiB limit for the body case).

### What the reader keeps

- **PL-6. The reader keeps exactly what admission keeps today; a body waits in the connection's
  private assembly.** The reader MUST verify with the existing verifiers (`log/history.rs:1355-2193`)
  and keep exactly what admission keeps today (`history_stream/admission.rs:455-619`): contexts,
  witness ranges, inclusion and prefix receipts, control coverage and PendingHeaders. A body stays
  in the connection's private assembly until the frontier admits it through the existing path into
  LogDb. A body that cannot be admitted yet is dropped and stays owed; there is no store row for an
  unadmitted body. The assembly is bounded to one 1 MiB answer plus one 16 MiB body. Local work
  and byte admission (`history_budget.rs`) are taken only for local work that is ready to run, never
  while waiting for a peer. Wire credit is never mistaken for acceptance. The assembly bound is not
  the node's whole memory peak: today's serving path reserves about five whole-record and sealing
  copies plus 4 MiB to read a body of up to 16 MiB, so "1 MiB per connection" does not bound it, and
  finite, ready-only local byte and work admission is kept (ruling.md:61; PL-13).
  - *Source*: design.md:43-46; C5 (design.md:67; ruling.md:69); ruling.md:61; experiment.md:36,
    :46.
  - *Why*: one staging record per node and purpose made one author's body wait on another's and on
    other ports (`what-the-room-needed.md:45-49`). In the experiment the kept rows reach disk with
    the next flushed commit; a crash before it costs a fetch again, not a wrong answer
    (experiment.md:36).

### Serving, without the actor

- **PL-7. A request is accepted and answered on the connection's own server task, from the room's
  published snapshot.**
  1. A request MUST be accepted on that connection's own server task, not in `run_sync_session` on
     the node actor, which awaits the room's lock four times today (`actor.rs:19033`; locks at
     about :19129-19220).
  2. The task MUST authorize from, and read through, a snapshot the room publishes after every
     committed history write (`channel/sparse_history.rs:896`), instead of taking the room's lock
     for each read (`history_stream/source.rs:525-528`). The snapshot holds the room's key, its
     committed directory roots, the epoch, the member set, the removal generation and the
     generation of recipient cuts. Reads run in a store read transaction.
  3. Accepting and answering a request therefore never waits for the actor's turn, the room's lock
     or this node's own saving.
  4. Serving gives only metadata evidence, or bodies already available through the existing safe
     serving boundary (`history_stream/server.rs:959-993`, recipient eligibility;
     `channel/sparse_history.rs:1199-1219`). There is no new durable store for unadmitted bodies.
  5. The existing confinement of a returning or non-member peer to its own recovery evidence, the
     check of current room, epoch, member and removal state, the re-authorization of each physical
     send, and the cancellation and egress fences are kept on the new path.
  6. If an extent shrank after it was advertised (for example, a body expired), the answer carries
     the holder's corrected extent for that author. The reader updates its copy of that peer's Have
     and never asks the same thing again under the same Have.
  - *Source*: design.md:48-52; design.md:132 (serving boundary); ruling.md:36 (item 5);
    ruling.md:77. design.md:135: the serving task off the actor is part of the first slice
    "because the busy room needs both".
  - *Why*: a holder's acceptance of a request queued behind its own node's work; Busy answers from a
    daemon-wide grant; serving held by the room's own saving (`what-the-room-needed.md:13-18,50,55-56`).

### When a peer is slow, gone or wrong

- **PL-8. A peer's trouble stays on its own connection.**
  - Slow: only that connection's loop waits.
  - Gone: the end of the connection drops that connection's state; what was owed stays owed.
  - Wrong: a reply that fails verification closes only that connection. It is never treated as a
    fork verdict (ADR-053 MP-9: a bad relay proof is pending, not a fork).
  - *Source*: design.md:54-57; ruling.md:33.
  - *Why*: `what-the-room-needed.md:12-18`.

### A sole source

- **PL-9. What only one stopped node holds is waited for, named, and blocks nothing else.** When only
  the paused creator holds something (positions nobody else has walked, a control proof nobody else
  holds, a fresh one-time prekey), the reader waits for it, and nothing else does. While it waits,
  the newcomer shows every other member's messages, every other author's frontier keeps going, and
  the missing thing is named as pending. It MUST NOT be made "fixed" by a deadline.
  - *Source*: design.md:59; ruling.md:83.
  - *What no fetching design can do* (design.md:60): it cannot make sole-source evidence arrive while
    its only holder is stopped, and it cannot replace a one-time prekey that has been used up
    (`what-the-room-needed.md:21-23`).

### What checking keeps

- **PL-10. Fetching changes no check.** The validator, every source, control and effect phase, and
  every branch, recipient, private and physical-send check MUST stay as they are. A page whose root
  checked out is transferable evidence, not a canonical source, a membership verdict, a readable
  message or an applied control, and grants no authority. ADR-053 MP-6 and MP-11 are not relaxed
  by fetching; unresolved unequal observations are kept (MP-9); a frozen author's material stays
  evidence-only where MP-9a permits it; private Session floors and continuity stay separate
  predicates. The ADR-053 boundary guards stay required.
  - *Source*: C4 (design.md:66; ruling.md:68); ruling.md:10, :32-35; design.md:144;
    ruling.md:79.

### What is deleted, and what stays

- **PL-11. The first slice deletes the fetching machinery of Public history.** In the same change
  that moves Public fetching to Have and pull loops, the following MUST be removed:
  1. `HintInbox` (`history_stream/hints.rs`, all 610 lines: pending hints, transient refusals, lane
     generations, `role_seen`) and its offer, take, finish and refusal plumbing;
  2. for Public history: route origin and reroute, the required queue's Public borrowing, Public
     ready and deferred retention and its displacement; the routed, return, parked and deferred
     ownership. These are names in today's code (design.md:96, :133). In the sources' words, the
     required queue (RequiredOwner) with reroute, route origin and rehome "Lends a need to another
     flow; sends a need to its author and back" (opus.md:42); the Public borrowing named above is
     Public's use of that queue. `ready` and `deferred` are today's lists that decide which request
     runs in which slot (opus.md:39); displacement among them is named (sol.md:87), not described.
     All of it goes;
  3. the announcement prefix with `own_seq` and `announced_seq`;
  4. availability tokens and rearm;
  5. the per-head control closure of the live walk (`push_control_closure`) and `LiveResume`; the
     Public live-walk operations `LiveWindow`, `LiveAdvance`, `LiveRetry` and `Tail`;
  6. the 30 s periodic raise and the 20 s frame deadline for Public;
  7. the history session collision;
  8. the node-wide set of pages being asked, every negative cache, every rearm and every fallback to
     the author;
  9. in `history_stream/source.rs`, inventory paging, the role and inventory offers, and the
     decline memory used only by Public;
  10. the Public admission in `run_sync_session`, which moves to the server task (PL-7).
  The design counts this as about 14 of the 30 kinds of state counted in the first design.
  - *Source*: design.md:93-100 (kinds), :103-116 (by file), :131-133; C7 (design.md:69;
    ruling.md:71); ruling.md:78.
- **PL-12. Untouched in the first slice.** The following MUST stay as they are; the first slice
  does not touch them, and their shared helpers are kept even where Public stops using them:
  1. *archive paging*: explicit saved user intent with its original root and bounds, pause,
     resume, cancel and status, and its demand slots (`history_demand.rs`,
     `actor/history_demand.rs`);
  2. *own recovery* (`channel/own_history.rs`): a durable write, fork and rollback fence;
  3. *key bodies*: key debts, `KeyBody` and `KeyAvailability`, with their ports' fields;
  4. *private and legacy Sessions*;
  5. *the meanings of status fields*: a new transport receipt does not raise held, verified or
     rendered counters interchangeably;
  6. the floor and debt (ADR-053 MP-12); publication and retirement cleanup with `ReceivedFlow`
     (the settlement of cleanup owed for a publication this node really owns, ruling.md:62); the
     daemon's local work and byte admission; the reach backoff.
  They stay until their producers have migrated; when and how each migrates is not decided.
  - *Source*: C6 (design.md:68; ruling.md:70); design.md:82-91, :134; ruling.md:56-62, :78.

### Rules of the build

- **PL-13. The build adds no rule of the kind it removes, and deletes more than it adds.** The
  change MUST NOT add a timer, a retry count or retry policy, a negative cache, a per-source refusal
  flag, a rearm, a fallback to the author, a remote-waiting shared admission, a restart of exact
  work driven by a new head, or a new scheduling rule or special case for a slow member. A stale
  extent is corrected by the holder (PL-7), not remembered by the reader. **The change MUST delete
  more fetching code than it adds, or the ruling withdraws it.** The ruling's approval is also
  withdrawn if existing-format evidence cannot support a correctly advertised finite response after
  a restart without weakening source ownership; if recipient cuts or fork or private boundaries need
  bypassing; if the first slice still needs a new scheduling rule to reach 16 of 16; if it loses
  explicit archive, recovery, key or status behaviour; or if it cannot bound total connection
  assembly plus local scratch.
  - *Source*: ruling.md:82-83 (§5); ruling.md:12, :47, :71; design.md:33, :69, :125, :153 ("No
    new frame, no gate change, no timer"); `exec/deviations.md:183` ("more rules, more special
    cases").

## Counts, by reading (the diff decides)

The first design's five-state and 20,000-line claims are withdrawn (C8; design.md:70; ruling.md:72).
Recounted with the obligations that remain (design.md:74-100):

- **New, 3 kinds**, all per connection: the peer's last Have; one request and its continuation; a
  private, bounded assembly.
- **Adapted, 1 kind**: the frontier for each author, built from today's admission cursors and Need
  results (`history_stream/admission.rs`, `history_stream/client.rs:1987-2422`), owned by the node
  instead of by a flow.
- **Added for serving, 1 kind**: the room's published snapshot.
- **Removed**: about 14 of the 30 kinds (PL-11).

Lines, read from the source and not a diff (design.md:102-125): the first slice removes about 2,000
to 2,600 lines and adds about 1,500 to 1,800, a net deletion of roughly 300 to 1,000 lines, "small
and uncertain". PL-13 decides on the real diff.

## Proof

Proof form as ADR-018 and ADR-053: acts and journeys on the real `vox` binary, asserting what a
person gets.

1. **Prerequisite, the page experiment**: done (`experiment.md`), except a real body above 1 MiB,
   which still needs an act. No real body above 1 MiB exists, and none can be made by posting text
   (capped at 64 KiB, `content.rs:40`); the continuation was shown at a scaled limit
   (design.md:128, :150; experiment.md:5, :38).
2. **The acts**, to be measured by the coordinating session on the first slice's binary; none has
   been run on it when this record is written:
   - `a_newcomer_reads_authors_who_keep_posting_past_their_controls`, with its early-pause arm;
   - `a_slow_member_delays_only_itself`;
   - `a_follower_held_still_through_a_burst_holds_every_post`;
   - the staging (2) act of `found-reds/backoff-news`,
     `a_newcomer_reads_the_returned_author_that_refused_it` (ledger 91; PL-1).
3. **Then the unchanged busy-room journey**: all 16 directions, both newcomers, and the restart.
4. **The ADR-053 boundary guards stay required**; the journey's verdict does not replace them.
5. **The room snapshot** (PL-7) is new code on the serving path; its consistency with the store's
   committed roots MUST be shown by an act: a request made during a publication still answers.
6. **Measured, not bounded: duplicates.** P connected holders can return up to P copies of one
   page; nothing coordinates between connections. The cost is measured, not bounded, and no bound
   is claimed.
7. **Net deletion** (PL-13) is read from the change's diff.

- *Source*: design.md:127-148; ruling.md:75-79; ruling.md:49 (duplicates).
- *Not decided by the sources*: a named mutant for each act; how the duplicate cost is measured and
  what figure would be too much.

## Risks

From design.md:145-150, with what the sources leave open:

- **Duplicate replies** (Proof, item 6).
- **A newcomer's first minute.** It still closes the controls that join requires, and checks the
  real signatures, per sender. It never sets up a barrier across the whole room. Full legacy
  ancestry still costs real signature checks (ruling.md:50).
- **The room snapshot is new code** on the serving path (Proof, item 5).
- **Net deletion in the first slice is not proven** (Counts; PL-13).
- **A real body of 1 to 16 MiB** (KeyPackage, Governance) has not been exercised (Proof, item 1).
- **A sole source stopped** is waited for (PL-9); no fetching design removes that wait.
- **Ledger 93 and 94** are recorded in the ledger as cases for this redesign
  (`exec/found-reds.md:196-197`: a member does not catch up on a burst while its own recovery save
  is pending; a single post arrived 24.9 s late in 1 run of 17 on main, its request parked waiting
  for the node's single live body slot). The design sources do not say how the design meets
  either: not decided.
- **A join answered only when the answering member's governance is idle**
  (`what-the-room-needed.md:59-60`) is not addressed by the design: not decided.

## What this ADR supersedes in ADR-053

By reference; ADR-053's amendment 4 marks each place, and its meaning is otherwise unchanged. Line
numbers are ADR-053's on main `4e16a0da7`, before amendment 4.

- **MP-13, the disposition of the parked candidate (:687-694), carried by Order step 4
  (:899-902).** Its rules about when to ask, ask again, park, route or re-arm do not land in any form;
  the machinery they schedule (the hint inbox, routed, parked and deferred flows) is deleted by
  PL-11. Of the rules that paragraph allowed to land: each peer its own turn is kept from the
  prototype as structural (`exec/deviations.md:189`); rules 3.4 (the per-room save gate) and 3.5
  (the lost-wake fix) are not named by this record's sources: not decided.
- **The coordinating session's approval of "ask who can answer"** (`exec/deviations.md:156`: an
  asker asks a holder only for a state the holder said it reached, and a decline stands until that
  holder says something new) is not an ADR-053 requirement; it is superseded by PL-2 and PL-7's
  corrected extent, with no decline kept (C7).
- **MP-12's "that holder is not asked again on that connection" (:652-653)** is met by the
  holder's corrected extent (PL-7, item 6), not by a refusal flag the reader keeps (C7;
  design.md:72). The rest of MP-12 stands (C3).
- **MP-9's *Why* (:490-496)**, which names the hint queue (`history_stream/hints.rs:367-392`) and
  the inventory that pages every author's committed head: under this ADR, signed heads and
  unresolved unequal observations are to travel in the Have (PL-2), and the inventory paging is to
  be deleted (PL-11). MP-9's rule stands. Whether its `forks` list (*Transport*, :481-489) rides on
  this ADR's Have is not decided.
- **MP-8a's head choice H (:448)** is not addressed by this record's sources: not decided.
- **ADR-053's Order** assumed the fetching machinery of today, with the parked candidate's
  disposition in step 4; that machinery is replaced by this ADR. MP-7's prefix serving P stays: the
  experiment served through it unchanged (experiment.md:26).

## Not decided

Where the sources are silent, this record says so: each act's mutant; how duplicates are measured
and what is too much (Proof); when the producers kept in PL-12 migrate; ledger 93 and 94, and the
join answered only when governance is idle (Risks); rules 3.4 and 3.5 of the parked candidate,
MP-9's `forks` list on the Have, and MP-8a's H (supersedes); whether a node answers a peer during
its roster admission other than as today, since design.md:10 went with the superseded Hello.

## Links

- ADR-018, ADR-052, ADR-053.
- In `/opt/vox-evidence/v0431/`: `exec/deviations.md` (2026-11-24); `design/simple-sync/design.md`,
  `ruling.md`, `experiment.md`, `opus.md` (the first design, as corrected), `sol.md`;
  `mp/sync-stack/what-the-room-needed.md`; `mp/land/plan.md`; `exec/found-reds.md` (ledger 91, 93,
  94); `found-reds/backoff-news/report.md`.
