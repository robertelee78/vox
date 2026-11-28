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
  *(Amended 2026-11-25, amendment 3: the decider's rulings 4 to 6 of the afternoon and evening of
  2026-11-24; design.md's Amendments 2, 3 and 4; the second ruling on the in-flight preference,
  `design/simple-sync/ruling-in-flight.md`; the adoption ruling, `design/adopt/ruling.md`, with the
  per-head audit, `design/adopt/per-head-audit.md`; the display-order ruling,
  `design/adopt/ruling-order.md`, which also amends PRD-001 R13, ADR-023 RL-1.2 and ADR-053 MP-5,
  with its second ruling, `design/adopt/ruling-order-2.md`; the admission-order ruling,
  `design/adopt/ruling-admission-order.md`, with its Amendment 1 (after measurement); the rulings
  made during review, on public body extents (`design/adopt/ruling-body-extents.md`,
  which also amends ADR-053 MP-12's promise that a holder is not asked again on that connection)
  and on what a peer is told of private records (`design/adopt/ruling-private-tip.md`); the design
  rules that the reviews of the built tree enforce; and the rules for a store written by v0.4.30.
  The new rules are PL-14 to PL-40, in the section "Amendment 3". Each amended place is marked; the
  text it amends stays as it was, beside the mark. An amendment 2 was drafted
  (`design/adr-054/amendment-2/`) and is not on main; what it carried is carried here. The loop and
  the adoption are built in a scratch tree, frozen at scratch commit `0bfd8592c`, measured there
  and accepted by each area's reviewer; a full sweep of the release proofs on that build then
  found two faults, fixed and accepted as PL-39 and PL-40 (scratch `8f28b38b8`, measured again
  there); none of it is merged.)*
  *(Amended 2026-11-28, amendment 4, merged with the fixes of the sixth proof sweep in pull
  request #1424, merge commit `516c08746` on main: PL-41, after a room's store recovery succeeds
  the node closes and redials its connections to that room's peers; PL-42, a refill that finds
  its key body already retired settles its root, and the body's debt is retired where its expiry
  is established (`exec/found-reds.md` entries 156 and 160); in the section "Amendment 4". Each
  amended place is marked.)*
- **Date**: 2026-11-24
- **Deciders**: Robert E. Lee
- **Tags**: sync, fetching, serving, admission, KISS, release
- **Amends**: ADR-053, by reference: the fetching machinery its Order assumed is replaced by this
  ADR. ADR-053 records this in its amendment 4. The exact places are under "What this ADR
  supersedes in ADR-053".
  *(Amended 2026-11-25, amendment 3:)* Also PRD-001 R13, ADR-023 RL-1.2 and ADR-053 MP-5, by the
  display-order ruling (PL-26), and ADR-053 MP-12's promise that a holder is not asked again on
  that connection, by the body-extents ruling (PL-20 item 2); each carries a note pointing here.
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
  *(Amended 2026-11-25, amendment 3:)* Also: the decider's words in `exec/deviations.md`, sections
  "The owner on 2026-11-24 (afternoon)", "The owner on 2026-11-24 (evening): everything adopts the
  fixed design" and "The owner on 2026-11-24 (evening), on tests", lines 199-224; design.md's
  Amendments 2 to 4 (lines 155-181); `design/simple-sync/ruling-in-flight.md`; in `design/adopt/`,
  `ruling.md`, `per-head-audit.md`, `ruling-order.md`, `ruling-order-2.md`,
  `ruling-admission-order.md`, `ruling-body-extents.md` and `ruling-private-tip.md`, with
  `restore-experiment/report.md`; the builders' records of the built tree in
  `simple-sync/pull/on-main/`, `simple-sync/review/fix-*.md` and `release/gate-sweep/fix-*.md`; the
  reviews of that tree in `simple-sync/review/` (their state in `simple-sync/review/STATE.md`); the
  upgrade measurement, `simple-sync/upgrade/report.md` and `why-upgrade.md`; and
  `exec/found-reds.md` (ledger 100 to 102).

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
4. **A reader must not work through other members' history link by link** (2026-11-24, afternoon;
   `exec/deviations.md:199-207`). Shown the finding that a newcomer to the eight-member room showed
   nobody because it "has to work through other members' history link by link, because every post
   points at everyone else's latest entry", each link taking 35 to 52 seconds, he wrote: "dogshit
   design", "must fix", "KISS", "without losing security". The coordinating session's reading
   (`exec/deviations.md:205-207`), not a further quotation: M0 (the rule that an ordinary post does
   not wait to fetch other members' hinted entries) lands in v0.4.31 with the pull loop, "not
   optional and not later", and the membership history must fold locally while the check of who is
   a member stays whole (PL-14, PL-17). *(Added 2026-11-25, amendment 3.)*
5. **Everything that fetches history adopts the fixed design** (2026-11-24, evening;
   `exec/deviations.md:210-218`). Told that the redesign added more code than it deleted "because
   three older paths still use the old machinery", he asked "why". Told that the design had left
   own-history recovery, key material and private Sessions on the old machinery on the independent
   reviewer's advice, and offered the choice between landing the busy room first and landing
   everything as one piece, he wrote: "like we keep patching a fundamentally fucked design" /
   "instead of fixing the design and having everything adopt it". The coordinating session's
   reading (`exec/deviations.md:216-217`): everything that fetches history adopts the pull loop in
   v0.4.31 and the old asking machinery is deleted, not kept beside it; and the fault found five
   times that day, a fact about an author's entries kept or looked up under one head of that author,
   is fixed as a rule (PL-19, PL-24). *(Added 2026-11-25, amendment 3.)*
6. **A test measures what a person gets** (2026-11-24, evening; `exec/deviations.md:220-224`).
   Told that re-pointing the existing tests at the redesign was being cut back, he wrote: "I fucking
   hate tests anyway -- anything that isn't measuring how a user experiences the app is a waste".
   The coordinating session's reading (`exec/deviations.md:224`): ADR-018 applies without exception
   to the redesign's test work; an act stays only if its verdict is what a person sees (Proof).
   *(Added 2026-11-25, amendment 3.)*

**Earlier rulings that stand:** the release waits for the busy room (ADR-053 ruling 1); KISS is the
law (ADR-052 ruling 2, RG-0; ADR-053 ruling 2); every member of a room runs the same Vox version,
"for now, yes." (ADR-053 ruling 4), so a wire change needs no compatibility path; a feature is
proven on the real binary and the proof asserts what a person gets (ADR-018); the release gate is
unchanged (ADR-053 MP-18).

**What is built when this record is written.** Nothing of this design has landed (design.md:4).
The page experiment the ruling required before any product code was run on scratch copies and is
reported (`experiment.md`); it is evidence, not product code, and was never committed
(experiment.md:1, :8).

*(Amended 2026-11-25, amendment 3:)* The loop and the adoption have since been built in a scratch
tree and measured there (Amendment 3 (g)). Five reviewers, one per area, each first answered
"REJECT be14a9bb7"; after fix-only rounds each accepted its area, and every area is accepted at
scratch commit `18b409efd` (`simple-sync/review/STATE.md:35-39`). The reviews read code only; none
ran anything (`STATE.md:31`). Nothing of it is merged.

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
*(Amended 2026-11-25, amendment 3:)* M0 is to be built with the loop, as its own change beside it
(PL-14).

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
- *(Added 2026-11-25, amendment 3.)* **Accepted chain**: an author's committed heads, each proven to
  extend the one before; a fact verified under one holds under every later one (PL-19).
  **Witness**: what a head is for a fact located by position: proof that the position is on the
  accepted chain, not the fact's identity (PL-19). **Promotion**: asking a peer for the proof that
  its newer head of an author extends this node's committed head (PL-16). **Ready set**: the
  entries of a room whose admission can run now (PL-17). **Mark**: what one live request of this
  node covers, used only as a planning preference (PL-21). **Display key**: what places a row in
  what a person is shown (PL-26). **Private tip**: a donor's `(incarnation, through)` for its
  private Sessions; an observation, not a permission (PL-20).

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
  - *(Amended 2026-11-25, amendment 3:)* What a Have tells, and to whom, is now PL-20 and PL-28:
    only what the peer lacks; body extents in bounded pages that cover every held body, told to
    every peer; the own-release section only to its author; the private section only after a
    record that peer may be served was found; and what a peer says it holds is kept within one
    bound per connection. *(Amended 2026-11-27 by ADR-055 FO-7: there is no own-release section.)*

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
  - *(Amended 2026-11-25, amendment 3:)* Item 2 is now saved history requests, each its own debt
    (PL-27). The frontier's admission runs as one task per room, fed by one ready set (PL-17). What
    is owed is located by author and position on the accepted chain, never by head (PL-19), and a
    need is exactly what the validator asked for (PL-16).

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
  - *(Amended 2026-11-25, amendment 3:)* Item 2: needs, a need for a member's head among them, are
    asked before promotions and debt, and newest and oldest debt alternate as before (PL-16);
    within each priority class, the in-flight preference of PL-21 applies. Public planning reads no
    store (PL-15). Item 5 is amended by the adoption ruling's correction 3
    (`design/adopt/ruling.md:11`): after a refusal the connection's outbound exchanges stop until
    the peer's news (PL-23); no retry, source-routing or rearm machinery is added.

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
  - *(Amended 2026-11-25, amendment 3:)* An answer page also starts with the receipt of position
    lo-1, and an answer under a newer head carries that head's terminal receipt (PL-18). How a
    proof continuation is encoded is decided by PL-18: a count of contexts already received, kept
    across the leading proofs and receipts and one unfinished proof stage, and ended by the first
    completed entry, body cut or control proof.

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
  - *(Amended 2026-11-25, amendment 3:)* The sentence "A body that cannot be admitted yet is dropped
    and stays owed" is narrowed by PL-17: an entry that waits on an earlier position is kept, with
    its body, within the bound, and handed on at that position's admission. Waiting copies count
    against the same bound, with a bound across connections (PL-17). "Never while waiting for a
    peer" now binds the asking loop's job and the serving side too (PL-22).

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
  - *(Amended 2026-11-25, amendment 3:)* Serving is bounded per connection and holds shared work
    admission only for ready local work: an answer is built under its job and written after the
    job is given back (PL-22). Private Session serving does not answer from the snapshot alone: it
    uses its bounded native operations, with short room locks for preparation and installation
    (PL-15, PL-28). Private serving checks its authority at each physical write, a
    queued answer ends with its asker, and an entry under an unresolved head is served with the
    header proven under that head (PL-25). Item 6's correction may carry up to three pages of the
    asked author, and its body part only takes claims away (PL-20, PL-25).

### When a peer is slow, gone or wrong

- **PL-8. A peer's trouble stays on its own connection.**
  - Slow: only that connection's loop waits.
  - Gone: the end of the connection drops that connection's state; what was owed stays owed.
  - Wrong: a reply that fails verification closes only that connection. It is never treated as a
    fork verdict (ADR-053 MP-9: a bad relay proof is pending, not a fork).
  - *Source*: design.md:54-57; ruling.md:33.
  - *Why*: `what-the-room-needed.md:12-18`.
  - *(Amended 2026-11-25, amendment 3:)* Refused: the connection's outbound exchanges stop until the
    peer's news, whatever form the refusal takes (PL-23). A fault of this node stays this node's: it
    is not charged to the peer or turned into a wait for the author's next head (PL-17).

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
  - *(Amended 2026-11-25, amendment 3:)* The deletion is no longer the first slice's alone or
    Public's alone: everything that fetches history adopts the loop, and what is to be deleted with
    it is under Amendment 3 (c). Of item 8, the second ruling withdraws only the deletion of the
    in-flight preference, which comes back as the non-exclusive mark of PL-21
    (`ruling-in-flight.md:5`); its other prohibitions stand.
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
  - *(Superseded 2026-11-25, amendment 3, by the decider's ruling 5 and PL-24.)* Nothing stays on
    the old machinery: archive paging, own recovery, key bodies and private Sessions adopt the loop
    in v0.4.31 (`exec/deviations.md:216`; design.md:181). Kept from the list: the meanings of status
    fields (item 5; PL-24); the floor and debt (PL-3); and bounded local allocation and work, native
    retirement and legacy Session record decoding (Amendment 3 (c)).

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
  - *(Amended 2026-11-25, amendment 3:)* One scheduling rule is added by a second ruling, which
    amends this requirement explicitly rather than claiming to meet it: the in-flight preference of
    PL-21 (`ruling-in-flight.md:5`). Its other prohibitions stand. The withdrawal tests of the
    adoption ruling are added to this requirement's (`design/adopt/ruling.md:93-97`); among them:
    any kind keeps a second asking owner or scheduler; a refusal causes outbound work without the
    peer's news; a later head recreates accepted-chain debt or progress; an unresolved or forked
    head borrows accepted-chain facts. The admission-order ruling adds an order inside the room's
    ready set (PL-30); in its words it is "one selection rule in ReadySet, not two worker pools, a
    timer, a new port queue or parallel publication owners", with "No new scheduler, timer, retry,
    durable priority flag or second admission owner" (`design/adopt/ruling-admission-order.md:22`,
    :58).

## Amendment 3 (2026-11-25): everything that fetches history adopts the loop

*(Added 2026-11-25, amendment 3.)* This section states the rules; the mechanism is in
`design/simple-sync/design.md` (Amendments 2 to 4) and `design/adopt/ruling.md`, which is the build
specification. Nothing of it is merged: the rules are built in a scratch tree, measured there, and
accepted by each area's reviewer ((g)). The built tree is frozen at scratch commit `0bfd8592c`
(`simple-sync/review/STATE.md:108`).

### (a) What changed, and why

**Why, in the decider's words** (rulings 4 to 6): "dogshit design", "must fix", "KISS", "without
losing security"; "like we keep patching a fundamentally fucked design" / "instead of fixing the
design and having everything adopt it"; "anything that isn't measuring how a user experiences the
app is a waste".

**What changed.**

1. M0 comes with the loop, and history that waits on another position folds locally (ruling 4;
   design.md's Amendment 2).
2. Runs of the loop showed one fault four times in one day: a fact about an author's positions was
   kept or looked up under one head of that author, and was owed or rebuilt again whenever the
   author posted (design.md:178). The rule is now that such a fact belongs to the author's position
   (PL-19). An audit listed every place: 174 places, 20 kinds that stay per head, 25 faults
   (design.md:181).
3. A second ruling put back one preference the first ruling had deleted: a planner prefers work
   that no other request of this node covers, but never waits for it (`ruling-in-flight.md:5`;
   PL-21).
4. Everything that fetches history adopts the loop (ruling 5). The independent ruling
   `design/adopt/ruling.md` answered "BUILD sol WITH CORRECTIONS from opus", with seven corrections
   and seven build steps, each leaving the product working and deleting something, and no question
   for the owner (design.md:181). It supersedes PL-12.
5. What a person is shown is placed by a key fixed when the entry is first admitted (PL-26), by a
   ruling that answered "BUILD (d)" (`ruling-order.md:3`).
6. Five reviews of the built tree, one per area, rejected it first and accepted it after fixes
   (`simple-sync/review/STATE.md:6-12`). Two rulings were made during them: public body extents are
   told to every peer, and a correction only takes body claims away
   (`ruling-body-extents.md:1`); and a peer is told of private records only by an exact, bounded,
   resumable local walk, with an anchored LiveTail, a request for the bounded private-record window
   ending at the announced position (`ruling-private-tip.md:1`, :46-49). Rules their findings
   enforce are stated below.
7. An upgrade of a room that v0.4.30 had left stalled did not recover on the built tree. Two faults
   were found while upgrading it: its upgrade floor, and admission of published predecessors
   without locators. Both were fixed (`exec/found-reds.md:218`; PL-29). The parent-evidence rule
   also covers locator-free published positions in stores written by the scratch build
   (`simple-sync/review/fix-FixLoopB.md:271`).
8. Two more rulings followed. The admission-order ruling, made after a busy-room run in which a
   paused member admitted 1.3 to 2.2 entries a second against about 8 arriving
   (`ruling-admission-order.md:1`, :6), orders the room's ready set and lets asking go on while
   admission is behind; its Amendment 1, after measurement, lets only runnable posts take the
   ordinary turn and rules one room-lock hold and one publication per admitted entry (PL-30,
   PL-31; built as one owned write and one publication). The second display-order ruling lifts a
   reply after an entry it names that is already shown here (`ruling-order-2.md:1`, :5; PL-26).
9. A sweep of the release's proofs found 26 that are green on main and red on the built tree, in
   eight groups (`simple-sync/review/STATE.md:61`). Their fixes, and fixes asked by later reviews,
   each accepted by its area's reviewer (`STATE.md:62-81`), add PL-32 to PL-35 and change PL-17,
   PL-20, PL-23, PL-24 and PL-28.
10. In the final rounds the one-step admission was built and accepted (PL-31), a kill inside a
    join was traced to a peer's told record kept per room and peer instead of per connection
    (PL-36), and a member trusted again was found never to get another member's key back (PL-37)
    (`STATE.md:83-98`; `exec/found-reds.md:265-266`, :271-272).
11. Last, a member back after 8,000 missed posts no longer showed the newest post first. A bisect
    found no first red commit among the 42; the builder infers that the earlier greens depended on
    which ask ran first. Admission's oldest-first take was changed (PL-30 item 6), and the
    deferred-row backfill reset was changed (PL-38); attributing the earlier unshown segments to
    that reset remains the builder's inference, not a reproduced failure
    (`exec/found-reds.md:286-287`, ledger 127; `simple-sync/review/fix-FixBack.md:20`, :29;
    `fix-FixBack2.md:24`, :66; `STATE.md:107-108`).

### (b) The rules as they now stand

- **PL-14. M0 is built together with the loop, as its own change beside it.** M0 (ADR-053
  amendment 2; in the coordinating session's words, "a post is accepted on its author's signature,
  its author's standing and its own predecessor; what it names of other members is a pointer for
  ordering that the reader never waits to fetch") MUST be built together with the pull loop: not
  optional and not later. Its security acts (a made-up tip, another branch, a hint that never
  arrives, an old checkpoint, a forged cut) and a security review come before its merge.
  - *Source*: `exec/deviations.md:205`; design.md:158.
  - *Why*, measured: with M0, no ordinary post records a need that names another author (0, in the
    eight-author act and in the short act); without it every post does (design.md:158;
    `simple-sync/pull-m0/report.md:66-67`).
- **PL-15. Public planning reads no store.** Public-history planning and preparation of public
  Have rows MUST read no store and MUST take no room lock. Private Session selection, discovery
  and serving use their bounded native operations, including short room locks for preparation and
  installation (PL-28). What this node holds per author (its signed heads, decoded once; the
  runs of positions validated, held and walked; the Have it tells) is one in-memory record per
  room, updated for the authors a commit names and published with the room's snapshot. A loop plans
  from the peer's last Have, that record and the frontier, and wakes only when one of them changed.
  - *Source*: design.md:160; private Sessions: `simple-sync/pull/on-main/step6.md:12-25`,
    `simple-sync/review/fix-FixPrivate.md:224`, :382-391.
  - *Why*, measured: with planning reading the store, each member of the eight-member room used
    about 83 % of a processor posting once a second before any newcomer joined; with the record, a
    newcomer to a 257-post room caught up at a flat 58 to 65 entries a second, where before it fell
    from 23 a second to 2 (design.md:160).
- **PL-16. A need is exactly what the validator asked for.**
  1. An ordinary post is admitted on its predecessor's receipt (header, inclusion and own-prefix
     proof under any committed head of its author) and on its author's earlier controls being
     admitted; it never waits for earlier posts to be admitted. Only a need for an entry waits on
     that position's admission.
  2. A need for one position asks for one position; pages are for debt. A need for a member's head
     is a need like any other.
  3. The loop asks needs before promotions and debt, and keeps PL-4's alternation of newest
     and oldest debt. For an author of whom nothing is admitted, it asks for the control coverage of
     the author's history, then for those controls, then for the newest page, then older pages.
  4. A need is anchored on what this node knew before the step that recorded it, so a head
     committed in between meets the need at the next plan.
  - *Source*: design.md:167, :169, :173 (which withdraws :169's "a need that names a position is
    met by the page that ends at that position"), :174; `ruling-in-flight.md:13`.
  - *Why*: built otherwise, a newcomer admitted each author from position 1 upward, about 1,670
    positions for each of two members at 7.5 a second (design.md:167); a need recorded one
    millisecond after the head it waited for had committed was never met, and every loop slept
    (design.md:174).
- **PL-17. One admission per room; an entry that waits is kept and handed on at once.**
  1. The room's frontier holds what is ready and what waits, as runs of positions per author. One
     admission task per room takes from the ready set; a need being met moves its waiters to the
     ready set. Nothing belongs to a connection once handed over.
  2. An entry whose admission needs an earlier position that is not yet admitted on this node is
     kept, with its body, and indexed by that position; that position's admission hands it to
     admission at once: no scan, no timer, no wake, no network round. Past the bound only its place
     is kept, and it is fetched again once the position is admitted. Every check stays (PL-10): the
     entry is admitted by the same validator, only later and locally.
  3. Every retained assembly allocation after an answer completes is counted: answers awaiting
     handover, partial bodies, ready entries, entries in admission and kept waiting copies. The
     accounting bound is one answer plus one largest entry per connection (17 MiB plus 8 KiB and
     nine bytes), and 64 answers plus one largest entry for the node (80 MiB plus 8 KiB and nine
     bytes). An answer still arriving is outside that count, within its request's 1 MiB wire
     credit, one per connection. A connection asks only with room for one more answer. Short of
     room, what no admission holds gives way first and is owed again; a complete answer the node's
     count has no room for is dropped, not held, before anything waits; and the wait is for this
     node's own admission, never for another connection's peer, holding no job, byte admission or
     lock.
  4. A local fault stays a local fault. Only a refusal of the author's evidence (an answer that
     does not match its request, fork evidence, an entry that differs from its inclusion, a head
     not yet committed, the validator refusing the entry's content, context, parent or controls)
     waits for a newer committed head of the author. A store fault, a fault of this node's durable
     state or a local bound never does. A failed admission keeps its room's admission until a real
     change for that room: its fence retired (the room left, closed or removed, or the node
     locked), the room's published snapshot revoked or of another epoch, a new entry made ready in
     the room, or the room's private news (a key, floor, opening, projection, trust, governance or
     permission change). Its failed entry goes back to the ready set when the failed work's
     retirement ends, and nothing in the room is admitted before that change; the failure's own
     cleanup, its returned entry and its wakes are no such change. No timer, no count. A local
     fault in a loop step parks that connection until the local cause clears (this node's byte
     pressure is released, or the room publishes again), not until the peer's news, and is not
     counted as the peer's failure.
  5. The room's own admission works for no peer, so the access rule for a peer (that peer's
     standing, no removal of it applied) is not applied to it: this node's own removal does not
     stop it admitting the entry that readmits it. Serving keeps that rule for every peer's reads
     and frames; admission still checks every entry, and what this node shows is still decided by
     its render check (the author's eligibility, the recipient's removal and readmission cut,
     consent).
  - *Source*: design.md:159, :168; `exec/deviations.md:207`; `simple-sync/review/loop.md`
    findings 4 and 9; `simple-sync/pull/on-main/step7.md:120-122`;
    `simple-sync/review/fix-FixLoopA.md:13`, :134-140, :201-205; `fix-FixLoopB.md:147`, :164-176,
    :187-199; item 3's figures: scratch commit `18b409efd`,
    `crates/vox-core/src/node/history_stream/pull.rs:927-953` and
    `crates/vox-core/src/log/history.rs:15-28`; item 4's failed admission:
    `simple-sync/review/fix-FixSpin.md:14-28`, accepted `serve-11.md:5-9`; item 5:
    `release/gate-sweep/fix-FixReadAfter.md:20-30`, accepted `serve-8.md:5-9`.
  - *Why*: dropping a waiting entry made every link of the membership history a fetch
    (design.md:159); with one admission flow per connection, entries handed over by a connection
    whose flow was still running were stranded (design.md:168).
  - *Why* (items 4 and 5): a room whose own admission failed was started again at once, unchanged,
    and failed the same way: "history room access changed", 103,485 times in about 40 s, and
    nothing in the room was admitted meanwhile. Its cause was this node's own removal judged by the
    rule for a peer, so the entry that readmitted it was never admitted (`fix-FixSpin.md:5-8`;
    `fix-FixReadAfter.md:13-18`).
- **PL-18. An answer page is admissible on arrival, and an answer that stops early continues by
  position.**
  1. A Range answer for entries lo to hi starts with the receipt of position lo-1 (existing proof
     forms, no body). When the reader's anchor is below the head's size and the page does not reach
     the head's last position, the answer also carries that last position's receipt (header and
     inclusion, no body) right after the consistency proof, so one answer promotes the head and
     brings the page. The header credit a reader grants counts these receipts as well as the
     entries asked for.
  2. Material that does not fit what is left of an answer is answered `More` with a continuation
     bound to the request, never Busy.
  3. Controls advance by position. The holder cuts control coverage into proofs that each fit one
     whole answer, halving what a proof covers down to a single position, and stops between proofs
     at a position. The reader ends the continuation at the first completed control proof, keeps
     what it verified as coverage, and asks next from after it. Nothing of earlier subranges is
     remembered but that coverage.
  4. Continuation state spans the leading consistency proof, terminal receipt and lo-1 receipt,
     plus one unfinished proof stage. When a single proof (a leading consistency proof, a terminal
     or lo-1 receipt, or one position's proof) does not fit one answer, the next request names how
     many contexts the reader already received across those stages, and the holder does not send
     them again. That count, the identities received and the contexts carried ahead of their proof
     end at the first completed entry, body cut or control proof; at most 100 contexts are carried
     and 301 identities kept at once. A context received before in the same continuation is no
     progress, and an answer bringing nothing new is a refusal (PL-23). Only contexts a verifier
     of the answer looked up are stored.
  - *Source*: design.md:169; `simple-sync/pull/on-main/per-head-a.md:5`;
    `simple-sync/review/loop.md` finding 8; `simple-sync/review/fix-FixLoopA.md:102`, :106-116,
    :162, :221-222, :264-272; `loop-3.md:5`, :11; `loop-4.md:9`, :11; `loop-5.md:5-7`.
  - *Why*: built without the lo-1 receipt, a newcomer to a 257-post room made 207 asks, one position
    each, walking backward; with it, 11 asks (design.md:169).
  - *Why* (items 2 to 4): in a room whose contexts are large, a holder that answered Busy when its
    leading material did not fit left the reader parked toward it for good, though the holder had
    everything (`fix-FixLoopA.md:129`); and a reader that kept every context identity for a whole
    Controls interval could be made to grow without bound by valid subranges (`loop-4.md:11`).
- **PL-19. A fact about an author's entries is located by author and position on the accepted
  chain; a head is a witness.**
  1. In the adoption ruling's words: "An authenticated entry fact or earned progress MUST be owned
     and located by room, scope, author and position/range (and entry hash where identity matters)
     on the verified accepted chain, with heads retained as witnesses rather than new debt
     identities, so a later proven extension neither recreates paid work nor resets progress,
     while authorization generations and exact-root evidence retain their separate meanings."
  2. For example: what an author's controls are, and how far they are admitted, is proven once
     under any committed head of the author and holds under every later one; a verified coverage
     is never shortened; when a head grows, only positions above what is covered are asked for. A
     verified full aligned block of an author's history is kept once, by author and position, and
     a proof under any committed head is assembled from those blocks and the head's own right edge.
  3. Evidence that arrives under a head not yet proven on the accepted chain stays bound to that
     head until the head is proven on it; only then are its facts kept by position. An unresolved
     or forked head, its pending evidence and its branch comparison never borrow accepted-chain
     facts.
  4. Stores written by main are migrated, never misread: the facts main keeps under head ids
     (control sources, coverage, source and effect prefixes) are migrated and merged from committed
     heads, in a way a restart resumes, before the new readers are enabled, and evidence under
     unresolved heads is kept apart.
  - *Source*: `design/adopt/ruling.md:67`, :69, :71; `exec/deviations.md:217`; design.md:170,
    :176, :178; `simple-sync/review/loop.md` findings 1 and 7; `simple-sync/review/delete.md`
    finding 1.
  - *Why*: kept per head, the same coverage of the same old positions was owed again every time an
    author posted: 5,235 coverage asks and 127 admitted entries in one run (design.md:170); a holder
    served its own feed at 4.6 ms an entry and another author's at 92 to 146 ms, because proof
    pieces were kept under the head they arrived with (design.md:176).
- **PL-20. What a Have tells, and to whom.**
  1. A Have tells a peer only what that peer does not already hold. Received entries are made
     durable once per publication of the room's record, not once per connection per changed
     author.
  2. Body extents are told in bounded pages that together cover every held body, old owed
     positions included. An omitted page is not absence; a page of an ordinary Have replaces what
     lies inside its span. Public body extents are told to every peer, not scoped to the recipient:
     they say only that this node holds those bytes now, and the recipient cut is still checked
     before any body is read or sent. A holder's correction in an answer only takes body claims
     away, inside each of its spans, and never adds or restores one; so a body the cut refuses
     costs at most one refused ask each time an ordinary Have offers it again, not once per
     connection.
  3. What a peer says it holds is kept per connection, within one allowance of 16 MiB per room and
     peer that all that peer's live connections share (PL-36), counted at the size of what is
     kept, not a measured memory peak. Rows of authors this node does not know yet are kept within
     that allowance, since a row dropped for arriving early would not be told again. A connection
     whose row or correction would pass the allowance is closed; nothing another connection keeps
     is evicted.
  4. What a peer is told of private records is PL-28. A peer is never sent a private section it
     was not found entitled to, not even a zero one.
  5. The own-release section (which sender-key releases of an author this node can give back) is
     told only to that author.
     *(Amended 2026-11-27 by ADR-055 FO-7: there is no own-release section. No sender-key release is
     advertised, asked for or served over the network; frame tag `0x0D` is decoded and discarded.)*
  6. A key package's body is told as held only when its stored entry carries the body, the same
     fact serving sends from, and as owed only when it is not held and its debt is live; a debt that
     expired unfilled is not possession. Every write that changes either fact touches that
     position, so the told record and a reopened store agree.
  - *Source*: design.md:175; `design/adopt/ruling.md:27`, :35; `simple-sync/pull/on-main/step4.md:7`,
    `step5c.md:9`; `simple-sync/review/loop.md` finding 5, `serve.md` finding 2, `private.md`
    finding 1; `design/adopt/ruling-body-extents.md:1-3`, :9-12, :22-25; `keys-3.md:5`;
    `simple-sync/review/fix-FixLoopA.md:9-10`, :38, :146; `loop-2.md:13`; `serve-2.md:7`; item 6:
    `simple-sync/review/fix-FixKeyHeld.md:15-29`, accepted `keys-8.md:5`; item 3 as amended:
    `simple-sync/review/fix-FixHaveLife.md:54-59`, :116-117, accepted `loop-19.md:5`.
  - *Why*: about 11 Haves per publication per node, 608 a second on one daemon; of 16,024 Haves one
    newcomer sent a daemon, 917 led to an ask (design.md:175). Body extents scoped to each
    recipient would cost eligibility work per peer and position on every changed Have and buy no
    secrecy of contents (`ruling-body-extents.md:30-32`). Item 6: a relay whose key-body debt had
    expired unfilled told that body as held (`keys-6.md:5`).
- **PL-21. The in-flight preference: non-exclusive, never waited on.** In the second ruling's
  words: "The node-owned frontier MUST expose the ranges covered by this node's live requests as an
  ephemeral, non-exclusive planning preference: within the existing priority class, prefer
  still-owed work not covered by those requests, otherwise ask covered work anyway. Selection and
  marking MUST be atomic with respect to other planners; each exchange's mark MUST disappear on
  completion, failure, cancellation or connection end, without changing debt, checked knowledge,
  admission readiness or authority."
  1. It applies alike to needs, promotions and debt pages.
  2. A mark is not a reservation: a planner never sleeps solely because all otherwise eligible work
     is marked, and no durable row, peer speed estimate, refusal outcome or new Have creates or
     prolongs a mark.
  3. It MUST NOT grow negative caches, per-source refusal memory, waiting on another connection,
     rearm, timers, retry policies or author fallback.
  4. Own-key requests are independent across donors: every connection whose peer offers this
     node's missing sender-key release may ask for it, and none waits for another.
     *(Amended 2026-11-27 by ADR-055 FO-7: withdrawn; no own key is asked for. A recovery request
     or reply for an own key is refused on every connection.)*
  - *Source*: `ruling-in-flight.md:5`, :9, :15, :17; design.md:172; `simple-sync/review/keys.md`
    first P1 finding and `loop.md` finding 3; `keys-2.md:5`.
  - *Why*: every loop plans from the same record and frontier by the same rule, so for pages the
    duplication was a certainty, not a race: a newcomer received each body 3.47 and 2.75 times (runs
    r12 and r17), and the same 128-entry page was asked of 6 peers at once (design.md:172).
- **PL-22. Waiting on a peer holds nothing shared.**
  1. An asking loop holds no job and no shared byte admission while it waits for an answer. The job
     is taken only for checking an answer that is in, and given back before the next request is
     written; sending a Have takes none.
  2. Shared work admission is held only for ready local work, never while waiting on a peer, on the
     serving side too. The holder reads the whole request first as the connection's own input,
     holding no job. It then takes the job, builds the whole answer under it (one answer is at most
     its request's 1 MiB wire credit), gives back the job and every shared charge, and only then
     writes. Each frame is authorized again just before it is written, against the room's current
     snapshot and the same access rules the answer was built under; a frame that fails resets the
     stream. At most one Have and one ask are served at a time per connection and room; a newer one
     in the same place retires the earlier. A private answer is received in the connection's own
     assembly before shared admission is taken to check and apply it.
  3. Fetching never holds what a member's own post needs across a wait, and a waiting own post gets
     the room's next publication before another fetch step.
  4. An old flow's body query (`Entry`, `Page`), which needs the asker's acknowledgement in the
     middle of an answer, is answered without the body; no asker of this version sends it.
  - *Source*: design.md:171; `design/adopt/ruling.md:13`, :63; `simple-sync/review/serve.md`
    finding 1, `private.md` finding 4; `simple-sync/pull/on-main/step7.md:93-99`;
    `simple-sync/review/fix-FixServe.md:9-11`, :62-63, :92-101; `serve-2.md:5`; `serve-3.md:5`,
    :7; `serve-4.md:5`.
  - *Why*: the build had held a job for the whole exchange, so a daemon hosting several nodes could
    have every foreground job held by loops waiting on other daemons (design.md:171); and one member
    that stopped reading an answer kept a job and about 16 MiB of the 88 MiB shared pool for as
    long as it liked (`fix-FixServe.md:76`).
- **PL-23. A refusal parks the connection until the peer sends news.**
  1. A loop stays registered for the life of its connection. After a refusal, the connection's
     outbound exchanges stop until news from that peer (item 6), a change of this node's own
     standing, or a replacement connection. This node's own publications are not news, and local
     progress does not end a park: other work that peer could give waits with it.
  2. One no-progress rule, whatever form the reply takes. A reply is a refusal, and parks the
     connection, when the holder declined (`Busy`, `Cancelled`, or stopping with more than one proof
     stage unfinished), or when it gave this node nothing it asked for (no entry taken by
     admission, no object saved, no receipt, no partial body, no stage to go on from, no body
     withdrawn from what this node knew the peer held) while this node's record of the asked author
     stood as the ask was planned from. If the holder has not explicitly declined and the
     proof-stage continuation limit was not exceeded, a changed author record or a checked
     key-package body matched to a live debt whose position another admission already owns lets
     the loop plan again without parking or blame. Progress already verified is kept.
  3. A holder answers a loop's request Busy only when it no longer serves that room or retired
     that answer, or under a test switch; material that does not fit is `More` (PL-18). An old
     flow's request may still be answered Busy.
  4. A private refusal parks the whole connection, public asking included.
  5. A malformed or cryptographically invalid reply closes the connection; it is not asked again.
  6. News is only what changes what this node knows the peer holds: a Have page whose heads,
     committed head, proof, body or control runs, fork, unresolved or role head differ from the row
     kept, compared as the positions covered (adjacent and overlapping runs merged), so a page that
     only splits or reorders runs is not news; an own-release entry that differs; a new
     connection; or this node's own standing. A page told again unchanged changes nothing. A row
     that would pass the allowance (PL-20 item 3) is not kept: its connection is closed. A
     correction counts as progress only when it withdraws a body. A private section is news each
     time it comes, by the private-tip ruling, which costs at most one public re-ask per private
     announcement received.
     *(Amended 2026-11-27 by ADR-055 FO-7: an own-release entry is no longer news; a reserved
     release frame (tag `0x0D`) is decoded for its structure and discarded with no effect.)*
  - *Source*: `design/adopt/ruling.md:11`, :61; `simple-sync/pull/on-main/step1-3.md:11`,
    `step6.md:61`; `simple-sync/review/loop.md` finding 2, `serve.md` finding 6, `private.md:47`;
    `simple-sync/review/fix-FixLoopA.md:11`, :118-127; `serve-2.md:15`; `loop-2.md:7`; items 1, 2
    and 6: `simple-sync/review/fix-FixKeyHeld.md:52-64`, :113-135, accepted `keys-8.md:9`,
    `keys-9.md:5`, `loop-14.md:15-23`, `loop-15.md:5-9`; item 6's allowance:
    `fix-FixHaveLife.md:58`, accepted `loop-19.md:5`.
  - *Why*: retiring and recreating the loop turned a refusal into perpetual requests
    (`design/adopt/ruling.md:11`).
  - *Why* (items 2 and 6): a relay asked for the same key body 40,027 times, each answer counted as
    progress though it kept nothing (`keys-6.md:11`; `release/gate-sweep/fix-FixKeyPkg.md:43-48`);
    a second valid copy of a body another connection had brought parked a whole connection
    (`keys-6.md:9`; `keys-8.md:7`); and identical corrections, a correction that only split runs,
    and a row the bound kept rejecting each let a peer keep one ask running or end a park
    (`loop-13.md:7`; `loop-14.md:8`, :11).
  *(Amended 2026-11-28, amendment 4: a node whose room store has recovered closes and redials its
  connections to that room's peers, because a peer parked on a refusal given while the store had
  failed waits for news, and the recovered node's unchanged Have is none (PL-41).)*
- **PL-24. Everything that fetches history adopts the loop.**
  1. Every kind of fetching has one asking owner, the connection's loop: public history, own-history
     recovery, key bodies, own sender-key releases, exact receipts, private Sessions and saved
     history requests.
     *(Amended 2026-11-27 by ADR-055 FO-7: "own sender-key releases" is withdrawn; own-history
     recovery fetches entries only and opens them with the keys the node still holds.)*
  2. Key bodies are asked as bodies under the Have's body extents, with the recipient checks
     unchanged.
  3. Private Sessions keep their existing queries and checks; the one loop chooses them from what
     the peer was told (PL-28) and from private debt.
  4. A role or departure receipt stays an exact semantic receipt: a Have or a role hint alone never
     advances what a member is counted to hold or completes a departure.
  5. Rooms the product already refuses stay refused and their bytes untouched.
  6. Stores written by main or by v0.4.30 open and are migrated, or are refused cleanly; they are
     never misread or reset (PL-29).
  7. The meanings of status fields stay (PL-12 item 5): the last sync time moves only when an answer
     brought evidence this node did not hold.
  8. Every connection this node dials is adopted by the one owner, the per-request dialler of
     `vox forward` and `vox up` included, so it gets its stream loop and serves its peer's
     introduction and asks; a live connection is returned as before. Adoption grants no
     permission: stream policy and room authorization still apply.
  - *Source*: `exec/deviations.md:216`; design.md:181; `design/adopt/ruling.md:9-15`, :47-49, :97;
    `simple-sync/pull/on-main/step7.md:114`; `simple-sync/review/delete.md` finding 6; item 8:
    `release/gate-sweep/fix-FixOrderAnchor.md:29-33`, accepted `serve-9.md:11-17`.
  - *Why* (item 8): a guest that had reached its room's anchor through the per-request dialler
    never served the anchor's introduction on that connection, so the anchor's new statement was
    never told to it (`fix-FixOrderAnchor.md:24-31`).
- **PL-25. Serving keeps its authority through the physical send, and nothing outlives its
  asker.**
  1. Private serving: the set of Drive holders is published together with the exact trust
     incarnation it was derived from, and serving checks that incarnation. Just before each
     physical write of a private page or a private Have, the trust incarnation and the removal
     generation are checked under the same fence that a keyring change commits under, so a
     withdrawal cannot commit between the check and the write.
  2. A queued answer whose asker abandons the stream or closes the connection is cancelled and its
     serving registration removed, before admission as after it.
  3. For an entry under an unresolved head, the holder serves the header proven under that head; a
     body is served only when its header hash matches that entry; otherwise the answer carries
     metadata only.
  4. A correction carries the bounded pages of the asked author that the holder builds, at most
     three, and the reader accepts them.
  5. Every worker of an own sender-key release holds the secret lease until its physical work and
     the disposal of its result are done.
     *(Overtaken 2026-11-27 by ADR-055 FO-7: the own sender-key release worker is deleted; the
     secret leases other lifecycles hold (leave, close, purge, untrust, own recovery's Computer
     policy wait) are unchanged.)*
  - *Source*: `simple-sync/review/private.md` findings 2 and 3; `serve.md` findings 3, 4 and 5;
    `keys.md` second P1 and P2 findings; `simple-sync/pull/on-main/step5c.md:80`, :86;
    `keys-2.md:7`, :9; `private-2.md:7`, :9; `private-3.md:11`; `serve-2.md:9-13`.
- **PL-28. A peer is told of private records only what it may be served, found by a bounded walk
  that only reads.**
  1. A donor tells a peer one position, `(incarnation, newest position servable to that peer)`,
     only after it has found an actual retained, unexpired record that the per-record serving
     check would serve that peer. With no such record there is no private section at all.
     Permission belongs to the record's author: B may tell C of A's record that B keeps without
     telling C anything of B's own records. A reader of an allowed record still learns the donor's
     incarnation and global arrival position. Gaps can reveal intervening arrivals, and `more` and
     archive scan cursors retain their existing numbering disclosures. This is not privacy from
     traffic analysis.
  2. It is computed when used, from the retained records and the current permission inputs. No
     permission result is cached: the connection keeps only the walk's progress, whether news came
     during it, the last permission serial it saw and what it last told.
  3. Looking is a read. A look takes no room write slot and no publication lease, and installs
     nothing. Only a record whose preparation is unfinished (a floor selection, an authorization, a
     continuity step, or the donor's first incarnation) takes one writing step for that record, and
     a waiting own post goes first. When no private record has ever been stored here, the zero
     private tip ends discovery before any native step, job or room lock.
  4. The walk is bounded and resumes. Each step examines at most 32 records and 1 MiB, reading the
     arrival locators and their records from one snapshot. Shared admission and ownership are given
     back between steps; cancellation and a waiting own post are checked before each. A running
     pass is never reset: later news only marks it to run again. Unfinished local preparation
     schedules its own next step. Only the connection's own teller advances the walk; no request,
     cursor or LiveTail from a peer can start, reset or advance it.
  5. A walk starts at the connection's start, for a new private record, or when the permission
     serial changes. The serial changes only when an input of permission actually changes: a
     governance change (membership, removal, readmission, standing), an installed keyring, this
     node's own floors, a Session floor or its source committed, an author's control readiness
     becoming ready, or a preparation completed (a recipient's eligibility decision among them,
     for a migrated legacy record too, moves the serial in the same transaction). A bare new signed
     head is not permission news. Under a changed serial the walk starts from the newest record,
     and a found position is told again even if its number is unchanged.
  6. LiveTail is anchored. The reader copies the position it was told into its LiveTail request
     (`through`). The donor checks that exact incarnation and that the record at `through` is
     present, unexpired and permitted; if not, it answers the asker's own cursor with no records
     and nothing new. If so, it serves only the 32 positions ending at `through`. One LiveTail
     costs one anchor check, at most 32 records and at most 1 MiB, whatever the history. An ask that
     does not decode, or comes from a peer not entitled to private records at all, gets the same
     fixed refusal (`AuthenticatorInvalid`, reset and stop), with no detail.
  7. An empty or non-advancing answer uses up the announcement once; the reader asks again only
     for another announcement or changed local private debt or permission.
  8. A private ask is its connection's one loop exchange in the room: it takes the place a public
     ask takes (PL-22 item 2), and a newer ask on that connection and room retires it. A donor that
     cannot answer yet, because its room's publication is busy, an own post is waiting, its policy
     publication is held or its last publication cannot decide the peer, waits inside that
     exchange for the event that ends it, holding no job, byte charge, lease, room lock or
     pending-write ownership; it does not refuse for its own busy state. Paging and sending the
     answer both stop at once when the ask is retired, the asker stops reading or the connection
     closes; a native step already running keeps its resources until it ends.
  9. Private news that makes the room's connections plan again comes only from what changes who
     may read or what is owed: a change of governance authority, of this node's membership or
     admission, of the keyring's Drive holders, of an author's Session floor, of a Drive receiver's
     release binding or of an opening basis, or an advanced projection; not every completed
     governance maintenance step. Completing own recovery or settling the room, together or apart,
     wakes the Session input that waited for it.
  10. The serving holder check stays: a donor serves its own records only to a current Drive
      holder. It protects the interval after a Drive downgrade is committed to the keyring and
      before the room's rekey makes the old generation fail the continuity check.
  - *Source*: `design/adopt/ruling-private-tip.md:1`, :7-11, :14-18, :24-25, :31-35, :40-42,
    :46-50; `simple-sync/review/fix-FixPrivate.md:168-173`, :382-399, :393, :474-476;
    `private-3.md:9`; `private-5.md:27-38`; `private-6.md:5-7`; `private-8.md:5-9`;
    `exec/found-reds.md:217`; item 5's eligibility decision: `private-10.md:5-7`, `private-11.md:5`;
    items 6 and 8 to 10: `release/gate-sweep/fix-FixSessionRead.md:15-19`, :27-31,
    `fix-FixSessionBusy.md:8-20`, :24-32, :52-62, `fix-FixSessionBusy2.md:8-23`, accepted
    `simple-sync/review/private-12.md:8`, `private-13.md:5`, :11-13, `private-14.md:5`, :9.
  - *Why*: B kept A's records while A was offline; withholding B's tip left C unable to read A's
    activity (`private-2.md:17`). A teller whose checks took the room's one write slot at every
    piece of news made fetched history answer busy and 4 to 5 times slower, in rooms with no
    private Session at all: the eight-author act went RED (ledger 100, `exec/found-reds.md:217`). A
    member given Drive late was told of the Session step written after its grant, asked for it, was
    refused "room publication is busy; retry this operation" for the donor's own busy state, and
    never asked again; that donor raised 2,438 private wakes in about 140 s from one line of
    maintenance (`fix-FixSessionRead.md:40-48`). A peer that stopped reading and asked again could
    keep one 4 MiB page charge per retired answer (`private-13.md:9`).
  - *Cost and limit*: a pass over N retained records costs O(N), at most 32 records per step; a
    peer that causes repeated readiness changes causes repeated passes (`private-8.md:9`). That
    every governance route that changes membership reaches a producer of permission news is not
    certified by the review (`STATE.md:12`).
- **PL-29. A store written by v0.4.30 or main is upgraded once, in place; there is no
  downgrade.**
  1. A published predecessor is its own parent evidence. When an entry's parent position is
     published here with the hash the entry names, and the author's range from position 1 to it
     has a frontier equal to the whole context that parent leaves (derived from the parent's own
     signed header), that is the parent's evidence; no receipt or locator is needed. One lookup
     serves admission and the answer's check of its leading receipt, so the loop and admission
     cannot disagree on whether a parent is held. The context is checked before admission follows
     the frontier, and again by the validator. A mismatch, or a missing context of the parent, is a
     local fault, held as PL-17 item 4 says, never a need. The rule is not only for old stores: it
     also covers published positions without locators in stores written by the scratch build, as
     own appends never write one.
  2. The floor of an author in a store written before floors existed is the lowest of that
     author's posts shown here, or the lower of it and the old program's window start; with none
     shown, the old window start if it kept one, else the newcomer rule (the newest 128 positions).
     It is set once at upgrade, with the one-time reindex, and resumes after a crash. What the old
     program left missing above the floor is owed and fetched without anyone asking; below it is
     older history (PL-27).
  3. At the first open the old proof cache is removed, once, in bounded slices, with the completion
     mark written last. The person is told the progress, as steps 1 to 9 with the first as "scan P%
     through": in the daemon log, in the room's wait that `vox status` and the room list print, and
     in a command's line when it gives up waiting.
  4. There is no downgrade. v0.4.30 refuses a store the new program has opened ("computer
     management state is malformed"; reaching the store, "on-disk schema 2, this build reads 1")
     and changes nothing. It does not tell the person to use the newer program.
  - *Source*: `simple-sync/review/fix-FixLoopB.md:220-226`, :234-242, :271, :276-288, :295-310,
    :401-402, :408-414, :436-438, :465-470; `loop-7.md:5`; `delete-4.md:7`; `delete-5.md:5-7`;
    `simple-sync/upgrade/report.md:117-120`, :125; `upgrade/why-upgrade.md:1`.
  - *Why*: on the built tree before these rules, a room v0.4.30 had left stalled did not recover:
    an entry whose predecessor v0.4.30 had published was never admitted (the answer dropped the
    predecessor's receipt, admission wanted a locator old stores lack, and the loop counted the
    need met), and what v0.4.30 left missing below the newest 128 posts became older history that
    nobody fetches. The first open took 89 s with no progress said (`exec/found-reds.md:218`;
    `upgrade/report.md:80`).
  - *Limit*: an author that forked, in a store where an older program kept the other branch's
    prefix, keeps its later posts missing on that member, held as a local fault; repairing it
    would mean deleting a real row (`fix-FixLoopB.md:382`; `loop-7.md:5`).
- **PL-30. A room admits urgent and ordinary entries in turn, and asking does not wait for
  admission.**
  1. An entry is urgent when its authenticated v2 signed kind is a control, or when an admission
     waits on its exact position. It is classed at handover, from the header already checked;
     nothing is decrypted. A waited position is urgent only while a waiter is registered on it: no
     author's whole history is promoted, and no priority outlives its last waiter.
  2. When both classes hold runnable entries, the room's one admission task takes one urgent entry,
     then one ordinary entry, each class in turn across authors. Within an author, urgent entries
     are taken in ascending position, and ordinary entries as item 6 says. When no ordinary entry
     is runnable, it goes on with urgent work. A later control may be tried before earlier posts of
     its author; the validator still decides it.
  3. Only runnable posts take the ordinary turn. A post below which a control of its own author is
     held here unadmitted (ready, in admission or waiting) takes no turn: it waits, with its kept
     copy and its charge, on that control's position, and is released and checked again when that
     control is published or leaves the frontier unpublished. When a control first becomes held,
     its author's queued posts above it are checked again in the same hold of the frontier lock.
     This is known only from authenticated positional facts, never from a claimed context, `seen`,
     an advertised head, earlier posts or a later control; earlier mandatory controls of an author
     are never bypassed.
  4. The guarantee, as amended: with D ordinary authors whose posts are runnable, an ordinary
     author's next turn comes after at most D−1 other ordinary and D urgent turns, besides the one
     running. It protects posts that can be admitted, not posts whose mandatory evidence or control
     effects are not available yet; a flood of signed controls cannot starve a runnable post.
  5. Asking does not wait for admission. Entries handed over and not yet admitted do not hold back
     asking: after its assembly check the loop goes on with exact needs, control prerequisites, key
     body debts and debt pages, and asks for a promotion only when none of these is eligible. Within
     debt, authors take turns after each debt ask, and each author's pages alternate newest and
     oldest, this node's own oldest first. Only positions walked, ready, in admission or waiting
     are taken off what is owed, never a whole connection, author or head; only bytes can hold back
     another ask.
  6. *(Amended 2026-11-26, amendment 3, by the loop reviewer's ruling.)* An author's ready posts
     are taken newest and oldest in turn, newest first; urgent takes (controls and waited-for
     positions) stay oldest first. This is a narrow, ruled exception to the admission-order
     ruling's "ascending by position within that author's class", for the ordinary class only. A
     post needs only its predecessor's receipt and its author's earlier controls, never an earlier
     post, so the newest post is taken at its author's first ordinary turn after its last control
     below it is in, and backlog that arrives after it does not go ahead of it; the oldest still
     gets every other take of its author, so a backlog drains while the author keeps posting.
     Asking already does the same (PL-4 item 2; item 5), so what is asked first is admitted first.
     The order between classes, the author rotation and the parking of item 3 are unchanged.
  - *Source*: `design/adopt/ruling-admission-order.md:15-22`, :40-46, :56-58, and its "Amendment 1
    (after measurement)", section 2, :67-72; `simple-sync/review/fix-FixAdmit.md:12-17`, :50-60,
    :170-185, :218-224, :267-271; accepted `simple-sync/review/loop-8.md:5-11`, `loop-10.md:5-9`,
    `loop-11.md:5`; item 6: `simple-sync/review/fix-FixBack.md:34`, :38-39, :43-46, ruling and
    acceptance `simple-sync/review/loop-20.md:3-5`.
  - *Why*: measured, the paused member of the busy room admitted 1.3 to 2.2 entries a second
    against about 8 arriving, with 400 to 500 entries queued (`ruling-admission-order.md:6`). In
    the eight-author act, 555 of 707 posts taken for admission ended waiting for one exact
    position, each wait an ordinary turn; the waits were the effects of the post's own author's
    controls, still held here unadmitted (`fix-FixAdmit.md:156-166`).
  - *Why* (item 6): a member back after 8,000 missed posts must show the newest post first. The
    fetching already asked the author's newest page first (PL-4 item 2), and admission undid it:
    the ordinary class took the author's oldest ready post every time, so in one traced run the
    newest post was never taken in 387 ordinary takes (`fix-FixBack.md:25-28`). The proof's earlier
    greens were a race: there, by the builder's inference, the reader's first ask happened to be
    the promotion of the author's head, so the newest post was the only one ready
    (`fix-FixBack.md:20`, :29).
  - *Built*: accepted at scratch `8199ede8a` (`loop-11.md:3`), from source. A turn is one entry,
    not the ruling's verifier work budget, and entries without a v2 header are ordinary
    (`loop-8.md:5`; `fix-FixAdmit.md:40-46`). A control whose own author's lower control is held
    here unadmitted still takes urgent turns to find its wait (`fix-FixAdmit.md:226`).
    Item 6, in the reviewer's ruling: it "changes the ruling’s literal requirement, but serves its
    intent"; no earlier ordinary post must be admitted first, and no check is bypassed.
    "Catch-up can now more often publish a reply before its question, extending the period when
    only the reply is visible"; "Where the missing anchor produces an inversion, that placement can
    remain permanently—catch-up does not repair fixed keys", within the second display-order
    ruling's catch-up concession; "The supplied evidence does not establish how frequently
    inversions occur." Fairness is unchanged: the D−1 ordinary and D urgent bound is an author-turn
    guarantee. "The reported 2–11 ms waits are observations, not a universal latency bound": in
    the eight-author act about 8 more ordinary takes per run went straight to a short wait (12 of
    156 against 4 of 109) (`loop-20.md:5-13`; `fix-FixBack.md:55`, :58). Accepted at scratch
    `12abc309b` (`loop-20.md:3`), from source.
  *(Amended 2026-11-28, amendment 4: a held key-package control whose body refill finds the body
  retired leaves the frontier, so the posts it held run again (PL-42).)*
- **PL-31. One admitted entry is one owned write and one publication.**
  1. A completed entry MUST be admitted as one bounded native operation: in the ruling's words,
     "one entry-local room-lock hold and one final changed-room/read publication for a completed
     entry, consolidating repeated phase locks and eliminating intermediate/no-op publication
     churn". As built and accepted, that hold is the room's pending write, owned by the entry from
     before its validation is re-derived to its one final publication; the room's mutex is taken
     only for each bounded in-memory step, and never across a store transaction. Runs of up to
     eight entries MUST NOT be built now. Only if the same user journeys after these changes still
     demonstrate an admission deficit may a separately measured decision enable them, within the
     original eight-entry, 256 KiB, shared-work-budget and prefix-atomicity ceilings.
  2. A room's log MUST NOT hold an entry its governance facts have not taken in: the transaction
     that writes an entry into the room's log MUST also advance the governance facts over it.
     Further steps of the same entry (a governance fold when needed, the entry's effect, a legacy
     migration) may run in transactions of their own, but no state between them is published.
  3. The lock and the publication reservation MUST NOT be kept across worker scheduling, a wait for
     remote evidence, a governance wait or a yielded continuation: an entry that cannot finish
     within its work bound keeps its exact checkpoints and lets go, and a waiting own post goes
     before the next entry. Every check, durability rule, cancellation and retirement guarantee,
     own-post priority and the 17 MiB / 80 MiB bounds stay; moving a check needs a security
     review.
  - *Source*: `design/adopt/ruling-admission-order.md:74-79` ("Amendment 1", section 3);
    `release/gate-sweep/fix-FixRoster.md:97-100` (second round); item 1's built form:
    `simple-sync/review/fix-FixQuantum.md:39`, `fix-FixQuantum2.md:52-59`, accepted
    `delete-10.md:9-17`; item 2: `delete-10.md:11-17`, `fix-FixQuantum2.md:73`.
  - *Why*: measured, waits for the room lock dominate admission; commits take under 1 % and
    publications 5 to 9 % (`ruling-admission-order.md:75`). Between the step that writes an entry
    into the room's log and the step that takes it into the governance facts, every command gated
    on the room's governance answers "this room's permissions are still being read from local
    storage", for content entries as for governance ones. In the agent-hook proof a member's
    `vox room link`, right after another member left, was refused so, 2 ms before the entry was
    taken in (`fix-FixRoster.md:42`, :70-77, :81, :86-90).
  - The two largest other holders of the room lock were fixed apart from this rule: the Session
    attention save holds the room lock only for its decision, not across its store write and
    flush, and a status view does not lock a room that nobody was granted since a view last read it
    (`simple-sync/review/fix-FixLock.md:16-18`, :30-33; accepted `delete-9.md:3-9`).
  - *Built*: accepted at scratch `774ebd9c2` by two reviews, each for its part: `loop-16.md` (every
    check still precedes the effect; admission order untouched) and `delete-10.md` (store,
    transactions, crash and reopen, display key, and the upgrade from the redesign's previous
    build) (`loop-16.md:15-27`; `delete-10.md:3-5`). In the reviewers' words it is "one owned
    operation and one final publication, **not one database transaction**", and "One owned write
    is not one atomic transaction": an uncommitted transaction rolls back; a source already
    committed stays accepted if a later fold or effect fails, its mirror installed before them, and
    the final publication exposes committed state rather than rolling it back
    (`delete-10.md:9`; `loop-16.md:21`). A crash at any point leaves a state reopen repairs:
    unfinished work is rolled back before the room is shown, a switched source keeps its cleanup,
    and an unfinished effect stays owed (`delete-10.md:19-32`). Per entry, from source and not
    measured: one owned write instead of at least eight, six room-mutex holds, plus one when
    governance needs folding and two when legacy migration is owed, instead of at least
    25, two transactions (publish and effect, plus a fold and a migration when owed) instead of at
    least seven, one publication instead of at least eight (`fix-FixQuantum2.md:52-59`). Both
    reviews are static: no build, test, daemon, fault injection or migration experiment, and
    neither repeated the other's part (`delete-10.md:55`; `loop-16.md:29`).
- **PL-32. A join always answers, and truly.**
  1. A join after which this node's own history in the room must still be recovered (as on a
     rejoin) answers within its deadline. When recovery is still pending it says so: "this node's
     own history recovery in this room is pending: it reads the room now and cannot post here until
     recovery completes; recovery needs members that hold the history and may remain pending
     (`vox status` reports its current state)". Posting stays fenced until recovery completes: the
     answer changes the reply only, not the fence. A fork of this node's own history, once found,
     still takes precedence.
  2. A member that a join reaches while its room's publication is busy MUST wait for that
     publication to end, on the event that ends it, within the admission's own patience (20 s from
     the proposal's start), holding no room lock, prekey lock, publication reservation or history
     budget. A busy publication MUST NOT be told as this node's own history being behind.
  3. When that patience runs out, the member answers `Busy` and ends the stream; the joiner reads it
     and tries another member. The words are true for both causes of `Busy`: "a member answered,
     but it is busy answering other joins or saving the room, so it did not take you in", "this is
     not a verdict on your passphrase", "try the join again shortly".
  4. A busy publication MUST NOT drop an accepted join's Session. On the answering member the
     Session and its lifetime are kept, and the adoption resumes when the publication completes. On
     the joining device, one that replaces an existing Session keeps its continuation with its
     existing owner, and resumes the same way.
  - *Source*: `simple-sync/review/STATE.md:60`; `keys-5.md:1`, :5-11;
    `release/gate-sweep/fix-FixJoinBehind.md:46-47`, :50, :97-120, :124-131, :152-164; accepted
    `simple-sync/review/serve-14.md:5`, `serve-15.md:5-9`, `serve-16.md:5`.
  - *Why*: in the eight-author act a newcomer's join failed with "a member answered but did not
    accept the join; no specific cause was received … join stream closed early": three members had
    each refused it as "this node's record of its own history in this room is behind what a member
    holds", while only their room's publication was in progress
    (`fix-FixJoinBehind.md:8-18`, :33). Before the rejoin's answer was bounded, the command could
    wait without end while recovery stayed pending (`keys-4.md:7`).
  - *Built*: accepted at scratch `afe8e4661` (`keys-5.md:3`, wording applied in `ae3e4be9d`) and
    `b08d9eda3` (`serve-16.md:3`), from source.
- **PL-33. A returning member's recovery does not wait behind its owed removal rotation.** When the
  own-history fence refuses a removal rotation the member's governance turn owes (that refusal from
  the turn's room rotation or Drive rotation stage, and only that), the turn goes on to its next
  stage and reaches own recovery, removing that deadlock; recovery can still wait for missing
  material. The rotation stays owed: its checkpoint is unchanged, no key is released before it,
  and when recovery completes the room is woken and the next turn rotates. Ordinary posts stay
  fenced meanwhile.
  - *Source*: `release/gate-sweep/fix-FixReturn.md:23-28`; accepted
    `simple-sync/review/keys-7.md:5-9`, :11 (recovery can still wait for missing material).
  - *Why*: after leaving and joining again with the same identity, a member saw another's applied
    removal and owed a removal rotation. The fence refused it, 155 times in about 100 s; each
    refusal ended the turn, and the recovery that would lift the fence came only after it: a
    deadlock (`fix-FixReturn.md:14-19`).
  - *Built*: accepted at scratch `e08b24fca` (`keys-7.md:3`), from source.
- **PL-34. A rival head of the same size is compared, and a holder sends what it proved.**
  1. For an author other than this node, a peer's committed head with this node's committed size
     and another id is opened and compared like any rival head: through the same listing (ADR-053
     MP-9), Range under that head, promotion and comparison. It is tried whenever the peer's listed
     unresolved head gives no step, before this node's own unresolved head. Each thing listed is
     asked of a peer once, and an author already frozen is not compared.
  2. A holder that does not hold an entry's prefix under the head asked for sends the entry with
     its header and inclusion alone. It never serves accepted-chain facts under an unresolved head
     and never makes up a prefix; a page's lower edge without its prefix is no parent receipt.
  3. A Range answer is judged by what admission took: under a head committed here, an answer that
     brings only openings of positions already ready, in admission or waiting takes nothing and,
     giving nothing else, is a refusal (PL-23).
  - *Source*: `release/gate-sweep/fix-FixFork.md:28-42`, :66-76, :100-126; accepted
    `simple-sync/review/loop-13.md:5`, `loop-15.md:3`, closing `loop-12.md:5-7` and `loop-13.md:7`.
  - *Why*: on the built tree the second head of an author never reached a comparison. A rival of
    the same size was told and staged but never asked; and a head held unresolved was asked for its
    opening and answered `EvidenceUnavailable`, for want of a prefix nobody had asked for
    (`fix-FixFork.md:11-26`, :44-64).
  - *Built*: accepted at scratch `e52b9ecdc` (`loop-15.md:3`; `STATE.md:80`), from source.
- **PL-35. A member admitted later reaches every connected member.**
  1. When this node's board grows (a record learned: a new author, or a changed claim of one), the
     board exchange runs again over each loop connection of the room, besides at the loop's start
     and when a key waits on that peer's bundle. It stays the only way records go between members'
     boards, and each record still passes the board's policy and the roster's admission checks.
  2. Each room and connection has one board-exchange owner: at most one exchange runs and at most
     one more is owed, whatever the number of growths, and an owed exchange reads both boards as
     they are when it starts. It ends when the loop retires or the connection closes, and takes the
     secret-work lease for one exchange at a time.
  3. A roster save starts only for what the room has not saved: a member it does not know whose
     admission it can check now, a newer notice whose witness it knows, or a newer withdrawal; a
     notice already kept whose joiner is not yet an author here also counts.
  - *Source*: `release/gate-sweep/fix-FixRoster.md:21-30` (first round), :114-130 (third),
    :150-158 (fourth), :186 (fifth); accepted `simple-sync/review/serve-9.md:7`,
    `serve-10.md:5-9`, `serve-12.md:7-11`, `serve-13.md:5`.
  - *Why*: the built tree had deleted the ports' sessions that used to offer new board records to
    connected members, so a newcomer admitted after a member's loop started never reached that
    member ("not in this node's keyring; its room consent has not reached this node",
    `fix-FixRoster.md:12-17`); one exchange per growth event could grow without bound
    (`serve-9.md:5`); and 102 board growths started 102 roster saves, 97 of them with no new record
    (`fix-FixRoster.md:147`).
  - *Built*: accepted at scratch `0793f4edc` and `020e2e234` (`serve-10.md:3`; `serve-13.md:3`),
    from source.
- **PL-36. What a peer told is kept per connection, for exactly as long as the connection.**
  1. What a peer told this node in a room on one connection (its Have rows, its own-release
     section, its private tip, the receipts served on it) is that connection's record. Fetching
     uses that connection's own told facts. Shared allowance accounting reads other connections'
     retained charges and may remove their closed records, but never removes a live connection's
     record. The start of a newer loop removes no older live connection's record, so an older
     connection that the connection manager promotes again still has everything its peer told on
     it.
  2. A record is made only by its connection's first Have, release section or served receipt, or
     its loop's first look, and its removal is registered as it is made; none is made after the
     connection has closed. A record is removed only after its connection has closed: by its own
     watch on that close, or by the next charge of the same peer in the same room, whichever comes
     first. Nothing removes a record while its connection is live.
     *(Amended 2026-11-27 by ADR-055 FO-7, items 1 and 2: no own-release section is kept in a
     connection's record or makes one; the other sources of a record and the rules of its lifetime
     are unchanged.)*
  3. One allowance of 16 MiB per room and peer is shared by that peer's live connections. A record
     is charged a fixed cost when it is made, and then each row it keeps; closed connections'
     records are removed before the allowance is read, so what is counted is what is kept. A charge
     that does not fit closes the connection that would make it, as a protocol limit. Nothing
     another live connection already keeps is taken back, but no room to grow is reserved: another
     connection of the same peer can take the rest, and the first connection's later growth then
     closes it. An honest peer can meet the limit: in a legal 64-member room it leaves about 5,390
     body runs per author on each of two connections, which is room, not a limit the protocol puts
     on a room's history.
  - *Source*: `simple-sync/review/fix-FixQuantum2.md:37` (section 1b); `fix-FixHaveLife.md:7-11`,
    :17, :21 (first round), :54-59, :63, :67-69 (second), :104, :110-117 (third); accepted
    `loop-16.md:11`, `loop-17.md:5-7`, `loop-18.md:8-12`, `loop-19.md:5`.
  - *Why*: after a kill inside a join, the restarted host never fetched the other member's
    history: red in 5 of 9 runs of the crash act. What a peer told was kept per room and peer, for
    one connection's serial at a time; while a new connection displaced the old one, the old
    loop's next look wiped the record the new connection had just filled, the peer did not tell its
    unchanged row again, and the new loop found nothing of hers to ask, for good
    (`fix-FixQuantum2.md:14`, :16-41; `exec/found-reds.md:265-266`, ledger 120). The first fix
    still removed older connections' records when a loop started, and left records of closed
    connections with no owner (`loop-16.md:5-9`); a peer redialling within the retirement grace
    could then fill another 16 MiB per connection, outside the 80 MiB assembly budget
    (`loop-17.md:10`).
  - *Built*: accepted at scratch `da223952b` (`loop-19.md:3`), from source; no review ran
    anything (`loop-17.md:12`; `loop-18.md:14`; `loop-19.md:7`).
- **PL-37. A member trusted again gets this node's keys again, from a debt written with its
  accepted key.**
  1. When this node accepts a fresh key handed over directly by a member (new to this node,
     installable, its author consented to here), the debt to send that member this node's keys
     again is computed by the rule that applied before and written in the same transaction that
     installs the key: that member's history row is set to its entitlement floor where that is
     older than the live generation and lowers or creates the row, and its delivered row is
     removed, so the live generation is owed again. The key is acknowledged only after that
     transaction; if the transaction fails, the key is not accepted.
  2. An accepted key leaves the install by one exit, which commits any debt computed before the
     key is marked accepted, an already-held Drive key included. Every other exit refuses.
  3. The periodic rekeys own the delivery: on every tick (each second) and on reaching a member
     they send what is owed, after checking that the room is settled, neither side is removed or
     has left, the member is trusted and its consent facts let it read, and no removal rotation is
     pending. After answering the key this node starts one such pass at once; when that pass is
     refused (a busy room, a locked profile, a replaced room, authority revoked) the debt stays on
     disk for the next. A room or store kept busy can delay the delivery past any fixed bound; the
     debt survives the delay.
  4. A debt is metadata of what is owed, not permission: a member whose trust is withdrawn after
     it is written gets nothing, and the same checks run when it is trusted again. A removed
     member's key is refused at install, so no debt is written for it.
  5. A key read from the room's log writes no debt and keeps its earlier behaviour, as before;
     other delivery resets (as on a join or rejoin) stay separate and are not part of a key's
     acceptance.
  - *Source*: `release/gate-sweep/fix-W2Keys2.md:57-59`, :63-72, :109-113, :124-125; accepted
    `simple-sync/review/keys-14.md:5`, :9, :13, `keys-15.md:5`.
  - *Why*: a member removed while its room was closed, then trusted again, never got the other
    member's key back: "her key never came back" (`exec/found-reds.md:271-272`, ledger 122). The
    other member's step that would owe her its keys again was refused because the room's
    publication was busy, and was then kept only in memory, to be run by the next fresh key
    accepted from any peer; she sent hers once (`release/gate-sweep/fix-W2Keys.md:24-31`). Kept
    as a list, one target's failure held every other target's delivery (`keys-12.md:5`); dropped
    when refused, a member's debt was lost while its acknowledged key said it had been delivered
    (`keys-13.md:7`); one acceptance exit skipped the debt (`keys-14.md:7`).
  - *Built*: accepted at scratch `6b2428f5d` (`keys-15.md:3`), from source. Debt storage is bounded
    to the existing per-recipient ledger rows; "fresh" means the key's receiver slot is absent, so
    a retired generation can look fresh again, and repeated genuinely accepted fresh keys can
    trigger repeated delivery, as before this fix (`keys-14.md:11`).
- **PL-38. A post admitted before its key remains owed for rendering after the key arrives.**
  1. A post admitted while this node holds no key for it is published unshown; installing the key
     queues its author's render backfill walk, which shows the post only if the walk reaches it and
     the render decision permits it.
     A row whose render decision is deferred (governance refreshing) sends that walk back only to
     its own position: the walk moves back to the row when it is past it or done, and stays when it
     has not reached it. It is never sent back to position 1 for it. Key installs, consent grants
     and the other callers that start the walk from position 1 are unchanged, since a new key may
     open any position. The render decision itself is unchanged, and a deferred row is decided
     again before it shows.
  2. The backfill drain stops on a deferred row. It does not step again at once: the rest stays
     owed, the governance turn goes on, and the next turn runs the room's governance fold first.
  3. A key handed over directly while the Computer's publication lease has a writer waiting waits
     for that writer, like an event behind a pending save, instead of being refused; when the
     writer ends, parked events run in arrival order before any new save. When it runs, every
     check of an inbound key is made as before (trust, profile, room, session, the native install's
     removal and publication-authority checks); nothing decided before the wait is kept.
  - *Source*: `simple-sync/review/fix-FixBack2.md:24`, :27-29, :34-35, :37-40; accepted
    `simple-sync/review/delete-17.md:3-13` (items 1 and 2), `keys-17.md:3-11` (item 3).
  - *Why*: a member back after 8,000 missed posts held its newest posts admitted but unshown. Every
    admitted post whose first decision was "governance refreshing" sent its author's walk back to
    position 1, so while the backlog was admitted the walk never got past the bottom of the
    author's history [the builder's inference, not reproduced] (`fix-FixBack2.md:24`;
    `fix-FixBack.md:78-84`). In one run the author's backfill drain stepped about 1,700 times a
    second until the act ended, holding the room's save slot, and the reader showed nothing
    (`fix-FixBack2.md:8-10`, :28). And the reader refused an inbound key, which its author logs as
    "the room would not take the key", while a writer waited on the publication lease
    (`fix-FixBack2.md:21`; `fix-FixBack.md:83`).
  - *Built*: accepted at scratch `0bfd8592c` (`delete-17.md:3`; `keys-17.md:3`), from source; no
    review ran anything. Its limits, in the reviewers' words: a permanently deferred row "can
    keep its author’s cursor low and delay farther positions beyond the bounded batch; there is no
    wall-clock guarantee if its required governance never becomes decidable"; "This patch bounds
    the drain; it does not bypass an unresolved security decision" (`delete-17.md:11`).
    "Receiver-side parking has no deadline"; the unchanged prekey wait and busy log-package
    selection "can delay presentation, so this change does not guarantee the newest key arrives
    first or prevent every busy refusal" (`keys-17.md:7`, :13). A peer can occupy the existing
    network allowance of 64 queued events: bounded contention, not unbounded accumulation
    (`keys-17.md:9`).
- **PL-39. A member this node has lost its connection to is reached again.**
  1. A room's loops run only over connections that exist. A member port with no connection
     reaches its peer (ADR-025 D2), one dial per peer at a time, a fixed 8 s apart. There is no
     doubling and no port backoff: PL-12's "the reach backoff" is this fixed spacing.
  2. The address comes from this node's board first, then a connected board, then the peer book.
     A kept anchor is left to its own redial. Only a port of the room instance held now, at the
     room's current epoch, for a peer that is a member there and whose removal is not applied,
     may dial; a port kept for a departure receipt or a recovery does not.
  3. A reach that fails only ends the attempt: it runs no key work, counts as no sync failure and
     says nothing; a failure from an earlier network changes nothing. Reaching grants nothing:
     a loop starts only for a peer with standing, and keys go only where key delivery decides.
  - *Source*: `simple-sync/pull/regress/FixRetrust.md`; `simple-sync/review/serve-22.md`,
    `serve-23.md` (both REJECT), accepted `serve-24.md`.
  - *Why*: adoption step 7 deleted the reach with the scheduler. After a relay froze, each side's
    one dial (made for key work) failed, its key went into the log, nothing was owed, and nobody
    dialled the other again: for 90 s only local-network dials, and a post made after the relay
    was back never arrived. Found by the full sweep on the frozen build (the re-trust proof).
  - *Built*: accepted at scratch `003effe82` (`serve-24.md`), from source; no review ran anything.
    The re-trust proof is green on it four times in four; that either side is back within 8 s is
    read from the code, not measured.
- **PL-40. Rows a governance fold takes away or brings back tell clients on every path that runs
  the fold.** Since the one-step admission (ledger 111) the admission's own write runs the fold;
  it now raises the same notice as the projection step, once per real change, and re-reads the
  room's newest row.
  - *Source*: `simple-sync/pull/regress/FixNews.md`; accepted `simple-sync/review/delete-18.md`.
  - *Why*: after a removed member's posts left a room, nothing told a client to re-read the
    room's preview and unread count. Found by the full sweep on the frozen build.
  - *Built*: accepted at scratch `b2f456aba` (`delete-18.md`), from source; its proof is green on
    it once.

### (c) What is deleted

Besides PL-11's list, the adoption ruling's seven steps are to delete (`design/adopt/ruling.md:83-89`):

- the restart of a loop on the same connection, and the retry, backoff and raise of a port;
- per-head earned progress with its resets and lookups, and reservations for publication taken
  before a worker runs;
- the preparation and single-slot ownership of public older-history requests;
- `actor/key_body_scan.rs`, the KeyBody and KeyAvailability exchanges, the port's key selection and
  the key-catalog announcement;
- the Inventory and its old Have, role and availability tokens, the own, departure and discovery
  selection, RequiredOwner, the automatic own-archive flow, and OpenScheduler with its parked donor
  selection;
- the actor's private asking and serving dispatch, with its pacing, attempt sets, network deadlines
  and Busy failures;
- the port scheduler, the network Controller and its queues, the old flow's wire path, the
  flow-state pool, Busy and backoff with their events and status, and legacy reconciliation.

Deleted during review: the acknowledgement wait of the old flow's body queries with the daemon-wide
grants that existed only for it (PL-22 item 4; `fix-FixServe.md:63`); and the private teller's
permission memos and its unbounded search for an anchor (PL-28; `ruling-private-tip.md:53-56`).

Deleted in the later rounds: the gate that stopped asking while entries a connection handed over
were not yet admitted, with the promotion asked in its place (PL-30;
`ruling-admission-order.md:40`, :56; `simple-sync/review/fix-FixAdmit.md:50-54`; accepted
`loop-8.md:7`); the hold of a failed entry until the room's keys are erased (PL-17 item 4;
`fix-FixSpin.md:29-32`; accepted `serve-11.md:9`); and the private serve's refusals for the donor's
own busy state, with the private wake raised after every completed maintenance step (PL-28 items 8
and 9; `release/gate-sweep/fix-FixSessionBusy.md:16-17`, :30; accepted `private-13.md:13`,
`private-14.md:5`).

Deleted in the final rounds: an admission's separate Prepare and Commit phases, the store-opening
wrappers that each ran its own transaction, and the continuation plumbing between owned writes
(PL-31; `simple-sync/review/fix-FixQuantum.md:80`, :82-83; accepted `delete-10.md:3`,
`loop-16.md:15`); the close of a peer's told record at the end of a loop and the removal of older
connections' records when a loop starts (PL-36; `fix-FixHaveLife.md:10`; accepted `loop-17.md:5`);
and the separate step that offered this node's keys again after a fresh key, with its in-memory
set of pending targets and its busy-room wait (PL-37; `release/gate-sweep/fix-W2Keys2.md:9`, :60,
:74-75; accepted `keys-13.md:5`, `keys-15.md:5`).

Kept: bounded local allocation and work, native retirement, record decoding and the refusal of
unsupported formats (`design/adopt/ruling.md:89`), and legacy Session record decoding and migration
(`design/adopt/ruling.md:57`). In the scratch tree these deletions are made; what could not be
deleted, and why, is in `simple-sync/pull/on-main/step7.md:193-201`, among it the holder's wire
Busy answer, a reserved status that peers on main decode.

### (d) What stays per head, and why

Some facts really are about one head; they stay keyed by it (`design/adopt/ruling.md:71`;
`per-head-audit.md:335-356`, 20 kinds). A fact stays per head when it is:

- a signature over a head, or that head's place in the accepted chain (the head itself, the
  committed and observed heads, the proven commitments);
- a proof between two particular roots: a consistency or prefix proof, a promotion;
- an inclusion or parent receipt, whose proofs are against one root, and the right-edge pieces of
  a tree, which exist only for that tree's size; only a receipt's locator becomes positional;
- a check half done against one root: a verifier checkpoint, one answer's continuation;
- something a head names exactly: a departure or role terminal head, a new head told as news, own
  continuity and recovery boundaries, the head a new own entry extends, an archive or own-recovery
  page's head;
- an unresolved or forked head, its pending evidence and its branch comparison, which never borrow
  accepted-chain facts.

A larger position alone proves none of these (`design/adopt/ruling.md:71`).

### (e) Display order, and its concession

- **PL-26. What a person is shown is placed by a key fixed at first admission.** In the words of
  the second display-order ruling, which replaces one sentence of the first: "At an entry’s first
  admitted header publication, the node MUST persist `(D, entry_hash)`, where `B = min(signed
  claimed_ms, original local first_seen_ms.saturating_add(600000))` and `D = B` if no signed `seen`
  reference names an entry already held and committed/published in the pre-publication snapshot,
  otherwise `D = max(B, greatest such entry’s fixed display time.saturating_add(1))`. The key MUST
  remain unchanged through later admissions, refill, withdrawal/restoration and reopen; absent or
  receipt-only references contribute nothing and MUST NOT be fetched or awaited for placement, and
  display keys MUST NOT confer authority or replace existing causal/effect clocks." The first
  ruling's other sentence stands: "Display order MUST NOT confer authority or drive roster,
  lifecycle or Session interpretation, which retain their existing authenticated causal/effect
  semantics independently." In plain words: a row starts from its author's signed time, but no
  later than ten minutes after this node first saw it; if it names in `seen` an entry this node
  already holds and has published, it is placed at least one millisecond after the latest such
  entry; ties go by its hash; and once placed it does not move.
  1. The causal clock and its cap stay for every use that reads it besides display: governance,
     the admin roster stamp, the end of an idle room, notices, authored tips and Session ordering.
  2. A room written by main is re-indexed once, before its first readable open, from the original
     first-sight records; the re-index resumes after a crash, a missing record is never replaced by
     the time of the upgrade, and no reader sees a half-built index.
  3. Each governance notice is attached to one displayed place: it is shown right after the last
     shown message whose display key is not after the notice's own, or before the first message
     when none is. Governance and the notices' own order stay causal.
  4. `seen` stays, as nonblocking references outside ordinary Content authority. A display key
     depends on `seen` only through the named entries this node already holds and has published
     when the key is first fixed, read from the committed roots the publication started from, never
     from work not yet published. It does not depend on context coordinates or predecessor clocks,
     and does not change when another entry arrives. Each named entry costs one indexed lookup, at
     most sixteen; nothing is fetched, no chain of entries is walked, and no key already fixed is
     lifted later. ADR-053 MP-5 is amended so, and marked there.
  5. There is no absolute ten-minute ceiling. Each link of a chain of named, already-published
     entries adds at most one millisecond. For chains whose seed keys obey the new base cap,
     ignoring integer saturation, a key is at most the largest original first-sight time in its
     anchor ancestry plus ten minutes plus the longest anchor-path length in milliseconds. A year
     beyond all those base times requires roughly 31.5 billion links; a far-future legacy key
     frozen from main is an exception that later entries can inherit. Naming one entry many times
     gives the same floor. A row placed ahead by its cap can keep the rows that name it ahead of
     ordinary rows of the same time for about the rest of its ten-minute lead; naming an entry
     whose signed time is a year ahead, but whose key was capped, does not give a key a year
     ahead.
  - *Source*: `design/adopt/ruling-order.md:5`, :9, :13, :19-25; `design/adopt/ruling-order-2.md:5`,
    :9, :11, :17-21, :33; `simple-sync/review/delete.md` finding 3;
    `simple-sync/review/fix-FixSeen.md:126-127`; `delete-2.md:9`; accepted
    `simple-sync/review/order-1.md:3-7`.
  - *Why* (the floor): with the first ruling's key alone, a reply whose author's clock was an hour
    behind was placed above the question it answered, though the replier had read the question
    first ("alice: question at 16, answer at 3 of 17",
    `release/gate-sweep/fix-FixOrderAnchor.md:9-12`); in the second ruling's words, "a real loss of
    ordinary live usability, not a bad proof" (`ruling-order-2.md:5`).
  - *Built*: accepted at scratch `0e578d76d` (`order-1.md:3-5`), from source; a restart is argued
    from source only ((g)).

**The concession.** Members are no longer promised the same order. Ordinary times agree; but an
entry signed more than ten minutes ahead of a member's first sight of it starts from that first
sight plus ten minutes, and an entry is lifted only by named entries the member already held and
had published in the pre-publication snapshot, so members that saw entries at different times,
or in a different order, can place them differently, for good. Display order is not causal
either: on a member that did not yet hold the question when the answer arrived, a backdated
answer can stand above its question, but it cannot move a row already placed. On a member that
already had the named question, the answer is placed after it, even when its author's clock is an
hour behind. A member whose own clock is wrong
first sees its own posts at the wrong time, and in the review's words "a later message naming his
already-published post inherits its display floor"; a far-ahead key frozen from main by the
upgrade can be inherited the same way. In the first ruling's words: "The deliberate concession is
display causality/equality, not authority safety." A person is told, in the second ruling's words:
"Replies stay after a question they name on computers that already had that question when the
reply arrived, even with a slow sender clock. During catch-up, another member may receive the
reply first and keep it earlier in the conversation; history arrival never moves a row already
shown." This amends PRD-001 R13, ADR-023 RL-1.2 and ADR-053 MP-5; each carries a note pointing
here.
- *Source*: `design/adopt/ruling-order.md:7`, :11; `design/adopt/ruling-order-2.md:21`, :25, :37;
  `simple-sync/review/order-1.md:11`.

### (f) Older history

- **PL-27. A saved request is the debt, and each author's history is read downward as one
  run.**
  1. A saved or resumed history request is itself the debt: it enters the frontier's set of owed
     requests when it is durably accepted and when it is restored, with no preparation, worker
     admission or actor event between. Requests are each their own, keep their original bounds,
     pause, resume and cancel, and one never displaces another. A saved private request carries its
     admission capability (its original binding and fence) together with its debt.
  2. For each author, a request extends the unbroken run of held or admission-completed positions
     reaching downward from that author's walk floor. Stray positions below a gap do not count. It
     owes the page of up to 64 positions immediately below that run; authors are selected by the
     display time of their run's lowest post, newest first.
  3. One predicate, whether a key held here opens a post, is used both for rendering and for
     reporting an unreadable oldest held post. Failure to open it does not stop the request owing
     earlier positions down to position 1. Nothing a reader holds proves where an author's grant
     to it begins, so a post is never said to be written before the reader was trusted. A reader
     that pages down therefore fetches, only when it asks, older posts it cannot open; it holds
     them unread.
  4. A node added by a computer policy reads forward only: a member's room releases keys to it from
     where that room marked the trust decision, and nothing before. Its requests for older posts
     fetch them as for any reader; they stay unreadable.
  5. The answer says what is true here. When the oldest posts held of some members cannot be
     opened: "The oldest posts held here of K member(s) cannot be read here: no key for them has
     reached this node." When nothing is owed, nothing is in flight, no member's history is
     unknown or still arriving and none was left out for capacity, the request is finished:
     `Complete`, "Nothing older to fetch: every member's history here reaches back to its first
     post.", with the sentence above where it applies. When this node can take no more saved
     requests, the members left out are counted and said, and the answer is never `Complete`.
     *(Amended 2026-11-27 by ADR-055 FO-11: the sentence is "The oldest posts held here of K
     member(s) cannot be read with the keys this node retains. Coming back to a room does not
     restore earlier keys.", and K counts this node's own posts too.)*
  - *Source*: `design/adopt/ruling.md:12`, :62; `simple-sync/pull/on-main/older.md:130`, :136-146,
    :223-224; `simple-sync/review/delete.md` findings 2, 4 and 5, `private.md` finding 5;
    `simple-sync/review/fix-FixSeen.md:317-337`, :359-365, :376-378; `delete-2.md:11-13`;
    `delete-3.md:5`; `private-3.md:13`; `simple-sync/review/STATE.md:22-26`.
  - *Why*: the earlier request walked only the asked row's author, and only below that row, so a
    hole above it was owed by nothing; after ten requests six members still missed 1,335 to 1,434
    posts each (`older.md:102-117`). Reading a held release's start as the trust boundary was
    wrong: a key not yet arrived, or an author's consent reset, made a post look older than trust
    and stopped the request owing what was below it (`fix-FixSeen.md:280-306`; `delete-2.md:7`).
  - *Cost*: a forward-only reader that keeps asking fetches each author's history before its trust,
    64 positions of each author a request; in a 3,000-post room of two authors about 24 more
    requests (`fix-FixSeen.md:329-333`; accepted, `delete-3.md:5`).

### (g) What is measured, and what is not proven

**Measured**, on scratch commit `be14a9bb7` (every adoption step merged), before the review fixes;
the build to land must be measured again (`simple-sync/pull/on-main/measure-pl24.md:1-3`):

- the short act GREEN in 40.9 s; the eight-author act GREEN in 154.5 s, the newcomer showing every
  author 25 to 28 posts after its join; busy-room journeys 13 and 14 GREEN, 16 of 16 directions,
  with 4,230 and 3,962 posts acknowledged and 0 to 49 and 0 to 45 older-history requests per member
  (`measure-pl24.md:7-10`);
- older history, on earlier scratch trees: the busy room's older-history stage GREEN twice, each
  run alone, every member reaching 0 missing; the slowest member needed 45 to 47 requests to read
  the room of about 3,900 posts back to its start (`older.md:172-201`, :262-283);
- the own-history restore experiment the adoption ruling required before the cutover: "FEASIBLE
  WITH three adapter pieces beyond the un-skips" (`design/adopt/restore-experiment/report.md:5`).

**Measured during review** (`exec/found-reds.md`, ledger 100 to 102):

- Ledger 100: the eight-author act went RED after the review fixes (run r30: an author acknowledged
  100 posts since the newcomer's join and the newcomer showed none of them). Cause: the private
  teller took the room's one write slot at every piece of news (PL-28 item 3). Fixed: GREEN in run
  r32 on scratch commit `34396daea`, the newcomer showing every author 38 to 40 posts after its
  join, and the act's mutant `VOX_MUTANT_NEED_SETTLES_EVERY_ROOT` RED on the act's own assertion
  (`exec/found-reds.md:215`, :217).
- Ledger 101: three members of a room that v0.4.30 had left stalled, each showing only 116 to 401
  of another member's 1,500 posts, were upgraded. On scratch commit `ea66ab73c` every member still
  showed what it had shown, in the same order, but the room did not recover, and the first open
  took 89 s (`upgrade/report.md:1`, :80-83). On scratch commit `fd14f0277`, with PL-29's first
  forms: all three members showed every acknowledged post of the other two within 140 s without
  anyone asking, the same 4,517 rows in the same order; the first open took 16 s. Over 30
  once-per-second samples at rest, the daemons averaged 0.1 to 0.4 % of a core; their observed
  maxima were 0.5 to 8.0 % (`upgrade/report.md:134`, :140, :159-160, :166;
  `exec/found-reds.md:218`).
  The old program on the upgraded store refused it and changed nothing (`upgrade/report.md:117-125`).
- Ledger 102, **open**: the act `a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back`,
  run for the first time on the redesign (run r32), went RED: "the page below RG6-away-7938 never
  arrived after 3 answered requests", while later reads did show lower posts. Whether the act or
  the product is at fault is being settled by running (`exec/found-reds.md:219`).
  *(Amended 2026-11-26, amendment 3:)* The act's later result is below, after the acts' list.

**The acts and their one mutant each** (`simple-sync/review/test-sweep.md:38-45`, :238-277): by
ruling 6 an act stays only if its verdict is what a person sees.

- `a_slow_member_delays_only_itself`, mutant `VOX_MUTANT_ONE_ASK_PER_NODE`: the arm bites by
  reading.
- `a_newcomer_reads_authors_who_keep_posting_past_their_controls`, mutant
  `VOX_MUTANT_NEED_SETTLES_EVERY_ROOT`: RED on its own assertion in run r32 (ledger 100).
- `a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back`, mutant
  `VOX_MUTANT_NO_PROMOTION`: the arm bites by reading; the act itself is ledger 102. *(Amended
  2026-11-26, amendment 3:)* The arm was run since: RED on its own assertion (below).
- Deleted, their claims carried by the busy-room journey, which has no mutant switch:
  `a_newcomer_who_keeps_posting_is_trusted_back_on_a_slow_path` (by the journey with a delayed
  path) and `a_follower_held_still_through_a_burst_holds_every_post` (by the journey's paused
  member).
- Deleted with nothing to carry them: the two `vox status` scenes of a newcomer still receiving and
  of a stalled author. The sentence "not receiving from connected member …" rests on review; the
  product was seen saying it in the upgrade spike (`test-sweep.md:269-277`).
- `a_reply_follows_what_it_answered_even_from_a_clock_an_hour_behind` (the hour-behind proof): one
  staging wait was added, and no assertion changed: Carol, like Bob, must show the question before
  Bob answers, so every reader already holds the question the answer names. It proves placement on
  a computer that already had the question (PL-26), not one causal order for all members
  (`simple-sync/review/order-1.md:9`). Its mutant, "ignore `seen` in display placement", is a
  hand-made source change in the run tree, not a switch, as on main: RED on the proof's own
  assertion in run `fixorder-4-mutant`; the proof GREEN in run `fixorder-1`
  (`release/gate-sweep/fix-FixOrder.md:19-37`, :43-44, :56-58).
- `a_post_from_a_clock_a_day_ahead_does_not_drag_the_room_a_day_forward` (the day-ahead proof): its
  claim on the member whose own clock is wrong is withdrawn. Bob's assertion that display times
  stay near Alice's correct clock is removed; on both members both posts are delivered and Alice's
  post follows Bob's, and on Alice her post is placed less than 15 minutes ahead of when she wrote
  it (`order-1.md:11`). GREEN in run `testtidy-order` (`release/gate-sweep/fix-TestTidy.md:13`,
  :39-54). No mutant was run for it.
- `three_members_one_offline_for_a_while_show_one_order` (the one-order proof): kept as a
  regression for its own scenario only. Its description no longer says that members converge to
  one order or that it proves PRD-001 R13. A sufficient condition for identical order is that every
  signed time is within every receiving member's first-sight cap and no floor changes a key; this
  fixture aims to satisfy that condition (`order-1.md:13`). Only its comment changed, and it was
  not run after (`fix-TestTidy.md:67-79`).
- `an_abandoned_key_request_is_selected_again`: its staging was corrected. Member B now comes back
  only after A says the key went into the room's log as a key package, the state the act is about;
  on main that state came about only because the deleted scheduler delayed the key by about 20 s.
  GREEN in run `adoptstep4-t3c`. It has no mutant arm, on main either
  (`release/gate-sweep/fix-FixKeyPkg.md:62-71`, :83-94; `simple-sync/review/STATE.md:70`).
- The sealed-Session probe of
  `a_session_is_read_only_by_members_with_drive_and_a_downgrade_changes_its_key`: it asks at the
  position the member itself saved, a record that exists, then at each LiveTail window. Cutting the
  continuity check alone turns the probe's own assertion RED (run `fsb2-m5`); cutting the holder
  check alone leaves it green (runs `fsb2-m2`, `fsb2-m3b`)
  (`release/gate-sweep/fix-FixSessionBusy2.md:74-83`; `simple-sync/review/private-14.md:7-9`).
- `a_node_that_left_rejoins_and_posts_at_once` (the rejoin act): two mutant arms that nothing
  reached were deleted with their product switches. The one kept arm,
  `VOX_MUTANT_FX28=rejoin-before-session-retirement`, is RED on its assertion, and the act GREEN
  (`release/gate-sweep/fix-TestTidy.md:11-12`, :18-37).
- `a_crash_inside_a_join_never_costs_the_member_the_room` (the crash-inside-a-join proof): it kills
  a member's daemon at each kill point inside a join and checks that, once she is back in her room
  and posts, the other member reads her post. On the redesign it was red in 5 of 9 runs before
  PL-36: the restarted host never read her post, and never committed her post's head. The one-step
  admission (PL-31) was not the cause: the act was red without it too (`fix-FixQuantum2.md:9`, :14;
  `exec/found-reds.md:265-266`). The cause was a peer's told record kept per room and peer (PL-36,
  *Why*). After PL-36's first form GREEN in runs `fq5-crash1` and `fq5-crash2`
  (`fix-FixQuantum2.md:84-85`); after its later rounds GREEN in runs `fhl-crash` (twice),
  `fhl2-crash` and `fhl3-crash` (`fix-FixHaveLife.md:31-32`, :84, :123). In its builders' words,
  two green runs do not prove gone a fault seen in 5 of 9: the argument is the cause
  (`fix-FixQuantum2.md:91`; `fix-FixHaveLife.md:39`). No mutant run is recorded for it.
- `a_member_removed_while_its_room_was_closed_is_acted_on_when_it_opens` (the removed-member
  proof): red 2 of 2 on scratch `bf5c9a96e` and red on `774ebd9c2`, "(c) bob trusted alice again,
  yet within 120 s he does not read her posts …: her key never came back"
  (`exec/found-reds.md:271-272`); a race, not a constant (`release/gate-sweep/fix-W2Keys.md:20`).
  After PL-37, GREEN once in each of its three rounds (`fix-W2Keys2.md:39`, :93, :138). One green
  run does not show that the race was lost and recovered (`fix-W2Keys2.md:100`). No mutant run is
  recorded for it.
- `a_returning_reader_eight_thousand_entries_behind_reads_and_pages_back` (the returning-reader
  proof): a member comes back after missing 8,000 posts and must show the newest post before more
  than 256 of the backlog, then show all 8,000 unasked. On the frozen build `e90cc7ace` it was RED:
  "the returning reader shows 265 of the 8000 posts it missed but not the newest"
  (`exec/found-reds.md:286-287`, ledger 127). A bisect found no first red commit among the 42
  since its last green commit: that commit is red today too; the builder infers that the earlier
  greens depended on which ask ran first (`simple-sync/review/fix-FixBack.md:20`, :29). After
  PL-30 item 6 it was still red in 2 of 5 runs (`fix-FixBack.md:5`); after PL-38, on this state,
  GREEN five times in a row (run `fb2-accept`, `back1` to `back5`). The first samples containing
  the newest post showed 44, 55, 72, 1 and 5 posts in total, respectively; all 8,000 were shown
  by samples 94 to 97. Its mutant `VOX_MUTANT_NO_PROMOTION` is RED on its own assertion:
  "the returning reader's shown count stopped at 0 of the 8000 posts it missed over 10 answered
  reads" (`simple-sync/review/fix-FixBack2.md:45-55`; the act's two demands in its own RED and
  GREEN lines, `fix-FixBack.md:68`, `fix-FixBack2.md:49`).

**RG-6 proofs, run:** *(awaiting: the table of `simple-sync/review/test-sweep.md`, section "RG-6
proofs, run", which is being written; no result is claimed here.)*

**The busy-room journey on the reviewed build `18b409efd`, open:** it ran twice. Run 15 GREEN:
every member shown both ways, every post each member is owed (of 4,299 acknowledged) shown on it
after authors stop, at most 56 `--history older` requests by one member
(`simple-sync/pull/journey-15/paused/receipt.log:2049557`, :2049568). Run 16 RED: the newcomer
acknowledged 110 posts since its join and the paused member showed none of them
(`simple-sync/pull/journey-16/paused/receipt.log:451603`). *(Awaiting: the cause is being traced,
`simple-sync/pull/why-j16/report.md`, not written yet; nothing is stated here about it.)*

**The two final busy-room journeys on the build that lands:** *(awaiting: not yet run; no result
is claimed here.)*

**Not proven:**

- the time of the re-index at the first open of a room written by main: measured once, for one
  room of about 1,900 rows on a scratch build, at 16 s for the whole first open; not measured on
  the build that lands or for a large room (`upgrade/report.md:140-147`; `order.md:80`);
- the upgrade's final forms (PL-29 at scratch commit `18b409efd`, after `fd14f0277` was measured):
  to be measured once more on the build that lands (`exec/found-reds.md:218`); a private Session
  through the upgrade was not tried (`upgrade/report.md:173`);
- the cost of the "what I hold" messages, which grow with the square of the members: unmeasured at
  64 members (`exec/deviations.md:218`);
- historical-key recovery, cancellation during an own sender-key release, and correction of an old
  page: not exercised by the journeys (`simple-sync/review/keys.md:42`);
- the security acts for the reader side, M0's among them (PL-14), are not among the runs
  (`measure-pl24.md:5-10`);
- every area is accepted by its reviewer, but the reviews read code only and ran nothing
  (`simple-sync/review/STATE.md:31`); the private review does not certify that every governance
  route that changes membership reaches a producer of permission news (`STATE.md:12`);
- ledger 76 remains: a receiver unaware of a removal can accept a removal-period private step from
  altered software; this transport change does not fix that receiver limitation
  (`simple-sync/review/private.md:54`; `private-3.md:9`);
- a departed nonmember with recovery standing can pass the outer serving gate but cannot obtain
  proof ranges through the existing member-only leaf (`serve.md:74`);
- universal revocation of already-prepared private or own-release output was not established;
  those outputs keep their native physical-send guards (`serve.md:60`);
- an already-authorized frame handed to QUIC can complete after a withdrawal; later writes must
  fail their checks (`private-2.md:9`; `serve-4.md:5`);
- a worker that panics every time remains an acknowledged recovery limitation; the review
  established no concrete path that panics every time (`loop-3.md:7`);
- continuous own posting has strict priority; no bounded fairness for fetching is claimed
  (`delete.md:88`);
- older-history reporting inspects the oldest held post within its bounded scan, not every
  unreadable post inside an author's history (`delete-2.md:11`; `fix-FixSeen.md:21-25`);
- the reviews were scoped source reviews and fix-only increments, not a line-by-line re-proof of
  every deletion or a review of all 140 changed files (`delete.md:69`, :101; `serve.md:81`);
- known and left as on main: a member that dialled while this node's room was still preparing can
  be listed as "refused … as Unknown" for an hour (`STATE.md:43`; `delete-5.md:9`);
- a body the recipient cut refuses can be asked once more after each ordinary Have that offers it
  again; no bound over a connection's life is claimed (`ruling-body-extents.md:24-25`);
- the measurement the second ruling asks for (request overlap, duplicate bodies and bytes, progress
  from need to what is shown, with a stopped holder) is not among the runs
  (`ruling-in-flight.md:17`; `measure-pl24.md:5-10`);
- the loop's patient transport and introduction use a one-year deadline, not an absent one, which
  does not meet the literal "no timer" (`loop.md:75`);
- proof runs in a Have are cut to the newest 256; complete proof availability for highly
  fragmented older history is not established (`loop.md:76`);
- a real body of 1 to 16 MiB (Proof, item 1);
- how fast a room admits under PL-30, and whether a journey succeeds with it: no run has
  established either (`simple-sync/review/loop-8.md:13`); a turn is one entry, not the ruling's
  work budget (`loop-8.md:5`);
- PL-31: accepted from source only; no fault was injected, and the crash-and-reopen states are
  read from the code (`delete-10.md:30`, :55); the per-entry counts are from source, not measured
  (`fix-FixQuantum2.md:52`);
- a failed admission's wait for a real change (PL-17 item 4) is argued from code; no run forces a
  persistent admission failure. A panic in an admission task still holds its room's admission until
  the room is retired. A fault local to one entry now holds the room's other ready entries until
  the next change; that it cannot be reached is not proved (`serve-11.md:11-15`;
  `simple-sync/review/fix-FixSpin.md:93-95`);
- the no-progress rule's cases (PL-23 items 2 and 6) are argued from code: no run drives a need met
  from elsewhere, an empty `Complete`, a repeated opening-only answer, a duplicate body already
  owned by another admission, a correction that only re-splits runs or a full Have cache
  (`keys-9.md:7`; `loop-15.md:11`; `simple-sync/review/fix-FixKeyHeld.md:87`, :105, :149);
- the interval the private holder check protects (PL-28 item 10), after a Drive downgrade and
  before the rekey, is not staged by the probe; the probe asks only at positions its members saved
  and at the fixed windows (`private-14.md:9`; `fix-FixSessionBusy2.md:85`);
- a restart in the middle of a publication keeps the display floor's choice by source reasoning
  only, not by a restart run; a candidate rolled back before it was published, and published again
  later, can get another key, though it was never shown (`order-1.md:7`);
- no run showed a member waiting on a busy publication to answer a join or adopt its Session, or
  answering `Busy` on that path (PL-32); its words are quoted from the code
  (`fix-FixJoinBehind.md:85`, :120, :146, :173);
- that the 3,600-odd governance sweeps of a fenced returning member are gone (PL-33) is not shown
  (`keys-7.md:11`);
- PL-36 is argued from code: no run stages an older connection promoted again, a closed
  connection leaving nothing behind, or a connection closed for passing the allowance, and the
  words that connection's peer sees were read from the code, not observed; the allowance's walk
  over every record on each charge was not measured on a node with many rooms
  (`fix-FixHaveLife.md:39-40`, :90-92, :127-128);
- PL-37 is argued from code: no run shows an already-held Drive key arriving with a debt and that
  debt then delivered, a refused first pass followed by the tick's delivery, or a trust
  withdrawal after a debt was written (`keys-15.md:7`; `release/gate-sweep/fix-W2Keys2.md:99`,
  :144);
- PL-38's item 2 (the drain stops on a deferred row) rests on one red trace: the spinning drain
  was seen once, and that the change removes it rests on the code and that trace, not on a
  reproduced red. Its item 1's cause was not reproduced either; five greens in a row make a repeat
  unlikely, not impossible (`fix-FixBack2.md:66-67`);
- the wait of PL-38 item 3 was never seen engaging in an acceptance run (`fix-FixBack2.md:68`;
  `keys-17.md:15`);
- how often a reply lands above its question during a catch-up, now that an author's newest posts
  are admitted first (PL-30 item 6), is not measured (`loop-20.md:9`).

## Amendment 4 (2026-11-28): a recovered store reconnects, and a retired key body releases its root

*(Added 2026-11-28, amendment 4; amendment 2 is the unlanded draft named under Status.)* Merged in
pull request #1424 (branch `fix/sweep6`, one squashed commit `08ec7b2aa` on main `695db44c4`),
merge commit `516c08746a16fd9da141672c100a8e31f52e08fa` on main, whose tree is that of
`scratch/sweep6-land` at `8761dd46f`. This section was checked for fidelity against the code and
the records (`design/forward-only/adr-sweep6-check-1.md`). Sources, in `/opt/vox-evidence/v0431/`:
`exec/found-reds.md` entries 156 and 160 (every row of each); under `release/regress6/`:
`DiskFull.md` (rounds 2 to 4, and its last section, "Coordinator's ruling on how the peer's park
ends"), `DiskFull-review-1.md`, `LateJoin.md` (with "Review fix"), `LateJoin-review-1.md` (both
rounds) and `pr-body.md`; `simple-sync/review/STATE.md` (passes 7 to 7d, jrnS2) and the pass logs
in `release/gate-sweep/pass7*/logs/`. Code is cited by file and function at main `516c08746`,
under `crates/vox-core/src/node/`. Run labels are directories under `simple-sync/pull/runs/`.
Nothing was built or run for this record.

### (a) What was found

1. **After a full disk was freed, a room could stay unsynced between two members for good**
   (found-reds 156, second part; `DiskFull.md`, rounds 2 and 4). With the naming fix of ADR-034
   amendment 1 in, the act `a_full_disk_recovers_without_stranding_sync_or_leave`
   (`a_sync_failure_names_its_reason_proof.rs`) went on and was red 3 of 3 (jnd5, jnd6, jnd7):
   "Bob reported recovery but received none of 100 further posts". The mechanism, from the
   diagnostic runs r4d1 (green) and r4d2 (red): while bob's disk was full, bob answered alice's
   sync stream for the room with `SyncModeUnsupported`, because the room check returned the
   poisoned room's save failure (`actor.rs`, the inbound sync admission: `uses_sparse_history`
   not `Ok(true)` gives `refuse_stream_because(…, SyncModeUnsupported)`). Alice's loop counted
   that as a refusal and parked (PL-23). Once bob recovered, his node dropped the room's old
   ports, made new ones and started a fresh loop, which told its Have 2 ms later (r4d2); but that
   page was the one alice already held (`news=false`), and by PL-23 item 6 a page told again
   unchanged is not news. So alice stayed parked and told bob none of her posts, and bob, holding
   what he took alice to hold, had nothing to ask. Whether it happened depended on whether bob's
   holdings changed after the refusal (r4d1 green, r4d2 red): timing. The inference of round 3,
   that recovery left bob's ports stranded, was wrong (round 4 §1).
2. **When it came in**: with `7257301f9` (#1411, the one loop), which added the park until news;
   before it the old asking machinery asked again on later events, so a refusal cost one round.
   The last green, sweep pass 4 on `9520dc0a9`, ran without that commit (`DiskFull.md`, round 4
   §4). `7257301f9` is in no published release (`git tag --contains`).
3. **A newcomer with a short retention could wait behind one expired key package until a
   restart** (found-reds 160; `LateJoin.md` §1). In run klq the late member of ADR-055's renamed
   interrupted-history act took nothing for nine minutes from the two members it was connected to
   (verified 5 of 141 and 3 of 9), and its daemon said "not receiving from connected member …
   (125 missing now)". The mechanism, from the diagnostic runs lj0 and lje: late asked for a key
   package addressed to another member and got its header, then asked for its body, to carry it on
   to its recipient (ADR-046). The body's refill found the package already expired under late's
   1 s retention (`channel/pending_received.rs`, `HistoryEffectProgress::KeyBodyRetired`). The
   loop mapped that need like a staged body (`history_stream/runtime.rs`), so the root was settled
   with a need for its own position and kept; the kept control stayed held unadmitted in the
   frontier, and every later post of that author waited on its position (PL-30 item 3); nothing
   was asked. Only a restart, which empties the in-memory frontier, ended it: copies of the klq
   stores, restarted, took all 125 entries at once. On main since `7257301f9`.

### (b) The rules

- **PL-41. After a room's store recovery succeeds, the node closes and redials its connections
  to that room's peers.** *(Added 2026-11-28, amendment 4; the coordinating session's ruling,
  option B, found-reds 156.)*
  1. A peer parked on a refusal this node gave while its store had failed waits for news
     (PL-23), and an unchanged Have is not news (item 6); a new connection is (items 1 and 6). So
     `finish_metadata_open_reply` (`actor/metadata_save.rs`), when a room's store recovery is
     done, calls `Node::replace_connections_after_recovery` (`actor/recovery.rs`): for each
     connected peer that has a live connection and shares the room (`shares_room`), it closes that
     connection with the existing code `WireError::Superseded`, then dials the closed peers again
     through `dial_stranded`, the path a network change's stranded peers take (the ordinary
     ladder; for a member, `reach_member`). No rule of PL-23 changes.
  2. Bounds (`DiskFull.md`, round 4 §2): only after a successful recovery (a failed one, or an
     ordinary open, never reaches it); only peers that share that room; a closed connection is no
     longer held, so rooms recovering together replace it once (r4d3: the second and third rooms
     found no peer to replace), except that a room recovering after the redial has landed replaces
     the new connection once more (jnd8: two reaches 215 ms apart). No new dial logic, timer or
     poll. No loop: a recovery starts only for a room poisoned by a failed write, and a reconnect
     poisons nothing. Loops start only behind the same standing rule as before. No wire change.
  3. Why not the other two options. The coordinating session's ruling of 2026-11-27, written at
     the end of `DiskFull.md` ("Coordinator's ruling on how the peer's park ends"), lists the
     options the builder put: "(A) the recovering node stops refusing a loop's exchange while its
     room is poisoned and serves from committed state (narrows the window, does not close it:
     in-flight answers retired by the recovery still park the peer on "transport failed"); (B)
     after its room recovers the node replaces its connection to each peer of that room (a new
     connection is news under ADR-054 PL-23; closes the window; every room on that connection
     restarts); (C) a rule change so any Have arriving while parked on a refusal counts as news
     (breaks PL-23 item 6)". Ruling: "**B**: it closes the window under the rules as they stand,
     needs no ADR rule change and no new wire value, and a store recovery is rare; A does not
     close it and serves from a store whose handle has just failed; C changes the park rule and
     would need its own security review". This amendment records the behaviour; it changes no
     earlier rule.
  4. The cost. Every room's loop with that peer starts again on the new connection, each with a
     fresh Have, and the peer is without a connection for one reach: about 60 ms from the close to
     the new loops in r4d3, and reaches that answered in 87 and 67 ms in jnd8; over a relay, as
     long as an ordinary circuit reach. Meanwhile `vox status` does not list the peer (the
     builder's [INFERENCE]: the list is of live connections). Neither daemon names the close, and
     `Superseded`'s documentation says "a duplicate connection … the peer is still connected over
     the other", while here the other is dialled after the close (`DiskFull.md`, round 4, "Not
     changed, for the notes").
  5. Named, not fixed: a false "sync mode unsupported". While a room's store has failed, the node
     still answers a peer's sync for that room with `SyncModeUnsupported` (item (a) 1), so the
     peer's `vox status` shows, on each room they share, "last failure: the peer refused: sync mode
     unsupported". It was captured in r4d2, without the fix, after the freeing ("room … peer
     <bob>: completed 15 empty 11 partial 0 failed 1; …; last failure: the peer refused: sync mode
     unsupported"); the act never reads alice's status inside the full-disk window, so the line
     there is inferred from the same counters. The sentence is false: the peer supports the mode,
     its store had failed. By the code it clears at the first exchange on the new connection that
     ends without error (`PortCounters::last_failure_stands`, `status.rs`), and `failed 1` stays
     counted; no status was captured after the fix to show it gone (the builder's [INFERENCE]).
     The release notes are to say so (`pr-body.md`, "Named, not fixed").
- **PL-42. A refill that finds its key body already retired settles its root, and the body's debt
  is retired where its expiry is established.** *(Added 2026-11-28, amendment 4; found-reds 160.)*
  1. The root: when a key-package body's refill comes back retired (its debt met or retired, or
     the package expired here: `LocalNeed::KeyBodyRetired`), the flow clears its tasks and
     settles the root with no need (`Flow`, `history_stream/runtime.rs`): the root leaves the
     frontier, and through `refresh` and `unblock` (`history_stream/pull.rs`) the posts its held
     control position blocked run again, as PL-30 item 3 provides for a control that "leaves the
     frontier unpublished". Its header was already admitted, so nothing more is owed for it
     (`LateJoin.md` §2). The reviewer: "The root-release operation itself is sound: the refill
     requires the already-published exact header and validates the body first; it grants no new
     admission authority" (`LateJoin-review-1.md`).
  2. The debt. With item 1 alone, the review found (P2): "The expiry producer returns
     `KeyBodyRetired` before committing …, so the durable KeyBody obligation remains. This new
     branch removes its frontier exclusion, making the same body immediately selectable again.
     Planner class 2b prioritizes that debt over ordinary history; successful body answers impose
     no retry delay. The observed 458 asks are therefore a real retry storm, not a bounded attempt
     count." (The builder had called those 458 asks in lje "bounded, but … extra work",
     `LateJoin.md` §2.) So the refill's expiry branch (`channel/pending_received.rs`, the refill of
     a key package whose body is owed) now drops its received batch and, in a fresh derived batch
     committed alone, retires the exact KeyBody obligation built from the refill's checked need
     (head, author, position, hash) with `finish_history_obligation`, the operation the retention
     sweep's KeyDebt step uses, before it returns `KeyBodyRetired` (`LateJoin.md`, "Review fix").
     A body that has not expired is never retired there; a crash leaves what the sweep would
     have left, and the retire does nothing if the debt is already gone. The expiry it acts on is
     this node's own retention, as PL-3 requires of a discharge of expired debt. The reviewer:
     "The expiry-only branch commits retirement of the exact checked KeyBody obligation using the
     sweep's operation before returning `KeyBodyRetired`. It touches the position, releases the
     root, and leaves no route that recreates that admitted entry's debt" (`LateJoin-review-1.md`,
     fix-only).
  3. Removed with the act's re-staging (ADR-055 amendment 2 (f), part 3), by the coordinating
     session's ruling, accepted by the owner on 2026-11-28 (`proof_changes_2 = accept`, ADR-055
     amendment 2 (e bis)): the act's expired-body refill sub-claim and its knobs, which waited for
     an expired Content body to be fetched. Since `7257301f9` an expired Content position completes
     without its body being fetched (`completed`, `channel/held_history.rs`: "the body is not
     needed, or its lifetime is over", applied to Content entries; `LateJoin.md` §3). A
     key-package body still owed can still be fetched and found expired at its checked refill,
     which is the case of items 1 and 2.

### (c) What a person sees

- After disk space is freed, a member's rooms sync again with every member; "recovered" is no
  longer followed by silence from one member in one room.
- While a member's disk is full, the others' `vox status` says "the peer refused: sync mode
  unsupported" on the rooms they share, which is false (PL-41 item 5).
- A newcomer with a short retention no longer stays "not receiving from connected member …"
  behind an expired key package until a restart.

### (d) What it costs

1. A store recovery restarts every room's loop with each peer that shares the recovered room,
   and the peer is unconnected for one reach (PL-41 item 4).
2. One extra small commit when a refill meets an expired key body (PL-42 item 2).

### (e) Proof

- **PL-41**, `a_full_disk_recovers_without_stranding_sync_or_leave`: red 3 of 3 without it (jnd5
  to jnd7); with it, green three times in a row (jnd8, jnd9, jnda: 23.59 s, 24.85 s, 25.32 s),
  and green with the diagnostics in r4d3. Also green on that tree: the crash-inside-a-join act
  (jndb) and the restored-backup act (jndc, which did not reach the new path: "can save again"
  0 times). With the later forms of the naming fix the act stayed green (jndd, jnde, jndf, jndh)
  and so did the crash-inside-a-join act (jndg). The test file only gains log keeping (listed in
  `pr-body.md` as a re-staging). No mutant arm for PL-41 is recorded; the reds without the fix
  are the runs without it.
- **PL-42**: in lje (diagnostics, item 1 only) the path was hit ("key body refill retired; root
  settled"), alice's live window was admitted and no "not receiving" was said; the builder reports
  that the same body was asked 458 times there before the sweep retired its debt (`LateJoin.md`
  §2), and the source reviewer calls that a retry storm. With item 2, lt2 (a diagnostic run with
  lje's staging put back for it): one ask of `Body { seq: 9 }`, then "expired key body debt
  retired … 9" once and "key body refill retired; root settled" once, and no "not receiving"; lt2
  then went red at the act's `shows_not_received_yet` step, which that staging cannot pass
  (`LateJoin.md` §3). lt1, the act as shipped: ok (208.88 s), the path not hit. Before item 2 the
  renamed act went green to its end twice (lj3, lj4). No mutant arm is recorded.
- **On the integrated tree** (`simple-sync/review/STATE.md`; the pass logs): the full-disk file,
  2 tests, both executed, green in pass 7 (on `e396fd1ee`) and in pass 7c (`43a3ab3cc`). The
  gate's file runs are built without `optional-proofs`, so an optional act prints `OPTIONAL PROOF
  NOT RUN` and counts as passed: the newcomer file's 15 harness successes in passes 7 and 7d
  (`b10f075e8`) are six executed tests and nine such notices, and the renamed act that carries the
  late member is one of the nine; it did not run in these file runs. It was last run alone in lt1
  (on `scratch/late-join` with item 2) and in fh1 and fw2 to fw8 (on `149a3bd0e` with the unlanded
  first-read fix of ADR-055 amendment 2), not on the merged tree; further runs on the release
  commit are to be recorded in `/opt/vox-evidence/v0431/rg-6/close/closing-runs.md`. The busy-room
  journey jrnS2 on `b10f075e8`: "GREEN: … every post each member is owed (of 3668 acknowledged)
  shown on it after authors stop" (`release/regress6/jrnS2/paused/receipt.log`). `8761dd46f`
  differs from `b10f075e8` by a lint-only change.
- **What rests on review**: PL-41's bounds (one replacement per connection, no loop); PL-42 item
  2's crash behaviour.

### (f) Reviews

Source review only. `DiskFull-review-1.md` (RevJoinLand) at `ccdae31fe`: "No additional reconnect
defect established: replacement is success-only, filtered by recovered-room membership, and uses
the existing close/reach paths"; its finding P2 and its later rounds concern the naming (ADR-034
amendment 1), and its third and fourth rounds did not re-review the reconnect.
`LateJoin-review-1.md` (RevJoinLand) at `33e3f9533`: the P2 of PL-42 item 2; "The removed hooks
are test-knob-only; the server helper's production branch was always `None`. No other live
behavior removal found." Its fix-only round (RevStore) at `661b38c4f`: **ACCEPT**, quoted in PL-42
item 2; "Crash consistency matches the existing derived sweep transaction: recovery may retain or
roll back retirement, allowing a safe retry rather than stranding the root. No introduced defect
found."

### (g) Built

In pull request #1424 (merge commit `516c08746`, tree of `8761dd46f`): PL-41 as `ccdae31fe`
(`scratch/disk-full`: `actor/recovery.rs`, +28 lines; one call in `actor/metadata_save.rs`; the
act's log keeping), merged into the integration branch at `d2c4b3795`; PL-42 as `33e3f9533` and
`661b38c4f` (`scratch/late-join`), merged at `483dfaf4b` and `3418305f7`. The builders report both
workspace checks clean (`DiskFull.md`, round 4 §5; `LateJoin.md`, "Review fix"); lint is clean on
`8761dd46f`, as the pull-request text reports.

### Landed

- Merge commit `516c08746` of #1424 on main.

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

*(Amended 2026-11-25, amendment 3:)* These counts are for the first slice, which the adoption
replaced. The builders' increments in the scratch tree, from each step's diff: steps 1 and 3,
+1,326 −521 lines (`step1-3.md:3`); step 4, +582 −2,686 (`step4.md:24`); step 6, +1,335 −2,204
(`step6.md:33`); step 7, +972 −27,006, of which product files +689 −16,277 and tests +283
−10,729, plus two new files of 1,440 and 149 lines that diff does not count (`step7.md:189-190`).
They are increments of an unmerged tree, not the diff that lands; PL-13 is read from that diff.

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
- *(Amended 2026-11-25, amendment 3:)* What is measured on the built tree, and what is not proven,
  is under Amendment 3 (g). By ruling 6, an act stays only if its verdict is what a person sees;
  each adoption step names one observation on the release binary, through what a person sees or a
  command answers (`design/adopt/ruling.md:81`). Item 6, duplicates, measured before the in-flight
  preference: a newcomer received each body 3.47 times in run r12 and 2.75 times in r17
  (design.md:162, :172).

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
- *(Added 2026-11-25, amendment 3.)* What the built tree has not proven is listed under Amendment 3
  (g).
- *(Amended 2026-11-25, amendment 3:)* A join that reaches a member while its room's publication is
  busy now waits, within the admission's patience, and is then answered (PL-32). Whether that
  covers every state of "governance is idle" above is not said by the sources.
- *(Added 2026-11-26, amendment 3.)* **Joining a room with hundreds of trust entries is slow, on
  main and on the redesign.** The proof `a_room_with_hundreds_of_consents_is_joined_promptly`
  measures the work from the join that got in to the first read. Against the proof's 4 s work
  bound, main `47bac534c` took 71.8 s in a room of 297 consents and revocations; a redesign build
  with the one-step admission (`ee9e41a36`) took 39.3 s in a room of 291. Each control entry costs
  about 0.13 s to accept. It is an existing fault that the redesign halves, not a regression. The
  admission-order ruling allows several entries per save only if the same user journeys after its
  changes still demonstrate an admission deficit, and then by a separately measured decision
  (Amendment 1, section 3); that is not built (`exec/found-reds.md:277-278`;
  `design/adopt/ruling-admission-order.md:79`; `simple-sync/pull/runs/gov-main/gov.log:105`;
  `release/gate-sweep/wave3/W3OthersA/a_room_with_hundreds_of_consents_is_joined_promptly-fix.log:91`).

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
  *(Amended 2026-11-25, amendment 3:)* Amendment 3 replaces this connection-lifetime promise for
  body availability: a denied body is not asked again until an ordinary Have positively advertises
  it again. The bound is per positive re-advertisement, not per connection (PL-20 item 2;
  `design/adopt/ruling-body-extents.md:24-25`).
- **MP-9's *Why* (:490-496)**, which names the hint queue (`history_stream/hints.rs:367-392`) and
  the inventory that pages every author's committed head: under this ADR, signed heads and
  unresolved unequal observations are to travel in the Have (PL-2), and the inventory paging is to
  be deleted (PL-11). MP-9's rule stands. Whether its `forks` list (*Transport*, :481-489) rides on
  this ADR's Have is not decided.
- **MP-8a's head choice H (:448)** is not addressed by this record's sources: not decided.
- **ADR-053's Order** assumed the fetching machinery of today, with the parked candidate's
  disposition in step 4; that machinery is replaced by this ADR. MP-7's prefix serving P stays: the
  experiment served through it unchanged (experiment.md:26).
- *(Added 2026-11-25, amendment 3.)* **MP-5** (ADR-053 on main `8490105c6`, :299-311), its
  normative paragraph, *Why* and *Proof*: amended by the display-order ruling's follow-up
  (`design/adopt/ruling-order.md:17-27`), as the second display-order ruling corrects that
  follow-up (`design/adopt/ruling-order-2.md:39`). A shown row is placed by its display key, fixed
  once at its first publication; `seen` lifts it only through a named entry already held and
  published here at that moment, and no later arrival moves it (PL-26). `seen` stays as nonblocking
  references outside ordinary Content authority, and still feeds the separate causal clock. The
  universal skewed-clock "question before reply" proof is withdrawn and narrowed: on a computer
  that already had the named question when the answer arrived, the answer is placed after it; the
  "ignore `seen` in display placement" mutant returns for that proof only. One identical or causal
  order for every member stays withdrawn. ADR-053 carries the amending note at MP-5.

## Not decided

Where the sources are silent, this record says so: each act's mutant; how duplicates are measured
and what is too much (Proof); when the producers kept in PL-12 migrate; ledger 93 and 94, and the
join answered only when governance is idle (Risks); rules 3.4 and 3.5 of the parked candidate,
MP-9's `forks` list on the Have, and MP-8a's H (supersedes); whether a node answers a peer during
its roster admission other than as today, since design.md:10 went with the superseded Hello.

*(Amended 2026-11-25, amendment 3:)* No longer open: when the producers kept in PL-12 migrate (all,
in v0.4.31: PL-24); how duplicates are measured (measured in run r12, design.md:162; what figure is
too much stays open); each act's mutant (one per kept act, or none, as Amendment 3 (g) lists). Also
not decided: whether `prior_heads`, a link between two particular heads that nothing reads, is
still to be written (`per-head-audit.md:356`).

*(Amended 2026-11-26, amendment 3:)* Not decided: whether the slow join of a room with hundreds of
trust entries (Risks) is fixed in this release, by the ruling's several entries per save or
otherwise, or named as open; the ledger puts it to the owner (`exec/found-reds.md:278`).

## Links

- ADR-018, ADR-052, ADR-053.
- In `/opt/vox-evidence/v0431/`: `exec/deviations.md` (2026-11-24); `design/simple-sync/design.md`,
  `ruling.md`, `experiment.md`, `opus.md` (the first design, as corrected), `sol.md`;
  `mp/sync-stack/what-the-room-needed.md`; `mp/land/plan.md`; `exec/found-reds.md` (ledger 91, 93,
  94); `found-reds/backoff-news/report.md`.
- *(Added 2026-11-25, amendment 3.)* PRD-001 (R13), ADR-023 (RL-1.2), ADR-053 (MP-5, MP-12). In
  `/opt/vox-evidence/v0431/`: `exec/deviations.md` (2026-11-24, afternoon and evening);
  `design/simple-sync/design.md` (Amendments 2 to 4), `ruling-in-flight.md`;
  `design/adopt/ruling.md`, `per-head-audit.md`, `ruling-order.md`, `ruling-body-extents.md`,
  `ruling-private-tip.md`, `restore-experiment/report.md`; `simple-sync/pull/on-main/` (step
  records, `older.md`, `order.md`, `per-head-a.md`, `per-head-b.md`, `measure-pl24.md`);
  `simple-sync/review/` (`STATE.md`, every verdict file it lists, the builders' `fix-*.md`,
  `test-sweep.md`); `simple-sync/upgrade/report.md`, `why-upgrade.md`;
  `simple-sync/pull-m0/report.md`; `exec/found-reds.md` (ledger 100 to 102);
  `simple-sync/pull/journey-15/`, `journey-16/`.
- *(Added 2026-11-25, amendment 3.)* In `/opt/vox-evidence/v0431/`:
  `design/adopt/ruling-admission-order.md` (with "Amendment 1 (after measurement)"),
  `design/adopt/ruling-order-2.md`; the builders' records in `release/gate-sweep/`
  (`fix-FixRoster.md`, `fix-FixReadAfter.md`, `fix-FixOrderAnchor.md`, `fix-FixOrder.md`,
  `fix-FixJoinBehind.md`, `fix-FixReturn.md`, `fix-FixFork.md`, `fix-FixKeyPkg.md`,
  `fix-FixSessionRead.md`, `fix-FixSessionBusy.md`, `fix-FixSessionBusy2.md`, `fix-TestTidy.md`)
  and in `simple-sync/review/` (`fix-FixAdmit.md`, `fix-FixSpin.md`, `fix-FixKeyHeld.md`,
  `fix-FixLock.md`, `fix-FixQuantum.md`, `fix-FixQuantum2.md`); the verdicts
  `simple-sync/review/loop-8.md` to `loop-15.md`, `serve-8.md` to `serve-16.md`, `keys-4.md` to
  `keys-9.md`, `private-9.md` to `private-14.md`, `delete-9.md` and `order-1.md`.
- *(Added 2026-11-26, amendment 3.)* In `/opt/vox-evidence/v0431/`: `simple-sync/review/`
  `fix-FixHaveLife.md`, `loop-16.md` to `loop-19.md`, `delete-10.md`, `keys-12.md` to
  `keys-15.md`; `release/gate-sweep/fix-W2Keys.md`, `fix-W2Keys2.md`; `exec/found-reds.md` (ledger
  120, 122, 124).
- *(Added 2026-11-26, amendment 3.)* In `/opt/vox-evidence/v0431/`: `simple-sync/review/`
  `fix-FixBack.md`, `fix-FixBack2.md`, `loop-20.md`, `delete-17.md`, `keys-17.md`;
  `exec/found-reds.md` (ledger 127).
- *(Added 2026-11-28, amendment 4.)* In `/opt/vox-evidence/v0431/`: `release/regress6/`
  `DiskFull.md`, `DiskFull-review-1.md`, `LateJoin.md`, `LateJoin-review-1.md`, `pr-body.md`;
  `exec/found-reds.md` (ledger 156, 160). Branches `scratch/disk-full`
  (`/opt/vox-worktrees/slow-join-land`) and `scratch/sweep6-land` (`/opt/vox-worktrees/sweep6-land`).
