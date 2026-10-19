# ADR-037: A Joined Room Converges Without Waiting

- **Status**: Proposed for v0.4.6. The decider ruled (2026-10-18/19): "Ready is a constant
  wait"; "stories #952–#958 are essential to v0.4.6"; "the correct long-term solve, no
  band-aids"; "Security outranks speed: the cryptography must be provably correct." R1–R6 are
  the v0.4.6 release line and are not built: each is to land with its proof (R6). R7–R13 are the
  measured pacing requirements that keep the background work bounded; the fixes for R8–R11 are
  on PR #946's branch and unreleased. No release acceptance is claimed.
- **Date**: 2026-10-19
- **Deciders**: Robert E. Lee
- **Tags**: sync, convergence, governance, settlement, sessions, drive keys, timing
- **Related**: ADR-007, ADR-018, ADR-026, ADR-029, ADR-031, ADR-036

## Context

A joined room becomes usable through a chain of gates: the fold settles the room's governance,
the sparse settlement acknowledges the joiner's own feed, the Session activity appends and opens
the Session, the drive key releases and installs, and the private pull projects the mirrored
work. Every gate in this chain is also a product claim: the proofs bound each stage.

The v0.4.6 validation exposed a family of timing defects. None produced a wrong answer; every
answer eventually arrived. But arrival was paced by periodics, by backoff curves borrowed from
unlike failures, and by single events a quiet room never gets, so a joined room sat silently
unusable, refusing Session openings, drive-key release and private pulls, each gated on a
settlement nothing was driving. Measured link by link on #934 with rate-limited per-conjunct
diagnostics (deleted from the tree; the measurements are on that issue):

- Entries converge after a join; the fold then settles 13–20 s after the last entries.
- A nine-entry control-lane walk took ~33 s: ~1 round per second, one task per round.
- The sparse settlement waited on the joiner's own live-window acknowledgement, whose fetch
  nothing drove: the 30 s periodic was the only event that ever fetched a node's own head back.
- The Session opening costs 1–5 s, the drive-key release 1–16 s, the private pull 1–10 s.
- A green chain totals 27–47 s against a 60 s claim; one late entry or one missed re-arm pushes
  the same room past the bound. The reds measured 60–75 s.

Post-#945 main (24f9af7fa) couples every first use of a room to room-global convergence state:
the Claude Session proof runs 6/7 red at 144 s there, and 6/7 red at 99 s with the pacing fixes
on PR #946's branch. v0.4.5 (tagged 2026-10-15) is the near-instant baseline. The regression is
the first-use coupling, not the pacing.

The decider's answer is that Ready means the nodes can communicate from that point forward, at
the same wait whether the room is fresh or carrying an unsynced backlog; history rehydrates from
local cache and older messages are fetched on demand, and none of that is part of Ready.

A superseded draft of this decision (985ce881b, never merged) answered with a parallel
control-only fold and made the fold "the arbiter, never the gate". That draft left the
irreversible egresses reachable while a received revocation sat unfolded, and let a page whose
fold lagged read as final. This revision replaces it: there is one governance fold per room, it
remains the gate for everything irreversible, it is made fast and content never holds it, and
everything that is not irreversible answers from what the node already knows.

## Requirements

### R1. Ready is a constant wait

From Ready, a node MUST post, read, append Session activity, list Sessions and answer attention
and net queries at the same wait whether the room is fresh or carrying an unsynced backlog.
History MUST rehydrate from the node's local cache; older messages MUST be fetched on demand
(`vox room read --history`). Neither is part of Ready.

No first-use operation MUST refuse on room-global convergence state ("room governance is
refreshing", "the room is refreshing saved Sessions", "joined and has not yet synced"). The
exceptions are the irreversible egresses of R3, which wait on the fold being current, and a
sparse room's first write, which waits on the room's own settlement (R5). Both are one bounded
governance turn away (R2), never a peer round trip.

A node MUST NOT download prior messages on its own. Earlier messages come through
`vox room read --history older --before X`, one bounded page per ask (at most 64 rows, 1 MiB),
served newest-first so a page cut short leaves a contiguous top and a missing bottom, never a
hole; the selector counts a row held only once it is rendered. An ask for a row the page in
flight already covers joins that page (it is answered with the page's status) and does not
restart it. The decider, 2026-10-19: downloading all prior messages "should not be
wired and is not necessarily expected that an agent would choose to do". The live window still
fetches each author's newest 128 bodies on join; that is the one known deviation from this rule,
and making the window fetch bodies only from the join on is the next change (see Consequences).

A room's preparation on open MUST wait only on work this node finishes alone: its governance
fold, the restore of its indexes, its legacy imports. Anything that needs a peer (an author's
control receipt, a pending private pull, a member's prekeys) MUST wait after publication, where
R4 answers it per author. A preparation step that waits MUST be retried at a pace, not spun.
Measured on the candidate: a reopened sparse room waited in preparation for a control receipt
only a sync could bring, and sync runs only for published rooms; it stayed "preparing history"
at full CPU for as long as the daemon ran, its control socket unanswered.

### R2. The fold is the gate, and it is fast

There is one governance fold per room. It remains the gate for everything irreversible. What
changes is its cost, and what may hold it.

- a. A governance turn MUST run the ordering and evaluation machines to completion under a
  bounded work budget, not one phase step per turn.
- b. The fold MUST be driven by the arrival of a control entry: the accept path marks
  governance work pending at once. The maintenance rotation is the backstop and MUST NOT be the
  only driver.
- c. In signed-format (sparse) rooms, content rows MUST NOT raise the fold's barrier and MUST
  NOT be a settlement precondition: control rows have their own settlement queue and are worked
  first; content rows are background frontier work. Legacy rooms are unchanged.
- d. Measured, then decided: once (a)–(c) are in, the fold's turn is measured on the late-join
  case. If content-body fetches still hold it, the source scan MUST classify rows by signed
  header and fetch bodies only for control rows.

### R3. The irreversible egresses are structurally gated

The irreversible egresses are three: the Session append's encryption audience (and the
drive-generation choice inside it), the drive-key release (`drive_skdm_for`) and the consent key
release. Each MUST wait on the fold being current, and the wait MUST be structural, not a check
a call site can forget: `require_governance_ready(...) -> Result<GovernanceCurrent>` is the only
constructor of the zero-size `Copy` proof token `GovernanceCurrent`, and each egress function
takes `GovernanceCurrent` by value. No call site can reach an irreversible egress without the
fold's proof.

Live delivery while the fold is behind the receipt frontier MUST be marked provisional, never
presented as final: `HistoryPage`, `MessagePage` and the RoomPage IPC frame carry
`provisional: bool`, true when the room's fold was not current at read time, and `vox room read`
MUST print, before the rows,
`note: this room is still folding its control entries; this page is provisional`.

The legacy-recovery gate (`require_legacy_current`) MUST stay on every opened path, including
`private_page` serving saved Session bodies: a legacy-required or legacy-provisional room's
operator-paused suffix is never folded, so no fold time ever comes to arbitrate it.

An append that finds the fold one turn behind MUST take that turn (R2) and proceed, not refuse:
a harness sends its activity once. Measured: a fold released from a hold stayed behind until the
one-second tick, and the harness's next append was refused meanwhile.

Where the constant wait (R1) and a gate in this requirement tension, the gate wins: security
outranks speed.

### R4. Reads, listings, attention and net queries answer from what is known

The session-projection family (files, activity, session queries) MUST answer the locally applied
data. The room-global "the room is refreshing saved Sessions; retry" refusals
(`needs_session_upgrade`, `current_session_controls_ready` and `private_expiry_ready` used as
gates, and the `read.header.ready` and `activity.ready` refusals) MUST NOT gate a read.

A per-author gap (an author whose control effects are not current, per
`current_session_control_ready(author)`) MUST be reported per author in the reply. The author
MUST NOT be dropped from the page (ADR-036 H-1 forbids a room looking emptier than it is), and
the room MUST NOT be refused. `private_expired` MUST apply per row, as `files.rs:46` already
does. `drive_from` MUST answer the authors it can and name the refreshing ones.

The two NetEvent handlers (`SessionActivity`, `SessionProjection`) MUST NOT call
`require_governance_ready` before answering; `advance_sessions` still runs its bounded step. The
attention/delivery path MUST NOT wait on the saved-Sessions refresh.

This requirement is security-neutral: every answer it unblocks is locally held plaintext the
node already decrypted under the checks that admitted it.

### R5. Own-authored state is the author's durable fact

A node's own sequence and own drive generation in a room MUST come from its local store. A
sparse room settles from the node's own record on its first governance turn after the join;
`RoomNotSynced` can fire only in that window and never waits on a peer. Settlement
(`settle_sparse`) still precedes the node's first write, because it rotates the node's sender
key past any generation shared during the join; what it no longer does is wait for a peer to
acknowledge the own head.

The acknowledgement check becomes a background conflict detector. A peer's higher own head, or
an observed own conflict, MUST mark the room "own history behind", and every write in that room
MUST then refuse with `Error::OwnHistoryBehind` / `Fault::OwnHistoryBehind`:

> this node's record of its own history in this room is behind what a member holds, as after
> restoring an older backup; it writes nothing here until that is resolved

The daemon MUST say so once as a NodeNote.

The drive generation is still never chosen off an unknown own feed: it MUST be chosen off the
local own feed, which is authoritative.

### R6. Proofs

Every claim above MUST have a proof that drives the shipped `vox` binary as a person would
(ADR-018), and every proof MUST have a mutant that turns it red on its own assertion:

- the same asserted bound for communication in a fresh room and in a room carrying an unsynced
  backlog; the late-join case becomes a first-class asserted case in an existing journey proof;
- "call prior messages on demand", asserted through `vox room read --history`;
- the egress-gate attacker proofs: a test-side attacker stages a cached-but-unfolded revocation
  or rotation, and the removed member MUST NOT decrypt content authored after the revocation was
  locally available; the mutant is the gate removed;
- the provisional marker (R3);
- the own-history-behind stop (R5).

No diagnostics land in released commits.

One test knob serves these proofs, compiled only with the cargo feature `test-knobs`:
`VOX_TEST_FOLD_HOLD_FILE=<path>`. While that file exists, no room's governance fold advances
(the turn returns without progress). A proof creates the file to stage "cached-but-unfolded",
drives the egress, asserts the refusal or the provisional marker, removes the file and asserts
recovery. The packaged release artifact MUST hold no knob.

### R7. Every background gate is event-driven

Each convergence gate MUST be re-armed by an event its own completion produces, or by the event
that produces its missing piece. A periodic MAY run as a backstop; it MUST NOT be the only
driver of a gate. A quiet room, with no traffic and no commands, MUST still converge through
its gates.

An own append the peer has not been told of MUST be a reason for the port to run a round
(`Port::needs`), not only an ordering of the round that happens to run. Measured: a Session
opened after a room went quiet was never announced, neither port ran a round for 90 s, and the
member trusted with drive never read it.

### R8. A Busy refusal is not Unreachable

A Busy refusal (the peer is mid-operation) costs the peer one lookup; an unreachable peer costs
a dial. The retry curve for a Busy refusal MUST NOT grow past 1 s. Entries converge at the
refusal's true cost, not at an unreachable's cost.

A history worker this node's own actor cancelled (its ask was replaced by a newer one, paused or
stopped) is neither: it stopped at its next store step on a local decision. Its port MUST NOT be
failed or backed off, and the room MUST NOT be poisoned by the cancellation; the replacing ask's
own flow runs next.

### R9. Admission distinguishes accepted from committed

A control admission gate MUST check the head is accepted, committed or proven on chain, not
committed alone. A control range at an earlier, proven-but-uncommitted head MUST complete.

### R10. A settlement's own feed is the settlement's own work

Under R5 the acknowledgement of a node's own head is the conflict detector's input, not a write
precondition; it MUST still be driven. A sparse settlement whose only missing piece is the
node's own live-window acknowledgement MUST offer the own-author hint for the committed own head
to every connected peer, so the next round fetches it now. Settlement MUST be retried for every
open room on every tick: no other sync event reliably arrives for a room whose remaining piece
is its own acknowledgement.

The own-author flow records the peer's authenticated head and walks no window: every position
of the node's own log is already held, and a peer holding more of it is the conflict R5 stops
the node on, not something to fetch. Measured before this: a creator walked her own ten-entry log
through a joiner's port for 8 s (103 rounds) while two other joiners' first posts waited.

### R11. A turn may run several control chunks, never a cycle

Control-lane work is metadata work (a proof check, a header fetch, a verify) where each step
costs the peer one lookup. A turn MAY process a bounded number of control-lane chunks
back-to-back (16); one chunk per round paces a whole convergence at one entry per second. A
step that signals a dependency need or a Busy answer MUST end the turn: cycling a need or a
busy answer inside one turn was measured as a spin (the product held 102% CPU until the proof
watchdog killed it). Live body work stays one step per round: a body chunk is the expensive
kind.

This holds for every local slice of a bounded-sync flow, not only control chunks: a turn MUST run
its local slices (verify, entry, reclaim, window steps) back to back until one needs the wire,
waits, errs, or the turn has spent 20 ms or 64 slices; a wire exchange still ends the turn. Each
slice as a turn of its own cost an actor round trip (~10 ms), about thirty per body: a joiner
drained a 128-position live window at three positions a second, and a creator serving three
joiners at once read their first posts after 30 s.

A need for the fold is such a dependency need. An entry slice that needs the governance fold
MAY run a bounded fold step and re-derive itself at most four times in one turn (R2 a); a need
still open after that MUST end the turn as a wait, MUST mark the actor's fold work pending so its
hook drives the fold (R2 b), and the flow resumes at the port's Busy cadence (R8). Treating each
fold step as progress cycled the need without bound: the entry slice ran again at once against
the same unready fold, 32 slices a turn and 77 turns a second (229,000 fold checks in 59 s), and
because the one foreground lane went back to the same flow every round, the node's other peer
never got a round: a post made while the fold was held reached no one in 30 s. Waiting on the
fold is a local wait, not a body slot held against a busy peer, so it MUST NOT count toward
retiring the flow's body slot.
The lane's queue is fair as well: a port whose turn found the lane taken keeps its place ahead
of the ports that become eligible after it, so the port sorted first cannot retake the lane
round after round while its flow waits.

### R12. A late entry re-arms the fold, and the fold re-settles at its own cost

Late-arriving entries re-open the fold (Dirty rows); before this decision a pending Session
activity then waited on "room governance is refreshing", measured at 20 s for a join burst's
entries. The fold's re-settle MUST be driven by the entries' own arrival (R2 b) and MUST NOT
charge the Session chain a wait beyond the ordering work's own cost.

### R13. Convergence is measured, then the measuring is deleted

Convergence defects MUST be root-caused by measurement (rate-limited, per-conjunct diagnostics,
link by link), not by guessing, and not by widening the proofs' bounds. Diagnostics MUST NOT
land in released commits; the measured evidence lives on the tracked issue.

## Consequences

### Positive

- A joined room is usable from Ready at one wait, fresh or carrying a backlog, and a
  late-joining agent is not locked out of the repo room by silence.
- The fold stays the single arbiter and gate for everything irreversible. ADR-007's rules are
  applied where they always were; the proof token makes forgetting the gate a compile error
  rather than a review finding.
- The pacing family (backoff, admission, hint, turn chunks) is fixed at each root cause, so the
  next timing defect has a named gate to measure rather than a widened bound to blame.

### Negative

- Whether a port runs a round is decided from five facts kept in five places (the room
  generation against the port's served generation, a raised request, an owed announcement,
  pending hints, required work). v0.4.6 adds the one that was missing; it does not consolidate.
  One derived `needs()` from one set of facts, with nothing else able to start or suppress a
  round, is the next design change after the body-lazy window.
- The live window fetches each author's newest 128 bodies on join (about 40 s of lane time per
  author) against R1's rule. Fetching bodies only from the join on, headers for the rest, is the
  first change after this release; the newcomer proofs then say: post-join rows at once, earlier
  rows on demand.

- The tick does settlement work for every open room every second: bounded, but no longer free.
- A page read while the fold is behind carries a provisional note; a room marked own-history
  behind refuses every write until a person resolves it. Both are loud by design.
- Every irreversible egress call site changes signature to take the proof token.

### Neutral

- The security core is unchanged: the accept path's authentication (the v2 signed control
  closure, admission boundaries and epoch checks), ADR-007's strict-past, removal-wins and
  concurrent-ordering rules, the drive-key chain's cryptography and the at-rest encryption.
- The proofs' windows stay the product's claims; the measured per-link budget remains the
  evidence on #934. Legacy rooms keep their fold barrier as it is.

## Links

- #934 (the measured evidence), #947 and #948–#958 (the tracked work), PR #946 (the pacing
  fixes' branch)
- [ADR-007: membership and governance](ADR-007-membership-consent-and-admin-governance.md)
- [ADR-018: product proofs](ADR-018-quality-bar-and-product-proof.md)
- [ADR-026: daemon and nodes](ADR-026-daemon-and-nodes.md)
- [ADR-029: Sessions and the drive-key chain](ADR-029-sessions-and-the-repo-room.md)
- [ADR-031: agent nodes joining a repo room](ADR-031-agent-nodes-join-a-repo-room-by-themselves.md)
- [ADR-036: live messages and requested history](ADR-036-live-messages-and-requested-history.md)
