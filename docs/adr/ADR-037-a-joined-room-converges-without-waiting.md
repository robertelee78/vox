# ADR-037: A Joined Room Converges Without Waiting

- **Status**: Proposed for v0.4.6. The decider ruled 2026-10-19: **Ready means the nodes can
  communicate from that point forward, at the same wait whether the room is fresh or carrying
  an unsynced backlog; history rehydrates from each node's local cache and older messages are
  fetched on demand, and none of that is part of ready.** A first-use operation refusing on
  room-global convergence state is therefore a product defect, not a pacing problem. The
  decider signed off the correctness semantics the same day: **new activity is admitted
  against the live control frontier its author has authenticated, and the fold is the
  arbiter, never the gate** — a conflict found later in the backlog resolves at fold time by
  the existing strict-past, removal-wins and concurrent-ordering rules. The decoupling
  (requirement 1) lands in v0.4.6; v0.4.6 launches when it is done. The pacing requirements
  below it (2–7) are the measured machinery learnings that keep the background work bounded;
  they no longer carry the release. Measured evidence: post-#945 main (24f9af7fa, the lazy
  architecture) runs the Claude session proof 6/7 red at 144 s — the regression is #945's
  first-use coupling, not this branch's work (the same proof on this branch: 6/7 red at 99 s;
  the branch's fixes improved the tail without touching the coupling). The pre-#945 behavior
  (v0.4.5, tagged 2026-10-15) is the near-instant baseline the decider remembers. No release
  acceptance is claimed before the proofs assert the constant wait and pass.
  **The decider further ruled 2026-10-19, over all of the above: Vox utterly fails if it
  fails security — the cryptography MUST be provably correct. Where the constant-wait ruling
  and a security gate tension, the gate wins (security outranks speed). The
  irreversible-egress gates below are structural, not incidental: no call site may reach
  key release, encryption-audience selection or final delivery without the control-stream
  fold's proof, and each gate carries a proof whose mutant — the gate removed — turns that
  proof red on its own assertion.** The independent adversarial review (kimi k3,
  2026-10-19; transcript on #934) found exactly the two holes this closes — H1
  stale-audience key egress and H2 unmarked provisional delivery — and its proposed fix,
  gating the irreversible egresses on a control-stream-only fold, is the adopted contract
  below.
- **Date**: 2026-10-18
- **Deciders**: Robert E. Lee
- **Tags**: sync, convergence, settlement, sessions, drive keys, timing
- **Related**: ADR-008, ADR-026, ADR-029, ADR-031, ADR-036

## Context

A joined room becomes usable through a chain of gates: the fold settles the room's governance,
the sparse settlement acknowledges the joiner's own feed, the Session activity appends and opens
the session, the drive key releases and installs, and the private pull projects the mirrored
work. Every gate in this chain is also a product claim — the proofs bound each stage (for
example, the mirrored-and-driven proof's 60 s windows, the fence proof's wake, the late-join
spike's whole chain).

The v0.4.6 validation exposed a family of timing defects. None of them produced a wrong answer:
every answer eventually arrived. But arrival was paced by periodics, by backoff curves borrowed
from unlike failures, and by single events that a quiet room never gets, so a joined room sat
silently unusable — refusing Session openings, drive-key release and private pulls, each gated
on a settlement that nothing was driving — for longer than the product's stated bounds.

Measured link by link on #934, with rate-limited per-conjunct diagnostics (deleted from the
tree; the measurements are the evidence on that issue):

- Entries converge after a join, then the fold settles 13–20 s after the last entries.
- A nine-entry control-lane walk took ~33 s: ~1 round per second, one task per round.
- The sparse settlement waited on the joiner's own live-window acknowledgement, whose fetch
  nothing drove: no hint drives a flow to a node's own author, and the 30 s periodic was the
  only event that ever fetched a node's own head back.
- The session opening costs 1–5 s, the drive-key release 1–16 s, the private pull 1–10 s.
- A green chain totals 27–47 s against a 60 s claim; one late-arriving entry or one missed
  re-arm pushes the same room past the bound. The reds measured 60–75 s.

Each root cause was fixed at its own gate rather than widening the proofs' bounds: the bounds
are the product's claims.

## Technical contract for v0.4.6 (the decoupling under review)

What is removed, per first-use path, and what per-operation checks remain:

1. **Local appends** (`append_private_content`): the room-global `require_governance_ready`
   (the fold's refresh refusal) and the `!settled` sparse-settlement refusal are removed.
   What remains: the room's own save-poison state, the author's own membership, the
   left/ended state, the drive-chain rotation, the floors, and the encrypt-record-keep
   write path — all per-operation, all local. **The one irreversible step inside the
   append — encryption-audience selection — gates on the control-stream fold below**
   (kimi k3's H1: a locally received but unfolded revocation/rotation must not let a
   removed member decrypt content authored after it).
2. **Reads** (the `session_projection` family — files, activity, session queries): the
   room-global REFRESHING refusals (`needs_session_upgrade`,
   `current_session_controls_ready`, `private_expiry_ready` as gates) are removed as
   refusals. A read answers the locally known data; a per-item gap is an honest
   "fetching that now" through the on-demand history path.
3. **Attention/message delivery**: never waits on the saved-Sessions refresh. **Live
   delivery is marked provisional while the control stream is not folded to the local
   receipt frontier** (kimi k3's H2: G-23's provisional mandate — a node that observably
   knows its fold lags must not present governance-contingent content as final).
4. **Net queries**: answered from known state; the global governance refusal no longer
   precedes the answer.
5. **The drive-key release and private pull**: the room-global gates drop; the per-key,
   per-holder checks remain. **Drive-key release — an irreversible egress — gates on the
   control-stream fold below** (H1).
6. **The control-stream fold gate (the adopted fix):** the three irreversible egresses —
   encryption-audience selection, drive-key release, and final (non-provisional) delivery —
   MUST NOT run while the node's control stream is not folded up to its local
   receipt frontier. Folding the control stream only is local compute over the
   separate, small control stream (ADR-036's separation): no network wait, no content
   backlog — so ready remains a constant wait. Where this gate and the constant-wait
   ruling tension, **the gate wins: security outranks speed** (the decider, 2026-10-19).
7. **The legacy-recovery gate stays (fable's F-H1):** `require_governance_ready` is two
   gates — the legacy-recovery state (`require_legacy_current`) and the fold check. Only
   the fold check is removed from first-use paths. A legacy-required or
   legacy-provisional room's operator-paused suffix is never folded, so the legacy gate
   MUST remain on every opened path, including `private_page` serving saved Session
   bodies: an ended room must not keep accepting Session activity, and old retention
   must not keep serving bodies, with no fold time ever coming to arbitrate.
8. **The drive generation is never chosen off an incomplete own feed (fable's F-H2):**
   the `settled` refusal MUST stay ahead of `begin_drive` in the append path — or
   `begin_drive` MUST refuse while unsettled the way `drive_members()` already does — so
   a rejoining node cannot reuse a drive generation members already hold.
9. **The read answers are per-author as well as per-row (fable's W8):** a partial
   `drive_from` answer must not silently drop an author out of the page (ADR-036 H-1
   forbids a room looking emptier than it is): the per-item "fetching that now" marker
   is per-author as well as per-row, and `private_expired` applies per row the way
   `files.rs:46` already does.

What is **not** changing — the security core:

- The accept path's authentication: remote entries still require the v2 signed control
  closure, admission boundaries and epoch checks before acceptance.
- ADR-007's ordering rules — strict-past, removal-wins, concurrent ordering — unchanged
  and still the arbiter: the fold still runs, still orders everything; only the
  append-time pre-check is removed.
- The sparse settlement still runs (background bookkeeping of the joiner's own feed).
- The drive-key chain's cryptography and the at-rest encryption: unchanged.

The review question for independent reviewers: under fold-as-arbiter, new activity is
admitted against the live control frontier while the backlog folds in the background.
Enumerate the windows this opens — for example, a revocation sitting in the backlog not
yet folded at append time, or a live delivery acted on before the fold arbitrates a
conflict — and confirm ADR-007's rules close each window at fold time, or name any
window they do not close.

The validation plan: the proofs assert the constant wait — the same bound whether the
room is fresh or carrying an unsynced backlog (the late-join case becomes a first-class
asserted case), and "call prior messages on demand" gets its own assertion through the
on-demand fetch path.

## Requirements

### 1. Ready is a constant wait, not a convergence

From the moment a node is Ready, the nodes MUST be able to communicate — the same wait
whether the room is fresh or carrying an unsynced backlog. History rehydrates from each
node's local cache and older messages are fetched on demand; none of that is part of ready.

First-use operations MUST NOT refuse on room-global convergence state:

- New activity appends against the live control frontier its author has authenticated; the
  fold is the arbiter, never the gate. A conflict found later in the backlog resolves at fold
  time by the existing strict-past, removal-wins and concurrent-ordering rules.
- A read answers the locally known data; a gap is an honest per-item "fetching that now,"
  never a room-global refresh refusal.
- The attention/message path never waits on the saved-Sessions refresh.
- The backlog folds in the background at its own bounded cost.

The one exception, and it is existential (the decider: "Vox utterly fails if we fail
security; crypto has to be provably correct"): the **irreversible egresses** —
encryption-audience selection, drive-key release, and final (non-provisional) delivery —
MUST NOT run until the node's control stream is folded to its local receipt frontier.
That fold is over the control stream only: local compute, no network wait, no content
backlog — so ready remains a constant wait. Live delivery during a lagging control fold
is marked provisional, never presented as final. These gates are structural — a call site
cannot reach an irreversible egress without the control-stream fold's proof — and each
carries a proof whose mutant, the gate removed, turns it red.

This is ADR-036's own separation ("Opening a node, opening a room, becoming Ready or healing
a network path MUST NOT request every missing content interval"), finished on the first-use
paths it was decided for.

### 2. Every background gate is event-driven

Each convergence gate MUST be re-armed by an event its own completion produces, or by the event
that produces its missing piece. A periodic MAY run as a backstop; it MUST NOT be the only
driver of a gate. A quiet room — no traffic, no commands — MUST still converge through its
gates.

### 3. A Busy refusal is not Unreachable

A Busy refusal (the peer is mid-operation) costs the peer one lookup; an unreachable peer costs
a dial. The retry curve for a Busy refusal MUST NOT grow past 1 s. Entries converge at the
refusal's true cost, not at an unreachable's cost.

### 4. Admission distinguishes accepted from committed

A control admission gate MUST check the head is accepted — committed or proven on chain — not
committed alone. A control range at an earlier, proven-but-uncommitted head MUST complete.

### 5. A settlement's own feed is the settlement's own work

A sparse settlement whose only missing piece is the node's own live-window acknowledgement
MUST be offered the own-author hint for the committed own head to every connected peer, so the
next round fetches it now. Settlement MUST be retried for every open room on every tick: no
other sync event reliably arrives for a room whose remaining piece is its own acknowledgement.

### 6. A turn may run several control chunks, never a cycle

Control-lane work is metadata work — a proof check, a header fetch, a verify — where each step
costs the peer one lookup. A turn MAY process a bounded number of control-lane chunks
back-to-back (16); one chunk per round paces a whole convergence at one entry per second. A
step that signals a dependency need or a Busy answer MUST end the turn: cycling a need or a
busy answer inside one turn was measured as a spin (the product held 102% CPU until the proof
watchdog killed it). Live body work stays one step per round: a body chunk is the expensive
kind.

### 7. A late entry re-arms the fold, and the fold re-settles at its own cost

Late-arriving entries re-open the fold (Dirty rows), and a pending Session activity then waits
on "room governance is refreshing" — measured at 20 s for a join burst's entries. The fold's
re-settle MUST be driven by the entries' own arrival, and MUST NOT charge the session chain a
wait beyond the ordering work's own cost. Recorded from the pre-decoupling era; the
decoupling (requirement 1) is the release line for v0.4.6, and these background gates keep
their own bounded cost.

### 8. Convergence is measured, then the measuring is deleted

Convergence defects MUST be root-caused by measurement — rate-limited, per-conjunct
diagnostics, link by link — not by guessing, and not by widening the proofs' bounds.
Diagnostics MUST NOT land in released commits; the measured evidence lives on the tracked
issue.

## Consequences

### Positive

- A joined room reaches its usable state through its own events; the proofs' bounds hold with
  the margin the claims state, and a late-joining agent is not locked out of the repo room by
  silence.
- The pacing family (backoff, admission, hint, turn chunks) is fixed at each root cause, so the
  next timing defect has a named gate to measure rather than a widened bound to blame.

### Negative

- The tick does settlement work for every open room every second: bounded, but no longer free.

### Neutral

- The proofs' windows stay as the product's claims; the measured per-link budget (27–47 s green
  against 60 s) remains the release evidence on #934.

## Links

- #934 (the measured evidence), PR #946 (the landed lines), ADR-026 (the daemon's bounded
  maintenance classes this rides on), ADR-029 (Sessions and the drive-key chain),
  ADR-031 (agent nodes joining a repo room), ADR-036 (the live/history split whose control
  lane requirement 5 paces).
