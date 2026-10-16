# ADR-036: Live Messages and Requested History

- **Status**: Proposed for v0.4.6. Requirements reflect the decider's 2026-10-15
  instructions; the remote authentication design below requires independent review before
  implementation. No release acceptance is claimed.
- **Date**: 2026-10-15
- **Deciders**: Robert E. Lee
- **Tags**: sync, history, control, authentication, startup, storage
- **Related**: ADR-007, ADR-008, ADR-010, ADR-018, ADR-025, ADR-026, ADR-031

## Context

The v0.4.5 daemon authenticated kept nodes but waited for their room archives before reporting
Ready. Rebuilding local indexes used hash order, repeatedly revisited descendants, pinned old
database snapshots across commits and committed tiny or empty governance work. Publishing read
indicators reopened message bodies even when their inputs had not changed. Bounded memory did
not imply bounded startup work. A real Mac remained Preparing for hours while writing far more
data than its stored history.

The remote path has a separate defect. A frontier request asks for everything from the local
head to the remote head, and partial progress immediately schedules the remainder. Page limits
therefore postpone a complete archive download; they do not prevent it. Feed acceptance requires
every preceding sequence. Existing Lipmaa helpers prove selected ancestry paths, not completeness
of omitted control events or validity of every skipped link. Entry kind is inferred from an
optional payload, so an omitted interval cannot be proved free of revocations from today's signed
skeletons. A peer's locally evaluated governance index is not an authority proof.

The decider requires startup and live messages to be independent of an archive's length. Moving
the same archive drain until after Ready is explicitly insufficient. Nodes own their durable
history; the shared daemon schedules bounded work for them and carries traffic.

## Decision

### H-1. Separate purposes and possession

Sync MUST distinguish current authenticated control, live messages and explicitly requested older
history. A node MUST track its validated contiguous prefix separately from authenticated sparse
positions and missing intervals. An observed signed tip MUST NOT advance the contiguous prefix.
Opening a node, opening a room, becoming Ready or healing a network path MUST NOT request every
missing content interval. Persisted control and cached message pages MUST survive restart.

Normal cached restart is governed by ADR-026 L-9–L-11. Essential control evidence that is missing
MUST be named as pending; unavailable archive bodies MUST NOT look like an empty room or failed
node unlock. Other ready nodes and rooms MUST remain usable.

### H-2. Authenticate control independently of content history

The proposed new signed skeleton explicitly distinguishes content from mandatory control and
commits to the author's preceding control position/hash. Mandatory control includes governance,
consent and revocation, key generations, retention, feed termination and authentication
checkpoints. Content cannot carry an operative control action merely by disguising its payload.

Control entries MUST also commit to their complete control-causal context, including control
dependencies learned through intervening content entries. The current strict-past epoch,
delegation, removal-wins and concurrent ordering rules in ADR-007 MUST be preserved. A plain
list of the last few seen content hashes is not sufficient evidence for this purpose.

A receiver follows and verifies the required control chain and its causal closure from its
last authenticated control position, using existing author keys and admission evidence. It MUST
NOT authorize an action from an incomplete closure or accept another node's unsigned/evaluated
snapshot as authority. Control work MUST itself be bounded and resumable; missing evidence
remains pending rather than triggering content-archive download.

The exact bounded representation of the complete control frontier, and the authenticated
transition from existing v0.4.5 records that lack these commitments, are review questions below.
They MUST be resolved before this protocol is execution-ready.

### H-3. Authenticate a requested interval without claiming a full prefix

Live delivery MUST authenticate each admitted author's requested tail and its relationship to
positions already held, without receiving every older content body or skeleton. Proofs MUST
bind author, room, epoch, sequence, hash and format. Every overlapping held position MUST agree;
conflicting valid author statements MUST retain the existing durable fork evidence and refusal.
Termination and control changes cannot be hidden in a skipped content interval.

The implementation MAY reuse existing backlink proofs only for the ancestry property they
actually establish. It MUST NOT silently replace full contiguous validation with a signed tip,
pretend an unsigned gap was validated, or discard a later conflict found during backfill.
Sparse positions and their evidence MUST be durable; requesting an older page MUST fill only its
missing intervals, merge idempotently and preserve actual message bodies and ordering.

### H-4. Bound demand across the daemon

The newest requested view and each explicit older-page request MUST have count, byte and work
budgets, a durable continuation and cancellation. The first implementation is to reuse current
page/stream machinery: a default page of at most 128 entries and 1 MiB, at most two archive
transfers across the daemon and at most one for a node. These are work budgets, not retention
limits or a limit on the room's history. A valid larger entry MUST be transferred in bounded
chunks under its authenticated length/hash, not silently truncated or allowed to bypass the
aggregate byte budget.

Control and live traffic MUST have capacity while archive work is active. The scheduler MUST
bound total buffered bytes and admitted work across all local nodes, not just each peer. It
MUST apply backpressure before allocating large payloads. Completing one history page MUST NOT
automatically request the next; a changed live tip is not permission to drain its older gap.
Requested pages MUST consult the node's disk cache first and fetch only what is missing.

Session history retains ADR-031's join/drive boundary: a request for older room history MUST NOT
grant earlier private Session steps or widen trust. Retention and unavailable-peer outcomes
remain explicit. No automatic reset or deletion of existing node data is permitted.

### H-5. User-visible acceptance and release boundary

Extend existing on-demand binary/app journeys; do not add a test framework or unit tests.
One old-history/returning-node journey MUST show a new message delivered before the old archive
is fetched, an explicit older page retrieved with its exact bodies, and another live message
delivered while that work runs. Restart MUST retain the received page without refetching it.
Exercise multiple local nodes to expose aggregate scheduling, not just one peer's limit.

Adversarial apparatus MUST exercise omitted control/revocation, conflicting overlapping history,
wrong room/epoch, missing required authority and malformed proof limits against the real binary.
Each negative verdict MUST come from the product; apparatus failures are named separately.
Run a proof once and repeat only where a change or observed failure reaches its claim. Existing
greens and mutants remain bound to the source and claims they actually cover.

H-1–H-5 are v0.4.6 obligations. A local restart optimization alone does not satisfy them. No
requirement is to be silently deferred in order to call the release complete.

## Review questions

1. What is the smallest authenticated control-causal frontier representation that preserves
   ADR-007 through skipped content without an unbounded inline vector or a new consensus system?
2. What exact sparse-feed proof/acceptance rule replaces the all-prefix assumption while retaining
   detectable equivocation and honest distinctions between an observed tip and validated history?
3. How can existing authenticated local v0.4.5 state transition without replaying all archived
   content or trusting a remote state summary? Which authority must sign any transition fence?
4. Can the existing entry framing carry a valid 16 MiB entry within bounded aggregate buffers,
   or must the existing stream be extended with authenticated chunked entry delivery?

## Consequences

### Positive

Startup and live work no longer scale with the content archive. Requested history remains
available on disk and can be filled from peers without monopolizing all nodes on a machine.

### Negative

The remote protocol needs an explicit format transition and security review. A node with missing
essential control evidence must report that limitation; it cannot manufacture current authority.

### Neutral

This decision supersedes ADR-008 LS-3's automatic replicate-all interpretation, LS-28's mandatory
continuous-prefix request and LS-29's immediate archive continuation for the new protocol.
It does not change room admission, trust, cryptographic forward revocation or the existing
partition limit: an unseen remote action cannot be known before communication.

## Links

- [ADR-007: membership and governance](ADR-007-membership-consent-and-admin-governance.md)
- [ADR-008: authenticated log and sync](ADR-008-replicated-authenticated-log-and-sync.md)
- [ADR-018: product proofs](ADR-018-quality-bar-and-product-proof.md)
- [ADR-025: sync scheduling](ADR-025-sync-scheduling-switch-not-hub.md)
- [ADR-026: daemon and nodes](ADR-026-daemon-and-nodes.md)
- [ADR-031: agent setup and private Session history](ADR-031-agent-nodes-join-a-repo-room-by-themselves.md)
