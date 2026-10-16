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

Content MUST bind the full effective control context by hash. A context object is immutable and
bounded by the existing room author cap; an author MUST publish a new context before its next
content entry whenever its applied control frontier changes. Each frontier position names the
author, counter and hash, not a counter alone. Context inheritance MUST preserve the prior
context and the control context of explicit causal parents. A missing context is pending, not an
empty frontier. This may reuse a separately carried, canonical sorted frontier object; it does
not require an inline vector in every message or a new consensus service.

The proposed completeness rule is H-3's single augmented commitment. A separately claimed latest
control pointer is insufficient. Context objects are canonical sorted maps with at most 2,048
distinct author fingerprints, each naming an exact control position and entry hash. Equal
positions with different hashes conflict; advancing a position requires authenticated continuity
of that author's feed. Store unchanged objects once by hash rather than copying a full map into
every entry or adding another frontier tree.

For a new entry, verify a receipt for its own immediately preceding prefix and each explicit
`seen` parent. A receipt binds the exact parent position/hash to the control frontier of its
authenticated prefix, not merely a context claimed in its header. The entry's signed pre-entry
context MUST include the join of those frontiers. Extra coordinates are explicit causal
references and need the same control verification. Each cited position requires complete control
verification up to that position, not only inclusion of the last cited control. Context changes
MUST precede content as control records; parent receipts and verified closures are reusable.

The following dispatch boundaries are mandatory. A signed kind selects its only handler; an
ordinary-content or addressed-key payload MUST NOT reach a room-governance handler.

| Existing payload/effect | New-format scope and verification |
| --- | --- |
| Every `GovBody` variant, including consent, revocation, lifecycle, retention, presence, service sharing, room names and anchors | Public room/author control; full original authority and causal checks. |
| Step policy, public Session floors and private-stream support marker | Public control; preserve policy, recipient, generation and continuity rules. Support declares transport capability and grants nothing. |
| Authentication checkpoint and feed termination | Author control; termination cannot hide in a skipped content interval. |
| Key package | Addressed key-delivery control; retain the existing public recipient and encrypted namespace. Other readers verify the authenticated header without requiring recipient decryption. Only the intended recipient may open it and apply existing namespace, generation and trust checks. |
| Legacy drive-generation headers and encrypted legacy Session indexes | Conversion evidence with the original audience; no new public authority source or public dependency on private bodies. |
| Text and read records | Content; no permission, generation or lifecycle effect. |
| Private Session opening/end and activity | Remain within the existing drive stream/namespace and uninterrupted generation eligibility. Lifecycle is control only in that private scope; activity is private content. |

Public readiness MUST NOT depend on private control closure. Public control may constrain private
access, but no private key, Session identity, lifecycle record or body becomes public proof data.
Every private page request still passes the current Drive and generation checks. The same proof
machinery may be reused within the private scope where necessary; this does not merge its history
or authority with the public room.

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

The proposed prefix-consistency primitive is an author-signed append-only Merkle head, using
RFC 9162 §2.1's canonical split and proof algorithms with a **Vox-specific augmentation**. This
is not the RFC's unmodified hash encoding and requires review as such. It uses no certificate
service, external log or consensus system. A descriptor carries leaf count, mandatory-control
count, frontier-object hash and node hash. A leaf's count follows its signed kind; its frontier
is its verified inherited context, extended by itself if it contributes a control fact. An
internal node recomputes both checked counts and the join of its children's frontiers, and
hashes the complete child descriptors and resulting frontier. Counts are nonnegative, cannot
exceed subtree length, and are checked at every reconstructed node. A count or frontier supplied
alongside an ordinary unaugmented root is not proof.

The signed head binds format, author, room, epoch, scope and its complete descriptor. It is
separate from the included entry hash so the encoding has no circular commitment. Existing heads
or authenticated prefixes supply parent receipts. Leaf/internal/empty domains and encodings are
distinct and canonical; all sizes, depth, arithmetic, context cardinality and proof bytes are
bounded before allocation or traversal.

Advancing a durable accepted root requires a valid consistency proof from that root. Receiving
an entry requires its ordinary authentication and an inclusion proof at its exact position.
These proofs reconstruct complete descriptors, including their checked sums and frontier joins.
These prove an unchanged committed prefix and membership, not semantic validity of unfetched
payloads or old `prev` links. Keep committed positions, individually validated entries and the
actually held contiguous legacy prefix distinct. Authority MUST derive from complete required
control evidence, never from the word "committed."

Two valid signed statements for the same position/size and binding that disagree can supply
fork evidence. A missing or invalid consistency proof alone is a refusal or pending result,
not proof that the author forked: a relay can supply a bad proof. Preserve signed evidence and
existing local revocation/fork restrictions when any later page reveals a contradiction.

A control-range proof reconstructs the same target descriptor and covers the requested interval
exactly. Within that interval it may collapse only zero-control subtrees; every positive-control
branch must yield all its control headers, and all required bodies and authority dependencies
must validate. A control becomes operative only with valid inclusion under this same commitment.
It cannot validate inside a collapsed zero-control subtree. Cited parent-prefix receipts must
verify their complete control frontier; inclusion of a single latest action is insufficient.
Partial verification is durable and keyed to the exact target descriptor, not just its size.
Budget exhaustion never promotes a head to control-ready. Persist promotion and derived indexes
atomically; restart reuses completed work and retains pending obligations.

The new-format causal model is explicitly the authenticated control projection of included
entries and validated references. This preserves verified control dependencies and honest
`prev`/`seen` inheritance without walking all content ancestors. A malformed, unvalidated skipped
leaf does not acquire an operative causal edge merely from its signature. It does not claim
universal semantic validation of omitted content, knowledge of globally unseen controls, or
instant verification of unlimited essential control history. A first-contact peer can withhold
or fork what it presents; existing partition provisionality and cross-peer fork evidence remain.

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

1. Does the proposed counted, frontier-augmented commitment plus parent-prefix receipt establish
   complete applicable control and causal inheritance under the stated relative-to-commitment
   semantics? Review malformed summaries, skipped cross-author edges and scoped private controls.
2. Does the proposed sparse-feed proof/acceptance rule retain detectable equivocation and the
   honest distinctions between observed, committed, control-ready and individually validated data?
3. How can existing authenticated local v0.4.5 state transition without replaying all archived
   content or trusting a remote state summary? Which authority must sign any transition fence?
4. Can the existing entry framing carry a valid 16 MiB entry within bounded aggregate buffers,
   or must the existing stream be extended with authenticated chunked entry delivery?

## Adversarial plan review, 2026-10-15

GLM-5.3, Kimi K3 and Fable reviewed this plan, then reviewed concrete counterexamples. All three
withdrew their initial claim that a selected Lipmaa path proves append-only consistency. A
receiver holding signed A1 can be shown signed H4 whose skip link reaches A1 while its immediate
parent B3 descends from conflicting B1. The offered path verifies without exposing that fork.
The Merkle consistency requirement above addresses prefix identity; it does not solve control
completeness by itself.

An own-control pointer also loses a cross-author revocation learned between that control record
and a later content entry. Complete signed context and explicit inheritance are necessary.
All security-sensitive payload classes must participate, not only the current Governance enum.

Legacy records already sign room and epoch, but do not sign kind or this complete control
context. A receiver holding prefix 100 is not thereby synchronized with an author's head 10000.
An opaque fence, a local reconstruction checkpoint or a peer's evaluated snapshot cannot prove
the missing interval contains no applicable revocation or terminal room End. A newly signed
"active" baseline cannot override an unseen valid End under existing governance rules.

The operator has been asked whether the upgrade may perform a one-time bounded, resumable
verification of missing legacy history, while preserving data and keeping other ready work
responsive. This is a proposed exception for existing-format conversion, not permission already
received, not an automatic archive drain on normal startup, and not a requirement deferred to
another release. Until that decision and the exact protocol are resolved, H-1–H-5 remain in
design and MUST NOT be described as implementation-ready.

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
