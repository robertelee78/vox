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

Each entry MUST sign its pre-entry control context by hash, never a post-context containing its
own hash. A context object is immutable; a missing object is pending, not an empty frontier.
Context inheritance MUST preserve the prior context and the control context of explicit causal
parents. This may reuse a separately carried, canonical sorted frontier object; it does not
require an inline vector in every message or a new consensus service.

The proposed completeness rule is H-3's single augmented commitment. A separately claimed latest
control pointer is insufficient. Context objects are canonical sorted maps with at most 2,048
distinct author fingerprints, each naming an exact control position and entry hash. Exceeding
that cap MUST produce an explicit refusal, never a truncated map. The syntactic join chooses the
higher position for each author; equal positions with different hashes conflict. Verifying an
advance separately requires authenticated continuity of that author's feed. Neither this join
nor the committed descriptor may depend on a receiver's local authorization verdict. Store
unchanged objects once by hash rather than copying a full map into every entry or adding another
frontier tree.

For a new entry, verify a receipt for its own immediately preceding prefix and each explicit
`seen` parent, using H-3's derived receipt. The entry's signed pre-entry context MUST dominate
their joined prefix frontiers: for every coordinate it preserves the same position/hash or
names a later position with verified continuity. Extra coordinates are explicit causal
references and need the same control verification. Each cited position requires complete control
verification up to that position, not only inclusion of the last cited control. Own-author
positions in a pre-context MUST be strictly before the entry. The first entry uses existing
genesis and author-admission evidence; this introduces no membership certificate or roster.

Changed contexts MUST precede content as control records. A control signs its pre-context and
derives its post-context by joining its own public position/hash; following content binds that
post-context. Publishing the derived object does not itself require another context-update
record. Parent receipts and verified closures are reusable by their exact authenticated bindings.
The receiver MUST NOT replace signed causal context with its own newer frontier: the existing
strict-past, current-trust and removal-wins rules remain separate checks.

The following dispatch boundaries are mandatory. A signed kind selects its only handler; an
ordinary-content or addressed-key payload MUST NOT reach a room-governance handler.

| Existing payload/effect | New-format scope and verification |
| --- | --- |
| Every `GovBody` variant, including consent, revocation, lifecycle, retention, presence, service sharing, room names and anchors | Public room/author control; full original authority and causal checks. |
| Step policy, public Session floors and private-stream support marker | Public control; preserve policy, recipient, generation and continuity rules. Support declares transport capability and grants nothing. |
| Authentication checkpoint and feed termination | Author control; termination cannot hide in a skipped content interval. |
| Key package | Addressed key-delivery control; retain the existing public recipient and encrypted namespace. Its public position/hash advances the committed frontier independently of recipient-side key application. Other readers verify the authenticated header without requiring recipient decryption. Only the intended recipient may open it and apply existing namespace, generation and trust checks. |
| Legacy drive-generation headers and encrypted legacy Session indexes | Conversion evidence with the original audience; no new public authority source or public dependency on private bodies. |
| Text and read records | Content; no permission, generation or lifecycle effect. |
| Private Session opening/end and activity | Remain within the existing drive stream/namespace and uninterrupted generation eligibility. Lifecycle is control only in that private scope; activity is private content. |

Public readiness MUST NOT depend on private control closure. Public control may constrain private
access, but no private key, Session identity, lifecycle record or body becomes public proof data.
Every private page request still passes the current Drive and generation checks. The same proof
machinery may be reused within the private scope where necessary; this does not merge its history
or authority with the public room.

The authenticated kind is public metadata for skeleton-only peers. It MUST NOT encode private
Session activity or expose an encrypted key namespace or generation. A control count and public
coordinate commit to a typed record, not to a recipient's applied key state or a grant of access.

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
count, frontier-object hash and node hash. A leaf's count follows its signed kind. Its frontier
is exactly its signed pre-context for content, or that context joined with its own position/hash
for a mandatory control kind. These are pure functions of signed bytes, including for a control
later found unauthorized or inert; receiver-local evaluation cannot change the commitment. An
internal node recomputes both checked counts and the syntactic join of its children's frontiers,
then hashes the complete child descriptors and resulting frontier. Counts are nonnegative,
cannot exceed subtree length, and are checked at every reconstructed node. Frontier objects
needed to recompute a join MUST be supplied or already cached and hash-checked. A count or
frontier supplied alongside an ordinary unaugmented root is not proof.

The signed head binds format, author, room, epoch, scope and its complete descriptor. The node
hash is derived from leaf bytes or child descriptors; the separate head signs the resulting
descriptor. Neither an entry nor a descriptor hashes itself. Leaf/internal/empty domains and
encodings are distinct and canonical; all sizes, depth, arithmetic, context cardinality and proof
bytes are bounded before allocation or traversal. Preserve the existing monotonic per-author
room feed positions across epochs. An epoch or format change MUST NOT reset prefix consistency,
discard earlier control or bypass feed termination. The legacy format boundary remains pending
as described below; this rule does not invent a transition fence.

A parent receipt is derived evidence, not a new independently signed statement. For parent
sequence `p` (one-based, hence prefix length `p`), it contains an author-signed head of size
`n >= p`, the parent's signed header and inclusion proof at leaf index `p - 1`, a prefix
descriptor of size `p` and its consistency proof to that head, and the required canonical
frontier objects. If `n == p`, the descriptors MUST agree. Inclusion binds the exact parent
hash; consistency binds its prefix frontier. The own-parent receipt MUST name sequence `seq - 1`
and the entry's exact previous hash; only an actual first entry uses the empty prefix. Required
control-range verification through `p` is a separate obligation before that receipt can authorize
a causal reference. Cache receipts by exact head/prefix bindings, never size alone.

Advancing a durable accepted root requires a valid consistency proof from that root. Receiving
an entry requires its ordinary authentication and an inclusion proof at its exact position.
These proofs reconstruct complete descriptors, including their checked sums and frontier joins.
These prove an unchanged committed prefix and membership, not semantic validity of unfetched
payloads or old `prev` links. Keep committed positions, individually validated entries and the
actually held contiguous legacy prefix distinct. Authority MUST derive from complete required
control evidence, never from the word "committed."

Conflicting valid author signatures at one position or equal-size heads can supply fork
evidence. Different-size signed heads also supply evidence when valid openings establish
conflicting same-position leaves or equal-prefix descriptors. A missing or invalid consistency
proof alone is a refusal or pending result, not proof that the author forked: a relay can supply
a bad proof, and withheld openings may prevent extraction of a contradiction. Preserve signed
evidence and existing local revocation/fork restrictions when a later page reveals one.

Blame MUST follow the authenticating signer. If one author's context cites `A:p/H`, conflicting
with authentic `A:p/H'`, that invalid citation is not proof that A forked. Reject the implicated
citation or commitment; A's fork restrictions require contradictory evidence authenticated by A.
Retain the raw signed heads, entries and authenticated openings needed to distinguish an
author's malformed commitment from a bad relay response. A single false claim is not, by itself,
two-statement equivocation.

A control-range proof reconstructs the same target descriptor and covers the requested interval
exactly. Within that interval it may collapse only zero-control subtrees; every positive-control
branch must yield all its control headers, and all required bodies and authority dependencies
must be resolved. A well-formed control that the existing deterministic evaluator deems inert,
unauthorized, expired or out-of-epoch remains counted but has no authority effect. Missing
authority or context is pending, not such a completed denial. Invalid signatures, malformed
structure, unknown kinds and inconsistent counts or joins reject the proof or branch; they MUST
NOT be skipped under a blanket no-op rule. A control becomes operative only with valid inclusion
under this same commitment and its existing authority checks.
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
In particular, an opaque zero-control subtree's frontier is committed, not independently checked
against every omitted leaf. If a later authenticated opening contradicts a signed pre-context,
derived leaf frontier or internal join, retain the attributable malformed-commitment evidence
and reject the implicated branch. Do not retroactively treat a malformed skipped leaf as an
operative causal parent, or claim its signature alone proves membership or a fork.

### H-4. Bound demand across the daemon

The newest requested view and each explicit older-page request MUST have count, byte and work
budgets, a durable continuation and cancellation. The proposed default is at most 128 entries per
logical page and 1 MiB of archive wire work per request/continuation response, with at most two
archive transfers across the daemon and one for a node, counting both serving and receiving.
These are work budgets, not retention limits. The existing stream MUST support a valid 16 MiB
entry through bounded chunks; an oversized first entry MUST NOT bypass the byte budget. When
that response budget is exhausted, return an explicit continuation bound to the same entry/hash
and offset. Continuing it cannot silently advance to another entry or the next history page.

A continuation MUST bind the node/room instance, audience, request, authenticated entry hash and
length, and persisted offset. Partial bytes remain unaccepted staging until whole-entry hash,
signature and admission checks pass; a final hash does not authenticate each chunk separately.
Only persisted offsets may be acknowledged. Restart retains cached pages and continuation state,
but MUST NOT resume archive traffic just because an unfinished continuation exists. Reuse the
existing node-local canonical store and atomic admission path; wire chunking does not require a
new at-rest record format.

Control and live traffic MUST have reserved capacity while archive work is active. One shared
daemon budget MUST bound admitted archive work and its aggregate resident bytes across all local
nodes and both directions, with bounded fair queues. Acquire permits before frame allocation,
stored-record copy/decryption or decode/re-encode buffers, without waiting while holding an actor
or room lock. Hold permits until the actual worker and buffers have been released, including on
cancellation. A page's wire cap is not a resident-memory cap: the existing whole-record AEAD path
may need the full ciphertext/plaintext working set of a legal large entry. Reserve that working
set or remove its copies; do not claim wire chunking makes the stored record stream-decryptable.
Transport receive windows and queued bytes also need bounded archive admission/credit; an
application semaphore alone does not bound all transport memory or preserve control progress.

Requested pages MUST consult the node's disk cache first and fetch only missing requested data.
Explicit newest/older view requests are separate from cache reads used by watches, retained
selections, room reconciliation and notices. Those reads MUST NOT initiate remote history.
Pending remote work preserves cached rows and reports fetch/continuation status, rather than
clearing a room or presenting missing history as an empty result.

Completing one history page MUST NOT automatically request the next; a changed live tip is not
permission to drain its older gap. Remove both public partial-session continuation and private
Session `more`/periodic pull loops as sources of archive demand. New-port, periodic, reconnect
and post-sync scheduling may request required current control/live work, not every owed body.
Retry only the still-authorized bounded request; current key/control delivery remains distinct
from private history. Keep each private request's current Drive, generation and audience checks.

Session history retains ADR-031's join/drive boundary: a request for older room history MUST NOT
grant earlier private Session steps or widen trust. Retention and unavailable-peer outcomes
remain explicit. No automatic reset or deletion of existing node data is permitted.

This remains a proposed protocol, not a complete byte-level specification. Before implementation,
the implementer must pin the canonical encodings/domain tags, numeric field widths, proof and
chunk limits, byte-accounting rules, aggregate resident-byte pool/reserves, request/continuation
and cancellation states, and errors. The 128-entry/1 MiB and transfer-count defaults above do not
define those remaining wire constants or approve legacy activation.

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
3. What evidence is required to convert existing v0.4.5 state without trusting a peer snapshot
   or overriding an unseen valid action, and will the operator authorize the legacy exception?
4. Do the proposed resumable entry chunks, explicit demand and shared resident-byte budget retain
   capacity for live/control traffic without silently draining the next page?

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

GLM-5.3, Kimi K3 and Fable then conditionally approved the new-format design at `7240cd5cc`.
Their concrete findings were adjudicated, not accepted wholesale. This revision incorporates
derived parent receipts, pure signed-byte descriptor construction, strict-past context,
signer-specific blame, bounded frontier overflow, invalid-versus-missing control and the separate
wire/resident-memory budgets. Their approvals do not establish implemented behavior or resolve
the legacy decision.

The adjudication rejected the claimed root self-hash circularity, an extra independently signed
receipt, guaranteed fork extraction from a withheld/invalid proof, replacement of signed causal
context with a receiver's newer state, a key-package frontier dependent on private key
application, and an invented governance authority for a legacy reset fence. Omitted-content
context underclaims are an ex-post commitment-consistency obligation, not a claim that every
omitted leaf was semantically validated. Detailed verdicts and implementation seam maps are
retained with the incident artifacts rather than copied into additional product documents.

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
