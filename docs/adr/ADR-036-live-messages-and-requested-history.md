# ADR-036: Live Messages and Requested History

- **Status**: Proposed for v0.4.6. Requirements reflect the decider's 2026-10-15
  instructions. The reviewed new-format design and concrete implementation contract below are
  approved for implementation; existing-format activation remains unresolved. This ADR stays
  Proposed until that separate decision and delivery are complete. No release acceptance is claimed.
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
commits to the author's complete preceding control context by hash. Mandatory control includes governance,
consent and revocation, key generations, retention, feed termination and authentication
checkpoints. Content cannot carry an operative control action merely by disguising its payload.

Control entries MUST also commit to their complete control-causal context, including control
dependencies learned through intervening content entries. The current strict-past epoch,
delegation, removal-wins and concurrent ordering rules in ADR-007 MUST be preserved. A plain
list of the last few seen content hashes is not sufficient evidence for this purpose.

A receiver verifies the required counted control intervals and their causal closure from its
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
Every private page request still passes the current Drive and generation checks. The existing signed private stream keeps its own format and authority; this decision does not
introduce a second Merkle log for it or merge its history with the public room.

The authenticated kind is public metadata for skeleton-only peers. It MUST NOT encode private
Session activity or expose an encrypted key namespace or generation. A control count and public
coordinate commit to a typed record, not to a recipient's applied key state or a grant of access.

### H-3. Authenticate a requested interval without claiming a full prefix

Live delivery MUST authenticate each admitted author's requested tail and its relationship to
positions already held, without receiving every older content body or skeleton. Proofs MUST
bind author, room, scope, sequence, hash and format. Each leaf retains its signed epoch; the
append-only tree binding spans epochs, as specified in H-6. Every overlapping held position MUST agree;
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

The existing signed and Drive-encrypted private record bytes remain unchanged. Version private
stream 13's request/page envelope so each request is exactly `LiveTail` or `ExplicitArchive`;
refuse unknown purposes rather than interpreting them as an older-page pull. The logical
`ExplicitArchive` operation uses separate bounded inventory and exact-record requests; neither
subrequest may widen the operation.

`LiveTail` samples a fixed newest window of at most 32 records and 1 MiB. Automatic acceptance
requires each unseen record to be the next contiguous iteration of its sender-key chain, with
no unresolved skipped iterations. Locally retained or co-delivered signed lifecycle facts govern
activity; an unknown lifecycle or gap leaves the durable live watermark unchanged and reports
that explicit private history recovery is required. A donor's unsigned descriptor or cursor
cannot prove that a later end, rename or metadata change was not omitted. No donor-selected
lifecycle completion is treated as currentness or authority.

Explicit private recovery binds the selected donor, its current trust/Drive incarnation and
one immutable ascending interval of at most 32 arrival positions. It exchanges a bounded
inventory, then asks for exact missing `(position, hash)` records within 1 MiB per quantum.
Genuine records may be cached under the existing signature, Drive, ratchet generation, replay
and `MAX_SKIP` rules; an unsigned inventory never proves global completeness. One quantum stops
and requires an explicit Resume; another interval also needs explicit selection. The durable
state shares the node's one archive operation, status, restart-paused, resume and cancel contract
with public history, while retaining explicit private scope and original bounds. Cache hits
suppress retransmission only after exact positions and hashes agree. Public v2 heads or contexts
never authorize a private record. Existing real data is not reset or silently migrated.

Session history retains ADR-031's join/drive boundary: a request for older room history MUST NOT
grant earlier private Session steps or widen trust. Retention and unavailable-peer outcomes
remain explicit. No automatic reset or deletion of existing node data is permitted.

H-6–H-8 fix the new-format implementation contract, including wire encodings, bounds and
persistent states. Those definitions do not authorize existing-format activation.


### H-5. User-visible acceptance and release boundary

Extend existing on-demand binary/app journeys; do not add a test framework or unit tests.
One old-history/returning-node journey MUST show a new message delivered before the old archive
is fetched, an explicit older page retrieved with its exact bodies, and another live message
delivered while that work runs. Restart MUST retain the received page without refetching it.
Exercise multiple local nodes to expose aggregate scheduling, not just one peer's limit.

**Existing v1 recovery.** A signed v1 witness may cover an unbounded retained suffix. Its
publication MUST advance only through explicit bounded Resume quanta; startup MUST NOT finish it
automatically. A room with paused Building or Switched work MUST reopen its published accepted
cache under current trust, Drive and retention checks and expose the exact saved request's Resume
and Cancel. Publication-dependent writes may return `Legacy history required`; neither this state
nor an unverified suffix may be reported as fully current. Cancellation and orphan reclamation may
run as bounded local maintenance without accepting history. Completed recovery or cancellation
MUST eventually restore an Idle entry index, including after a crash. Ordinary writes resume once
no authenticated essential gap remains; cancellation never discards such evidence or certifies
current authority. The live-before-archive and live-during-archive journey above applies to the
authenticated new format; existing v1 rooms separately prove responsive cached recovery,
preserved restart-paused progress, and recovery to Idle. This does not authorize format
conversion, weaken governance, or grant the unresolved legacy activation exception.

Adversarial apparatus MUST exercise omitted control/revocation, conflicting overlapping history,
wrong room/epoch, missing required authority and malformed proof limits against the real binary.
Each negative verdict MUST come from the product; apparatus failures are named separately.
Run a proof once and repeat only where a change or observed failure reaches its claim. Existing
greens and mutants remain bound to the source and claims they actually cover.

H-1–H-8 are v0.4.6 obligations. A local restart optimization alone does not satisfy them. No
requirement is to be silently deferred in order to call the release complete.

### H-6. Concrete new-format wire contract

This section is the implementation contract approved for new-format work. It does not claim
that the described code exists. Reuse Vox's existing canonical CBOR `Encoder`/`Decoder`; no
second serialization system or generic protocol framework is required. All arrays are definite,
integers use their shortest unsigned encoding, and decoders require exact arity and end of input.
Reject unknown kinds, scopes, flags and extra fields. Check lengths before allocation or copying.
Hashes and fingerprints are 32-byte strings, request IDs are 16-byte strings and a composite
signature is exactly 3,373 bytes. Sequence/count values are at most `2^48`, epochs and claimed
milliseconds are `u64`, algorithm identifiers are `u16`, and kind/scope discriminants are `u8`.
Arithmetic, proof indexes and offset sums use checked operations. Direct schema decoding has a
maximum nesting depth of 32; using the low-level decoder does not waive that bound.

**Fresh-room activation.** A newly created room MUST bind this history format in its signed
and hashed genesis, not infer it from a peer version or an empty local store. Genesis tag
`0x000D` version 3 uses signing domain `vox/genesis/v3`. Its canonical body is the existing
six-field genesis body followed by the unsigned integer `2` (authenticated history format);
its wire body appends the creator signature as field eight. Unknown values and extra fields
are refused. Genesis versions 1 and 2 retain their exact bytes, hashes and signing domains.
Creating or joining a verified version-3 room initializes the sparse index in the existing
atomic empty-room transaction, before any authored entry. Reopening a room preserves its
published format; an empty local join store is not authorization to activate a legacy room.
This marker does not convert an existing room, create a reset fence or authorize the legacy
exception below.

**Entries and kinds.** Preserve tag `0x0001` version 1, its bytes, hash and signature domain
exactly. Version 2 is an explicit supported version of that tag, signed with `vox/log-entry/v2`.
Its canonical signed skeleton is this 16-field array:

```text
[author, seq, prev, lipmaa, room, epoch, [sign_algo, aead_algo],
 payload_hash, payload_len, end_flag, claimed_ms, seen_refs,
 kind, scope, pre_context_hash, recipient_option]
```

`seen_refs` is `[[author, seq, hash], ...]`, strictly sorted by author, with at most 16 distinct
nonself authors. `recipient_option` is `[]`, except for a key package, where it is `[recipient]`.
The entry hash remains SHA-256 of the canonical skeleton. The entry wire flattens those fields,
then appends `auth_type`, `signature`, `payload_present` and, when present, `payload`: exactly
19 or 20 fields. Presence and end flags are integers 0 or 1. A signed header is the body-absent
19-field form. It is at most 8 KiB. Payload length is at most 16,777,216 bytes. Consequently
`MAX_ENTRY_WIRE = 16 MiB + 8 KiB + 9` bounds the complete canonical record, including the
largest CBOR byte-string length header. Signature type 1 is required for every v2 header. Retain
those signatures even after body retention: a later live entry may require an exact receipt for any earlier content parent.
Otherwise dropping a content signature could make the required parent evidence unavailable.
This deliberately preserves v1 dropped-signature behavior and adds no alternate sparse
signature-authentication path. An unsigned sparse record cannot acquire authenticity merely
by arriving or being described as checkpointed.

A v2 checkpoint still names an exact earlier position/hash on its own authenticated feed;
missing source evidence stays pending. Because v2 retains each signed header, that checkpoint
neither drops signatures nor imposes v1's blanket refusal of previously unheld positions below
the checkpoint. Explicit backfill may authenticate those positions normally. It does not restore
expired bodies, override retention or certify a contiguous prefix that was never verified.

| Kind | Sole dispatch |
| --- | --- |
| 0 | Ordinary content: text/read records; no control handler |
| 1 | Existing `GovBody`, with its existing authority rules |
| 2 | Authentication checkpoint |
| 3 | Step policy |
| 4 | Public Session floor |
| 5 | Private-stream support declaration |
| 6 | Addressed key package; only this kind has a recipient field |
| 7 | Context update |
| 8 | Feed termination |

Kinds 1–8 contribute one to the control count; kind 0 contributes zero. Kinds 7 and 8 have an
empty payload and SHA-256 of empty bytes as their payload hash. `end_flag == 1` if and only if
kind is 8. Decrypted ordinary-content envelopes that encode Session lifecycle, legacy Session
indexes or another control effect are refused, not dispatched by payload inspection. In the
public feed, ordinary content also refuses drive-channel encrypted payload classes. Legacy
private headers/indexes remain original-byte conversion evidence, not newly relabeled records.
Scope 0 is the public room feed. Scope 1 is reserved and refused by this public format; existing
private stream 13 retains its signed, Drive-protected format. A v2 public context cannot name a
private context or require its plaintext. Key-package namespace and generation remain encrypted;
its public coordinate is sufficient to compute the syntactic frontier.

**Contexts, descriptors and heads.** Reserve struct tags `0x0022` for `LogHead` and `0x0023`
for `ControlContext`, both version 1. A tree binding is `B = [2, room, scope, author]`.
It deliberately excludes epoch. A context object is:

```text
C = [2, room, scope, [[author, seq, entry_hash], ...]]
F = SHA256("vox/log-context/v1" || CBOR(C))
D = [leaf_count, control_count, F, node_hash]
```

Coordinates are strictly sorted by author, have nonzero positions and contain at most 2,048
authors. The 1,024-member operating bound and 2,048 hard protocol cap are not permission to
truncate a frontier. Conflicting equal-position coordinates fail the join. The canonical empty
context is `C` with an empty coordinate array. Descriptors are defined by these exact domains:

```text
empty: [0, 0, F_empty,
        SHA256("vox/log-tree/empty/v1" || CBOR([B, F_empty]))]
leaf:  [1, c, F_post,
        SHA256("vox/log-tree/leaf/v1" || CBOR([B, entry_hash, c, F_post]))]
node:  [n_left+n_right, c_left+c_right, F_join,
        SHA256("vox/log-tree/node/v1" || CBOR([B, D_left, D_right, F_join]))]
```

A leaf uses the signed pre-context for content, or that context joined with its own coordinate
for control. Internal children are nonempty and use RFC 9162's canonical largest-power-of-two
split. Both count sums and the context join must be recomputed. A collapsed descriptor is a
commitment, not a claim that all its omitted leaf semantics were independently checked.

The head body is `H = [2, author, room, scope, tail_epoch, D]`. Its signature domain is
`vox/log-head/v1`; its framed wire has these six fields followed by auth type 1 and the signature.
`HeadID = SHA256("vox/log-head/v1" || CBOR(H))`, excluding randomized signature bytes.
`tail_epoch` must match the authenticated terminal leaf when the head is promoted. It is not an
epoch authority or a tree key. Leaf epochs are evaluated against their original strict past;
the current request preamble is checked against current room admission. Epoch changes never
reset positions, tree consistency, control obligations or termination. The present governance
evaluator's epoch-zero behavior is preserved until separately changed; this format does not
invent an epoch transition or legacy fence.

**Proof objects.** All positions below are one-based; inclusion leaf index is `p - 1`.
Descriptor orientation comes from indexes and canonical splits, never a peer-provided side bit.

```text
inclusion:   [p, n, [sibling_descriptor, ...]]
consistency: [m, n, [proof_descriptor, ...]]
receipt:     [HeadID, signed_parent_header_bytes, inclusion,
              prefix_descriptor_of_size_p, consistency_p_to_n]
control:     [HeadID, lo, hi, [token, ...]]
```

Inclusion siblings are in bottom-up RFC 9162 order, at most 48. Consistency uses RFC 9162 order,
at most 49 descriptors, with `0 <= m <= n <= 2^48`. For `m == n`, the descriptors must be
identical and the proof empty. An empty-prefix proof never bypasses an existing accepted root
or unresolved legacy boundary. A receipt refers to separately supplied, verified head/context
objects and the exact parent hash; required control coverage through `p` is still a separate
obligation. Cache it by those exact bindings.

Control tokens use canonical preorder traversal of the target root: `[0, D]` collapses a
subtree, `[1, signed_entry_header_bytes]` expands a leaf, and `[2]` expands a branch followed
by left and right children. Outside `[lo, hi]`, any subtree may be collapsed. Within that
interval, only a zero-control subtree may be collapsed. The proof must consume the exact root,
range and token list; missing/extra tokens, wrong splits, counts or joins reject it. A proof
object has at most eight expanded control headers, 1,024 tokens and 256 KiB. Larger coverage
uses successive proved position intervals under the same exact HeadID; it does not pretend the
unproved remainder has zero controls. Frontier preimages travel as separate content-addressed
objects, never as a repeated full map inside every sibling descriptor. Missing preimages or
control bodies leave verification pending. A context object is at most 160 KiB.

**Sync requests and frames.** Reuse stream kind Sync (1), its existing four-byte frame-length
prefix and HELLO. Mode bit `0x04` selects this format; failure cannot fall back to archive-drain
mode. The new preamble is `[2, room, current_epoch, scope, purpose, request_id]`, at most
128 bytes. Purpose 0 is required control, 1 is live, and 2 is explicit history. The identifiable
old two-field preamble does not authorize legacy conversion. A v2 stream serves one bounded
request exchange; both directions count against the daemon's shared budgets. HAVE is a sorted
list of at most 2,048 `[author, size, HeadID]` hints, not verified state.

WANT (`0x03`) is `[request_id, query]`, where query is exactly one of:

```text
[0, author]                                      # head
[1, context_hash]                                # context object
[2, HeadID, proof_kind, from, to]                 # proof
[3, HeadID, seq, offset]                          # one entry/body continuation
[4, HeadID, lo, hi, entry_limit, wire_limit]       # bounded page
[5, HeadID, seq]                                 # signed header only; no body
[6]                                             # current head inventory; control purpose only
```

Inventory is `WANT -> client HAVE -> server HAVE -> DONE`, with the full bidirectional
exchange charged to the same 1 MiB wire quantum. Hints convey no body permission or authority.
Only newly queued, bounded exact head hints wake metadata verification; accepted/in-flight
hints are deduplicated, and neither an inventory nor its completion requests archive bodies.

Proof kinds 0/1/2 mean inclusion/consistency/control range. Inclusion requires `from == to == p`;
consistency uses old/new sizes. Requests are bound to the authenticated author/scope and the
original local operation; a peer cannot widen demand through a returned continuation.
Header-only requests consume one header credit and never permit CHUNK. Required proof/parent
headers therefore do not implicitly request their older content bodies.

The purpose also constrains the server before any body read: pages require the history
reservation, and a control-body request requires a signed mandatory-control kind. A live body
must be the current accepted author's tail when selected. Finishing that body across quanta may
use the same exact node/peer/room/epoch/request/head/position/hash/length binding and durable ACK
offset even after the author advances. At most 64 such volatile bindings exist daemon-wide;
they expire after 30 seconds without progress or 300 seconds total. A receiver whose ACK was
lost may resume only at the last acknowledged offset or the sole outstanding chunk boundary.
The binding authorizes no additional entry or page. Restart drops it; this is bounded transfer
state, not a saved history queue or permission to resume archive work. Changing a query's purpose
cannot borrow reserved control/live capacity for arbitrary older bodies.

The consistency META proof body is `[claimed_prefix_descriptor, consistency]`, carrying the
prefix descriptor already required by the receipt above. Its leaf count MUST equal `from`.
This descriptor is untrusted input: the ordinary consistency verifier must bind it to the exact
signed target head. For head advancement it must additionally equal this receiver's accepted
baseline. For a previously unseen parent, the verifier may authenticate that claimed prefix
relative to the target without pretending it was a previously accepted head. In particular a
power-of-two prefix is not implicitly available from an RFC consistency path. No unsigned
prefix descriptor alone grants continuity, control completeness or authority.

| Frame | Exact payload |
| --- | --- |
| `0x06 META` | `[request_id, object_type, body]`; types 0/1 are framed head/context bytes, 2 is `[proof_kind, proof]`, 3 is signed entry-header bytes |
| `0x07 CHUNK` | `[request_id, entry_hash, offset, bytes]` |
| `0x08 DONE` | `[request_id, status, continuation]` |
| `0x09 CANCEL` | `[request_id]` |
| `0x0A ACK` | `[request_id, entry_hash, next_persisted_offset]` |

CHUNK bytes are raw payload bytes, with offsets relative to the signed `payload_len`; the
signed header must arrive first. For encrypted content these are the existing ciphertext bytes.
Only the complete payload hash plus signature/admission checks permit assembly into the existing
canonical full entry record. Partial chunks are not individually authenticated by the final hash.
Each direction permits at most one outstanding chunk of at most 64 KiB. The receiver sends ACK
only after persisting that exact next offset. A duplicate ACK adds no credit; a wrong hash,
request or offset rejects the response. An ACK grants only another chunk within this already
authorized response's remaining byte credit. It does not authorize a new quantum or page.
Check cancellation and deadlines around credit waits. Withheld credit cannot hold an actor lock.

DONE status 0/1/2/3/4/5/6 means complete/more/required-evidence-unavailable/body-not-held/busy/
cancelled/control-pending. Body-not-held is not an authenticated expiry claim; local retention
and first-seen rules still decide that. Continuation is `[]` or
`[query_kind, HeadID, lo, hi, next_seq, entry_hash_option, offset, entries_remaining]`, where
`entry_hash_option` is `[]` or `[hash]`. The receiver recomputes its limits from its persisted
original operation. Duplicate chunk bytes are idempotent only if they match. Completion of a
large entry does not authorize the next page. Existing hard errors retain their meaning; new
WireError `0x10 ProtocolLimits` reports malformed/oversize input, not ordinary budget exhaustion.
Reserved error `0x06` stays reserved.

**Hard work and memory bounds.** A response quantum is at most 1 MiB, counting every frame's
four-byte prefix, CBOR, request ID, proof/context/signature and chunk bytes, but excluding QUIC/
UDP headers. Reserve 512 bytes of that quantum for DONE. One logical page authorizes at most
128 new entry headers; continuations carry the remaining count, not a reset count. A frame or
proof object is at most 256 KiB. Work yields after the first of four composite verifications,
32 descriptor reconstructions or 65,536 frontier-coordinate visits. One indivisible signature
operation may finish; join/proof cursors must resume rather than restart their completed work.
Persist through existing at-most-64-row/1-MiB commit slices. Missing essential control may require
multiple such slices, but cannot monopolize the node actor or turn into ordinary archive demand.

The locally authored append has a separate, private `LocalAppendBudget`: it preserves the
existing atomic sender-state/entry commit without replaying a partly executed user command.
Its exact signature, descriptor, context-visit and object-load limits MUST be derived from
`MAX_TREE_DEPTH` and `MAX_CONTEXT_AUTHORS`, including pre-context construction and every reused
inclusion/consistency verification pass. It uses the same authentication predicates and only
durable, already authenticated parents. It MUST NOT fetch, scan an archive, reset a spent budget
or expose this quota to a remote verification path. A missing own-parent object or exhausted
derived quota is an invariant/storage failure, never permission to retry encryption or commit a
partial append. New leaf-dependent descriptors, head, entry and sender state commit atomically;
unchanged context objects are shared by hash. Intermediate context maps MUST NOT accumulate.
The numerical bound is not a latency claim: a bounded diagnostic spike must establish the cost
before activation, and expensive execution must stay off the shared node actor. This exception
does not alter the remote 4/32/65,536 verification slices or authorize legacy conversion.

The transient application-buffer contract is **288 MiB across the daemon**: 192 MiB archive
(two jobs of at most 96 MiB each, at most one per node, serving and receiving combined), plus
96 MiB reserved for live/control. Within the reserve, 8 MiB guarantees small control progress
and at most 88 MiB supports a large live/control record, with control-priority admission. A legal
16-MiB control body is not restricted to the small 8-MiB pool; it must acquire that large-record
envelope rather than deadlock or consume archive capacity. Archive jobs use at most one full
entry at a time; the enforceable buffer envelope is `5 * MAX_ENTRY_WIRE + 4 MiB < 88 MiB`.
Every real allocation/copy must fit an acquired permit, including ciphertext reads, plaintext,
parsed payload, serialization and sealing copies. Drop obsolete copies between phases. This
is a transient-buffer budget, not a measured RSS claim: bounded store/page caches and transport
windows/queues remain separate. Acquire before allocation outside actor/room locks, and release
only when the actual worker and buffers are gone. Archive transport credit must respect the
single-chunk rule, not queue full windows behind the application permits.

The fair archive wait queue holds at most 64 node requests, one coalesced pending request per
node; excess work returns busy. Per node, only one unfinished archive operation, including
paused staging, is retained; a new one must reuse it or require explicit cancellation. At most
one incomplete 16-MiB entry body is staged for that operation. Private stream 13 retains its
96-KiB record bound but caps each serialized page at 1 MiB, uses the shared admission budget,
and requires explicit further demand instead of `more`/periodic draining. Its current Drive,
grant generation and audience checks run on every request.

### H-7. Durable state, publication and bounded demand

A per-`(room, scope, author)` record must distinguish these states; they are not synonyms:

1. **Observed:** a valid author-signed head is a hint. It establishes no continuity or authority.
2. **Committed:** valid consistency advances a previously accepted descriptor. This establishes
   append-only commitment, not semantic validity of all omitted leaves.
3. **Control pending/ready:** exact-head interval coverage, parent receipts and control dependencies
   are accumulated durably. Ready requires complete applicable evidence and existing deterministic
   governance checks. Exhausted budgets and missing bodies never count as completed denial.
4. **Individually admitted:** exact inclusion, required control closure and existing entry/body
   checks pass. Such an entry may occupy a sparse position without changing the contiguous head.
5. **Contiguous:** the existing feed's actually validated gap-free prefix. Never set it to an
   observed, committed or sparse tip.

A failed relay proof rejects that response, not the alleged author's identity. Attributable
contradictions retain raw signed evidence and apply existing fork restrictions to the implicated
author/branch. Reuse immutable proof results only under their exact authenticated bindings;
recheck current local trust, fork restrictions, Drive generation and authority at action/use.
Publish entry admission, derived control/render/order roots and obligation progress atomically.
Unfinished work uses unpublished roots. A cancellation leaves already accepted cached rows intact.

Use existing sealed segments and EntryIndex B-trees, adding only the roots/values needed for:

- content-addressed head, context and proof objects, plus `(author, tree range) -> descriptor`;
- `(author, seq) -> header/locator/admission flags`, independently of the contiguous feed;
- accepted commitments, exact-head verified control intervals, receipt/dependency obligations
  and missing position/body intervals;
- explicit local demand and provisional chunk records keyed to request/entry/offset.

The existing LogDb remains canonical complete entry bytes. A partial chunk's sealed provisional
segment is not a canonical locator. Context objects up to 160 KiB reuse the existing sealed
segment allocator; they are not forced into a 16-KiB index page or a new database. Root-swap
publication uses the existing transaction/Directory boundary. Full signed heads and frontier
maps must not be embedded in the at-most-1-MiB Directory or restart capsule: retain compact IDs,
flags and root references, then read objects lazily. `PublishedFeed` continues to mean the
actual contiguous prefix. Warm restart reads compact accepted state, reevaluates current local
trust and starts only required control/live work; it does not scan all message bodies or resume
an unfinished archive operation automatically.

Bound unverified/pending state as well as accepted pages. At most one current observed-head
reference per admitted author (2,048 author cap) is resident; additional signed evidence is
stored lazily with its exact attributable bindings. At most 4,096 unresolved dependency keys per
room are admitted at once; additional work remains pending before allocation. A process-wide
lazy object cache is at most 64 objects and 4 MiB, subject to the shared buffer permits. Neither
an unlimited pending-head map nor a restart-time load of all proof/context objects is permitted.
Discarding an unaccepted relay hint to stay within a bound does not discard accepted evidence.

An archive operation progresses through explicit local demand, cache lookup, bounded missing
interval selection, fair permit wait, a single quantum and complete/more/pending/unavailable/
cancelled. Persist its node/room instance, audience/grant generation, HeadID, interval/count
limits, current entry/hash/length and persisted offset. Explicit resume rechecks authority and
cannot widen that operation. ACK only grants within-quantum persisted-offset credit. Expiration
or cancellation releases actual worker resources; retained state cannot secretly restart traffic.

Keep existing cache-only APIs cache-only: `RoomPage`/`RoomViewPage`, watch refresh, retained row
selection and notices must not acquire remote history as a side effect. CLI explicit newest/
older operations and app Load older initiate the separately identified bounded demand; their
cache read remains usable while fetch state is pending. IPC's existing frame and row-byte caps
still apply, even where tighter than the network quantum. Large cached bodies must not be copied
into every row/window merely because their wire transfer completed.

### H-8. Sparse order and implementation boundaries

Sparse delivery must not silently place a new tail behind the visible window because its own
immediate predecessor is absent. It also must not fetch all old ancestry just to calculate an
order. An authenticated receipt proves identity and control context, not a recursively evaluated
HLC; do not add a signed claimed HLC and describe it as a verified full-history clock.

For the v2 held set, derive ordering from held explicit `seen` parents, verified control-context
coordinates and the nearest held lower position of the same author. The latter is a temporary
transitive order edge when the exact own predecessor is absent, not proof that the gap is held
or individually valid. An immutable context's maximum held clock may be cached only with the
sealed order revision; it is a local display aggregate, never authenticated authority.

When a gap fills, atomically splice the held same-author predecessor/new-entry/successor edges,
removing the superseded temporary predecessor-to-successor edge. Recompute affected clocks in
**both directions**, not only increases, using bounded durable work and atomic root publication.
The no-held-parent genesis fallback can exceed a later supplied parent's capped clock, so an
increase-only implementation is not a function of the final held set. Preserve first-seen times,
retention, arrival cursors and late-row rules during reordering. Every node with the same held
entry set and required authenticated context must converge to the same `(clock, hash)` order.

Fresh delivery remains visible through the existing arrival cursor even when its provisional
chronological position is above the current page. Retain a bounded arrival-visible view of at
most 128 row references/summaries and at most 1 MiB serialized row data, subject to the existing
tighter IPC limits; do not retain duplicate large bodies. On overflow, preserve the unconsumed
arrival cursor and show the remaining unread/older count. Never silently advance past unseen
rows, force late entries to the bottom or fabricate a contiguous position. Missing ordering
ancestry and pending mandatory control are distinct UI states. Ordinary order gaps initiate no
network request. The app's explicit page/window retention follows the same bounds.

The smallest implementation packages and their handoff are:

| Package | Existing seams and owned result |
| --- | --- |
| Codec and proof foundation | `wire.rs`, `cbor.rs`, `log/entry.rs`, and focused log context/tree/proof code integrated with those types. Versioned entry codec, typed dispatch, head/context/descriptor formats and bounded pure proof verification; no network or authority side effects. Return missing-object obligations explicitly. |
| Admission and durable state | `log/feed.rs`, channel admission/governance, `entry_store.rs`, `entry_store/restart.rs` and DAG/order facts. Preserve contiguous Feed; add durable sparse/committed/control state and atomic publication/gap splice. No whole-body restart scan. |
| Transport and shared scheduling | `log/sync.rs`, `node/syncstream.rs`, `transport/framing.rs`, `transport/stream_transport.rs`, actor/ports and host defaults. Lazy frame production, allocation permits, ACK credit, explicit demand and removal of public/private automatic archive continuation. The host shares one budget across its nodes. |
| User demand and display | Existing IPC, `room_cli.rs`, FFI page calls and `NodeModel.readOlderTimeline`. Separate explicit fetch from cache queries, preserve instance/request stale-result guards, and bound the arrival-visible window. |

The foundation API must take exact bindings and bounded borrowed input: decode header/context/
head; compute leaf/join descriptor; verify inclusion/consistency/control interval; verify a
parent receipt; and return verified values or explicit missing-object/invalid/limit outcomes.
It must not retrieve data, advance a feed, apply governance or publish rows. The integration
owner performs those transitions in the existing store transaction. Do not create an unused
parallel log implementation while leaving the actual EntrySkeleton/sync path on v1 assumptions.

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

The integration owner accepted the concrete new-format contract after that adjudication, including
explicit persisted-offset ACK credit, the 288-MiB transient-buffer contract and sparse clock
recomputation in both directions. No additional whole-plan review cycle is required before
new-format implementation; changed code still requires its scoped review and user-facing proof.
Legacy activation remains a separate unresolved operator decision.

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
another release. The new-format contract in H-6–H-8 may be implemented independently. Existing-format activation
remains blocked on that decision and MUST NOT be silently enabled by implementing the new codec,
by an upgrade, or by opening a node. All H-1–H-8 obligations remain in v0.4.6; this separation is
not permission to ship a known defect or defer the legacy decision.

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
- [ADR-023: room lifecycle and ordering](ADR-023-room-lifecycle.md)
- [ADR-025: sync scheduling](ADR-025-sync-scheduling-switch-not-hub.md)
- [ADR-026: daemon and nodes](ADR-026-daemon-and-nodes.md)
- [ADR-031: agent setup and private Session history](ADR-031-agent-nodes-join-a-repo-room-by-themselves.md)
