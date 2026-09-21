# ADR-007: Membership, Per-Sender Consent, and Admin Governance

**Status**: implemented (M6, `crates/vox-core/src/governance/`)
**Date**: 2026-06-19
**Updated**: 2026-09-21 (later the same day) — **per-sender consent now carries service authorization.** A room-bound service is reachable by exactly the members its host has consented to for reading (ADR-017 decision 3, revised), so the outbound-consent machinery below is load-bearing for reach as well as readability, and a consent revocation withdraws both. The **genesis service grant and its `service-grant-exclusion` (`0x0013`) are withdrawn**; `0x0013` is retired and not reused. Earlier the same day — the genesis body gains a **service grant** (ADR-017 decision 3: capabilities conferred on every admitted member, no certificate issued to anyone) and a new **`service-grant-exclusion`** (`0x0013`) takes it back per member, which is what keeps a capability-bearing room from being a one-way door. **Per-member consent revocation is live** (M18.1): `vox`'s `revoke` verb rotates the
sender key, records the `consent-revocation` fact and re-keys the remaining consenters; it needs no
network, and a release gate proves the revoked member reads nothing afterwards while the others lose
nothing. 2026-09-20 — the join/consent flow now has a runtime: joiner-side channel state, author admission as a log fact, and consent grants appended and evaluated (`node::channel`, ADR-016 M14.5). 2026-09-19 — Implementation notes (M6) added; denied verdicts now carry the classified reason (expired / revoked / over-attenuated) instead of collapsing to "not admin"; genesis policy and policy-update carry the ADR-003 `min_suite` floor.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: consent, membership, admin, governance, revocation, capabilities, differentiator

## Context

This is Vox's headline differentiator (ADR-001), designed against the Signalgate failure: in
Signal/Matrix/WhatsApp, group membership is not cryptographically authenticated, so one wrong add
exposes all future traffic. Vox makes admission a *per-member, per-sender* cryptographic decision
with no central authority, while providing workable, verifiable admin and policy in a serverless
setting. It is built on identity (ADR-002), channel join (ADR-005), Sender Keys (ADR-006), and the
causal log (ADR-008), and is validated against the Megolm membership-control attacks (Albrecht et
al., IEEE S&P 2023; eprint 2023/1300). This ADR specifies the complete governance protocol: the
trust anchor, the certificate/grant schema, the consent and revocation flows, and conflict
resolution under partition.

## Decision

### Trust anchor: the genesis capability

A channel begins with a **genesis record** — its own canonical struct (ADR-008 tag `0x000D`, domain
`vox/genesis/v1`), **not** a generic governance cert — with this pinned, ordered field list:
`{ nonce(16 B random), created(uint epoch-seconds), policy{ history_mode(enum), deniability_mode(enum),
ttl(uint seconds, 0=never) }, creator_pubkey(composite, ADR-002), algo_ids }`, self-signed by the
creator's composite identity key. The **`channelID` is defined as `SHA-256(canonical genesis record)`**
— so it is 256-bit, high-entropy (the nonce guarantees it), self-certifying, and bound to exactly one
genesis: a cold-joining node fetches the genesis from the rendezvous (ADR-012) and accepts it **only if
its hash equals the `channelID`** it joined with. Because the field order/encoding is pinned, every
implementation derives the *same* channelID from the same logical genesis. The genesis hash is thus
simultaneously the channelID, the rendezvous seed (ADR-005), and the root of every certificate chain;
every authority claim must verify back to it. The creator is **root admin** (holds `admin`, below).

### Certificate and grant schema

All of the following are signed entries on the causal log (ADR-008). Each carries: author
identity, `(channelID, epoch)` binding (ADR-006), monotonic per-author sequence number, parent
hash-links, the issuer's certificate chain reference, and a composite Ed25519+ML-DSA signature
(ADR-002/ADR-003).

**Canonical encoding & evaluator (required for interop and safety).** Every certificate/grant has a
**deterministic canonical serialization** (a single, versioned, canonical-CBOR layout with fixed field
order and a type tag) signed under a **per-type domain-separation string** (e.g. `vox/cert/admin-deleg/v1`).
Authorization is decided by a **single deterministic evaluator** — input: the requester's cert chain +
the channel's current log state; output: granted/denied + the governing capability — specified with a
mandatory suite of **golden test vectors** (valid chains, over-attenuation, expiry, revoked links,
concurrent-conflict cases). Two correct implementations MUST agree bit-for-bit on every vector; this is
a release gate for the governance layer (not an open detail).

**Capability vocabulary (closed set — the evaluator's entire domain).** The evaluator recognizes
exactly these capabilities, ordered by the attenuation lattice (a delegation may grant only
capabilities at or below its own; unknown capability types are a verification failure):
- `admin` — full governance; implies every capability below. Held by the root admin from genesis.
- `delegate` — may issue admin-delegation certs (attenuable; never exceeding the issuer's set).
- `invite` — may issue identity-bound invites (ADR-005).
- `policy` — may author policy-update entries (history / deniability / TTL).
- `passphrase-rotate` — may author passphrase-rotation (epoch) entries.
- **~~Tunnel capabilities, registered by ADR-013 into *this* lattice~~ — withdrawn 2026-09-21.**
  `bind:<service-tag>` (advertise/host) and `dial:<service-tag>` (consume), plus attenuable **role-tag
  attributes** (e.g. `#ops`, `#ssh-hosts`), are **no longer the authorization for a room-bound service**;
  ADR-017 decision 3 makes that the host's explicit per-sender consent. `dial:` goes because consent
  replaces it. **`bind:` goes because offering a port of one's own machine is not the room's business** —
  `add_service`'s `can_bind` check had exactly two sources of the capability, the genesis grant and
  `vox grant --may-bind`, and withdrawing both while keeping the check would have left `vox serve` working
  only for a room's creator. Independent review found that on all three reads; it was an accident rather
  than a decision, and the decision is that there is no such capability.

  Both tags **remain decodable** so that existing logs and genesis bodies still parse and keep their
  channelIDs (ADR-017 decision 11); neither is consulted. ADR-013's ABAC role-tag policies go with them,
  unbuilt and now unneeded — ADR-013 still adds **no** parallel authorization engine, and after this there
  is one authorization input rather than two.
New capability types are added only here (versioned), preserving the single-evaluator guarantee.

- **Admin delegation cert** — issued by an admin, names a delegate identity key and the granted
  capability set, optionally *attenuated* (e.g. `invite` but not `delegate`) and optionally with an
  expiry. Delegations chain to genesis, forming an SPKI/SDSI/UCAN-style capability tree the client
  verifies independently. No capability can exceed its issuer's (monotonic attenuation).
- **Consent grant** — issued by an *individual member* `A`, names a target `N`, and is the act of
  releasing `A`'s Sender Key to `N`: `A` encrypts the appropriate SKDM (ADR-006) to `N` over their
  pairwise channel (ADR-004) — the *current* iteration in forward-only channels, or the *origin*
  iteration in full-history channels so `N` can read `A`'s retained history — and records a
  consent-grant entry. This is the per-sender consent
  primitive — entirely `A`'s decision, authored only by `A`. **Membership is emergent, not an admin
  cert:** you are in the swarm by holding the passphrase (ADR-005), and you are *readable* by whoever
  has consent-granted to you. There is no admin-issued membership certificate and no admin-maintained
  member roster.
- **Consent revocation** *(outbound — "should a given member see messages from me?")* — member `A`
  withdraws `N`'s access to `A`'s *future* messages; authored only by `A`, it rotates `A`'s own sender
  key (`chain_id`) excluding `N` (below). There is **no admin per-member removal** — an admin removes
  people only by rotating the channel passphrase (bulk; below).
- **Visibility opt-out** *(inbound — "do I want to see messages from them?")* — a **separate,
  purely receiver-side** control: `A` chooses to stop seeing `B`'s messages by discarding/ignoring
  `B`'s sender key and not rendering `B`. It needs no cooperation from `B`, creates **no governance
  entry** (it affects only `A`'s own view), and is reversible while `B` still consents to `A`. This is
  fully independent of outbound consent — the two functions answer two different questions ("who may
  read me" vs "whom do I read") and are set independently per member.
- **Policy update** — issued by a `policy`-capability holder, changes **history-mode and TTL** from its
  causal position forward. **The deniability axis is genesis-immutable:** `deniability_mode` is set once
  in the genesis record and a policy-update MUST NOT change it (an evaluator rejects a policy-update that
  attempts to). Rationale: members join under a fixed authorship-accountability contract; flipping
  attributable↔deniable mid-life would change the threat model under existing members and the
  fork-handling split (ADR-008). History/TTL are retention conveniences with no such trust-contract
  inversion, so they stay mutable.

**Per-type body schemas (pinned, so the golden-vector gate is writable).** Beyond the common envelope
above, each governance struct has this canonical body (ADR-008 tags in parentheses):
- **admin-delegation cert** (`0x0003`): `{ delegate_pubkey(composite), capability_set[], expiry?(uint) }`.
- **admin-delegation-revocation** (`0x000E`): `{ revoked_delegation_hash(32 B), reason?(enum) }` — the
  first-class revocation the conflict rules below reference; removal-wins, ordered by the tie-break.
- **consent-grant** (`0x0004`): `{ target_id(composite fpr), skdm_ref(32 B hash of the SKDM delivered
  over ADR-004), history_mode_at_grant }` — the SKDM itself travels in the pairwise session, not inline;
  the entry carries only its hash.
- **consent-revocation** (`0x0005`): `{ target_id(composite fpr), new_chain_id }`.
- ~~**service-grant-exclusion** (`0x0013`)~~ — **added and withdrawn 2026-09-21.** It withdrew the genesis
  **service grant** from one member. Both it and the grant are withdrawn by ADR-017 decision 3 as revised:
  authorization for a room-bound service is the host's **per-sender consent**, so there is no
  membership-conferred capability left to exclude anyone from. **The wire tag `0x0013` is retired and must
  not be reused**, so that a node holding an old log cannot have a retired entry reinterpreted as something
  else.
- **policy-update** (`0x0006`): `{ history_mode?, ttl? }` (never `deniability_mode`).

### Invite modes (how a joiner's identity is known — no admin "admit" step)

How a newcomer's identity is established, chosen by whoever shares the channel. Neither mode involves
an admin admitting anyone — membership is consent-based:
- **Identity-bound invite (high-trust default).** The out-of-band invite names the newcomer's identity
  fingerprint, so members know which identity to expect and verify before consent-granting. The joiner
  is recognized on arrival.
- **Open passphrase join.** Anyone with `channelID + passphrase` joins the swarm (ADR-005) and appears
  to members as an *unverified* self-asserted identity (shown explicitly as unverified, ADR-014).
  Members verify the fingerprint and consent at will; until a member consents, the joiner reads only
  that member's ciphertext.

The passphrase gates the swarm; per-sender consent gates reading. There is no admin admission.

### Join and per-sender consent flow

1. `N` joins via CPace (ADR-005) and establishes pairwise PQXDH sessions (ADR-004) with members it
   meets. Holding channel credentials yields **no** sender keys — `N` can read nothing yet (and shows
   as an unverified identity until members verify it).
2. **`N` independently decides which members may read `N`** and issues a consent grant to each — sending
   `N`'s SKDM to exactly those. Until `N` does so for `A`, `N`'s messages are undecryptable to `A`,
   forever if `N` never chooses `A`. This is **fully symmetric to step 3** and is a deliberate human act,
   not a side effect of joining.

   **Revised 2026-09-21**, in two places. This step previously read *"`N` broadcasts its own SKDM to
   members (it has nothing to consent over; whether others can read `N` is each member's own decision)"* —
   whose parenthetical has the direction backwards: whether others may read `N` is **`N`'s** decision, and
   the only thing that is each member's own decision is whether `N` may read *them* (step 3). And the
   implementation was narrower and worse than either reading: `join` released `N`'s sender key to **the
   single member that answered the join** and recorded it as an ordinary consent grant
   (`node/actor.rs:1764` → `:1835`), with the recipient chosen from the board (`:1603`) and therefore
   influenceable by whoever supplied the link. ADR-017 decision 3 makes that consent load-bearing for
   *service reach*, so an automatic grant there would have handed a service to a party no human approved.
   The automatic release is removed (ADR-017 M17.6). The decider's statement of the rule:

   > *"A new node joins. They will need to approve who they want to share with of the people that are
   > already in the room. Once they do that, when this new node writes something to the room then the
   > people that they approved should be able to read messages from the new node. However, of the people
   > already in the room, anything that they write will not be readable by the new node until the new node
   > has been approved by the existing node."*

3. Each existing member `A` independently decides whether to consent. On consent, `A` issues a
   **consent grant** (sends `A`'s SKDM to `N`). Until `A` does so, `A`'s messages remain undecryptable
   to `N` — forever if `A` never consents. `N`'s readable view fills in **monotonically, per sender**.

Because possession of credentials releases no keys, and readability is granted only by each party's own
consent grant (no admin admission, no central roster), there is no server-controlled member list to forge
— the Signalgate / Megolm membership-injection class is structurally absent. *Until 2026-09-21 the first
clause was not true of the implementation: joining released one sender key automatically (step 2).*

**Consent now carries service reach.** Under ADR-017 decision 3 a consent grant also authorizes the
grantee to reach every service its grantor has bound to that room. Two consequences are binding here:
the consent UI must say so at the moment of granting, and **only consent issued by an explicit human act
qualifies** — which is why step 2's automatic release had to go rather than be marked.

### The genesis service grant, and taking it back (ADR-017 decision 3)

The genesis body may carry a **service grant**: a capability set conferred on every identity a node has
admitted as an author of the channel, **with no certificate issued to anyone**. It exists to delete the
worst step in offering a room-bound service — the host waiting for a guest to appear and then granting
them something. The authorization basis is the one on which the joiner became a member at all: they held
the passphrase and paid the ADR-005 proof of work, and in a room whose purpose *is* the service, "may this
member dial it" and "is this person a member" are the same question.

Four properties make it safe, and all four are normative:

1. **Only `dial:` and `bind:` may appear**, at most `MAX_SERVICE_GRANT = 16` of them, validated at
   creation and on decode. A genesis conferring `admin`, `delegate`, `policy`, `passphrase-rotate` or a
   `#role` on every member would make membership permanently equal to control of the channel, and the
   genesis is immutable — no later governance could undo it. A `#role` is excluded for the subtler reason
   that a role is an attribute other certificates attenuate *from*.
2. **It is genesis-immutable**, being part of the signed body and therefore of the channelID. A chat room
   cannot silently *become* an access list, and a service room cannot stop being one. The two shapes are
   different rooms, deliberately.
3. **"Member" is this node's own admitted-author set.** Membership is emergent and there is no roster
   (above), so who is a member is necessarily local state — and that is sound because the decision it
   feeds is local too: a host serving its own service consults the keys it verified itself, and refuses
   anyone it has not (fail closed). An evaluator built without a member set confers nothing, which is the
   safe default for any caller that does not know who the members are.
4. **~~It is revocable per member, by a `service-grant-exclusion` (`0x0013`).~~ Withdrawn with the grant
   itself (ADR-017 decision 3, revised 2026-09-21); the reasoning is kept because it is the record of why
   the mechanism existed, and its last sentence is the statement of verified finding #5.** This is not a
   convenience.
   ADR-007's admin-delegation-revocation names *the entry hash of a delegation*, and a genesis grant
   issues no delegation — so without a fact that names the **identity**, adding a genesis grant would
   *remove* the per-member control the channel already had, since an explicit certificate can always be
   revoked. An exclusion suppresses **only** the genesis-conferred capabilities: a certificate issued to
   the same identity is governed by its own revocation, so an admin who excludes a member and then
   deliberately certifies them again has done exactly that, and the later explicit act stands. Exclusion
   is one-way within an epoch (there is no un-exclude entry); a passphrase rotation clears every exclusion
   along with every certificate, and the room starts again from its genesis.

### Revocation and epochs

- **Outbound consent revocation ("who may read me"):** `A` generates a fresh sender key, **advancing
  `A`'s own `chain_id`** (the per-author generation counter, ADR-006) — *not* the channel `epoch`. `A`
  distributes the new key to all members `A` still consents to *except* the revoked `N`, and records a
  revocation entry. `N` retains previously-held keys (uncallable) but cannot decrypt `A`'s future
  messages. **Revocation is rotation with one member left out** — there is no second mechanism, and the
  rotation *is* the enforcement.

  Three properties of the runtime are normative (M18.1, `ChannelState::revoke_consent`):
  1. **The rotation and the log fact land first, unconditionally.** They are purely local: revoking
     needs no network and no peer to be reachable, and a revocation that waited for the rest of the room
     to come online would be a revocation in name only. The re-keys follow best-effort and are retried
     by the node's tick.
  2. **The entry names the generation that excludes `N`,** so `new_chain_id` is filled from a generation
     that already exists; the fact cannot promise a rotation that failed to happen.
  3. **The remaining consenters lose nothing, including the ones who were away.** They are re-keyed at
     the new generation's *origin*, not at `A`'s current position, so a rotation is invisible to whoever
     keeps consent (ADR-006 §"A rotation retains the new generation's origin key"). (Terminology, normative: **`epoch` is a single channel-global counter** set only by the
  genesis record and admin policy/passphrase-rotation entries; per-author rotation is always
  `chain_id`. There is no per-author "epoch contribution.")
- **Inbound visibility opt-out ("whom I read"):** independently of the above, `A` may stop *seeing* any
  sender `B` by dropping `B`'s sender key from `A`'s active set and not rendering `B`. This is local to
  `A` — **no log entry, no key rotation, no effect on others** — and reversible while `B` still
  consents to `A`. Outbound consent and inbound visibility are orthogonal and independently set.
- **Passphrase rotation (the only admin-side removal — bulk).** An admin changes the channel
  passphrase (ADR-005), incrementing the channel `epoch`. **All members must rejoin with the new
  passphrase**; anyone not given it is thereby evicted. This is the clean epoch boundary that re-binds
  all sender keys to the new `(channelID, epoch)` (ADR-006). It is deliberately **all-or-nothing**:
  there is no admin facility to remove one member. Targeted removal is member-driven — each member who
  no longer wants `N` reading them simply revokes consent (above); to force `N` out of the swarm
  entirely, the admin rotates the passphrase.

### Conflict resolution under partition

Governance state lives on the causal Merkle-DAG (ADR-008), which converges without consensus, and
relies on ADR-008's **fork/equivocation handling** (signed heads, durable fork proofs, equivocator
freeze). Partition-time authority actions are therefore **provisional until their causal neighborhood
reconciles** (ADR-008). The model is chosen so most actions never truly conflict:

- **Consent is single-writer.** Only `A` authors `A`'s consent grants and `A`'s sender-key rotations,
  so `A`'s consent timeline is totally ordered within `A`'s own log. There is no cross-writer race on
  "can `N` read `A`."
- **Additive facts merge freely.** Consent grants and admin delegations are add-only; concurrent ones
  all stand and are ordered causally.
- **Removal beats addition (fail-safe), where removal exists.** The only removals are (a) a member's
  own *consent revocation* and (b) an *admin-delegation revocation*. Consent has no race — it is
  single-writer (`A` alone authors `A`'s grants and revocations), so `A`'s latest causal state wins.
  For admin delegation, when a revocation is concurrent with or after a delegation of the same key,
  that key is treated as **not-an-admin** until a causally-later re-delegation (revocation wins). There
  is **no membership add/remove race**, because there is no admin membership operation — membership is
  emergent (join + consent), and bulk removal is passphrase rotation, which is a clean epoch boundary,
  not a per-member race.
- **Admin authority is monotonic + revocable.** A key is an admin iff some valid delegation chain to
  genesis grants it and no causally-later authorized revocation supersedes it; ties resolve by the
  same removal-wins rule. Attenuation prevents privilege escalation regardless of ordering.
- **Deterministic total tie-break (required for the bit-for-bit guarantee).** Causal order is partial,
  so two concurrent, causally-unordered entries (e.g. two delegations of different attenuations to the
  same key with no link between them) need a tie-break for all clients to converge identically. After
  the removal-wins rule, the evaluator orders any remaining concurrent entries by the **canonical
  total order** (Kahn's algorithm over the causal relation, smallest ready entry hash first — in the
  common case simply ascending entry hash, `SHA-256` of the canonical entry, ADR-008; see
  Implementation notes) and takes the last. This makes the evaluator a
  total function of log state — the precondition for the golden-vector equality gate above.

### Enforcement honesty

Only **forward** guarantees are cryptographic: rotating to keys a party never receives is enforceable;
recalling keys a party already holds is not, and TTL/erasure (ADR-010) is client-honored. That
members who were previously consented-to can still read traffic they already hold keys for is an
accepted, documented property of the threat model — not a defect to paper over.

## Consequences

### Positive
- Eliminates the Signalgate single-wrong-add exposure by construction — the core product promise.
- Fully serverless, client-verifiable governance: every authority claim chains to genesis.
- Per-sender, monotonic visibility is expressible precisely because consent is single-writer over
  per-author Sender Keys (ADR-006), and converges cleanly on the causal log.

### Negative
- Per-member revocation costs O(remaining consented members) of SKDM redistribution; a passphrase
  epoch is a full re-admission/re-consent cycle — strong but expensive as membership grows.
- "Removal wins" can transiently hide a legitimately re-added member until a causally-later re-grant
  propagates; acceptable as the fail-safe direction.
- Admin reintroduces a delegated (signed, non-server) authority that must be implemented with strict
  attenuation and chain verification.

### Neutral
- All governance state is ordinary signed log content (ADR-008); deniable channels (ADR-009) change
  message-content signing but not the governance plane, which stays attributable.

## Implementation notes (M6)

These record the concrete decisions made building this ADR (`crates/vox-core/src/governance/`), so the spec and code stay in lockstep:

- **Denied verdicts name the reason.** `Evaluator::grants` returns `Verdict::Denied(DenyReason)` where
  the reason is classified by the resolver, not inferred after the fact: for a key with no effective
  authority, every in-scope delegation naming it is classified — killed by an authorized revocation
  (removal-wins) → `Revoked`; past `expiry` at `now_secs` → `Expired`; issuer holds a chain but the
  granted set is not within it → `OverAttenuated`; issuer holds no chain, or the cert is bound to an
  epoch not in force → `NotAdmin` — and the highest-priority reason wins
  (`Revoked` > `Expired` > `OverAttenuated` > `NotAdmin`; a deliberate removal outranks a passive lapse,
  which outranks a void cert). A key never named as a delegate is plain `NotAdmin`; a key with a
  chain that lacks the queried capability is `CapabilityNotHeld`. The golden-vector suite pins the
  exact reason for the over-attenuation, expiry and revoked-link vectors and for the priority rule.
  *(2026-09-19 review: `Expired`/`Revoked`/`OverAttenuated` were declared but never emitted —
  everything collapsed to `NotAdmin`, contradicting the "golden vectors can pin the exact reason"
  intent.)*
- **Genesis policy carries the ciphersuite floor (ADR-003).** The genesis canonical body is
  `[nonce, created, [history_mode, deniability_mode, ttl, min_suite], [service_grant_token…],
  creator_pubkey, [sign_algo]]` (`service_grant` added 2026-09-21, ADR-017 decision 3 — see below);
  `min_suite` must name a registered suite (validated at creation and on decode) and, being part of
  the signed body, is bound into the channelID. The policy-update body (`0x0006`, kind 1) is
  `[kind, channelID, epoch, issuer_id, history_present, history_mode?, ttl_present, ttl?,
  suite_present, min_suite?]`; the evaluator applies `min_suite` **raise-only** (see ADR-003
  Implementation notes). `ChannelPolicy::suite_floor()` yields the typed `SuiteFloor` handshakes take.
  *(2026-09-19; wire-format change, no channels shipped.)*
- **Concurrent-conflict tie-break is the canonical order, not a literal hash sort.** Among the
  causally-maximal concurrent delegations of a delegate, the governing one is the **last in the
  canonical total order** — Kahn's algorithm over the causal relation, always emitting the
  smallest-hash ready entry (`Causality::build`). That equals "ascending entry hash" when the
  candidates become ready together and can differ when their predecessors differ; both rules are
  deterministic, and the canonical order is **normative** (an independent implementation must
  reproduce `Causality::build`'s order to agree bit-for-bit). *(Recorded 2026-09-19 to reconcile the
  Decision text above with the code; the golden vectors pin the code's rule.)*
- **The join/consent flow runs (ADR-016 M14.5).** §"Join and per-sender consent flow" is now executable
  in `node::channel`, and the separation it rests on is explicit in the code: **log authorship and read
  authority are different things.** `ChannelState::join_channel` builds a joiner's local state from a
  genesis fetched off the board, accepting it **only if its hash equals the channelID joined with** —
  that check, not any roster, is what makes a cold-fetched genesis safe — and gives the joiner its own
  local SEK and its own sender chain at `chain_id` 0. `admit_author` then records a verified composite key
  as a log author (persisted in a new sealed `SEG_AUTHORS` segment, ADR-010), which lets that identity's
  entries pass the ADR-008 predicate and **nothing more**: a content entry from an admitted author is
  stored as ciphertext and never rendered, because rendering needs that author's sender key. Keys come
  from the verified genesis, admin certificates, or the board's records (ADR-016), never from a
  server-supplied list — the membership-injection class stays structurally absent. `issue_consent` builds
  the grant with the `skdm_ref` of the SKDM actually delivered plus the history mode in force, appends it
  as a **governance** entry, and folds it into the evaluator, so consent is a log fact both sides
  evaluate independently; `may_read` is the resulting per-sender verdict. A test walks it: Bob joins, each
  side admits the other, Alice's message crosses and is unreadable, her grant crosses and flips only
  `Alice → Bob` (consent is per-sender, not mutual), and all of it survives a reopen.
- **History is the consenting member's choice, per grant (decider, 2026-09-21).** The Decision treats
  history mode as **channel policy** (set in the genesis, changed by a `policy`-capability holder). The
  decider has narrowed it: *"each existing member, as they accept the new member, should individually
  make that decision, and it should only impact messages they shared to the room."*
  This is a better fit for the mechanism than the policy reading, and the data already has the shape:
  a member's consent releases **that member's own** sender key and nothing else, so whether the newcomer
  receives the *current* key (forward-only) or the *origin* key (that member's retained history) is
  inherently a per-member, per-grant decision — and `ConsentGrant.history_mode_at_grant` already records
  it per grant. What was missing is only that the node passes the channel policy instead of letting the
  consenter choose.
  The channel policy therefore becomes the **default** a client offers, not a constraint it enforces: a
  member may always be more conservative than the room's default (release the current key in a
  full-history room), and a client may offer to be less conservative where the room's default is
  forward-only. Nothing is lost by this, because a member who wants to hand over their own history can
  do so outside the protocol regardless — the decider's point that *"there's nothing stopping them from
  copy-pasting more, but no need to make that part of the UX/protocol"* is the correct boundary. What the
  protocol owes is that the choice is **recorded** (it is, in the grant) and that it can never expose
  another member's history (it cannot, structurally: nobody holds another member's origin key).
  Consequence for the evaluator's known gap below: `history_mode_at_grant` moves from "recorded but never
  validated" to *the* authority on what a grant released, which is what it should always have been.
- **Known gaps (recorded 2026-09-19).** Role-tag ABAC (`#ops` may `dial:` `#ssh-hosts`) is not
  evaluated anywhere — `Capability::Role` exists, `is_at_or_below` is exact-match, and `tunnel/authz`
  checks only `bind:`/`dial:` tags; `Invite` has no wire encoding or signature yet; any `delegate`-holder
  may revoke any delegation (not lineage-restricted — the Decision does not say which capability
  authorizes revocation); `history_mode_at_grant` and `new_chain_id` are recorded but never validated by
  the evaluator; the golden-vector suite is in-process Rust assertions, not language-neutral fixtures
  with pinned bytes (the "two independent implementations" gate needs the latter).

## Links
**Depends on**: ADR-002, ADR-005, ADR-006, ADR-008.
- Depended on by: ADR-009, ADR-010, ADR-013, ADR-014.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
