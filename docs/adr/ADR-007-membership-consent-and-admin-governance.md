# ADR-007: Membership, Per-Sender Consent, and Admin Governance

**Status**: proposed
**Date**: 2026-06-19
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
- **Tunnel capabilities, registered by ADR-013 into *this* lattice:** `bind:<service-tag>` (advertise/
  host) and `dial:<service-tag>` (consume), plus attenuable **role-tag attributes** (e.g. `#ops`,
  `#ssh-hosts`). ADR-013's ABAC policies (“`#ops` may Dial `#ssh-hosts`”) are evaluated by this same
  evaluator over these grants — ADR-013 adds **no** parallel authorization engine.
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
2. `N` broadcasts its own SKDM to members (it has nothing to consent over; whether others can read
   `N` is each member's own decision, symmetric to the rule below).
3. Each existing member `A` independently decides whether to consent. On consent, `A` issues a
   **consent grant** (sends `A`'s SKDM to `N`). Until `A` does so, `A`'s messages remain undecryptable
   to `N` — forever if `A` never consents. `N`'s readable view fills in **monotonically, per sender**.

Because possession of credentials releases no keys, and readability is granted only by each member's
own consent grant (no admin admission, no central roster), there is no server-controlled member list
to forge — the Signalgate / Megolm membership-injection class is structurally absent.

### Revocation and epochs

- **Outbound consent revocation ("who may read me"):** `A` generates a fresh sender key, **advancing
  `A`'s own `chain_id`** (the per-author generation counter, ADR-006) — *not* the channel `epoch`. `A`
  distributes the new key to all members `A` still consents to *except* the revoked `N`, and records a
  revocation entry. `N` retains previously-held keys (uncallable) but cannot decrypt `A`'s future
  messages. (Terminology, normative: **`epoch` is a single channel-global counter** set only by the
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
  the removal-wins rule, the evaluator orders any remaining concurrent entries by **ascending entry
  hash** (`SHA-256` of the canonical entry, ADR-008) and takes the last. This makes the evaluator a
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
