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

A channel begins with a **genesis record**: a self-signed root capability authored by the
creator's identity key (ADR-002), fixing `channelID`, creation timestamp, the initial policy
(history mode, deniability mode, TTL), and naming the creator as **root admin**. Its hash is the
root of every certificate chain in the channel; every authority claim must verify back to it.

### Certificate and grant schema

All of the following are signed entries on the causal log (ADR-008). Each carries: author
identity, `(channelID, epoch)` binding (ADR-006), monotonic per-author sequence number, parent
hash-links, the issuer's certificate chain reference, and a composite Ed25519+ML-DSA signature
(ADR-002/ADR-003).

- **Admin delegation cert** — issued by an admin, names a delegate identity key and the granted
  capability set, optionally *attenuated* (e.g. `invite` but not `delegate`) and optionally with an
  expiry. Delegations chain to genesis, forming an SPKI/SDSI/UCAN-style capability tree the client
  verifies independently. No capability can exceed its issuer's (monotonic attenuation).
- **Membership cert** — issued by an admin holding the `invite` capability, names the newcomer's
  identity key and admits them to the channel (eligibility to participate). Attributable and durable
  (this is why membership is *not* deniable — ADR-009).
- **Consent grant** — issued by an *individual member* `A`, names a target member `N`, and is the
  act of releasing `A`'s Sender Key to `N`: `A` encrypts `A`'s current SKDM (ADR-006) to `N` over
  their pairwise channel (ADR-004) and records a consent-grant entry. This is the per-sender consent
  primitive — entirely `A`'s decision, authored only by `A`.
- **Revocation** — a *consent revocation* (member `A` withdraws `N`'s access to `A`'s future
  messages) or a *membership revocation* (an admin removes `N` from the channel). Triggers sender-key
  rotation excluding the target (below).
- **Policy update** — issued by an admin, changes channel policy (history/forward-only,
  deniable/attributable, TTL). Takes effect from its causal position forward.

### Admission and per-sender consent flow

1. `N` completes the CPace join (ADR-005) and establishes pairwise PQXDH sessions (ADR-004) with
   whichever members it meets. Holding channel credentials yields **no** sender keys — `N` can read
   nothing yet.
2. An admin issues a **membership cert** for `N` (eligibility). This does not grant readability.
3. `N` broadcasts its own SKDM to members (it has nothing to consent over; others reading `N`
   depends on each of them, symmetric to the rule below).
4. Each existing member `A` independently decides whether to consent. On consent, `A` issues a
   **consent grant** (sends `A`'s SKDM to `N`). Until `A` does so, `A`'s messages remain
   undecryptable to `N` — forever if `A` never consents. `N`'s readable view of the channel fills
   in **monotonically, per sender**.

Because possession of credentials releases no keys and every membership/consent act is a signed
certificate verified to genesis, there is no server-controlled member list to forge — the
Signalgate / Megolm membership-injection class is structurally absent.

### Revocation and epochs

- **Per-member consent revocation:** `A` generates a fresh sender key, **advancing `A`'s own
  `chain_id`** (the per-author generation counter, ADR-006) — *not* the channel `epoch`. `A`
  distributes the new key to all members `A` still consents to *except* the revoked `N`, and records a
  revocation entry. `N` retains previously-held keys (uncallable) but cannot decrypt `A`'s future
  messages. (Terminology, normative: **`epoch` is a single channel-global counter** set only by the
  genesis record and admin policy/passphrase-rotation entries; per-author rotation is always
  `chain_id`. There is no per-author "epoch contribution.")
- **Admin membership revocation:** an admin issues a membership-revocation cert; consenting members
  rotate their sender keys excluding `N`.
- **Passphrase-rotation epoch (bulk):** an admin rotates the channel passphrase (ADR-005), incrementing
  the channel `epoch`. This evicts all members and forces rejoin (re-CPace, re-admission, re-consent),
  and is the clean epoch boundary that re-binds all sender keys to the new `(channelID, epoch)`
  (ADR-006) — the mass-revocation primitive.

### Conflict resolution under partition

Governance state lives on the causal Merkle-DAG (ADR-008), which converges without consensus, and
relies on ADR-008's **fork/equivocation handling** (signed heads, durable fork proofs, equivocator
freeze). Partition-time authority actions are therefore **provisional until their causal neighborhood
reconciles** (ADR-008). The model is chosen so most actions never truly conflict:

- **Consent is single-writer.** Only `A` authors `A`'s consent grants and `A`'s sender-key rotations,
  so `A`'s consent timeline is totally ordered within `A`'s own log. There is no cross-writer race on
  "can `N` read `A`."
- **Additive facts merge freely.** Membership certs, consent grants, and admin delegations are
  add-only; concurrent ones all stand and are ordered causally.
- **Removal beats addition (fail-safe).** When an authorized revocation/removal is concurrent with
  (no causal ordering) or after a corresponding add/grant for the same subject, the subject is
  treated as **not-admitted / not-consented** until a *causally-later* re-grant. This deterministic
  "revocation wins" rule is applied per subject and resolves concurrent admin add-vs-remove
  conservatively.
- **Admin authority is monotonic + revocable.** A key is an admin iff some valid delegation chain to
  genesis grants it and no causally-later authorized revocation supersedes it; ties resolve by the
  same removal-wins rule. Attenuation prevents privilege escalation regardless of ordering.

### Enforcement honesty

Only **forward** guarantees are cryptographic: rotating to keys a party never receives is enforceable;
recalling keys a party already holds is not, and TTL/erasure (ADR-010) is client-honored. That
previously-admitted members can still read traffic they already had keys for is an accepted,
documented property of the threat model — not a defect to paper over.

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
