# ADR-007: Membership, Per-Sender Consent, and Admin Governance

- **Status**: proposed
- **Date**: 2026-06-19
- **Deciders**: Robert E. Lee <robert@agidreams.us>
- **Tags**: consent, membership, admin, governance, revocation, differentiator

## Context

This is Vox's headline differentiator, designed against the Signalgate failure (ADR-001): in
Signal/Matrix/WhatsApp, group membership is not cryptographically authenticated, so one wrong add
exposes all future traffic to the intruder. Vox must instead make admission a *per-member,
per-sender* cryptographic decision, with no central authority — while still providing workable
admin and channel policy in a serverless setting. Built on Sender Keys (ADR-006), identity
(ADR-002), and verified against the Megolm membership-control attacks (IEEE S&P 2023, eprint
2023/1300).

## Decision

**Per-sender consent admission.** A node that joins the swarm with correct credentials (ADR-005)
can read *nothing* by default — it holds no member's sender key. Each existing member individually
consents to a newcomer by releasing *their* SKDM (ADR-006) to it. Until member A consents, A's
messages remain undecryptable to the newcomer — forever, if A never consents. Visibility fills in
monotonically, per sender. Newcomers auto-broadcast their own SKDM to all (they have nothing to
consent over). This structurally avoids the Signalgate cascade: there is no server-controlled
member list to forge, and possessing credentials releases no keys.

**Cryptographic admin without a server = a signed certificate tree.** Admin and membership are
governed by Ed25519/ML-DSA-signed certificates forming a tree of signatures rooted at the
channel-creation event (the trust anchor) — SPKI/SDSI/UCAN-style attenuated delegation, verified
independently by every client. (This is precisely the fix the Matrix authors proposed but never
shipped.) The creator is the root admin and may delegate admin by signing an admin certificate
naming a delegate's key (ADR-002).

**Channel policy is admin-set and mutable.** The admin sets per-channel policy — notably
history-vs-forward-only for newcomers, and the deniable-vs-attributable mode (ADR-009) — and may
change it after creation. Prior-message *metadata* visibility to newcomers follows the channel's
history policy.

**Revocation = forward rotation.**
- **Per-member revocation:** remaining members rotate their sender keys and redistribute to all
  except the revoked node (excludes it from future traffic).
- **Passphrase-rotation epoch:** the admin rotates the channel passphrase, evicting all members
  and forcing rejoin — a bulk re-key / mass-revocation primitive and a clean epoch boundary
  (ADR-006 binding).

**Enforcement honesty.** Only *forward* guarantees are cryptographic: no mechanism can recall keys
a member already holds, and TTL/erasure is client-honored, not enforceable (ADR-010). Past traffic
remaining readable by previously-admitted members is an accepted, documented property of the
threat model.

## Consequences

### Positive
- Eliminates the Signalgate single-wrong-add exposure by construction — the core product promise.
- Serverless, verifiable governance with no central membership authority.
- Per-sender monotonic visibility is expressible because of the Sender-Keys per-author model (ADR-006).

### Negative
- Revocation is O(remaining members) of SKDM redistribution; a passphrase epoch is a full
  re-admission/re-consent cycle (~O(N²) pairwise) — strong but expensive as N grows.
- Consent state and the certificate tree must stay consistent across a serverless overlay under
  partition / concurrent admin actions — handled on the causal log (ADR-008).
- "Admin" reintroduces a (delegated, signed, non-server) authority concept that must be designed carefully.

### Neutral
- Consent/admin state lives in the replicated log (ADR-008); deniable channels alter the signing
  story (ADR-009) but not the consent mechanics.

## Links
- Depends on: ADR-002, ADR-005, ADR-006.
- Depended on by: ADR-008, ADR-009, ADR-014.
