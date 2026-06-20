# ADR-009: Deniability Mode (per-channel)

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: deniability, mpotr, content-authorship, control-plane, data-plane

## Context

Deniability is a per-channel option (ADR-007). The tension: the attributable control plane
(signed membership/admin certificate tree, ADR-007) inherently uses signatures, while message
content deniability requires the *opposite* of non-repudiation. The scope must be pinned down,
and a concrete mechanism chosen that composes with the append-only log (ADR-008) and the PQ policy
(ADR-003).

## Decision

**Scope = content-authorship deniability ONLY.** A deniable channel ensures no one can
cryptographically prove to an *outsider* which member authored a given message. Membership is
*not* deniable (the signed certificate tree stays intact), and transcript deniability is not a
goal. A member wanting unlinkability uses a dedicated/pseudonymous identity key (ADR-002).

**Control-plane / data-plane key separation** (ADR-002). The signed identity/governance key
authenticates membership and admin certificates (attributable). A *separate*, per-epoch
ephemeral key authenticates message content in deniable mode — so signing governance does not
undermine message deniability.

**Mechanism = mpOTR-style per-epoch ephemeral signing keys, NOT shared MACs.** Verified finding:
plain shared-key MACs give deniability for two parties (OTR) but do **not** provide origin
authentication for >2 parties — so the OTR MAC trick does not generalize to a group log. Instead,
each member signs content with a *fresh ephemeral signing key per epoch*, bootstrapped via a
deniable key exchange: insiders get origin authenticity, outsiders get no transferable proof.
(Evaluate "epochal signatures" as a more async-friendly variant at implementation time.)

**Attributable mode (default alternative).** Channels that want accountability use per-message
signatures (intra-group attribution). Note even attributable mode remains deniable to *outsiders*
because group signing keys are group-known/ephemeral.

**Post-quantum deniability.** Ordinary PQ signatures destroy deniability; in PQ mode the deniable
data plane must use PQ-deniable primitives (PQ ring signatures / designated-verifier signatures —
the K-Waay / Apple PQ3 approach). This couples ADR-009 with ADR-003.

**Log integration.** Deniable channels replace per-author entry signatures with the per-epoch
ephemeral-key authentication; the hash-chain (ADR-008) still provides ordering and tamper-evidence.

## Consequences

### Positive
- Resolves the deniable-vs-signed-admin tension cleanly via role-separated keys.
- Content deniability with intra-group authenticity — the OTR property, generalized to a group.
- Membership stays verifiable, so admin/governance is unaffected.

### Negative
- A forked authentication path (signed vs deniable) doubles part of the auth surface and testing.
- Deniable mode loses signature-based PCS assurances, so it must rotate keys more aggressively.
- PQ-deniable primitives (ring/DVS) are heavier and less battle-tested than ML-DSA.

### Neutral
- Per-channel choice: the admin selects deniable vs attributable (ADR-007), like the history policy.

## Links
**Depends on**: ADR-002, ADR-003, ADR-006, ADR-007, ADR-008.
- Depended on by: ADR-014.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
