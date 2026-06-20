# ADR-009: Deniability Mode (per-channel)

**Status**: proposed
**Date**: 2026-06-20
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: deniability, mpenc, deniable-gka, content-authorship, post-quantum

## Context

Deniability is a per-channel option, scoped to **content-authorship only** (governance/membership stay
attributable, ADR-007/ADR-008). Earlier drafts named a *family* ("DAKE + MDVS") rather than a buildable
protocol and left the deniable/governance collision unresolved. This ADR specifies ONE concrete,
implementation-grade construction and how it composes with the log (ADR-008) and per-sender consent
(ADR-007). It is grounded in the mpENC/mpOTR lineage (Van Gundy's *Deniable Key Exchange for Group
Messaging*; mpENC "Multi-Party Encrypted Messaging Protocol", arXiv 1606.04598) and the deniable group
key agreement of Bohli–Steinwandt. *(Verified 3-0 against these primary sources.)*

## Decision

### Deniability scope = "weak" (content) deniability — the group analogue of OTR

We adopt exactly mpENC's **weak deniability**: *message contents are deniable, but session
participation is not*. This matches ADR-001/ADR-007 (membership is attributable) and is the group
analogue of how OTR achieves deniability — equivalent security. Full participation-deniability would
require ring signatures "not yet in widespread usage" and is explicitly **out of scope** (it would also
contradict the attributable governance plane). Deniability is defined against a judge and is **offline
content repudiation**: no transferable proof of *who authored a message* survives, even given long-term
secrets.

### Per-entry-type signing (canonical; mirrors ADR-008)

Confirmed by mpENC, which warns that signing content with static keys "destroys any chance … at
retaining deniability … we can never regain it in a higher layer":
- **Governance/structural entries are static-composite-signed (Ed25519+ML-DSA identity key) in ALL
  modes:** genesis, admin delegations, consent grants, consent revocations, policy/passphrase-rotation
  updates. (Attributable; preserves ADR-007 single-writer consent integrity.)
- **Message-content payloads** in a deniable channel are authenticated **only** by the per-author
  ephemeral key below — never the static key.

### Concrete protocol — Van Gundy Deniable GKA + DSKE (per-epoch)

At each epoch (the passphrase/epoch boundary, ADR-006), members run a **4-round deniable group key
agreement + deniable signature-key exchange (DSKE)** that augments Bohli–Steinwandt deniable GKA:
1. each member contributes to a deniable group key agreement (the GKA legs ride PQXDH material,
   ADR-004, so the agreement itself is deniable — no static signature enters it);
2. each member generates a **per-epoch ephemeral signing keypair** and shares its public part bound to
   the session transcript;
3. **signature-key confirmation:** each member signs the per-session Schnorr challenge `c_i` with its
   ephemeral key to *prove knowledge of the ephemeral private key and bind it to the transcript* —
   giving members non-repudiable origin authentication **to each other**, non-transferable to outsiders
   (an outsider cannot bind the ephemeral key to any identity);
4. key confirmation completes the session.

Message content is then signed with the per-author per-epoch ephemeral key. **At epoch end each member
publishes its ephemeral *private* key**, so anyone can retroactively forge that epoch's content
signatures → content authorship is repudiable (the deniability property), while *live* recipients still
got real origin authentication.

### Per-sender consent is preserved (critical)

The construction keeps **one ephemeral signing key per member** (public part shared), **not** a shared
group signing secret. So the consent primitive survives unchanged in deniable mode: to consent, `A`
releases `A`'s per-epoch ephemeral verifier (and the per-sender content key, ADR-006) to `N`; to
withhold/revoke, `A` does not. `N` gains or loses **only `A`'s** content — exactly the per-sender,
monotonic visibility of ADR-007. (A shared-group-secret design, e.g. a pure DGKE, would break this and
is rejected for that reason.)

### Mid-epoch membership change

A member admitted between passphrase-epochs does **not** reuse the prior epoch's (now-published,
forgeable) keys. Instead an **incremental DSKE re-key** runs: the affected members generate fresh
per-epoch ephemeral keypairs and re-confirm, so the newcomer obtains live per-member verifiers. Cost:
one incremental key-agreement round per admission affecting a deniable channel (bounded; the FS window
is one re-key interval). This is the concrete answer to "consent is continuous but the DAKE is
per-epoch."

### Fork / equivocation in deniable channels

Because content authenticators are forgeable by any member, automated "freeze the equivocator" is
**disabled** for deniable content (it would be a framing/DoS primitive — ADR-008). Vox uses mpENC's
policy: a deniable-content fork raises a **non-attributable alarm** (causal-DAG inconsistency +
TCP-style timeout warnings) surfaced for manual, out-of-band resolution, optionally hardened with
GOTR-style deferred pairwise consistency checks. Governance forks remain attributable and auto-handled
(they are static-signed, ADR-008).

### Attributable mode (default)

Content is signed with the root-cross-signed composite key — **non-repudiable to insiders and
outsiders** (honest: it is *not* deniable). Used when intra-group accountability is wanted.

### Post-quantum instantiation (hybrid, versioned)

The ephemeral content authenticator is **hybrid**: classical Schnorr/Ed25519 ephemeral signatures
today, plus a lattice multi-/designated-verifier signature as those mature — the chosen PQ target is
**UDMVS** (lattice SIS/LWE universal designated-multi-verifier signature, ROM, peer-reviewed ISPEC 2024)
or a post-quantum **MDVRS** built from generic primitives. Explicitly rejected as unfit: **LaSDVS**
(single-verifier only, not group-applicable) and **PSDVRS** (efficient but discrete-log, *not*
post-quantum). The scheme is versioned via ADR-003 crypto-agility so the PQ MDV component advances
without changing the mode's semantics. Until a vetted PQ MDV ships, deniable mode runs classical-hybrid
ephemeral signatures (deniable today; the governance/transport/key-agreement planes are already PQ).

## Consequences

### Positive
- One concrete, citable, buildable protocol (Van Gundy GKA+DSKE) — no families, no deferral.
- Per-sender consent is provably preserved (per-author ephemeral keys), so the headline feature works
  in deniable channels.
- Clean split: governance attributable + auto-fork-handled; content deniable + alarm-only — the C1/C2
  knot is resolved end-to-end with ADR-008.

### Negative
- In-epoch message **unlinkability** is sacrificed (a member's content in one epoch shares an ephemeral
  key) — acceptable, since intra-group linkage is already attributable; only outsider non-attribution
  matters.
- A multi-round deniable GKA + incremental re-key on admission is real protocol complexity and must be
  formally analyzed before shipping (Van Gundy/mpENC give the template, not a drop-in library).
- The PQ MDV component (UDMVS/MDVRS) is young; until vetted, PQ deniability rests on the hybrid's
  classical half (the rest of the stack is PQ).

### Neutral
- Per-channel choice (admin-set, ADR-007), attributable default.

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
