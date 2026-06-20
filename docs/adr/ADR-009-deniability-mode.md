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

### Concrete protocol — Deniable GKA + DSKE (per-epoch), buildable rounds

At each epoch (the passphrase/epoch boundary, ADR-006) the consenting member set runs a **4-round**
deniable group key agreement + deniable signature-key exchange (DSKE), augmenting Bohli–Steinwandt
deniable GKA. All broadcasts are log entries (ADR-008) bound to `(channelID, epoch)`. Let each member
`i` hold an ephemeral DH share `x_i` and generate a **per-epoch ephemeral composite (Ed25519+ML-DSA-65)
signing keypair** `(esk_i, epk_i)`:

1. **Commit.** `i` broadcasts `commit_i = SHA-256("vox/dgka-commit/v1" ‖ epk_i ‖ g^{x_i} ‖ n_i)` with a
   fresh 128-bit nonce `n_i`. (Commitments prevent adaptive key-choice.)
2. **Reveal.** `i` broadcasts `(epk_i, g^{x_i}, n_i)`; everyone checks each `commit_i`. The group key is
   `K = HKDF-SHA-256(BD-combine({g^{x_i}}), info="vox/dgka/v1" ‖ channelID ‖ epoch)` via the
   Burmester–Desmedt/Bohli–Steinwandt combiner — a **deniable** agreement: only ephemeral DH shares
   enter it, **no static signature**, so participation is authenticated by membership (ADR-007), not by
   a transferable signature.
3. **DSKE bind.** Each `i` signs the transcript `T = SHA-256(sorted{epk_*} ‖ sorted{g^{x_*}} ‖ channelID
   ‖ epoch)` with `esk_i` and broadcasts the signature. This proves knowledge of `esk_i` and binds
   `epk_i` to *this session’s transcript* — giving members real, **post-quantum** origin authentication
   to each other (composite signature), **non-transferable** to outsiders because `epk_i` is never
   cross-signed by `i`'s root identity (an outsider cannot tie `epk_i` to any identity).
4. **Confirm.** Each `i` broadcasts `MAC_K(T)`; the session opens when all confirmations verify.

Message content in the epoch is then signed with the author's `esk_i`. **At epoch end each member
publishes its ephemeral *private* key `esk_i`**, so anyone can retroactively forge that epoch's content
signatures → content authorship is repudiable (the deniability property), while *live* recipients got
genuine PQ origin authentication during the epoch.

### Per-sender consent is preserved (critical)

The construction keeps **one ephemeral signing key per member** (public part shared), **not** a shared
group signing secret. So the consent primitive survives unchanged in deniable mode: to consent, `A`
releases `A`'s per-epoch ephemeral verifier (and the per-sender content key, ADR-006) to `N`; to
withhold/revoke, `A` does not. `N` gains or loses **only `A`'s** content — exactly the per-sender,
monotonic visibility of ADR-007. (A shared-group-secret design, e.g. a pure DGKE, would break this and
is rejected for that reason.)

### Mid-epoch membership change

A member who joins (and is newly consented to, ADR-007) between passphrase-epochs does **not** reuse
the prior epoch's (now-published, forgeable) keys. The **incremental DSKE re-key** is triggered by the
consent-grant log entry naming the newcomer: each member that consented generates a fresh `(esk', epk')`,
re-runs steps 3–4 (DSKE bind + confirm) against an updated transcript `T'` that includes the newcomer's
`epk_new`, and distributes the result to the newcomer. The group key `K` (a confidentiality key, not an
authenticator) may be retained for the epoch, or re-derived if the join changes the DH set. Cost: one
incremental bind+confirm round per such join (bounded; the FS window for the new verifiers is one re-key
interval). This is the concrete answer to "consent is continuous but the DGKA is per-epoch."

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

### Post-quantum instantiation — deniable mode is PQ today

Deniable mode is **fully post-quantum now**, with no dependency on any unshipped primitive:
- **Live origin authentication is PQ.** The per-epoch ephemeral signing key is the **composite
  Ed25519+ML-DSA-65** key (ADR-002/ADR-003), so content signatures verify under a PQ signature during
  the epoch.
- **Confidentiality is PQ.** The deniable group key `K` rides ephemeral DH that mixes ML-KEM-768 material
  via the PQXDH pairwise legs (ADR-004).
- **Deniability is mechanism-based, not primitive-based.** Repudiation comes from **publishing the
  ephemeral private key at epoch end** (anyone can then forge that epoch's content) — this needs no
  special signature type, so there is no "classical-only until a PQ scheme ships" gap. Participation is
  attributable by design (ADR-001/ADR-007), consistent with weak/content deniability.

**Optional future strengthening (not required, via crypto-agility).** A post-quantum *designated-verifier*
signature — **UDMVS** (lattice SIS/LWE universal designated-multi-verifier, ROM, ISPEC 2024) or a PQ
**MDVRS** — would give **live non-transferability** so members need not wait for epoch-end key
publication to obtain repudiation. It is an enhancement layered in through ADR-003 versioning without
changing this mode's semantics; deniable mode ships complete without it. (Rejected as unfit for the
group setting: **LaSDVS** single-verifier-only; **PSDVRS** discrete-log, not PQ.)

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
- A multi-round deniable GKA + incremental re-key on each mid-epoch join is real protocol complexity and must be
  formally analyzed before shipping (Van Gundy/mpENC give the template, not a drop-in library).
- Deniable mode is PQ today (composite ephemeral keys + epoch-end publication); the *optional*
  live-non-transferability upgrade (PQ designated-verifier, UDMVS/MDVRS) is a young primitive, so until
  one is vetted, repudiation is obtained by key publication rather than a designated-verifier signature.

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
