# ADR-009: Deniability Mode (per-channel)

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: deniability, mpotr, dake, mdvs, content-authorship, post-quantum

## Context

Deniability is a per-channel option (ADR-007), scoped to **content-authorship only** (membership
stays attributable). A prior review found two real defects: (1) a contradiction — "attributable
mode" message signing keys are root-cross-signed (ADR-002), which is *transferable, non-repudiable*
proof, yet the design loosely claimed attributable mode was still "deniable to outsiders"; and
(2) the deniable mode named "per-epoch ephemeral signing keys" without a concrete construction —
and ephemeral *signatures* are still transferable unless the key→identity binding is itself
deniable. This ADR fixes both: it states deniability precisely (relative to a judge) and picks ONE
concrete construction. Grounded in the Berkeley *SoK: Secure Messaging*, the cypherpunks
mpOTR/DAKE work (Goldberg et al.), and ETH Zürich's MDVS/MDRS-PKE results (CHMR23). *(Verifier
agents abstained under rate-limiting; the sources are canonical primary literature.)*

## Decision

### Deniability model (precise)

Deniability is defined **relative to a judge** who accepts only transferable cryptographic proof.
Vox distinguishes (SoK):
- **Message/content repudiation** — denying authorship of a specific message. **This is Vox's goal.**
- **Participation repudiation** — denying having been in the channel at all. **Not a goal**:
  membership is attributable (ADR-007); pseudonymity is handled by joining under a dedicated key
  (ADR-002).
- **Online vs offline** — Vox targets **offline** deniability (judge examines a past transcript,
  even given long-term secrets). Online deniability (judge colludes live with an insider) is **not**
  targeted; it is achieved by few protocols and is explicitly out of scope.

### The two modes, characterized honestly

- **Attributable mode (default).** Message content is signed with the author's root-cross-signed
  Sender-Key signing key (ADR-002). This is **transferable, non-repudiable proof of authorship to
  anyone — insiders and outsiders alike. It is NOT deniable.** (This is the correction: no
  outsider-deniability is claimed for attributable mode.) Use it when intra-group accountability is
  wanted.
- **Deniable mode.** Message content carries **no transferable proof of authorship**: any channel
  member could have produced any member's authenticator, so a judge cannot attribute a message even
  given long-term secrets.

### Concrete deniable construction (chosen)

**Per-epoch deniable authenticated group key exchange (DAKE) + ephemeral authentication, with MDVS
for receiver-coercion resistance** — the mpOTR/DGKE pattern, instantiated post-quantum:

1. **Epoch DAKE.** At each epoch (ADR-006 passphrase/epoch boundary), members run a *deniable*
   authenticated group key exchange that binds a fresh per-epoch ephemeral signing key to each
   member's identity in a **non-transferable** way — the binding is forgeable from public keys
   alone, so no outsider can prove "this ephemeral key is Alice's." The DAKE rides PQXDH (ADR-004),
   whose KEM/DH shared secret is deniable-friendly (no long-term signature enters the secret).
2. **In-epoch authentication.** Messages are authenticated under these ephemeral keys: insiders
   verify origin (they witnessed the DAKE binding); outsiders cannot bind ephemeral→identity, so
   they get no transferable proof — offline message repudiation holds against outsiders.
3. **Receiver-coercion resistance (strong deniability).** Where a channel needs deniability even
   against a *member who surrenders their own secret key to a judge*, the per-recipient authenticator
   is a **Multi-Designated-Verifier Signature (MDVS)** / MDRS-PKE (ETH CHMR23): every designated
   verifier could have forged it, so a colluding receiver still cannot convince a judge. MDVS is the
   strong-deniability profile; DAKE-ephemeral authentication is the baseline profile.

**Honest limit:** mpOTR-style per-epoch ephemeral keys lose *message unlinkability within an epoch*
(a sender's messages in one epoch share an ephemeral key). This is acceptable: linkage *among
members* is already attributable inside the channel; the property that matters — non-attribution to
**outsiders/judges** — is preserved. Channels needing per-message unlinkability use the MDVS profile.

### Log integrity in deniable mode

The hash-linked log (ADR-008) provides tamper-evidence, causal ordering, and fork detection
independent of *who* authenticates. In deniable mode the per-entry authenticator is the
DAKE-ephemeral key (or MDVS), not the root-chained composite signature. Integrity against
*outsiders* holds (only epoch members hold the ephemeral/MDVS keys); deniability holds because any
*member* could have forged the authenticator — which is exactly the goal. Fork proofs still work:
two conflicting entries at one `(author, seq)` are detectable even under deniable authentication,
and equivocation is handled per ADR-008.

### Post-quantum instantiation

Ordinary PQ signatures (ML-DSA) are transferable and **must not** be used to authenticate deniable
content. The PQ deniable authenticator is a **lattice-based (multi-)designated-verifier signature**
(e.g. an ideal-lattice/NTRU SDVS such as LaSDVS, or a ring-style multi-designated-verifier scheme);
the DAKE uses PQXDH (ADR-004), already PQ-hybrid and deniable-friendly. Sizes/maturity of PQ MDVS
are tracked in ADR-003's agility framework; the construction is versioned so the concrete PQ MDVS
scheme can advance without changing the mode's semantics.

## Consequences

### Positive
- Resolves the contradiction: attributable mode is honestly non-repudiable; deniable mode has a
  concrete, named construction with stated transferable/non-transferable guarantees.
- Offline message repudiation against outsiders (baseline) and against colluding receivers (MDVS
  profile), with PQ instantiation.
- Log integrity, ordering, and fork detection are preserved in both modes.

### Negative
- Per-epoch ephemeral authentication sacrifices in-epoch message unlinkability (baseline profile);
  the MDVS profile recovers it at higher cost/complexity.
- PQ MDVS/SDVS schemes are less mature and larger than ML-DSA; a real implementation and review-cost
  risk that ADR-003 agility is meant to absorb.
- A deniable group DAKE is non-trivial to implement and must be formally checked before shipping.

### Neutral
- Per-channel choice (admin-set, ADR-007), like the history policy; attributable is the default.

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
