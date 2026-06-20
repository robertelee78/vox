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
  updates, **and the DGKA/DSKE setup entries** (§Concrete protocol; participation is attributable).
  (Attributable; preserves ADR-007 single-writer consent integrity.)
- **Message-content payloads** in a deniable channel are authenticated **only** by the per-author
  ephemeral key below — never the static key.

### Concrete protocol — Deniable GKA + DSKE (per-epoch), buildable rounds

At each epoch (the passphrase/epoch boundary, ADR-006) the consenting member set runs a **4-round**
deniable group key agreement + deniable signature-key exchange (DSKE), augmenting Bohli–Steinwandt
deniable GKA. All four rounds' broadcasts are **governance/control-class log entries** (ADR-008,
struct-type `dgka-setup`): they are **root-composite-signed**, so peers accept them under ADR-008's
per-entry-type rule and *participation* in the epoch is attributable — which is exactly mpENC **weak
deniability** (participation is never deniable; only message *content* is). The static signature is on
the log envelope only; the key-agreement material *inside* carries no static signature, preserving
content deniability. Let each member `i` hold an ephemeral DH share `x_i` and generate a **per-epoch
ephemeral composite (Ed25519+ML-DSA-65) signing keypair** `(esk_i, epk_i)`:

1. **Commit.** `i` broadcasts `commit_i = SHA-256("vox/dgka-commit/v1" ‖ epk_i ‖ g^{x_i} ‖ n_i)` with a
   fresh 128-bit nonce `n_i`. (Commitments prevent adaptive key-choice.)
2. **Reveal.** `i` broadcasts `(epk_i, g^{x_i}, n_i)`; everyone checks each `commit_i`. The group key is
   `K = HKDF-SHA-256(ikm = BD-combine([g^{x_1}, …, g^{x_m}] sorted by author composite-pubkey),
   info="vox/dgka/v1" ‖ channelID ‖ epoch)` — the Burmester–Desmedt/Bohli–Steinwandt combiner over the
   ephemeral DH shares in **ascending-composite-pubkey order** (pinned so every member derives the *same*
   `K`; the BD term order follows the standard published construction over that ordering). `K` is used
   **only for epoch key-confirmation/binding (step 4), not as the content key**. It is a **deniable**
   agreement: only ephemeral DH shares enter it, **no static signature on the key**. *(Note: `K` itself is
   classical-DH; this is harmless because message **content** confidentiality is owned by the per-sender
   Sender Keys (ADR-006), which are ML-KEM-768/PQXDH-distributed — see §Post-quantum instantiation. A
   hybrid `K` is unnecessary since `K` only confirms the agreement.)*
3. **DSKE bind.** Each `i` signs the transcript `T = SHA-256(epk_* ‖ g^{x_*} ‖ channelID ‖ epoch)`
   — both lists in ascending author composite-pubkey order — with `esk_i` and broadcasts the signature,
   proving knowledge of `esk_i` and binding `epk_i` to this session's transcript. This gives members
   real **post-quantum origin authentication to each other** for the epoch's content.
   **Honest deniability scope (important):** the `dgka-setup` envelope is root-signed (it must be an
   accepted log entry, ADR-008), so it *is* transferable proof that identity `i` **participated** and
   registered `epk_i` this epoch — consistent with mpENC **weak deniability** (participation is never
   deniable). Consequently **live content authored under `esk_i` is attributable to `i` during the
   epoch**; content-authorship repudiation is **retrospective**, taking effect at epoch end when `esk_i`
   is published (step below), after which anyone could have forged it. This matches this ADR's scope —
   *offline content repudiation against a later judge*, not live unlinkability. (The optional UDMVS
   upgrade in §Post-quantum would add *live* non-transferability; not required for the threat model.)
4. **Confirm.** Each `i` broadcasts `MAC_K(T)`; the session opens when all confirmations verify.

Message content in the epoch is then signed with the author's `esk_i`. **At epoch end** — and only after
the epoch has closed (a passphrase-rotation/epoch-increment is on the log; publishing earlier would void
live authentication) — **each member publishes its ephemeral *private* key `esk_i`** as an
`esk-publication` log entry (ADR-008 tag `0x0010`, root-signed envelope, body `{ epoch, esk_i }`). Anyone
can then retroactively forge that epoch's content signatures → content authorship becomes repudiable (the
deniability property), while *live* recipients got genuine PQ origin authentication during the epoch.

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
`epk_new` (members in `T'` ordered by ascending composite-pubkey, the same sort rule as `T`), and
distributes the result to the newcomer. The group key `K` (a confidentiality key, not an
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
- **Confidentiality is PQ.** Message *content* confidentiality is owned by the per-sender Sender Keys
  (ADR-006), which are distributed over PQXDH (ML-KEM-768) — PQ independent of the DGKA. The DGKA's own
  key `K` (used for epoch key-confirmation/binding, not as the content key) is additionally **hybrid-PQ**
  because its derivation mixes the members' pairwise PQXDH secrets (§Concrete protocol, step 2).
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
