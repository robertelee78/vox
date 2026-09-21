# ADR-009 — Security analysis of the DGKA + DSKE construction

**Status**: internal, **not externally reviewed**. Written 2026-09-21 to discharge ADR-009 shipping
blocker (1), *"the formal analysis of the DGKA+DSKE construction the Decision requires before shipping
is not on file"*. Whether an internally-written analysis clears that bar is the decider's call, and
§8 states plainly what this is and is not.

**Normative source**: the **code**, not this document and not ADR-009's prose. ADR-009's own
Implementation notes record formula drift with the code normative. Everything below was read from
`crates/vox-core/src/deniable/{dgka,epoch,rounds,share,key,rekey,verifier,esk_publication,wire}.rs`
at `main`.

---

## 1. What is claimed, and what is not

ADR-009 adopts mpENC's **weak deniability**: *message contents are deniable, participation is not*.
Precisely, the target is **offline content repudiation against a judge**: after an epoch closes, no
transferable proof survives that a particular member authored a particular message, *even given every
long-term secret*.

Four things are explicitly **not** claimed, and a reader should hold the analysis to the claim made:

- **Participation is attributable, by construction.** Every `dgka-setup` (`0x000B`) round is a
  root-composite-signed log entry, so "identity `i` took part in epoch `e` and registered `epk_i`" is
  transferable proof. This is deliberate — ADR-007 needs attributable membership.
- **Live content is attributable during the epoch.** Repudiation is *retrospective*: it begins when
  `esk_i` is published at epoch end, not before.
- **No unlinkability.** A judge sees who spoke, when, and how much.
- **Nothing here is claimed about traffic analysis**, which ADR-001 scopes out.

## 2. The construction as implemented

Let the epoch have `m` members with static composite identities (Ed25519+ML-DSA-65). Member `i` holds
an ephemeral ristretto255 DH share `x_i` (`share.rs`) and a per-epoch ephemeral composite signing
keypair `(esk_i, epk_i)` (`dgka.rs::DgkaMember::start`).

Members are ordered by **ascending static composite public key**; `EpochContext` canonicalises that
order, so every member derives the same transcript.

1. **Commit** — `commit_i = SHA-256("vox/dgka-commit/v1" ‖ author_pubkey_i ‖ epk_i ‖ z_i ‖ n_i)`,
   `n_i` a fresh 128-bit nonce (`rounds.rs::commitment`). Note `author_pubkey_i` is inside the hash:
   a member is bound to its static identity **at commit time**.
2. **Reveal** — `(author_id_i, author_pubkey_i, epk_i, z_i, n_i, σ_i)` where `σ_i` is a **static**
   composite signature over the `dgka-setup` signing input
   `vox/dgka-setup/v1 ‖ CBOR[channelID, epoch, author_id, epk_bytes, share]`
   (`epoch.rs::dgka_setup_signing_input`). Every peer re-computes `commit_i` and rejects a mismatch.
3. **Round-2 / bind** — `X_i = x_i·(z_{i+1} − z_{i−1})` over the canonical ring
   (`dgka.rs::own_round2`); for `m = 2` BD degenerates and `X_i` is the member's own share, ignored by
   verifiers. Then `T = EpochContext::transcript()` over `(channelID, epoch, ordered members)`, and
   `T_bind = SHA-256(T ‖ X_1 ‖ … ‖ X_m)` in canonical order (`dgka.rs::bind_transcript`). Member `i`
   signs `T_bind` **with `esk_i`** (the DSKE bind).
4. **Confirm** — `HMAC(K_confirm, T_bind)`, `K` derived by the BD combiner over the ordered shares and
   `X_*`, through HKDF-SHA-256 with `info = "vox/dgka/v1" ‖ channelID ‖ epoch` (`key.rs`).

Content in the epoch is signed **only** with `esk_i`. At epoch end — gated on
`publishing_epoch < current_epoch` (`esk_publication.rs`) — each member publishes `esk_i` as an
`esk-publication` (`0x0010`) entry, after which anyone can forge that epoch's content signatures.

All four setup rounds are framed by `deniable::wire::DgkaMessage` under tag `0x000B`.

## 3. Assumptions

- **A1 (Gap-DH / DDH in ristretto255)** for the secrecy of `K`.
- **A2 (EUF-CMA)** of the composite signature scheme, for both static identity keys and `esk`.
- **A3 (Random oracle)** for SHA-256 as used in the commitment, the transcripts and HKDF extraction.
- **A4 (PRF)** for HMAC-SHA-256 in key confirmation.
- **A5 (Authenticated broadcast)** — every `0x000B` entry reaches every member unmodified, in an order
  the log makes agreeable. Supplied by ADR-008, *not* by this construction.
- **A6 (Static corruption)** — the adversary fixes which members it controls before the epoch begins.
  §7 says what breaks under adaptive corruption.

## 4. Claims and reduction sketches

**C1 — Key secrecy.** Against an outsider (no `x_i` for any honest `i`), `K` is indistinguishable from
random under A1 and A3. *Sketch:* the commitment round fixes every `z_i` before any is revealed, so an
adversary cannot choose its own share as a function of honest shares (A3, binding of the hash). Given
that, the BD combiner over the ordered `z_*` is the standard Burmester–Desmedt key, and HKDF with a
transcript-bound `info` is a random-oracle extraction of it. A distinguisher for `K` yields a DDH
distinguisher by embedding the challenge in an honest member's `z`.

**C2 — Agreement.** Two honest members that both open the session hold the same `K` and the same
`T_bind`. *Sketch:* `T` is a hash over the canonical member ordering, so any disagreement about the
member set or any `epk`/`z` gives a different `T` and the confirmation MACs do not verify. `T_bind`
additionally commits to the **exact** `X_*` vector used to derive `K`, so a member that broadcasts one
`X_i` to one peer and another `X_i` to a second — a split view — is detected rather than silently
producing divergent keys. This is the specific property `T_bind` exists for.

**C3 — Live origin authentication.** During the epoch, a member accepting content signed by `esk_i`
has PQ-sound assurance it came from the party that ran round 3, under A2. *Sketch:* the DSKE bind is a
signature by `esk_i` over `T_bind`, which commits to the channel, the epoch, the full member set and
the full `X_*` vector. Forging it requires forging a composite signature (A2). The `esk_i → i` binding
comes from the static signature `σ_i` in round 2 over `(channelID, epoch, author_id, epk_i, z_i)`.

**C4 — Content repudiation after publication.** Once `esk_i` is published, no transferable proof of
authorship survives. *Sketch:* after publication the signing key is public, so *any* party can produce
a valid content signature under `epk_i` for arbitrary content. A judge presented with a signed message
cannot distinguish "`i` wrote it" from "anyone wrote it after publication", because the signature is
verifiable but no longer exclusive. This is the entire deniability mechanism: it is **key publication**,
not a zero-knowledge property, and its strength is exactly the strength of "the key is now public".

**C5 — Participation non-deniability (a claimed *non*-property).** `σ_i` is a static signature over
`(channelID, epoch, author_id, epk_i, z_i)`; publishing `esk_i` does not weaken it. So participation
remains provable forever. Intentional.

## 5. The dependency that deserves the most scrutiny

**C4 holds only if publication actually happens.** A member who never publishes `esk_i` — offline,
coerced, or simply unwilling — gets **no repudiation at all** for that epoch: its content stays
verifiable under an `epk_i` whose private half only it ever held, and `σ_i` binds that `epk_i` to its
identity. Worse, the log makes the absence *visible*: a judge can see exactly which members published
and which did not, so a non-publisher is conspicuous.

This inverts the usual intuition about deniable messaging. Here deniability is not a property the
protocol gives you; it is a property **you grant yourself by publishing your own secret**, and the
system cannot make you. Any deployment must treat publication as a liveness requirement with a
user-visible failure mode, and this analysis cannot establish C4 for a member that does not publish.

A second-order consequence: an adversary who can keep a target offline across an epoch boundary — a
denial-of-service, not a cryptographic attack — denies that target repudiation for the epoch.

## 6. Attacks considered and why they fail

- **Adaptive share choice.** Prevented in setup by the commitment round (C1). **Not prevented on
  re-key** — see §7.
- **Identity substitution at reveal** (`(victim_author_id, attacker_epk)`). Prevented twice:
  `author_pubkey` is inside the commitment, and `σ_i` is a static signature over
  `(author_id, epk, share)`. The codec additionally refuses a reveal whose `author_pubkey`
  fingerprint ≠ `author_id`.
- **Split view on `X_i`.** Detected by `T_bind` (C2).
- **Replaying a reveal into another channel or epoch.** `σ_i` covers `channelID` and `epoch`, and the
  signing input is domain-separated, so it does not verify elsewhere.
- **Re-framing a reveal.** The static signature covers the `dgka-setup` *signing input*, not the frame
  bytes, so re-encoding cannot change what was signed.
- **Premature `esk` publication** (destroying live authentication mid-epoch). Gated on
  `publishing_epoch < current_epoch` — but see §7, that gate reads a caller-supplied value.

## 7. What this analysis does NOT cover

Stated so no reader mistakes silence for coverage. Each is an open ADR-009 gap.

1. **Re-key (gap 3) is outside every claim above.** It skips the commitment round, so C1's argument —
   which *depends* on commitments — does not apply: a re-key participant can choose `z'` after seeing
   others'. It also carries no static reveal signature on the wire, so C3's `esk' → i` binding rests on
   the caller sourcing descriptors from root-signed entries rather than on the protocol. **No claim in
   §4 should be read as covering re-key.** As of 2026-09-21 the path had never executed anywhere in the
   workspace; it now runs in one test, which exercises it without hardening it.
2. **Adaptive corruption (A6).** No claim is made about an adversary that corrupts a member after
   seeing the transcript.
3. **Epoch-close gating (gap 4)** compares against a caller-supplied `current_epoch` rather than log
   state. A caller that passes a wrong value can publish `esk_i` while the epoch is live, destroying
   C3 for itself. This is a trust boundary inside the API, not a protocol property.
4. **`m = 2`.** BD degenerates and `X_i` is ignored. C1's reduction is the two-party DH case, which is
   sound, but the `X_*` binding in `T_bind` carries no information there — so C2's split-view detection
   is vacuous for two members. Their agreement rests on `T` alone.
5. **`K` is classical-only.** ADR-009 argues this is harmless because content confidentiality belongs
   to ADR-006 sender keys and `K` only confirms. Accepting that, a future quantum adversary can recover
   `K` retroactively and forge confirmation MACs — which *helps* C4 and does not affect C3 (the bind is
   a PQ composite signature). This document accepts the argument but flags it as the place a reviewer
   should push hardest.
6. **No pinned test vectors** for `K`, `T`, `T_bind`, the commitment or the MAC. The construction is
   exercised only against itself, so a second implementation could not check agreement.
7. **Composability.** No claim about running deniable mode alongside the ADR-006 sender-key ratchet in
   the same epoch beyond what ADR-009 asserts.

## 8. What this document is

An internal analysis written by the same process that wrote the code. It is **not** a peer-reviewed
proof, it contains reduction *sketches* rather than full games with explicit advantage bounds, and it
has not been checked by a cryptographer. Deniability has the unpleasant property that failure is
silent — a broken deniability scheme behaves exactly like a working one — so "we analysed it ourselves"
is weak evidence.

Its purpose is to be **attackable**: the construction is stated precisely enough, and the assumptions
and non-claims enumerated explicitly enough, that a reviewer can find what is wrong with it. §5 and §7
are where to start.
