# ADR-007: Membership, Per-Sender Consent, and Admin Governance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status:** accepted. Built in `crates/vox-core/src/governance/` (M6), `node::channel`, `node::trust` and
`node::actor` (ADR-016 M14.5, ADR-017 M17.6, M17.14, M18.1, ADR-020 M19.2), except:
- The genesis service grant, `bind:`/`dial:` and `ServiceGrantExclusion` (`governance/servicegrant.rs`)
  are removed under R44 (#94); the strict member cap (G-22) is V030-30 (#366).
- G-10's golden-vector suite does not exist on this tree, and the known gaps listed at the end are open.

**Date:** 2026-06-19
**Deciders:** Robert E. Lee <robert@agidreams.us>

## Context

In Signal, Matrix and WhatsApp group membership is not cryptographically authenticated, so one wrong add
exposes all future traffic (the "Signalgate" failure; the Megolm membership-control attacks, Albrecht,
Celi, Dowling and Jones, IEEE S&P 2023, eprint 2023/485). Vox makes reading a per-node, per-direction
cryptographic decision with no central authority: a node is read only by the nodes its owner trusts. The
only room governance is who sets the room's retention. This builds on identity (ADR-002), the join
(ADR-005), Sender Keys (ADR-006) and the causal log (ADR-008).

## Requirements

### §"Trust anchor": the genesis record

- **G-1.** A room MUST begin with a genesis record, its own struct (tag `0x000D`, domain
  `vox/genesis/v1`), with this pinned canonical body:
  `[nonce(16 B random), created, [history_mode, deniability_slot, ttl, min_suite], [service_grant_token…],
  creator_pubkey(composite, ADR-002), [sign_algo]]`, self-signed by the creator's composite identity key.
- **G-2.** The `channelID` MUST be `SHA-256(canonical genesis record)`: 256-bit, self-certifying, bound
  to one genesis. A node MUST accept a genesis fetched from a board only if its hash equals the channelID
  it joined with (ADR-005 J-8). The genesis hash is the channelID, the rendezvous seed (ADR-005) and the
  root of every admin certificate chain.
- **G-3.** The deniability slot MUST be written as `0`, and a genesis with any other value MUST be
  refused: deniable rooms are removed (PRD-001 R43; ADR-009 is withdrawn).
- **G-4.** `min_suite` MUST name a registered ciphersuite (validated at creation and on decode) and is
  bound into the channelID (ADR-003).

### §"Capability vocabulary": the room's governance (V030-32)

- **G-5.** The room's creator MUST be its root admin. Only the creator MAY add or remove an admin, with
  `vox room admin add|remove <member>` (an admin-delegation cert `0x0003` and its revocation `0x000E`).
  A node MUST honour an admin certificate only when the creator issued it, and a delegated admin's
  certificate MUST carry `policy` only, never `admin` (#319). The creator or an admin MAY end the room
  for everyone (`vox room end`, a room-lifecycle fact `0x0019`, V030-08).
- **G-6.** The only governance act MUST be setting the room's retention (the policy-update `ttl`), and
  only the creator or an admin it delegated MAY do it. The capabilities are `admin` and `policy`; every
  other capability token (`delegate`, `invite`, `passphrase-rotate`, `#role`, `bind:`, `dial:`) MUST be
  refused as unknown. Policy updates beyond retention, passphrase rotation, invite modes and the
  capability lattice are removed (#380; `bind:`/`dial:` under #94, see Status).
- **G-7.** A member that is not an admin MAY set a lower retention for its own node only, for one room;
  it MUST NOT set a retention higher than the room's. A node's retention value above the room's MUST be
  ignored (built: the effective retention is the shorter of the two, ADR-010 AR-30), with a warning
  (**planned**, #380).
- **G-8.** The genesis service grant and `service-grant-exclusion` (`0x0013`) are withdrawn
  (ADR-017 decision 3). Wire tag `0x0013` MUST NOT be reused.

### §"Per-type body schemas"

- **G-9.** Every governance entry MUST be a signed entry on the causal log (ADR-008) carrying the author
  identity, the `(channelID, epoch)` binding (ADR-006), a monotonic per-author sequence number, parent
  hash-links, the issuer's certificate-chain reference and a composite Ed25519+ML-DSA signature. Each MUST
  have one deterministic canonical-CBOR serialization (fixed field order, type tag) signed under a
  per-type domain string (for example `vox/cert/admin-deleg/v1`). The bodies MUST be:
  - admin-delegation cert (`0x0003`): `{ delegate_pubkey(composite), capability_set[], expiry?(uint) }`;
  - admin-delegation revocation (`0x000E`): `{ revoked_delegation_hash(32 B), reason?(enum) }`;
  - consent grant (`0x0004`): `{ target_id(composite fpr), skdm_ref(32 B hash of the SKDM delivered over
    ADR-004), history_mode_at_grant }`; the SKDM itself travels in the pairwise session;
  - consent revocation (`0x0005`): `{ target_id(composite fpr), new_chain_id }`;
  - policy update (`0x0006`): `{ ttl }`. **Planned (#380):** it still also carries `history_mode` and
    `min_suite` (raise-only) on this tree.

### §"Canonical encoding & evaluator"

- **G-10.** Authorization MUST be decided by one deterministic evaluator: input the requester's
  certificate chain and the room's log; output granted or denied with the governing capability. Two
  correct implementations MUST agree bit-for-bit on the golden test vectors (valid chains,
  over-attenuation, expiry, revoked links, concurrent conflicts). Under ADR-018 these are run on demand,
  not in the build or CI. **Not built:** no golden-vector suite exists on this tree; the in-process
  suite was deleted with the unit tests (V29-17, `df850734`).
- **G-11.** A delegation MUST NOT grant a capability beyond its issuer's (monotonic attenuation). A denied
  verdict MUST carry its classified reason: a delegation killed by an authorized revocation is `Revoked`;
  past `expiry` is `Expired`; an issuer whose chain does not cover the granted set is `OverAttenuated`; an
  issuer with no chain, or a cert bound to an epoch not in force, is `NotAdmin`; the highest-priority
  reason wins (`Revoked` > `Expired` > `OverAttenuated` > `NotAdmin`). A key never named is `NotAdmin`; a
  chain lacking the queried capability is `CapabilityNotHeld`.
- **G-12. (M17.8)** An entry whose body epoch differs from the epoch established in its strict causal
  past MUST be inert (`Evaluator::in_effect`), and that check MUST run before causal position is
  consulted.

### §"Join and per-sender consent flow"

- **G-13.** Trust MUST be per node, held in each node's own keyring (ADR-020 decision 3), and per
  direction. Approving a node is adding it to the keyring (`vox trust add`); from then on it reads this
  node in every room they share, including rooms made later. There MUST NOT be a per-room consent step:
  a consent grant scoped to one room is not part of the model. Trust is one-sided, and a client MUST say
  so where trust is added.
- **G-14.** Every consent grant MUST be caused by a keyring entry. A node MUST release its sender key only
  to a member its owner's keyring trusts, checked in the core (V210-148).
- **G-15.** The join flow MUST be:
  1. `N` joins (ADR-005) and opens pairwise sessions (ADR-004) with the members it meets. Holding the
     room's credentials releases no sender key, so `N` reads nothing yet.
  2. `N` decides which members read `N`, by trusting them. Joining MUST NOT release `N`'s sender key to
     anyone (M17.6). The joiner opens its session with `PairwiseFrame::Open`, one sealed message with an
     empty plaintext, so the responder gains a sending chain and receives no key and no grant.
  3. Each member `A` decides whether `N` reads `A`, by trusting `N`. Until `A` does, `A`'s messages stay
     unreadable to `N`. `N`'s view fills in monotonically, per sender.
- **G-16.** A grant MUST record what it released (`history_mode_at_grant`): the granting owner's choice
  per grant (ADR-006 S-18), never another member's history.
- **G-17.** Log authorship and read authority MUST stay separate: `admit_author` records a verified key
  as a log author, which lets its entries pass the ADR-008 predicate and nothing more; its content stays
  ciphertext until its sender key arrives. Keys come from the verified genesis, admin certificates or the
  board's records (ADR-016), never from a server-supplied list. There is no admin-issued membership
  certificate and no roster.
- **G-18.** A member reaches a room-bound service when it is in the host's keyring and in the room the
  service is bound to, both checked at dial time (ADR-017 decision 3). A member the host has not trusted
  MUST reach nothing; a trusted identity that later joins gains reach on joining. The trust surface MUST
  state this scope when trust is added, and `vox serve` MUST name who can reach the service (ADR-017
  decision 4).

### §"Revocation and epochs"

- **G-19. (M17.14, M18.1)** Removing a node from the keyring (`vox trust remove`) MUST change the lock in
  every room shared with it: rotate this node's sender key (advancing its own `chain_id`, not the room
  `epoch`), record a consent-revocation fact naming the generation that excludes it, and re-key every
  member still trusted at the new generation's origin. Revocation is rotation with one member left out;
  there is no second mechanism.
  - The keyring edit, the rotation and the log fact MUST land first and unconditionally, with no network
    needed; the re-keys follow best-effort and the tick MUST retry them.
  - The node MUST also drop the removed node's keys in every room, so it stops reading it (V210-118).
  - A room closed at the time MUST do both when it next opens (V210-118).
- **G-20.** `epoch` MUST be a single room-global counter; per-author rotation is always `chain_id`.
- **G-21.** There MUST be no per-room visibility opt-out and no admin removal of a member: a node stops
  reading a member, and stops being read by it, by removing it from its keyring (G-19). Passphrase
  rotation is removed (G-6).

### Member cap

- **G-22.** A room MUST NOT exceed its member cap (`MAX_AUTHORS` = 1024). A newcomer MUST be admitted only
  once every member that is online has agreed. A member that is offline MUST NOT block the join and learns
  of it when it returns. A join MAY be slow, or fail, while members are slow to answer. **Planned:**
  V030-30 (#366). Built (V210-128): a join to a full room is refused with the `FULL` frame, exits non-zero
  and says the room is full; no join reports success unless the joiner was admitted; a member another
  member admitted is admitted from the board even past the cap, up to `AUTHORS_HARD_LIMIT` (2048), and
  this is logged.

### §"Conflict resolution"

- **G-23.** Governance state lives on the causal log (ADR-008) and relies on its fork handling. An
  authority action made during a partition MUST be provisional until its causal neighbourhood reconciles.
- **G-24.** Consent MUST be single-writer: only `A` authors `A`'s grants, revocations and sender-key
  rotations, so `A`'s latest causal state wins. Additive facts (grants, delegations) MUST all stand,
  ordered causally.
- **G-25. §"Removal beats addition"** A revocation of an admin delegation concurrent with or after that
  delegation MUST make the key not an admin until a causally later re-delegation. A key MUST be an admin
  iff a valid delegation chain to genesis grants it and no causally later authorized revocation supersedes
  it.
- **G-26.** Among the causally maximal concurrent delegations of one delegate, the governing one MUST be
  the last in the canonical total order: Kahn's algorithm over the causal relation, always emitting the
  smallest-hash ready entry (`Causality::build`). An independent implementation MUST reproduce this order.

### §"Enforcement honesty"

- **G-27.** Only forward guarantees are cryptographic: rotating to keys a party never receives is
  enforced; keys a party already holds MUST NOT be described as recalled. A removed node keeps what it
  already read. Retention and erasure are honoured by clients (ADR-010).

### Known gaps

- `history_mode_at_grant` and `new_chain_id` are recorded but never validated by the evaluator.
- The golden-vector suite is in-process Rust assertions, not language-neutral fixtures with pinned bytes
  (the "two independent implementations" gate needs the latter). Since V29-17 (`df850734`) there is no
  suite at all (G-10).
- Role-tag ABAC is not evaluated, `Invite` has no wire encoding, and any `delegate`-holder may revoke any
  delegation: each goes with the capabilities #380 removes; only the creator removes an admin under #319.

Fixed since:
- Joining released the joiner's sender key to the member that answered (M17.6).
- `NodeCommand::Consent` released a key without a keyring entry: removed; a key goes only to a trusted
  member, checked in the core (V210-148, `bb1481b1`; proof `no_consent_without_a_ring_entry_proof.rs`).
- `Untrust` was forward-looking only and did not change the lock (M17.14, `8894b2b2`).

## Consequences

- The single-wrong-add exposure is gone by construction: nothing is readable without the reader's trust.
- Governance is serverless and client-verifiable; every admin claim chains to the genesis.
- Removing a node costs O(remaining trusted members) of SKDM redistribution, in every shared room.
- Removal-wins can briefly hide a legitimately re-added admin until the re-delegation propagates.
- A room near its cap is joined only as fast as its online members answer (G-22).

## Related ADRs

Depends on ADR-002, ADR-005, ADR-006, ADR-008. Depended on by ADR-010, ADR-013, ADR-014, ADR-017,
ADR-020, ADR-023. Cited: ADR-003, ADR-004, ADR-016, ADR-018. ADR-009 (deniable mode) is withdrawn.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
