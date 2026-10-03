# ADR-005: Channel Addressing and Authenticated Join

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status:** accepted. Built in `crates/vox-core/src/join/` (M3), `node::joinstream` (ADR-016 M14.4)
and `node::link`, except:
- J-5: `<room>.vox` still resolves to the room's creator on this tree; its removal is V030-25 (#339).
- J-24: the ≈ 1–2 s mobile solve target is not measured, because no mobile client exists (ADR-014 is
  macOS).

**Date:** 2026-06-19
**Deciders:** Robert E. Lee <robert@agidreams.us>

## Context

A room (a channel) is joined with a link and a passphrase shared out of band (ADR-001). That pair does
two jobs, which this ADR keeps apart: *rendezvous* (finding the room's members) and *authentication*
(proving the joiner may join). The passphrase is low-entropy and human-chosen, so it must resist
offline dictionary attack. A join yields an authenticated pairwise session (ADR-004) and nothing
readable: who reads whom is decided by trust (ADR-007).

## Requirements

### §Joining a room

- **J-1.** Joining MUST work this way, with no other step: the two people swap fingerprints; one
  creates the room; `vox room invite` prints the room's link; the link and the passphrase are sent
  separately; the other runs `vox room join` with them; each then runs `vox trust add` for the other
  (ADR-007).
- **J-2.** A room passphrase is OPTIONAL. The core MUST NOT refuse an empty room passphrase. An identity
  passphrase is OPTIONAL by the same rule: the core MUST NOT refuse an empty identity passphrase
  (ADR-010 AR-5).
- **J-3.** A join naming a room this node already holds MUST update the room's stored address to the
  new link's addresses, not refuse (V210-167): the members the link names are dialled there, and those
  that answer, with the anchors it names, are kept as the room's address. An address at which no member
  answers MUST change nothing. A link that names no other member of the room MUST be refused as a bad
  link.
- **J-4.** A room made by a Vox release before v0.3.0 MUST be refused, saying to make the room again
  (`Fault::RoomFromBeforeV030`). There is no compatibility path.
- **J-5.** Addressing a service is ADR-017's: only `service.node.room.vox` connects; `room.vox` and
  `node.room.vox` MUST resolve to nothing. A `<room>.vox` name that resolves to the room's creator is
  removed. **Planned:** V030-25 (#339).

### §"Separate rendezvous from authentication"

- **J-6.** The invite link (`vox://…`, ADR-016) MUST carry only what finds the room: the channelID, the
  inviting host and any anchors (each a fingerprint with its addresses, at most `MAX_LINK_ANCHORS` = 4,
  ADR-012), and optionally a pin of the responder's fingerprint. The passphrase MUST NOT be in the link;
  `InviteLink` has no field for a secret.
- **J-7.** The passphrase MUST be an input to CPace only. It MUST NOT be an input to rendezvous.

#### §"channelID is high-entropy and self-certifying"

- **J-8.** The `channelID` MUST be `SHA-256(canonical genesis record)` (ADR-007 §"Trust anchor"; the
  genesis carries a 128-bit random nonce). A joiner MUST accept a genesis fetched from a board only if
  its hash equals the `channelID` it joined with, so each channel has one genesis.

#### §"channelID → rendezvous address"

- **J-9.** The rendezvous key MUST be `HKDF-SHA-256(channelID, info = "vox/rendezvous/v1" ‖ epoch_be)`,
  truncated to the key width. A memory-hard KDF MUST NOT be used here: the channelID is already
  high-entropy. ADR-012 uses this exact derivation.
- **J-10.** Any other high-entropy seed MAY use the same construction under its own label. The personal
  self-channel (ADR-008) MUST use the private `self_seed` (ADR-002), never the public identity key,
  under `"vox/self-rzv/v1"`, so no third party can locate it.

### §Authenticated join: CPace and identity proof-of-possession

- **J-11.** The join MUST run CPace instantiated as Ristretto255 + SHA-512 (CFRG primary
  instantiation, generator by `calculate_generator`/`map_to_group`, ADR-003 registry `0x07/0x01`), with
  `CI = "vox/cpace/v1" ‖ channelID ‖ epoch`, `sid` a fresh nonce per run, and `AD = suite_id`.
- **J-12.** Inside the CPace session each party MUST prove possession of its identity: it signs the
  CPace `sid` and transcript hash with its composite Ed25519+ML-DSA identity key (ADR-002) and sends its
  identity public keys; the peer MUST verify the signature and match the derived fingerprint to the one
  expected. Naming an identity in the CPace inputs MUST NOT be accepted as proof.
- **J-13.** The proof of possession MUST be AEAD-sealed (AES-256-GCM) under
  `K_pop = HKDF-SHA-256(ISK, info = "vox/cpace-pop/v1")`, returned in a zeroizing buffer, so identity keys
  and signature are not on the wire in the clear.
- **J-14.** `derive_pop_key` and the rendezvous derivation MUST return an error (`MalformedJoin`) on an
  HKDF failure. They MUST NOT substitute an all-zero key.
- **J-15.** Members MUST run pairwise CPace when they meet. A group PAKE MUST NOT be used.
- **J-16.** The transport identity MUST be the expected proof-of-possession identity: the responder
  verifies the joiner's proof against `VoxConnection::peer_id`, and the joiner MUST require the
  challenge's composite key to hash to the peer it dialled, so a third party cannot relay another's join.
- **J-17.** The joiner MUST prove first. A wrong passphrase is detected by the responder, which MUST
  answer with one opaque `Refused`: a wrong passphrase MUST NOT be distinguishable from an identity
  mismatch or a policy refusal. `PowInvalid` and `Malformed` MAY stay distinguishable (they are
  structural).
- **J-18.** The exchange MUST be ordered frames on a bi-stream typed `join` (ADR-016 M14.4):
  CHALLENGE → SOLVE → SHARE → PROOF → PROOF → INIT, then ACCEPTED, REJECTED, or FULL for a room at its
  member cap (ADR-007 G-22).
- **J-19. (M14.7c)** A node MUST hold a room's passphrase live while the room is open, because a CPace
  responder needs it at handshake time and nothing derived from it can stand in. It MUST be held in a
  zeroizing buffer and wiped from memory on lock and on close (under ADR-026, on detach and on close). A daemon's set of open rooms keeps it
  sealed at rest so the rooms reopen after a restart (#208; ADR-010). *Decided, not built (ADR-026):*
  the set is per node, and a node's rooms reopen when it attaches. A room passphrase given to a join
  travels to the daemon over the control socket in a zeroizing buffer (ADR-026 C-6).

### §Post-join

- **J-20.** A successful join MUST bootstrap a PQXDH / Double Ratchet pairwise session (ADR-004) and
  MUST yield no readable content: the joiner reads a member only once that member's node trusts it
  (ADR-007). There MUST be no admin admission step and no membership certificate.

### §Anti-abuse

- **J-21.** The read gate MUST be trust (ADR-007): a correct passphrase guess buys only ciphertext.
- **J-22.** Each join attempt MUST carry a proof-of-work token: Equihash `(n = 200, k = 9)`, bound to
  `(channelID, epoch, responder_nonce)` so it cannot be precomputed or replayed, with the difficulty
  carried in the signed responder nonce so the prover cannot understate it.
  - Verification MUST use the `equihash` (librustzcash) verifier plus the difficulty-filter hash.
  - Solving MUST use Vox's own pure-Rust solver (`join::pow::wagner`), the only prover. A non-Rust
    solver MUST NOT be used (the C++ carve-out was rejected, 2026-09-19, ADR-001 principle 10).
  - The solver's peak memory MUST be a function of the parameters alone (a full bucket drops further
    entries), and every solution it emits MUST pass the verifier for the same `(seed, nonce)`.
- **J-23.** A responder MUST verify the PoW token before doing any CPace work.
- **J-24.** Difficulty MUST be counted in base solves: a `d`-bit filter costs `max(1, 2^d / 2)` solves
  (`Difficulty::expected_solves`). The responder's base MUST be `DEFAULT_INVITE` = 1 bit (low but non-zero,
  so a leaked channelID still costs a full solve per attempt); `DEFAULT_OPEN` = 2 bits; `ZERO` MAY be used
  only for an explicit LAN or closed deployment. A joiner MUST refuse a challenge above `MAX` = 8 bits
  before grinding. The target base solve SHOULD be ≈ 1–2 s on a mobile CPU.
- **J-25.** The responder MUST adapt difficulty to its live count of joins in flight with
  `Difficulty::adapted_for_load`: one bit per doubling of the queue at or above `ADAPT_THRESHOLD` = 4,
  saturating at `MAX`, falling back as the queue drains.
- **J-26.** The log MUST accept entries only from identities that completed the authenticated join and
  carry valid per-author composite signatures (ADR-008). There MUST be no per-author entry or byte quota
  (PRD-001 R3, 2026-09-24): an admitted member is not rate-limited.
- **J-27.** Peers MAY rate-limit as a first filter; that MUST NOT be treated as the security boundary.
  A joined member's abuse is bounded by membership (its peers remove their trust, ADR-007), and the board
  by ADR-012's rendezvous-record caps.

## Consequences

- The passphrase is a cryptographic gate, not obscurity, and offline guessing is not possible.
- Serverless: no prekey server; peers authenticate as equals.
- A leaked passphrase lets an attacker join, but yields only ciphertext unless members trust it.
- Moving the link and the passphrase by two channels is a burden the user owns.
- Group PAKE and affiliation hiding are left to a later metadata-privacy phase.

## Related ADRs

Depends on ADR-002, ADR-003, ADR-004. Depended on by ADR-007, ADR-012. Cited: ADR-001, ADR-008,
ADR-010, ADR-014, ADR-016, ADR-017.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
