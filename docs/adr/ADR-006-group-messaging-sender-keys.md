# ADR-006: Group Messaging — Sender Keys

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status:** accepted. Built in `crates/vox-core/src/group/` (M4), `node::pairwise_stream` and
`node::channel` (ADR-016 M14.5b), with rotation enforced (M18.1), except: S-5's shared-root device
sharing is planned (ADR-002 D2), and the two known gaps below are open.
**Date:** 2026-06-19
**Deciders:** Robert E. Lee <robert@agidreams.us>

## Context

Every message is a one-to-many broadcast to a room (ADR-001). The group primitive must let each node
decide who reads it (ADR-007), meet the post-quantum policy (ADR-003), and avoid the cross-group
confusion weakness in the Sender Keys literature. MLS/TreeKEM puts every member on one shared epoch key,
which makes per-sender visibility impossible; Sender Keys gives each member its own key, distributed per
recipient, which is what per-sender trust needs.

## Requirements

### §Decision

- **S-1.** Group messaging MUST be Sender Keys, scoped to one room. Each member MUST generate its own
  sender key (chain ID, chain key, signing keypair) and send a per-author Sender-Key Distribution
  Message (SKDM) to each recipient over the pairwise channel (ADR-004). A message MUST be broadcast once
  under the sender's current chain key, and the chain MUST ratchet forward per message. MLS/TreeKEM is
  not adopted.
- **S-2.** Per-recipient distribution is the consent hook: a node MUST release its SKDM only to members
  its owner's keyring trusts (ADR-007 G-14). Withholding the SKDM is the whole mechanism; no other
  cryptographic construct is used.
- **S-3.** Every SKDM and every message MUST bind `(channelID, epoch)` into its signed or AEAD
  associated-data context, and a receiver MUST reject a message whose `(channelID, epoch)` is not the
  expected room's (cross-group confusion, eprint 2023/1385).
- **S-4.** An SKDM MUST be delivered as an ordinary Double Ratchet message inside the established
  pairwise session (ADR-004), inheriting its hybrid AEAD and PQXDH's ML-KEM secret. A separate
  per-SKDM KEM step MUST NOT be built.
- **S-5.** An SKDM MUST be addressed to a recipient identity (a node), not to a device. **Planned
  (ADR-002 D2):** under a shared root, the identity's devices share received SKDMs over the self-channel
  (ADR-008), so adding a device needs no new trust. A per-device key is a distinct identity, trusted
  separately.
- **S-6.** Post-compromise recovery and revocation MUST rely on explicit sender-key rotation (S-14),
  never on ratchet self-healing, which Sender Keys does not provide (Balbás et al., ASIACRYPT 2023).

### §Wire

- **S-7.** An SKDM MUST be tag `0x0002`, domain `vox/skdm/v1`, canonical body
  `[cid, epoch, author_id, chain_id, iteration, chain_key, signing_pubkey, [0x0304, 0x0401]]`,
  root-signed. `chain_id` MUST be a per-sender generation counter, distinct from the room `epoch`,
  incremented on every rotation. `ReceiverChain::from_skdm` MUST re-verify the `(channelID, epoch)`
  binding and `author_id == root.fingerprint()` before deriving any state, and the recipient MUST verify
  the SKDM against the author's admitted key (`ChannelState::accept_skdm`).
- **S-8.** A message header MUST be `{channelID, epoch, author_id, chain_id, iteration}`, bound as AEAD
  associated data `vox/group-msg-ad/v1 ‖ cbor[cid, epoch, author_id, chain_id, iteration]`; the
  ciphertext MUST be Sender-Key-signed under `vox/group-msg/v1`.
- **S-9.** The chain KDF MUST be `mk = HMAC(CK, 0x01)`, `CK' = HMAC(CK, 0x02)`, and the AEAD nonce
  `HMAC(mk, 0x03 ‖ header)[..12]`.
- **S-10.** A receiver MUST accept a message only if its `iteration` advances the last seen for
  `(author_id, chain_id)`, MUST cache skipped keys within `MAX_SKIP` = 1000 per chain and 2000 in all
  (ADR-004 W3), and MUST reject beyond. It MUST plan the ratchet advance in temporaries and commit only
  after the AEAD and signature pass, and MUST delete a consumed key.
- **S-11. (M14.7d)** The `pairwise` frame that carries an SKDM MUST name its channelID beside the sealed
  message, so the recipient knows which session opens it.
- **S-12. (M14.5b)** A receiver chain MUST persist its live state (`next_iteration` and the skipped-key
  cache), sealed as a `KeyMaterial` segment (ADR-010), never the SKDM it came from. A restored chain MUST
  refuse a replay as the live one does, and a cached key at or above the head MUST be refused on decode.
  A second SKDM for a generation already held MUST be ignored, never rewind the head.
- **S-13.** Accepting an SKDM MUST retry every content entry already stored from that author and render
  those that open.

### §Rotation (M18.1)

- **S-14.** A sender MUST rotate its sender key (new `chain_id`) on every membership change that affects
  it (a trust removal, ADR-007 G-19) and on the schedule `ROTATE_AFTER_MESSAGES` = 1000 messages or
  `ROTATE_AFTER_SECS` = 7 days, whichever comes first. The node MUST check `should_rotate_sender` on every
  append, so a chain never runs past the bound.
- **S-15.** A rotation MUST retain the new generation's origin key at the moment it is minted
  (`OriginKeyStore::retain_origin`) and MUST re-key every member that keeps its trust at iteration 0
  (`release_at(…, 0)`), so a rotation costs them nothing, including members who were away. At most
  `MAX_RETAINED_ORIGINS` = 256 generations are kept, evicting the oldest. Origins and the delivery ledger
  MUST be sealed `KeyMaterial` segments (ADR-010).
- **S-16.** What is owed MUST be derived, never stored: `ChannelState::owed_rekeys` is the consent set
  on the log minus the members whose delivery-ledger row names the current generation. A member the log
  excludes MUST drop out of it.
- **S-17. (V29-22)** A key MUST count as delivered only when the recipient answers. The recipient MUST
  answer with one byte (`KEY_TAKEN`) once it has taken the key, or reset the stream with a wire code. The
  sender MUST await that answer on its own task, never on the actor, for `KEY_DELIVERY_PATIENCE` = 30 s.
  Anything but the byte (a reset, no answer, a lost connection) MUST lower the ledger row for exactly that
  generation, and the tick MUST send the key again. Sending a key twice is harmless. When no direct path
  reaches the recipient, the key goes through the log as a key-package (ADR-023 decision 4).

### §History

- **S-18.** An SKDM names a starting `iteration`, and the chain is one-way, so what a newly trusted
  member reads of a sender is set by which SKDM that sender releases. The choice MUST be the granting
  owner's, per grant (`vox trust add --history now|full`, PRD-001 R12, ADR-023 M23.4):
  - `now` (the default) MUST release the sender's current iteration: the newcomer reads from now on;
  - `full` MUST release each retained generation at its origin: the newcomer reads that sender's retained
    history.
  History MUST be per sender and trust-gated exactly as live messages are: a node that never trusts a
  member reveals no history to it, and nobody can release another member's history.
- **S-19.** A superseded generation's origin key MUST be deleted once no full-history grant is still owed
  in the room (`prune_superseded_origins`, PRD-001 R14). For a trusted identity that has not joined, it
  MUST be kept `UNJOINED_HOLD_SECS` = 30 days in a room kept forever, or for the room's retention.

### Known gaps

1. The ADR-002 §3 cross-signature requirement is met by the root signature over the whole SKDM body; the
   separate `SenderKeyCrossSig` / `sender_key_binding_input` mechanism exists but is not wired anywhere —
   two mechanisms for one requirement, one dead (candidate for removal).
2. `GroupMessage::to_wire` reuses the *signing* label as its wire prefix rather than a struct-tag frame
   (safe — different arity — but inconsistent with the SKDM rule).

Fixed since: rotation was advisory (`SenderChain::encrypt` never refused past the bound); the node now
rotates on every append (S-14, M18.1).

## Consequences

- The per-author key model makes per-sender trust (ADR-007) natural, with one-to-many broadcast.
- Post-compromise security is weak, as in all Sender Keys, and is bounded only by explicit rotation,
  which costs O(recipients) per rotation.
- Post-quantum keys make SKDMs larger and their distribution costlier.
- MLS/TreeKEM stays a possible future option for rooms that prefer group PCS to per-sender visibility.

## Related ADRs

Depends on ADR-003, ADR-004. Depended on by ADR-007, ADR-008. Cited: ADR-001, ADR-002, ADR-010,
ADR-016, ADR-023. ADR-009 (deniable mode) is withdrawn (PRD-001 R43).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
