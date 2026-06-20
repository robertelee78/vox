# ADR-006: Group Messaging — Sender Keys

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: group-messaging, sender-keys, channel, pq-kem

## Context

The channel is the unit; every message is a one-to-many broadcast to the channel (ADR-001). The
group-messaging primitive must (a) make per-sender consent expressible (ADR-007), (b) satisfy the
PQ policy (ADR-003), and (c) avoid the cross-group confusion weakness documented in the
Sender-Keys literature. The alternative, MLS/TreeKEM, converges all members onto a *single* shared
epoch key — which makes per-sender partial visibility (the core of ADR-007) effectively
impossible. Sender Keys, by contrast, gives each member their own key material distributed
per-recipient, which is exactly what per-sender consent needs.

## Decision

**Group messaging = Sender Keys, channel-scoped.** Each member generates their own sender key
(chain ID, chain key, signing keypair) and distributes a per-author Sender-Key Distribution
Message (SKDM) to each recipient over the pairwise channel (ADR-004). Messages are broadcast once
under the sender's current chain key; the chain ratchets forward per message.

**Per-recipient distribution is the consent hook.** Because each member distributes their own SKDM
individually, "consent" is simply *withholding* a member's SKDM from a newcomer until that member
consents (ADR-007). This requires no new cryptographic construct.

**Mandatory (channelID, epoch) binding.** Sender keys are NOT inherently bound to a logical group —
without binding, an inbound session from channel G can be replayed as one in channel H (cross-group
confusion; eprint 2023/1385). Every SKDM and message MUST bind `(channelID, epoch)` into its
signed/AAD context. The epoch is the passphrase-rotation generation (ADR-007), giving a clean
boundary that invalidates prior-epoch keys.

**Post-quantum distribution.** SKDM transport uses the PQXDH pairwise channel (ADR-004); the
distribution is KEM-encapsulation-based, accommodating ML-KEM's lack of static-static DH and
larger keys (ADR-003).

**PCS via explicit rotation.** Base Sender Keys has only weak post-compromise security and does
not self-heal (Balbás et al., ASIACRYPT 2023). Recovery and revocation rely on *explicit* sender-
key rotation and passphrase-epoch rotation (ADR-007), not on ratchet self-healing.

**Wire format & operational rules (so the group layer is buildable):**
- **SKDM fields:** `{ channelID, epoch, author_id, chain_id, iteration, chain_key, signing_pubkey,
  algo_ids, signature }`. The **`chain_id` is a per-sender generation identifier distinct from the
  channel `epoch`** — it increments on every per-member sender-key rotation (revocation, scheduled
  refresh) so multiple generations are unambiguous within one epoch.
- **Message header:** `{ channelID, epoch, author_id, chain_id, iteration }`, all bound into the
  AEAD associated data; receivers reject a message whose `(channelID, epoch)` does not match the
  expected channel (the cross-group-confusion guard).
- **Replay / window:** accept a message only if its `iteration` advances the receiver's last-seen
  value for `(author_id, chain_id)`; cache a **bounded** set of skipped per-iteration message keys
  for out-of-order delivery (same `MAX_SKIP` discipline as ADR-004); reject beyond the bound.
- **Rotation cadence:** a sender rotates its sender key (new `chain_id`) on every membership change
  affecting it (revocation, ADR-007) and additionally on a scheduled bound (max `N` messages or max
  `T` time) to cap the post-compromise exposure window; passphrase-epoch rotation supersedes all
  per-sender chains.
- **Compromise recovery:** because there is no self-heal, recovery is an explicit `chain_id` rotation
  redistributed to current consenters (ADR-007); the schedule above bounds how long a leaked sender
  key remains useful.

## Consequences

### Positive
- Per-author key model makes per-sender consent (ADR-007) natural — the headline differentiator.
- Efficient one-to-many broadcast; channel-scoped fits the ADR-001 model exactly.
- Vindicates choosing Sender Keys over MLS for *this* product's trust model.

### Negative
- Weak PCS inherent to Sender Keys; mitigated only by explicit rotation (a chatty operation as
  membership churns).
- Larger PQ keys increase SKDM size and distribution cost (O(recipients) per rotation).

### Neutral
- MLS/TreeKEM remains a possible future option for channels that prioritize group-PCS over
  per-sender partial visibility, but is not adopted now.

## Links
**Depends on**: ADR-003, ADR-004.
- Depended on by: ADR-007, ADR-008, ADR-009.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
