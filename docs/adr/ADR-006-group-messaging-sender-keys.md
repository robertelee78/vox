# ADR-006: Group Messaging — Sender Keys

**Status**: implemented (M4, `crates/vox-core/src/group/`)
**Date**: 2026-06-19
**Updated**: 2026-09-21 — **rotation is live and enforced** (M18.1): the node consults
`should_rotate` on every append, a rotation retains the new generation's origin key so the members who
keep consent are re-keyed at iteration 0, and both are persisted. Known gap (2) is closed. 2026-09-20 — SKDMs are delivered over a `pairwise` stream and receiver chains persist their live state (`node::pairwise_stream`, `node::channel`, ADR-016 M14.5b). 2026-09-19 — status reconciled; Implementation notes (M4) added.
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

**Post-quantum distribution.** An SKDM is delivered **as an ordinary Double-Ratchet message inside the
already-established pairwise session** (ADR-004); it inherits that session's hybrid AEAD and the ML-KEM
secret already mixed in by PQXDH — there is **no separate per-SKDM KEM step** (implementers must not
build a redundant KEM layer). This accommodates ML-KEM's lack of static-static DH and larger keys
(ADR-003) because the KEM was already done once at session setup.

**Consent binds to an identity, not a device.** An SKDM is addressed to a recipient *identity*. Under
the shared-root multi-device model (ADR-002), the recipient's devices share received SKDMs over the
identity-keyed self-channel (ADR-008), so every device of a consented-to identity can read — adding or
restoring a shared-root device needs no re-consent. Per-device-key users are distinct identities,
consented to separately.

**History delivery (forward-only vs full-history — ADR-007 channel policy).** The SKDM names a starting
`iteration`, and the chain is one-way (you cannot derive keys before your starting point), so what a
newly-consented member can read is set by *which* SKDM the sender releases:
- **Forward-only channels:** consent releases the SKDM at the sender's **current** `iteration` → the
  newcomer reads only messages from now on.
- **Full-history channels (the default, ADR-014):** consent releases the sender's **origin SKDM
  (`iteration = 0`) for each epoch the retained history spans** → the newcomer derives the whole chain
  and reads all of that sender's retained history. Senders keep their per-epoch origin chain keys for
  this purpose, bounded by channel TTL (ADR-010).
History is therefore **per-sender and consent-gated exactly like live messages**: a member who never
consents reveals no history, and "full history" never bypasses per-sender consent.

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
- **Rotation cadence (concrete defaults, channel-policy-tunable):** a sender rotates its sender key
  (new `chain_id`) on every membership change affecting it (revocation, ADR-007) and additionally on a
  scheduled bound — **default max `N` = 1000 messages or max `T` = 7 days, whichever first** — to cap
  the post-compromise exposure window; passphrase-epoch rotation supersedes all per-sender chains.
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

## Implementation notes (M4)

These record the concrete decisions made building this ADR (`crates/vox-core/src/group/`), so the spec and code stay in lockstep:

- **SKDM (tag `0x0002`, `vox/skdm/v1`)** is the canonical body `[cid, epoch, author_id, chain_id,
  iteration, chain_key, signing_pubkey, [0x0304, 0x0401]]`, root-signed, and delivered **inside the
  ADR-004 pairwise session** (`Skdm::seal_into` / `open_from`) — no per-SKDM KEM, exactly the
  §"Post-quantum distribution" rule. `ReceiverChain::from_skdm` re-verifies the `(channelID, epoch)`
  binding and `author_id == root.fingerprint()` before deriving any state.
- **Chain KDF and message AEAD.** `mk = HMAC(CK, 0x01)`, `CK' = HMAC(CK, 0x02)`; the message header is
  bound as AEAD associated data (`vox/group-msg-ad/v1 ‖ cbor[cid, epoch, author_id, chain_id,
  iteration]`) and the ciphertext is Sender-Key-signed under `vox/group-msg/v1`; the AEAD nonce is
  `HMAC(mk, 0x03 ‖ header)[..12]` (defence in depth against key reuse under a different header). The
  receiver plans its ratchet advance in temporaries and commits only after the AEAD + signature pass;
  a consumed key is deleted (replay fails). Out-of-order window `MAX_SKIP = 1000` / cache 2000, shared
  with ADR-004.
- **Rotation bounds** `ROTATE_AFTER_MESSAGES = 1000`, `ROTATE_AFTER_SECS = 7 d` are exposed as
  `SenderChain::should_rotate` for the governing layer to poll — and the node **does** poll it, on every
  append (`node::actor::send_text` → `ChannelState::rotate_sender`, M18.1).
- **A rotation retains the new generation's origin key, and re-keys at iteration 0 (M18.1).** This is
  the decision that makes rotation free for the people who keep consent. The naive re-key — release the
  author's *current* position, as first consent does — leaves a hole exactly the width of whatever the
  author sent between rotating and reaching each recipient: a member who was merely offline for a minute
  loses messages they were entitled to. So `SenderChain::rotated` is paired with
  `OriginKeyStore::retain_origin` at the instant of minting (the origin is the live chain key only while
  `next_iteration == 0`; one step later it is gone for good), and the re-key is
  `OriginKeyStore::release_at(…, 0)`. It widens nothing: a generation minted *after* someone consented
  contains, by construction, only messages sent after their consent, so releasing it whole can never
  reveal history that consent did not already cover. The bound is `MAX_RETAINED_ORIGINS = 256`
  generations, evicting the **oldest** — never the newest, which is the one a rotation must release.
  Origins and the delivery ledger are sealed `KeyMaterial` segments (ADR-010), because a rotation that
  persisted the chain but lost the origin would strand every remaining consenter permanently.
- **What is owed is derived, never stored (M18.1).** `ChannelState::owed_rekeys` is the consent set on
  the log minus the members whose delivery ledger row already names the current generation. A revoked
  member drops out because the log says so, not because a cached list was updated — so no bookkeeping
  error can re-key someone the log has excluded. Delivery is recorded only after the bytes go out, so a
  failed delivery stays owed and the node's tick retries it when the peer is reachable.
  > **Written is not delivered (2026-09-25, v0.2.9, V29-22).** Bytes going out proved nothing: QUIC
  > acknowledges them before the recipient decides anything, and a recipient that refused the stream at
  > accept, or had no session to open the key with, dropped it without saying so. The sender recorded
  > it as delivered and never sent it again. A trusted member then never read the first room it joined:
  > measured through the real binaries, both members had nothing in the first of two rooms after 90s, in
  > 3 runs of 3. The recipient now **answers**, with one byte once the key is taken, or by resetting the
  > stream with a wire code. The sender awaits that answer on its own task, never on the actor. Anything
  > but the byte (a reset, no answer within 30s, a lost connection) lowers the ledger row for exactly that
  > generation, and the tick sends the key again. Sending a key twice is harmless.
- **Sender keys are delivered and retained (ADR-016 M14.5b).** An SKDM now travels as one frame on a
  bi-stream typed `pairwise`, sealed into the recipient's ADR-004 session (`Skdm::seal_into`), so the
  ratchet — not the stream — provides confidentiality and authenticity; the recipient verifies it against
  the author's *admitted* key and this channel/epoch before it becomes a `ReceiverChain`
  (`ChannelState::accept_skdm`). Two things this forced, both recorded here:
  (1) **A receiver chain persists its live state, not the SKDM that created it.** `ReceiverChain` gained
  `to_state`/`from_state` (sealed as a `KeyMaterial` segment, ADR-010), because `next_iteration` and the
  skipped-key cache *are* the replay defence: rebuilding from the SKDM after a restart would reset the
  head and let an already-consumed iteration decrypt again. A restored chain refuses a replay exactly as
  the live one does, and a cached key at or above the head is refused on decode.
  (2) **Key arrival and message arrival are independent, so acceptance backfills.** A message often
  arrives before the key that opens it, so accepting an SKDM retries every content entry already stored
  from that author and renders those that open — the monotone per-sender fill-in ADR-007 describes. Under
  this channel's default `ForwardOnly` history mode an SKDM released at the author's current position
  renders *nothing* earlier, which a test asserts as intended behaviour rather than a plumbing failure.
  A second SKDM for a generation already held is ignored rather than rewinding the chain head.
- **The pairwise frame names its channel (M14.7d).** An SKDM is delivered inside an ADR-004 session, and a
  session is bound to a `(channelID, epoch)` while a connection is per *peer* — so the recipient needs to
  know which session to open the frame with before it can decrypt anything. The `pairwise` frame therefore
  carries the channelID alongside the sealed message. It is not a secret (it is on the board and in the
  invite link) and the frame is inside the authenticated QUIC stream either way, so nothing this ADR
  protects is weakened; the SKDM itself is unchanged.
- **Known gaps (recorded 2026-09-19).** (1) The ADR-002 §3 cross-signature requirement is met by the
  root signature over the whole SKDM body; the separate `SenderKeyCrossSig` / `sender_key_binding_input`
  mechanism exists but is not wired anywhere — two mechanisms for one requirement, one dead (candidate
  for removal). (2) **Closed 2026-09-21 (M18.1).** Rotation was advisory: `SenderChain::encrypt` never refuses past
  the bound, and because `OriginKeyStore::derive_at` caps history release at
  `iteration ≤ MAX_SKIP = ROTATE_AFTER_MESSAGES`, an un-rotated chain past 1000 messages could not
  release history at its head. The node runtime now enforces the bound: every append consults
  `should_rotate_sender` and rotates, so a chain never runs past it in the first place. (3) `GroupMessage::to_wire` reuses the *signing* label as its wire prefix rather
  than a struct-tag frame (safe — different arity — but inconsistent with the SKDM rule).
- **History is chosen per grant, and superseded keys are deleted (2026-09-25, ADR-023 M23.4,
  PRD-001 R12/R14).** The forward-only / full-history choice above is now the approver's, per
  grant (`vox trust add --history now|full`), rather than a room-wide default; a full grant
  releases each retained generation at its origin. A superseded generation's origin is deleted
  once no full-history grant is still owed in the room, so a sender normally holds one. See
  ADR-023 §Implementation plan M23.4 for the gates and what is not yet proved.

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
