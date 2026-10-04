# ADR-009: Deniability Mode (per-channel)

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Withdrawn (PRD-001 R43). The code is removed. Only the requirements below bind: they say
what remains on the wire so existing rooms keep their names. As R43 requires, the withdrawn design is
kept in the non-normative design record at the end.
**Deciders**: Robert E. Lee <robert@agidreams.us>

## Context

Deniability would have been a per-channel option: after an epoch closed, nothing would prove to an
outsider who wrote a message. Vox does not offer it (PRD-001 R43); every room is attributable.

## Requirements

1. **R43.** The code MUST NOT contain deniable mode: no deniable group key agreement, no deniable
   authenticator, and no non-attributable fork alarm. *Status:* built.
2. A genesis policy MUST keep the deniability slot in its wire layout, because a room's channelID is
   the hash of the genesis bytes and dropping the slot would rename every existing room. The slot MUST
   be written as `0`. A genesis carrying any other value MUST be refused, so a deniable room can be
   neither created nor joined (`governance/genesis.rs`, `attributable_slot`). *Status:* built.
3. A log entry's `auth_type` `2` (the removed deniable authenticator) MUST be refused like any unknown
   type. *Status:* built (`log/entry.rs`, `decode_authenticator`).
4. The ADR-008 struct tags `0x000B` (formerly `dgka-setup`) and `0x0010` (formerly `esk-publication`)
   MUST stay reserved: a build MUST NOT write them, and they MUST NOT be reused. A frame carrying either
   MUST be refused as an unknown struct tag (`UnknownStructTag`, sync wire error `0x03`).
   *Status:* built (`wire.rs` marks both reserved).

## Consequences

- No room is deniable. A message's authenticator is the author's composite signature (ADR-008), so
  authorship and forks are attributable, to insiders and outsiders alike.
- Every existing room keeps its channelID.

## Related ADRs

ADR-002, ADR-003, ADR-006, ADR-007, ADR-008 (the log and its struct tags), ADR-014.

## Design record (non-normative)

The withdrawn design, kept as R43 requires. Nothing in this section binds the code.

- **Scope:** weak (content) deniability, after mpENC: message contents deniable, participation not.
  Repudiation was retrospective: offline, against a later judge, not live unlinkability.
- **Signing:** governance and structural entries, including the setup rounds, were static
  composite-signed in every mode. Content in a deniable channel was signed only with a per-epoch,
  per-member ephemeral composite (Ed25519+ML-DSA-65) key `esk_i`.
- **Setup:** a 4-round deniable group key agreement plus signature-key exchange, after Van Gundy and
  Bohli–Steinwandt, carried as `dgka-setup` (`0x000B`) entries:
  1. commit: `SHA-256("vox/dgka-commit/v1" ‖ author_pubkey ‖ epk ‖ z ‖ n16)`;
  2. reveal: `(epk_i, z_i)`, statically signed over `vox/dgka-setup/v1 ‖ CBOR[cid, epoch, author_id, epk, z]`;
  3. bind: each member signed `T_bind = SHA-256(T ‖ X_1..m)` with `esk_i`;
  4. confirm: `HMAC-SHA-256(K_confirm, T_bind)`.

  `K` was a classical Burmester–Desmedt key over ristretto255 shares in ascending author-pubkey order,
  through HKDF with `info = "vox/dgka/v1" ‖ cid ‖ epoch_le`. It only confirmed the agreement. Content
  confidentiality stayed with the PQ sender keys (ADR-006).
- **Repudiation:** at epoch end, after the epoch had closed, each member published `esk_i` as an
  `esk-publication` (`0x0010`) entry, after which anyone could forge that epoch's content.
- **Consent:** one ephemeral key per member, not a shared group secret, so ADR-007's per-sender consent
  held unchanged.
- **Mid-epoch join:** the consent grant naming the newcomer triggered a fresh `(esk', epk')` and a
  re-run of bind and confirm.
- **Forks:** automatic freezing was disabled for deniable content, because it would have been a
  framing primitive. A content fork raised a non-attributable alarm. Governance forks stayed
  attributable.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
