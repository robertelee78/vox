# ADR-005: Channel Addressing and Authenticated Join

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: channel, addressing, pake, cpace, rendezvous, join

## Context

A channel is addressed magnet-link style by a channel ID + passphrase shared out-of-band
(ADR-001). Two distinct jobs are bundled in that string and must be separated: *rendezvous*
(finding the swarm) and *authentication* (proving you may join). The passphrase is low-entropy
and human-chosen, so it must resist offline dictionary attack. Discovery rides the P2P swarm/DHT
(ADR-012). Joining must yield a real authenticated pairwise channel (ADR-004), and — critically —
joining must grant *no* readable content by itself (per-sender consent, ADR-007).

## Decision

**Authenticated join = CPace** (the CFRG-recommended *balanced* PAKE). Symmetric (no server, no
fixed roles), implicit mutual authentication, and a proof that an attacker gets at most one online
guess per interaction — provably resisting offline dictionary attack on the low-entropy passphrase
(UC proof, eprint 2021/114). Bind GPG/Ed25519 identity strings (ADR-002) into CPace's CI/sid/AD so
the handshake authenticates party identities, not merely the passphrase. Pairwise CPace-on-meet
between members; no bespoke group PAKE (GPAKE is immature/unstandardized).

**Separate rendezvous from authentication.**
- **channelID → rendezvous address.** Derive the DHT/PubSub lookup key from the channel ID via a
  one-way (and slow/memory-hard) KDF. Use a *distinct, high-entropy* channel ID for rendezvous;
  do **not** derive the public lookup key directly from the human passphrase, or passive DHT
  observers could offline-guess it (this derivation is outside CPace's proof).
- **passphrase → CPace secret only.**

**Post-join.** A successful CPace run bootstraps a PQXDH/Double-Ratchet pairwise session (ADR-004).
Membership and any readable content still require the consent + certificate machinery of ADR-007;
a joined node that no member has consented to sees only ciphertext.

**Anti-abuse.** PAKE does not stop *online* guessing (one per run); add rate-limiting and/or
proof-of-work join tokens on join attempts (ADR-012).

## Consequences

### Positive
- The passphrase becomes a real cryptographic gate, not mere obscurity.
- Serverless: no prekey server; peers authenticate as equals.
- Separating rendezvous-ID from auth-passphrase closes the offline-guessing leak on the DHT.

### Negative
- A leaked passphrase lets an attacker complete the join (but still yields only ciphertext until
  members consent — ADR-007); passphrase rotation is the mitigation (ADR-007 epoch).
- Out-of-band exchange of channelID + passphrase is a usability burden the user owns.

### Neutral
- Group PAKE / affiliation-hiding (partitioned GPAKE) is deferred to the metadata-privacy phase.

## Links
**Depends on**: ADR-002, ADR-003, ADR-004.
- Depended on by: ADR-007, ADR-012.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
