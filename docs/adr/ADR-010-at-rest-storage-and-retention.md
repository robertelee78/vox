# ADR-010: At-Rest Storage and Retention

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: storage, at-rest, encryption, retention, ttl, device-seizure

## Context

Device seizure / local compromise is in the threat model (ADR-001). The local store holds the
replicated log (ADR-008) — including a full message history — which is a goldmine if a device is
taken. Retention is also a channel-policy concern (admin-set TTL, ADR-007). At-rest protection must
co-exist with the content-addressed, de-duplicated, sparsely-replicated log.

## Decision

**Double-lock at rest.** Encrypt the local message store such that a thief who has the device *and*
the user's GPG key would *still* need the channel passphrase. Concretely, derive the local store
key from *both* the GPG-held key material *and* the channel passphrase. Defense-in-depth: raises
the bar against device seizure beyond single-key compromise.

**Acknowledged limits of double-lock.** The channel passphrase is shared among members (not a
per-user secret), so it raises the bar against an outsider/thief, not against another member. And
passphrase rotation (ADR-007) means old messages were encrypted under the prior passphrase —
reading them after rotation requires retaining the old key or re-encrypting; this interaction must
be specified.

**Dedup/replication interaction.** Payloads encrypted under the shared channel key preserve
cross-member de-duplication (same key → same ciphertext → same CID) and sparse replication
(ADR-008). Per-recipient consent encryption differs per recipient and breaks dedup; the design
keeps channel-shared payload encryption for the log and layers per-recipient gating via key
*distribution* (ADR-006/ADR-007), not per-recipient payload re-encryption.

**Retention / TTL is admin-set and client-honored, not enforceable.** The admin sets TTL (default:
never expire) and may change it anytime. Clients are expected to honor it by pruning payload bytes
(ADR-008 payload-hash signing keeps the chain intact), but a malicious client can ignore TTL. This
limit is documented, not papered over.

## Consequences

### Positive
- Device seizure requires device + GPG key + channel passphrase to read history — strong defense-in-depth.
- TTL pruning works without breaking log integrity (ADR-008).
- Channel-shared payload encryption keeps dedup and sparse replication intact.

### Negative
- Double-lock complicates key management and the passphrase-rotation/history-readability interaction.
- TTL/erasure is best-effort; "delete" cannot be guaranteed across honest-but-curious or malicious peers.
- Shared channel passphrase as a second factor does not protect against a malicious *member*.

### Neutral
- Could be merged into ADR-008 implementation-wise, but kept separate as a distinct security decision.

## Links
**Depends on**: ADR-002, ADR-007, ADR-008.
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
