# ADR-014: macOS Client

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: client, macos, ux, verification, consent-ui, architecture

## Context

The macOS client is the first surface over the Rust core and the primary real-world use (the
author and his wife, across devices; macOS first, with an Apple developer account). Its job is to
make Vox Lux's novel trust model usable: per-sender consent (ADR-007), member/key verification
(ADR-002), channel join (ADR-005), the replicated log (ADR-008), at-rest protection (ADR-010), and
connectivity/node operation (ADR-012). Research is authoritative on the make-or-break part —
**key-verification UX** — and that evidence drives the trust-ceremony design below; the remaining
UX is designed from Vox Lux's established architecture and established secure-messenger patterns,
marked as such. This ADR specifies the complete macOS client capability. Capabilities surfaced by
their own ADRs (tunneling UI → ADR-013; voice/video → a future capability ADR; iOS/Linux clients →
their own ADRs) are referenced, not duplicated, and are not deferrals.

## Decision

### Client architecture

- **Headless Rust core.** All protocol logic (ADR-002…ADR-013) lives in a Rust core library that
  also runs the local node (swarm, sync, transport — ADR-008/011/012). The UI is a thin front end
  over a stable, typed API.
- **Native SwiftUI over the Rust core via UniFFI.** The macOS app is native SwiftUI; the Rust core
  is compiled to a static library with **UniFFI**-generated Swift bindings. Rationale: native gives
  first-class macOS integration the security model needs — Keychain/Secure Enclave for the
  identity-factor unlock (ADR-010), `NetworkExtension`/`utun` for tunneling (ADR-013), notarization
  and hardened runtime — while UniFFI gives a typed, memory-safe boundary and lets **the same core
  be reused on iOS** (SwiftUI) and Linux (its own UI). **Rejected:** Tauri/Electron (webview =
  weaker native integration, larger attack surface, no clean Secure Enclave / NetworkExtension
  path).
- **Secret handling across the FFI.** Private keys and the SEK never cross the FFI as long-lived
  plaintext; signing/decryption happen in the core (or `gpg-agent`/Secure Enclave), which holds
  secrets in locked, zeroized memory (ADR-002/ADR-010). The Swift layer receives only what it must
  render.
- **Packaging.** App Sandbox + Hardened Runtime + notarization; Keychain for the wrapped identity
  factor; an XPC/privileged helper only where a TUN interface later requires it (ADR-013).

### Identity & onboarding

- Generate or import a GPG/Ed25519 identity (ADR-002); display the identity as a plain-language
  **safety code** (not "fingerprint" — evidence: the term confuses non-cryptographers).
- Per-channel identity selection is an explicit step at create/join (pseudonymity, ADR-002).
- Guided, encrypted identity **backup/export** during onboarding; loss is unrecoverable, so the app
  insists on a backup before first use.

### Channel create / join

- **Create:** the creator (root admin) sets channel policy up front and can change it later —
  history vs forward-only, deniable vs attributable, retention/TTL (ADR-007).
- **Join:** present an invite as a **single scannable QR + copyable code that carries only the
  channelID (rendezvous)**, with the **passphrase shared over a separate out-of-band channel** by
  default — never both in one artifact, so a leaked QR alone cannot join. The UI explains the split
  in plain language. (Conservative design; this sub-area had no surviving verified evidence.)
- Set expectations explicitly: joining grants nothing readable until members consent (ADR-007).

### Member list & verification ceremony (evidence-driven)

The single most failure-prone part of any E2EE app; the research is unambiguous, so these are
requirements, not preferences:

- **QR / in-person scan is the DEFAULT trust ceremony.** Manual digit comparison is a *fallback
  only* — long numeric fingerprints suffer ~43% false-acceptance against near-collision (AitM)
  fingerprints because users short-circuit comparisons (ARES 2023). Do not make manual comparison
  the headline path.
- **Plain-language, per-pair, numeric** "safety code" for the manual fallback (Signal's evolution:
  rename, per-conversation 1:1 mapping, numeric to halve comparison load).
- **Proactively prompt** verification at trust-relevant moments — new member, *before a consent
  decision*, and on any key change — never bury it behind a menu. Evidence: unprompted ceremonies
  succeed ~14% vs ~78% when the UI names the task; so name the task and guide it.
- **Fast, one step.** Single-scan, single-screen (evidence: ~11-minute ceremonies discourage use).
- **Key-change alerts + TOFU indicators** surfaced automatically over the log; verification state
  per member (verified / unverified-TOFU / key-changed). (Server-dependent key transparency like
  CONIKS is not adopted — no central server; local key-change detection over the log is.)

### Per-sender consent UX (the differentiator)

No verified external precedent survived (the Cwtch claims were refuted), so this is designed
carefully from ADR-007 and will require user testing:

- Consent is an explicit, **per-member decision**: when a newcomer is admitted, each member is
  prompted "Allow [member] to read your messages?", tied to that member's verification state to
  encourage *verify-before-consent*.
- **Two distinct axes, never conflated:** *verification* ("is this really them?") and *consent*
  ("can they read me?" / "can I read them?") are shown as separate, clearly-labeled states per
  member — avoiding the binary trusted/untrusted confusion.
- **Honest partial-visibility display:** show, per member, whether you've consented to them and
  (where known) whether they've consented to you; show a newcomer a clear "you'll see each member's
  messages as they allow you" state rather than a confusing empty/partial timeline.
- **Revocation** is a clear per-member "stop sharing my messages with them" action (triggers
  rotation, ADR-007).

### Messaging

- **Text and files.** Render-gated: undecryptable entries are not shown (ADR-008); where a gap would
  be confusing, show an honest, non-leaking "messages you haven't been given access to" marker
  rather than silently dropping context.
- Voice/video are a separate future capability ADR (the transport datagram path, ADR-011, is built
  to carry them) — out of this client capability's scope, not deferred work within it.

### Connectivity, availability & node operation

- Surface **emergent availability honestly** (ADR-001/ADR-012): per-channel reachability and sync
  state; for a two-member channel, clearly communicate "both must be online" and current status;
  show sync progress and node/rendezvous status (patterns informed by Briar/SimpleX intermittent-
  connectivity UX; designed, evidence-gap noted).
- **Run-your-own-node configuration:** point the client at the user's always-on node / LAN box with
  port-forward as their rendezvous/relay (ADR-012).

### At-rest & device-seizure UX

- **App-lock** on idle-timeout / manual / sleep, with re-auth = channel passphrase + identity
  factor; on Secure-Enclave hardware, biometrics gate the *identity* factor only and never replace
  the passphrase factor (ADR-010).
- **Disappearing messages** tied to admin TTL; **screen-security** (hide previews; deter
  screenshots where the OS permits).

## Consequences

### Positive
- Native SwiftUI+UniFFI gives the security integrations the model depends on and reuses the Rust
  core on iOS/Linux.
- Verification is designed against the known fatal flaw of E2EE UX (scan-first, prompted, one-step).
- Per-sender consent and verification are presented as distinct, honest axes — the differentiator
  made tangible.

### Negative
- Native UI is macOS-specific: Linux/iOS reuse the core but need their own UIs (their own ADRs).
- The UniFFI boundary must be carefully designed to avoid leaking secrets or blocking on the core.
- The per-sender consent UX is genuinely novel with no verified precedent — it carries design risk
  addressed by **pre-release usability validation as a release acceptance criterion** (not a deferred
  protocol requirement; the underlying protocol guarantees of ADR-007 do not depend on it).

### Neutral
- Choosing native-per-platform over a single cross-platform UI is a deliberate trade of code reuse
  for integration depth and security.

## Links
**Depends on**: ADR-002, ADR-005, ADR-006, ADR-007, ADR-008, ADR-009, ADR-010, ADR-012, ADR-013.
- First user-facing surface of the capability series.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
