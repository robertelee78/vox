# ADR-014: macOS Client

**Status**: proposed
**Date**: 2026-06-19
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: client, macos, ux, verification, consent-ui, architecture

## Context

The macOS client is the first surface over the Rust core and the primary real-world use (the
author and his wife, across devices; macOS first, with an Apple developer account). Its job is to
make Vox's novel trust model usable: per-sender consent (ADR-007), member/key verification
(ADR-002), channel join (ADR-005), the replicated log (ADR-008), at-rest protection (ADR-010), and
connectivity/node operation (ADR-012). Research is authoritative on the make-or-break part —
**key-verification UX** — and that evidence drives the trust-ceremony design below; the remaining
UX is designed from Vox's established architecture and established secure-messenger patterns,
marked as such. This ADR specifies the complete macOS client capability with no open questions: it
fixes distribution, the FFI contract, identity storage on macOS, the navigation model, channel
policy defaults, the verification and consent ceremonies, node/availability operation, notifications,
and the at-rest UX — every one a concrete, executable decision. Capabilities surfaced by their own
ADRs (tunneling UI → ADR-013; voice/video → a future capability ADR; iOS/Linux clients → their own
ADRs) are referenced, not duplicated, and are not deferrals.

## Decision

### Client architecture

- **Headless Rust core.** All protocol logic (ADR-002…ADR-013) lives in a Rust core library that
  also runs the local node (swarm, sync, transport — ADR-008/011/012). The UI is a thin front end
  over a stable, typed API.
- **Native SwiftUI over the Rust core via UniFFI.** The macOS app is native SwiftUI; the Rust core
  is compiled to a static library with **UniFFI**-generated Swift bindings. Rationale: native gives
  first-class macOS integration the security model needs — Keychain/Secure Enclave for the at-rest
  unlock factor (ADR-010), `NetworkExtension`/`utun` for tunneling (ADR-013), notarization and
  hardened runtime — while UniFFI gives a typed, memory-safe boundary and lets **the same core be
  reused on iOS** (SwiftUI) and Linux (its own UI). **Rejected:** Tauri/Electron (webview = weaker
  native integration, larger attack surface, no clean Secure Enclave / NetworkExtension path).
- **FFI contract (binding).** The core exposes an **async, callback/stream API** — SwiftUI never
  makes a blocking call into the core, and the node's sync/connectivity events are delivered to the
  UI as streams. Private keys and the SEK **never cross the FFI as long-lived plaintext**;
  signing/decryption happen inside the core (or `gpg-agent`/Secure Enclave), which holds secrets in
  locked, zeroized memory (`mlock`/`zeroize`, ADR-002/ADR-010). The Swift layer receives only the
  rendered state it must display (decrypted text for the view, verification/consent states, sync
  status) — never raw secret material.
- **Distribution: Developer ID, notarized.** Shipped as a **notarized, hardened-runtime app via
  Developer ID** (direct download / DMG), **not** the Mac App Store. Rationale: the App Store sandbox
  cannot accommodate the `NetworkExtension` + privileged helper that tunneling requires (ADR-013) or
  a long-lived background node agent. App Sandbox entitlements are applied where compatible with those
  components; the privileged helper / system extension is added only where a TUN interface later
  requires it (ADR-013).

### Identity & onboarding

- Generate or import a GPG/Ed25519 identity (paired with its ML-DSA co-key, ADR-002); display the
  identity as a plain-language **safety code** (not "fingerprint" — evidence: the term confuses
  non-cryptographers).
- **Identity-key storage on macOS (binding).** The Secure Enclave **cannot** hold the Vox identity
  key — the Enclave stores only NIST P-256 keys, while the identity is Ed25519 + ML-DSA. The Enclave's
  role is strictly the ADR-010 *at-rest unlock factor* (a biometric-gated random secret), never the
  identity itself. Concretely:
  - **Generate path (default).** The core generates the Ed25519+ML-DSA root and holds it in locked,
    zeroized memory while unlocked. At rest the root is wrapped in a **separate identity vault** — an
    *identity* factor (Argon2id over an identity passphrase, or a Secure-Enclave-gated random secret),
    **distinct from any per-channel SEK** (ADR-010), so the identity key is available to derive each
    channel's SEK without circularity, and a warm, screen-unlocked but Vox-locked Mac never exposes the
    identity. A user-facing GnuPG install is **not required** for this path.
  - **Import path (fully built, not stubbed).** A user may bind an existing GPG Ed25519 primary/subkey
    (or a YubiKey/smartcard) as the root; signing is delegated to `gpg-agent`/the card and the private
    key never leaves it (ADR-002). `gpg-agent` is engaged **only** on this explicit path.
- **Mandatory encrypted backup.** Guided encrypted identity **backup/export** (OpenPGP format,
  ADR-002) during onboarding; root loss is unrecoverable, so the app **insists on a verified backup
  before first use**. (Hardware-bound import keys are backed up by the user's existing card/agent
  practice; the app states this honestly rather than implying it can export a non-exportable key.)
- **Per-channel identity selection.** Identity choice is an explicit, always-visible step at
  create/join that **pre-selects the main/last-used identity** (the common case is one tap) and shows
  which key you are acting as; creating a **fresh per-channel pseudonymous identity** (ADR-002) is a
  prominent option on the same screen. Vox never silently reuses an identity across channels.
- **Device add / device loss (stated honestly).** Adding or restoring a **shared-root** device backfills
  channels *and received consent* from a surviving device via the self-channel (ADR-008) — **no
  re-consent**. If **all** devices are lost (identity backup only, no sibling to sync from), recovery is
  **rejoin each channel + be re-consented** by members: inbound consent grants were device-local and are
  gone, while outbound consent you authored is on the log and recovers. The app surfaces this in
  onboarding rather than implying seamless recovery.

### Channel create / join

- **Create:** the creator (root admin) sets channel policy up front and can change it later (ADR-007).
  **Policy defaults** the create screen starts on (both options always supported):
  - **Authorship: attributable** (per-message signatures → **non-repudiable to insiders and outsiders**;
    ADR-009). Deniable mode — outsider-repudiable content — is the explicit opt-in.
  - **History: full history** (new members *may* be given prior messages; per-sender consent still
    gates what decrypts; ADR-007). Forward-only is an explicit opt-in.
  - **Retention/TTL: never expire** (ADR-010), changeable anytime.
- **Join:** present an invite as a **single scannable QR + copyable code that carries only the
  channelID (rendezvous, ADR-005)**, with the **passphrase shared over a separate out-of-band
  channel** by default — never both in one artifact, so a leaked QR alone cannot join. The UI
  explains the split in plain language. (Conservative design; this sub-area had no surviving verified
  evidence.)
- Set expectations explicitly: joining grants nothing readable until members consent (ADR-007).

### Navigation model

The channel is the unit of communication (ADR-001 principle 2): there is **no contacts tier and no
special 1:1 path** — a two-member channel *is* the only "direct message."

- **Home = the list of channels (swarms)** the user has created or joined. Creating or joining a
  channel is the primary action. The user can give each channel a **local name**.
- **Members are shown by a local nickname bound to their identity key.** The same key may recur across
  channels (shared-root identity) or a person may deliberately use different keys per channel
  (pseudonymity, ADR-002); a nickname is a private label over a *verified key*, never an account.
- **Nickname, verification state, and received consent sync across the user's own devices**
  (shared-root strategy) via the **personal self-channel — specified in ADR-008** (identity-keyed
  rendezvous in ADR-005). The client only surfaces the resulting synced state; it adds no protocol.
  Because the self-channel also syncs received SKDMs, a newly added/restored shared-root device gains
  access with **no re-consent**. Users on the **per-device-key** strategy have no shared root, so their
  state stays device-local — composes cleanly, no special case.

### Member list & verification ceremony (evidence-driven)

The single most failure-prone part of any E2EE app; the research is unambiguous, so these are
requirements, not preferences:

- **QR / in-person scan is the DEFAULT trust ceremony.** Manual digit comparison is a *fallback
  only* — long numeric fingerprints suffer ~43% false-acceptance against near-collision (AitM)
  fingerprints because users short-circuit comparisons (ARES 2023). Do not make manual comparison the
  headline path.
- **Safety-code format.** Per-pair, **numeric, grouped** (Signal's evolution: rename, per-conversation
  1:1 mapping, numeric to halve comparison load), derived from `SHA-256(Ed25519_pub ‖ ML-DSA_pub)` of
  both parties (ADR-002). The QR encodes the same identity material for one-scan verification; the
  grouped numeric code is the manual fallback.
- **Proactively prompt** verification at trust-relevant moments — new member, *before a consent
  decision*, and on any key change — never bury it behind a menu. Evidence: unprompted ceremonies
  succeed ~14% vs ~78% when the UI names the task; so name the task and guide it.
- **Fast, one step.** Single-scan, single-screen (evidence: ~11-minute ceremonies discourage use).
- **Key-change alerts + TOFU indicators** surfaced automatically over the log; verification state per
  member (verified / unverified-TOFU / key-changed). (Server-dependent key transparency like CONIKS is
  not adopted — no central server; local key-change detection over the log is.)

### Per-sender consent UX (the differentiator)

No verified external precedent survived (the Cwtch claims were refuted), so this is designed
carefully from ADR-007. Per the engineering mantra it **ships complete and production-quality** —
it is *not* a stub awaiting a future milestone, and usability validation is **not a release gate**.
Structured user testing runs **continuously** and feeds iterative refinement; ADR-007's protocol
guarantees stand regardless of it. The bar is "ship the best-designed version, complete" — never a
reason to withhold the surface or ship it incomplete.

- Consent is an explicit, **per-member decision**: when a newcomer joins the swarm, each member is
  prompted "Allow [member] to read your messages?", tied to that member's verification state to
  encourage *verify-before-consent*.
- **Three distinct, clearly-labeled states per member — never conflated:** *verification* ("is this
  really them?"), *outbound consent* ("should they see my messages?"), and *inbound visibility* ("do I
  want to see theirs?"). Independent toggles, not one trusted/untrusted switch.
- **Honest partial-visibility display:** show, per member, whether you've consented to them and (where
  known) whether they've consented to you; show a newcomer a clear "you'll see each member's messages
  as they allow you" state rather than a confusing empty/partial timeline.
- **Per-member controls (both directions, ADR-007):**
  - *Outbound consent* — "share / stop sharing my messages with them" (rotates `A`'s sender key
    excluding them).
  - *Inbound visibility* — "see / stop seeing their messages" (local; drops their sender key from your
    view; no rotation, no log entry).
- **Block — the common combined action.** Realistic flow: member-2 joins, member-1 consents, then later
  member-1 wants nothing to do with member-2. A single **"Block [member]"** action handles **both
  directions at once** — revoke outbound consent *and* opt out inbound visibility — so the user isn't
  forced to reason about two toggles in the moment. The per-member panel still exposes the two toggles
  individually for the less-common asymmetric cases.
  - **Block is NOT removal.** There is no removal (ADR-007); the blocked member **remains visible in
    the channel/swarm member list**, shown with a clear **"Blocked"** state. You simply stop sharing
    with and seeing them.
  - **Unblock re-consents both directions** — restores outbound consent (re-shares your sender key
    going forward, ADR-007) and inbound visibility (resumes rendering them). It is always available
    from the member's entry in the list.

### Messaging

- **Text and files.** Files are carried as ordinary log payloads (ADR-008): content-encrypted with a
  fresh nonce, **chunked above a size threshold (default 256 KiB/chunk)** with a **chunk-manifest entry**
  `{ file_id, total_len, content_type, chunk_hashes[] }` (canonical-CBOR, ADR-008) that orders
  reassembly and lets a receiver fetch/verify chunks independently; render-gated and TTL-pruned like any
  payload (ADR-010). No separate file-transfer path.
- **Render-gating:** undecryptable entries are not shown (ADR-008); where a gap would be confusing,
  show an honest, non-leaking "messages you haven't been given access to" marker rather than silently
  dropping context.
- Voice/video are a separate future capability ADR (the transport datagram path, ADR-011, is built to
  carry them) — out of this client capability's scope, not deferred work within it.

### Connectivity, availability & node operation

- **The macOS app embeds the node** (the core runs the local node, above) whenever it is running.
- **Headless node build.** Vox also ships a **headless node binary** (same Rust core, no UI) for an
  always-on box (LAN machine / mini PC) with a port-forward, for reachability while the Mac sleeps
  (ADR-012). The client can **point at any user-run node** as its rendezvous/relay+store anchor. Vox
  **mandates no topology** — how the household stays reachable is the users' to arrange (ADR-001/012);
  the client makes every user-run option configurable and none compulsory.
- **Surface emergent availability honestly** (ADR-001/ADR-012): per-channel reachability and sync
  state; for a two-member channel, clearly communicate "both must be online (or your node must be
  reachable)" and current status; show sync progress and node/rendezvous status (patterns informed by
  Briar/SimpleX intermittent-connectivity UX; designed, evidence-gap noted).

### Tunneling — OFF by default in the chat client

- **The human chat client ships with tunneling disabled and out of sight.** A normal chat user never
  encounters a tunnel surface: no service list, no `bind`/`dial`, no TUN interface. This matches the
  protocol invariant that tunnel access is never inherited from chat membership (ADR-013) — the GUI
  simply does not expose it by default.
- **Tunneling is an explicit opt-in** (an Advanced/Power-User toggle, or the headless node's config for
  compute-node swarms). Enabling it reveals the ADR-013 surfaces (`vox service add`, `vox forward`,
  `vox up`) and the per-member `bind:`/`dial:` capability grants. A swarm can carry both chat and
  tunnels at once (ADR-013), but in a chat-only deployment the feature stays dark.

### Notifications

- **Serverless local notifications.** A background **LaunchAgent** keeps the node syncing; on a new
  *decryptable* entry it posts a native macOS local notification. No APNs, no third party (consistent
  with ADR-001). The cost — a persistent background process and its battery/power use — is accepted
  and stated honestly. Notification previews are hidden by default (screen-security, below).

### At-rest & device-seizure UX

- **App-lock.** The SEK lives only in memory while unlocked; lock zeroizes it and forces re-auth =
  channel passphrase + identity factor (ADR-010). **Default: 5-minute idle timeout + lock on sleep.**
  The lock is **fully user-configurable, including disabling it entirely** — honoring user autonomy,
  with the **honest, documented consequence** that a warm Mac with lock disabled exposes the local
  vault (the one exposure ADR-010 otherwise bounds; the app states this plainly at the point of
  change).
- On Secure-Enclave hardware, biometrics gate the *identity factor* only and **never replace the
  passphrase factor** (ADR-010).
- **Disappearing messages** tied to admin TTL (default never-expire, so off by default; ADR-010).
- **Screen-security:** hide message previews in notifications by default; deter screenshots where the
  OS permits.

## Consequences

### Positive
- Native SwiftUI+UniFFI gives the security integrations the model depends on and reuses the Rust core
  on iOS/Linux.
- Verification is designed against the known fatal flaw of E2EE UX (scan-first, prompted, one-step).
- Per-sender consent and verification are presented as distinct, honest axes — the differentiator
  made tangible.
- Every section is concretely specified (storage, FFI contract, defaults, node operation,
  notifications, lock behavior), so an engineer can execute without re-deciding architecture.

### Negative
- Native UI is macOS-specific: Linux/iOS reuse the core but need their own UIs (their own ADRs).
- The UniFFI boundary must be carefully designed to avoid leaking secrets or blocking on the core
  (mitigated by the async/stream contract above).
- The per-sender consent UX is genuinely novel with no verified precedent — it carries design risk
  addressed by **continuous user-testing and iterative refinement** (not a release gate, not a
  deferred protocol requirement; the underlying protocol guarantees of ADR-007 do not depend on it).
- Developer-ID distribution forgoes Mac App Store discovery/auto-update in exchange for the system
  extension / privileged-helper / background-agent freedom the capability set requires.
- The personal self-channel for nickname/verification sync is a real mechanism to build and test (not
  free), justified by cross-device usability for shared-root users.

### Neutral
- Choosing native-per-platform over a single cross-platform UI is a deliberate trade of code reuse for
  integration depth and security.
- App-lock-disable and topology are deliberately left to the user, consistent with Vox's
  user-autonomy posture; the client states the consequences rather than enforcing a policy.

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
