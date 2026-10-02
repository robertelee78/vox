# ADR-014: macOS Client

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: proposed. On integrate/v0.3.0 only the embedded node over FFI (requirements 11.x,
`crates/vox-ffi`) is built. The macOS app itself (requirements 1.1–10.x) is not started; each of
those requirements is *planned*. The iOS app (PRD-001 R30) is planned for v0.4.0, and calls (PRD-001
R32) are planned for v0.4.0; neither is a v0.3.0 requirement.
**Date**: 2026-06-19
**Deciders**: Robert E. Lee
**Tags**: client, macos, ux, verification, consent-ui, ffi

## Context

The macOS client is the first native GUI over the Rust core; the Rust TUI client (ADR-015) is the
first client of any kind. The primary users are the decider and his family, across devices, macOS
first. The client's job is to make Vox's trust model usable: per-sender consent (ADR-007), member
verification (ADR-002), joining (ADR-005), the replicated log (ADR-008), at-rest protection (ADR-010)
and node operation (ADR-012). Research on key-verification UX (ARES 2023, Signal's safety-number
evolution) drives requirement 4. Tunneling has its own ADRs (ADR-013, ADR-017); this ADR only says how
the client presents it.

## Requirements

### 1. Architecture

1.1. All protocol logic MUST live in the Rust core, which also runs the local node. The app MUST be a
     thin front end over a typed API. *Planned.*
1.2. The app MUST be native SwiftUI over the Rust core, compiled as a static library with
     UniFFI-generated Swift bindings. Tauri and Electron MUST NOT be used. *Planned; the binding is
     built (11.x).*
1.3. The core MUST expose an async API with callbacks or streams. SwiftUI MUST NOT make a blocking call
     into the core, and node events MUST reach the UI as streams.
1.4. Private keys and the SEK MUST NOT cross the FFI as long-lived plaintext. Signing and decryption
     MUST happen inside the core (or `gpg-agent`, or the Secure Enclave), which holds secrets in
     locked, zeroized memory (ADR-002, ADR-010). The Swift layer MUST receive only rendered state:
     decrypted text for display, verification and consent states, sync status.
1.5. The app MUST be distributed as a notarized, hardened-runtime app signed with Developer ID (direct
     download or DMG). It MUST NOT be distributed through the Mac App Store, whose sandbox does not
     allow a long-lived background node agent. App Sandbox entitlements SHOULD be applied where they
     are compatible with the app's other components.
1.6. If the app installs a privileged helper or system extension, it MUST claim what it needs once, at
     install. Nothing on the data path MUST be privileged.

### 2. Identity and onboarding

2.1. The app MUST generate or import an Ed25519 identity with its ML-DSA co-key (ADR-002), and MUST
     present it as a **safety code**, never as a "fingerprint". *Planned.*
2.2. The Secure Enclave MUST NOT hold the identity key (it stores only P-256 keys). It MAY hold only
     the ADR-010 at-rest unlock factor: a biometric-gated random secret.
2.3. **Generate path (default).** The core MUST generate the root and hold it in locked, zeroized
     memory while unlocked. At rest the root MUST be wrapped in an identity vault whose factor
     (Argon2id over an identity passphrase, or a Secure-Enclave-gated random secret) is distinct from
     every per-channel SEK (ADR-010). This path MUST NOT require GnuPG.
2.4. **Import path.** A user MAY bind an existing GPG Ed25519 key or a smartcard as the root. Signing
     MUST then be delegated to `gpg-agent` or the card, and the private key MUST NOT leave it.
     `gpg-agent` MUST be engaged only on this path.
2.5. The app MUST require a verified, encrypted identity backup (OpenPGP format, ADR-002) before first
     use. For a hardware-bound key it MUST say that the card's own backup practice applies and MUST
     NOT imply it can export the key.
2.6. Identity selection MUST be an explicit, visible step at create and join. It MUST pre-select the
     main or last-used identity, MUST show which key the user acts as, and MUST offer a fresh
     per-channel pseudonymous identity (ADR-002) on the same screen. The app MUST NOT silently reuse an
     identity across channels.
2.7. Onboarding MUST state recovery honestly: a restored shared-root device backfills channels and
     received consent from a surviving device through the self-channel (ADR-008), with no
     re-consent; with every device lost, the user rejoins each channel and needs to be re-consented.

### 3. Channel create, join and navigation

3.1. The create screen MUST start on these policy defaults, and the creator MUST be able to change
     them (ADR-007): authorship attributable (ADR-009); history full, with forward-only as an
     opt-in; retention never expires (ADR-010). *Planned.*
3.2. An invite MUST be one scannable QR and copyable code carrying only the channel ID (ADR-005). The
     passphrase MUST be shared out of band and MUST NOT be in the same artifact, and the UI MUST
     explain why.
3.3. The UI MUST tell a joiner that joining grants nothing readable until members consent (ADR-007).
3.4. Home MUST be the list of channels the user created or joined; creating or joining MUST be the
     primary action, and each channel MAY have a local name. There MUST be no contacts tier and no
     separate 1:1 path: a two-member channel is the only direct message (ADR-001).
3.5. Members MUST be shown by a local nickname bound to a verified key, never by an account.
3.6. Nicknames, verification state and received consent MUST sync across the user's own shared-root
     devices through the self-channel (ADR-008). The client MUST add no protocol for this. Per-device
     identities keep this state device-local.

### 4. Verification

4.1. QR scan, in person, MUST be the default verification ceremony. Manual digit comparison MUST be a
     fallback only. *Planned.*
4.2. The safety code MUST be per pair, numeric and grouped, derived as ADR-015 requirement 4.2 pins
     it, so both clients agree. The QR MUST encode the same identity material.
4.3. The app MUST prompt for verification at a new member, before a consent decision and on any key
     change. It MUST NOT bury verification behind a menu.
4.4. The ceremony MUST be one scan on one screen.
4.5. The app MUST raise key-change alerts and show a per-member state: verified, unverified (TOFU) or
     key-changed, detected locally over the log. Server-based key transparency MUST NOT be adopted.

### 5. Per-sender consent

5.1. The consent UI MUST ship complete. User testing MUST be continuous and MUST NOT be a release gate.
     *Planned.*
5.2. When a newcomer joins, each member MUST be asked whether to allow them to read their messages,
     shown with that member's verification state.
5.3. Verification, outbound consent and inbound visibility MUST be three separate, labelled
     per-member states with independent controls. They MUST NOT be merged into one switch.
5.4. Per member, the app MUST show whether the user has consented to them and, where known, whether
     they have consented to the user. A newcomer MUST be told they will see each member's messages as
     that member allows.
5.5. Outbound consent ("share / stop sharing my messages") MUST rotate the user's sender key without
     them (ADR-007). Inbound visibility ("see / stop seeing their messages") MUST be local: no
     rotation and no log entry.
5.6. **Block** MUST revoke outbound consent and turn off inbound visibility in one action. A blocked
     member MUST stay in the member list, marked "Blocked"; Block MUST NOT remove anyone (ADR-007).
     **Unblock** MUST restore the user's outbound consent and inbound visibility, and MUST always be
     available from the member's entry.

### 6. Messaging

6.1. The app MUST send text and files. *Planned.*
6.2. Entries the user cannot decrypt MUST NOT be shown. Where the gap would confuse, the app MUST show
     a non-leaking "messages you haven't been given access to" marker.
6.3. Calls (PRD-001 R32) are planned for v0.4.0 as an app on the app API (ADR-022) and are not part of
     this client's v0.3.0 scope.

### 7. Node operation and availability

7.1. The app MUST embed the node and run it while the app runs. *Planned; the embedding is built
     (11.x).*
7.2. The app MUST be able to point at any user-run node as its anchor (ADR-012). Vox MUST NOT mandate
     a topology: every option MUST be configurable and none compulsory.
7.3. The app MUST show per-channel reachability and sync state, and node and anchor status. For a
     two-member channel it MUST say "both must be online, or your node reachable".

### 8. Tunneling

8.1. Tunneling MUST be present and discoverable in the app and MUST be off by default: nothing is
     reachable through it until the user turns it on. Off by default MUST NOT mean hidden. *Planned.*
8.2. Chat membership MUST NOT grant tunnel reach (ADR-017 decision 3). A room MAY carry chat and
     tunnels at once.

### 9. Notifications

9.1. A background LaunchAgent MUST keep the node syncing and MUST post a native local notification for
     each new decryptable entry. There MUST be no APNs and no third party (ADR-001). *Planned.*
9.2. Notification previews MUST be hidden by default.

### 10. At rest and device seizure

10.1. The SEK MUST live only in memory while unlocked. Locking MUST zeroize it and require the channel
      passphrase and the identity factor again (ADR-010). *Planned.*
10.2. The default MUST be a 5-minute idle lock plus lock on sleep. The lock MUST be configurable,
      including off, and turning it off MUST state that a warm Mac then exposes the local vault.
10.3. Biometrics MUST gate only the identity factor and MUST NOT replace the passphrase factor.
10.4. Disappearing messages MUST follow the room's TTL (ADR-010), off by default.
10.5. The app MUST hide notification previews by default and SHOULD deter screenshots where the OS
      allows.

### 11. The embedded node (PRD-001 R30, R31)

11.1. `crates/vox-ffi` MUST expose the node over UniFFI so that an app runs it in its own process.
      *Built.*
11.2. Only these MUST cross the boundary: in — a profile directory, passphrases (consumed, never
      returned), room links, text, app-stream labels and bytes; out — fingerprints and room ids as
      base32, rendered messages, event notices, app-stream bytes and datagrams. No key material MUST
      cross. *Built.*
11.3. The surface is `VoxNode.start(dataDir, passphrase, listen)` (creates the identity on first use,
      unlocks it after), `stop`, `fingerprint`, `rooms`, `createRoom`, `openRoom`, `joinRoom(link)`,
      `invite`, `post`, `read`, `subscribe(EventListener)`, `trust`, `untrust`, and the app API
      (ADR-022): `appListen` → `AppListener.next/accept`, `appOpen` →
      `AppStream.read/write/finish/sendDatagram/recvDatagram`. It MUST NOT expose tunnels. *Built.*
11.4. Every call that waits MUST be Swift `async`, with the work on the node's own tokio runtime.
      *Built.*
11.5. Every readable message MUST be delivered to the listener exactly once, including other
      members' messages as sync brings them in or a sender key makes them readable. *Built.*
11.6. `scripts/build-xcframework.sh` MUST build `VoxFFI.xcframework` with `ios-arm64`,
      `ios-arm64-simulator` and one `macos-arm64_x86_64` slice, each a static library, and MUST
      generate the Swift bindings from the built library. *Built.*
11.7. `crates/vox-tui/tests/ffi_swift_proof.rs` MUST prove the macOS slice from Swift against a real
      `vox daemon`: join, post, receive through `EventListener`, a 1 MiB app-stream round trip and
      100 datagrams. *Built.*
11.8. The iOS app is planned for v0.4.0 (PRD-001 R30). On integrate/v0.3.0 the
      `ios-arm64-simulator` slice runs in a simulator (`scripts/ios-sim-smoke.sh`: start, create a
      room, post, read it back); the `ios-arm64` device slice is linked but not run; no iOS run has
      reached another node and no app bundle has been built.

## Consequences

- SwiftUI over UniFFI gives the Keychain, Secure Enclave and notarization integration the security
  model needs, and the same core serves iOS. Each platform needs its own UI.
- The FFI boundary has to be kept free of secrets and blocking calls (1.3, 1.4).
- Per-sender consent has no verified precedent; it carries design risk, met by continuous user
  testing, while ADR-007's protocol guarantees do not depend on it.
- Developer ID distribution gives up the Mac App Store in exchange for a background agent and the
  freedom to install system components.
- The self-channel sync (3.6) is a real mechanism to build and test.

## Related ADRs

ADR-001, ADR-002, ADR-005, ADR-006, ADR-007, ADR-008, ADR-009, ADR-010, ADR-012, ADR-013, ADR-015
(peer client; requirement 4.2's derivation), ADR-017 (room-bound services and the entry point),
ADR-022 (app API).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
