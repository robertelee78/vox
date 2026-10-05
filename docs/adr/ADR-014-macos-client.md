# ADR-014: The macOS App

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Proposed for v0.4.0. Nothing in this ADR is built unless a requirement says so.
**Date**: 2026-10-05
**Deciders**: Robert E. Lee
**Tags**: client, macos, swiftui, appkit, daemon-client, packaging
**Related**: ADR-001, ADR-013, ADR-015, ADR-017, ADR-018, ADR-020, ADR-026, ADR-028

## Context

Vox.app is the native macOS client for v0.4.0. ADR-028 defines what a person sees and does in it,
the same as in the TUI; this ADR defines how the app is built, packaged, installed and proved. The
app is a client of the account's daemon (ADR-026 S-4), like the TUI and every `vox` verb. The iOS
app (v0.4.1) hosts its own node and is not covered here; calls are v0.5.0.

## Requirements

### 1. Architecture

- **M-1.** Vox.app MUST be a native SwiftUI app, with AppKit where SwiftUI lacks a surface (the
  menu bar extra, `NSVisualEffectView`, services, the share extension). Electron and Tauri MUST NOT
  be used (ADR-028 A-1).
- **M-2.** The app MUST NOT host a node. It MUST be a client of the daemon's control socket,
  `<data root>/.daemon/vox.sock` (ADR-026 C-1), speaking IPC protocol version 9 or later exactly as
  `vox` does.
- **M-3.** The protocol MUST be spoken by Rust, not reimplemented in Swift: the app links a Rust
  static library that wraps `vox-core`'s own client (`node::daemonipc::DaemonClient` and
  `node::ipc` frames) and exposes it to Swift through UniFFI. Reasons:
  - one implementation of the framing, canonical CBOR, the `Use { node }` opening, paging and the
    version check, so a protocol change is a compile error in the app, not a silent misread;
  - passphrases stay in zeroizing Rust buffers end to end (ADR-026 C-6), never Swift `String`s;
  - ADR-001 principle 10 (Rust-maximal; Swift only for native UX).
  Rejected: a Swift reimplementation of the frames (a second implementation of about 6,000 lines
  of protocol, drifting at every bump); driving `vox` subprocesses and parsing their output (not
  every request has a `--json` form, event streams need a long-lived process, and passphrases
  would cross a pipe).
- **M-4.** The Rust library MUST be `crates/vox-ffi`, holding two UniFFI objects in one
  XCFramework: `VoxClient`, the daemon client this app uses, and `VoxNode`, the in-process node,
  kept only for the iOS app (ADR-026 S-4's exception). `VoxClient` MUST expose, as Swift `async`
  calls and an event stream, what the TUI uses over the socket: node list, attach and detach;
  rooms, roster, read (paged), tail events, post (with `to`, `re`, `urgent`), create, join, link,
  leave, end, retention, admin; trust add, list, rename, remove; services list, add, remove;
  forward and its close; shares and pulls (ADR-028 §5); status; and the decision record (ADR-028
  §7). Requests the daemon does not yet serve are to be added to the protocol first, used by the
  TUI and the app alike.
- **M-5.** Nothing but rendered state MUST cross into Swift: decrypted text for display, aliases,
  fingerprints, trust states, addresses, counts and paths. Keys, sender keys and room secrets MUST
  NOT. A passphrase typed in the app MUST go into `VoxClient` at once and MUST NOT be stored by
  Swift, except in the Keychain under ADR-028 K-10.
- **M-6.** The app MUST act as one node, chosen at first run and shown in the sidebar
  (ADR-028 E-4). It MUST attach that node on launch, with the passphrase from the Keychain when
  stored there (ADR-028 K-10) or else asked for, and MUST detach it on quit (ADR-028 A-4) unless
  the node is kept attached by `--keep` or held by another client.
- **M-7.** Every user-visible failure MUST be the daemon's sentence, shown where the action was
  taken, never a generic error.

### 2. The daemon and the LAN helper

- **M-8.** The user-level daemon MUST be registered as a login item with
  `SMAppService.agent(plistName:)`, from a launch agent plist inside the bundle
  (`Contents/Library/LaunchAgents/us.vox.daemon.plist`) running the bundle's own `vox daemon`
  (ADR-028 A-5). The app MUST ask once, at first run, and say what it does: Vox keeps your rooms
  reachable while you are logged in, even with the app closed.
- **M-9.** The app MUST start and reach that daemon; it MUST NOT start a second one for the same
  data root (ADR-026 D-1). With the login item declined, the app MUST start the daemon as `vox`
  does (ADR-026 S-2).
- **M-10.** The family LAN's root part MUST be a privileged helper registered with
  `SMAppService.daemon(plistName:)` (`Contents/Library/LaunchDaemons/us.vox.lanhelper.plist`),
  approved once by the person in System Settings. It replaces `sudo vox lan helper` on macOS. It
  MUST run the bundle's `vox lan helper` and do only what that helper does today:
  - accept a connection on `/var/run/vox-lan.sock` only from the uid that registered it (checked
    with `getpeereid`);
  - check that the requested addresses are a family LAN's (`100.64.0.0/10`, `fd00::/8`);
  - create a `utun`, address it, route the room's /24 and /64 to it;
  - hand the descriptor to the user daemon (`SCM_RIGHTS`) and keep nothing.
- **M-11.** The helper MUST never open a node, a store, a keyring or a passphrase, never see room
  data and never touch the network. The interface MUST live only as long as the user daemon holds
  its descriptor.
- **M-12.** The app MUST offer the family LAN (ADR-013) only after the helper is approved, and
  MUST say what approval grants: one root process that creates network interfaces for Vox and
  nothing else.

### 3. Windows, views and keyboard

- **M-13.** The main window MUST follow ADR-028 W-1: a sidebar (the acting node, rooms grouped as
  W-2, nodes on this machine), the room's timeline, an inspector (members with trust glyphs, the
  member's keyring card, the room's services with copy commands), and a status bar (node, peers,
  keyring window). Keyring, Services and the decision record MUST be views of this window, chosen
  in the sidebar or by key.
- **M-14.** The timeline MUST show service cards, file offers with thumbnails, link cards, `read
  by` and `pulled by` lines, retention lines and late rows inline (ADR-028 R-6, R-7, F-7, F-9,
  F-10).
- **M-15.** A room with agents' nodes as members MUST offer the lanes view (ADR-028 W-3–W-6), with
  the To: selector and urgent switch in the composer.
- **M-16.** The keyring view MUST list the nodes in the keyring by alias with fingerprint art and
  grouped fingerprint, and offer add (paste, or scan with the Mac's camera), rename, compare and
  remove, each stating its effect first (ADR-028 K-1–K-6, E-5).
- **M-17.** The services view MUST list every service the node can see and its own shares, with
  the copy box (readable shown, canonical copied) and the needs lines, and offer one-step sharing
  from the services listening on this Mac (ADR-028 S-1–S-5).
- **M-18.** The decision record MUST be a timeline view, newest first, filterable by room and by
  node (ADR-028 D-3).
- **M-19.** A command palette (⌘K) MUST reach every action, as `:` does in the TUI.
- **M-20.** The keyboard map MUST be:

  | Key | Action |
  |---|---|
  | ⌘K | Command palette |
  | ⌘1 … ⌘9 | Room by sidebar position |
  | ⌘J | Next room that needs you (ADR-028 R-8, W-2) |
  | ⌘N | New room |
  | ⌘⇧J | Join a room (room link and passphrase) |
  | ⌘L | Copy this room's link |
  | ⌘O | Attach a file to this room |
  | ⌘⇧C | Copy the selected service's command |
  | ⌘I | Show this node's fingerprint |
  | ⌘⇧K | Keyring view |
  | ⌘⇧S | Services view |
  | ⌘⇧D | Decision record |
  | ⌘⇧L | Lanes view of this room |
  | ⌘R | Reply to the selected message |
  | ⌘↩ | Send urgent |

- **M-21.** The menus MUST be: File (New Room, Join Room…, Attach File…, Share Service…); Room
  (Copy Room Link, Rename…, Retention…, Admins…, Leave, End for Everyone…); Node (Attach, Detach,
  Show Fingerprint); Keyring (Add…, Compare…, Rename…, Remove…); View (Room, Lanes, Keyring,
  Services, Decision Record).
- **M-22.** A menu bar extra MUST follow ADR-028 A-3, offered at first run and off unless the person
  turns it on.
- **M-23.** Notifications MUST be local (`UserNotifications`), grouped by room, with message text
  hidden by default (ADR-028 R-10); an urgent message addressed to this node MAY be time-sensitive.
  There MUST be no APNs or other remote push.
- **M-24.** A pulled file MUST open with Quick Look from its card. A share extension ("Share to Vox
  room") and a Finder Services item MUST attach a file to a chosen room with a To: and a note
  (ADR-028 F-1). Drag and drop onto the timeline MUST do the same.
- **M-25.** The app MUST use the token file for every colour, type and motion value (ADR-028 L-1),
  with the Swift asset catalogue generated from it at build time, and MUST respect Reduce Motion,
  Reduce Transparency and Increase Contrast (ADR-028 L-5). Every control MUST have an
  accessibility label that states its state in words (ADR-028 E-6).

### 4. ADR-028 requirements the app must meet

The app MUST meet, and each story is to cite: E-1–E-6; K-1–K-10; R-1–R-10; S-1, S-1a, S-1b, S-3,
S-4 (S-2 and S-5 are the daemon's); F-1, F-3, F-4, F-6 (the hook's part is the agent's node), F-7,
F-9–F-11; RR-1, RR-3, RR-4 (RR-2 is the daemon's); D-3; L-1–L-10; W-1–W-6; A-1–A-5; I-1–I-3.

### 5. Packaging, install and update

- **M-26.** The bundle MUST be `Vox.app`, identifier `us.vox.app`, with the release's `vox` binary
  inside at `Contents/Helpers/vox` (identifier `us.vox.cli`, unchanged), the two plists of M-8 and
  M-10, and the share extension. The app's minimum MUST be macOS 13, which `SMAppService` needs;
  `vox` alone keeps the release's floor (ADR-015 17.15), and on macOS 11 and 12 `install.sh` MUST
  install `vox` alone and say why.
- **M-27.** `release.yml`'s macOS jobs MUST build the app for both architectures (or as one
  universal bundle), sign every executable in it inside-out with the Developer ID by fingerprint,
  with the hardened runtime and a secure timestamp, notarize the bundle, staple it, and publish it
  as `Vox-<version>-<triple>.zip` with a record and proof receipt like `vox`'s (ADR-015 17.2,
  17.16–17.19). A release MUST NOT publish one without the other (ADR-028 I-3).
- **M-28.** On macOS `install.sh` MUST install `Vox.app` to `/Applications` when writable, else
  `~/Applications`, after verifying its size, SHA-256, signature, team and notarization
  (ADR-028 I-2), and MUST make `~/.local/bin/vox` a symbolic link to the app's `Contents/Helpers/
  vox`, so the CLI, the daemon and the app are one binary of one version.
- **M-29.** `vox update`, and the app's own "Update Vox" offer, MUST replace the whole bundle
  atomically (download beside it, verify, rename into place, keep the previous bundle for
  `--rollback`), and MUST then ask the person to restart the app and the daemon (ADR-028 I-3).
  An install not made by `install.sh` MUST be refused, as today (ADR-015 17.10).

### 6. Proof

- **M-30.** The app's claims MUST be proved by real use of the shipped app (ADR-018): an XCUITest
  suite (`apps/macos/VoxAppProofs`) MUST launch the **signed release build** of `Vox.app` with
  `VOX_DATA_DIR` and `VOX_CONFIG_DIR` set to scratch directories, against a real daemon run from
  the same bundle, with a second node in another scratch data root as the peer, and assert what is
  on screen through accessibility. Each proof MUST name a mutant that turns it red.
- **M-31.** The suite MUST cover at least: first run to an attached node; create, room link, join
  and trust both ways with a message read each way and `read by` shown; a service shared and its
  canonical command copied and used; a file attached with a To: and pulled by the peer, `pulled
  by` shown; untrust cutting a live forward; quit detaching the node; the decision record showing a
  refused join.
- **M-32.** These proofs are optional proofs (AGENTS.md: the `optional-proofs` mechanism, loud when
  not run) because they need a macOS GUI session; they are to be run before a release is tagged.
- **M-33.** What no automated proof can reach MUST be listed as manual checks in
  `docs/release/optional-proofs.md`, run by a person before tagging, and MUST NOT be claimed as
  proven otherwise: approving the login item and the LAN helper in System Settings; a notification
  arriving under Focus; the share extension from another app; Quick Look; the menu bar extra.
- **M-34.** Screenshots for documentation and release notes MUST be rendered offscreen from demo
  data in a scratch data root made for them, never from a real data root. They show the look; they
  are not product proof.

### 7. Out of scope

The iOS app (v0.4.1) and calls (v0.5.0).

## Consequences

- The app and the TUI share one protocol client, so every request is built once, in Rust.
- `crates/vox-ffi` serves two clients: `VoxClient` here and `VoxNode` for iOS.
- macOS installs carry the CLI inside the app; `~/.local/bin/vox` is a link to it.
- Two system approvals exist on macOS: the login item and, for the family LAN only, the helper.
- The app's proofs need a GUI session and a signed build, so they run before tagging, not in CI.

## Related ADRs

ADR-001 (principle 10), ADR-013 (the family LAN), ADR-015 (release and update), ADR-017
(services), ADR-018 (proof), ADR-020 (agents), ADR-026 (the daemon and its clients), ADR-028 (the
experience this app implements).
