# ADR-015: Rust TUI Client

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: implemented in part, `crates/vox-tui` on integrate/v0.3.0. The `vox` binary, its live TUI over
the embedded node, the network verbs and install/update are built. Each requirement below is marked
*Built* or *Planned*, or says which part is built. **Decided 2026-10-03, not built (#397, ADR-026):**
the TUI and every verb become clients of the account's one daemon (1.2, 9.1, 9.4, 12.1, 16.4–16.6
say how); until it is built the TUI embeds the node.
**Date**: 2026-06-20
**Deciders**: Robert E. Lee
**Tags**: client, tui, rust, terminal, ratatui, verification, consent-ui, distribution

## Context

Vox is one Rust core with Rust clients over it (ADR-001 principle 10); the macOS client (ADR-014) is
the native-UI exception. This ADR specifies the terminal client: chat, room create and join,
verification and consent, for Linux, servers, headless boxes and power users, including over SSH. It
links the core directly, so there is no binding layer for secrets to leak across, and it makes the
same trust model usable as ADR-014 under the same protocol guarantees; only presentation differs.

## Requirements

### 1. Architecture

1.1. The client MUST be a single Rust binary that links `vox-core` as a library, with no UniFFI.
     *Built.*
1.2. A user-run headless node MUST be only a ciphertext-only sync peer of the TUI's embedded node
     (ADR-008 over ADR-011). It MUST NOT hold this user's secrets or plaintext, and the TUI MUST NOT
     remote-control it. The TUI MUST hold the secrets and decrypt locally. A remote-core thin client
     is out of scope and needs its own ADR. *Built.* *Decided, not built (ADR-026 S-4):* the TUI is a
     client of the account's daemon over its control socket, which holds the node's secrets in the
     same OS account; a headless node elsewhere stays a ciphertext-only peer.
1.3. The runtime MUST be multi-threaded tokio. The main task MUST own the terminal and the render
     loop, a dedicated blocking task MUST read `crossterm` events, and shutdown MUST be cooperative
     through a `CancellationToken`. Rendering MUST NOT block on the core. *Built.*
1.4. Core to UI MUST carry latest-wins state (a `ViewModel`) and ordered events that never coalesce;
     UI to core MUST carry typed commands. These MUST carry only rendered, redacted data: decrypted
     display text, yes; keys, SKDMs, passphrases, the SEK and `self_seed`, never. The channels MUST be
     bounded; view-state updates are newest-wins, and events MUST NOT be dropped. *Built (errors and
     command results are bounded types with fixed messages).*

### 2. Stack

2.1. The client MUST use `ratatui` with the `crossterm` backend, `qrcode`, `clap` with `clap_complete`
     and `clap_mangen`, and `zeroize`/`secrecy` with explicit memory locking. *Built.* (`tui-textarea`
     was dropped; a single-line composer replaces it, and a multi-line or vim composer would be its
     own decision.)

### 3. Navigation and input

3.1. Home MUST be the room list; create and join MUST be the primary action, and each room MAY have a
     local name. The room view MUST show the timeline, the composer and a toggleable member pane
     (nickname, verification, consent). There MUST be no contacts tier and no separate 1:1 path
     (ADR-001). *Built.*
3.2. `Tab` MUST cycle timeline → composer → member pane, with the focused pane visibly marked. The
     composer MUST be modeless insert with Enter to send. *Built.*
3.3. An optional vim mode MAY be offered through configuration. *Planned.*
3.4. A `:` command palette MUST be a modal overlay that `Esc` dismisses, and a keybind hint bar MUST
     always be shown. *Built.*
3.5. Every action MUST be reachable by a typed `:` command. *Built, except creating and joining a
     room, which need a passphrase and go through a masked prompt instead of the palette line.*

### 4. Verification

4.1. The TUI MUST display a QR that the peer scans with their phone as the recommended ceremony. A
     grouped numeric safety-code comparison MUST be the in-terminal fallback, and reading a QR image
     file MAY give scan-equivalent verification. *Planned.*
4.2. The safety code MUST be the grouped decimal of `SHA-256("vox/safety/v1" ‖ pk_lo ‖ pk_hi)`, where
     `pk_lo` and `pk_hi` are the two parties' composite identity public keys (ADR-002) in ascending
     byte order. The verification QR payload MUST be a canonical-CBOR record of the displaying party's
     composite public key (ADR-008 encoding). *The derivation (8 groups of 5 digits) and the QR
     payload (`[label, composite_pubkey]`, strictly decoded) are built in `verify`; showing them in
     the TUI is planned.*
4.3. Verification state MUST move `unverified-TOFU → verified` on a successful scan or comparison,
     and any key change MUST reset it to `key-changed`. The state MUST be persisted per member in the
     room's store. *Planned (`:verify` answers "not available yet").*
4.4. The TUI MUST prompt for verification at a new member, before a consent decision and on a key
     change, on one screen. *Planned.*

### 5. Identity and onboarding

5.1. The TUI MUST create an Ed25519 identity with its ML-DSA co-key and a 256-bit `self_seed`
     (ADR-002). *Built, through a masked prompt that echoes one `•` per character into zeroizing
     buffers.*
5.2. Generate path: the root MUST be held in locked, zeroized memory while unlocked and, at rest, in
     the identity vault (Argon2id over the identity passphrase), separate from every room SEK
     (ADR-010). *Built.*
5.3. Import path: the user MAY bind a GPG Ed25519 key or a smartcard; signing MUST be delegated to
     `gpg-agent` or the card, over the agent's socket, and the key MUST NOT leave it. *Planned in the
     client; the core binding exists.*
5.4. The TUI MUST require a verified, encrypted backup before first use (OpenPGP export including
     `self_seed`, ADR-002). For a hardware-bound key it MUST back up `self_seed` and Vox-managed
     material and MUST say it cannot export the hardware-held key. *Planned.*
5.5. Identity selection MUST be explicit at create and join, pre-selecting the main or last-used
     identity, with a fresh pseudonymous identity (ADR-002) one key away. *Planned.*
5.6. The identity MUST be shown as a plain-language safety code and a terminal QR. *Planned.*

### 6. Room create and join

6.1. Create MUST set policy up front (ADR-007): authorship attributable, history full, TTL never,
     each changeable as ADR-007 allows. Creating mints the genesis; `channelID = SHA-256(genesis)`.
     *Built.* Deniable authorship is not offered: deniable mode is removed (PRD-001 R43).
6.2. Two invite modes MUST be supported (ADR-007): an identity-bound invite (the default), which
     names the newcomer's expected identity, after which the TUI shows "expecting `<safety code>`"
     and flags a joiner who doesn't match; and an open passphrase join, whose joiner is shown
     unverified until a member verifies them. *The core supports both (`governance::invite`); the TUI
     shows neither expectation yet: planned.*
6.3. The passphrase MUST always be shared out of band and MUST NOT be in the invite. *Built.*
6.4. The invite QR MUST encode the channel ID (and the expected identity for an identity-bound
     invite) at ECC level M with a quiet zone, Unicode half-block by default with an ASCII fallback,
     check the terminal size (else show only the copyable string), and always show the copyable
     string beside it. *The renderer is built (`qr`); showing it in the TUI is planned.*
6.5. The client MUST say that joining grants nothing readable until members consent (ADR-007).
     *Built.*

### 7. Per-sender consent

7.1. Verification, outbound consent and inbound visibility MUST be three separate, labelled
     per-member states with independent controls in the member pane (ADR-007). *Outbound consent is
     built (`:consent grant`, `:consent revoke`).*
7.2. Inbound visibility (`:show`, `:hide`) MUST be local. *Planned (answers "not available yet").*
7.3. **Block** MUST revoke outbound consent and turn off inbound visibility at once. A blocked member
     MUST stay in the list marked "Blocked"; Block MUST NOT remove anyone. **Unblock** MUST restore the
     user's own outbound consent and inbound visibility, and MUST NOT claim to restore the peer's
     consent. *Planned (answers "not available yet").*
7.4. Revoking outbound consent MUST behave as ADR-014 requirement 5.5 states (ADR-007). *Built.*
7.5. Per member, the TUI MUST show whether the user consented to them and, where known, whether they
     consented to the user; a newcomer MUST be told they will see each member's messages as that
     member allows. *Planned.*

### 8. Messaging

8.1. The TUI MUST send and render text. Entries the user cannot decrypt MUST render as a non-leaking
     marker. *Built.*
8.2. Files MUST be sendable. *Built as `vox room send` / `vox room get` (ADR-020 §11).*
8.3. Voice and video are out of scope for this client.

### 9. Node operation and notifications

9.1. The TUI MUST embed the node while running, or sync with a user-run node as a ciphertext-only
     peer (1.2). The TUI MUST NOT make either compulsory. It MUST show per-room reachability and sync
     state. *Built.* *Decided, not built (ADR-026):* the TUI shows the daemon's attached nodes, live
     through attach, detach, lock and unlock events, and acts as the node the person picks (ADR-026
     C-3); it MUST NOT embed a node.
9.2. New decryptable entries MUST show in the app (unread markers on the room list, a status line).
     *Built.*
9.3. On a desktop session the TUI MUST also raise an OS notification, and over SSH it MUST fall back to
     OSC 9 or the terminal bell. The TUI MUST NOT spawn a background agent; it notifies only while it
     runs. *Planned.*
9.4. `vox daemon` MUST pass every node event through the one failure reporter the CLI uses
     (`tunnel_cli::say_if_it_explains_a_failure`), so it reports an unreachable peer, a refused
     publish or a stall as `vox node` does. *Built: the daemon reported no failures at all until
     `f3f8a94e` fixed it.* Under ADR-026 the reporter runs per node in the daemon.

### 10. Tunneling

10.1. Tunneling MUST be present in the client and MUST be off by default: present, not hidden, and
      nothing reachable until the user turns it on. *Built (`vox serve`, `vox up`, `vox forward`).*
10.2. Room membership MUST NOT grant tunnel reach (ADR-017 decision 3). *Built.*
10.3. The TUI's tunneling surface MUST follow ADR-017. Per-member `bind:`/`dial:` grants and a
      privileged TUN `vox up` are withdrawn by policy (ADR-017's third revision). `vox up` is an
      unprivileged SOCKS5 proxy (ADR-017 decision 5): *built*. Removing the withdrawn capability
      model's remaining code (`governance::capability`'s `bind:`/`dial:` prefixes and its evaluator)
      is *planned* (PRD-001 R44, #94).

### 11. At rest, lock and screen

11.1. Plaintext MUST be drawn only on the alternate screen, never the primary buffer, so it never
      enters scrollback. The TUI MUST enter the alternate screen before any draw and MUST leave it,
      cleared, with a best-effort `ESC[3J`, on every exit path. *Built.* Known limit: non-cooperating
      emulators, `tmux`/`screen`, or `script` may retain copies (not claimed-fixed).
11.2. Lock MUST zeroize the room SEKs, the in-memory identity root (generate path) and the decrypted
      view models, and MUST require the identity vault and each room's passphrase again. For a
      `gpg-agent` key, Vox MUST clear only its own derived material. *Built for the generate path.*
11.3. The TUI MUST lock after 5 minutes idle (the default) and on `SIGHUP` or a dropped connection. The
      lock MUST be configurable, including off, with a direct warning. *The 5-minute idle lock, `:lock`
      and `SIGHUP` are built; configuring them is planned.*
11.4. The node MUST track every task it hands a signer handle to and abort them all when it locks,
      before it drops the prekey ring, so no task outlives the lock holding the identity. *Built
      (`Profile::signer_arc`).*
11.5. Inside a detected terminal multiplexer the TUI MUST show a one-time warning that capture there
      is outside Vox's control. *Planned.*
11.6. Secrets MUST be `zeroize`/`secrecy` types and MUST be memory-locked. Where locking is
      unavailable (`RLIMIT_MEMLOCK=0`), the client MUST show a prominent warning and continue with
      zeroize only. It MUST NOT pretend. *Built ("mlock unavailable (zeroize-only)").*

### 12. Configuration, state and logging

12.1. Paths MUST be XDG-conformant: data under `$XDG_DATA_HOME/vox/` (macOS: `~/Library/Application
      Support/vox`), with per-identity profiles in separate directories. Precedence MUST be CLI flags,
      then environment (`VOX_PROFILE`, `VOX_DATA_DIR`, `VOX_CONFIG_DIR`), then config, then defaults.
      *Built, except the config file (12.4).* *Decided, not built (ADR-026 C-3, F-1):* `--profile`
      and `VOX_PROFILE` are replaced by `--node` and `VOX_NODE`, with no alias; nodes live in
      `<data root>/nodes/<name>/`.
12.2. Store files MUST be mode `0600` and directories `0700`. *Built.*
12.3. Logs and panic reports MUST NOT contain plaintext, keys, passphrases or seeds. *Built for the UI
      types.*
12.4. Keybindings MUST be overridable in a config file (`config.toml`). *Planned.*

### 13. Errors and offline

13.1. A status bar and a dismissible alert log MUST show errors (*the status line is built; the alert
      log is planned*). ADR-008 wire codes `0x01`–`0x08`
      MUST map to human strings; `0x06` is reserved and reads as malformed, like any unknown code. Join
      failures (wrong passphrase, proof-of-work delay, PoP mismatch), an unreachable peer, epoch
      mismatch, key change and missing consent MUST each render as a visible state with a recovery
      action, never fail silently. *The mapped codes and states are built.*

### 14. Accessibility

14.1. State MUST never be signalled by colour alone: verification, consent and Block render as colour,
      glyph and label. *Built.*
14.2. The client MUST honour `NO_COLOR` and offer a no-colour, high-contrast mode, an `--accessible`
      ASCII QR, a linear screen-reader-friendly view, and no dependence on the mouse. *Glyph labels
      and keyboard-only operation are built; reading `NO_COLOR`, the `--accessible` flag and the linear
      view are planned.*

### 15. Distribution

15.1. The command is `vox`; the TUI runs as `vox` with no arguments or `vox tui`; the crate is
      `vox-tui`. *Built.*
15.2. Shell completions (`vox completions <shell>`) and a man page (`vox man`) MUST be generated from
      the same clap model. *Built.*
15.3. The import path MUST talk to the system `gpg-agent` over its socket and MUST NOT link gpgme.
      *Planned with 5.3.*
15.4. Targets MUST be macOS and Linux only. Windows is not a target and would need its own ADR.
      *Built.*

### 16. Passphrases on the command line

16.1. `--identity-passphrase` MUST be refused with a message naming the replacements, and MUST still
      be parsed so a script using it fails with that message. *Built.*
16.2. The identity passphrase MUST be taken from `--identity-passphrase-file`, then
      `VOX_IDENTITY_PASSPHRASE` (read directly, not through clap's `env`), then an unechoed prompt.
      *Built.*
16.3. A tty-less, empty stdin MUST be refused rather than tried as an empty passphrase. *Built.*
16.4. Every passphrase source (file, environment variable, prompt) MUST be resolved in the client;
      the daemon MUST NOT read a passphrase from its own environment (ADR-026 C-6). *Decided, not
      built.*
16.5. A passphrase sent to the daemon (attach, unlock) MUST travel in a zeroizing buffer end to end
      (ADR-026 C-6). *Decided, not built.*
16.6. A client that finds no daemon MUST start one (ADR-026 S-2) before sending its request.
      *Decided, not built.*

### 17. Install and update

17.1. `vox` MUST be installable and updatable from GitHub Releases only: no vanity domain, third-party
      host, account or package manager. *Built.*
17.2. Every release MUST publish, per target triple, `stable-<triple>.json` beside `vox-<triple>` and
      its `.sha256`:
      ```json
      {"kind":"vox.standalone-release","schema_version":1,"package":"vox","channel":"stable",
       "target":"aarch64-apple-darwin","version":"0.1.0","size":12345678,"sha256":"…"}
      ```
      This record MUST be the only "what is current" lookup, fetched through
      `releases/latest/download/<name>`. Its `kind`, `schema_version`, `package`, `channel` and
      `target` MUST be checked against the request before any other field is used.
17.3. `vox update` MUST decide status, redirects, length and digest in Rust (`reqwest`): redirects
      bounded to GitHub's origins, any `Content-Encoding` rejected, `Content-Length` equal to the
      record's size, and the body streamed through SHA-256 with the size bound enforced during the
      transfer. The record MUST parse as strict schema-1 JSON with unknown fields rejected, and
      versions MUST compare as SemVer.
17.4. `install.sh` MUST be POSIX sh and MUST use `curl -f`.
17.5. The binary MUST be pinned to the tag the record named and MUST NOT be re-fetched through
      `latest`.
17.6. Redirects MUST be confined to `github.com`, `release-assets.githubusercontent.com` and
      `objects.githubusercontent.com`, checked on the effective URL after the transfer. A redirect
      elsewhere MUST abort.
17.7. Size and SHA-256 MUST both be verified before anything is renamed into place, and the transfer
      MUST be bounded by the record's `size`.
17.8. A candidate binary MUST be closed before anything executes it. (`vox update` never worked on
      Linux until `4ea10789` fixed this: `execve` returned `ETXTBSY` on the still-open candidate.)
17.9. Publishing MUST be atomic: write the candidate beside the destination on the same filesystem,
      keep the active binary as `.previous`, then rename. `--rollback` MUST restore the previous one.
17.10. Only an install this installer made MAY be updated in place, identified by
       `.vox-standalone.json` beside the binary:
       `{"kind":"vox.install-channel","schema_version":1,"package":"vox","channel":"<channel>"}`,
       parsed with unknown fields rejected. A build from source MUST be refused with guidance. The
       marker's `channel` MUST select `<channel>-<triple>.json`, whose own `channel` MUST equal it. A
       marker that is present but not canonical MUST be reported as a broken install.
17.11. Every release MUST also publish `proof-<triple>.json` (the real version and size, and a
       deliberately wrong `sha256`) so the updater's mismatch refusal is proved end to end (ADR-018).
       That channel MUST NOT be selected by default.
17.12. On macOS, `vox update` MUST authenticate the candidate through Apple before publishing it, and
       the candidate MUST carry the same Developer ID as the installed binary. It MUST run `codesign
       --verify --strict --all-architectures` on both; parse `codesign --display --verbose=4` for each
       and require the full `Developer ID Application → Developer ID Certification Authority → Apple
       Root CA` chain, a hardened runtime, a secure timestamp and the canonical team and identifier;
       require the two identities to be equal; confirm the candidate's notarization online
       (`--check-notarization --test-requirement '=notarized'`); and require its `--version` output to
       be exactly what the record's version implies.
17.13. `install.sh` MUST pin the expected team and identifier (`us.vox.cli`) itself and make the same
       signature and notarization checks. That pin and the workflow's `APPLE_CODESIGN_IDENTIFIER` and
       `APPLE_TEAM_ID` MUST agree. The clients MUST NOT read their trust expectations from the release
       record.
17.14. On Linux there is no signature check: an update rests on TLS to GitHub and the record's digest.
       This MUST be stated as a known gap, not papered over. A detached release signature verified
       against a key compiled into the binary is what would close that, and is deliberately not in
       this change: it needs a release key with its own custody story. Recorded as a known gap.
17.15. Targets MUST be `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` and `x86_64-apple-darwin`.
       The macOS floor MUST be 11.0, pinned with `MACOSX_DEPLOYMENT_TARGET` and asserted by the signer.
17.16. macOS artifacts MUST be signed with a Developer ID Application certificate and notarized.
       Signing MUST happen after `strip` and before packaging, so the record's `sha256` covers the
       signed bytes. There MUST be no unsigned fallback.
17.17. The signer is `scripts/sign_notarize_release.sh`. It MUST decode credentials into a `0700`
       directory deleted on exit; import them into an ephemeral keychain holding exactly one identity,
       the expected `Developer ID Application: … (<team>)`; sign by that identity's fingerprint, never
       by name, with `--options runtime --timestamp`; and verify from `codesign --display
       --verbose=4` the identifier, Team ID, authority, hardened runtime, secure timestamp and exactly
       one canonical `CDHash`.
17.18. Notarization MUST use an App Store Connect API key (`--key`, `--key-id`, `--issuer`). The
       submission MUST be waited on to `Accepted`; the notary log MUST be fetched and MUST bind the
       same `CDHash` under SHA-256 with no issues; the online ticket MUST then be verified with
       `codesign --check-notarization --test-requirement '=notarized'`. `spctl --assess --type
       execute` MUST NOT be used.
17.19. Each signed target MUST emit and publish `apple-proof-<triple>.json`, a
       `vox.apple-release-proof` receipt naming the unsigned and signed digests, the minimum macOS,
       the signing authority, Team ID, identifier and `CDHash`, the notary submission id and status,
       and the SHA-256 of every log. The publish job MUST refuse to release unless every receipt
       attests `Accepted` for the version being tagged and each `stable-<triple>.json` digest equals
       its receipt's `asset.sha256`.
17.20. Credentials MUST live in a GitHub environment named `apple-release`: variables
       `APPLE_DEVELOPER_ID_APPLICATION`, `APPLE_TEAM_ID`, `APPLE_CODESIGN_IDENTIFIER`,
       `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`; secrets
       `APPLE_DEVELOPER_ID_APPLICATION_P12_BASE64`, `APPLE_DEVELOPER_ID_APPLICATION_P12_PASSWORD`,
       `APPLE_NOTARY_KEY_P8_BASE64`. The macOS jobs MUST draw them only from that environment, so a
       fork or pull request cannot produce a release artifact.

### 18. Proof

18.1. The client's claims MUST be proved as ADR-018 requires: only real use of the shipped binary
      counts. There MUST be no unit-test, render-snapshot or input-injection gate.
18.2. Known limit: the runtime's shutdown/backpressure and the terminal-compatibility matrix are
      exercised manually, not by tests.

## Consequences

- Pure Rust with no FFI is the smallest secret-handling surface of any client.
- The client runs wherever a terminal does, including headless servers and SSH sessions.
- With no camera, the strong scan path lives on the peer's phone; numeric comparison is the weaker
  in-terminal fallback, mitigated by keeping scan primary and prompting.
- Memory locking can be unavailable on the container targets this client favours; that is warned
  about, not hidden.
- Terminal a11y has real limits (screen-reader/TUI variance); addressed by the executable a11y mode
  and stated honestly. No rich media in the terminal.
- A Linux update has no signature check (17.14).

## Related ADRs

ADR-001, ADR-002, ADR-004, ADR-005, ADR-006, ADR-007, ADR-008, ADR-009, ADR-010, ADR-011, ADR-012,
ADR-013, ADR-014 (peer client), ADR-016 (the embedded node), ADR-017 (room-bound services), ADR-018
(proof), ADR-020 (`vox room send`, `vox daemon`).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
