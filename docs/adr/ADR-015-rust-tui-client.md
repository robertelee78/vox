# ADR-015: Rust TUI Client

**Status**: proposed
**Date**: 2026-06-20
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: client, tui, rust, terminal, ratatui, verification, consent-ui

## Context

Vox is Rust-maximal (ADR-001 principle 10): one shared Rust **core** with Rust **clients** over it.
The macOS client (ADR-014) is the deliberate native-UI exception (SwiftUI over the core via UniFFI).
This ADR specifies the **first-class Rust TUI client** — a terminal-native client for chat, swarm
create/join, verification, and consent — which is the natural home client for Linux, servers,
headless boxes, and power users, and the one that runs *over SSH* (and over Vox's own tunnel,
dogfooding ADR-013). Unlike the macOS client it links the core **directly as a Rust crate (no FFI)**,
so there is no binding layer to leak secrets across. It must make Vox's novel trust model usable in a
terminal: per-sender consent (ADR-007), key verification (ADR-002), and the honest-limits discipline,
under the same protocol guarantees as ADR-014 — only the presentation differs.

## Decision

### Architecture

- **Single Rust binary linking the `vox-core` crate directly.** The core (identity ADR-002, crypto
  ADR-004/006, log/sync ADR-008, governance ADR-007, transport ADR-011, NAT ADR-012, tunneling
  ADR-013) is a library crate; the TUI is a binary crate that depends on it. **No UniFFI, no IPC** —
  the same APIs the macOS Swift layer reaches through UniFFI are plain async Rust calls here.
- **Async runtime = `tokio`** (the core's runtime); the UI render loop runs on the main thread and
  receives core state over channels (`tokio::sync::mpsc`/`watch`), so the render never blocks on the
  core and secrets never cross a process boundary.
- **TUI stack (SOTA, production-ready as of 2026):** **`ratatui`** (immediate-mode TUI framework) +
  **`crossterm`** backend (cross-platform: Linux/macOS/Windows terminals, raw mode, key/mouse
  events). Text entry via `tui-textarea`; in-terminal QR rendering via the `qrcode` crate (Unicode
  half-block / ANSI); argument parsing via `clap`. Secrets held in `zeroize`/`secrecy` types,
  `mlock`'d (ADR-010), never written to scrollback or logs.

### Navigation model (the channel is the unit, ADR-001)

- **Home = channel (swarm) list**; create/join is the primary action; each channel has a local name.
- **Channel view** = message timeline + composer; a **member pane** (toggle) shows each member's
  local nickname, verification state, and consent state. **No contacts tier, no special 1:1** — a
  two-member channel is the only "DM" (ADR-001 principle 2).
- **Keyboard-first, discoverable.** Vim-style motion plus an always-available command palette
  (`:`-prompt) and a visible keybinding hint bar; nothing essential is hidden behind unlabeled keys.
  Mouse is supported where the terminal allows but never required.

### Identity & onboarding

- Generate or import a GPG/Ed25519 identity paired with its ML-DSA co-key (ADR-002); generate the
  256-bit `self_seed` (ADR-002). Display the identity as a plain-language **safety code** (not
  "fingerprint"), and a **terminal QR** of the identity material for a phone/other device to scan.
- **Identity-key storage (no Secure Enclave here).** On generate, the root is held in `mlock`'d
  zeroized memory while unlocked and wrapped at rest in the **identity vault** (Argon2id over an
  identity passphrase), separate from any per-channel SEK (ADR-010) — no circularity. On import,
  signing is delegated to `gpg-agent`/smartcard; the key never leaves it.
- **Mandatory verified encrypted backup before first use** (OpenPGP export incl. `self_seed`,
  ADR-002); root loss is unrecoverable and the client says so.
- **Per-channel identity selection** is an explicit step at create/join, pre-selecting the
  main/last-used identity, with "create a fresh pseudonymous identity" as a one-key option (ADR-002).

### Swarm create / join

- **Create:** set policy up front — **authorship: attributable** (default; deniable is an explicit
  opt-in and is **genesis-immutable**, ADR-007), **history: full** (default), **TTL: never** (default,
  changeable). Creating mints the genesis record → `channelID = SHA-256(genesis)` (ADR-007).
- **Join:** paste/scan the **channelID** (the invite artifact, ADR-005/014); enter the **passphrase
  separately** (never one artifact). The client runs CPace + identity PoP (ADR-005). It states plainly
  that **joining grants nothing readable until members consent** (ADR-007).
- **Sharing an invite:** render the channelID as a **terminal QR + copyable string**; the passphrase
  is shared out-of-band by the user. The client never puts both in one artifact.

### Verification ceremony (terminal-adapted, evidence-aligned)

The terminal cannot operate a camera, so the scan-first default of ADR-014 inverts: **the TUI
*displays* a QR for the peer's phone to scan**, and the **grouped numeric safety code** (derived from
`SHA-256(Ed25519_pub ‖ ML-DSA_pub)` of both parties, ADR-002) is the **primary in-terminal compare**
path. Optionally a QR **image file** can be read for scan-equivalent verification. Verification is
**proactively prompted** at trust-relevant moments — new member, **before a consent decision**, on any
key change — and is one screen, not buried. Key-change / TOFU state is surfaced per member (verified /
unverified-TOFU / key-changed) over the log; no server-dependent key transparency (ADR-014 parity).

### Per-sender consent UX (the differentiator, in a terminal)

- Three **distinct, labeled** per-member states, never conflated: *verification* ("is this them?"),
  *outbound consent* ("should they see my messages?"), *inbound visibility* ("do I want to see
  theirs?") — independent toggles in the member pane (ADR-007).
- **Block** = the combined action (revoke outbound consent + opt out inbound visibility); **Block is
  NOT removal** — the member stays in the list with a "Blocked" state; **Unblock** re-consents both
  directions (ADR-007/014 parity).
- **Honest partial-visibility:** show, per member, whether you've consented to them and (where known)
  whether they've consented to you; show a newcomer the "you'll see each member's messages as they
  allow you" state rather than a confusing empty timeline.

### Messaging

- **Text and files.** Files are sent by path, carried as chunk-manifest log payloads (ADR-008/014:
  256 KiB chunks). Render-gated, undecryptable entries shown as an honest non-leaking marker.
- **Voice/video are out of scope** for the TUI (no terminal path); they remain a separate future
  capability for GUI clients (ADR-014).

### Connectivity, node operation & tunneling

- The TUI **embeds the node** when running, or **attaches to a user-run headless node** (the same
  Rust core, ADR-012/014) as rendezvous/relay/store anchor — configurable, none compulsory.
- Surfaces emergent availability honestly (per-channel reachability/sync; for a two-member channel,
  "both must be online or your node reachable").
- **Tunneling (ADR-013) is a first-class capability, present but OFF by default** (parity with
  ADR-014: nothing active until enabled). The terminal is its *natural* surface — `vox service add`,
  `vox forward`, `vox up` and per-member `bind:`/`dial:` grants are exposed when enabled. Chat
  membership still grants **zero** tunnel reach; access requires explicit capability grants (ADR-013).

### At-rest, app-lock & screen security

- Per-channel SEK + identity vault (ADR-010). **App-lock** zeroizes the SEK from memory and requires
  re-auth (passphrase + identity factor); default 5-min idle timeout. On lock the TUI **clears the
  alternate screen and disables scrollback retention** so plaintext is not left in terminal history;
  it warns that terminal multiplexers/loggers (tmux/screen, `script`) can defeat this — honest limit.

### Distribution

- **`cargo install vox-tui`**, plus prebuilt **static `musl` binaries** and per-distro packages; no
  notarization needed (CLI). Runs over SSH and over Vox's own tunnel (dogfooding ADR-013).

## Consequences

### Positive
- Pure Rust, **no FFI boundary** to secure — the smallest secret-handling attack surface of any client.
- Runs everywhere a terminal does, including **headless servers and over SSH**, making it the natural
  Linux/server client and the one that exercises tunneling end-to-end.
- Reuses the entire core and the ADR-014 trust-model UX requirements; only presentation is new.

### Negative
- **No camera ⇒ verification inverts** to display-QR-for-phone + safety-code compare; slightly higher
  friction than scan-first, mitigated by proactive prompting and the numeric code.
- Terminal UX has real accessibility limits (screen readers vary on TUIs); documented, not hidden.
- No rich media (voice/video/inline images) in the terminal.

### Neutral
- Peer to ADR-014 over one core, not a fork; future iOS/Linux-GUI clients are additional peers.

## Links
**Depends on**: ADR-002, ADR-004, ADR-005, ADR-006, ADR-007, ADR-008, ADR-009, ADR-010, ADR-011, ADR-012, ADR-013.
- Peer client to ADR-014 (shared `vox-core`).

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
