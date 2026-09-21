# ADR-015: Rust TUI Client

**Status**: implemented (M12 + M13.5, `crates/vox-tui/`) — live client over the embedded node; the network verbs landed with ADR-016 M14–M15 and the room-bound-service CLI with ADR-017 M17
**Date**: 2026-06-20
**Updated**: 2026-09-21 — `vox update`, `install.sh`, `scripts/package-release.sh`, `scripts/sign-macos.sh` and `.github/workflows/release.yml` implement §Distribution's install/update model, and the marker now **names the channel** (with a `proof` channel that exists so the digest-mismatch refusal can be proved); the absence of an independent release signature is recorded as a known gap. 2026-09-21 — the **install and update model** is specified (GitHub Releases only, a per-target release record fetched through `latest/download`, fail-closed transport, origin-confined redirects, atomic publish with rollback, `vox shell-setup`, signed+notarized macOS artifacts); see §Distribution. 2026-09-20 — the network verbs are wired (join from a link, invite, consent) and the binary listens (`--listen`); ADR-016 M14.7g. 2026-09-19 — status reconciled; test count corrected; Known gaps recorded. 2026-09-19 (M13.5): live `CoreHandle`, tokio runtime, masked onboarding prompts, composer, idle/SIGHUP lock, primary-buffer + lock gates met; `tui-textarea` dropped.
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: client, tui, rust, terminal, ratatui, verification, consent-ui

## Context

Vox is Rust-maximal (ADR-001 principle 10): one shared Rust **core** with Rust **clients** over it.
The macOS client (ADR-014) is the deliberate native-UI exception (SwiftUI over the core via UniFFI).
This ADR specifies the **first-class Rust TUI client** — a terminal-native client for chat, swarm
create/join, verification, and consent — the natural home client for Linux, servers, headless boxes,
and power users, and the one that runs *over SSH* (and over Vox's own tunnel, dogfooding ADR-013).
It links the core **directly as a Rust crate (no FFI)**, so there is no binding layer to leak secrets
across. It must make Vox's trust model usable in a terminal: per-sender consent (ADR-007), key
verification (ADR-002), the honest-limits discipline — under the same protocol guarantees as ADR-014,
held to the same "execute without re-deciding" bar; only presentation differs.

## Decision

### Architecture

- **Single Rust binary linking the `vox-core` crate directly — no UniFFI, no IPC control plane.** The
  core (identity ADR-002, crypto ADR-004/006, log/sync ADR-008, governance ADR-007, transport ADR-011,
  NAT ADR-012, tunneling ADR-013) is a library crate; the TUI is a binary crate depending on it.
- **The headless node is a *sync peer*, not a control plane (resolves the no-IPC claim).** "Attach to a
  user-run headless node" (ADR-012/014) means the TUI's **embedded** node syncs with that node **as just
  another ciphertext-only relay/store peer** over the ADR-008 sync protocol on ADR-011 transport — the
  node never holds this user's secrets or plaintext and is never remote-controlled. The TUI **always**
  holds the secrets and does all decryption locally; so "secrets never cross a process boundary" holds.
  A true remote-core / thin-client (secrets on a remote node) is **explicitly out of scope** here and
  would be its own capability ADR.
- **Async runtime = multi-threaded `tokio`** (the core's runtime). The **main task owns the terminal and
  the render loop**; a **dedicated blocking task** polls `crossterm` events and forwards them; shutdown
  is cooperative via a `CancellationToken`. The render never blocks on the core.
- **Typed core↔UI boundary (no secrets in UI channels — binding contract).** core→UI uses
  **`watch<ViewModel>` for latest-wins *state*** (sync status, per-member verification/consent/visibility
  state, reachability) and **`mpsc<Event>` for ordered *events* that must never coalesce** (new log
  entries, key-change alerts, errors). UI→core uses `mpsc<Command>`. These channels carry **only
  rendered/redacted view models** — decrypted text destined for display, yes; **never** raw keys, SKDMs,
  passphrases, the SEK, or `self_seed`, which stay inside core types (`zeroize`/`secrecy`, mlock'd). Bounded
  channels; view-state updates use newest-wins, events are never dropped.

### TUI stack (SOTA, production-ready 2026)

`ratatui` (immediate-mode TUI) + `crossterm` backend (Linux/macOS terminals, raw mode, key/mouse
events) + `tui-textarea` (composer) + `qrcode` (matrix generation) + `clap`/`clap_complete`/`clap_mangen`
(args, completions, man pages) + `zeroize`/`secrecy` (+ explicit `libc::mlock`/`region`, below).

### Navigation & input state machine

- **Home = channel (swarm) list**; create/join is the primary action; each channel has a local name.
  **Channel view** = message timeline + composer + toggleable **member pane** (nickname, verification,
  consent state). **No contacts tier, no special 1:1** — a two-member channel is the only "DM" (ADR-001).
- **Focus model:** `Tab` cycles timeline → composer → member pane; the focused pane is visibly marked.
- **Input modality:** the composer is **modeless insert** by default (`tui-textarea`), with an optional
  vim mode (config). A **`:` command palette** is a modal overlay (`Esc` dismisses). A **visible keybind
  hint bar** is always shown. **Every action is reachable by a typed `:`-command**, not only by chord
  (discoverability + accessibility).

### Identity & onboarding

- Generate or import a GPG/Ed25519 identity + ML-DSA co-key (ADR-002); generate the 256-bit `self_seed`
  (ADR-002). Show the identity as a plain-language **safety code** and a **terminal QR** of the identity.
- **Storage (no Secure Enclave here).** Generate path: root in `mlock`'d zeroized memory while unlocked,
  at rest in the **identity vault** (Argon2id over an identity passphrase), separate from any per-channel
  SEK (ADR-010) — no circularity. Import path: signing delegated to `gpg-agent`/smartcard; the key never
  leaves it.
- **Mandatory verified encrypted backup before first use** (OpenPGP export incl. `self_seed`, ADR-002),
  with ADR-014's **honest caveat**: a hardware-bound/non-exportable import key **cannot** be exported —
  Vox backs up `self_seed` + its Vox-managed companion material and says plainly it cannot export the
  hardware-held private key (that is the card/agent's responsibility).
- **Per-channel identity selection** is explicit at create/join, pre-selecting the main/last-used
  identity; "create a fresh pseudonymous identity" (ADR-002) is a one-key option.

### Swarm create / join (incl. ADR-007 invite modes)

- **Create:** set policy up front — **authorship attributable** (default; deniable is opt-in and
  **genesis-immutable**, ADR-007), **history full** (default), **TTL never** (default, mutable). Creating
  mints the genesis record → `channelID = SHA-256(genesis)` (ADR-007).
- **Invite modes (ADR-007), both supported:** **identity-bound invite (default, high-trust)** — the
  invite artifact names the newcomer's expected identity fingerprint; the TUI shows "expecting `<safety
  code>`" and flags any joiner who doesn't match. **Open passphrase join** — anyone with `channelID +
  passphrase`; such a joiner is shown **unverified** until a member verifies them. The **passphrase is
  always shared out-of-band, never in the invite artifact**.
- **Terminal QR rendering contract:** the QR encodes the **channelID** (plus the expected fingerprint
  for an identity-bound invite); ECC level **M**, mandatory **quiet zone**, **Unicode half-block** render
  by default with an **ASCII fallback** (`--accessible`/no-Unicode terminals), a **minimum-terminal-size
  check** (else show the copyable string), and a copyable string alongside. The client states plainly:
  **joining grants nothing readable until members consent** (ADR-007).

### Verification ceremony (terminal-adapted, ADR-014 evidence ordering preserved)

A terminal has no camera, so the strong scan path is **relocated to the peer's device, not weakened**:

- **Recommended ceremony: the TUI *displays* a QR; the peer scans it with their phone** — one-scan
  verification with the strong properties ADR-014 requires. The grouped **numeric safety-code compare**
  is the **in-terminal fallback** when no phone is present (ADR-014's evidence-weakest path, used only as
  fallback — the strong path stays primary, just on the peer's camera). An optional **QR-image-file** read
  gives scan-equivalent verification.
- **Pinned derivation (so two clients agree):** safety code = grouped decimal of
  `SHA-256("vox/safety/v1" ‖ pk_lo ‖ pk_hi)` where `pk_lo,pk_hi` are the two parties' composite identity
  pubkeys (ADR-002) in **ascending byte order**. The verification QR payload is a canonical-CBOR record
  of the displaying party's composite pubkey (ADR-008 encoding).
- **Acceptance state machine:** `unverified-TOFU → verified` on a successful scan/compare; any key change
  resets to **`key-changed` (must re-verify)**. State is **persisted per member** in the per-channel
  store. Verification is **proactively prompted** at new-member, **before a consent decision**, and on key
  change — one screen, never buried.

### Per-sender consent UX (the differentiator, in a terminal)

- Three **distinct, labeled** per-member states, never conflated: *verification*, *outbound consent*,
  *inbound visibility* — independent toggles in the member pane (ADR-007).
- **Block** = combined (revoke outbound consent + opt out inbound visibility); **Block is NOT removal**
  (member stays in the list with a "Blocked" state). **Unblock restores *your* outbound consent and
  *your* local inbound-visibility preference** — it **cannot force the peer to consent to you** (ADR-007).
- **Honest partial-visibility:** per member, show whether you've consented to them and (where known)
  whether they've consented to you; show a newcomer "you'll see each member's messages as they allow you"
  rather than a confusing empty timeline.

### Messaging

- **Text and files.** Files are sent by path, carried as **chunk-manifest** payloads — manifest schema
  `{ file_id, total_len, content_type, chunk_hashes[] }` is ADR-014's, its 256-KiB chunking and canonical
  encoding (tag `0x000A`) are ADR-008's. Render-gated; undecryptable entries shown as an honest
  non-leaking marker. **Voice/video are out of scope** (no terminal path).

### Connectivity, node operation, notifications & tunneling

- The TUI **embeds the node** when running, or syncs with a **user-run headless node as a ciphertext-only
  peer/anchor** (above; ADR-012/014) — configurable, none compulsory. Surfaces emergent availability
  honestly (per-channel reachability/sync; for a two-member channel, "both must be online or your node
  reachable").
- **Notifications (while running; no extra daemon).** New-decryptable-entry events surface **in-app**
  (unread markers in the channel list, a status line) and, on a desktop session, as OS notifications via
  `notify-rust`; over SSH the fallback is **OSC 9 / terminal bell**. The TUI does **not** spawn a
  background agent (that is the headless-node binary's role, ADR-012/014) — it notifies only while running.
- **Tunneling (ADR-013): first-class, present but OFF (inactive, not hidden) by default.** The terminal
  is its natural surface: the **full** ADR-013 surface ships — `vox service add`, `vox forward` / SOCKS,
  and per-member `bind:`/`dial:` grants require **no privilege** and are the default tunneling path;
  **`vox up` (TUN) is gated behind an explicit privilege step** (run as root / `CAP_NET_ADMIN` via
  `setcap`) and refuses with a clear message if unprivileged. Chat membership still grants **zero** tunnel
  reach; access requires explicit capability grants (ADR-013).

### At-rest, app-lock & screen security

- Per-channel SEK + identity vault (ADR-010). **Plaintext is rendered ONLY to the alternate screen,
  never to the primary buffer** — so it never enters terminal scrollback. (The earlier "disable
  scrollback" framing was wrong: scrollback is the emulator's buffer, not ours.)
- **App-lock** zeroizes the SEK(s) **and** the in-memory identity root (generate path) and decrypted view
  models, then requires re-auth (identity-vault unlock + per-channel SEK re-derive). For `gpg-agent`
  imports, Vox clears only its **own** derived material — the key's custody and TTL are the agent's
  (honest limit). On lock the TUI **leaves the alternate screen with its buffer cleared** and issues a
  **best-effort `ESC[3J`**; it **documents the honest limit** that non-cooperating emulators, `tmux`/
  `screen`, or `script` may retain copies (not claimed-fixed). **Default 5-min idle-lock**; it **also
  locks on terminal detach / `SIGHUP` / connection drop** (the SSH analogue of "lock on sleep"). Lock is
  **user-configurable incl. disable** (with a direct warning, ADR-014 parity). On first run inside a
  detected multiplexer it shows a **one-time honest warning** about capture being outside Vox's control.
- **Memory protection (no false claim).** Secrets use `zeroize`/`secrecy` types **and are `mlock`'d**
  (explicit `libc::mlock`/`region`). Where `mlock` is **unavailable** (e.g. `RLIMIT_MEMLOCK=0` in an
  unprivileged container — exactly the headless target), the client does **not** silently pretend: it
  surfaces a prominent warning and continues with **zeroize-only**, a defined, documented degradation
  (per the no-fallback mantra this behavior is specified, not stubbed).

### Configuration, state & logging

- **XDG-conformant layout:** config `$XDG_CONFIG_HOME/vox/config.toml` (macOS `~/Library/Application
  Support/vox`), data `$XDG_DATA_HOME/vox/` (identity vault, per-channel SEK stores, log DB). **Store
  files `0600`, dirs `0700`.** Precedence: CLI flags > env > config file > defaults. Per-identity
  **profile separation** (distinct data dirs). Keybindings overridable in config.
- **Log redaction is mandatory:** logs and panic reports never contain plaintext, keys, passphrases, or
  seeds; secret types render as redacted.

### Error & offline UX

- A persistent **status bar** plus a **dismissible alert log**. The **ADR-008 wire error codes
  `0x01`–`0x08`** map to human strings; join failures (wrong passphrase, Equihash PoW delay, PoP
  mismatch), unreachable-peer / "both must be online", epoch mismatch, quota, key-change, and
  missing-consent ("you'll see them once they consent") each render as a visible state with a recovery
  action — never a silent failure.

### Accessibility (an executable mode, not a disclaimer)

- **Never color-only signalling:** verification / consent / Block state is always color **+ glyph +
  label**. Honor **`NO_COLOR`** and a high-contrast/no-color mode. **ASCII (non-Unicode) QR fallback.**
  Every action reachable by typed `:`-command (no chord-only paths). **No mouse dependence** (mouse
  optional). A linear, screen-reader-friendly view mode.

### Testing strategy (release gate)

- `ratatui` **`TestBackend` render-snapshot** tests; headless **input-injection** state-machine tests;
  an explicit assertion that **plaintext never reaches the primary buffer** (directly validates the
  at-rest screen claim); **QR encode/decode round-trip**; consent/verification **golden flows**;
  **lock/zeroize** tests; **tokio shutdown/backpressure** tests; a **terminal-compatibility matrix**;
  core integration tests (trivial via direct linking); **parity tests** against ADR-014 client
  expectations (same core state → equivalent surfaced state).

### Distribution

- Command suite is **`vox`**; the interactive TUI is `vox` (no args) or `vox tui`; crate/package name
  `vox-tui`. Static **`musl`** binary for the generate path; the import path **shells to the system
  `gpg-agent`** over its socket (not gpgme-linked) so the static build stays clean. **Signed,
  reproducible** release artifacts (supply-chain integrity the threat model expects). Shell completions
  (`clap_complete`) + man pages (`clap_mangen`). Runs over SSH and over Vox's own tunnel (dogfoods
  ADR-013). **Targets macOS and Linux only** — every at-rest/identity mechanism here is POSIX (`mlock`,
  `gpg-agent`, XDG). Windows is **not a target**; supporting it would need its own ADR (DPAPI/`VirtualLock`/
  `%APPDATA%` mappings) only if it is ever wanted — it is not planned.

### Install and update (added 2026-09-21)

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD** and **MAY** in this section are to be
interpreted as described in BCP 14 (RFC 2119 and RFC 8174).

`vox` MUST be installable and updatable from **GitHub Releases only** — no vanity domain, no
third-party host, no account, no package manager.

**The release record.** Every release MUST publish, per target triple, a small JSON record
`stable-<triple>.json` beside the binary `vox-<triple>` and its `.sha256`:

```json
{"kind":"vox.standalone-release","schema_version":1,"package":"vox","channel":"stable",
 "target":"aarch64-apple-darwin","version":"0.1.0","size":12345678,"sha256":"…"}
```

That record is the **only** "what is current" lookup. It is fetched through GitHub's
`releases/latest/download/<name>` redirect, which needs no API, no auth and no token
(spike-verified 2026-09-21: `302` to the newest tag, `302` to `release-assets.githubusercontent.com`,
`200`). Its `kind`, `schema_version`, `package`, `channel` and `target` MUST all be checked against what was
asked for before any other field of it is used.

**Fetching MUST fail closed.** `--fail` is REQUIRED on every request, and the HTTP status MUST be
checked independently of the transport's exit status. Spike-verified 2026-09-21, and the reason this is
normative rather than stylistic: *without* `--fail`, a `404` returns **exit 0** and writes the response
body — `Not Found` — into the output file, which would then be parsed as the release record. Worse,
curl's exit `56` is overloaded: it means both "404 under `--fail`" and "body exceeded
`--max-filesize`", so the status MUST be read from `%{http_code}` and never inferred from the exit
code.

**The binary MUST be pinned to the tag the record named**, and MUST NOT be re-fetched through `latest`,
which can move between the two requests.

**Redirects MUST be confined to GitHub origins** — `github.com`,
`release-assets.githubusercontent.com`, `objects.githubusercontent.com` — verified from the effective
URL *after* the transfer. A redirect anywhere else MUST abort the update.

**Size and SHA-256 MUST both be verified** before anything is renamed into place, and the transfer MUST
be bounded by the record's `size`.

**Publishing MUST be atomic**: write a candidate beside the destination on the same filesystem, retain
the active binary as a `.previous` copy, then `rename`. `--rollback` MUST put the previous one back.

**Only an install this installer made MAY be updated in place**, identified by a marker file beside the
binary. A build from source MUST be refused with guidance rather than silently overwritten.

**The marker names the channel.** Its first line is the channel the install follows, so the record it
resolves is `<channel>-<triple>.json`; `install.sh` writes `stable`. A marker that names nothing usable
MUST fall back to `stable` rather than refuse — the marker's job is to say "this install is ours", and
an install that cannot state a channel still follows the default one. The record's own `channel` field
MUST equal the channel that was asked for.

A second channel is REQUIRED for one reason: a refusal cannot be proved against a record that is
correct. Every release therefore also publishes `proof-<triple>.json` — the real version, the real
size, and a **deliberately wrong** `sha256` — so that the updater's "this download does not match the
release record" path is exercised end to end by ADR-018's proof instead of being assumed. Nothing
selects that channel by default, so no install can resolve it by accident.

**There is no independent release signature.** The record carries the digest the binary is checked
against, so the record is the trust anchor, and its integrity rests on TLS to `github.com` plus GitHub
itself — the same posture as every `curl | sh` installer. On macOS the Developer ID signature is a
second, independent check; on Linux there is none. A detached signature over the record, verified
against a key compiled into the binary, is the way to close that, and is deliberately NOT in this
change: it needs a release key with its own custody story. Recorded here so it is a known gap rather
than an unexamined assumption.

**Shell integration is `vox shell-setup`** — completions into each shell's own autoload directory and
one marked block at the *end* of the rc, so it wins the `PATH` race against version managers that
prepend their shims earlier in the same file. `install.sh` and `vox update` MUST run it after placing
the binary, and it MUST be skippable (`VOX_NO_SHELL_SETUP=1`) and exactly removable
(`--remove`). Its proof is the standard ADR-018 cites.

**Targets** are `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` and `x86_64-apple-darwin`. macOS
artifacts MUST be signed and notarized with a Developer ID: an unsigned download is quarantined by
Gatekeeper, and "clear the quarantine flag by hand" is not an acceptable first run for a tool whose
purpose is confidentiality. Signing MUST happen **after** `strip`, which rewrites the Mach-O and
invalidates any earlier signature.

## Consequences

### Positive
- Pure Rust, **no FFI boundary** to secure — the smallest secret-handling surface of any client; the
  headless node never holds this user's secrets, preserving the no-IPC-secret-crossing claim.
- Runs everywhere a terminal does, incl. **headless servers and over SSH**, and exercises tunneling
  end-to-end (dogfoods ADR-013); the natural Linux/server client.
- Reuses the entire core and the ADR-014 trust-model UX requirements; only presentation is new.

### Negative
- **No camera ⇒ the strong scan path lives on the peer's phone**; numeric compare is the in-terminal
  fallback (higher false-accept, ARES 2023), mitigated by keeping scan primary and prompting proactively.
- `mlock` can be unavailable on the very headless/container targets this client favors — handled by a
  surfaced, documented degradation rather than a silent one.
- Terminal a11y has real limits (screen-reader/TUI variance); addressed by the executable a11y mode and
  stated honestly. No rich media in the terminal.

### Neutral
- Peer to ADR-014 over one core, not a fork. Targets macOS + Linux; iOS / Linux-GUI are additional peer
  ADRs if/when wanted (Windows is not a target).

## Implementation notes (M12)

Built as `crates/vox-tui` — a `vox_tui` library (all testable logic) + the `vox` binary, linking `vox-core` directly (no FFI). Stack: ratatui + crossterm + qrcode + clap(+complete+mangen) + secrecy/zeroize + tokio/tokio-util (`tui-textarea` was dropped in M13.5, see below).

- **Verification core** (`verify`): the pinned safety code — `SHA-256("vox/safety/v1" ‖ pk_lo ‖ pk_hi)` over the two composite pubkeys in ascending byte order — rendered as 8 groups of 5 decimal digits (~133 bits), symmetric so this TUI and the ADR-014 client agree. The verification-QR payload is canonical-CBOR `[label, composite_pubkey]`, strictly decoded. Exhaustively unit-tested (symmetry, pinned re-derivation, tamper/label rejection).
- **Typed core↔UI boundary** (`viewmodel`): `ViewModel` (latest-wins, `watch`-shaped) + `Event` (ordered, `mpsc`) + `Command` (UI→core). The binding contract holds *by construction* — these types carry only fingerprints, nicknames, already-decrypted display text, and enum state; **no** keys/SKDMs/SEK/`self_seed`. The one secret-bearing input (a create/join passphrase) is a transient `secrecy::SecretString`, never retained in a `ViewModel`. Both core→UI text paths are **typed, not free strings** — errors are a bounded `UiError` and command results a bounded `CommandStatus`, each mapping to fixed redaction-safe messages — so a (future live) core cannot leak plaintext through the error or status channel. Tests assert the types are `Send + 'static` and `Clone` (channel-safe).
- **State machine** (`state`): screen/focus navigation, the modal `:` command palette, and the verification acceptance transitions (`unverified-tofu → verified`; any key change → `key-changed`). Every *non-secret* action is reachable by a typed `:`-command (channel-independent verbs like `quit`/`lock`/`open`/`back`/`focus` work even from the channel list); **create/join are the deliberate exception** — they need a passphrase, which is entered through a *masked* prompt and shared out-of-band, never on the palette line, so they are initiated through the dedicated onboarding flow (wired with the live core), not a one-line command. Driven by injected `crossterm` key events in tests (the ADR-015 input-injection gate).
- **QR rendering** (`qr`): ECC level M, mandatory 4-module quiet zone, Unicode half-block default + ASCII fallback, an `invert` for dark terminals, and a `fits` check for the minimum-terminal-size fallback. Tests verify faithful rendering, quiet zone on all sides, invert, and oversized-payload error (no panic).
- **View** (`ui`): ratatui render of the channel list / channel (timeline + composer + member pane) / status + hint bars / palette overlay. State is **never colour-only** — verification/consent/Block render as glyph + text label (NO_COLOR-safe). Undecryptable entries show an honest non-leaking marker. Covered by `TestBackend` render-snapshot tests, including the marker (no plaintext leak) and the `mlock`-unavailable warning surface.
- **Event loop** (`app`) + **CLI** (`cli`): correct terminal lifecycle (enter alternate screen before any draw; leave + `ESC[3J` Purge on every exit path) so decrypted text never enters the primary buffer/scrollback. `vox`/`vox tui` runs the loop; `vox completions <shell>` and `vox man` are fully implemented from the same clap model.

**Honest scope — the live-core runtime is the documented integration seam, exercised by the post-M12 manual-spike phase.** M12 ships the complete, tested client *structure*: the security-critical verification, the typed boundary, the navigation/consent state machine, QR, the ratatui view, and a terminal-correct event loop — all behind a `CoreHandle` trait. Binding that to a **running** embedded `vox-core` node (identity-vault unlock, channel create/join, log append + render-gate, sync producing `ViewModel`s and consuming `Command`s) is the `CoreHandle` contract; the shipped `OfflineCore` binding renders honestly and records commands **without fabricating** channels, messages, or trust state (it explicitly says "not connected" rather than faking delivery). This is a layering boundary, not a stub: nothing here pretends to work that doesn't. Wiring a live `CoreHandle` and proving it end-to-end against real peers is precisely the manual end-to-end verification the project runs after M12 (green unit tests ≠ verified-working). The TUN datapath (ADR-013/ADR-014, privileged helper + smoltcp) and desktop OS notifications (`notify-rust`; the dep-free OSC 9 / bell path is the SSH fallback) are likewise client-surface items folded into that phase.

The workspace test counts are recorded in the ADR index status table, not here (they change with every milestone); fmt/clippy(`-D warnings`)/doc are CI gates and the `vox` binary builds.

- **Live client (M13.5, 2026-09-19).** `app::run_live` builds the multi-threaded tokio runtime,
  spawns the embedded `vox-core` node (ADR-016) on it, runs the UI loop on the calling thread as the
  blocking crossterm task, cancels auxiliary tasks with a `CancellationToken` and shuts the node down
  (locking everything) on every exit path — the runtime shape this ADR specifies, now real.
  `live::LiveCore` is the live `CoreHandle`: it projects the node's client-agnostic `NodeView` into
  the `ViewModel` and maps each `Command` onto `NodeCommand`s, blocking the UI thread on the node's
  typed reply; UI-local state (channel on screen, unread counts from the node's ordered events,
  verification marks) lives there. `cli` always runs live over a profile (`--profile`, `--data-dir`,
  `--config-dir`; env `VOX_PROFILE`/`VOX_DATA_DIR`/`VOX_CONFIG_DIR`; then XDG — the precedence above).
- **Onboarding and passphrases (M13.5).** A modal, **masked** multi-field prompt (`state::Prompt`)
  collects every passphrase: create-identity (opens automatically on a fresh profile), unlock (opens
  whenever the view reports `locked`), create-channel (`:new <name>`, name prefilled), open-channel
  (Enter on a closed channel — its local name is under the channel lock, so it is listed by a short
  id). Field buffers are `Zeroizing<String>`; the prompt renders one `•` per character and a
  mismatch is reported through the status line without echoing anything typed. Ctrl-C quits from any
  mode. `:lock`, the 5-minute idle timer and `SIGHUP` lock the node.
- **Composer (M13.5).** A single-line composer owns printable keys/Backspace/Enter when focused;
  Enter sends `:send`-equivalent text to the channel on screen. **`tui-textarea` is dropped from the
  stack** listed above: a chat composer with Enter-to-send is single-line by nature, and the widget
  was an unused dependency; a multi-line/vim composer would be its own decision.
- **Release gates now met (M13.5).** The primary-buffer assertion: terminal I/O is behind
  `app::TerminalIo`, and tests with a recording backend prove the alternate screen is entered before
  any draw and left (with purge) after the last, on a normal quit *and* on a mid-loop error.
  Lock/zeroize: the live-core test locks and proves the view is locked, the channel closed and its
  name hidden; prompt fields are zeroizing by type and a cancelled prompt drops them. Idle lock is
  tested with an injected clock. Verification acceptance and consent flows remain unit-level until
  M14 gives them a second party.
- **Known gaps (re-cut 2026-09-19 after M13.5).** Still not implemented: identity import/export
  (armored OpenPGP export with user ID + self-signature), backup, join onboarding and invite QR
  (M14), the in-app verification screen and safety-code display (needs the peer's key: M14 member
  bundles), keybinding config, the multiplexer warning, `NO_COLOR` handling, OS/OSC-9 notifications,
  the tunneling subcommands (`vox service add` / `vox forward` / `vox up`, M15), file send, and the
  `--accessible` flag (the ASCII QR style is unreachable from the CLI). The QR "round-trip" test
  still compares dimensions only. The `tokio` and `zeroize` dependencies are now used; the runtime's
  shutdown/backpressure and the terminal-compatibility matrix are exercised manually, not by tests.
  The live-core lifecycle test runs the production Argon2id profile and is therefore `#[ignore]`d in
  the debug suite and run in release by CI.

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
