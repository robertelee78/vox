# ADR-028: One Experience — Keyring, Rooms, Services and Files, in the TUI and the App

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted for v0.4.0 (the decider, 2026-10-05); §2a added, and the lanes view (W-3)
removed, from the decider's answers of 2026-10-06; E-2, E-5, E-7, K-6, K-8, L-1, L-1a, L-1b, L-2, L-6 and L-7 amended
for v0.4.1 (the decider, 2026-10-08). Nothing in this ADR is built unless a requirement says so.

**Proposed for v0.4.20, not accepted or built:** K-6 and K-7 are amended only as specified
in K-21–K-26 below; existing accepted requirements remain in force pending decision.
**Date**: 2026-10-05
**Deciders**: Robert E. Lee
**Tags**: ux, tui, macos, keyring, rooms, services, files, look, install
**Related**: ADR-001, ADR-005, ADR-007, ADR-008, ADR-014, ADR-015, ADR-016, ADR-017, ADR-020, ADR-021, ADR-023, ADR-026, ADR-027, ADR-029
**Inputs**: [docs/ux/v040-ux-research.md](../ux/v040-ux-research.md) and the decider's answers in
[docs/ux/v040-ux-interview-decisions.md](../ux/v040-ux-interview-decisions.md) (2026-10-03, 2026-10-04,
2026-10-05, including the answers to this ADR's first draft's open questions, and 2026-10-06 for
§2a, W-3 and W-4); the website's app study (`voxlucis.us` `src/components/Experience.astro`).

## Context

v0.4.0 is the native macOS app (ADR-014, to be rewritten) beside the TUI (ADR-015). Both are
clients of the daemon (ADR-026 S-4). Vox has only rooms, nodes, Sessions (ADR-029), trust and
services; this ADR defines how a person sees and uses them, once, for both clients, and amends the
ADR lines the decider's answers overrule. It adds no concept beyond those, except the four the
decider named: read records, the room's shared name, the decision record and the token file.

## Requirements

### 1. One experience

- **E-1.** The TUI and the app MUST present one model: the keyring (who this node trusts), rooms
  (where its members talk and share), and services and files (what is reachable through a room).
  A task MUST take the same steps and the same words in both clients.
- **E-2.** The words MUST be: node, fingerprint, keyring, alias, room, room link, passphrase,
  Session, service, address, file, trust, remove, attach, detach. Taking a node out of the keyring
  MUST be called Remove in both clients, the CLI's help and output, and the manual. "Contact",
  "channel", "invite", "consent", "safety code", "verified", "block" and "untrust" MUST NOT appear in
  what either client or the CLI says.
- **E-3.** There MUST be no contacts list, no directory and no separate 1:1 path (ADR-001): a
  direct message is a two-member room.
- **E-4.** Each client MUST act as exactly one node: the one it was signed in as, until it signs
  out. The TUI and the app MUST refuse to post, trust or share as any other node, including an
  agent's node on the same machine. Other nodes on the machine appear only as members of rooms
  this node shares with them. Sign Out (the app's Node › Sign Out…, `vox node signout`; the
  decider, 2026-10-08) MUST detach the node and forget everything that would bring it back without
  the person: its keep (`.daemon/attach`), the passphrase kept for it in the Keychain, and the app's
  remembered node; it MUST leave the node, its rooms and its messages on disk. Signed out, the app
  offers the first-run sign-in: choose a node on the machine, or make a new one. Detach MUST NOT
  sign out: after Detach the app offers to attach the same node again, and Quit.
- **E-5.** Every action that changes access MUST state its effect in words before it acts and
  report what it did after: trusting (which rooms and services it covers, now and later),
  removing a node (what stops, what was already read, which live sessions were cut), leaving, ending,
  retention, sharing and stopping a share.
- **E-6.** Every state MUST be shown by a glyph and a word, never by colour alone (ADR-015 14.1
  as amended in §9).
- **E-7.** A failure MUST be told in one sentence, written once in vox-core and shown by every
  client and the CLI. The sentence MUST say what failed and what the person can do next. A client
  MAY capitalise its first letter, end it with a full stop, and show its technical detail in a
  disclosure with Copy; it MUST NOT reword it. A sentence that fails this rule MUST be fixed in
  vox-core, not in a client.

### 2. Identity and keyring

- **K-1.** A node's identity MUST be shown as its **fingerprint**: the full 52-character base32
  string, grouped for reading, with its fingerprint art (§8 L-9) beside it. `vox id` MUST keep
  printing the bare fingerprint alone on stdout. Showing a fingerprint as a QR code is v0.4.1,
  with the iOS app.
- **K-2.** There MUST be exactly one trust state: **in my keyring**, or not. There MUST be no
  "verified", "unverified", TOFU or "key changed" state. A different key is a different node.
- **K-3.** Adding a fingerprint to the keyring MUST offer the authenticated name the node
  presents as an editable default, available before trust through optional identity-authenticated
  metadata independent of room, chat and drive permissions (the decider, 2026-10-12; #796).
  The person MAY accept that default without typing, override it, or change the local alias later
  (`vox trust rename`). A local alias remains separate from the remote name and MUST survive a
  remote rename, reconnect, rejoin or rediscovery. Wherever a node is named, a keyring node is
  shown by its local alias; a remote-only name MUST carry its fingerprint and "not in keyring".
  A name never selects an identity or grants authority. Missing names and older peers retain
  fingerprint/manual-name fallback. Remote metadata is bounded and presentation-safe, held only
  in memory and refreshed after restart; existing sealed aliases and grants remain unchanged.
- **K-4.** Addressing MUST accept `@alias` in the composer; the client MUST write the whole
  fingerprint into `to` (ADR-020 4.6). Two members whose aliases are equal or differ only in case
  MUST be shown with a fingerprint suffix.
- **K-5.** Trust MUST be reachable where it matters, with the same action in both clients: on a
  message from a node not in the keyring, on a member in the member pane, on a join, and on a
  service or file the node cannot reach because the sharer does not trust it. Comparing a
  fingerprint MUST offer paste or typing, and grouped text; a mismatch MUST be its own action that
  says not to trust the node. Scanning a fingerprint is v0.4.1, with the iOS app.
- **K-6.** Removing a node from the keyring (Remove, E-2) MUST be the only way to stop reading and
  being read by it (ADR-007 G-21). There MUST be no separate block. **Proposed v0.4.20 amendment:**
  ADR-007 G-28–G-32 also permit authorized removal of a node from one room, distinct from global
  keyring removal; this is not a personal block or per-room visibility opt-out.
- **K-7.** When a node joins a room, each member's client MUST say which of this node's trusted
  members trust the newcomer, from the consent grants on the log (ADR-007 G-9), for example
  `K2M9·Q7RT joined. ann trusts it.` This MUST NOT add it to anyone's keyring. **Proposed
  v0.4.20 amendment:** K-23–K-25 govern when an observed roster addition may be presented as a
  join; current membership and caption data do not prove historical admission time.

- **K-8.** There MUST be no identity backup. Onboarding MUST say plainly that a lost machine means
  a new node, and that the people who trust the old one remove it from their keyrings.
- **K-9.** The keyring window (ADR-026 N-2, 30 minutes) MUST be visible where the person works:
  the TUI status bar and the app's menu bar extra MUST show whether a keyring change will ask for
  the passphrase, for example `keyring open 23m`. *Amended 2026-11-13 by ADR-042:* `vox status`
  shows it as a fact row directly after the log line,
  `keyring: locked; a trust change will ask for your passphrase` or `keyring: open, 23m left`, never
  beside the health verdict (ADR-042 TR-9).
- **K-10. A node attached with its passphrase is remembered.** *Amended 2026-10-10 (#666):* the
  decider, 2026-10-09: "vox is unusable"; "if it need a passphrase it should tell me what to do",
  "not silently fail". Attaching a node with its identity passphrase (`vox node attach`, the app's
  attach) MUST store that passphrase in the macOS Keychain, keyed per node, once the daemon has
  proved it, and a node made by `vox node create`, `vox setup` or `vox agent setup` MUST be
  attached at once and remembered the same way. At its start the daemon MUST attach every node
  whose passphrase is stored, and every remembered node that has none, with nobody typing: after a
  daemon restart, `vox update`, the app's quit and a reboot. `vox node attach --no-remember`
  MUST store nothing, and `vox node forget-passphrase <node>` MUST remove what is stored. Where
  the passphrase is asked for, Vox MUST say that anyone who can unlock this Mac's login keychain
  can then attach the node. On Linux the kernel's per-user persistent keyring is the store (ADR-041
  RS-1); after a reboot a node is Ready only from a credential or a passphrase file, and otherwise
  says its remembered passphrase is gone and how to unlock it once (ADR-041 RS-3). *(Amended
  2026-11-13 by ADR-041.)* A remembered node that cannot be attached at the daemon's start MUST be
  said to the person: a notification with the command, and an Attach… action on its row under ON
  THIS MACHINE in the app. (Until this amendment the Keychain was opt-in per node in the app only,
  off by default.)

### 2a. Passphrases and trust offers (the decider, 2026-10-06)

These rules are the same for every node. A person's node and an agent's node MUST NOT be told apart
by any of them (ADR-001: there is no typed agent or human).

- **K-11. An identity passphrase is optional.** *Amended 2026-10-10:* ADR-005 J-2 (V030-36) is
  restored, by the decider's ruling of 2026-10-09 ("passphrases are optional"; "we talked about
  this"). Creating a node (`vox node create`, `vox setup`, `vox agent setup`, the TUI's or the
  app's onboarding) MUST accept an empty identity passphrase, and MUST say once, where it is given,
  what it means: the node's identity key is kept on that machine unencrypted, so anyone who can
  read its data folder can act as the node. Attaching or unlocking a node made with none MUST
  accept the empty one without asking again. Whatever the node has, the passphrase MUST be asked
  for in exactly two cases: attaching the node, and changing its keyring (trust add, remove,
  rename, a capability change). A retention change MUST NOT ask for it (ADR-010 AR-28 as
  amended). (Between 2026-10-06 and this amendment K-11 required a non-empty passphrase, which
  v0.4.0 to v0.4.2 enforce.)
- **K-12. Attaching does not open the keyring window.** A passphrase given to attach a node MUST
  NOT open the keyring window (ADR-026 N-2). Only a passphrase entered for a keyring change MUST
  open it, for 30 minutes. K-9 shows the window.
- **K-13. A passphrase is typed outside an agent's session.** When an agent's hook finds its node
  not attached, or a keyring change is to be made for its node, the hook MUST show the operator, in
  the harness session, the command for each step to run in a terminal outside that session, once
  per session for a node not attached (#666), for example
  `vox node attach claude-code-mbp` or `vox trust add <fingerprint> --node claude-code-mbp`. That
  command MUST read the passphrase from its own terminal. A hook MUST NOT attach a node, and MUST
  NOT take a passphrase from the environment, a file or the session. A keyring change MUST NOT take
  its passphrase from an environment variable, a file or the Keychain (K-10 covers attach only).
  The daemon attaching a remembered node at its own start (K-10) is not a hook attaching it.
- **K-14. Capabilities.** A keyring entry MUST carry what it grants: **read** (what trust means
  today, ADR-020 §3), or **read + drive**, stored in the sealed keyring with the entry. Both clients
  and `vox trust list` MUST show it. What drive permits is ADR-029 §3 (Sessions, v0.4.0).
- **K-15. A join offers trust.** When a node joins a room, each member whose keyring does not hold
  it MUST be offered the newcomer: an item under **needs you** (W-2) showing its fingerprint grouped
  with its art (K-1) and what K-7 says about it. The offer MUST be derived from the join on the log;
  it MUST NOT add an entry type.
- **K-16. Accepting.** Accepting an offer is ADR-020 3.7's second entry point, `vox trust add` with
  the offered fingerprint. It MUST ask for an editable local alias with its known presented name as the default (K-3) and for **read** or **read + drive**, with
  read the default, and MUST pass ADR-020 3.1's passphrase gate as amended by K-12. It MUST NOT
  require comparing the
  fingerprint: the client shows it, and the person accepting does whatever check their threat model
  needs (K-5's compare action stays available).
- **K-17. Accepting offers back.** Once a node accepts a newcomer, the newcomer's client MUST show
  an offer of that node, derived from the consent grant on the log (ADR-007 G-9), accepted as in
  K-16. One accept on each side completes a pair.
- **K-18. An offer waits.** An offer MUST stay under needs you until it is accepted, dismissed, or
  the offered node leaves the room. Dismissing MUST be local and silent: the offered node is not
  told and stays not in keyring. Trust stays reachable later from the member pane (K-5).
  Removing a member from the keyring MUST also dismiss what it is offered on now, in the same
  local, silent way, so a node is not offered back someone its person just removed; it MUST be
  offered again on a new basis only: the member leaves and joins again, or grants this node
  consent again (amended 2026-10-10, under the decider's delegation).
- **K-19. An agent's node is offered in its harness.** For an agent's node, the hook MUST show the
  offer in the harness session, in the agent's per-turn read (ADR-020 6.6), with K-13's command to
  accept it outside the session. An accept MUST pass ADR-020 3.1's passphrase gate whichever
  client or command makes it.
- **K-20. No trust file.** There MUST be no provision-time import, bulk trust file or other trust
  path beyond ADR-020 3.7's two entry points.

### v0.4.20 — scoped design approval, not built

The operator selected these outcomes; independent Opus review of `37b0ffbf4` approved K-21–K-25
at design level, with K-22's independent staging clarification below. K-26 member removal
remains proposed. No implementation, consumer acceptance or publication is approved here.

- **K-26. Room removal action.** The native member UI and CLI MUST allow the creator or authorized
  admin to select the exact verified member fingerprint for removal from this room under ADR-007
  G-28–G-32. Before acting and in the result, identify the room and full fingerprint, distinguish
  same-name replacement nodes, explain that other rooms and global trust are unchanged, that old
  disclosures cannot be recalled, and show applied versus pending/unknown propagation. Do not
  confuse this action with removing an admin role or a node from the keyring. Show a non-admin
  refusal without changing membership. Ordinary admin grants last until explicitly revoked;
  a certificate carrying an expiry MUST be refused for removal, with a clear permission refusal
  (not an internal-error report) explaining that the operator must ask the creator. Creator-only
  explicit readmission MUST likewise identify
  the room and exact fingerprint and MUST NOT promise access before independent checks succeed.
- **K-21. Evidence-bounded access warnings.** A client MUST distinguish authenticated computer
  approval/application, effective local node trust, room membership/reciprocal consent, key
  delivery, connectivity and private Session permission; none alone implies the others. Absence
  of inbound room consent MUST NOT be presented as a remote decision not to trust or as an
  explicit refusal. Show confirmed computer application only when the matching current
  authenticated receipt establishes it; local application is not a fresh remote receipt. Show
  pending/unobserved room consent, actual key or governance failure, unreachable, explicit refusal,
  or unavailable/stale observation only when supported by the corresponding evidence. Failed
  reads MUST NOT convert unknown into false or present last-good data as current; retained rows
  MUST identify staleness and the actual failure. No approval, trust or access check is weakened.
- **K-22. Warning consumer acceptance.** In the existing isolated native paired-computer journey,
  complete actual approvals and stage genuine unresolved inbound consent or key wait; a failed
  join may supply it but is not required, so acceptance does not depend on FX-53's repair. The visible warning
  MUST not accuse the remote node of withholding trust; it MUST show the actual unresolved room or
  delivery condition. After real repair, exchange distinct new messages both ways before presenting
  room access as ready. Separately exercise genuine missing approval/refusal, stale and unavailable
  observations, same-name distinct fingerprints and private Session read/Drive denial. The
  apparatus is controlled failure and isolated profiles; the PRODUCT verdict is the native
  display and actual access, not a mocked projection, string search or successful post exit.
  A mutant that treats missing inbound consent as an explicit remote refusal MUST fail this proof.
- **K-23. One roster observation owner.** The selected room's initial, refresh and watcher roster
  publications MUST share one ordered owner bound to room ID, saved-room instance, selection
  generation and node-observation epoch. Distinguish an unknown baseline from a successfully
  observed empty baseline. The first successful current snapshot seeds it without join lines;
  failed reads do not seed it or replace good rows. Later ordered snapshots compare fingerprints
  against the known baseline, publish at most one line for each newly observed member and remove
  departed members' lines. Fence async publications and captions so obsolete same-generation
  reads, replaced room instances, switches and observer recovery cannot regress current state or
  disclose a previous room's private caption. Reconcile an obsolete page/roster read rather than
  falsely reporting recovery complete. Preserve existing caption and Drive authorization checks.
- **K-24. Observation honesty.** A roster-difference line is a local observation, not a durable
  admission event or authenticated admission timestamp. It MUST NOT assert an exact join time or
  reconstruct an admission before the baseline or a join and departure between snapshots. Current
  Session/cwd information MUST be disclosed only under current authority and MUST NOT be implied
  to have existed at admission.
- **K-25. Join-line consumer acceptance.** Extend the existing isolated native journey: force both
  orders of initial and watch reads for a pre-populated room and observe no lines for existing
  members, then admit a new fingerprint and observe exactly one line. After a successful known-empty
  peer baseline, the first real peer must produce one line; after a failed first read, the first
  successful populated snapshot produces none. Hold roster and caption responses over room switch,
  same-ID instance replacement and observation recovery, and exercise reordered same-generation
  reads; verify no stale member, false join or unauthorized cwd appears and a later real addition
  remains visible. Apparatus is bounded controlled interleaving and real isolated members; PRODUCT
  verdicts are native timeline, roster and authorized disclosure. Mutants reproducing the old
  initial/watch race and suppressing all joins after an empty baseline MUST each fail the relevant
  consumer proof. These are proposed proofs, not results.

### 3. Rooms

- **R-1.** A room MUST have one **shared name** that every member sees, set at creation and
  changeable only by its creator or an admin (ADR-007 G-5). The name MUST be stated on the room's
  log as a signed governance entry, and the causally last statement by an admin MUST win, as
  retention does (ADR-023 RL-2.1). Per-member room aliases MUST NOT exist.
- **R-2.** A room name MUST be one DNS label: 1–63 characters of `[a-z0-9-]`, not starting or
  ending with `-`, case-folded to lower case, because it is the room part of the readable form of
  every service address (§4 S-1).
- **R-3.** A node MUST refuse to create a room, or to join one, whose shared name equals the name
  of a room it already holds, and say which room holds the name. When a rename by a room's creator
  or admin gives a room the same name as another room on a node, that node, and only that node,
  MUST show every room involved by its room ID instead of its name, in every view and in readable
  addresses, until the clash is gone; it MUST say why once.
  **Proposed v0.4.20 exception, not built:** ADR-023 RL-8.7 checks and reserves the authenticated
  proposed name before remote admission. If the authoritative name changes after admission,
  complete that admitted join and use the same by-ID clash presentation, explaining the
  outcome; do not claim the remote admission was rolled back or invent responder erasure
  authority. Preflight collisions still refuse and preserve the existing room.
- **R-4.** The verb that prints a room's link MUST be `vox room link` (built in v0.3.0) and `:link`
  in the TUI. A room link MUST NOT expire; it stops working only when the room is ended (ADR-023
  RL-8.2). The link and the passphrase MUST be presented as two things sent two ways.
- **R-5.** Joining MUST show the who-reads-whom state per member right away (trusted in each
  direction, waiting for the other side, not in keyring), and say what each person still has to
  do.
- **R-6.** Under each message it sent, a client MUST show who has read it, by alias: `read by ann,
  bea`. A message no member has read MUST show where it is: `only on this machine` or `on N of M
  members' nodes`.
- **R-7.** Retention changes MUST appear in the timeline as one line saying who set what and that
  older messages were removed. The room header MUST always show the retention.
- **R-8.** Unread MUST have three levels per room: addressed to this node (from `to`), new, and
  coordination traffic (counted only, ADR-020 6.6). A key MUST jump to the next room with a message
  addressed to this node.
- **R-8a.** The native room-message view MUST expose a room-wide unread summary and explicit
  **Mark as Read** beside it, including tagged views, with the same captured-room action in the
  Room menu and command palette (⇧⌘U). It MUST acknowledge received messages from other members
  through the captured arrival boundary, including other tags, thread replies and unloaded
  received history; it MUST NOT answer Session requests, accept trust offers or acknowledge later
  arrivals. Successful acknowledgement MUST schedule the existing guarded authoritative unread
  summary reader so the current room updates without navigation or optimistic counter clearing.
  Progress and done/refused/unknown results MUST remain accessible in the existing status surface.
  The explanation MUST distinguish addressed/new/coordination messages from waiting attention,
  state scan limits, and retain the existing explicit cached/peer history and thread/tag routes.
- **R-9.** A reply MUST quote one level (the message named by `re`), and selecting the quote MUST
  jump to it. There MUST be no thread pane.
- **R-10.** Notifications MUST be grouped by room and MUST hide message text by default.

### 4. Services

- **S-1.** A service address MUST travel in its **canonical** form, every part an identifier:
  `<service id>.<node fingerprint>.<room id>.vox`, where:
  - the service id is the service's fingerprint (ADR-017 12.2), `SHA-256("vox/service-fingerprint/v1"
    ‖ room id ‖ sharer fingerprint ‖ name)`, base32 as `b32_encode` writes it (52 characters), so it
    is stable for as long as the sharer keeps that name in that room;
  - the node part is the sharing node's fingerprint (52 characters);
  - the room part is the room's ID (52 characters).
  Each label is 52 characters (at most 63) and the whole address is 162 characters (at most 253).
  Copy actions, pasted text, messages, agent hooks and `--json` output MUST carry the canonical
  form, so an address means the same on every member's machine.
- **S-1a.** Each client MUST render an address in its **readable** form, part by part:
  `<service name>.<the viewer's alias for the node, or its short fingerprint>.<the room's shared
  name>.vox`, for example `nas-ssh.nas.family.vox`. Wherever a readable part is ambiguous on this
  node (an alias clash, K-4; a room-name clash, R-3), that part MUST be shown in its canonical form.
  A canonical address inside a message MUST be shown readable.
- **S-1b.** Every place that takes an address (`vox forward`, the `.vox` proxy, the clients'
  inputs) MUST accept both forms. A readable address typed on this node MUST be translated to the
  canonical form with this node's own aliases and room names; a readable part that names nothing,
  or more than one thing, MUST be refused with a sentence saying which (ADR-017 12.5).
- **S-2.** A share MUST record the service's kind in its `0x0018` statement (ADR-017 12.8): `ssh`,
  `http`, `https`, `dns`, or plain `tcp` or `udp`. The kind MUST be detected, never typed by the
  sharer and never guessed from the port number or the service name:
  - for an endpoint on the sharing machine, from the listening process (its command name, read
    with `lsof` on macOS and `ss` on Linux) and a probe;
  - for an endpoint on another machine (for example `192.168.1.20:22`), by a probe on the wire: an
    SSH banner, an HTTP response, a TLS handshake or a DNS answer;
  - anything not identified MUST be recorded as `tcp` or `udp`.
- **S-3.** For every service a member can see, both clients and `vox service list` MUST offer
  ready-to-copy commands for its kind. What is shown MUST use the readable address (S-1a); what is
  copied MUST use the canonical address (S-1), so the command works when pasted on any member's
  machine. `vox service list` MUST print each share's readable address with its canonical address
  beneath it, and `vox service list --json` and the copy actions MUST give the canonical one. The
  commands are: for `ssh`,
  `ssh USER@ADDRESS`, a `vox forward ADDRESS 127.0.0.1:PORT` pair and an `~/.ssh/config` block; for
  `http`/`https`, a browser URL through the proxy and a forward; for `tcp`/`udp`, a forward. Each
  MUST show what it needs as readiness ticks, in this order and these words in every client and
  `vox service list`: `proxy configured` (for what goes through the proxy), `node attached`,
  `<sharer> trusts you`, `<sharer> online`, each `✓` when it holds and, when it does not,
  `missing:` with what to do (decider, 2026-10-08, G4). `<sharer> trusts you` MUST come only from
  the sharer's own consent to this node in the room's log, never from reading anyone's keyring;
  `<sharer> online` is whether this node holds a live connection to the sharer; nothing is sent to
  learn any of them. Copy MUST use the system clipboard in the app and OSC 52 in the TUI, and the
  command MUST also be printed.
- **S-4.** Sharing MUST be one step in both clients: the client MUST list the services listening
  on this machine with their process names, suggest a name, and before sharing show the address
  members will use and name who in the room can and cannot reach it (ADR-017 4.2). A share of an
  endpoint bound to every interface, or of a well-known sensitive port, MUST be warned about first.
- **S-5.** The daemon MUST run the `.vox` SOCKS5 proxy (ADR-017 §5) while any node is attached, on
  `127.0.0.1:1080` unless configured otherwise. `vox up` MUST NOT start a second proxy; it MUST
  report the running one and print the `ssh` configuration block.

### 5. Files

Files and folders are temporary hand-offs between members, not a way to keep code in step: agents
keep code in sync through GitHub.

- **F-1.** A share MUST be a message, addressed like one. `vox share ROOM PATH [--to NODE]…
  [--urgent] [-m NOTE]` MUST post one announcement carrying the note, the addressees (`to`, as
  whole fingerprints, ADR-020 4.6) and the urgent flag, besides the name, size and SHA-256
  (ADR-020 11.3). The note and the addressee MUST travel in the share itself, never as a separate
  message. Dropping, pasting or attaching a file or folder in either client MUST do the same, with
  the composer's To: and urgent switch (W-4).
- **F-2.** The daemon MUST hash and serve the share on a room-bound service until the message
  expires under the room's retention, the sharer stops it, the sharer leaves the room, or the room
  ends. No foreground process is needed; `vox share` returns once the daemon serves. `--count`
  and `--for` MAY remain as the sharer's own earlier stop.
- **F-3.** A node MUST pull a share automatically when it is addressed to that node, or to no one,
  and the sharer is in its keyring, whatever its size, file or folder: an agent cannot click.
  A share addressed to other nodes MUST show as a card naming who it is for (with its name, size,
  note, sharer and whether the sharer is online); any member MAY still pull it with `vox room get`
  or the card's action. Every pull MUST be verified (ADR-020 11.4) before it is shown or saved.
- **F-4.** Pulled files MUST land in `<data root>/nodes/<node>/files/<room>/`. A person's client MAY
  save a copy elsewhere, for example `~/Downloads`, and MUST ask before it does; that copy is theirs
  and outlives the message. Nothing is written outside the node's files directory without asking.
- **F-5.** When a share's message expires, every node MUST delete its pulled copy under
  `files/<room>/`, its thumbnail and its preview, and the sharer's daemon MUST stop serving it.
- **F-6.** An agent's node MUST give its agent, through its hook (ADR-020 6.6), the share's note and
  the local path of the pulled copy. `--urgent` MUST wake an addressed agent as any addressed urgent
  message does (ADR-020 4.5, 6.2).
- **F-7.** The sharer's card MUST show who has pulled the share, by alias, from its own daemon's
  record of completed, verified fetches, beside the message's read receipts: `pulled by agent-2 ·
  read by ann`.
- **F-8.** A shared folder's announcement MUST carry a file list with each file's hash and size.
  Pulling it again MUST fetch only new or changed files, and an interrupted pull MUST resume. The
  sharer's folder is the source; there MUST be no live or two-way sync. A share is a hand-off that
  ends with its message; keeping code or long-lived files in step is git's job, not Vox's.
- **F-9.** An image announcement MUST carry a thumbnail of at most 16 KB, a BlurHash and the image's
  dimensions inside the encrypted message, so a reader sees a preview while the sharer is offline.
- **F-10.** A message carrying a URL MUST carry a link card (title, description, an image of at most
  16 KB) fetched once by the **sender's** node and placed in the encrypted message. A reader's node
  MUST NOT contact the linked site.
- **F-11.** The TUI MUST show images inline where the terminal supports it (kitty, iTerm2, sixel,
  then half-blocks), only after verification; the app MUST show them inline and offer Quick Look.

### 6. Read records

- **RR-1.** A node MUST post a read record when a message is shown to its person (the message is on
  screen in the focused room in either client) or, for an agent's node, when its hook drains the
  message into the agent's turn (ADR-020 6.6). There MUST be no opt-out and no distinction by kind
  of node.
- **RR-2.** A read record MUST be a content entry in the reader's own feed, sealed under the
  reader's sender key like any message, listing the entry hashes read since its last record.
  Records MUST be batched (at most one per room per 5 seconds). They expire with the room's
  retention. A read record counts as room activity for the idle end (ADR-023 RL-8.2), as any
  entry does: it is sealed, so a member that cannot open it cannot tell it from a message, and
  every member's node MUST reckon the end from the same entries or they would disagree on whether
  the room is over. A record MUST NOT name a read record, or two nodes would answer each other's
  records for as long as both are open.
- **RR-3.** A client MUST compute `read by …` (R-6) from the read records it can open. A member
  whose read records this node cannot open (it does not trust this node) MUST NOT be shown as
  having read or not read.
- **RR-4.** A read record MUST NOT be shown as a message, counted as unread, injected into an
  agent's context, or wake anyone.

### 7. Decision record

- **D-1.** Each node MUST keep a local record of what it decided: every refusal and every change of
  access (a refused join, dial, circuit or tunnel; a trust added or removed; a share stopped; a
  session cut), one event per decision with its time, what was asked, by whom (fingerprint and
  alias), what was decided, and why, and, for a decision about a room (a join, a share stopped),
  that room's ID.
- **D-2.** The record MUST hold no message text, file name or content, passphrase, key or token,
  and of a room only its ID, never its name. It MUST be sealed at rest under a key derived from
  the identity, as the trust keyring is (ADR-010 AR-22): each event AES-256-GCM under
  `HKDF(self_seed, "vox/decisions-sek/v1")`, or, for a headless `vox node`, under its identity
  factor. It MUST be stored under the node's directory (`nodes/<name>/decisions/<YYYY-MM-DD>.sealed`,
  mode `0600`), kept 14 days, never sent anywhere, and read by clients only through the node
  while it is attached. A plaintext day an earlier build wrote MUST be sealed or removed at the
  next unlock, never left readable. (The decider, 2026-10-07: "Encrypting the diary is the right
  option"; #563.)
- **D-3.** `vox status` MUST name the most recent refusals; the TUI and the app MUST show the record
  as a timeline.

### 8. Look

- **L-1.** One token file MUST define every colour, type, spacing, corner radius and motion value.
  The TUI MUST read it at build time and the app's Swift asset catalogue MUST be generated from it;
  neither MAY hard-code a value the file defines.
- **L-1a.** The app's spacing MUST come from a 4-point scale (4, 8, 12, 16, 20, 24, 32) and its
  corner radii from two values: 5 for controls, cards and tiles, and 10 for windows and frames.
  Spacing and radii inside the timeline and the composer MUST scale with the conversation text size
  (L-1b); everywhere else they MUST stay fixed.
- **L-1b.** ⌘+, ⌘− and the text size in Settings MUST scale the conversation only: the timeline
  and the composer. They MUST NOT scale the sidebar, the inspector, the toolbar, the status bar or
  sheets.
- **L-2.** The default and only theme for v0.4.0 MUST be dark, with these values:

  | Token | Hex | 256 | 16 |
  |---|---|---|---|
  | bg.base | `#0c0d0f` | 233 | default bg |
  | bg.raised | `#131417` | 233 | default bg |
  | bg.panel | `#16171a` | 234 | default bg |
  | bg.overlay | `#1c1d21` | 234 | black |
  | selection | `#45474f` (Increase Contrast `#55575f`), with an accent bar at its leading edge: text.primary on it 7.86:1 (hc 7.20), the bar against bg.panel 9.54:1 (hc 11.73) | 239 | bright black |
  | selection.secondary | `#dcd7cf` (Increase Contrast `#e2ddd5`): a selected row's second line, 6.47:1 on selection (hc 5.33) | 252 | default fg |
  | line.hair | `#303137` (Increase Contrast `#8c8780`) | 236 | bright black |
  | text.primary | `#f0ece4` | 255 | default fg |
  | text.secondary | `#a8a299` | 247 | default fg |
  | text.muted | `#8a857f` | 244 | bright black |
  | accent (ice) | `#5ec8ff`, hover `#8fdbff`, deep `#2fa8f0` | 81 | bright cyan |
  | attention | `#f2b33d` with ▲ | 215 | yellow |
  | danger | `#ff5f3a` with ✕ | 203 | bright red |

- **L-3.** The accent MUST mean only focus or "live" (a peer connecting, a key arriving, a transfer
  verifying, a share going live). It MUST NOT mark trust, danger or decoration.
- **L-4.** Trust MUST be shown by glyph and weight: a node in the keyring in text.primary bold with
  `⇄` (each trusts the other) or `→` (this node trusts it, and as of the other's verified head it
  had not); while this node cannot yet tell, `→` is followed by "cannot tell yet" (ADR-042 TR-10);
  not in keyring in text.secondary with `·` and the words "not in keyring". *(Amended 2026-11-13 by
  ADR-042.)* ASCII fallbacks: `<>`, `->`, `.`.
- **L-5.** The TUI MUST detect truecolour, then 256, then 16 colours, and honour `NO_COLOR`.
  Motion MUST be at most 3 frames in the TUI, off over SSH and slow links, and in the app MUST
  respect Reduce Motion, Reduce Transparency and Increase Contrast.
- **L-6.** The app MUST draw every surface from the tokens, never the system background: the
  timeline and content panes on bg.base, the sidebar and sheets on bg.panel, and the inspector and
  status bar on bg.raised. Surfaces MUST be separated by line.hair, not the system divider. The app
  MAY use the system glass material only on the toolbar and the menu bar extra.
- **L-7.** App type MUST be SF Pro for text, SF Mono (`monospacedSystemFont`) for fingerprints,
  addresses, commands and uppercase eyebrow labels, and Inter Display (SIL OFL 1.1, bundled) at
  800–900 weight for large headings, which are on the first-run screens only. Pane, sheet and
  dialog titles MUST be SF Pro semibold.
- **L-8.** Security state MUST be stated in words. Decorative locks, code rain, green-on-black,
  "access granted" and any glitch effect MUST NOT be used.
- **L-8a.** The standard is mastery, not costume (the decider: "dead sexy hacker style — something
  Neo would use"): dense and precise, keyboard-first, instant, and quiet until something needs the
  person. Every view MUST be fully usable from the keyboard, with a command palette (`:` in the
  TUI, ⌘K in the app) and a key for "next thing that needs you". Live facts (path, latency, bytes
  verified, who read what) MUST be shown as information, not decoration.
- **L-9.** Each node MUST have fingerprint art derived from its fingerprint (a 5×5 mosaic of split
  triangles), always shown beside the grouped text, never instead of it.
- **L-10.** The Vox mark MUST be a faceted V of five planes with one accent glint at the vertex.

### 9. Layout

The website's app study (`voxlucis.us`, `src/components/Experience.astro`) is the baseline
structure for both clients; the TUI renders the same regions in text.

- **W-1.** The window MUST have: a sidebar with the acting node (alias, attached state), the rooms,
  and the nodes on this machine (each `attached` or `detached`); the room's timeline with service
  cards and file offers inline; an inspector with the members and their trust glyphs (L-4); and a
  status bar with the node, its peers and the keyring window (K-9). Keyring and Services MUST be
  views of the same window, not separate windows.
- **W-2.** *Amended (the decider, v0.4.3: "we should just list the rooms and they should change
  color when there's something that I need to respond on to an update of any type but basically
  anybody talking, And maybe a count of the number of messages I've not read yet But we don't
  need those three headings those three headings make it really hard to know where to click";
  and, of a chat list, "should be more like that").* The app's sidebar MUST list the rooms as one
  list with no group headings, the most recent activity first. Each row MUST show the room's
  name, the time of its newest message (the time today, "Yesterday", the weekday within the week,
  else the date), a one-line preview of that message as "sender: text" ("new message" when this
  node cannot read it), and a badge counting its unread messages. A room that **needs** the
  person (a message addressed to this node unread, a trust offer from one of its members, K-15,
  or a Session waiting on this node, ADR-029 CL-2) MUST show it in the stronger accent, and its
  preview MUST say what waits. A trust offer MUST be shown in the room it came from, at the top of
  its General. A key MUST move to the next room that needs the person. The TUI keeps its groups
  (needs you, active, quiet) until it is amended in turn.
- **W-3.** *Removed (the decider, 2026-10-06):* there MUST be no lanes view. A room shows its own
  conversation and its Sessions (ADR-029 §8): Vox has rooms, nodes and Sessions.
- **W-4.** The room's composer MUST carry a **To:** selector of members and of their open
  Sessions (written into `to`, ADR-020 4.6 as amended by ADR-029 TA-1) and an urgent switch
  (ADR-020 4.5). There MUST be no hidden
  coordinator: the composer posts as this node, into this room, like any message.
- **W-5.** "Add to room" MUST show the room link with a copy action and a reminder to send the
  passphrase another way; a node joins only by its own `vox room join` (ADR-005 J-1). The client
  MUST NOT join, trust or act for another node.
- **W-6.** A client MUST NOT show an agent's tool calls, thoughts or turn-by-turn activity in the
  room's timeline. *Amended by ADR-029 SC-4:* that activity is shown only in the session's
  Session, to members with drive. Progress stays on the GitHub issue (ADR-021).

### 10. The app's shell (input to the ADR-014 rewrite)

- **A-1.** The app MUST be native SwiftUI/AppKit over the daemon's control socket (ADR-026 S-4).
  Electron and Tauri MUST NOT be used.
- **A-2.** The window MUST follow W-1: sidebar, timeline, inspector, status bar.
- **A-3.** A menu bar extra, opt-in, MUST show the node's state and keyring window, rooms with
  messages addressed to it, services shared to it with copy buttons, its own shares with stop, and
  live tunnels.
- **A-4.** Quitting the app MUST detach its node, as quitting the TUI does (ADR-026 S-4), except
  when the node is remembered (K-10 as amended 2026-10-10: its passphrase stored in the Keychain,
  which the app's attach does unless the person turns it off, or none needed): then the node stays
  attached (ADR-014 M-6, M-8).
- **A-5.** On macOS the user-level `vox daemon` MUST be registered as a login item with
  `SMAppService`, so it runs before the app opens.

### 11. Install and update

- **I-1.** Vox.app MUST be signed with the Developer ID and notarized, like `vox` (ADR-015 17.16).
- **I-2.** On macOS the one-line `install.sh` MUST install Vox.app as well as `vox`, from the same
  release, verifying the app's signature and notarization as it verifies the binary's
  (ADR-015 17.12–17.13). It MUST install the app to `/Applications` when writable, else to
  `~/Applications`, and say where.
- **I-3.** `vox update` and the app's own update offer MUST run the same updater and MUST update
  `vox` and Vox.app together, to one version. A release MUST NOT be applied to one without the
  other.
- **I-4.** On Linux, install and update MUST be unchanged.

### 12. Out of scope

Calls and the iOS app (both v0.5.0).

## Superseded and amended lines

Each line below is amended as stated. Where code already matches, the ADR text is to follow.

| ADR line | Was | Now |
|---|---|---|
| ADR-005 J-1 | "`vox room invite` prints the room's link" | `vox room link` (R-4; already built) |
| ADR-005 J-6 | "The invite link (`vox://…`)" | "The room link" (E-2) |
| ADR-014 2.2 | Secure Enclave may hold only the unlock factor | Keychain also holds the passphrase of a node attached with it, unless declined (K-10 as amended 2026-10-10) |
| ADR-014 2.5, 2.7 | Required identity backup; restore via self-channel | No backup (K-8) |
| ADR-014 2.6 | Explicit identity selection; per-channel pseudonymous identity | One node per client (E-4) |
| ADR-014 3.2–3.5 | Invite QR; consent wording; per-channel local name; nickname bound to a verified key | Room link (R-4); trust wording (E-2); shared room name (R-1); alias (K-3) |
| ADR-014 3.6 | Nicknames and verification synced across shared-root devices | Removed: one identity per device (ADR-001) |
| ADR-014 §4 (4.1–4.5) | Safety code; verified / TOFU / key-changed states | Fingerprint and one trust state (K-1, K-2, K-5) |
| ADR-014 §5 (5.1–5.6) | Per-sender consent prompts, three states, Block | Keyring trust and removal (K-2, K-6) |
| ADR-014 9.1 | Background LaunchAgent | Daemon as a login item (A-5) |
| ADR-015 3.1 | Room "MAY have a local name"; member pane shows "nickname, verification, consent" | Shared name (R-1); alias and trust (K-3, L-4) |
| ADR-015 4.1–4.4 | Safety-code QR and digits; verification states; prompts | Fingerprint compare (K-1, K-5); one state (K-2) |
| ADR-015 5.4 | Required verified backup | No backup (K-8) |
| ADR-015 5.5 | Explicit identity selection; pseudonymous identity | One node per client (E-4) |
| ADR-015 5.6 | Shown as a safety code | Shown as a fingerprint (K-1) |
| ADR-015 6.4 | "The invite QR" | The room link QR (R-4) |
| ADR-015 6.5 | "until members consent" | "until members trust you" (E-2) |
| ADR-015 §7 (7.1–7.5) | Consent states, `:show`/`:hide`, Block | Removed (K-2, K-6) |
| ADR-015 8.2 | Files via `vox room send`/`get` | F-1–F-11 |
| ADR-015 9.1 | "acts as the node the person picks (`:node <name>`)" | Acts only as the node it was opened with (E-4) |
| ADR-015 14.1 | "verification, consent and Block render as colour, glyph and label" | Trust renders as glyph, weight and label (E-6, L-4) |
| ADR-016 NR-17a | "A room's local name MUST live only in its sealed manifest" | The room's shared name lives on the log (R-1) |
| ADR-017 5.1–5.2, 5.5 | `vox up` runs the proxy | The daemon runs it while a node is attached; `vox up` reports it (S-5) |
| ADR-017 12.1 | "Only `service.node.room.vox` MUST connect" | The canonical form `<service id>.<node fingerprint>.<room id>.vox` and the readable form both connect (S-1, S-1b) |
| ADR-017 12.2 | "The node and room parts MUST be the resolving client's own aliases, or the fingerprints" | Canonical: fingerprint and room ID; readable: the viewer's alias and the room's shared name (S-1, S-1a) |
| ADR-017 12.3 | Rendered with the viewer's aliases or fingerprints | Rendered readable; the canonical form is what is copied and sent (S-1a, S-3) |
| ADR-017 12.9 | `vox service list` renders addresses as 12.3 | Readable with the canonical beneath it; `--json` canonical (S-3) |
| ADR-017 12.10 | `vox serve` prints fingerprints in the node and room places | Prints the canonical address and the readable one (S-1, S-1a) |
| ADR-017 12.8 | Statement carries name, transport, shared or withdrawn | Also the detected kind (S-2) |
| ADR-020 3.10 | "Not built" | Built by read records (§6) |
| ADR-020 4.9a, last sentence | "It MUST NOT say a reply is overdue: a node cannot see another node's reads" | A node sees the reads it can open (RR-3); still no "overdue" claim |
| ADR-020 11.1 | "File bytes MUST NOT enter the log" | Except a thumbnail and a link card of at most 16 KB each inside the encrypted message (F-9, F-10) |
| ADR-020 11.3 | Announcement carries name, size, SHA-256 and service tag | Also the note and the addressees, and the urgent flag (F-1) |
| ADR-020 11.6 | `vox share <room> <file\|dir> [--count N] [--for D]`; ends after `--count`, `--for` or ^C | Also `--to NODE…`, `--urgent`, `-m NOTE` inside the announcement (F-1); the daemon serves until expiry, stop, leave or end, with `--count`/`--for` as the sharer's earlier stop (F-2) |
| ADR-020 11.6 | A folder served as one tar | A file list with hashes, incremental and resumable (F-8) |
| ADR-020 11.5 | Default destination `downloads` setting, else `~/Downloads` | `<data root>/nodes/<node>/files/<room>/`; a person may save a copy elsewhere (F-4) |
| ADR-020 11.2 | The receiver pulls when asked | Pulled automatically when addressed to this node or to no one, from a keyring member (F-3) |
| ADR-026 S-6 | `vox daemon install` deferred | On macOS, a login item via `SMAppService` (A-5); Linux unchanged |
| ADR-005 J-1 | "the two people swap fingerprints … each then runs `vox trust add` for the other" | Swapping fingerprints first is optional; each accepts the other's offer (K-15–K-17) |
| ADR-005 J-2 | An identity passphrase is OPTIONAL (V030-36) | Restored (K-11 as amended 2026-10-10): optional, and an empty one says the key is kept unencrypted; a room passphrase stays optional |
| ADR-020 2.1 | The skill pack's setup creates the agent's node | The operator makes it, at a terminal of their own (`vox setup` or `vox agent setup`), with a passphrase they type or none (K-11 as amended) |
| ADR-020 3.1 | The keyring window runs from when the passphrase "was last entered" | From when it was last entered for a keyring change; attaching does not open it (K-12) |
| ADR-020 3.7 | Entry point 2, in-room approval, not built | Specified as offers on join (K-15–K-19) |
| ADR-020 3.8 | A provision-time import MAY be provided | No import (K-20) |
| ADR-026 N-2 | The window runs from the passphrase given at attach | Attaching does not open it (K-12) |
| ADR-026 N-6 | Agent node created "with no passphrase or one from an environment variable" | With a passphrase the operator types, or none (K-11 as amended); a hook never supplies one (K-13) |
| ADR-026 L-2 | A hook may attach a node implicitly | A hook never attaches; it shows the attach command (K-13) |
| ADR-026 C-6 | Passphrases may come from an environment variable resolved in the client | Never for a keyring change (K-13) |
| ADR-010 AR-28 | A retention request over the socket is gated on the identity passphrase | Not gated: retention is not one of the passphrase's two cases (K-11) |
| ADR-026 L-4 | Passphrase source: none, or a file path | None only for an anchor's headless key; a file serves attach only (K-13) |
| ADR-026 S-2, Context | A hook may attach; a session brings its node in | A hook may start the daemon but never attaches (K-13) |
| ADR-015 16.2 | Passphrase from a file, `VOX_IDENTITY_PASSPHRASE`, then a prompt | File and variable for attach only; a keyring change is prompted (K-13) |
| ADR-016 NR-13 note | "after the keyring window only keyring changes ask again" | The window opens only for a keyring change (K-12) |
| ADR-017 3.4 | Window counted from when the passphrase was last entered | From when it was last entered for a keyring change (K-12) |
| ADR-020 6.10, 12.2 | A hook starts the daemon and attaches its node implicitly | Starts the daemon; never attaches (K-13) |
| ADR-028 W-2 | Needs you: an unread message addressed to this node | Also a waiting trust offer (K-15) |
| ADR-028 E-4 | A client acts as the node it was opened with | As the node it was signed in as, until it signs out; Sign Out detaches and forgets the node's keep, Keychain passphrase and the app's choice, then the first-run sign-in; Detach never signs out (the decider, 2026-10-08) |

## Fixes outside this repository

- `voxlucis.us` `src/components/Experience.astro`, address anatomy: `family` is labelled "your room
  alias"; under S-1a it is the room's shared name. The anatomy should also show that what is copied
  is the canonical form, `<service id>.<node fingerprint>.<room id>.vox` (S-1, S-3).

## Consequences

- One vocabulary and one set of flows across the CLI, the TUI and the app.
- Read records add one small entry per reader per room every few seconds of reading, and expose to
  trusted members, and only to them (RR-2, RR-3), when each message was seen.
- Copied commands carry 162-character canonical addresses: long, but the same on every machine.
- The daemon holds file offers and the proxy for as long as a node is attached.
- For 30 minutes after a passphrase is typed for a keyring change, any program running as the
  user, an agent included, can make further keyring changes on that node without typing it
  (K-12 keeps the window; the decider, 2026-10-06).
- Every member keyring-trusted by a sharer pulls an unaddressed share at once, so a large
  unaddressed share costs every such member its size in transfer and disk until it expires.
- Thumbnails and link cards put up to 32 KB of non-text bytes into a message; the sender's node
  contacts the linked site.
- The release carries two signed artifacts on macOS, updated as one.
