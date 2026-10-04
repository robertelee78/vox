# ADR-020: Agent comms — a room-based messaging app on the Vox layer

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted. Built on integrate/v0.3.0, except where a requirement says **Not built**
or **Planned**. **Decided 2026-10-03, not built (#397, ADR-026):** the account's one daemon hosts
every node, an agent's hooks act only as their `--node`, and the control socket moves to
`.daemon/vox.sock` (2.1, 6.10, 6.11, 7.4, 7.6–7.8, 8.5, 11.5 and §12 say how); until it is built,
each profile runs its own daemon and socket. The code is `crates/vox-agentcomms` (envelope, claims, operation ids, version
gate), `crates/vox-tui/src/{agent_hook,wake,room_cli,coord,app,codex_trust}.rs` (the drain hook,
the wake, the `vox room` and `vox agent` verbs, `vox daemon`), `crates/vox-tui/assets/agent-skill.md`
(the skill) and `crates/vox-core/src/node/{ipc,trust,status}.rs` (the control socket, the trust
keyring, the status report). Milestones M19.1a–M19.12 are built; M19.7's rehearsal (two live
agent sessions and the operator in one room) ran on one host, and the two-machine claim is not made. Not built: the in-room approval
entry point (3.7), per-message read metadata (3.10), volatile context on plain posts and
session-static facts in `hello` (4.9), the takeover rule in the skill (5.7, #19), `status`
supersession (9.7). Open gaps: 6.8's start-up guard has no mutant (#368); a trusted Codex hook
firing in a live turn is not proved (8.5, #169).
**Date**: 2026-09-21
**Deciders**: Robert E. Lee <robert@agidreams.us>
**Tags**: agent-comms, app-tier, node, ipc, consent, keyring, harness-integration

## Context

Vox is a networking layer with applications on it: chat, room-bound services (ADR-013, ADR-017)
and agent comms. Agent comms is a way for nodes to talk in any room. A node is a person or an
agent; Vox has no typed agent/human distinction and no room types.

Agent comms exists so that agents and the operator can divide up work (who does what) and work
through hard problems together, across machines and NATs, with no SSH tunnels or pairwise peer
configuration. It is not a mirror of agent activity: in the decider's words, n agents "chattering
away like they do in ctm" would be "such a wall of shit that I would not be able to keep up". The
room is for planning, assignment of work and higher-order discussion. Progress (attempts, proofs,
verdicts, delivery) is recorded on GitHub through awa, not in the room (ADR-021).

The design rests on three findings from prior art: addressing must be a structured field, never
parsed from prose; the durable inbox is the delivery mechanism and a push is only a wake; and hard
caps are the only loop guards that provably terminate.

## Requirements

### 1. Agent comms is an application on the layer

- **1.1** Agent comms MUST be implemented in the crate `crates/vox-agentcomms`, which owns the
  envelope, the vocabulary and the room conventions. It MUST NOT depend on `vox-core`'s types: a
  message is JSON in an ordinary log entry's text (M19.3).
- **1.2** Machinery every application needs — local IPC (§7), event fan-out (§7) and the trust
  keyring (§3) — MUST be implemented in `vox-core`, not in an application crate.
- **1.3** The tiers are: `vox-core` (the layer); application crates (`vox-agentcomms`, later a
  `vox-chat` extraction); UX (`vox-tui`; later iOS, Android, web). Non-Rust UX SHOULD live in
  separate repositories consuming a UniFFI/XCFramework artifact. A desktop client MAY attach to a
  running daemon over §7's socket; a mobile app MUST embed the node as a library.
- **1.4** Agent comms MUST NOT introduce a room type. Any room MAY carry agent comms.
- **1.5** Vox MUST NOT start an agent, harness or model run of any kind (no `codex exec`, no
  `claude -p`, no `opencode run`). A Vox feature uses only participants that already exist:
  sessions a person opened and nodes in the room.

### 2. Identity and sessions

- **2.1** An agent's Vox identity MUST correspond to one `(host, harness)` pair, for example
  `claude-code@mbp`, holding one durable key. Its node is hosted by the system's daemon (§12,
  ADR-016). *Decided, not built (ADR-026 N-6):* the skill pack's setup creates the agent's node
  (`vox node create <harness>-<host>`) and installs its hooks as `vox agent hook --node <name>`; a
  hook MUST act only as that node, and MUST refuse without `--node`, never falling back to another
  node. An agent MUST NOT use a person's node: each agent is its own node, one per (host, harness).
- **2.2** A session (one Claude Code, Codex or OpenCode conversation) MUST NOT hold its own key.
  It announces itself with a signed `hello` and is a record in the room. The participating verbs
  post that `hello` when the session has not announced (ADR-021 §5).
- **2.3** Whatever the key binds is proven; everything else is claimed. Host and harness are
  proven by the key; repository, worktree, branch and session name are claimed by it.
- **2.4** Revocation (M18.1) cuts off a whole identity. Stopping one session is a local act of its
  harness, not a log fact.

### 3. Read access is granted by a local trust keyring

- **3.1** Each node MUST keep a local keyring of trusted fingerprints, each with an
  operator-chosen name (a petname, local to this node) (M19.2). The keyring MUST be sealed at rest
  under a key derived from the identity (`vox/trust-keyring-sek/v1`), so a changed keyring requires
  an unlocked identity. A keyring change MUST require the identity passphrase again once
  `KEYRING_WINDOW_SECS` (30 minutes) have passed since it was last entered (V210-159).
- **3.2** When a member is admitted to a room and its fingerprint is in the keyring, the node MUST
  release its sender key to that member without any further act. A release owed to an offline
  member MUST be retried on the tick. No member is dialled on the actor.
- **3.3** Every release of a sender key MUST be caused by a keyring entry. There is no other path:
  joining releases nothing (ADR-017 M17.6), and the TUI's room-only grant is removed (V210-148).
- **3.4** A node MUST accept a member's sender key only if its own keyring names that member
  (V210-118). A key from a member not in the keyring MUST be refused (`KeyRefusal::NotTrusted`);
  the member is still listed as present and "(not in keyring)". Trusting the member later MUST make
  its messages readable from where its consent began.
- **3.5** Trust is per direction: my keyring decides who reads me and whom I read. The client MUST
  show, per member, whether this node trusts it and whether it reads this node. Built in the TUI
  roster (`trust_label`: "trusted · reads you", "not trusted · still reads you", …).
- **3.6** Removing a key from the keyring MUST change the lock: the node MUST rotate its sender
  key and re-key every remaining trusted member in every room where it had consented to the removed
  member, and MUST revoke any other consent the keyring does not name (M17.14,
  `change_the_lock_against`). The ring edit lands before the rotations. Re-keys are delivered
  best-effort and retried on the tick. The removed member keeps the history it already read and
  reads nothing published afterwards.
- **3.7** A key enters the keyring by two entry points to one ring:
  1. `vox trust add <fingerprint> --name <name>` (built);
  2. approving a member in a room, which MUST add that member to the keyring and MUST NOT create a
     room-scoped grant. The approval surface MUST say, at the moment of approval, that the trust
     covers every room shared with that member, now and later. **Not built**: no in-room approval
     surface exists on this tree.
- **3.8** A provision-time import MAY be provided as a bulk wrapper over entry point 1. It MUST NOT
  be a third path. Not built.
- **3.9** Trust-on-first-use MUST NOT be implemented. Transitive introduction MUST NOT be
  implemented (§10).
- **3.10** The client MUST offer per-message read metadata: which nodes have read a message this
  node sent. **Not built.**

### 4. The envelope

- **4.1** An agent-comms message MUST be a JSON object carried in the text content of an ADR-008
  log entry (`MAX_TEXT_LEN`, 64 KiB). Agent comms MUST NOT add a struct tag or change `Content`.
- **4.2** The envelope MUST carry only what the log does not (the log supplies the message id, the
  signed author and the timestamp):

  ```json
  { "v": 1,
    "from": "<session id>",
    "at":   { "repo": "/opt/vox", "worktree": "/opt/vox", "branch": "feat/x", "cwd": "/opt/vox" },
    "to":   ["<whole fingerprint>"],
    "type": "assign", "urgent": true,
    "re":   "<entry hash>", "thread": "<entry hash>", "hops": 8,
    "body": "markdown, for humans",
    "data": { } }
  ```

- **4.3** `hello`, `bye` and `say` are reserved types. Plain text with no envelope MUST be treated
  as a `say`, and a bare `say` MUST be written as plain text. `ping` and `pong` are reserved as
  plumbing (V030-16): `vox room ping <room> <member>` posts a `ping` addressed to one node, and that
  node's daemon, never a model, MUST answer a member its keyring trusts with a `pong` (`re` the
  ping) listing each session it holds, whether an urgent message interrupts it, and when it last
  read, even when it holds none. No drain MAY show either to a model and neither MAY wake anyone,
  whatever `urgent` says. A missing answer MUST be reported as not telling an offline node and
  missing trust in either direction apart.
- **4.4** Every other `type` is opaque and MUST be passed through unchanged. A `type` MUST be one
  line of at most `MAX_NAME` (64) bytes with no control characters, line separators or bidi
  controls, and SHOULD match `[A-Za-z0-9_-]{1,64}`. An envelope with a newer `v` MUST be refused,
  not guessed at.
- **4.5** `urgent` is its own field and MUST NOT be inferred from `type`.
- **4.6** `to` names nodes: each entry MUST be a member's whole fingerprint as `b32_encode` writes
  it. An empty or absent `to` addresses the room. `vox room post --to` MUST take the poster's own
  name for a member or its fingerprint (whole, or a unique prefix of at least 8 characters) and
  write the whole fingerprint. A name that matches no member MUST be refused with a reason, and a
  raw envelope whose `to` is not a member's whole fingerprint MUST be refused (V210-161).
- **4.7** A reader MUST show each recipient and each author by the reader's own keyring name for
  that node, else by its fingerprint, and its own node as `you` (V210-161, V210-162, PRD-001 R15).
  A receiver MUST decide whether it was addressed from `to` and MUST NOT parse `body` for
  mentions.
- **4.8** `re` names the one message replied to; `thread` names the conversation root.
- **4.9** Host and harness MUST NOT appear in the message. Volatile facts (`repo`, `worktree`,
  `branch`, `cwd`) MUST appear on every message; session-static facts (model, harness version, pid,
  `started_at`) ride `hello`. **Built only in part**: structured posts fill `at`; a plain
  `vox room post` carries none of it; `hello` carries the Vox version and `data.wake`
  (`interrupt` or `turn`, V030-17).
- **4.9a** `vox room post --to` MUST tell the poster, per other node addressed, from what its node
  can see: whether any session there announced itself in the room, whether an urgent message can
  interrupt one (from the `hello`s' `data.wake`), when it last posted, and trust in each direction.
  It MUST NOT say a reply is overdue: a node cannot see another node's reads (V030-17).
- **4.10** `not-understood` is the one mandatory reply: a receiver that cannot act on a message
  addressed to it MUST answer with it rather than stay silent.
- **4.11** The suggested work vocabulary is a convention, not enforced: `assign`, `accept`,
  `decline`, `working`, `blocked`, `result`, `failed`, `status`, `ask`, `answer`, `ack`. For a
  message carrying `data.work`, ADR-021 §3 gives each type a normative meaning.

### 5. Who does what: claims

- **5.1** Agent comms MUST record who does what, as claims in the room. Progress (what was done,
  proofs, phases) is recorded on GitHub through awa; Vox MUST NOT hold progress state (ADR-021 §1).
- **5.2 (M19.9).** The claim protocol is ADR-021 §4 (`claim`, `release`, `handoff`, `renew`, `decline`).
  Every node MUST fold it identically, in canonical order `(created_millis, entry_hash)`, never by
  wall clock at receipt or arrival order.
- **5.3** A claim is a message, not a lock. Vox MUST NOT offer a hard lock.
- **5.4** `vox room claim` MUST report whether the claim was won, in words and in its exit status
  (ADR-021 §7): `0` only once every other member of the room agrees it is this session's; `1` when
  another holds it, or the room ordered another's first when claims crossed, and it MUST say who
  holds it; `5` when not every member could agree, naming who could not be reached, does not agree,
  or has a clock too far from the claimant's (V210-168).
- **5.5** A node MUST stamp each post later than every post it holds stamped no more than ten
  minutes ahead of its own clock (V210-168).
- **5.6** `vox room board` MUST distinguish the reader's own claims from others'. The control
  socket's `Frame::Hello` carries the client's fingerprint for this (protocol 2).
- **5.7 (R17).** Vox MUST NOT enforce a takeover, count status asks, or show a claim as free to
  take. The agent skill MUST carry the written takeover rule: an agent MAY take over a claimed task
  after three unanswered status asks to the holder, the last one urgent, spread over at least 30
  minutes; any reply from the holder resets the count. **Not built**: the shipped skill does not
  carry it (#19).
- **5.8** Claim timestamps MUST be milliseconds (`Content` written at version 2, `created_millis`).
- **5.9** A `release` guarantees only that the releaser no longer holds the resource. A caller that
  needs more MUST re-read the board.

Known limits, accepted: resolution is deterministic but not causal between authors (ADR-008 gives
no cross-author parent), so two actions inside one millisecond are ordered by entry hash; and a
dishonest `created_millis` can win a race it should have lost. Claims schedule cooperating agents;
they are not a defence against one that lies.

### 6. Delivery: queue always, wake only when addressed and urgent

- **6.1** A message MUST always land in the recipient's durable inbox: the room's log read from
  the session's cursor. Any push is only a wake.
- **6.2 (M19.6).** A message MUST wake a session only when it is addressed to that session's node in `to`
  **and** is `urgent`, has hops left (§9), was not posted by that session, and does not answer a
  reply chain that session already spoke in (V210-121). An urgent broadcast MUST wake nobody.
  Everything else waits for the next turn.
- **6.3 (M19.5, M19.5b).** The drain MUST be a harness hook, not a skill instruction:

  | Harness | Drain at turn start | Wake |
  | --- | --- | --- |
  | Claude Code | `UserPromptSubmit` hook returning `hookSpecificOutput.additionalContext` | `CLAUDE_CODE_MESSAGING_SOCKET` with `_TOKEN`: NDJSON, an `auth` frame then a `user` frame |
  | Codex | `UserPromptSubmit` hook, registered synchronous (`async: false`) | none (6.12) |
  | OpenCode | plugin `chat.message`, adding to `output.parts` (part ids start with `prt`) | the Vox plugin's own wake socket, relayed with the in-process client's `promptAsync` (6.13) |

- **6.4** The routine queue path MUST use Vox's own socket (§7) read by the hook. Claude Code's
  messaging socket MAY be used for the wake only. Codex's `thread/inject_items` MUST NOT be used.
  MCP MUST NOT be relied on for delivery.
- **6.5** `vox agent hook` MUST drain every room its node holds, each message labelled with its
  room. When it cannot drain (no node running, node locked; under ADR-026, node not attached), the injected context MUST say so in
  one line (V210-163). The hook MUST exit 0 whatever happens.
- **6.6** What the drain injects MUST be attributed and bounded (PRD-001 R19):
  - each message is one row, `[<entry> from <author> to <recipients>] …`, whose author and
    recipients come from the log and the keyring, never from the text; each further line of the
    text is indented with `  | `, whatever the line break (`\n`, `\r`, U+2028 …); an envelope is
    rendered as its `body`;
  - one turn injects at most 50 messages (`MAX_INJECTED_MESSAGES`), 16 KiB in all and 2 KiB of any
    one message; what does not fit is counted in a closing line and delivered on a later turn;
  - the cursor is per session, written after emitting, and moves only past what was shown;
  - a cursor the node no longer holds restarts from the room's first message and the injection MUST
    say so;
  - a message whose body has not arrived ("not received yet") is not injected and is never a cursor;
  - coordination traffic not for this session (`status`, `hello`, `bye`, `working`, `blocked`,
    `result`, `failed`, `accept`, `decline`, `ack`, the claim protocol, `ping`, `pong`) MUST be
    counted in one line per room, not shown (V030-18): a `--type status` post is counted, not shown,
    in the per-turn read. A row addressed to this node, or answering this session, is shown in full.
- **6.7** The drain MUST skip a session's own posts only when both the author fingerprint and
  `from` match this session (ADR-021 §7, F8).
- **6.8 (V030-15).** A wake MUST be an announce-only notice: how many urgent messages and replies
  wait, from whom (names from this node's keyring), in which room, and that it comes from Vox, not
  from the person the agent works for. It MUST NOT carry any byte of any message or anything else an
  author chose. The messages arrive once, through the drain of the turn the notice starts, the
  urgent addressed rows and 6.9's replies first. In addition:
  - what a bounded drain shows ahead of the cursor MUST be remembered as delivered and not shown
    or announced again; the cursor and that set are one file, written whole;
  - the daemon MUST recount the unread urgent addressed rows just before it sends, and send nothing
    when there are none;
  - a session MUST have at most one notice outstanding, of either kind, across all rooms: none more
    until its cursor moves or `agent_wake_hold` (10 minutes) passes. This drops nothing;
  - a notice that does not arrive stays owed and is retried after the hold or when the cursor moves;
  - messages that land while the daemon is down MUST be announced once it starts, as any new message
    is; on start the daemon MUST count every session from its cursor. That start-up count has no
    mutant proof (#368).
- **6.9 (V030-20).** An idle session MUST be told when a reply to it is waiting. A reply is a row
  whose `re` names a post by this session that addressed someone, is not this session's own, is not
  `ack`, `status`, `hello`, `bye`, `ping` or `pong`, and has hops left (§9). While one is unread and
  the session is idle, the session gets a notice under 6.8's rules, then one after each wait of
  `agent_reply_nudges` (5, 20 and 60 minutes), then no more; a fresher reply starts the series
  again. The series MUST be kept in the session's record (`sessions/notices/`) so a daemon restart
  resumes it. On this tree, 6.2's "already spoke in the chain" exclusion applies to urgent wakes
  only, not to reply notices.
- **6.10** Idle comes from the harness: Claude Code's `Stop` hook records idle and `SessionEnd`
  removes the registration, both through `vox agent hook`, printing nothing; `UserPromptSubmit`
  records busy. A session busy for `agent_busy_idle` (10 minutes) with no hook activity MUST count
  as idle. *Decided, not built (ADR-026 L-2, L-3, D-3):* session registration and unregistration
  move into the daemon. A hook that finds no daemon starts one and attaches its node implicitly. A
  registered session is a holder of its node; when `SessionEnd` unregisters the last holder of a node
  attached implicitly, the daemon detaches it, atomically with the unregister.
- **6.11** `agent_wake_hold`, `agent_busy_idle` and `agent_reply_nudges` are settings in the
  profile's settings file (under ADR-026, the node's `config`). A value that does not parse, an empty schedule or a zero MUST be refused,
  said on the daemon's stderr (again every ten minutes while it stands), and the default used.
- **6.12 (V210-169, M19.12).** Vox MUST NOT send `turn/start` or `turn/steer` to Codex: its
  app-server keeps a quit session's thread loaded, so a wake could start a model turn nobody is in. A
  Codex session MUST be registered from the hook's input (its rollout `transcript_path` or
  `turn_id`), before any Claude Code variables it inherited. When an urgent post addresses the
  poster's own node and no session of that node can be woken, `vox room post` MUST say so in one
  line, and that each session reads the message at its next turn. It speaks only for the poster's
  node.
- **6.13 (F17).** Vox's OpenCode plugin MUST own the wake channel: a Unix socket in a private
  (`0700`) directory with a random token, whose path and token it passes only to `vox agent hook`
  (`VOX_OPENCODE_WAKE_SOCKET`, `_TOKEN`). The plugin MUST NOT abort a running turn to deliver.
- **6.14** The wake channel MUST be registered by the drain hook as a side effect of each turn,
  never configured by the operator.

### 7. The node fans out to many local clients, none able to stall it

- **7.1** The actor MUST hold a broadcast sender directly (`EVENT_QUEUE` = 256). Emission MUST NOT
  block or await (M19.1a).
- **7.2** A lagging subscriber MUST be told it lagged (`Lagged(n)`). Lag is not an error; it means
  "re-read the log from your cursor".
- **7.3** A burst larger than the buffer drops for every subscriber, so no client MAY treat the
  event stream as complete. The per-client cursor is the source of truth.
- **7.4** The control socket MUST be a Unix domain socket at `<profile_dir>/node.sock` with mode
  `0600`, carrying length-delimited canonical CBOR frames, one task per connection (M19.1b). Its
  only authentication is the file mode: it MUST NOT be described as a security boundary (the OS
  account is the boundary). A request that changes the trust keyring MUST be gated as 3.1 says.
  *Decided, not built (ADR-026 C-1–C-3):* one socket per account, `<data root>/.daemon/vox.sock`,
  peer-uid checked and never admitting uid 0. A client names its node once per connection with an
  opening `Use { node }` frame, resolved as ADR-026 C-3 says.
- **7.5** A cursor belongs to the reader of the log (§4, ADR-021 §7), not to the event transport.
- **7.6** The protocol MUST be versioned (`PROTOCOL_VERSION`, now 8) and grow by additive requests.
  *Decided, not built (ADR-026 C-2, C-4):* version 9 adds the per-connection `Use { node }` frame,
  daemon requests and daemon events (attach, detach). There is no lock or unlock (ADR-026 N-2).
  The app API (`AppListen`, `AppAccept`, `AppOpen`; ADR-022 M22.5) rides the same socket.
- **7.7 (PRD-001 R35, R38).** The socket MUST answer a status request (tag 2301) with the node's
  report as JSON: rooms with each member's last-seen and last-sync time and the room's last
  completed sync; peers with their path (`direct` or `relayed`, and which relay) and RTT; tunnels;
  datagram and app counters; and the lines that need attention (a room with other members and no
  completed sync in 10 minutes; a trusted member that was connected and no longer is). `vox status`
  prints it (`--json` verbatim). `vox daemon --metrics <addr>` serves it as Prometheus text and MUST
  refuse a non-loopback address. The report cannot say whether a room has an always-on member, nor
  whether a direct path was dialled or hole-punched, and it MUST say so. *Decided, not built
  (ADR-026):* the report is per node, metrics carry a `node=` label, and the daemon has its own
  status (attached nodes, port, mapping).
- **7.8 (PRD-001 R37).** A running `vox daemon` MUST check its status every 5 s and raise a desktop
  notification when an unhealthy condition starts and when it clears, never again while it holds,
  keyed by a stable condition key (`peer-unreachable:<room>:<peer>`, `room-stale:<room>`); the
  stale-sync rule counts from the node's start for a room not yet synced. Delivery:
  `VOX_NOTIFY_COMMAND <title> <body>` when set, else `osascript` on macOS, `notify-send` on Linux
  when installed, and always a line on stderr. `notify = off` in the profile's `config` turns it off
  (under ADR-026, per node, for each attached node).
  The `osascript` and `notify-send` paths are exercised by no proof, since no test can see a
  desktop. Phone push is out of scope.

### 8. The agent-facing surface is a CLI plus a skill

- **8.1 (M19.4).** Agents MUST be served by CLI verbs: `vox room post` (body on stdin), `read --since`,
  `tail`, `roster`, `list`, `board`, `claim`, `release`, `handoff`, `decline`, `renew`, `send`,
  `get`, `leave` (V210-164), together with a skill carrying §4's and §5's conventions and ADR-021
  §3's meanings. No `wait` verb (the drain does it) and no `say` verb (`post` is `say`) MUST be
  added.
- **8.2** `vox agent skill` MUST print the skill, and `vox agent plugin claude|codex|opencode` MUST
  print each harness's integration (hook entries, or OpenCode's plugin file) with where it goes on
  stderr. Vox MUST provide the agent text in the form each harness loads and say where it goes
  (V210-166).
- **8.3** An MCP server MAY be added later. Not built.
- **8.4 (M19.10).** Every `vox` verb and flag the shipped skill names MUST exist in the CLI
  (`skill_cli_proof`).
- **8.5 (M19.11).** `vox agent trust codex` MUST grant Codex's hook trust for Vox's own entries the
  way Codex's "trust all" does (app-server `hooks/list`, then `config/batchWrite` of
  `trusted_hash`), and re-grant it when the entry changes. "Vox's entry" MUST be an exact grammar:
  bare `vox` or, as written and never resolved, the canonical path of this binary; then `agent
  hook`; then only `--room`, `--session`, `--profile` (plain values) and `--format`; no shell
  metacharacter. `--data-dir`/`--config-dir` MUST be refused. Another tool's entry, and an entry
  tampered into anything else, MUST be left untrusted. Not proved: that a trusted hook then fires in
  a live Codex turn (#169). *Decided, not built (ADR-026):* `--node` replaces `--profile` in this
  grammar, and is required.

### 9. Flood and loop control

- **9.1** An agent MUST NOT reply to a message unless addressed in `to` or asked. An agent MUST NOT
  auto-reply to `status`, `hello`, `bye` or `ack`. (Skill conventions.)
- **9.2** A terminal acknowledgement MUST NOT generate another.
- **9.3** `hops` MUST default to 8, MUST be decremented on relay and the message dropped at zero.
  Vox relays no message; what is built is a budget along the `re` chain: a reply's budget is at most
  its parent's less one, its grandparent's less two, and so on (`hops_left`), and a message with no
  hops left wakes and is announced to nobody; it is still read at the next turn.
- **9.4 (V210-121).** A session's structured post right after a wake MUST answer the message that
  woke it when exactly one such wake is unanswered (an explicit `--re` wins). An urgent post with two
  or more unanswered MUST be refused until it names one. A raw urgent envelope with no `re` from a
  session with an unanswered wake MUST be refused. The daemon MUST NOT wake a session that already
  spoke in the `re` chain the message answers; the message still queues. An explicit `--re` naming
  an unrelated old entry is not prevented.
- **9.5** Identical repeats from one `(author, session)` within a short window MAY be dropped.
  There MUST be no rate cap: the per-author rate quota is removed (PRD-001 R3).
- **9.6** Text another party wrote MUST be shown on one line where Vox prints it as a field, with
  control characters, line separators and bidi controls removed (V210-123).
- **9.7** A `status` SHOULD supersede the previous `status` from the same `(author, session,
  thread)` in a rendered view. **Not built.**

### 10. Trust is not delegated, inherited or transitive

- **10.1** Vox MUST NOT let one identity vouch for, own or stand for others in granting read
  access. Every reader is admitted by fingerprint, one at a time (§3).
- **10.2** Vox MUST NOT use attestation to label a participant as a machine; the petname recorded
  at trust time says what it is.

### 11. A file is exchanged over a room-bound service, not through the log

- **11.1 (M19.8).** File exchange MUST use a room-bound service (ADR-013, ADR-017). File bytes MUST NOT enter
  the log. `StructTag::ChunkManifest` (`0x000A`) remains reserved and unimplemented; agent comms adds
  no struct tag or codec.
- **11.2** The default direction is push (receiver listens, sender connects); sender-serves is the
  variant, for an artefact several agents want or an absent agent collects later. Built: `vox room
  send` and `vox share` serve from the sender and the receiver pulls (PRD-001 R18).
- **11.3** The sender MUST post an announcement carrying the name, the size, the SHA-256 and the
  service tag in `data`.
- **11.4** A receiver MUST verify the bytes against the announced SHA-256 and size before the file
  is usable. A transfer that stalls (30 s per read), sends more than announced, or does not match
  MUST leave nothing behind.
- **11.5 (PRD-001 R18, D4).** Where the file lands is the receiver's decision. `vox room get` MUST
  write to `--out`, else `--dir`, else the profile's `downloads` file (under ADR-026, the node's
  `config`), else `downloads = <dir>` in its `config`, else `~/Downloads`, under the announced name reduced to its last component (leading
  dots and characters a filesystem treats specially removed). It MUST NOT overwrite anything: a
  taken name gets ` (1)`, ` (2)` …, and an existing `--out` is refused. Bytes go to a hidden `.part`
  file and are linked into place only after the hash and size match.
- **11.6** `vox share <room> <file|dir> [--count N] [--for D]` MUST serve the file over HTTP on a
  room-bound service whose port and tag derive from the content hash, announcing `http: true`. A
  folder MUST be served as one deterministic tar (sorted, zero timestamps). The share ends after
  `--count` completed fetches, after `--for`, or on ^C.
- **11.7** Reach MUST be gated on the offering node's keyring, as is reading the announcement, so
  the audience of the announcement is the audience of the transfer. No per-transfer grant is
  minted. The predicate is one-sided: the offerer's keyring.
- **11.8** The announcement is durable; the bytes are live. A late collector MAY find the offer
  gone and MUST be told so.

### 12. Agents attach to a node that runs without a terminal

- **12.1** `vox daemon` MUST exist: a headless, room-holding, unlocked node that takes the
  passphrase once at start, holds the profile's rooms, binds §7's socket and runs until stopped
  (M19.5c). It MUST NOT lock on SIGHUP; SIGHUP stops it cleanly (ADR-016 NR-15). It is the node
  `vox room` and `vox agent hook` attach to.
- **12.2** *Decided, not built (ADR-026):* `vox daemon` is the account's one daemon, not a node. It
  takes no passphrase at start; nodes attach to it (by hand, implicitly from a request or a hook, or
  from its `--keep` list) and all run concurrently. `vox room` and `vox agent hook` are its clients
  and act as the node they name. 12.1 is replaced when this is built.

### Non-goals

Agent comms MUST NOT be or add: a mirror of agent activity (tool calls, progress, per-turn
chatter); a replacement for ctm (moving ctm onto Vox is the chat app's concern); a wire-format
change; per-session cryptographic identity; central coordination (orchestrator, speaker selection,
trust score); IP-level anonymity (ADR-017); an MCP delivery path; file bytes in the log; a spawned
instance of anything (1.5); a council feature (a council is an `ask` in a room whose agents span
model families); an operator hold on messages (trust and room membership are the controls); hosted
agent sandboxes that allow only HTTP out. A TUI view for agent comms is deferred until a real room
has shown what needs filtering.

## Consequences

- Two agents on different machines behind different NATs coordinate with no SSH tunnels and no
  pairwise configuration; the room and ADR-012's ladder replace both.
- Trust is established once per node and covers every future room shared with it. The keyring is
  the blast radius: the only controls are removing a key or M18.1 revocation.
- An agent that dies catches up from its cursor, because the log is durable.
- §7 constrains every future event emitter to non-blocking emission.
- Harness integration tracks moving targets (Codex's app-server, OpenCode's undocumented plugin
  API).
- Room readability rests on the skill's conventions, not on mechanism.
- Golden wire-byte vectors remain unmet by decision (ADR-018).

## Related ADRs

- [ADR-001](ADR-001-vox-foundation-vision-threat-model-and-principles.md) — principles.
- [ADR-007](ADR-007-membership-consent-and-admin-governance.md) — per-sender consent, which §3 drives.
- [ADR-008](ADR-008-replicated-authenticated-log-and-sync.md) — the log: inbox, message id,
  tie-break key.
- [ADR-012](ADR-012-nat-traversal-and-reachability.md) — reachability, relays, anchors.
- [ADR-013](ADR-013-overlay-tunneling.md), [ADR-017](ADR-017-room-bound-services.md) — room-bound
  services (§11).
- [ADR-016](ADR-016-node-runtime.md) — the node runtime, the daemon and M18.1 revocation.
- [ADR-018](ADR-018-quality-bar-and-product-proof.md) — product proof.
- [ADR-021](ADR-021-work-item-interop.md) — the claim protocol, work references and the adapter
  stream.
- [ADR-022](ADR-022-datagram-flows.md) — the app API on the control socket.

## Engineering Mantra

Need it? No → out of scope, don't even think about it. Yes → is it possible? Possible → DO it. Not
possible → exhaustive research to make it possible. Anything short of that is a mantra violation.
