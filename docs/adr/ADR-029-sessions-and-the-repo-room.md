# ADR-029: Sessions, and the Room a Session Works In

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted for v0.4.0 (the decider, 2026-10-06); ST-4 added for v0.4.11
(the decider, 2026-10-30). Acceptance of a requirement is not implementation evidence.
**Date**: 2026-10-06
**Deciders**: Robert E. Lee
**Tags**: sessions, agents, rooms, drive, setup, tui, macos
**Related**: ADR-001, ADR-007, ADR-008, ADR-020, ADR-021, ADR-026, ADR-028
**Inputs**: the decider's product Q&A of 2026-10-05 and 2026-10-06
([docs/ux/v040-ux-interview-decisions.md](../ux/v040-ux-interview-decisions.md), "Sessions");
the claude-telegram-mirror (ctm) design it learns from: one Telegram topic per harness session,
both surfaces live (its ADR-015), membership not mutation (its ADR-016), refuse rather than guess
(its ROUTING-001), end only on a real `SessionEnd`.

## Context

A node is one harness on one computer (ADR-020 2.1). One node often runs several harness sessions
at once: two Codex sessions on one machine are one node, `codex@device-2`, and two participants.
A session holds no key and is a record its node announces (ADR-020 2.2). Today a message can name
only a node, a wake goes to any session of that node, and nothing lets the person follow or steer
one session from another device.

The decider's working shape: one room per repository, where every node with a session on that
repository talks about the work; inside it, a **Session** per harness session, where the person
can follow that one session and drive it from the TUI or the app, as ctm does from a phone. A
Session is to a room what a forum topic is to a Telegram group. This ADR adds the Session to
rooms, nodes, trust and services; it adds no other concept. The keyring capability **drive** it
relies on is ADR-028 K-14.

## Requirements

### 1. A Session

- **SE-1.** A Session MUST exist in a room for each interactive harness session working in that
  room, created when the daemon registers the session (ADR-020 6.10), whether or not it has posted
  a `hello`. A headless run
  (`claude -p`, `codex exec`, a non-interactive OpenCode run) MUST NOT get one.
  Registration is accepted once its record and room binding are durable; its hook response MUST
  NOT wait for room history, Session projection or attention readiness. The daemon MUST coalesce
  repeated hooks into one idempotent opening attempt per registered Session, cancel an attempt
  whose registration ends or moves, and reconstruct unfinished openings from the durable
  registrations whenever the node becomes Ready after daemon restart. A bounded attempt that
  finds governance, controls, floors or Session projection still refreshing MUST continue from
  that same durable obligation; its deadline MUST NOT turn transient readiness into abandonment.
  A permanent detached opening failure MUST be logged and told to that Session on its next hook
  before a new attempt starts.
  A Session's opening record MUST precede its activity in the author's drive chain. Activity that
  arrives while the opening is still being retried MUST stay queued and be sealed only once the
  opening is the author's own fact: a reader takes the chain in order and cannot place activity
  whose Session it has not seen, so activity sealed first stalled every reader with drive on that
  record for good (measured 2026-10-19: the reader asked for the same page 71 times in 120 s and
  never listed the Session).
- **SE-2.** A Session's identity MUST be the harness's own session id (Claude Code's
  `session_id`, Codex's thread id, OpenCode's `ses_…` id); Vox MUST NOT mint one. A sub-agent's
  activity MUST belong to its parent's Session, never a Session of its own: each of its entries
  MUST be labelled with the sub-agent's type, its completion MUST be shown with its result on
  request (Details), and it ends when its parent does, as ctm does. A message a sub-agent posts
  MUST carry its parent's session id in `from` (MD-1).
- **SE-3.** A Session MUST be labelled with the viewer's alias for its node (ADR-028 K-3), the
  session's current name (§5 MD-1) and the session's short id (the first 8 characters of its id),
  for example
  `codex@device-2 · gso-cap · 3f0c25bf`.
- **SE-4.** A Session MUST end only on the harness's real end: the hook's `SessionEnd`, which
  unregisters the session (ADR-020 6.10). *Amended 2026-11-13 by ADR-041:* For OMP, the end of its
  process, found as ADR-041 RS-8 says (its watcher's lifetime lock free and its wake endpoint
  refusing, twice), is also the harness's real end; the end is posted once, however many times the
  daemon restarts. A `SessionEnd` whose reason is `resume`, or a resumed
  session id, MUST keep the Session open.
- **SE-5.** An ended Session MUST be closed and moved out of the person's way (shown apart from
  open Sessions, like an archived conversation). Its content MUST NOT be deleted when the session
  ends: it follows the room's retention (ADR-010 AR-28, AR-29), as the room's own messages do.
  *Amended by ADR-031 SA-9 (the decider, 2026-10-10):* a Session's steps follow the room's
  Session-step retention, by default 7 days or the room's message retention, whichever is shorter.
- **SE-6.** A Session MUST belong to exactly one room, the room its session works in (§6). When a
  session moves room (RB-5), its Session in the old room MUST end as in SE-5 and a new Session MUST
  begin in the new room.

### 2. What a Session carries, and who sees it

- **SC-1.** A Session MUST carry the session's activity: each tool call with a summary of its input
  and output of at most one line each, and its full input and output, shown on request (Details);
  the session's replies; the end of each turn; tool approval requests and their outcome; the
  session's own questions and their answers; and the files sent either way (§3 DR-1). Content
  longer than the log's text limit (ADR-020 4.1) MUST be split across entries. File bytes MUST NOT
  enter the log: a file travels as a share addressed to its receiver (ADR-028 §5).
  *Amended by ADR-031 SA-7 (the decider, 2026-10-10):* these steps are sent, synced and stored only
  on the session's node and the members it trusts with drive; a member without drive never
  receives them.
- **SC-2.** A Session's content MUST be readable only by members of the room whom the session's
  node trusts with **drive** (ADR-028 K-14). Its entries MUST be sealed under a Session key that
  the session's node holds and releases only to those members, each release caused by a keyring
  entry carrying drive (ADR-020 3.3); the session itself holds no key (ADR-020 2.2). A member the
  node trusts with read only MUST NOT be able to read it.
- **SC-2a.** The node MUST release the Session key to a member with drive when that member is
  admitted to the room or gains drive, whichever is later, retrying on the tick (ADR-020 3.2). A
  member reads the Session from that release onward, as ADR-006's forward-only rule does for
  messages. *Amended by ADR-031 SA-8 (the decider, 2026-10-10):* a joining node gets a Session's
  steps only from the later of its join and its gaining drive; no earlier step is sent to it. Once
  an addressed release body is durably cataloged by its recipient, key installation MUST become
  runnable from that publication itself; a best-effort display/event wake is not the obligation,
  and daemon restart MUST recover an uninstalled catalog entry from the room.
- **SC-2b.** When a member loses drive (downgraded to read, or untrusted), the node MUST rotate the
  Session key and release the new one only to the members that still have drive, as ADR-020 3.6
  does for the sender key. The member keeps what it already read and reads nothing sealed
  afterwards.
- **SC-3.** Every other member MUST see only that the Session exists: its label (SE-3) and whether
  it is open or ended.
- **SC-4.** The room's own timeline MUST NOT show a session's activity (ADR-028 W-6 as amended):
  activity lives only in its Session.

### 3. Driving a Session

- **DR-1.** A member the session's node trusts with drive MUST be able, from the TUI and the app:
  1. to read the Session (SC-1), with Details. One read MUST show the whole current turn, from
     its prompt to its end, whatever the size of a tool output in it: a page is bounded by the
     IPC frame, and the reader follows older pages until the turn's prompt is in hand (a bounded
     number of pages); what lies before the turn is what it counts as older. Measured
     2026-10-19: one 216 KB tool output pushed a turn's prompt and the call that made it off the
     page a person read first, on v0.4.5 as well;
  2. to type into the session as its operator;
  3. to interrupt it (Esc) and to stop it (Ctrl-C);
  4. to approve or reject its tool calls;
  5. to answer its questions;
  6. to send it a slash command (`/compact`, `/clear`, `/rename`);
  7. to send it a file or an image;
  8. to receive files it sends.
- **DR-2.** A node MUST be able to drive only Sessions in rooms it is a member of, and only those of
  nodes that trust it with drive.
- **DR-3.** Both surfaces MUST stay live: the harness's own terminal keeps working, an approval or
  a question MUST render in both the terminal and the Session, and either side MAY answer.
- **DR-4.** The first answer MUST win, decided by the harness's own resolution event, never by a
  send having succeeded; the other surface MUST then show the request as answered elsewhere.
- **DR-5.** Driving input MUST reach exactly the session the Session belongs to. When Vox cannot
  establish where that session is, it MUST refuse and say why; it MUST NOT guess a target.
- **DR-6.** A failed delivery MUST be reported to the driver every time, naming what failed.
- **DR-7.** Driving MUST NOT start a harness or a model run: a Session drives only a session a
  person already opened (ADR-020 1.5). Driving an open Codex session MAY use the app-server's
  `turn/start` and `turn/steer` (ADR-020 6.12 as amended); a wake MUST NOT.
- **DR-8.** The first version MUST NOT offer muting a Session or switching its mirror off.

### 4. Talking to a session

- **TA-1.** Talking is not driving. Any member the session's node trusts with read, and any other
  session of the same node, MAY address a message to one session: a `to` entry MAY name
  `<whole fingerprint>/<session id>` (ADR-020 4.6 as amended).
- **TA-2.** A message addressed to a session MUST be shown in full in that session's per-turn read
  (ADR-020 6.6), attributed to the sending node and its session (§5), as a message from another
  participant, never as the operator's input. The node's other sessions MUST count it as room traffic and
  MUST NOT show it in full.
- **TA-3.** An urgent message addressed to a session MAY wake it, announce-only (ADR-020 6.2):
  waking is talking ("yo, let's chat"). Interrupting a session mid-task is driving (DR-1.3).
- **TA-4.** A message addressed to a node, without a session, MUST reach every session of that
  node working in the room.
- **TA-5.** A message addressed to a session that has ended MUST be refused, and the sender told
  that the session has ended; it MUST NOT be delivered to another session of the node.

### 5. Session metadata on every message

- **MD-1.** Every message posted from a harness session MUST carry the session's id (`from`,
  ADR-020 4.2) and, when the harness gives one, its current name in `at.session_name` (ADR-020 4.9
  as amended). The name is the harness's own session name (Claude Code's `/rename` title, Codex's
  thread name, OpenCode's session title); when the harness gives none, the field MUST be absent and
  clients MUST show the short id (SE-3).
- **MD-2.** Vox's hook and verbs MUST fill these fields, whatever verb posts; the model MUST NOT be
  relied on to supply them.
- **MD-3.** The session id and name are claimed by the node, not proven (ADR-020 2.3). Clients
  MUST show them as the node's claim beside the proven node identity.

### 6. The room a session works in

- **RB-1.** Each data root (ADR-026 D-1; normally one per OS account) MUST have one room map,
  `<data root>/rooms`, mode `0600`, read by every node of that data root, in the style of
  `~/.ssh/config`:

  ```
  repo /opt/vox
      room       <room link>
      passphrase <room passphrase>
  ```

  `room` and `passphrase` MUST be separate fields; the passphrase MUST NOT be part of the link
  (ADR-005). A block whose `room` is `none` records that the operator said no to binding
  that directory (RB-7), and holds no passphrase. Every node of the data root can read every passphrase in the map, so any of them can
  join any mapped room; whatever writes the map (setup, `vox agent room`) MUST say so (ADR-028 E-5).
- **RB-2.** When a harness session starts, its node's hook MUST look up the session's start
  directory in the room map, and the session MUST work by the deepest block whose `repo` is that
  directory or one above it: a session started in `/opt/vox/crates` works by `/opt/vox`'s block
  unless `/opt/vox/crates` has its own. A start directory inside a linked git worktree MUST first
  be looked up within the worktree (a block for the worktree, or for a folder in it, wins), then as
  the same place in the worktree's main repository, found from the worktree's `.git` file and its
  `commondir`. A `none` block found this way MUST mean none (RB-7). Writing the map (`--bind`, a
  no) names exactly the directory given.
- **RB-3.** On a match, the node MUST join the room if it is not a member (ADR-005 J-1 with the
  map's link and passphrase), and the session MUST work in that room.
- **RB-4.** A session's room MUST NOT change during the session's life because of where it works
  afterwards: new branches, worktrees, or reading or editing other repositories' files do not move
  it.
- **RB-5.** With no match, the session MUST work in no room. There MUST be one ask, made in two
  places (RB-5a): Vox asks the operator itself, and on the session's first turn the hook MUST tell
  the agent, once, that its repository is not tied to a Vox room, that Vox has asked the operator,
  and to say so to the operator once, in one sentence: "This repo isn't tied to a Vox room. Vox has
  asked you in its app; you can also paste its room link here, or say no." The agent MUST NOT ask
  again on later turns. The operator MAY answer in the session; the hook MUST tell the agent what to
  do with a link or a no given there (RB-6, RB-7). `vox agent room <room>`, run later, MUST move the
  session to that room; a session MUST work in one room at a time.
- **RB-5a.** Every registered interactive session that works in no room, started in a directory
  the room map does not name, MUST raise an ask for the operator, one per directory, naming the
  harness and the directory ("Claude Code in /opt/vox has no room"). Vox.app MUST show it as a
  banner across its window, with "Choose a room…" (a room the operator's node holds, or a pasted
  link, and the room's passphrase typed in the app) and "Not this repo", and post one notification
  for it; the TUI and `vox agent status` MUST show it with the commands that answer it at a
  terminal. Choosing a room MUST do what RB-6's `--bind` does, and MUST also put every session
  waiting in that directory in the room; "Not this repo" MUST record a no as RB-7 does. The ask
  MUST end when the directory is bound or declined, or when no session there works in no room.
- **RB-6.** A link is bound by the operator, never by the agent: the agent MUST NOT ask for, and
  the operator MUST NOT be asked to give, the room's passphrase in the session. The agent MUST give
  the operator the command to run in a terminal of their own, `vox room join <link> --node <the
  agent's node> --bind <the start directory>`, which asks for the passphrase there, joins the
  agent's node, and writes the directory's block to the room map with that link and passphrase,
  saying first who can read the map (ADR-028 E-5). The agent MUST give that command with its node
  and the absolute directory filled in, and the link the operator pasted, so it can be run as it
  stands. A block the map held for that directory, a no or another room, MUST be replaced, and the
  command MUST say what it replaced. Every later session started in that directory,
  from any harness, MUST then work in that room (RB-2, RB-3). Binding needs no identity passphrase
  and changes no trust (ADR-028 K-13). The agent then puts its running session in the room with
  `vox agent room <room>`.
- **RB-7.** A no MUST be recorded for that directory, as a block whose `room` is `none`
  (`vox agent room --none`, which the agent may run: it holds no secret), and a session started
  there MUST NOT be asked again. The operator removes the block to be asked again; a later `--bind`
  replaces it.

(The decider, 2026-10-08: "if I start a session in claude/codex/opencode etc. in a repo, and we
don't have the configuration set up yet where the repo is tied to a room, ask if there's a room
url/link for it to bind to"; the passphrase is typed by the operator in another shell.)
(RB-2's deepest-block and worktree matching: the lead's ruling, 2026-10-10, under the decider's
delegation, v0.4.3 #671; it replaced the exact match, which asked again in every subfolder and
worktree of a bound repo.)
(The decider, 2026-10-10, v0.4.3 #671: an agent that did not relay the ask left the operator never
knowing, so Vox asks the operator itself, and the operator may still answer in the session: "let
me specify one if not".)

### 7. Setting up a machine

- **ST-1.** `vox setup` MUST detect the harnesses installed on the machine (Claude Code, Codex,
  OpenCode) and offer to create one node per harness (`<harness>-<host>`, ADR-026 N-6), each with a
  passphrase the operator types (ADR-028 K-11), and to install its hooks.
- **ST-2.** On macOS, setup MUST offer to create a node for the person, and it MUST be optional
  (on iOS, with its app, v0.5.0).
- **ST-3.** Setup MUST end by printing, for every node it created, its fingerprint (grouped, with
  its art, ADR-028 K-1) with the facts a person needs to recognise it: alias, harness, host, OS and
  Vox version.
- **ST-4.** Oh My Pi MUST be a first-class harness peer of Claude Code, Codex and OpenCode:
  setup, installation, diagnostics, room binding, real session identity and lifecycle, activity
  publication, discovery and authorized Session interaction MUST cover it, not merely rename
  another harness's messages. Integration MUST use Oh My Pi's actual supported session and
  extension contracts and MUST NOT require changes to Oh My Pi itself: Vox does not control
  that repository and it changes often. The OMP source is a reference for how the runtime
  actually behaves, never a place to add an API (operator ruling, 2026-11-07). In particular, eligible
  urgent room messages MUST reach the intended
  already-running Oh My Pi session through native message delivery, without tmux or simulated
  terminal input. Normal room attention MUST retain its existing read/addressing authorization;
  private Session content and driving MUST retain their separate drive authorization. Session
  switches and restarts MUST NOT send a message to the wrong session. Delivery reporting MUST
  distinguish acceptance or queueing from observed consumption or a reply, and MUST NOT advertise
  a control capability the native harness cannot perform. Research MUST include Oh My Pi's IRC
  implementation without assuming that its in-process bus is an external transport API.


### 8. In the TUI and the app

- **CL-1.** The TUI and the app MUST present Sessions the same way, with the same steps and words
  (ADR-028 E-1).
- **CL-2.** A room MUST list its Sessions beside the room's own conversation, as a group lists its
  topics: the room's conversation (**General**); **All**, which merges in time order the room's
  conversation, each Session's opening and end, and, for a member with drive, those Sessions'
  entries; and one entry per open Session, with ended Sessions apart (SE-5). For a member with
  drive, a Session waiting on it (an approval or a question pending) MUST count under **needs you**
  (ADR-028 W-2 as amended).
- **CL-3.** A member without drive MUST see a Session's entry (SC-3) and MUST NOT be offered any
  driving action on it. A room's Session listing therefore names every member's Sessions, and
  each row's `can_drive` says whether this node holds that member's drive key; listing only the
  members whose key it held made a Session vanish from the list the moment its node took drive
  back, instead of saying `can_drive: false` (measured 2026-10-19, on v0.4.5 as well).

## v0.4.20 amendments — design status by scope, not built

The operator selected these product outcomes. Independent Opus review of `37b0ffbf4` approved
P420-RB-1–5, P420-OD-1–4 and P420-OP-1–4 at design level; implementation, consumer acceptance
and publication are not approved. P420-OR's scoped design approvals and the additional
source-discovered transition prerequisite are recorded in the review documents.
Existing node identity, membership, read and Drive safeguards remain required. Repository
replacement narrows agent `--none` permission. ST-4's no-OMP-change rule is unchanged.

### Repository decision and deliberate rebind

- **P420-RB-1.** A bound repository ask MUST offer an explicit operator-confirmed “Not This
  Repo”, including after a failed Join It. Failure alone MUST NOT alter the map, room membership,
  trust or history. Confirmation MUST identify the actual repository, resolved binding and
  affected scope, including inheritance and overrides; say that future sessions across the data
  root's nodes and harnesses use `room none`, existing sessions do not move, no room is left or
  trust changed, and an exactly replaced block's saved link and passphrase are discarded and
  needed again to rebind. Cancel changes nothing. Never show or log the credential.
- **P420-RB-2.** An exact repository binding is replaced by the canonical `room none` block.
  For a binding inherited from a parent outside the actual repository, derive and validate the
  repository boundary from the registered start independently of the displayed source block,
  including linked-worktree mapping, and place a more-specific `none` there; do not replace the
  parent. Split asks grouped under a parent by actual decision boundary. Sibling repositories,
  parent credentials and explicit more-specific repository or worktree overrides remain effective.
  If the boundary or effective scope is ambiguous, stale or invalid, refuse and explain; do not
  choose a parent or arbitrary subdirectory. The operator may then choose an unambiguous valid
  repository through the deliberate rebind surface.
- **P420-RB-3.** Replacement is a distinct operator action, not a broadening of agent decline.
  An agent's `vox agent room --none` MAY record a no for an unbound scope but MUST NOT replace an
  operator binding or shadow any resolved inherited binding. Check this against the effective map
  atomically. Replacement CLI entry points MUST reject agent-marked callers, including malformed
  nonempty harness marks. The native action and operator CLI use a distinct replacement daemon
  verb behind the existing mode-0600, uid-checked local control socket. The OS account remains
  the authorization boundary (ADR-026 C-1/C-6), not person attestation or a new grant ceremony.
  Ordinary agent-facing decline does not gain replacement authority. This does not claim to
  isolate an arbitrary malicious process already running as the same OS user.
- **P420-RB-4.** The displayed decision MUST carry an opaque non-secret snapshot of the
  registered target boundary, effective source block and target override, detecting even a
  credential change for the same room. A lost snapshot or restart is stale. Under one data-root
  interprocess writer lock, every Vox map writer MUST re-read, validate and re-resolve the map,
  compare the displayed snapshot and applicable override, and either report conflict and refresh
  or construct one whole-map replacement preserving unrelated blocks, comments and credentials.
  Use a unique private mode-0600 temporary file, flush and atomically replace using durable-write
  conventions; do not expose a transient missing block. Compare again before replacement for
  detectable outside edits; an advisory lock cannot serialize arbitrary noncooperating editors.
  Report failure truthfully; if rename succeeded but durability is uncertain, re-read and report
  uncertainty, not a false unchanged or durable-success claim. Never expose secret map text or a
  guessable password-derived digest in the snapshot, IPC, UI or logs.
- **P420-RB-5.** Vox.app MUST offer deliberate repository rebind independent of a pending ask:
  choose a directory, show its resolved decision and precise scope, choose a room or link, enter
  its passphrase in the app and explain who can read it. Authenticate even a held room's
  credential and perform required joins before the same stale-safe map replacement. Bad
  credentials, stale scope, unavailable node or failed write MUST NOT erase the no; report any
  actual partial joins. The operator's existing terminal `--bind` remains available and uses
  the same transaction. Rebinding changes future selection, not running sessions; existing
  explicit session moves and documented ask-answer moves remain separate.

### OMP registration and recovery

- **P420-OR-1.** Registration belongs to the exact live OMP TUI main-session generation and
  authenticated bridge route, not to a process-wide success flag. Track unregistered, pending,
  registered and actionable failure for that generation. The existing registration-only child
  exit 0, still in the captured generation and `current()` at close, is its receipt: that mode
  succeeds only after actual non-Attaching SessionRegistered. No new success ACK format is
  required, but the typed retryable daemon refusal in OR-5 is required. Ordinary hook success,
  staging, attaching, missing node, timeout, EOF or a listening bridge is not registration.
  Capture bounded sanitized child stderr without credentials, route tokens or private content.
  Registration-only exits MUST distinguish transient unavailability from permanent identity,
  route, permission, incompatible protocol or obsolete extension refusal without parsing prose.
  Exit 0 retains its existing receipt meaning; use a distinct documented nonzero temporary
  category (75) versus permanent failure (1), preserving other existing exit categories.
- **P420-OR-2.** On activation and for each real prompt (at its first `context`), or other registration-dependent
  use, reconcile the live manager; if its generation is not registered, invoke the existing
  register-only child once, coalescing concurrent callers, then recheck the fence. A confirmed
  pre-envelope missing-registration failure returns that generation to unregistered. Capture
  errors and keep ordinary OMP usable. No blind five-attempt loop, automatic attach/unlock,
  credential retention or unnecessary receipt/subscription framework is required.
  Idle urgent-attention recovery after initial daemon/node failure is required by ST-4:
  use P420-OR-5's bounded native availability bridge and mutation-time route ownership,
  not an assumed external Subscribe stream or another model prompt.
- **P420-OR-3.** Preserve transition fences and route authentication. A stale completion cannot
  revive an old route, register a newer generation or overwrite its state. A cancelled or
  rolled-back switch MUST reconcile the live manager and retire a provisional target, even if
  OMP emits no compensating event. Preserve native marker, exact registration, harness, room and
  trust checks; do not borrow an ID, replay a failed post, or claim it succeeded. A later
  user-requested post uses the verified current native identity.
- **P420-OR-4.** A prepare child closing before any envelope or injection MUST be distinguished
  from genuinely ambiguous delivery. A transient pre-envelope failure MUST NOT permanently
  poison later legitimate use: recover only after a matching current registration receipt.
  Ambiguous delivery remains fail-closed; never clear it blindly or replay potentially delivered
  context. Repeated failures remain bounded and visible rather than silently disabling Vox.
- **P420-OR-5. Idle availability and native ownership.** One narrowly scoped Vox CLI watcher
  belongs to each native extension instance for its process lifetime, not to each generation.
  It does not register, autostart, attach/unlock, read rooms or call a model. It holds a
  persistent Subscribe connection only while the exact selected node is Attached and Ready.
  When absent, detached, attaching, detaching or locked it closes persistent connections and
  uses bounded short-lived authenticated hello probes with capped 1/2/4/8/16/30-second
  backoff, so the daemon's one-second autostart linger can expire. Never issue Nodes or
  Status: those operations can attach nodes. Attached implies Ready in the current host.
  On apparent Ready, Subscribe and receive its acknowledgment before opening a separate
  fresh hello connection for the final exact-fingerprint attached snapshot. The subscription
  connection's earlier hello is not final proof. Reconcile intervening events and resnapshot;
  while subscribed, resnapshot on relevant events and at most once per 30 seconds for lag
  recovery. Limit connections, handshakes, frames, stderr and in-flight work; stdin EOF ends
  the watcher. No room/model polling or generic retry framework. A detached passphrase-free
  node stays detached, including after manual detach, and unrelated node failures do not
  block the selected node's observation.
  A Ready observation triggers a coalesced register only for an unconfirmed current generation.
  A typed transient registration failure permits retry after a fresh successful Ready snapshot
  at capped pace even in steady Ready. Confirmation stops retry; permanent refusal remains
  visible without a respawn loop. No operator prompt is needed for transient recovery.
  Same-generation retry is idempotent for the exact node/session/route, not message replay.

  Add a small typed daemon retryable registration refusal carrying a fixed reason enum, for
  initial and deferred writes. Classify NoNode, Attaching, Unanswered, NoDaemon, timeout,
  StillDetaching, registration-lock busy and Session ending as temporary; wrong identity,
  route, permission or incompatible protocol are permanent. Never parse prose-only `Failed`.
  This control IPC change requires protocol 10 → 11 (`node/ipc.rs:78`); retain the existing
  version-independent updater bootstrap, without bypassing version checks. The registration
  CLI maps typed results to OR-1 exit categories.
  A watcher's first handshake version/protocol mismatch invalidates the observation and
  exits with a distinct fixed category. The extension drains and retires it, then at capped
  pace resolves the current configured Vox binary and starts at most one successor for that
  mismatch episode. If the successor also mismatches, it stays alive as lifetime owner,
  reports a fixed unavailable/mismatch category and visible update guidance, and continues
  capped short authenticated-hello observations without reporting Ready or permitting writes.
  No replacement loop or handshake bypass is allowed. Observe daemon pid/version before
  the strict compatibility check; the first fully successful handshake resumes normal
  availability observation and ends the mismatch episode. Later updates get a new bounded
  successor opportunity. Matching daemon recovery works without an OMP prompt or restart.
  A registration refusal caused solely by that daemon mismatch is scoped to the episode;
  the first subsequent matching Ready snapshot clears that refusal and coalesces one
  register-only attempt for the unconfirmed generation. It is not a permanent session latch.
  Ordinary helper spawn/pipe failures remain visible and fail closed.

  Every new registration write, including prompt registration and cold staging, requires live
  ownership. If the helper fails, Vox is unavailable for that extension while ordinary OMP
  remains usable; never fall back to an unfenced write. A reference-less old in-memory
  extension receives a typed permanent update/reload-extension refusal. Disk setup refresh
  alone does not prove the loaded extension changed: status/doctor MUST explain that the
  operator must restart OMP and resume the same conversation to load the refreshed extension.
  Confine ownership under account-data `.daemon/omp-instances/<opaque-random-id>`: current-uid
  private 0700 directories and 0600 files; reject symlinks, hardlinks and path traversal.
  Wire data carries only opaque instance ID and generation, never a caller-selected path.
  Validate current node fingerprint, session and generation; a replacement fingerprint is
  not the old identity.

  The watcher holds its instance lifetime lock once; it accepts correlated revoke/install
  generation commands and acknowledges only after mutation under the same stable instance
  mutation lock. A private instance lock is required because the existing node
  `registration_lock` cannot cover NoNode, Attaching, cold staging and retirement across
  processes. All three `store_checked` paths and deferred writes acquire that lock, recheck
  exact active binding and live lifetime ownership, and hold it through the write. Retirement
  first rejects old bridge work in memory, then revokes and ACKs. After confirmed watcher
  death/EOF a successor takes the same mutation lock, drains prior writers, acquires lifetime
  ownership and revokes the old record before releasing mutation ownership; only then may
  it install a fresh reference. A write already past its live check may finish after death,
  but the successor waits for it; an old reference is never reused. Mutation-lock contention
  is a typed temporary refusal. Never unlink/recreate lock inodes while held or awaited.
  The extension owns cleanup after confirmed helper exit and all mutation owners/waiters
  drain; if that cannot be established, retain the private directory rather than race unlink.
  Unknown retirement fails closed. Reconcile the live OMP Manager after a cancelled
  or rolled-back transition, including one with no compensating event. The fence is local
  OS-account ownership, not person attestation or a room trust capability.

  The [source-bound bridge design](../research/v0.4.20-omp-idle-registration-design.md)
  defines acceptance: actual idle room delivery after missing-node and busy-daemon recovery,
  delayed-write inverses on every write path, daemon linger, old extension reload guidance,
  and an actual v0.4.19 CLI/daemon upgrade cohort through post-update Ready and Locked
  guidance. No version-check bypass or real-profile proof is permitted.

- **P420-OR-6. Native transition boundary on stock OMP.** An earlier draft added a
  transition-settlement API to OMP; the operator ruled on 2026-11-07 that Vox MUST NOT require
  any OMP change, so that draft is withdrawn. Independent review (OpusStockOmpFence, OMP
  `dc295ad286`) selected the following, which does not depend on observing settlement:

  - **Transitions.** On `session_before_switch`/`_branch`/`_tree`: if an injected Vox
    operation is in flight, veto (`cancel`) without retiring; otherwise retire synchronously
    (new generation, rotated route, children killed, non-injected operation cancelled with an
    explicit decision, notices and followers cleared) and return nothing. `current()` is: not
    stopped, TUI main agent, installed, live Session ID equals the bound Session, and the bound
    reset boundary and leaf ancestry still match.
  - **Reinstall** only from `session_start`, `before_agent_start` when not current, or a
    `session_switch`/`_branch`/`_tree` success event (which retires first), synchronously
    snapshotting live identity, leaf, reset boundary and entries before any await, and
    rechecking serial, generation and `current()` after every await. Never from a timer, a
    watcher Ready signal, `isIdle` or socket traffic; Ready only re-registers an installed
    generation.
  - **Delivery.** No room, notice or Drive text in any `before_agent_start` result: OMP can
    admit a prompt mid-transition and its prompt commit fence counts generations, not identity.
    `before_agent_start` returns only a neutral wake marker. Content materializes only in
    `context`, after a synchronous live fence check, staged in the same step;
    `before_provider_request` rechecks synchronously and aborts with the uncertainty marker on
    mismatch; acceptance only at the assistant's `message_end` with one request, one marker and
    a known stop reason. Wakes use only `deliverAs: "aside"`, which OMP holds until a transition
    settles and drops on a generation change.
  - **Residuals.** Vox cannot observe settlement and does not rely on it. After a transition
    cancelled or rolled back without a compensating event, Vox stays unregistered until the
    next `session_start`, prompt or success event; idle attention is unavailable until then.
    A rolled-back switch can leave a registration for the abandoned target, which this
    instance refuses. A wake queued before a branch/tree move can start one empty turn; no
    content crosses. A prompt the person submits inside OMP's own generation/identity gap is
    an OMP-native race outside Vox's control; Vox content is excluded from it. Any delivery
    Vox cannot classify keeps the per-Session uncertainty marker, never cleared or replayed.
  - **Proof.** On the operator's installed stock OMP with a fixture extension loaded after
    Vox: later-handler cancel, rolled-back switch, `/clear` silent reset, ABA (reload, tree
    away/back, A→B→A), switch during a Vox-woken turn (injected and not), prompt admitted
    mid-switch, and branch with a held aside, each with its inverse mutant.

### OMP private Drive

- **P420-OD-1.** Explicit authenticated private Drive text under the existing node-to-node Drive
  capability and exact Session guard is operator input under DR-1.2, whether the caller is a
  person or an agent; nodes, not human/agent types, are the identities. No new human-origin flag
  or grant ceremony is required. Preserve the authenticated peer node, room/history instance,
  session/branch and explicit action kind. Ordinary room attention and messages remain foreign
  participant content, not operator instructions; file bytes and notes remain data. Retain the
  existing aside wake → `context`-time capability materialization → provider-marker observation
  path. At the guarded context event inject explicit Drive text as a supported `role: user`
  AgentMessage with authenticated node provenance, not the “not the user” wrapper. An idle
  Session starts a turn; a streaming Session consumes it at the next eligible step boundary.
  Do not substitute eager `sendUserMessage`, which would bypass deferred materialization.
- **P420-OD-2.** Preserve the single-use deferred capability and revalidate membership, Drive,
  node/room/history, exact registration and branch immediately before materialization and native
  delivery. Revocation or transition before that boundary prevents delivery; after irreversible
  delivery report uncertainty, not retraction. Do not replay unaccepted staged content on
  reconnect or reset. Existing ContextEventResult.messages supports this AgentMessage path;
  no upstream API change is required. Exactly one provider marker establishes the candidate
  consumption step under the existing native observation criterion.
  If Drive is revoked before consumption, read access remains but the operation has no accepted
  receipt; OMP shows the refusal and an already-started wake turn runs without the Drive content.
- **P420-OD-3.** Generate an unpredictable operation ID before send and carry it with authenticated
  author and scope through request, `drive.id`, private capability mapping, native receipt,
  `drive-result.of`, projection, pagination/reconnect, FFI and UI. The private capability is
  secret and distinct from this correlation ID. Deduplicate within author/operation scope; never
  associate by text or timing. Show refused/not sent, bridge queued, and native/provider accepted
  under the defined marker criterion separately. The assistant `message_end` belonging to the
  single provider request containing that operation's marker is its linked response step;
  publish an ID-bearing event over the authenticated follower and `drive-result.of`. Do not
  call that step a semantic answer, or attach any later/unmarked reply. Missing or ambiguous
  evidence stays unconfirmed, never auto-resends or downgrades established evidence.
  A late receipt cannot update a different sender, room, Session, branch or UI item. Queue acceptance MAY clear the
  draft only with recoverable submitted text and status for refusal or unknown delivery.
- **P420-OD-4.** Advertise only native controls actually supported. OMP `abort()` is a request
  to abort the current operation, not evidence of completion or termination of the Session;
  expose Interrupt accordingly and omit, disable or explicitly mark Stop unsupported if real
  termination is unavailable. Completion requires a matching native event. Slash, approvals,
  rejection and question answers remain unavailable unless their authorized, correlated native
  operations are established; retain existing cancellation guards and do not report success
  merely because a control was sent.

### OMP semantic Session presentation

- **P420-OP-1.** OMP Sessions MUST show meaningful semantic tool intent and a typed heading
  derived from intent, tool name and status, readable rich body, live partial progress,
  async running/waiting and final outcomes,
  including truthful error and cancellation states, rather than raw JSON envelopes or flattened
  160-character strings as normal presentation. Readable prose, Markdown, code, diffs and
  supported image/rich parts retain their meaning and long details remain accessible. Intentional
  JSON tool output may still be shown as content. Both app and TUI consume the same structured
  projection; the TUI may use a readable bounded fallback. Other harnesses and existing
  authorized approval/question behavior remain intact.
- **P420-OP-2.** Use existing supported OMP lifecycle and read-only Session APIs, without an
  OMP change: separate `intent` at tool start; coalesced `partialResult` updates; final typed
  result content/details and `isError`; streaming assistant text; `getAsyncJobSnapshot()` jobs
  (id, type, status, label, intent, command, caption, start/end); and async-result messages.
  Present intent or tool name as the heading, status/progress and readable text/image parts.
  Tool args and intentionally structured JSON remain available in disclosure, never a protocol
  envelope as the normal card. Do not copy arbitrary tool-specific renderers into Vox.
  Full arbitrary/custom `describeCall`/`describeResult` visual parity would need a supported
  future OMP API; it is not required for this outcome and is not a release prerequisite.
- **P420-OP-3.** Build the active-branch snapshot from the supported `sessionManager.getBranch()`,
  persisted native tool-call intent, async snapshot and the extension's current running-call
  map. Capture it synchronously with follower enrollment on the native event loop and assign
  a cursor before subsequent deltas; do not assume asynchronous renderer objects are
  serializable. Carry stable session, branch/reset generation, message/call/job identifiers
  and ordered typed updates with explicit replacement/reset. A gap, reconnect or branch change
  marks observation incomplete until a fresh current snapshot; reject late old-generation
  updates. Preserve latest coalesced progress and every terminal outcome, native history
  separately, and explicit unsupported/omitted-content indicators.
- **P420-OP-4.** Carry typed semantics through sealed Session activity, validation, bounded
  storage and paging, projection, FFI and client views without exposing hidden/private reasoning.
  Bound frames, tree depth and nodes, retained snapshot, text/blobs, in-flight bytes and update
  queues; page long detail in order at Unicode boundaries without silently clipping. Media MUST
  use a Session-scoped access-checked bounded transfer, not remote local paths or automatic
  arbitrary URL fetches; recheck authorization on fetch, verify declared size, appropriate MIME
  and SHA-256, bound concurrency/storage, and discard stale results after access or branch
  changes. Show unavailable, unsupported or oversized media honestly. Viewing never executes
  code or grants tool authority.

### Proposed acceptance matrix and evidence

Each row requires an observable outcome from the real consuming product, not just an internal
counter, source assertion, synthetic callback or registration file. Use isolated scratch data and
configuration, synthetic credentials and actual native clients/daemon. Extend existing
user-journey proofs where applicable; no unit or in-process library tests. For every claim an
independent verifier runs one relevant mutant and it MUST turn red on that claim's own
consumer assertion; CANNOT MEASURE is not a mutant red. Every red identifies **PRODUCT** with
the observed behavior or **APPARATUS** with the unmet staging/precondition or proof fault.
No acceptance, mutant or implementation is claimed here.

| Requirement | Real consumer acceptance and inverse |
|---|---|
| P420-RB-1, P420-RB-2 | In Vox.app, fail a real Join It on a bound repository, then confirm Not This Repo; see truthful failure and durable opt-out, no subsequent ask for future repo/worktree sessions after normal lifecycle. A sibling under the inherited parent still joins and communicates, explicit overrides work, and running sessions, trust and membership remain unchanged. An ambiguous boundary refuses with an explanation and changes nothing. |
| P420-RB-3, P420-RB-4 | From real agent-marked entry points attempt exact replacement and inherited shadowing: both refuse, while unbound agent no works. Change room, same-room credential or override after displaying confirmation and observe conflict without lost data; exercise competing cooperating writers and write/durability failure, with no credential disclosure or false success. |
| P420-RB-5 | After opt-out use native rebind without an ask; wrong credentials retain the no, correct credentials permit a new session/worktree to use the room without a prompt loop. Verify held-room credential checking and the operator CLI route; existing sessions do not silently move. |
| P420-OR-1–P420-OR-3 | In a real resumed OMP TUI with real room/node, observe actual register-only success under the unchanged native generation and post/read a distinct message. Exercise startup node absent then Ready and actual prompt recovery, startup resume and in-process switch/branch/tree without restarting OMP. Delayed old completion, cancelled/rolled-back switch, mismatched markers, wrong harness or borrowed ID must not route or post. Staging, timeout and ordinary-hook success are not registration. |
| P420-OR-4 | In a fresh native session arrange a real startup daemon timeout and first prepare's pre-envelope close; show failure while OMP remains usable, restore the authorized node and recover context and a new post/read under the same current identity without restart or replay. Repeat unavailable/repeated failure and genuinely ambiguous delivery: no false receipt, unbounded respawn, silent permanent disablement or duplicate injection. |
| P420-OD-1–P420-OD-4 | In actual OMP and Vox, send harmless uniquely identified private Drive inputs while idle and streaming; see authenticated node provenance, queue then matching observed native acceptance and the marker-associated response step, not an invented answer state. Concurrent input and unrelated turns cannot take its receipt. Exercise disconnect, branch/reset, revocation and late receipts, plus foreign room text and file content; no unauthorized elevation, replay or cross-session association. Controls report only evidenced native capability and outcome. |
| P420-OP-1–P420-OP-4 | Using current supported OMP APIs, observe actual app and TUI Sessions with real intent, coalesced partial progress, success/error/cancellation, async jobs and background completion, text/image parts and long Unicode details across pages. Disconnect, gap and branch reset recover without stale updates. Media works across hosts without shared paths; denied/revoked access, forged hashes or unsupported/oversized media never leak or render as verified. No hidden reasoning, executable content, private renderer import or new terminal/runtime is introduced. |

The complete [incident RCA and proposed corrective boundaries](../research/v0.4.20-incident-rcas.md)
retain observations, source mechanisms, original alternatives and uncertainty separately.
Local diagnostic logs are not published and are not candidate acceptance. Repository-side source
anchors include [OMP extension](../../crates/vox-tui/assets/omp-extension.ts),
[OMP mirror](../../crates/vox-tui/src/omp_mirror.rs),
[Drive host](../../crates/vox-tui/src/host.rs) and
[Session projection](../../crates/vox-core/src/node/session_view.rs). The reproduced absent-node
recovery gap and the separately reported fresh-start timeout do not establish the original
incident's exact trigger. OMP lifecycle source inspected for this proposal is at
`dc295ad286692e9668914cfb44127097039b2f3e`; this does not attest the incident's installed
binary. Tern.app 0.9.12 is a presentation reference, not an authority channel:
[transport](https://docs.stencil.so/tern/protocol/transport.md),
[operations](https://docs.stencil.so/tern/protocol/operations.md) and
[design](https://docs.stencil.so/tern/guides/design.md). Its protocol is a presentation reference,
not evidence of an external OMP renderer API. Current supported OMP events and snapshots are
sufficient for P420-OP's required outcome; idle registration-recovery ownership remains an
explicit technical design-review item rather than an invented native API.

## Superseded and amended lines

| ADR line | Was | Now |
|---|---|---|
| ADR-020 4.2, 4.9 | `at` carries repo, worktree, branch and cwd | Also `session_name` (MD-1) |
| ADR-020 4.6 | `to` names nodes only | An entry MAY name `<fingerprint>/<session id>` (TA-1) |
| ADR-020 6.2 | A wake goes to a session of the node addressed | A message addressed to a session wakes only that session (TA-3) |
| ADR-020 Context, Non-goals ("a TUI view … is deferred"; "per-session cryptographic identity") | Not a mirror; no TUI view yet; no per-session key | The room's conversation is not a mirror; Sessions have TUI and app views (§8); a Session key is held and released by the node, never by a session (SC-2) |
| ADR-020 6.12 | Vox MUST NOT send `turn/start` or `turn/steer` to Codex | A wake MUST NOT; driving an open session MAY (DR-7) |
| ADR-028 W-2 | Needs you: an unread message addressed to this node, or a trust offer | Also a Session waiting on this node, for a member with drive (CL-2) |
| ADR-020 6.6 | A row addressed to this node is shown in full | A row addressed to another session of this node is counted, not shown (TA-2) |
| ADR-020 Non-goals | No mirror of agent activity; ctm stays out | Activity lives only in a Session, sealed to drive (SC-1, SC-2); the room stays free of it |
| ADR-028 W-6 | A client MUST NOT show an agent's tool calls or activity | Not in the room's timeline; shown in its Session to members with drive (SC-4) |
| ADR-028 K-14 | Drive grants exactly what read grants until Sessions are specified | Drive grants §3 |

## Consequences

- A busy session writes many entries, kept only on the members with drive and only for the room's
  Session-step retention (ADR-031 SA-7, SA-9, as amended 2026-10-10).
- The person can follow and steer every session from the TUI or the app; Telegram is no longer
  needed for that.
- Two sessions of one node can be told apart and addressed separately without either gaining any
  power over the other.
