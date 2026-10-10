# ADR-029: Sessions, and the Room a Session Works In

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted for v0.4.0 (the decider, 2026-10-06). Nothing in this ADR is built.
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
  unregisters the session (ADR-020 6.10). A `SessionEnd` whose reason is `resume`, or a resumed
  session id, MUST keep the Session open.
- **SE-5.** An ended Session MUST be closed and moved out of the person's way (shown apart from
  open Sessions, like an archived conversation). Its content MUST NOT be deleted when the session
  ends: it follows the room's retention (ADR-010 AR-28, AR-29), as the room's own messages do.
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
- **SC-2.** A Session's content MUST be readable only by members of the room whom the session's
  node trusts with **drive** (ADR-028 K-14). Its entries MUST be sealed under a Session key that
  the session's node holds and releases only to those members, each release caused by a keyring
  entry carrying drive (ADR-020 3.3); the session itself holds no key (ADR-020 2.2). A member the
  node trusts with read only MUST NOT be able to read it.
- **SC-2a.** The node MUST release the Session key to a member with drive when that member is
  admitted to the room or gains drive, whichever is later, retrying on the tick (ADR-020 3.2). A
  member reads the Session from that release onward, as ADR-006's forward-only rule does for
  messages.
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
  1. to read the Session (SC-1), with Details;
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
  driving action on it.

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

- A busy session writes many entries into its room's log, kept as long as the room keeps messages.
- The person can follow and steer every session from the TUI or the app; Telegram is no longer
  needed for that.
- Two sessions of one node can be told apart and addressed separately without either gaining any
  power over the other.
