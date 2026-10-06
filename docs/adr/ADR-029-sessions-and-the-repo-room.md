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
  room, created when the session first acts there (its `hello`, ADR-020 2.2). A headless run
  (`claude -p`, `codex exec`, a non-interactive OpenCode run) MUST NOT get one.
- **SE-2.** A Session's identity MUST be the harness's own session id (Claude Code's
  `session_id`, Codex's thread id, OpenCode's `ses_…` id); Vox MUST NOT mint one. A sub-agent's
  activity MUST belong to its parent's Session.
- **SE-3.** A Session MUST be labelled with its node's alias (or short fingerprint), the session's
  current name (§5 MD-1) and the first 8 characters of its id, for example
  `codex@device-2 · gso-cap · 3f0c25bf`.
- **SE-4.** A Session MUST end only on the harness's real end (`SessionEnd` or its equivalent).
  A `SessionEnd` whose reason is `resume`, or a resumed session id, MUST keep the Session open.
- **SE-5.** An ended Session MUST be closed and moved out of the person's way (shown apart from
  open Sessions, like an archived conversation). Its content MUST NOT be deleted when the session
  ends: it follows the room's retention (ADR-010 AR-28, AR-29), as the room's own messages do.
- **SE-6.** A Session MUST belong to exactly one room, the room its session works in (§6).

### 2. What a Session carries, and who sees it

- **SC-1.** A Session MUST carry the session's activity: each tool call with a short summary of
  its input and output and its full input and output on request (Details); the agent's replies;
  the end of each turn; tool approval requests and their outcome; the session's own questions and
  their answers; and files sent either way (§3 DR-1).
- **SC-2.** A Session's content MUST be readable only by members of the room whom the session's
  node trusts with **drive** (ADR-028 K-14). Its entries MUST be sealed under a key the session's
  node releases only to those members. A member the node trusts with read only MUST NOT be able
  to read it.
- **SC-3.** Every other member MUST see only that the Session exists: its label (SE-3), whether it
  is open or ended, and whether it is waiting on a person (an approval or a question pending).
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
- **DR-2.** What a member may drive MUST be its drive capability limited by room membership: a
  node can drive only Sessions in rooms it is a member of.
- **DR-3.** Both surfaces MUST stay live: the harness's own terminal keeps working, an approval or
  a question MUST render in both the terminal and the Session, and either side MAY answer.
- **DR-4.** The first answer MUST win, decided by the harness's own resolution event, never by a
  send having succeeded; the other surface MUST then show the request as answered elsewhere.
- **DR-5.** Driving input MUST reach exactly the session the Session belongs to. When Vox cannot
  establish where that session is, it MUST refuse and say why; it MUST NOT guess a target.
- **DR-6.** A failed delivery MUST be reported to the driver every time, naming what failed.
- **DR-7.** Driving MUST NOT start a harness or a model run: a Session drives only a session a
  person already opened (ADR-020 1.5).

### 4. Talking to a session

- **TA-1.** Talking is not driving. Any member the session's node trusts with read MAY address a
  message to one session: a `to` entry MAY name `<whole fingerprint>/<session id>` (ADR-020 4.6 as
  amended).
- **TA-2.** A message addressed to a session MUST be shown in full in that session's per-turn read
  (ADR-020 6.6), attributed to the sending node and its session (§5), as a message from another
  node, never as the operator's input. The node's other sessions MUST count it as room traffic and
  MUST NOT show it in full.
- **TA-3.** An urgent message addressed to a session MAY wake it, announce-only (ADR-020 6.2):
  waking is talking ("yo, let's chat"). Interrupting a session mid-task is driving (DR-1.3).
- **TA-4.** A message addressed to a node, without a session, MUST reach every session of that
  node working in the room.
- **TA-5.** A message addressed to a session that has ended MUST be refused, and the sender told
  that the session has ended; it MUST NOT be delivered to another session of the node.

### 5. Session metadata on every message

- **MD-1.** Every message an agent's node posts MUST carry the posting session's id (`from`,
  ADR-020 4.2) and its current name, in `at.session_name` (ADR-020 4.9 as amended). The name is the
  harness's own session name (Claude Code's `/rename` title, Codex's thread name, OpenCode's
  session title); when the harness gives none, the field MUST be absent and clients MUST show the
  short id.
- **MD-2.** Vox's hook and verbs MUST fill these fields, whatever verb posts; the model MUST NOT be
  relied on to supply them.
- **MD-3.** The session id and name are claimed by the node, not proven (ADR-020 2.3). Clients
  MUST show them as the node's claim beside the proven node identity.

### 6. The room a session works in

- **RB-1.** Each machine MUST have one room map, `<config dir>/rooms`, mode `0600`, readable by
  every node on the machine, in the style of `~/.ssh/config`:

  ```
  repo /opt/vox
      room       <room link>
      passphrase <room passphrase>
  ```

  `room` and `passphrase` MUST be separate fields; the passphrase MUST NOT be part of the link
  (ADR-005).
- **RB-2.** When a harness session starts, its node's hook MUST look up the session's start
  directory in the room map. The match MUST be exact: `/opt/vox` matches a session started in
  `/opt/vox` and nothing else.
- **RB-3.** On a match, the node MUST join the room if it is not a member (ADR-005 J-1 with the
  map's link and passphrase), and the session MUST work in that room.
- **RB-4.** A session's room MUST NOT change during the session's life because of where it works
  afterwards: new branches, worktrees, or reading or editing other repositories' files do not move
  it.
- **RB-5.** With no match, the session MUST work in no room, and the hook MUST say so in the
  harness session with the command that sets one: `vox agent room <room>`. The same command, run
  later, MUST move the session to that room; a session MUST work in one room at a time.

### 7. Setting up a machine

- **ST-1.** `vox setup` MUST detect the harnesses installed on the machine (Claude Code, Codex,
  OpenCode) and offer to create one node per harness (`<harness>-<host>`, ADR-026 N-6), each with a
  passphrase the operator types (ADR-028 K-11), and to install its hooks.
- **ST-2.** On macOS (and iOS, with its app), setup MUST offer to create a node for the person; it
  MUST be optional. On Linux it MUST NOT offer one unless asked.
- **ST-3.** Setup MUST end by printing, for every node it created, its fingerprint (grouped, with
  its art, ADR-028 K-1) with the facts a person needs to recognise it: alias, harness, host, OS and
  Vox version.

### 8. In the TUI and the app

- **CL-1.** The TUI and the app MUST present Sessions the same way, with the same steps and words
  (ADR-028 E-1).
- **CL-2.** A room MUST list its Sessions beside the room's own conversation, as a group lists its
  topics: the room's conversation (**General**), every message and Session event merged in time
  order (**All**), and one entry per open Session, with ended Sessions apart (SE-5). A Session
  waiting on the person MUST count under **needs you** (ADR-028 W-2).
- **CL-3.** A member without drive MUST see a Session's entry (SC-3) and MUST NOT be offered any
  driving action on it.

## Superseded and amended lines

| ADR line | Was | Now |
|---|---|---|
| ADR-020 4.2, 4.9 | `at` carries repo, worktree, branch and cwd | Also `session_name` (MD-1) |
| ADR-020 4.6 | `to` names nodes only | An entry MAY name `<fingerprint>/<session id>` (TA-1) |
| ADR-020 6.2 | A wake goes to a session of the node addressed | A message addressed to a session wakes only that session (TA-3) |
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
