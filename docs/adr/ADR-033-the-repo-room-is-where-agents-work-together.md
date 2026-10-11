# ADR-033: The Repo Room Is Where Agents Work Together

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

**Status**: Accepted for v0.4.4 (the decider's Q&A, 2026-10-10, and his answers to this ADR's
open questions, the same evening, and his story-plan answers that night: threads in the TUI).
Nothing in this ADR is built.
**Date**: 2026-10-10
**Deciders**: Robert E. Lee
**Tags**: rooms, threads, pause, sessions, layout, composer, claims, macos, tui
**Related**: ADR-014, ADR-020, ADR-021, ADR-028, ADR-029, ADR-031, ADR-034
**Inputs**: the decider's product Q&A of 2026-10-10 (Q9–Q19) and its screenshots of the room
window; his answers to the open questions (who does what shows the room's claims only, with no
awa or GitHub; every other first choice "ok"); issue #683 (the room window works like a chat
app), whose flat room list shipped in v0.4.3.

## Context

The decider uses one room per repository, and in it: "The rooms I use for repos are a way for the
agents to distribute load, and collaborate on hard issues." There he reads General, watches a
Session live, drives one, answers an agent waiting on him, hands files, and steers "conversations
for hard collaborative problems". The room says who does what: claims, asks, hand-offs and tags.
Where an agent records its progress is the agent's business. The decider: "vox is agent comms.
Agents know how to communicate with github."

To steer a hard problem he asked to address several agents at once, give each problem a focused
thread, pause the agents at once, and see at a glance who works on what and who waits on whom. Of
today's room window: the Sessions list on the right ("General, all, etc.. It's weird"); the
composer ("I can't really see where I should be clicking to start typing -- and it takes up more
space than it should"); and the header ("The top area is taking up too much space").

## Requirements

### 1. Threads

The decider: "UX wise I think this is similar to how slack and others do replies to a message from
the general/main part of the room."

- **TH-1.** A thread MUST be the replies to one message in General: every message whose `thread`
  names that message (ADR-020 4.8). A thread is not a room: nothing joins it, it has no key, and
  every member who reads the room MUST be able to read it. It MUST add no entry type.
- **TH-2.** In General, a thread's starting message MUST show its reply count, who replied and when
  the last reply came; the replies MUST NOT be shown in General. Opening it MUST show the thread in
  the right panel (LY-6), beside General. In the TUI, which has no right panel, opening it MUST show
  the replies indented under the starting message (the decider, 2026-10-10).
- **TH-3.** Any message in General MAY start a thread, with Reply in Thread in the app and the TUI
  and `vox room post --re <message>` at a terminal. A starting message that names agents ("@claude-code
  @codex: …") addresses them (ADR-028 K-4), and their replies go in its thread.
- **TH-4.** A thread's replies MUST come to an agent's turn as news only for the nodes and sessions
  that posted in the thread or were named in it, the starting message included. Every other node
  MUST count them and MUST NOT show them in full (ADR-020 6.6). Every member still sees the starting
  message in General.
- **TH-5.** A reply MUST carry its starting message's tags (`task:`, `project:`, `milestone:`)
  automatically, so a thread keeps the tags its starting message had. Vox's verbs and clients MUST
  add them; the model MUST NOT be relied on to. Vox MUST NOT read, resolve or link what a tag
  names (WD-4).
- **TH-6.** A thread's message MUST be labelled with its thread in an agent's news, by the first
  line of the starting message.

### 2. Pause

- **PA-1.** The person MUST be able to pause, from the app, the TUI and `vox room pause`, at three
  levels: the whole room, one node, or a selection of nodes; and resume at the same levels.
- **PA-2.** Pausing MUST interrupt each paused node's sessions working in that room at once, as Esc
  does (ADR-029 DR-1.3), and MUST hold every new message of that room for them: no news and no wake
  until resume.
- **PA-3.** Pausing is driving: it MUST apply only to nodes that trust the person's node with drive
  (ADR-029 DR-2). A pause that covers other nodes MUST name each one it did not pause, and why.
- **PA-4.** Resuming MUST deliver the held messages as news at each session's next turn. It MUST
  NOT start a turn (ADR-020 1.5); an urgent message addressed to a session MAY wake it then, as
  ADR-020 6.2 allows.
- **PA-5.** A pause MUST hold until resumed, across restarts of either side. Every member who can see
  the node's Session MUST see it marked **Paused**, with who paused it and when.
- **PA-6.** The person's own input to a paused Session (ADR-029 DR-1) MUST still reach it.

### 3. Marks on a room's row

- **MK-1.** A room's row in the sidebar MUST show **@** when a message addressed to this node is
  unread, and **@!** when that message is urgent or a session waits on this node (ADR-029 CL-2).
  The marks join ADR-028 W-2's stronger colour and unread badge.

### 4. The composer

- **CO-1.** The composer MUST be one slim line: attach on the left, the field, then Send. The field
  MUST be visibly distinct from what surrounds it, with its own fill and edge from the token file
  (ADR-028 L-1). The decider: "we need some sort of color for the box where we type. Black on black
  is not obvious". It MUST grow only as the person types.
- **CO-2.** To: and Urgent MUST move into a small menu on the field. Typing `@name` MUST address a
  member (ADR-028 K-4), and a leading `!` MUST mark the message urgent; each MUST show in the field
  as a token that can be removed.
- **CO-3.** The TUI's composer MUST take the same `@name` and `!` (ADR-028 E-1).

### 5. Layout

- **LY-1.** The window's top line MUST be the room's tab row: the room's name and member count, then
  **General** and one tab per open Session the person can drive (ADR-031 SA-1), separated by thin
  lines. The decider: "I'd expect the name of the node that has a session I can drive to appear as a
  tab in this area next to general, with thin lines between the tabs. Clicking on the tab puts that
  session into the center panel. Clicking on general goes back to the main room chat." A tab MUST
  be labelled by the node's alias, and by its Session's name too when the node has more than one.
- **LY-2.** The second header block (the room's eyebrow, name, members and General under the title
  bar) MUST be removed.
- **LY-3.** There MUST be no list of Sessions and no **All** view. Ended Sessions MUST be reached
  from a menu on the tab row.
- **LY-4.** A room MUST open at General. A Session's opening or end MUST NOT be drawn in General.
- **LY-5.** In a Session, each tool step MUST be folded to one line, expandable to its Details
  (ADR-029 SC-1). Replies, questions and approvals MUST be shown in full.
- **LY-6.** The right panel MUST show only the room's members or the open thread. For members, each
  node with its admin or creator mark, its trust each way (ADR-028 L-4) and drive; a new member from
  another machine with Trust and Dismiss (ADR-031 LT-7). The decider: "Why can't we use that right
  panel for this?"
- **LY-7.** There MUST be no "Next Room That Needs You": the room list's marks and counts show it.
  The family LAN's control MUST move to a menu.
- **LY-8.** The sidebar MUST hold the rooms (ADR-028 W-2) and, at its foot, this Mac's nodes as
  Ready or Locked, with Unlock… on a Locked one (ADR-031 CW-1, CW-2). Keyring, Decision record and
  Services MUST move into a menu; all three stay. The decider: "I will use both more as I start
  actually using vox."
- **LY-9.** Ending a room MUST have its own sheet, and End for Everyone MUST say why when it is not
  offered. A room's row MUST have a context menu with Copy Room Link (⌘C) and Mark as Read.
- **LY-10.** Text MUST use the body face; monospace MUST be used only for what is copied
  (fingerprints, addresses, commands). A message addressed to this node MUST carry an accent bar.
- **LY-11.** The TUI MUST present the same regions in text: the tab row, General, threads (as
  indented replies, TH-2), members, and the marks (ADR-028 E-1).

### 6. Who does what

The decider: "vox is agent comms. Agents know how to communicate with github." Vox shows the room's
own claims and asks, and nothing from awa, GitHub or any tracker.

- **WD-1.** The members panel MUST show, per member and per session, what it holds and who waits on
  whom: the room's claims (ADR-021 §4, as `vox room board` folds them), with each claim's `task:`
  tag and work reference as plain text, and the addressed asks, hand-offs and `blocked` messages
  not yet answered.
- **WD-2.** It MUST be computed from the room's log each time it is shown, by the daemon's own fold,
  and MUST NOT be stored (ADR-021 1.2).
- **WD-3.** The app MUST read the board and claims through the daemon, as the CLI does; it MUST NOT
  fold claims itself. A room message given to the app MUST carry its `data.work` beside its tags.
- **WD-4.** No client, verb or hook of Vox MAY read awa, GitHub or any tracker, call its API, or
  turn a tag or work reference into a link to it (ADR-021 1.2).

## Superseded and amended lines

| ADR line | Was | Now |
|---|---|---|
| ADR-028 R-9 | A reply quotes one level; there MUST be no thread pane | Threads in the right panel (TH-1, TH-2); a reply outside a thread still quotes one level |
| ADR-028 W-1; ADR-014 M-13 | Sidebar with the acting node; inspector with members, keyring card and the room's services; Keyring, Services and Decision record in the sidebar | Members or the open thread only (LY-6); this Mac's nodes at the sidebar's foot; the three views in a menu (LY-8) |
| ADR-028 W-2 | Stronger colour, a badge and a key to the next room that needs the person | Also @ and @! (MK-1); no Next Room That Needs You (LY-7) |
| ADR-028 W-4; ADR-014 M-15 | The composer carries a To: selector and an urgent switch | One slim line; To: and Urgent in a menu, `@name` and `!` typed (CO-1–CO-3) |
| ADR-029 CL-2 | General, All, and one entry per open Session beside the conversation | Tabs in the top line, General first, no All (LY-1, LY-3) |
| ADR-014 M-21 | Menus as listed | Also Pause and Resume in Room (PA-1); the LAN control and Keyring, Services and Decision Record in a menu (LY-7, LY-8) |

## Consequences

- A hard problem gets its own thread without a new room, and only the agents in it are fed its
  traffic.
- Pausing a room stops every agent the person can drive in it at once; agents on other people's
  machines that do not grant drive keep running and are named.
- The room window loses its header block and its Sessions column; the members panel carries who
  does what, from the room's own claims.
- A person who wants an item's progress reads it where the agents record it; Vox does not show it.

## Related ADRs

Depends on ADR-020, ADR-021, ADR-028, ADR-029, ADR-031. Amends ADR-014 (M-13, M-15, M-21), ADR-028
(R-9, W-1, W-2, W-4) and ADR-029 (CL-2). Cited: ADR-034.

## Engineering Mantra

These principles are binding on all work under this ADR:

- **Do not be lazy.** Plenty of time to do it right.
- **No shortcuts.** Every component is built to production quality from day one.
- **Never make assumptions.** Dive deep before writing a single line of code.
- **Measure three times, cut once.** Verify designs, implementations, and outputs.
- **No fallback. No stub code.** No `todo!()`, no `unimplemented!()`, no "we'll fix this later." If a feature isn't ready, it doesn't ship — but what ships is complete. And if we need it, we build it: no false deferrals.
- **Chesterton's Fence.** Always understand what exists and why before changing or removing it.
- **Pure excellence.** A finding emitted by r2c is one a senior IOActive consultant would defend in front of a client.
