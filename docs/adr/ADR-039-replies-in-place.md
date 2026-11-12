# ADR-039: Replies in Place

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

- **Status**: Proposed. The decider's eight product rulings of 2026-11-12 (D1–D8 below) are
  rulings and are recorded as such. Every rule this ADR derives from them is proposed; a rule
  marked *(open: Qn)* waits on that question in "Open questions for the decider". Nothing in this
  ADR is built: each requirement is to land with its proof (ADR-018). When accepted, it replaces
  ADR-028 R-9 (as amended by ADR-033) and amends the ADR-033, ADR-028, ADR-014 and ADR-034 lines
  listed under "Superseded and amended lines".
- **Date**: 2026-11-12
- **Deciders**: Robert E. Lee
- **Tags**: rooms, replies, conversations, tasks, timeline, unread, macos, tui, cli, agents
- **Related**: ADR-014, ADR-018, ADR-020, ADR-021, ADR-023, ADR-028, ADR-029, ADR-033, ADR-034
- **Inputs**: the operator's complaint and the decider's product Q&A of 2026-11-12; an audit of
  how replies work at `d9a8667ba` (cited by file and line below); Slack's account of designing
  threads, Microsoft Teams' channel layouts, Discord and Telegram replies, and Zulip topics
  (cited under "Rejected alternatives").

## Context

On 2026-11-12 the operator said: "I'm having a hard time following the replies in the threads".
Of the pains offered to him, he ticked two: he cannot tell what a reply is answering without
jumping to it, and the replies to one message are scattered or out of sight.

How replies work today (`d9a8667ba`):

- **Data.** A reply carries `re`, the entry it answers, and `thread`, the General message that
  starts its conversation (ADR-020 4.8). A reply to a reply copies its parent's `thread`
  (`reply_thread_by`, `crates/vox-agentcomms/src/envelope.rs:692–702`), so a conversation is one
  flat level: every reply is a sibling of every other under one root. There is no tree. A reply
  inherits its root's `task:`, `project:` and `milestone:` tags (ADR-033 TH-5;
  `envelope.rs:704`).
- **The app hides replies.** The room timeline keeps a message only when its `thread` is empty
  (`apps/macos/Vox/Timeline.swift:73`), so no reply is ever drawn in General. The root shows
  "N replies · authors · time of last reply" (`ThreadSummaryLine`,
  `apps/macos/Vox/MainWindow.swift:3196–3242`); selecting it opens a thread panel that replaces
  the member inspector (`MainWindow.swift:1752–1755`, `ThreadPanel` from `:3245`) and cuts the
  root to three lines (`:3264`). Members and a thread cannot be seen together.
- **The quote is one level and short.** A reply shows `re <who>: <first line, 80 characters>…`
  above its body, as a link to its parent (`MainWindow.swift:2326–2335`;
  `Timeline.swift:202–213`). A reply to a reply quotes its immediate parent, never the root.
  The composer cuts its "Replying to" line at 60 characters (`MainWindow.swift:1822–1837`); the
  agent hook cuts its "↳ in reply to" line at 100 (`PREVIEW_CHARS`,
  `crates/vox-tui/src/agent_hook.rs:1118`). Three lengths say one thing.
- **Walls of text.** A message body is drawn whole, with no line limit
  (`MainWindow.swift:2340–2343`), and so is every Ask row in the inspector
  (`MainWindow.swift:2994`). An Ask row has no way back to the message it came from.
- **Unread.** Unread is per room only (ADR-028 R-8, R-8a). The unread line sits above the first
  unread message as the room opened (`NodeModel.swift:2206`; `MainWindow.swift:1214`); when that
  message is a hidden reply the line is not drawn at all. Reading a thread clears nothing per
  thread; only the room-wide Mark as Read does.
- **CLI.** `vox room read` prints `<entry> <author> <text>` in room order and shows neither `re`
  nor `thread` (`plain_row`, `crates/vox-tui/src/room_cli.rs:1666–1716`): a text reader cannot
  tell a reply from a new message. `--json` carries them only inside `envelope`. The agent hook
  already prints both: "↳ in reply to <entry> <author>: <preview>", read from the log by hash,
  and "↳ thread: <root's first line>" (`agent_hook.rs:1174–1220`).
- **Notifications** are grouped by room and never carry text (`apps/macos/Vox/Notify.swift:49–53`,
  `:116–117`; ADR-028 R-10).
- **The record contradicts itself.** ADR-028 R-9 says "There MUST be no thread pane"; ADR-033
  TH-2 and LY-6 then asked for the thread in the right panel, and that panel is what shipped.

The timeline hides exactly what the operator needs to follow: who answered what, next to what
it answered. This ADR records the decider's answer and works out what it implies.

## Terms

- **Root**: a message in General with no `thread`. Every root starts a conversation.
- **Reply**: a message whose `thread` names a root. Its **parent** is the message its `re` names:
  the root, or another reply in the same conversation.
- **Conversation**: a root and every reply whose `thread` names it. A root with no replies is a
  conversation of one. This is the reply conversation of D6.
- **Task**: every readable message in a room carrying one `task:` tag, with the replies that carry
  it. This is the task conversation of D6 *(open: Q9 for which tags make a task)*.
- **Group**: how the timeline draws one conversation: its root, then its replies under it.
- **Last activity**: the position, in the room's one order (ADR-023 RL-1.2), of the newest
  readable entry of a conversation.
- **Preview**: the line on a reply that says what it answers: the parent's author and the start of
  the parent's text.
- **Focus**: the view that dims everything except one conversation or one task (D4).

## The decider's rulings (2026-11-12)

The decider answered the product questions one at a time on 2026-11-12. His answers are the
decision:

- **D1.** Replies show in the room timeline, grouped under the message they answer, each with a
  preview of what it answers.
- **D2.** A new reply moves the whole conversation to the bottom of the timeline.
- **D3.** The latest three replies stay visible; earlier ones collapse behind a "show N earlier
  replies" control.
- **D4.** The thread panel goes away. A "Focus" action dims everything except one conversation.
- **D5.** Long posts collapse after about eight lines, with "show more".
- **D6.** A conversation is both the replies to a message and everything on one task (a work item,
  or a task tag such as `task:#2372`). There must be a way to read one task end to end. There is
  no separate threads inbox.
- **D7.** Agent-to-agent replies stay visible in the main timeline; they are not hidden.
- **D8.** The model he wants is "a mix of" Teams' grouping under the parent and Discord's
  chronological replies with a preview of the parent.

## Requirements

### 1. Replies stay in the timeline

- **RP-1. (D1, D8)** The room timeline in the app and the TUI MUST draw every readable reply,
  grouped under its root, in the conversation's group. A reply MUST NOT be drawn only somewhere
  else. Reason: the operator cannot follow replies he cannot see beside what they answer; Teams'
  posts layout groups replies under the post for the same reason.
- **RP-2. (D7)** A reply MUST NOT be hidden or folded away for its author's kind. A reply from one
  agent's node to another's is drawn like any other. Reason: in a repo room the agents' answers to
  each other are the work the person steers (ADR-033 Context); and Vox has no human/agent typing,
  only nodes (ADR-038 "Unchanged rulings"). The app's existing rule that control kinds are not
  drawn (`Preview.shows`, `NodeModel.swift:115–117`) and read records (RR-4) are unchanged.
- **RP-3. (D1)** A group MUST be one level. Inside it, replies MUST be drawn in the room's one
  order (ADR-023 RL-1.2), oldest first, each at one indent under the root. A reply to a reply MUST
  stay in that flat list, in its place by order, and MUST NOT be indented further or nested
  under its parent. Reason: Slack found that replies to replies made threads "extremely complex"
  and that one level "was an instant success on all fronts"; Vox's `thread` is already one level.
- **RP-4. (D1)** Every reply MUST carry its preview, directly above its body *(open: Q3 for
  replies that answer the root)*. The preview MUST say:
  - the parent's author, as this reader names that node (ADR-020 4.7), and `you` for its own;
  - the first line of the parent's words (a file share: its note, else its file name), at most 100
    characters, cut further to the row's width with an ellipsis;
  - nothing taken from the reply: the preview MUST be read from the log by the parent's entry
    hash, so a reply's author can point at a message but cannot make the preview say anything that
    message did not (as the hook does today, `agent_hook.rs:1169–1173`).

  When the parent is not readable here, the preview MUST NOT be omitted: it MUST say so in one
  sentence written once in vox-core and shown by every client (ADR-028 E-7): one for a parent this
  node does not hold, one for a parent it holds but cannot open yet. Selecting a preview, or ⌘↑
  with the reply selected, MUST select the parent, expanding the earlier replies (RP-12) when the
  parent is among them. One preview length (100) MUST replace today's three (60, 80 and 100).
- **RP-5.** The envelope MUST NOT change: `re` and `thread` keep their meaning (ADR-020 4.8),
  ADR-033 TH-1 (a thread is not a room and adds no entry type) and TH-5 (a reply inherits its
  root's tags) stand. Replying MUST be one action, **Reply** (⌘R), on any row; a reply to a
  reply lands in the root's conversation as it does today.

### 2. Where a conversation sits

- **RP-6. (D2)** The timeline MUST arrange conversations by last activity, oldest at the top,
  newest at the bottom. A new reply therefore moves its whole group, root included, to the bottom.
  A root with no replies sits by its own position. Reason: D2; it keeps the newest talk where the
  person is already looking, as Teams' posts layout does.
- **RP-7.** Last activity MUST be computed from the room's one order (ADR-023 RL-1.2), never from
  when this node received an entry, so that every node holding the same entries arranges the same
  conversations in the same order (ADR-023 R13).
- **RP-8.** An entry that arrives late (ADR-023 RL-1.3) MUST take its causal position inside its
  group, and its group MUST take the place its last activity gives it, which can be above groups
  already on screen *(open: Q1)*. The row keeps its "arrived late" mark, counts as unread, and the
  next-unread key (RP-27) MUST reach it. ADR-023 RL-1.3 and RL-1.4 stand for entries and for
  `vox room read`.
- **RP-9.** An opaque row (owed, or not yet readable) cannot say its conversation ("Opaque owed
  rows cannot establish thread membership", `crates/vox-core/src/node/ipc.rs`, `Request::Thread`):
  it MUST sit by its own position as a placeholder, as General shows it today, and MUST join its
  group, which then takes its new place, once it is readable.
- **RP-10.** Room notices (retention, renames, joins) MUST sit between groups by their own
  position and MUST NOT be drawn inside a group. A day divider MUST follow last activity; a root
  or reply whose own day differs from the divider above its group MUST show its date beside its
  time.
- **RP-11.** The timeline MUST NOT move what the person is reading. While the view follows the
  bottom, a moved group appears at the bottom. While the person is scrolled up, and while Focus is
  on (§4), the arrangement MUST hold still: a new reply joins its group in place, the rows on
  screen keep their position, and a bar at the bottom edge MUST say "New replies in N
  conversations" with a control that goes to the newest. Returning to the bottom, or that control,
  applies the held moves *(open: Q2)*. Under Reduce Motion a move MUST NOT animate (ADR-028 L-5).

### 3. What collapses

- **RP-12. (D3)** A group MUST show its latest three replies. Earlier replies MUST collapse behind
  one control, "Show N earlier replies", placed between the root and the first shown reply, which
  loads them in bounded pages (ADR-034 FR-4) and shows them in place; "Hide earlier replies"
  collapses them again. When any collapsed reply is unread, the control MUST say how many: "Show
  N earlier replies (M new)", and "· K to you" when K of them are addressed to this node
  *(open: Q4)*. An expanded group SHOULD stay expanded until the person collapses it or leaves
  the room. A group with three replies or fewer has no control.
- **RP-13. (D5)** A root or a reply whose body draws more than eight lines at the current width
  and text size (ADR-028 L-1b) MUST show its first eight lines and "Show more (N more lines)";
  "Show less" folds it again. A body that would hide fewer than three lines MUST be shown whole,
  so "Show more" never reveals one line *(open: Q5)*. A file card, the preview and the
  read-by line (ADR-028 R-6) are not counted and never collapse. Selecting the text, copying it,
  and a search MUST reach the whole body.
- **RP-14. (D5)** The inspector's work rows (ADR-033 WD-1; `workRow`, `MainWindow.swift:2986`)
  MUST show at most two lines of an Ask's, Assign's or Handoff's text with "Show more", and MUST
  offer **Show in Timeline**, which selects the message the row came from (its `entry`), expanding
  whatever hides it *(open: Q6)*.
- **RP-15.** A Session tab (ADR-029) is not the room timeline: ADR-033 LY-5 (tool steps folded,
  replies, questions and approvals in full) is unchanged by RP-13 *(open: Q5)*.

### 4. Focus

- **RP-16. (D4)** The thread panel MUST be removed. The right panel MUST show only the room's
  members and their work (ADR-033 LY-6, WD-1). Nothing else MAY replace the inspector.
- **RP-17. (D4)** **Focus** MUST be offered on every row of a conversation (its context menu, the
  Room menu and the command palette) and on every `task:` chip (§5). Focused, the app MUST:
  - draw the focused conversation or task at full contrast with every reply expanded, and dim
    every other row;
  - hold the arrangement still (RP-11), so the focused rows do not move while read; new replies to
    them join in place, and other conversations keep arriving, dimmed;
  - make Reply in the composer answer the focused conversation's newest reply unless the person
    picks another row;
  - show a bar above the timeline naming what is focused ("Focused on: <root's author>: <first
    line>", or "Focused on task:#2372") with **Leave Focus**.

  Esc, **Leave Focus**, the Focus key again, or opening another room MUST leave Focus. Leaving
  MUST apply the held moves and keep the focused conversation on screen. Focus MUST NOT change
  what is read: RR-1 still counts only rows on screen, dimmed or not *(open: Q7 for a task)*.
- **RP-18.** A dimmed row MUST stay readable: its text at no less than `text.muted` on its surface
  (ADR-028 L-2), and it MUST say so in words to assistive technology ("outside focus"), never by
  colour alone (ADR-028 E-6).

### 5. Reading one task end to end

- **RP-19. (D6)** A task MUST be every readable message carrying one `task:` tag; replies carry
  their root's tags (TH-5), so a tagged root brings its replies. A message that carries several
  `task:` tags belongs to each of those tasks. `project:` and `milestone:` tags MUST stay what they
  are today, filters in the tag menu, and do not make a task *(open: Q9)*. Vox MUST NOT read,
  resolve or link what a tag names (ADR-033 WD-4).
- **RP-20. (D6)** The person MUST be able to read one task end to end: Focus on a task (from a
  `task:` chip on any row, or from the room's tag menu) MUST show every message of the task in
  the same grouped layout as General, its conversations arranged by last activity, so reading
  top to bottom reads the task from its first activity to its last *(open: Q7)*. A tagged reply
  whose root carries no tag MUST be shown under that root, drawn as context and labelled
  "outside this task".
- **RP-21. (D6)** The room's General timeline MUST group by reply conversation only: a message is
  drawn once, in its reply conversation's group, and a task is read through Focus *(open: Q8)*.
- **RP-22. (D6)** There MUST be no threads inbox: no All Threads view, no list of conversations
  across rooms, no Activity panel for replies. The room list's marks and counts (ADR-033 MK-1,
  ADR-028 W-2) and the per-conversation marks (§6) say where something new is. Reason: the
  decider ruled it; Slack needed All Threads only because it took replies out of the channel.

### 6. Unread, per conversation

- **RP-23.** A group with unread replies MUST say so on its root's line: "N new", and "K to you"
  when K of them are addressed to this node, with the three levels of ADR-028 R-8 (addressed, new,
  coordination). Each unread reply MUST carry a "new" mark until it is read.
- **RP-24.** Reading MUST stay as ADR-028 RR-1 says: a reply is read when it is drawn on screen in
  the focused room. A collapsed reply is not drawn and so is not read; expanding it draws it.
- **RP-25.** The unread line (ADR-028 R-8) MUST sit above the first group whose last activity is
  unread. Because groups are arranged by last activity, every group below the line has something
  new, and inside each the "new" marks say what. A group placed above the line by a late entry
  (RP-8) keeps its own marks.
- **RP-26.** The room-wide **Mark as Read** (ADR-028 R-8a, ⇧⌘U) MUST be unchanged: it
  acknowledges every received message through the captured arrival boundary, replies included,
  collapsed or not. A **Mark Conversation as Read** on a group's context menu MUST do the same for
  that conversation only *(open: Q10)*.
- **RP-27.** A key MUST move to the next group with an unread reply, and another to the next
  group with a reply addressed to this node (§9).

### 7. What the daemon supplies and what the app computes

- **RP-28.** The daemon MUST serve the grouped timeline through a paged request (named here
  `ConversationPage`) for a room, a view (General, or one `task:` tag) and a cursor. Each page
  MUST carry, per conversation, newest last activity first:
  - the root row, or its placeholder (RP-9), and the root's last-activity position;
  - the reply count and the latest three replies;
  - each shown reply's preview, computed by the daemon from the log (RP-4) and bounded to the
    preview length, never the parent's whole body;
  - the conversation's unread counts by level and the first unread reply, within the existing
    unread scan bound (`UNREAD_LOOKED`, 1,000 rows, `crates/vox-core/src/node/channel.rs:1130`),
    stating when the bound was reached as the room-wide summary does (R-8a);
  - for a task view, which rows carry the tag and which are context (RP-20).

  Earlier replies MUST come from the existing bounded `ThreadPage`. A bounded re-read of named
  conversations (named here `ConversationFind`, at most `MAX_FIND` roots) MUST serve live updates,
  as `RoomViewFind` does for rows.
- **RP-29.** Every page MUST be served from an index, never by decoding a room's history (ADR-034
  FR-5), and MUST fit one frame by rows and bytes (FR-7). The General view MUST keep a per-room
  last-activity index of conversations beside the existing thread index, updated in bounded work
  for each entry that becomes readable (a logarithmic insert, not a scan), and rebuilt from the
  thread index on open in bounded, event-driven turns (ADR-037 R7). A task view MAY scan the
  existing tag index newest first with a resumable scan cursor, as `Tagged` does, so a page with
  few conversations is still bounded work. The memory the daemon and the app use MUST be bounded
  by the pages shown (FR-5), and ADR-034 FR-6's bounds MUST hold for the grouped view: on a room
  of 100,000 replies, the newest page shows, and each older page loads, in under one second, and
  the daemon's and the app's resident memory each stay under 50 MB.
- **RP-30.** The live event for a new readable entry MUST carry its `thread` root, so a client
  moves or grows one group without re-reading the page.
- **RP-31.** The app MUST NOT arrange conversations, count their unread or compute previews by
  reading the room itself; it MUST take them from the daemon, as it takes the board (ADR-033
  WD-3). The app computes only what is a fact of drawing: line counts and RP-13's collapse,
  truncation of the preview to the row's width, dimming, scroll position and RP-11's held moves.
- **RP-32.** The TUI MUST present the same model in text (ADR-028 E-1): groups under their roots
  with one indent, previews, the latest three replies and the earlier-replies line, long bodies
  folded, conversations moving to the bottom, per-conversation unread, and Focus, through its own
  keys and its `:` palette.

### 8. The CLI and the agents

- **RP-33.** `vox room read` text MUST keep the room's one order, so its `--since` and `--before`
  cursors keep their meaning (ADR-023 RL-1.4) *(open: Q11)*. Every reply MUST print, under its
  first line, the two lines the hook prints today, from the same code: `↳ in reply to <entry>
  <author>: <preview>` and `↳ thread: <root's first line>`. A reader MUST be able to tell a reply
  from a new message from text alone.
- **RP-34.** `vox room read --conversations` MUST print the grouped arrangement of RP-6: per
  conversation, the root, then "N earlier replies: `vox room read <room> --conversation
  <entry>`" when there are more than three, then the latest three replies indented, each with its
  preview. `vox room read <room> --conversation <entry>` MUST print one whole conversation, one
  bounded page by default, saying how to get the rest (ADR-034 FR-4). With `--tag task:<value>`,
  `--conversations` MUST print that task end to end (RP-20).
- **RP-35.** `vox room read --json` MUST add top-level `re`, `thread` and `reply_to` (the parent's
  entry, author, preview and whether it is held and readable) to each `vox.room.row/1` row; the
  fields already inside `envelope` stay. `--conversations --json` MUST print one
  `vox.room.conversation/1` object per conversation.
- **RP-36. (D7)** What an agent is fed MUST be unchanged: the hook's drain keeps ADR-033 TH-4
  (a conversation's replies come to an agent's turn only when its node or session posted in it
  or was named in it; other replies are counted) and TH-6 (the thread label). D7 rules the
  person's timeline, not an agent's context *(open: Q12)*. The skill pack MUST say "reply" and
  "conversation" where it says "thread" today, with no change of behaviour.

### 9. Accessibility and keyboard

- **RP-37.** Each group MUST be one accessibility container labelled "Conversation: <root's
  author>: <first line>, N replies, M new". A reply's label MUST begin "Reply to <author>:
  <preview>". "Show N earlier replies" and "Show more (N more lines)" MUST be buttons that say
  their counts; a collapsed body MUST say it is collapsed. A moved group MUST NOT be announced;
  notifications are unchanged (§10). Every control MUST be reachable from the keyboard and the
  command palette (ADR-028 L-8a; ADR-014 M-19).
- **RP-38.** The app's key map (ADR-014 M-20) MUST add *(open: Q14)*:

  | Key | Action |
  |---|---|
  | ⌘R | Reply to the selected message (was "Reply in Thread") |
  | ⌘↑ | Go to the message the selected reply answers (exists) |
  | ⌥↑ / ⌥↓ | Previous / next conversation |
  | ⌥⌘↓ | Next conversation with an unread reply |
  | ⌘⇧F | Focus on the selected conversation; again, Leave Focus |
  | Esc | Leave Focus (after the composer's own Esc: an unsent reply is cancelled first) |
  | Space, Return | On "Show N earlier replies" or "Show more": expand |

- **RP-39.** The word **thread** MUST leave what the app, the TUI and the CLI say: they say
  **reply**, **replies** and **conversation**. `thread` stays the envelope's field name
  *(open: Q13)*.

### 10. Notifications

- **RP-40.** Notifications MUST be unchanged: grouped by room, text hidden (ADR-028 R-10; ADR-014
  M-23); a reply notifies exactly when any message would (addressed to this node, urgent). A
  conversation moving to the bottom, a Focus, or a collapse MUST NOT notify.

### 11. Migration

- **RP-41.** When this lands, the thread panel and what serves only it MUST be deleted, not left
  unreachable: `ThreadPanel` and its "Reply in Thread" buttons (`MainWindow.swift:3245–3300`),
  the inspector's swap (`:1752–1755`), `ThreadSummaryLine` and its states (`:3196–3242`),
  `showThread`, `openThread`, `threadReplies`, `threadHasMore` and `threadRootMessage`
  (`NodeModel.swift:198–216`), the General filter at `Timeline.swift:73`, and the TUI's opened
  thread (`expanded_thread` and "Enter: open thread", `crates/vox-tui/src/ui.rs:1198–1342`).
  `Request::ThreadSummary` MUST be deleted once nothing calls it. `Request::Thread` (the hook's
  participation, TH-4) and `Request::ThreadPage` (RP-12) stay.
- **RP-42.** No stored data changes: the envelope is unchanged and the last-activity index is
  derived (RP-29). There is no data migration (AGENTS.md, Releases: no prior-release
  compatibility requirement).
- **RP-43.** The manual's "Threads and bounded views" (`docs/manual/rooms.md:129–139`), its
  reference page, and the skill pack's room reference MUST be rewritten in the same change.
- **RP-44.** ADR-028 R-9, as amended by ADR-033, MUST read: a reply is drawn in its conversation's
  group in the timeline with a preview of what it answers (RP-1–RP-4), and there is no thread pane
  (RP-16).

## How this is proven

Each proof drives the shipped `vox` and the built Vox.app as a person would and asserts what that
person sees (ADR-018; AGENTS.md, Tests). Each extends an existing journey rather than adding a
file; each names its mutant, run once, that turns it red on its own assertion; each red names
PRODUCT (quoting what the product showed) or APPARATUS. Staging: alice's app in a scratch data
root; bob and carol as `vox` nodes in scratch roots (`VOX_DATA_DIR` and `VOX_CONFIG_DIR` set for
every `vox`).

| Proof | Journey | Extends | Mutant |
|---|---|---|---|
| P-1 (RP-1–RP-4, RP-6) | bob posts ROOT-A, then ROOT-B; carol replies to ROOT-A, bob answers carol's reply. In alice's app ROOT-A's group is below ROOT-B; both replies are under ROOT-A at one indent, in order; bob's says "carol: <carol's first line>" above it, and clicking that selects carol's reply. | `apps/macos/VoxAppProofs/FirstRunProof.swift` step 4 (its reply quote and 4c1, whose thread-panel assertions this deletes) | Restore the General filter (`Timeline.swift:73`): red at "carol's reply must be drawn under ROOT-A". Arrange by root position: red at "ROOT-A must sit below ROOT-B". |
| P-2 (RP-12, RP-13) | carol replies five times to ROOT-A; the group shows the latest three and "Show 2 earlier replies"; activated, all five show. bob posts a 20-line message; it shows 8 lines and "Show more (12 more lines)"; activated, all 20. | FirstRunProof step 4 | Show every reply; or never collapse a body: red on the control's absence. |
| P-3 (RP-16–RP-18) | Focus on ROOT-A from its context menu: every other row's accessibility value says "outside focus", the inspector still lists the members; a reply to ROOT-B arriving meanwhile does not move ROOT-B; Esc leaves Focus and the bar is gone. | FirstRunProof step 4 | Focus that filters instead of dimming, or Esc that does not leave: red at the named assertion. |
| P-4 (RP-19–RP-21) | bob posts ROOT-T tagged `task:#2372`, carol replies, bob posts an untagged message between; Focus on the `task:#2372` chip shows ROOT-T and the reply undimmed and the untagged message dimmed. | FirstRunProof step 17 (a room by tag) | Focus on a task that ignores the tag: red at "the untagged message must be outside focus". |
| P-5 (RP-23–RP-26) | alice's app hidden, carol replies to the old ROOT-B; shown again, ROOT-B's group is at the bottom below the unread line, says "1 new", and the reply carries "new"; ⇧⌘U clears both, and `vox room read --json` on carol's node says alice read it. | FirstRunProof steps 4 and 13 | Unread line above the first unread row instead of the first unread group: red. |
| P-6 (RP-11) | alice scrolls ROOT-B's group to the top of the view and stays scrolled up; a reply to ROOT-B arrives: ROOT-B has not moved, and the bar says "New replies in 1 conversation"; its control shows ROOT-B at the bottom. | FirstRunProof step 4 | Apply moves at once: red at "ROOT-B must not move while read". |
| P-7 (RP-7, RP-8) | carol, offline, replies to ROOT-A; bob and alice post meanwhile; carol reconnects. `vox room read --conversations` on bob's and carol's nodes prints the same arrangement as alice's app, and carol's reply is marked late. | `crates/vox-tui/tests/causal_order_proof.rs` | Arrange by local arrival: red at "the arrangements must match". |
| P-8 (RP-33–RP-35) | `vox room read` prints, under bob's reply, "↳ in reply to <entry> carol: …" and "↳ thread: ROOT-A"; `--json` has top-level `re`, `thread` and `reply_to`; `--conversations` prints ROOT-A's group last; `--conversation` prints it whole. | `crates/vox-tui/tests/room_verbs_proof.rs` | Drop the reply lines from `plain_row`: red. |
| P-9 (RP-32) | The TUI draws ROOT-A's replies indented under it with their previews and moves the group to the bottom on a new reply. | `crates/vox-tui/tests/the_tui_shows_the_room_truthfully_proof.rs` | Draw replies flat by order: red. |
| P-10 (RP-37, RP-38) | With Full Keyboard Access on: ⌥↓ moves the selection from ROOT-B to ROOT-A; ⌘↑ on bob's reply selects carol's; ⌘⇧F focuses, Esc leaves; Space on "Show 2 earlier replies" expands it. | FirstRunProof step 14 | Unbind ⌥↓: red. |
| P-11 (RP-29) | On a room of 100,000 replies across 10,000 conversations, the app's client opens the newest grouped page, and each older page loads, in under one second, and the daemon's and the client's resident memory stay under 50 MB. An optional proof, as FR-6 is: it blocks nothing and prints `OPTIONAL PROOF NOT RUN` when not run. | `crates/vox-tui/tests/a_large_room_reads_whole_proof.rs` (its ADR-034 FR-6 case) | Build each page by decoding the room's history: red on the time bound, PRODUCT. |

The agent hook is unchanged (RP-36): its existing `crates/vox-tui/tests/agent_hook_proof.rs`
stands and no proof is added for it. Notifications are unchanged (RP-40): FirstRunProof's step 8
stands.

## Open questions for the decider

Each has a recommended answer; the rule it holds is marked *(open: Qn)* above.

- **Q1. A late reply's place (RP-8).** Recommended: its group takes the place its causal
  position gives it, which may be above groups already shown, marked "arrived late" and counted
  unread, so every node shows the same arrangement (ADR-023 R13). Alternative: a late reply moves
  its group to the bottom on each node as it arrives, so D2 holds literally, but two nodes then
  disagree on the arrangement.
- **Q2. Holding still while reading (RP-11).** Recommended: no group moves while the person is
  scrolled up or in Focus; a bar says what moved, and returning to the bottom applies it. Without
  this, the text he is reading can jump away under him.
- **Q3. The preview on a reply that answers the root (RP-4).** Recommended: keep it on every
  reply, as D1 says, so every reply reads the same and still says what it answers when the root
  is far above or collapsed. Alternative: omit it when the parent is the root, to save a line per
  reply.
- **Q4. Unread replies inside the collapse (RP-12).** Recommended: keep "the latest three" literal
  and say in the control how many collapsed replies are new and how many are to you.
  Alternative: always show an unread reply addressed to this node, even when it is older than the
  latest three.
- **Q5. Long posts (RP-13, RP-15).** Recommended: eight drawn lines, never collapsing to hide
  fewer than three; urgent messages and messages to this node collapse too; Session tabs keep
  LY-5 (in full). Asks: is "about eight" eight, and should anything be exempt?
- **Q6. Ask rows in the inspector (RP-14).** Recommended: two lines with "Show more", and Show in
  Timeline to the message the row came from.
- **Q7. Focus on a task (RP-17, RP-20).** A task's messages may be far apart in General.
  Recommended: Focus on a task dims everything else and folds each long stretch of dimmed rows
  into one line ("12 other messages"), so the task reads end to end in place. Alternative: show
  only the task's messages, as the tag menu's filter does today.
- **Q8. Does General group by task as well (RP-21)?** Recommended: no. A message is drawn once, in
  its reply conversation; a task is read through Focus. Grouping by task in General would put a
  reply conversation inside a task group (two levels), and a message with two `task:` tags in two
  places.
- **Q9. Which tags make a task (RP-19)?** Recommended: `task:` only (a work item's reference
  already becomes its `task:` tag, `envelope.rs:198–203`); `project:` and `milestone:` stay
  filters.
- **Q10. Mark Conversation as Read (RP-26)?** Recommended: yes, on a group's context menu, beside
  the unchanged room-wide Mark as Read; otherwise a collapsed unread reply is cleared only by
  expanding it or by marking the whole room.
- **Q11. The CLI's default (RP-33, RP-34).** Recommended: `vox room read` stays in room order with
  the reply lines added, and `--conversations` gives the grouped arrangement. Alternative: grouped
  by default, which changes what `--since` and `--before` page through.
- **Q12. Agents (RP-36).** Recommended: D7 is about the person's timeline; what an agent is fed
  keeps ADR-033 TH-4. Alternative: feed every agent every reply, which widens each agent's context
  to every conversation in the room.
- **Q13. Words (RP-39, RP-17).** Recommended: "reply" and "conversation" replace "thread" in what
  Vox says. "Focus" is already macOS's name for notification modes, and the app already has View
  > Focus Timeline (⌃⌘T); recommended: the new menu items are "Focus on Conversation" and "Focus
  on Task", and Focus Timeline becomes "Go to Timeline".
- **Q14. Keys (RP-38).** Recommended as listed: ⌥↑/⌥↓, ⌥⌘↓, ⌘⇧F, Esc.

## Rejected alternatives

- **Slack's side panel (what Vox ships today).** Slack's designers found that showing replies in
  both the thread and the channel made people read every reply twice, and that "Hiding replies
  from the channel content turned out to be the single most meaningful change" ([Slack, Threads
  in Slack part 2](https://slack.design/articles/threads-in-slack-a-long-design-journey-part-2-of-2)).
  Hiding replies then needed three more features to work: an inbox of threads (All Threads), an
  activity panel, and "also send to channel" so people did not miss replies. Vox built the
  hiding and the panel without the rest, and the operator cannot follow his rooms. In a repo room
  the replies are the work, not side talk; the decider removed the panel (D4) and ruled out an
  inbox (D6). D3's collapse and D1's grouping answer Slack's read-twice problem differently: a
  reply is drawn once, in its group, never twice.
- **Pure chronological replies with a preview (Discord, Telegram).** Discord's replies quote the
  parent above the reply in the channel ([Discord, Replies FAQ](https://support.discord.com/hc/en-us/articles/360057382374-Replies-FAQ));
  Telegram's tap on the quote scrolls to the original ([Telegram, Replies, Mentions,
  Hashtags](https://telegram.org/blog/replies-mentions-hashtags)). The preview answers "what is
  this answering", but the replies to one message stay scattered through the room, the second pain
  the operator ticked; Slack found that conversations "wove into each other constantly" and
  preambles before replies did not help. Vox keeps the preview from this model (D8) and not the
  scattering.
- **Topics only (Zulip).** In Zulip "each conversation within a channel is labeled with a topic"
  and a person can "read Zulip one conversation at a time" ([Zulip, Why Zulip](https://zulip.com/why-zulip/)).
  It needs every message, from every person and agent, to name a topic, and topics to be renamed,
  split and moved as talk drifts. Vox's replies and asks are reply-shaped (ADR-020 4.8, the hop
  budget), and its `task:` tag is the closest thing to a topic; D6 adopts the task as a way to
  read, not as the only structure.
- **Nested replies.** Slack found that replies to replies made threads "extremely complex" and
  one level "an instant success". Vox's `thread` is one level by its data model; RP-3 keeps it.
- **Grouping without a preview (Teams' posts layout alone).** Teams' posts layout groups replies
  under the post ([Microsoft, Choose your channel layout in Teams](https://support.microsoft.com/en-us/teams/teams-channels/choose-your-channel-layout-in-microsoft-teams)).
  Inside a flat group a reply to a reply then loses who answered whom, which is the first pain the
  operator ticked; D8 adds Discord's preview to the grouping.

## Superseded and amended lines

| ADR line | Was | Now |
|---|---|---|
| ADR-028 R-9 (as amended by ADR-033) | A reply quotes one level; "There MUST be no thread pane"; ADR-033: threads in the right panel | Replies drawn in their conversation's group with a preview (RP-1–RP-4); no thread pane (RP-16); RP-44 |
| ADR-033 TH-2 | Replies not shown in General; the thread in the right panel; the TUI indents an opened thread | Replies in General, grouped, by last activity (RP-1, RP-6, RP-12); the TUI the same (RP-32) |
| ADR-033 TH-3 | Reply in Thread | Reply (⌘R) on any row (RP-5) |
| ADR-033 TH-1, TH-4, TH-5, TH-6 | — | Preserved (RP-5, RP-36) |
| ADR-033 LY-6 | The right panel shows the members or the open thread | The members only (RP-16) |
| ADR-033 LY-11 | Threads as indented replies (TH-2) | Conversations as RP-32 |
| ADR-028 R-8 | Unread per room, three levels | Also per conversation (RP-23); the unread line above the first unread group (RP-25) |
| ADR-028 R-8a | Room-wide Mark as Read; "thread/tag routes" | Unchanged; adds Mark Conversation as Read (RP-26, open Q10); conversation and task routes |
| ADR-023 RL-1.3 | A late entry takes its causal position and does not move to the bottom | Preserved for entries; a conversation's place follows its newest entry's position (RP-7, RP-8, open Q1) |
| ADR-014 M-20 | The key map | Adds RP-38's keys |
| ADR-034 FR-7 | The paged lists | Adds `ConversationPage` and `ConversationFind` (RP-28, RP-29) |
| ADR-028 R-10; ADR-014 M-23 | Notifications grouped by room, text hidden | Preserved (RP-40) |

## Consequences

### Positive

- A reply is seen where it belongs, beside what it answers, with what it answers written on it.
- The room needs no second place to read: no panel, no inbox; the inspector keeps the members.
- A task reads from its first message to its last, in one view.
- Every node arranges a room the same way, and the CLI prints that arrangement.
- One preview, computed once from the log, for the app, the TUI, the CLI and the hook.

### Negative

- Old conversations move. A person who remembers where a message sat finds it lower after a
  reply; RP-11 keeps it from moving while it is read, not after.
- A busy room shows more rows than today's roots-only General, even with three replies per group
  and collapsed bodies.
- The daemon keeps one more derived index per room and serves one more paged request.
- A late reply can land above what the person has already read (as late rows do today, ADR-023).

### Neutral

- The envelope, the log and what agents are fed do not change.
- Notifications do not change.

## Related ADRs

Depends on ADR-020, ADR-023, ADR-028, ADR-033, ADR-034. Amends ADR-028 (R-8, R-8a, R-9), ADR-033
(TH-2, TH-3, LY-6, LY-11), ADR-014 (M-20) and ADR-034 (FR-7). Cited: ADR-018, ADR-021, ADR-029,
ADR-037, ADR-038.
