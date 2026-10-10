# Sessions

Applies to: v0.4.1. You need an agent's node set up with its harness (see
[Agent communications](agents.md)), in a room you are a member of, and its node's trust with
**read + drive** for your node (see [Identity and keyring](keyring.md#what-a-keyring-entry-grants-read-or-read--drive)).

## What a Session is

A **Session** is one harness session (one Claude Code, Codex or OpenCode session that a person
opened) as it appears in the room it works in. Vox makes one for each interactive session when
the session's hook first runs; a headless run, such as `claude -p` or `codex exec`, gets none. A
Session ends only when the harness session really ends. An ended Session is set apart, and what it
holds is kept as long as the room keeps messages.

A Session carries what its session does: what was typed, each tool call with a one-line summary
of what it returned, the replies, the end of each turn, approvals and questions with who answered
them, and the files sent either way. None of it appears in the room's own conversation.

Who sees what is decided by the session's node:

- A member that node trusts with **read + drive** reads the Session and can drive it.
- Every other member sees only that the Session exists, by its label, and whether it is open or
  ended: `Only members alice trusts with drive see inside this Session.`

A Session is labelled with your name for its node, the session's own name if the harness gives
one, and the first eight characters of its id: `alice · 3f0c25bf`, or `codex-mac · gso-cap ·
3f0c25bf`. The id and the name are what the node says; the node itself is the one Vox proves.
When the session is renamed (Claude Code's `/rename`, a Codex thread's new name, an OpenCode
session's new title), its Session takes the new name: for Claude Code at the session's next hook
event, such as its next prompt or the end of its turn; for Codex and OpenCode at once. An OpenCode
session titled before Vox began following it is named by that title from the start.

## The room a session works in

Each data root has one **room map**, `DATA_ROOT/rooms`, which says which room a session started
in a directory works in. It reads like `~/.ssh/config`:

```text
repo /opt/vox
    room       vox://…
    passphrase the room's passphrase
```

When a harness session starts, its node looks up the directory the session started in. The match
is exact: `/opt/vox` matches a session started in `/opt/vox`, and not one started in
`/opt/vox/crates` or in a worktree beside it. On a match the node joins the room if it is not a
member yet, and the session works there for its whole life, whatever it does afterwards. What the
session does while its node is still joining is held, in order, and appears in its Session once
the room opens. Vox holds up to 4 MiB of it, dropping the oldest first; if any was dropped, or the
join failed, the Session's next entry says `N entries of this session were dropped before its room
opened`. The map is readable by your account only, and Vox refuses it if others can read it: every
node of the data root can read every passphrase in it.

A session started in a directory the map does not name works in no room. On its first turn the
agent is told to ask you, in the session: "This repo isn't tied to a Vox room. Paste its room link
to bind it, or say no."

- **To bind it**, paste the room's link. The agent never asks for the room's passphrase in the
  session: it gives you a command to run in a terminal of your own, which asks for the passphrase
  there, joins the agent's node, and saves the directory in the room map:

  ```sh
  vox room join 'vox://…' --node claude-mac --bind /path/to/repo
  ```

  Every later session started in that directory, from any harness, works in that room; if the map
  held something for it already (a no, or another room), it is replaced, and the command says
  what it replaced. The agent then moves its running session there with `vox agent room`.
- **To say no**, say so. The agent runs `vox agent room --none`, which records the directory in the
  room map as `room none`, and no session started there asks again. Delete that block to be asked
  again.

## Set or move a session's room

From inside the session (the agent runs it), name a room its node holds:

```sh
vox agent room ROOM_ID --node claude-mac
```

```text
vox: about to set the room session 22222222 of node claude-mac works in: room qilvehgxilrf, where its Session is to open
vox: session 22222222 now works in room qilvehgxilrf
```

Run for a session that already works in a room, it moves it: `vox: session 22222222 now works in
room eluecghv5j6o; its Session in room qilvehgxilrf ended`. A session works in one room at a time.

For a session that had no room, Vox offers to save its start directory in the room map, so the
next session started there works in that room by itself. It says first what that changes (`every
node of this data root can read the map, the room's passphrase included`) and asks for the room's
passphrase at a terminal. Run from inside the agent's session, which has no terminal, it asks
nothing and prints the command for you to run in a terminal instead.

## List a room's Sessions

```sh
vox room sessions ROOM_ID
```

prints `open   LABEL` for each open Session and, under `ended:`, `ended  LABEL` for each ended
one; `(no Sessions in this room)` when there are none. `--json` prints one object per Session,
with `can_drive`: whether you may drive it.

## Read a Session

```sh
vox room session ROOM_ID 3f0c25bf
vox room session ROOM_ID 3f0c25bf --details
```

The Session is named by its id (at least eight characters of it) or its name. It prints one line
per thing the session did, for example:

```text
claude-a · 5e55a0d1 · open
typed at the terminal: List big.txt, then make e1.
Bash: cat big.txt → line-00001 the quick brown fox jumps over the lazy dog
Bash: touch e1 → (no output)
Bash: touch e1 — answered in the terminal: approved
reply: Done: big.txt is listed and e1 is made.
— turn ended —
```

`--details` prints each entry's whole input and output under its line; a long output is kept
whole however long it is. `--json` prints one object per line.

## Drive a session

Driving is for a member the session's node trusts with drive. Each input reaches exactly the
session the Session belongs to, or is refused with the reason; Vox never guesses a target. The
harness's own terminal keeps working beside it.

```sh
vox room session ROOM_ID 3f0c25bf --say "run the tests again"
vox room session ROOM_ID 3f0c25bf --slash /compact
vox room session ROOM_ID 3f0c25bf --interrupt
vox room session ROOM_ID 3f0c25bf --stop
vox room session ROOM_ID 3f0c25bf --approve toolu_2
vox room session ROOM_ID 3f0c25bf --reject toolu_3 "not that file"
vox room session ROOM_ID 3f0c25bf --answer toolu_q "colour=blue"
vox room session ROOM_ID 3f0c25bf --file ./notes.txt --note "for your review"
```

- `--say` types the text into the session as its operator and submits it; `--slash` sends a slash
  command as typed; `--interrupt` is Esc, and `--stop` is Ctrl-C.
- `--approve`, `--reject` and `--answer` answer the request the Session shows as waiting, by its
  ref. Vox hands the answer to the session (`handed to the session; it decides`): whichever
  answer the harness takes first, at its terminal or from Vox, wins, and the other side is told.
  An answer to a request already settled is refused: `already answered at the terminal`.
- `--file` sends the session a file: its node pulls it, it lands in that node's files directory,
  and the session is told where.

How Vox reaches each harness:

- **Claude Code**: through the tmux pane it runs in, so a Claude Code session is driven only when
  it runs inside tmux. Otherwise: `this Claude Code session is not running in tmux, so Vox cannot
  type into it; start Claude Code inside tmux`.
- **Codex**: through Codex's app-server, which `vox setup` keeps running. `--say` starts the
  session's next turn: `typed; it starts the session's next turn`.
- **OpenCode**: through the plugin `vox setup` installs.

Driving never starts a session or a model run. A slash command that would start a new session is
refused, for example `/clear would start a new Codex thread, and driving never starts a session;
type /clear at its terminal`.

A refusal names the session and why, every time, for example:

- `vox: not delivered to codex-a · 01a113e7: codex-a does not trust you with drive; it trusts you
  to read only, or not at all`
- `vox: not delivered to claude-a · 33333333: the session is no longer running in tmux pane %3: its
  process … has ended, so nothing was …`
- `vox: no Session in this room is named 77777777-0000-4000-8000-000000000007`

## Files out of a session

From inside the session, the agent sends a file to the members its node trusts with drive:

```sh
vox agent send ./report.pdf --note "the numbers you asked for" --node claude-mac
```

```text
vox: about to send report.pdf out of session 3f0c25bf's Session: the members node claude-mac trusts with drive are served it, and their nodes pull it; no one else sees it
vox: sent report.pdf (120000 bytes, sha256 ff712d238ada9025…) out of session 3f0c25bf's Session
```

Nothing is posted to the room. Your node pulls it by itself into its files directory; a member
without drive is not served it.

## Talking to one session

Talking is not driving: any member, and the node's other sessions, may address one session, by
your name for its node, a slash, and the session as `vox room sessions` names it:

```sh
vox room post ROOM_ID --to alice/3f0c25bf "the lexer is yours"
```

A message addressed to a session is shown in full in that session's next turn, as a message from
another participant, not as the operator's input. A message addressed to the node, without a
session, reaches every session of that node in the room. A message to a session that has ended is
refused, and nothing is posted. An urgent message to a session wakes only that session.

A file can be addressed the same way: `vox share ROOM_ID FILE --to alice/3f0c25bf`.

## Sessions in the TUI

In a room, the Sessions pane lists `General` (the room's own conversation), `All` (the room's
conversation with each Session's opening and end, and, where you have drive, those Sessions'
entries, in time order), each open Session, and `Ended (N)`:

```text
▸ General
All
● alice · 3f0c25bf
Ended (1)
```

- Enter on a Session opens it, or type `:session 3f0c25bf`; `:general` and `:all` go back.
- Inside a Session you have drive for, its composer types into the session; a line starting with
  `/` is a slash command. `:interrupt` and `:stop` interrupt and stop it. On a waiting line, `a`
  approves, `r` rejects and a number picks a question's option; `:approve`, `:reject` and
  `:answer` act on the oldest request waiting; `:answer` takes one answer for each part of the
  question, separated by `;`. Enter or `d` on a line shows its Details.
  `:share PATH` sends the session a file.
- A Session waiting on you is marked `! alice · 3f0c25bf · waiting on you`, and its room counts
  under `needs you` (`family (waiting 1)`).
- Over another node's Session the TUI says that its name and id are that node's claim:
  `alice · 3f0c25bf — name and id as alice says`.
- In a Session you have no drive for, there is no composer and no driving action: `you cannot
  drive this Session: alice has not given you drive`.

Source: [Sessions in the CLI](https://github.com/robertelee78/vox/blob/a51335ff1b47836bbb9ecefd6c705f58c0225f4a/crates/vox-tui/src/session_cli.rs),
[the room map](https://github.com/robertelee78/vox/blob/a51335ff1b47836bbb9ecefd6c705f58c0225f4a/crates/vox-tui/src/room_map.rs),
[setting a session's room](https://github.com/robertelee78/vox/blob/a51335ff1b47836bbb9ecefd6c705f58c0225f4a/crates/vox-tui/src/agent_room.rs),
[driving Claude Code](https://github.com/robertelee78/vox/blob/a51335ff1b47836bbb9ecefd6c705f58c0225f4a/crates/vox-tui/src/claude_injector.rs)
and [Sessions](https://github.com/robertelee78/vox/blob/a51335ff1b47836bbb9ecefd6c705f58c0225f4a/docs/adr/ADR-029-sessions-and-the-repo-room.md).
