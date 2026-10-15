# Sessions

Applies to Vox v0.4.5.

This page shows how to put an agent's sessions in the right room, follow what a session does,
and drive it. To drive a session, the agent's node must trust your node with **read + drive**
([Identity and keyring](keyring.md#what-a-keyring-entry-grants-read-or-read--drive)).
The examples use the existing room `family`, operator node `robertgpt`, and agent node `claude-mac`
from the earlier chapters; actual Session IDs and waiting references come from your own output.

## What a Session is

A **Session** is one harness session, such as one Claude Code, Codex or OpenCode session a
person opened, as it appears in its room. Vox makes one when an interactive session's hook first
runs. A headless run, such as `claude -p` or `codex exec`, gets none. A Session ends when the
harness session ends. Its steps have a separate lifetime from the room conversation.

A Session records what its session does: what was typed, each tool call with a one-line summary
of its result, the replies, the end of each turn, approvals and questions with who answered them,
and files sent either way. None of it appears in the room's conversation.

A step is one thing an agent did in its Session: a message, a command it ran, or a file it
edited. By default, steps stay for seven days or the room's message lifetime, whichever is
shorter. A shorter message lifetime on your node can shorten it further. Keeping ordinary room
messages forever therefore does not keep Session steps forever.

Set the step lifetime separately with `vox room retention family --steps 7d --node robertgpt`,
or the **Session steps** control in Vox.app's **Retention** sheet. An admin sets the room rule; other members may
choose a shorter lifetime for their own node. **Use room rule** removes that local choice.
Shortening it deletes older steps immediately and leaves ordinary messages and shared files
under their own retention. See [Session step retention](rooms.md#set-how-long-session-steps-stay).

The session's node decides who sees inside:

- A member it trusts with **read + drive** reads the Session and can drive it.
- Read-only membership does not expose a selectable private Session or its attention state.
  General may show ordinary room membership/join information, not the private activity.
- When Drive is taken back, the app retires the selected private surface and returns to General;
  CLI private queries refuse. Revocation cannot erase content someone already copied.

A Session's label is your name for its node, the session's own name if it has one, and the first
eight characters of its ID: `claude-mac · 3f0c25bf`, or `codex-mac · gso-cap · 01a113e7`. The name and
ID are the node's claim. When the session is renamed in its harness, its Session takes the new
name: Claude Code's at its next prompt or turn end, Codex's and OpenCode's at once.

## The room a session works in

Each data root has one **room map**, the file `rooms` in the data root
([local state](reference.md#local-state)). It says which room a
session works in, by the directory it started in:

```text
repo /opt/vox
    room       vox://…
    passphrase the room's passphrase
```

A session works in the room of the deepest directory the map names at or above its start
directory. So a session started in `/opt/vox/crates` works in `/opt/vox`'s room, unless
`/opt/vox/crates` has a block of its own. A session in a git worktree of `/opt/vox` works in
`/opt/vox`'s room too, unless a block names the worktree. If the node is not in that room yet, it
joins. What the session does meanwhile is kept, up to 4 MiB, and added to its Session once the
room opens. The session stays in that room until it ends or you explicitly move it as described below.

The map holds room passphrases. It must be readable by your account only, or Vox refuses to use
it. Every node in the data root uses it, so each of them can use every passphrase in it.

### Bind a repository from your terminal

For an existing `family` room, with `robertgpt` and the setup-created `claude-mac` Ready on this
computer, open your own terminal in the actual repository directory and run:

```sh
room_link=$(vox room link family --node robertgpt)
vox room join "$room_link" --bind "$PWD" --node claude-mac
```

The first command captures your real link; the second quotes it and binds your current directory
while joining as the agent node. Type the room passphrase in this terminal. This saves a room
passphrase in the private room map, available to nodes in this data root. It does not grant trust.
For a remote room, use its actual received link in the same join flow.

If the repository needs a **new** room instead, while in that directory:

```sh
vox room create --name work --bind "$PWD" --node claude-mac
```

Use a different valid name if this node already holds `work`. Start the harness in this directory,
run its `vox agent status --harness claude` check, and confirm the actual bound room and Session
in `vox room sessions` before sending a question. Substitute the actual setup-created harness/node
when using Codex or OpenCode; do not bind another Session's repository by guessing.

### When a repository has no room

When a session starts in a directory the map does not name, it works in no room, and Vox asks you
which room the repository works in, once per directory:

- in the Vox app, a banner across the window, such as `Claude Code in /opt/vox has no room`, and
  a notification, `Which room is this repo in?`;
- in the terminal interface, under `needs you`;
- in `vox agent status`, as `Vox needs you: Claude Code in /opt/vox has no room. …`;
- in the session, where the agent tells you once.

Answer in one of three ways:

- **In the app:** choose **Choose a room…**, pick one of your node's rooms or paste a room link,
  and type the room's passphrase. Vox saves the directory in the room map and puts every session
  waiting there in that room.
- **In the session:** paste the room's actual link. The agent never asks for the passphrase. It
  constructs a complete join command with that link, its actual `--node` and this repository's
  absolute `--bind` path, quoting each raw argument. Run the complete command in your own terminal.
  It asks for the passphrase, joins the agent's node and saves the directory in the room map.
  If the map held something for the directory, it is replaced and the command says what. Status
  or the next hook turn puts the waiting session in that bound room.
  If you want a new room, the notice also supplies a complete create command with a suggested
  name, the actual node and the repository's binding; you can run it in your terminal.
- **To say no:** choose **Not this repo** in the app, or say no in the session. The agent then runs
  `vox agent room --none --node claude-mac` for this example's agent. The map records the
  directory as `room none`, and no session started there asks again. Delete that block to be asked again.

A directory bound to a room its node is not in is asked about too. In the app, **Join It** joins
with the link and passphrase the map holds.

## Move a session to another room

From inside the session, the agent names a room its node holds:

```sh
vox agent room family --node claude-mac
```

```text
vox: about to set the room session 3f0c25bf of node claude-mac works in: room gkpeyuly4m4e, where its Session is to open
vox: session 3f0c25bf now works in room gkpeyuly4m4e
```

A session works in one room at a time. Moving it ends its Session in the old room. For a session
that had no room, Vox offers to save its start directory in the room map, and asks for the room's
passphrase at a terminal. From inside the agent's session, which has no terminal, it prints the
command for you to run instead.

## List and read Sessions

```sh
vox room sessions family --node robertgpt
```

Choose the intended Session from that actual output. Construct `vox room session` with `family`,
its returned ID or name, and `--node robertgpt`; add `--details` to inspect full input and output.
There is no fixed Session ID to reuse from this manual.

`vox room sessions` lists the retained `open` and `ended` Sessions visible to the acting node.
With `--json`, each returned row has `can_drive`. A read-only viewer may get no row at all; absence
from that list does not prove the harness is stopped. Use the owner's view for an owner-side check.

`vox room session` takes a Session's ID (at least eight characters) or its name, and prints one
line per thing the session did:

```text
claude-mac · 3f0c25bf · open
typed at the terminal: List big.txt, then make e1.
Bash: cat big.txt → line-00001 the quick brown fox jumps over the lazy dog
Bash: touch e1 → (no output)
Bash: touch e1 — answered in the terminal: approved
reply: Done: big.txt is listed and e1 is made.
— turn ended —
```

The command returns one bounded page, newest by default, and prints how to request an older page.
Keep its exact `--before` entry, node, room and Session together. `--details` adds the selected
entries' whole joined input and output. `--raw` exposes unjoined records for inspection; it is
still paged. `--json` prints one object per line, and continuation guidance remains on stderr.
An empty current page or a retained page is not the whole history. A removed or expired cursor
requires a fresh newest read; do not silently treat it as a complete empty Session.

## Drive a session

Each input reaches exactly the session named, or is refused with the reason. The harness's own
terminal keeps working beside it.

Use the complete read command for the actual Session selected above, retaining its room, ID
and `--node robertgpt`. Add one of the input flags below. Text, file paths and waiting request
references must come from your intended action and that Session's actual output; quote them
with the [shell-quoting rule](reference.md#commands-you-can-paste).

- `--say` types the text as the operator and submits it. `--slash` sends a slash command.
  `--interrupt` is Esc. `--stop` is Ctrl-C.
- `--approve` takes the waiting tool call's exact reference. `--reject` takes that reference and
  your reason. `--answer` takes the waiting question's exact reference and the actual answer in
  its displayed question/answer format. Whichever answer the harness takes first, from its terminal or from Vox, wins, and the other side is told.
- `--file` takes an existing file path; `--note` adds your message. The file lands in the
  Session's node's files directory.

How Vox reaches each harness:

- **Claude Code:** through the tmux pane it runs in, so Claude Code must run inside tmux.
- **Codex:** through Codex's app-server, which `vox setup` keeps running. `--say` starts the
  session's next turn.
- **OpenCode:** through the plugin `vox setup` installs.

Driving does not launch a new harness or Session. Submitted input can start a turn in the existing
Session. A slash command that would start a new session,
such as `/clear` in Codex, is refused. A refusal names the session and the reason:

```text
vox: not delivered to codex-mac · 01a113e7: codex-mac does not trust you with drive; it trusts you to read only, or not at all
```

## Send a file out of a session

From inside the session, with the actual report saved as `report.pdf` in its current directory,
the agent sends that file to the members its node trusts with drive:

```sh
vox agent send ./report.pdf --note 'the numbers you asked for' --node claude-mac
```

Nothing is posted to the room. Each of those members' nodes pulls it into its files directory.

## Talk to one session

Addressing a known Session does not itself grant Drive. Use your local name for its node, a
slash, and its actual Session ID supplied by its owner or visible in `vox room sessions`. A
read-only viewer may not be able to discover it through the private list.

Construct `vox room post` with `family`, `--node robertgpt`, your message and `--to` holding
`claude-mac/` followed by the intended Session's actual ID from the list. Quote the combined
address as one argument.

The eligible session receives attributed context through its hook, as a message from a participant, not as its
operator's input. A message to the node without a session reaches every session of that node in
the room. A message to an ended session is refused. A file is addressed the same way:
use `vox share` with an existing file, `family`, `--node robertgpt` and that same actual
Session address in `--to`.

## Inspect room-message attention

With a current open Session selected from the actual list, add `--attention` to its complete
`vox room session` command. Keep the same room, Session and acting node. `--json` exposes the
source message ID, state, reason and any correlated answer. Use only the returned
`--attention-after` cursor for the next page of that same selection. This is a private report,
not room conversation; the receiver requires current Drive access.

- **Queued** explains what holds delivery, such as the next Codex turn, pause, a client that
  cannot currently admit input, or acceptance that is unknown.
- **Delivered** means context reached the harness; it does not claim a running model turn.
- **Answering** requires an observed running turn correlated to that input.
- **Answered** identifies that Session's correlated room answer.
- **Unavailable** names a source or recipient that can no longer be delivered.

A preparing page is still checking thread audience; an error or unknown state is not an empty
completed report. Follow its reason or refresh the current selection. Do not resend automatically
when acceptance is unknown. Session retention or a room/Session change can retire the selection.
In Vox.app this report is **Room message attention** inside the selected Session; **Refresh
attention**, **First attention page** and **Next attention page** read bounded pages. General and
read-only viewers do not show it.

## Sessions in the terminal interface

A room has a horizontal row with **General** and the Sessions you can drive, with bounded
navigation to more and ended Sessions. There is no combined All view or vertical Sessions list.
General shows room roots; Enter opens a thread with indented replies, Right pages replies, and
Left closes it. Tag selection includes that conversation's matching replies.

- Enter on a Session opens it, as does `:session` followed by its actual listed ID. `:general`
  returns to the room. Ended Sessions remain accessible through their navigation.
- In a Session you drive, the composer types into the session. A line starting with `/` is a slash
  command. `:interrupt` and `:stop` act on it. On a waiting line, `a` approves, `r` rejects, and a
  number picks an option. `:answer` takes one answer per part of a question, separated by `;`.
  `:share` followed by an existing file path sends that file. Enter or `d` on a line shows its details.
- A Session waiting on you is marked `! LABEL · waiting on you`.
- `:attention` opens the selected open Session's private report; `r` refreshes and `n` requests
  its next page. These controls require Drive.
- `:pause` and `:resume` operate on room agents, optionally followed by actual node names. See
  [pause and resume](rooms.md#pause-and-resume-agents) for the difference from direct Drive.
