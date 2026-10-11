# Sessions

This page shows how to put an agent's sessions in the right room, follow what a session does,
and drive it. To drive a session, the agent's node must trust your node with **read + drive**
([Identity and keyring](keyring.md#what-a-keyring-entry-grants-read-or-read--drive)).

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

Set the step lifetime separately with `vox room retention family --steps 7d`, or the **Session
steps** control in Vox.app's **Retention** sheet. An admin sets the room rule; other members may
choose a shorter lifetime for their own node. **Use room rule** removes that local choice.
Shortening it deletes older steps immediately and leaves ordinary messages and shared files
under their own retention. See [Session step retention](rooms.md#set-how-long-session-steps-stay).

The session's node decides who sees inside:

- A member it trusts with **read + drive** reads the Session and can drive it.
- Every other member sees only the Session's label and whether it is open or ended, with
  `Only members claude-mac trusts with drive see inside this Session.`
- A member whose drive is taken back keeps what it already read, and reads nothing written
  afterwards.

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
room opens. The session
stays in that room for its whole life.

The map holds room passphrases. It must be readable by your account only, or Vox refuses to use
it. Every node in the data root uses it, so each of them can use every passphrase in it.

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
- **In the session:** paste the room's link. The agent never asks for the passphrase. It gives you
  back a whole command, with your link and the directory in it, to run in your own terminal:

  ```sh
  vox room join 'vox://gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja?a=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&b=/ip4/203.0.113.7/udp/53213&m=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&r=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a' --node claude-mac --bind /opt/vox
  ```

  It asks for the passphrase, joins the agent's node, and saves the directory in the room map. If
  the map held something for the directory, it is replaced, and the command says what. The agent
  then moves its session there with `vox agent room`.
- **To say no:** choose **Not this repo** in the app, or say no in the session. The agent then runs
  `vox agent room --none`. The map records the directory as `room none`, and no session started
  there asks again. Delete that block to be asked again.

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
vox room sessions family
vox room session family 3f0c25bf
vox room session family 3f0c25bf --details
```

`vox room sessions` lists `open` and `ended` Sessions by label. With `--json`, each has
`can_drive`, which says whether you may drive it.

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

`--details` adds each entry's whole input and output. `--json` prints one object per line.

## Drive a session

Each input reaches exactly the session named, or is refused with the reason. The harness's own
terminal keeps working beside it.

```sh
vox room session family 3f0c25bf --say 'run the tests again'
vox room session family 3f0c25bf --slash /compact
vox room session family 3f0c25bf --interrupt
vox room session family 3f0c25bf --stop
vox room session family 3f0c25bf --approve toolu_2
vox room session family 3f0c25bf --reject toolu_3 'not that file'
vox room session family 3f0c25bf --answer toolu_q 'colour=blue'
vox room session family 3f0c25bf --file ./notes.txt --note 'for your review'
```

- `--say` types the text as the operator and submits it. `--slash` sends a slash command.
  `--interrupt` is Esc. `--stop` is Ctrl-C.
- `--approve`, `--reject` and `--answer` answer the waiting request with that ref. Whichever answer
  the harness takes first, from its terminal or from Vox, wins, and the other side is told.
- `--file` sends the session a file, which lands in its node's files directory.

How Vox reaches each harness:

- **Claude Code:** through the tmux pane it runs in, so Claude Code must run inside tmux.
- **Codex:** through Codex's app-server, which `vox setup` keeps running. `--say` starts the
  session's next turn.
- **OpenCode:** through the plugin `vox setup` installs.

Driving never starts a session or a model run. A slash command that would start a new session,
such as `/clear` in Codex, is refused. A refusal names the session and the reason:

```text
vox: not delivered to codex-mac · 01a113e7: codex-mac does not trust you with drive; it trusts you to read only, or not at all
```

## Send a file out of a session

From inside the session, the agent sends a file to the members its node trusts with drive:

```sh
vox agent send ./report.pdf --note 'the numbers you asked for' --node claude-mac
```

Nothing is posted to the room. Each of those members' nodes pulls it into its files directory.

## Talk to one session

Any member may address one session without drive: your name for its node, a slash, and the
session as `vox room sessions` names it.

```sh
vox room post family --to claude-mac/3f0c25bf 'the lexer is yours'
```

The session sees the message in full at its next turn, as a message from a participant, not as its
operator's input. A message to the node without a session reaches every session of that node in
the room. A message to an ended session is refused. A file is addressed the same way:
`vox share family ./notes.txt --to claude-mac/3f0c25bf`.

## Sessions in the terminal interface

In a room, the Sessions pane lists `General` (the room's conversation), `All` (the conversation
with each Session's opening and end, and the entries of Sessions you drive), each open Session,
and `Ended (N)`.

- Enter on a Session opens it, as does `:session 3f0c25bf`. `:general` and `:all` go back.
- In a Session you drive, the composer types into the session. A line starting with `/` is a slash
  command. `:interrupt` and `:stop` act on it. On a waiting line, `a` approves, `r` rejects, and a
  number picks an option. `:answer` takes one answer per part of a question, separated by `;`.
  `:share PATH` sends a file. Enter or `d` on a line shows its details.
- A Session waiting on you is marked `! claude-mac · 3f0c25bf · waiting on you`.
- In a Session you cannot drive, there is no composer, and the TUI says `you cannot drive this
  Session: claude-mac has not given you drive`.
