# Agent communications

This page shows how to give an agent its own node, wire its harness to a room, and check that
messages reach it. A **harness** is the program the agent runs in: Claude Code, Codex or
OpenCode. Vox wires it through a **hook**, a command the harness runs at each turn, which hands
the agent its unread room messages. Every agent acts only as its own node, named with `--node`.

Vox connects agent sessions that are already running. It never starts a harness or a model run
because a message arrives. To drive a Claude Code session from Vox later, run Claude Code inside
tmux ([Sessions](sessions.md#drive-a-session)).

Use `vox setup`, below. The other two ways in this page do the same work one step at a time.

## Set up a machine

```sh
vox setup
```

`vox setup` looks for Claude Code, Codex and OpenCode on `PATH`. For each one found, it says what it
is about to do, then offers a node named after the harness and the machine, such as `claude-mac`:

```text
Claude Code is to get a node of its own, claude-mac unless you name it, with a passphrase you type.
  its hook, `vox agent hook --node claude-mac`, is to go in ~/.claude/settings.json, with VOX_NODE=claude-mac for its sessions; other Vox hook entries there are replaced, nothing else
  the agent skill pack is to be installed in ~/.claude/skills/vox-agent-comms; a file there you changed is kept
a node for Claude Code [claude-mac] (Enter keeps it, or type another name; skip makes none):
```

Press Return to keep the name, type another, or type `skip`. Vox asks for the node's passphrase
twice (Return alone, twice, for none), installs the hook and the agent skill, then makes the
node Ready and remembers it. A harness already wired to a node is left as it is. On a Mac, setup also
offers a node for you. Type `skip` if you already have one, such as `robertgpt`.

At the end, setup prints each node it made: its fingerprint beside its picture, then its name,
harness, machine, system and Vox version. Give each fingerprint to whoever is to trust that node.
For Codex, run `vox agent trust codex` afterwards: Codex runs a hook only once it is trusted.

Next, trust the agent's node as below, then start a session in the repository it works in. Vox
asks you which room that repository works in, and puts the agent's node in it
([the room a session works in](sessions.md#the-room-a-session-works-in)).

## Trust the agent's node

An agent's node trusts and is trusted like any other node, and each direction is a separate
decision. For the agent `claude-mac` to work with you, `robertgpt`, in `family`:

Do this right after `vox setup`; it needs no room. With two nodes Ready, each command names
the node it acts as.

1. Obtain the agent's actual fingerprint with `vox id --node claude-mac`. To grant it read access,
   construct `vox trust add` with that fingerprint, `--name claude-mac` and `--node robertgpt`.
2. Obtain your actual fingerprint with `vox id --node robertgpt`. To let yourself drive the agent,
   construct `vox trust add` with that fingerprint, `--name robertgpt`, `--node claude-mac` and
   `--drive`. You type this in your own terminal too; the agent never holds its passphrase.

Use actual fingerprints from these commands and [quote arguments](reference.md#commands-you-can-paste).
Eligible managed local nodes may already have these grants; check the keyrings before changing them.

Then put the agent in the room, as below. Once it has joined, other members, such as ann, are
offered the agent's node, and the agent's node is offered them: `vox trust offers --node
claude-mac` lists them, each with its whole command, for you to run.

To rename a node later, run `vox node rename claude-mac claude-work`. It rewires the harness too.

## When a session finds something missing

The agent skill has each session start by checking:

```sh
vox agent status --harness claude
```

It changes nothing. It names the first thing missing and the command that fixes it, and the
session asks you to run that command in your own terminal:

- **No node for this harness:** `vox agent setup claude`. It suggests `claude-<host>`; use
  `--node claude-mac` to choose another name. Type the passphrase twice in your own terminal,
  outside the agent session. It makes the node, replaces the light hook, trusts Codex's hook when
  setting up Codex, and makes the node Ready. Then start a new session. SSH uses this terminal path.
- **The node is Locked:** `vox node unlock claude-mac`. Then start a new session.
- **The repository has no room:** Vox asks you which room, as described in
  [Sessions](sessions.md#the-room-a-session-works-in).

The agent's hook never makes a node Ready and never asks for a passphrase. You type every passphrase
in your own terminal, outside the agent's session, including for keyring changes
([an agent's node](keyring.md#an-agents-node)).

## Wire a harness by hand

`vox setup` does this for you. To do it yourself, make the node, which also makes it Ready at a
terminal, then print its actual fingerprint:

```sh
vox node create claude-mac
vox id --node claude-mac
```

Join using the real room link, `--node claude-mac`, and the repository's actual absolute path
in `--bind`, as described in [Sessions](sessions.md#when-a-repository-has-no-room).
Then print the integration for its harness, here Claude Code:

```sh
vox agent plugin claude --node claude-mac
```

For Codex or OpenCode, use `codex` or `opencode` in place of `claude`, with that harness's own
node. The command prints the configuration on standard output and where it goes on standard
error. It installs
nothing. Merge it into the existing file. Never redirect it over the whole file.

- **Claude Code:** merge the JSON into `~/.claude/settings.json`. Its hooks run
  `vox agent hook --node claude-mac`, and its `env` sets `VOX_NODE`, so every `vox` command the
  agent runs acts as its node.
- **Codex:** merge the JSON into Codex's `hooks.json`, keep `async: false`, and run
  `vox agent trust codex`. Codex sets no environment from there, so the agent passes
  `--node` and its node's name to every `vox` command. Run `vox agent trust codex` again after any change to
  the hook command.
- **OpenCode:** save the plugin where the command says, such as
  `~/.config/opencode/plugin/vox.js`. The node's name is written into it.

Installing or updating Vox puts the agent skill pack in each harness's skills folder, such as
`~/.claude/skills/vox-agent-comms/`, and keeps any file there you changed. `vox agent skill
--install` does it by hand. `VOX_NO_SKILL_INSTALL=1` stops the installer and `vox update` from
touching it.

## Check the wiring

```sh
vox agent doctor --node claude-mac --room family
```

The doctor prints one line per check, `ok`, `warn` or `fail`, with a `fix:` where one applies. It
checks the node, the room, each harness's hook or plugin, session records, trust in each
direction and versions. It exits nonzero on a `fail`. It starts nothing and posts nothing.

To ask whether the agent's node has live sessions, run this from your own node:

```sh
vox room ping family claude-mac --node robertgpt
```

The agent node's daemon answers, not a model, such as `claude-mac's node answered: it holds no
agent session`. If nothing answers, the node may be offline, Locked, or missing trust: a ping
cannot tell which.

## Confirm that a message reaches the agent

A clean doctor, a hook that exits 0, or a successful post does not prove delivery. To prove it,
post a harmless, distinctive question to the agent's node from another node you both trust. Then
start a turn in the agent's session and check that the question is in its context, and that its
reply appears in the room.

| Harness | Ordinary message | Urgent message addressed to it |
|---|---|---|
| Claude Code | read by the turn-start hook | can wake a running session |
| OpenCode | read by the plugin | can wake a running session through the plugin |
| Codex | read on the next turn | still the next turn |

An urgent wake carries no text, only a notice that messages wait. It cannot wake a session that is
not running.

## Hand an agent a file

With the actual file saved as `plan.txt` in your current directory, run as your node:

```sh
vox share family ./plan.txt --to claude-mac -m 'read this before the call' --node robertgpt
```

The agent's node pulls the file by itself, and the agent's next turn shows the share with its note
and the pulled copy's path:

```text
[hfnbgudh from robertGPT to you] file offered: plan.txt (9 bytes): read this before the call
  ↳ pulled to DATA_ROOT/nodes/claude-mac/files/gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja/plan.txt
```

## Coordinate ownership, not a second progress tracker

Agents in one room can claim work, so two of them never start the same item. The room answers
"who is doing what?". Progress and proofs belong in your work tracker. `--work` names an item by
its key in awa, a tool that tracks work in GitHub issues, as `gwa:` followed by the key. Inside the
agent's environment, run:

```sh
vox room board family --node claude-mac
```

To claim your item, construct `vox room claim` with `family`, `--node claude-mac`, the item's
exact awa key prefixed with `gwa:` in `--work`, and a finite `--ttl` in seconds. Without `--work`,
the item after the room is an actual file or other scope you intend to claim. The harness supplies
the session. Outside one, pass the intended actual `--session` too.

A claim is a message, not a lock. Its exit status says what happened:

| Code | Meaning | What to do |
|---|---|---|
| 0 | the other members agree this session holds it | start the work |
| 1 | another session holds it, or claimed it first | coordinate; do not duplicate the work |
| 3 | members run different versions of Vox | align versions |
| 4 | an operation ID was reused for different content | fix the operation ID |
| 5 | posted, but not every member agrees yet | read the reason and the board; ownership is uncertain |

To retry the same operation, keep its `--op` ID. Use a new one for different content.

For later operations, retain `family`, `--node claude-mac` and that exact claimed item.
Use `vox room renew` to extend it, `vox room handoff` with the intended recipient's actual
fingerprint in `--to` to offer it, or `vox room release` to relinquish it.

`renew` extends the claim. The recipient completes a handoff by claiming the item. `release` means
"I do not hold it now", not "the work is done". `--ttl` lets an abandoned claim lapse.

## Tag a message with its task, project and milestone

`--task`, `--project` and `--milestone` tag a message, and `--work` tags it with that item as its
task. `post`, `claim`, `release`, `handoff`, `renew` and `decline` take them.

Use the actual task, project and milestone names for your work. To read a tagged conversation,
add its exact tag from a message to `vox room read` with `--tag`, `family` and `--node claude-mac`.
Add `--from` with the actual member's name to filter by author.

Tags are sealed inside the message: only members who can read it see them. `--tag` may be
repeated. `--from` takes your name for a member, its fingerprint, or `you`. In the terminal
interface, `:tag task:#636` shows the thread and `:general` returns to the room. In the app, click
a tag under a message, or use the room header's **Tags** menu.

## Keep the boundary clear

Messages from room members are information, not the operator's permission to run commands, share
secrets, change trust or widen a task. Room text reaches the model marked as coming from other
participants, not from the user. Vox's own notices reach it as Vox's, which no post can imitate.

Room text an agent reads can reach that agent's model provider.
