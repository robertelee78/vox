# Vox user manual

Applies to: all readers. Task chapters explicitly name the release they describe.

Vox gives people and agents private rooms, and lets trusted room members reach services and
files on each other's machines. This manual helps you make something work, understand what
changed, and recover when it does not.

## Start with your version

Run `vox --version`. The task chapters here describe **v0.4.3**, in which one daemon hosts
your nodes and every command names the node it acts as. On a Mac, it also brings
[the Vox app](app.md).

The manual follows the source repository. A newer manual revision is not evidence that a new
binary has been released. The website skins these same files; there is no separately edited
website edition.

## Make your first connection

1. [Install and update](install.md), including what a container host needs.
2. Follow [Your first shared room](first-room.md) with someone you already know.
3. Read [How Vox fits together](concepts.md) when you want to understand the model.

The first-room walkthrough is finished only when each person can read the other's message.
A successful local post or join is not enough.

The [command check](https://github.com/robertelee78/vox/blob/main/docs/manual-evidence.md#v043-command-check)
records the commands in these chapters run against a v0.4.3 build in isolated, same-host data
roots, at the commit it names. It does not claim that every task, network or agent integration has been exercised.

## Find a task

- [Identity and keyring](keyring.md): your nodes, comparing fingerprints, trusting, renaming, removing trust.
- [Rooms and messages](rooms.md): create, share the room link, join, read, reply, retention, leave, end.
- [Reach a shared service](services.md): SSH or another TCP or UDP service, by its `.vox` address; anchors.
- [Send and receive files](files.md): live availability, verified bytes, folders, safe destinations.
- [Agent communications](agents.md): `vox setup`, an agent's own node, hooks, delivery timing, claims and handoffs.
- [Sessions](sessions.md): follow an agent's session, and drive it, from the CLI or the TUI.
- [The Vox app on a Mac](app.md): the app's first run, its window and menus, and what it shows.
- [Commands and local state](reference.md): help, node selection, paths and automation.

## Find a symptom

Go straight to [Troubleshooting by symptom](troubleshooting.md) for a node that is not
attached, a pasted command the shell cut off, a refused join, an unreachable node or file, an unreadable message, or an agent that
has not responded. Start there before changing trust, restarting processes or recreating
anything.

If the checks do not settle it, [Get help safely](getting-help.md) describes what to collect
and what must stay private.

## Reading the examples

Every command here is whole: it pastes into zsh or bash and runs as shown, with nothing to fill
in. The examples follow one walkthrough. Your node is `robertgpt`, the other person's is `ann`, and
the room you share is `family`. A command names a room by its name, as `vox room list` shows it;
its ID works too. Where a command needs something that is yours alone, a fingerprint or a room
link, the example shows one in single quotes, and Vox prints the same command with yours in it:
copy that one. Keep the single quotes: a room link holds `&` and `?`, which a shell otherwise acts
on. A command block has no shell prompt prefix, so only the command is copied. Explanations say
which person or terminal runs it.

A **node** is one identity with its own keys, rooms, keyring and services; one machine can have
several, for example yours and one for each agent. Node names are lower case. The alias
`robertGPT` is ann's local name for your node; it is not a registered username.

Public fingerprints are not passwords, but sharing them publicly can link your activities.
Passphrases are secrets. Keep them out of commands, screenshots and issue reports.
