# Vox user manual

Vox gives people and agents private rooms. Members you trust read what you write, reach the
services you share, and pull the files you offer, straight from your machine. No server holds a
copy.

This edition describes Vox **v0.4.5**. Run `vox --version` to identify your installed command.
The [evidence map](https://github.com/robertelee78/vox/blob/main/docs/manual-evidence.md) distinguishes
source review from retained real-use observations.

## Start here

[Your first shared room](first-room.md) takes you from installing Vox to a message read on both
machines. It branches before asking you to exchange node trust:

1. For several computers you own, [enroll the computers](keyring.md#my-computers) first; their
   managed nodes receive the computer policy. Use [individual node trust](keyring.md#what-a-keyring-entry-grants-read-or-read--drive)
   for another person or a deliberately narrower grant.
2. Create and join the same room, then confirm messages both ways. Connect directly where possible;
   add [room anchors](services.md#put-an-anchor-in-a-room-link) only when hosts cannot reach one another.
3. [Set up your harnesses](agents.md#set-up-a-machine), [bind the repository](sessions.md#bind-a-repository-from-your-terminal),
   and [verify actual communication](agents.md#confirm-that-a-message-reaches-the-agent).
4. Use [Sessions](sessions.md) for private activity/Drive and [pause](rooms.md#pause-and-resume-agents)
   to hold automatic room attention.

## Do a task

- [Install and update](install.md): install, update, run in a container, remove.
- [Identity and keyring](keyring.md): your nodes, and whom you trust.
- [Rooms and messages](rooms.md): create, join, post, read, retention, leave, end.
- [Reach a shared service](services.md): SSH or another service by its `.vox` address, and anchors.
- [Send and receive files](files.md): share a file or folder, pull a share.
- [Agent communications](agents.md): give an agent its own node and wire its harness.
- [Sessions](sessions.md): follow and drive an agent's session.
- [The Vox app on a Mac](app.md): where each thing is in the app.

## Look something up

- [Commands and local state](reference.md): the terms this manual uses, commands, node selection, files on disk,
  passphrase input, the terminal interface.
- [How Vox fits together](concepts.md): nodes, rooms, trust, services, anchors, and what
  encryption covers.

## Fix a problem

[Troubleshooting by symptom](troubleshooting.md) starts from the exact message you see. If it
does not settle the problem, [Get help safely](getting-help.md) says what to report and what to
keep private.

## How the examples work

Command blocks use the tutorial's concrete context: your node is `robertgpt`, the other person's
is `ann`, and the room is `family`. Follow the prerequisites before pasting them. When a value
is unique to your setup—a fingerprint, link, Session ID, waiting reference or path—the prose tells
you where to obtain it. Use the complete contextual command Vox prints, or construct it from those
actual values with the [shell-quoting rule](reference.md#commands-you-can-paste). There are no
reusable example credentials. Include the intended `--node` when moving a command to another terminal.

Passphrases are secrets. Keep them out of commands, screenshots and reports. A fingerprint is
public, but sharing it can link your activities.
