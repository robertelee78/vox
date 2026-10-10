# Vox user manual

Vox gives people and agents private rooms. Members you trust read what you write, reach the
services you share, and pull the files you offer, straight from your machine. No server holds a
copy.

## Start here

[Your first shared room](first-room.md) takes you from installing Vox to a message read on both
sides, with someone you already know. Do it first.

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

Every command is whole: it pastes into zsh or bash as it stands, with nothing to fill in. The examples follow one story: your node
is `robertgpt`, the other person's is `ann`, and the room you share is `family`. A fingerprint or
a room link in an example is a real one in single quotes. Yours differ, and Vox prints the same
command with yours in it, ready to copy. Keep the single quotes: a link holds `&` and `?`, which a
shell otherwise acts on.

Passphrases are secrets. Keep them out of commands, screenshots and reports. A fingerprint is
public, but sharing it can link your activities.
