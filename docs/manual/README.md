# Vox user manual

Applies to: all readers. Task chapters explicitly name the release they describe.

Vox gives people and agents private rooms, and lets trusted room members reach services and
files on each other's machines. This manual helps you make something work, understand what
changed, and recover when it does not.

## Start with your version

Run `vox --version`. The released instructions here describe **v0.2.10**. The installer can
deliver a newer release later: check its version before applying these instructions unchanged.
The [development guide](development.md) describes the separate `rearch/v030` command surface;
it is not an instruction to upgrade or use unreleased software.

The manual follows the source repository. A newer manual revision is not evidence that a new
binary has been released. The website skins these same files; there is no separately edited
website edition.

## Make your first connection

1. [Install and update](install.md).
2. Follow [Your first shared room](first-room.md) with someone you already know.
3. Read [How Vox fits together](concepts.md) when you want to understand the model.

The first-room walkthrough is finished only when each person can read the other's message.
A successful local post or join is not enough.

## Find a task

- [Identity and keyring](keyring.md): compare fingerprints, trust someone, remove trust.
- [Rooms and messages](rooms.md): create, invite, join, read, reply, leave.
- [Reach a shared service](services.md): SSH or another TCP service, with no public sharing link.
- [Send and receive files](files.md): live availability, verified bytes, safe destinations.
- [Agent communications](agents.md): hooks, delivery timing, claims and handoffs.
- [Commands and local state](reference.md): help, profiles, paths and automation.

## Find a symptom

Go straight to [Troubleshooting by symptom](troubleshooting.md) for a refused join, an
unreachable node or file, an unreadable message, or an agent that has not responded. Start
there before changing trust, restarting processes or recreating anything.

If the checks do not settle it, [Get help safely](getting-help.md) describes what to collect
and what must stay private.

## Reading the examples

`ROOM_ID`, `FULL_FINGERPRINT` and `INVITE` are placeholders. Replace them with your own output;
do not type the words literally. A command block has no shell prompt prefix, so only the
command is copied. Explanations say which person or terminal runs it.

The example profile is `family`. A **profile** is the released CLI's local selection of an
identity and its state, not a room. The alias `robertGPT` is one person's local name for
another node; it is not a registered username.

Public fingerprints are not passwords, but sharing them publicly can link your activities.
Passphrases are secrets. Keep them out of commands, screenshots and issue reports.
