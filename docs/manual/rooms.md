# Rooms and messages

Applies to: v0.3.0. The `vox room` commands ask an attached node through the daemon; they do not
attach one. Examples act as the only attached node; with several, add `--node robertgpt`.
`ROOM_ID` is copied from `vox room list`.

A room lives only on its members' nodes. It is usually made for one purpose: members come and
go, and when the work is over its creator or an admin can end it, which deletes it everywhere.

## Find the room you mean

```sh
vox room list
vox room roster ROOM_ID
```

Use the room ID or an unambiguous prefix accepted by the command. Do not assume a local name
is interchangeable with an ID. The roster shows membership; your keyring shows your trust
decisions. Being present in one does not imply the other.

`no rooms` means this node holds no rooms. A closed room is different: the node holds it, but
has not opened it. See [closed-room recovery](troubleshooting.md#the-room-is-closed).

## Create or join

```sh
vox room create --name family
vox room invite ROOM_ID
```

Create asks for a new room passphrase and confirmation; an empty one is allowed, but then anyone
with the link can join. Without `--name` the local name is `room`. `--idle-end 1w` makes the room
end by itself after a week with nothing said in it; it is off unless given.

`room invite` prints the **room link** (`vox://…`) on standard output, so it can be piped; its
notes go to standard error. Send the link one way and the passphrase another. The new member runs:

```sh
vox room join 'ROOM_LINK' --name family
```

Join asks for the room passphrase. With no terminal, provide it explicitly through
`--passphrase-file`; `-` selects stdin. Do not put a secret in a command-line argument or
paste it into an agent conversation merely to get through a prompt.

Joining a room your node already holds updates where it finds the room's members; it is not
refused. Confirm with `room list` and `room roster`, then compare and exchange trust as needed.
[Your first shared room](first-room.md) shows the complete sequence.

## Post and read

```sh
vox room post ROOM_ID "dinner at seven?"
vox room read ROOM_ID
```

Each row is `ENTRY_HASH AUTHOR TEXT`. Author names are your local aliases, `you` for your own
posts, or the fingerprint of a node you have not named; they are never sender-chosen usernames.
A local post is not proof that another member has received or read it.

For multiline text, omit the text argument or pass `-` and give the body on stdin. Each further
line of a message is printed behind `  | `, so no message can print a row that looks like another
author's. The message is still a message, not a shell command for recipients to execute.

```sh
vox room post ROOM_ID --to ann "can you check the file?"
vox room post ROOM_ID --re FULL_ENTRY_HASH "yes, it arrived"
```

`--to` selects a member using your local alias or its fingerprint; a name that is not a member
is refused. Addressing does not turn a room into a private two-person message; other members
who can read your posts can still read it. `--re` names the message being answered. The poster
is told what its node can see about each addressed member, for example `vox: to ann: none of its
sessions has announced itself in this room; you trust it; it trusts you`.

An addressed post, a reply, a file offer and a ping are printed by their words, as any message
is: the reply reads `yes, it arrived`, a file offer `file offered: report.pdf (18 bytes)`, a ping
`ping: which agent sessions does this node hold, and can each be reached?`. An addressed post
adds a line naming its recipients as you name them, such as `(to you)`. `--json` keeps the whole
envelope, with the words in its `body` field, for programs.

### Characters you cannot see

`room read` shows characters a reader could not otherwise see instead of printing them, each as
its code point: a zero-width space appears as `⟨U+200B⟩`, and a character that reverses text
direction, such as U+202E, as `⟨U+202E⟩`. Treat one inside a name, link or command as a warning
sign: the sender's text is not what it first looks like.
`--json` output keeps the original characters, JSON-escaped.

## Follow messages or resume a reader

```sh
vox room tail ROOM_ID
vox room read ROOM_ID --json
vox room read ROOM_ID --since FULL_ENTRY_HASH --json
```

Stop `tail` with Ctrl-C. For a resumed reader, retain the full entry hash from a previous
successful output. It is a cursor, not a room/member prefix: a shortened one is refused with
`--since takes a full 52-character entry hash, as vox room read prints it in the first column`.
`--since` returns what **arrived** after the cursor, so a message from a member who was offline
can appear above newer ones and is still returned.

A row can read `(not received yet)`: this node holds the signed envelope but the message body is
still owed by a member. See [a message says not received yet](troubleshooting.md#a-message-says-not-received-yet).

JSON output is intended for programs. Keep data from a room separate from commands or
operator instructions in whatever program consumes it.

## How long the room keeps messages

A room keeps messages forever unless its creator, or an admin the creator named, sets a
retention:

```sh
vox room retention ROOM_ID 1w
```

The duration is `1h`, `1w`, `1m` (a month), a number of seconds, or `forever`. It applies to
**everything already in the room**, on every member as the change reaches them: shortening it
deletes older messages. It always asks for your identity passphrase. Vox says plainly that a
modified node can keep everything: retention is housekeeping, not a security property.

A member who is not an admin can only keep less on its own node. The same command then reports
`set your own retention for … this node keeps its messages for 1 hour` and that nothing changed
for anyone else. The shorter of the room's and the node's retention wins.

## Admins

```sh
vox room admin list ROOM_ID
vox room admin add ROOM_ID FULL_FINGERPRINT
vox room admin remove ROOM_ID FULL_FINGERPRINT
```

The creator is always an admin. Only the creator adds or removes admins. An admin may set the
room's retention and end the room. Being an admin grants no reading: who reads whom is still
each node's trust decision.

## Leave deliberately

Leaving removes the room from this node once the departure can be communicated. It can
interrupt work or services associated with this node's room. It does not remove other members
from your keyring or retrieve copies they already retained.

```sh
vox room leave ROOM_ID
```

Vox reports `left room "family"` and that the other members see that you left. The command
waits up to 30 seconds for another member to take the departure. If nobody can, it reports
that the node will leave once someone can be told. A timeout is not a completed remote
notification. Keep the node online if you want the pending departure delivered, and check its
reported result and room list. Joining again later with the room link works.

## End a room for everyone

```sh
vox room end ROOM_ID
```

Only the creator or an admin may; anyone else is refused with `cannot end: only the room's
creator, or an admin it delegated, may do that`. Ending is not a leave: every member's node takes
no new message in the room, passes the end on, and deletes the room, and the services shared in
it stop. Warn the members first. An ended room cannot be joined again; make a new one. Members
may still hold copies they made.

Source: [v0.3.0 room commands and their arguments](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/cli.rs),
[room read, join, retention and leave behavior](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/crates/vox-tui/src/room_cli.rs)
and [room lifecycle](https://github.com/robertelee78/vox/blob/82523cebc870a29e0947b0cb7c20b4563d233966/docs/adr/ADR-023-room-lifecycle.md).
