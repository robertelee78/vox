# Rooms and messages

Applies to: v0.2.10. The `vox room` commands ask a running daemon or TUI; they do not start one.
Examples use the `family` profile and `ROOM_ID` copied from its room list.

## Find the room you mean

```sh
vox room list --profile family
vox room roster --profile family ROOM_ID
```

Use the room ID or an unambiguous prefix accepted by the command. Do not assume a local name
is interchangeable with an ID in this release. The roster shows membership; your keyring
shows your trust decisions. Being present in one does not imply the other.

An empty list means this node holds no rooms. A closed room is different: the node holds it,
but has not opened it. See [closed-room recovery](troubleshooting.md#the-room-is-closed).

## Create or join

```sh
vox room create --profile family --name family
vox room invite --profile family ROOM_ID
```

Create asks for a new room passphrase and confirmation. Invite prints the address; send its
passphrase separately. The new member runs:

```sh
vox room join --profile family 'vox://…' --name family
```

Join asks for the room passphrase. With no terminal, provide it explicitly through
`--passphrase-file`; `-` selects stdin. Do not put a secret in a command-line argument or
paste it into an agent conversation merely to get through a prompt.

Confirm with `room list` and `room roster`, then compare and exchange trust as needed.
[Your first shared room](first-room.md) shows the complete sequence.

## Post and read

```sh
vox room post --profile family ROOM_ID "dinner at seven?"
vox room read --profile family ROOM_ID
```

The reader prints an entry hash, author and text. Author names are your local aliases, not
sender-chosen usernames. A local post is not proof that another member has received or read it.

For multiline text, omit the text argument or pass `-` and give the body on stdin. The message
is still a message, not a shell command for recipients to execute.

```sh
vox room post --profile family ROOM_ID --to ann "can you check the file?"
vox room post --profile family ROOM_ID --re FULL_ENTRY_HASH "yes, it arrived"
```

`--to` selects a member using your local alias or a supported fingerprint prefix. Addressing
does not turn a room into a private two-person message; other members who can read your posts
can still read it. `--re` names the message being answered.

## Follow messages or resume a reader

```sh
vox room tail --profile family ROOM_ID
vox room read --profile family ROOM_ID --json
vox room tail --profile family ROOM_ID --since FULL_ENTRY_HASH --json
```

Stop `tail` with Ctrl-C. For a resumed reader, retain the full entry hash from a previous
successful output. It is a cursor, not a room/member prefix. An unknown or invalid cursor
is an error; do not silently replace it with an arbitrary shorter ID.

JSON output is intended for programs. Keep data from a room separate from commands or
operator instructions in whatever program consumes it.

## Leave deliberately

Leaving removes the room from this node once the departure can be communicated. It can
interrupt work or access associated with this node's room. It does not remove other members
from your keyring or retrieve copies they already retained.

```sh
vox room leave --profile family ROOM_ID
```

The command waits up to 30 seconds for another member to take the departure. If nobody can,
it reports that the node will leave once someone can be told. A timeout is not a completed
remote notification. Keep the node online if you want the pending departure delivered, and
check its reported result and room list.

This chapter does not prescribe development `room end`, `room retention` or automatic room
expiry commands. See the [development guide](development.md) for that different surface.

Source: [released room commands and their arguments](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/cli.rs)
and [room read, join and leave behavior](https://github.com/robertelee78/vox/blob/8d95a381f14d6bbb45f714d75f64e57d2f5dbf96/crates/vox-tui/src/room_cli.rs).
