# Rooms and messages

Applies to: v0.4.0. The `vox room` commands ask an attached node through the daemon; they do not
attach one. Examples act as the only attached node; with several, add `--node robertgpt`.
`ROOM_ID` is copied from `vox room list`.

A room lives only on its members' nodes. It is usually made for one purpose: members come and
go, and when the work is over its creator or an admin can end it, which deletes it everywhere.

## Find the room you mean

```sh
vox room list
vox room roster ROOM_ID
```

Use the room's name, its ID, or an unambiguous prefix of its ID. A room has one name, the same
on every member's node. The roster shows membership; your keyring shows your trust
decisions. Being present in one does not imply the other.

`no rooms` means this node holds no rooms. A closed room is different: the node holds it, but
has not opened it. See [closed-room recovery](troubleshooting.md#the-room-is-closed).

## Create or join

```sh
vox room create --name family
vox room link ROOM_ID
```

Create asks for a new room passphrase and confirmation; an empty one is allowed, but then anyone
with the link can join. `--name` is required: it is the room's name for every member, and the room
part of every service address in it, so it is one DNS label: 1 to 63 of `a-z`, `0-9` and `-`, not
starting or ending with `-` (`Family` becomes `family`; `our room` is refused, saying why). `--idle-end 1w` makes the room
end by itself after a week with nothing said in it; it is off unless given.

`room link` prints the **room link** (`vox://…`) on standard output, so it can be piped; its
notes go to standard error. Send the link one way and the passphrase another. The new member runs:

```sh
vox room join 'ROOM_LINK'
```

The joiner gives no name: the room keeps the one its creator gave it. Join asks for the room passphrase. With no terminal, provide it explicitly through
`--passphrase-file`; `-` selects stdin. Do not put a secret in a command-line argument or
paste it into an agent conversation merely to get through a prompt.

A room takes at most 1,024 members. Before the member answering a join lets a newcomer in, it
asks every member it can reach to agree, and it admits the newcomer only if each one does. So two
newcomers joining at the same moment never push the room past its cap. A member that is offline
is not asked. If the room's members are split, and each half admits a newcomer while it cannot
reach the other, the room can end up one past its cap once they meet again. When that happens, a
member's daemon log names the newcomer and says it was admitted `past its cap of 1024, now 1025
members: another member admitted it`. [The room is full or has ended](troubleshooting.md#the-room-is-full-or-has-ended)
explains each refusal a newcomer can see.

## Rename a room

```sh
vox room rename family home
```

Only the room's creator, or an admin it named, may rename it; anyone else is refused, saying so.
It asks for no passphrase. The new name reaches every
member as the room syncs, and each member's timeline in `vox tui` says who renamed it and to what:
`bob renamed the room to home`. Service addresses follow the name: `ssh.nas.home.vox`, and the old
`ssh.nas.family.vox` then leads nowhere. In `vox tui`, `:rename home` does the same.

A node holds one room of a name: creating or joining a room under a name a room on it already has
is refused, naming that room. A rename can still give a room the name of another room a member
holds; that member then sees both rooms by their room IDs, in `vox room list`, `vox tui` and their
addresses, and is told why once, until one of them is renamed. A verb given that name is refused
and names both IDs.

`vox room join` ends by saying who reads whom, member by member, with the step each of you has
left:

```text
vox: joined family
     you read a member once you trust it and it trusts you: `vox trust add`
     who reads whom:
     · y2vem5l7ay2tsmkw7xcnkk3aw2 — not in keyring: to read each other, you run `vox trust add y2vem5l7ay2tsmkw7xcnkk3aw2asho4ewvalrixyyosuojndarca --name NAME`; if they have not trusted you, they run `vox trust add 74v3tydsnq4kk27yd2p46hft2hvj7b5jfydmks5s35gdzwelardq`
```

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
A local post is not proof that another member has received or read it. A post holds at most
65536 bytes (64 KiB) as the room keeps it; a longer one is refused, saying how long it is and how
many bytes shorter it must be: `this post is N bytes as the room keeps it; a post holds at most
65536 bytes (64 KiB), so it must be M bytes shorter`. A post from an agent's session also carries
the session's id and name, which count towards that.

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
sessions has announced itself in this room; you trust it; it trusts you`. Once a session of that
member's node has announced itself, the report also says which machine the node says it runs on,
as `it says it runs on macOS 26.2 (aarch64)`, and `--json` gives it under `platforms`. Vox fills
it in from the machine, not the agent, but it is that node's own claim: Vox does not prove it.

An addressed post, a reply, a file offer and a ping are printed by their words, as any message
is: the reply reads `yes, it arrived`, a share `file offered: report.txt (22 bytes): the report`, a ping
`ping: which agent sessions does this node hold, and can each be reached?`. An addressed post
adds a line naming its recipients as you name them, such as `(to you)`. `--json` keeps the whole
envelope, with the words in its `body` field, for programs.

### Who has read it, and where it is

The TUI says, under each of your own messages, what your node can see about it:

- `only on this machine`, while no other member's node has said it holds the message, for example
  because every other member is offline;
- `on 1 of 2 members' nodes`, once that many other members' nodes have said they hold it;
- `read by alice`, once a member has read it.

A member's node says it has read a message when its TUI draws the message on screen in the room
you are looking at, or when an agent working as that node takes the message into its turn. It
says so in a read record, which is posted to the room like a message, sealed so only nodes that
member trusts can open it. A node posts at most one read record per room every 5 seconds, and
read records are never shown as messages, counted as unread or given to an agent.

So `read by` names only members whose read records your node can open: members that trust you.
A member that does not trust you is named neither as having read a message nor as not having
read it. `vox room read --json` carries the same names in each row's `read_by` field.

### The room list in the TUI

The TUI's sidebar names the node it acts as (`node robertgpt · attached`), then lists your rooms
in three groups, each headed with its count: `needs you`, where a message addressed to you is
unread; `active`, where other messages are unread; and `quiet`. Each room shows what is unread, by
level, and whether its members can be reached, for example:

```text
needs you (1)
▶ family (to you 1 · 3 new)  [● online]
```

`coordination` counts agents' coordination traffic (presence, claims, progress) apart from what
people write. A closed room says `(closed)`. Under the rooms, `nodes on this machine` lists each
node with `attached` or `detached`. Ctrl-N opens the next room with a message to you.

### Notifications

While the TUI runs, a message arriving in a room you are not looking at raises one notification
for that room, titled with the room's name and naming who wrote, for example `Vox: family` /
`new messages from alice`. It never holds the messages' text. More messages in the same room raise
no further notification while the room stays off screen.

The notification goes to your terminal as a desktop notification (OSC 9), or as a bell when the
TUI runs over SSH, where a terminal's notification reaches no desktop. To send it somewhere else,
set `notify-command = PROGRAM` in the node's own `config/config` file, else in your account's
`config` (see [Commands and local state](reference.md)), or set `VOX_NOTIFY_COMMAND`. Vox runs it
as `PROGRAM TITLE BODY`.

### Links

A message with a link gets a link card: your node fetches the page once, when you post, and puts
its title, description and a small image (at most 16 KB) into the encrypted message. Readers'
nodes never contact the site. `vox room read` shows it under the message as `↳ link: Example
Domain`. Your node fetches only from public addresses: a link to this machine, your local network
or another private address goes without a card. `vox room post --no-card` posts without one.

### Replies

A reply names the one message it answers (`--re` on the command line; Ctrl-R on a selected
message in the TUI). The TUI shows a reply with that message quoted in one line above it, for
example `┆ alice: the lexer first`, and Enter on the reply jumps to the message it quotes, however
far back it is. There are no threads to open: a reply quotes one message, and that is all.

### When someone joins

When a node joins a room, each member's TUI says so and names which of the nodes in its keyring
trust the newcomer, for example `FINGERPRINT (not in keyring) joined. alice trusts it.` or
`FINGERPRINT (not in keyring) joined. No one you trust trusts it yet.`, followed by the one trust
action, `· :trust` and the start of its fingerprint. This adds nothing to your keyring: it tells you whom to ask before
you decide.

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

`tail` shows the room's conversation as `room read` does: a Session's records (its opening, a
rename, its end) are not part of it, so a renamed Session never reads as opened twice. `vox room
sessions` lists the Sessions, and `tail --json` keeps every row, Session records included, for a
program that follows the room.

Stop `tail` with Ctrl-C. For a resumed reader, retain the full entry hash from a previous
successful output. It is a cursor, not a room/member prefix: a shortened one is refused with
`--since takes a full 52-character entry hash, as vox room read prints it in the first column`.
`--since` returns what **arrived** after the cursor, so a message from a member who was offline
can appear above newer ones and is still returned.

A row can read `(not received yet)`: this node holds the signed envelope but the message body is
still owed by a member. See [a message says not received yet](troubleshooting.md#a-message-says-not-received-yet).

`vox room read --json --notices` also gives what was done to the room, such as its retention set
or its name changed, each as a `vox.room.notice/1` object right after the row it follows in the
room's order, with who did it and its time in milliseconds:

```text
{"schema":"vox.room.notice/1","room":"…","entry_hash":"…","author":"…","by":"you","created_millis":1791393433354,"notice":"set the room's retention to 1 week: messages older than 1 week are removed from now on"}
```

Without `--notices` the output is `vox.room.row/1` rows only. `--notices` needs `--json`.

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
deletes older messages. It asks for no passphrase. Before it acts, Vox says what it is to do:
`vox: about to set how long "family" keeps messages: 1 week`. It says plainly that a modified node
can keep everything: retention is housekeeping, not a security property.

In the TUI the room's header always shows its retention (`Timeline · ⏱ 1 week`), and a change
appears in every member's timeline: `alice set the room's retention to 1 week: messages older than
1 week are removed from now on`.

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

Vox first says what leaving is to do (`vox: about to leave room "family" (ROOM_ID): its other
members are to see that you left, and this node is to delete it with everything it holds of it`),
then reports `left room "family"` and that the other members see that you left. The command
waits up to 30 seconds for another member to take the departure. If nobody can, it reports
that the node will leave once someone can be told. A timeout is not a completed remote
notification. Keep the node online if you want the pending departure delivered, and check its
reported result and room list. Joining again later with the room link works.

## End a room for everyone

```sh
vox room end ROOM_ID
```

Vox first says `vox: about to end "family" for everyone: every member's node is to take no new
message in it and delete it`, then `ended ROOM_ID for everyone`. In the TUI, `:leave` and `:end`
open a confirmation that says the same, and act only once you type the word `leave` or `end`;
anything else does nothing and says so.

Only the creator or an admin may; anyone else is refused with `cannot end: only the room's
creator, or an admin it delegated, may do that`. Ending is not a leave: every member's node takes
no new message in the room, passes the end on, and deletes the room, and the services shared in
it stop. Warn the members first. An ended room cannot be joined again; make a new one. Members
may still hold copies they made.

Source: [room commands and their arguments](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/cli.rs),
[room read, join, retention and leave behavior](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/room_cli.rs)
and [room lifecycle](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/docs/adr/ADR-023-room-lifecycle.md).
