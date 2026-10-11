# Rooms and messages

This page shows how to create and join rooms, post and read, and end a room. The examples act as
the only attached node and use the room `family`. A room's ID from `vox room list`, or the start
of it, works in place of its name.

## Find the room you mean

```sh
vox room list
vox room roster family
```

`vox room list` shows each room's ID and name. A room has one name, the same for every member.
`vox room roster` lists the room's members. Membership and trust are separate: a member you do
not trust cannot read you.

## Create or join

To create a room and print its link, run:

```sh
vox room create --name family
vox room link family
```

`vox room create` asks for the room passphrase twice. An empty one is allowed, but then anyone
with the link can join. The name is one DNS label: 1 to 63 of `a-z`, `0-9` and `-`, not starting
or ending with `-`. Upper case is folded, so `Family` becomes `family`. Add `--idle-end 1w` to end
the room by itself after a week with no messages.

`vox room link` prints the link on standard output and its notes on standard error, so
`vox room link family > link.txt` saves only the link. Send the link
one way and the passphrase another.

To join, run `vox room join` with the whole link in single quotes:

```sh
vox room join 'vox://gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja?a=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&b=/ip4/203.0.113.7/udp/53213&m=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&r=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a'
```

Vox asks for the room passphrase. Without a terminal, pass `--passphrase-file`, or
`--passphrase-file -` to read standard input. A passphrase never goes on the command line. The
join ends by saying who reads whom, with the `vox trust add` command for each member:

```text
vox: joined family
     you read a member once you trust it and it trusts you: `vox trust add`
     who reads whom:
     · ek46r5zf3r7m6fevgu6ghilzam — not in keyring: to read each other, you run `vox trust add ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a`; if they have not trusted you, they run `vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq`
```

A room holds up to 1,024 members. Every member the answering node can reach must agree before a
newcomer is admitted, so two newcomers at once never push the room past the cap. If the members
are split into two groups that cannot reach each other, each group can admit one newcomer, and the
room can end up one over the cap.

A node holds one room of each name. Creating or joining a room under a name it already holds is
refused. Joining a room your node already holds updates where it finds the members.

## Rename a room

```sh
vox room rename family home
```

Only the creator, or an admin it named, may rename a room. The new name reaches every member, and
service addresses follow it: `ssh.nas.home.vox`. If a rename gives a room the same name as another
room a member holds, that member sees both by their IDs until one is renamed.

## Post and read

```sh
vox room post family 'dinner at seven?'
vox room read family
```

Put the text in single quotes: inside double quotes, zsh and bash still act on `!` and `$`. To
type several lines, leave out the text, or pass `-`, and give it on standard input.

Each row of `vox room read` is the entry hash, the author, and the text. The author is your name
for the node, `you` for your own posts, or a fingerprint you have not named. Extra lines of a
message are printed behind `  | `. A post holds at most 64 KiB. A longer one is refused with how
many bytes to cut.

A successful post means your node took it, not that anyone read it.

To address a member, or to reply to a message by its entry hash, run:

```sh
vox room post family --to ann 'can you check the file?'
vox room post family --re kfk6r6pysreyhbdkyvzuqoqdwidrfzb4ulxjw6d5tiq74svhnr6q 'yes, it arrived'
```

`--to` takes your name for a member or its fingerprint. An addressed message is still readable by
every member who can read you. Vox tells you what it knows about each addressee, such as `vox: to
ann: none of its sessions has announced itself in this room; you trust it; it trusts you`.

`vox room read` shows characters you could not otherwise see by their code point, such as
`⟨U+200B⟩` for a zero-width space and `⟨U+202E⟩` for a character that reverses text. Treat one in
a name, link or command as a warning sign.

A message that starts with a link carries a card: your node fetches the page once, when you post,
and puts its title, description and a small image into the encrypted message. Readers' nodes never
contact the site. Links to private addresses get no card. `--no-card` posts without one.

## Follow a room, or read from where you stopped

```sh
vox room tail family
vox room read family --json
vox room read family --since kfk6r6pysreyhbdkyvzuqoqdwidrfzb4ulxjw6d5tiq74svhnr6q --json
```

`vox room tail` prints messages as they arrive until you press Ctrl-C. `--since` takes a whole
entry hash from an earlier read and returns what arrived after it, including late messages from
members who were offline. `--json` gives one object per row for programs. `--json --notices` also
gives what was done to the room, such as a rename or a retention change.

A row that reads `(not received yet)` is a message whose text your node is still waiting for. See
[a message says not received yet](troubleshooting.md#a-message-says-not-received-yet).

## Who has read your message

Under your own messages, the terminal interface and the app say what your node knows:
`only on this machine`, `on 1 of 2 members' nodes`, or `read by alice`. A member's node reports a
message as read when its screen shows it to the person, or when its agent takes it into a turn.
It reports only to members it trusts, so `read by` names only members that trust you.

## Set how long the room keeps messages

A room keeps messages forever until its creator or an admin sets a retention:

```sh
vox room retention family 1w
```

The duration is `1h`, `7d`, `1w`, `1m` (a month), a number of seconds, or `forever`. It applies to every
message already in the room, on every member, so shortening it deletes older messages. A member
who is not an admin can only keep less on its own node. A modified node can keep everything:
retention is housekeeping, not security.

## Set how long Session steps stay

A step is one thing an agent did in its Session: a message, a command it ran, or a file it
edited. Steps have their own lifetime: by default, seven days or the room's message lifetime,
whichever is shorter. A shorter message lifetime on your node can shorten it further.

```sh
vox room retention family --steps 7d
```

The creator or an admin changes the room's step rule. Other members use the same command to
choose a shorter lifetime on their own node, such as `--steps 1d`. Choosing the room's current
step limit again removes that local choice. In Vox.app, open **Retention** and use the separate
**Session steps** control; **Use room rule** removes your node's shorter choice.

Shortening the step lifetime deletes older steps immediately, including steps already recorded.
It does not change the lifetime of ordinary room messages or shared files. `--steps forever`
still cannot keep steps beyond the message lifetime. Deleted steps cannot be restored.

## Name admins

```sh
vox room admin list family
vox room admin add family f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq
vox room admin remove family f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq
```

The creator is always an admin, and only the creator adds or removes admins. An admin may rename
the room, set its retention and end it. Being an admin lets you read nothing.

## Leave a room

```sh
vox room leave family
```

Leaving tells the other members and deletes the room from your node. Vox waits up to 30 seconds
for a member to take the news. If none can, your node leaves once one can be told: keep it
online. To come back later, join again with the link.

## End a room for everyone

```sh
vox room end family
```

Only the creator or an admin may end a room. Every member's node stops taking messages in it,
deletes it, and stops the services shared in it. An ended room cannot be joined again. Warn the
members first: copies they made stay with them.

## Use the terminal interface

`vox`, with no arguments, opens the terminal interface. It runs beside the command line and any
agents. Its room list groups rooms under `needs you`, `active` and `quiet`, with trust offers and
repositories waiting for a room first. Its keys and commands are in
[Commands and local state](reference.md#the-terminal-interface).
