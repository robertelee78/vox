# Your first shared room

Applies to: v0.4.1. Allow a few minutes and keep both machines online. You need another person
whose identity you can compare through a way you already trust, such as meeting or a call.

You will each make a node, create and join a room, exchange trust, then confirm that a message
arrives **in each direction**. The first time takes these six steps; every later room you share
with the same person needs only steps 3 and 4, because trust carries over.

## 1. Each person creates an identity

On each person's machine:

```sh
vox --version
vox node create robertgpt
vox node attach robertgpt
```

Choose your own node name: lower-case letters, digits, `.`, `_` and `-`. `node create` asks for
the node's identity passphrase twice. Every node has one, so it may not be empty; this is not the
room passphrase. It prints the node's 52-character fingerprint and says `there is no backup
of a node`: if this machine is lost, you make a new node and the other person trusts that one
instead ([Identity and keyring](keyring.md#your-nodes)). `node attach` asks for the
passphrase once, starts the machine's daemon in the background if none runs, and keeps the
node running: `vox: node robertgpt attached`. `vox node list` then shows it as `attached`.

From now on, commands act as this node. With more than one node attached, name the node with
`--node robertgpt`. If you would rather see the daemon in a terminal, `vox daemon --node
robertgpt` runs it in the foreground instead of `node attach`; Ctrl-C stops it and detaches the
node.

## 2. Exchange and compare fingerprints

```sh
vox id
```

`vox id` prints the full fingerprint on one line. Send it to the other person and receive
theirs. Compare them through a way you already trust, such as in person or a call to a voice
you know. Do not accept a replacement fingerprint solely because an unknown sender says “it's
me”. A fingerprint is public, but deciding whose fingerprint it is is your decision.

Confirm the node answers:

```sh
vox room list
```

A new node prints `no rooms`. If you see `no vox daemon is running for this data root, so node
robertgpt is not attached`, run `vox node attach robertgpt` again; see
[the node is not attached](troubleshooting.md#the-node-is-not-attached).

## 3. One person creates the room and shares its link

The person creating the room runs:

```sh
vox room create --name family
vox room list
```

Vox asks for the new room's passphrase and confirmation. This is a separate secret from either
person's identity passphrase. `room create` prints `vox: created family`. Copy the room ID from
`vox room list`, for example `bmbkjywlgzar  family`. In examples below, replace `ROOM_ID` with it:

```sh
vox room link ROOM_ID
```

`room link` prints the **room link**, a `vox://…` address, on standard output. Its other lines
go to standard error: they describe how the link names this host, say `send the passphrase
another way than this address (in person, a call, a different app)`, and remind you that the
link grants nothing by itself.

Send the complete link to the other person. Send or say the room passphrase by a different way.
Keep a room member online for the join. If both hosts cannot reach each other directly, read
[when an anchor is needed](services.md#when-an-anchor-is-needed).

## 4. The other person joins

The other person runs this, replacing `ROOM_LINK` with the complete link received, in quotes:

```sh
vox room join 'ROOM_LINK'
vox room list
```

Enter the **room** passphrase at its prompt. Success prints `vox: joined family`. Joining keeps
the room on this node; it does not give either person permission to read the other's messages.
The name `family` is the room's own, the same for both people: the joiner does not choose one.
The room's creator, or an admin it named, can change it with `vox room rename`.

Both people can inspect membership:

```sh
vox room roster ROOM_ID
```

The two expected fingerprints should be present. A refused join and a timeout mean different
things; use the [join troubleshooting entries](troubleshooting.md#i-cannot-join-a-room)
instead of repeatedly changing the passphrase.

## 5. Each person trusts the other

The first person substitutes the full fingerprint of the other person, already compared:

```sh
vox trust add FULL_FINGERPRINT --name ann
vox trust list
```

The other person substitutes the first person's fingerprint and chooses their local alias:

```sh
vox trust add FULL_FINGERPRINT --name robertGPT
vox trust list
```

These are two independent decisions. Vox says what each one grants: the node `may now read what
you write in every room you share — now and later`, you read it `once it trusts you too`, and it
may `reach every service you bind to a room you are both in`. It is not restricted to this
room. A keyring change asks for your identity passphrase again once 30 minutes have passed since
you last gave it; `vox status` says how long is left (`keyring open 30m`).

## 6. Prove receipt both ways

The first person posts:

```sh
vox room post ROOM_ID "hello from robertGPT"
```

The second person reads, confirms that exact message appeared, and replies:

```sh
vox room read ROOM_ID
vox room post ROOM_ID "hello back from ann"
```

The first person then runs:

```sh
vox room read ROOM_ID
```

Each row is the entry hash, the author as you named them (`you` for your own), and the text.
You are done when each person sees the other's text. Local post success means the local node
accepted a post, not that someone else read it. If one side cannot read, check both keyrings,
membership and connectivity using [Troubleshooting](troubleshooting.md#we-joined-but-cannot-read-each-other).

## Use the terminal interface instead

`vox` with no arguments, or `vox tui`, opens the interactive client. It is a client of the same
daemon, so it runs beside the CLI and any agent sessions; you do not stop anything to use it.
`:attach` attaches your node if it is not attached. A TUI acts only as the node it was opened
with; to act as another, open another: `vox tui --node spare`.

On the room list: `:new` creates a room and `:join` takes a room link, both through a masked
passphrase prompt; Enter or `:open` opens the selected room; `t` or `:tunnels` lists live
tunnels; `k` or `:keyring` shows your keyring; Ctrl-N opens the next room with a message to you.
In a room, Tab moves between the timeline, the composer, the members pane and the Shared pane:

- In the composer, Enter sends. `@alice` in the text addresses alice: the message carries her
  whole fingerprint, as `vox room post --to` does.
- In the timeline, Up and Down select a message, Ctrl-R replies to it, quoting it, and Enter on a
  reply's quote jumps to the message it answers.
- In the Shared pane, each service shared in the room is listed with its commands; `y` copies the
  selected one to your clipboard. `:serve` shares one of yours there, picked from what listens on
  this machine.
- `:link` prints the room link, `:rename NAME` renames the room for every member (creator or
  admin only), `:close` closes it on this node, `:leave` leaves it and `:end` ends it for everyone
  (creator or admin only); each of the last two asks you to type its word first. `:back` or Esc
  returns to the list.

`:quit` exits. The members pane states trust by glyph and in words, such as `⇄ alice` and `trusted
both ways`; `t` on a member, or `:trust`, trusts it (see [Identity and keyring](keyring.md#trust-from-the-tui)).
`d` or `:decisions` on the room list shows the [decision record](reference.md#the-decision-record). Use the same fingerprints and room IDs whichever client you choose.

Next: [Rooms and messages](rooms.md), or [Identity and keyring](keyring.md).

Source: [command definitions](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/cli.rs),
[room operations](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/room_cli.rs)
and [TUI commands](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/state.rs).
