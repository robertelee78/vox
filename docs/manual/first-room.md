# Your first shared room

Applies to: v0.3.1. Allow a few minutes and keep both machines online. You need another person
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
the node's identity passphrase twice. An empty one is allowed, but one is encouraged; this is not
the room passphrase. It prints the node's 52-character fingerprint. `node attach` asks for the
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
vox room join 'ROOM_LINK' --name family
vox room list
```

Enter the **room** passphrase at its prompt. Success prints `vox: joined family`. Joining keeps
the room on this node; it does not give either person permission to read the other's messages.
The name `family` is local: the two people may choose different names for the same room.

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
you last gave it.

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
`:attach` attaches your node if it is not attached, and `:node NAME` acts as another of your
nodes.

On the room list: `:new` creates a room and `:join` takes a room link, both through a masked
passphrase prompt; Enter or `:open` opens the selected room; `t` or `:tunnels` lists live
tunnels. In a room: `:link` prints its link, `:close` closes it on this node, `:leave` leaves
it, `:end` ends it for everyone (creator or admin only), and `:back` or Esc returns to the list.
`:quit` exits. The members pane states trust in words, such as `trusted · reads you`. Use the
same fingerprints and room IDs whichever client you choose.

Next: [Rooms and messages](rooms.md), or [Identity and keyring](keyring.md).

Source: [command definitions](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/cli.rs),
[room operations](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/room_cli.rs)
and [TUI commands](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/state.rs).
