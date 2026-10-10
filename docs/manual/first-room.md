# Your first shared room

Applies to: v0.4.3. Allow a few minutes and keep both machines online. You need another person
whose identity you can compare through a way you already trust, such as meeting or a call.

You will each make a node, one of you makes a room and the other joins it, you trust each other,
then you confirm that a message arrives **in each direction**. The first time takes these six
steps; every later room you share with the same person needs only steps 3 and 4, because trust
carries over. The examples are robertgpt's machine and ann's; use your own names.

## 1. Each person creates an identity

On each person's machine, in a terminal:

```sh
vox --version
vox node create robertgpt
```

Choose your own node name: lower-case letters, digits, `.`, `_` and `-`. `node create` asks for
the node's **identity passphrase** twice. It unlocks this node on this machine; it is not the room
passphrase, which comes later. You may leave it empty (Enter twice): Vox then says that the node's
key is kept unencrypted, so anyone who can read its data folder can act as it, and encourages a
passphrase.

It prints the node's 52-character fingerprint and says `there is no backup of a node`: if this
machine is lost, you make a new node and the other person trusts that one instead
([Identity and keyring](keyring.md#your-nodes)). Run at a terminal, it also attaches the node at
once, starting the machine's daemon in the background if none runs, and remembers it, so the node
is attached again by itself after a restart: `vox: node robertgpt attached (kept)`. `vox node
list` shows it as `attached`. (Made by a script, with no terminal, the node is only made; `vox node
attach robertgpt` then attaches it.)

From now on, commands act as this node. With more than one node attached, name it with
`--node robertgpt`. If you would rather see the daemon in a terminal, `vox daemon --node
robertgpt` runs it in the foreground; Ctrl-C stops it and detaches the node.

Confirm the node answers:

```sh
vox room list
```

A new node prints `no rooms`. If you see `no
vox daemon is running for this data root, so node robertgpt is not attached`, run `vox node attach
robertgpt`; see [the node is not attached](troubleshooting.md#the-node-is-not-attached).

## 2. Exchange and compare fingerprints

```sh
vox id
```

`vox id` prints the full fingerprint on one line. Send it to the other person and receive
theirs. Compare them through a way you already trust, such as in person or a call to a voice
you know. Do not accept a replacement fingerprint solely because an unknown sender says “it's
me”. A fingerprint is public, but deciding whose fingerprint it is is your decision.

## 3. One person creates the room and shares its link

The person creating the room, here robertgpt, runs:

```sh
vox room create --name family
vox room link family
```

Vox asks for the new **room passphrase** and its confirmation. This is a separate secret from
either person's identity passphrase. `room create` prints `vox: created family`, and `vox room
list` then shows the room with its ID, for example `gkpeyuly4m4e  family`. A command takes the
room's name or its ID.

`room link` prints the **room link**, a `vox://…` address, on standard output. Its other lines
go to standard error: they describe how the link names this host, say `send the passphrase
another way than this address (in person, a call, a different app)`, and remind you that joining
grants nothing by itself.

Send the complete link to the other person. Send or say the room passphrase by a different way.
Keep a room member online for the join. If both hosts cannot reach each other directly, read
[when an anchor is needed](services.md#when-an-anchor-is-needed).

## 4. The other person joins

The other person, here ann, runs `vox room join` with the complete link received, inside single
quotes. With the link from step 3 it reads:

```sh
vox room join 'vox://gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja?a=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&b=/ip4/203.0.113.7/udp/53213&m=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&r=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a'
```

Type `vox room join '`, paste the link, and type the closing `'`. The quotes matter: without
them, the shell takes the link's `&` as the end of the command, and the join is cut off. Enter the
**room** passphrase at its prompt. Success prints `vox: joined family`, then who reads whom, with
the command that trusts each member:

```text
vox: joined family
     you read a member once you trust it and it trusts you: `vox trust add`
     who reads whom:
     · ek46r5zf3r7m6fevgu6ghilzam — not in keyring: to read each other, you run `vox trust add ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a`; if they have not trusted you, they run `vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq`
```

Joining keeps the room on this node; it does not give either person permission to read the
other's messages. The name `family` is the room's own, the same for both people: the joiner does
not choose one. The room's creator, or an admin it named, can change it with `vox room rename`.

Both people can inspect membership:

```sh
vox room roster family
```

The two expected fingerprints should be present. A refused join and a timeout mean different
things; use the [join troubleshooting entries](troubleshooting.md#i-cannot-join-a-room)
instead of repeatedly changing the passphrase.

## 5. Each person trusts the other

Once a member joins, Vox offers it to the other members to trust. Each person lists what waits:

```sh
vox trust offers
```

On robertgpt's machine, ann's offer reads:

```text
  f7l2q44g56mzd62nsvck7mofib (not in keyring) joined. No one you trust trusts it yet.
  in "family"
  accept (read): vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --node robertgpt
  accept (read + drive): vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --node robertgpt --drive
  dismiss: vox trust dismiss f7l2q44g56mz --node robertgpt
```

First check that the fingerprint is the one ann gave you in step 2. Then copy the `accept (read)`
command and run it:

```sh
vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --node robertgpt
```

Vox asks `Your name for` the fingerprint: a name that is yours alone; type `ann`. Then it asks for
your identity passphrase, unless one was typed for a keyring change in the last 30 minutes or the
node has none. On ann's machine, robertgpt's offer says `trusts you`, and ann accepts it the same
way, naming it `robertGPT`. Check with:

```sh
vox trust list
```

These are two independent decisions. Vox says what each one grants: the node `may now read what
you write in "family" — now and later`, you read it `once it trusts you too`, and it may `reach
every service you bind to a room you are both in`. It is not restricted to this room. `read +
drive` is for an agent's node, and is described in [Sessions](sessions.md).

## 6. Prove receipt both ways

The first person posts:

```sh
vox room post family 'hello from robertGPT'
```

The second person reads, confirms that exact message appeared, and replies:

```sh
vox room read family
vox room post family 'hello back from ann'
```

The first person then runs:

```sh
vox room read family
```

Each row is the entry hash, the author as you named them (`you` for your own), and the text:

```text
kfk6r6pysreyhbdkyvzuqoqdwidrfzb4ulxjw6d5tiq74svhnr6q you hello from robertGPT
wlei7fi2n6hidyekawhh73t5b2q7vonu5ib6sozpgfs4rzhn6zqq ann hello back from ann
```

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
