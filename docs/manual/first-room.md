# Your first shared room

In this tutorial you and one other person each install Vox, make a node, share a room, trust each
other, and read each other's message. It takes about ten minutes. You need a terminal on each
machine and a way to talk to the other person that you already trust, such as a call.

The examples call your node `robertgpt` and the other person's node `ann`. Each step says who
runs it.

## 1. Both of you install Vox

On each machine, run:

```sh
curl -fsSL https://voxlucis.us/install.sh | sh
```

Open a new terminal, then check that the shell finds it:

```sh
vox --version
```

You see `vox` and its version number.

## 2. Both of you make a node

A node is your identity in Vox: its own keys, rooms and keyring. On your machine, run:

```sh
vox node create robertgpt
```

The other person runs the same command with their name, `ann`. Use lower-case letters, digits,
`.`, `_` and `-`.

Vox asks for an identity passphrase twice. It unlocks the node on this machine. You see, among
other lines:

```text
vox: created node robertgpt
ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a
vox: there is no backup of a node: if this machine is lost, so is this node; make a new one, and ask everyone who trusts this one to remove it from their keyring and trust the new one
vox: node robertgpt attached (kept)
```

The second line is the node's fingerprint, the public name of its keys. The node is now
**attached**: Vox's **daemon**, a background program, runs it, and attaches it again by itself
after a restart.

## 3. Both of you compare fingerprints

Each of you runs:

```sh
vox id
```

You see your node's fingerprint on one line. Read it to the other person over the call, and
write down theirs. You check it in step 6.

## 4. You create the room

On your machine, run:

```sh
vox room create --name family
```

Vox asks for a room passphrase twice. This is a second secret, separate from your identity
passphrase. You see `vox: created family`.

Now print the room's link:

```sh
vox room link family
```

You see the link, one line that starts with `vox://`, and these notes:

```text
vox: the address names this host directly — the local network, a port mapping the router granted (nobody has confirmed it reachable), this machine — and a guest who can reach that joins without an anchor
vox: send the passphrase another way than this address (in person, a call, a different app)
     joining grants nothing — use `vox trust add` to decide who reads you
```

Send the link to the other person in a message. Tell them the room passphrase over the call, not
in the same message.

The other person's machine must be able to reach yours. On the same network, or with a router
that grants the port mapping the note mentions, it can. If you are both behind routers that grant
none, you need an anchor, a node on a host both machines reach
([when an anchor is needed](services.md#when-an-anchor-is-needed)).

## 5. The other person joins

On their machine, the other person types `vox room join '`, pastes the link, types `'`, and
presses Return. With the link from step 4 the command reads:

```sh
vox room join 'vox://gkpeyuly4m4ezlidyid3vocosfzpec2o7um5dleicv2aacz6z2ja?a=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&b=/ip4/203.0.113.7/udp/53213&m=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a&r=ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a'
```

The single quotes matter: without them the shell cuts the link at its first `&`. Vox asks for the
room passphrase. They see, first:

```text
vox: joined family
     you read a member once you trust it and it trusts you: `vox trust add`
```

Joining makes them a member. Neither of you can read the other yet: reading takes trust from
both of you, which you give next.

## 6. Both of you trust each other

Your **keyring** is the list of nodes you trust. You go first. On your machine, list the nodes
waiting for your trust:

```sh
vox trust offers
```

You see the other person's node:

```text
  f7l2q44g56mzd62nsvck7mofib (not in keyring) joined. No one you trust trusts it yet.
  in "family"
  accept (read): vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --node robertgpt
  accept (read + drive): vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --node robertgpt --drive
  dismiss: vox trust dismiss f7l2q44g56mz --node robertgpt
```

Check that the fingerprint matches the one you wrote down in step 3. Then copy the
`accept (read)` command and run it. (`read + drive` is for agents; see [Sessions](sessions.md).)

```sh
vox trust add f7l2q44g56mzd62nsvck7mofibuj4l57uchhi446s32w3cg5arrq --node robertgpt
```

Vox asks for your own name for the other person's node. It is a local label that only you see,
and it may have capital letters. Type `ann`. Then Vox asks for your identity passphrase. You see
`vox: trusting f7l2q44g56mzd62nsvck7mofib as "ann": read`, and what that lets ann do.

Now the other person runs `vox trust offers` on their machine. Because you trust them, your node
is offered there, marked `trusts you`. They run its `accept (read)` command the same way, and
name your node `robertGPT`.

If `vox trust offers` says `no offers`, wait a few seconds for the two nodes to sync, and run it
again.

## 7. Exchange a message

On your machine, post:

```sh
vox room post family 'hello from robertGPT'
```

On their machine, the other person reads the room and replies:

```sh
vox room read family
vox room post family 'hello back from ann'
```

They see your message. Each row is the message's entry hash (its ID), its author by their name
for it, and the text. If a row says `(not received yet)`, wait a few seconds and read again. Back on your machine, read the room:

```sh
vox room read family
```

You see both messages:

```text
kfk6r6pysreyhbdkyvzuqoqdwidrfzb4ulxjw6d5tiq74svhnr6q you hello from robertGPT
wlei7fi2n6hidyekawhh73t5b2q7vonu5ib6sozpgfs4rzhn6zqq ann hello back from ann
```

You now share a room in which each of you reads the other. Trust carries over: a later room
with the same person needs only steps 4 and 5.

## Next

- [Rooms and messages](rooms.md): reply, address a member, set how long the room keeps messages.
- [Reach a shared service](services.md): reach SSH on each other's machine.
- [Agent communications](agents.md): bring an agent into the room.

If a step does not show what this page says, see [Troubleshooting by symptom](troubleshooting.md).
