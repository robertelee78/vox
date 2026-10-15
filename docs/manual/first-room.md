# Your first shared room

Applies to Vox v0.4.5.

This tutorial connects two machines and confirms a message in each direction. Choose your trust
path before exchanging node fingerprints:

- **Computers you own:** after installing Vox in step 1, follow [My computers](keyring.md#my-computers)
  to enroll them with approval on both machines. This is the recommended path for your own
  computers: managed nodes receive the computer policy without a separate trust exchange for
  every pair. Then follow steps 2, 4, 5 and 7 here. Skip the individual trust steps 3 and 6.
- **Another person's computer, or access to just one node:** follow every step below. Compare
  node fingerprints through a channel you already trust, such as a call, and grant trust individually.

The examples call the first machine's node `robertgpt`, the second's `ann`, and the room `family`.
Each step says who runs it. If both machines are yours, you perform both roles. You need a terminal
on each machine; the individual-trust walkthrough takes about ten minutes.

For agents, finish this room exchange first, then use [setup](agents.md#set-up-a-machine) and
[repository binding](sessions.md#the-room-a-session-works-in). Making a bare node alone does not wire a harness.

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

On the other person's machine:

```sh
vox node create ann
```

Node names use lower-case letters, digits, `.`, `_` and `-`.

Vox asks for an identity passphrase twice. It unlocks the node on this machine. On a Mac with
successful Keychain storage, you see these lines among the output:

```text
vox: created node robertgpt
ek46r5zf3r7m6fevgu6ghilzamowcaj66qdmw27zxvozxr4m2z4a
vox: there is no backup of a node: if this machine is lost, so is this node; make a new one, and ask everyone who trusts this one to remove it from their keyring and trust the new one
vox: node robertgpt is Ready (remembered)
```

The second line is the node's fingerprint, the public name of its keys. The node is now
**Ready**: Vox's **daemon**, a background program, runs it. On a Mac, successful remembering
lets it become Ready again after a restart. On Linux, creating a protected node interactively
makes it Ready but does not remember its passphrase; the output says so. Follow the
[persistent passphrase-file unlock instructions](keyring.md#your-nodes) before relying on automatic
restart there. If remembering fails on either platform, keep the reported qualification rather
than treating Ready as remembered.

## 3. Both of you compare fingerprints

On your machine:

```sh
vox id --node robertgpt
```

On the other person's machine:

```sh
vox id --node ann
```

You see your node's fingerprint on one line. Read it to the other person over the call, and
write down theirs. You check it in step 6.

## 4. You create the room

On your machine, run:

```sh
vox room create --name family --node robertgpt
```

Vox asks for a room passphrase twice. This is a second secret, separate from your identity
passphrase. You see `vox: created family`.

Now print the room's link:

```sh
vox room link family --node robertgpt
```

You see the link, one line that starts with `vox://`, and these notes:

```text
vox: the address names this host directly — the local network, a port mapping the router granted (nobody has confirmed it reachable), this machine — and a guest who can reach that joins without an anchor
vox: send the passphrase another way than this address (in person, a call, a different app)
     joining grants nothing — use `vox trust add` to decide who reads you
```

Send the link to the other person in a message. Tell them the room passphrase over the call, not
in the same message.

The other person's machine must be able to reach a member. The same LAN, a public address or a
reachable port mapping can provide that without an anchor. A granted mapping alone is not proof
that a guest can reach it. If neither host can reach the other, follow
[room anchor setup](services.md#put-an-anchor-in-a-room-link), then print and send a fresh room link.
Being behind NAT by itself does not mean an anchor is required.

## 5. The other person joins

On their machine, the other person uses **Join Room** in Vox with the actual link from step 4,
or constructs a `vox room join` command with that entire link as its argument and `--node ann`.
The link is unique to your room; there is no reusable link in this manual. Single-quote the link
so the shell does not split it at `&` or interpret `?`. If an argument contains an apostrophe,
use the [shell-quoting rule](reference.md#commands-you-can-paste).

Vox asks for the room passphrase. They see, first:

```text
vox: joined family
     you read a member once you trust it and it trusts you: `vox trust add`
```

Joining makes them a member; it grants no trust itself. With completed computer enrollment,
confirm the managed grants have applied and continue to step 7. On the individual-node path,
reading takes trust from both of you, which you give next.

## 6. Both of you trust each other

Your **keyring** is the list of nodes you trust. You go first. On your machine, list the nodes
waiting for your trust:

```sh
vox trust offers --node robertgpt
```

The offer names the other person's actual fingerprint, why it is offered, and the room you
share. Check every character against the fingerprint from step 3. Then copy the complete
`accept (read)` command from **your terminal's output**, including `--node robertgpt`, and run
it unchanged. `read + drive` is for letting that node drive your agents; see [Sessions](sessions.md).

Vox asks for your own name for the other person's node. It is a local label that only you see,
and it may have capital letters. Type `ann`. Then Vox asks for your identity passphrase. Vox
prints the accepted fingerprint, the name `ann`, the `read` grant and what that lets ann do.

Now the other person runs `vox trust offers --node ann` on their machine. Because you trust them,
your node is offered there, marked `trusts you`. They run its `accept (read)` command the same way, and
name your node `robertGPT`.

If `vox trust offers` says `no offers`, wait a few seconds for the two nodes to sync, and run it
again.

## 7. Exchange a message

On your machine, post:

```sh
vox room post family 'hello from robertGPT' --node robertgpt
```

On their machine, the other person reads the room and replies:

```sh
vox room read family --node ann
vox room post family 'hello back from ann' --node ann
```

They see your message. Each row is the message's entry hash (its ID), its author by their name
for it, and the text. If a row says `(not received yet)`, wait a few seconds and read again. Back on your machine, read the room:

```sh
vox room read family --node robertgpt
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
