# Identity and keyring

Applies to: v0.3.1. Examples act as the node `robertgpt`. With one node attached, commands act
as it; with several, add `--node robertgpt`.

## Your nodes

A node is one identity: its own keys, rooms, keyring and services. One machine can hold several,
for example yours and one for each agent working beside you. Never share one node between a
person and an agent.

```sh
vox node create robertgpt
vox node attach robertgpt
vox node list
vox node detach robertgpt
```

`node create` writes the identity and prints its fingerprint; it attaches nothing. `node attach`
takes the identity passphrase once and runs the node in full until `node detach` or until the
daemon stops. `node list` shows each node as `attached` or `detached`. `node detach` closes that
node's connections, stops its services and wipes its keys from memory; other attached nodes keep
running. Detaching is not deleting: the node, its rooms and its keyring stay on disk.

## Compare before trusting

Your fingerprint identifies your node's key material. `vox id` prints it, whole, on one line.

Ask the other person for their **whole fingerprint** through a way you already trust and
compare it with the intended node. Do not trust a short prefix as proof that two full
fingerprints match. The CLI can resolve some unambiguous known prefixes, but that is a
selection convenience, not an identity-verification method.

A different key is a different node. If someone replaces their machine or agent identity,
compare the new fingerprint and decide whether to remove the old one; do not automatically
trust a replacement because it claims the old name.

## Add a node to your keyring

Prerequisite: the fingerprint has been compared, and this is the node you intend to act as.

```sh
vox trust add FULL_FINGERPRINT --name robertGPT
vox trust list
```

Choose a name meaningful to you. It is local and never registers a username. In a terminal,
Vox asks for a name if `--name` is omitted. In automation, give one explicitly. `trust list`
prints each trusted fingerprint and your name for it.

This grants the node access governed by your trust decision across **all shared rooms**,
including ones you join later, and reach to every service you share in a room you are both in.
Vox states this when you add it. It is not just permission for the currently open room or one
file. The other node makes its own independent decision to trust you. For a conversation,
confirm a message can be read in each direction.

`--history` chooses what of **your own** earlier messages the trusted node can read: `now`, the
default, releases what you write from this approval onward; `full` also releases everything you
still hold a key for. It never releases anyone else's messages.

A keyring change (add, rename, remove) asks for the identity passphrase again once 30 minutes
have passed since you last gave it. At a terminal it asks; otherwise give
`--identity-passphrase-file`. Do not put that passphrase in `--identity-passphrase`, which is
intentionally refused.

## Rename a node in your keyring

```sh
vox trust rename FULL_FINGERPRINT annie
```

Vox confirms the new name and the service address it gives, for example `its services are
reachable as <service>.annie.<room>.vox`. Renaming grants and removes nothing; only a node you
already trust can be renamed. Do not remove and re-add a trusted node to change its name:
removal has real access and key-rotation consequences.

## Understand the member pane

The TUI shows trust by glyph, weight and words. A node in your keyring is drawn bold with `→`,
and its line says `in keyring · reads you` or `in keyring · cannot read you yet`. A node not in
your keyring is drawn plain with `·` and named by its fingerprint. Its line says
`not in keyring · still reads you` or `not in keyring · you don't read each other`. Where the
terminal takes only ASCII, the glyphs are `->` and `.`. The words describe local trust and
whether the other member can read your messages in that room. They are not read receipts for
an individual message.

If the state and your expectation differ, check each person's selected node and keyring,
then connectivity. Do not add an unfamiliar fingerprint simply to silence a warning.

## Remove trust

Before removing a node, understand the scope: its access to your future messages and shared
services is withdrawn across the rooms you share. Your sender key is rotated and everyone you
still trust is re-keyed; a connection it opens to your services from then on is refused. The
node retains anything it already read or copied. Room membership and your local naming choices
are not a guarantee that earlier data disappears remotely.

```sh
vox trust remove FULL_FINGERPRINT
vox trust list
```

Vox reports `your sender key is rotated and everyone still trusted is re-keyed`. Verify the
fingerprint is absent from `vox trust list`, and inspect any affected service or conversation
from the other side if you need operational confirmation. Do not run this as an experiment on a
family member's or production agent's identity.

For passphrases and paths, see [Commands and local state](reference.md). For a one-way
conversation, see [the trust troubleshooting entry](troubleshooting.md#we-joined-but-cannot-read-each-other).

Source: [trust and node commands](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/cli.rs),
[the 30-minute keyring window](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-core/src/node/actor.rs)
and [TUI state wording](https://github.com/robertelee78/vox/blob/bf6dfcdbee65e82a4683400baa94dd62fc8532d6/crates/vox-tui/src/ui.rs).
